// HexFindBar.cpp
// 作用：HexFindBar 的界面搭建、搜索调度（票据/取消/后台线程）、结果呈现与可见高亮。
// 纯逻辑（模式解析、数据源、查找、可见命中）在 HexFindSearch.cpp。

#include "HexFindBar.h"
#include "../PageControlStyle.h"
#include "../ToolbarMetrics.h"

#include "HexCanvasFormat.h"
#include "HexViewFormat.h"

#include <QHBoxLayout>
#include <QLineEdit>
#include <QMetaObject>
#include <QRunnable>

#include <algorithm>

namespace ks::ui
{
    // 构造：搭界面、配单线程池、连接按钮与回车。
    HexFindBar::HexFindBar(QWidget* parent)
        : HexViewBarFrame(Edge::Bottom, parent)
    {
        // 单线程：同一时刻只有一个搜索在扫描，新搜索会先取消旧的。
        m_pool.setMaxThreadCount(1);
        buildUi();
    }

    // 析构：先让在途搜索失效并等待线程结束，再销毁控件（见头文件第二节）。
    HexFindBar::~HexFindBar()
    {
        cancelRunning();
        ++m_ticket;
        m_pool.waitForDone();
    }

    // 搭建界面：[模式三段] [输入框] [Aa] [上一个] [下一个] [结果文字] [关闭]。
    void HexFindBar::buildUi()
    {
        auto* layout = new QHBoxLayout(this);
        layout->setContentsMargins(8, 4, 8, 4);
        layout->setSpacing(6);

        // 模式三段按钮：标签是纯标识符（不翻译），说明放在逐段悬停提示里。
        m_modeSegment = new HexViewSegmented(
            QStringList{ QStringLiteral("HEX"), QStringLiteral("UTF-8"), QStringLiteral("UTF-16") }, this);
        m_modeSegment->setSegmentToolTip(
            0,
            QStringLiteral("十六进制字节查找：空格或逗号分隔、连写都可以；?? 通配整个字节，A? 与 ?A 通配半个字节"));
        m_modeSegment->setSegmentToolTip(1, QStringLiteral("文本查找，按 UTF-8 编码匹配"));
        m_modeSegment->setSegmentToolTip(2, QStringLiteral("文本查找，按 UTF-16 小端编码匹配（Windows 宽字符串）"));
        m_modeSegment->setAccessibleName(QStringLiteral("查找模式"));
        layout->addWidget(m_modeSegment);

        // 输入框：回车 = 查找下一个。
        m_edit = new QLineEdit(this);
        m_edit->setClearButtonEnabled(true);
        m_edit->setMinimumWidth(110);
        m_edit->setAccessibleName(QStringLiteral("查找内容"));
        StyleSearchField(m_edit);
        layout->addWidget(m_edit, 2);

        // 区分大小写开关：可勾选的图标按钮，只在文本模式可用。
        m_caseButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::CaseSensitive, this);
        m_caseButton->setCheckable(true);
        m_caseButton->setToolTip(QStringLiteral("区分大小写：开启后文本查找区分 ASCII 字母大小写（仅文本模式有效）"));
        layout->addWidget(m_caseButton);

        // 上一个 / 下一个。
        m_prevButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::Previous, this);
        m_prevButton->setToolTip(QStringLiteral("上一个命中（Shift+F3）；到开头会从末尾继续并提示"));
        layout->addWidget(m_prevButton);
        m_nextButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::Next, this);
        m_nextButton->setToolTip(QStringLiteral("下一个命中（F3、回车）；到末尾会从头继续并提示"));
        layout->addWidget(m_nextButton);

        // 结果文字：吃掉剩余宽度。
        m_result = new HexViewMessageLabel(this);
        m_result->setAccessibleName(QStringLiteral("查找结果"));
        layout->addWidget(m_result, 3);

        // 关闭按钮。
        m_closeButton = new HexViewGlyphButton(HexViewGlyphButton::Glyph::Close, this);
        m_closeButton->setToolTip(QStringLiteral("关闭查找条（Esc）"));
        layout->addWidget(m_closeButton);
        // 模式分段为自绘容器，显式与旁边搜索和图标按钮等高。
        NormalizeToolbarRow(layout);
        NormalizeToolbarControl(m_modeSegment, m_edit->height());

        // 连接：回车与按钮触发搜索；关闭按钮只发信号，由宿主决定如何收起；模式切换更新提示。
        connect(m_edit, &QLineEdit::returnPressed, this, [this]() { findNext(); });
        connect(m_nextButton, &QToolButton::clicked, this, [this]() { findNext(); });
        connect(m_prevButton, &QToolButton::clicked, this, [this]() { findPrevious(); });
        connect(m_closeButton, &QToolButton::clicked, this, [this]() { emit closeRequested(); });
        connect(m_modeSegment, &HexViewSegmented::currentIndexChanged, this, [this](int) { onModeChanged(); });
        onModeChanged();
    }

    // 模式切换：更新占位提示与大小写开关的可用性。
    void HexFindBar::onModeChanged()
    {
        const Mode current = mode();
        if (current == Mode::Hex)
        {
            m_edit->setPlaceholderText(QStringLiteral("十六进制字节，例如 4D 5A ?? A?"));
        }
        else if (current == Mode::TextUtf8)
        {
            m_edit->setPlaceholderText(QStringLiteral("要查找的文本（UTF-8）"));
        }
        else
        {
            m_edit->setPlaceholderText(QStringLiteral("要查找的文本（UTF-16）"));
        }

        // 区分大小写只对文本有意义；十六进制模式下禁用，避免用户以为它起作用。
        m_caseButton->setEnabled(current != Mode::Hex);
    }

    // ======================== 宿主接口 ========================

    // 设置数据回调。
    void HexFindBar::setSourceGetter(SourceGetter getter)
    {
        m_sourceGetter = std::move(getter);
    }

    // 设置选区回调。
    void HexFindBar::setSelectionGetter(SelectionGetter getter)
    {
        m_selectionGetter = std::move(getter);
    }

    // 置位当前在途搜索的取消标志（没有在途搜索时什么也不做）。
    void HexFindBar::cancelRunning()
    {
        if (m_cancel != nullptr)
        {
            m_cancel->store(true);
        }
    }

    // 清除高亮：有内容才发信号。
    void HexFindBar::clearHighlights()
    {
        if (m_highlights.empty())
        {
            return;
        }
        m_highlights.clear();
        emit highlightsChanged(m_highlights);
    }

    // 缓冲变化：在途搜索作废，高亮与上次命中清除。
    void HexFindBar::dataChanged()
    {
        cancelRunning();
        ++m_ticket;
        const bool wasSearching = m_searching;
        m_searching = false;
        m_last = LastMatch();
        const bool wasActive = m_active;
        m_active = false;
        clearHighlights();

        // 之前有命中状态或搜索在途才提示（在途时结果文字还停在"正在查找…"，必须换掉）：
        // 没搜索过的条在用户每敲一次键编辑时不该冒出文字。
        if (wasActive || wasSearching)
        {
            showResult(HexViewMessageLabel::Kind::Hint, QStringLiteral("数据已变化，请重新查找"));
        }
    }

    // 宿主告知可见范围：已有命中时重算高亮。
    void HexFindBar::setVisibleRange(std::uint64_t first, std::uint64_t last)
    {
        m_visibleValid = (first <= last);
        m_visibleFirst = first;
        m_visibleLast = last;
        if (m_active)
        {
            refreshHighlights();
        }
    }

    // 打开：显示、聚焦、全选。
    void HexFindBar::open()
    {
        show();
        m_edit->setFocus(Qt::ShortcutFocusReason);
        m_edit->selectAll();
    }

    // 关闭前的清理：取消搜索、清高亮与结果文字、票据前进。
    void HexFindBar::deactivate()
    {
        cancelRunning();
        ++m_ticket;
        m_searching = false;
        m_last = LastMatch();
        m_active = false;
        clearHighlights();
        m_result->clearMessage();
    }

    // ======================== 状态与输入 ========================

    // 当前模式：由三段按钮的下标换算。
    HexFindBar::Mode HexFindBar::mode() const
    {
        switch (m_modeSegment->currentIndex())
        {
        case 1:
            return Mode::TextUtf8;
        case 2:
            return Mode::TextUtf16Le;
        default:
            return Mode::Hex;
        }
    }

    // 设置模式：同步三段按钮（其信号会更新提示）。
    void HexFindBar::setMode(Mode newMode)
    {
        m_modeSegment->setCurrentIndex(static_cast<int>(newMode));
    }

    // 输入框文字。
    QString HexFindBar::patternText() const
    {
        return m_edit->text();
    }

    // 设置输入框文字。
    void HexFindBar::setPatternText(const QString& text)
    {
        m_edit->setText(text);
    }

    // 区分大小写。
    bool HexFindBar::caseSensitive() const
    {
        return m_caseButton->isChecked();
    }

    // 设置区分大小写。
    void HexFindBar::setCaseSensitive(bool enabled)
    {
        m_caseButton->setChecked(enabled);
    }

    // 向后查找。
    bool HexFindBar::findNext()
    {
        return startSearch(Direction::Forward);
    }

    // 向前查找。
    bool HexFindBar::findPrevious()
    {
        return startSearch(Direction::Backward);
    }

    // 是否在搜索。
    bool HexFindBar::isSearching() const
    {
        return m_searching;
    }

    // 等待线程池空闲。
    bool HexFindBar::waitForIdle(int timeoutMs)
    {
        return m_pool.waitForDone(timeoutMs);
    }

    // 结果文字。
    QString HexFindBar::resultText() const
    {
        return m_result->text();
    }

    // 结果种类。
    HexViewMessageLabel::Kind HexFindBar::resultKind() const
    {
        return m_result->kind();
    }

    // 当前可见高亮。
    const std::vector<HexFindBar::AddressRange>& HexFindBar::highlightRanges() const
    {
        return m_highlights;
    }

    // 是否处于有命中状态。
    bool HexFindBar::highlightActive() const
    {
        return m_active;
    }

    // 内部控件访问器。
    QLineEdit* HexFindBar::lineEdit() const
    {
        return m_edit;
    }

    HexViewSegmented* HexFindBar::modeSegment() const
    {
        return m_modeSegment;
    }

    HexViewGlyphButton* HexFindBar::caseButton() const
    {
        return m_caseButton;
    }

    HexViewGlyphButton* HexFindBar::previousButton() const
    {
        return m_prevButton;
    }

    HexViewGlyphButton* HexFindBar::nextButton() const
    {
        return m_nextButton;
    }

    HexViewGlyphButton* HexFindBar::closeButton() const
    {
        return m_closeButton;
    }

    // ======================== 搜索调度 ========================

    // 显示结果文字。
    void HexFindBar::showResult(HexViewMessageLabel::Kind kind, const QString& text)
    {
        m_result->setMessage(kind, text);
    }

    // 启动一次搜索。
    // 流程：解析模式 -> 取数据快照 -> 决定起点 -> 取消旧搜索并领新票据 -> 后台扫描 -> 结果入队回到 UI 线程。
    bool HexFindBar::startSearch(Direction direction)
    {
        // 1) 解析：失败时显示"无效模式：原因"，不动在途搜索与旧高亮。
        ksword::memwb::SearchPattern pattern;
        ksword::memwb::ParseError error;
        QByteArray utf8;
        if (!hexfind::ParsePattern(mode(), m_edit->text(), caseSensitive(), pattern, error, &utf8))
        {
            showResult(
                HexViewMessageLabel::Kind::Error,
                QStringLiteral("无效模式：%1").arg(hexfind::DescribeParseError(error, utf8)));
            return false;
        }

        // 2) 数据快照：没有数据没法查。
        SourceView source;
        if (m_sourceGetter)
        {
            source = m_sourceGetter();
        }
        if (source.data.isEmpty())
        {
            showResult(HexViewMessageLabel::Kind::Warning, QStringLiteral("没有可查找的数据"));
            return false;
        }

        // 3) 起点：缓冲末地址、选区、上次命中三者决定。
        const std::uint64_t dataLast = source.base + (static_cast<std::uint64_t>(source.data.size()) - 1ULL);
        std::uint64_t selectionFirst = 0;
        std::uint64_t selectionLast = 0;
        const bool hasSelection = m_selectionGetter && m_selectionGetter(&selectionFirst, &selectionLast);

        // selectionIsLastMatch：选区恰好就是同一个模式的上次命中——用户在连续按 F3，要从命中起点前进一格（允许重叠命中）。
        // 模式必须相同：用户改了模式（例如把 "4D 5A" 补成 "4D 5A 90 00"）再回车，选区仍是旧命中，
        // 新模式在同一起点上就可能命中，不能跳过它。
        const bool selectionIsLastMatch = m_last.valid && hasSelection
            && selectionFirst == m_last.address
            && selectionLast == m_last.address + (m_last.length - 1ULL)
            && m_last.pattern.bytes == pattern.bytes
            && m_last.pattern.mask == pattern.mask;

        // start：引擎的起点；forcedWrap：起点在 0 或 UINT64_MAX 无法再前进一格时，直接从另一端开始并如实标注回绕。
        std::uint64_t start = source.base;
        bool forcedWrap = false;
        if (direction == Direction::Forward)
        {
            if (selectionIsLastMatch)
            {
                if (!ksword::memwb::AdvanceSearchStart(m_last.address, Direction::Forward, start))
                {
                    start = source.base;
                    forcedWrap = true;
                }
            }
            else
            {
                start = hasSelection ? selectionFirst : source.base;
            }
        }
        else
        {
            if (selectionIsLastMatch)
            {
                if (!ksword::memwb::AdvanceSearchStart(m_last.address, Direction::Backward, start))
                {
                    start = dataLast;
                    forcedWrap = true;
                }
            }
            else if (hasSelection)
            {
                if (!ksword::memwb::AdvanceSearchStart(selectionFirst, Direction::Backward, start))
                {
                    start = dataLast;
                    forcedWrap = true;
                }
            }
            else
            {
                start = dataLast;
            }
        }

        // 4) 取消旧搜索并领新票据；取消标志与工作线程共享。
        cancelRunning();
        const std::uint64_t ticket = ++m_ticket;
        m_cancel = std::make_shared<std::atomic<bool>>(false);
        m_searching = true;
        m_pendingPattern = pattern;
        showResult(HexViewMessageLabel::Kind::Hint, QStringLiteral("正在查找…"));

        // 5) 后台扫描：任务拥有数据快照、模式、取消标志的拷贝；完成后以本对象为上下文入队，
        //    本对象先于队列销毁时回调被 Qt 丢弃。
        const std::shared_ptr<std::atomic<bool>> cancelFlag = m_cancel;
        HexFindBar* const self = this;
        QRunnable* task = QRunnable::create([self, source, pattern, start, direction, forcedWrap, ticket, cancelFlag]() {
            const hexfind::Outcome outcome = hexfind::RunSearch(
                source.data, source.base, pattern, start, direction, true, cancelFlag.get(), source.validMask);
            QMetaObject::invokeMethod(
                self,
                [self, ticket, outcome, forcedWrap, direction]() {
                    self->onSearchFinished(ticket, outcome, forcedWrap, direction);
                },
                Qt::QueuedConnection);
        });
        m_pool.start(task);
        return true;
    }

    // 搜索结果回到 UI 线程。
    // 传入：搜索时的票据、引擎结果、是否强制标注回绕、方向。票据对不上说明已被取代或数据已变，直接丢弃。
    void HexFindBar::onSearchFinished(
        std::uint64_t ticket,
        const hexfind::Outcome& outcome,
        bool forcedWrap,
        Direction direction)
    {
        if (ticket != m_ticket)
        {
            return;
        }
        m_searching = false;
        if (outcome.cancelled)
        {
            return;
        }
        if (outcome.invalid)
        {
            showResult(HexViewMessageLabel::Kind::Error, QStringLiteral("没有可查找的数据"));
            emit searchCompleted(false);
            return;
        }

        // 没找到：整个范围都扫过了（回绕已开启）。清状态与高亮。
        if (!outcome.found)
        {
            m_last = LastMatch();
            m_active = false;
            clearHighlights();
            showResult(HexViewMessageLabel::Kind::Warning, QStringLiteral("未找到"));
            emit searchCompleted(false);
            return;
        }

        // 找到：记住命中，启用可见高亮，文字注明起始地址与是否回绕。
        const bool wrapped = outcome.wrapped || forcedWrap;
        const std::uint64_t length = static_cast<std::uint64_t>(m_pendingPattern.bytes.size());
        m_last.valid = true;
        m_last.address = outcome.address;
        m_last.length = length;
        m_last.pattern = m_pendingPattern;
        m_activePattern = m_pendingPattern;
        m_active = true;

        QString text = QStringLiteral("已找到 %1").arg(
            hexcanvas_format::FormatAddress(outcome.address, hexview_format::AddressDigitsFor(outcome.address, outcome.address)));
        if (wrapped)
        {
            text += (direction == Direction::Forward)
                ? QStringLiteral("，已从头继续")
                : QStringLiteral("，已从末尾继续");
        }
        showResult(HexViewMessageLabel::Kind::Info, text);

        // 先发 matchFound：宿主选中并滚动（滚动会经 setVisibleRange 触发一次高亮重算），
        // 再补一次重算覆盖"命中本来就可见、没有滚动"的情形。
        emit matchFound(outcome.address, length, wrapped);
        refreshHighlights();
        emit searchCompleted(true);
    }

    // 重算可见高亮：只扫描可见范围；结果与当前相同不发信号。
    void HexFindBar::refreshHighlights()
    {
        if (!m_active || !m_visibleValid || !m_sourceGetter)
        {
            return;
        }
        const SourceView source = m_sourceGetter();
        const std::vector<AddressRange> hits = hexfind::HitsInRange(
            source.data, source.base, m_activePattern, m_visibleFirst, m_visibleLast, hexfind::kMaxVisibleHits, source.validMask);
        if (hits == m_highlights)
        {
            return;
        }
        m_highlights = hits;
        emit highlightsChanged(m_highlights);
    }
}
