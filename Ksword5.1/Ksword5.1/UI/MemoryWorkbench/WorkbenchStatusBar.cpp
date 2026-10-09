#include "WorkbenchStatusBar.h"

// ============================================================
// WorkbenchStatusBar.cpp
// 作用：见头文件。
//
// 宿主由装配层注入；字段模型和原始日志各有正式接口，状态条仅负责抽屉与复制动作。
// ============================================================

#include "WorkbenchMessages.h"

#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"

#include <QCheckBox>
#include <QClipboard>
#include <QEvent>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QStyle>
#include <QToolButton>
#include <QVBoxLayout>

#include <algorithm>
#include <cstddef>

namespace ks::ui
{
    namespace
    {
        // ElidedSegmentLabel：状态条里"文字可能很长"的摘要段（读取结果、窗口范围）用的标签。
        // - text() 始终是调用方给的完整原文：运行期整句翻译（LanguageManager）与测试都按它做精确匹配，
        //   所以不能像写入结果段那样把省略后的文字 setText 回去；
        // - 放不下时在绘制阶段做右省略（"已读 4096/40…"），不是被布局硬裁成半截；
        // - 最小宽度只够画一个省略号：窗口再窄，这一段也缩成"…"，不会被压成 1px 的空白，
        //   同时又不会像"最小宽度=文字宽度"那样把状态条的最小宽度越撑越大（T13 棘轮测试）。
        // 没有信号槽，不需要 Q_OBJECT（因此也不进 moc）。
        class ElidedSegmentLabel final : public QLabel
        {
        public:
            explicit ElidedSegmentLabel(QWidget* parent) : QLabel(parent) {}

            // minimumSizeHint：一个省略号的宽度加上标签自己的边距；高度沿用 QLabel 的。
            QSize minimumSizeHint() const override
            {
                const QFontMetrics metrics(font());
                const int ellipsisWidth = metrics.horizontalAdvance(QChar(0x2026));
                return QSize(ellipsisWidth + 2 * margin() + 2 * frameWidth(), QLabel::minimumSizeHint().height());
            }

        protected:
            // paintEvent：放得下就交给 QLabel 自己画（样式表颜色/字重、选中高亮全部保持原样）；
            // 放不下才改画省略后的文字，颜色取控件当前调色板的前景角色（样式表的 color 就落在它上面）。
            void paintEvent(QPaintEvent* event) override
            {
                const QString fullText = text();
                const QRect area = contentsRect().adjusted(margin(), 0, -margin(), 0);
                const QFontMetrics metrics(font());
                if (fullText.isEmpty() || area.width() <= 0 || metrics.horizontalAdvance(fullText) <= area.width())
                {
                    QLabel::paintEvent(event);
                    return;
                }
                QPainter painter(this);
                painter.setFont(font());
                const QString elided = metrics.elidedText(fullText, Qt::ElideRight, area.width());
                style()->drawItemText(
                    &painter, area, Qt::AlignLeft | Qt::AlignVCenter | Qt::TextSingleLine, palette(), isEnabled(),
                    elided, foregroundRole());
            }
        };
    }

    WorkbenchStatusBar::WorkbenchStatusBar(
        std::unique_ptr<IWorkbenchDiagnosticsHost> diagnosticsHost, QWidget* parent)
        : QWidget(parent)
        , m_diagnosticsHost(std::move(diagnosticsHost))
    {
        auto* rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(4, 2, 4, 2);
        rootLayout->setSpacing(2);

        // 第一行：保护徽章 + 四段摘要（各自独立 QLabel，S1）+ 展开/收起箭头。
        auto* summaryRow = new QHBoxLayout();
        summaryRow->setContentsMargins(0, 0, 0, 0);
        summaryRow->setSpacing(6);

        m_protectionBadge = new QLabel(this);
        ApplyStatusRole(m_protectionBadge, StatusRole::Idle);
        summaryRow->addWidget(m_protectionBadge);

        // 四段摘要的三种构造方式（全部可选中复制、不自动换行）：
        //  - Fixed：通道·范围段。文字短且有界（"R3 · 进程"一类），用 QLabel 默认的"最小宽度=自身文字宽度"，
        //    任何窗口宽度下都完整显示、绝不被压缩。
        //    （历史：这里原先和读取结果/窗口范围两段一样 setMinimumWidth(1)，窗口一窄就被压到 1px——
        //    240px 时整段消失、300~360px 时只剩半个字，与主题无关。）
        //  - Elastic：读取结果/窗口范围两段。文字可能很长，必须能缩：用 ElidedSegmentLabel，
        //    最小宽度只够一个省略号，放不下时绘制成"已读 4096/40…"。
        //  - Tail：写入结果段。唯一可能携带任意长度失败详情的一段，沿用原来的做法——
        //    Ignored 策略吃掉所有剩余空间，文字由 applyElidedSummary 估算宽度后 setText 省略。
        // N1（第二轮修复，保留）：前三段不能用 Ignored——布局会完全无视"当前文字需要多宽"，
        // 实测宽度直接塌成 0（只剩 "RW | | | 已写入…"）。B4 的棘轮效应（最小宽度被当前文字宽度顶住、
        // 越撑越大）只对长文字段成立，所以只有 Elastic/Tail 不能用"最小=文字宽度"。
        enum class SegmentKind { Fixed, Elastic, Tail };
        const auto makeSegmentLabel = [this](const SegmentKind kind) {
            QLabel* label = (kind == SegmentKind::Elastic) ? new ElidedSegmentLabel(this) : new QLabel(this);
            label->setTextInteractionFlags(Qt::TextSelectableByMouse);
            if (kind == SegmentKind::Tail)
            {
                // Ignored：吃掉所有剩余空间；显式最小宽度 1px 打破"当前文字宽度即最小宽度"的棘轮。
                label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
                label->setMinimumWidth(1);
            }
            else
            {
                label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
            }
            return label;
        };
        m_channelScopeLabel = makeSegmentLabel(SegmentKind::Fixed);
        summaryRow->addWidget(m_channelScopeLabel);
        m_separators[0] = new QLabel(QStringLiteral("|"), this);
        summaryRow->addWidget(m_separators[0]);
        m_readResultLabel = makeSegmentLabel(SegmentKind::Elastic);
        summaryRow->addWidget(m_readResultLabel);
        m_separators[1] = new QLabel(QStringLiteral("|"), this);
        summaryRow->addWidget(m_separators[1]);
        m_windowRangeLabel = makeSegmentLabel(SegmentKind::Elastic);
        summaryRow->addWidget(m_windowRangeLabel);
        m_separators[2] = new QLabel(QStringLiteral("|"), this);
        summaryRow->addWidget(m_separators[2]);
        // 本轮自补变异 wpGN2-08 实测过：这里改成按 Elastic 走（Preferred，不再是 Ignored）
        // 不会让既有的 T13 棘轮回归测试报警——最小宽度本身已经独立于 Ignored/Preferred 阻止了棘轮，
        // 真正的差异只在"这一段的 sizeHint 要不要算进这一行的首选宽度"，属于那批测试看不出来的
        // 等价行为，不是本段仍然选 Tail（Ignored + 手动省略）的理由失效。
        m_writeResultLabel = makeSegmentLabel(SegmentKind::Tail);
        summaryRow->addWidget(m_writeResultLabel, 1);

        m_expandButton = new QToolButton(this);
        m_expandButton->setAutoRaise(true);
        m_expandButton->setCheckable(true);
        m_expandButton->setIcon(QIcon(QStringLiteral(":/Icon/detail_node_collapsed.svg")));
        m_expandButton->setToolTip(workbench_messages::ExpandDiagnosticsTooltip(false));
        KswordTheme::ApplyCompactIconButtonMetrics(m_expandButton);
        connect(m_expandButton, &QToolButton::toggled, this, [this](const bool expanded) {
            setDrawerExpanded(expanded);
        });
        summaryRow->addWidget(m_expandButton);
        rootLayout->addLayout(summaryRow);

        // 第二行：三个状态 chip，平时都隐藏，各自按条件显示。
        auto* chipRow = new QHBoxLayout();
        chipRow->setContentsMargins(0, 0, 0, 0);
        chipRow->setSpacing(6);

        m_scratchDirtyChip = new QWidget(this);
        auto* scratchLayout = new QHBoxLayout(m_scratchDirtyChip);
        scratchLayout->setContentsMargins(0, 0, 0, 0);
        scratchLayout->setSpacing(2);
        auto* scratchLabel = new QLabel(workbench_messages::ScratchAreaDirtyChipText(), m_scratchDirtyChip);
        ApplyStatusRole(scratchLabel, StatusRole::Error);
        scratchLayout->addWidget(scratchLabel);
        m_scratchDirtyAckButton = new QToolButton(m_scratchDirtyChip);
        m_scratchDirtyAckButton->setIcon(QIcon(QStringLiteral(":/Icon/log_cancel_track.svg")));
        m_scratchDirtyAckButton->setToolTip(workbench_messages::ScratchAreaDirtyAckTooltip());
        KswordTheme::ApplyCompactIconButtonMetrics(m_scratchDirtyAckButton);
        connect(m_scratchDirtyAckButton, &QToolButton::clicked, this, &WorkbenchStatusBar::acknowledgeScratchAreaDirty);
        scratchLayout->addWidget(m_scratchDirtyAckButton);
        m_scratchDirtyChip->setVisible(false);
        chipRow->addWidget(m_scratchDirtyChip);

        m_rmwChip = new QWidget(this);
        auto* rmwLayout = new QHBoxLayout(m_rmwChip);
        rmwLayout->setContentsMargins(0, 0, 0, 0);
        auto* rmwLabel = new QLabel(workbench_messages::ReadModifyWriteWindowChipText(), m_rmwChip);
        ApplyStatusRole(rmwLabel, StatusRole::Warning);
        rmwLayout->addWidget(rmwLabel);
        m_rmwChip->setVisible(false);
        chipRow->addWidget(m_rmwChip);

        m_needsRereadLabel = new QLabel(workbench_messages::NeedsRereadHintText(), this);
        ApplyStatusRole(m_needsRereadLabel, StatusRole::Warning);
        m_needsRereadLabel->setCursor(Qt::PointingHandCursor);
        m_needsRereadLabel->installEventFilter(this);
        m_needsRereadLabel->setVisible(false);
        chipRow->addWidget(m_needsRereadLabel);

        chipRow->addStretch(1);
        rootLayout->addLayout(chipRow);

        // 第三行（抽屉）：诊断宿主控件 + 换行勾选 + 复制按钮，默认收起。
        m_drawerContainer = new QWidget(this);
        // 抽屉最大高度：展开状态会被持久化（diagExpanded），而 CodeEditorWidget 的首选高度可以很大，
        // 不设上限时展开的抽屉会在窗口不高时把十六进制画布挤到只剩一条缝。
        // 160px = 工具行（换行勾选 + 复制钮）约 28 + 诊断文本约 8 行；文本更长时编辑器自己滚动。
        constexpr int kDrawerMaxHeight = 160;
        m_drawerContainer->setMaximumHeight(kDrawerMaxHeight);
        auto* drawerLayout = new QVBoxLayout(m_drawerContainer);
        drawerLayout->setContentsMargins(0, 0, 0, 0);
        drawerLayout->setSpacing(2);

        auto* drawerToolRow = new QHBoxLayout();
        drawerToolRow->setContentsMargins(0, 0, 0, 0);
        // B12：换行勾选框原来只在注释里提了一句，SetWrapEnabled 从未被调用过
        // （死接口）。默认勾选=换行，与 FakeDiagnosticsHost/生产实现里
        // QPlainTextEdit 的默认 WidgetWidth 换行模式一致，勾选框只是让用户能
        // 关掉它去看长行的原始换行位置。
        m_wrapCheckBox = new QCheckBox(workbench_messages::DiagnosticsWrapCheckboxText(), m_drawerContainer);
        m_wrapCheckBox->setChecked(true);
        // N4（第二轮修复）：原来只 setChecked(true) 却从不调用一次 SetWrapEnabled——
        // 宿主（诊断抽屉的具体实现）构造时若自己默认不换行，勾选框和宿主真实状态
        // 就立刻不同步（勾选框显示"已勾选"，宿主其实没在换行）。这里用勾选框的
        // 初值去同步宿主一次，勾选框是本控件唯一的"用户看得到的状态来源"。
        m_diagnosticsHost->SetWrapEnabled(m_wrapCheckBox->isChecked());
        connect(m_wrapCheckBox, &QCheckBox::toggled, this, [this](const bool wrap) {
            m_diagnosticsHost->SetWrapEnabled(wrap);
        });
        drawerToolRow->addWidget(m_wrapCheckBox);
        drawerToolRow->addStretch(1);
        m_copyDiagnosticsButton = new QToolButton(m_drawerContainer);
        m_copyDiagnosticsButton->setObjectName(QStringLiteral("workbench_copy_diagnostics"));
        m_copyDiagnosticsButton->setIcon(QIcon(QStringLiteral(":/Icon/log_copy.svg")));
        m_copyDiagnosticsButton->setToolTip(workbench_messages::CopyDiagnosticsButtonTooltip());
        KswordTheme::ApplyCompactIconButtonMetrics(m_copyDiagnosticsButton);
        connect(m_copyDiagnosticsButton, &QToolButton::clicked, this, [this]() {
            // 复制诊断纯粹是把当前抽屉文本放进系统剪贴板，不涉及任何用户私密数据以外的内容，
            // 因此直接在控件内部完成，不另发信号让上层转发。
            if (auto* clipboard = QGuiApplication::clipboard())
            {
                clipboard->setText(m_diagnosticsHost->DiagnosticsText());
            }
        });
        drawerToolRow->addWidget(m_copyDiagnosticsButton);
        drawerLayout->addLayout(drawerToolRow);

        drawerLayout->addWidget(m_diagnosticsHost->HostWidget());
        m_drawerContainer->setVisible(false);
        rootLayout->addWidget(m_drawerContainer);

        rebuildSummary();
    }

    WorkbenchStatusBar::~WorkbenchStatusBar() = default;

    void WorkbenchStatusBar::setChannelScopeText(const QString& text)
    {
        m_channelScopeText = text;
        rebuildSummary();
    }

    void WorkbenchStatusBar::setReadResultText(const QString& text, const bool warning)
    {
        // N2（第二轮修复）：这里拼的是"固定前缀 + 调用方给的文本"，运行期整树翻译
        // 只按控件当前整串文字做精确匹配，前缀拼接后的整串从没在任何词条表里出现
        // 过，英文模式下会连同固定前缀一起停在原样。固定前缀本身经
        // ks::i18n::sourceText 在拼接前就地翻译（“⚠”本身无需翻译，这里统一走
        // sourceText 是为了与本文件其余字面量保持同一种"源头直译"写法，不依赖
        // 运行期扫描）；text 是调用方已经处理好的文本，原样保留，不在本函数翻译。
        m_readResultText = warning
            ? ks::i18n::sourceText(QStringLiteral("⚠ %1")).arg(text)
            : text;
        rebuildSummary();
    }

    void WorkbenchStatusBar::setProtection(const QString& text, const StatusRole role)
    {
        m_protectionText = text;
        m_protectionBadge->setText(text);
        ApplyStatusRole(m_protectionBadge, role);
        rebuildSummary();
    }

    void WorkbenchStatusBar::setWindowRangeText(const QString& text)
    {
        m_windowRangeText = text;
        rebuildSummary();
    }

    void WorkbenchStatusBar::setWriteResultText(const QString& text)
    {
        m_writeResultText = text;
        rebuildSummary();
    }

    void WorkbenchStatusBar::reportScratchAreaDirty(const bool dirtyThisReport)
    {
        // 不变式 14：只升不降。一旦任意一次报告过"脏"，chip 就常驻显示，之后即便
        // 某次报告是干净的，也不会自动把 chip 收回去——只有显式点 × 才行。
        if (dirtyThisReport)
        {
            m_scratchDirtyLatched = true;
        }
        m_scratchDirtyChip->setVisible(m_scratchDirtyLatched);
    }

    bool WorkbenchStatusBar::isScratchAreaDirtyChipVisible() const
    {
        // B8：isVisible() 要求整条祖先链都真的 show() 过——状态条还没显示出来时
        // （例如宿主 Dock 刚构造、还没插进可见的布局）调它会恒读成 false，即使
        // chip 本身已经被 setVisible(true) 过。isHidden() 只问控件自己的显隐旗标。
        return !m_scratchDirtyChip->isHidden();
    }

    void WorkbenchStatusBar::acknowledgeScratchAreaDirty()
    {
        m_scratchDirtyLatched = false;
        m_scratchDirtyChip->setVisible(false);
        emit scratchDirtyAcknowledged();
    }

    void WorkbenchStatusBar::setReadModifyWriteWindow(const bool active)
    {
        // 与暂存区脏不同：这个 chip 只反映"最近一次"，没有常驻语义。
        m_rmwChip->setVisible(active);
    }

    bool WorkbenchStatusBar::isReadModifyWriteWindowChipVisible() const
    {
        // B8：理由同 isScratchAreaDirtyChipVisible。
        return !m_rmwChip->isHidden();
    }

    void WorkbenchStatusBar::setNeedsReread(const bool needsReread)
    {
        m_needsRereadLabel->setVisible(needsReread);
    }

    void WorkbenchStatusBar::setDiagnosticsText(const QString& text, const bool autoExpand)
    {
        m_diagnosticsHost->SetDiagnosticsText(text);
        if (autoExpand)
        {
            setDrawerExpanded(true);
        }
    }

    void WorkbenchStatusBar::setDiagnosticsDocument(const FieldDocument& document, const bool autoExpand)
    {
        m_diagnosticsHost->SetDiagnosticsDocument(document);
        if (autoExpand) setDrawerExpanded(true);
    }

    QString WorkbenchStatusBar::diagnosticsText() const
    {
        return m_diagnosticsHost->DiagnosticsText();
    }

    void WorkbenchStatusBar::setDrawerExpanded(const bool expanded)
    {
        m_drawerContainer->setVisible(expanded);
        m_expandButton->setChecked(expanded);
        const QString iconPath = expanded
            ? QStringLiteral(":/Icon/detail_node_expanded.svg")
            : QStringLiteral(":/Icon/detail_node_collapsed.svg");
        m_expandButton->setIcon(QIcon(iconPath));
        m_expandButton->setToolTip(workbench_messages::ExpandDiagnosticsTooltip(expanded));
    }

    bool WorkbenchStatusBar::isDrawerExpanded() const
    {
        // B8：理由同上——装配层若在状态条还没显示出来时（或者所在页签被切走后）
        // 持久化 diagExpanded，用 isVisible() 永远读成 false，等于这个设置白存了。
        return !m_drawerContainer->isHidden();
    }

    QString WorkbenchStatusBar::summaryText() const
    {
        return m_summaryFullText;
    }

    void WorkbenchStatusBar::rebuildSummary()
    {
        // 保护属性段不进摘要文本：它已经由紧挨在摘要左边的彩色徽章（m_protectionBadge）
        // 展示过一次，再塞进摘要会在同一行里把"RW"连续显示两遍（截图实测发现，
        // 修复前是 "RW  … | RW | …"）。
        //
        // S1：四段各自写进自己独立的 QLabel（而不是像以前那样拼成一条字符串再整体
        // 设进一个 QLabel）——运行期整句翻译是按控件逐一扫描 QLabel::text() 做精确
        // 匹配的，拼接出来的新字符串从没在任何词条表里出现过，英文界面下这一整行
        // 会原样停在中文。拆开后，每一段仍是调用方给出的那个原始字符串，才能被
        // 正确匹配、正确翻译。
        //
        // 三个分隔符的显隐规则：只有"前面已经有一个可见段、且本段自己也可见"才显示
        // 对应的那根竖线，这样跳过空段时不会出现连续的"| |"，效果与旧版拼接时
        // 「空段跳过」完全一致。
        struct Segment
        {
            QLabel* label;
            const QString* text;
        };
        const Segment segments[] = {
            { m_channelScopeLabel, &m_channelScopeText },
            { m_readResultLabel, &m_readResultText },
            { m_windowRangeLabel, &m_windowRangeText },
            { m_writeResultLabel, &m_writeResultText },
        };
        bool sawVisibleSegment = false;
        constexpr std::size_t kSegmentCount = 4;
        for (std::size_t i = 0; i < kSegmentCount; ++i)
        {
            const bool segmentVisible = !segments[i].text->isEmpty();
            segments[i].label->setText(*segments[i].text);
            segments[i].label->setToolTip(*segments[i].text);
            segments[i].label->setVisible(segmentVisible);
            if (i > 0)
            {
                m_separators[i - 1]->setVisible(segmentVisible && sawVisibleSegment);
            }
            sawVisibleSegment = sawVisibleSegment || segmentVisible;
        }

        QStringList parts;
        if (!m_channelScopeText.isEmpty()) parts << m_channelScopeText;
        if (!m_readResultText.isEmpty()) parts << m_readResultText;
        if (!m_windowRangeText.isEmpty()) parts << m_windowRangeText;
        if (!m_writeResultText.isEmpty()) parts << m_writeResultText;
        m_summaryFullText = parts.join(QStringLiteral(" | "));
        applyElidedSummary();
    }

    void WorkbenchStatusBar::applyElidedSummary()
    {
        // 只省略"写入结果"这一段：它是唯一可能携带任意长度失败详情
        // （CommitReportSummary 可能附带失败原因细节串）的段落，其余三段都是格式
        // 固定、长度有界的短句，始终显示完整文字。可用宽度＝本控件宽度减去内容
        // 边距，再减去其余可见兄弟控件的估算宽度——这是一次性的粗略估算，不要求
        // 像素级精确，省略多一点或少一点不影响正确性，只影响好不好看。
        constexpr int kContentMargins = 8;   // rootLayout 左右内边距 4+4
        constexpr int kRowSpacing = 6;        // summaryRow 的控件间距
        int consumed = kRowSpacing * 7;       // summaryRow 里 8 个控件共 7 条间隔
        const QWidget* siblings[] = {
            m_protectionBadge, m_channelScopeLabel, m_separators[0], m_readResultLabel,
            m_separators[1], m_windowRangeLabel, m_separators[2], m_expandButton,
        };
        for (const QWidget* sibling : siblings)
        {
            if (sibling != nullptr && !sibling->isHidden())
            {
                consumed += sibling->sizeHint().width();
            }
        }
        const int totalWidth = width() > kContentMargins ? width() - kContentMargins : 10000;
        const int available = std::max(0, totalWidth - consumed);
        const QFontMetrics metrics(m_writeResultLabel->font());
        m_writeResultLabel->setText(metrics.elidedText(m_writeResultText, Qt::ElideRight, available));
    }

    void WorkbenchStatusBar::resizeEvent(QResizeEvent* event)
    {
        QWidget::resizeEvent(event);
        applyElidedSummary();
    }

    bool WorkbenchStatusBar::eventFilter(QObject* watched, QEvent* event)
    {
        if (watched == m_needsRereadLabel && event != nullptr
            && event->type() == QEvent::MouseButtonRelease)
        {
            emit rereadRequested();
        }
        return QWidget::eventFilter(watched, event);
    }
}
