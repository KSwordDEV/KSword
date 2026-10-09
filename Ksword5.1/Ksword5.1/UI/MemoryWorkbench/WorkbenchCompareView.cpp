// WorkbenchCompareView.cpp
// 作用：WorkbenchCompareModel 的实现与 WorkbenchCompareView 的搭建/数据流。
// 两段"待写入修改/两次读取之间"分别对应 ByteChangeKind::Pending/ExternalChange（后者经过
// D8/可疑点 7 的修复后不再直接等值比较 ChangeKind，见 isExternalChangeByte），行按绝对地址
// 16 字节对齐分组（可疑点 6），只保留命中当前分段的分组——且命中分组本身也不在这里把
// 文本一次性格式化好，真正的虚拟列表交给 WorkbenchCompareModel::data() 按需现算（D8）。

#include "WorkbenchCompareView.h"
#include "../../theme.h"
#include <QClipboard>
#include <QGuiApplication>
#include <QMenu>
#include <QPointer>
#include <QPersistentModelIndex>

#include "HexCanvasFormat.h"
#include "HexViewWidgets.h"

#include "../../theme.h"
#include "../../Internationalization/LanguageManager.h"

#include <QFont>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QTableView>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

namespace ks::ui
{
    namespace
    {
        using Kind = ksword::memwb::ByteChangeKind;

        // columnTitle：六列表头文字。D5：自定义模型的表头不会被 LanguageManager 的通用
        // 小部件扫描自动翻译，必须显式经 ks::i18n::displayText 转换（词条已在语言包里登记，
        // 本次未新增、未修改词条内容，只是在代码里接上这条翻译链路）。
        QString columnTitle(const int column)
        {
            switch (column)
            {
            case 0: return ks::i18n::displayText(QStringLiteral("地址"));
            case 1: return ks::i18n::displayText(QStringLiteral("旧值（十六进制）"));
            case 2: return ks::i18n::displayText(QStringLiteral("新值（十六进制）"));
            case 3: return ks::i18n::displayText(QStringLiteral("旧值（ASCII）"));
            case 4: return ks::i18n::displayText(QStringLiteral("新值（ASCII）"));
            case 5: return ks::i18n::displayText(QStringLiteral("变化数"));
            default: return QString();
            }
        }

        // byteHexToken：单字节的十六进制记号，不可用时用 "??"（与 HexCanvas 的不可读写法一致）。
        QString byteHexToken(const std::uint8_t value, const bool valid)
        {
            return valid ? QStringLiteral("%1").arg(value, 2, 16, QChar('0')).toUpper() : QStringLiteral("??");
        }

        // byteAsciiToken：单字节的 ASCII 字符，不可用用乘号，可读但不可见用点号。
        QChar byteAsciiToken(const std::uint8_t value, const bool valid)
        {
            if (!valid)
            {
                return QChar(hexcanvas_format::kUnreadableAsciiGlyph);
            }
            return hexcanvas_format::IsPrintableAscii(value) ? QChar(static_cast<char>(value)) : QChar(QLatin1Char('.'));
        }

        // modeHighlightColor：分段底色，公式与 HexCanvas.Paint.cpp 的 PaintPalette 完全一致。
        // D12：不在 setWindow/rebuildRows 时算好存进模型——数据没变但主题切换了的那段时间，
        // 缓存的颜色会是旧主题的；改成 data() 的 BackgroundRole 现取，下一次重绘就跟得上。
        QColor modeHighlightColor(const bool isPendingMode)
        {
            const QColor surface = KswordTheme::SurfaceColor();
            return isPendingMode
                ? KswordTheme::BlendColors(surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Orange), 120)
                : KswordTheme::BlendColors(surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Cyan), 105);
        }

        // resolveWindowIndex：把绝对地址换成 window 内部数组下标；地址落在窗口之外时传出
        // false（可疑点 6 的虚拟分组：分组覆盖的字节有一部分可能根本不在窗口范围内）。
        bool resolveWindowIndex(const WorkbenchByteWindow& window, const std::uint64_t address, std::size_t* indexOut)
        {
            if (address < window.address)
            {
                return false;
            }
            const std::uint64_t offset = address - window.address;
            const std::size_t effectiveLength = std::min(window.bytes.size(), window.validMask.size());
            if (offset >= effectiveLength)
            {
                return false;
            }
            *indexOut = static_cast<std::size_t>(offset);
            return true;
        }

        // resolveCompareByte：按当前分段取某个绝对地址的旧/新值与有效性；地址不在窗口内时
        // 两边都报不可用（而不是读到垃圾值）。Pending 分段：旧值=基线，新值=现值（含补丁）；
        // ExternalChange 分段：旧值=上次读取，新值=基线（这一次读取），与暂存补丁无关。
        void resolveCompareByte(
            const WorkbenchByteWindow& window, const bool isPendingMode, const std::uint64_t address,
            std::uint8_t* oldByte, bool* oldValid, std::uint8_t* newByte, bool* newValid)
        {
            *oldByte = 0;
            *newByte = 0;
            *oldValid = false;
            *newValid = false;
            std::size_t index = 0;
            if (!resolveWindowIndex(window, address, &index))
            {
                return;
            }
            if (isPendingMode)
            {
                if (index < window.baselineValidMask.size() && window.baselineValidMask[index] == 1
                    && index < window.baselineBytes.size())
                {
                    *oldValid = true;
                    *oldByte = window.baselineBytes[index];
                }
                if (index < window.validMask.size() && window.validMask[index] == 1)
                {
                    *newValid = true;
                    *newByte = window.bytes[index];
                }
            }
            else
            {
                if (index < window.previousValidMask.size() && window.previousValidMask[index] == 1
                    && index < window.previousBytes.size())
                {
                    *oldValid = true;
                    *oldByte = window.previousBytes[index];
                }
                if (index < window.baselineValidMask.size() && window.baselineValidMask[index] == 1
                    && index < window.baselineBytes.size())
                {
                    *newValid = true;
                    *newByte = window.baselineBytes[index];
                }
            }
        }

        // isExternalChangeByte：可疑点 7——"两次读取之间"分段该不该显示某个地址。
        // 不能直接用 window.changeKinds==ExternalChange：ChangeKind() 按 Pending >
        // SelfWritten > ExternalChange 的优先级，一个字节同时有暂存补丁又发生了外部变化时
        // 只会报 Pending，把"目标自己也变了"这件事藏起来——这正是本页最该提示的情形。
        // 这里保留 SelfWritten 的排除（自己确认写入的不算外部变化，这个判断是对的），但
        // Pending 分支额外用 previous/baseline 的原始值回补一次比较。
        bool isExternalChangeByte(const WorkbenchByteWindow& window, const std::size_t index)
        {
            if (index < window.changeKinds.size() && window.changeKinds[index] == Kind::SelfWritten)
            {
                return false;
            }
            // 无论着色是否开启，只有两侧确实捕获且字节不同才存在两次读取差异。
            const bool previousValid = index < window.previousValidMask.size() && window.previousValidMask[index] == 1;
            const bool baselineValid = index < window.baselineValidMask.size() && window.baselineValidMask[index] == 1;
            if (!previousValid || !baselineValid || index >= window.previousBytes.size() || index >= window.baselineBytes.size())
            {
                return false; // 任一边不可用，谈不上"变了"。
            }
            return window.previousBytes[index] != window.baselineBytes[index];
        }

        // matchesMode：某个绝对地址是否命中当前分段；Pending 分段仍然是直接的 ChangeKind
        // 相等比较（这部分审核报告没有提出异议），ExternalChange 分段改走 isExternalChangeByte。
        bool matchesMode(const WorkbenchByteWindow& window, const bool isPendingMode, const std::uint64_t address)
        {
            std::size_t index = 0;
            if (!resolveWindowIndex(window, address, &index))
            {
                return false;
            }
            if (isPendingMode)
            {
                // 证据差异不能依赖宿主是否打开着色：明确有效的现值与基线直接比较。
                return index < window.validMask.size() && window.validMask[index] == 1 &&
                    index < window.baselineValidMask.size() && window.baselineValidMask[index] == 1 &&
                    index < window.baselineBytes.size() && window.bytes[index] != window.baselineBytes[index];
            }
            return isExternalChangeByte(window, index);
        }
    }

    // ---------------- WorkbenchCompareModel ----------------

    WorkbenchCompareModel::WorkbenchCompareModel(QObject* parent) : QAbstractTableModel(parent)
    {
    }

    void WorkbenchCompareModel::setWindow(
        const WorkbenchByteWindow& window, const bool isPendingMode, const QVector<CompareGroupSummary>& groups)
    {
        const QPointer<WorkbenchCompareModel> alive(this);
        beginResetModel();
        if (!alive) return;
        m_provider = nullptr;
        m_window = window;
        m_address = window.address;
        m_length = static_cast<std::uint64_t>(window.bytes.size());
        m_isPendingMode = isPendingMode;
        m_groups = groups;
        endResetModel();
    }

    // setRange：保存缓存提供者和完整范围，文字/字节只在表格实际请求一行时读取。
    void WorkbenchCompareModel::setRange(IWorkbenchBytesProvider* provider, std::uint64_t address,
        std::uint64_t length, bool isPendingMode, const QVector<CompareGroupSummary>& groups)
    {
        const QPointer<WorkbenchCompareModel> alive(this);
        beginResetModel();
        if (!alive) return;
        m_window = {};
        m_provider = provider;
        m_address = address;
        m_length = length;
        m_isPendingMode = isPendingMode;
        m_groups = groups;
        endResetModel();
    }

    // firstRowAtOrAfter：分组列表按地址升序，二分找第一个 groupAddress >= address 的行。
    // 全部分组都在 address 之前就返回最后一行（离目标最近的变化）；没有分组返回 -1。
    int WorkbenchCompareModel::firstRowAtOrAfter(const std::uint64_t address) const
    {
        if (m_groups.isEmpty())
        {
            return -1;
        }
        const auto found = std::lower_bound(
            m_groups.begin(),
            m_groups.end(),
            address,
            [](const CompareGroupSummary& group, const std::uint64_t value) { return group.groupAddress < value; });
        if (found == m_groups.end())
        {
            return static_cast<int>(m_groups.size()) - 1;
        }
        return static_cast<int>(found - m_groups.begin());
    }

    int WorkbenchCompareModel::rowCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : m_groups.size();
    }

    int WorkbenchCompareModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : 6;
    }

    QVariant WorkbenchCompareModel::data(const QModelIndex& index, const int role) const
    {
        if (!index.isValid() || index.row() < 0 || index.row() >= m_groups.size())
        {
            return QVariant();
        }
        const CompareGroupSummary& group = m_groups.at(index.row());
        if (role == Qt::UserRole)
        {
            // 首组可能从窗口之前的 16 字节边界开始；导航只能落在真实窗口内。
            return QVariant::fromValue<qulonglong>(std::max(group.groupAddress, m_address));
        }
        if (role == Qt::BackgroundRole && index.column() >= 1 && index.column() <= 4 && group.changedCount > 0)
        {
            // D12：现取，不缓存——主题切换后下一次重绘就跟得上。
            return modeHighlightColor(m_isPendingMode);
        }
        if (role == Qt::FontRole && group.changedCount > 0)
        {
            QFont font;
            font.setBold(true);
            return font;
        }
        if (role == Qt::DisplayRole && index.column() == 0)
        {
            return hexcanvas_format::FormatAddress(group.groupAddress, 16);
        }
        if (role == Qt::DisplayRole && index.column() == 5)
        {
            return group.changedCount;
        }
        if ((role == Qt::DisplayRole && (index.column() >= 1 && index.column() <= 4)) || role == Qt::ToolTipRole)
        {
            // 首尾分组都夹在请求范围中；提供者单次上限不影响大范围的行数据。
            WorkbenchByteWindow fetched;
            const WorkbenchByteWindow* window = &m_window;
            if (m_provider && m_length)
            {
                const auto first = std::max(group.groupAddress, m_address);
                const auto offset = first - m_address;
                if (offset < m_length)
                {
                    const auto count = std::min(kGroupBytes - (first - group.groupAddress), m_length - offset);
                    fetched = m_provider->FetchWindow(first, count);
                    if (fetched.ok && fetched.address == first && fetched.bytes.size() <= count)
                        window = &fetched;
                }
            }
            // D8：十六进制/ASCII/悬停明细都在这里按需现算，不在 rebuildRows 时预先格式化。
            QString oldHex;
            QString newHex;
            QString oldAscii;
            QString newAscii;
            QString detail;
            for (std::uint64_t i = 0; i < kGroupBytes; ++i)
            {
                if (i > UINT64_MAX - group.groupAddress) break;
                const std::uint64_t address = group.groupAddress + i;
                std::uint8_t oldByte = 0;
                std::uint8_t newByte = 0;
                bool oldValid = false;
                bool newValid = false;
                resolveCompareByte(*window, m_isPendingMode, address, &oldByte, &oldValid, &newByte, &newValid);
                if (i != 0)
                {
                    oldHex += QLatin1Char(' ');
                    newHex += QLatin1Char(' ');
                }
                oldHex += byteHexToken(oldByte, oldValid);
                newHex += byteHexToken(newByte, newValid);
                oldAscii += byteAsciiToken(oldByte, oldValid);
                newAscii += byteAsciiToken(newByte, newValid);
                if (role == Qt::ToolTipRole && matchesMode(*window, m_isPendingMode, address))
                {
                    detail += hexcanvas_format::FormatAddress(address, 16) + QStringLiteral("  ")
                        + byteHexToken(oldByte, oldValid) + QStringLiteral(" → ") + byteHexToken(newByte, newValid);
                    // 可疑点 7：在"两次读取之间"视图里，这个字节如果同时还挂着一笔暂存补丁，
                    // 额外标注一下——它既是外部变了，也即将被我们的写入覆盖掉。
                    std::size_t rawIndex = 0;
                    if (!m_isPendingMode && resolveWindowIndex(*window, address, &rawIndex)
                        && rawIndex < window->changeKinds.size() && window->changeKinds[rawIndex] == Kind::Pending)
                    {
                        // N6（第二轮审核）：这段文案走的是模型 ToolTipRole，不会被
                        // LanguageManager 的通用小部件扫描自动翻译（那只对 setToolTip 的
                        // 控件生效）；必须像表头/状态行一样显式经 displayText 转换，否则
                        // en-US 下悬停明细仍然混着一句中文（词条已在语言包里登记）。
                        detail += ks::i18n::displayText(QStringLiteral("（另有待写入）"));
                    }
                    detail += QLatin1Char('\n');
                }
            }
            if (role == Qt::ToolTipRole)
            {
                return detail;
            }
            switch (index.column())
            {
            case 1: return oldHex;
            case 2: return newHex;
            case 3: return oldAscii;
            case 4: return newAscii;
            default: return QVariant();
            }
        }
        return QVariant();
    }

    QVariant WorkbenchCompareModel::headerData(const int section, const Qt::Orientation orientation, const int role) const
    {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        {
            return section == 0 && m_fileOffsets
                ? ks::i18n::sourceText(QStringLiteral("文件偏移")) : columnTitle(section);
        }
        return QAbstractTableModel::headerData(section, orientation, role);
    }

    void WorkbenchCompareModel::setFileOffsetCoordinates(bool fileOffsets)
    {
        if (m_fileOffsets == fileOffsets) return;
        m_fileOffsets = fileOffsets;
        emit headerDataChanged(Qt::Horizontal, 0, 0);
    }

    void WorkbenchCompareView::setFileOffsetCoordinates(bool fileOffsets)
    {
        m_model->setFileOffsetCoordinates(fileOffsets);
    }

    // ---------------- WorkbenchCompareView ----------------

    WorkbenchCompareView::WorkbenchCompareView(QWidget* parent) : QWidget(parent)
    {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(4);

        auto* topBar = new QHBoxLayout;
        topBar->setContentsMargins(4, 4, 4, 0);
        m_modeSegmented = new HexViewSegmented({QStringLiteral("待写入修改"), QStringLiteral("两次读取之间")}, this);
        m_modeSegmented->setSegmentToolTip(0, QStringLiteral("显示本窗口内尚未写入目标的暂存修改（橙色）"));
        m_modeSegmented->setSegmentToolTip(1, QStringLiteral("显示本窗口内与上一次读取不同的字节（青色）"));
        connect(m_modeSegmented, &HexViewSegmented::currentIndexChanged, this, [this](int) { rebuildRows(); });
        topBar->addWidget(m_modeSegmented);
        topBar->addStretch(1);
        layout->addLayout(topBar);

        m_model = new WorkbenchCompareModel(this);
        m_table = new QTableView(this);
        m_table->setObjectName(QStringLiteral("ksMemwbCompareTable"));
        m_table->setModel(m_model);
        m_table->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_table->setSelectionMode(QAbstractItemView::SingleSelection);
        m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_table->verticalHeader()->hide();
        m_table->horizontalHeader()->setStretchLastSection(true);
        m_table->setAlternatingRowColors(true);
        layout->addWidget(m_table, 1);
        // 相同模型提供导航和原始字节复制，避免静态宿主再维护一张旧比较表。
        connect(m_table, &QTableView::doubleClicked, this, [this](const QModelIndex& index) {
            if (index.isValid()) emit requestHexLocate(index.data(Qt::UserRole).toULongLong());
        });
        m_table->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(m_table, &QTableView::customContextMenuRequested, this, [this](const QPoint& point) {
            const QPersistentModelIndex index(m_table->indexAt(point));
            if (!index.isValid()) return;
            const auto address = index.data(Qt::UserRole).toULongLong();
            const auto before = m_model->index(index.row(), 1).data().toString();
            const auto after = m_model->index(index.row(), 2).data().toString();
            const QPointer<WorkbenchCompareView> alive(this);
            QPointer<QMenu> menu = new QMenu(this);
            menu->setStyleSheet(KswordTheme::ContextMenuStyle());
            auto* copyAddress = menu->addAction(ks::i18n::sourceText(QStringLiteral("复制地址")));
            auto* copyBefore = menu->addAction(ks::i18n::sourceText(QStringLiteral("复制基线字节")));
            auto* copyAfter = menu->addAction(ks::i18n::sourceText(QStringLiteral("复制当前字节")));
            auto* locate = menu->addAction(ks::i18n::sourceText(QStringLiteral("在十六进制视图中定位")));
            const auto* action = menu->exec(m_table->viewport()->mapToGlobal(point));
            if (!alive || !menu) return;
            const bool addressChosen = action == copyAddress;
            const bool beforeChosen = action == copyBefore;
            const bool afterChosen = action == copyAfter;
            const bool locateChosen = action == locate;
            delete menu.data();
            if (addressChosen) QGuiApplication::clipboard()->setText(hexcanvas_format::FormatAddress(address, 16));
            if (beforeChosen) QGuiApplication::clipboard()->setText(before);
            if (afterChosen) QGuiApplication::clipboard()->setText(after);
            // 模型在模态菜单期间被刷新时旧索引失效，不能拿旧地址跳转新目标。
            if (alive && locateChosen && index.isValid()) emit requestHexLocate(address);
        });

        m_status = new QLabel(this);
        m_status->setObjectName(QStringLiteral("ksMemwbCompareStatus"));
        m_status->setWordWrap(true);
        m_status->setText(QStringLiteral("尚未定位；跟随十六进制页的当前窗口。"));
        layout->addWidget(m_status);
    }

    void WorkbenchCompareView::setBytesProvider(IWorkbenchBytesProvider* provider)
    {
        m_provider = provider;
        rebuildRows();
    }

    void WorkbenchCompareView::setWindow(const std::uint64_t address, const std::uint64_t length)
    {
        m_address = address;
        m_length = length;
        m_hasWindow = true;
        rebuildRows();
    }

    // reset：回到"尚未定位"——窗口清零、hasWindow 置假，rebuildRows 显示占位文案并清空模型。
    void WorkbenchCompareView::reset()
    {
        m_address = 0;
        m_length = 0;
        m_hasWindow = false;
        rebuildRows();
    }

    // scrollToAddress：滚到并选中第一个分组地址 >= address 对齐到 16 字节的行。
    void WorkbenchCompareView::scrollToAddress(const std::uint64_t address)
    {
        const std::uint64_t alignedAddress = address - (address % kGroupBytes);
        const int row = m_model->firstRowAtOrAfter(alignedAddress);
        if (row < 0)
        {
            return;
        }
        m_table->selectRow(row);
        m_table->scrollTo(m_model->index(row, 0), QAbstractItemView::PositionAtTop);
    }

    void WorkbenchCompareView::setMode(const Mode mode)
    {
        if (static_cast<int>(mode) == m_modeSegmented->currentIndex())
        {
            return;
        }
        m_modeSegmented->setCurrentIndex(static_cast<int>(mode));
        // setCurrentIndex 已经通过 currentIndexChanged 触发过一次 rebuildRows，这里不再重复
        // 调用（D8 顺带修的小问题：旧代码在这里又调了一次，等于同一次切换重建两遍模型）。
    }

    WorkbenchCompareView::Mode WorkbenchCompareView::mode() const
    {
        return static_cast<Mode>(m_modeSegmented->currentIndex());
    }

    void WorkbenchCompareView::refreshView()
    {
        rebuildRows();
    }

    QTableView* WorkbenchCompareView::table() const
    {
        return m_table;
    }

    WorkbenchCompareModel* WorkbenchCompareView::model() const
    {
        return m_model;
    }

    // minimumSizeHint：见头文件声明处的注释——故意返回一个很小的固定值，不让
    // m_table 的列宽偏好向上传播成宿主的硬性下限（与 WorkbenchHexPane::
    // minimumSizeHint 同一处理方式）。
    QSize WorkbenchCompareView::minimumSizeHint() const
    {
        return QSize(1, 1);
    }

    // rebuildRows：按当前窗口与分段重新计算命中分组；无上次读取时整段隐藏表格显示旧文案。
    // D8：只做整数比较找出命中分组（changedCount），不在这里格式化任何十六进制/ASCII 文本——
    // 那些留给 WorkbenchCompareModel::data() 按需现算，这样"1 MiB 全部无变化"的窗口只是
    // 扫一遍整数、不分配任何字符串；"1 MiB 全部有变化"也不会在这一刻就把 65536 行的文本
    // 全部建好，只建命中分组的摘要（地址+计数两个整数）。
    void WorkbenchCompareView::rebuildRows()
    {
        const QPointer<WorkbenchCompareView> alive(this); // 模型 reset 通知可以关闭所属宿主。
        const Mode activeMode = mode();
        const bool isPendingMode = activeMode == Mode::Pending;
        m_totalChanged = 0;
        m_compared = 0;
        if (m_provider == nullptr || !m_hasWindow)
        {
            m_model->setWindow(WorkbenchByteWindow(), isPendingMode, {});
            if (!alive) return;
            m_status->setText(m_provider == nullptr
                ? QStringLiteral("尚未接入数据源。")
                : QStringLiteral("尚未定位；跟随十六进制页的当前窗口。"));
            return;
        }
        if (activeMode == Mode::ExternalChange && !m_provider->HasPreviousRead())
        {
            // 沿用旧文案（MemoryEditorWidget.cpp:746），一字不改。
            m_model->setWindow(WorkbenchByteWindow(), isPendingMode, {});
            if (!alive) return;
            m_status->setText(QStringLiteral("没有上次相同目标和范围的读取可供对比。"));
            return;
        }
        // 范围预算与单次读取预算分别检查；超限不能退化成只比较前一部分。
        if (m_length > kMaxWindowBytes || (m_length && m_length - 1 > UINT64_MAX - m_address))
        {
            m_model->setWindow(WorkbenchByteWindow(), isPendingMode, {});
            if (!alive) return;
            m_status->setText(ks::i18n::sourceText(QStringLiteral("比较范围无效或超过 64 MiB；未执行比较，请缩小捕获范围。")));
            return;
        }
        QVector<CompareGroupSummary> groups;
        constexpr std::uint64_t chunkLimit = 64ULL * 1024ULL; // 兼容实时 64 KiB 与快照 1 MiB 提供者。
        std::uint64_t offset = 0; // 全范围已处理前缀，不以提供者返回长度冒充总范围。
        while (offset < m_length)
        {
            const auto address = m_address + offset;
            const auto requested = std::min(chunkLimit, m_length - offset);
            const WorkbenchByteWindow window = m_provider->FetchWindow(address, requested);
            const bool shapeValid = window.ok && window.address == address && window.bytes.size() <= requested;
            const auto available = shapeValid ? static_cast<std::uint64_t>(window.bytes.size()) : 0;
            for (std::uint64_t i = 0; i < available; ++i)
            {
                const auto at = static_cast<std::size_t>(i);
                // 不可用/加载中/掩码不完整都不计入已比较数，也不被补零当成无变化。
                const bool baselineValid = at < window.baselineBytes.size()
                    && at < window.baselineValidMask.size() && window.baselineValidMask[at] == 1;
                const bool otherValid = isPendingMode
                    ? at < window.validMask.size() && window.validMask[at] == 1
                    : at < window.previousBytes.size() && at < window.previousValidMask.size()
                        && window.previousValidMask[at] == 1 && at < window.validMask.size();
                if (!baselineValid || !otherValid) continue;
                ++m_compared;
                const auto byteAddress = address + i;
                if (!matchesMode(window, isPendingMode, byteAddress)) continue;
                const auto groupAddress = byteAddress - byteAddress % kGroupBytes;
                // 跨块边界的同一分组必须合并；非 16 对齐起点不会产生重复行。
                if (!groups.isEmpty() && groups.last().groupAddress == groupAddress)
                {
                    ++groups.last().changedCount;
                }
                else groups.push_back({groupAddress, 1});
                ++m_totalChanged;
            }
            // 提供者有更小的单 call 预算时顺序续取，不跳过被截短的真实尾部。
            // 完全失败则跳过本次请求块，并在最终总计注明这部分没有完成比较。
            offset += available ? available : requested;
        }
        m_model->setRange(m_provider, m_address, m_length, isPendingMode, groups);
        if (!alive) return;
        if (m_compared < m_length)
        {
            m_status->setText(ks::i18n::sourceText(QStringLiteral("比较未完成：已比较 %1/%2 字节；已确认 %3 字节变化，共 %4 行。"))
                .arg(m_compared).arg(m_length).arg(m_totalChanged).arg(groups.size()));
        }
        else
        {
            m_status->setText(ks::i18n::sourceText(QStringLiteral("完整比较 %1 字节；%2 字节变化；共 %3 行；悬停可查看逐字节明细。"))
                .arg(m_length).arg(m_totalChanged).arg(groups.size()));
        }
    }
}
