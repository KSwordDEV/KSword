// WorkbenchDisasmView.cpp
// 作用：WorkbenchDisasmModel 的实现、WorkbenchDisasmView 的搭建/数据流/导航/重同步算法。
// 行内编辑委托与汇编预览对话框在 WorkbenchDisasmView.Edit.cpp（本文件只留转发声明）。

#include "WorkbenchDisasmView.h"
#include "MemoryRowCanvas.h"
#include <QLineEdit>

#include "HexCanvasFormat.h"
#include "HexViewWidgets.h"

#include "../../theme.h"
#include "../../Internationalization/LanguageManager.h"
#include "../ThemeStatusRole.h"

#include <QAction>
#include <QClipboard>
#include <QEvent>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QKeyEvent>
#include <QLabel>
#include <QMenu>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QScrollBar>
#include <QSet>
#include <QTableView>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

namespace ks::ui
{
    namespace
    {
        // kColumnCount：地址/字节/助记符/操作数，与旧 QTableWidget 列序一致，方便复用阅读习惯。
        constexpr int kColumnCount = 4;

        // columnTitle：表头文字，纯函数方便复用到 headerData。
        // D5：自定义 QAbstractTableModel 的表头不会被 LanguageManager 的通用小部件扫描
        // 自动翻译（它只对 QTableView::setHeaderData 生效，本模型不走那条路），必须显式
        // 经 ks::i18n::displayText 把中文源文本换成当前语言包的文本；三个词条已在
        // languages/zh-CN.json、en-US.json 里登记过（本次未新增、未修改词条内容）。
        QString columnTitle(const int column)
        {
            switch (column)
            {
            case 0: return ks::i18n::displayText(QStringLiteral("地址"));
            case 1: return ks::i18n::displayText(QStringLiteral("字节"));
            case 2: return ks::i18n::displayText(QStringLiteral("指令"));
            case 3: return ks::i18n::displayText(QStringLiteral("操作数"));
            default: return QString();
            }
        }

        // kBranchMnemonics：可疑点 2——Enter 跟随跳转只应该对"分支类"指令生效。旧实现只看
        // 操作数文本是否形如 "0x..."，于是 push 0x10 / ret 0x8 / int 0x2E 这类把立即数当成
        // 操作数、但语义上根本不是跳转目标的指令也会被误跟随：污染后退栈，还让这些行无法
        // 用 Enter 进入行内编辑。这里把 Zydis 输出的小写助记符白名单列出来。
        // N1（第二轮审核）：Zydis 对 73/77/7D/7F 以及 0F 83/87/8D/8F 这四组条件跳转实际输出
        // 的助记符是 jnb/jnbe/jnl/jnle，不是常见写法 jae/ja/jge/jg（两者是同一条指令的别名，
        // Zydis 固定选了"取反"那一种拼法）；漏掉这四个会让这组最常见的条件跳转按 Enter 时
        // 进了行内编辑而不是跟随跳转。白名单必须按 Zydis 真实输出的拼法登记，不能按手写的
        // "常见助记符"直觉补全——这正是本条缺陷的根因，所以这里逐一列出两种拼法都在的情况，
        // 并在夹具里给白名单每一项都配一个用例（T05/T06），不再靠直觉判断够不够全。
        const QSet<QString>& branchMnemonics()
        {
            static const QSet<QString> mnemonics{
                QStringLiteral("call"), QStringLiteral("jmp"),
                QStringLiteral("je"), QStringLiteral("jne"), QStringLiteral("jz"), QStringLiteral("jnz"),
                QStringLiteral("ja"), QStringLiteral("jae"), QStringLiteral("jb"), QStringLiteral("jbe"),
                QStringLiteral("jg"), QStringLiteral("jge"), QStringLiteral("jl"), QStringLiteral("jle"),
                QStringLiteral("jo"), QStringLiteral("jno"), QStringLiteral("js"), QStringLiteral("jns"),
                QStringLiteral("jp"), QStringLiteral("jnp"), QStringLiteral("jpe"), QStringLiteral("jpo"),
                QStringLiteral("jc"), QStringLiteral("jnc"),
                QStringLiteral("jnb"), QStringLiteral("jnbe"), QStringLiteral("jnl"), QStringLiteral("jnle"),
                QStringLiteral("jcxz"), QStringLiteral("jecxz"), QStringLiteral("jrcxz"),
                QStringLiteral("loop"), QStringLiteral("loope"), QStringLiteral("loopne"),
                QStringLiteral("loopz"), QStringLiteral("loopnz")};
            return mnemonics;
        }

        // formatHexDigitsUpper：D4——只把"数字部分"转成大写十六进制，固定宽度左补零，
        // 不带 "0x" 前缀。旧代码对拼好的整条模板字符串调用 toUpper()，会连模板里的英文字面量
        // （"Enter"/"Backspace"）一起大写，破坏 LanguageManager 的大小写敏感模板匹配
        // （运行时翻译因此静默失效）。正确做法是只对这一小段数字字符串大写，再 .arg() 进
        // 保持原样的模板（模板文本必须与语言包里已登记的词条逐字节一致）。
        QString formatHexDigitsUpper(const quint64 value, const int width)
        {
            return QString::number(value, 16).rightJustified(width, QChar('0')).toUpper();
        }

        QString decodedStatus(quint64 anchor, int count, bool x64, bool editable)
        {
            return (editable
                ? QStringLiteral("从 0x%1 解码 %2 条指令（%3）。双击/F2/Enter 行内编辑，Backspace 返回跳转。")
                : QStringLiteral("从 0x%1 解码 %2 条指令（%3，只读）。Backspace 返回跳转。"))
                .arg(formatHexDigitsUpper(anchor, 16)).arg(count)
                .arg(x64 ? QStringLiteral("x64") : QStringLiteral("x86"));
        }

        // rowChangeKind：一行覆盖的若干字节里，取"最该被看见"的那一种变化种类用于着色，
        // 优先级与 MemoryDiffOverlay::ChangeKind 一致：Pending > SelfWritten > ExternalChange。
        // 入参：窗口与该行在窗口内的字节偏移、长度；传出：变化种类，窗口越界时视为 Unchanged。
        ksword::memwb::ByteChangeKind rowChangeKind(
            const WorkbenchByteWindow& window, const std::uint64_t offset, const std::uint64_t length)
        {
            using Kind = ksword::memwb::ByteChangeKind;
            bool sawExternal = false;
            bool sawSelf = false;
            for (std::uint64_t i = 0; i < length; ++i)
            {
                const std::uint64_t index = offset + i;
                if (index >= window.changeKinds.size())
                {
                    continue;
                }
                const Kind kind = window.changeKinds[static_cast<std::size_t>(index)];
                if (kind == Kind::Pending)
                {
                    return Kind::Pending;
                }
                sawSelf |= kind == Kind::SelfWritten;
                sawExternal |= kind == Kind::ExternalChange;
            }
            if (sawSelf)
            {
                return Kind::SelfWritten;
            }
            if (sawExternal)
            {
                return Kind::ExternalChange;
            }
            return Kind::Unchanged;
        }

        // changeKindBackground：把变化种类映射成底色，公式与 HexCanvas.Paint.cpp 的
        // PaintPalette 完全一致（暖色=暂存、冷色=外部变化、淡色=自己写入），保持两处视觉一致。
        QColor changeKindBackground(const ksword::memwb::ByteChangeKind kind)
        {
            using Kind = ksword::memwb::ByteChangeKind;
            const QColor surface = KswordTheme::SurfaceColor();
            switch (kind)
            {
            case Kind::Pending:
                return KswordTheme::BlendColors(surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Orange), 120);
            case Kind::ExternalChange:
                return KswordTheme::BlendColors(surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Cyan), 105);
            case Kind::SelfWritten:
                return KswordTheme::BlendColors(surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Green), 70);
            default:
                return QColor();
            }
        }

        // kFollowOperandPattern：操作数文本是否"单个立即数/绝对地址"——Zydis 输出的分支目标
        // 形如 "0x7FF600001000"，纯数字记法也认；带寄存器/逗号/方括号的一律不算单个地址。
        const QRegularExpression& followOperandPattern()
        {
            static const QRegularExpression pattern(QStringLiteral("^0[xX][0-9A-Fa-f]+$"));
            return pattern;
        }
    }

    // ---------------- WorkbenchDisasmModel ----------------

    WorkbenchDisasmModel::WorkbenchDisasmModel(QObject* parent) : QAbstractTableModel(parent)
    {
    }

    // setRows：整体替换行数据；窗口末尾不完整时追加一条提示行，见文件头"四"。
    void WorkbenchDisasmModel::setRows(
        const QVector<DecodedRow>& rows,
        const QVector<ksword::memwb::ByteChangeKind>& rowKinds,
        const QString& endOfWindowNote)
    {
        beginResetModel();
        m_rows = rows;
        m_rowKinds = rowKinds;
        m_endOfWindowNote = endOfWindowNote;
        endResetModel();
    }

    std::optional<DecodedRow> WorkbenchDisasmModel::rowAt(const int row) const
    {
        if (row < 0 || row >= m_rows.size())
        {
            return std::nullopt;
        }
        return m_rows.at(row);
    }

    // isEndOfWindowRow：提示行是真正追加在 m_rows 之后的一条合成行（下标恰好等于
    // m_rows.size()），不是把最后一条真实指令行借用/覆盖显示——否则真实指令（例如本该可以
    // 跟随跳转的最后一行）会被提示文案顶替，连带编辑、跟随跳转等交互都会读到假数据。
    bool WorkbenchDisasmModel::isEndOfWindowRow(const int row) const
    {
        return !m_endOfWindowNote.isEmpty() && row == m_rows.size();
    }

    int WorkbenchDisasmModel::rowCount(const QModelIndex& parent) const
    {
        if (parent.isValid())
        {
            return 0;
        }
        return m_rows.size() + (m_endOfWindowNote.isEmpty() ? 0 : 1);
    }

    int WorkbenchDisasmModel::columnCount(const QModelIndex& parent) const
    {
        return parent.isValid() ? 0 : kColumnCount;
    }

    QVariant WorkbenchDisasmModel::data(const QModelIndex& index, const int role) const
    {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount())
        {
            return QVariant();
        }
        const bool endRow = isEndOfWindowRow(index.row());
        if (endRow)
        {
            // 合成的提示行：只在第一列显示文案，其余列留空；不是真实指令，不参与着色。
            // D5：提示行文案不是目标内容，是本组件自己的 UI 文案，必须经 displayText 翻译
            // （m_endOfWindowNote 本身存的是中文源文本，见 rebuildRowsNow）。
            if (role == Qt::DisplayRole || role == Qt::EditRole)
            {
                return index.column() == 0 ? ks::i18n::displayText(m_endOfWindowNote) : QVariant();
            }
            if (role == Qt::ForegroundRole)
            {
                return KswordTheme::TextSecondaryColor();
            }
            if (role == Qt::ToolTipRole)
            {
                return ks::i18n::displayText(QStringLiteral("已超出本次读取到的窗口，继续浏览需要重新定位或重读。"));
            }
            return QVariant();
        }
        const DecodedRow& row = m_rows.at(index.row());
        if (role == Qt::DisplayRole || role == Qt::EditRole)
        {
            switch (index.column())
            {
            case 0: return hexcanvas_format::FormatAddress(row.address, 16);
            case 1: return hexcanvas_format::FormatHexText(row.bytes);
            case 2: return row.mnemonic;
            case 3: return row.operands;
            default: return QVariant();
            }
        }
        if (role == Qt::BackgroundRole && index.row() < m_rowKinds.size())
        {
            const QColor color = changeKindBackground(m_rowKinds.at(index.row()));
            if (color.isValid())
            {
                return color;
            }
        }
        if (role == Qt::ForegroundRole && !row.decoded)
        {
            return KswordTheme::TextSecondaryColor();
        }
        return QVariant();
    }

    QVariant WorkbenchDisasmModel::headerData(const int section, const Qt::Orientation orientation, const int role) const
    {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        {
            return columnTitle(section);
        }
        return QAbstractTableModel::headerData(section, orientation, role);
    }

    Qt::ItemFlags WorkbenchDisasmModel::flags(const QModelIndex& index) const
    {
        if (!index.isValid())
        {
            return Qt::NoItemFlags;
        }
        Qt::ItemFlags result = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
        // 只有指令/助记符/操作数列在"行内编辑"场景下可编辑；提示行与地址/字节列始终只读。
        if (index.column() >= 2 && !isEndOfWindowRow(index.row()))
        {
            result |= Qt::ItemIsEditable;
        }
        return result;
    }

    // ---------------- DecodeWindowResynced ----------------

    // 纯函数重同步算法：见 WorkbenchDisasmView.h 文件头"三"。
    QVector<DecodedRow> DecodeWindowResynced(
        const std::vector<std::uint8_t>& bytes,
        const std::uint64_t baseAddress,
        const DecodeOneFn& decodeOne,
        const std::uint32_t maxInstructions,
        const bool x64)
    {
        QVector<DecodedRow> rows;
        if (bytes.empty() || !decodeOne)
        {
            return rows;
        }
        std::size_t offset = 0;
        while (offset < bytes.size() && static_cast<std::uint32_t>(rows.size()) < maxInstructions)
        {
            // 地址溢出是调用方的职责（提供者已经把窗口裁在合法范围内），这里只防御性地跳过。
            if (baseAddress > std::numeric_limits<std::uint64_t>::max() - offset)
            {
                break;
            }
            const std::uint64_t address = baseAddress + offset;
            const std::size_t available = bytes.size() - offset;
            std::optional<DecodedRow> decoded = decodeOne(bytes.data() + offset, available, address, x64);
            if (decoded.has_value() && decoded->decoded && !decoded->bytes.isEmpty()
                && static_cast<std::size_t>(decoded->bytes.size()) <= available)
            {
                rows.push_back(*decoded);
                offset += static_cast<std::size_t>(decoded->bytes.size());
                continue;
            }
            // 后端在此处失败：只把这一个字节标成 db，下一轮从 offset+1 重新调用 decodeOne，
            // 这就是"重同步"——不会像旧降级解码器一样整段改用猜测式解码。
            DecodedRow dbRow;
            dbRow.address = address;
            dbRow.bytes = QByteArray(1, static_cast<char>(bytes[offset]));
            dbRow.mnemonic = QStringLiteral("db");
            dbRow.operands = QStringLiteral("0x%1").arg(formatHexDigitsUpper(bytes[offset], 2));
            dbRow.decoded = false;
            rows.push_back(dbRow);
            offset += 1;
        }
        return rows;
    }

    // ---------------- WorkbenchDisasmView ----------------

    WorkbenchDisasmView::WorkbenchDisasmView(QWidget* parent) : QWidget(parent)
    {
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(4);

        // 顶部条：x86/x64 分段钮——ux.md 4.2 要求架构选择移到本页，默认取 provider 的位数。
        auto* topBar = new QHBoxLayout;
        topBar->setContentsMargins(4, 4, 4, 0);
        m_archSegmented = new HexViewSegmented({QStringLiteral("x86"), QStringLiteral("x64")}, this);
        m_archSegmented->setSegmentToolTip(0, QStringLiteral("按 32 位寻址与指令集解码"));
        m_archSegmented->setSegmentToolTip(1, QStringLiteral("按 64 位寻址与指令集解码"));
        connect(m_archSegmented, &HexViewSegmented::currentIndexChanged, this, [this](int) {
            // 架构选择真正变化后，旧行内或模态汇编结果不能继续沿用原架构提交。
            ++m_editContextRevision;
            // D3：currentIndexChanged 在"用户点击"与"程序化 setCurrentIndex"两种场景下都会
            // 触发；m_programmaticArchChange 由 setAddressBits/setBytesProvider 在自己调用
            // setCurrentIndex 前后置位，只有不在这个窗口内触发的变化才算用户真的点了分段钮。
            if (m_programmaticArchChange)
            {
                rebuildRows();
                return;
            }
            m_x64Override = true;
            m_x64OverrideValue = m_archSegmented->currentIndex() == 1;
            rebuildRows();
            emit architectureChanged(isX64());
        });
        topBar->addWidget(m_archSegmented);
        topBar->addStretch(1);
        layout->addLayout(topBar);

        m_findBar = new QWidget(this);
        auto* findLayout = new QHBoxLayout(m_findBar);
        findLayout->setContentsMargins(0, 0, 0, 0);
        m_findEdit = new QLineEdit(m_findBar);
        m_findEdit->setObjectName(QStringLiteral("ksMemwbDisasmFind"));
        m_findEdit->setPlaceholderText(ks::i18n::sourceText(QStringLiteral("查找指令、操作数或 HEX")));
        auto* findButton = new QPushButton(ks::i18n::sourceText(QStringLiteral("下一处")), m_findBar);
        findLayout->addWidget(m_findEdit, 1);
        findLayout->addWidget(findButton);
        connect(m_findEdit, &QLineEdit::returnPressed, this, &WorkbenchDisasmView::findNext);
        connect(findButton, &QPushButton::clicked, this, &WorkbenchDisasmView::findNext);
        m_findEdit->installEventFilter(this);
        m_findBar->hide();
        layout->addWidget(m_findBar);

        m_model = new WorkbenchDisasmModel(this);
        m_canvas = new MemoryRowCanvas(this);
        m_canvas->setObjectName(QStringLiteral("ksMemwbDisasmCanvas"));
        m_canvas->setContentTitle(QStringLiteral("反汇编 + 操作数"));
        m_canvas->setBranchGutterVisible(true);
        m_canvas->installEventFilter(this);
        connect(m_canvas, &MemoryRowCanvas::contextMenuRequested, this, &WorkbenchDisasmView::showContextMenu);
        connect(m_canvas, &MemoryRowCanvas::selectionChanged, this, &WorkbenchDisasmView::selectionChanged);
        connect(m_canvas, &MemoryRowCanvas::rowActivated, this, &WorkbenchDisasmView::beginRowEdit);
        connect(m_canvas, &MemoryRowCanvas::requestMore, this, &WorkbenchDisasmView::browseMore);
        layout->addWidget(m_canvas, 1);

        // 状态行：解码来源、行数、交互提示；越过显示宽度时交给 QLabel 自己省略。
        m_status = new QLabel(this);
        m_status->setObjectName(QStringLiteral("ksMemwbDisasmStatus"));
        m_status->setWordWrap(false);
        m_status->setText(QStringLiteral("尚未定位；在地址条输入地址或使用跳转到此处。"));
        layout->addWidget(m_status);

        // 行内编辑错误提示：覆盖在表格视口上方，默认隐藏；见 .Edit.cpp。
        // D12（主题）：背景/边框用动态 palette token（SurfaceAltHex/BorderHex 直接返回
        // "palette(alternate-base)" 这类字符串，Qt 样式引擎每次重绘自己取当前调色板，
        // 天然跟随主题切换），但不在这里写死文字颜色——语义"错误色"不是 QPalette 能表达的
        // 角色，必须交给 ApplyStatusRole 对接的全局样式块（见下面的调用），否则跟旧写法
        // 一样是构造期烧死的 #RRGGBB，深浅主题切换后红框配色不会变。
        m_inlineError = new QLabel(m_canvas->viewport());
        m_inlineError->setObjectName(QStringLiteral("ksMemwbDisasmInlineError"));
        m_inlineError->hide();
        m_inlineError->setWordWrap(true);
        m_inlineError->setStyleSheet(QStringLiteral("background-color:%1;border:1px solid %2;padding:2px 4px;")
            .arg(KswordTheme::SurfaceAltHex(), KswordTheme::BorderHex()));
        ApplyStatusRole(m_inlineError, StatusRole::Error);

    }

    WorkbenchDisasmView::~WorkbenchDisasmView() = default;

    void WorkbenchDisasmView::setBytesProvider(IWorkbenchBytesProvider* provider)
    {
        // D3："目标变化重新取"：provider 指针变了（含 nullptr<->非空）就认为切了目标，
        // 忘记上一个目标下的用户覆盖，让新 provider->AddressBits() 重新生效为默认值；
        // 否则在 64 位目标上手动切过架构后，再换到一个 32 位目标会被锁死显示成 64 位。
        if (provider != m_provider)
        {
            m_canvas->cancelPendingNavigation();
            ++m_editContextRevision;
            m_x64Override = false;
            // N4（第二轮审核）：正在编辑的内容是针对"旧目标"冻结的地址/原字节（见
            // installEditDelegate 的 createEditor），换了目标后这段编辑必须作废——否则
            // Enter 提交时会把旧目标的编辑结果当成对新目标的写入请求发出去。下面马上会
            // 无条件 rebuildRows()，这里不用再补一次"推迟的刷新"，直接丢弃即可。
            if (m_editingActive)
            {
                cancelInlineEdit();
                m_refreshPending = false;
            }
        }
        m_provider = provider;
        if (m_provider != nullptr && !m_x64Override)
        {
            m_programmaticArchChange = true;
            m_archSegmented->setCurrentIndex(m_provider->AddressBits() > 32 ? 1 : 0);
            m_programmaticArchChange = false;
        }
        rebuildRows();
    }

    void WorkbenchDisasmView::setDecodeBackend(DecodeOneFn backend)
    {
        // 后端替换也使已打开编辑器的解码边界和预览失效。
        ++m_editContextRevision;
        m_decodeOne = std::move(backend);
        rebuildRows();
    }

    void WorkbenchDisasmView::setAssembleBackend(AssembleOneFn backend)
    {
        ++m_editContextRevision;
        m_assembleOne = std::move(backend);
    }

    void WorkbenchDisasmView::setOperandTargetResolver(OperandTargetResolver resolver)
    {
        m_operandTargetResolver = std::move(resolver);
    }

    void WorkbenchDisasmView::setAddressBits(int bits)
    {
        if (!m_x64Override)
        {
            // 没有用户显式覆盖时，外部给的位数（例如物理范围手选）直接驱动分段按钮显示；
            // D3：程序化调用 setCurrentIndex 不算用户覆盖，用标志位把这次信号发射标记出来，
            // 避免 currentIndexChanged 槛里把它误判成"用户点了一下"。
            m_programmaticArchChange = true;
            m_archSegmented->setCurrentIndex(bits > 32 ? 1 : 0);
            m_programmaticArchChange = false;
            rebuildRows();
        }
    }

    bool WorkbenchDisasmView::isX64() const
    {
        return m_x64Override ? m_x64OverrideValue : m_archSegmented->currentIndex() == 1;
    }

    bool WorkbenchDisasmView::isEditable() const
    {
        return m_editable;
    }

    // setEditable：可疑点 1——只读通道/写入忙时宿主应调用 false；立即结束正在进行的编辑
    // （与 Esc 同义，不提交半成品输入），后续 F2/Enter/双击与右键"汇编编辑"菜单项一律
    // 失效（置灰+提示），直到再次调用 true。
    void WorkbenchDisasmView::setEditable(const bool editable)
    {
        if (m_editable == editable)
        {
            return;
        }
        m_editable = editable;
        // 即使随后重新允许编辑，也不能复活暂停权限之前的模态写请求。
        ++m_editContextRevision;
        if (!m_editable && m_editingActive)
        {
            cancelInlineEdit();
            // N3（第二轮审核）：cancelInlineEdit 只负责关闭编辑框本身，不处理"推迟的刷新"
            // ——closePersistentEditor 不会发出委托的 closeEditor 信号，不会走 .Edit.cpp 里
            // 那条自动补刷新的路径（那条路径只在用户按 Enter/Esc/失焦结束编辑时触发）。
            // setEditable 是唯一没有别的地方会接着再刷新一次的调用点，必须自己把推迟的
            // 刷新请求（如果有）在这里补上，否则 jumpTo/refreshView/navigateBack 会一直
            // 被"编辑中延后"吞掉——表格看起来彻底冻住，直到用户再做一次双击编辑并结束。
            if (m_refreshPending)
            {
                m_refreshPending = false;
                rebuildRowsNow();
                return;
            }
        }
        // Permission changes affect wording without re-reading or decoding.
        // Keep unavailable/not-positioned statuses until a real row exists.
        if (m_model->rowAt(0))
        {
            const int count = m_model->rowCount()
                - (m_model->isEndOfWindowRow(m_model->rowCount() - 1) ? 1 : 0);
            m_status->setText(decodedStatus(m_anchor, count, isX64(), m_editable));
        }
    }

    bool WorkbenchDisasmView::jumpTo(const std::uint64_t address)
    {
        if (m_provider == nullptr || (m_addressRange && (address < m_addressRange->first || address > m_addressRange->second)))
        {
            return false;
        }
        m_canvas->cancelPendingNavigation();
        if (m_hasAnchor)
        {
            pushBackStack(m_anchor);
        }
        m_hasAnchor = true;
        m_anchor = address;
        emit windowRequested(m_anchor, kDecodeWindowBytes + kLookaheadBytes);
        rebuildRows();
        return true;
    }

    void WorkbenchDisasmView::refreshView()
    {
        rebuildRows();
    }

    // reset：可疑点 5——显式清空到"尚未定位"状态；与传 nullptr 给 setBytesProvider 不同，
    // 这里连锚点、后退栈都一起清，避免宿主换了目标又换回同一个 provider 时意外复原旧位置。
    void WorkbenchDisasmView::reset()
    {
        m_canvas->cancelPendingNavigation();
        // 宿主换目标仍可能复用同一个 provider；reset 才是这条路径的身份失效边界。
        ++m_editContextRevision;
        // N4（第二轮审核）：与 setBytesProvider 同源的另一半——reset() 同样代表"放弃当前
        // 目标的一切状态"，正在进行的行内编辑也不例外，必须先取消，不能让它残留到下一次
        // jumpTo 之后还能被提交。下面的 rebuildRows() 会无条件刷新，这里不用再补一次。
        if (m_editingActive)
        {
            cancelInlineEdit();
        }
        m_hasAnchor = false;
        m_anchor = 0;
        m_hasLastRebuiltAnchor = false;   // 新会话不继承旧会话的滚动位置
        m_backStack.clear();
        m_browseHistory.clear();
        m_refreshPending = false;
        rebuildRows();
    }

    std::uint64_t WorkbenchDisasmView::anchorAddress() const
    {
        return m_anchor;
    }

    MemoryRowCanvas* WorkbenchDisasmView::canvas() const
    {
        return m_canvas;
    }

    std::optional<DecodedRow> WorkbenchDisasmView::selectedInstruction() const
    {
        return m_model->rowAt(m_canvas->selectedRow());
    }

    WorkbenchDisasmModel* WorkbenchDisasmView::model() const
    {
        return m_model;
    }

    bool WorkbenchDisasmView::isEditing() const
    {
        return m_editingActive;
    }

    // minimumSizeHint：见头文件声明处的注释——故意返回一个很小的固定值，不让
    // m_table 的列宽偏好向上传播成宿主的硬性下限（与 WorkbenchHexPane::
    // minimumSizeHint 同一处理方式）。
    QSize WorkbenchDisasmView::minimumSizeHint() const
    {
        return QSize(1, 1);
    }

    // navigateBack：Backspace 的槛外入口，弹出后退栈最新一项并跳转（不再压回，避免来回循环）。
    void WorkbenchDisasmView::navigateBack()
    {
        if (m_backStack.empty() || m_provider == nullptr)
        {
            return;
        }
        m_anchor = m_backStack.back();
        m_backStack.pop_back();
        m_hasAnchor = true;
        rebuildRows();
    }

    void WorkbenchDisasmView::pushBackStack(const std::uint64_t address)
    {
        if (m_backStack.size() >= static_cast<std::size_t>(kMaxBackStack))
        {
            m_backStack.erase(m_backStack.begin());
        }
        m_backStack.push_back(address);
    }

    // tryFollowOperand：操作数文本整体匹配"0x..."、且助记符属于分支类指令才算可跟随；
    // 否则（寄存器/内存/多操作数，或 push/ret/int 这类把立即数当操作数但不是跳转目标的
    // 指令）不算（可疑点 2）。
    bool WorkbenchDisasmView::tryFollowOperand(const DecodedRow& row, std::uint64_t* addressOut) const
    {
        if (!row.decoded || !branchMnemonics().contains(row.mnemonic.trimmed().toLower()))
        {
            return false;
        }
        const QString trimmed = row.operands.trimmed();
        if (!followOperandPattern().match(trimmed).hasMatch())
        {
            return false;
        }
        bool ok = false;
        const std::uint64_t value = trimmed.mid(2).toULongLong(&ok, 16);
        if (!ok)
        {
            return false;
        }
        const auto target = m_operandTargetResolver ? m_operandTargetResolver(value)
            : std::optional<std::uint64_t>(value);
        if (!target) return false;
        if (addressOut != nullptr)
        {
            *addressOut = *target;
        }
        return true;
    }

    // rebuildRows：对外统一入口（D2）。编辑中时只记"待刷新"标志，真正的刷新推迟到编辑
    // 结束之后（见 .Edit.cpp 里 closeEditor 的处理）；否则直接做。
    void WorkbenchDisasmView::rebuildRows()
    {
        if (m_editingActive)
        {
            m_refreshPending = true;
            return;
        }
        rebuildRowsNow();
    }

    namespace
    {
        // clipRowsToDisplayBoundary：D9——把"含 kLookaheadBytes 额外字节"解码出来的行列表，
        // 裁回真正要展示的窗口（displayBoundary 字节，相对 anchor 的偏移）。
        // - 完整落在窗口内的行原样保留；
        // - 第一条跨越窗口边界的行（不管它本来是解码成功的指令还是重同步插进来的 db），
        //   都不展示其"看起来解码成功"的内容——直接拆成逐字节 db，只拆到窗口边界为止，
        //   之后的行（包括这条指令真正的后续字节）全部丢弃；
        // 这样窗口边界恰好落在指令中间时，永远展示"被截断的 db"而不是幻影指令。
        // applyTailGiveUp：D9 的第二种触发方式——有效数据本身（不是我们自己的显示上限）
        // 在某条指令中间就耗尽了（例如可读内存正好在这里结束）。resync 算法按"失败→db→
        // 从下一字节重试"处理残留字节时，残留字节有时会凑巧拼出一条合法的短指令（审核报告
        // 的例子：mov rax,[rip+0x10] 被截掉最后两字节，残留的位移字节"10 00"被 Zydis 解成
        // 真实但完全不存在的 adc [rax], al）。
        // 规则：只要在"距有效数据末尾 kLookaheadBytes 字节以内"出现过一次 db（代表这里发生
        // 过一次因为字节不够而失败的解码尝试），就不再信任这之后任何"看起来解码成功"的
        // 内容——从那一个 db 开始，一路到有效数据末尾全部按逐字节 db 处理，不再继续重同步
        // 进已经失败过的指令内部。只在真正耗尽有效数据时才有意义，调用方只对
        // validPrefix<=kDecodeWindowBytes 的情形喂入；validPrefix 超出显示上限的情形由
        // clipRowsToDisplayBoundary 负责，那里有效数据并没有真的耗尽。
        QVector<DecodedRow> applyTailGiveUp(
            const QVector<DecodedRow>& rows, const std::vector<std::uint8_t>& validBytes,
            const std::uint64_t anchor, const std::uint64_t lookahead)
        {
            const auto validPrefix = static_cast<std::uint64_t>(validBytes.size());
            QVector<DecodedRow> result;
            for (const DecodedRow& row : rows)
            {
                const std::uint64_t startOffset = row.address - anchor;
                const std::uint64_t remaining = validPrefix - startOffset;
                if (!row.decoded && remaining <= lookahead)
                {
                    result.push_back(row);
                    for (std::uint64_t i = startOffset + 1; i < validPrefix; ++i)
                    {
                        DecodedRow dbRow;
                        dbRow.address = anchor + i;
                        dbRow.bytes = QByteArray(1, static_cast<char>(validBytes[static_cast<std::size_t>(i)]));
                        dbRow.mnemonic = QStringLiteral("db");
                        dbRow.operands = QStringLiteral("0x%1").arg(
                            formatHexDigitsUpper(validBytes[static_cast<std::size_t>(i)], 2));
                        dbRow.decoded = false;
                        result.push_back(dbRow);
                    }
                    return result; // 后面原本的行（可能含幻影指令）不要，上面已经逐字节 db 替代。
                }
                result.push_back(row);
            }
            return result;
        }
    }

    // rebuildRowsNow：真正的刷新实现，从 provider 拉一次窗口、重同步解码，刷新模型与状态行。
    void WorkbenchDisasmView::rebuildRowsNow()
    {
        const bool keepScrollPosition = m_hasLastRebuiltAnchor && m_hasAnchor && m_lastRebuiltAnchor == m_anchor;

        if (m_provider == nullptr || !m_hasAnchor)
        {
            m_model->setRows({}, {}, QString());
            m_status->setText(m_provider == nullptr
                ? QStringLiteral("尚未接入数据源。")
                : QStringLiteral("尚未定位；在地址条输入地址或使用跳转到此处。"));
            updateCanvas(keepScrollPosition);
            emit statusMessage(m_status->text());
            return;
        }
        // D9：多取 kLookaheadBytes 字节，只用来判断窗口边界那条指令是否完整，不展示其内容
        // （见 clipRowsToDisplayBoundary）。
        const WorkbenchByteWindow window = m_provider->FetchWindow(m_anchor, kDecodeWindowBytes + kLookaheadBytes);
        if (!window.ok || window.bytes.empty())
        {
            m_model->setRows({}, {}, QStringLiteral("超出已读取窗口"));
            m_status->setText(QStringLiteral("0x%1 超出已读取窗口。").arg(formatHexDigitsUpper(m_anchor, 16)));
            updateCanvas(keepScrollPosition);
            emit statusMessage(m_status->text());
            return;
        }
        // 只把"已读取且有效"的前缀字节交给重同步解码；第一个失效字节之后的内容未知，
        // 用一条提示行代替，绝不假装它是 00 或继续解码出下一条指令。
        // 可疑点 4：validMask 与 bytes 理论上应该等长，但防御性地用 min 夹取，避免一个
        // 实现有误的 provider 导致越界读。
        const std::size_t effectiveLength = std::min(window.bytes.size(), window.validMask.size());
        std::size_t validPrefix = 0;
        while (validPrefix < effectiveLength && window.validMask[validPrefix] == 1)
        {
            ++validPrefix;
        }
        const auto validOffset = static_cast<std::vector<std::uint8_t>::difference_type>(validPrefix);
        const std::vector<std::uint8_t> validBytes(window.bytes.begin(), window.bytes.begin() + validOffset);
        if (!m_decodeOne)
        {
            m_model->setRows({}, {}, QStringLiteral("未设置解码后端"));
            m_status->setText(QStringLiteral("未设置解码后端，无法反汇编。"));
            updateCanvas(keepScrollPosition);
            emit statusMessage(m_status->text());
            return;
        }
        QVector<DecodedRow> rawRows = DecodeWindowResynced(validBytes, m_anchor, m_decodeOne, kMaxInstructionRows, isX64());
        if (validPrefix <= kDecodeWindowBytes)
        {
            // D9：有效数据本身（不是我们的显示上限）耗尽时才需要"放弃重同步"，见
            // applyTailGiveUp 注释；validPrefix 超出显示上限的情形交给下面的边界裁剪处理。
            rawRows = applyTailGiveUp(rawRows, validBytes, m_anchor, kLookaheadBytes);
        }
        // displayBoundary：真正要展示的字节数——有效字节与"显示窗口大小"的较小值。
        const std::uint64_t displayBoundary = std::min<std::uint64_t>(validPrefix, kDecodeWindowBytes);
        QVector<DecodedRow> rows;
        for (const auto& row : rawRows) if (row.address - m_anchor < displayBoundary) rows.push_back(row);
        QVector<ksword::memwb::ByteChangeKind> rowKinds;
        rowKinds.reserve(rows.size());
        for (const DecodedRow& row : rows)
        {
            const std::uint64_t offset = row.address - m_anchor;
            rowKinds.push_back(rowChangeKind(window, offset, static_cast<std::uint64_t>(row.bytes.size())));
        }
        // hasMore：有效字节数不等于显示窗口大小——either 真的没读到那么多（validPrefix 更小），
        // 要么我们自己的显示上限把更多有效数据截掉了（validPrefix 更大）。两种情况都应该
        // 提示"继续浏览需要重新定位或重读"。
        const bool hasMore = validPrefix != kDecodeWindowBytes;
        const QString note = hasMore ? QStringLiteral("超出已读取窗口") : QString();
        m_model->setRows(rows, rowKinds, note);
        // D4：数字部分单独大写再 .arg() 进模板，模板本身（含 Enter/Backspace/x64 等英文
        // 字面量）原样保留，不会被 toUpper() 误伤导致运行时翻译的模板匹配失效。
        m_status->setText(decodedStatus(m_anchor, static_cast<int>(rows.size()), isX64(), m_editable));
        emit statusMessage(m_status->text());
        updateCanvas(keepScrollPosition);
        m_lastRebuiltAnchor = m_anchor;
        m_hasLastRebuiltAnchor = true;
    }

    // eventFilter：装在表格与其视口上，统一处理 F2/Enter/Backspace 与右键菜单。
    bool WorkbenchDisasmView::eventFilter(QObject* watched, QEvent* event)
    {
        if ((watched == m_canvas || watched == m_findEdit) && event->type() == QEvent::ShortcutOverride)
        {
            const auto* key = static_cast<QKeyEvent*>(event);
            if ((key->key() == Qt::Key_F && key->modifiers() == Qt::ControlModifier) || key->key() == Qt::Key_F3)
            { event->accept(); return true; }
        }
        if ((watched == m_canvas || watched == m_findEdit) && event->type() == QEvent::KeyPress)
        {
            const auto* key = static_cast<QKeyEvent*>(event);
            if (key->key() == Qt::Key_F && key->modifiers() == Qt::ControlModifier)
            { openFind(); return true; }
            if (key->key() == Qt::Key_F3) { if (m_findEdit->text().isEmpty()) openFind(); else if (key->modifiers() & Qt::ShiftModifier) findPrevious(); else findNext(); return true; }
            if (key->key() == Qt::Key_Escape && m_findBar->isVisible())
            { m_findBar->hide(); m_canvas->setFocus(); return true; }
        }
        if (watched == m_inlineEditor)
        {
            if (event->type() == QEvent::KeyPress && (static_cast<QKeyEvent*>(event)->key() == Qt::Key_Return || static_cast<QKeyEvent*>(event)->key() == Qt::Key_Enter))
            { commitInlineEdit(); return true; }
            if (event->type() == QEvent::KeyPress && static_cast<QKeyEvent*>(event)->key() == Qt::Key_Escape)
            { cancelInlineEdit(); return true; }
            if (event->type() == QEvent::FocusOut)
            { cancelInlineEdit(); return false; }
        }
        if (watched == m_canvas && event->type() == QEvent::KeyPress)
        {
            auto* keyEvent = static_cast<QKeyEvent*>(event);
            const int current = m_canvas->selectedRow();
            const bool editing = m_editingActive;
            // F2 只在允许编辑时才进入编辑（可疑点 1）；beginRowEdit 内部也会再查一次
            // m_editable 作为第二道防线（双击路径走的是另一个入口，同样汇聚到那里）。
            if (!editing && m_editable && keyEvent->key() == Qt::Key_F2 && current >= 0 && !m_model->isEndOfWindowRow(current))
            {
                beginRowEdit(current);
                return true;
            }
            if (!editing && (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
                && current >= 0 && !m_model->isEndOfWindowRow(current))
            {
                // 跟随跳转不是编辑，只读模式下也允许；只有"进入编辑"这一分支受 m_editable 约束。
                const std::optional<DecodedRow> row = m_model->rowAt(current);
                std::uint64_t target = 0;
                if (row.has_value() && tryFollowOperand(*row, &target))
                {
                    jumpTo(target);
                }
                else if (m_editable)
                {
                    beginRowEdit(current);
                }
                return true;
            }
            if (!editing && keyEvent->key() == Qt::Key_Backspace)
            {
                navigateBack();
                return true;
            }
        }
        return QWidget::eventFilter(watched, event);
    }

    // showContextMenu：复制地址/字节/整条指令、在十六进制视图中定位、汇编编辑（见 .Edit.cpp）。
    void WorkbenchDisasmView::showContextMenu(const QPoint& viewportPos)
    {
        const int index = m_canvas->rowAt(viewportPos);
        if (index < 0 || m_model->isEndOfWindowRow(index)) return;
        const std::optional<DecodedRow> row = m_model->rowAt(index);
        if (!row) return;
        const DecodedRow rowData = *row;
        bool selectionComplete = false;
        const QByteArray selectionBytes = m_canvas->selectedBytes(&selectionComplete);

        // 可疑点 3（第二轮审核）：右键菜单改成堆分配 + WA_DeleteOnClose，不再用栈对象——
        // 栈上的 QMenu 以 this 为父对象，若 exec() 的嵌套事件循环期间 this（本控件）被
        // 宿主销毁，Qt 会同步把子对象（含这个菜单）一起销毁；函数栈展开到这里时局部变量
        // menu 的析构函数又会对同一块内存再析构一次——与 .Edit.cpp 里汇编预览对话框
        // （#9 已修过的同一类问题）用的是同一套手法：堆分配避免二次释放，QPointer 自guard
        // 避免 exec() 返回后访问悬空的 this。
        auto* menu = new QMenu(this);
        menu->setAttribute(Qt::WA_DeleteOnClose);
        menu->setAttribute(Qt::WA_TranslucentBackground, false);
        menu->setAutoFillBackground(true);
        menu->setStyleSheet(QStringLiteral(
            "QMenu{background-color:%1;color:%2;border:1px solid %3;padding:3px;}"
            "QMenu::item{color:%2;background-color:transparent;padding:5px 20px 5px 28px;}"
            "QMenu::item:selected{background-color:%4;color:%5;}"
            "QMenu::item:disabled{color:%6;background-color:transparent;}"
            "QMenu::separator{height:1px;background-color:%3;margin:3px 6px;}")
            .arg(KswordTheme::SurfaceColorHex(), KswordTheme::TextPrimaryColorHex(), KswordTheme::BorderColorHex(),
                KswordTheme::ThemeColorName(KswordTheme::PrimaryAccentColor()), KswordTheme::OnAccentHex(), KswordTheme::TextDisabledColorHex()));
        menu->setToolTipsVisible(true);

        QAction* assemble = menu->addAction(QIcon(QStringLiteral(":/Icon/memwb_assemble.svg")), QStringLiteral("汇编编辑"));
        // 可疑点 1：只读模式下禁用并在提示里说明原因，不是单纯置灰不给理由。
        assemble->setToolTip(m_editable
            ? QStringLiteral("编辑选中指令；Enter 写入，Esc 取消；可预览并调整覆盖长度")
            : QStringLiteral("编辑选中指令；Enter 写入，Esc 取消；可预览并调整覆盖长度（当前只读，不可编辑）"));
        assemble->setEnabled(static_cast<bool>(m_assembleOne) && m_editable);
        QAction* copyAddress = menu->addAction(QIcon(QStringLiteral(":/Icon/codeeditor_copy.svg")), QStringLiteral("复制地址"));
        QAction* copyBytes = menu->addAction(QIcon(QStringLiteral(":/Icon/codeeditor_copy.svg")), QStringLiteral("复制原始字节"));
        copyBytes->setEnabled(selectionComplete);
        QAction* copyInstruction = menu->addAction(QIcon(QStringLiteral(":/Icon/codeeditor_copy.svg")), QStringLiteral("复制整条指令"));
        QAction* locateHex = menu->addAction(QStringLiteral("在十六进制视图中定位"));

        const QPointer<WorkbenchDisasmView> self(this);
        const auto revision = m_editContextRevision;
        emit contextMenuAboutToShow(menu, rowData.address, !rowData.bytes.isEmpty());
        if (!self) return;
        QAction* selected = menu->exec(m_canvas->viewport()->mapToGlobal(viewportPos));
        if (!self)
        {
            // this 已经在 exec() 期间被销毁：不能再访问 m_status、不能再 emit 本对象的信号；
            // menu 作为它的子对象也已经/正在被销毁，不需要（也不能）再手动处理。
            return;
        }
        // 菜单关闭（选中某项或在外部点击/Esc 取消）不保证一定会走 QCloseEvent——
        // QMenu 的常规关闭路径是 hidePopup()/hide()，不是 close()，WA_DeleteOnClose 依赖的
        // 正是 close() 那条路径，对菜单未必可靠触发；这里显式 deleteLater()，不依赖那份
        // 不确定的内部时序（即使 WA_DeleteOnClose 碰巧也触发了一次，deleteLater 两次是
        // 安全的——对象销毁时 Qt 会把尚未派发的那一份事件一并清理，不会二次释放）。
        menu->deleteLater();
        if (revision != m_editContextRevision) return;
        if (selected == copyAddress)
        {
            QGuiApplication::clipboard()->setText(hexcanvas_format::FormatAddress(rowData.address, 16));
        }
        else if (selected == copyBytes)
        {
            if (selectionComplete) QGuiApplication::clipboard()->setText(hexcanvas_format::FormatHexText(selectionBytes));
        }
        else if (selected == copyInstruction)
        {
            QGuiApplication::clipboard()->setText((rowData.mnemonic + QLatin1Char(' ') + rowData.operands).trimmed());
        }
        else if (selected == locateHex)
        {
            emit requestHexLocate(rowData.address);
        }
        else if (selected == assemble)
        {
            // D10：传菜单打开时冻结的快照（地址+原字节），而不是行号——菜单是模态的，
            // exec() 期间数据可能被 refreshView 刷新，行号对应的内容可能已经变了。
            showAssemblyPreviewDialog(rowData);
        }
    }
}
