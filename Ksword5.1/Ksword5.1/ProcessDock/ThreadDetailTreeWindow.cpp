#include "ThreadDetailWindow.h"
#include "KernelStructureTree.h"
#include "KernelStructureLiveSample.h"
#include "ThreadSettingsInline.h"
#include "ThreadStackWindow.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/DetailPresentation.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/PageControlStyle.h"
#include "../UI/TablePresentation.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/UI_All.h"

#include <QCoreApplication>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QThreadPool>
#include <QToolButton>
#include <QTreeView>
#include <QVBoxLayout>
#include <limits>

namespace
{
    namespace structure = ks::ui::kernelstructure; // 与 EPROCESS 页共用同一布局、采样和显示语义。
    // 将数字格式化为十六进制；width 是最小位数，便于对齐相对偏移。
    QString hexValue(const std::uint64_t value, const int width = 0)
    {
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), width, 16, QLatin1Char('0'));
    }

    // GUI 输入正文或固定回退及其布局，返回新根索引；一次只展示一种采样，不触碰独立 R3 草稿。
    QModelIndex fillTree(QStandardItemModel& model, const VerifiedThreadDetail& sample,
        const structure::Layout& layout, const structure::LiveSample& body)
    {
        // 只更新 ETHREAD 子树；同表独立的 R3 设置和编辑草稿不随 R0 刷新销毁。
        constexpr int kKernelRootRole = Qt::UserRole + 27; // 只标记可由 R0 刷新替换的内核根。
        if (auto* previous = model.item(0, 0); previous && previous->data(kKernelRootRole).toBool()) // 上轮内核根。
        {
            model.removeRow(0);
        }
        // 正文通过完整运行身份后直接投影；不要求旧固定详情或 DynData 先成功。
        if (body.body.identityVerified && layout.runningMatch && !layout.profile.fields.empty())
        {
            const auto empty = QStringLiteral("—"); // 根项没有相对偏移。
            const auto base = body.body.response.objectAddress; // 唯一基址来自本次正文回执。
            const auto live = structure::ProjectedSamples(layout.profile, body.body.projection); // 所有行含失败状态。
            auto* root = structure::Append(*model.invisibleRootItem(), {empty, hexValue(base),
                QStringLiteral("ETHREAD"), QStringLiteral("_ETHREAD"), structure::LayoutStatus(layout)}, true); // 内核根。
            root->setData(true, kKernelRootRole);
            // 正文已匹配精确布局；无论是否存在双侧邻版，根项和成员均保留正常主题背景。
            structure::AppendLayout(*root, layout, base, live);
            return root->index();
        }
        if (!sample.verified && layout.profile.fields.empty() && layout.candidates.isEmpty())
        {
            return {};
        }

        const auto data = sample.verified ? sample.response : KSWORD_ARK_THREAD_DETAIL_RESPONSE{}; // 非验证回执不入表。
        const auto& at = data.offsets; // 本轮驱动提供的各字段相对偏移。
        const auto& from = data.sources; // 偏移来源为逐字段数据，不用值是否为零来判断布局。
        const bool hasSources = (data.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_OFFSET_SOURCES) != 0; // 固定回执是否携带逐字段偏移来源。
        const std::uint64_t base = (data.fieldFlags & KSWORD_ARK_THREAD_DETAIL_FIELD_OBJECT_ADDRESS) != 0
            ? data.threadObjectAddress : 0; // 未明确返回对象地址时不推导任何字段地址。
        const QString unavailable = ks::i18n::displayText(QStringLiteral("不可用")); // 缺证据时不填假零值。
        const QString empty = QStringLiteral("—"); // 未核验布局不计算存储地址。
        // 输入父项、五列文本和插入方向，返回第零列节点；视图将展开指示器放到字段列。
        const auto append = [](QStandardItem* parent, const QStringList& cells, bool prepend = false)
        {
            QList<QStandardItem*> row; // 当前层的五个显示单元格。
            for (const auto& cell : cells)
            {
                auto* item = new QStandardItem(cell); // 由父模型接管。
                item->setToolTip(cell);
                row.append(item);
            }
            if (prepend)
            {
                parent->insertRow(0, row);
            }
            else
            {
                parent->appendRow(row);
            }
            return row.first();
        };
        auto* root = append(model.invisibleRootItem(), {empty, base ? hexValue(base) : empty,
            QStringLiteral("ETHREAD"), QStringLiteral("_ETHREAD"), structure::LayoutStatus(layout)}, true); // 固定回退或仅布局的根项。
        root->setData(true, kKernelRootRole);
        if (!sample.verified)
        {
            structure::AppendLayout(*root, layout, 0, {}); // 无驱动仍可查看磁盘 PDB 布局。
            structure::AppendCandidates(*root, layout.candidates, !layout.bracketed);
            if (layout.profile.fields.empty() && !layout.bracketed)
            {
                structure::ColorUnbracketedTree(*root); // 未采样的精确磁盘布局也不按邻版参考染黄。
            }
            return root->index();
        }
        // 固定只读查询本来就以 ETHREAD 起点读取 KTHREAD；这里描述同一段内嵌布局，不发请求。
        auto* tcb = append(root, {hexValue(0, 4), base ? hexValue(base) : empty,
            QStringLiteral("Tcb"), QStringLiteral("_KTHREAD"), ks::i18n::displayText(QStringLiteral("内嵌线程调度结构"))}); // 对象正文中的内嵌调度结构。

        // 追加一行：offset/source 为驱动回执；value 是字段内容，不能用作第二列地址。
        const auto add = [&](QStandardItem* parent, const QString& field, const QString& type, const unsigned long offset,
            const unsigned long source, const QString& value, const QString& meaning)
        {
            const bool located = hasSources && source != KSW_DYN_FIELD_SOURCE_UNAVAILABLE &&
                offset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE; // 有独立偏移证据才允许计算存储位置。
            const QString address = located && base && offset <= (std::numeric_limits<std::uint64_t>::max)() - base
                ? hexValue(base + offset) : empty; // 加法不溢出时的字段存储地址，不是指针所指地址。
            const QString interpreted = QStringLiteral("%1 · %2")
                .arg(value.isEmpty() ? unavailable : value, ks::i18n::displayText(meaning)); // 原始值与来源限制同列展示。
            return append(parent, {located ? hexValue(offset, 4) : empty, address, field, type, interpreted});
        };
        // 0 和 8 是这两个 x64 结构的成员偏移；子项地址以父项存储地址为基址。
        const auto appendPair = [&](QStandardItem* parent, const QString& first, const QString& second,
            const QString& type, const QString& firstValue, const QString& secondValue)
        {
            bool parsed = false; // 地址无法核验时只显示子项相对偏移及值。
            const auto parentAddress = parent->index().siblingAtColumn(1).data().toString().toULongLong(&parsed, 16); // 从父项已核验存储地址计算内嵌字段。
            const bool addressable = parsed && parentAddress <= (std::numeric_limits<std::uint64_t>::max)() - 8; // 第二个指针存储位置不得溢出。
            append(parent, {hexValue(0, 4), addressable ? hexValue(parentAddress) : empty, first, type, firstValue});
            append(parent, {hexValue(8, 4), addressable ? hexValue(parentAddress + 8) : empty, second, type, secondValue});
        };
        // 读取成功标志只对相应字段生效；栈指针旧协议没有逐项标志，仍仅展示非零读数。
        const auto valid = [&data](const unsigned long flag) // 输入字段标志，返回固定回执是否明确报告其有效。
        {
            return (data.fieldFlags & flag) != 0;
        };
        const auto pointer = [](const std::uint64_t value) // 输入旧栈线索，返回非零数值或缺失文本，不解引用。
        {
            return value ? hexValue(value) : QString{};
        };

        // 驱动的固定 KTHREAD 字段以同一线程对象起点为基址，并非从指针值向后解引用。
        add(tcb, QStringLiteral("KTHREAD.InitialStack"), QStringLiteral("Ptr64 Void"), at.ktInitialStack, from.ktInitialStack,
            pointer(data.initialStack), QStringLiteral("初始内核栈位置，不是调用帧"));
        add(tcb, QStringLiteral("KTHREAD.StackLimit"), QStringLiteral("Ptr64 Void"), at.ktStackLimit, from.ktStackLimit,
            pointer(data.stackLimit), QStringLiteral("内核栈低地址边界"));
        add(tcb, QStringLiteral("KTHREAD.StackBase"), QStringLiteral("Ptr64 Void"), at.ktStackBase, from.ktStackBase,
            pointer(data.stackBase), QStringLiteral("内核栈高地址边界"));
        add(tcb, QStringLiteral("KTHREAD.KernelStack"), QStringLiteral("Ptr64 Void"), at.ktKernelStack, from.ktKernelStack,
            pointer(data.kernelStack), QStringLiteral("内核栈指针线索，不是调用帧"));
        add(tcb, QStringLiteral("KTHREAD.Process"), QStringLiteral("Ptr64 _KPROCESS"), at.ktProcess, from.ktProcess,
            valid(KSWORD_ARK_THREAD_DETAIL_FIELD_KTHREAD_PROCESS) ? hexValue(data.kthreadProcessObject) : QString{},
            QStringLiteral("所属进程的内核对象指针"));

        // ETHREAD 聚合值只解码协议明确提供的成员，不追链表或一律把零当失败。
        const bool hasCid = valid(KSWORD_ARK_THREAD_DETAIL_FIELD_ETHREAD_CID); // 标识字段采样成功。
        auto* cid = add(root, QStringLiteral("ETHREAD.Cid"), QStringLiteral("_CLIENT_ID"), at.etCid, from.etCid,
            hasCid ? QStringLiteral("PID %1 / TID %2")
                .arg(data.cidUniqueProcess).arg(data.cidUniqueThread) : QString{}, QStringLiteral("线程与所属进程的标识")); // 客户端身份聚合节点。
        appendPair(cid, QStringLiteral("UniqueProcess"), QStringLiteral("UniqueThread"), QStringLiteral("HANDLE"),
            hasCid ? QString::number(data.cidUniqueProcess) : unavailable, hasCid ? QString::number(data.cidUniqueThread) : unavailable);
        const bool hasLinks = valid(KSWORD_ARK_THREAD_DETAIL_FIELD_THREAD_LIST_ENTRY); // 双链表字段采样成功。
        auto* links = add(root, QStringLiteral("ETHREAD.ThreadListEntry"), QStringLiteral("_LIST_ENTRY"), at.etThreadListEntry, from.etThreadListEntry,
            hasLinks ? QStringLiteral("Flink %1 / Blink %2")
                .arg(hexValue(data.threadListEntryFlink), hexValue(data.threadListEntryBlink)) : QString{},
            QStringLiteral("进程线程链表的相邻链接")); // 仅展示同一固定回执中的双指针存储。
        appendPair(links, QStringLiteral("Flink"), QStringLiteral("Blink"), QStringLiteral("Ptr64 _LIST_ENTRY"),
            hasLinks ? hexValue(data.threadListEntryFlink) : unavailable, hasLinks ? hexValue(data.threadListEntryBlink) : unavailable);
        add(root, QStringLiteral("ETHREAD.StartAddress"), QStringLiteral("Ptr64 Void"), at.etStartAddress, from.etStartAddress,
            valid(KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS) ? hexValue(data.startAddress) : QString{},
            QStringLiteral("系统记录的线程入口，不是当前执行位置"));
        add(root, QStringLiteral("ETHREAD.Win32StartAddress"), QStringLiteral("Ptr64 Void"), at.etWin32StartAddress, from.etWin32StartAddress,
            valid(KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS) ? hexValue(data.win32StartAddress) : QString{},
            QStringLiteral("记录的 Win32 线程入口"));
        if (!layout.profile.fields.empty())
        {
            // 正文不可用时保留原固定字段视图；磁盘布局单独列出，禁止与另一采样时刻叠加。
            auto* disk = append(root, {empty, empty, QStringLiteral("_ETHREAD"), {}, structure::LayoutStatus(layout)}); // 不能与固定回执合并的磁盘符号分组。
            structure::AppendLayout(*disk, layout, 0, {}); // 不把未核验磁盘布局与实际回执混用。
        }
        structure::AppendCandidates(*root, layout.candidates, !layout.bracketed); // 不替换已核验的固定字段。
        if (layout.profile.fields.empty() && !layout.bracketed)
        {
            structure::ColorUnbracketedTree(*root); // 固定字段回退仅在缺少精确布局与双侧参考时染黄。
        }
        return root->index();
    }

    // 用回执状态与采样时刻组装工具带下方的简短提示；原始状态码保留供核对。
    QString describeSample(const VerifiedThreadDetail& sample, const QDateTime& sampledAt)
    {
        if (!sample.verified)
        {
            return sample.diagnostic;
        }
        const auto& data = sample.response; // 固定协议状态码与缺失能力掩码。
        const auto text = data.status == KSWORD_ARK_DETAIL_STATUS_OK ? QStringLiteral("字段读取成功")
            : data.status == KSWORD_ARK_DETAIL_STATUS_PARTIAL || data.status == KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING
                ? QStringLiteral("部分字段不可用") : QStringLiteral("字段查询未完成"); // 固定查询的显示状态，独立于新正文回执。
        return QStringLiteral("%1 · ETHREAD %2 · R0 %3 (%4 / %5) · %6 %7")
            .arg(sampledAt.toString(Qt::ISODateWithMs), hexValue(data.threadObjectAddress),
                text, QString::number(data.status), hexValue(static_cast<std::uint32_t>(data.lastStatus), 8),
                QStringLiteral("缺失能力"), hexValue(data.missingCapabilityMask));
    }

}

// 两个线程列表入口传入父窗和冻结目标；创建独立详情窗，关闭时释放控件，不改变原列表选择。
void ShowThreadDetailWindow(QWidget* parent, const ThreadStackTarget& target)
{
    // 实际导航：进程详情线程列表 / 进程列表线程菜单 → 对象详情 → 五列字段表。
    const auto frozen = structure::CaptureLiveTarget(target.processId, target.processCreationTime100ns,
        target.threadId, target.threadCreationTime100ns); // 两个入口都只在开窗时冻结同一真实目标。
    auto* dialog = new QDialog(parent); // 独立对象详情，关闭时释放本页控件。
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setObjectName(QLatin1String("ksword_thread_detail_tree"));
    dialog->setProperty("ksword_detail_keep_layout", true); // 专业树表保留内部页根，不由外壳重排。
    dialog->setWindowTitle(QStringLiteral("线程详细信息"));
    ks::ui::applyResponsiveWindowGeometry(dialog, parent, QSize(1060, 630), QSize(590, 420));
    // 共享外壳会清除直接根布局的边距；只在内部页根留等宽边距。
    auto* layout = new QVBoxLayout(dialog); // 详情外壳层。
    auto* content = new QWidget(dialog); // 摘要、工具带与列表的共同边界。
    auto* page = new QVBoxLayout(content); // 唯一承担本页四边留白的布局。
    page->setContentsMargins(8, 8, 8, 8);
    page->setSpacing(8);
    layout->addWidget(content);
    const QString subtitle = QStringLiteral("PID %1 · TID %2").arg(target.processId).arg(target.threadId); // 始终显示目标的两个 ID。
    auto* header = ks::ui::CreateDetailSummaryHeader(content,
        target.processName.isEmpty() ? QStringLiteral("线程详细信息") : target.processName,
        subtitle); // 只显示真实目标，不使用易与其它对象混淆的装饰图标。
    if (target.threadCreationTime100ns != 0)
    {
        header->setToolTip(QStringLiteral("线程创建时间（FILETIME）：%1").arg(target.threadCreationTime100ns));
    }
    page->addWidget(header);

    // 工具带承载同一线程上的结果刷新、栈入口与五列搜索。
    auto* tools = new QHBoxLayout(); // 与字段区独立的共享工具带。
    auto* refresh = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("R0 刷新"), content); // 读取字段。
    auto* stack = new QPushButton(QStringLiteral("查看调用栈"), content); // 打开同一目标的栈页。
    auto* search = new QLineEdit(content); // 只筛选已采样的值，无额外驱动请求。
    refresh->setToolTip(QStringLiteral("重新读取当前线程的只读字段"));
    stack->setToolTip(QStringLiteral("查看调用栈"));
    search->setPlaceholderText(QStringLiteral("搜索字段或值"));
    search->setAccessibleName(search->placeholderText());
    search->setClearButtonEnabled(true);
    search->setMaximumWidth(320);
    ks::ui::StyleSearchField(search);
    tools->addWidget(refresh);
    tools->addWidget(stack);
    tools->addStretch(1);
    tools->addWidget(search, 1);
    page->addLayout(tools);

    // 专业字段表固定顺序；窄窗可以横向滚动，表头与选中态由共享表格样式提供。
    auto* status = new QLabel(content); // 加载、不可用、部分结果和采样来源。
    status->setWordWrap(true);
    status->setTextFormat(Qt::PlainText);
    status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    page->addWidget(status);
    auto* fields = new QTreeView(content); // 结构层级与五列数据共用一个只读视口。
    auto* model = new QStandardItemModel(fields); // 当前回执的唯一规范字段模型。
    model->setHorizontalHeaderLabels({ks::i18n::displayText(QStringLiteral("相对偏移")),
        ks::i18n::displayText(QStringLiteral("地址")), ks::i18n::displayText(QStringLiteral("字段")),
        ks::i18n::displayText(QStringLiteral("类型")), ks::i18n::displayText(QStringLiteral("实际值 / 解释值"))});
    auto* filter = new QSortFilterProxyModel(fields); // 命中后保留父项，以便辨认字段归属。
    filter->setSourceModel(model);
    filter->setFilterKeyColumn(-1);
    filter->setFilterCaseSensitivity(Qt::CaseInsensitive);
    filter->setRecursiveFilteringEnabled(true);
    filter->setAutoAcceptChildRows(true);
    fields->setModel(filter);
    fields->setTreePosition(2);
    // 树表不使用仅适配 QTableView 的操作条；上方已提供本页动作。
    fields->setEditTriggers(QAbstractItemView::NoEditTriggers);
    fields->setSortingEnabled(false);
    fields->setSelectionBehavior(QAbstractItemView::SelectRows);
    fields->setWordWrap(false);
    fields->setUniformRowHeights(false); // R3 编辑行按内联控件的高度，其他行仍保持自然密度。
    fields->setAlternatingRowColors(true);
    // 基础列按内容预留宽度，解释列至少保持一段可读空间并填充剩余宽度。
    auto* columns = fields->header(); // 采用共享表头样式，列宽可手动调整。
    columns->setSectionsMovable(false);
    columns->setSectionResizeMode(QHeaderView::Interactive);
    columns->resizeSection(0, 102);
    columns->resizeSection(1, 180);
    columns->resizeSection(2, 214);
    columns->resizeSection(3, 160);
    columns->resizeSection(4, 285);
    columns->setStretchLastSection(true);
    ks::ui::ApplyTablePresentation(fields);
    // 独立模块只给 R3 公开设置挂行内编辑，R0 私有成员仍无编辑入口。
    tools->insertWidget(1, AddInlineThreadSettings(*fields, *model, *filter, target));
    ks::ui::NormalizeToolbarRow(tools);
    page->addWidget(fields, 1);
    ks::ui::ApplyDetailDialogChrome(dialog);
    // 搜索只浏览已采样字段；显示匹配后代时展开父项，不重新读取驱动。
    QObject::connect(search, &QLineEdit::textChanged, fields, [filter, fields](const QString& query)
    {
        filter->setFilterFixedString(query.trimmed());
        if (!query.trimmed().isEmpty())
        {
            fields->expandAll();
        }
        else
        {
            for (int row = 0; row < filter->rowCount(); ++row)
            {
                fields->expand(filter->index(row, 0)); // 清空时恢复两个根项的一级成员。
            }
        }
    });
    // 使用共享实底菜单样式；右键复制以命中行而非历史选择为准。
    fields->setContextMenuPolicy(Qt::CustomContextMenu);
    QObject::connect(fields, &QTreeView::customContextMenuRequested, fields, [fields](const QPoint& position)
    {
        const auto index = fields->indexAt(position); // 当前点击的字段单元格。
        if (!index.isValid())
        {
            return;
        }
        QStringList cells; // 将当前行的五列冻结为制表符分隔文本。
        const int count = fields->model()->columnCount(index.parent()); // 当前树层的列数。
        for (int column = 0; column < count; ++column)
        {
            cells.append(index.siblingAtColumn(column).data().toString());
        }
        const QString cell = index.data().toString(); // 冻结单元格内容，避免菜单打开期间对象更新。
        QMenu menu; // 使用独立栈对象，宿主关窗时不会重复销毁此菜单。
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        auto* copyCell = menu.addAction(ks::i18n::displayText(QStringLiteral("复制单元格"))); // 仅复制命中格。
        auto* copyRow = menu.addAction(ks::i18n::displayText(QStringLiteral("复制行"))); // 复制完整五列。
        auto* selected = menu.exec(fields->viewport()->mapToGlobal(position)); // 不依赖当前选择。
        if (selected == copyCell)
        {
            QApplication::clipboard()->setText(cell);
        }
        else if (selected == copyRow)
        {
            QApplication::clipboard()->setText(cells.join(QLatin1Char('\t')));
        }
    });

    // 禁用在途刷新，保留旧表到新回执就绪；关窗后丢弃回执。
    const auto request = [fields, model, filter, refresh, status, target, frozen]() // GUI 发起单次异步读取，无返回值。
    {
        if (!refresh->isEnabled())
        {
            return;
        }
        refresh->setEnabled(false);
        status->show();
        status->setText(QStringLiteral("正在读取线程字段…"));
        ks::ui::ApplyStatusRole(status, ks::ui::StatusRole::Info);
        auto* app = QCoreApplication::instance(); // GUI 线程上的稳定投递入口。
        const QPointer<QTreeView> view(fields); // 当前窗口的树表及以下两个子对象。
        const QPointer<QStandardItemModel> treeModel(model); // 仅在 GUI 线程更新。
        const QPointer<QSortFilterProxyModel> proxy(filter); // 保留现有筛选条件。
        const QPointer<QPushButton> button(refresh); // 查询结束时恢复刷新入口。
        const QPointer<QLabel> label(status); // 当前窗口的状态展示。
        QThreadPool::globalInstance()->start([app, view, treeModel, proxy, button, label, target, frozen]()
        {
            auto layout = structure::LoadLayout(ks::threadlayout::Kind::Thread); // 按需加载精确符号分片。
            auto body = structure::ReadLiveSample(*frozen, layout); // 新正文先查询，独立于旧固定详情能力。
            VerifiedThreadDetail sample; // 仅正文失败才产生固定回退，不能混合两个采样批次。
            if (!body.body.identityVerified)
            {
                if (structure::LiveTargetRunning(*frozen))
                {
                    ThreadStackTarget verifiedTarget = target; // 用入口冻结的实际时间补齐旧接口的必填身份。
                    verifiedTarget.processCreationTime100ns = frozen->request.processCreationTime100ns;
                    verifiedTarget.threadCreationTime100ns = frozen->request.threadCreationTime100ns;
                    constexpr auto groups = KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_STACK |
                        KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START | KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_LISTS; // 原固定字段组。
                    sample = QueryVerifiedThreadDetail(verifiedTarget, groups);
                }
                else
                {
                    sample.diagnostic = body.diagnostic;
                }
            }
            const auto sampledAt = QDateTime::currentDateTime(); // 固定回退完成时刻，绝不代替正文采样区间。
            QMetaObject::invokeMethod(app, [view, treeModel, proxy, button, label, sampledAt,
                sample = std::move(sample), layout = std::move(layout), body = std::move(body)]()
            {
                if (view && treeModel && proxy)
                {
                    const auto root = fillTree(*treeModel, sample, layout, body); // 只展开本次新建的 R0 根。
                    if (proxy->filterRegularExpression().pattern().isEmpty())
                    {
                        view->expand(proxy->mapFromSource(root));
                    }
                    else
                    {
                        view->expandAll();
                    }
                }
                if (label)
                {
                    QString description; // 正常成功时隐藏长横幅，覆盖率和读取区间仍保存在 CLI 原始回执。
                    if (!body.body.identityVerified)
                    {
                        description = structure::DescribeLiveSample(body) + QStringLiteral(" · ") +
                            ks::i18n::displayText(sample.verified
                            ? QStringLiteral("固定字段回退（独立采样，不与对象体快照合并）")
                            : QStringLiteral("仅布局；本次没有可用现场值"));
                        description += QStringLiteral(" · ") + describeSample(sample, sampledAt);
                    }
                    else if (body.body.projection.unreadRows)
                    {
                        description = ks::i18n::displayText(QStringLiteral("部分字段未完整读取：%1"))
                            .arg(static_cast<qulonglong>(body.body.projection.unreadRows));
                    }
                    label->setText(description);
                    label->setVisible(!description.isEmpty());
                    // 固定回退即使有值也保留警告，不能把新接口失败涂成整体成功。
                    ks::ui::ApplyStatusRole(label, body.body.identityVerified
                        ? body.body.projection.unreadRows == 0 ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning
                        : sample.verified ? ks::ui::StatusRole::Warning : ks::ui::StatusRole::Error);
                }
                if (button)
                {
                    button->setEnabled(true);
                }
            }, Qt::QueuedConnection);
        });
    };
    QObject::connect(refresh, &QPushButton::clicked, dialog, request);
    QObject::connect(stack, &QPushButton::clicked, dialog, [dialog, target]()
    {
        auto* window = new ThreadStackWindow(target, dialog); // 默认在线 R0 采集，R3 是独立显式入口。
        window->setAttribute(Qt::WA_DeleteOnClose);
        window->show();
    });
    request();
    dialog->show();
}
