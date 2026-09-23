#include "KernelObjectTypeProcedureTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/IntegrityRiskPresentation.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QEvent>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // 表格列：类型索引、类型名、方法、槽位地址、目标地址、归属模块、所在节、风险、状态。
    constexpr int kColumnCount = 9;
    constexpr int kColumnRisk = 7;

    QString buttonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString headerStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;border:1px solid %2;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex());
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

KernelObjectTypeProcedureTab::KernelObjectTypeProcedureTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelObjectTypeProcedureTab::requestInitialRefresh()
{
    if (m_initialRefreshRequested)
    {
        return;
    }

    m_initialRefreshRequested = true;
    refreshAsync();
}

void KernelObjectTypeProcedureTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }

    // 单元格前景/底色是绘制路径的 QBrush，换主题后不会自己更新；只重涂已有行与状态标签，不访问驱动。
    if (event->type() == QEvent::ApplicationPaletteChange ||
        event->type() == QEvent::PaletteChange)
    {
        applyRowHighlights();
        updateStatusLabel();
    }
}

void KernelObjectTypeProcedureTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText("kernel.object_type_proc.refresh", QStringLiteral("刷新方法指针")),
        this);
    m_refreshButton->setStyleSheet(buttonStyle());
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(kernelText(
        "kernel.object_type_proc.filter.placeholder",
        QStringLiteral("筛选类型、方法、模块、地址或风险...")));
    m_filterEdit->setMinimumWidth(280);
    m_clearFilterButton = new QPushButton(
        kernelText("kernel.object_type_proc.filter.clear", QStringLiteral("清除筛选")),
        this);
    m_clearFilterButton->setStyleSheet(buttonStyle());
    m_statusLabel = new QLabel(
        kernelText("kernel.object_type_proc.loading", QStringLiteral("等待查询 ObjectType 方法指针。")),
        this);
    m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));
    m_statusLabel->setWordWrap(true);
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_filterEdit);
    toolbar->addWidget(m_clearFilterButton);
    toolbar->addWidget(m_statusLabel, 1);
    rootLayout->addLayout(toolbar);

    m_table = new ks::ui::VisibleTableWidget(this);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->setStyleSheet(QStringLiteral("QTableWidget{background:transparent;color:%1;}").arg(KswordTheme::TextPrimaryHex()));
    m_table->horizontalHeader()->setStyleSheet(headerStyle());
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->setVisible(false);
    m_table->setColumnCount(kColumnCount);
    m_table->setHorizontalHeaderLabels({
        kernelText("kernel.object_type_proc.header.type_index", QStringLiteral("类型索引")),
        kernelText("kernel.object_type_proc.header.type_name", QStringLiteral("类型名")),
        kernelText("kernel.object_type_proc.header.method", QStringLiteral("方法")),
        kernelText("kernel.object_type_proc.header.slot", QStringLiteral("槽位地址")),
        kernelText("kernel.object_type_proc.header.target", QStringLiteral("目标地址")),
        kernelText("kernel.object_type_proc.header.module", QStringLiteral("归属模块")),
        kernelText("kernel.object_type_proc.header.section", QStringLiteral("所在节")),
        kernelText("kernel.object_type_proc.header.risk", QStringLiteral("风险")),
        kernelText("kernel.object_type_proc.header.state", QStringLiteral("状态"))});
    rootLayout->addWidget(m_table, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&) { applyFilter(); });
    connect(m_clearFilterButton, &QPushButton::clicked, this, [this]() {
        if (m_filterEdit != nullptr)
        {
            m_filterEdit->clear();
        }
    });
    connect(m_table, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
        showCopyMenu(position);
    });
    applyFilter();
}

void KernelObjectTypeProcedureTab::refreshAsync()
{
    if (m_refreshRunning)
    {
        return;
    }
    m_refreshRunning = true;
    m_refreshButton->setEnabled(false);
    m_statusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));
    m_statusLabel->setText(kernelText(
        "kernel.object_type_proc.refreshing",
        QStringLiteral("正在读取各对象类型的方法指针并核对归属模块...")));
    QPointer<KernelObjectTypeProcedureTab> safeThis(this);
    std::thread([safeThis]() {
        Snapshot snapshot;
        // 翻页由 ArkDriverClient 封装内部完成；layoutState 等响应级字段随结果一起带回。
        const ksword::ark::ObjectTypeProceduresResult result =
            ksword::ark::DriverClient().enumObjectTypeProcedures();
        snapshot.queryFailed = !result.io.ok;
        snapshot.unsupported = result.unsupported;
        snapshot.ioMessage = QString::fromStdString(result.io.message);
        if (!snapshot.queryFailed)
        {
            snapshot.layoutState = result.layoutState;
            snapshot.procedureBlockOffset = result.procedureBlockOffset;
            snapshot.layoutAnchorTypes = result.layoutAnchorTypes;
            snapshot.layoutAnchorAgree = result.layoutAnchorAgree;
            snapshot.layoutReason = result.layoutReason;
            snapshot.skippedTypes = result.skippedTypes;
            snapshot.truncated = result.truncated;
            snapshot.rows.reserve(result.entries.size());
            QSet<std::uint32_t> seenTypes;
            for (const ksword::ark::ObjectTypeProcedureEntry& entry : result.entries)
            {
                ProcedureRow row;
                row.typeIndex = entry.typeIndex;
                row.typeName = QString::fromStdWString(entry.typeName);
                row.procedureKind = entry.procedureKind;
                row.riskFlags = entry.riskFlags;
                row.entryFlags = entry.entryFlags;
                row.lastStatus = static_cast<std::int32_t>(entry.lastStatus);
                row.slotAddress = entry.slotAddress;
                row.targetAddress = entry.targetAddress;
                row.detourTargetAddress = entry.detourTargetAddress;
                row.ownerModule = QString::fromStdWString(entry.ownerModule);
                row.sectionName = QString::fromStdWString(entry.sectionName);
                seenTypes.insert(entry.typeIndex);
                snapshot.rows.push_back(std::move(row));
            }
            snapshot.typeCount = static_cast<std::uint32_t>(seenTypes.size());
        }

        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [safeThis, snapshot = std::move(snapshot)]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applySnapshot(std::move(snapshot));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelObjectTypeProcedureTab::applySnapshot(Snapshot snapshot)
{
    const QPointer<KernelObjectTypeProcedureTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-object-type-procedure-snapshot"),
        { m_table },
        [safeThis, snapshot]() mutable
        {
            if (!safeThis.isNull())
            {
                safeThis->applySnapshot(std::move(snapshot));
            }
        }))
    {
        return;
    }

    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    m_hasResult = true;
    m_rows = std::move(snapshot.rows);
    m_queryFailed = snapshot.queryFailed;
    m_unsupported = snapshot.unsupported;
    m_ioMessage = std::move(snapshot.ioMessage);
    m_layoutState = snapshot.layoutState;
    m_procedureBlockOffset = snapshot.procedureBlockOffset;
    m_layoutAnchorTypes = snapshot.layoutAnchorTypes;
    m_layoutAnchorAgree = snapshot.layoutAnchorAgree;
    m_layoutReason = snapshot.layoutReason;
    m_typeCount = snapshot.typeCount;
    m_truncated = snapshot.truncated;
    m_skippedTypes = snapshot.skippedTypes;
    populateTable();
}

QString KernelObjectTypeProcedureTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0'));
}

QString KernelObjectTypeProcedureTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0'));
}

QString KernelObjectTypeProcedureTab::methodText(const std::uint32_t procedureKind)
{
    // 方法名就是 OBJECT_TYPE_INITIALIZER 的成员名，属于标识符，不做翻译。
    switch (procedureKind)
    {
    case KSWORD_ARK_OBJTYPE_PROC_DUMP: return QStringLiteral("Dump");
    case KSWORD_ARK_OBJTYPE_PROC_OPEN: return QStringLiteral("Open");
    case KSWORD_ARK_OBJTYPE_PROC_CLOSE: return QStringLiteral("Close");
    case KSWORD_ARK_OBJTYPE_PROC_DELETE: return QStringLiteral("Delete");
    case KSWORD_ARK_OBJTYPE_PROC_PARSE: return QStringLiteral("Parse");
    case KSWORD_ARK_OBJTYPE_PROC_SECURITY: return QStringLiteral("Security");
    case KSWORD_ARK_OBJTYPE_PROC_QUERY_NAME: return QStringLiteral("QueryName");
    case KSWORD_ARK_OBJTYPE_PROC_OKAY_TO_CLOSE: return QStringLiteral("OkayToClose");
    default: return QStringLiteral("Unknown(%1)").arg(procedureKind);
    }
}

bool KernelObjectTypeProcedureTab::layoutVerified() const
{
    return m_layoutState == KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED;
}

std::uint32_t KernelObjectTypeProcedureTab::effectiveRisk(const ProcedureRow& row) const
{
    // 布局没通过运行时自验证时，行里的地址只是参考信息：既不能当“被劫持”的证据，也不能当“干净”的证据。
    // 驱动按约定此时只会带 LAYOUT_UNVERIFIED，这里再收口一次，避免异常上报的风险位被渲染成红色告警；
    // 原始上报值仍保留在 tooltip 里，没有被静默吞掉。
    if (!layoutVerified())
    {
        return KSWORD_ARK_DRIVER_INTEGRITY_RISK_LAYOUT_UNVERIFIED;
    }
    return row.riskFlags;
}

QString KernelObjectTypeProcedureTab::stateText(const ProcedureRow& row) const
{
    // 空指针与读取失败必须分开：前者是很多类型的合法常态，后者是证据缺失。
    QString text;
    if ((row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_READ_FAILED) != 0U)
    {
        text = kernelText("kernel.object_type_proc.state.read_failed", QStringLiteral("读取失败"));
    }
    else if ((row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_NULL_POINTER) != 0U)
    {
        text = kernelText("kernel.object_type_proc.state.null", QStringLiteral("空指针"));
    }
    else if ((row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_CORE_KERNEL) != 0U)
    {
        text = kernelText("kernel.object_type_proc.state.core_kernel", QStringLiteral("非空 · 核心内核"));
    }
    else if ((row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_MODULE) != 0U)
    {
        text = kernelText("kernel.object_type_proc.state.external_module", QStringLiteral("非空 · 外部模块"));
    }
    else
    {
        text = kernelText("kernel.object_type_proc.state.unresolved", QStringLiteral("非空 · 模块未解析"));
    }

    if ((row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_DETOUR) != 0U)
    {
        text += QStringLiteral(" · ") + kernelText("kernel.object_type_proc.state.detour", QStringLiteral("入口跳板"));
    }
    if (!layoutVerified())
    {
        text += QStringLiteral(" · ") + kernelText("kernel.object_type_proc.state.reference_only", QStringLiteral("布局未验证，仅供参考"));
    }
    // TYPE_JUDGED 只在这一行所属的类型满足"类型内一致性"判据的前提时才置位（核心类型恒置位）。
    // 没置位又没有任何风险位，不代表"查过、干净"——只代表本版本对这一类型给不出硬判据，
    // 单独一行看不出这个区别，所以非空指针的"干净"行都要如实带上这句。
    else if (row.riskFlags == KSWORD_ARK_DRIVER_INTEGRITY_RISK_NONE &&
        (row.entryFlags & (KSWORD_ARK_OBJTYPE_ENTRY_FLAG_NULL_POINTER | KSWORD_ARK_OBJTYPE_ENTRY_FLAG_READ_FAILED)) == 0U &&
        (row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_TYPE_JUDGED) == 0U)
    {
        text += QStringLiteral(" · ") + kernelText(
            "kernel.object_type_proc.state.unjudged",
            QStringLiteral("本类型无硬判据，干净仅代表未查出问题"));
    }
    return text;
}

QString KernelObjectTypeProcedureTab::rowDetailText(const ProcedureRow& row) const
{
    const std::uint32_t risk = effectiveRisk(row);
    const bool hasDetour = (row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_DETOUR) != 0U;
    return ks::ui::integrity::tooltipText(risk)
        + QStringLiteral("\n")
        + kernelText(
            "kernel.object_type_proc.tooltip.detail",
            QStringLiteral("原始风险位 %1，入口跳板落点 %2，NTSTATUS %3"))
            .arg(hex32(row.riskFlags))
            .arg(hasDetour ? hex64(row.detourTargetAddress) : QStringLiteral("-"))
            .arg(hex32(static_cast<std::uint32_t>(row.lastStatus)));
}

void KernelObjectTypeProcedureTab::populateTable()
{
    m_table->setRowCount(0);
    m_table->setRowCount(static_cast<int>(m_rows.size()));
    for (int tableRow = 0; tableRow < static_cast<int>(m_rows.size()); ++tableRow)
    {
        const ProcedureRow& row = m_rows[static_cast<std::size_t>(tableRow)];
        // 空指针与读取失败都没有目标地址可展示，统一渲染成 "-"；
        // 两者的区别只由状态列承担，绝不用 0 地址冒充空值。
        const bool hasTarget =
            (row.entryFlags & (KSWORD_ARK_OBJTYPE_ENTRY_FLAG_NULL_POINTER |
                               KSWORD_ARK_OBJTYPE_ENTRY_FLAG_READ_FAILED)) == 0U;
        m_table->setItem(tableRow, 0, readOnlyItem(QString::number(row.typeIndex)));
        m_table->setItem(tableRow, 1, readOnlyItem(row.typeName.isEmpty() ? QStringLiteral("-") : row.typeName));
        m_table->setItem(tableRow, 2, readOnlyItem(methodText(row.procedureKind)));
        m_table->setItem(tableRow, 3, readOnlyItem(row.slotAddress != 0U ? hex64(row.slotAddress) : QStringLiteral("-")));
        m_table->setItem(tableRow, 4, readOnlyItem(hasTarget ? hex64(row.targetAddress) : QStringLiteral("-")));
        m_table->setItem(tableRow, 5, readOnlyItem(row.ownerModule.isEmpty() ? QStringLiteral("-") : row.ownerModule));
        m_table->setItem(tableRow, 6, readOnlyItem(row.sectionName.isEmpty() ? QStringLiteral("-") : row.sectionName));
        m_table->setItem(tableRow, kColumnRisk, readOnlyItem(ks::ui::integrity::riskText(effectiveRisk(row))));
        m_table->setItem(tableRow, 8, readOnlyItem(stateText(row)));
    }
    m_table->resizeColumnsToContents();
    applyRowHighlights();
    applyFilter();
    updateStatusLabel();
}

void KernelObjectTypeProcedureTab::applyRowHighlights()
{
    if (m_table == nullptr)
    {
        return;
    }

    // 表格行号与 m_rows 下标一一对应（populateTable 按序填充，本页不排序）。
    const int rowLimit = std::min(m_table->rowCount(), static_cast<int>(m_rows.size()));
    for (int tableRow = 0; tableRow < rowLimit; ++tableRow)
    {
        const ProcedureRow& row = m_rows[static_cast<std::size_t>(tableRow)];
        const std::uint32_t risk = effectiveRisk(row);
        // 带 HIDDEN_HOOK 的行由共享呈现单元整行 Danger 高亮，风险单元格文字以“存在隐藏行为”开头；
        // 风险位为 0 的行不挂 tooltip，避免每格都弹一句“正常”。
        ks::ui::integrity::applyRowHighlight(
            m_table,
            tableRow,
            ks::ui::integrity::tierOf(risk),
            risk == 0U ? QString() : rowDetailText(row));
    }
}

void KernelObjectTypeProcedureTab::updateStatusLabel()
{
    if (m_statusLabel == nullptr || !m_hasResult)
    {
        return;
    }

    QString text;
    QString colorHex = KswordTheme::TextSecondaryHex();
    if (m_queryFailed)
    {
        text = m_unsupported
            ? kernelText(
                "kernel.object_type_proc.unsupported",
                QStringLiteral("当前驱动不支持 ObjectType 方法指针查询（驱动版本较旧）。"))
            : kernelText("kernel.object_type_proc.query_failed", QStringLiteral("查询失败：%1"))
                .arg(m_ioMessage.isEmpty() ? QStringLiteral("-") : m_ioMessage);
        colorHex = KswordTheme::ErrorHex();
    }
    else if (!layoutVerified())
    {
        // 布局没通过自验证：不能显示一张空表就完事，必须明说检查没有启用，且这不代表没有 Hook。
        text = kernelText(
            "kernel.object_type_proc.layout_unverified",
            QStringLiteral("本机 ObjectType 方法指针布局未通过运行时自验证，检查未启用（这不代表没有 Hook）。"));
        // 说明为什么没验证过：这条链路既不依赖 DynData 也不依赖任何导出符号，
        // 别让人去错误的方向查。
        QString reasonText;
        switch (m_layoutReason)
        {
        case KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NO_MODULE_SNAPSHOT:
            reasonText = kernelText(
                "kernel.object_type_proc.reason.no_module_snapshot",
                QStringLiteral("原因：没有取到已加载模块快照，无法把任何指针归属到模块。"));
            break;
        case KSWORD_ARK_OBJTYPE_LAYOUT_REASON_TOO_FEW_TYPES:
            reasonText = kernelText(
                "kernel.object_type_proc.reason.too_few_types",
                QStringLiteral("原因：能读到的对象类型太少，统计没有意义。"));
            break;
        case KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NO_DOMINANT_ANCHOR:
            reasonText = kernelText(
                "kernel.object_type_proc.reason.no_dominant_anchor",
                QStringLiteral("原因：没有哪个偏移上出现足够多类型共享的 ntoskrnl 内指针（找不到唯一的锚点偏移）。"));
            break;
        case KSWORD_ARK_OBJTYPE_LAYOUT_REASON_BLOCK_SHAPE_FAILED:
            reasonText = kernelText(
                "kernel.object_type_proc.reason.block_shape_failed",
                QStringLiteral("原因：锚点找到了，但八槽方法指针块没有通过全体对象类型的一致性核对。"));
            break;
        case KSWORD_ARK_OBJTYPE_LAYOUT_REASON_OUT_OF_MEMORY:
            reasonText = kernelText(
                "kernel.object_type_proc.reason.out_of_memory",
                QStringLiteral("原因：驱动分配验证工作区失败。"));
            break;
        default:
            break;
        }
        if (!reasonText.isEmpty())
        {
            text += QStringLiteral(" ") + reasonText;
        }
        if (m_layoutAnchorTypes > 0U)
        {
            text += QStringLiteral(" ") + kernelText(
                "kernel.object_type_proc.layout_anchors_v2",
                QStringLiteral("参与统计的对象类型 %1 个，锚点偏移上共享同一个内核指针的类型 %2 个。"))
                .arg(m_layoutAnchorTypes)
                .arg(m_layoutAnchorAgree);
        }
        colorHex = KswordTheme::WarningHex();
    }
    else
    {
        std::uint32_t suspiciousRows = 0;
        std::uint32_t hiddenRows = 0;
        // 覆盖度：能给出硬判据的类型（entryFlags 带 TYPE_JUDGED）比上见过的类型总数——
        // 与 KswordCLI 的 judged_types 是同一个口径。不在这个数里的类型不代表"干净"，
        // 只代表本版本对它没有硬判据，只是没查出问题。
        QSet<std::uint32_t> judgedTypeIndices;
        QSet<std::uint32_t> seenTypeIndices;
        for (const ProcedureRow& row : m_rows)
        {
            const std::uint32_t risk = effectiveRisk(row);
            if (ks::ui::integrity::tierOf(risk) != ks::ui::integrity::Tier::Clean)
            {
                ++suspiciousRows;
            }
            if ((risk & KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK) != 0U)
            {
                ++hiddenRows;
            }
            seenTypeIndices.insert(row.typeIndex);
            if ((row.entryFlags & KSWORD_ARK_OBJTYPE_ENTRY_FLAG_TYPE_JUDGED) != 0U)
            {
                judgedTypeIndices.insert(row.typeIndex);
            }
        }
        text = kernelText(
            "kernel.object_type_proc.summary_v2",
            QStringLiteral("布局已验证（方法指针块偏移 %1，参与统计 %2 个对象类型，其中 %3 个共享锚点指针）。类型 %4 个，可疑 %5 行，存在隐藏行为 %6 行，有硬判据覆盖的类型 %7/%8。"))
            .arg(hex32(m_procedureBlockOffset))
            .arg(m_layoutAnchorTypes)
            .arg(m_layoutAnchorAgree)
            .arg(m_typeCount)
            .arg(suspiciousRows)
            .arg(hiddenRows)
            .arg(judgedTypeIndices.size())
            .arg(seenTypeIndices.size());
        // 结果被截断或有类型被跳过时，"0 可疑" 只代表已取到的那部分干净，不能涂成绿色的
        // "全部干净"——那会让用户把"没查完"读成"查完了、没事"。
        const bool incomplete = m_truncated || m_skippedTypes;
        colorHex = hiddenRows != 0U
            ? KswordTheme::ErrorHex()
            : (suspiciousRows != 0U || incomplete ? KswordTheme::WarningHex() : KswordTheme::SuccessHex());
    }

    if (m_truncated && !m_queryFailed)
    {
        text += QStringLiteral(" ") + kernelText(
            "kernel.object_type_proc.truncated",
            QStringLiteral("结果被截断，未取完全部对象类型。"));
    }
    if (m_skippedTypes && !m_queryFailed)
    {
        // 表槽读失败的类型没有任何行：不说明的话，"可疑 0 行"会被当成全部干净。
        text += QStringLiteral(" ") + kernelText(
            "kernel.object_type_proc.skipped_types",
            QStringLiteral("部分对象类型的表槽读取失败被跳过，结果不完整。"));
    }
    m_statusLabel->setStyleSheet(statusLabelStyle(colorHex));
    m_statusLabel->setText(text);
    m_statusLabel->setToolTip(m_ioMessage);
}

void KernelObjectTypeProcedureTab::applyFilter()
{
    const QString filterText = m_filterEdit == nullptr ? QString() : m_filterEdit->text().trimmed();
    const bool hasFilter = !filterText.isEmpty();
    if (m_table != nullptr)
    {
        for (int row = 0; row < m_table->rowCount(); ++row)
        {
            bool matched = !hasFilter;
            for (int column = 0; !matched && column < m_table->columnCount(); ++column)
            {
                const QTableWidgetItem* item = m_table->item(row, column);
                matched = item != nullptr && item->text().contains(filterText, Qt::CaseInsensitive);
            }
            m_table->setRowHidden(row, !matched);
        }
    }
    if (m_clearFilterButton != nullptr)
    {
        m_clearFilterButton->setEnabled(hasFilter);
    }
}

QString KernelObjectTypeProcedureTab::tableRowText(QTableWidget* table, const int row, const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }
    QStringList values;
    if (includeHeader)
    {
        QStringList headerValues;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            const QTableWidgetItem* headerItem = table->horizontalHeaderItem(column);
            headerValues << (headerItem == nullptr ? QString() : headerItem->text());
        }
        values << headerValues.join(QLatin1Char('\t'));
    }
    QStringList rowValues;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        rowValues << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    values << rowValues.join(QLatin1Char('\t'));
    return values.join(QLatin1Char('\n'));
}

void KernelObjectTypeProcedureTab::showCopyMenu(const QPoint& position)
{
    if (m_table == nullptr)
    {
        return;
    }
    const QModelIndex index = m_table->indexAt(position);
    const int row = index.isValid() ? index.row() : -1;
    QMenu menu(this);
    QAction* copyRow = menu.addAction(kernelText("kernel.object_type_proc.copy_row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(kernelText("kernel.object_type_proc.copy_all", QStringLiteral("复制全部行")));
    copyRow->setEnabled(row >= 0);
    copyAll->setEnabled(m_table->rowCount() > 0);
    QAction* selected = menu.exec(m_table->viewport()->mapToGlobal(position));
    if (selected == copyRow)
    {
        QApplication::clipboard()->setText(tableRowText(m_table, row, true));
    }
    else if (selected == copyAll)
    {
        // 只复制当前筛选下可见的行，表头只写一次。
        QStringList lines;
        for (int rowIndex = 0; rowIndex < m_table->rowCount(); ++rowIndex)
        {
            if (m_table->isRowHidden(rowIndex))
            {
                continue;
            }
            lines << tableRowText(m_table, rowIndex, lines.isEmpty());
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
}
