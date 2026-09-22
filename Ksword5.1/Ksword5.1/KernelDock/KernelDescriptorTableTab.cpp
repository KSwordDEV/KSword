#include "KernelDescriptorTableTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/IntegrityRiskPresentation.h"
#include "../UI/KernelDisassemblyDialog.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextEdit>
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum DescriptorColumn : int
    {
        ColumnTable = 0,
        ColumnCpu,
        ColumnVectorSelector,
        ColumnTableBase,
        ColumnTableLimit,
        ColumnEntryAddress,
        ColumnSize,
        ColumnTargetBase,
        ColumnSelector,
        ColumnType,
        ColumnDpl,
        ColumnPresent,
        ColumnIst,
        ColumnGranularity,
        ColumnOwner,
        ColumnRisk,
        ColumnBaseline,
        ColumnTrustedImageBaseline,
        ColumnRaw,
        ColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    QString tableStyle()
    {
        return QStringLiteral("QTableWidget{background:transparent;color:%1;} QHeaderView::section{color:%2;background:transparent;border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex());
    }
}

KernelDescriptorTableTab::KernelDescriptorTableTab(
    const KernelDescriptorTableKind tableKind,
    QWidget* parent)
    : QWidget(parent),
      m_tableKind(tableKind)
{
    initializeUi();
}

void KernelDescriptorTableTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(this, [this]() { refreshAsync(); }, Qt::QueuedConnection);
    }
}

void KernelDescriptorTableTab::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    // 行高亮的画刷在 rebuildTable 里按当时的主题令牌烘焙进单元格，换主题后会过期；
    // 收到应用调色板变更就用已缓存的 m_rows 重建一遍，不再访问驱动。
    if (event != nullptr
        && event->type() == QEvent::ApplicationPaletteChange
        && m_table != nullptr)
    {
        const QPointer<KernelDescriptorTableTab> safeThis(this);
        if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("kernel-descriptor-table-theme-rebuild"),
            { m_table },
            [safeThis]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->rebuildTable();
                }
            }))
        {
            return;
        }
        rebuildTable();
    }
}

void KernelDescriptorTableTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(5);

    // idtOnly 用于为两个独立子页选择精确文本，不在运行期改变页面类型。
    const bool idtOnly = m_tableKind == KernelDescriptorTableKind::Idt;
    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText(
            idtOnly ? "kernel.descriptor.refresh.idt" : "kernel.descriptor.refresh.gdt",
            idtOnly ? QStringLiteral("刷新 IDT") : QStringLiteral("刷新 GDT")),
        this);
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    if (idtOnly)
    {
        m_restoreIdtButton = new QPushButton(
            kernelText("kernel.descriptor.restore_idt", QStringLiteral("恢复选中 IDT 基线")),
            this);
        m_restoreIdtButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
        m_restoreIdtButton->setEnabled(false);
    }
    m_filterEdit = new QLineEdit(this);
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setPlaceholderText(kernelText(
        idtOnly
            ? "kernel.descriptor.filter.idt.placeholder"
            : "kernel.descriptor.filter.gdt.placeholder",
        idtOnly
            ? QStringLiteral("按 CPU、向量、地址、模块和风险筛选 IDT")
            : QStringLiteral("按 CPU、选择子、地址、类型和风险筛选 GDT")));
    m_statusLabel = new QLabel(kernelText("kernel.descriptor.status.waiting", QStringLiteral("状态：等待刷新")), this);
    m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));
    toolbar->addWidget(m_refreshButton);
    if (m_restoreIdtButton != nullptr)
    {
        toolbar->addWidget(m_restoreIdtButton);
    }
    toolbar->addWidget(m_filterEdit, 1);
    toolbar->addWidget(m_statusLabel);
    rootLayout->addLayout(toolbar);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    m_table = new ks::ui::VisibleTableWidget(splitter);
    m_table->setColumnCount(ColumnCount);
    m_table->setHorizontalHeaderLabels({
        kernelText("kernel.descriptor.header.table", QStringLiteral("表")),
        kernelText("kernel.descriptor.header.cpu", QStringLiteral("CPU")),
        kernelText("kernel.descriptor.header.vector_selector", QStringLiteral("向量/选择子")),
        kernelText("kernel.descriptor.header.table_base", QStringLiteral("表基址")),
        kernelText("kernel.descriptor.header.table_limit", QStringLiteral("表 Limit")),
        kernelText("kernel.descriptor.header.entry", QStringLiteral("表项地址")),
        kernelText("kernel.descriptor.header.size", QStringLiteral("大小")),
        kernelText("kernel.descriptor.header.target_base", QStringLiteral("Handler/段基址")),
        kernelText("kernel.descriptor.header.selector", QStringLiteral("SEL")),
        kernelText("kernel.descriptor.header.type", QStringLiteral("类型")),
        kernelText("kernel.descriptor.header.dpl", QStringLiteral("DPL")),
        kernelText("kernel.descriptor.header.present", QStringLiteral("Present")),
        kernelText("kernel.descriptor.header.ist", QStringLiteral("IST")),
        kernelText("kernel.descriptor.header.granularity", QStringLiteral("Granularity")),
        kernelText("kernel.descriptor.header.owner", QStringLiteral("归属模块")),
        kernelText("kernel.descriptor.header.risk", QStringLiteral("完整性")),
        kernelText("kernel.descriptor.header.baseline", QStringLiteral("启动期基线")),
        kernelText("kernel.descriptor.header.trusted_image_baseline", QStringLiteral("可信映像基线")),
        kernelText("kernel.descriptor.header.raw", QStringLiteral("原始值"))});
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->setContextMenuPolicy(Qt::CustomContextMenu);
    m_table->setStyleSheet(tableStyle());
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setStretchLastSection(true);
    m_table->verticalHeader()->setVisible(false);

    m_detailEdit = new QTextEdit(splitter);
    m_detailEdit->setReadOnly(true);
    m_detailEdit->setPlaceholderText(kernelText(
        idtOnly
            ? "kernel.descriptor.detail.idt.placeholder"
            : "kernel.descriptor.detail.gdt.placeholder",
        idtOnly
            ? QStringLiteral("选择 IDT 表项查看 Handler、位域和 R0 诊断详情")
            : QStringLiteral("选择 GDT 表项查看段描述符、位域和 R0 诊断详情")));
    splitter->addWidget(m_table);
    splitter->addWidget(m_detailEdit);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 1);
    rootLayout->addWidget(splitter, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshAsync(); });
    if (m_restoreIdtButton != nullptr)
    {
        connect(m_restoreIdtButton, &QPushButton::clicked, this, [this]() { restoreSelectedIdtBaseline(); });
    }
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&) { rebuildTable(); });
    connect(m_table, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCurrentDetail();
        if (m_restoreIdtButton == nullptr)
        {
            return;
        }
        bool canRestore = false;
        if (m_table->currentRow() >= 0)
        {
            const QTableWidgetItem* item = m_table->item(m_table->currentRow(), ColumnTable);
            if (item != nullptr)
            {
                const std::size_t sourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
                if (sourceIndex < m_rows.size())
                {
                    const auto& row = m_rows[sourceIndex];
                    canRestore =
                        row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER &&
                        (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) != 0U &&
                        (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS) != 0U;
                }
            }
        }
        m_restoreIdtButton->setEnabled(canRestore && !m_refreshRunning);
    });
    connect(m_table, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) { showCopyMenu(position); });
}

void KernelDescriptorTableTab::refreshAsync()
{
    if (m_refreshRunning)
    {
        return;
    }
    m_refreshRunning = true;
    m_firstRefreshStarted = true;
    m_refreshButton->setEnabled(false);
    if (m_restoreIdtButton != nullptr)
    {
        m_restoreIdtButton->setEnabled(false);
    }

    // queryFlags 只请求当前子页所需证据，避免切换 IDT/GDT 时重复传输另一张表。
    const bool idtOnly = m_tableKind == KernelDescriptorTableKind::Idt;
    const std::uint32_t queryFlags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU |
        (idtOnly
            ? KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES
            : KSWORD_ARK_DRIVER_INTEGRITY_FLAG_GDT_ENTRIES);
    m_statusLabel->setText(kernelText(
        idtOnly
            ? "kernel.descriptor.status.refreshing.idt"
            : "kernel.descriptor.status.refreshing.gdt",
        idtOnly
            ? QStringLiteral("正在按 CPU 读取 IDTR 与 IDT 表项...")
            : QStringLiteral("正在按 CPU 读取 GDTR 与 GDT 描述符...")));
    QPointer<KernelDescriptorTableTab> safeThis(this);
    std::thread([safeThis, queryFlags]() {
        ksword::ark::DriverClient client;
        ksword::ark::DriverIntegrityResult result = client.queryKernelCpuIntegrity(
            queryFlags,
            KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS);
        std::vector<ks::kernel::IdtHandlerObservation> observations;
        if (result.io.ok
            && (queryFlags
                & KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES) != 0U)
        {
            for (const ksword::ark::DriverIntegrityEvidenceEntry& row
                 : result.entries)
            {
                if (row.evidenceClass
                    == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
                {
                    observations.push_back({
                        row.vector,
                        row.descriptorBase
                    });
                }
            }
        }
        std::vector<ks::kernel::TrustedIdtBaselineResult>
            trustedIdtBaselines =
                ks::kernel::KernelCleanImageBaseline::compareIdtHandlers(
                    observations);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(safeThis, [
            safeThis,
            result = std::move(result),
            trustedIdtBaselines = std::move(trustedIdtBaselines)
        ]() mutable {
            if (safeThis != nullptr)
            {
                safeThis->applyResult(
                    std::move(result),
                    std::move(trustedIdtBaselines));
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDescriptorTableTab::applyResult(
    ksword::ark::DriverIntegrityResult result,
    std::vector<ks::kernel::TrustedIdtBaselineResult>
        trustedIdtBaselines)
{
    const QPointer<KernelDescriptorTableTab> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("kernel-descriptor-table-snapshot"),
        { m_table },
        [safeThis, result, trustedIdtBaselines]() mutable
        {
            if (!safeThis.isNull())
            {
                safeThis->applyResult(
                    std::move(result),
                    std::move(trustedIdtBaselines));
            }
        }))
    {
        return;
    }

    m_refreshRunning = false;
    m_refreshButton->setEnabled(true);
    if (m_restoreIdtButton != nullptr)
    {
        m_restoreIdtButton->setEnabled(false);
    }
    m_rows.clear();
    m_trustedIdtBaselines.clear();
    if (!result.io.ok)
    {
        // failureKey 与 fallbackText 由固定子页类型决定，避免错误信息仍写成 IDT/GDT 混合查询。
        const bool idtOnly = m_tableKind == KernelDescriptorTableKind::Idt;
        const QString errorText = result.io.message.empty()
            ? kernelText(
                idtOnly
                    ? "kernel.descriptor.status.failed.idt"
                    : "kernel.descriptor.status.failed.gdt",
                idtOnly ? QStringLiteral("IDT 查询失败") : QStringLiteral("GDT 查询失败"))
            : QString::fromStdString(result.io.message);
        m_statusLabel->setText(errorText);
        rebuildTable();
        return;
    }

    std::size_t idtCount = 0U;
    std::size_t gdtCount = 0U;
    std::size_t trustedIdtIndex = 0U;
    std::size_t hiddenRowCount = 0U;
    bool interruptLayoutUnverified = false;
    bool interruptPartial = false;
    QString interruptSummaryText;
    for (ksword::ark::DriverIntegrityEvidenceEntry& row : result.entries)
    {
        if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
        {
            ++idtCount;
            m_rows.push_back(std::move(row));
            if (trustedIdtIndex < trustedIdtBaselines.size())
            {
                m_trustedIdtBaselines.push_back(
                    std::move(
                        trustedIdtBaselines[trustedIdtIndex]));
            }
            else
            {
                m_trustedIdtBaselines.emplace_back();
            }
            ++trustedIdtIndex;
        }
        else if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR)
        {
            ++gdtCount;
            m_rows.push_back(std::move(row));
            m_trustedIdtBaselines.emplace_back();
        }
        else if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT
            && m_tableKind == KernelDescriptorTableKind::Idt)
        {
            // 沿 IDT 网关走到中断对象后取得的二级指针行：网关地址可以是干净的，
            // 被改的是 ServiceRoutine 等字段，所以必须和网关行放在同一张表里让人看到。
            if ((row.riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK) != 0U)
            {
                ++hiddenRowCount;
            }
            if ((row.riskFlags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_LAYOUT_UNVERIFIED) != 0U)
            {
                // 驱动对"完全没法检查"和"只有 Message/Dispatch 字段没验证"用同一个风险位，
                // 靠 detail 前缀区分：部分可用时 ServiceRoutine 仍然核对过了。
                if (row.detail.rfind(L"Interrupt-object check is partial", 0) == 0)
                {
                    interruptPartial = true;
                }
                else
                {
                    interruptLayoutUnverified = true;
                }
            }
            else if (row.ordinal == 3U && row.riskFlags == 0U)
            {
                // 整次查询的汇总行：干净时"检查确实做过"的证据。
                interruptSummaryText = QString::fromStdWString(row.detail);
            }
            m_rows.push_back(std::move(row));
            m_trustedIdtBaselines.emplace_back();
        }
    }
    // summary 只报告当前子页的表项数，CPU 和协议版本仍保留用于定位采集环境。
    const bool idtOnly = m_tableKind == KernelDescriptorTableKind::Idt;
    QString summary = idtOnly
        ? kernelText(
            "kernel.descriptor.status.completed.idt",
            QStringLiteral("已读取 %1 个 IDT 表项，CPU %2，协议 v%3"))
            .arg(static_cast<qulonglong>(idtCount))
            .arg(result.cpuCount)
            .arg(result.version)
        : kernelText(
            "kernel.descriptor.status.completed.gdt",
            QStringLiteral("已读取 %1 个 GDT 表项，CPU %2，协议 v%3"))
            .arg(static_cast<qulonglong>(gdtCount))
            .arg(result.cpuCount)
            .arg(result.version);
    if ((result.flags & KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED) != 0U ||
        (result.statusFlags & KSWORD_ARK_DRIVER_INTEGRITY_STATUS_FLAG_TRUNCATED) != 0U)
    {
        summary += kernelText("kernel.descriptor.status.truncated", QStringLiteral("；响应已截断，部分 CPU 表项未返回"));
    }
    if (idtOnly)
    {
        const std::size_t trustedAvailable = static_cast<std::size_t>(
            std::count_if(
                m_trustedIdtBaselines.cbegin(),
                m_trustedIdtBaselines.cend(),
                [](const ks::kernel::TrustedIdtBaselineResult& baseline)
                {
                    return baseline.available;
                }));
        const std::size_t trustedMismatch = static_cast<std::size_t>(
            std::count_if(
                m_trustedIdtBaselines.cbegin(),
                m_trustedIdtBaselines.cend(),
                [](const ks::kernel::TrustedIdtBaselineResult& baseline)
                {
                    return baseline.available
                        && !baseline.handlerMatches;
                }));
        summary += kernelText(
            "kernel.descriptor.status.trusted_baseline_summary",
            QStringLiteral(
                "；可信映像/PDB 基线可用 %1，偏离 %2，unsupported %3"))
            .arg(static_cast<qulonglong>(trustedAvailable))
            .arg(static_cast<qulonglong>(trustedMismatch))
            .arg(static_cast<qulonglong>(
                m_trustedIdtBaselines.size() - trustedAvailable));
    }
    if (idtOnly && hiddenRowCount != 0U)
    {
        // 用户的明确要求：检测到隐藏项要高亮并明说"存在隐藏行为"。
        summary += kernelText(
            "kernel.descriptor.status.hidden_hook",
            QStringLiteral("；检测到 %1 项隐藏行为（中断对象的二级指针被劫持，只核对 IDT 网关地址的检测发现不了它，见高亮行）"))
            .arg(static_cast<qulonglong>(hiddenRowCount));
    }
    else if (idtOnly && interruptLayoutUnverified)
    {
        summary += kernelText(
            "kernel.descriptor.status.interrupt_unverified",
            QStringLiteral("；中断对象二级检查在本机不可用（布局未通过运行时自验证，这不代表没有 Hook）"));
    }
    else if (idtOnly && !interruptSummaryText.isEmpty())
    {
        summary += kernelText(
            "kernel.descriptor.status.interrupt_clean",
            QStringLiteral("；中断对象二级核对完成，未发现隐藏行为（%1）"))
            .arg(interruptSummaryText);
    }
    if (idtOnly && hiddenRowCount == 0U && interruptPartial)
    {
        summary += kernelText(
            "kernel.descriptor.status.interrupt_partial",
            QStringLiteral("；中断对象二级检查只部分可用：ServiceRoutine 已核对，Message/Dispatch 字段未能通过自验证"));
    }
    m_statusLabel->setText(summary);
    rebuildTable();
}

bool KernelDescriptorTableTab::rowMatchesFilter(
    const ksword::ark::DriverIntegrityEvidenceEntry& row,
    const std::size_t sourceIndex) const
{
    // expectedClass 把实例固定为单一表类型，即使旧驱动意外返回混合证据也不会串页。
    const std::uint32_t expectedClass = m_tableKind == KernelDescriptorTableKind::Idt
        ? KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        : KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR;
    const bool interruptObjectRowOnIdtPage =
        m_tableKind == KernelDescriptorTableKind::Idt &&
        row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT;
    if (row.evidenceClass != expectedClass && !interruptObjectRowOnIdtPage)
    {
        return false;
    }
    const QString keyword = m_filterEdit->text().trimmed();
    if (keyword.isEmpty())
    {
        return true;
    }
    QStringList values;
    for (int column = 0; column < ColumnCount; ++column)
    {
        values.push_back(columnText(row, column, sourceIndex));
    }
    values.push_back(QString::fromStdWString(row.detail));
    return values.join(QLatin1Char(' ')).contains(keyword, Qt::CaseInsensitive);
}

void KernelDescriptorTableTab::rebuildTable()
{
    m_table->setRowCount(0);
    for (std::size_t sourceIndex = 0U; sourceIndex < m_rows.size(); ++sourceIndex)
    {
        const ksword::ark::DriverIntegrityEvidenceEntry& row = m_rows[sourceIndex];
        if (!rowMatchesFilter(row, sourceIndex))
        {
            continue;
        }
        const int tableRow = m_table->rowCount();
        m_table->insertRow(tableRow);
        for (int column = 0; column < ColumnCount; ++column)
        {
            QTableWidgetItem* item = readOnlyItem(
                columnText(row, column, sourceIndex));
            if (column == ColumnTable)
            {
                item->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
            }
            m_table->setItem(tableRow, column, item);
        }

        // 整行高亮由该行的 riskFlags 决定：带 HIDDEN_HOOK 的行整行标红并在 tooltip 里解释成因；
        // 单元格自己的前景色（完整性正常、可信映像基线一致/偏离）在整行高亮之后再叠加，不被它覆盖。
        ks::ui::integrity::applyRiskRowHighlight(m_table, tableRow, row.riskFlags);
        if (row.riskFlags == 0U)
        {
            m_table->item(tableRow, ColumnRisk)->setForeground(KswordTheme::SuccessColor());
        }
        if (sourceIndex < m_trustedIdtBaselines.size()
            && m_trustedIdtBaselines[sourceIndex].available)
        {
            m_table->item(tableRow, ColumnTrustedImageBaseline)->setForeground(
                m_trustedIdtBaselines[sourceIndex].handlerMatches
                    ? KswordTheme::SuccessColor()
                    : KswordTheme::ErrorColor());
        }
    }
    m_table->resizeColumnsToContents();
    showCurrentDetail();
}

QString KernelDescriptorTableTab::tableName(const ksword::ark::DriverIntegrityEvidenceEntry& row)
{
    if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT)
    {
        return QStringLiteral("IDT > KINTERRUPT");
    }
    return row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        ? QStringLiteral("IDT")
        : QStringLiteral("GDT");
}

// interruptFieldText 把中断对象证据行的 ordinal 翻成被核对的字段名。
// ordinal 为 ~0 的是"布局未验证"的说明行，不对应任何字段。
static QString interruptFieldText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
{
    switch (row.ordinal)
    {
    case 0U: return QStringLiteral("ServiceRoutine");
    case 1U: return QStringLiteral("MessageServiceRoutine");
    case 2U: return QStringLiteral("DispatchAddress");
    case 3U: return QStringLiteral("Summary");
    default: return QStringLiteral("-");
    }
}

QString KernelDescriptorTableTab::descriptorTypeText(const ksword::ark::DriverIntegrityEvidenceEntry& row)
{
    if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
    {
        if (row.descriptorType == 0xEU)
        {
            return kernelText("kernel.descriptor.type.interrupt_gate", QStringLiteral("Interrupt Gate"));
        }
        if (row.descriptorType == 0xFU)
        {
            return kernelText("kernel.descriptor.type.trap_gate", QStringLiteral("Trap Gate"));
        }
        return kernelText("kernel.descriptor.type.gate", QStringLiteral("Gate 0x%1")).arg(row.descriptorType, 0, 16);
    }
    if ((row.descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_USER_SEGMENT) != 0U)
    {
        const bool code = (row.descriptorType & 0x8U) != 0U;
        const bool accessed = (row.descriptorType & 0x1U) != 0U;
        const bool readableWritable = (row.descriptorType & 0x2U) != 0U;
        if (code)
        {
            return kernelText("kernel.descriptor.type.code", QStringLiteral("Code%1%2"))
                .arg(readableWritable ? QStringLiteral(" R") : QString())
                .arg(accessed ? QStringLiteral(" A") : QString());
        }
        return kernelText("kernel.descriptor.type.data", QStringLiteral("Data%1%2"))
            .arg(readableWritable ? QStringLiteral(" W") : QString())
            .arg(accessed ? QStringLiteral(" A") : QString());
    }
    switch (row.descriptorType)
    {
    case 0x0U: return kernelText("kernel.descriptor.type.reserved", QStringLiteral("Reserved"));
    case 0x2U: return QStringLiteral("LDT");
    case 0x9U: return kernelText("kernel.descriptor.type.tss_available", QStringLiteral("TSS Available"));
    case 0xBU: return kernelText("kernel.descriptor.type.tss_busy", QStringLiteral("TSS Busy"));
    case 0xCU: return kernelText("kernel.descriptor.type.call_gate", QStringLiteral("Call Gate"));
    case 0xEU: return kernelText("kernel.descriptor.type.interrupt_gate", QStringLiteral("Interrupt Gate"));
    case 0xFU: return kernelText("kernel.descriptor.type.trap_gate", QStringLiteral("Trap Gate"));
    default: return kernelText("kernel.descriptor.type.system", QStringLiteral("System 0x%1")).arg(row.descriptorType, 0, 16);
    }
}

QString KernelDescriptorTableTab::columnText(
    const ksword::ark::DriverIntegrityEvidenceEntry& row,
    const int column,
    const std::size_t sourceIndex) const
{
    if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT)
    {
        // 中断对象二级指针行只有一部分列有意义；其余列写 "-"，不套用 IDT 描述符的语义。
        // 布局未验证的说明行没有 CPU/向量（驱动把它们置成 ~0），也写 "-"。
        const bool noCpu = row.processorGroup == 0xFFFFFFFFU || row.processorNumber == 0xFFFFFFFFU;
        switch (column)
        {
        case ColumnTable: return tableName(row);
        case ColumnCpu:
            return noCpu ? QStringLiteral("-") : QStringLiteral("%1:%2").arg(row.processorGroup).arg(row.processorNumber);
        case ColumnVectorSelector:
            return row.vector == 0xFFFFFFFFU ? QStringLiteral("-") : QString::number(row.vector);
        case ColumnEntryAddress: return hex64(row.objectAddress);
        case ColumnTargetBase: return hex64(row.targetAddress);
        case ColumnType: return interruptFieldText(row);
        case ColumnOwner: return QString::fromStdWString(row.ownerModule);
        case ColumnRisk: return ks::ui::integrity::riskText(row.riskFlags);
        default: return QStringLiteral("-");
        }
    }
    const bool isIdt = row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER;
    switch (column)
    {
    case ColumnTable: return tableName(row);
    case ColumnCpu: return QStringLiteral("%1:%2").arg(row.processorGroup).arg(row.processorNumber);
    case ColumnVectorSelector:
        return isIdt ? QString::number(row.vector) : hex32(row.descriptorSelector);
    case ColumnTableBase: return hex64(row.descriptorTableBase);
    case ColumnTableLimit: return hex32(row.descriptorTableLimit);
    case ColumnEntryAddress: return hex64(row.objectAddress);
    case ColumnSize: return QString::number(row.descriptorSize);
    case ColumnTargetBase: return hex64(row.descriptorBase);
    case ColumnSelector: return hex32(row.descriptorSelector);
    case ColumnType: return descriptorTypeText(row);
    case ColumnDpl: return QString::number(row.descriptorDpl);
    case ColumnPresent:
        return (row.descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_PRESENT) != 0U ? QStringLiteral("P") : QStringLiteral("-");
    case ColumnIst:
        return isIdt ? QString::number(static_cast<unsigned int>((row.descriptorRawLow >> 32) & 0x7ULL)) : QStringLiteral("-");
    case ColumnGranularity:
        return isIdt
            ? QStringLiteral("-")
            : ((row.descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_GRANULARITY_PAGE) != 0U ? QStringLiteral("PAGE") : QStringLiteral("BYTE"));
    case ColumnOwner: return QString::fromStdWString(row.ownerModule);
    case ColumnRisk: return ks::ui::integrity::riskText(row.riskFlags);
    case ColumnBaseline:
        if ((row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) == 0U)
        {
            return kernelText("kernel.descriptor.baseline.unavailable", QStringLiteral("不可用"));
        }
        return (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS) != 0U
            ? hex64(row.descriptorBaselineRawLow) + QStringLiteral(" / ") + hex64(row.descriptorBaselineRawHigh)
            : kernelText("kernel.descriptor.baseline.matches", QStringLiteral("一致"));
    case ColumnTrustedImageBaseline:
        if (!isIdt || sourceIndex >= m_trustedIdtBaselines.size())
        {
            return QStringLiteral("-");
        }
        if (!m_trustedIdtBaselines[sourceIndex].available)
        {
            return kernelText(
                "kernel.descriptor.trusted_baseline.unsupported",
                QStringLiteral("Unsupported"));
        }
        return m_trustedIdtBaselines[sourceIndex].handlerMatches
            ? kernelText(
                "kernel.descriptor.trusted_baseline.matches",
                QStringLiteral("一致"))
            : kernelText(
                "kernel.descriptor.trusted_baseline.differs",
                QStringLiteral("偏离"));
    case ColumnRaw:
        return row.descriptorSize > 8U
            ? hex64(row.descriptorRawLow) + QStringLiteral(" / ") + hex64(row.descriptorRawHigh)
            : hex64(row.descriptorRawLow);
    default: return {};
    }
}

QString KernelDescriptorTableTab::detailText(
    const ksword::ark::DriverIntegrityEvidenceEntry& row,
    const std::size_t sourceIndex) const
{
    QStringList lines;
    lines << kernelText("kernel.descriptor.detail.table", QStringLiteral("表: %1")).arg(tableName(row));
    lines << kernelText("kernel.descriptor.detail.cpu", QStringLiteral("CPU: %1:%2")).arg(row.processorGroup).arg(row.processorNumber);
    lines << kernelText("kernel.descriptor.detail.table_range", QStringLiteral("表基址: %1  Limit: %2")).arg(hex64(row.descriptorTableBase), hex32(row.descriptorTableLimit));
    lines << kernelText("kernel.descriptor.detail.entry", QStringLiteral("表项: %1  大小: %2")).arg(hex64(row.objectAddress)).arg(row.descriptorSize);
    lines << kernelText("kernel.descriptor.detail.decoded", QStringLiteral("选择子: %1  类型: %2  DPL: %3  基址/Handler: %4  Limit: %5"))
        .arg(hex32(row.descriptorSelector), descriptorTypeText(row))
        .arg(row.descriptorDpl)
        .arg(hex64(row.descriptorBase), hex64(row.descriptorLimit));
    lines << kernelText("kernel.descriptor.detail.flags", QStringLiteral("Flags: %1  风险: %2")).arg(hex32(row.descriptorFlags), ks::ui::integrity::riskText(row.riskFlags));
    lines << kernelText("kernel.descriptor.detail.raw", QStringLiteral("Raw: %1 / %2")).arg(hex64(row.descriptorRawLow), hex64(row.descriptorRawHigh));
    if ((row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) != 0U)
    {
        lines << kernelText(
            "kernel.descriptor.detail.baseline",
            QStringLiteral("启动期基线 #%1: Handler %2  Raw %3 / %4"))
            .arg(row.descriptorBaselineGeneration)
            .arg(hex64(row.descriptorBaselineHandler))
            .arg(hex64(row.descriptorBaselineRawLow))
            .arg(hex64(row.descriptorBaselineRawHigh));
    }
    if (row.evidenceClass
            == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        && sourceIndex < m_trustedIdtBaselines.size())
    {
        const ks::kernel::TrustedIdtBaselineResult& trusted =
            m_trustedIdtBaselines[sourceIndex];
        lines << kernelText(
            "kernel.descriptor.detail.trusted_baseline",
            QStringLiteral(
                "可信映像基线: %1\n主预期 Handler: %2\nPDB 候选数: %3\n观察 Handler: %4\n"
                "映像: %5\nSHA256: %6\nProfile: %7\n来源符号: %8\n状态: %9"))
            .arg(trusted.available
                ? QStringLiteral("AVAILABLE")
                : QStringLiteral("UNSUPPORTED"))
            .arg(hex64(trusted.expectedHandler))
            .arg(trusted.expectedCandidateCount)
            .arg(hex64(trusted.observedHandler))
            .arg(trusted.imagePath.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.imagePath)
            .arg(trusted.imageSha256.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.imageSha256)
            .arg(trusted.profilePath.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.profilePath)
            .arg(trusted.sourceSymbol.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.sourceSymbol)
            .arg(trusted.statusText);
    }
    if (!row.ownerModule.empty())
    {
        lines << kernelText("kernel.descriptor.detail.owner", QStringLiteral("归属模块: %1 [%2 +%3]"))
            .arg(QString::fromStdWString(row.ownerModule), hex64(row.ownerModuleBase), hex32(row.ownerModuleSize));
    }
    if (!row.detail.empty())
    {
        lines << QString() << QString::fromStdWString(row.detail);
    }
    return lines.join(QLatin1Char('\n'));
}

void KernelDescriptorTableTab::showCurrentDetail()
{
    if (m_table->currentRow() < 0)
    {
        m_detailEdit->clear();
        return;
    }
    const QTableWidgetItem* item = m_table->item(m_table->currentRow(), ColumnTable);
    if (item == nullptr)
    {
        m_detailEdit->clear();
        return;
    }
    const std::size_t sourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    m_detailEdit->setPlainText(
        sourceIndex < m_rows.size()
            ? detailText(m_rows[sourceIndex], sourceIndex)
            : QString());
}

void KernelDescriptorTableTab::restoreSelectedIdtBaseline()
{
    const int selectedRow = m_table->currentRow();
    const QTableWidgetItem* item = selectedRow >= 0 ? m_table->item(selectedRow, ColumnTable) : nullptr;
    if (item == nullptr)
    {
        return;
    }
    const std::size_t sourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    if (sourceIndex >= m_rows.size())
    {
        return;
    }
    const auto row = m_rows[sourceIndex];
    if (row.evidenceClass != KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER ||
        row.processorGroup > 0xFFFFU ||
        row.processorNumber > 0xFFU ||
        row.vector > 0xFFU ||
        (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) == 0U ||
        (row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_DIFFERS) == 0U)
    {
        QMessageBox::information(
            this,
            kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
            kernelText("kernel.descriptor.restore.not_needed", QStringLiteral("该行没有可恢复的 IDT 基线差异。")));
        return;
    }

    ksword::ark::DriverClient client;
    const auto preflight = client.restoreIdtBaseline(
        static_cast<std::uint16_t>(row.processorGroup),
        static_cast<std::uint8_t>(row.processorNumber),
        static_cast<std::uint8_t>(row.vector),
        row.descriptorRawLow,
        row.descriptorRawHigh,
        false,
        false);
    if (!preflight.io.ok ||
        preflight.status != KSWORD_ARK_IDT_RESTORE_STATUS_FORCE_REQUIRED)
    {
        QMessageBox::critical(
            this,
            kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
            kernelText(
                "kernel.descriptor.restore.preflight_failed",
                QStringLiteral("R0 预检未通过。状态 %1，NTSTATUS %2。\n%3"))
                .arg(preflight.status)
                .arg(hex32(static_cast<std::uint32_t>(preflight.lastStatus)))
                .arg(QString::fromStdString(preflight.io.message)));
        return;
    }

    QMessageBox::warning(
        this,
        kernelText("kernel.descriptor.restore.warning_title", QStringLiteral("高风险：修改 IDT")),
        kernelText(
            "kernel.descriptor.restore.warning",
            QStringLiteral("将原子替换 CPU %1:%2 的 IDT 向量 %3。错误的中断门会立即造成系统崩溃；仅在已确认当前值异常且启动期基线可信时继续。"))
            .arg(row.processorGroup)
            .arg(row.processorNumber)
            .arg(row.vector));
    bool accepted = false;
    const QString confirmation = QInputDialog::getText(
        this,
        kernelText("kernel.descriptor.restore.confirm_title", QStringLiteral("确认恢复 IDT")),
        kernelText("kernel.descriptor.restore.confirm_prompt", QStringLiteral("输入 RESTORE IDT 继续：")),
        QLineEdit::Normal,
        QString(),
        &accepted);
    if (!accepted || confirmation != QStringLiteral("RESTORE IDT"))
    {
        return;
    }

    const auto restored = client.restoreIdtBaseline(
        static_cast<std::uint16_t>(row.processorGroup),
        static_cast<std::uint8_t>(row.processorNumber),
        static_cast<std::uint8_t>(row.vector),
        row.descriptorRawLow,
        row.descriptorRawHigh,
        true,
        true);
    if (!restored.io.ok || restored.status != KSWORD_ARK_IDT_RESTORE_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
            kernelText(
                "kernel.descriptor.restore.failed",
                QStringLiteral("IDT 恢复失败。状态 %1，NTSTATUS %2。\n%3"))
                .arg(restored.status)
                .arg(hex32(static_cast<std::uint32_t>(restored.lastStatus)))
                .arg(QString::fromStdString(restored.io.message)));
        return;
    }
    QMessageBox::information(
        this,
        kernelText("kernel.descriptor.restore.title", QStringLiteral("恢复 IDT 基线")),
        kernelText(
            "kernel.descriptor.restore.completed",
            QStringLiteral("IDT 表项已按启动期基线恢复，并完成原子写入后的逐位校验。")));
    refreshAsync();
}

QString KernelDescriptorTableTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0')).toUpper();
}

QString KernelDescriptorTableTab::hex32(const std::uint32_t value)
{
    return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')).toUpper();
}

QString KernelDescriptorTableTab::rowClipboardText(QTableWidget* table, const int row, const bool includeHeader)
{
    if (table == nullptr || row < 0 || row >= table->rowCount())
    {
        return {};
    }
    QStringList lines;
    if (includeHeader)
    {
        QStringList headers;
        for (int column = 0; column < table->columnCount(); ++column)
        {
            headers << (table->horizontalHeaderItem(column) == nullptr ? QString() : table->horizontalHeaderItem(column)->text());
        }
        lines << headers.join(QLatin1Char('\t'));
    }
    QStringList values;
    for (int column = 0; column < table->columnCount(); ++column)
    {
        values << (table->item(row, column) == nullptr ? QString() : table->item(row, column)->text());
    }
    lines << values.join(QLatin1Char('\t'));
    return lines.join(QLatin1Char('\n'));
}

void KernelDescriptorTableTab::showCopyMenu(const QPoint& position)
{
    const QModelIndex index = m_table->indexAt(position);
    const int row = index.isValid() ? index.row() : m_table->currentRow();
    QMenu menu(this);
    QAction* copyCell = menu.addAction(kernelText("kernel.descriptor.copy.cell", QStringLiteral("复制单元格")));
    QAction* copyRow = menu.addAction(kernelText("kernel.descriptor.copy.row", QStringLiteral("复制当前行")));
    QAction* copyAll = menu.addAction(kernelText("kernel.descriptor.copy.all", QStringLiteral("复制全部行")));
    menu.addSeparator();
    QMenu* advancedAnalysis = menu.addMenu(
        QStringLiteral("高级分析"));
    QAction* instructionView = advancedAnalysis->addAction(
        QStringLiteral("指令视图…"));
    copyCell->setEnabled(index.isValid());
    copyRow->setEnabled(row >= 0);
    copyAll->setEnabled(m_table->rowCount() > 0);
    std::size_t sourceIndex = m_rows.size();
    if (row >= 0)
    {
        const QTableWidgetItem* sourceItem =
            m_table->item(row, ColumnTable);
        if (sourceItem != nullptr)
        {
            sourceIndex = static_cast<std::size_t>(
                sourceItem->data(Qt::UserRole).toULongLong());
        }
    }
    const bool canOpenInstructionView =
        sourceIndex < m_rows.size()
        && m_rows[sourceIndex].evidenceClass
            == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        && m_rows[sourceIndex].descriptorBase != 0U;
    instructionView->setEnabled(canOpenInstructionView);
    QAction* selected = menu.exec(m_table->viewport()->mapToGlobal(position));
    if (selected == copyCell && index.isValid())
    {
        const QTableWidgetItem* item = m_table->item(index.row(), index.column());
        QApplication::clipboard()->setText(item == nullptr ? QString() : item->text());
    }
    else if (selected == copyRow)
    {
        QApplication::clipboard()->setText(rowClipboardText(m_table, row, true));
    }
    else if (selected == copyAll)
    {
        QStringList lines;
        for (int tableRow = 0; tableRow < m_table->rowCount(); ++tableRow)
        {
            lines << rowClipboardText(m_table, tableRow, tableRow == 0);
        }
        QApplication::clipboard()->setText(lines.join(QLatin1Char('\n')));
    }
    else if (selected == instructionView
        && canOpenInstructionView)
    {
        const auto& descriptor = m_rows[sourceIndex];
        ks::ui::KernelDisassemblyDialog::openKernelAddress(
            this,
            descriptor.descriptorBase,
            QStringLiteral(
                "IDT 向量 %1（CPU %2:%3）Handler")
                .arg(descriptor.vector)
                .arg(descriptor.processorGroup)
                .arg(descriptor.processorNumber));
    }
}
