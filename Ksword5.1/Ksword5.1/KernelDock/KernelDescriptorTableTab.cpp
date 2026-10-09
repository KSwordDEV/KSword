#include "KernelDescriptorTableTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/IntegrityRiskPresentation.h"
#include "../UI/KernelDisassemblyDialog.h"
// IDT/GDT 表项、它指向的代码、以及这张表所在页的 PTE，三条监视共用统一入口。
#include "../UI/HvmWatchDialog.h"
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
#include "../UI/StructuredFieldView.h"
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

    m_detailEdit = new ks::ui::StructuredFieldView(splitter);

    m_detailEdit->setDocument(ks::ui::FieldDocument{}.note(kernelText(
        idtOnly
            ? "kernel.descriptor.detail.idt.placeholder"
            : "kernel.descriptor.detail.gdt.placeholder",
        idtOnly
            ? QStringLiteral("选择 IDT 表项查看 Handler、位域和 R0 诊断详情")
            : QStringLiteral("选择 GDT 表项查看段描述符、位域和 R0 诊断详情"))));
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
    // m_trustedIdtBaselines 按 sourceIndex 和 m_rows 对齐，GDT/中断对象行也要占位——
    // 但信任基线摘要只该统计真正的 IDT 网关行，那些占位槽本身不是"未支持的网关"，
    // 不能被 count_if(m_trustedIdtBaselines) 一起数进 unsupported。这里在推入的同时
    // 单独记一份只含网关行的统计。
    std::size_t trustedGateTotal = 0U;
    std::size_t trustedGateAvailable = 0U;
    std::size_t trustedGateMismatch = 0U;
    bool interruptLayoutUnverified = false;
    bool interruptPartial = false;
    QString interruptSummaryText;
    for (ksword::ark::DriverIntegrityEvidenceEntry& row : result.entries)
    {
        if (row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER)
        {
            ++idtCount;
            m_rows.push_back(std::move(row));
            ++trustedGateTotal;
            if (trustedIdtIndex < trustedIdtBaselines.size())
            {
                const ks::kernel::TrustedIdtBaselineResult& baseline = trustedIdtBaselines[trustedIdtIndex];
                if (baseline.available)
                {
                    ++trustedGateAvailable;
                    if (!baseline.handlerMatches)
                    {
                        ++trustedGateMismatch;
                    }
                }
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
        // 用推入网关行时同步记的统计，不能用 m_trustedIdtBaselines.size()：那个数组还
        // 混着中断对象行的占位槽（为了按 sourceIndex 跟 m_rows 对齐），拿它当分母会把
        // "这一行根本不是网关"也算进 unsupported，虚报本机不支持的网关数。
        summary += kernelText(
            "kernel.descriptor.status.trusted_baseline_summary",
            QStringLiteral(
                "；可信映像/PDB 基线可用 %1，偏离 %2，unsupported %3"))
            .arg(static_cast<qulonglong>(trustedGateAvailable))
            .arg(static_cast<qulonglong>(trustedGateMismatch))
            .arg(static_cast<qulonglong>(
                trustedGateTotal - trustedGateAvailable));
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

ks::ui::FieldDocument KernelDescriptorTableTab::detailText(
    const ksword::ark::DriverIntegrityEvidenceEntry& row,
    const std::size_t sourceIndex) const
{
    ks::ui::FieldDocument lines;
    lines.field(QStringLiteral("表"), QStringLiteral("%1").arg(tableName(row)));
    lines.field(QStringLiteral("CPU"), QStringLiteral("%1:%2").arg(QStringLiteral("%1").arg(row.processorGroup)).arg(QStringLiteral("%1").arg(row.processorNumber)));
    lines.field(QStringLiteral("表基址"), QStringLiteral("%1").arg(hex64(row.descriptorTableBase)));
    lines.field(QStringLiteral("Limit"), QStringLiteral("%1").arg(hex32(row.descriptorTableLimit)));
    lines.field(QStringLiteral("表项"), QStringLiteral("%1  大小: %2").arg(QStringLiteral("%1").arg(hex64(row.objectAddress))).arg(QStringLiteral("%1").arg(row.descriptorSize)));
    lines.field(QStringLiteral("选择子"), QStringLiteral("%1  类型: %2").arg(QStringLiteral("%1").arg(hex32(row.descriptorSelector))).arg(QStringLiteral("%1").arg(descriptorTypeText(row))));
    lines.field(QStringLiteral("DPL"), QStringLiteral("%1  基址/Handler: %2").arg(QStringLiteral("%1").arg(row.descriptorDpl)).arg(QStringLiteral("%1").arg(hex64(row.descriptorBase))));
    lines.field(QStringLiteral("Limit"), QStringLiteral("%1").arg(hex64(row.descriptorLimit)));
    lines.field(QStringLiteral("Flags"), QStringLiteral("%1  风险: %2").arg(QStringLiteral("%1").arg(hex32(row.descriptorFlags))).arg(QStringLiteral("%1").arg(ks::ui::integrity::riskText(row.riskFlags))));
    lines.field(QStringLiteral("Raw"), QStringLiteral("%1 / %2").arg(QStringLiteral("%1").arg(hex64(row.descriptorRawLow))).arg(QStringLiteral("%1").arg(hex64(row.descriptorRawHigh))));
    if ((row.descriptorBaselineFlags & KSWORD_ARK_DESCRIPTOR_BASELINE_FLAG_AVAILABLE) != 0U)
    {
        lines.field(QStringLiteral("启动期基线 #"), QStringLiteral("启动期基线 #%1: Handler %2  Raw %3 / %4").arg(QStringLiteral("%1").arg(row.descriptorBaselineGeneration)).arg(QStringLiteral("%1").arg(hex64(row.descriptorBaselineHandler))).arg(QStringLiteral("%1").arg(hex64(row.descriptorBaselineRawLow))).arg(QStringLiteral("%1").arg(hex64(row.descriptorBaselineRawHigh))));
    }
    if (row.evidenceClass
            == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER
        && sourceIndex < m_trustedIdtBaselines.size())
    {
        const ks::kernel::TrustedIdtBaselineResult& trusted =
            m_trustedIdtBaselines[sourceIndex];
        lines.field(QStringLiteral("可信映像基线"), QStringLiteral("%1").arg(trusted.available
                ? QStringLiteral("AVAILABLE")
                : QStringLiteral("UNSUPPORTED")));
        lines.field(QStringLiteral("主预期 Handler"), QStringLiteral("%1").arg(hex64(trusted.expectedHandler)));
        lines.field(QStringLiteral("PDB 候选数"), QStringLiteral("%1").arg(trusted.expectedCandidateCount));
        lines.field(QStringLiteral("观察 Handler"), QStringLiteral("%1").arg(hex64(trusted.observedHandler)));
        lines.field(QStringLiteral("映像"), QStringLiteral("%1").arg(trusted.imagePath.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.imagePath));
        lines.field(QStringLiteral("SHA256"), QStringLiteral("%1").arg(trusted.imageSha256.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.imageSha256));
        lines.field(QStringLiteral("Profile"), QStringLiteral("%1").arg(trusted.profilePath.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.profilePath));
        lines.field(QStringLiteral("来源符号"), QStringLiteral("%1").arg(trusted.sourceSymbol.isEmpty()
                ? QStringLiteral("<unavailable>")
                : trusted.sourceSymbol));
        lines.field(QStringLiteral("状态"), QStringLiteral("%1").arg(trusted.statusText));
    }
    if (!row.ownerModule.empty())
    {
        lines.field(QStringLiteral("归属模块"), QStringLiteral("%1 [%2 +%3]").arg(QStringLiteral("%1").arg(QString::fromStdWString(row.ownerModule))).arg(QStringLiteral("%1").arg(hex64(row.ownerModuleBase))).arg(QStringLiteral("%1").arg(hex32(row.ownerModuleSize))));
    }
    if (!row.detail.empty())
    {

        lines.note(QString::fromStdWString(row.detail));
    }
    return lines;
}

void KernelDescriptorTableTab::showCurrentDetail()
{
    if (m_table->currentRow() < 0)
    {
        m_detailEdit->setDocument({});
        return;
    }
    const QTableWidgetItem* item = m_table->item(m_table->currentRow(), ColumnTable);
    if (item == nullptr)
    {
        m_detailEdit->setDocument({});
        return;
    }
    const std::size_t sourceIndex = static_cast<std::size_t>(item->data(Qt::UserRole).toULongLong());
    m_detailEdit->setDocument(sourceIndex < m_rows.size()
            ? detailText(m_rows[sourceIndex], sourceIndex)
            : ks::ui::FieldDocument{});
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

    /*
     * HVM 监视入口。
     *
     * 三个请求在 menu.exec() **之前**就算好并存进局部量，而不是等选完再去
     * 读 m_rows[sourceIndex]。理由是这一页的刷新走
     * std::thread(...).detach() 加 Qt::QueuedConnection 回投，而 menu.exec()
     * 本身是一个嵌套事件循环——菜单开着的那几秒里整张 m_rows 可以被换掉。
     * 那时按 sourceIndex 取到的是另一行，而后果不是报错，是悄悄监视了一页
     * 毫不相干的内存。上面那条"指令视图"就是 exec 之后才取的，属于既有形态，
     * 这里不跟着它错。
     */
    const WatchPlan watchPlan = buildWatchPlan(sourceIndex);
    menu.addSeparator();
    QAction* const watchEntry = menu.addAction(kernelText(
        "kernel.descriptor.menu.hvm_watch_entry",
        QStringLiteral("HVM 监视：下一次写入这一个表项")));
    watchEntry->setEnabled(watchPlan.entryValid);
    watchEntry->setToolTip(watchPlan.entryTip);
    QAction* const watchTarget = menu.addAction(kernelText(
        "kernel.descriptor.menu.hvm_watch_target",
        QStringLiteral("HVM 监视：下一次执行这一项指向的代码")));
    watchTarget->setEnabled(watchPlan.targetValid);
    watchTarget->setToolTip(watchPlan.targetTip);
    QAction* const watchPte = menu.addAction(kernelText(
        "kernel.descriptor.menu.hvm_watch_pte",
        QStringLiteral("HVM 监视：下一次写入这张表所在页的页表项")));
    watchPte->setEnabled(watchPlan.pteValid);
    watchPte->setToolTip(kernelText(
        "kernel.descriptor.menu.hvm_watch_pte.tip",
        QStringLiteral("盯的不是表本身，而是指向它的那一项页表项——回答的是「谁把这张表重映射到别处了」。表被整体搬走时，表内容一个字节都不用改。")));

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
    // 三条监视都用 exec 之前算好的 watchPlan，不再回头读 m_rows。
    else if (selected == watchEntry && watchPlan.entryValid)
    {
        ks::ui::HvmWatchRequest request;
        request.virtualAddress = true;
        request.address = watchPlan.entryAddress;
        request.length = watchPlan.entryLength;
        request.access = KSWORD_ARK_HVM_EPT_ACCESS_WRITE;
        request.label = watchPlan.entryLabel;
        ks::ui::openHvmWatch(this, request);
    }
    else if (selected == watchTarget && watchPlan.targetValid)
    {
        ks::ui::HvmWatchRequest request;
        request.virtualAddress = true;
        request.address = watchPlan.targetAddress;
        request.length = 1ULL;
        request.access = KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE;
        request.label = watchPlan.targetLabel;
        ks::ui::openHvmWatch(this, request);
    }
    else if (selected == watchPte && watchPlan.pteValid)
    {
        ks::ui::openHvmWatchOnPte(
            this, watchPlan.pteSourceAddress, watchPlan.pteLabel);
    }
}

/*
 * buildWatchPlan：在弹出菜单之前，把这一行能建的三条监视全部算好。
 *
 * 入参 SourceIndex 是 m_rows 的下标（不是表格行号——表格可排序）。
 * 出参是一份自足的快照：地址、长度、标签、启用与否、以及每一项的提示文字。
 * 菜单关闭后只读这份快照，不再碰 m_rows。
 *
 * 为什么整份算好而不是选完再算：menu.exec() 是嵌套事件循环，而本页的刷新是
 * 后台线程加 QueuedConnection 回投的，菜单开着时 m_rows 可以被整体替换。
 * 那之后按同一个下标取到的是另一行，而这种错不报错，只是监视了别处。
 */
KernelDescriptorTableTab::WatchPlan
KernelDescriptorTableTab::buildWatchPlan(const std::size_t sourceIndex) const
{
    WatchPlan plan;
    if (sourceIndex >= m_rows.size())
    {
        plan.entryTip = kernelText(
            "kernel.descriptor.menu.hvm_watch.no_row",
            QStringLiteral("请先选中一行。"));
        plan.targetTip = plan.entryTip;
        return plan;
    }
    const ksword::ark::DriverIntegrityEvidenceEntry& row = m_rows[sourceIndex];
    const bool isDescriptor =
        row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER ||
        row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR;
    /*
     * 中断对象行混在同一张表里，而且有两类**没有可用地址**的行必须挡掉。
     *
     * 一类是布局未验证说明行：它的 objectAddress 不是 0 而是 KPRCB 地址，
     * 所以 "!= 0" 这个常见判据挡不住它——照着装下去就是对 KPRCB 那一页开
     * 写监视。它的标志是 group/number/vector 被置成 0xFFFFFFFF。
     * 另一类是 ordinal == 3 的汇总行，同样没有单项地址。
     */
    const bool isInterruptObject =
        row.evidenceClass == KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT &&
        row.processorGroup != 0xFFFFFFFFU &&
        row.processorNumber != 0xFFFFFFFFU &&
        row.vector != 0xFFFFFFFFU &&
        row.ordinal <= 2U;
    // 驱动自己都没读出这一项时不放行：安装会在翻译处失败，说明不了问题。
    const bool readFailed =
        (row.descriptorFlags & KSWORD_ARK_DESCRIPTOR_FLAG_READ_FAILED) != 0U;
    const QString tableName = m_tableKind == KernelDescriptorTableKind::Idt
        ? QStringLiteral("IDT")
        : QStringLiteral("GDT");
    const QString whereText = kernelText(
        "kernel.descriptor.menu.hvm_watch.where",
        QStringLiteral("%1[%2]（CPU %3:%4）"))
        .arg(tableName)
        .arg(row.vector)
        .arg(row.processorGroup)
        .arg(row.processorNumber);

    if (isDescriptor && !readFailed && row.objectAddress != 0ULL)
    {
        plan.entryValid = true;
        plan.entryAddress = row.objectAddress;
        /*
         * 长度用驱动回报的描述符宽度，并且**收到本页剩余字节**。
         *
         * 不把"表项跨页"当成禁用条件：表基址未对齐正是 IDT_TABLE_RELOCATED
         * 要查的情形，在那一刻把入口灰掉，等于在最该监视的时候关掉它。
         * 跨页时硬件仍然只覆盖前一页，所以把 length 收到实际覆盖的那一段，
         * 并在提示里说明——收窄的是"命中算不算落在你的目标上"这个判据，
         * 不是硬件监视范围。
         */
        const unsigned long long width = row.descriptorSize != 0U
            ? static_cast<unsigned long long>(row.descriptorSize)
            : 16ULL;
        const unsigned long long remaining =
            0x1000ULL - (row.objectAddress & 0xFFFULL);
        plan.entryLength = width <= remaining ? width : remaining;
        // 同一个表项地址在几个 CPU 上重复，就说几个——不写死"每核一份"。
        std::size_t sameAddress = 0;
        for (const ksword::ark::DriverIntegrityEvidenceEntry& other : m_rows)
        {
            if (other.evidenceClass == row.evidenceClass &&
                other.vector == row.vector &&
                other.objectAddress == row.objectAddress)
            {
                ++sameAddress;
            }
        }
        plan.entryLabel = kernelText(
            "kernel.descriptor.menu.hvm_watch_entry.label",
            QStringLiteral("%1 表项"))
            .arg(whereText);
        plan.entryTip = kernelText(
            "kernel.descriptor.menu.hvm_watch_entry.tip",
            QStringLiteral("盯这一项本身（%1 字节），等下一次有人改它。这一项的地址在 %2 个 CPU 行上是同一个，所以装一条就覆盖了那几个核；其余核的同名向量若指向别的表，要各装一条。%3"))
            .arg(plan.entryLength)
            .arg(sameAddress)
            .arg(width > remaining
                ? kernelText(
                    "kernel.descriptor.menu.hvm_watch_entry.tip_split",
                    QStringLiteral("注意：这一项横跨页边界，硬件只覆盖它在前一页的 %1 字节，后面 %2 字节不在被监视的页上。"))
                    .arg(remaining).arg(width - remaining)
                : QString());
    }
    else if (isInterruptObject && row.objectAddress != 0ULL)
    {
        plan.entryValid = true;
        plan.entryAddress = row.objectAddress;
        // KINTERRUPT 的大小是版本相关的 Windows 结构布局，不在 R3 写死；
        // 给 0 表示整页，并在提示里说清楚这是退路而不是精确到字段。
        plan.entryLength = 0ULL;
        plan.entryLabel = kernelText(
            "kernel.descriptor.menu.hvm_watch_entry.interrupt_label",
            QStringLiteral("KINTERRUPT 0x%1（%2）"))
            .arg(row.objectAddress, 0, 16)
            .arg(whereText);
        plan.entryTip = kernelText(
            "kernel.descriptor.menu.hvm_watch_entry.interrupt_tip",
            QStringLiteral("盯中断对象**基址所在的那一页**。协议没有回报被改的那个函数指针槽位自己的地址，所以只能到页粒度：同页任何写入都会先把这条一次性监视吃掉，命中后不能直接说成「有人改了 ServiceRoutine」。"));
    }
    else
    {
        plan.entryTip = readFailed
            ? kernelText(
                "kernel.descriptor.menu.hvm_watch.read_failed",
                QStringLiteral("驱动读不出这一项的内容，装上的监视多半会在地址翻译处失败。"))
            : kernelText(
                "kernel.descriptor.menu.hvm_watch.no_entry_address",
                QStringLiteral("这一行没有可监视的表项地址（汇总行、或本机结构布局未验证的说明行）。"));
    }

    // 指向的目标：描述符行是 handler / 段基址，中断对象行是 ISR 指针的值。
    if ((isDescriptor || isInterruptObject) && !readFailed)
    {
        const unsigned long long target = isDescriptor
            ? row.descriptorBase
            : row.targetAddress;
        if (target != 0ULL)
        {
            plan.targetValid = true;
            plan.targetAddress = target;
            plan.targetLabel = kernelText(
                "kernel.descriptor.menu.hvm_watch_target.label",
                QStringLiteral("%1 指向的代码 0x%2"))
                .arg(whereText)
                .arg(target, 0, 16);
            plan.targetTip = kernelText(
                "kernel.descriptor.menu.hvm_watch_target.tip",
                QStringLiteral("盯这一项现在指向的那段代码，回答的是「它有没有在被调用」——与「谁改了这一项」是两个不同的问题。注意多个向量的 handler 很可能同在一个可执行页上，一条一次性执行监视可能先被某个无关的热向量触发。"));
        }
        else
        {
            plan.targetTip = kernelText(
                "kernel.descriptor.menu.hvm_watch_target.none",
                QStringLiteral("这一行没有记录指向的目标地址。"));
        }
    }
    else
    {
        plan.targetTip = plan.entryTip;
    }

    /*
     * 表所在页的页表项。
     *
     * 用表基址而不是表项地址：要问的是"谁把这张表重映射到别处了"，那是整张
     * 表的映射，而不是某一项。表基址为零（中断对象行不填）时不提供。
     */
    if (isDescriptor && row.descriptorTableBase != 0ULL)
    {
        plan.pteValid = true;
        plan.pteSourceAddress = row.descriptorTableBase;
        plan.pteLabel = kernelText(
            "kernel.descriptor.menu.hvm_watch_pte.label",
            QStringLiteral("%1 表（CPU %2:%3，基址 0x%4）"))
            .arg(tableName)
            .arg(row.processorGroup)
            .arg(row.processorNumber)
            .arg(row.descriptorTableBase, 0, 16);
    }
    return plan;
}
