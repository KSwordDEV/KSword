#include "KernelSlatIommuAuditTab.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QCheckBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QShowEvent>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include "../UI/StructuredFieldView.h"
#include <QVBoxLayout>

#include <algorithm>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    enum ProbeColumn : int
    {
        ProbeColumnName = 0,
        ProbeColumnVirtualAddress,
        ProbeColumnPhysicalAddress,
        ProbeColumnBytes,
        ProbeColumnVirtualHash,
        ProbeColumnPhysicalHash,
        ProbeColumnVerdict,
        ProbeColumnStatus,
        ProbeColumnCount
    };

    enum IommuColumn : int
    {
        IommuColumnType = 0,
        IommuColumnSegmentDevice,
        IommuColumnBase,
        IommuColumnLimit,
        IommuColumnFlags,
        IommuColumnCapabilities,
        IommuColumnRuntime,
        IommuColumnStatus,
        IommuColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // setHeaderTip 作用：
    // - 输入 table/column/tipText：目标表格、列序号和悬停说明；
    // - 处理：把判定口径挂到它解释的那一列表头上；
    // - 返回：无，表头项缺失时静默跳过。
    void setHeaderTip(QTableWidget* table, const int column, const QString& tipText)
    {
        QTableWidgetItem* headerItem = table->horizontalHeaderItem(column);
        if (headerItem != nullptr)
        {
            headerItem->setToolTip(tipText);
        }
    }
}

KernelSlatIommuAuditTab::KernelSlatIommuAuditTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
}

void KernelSlatIommuAuditTab::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (!m_firstRefreshStarted)
    {
        m_firstRefreshStarted = true;
        QMetaObject::invokeMethod(
            this,
            [this]() { refreshAsync(); },
            Qt::QueuedConnection);
    }
}

void KernelSlatIommuAuditTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText("kernel.slat_iommu.refresh", QStringLiteral("刷新取证")),
        this);
    m_refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    // 取证边界跟着触发它的按钮走，不再在页首铺一段常驻说明。
    m_refreshButton->setToolTip(
        kernelText(
            "kernel.slat_iommu.refresh.tooltip",
            QStringLiteral("只读取证：比较来宾可见的内核虚拟视图与物理别名，并解析 CPUID、DMAR/IVRS 和公开 IOMMU 接口。")));
    m_includeMmioCheck = new QCheckBox(
        kernelText(
            "kernel.slat_iommu.include_mmio",
            QStringLiteral("读取 IOMMU MMIO 状态（只读，可能被固件/平台拒绝）")),
        this);
    m_includeMmioCheck->setToolTip(
        kernelText(
            "kernel.slat_iommu.include_mmio.tooltip",
            QStringLiteral("只读寄存器、不写入，但错误的固件地址仍可能被平台拒绝或触发硬件异常。")));
    m_statusLabel = new QLabel(
        kernelText(
            "kernel.slat_iommu.status.waiting",
            QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(KswordTheme::TextSecondaryHex()));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_includeMmioCheck);
    toolbar->addStretch(1);
    toolbar->addWidget(m_statusLabel);
    ks::ui::NormalizeToolbarRow(toolbar);
    rootLayout->addLayout(toolbar);

    m_summaryLabel = new QLabel(this);
    m_summaryLabel->setWordWrap(true);
    m_summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_summaryLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}")
            .arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_summaryLabel);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    auto* evidenceTabs = new QTabWidget(splitter);
    ks::ui::StylePageTabs(evidenceTabs);

    m_probeTable = new ks::ui::VisibleTableWidget(evidenceTabs);
    // 虚拟/物理别名探针差异需要保留现场快照比较。
    ks::ui::SetTableActionBarMode(m_probeTable, ks::ui::TableActionBarMode::Full);
    m_probeTable->setColumnCount(ProbeColumnCount);
    m_probeTable->setHorizontalHeaderLabels({
        kernelText("kernel.slat_iommu.probe.name", QStringLiteral("探针")),
        kernelText("kernel.slat_iommu.probe.virtual", QStringLiteral("虚拟地址")),
        kernelText("kernel.slat_iommu.probe.physical", QStringLiteral("物理地址")),
        kernelText("kernel.slat_iommu.probe.bytes", QStringLiteral("字节")),
        kernelText("kernel.slat_iommu.probe.virtual_hash", QStringLiteral("虚拟哈希")),
        kernelText("kernel.slat_iommu.probe.physical_hash", QStringLiteral("物理哈希")),
        kernelText("kernel.slat_iommu.probe.verdict", QStringLiteral("交叉视图")),
        QStringLiteral("NTSTATUS")
    });
    // 判定口径挂在它解释的那一列表头上，比页首堆一段总说明更容易对上号。
    setHeaderTip(
        m_probeTable,
        ProbeColumnVerdict,
        kernelText(
            "kernel.slat_iommu.probe.verdict.tooltip",
            QStringLiteral("外层 Hypervisor 可用 EPT/NPT 对执行和读取提供不同视图，因此“未发现异常”不等于已证明不存在 Hook。")));
    m_probeTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_probeTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_probeTable->setAlternatingRowColors(true);
    m_probeTable->verticalHeader()->setVisible(false);
    m_probeTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_probeTable->horizontalHeader()->setStretchLastSection(true);
    evidenceTabs->addTab(
        m_probeTable,
        kernelText(
            "kernel.slat_iommu.probe.tab",
            QStringLiteral("EPT/NPT 交叉视图")));

    m_iommuTable = new ks::ui::VisibleTableWidget(evidenceTabs);
    // 固件表与接口能力摘要变化少，保留紧凑复制导出入口。
    ks::ui::SetTableActionBarMode(m_iommuTable, ks::ui::TableActionBarMode::Compact);
    m_iommuTable->setColumnCount(IommuColumnCount);
    m_iommuTable->setHorizontalHeaderLabels({
        kernelText("kernel.slat_iommu.iommu.type", QStringLiteral("类型")),
        kernelText("kernel.slat_iommu.iommu.segment_device", QStringLiteral("段 / 设备")),
        kernelText("kernel.slat_iommu.iommu.base", QStringLiteral("基址")),
        kernelText("kernel.slat_iommu.iommu.limit", QStringLiteral("上界")),
        kernelText("kernel.slat_iommu.iommu.flags", QStringLiteral("证据标志")),
        kernelText("kernel.slat_iommu.iommu.capability", QStringLiteral("能力 / 扩展能力")),
        kernelText("kernel.slat_iommu.iommu.runtime", QStringLiteral("状态 / 根表")),
        QStringLiteral("NTSTATUS")
    });
    m_iommuTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_iommuTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_iommuTable->setAlternatingRowColors(true);
    m_iommuTable->verticalHeader()->setVisible(false);
    m_iommuTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_iommuTable->horizontalHeader()->setStretchLastSection(true);
    evidenceTabs->addTab(
        m_iommuTable,
        kernelText(
            "kernel.slat_iommu.iommu.tab",
            QStringLiteral("IOMMU / DMAR / IVRS")));

    m_detailEdit = new ks::ui::StructuredFieldView(splitter);

    m_detailEdit->setDocument(ks::ui::FieldDocument{}.note(
        kernelText(
            "kernel.slat_iommu.detail.placeholder",
            QStringLiteral("刷新后显示 CPU、Hypervisor、SLAT 与 IOMMU 原始证据"))));
    splitter->addWidget(evidenceTabs);
    splitter->addWidget(m_detailEdit);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    rootLayout->addWidget(splitter, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
}

void KernelSlatIommuAuditTab::refreshAsync()
{
    if (m_queryRunning)
    {
        return;
    }
    m_queryRunning = true;
    m_refreshButton->setEnabled(false);
    m_includeMmioCheck->setEnabled(false);
    m_statusLabel->setText(
        kernelText(
            "kernel.slat_iommu.status.refreshing",
            QStringLiteral("状态：正在采集只读证据...")));
    const bool includeMmio = m_includeMmioCheck->isChecked();
    QPointer<KernelSlatIommuAuditTab> safeThis(this);
    std::thread([safeThis, includeMmio]() {
        ksword::ark::DriverClient client;
        auto result = client.querySlatIommuAudit(includeMmio);
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result = std::move(result)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyResult(std::move(result));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelSlatIommuAuditTab::applyResult(
    ksword::ark::SlatIommuAuditResult result)
{
    m_queryRunning = false;
    m_refreshButton->setEnabled(true);
    m_includeMmioCheck->setEnabled(true);
    if (!result.io.ok)
    {
        m_probeTable->setRowCount(0);
        m_iommuTable->setRowCount(0);
        m_detailEdit->setDocument({});
        if (result.unsupported)
        {
            m_statusLabel->setText(
                kernelText(
                    "kernel.slat_iommu.status.unsupported",
                    QStringLiteral("状态：当前驱动不支持此取证协议")));
        }
        else
        {
            m_statusLabel->setText(
                kernelText(
                    "kernel.slat_iommu.status.failed",
                    QStringLiteral("状态：读取失败（%1）"))
                    .arg(QString::fromStdString(result.io.message)));
        }
        m_summaryLabel->setText(m_statusLabel->text());
        return;
    }

    const auto& response = result.response;
    populateProbeTable(response);
    populateIommuTable(response);
    m_detailEdit->setDocument(buildDetail(response));
    m_summaryLabel->setText(
        kernelText(
            "kernel.slat_iommu.summary",
            QStringLiteral("CPU：%1；Hypervisor：%2；特性：%3；来宾可见风险：%4；别名探针 %5 个（不一致 %6，不稳定 %7）；IOMMU 记录 %8 个（保留内存 %9，畸形 %10）。"))
            .arg(fixedAscii(response.cpuVendor, sizeof(response.cpuVendor)))
            .arg(fixedAscii(
                response.hypervisorVendor,
                sizeof(response.hypervisorVendor)).isEmpty()
                    ? QStringLiteral("-")
                    : fixedAscii(
                        response.hypervisorVendor,
                        sizeof(response.hypervisorVendor)))
            .arg(featureText(response.featureFlags))
            .arg(riskText(response.riskFlags))
            .arg(response.probeCount)
            .arg(response.mismatchCount)
            .arg(response.unstableCount)
            .arg(response.iommuRowCount)
            .arg(response.reservedMemoryCount)
            .arg(response.malformedRowCount));
    m_statusLabel->setText(
        response.queryStatus < 0
            ? kernelText(
                "kernel.slat_iommu.status.partial",
                QStringLiteral("状态：部分证据不可用（%1）"))
                .arg(ntStatusText(response.queryStatus))
            : kernelText(
                "kernel.slat_iommu.status.ready",
                QStringLiteral("状态：只读取证已刷新")));
}

void KernelSlatIommuAuditTab::populateProbeTable(
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response)
{
    const auto count = std::min<unsigned long>(
        response.probeCount,
        KSWORD_ARK_SLAT_IOMMU_MAX_PROBES);
    m_probeTable->setRowCount(static_cast<int>(count));
    for (unsigned long index = 0; index < count; ++index)
    {
        const auto& row = response.probes[index];
        const int tableRow = static_cast<int>(index);
        m_probeTable->setItem(
            tableRow,
            ProbeColumnName,
            readOnlyItem(fixedAscii(row.name, sizeof(row.name))));
        m_probeTable->setItem(
            tableRow,
            ProbeColumnVirtualAddress,
            readOnlyItem(hex64(row.virtualAddress)));
        m_probeTable->setItem(
            tableRow,
            ProbeColumnPhysicalAddress,
            readOnlyItem(hex64(row.physicalAddress)));
        m_probeTable->setItem(
            tableRow,
            ProbeColumnBytes,
            readOnlyItem(QString::number(row.bytesCompared)));
        m_probeTable->setItem(
            tableRow,
            ProbeColumnVirtualHash,
            readOnlyItem(hex64(row.virtualHash)));
        m_probeTable->setItem(
            tableRow,
            ProbeColumnPhysicalHash,
            readOnlyItem(hex64(row.physicalHash)));
        m_probeTable->setItem(
            tableRow,
            ProbeColumnVerdict,
            readOnlyItem(probeVerdictText(row)));
        m_probeTable->setItem(
            tableRow,
            ProbeColumnStatus,
            readOnlyItem(ntStatusText(row.status)));
    }
}

void KernelSlatIommuAuditTab::populateIommuTable(
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response)
{
    const auto count = std::min<unsigned long>(
        response.iommuRowCount,
        KSWORD_ARK_SLAT_IOMMU_MAX_ROWS);
    m_iommuTable->setRowCount(static_cast<int>(count));
    for (unsigned long index = 0; index < count; ++index)
    {
        const auto& row = response.iommuRows[index];
        const int tableRow = static_cast<int>(index);
        QString segmentDevice = QStringLiteral("%1 / 0x%2")
            .arg(row.segment)
            .arg(row.deviceId, 4, 16, QLatin1Char('0'))
            .toUpper();
        if (row.endDeviceId != 0)
        {
            segmentDevice = QStringLiteral("%1 / 0x%2-0x%3")
                .arg(row.segment)
                .arg(row.deviceId, 4, 16, QLatin1Char('0'))
                .arg(row.endDeviceId, 4, 16, QLatin1Char('0'))
                .toUpper();
        }
        m_iommuTable->setItem(
            tableRow,
            IommuColumnType,
            readOnlyItem(iommuTypeText(row.type)));
        m_iommuTable->setItem(
            tableRow,
            IommuColumnSegmentDevice,
            readOnlyItem(segmentDevice));
        m_iommuTable->setItem(
            tableRow,
            IommuColumnBase,
            readOnlyItem(hex64(row.baseAddress)));
        m_iommuTable->setItem(
            tableRow,
            IommuColumnLimit,
            readOnlyItem(hex64(row.limitAddress)));
        m_iommuTable->setItem(
            tableRow,
            IommuColumnFlags,
            readOnlyItem(QStringLiteral("%1 | FW=0x%2 | scopes=%3")
                .arg(iommuFlagsText(row.flags))
                .arg(row.firmwareFlags, 8, 16, QLatin1Char('0'))
                .arg(row.scopeCount)
                .toUpper()));
        m_iommuTable->setItem(
            tableRow,
            IommuColumnCapabilities,
            readOnlyItem(QStringLiteral("%1 / %2")
                .arg(hex64(row.capability), hex64(row.extendedCapability))));
        m_iommuTable->setItem(
            tableRow,
            IommuColumnRuntime,
            readOnlyItem(QStringLiteral("%1 / %2")
                .arg(hex64(row.statusRegister), hex64(row.rootTableAddress))));
        m_iommuTable->setItem(
            tableRow,
            IommuColumnStatus,
            readOnlyItem(ntStatusText(row.status)));
    }
}

ks::ui::FieldDocument KernelSlatIommuAuditTab::buildDetail(
    const KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE& response) const
{
        ks::ui::FieldDocument document;
        document.field(QStringLiteral("CPU 厂商"), QStringLiteral("%1").arg(fixedAscii(response.cpuVendor, sizeof(response.cpuVendor))));
        document.field(QStringLiteral("Hypervisor 厂商"), QStringLiteral("%1").arg(fixedAscii(response.hypervisorVendor, sizeof(response.hypervisorVendor))));
        document.field(QStringLiteral("特性"), QStringLiteral("%1").arg(featureText(response.featureFlags)));
        document.field(QStringLiteral("来宾可见风险"), QStringLiteral("%1").arg(riskText(response.riskFlags)));
        document.field(QStringLiteral("原始字段/风险/特性"), QStringLiteral("0x%1 / 0x%2 / 0x%3").arg(QStringLiteral("%1").arg(response.fieldFlags, 8, 16, QLatin1Char('0'))).arg(QStringLiteral("%1").arg(response.riskFlags, 8, 16, QLatin1Char('0'))).arg(QStringLiteral("%1").arg(response.featureFlags, 16, 16, QLatin1Char('0'))));
        document.field(QStringLiteral("CPUID 最大叶"), QStringLiteral("basic=0x%1 extended=0x%2 hypervisor=0x%3").arg(QStringLiteral("%1").arg(response.cpuidMaxBasic, 0, 16)).arg(QStringLiteral("%1").arg(response.cpuidMaxExtended, 0, 16)).arg(QStringLiteral("%1").arg(response.cpuidMaxHypervisor, 0, 16)));
        document.field(QStringLiteral("CPUID 周期 min/median/max"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg(response.cpuidCyclesMinimum)).arg(QStringLiteral("%1").arg(response.cpuidCyclesMedian)).arg(QStringLiteral("%1").arg(response.cpuidCyclesMaximum)));
        document.field(QStringLiteral("IA32_FEATURE_CONTROL"), QStringLiteral("%1").arg(hex64(response.vmxFeatureControl)));
        document.field(QStringLiteral("IA32_VMX_EPT_VPID_CAP"), QStringLiteral("%1").arg(hex64(response.vmxEptVpidCapabilities)));
        document.field(QStringLiteral("AMD VM_CR"), QStringLiteral("%1").arg(hex64(response.amdVmCr)));
        document.field(QStringLiteral("AMD EFER"), QStringLiteral("%1").arg(hex64(response.amdEfer)));
        document.field(QStringLiteral("DMAR/IVRS"), QStringLiteral("%1 / %2").arg(QStringLiteral("%1").arg(ntStatusText(response.dmarStatus))).arg(QStringLiteral("%1").arg(ntStatusText(response.ivrsStatus))));
        document.field(QStringLiteral("IOMMU Interface/Ex"), QStringLiteral("%1(v%2) / %3(v%4)").arg(QStringLiteral("%1").arg(ntStatusText(response.iommuInterfaceStatus))).arg(QStringLiteral("%1").arg(response.iommuInterfaceVersion)).arg(QStringLiteral("%1").arg(ntStatusText(response.iommuInterfaceExStatus))).arg(QStringLiteral("%1").arg(response.iommuInterfaceExVersion)));
        document.field(QStringLiteral("查询标志"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(response.queryFlags, 8, 16, QLatin1Char('0'))));
        document.field(QStringLiteral("证据边界"), QStringLiteral("虚拟/物理视图一致只能排除当前来宾可观察到的分离"), true);
        document.note(QStringLiteral("不能读取外层 EPT/NPT 表，也不能证明不存在 execute-only 或按访问类型切换的 Hook。"));
        return document;
    }

QString KernelSlatIommuAuditTab::featureText(const std::uint64_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_INTEL) != 0) values << QStringLiteral("Intel");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_AMD) != 0) values << QStringLiteral("AMD");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_VMX) != 0) values << QStringLiteral("VMX");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_EPT) != 0) values << QStringLiteral("EPT");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_SVM) != 0) values << QStringLiteral("SVM");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_NPT) != 0) values << QStringLiteral("NPT");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_HYPERVISOR) != 0) values << QStringLiteral("Hypervisor");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_DMAR) != 0) values << QStringLiteral("DMAR");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IVRS) != 0) values << QStringLiteral("IVRS");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE) != 0) values << QStringLiteral("IOMMU Interface");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_INTERFACE_EX) != 0) values << QStringLiteral("IOMMU InterfaceEx");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_TRANSLATION) != 0) values << QStringLiteral("VT-d Translation");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_VTD_INTERRUPT_REMAP) != 0) values << QStringLiteral("Interrupt Remap");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_DMA_GUARD_OPT_IN) != 0) values << QStringLiteral("DMA Guard Opt-In");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_PHYSICAL_ALIAS) != 0) values << QStringLiteral("Physical Alias");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EXPORT) != 0) values << QStringLiteral("IOMMU Export");
    if ((flags & KSWORD_ARK_SLAT_IOMMU_FEATURE_IOMMU_EX_EXPORT) != 0) values << QStringLiteral("IOMMU Ex Export");
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(", "));
}

QString KernelSlatIommuAuditTab::riskText(const std::uint32_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_HYPERVISOR_OPAQUE) != 0)
        values << kernelText("kernel.slat_iommu.risk.hypervisor_opaque", QStringLiteral("外层 SLAT 不可见"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_CPUID_INCONSISTENT) != 0)
        values << kernelText("kernel.slat_iommu.risk.cpuid", QStringLiteral("CPUID 不一致"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_MISMATCH) != 0)
        values << kernelText("kernel.slat_iommu.risk.alias_mismatch", QStringLiteral("虚拟/物理别名不一致"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ALIAS_UNSTABLE) != 0)
        values << kernelText("kernel.slat_iommu.risk.alias_unstable", QStringLiteral("别名读取不稳定"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_CHECKSUM) != 0)
        values << kernelText("kernel.slat_iommu.risk.acpi_checksum", QStringLiteral("ACPI 校验和异常"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ACPI_MALFORMED) != 0)
        values << kernelText("kernel.slat_iommu.risk.acpi_malformed", QStringLiteral("ACPI 结构畸形"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_MMIO_UNREADABLE) != 0)
        values << kernelText("kernel.slat_iommu.risk.mmio", QStringLiteral("MMIO 不可读"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_TRANSLATION_DISABLED) != 0)
        values << kernelText("kernel.slat_iommu.risk.translation", QStringLiteral("IOMMU 转换未启用"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_ROOT_TABLE_UNAVAILABLE) != 0)
        values << kernelText("kernel.slat_iommu.risk.root", QStringLiteral("根表不可用"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_RESERVED_MEMORY_PRESENT) != 0)
        values << kernelText("kernel.slat_iommu.risk.reserved", QStringLiteral("存在保留内存窗口"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_TIMING_VARIANCE) != 0)
        values << kernelText("kernel.slat_iommu.risk.timing", QStringLiteral("CPUID 时延离散"));
    if ((flags & KSWORD_ARK_SLAT_IOMMU_RISK_TRUNCATED) != 0)
        values << kernelText("kernel.slat_iommu.risk.truncated", QStringLiteral("结果被截断"));
    return values.isEmpty()
        ? kernelText("kernel.slat_iommu.risk.none", QStringLiteral("未发现来宾可见异常"))
        : values.join(QStringLiteral("; "));
}

QString KernelSlatIommuAuditTab::iommuTypeText(const std::uint32_t type)
{
    switch (type)
    {
    case KSWORD_ARK_IOMMU_ROW_INTEL_DRHD: return QStringLiteral("Intel DRHD");
    case KSWORD_ARK_IOMMU_ROW_INTEL_RMRR: return QStringLiteral("Intel RMRR");
    case KSWORD_ARK_IOMMU_ROW_INTEL_ATSR: return QStringLiteral("Intel ATSR");
    case KSWORD_ARK_IOMMU_ROW_INTEL_RHSA: return QStringLiteral("Intel RHSA");
    case KSWORD_ARK_IOMMU_ROW_AMD_IVHD: return QStringLiteral("AMD IVHD");
    case KSWORD_ARK_IOMMU_ROW_AMD_IVMD: return QStringLiteral("AMD IVMD");
    case KSWORD_ARK_IOMMU_ROW_INTEL_ANDD: return QStringLiteral("Intel ANDD");
    case KSWORD_ARK_IOMMU_ROW_INTEL_SATC: return QStringLiteral("Intel SATC");
    default: return kernelText("kernel.slat_iommu.iommu.unknown", QStringLiteral("未知"));
    }
}

QString KernelSlatIommuAuditTab::iommuFlagsText(const std::uint32_t flags)
{
    QStringList values;
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_INCLUDE_ALL) != 0) values << QStringLiteral("IncludeAll");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_RESERVED_MEMORY) != 0) values << QStringLiteral("ReservedMemory");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_MMIO_READ) != 0) values << QStringLiteral("MMIO");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_TRANSLATION) != 0) values << QStringLiteral("Translation");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_INTERRUPT_REMAP) != 0) values << QStringLiteral("InterruptRemap");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_ROOT_TABLE_VALID) != 0) values << QStringLiteral("RootValid");
    if ((flags & KSWORD_ARK_IOMMU_ROW_FLAG_MALFORMED) != 0) values << QStringLiteral("Malformed");
    return values.isEmpty() ? QStringLiteral("-") : values.join(QStringLiteral(", "));
}

QString KernelSlatIommuAuditTab::probeVerdictText(
    const KSWORD_ARK_SLAT_PROBE_ROW& row)
{
    if (row.status < 0)
        return kernelText("kernel.slat_iommu.probe.failed", QStringLiteral("读取失败"));
    if ((row.flags & (KSWORD_ARK_SLAT_PROBE_FLAG_VIRTUAL_UNSTABLE |
                     KSWORD_ARK_SLAT_PROBE_FLAG_PHYSICAL_UNSTABLE)) != 0)
        return kernelText("kernel.slat_iommu.probe.unstable", QStringLiteral("读取不稳定"));
    if ((row.flags & KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MISMATCH) != 0)
        return kernelText("kernel.slat_iommu.probe.mismatch", QStringLiteral("视图不一致"));
    if ((row.flags & KSWORD_ARK_SLAT_PROBE_FLAG_HASH_MATCH) != 0)
        return kernelText("kernel.slat_iommu.probe.match", QStringLiteral("来宾可见视图一致"));
    return kernelText("kernel.slat_iommu.probe.insufficient", QStringLiteral("证据不足"));
}

QString KernelSlatIommuAuditTab::ntStatusText(const long status)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<quint32>(status), 8, 16, QLatin1Char('0'))
        .toUpper();
}

QString KernelSlatIommuAuditTab::hex64(const std::uint64_t value)
{
    return QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(value), 16, 16, QLatin1Char('0'))
        .toUpper();
}

QString KernelSlatIommuAuditTab::fixedAscii(
    const char* text,
    const int capacity)
{
    if (text == nullptr || capacity <= 0)
    {
        return {};
    }
    int length = 0;
    while (length < capacity && text[length] != '\0')
    {
        ++length;
    }
    return QString::fromLatin1(text, length);
}
