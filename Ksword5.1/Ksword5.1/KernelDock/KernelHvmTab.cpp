#include "KernelHvmTab.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../SettingsDock/AppearanceSettings.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
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
    enum HvmCpuColumn : int
    {
        CpuColumnProcessor = 0,
        CpuColumnResource,
        CpuColumnSelfTest,
        CpuColumnGuestExit,
        CpuColumnVmxResult,
        CpuColumnNtStatus,
        CpuColumnCount
    };

    QTableWidgetItem* readOnlyItem(const QString& text)
    {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }
}

KernelHvmTab::KernelHvmTab(QWidget* parent)
    : KernelHvmTab(FeatureArea::Ept, parent)
{
}

KernelHvmTab::KernelHvmTab(
    const FeatureArea featureArea,
    QWidget* parent)
    : QWidget(parent)
    , m_featureArea(featureArea)
{
    initializeUi();
}

void KernelHvmTab::showEvent(QShowEvent* event)
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

void KernelHvmTab::initializeUi()
{
    auto* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // 危险口径不占版面：跟着真正触发硬件操作的按钮走，点击后的确认框里还有完整版。
    const QString hazardTip = kernelText(
        "kernel.hvm.hazard.tooltip",
        QStringLiteral("VMX/EPT 操作可能因异常 VM-exit、错误 MTRR 类型、EPT misconfiguration 或与其它 VMM 冲突导致系统不稳定甚至蓝屏。"));

    auto* toolbar = new QHBoxLayout();
    m_refreshButton = new QPushButton(
        kernelText("kernel.hvm.refresh", QStringLiteral("刷新能力")),
        this);
    m_prepareButton = new QPushButton(
        kernelText("kernel.hvm.prepare", QStringLiteral("准备 VMX/EPT")),
        this);
    m_selfTestButton = new QPushButton(
        kernelText("kernel.hvm.self_test", QStringLiteral("逐 CPU 自检")),
        this);
    m_launchButton = new QPushButton(
        kernelText("kernel.hvm.launch", QStringLiteral("启动一次性来宾")),
        this);
    m_teardownButton = new QPushButton(
        kernelText("kernel.hvm.teardown", QStringLiteral("释放后端")),
        this);
    m_startResidentButton = new QPushButton(
        kernelText(
            "kernel.hvm.resident.start",
            QStringLiteral("启动驻留 VMM")),
        this);
    m_stopResidentButton = new QPushButton(
        kernelText(
            "kernel.hvm.resident.stop",
            QStringLiteral("停止驻留 VMM")),
        this);
    m_refreshButton->setToolTip(
        kernelText(
            "kernel.hvm.refresh.tooltip",
            QStringLiteral("重新检测当前 CPU 支持哪些硬件虚拟化能力")));
    m_prepareButton->setToolTip(
        kernelText(
            "kernel.hvm.prepare.tooltip",
            QStringLiteral("为硬件虚拟化分配所需内存与页表结构，是启动来宾前的准备步骤"))
        + QLatin1Char('\n') + hazardTip);
    m_selfTestButton->setToolTip(
        kernelText(
            "kernel.hvm.self_test.tooltip",
            QStringLiteral("逐个 CPU 核心测试虚拟化功能是否可以正常开启"))
        + QLatin1Char('\n') + hazardTip);
    m_launchButton->setToolTip(
        kernelText(
            "kernel.hvm.launch.tooltip",
            QStringLiteral("启动一个一次性的虚拟机来宾用于验证，运行后立即退出"))
        + QLatin1Char('\n') + hazardTip);
    m_teardownButton->setToolTip(
        kernelText(
            "kernel.hvm.teardown.tooltip",
            QStringLiteral("释放虚拟化后端占用的内存与资源")));
    m_startResidentButton->setToolTip(
        kernelText(
            "kernel.hvm.resident.start.tooltip",
            QStringLiteral("启动常驻的虚拟机监控器，持续运行以便监控（会影响系统运行状态，请谨慎使用）"))
        + QLatin1Char('\n')
        + kernelText(
            "kernel.hvm.resident.start.gate_tooltip",
            QStringLiteral("仅支持 Intel VT-x/EPT；AMD、现有 Hypervisor、未通过全 CPU 自检或生命周期保护不完整时，驱动会拒绝启动。")));
    m_stopResidentButton->setToolTip(
        kernelText(
            "kernel.hvm.resident.stop.tooltip",
            QStringLiteral("停止常驻的虚拟机监控器并恢复系统原状")));
    m_featureActionButton = new QPushButton(this);
    if (m_featureArea == FeatureArea::Ept)
    {
        m_featureActionButton->setText(
            kernelText(
                "kernel.hvm.ept.actions",
                QStringLiteral("EPT 规则与事件")));
        m_featureActionButton->setToolTip(
            kernelText(
                "kernel.hvm.ept.actions.tooltip",
                QStringLiteral("EPT 严格规则只是取证 tripwire：命中后记录并去虚拟化，不注入异常，原访问仍可能在同一 RIP 原生重试并成功。")));
        auto* eptMenu = new QMenu(m_featureActionButton);
        QAction* addRule = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.add",
                QStringLiteral("添加物理页规则...")));
        QAction* queryRule = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.query",
                QStringLiteral("查询规则...")));
        QAction* removeRule = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.remove",
                QStringLiteral("移除规则...")));
        QAction* clearRules = eptMenu->addAction(
            kernelText(
                "kernel.hvm.ept.clear",
                QStringLiteral("清空全部规则...")));
        eptMenu->addSeparator();
        QAction* readEvents = eptMenu->addAction(
            kernelText(
                "kernel.hvm.events.read",
                QStringLiteral("读取 VM-exit / EPT 事件")));
        QAction* clearEventRing = eptMenu->addAction(
            kernelText(
                "kernel.hvm.events.clear",
                QStringLiteral("清空已停止的事件环...")));
        m_featureActionButton->setMenu(eptMenu);
        connect(addRule, &QAction::triggered, this, [this]() {
            addEptRule();
        });
        connect(queryRule, &QAction::triggered, this, [this]() {
            queryEptRule();
        });
        connect(removeRule, &QAction::triggered, this, [this]() {
            removeEptRule();
        });
        connect(clearRules, &QAction::triggered, this, [this]() {
            clearEptRules();
        });
        connect(readEvents, &QAction::triggered, this, [this]() {
            queryEvents();
        });
        connect(clearEventRing, &QAction::triggered, this, [this]() {
            clearEvents();
        });
    }
    else if (m_featureArea == FeatureArea::NestedVmx)
    {
        m_featureActionButton->setText(
            kernelText(
                "kernel.hvm.nested.validate",
                QStringLiteral("验证 Nested VMX（partial）")));
        m_featureActionButton->setToolTip(
            kernelText(
                "kernel.hvm.nested.validate.tooltip",
                QStringLiteral("仅为实验性 partial 指令分派：vmcs12/vmcs02、L2 退出反射与 shadow EPT 尚未完整，不会声称也不允许成功运行 L2。")));
        connect(
            m_featureActionButton,
            &QPushButton::clicked,
            this,
            [this]() { validateNested(); });
    }
    else
    {
        m_featureActionButton->setText(
            kernelText(
                "kernel.hvm.evmcs.validate",
                QStringLiteral("验证 Hyper-V eVMCS（partial）")));
        m_featureActionButton->setToolTip(
            kernelText(
                "kernel.hvm.evmcs.validate.tooltip",
                QStringLiteral("仅做 TLFS 能力、根/来宾分区与 VP-assist 所有权检查；不接管 VP-assist 页面和 clean fields，不会标为 active。")));
        connect(
            m_featureActionButton,
            &QPushButton::clicked,
            this,
            [this]() { validateEvmcs(); });
    }
    for (QPushButton* button :
         { m_refreshButton,
           m_prepareButton,
           m_selfTestButton,
           m_launchButton,
           m_teardownButton,
           m_startResidentButton,
           m_stopResidentButton,
           m_featureActionButton })
    {
        button->setStyleSheet(KswordTheme::ThemedButtonStyle());
    }
    m_statusLabel = new QLabel(
        kernelText("kernel.hvm.status.waiting", QStringLiteral("状态：等待刷新")),
        this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(KswordTheme::TextSecondaryHex()));
    toolbar->addWidget(m_refreshButton);
    toolbar->addWidget(m_prepareButton);
    toolbar->addWidget(m_selfTestButton);
    toolbar->addWidget(m_launchButton);
    toolbar->addWidget(m_startResidentButton);
    toolbar->addWidget(m_stopResidentButton);
    toolbar->addWidget(m_teardownButton);
    toolbar->addWidget(m_featureActionButton);
    toolbar->addStretch(1);
    toolbar->addWidget(m_statusLabel);
    rootLayout->addLayout(toolbar);

    m_summaryLabel = new QLabel(this);
    m_summaryLabel->setWordWrap(true);
    m_summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_summaryLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}")
            .arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_summaryLabel);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    m_cpuTable = new ks::ui::VisibleTableWidget(splitter);
    m_cpuTable->setColumnCount(CpuColumnCount);
    m_cpuTable->setHorizontalHeaderLabels({
        kernelText("kernel.hvm.cpu.processor", QStringLiteral("处理器")),
        kernelText("kernel.hvm.cpu.resource", QStringLiteral("VMX 区域")),
        kernelText("kernel.hvm.cpu.self_test", QStringLiteral("自检")),
        kernelText("kernel.hvm.cpu.guest_exit", QStringLiteral("来宾 / VM-exit")),
        kernelText("kernel.hvm.cpu.vmx_result", QStringLiteral("VMX 指令结果")),
        kernelText("kernel.hvm.cpu.ntstatus", QStringLiteral("NTSTATUS"))
    });
    m_cpuTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_cpuTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_cpuTable->setAlternatingRowColors(true);
    m_cpuTable->verticalHeader()->setVisible(false);
    m_cpuTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_cpuTable->horizontalHeader()->setStretchLastSection(true);

    m_detailEdit = new QTextEdit(splitter);
    m_detailEdit->setReadOnly(true);
    m_detailEdit->setPlaceholderText(
        kernelText(
            "kernel.hvm.detail.placeholder",
            QStringLiteral("刷新后显示 VMX MSR、EPT 映射与生命周期证据")));
    splitter->addWidget(m_cpuTable);
    splitter->addWidget(m_detailEdit);
    splitter->setStretchFactor(0, 2);
    splitter->setStretchFactor(1, 3);
    rootLayout->addWidget(splitter, 1);

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() {
        refreshAsync();
    });
    connect(m_prepareButton, &QPushButton::clicked, this, [this]() {
        prepareBackend();
    });
    connect(m_selfTestButton, &QPushButton::clicked, this, [this]() {
        selfTestBackend();
    });
    connect(m_launchButton, &QPushButton::clicked, this, [this]() {
        launchControlledGuest();
    });
    connect(m_teardownButton, &QPushButton::clicked, this, [this]() {
        teardownBackend();
    });
    connect(m_startResidentButton, &QPushButton::clicked, this, [this]() {
        startResident();
    });
    connect(m_stopResidentButton, &QPushButton::clicked, this, [this]() {
        stopResident();
    });
    if (m_featureArea == FeatureArea::Evmcs)
    {
        m_prepareButton->setVisible(false);
        m_selfTestButton->setVisible(false);
        m_launchButton->setVisible(false);
        m_startResidentButton->setVisible(false);
        m_stopResidentButton->setVisible(false);
        m_teardownButton->setVisible(false);
    }
    updateButtons();
}

void KernelHvmTab::refreshAsync()
{
    if (m_operationRunning)
    {
        return;
    }
    m_operationRunning = true;
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.refreshing",
            QStringLiteral("正在读取 CPUID、VMX MSR 与后端状态...")));
    updateButtons();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([safeThis]() {
        ksword::ark::DriverClient client;
        auto result = client.queryHvmStatus();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result = std::move(result)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyStatus(std::move(result));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyStatus(ksword::ark::HvmStatusResult result)
{
    m_operationRunning = false;
    m_supported = result.io.ok && !result.unsupported;
    if (!m_supported)
    {
        m_snapshot = {};
        m_cpuTable->setRowCount(0);
        m_summaryLabel->setText(
            result.unsupported
                ? kernelText(
                      "kernel.hvm.status.unsupported",
                      QStringLiteral("当前驱动不支持 HVM 协议，请更新并重新加载驱动。"))
                : kernelText(
                      "kernel.hvm.status.failed",
                      QStringLiteral("HVM 状态读取失败：%1"))
                      .arg(QString::fromStdString(result.io.message)));
        m_detailEdit->clear();
        m_statusLabel->setText(
            kernelText("kernel.hvm.status.failed_short", QStringLiteral("状态：读取失败")));
        updateButtons();
        return;
    }

    m_snapshot = result.response;
    const QString cpuVendor = fixedAscii(
        m_snapshot.cpuVendor,
        KSWORD_ARK_HVM_VENDOR_CHARS);
    const QString hypervisorVendor = fixedAscii(
        m_snapshot.hypervisorVendor,
        KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS);
    m_summaryLabel->setText(
        kernelText(
            "kernel.hvm.summary",
            QStringLiteral("CPU：%1　Hypervisor：%2　状态：%3　准备 CPU：%4/%5　自检通过：%6/%5　EPT 页表页：%7　RAM 映射：%8 GiB　VM-exit：%9　最近退出：%10"))
            .arg(cpuVendor.isEmpty() ? QStringLiteral("-") : cpuVendor)
            .arg(hypervisorVendor.isEmpty()
                     ? kernelText("kernel.hvm.none", QStringLiteral("未检测到"))
                     : hypervisorVendor)
            .arg(stateText(m_snapshot.stateFlags))
            .arg(m_snapshot.preparedProcessorCount)
            .arg(m_snapshot.processorCount)
            .arg(m_snapshot.selfTestPassedProcessorCount)
            .arg(m_snapshot.eptPageCount)
            .arg(
                static_cast<double>(m_snapshot.mappedRamBytes) /
                    (1024.0 * 1024.0 * 1024.0),
                0,
                'f',
                2)
            .arg(m_snapshot.vmExitCount)
            .arg(
                m_snapshot.lastExitReason ==
                        KSWORD_ARK_HVM_EXIT_REASON_NONE
                    ? QStringLiteral("-")
                    : QString::number(m_snapshot.lastExitReason)));
    m_summaryLabel->setText(
        m_summaryLabel->text() +
        kernelText(
            "kernel.hvm.summary.implementation",
            QStringLiteral(
                "\n实现成熟度（Resident / EPT / Nested / eVMCS）："
                "%1 / %2 / %3 / %4；驻留 CPU：%5；规则：%6；事件：%7（丢弃 %8）"))
            .arg(implementationText(
                m_snapshot.residentImplementation))
            .arg(implementationText(
                m_snapshot.eptImplementation))
            .arg(implementationText(
                m_snapshot.nestedImplementation))
            .arg(implementationText(
                m_snapshot.evmcsImplementation))
            .arg(m_snapshot.residentProcessorCount)
            .arg(m_snapshot.eptRuleCount)
            .arg(m_snapshot.eventCount)
            .arg(m_snapshot.droppedEventCount));

    const int rowCount = static_cast<int>(std::min<unsigned long>(
        m_snapshot.processorCount,
        KSWORD_ARK_HVM_MAX_PROCESSORS));
    m_cpuTable->setRowCount(rowCount);
    for (int rowIndex = 0; rowIndex < rowCount; ++rowIndex)
    {
        const auto& cpu = m_snapshot.processors[rowIndex];
        const bool resourceReady =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY) != 0U;
        const bool tested =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED) != 0U;
        const bool passed =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED) != 0U;
        const bool vmcsLoaded =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED) != 0U;
        const bool guestLaunched =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED) != 0U;
        const bool vmExitHandled =
            (cpu.stateFlags & KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED) != 0U;
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnProcessor,
            readOnlyItem(
                QStringLiteral("%1:%2")
                    .arg(cpu.processorGroup)
                    .arg(cpu.processorNumber)));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnResource,
            readOnlyItem(
                resourceReady
                    ? kernelText("kernel.hvm.yes", QStringLiteral("已准备"))
                    : kernelText("kernel.hvm.no", QStringLiteral("未准备"))));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnSelfTest,
            readOnlyItem(
                !tested
                    ? kernelText("kernel.hvm.not_tested", QStringLiteral("未执行"))
                    : (passed
                           ? kernelText("kernel.hvm.passed", QStringLiteral("通过"))
                           : kernelText("kernel.hvm.failed", QStringLiteral("失败")))));
        QString guestExitText = QStringLiteral("-");
        if (vmExitHandled)
        {
            guestExitText = kernelText(
                "kernel.hvm.cpu.exit_handled",
                QStringLiteral("已退出（原因 %1）"))
                .arg(cpu.lastExitReason);
        }
        else if (guestLaunched)
        {
            guestExitText = kernelText(
                "kernel.hvm.cpu.launched",
                QStringLiteral("来宾已启动"));
        }
        else if (vmcsLoaded)
        {
            guestExitText = kernelText(
                "kernel.hvm.cpu.vmcs_loaded",
                QStringLiteral("VMCS 已加载"));
        }
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnGuestExit,
            readOnlyItem(guestExitText));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnVmxResult,
            readOnlyItem(
                cpu.vmxInstructionResult == 0xFFU
                    ? QStringLiteral("-")
                    : QString::number(cpu.vmxInstructionResult)));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnNtStatus,
            readOnlyItem(ntStatusText(cpu.lastStatus)));
    }
    m_detailEdit->setPlainText(buildDetail(m_snapshot));
    m_statusLabel->setText(
        kernelText("kernel.hvm.status.ready", QStringLiteral("状态：已刷新")));
    updateButtons();
}

void KernelHvmTab::runControlAsync(
    const unsigned long command,
    const bool force,
    const bool enableEptEvents,
    const bool enableNestedVmx,
    const bool enableEvmcs)
{
    if (m_operationRunning)
    {
        return;
    }
    m_operationRunning = true;
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.operating",
            QStringLiteral("正在执行 HVM 生命周期操作...")));
    updateButtons();
    const unsigned long generation = m_snapshot.generation;
    const bool allowNested =
        command == KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED
            ? (enableNestedVmx || enableEvmcs)
            : ((command == KSWORD_ARK_HVM_CONTROL_PREPARE ||
                command == KSWORD_ARK_HVM_CONTROL_SELF_TEST ||
                command ==
                    KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) &&
               m_featureArea == FeatureArea::NestedVmx);
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([
        safeThis,
        command,
        generation,
        force,
        allowNested,
        enableEptEvents,
        enableNestedVmx,
        enableEvmcs]() {
        ksword::ark::DriverClient client;
        auto control = client.controlHvm(
            command,
            generation,
            force,
            allowNested,
            true,
            enableEptEvents,
            enableNestedVmx,
            enableEvmcs);
        auto status = client.queryHvmStatus();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis,
             command,
             control = std::move(control),
             status = std::move(status)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyControl(
                        command,
                        std::move(control),
                        std::move(status));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyControl(
    const unsigned long command,
    ksword::ark::HvmControlResult control,
    ksword::ark::HvmStatusResult status)
{
    m_operationRunning = false;
    const bool partial =
        control.io.ok &&
        control.response.status ==
            KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION;
    if (partial)
    {
        QMessageBox::warning(
            this,
            kernelText(
                "kernel.hvm.operation.title",
                QStringLiteral("HVM 操作")),
            kernelText(
                "kernel.hvm.operation.partial",
                QStringLiteral(
                    "能力检查已完成，但实现成熟度为 partial，未进入 active。"
                    "\nResident / EPT / Nested / eVMCS：%1 / %2 / %3 / %4"
                    "\nNTSTATUS：%5"
                    "\nNested 不会运行 L2；eVMCS 未接管 VP-assist/clean fields。"))
                .arg(control.response.residentImplementation)
                .arg(control.response.eptImplementation)
                .arg(control.response.nestedImplementation)
                .arg(control.response.evmcsImplementation)
                .arg(ntStatusText(control.response.lastStatus)));
    }
    else if (!control.io.ok ||
             control.response.status != KSWORD_ARK_HVM_CONTROL_STATUS_OK)
    {
        QMessageBox::critical(
            this,
            kernelText("kernel.hvm.operation.title", QStringLiteral("HVM 操作")),
            kernelText(
                "kernel.hvm.operation.failed",
                QStringLiteral("操作未完成。\n协议状态：%1\nNTSTATUS：%2\n%3"))
                .arg(control.response.status)
                .arg(ntStatusText(control.response.lastStatus))
                .arg(QString::fromStdString(control.io.message)));
    }
    else
    {
        QString action;
        if (command == KSWORD_ARK_HVM_CONTROL_PREPARE)
        {
            action = kernelText(
                "kernel.hvm.action.prepared",
                QStringLiteral("VMX/EPT 后端已准备"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_SELF_TEST)
        {
            action = kernelText(
                "kernel.hvm.action.tested",
                QStringLiteral("逐 CPU VMX 自检已完成"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST)
        {
            action = kernelText(
                "kernel.hvm.action.launched",
                QStringLiteral("一次性来宾已 VMLAUNCH，并通过 VMCALL 完成 VM-exit"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_START_RESIDENT)
        {
            action = kernelText(
                "kernel.hvm.action.resident_started",
                QStringLiteral(
                    "所有目标 CPU 已进入驻留 VMX non-root；"
                    "只有完整 rendezvous 成功后才标记为 active"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT)
        {
            action = kernelText(
                "kernel.hvm.action.resident_stopped",
                QStringLiteral(
                    "驻留 VMM 已停止；所有完成处理器均已 VMXOFF 并恢复原始 CR4"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_RESET_FAULT)
        {
            action = kernelText(
                "kernel.hvm.action.fault_reset",
                QStringLiteral("已清除停止状态下的可恢复故障标记"));
        }
        else
        {
            action = kernelText(
                "kernel.hvm.action.torn_down",
                QStringLiteral("HVM 后端资源已释放"));
        }
        QMessageBox::information(
            this,
            kernelText("kernel.hvm.operation.title", QStringLiteral("HVM 操作")),
            action);
    }
    applyStatus(std::move(status));
}

void KernelHvmTab::prepareBackend()
{
    const QString warning = kernelText(
        "kernel.hvm.prepare.warning",
        QStringLiteral(
            "准备操作会为每个活动 CPU 分配物理连续的 VMXON/VMCS 页面，"
            "并按 CPUID.80000008 的 MAXPHYADDR 构造从物理地址 0 开始、"
            "最多 8 TiB 的连续 EPT 恒等映射，以覆盖高位 PCI/ReBAR MMIO。"
            "完整 RAM 叶按 MTRR 定型，固件、PCI 和其它物理空洞使用 UC；"
            "MAXPHYADDR 超过 8 TiB 时会明确标记截断并禁止驻留启动。"
            "它不会执行 VMLAUNCH，但会增加不可分页内存占用；"
            "驱动卸载或“释放后端”会回收这些资源。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.prepare", QStringLiteral("准备 VMX/EPT"))))
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_PREPARE, false);
    }
}

void KernelHvmTab::selfTestBackend()
{
    const QString warning = kernelText(
        "kernel.hvm.self_test.warning",
        QStringLiteral(
            "这是高风险硬件自检：驱动会将系统线程依次绑定到每个 CPU，短暂调整 CR4.VMXE，执行 VMXON 后立即 VMXOFF，再恢复原始 CR4。"
            "已运行的 Hyper-V/VBS/其它 VMM、固件限制或异常 VMX 实现可能导致操作被拒绝、系统不稳定，极端情况下可能蓝屏。"
            "请先保存工作并确保你接受重启风险。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.self_test", QStringLiteral("逐 CPU 自检"))))
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_SELF_TEST, true);
    }
}

void KernelHvmTab::launchControlledGuest()
{
    const QString warning = kernelText(
        "kernel.hvm.launch.warning",
        QStringLiteral(
            "这是实际的高风险 VM-entry：驱动会在一个已自检 CPU 上进入 VMX root，装载完整 VMCS，真实执行 VMLAUNCH。"
            "一次性来宾只执行 VMCALL；VM-exit 入口会采集退出原因、qualification、RIP/RSP 和 VM-instruction error，随后 VMCLEAR、VMXOFF 并恢复 CR4。"
            "任何 VMCS、EPT、固件、Hyper-V/VBS、嵌套虚拟化或处理器实现异常都可能导致系统不稳定、蓝屏或必须重启。"
            "请先保存全部工作；若检测到上层 Hypervisor，只能从 Nested VMX（partial）入口"
            "并在硬件确实暴露 VMX 时尝试，但这不代表能够运行 L2。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.launch", QStringLiteral("启动一次性来宾"))))
    {
        runControlAsync(
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST,
            true);
    }
}

void KernelHvmTab::teardownBackend()
{
    const bool confirmationSuppressed =
        ks::settings::dangerousActionConfirmationsSuppressed();
    if (confirmationSuppressed ||
        QMessageBox::question(
                this,
                kernelText("kernel.hvm.teardown.title", QStringLiteral("释放 HVM 后端")),
                kernelText(
                    "kernel.hvm.teardown.warning",
                    QStringLiteral(
                        "释放所有 VMXON、VMCS 和 EPT 页表资源，并清除本次自检、"
                        "一次性来宾启动与 VM-exit 摘要。独立事件环会保留，"
                        "只能在驻留 CPU 全部停止后从“EPT 规则与事件”中清空。继续吗？")),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) == QMessageBox::Yes)
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_TEARDOWN, false);
    }
}

bool KernelHvmTab::confirmTyped(
    const QString& warning,
    const QString& phrase)
{
    if (ks::settings::dangerousActionConfirmationsSuppressed())
    {
        return true;
    }
    const auto answer = QMessageBox::warning(
        this,
        kernelText("kernel.hvm.confirm.title", QStringLiteral("内核虚拟化风险确认")),
        warning,
        QMessageBox::Ok | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (answer != QMessageBox::Ok)
    {
        return false;
    }

    // 二次确认改为直接点击：不再要求手动输入确认短语。
    // phrase 仍作为动作标识展示，让用户清楚本次确认的是哪一项操作。
    const auto finalAnswer = QMessageBox::warning(
        this,
        kernelText("kernel.hvm.confirm.final.title", QStringLiteral("最终确认")),
        kernelText(
            "kernel.hvm.confirm.final.prompt",
            QStringLiteral("确认执行“%1”？此操作可能导致系统不稳定。"))
            .arg(phrase),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    return finalAnswer == QMessageBox::Yes;
}

void KernelHvmTab::updateButtons()
{
    const bool resourcesReady =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0U;
    const bool guestReady =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_GUEST_READY) != 0U;
    const bool guestRunning =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_GUEST_RUNNING) != 0U;
    const bool residentActive =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0U;
    const bool selfTestPassed =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED) != 0U;
    const bool residentAvailable =
        (m_snapshot.featureFlags &
            (KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
             KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED)) ==
            (KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
             KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED) &&
        m_snapshot.residentImplementation !=
            KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED &&
        (m_snapshot.stateFlags &
            (KSWORD_ARK_HVM_STATE_EPT_TRUNCATED |
             KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING |
             KSWORD_ARK_HVM_STATE_FAULTED |
             KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED |
             KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED)) == 0U;
    m_refreshButton->setEnabled(!m_operationRunning);
    m_prepareButton->setEnabled(
        !m_operationRunning && m_supported && !resourcesReady);
    m_selfTestButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        resourcesReady &&
        !residentActive);
    m_launchButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        guestReady &&
        !guestRunning &&
        !residentActive);
    m_teardownButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        resourcesReady &&
        !guestRunning &&
        !residentActive);
    m_startResidentButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        residentAvailable &&
        selfTestPassed &&
        !residentActive &&
        m_featureArea != FeatureArea::Evmcs);
    m_stopResidentButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        residentActive);
    m_featureActionButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        (m_featureArea != FeatureArea::Ept || resourcesReady));
}
