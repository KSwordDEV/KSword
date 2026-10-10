#include "../UI/StructuredFieldView.h"
#include "../UI/ToolbarMetrics.h"
#include "KernelHvmTab.h"
#include "../MainWindow.h"

#include "KernelDock.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../SettingsDock/AppearanceSettings.h"
#include "../UI/FlowLayout.h"
// isNestedAllowed：嵌套开关的权威来源。这个页面原先自己算一份，且算得比它窄。
#include "../UI/HvmControl.h"
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
#include "../UI/CodeEditorWidget.h"
#include <QVBoxLayout>
#include <QVariant>

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

    // 按钮可用性已经把生命周期顺序表达清楚了，缺的是「为什么灰」：
    // updateButtons 算得出禁用条件，而用户看到的只有一个灰按钮，得自己
    // 反推该先点哪一个。这里把原因接在静态说明后面。
    //
    // 静态说明存进动态属性再取回，是因为本函数每次刷新都会跑一遍：
    // 直接往 toolTip 上追加会把原因一条条叠成长串。
    void setGateTooltip(QPushButton* const button, const QString& gateReason)
    {
        if (button == nullptr)
        {
            return;
        }
        const QVariant storedBaseTooltip = button->property("ks_base_tooltip");
        const QString baseTooltip = storedBaseTooltip.isValid()
            ? storedBaseTooltip.toString()
            : button->toolTip();
        if (!storedBaseTooltip.isValid())
        {
            button->setProperty("ks_base_tooltip", baseTooltip);
        }
        if (gateReason.isEmpty())
        {
            button->setToolTip(baseTooltip);
            return;
        }
        button->setToolTip(baseTooltip.isEmpty()
            ? gateReason
            : baseTooltip + QLatin1Char('\n') + gateReason);
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
        QStringLiteral("虚拟化进入、页表缓存类型或退出恢复错误可能导致系统不稳定或蓝屏。"));

    // 换行布局而不是 QHBoxLayout：这排有八个按钮，标签又都是「启动一次性来宾」
    // 这种四到六字的完整句子。1024 宽下 QHBoxLayout 会把每个按钮压到 sizeHint
    // 以下，于是「刷新能力」被裁成「efresh Capabilitie」——按钮还能点，但没人
    // 读得出它是哪一个。换行布局改为折行，宽窗口仍然是一排。
    auto* toolbar = new ks::ui::FlowLayout(nullptr, 0, 8, 8);
    m_refreshButton = new QPushButton(
        kernelText("kernel.hvm.refresh", QStringLiteral("刷新能力")),
        this);
    m_prepareButton = new QPushButton(
        kernelText("kernel.hvm.prepare", QStringLiteral("准备虚拟化后端")),
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
            QStringLiteral("Intel 使用 VMX/EPT，AMD 使用实验性 SVM/NPT。必须通过全 CPU 自检与生命周期保护；AMD 仅接受明确允许的 VMware 外层。")));
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
        /*
         * 标签用的键与 validateNested() 里确认框标题的是同一个，两处的兜底
         * 文案必须逐字一致——不一致的话，同一个键会因为哪一处先取而显示出两
         * 种名字，而这种差异只在没有词条时才暴露。
         */
        m_featureActionButton->setText(
            kernelText(
                "kernel.hvm.nested.validate",
                QStringLiteral("验证 Nested VMX 分派能力")));
        m_featureActionButton->setToolTip(
            kernelText(
                "kernel.hvm.nested.validate.tooltip",
                QStringLiteral("探测并报告嵌套 VMX 分派能力。分派本身已完整：vmcs12/vmcs02 合并、L2 退出反射与影子 EPT 都已实现并在硬件上验证过。这个按钮只做探测，不会让常驻带上嵌套派发——那一位在虚拟化菜单的「允许来宾嵌套（我们作为宿主）」。")));
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
        // 只规范按钮本体，保留流式布局的自动换行。
        ks::ui::NormalizeToolbarControl(button);
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
    rootLayout->addLayout(toolbar);
    // 状态标签移出按钮行：换行布局没有 stretch，跟在最后一个按钮后面会被
    // 当成第九个"按钮"参与折行，位置随窗口宽度乱跳。自己占一行反而稳定。
    rootLayout->addWidget(m_statusLabel);

    m_summaryLabel = new QLabel(this);
    m_summaryLabel->setWordWrap(true);
    m_summaryLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_summaryLabel->setStyleSheet(
        QStringLiteral("QLabel{padding:6px;color:%1;}")
            .arg(KswordTheme::TextPrimaryHex()));
    rootLayout->addWidget(m_summaryLabel);

    auto* splitter = new QSplitter(Qt::Vertical, this);
    m_cpuTable = new ks::ui::VisibleTableWidget(splitter);
    // 逐核状态已有生命周期报告，收拢完整快照，仅保留复制导出。
    ks::ui::SetTableActionBarMode(m_cpuTable, ks::ui::TableActionBarMode::Compact);
    m_cpuTable->setColumnCount(CpuColumnCount);
    m_cpuTable->setHorizontalHeaderLabels({
        kernelText("kernel.hvm.cpu.processor", QStringLiteral("处理器")),
        kernelText("kernel.hvm.cpu.resource", QStringLiteral("控制结构")),
        kernelText("kernel.hvm.cpu.self_test", QStringLiteral("自检")),
        kernelText("kernel.hvm.cpu.guest_exit", QStringLiteral("来宾 / VM-exit")),
        kernelText("kernel.hvm.cpu.vmx_result", QStringLiteral("执行状态")),
        kernelText("kernel.hvm.cpu.ntstatus", QStringLiteral("NTSTATUS"))
    });
    m_cpuTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_cpuTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_cpuTable->setAlternatingRowColors(true);
    m_cpuTable->verticalHeader()->setVisible(false);
    m_cpuTable->horizontalHeader()->setSectionResizeMode(
        QHeaderView::ResizeToContents);
    m_cpuTable->horizontalHeader()->setStretchLastSection(true);

    m_detailEdit = new ks::ui::StructuredFieldView(splitter);

    m_detailEdit->setDocument(ks::ui::FieldDocument{}.note(
        kernelText(
            "kernel.hvm.detail.placeholder",
            QStringLiteral("刷新后显示后端能力、页表与生命周期证据"))));
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
    if (onBusyChanged) { onBusyChanged(true); }
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.refreshing",
            QStringLiteral("正在读取处理器能力与虚拟化后端状态...")));
    updateButtons();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([safeThis]() {
        ksword::ark::DriverClient client;
        auto result = client.queryHvmStatus();
        ksword::ark::HvmMetricsResult metrics{};
        if (result.io.ok && result.response.backend == KSWORD_ARK_HVM_BACKEND_SVM) { metrics = client.queryHvmMetrics(); }
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, result = std::move(result), metrics = std::move(metrics)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyStatus(std::move(result));
                    safeThis->applyMetrics(std::move(metrics));
                }
            },
            Qt::QueuedConnection);
    }).detach();
}

void KernelHvmTab::applyStatus(ksword::ark::HvmStatusResult result)
{
    m_operationRunning = false;
    if (onBusyChanged) { onBusyChanged(false); }
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
        m_detailEdit->setDocument({});
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
                "\n实现成熟度（Resident / EPT / Nested / eVMCS）：%1 / %2 / %3 / %4；驻留 CPU：%5；规则：%6；事件：%7（丢失 %8 / 环回 %9 / 累计 %10）"))
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
            .arg(m_snapshot.droppedEventCount)
            .arg(m_snapshot.overwrittenEventCount)
            .arg(m_snapshot.publishedEventCount));
    /*
     * 物理映射窗口单独占一行，并且和处理器数摆在一起。
     *
     * 它的准备期自检在别处**完全看不见**：过不了只会让嵌套 L2 进入和影子 EPT
     * 合成安静地拒绝，而状态位、成熟度、处理器计数没有一个会变。所以这里要的
     * 不是"有没有"，而是"够不够"——少于处理器数就意味着某些核上那些功能会拒绝，
     * 而拒绝的理由会指向功能本身，不会指向窗口。
     *
     * 分母**不能用 m_snapshot.processorCount**。那是驱动的"已准备处理器数"，
     * 在准备资源之前是 0，而窗口是在**驱动初始化**时就建好的。拿它当分母，
     * 刚加载完驱动去看这一行会显示「2 / 0 —— 不足」：分子对、分母错、结论
     * 正好反了，而且反的方向是把一台好机器报成坏的。
     */
    const unsigned long logicalProcessorCount =
        static_cast<unsigned long>(
            ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    m_summaryLabel->setText(
        m_summaryLabel->text() +
        ((logicalProcessorCount != 0UL &&
          m_snapshot.physWindowReadyCount >= logicalProcessorCount)
            ? kernelText(
                  "kernel.hvm.summary.phys_window_ok",
                  QStringLiteral("\n退出安全物理窗口：%1 / %2 个处理器已就绪"))
                  .arg(m_snapshot.physWindowReadyCount)
                  .arg(logicalProcessorCount)
            : kernelText(
                  "kernel.hvm.summary.phys_window_short",
                  QStringLiteral("\n退出安全物理窗口：%1 / %2 个处理器已就绪 —— **不足**。缺窗口的处理器上，嵌套 L2 进入与影子 EPT 合成会被拒绝，而报出来的理由会指向那些功能，不会指向窗口。"))
                  .arg(m_snapshot.physWindowReadyCount)
                  .arg(logicalProcessorCount)));
    /*
     * 嵌套单独占一行，而且**必须两个数一起报**。
     *
     * nestedState 是瞬时的：L2_ACTIVE 只在 L2 真正在跑的那一瞬成立，来宾一
     * VMXOFF 就退回 DISPATCH_READY。两秒一次的轮询几乎永远抓不到那一瞬，所以
     * 单看它会得出"L2 从来没跑起来过"的结论——而这个结论是错的。
     *
     * 拒绝计数是单调的，补的正是这个缺口：它非零，就说明这台机器上确实有别的
     * hypervisor（VMware / VirtualBox / WSL2 / Docker）想在我们底下开虚拟机
     * 并且被我们挡了。用户那边的症状是"我的虚拟机打不开了"，而在此之前没有
     * 任何读数指向我们。
     */
    m_summaryLabel->setText(
        m_summaryLabel->text() +
        kernelText(
            "kernel.hvm.summary.nested",
            QStringLiteral("\n嵌套：%1（瞬时读数）　L2 进入被拒累计：%2"))
            .arg(nestedStateText(m_snapshot.nestedState))
            .arg(m_snapshot.nestedL2LaunchRefusedCount));

    // AMD 用自己的摘要，免得把 Intel 的 EPT 与嵌套计数当成 AMD 的证据摆出来。
    //
    // 摘要是一条横幅，不是详情：原先这里整块塞的是 buildDetail 的七行输出，
    // 而下面的 m_detailEdit 显示的就是同一个 buildDetail —— 同样的内容在一页上
    // 出现两次，其中一次还把横幅撑成七行。这里只留一行，并指向详情框。
    if (m_snapshot.backend == KSWORD_ARK_HVM_BACKEND_SVM)
    {
        m_summaryLabel->setText(kernelText(
            "kernel.hvm.summary.amd",
            QStringLiteral("AMD SVM / VMCB / NPT（实验性）　准备 / 自检 / 常驻：%1 / %2 / %3　NPT 就绪：%4\n完整读数见下方详情；嵌套 SVM 为实验性，内层系统启动尚未验收。"))
            .arg(m_snapshot.preparedProcessorCount)
            .arg(m_snapshot.selfTestPassedProcessorCount)
            .arg(m_snapshot.residentProcessorCount)
            .arg(m_snapshot.slatReady
                ? kernelText("kernel.hvm.yes_plain", QStringLiteral("是"))
                : kernelText("kernel.hvm.no_plain", QStringLiteral("否"))));
    }

    m_cpuTable->setColumnCount(CpuColumnCount);
    m_cpuTable->setHorizontalHeaderLabels({
        kernelText("kernel.hvm.cpu.processor", QStringLiteral("处理器")),
        kernelText("kernel.hvm.cpu.resource", QStringLiteral("控制结构")),
        kernelText("kernel.hvm.cpu.self_test", QStringLiteral("自检")),
        kernelText("kernel.hvm.cpu.guest_exit", QStringLiteral("来宾 / VM-exit")),
        kernelText("kernel.hvm.cpu.vmx_result", QStringLiteral("执行状态")),
        kernelText("kernel.hvm.cpu.ntstatus", QStringLiteral("NTSTATUS")) });
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
            (cpu.backend == KSWORD_ARK_HVM_BACKEND_SVM) ? tested :
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
            // AMD 下这一列是 VMCB 的退出码，但它只有在真的退出过之后才有意义：
            // 没跑过 VMRUN 时字段是零，而零是一个合法的退出码（#DE）。原先无条件
            // 把它显示成 0x0000000000000000，等于把一个从没采集过的值摆成硬件读数。
            readOnlyItem(cpu.backend == KSWORD_ARK_HVM_BACKEND_SVM
                ? (cpu.vmExitCount == 0ULL
                       ? QStringLiteral("-")
                       : QStringLiteral("0x%1")
                             .arg(cpu.svmExitCode, 16, 16, QLatin1Char('0')))
                : guestExitText));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnVmxResult,
            // 这一列的表头是「执行状态」。Intel 侧放的是 VM-instruction error，
            // AMD 侧放的是执行阶段——两者都是"这一步走到哪儿/错在哪儿"，同一列成立。
            // 但阶段必须译成名字：一个裸的 3 在这张表里读不出任何东西。
            readOnlyItem(
                cpu.backend == KSWORD_ARK_HVM_BACKEND_SVM
                    ? executionStageText(cpu.executionStage)
                    : cpu.vmxInstructionResult == 0xFFU
                        ? QStringLiteral("-")
                        : QString::number(cpu.vmxInstructionResult)));
        m_cpuTable->setItem(
            rowIndex,
            CpuColumnNtStatus,
            readOnlyItem(ntStatusText(cpu.lastStatus)));
    }
    m_detailEdit->setDocument(buildDetail(m_snapshot));
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
    if (onBusyChanged) { onBusyChanged(true); }
    m_statusLabel->setText(
        kernelText(
            "kernel.hvm.status.operating",
            QStringLiteral("正在执行 HVM 生命周期操作...")));
    updateButtons();
    QPointer<KernelHvmTab> safeThis(this);
    std::thread([safeThis, command, force, enableEptEvents, enableNestedVmx, enableEvmcs]() {
        ksword::ark::DriverClient client;
        const auto before = client.queryHvmStatus();
        ksword::ark::HvmControlResult control{};
        if (before.io.ok && !before.unsupported)
        {
            control = ksword::hvm::controlWithPreferences(client, before.response, command,
                force, enableEptEvents, enableNestedVmx, enableEvmcs);
        }
        auto status = client.queryHvmStatus();
        ksword::ark::HvmMetricsResult metrics{};
        if (status.io.ok && status.response.backend == KSWORD_ARK_HVM_BACKEND_SVM) { metrics = client.queryHvmMetrics(); }
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis,
             command,
             control = std::move(control),
             status = std::move(status),
             metrics = std::move(metrics)]() mutable {
                if (safeThis != nullptr)
                {
                    safeThis->applyControl(
                        command,
                        std::move(control),
                        std::move(status));
                    safeThis->applyMetrics(std::move(metrics));
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
    if (onBusyChanged) { onBusyChanged(false); }
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
                QStringLiteral("虚拟化后端资源已准备"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_SELF_TEST)
        {
            action = kernelText(
                "kernel.hvm.action.tested",
                QStringLiteral("逐 CPU 虚拟化自检已完成"));
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
                    "所有目标 CPU 已进入虚拟化常驻；"
                    "只有完整 rendezvous 成功后才标记为 active"));
        }
        else if (command == KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT)
        {
            action = kernelText(
                "kernel.hvm.action.resident_stopped",
                QStringLiteral(
                    "驻留 VMM 已停止；所有目标处理器均已确认退出虚拟化并恢复 Windows 状态"));
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
            "按当前后端为每个 CPU 分配控制结构、保存区及页表。AMD 使用 VMCB/HSAVE 和完整 NPT 身份映射，Intel 使用 VMXON/VMCS/EPT。准备会占用不可分页内存，但不会进入常驻；只有全部 CPU 停止后才能释放。"));
    if (confirmTyped(warning, kernelText("kernel.hvm.prepare", QStringLiteral("准备虚拟化后端"))))
    {
        runControlAsync(KSWORD_ARK_HVM_CONTROL_PREPARE, false);
    }
}

void KernelHvmTab::selfTestBackend()
{
    const QString warning = kernelText(
        "kernel.hvm.self_test.warning",
        QStringLiteral(
            "驱动将绑定每个 CPU 执行硬件自检。AMD 必须完成一次带已知退出标记的 VMRUN 往返并恢复原生状态；Intel 执行 VMX 自检。请在调试虚拟机中保存工作并连接调试器，硬件或恢复错误可能导致蓝屏。"));
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
            "请先保存全部工作；外层已有 Hypervisor 时，请求必须带上嵌套允许位，也就是虚拟化菜单里的「允许嵌套运行（作为 L1）」，并且外层确实把 VMX 暴露进来。"));
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
                        "全部 CPU 停止后释放当前后端资源，并清除准备和自检证据。请先导出诊断记录。继续吗？")),
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
    const bool amd = m_snapshot.backend == KSWORD_ARK_HVM_BACKEND_SVM;
    const bool resourcesReady =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0U;
    const bool guestReady =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_GUEST_READY) != 0U;
    const bool guestRunning =
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_GUEST_RUNNING) != 0U;
    const bool residentActive = m_snapshot.residentProcessorCount > 0 ||
        (m_snapshot.stateFlags &
            KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE) != 0U;
    ksword::ark::HvmStatusResult gateResult{};
    gateResult.io.ok = m_supported;
    gateResult.response = m_snapshot;
    const auto gate = ksword::hvm::stateFromStatus(gateResult);
    const bool residentAvailable = gate.residentAdmission && gate.configurationReason.isEmpty();
    m_refreshButton->setEnabled(!m_operationRunning);

    // 下面每个按钮各算一次「第一条挡住它的门」。顺序与 setEnabled 的条件
    // 逐条对应，改其中一边必须同时改另一边。
    const QString busyReason = kernelText(
        "kernel.hvm.gate.busy",
        QStringLiteral("灰掉的原因：另一项虚拟化操作正在执行。"));
    const QString unsupportedReason = kernelText(
        "kernel.hvm.gate.unsupported",
        QStringLiteral("灰掉的原因：当前 CPU 或驱动不提供硬件虚拟化后端。"));
    const QString needResourcesReason = kernelText(
        "kernel.hvm.gate.needs_resources",
        QStringLiteral("灰掉的原因：需要先准备虚拟化后端。"));
    const QString residentActiveReason = kernelText(
        "kernel.hvm.gate.resident_active",
        QStringLiteral("灰掉的原因：驻留 VMM 正在运行；先点“停止驻留 VMM”。"));
    // commonReason：三条对所有按钮一视同仁的门，按它们实际的判定顺序返回。
    const auto commonReason = [&]() -> QString {
        if (m_operationRunning) { return busyReason; }
        if (!m_supported) { return unsupportedReason; }
        return QString();
    };

    m_prepareButton->setEnabled(
        !m_operationRunning && m_supported && !resourcesReady && !residentActive);
    setGateTooltip(m_prepareButton, [&]() -> QString {
        const QString common = commonReason();
        if (!common.isEmpty()) { return common; }
        if (resourcesReady)
        {
            return kernelText(
                "kernel.hvm.gate.already_prepared",
                QStringLiteral("灰掉的原因：资源已经准备过了；要重新准备先点“释放后端”。"));
        }
        return QString();
    }());

    m_selfTestButton->setEnabled(
        !m_operationRunning &&
        m_supported && residentAvailable &&
        resourcesReady &&
        !residentActive);
    setGateTooltip(m_selfTestButton, [&]() -> QString {
        const QString common = commonReason();
        if (!common.isEmpty()) { return common; }
        if (!resourcesReady) { return needResourcesReason; }
        if (residentActive) { return residentActiveReason; }
        if (!residentAvailable) { return gate.configurationReason.isEmpty() ? gate.admissionReason : gate.configurationReason; }
        return QString();
    }());

    m_launchButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        guestReady &&
        !guestRunning &&
        !residentActive);
    setGateTooltip(m_launchButton, [&]() -> QString {
        const QString common = commonReason();
        if (!common.isEmpty()) { return common; }
        if (!guestReady)
        {
            return kernelText(
                "kernel.hvm.gate.guest_not_ready",
                QStringLiteral("灰掉的原因：一次性来宾尚未就绪，需要先准备资源并通过逐 CPU 自检。"));
        }
        if (guestRunning)
        {
            return kernelText(
                "kernel.hvm.gate.guest_running",
                QStringLiteral("灰掉的原因：一次性来宾正在运行。"));
        }
        if (residentActive) { return residentActiveReason; }
        return QString();
    }());

    m_teardownButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        resourcesReady &&
        !guestRunning &&
        !residentActive);
    setGateTooltip(m_teardownButton, [&]() -> QString {
        const QString common = commonReason();
        if (!common.isEmpty()) { return common; }
        if (!resourcesReady)
        {
            return kernelText(
                "kernel.hvm.gate.nothing_to_release",
                QStringLiteral("灰掉的原因：当前没有已准备的资源可释放。"));
        }
        if (guestRunning)
        {
            return kernelText(
                "kernel.hvm.gate.guest_running",
                QStringLiteral("灰掉的原因：一次性来宾正在运行。"));
        }
        if (residentActive) { return residentActiveReason; }
        return QString();
    }());

    m_startResidentButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        residentAvailable &&
        gate.selfTestPassed &&
        !residentActive &&
        m_featureArea != FeatureArea::Evmcs);
    setGateTooltip(m_startResidentButton, [&]() -> QString {
        const QString common = commonReason();
        if (!common.isEmpty()) { return common; }
        if (m_featureArea == FeatureArea::Evmcs)
        {
            return kernelText(
                "kernel.hvm.gate.evmcs_no_resident",
                QStringLiteral("灰掉的原因：eVMCS 视图不提供常驻启动入口。"));
        }
        if (!residentAvailable)
        {
            return !gate.configurationReason.isEmpty() ? gate.configurationReason : gate.admissionReason;
        }
        if (!gate.selfTestPassed)
        {
            return kernelText(
                "kernel.hvm.gate.self_test_required",
                QStringLiteral("灰掉的原因：需要先通过“逐 CPU 自检”。"));
        }
        if (residentActive)
        {
            return kernelText(
                "kernel.hvm.gate.already_resident",
                QStringLiteral("灰掉的原因：驻留 VMM 已经在运行。"));
        }
        return QString();
    }());

    m_stopResidentButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        residentActive);
    setGateTooltip(m_stopResidentButton, [&]() -> QString {
        const QString common = commonReason();
        if (!common.isEmpty()) { return common; }
        if (!residentActive)
        {
            return kernelText(
                "kernel.hvm.gate.resident_inactive",
                QStringLiteral("灰掉的原因：当前没有驻留 VMM 在运行。"));
        }
        return QString();
    }());

    m_featureActionButton->setEnabled(
        !m_operationRunning &&
        m_supported &&
        (m_featureArea != FeatureArea::Ept || resourcesReady));
    setGateTooltip(m_featureActionButton, [&]() -> QString {
        const QString common = commonReason();
        if (!common.isEmpty()) { return common; }
        if (m_featureArea == FeatureArea::Ept && !resourcesReady)
        {
            return needResourcesReason;
        }
        return QString();
    }());
    m_launchButton->setVisible(!amd);
    m_featureActionButton->setVisible(!amd);
    if (amd)
    {
        m_launchButton->setEnabled(false);
        m_featureActionButton->setEnabled(false);
    }
    if (!gate.residentAdmission || !gate.configurationReason.isEmpty())
    {
        m_prepareButton->setEnabled(false);
        setGateTooltip(m_prepareButton, !gate.configurationReason.isEmpty() ? gate.configurationReason : gate.admissionReason);
    }
}
