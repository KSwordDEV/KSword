#include "KvmDock.h"

#include "../Internationalization/LanguageManager.h"
#include "../KernelDock/KernelHvmTab.h"
#include "../UI/FlowLayout.h"
#include "../UI/KvmControl.h"
#include "../theme.h"

#include <QGroupBox>
#include <QHideEvent>
#include <QLabel>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <QVariant>

#include <thread>
#include <utility>

namespace
{
    // 轮询周期。状态查询是阻塞 IOCTL，读一次的代价不高，但常驻切换期间
    // 驱动侧状态锁被独占，查询会一直排队，所以不能压得更短。
    constexpr int kStatePollIntervalMilliseconds = 2000;

    enum class StepPhase
    {
        Done,
        Active,
        Pending
    };

    // 三态一律用 QSS 动态调色板角色表达。静态 *ColorHex() 在这里也能显示，
    // 但主题切换后不会自己更新，而这一页没有重建入口。
    void applyStepStyle(QLabel* const label, const StepPhase phase)
    {
        if (label == nullptr)
        {
            return;
        }
        QString backgroundColor = QStringLiteral("transparent");
        QString textColor = KswordTheme::TextSecondaryHex();
        QString borderColor = KswordTheme::BorderHex();
        if (phase == StepPhase::Active)
        {
            backgroundColor = KswordTheme::PrimaryBlueHex;
            textColor = KswordTheme::OnAccentDynamicHex();
            borderColor = KswordTheme::PrimaryBlueHex;
        }
        else if (phase == StepPhase::Done)
        {
            textColor = KswordTheme::TextPrimaryHex();
            borderColor = KswordTheme::BorderStrongHex();
        }
        label->setStyleSheet(
            QStringLiteral(
                "QLabel{"
                "  background:%1;"
                "  color:%2;"
                "  border:1px solid %3;"
                "  border-radius:%4px;"
                "  padding:3px 10px;"
                "  font-weight:600;"
                "}")
                .arg(backgroundColor)
                .arg(textColor)
                .arg(borderColor)
                .arg(KswordTheme::ControlCornerRadius));
    }

    // 「为什么灰」必须跟着按钮走：调用点算得出禁用条件，而用户看到的只有一个
    // 灰按钮。首次调用时把静态说明存进动态属性，之后每次都以它为底重新拼，
    // 否则反复禁用会把原因一条条叠成长串。
    void setGatedTooltip(QPushButton* const button, const QString& gateReason)
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

KvmDock::KvmDock(QWidget* const parent)
    : QWidget(parent)
{
    initializeUi();
    updateLifecycleView();
}

void KvmDock::setActionHandler(ActionHandler handler)
{
    m_actionHandler = std::move(handler);
}

void KvmDock::setOperationRunning(const bool running)
{
    if (m_operationRunning == running)
    {
        return;
    }
    m_operationRunning = running;
    updateLifecycleView();
    if (!running)
    {
        // 命令刚结束，状态锁已经放开：立刻补一次查询，不用等下一个轮询周期，
        // 否则用户会看到两秒钟的旧步骤。
        refreshStateAsync();
    }
}

void KvmDock::showEvent(QShowEvent* const event)
{
    QWidget::showEvent(event);
    refreshStateAsync();
    if (m_pollTimer != nullptr)
    {
        m_pollTimer->start();
    }
}

void KvmDock::hideEvent(QHideEvent* const event)
{
    QWidget::hideEvent(event);
    // 页面不可见时停表：这一页不是常驻监控，没必要让后台一直发 IOCTL。
    if (m_pollTimer != nullptr)
    {
        m_pollTimer->stop();
    }
}

void KvmDock::initializeUi()
{
    auto* const rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // 常驻表头：只放「我现在在哪一步」。
    //
    // 这两行是唯一在任何子页下都必须看得见的东西——切到证据页之后仍然要
    // 知道自己处在哪一步，否则子 Tab 就把生命周期这条主线切断了。
    auto* const headerPanel = new QWidget(this);
    auto* const headerLayout = new QVBoxLayout(headerPanel);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(4);

    // 面包屑用换行布局：1024 宽下三段加两个箭头刚好占满，再窄一点
    // QHBoxLayout 会把标签压到裁字，换行布局则是折到第二行。
    auto* const stepRow = new ks::ui::FlowLayout(nullptr, 0, 6, 4);
    m_stepOneLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("第 1 步 · 准备资源")),
        headerPanel);
    m_stepTwoLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("第 2 步 · 安装视图 / 策略 / 域")),
        headerPanel);
    m_stepThreeLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("第 3 步 · 启动常驻")),
        headerPanel);
    stepRow->addWidget(m_stepOneLabel);
    stepRow->addWidget(new QLabel(QStringLiteral("→"), headerPanel));
    stepRow->addWidget(m_stepTwoLabel);
    stepRow->addWidget(new QLabel(QStringLiteral("→"), headerPanel));
    stepRow->addWidget(m_stepThreeLabel);
    headerLayout->addLayout(stepRow);

    m_stateLabel = new QLabel(headerPanel);
    m_stateLabel->setWordWrap(true);
    m_stateLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
            .arg(KswordTheme::TextPrimaryHex()));
    headerLayout->addWidget(m_stateLabel);
    rootLayout->addWidget(headerPanel);

    // 子 Tab：把原先竖着堆五段的控制面板拆开。
    //
    // 竖着堆在 1024×768 上是灾难：三个分组加两段说明文字先吃掉三分之二的
    // 高度，剩给逐 CPU 表的只有两三行；而每个分组内部的按钮又在横向被裁。
    // 拆成子页之后每一页只剩一件事，两个方向的挤压同时消失。
    auto* const tabs = new QTabWidget(this);
    tabs->setDocumentMode(true);

    auto* const controlPanel = new QWidget(tabs);
    auto* const controlLayout = new QVBoxLayout(controlPanel);
    controlLayout->setContentsMargins(6, 6, 6, 6);
    controlLayout->setSpacing(6);

    // 第 1 步：准备与释放。两者都不进入常驻，它们围出的正是第 2 步的窗口期。
    auto* const prepareGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 1 步 · 资源（不进入常驻）")),
        controlPanel);
    auto* const prepareRow = new ks::ui::FlowLayout(prepareGroup, 6, 6, 4);
    m_prepareButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("准备资源（不进入常驻）")),
        prepareGroup);
    m_prepareButton->setToolTip(ks::i18n::sourceText(QStringLiteral("分配每处理器资源并建立 EPT，但不进入常驻。分离视图、MSR 策略、CR 策略与执行域都必须在这一步之后、启动常驻之前安装 —— 常驻期间这几张表都是不可变的。")));
    m_releaseButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("释放资源")),
        prepareGroup);
    m_releaseButton->setToolTip(ks::i18n::sourceText(QStringLiteral("释放全部可逆资源，回到未准备状态。改过分离视图后端或每处理器私有 EPT 之后必须走这一步 —— 那两个选择只在准备资源时被消费，已准备的运行时改开关不会生效。")));
    prepareRow->addWidget(m_prepareButton);
    prepareRow->addWidget(m_releaseButton);
    controlLayout->addWidget(prepareGroup);

    // 第 2 步：一个引导式入口加六个 R-1 面板。它们本身不改状态，改状态的是里面的安装动作，
    // 而那些动作要求资源已准备且未常驻——正是这个分组标题写的那句话。
    auto* const installGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 2 步 · 安装（要求资源已准备且未常驻）")),
        controlPanel);
    auto* const installRow = new ks::ui::FlowLayout(installGroup, 6, 6, 4);
    // 引导式入口放在第一个：它是这一组里唯一一个不要求用户先自己算出物理页地址的。
    // 下面那六个面板保留原样给专家用——它们能做的事更多，代价是每一个值都要自己备好。
    m_hookWizardButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("添加 Hook（引导式）...")),
        installGroup);
    m_hookWizardButton->setToolTip(ks::i18n::sourceText(QStringLiteral("按模块加偏移或虚拟地址指定目标，自动翻译成页对齐的物理地址；影子页默认与目标页逐字节相同，只改你指定的那几个字节。装前逐条预检，装后把 EPT 叶读回来核对。")));
    m_viewButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("EPT 分离视图（隐蔽 Hook / 内存隐藏）...")),
        installGroup);
    m_domainButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("EPT 执行域（VMFUNC 可切换）...")),
        installGroup);
    m_msrButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("MSR 策略...")),
        installGroup);
    m_crButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("控制寄存器策略...")),
        installGroup);
    m_memoryButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("R-1 内存操作...")),
        installGroup);
    m_eventButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("事件流...")),
        installGroup);
    for (QPushButton* const button :
         { m_hookWizardButton, m_viewButton, m_domainButton, m_msrButton, m_crButton, m_memoryButton, m_eventButton })
    {
        installRow->addWidget(button);
    }
    controlLayout->addWidget(installGroup);

    // 第 3 步：进出常驻，以及唯一一个"卡住时先做这个"的出口。
    auto* const residentGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 3 步 · 常驻与故障")),
        controlPanel);
    auto* const residentRow = new ks::ui::FlowLayout(residentGroup, 6, 6, 4);
    m_residentButton = new QPushButton(residentGroup);
    m_soakButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("常驻保持自检（5 秒）")),
        residentGroup);
    m_soakButton->setToolTip(ks::i18n::sourceText(QStringLiteral("全部逻辑处理器会进入 VMX non-root 并保持数秒后自动退出。期间任何未被处理的 VM-exit 都会被记录为掉核，与 Hyper-V/VBS 冲突时可能导致系统不稳定。")));
    m_resetFaultButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("重置故障状态")),
        residentGroup);
    residentRow->addWidget(m_residentButton);
    residentRow->addWidget(m_soakButton);
    residentRow->addWidget(m_resetFaultButton);
    controlLayout->addWidget(residentGroup);

    // 说明文字放在控制页最下面而不是页首：它解释的是"右键菜单还在"，
    // 属于读一次就够的话，占着页首会把三个分组一起往下推。
    m_hintLabel = new QLabel(
        ks::i18n::sourceText(QStringLiteral("标题栏 KVM 按钮的右键菜单原样保留，能力与这一页一致；这一页额外把生命周期顺序和每一步的前置条件写出来。")),
        controlPanel);
    m_hintLabel->setWordWrap(true);
    m_hintLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    controlLayout->addWidget(m_hintLabel);
    controlLayout->addStretch(1);

    for (QPushButton* const button :
         { m_prepareButton,
           m_releaseButton,
           m_hookWizardButton,
           m_viewButton,
           m_domainButton,
           m_msrButton,
           m_crButton,
           m_memoryButton,
           m_eventButton,
           m_residentButton,
           m_soakButton,
           m_resetFaultButton })
    {
        button->setStyleSheet(KswordTheme::ThemedButtonStyle());
    }

    connect(m_prepareButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::PrepareResources);
    });
    connect(m_releaseButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::ReleaseResources);
    });
    connect(m_hookWizardButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenHookWizard);
    });
    connect(m_viewButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenViewDialog);
    });
    connect(m_domainButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenDomainDialog);
    });
    connect(m_msrButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenMsrPolicyDialog);
    });
    connect(m_crButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenCrPolicyDialog);
    });
    connect(m_memoryButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenMemoryDialog);
    });
    connect(m_eventButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenEventDialog);
    });
    connect(m_residentButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::ToggleResident);
    });
    connect(m_soakButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::Soak);
    });
    connect(m_resetFaultButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::ResetFault);
    });

    // 状态详情页：快照原文。
    //
    // 单独成页而不是跟按钮挤在一起，是因为它的行数不受控——后端、嵌套、
    // 写访问、保持自检每多一条就多一行，而按钮的位置不该跟着它上下漂。
    // 外面套滚动区：行数超过页高时要能滚，不能把文字挤没。
    auto* const detailPage = new QScrollArea(tabs);
    detailPage->setWidgetResizable(true);
    detailPage->setFrameShape(QFrame::NoFrame);
    auto* const detailHost = new QWidget(detailPage);
    auto* const detailLayout = new QVBoxLayout(detailHost);
    detailLayout->setContentsMargins(6, 6, 6, 6);
    detailLayout->setSpacing(6);
    m_detailLabel = new QLabel(detailHost);
    m_detailLabel->setWordWrap(true);
    m_detailLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_detailLabel->setAlignment(Qt::AlignTop | Qt::AlignLeft);
    m_detailLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    detailLayout->addWidget(m_detailLabel);
    detailLayout->addStretch(1);
    detailPage->setWidget(detailHost);

    // 从「内核」页整块搬过来的 VT-x/EPT 页。它带着 PREPARE / SELF_TEST /
    // 一次性来宾 / TEARDOWN 与 EPT 规则——EPT 规则至今只有这一条路可达，
    // 所以它必须跟着搬，而不是被上面的按钮取代。
    //
    // 它自己就带一个逐 CPU 表加一个详情面板，独占一页才有得看：原先跟
    // 控制面板共享一个分隔条时，默认分法只给它留下两三行表格。
    m_hvmTab = new KernelHvmTab(tabs);

    tabs->addTab(controlPanel, ks::i18n::sourceText(QStringLiteral("控制")));
    tabs->addTab(detailPage, ks::i18n::sourceText(QStringLiteral("状态详情")));
    tabs->addTab(m_hvmTab, ks::i18n::sourceText(QStringLiteral("VT-x/EPT 证据")));
    rootLayout->addWidget(tabs, 1);

    m_pollTimer = new QTimer(this);
    m_pollTimer->setInterval(kStatePollIntervalMilliseconds);
    connect(m_pollTimer, &QTimer::timeout, this, [this]() {
        refreshStateAsync();
    });
}

void KvmDock::refreshStateAsync()
{
    // 合并并发查询：轮询是周期性的，堆积请求只会拖慢驱动。
    // 命令执行期间同样不查：状态锁被独占，查询只会挂在那里等。
    if (m_queryInFlight || m_operationRunning)
    {
        return;
    }
    m_queryInFlight = true;
    QPointer<KvmDock> safeThis(this);
    std::thread([safeThis]() {
        const ksword::kvm::KvmState state = ksword::kvm::queryState();
        if (safeThis == nullptr)
        {
            return;
        }
        QMetaObject::invokeMethod(
            safeThis,
            [safeThis, state]() {
                if (safeThis == nullptr)
                {
                    return;
                }
                safeThis->m_queryInFlight = false;
                safeThis->applyState(state);
            },
            Qt::QueuedConnection);
    }).detach();
}

void KvmDock::applyState(const ksword::kvm::KvmState& state)
{
    m_driverRunning =
        state.availability != ksword::kvm::KvmAvailability::DriverNotRunning;
    m_hardwareAvailable =
        state.availability == ksword::kvm::KvmAvailability::Available ||
        state.availability == ksword::kvm::KvmAvailability::NotPrepared;
    // NotPrepared 是"硬件门过了但资源还没分配"，也就是第 1 步尚未完成。
    // 其余可用态都意味着 PREPARE 已经做过。
    m_resourcesReady =
        state.availability == ksword::kvm::KvmAvailability::Available;
    m_residentActive = state.residentActive;
    m_faulted = state.faulted;
    m_availabilityText = ksword::kvm::describeAvailability(state.availability);
    m_detailText = state.detail;
    updateLifecycleView();
}

void KvmDock::updateLifecycleView()
{
    // 三个步骤标签只表达"走到哪儿了"，与按钮可用性分开算：
    // 故障态下按钮全灰，但步骤条仍应显示资源是否已经准备过。
    StepPhase stepOnePhase = StepPhase::Pending;
    StepPhase stepTwoPhase = StepPhase::Pending;
    StepPhase stepThreePhase = StepPhase::Pending;
    if (m_residentActive)
    {
        stepOnePhase = StepPhase::Done;
        stepTwoPhase = StepPhase::Done;
        stepThreePhase = StepPhase::Active;
    }
    else if (m_resourcesReady)
    {
        stepOnePhase = StepPhase::Done;
        stepTwoPhase = StepPhase::Active;
    }
    else if (m_driverRunning && m_hardwareAvailable)
    {
        stepOnePhase = StepPhase::Active;
    }
    applyStepStyle(m_stepOneLabel, stepOnePhase);
    applyStepStyle(m_stepTwoLabel, stepTwoPhase);
    applyStepStyle(m_stepThreeLabel, stepThreePhase);

    QString stateText;
    if (m_operationRunning)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：正在执行一项 KVM 操作，等它结束。"));
    }
    else if (!m_driverRunning)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：KswordARK 驱动未运行。先用标题栏的 R0 按钮启动驱动服务，这一页的入口在那之前都不会生效。"));
    }
    else if (m_faulted)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：故障或待回滚。先执行“重置故障状态”，其余入口在那之前都不会生效。"));
    }
    else if (!m_hardwareAvailable)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：不可用。%1")).arg(m_availabilityText);
    }
    else if (m_residentActive)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：第 3 步。常驻运行中；分离视图、MSR 策略、CR 策略与执行域这几张表在常驻期间不可改，要改先停止常驻。"));
    }
    else if (m_resourcesReady)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：第 2 步。资源已准备且未常驻，这是安装分离视图、MSR 策略、CR 策略与执行域的唯一窗口期。"));
    }
    else
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：第 1 步。资源尚未准备，先点“准备资源（不进入常驻）”。"));
    }
    m_stateLabel->setText(stateText);
    m_detailLabel->setText(m_detailText);
    m_detailLabel->setVisible(!m_detailText.isEmpty());

    m_residentButton->setText(m_residentActive
        ? ks::i18n::sourceText(QStringLiteral("停止常驻"))
        : ks::i18n::sourceText(QStringLiteral("启动常驻")));

    // 每个按钮的门与右键菜单逐条一致；这里只是把"为什么灰"一并说出来。
    const QString driverGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：KswordARK 驱动未运行。"));
    const QString busyGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：正在执行另一项 KVM 操作。"));
    const QString residentGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：常驻运行中，这一步只能在未常驻时做。"));
    const QString hardwareGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：当前硬件或系统状态不满足 KVM 常驻条件。"));

    const auto resourceStageReason = [&]() -> QString {
        if (m_operationRunning) { return busyGate; }
        if (!m_driverRunning) { return driverGate; }
        if (m_residentActive) { return residentGate; }
        if (!m_hardwareAvailable) { return hardwareGate; }
        return QString();
    };
    const QString resourceGateReason = resourceStageReason();
    m_prepareButton->setEnabled(resourceGateReason.isEmpty());
    m_releaseButton->setEnabled(resourceGateReason.isEmpty());
    setGatedTooltip(m_prepareButton, resourceGateReason);
    setGatedTooltip(m_releaseButton, resourceGateReason);

    // 这七个入口只要驱动在就能打开：里面读得到状态，写得动的动作各自有门。
    // 常驻期间照样能开，否则用户连"现在装了什么"都看不到。
    const QString panelGateReason = m_driverRunning ? QString() : driverGate;
    for (QPushButton* const button :
         { m_hookWizardButton, m_viewButton, m_domainButton, m_msrButton, m_crButton, m_memoryButton, m_eventButton })
    {
        button->setEnabled(m_driverRunning);
        setGatedTooltip(button, panelGateReason);
    }

    const auto residentToggleReason = [&]() -> QString {
        if (m_operationRunning) { return busyGate; }
        if (!m_driverRunning) { return driverGate; }
        if (m_residentActive) { return QString(); }
        if (!m_hardwareAvailable) { return hardwareGate; }
        return QString();
    };
    const QString residentReason = residentToggleReason();
    m_residentButton->setEnabled(residentReason.isEmpty());
    setGatedTooltip(m_residentButton, residentReason);

    const QString soakReason = resourceGateReason;
    m_soakButton->setEnabled(soakReason.isEmpty());
    setGatedTooltip(m_soakButton, soakReason);

    const auto faultResetReason = [&]() -> QString {
        if (m_operationRunning) { return busyGate; }
        if (!m_driverRunning) { return driverGate; }
        if (!m_faulted)
        {
            return ks::i18n::sourceText(QStringLiteral("灰掉的原因：当前没有记录到故障或待回滚标记。"));
        }
        return QString();
    };
    const QString faultReason = faultResetReason();
    m_resetFaultButton->setEnabled(faultReason.isEmpty());
    setGatedTooltip(m_resetFaultButton, faultReason);
}

void KvmDock::requestAction(const Action action)
{
    if (!m_actionHandler)
    {
        return;
    }
    m_actionHandler(action);
    // 控制命令会让 MainWindow 立刻推进 setOperationRunning(true)，
    // 那条路径自己会补查询；打开面板则什么都不会变，这里补一次也无害。
    refreshStateAsync();
}
