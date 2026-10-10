#include "HvmDock.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/FlatButtonTheme.h"

#include "../Internationalization/LanguageManager.h"
#include "../KernelDock/KernelHvmTab.h"
#include "../UI/FlowLayout.h"
#include "../UI/HvmControl.h"
#include "../UI/HvmGuestVmPanel.h"
#include "../UI/HvmWatchPanel.h"
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

HvmDock::HvmDock(QWidget* const parent)
    : QWidget(parent)
{
    initializeUi();
    updateLifecycleView();
    applyState(ksword::hvm::HvmState{});
}

void HvmDock::setActionHandler(ActionHandler handler)
{
    m_actionHandler = std::move(handler);
}

void HvmDock::setCommandOperationHandler(std::function<void(bool)> handler)
{
    m_commandOperationHandler = std::move(handler);
}

void HvmDock::setOperationRunning(const bool running)
{
    if (m_operationRunning == running)
    {
        return;
    }
    m_operationRunning = running;
    m_hvmTab->setEnabled(!running);
    // 内存监视发的是同一条 EPT 规则 IOCTL，与其余入口共用驱动侧那把状态锁。
    m_watchPanel->setEnabled(!running);
    // 「跑第三方虚拟机」页发的是同一批控制命令，必须和其它入口一起串行化：
    // 漏掉它，别处的命令在飞时用户仍能按下「一键完成全部五步」，两路 IOCTL
    // 会同时压到驱动侧那把状态锁上。自己发起时它先经 setBusy 禁掉自家按钮，
    // 再被这一行连同整页禁用。
    m_guestVmPanel->setEnabled(!running);
    updateLifecycleView();
    if (!running)
    {
        // 命令刚结束，状态锁已经放开：立刻补一次查询，不用等下一个轮询周期，
        // 否则用户会看到两秒钟的旧步骤。
        refreshStateAsync();
    }
}

void HvmDock::showEvent(QShowEvent* const event)
{
    QWidget::showEvent(event);
    refreshStateAsync();
    if (m_pollTimer != nullptr)
    {
        m_pollTimer->start();
    }
}

void HvmDock::hideEvent(QHideEvent* const event)
{
    QWidget::hideEvent(event);
    // 页面不可见时停表：这一页不是常驻监控，没必要让后台一直发 IOCTL。
    if (m_pollTimer != nullptr)
    {
        m_pollTimer->stop();
    }
}

void HvmDock::initializeUi()
{
    auto* const rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(6, 6, 6, 6);
    rootLayout->setSpacing(6);

    // 常驻表头：只放「我现在在哪一步」。
    //
    // 这两行是唯一在任何子页下都必须看得见的东西——切到证据页之后仍然要
    // 知道自己处在哪一步，否则子 Tab 就把生命周期这条主线切断了。
    auto* const headerPanel = new QWidget(this);
    // 生命周期状态使用轻底面，和下方操作页形成稳定的阅读起点。
    ks::ui::StylePrimaryToolbar(headerPanel);
    auto* const headerLayout = new QVBoxLayout(headerPanel);
    headerLayout->setContentsMargins(8, 6, 8, 6);
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
    m_tabs = tabs;
    ks::ui::StylePageTabs(tabs);

    auto* const controlPanel = new QWidget(tabs);
    auto* const controlLayout = new QVBoxLayout(controlPanel);
    controlLayout->setContentsMargins(6, 6, 6, 6);
    // 三个步骤之间留出分区间距，组内按钮仍保持紧凑流式排列。
    controlLayout->setSpacing(16);

    // 第 1 步：准备与释放。两者都不进入常驻，它们围出的正是第 2 步的窗口期。
    auto* const prepareGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 1 步 · 资源（不进入常驻）")),
        controlPanel);
    auto* const prepareRow = new ks::ui::FlowLayout(prepareGroup, 6, 8, 8);
    ks::ui::StylePrimaryGroup(prepareGroup);
    m_prepareButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("准备资源（不进入常驻）")),
        prepareGroup);
    // 说明里同时点名两套后端：这一页在 AMD 机器上结构不变，只是有些入口会灰掉。
    // 把 Intel 的术语写死在这里，等于让 AMD 用户看着一句与自己无关的话去按按钮。
    m_prepareButton->setToolTip(ks::i18n::sourceText(QStringLiteral("按当前后端分配每处理器资源并建立 EPT 或 NPT，但不进入常驻。分离视图、MSR 策略、CR 策略与执行域都必须在这一步之后、启动常驻之前安装 —— 常驻期间这几张表都是不可变的。")));
    m_releaseButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("释放资源")),
        prepareGroup);
    m_releaseButton->setToolTip(ks::i18n::sourceText(QStringLiteral("释放全部可逆资源，回到未准备状态。改过分离视图后端或每处理器私有 EPT 之后必须走这一步 —— 那两个选择只在准备资源时被消费，已准备的运行时改开关不会生效。")));
    // 「硬件虚拟化证据」原先只有把页翻到最后一个子 Tab 才找得到。放进第 1 步，
    // 是因为它回答的正是这一步之前必须先问的问题：这台机器到底是什么后端、
    // 逐核准备到哪儿了。它只读，任何时候按都不改状态。
    m_evidenceButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("硬件虚拟化证据")),
        prepareGroup);
    m_evidenceButton->setToolTip(ks::i18n::sourceText(QStringLiteral("切到证据页：完整能力、逐处理器状态与退出计数。只读，不改变任何状态。")));
    prepareRow->addWidget(m_prepareButton);
    prepareRow->addWidget(m_releaseButton);
    prepareRow->addWidget(m_evidenceButton);
    controlLayout->addWidget(prepareGroup);

    // 第 2 步：一个引导式入口加七个 R-1 面板。它们本身不改状态，改状态的是里面的安装动作，
    // 而那些动作要求资源已准备且未常驻——正是这个分组标题写的那句话。
    auto* const installGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 2 步 · 安装（要求资源已准备且未常驻）")),
        controlPanel);
    auto* const installRow = new ks::ui::FlowLayout(installGroup, 6, 8, 8);
    ks::ui::StylePrimaryGroup(installGroup);
    // 引导式入口放在第一个：它是这一组里唯一一个不要求用户先自己算出物理页地址的。
    // 下面那七个面板保留原样给专家用——它们能做的事更多，代价是每一个值都要自己备好。
    m_selfTestButton = new QPushButton(ks::i18n::sourceText(QStringLiteral("全核 SVM 自检")), installGroup);
    installRow->addWidget(m_selfTestButton);
    connect(m_selfTestButton, &QPushButton::clicked, this, [this]() { requestAction(Action::SelfTest); });
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
    m_processButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("R-1 进程处置与注入...")),
        installGroup);
    m_processButton->setToolTip(ks::i18n::sourceText(QStringLiteral("在 R0 之外冻结或结束一个进程，或用分离视图加线程劫持在目标里加载 DLL。要求先开启 CR3 追踪、用 EPTP 切换后端准备资源，且常驻停着。这不是安全边界：目标换掉自己那一页的物理页就不在被拒绝的页上了。")));
    for (QPushButton* const button :
         { m_hookWizardButton, m_viewButton, m_domainButton, m_msrButton, m_crButton,
           m_memoryButton, m_eventButton, m_processButton })
    {
        installRow->addWidget(button);
    }
    controlLayout->addWidget(installGroup);

    // 第 3 步：进出常驻，以及唯一一个"卡住时先做这个"的出口。
    auto* const residentGroup = new QGroupBox(
        ks::i18n::sourceText(QStringLiteral("第 3 步 · 常驻与故障")),
        controlPanel);
    auto* const residentRow = new ks::ui::FlowLayout(residentGroup, 6, 8, 8);
    ks::ui::StylePrimaryGroup(residentGroup);
    m_residentButton = new QPushButton(residentGroup);
    m_soakButton = new QPushButton(
        ks::i18n::sourceText(QStringLiteral("常驻保持自检（5 秒）")),
        residentGroup);
    m_soakButton->setToolTip(ks::i18n::sourceText(QStringLiteral("全部逻辑处理器会用当前后端进入来宾态并保持数秒后自动退出。期间任何未被处理的退出都会被记录为掉核，与已有 Hypervisor 冲突时可能导致系统不稳定。")));
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
        ks::i18n::sourceText(QStringLiteral("标题栏 HVM 按钮的右键菜单原样保留，能力与这一页一致；这一页额外把生命周期顺序和每一步的前置条件写出来。")),
        controlPanel);
    m_hintLabel->setWordWrap(true);
    m_hintLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    controlLayout->addWidget(m_hintLabel);
    controlLayout->addStretch(1);

    for (QPushButton* const button :
         { m_prepareButton,
           m_selfTestButton,
           m_releaseButton,
           m_evidenceButton,
           m_hookWizardButton,
           m_viewButton,
           m_domainButton,
           m_msrButton,
           m_crButton,
           m_memoryButton,
           m_eventButton,
           m_processButton,
           m_residentButton,
           m_soakButton,
           m_resetFaultButton })
    {
        // 生命周期动作保留实心可识别底面，禁用和悬停由统一状态配方处理。
        ks::ui::ApplyFlatButtonTheme(button,
            ks::ui::FlatButtonTone::Neutral, ks::ui::FlatButtonAppearance::Solid);
        // 流式布局保留窄窗换行，只统一每个生命周期按钮的尺寸。
        ks::ui::NormalizeToolbarControl(button);
    }

    connect(m_prepareButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::PrepareResources);
    });
    connect(m_releaseButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::ReleaseResources);
    });
    // 证据页不经 ActionHandler：它不是一条控制命令，只是把本页的子 Tab 翻过去。
    // 走分派会让 MainWindow 多出一条什么都不做的分支。
    connect(m_evidenceButton, &QPushButton::clicked, this, [this]() {
        m_tabs->setCurrentWidget(m_hvmTab);
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
    connect(m_processButton, &QPushButton::clicked, this, [this]() {
        requestAction(Action::OpenProcessDialog);
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

    // 从「内核」页整块搬过来的硬件虚拟化页。它带着 PREPARE / SELF_TEST /
    // 一次性来宾 / TEARDOWN 与 EPT 规则——EPT 规则至今只有这一条路可达，
    // 所以它必须跟着搬，而不是被上面的按钮取代。
    //
    // 它自己就带一个逐 CPU 表加一个详情面板，独占一页才有得看：原先跟
    // 控制面板共享一个分隔条时，默认分法只给它留下两三行表格。
    m_hvmTab = new KernelHvmTab(tabs);

    // 「跑第三方虚拟机」排在最前面。
    //
    // 它是唯一一页写给不了解虚拟化的人看的：其余三页都假设读者知道 PREPARE、
    // 常驻、EPT 是什么。而"装了 KSwordVM 之后 VMware 打不开"恰恰是普通用户最
    // 容易撞上、也最不可能自己查出来的一件事——VMware 报的是"与 Hyper-V 不兼容"，
    // 根本不指向我们。放第一页是为了让人不用先知道该找什么才能找到它。
    m_guestVmPanel = new HvmGuestVmPanel(tabs);
    m_guestVmPanel->onBusyChanged = [this](bool running) {
        setOperationRunning(running);
        if (m_commandOperationHandler) { m_commandOperationHandler(running); }
    };
    tabs->addTab(m_guestVmPanel,
                 ks::i18n::sourceText(QStringLiteral("跑第三方虚拟机")));

    tabs->addTab(controlPanel, ks::i18n::sourceText(QStringLiteral("控制")));

    // 内存监视排在控制之后、状态详情之前。
    //
    // 它是这一页里唯一一个**产出证据**而不是改状态的功能：其余几页回答的是
    // "现在装了什么、走到哪一步了"，这一页回答的是"下一次是谁动了它"。紧挨着
    // 控制页，是因为它有一个硬前置条件——常驻必须在跑，否则装上的监视永远不会
    // 响，而那个条件正是控制页在管的。
    m_watchPanel = new HvmWatchPanel(tabs);
    m_watchPanel->onBusyChanged = [this](bool running) {
        setOperationRunning(running);
        if (m_commandOperationHandler) { m_commandOperationHandler(running); }
    };
    tabs->addTab(m_watchPanel, ks::i18n::sourceText(QStringLiteral("内存监视")));

    tabs->addTab(detailPage, ks::i18n::sourceText(QStringLiteral("状态详情")));
    // 页名不再写 VT-x/EPT：同一页在 AMD 机器上显示 SVM/NPT 的读数，
    // 页名钉死在一套架构上会让另一套的用户以为这页与自己无关。
    m_hvmTab->onBusyChanged = [this](bool running) {
        setOperationRunning(running);
        if (m_commandOperationHandler) { m_commandOperationHandler(running); }
    };
    tabs->addTab(m_hvmTab, ks::i18n::sourceText(QStringLiteral("硬件虚拟化证据")));
    // 默认落在「控制」而不是第一页：「跑第三方虚拟机」是给撞上问题的人准备的
    // 出口，不是这一页的主线。主线是三步生命周期，它在「控制」上。
    tabs->setCurrentWidget(controlPanel);
    rootLayout->addWidget(tabs, 1);

    m_pollTimer = new QTimer(this);
    m_pollTimer->setInterval(kStatePollIntervalMilliseconds);
    connect(m_pollTimer, &QTimer::timeout, this, [this]() {
        refreshStateAsync();
    });
}

void HvmDock::testPreparedBackend()
{
    m_hvmTab->testPreparedBackend();
}

void HvmDock::refreshStateAsync()
{
    // 合并并发查询：轮询是周期性的，堆积请求只会拖慢驱动。
    // 命令执行期间同样不查：状态锁被独占，查询只会挂在那里等。
    if (m_queryInFlight || m_operationRunning)
    {
        return;
    }
    m_queryInFlight = true;
    QPointer<HvmDock> safeThis(this);
    std::thread([safeThis]() {
        const ksword::hvm::HvmState state = ksword::hvm::queryState();
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

void HvmDock::applyState(const ksword::hvm::HvmState& state)
{
    m_driverRunning =
        state.availability != ksword::hvm::HvmAvailability::DriverNotRunning;
    m_hardwareAvailable =
        state.availability == ksword::hvm::HvmAvailability::Available ||
        state.availability == ksword::hvm::HvmAvailability::NotPrepared;
    // 资源是否已准备直接读驱动回报的那一位，不再从 availability 反推。
    //
    // 反推在 AMD 上会给出相反的答案：availability 报的是"能不能常驻"，而
    // AMD 后端在准备完成之后照样可能因为别的条件不落在 Available 上——那时
    // 第 2 步的窗口期明明开着，步骤条却还停在第 1 步。resourcesReady 是驱动
    // 对 PREPARE 已执行且未 TEARDOWN 的直接回报，没有这层歧义。
    m_resourcesReady = state.resourcesReady;
    m_selfTestPassed = state.selfTestPassed;
    m_amdBackend = state.backend == KSWORD_ARK_HVM_BACKEND_SVM;
    m_backendKnown = m_amdBackend || state.backend == KSWORD_ARK_HVM_BACKEND_VMX;
    m_residentActive = state.residentActive;
    m_faulted = state.faulted;
    m_availabilityText = state.admissionReason;
    if (!state.configurationReason.isEmpty() && !state.residentActive) { m_hardwareAvailable = false; m_availabilityText = state.configurationReason; }
    m_detailText = state.detail;
    for (QPushButton* button : { m_hookWizardButton, m_viewButton, m_domainButton, m_msrButton, m_crButton, m_processButton })
    {
        button->setVisible(state.backend == KSWORD_ARK_HVM_BACKEND_VMX);
    }
    m_tabs->setTabVisible(m_tabs->indexOf(m_watchPanel), state.backend == KSWORD_ARK_HVM_BACKEND_VMX);
    m_soakButton->setVisible(state.backend == KSWORD_ARK_HVM_BACKEND_VMX);
    m_selfTestButton->setVisible(m_amdBackend);

    m_stepTwoLabel->setText(m_amdBackend ? ks::i18n::sourceText(QStringLiteral("第 2 步 · 全核 SVM 自检"))
        : ks::i18n::sourceText(QStringLiteral("第 2 步 · 安装视图 / 策略 / 域")));
    if (auto* group = qobject_cast<QGroupBox*>(m_selfTestButton->parentWidget()))
    {
        group->setTitle(m_amdBackend ? ks::i18n::sourceText(QStringLiteral("第 2 步 · 自检与内存访问"))
            : ks::i18n::sourceText(QStringLiteral("第 2 步 · 安装（必须在常驻之前）")));
    }
    m_hintLabel->setText(m_amdBackend
        ? ks::i18n::sourceText(QStringLiteral("AMD 使用 SVM/VMCB/NPT。Intel 专属偏好保留但不应用；嵌套模式必须在准备前选择，内层系统启动仍待独立验收。"))
        : ks::i18n::sourceText(QStringLiteral("标题栏 HVM 按钮的右键菜单原样保留，能力与这一页一致；这一页额外把生命周期顺序和每一步的前置条件写出来。")));
    for (QPushButton* button : {m_prepareButton, m_releaseButton})
    {
        if (!button->property("ks_intel_tooltip").isValid()) { button->setProperty("ks_intel_tooltip", button->property("ks_base_tooltip")); }
    }
    m_prepareButton->setProperty("ks_base_tooltip", m_amdBackend
        ? ks::i18n::sourceText(QStringLiteral("准备 AMD SVM/VMCB/NPT 资源，不进入常驻；嵌套模式在此确定，随后执行全核自检。"))
        : m_prepareButton->property("ks_intel_tooltip").toString());
    m_releaseButton->setProperty("ks_base_tooltip", m_amdBackend
        ? ks::i18n::sourceText(QStringLiteral("释放 SVM/VMCB/NPT 资源；更改嵌套模式后必须释放并重新准备。"))
        : m_releaseButton->property("ks_intel_tooltip").toString());
    updateLifecycleView();
}

void HvmDock::updateLifecycleView()
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
    else if (m_resourcesReady && m_amdBackend && m_selfTestPassed)
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
        stateText = ks::i18n::sourceText(QStringLiteral("当前：正在执行一项 HVM 操作，等它结束。"));
    }
    else if (!m_driverRunning)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：KswordARK 驱动未运行。先用标题栏的 R0 按钮启动驱动服务，这一页的入口在那之前都不会生效。"));
    }
    else if (!m_backendKnown)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("还读不到虚拟化后端，请先启动 R0 并刷新。"));
    }
    else if (m_residentActive && m_amdBackend)
    {
        stateText = ks::i18n::sourceText(QStringLiteral("当前：AMD SVM 常驻中。需要更改嵌套模式时，先停止、释放并重新准备；部分常驻或回滚状态也必须先完成停止。"));
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
    else if (m_resourcesReady && m_amdBackend)
    {
        // AMD 第 2 步使用已准备资源做全核 SVM 自检。
        stateText = ks::i18n::sourceText(QStringLiteral("当前：AMD SVM/NPT 资源已准备。全核自检通过后可启动常驻，嵌套配置须与准备时一致。"));
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
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：正在执行另一项 HVM 操作。"));
    const QString residentGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：常驻运行中，这一步只能在未常驻时做。"));
    const QString hardwareGate =
        ks::i18n::sourceText(QStringLiteral("灰掉的原因：当前硬件或系统状态不满足 HVM 常驻条件。"));

    const auto resourceStageReason = [&]() -> QString {
        if (m_operationRunning) { return busyGate; }
        if (!m_driverRunning) { return driverGate; }
        if (m_residentActive) { return residentGate; }
        if (!m_hardwareAvailable) { return hardwareGate; }
        return QString();
    };
    const QString resourceGateReason = resourceStageReason();
    m_selfTestButton->setEnabled(resourceGateReason.isEmpty() && m_resourcesReady);
    setGatedTooltip(m_selfTestButton, resourceGateReason);
    m_prepareButton->setEnabled(resourceGateReason.isEmpty());
    setGatedTooltip(m_prepareButton, resourceGateReason);
    // 释放资源不看硬件门：硬件门回答的是"能不能常驻"，而释放要做的事正好相反
    // ——把已经分配出去的东西收回来。用准备那条门一起判，会让"硬件条件变了、
    // 资源却还挂着"这种状态没有任何出口，只能重启机器。
    const QString releaseReason = m_operationRunning ? busyGate
        : !m_driverRunning ? driverGate
        : m_residentActive ? residentGate
        : !m_backendKnown ? m_availabilityText
        : QString();
    m_releaseButton->setEnabled(releaseReason.isEmpty());
    setGatedTooltip(m_releaseButton, releaseReason);
    // 证据页只读，驱动在就能看。
    const QString evidenceReason = m_operationRunning ? busyGate
        : !m_driverRunning ? driverGate
        : QString();
    m_evidenceButton->setEnabled(evidenceReason.isEmpty());
    setGatedTooltip(m_evidenceButton, evidenceReason);

    // 这八个入口只要驱动在就能打开：里面读得到状态，写得动的动作各自有门。
    // 常驻期间照样能开，否则用户连"现在装了什么"都看不到。
    const QString panelGateReason = !m_driverRunning ? driverGate : !m_backendKnown ? m_availabilityText : QString();
    for (QPushButton* const button :
         { m_hookWizardButton, m_viewButton, m_domainButton, m_msrButton, m_crButton,
           m_memoryButton, m_eventButton, m_processButton })
    {
        button->setEnabled(m_driverRunning && m_backendKnown);
        setGatedTooltip(button, panelGateReason);
    }

    // Intel 专属入口按后端隐藏；内存操作与事件流继续使用通用接口。
    if (m_amdBackend)
    {
        const QString amdGate = ks::i18n::sourceText(QStringLiteral("灰掉的原因：这一项建立在 EPT 分离视图或 VMCS 字段上，当前的 AMD SVM/NPT 后端还没有对应实现。AMD 上可用的是资源准备、逐核自检与常驻。"));
        for (QPushButton* const button :
             { m_hookWizardButton, m_viewButton, m_domainButton, m_msrButton,
               m_crButton, m_processButton })
        {
            button->setEnabled(false);
            setGatedTooltip(button, amdGate);
        }
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
    m_soakButton->setEnabled(!m_amdBackend && soakReason.isEmpty());
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

void HvmDock::requestAction(const Action action)
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
