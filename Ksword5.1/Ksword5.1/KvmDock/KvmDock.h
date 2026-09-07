#pragma once

// KvmDock：KSwordVM（R-1 / hypervisor 层）的顶层功能页。
//
// 存在的理由不是"给 VT-x/EPT 页换个位置"。这套能力此前被劈成互不相通的两半：
// - 标题栏 KVM 按钮的右键菜单：常驻起停、保持自检、准备/释放资源，加视图 /
//   内存 / MSR / CR / 域 / 事件六个 R-1 面板；
// - KernelDock 的「VT-x/EPT」页：PREPARE、SELF_TEST、一次性来宾、TEARDOWN，
//   以及 EPT 规则（EPT 规则只有这一条路可达）。
// 两边零交叉引用，于是有一条必然踩中的死路：视图 / MSR / CR / 域四个面板都
// 要求"资源已准备且未常驻"，而右键菜单里唯一能做的「启动常驻」会在同一次
// 调用里准备完资源紧接着进入常驻 —— 四个面板直接从「尚未准备」跳到「常驻
// 期间不能改」，中间那个唯一可用的窗口期在 UI 里按不出来。
//
// 因此这一页做三件事：
// - 把两半的入口收进同一屏（右键菜单原样保留，老用户的肌肉记忆不动）；
// - 把生命周期顺序画出来：准备资源 → 装视图 / 策略 / 域 → 启动常驻；
// - 每个按钮灰掉时说明它在等哪一步，而不是只给一个灰按钮。
//
// 业务逻辑一行都不在这里：控制命令原样落到 MainWindow.Kvm.cpp 里右键菜单
// 用的同一批实现（含 confirmDestructiveAction 高危确认），状态读取走
// ksword::kvm 门面。这一页只负责把顺序和前置条件画出来。

#include <QString>
#include <QWidget>

#include <functional>

class QHideEvent;
class QLabel;
class QPushButton;
class QShowEvent;
class QTimer;

class KernelHvmTab;

namespace ksword::kvm
{
    struct KvmState;
}

class KvmDock final : public QWidget
{
public:
    // Action：这一页能发出的全部请求，一条不落地对应右键菜单里的一项。
    enum class Action
    {
        ToggleResident,
        Soak,
        PrepareResources,
        ReleaseResources,
        ResetFault,
        OpenHookWizard,
        OpenViewDialog,
        OpenDomainDialog,
        OpenMsrPolicyDialog,
        OpenCrPolicyDialog,
        OpenMemoryDialog,
        OpenEventDialog
    };

    // ActionHandler：请求的唯一出口。
    //
    // 用 std::function 而不是信号槽，是为了让这个类和它承载的 KernelHvmTab
    // 一样不带 Q_OBJECT——省掉 vcxproj 里的 QtMoc 登记这一个只在运行期
    // 才会暴露的接入点。KernelKnowledgeTab::setRouteHandler 是本仓库里
    // 同样形状的既有做法。
    using ActionHandler = std::function<void(Action)>;

    explicit KvmDock(QWidget* parent = nullptr);
    ~KvmDock() override = default;

    void setActionHandler(ActionHandler handler);

    // setOperationRunning：控制命令执行期间禁用本页全部入口。
    //
    // 这件事本页的状态轮询看不到：命令期间驱动侧状态锁被独占，查询要排在
    // 它后面才返回。只能由发起命令的那一侧（MainWindow）告诉它。
    void setOperationRunning(bool running);

    // refreshStateAsync：后台线程读一次状态快照。
    // queryState 是阻塞 IOCTL，绝不能在 UI 线程直接调用。
    void refreshStateAsync();

protected:
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private:
    void initializeUi();
    void applyState(const ksword::kvm::KvmState& state);
    void updateLifecycleView();
    void requestAction(Action action);

    ActionHandler m_actionHandler;
    QTimer* m_pollTimer = nullptr;

    // 只留派生位而不是整个 KvmState：把 KvmControl.h 拖进本头文件，
    // 等于把 ArkDriverClient 的包含链带进 MainWindow.h。
    bool m_driverRunning = false;      // 驱动服务在跑（availability != DriverNotRunning）。
    bool m_hardwareAvailable = false;  // 硬件门通过（Available 或 NotPrepared）。
    bool m_resourcesReady = false;     // 资源已准备，即第 2 步的窗口期已打开。
    bool m_residentActive = false;     // 至少一个逻辑处理器处于 VMX non-root。
    bool m_faulted = false;            // 存在故障或待回滚，必须先重置。
    bool m_operationRunning = false;   // 由 MainWindow 推进来的命令执行中标志。
    bool m_queryInFlight = false;      // 合并并发轮询，避免请求在驱动侧堆积。
    QString m_availabilityText;        // 不可用时的原因，直接来自门面。
    QString m_detailText;              // 快照详情，与标题栏按钮 tooltip 同源。

    QLabel* m_hintLabel = nullptr;
    QLabel* m_stepOneLabel = nullptr;
    QLabel* m_stepTwoLabel = nullptr;
    QLabel* m_stepThreeLabel = nullptr;
    QLabel* m_stateLabel = nullptr;
    QLabel* m_detailLabel = nullptr;

    QPushButton* m_prepareButton = nullptr;
    QPushButton* m_releaseButton = nullptr;
    QPushButton* m_hookWizardButton = nullptr;
    QPushButton* m_viewButton = nullptr;
    QPushButton* m_domainButton = nullptr;
    QPushButton* m_msrButton = nullptr;
    QPushButton* m_crButton = nullptr;
    QPushButton* m_memoryButton = nullptr;
    QPushButton* m_eventButton = nullptr;
    QPushButton* m_residentButton = nullptr;
    QPushButton* m_soakButton = nullptr;
    QPushButton* m_resetFaultButton = nullptr;

    KernelHvmTab* m_hvmTab = nullptr;
};
