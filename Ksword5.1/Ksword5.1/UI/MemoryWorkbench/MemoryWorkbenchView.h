#pragma once

// ============================================================
// MemoryWorkbenchView.h
// 作用：
// - 内存工作台的顶层视图（见 ux.md §1 布局、docs/内存工作台Phase3集成设计.md §1 导航
//   路径 N1-N4）：会话条｜地址条｜子页签（十六进制/反汇编/文本/对比）｜侧栏（地址簿/
//   int3 补丁）｜状态条，装配全部其它五个类并对外提供 MemoryDock 需要的入口
//   （openAt/onDockAttached 等）。
// - 每个 MemoryDock 实例（含每个 ProcessDetailWindow 的内嵌 Dock）各创建一个本类
//   实例；本类构造时创建**仅属于自己**的 WorkbenchTarget/WorkbenchPageProvider/
//   WorkbenchBaselineFeeder/WorkbenchWriteController/WorkbenchHexPane 五个对象
//   （均为本类的子对象或 unique_ptr 成员），只有地址簿存储/模型与 int3 控制器取自
//   WorkbenchShared::Instance() 的共享单例（非拥有指针）。
// - 本类不直接碰 Win32/驱动/Zydis：反汇编/汇编后端、指针命名器等重依赖通过回调
//   注入点传入（见 setDisasmBackends/setPointerNamer），真正的生产实现在 MemoryDock
//   侧（工作包 K）组装并调用这些 setter，本类自己不 #include 任何重依赖头文件。
// ------------------------------------------------------------
// 创建/销毁顺序
// ------------------------------------------------------------
// - 构造顺序（均在构造函数体或成员初始化列表内完成，见 .cpp）：
//   WorkbenchTarget → WorkbenchConfirmations → WorkbenchPageProvider →
//   WorkbenchBaselineFeeder → WorkbenchWriteController → WorkbenchHexPane
//   （创建时机取 overlay()，随后把前四者注入 HexPane）→ 反汇编/文本/对比三个子页
//   （各自的 IWorkbenchBytesProvider 适配器包装 HexPane::overlay()）→ 会话条/地址条/
//   侧栏/状态条 → WorkbenchActions 挂快捷键。
// - 析构安全性依赖的不是成员声明顺序，而是 C++ 的一条通用规则：派生类自己的非
//   静态成员（pageProvider_/baselineFeeder_/writeController_ 等 unique_ptr）会在
//   ~MemoryWorkbenchView() 函数体之后、**基类（QWidget/QObject）析构之前**按声明
//   逆序销毁；而 hexPane_/disasmView_/textView_/compareView_ 这些 Qt 子控件的删除
//   发生在基类 QObject 的析构阶段（parent-child 自动删除），天然晚于前者。因此
//   pageProvider_/baselineFeeder_/writeController_ 析构时，hexPane_ 持有的 overlay
//   仍然有效，不存在悬空——这个安全性与这几个 unique_ptr 成员相对彼此的声明顺序
//   无关，但它们各自内部如果互相持有对方的非拥有指针，仍需要调用方（本类的
//   析构函数体，而不是依赖隐式顺序）显式先置空引用。

// ============================================================

#include "WorkbenchConfirmations.h"
#include "WorkbenchDisasmView.h"
#include "WorkbenchHexPane.h"
#include "WorkbenchNavigation.h"
#include "WorkbenchTarget.h"

#include "../ThemeStatusRole.h"

#include "../../../../shared/evidence/memory_workbench/MemoryAddressBook.h"
#include "../../../../shared/evidence/memory_workbench/MemoryChannelGate.h"
#include "../../../../shared/evidence/memory_workbench/MemoryWriteTransaction.h"
#include "../../../../shared/evidence/memory_workbench/PointerChainBindings.h"

#include <QByteArray>
#include <QList>
#include <QPointer>
#include <QSize>
#include <QString>
#include <QWidget>

#include <array>
#include <cstdint>
#include <atomic>
#include <functional>
#include <memory>
#include <map>
#include <optional>
#include <string>
#include <vector>

class QCheckBox;
class QLineEdit;
class QMenu;
class QEvent;
class QResizeEvent;
class QShowEvent;
class QStackedWidget;
class QSplitter;
class QTimer;
class QToolButton;
class QVBoxLayout;

namespace ksword::memwb
{
    class IPointerNamer;
}

namespace ks::ui
{
    // Int3LeaveScenario：定义在 Int3Controller.h（默认底层类型 int），这里只需要不透明声明。
    enum class Int3LeaveScenario;

    class AddressBookPanel;
    class HexViewGlyphButton;
    class HexViewSegmented;
    class Int3PatchPanel;
    class WorkbenchBaselineFeeder;
    class WorkbenchCompareView;
    class WorkbenchConfirmations;
    class WorkbenchPageProvider;
    class WorkbenchSessionBar;
    class WorkbenchStatusBar;
    class WorkbenchTextView;
    class WorkbenchPseudocodeView;
    class WorkbenchWriteController;

    // AttachedProcessDisplayInfo：实现期发现的接口缺口（本任务书未点名，按§8.0同类
    // 注入点的方式补齐，记在报告"接口缺口"一节）——WorkbenchTarget 只持有会话的
    // pid/创建时间等纯身份字段，不持有"进程名"与"当前是否可读写"这两个纯展示性
    // 提示（旧代码里它们来自 Dock 的 m_attachedProcessName/m_canReadWriteMemory，
    // target.md 1.1 明确写的是"Dock 侧状态"，不属于 WorkbenchTarget 的职责）。
    // 会话条目标 chip 与确认框正文都需要这两个字段拼人话描述，本视图自己拿不到，
    // 由宿主经 setAttachedProcessInfoProvider 按当前 pid 查询后喂入。
    struct AttachedProcessDisplayInfo
    {
        QString processName;
        bool canReadWrite = false;
    };

    // WorkbenchProtectionInfo：装配接口文档 §8.0 审阅时新增的注入点
    // setProtectionProvider 的返回值——状态条"保护"段（ux.md §5 第③段，RWX 红/X
    // 橙/RW 绿）展示数据。本视图不直接查询页保护属性（那需要驱动/Win32），由宿主
    // 按当前插入点算好后经回调喂入；未注入或回调返回空时该段不显示。
    struct WorkbenchProtectionInfo
    {
        // text：展示文字，例如 "RWX"。
        QString text;
        // role：配色语义，参见 ThemeStatusRole.h。
        StatusRole role = StatusRole::Idle;
    };

    // SessionChangeHandling：onSessionChanged(mask) 的两种处理路径，供文档与测试
    // 核对调用了哪一条，不是公开的业务枚举。
    enum class SessionChangeHandling
    {
        // Identity：掩码含身份位（IsIdentityChange）——清 overlay 与撤销历史、
        // canvas_->setAddressSpace、provider 换代（resetScratchLatch/cancelAllInFlight）、
        // 重新枚举模块、重新选取基线窗口。
        Identity,
        // ReloadOnly：掩码恰为 Reload——只做"软重读"：canvas_->refresh() 之外的
        // 原位重读（见数据流 R4），不清空补丁与撤销历史。
        ReloadOnly,
    };

    // MemoryWorkbenchView：工作台顶层视图，详见文件头。全部公开函数只在 UI 线程
    // 调用。
    class MemoryWorkbenchView final : public QWidget
    {
        Q_OBJECT

    public:
        explicit MemoryWorkbenchView(QWidget* parent = nullptr);
        ~MemoryWorkbenchView() override;

        // target：本视图私有的目标持有者（非共享，每个视图一份）。供 MemoryDock 的
        // 三个钩子（onDockAttached/onDockAboutToDetach/onDockDetached）转发调用。
        WorkbenchTarget& target() noexcept;

        // setEmbeddedProcessMode：内嵌进程详情窗口调用（ux.md"线程"一节/
        // target.md §6）。作用：target().setPolicy({lockToDock=true,
        // allowKernelPhysical=false})、隐藏侧栏与钉住输入框、范围锁定为进程。
        void setEmbeddedProcessMode(bool embedded);

        // setMemoryDebugMode：在 loadSettings 后配置独立进程内存调试页。
        // enabled=true 时恒为进程范围、初始 R3、忽略 Dock 跟随并隐藏 int3 工具。
        // 本接口不建立 Windows 调试会话；上层通过 target().requestPin 选择进程。
        // 返回 false：内嵌模式冲突、离开守卫拒绝或视图在守卫期间被销毁。
        bool setMemoryDebugMode(bool enabled);
        // isMemoryDebugMode：查询当前是否使用独立进程内存调试策略。
        bool isMemoryDebugMode() const noexcept;
        // clearMemoryDebugTarget：关闭独立内存会话；取消保留目标和待写补丁。
        bool clearMemoryDebugTarget();

        // showDisassemblyAt：在当前目标地址定位 HEX 基线，再显式显示同址反汇编。
        // 传入 address：当前目标的虚拟地址；返回正式导航结果，不创建或附加调试器。
        NavStatus showDisassemblyAt(std::uint64_t address);

        // showPseudocodeAt：统一 C 页定位并显式分析当前地址，沿用当前目标身份。
        NavStatus showPseudocodeAt(std::uint64_t address);

        // openAt：统一跳转入口（N1-N4），对应
        // `bool MemoryDock::navigateWorkbench(const NavRequest&)` 的真正落地实现
        // （Dock 侧只做"确保视图存在/切页签/翻译状态"，具体导航全部在这里）。
        // 流程：身份是否变化 → 变化则经 target().requestIdentity 一次性问离开守卫
        // （N2，一次合并）；被拒绝返回 LeaveRefused；地址求值（target().evaluate）→
        // suggestScope 非空且与当前范围不同 → NeedsScopeSwitch（不静默切换，N4）；
        // 落在地址空间外 → Unavailable；否则 hexPane 跳转、按 request.focusView
        // 决定是否切到前台页签，返回 Ok。
        NavStatus openAt(const NavRequest& request);

        // setDisasmBackends：注入反汇编/汇编后端（见 WorkbenchDisasmView.h 的
        // DecodeOneFn/AssembleOneFn）。生产实现（WP-K）应传入包装
        // ks::ui::InstructionDecoder::decode 与 ks::ui::InstructionAssembler::assemble
        // 的闭包；不调用则反汇编页显示"未设置解码/汇编后端"。
        void setDisasmBackends(DecodeOneFn decodeBackend, AssembleOneFn assembleBackend);

        // setPointerNamer：注入解释器面板的指针描述器（非拥有，生命周期由调用方
        // 保证长于本视图或先传空）。
        void setPointerNamer(ksword::memwb::IPointerNamer* namer);

        // loadSettings / saveSettings：对应 ux.md §9 的持久化键表。loadSettings 在
        // 构造完成后由装配层调用一次（所有视图都读）；saveSettings 只有"权威"视图才真正
        // 写盘（已拍板：主 Dock 的那个非内嵌视图是权威，内嵌窗口永不落盘，避免多开时
        // 落盘顺序不确定、旧记忆覆盖新选择）。
        void loadSettings();
        void saveSettings() const;

        // setSettingsAuthoritative / isSettingsAuthoritative：是否权威视图。默认 false
        // （安全默认：忘记设置只会少落盘，不会乱落盘）；MemoryDock 创建主视图时设为
        // true。非权威视图的 saveSettings() 是空操作。
        void setSettingsAuthoritative(bool authoritative);
        bool isSettingsAuthoritative() const noexcept;

        // requestLeave：对外暴露 target().requestLeave 的薄包装，供
        // confirmDiscardMemoryEditsForProcessChange 等旧集成点直接调用（target.md
        // §2.2）。
        bool requestLeave(LeaveReason reason);

        // confirmQuit：主窗口关闭前的最后一次询问（MemoryDock::confirmWorkbenchQuit 经
        // MainWindow::closeEvent 最前调用——关闭路径的后半段会停 R0 驱动，守卫晚了 int3 还原必失败）。
        // 与离开守卫共用同一条三阶段原子逻辑（见 runLeaveSequence）：暂存里有未提交补丁时先问
        // "应用并离开/丢弃并离开/取消"，再问 int3 账本里当前目标未还原的补丁（全部还原后继续/
        // 保留补丁继续/取消），两个都同意之后才真正应用或丢弃暂存。
        // 传出：true=可以继续退出；false=用户取消（或应用失败），此时暂存与 int3 都原封不动。
        // 无暂存、无未还原 int3 时不弹任何框，直接返回 true。只在 UI 线程调用。
        bool confirmQuit();

        // 多窗口退出被其他窗口取消时，撤回仅供这次关闭使用的保留补丁许可。
        void cancelQuitPreparation();

        // focusAddress：十六进制子页当前的插入点地址，供旧页面取"用户正在看哪里"当默认值
        // （例如 PTE 页的默认地址）。没有可用目标（进程范围且未附加）或画布无数据时返回空，
        // 调用方应回退到自己的默认。只读，不改变任何状态。
        std::optional<std::uint64_t> focusAddress() const;

        // ---- 装配接口文档 §8.0 审阅时补的三个注入点（新增，不改既有签名）----

        // setGateInputsProvider：Gate 可用性判定所需的运行期输入（驱动是否已加载、
        // HVM/DDMA 是否可用等），由宿主 Dock 按真实环境探测后喂入；未注入时按
        // "全部最保守"处理（EvaluateChannel 收到默认 GateInputs 全部 false），与
        // WorkbenchPageProvider 未注入 GateInputsProvider 时的保守默认一致，绝不
        // 因为缺省而误判成可用。本视图把它同时转发给 pageProvider_
        // （setGateInputsProvider）与自己的会话条可用性刷新（setChannelVerdicts）。
        void setGateInputsProvider(std::function<ksword::memwb::GateInputs()> provider);

        // setProtectionProvider：状态条"保护"段的数据来源（见
        // WorkbenchProtectionInfo），由宿主按当前插入点查询页保护属性后喂入；未
        // 注入或某次调用返回 std::nullopt 时该段不显示。
        void setProtectionProvider(
            std::function<std::optional<WorkbenchProtectionInfo>(std::uint64_t address)> provider);

        // setGlobalSkipDangerousConfirmProvider：MemoryWritePolicy::Decide 需要的
        // "全局跳过危险确认"开关当前值（设置对话框里的勾选项），由宿主喂入；未
        // 注入时恒为 false（默认仍然确认，不默认跳过风险操作，安全默认）。
        void setGlobalSkipDangerousConfirmProvider(std::function<bool()> provider);

        // setAttachedProcessInfoProvider：见 AttachedProcessDisplayInfo 的注释——
        // 补齐"进程名/可读写"两个纯展示字段的来源；未注入或返回空时目标 chip 只
        // 显示 pid，不显示进程名，canReadWrite 按保守值（false）展示。
        void setAttachedProcessInfoProvider(
            std::function<std::optional<AttachedProcessDisplayInfo>(std::uint32_t pid)> provider);

        // InstallConfirmPrompterFactoryForTest（仅供夹具白盒测试，命名仿既有的
        // FinalizePendingStageForTest 惯例）：WorkbenchConfirmations 默认用真实
        // QMessageBox 弹确认框，离屏自动化测试里弹出真实模态框会卡死整个进程。
        // 本静态钩子设置后，**下一次**构造 MemoryWorkbenchView 会消费它产出的
        // IConfirmPrompter 来构造 confirmations_（而不是默认实现），消费后立即
        // 清空，不影响后续任何构造；生产装配从不调用本方法。必须在
        // `new MemoryWorkbenchView(...)` 之前设置。
        static void InstallConfirmPrompterFactoryForTest(
            std::function<std::unique_ptr<IConfirmPrompter>()> factory);

        // ---- 以下访问器仅供夹具白盒测试与诊断查询使用（命名与既有组件
        // "供夹具与宿主做诊断查询，不对外转移所有权"的惯例一致，例如
        // WorkbenchDisasmView::table()/model()）。生产装配（WP-K）不应依赖它们
        // 驱动业务逻辑——业务入口始终是 openAt/target()/setDisasmBackends 等
        // 已有的公开方法，这些访问器只读不改变任何契约。----
        WorkbenchHexPane* hexPaneForTest() const noexcept;
        WorkbenchSessionBar* sessionBarForTest() const noexcept;
        WorkbenchStatusBar* statusBarForTest() const noexcept;
        WorkbenchWriteController* writeControllerForTest() const noexcept;
        AddressBookPanel* addressBookPanelForTest() const noexcept;
        Int3PatchPanel* int3PanelForTest() const noexcept;
        QSplitter* mainSplitterForTest() const noexcept;
        QToolButton* rerouteButtonForTest() const noexcept;
        QToolButton* backButtonForTest() const noexcept;
        QToolButton* forwardButtonForTest() const noexcept;
        QStackedWidget* subTabStackForTest() const noexcept;
        const std::vector<std::uint64_t>& backStackForTest() const noexcept;
        const std::vector<std::uint64_t>& forwardStackForTest() const noexcept;

        // minimumSizeHint（修复缺陷 1，根因）：不把 mainSplitter_ 两个子控件
        // （subTabStack_/sidebarContainer_）此刻的尺寸偏好向外传播——与
        // WorkbenchHexPane::minimumSizeHint 同一处理方式（见该函数注释），
        // 理由也相同：窄窗口下内容靠画布自身横向滚动与侧栏自动折叠承担，不应该
        // 让宿主（例如把本视图安置进自己布局的 Dock）因为本类内部某个控件的
        // 尺寸偏好被钉在一个拖不动的下限上。真正阻止"本类自己被 resize() 到
        // 更窄"的是 buildUi() 里把 root 切成 QLayout::SetNoConstraint（见该函数
        // 注释）——两处分别处理"本类查询谁"与"本类自己被谁查询"两个方向。
        QSize minimumSizeHint() const override;

    signals:
        // statusMessage：状态条摘要文本变化（供 MainWindow 全局状态栏等可选订阅）。
        void statusMessage(const QString& text);
        // navigationRefused：openAt 返回非 Ok 时发出，携带原因，供 Dock 侧决定是否
        // 需要额外提示（例如 NeedsAttach 时聚焦进程选择框）。
        void navigationRefused(NavStatus status);
        // pickTargetRequested：用户点击会话条目标 chip 的"在 Dock 附加…"（或未附加进程时
        // 点 chip），请求宿主 Dock 聚焦进程选择。本视图不碰 Dock 的下拉框，只发信号。
        void pickTargetRequested();
        // writeFailureText：每次写入失败（CommitReport 的 outcome 既非 Committed 也非
        // NoChange，且 failureText 非空）发出一次，携带通道给出的失败原文。**本视图自己
        // 不弹任何提权框、也不判断是不是权限问题**：宿主 Dock 把文本交给既有的
        // ks::ui::promptForPrivilegeFailure(parent, 功能名, 文本)（Framework/
        // PrivilegeElevationPrompt.h，它自己按"拒绝访问/error=5/0x80070005…"文本判据，且
        // 已提权时返回 false），返回 true 才说明已经弹了提权提示。没有连接处理者时什么都
        // 不会发生——失败照常进状态条与诊断抽屉（连续编辑不能弹窗风暴）。
        void writeFailureText(const QString& failureText);

    protected:
        // resizeEvent（修复缺陷 1）：每次尺寸变化都重新同步几件事——①会话条
        // 换行后的真实高度（updateSessionBarHeightForWidth）；②侧栏可见性
        // （maybeAutoCollapseSidebar）；③解释器面板是否应当自动隐藏；④还没落地的偏好
        // 侧栏宽度（applySidebarWidthIfPossible）。都是"主动量一次、手动应用结果"。
        void resizeEvent(QResizeEvent* event) override;

        // showEvent / changeEvent：把"本视图的会话"重新声明为 int3 账本的当前目标。账本全进程
        // 只有一份当前目标，主 Dock 的视图与内嵌进程详情窗口的视图共用它；视图被切到前台、
        // 窗口被激活时重新声明一次，面板上的"写入/还原"才会作用在用户眼前这个目标上。
        void showEvent(QShowEvent* event) override;
        void changeEvent(QEvent* event) override;

    private slots:
        // onTargetSessionChanged：WorkbenchTarget::sessionChanged 的槛，按
        // IsIdentityChange(mask) 分派到 handleIdentityChange/handleReloadOnly
        // （SessionChangeHandling 两条路径）。
        void onTargetSessionChanged(quint32 changeMask);
        // onTargetAboutToDetach：int3 未经提示路径的安全网（设计文档 §0 第 6 条），
        // 仅当 Int3Controller::HasUnrestoredForCurrentTarget() 为真时才在这里强制
        // RestoreAll（不弹框——真正的提示在 requestLeave 路径上，这里只是兜底）。
        void onTargetAboutToDetach();
        // onWriteControllerCommitFinished：刷新状态条"写入结果"段与会话条待写入区。
        void onWriteControllerCommitFinished();
        // onSessionBarPickTargetRequested：转发给 Dock（经信号出口，本类不直接碰
        // Dock 的下拉框）。
        void onSessionBarPickTargetRequested();

    private:
        // buildUi：搭建会话条/地址条/子页签/侧栏/状态条的布局；构造函数调用一次。
        void buildUi();

        // wireActions：对 WorkbenchActionId 枚举的每一项调用
        // ks::ui::CreateWorkbenchShortcut（Redo 额外调用
        // CreateWorkbenchAlternateShortcut，见 WorkbenchActions.h）并连接到对应槛；
        // WorkbenchActions.h 本身只是一组自由函数+数据表，不是需要持有的对象，本类
        // 不保存返回的 QShortcut*（生命周期由 Qt 的父子关系管理，父对象为 this）。
        void wireActions();

        // installLeaveGuard：组合离开守卫并注册给 target()（N2）。组合内容：
        // ① writeController_ 是否有未提交的暂存补丁（PendingOverlayGuard 语义，
        //    有则按 D1 弹三选一）；② int3Controller（取自 WorkbenchShared）的
        // HasUnrestoredForCurrentTarget，有则调用 Int3Controller::RequestLeave。
        // 两者都通过才放行；具体弹框顺序与"只问一次"的落实细节见装配接口文档 §4
        // 不变式 2/11。
        void installLeaveGuard();

        // runLeaveSequence：离开守卫（installLeaveGuard 注册的回调）与 confirmQuit 共用的三阶段
        // 原子逻辑。传入：reasonText 拼进"有未提交修改"确认框正文的原因短句；scenario 传给 int3
        // 退出提示的场景。传出：true=可以离开/退出；false=用户取消或应用失败（暂存与 int3 不动）。
        bool runLeaveSequence(const QString& reasonText, Int3LeaveScenario scenario);

        // applyInt3Context / syncInt3Context：把会话声明为 int3 账本的当前目标（内容一致时不重复写，
        // 免得面板无谓重建）；前者收已取得的会话引用，后者自己取 target_->session()。
        // 见 MemoryWorkbenchView.Session.cpp 的实现注释。
        void applyInt3Context(const ksword::memwb::MemoryTargetSession& session);
        void syncInt3Context();

        // handleIdentityChange / handleReloadOnly：onTargetSessionChanged 的两条分支
        // 实现，对应 SessionChangeHandling。
        void handleIdentityChange(quint32 changeMask);
        void handleReloadOnly();

        // currentBytesProvider：返回当前可以喂给反汇编/文本/对比三个子页的
        // IWorkbenchBytesProvider 适配器（包装 hexPane_.overlay()，定义在 .cpp）。
        IWorkbenchBytesProvider* currentBytesProvider();

        // ensureBytesProviderAdapter：构造并赋给 bytesProviderAdapter_（若尚未
        // 构造）。定义在 MemoryWorkbenchView.cpp（唯一能看到该嵌套类完整定义的
        // 文件）——unique_ptr<DisasmBytesProviderAdapter> 的赋值/析构都需要完整
        // 类型，这一步必须发生在那个翻译单元里；buildUi()（定义在 .Ui.cpp，
        // 看不到该类型的完整定义）只调用这个函数，不直接触碰
        // bytesProviderAdapter_ 这个成员本身。前置声明提前到这里（下方"三个
        // 只读子页"一节还有一份，类内重复前置声明是合法的）。
        class DisasmBytesProviderAdapter;
        void ensureBytesProviderAdapter();

        // ---- 以下为本实现新增的私有方法，仅用于把构造期接线与各信号处理函数拆成
        // 可读的小块；均不出现在类的公开契约里，不影响 MemoryDock（WP-K）与本类的
        // 既有交互方式。按职责分散在 MemoryWorkbenchView.cpp /.Ui.cpp /.Session.cpp /
        // .Nav.cpp 四个文件（见各自文件头的分工说明）----

        // connectPipelineSignals：buildUi 之后调用一次，把 pageProvider_/
        // baselineFeeder_/writeController_ 的信号接到状态条与本类自己的收尾逻辑。
        void connectPipelineSignals();
        // connectPanelSignals：把会话条/地址条/地址簿/int3 面板/十六进制子页/
        // 三个只读子页的信号接到对应处理函数。
        void connectPanelSignals();

        // ---- 会话条请求 → 裁决 → 回写（§3 信号表）----
        void onSessionBarScopeRequested(ksword::memwb::Scope scope);
        void onSessionBarChannelRequested(ksword::memwb::Channel channel);
        void onSessionBarModeRequested(ksword::memwb::WriteMode mode);
        void onSessionBarApplyRequested();
        void onSessionBarDiscardRequested();

        // ---- 地址簿/int3 面板转发 ----
        void onAddressBookValueEditRequested(quint64 id, ksword::memwb::ValueType valueType, const QString& text);
        void onAddressBookJumpRequested(quint64 id);
        void onAddressBookOpenDisassemblyRequested(quint64 id);
        void onAddressBookPromoteRequested(quint64 id, ksword::memwb::EntryKind newKind);
        void onAddressBookRemoveRequested(const QList<quint64>& ids);
        void onPointerChainCreateRequested();
        void onPointerChainEditRequested(quint64 id);
        void onPointerChainResolveRequested(quint64 id);
        void showPointerChainEditor(std::uint64_t id);
        void resolvePointerChain(std::uint64_t id, bool navigate, bool disassembly = false);
        void cancelPointerChainResolution();
        void leavePointerChainNavigation();
        bool validatePointerChainWrite(const ksword::memwb::MemoryTargetSession& session,
            std::uint64_t address, std::uint64_t length, std::string& reason);
        void onInt3ResultMessage(const QString& text, bool isError);

        // ---- 十六进制子页与只读子页转发 ----
        void onHexPaneInsertionPointChanged(quint64 address);
        void onHexPaneEditRejected(const QString& reason);
        void onHexPaneContextMenuAboutToShow(QMenu* menu, quint64 address, bool hasByte);
        void onDisasmStageRequested(quint64 address, QByteArray bytes);
        void onDisasmRequestHexLocate(quint64 address);

        // onToggleInt3AtAddress（修复缺陷 2）：右键"写入/还原此处 int3"的真正执行
        // 函数——按当前目标在该地址是否已有待还原条目二选一（Install/Restore），
        // 结果经 onInt3ResultMessage 走状态条，不再像原实现那样永远只调用
        // Install、结果被直接丢弃。
        void onToggleInt3AtAddress(quint64 address);

        // ---- 写入反馈（W4，§6）----
        void onWriteControllerCommitFailed(const ksword::memwb::CommitReport& report);
        void onWriteControllerScratchAreaDirtyReported();
        void onWriteControllerPendingPatchesChanged(quint64 bytesPending, quint64 blocksPending);
        void onWriteControllerCommitRejectedBusy(const QString& source);
        void updateUndoRedoActionsEnabled();

        // ---- 读反馈与 Gate（§7）----
        void onProviderChannelUnavailable(const ksword::memwb::GateVerdict& verdict);
        void onProviderReadFailed(quint64 sourceRevision, const QString& failureText, int failedRangeCount);
        void onProviderScratchAreaDirtyLatched();
        void onProviderRetryBlockedByLatch(quint64 sourceRevision);
        void onProviderJobLanded();
        void refreshChannelGateDisplay();
        void refreshStatusBarChannelScopeText();
        void refreshProtectionDisplay();

        // ---- 导航与地址条（.Nav.cpp）----
        void onAddressBarReturnPressed();
        void onGoBackRequested();
        void onGoForwardRequested();
        void onRerouteButtonClicked();
        void applyNavOutcome(const NavRequest& request, NavStatus status);
        void pushBackStackEntry(std::uint64_t address);

        // ---- 地址簿去重新增条目（G4）----
        void addInsertionPointToAddressBook(std::uint64_t address);
        std::string currentAddressBookTargetKey() const;

        // ---- 确认策略刷新（每次会话/模式变化调用一次）----
        void refreshConfirmationsAndSuppression();

        // refreshTargetDisplays：用 attachedProcessInfoProvider_ 查到的"进程名/
        // 可读写"两个展示字段，同时刷新会话条目标 chip（setTargetInfo）与确认框
        // 正文描述（confirmations_->SetTargetDescription）——装配接口文档 §6 B2
        // 要求两处共用同一份数据源但不共用控件状态，因此各自独立拼一次文本。
        void refreshTargetDisplays();

        // ---- 修复缺陷 1：窄窗口会话条高度与侧栏可见性 ----

        // updateSessionBarHeightForWidth：按会话条当前宽度直接问它自己的顶层
        // 布局（FlowLayout）要多高，再显式 setMinimumHeight 上去。
        // 【2026-10 第二轮复核更正】早先注释把"改了 sizePolicy 也没用、wide=narrow=36"
        // 归因于 Qt 的 heightForWidth 委托链不可靠，这个因果是错的：当时窗口被钉在约
        // 628px 的硬性最小宽度上，根本没有缩窄，所以高度恒为 36。把本函数与
        // sessionBar_ 的 setHeightForWidth(true) 一起撤掉，完整夹具套件照样全绿——
        // 两处在当前夹具模型下没有可观测效果。保留它们只是为了让"以 heightForWidth
        // 协议查询"的宿主在会话条换行时拿到正确高度；没有读数要求就不删（删除同样
        // 没有读数支持）。
        void updateSessionBarHeightForWidth();

        // maybeAutoCollapseSidebar：侧栏可见性的唯一裁决入口（名字沿用，语义已扩展）。
        // 规则：内嵌模式恒隐藏；否则 显示 = 用户想要可见(sidebarWantedVisible_) 且
        // (用户手动决定过 sidebarUserOverride_ 或 窗口宽度 >= kSidebarAutoCollapseWidth)。
        // 因此窄窗口只会"折叠一个想要可见的侧栏"，绝不会把"默认/已存为隐藏"或"用户
        // 手动收起"的侧栏在宽屏下重新放出来（第二轮复核 B1）。侧栏隐藏时
        // sidebarExpandButton_ 是唯一的展开入口（内嵌模式除外）。
        void maybeAutoCollapseSidebar();

        // updateSidebarWidthCap：窄宽度（< kSidebarAutoCollapseWidth）下侧栏只会因为用户手动展开而
        // 可见，此时按"主体至少拿到 min(kMinMainBodyWidth, 可用宽度/2)"给侧栏设宽度上限，避免侧栏的
        // 内容最小宽度（约 244px）把十六进制画布挤到 1px；宽屏或侧栏隐藏时不设上限
        // （QWIDGETSIZE_MAX）。上限解除时复位 sidebarWidthApplied_，让侧栏回到偏好宽度。
        // 由 maybeAutoCollapseSidebar 末尾调用（resizeEvent/手动切换/内嵌切换/加载设置都经过它）。
        void updateSidebarWidthCap();

        // applySidebarWidthIfPossible：把偏好侧栏宽度（sidebarPreferredWidth_）落到
        // 分割条上。只在侧栏可见、分割条已有真实宽度（装得下偏好宽度 + 最小主体宽度）
        // 时执行一次（sidebarWidthApplied_ 置真）；否则什么都不做，等后面的
        // resizeEvent 再试。loadSettings 通常在 show 之前调用，那时分割条还是默认
        // 的小宽度，直接 setSizes 会把全部宽度分给侧栏、画布 0px（第二轮复核 B1）。
        void applySidebarWidthIfPossible();

        // refreshPendingPatchesDisplay：用叠加层当前的暂存量刷新会话条"N 字节待写入"。
        // 离开守卫丢弃暂存、换目标清空叠加层之后调用（第二轮复核 B4）。
        void refreshPendingPatchesDisplay();

        // clearScopeSwitchPrompt：撤销"切换并跳转"挂起请求并隐藏对应按钮；任何
        // 使该请求失效的导航（后退/前进/身份变化/新的成功跳转）都经这里。
        void clearScopeSwitchPrompt();

        // maybeAutoCollapseInspector（修复缺陷 1 的配套调整）：窗口宽度小于
        // kSidebarAutoCollapseWidth 时同时自动隐藏十六进制页的解释器面板
        // （hexPane_->inspector()，公开访问器，既有用途是 Ctrl+I 与
        // setPointerNamer）。原因：HexInspectorPanel 自身有约 260px 的硬性最小
        // 宽度（见 WorkbenchHexPane.h minimumSizeHint 的注释），这个下限不在
        // 本任务书允许修改的文件范围内（HexInspectorPanel/WorkbenchHexPane 都
        // 不是点名允许改的文件），窄窗口下它会把画布挤到不到 150px；自动隐藏
        // 它（而不是去改它的下限）才能让画布在窄窗口下真正可用。同样遵守
        // "用户手动展开/收起过就不再自作主张"（inspectorUserOverride_），且
        // ToggleInspector 快捷键（Ctrl+I）本身仍然可用。
        void maybeAutoCollapseInspector();

        // updateAddressRowLabels：地址栏右侧的重读/实时刷新/展开侧栏三个控件平时带文字标签
        // （真机反馈"只有图标看不懂"）；视图窄于 kAddressRowLabelsMinWidth 时退成纯图标
        // （复选框去掉文字、悬停提示仍在），避免带文字后地址栏最小宽度把窄窗口挤出界。
        // 由 resizeEvent 调用；只在"是否紧凑"变化时才改控件，重复调用无副作用。
        void updateAddressRowLabels();

        // ---- 子页自动跳转（反汇编/文本/对比跟随十六进制；实现在 MemoryWorkbenchView.SubPages.cpp）----
        // 规则见该文件头：每页一个"同步令牌"（上次跟随时的十六进制选区起点），只有从未定位过 /
        // 十六进制动过 / 被强制才重新定位，否则只刷新数据，保留用户在子页里手动导航到的位置。

        // SubPageFollowState：一个子页的跟随状态。
        struct SubPageFollowState
        {
            // positioned：是否已经定位过（从未定位过一定要定位）。
            bool positioned = false;
            // syncedSelectionStart：令牌——上次跟随时十六进制的原始选区起点。
            std::uint64_t syncedSelectionStart = 0;
            // anchor：页面实际定位的地址（显式动作时可能不等于选区起点）；数据晚到刷新时用它重算窗口。
            std::uint64_t anchor = 0;
            // dirty：画布内容变过（页回填/暂存/换代次），切到本页时需要刷新。
            bool dirty = false;
        };

        // onSubTabChanged：子页签切换（分段按钮/快捷键/loadSettings 恢复都经 currentChanged），切到 1~3 时跟随。
        void onSubTabChanged(int tabIndex);
        // onSubPageDataChanged：画布 contentChanged——三页标脏，当前可见的那页立即刷新。
        void onSubPageDataChanged();
        // onTargetModulesChanged：模块目录就绪/失败；有挂起的跟随请求且当前在子页时重试。
        void onTargetModulesChanged(bool kernel);
        // followSubPage：隐式跟随的核心；force 为真无视令牌（身份变化后、模块列表就绪后）。
        void followSubPage(int tabIndex, bool force);
        // showSubPageAt：显式地址（Ctrl+D、右键"从此处反汇编"）：总是覆盖，令牌记成当前选区起点，再切到该页。
        void showSubPageAt(int tabIndex, std::uint64_t address);
        // positionSubPage：把某个子页定位到 address（不判断要不要跟随，调用方已决定）。
        // scrollToTarget：对比页重算窗口后是否滚到目标分组；数据到达引起的刷新传假，保持用户当前的滚动位置。
        void positionSubPage(int tabIndex, std::uint64_t address, bool scrollToTarget = true);
        // refreshSubPage：数据到达后刷新某个子页（文本/对比按上次定位的地址重算窗口）。
        void refreshSubPage(int tabIndex);
        // ensureWindowCovers：目标地址不在叠加层基线窗口里时，把十六进制画布滚到该地址，让基线重选窗口。
        void ensureWindowCovers(std::uint64_t address);
        // resetSubPageFollow：会话身份变化时清三页的跟随状态，文本/对比回到"尚未定位"。
        void resetSubPageFollow();
        // attachedProcessNameHint：宿主按 pid 查到的进程名（没有注入回调/查不到为空串），模块兜底按名字命中用。
        QString attachedProcessNameHint(std::uint32_t pid) const;

        // toggleSidebarByUser：Ctrl+Shift+B 快捷键与 sidebarExpandButton_ 共用的
        // 手动切换入口；调用即视为"用户决定过"，置位 sidebarUserOverride_。
        void toggleSidebarByUser();

        // ---- 十六进制画布自适应：视图菜单钮与偏好（实现在 MemoryWorkbenchView.HexPrefs.cpp）----
        // loadHexPreferences：loadSettings 里调用一次。把已存的分组、字号、行宽偏好灌给十六进制页；
        // 行宽"自动"默认真（WorkbenchSettings::LoadRowWidthAuto 默认 true）——**自适应只在这条路径里打开**，
        // 不调 loadSettings 的宿主/夹具仍是固定 16 字节行宽。
        void loadHexPreferences();
        // saveHexPreferences：saveSettings 里（权威视图检查之后）调用一次。总是存"自动"状态；
        // 只在非自动时才存 bytesPerRow，自动状态不得覆盖用户上次手选的值。
        void saveHexPreferences() const;
        // connectHexViewMenu：把 hexViewMenuButton_ 接上十六进制页的"视图"菜单（aboutToShow 重建）、
        // 行宽模式变化时刷新徽标与悬停说明、仅在十六进制子页（子页签第 0 页）显示。buildUi 之后调用一次。
        void connectHexViewMenu();
        void connectRowCanvasSignals();
        void openActiveFind();
        void requestRowCanvasWindow(int tabIndex, std::uint64_t address, std::uint64_t length);
        // 伪代码与 HEX 共用缓存与读取管线；上下文只允许本目标当前分析范围。
        void connectPseudocodeSignals();
        void updatePseudocodeContext(std::uint64_t address);
        // hexViewMenuButton_：子页签那一行右侧的"视图"菜单钮（自绘图标钮，徽标显示"自动"或当前行宽）。
        HexViewGlyphButton* hexViewMenuButton_ = nullptr;

        // ---- 本视图私有的五个对象（创建/销毁顺序见文件头）----
        // target_：本视图私有的目标持有者，由 WorkbenchShared::Instance().
        // CreateServices() 产出的 IWorkbenchServices 构造。
        std::unique_ptr<WorkbenchTarget> target_;
        // confirmations_：实现 IConfirmationSink，持有对 WorkbenchShared::
        // Instance().WritePolicy() 的引用（供"本次运行不再询问"判断）。
        std::unique_ptr<WorkbenchConfirmations> confirmations_;
        // pageProvider_ / baselineFeeder_ / writeController_：读/基线/写三条管线。
        std::unique_ptr<WorkbenchPageProvider> pageProvider_;
        std::unique_ptr<WorkbenchBaselineFeeder> baselineFeeder_;
        std::unique_ptr<WorkbenchWriteController> writeController_;
        std::shared_ptr<ksword::memwb::PointerChainBindings> pointerBindings_ =
            std::make_shared<ksword::memwb::PointerChainBindings>();
        std::shared_ptr<std::atomic<bool>> pointerCancel_;
        std::uint64_t pointerTicket_ = 0;
        bool pointerResolutionBusy_ = false;
        bool pointerNavigation_ = false;
        bool pointerClearAfterPending_ = false;
        bool pointerClosing_ = false;
        std::map<std::uint64_t, std::string> pointerTraces_;
        // hexPane_：十六进制子页，持有 overlay 唯一一份；用 QWidget 的 parent 机制
        // 管理（本类作为父对象，构造时用 new 创建，不需要 unique_ptr）。它比上面
        // 三个 unique_ptr 成员活得更久的原因见文件头"创建/销毁顺序"——这是 Qt
        // 子对象删除时机晚于派生类成员析构这条通用规则的结果，与本成员在类体内的
        // 声明位置无关。
        WorkbenchHexPane* hexPane_ = nullptr;

        // ---- 四个只读子页（反汇编/文本/对比/C 伪代码），均拥有（child widget）----
        class DisasmBytesProviderAdapter;
        std::unique_ptr<DisasmBytesProviderAdapter> bytesProviderAdapter_;
        WorkbenchDisasmView* disasmView_ = nullptr;
        WorkbenchTextView* textView_ = nullptr;
        WorkbenchCompareView* compareView_ = nullptr;
        WorkbenchPseudocodeView* pseudocodeView_ = nullptr;

        // subPageFollow_：四个子页（0=反汇编、1=文本、2=对比、3=C 伪代码）的跟随状态。
        std::array<SubPageFollowState, 4> subPageFollow_{};
        // subPageFollowBusy_：跟随过程中的防重入标志（跟随时会让十六进制跳转/滚动，它们的信号不能再触发跟随）。
        bool subPageFollowBusy_ = false;
        // subPageFollowPending_：模块目录还在加载时挂起的跟随请求，等 modulesChanged/modulesFailed 再重试。
        bool subPageFollowPending_ = false;
        // kTextFollowBytes / kCompareFollowBytes：文本页/对比页跟随时单次窗口的字节上限（对比页的适配器逐字节
        // 组装，窗口太大每次刷新会明显变慢，所以比文本页的上限更保守的是"整窗扫描"而不是字符串化）。
        static constexpr std::uint64_t kTextFollowBytes = 64ULL * 1024ULL;
        static constexpr std::uint64_t kCompareFollowBytes = 256ULL * 1024ULL;

        // ---- 会话条/地址条/侧栏/状态条/动作 ----
        WorkbenchSessionBar* sessionBar_ = nullptr;
        QLineEdit* addressEdit_ = nullptr;
        QStackedWidget* subTabStack_ = nullptr;
        AddressBookPanel* addressBookPanel_ = nullptr;      // 绑定 WorkbenchShared 共享模型
        Int3PatchPanel* int3Panel_ = nullptr;               // 绑定 WorkbenchShared 共享控制器
        WorkbenchStatusBar* statusBar_ = nullptr;

        // ---- 导航历史（N1 的"内存栈 64 项"，后退/前进）----
        std::vector<std::uint64_t> backStack_;
        std::vector<std::uint64_t> forwardStack_;

        // embedded_：是否处于内嵌进程详情模式（setEmbeddedProcessMode）。
        bool embedded_ = false;
        // memoryDebugMode_：独立目标模式，不允许 Dock 跟随、内核范围或 int3 操作。
        bool memoryDebugMode_ = false;
        // settingsAuthoritative_：是否权威视图（setSettingsAuthoritative）。
        bool settingsAuthoritative_ = false;

        // ---- 本实现新增的布局成员（均为私有实现细节，不出现在任何公开签名里）----
        // mainSplitter_：主体（hexPane_/subTabStack_）与侧栏（sidebarContainer_）
        // 之间的可拖拽分割条，默认侧栏宽度 300（ux.md §1）。
        QSplitter* mainSplitter_ = nullptr;
        // sidebarContainer_：地址簿面板 + int3 补丁面板的垂直容器；内嵌模式下整体隐藏。
        QWidget* sidebarContainer_ = nullptr;
        // subTabSegmented_：十六进制｜反汇编｜文本｜对比｜C 伪代码，驱动共同页面栈。
        HexViewSegmented* subTabSegmented_ = nullptr;
        // backButton_ / forwardButton_：地址条 Alt+←/→ 对应的工具钮。
        QToolButton* backButton_ = nullptr;
        QToolButton* forwardButton_ = nullptr;
        // rerouteButton_：N4"切换范围并跳转"按钮，默认隐藏，只有 openAt 返回
        // NeedsScopeSwitch 时才显示并记下待跳转请求（不静默切换范围）。
        QToolButton* rerouteButton_ = nullptr;
        // rereadButton_：F5 对应的"重读"工具钮，与 Reread 快捷键共用同一个槛。
        QToolButton* rereadButton_ = nullptr;
        // liveRefreshCheckBox_ / liveRefreshTimer_：实时刷新（1 s，DDMA 通道下置灰）。
        QCheckBox* liveRefreshCheckBox_ = nullptr;
        QTimer* liveRefreshTimer_ = nullptr;

        // ---- 修复缺陷 1 新增：侧栏自动折叠 ----
        // sidebarExpandButton_：窄窗口下侧栏被自动折叠（或用户手动折叠）之后
        // 唯一的展开入口；复用 ToggleSidebar 动作已经登记的图标
        // memwb_bookmarks（不新增 qrc 资源）。只在"侧栏当前不可见且非内嵌模式"时显示
        // （由 maybeAutoCollapseSidebar 统一同步）。
        QToolButton* sidebarExpandButton_ = nullptr;
        // sidebarUserOverride_：用户是否已经手动切换过侧栏（无论折叠还是展开）；
        // 一旦置真，窗口宽度不再影响侧栏可见性（见 maybeAutoCollapseSidebar）。
        // loadSettings 会把它复位为假：已存偏好只是"想要什么"，窄窗口仍可折叠它。
        bool sidebarUserOverride_ = false;
        // sidebarWantedVisible_：用户（或已存设置）想要侧栏可见与否。只由 loadSettings
        // 与 toggleSidebarByUser 改写，窗口宽度导致的自动折叠不改它；saveSettings
        // 存的也是它，所以窄窗口的折叠副作用不会覆盖宽屏时的"可见"偏好。
        // 初值 true：buildUi 创建的侧栏默认可见（未调用 loadSettings 的宿主/夹具）。
        bool sidebarWantedVisible_ = true;
        // sidebarPreferredWidth_ / sidebarWidthApplied_：偏好侧栏宽度（默认 300）与
        // "是否已经落到分割条上"，见 applySidebarWidthIfPossible。
        int sidebarPreferredWidth_ = 300;
        bool sidebarWidthApplied_ = true;
        // identityChangeCount_：handleIdentityChange 实际执行的累计次数。openAt 用它的
        // 前后差值判断"身份是否真的变了"（而不是按请求里写了哪些字段猜），决定要不要
        // 压后退栈（第二轮复核 B2）。
        std::uint64_t identityChangeCount_ = 0;
        // int3KeptByLeaveGuard_：Dock 附加/分离的离开守卫刚被放行，且用户在 int3 三选一里选了
        // "保留补丁继续"（账本里当前目标仍有未还原条目）。onTargetAboutToDetach 据此跳过一次
        // 强制还原（一次性，取走即清），避免安全网无视用户刚做的明确选择。
        bool int3KeptByLeaveGuard_ = false;
        // inspectorUserOverride_：用户是否已经手动按过 Ctrl+I；一旦置真，
        // maybeAutoCollapseInspector 永久不再自作主张（见该函数注释）。
        bool inspectorUserOverride_ = false;
        // kSidebarAutoCollapseWidth：触发自动折叠的窗口宽度阈值（ux.md §1）。
        static constexpr int kSidebarAutoCollapseWidth = 760;
        // kAddressRowLabelsMinWidth：地址栏右侧三个控件显示文字标签所需的最小视图宽度；
        // 低于它退成纯图标（见 updateAddressRowLabels）。
        static constexpr int kAddressRowLabelsMinWidth = 560;
        // kMinMainBodyWidth：落偏好侧栏宽度时，分割条至少要给主体（十六进制/反汇编等
        // 子页）留的宽度；放不下就不落（见 applySidebarWidthIfPossible）。
        static constexpr int kMinMainBodyWidth = 300;

        // pendingScopeSwitchRequest_：rerouteButton_ 显示期间记下的"切换范围后要跳转
        // 到哪"，点击按钮时取出并清空；地址/范围发生新的 openAt 调用会覆盖它。
        std::optional<NavRequest> pendingScopeSwitchRequest_;

        // ---- §8.0 审阅新增的三个注入点（见对应 setter 的头文件注释）----
        std::function<ksword::memwb::GateInputs()> gateInputsProvider_;
        std::function<std::optional<WorkbenchProtectionInfo>(std::uint64_t)> protectionProvider_;
        std::function<bool()> globalSkipDangerousConfirmProvider_;
        std::function<std::optional<AttachedProcessDisplayInfo>(std::uint32_t)> attachedProcessInfoProvider_;

        // confirmPrompterFactoryForTest_：InstallConfirmPrompterFactoryForTest 的
        // 后备存储，静态成员（见该方法的注释）。
        static std::function<std::unique_ptr<IConfirmPrompter>()> confirmPrompterFactoryForTest_;

        // lastCommitReport_：onWriteControllerCommitFinished 这个槛的签名在头文件
        // 冻结时就已经定成无参（只承诺"刷新状态条"，不承诺怎么拿到数据）；
        // WorkbenchWriteController::commitFinished 信号本身带完整 CommitReport，
        // 本类在 connectPipelineSignals 里用一个小 lambda 把参数先存进这个成员，
        // 再调用无参槛，槛函数体从这里读，不丢失任何字段。
        ksword::memwb::CommitReport lastCommitReport_;
    };
}
