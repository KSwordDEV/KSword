#pragma once

// ============================================================
// WorkbenchTarget.h
// 作用：
// - 内存工作台"当前目标"持有者的 Qt 包装。纯逻辑（何时换目标、通道/范围如何
//   转移）全部委托给 Qt-free 的 ksword::memwb::MemoryTargetTracker（见
//   shared/evidence/memory_workbench/MemoryTargetTracker.h）；本类只负责：
//     1) 把 MemoryDock 的附加/分离钩子接到 tracker 上，并用 Win32 句柄做一次
//        "身份锚定"（创建时间、位数、退出检测），锚点逻辑全部在
//        WorkbenchTarget.Anchor.cpp（本组件唯一含 Windows.h 的文件）；
//     2) 身份类变更（范围/钉住或回到跟随/通道）前先问"离开守卫"，被否决就完全
//        不调用 tracker；
//     3) 按会话所有者异步枚举模块并提交到两个 MemoryModuleDirectory（进程/内核），
//        异步部分在 WorkbenchTarget.Modules.cpp；
//     4) 把"求值一条地址表达式""匹配一段进程名/PID 文本"包装成两个薄封装
///       （evaluate/matchProcess），真正的逻辑在 Core 的 SessionAddressResolver
//        与 MemoryProcessMatch 里，这里只负责接线 IWorkbenchServices。
// - 本类只在 UI 线程使用（文档参见 target.md 第 2.4 节）；唯一的例外是
//   enumerateProcessModules/enumerateKernelModules 两个回调本身在工作线程执行
//   （由 IWorkbenchServices 实现方保证线程安全），结果通过 QPointer 守卫的
//   跨线程排队调用落回 UI 线程后才会触碰 tracker/目录。
//
// requestIdentity 与 target.md 骨架的差异（本文件对骨架的一处必要扩展）：
// - target.md 2.5 把范围/钉住/通道分别列成 requestScope/requestPin/requestChannel
//   三个独立方法；但 target.md 第 2.2 节与本工作包任务都要求"身份类变更（范围/pid/
//   通道）合并为一次离开守卫询问"。三个独立方法各自单独调用时天然只能各问一次，
//   无法满足"组合变更只问一次"；因此这里新增 requestIdentity(IdentityRequest,
//   LeaveReason) 作为同时改多个维度时的入口，三个独立方法与 requestFollowDock
//   都是它的薄包装（各自只填一个字段）。之后的 Dock 侧跳转入口
//   （MemoryDock.Workbench.cpp，工作包 K）若一次导航要同时换范围/钉住/通道，
//   必须调用 requestIdentity 而不是依次调用三个独立方法，否则会被连续问三次。
//
// 本文件允许包含 Qt 头，但不包含 Windows.h、不包含 Framework.h
// （组件自包含，便于夹具单独编译）。命名空间固定为 ks::ui。
// ============================================================

#include "WorkbenchNavigation.h"
#include "WorkbenchServices.h"

#include "../../../../shared/evidence/memory_workbench/MemoryModuleDirectory.h"
#include "../../../../shared/evidence/memory_workbench/MemoryProcessMatch.h"
#include "../../../../shared/evidence/memory_workbench/MemoryTargetTracker.h"
#include "../../../../shared/evidence/memory_workbench/SessionAddressResolver.h"

#include <QObject>
#include <QString>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

namespace ks::ui
{
    // ------------------------------------------------------------
    // 锚点工具函数（实现见 WorkbenchTarget.Anchor.cpp，本组件唯一含 Windows.h 的文件）。
    // 以 void* 传递 Win32 HANDLE，使本头文件与调用方都不需要引入 Windows.h；
    // 夹具可以直接调用这几个自由函数做"真实本进程"的锚点冒烟测试。
    // ------------------------------------------------------------

    // AnchorInfo：一次锚点获取的结果。
    struct AnchorInfo
    {
        // identityWeak：true 表示拿不到创建时间（GetProcessTimes 失败）。此时不
        // 代表目标无效，只代表"身份未锚定"：createTime100ns 恒为 0。
        // **D9 修复（头文件契约与实现统一）**：identityWeak 为 true 时 handle
        // **不保证**为 nullptr——只要句柄本身成功拿到（OpenProcess/DuplicateHandle
        // 成功），就会原样带回，调用方仍然必须在不再需要时传给 ReleaseAnchorHandle
        // 关闭，不能因为 identityWeak 为真就假设没有句柄要释放（那样会泄漏）。
        // createTime100ns 恒为 0 才是 identityWeak 的唯一可靠信号；handle 是否
        // 为空只反映"打开/复制句柄这一步"本身成功与否，两者是两件独立的事。
        bool identityWeak = true;
        // createTime100ns：目标进程创建时间（100ns 单位，GetProcessTimes 的结果）；
        // identityWeak 为 true 时恒为 0。
        std::uint64_t createTime100ns = 0;
        // addressBits：目标地址宽度（IsWow64Process 的结果），默认 64。
        std::uint32_t addressBits = 64;
        // handle：降权（仅 PROCESS_QUERY_LIMITED_INFORMATION）句柄，调用方负责
        // 最终传给 ReleaseAnchorHandle 关闭；获取失败时为 nullptr。
        void* handle = nullptr;
        // targetGone（D6 新增）：仅 AcquireAnchorForPid 会设置；true 表示
        // OpenProcess 本身失败，且系统报告的原因是"这个 pid 不是任何进程"
        // （不是权限不足）。调用方据此区分"进程已经不存在/从未存在"与
        // "进程存在但我们打不开它"（后者只是 identityWeak，仍应把 pid 当成
        // 目标，见 D3）。AcquireAnchorFromDockHandle 恒为 false——Dock 既然
        // 已经持有句柄，说明进程此刻一定存在。
        bool targetGone = false;
        // lastError（D6 新增）：底层 Win32 API（OpenProcess/DuplicateHandle）
        // 打开/复制句柄这一步失败时的 GetLastError() 原始值，仅供日志诊断；
        // 句柄成功拿到时恒为 0（哪怕随后 GetProcessTimes/IsWow64Process 失败）。
        std::uint32_t lastError = 0;
    };

    // AcquireAnchorFromDockHandle：从 Dock 持有的进程句柄复制一份降权句柄并读取
    // 创建时间/位数。传入的 dockHandle 本身不会被本函数关闭或改变所有权。
    // 传入：dockHandle 原始 Win32 HANDLE（以 void* 传递）；为 nullptr 时直接返回
    //       identityWeak=true 的结果，不做任何系统调用。
    AnchorInfo AcquireAnchorFromDockHandle(void* dockHandle);

    // AcquireAnchorForPid：为钉住的进程按 PID 打开一个降权句柄并读取创建时间/位数。
    AnchorInfo AcquireAnchorForPid(std::uint32_t pid);

    // ReleaseAnchorHandle：关闭一个锚点句柄；handle 为 nullptr 时是空操作。
    void ReleaseAnchorHandle(void* handle) noexcept;

    // QueryAnchorAlive：查询锚点句柄对应的进程是否仍存活（GetExitCodeProcess）。
    // 传出：true=存活，false=已退出，std::nullopt=查询调用本身失败（句柄为
    //       nullptr 或 API 失败），调用方此时应保留上一次已知的状态，不要当作
    //       "已退出"。
    // **D4 修复**：退出码恰好等于 STILL_ACTIVE（259）时不能直接当"仍在运行"——
    // 进程本身也可能是以 259 作为真实退出码退出的（例如 `cmd /c exit 259`），
    // API 层面两者无法区分。此时再查一次 GetProcessTimes 的退出时间字段消歧：
    // 仍在运行的进程该字段恒为全零，已退出的进程（哪怕退出码凑巧是 259）该字段
    // 必然非零。
    std::optional<bool> QueryAnchorAlive(void* handle) noexcept;

    // ------------------------------------------------------------
    // WorkbenchTarget 本体
    // ------------------------------------------------------------

    // LeaveReason：请求一次身份类变更前，离开守卫被问到的理由。
    enum class LeaveReason : std::uint32_t
    {
        DockAttachChange = 0,  // Dock 附加/分离了进程（跟随模式下会改变会话）
        ScopeChange = 1,       // 用户切换了范围（进程/内核/物理）
        ChannelChange = 2,     // 用户切换了通道
        PinChange = 3,         // 钉住某个进程，或从钉住回到跟随 Dock
    };

    // TargetCapture：某一时刻的会话快照，供工作线程/异步任务携带。
    struct TargetCapture
    {
        ksword::memwb::MemoryTargetSession session;
        ksword::memwb::RevisionSnapshot rev;
    };

    // IdentityRequest：requestIdentity 的输入，描述一次范围/钉住(或跟随)/通道的
    // 组合变更。任一字段为 std::nullopt 表示"这一维不变"。
    struct IdentityRequest
    {
        // scope：新范围；为空表示不变。
        std::optional<ksword::memwb::Scope> scope;
        // pinPid：有值且非 0 表示钉住该 pid；有值且为 0 表示"回到跟随 Dock"；
        // 为空表示跟随/钉住状态不变。
        std::optional<std::uint32_t> pinPid;
        // channel：新通道；为空表示不变。
        // **D5 修复**：原来这里还有一个 ddmaGeneration 字段，调用方必须自己传
        // "当前代次"，缺省值 0 会被当成真实代次喂给 tracker，紧接着下一次
        // session()/capture() 又把真实代次拉回来，等于多发一次 sessionChanged
        // 并让订阅者在槅里重入。现在 channel 切到 Ddma 时 requestIdentity 内部
        // 自己调用 services_->ddmaGeneration()，调用方不需要也不能再传代次。
        std::optional<ksword::memwb::Channel> channel;
        // expectCreateTime（D6 新增）：pinPid 有值且非 0 时，期望被钉住的进程
        // 实例的创建时间（100ns，与 target.md 的"核对进程实例"对应）；0 表示
        // "不要求校验"（调用方不知道，或是第一次钉住、没有旧实例可比较）。
        // 非 0 且与实际打开到的进程创建时间不符时，requestIdentity 会在问离开
        // 守卫之前就直接失败（NavStatus::TargetMismatch），不会把请求静默应用
        // 到"同 pid 但已经是另一个进程实例"上。pinPid 为空或为 0 时忽略本字段。
        //
        // **N4 决策（第二轮审核 + 主会话拍板，不是缺陷，是设计选择）**：上面这条
        // 核对只在锚点"已锚定"（AnchorInfo::identityWeak 为 false）时才会执行。
        // 打不开的进程（受保护进程/权限不足，只能拿到 weak 锚点）无法获取真实创建
        // 时间，expectCreateTime 对这类目标**结构性核对不了**——这正是"钉住受保护
        // 进程走 R0/HVM/DDMA 通道"的头号用法，若因为核对不了就拒绝钉住，反而堵死
        // 了这条路。因此 weak 锚点下 requestPin 即便 expectCreateTime 与实际（永远
        // 是 0）不符也**不失败**，会话创建时间维持 0，identityAnchored() 相应返回
        // false，lastIdentityFailure() 维持 Ok（不会被误报成校验失败）。调用方
        // （装配层/状态条）必须据此自行给出提示：identityAnchored()==false 时应
        // 展示"身份未锚定，无法核对进程实例是否被复用"一类的文案，不能假设
        // "requestPin 成功=身份已核对"。
        std::uint64_t expectCreateTime = 0;
    };

    // LivenessState：checkLiveness() 探测到的、被跟随/钉住目标的存活状态。
    enum class LivenessState : int
    {
        Unknown = 0,  // 还没探测过，或没有锚点句柄
        Alive = 1,
        Exited = 2,
    };

    // WorkbenchTarget：目标会话的 Qt 包装，全部公开函数只在 UI 线程调用
    // （enumerateProcessModules/enumerateKernelModules 的工作线程调用由
    // IWorkbenchServices 实现方负责，本类不在工作线程被直接调用）。
    class WorkbenchTarget final : public QObject
    {
        Q_OBJECT

    public:
        // DockAttach：MemoryDock 附加了一个进程时传入的信息。
        struct DockAttach
        {
            void* handle = nullptr;           // Dock 持有的进程句柄（仅供复制，不可写）
            std::uint32_t pid = 0;
            QString name;
            std::uint64_t attachGeneration = 0; // Dock 自己的附加代次（必须小于 2^63）
            bool hintReadOnly = false;
        };

        // Policy：内嵌实例（如 ProcessDetailWindow 的内嵌 Dock）用来约束自己的策略。
        struct Policy
        {
            bool lockToDock = false;        // true：禁止钉住/回到跟随之外的操作，恒跟随 Dock
            bool allowKernelPhysical = true; // false：禁止切换到内核/物理范围
            // allowFollowDock：独立内存调试页为 false，忽略 Dock 事件并拒绝回到跟随。
            bool allowFollowDock = true;
        };

        // 构造：services 不能为空（空指针会在构造时被替换为一个"全部调用都失败"的
        // 占位实现，避免后续每个调用点都要判空；这只是防御，不是推荐用法）。
        // 内部以 std::shared_ptr 持有 services：纵使本对象被销毁，仍在工作线程上
        // 执行的 enumerate 调用也不会访问已释放的对象，只是其结果会被静默丢弃。
        explicit WorkbenchTarget(std::unique_ptr<IWorkbenchServices> services, QObject* parent = nullptr);
        ~WorkbenchTarget() override;

        // session：当前会话。每次调用先把当前 DDMA 代次拉取一遍并喂给
        // ObserveDdma（仅通道为 Ddma 时才真的调用 services 的 ddmaGeneration()），
        // 因此本函数不是纯访问器，可能同步触发 sessionChanged(Ddma)。
        const ksword::memwb::MemoryTargetSession& session();

        // capture：等价于 {session(), tracker 当前的代次快照}，用于把目标状态带去
        // 工作线程或异步任务；同样会先拉取 DDMA 代次。
        TargetCapture capture();

        // isStale：capture() 得到的快照是否已经陈旧（来源或内容代次任一变化）。
        // **D2 修复**：原来是 const 且只比对 tracker 里已有的代次，不会主动去拉
        // 一次最新 DDMA 代次；若调用方全程只调 capture()+isStale()、从未调用过
        // session()，暂存扇区在读期间换代就会被漏判为"未陈旧"。现在改成非 const：
        // 通道恰好是 Ddma 时，内部先调一次与 session()/capture() 相同的拉取
        // 流程（可能同步触发 sessionChanged(Ddma)），再比较代次，确保"换了暂存
        // 扇区，旧读取不再可信"这条设计不变式不依赖调用方有没有先调用过 session()。
        bool isStale(const ksword::memwb::RevisionSnapshot& captured);

        // revisions（装配层拍板新增的只读访问器）：取 tracker 内部那份代次计数器
        // 的只读引用，不是拷贝。供"必须比它们活得更久的代次引用"的调用方使用
        // （例如写事务：开始写入时取一次引用，写入过程中随时能看到最新代次，
        // 不需要反复调用 capture() 重新拷贝）。这里返回的引用与 capture()/
        // isStale() 内部使用的是**同一份**真实代次状态——会话身份一变、
        // noteContentChanged()/requestReload() 一调用，这个引用上读到的值
        // 立刻跟着变，不需要调用方重新取一次引用。引用的生命周期与本对象一致，
        // 调用方不得在本对象销毁后继续使用。
        const ksword::memwb::SessionRevisions& revisions() const noexcept
        {
            return tracker_.Revisions();
        }

        // policy / setPolicy：内嵌实例的策略；默认是"完全自由"的 Policy{}。
        const Policy& policy() const noexcept;
        void setPolicy(const Policy& policy);

        // followMode：当前是跟随 Dock 还是钉住了某个进程。
        ksword::memwb::MemoryTargetTracker::Follow followMode() const noexcept;

        // wouldChangeOnDockAttach：Dock 此刻的附加/分离是否会改变会话
        // （跟随 Dock 且范围=进程时为 true）。
        bool wouldChangeOnDockAttach() const noexcept;

        // identityAnchored（可疑点 #5 新增访问器）：当前会话的进程身份是否已经
        // "锚定"（能用创建时间区分"同一个进程实例"与"同 pid 的另一个进程"）。
        // 范围不是进程、pid 为 0、或创建时间为 0（句柄获取失败/受保护进程降级为
        // weak，见 D3）都返回 false。旧版本只能靠调用方自己猜
        // session().processCreateTime100ns==0 的含义，状态条想展示"身份未锚定"
        // 提示没有现成接口，这里补上。
        bool identityAnchored() const noexcept;

        // clearMemoryDebugTarget：仅供独立模式关闭会话；先问离开守卫再释放锚点。
        // 返回 false 时保留目标与代次；成功清缓存但不操作目标进程或回到 Dock。
        bool clearMemoryDebugTarget();
        // livenessState：返回最后一次锚点探测状态，供独立模式阻止退出后的 I/O。
        LivenessState livenessState() const noexcept;

        // 三个钩子：只由 MemoryDock 在附加/分离的对应时点调用，语义见文件顶部与
        // target.md 第 2.2 节。onDockAboutToDetach 内部按直接连接同步发出
        // aboutToDetach()，调用返回前 Dock 持有的句柄仍然有效。
        // **可疑点 #2 修复**：onDockAboutToDetach 不再无条件发出 aboutToDetach——
        // 只有"这次分离确实会改变会话目标"时才发（跟随 Dock、范围=进程、且当前
        // 确实有一个非零 pid；判据与 wouldChangeOnDockAttach 对称）。Dock 本来就
        // 没有附加、或工作台此刻钉在别的进程/内核/物理范围时，分离与会话目标无关，
        // 不应该让订阅者（例如 int3 补丁的"未经提示安全网"）误把它当成目标要变了，
        // 去处理一个与会话无关的进程的补丁。
        void onDockAttached(const DockAttach& attach);
        void onDockAboutToDetach();
        void onDockDetached();

        // setLeaveGuard：视图注册一个"是否允许离开当前编辑状态"的回调；
        // 不注册（传 nullptr）时按"无视图=放行"处理，requestLeave 恒返回 true。
        void setLeaveGuard(std::function<bool(LeaveReason)> guard);

        // requestLeave：直接问一次离开守卫。confirmDiscardMemoryEditsForProcessChange
        // 之类的旧集成点会直接调用它；requestIdentity 内部身份确实要变时也调用它。
        // **可疑点 #1 修复**：内部先把 leaveGuard_ 拷贝一份再调用——如果守卫本身
        // 弹出模态框（嵌套事件循环）期间视图被销毁并调用 setLeaveGuard(nullptr)，
        // 正在执行的那个 std::function 不会被自身的重新赋值破坏。
        bool requestLeave(LeaveReason reason);

        // requestIdentity：一次性请求范围/钉住(或跟随)/通道的组合变更，身份确实
        // 会变时只问一次离开守卫（见文件顶部说明）。
        // 传出：
        //   - scope/channel 枚举值越界（D7 修复：入口直接校验，不再先问守卫再被
        //     tracker 拒绝）、policy 禁止其中某一项（不问守卫）、钉住目标已不存在
        //     或创建时间与 expectCreateTime 不符（D6 修复：在问守卫之前就失败，
        //     不弹"要不要离开"再告诉用户目标根本不对）、守卫否决，以上任一都返回
        //     false，tracker 完全不变；
        //   - 否则按范围→钉住/跟随→通道的顺序依次应用并返回 true（哪怕某一步
        //     实际没有变化也算成功）；tracker 另外因为自身规则拒绝了某一步
        //     （返回掩码含 Rejected，理论上不会发生，因为上面已经前置校验过枚举
        //     合法性）也返回 false（D7 续）。
        //   具体失败原因可随后调用 lastIdentityFailure() 取得。
        bool requestIdentity(const IdentityRequest& request, LeaveReason reason);

        // lastIdentityFailure（D6/D7 新增）：requestIdentity（含下面四个薄包装）
        // 最近一次返回 false 时的原因；返回 true 时恒为 NavStatus::Ok。供 Dock 侧
        // 区分"策略拒绝"/"守卫否决"/"目标不存在或已被复用"，不需要靠猜。
        NavStatus lastIdentityFailure() const noexcept;

        // 下面四个是 requestIdentity 的薄包装，各自只填一个维度，供只改单一维度的
        // 界面控件（范围分段钮、通道分段钮等）直接调用。
        // **D5 修复**：requestChannel 不再接受 ddmaGeneration 参数——切到 Ddma
        // 通道时内部自己向 services_ 要当前代次，调用方不需要也不能再传。
        // **D6 新增**：requestPin 多了一个可选的 expectCreateTime 参数，语义见
        // IdentityRequest::expectCreateTime；缺省 0 表示不校验，兼容旧调用点。
        bool requestScope(ksword::memwb::Scope scope);
        bool requestChannel(ksword::memwb::Channel channel);
        bool requestPin(std::uint32_t pid, std::uint64_t expectCreateTime = 0);
        bool requestFollowDock();

        // requestReload：用户按了重读/F5，或整窗需要重读。不经过离开守卫
        // （不改变身份，只是来源代次 +1），恒成功。
        void requestReload();

        // noteContentChanged：暂存/丢弃/撤销/写入提交之后调用，只让内容代次 +1。
        void noteContentChanged();

        // refreshModules：强制按当前范围重新枚举模块（进程范围→枚举进程模块；
        // 内核范围→枚举内核模块；物理范围没有模块，空操作）。供目标条的"刷新
        // 模块"图标调用；身份变更触发的自动枚举见 onDockAttached/requestIdentity
        // 内部逻辑，那条路径是"惟进程范围必刷新、惟首次进入内核才懒加载一次"，
        // 本函数则无条件重新发起一次。
        void refreshModules();

        // A copied snapshot for pointer-bookmark forms, with strict owner identity.
        std::vector<ksword::memwb::ModuleRecord> pointerChainModules();

        // PrimaryModuleState：primaryModule 的三态结果。
        //   Unavailable：没有"起始模块"可言——物理范围、未附加进程、目录所有者不符、
        //                目录为空/加载失败、或目录里没有记录；调用方退回当前插入点，不空等；
        //   Loading：目录正在为当前所有者加载，调用方应挂起，等 modulesChanged/modulesFailed 再问；
        //   Ready：record 里是起始模块。
        enum class PrimaryModuleState
        {
            Unavailable = 0,
            Loading,
            Ready,
        };

        // PrimaryModuleResult：primaryModule 的返回值。
        struct PrimaryModuleResult
        {
            // state：见 PrimaryModuleState。
            PrimaryModuleState state = PrimaryModuleState::Unavailable;
            // record：state==Ready 时的起始模块记录（拷贝，不指向目录内部）。
            ksword::memwb::ModuleRecord record;
        };

        // primaryModule：当前范围的"起始模块"——反汇编/文本/对比三个子页在十六进制没有选区时
        // 自动落到的位置。进程范围：先按 processNameHint（宿主查到的进程名，可空）不区分大小写命中，
        // 没命中取名字以 .exe 结尾的最低基址模块，再不行取最低基址模块；内核范围：先取 ntoskrnl.exe，
        // 没有就取最低基址模块；物理范围没有模块。只读当前会话快照（不触发 DDMA 代次拉取），
        // 不发起枚举（枚举由身份变更/进入内核范围时的既有逻辑负责）。
        PrimaryModuleResult primaryModule(const QString& processNameHint) const;

        // evaluate：求值一条地址表达式（回车提交时调用，绝不逐键调用）。
        // 内部用当前会话 + 两个模块目录 + 一个包装 services.readPointer 的读取器
        // 调用 SessionAddressResolver::EvaluateForSession。
        ksword::memwb::AddressEval evaluate(const QString& text);

        // matchProcess：把"目标进程"输入框里的文本匹配成候选进程
        // （services.processCandidates() + ksword::memwb::MatchProcessText）。
        ksword::memwb::ProcessMatchResult matchProcess(const QString& text) const;

        // checkLiveness：主动探测被跟随/钉住目标的存活状态（本类不自带定时器，
        // 由宿主在自己已有的节奏里调用，例如 Dock 已有的进程存活轮询）；状态
        // 相对上一次确实变化时才发 livenessChanged。
        // **可疑点 #8 修复**：范围不是进程（内核/物理）时恒报 Unknown，不再去探测
        // Dock 当前附着的那个进程——那个进程不是当前会话的目标，用它的存活状态
        // 回答"目标是否存活"是张冠李戴。
        void checkLiveness();

    signals:
        // sessionChanged：tracker 产生了非 None、非 Rejected 的变更掩码时发出，
        // changeMask 是 ksword::memwb::TargetChange 的位组合（转成 quint32 以便
        // 跨 Q_OBJECT 信号槅传递，不强制依赖该枚举的头文件）。
        // **可疑点 #3 修复（顺序）**：现在在 applyMaskSideEffects 内部先完成
        // "身份变了就同步 BeginLoad 新所有者"这一步，再发出本信号；订阅者在槅里
        // 同步调用 evaluate() 时，模块目录已经处于新所有者的 Loading 状态，不会
        // 再读到旧所有者的 Ready 结果。
        void sessionChanged(quint32 changeMask);
        // aboutToDetach：onDockAboutToDetach 内部直接（同步）发出，订阅者应使用
        // 直接连接；发出时 Dock 的进程句柄仍然有效。
        // **可疑点 #2 修复**：只在"这次分离确实会改变会话目标"时才发出，见
        // onDockAboutToDetach 的声明处注释。
        void aboutToDetach();
        // modulesChanged：某个模块目录完成了一次 Commit（kernel=true 表示内核
        // 目录，否则是进程目录）。
        void modulesChanged(bool kernel);
        // modulesFailed（可疑点 #3 新增）：某个模块目录完成了一次 Fail（kernel
        // 语义同 modulesChanged）。旧版本枚举失败后什么信号都不发，界面上
        // "加载中"的指示灯永远不会熄灭，必须自己去查 GetState()==Failed 才知道；
        // 现在失败也主动通知一次，界面可以直接订阅它来熄灭指示灯/展示失败详情。
        void modulesFailed(bool kernel);
        // livenessChanged：checkLiveness 探测到状态变化（见 LivenessState）。
        // **可疑点 #6 修复**：状态被重置为 Unknown（换目标/钉住切换时）也算一次
        // "相对上一次确实变化"，同样会发出本信号，不再是静默重置——否则"上一个
        // 状态是 Exited，换了新目标但还没来得及探测"这段时间界面会一直停留在
        // "已退出"，误导用户。
        void livenessChanged(int state);

    private:
        // ServicesPointerReader：实现 SessionAddressResolver.h 的 IPointerReader，
        // 把调用转发到 IWorkbenchServices::readPointer；定义在 WorkbenchTarget.cpp。
        class ServicesPointerReader;

        // ModuleEnumTask：QThreadPool 上跑的一次模块枚举任务；定义在
        // WorkbenchTarget.Modules.cpp。
        class ModuleEnumTask;

        // applyMaskSideEffects：tracker 调用返回掩码后的统一收尾——按掩码自动
        // 触发模块刷新（BeginLoad 同步执行）、再发 sessionChanged。None 与含
        // Rejected 位都不发信号（含 Rejected 额外记一条警告日志）。
        void applyMaskSideEffects(ksword::memwb::TargetChange mask);

        // predictsIdentityChange：requestIdentity 在真正调用 tracker 之前，先在
        // tracker 的一份值拷贝上试应用这次请求的三个维度，用"试应用后的掩码是否
        // 含身份位"做预测，决定要不要问离开守卫（D8 修复：不再自己重复一遍
        // tracker 的身份规则，避免两份规则各自演化、渐渐分叉）。
        // 传入：resolvedPinAnchor 在 request.pinPid 有值且非 0 时必须非空，带着
        //       AcquireAnchorForPid 已经查到的真实创建时间/位数（不是猜测值），
        //       预测才能准确反映 Pin() 真正会不会 bump 身份位；pinPid 为空或为 0
        //       时忽略该参数（可传 nullptr）。
        bool predictsIdentityChange(
            const IdentityRequest& request,
            const AnchorInfo* resolvedPinAnchor) const;

        // refreshProcessModules / refreshKernelModules：定义在 WorkbenchTarget.Modules.cpp。
        // force 为 false 时只在目录当前不是 Ready/Loading 时才发起（懒加载一次）；
        // force 为 true 时无条件发起新一轮（旧票据作废）。
        void refreshProcessModules(bool force);
        void refreshKernelModules(bool force);

        // handleProcessModulesReady / handleKernelModulesReady：工作线程完成后，经
        // QPointer 守卫的排队调用落回 UI 线程时调用，定义在 WorkbenchTarget.Modules.cpp。
        void handleProcessModulesReady(
            const ksword::memwb::ModuleOwner& owner,
            std::uint64_t ticket,
            ModuleEnumResult result);
        void handleKernelModulesReady(
            const ksword::memwb::ModuleOwner& owner,
            std::uint64_t ticket,
            ModuleEnumResult result);

        // updateLiveness：checkLiveness 的内部落地，状态变化才发信号。
        void updateLiveness(LivenessState state);

        // services_：外部环境依赖；见 WorkbenchServices.h 顶部的线程规则。
        std::shared_ptr<IWorkbenchServices> services_;
        // tracker_：唯一的会话状态机，全部转移规则都在这里（Qt-free）。
        ksword::memwb::MemoryTargetTracker tracker_;
        // processDirectory_ / kernelDirectory_：两份带所有者身份的模块目录。
        ksword::memwb::MemoryModuleDirectory processDirectory_;
        ksword::memwb::MemoryModuleDirectory kernelDirectory_;
        // leaveGuard_：视图注册的离开守卫；为空表示放行。
        std::function<bool(LeaveReason)> leaveGuard_;
        // policy_：当前策略（默认完全自由）。
        Policy policy_;
        // dockAnchorHandle_：复制自 Dock 句柄的降权句柄（仅查询权限），Dock 未附加
        // 或已分离时为 nullptr。
        void* dockAnchorHandle_ = nullptr;
        // pinnedAnchorHandle_：钉住进程时按 PID 打开的降权句柄；未钉住时为 nullptr。
        void* pinnedAnchorHandle_ = nullptr;
        // lastLiveness_：checkLiveness 最近一次确定的状态，用于判断是否需要发信号。
        LivenessState lastLiveness_ = LivenessState::Unknown;
        // processModuleTicket_ / kernelModuleTicket_：两个目录各自的票据计数器，
        // 每发起一轮新的枚举就自增，陈旧票据的回调会被 MemoryModuleDirectory::Commit
        // 自动丢弃。
        std::uint64_t processModuleTicket_ = 0;
        std::uint64_t kernelModuleTicket_ = 0;
        // lastIdentityFailure_（D6/D7 新增）：requestIdentity 最近一次返回值的
        // 原因；每次 requestIdentity 调用开始时先重置为 Ok，只有真正要返回 false
        // 时才会被改写成具体原因，供 lastIdentityFailure() 读取。
        NavStatus lastIdentityFailure_ = NavStatus::Ok;
    };
}
