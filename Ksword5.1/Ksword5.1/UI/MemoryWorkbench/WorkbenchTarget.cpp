// ============================================================
// WorkbenchTarget.cpp
// 作用：
// - WorkbenchTarget 的主体实现：构造/析构、会话访问（session/capture/isStale）、
//   策略、三个 Dock 钩子（不含模块枚举的异步部分，那部分在
//   WorkbenchTarget.Modules.cpp）、离开守卫、身份类变更的统一入口 requestIdentity
//   及其四个薄包装、重读/内容变更、地址表达式求值、进程文本匹配、存活探测。
// - 锚点相关的 Win32 调用全部在 WorkbenchTarget.Anchor.cpp；模块异步枚举全部在
//   WorkbenchTarget.Modules.cpp。本文件不包含 Windows.h。
// ============================================================

#include "WorkbenchTarget.h"

#include <QByteArray>
#include <QPointer>
#include <QtGlobal>

#include <string_view>
#include <utility>

namespace ks::ui
{
    namespace
    {
        // NullWorkbenchServices：构造时 services 传了空指针的防御性占位实现，
        // 全部调用都如实报告失败，不让后续代码到处判空。只在这一种异常用法下出现。
        class NullWorkbenchServices final : public IWorkbenchServices
        {
        public:
            // 可疑点 #11 修复：这几条 failure 串会作为 PointerReadResult/ModuleEnumResult
            // 的 detail 字段一路流进 ksword::memwb::Issue 的 detail，属于"不含面向
            // 用户句子"的技术诊断串（见 WorkbenchServices.h 的契约），只会在
            // "构造时 services 传了空指针"这种异常用法下出现；原来写的是中文完整
            // 句子，en-US 界面会原样漏出一串汉字。改成纯英文技术短语。
            ModuleEnumResult enumerateProcessModules(std::uint32_t, std::uint64_t) override
            {
                return ModuleEnumResult{false, {}, "WorkbenchTarget: services not injected"};
            }

            ModuleEnumResult enumerateKernelModules() override
            {
                return ModuleEnumResult{false, {}, "WorkbenchTarget: services not injected"};
            }

            std::vector<ksword::memwb::ProcessCandidate> processCandidates() override
            {
                return {};
            }

            PointerReadResult readPointer(
                const ksword::memwb::MemoryTargetSession&,
                std::uint64_t,
                std::uint32_t) override
            {
                return PointerReadResult{false, 0, "WorkbenchTarget: services not injected"};
            }

            std::uint64_t ddmaGeneration() override
            {
                return 0;
            }
        };

        // Utf8View：把 QString 转成一份 UTF-8 字节的 string_view，返回值持有底层
        // QByteArray，调用方只要让返回值存活到不再使用 view 为止即可
        // （EvaluateForSession/MatchProcessText 都是同步调用，不存在生命周期问题）。
        struct Utf8View
        {
            QByteArray bytes;
            std::string_view view;

            explicit Utf8View(const QString& text)
                : bytes(text.toUtf8())
                , view(bytes.constData(), static_cast<std::size_t>(bytes.size()))
            {
            }
        };
    }

    // ------------------------------------------------------------
    // ServicesPointerReader：把 SessionAddressResolver.h 的 IPointerReader 接到
    // IWorkbenchServices::readPointer 上，供 evaluate() 临时构造使用。
    // ------------------------------------------------------------
    class WorkbenchTarget::ServicesPointerReader final : public ksword::memwb::IPointerReader
    {
    public:
        explicit ServicesPointerReader(std::shared_ptr<IWorkbenchServices> services)
            : services_(std::move(services))
        {
        }

        bool ReadPointer(
            const ksword::memwb::MemoryTargetSession& session,
            std::uint64_t address,
            std::uint32_t widthBytes,
            std::uint64_t& valueOut,
            std::string& failureOut) override
        {
            const PointerReadResult result = services_->readPointer(session, address, widthBytes);
            valueOut = result.ok ? result.value : 0;
            failureOut = result.failure;
            return result.ok;
        }

    private:
        std::shared_ptr<IWorkbenchServices> services_;
    };

    // ------------------------------------------------------------
    // 构造 / 析构
    // ------------------------------------------------------------

    WorkbenchTarget::WorkbenchTarget(std::unique_ptr<IWorkbenchServices> services, QObject* parent)
        : QObject(parent)
        , services_(services
              ? std::shared_ptr<IWorkbenchServices>(std::move(services))
              : std::static_pointer_cast<IWorkbenchServices>(std::make_shared<NullWorkbenchServices>()))
    {
    }

    WorkbenchTarget::~WorkbenchTarget()
    {
        // 两个锚点句柄都是本对象独占持有的降权句柄，析构时必须关闭；
        // 在途的模块枚举任务另持一份 services_ 的 shared_ptr，与本对象的生命周期无关，
        // 不受这里影响（它们的结果会在落地时发现 QPointer 已空而被安全丢弃）。
        ReleaseAnchorHandle(dockAnchorHandle_);
        ReleaseAnchorHandle(pinnedAnchorHandle_);
    }

    // ------------------------------------------------------------
    // 会话访问
    // ------------------------------------------------------------

    const ksword::memwb::MemoryTargetSession& WorkbenchTarget::session()
    {
        // 只有通道确实是 Ddma 时才去问 services：ObserveDdma 本身对非 Ddma 通道
        // 是无条件 None，调用 services 只会白白浪费一次虚函数调用。
        if (tracker_.Session().channel == ksword::memwb::Channel::Ddma)
        {
            // N3 修复（session()/isStale() 这一半）：applyMaskSideEffects 内部会
            // 同步发出 sessionChanged；订阅者的槅理论上可以在这次调用栈内同步
            // 销毁 this（例如视图被程序性关闭）。用 QPointer 守卫，发出信号之后
            // 先判空，被销毁就不能再碰 tracker_ 这个成员。
            const QPointer<WorkbenchTarget> self(this);
            const std::uint64_t currentGeneration = services_->ddmaGeneration();
            const ksword::memwb::TargetChange mask = tracker_.ObserveDdma(currentGeneration);
            applyMaskSideEffects(mask);
            if (!self)
            {
                // 对象已经被销毁：不能再返回 tracker_.Session() 的引用（那是对已
                // 释放内存的解引用）。调用方此刻持有的 this 指针同样已经失效，
                // 返回值不会被安全使用，这里只是避免在本函数内部触发未定义行为。
                static const ksword::memwb::MemoryTargetSession kDestroyedSessionFallback{};
                return kDestroyedSessionFallback;
            }
        }
        return tracker_.Session();
    }

    TargetCapture WorkbenchTarget::capture()
    {
        // session() 的同步代次通知可能销毁目标；完成通知后先探活，禁止继续读取成员。
        const QPointer<WorkbenchTarget> self(this);
        // session() 已经把 DDMA 代次拉取过一遍，这里拿到的已经是最新状态。
        const ksword::memwb::MemoryTargetSession snapshot = session();
        if (!self)
        {
            return TargetCapture{};
        }
        return TargetCapture{snapshot, tracker_.Revisions().Capture()};
    }

    bool WorkbenchTarget::isStale(const ksword::memwb::RevisionSnapshot& captured)
    {
        // D2 修复：通道恰好是 Ddma 时，先按 session()/capture() 同样的规则拉一次
        // 最新代次喂给 tracker——不能指望调用方在 capture() 之后、isStale() 之前
        // 一定调用过 session()。没有这一步，暂存扇区在"capture 之后、isStale
        // 判断之前"换代的那段窗口会被漏判为"未陈旧"，R3 的"isStale 通过才
        // deliverPage"就会把旧暂存扇区代次下读到的页当成新鲜页展示。
        if (tracker_.Session().channel == ksword::memwb::Channel::Ddma)
        {
            // N3 修复：同 session()，applyMaskSideEffects 可能同步触发 this 被
            // 销毁，发信号之后先判空。
            const QPointer<WorkbenchTarget> self(this);
            const std::uint64_t currentGeneration = services_->ddmaGeneration();
            applyMaskSideEffects(tracker_.ObserveDdma(currentGeneration));
            if (!self)
            {
                // 对象已销毁：没有机器可读了，保守按"已陈旧"处理——不会再被
                // 用来触发任何真实的重读，只是避免返回值被当成"仍新鲜"误用。
                return true;
            }
        }
        return tracker_.Revisions().IsStale(captured);
    }

    const WorkbenchTarget::Policy& WorkbenchTarget::policy() const noexcept
    {
        return policy_;
    }

    void WorkbenchTarget::setPolicy(const Policy& policy)
    {
        policy_ = policy;
    }

    ksword::memwb::MemoryTargetTracker::Follow WorkbenchTarget::followMode() const noexcept
    {
        return tracker_.FollowMode();
    }

    bool WorkbenchTarget::wouldChangeOnDockAttach() const noexcept
    {
        return policy_.allowFollowDock && tracker_.WouldChangeOnDockAttach();
    }

    bool WorkbenchTarget::identityAnchored() const noexcept
    {
        // 可疑点 #5 新增：范围是进程、pid 非零、且创建时间非零（锚点成功取到，
        // 不是 D3 场景下的 weak 身份）才算"已锚定"。只读 tracker_.Session()，
        // 不触发任何 DDMA 拉取，noexcept 与 followMode()/policy() 保持同类用法。
        const ksword::memwb::MemoryTargetSession& current = tracker_.Session();
        return current.scope == ksword::memwb::Scope::ProcessVirtual
            && current.pid != 0
            && current.processCreateTime100ns != 0;
    }

    bool WorkbenchTarget::clearMemoryDebugTarget()
    {
        if (policy_.allowFollowDock)
        {
            return false;
        }
        // 守卫可能进入模态事件循环并销毁宿主；允许之后才能清目标。
        const QPointer<WorkbenchTarget> self(this);
        if (!requestLeave(LeaveReason::PinChange) || !self)
        {
            return false;
        }
        ReleaseAnchorHandle(pinnedAnchorHandle_);
        ReleaseAnchorHandle(dockAnchorHandle_);
        pinnedAnchorHandle_ = nullptr;
        dockAnchorHandle_ = nullptr;
        const auto mask = tracker_.ClearPinnedTarget();
        updateLiveness(LivenessState::Unknown);
        if (!self)
        {
            return false;
        }
        applyMaskSideEffects(mask);
        return true;
    }

    LivenessState WorkbenchTarget::livenessState() const noexcept
    {
        return lastLiveness_;
    }

    // ------------------------------------------------------------
    // 三个 Dock 钩子
    // ------------------------------------------------------------

    void WorkbenchTarget::onDockAttached(const DockAttach& attach)
    {
        // 独立内存调试目标由上层选择器钉住，Dock 的附加事件不能接管它。
        if (!policy_.allowFollowDock)
        {
            return;
        }
        // 存活状态通知可同步关闭宿主；通知返回后不能继续使用已销毁的目标。
        const QPointer<WorkbenchTarget> self(this);
        // 先锚定身份（复制 Dock 句柄、取创建时间/位数），再喂给 tracker；
        // 旧的 dock 锚点句柄（上一个被附加的进程）先释放，避免句柄泄漏。
        const AnchorInfo info = AcquireAnchorFromDockHandle(attach.handle);
        ReleaseAnchorHandle(dockAnchorHandle_);
        dockAnchorHandle_ = info.handle;

        // N2 修复：先把结果喂给 tracker 算出 mask，再决定要不要重置存活状态
        // ——旧顺序是先发 livenessChanged 再喂 tracker（订阅者在槅里看到的是
        // 旧会话），而且是无条件重置。现在只在"探测用的句柄真的换了主人"
        // （mask 含 Process：pid/创建时间/附加代次变了；或含 Policy：跟随/钉住
        // 模式变了）时才重置，且严格在算出 mask 之后，保证 sessionChanged 与
        // livenessChanged 两个信号对订阅者呈现的都是同一份新会话。钉住态下
        // FollowAttach 恒返回 None（Dock 的附加只记账，不影响会话），这里天然
        // 不会重置——钉住态下的 Dock 事件与会话/存活探测无关（可疑点 #6 续）。
        const ksword::memwb::TargetChange mask = tracker_.FollowAttach(
            attach.pid, info.createTime100ns, attach.attachGeneration, info.addressBits);
        if (ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Process)
            || ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Policy))
        {
            updateLiveness(LivenessState::Unknown);
            if (!self)
            {
                return;
            }
        }
        applyMaskSideEffects(mask);
    }

    void WorkbenchTarget::onDockAboutToDetach()
    {
        // 可疑点 #2 修复：只有"这次分离确实会改变会话目标"才发出——跟随 Dock
        // （不是钉住）、范围是进程、且当前确实有一个非零 pid（wouldChangeOnDockAttach
        // 已经判了前两条，这里再补上第三条：Dock 真的附着着一个进程）。否则分离
        // 与会话目标无关，发出信号只会让订阅者（例如 int3 补丁的"未经提示安全网"）
        // 误把它当成"目标要变了"，去处理一个与会话无关的进程的补丁。
        if (!wouldChangeOnDockAttach() || tracker_.Session().pid == 0)
        {
            return;
        }
        // 直接（同步）发出：调用方此刻的 Dock 进程句柄仍然有效。订阅者（例如
        // int3 补丁控制器）必须用直接连接，在本次调用返回之前完成需要句柄的收尾；
        // 这里本身不触碰 tracker——分离到底有没有改变会话，由 onDockDetached 决定。
        emit aboutToDetach();
    }

    void WorkbenchTarget::onDockDetached()
    {
        // 独立目标的生命周期与 Dock 分离无关，不清身份或存活探测锚点。
        if (!policy_.allowFollowDock)
        {
            return;
        }
        // 与附加入口共用相同的同步通知生命周期边界。
        const QPointer<WorkbenchTarget> self(this);
        ReleaseAnchorHandle(dockAnchorHandle_);
        dockAnchorHandle_ = nullptr;
        // N2 修复：同 onDockAttached，先算 mask 再按"是否真的换了探测句柄的
        // 主人"决定是否重置存活状态；钉住态下 FollowDetach 恒返回 None，天然
        // 不会重置。
        const ksword::memwb::TargetChange mask = tracker_.FollowDetach();
        if (ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Process)
            || ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Policy))
        {
            updateLiveness(LivenessState::Unknown);
            if (!self)
            {
                return;
            }
        }
        applyMaskSideEffects(mask);
    }

    // ------------------------------------------------------------
    // 离开守卫
    // ------------------------------------------------------------

    void WorkbenchTarget::setLeaveGuard(std::function<bool(LeaveReason)> guard)
    {
        leaveGuard_ = std::move(guard);
    }

    bool WorkbenchTarget::requestLeave(LeaveReason reason)
    {
        if (!leaveGuard_)
        {
            return true; // 无视图注册=放行
        }
        // 可疑点 #1 修复：先拷贝一份再调用。如果守卫内部弹出模态框（嵌套事件
        // 循环）期间视图被销毁并调用 setLeaveGuard(nullptr)，被我们正在执行的
        // 这个 std::function 对象不会因为 leaveGuard_ 本体被重新赋值而出问题——
        // 拷贝之后两者是独立对象，leaveGuard_ 可以被安全替换，这份本地拷贝仍然
        // 持有原始可调用对象直到调用返回。
        const std::function<bool(LeaveReason)> guard = leaveGuard_;
        return guard(reason);
    }

    // ------------------------------------------------------------
    // 身份类变更
    // ------------------------------------------------------------

    namespace
    {
        // IsLegalScope / IsLegalChannel：D7 修复的入口校验——requestIdentity 必须
        // 在问离开守卫之前就拒绝越界的枚举值（例如持久化配置被手改或版本回退带出
        // 的越界值），不能先问了用户一次、再被 tracker 的内部校验拒绝。
        bool IsLegalScope(ksword::memwb::Scope scope) noexcept
        {
            return scope == ksword::memwb::Scope::ProcessVirtual
                || scope == ksword::memwb::Scope::KernelVirtual
                || scope == ksword::memwb::Scope::Physical;
        }

        bool IsLegalChannel(ksword::memwb::Channel channel) noexcept
        {
            return channel == ksword::memwb::Channel::UserMode
                || channel == ksword::memwb::Channel::StandardDriver
                || channel == ksword::memwb::Channel::Hvm
                || channel == ksword::memwb::Channel::Ddma;
        }
    }

    bool WorkbenchTarget::predictsIdentityChange(
        const IdentityRequest& request, const AnchorInfo* resolvedPinAnchor) const
    {
        // D8 修复：不再自己重复一遍 tracker 的身份规则（旧实现只比 pid，不比
        // 创建时间/位数，也不区分"同 pid 不同创建时间"；物理/内核范围下任何
        // requestPin 都被错误地预测为变化）。改成在 tracker 的一份值拷贝上真正
        // 把这次请求的三个维度都试应用一遍（与 requestIdentity 应用阶段完全相同
        // 的三步：范围→钉住/跟随→通道），用"试应用后的掩码是否含身份位"作为
        // 唯一事实源——tracker 自己的转移规则之后如果改了，这里不需要跟着改第二遍。
        // 拷贝一份完整的 tracker（所有成员都是值类型，拷贝构造是安全的），用完即
        // 丢弃，不影响真正的 tracker_；也不会多打开/多关闭任何 Win32 句柄。
        ksword::memwb::MemoryTargetTracker trial = tracker_;
        ksword::memwb::TargetChange mask = ksword::memwb::TargetChange::None;
        if (request.scope)
        {
            mask |= trial.SetScope(*request.scope);
        }
        if (request.pinPid)
        {
            if (*request.pinPid == 0)
            {
                mask |= trial.Unpin();
            }
            else if (resolvedPinAnchor)
            {
                // resolvedPinAnchor 带着 AcquireAnchorForPid 已经查到的真实创建
                // 时间/位数——用真实值试应用，不需要猜测。
                mask |= trial.Pin(
                    *request.pinPid, resolvedPinAnchor->createTime100ns, resolvedPinAnchor->addressBits);
            }
        }
        if (request.channel)
        {
            // N5 修复：只有"当前已经停留在 Ddma 通道，这次仍然请求 Ddma"（通道
            // 字段本身不变）时，才需要真的去问 services_ 的最新代次——这正是
            // 漏判的那个场景：通道字段不变，trial.SetChannel 能不能探测到身份
            // 变化完全取决于代次是不是真的变了，而旧写法用的是会话里已知的
            // 旧值，哪怕暂存扇区早已换代、只是没人主动拉取过，也会被判成
            // "没变"。其它场景（从别的通道切进 Ddma）通道字段本身已经是一次
            // 身份变化（Channel 位），不需要、也不应该为了预测一个已经确定为真
            // 的结果而多问一次 services_——那会在"切换通道"这个既有契约上
            // 多算一次调用（见 Ddma.cpp 的 T5：切换本身必须恰好调用一次
            // ddmaGeneration()），这里用 0 占位，不影响 trial 的身份变化判断。
            const bool alreadyOnDdma = tracker_.Session().channel == ksword::memwb::Channel::Ddma;
            const std::uint64_t ddmaGen = (*request.channel == ksword::memwb::Channel::Ddma && alreadyOnDdma)
                ? services_->ddmaGeneration()
                : 0;
            mask |= trial.SetChannel(*request.channel, ddmaGen);
        }
        return ksword::memwb::IsIdentityChange(mask);
    }

    bool WorkbenchTarget::requestIdentity(const IdentityRequest& request, LeaveReason reason)
    {
        // N3 修复：requestLeave 可能在守卫内部弹出模态框（嵌套事件循环），这段
        // 时间里本对象可能被外部同步销毁（例如内嵌详情窗口被程序性关闭）。用
        // QPointer 在"问完守卫"这一步之后立刻判空，一旦已被销毁就不再触碰任何
        // 成员（tracker_/lastIdentityFailure_/pinnedAnchorHandle_ 等全部不可再
        // 写）；pinAnchor 的句柄是局部变量，被销毁时仍可以安全释放，不会泄漏。
        const QPointer<WorkbenchTarget> self(this);

        lastIdentityFailure_ = NavStatus::Ok;

        // D7 修复：入口先校验枚举合法性，非法值直接拒绝——不问离开守卫、不碰
        // tracker。必须比 tracker 的内部校验更早拦截，否则会先弹一次守卫，用户
        // 平白被问了一次，随后才发现这次请求压根不会被接受。
        if (request.scope && !IsLegalScope(*request.scope))
        {
            lastIdentityFailure_ = NavStatus::Unavailable;
            return false;
        }
        if (request.channel && !IsLegalChannel(*request.channel))
        {
            lastIdentityFailure_ = NavStatus::Unavailable;
            return false;
        }

        // 策略门：内嵌实例锁定跟随 Dock 时不允许钉住；不允许内核/物理范围时拒绝。
        // 这两种拒绝都不问离开守卫——不是用户在犹豫，是这次请求本身不被允许。
        if (policy_.lockToDock && request.pinPid.has_value() && *request.pinPid != 0)
        {
            lastIdentityFailure_ = NavStatus::Unavailable;
            return false;
        }
        // pinPid=0 的公开语义是回到 Dock；独立页只能选择明确的进程实例。
        if (!policy_.allowFollowDock && request.pinPid.has_value() && *request.pinPid == 0)
        {
            lastIdentityFailure_ = NavStatus::Unavailable;
            return false;
        }
        if (!policy_.allowKernelPhysical && request.scope
            && (*request.scope == ksword::memwb::Scope::KernelVirtual
                || *request.scope == ksword::memwb::Scope::Physical))
        {
            lastIdentityFailure_ = NavStatus::Unavailable;
            return false;
        }

        // D6 修复：钉住一个 pid 前先验证它仍然存在、且（给出了期望创建时间时）
        // 确实是同一个进程实例，必须在问离开守卫之前完成——否则用户已经被问过
        // 一次"要不要离开"，随后却发现目标根本不对，体验比直接报错更差。校验
        // 顺带拿到的锚点句柄留给下面应用阶段直接复用，不重复 OpenProcess。
        AnchorInfo pinAnchor;
        const bool havePinAnchor = request.pinPid.has_value() && *request.pinPid != 0;
        if (havePinAnchor)
        {
            pinAnchor = AcquireAnchorForPid(*request.pinPid);
            if (pinAnchor.targetGone)
            {
                lastIdentityFailure_ = NavStatus::TargetGone;
                return false;
            }
            // 独立内存调试不能把选择器捕获的强身份降成仅 PID；旧工作台保留弱锚规则。
            if (!policy_.allowFollowDock
                && (pinAnchor.handle == nullptr || pinAnchor.identityWeak || pinAnchor.createTime100ns == 0))
            {
                ReleaseAnchorHandle(pinAnchor.handle);
                lastIdentityFailure_ = NavStatus::TargetMismatch;
                return false;
            }
            // 已明确退出的独立目标在离开守卫前拒绝，不接入一个已失效身份。
            if (!policy_.allowFollowDock
                && QueryAnchorAlive(pinAnchor.handle) == std::optional<bool>(false))
            {
                ReleaseAnchorHandle(pinAnchor.handle);
                lastIdentityFailure_ = NavStatus::TargetGone;
                return false;
            }
            if (!pinAnchor.identityWeak && request.expectCreateTime != 0
                && pinAnchor.createTime100ns != request.expectCreateTime)
            {
                ReleaseAnchorHandle(pinAnchor.handle);
                lastIdentityFailure_ = NavStatus::TargetMismatch;
                return false;
            }
        }

        if (predictsIdentityChange(request, havePinAnchor ? &pinAnchor : nullptr))
        {
            const bool leaveApproved = requestLeave(reason);
            // N3 修复：守卫返回之后立刻判空，禁止在宿主关闭后继续改目标。
            if (!self)
            {
                if (havePinAnchor)
                {
                    ReleaseAnchorHandle(pinAnchor.handle); // 局部变量，销毁后仍可安全释放。
                }
                return false; // this 已失效，不能再写 lastIdentityFailure_ 等任何成员。
            }
            if (!leaveApproved)
            {
                if (havePinAnchor)
                {
                    ReleaseAnchorHandle(pinAnchor.handle); // 被否决：完全不调用 tracker 的任何改动函数，句柄也不留。
                }
                lastIdentityFailure_ = NavStatus::LeaveRefused;
                return false;
            }
        }

        // 应用顺序固定为 范围 → 钉住/跟随 → 通道，与 target.md 导航表的顺序一致。
        ksword::memwb::TargetChange mask = ksword::memwb::TargetChange::None;
        if (request.scope)
        {
            mask |= tracker_.SetScope(*request.scope);
        }
        if (request.pinPid)
        {
            ksword::memwb::TargetChange pinMask = ksword::memwb::TargetChange::None;
            if (*request.pinPid == 0)
            {
                ReleaseAnchorHandle(pinnedAnchorHandle_);
                pinnedAnchorHandle_ = nullptr;
                pinMask = tracker_.Unpin();
            }
            else
            {
                // 复用上面验证阶段已经拿到的锚点句柄，不重复 OpenProcess。
                ReleaseAnchorHandle(pinnedAnchorHandle_);
                pinnedAnchorHandle_ = pinAnchor.handle;
                pinMask = tracker_.Pin(*request.pinPid, pinAnchor.createTime100ns, pinAnchor.addressBits);
            }
            mask |= pinMask;
            // N2 修复：只有这一步真的换了"存活探测要用的那个句柄的主人"（含
            // Process：钉住了不同身份的进程；或含 Policy：跟随/钉住模式本身
            // 变了，哪怕钉住的是与 Dock 相同的进程，探测用的句柄也从
            // dockAnchorHandle_ 换成了刚打开的 pinnedAnchorHandle_）才重置存活
            // 状态。requestPin(同一个 pid) 这种 Pin() 返回 None 的空操作不会
            // 重置，不会让界面的存活指示灯无故闪烁。
            if (ksword::memwb::HasChange(pinMask, ksword::memwb::TargetChange::Process)
                || ksword::memwb::HasChange(pinMask, ksword::memwb::TargetChange::Policy))
            {
                updateLiveness(LivenessState::Unknown);
                // 同步 livenessChanged 的订阅者也可销毁目标；新锚点已交由对象持有并释放。
                if (!self)
                {
                    return false;
                }
            }
        }
        if (request.channel)
        {
            // D5 修复：不再从 request 读取调用方传入的代次——通道为 Ddma 时直接
            // 向 services_ 要当前真实代次，调用方不需要也不能再传一份可能过期的值。
            const std::uint64_t ddmaGen = (*request.channel == ksword::memwb::Channel::Ddma)
                ? services_->ddmaGeneration()
                : 0;
            mask |= tracker_.SetChannel(*request.channel, ddmaGen);
        }

        // D7 续：前面已经把枚举值校验过一遍，tracker 理论上不应该再给出 Rejected；
        // 这里仍然防御性地检查一次并把返回值改成 false（而不是无条件 true），
        // 不能让"参数非法但状态已经部分应用"被上报成功。
        if (ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Rejected))
        {
            applyMaskSideEffects(mask);
            lastIdentityFailure_ = NavStatus::Unavailable;
            return false;
        }

        applyMaskSideEffects(mask);
        return true;
    }

    NavStatus WorkbenchTarget::lastIdentityFailure() const noexcept
    {
        return lastIdentityFailure_;
    }

    bool WorkbenchTarget::requestScope(ksword::memwb::Scope scope)
    {
        IdentityRequest request;
        request.scope = scope;
        return requestIdentity(request, LeaveReason::ScopeChange);
    }

    bool WorkbenchTarget::requestChannel(ksword::memwb::Channel channel)
    {
        // D5 修复：不再接受/转发 ddmaGeneration 参数——通道为 Ddma 时
        // requestIdentity 内部自己向 services_ 要当前代次。
        IdentityRequest request;
        request.channel = channel;
        return requestIdentity(request, LeaveReason::ChannelChange);
    }

    bool WorkbenchTarget::requestPin(std::uint32_t pid, std::uint64_t expectCreateTime)
    {
        // N1 修复：复位提到函数开头，覆盖"pid==0"这条早返回路径——旧写法只有
        // 走到 requestIdentity 内部才会重置 lastIdentityFailure_，pid==0 直接
        // return false 时完全不碰这个成员，导致它残留上一次失败的陈旧原因（甚至
        // 可能是 Ok，让"失败却读到 Ok"的矛盾状态被外部看到）。
        lastIdentityFailure_ = NavStatus::Ok;
        if (pid == 0)
        {
            // 0 不是合法 PID；调用方想回到跟随应调用 requestFollowDock()，不是传 0。
            lastIdentityFailure_ = NavStatus::Unavailable;
            return false;
        }
        IdentityRequest request;
        request.pinPid = pid;
        request.expectCreateTime = expectCreateTime; // D6：0 表示不校验，兼容旧调用点。
        return requestIdentity(request, LeaveReason::PinChange);
    }

    bool WorkbenchTarget::requestFollowDock()
    {
        IdentityRequest request;
        request.pinPid = 0;
        return requestIdentity(request, LeaveReason::PinChange);
    }

    void WorkbenchTarget::requestReload()
    {
        // 重读不改变身份，不经过离开守卫；Reload 位恒被设置，哪怕会话字段没变。
        const ksword::memwb::TargetChange mask = tracker_.Reload();
        applyMaskSideEffects(mask);
    }

    void WorkbenchTarget::noteContentChanged()
    {
        tracker_.NoteContentChanged();
    }

    void WorkbenchTarget::applyMaskSideEffects(ksword::memwb::TargetChange mask)
    {
        if (mask == ksword::memwb::TargetChange::None)
        {
            return;
        }
        if (ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Rejected))
        {
            // 含 Rejected 位：被拒绝的那一维度 tracker 状态没变，但 mask 里若还
            // 混有其它真实身份位（理论上不该发生——D7 的入口校验已经在
            // requestIdentity 里把越界枚举挡在最前面；这里仍然用 HasChange 而不是
            // 精确相等防御性处理），说明其它维度已经真的生效了。不管哪种情形都
            // 不发 sessionChanged：调用方（requestIdentity）已经把这次整体请求的
            // 返回值改成 false，不应该再看到一个"成功"的信号。
            qWarning("WorkbenchTarget: 目标变更的某一维度被拒绝（参数非法）");
            return;
        }

        // 可疑点 #3 修复（顺序）：先做"身份变了就同步 BeginLoad 新所有者"这一步，
        // 再发 sessionChanged。旧顺序是先发信号、再 BeginLoad；如果订阅者在
        // sessionChanged 的槅里同步调用 evaluate()，会看到模块目录仍然挂着上一个
        // 所有者的 Ready 结果，对新会话给出一个张冠李戴的答案，而不是正确的
        // "正在加载"。调换顺序后，信号发出时目录已经处于新所有者的 Loading 状态。
        const ksword::memwb::MemoryTargetSession& current = tracker_.Session();
        if (ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Process)
            && current.scope == ksword::memwb::Scope::ProcessVirtual)
        {
            refreshProcessModules(/*force=*/true);
        }
        if (ksword::memwb::HasChange(mask, ksword::memwb::TargetChange::Scope)
            && current.scope == ksword::memwb::Scope::KernelVirtual)
        {
            refreshKernelModules(/*force=*/false);
        }

        emit sessionChanged(static_cast<quint32>(mask));
    }

    // ------------------------------------------------------------
    // 模块刷新的公开入口（force=true，无条件重新发起；异步细节见 .Modules.cpp）
    // ------------------------------------------------------------

    void WorkbenchTarget::refreshModules()
    {
        const ksword::memwb::Scope scope = tracker_.Session().scope;
        if (scope == ksword::memwb::Scope::ProcessVirtual)
        {
            refreshProcessModules(/*force=*/true);
        }
        else if (scope == ksword::memwb::Scope::KernelVirtual)
        {
            refreshKernelModules(/*force=*/true);
        }
        // Physical 范围没有模块，空操作。
    }

    // ------------------------------------------------------------
    // 地址表达式求值 / 进程文本匹配
    // ------------------------------------------------------------

    ksword::memwb::AddressEval WorkbenchTarget::evaluate(const QString& text)
    {
        ServicesPointerReader reader(services_);
        const Utf8View utf8(text);
        // session() 会先拉取一次 DDMA 代次，保证求值用的是最新会话。
        return ksword::memwb::EvaluateForSession(
            utf8.view, session(), &processDirectory_, &kernelDirectory_, &reader);
    }

    ksword::memwb::ProcessMatchResult WorkbenchTarget::matchProcess(const QString& text) const
    {
        const std::vector<ksword::memwb::ProcessCandidate> candidates = services_->processCandidates();
        const Utf8View utf8(text);
        return ksword::memwb::MatchProcessText(utf8.view, candidates);
    }

    // ------------------------------------------------------------
    // 存活探测
    // ------------------------------------------------------------

    void WorkbenchTarget::checkLiveness()
    {
        // 可疑点 #8 修复：内核/物理范围没有"进程目标"的存活概念；即便此刻 Dock
        // 仍附着某个进程，那个进程也不是当前会话的目标，不应该拿它来回答
        // "目标是否存活"——统一报告 Unknown（updateLiveness 内部的等值检查保证
        // 只在真的发生变化时才发信号，不会每次调用都重复发出）。
        if (tracker_.Session().scope != ksword::memwb::Scope::ProcessVirtual)
        {
            updateLiveness(LivenessState::Unknown);
            return;
        }
        void* handle = (tracker_.FollowMode() == ksword::memwb::MemoryTargetTracker::Follow::Pinned)
            ? pinnedAnchorHandle_
            : dockAnchorHandle_;
        if (!handle)
        {
            updateLiveness(LivenessState::Unknown);
            return;
        }
        const std::optional<bool> alive = QueryAnchorAlive(handle);
        if (!alive)
        {
            return; // 查询调用本身失败，保留上一次已知状态，不要误报"已退出"。
        }
        updateLiveness(*alive ? LivenessState::Alive : LivenessState::Exited);
    }

    void WorkbenchTarget::updateLiveness(LivenessState state)
    {
        if (state == lastLiveness_)
        {
            return;
        }
        lastLiveness_ = state;
        // 独立页确认退出后使所有在途读取/确认前事务变旧，但保留显示快照。
        if (!policy_.allowFollowDock && state == LivenessState::Exited)
        {
            tracker_.Reload();
        }
        emit livenessChanged(static_cast<int>(state));
    }
}
