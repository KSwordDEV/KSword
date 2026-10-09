// ============================================================
// WorkbenchWriteController.cpp
// 作用：
// - WorkbenchWriteController.h 声明的主体实现：构造/销毁、六个装配 setter、写入
//   模式转发、UI 确认抑制开关、onEditCompleted/commitPendingNow 两条提交入口、
//   isCommitting、以及撤销/重做四个转发方法（真正的回放算法在
//   WorkbenchWriteController.Undo.cpp 的 WorkbenchUndoCoordinator 里）。
// - PendingStage 票据系统（beginPendingStage/cancelPendingStage/
//   notifyWindowMayCover）拆在 WorkbenchWriteController.PendingStage.cpp。
// - 本文件遵守 D1-D4 修复后的重入保护与晚绑定防御（见 WorkbenchWriteController.h
//   文件头的"D1-D4 修复"一节），头文件已按主会话裁决解冻：PendingStage 票据表
//   （pendingStages_）、重入深度计数（commitDepth_）等都是直接私有成员，不再
//   使用 Internal.h 的"以 this 指针为键的关联表"。代次计数器本身不再由本类
//   另镶一份（原 localRevisions_ 已删除），改为直接引用
//   target_->revisions()（见 ensureTransaction 的构造语句）。
// ============================================================

#include "WorkbenchWriteController.h"
#include "WorkbenchWriteController.Internal.h"
#include "WorkbenchWriteController.Undo.h"

#include <QDebug>

#include <algorithm>
#include <utility>

namespace ks::ui
{
    namespace
    {
        // TargetCheckedIoPort：仅在独立模式阻止退出/关闭后的事务读写。
        // 事务在 UI 线程同步调用本端口；普通工作台始终保留原端口行为。
        class TargetCheckedIoPort final : public ksword::memwb::IMemoryIoPort
        {
        public:
            // inner：真实端口；target：存活检测来源，仅以弱引用保留。
            TargetCheckedIoPort(std::unique_ptr<ksword::memwb::IMemoryIoPort> inner, WorkbenchTarget* target)
                : inner_(std::move(inner)), target_(target)
            {
            }

            ksword::memwb::IoLimits Limits(const ksword::memwb::MemoryTargetSession& session) const override
            {
                return inner_->Limits(session);
            }

            // Read：读前核验独立目标状态，失败不调用后端。
            ksword::memwb::IoReadResult Read(const ksword::memwb::MemoryTargetSession& session,
                const std::uint64_t address, const std::uint64_t length) override
            {
                if (!canAccess(session))
                {
                    ksword::memwb::IoReadResult result;
                    result.status = ksword::memwb::IoReadStatus::Failed;
                    result.failure = "目标进程已退出或内存会话已关闭";
                    return result;
                }
                return inner_->Read(session, address, length);
            }

            // Write：确认框之后仍逐次核验，拒绝新写入而不触碰已退出目标。
            ksword::memwb::IoWriteResult Write(const ksword::memwb::MemoryTargetSession& session,
                const std::uint64_t address, const std::vector<std::uint8_t>& bytes, const bool approved) override
            {
                if (!canAccess(session))
                {
                    ksword::memwb::IoWriteResult result;
                    result.failure = "目标进程已退出或内存会话已关闭";
                    return result;
                }
                return inner_->Write(session, address, bytes, approved);
            }

        private:
            bool canAccess(const ksword::memwb::MemoryTargetSession& session) const
            {
                // 模式由目标策略表达；默认 allowFollowDock=true 的旧视图不受影响。
                return target_ && (target_->policy().allowFollowDock
                    || (session.pid != 0U && target_->livenessState() != LivenessState::Exited));
            }
            std::unique_ptr<ksword::memwb::IMemoryIoPort> inner_; // 被包装端口的独占所有权。
            QPointer<WorkbenchTarget> target_;                 // 目标销毁时自动失效。
        };
    }
    using ksword::memwb::CommitOutcome;
    using ksword::memwb::CommitReport;
    using ksword::memwb::DiffBlock;
    using ksword::memwb::IAuditSink;
    using ksword::memwb::IConfirmationSink;
    using ksword::memwb::IKernelMutationPort;
    using ksword::memwb::IMemoryIoPort;
    using ksword::memwb::MemoryDiffOverlay;
    using ksword::memwb::MemoryIoByteStore;
    using ksword::memwb::MemoryWriteTransaction;
    using ksword::memwb::ModeSwitchDecision;
    using ksword::memwb::ModeSwitchResult;
    using ksword::memwb::ModeSwitchStatus;
    using ksword::memwb::WriteMode;

    // ------------------------------------------------------------
    // 构造 / 销毁
    // ------------------------------------------------------------

    WorkbenchWriteController::WorkbenchWriteController(QObject* parent)
        : QObject(parent)
    {
        // 头文件解冻之后，票据表（pendingStages_）、重入深度计数（commitDepth_）
        // 等都是直接成员，随本对象一起默认构造，不需要像以前那样手动在构造函数
        // 体里向关联表插入一条记录；代次计数器不是本类的成员，构造时无需处理
        // （见 target_->revisions() 的说明）。
    }

    WorkbenchWriteController::~WorkbenchWriteController()
    {
        // unique_ptr 成员（undo_/transaction_/byteStore_/kernelPort_/port_）在本
        // 函数体执行完之后、基类 QObject 析构之前按声明逆序自动销毁；接口文档
        // §1 已经论证过这个顺序为什么是安全的（它们持有的 overlay_/target_ 都是
        // 非拥有指针，析构不会触碰已经失效的对象）。pendingStages_ 里残留的
        // QTimer* 是 this 的子对象，Qt 的父子关系会在基类析构阶段级联删除它们，
        // 这里不需要逐个 delete。
    }

    // ------------------------------------------------------------
    // 六个装配 setter
    // ------------------------------------------------------------
    // **D1/D2 修复**：transaction_ 一旦惰性构造成功，就已经把当时的 overlay_/
    // target_/confirmation_/audit_ 以 C++ 引用的形式永久绑定进去（construct 一次，
    // 之后 ensureTransaction() 短路返回 true，不会重新绑定）。事后再调用这四个
    // setter 换成不同的值，transaction_ 内部的引用不会跟着变——旧实现对此没有
    // 任何防御，换成 nullptr 之后下一次 Commit 就是空指针解引用崩溃（见
    // review-wpJ4.md D1/D2，探针实测 0xC0000005）。下面四个 setter 统一规则：
    // transaction_ 已存在时，新值与当前值不同就拒绝（忽略调用并 qWarning 记一条
    // 诊断日志，不用 Q_ASSERT——断言在 Release 构建里不生效，这里要的是任何构建
    // 配置下都不崩溃）；新值与当前值相同是空操作，不警告。

    void WorkbenchWriteController::setOverlay(MemoryDiffOverlay* overlay)
    {
        if (transaction_ && overlay_ != overlay)
        {
            qWarning() << "WorkbenchWriteController::setOverlay: transaction_ 已构造，"
                          "拒绝晚绑定换成不同的 overlay（D1/D2 修复：防止悬空引用崩溃）";
            return;
        }
        overlay_ = overlay;
    }

    void WorkbenchWriteController::setTarget(WorkbenchTarget* target)
    {
        if (transaction_ && target_ != target)
        {
            qWarning() << "WorkbenchWriteController::setTarget: transaction_ 已构造，"
                          "拒绝晚绑定换成不同的 target（D1/D2 修复：防止悬空引用崩溃）";
            return;
        }
        if (target_ == target)
        {
            return; // 换成相同的值：空操作，不需要重新订阅信号。
        }
        // 换 target_：若之前已经连过一个不同对象的信号，先断开，避免旧连接的
        // lambda 在旧对象仍存活、但已经不是本类当前目标的情况下继续触发并污染
        // 撤销协调器的身份串。QObject 的 destroyed() 本来就会在对象销毁时自动
        // 断开连接，这里的显式断开只是为了"换 target_ 但旧对象还活着"这个更
        // 罕见的场景。
        if (target_ != nullptr)
        {
            QObject::disconnect(target_, nullptr, this, nullptr);
        }
        target_ = target;
        if (target_ == nullptr)
        {
            return;
        }
        // 订阅 sessionChanged：target_->revisions() 内部的来源代次已经由
        // WorkbenchTarget 自己的 MemoryTargetTracker 在 Reload()/身份变更时原地
        // 递增过了（见头文件 target_->revisions() 的成员注释），本类不需要、也
        // 不应该再手动 BumpSource 一份镶像——这里只负责把身份变化转发给撤销
        // 协调器：bindTarget 内部用 SameTarget 判断是否真的变了，真正变化时清空
        // 历史并通知装配层撤销/重做可用性可能变化。
        QObject::connect(target_, &WorkbenchTarget::sessionChanged, this,
            [this](quint32 /*changeMask*/)
            {
                if (undo_)
                {
                    const bool clearedNonEmpty = undo_->bindTarget(target_->session());
                    undo_->setIdentityKey(detail::ComputeSessionIdentityKey(target_->session()));
                    if (clearedNonEmpty)
                    {
                        // 没有专门的"撤销历史已清空"提示信号（见报告接口缺口），
                        // 借用最接近的既有信号通知装配层"可用性可能变了"。
                        emit undoRedoAvailabilityChanged();
                    }
                }
            });
    }

    void WorkbenchWriteController::setConfirmationSink(IConfirmationSink* sink)
    {
        if (transaction_ && confirmation_ != sink)
        {
            qWarning() << "WorkbenchWriteController::setConfirmationSink: transaction_ 已构造，"
                          "拒绝晚绑定换成不同的确认接口（D1/D2 修复：防止悬空引用崩溃）";
            return;
        }
        confirmation_ = sink;
    }

    void WorkbenchWriteController::setAuditSink(IAuditSink* sink)
    {
        if (transaction_ && audit_ != sink)
        {
            qWarning() << "WorkbenchWriteController::setAuditSink: transaction_ 已构造，"
                          "拒绝晚绑定换成不同的审计接收器（D1/D2 修复：防止悬空引用崩溃）";
            return;
        }
        audit_ = sink;
    }

    void WorkbenchWriteController::setIoPortFactory(IoPortFactory factory)
    {
        ioPortFactory_ = std::move(factory);
    }

    void WorkbenchWriteController::setKernelMutationPortFactory(KernelPortFactory factory)
    {
        kernelPortFactory_ = std::move(factory);
    }

    void WorkbenchWriteController::setWriteValidationCallback(WriteValidationFn callback)
    {
        writeValidationCallback_ = std::move(callback);
        if (byteStore_) byteStore_->SetWriteValidationCallback(writeValidationCallback_);
    }

    void WorkbenchWriteController::setRereadRangeCallback(RereadRangeFn callback)
    {
        rereadRangeCallback_ = std::move(callback);
    }

    void WorkbenchWriteController::setTickProvider(TickProviderFn provider)
    {
        tickProvider_ = std::move(provider);
    }

    void WorkbenchWriteController::setCanvasReadOnlyHook(CanvasReadOnlyHook hook)
    {
        canvasReadOnlyHook_ = std::move(hook);
    }

    void WorkbenchWriteController::setCommitSuspendHook(CommitSuspendHook hook)
    {
        commitSuspendHook_ = std::move(hook);
    }

    // ------------------------------------------------------------
    // byteStore() / ensureTransaction()：两个已在头文件声明的私有惰性构造方法。
    // ------------------------------------------------------------

    MemoryIoByteStore* WorkbenchWriteController::byteStore()
    {
        if (byteStore_)
        {
            return byteStore_.get();
        }
        if (!ioPortFactory_ || target_ == nullptr)
        {
            // 工厂未设置，或者没有目标（取不到 session() 的稳定引用）：不能构造。
            return nullptr;
        }
        port_ = ioPortFactory_();
        if (!port_)
        {
            // 工厂本身返回了空指针：同样当作"端口不可用"处理，不假装成功。
            return nullptr;
        }
        // 包装事务端口而不是只禁按钮，覆盖暂存应用和历史回放的实际 I/O。
        port_ = std::make_unique<TargetCheckedIoPort>(std::move(port_), target_);
        if (kernelPortFactory_ && !kernelPort_)
        {
            // 内核端口工厂是可选的；工厂调用本身返回空指针也接受——语义上等价于
            // "没有设置内核端口工厂"，写入时走 MemoryIoByteStore 文档里"内核范围+
            // 标准驱动通道但没有内核端口"的显式失败分支，不会静默降级到别的写法。
            kernelPort_ = kernelPortFactory_();
        }
        byteStore_ = std::make_unique<MemoryIoByteStore>(
            *port_, target_->session(), kernelPort_.get());
        byteStore_->SetWriteValidationCallback(writeValidationCallback_);
        return byteStore_.get();
    }

    bool WorkbenchWriteController::ensureTransaction()
    {
        if (transaction_)
        {
            return true;
        }
        if (overlay_ == nullptr || target_ == nullptr || confirmation_ == nullptr || audit_ == nullptr)
        {
            // 装配顺序错误：缺 overlay/target/确认接口/审计接收器任一都不弹框，
            // 只报错给调用方（头文件注释："装配顺序错误是实现缺陷不是用户可见的
            // 运行期状况"）。审计接收器是审阅后新增的强制项——未设置时必须失败，
            // 绝不退回空审计（"跳过 UI 确认不跳过审计"是不变式）。
            return false;
        }
        MemoryIoByteStore* store = byteStore();
        if (store == nullptr)
        {
            return false;
        }
        // 代次计数器直接引用 target_->revisions()（WorkbenchTarget 内部
        // MemoryTargetTracker 的唯一真身，不是本类另镶的一份拷贝）——D1/D2 已经
        // 保证 transaction_ 构造成功之后 target_ 不可能再被换成不同对象，这个
        // 引用在 transaction_ 整个生命周期内稳定，不会悬空。
        transaction_ = std::make_unique<MemoryWriteTransaction>(
            *overlay_, target_->session(), target_->revisions(),
            *store, *confirmation_, *audit_);
        // 把 setUiConfirmSuppressed 在构造前缓存的值立即应用——缓存值不得被这条
        // 失败/成功路径丢掉（头文件注释原文）。
        transaction_->SetUiConfirmSuppressed(pendingUiConfirmSuppressed_);

        // 顺带惰性构造撤销协调器：它的依赖（session/revisions/store/confirmation/
        // audit）是 transaction_ 依赖的子集（少一个 overlay_），既然 transaction_
        // 刚刚构造成功，这些依赖必然齐备，一次性把 undo_ 也建好，避免
        // onEditCompleted/commitPendingNow 成功提交之后却因为 undo_ 还没构造而
        // 记不了账。suppressedProvider 转发 uiConfirmSuppressed()（COMMON 裁决第
        // 3 项：撤销/重做的临时事务继承控制器当前的确认抑制状态）。
        if (!undo_)
        {
            undo_ = std::make_unique<WorkbenchUndoCoordinator>(
                target_->session(), target_->revisions(), *store,
                *confirmation_, *audit_,
                [this]() { return detail::ComputeTick(tickProvider_); },
                [this]() { return uiConfirmSuppressed(); });
            undo_->bindTarget(target_->session());
            undo_->setIdentityKey(detail::ComputeSessionIdentityKey(target_->session()));
        }
        return true;
    }

    // ------------------------------------------------------------
    // 写入模式：薄包装，直接转发 MemoryWriteTransaction。
    // ------------------------------------------------------------

    WriteMode WorkbenchWriteController::mode() const
    {
        if (transaction_)
        {
            return transaction_->Mode();
        }
        // 事务尚未构造（装配顺序未完成）时的安全默认值：与 MemoryWriteTransaction
        // 自身的默认构造初值一致，不会给调用方一个"假的"当前模式。
        return WriteMode::Immediate;
    }

    ModeSwitchStatus WorkbenchWriteController::requestModeSwitch(WriteMode newMode)
    {
        if (!ensureTransaction())
        {
            // 防御性兜底：没有事务可切。借用语义最接近的 Busy（"现在不能切，稍后
            // 再试"），不代表真的有 Commit 在进行——生产环境按正确顺序装配后不会
            // 走到这里。
            return ModeSwitchStatus::Busy;
        }
        return transaction_->SetMode(newMode);
    }

    ModeSwitchResult WorkbenchWriteController::resolveModeSwitch(ModeSwitchDecision decision)
    {
        // 结果通知可能同步销毁宿主；所有收尾操作都先核对自身存活。
        const QPointer<WorkbenchWriteController> self(this);
        if (!ensureTransaction())
        {
            ModeSwitchResult result;
            result.status = ModeSwitchStatus::Busy;
            return result;
        }
        if (decision != ModeSwitchDecision::ApplyThenSwitch)
        {
            // DiscardThenSwitch / Cancel 不会触发 Commit，不需要只读守卫，也没有
            // CommitReport 要处理。真实丢弃仍须推进内容代次并清掉待写提示；没有
            // 待决切换、取消或空 overlay 都不能虚构内容变化。
            const bool hadPatches = overlay_ != nullptr && overlay_->HasPendingPatches();
            const ModeSwitchResult result = transaction_->ResolveModeSwitch(decision);
            if (decision == ModeSwitchDecision::DiscardThenSwitch && hadPatches
                && result.status == ModeSwitchStatus::Switched)
            {
                target_->noteContentChanged();
                detail::EmitPendingPatchesChanged(this, overlay_);
            }
            // pendingPatchesChanged 可同步删除宿主；此后只返回栈上结果。
            return result;
        }
        // **D3/D4 修复**：ApplyThenSwitch 分支内部会真的尝试一次 Commit，受统一
        // 的重入深度保护——已经有 Commit 在进行（commitDepth_ > 0，可能是外层
        // 确认框的事件循环还没返回）时直接拒绝，不嵌套执行。
        if (commitDepth_ > 0)
        {
            emit commitRejectedBusy(QStringLiteral("resolveModeSwitch"));
            ModeSwitchResult result;
            result.status = ModeSwitchStatus::Busy;
            return result;
        }
        // ApplyThenSwitch：内部会先尝试提交一次，按"提交期间"的不变式包一层只读
        // 守卫，并在成功时走与 onEditCompleted/commitPendingNow 相同的收尾。
        target_->session(); // 提交前拉一次最新 DDMA 代次（见 self-check 清单 (f)）。
        const std::vector<DiffBlock> preCommitBlocks = overlay_ != nullptr
            ? overlay_->DiffBlocks()
            : std::vector<DiffBlock>{};
        ModeSwitchResult result;
        {
            detail::CommitReadOnlyGuard guard(commitDepth_, canvasReadOnlyHook_, commitSuspendHook_);
            result = transaction_->ResolveModeSwitch(decision);
        }
        if (result.commitReport.has_value())
        {
            detail::HandleCommitReport(
                this, target_, undo_.get(), rereadRangeCallback_, *result.commitReport, preCommitBlocks);
            if (!self)
            {
                return result;
            }
            detail::EmitPendingPatchesChanged(this, overlay_);
        }
        return result;
    }

    // ------------------------------------------------------------
    // UI 确认抑制开关
    // ------------------------------------------------------------

    void WorkbenchWriteController::setUiConfirmSuppressed(bool suppressed)
    {
        // 始终缓存一份，不管 transaction_ 是否已经存在——ensureTransaction() 的
        // 失败路径不得把这份缓存值丢掉（头文件注释原文）。
        pendingUiConfirmSuppressed_ = suppressed;
        if (transaction_)
        {
            transaction_->SetUiConfirmSuppressed(suppressed);
        }
    }

    bool WorkbenchWriteController::uiConfirmSuppressed() const
    {
        if (transaction_)
        {
            return transaction_->UiConfirmSuppressed();
        }
        return pendingUiConfirmSuppressed_;
    }

    // ------------------------------------------------------------
    // onEditCompleted / commitPendingNow：W1-W3 的两条入口。
    // ------------------------------------------------------------

    void WorkbenchWriteController::onEditCompleted()
    {
        // 结果通知可能同步销毁宿主；所有收尾操作都先核对自身存活。
        const QPointer<WorkbenchWriteController> self(this);
        if (target_ == nullptr)
        {
            // 没有目标：理论上编辑手势发生之前必然已经有目标，这里只做防御，不
            // 崩溃也不弹框。
            return;
        }
        // 一次编辑手势已经完成（画布早已经把补丁 Stage 进 overlay_），内容代次
        // +1：推进真实 target_ 的代次——target_->revisions() 内部的计数器原地
        // 跟着变，transaction_/undo_ 持有的引用立刻能看到，不需要本类另外维护
        // 一份镶像。无论下面是否因为"忙"被拒绝，这个补丁已经真实地落在
        // overlay_ 里了，代次必须先推进——这样如果外层正在进行的那次 Commit
        // 随后做 Stale 复核，能正确发现"确认期间内容又变了"。
        target_->noteContentChanged();
        if (commitDepth_ > 0)
        {
            // **D3 修复，第二轮审核 B-1/B-2 裁决后简化**：已经有一次 Commit 在
            // 进行（典型场景：外层 ConfirmUi 的模态事件循环还没返回，
            // PendingStage 的超时计时器或地址簿编辑在这个窗口里又触发了一次
            // onEditCompleted）。不嵌套发起第二次 Commit，也**不**自动替用户
            // 补跑一次——早期修复曾经置一个"补跑请求"标记，等外层结束后自动
            // 合并重跑一次，但这个机制完全不看外层结果（哪怕用户刚在确认框里
            // 点了"否"也会被无视、立刻又弹一次几乎相同的确认框），且这个标记
            // 只在本函数内被消费，经由其它入口触发的忙碌拒绝会让它永久残留、
            // 污染下一次毫不相关的正常编辑，已被主会话裁决整个删掉。这里只发
            // 一次 commitRejectedBusy 供装配层提示，直接返回——补丁继续以
            // "待写入"状态留在 overlay_ 里，用户下一次真正的新编辑或主动点
            // "应用"时会被一次新的 Commit 一并处理（Commit() 本来就是对
            // overlay_ 当前全部 DiffBlocks 整体处理，不需要本类另外补一次）。
            emit commitRejectedBusy(QStringLiteral("onEditCompleted"));
            return;
        }
        if (!ensureTransaction())
        {
            // 装配顺序错误：不弹框、只报错（头文件注释原文），直接返回。
            return;
        }
        if (transaction_->Mode() != WriteMode::Immediate)
        {
            // 暂存模式：只需要让会话条知道"待写入"的字节/块数变化，不触碰 store。
            detail::EmitPendingPatchesChanged(this, overlay_);
            return;
        }
        // 立即模式：走一次完整 Commit。提交前先拉一次会话（可能同步刷新 DDMA
        // 代次，确保 transaction_ 读到的 session_ 是最新的）。**第二轮审核
        // B-1/B-2 裁决后简化**：只走这一次，不再有"合并补跑"——上面的忙碌分支
        // 已经直接返回，走到这里时 commitDepth_ 必然是 0，不需要额外的重跑
        // 循环。
        target_->session();
        const std::vector<DiffBlock> preCommitBlocks = overlay_->DiffBlocks();
        CommitReport report;
        {
            detail::CommitReadOnlyGuard guard(commitDepth_, canvasReadOnlyHook_, commitSuspendHook_);
            auto optionalReport = transaction_->OnEditCompleted();
            report = optionalReport.value_or(CommitReport{});
        }
        detail::HandleCommitReport(
            this, target_, undo_.get(), rereadRangeCallback_, report, preCommitBlocks);
        if (!self)
        {
            return;
        }
        detail::EmitPendingPatchesChanged(this, overlay_);
    }

    CommitAttempt WorkbenchWriteController::commitPendingNow()
    {
        // 结果通知可能同步销毁宿主；所有收尾操作都先核对自身存活。
        const QPointer<WorkbenchWriteController> self(this);
        // **D3 修复**：已经有一次 Commit 在进行时直接拒绝，不嵌套执行。
        if (commitDepth_ > 0)
        {
            emit commitRejectedBusy(QStringLiteral("commitPendingNow"));
            return CommitAttempt{CommitEntryStatus::Busy, CommitReport{}};
        }
        if (!ensureTransaction())
        {
            // 防御性兜底：默认报告（outcome=NoChange）。
            return CommitAttempt{CommitEntryStatus::Started, CommitReport{}};
        }
        target_->session();
        const std::vector<DiffBlock> preCommitBlocks = overlay_->DiffBlocks();
        CommitReport report;
        {
            detail::CommitReadOnlyGuard guard(commitDepth_, canvasReadOnlyHook_, commitSuspendHook_);
            report = transaction_->Commit();
        }
        detail::HandleCommitReport(this, target_, undo_.get(), rereadRangeCallback_, report, preCommitBlocks);
        if (!self)
        {
            return CommitAttempt{CommitEntryStatus::Started, report};
        }
        detail::EmitPendingPatchesChanged(this, overlay_);
        return CommitAttempt{CommitEntryStatus::Started, report};
    }

    bool WorkbenchWriteController::isCommitting() const
    {
        if (commitDepth_ > 0)
        {
            // 覆盖撤销/重做的临时提交——它用的是另一个独立的
            // MemoryWriteTransaction，transaction_->IsBusy() 并不知道它的存在，
            // 必须靠本类自己这一个统一的重入深度计数。
            return true;
        }
        if (transaction_)
        {
            return transaction_->IsBusy();
        }
        return false;
    }

    // ------------------------------------------------------------
    // 撤销 / 重做：转发给 WorkbenchUndoCoordinator，算法见 .Undo.cpp。
    // ------------------------------------------------------------

    bool WorkbenchWriteController::canUndo() const
    {
        return undo_ && undo_->canUndo();
    }

    bool WorkbenchWriteController::canRedo() const
    {
        return undo_ && undo_->canRedo();
    }

    CommitEntryStatus WorkbenchWriteController::undo()
    {
        // 结果通知可能同步销毁宿主；所有收尾操作都先核对自身存活。
        const QPointer<WorkbenchWriteController> self(this);
        // **D4 修复**：已经有一次 Commit 在进行（包括外层编辑自己的确认框还没
        // 返回）时直接拒绝，不新建临时 scratch 事务、不弹第二个确认框，也不会
        // 把正在等待确认的那次编辑静默吞掉。
        if (commitDepth_ > 0)
        {
            emit commitRejectedBusy(QStringLiteral("undo"));
            return CommitEntryStatus::Busy;
        }
        // 撤销不需要 overlay_（它用自己的临时 scratch overlay），但复用
        // ensureTransaction() 顺带把 undo_ 构造出来更简单：实际装配顺序里
        // overlay_ 总是在任何提交/撤销发生之前就已经设置好（WorkbenchHexPane
        // 创建 overlay 在先），这个理论上的"更严格"不会在真实场景触发。
        if (!ensureTransaction() || target_ == nullptr)
        {
            return CommitEntryStatus::Started;
        }
        const bool canUndoBefore = undo_->canUndo();
        const bool canRedoBefore = undo_->canRedo();
        target_->session(); // 撤销前先拉一次最新 DDMA 代次。
        UndoReplayResult replay;
        {
            detail::CommitReadOnlyGuard guard(commitDepth_, canvasReadOnlyHook_, commitSuspendHook_);
            const auto resetHistory = [self, previous = historyReplay_](WorkbenchWriteController*) {
                if (self) self->historyReplay_ = previous;
            };
            const std::unique_ptr<WorkbenchWriteController, decltype(resetHistory)> historyGuard(this, resetHistory);
            historyReplay_ = true;
            replay = undo_->undo();
        }
        if (replay.commitAttempted)
        {
            // 已落地的部分也是真实写入；失败不能沿用写前内容代次。仅拒绝确认或
            // 写前复核失败且未写入时不推进，日志游标仍由协调器只在成功时移动。
            if (replay.report.bytesWritten != 0)
            {
                target_->noteContentChanged();
            }
            // **COMMON 裁决第 3 项**：W4 收尾——复用 HandleCommitReport 处理
            // commitFinished/commitFailed/scratchAreaDirtyReported/needsReread/
            // 局部重读，这些行为与正常 Commit 完全一致。undo 参数传 nullptr：
            // 撤销/重做不应该向 journal 再记一步（HandleCommitReport 内部
            // "undo != nullptr 才 record"的短路恰好满足，不需要额外改动）。
            std::vector<DiffBlock> landedBlocks(1);
            landedBlocks[0].address = replay.address;
            landedBlocks[0].before = replay.before;
            landedBlocks[0].after = replay.after;
            detail::HandleCommitReport(
                this, target_, nullptr, rereadRangeCallback_, replay.report, landedBlocks);
            if (!self)
            {
                return CommitEntryStatus::Started;
            }
        }
        if (undo_->canUndo() != canUndoBefore || undo_->canRedo() != canRedoBefore)
        {
            emit undoRedoAvailabilityChanged();
        }
        return CommitEntryStatus::Started;
    }

    CommitEntryStatus WorkbenchWriteController::redo()
    {
        // 结果通知可能同步销毁宿主；所有收尾操作都先核对自身存活。
        const QPointer<WorkbenchWriteController> self(this);
        if (commitDepth_ > 0)
        {
            emit commitRejectedBusy(QStringLiteral("redo"));
            return CommitEntryStatus::Busy;
        }
        if (!ensureTransaction() || target_ == nullptr)
        {
            return CommitEntryStatus::Started;
        }
        const bool canUndoBefore = undo_->canUndo();
        const bool canRedoBefore = undo_->canRedo();
        target_->session();
        UndoReplayResult replay;
        {
            detail::CommitReadOnlyGuard guard(commitDepth_, canvasReadOnlyHook_, commitSuspendHook_);
            const auto resetHistory = [self, previous = historyReplay_](WorkbenchWriteController*) {
                if (self) self->historyReplay_ = previous;
            };
            const std::unique_ptr<WorkbenchWriteController, decltype(resetHistory)> historyGuard(this, resetHistory);
            historyReplay_ = true;
            replay = undo_->redo();
        }
        if (replay.commitAttempted)
        {
            // 重做失败后的部分落地同样推进内容代次；未写入的拒绝保持原代次。
            // 统一转发失败/重读/暂存区告警，不把失败回放当成成功消耗历史。
            if (replay.report.bytesWritten != 0)
            {
                target_->noteContentChanged();
            }
            std::vector<DiffBlock> landedBlocks(1);
            landedBlocks[0].address = replay.address;
            landedBlocks[0].before = replay.before;
            landedBlocks[0].after = replay.after;
            detail::HandleCommitReport(
                this, target_, nullptr, rereadRangeCallback_, replay.report, landedBlocks);
            if (!self)
            {
                return CommitEntryStatus::Started;
            }
        }
        if (undo_->canUndo() != canUndoBefore || undo_->canRedo() != canRedoBefore)
        {
            emit undoRedoAvailabilityChanged();
        }
        return CommitEntryStatus::Started;
    }

    // ------------------------------------------------------------
    // 自由函数：HandleCommitReport / EmitPendingPatchesChanged
    // 在 detail 命名空间下，签名见 WorkbenchWriteController.Internal.h。
    // ------------------------------------------------------------

    void detail::HandleCommitReport(
        WorkbenchWriteController* controller,
        WorkbenchTarget* target,
        WorkbenchUndoCoordinator* undo,
        const WorkbenchWriteController::RereadRangeFn& rereadCallback,
        const CommitReport& report,
        const std::vector<DiffBlock>& preCommitBlocks)
    {
        const QPointer<WorkbenchWriteController> self(controller);
        const QPointer<WorkbenchTarget> targetGuard(target);
        // 参数引用来自控制器成员；先复制，回调自身销毁宿主时仍由本次调用持有。
        const WorkbenchWriteController::RereadRangeFn reread = rereadCallback;
        // 先完成已落地前缀的内部记账，再发外部通知；槽函数可能销毁或重入宿主。
        // blocksWritten 个块就是 preCommitBlocks 里"按地址升序"的前 blocksWritten
        // 个——Commit() 按序写入、遇错即停，因此这些块是真正落地（写入且回读
        // 通过）的那些，哪怕整体 outcome 不是 Committed（例如"前两块成功、第
        // 三块 VerifyMismatch"只记两步，任务书 wpJ4 的要求）。对撤销/重做的调用
        // 场景，preCommitBlocks 恒为一个元素、report.blocksWritten 恒为 0 或 1，
        // 同一套逻辑天然适用。
        const std::size_t landedCount =
            std::min<std::size_t>(report.blocksWritten, preCommitBlocks.size());
        bool haveRange = false;
        std::uint64_t rangeStart = 0;
        std::uint64_t rangeEnd = 0;
        for (std::size_t index = 0; index < landedCount; ++index)
        {
            const DiffBlock& block = preCommitBlocks[index];
            const std::uint64_t blockEnd = block.address + static_cast<std::uint64_t>(block.after.size());
            if (!haveRange)
            {
                rangeStart = block.address;
                rangeEnd = blockEnd;
                haveRange = true;
            }
            else
            {
                rangeStart = std::min(rangeStart, block.address);
                rangeEnd = std::max(rangeEnd, blockEnd);
            }
            if (undo != nullptr)
            {
                undo->record(block.address, block.before, block.after);
            }
        }
        // 每次同步通知之后检查存活，避免使用已经释放的控制器或撤销协调器。
        controller->commitFinished(report);
        if (!self)
        {
            return;
        }
        if (report.outcome != CommitOutcome::Committed && report.outcome != CommitOutcome::NoChange)
        {
            controller->commitFailed(report);
            if (!self)
            {
                return;
            }
        }
        if (report.scratchAreaDirty)
        {
            controller->scratchAreaDirtyReported();
            if (!self)
            {
                return;
            }
        }
        if (report.needsReread && targetGuard)
        {
            targetGuard->requestReload();
            if (!self)
            {
                return;
            }
        }
        if (haveRange && reread)
        {
            // 合并范围只包含真正写入并核验的块；本地函数副本允许同步销毁宿主。
            reread(rangeStart, rangeEnd - rangeStart);
        }
    }

    void detail::EmitPendingPatchesChanged(
        WorkbenchWriteController* controller, MemoryDiffOverlay* overlay)
    {
        if (overlay == nullptr)
        {
            controller->pendingPatchesChanged(0, 0);
            return;
        }
        const std::vector<DiffBlock> blocks = overlay->DiffBlocks();
        controller->pendingPatchesChanged(
            overlay->PendingByteCount(), static_cast<quint64>(blocks.size()));
    }
}
