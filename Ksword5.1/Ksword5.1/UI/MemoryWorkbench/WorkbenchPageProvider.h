#pragma once

// ============================================================
// WorkbenchPageProvider.h
// 作用：
// - 实现 HexCanvas 的页提供者协议 ks::ui::IHexPageProvider（读路径 R1-R3，详见
//   docs/内存工作台Phase3装配接口.md §2）：画布请求一批页范围，本类在唯一的单线程
//   读池里调用 shared/evidence/memory_workbench/MemoryPageReader.h 的 ReadPages()，
//   结果排队回到 UI 线程后核对"来源代次"，核对通过才回填画布，否则取消在途登记
//   （不标不可读、不换通道——不变式 4）。
// - 本类自身**不实现**任何重试/分块/回退策略，那些策略全部封在
//   ksword::memwb::ReadPages 内部（见 MemoryPageReader.h）；本类只负责"开一条串行
//   读线程 + 把结果如实搬回 UI 线程 + 核对陈旧性 + 维护 DDMA 脏扇区闩锁 + 门控
//   （Gate）判定"。不变式 5："读线程=一条串行池，只持值"由本类的 ReadPool 落实：
//   工作线程里只能出现 IMemoryIoPort::Read 的参数（会话快照、地址、长度）与返回值
//   （PageReadResult），绝不能触碰 HexCanvas/QWidget 或任何 UI 线程对象。
//
// ------------------------------------------------------------
// 两条数轴（Wave 3 审核决策 2 落实；§5 决策 2 的坑逐条照办，不要再假设两者是一回事）
// ------------------------------------------------------------
// - canvasRevision：RequestPages 收到的 sourceRevision 参数本身，即 HexCanvas 自己
//   的 ++m_revisionCounter。只用于两件事：①原样回传给 canvas_->deliverPage /
//   deliverUnreadable（HexViewport::InsertPage 按这个值核对，不符就整页拒收）；
//   ②作 cancelPages 的守卫——cancelPages 本身没有代次参数，调用前必须自己核对
//   canvas_->sourceRevision() 是否仍等于当时登记的 canvasRevision，不等就什么都
//   不做（新地址空间已经自己 InvalidateAll，不需要也不能被旧任务的撤销波及）。
// - targetRevision：target_->capture() 取得的 rev.source（只在 RequestPages 开头
//   取一次，不在中途重复拉取）。用于①陈旧性核对（isSourceFresh）；②DDMA 脏扇区
//   闩锁的键。target_->requestReload()（用户显式重读/F5）会让这个值前进，因此也
//   会**自动释放**命中同一代次的闩锁——这是设计好的"显式重读=显式重试"，不是
//   疏漏；若宿主想让状态条的红 chip 跟着熄灭，必须自己在重读时另外清理，本类不
//   负责任何"chip"的显示，闩锁命中之后红 chip 的清除永远只由用户点击状态条的
//   "×"触发（§5 决策 2 第 5 点）。
// - 两条数轴互不要求对齐，也没有任何已存在的代码负责把它们对齐（那是未来
//   WorkbenchHexPane 的职责，不在本包范围）。
//
// ------------------------------------------------------------
// R1：Gate 判定与 TargetCapture
// ------------------------------------------------------------
// - RequestPages 开头先用 target_->capture() 取一份 {session, RevisionSnapshot}
//   快照（这一步在 UI 线程完成，会话字段随之被值拷贝，工作线程不会再触碰
//   WorkbenchTarget）；再用 gateInputsProvider_() 取运行期可用性输入，调用
//   ksword::memwb::EvaluateChannel(session.scope, session.channel, inputs)。
// - capture() 内部可能同步拉取一次 DDMA 代次并发出 WorkbenchTarget::sessionChanged
//   （通道为 Ddma 时）；订阅者的槽理论上可以同步改变 canvas_（换地址空间、甚至
//   setCanvas(nullptr)）。capture() 返回之后，本类绝不缓存任何指向 canvas_ 的裭
//   引用跨越这次回调——后续每次用到画布都重新读一次 canvas_ 这个 QPointer 成员
//   （§5 决策 2 第 6 点 / D9：这与 wpI 当年吃过的"同步重入后解引用已置空指针"
//   是同一类问题，修法也相同：不持有跨调用引用，回来后重新判空）。
// - Gate 判不可用：对 ranges 逐个调用 canvas_->cancelPages(range)（不是
//   deliverUnreadable——"不可用"与"目标本身读不到"是两件事），**去抖**发
//   channelUnavailable——同一个 GateReason 连续命中只在第一次发信号，Gate 变回
//   可用之后再次变不可用才会重新发一次（D2 续：否则宿主的状态条会跟着画布每次
//   重绘而反复闪烁/刷日志，参见下面"绝不自动重试"一节），直接返回，一次端口
//   调用都不发起。
//
// ------------------------------------------------------------
// R2：读线程与 DDMA 脏扇区闩锁
// ------------------------------------------------------------
// - 通过 Gate 之后，把 {ranges, capture, canvasRevision, targetRevision,
//   jobTicket, generation} 整体投给 ReadPool（唯一的单线程 QThreadPool，
//   maxThreadCount=1），工作线程逐个 range 调用
//   ksword::memwb::ReadPages(port_, capture.session, range.pageStart, range.pageCount,
//   &cancelFlag)。
// - 闩锁：若 session.channel==Ddma 且 scratchLatched_ 为真、且
//   scratchLatchedForRevision_==targetRevision（**目标轴**，决策 2 之前这里误用
//   的是画布轴），本次请求直接按"整体已知不可用"处理（cancelPages 全部 range，
//   不问端口，并发 retryBlockedByLatch 信号——撞上闩锁不再是"什么都不提示"的
//   静默拦截，D10/头文件契约统一改成这个新信号，不复用 channelUnavailable，
//   因为 Core 的 GateReason 里没有合适的"暂存区脏"原因，伪造一个会误导状态条
//   的翻译表）；否则正常发起读取，读取结果里任一 PageReadResult::scratchAreaDirty
//   为真则在 UI 线程落地时置位闩锁并发 scratchAreaDirtyLatched（只发一次，同
//   目标代次内重复命中不再发）。
// - 跨任务/同任务内的"通道中毒"标志（D3）：worker 与 provider 共享一个
//   atomic<bool>（由 ReadPool 持有，每次 RequestPages 成功提交新任务前重置为
//   false），任一 range 的读取结果报告 channelFailed 或 scratchAreaDirty，就在
//   工作线程里立即置位——同一任务里排在它后面的 range、以及**已经排在队列里、
//   尚未开始跑**的下一个任务，都会在各自的 range 开始之前看到这个标志并整段
//   跳过（不产生任何 PageRecord，落地时这段 range 什么都不做，页保持 Pending，
//   不会被误标成"已跳过=取消"而被 anyCancelled 整批吞掉——那是另一个独立的
//   聚合维度，见下）。因为唯一的单线程池保证了"同一个共享标志"在跨任务时也是
//   按真实执行顺序被设置/读取的，不需要额外加锁。
//
// ------------------------------------------------------------
// R3：陈旧性核对与回填
// ------------------------------------------------------------
// - 结果通过 Qt::QueuedConnection 排队回 UI 线程（本类内部的私有信号/槛，不在本头文件
//   暴露），落地时先核对任务代次（generation，见下），再用 isSourceFresh(targetRevision)
//   核对——只比较目标轴的来源代次，不比较内容代次：暂存/撤销只会让内容代次变，
//   不应该作废仍在途的页读取。
// - 核对通过：按 PageRecord::state 逐页调用 canvas_->deliverPage(...)（Valid/
//   PartiallyValid）或 canvas_->deliverUnreadable(...)（Unreadable），统一原样
//   带回**画布轴**（canvasRevision）；NotAttempted 的页一律 cancelPages（允许
//   画布之后重试）。核对不通过：整批 cancelPages（画布代次仍等于 canvasRevision
//   时才做，D6），什么都不回填。
// - channelFailed 为真：**不再 cancelPages**（D2 决策 a）——整批页保持 Pending，
//   并发 readFailed(canvasRevision, failure) 供状态条给出"可重试"的提示；本类
//   不自动重试，重试只能通过 retryFailedRanges 显式触发，或者宿主重建整个地址
//   空间（会自己 InvalidateAll）。这正是"绝不自动重试"这条规则真正落地的地方：
//   过去靠"画布恰好从不重绘"这个脆弱的前提，现在靠"provider 自己不碰端口"，
//   画布正常重绘（鼠标悬停高亮等）不会再触发任何额外的端口调用。
//
// ------------------------------------------------------------
// D4/D5/D6：任务代次与"被丢弃的任务必须补 cancelPages"
// ------------------------------------------------------------
// - cancelAllInFlight 会递增 generation_，并立即（同步，在该函数自己的调用栈里）
//   对 provider 自己记的"已提交、尚未落地"任务表逐条核对画布代次、补一次
//   cancelPages——这是"排队中、从未真正跑过 run()"的任务唯一能被通知到的机会
//   （它们会被 ReadPool 内部的 QThreadPool::clear() 直接删除，永远不会触发
//   onJobFinishedOnUiThread）。仍在跑的、或已经跑完但完成事件还卡在事件队列里
//   的任务，之后真的落地时会发现自己的 generation 已经落后于当前的 generation_，
//   同样被判定为"已作废"而不会被当成新鲜结果展示（这正是"读完但完成事件还在
//   队列里"那类时序缺陷的修法：只看 cancelFlag_ 不够，必须看代次）。
//
// ------------------------------------------------------------
// Wave 3 第二轮独立审核（review2-wpJ2.md）确认缺陷的修法（N1-N6）
// ------------------------------------------------------------
// - N1（D9 没修好）：isSourceFresh() 内部的 target_->capture() 仍然可能同步
//   触发 sessionChanged，订阅者的槛可能在这次回调里把 canvas_ 置空。修法：
//   onJobFinishedOnUiThread 在调用 isSourceFresh() **之后**立刻重新判一次
//   canvas_ 是否仍非空，不能只信"函数开头判过一次"——这正是上一轮同一处只
//   判了"调用前"、漏判了"调用后"的根因。
// - N2（rereadByteRange 去重吞掉写后重读）：去重只能对"已提交、尚未被工作
//   线程真正开始处理"的任务生效。PendingJobRecord 新增 started
//   （shared_ptr<atomic<bool>>），InFlightJob::run() 一进入就置位；去重循环
//   遇到 started 为真的记账条目，当它"不提供去重覆盖"处理——哪怕这一页的
//   地址落在它的 range 里，也不能据此跳过新的重读请求，因为这个任务可能已经
//   读过这一页，继续沿用旧判据会把写前的值误当成写后的值。
// - N3（channelFailed 整批丢弃同批已经读成功的 range）：落地时按 range 逐个
//   处理，不再因为批里某一个 range 通道失败就连带丢弃同批其它已经读成功的
//   range；channelFailed 的那个 range 里真正读到的页仍然正常交付，只有它
//   自己的 NotAttempted 页与被毒标志跳过（skippedDueToPoison）的整段 range
//   保持 Pending，一起记进新增的 failedRanges_。
// - N4（被毒标志跳过的 range 永远救不回来)：同一个 failedRanges_ 机制覆盖
//   skippedDueToPoison 的整段 range——它的 result.pages 恒为空，逐页回填
//   循环天然不会碰它，必须单独记账才有重试的机会。新增只读出口
//   failedRanges() 与显式动作 retryAllFailed()；画布滚走再滚回**不会**自动
//   重读（这是裁决的既定行为，不是漏改），只有调用方显式触发 retryAllFailed
//   才会再问端口。
// - N5（闩锁路径没有去抖）：仿照 lastGateUnavailableReason_ 的去抖写法，新增
//   lastLatchRetryNotifiedFor_ 记"（闩锁目标轴，触发请求的画布轴）"这一对
//   键，同一组合只发一次 retryBlockedByLatch；resetScratchLatch() 会清空这份
//   记忆，保证闩锁被显式清除之后下一次命中（哪怕键值恰好相同）会被当成"新的
//   一次"重新通知。
// - N6（setCanvas(nullptr) 暂停期间落地的结果被丢弃，恢复后永远 Pending）：
//   新增 pausedPendingRanges_，在"画布为空，结果只能丢弃"的分支里顺手记下
//   range+画布轴；setCanvas() 检测到"从空变回非空"（真正意义上的"恢复"，
//   不是换成另一块画布）时，对画布轴仍相符的记录补一次 cancelPages，让下
//   一次重绘的 PlanFetch 能重新把它们排进请求——这不是"自动重试已知失败的
//   通道"（那条红线只管 channelFailed/skippedDueToPoison，走的是上面的
//   failedRanges_），只是让"暂停"这个纯 UI 动作对称：暂停丢弃的结果，恢复
//   之后应该像"从没发生过"，而不是卡死。
// ============================================================

#include "HexCanvas.h"
#include "WorkbenchTarget.h"

#include "../../../../shared/evidence/memory_workbench/MemoryChannelGate.h"
#include "../../../../shared/evidence/memory_workbench/MemoryIoPort.h"
#include "../../../../shared/evidence/memory_workbench/MemoryPageReader.h"
#include "../../../../shared/evidence/memory_workbench/MemoryReadSchedule.h"

#include <QObject>
#include <QPointer>
#include <QString>

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace ks::ui
{
    // WorkbenchPageProvider：详见文件头。公开接口只允许 UI 线程调用；唯一的例外是
    // IHexPageProvider::RequestPages 本身——它也只被画布在 UI 线程调用，之后才派发
    // 到内部的读线程，所以整个公开表面仍然是"仅 UI 线程"。
    class WorkbenchPageProvider final : public QObject, public IHexPageProvider
    {
        Q_OBJECT

    public:
        void SetUnknownFoldingEnabled(bool enabled) override { foldUnknown_ = enabled; }
        // IoPortFactory：构造一个 IMemoryIoPort 实现的工厂。本类在构造时调用恰好一次
        // 并长期持有返回的端口——真实端口（WorkbenchIoPort，见 MemoryDock/
        // WorkbenchIoPorts.h）本身无成员状态，可安全地让读线程与 UI 线程并发使用；
        // 假端口（夹具）通常同样无状态或自带锁，由实现者保证。
        using IoPortFactory = std::function<std::unique_ptr<ksword::memwb::IMemoryIoPort>()>;

        // GateInputsProvider：取运行期可用性输入的回调，只在 UI 线程调用。
        using GateInputsProvider = std::function<ksword::memwb::GateInputs()>;

        // 构造：portFactory 必须非空可调用；target 用于取会话快照与来源代次（非拥有，
        // 调用方必须保证它的生命周期覆盖本对象——装配层约定：PageProvider 由持有
        // 同一个 WorkbenchTarget 的 WorkbenchHexPane 创建，且先于 target 销毁）。
        explicit WorkbenchPageProvider(
            IoPortFactory portFactory,
            WorkbenchTarget* target,
            QObject* parent = nullptr);
        ~WorkbenchPageProvider() override;

        // setCanvas：设置要回填的画布（非拥有，QPointer 自动探活）。传空表示暂停
        // 回填——仍在途的读取完成后发现画布已空，直接丢弃结果。
        void setCanvas(HexCanvas* canvas);

        // setGateInputsProvider：注入 Gate 判定所需的可用性输入回调；不注入时按
        // "全部最保守"处理（一律视为不可用），绝不会因为缺省值而误判成可用。
        void setGateInputsProvider(GateInputsProvider provider);

        // RequestPages：实现 IHexPageProvider（见 HexCanvas.h）。流程见文件头 R1-R3。
        // sourceRevision 就是文件头说的"画布轴"（canvasRevision）。
        void RequestPages(
            const std::vector<HexFetchRange>& ranges,
            std::uint64_t sourceRevision) override;

        void RequestExplicitPages(const std::vector<HexFetchRange>& ranges, std::uint64_t sourceRevision) override;
        void UpdateViewportInterest(const std::vector<HexFetchRange>& ranges, std::uint64_t sourceRevision) override;
        void ProtectPages(const std::vector<HexFetchRange>& ranges, std::uint64_t sourceRevision) override;

        // cancelAllInFlight：装配层在身份类变更（换目标/换范围/换通道，离开守卫通过
        // 之后）调用，让仍在读线程里跑着的任务、已经排队但还没开始跑的任务、甚至
        // 已经跑完但完成事件还卡在事件队列里的任务全部作废（D4）；凡是此刻还没
        // 落地的任务，涉及的 range 会在本函数调用期间立即（同步）补一次 cancelPages
        // （画布代次仍与任务提交时一致才做，D5/D6），不等待线程池排空、不阻塞 UI
        // 线程。
        void cancelAllInFlight();

        // resetScratchLatch：清空 DDMA 脏扇区闩锁（换目标、切通道、用户显式重读时
        // 调用）。不调用它时，同一**目标**代次下一旦命中过 scratchAreaDirty，后续对
        // DDMA 通道的 RequestPages 一律立即 cancelPages 并发 retryBlockedByLatch，
        // 不再问端口（不变式 14 的读侧落点）。注意 target_->requestReload() 本身就会
        // 让目标代次前进，因此也会**自动**让闩锁对新代次失效（不需要调用方额外调用
        // 本函数）——这是设计好的行为，不是疏漏，详见文件头"两条数轴"一节。
        void resetScratchLatch();

        // retryFailedRanges：唯一的"重试"入口。上一次 channelFailed/取消的范围需要
        // 显式请求才会再问端口一次；传入的范围会先按页对齐并夹取到
        // HexViewport::kMaxCachedPages（调用方可能传来字节级别未对齐、或超出缓存
        // 容量的范围，本函数负责规整，不要求调用方自己换算，D7/D11），再原样重新
        // 走一次 RequestPages 流程。画布轴用 canvas_->sourceRevision()（回填要用
        // 这个值；画布为空时直接返回，没有地方可回填），目标轴仍由 RequestPages
        // 内部自己重新 capture() 一次（决策 2：两条数轴各自独立取值，不在这里提前
        // 算好再传）。
        void retryFailedRanges(const std::vector<HexFetchRange>& ranges);

        // failedRanges（N3/N4 修复新增）：只读出口，返回当前记在 failedRanges_
        // 里的全部 range 的一份拷贝——通道失败（channelFailed）或被毒标志
        // 跳过（skippedDueToPoison）之后保持 Pending、尚未被显式重试的那些
        // range。供状态条/诊断抽屉展示"N 处可重试"，不改变任何状态。
        std::vector<HexFetchRange> failedRanges() const;

        // retryAllFailed（N3/N4 修复新增）：状态条"重试"按钮的落点，唯一会
        // 把 failedRanges_ 里记的 range 重新送回端口的入口。取出当前全部
        // 记账并立刻清空（乐观清空——如果这次重试仍然失败，landing 时会把
        // 对应 range 原样再记回来，不会丢记账），再复用 retryFailedRanges
        // 的页对齐/夹取/Gate/闩锁判定逐段重新请求。failedRanges_ 为空时是
        // 空操作。
        void retryAllFailed();

        // rereadByteRange（Wave 3 新增公有接口）：供 WorkbenchWriteController 的
        // RereadRangeFn 使用——写提交/撤销/重做完成后，按**字节范围**（不是页范围）
        // 请求重读。内部换算成页对齐范围、夹取到 HexViewport::kMaxCachedPages
        // （D7/D11，与 retryFailedRanges 共用同一套规整逻辑），并与"当前已提交、
        // 尚未落地"的任务按页去重——如果这次要读的每一页都已经在某个在途/排队
        // 任务的记账范围内，直接跳过，不再重复提交（连续撤销/重做背靠背调用本函数
        // 时，不让读池里堆积一串读同一页的重复任务）。画布轴用
        // canvas_->sourceRevision()，画布为空时直接返回。撞上 DDMA 闩锁时与
        // RequestPages 共用同一条路径，同样发 retryBlockedByLatch，不会静默什么
        // 都不提示。
        // 传入：address 字节范围起点；length 字节数（0 表示无效，直接返回）。
        void rereadByteRange(std::uint64_t address, std::uint64_t length);

        // hasInFlightRequests（Wave 3 wpJ5 新增，装配接口文档 §8.2 增量①）：当前是否
        // 存在"已提交、尚未落地"的页读取请求——含仍在读线程里跑着的那一个、已经排队
        // 但还没真正开始跑的后续任务，两者都记在 pendingJobs_ 里（见该成员的声明处
        // 注释），落地（不管哪条分支：陈旧/取消/失败/成功）都会从表里摘掉，所以
        // "表非空"与"确实有未完成的请求"始终同义，不需要另开一套计数。
        // 用途：WorkbenchHexPane 调用 WorkbenchBaselineFeeder::noteDirty 时，必须把
        // "此刻有没有在途页读取"如实传过去——feeder 在在途请求存在时不会起算防抖
        // （避免把"还没读完的窗口"误判成最终结果），本函数就是它要的那个布尔值的
        // 唯一权威来源。UI 线程调用，不改变任何状态。
        bool hasInFlightRequests() const noexcept;

    signals:
        // channelUnavailable：本次请求整体被 Gate 拒绝时发出（去抖：同一个
        // GateReason 连续命中只发一次，见文件头 R1）；装配层（状态条）据此标红，
        // 绝不自动换通道、绝不自动重试。
        void channelUnavailable(ksword::memwb::GateVerdict verdict);

        // readFailed：某个画布代次下这次落地里有 range 因为通道自身失败
        // （channelFailed）或被毒标志跳过（skippedDueToPoison）而没有被交付，
        // 装配层据此给出"可重试"提示并把 failureText 写进诊断抽屉。对应的
        // range**不会**被 cancelPages（D2/N3/N4），保持 Pending，并被记进
        // failedRanges_，必须显式 retryFailedRanges/retryAllFailed 才会再问
        // 端口。failedRangeCount（N3/N4 修复新增参数）是本次落地里新记进
        // failedRanges_ 的 range 条数（同批里已经成功交付的 range 不计入），
        // 供状态条展示"N 处失败/待重试"；只看 failureText 想知道"失败原因"
        // 的旧消费者不受影响（新增参数不改变前两个参数的含义）。
        void readFailed(quint64 sourceRevision, QString failureText, int failedRangeCount);

        // scratchAreaDirtyLatched：本**目标**代次下 DDMA 闩锁刚刚被置位（只在第一次
        // 命中时发，同一目标代次内重复命中不会再发第二次）。
        void scratchAreaDirtyLatched();

        // retryBlockedByLatch（D10 新增，N5 修复补了去抖）：本次请求
        // （RequestPages 或 rereadByteRange）撞上了尚未释放的 DDMA 脏扇区
        // 闩锁，整批已被 cancelPages，一次端口调用都没有发起。携带触发这次
        // 请求的画布代次，供诊断抽屉/状态条给出"暂存区尚未恢复，重读前请先
        // 处理"一类的提示，不再是"什么都不提示"的静默拦截。去抖：同一组
        // （闩锁所属的目标轴代次，这次请求的画布轴代次）只发一次，闩锁没被
        // resetScratchLatch() 清除之前，画布每次重绘触发的重复请求不会反复
        // 刷这个信号（N5：第二轮审核确认的缺口，之前这里完全没有去抖，与
        // Gate 不可用路径的去抖不对称）。
        void retryBlockedByLatch(quint64 sourceRevision);

        // jobLanded（Wave 3 wpJ5 新增，装配接口文档 §8.2 增量①）：每当
        // onJobFinishedOnUiThread 真的取到一份已完成的任务记账（不管接下来走哪条
        // 分支——陈旧丢弃、画布已空、通道失败、还是成功回填）并处理完毕，就恰好发一次
        // 本信号；票据根本不存在（从未存在，或已经被别的路径处理过，见该函数开头
        // 的提前返回）不算一次"落地"，不发。
        // 用途：WorkbenchHexPane 订阅它，在每次页真正落地（无论是否成功回填）之后
        // 重新驱动一次 WorkbenchBaselineFeeder::noteDirty——"在途请求变成没有在途
        // 请求"正是 feeder 被告知"现在可以开始算防抖"的唯一时机，没有这个信号，
        // feeder 只能靠下一次画布信号（滚动/插入点移动）才会被动唤醒，窗口会在
        // "读完但没人catch"的状态下多停留一段时间。
        void jobLanded();

    private:
        bool foldUnknown_ = false;
        // ReadPool：唯一的单线程读池，定义在 .cpp（避免本头文件把 QThreadPool 的
        // 调度细节暴露给每个包含者）。
        class ReadPool;
        // InFlightJob：一次 RequestPages 调用对应的内部记账，定义在 .cpp。
        struct InFlightJob;

        using ReadPurpose = ksword::memwb::MemoryReadSchedule::Purpose;
        void requestPages(const std::vector<HexFetchRange>& ranges,
            std::uint64_t sourceRevision, ReadPurpose purpose);

        // PendingJobRecord：provider 自己维护的"已提交、尚未落地"的任务记账，键为
        // 票据（jobCounter_ 发出的 ticket）。只记两件事：canvasRevision（D5/D6 的
        // 画布代次守卫）与 ranges（丢弃时逐段 cancelPages 要用的粒度）。正常落地
        // （不管是新鲜回填、陈旧、channelFailed，还是代次不符被判定作废）都会在
        // onJobFinishedOnUiThread 开头把自己的条目摘掉；cancelAllInFlight 丢弃
        // "排队中、从未真正跑过"的任务时，靠这张表补上唯一的一次 cancelPages
        // 机会（ReadPool 自己只认 QRunnable，不知道 HexCanvas 长什么样，也不应该
        // 知道——见 WorkbenchPageProvider.Pool.h 的职责边界）。
        struct PendingJobRecord
        {
            std::uint64_t canvasRevision = 0;
            std::vector<HexFetchRange> ranges;
            // started（N2 修复新增）：这个任务是不是已经进入工作线程的
            // run()、真正开始处理（不是还在线程池队列里排队）。只在构造时
            // 由 submitJob 创建一份新的 atomic，传进 InFlightJob；工作线程
            // 在 run() 最开头、处理第一个 range 之前就把它置位，之后 UI
            // 线程只读不写，不需要额外加锁。rereadByteRange 的去重判断靠
            // 它分辨"这一页只是排在队列里、还没被真正读过"（可以安全去重，
            // 它迟早会读到最新值）与"已经在读、可能已经读过这一页"（不能
            // 去重，否则写后重读会被吞掉，见文件头 N2 一节）。
            std::shared_ptr<std::atomic<bool>> started;
            ReadPurpose purpose = ReadPurpose::Browse;
            std::uint64_t targetRevision = 0;
            std::uint64_t jobGeneration = 0;
            std::function<void()> start;

        };

        // PausedRangeRecord（N6 修复新增）：见文件头"Wave 3 第二轮...N6"一节。
        // setCanvas(nullptr) 暂停回填期间落地的结果本来就要丢弃；丢弃之前把
        // range 连同当时的画布轴记在这里，供 setCanvas() 从空恢复为非空时
        // 补一次 cancelPages，让这些地址不至于在画布自己的状态里永远卡在
        // Pending。
        struct PausedRangeRecord
        {
            std::uint64_t canvasRevision = 0;
            HexFetchRange range;
        };

        // onJobFinishedOnUiThread：读线程任务完成后，经 Qt::QueuedConnection 排队回
        // UI 线程调用的收尾函数，只在 UI 线程执行，实现 R3 的核对与回填。
        void onJobFinishedOnUiThread(std::uint64_t jobTicket);

        // isSourceFresh：只比较**目标轴**来源代次（不比较内容代次）的轻量核对，供
        // R3 使用；与 WorkbenchTarget::isStale() 不同——内容代次变化不应作废在途页
        // 读取。
        // **契约**：比较之前必须先调用一次 target_->session()（它在通道为 DDMA 时会拉取
        // 并登记最新的暂存扇区代次，必要时 bump 来源代次）。DDMA 代次的变化没有可靠的
        // 回调（设计 §0.4 只做拉取），不先拉就比较，会把换了暂存扇区之后才落地的旧页判成
        // 新鲜（Wave 2 审核 wpI D2 的同一形状）。因此本函数不是 const。
        bool isSourceFresh(std::uint64_t capturedTargetRevision);

        // submitJob：RequestPages/retryFailedRanges/rereadByteRange 共用的"通过 Gate
        // 与闩锁判定之后，正式把一批 range 投给 ReadPool"的收尾步骤，定义在 .cpp。
        // 传入：cap 本次 capture() 得到的快照；canvasRevision 画布轴；
        //       targetRevision 目标轴；isDdmaChannel 会话通道是否为 Ddma；ranges 已经
        //       被上层夹取过 pageCount 的范围。
        void submitJob(
            const TargetCapture& cap,
            std::uint64_t canvasRevision,
            std::uint64_t targetRevision,
            bool isDdmaChannel,
            const std::vector<HexFetchRange>& ranges,
            ReadPurpose purpose);

        void dispatchNextJob();
        void discardQueuedJob(std::uint64_t ticket);
        void cancelUnownedPages(const std::vector<HexFetchRange>& ranges, std::uint64_t canvasRevision);
        bool pageInterested(std::uint64_t pageStart, std::uint64_t canvasRevision) const;

        // normalizeRangeForRetry：把一段可能未页对齐、也可能超过缓存容量的范围
        // 规整成页对齐、页数不超过 HexViewport::kMaxCachedPages 的范围，供
        // retryFailedRanges 使用（D7/D11）。pageCount 为 0 的输入原样返回（调用方
        // 据此判断要不要整体跳过这一条）。
        static HexFetchRange normalizeRangeForRetry(const HexFetchRange& range);

        // canvas_：回填目标（非拥有）。target_：会话与代次来源（非拥有，生命周期
        // 约定见构造函数注释）。port_：本类拥有的唯一端口实例，无成员状态。
        QPointer<HexCanvas> canvas_;
        WorkbenchTarget* target_ = nullptr;
        std::unique_ptr<ksword::memwb::IMemoryIoPort> port_;
        // gateInputsProvider_：可用性输入回调；未注入时 RequestPages 一律按不可用处理。
        GateInputsProvider gateInputsProvider_;
        // readPool_：唯一的单线程读池（不变式 5）。
        std::unique_ptr<ReadPool> readPool_;
        // jobCounter_：任务票据发生器，只在 UI 线程递增，用于识别/作废在途任务。
        std::uint64_t jobCounter_ = 0;
        // generation_（D4 新增）：cancelAllInFlight 每调用一次就递增；任务落地时
        // 携带的 generation 与此刻的值不符，一律当作已作废处理，不展示、不重复
        // 触碰画布（已经在 cancelAllInFlight 自己的调用栈里同步处理过一次）。
        std::uint64_t generation_ = 0;
        // pendingJobs_（D4/D5/D6 新增）：见 PendingJobRecord 的说明。
        std::map<std::uint64_t, PendingJobRecord> pendingJobs_;
        std::vector<HexFetchRange> viewportInterest_;
        std::uint64_t viewportInterestCanvasRevision_ = 0;
        bool hasViewportInterest_ = false;
        std::uint64_t viewportInterestRevision_ = 0;
        ksword::memwb::MemoryReadSchedule readSchedule_;
        std::optional<std::uint64_t> dispatchedTicket_;
        std::optional<std::uint64_t> poisonTargetRevision_;
        bool dispatching_ = false;

        // scratchLatched_ / scratchLatchedForRevision_：DDMA 脏扇区闩锁与其所属
        // **目标**代次（决策 2 之前这里存的是画布代次，已按裁决改键）。
        bool scratchLatched_ = false;
        std::uint64_t scratchLatchedForRevision_ = 0;
        // lastGateUnavailableReason_（D2 新增）：Gate 判不可用时去抖用——同一个
        // 原因连续命中只在第一次发 channelUnavailable；Gate 变回可用时清空
        // （std::nullopt），下次再次不可用会重新发一次，不管原因是否与上次相同。
        std::optional<ksword::memwb::GateReason> lastGateUnavailableReason_;
        // failedRanges_（N3/N4 修复新增）：channelFailed 或 skippedDueToPoison
        // 之后保持 Pending、尚未被显式重试的 range 记账。只在
        // onJobFinishedOnUiThread 里追加，只在 retryAllFailed()（取出重试）
        // 或 cancelAllInFlight()（身份变化，整批作废）里清空；resetScratchLatch
        // 不碰它——"重试"是用户显式动作，不随闩锁清除自动发生（见文件头 N4）。
        std::vector<HexFetchRange> failedRanges_;
        // pausedPendingRanges_（N6 修复新增）：见 PausedRangeRecord 的声明处
        // 注释。只在"落地时发现画布为空"的分支里追加，只在 setCanvas() 侦测
        // 到"从空恢复为非空"时消费并清空。
        std::vector<PausedRangeRecord> pausedPendingRanges_;
        // lastLatchRetryNotifiedFor_（N5 修复新增）：retryBlockedByLatch 的
        // 去抖记忆，键是 (闩锁所属的目标轴代次, 触发这次请求的画布轴代次)。
        // resetScratchLatch() 会清空它——闩锁被显式清除之后下一次命中（哪怕
        // 键值恰好相同）要被当成"新的一次"重新通知。
        std::optional<std::pair<std::uint64_t, std::uint64_t>> lastLatchRetryNotifiedFor_;
    };
}
