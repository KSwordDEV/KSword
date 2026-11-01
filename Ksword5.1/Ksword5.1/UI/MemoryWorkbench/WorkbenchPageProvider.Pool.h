#pragma once

// ============================================================
// WorkbenchPageProvider.Pool.h
// 作用：
// - WorkbenchPageProvider.h 把 ReadPool（唯一的单线程读池）与 InFlightJob
//   （一次 RequestPages 调用对应的内部记账）都只前置声明，不把 QThreadPool
//   的调度细节写进那份对外发布、/W4 /WX 已冻结的公开头文件。本文件补全这
//   两个类型的完整定义，只在 WorkbenchPageProvider.cpp 与
//   WorkbenchPageProvider.Pool.cpp 两个实现文件之间共享，不对外发布、不会
//   被任何别的类 #include。
// - 本文件不是"第七个装配层类"的头文件，只是实现细节的内部拆分（呼应
//   docs/内存工作台Phase3装配接口.md 对 WorkbenchWriteController.Undo.h 的
//   同类处理方式："卫星头"，不是独立的装配层成员）。
//
// 设计要点（呼应接口文档 §4 不变式 5 与 Wave 2 wpI 复核出的 UAF 教训，见
// WorkbenchTarget.Modules.cpp 的 D1 修复注释，以及
// .claude/memory/ksword-memwb-parallel-mutation-pitfalls.md）：
//
// 1) InFlightJob::run() 在工作线程里只持值——会话的值拷贝
//    （ksword::memwb::MemoryTargetSession）、地址/长度/票据等整数、取消标志的
//    shared_ptr<atomic<bool>>、IMemoryIoPort 的裭指针（生命周期安全见第 4 点，
//    不是靠本文件的任何"花招"，是 WorkbenchPageProvider.h 成员声明顺序的直接
//    推论）。绝不持有 HexCanvas*、WorkbenchPageProvider* 的裭指针来直接解引用。
// 2) 真正要把结果带回 UI 线程时，只把 QPointer<WorkbenchPageProvider> 的
//    "值"（不是 data() 取出的裭指针）捕获进 lambda，QMetaObject::invokeMethod
//    的 context 参数用进程内长期存活的 QCoreApplication::instance()——这与
//    WorkbenchTarget.Modules.cpp 的 D1 修复完全同款：如果 context 换成从
//    QPointer 取出的裭指针，"取出裭指针"到"调用真正排队"之间仍有一个窗口，
//    对象恰好在这期间销毁就是对已释放堆内存的解引用；用 QCoreApplication
//    实例做 context，只决定"回调在哪个线程的事件循环里执行"，不代表回调会碰
//    它，真正的判空发生在 lambda 真的落到 UI 线程执行的那一刻（data()），
//    这才是唯一安全的读取时机。
// 3) 结果数据（ReadPool::CompletedJob）先存进 ReadPool 自己的互斥锁保护的表，
//    排队调用只携带 jobTicket 这一个整数作为参数，与
//    WorkbenchPageProvider.h 里 onJobFinishedOnUiThread(std::uint64_t jobTicket)
//    的冻结签名完全对应——不需要也不应该改用别的签名绕开它。
// 4) port_（WorkbenchPageProvider.h 的成员，std::unique_ptr<IMemoryIoPort>）
//    的生命周期安全，靠的是该头文件里成员的声明顺序：readPool_ 声明在 port_
//    之后，C++ 保证销毁一个对象时，它的成员按声明顺序的**逆序**析构——也就是
//    说 readPool_ 先于 port_ 被销毁。ReadPool 的析构（见下面 CancelAll 的用法）
//    会先丢弃排队中尚未开始的任务、给"正在跑的那一个"（至多一个，因为
//    maxThreadCount=1）置位取消标志，再让其内部的 QThreadPool 成员做默认析构
//    （Qt 的既定行为：QThreadPool 的析构会等待仍在跑的任务结束）。等这一步
//    真正返回之后，port_ 才开始被销毁——此时已经不存在任何工作线程还在用它，
//    不是侥幸，是这两个成员的声明顺序决定的必然结果。因此 InFlightJob 持有
//    IMemoryIoPort 的裭指针（不是 shared_ptr）是安全的，不需要为它另外发明
//    一套"非拥有 shared_ptr 别名"之类的技巧（那样反而会让生命周期关系变得
//    不透明）。
// 5) 这个等待不是"无限等待"：排队中的积压已经被 clear() 丢弃，真正等待的
//    只是"当前这一次 Read 调用"的耗时，上限由端口实现自己的响应性决定，与
//    本类的策略无关（本类自身不实现任何重试/超时策略，这是 MemoryPageReader.h
//    的既定分工）。取消标志在析构最早期就被置位，给工作线程尽量早的机会
//    在下一次 Read 之前的检查点发现取消并提前返回，缩短这个等待窗口。
// 6)（Wave 3 新增，D3）poisoned_：与第 1-5 点的 cancelFlag_ 是两件独立的事。
//    cancelFlag_ 按票据一对一，只表达"这一个任务被 cancelAllInFlight 作废了"；
//    poisoned_ 是整个 ReadPool 共用一份（shared_ptr<atomic<bool>>），表达
//    "通道已经出现过失败/暂存区弄脏，排在后面的 range——不管是同一个任务里的，
//    还是另一个已经排队、尚未开始跑的任务——都不应该再碰端口"。因为唯一的
//    单线程池保证任务严格按提交顺序串行执行，这份共享标志不需要额外加锁
//    （InFlightJob::run() 只有一条线程会读写它，UI 线程只在提交新任务前把它
//    重置为 false，写-写之间天然没有竞争：UI 线程的重置发生在 Submit() 之前，
//    工作线程只在 run() 内部读写，两者靠"唯一串行池"这一不变式隔开）。
// 7)（Wave 3 第二轮审核修复，N2）started_：每个任务各自一份（与 poisoned_
//    不同，poisoned_ 是整池共用一份），由 provider 的 PendingJobRecord 持有
//    同一份引用，run() 最开头（处理第一个 range 之前）就置位，之后只有 UI
//    线程会读它。用途：rereadByteRange 的去重判断必须分清"这一页只是排在
//    队列里、还没真的开始读"（可以安全去重）与"已经开始读、可能已经读过
//    这一页"（不能去重，否则写后重读会被吞掉，画面停在写之前的值——这正是
//    第二轮审核抓到的 N2 真实缺口）。只在构造时赋值一次、run() 里写一次，
//    没有需要额外加锁的读写交叠。
// ============================================================

#include "WorkbenchPageProvider.h"

#include <QPointer>
#include <QRunnable>
#include <QThreadPool>

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace ks::ui
{
    // JobRangeResult：一次 RequestPages 调用里，某一段 range 的读取结果。
    // range 字段保留"发起请求时的原始范围"（可能跨多页）：核对不通过（陈旧）
    // 或通道失败时，整批撤销要用这个粒度（不能偷懶改成逐页撤销——那样会
    // 在同一个来源代次下对同一段地址发出两份语义不同的撤销记录）；真正逐页
    // 回填时再从 result.pages 里逐页取出 pageStart 另外拼一次单页 range。
    struct JobRangeResult
    {
        // range：发起这次读取时，HexCanvas 传进 RequestPages 的那一段原始范围。
        HexFetchRange range;
        // result：ksword::memwb::ReadPages 对这段 range 的完整结果（见
        // MemoryPageReader.h 的 PageReadResult）。skippedDueToPoison 为真时，
        // result 恒为默认构造值（pages 为空、channelFailed/cancelled 均为假）——
        // 这段 range 从未被真正问过端口，不是"问过了但失败"。
        ksword::memwb::PageReadResult result;
        // skippedDueToPoison（D3 新增）：true 表示本段 range 因为共享的"通道中毒"
        // 标志已经置位而被整段跳过，从未发起任何 Read。落地时 UI 线程不需要
        // 对它做任何特殊处理——result.pages 为空，逐页回填循环天然什么都不做，
        // 这段地址保持 Pending，等下一次显式 retryFailedRanges/重建地址空间；
        // 这个字段只用于诊断/日志，不参与任何判断分支。
        bool skippedDueToPoison = false;
        std::vector<ksword::memwb::IMemoryIoPort::UnreadableExtent> unreadableExtents;
    };

    // WorkbenchPageProvider::ReadPool：唯一的单线程读池，详见本文件头与
    // WorkbenchPageProvider.h 里 ReadPool 前置声明处的注释。
    class WorkbenchPageProvider::ReadPool
    {
    public:
        // CompletedJob：一次 RequestPages 调用的完整记账。工作线程把全部 range
        // 读完后，把这份记账存进 completed_ 表；UI 线程的
        // onJobFinishedOnUiThread 用票据把它取出来做 R3 的核对与回填。
        struct CompletedJob
        {
            // canvasRevision：这次请求收到的"画布轴"代次（HexCanvas 自己的
            // ++m_revisionCounter）。回填画布时必须原样带回——这正是
            // IHexPageProvider::RequestPages 文档里"回填时必须原样带回"的落地点；
            // 也是 cancelPages 守卫比较的那个值（D5/D6）。
            std::uint64_t canvasRevision = 0;
            // targetRevision（Wave 3 决策 2 新增）：这次请求开头 capture() 取到的
            // "目标轴"代次（target_->capture().rev.source）。只用于陈旧性核对与
            // DDMA 闩锁键，绝不用于回填（那是 canvasRevision 的职责，两者不能
            // 混用，否则就是审核报告里的"axismismatch"那类缺陷）。
            std::uint64_t targetRevision = 0;
            // isDdma：发起这次请求时，会话的通道是不是 Ddma；只有这种情况才需要
            // 在落地时核对/置位 DDMA 脏扇区闩锁。
            bool isDdma = false;
            // jobGeneration（D4 新增）：提交这次任务时 provider 的 generation_
            // 快照。落地时与 provider 当下的 generation_ 不符，说明
            // cancelAllInFlight 在这之后被调用过，这份结果已经作废，必须丢弃，
            // 不得展示。
            std::uint64_t jobGeneration = 0;
            // rangeResults：按请求时 ranges 向量的原始顺序排列，每段一份结果。
            std::vector<JobRangeResult> rangeResults;
        };

        // 构造：把内部的单线程池设为 maxThreadCount=1——落实不变式 5"读线程是
        // 一条串行池"：同一个 WorkbenchPageProvider 实例的多次 RequestPages，
        // 不管调用方发起得多密，端口侧观察到的调用永远不会重叠。同时构造一份
        // 共享的"通道中毒"标志（D3），初值 false。
        ReadPool();

        // 析构：见本文件头第 4/5 点——先丢弃排队积压、给正在跑的任务置位取消
        // 标志，再让 QThreadPool 成员的默认析构收尾。不额外调用任何会无限期
        // 阻塞的等待函数。
        ~ReadPool();

        // Submit：把一个任务交给线程池，并记录它专属的取消标志，供 CancelAll
        // 使用。传入：job 调用方 new 出来的 QRunnable（setAutoDelete(true)，
        // 线程池负责在 run() 返回后释放，调用方不需要也不应该再 delete 它）；
        // ticket 这次任务的票据；cancelFlag 这次任务专用的取消标志。
        void Submit(QRunnable* job, std::uint64_t ticket, std::shared_ptr<std::atomic<bool>> cancelFlag);

        // CancelAll：装配层调用 WorkbenchPageProvider::cancelAllInFlight 时的
        // 落地，也是本类析构时的收尾第一步。丢弃排队中尚未开始的任务（它们是
        // autoDelete 的 QRunnable，clear() 会直接删除而不调用 run()，因此永远
        // 不会再产生任何回调，不需要单独处理它们各自的取消标志）；再给仍记在
        // 账上的任务（此刻至多只剩"正在跑的那一个"）置位取消标志，让它在下一
        // 次 Read 之前的检查点尽快发现并提前返回。**不**在这里碰 poisoned_
        // （那是"通道本身坏没坏"的状态，与"这批任务被用户取消了"是两件独立的
        // 事；poisoned_ 只在 ResetPoison() 里清零）。
        void CancelAll();

        // Finish：工作线程把一次任务的全部 range 都读完之后调用，把结果存进
        // 完成表，并顺手摘掉这次任务的取消标志记账（它已经用不到了，留着只会
        // 让 cancelFlags_ 不必要地增长）。
        void Finish(std::uint64_t ticket, CompletedJob job);

        // TakeCompleted：UI 线程用票据取出并移除一份已完成的记账。找不到
        // （从未存在、或早被别的路径清理过）时返回空，调用方据此判断"这次落地
        // 没有东西可核对"，直接丢弃，不是缺陷。
        std::optional<CompletedJob> TakeCompleted(std::uint64_t ticket);

        // ResetPoison（D3 新增）：UI 线程在每次成功通过 Gate/闩锁前置判定、正式
        // 提交一个新任务之前调用，把共享的"通道中毒"标志清回 false——保证"全新
        // 的一次请求"总有机会真正问一次端口，不会被更早、已经落地过的失败
        // 永久封死；但如果这个新任务恰好排在一个"即将中毒"的任务后面（同一个
        // 单线程池里先提交的先跑），等它真正开始跑的时候，前一个任务可能已经
        // 把标志重新置位——那正是 D3 要抓的"已排队任务不得再碰已知坏掉的通道"。
        void ResetPoison();

        // PoisonFlag（D3 新增）：取共享标志的 shared_ptr，供构造 InFlightJob 时
        // 传入（只传"值"，工作线程与 UI 线程各自持有一份引用计数，不存在谁先
        // 销毁的问题——这份标志与 ReadPool 本身同生命周期，析构前不会被重置）。
        std::shared_ptr<std::atomic<bool>> PoisonFlag() const;

    private:
        // 成员声明顺序是本类唯一的安全关键点，必须保持 mutex_/cancelFlags_/
        // completed_/poisoned_ 都排在 pool_ 前面：C++ 按声明的**逆序**析构成员，
        // pool_ 排在最后，析构时就会最先被销毁——~QThreadPool() 会阻塞等待
        // "正在跑的那一个"任务真正跑完（见 Submit/CancelAll 的注释），而工作线程在
        // 那段等待期间仍可能调用 Finish()/读写 poisoned_。如果 pool_ 排在前面
        // （会在这些成员**之后**才被销毁），等待期间它们已经先被销毁，工作线程
        // 这一刻的访问就是对已销毁对象的访问——这正是本包夹具用离屏 cdb 实测
        // 抓到的第一个真实缺陷（Access violation，rax 落在
        // 0xfeeefeee`feeeff07 这个"已释放内存"特征值上，调用栈是工作线程在
        // ~QThreadPool 仍在等待期间执行 Finish），不是靠推理得出，记在这里
        // 防止后续重构时又把顺序改回去。poisoned_ 是 shared_ptr，即使声明顺序
        // 不对也不会直接崩溃（引用计数会保它到最后一次使用），但为了"谁在管
        // 这件事"读起来不产生歧义，仍然把它放在 pool_ 之前。

        // mutex_：保护下面两张表——它们会被工作线程（Finish）与 UI 线程
        // （Submit/CancelAll/TakeCompleted）同时触碰，必须加锁。
        std::mutex mutex_;
        // cancelFlags_：按票据记录"已提交、尚未 Finish"的任务的取消标志；任务
        // 结束时 Finish 会自己摘掉这一条，CancelAll 也会整体清空，不会无限增长。
        std::map<std::uint64_t, std::shared_ptr<std::atomic<bool>>> cancelFlags_;
        // completed_：按票据记录已经跑完、等待 UI 线程核对回填的结果。
        std::map<std::uint64_t, CompletedJob> completed_;
        // poisoned_（D3 新增）：见 ResetPoison/PoisonFlag 的说明。shared_ptr 本身
        // 不需要 mutex_ 保护（引用计数原子；指向的 atomic<bool> 自己也是原子），
        // 这里只是把"谁拥有这份标志"的生命周期记在 ReadPool 身上。
        std::shared_ptr<std::atomic<bool>> poisoned_;
        // pool_：唯一的单线程池本体。必须是本类最后一个声明的成员（见上）。
        QThreadPool pool_;
    };

    // WorkbenchPageProvider::InFlightJob：ReadPool 唯一会跑的任务类型，详见
    // 本文件头"设计要点"第 1/2 点。头文件里把它前置声明成 struct（不是
    // class），这里保持同一关键字，避免 /W4 下的 C4099（先 struct 后 class）
    // 警告在 /WX 下变成编译错误。
    struct WorkbenchPageProvider::InFlightJob final : public QRunnable
    {
        // 构造：把这次读取需要的一切都按值/独立引用计数拷贝进来，run() 执行期间
        // 不再读写 WorkbenchPageProvider 的任何成员（直到结果需要落地，才通过
        // provider 的 QPointer 值间接、且只在 UI 线程上访问，见文件头第 2 点）。
        // 传入：provider 供结果落地用的 QPointer（只传值，不在本线程解引用）；
        //       port 本次读取要用的端口裭指针（生命周期安全见文件头第 4 点）；
        //       session 发起请求时的会话值拷贝；ticket 本次任务的票据；
        //       canvasRevision 画布轴（原样回填用）；targetRevision 目标轴
        //       （陈旧性/闩锁用，Wave 3 决策 2 新增）；jobGeneration 提交时的
        //       provider 代次（D4 新增）；isDdma 发起时会话通道是否为 Ddma；
        //       ranges 本次请求的全部页范围；cancelFlag 本次任务专用的取消标志；
        //       poisoned 共享的"通道中毒"标志（D3 新增，取自
        //       ReadPool::PoisonFlag()）；started（N2 修复新增）provider 自己
        //       记账用的"是否已经开始跑"标志，本构造函数只是原样存一份引用
        //       计数，run() 最开头会把它置位；pool 结果要存进去的那个
        //       ReadPool（非拥有，生命周期覆盖 run() 的整个执行期，因为 pool_
        //       析构前会先清空队列、等正在跑的任务结束，见文件头第 4 点）。
        InFlightJob(
            QPointer<WorkbenchPageProvider> provider,
            ksword::memwb::IMemoryIoPort* port,
            ksword::memwb::MemoryTargetSession session,
            std::uint64_t ticket,
            std::uint64_t canvasRevision,
            std::uint64_t targetRevision,
            std::uint64_t jobGeneration,
            bool isDdma,
            std::vector<HexFetchRange> ranges,
            std::shared_ptr<std::atomic<bool>> cancelFlag,
            std::shared_ptr<std::atomic<bool>> poisoned,
            std::shared_ptr<std::atomic<bool>> started,
            ReadPool* pool, bool foldUnknown = false);

        // run：QThreadPool 的工作线程调用。逐个 range 调用
        // ksword::memwb::ReadPages（除非共享的 poisoned_ 标志已经置位，这种
        // range 整段跳过，见 JobRangeResult::skippedDueToPoison），把结果存进
        // pool 的完成表，再把票据（只有票据，不带结果本身）经
        // Qt::QueuedConnection 排队回 UI 线程，触发
        // WorkbenchPageProvider::onJobFinishedOnUiThread。本函数整体包一层
        // try/catch（D7）：端口实现万一抛出异常，不能让工作线程未捕获异常
        // 终止整个进程——按 channelFailed 处理，剩余尚未处理的 range 会因为
        // 循环直接中断而没有任何记录（落地时逐页回填循环找不到它们的
        // PageRecord，等价于保持 Pending，不展示任何假数据）。
        void run() override;

    private:
        QPointer<WorkbenchPageProvider> provider_;
        ksword::memwb::IMemoryIoPort* port_;
        ksword::memwb::MemoryTargetSession session_;
        std::uint64_t ticket_;
        std::uint64_t canvasRevision_;
        std::uint64_t targetRevision_;
        std::uint64_t jobGeneration_;
        bool isDdma_;
        std::vector<HexFetchRange> ranges_;
        std::shared_ptr<std::atomic<bool>> cancelFlag_;
        std::shared_ptr<std::atomic<bool>> poisoned_;
        // started_（N2 修复新增）：与 provider 侧 PendingJobRecord::started
        // 共享同一个 atomic<bool>；run() 最开头置位，之后不再读写，没有
        // 竞争——UI 线程只在 rereadByteRange 的去重判断里读它。
        std::shared_ptr<std::atomic<bool>> started_;
        ReadPool* pool_;
        bool foldUnknown_ = false;
    };
}
