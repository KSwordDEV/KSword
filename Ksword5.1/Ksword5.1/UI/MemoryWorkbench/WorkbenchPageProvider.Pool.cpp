// ============================================================
// WorkbenchPageProvider.Pool.cpp
// 作用：
// - 实现 WorkbenchPageProvider.Pool.h 声明的 ReadPool 与 InFlightJob 两个类型，
//   也就是读路径 R2 "唯一的单线程读池"的全部调度细节。WorkbenchPageProvider.cpp
//   只负责 R1（Gate 判定/会话快照）与 R3（陈旧性核对/回填），本文件只负责
//   "怎么把一批 range 安全地搬到工作线程读完、再安全地把结果搬回 UI 线程"，
//   不关心 Gate、不关心 DDMA 闩锁的业务语义（那些在 WorkbenchPageProvider.cpp
//   的 onJobFinishedOnUiThread 里）；本文件也不关心 channelFailed/scratchAreaDirty
//   之后"要不要停"的业务判断之外的东西——D3 的"通道中毒"标志本身只是一个
//   机械的共享开关，是否要置位由 run() 按 PageReadResult 的两个字段机械判断，
//   不掺入任何只有 UI 线程才知道的状态（例如闩锁所属的目标代次）。
// ============================================================

#include "WorkbenchPageProvider.Pool.h"

#include <QCoreApplication>
#include <QMetaObject>

#include <exception>
#include <algorithm>
#include <utility>

namespace ks::ui
{
    // ---------------- WorkbenchPageProvider::ReadPool ----------------

    WorkbenchPageProvider::ReadPool::ReadPool()
        : poisoned_(std::make_shared<std::atomic<bool>>(false))
    {
        // 不变式 5 的落实点：唯一的单线程池，任何时刻最多一个任务在跑，
        // 不同任务之间端口侧的调用永远不会重叠。
        pool_.setMaxThreadCount(1);
    }

    WorkbenchPageProvider::ReadPool::~ReadPool()
    {
        // 先把"排队积压 + 正在跑的那一个"都处理掉——见 CancelAll 的注释。
        // 之后 pool_（QThreadPool 成员）的默认析构会接管：它会等待仍在跑的
        // 任务结束（Qt 的既定行为，无法绕开），但经过上面这一步，等待的只是
        // "至多一次 Read 调用"的耗时，不是排队积压的耗时，也不是无限等待。
        CancelAll();
    }

    void WorkbenchPageProvider::ReadPool::Submit(
        QRunnable* job, std::uint64_t ticket, std::shared_ptr<std::atomic<bool>> cancelFlag)
    {
        // 先登记取消标志再提交：避免"刚提交、还没登记"这极窄的窗口里，万一
        // 任务瞬间跑完又触发 CancelAll，CancelAll 找不到这张记账——提交之后
        // Finish 会自己摘掉它，不会有人遗漏清理。
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelFlags_[ticket] = std::move(cancelFlag);
        }
        pool_.start(job);
    }

    void WorkbenchPageProvider::ReadPool::CancelAll()
    {
        // 第一步：丢弃排队中尚未开始的任务。QThreadPool::clear() 只移除还没
        // 开始跑的 QRunnable；它们 setAutoDelete(true)，clear() 会直接删除
        // 而不调用 run()——这些任务永远不会产生任何回调，也就不需要（也没有
        // 机会）单独处理它们各自的取消标志。这一步把"等待时间随排队积压线性
        // 增长"的风险砍掉，剩下的等待上限就是"至多一个正在跑的任务"。
        // Provider-owned descriptors were already removed. Keep the sole dispatched
        // runnable: even a not-yet-started cancelled job must run and Finish so its
        // physical-worker slot retires before another source can dispatch.


        // 第二步：给仍记在账上的任务（此刻只可能是"正在跑的那一个"，因为
        // 刚被 clear() 丢弃的那些从未被记进这张表之外的任何地方访问——它们的
        // 记账条目会在下面一起清空）置位取消标志，让它在下一次 Read 之前的
        // 检查点尽快发现并提前返回（ksword::memwb::ReadPages 的"每次发起 Read
        // 之前先检查 cancel"）。
        std::lock_guard<std::mutex> lock(mutex_);
        for (auto& entry : cancelFlags_)
        {
            if (entry.second)
            {
                entry.second->store(true);
            }
        }
        // 清空整张表：被 clear() 丢弃的任务不会再触发 Finish 来摘掉自己的条目，
        // 这里统一清掉，避免它们的 shared_ptr 一直被这张表多余地引用着
        // （纯粹是记账整洁，不影响安全性——那些 shared_ptr 指向的 atomic<bool>
        // 本来就不会再被任何人读取了）。
        cancelFlags_.clear();
    }

    void WorkbenchPageProvider::ReadPool::Finish(std::uint64_t ticket, CompletedJob job)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // 摘掉这次任务的取消标志记账——它已经跑完，用不到了。
        cancelFlags_.erase(ticket);
        completed_[ticket] = std::move(job);
    }

    std::optional<WorkbenchPageProvider::ReadPool::CompletedJob>
    WorkbenchPageProvider::ReadPool::TakeCompleted(std::uint64_t ticket)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = completed_.find(ticket);
        if (it == completed_.end())
        {
            // 找不到：可能票据从未存在，也可能这份结果早被别的路径（目前
            // 没有别的路径会主动清空 completed_，但保持防御）清理过。调用方
            // 据此判断"没有东西可核对"，直接丢弃。
            return std::nullopt;
        }
        CompletedJob result = std::move(it->second);
        completed_.erase(it);
        return result;
    }

    void WorkbenchPageProvider::ReadPool::ResetPoison()
    {
        // UI 线程在每次正式提交新任务之前调用；见头文件 ResetPoison 的说明。
        if (poisoned_)
        {
            poisoned_->store(false);
        }
    }

    std::shared_ptr<std::atomic<bool>> WorkbenchPageProvider::ReadPool::PoisonFlag() const
    {
        return poisoned_;
    }

    // ---------------- WorkbenchPageProvider::InFlightJob ----------------

    WorkbenchPageProvider::InFlightJob::InFlightJob(
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
        ReadPool* pool, bool foldUnknown)
        : provider_(std::move(provider))
        , port_(port)
        , session_(std::move(session))
        , ticket_(ticket)
        , canvasRevision_(canvasRevision)
        , targetRevision_(targetRevision)
        , jobGeneration_(jobGeneration)
        , isDdma_(isDdma)
        , ranges_(std::move(ranges))
        , cancelFlag_(std::move(cancelFlag))
        , poisoned_(std::move(poisoned))
        , started_(std::move(started))
        , pool_(pool)
        , foldUnknown_(foldUnknown)
    {
        // autoDelete=true：线程池会在 run() 返回后自动释放本对象，调用方
        // （WorkbenchPageProvider::RequestPages）不持有也不需要释放它。
        setAutoDelete(true);
    }

    void WorkbenchPageProvider::InFlightJob::run()
    {
        // 工作线程：从这里到把结果存进 pool_ 之前，只触碰 session_/ranges_/
        // cancelFlag_/poisoned_/port_ 这几个值或裭指针，绝不触碰 HexCanvas、
        // WorkbenchPageProvider、WorkbenchTarget 的任何成员——port_ 的生命周期
        // 安全由 WorkbenchPageProvider.h 的成员声明顺序保证（见
        // WorkbenchPageProvider.Pool.h 文件头第 4 点），这里只管按顺序调用。
        // N2 修复：一进入 run()（线程池真的把这个任务排上了，不再是"还在
        // 队列里等"）就立刻置位——UI 线程的 rereadByteRange 据此判断这一个
        // 记账是否还"安全可去重"，见 WorkbenchPageProvider.h 文件头 N2 一节
        // 与本文件头第 7 点。放在最前面，早于任何可能抛异常的调用，保证
        // "run() 已经被调用"与"started_==true"严格同义。
        if (started_)
        {
            started_->store(true);
        }

        ReadPool::CompletedJob completed;
        completed.canvasRevision = canvasRevision_;
        completed.targetRevision = targetRevision_;
        completed.isDdma = isDdma_;
        completed.jobGeneration = jobGeneration_;
        completed.rangeResults.reserve(ranges_.size());

        // D7：端口实现（真实端口或测试假端口）抛出的任何异常都不能让工作线程
        // 带着未捕获异常退出——那会让整个进程 std::terminate。按 channelFailed
        // 处理：剩下没来得及处理的 range 没有任何记录，落地时的逐页回填循环
        // 根本看不到它们，等价于这些地址保持 Pending，不会展示任何假数据。
        try
        {
            for (const HexFetchRange& range : ranges_)
            {
                // D3：共享的"通道中毒"标志——同一任务内更早的 range，或排在
                // 前面、已经跑过的另一个任务，一旦遇到通道失败/暂存区弄脏，
                // 就会把它置位。本任务每个 range 开始之前都重新检查一次，
                // 命中就整段跳过，不再碰端口。
                if (poisoned_ && poisoned_->load())
                {
                    JobRangeResult skipped;
                    skipped.range = range;
                    skipped.skippedDueToPoison = true;
                    completed.rangeResults.push_back(std::move(skipped));
                    continue;
                }

                ksword::memwb::PageReadResult pageResult = ksword::memwb::ReadPages(
                    *port_, session_, range.firstPageStart, range.pageCount, cancelFlag_.get());
                const bool shouldPoison = pageResult.channelFailed || pageResult.scratchAreaDirty;
                JobRangeResult entry{range, std::move(pageResult), false, {}};
                if (foldUnknown_ && !shouldPoison && !entry.result.cancelled)
                {
                    for (const auto& page : entry.result.pages)
                    {
                        if (cancelFlag_ && cancelFlag_->load()) break;
                        if (page.state != ksword::memwb::PageState::Unreadable) continue;
                        const bool covered = std::any_of(entry.unreadableExtents.begin(), entry.unreadableExtents.end(),
                            [&page](const auto& extent) { return page.pageStart >= extent.first && page.pageStart <= extent.last; });
                        if (covered) continue;
                        // Optional metadata must not turn a successful read into channel failure.
                        try
                        {
                            const auto extent = port_->QueryUnreadableExtent(session_, page.pageStart);
                            if (extent && extent->first <= page.pageStart && extent->last >= page.pageStart)
                                entry.unreadableExtents.push_back(*extent);
                        }
                        catch (...) {}
                    }
                }
                completed.rangeResults.push_back(std::move(entry));
                if (shouldPoison && poisoned_)
                {
                    poisoned_->store(true);
                }
            }
        }
        catch (const std::exception& ex)
        {
            ksword::memwb::PageReadResult failure;
            failure.channelFailed = true;
            failure.failure = std::string("WorkbenchPageProvider worker exception: ") + ex.what();
            completed.rangeResults.push_back(
                JobRangeResult{ranges_.empty() ? HexFetchRange{} : ranges_.front(), std::move(failure), false, {}});
            if (poisoned_)
            {
                poisoned_->store(true);
            }
        }
        catch (...)
        {
            ksword::memwb::PageReadResult failure;
            failure.channelFailed = true;
            failure.failure = "WorkbenchPageProvider worker exception: unknown";
            completed.rangeResults.push_back(
                JobRangeResult{ranges_.empty() ? HexFetchRange{} : ranges_.front(), std::move(failure), false, {}});
            if (poisoned_)
            {
                poisoned_->store(true);
            }
        }

        if (pool_ != nullptr)
        {
            pool_->Finish(ticket_, std::move(completed));
        }

        // 回 UI 线程：只把 provider 的 QPointer"值"（不是 data() 取出的裭指针）
        // 与票据带进 lambda；QMetaObject::invokeMethod 的 context 用进程内
        // 长期存活的 QCoreApplication::instance()。这是
        // WorkbenchTarget.Modules.cpp 的 D1 修复同款写法：真正的判空只在 lambda
        // 落到 UI 线程执行的那一刻做（QPointer 的失效通知与这一刻同在 UI
        // 线程，不存在竞态窗口）；本函数自己不做任何判空短路（不像
        // ModuleEnumTask 还有一个"显然已经不在了"的提前返回优化——这里省略
        // 那一步纯粹是因为本类任务通常很快，没有必要为了省一次排队调用而
        // 多一次对 QPointer 的读取,两种写法都安全,这里选更简单的一种）。
        const QPointer<WorkbenchPageProvider> providerPointer = provider_;
        const std::uint64_t ticket = ticket_;
        QMetaObject::invokeMethod(
            QCoreApplication::instance(),
            [providerPointer, ticket]()
            {
                WorkbenchPageProvider* provider = providerPointer.data();
                if (provider == nullptr)
                {
                    // 已经在 UI 线程：provider 已被销毁，这次迟到的结果直接
                    // 丢弃——设计好的正常路径，不是缺陷。
                    return;
                }
                provider->onJobFinishedOnUiThread(ticket);
            },
            Qt::QueuedConnection);
    }
}
