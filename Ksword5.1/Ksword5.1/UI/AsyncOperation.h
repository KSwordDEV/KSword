#pragma once

// 页面拥有控制器；后台只携带值请求、取消令牌和共享投递门禁。
// 一条控制器最多执行一个 worker，并把后续请求合并为最新一个。
#include "AsyncUiDispatcher.h"
#include "PerfTrace.h"

#include <QObject>
#include <QRunnable>
#include <QThreadPool>

#include <any>
#include <cstdint>
#include <exception>
#include <functional>
#include <memory>
#include <utility>

namespace ks::ui
{
    class AsyncOperation;
    struct AsyncOperationSharedState;
    struct AsyncOperationRequestState;

    // 终态用于值化资源收尾；回调可能在线程池或 Qt 丢弃队列的线程执行。
    enum class AsyncOperationOutcome
    {
        Applied,
        Superseded,
        Canceled,
        OwnerClosed,
        DeliveryDropped,
        Failed,
        BusyRejected
    };

    // 令牌不借用页面对象；后台查询可在昂贵步骤之间读取取消状态。
    class AsyncOperationToken final
    {
    public:
        AsyncOperationToken() = default;
        // 查询当前请求是否取消；空令牌也视为已取消。
        bool isCanceled() const;
        // 返回请求代次；只用于值身份或测试，不读取页面成员。
        std::uint64_t generation() const;
        // 结束后台步骤，排队交给控制器；拒绝或丢队列会统一收尾。
        void deliver(std::any result, std::exception_ptr failure = {}) const noexcept;
#if KSWORD_PERF_TRACE_ENABLED
        PerfTraceContext perfTraceContext() const noexcept;
#endif

    private:
        friend class AsyncOperation;
        AsyncOperationToken(std::shared_ptr<AsyncOperationSharedState> shared,
            std::shared_ptr<AsyncOperationRequestState> request,
            std::shared_ptr<AsyncUiDispatcher> dispatcher, AsyncOperation* receiver);

        std::shared_ptr<AsyncOperationSharedState> m_shared; // 仅含线程安全请求状态。
        std::shared_ptr<AsyncOperationRequestState> m_request; // 本次代次与一次收尾门禁。
        std::shared_ptr<AsyncUiDispatcher> m_dispatcher; // 接收器关闭后拒绝投递。
        AsyncOperation* m_receiver = nullptr; // 仅在门禁保护的 UI 回调内解引用。
    };

    // 控制器必须在页面析构第一步 close()；成员析构再删除 QObject 子对象。
    class AsyncOperation final : public QObject
    {
        struct Job;
    public:
        using Cleanup = std::function<void(AsyncOperationOutcome)>;
        explicit AsyncOperation(QObject* owner);
        ~AsyncOperation() override;

        // request/worker 必须仅持值；apply/failure 仅在所属 UI 线程调用。
        // apply 返回 false 表示菜单等屏障延期；屏障结束调用 completeDeferred。
        // cleanup 只可持值资源，不得访问页面或其他 QObject。
        template<class Request, class Result, class Worker, class Apply, class Failure>
        std::uint64_t submit(Request request, Worker worker, Apply apply,
            Failure failure, Cleanup cleanup = {}, int workerPriority = 0)
        {
            Job job;
            job.apply = makeResultHandler<Result>(std::move(apply));
            job.failure = std::move(failure);
            return submitImpl<false, Request, Result>(std::move(request), std::move(worker),
                std::move(job), std::move(cleanup), workerPriority);
        }

        // 已接受的副作用事务不合并、不取消；忙/关闭返回0，worker只接值请求。
        // worker与值资源收尾独立于页面存活；成功回执仍只交给有效UI拥有者。
        template<class Request, class Result, class Worker, class Apply, class Failure>
        std::uint64_t submitTransaction(Request request, Worker worker, Apply apply,
            Failure failure, Cleanup cleanup = {}, int workerPriority = 0)
        {
            Job job;
            job.apply = makeResultHandler<Result>(std::move(apply));
            job.failure = std::move(failure);
            return submitImpl<true, Request, Result>(std::move(request), std::move(worker),
                std::move(job), std::move(cleanup), workerPriority);
        }

    private:
        template<class Result, class Apply>
        static auto makeResultHandler(Apply apply)
        {
            return [apply = std::move(apply)](const std::any& payload, std::uint64_t ticket)
            {
                const auto& result = std::any_cast<const std::shared_ptr<Result>&>(payload);
                return apply(*result, ticket);
            };
        }

        // GUI回调已经由Job拥有；后台启动器不再把Apply/Failure类型嵌入每层实例，
        // 事务直接调用原worker，省去再包一层带全部回调类型的适配lambda。
        template<bool Transaction, class Request, class Result, class Worker>
        std::uint64_t submitImpl(Request request, Worker worker, Job job,
            Cleanup cleanup, int workerPriority)
        {
            job.transaction = Transaction;
            job.launch = [request = std::move(request), worker = std::move(worker), workerPriority,
                cpu = TaskCpuScope::capture()](
                const AsyncOperationToken& token)
            {
                // worker 不持页面守卫；业务查询仍使用既有全局 Qt 线程池。
                // worker可持有需要移动的值请求；mutable只作用于本任务副本，不共享页面或其它请求状态。
                auto* task = QRunnable::create([request, worker, token, cpu]() mutable
                {
                    const TaskCpuScope measurement(cpu, TaskCpuPhase::Worker);
#if KSWORD_PERF_TRACE_ENABLED
                    const auto traceContext = token.perfTraceContext();
                    const PerfTraceContextScope context(traceContext);
                    PerfScope phase(traceContext.requestId ? "perf_async_worker" : nullptr, QString());
#endif
                    try
                    {
                        if constexpr (!Transaction)
                        {
                            if (token.isCanceled())
                            {
                                token.deliver({});
                                return;
                            }
                        }
                        if constexpr (Transaction)
                            token.deliver(std::make_shared<Result>(worker(request)));
                        else
                            token.deliver(std::make_shared<Result>(worker(request, token)));
                    }
                    catch (...)
                    {
                        token.deliver({}, std::current_exception());
                    }
                });
                task->setAutoDelete(true);
                QThreadPool::globalInstance()->start(task, workerPriority);
            };
            return enqueue(std::move(job), std::move(cleanup));
        }

    public:
        // 主线程取消当前/待执行请求；仍等已运行 worker 返回，避免叠加实际查询。
        void cancel();
        // 析构前关闭门禁并取消全部值资源；可以重复调用。
        void close();
        // 完成菜单延期提交，代次不匹配时只允许收尾该旧请求。
        void completeDeferred(std::uint64_t generation);
        // 查询最新有效代次，延期重放前必须再次调用。
        bool isCurrent(std::uint64_t generation) const;
        std::uint64_t generation() const;
        bool isBusy() const;
        bool hasPending() const;
        bool isInFlight() const;
        // UI 状态回调只保存在控制器中，不进入 worker；关闭时不回调页面。
        void setStateChangedCallback(std::function<void()> callback);

    private:
        friend class AsyncOperationToken;
        struct Job
        {
            std::shared_ptr<AsyncOperationRequestState> request; // 对应一次请求状态。
            std::function<void(const AsyncOperationToken&)> launch; // 仅捕获值请求和 worker。
            std::function<bool(const std::any&, std::uint64_t)> apply; // UI 应用入口。
            std::function<void(std::exception_ptr)> failure; // UI 错误入口。
            bool awaitingCommit = false; // worker 已结束，等待 UI 屏障。
            bool launched = false; // 状态回调重入时仍只允许启动一次实际 worker。
            bool transaction = false; // 已接受事务只允许最终完成，不作latest-only合并。
        };

        std::uint64_t enqueue(Job job, Cleanup cleanup);
        void launchActive();
        void complete(const std::shared_ptr<AsyncOperationRequestState>& request,
            const std::any& result, std::exception_ptr failure);
        void finishActive(AsyncOperationOutcome outcome);
        void reconcileDroppedJobs();
        void notifyStateChanged();

        std::shared_ptr<AsyncOperationSharedState> m_shared; // 跨线程请求状态不含 UI 回调。
        std::shared_ptr<AsyncUiDispatcher> m_dispatcher; // 专属控制器接收器门禁。
        std::unique_ptr<Job> m_active; // 所属线程中的当前任务与 UI 回调。
        std::unique_ptr<Job> m_pending; // 所属线程中的最新待运行任务。
        std::function<void()> m_stateChanged; // 兼容页面原有 busy 标志。
    };
}
