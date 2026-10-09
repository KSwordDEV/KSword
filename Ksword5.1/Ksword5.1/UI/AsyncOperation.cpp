#include "AsyncOperation.h"

#include <QThread>
#include <QPointer>

#include <atomic>
#include <mutex>
#include <vector>

namespace ks::ui
{
    // 此状态不含 QObject/页面回调，取消和一次值资源收尾可安全跨线程。
    struct AsyncOperationRequestState
    {
        std::uint64_t generation = 0; // 请求创建后保持不变的代次。
        std::atomic_bool canceled{ false }; // 合作式查询取消门禁。
        std::atomic_bool settled{ false }; // 成功、取消和丢队列共用一次收尾。
        AsyncOperation::Cleanup cleanup; // 只持值资源的最终回调。

        // 所有终态竞争同一个 CAS；收尾不能把异常带入 Qt functor 析构。
        void settle(const AsyncOperationOutcome outcome)
        {
            if (!settled.exchange(true) && cleanup)
            {
                try
                {
                    cleanup(outcome);
                }
                catch (...)
                {
                    // 用户值资源收尾失败也不得重复执行或越过析构边界。
                }
            }
        }
    };

    // active/pending 仅存请求值状态；真实 UI 回调保存在控制器 Job 中。
    struct AsyncOperationSharedState
    {
        mutable std::mutex mutex; // 请求状态与后台队列丢弃共用锁。
        std::uint64_t generation = 0; // 最新被接受或取消的代次。
        bool closed = false; // 页面关闭后不再接受任何请求。
        std::shared_ptr<AsyncOperationRequestState> active; // 已启动或等待 UI 提交的请求。
        std::shared_ptr<AsyncOperationRequestState> pending; // 最新合并待执行请求。

        // 接收器队列丢失时，当前请求与无法启动的 pending 均统一释放。
        void drop(const std::shared_ptr<AsyncOperationRequestState>& request)
        {
            std::shared_ptr<AsyncOperationRequestState> abandonedPending; // 锁外收尾。
            {
                std::lock_guard<std::mutex> lock(mutex);
                if (active == request)
                {
                    active.reset();
                    abandonedPending = std::move(pending);
                    ++generation;
                }
            }
            request->canceled.store(true);
            request->settle(AsyncOperationOutcome::DeliveryDropped);
            if (abandonedPending)
            {
                abandonedPending->canceled.store(true);
                abandonedPending->settle(AsyncOperationOutcome::DeliveryDropped);
            }
        }
    };

    // 令牌只保存线程安全状态和专属投递门禁；receiver 不在 worker 中解引用。
    AsyncOperationToken::AsyncOperationToken(std::shared_ptr<AsyncOperationSharedState> shared,
        std::shared_ptr<AsyncOperationRequestState> request,
        std::shared_ptr<AsyncUiDispatcher> dispatcher, AsyncOperation* receiver)
        : m_shared(std::move(shared)), m_request(std::move(request)),
          m_dispatcher(std::move(dispatcher)), m_receiver(receiver)
    {
    }

    bool AsyncOperationToken::isCanceled() const
    {
        return !m_request || m_request->canceled.load();
    }

    std::uint64_t AsyncOperationToken::generation() const
    {
        return m_request ? m_request->generation : 0;
    }

    // 即使投递成功，Qt 稍后丢弃该 functor 时也会走同一状态收尾。
    void AsyncOperationToken::deliver(std::any result, std::exception_ptr failure) const
    {
        if (!m_request || !m_dispatcher)
        {
            return;
        }
        const auto shared = m_shared; // 共享的非 UI 请求状态。
        const auto request = m_request; // 本次请求身份。
        AsyncOperation* const receiver = m_receiver; // 仅在排队回调中使用。
        m_dispatcher->post([receiver, request, result = std::move(result), failure]()
        {
            receiver->complete(request, result, failure);
        }, [shared, request]()
        {
            shared->drop(request);
        });
    }

    AsyncOperation::AsyncOperation(QObject* owner)
        : QObject(owner), m_shared(std::make_shared<AsyncOperationSharedState>()),
          m_dispatcher(std::make_shared<AsyncUiDispatcher>(this))
    {
        // 成员拥有时会先显式关闭；作为普通 QObject 子对象时再提供销毁兜底。
        if (owner)
        {
            QObject::connect(owner, &QObject::destroyed, this, [this]() { close(); });
        }
    }

    AsyncOperation::~AsyncOperation()
    {
        close();
    }

    // 保持单个实际 worker；连续替换只更新 pending，不产生线程池风暴。
    std::uint64_t AsyncOperation::enqueue(Job job, Cleanup cleanup)
    {
        Q_ASSERT(QThread::currentThread() == thread());
        reconcileDroppedJobs();
        auto request = std::make_shared<AsyncOperationRequestState>(); // 新请求的值状态。
        request->cleanup = std::move(cleanup);
        std::shared_ptr<AsyncOperationRequestState> replaced; // 旧 pending 的收尾对象。
        std::shared_ptr<AsyncOperationRequestState> deferred; // worker 已结束的旧请求。
        bool launch = false; // 本次请求是否立即启动。
        {
            std::lock_guard<std::mutex> lock(m_shared->mutex);
            if (m_shared->closed)
            {
                request->canceled.store(true);
            }
            else
            {
                request->generation = ++m_shared->generation;
                job.request = request;
                replaced = std::move(m_shared->pending);
                m_pending.reset();
                if (m_shared->active)
                {
                    m_shared->active->canceled.store(true);
                }
                // 菜单延期不占用实际 worker；新请求可以直接取代旧提交。
                if (m_active && m_active->awaitingCommit)
                {
                    deferred = std::move(m_shared->active);
                    m_active.reset();
                }
                if (m_shared->active)
                {
                    m_shared->pending = request;
                    m_pending = std::make_unique<Job>(std::move(job));
                }
                else
                {
                    m_shared->active = request;
                    m_active = std::make_unique<Job>(std::move(job));
                    launch = true;
                }
            }
        }
        // cleanup 可调用其他有锁值资源，必须在请求状态锁外执行。
        if (!request->generation)
        {
            request->settle(AsyncOperationOutcome::OwnerClosed);
            return 0;
        }
        for (const auto& oldRequest : { replaced, deferred })
        {
            if (oldRequest)
            {
                oldRequest->canceled.store(true);
                oldRequest->settle(AsyncOperationOutcome::Superseded);
            }
        }
        const QPointer<AsyncOperation> guard(this); // 状态回调可同步关闭或销毁所属对象。
        notifyStateChanged();
        if (!guard.isNull() && launch)
        {
            launchActive();
        }
        return request->generation;
    }

    void AsyncOperation::launchActive()
    {
        if (!m_active || m_active->launched)
        {
            return;
        }
        m_active->launched = true;
        const auto request = m_active->request; // 回调/异常返回后重新校验的请求身份。
        const QPointer<AsyncOperation> guard(this); // 回调可能销毁控制器。
        const AsyncOperationToken token(m_shared, m_active->request, m_dispatcher, this);
        try
        {
            m_active->launch(token);
        }
        catch (...)
        {
            if (!guard.isNull() && m_active && m_active->request == request)
            {
                complete(request, {}, std::current_exception());
            }
        }
    }

    // 所有页面更新只从此 UI 入口发出，先验证代次，再处理错误或延期提交。
    void AsyncOperation::complete(const std::shared_ptr<AsyncOperationRequestState>& request,
        const std::any& result, std::exception_ptr failure)
    {
        Q_ASSERT(QThread::currentThread() == thread());
        reconcileDroppedJobs();
        if (!m_active || m_active->request != request)
        {
            return;
        }
        if (!isCurrent(request->generation))
        {
            finishActive(AsyncOperationOutcome::Superseded);
            return;
        }
        const QPointer<AsyncOperation> guard(this); // UI 回调可能嵌套销毁所属页面。
        try
        {
            // 应用回调本身可能 close；局部副本避免关闭时销毁正在执行的 callable。
            const auto apply = m_active->apply;
            const bool committed = failure || apply(result, request->generation);
            if (guard.isNull() || !m_active || m_active->request != request)
            {
                return;
            }
            if (!committed && isCurrent(request->generation))
            {
                m_active->awaitingCommit = true;
                return;
            }
        }
        catch (...)
        {
            failure = std::current_exception();
        }
        if (guard.isNull() || !m_active || m_active->request != request)
        {
            return;
        }
        if (!isCurrent(request->generation))
        {
            // apply 可重入接受新请求后再抛异常；旧错误不得覆盖新代次的页面状态。
            finishActive(AsyncOperationOutcome::Superseded);
            return;
        }
        if (failure)
        {
            // 错误回调同样不能把异常带出 Qt 事件循环。
            try
            {
                const auto onFailure = m_active->failure; // 保证 close 后 callable 仍活到返回。
                onFailure(failure);
            }
            catch (...)
            {
            }
        }
        if (!guard.isNull() && m_active && m_active->request == request)
        {
            finishActive(failure ? AsyncOperationOutcome::Failed :
                (isCurrent(request->generation) ? AsyncOperationOutcome::Applied
                    : AsyncOperationOutcome::Superseded));
        }
    }

    // 先释放旧请求，再启动最新 pending；结束后状态回调读取的是新一轮状态。
    void AsyncOperation::finishActive(const AsyncOperationOutcome outcome)
    {
        if (!m_active)
        {
            return;
        }
        const auto finished = m_active->request; // 锁外统一收尾的旧请求。
        m_active.reset();
        {
            std::lock_guard<std::mutex> lock(m_shared->mutex);
            if (m_shared->active == finished)
            {
                m_shared->active = std::move(m_shared->pending);
            }
        }
        finished->settle(outcome);
        m_active = std::move(m_pending);
        const QPointer<AsyncOperation> guard(this); // 状态通知可能同步销毁页面。
        notifyStateChanged();
        if (!guard.isNull())
        {
            launchActive();
        }
    }

    void AsyncOperation::completeDeferred(const std::uint64_t ticket)
    {
        Q_ASSERT(QThread::currentThread() == thread());
        reconcileDroppedJobs();
        if (m_active && m_active->awaitingCommit && m_active->request->generation == ticket)
        {
            finishActive(isCurrent(ticket) ? AsyncOperationOutcome::Applied
                : AsyncOperationOutcome::Superseded);
        }
    }

    // 用户取消立即收尾值资源；实际 worker 返回前仍占单个执行槽。
    void AsyncOperation::cancel()
    {
        Q_ASSERT(QThread::currentThread() == thread());
        std::shared_ptr<AsyncOperationRequestState> active; // 正在运行的请求。
        std::shared_ptr<AsyncOperationRequestState> pending; // 尚未启动的请求。
        {
            std::lock_guard<std::mutex> lock(m_shared->mutex);
            ++m_shared->generation;
            active = m_shared->active;
            pending = std::move(m_shared->pending);
        }
        m_pending.reset();
        for (const auto& request : { active, pending })
        {
            if (request)
            {
                request->canceled.store(true);
                request->settle(AsyncOperationOutcome::Canceled);
            }
        }
        if (m_active && m_active->awaitingCommit)
        {
            finishActive(AsyncOperationOutcome::Canceled);
            return; // finishActive 已通知状态，不能在销毁回调后再次访问 this。
        }
        notifyStateChanged();
    }

    // 页面析构先关投递门禁；后台不再借用任何正处于销毁阶段的 QObject。
    void AsyncOperation::close()
    {
        m_dispatcher->close();
        std::shared_ptr<AsyncOperationRequestState> active; // 页面关闭的执行请求。
        std::shared_ptr<AsyncOperationRequestState> pending; // 页面关闭的待运行请求。
        {
            std::lock_guard<std::mutex> lock(m_shared->mutex);
            m_shared->closed = true;
            active = std::move(m_shared->active);
            pending = std::move(m_shared->pending);
        }
        m_stateChanged = {};
        m_active.reset();
        m_pending.reset();
        for (const auto& request : { active, pending })
        {
            if (request)
            {
                request->canceled.store(true);
                request->settle(AsyncOperationOutcome::OwnerClosed);
            }
        }
    }

    // Qt 可在控制器仍存在时丢弃完成队列；下次 UI 操作丢弃残留的 UI Job。
    void AsyncOperation::reconcileDroppedJobs()
    {
        std::lock_guard<std::mutex> lock(m_shared->mutex);
        if (m_active && m_shared->active != m_active->request)
        {
            m_active.reset();
        }
        if (m_pending && m_shared->pending != m_pending->request)
        {
            m_pending.reset();
        }
    }

    bool AsyncOperation::isCurrent(const std::uint64_t ticket) const
    {
        std::lock_guard<std::mutex> lock(m_shared->mutex);
        return !m_shared->closed && m_shared->generation == ticket && m_shared->active
            && m_shared->active->generation == ticket && !m_shared->active->canceled.load();
    }

    std::uint64_t AsyncOperation::generation() const
    {
        std::lock_guard<std::mutex> lock(m_shared->mutex);
        return m_shared->generation;
    }

    bool AsyncOperation::isBusy() const
    {
        std::lock_guard<std::mutex> lock(m_shared->mutex);
        return m_shared->pending || (m_shared->active && !m_shared->active->canceled.load());
    }

    bool AsyncOperation::hasPending() const
    {
        std::lock_guard<std::mutex> lock(m_shared->mutex);
        return m_shared->pending != nullptr;
    }

    bool AsyncOperation::isInFlight() const
    {
        std::lock_guard<std::mutex> lock(m_shared->mutex);
        return m_shared->active != nullptr;
    }

    void AsyncOperation::setStateChangedCallback(std::function<void()> callback)
    {
        m_stateChanged = std::move(callback);
    }

    void AsyncOperation::notifyStateChanged()
    {
        const auto callback = m_stateChanged; // close 可以清空成员，但局部副本活到调用结束。
        if (callback)
        {
            callback();
        }
    }
}
