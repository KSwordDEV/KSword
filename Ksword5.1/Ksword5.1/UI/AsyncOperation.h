#pragma once

// 页面拥有控制器；后台只携带值请求、取消令牌和共享投递门禁。
// 一条控制器最多执行一个 worker，并把后续请求合并为最新一个。
#include "AsyncUiDispatcher.h"

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
        Failed
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
        void deliver(std::any result, std::exception_ptr failure = {}) const;

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
    public:
        using Cleanup = std::function<void(AsyncOperationOutcome)>;
        explicit AsyncOperation(QObject* owner);
        ~AsyncOperation() override;

        // request/worker 必须仅持值；apply/failure 仅在所属 UI 线程调用。
        // apply 返回 false 表示菜单等屏障延期；屏障结束调用 completeDeferred。
        // cleanup 只可持值资源，不得访问页面或其他 QObject。
        template<class Request, class Result, class Worker, class Apply, class Failure>
        std::uint64_t submit(Request request, Worker worker, Apply apply,
            Failure failure, Cleanup cleanup = {})
        {
            Job job; // 主线程保存应用回调，后台任务不捕获它们。
            job.apply = [apply = std::move(apply)](const std::any& payload, std::uint64_t ticket)
            {
                const auto& result = std::any_cast<const std::shared_ptr<Result>&>(payload);
                return apply(*result, ticket);
            };
            job.failure = std::move(failure);
            job.launch = [request = std::move(request), worker = std::move(worker)](
                const AsyncOperationToken& token)
            {
                // worker 不持页面守卫；业务查询仍使用既有全局 Qt 线程池。
                auto* task = QRunnable::create([request, worker, token]()
                {
                    try
                    {
                        if (token.isCanceled())
                        {
                            token.deliver({});
                            return;
                        }
                        auto result = std::make_shared<Result>(worker(request, token));
                        token.deliver(std::move(result));
                    }
                    catch (...)
                    {
                        token.deliver({}, std::current_exception());
                    }
                });
                task->setAutoDelete(true);
                QThreadPool::globalInstance()->start(task);
            };
            return enqueue(std::move(job), std::move(cleanup));
        }

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
