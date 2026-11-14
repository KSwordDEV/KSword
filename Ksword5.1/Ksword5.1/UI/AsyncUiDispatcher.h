#pragma once
#include "../Framework/TaskCpuMeasurement.h"

#include <QtCore/QMetaObject>
#include <QtCore/QObject>

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <utility>

namespace ks::ui
{
    // 后台任务只持有此共享门禁；控件析构第一步必须 close()。
    // 同一把锁使 post 不会在接收器开始销毁后借用 QObject，也无需借用 QApplication。
    class AsyncUiDispatcher final
    {
    public:
        explicit AsyncUiDispatcher(QObject* receiver) : m_receiver(receiver) {}

        void close()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_receiver = nullptr;
            m_closed->store(true);
        }

        bool post(std::function<void()> callback, std::function<void()> onCanceled = {})
        {
            // Qt 丢弃已入队的 functor 时同样触发收尾，不能只处理 invokeMethod=false。
            const auto pending = std::make_shared<PendingCallback>(
                std::move(callback), std::move(onCanceled));
            // pending 先于 lock 构造，拒绝投递或 Qt 同步丢弃 functor 时，取消收尾在解锁后执行。
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_receiver != nullptr && QMetaObject::invokeMethod(
                m_receiver, [pending, closed = m_closed]()
                {
                    if (!closed->load())
                    {
                        pending->run();
                    }
                }, Qt::QueuedConnection);
        }

    private:
        struct PendingCallback final
        {
            PendingCallback(std::function<void()> action, std::function<void()> canceled)
                : callback(std::move(action)), onCanceled(std::move(canceled)) {}

            ~PendingCallback()
            {
                if (!claimed.load() && onCanceled)
                {
                    try { onCanceled(); } catch (...) {} // 不能越过Qt丢队列/析构边界。
                }
            }

            void run()
            {
                claimed.store(true);
                const TaskCpuScope measurement(cpu, TaskCpuPhase::Completion);
                callback();
            }

            std::function<void()> callback;
            std::function<void()> onCanceled;
            std::atomic_bool claimed{ false };
            TaskCpuToken cpu = TaskCpuScope::capture();
        };

        std::mutex m_mutex;
        QObject* m_receiver;
        std::shared_ptr<std::atomic_bool> m_closed = std::make_shared<std::atomic_bool>(false);
    };
}
