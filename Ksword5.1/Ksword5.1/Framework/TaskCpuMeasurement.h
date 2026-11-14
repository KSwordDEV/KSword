#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>

namespace ks::ui
{
    // Value-only attribution may cross threads; it never owns a QObject or timer.
    enum class TaskCpuPhase : unsigned { Dispatch, Worker, Completion };
    struct TaskCpuReading { std::uint64_t time100ns = 0; bool valid = false; };
    struct TaskCpuStats
    {
        std::array<std::uint64_t, 3> time100ns{}, samples{}, unavailable{};
    };
    struct TaskCpuSession
    {
        using Reader = TaskCpuReading (*)();
        explicit TaskCpuSession(Reader read) : reader(read) {}
        Reader reader;
        std::atomic_bool enabled{true};
        std::mutex mutex; // Serializes freeze/reset against a finishing worker.
        void stop()
        {
            std::lock_guard<std::mutex> lock(mutex);
            enabled.store(false, std::memory_order_relaxed);
        }
    };
    struct TaskCpuCounter
    {
        explicit TaskCpuCounter(std::shared_ptr<TaskCpuSession> value) : session(std::move(value)) {}
        std::shared_ptr<TaskCpuSession> session;
        TaskCpuStats stats;
        std::atomic_uint inFlight{0};
        TaskCpuStats snapshot() const
        {
            std::lock_guard<std::mutex> lock(session->mutex);
            return stats;
        }
    };
    using TaskCpuToken = std::shared_ptr<TaskCpuCounter>;

    // Exclusive thread CPU time: nested task/event scopes suspend their parent.
    // Empty scopes isolate unrelated nested Qt events. Disabled scopes read no clocks.
    class TaskCpuScope final
    {
    public:
        explicit TaskCpuScope(TaskCpuToken token = {}, TaskCpuPhase phase = TaskCpuPhase::Dispatch)
            : m_token(std::move(token)), m_phase(static_cast<unsigned>(phase)), m_parent(s_current)
        {
            if (m_token && !m_token->session->enabled.load(std::memory_order_relaxed)) m_token.reset();
            if (!m_token && !m_parent) return;
            if (m_parent) m_parent->pause();
            s_current = this;
            m_entered = true;
            if (m_token) { ++m_token->inFlight; resume(); }
        }
        ~TaskCpuScope()
        {
            if (!m_entered) return;
            pause();
            if (m_token)
            {
                std::lock_guard<std::mutex> lock(m_token->session->mutex);
                if (m_token->session->enabled.load(std::memory_order_relaxed))
                {
                    if (m_valid)
                    {
                        m_token->stats.time100ns[m_phase] += m_total;
                        ++m_token->stats.samples[m_phase];
                    }
                    else ++m_token->stats.unavailable[m_phase];
                }
                --m_token->inFlight;
            }
            s_current = m_parent;
            if (m_parent) m_parent->resume();
        }
        TaskCpuScope(const TaskCpuScope&) = delete;
        TaskCpuScope& operator=(const TaskCpuScope&) = delete;
        static bool hasCurrent() { return s_current != nullptr; }
        static TaskCpuToken capture()
        {
            if (!s_current || !s_current->m_token
                || !s_current->m_token->session->enabled.load(std::memory_order_relaxed)) return {};
            return s_current->m_token;
        }
        template<class Callback> static auto wrap(TaskCpuPhase phase, Callback callback)
        {
            return [token = capture(), phase, callback = std::move(callback)](auto&&... args) mutable -> decltype(auto)
            {
                TaskCpuScope scope(token, phase);
                return callback(std::forward<decltype(args)>(args)...);
            };
        }
    private:
        void resume()
        {
            if (!m_token || !m_token->session->enabled.load(std::memory_order_relaxed)) return;
            m_start = m_token->session->reader();
            m_running = true;
        }
        void pause()
        {
            if (!m_running) return;
            m_running = false;
            const auto end = m_token->session->reader();
            if (m_start.valid && end.valid && end.time100ns >= m_start.time100ns)
                m_total += end.time100ns - m_start.time100ns;
            else m_valid = false;
        }
        inline static thread_local TaskCpuScope* s_current = nullptr;
        TaskCpuToken m_token;
        unsigned m_phase;
        TaskCpuScope* m_parent;
        TaskCpuReading m_start;
        std::uint64_t m_total = 0;
        bool m_entered = false, m_running = false, m_valid = true;
    };
}
