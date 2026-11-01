#pragma once

#include <cstdint>
#include <mutex>

namespace ks::process
{
    struct ProcessEtwCaptureDemand
    {
        bool monitoring = false;
        bool processListVisible = false;
        bool background = false;
        bool visibleDetail = false;
        bool cpuColumnVisible = false;

        bool RefreshAllowed() const
        {
            return monitoring && (processListVisible || background || visibleDetail);
        }
        bool RecordingAllowed() const
        {
            return monitoring && (processListVisible || background);
        }
        bool CpuCaptureAllowed() const
        {
            return RefreshAllowed() && (cpuColumnVisible || visibleDetail);
        }
    };

    // One worker owns all Start/Stop calls. Requests are cheap and never wait for ETW.
    // A failed start is retried only after a new false -> true demand generation.
    class ProcessEtwCaptureLifecycle final
    {
    public:
        explicit ProcessEtwCaptureLifecycle(const std::uint64_t initialGeneration = 0)
            : m_generation(initialGeneration) {}
        enum class Operation { None, Start, Stop };

        bool Request(const bool desired)
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            if (m_closing && desired) return false;
            ++m_requestRevision;
            if (m_desired != desired)
            {
                m_desired = desired;
                ++m_generation;
                if (!desired && (m_owned || m_workerScheduled))
                {
                    m_stopRequired = true;
                }
            }
            const bool needsStop = m_owned && (!m_desired || m_stopRequired || m_cleanupPending);
            const bool needsStart = !m_closing && m_desired && !m_owned && m_attemptedGeneration != m_generation;
            if (m_workerScheduled || (!needsStop && !needsStart)) return false;
            m_workerScheduled = true;
            return true;
        }

        Operation NextOperation()
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            if (!m_closing && m_owned && (!m_desired || m_stopRequired || m_cleanupPending)
                && m_stopAttemptedRevision != m_requestRevision)
            {
                m_stopAttemptedRevision = m_requestRevision;
                return Operation::Stop;
            }
            if (!m_closing && m_desired && !m_owned && m_attemptedGeneration != m_generation)
            {
                m_attemptedGeneration = m_generation;
                return Operation::Start;
            }
            m_workerScheduled = false;
            return Operation::None;
        }

        bool RestartIfActive()
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            if (m_closing || !m_desired || !m_active || m_workerScheduled) return false;
            m_active = false;
            ++m_generation;
            ++m_requestRevision;
            m_stopRequired = m_owned;
            m_workerScheduled = true;
            return true;
        }

        void CompleteStart(const bool started, const bool ownedResources = false)
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            m_active = started;
            m_owned = started || ownedResources;
            m_cleanupPending = !started && m_owned;
            if (m_cleanupPending)
            {
                m_stopRequired = true;
                // The backend already attempted compensating STOP during Start.
                // Preserve its failure until a later intent/explicit cleanup.
                m_stopAttemptedRevision = m_requestRevision;
            }
            else if (!m_owned) m_stopRequired = false;
        }

        void CompleteStop(const bool stopped = true)
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            m_active = false;
            m_owned = !stopped;
            m_cleanupPending = !stopped;
            m_stopRequired = !stopped;
            // A failure consumes intents already coalesced into this attempt.
            // Only a later request/retry may run it again; never spin in this pump.
            if (!stopped) m_stopAttemptedRevision = m_requestRevision;
        }

        // The retained owner becomes the sole Stop authority after Close.
        // An ordinary pump may finish its current operation but cannot retry it.
        void Close()
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            if (!m_closing)
            {
                m_closing = true;
                m_desired = false;
                ++m_generation;
                ++m_requestRevision;
                m_stopRequired = m_owned || m_workerScheduled;
            }
        }

        // Only after the prior cleanup is complete; this changes value state only.
        // Caller must admit a fresh lease before requesting Start. No backend
        // resources may cross this reuse boundary.
        bool Reopen()
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            if (m_owned || m_cleanupPending || m_active) return false;
            if (m_closing) { m_closing = false; ++m_generation; }
            return true;
        }

        bool CleanupPending() const
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            return m_cleanupPending;
        }

        // Background only. Never acquire this gate from GUI request/visibility handlers.
        std::unique_lock<std::mutex> LockBackgroundOperation()
        {
            return std::unique_lock<std::mutex>(m_operationMutex);
        }

        template<typename Callback>
        bool SnapshotIfCurrent(const std::uint64_t generation, Callback callback)
        {
            const auto operationGuard = LockBackgroundOperation();
            {
                std::lock_guard<std::mutex> guard(m_mutex);
                if (generation != m_generation || !m_active || !m_desired || m_closing || m_cleanupPending || m_workerScheduled)
                {
                    return false;
                }
            }
            // Start/Stop cannot replace the session between this check and consumption.
            // Request still takes only m_mutex and never waits for this callback.
            callback();
            return true;
        }

        bool IsSettledActive() const
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            return m_active && m_desired && !m_closing && !m_cleanupPending && !m_workerScheduled;
        }

        std::uint64_t Generation() const
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            return m_generation;
        }

    private:
        mutable std::mutex m_mutex;
        std::mutex m_operationMutex; // Lock order: operation -> state; Request only locks state.
        bool m_desired = false;
        bool m_active = false;
        bool m_owned = false;
        bool m_cleanupPending = false;
        bool m_closing = false;
        bool m_stopRequired = false;
        bool m_workerScheduled = false;
        std::uint64_t m_generation = 0;
        std::uint64_t m_attemptedGeneration = 0;
        std::uint64_t m_requestRevision = 0;
        std::uint64_t m_stopAttemptedRevision = 0;
    };
}
