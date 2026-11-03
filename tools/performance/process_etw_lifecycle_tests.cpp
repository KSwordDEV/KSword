#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessEtwCaptureLifecycle.h"
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <thread>
#include <vector>

using Lifecycle = ks::process::ProcessEtwCaptureLifecycle;
using Op = Lifecycle::Operation;

int main()
{
    {
        Lifecycle c;
        assert(c.Request(true));
        assert(c.NextOperation() == Op::Start);
        c.CompleteStart(true);
        assert(c.NextOperation() == Op::None);
        const auto old = c.Generation();
        assert(c.RestartIfActive());
        assert(c.Generation() != old && !c.IsSettledActive());
        assert(!c.RestartIfActive());
        assert(c.NextOperation() == Op::Stop);
        c.CompleteStop();
        assert(c.NextOperation() == Op::Start);
        c.CompleteStart(true);
        assert(c.NextOperation() == Op::None && c.IsSettledActive());
        c.Close();
        assert(!c.RestartIfActive());
    }
    for (int bits = 0; bits < 32; ++bits)
    {
        ks::process::ProcessEtwCaptureDemand d{
            (bits & 1) != 0, (bits & 2) != 0, (bits & 4) != 0,
            (bits & 8) != 0, (bits & 16) != 0};
        assert(d.RefreshAllowed() == (d.monitoring &&
            (d.processListVisible || d.background || d.visibleDetail)));
        assert(d.RecordingAllowed() == (d.monitoring &&
            (d.processListVisible || d.background)));
        assert(d.CpuCaptureAllowed() == (d.RefreshAllowed() &&
            (d.cpuColumnVisible || d.visibleDetail)));
        if (!d.monitoring)
            assert(!d.RefreshAllowed() && !d.RecordingAllowed() && !d.CpuCaptureAllowed());
        if (d.visibleDetail && !d.processListVisible && !d.background)
            assert(!d.RecordingAllowed());
    }
    {
        Lifecycle c;
        assert(!c.Request(false));
        assert(c.Request(true));
        assert(!c.Request(true));
        assert(c.NextOperation() == Op::Start);
        const auto generation = c.Generation();
        assert(!c.Request(false)); // cancel while Start is in flight
        assert(c.Generation() != generation);
        c.CompleteStart(true);
        assert(!c.IsSettledActive()); // worker still reconciling the request
        assert(c.NextOperation() == Op::Stop);
        c.CompleteStop();
        assert(c.NextOperation() == Op::None);
        assert(!c.Request(false));
    }
    {
        Lifecycle c;
        assert(c.Request(true));
        assert(c.NextOperation() == Op::Start);
        assert(!c.Request(false));
        assert(!c.Request(true)); // resume before initial Start completes
        c.CompleteStart(true);
        assert(c.NextOperation() == Op::Stop); // a transient pause must end the old interval
        c.CompleteStop();
        assert(c.NextOperation() == Op::Start); // restart only after the same instance stopped
        c.CompleteStart(true);
        assert(c.NextOperation() == Op::None);
        assert(c.IsSettledActive());
        assert(c.Request(false));
        assert(c.NextOperation() == Op::Stop);
        assert(!c.IsSettledActive());
        assert(!c.Request(true)); // resume while Stop/join is in flight
        c.CompleteStop();
        assert(c.NextOperation() == Op::Start);
        c.CompleteStart(true);
        assert(c.NextOperation() == Op::None);
    }
    {
        Lifecycle c;
        assert(c.Request(true));
        assert(c.NextOperation() == Op::Start);
        c.CompleteStart(false);
        assert(c.NextOperation() == Op::None);
        assert(!c.Request(true)); // no per-frame failed Start retry
        assert(!c.Request(false));
        assert(c.Request(true));
        assert(c.NextOperation() == Op::Start);
        c.CompleteStart(true);
        assert(c.NextOperation() == Op::None);
    }
    {
        Lifecycle c;
        std::mutex mutex;
        std::condition_variable ready;
        bool entered = false, release = false;
        std::atomic_int starts{0}, stops{0};
        assert(c.Request(true));
        std::thread worker([&]() {
            for (;;) {
                const auto op = c.NextOperation();
                if (op == Op::None) break;
                if (op == Op::Start) {
                    ++starts;
                    std::unique_lock<std::mutex> guard(mutex);
                    entered = true;
                    ready.notify_all();
                    ready.wait(guard, [&]() { return release; });
                    c.CompleteStart(true);
                } else {
                    ++stops;
                    c.CompleteStop();
                }
            }
        });
        {
            std::unique_lock<std::mutex> guard(mutex);
            ready.wait(guard, [&]() { return entered; });
        }
        // Ten thousand UI demand transitions do not wait for the fake ETW API.
        for (int i = 0; i < 10000; ++i) {
            assert(!c.Request(false));
            assert(!c.Request(true));
        }
        assert(!c.Request(false));
        {
            std::lock_guard<std::mutex> guard(mutex);
            release = true;
        }
        ready.notify_all();
        worker.join();
        assert(starts == 1 && stops == 1);
    }
    {
        Lifecycle c;
        assert(c.Request(true));
        assert(c.NextOperation() == Op::Start);
        c.CompleteStart(true);
        assert(c.NextOperation() == Op::None);
        const auto oldGeneration = c.Generation();
        std::mutex mutex;
        std::condition_variable ready;
        bool snapshotEntered = false, releaseSnapshot = false, stopAttempted = false;
        std::atomic_int interval{13}, consumed{-1};
        std::atomic_bool newSessionStarted{false};
        std::thread oldSnapshot([&]() {
            const bool applied = c.SnapshotIfCurrent(oldGeneration, [&]() {
                std::unique_lock<std::mutex> guard(mutex);
                snapshotEntered = true;
                ready.notify_all();
                ready.wait(guard, [&]() { return releaseSnapshot; });
                consumed = interval.exchange(0);
            });
            assert(applied);
        });
        {
            std::unique_lock<std::mutex> guard(mutex);
            ready.wait(guard, [&]() { return snapshotEntered; });
        }
        assert(c.Request(false));
        assert(!c.Request(true));
        std::thread lifecycleWorker([&]() {
            for (;;) {
                const auto op = c.NextOperation();
                if (op == Op::None) return;
                {
                    std::lock_guard<std::mutex> guard(mutex);
                    stopAttempted = true;
                }
                ready.notify_all();
                const auto operationGuard = c.LockBackgroundOperation();
                if (op == Op::Stop) {
                    interval = 0;
                    c.CompleteStop();
                } else {
                    interval = 99;
                    newSessionStarted = true;
                    c.CompleteStart(true);
                }
            }
        });
        {
            std::unique_lock<std::mutex> guard(mutex);
            ready.wait(guard, [&]() { return stopAttempted; });
        }
        // GUI requests cannot wait on the operation mutex held by the blocked snapshot.
        for (int i = 0; i < 10000; ++i) {
            assert(!c.Request(false));
            assert(!c.Request(true));
        }
        assert(!newSessionStarted);
        {
            std::lock_guard<std::mutex> guard(mutex);
            releaseSnapshot = true;
        }
        ready.notify_all();
        oldSnapshot.join();
        lifecycleWorker.join();
        assert(consumed == 13 && interval == 99 && newSessionStarted);
        bool staleConsumed = false;
        assert(!c.SnapshotIfCurrent(oldGeneration, [&]() {
            staleConsumed = true;
            interval = 0;
        }));
        assert(!staleConsumed && interval == 99);
        assert(c.SnapshotIfCurrent(c.Generation(), [&]() { consumed = interval.exchange(0); }));
        assert(consumed == 99);
    }
    std::cout << "PASS: 32 demand combinations; lifecycle races; old-generation snapshot cannot consume new interval; GUI requests bypass backend gate\n";
}
