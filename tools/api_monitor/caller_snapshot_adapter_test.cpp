#include "MonitorDock/WinAPICallerSnapshotAdapter.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QThread>
#include <iostream>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << " " #x "\n"; return 1; } } while (false)
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    FILETIME created{}, exited{}, kernel{}, user{};
    CHECK(::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user));
    const auto identity = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    auto first = std::make_shared<WinAPIEventRecord>();
    first->generation = 1; first->sequence = 1;
    first->value.sourcePid = ::GetCurrentProcessId(); first->value.sourceCreationTime100ns = identity;
    const auto address = reinterpret_cast<std::uintptr_t>(::GetModuleHandleW(nullptr));
    first->value.detailText = QStringLiteral("target=0x1 caller=0x%1 strongTyped=0 params=raw abi=x64").arg(qulonglong(address), 0, 16);
    auto second = std::make_shared<WinAPIEventRecord>(*first); second->sequence = 2;
    int calls = 0; WinAPIEventRef selected; ks::winapi_monitor::CallerSnapshot received;
    {
        WinAPICallerSnapshotAdapter adapter;
        QEventLoop wait;
        adapter.finished = [&](const WinAPIEventRef& record, const ks::winapi_monitor::CallerSnapshot& value) {
            ++calls; selected = record; received = value; wait.quit();
        };
        CHECK(adapter.select({}) == WinAPICallerSnapshotAdapter::SelectResult::Unsupported);
        CHECK(adapter.select(first) == WinAPICallerSnapshotAdapter::SelectResult::Started);
        CHECK(adapter.select(second) == WinAPICallerSnapshotAdapter::SelectResult::Started);
        QTimer::singleShot(5000, &wait, &QEventLoop::quit); wait.exec();
        CHECK(calls == 1 && selected == second);
        CHECK(received.status == ks::winapi_monitor::CallerSnapshotStatus::Available);
        CHECK(received.request.sequence == 2 && received.observedTime100ns >= identity && received.type == MEM_IMAGE);
        // Immediately selecting another event while the previous resolver is
        // retiring waits asynchronously and still delivers the new result.
        CHECK(adapter.select(first) == WinAPICallerSnapshotAdapter::SelectResult::Started);
        QTimer::singleShot(5000, &wait, &QEventLoop::quit); wait.exec();
        CHECK(calls == 2 && selected == first && received.request.sequence == 1);
        auto bad = std::make_shared<WinAPIEventRecord>(*second); bad->value.sourceCreationTime100ns = 0;
        CHECK(adapter.select(bad) == WinAPICallerSnapshotAdapter::SelectResult::Unsupported);
    }
    QElapsedTimer timer; timer.start();
    while (ks::ui::AsyncCleanupRegistry::global().pending() && timer.elapsed() < 5000)
        QThread::msleep(1);
    CHECK(ks::ui::AsyncCleanupRegistry::global().pending() == 0);
    std::cout << "PASS: selected identity, stale selection rejection, image snapshot and async cleanup\n";
}
