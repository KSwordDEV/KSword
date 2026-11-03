#include "MonitorDock/WinAPIStackSnapshotAdapter.h"
#include "UI/AsyncCleanupRegistry.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QTimer>
#include <QThread>
#include <iostream>
#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (false)
extern "C" __declspec(dllexport) __declspec(noinline) void StackAdapterFixture() {}
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    FILETIME created{}, exited{}, kernel{}, user{};
    CHECK(::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user));
    const auto creation = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    const auto address = reinterpret_cast<std::uintptr_t>(&StackAdapterFixture);
    auto first = std::make_shared<WinAPIEventRecord>();
    first->generation = 1; first->sequence = 1; first->value.sourcePid = ::GetCurrentProcessId();
    first->value.sourceCreationTime100ns = creation;
    first->value.capturedCallStack = QStringLiteral("#0 0x%1\n#1 0x%1").arg(static_cast<qulonglong>(address), 0, 16);
    auto second = std::make_shared<WinAPIEventRecord>(*first); second->sequence = 2;
    int calls = 0; WinAPIEventRef selected; std::vector<ks::winapi_monitor::StackFrameSnapshot> result;
    {
        WinAPIStackSnapshotAdapter adapter; QEventLoop wait;
        adapter.finished = [&](const WinAPIEventRef& record, const auto& frames) {
            ++calls; selected = record; result = frames; wait.quit();
        };
        CHECK(adapter.select(first)); CHECK(adapter.select(second));
        QTimer::singleShot(5000, &wait, &QEventLoop::quit); wait.exec();
        CHECK(calls == 1 && selected == second && result.size() == 2);
        CHECK(result[0].imageOffsetAvailable && result[0].observedTime100ns >= creation);
        CHECK(result[1].address == address && result[1].imageOffsetAvailable);
        CHECK(result[0].nearestExportName == "StackAdapterFixture" && result[0].nearestExportDisplacement == 0
            && result[0].nearestExportObservedTime100ns >= creation);
        auto bad = std::make_shared<WinAPIEventRecord>(*first);
        bad->value.capturedCallStack = QStringLiteral("#0 0x1junk");
        CHECK(!adapter.select(bad));
        CHECK(adapter.select(first));
    }
    QElapsedTimer timeout; timeout.start();
    while (ks::ui::AsyncCleanupRegistry::global().pending() && timeout.elapsed() < 5000) {
        QCoreApplication::processEvents(); QThread::msleep(1);
    }
    CHECK(ks::ui::AsyncCleanupRegistry::global().pending() == 0);
    std::cout << "PASS: async stack mapping, selection replacement, malformed input and cleanup\n";
}
