#include "MonitorDock/WinAPISessionBackend.h"
#include <QCoreApplication>
#include <QDir>
#include <QUuid>
#include <iostream>
#include <functional>
void WinAPISessionBackend::queueCoverageSnapshot(std::uint32_t, std::uint64_t, std::uint64_t,
    std::vector<ks::winapi_monitor::ApiMonitorEventPacket>, bool, std::uint64_t) {}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    if (argc == 3 && QByteArray(argv[1]) == "--target") {
        const auto handle = reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(QByteArray(argv[2]).toULongLong()));
        wchar_t path[32768]{}; GetModuleFileNameW(nullptr, path, 32768);
        while (WaitForSingleObject(handle, 10) == WAIT_TIMEOUT) (void)GetFileAttributesW(path);
        CloseHandle(handle); return 0;
    }
    wchar_t exe[32768]{}; GetModuleFileNameW(nullptr, exe, 32768);
    const bool badAgent = argc == 2 && QByteArray(argv[1]) == "--bad-agent";
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE targetStop = CreateEventW(&sa, TRUE, FALSE, nullptr);
    std::wstring cmd = L"\"" + std::wstring(exe) + L"\" --target " + std::to_wstring(reinterpret_cast<std::uintptr_t>(targetStop));
    STARTUPINFOW si{}; si.cb = sizeof(si); PROCESS_INFORMATION pi{};
    if (!CreateProcessW(exe, cmd.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return 2;
    CloseHandle(pi.hThread);
    WinAPISessionConfig config; config.pid = pi.dwProcessId; config.generation = 1;
    config.sessionId = QUuid::createUuid().toString(QUuid::WithoutBraces);
    config.requestedAgentPath = badAgent ? QStringLiteral("Z:/missing/invalid-agent.dll") : qEnvironmentVariable("KSWORD_PAUSE_AGENT");
    const QString root = qEnvironmentVariable("KSWORD_PAUSE_TEST_ROOT", QDir::tempPath() + QStringLiteral("/ksword-winapi-backend-test"));
    config.archiveDirectory = QDir(root).filePath(config.sessionId);
    config.options = QStringLiteral("enable_file=1\nenable_registry=0\nenable_network=0\nenable_process=0\nenable_loader=0\nenable_clipboard=0\nauto_inject_child=0\nenable_raw_fallback=0\n");
    auto backend = std::make_shared<WinAPISessionBackend>(std::move(config));
    const bool started = backend->start();
    std::cout << "started=" << started << " error=" << backend->startupError.toStdString() << " published=" << backend->configPublished << std::endl;
    auto waitFor = [&](const std::function<bool()>& condition) {
        const auto deadline = GetTickCount64() + 30000;
        while (GetTickCount64() < deadline) { if (condition()) return true; Sleep(10); }
        return false;
    };
    auto count = [&](const QString& name) {
        std::lock_guard<std::mutex> lock(backend->pendingMutex); int result = 0;
        for (const auto& record : backend->pendingRows) if (record->value.agentStatus == name || record->value.apiText.endsWith(name)) ++result;
        return result;
    };
    bool ok = badAgent ? (!started && !backend->startupError.isEmpty() && !backend->configPublished)
        : started && waitFor([&] { return count(QStringLiteral("PauseControlReady")) && count(QStringLiteral("HooksInstalled")) && count(QStringLiteral("GetFileAttributesW")); });
    if (ok && !badAgent) {
        backend->setEventsPaused(true); backend->setEventsPaused(false);
        ok = !backend->eventsPaused.load();
        backend->setEventsPaused(true);
        ok = ok && waitFor([&] { return count(QStringLiteral("HooksPaused")) > 0; });
        const int before = count(QStringLiteral("GetFileAttributesW")); Sleep(400);
        ok = ok && before == count(QStringLiteral("GetFileAttributesW"));
        backend->setEventsPaused(false);
        ok = ok && waitFor([&] { return count(QStringLiteral("HooksResumed")) > 0 && !backend->eventsPaused.load(); });
        ok = ok && waitFor([&] { return count(QStringLiteral("GetFileAttributesW")) > before; });
        backend->setEventsPaused(true);
        ok = ok && waitFor([&] { return count(QStringLiteral("HooksPaused")) > 1; });
    }
    const bool cleaned = backend->cleanup();
    std::cout << "cleanup=" << cleaned << " connected=" << backend->connected.load() << " drainIncomplete=" << backend->drainIncomplete.load() << std::endl;
    SetEvent(targetStop); WaitForSingleObject(pi.hProcess, 5000); CloseHandle(pi.hProcess); CloseHandle(targetStop);
    std::cout << "pause-and-resume=" << ok << std::endl;
    return cleaned && ok && (badAgent || started) ? 0 : 1;
}
