// Real R3 close regression. Only a disposable child's explicitly reported file handle is eligible.
#include "../Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <iostream>

// Unused R0 paths stay inert in this R3-only harness.
namespace ksword::ark {
    ProcessEnumResult DriverClient::enumerateProcesses(unsigned long) const { return {}; }
    HandleEnumResult DriverClient::enumerateProcessHandles(std::uint32_t, unsigned long) const { return {}; }
    HandleObjectQueryResult DriverClient::queryHandleObject(std::uint32_t, std::uint64_t, unsigned long, unsigned long) const { return {}; }
}
namespace ks::process {
    std::string QueryProcessPathByPid(std::uint32_t) { return {}; }
}
namespace ks::str {
    std::wstring Utf8ToUtf16(const std::string& text) {
        if (text.empty()) { return {}; }
        const int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
        if (length <= 0) { return {}; }
        std::wstring result(static_cast<std::size_t>(length), L'\0');
        MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length);
        return result;
    }
    std::string Utf16ToUtf8(const std::wstring& text) {
        if (text.empty()) { return {}; }
        const int length = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
        if (length <= 0) { return {}; }
        std::string result(static_cast<std::size_t>(length), '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), result.data(), length, nullptr, nullptr);
        return result;
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc == 4 && std::wstring(argv[1]) == L"--hold") {
        const std::wstring base = argv[3];
        HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, (base + L"-ready").c_str());
        HANDLE stop = OpenEventW(SYNCHRONIZE, FALSE, (base + L"-stop").c_str());
        HANDLE mapping = OpenFileMappingW(FILE_MAP_WRITE, FALSE, (base + L"-mapping").c_str());
        auto* value = mapping ? static_cast<std::uint64_t*>(MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(std::uint64_t))) : nullptr;
        HANDLE file = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (!ready || !stop || !value || file == INVALID_HANDLE_VALUE) { return 20; }
        *value = reinterpret_cast<ULONG_PTR>(file);
        SetEvent(ready);
        WaitForSingleObject(stop, 15000);
        // The parent may already have closed this handle; process exit owns any remaining file handle.
        UnmapViewOfFile(value);
        CloseHandle(mapping);
        CloseHandle(stop);
        CloseHandle(ready);
        return 0;
    }
    wchar_t tempDirectory[MAX_PATH]{}, tempFile[MAX_PATH]{}, executable[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, tempDirectory) || !GetTempFileNameW(tempDirectory, L"ksh", 0, tempFile) ||
        !GetModuleFileNameW(nullptr, executable, MAX_PATH)) { return 21; }
    const std::wstring base = L"Local\\KswordHandleCloseTest-" + std::to_wstring(GetCurrentProcessId());
    HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, (base + L"-ready").c_str());
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, (base + L"-stop").c_str());
    HANDLE mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(std::uint64_t), (base + L"-mapping").c_str());
    auto* value = mapping ? static_cast<std::uint64_t*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(std::uint64_t))) : nullptr;
    if (!ready || !stop || !value) { return 22; }
    std::wstring command = L"\"" + std::wstring(executable) + L"\" --hold \"" + tempFile + L"\" \"" + base + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    if (!CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
        nullptr, nullptr, &startup, &child)) { return 23; }
    const auto cleanup = [&]() {
        SetEvent(stop);
        WaitForSingleObject(child.hProcess, 3000);
        CloseHandle(child.hThread);
        CloseHandle(child.hProcess);
        UnmapViewOfFile(value);
        CloseHandle(mapping);
        CloseHandle(ready);
        CloseHandle(stop);
        DeleteFileW(tempFile);
    };
    if (WaitForSingleObject(ready, 3000) != WAIT_OBJECT_0) { cleanup(); return 24; }
    ks::file::HandleSnapshotOptions options{};
    options.enumMode = ks::file::HandleEnumMode::UserSnapshot;
    options.resolveObjectName = false;
    options.hasPidFilter = true;
    options.pidFilter = child.dwProcessId;
    const auto snapshot = ks::file::BuildHandleSnapshot(options);
    const ks::file::HandleSnapshotRow* target = nullptr;
    for (const auto& row : snapshot.rows) {
        if (row.processId == child.dwProcessId && row.handleValue == *value) { target = &row; break; }
    }
    if (!target || !target->objectAddress || !target->processCreationTime) { cleanup(); return 25; }
    std::string detail;
    const bool stalePidRejected = !ks::file::CloseRemoteHandleByObjectIdentity(target->processId,
        target->handleValue, target->processCreationTime + 1U, target->objectAddress, detail);
    const bool staleObjectRejected = !ks::file::CloseRemoteHandleByObjectIdentity(target->processId,
        target->handleValue, target->processCreationTime, target->objectAddress + 8U, detail);
    const auto receipt = ks::file::CloseRemoteHandleByObjectIdentityDetailed(target->processId,
        target->handleValue, target->processCreationTime, target->objectAddress);
    const bool closed = receipt.success && receipt.suspendAttempted && receipt.closeAttempted &&
        receipt.closeSucceeded && receipt.resumeAttempted && receipt.resumeStatus >= 0;
    HANDLE probe = nullptr;
    const bool disappeared = !DuplicateHandle(child.hProcess, reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target->handleValue)),
        GetCurrentProcess(), &probe, 0, FALSE, DUPLICATE_SAME_ACCESS);
    if (probe) { CloseHandle(probe); }
    SetEvent(stop);
    const bool resumed = WaitForSingleObject(child.hProcess, 3000) == WAIT_OBJECT_0;
    std::cout << "LIVE_R3_CLOSE=" << closed << " STALE_PID_REJECTED=" << stalePidRejected
        << " STALE_OBJECT_REJECTED=" << staleObjectRejected << " HANDLE_GONE=" << disappeared
        << " CHILD_RESUMED=" << resumed << '\n';
    cleanup();
    return stalePidRejected && staleObjectRejected && closed && disappeared && resumed ? 0 : 26;
}
