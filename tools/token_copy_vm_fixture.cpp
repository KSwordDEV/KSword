#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <sddl.h>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <share.h>

static unsigned long long luid_value(LUID value) {
    return (static_cast<unsigned long long>(static_cast<unsigned long>(value.HighPart)) << 32) | value.LowPart;
}

static int query(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) { std::printf("{\"error\":\"OpenProcess\",\"win32\":%lu}\n", GetLastError()); return 1; }
    HANDLE token = nullptr;
    TOKEN_STATISTICS stats{};
    DWORD length = 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    BYTE buffer[SECURITY_MAX_SID_SIZE + sizeof(TOKEN_USER)]{};
    LPSTR sid = nullptr;
    bool ok = GetProcessTimes(process, &created, &exited, &kernel, &user) &&
        OpenProcessToken(process, TOKEN_QUERY, &token) &&
        GetTokenInformation(token, TokenStatistics, &stats, sizeof(stats), &length) && length == sizeof(stats) &&
        GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &length) &&
        ConvertSidToStringSidA(reinterpret_cast<TOKEN_USER*>(buffer)->User.Sid, &sid);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (ok) {
        ULARGE_INTEGER time{}; time.LowPart = created.dwLowDateTime; time.HighPart = created.dwHighDateTime;
        std::printf("{\"pid\":%lu,\"creationTime\":\"%llu\",\"tokenId\":\"0x%llX\",\"authenticationId\":\"0x%llX\",\"userSid\":\"%s\"}\n",
            pid, time.QuadPart, luid_value(stats.TokenId), luid_value(stats.AuthenticationId), sid);
    } else std::printf("{\"error\":\"query\",\"win32\":%lu}\n", error);
    if (sid) LocalFree(sid);
    if (token) CloseHandle(token);
    CloseHandle(process);
    return ok ? 0 : 1;
}

static DWORD WINAPI worker(void* context) {
    HANDLE stop = static_cast<HANDLE>(context);
    while (WaitForSingleObject(stop, 100) == WAIT_TIMEOUT) { SwitchToThread(); }
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && wcscmp(argv[1], L"query") == 0) return query(wcstoul(argv[2], nullptr, 10));
    if (argc != 4 || wcscmp(argv[1], L"watch") != 0) return 2;
    unsigned long count = wcstoul(argv[3], nullptr, 10);
    if (count < 1 || count > 8) return 2;
    HANDLE stop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stop) return 1;
    HANDLE threads[8]{};
    DWORD started = 0;
    for (; started < count; ++started) {
        threads[started] = CreateThread(nullptr, 0, worker, stop, 0, nullptr);
        if (!threads[started]) break;
    }
    int result = started == count ? 0 : 1;
    if (!result) {
        wchar_t path[MAX_PATH]{};
        FILE* heartbeat = nullptr;
        if (swprintf_s(path, L"%s.%lu.log", argv[2], GetCurrentProcessId()) < 0 ||
            (heartbeat = _wfsopen(path, L"w", _SH_DENYNO)) == nullptr) result = 1;
        wchar_t selfPath[MAX_PATH]{};
        FILE* selfOutput = nullptr;
        if (swprintf_s(selfPath, L"%s.%lu.self.json", argv[2], GetCurrentProcessId()) < 0 ||
            _wfreopen_s(&selfOutput, selfPath, L"w", stdout) != 0) result = 1;
        if (query(GetCurrentProcessId())) result = 1;
        std::fflush(stdout);
        for (unsigned long beat = 0; !result && beat < 600; ++beat) {
            if (GetFileAttributesW(argv[2]) != INVALID_FILE_ATTRIBUTES) break;
            std::printf("heartbeat %lu\n", beat); std::fflush(stdout); Sleep(500);
            std::fprintf(heartbeat, "heartbeat %lu\n", beat); std::fflush(heartbeat);
        }
        if (heartbeat) { std::fprintf(heartbeat, "exit %d\n", result); std::fclose(heartbeat); }
    }
    SetEvent(stop);
    if (started) WaitForMultipleObjects(started, threads, TRUE, INFINITE);
    for (DWORD i = 0; i < started; ++i) CloseHandle(threads[i]);
    CloseHandle(stop);
    std::printf("exit %d\n", result); std::fflush(stdout);
    return result;
}
