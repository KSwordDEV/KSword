// Owned guest-only target: fixed output parameters, asynchronous completion,
// and native clipboard denials on a newly created private window station.
#define NOMINMAX
#include <Windows.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

namespace {
volatile LONG completed = 0;
DWORD completionError = 0, completionBytes = 0;
void CALLBACK completion(DWORD error, DWORD bytes, LPOVERLAPPED) {
    completionError = error; completionBytes = bytes; ::InterlockedExchange(&completed, 1);
}
bool marker(const std::filesystem::path& path) {
    return ::GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES;
}
bool touch(const std::filesystem::path& path) { std::ofstream out(path); return !!out; }
std::uintptr_t bits(HANDLE h) { return reinterpret_cast<std::uintptr_t>(h); }
}
int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 1;
    const std::filesystem::path root(argv[1]);
    if (!std::filesystem::is_directory(root)) return 2;
    const auto payload = root / L"semantic-read.dat";
    { std::ofstream f(payload, std::ios::binary); f << "semantic-fixture"; if (!f) return 3; }
    HMODULE user32 = ::LoadLibraryW(L"user32.dll");
    if (!user32) return 4;
    const std::wstring stationName = L"KSwordFixture-" + std::to_wstring(::GetCurrentProcessId());
    HWINSTA station = ::CreateWindowStationW(stationName.c_str(), 0, WINSTA_ALL_ACCESS, nullptr);
    const bool isolated = station && ::SetProcessWindowStation(station) != FALSE;
    HMODULE win32u = isolated ? ::LoadLibraryW(L"win32u.dll") : nullptr;
    using Read = HANDLE(WINAPI*)(UINT, void*);
    using Write = HANDLE(WINAPI*)(UINT, HANDLE, void*);
    using Empty = BOOL(WINAPI*)();
    auto read = win32u ? reinterpret_cast<Read>(::GetProcAddress(win32u, "NtUserGetClipboardData")) : nullptr;
    auto write = win32u ? reinterpret_cast<Write>(::GetProcAddress(win32u, "NtUserSetClipboardData")) : nullptr;
    auto empty = win32u ? reinterpret_cast<Empty>(::GetProcAddress(win32u, "NtUserEmptyClipboard")) : nullptr;
    std::array<unsigned char, 16> beforeRead{}, beforeWrite{}, beforeEmpty{};
    if (read && write && empty) {
        std::memcpy(beforeRead.data(), reinterpret_cast<const void*>(read), beforeRead.size());
        std::memcpy(beforeWrite.data(), reinterpret_cast<const void*>(write), beforeWrite.size());
        std::memcpy(beforeEmpty.data(), reinterpret_cast<const void*>(empty), beforeEmpty.size());
    }
    if (!touch(root / L"ready")) return 5;
    const auto deadline = ::GetTickCount64() + 120000;
    while (!marker(root / L"start")) {
        if (marker(root / L"stop") || ::GetTickCount64() >= deadline) return 6;
        ::Sleep(10);
    }
    void* memory = ::VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) return 7;
    DWORD oldProtect=0;
    const BOOL protection = ::VirtualProtect(memory, 4096, PAGE_READONLY, &oldProtect);
    DWORD failedProtect=0xdeadbeef;
    const BOOL protectionFailed = ::VirtualProtect(nullptr, 4096, PAGE_READONLY, &failedProtect);
    const DWORD protectionError=::GetLastError();
    HANDLE source=::CreateEventW(nullptr, FALSE, FALSE, nullptr), duplicate=nullptr;
    if (!source) return 8;
    const BOOL duplicated=::DuplicateHandle(::GetCurrentProcess(),source,::GetCurrentProcess(),&duplicate,0,FALSE,DUPLICATE_SAME_ACCESS);
    HANDLE failedDuplicate=reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x1234));
    const BOOL duplicateFailed=::DuplicateHandle(::GetCurrentProcess(),reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(0x41414141)),::GetCurrentProcess(),&failedDuplicate,0,FALSE,DUPLICATE_SAME_ACCESS);
    const DWORD duplicateError=::GetLastError();
    HANDLE file=::CreateFileW(payload.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
    if (file==INVALID_HANDLE_VALUE) return 9;
    std::array<char,16> buffer{}; OVERLAPPED overlap{};
    const BOOL submitted=::ReadFileEx(file,buffer.data(),static_cast<DWORD>(buffer.size()),&overlap,completion);
    const DWORD submitError=::GetLastError();
    const auto waitEnd=::GetTickCount64()+5000;
    while (!completed && ::GetTickCount64()<waitEnd) ::SleepEx(50,TRUE);
    // A private window station guarantees this does not touch the interactive
    // user's clipboard even if a policy hook is missing. Never open clipboard.
    const bool allPatched = read && write && empty
        && std::memcmp(beforeRead.data(),reinterpret_cast<const void*>(read),beforeRead.size())
        && std::memcmp(beforeWrite.data(),reinterpret_cast<const void*>(write),beforeWrite.size())
        && std::memcmp(beforeEmpty.data(),reinterpret_cast<const void*>(empty),beforeEmpty.size());
    bool blockedRead=false,blockedWrite=false,blockedEmpty=false;
    if (isolated && allPatched) {
        ::SetLastError(0); blockedRead=read(CF_UNICODETEXT,nullptr)==nullptr && ::GetLastError()==ERROR_ACCESS_DENIED;
        ::SetLastError(0); blockedWrite=write(CF_UNICODETEXT,nullptr,nullptr)==nullptr && ::GetLastError()==ERROR_ACCESS_DENIED;
        ::SetLastError(0); blockedEmpty=empty()==FALSE && ::GetLastError()==ERROR_ACCESS_DENIED;
    }
    std::ofstream out(root / L"observed.txt",std::ios::binary|std::ios::trunc);
    if (!out) return 10;
    out << "tid=" << ::GetCurrentThreadId() << "\nprotection=" << protection << "\noldProtect=" << oldProtect
        << "\nprotectionFailed=" << protectionFailed << "\nprotectionError=" << protectionError
        << "\nduplicated=" << duplicated << "\nduplicateHandle=" << bits(duplicate)
        << "\nduplicateFailed=" << duplicateFailed << "\nduplicateError=" << duplicateError
        << "\nsubmitted=" << submitted << "\nsubmitError=" << submitError
        << "\ncompleted=" << completed << "\ncompletionError=" << completionError << "\ncompletionBytes=" << completionBytes
        << "\nclipboardIsolated=" << isolated << "\nclipboardPatched=" << allPatched
        << "\nclipboardBlockedRead=" << blockedRead << "\nclipboardBlockedWrite=" << blockedWrite
        << "\nclipboardBlockedEmpty=" << blockedEmpty << '\n';
    out.close();
    if (duplicate) ::CloseHandle(duplicate);
    ::CloseHandle(source); ::CloseHandle(file); ::VirtualFree(memory,0,MEM_RELEASE);
    if (!out || !touch(root / L"done")) return 11;
    while (!marker(root / L"stop")) { if (::GetTickCount64() >= deadline) return 12; ::Sleep(10); }
    if (win32u) ::FreeLibrary(win32u);
    if (station) ::CloseWindowStation(station);
    ::FreeLibrary(user32);
    return 0;
}
