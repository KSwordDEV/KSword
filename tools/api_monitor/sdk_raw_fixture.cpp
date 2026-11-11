// Owned VM target for verifying SDK declarations against raw ABI snapshots.
// It has no windows and does not read keyboard/mouse input.
#include <Windows.h>
#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 1;
    const std::wstring root = argv[1];
    const auto module = ::LoadLibraryW(L"user32.dll");
    if (!module) return 2;
    using Metrics = int (WINAPI*)(int);
    const auto metrics = reinterpret_cast<Metrics>(::GetProcAddress(module, "GetSystemMetrics"));
    if (!metrics) return 3;
    const auto ready = root + L"\\ready";
    const auto stop = root + L"\\stop";
    const HANDLE marker = ::CreateFileW(ready.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (marker == INVALID_HANDLE_VALUE) return 4;
    ::CloseHandle(marker);
    const auto deadline = ::GetTickCount64() + 120000;
    while (::GetTickCount64() < deadline && ::GetFileAttributesW(stop.c_str()) == INVALID_FILE_ATTRIBUTES) {
        (void)metrics(42);
        ::Sleep(25);
    }
    ::FreeLibrary(module);
    return 0;
}
