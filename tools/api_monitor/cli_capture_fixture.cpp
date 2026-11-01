// Owned native target for CLI/VM integration: real file/registry calls continue
// before, during and after monitoring. A marker launches an opposite-bitness child.
#include <Windows.h>
#include <string>
#include <vector>

BOOL WINAPI ignoreControl(DWORD) { return TRUE; }
int cancelController(int argc, wchar_t** argv) {
    if (argc != 5) return 10;
    SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};
    HANDLE output=::CreateFileW(argv[4],GENERIC_WRITE,FILE_SHARE_READ,&security,CREATE_ALWAYS,0,nullptr);
    if(output==INVALID_HANDLE_VALUE)return 11;
    std::wstring command=L"\""+std::wstring(argv[2])+L"\" monitor api capture --pid "+argv[3]
        +L" --duration-ms 30000 --categories file --limit 10000 --confirm --json";
    STARTUPINFOW startup{};startup.cb=sizeof(startup);startup.dwFlags=STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
    startup.wShowWindow=SW_HIDE;startup.hStdOutput=output;startup.hStdError=output;
    startup.hStdInput=::GetStdHandle(STD_INPUT_HANDLE);PROCESS_INFORMATION controller{};
    const bool launched=::CreateProcessW(argv[2],command.data(),nullptr,nullptr,TRUE,CREATE_NEW_CONSOLE,nullptr,nullptr,&startup,&controller)!=FALSE;
    ::CloseHandle(output);if(!launched)return 12;
    ::CloseHandle(controller.hThread);::Sleep(3000);
    ::FreeConsole();
    const bool attached=::AttachConsole(controller.dwProcessId)!=FALSE;
    if(attached)::SetConsoleCtrlHandler(ignoreControl,TRUE);
    const bool signaled=attached&&::GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT,0)!=FALSE;
    const auto wait=::WaitForSingleObject(controller.hProcess,45000);DWORD code=0;
    const bool exited=wait==WAIT_OBJECT_0&&::GetExitCodeProcess(controller.hProcess,&code)!=FALSE;
    ::CloseHandle(controller.hProcess);if(attached)::FreeConsole();
    return signaled&&exited&&code==6?0:13;
}

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) return 1;
    if (std::wstring(argv[1]) == L"--cancel-controller") return cancelController(argc,argv);
    const std::wstring root = argv[1];
    ::CreateDirectoryW(root.c_str(), nullptr);
    const auto stop = root + L"\\stop", ready = root + L"\\ready", spawn = root + L"\\spawn";
    HANDLE readyFile = ::CreateFileW(ready.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (readyFile == INVALID_HANDLE_VALUE) return 2;
    ::CloseHandle(readyFile);
    HMODULE version = ::LoadLibraryW(L"version.dll");
    using VersionSize = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
    const auto versionSize = version ? reinterpret_cast<VersionSize>(::GetProcAddress(version,"GetFileVersionInfoSizeW")) : nullptr;
    PROCESS_INFORMATION child{}; bool spawned = false;
    const auto deadline = ::GetTickCount64() + 180000;
    while (::GetTickCount64() < deadline && ::GetFileAttributesW(stop.c_str()) == INVALID_FILE_ATTRIBUTES) {
        HANDLE file = ::CreateFileW((root + L"\\activity.bin").c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return 3;
        DWORD written = 0;
        const bool ok = ::WriteFile(file, "owned-cli-api-fixture", 21, &written, nullptr) && written == 21;
        ::CloseHandle(file); if (!ok) return 4;
        DWORD ignored = 0; if (versionSize) versionSize((root + L"\\activity.bin").c_str(), &ignored);
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, L"Software", 0, KEY_READ, &key) == ERROR_SUCCESS) ::RegCloseKey(key);
        if (argc >= 3 && !spawned && ::GetFileAttributesW(spawn.c_str()) != INVALID_FILE_ATTRIBUTES) {
            const auto childRoot = root + L"\\child"; ::CreateDirectoryW(childRoot.c_str(), nullptr);
            std::wstring line = L"\"" + std::wstring(argv[2]) + L"\" \"" + childRoot + L"\"";
            STARTUPINFOW startup{}; startup.cb = sizeof(startup);
            if (!::CreateProcessW(argv[2], line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &child)) return 5;
            ::CloseHandle(child.hThread); spawned = true;
        }
        ::Sleep(30);
    }
    if (child.hProcess) {
        HANDLE marker = ::CreateFileW((root + L"\\child\\stop").c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, 0, nullptr);
        if (marker != INVALID_HANDLE_VALUE) ::CloseHandle(marker);
        const auto status = ::WaitForSingleObject(child.hProcess, 10000); ::CloseHandle(child.hProcess);
        if (status != WAIT_OBJECT_0) return 6;
    }
    if (version) ::FreeLibrary(version);
    return 0;
}
