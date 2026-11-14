// 真实双位数控制台回归：只创建/操作本夹具的子进程，不注入用户应用。
#include "../../shared/usermode/ProcessConsole.h"
#include "../../shared/usermode/ProcessConsoleRemote.h"
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <iostream>
#include <io.h>
#include <string>

namespace
{
    // 两个位数通过命名共享内存交换固定宽度状态，不传递本地指针。
    struct ProbeState
    {
        DWORD console = 0;      // 目标是否已具有控制台窗口。
        DWORD win32Io = 0;      // Win32 标准句柄和 UTF-8 是否可用。
        DWORD cInput = 0;       // C stdin 是否绑定控制台。
        DWORD cppGood = 0;      // 六路 C++ 输出流是否已清错。
        DWORD observed = 0;     // 实际屏幕缓冲区中看见的输出位图。
    };

    // probe：在子进程读取真实句柄、运行库状态和屏幕缓冲区，输出到共享回执。
    void probe(ProbeState& state)
    {
        state = {};
        state.console = ::GetConsoleWindow() != nullptr;
        DWORD mode = 0; // GetConsoleMode 写回的模式字段。
        const HANDLE input = ::GetStdHandle(STD_INPUT_HANDLE); // Win32 标准输入。
        const HANDLE output = ::GetStdHandle(STD_OUTPUT_HANDLE); // Win32 标准输出。
        state.win32Io = ::GetConsoleMode(input, &mode) && ::GetConsoleMode(output, &mode)
            && ::GetConsoleOutputCP() == CP_UTF8 && ::GetConsoleCP() == CP_UTF8;
        state.cInput = ::GetConsoleMode(reinterpret_cast<HANDLE>(::_get_osfhandle(::_fileno(stdin))), &mode);
        state.cppGood = std::cout.good() && std::clog.good() && std::cerr.good()
            && std::wcout.good() && std::wclog.good() && std::wcerr.good();

        // 必须在目标业务线程真正打印，再从 console buffer 读回，不能只断言调用返回。
        DWORD written = 0; // 写入或读回的字符数。
        ::WriteConsoleA(output, "WIN32-OUT\n", 10, &written, nullptr);
        std::printf("C-OUT\n");
        std::fprintf(stderr, "C-ERR\n");
        std::cout << "CPP-OUT\n";
        std::clog << "CPP-LOG\n";
        std::cerr << "CPP-ERR\n";
        std::wcout << L"WCPP-OUT\n";
        std::wclog << L"WCPP-LOG\n";
        std::wcerr << L"WCPP-ERR\n";
        std::cout.flush();
        std::clog.flush();
        std::cerr.flush();
        std::wcout.flush();
        std::wclog.flush();
        std::wcerr.flush();
        std::fflush(nullptr);

        char screen[8192]{}; // 从真实控制台读取的字符缓存。
        ::ReadConsoleOutputCharacterA(output, screen, sizeof(screen) - 1, {0, 0}, &written);
        const char* tokens[] = {"WIN32-OUT", "C-OUT", "C-ERR", "CPP-OUT", "CPP-LOG", "CPP-ERR",
            "WCPP-OUT", "WCPP-LOG", "WCPP-ERR"}; // 每项对应一个独立输出来源。
        for (DWORD index = 0; index < ARRAYSIZE(tokens); ++index)
        {
            if (std::strstr(screen, tokens[index]))
            {
                state.observed |= 1U << index;
            }
        }
    }

    // child：打开父进程创建的通信对象；先把流设为 badbit，等待远程步骤清错。
    // 输入为唯一通信名称；输出为自身退出码，退出由父进程显式信号触发。
    int child(const std::wstring& name)
    {
        HANDLE mapping = ::OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
        auto* state = static_cast<ProbeState*>(::MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ProbeState)));
        HANDLE ready = ::OpenEventW(EVENT_MODIFY_STATE, FALSE, (name + L"-ready").c_str());
        HANDLE request = ::OpenEventW(SYNCHRONIZE, FALSE, (name + L"-request").c_str());
        HANDLE done = ::OpenEventW(EVENT_MODIFY_STATE, FALSE, (name + L"-done").c_str());
        HANDLE stop = ::OpenEventW(SYNCHRONIZE, FALSE, (name + L"-stop").c_str());
        if (!state || !ready || !request || !done || !stop)
        {
            return 2;
        }
        // 用错误态检验 clear 真正作用于目标的六个流对象。
        std::cout.setstate(std::ios::badbit);
        std::clog.setstate(std::ios::badbit);
        std::cerr.setstate(std::ios::badbit);
        std::wcout.setstate(std::ios::badbit);
        std::wclog.setstate(std::ios::badbit);
        std::wcerr.setstate(std::ios::badbit);
        ::SetEvent(ready);
        HANDLE waits[] = {stop, request}; // 停止优先，其次采样真实输出。
        while (::WaitForMultipleObjects(2, waits, FALSE, 30000) == WAIT_OBJECT_0 + 1)
        {
            probe(*state);
            ::SetEvent(done);
        }
        ::UnmapViewOfFile(state);
        for (HANDLE handle : {stop, done, request, ready, mapping})
        {
            ::CloseHandle(handle);
        }
        return 0;
    }

    // check：统一断言并输出到宿主日志；name 标识具体观察，failures 累加失败数。
    void check(bool ok, const char* name, unsigned& failures)
    {
        std::printf("%s %s\n", ok ? "PASS" : "FAIL", name);
        if (!ok)
        {
            ++failures;
        }
    }
}

// 主入口：--child 为独立目标；否则以指定 exe 创建 detached 子进程，重复执行生产后端。
int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wcscmp(argv[1], L"--child") == 0)
    {
        return child(argv[2]);
    }
    if (argc != 3)
    {
        std::fprintf(stderr, "usage: console_fixture.exe target.exe dynamic|static\n");
        return 2;
    }
    const bool dynamic = std::wcscmp(argv[2], L"dynamic") == 0; // 目标是否共享 CRT/STL。
    const std::wstring name = L"Local\\KSwordConsoleFixture-" + std::to_wstring(::GetCurrentProcessId())
        + L"-" + std::to_wstring(::GetTickCount64()); // 隔离本次测试的内核对象名。
    HANDLE mapping = ::CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, sizeof(ProbeState), name.c_str());
    auto* state = static_cast<ProbeState*>(::MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(ProbeState)));
    HANDLE ready = ::CreateEventW(nullptr, FALSE, FALSE, (name + L"-ready").c_str());
    HANDLE request = ::CreateEventW(nullptr, FALSE, FALSE, (name + L"-request").c_str());
    HANDLE done = ::CreateEventW(nullptr, FALSE, FALSE, (name + L"-done").c_str());
    HANDLE stop = ::CreateEventW(nullptr, TRUE, FALSE, (name + L"-stop").c_str());
    std::wstring command = L"\"" + std::wstring(argv[1]) + L"\" --child " + name; // 可写命令行。
    STARTUPINFOW startup{}; // 隐藏创建的控制台，回归只验证后台真实 I/O。
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION process{}; // 本夹具唯一允许操作的子进程。
    if (!state || !::CreateProcessW(argv[1], command.data(), nullptr, nullptr, FALSE,
            DETACHED_PROCESS, nullptr, nullptr, &startup, &process))
    {
        return 3;
    }
    unsigned failures = 0; // 累积所有独立失败，保证正常发信号清理子进程。
    check(::WaitForSingleObject(ready, 10000) == WAIT_OBJECT_0, "target ready", failures);
    FILETIME created{}, exited{}, kernel{}, user{}; // 真实的子进程创建身份。
    ::GetProcessTimes(process.hProcess, &created, &exited, &kernel, &user);
    const auto identity = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    std::string detail; // 生产后端的逐层回执。
    check(!ks::process::ForceProcessConsole(process.dwProcessId, identity + 1, &detail), "reject stale identity", failures);
    ::SetEvent(request);
    check(::WaitForSingleObject(done, 10000) == WAIT_OBJECT_0 && !state->console, "stale identity leaves console absent", failures);
    for (unsigned pass = 0; pass < 2; ++pass)
    {
        const bool ok = ks::process::ForceProcessConsole(process.dwProcessId, identity, &detail); // 首次和重复执行。
        std::printf("DETAIL %s\n", detail.c_str());
        check(ok, pass == 0 ? "initial console execution" : "repeat console execution", failures);
        ::SetEvent(request);
        check(::WaitForSingleObject(done, 10000) == WAIT_OBJECT_0, "target probe completed", failures);
        check(state->console && state->win32Io, "console/Win32 handles/UTF-8", failures);
        check((state->observed & 1U) != 0, "actual Win32 output", failures);
        if (dynamic)
        {
            check(state->cInput != 0, "actual C stdin", failures);
            check(state->cppGood != 0, "all six C++ stream states cleared", failures);
            check(state->observed == 0x1FF, "actual C/C++ narrow/wide output", failures);
        }
        else
        {
            check(detail.find("static/private CRT unchanged") != std::string::npos, "static CRT boundary reported", failures);
        }
    }
    // 对真实远程等待超时做一次验证：析构后参数页仍在，迟到线程不会访问已释放页。
    // 只在同位数动态夹具跑这一条，避免四组矩阵重复消耗五秒等待。
    if (dynamic && sizeof(void*) == 8 && std::wcsstr(argv[1], L"x64"))
    {
        std::uint64_t remoteData = 0; // 超时会话拥有的目标参数页地址。
        {
            ks::process::console_detail::RemoteSession timeoutSession(process.dwProcessId, identity);
            check(timeoutSession.initialize(), "timeout session initialized", failures);
            remoteData = timeoutSession.address(0);
            std::uint64_t ignored = 0; // Sleep 的返回值没有业务含义。
            check(!timeoutSession.call(L"kernel32.dll", "Sleep", {5500}, ignored)
                && timeoutSession.error().find("retained") != std::string::npos,
                "unfinished remote call reports timeout", failures);
        }
        MEMORY_BASIC_INFORMATION memory{}; // 析构后的真实远程参数页状态。
        HANDLE inspection = ::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, process.dwProcessId);
        check(inspection && ::VirtualQueryEx(inspection,
                reinterpret_cast<void*>(static_cast<std::uintptr_t>(remoteData)), &memory, sizeof(memory))
                && memory.State == MEM_COMMIT,
            "unfinished call data remains committed after session destruction", failures);
        if (inspection)
        {
            ::CloseHandle(inspection);
        }
        ::Sleep(650); // 等待自有迟到线程完成，再确认目标仍能响应业务请求。
        ::SetEvent(request);
        check(::WaitForSingleObject(done, 3000) == WAIT_OBJECT_0, "target survives late remote return", failures);
    }
    // 所有退出路径均先请求子进程自行退出；不结束任意已有进程。
    ::SetEvent(stop);
    check(::WaitForSingleObject(process.hProcess, 10000) == WAIT_OBJECT_0, "target exited normally", failures);
    ::CloseHandle(process.hThread);
    ::CloseHandle(process.hProcess);
    ::UnmapViewOfFile(state);
    for (HANDLE handle : {stop, done, request, ready, mapping})
    {
        ::CloseHandle(handle);
    }
    std::printf("FAILURES=%u\n", failures);
    return failures ? 1 : 0;
}
