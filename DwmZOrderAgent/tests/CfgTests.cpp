#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstring>
#include <iostream>
#include <string>
#include "../NativeQueries.h"

namespace
{
    using AddressesFn = void (WINAPI*)(const void**, const void**);

    bool QueryAddresses(HMODULE module, const void*& find, const void*& desktop)
    {
        auto addresses = reinterpret_cast<AddressesFn>(GetProcAddress(module, "DwmQueryFixtureAddresses"));
        if (!addresses) return false;
        addresses(&find, &desktop);
        return find && desktop;
    }

    bool IsCfgTarget(HMODULE module, const void* function)
    {
        auto* image = reinterpret_cast<const unsigned char*>(module);
        auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image);
        auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(image + dos->e_lfanew);
        auto* config = reinterpret_cast<const IMAGE_LOAD_CONFIG_DIRECTORY64*>(image
            + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
        const auto target = reinterpret_cast<const unsigned char*>(function) - image;
        const auto* entries = reinterpret_cast<const unsigned char*>(config->GuardCFFunctionTable);
        const DWORD stride = 4 + ((config->GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK)
            >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);
        for (ULONGLONG i = 0; i < config->GuardCFFunctionCount; ++i)
        {
            DWORD rva = 0;
            std::memcpy(&rva, entries + i * stride, sizeof(rva));
            if (rva == target) return stride == 4 || !(entries[i * stride + 4] & IMAGE_GUARD_FLAG_FID_SUPPRESSED);
        }
        return false;
    }
}

int RunCfgRepro(const wchar_t* fixture)
{
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    HMODULE module = LoadLibraryW(fixture);
    if (!module) return 2;
    const void* find = nullptr;
    const void* desktop = nullptr;
    if (!QueryAddresses(module, find, desktop)) return 3;
    auto legacy = reinterpret_cast<ks::dwm_order::NativeQueries::FindWindowFn>(const_cast<void*>(find));
    LIST_ENTRY list{};
    // This is the former production call shape. Only the disposable debugger
    // child executes it; the expected result is FAST_FAIL_GUARD_ICALL_CHECK_FAILURE.
    return legacy(&list, reinterpret_cast<HWND>(0x7788)) == &list ? 4 : 5;
}

void RunCfgTests(void (*check)(bool, const char*))
{
    using ks::dwm_order::NativeQueries;
    wchar_t executable[32768]{};
    GetModuleFileNameW(nullptr, executable, 32768);
    const std::wstring executablePath(executable);
    const auto directory = executablePath.substr(0, executablePath.find_last_of(L'\\') + 1);
    const auto fixture = directory + L"DwmLoaderFixture.dll";
    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY policy{};
    check(GetProcessMitigationPolicy(GetCurrentProcess(), ProcessControlFlowGuardPolicy, &policy, sizeof(policy))
        && policy.EnableControlFlowGuard, "CFG is active throughout the regression test process");
    HMODULE module = LoadLibraryW(fixture.c_str());
    check(module != nullptr, "load CFG-enabled private-query fixture");
    if (!module) return;
    const void* find = nullptr;
    const void* desktop = nullptr;
    const bool found = QueryAddresses(module, find, desktop);
    check(found, "resolve fixture query entry addresses without registering them as CFG targets");
    if (!found) { FreeLibrary(module); return; }
    check(!IsCfgTarget(module, find) && !IsCfgTarget(module, desktop),
        "both query helpers are absent from the fixture GFIDS table");
    const auto* binding = NativeQueries::Create(
        reinterpret_cast<NativeQueries::FindWindowFn>(const_cast<void*>(find)),
        reinterpret_cast<NativeQueries::DesktopListFn>(const_cast<void*>(desktop)));
    check(binding != nullptr, "create production query binding");
    if (binding)
    {
        MEMORY_BASIC_INFORMATION memory{};
        check(VirtualQuery(binding, &memory, sizeof(memory)) && memory.Protect == PAGE_READONLY,
            "query addresses are sealed read-only before use");
        LIST_ENTRY list{};
        check(binding->FindWindow(&list, reinterpret_cast<HWND>(0x7788)) == &list,
            "production FindWindow bridge handles a direct-only entry with CFG still enabled");
        check(binding->DesktopList(&list, 0x1234567887654321ULL) == &list,
            "production DesktopList bridge preserves its 64-bit desktop argument");
        NativeQueries::Destroy(binding);
    }
    FreeLibrary(module);

    // Observe the precise fast-fail subcode in a debugger child. No WER dialog,
    // DWM injection, desktop changes, or exception-policy changes are required.
    std::wstring command = L"\"" + executablePath + L"\" --cfg-repro \"" + fixture + L"\"";
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    const bool created = CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW, nullptr, directory.c_str(), &startup, &child) != FALSE;
    check(created, "launch disposable CFG reproduction under the test debugger");
    if (!created) return;
    bool matched = false, exited = false;
    DWORD exitCode = 0;
    const ULONGLONG deadline = GetTickCount64() + 15000;
    while (!exited && GetTickCount64() < deadline)
    {
        DEBUG_EVENT event{};
        if (!WaitForDebugEvent(&event, 1000)) continue;
        DWORD disposition = DBG_CONTINUE;
        if (event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && event.u.CreateProcessInfo.hFile)
            CloseHandle(event.u.CreateProcessInfo.hFile);
        if (event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && event.u.LoadDll.hFile)
            CloseHandle(event.u.LoadDll.hFile);
        if (event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
        {
            const auto& exception = event.u.Exception.ExceptionRecord;
            if (exception.ExceptionCode == 0xc0000409 && exception.NumberParameters
                && exception.ExceptionInformation[0] == FAST_FAIL_GUARD_ICALL_CHECK_FAILURE) matched = true;
            if (exception.ExceptionCode != EXCEPTION_BREAKPOINT) disposition = DBG_EXCEPTION_NOT_HANDLED;
        }
        if (event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
        { exited = true; exitCode = event.u.ExitProcess.dwExitCode; }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition);
    }
    check(matched && exited && exitCode == 0xc0000409,
        "former call shape reproduces 0xC0000409 with CFG subcode 0xA in an isolated child");
    std::cout << "CFG_LEGACY_FASTFAIL=" << matched << " EXIT=0x" << std::hex << exitCode << std::dec << '\n';
    if (!exited) { TerminateProcess(child.hProcess, ERROR_CANCELLED); WaitForSingleObject(child.hProcess, 2000); }
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);
}
