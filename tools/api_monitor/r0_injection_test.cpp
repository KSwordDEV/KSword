#include "shared/ApiMonitorR0Injection.h"
#include <cstdio>

namespace {
unsigned calls = 0;
bool simulateFailure = false;
bool simulateBadStatus = false;
bool simulateShortWrite = false;
std::uint64_t observedEntry = 0;
DWORD observedPid = 0;
}

// Test seam: no device is opened and no thread is injected.
namespace ksword::ark {
ProcessInjectResult DriverClient::injectProcessDllAt(std::uint32_t pid, const std::wstring& path,
    std::uint64_t entry, unsigned long flags) const
{
    ++calls; observedEntry = entry; observedPid = pid;
    ProcessInjectResult r{};
    r.io.ok = !simulateFailure; r.io.win32Error = simulateFailure ? ERROR_ACCESS_DENIED : 0;
    r.version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION; r.processId = pid;
    r.injectType = KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH;
    r.status = KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    r.flags = flags; r.bytesWritten = static_cast<std::uint32_t>((path.size() + 1) * sizeof(wchar_t));
    if (simulateBadStatus) r.status = KSWORD_ARK_PROCESS_INJECT_STATUS_THREAD_FAILED;
    if (simulateShortWrite) --r.bytesWritten;
    return r;
}
}

int wmain()
{
    using namespace ks::winapi_monitor;
    wchar_t path[32768]{};
    HMODULE module = ::GetModuleHandleW(L"KernelBase.dll");
    if (!module || !::GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path)))) return 1;
    const auto pid = ::GetCurrentProcessId();
    const auto creation = processCreationIdentity(::GetCurrentProcess());
    if (!creation) return 2;
    std::wstring error;
    if (!injectAgentR0(pid, path, &error, nullptr, creation)) { std::fwprintf(stderr, L"%ls\n", error.c_str()); return 3; }
    const auto expected = findRemoteExport(::GetCurrentProcess(), pid, currentMachine(), L"KernelBase.dll", "LoadLibraryW");
    if (calls != 1 || observedPid != pid || !expected || observedEntry != expected) return 4;
    if (injectAgentR0(pid, path, &error, nullptr, creation + 1) || calls != 1) return 5;
    HANDLE cancel = ::CreateEventW(nullptr, TRUE, TRUE, nullptr);
    if (!cancel) return 6;
    const bool canceled = injectAgentR0(pid, path, &error, cancel, creation);
    const DWORD cancelError = ::GetLastError();
    ::CloseHandle(cancel);
    if (canceled || calls != 1 || cancelError != ERROR_OPERATION_ABORTED) return 7;
    simulateFailure = true;
    if (injectAgentR0(pid, path, &error, nullptr, creation) || calls != 2 || ::GetLastError() != ERROR_ACCESS_DENIED) return 8;
    simulateFailure = false; simulateBadStatus = true;
    if (injectAgentR0(pid, path, &error, nullptr, creation) || calls != 3) return 9;
    simulateBadStatus = false; simulateShortWrite = true;
    if (injectAgentR0(pid, path, &error, nullptr, creation) || calls != 4) return 10;
    if (injectAgentR0(pid, L"Z:\\missing-agent.dll", &error, nullptr, creation) || calls != 4) return 11;
    std::puts("PASS: R0 adapter validates target identity, target export, cancellation and driver failure without fallback");
    return 0;
}
