#pragma once

#include "ApiMonitorInjection.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

namespace ks::winapi_monitor
{
    // Explicit R0 choice: the existing v1 driver IOCTL still looks up a PID,
    // so the user-mode creation-time checks cannot make that lookup atomic.
    // Do not treat a successfully created loader thread as Agent readiness.
    inline bool injectAgentR0(DWORD pid, const std::wstring& path, std::wstring* error,
        HANDLE cancelEvent, std::uint64_t expectedCreation)
    {
        if (error) error->clear();
        if (pid <= 4 || path.empty() || !expectedCreation)
            return platformFailure(error, L"R0 injection requires a target identity and Agent path", ERROR_INVALID_PARAMETER);
        if (cancelEvent && ::WaitForSingleObject(cancelEvent, 0) == WAIT_OBJECT_0)
            return platformFailure(error, L"R0 injection cancelled", ERROR_OPERATION_ABORTED);

        HANDLE process = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, pid);
        if (!process) return platformFailure(error, L"OpenProcess for R0 target verification", ::GetLastError());
        const auto closeFailure = [&](const wchar_t* operation, DWORD code) {
            ::CloseHandle(process); return platformFailure(error, operation, code);
        };
        const auto identityMatches = [&]() {
            return ::WaitForSingleObject(process, 0) == WAIT_TIMEOUT
                && processCreationIdentity(process) == expectedCreation;
        };
        if (!identityMatches()) return closeFailure(L"R0 target process identity changed", ERROR_INVALID_HANDLE);
        USHORT machine = 0, image = 0;
        if (!queryProcessMachine(process, &machine, error) || !queryImageMachine(path, &image, error)) {
            const DWORD code = ::GetLastError(); ::CloseHandle(process); ::SetLastError(code); return false;
        }
        if (machine != image) return closeFailure(L"R0 Agent DLL does not match target architecture", ERROR_BAD_EXE_FORMAT);
#ifndef _WIN64
        if (machine != currentMachine()) return closeFailure(L"R0 injector architecture unsupported", ERROR_BAD_EXE_FORMAT);
#endif
        auto loader = findRemoteExport(process, pid, machine, L"KernelBase.dll", "LoadLibraryW");
        if (!loader) loader = findRemoteExport(process, pid, machine, L"kernel32.dll", "LoadLibraryW");
        if (!loader || (machine == IMAGE_FILE_MACHINE_I386 && loader > UINT32_MAX))
            return closeFailure(L"R0 target LoadLibraryW unavailable", ERROR_PROC_NOT_FOUND);
        if (!identityMatches()) return closeFailure(L"R0 target process identity changed", ERROR_INVALID_HANDLE);
        if (cancelEvent && ::WaitForSingleObject(cancelEvent, 0) == WAIT_OBJECT_0)
            return closeFailure(L"R0 injection cancelled", ERROR_OPERATION_ABORTED);

        // The existing driver performs a bounded ten-second wait. Cancellation
        // cannot interrupt an in-flight synchronous IOCTL; on return the usual
        // session cleanup signals a possibly late Agent to stop.
        const auto result = ksword::ark::DriverClient().injectProcessDllAt(pid, path, loader);
        if (!result.io.ok || result.version != KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION
            || result.processId != pid || result.injectType != KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH
            || result.status != KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED
            || result.waitStatus != 0
            || result.bytesWritten != (path.size() + 1U) * sizeof(wchar_t)) {
            if (error) {
                *error = L"R0 Agent injection failed; driverStatus=" + std::to_wstring(result.status)
                    + L"; ntStatus=" + std::to_wstring(static_cast<unsigned long>(result.lastStatus))
                    + L"; win32=" + std::to_wstring(result.io.win32Error);
            }
            const DWORD code = result.io.win32Error ? result.io.win32Error : ERROR_DLL_INIT_FAILED;
            ::CloseHandle(process); ::SetLastError(code); return false;
        }
        if (!identityMatches()) return closeFailure(L"R0 target process identity changed", ERROR_INVALID_HANDLE);
        if (cancelEvent && ::WaitForSingleObject(cancelEvent, 0) == WAIT_OBJECT_0)
            return closeFailure(L"R0 injection cancelled", ERROR_OPERATION_ABORTED);
        DWORD moduleError = ERROR_SUCCESS;
        if (!remoteImageLoaded(pid, path, &moduleError))
            return closeFailure(L"R0 Agent loader did not confirm module", moduleError ? moduleError : ERROR_DLL_INIT_FAILED);
        if (!identityMatches()) return closeFailure(L"R0 target process identity changed", ERROR_INVALID_HANDLE);
        ::CloseHandle(process);
        return true;
    }
}
