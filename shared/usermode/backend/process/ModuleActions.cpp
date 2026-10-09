#include "ModuleActions.h"
#include <algorithm>
#include <cwchar>
#include <iterator>
#include <sstream>
namespace ks::r3::process_detail::module_actions {
std::wstring LastErrorText(const wchar_t* operation, DWORD error) {
    wchar_t* systemText = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    ::FormatMessageW(
        flags,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&systemText),
        0,
        nullptr);
    std::wstring result = operation ? operation : L"Win32 operation";
    result += L" failed";
    if (systemText) {
        result += L": ";
        result += systemText;
        while (!result.empty() &&
               (result.back() == L'\r' || result.back() == L'\n' || result.back() == L' ')) {
            result.pop_back();
        }
        ::LocalFree(systemText);
    } else {
        result += L" (" + std::to_wstring(error) + L")";
    }
    return result;
}
std::wstring BaseNameFromPath(const std::wstring& path) {
    const std::size_t separator = path.find_last_of(L"\\/");
    if (separator == std::wstring::npos || separator + 1U >= path.size()) {
        return path;
    }
    return path.substr(separator + 1U);
}
}
namespace ks::r3::process_detail {
using namespace module_actions;
using thread_actions::DecimalText;
ProcessDetailActionResult UnloadDetailModule(std::uintptr_t moduleBase, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns, const std::shared_ptr<const std::vector<ProcessModuleInfo>>& moduleSnapshot) {

            ProcessDetailActionResult action{};
            HMODULE localKernel32 = ::GetModuleHandleW(L"kernel32.dll");
            FARPROC localFreeLibrary = localKernel32 ? ::GetProcAddress(localKernel32, "FreeLibrary") : nullptr;
            HMODULE localFunctionModule = nullptr;
            if (!localFreeLibrary || !::GetModuleHandleExW(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCWSTR>(localFreeLibrary),
                    &localFunctionModule)) {
                action.statusText = L"● 卸载模块失败 | 无法解析 FreeLibrary";
                return action;
            }
            wchar_t localFunctionPath[32768]{};
            const DWORD localFunctionPathLength = ::GetModuleFileNameW(
                localFunctionModule,
                localFunctionPath,
                static_cast<DWORD>(std::size(localFunctionPath)));
            const std::wstring functionModuleName = localFunctionPathLength > 0
                ? BaseNameFromPath(std::wstring(localFunctionPath, localFunctionPathLength))
                : L"kernel32.dll";
            std::uintptr_t remoteFunctionModule = 0;
            if (moduleSnapshot) {
                for (const ProcessModuleInfo& module : *moduleSnapshot) {
                    if (_wcsicmp(BaseNameFromPath(module.modulePath).c_str(), functionModuleName.c_str()) == 0) {
                        remoteFunctionModule = module.baseAddress;
                        break;
                    }
                }
            }
            const std::uintptr_t localFunctionModuleAddress = reinterpret_cast<std::uintptr_t>(localFunctionModule);
            const std::uintptr_t freeLibraryOffset =
                reinterpret_cast<std::uintptr_t>(localFreeLibrary) - localFunctionModuleAddress;
            const std::uintptr_t remoteFreeLibrary = remoteFunctionModule
                ? remoteFunctionModule + freeLibraryOffset
                : reinterpret_cast<std::uintptr_t>(localFreeLibrary);

            ks::r3::common::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!OpenVerifiedProcessActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● 卸载模块失败 | " + identityError;
                return action;
            }
            ks::r3::common::UniqueHandle remoteThread(::CreateRemoteThread(
                verifiedProcess.get(),
                nullptr,
                0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteFreeLibrary),
                reinterpret_cast<void*>(moduleBase),
                0,
                nullptr));
            if (!remoteThread.valid()) {
                action.statusText = L"● 卸载模块失败 | " + LastErrorText(L"CreateRemoteThread", ::GetLastError());
                return action;
            }
            const DWORD waitResult = ::WaitForSingleObject(remoteThread.get(), 10000);
            DWORD exitCode = 0;
            const bool completed = waitResult == WAIT_OBJECT_0 &&
                ::GetExitCodeThread(remoteThread.get(), &exitCode) != FALSE && exitCode != 0;
            if (!completed) {
                action.statusText = L"● 卸载模块失败 | FreeLibrary 未成功返回";
                return action;
            }
            action.refreshRequired = true;
            action.statusText = L"● 卸载模块成功";
            return action;

}
ProcessDetailActionResult SuspendModuleThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns) {

            ProcessDetailActionResult action{};
            ks::r3::common::UniqueHandle verifiedProcess;
            ks::r3::common::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!OpenVerifiedThreadActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    threadId,
                    expectedThreadCreationTime100ns,
                    THREAD_SUSPEND_RESUME,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 挂起 Thread 失败 | " + identityError;
                return action;
            }
            const DWORD previousCount = ::SuspendThread(verifiedThread.get());
            const DWORD error = previousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            action.refreshRequired = error == ERROR_SUCCESS;
            action.statusText = error == ERROR_SUCCESS
                ? L"● 挂起 Thread 成功"
                : L"● 挂起 Thread 失败 | " + LastErrorText(L"SuspendThread", error);
            return action;

}
ProcessDetailActionResult ResumeModuleThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns) {

            ProcessDetailActionResult action{};
            ks::r3::common::UniqueHandle verifiedProcess;
            ks::r3::common::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!OpenVerifiedThreadActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    threadId,
                    expectedThreadCreationTime100ns,
                    THREAD_SUSPEND_RESUME,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 取消挂起 Thread 失败 | " + identityError;
                return action;
            }
            const DWORD previousCount = ::ResumeThread(verifiedThread.get());
            const DWORD error = previousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            action.refreshRequired = error == ERROR_SUCCESS;
            action.statusText = error == ERROR_SUCCESS
                ? L"● 取消挂起 Thread 成功"
                : L"● 取消挂起 Thread 失败 | " + LastErrorText(L"ResumeThread", error);
            return action;

}
ProcessDetailActionResult TerminateModuleThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns) {

            ProcessDetailActionResult action{};
            ks::r3::common::UniqueHandle verifiedProcess;
            ks::r3::common::UniqueHandle verifiedThread;
            std::wstring identityError;
            if (!OpenVerifiedThreadActionTarget(
                    targetProcessId,
                    expectedProcessCreationTime100ns,
                    threadId,
                    expectedThreadCreationTime100ns,
                    THREAD_TERMINATE,
                    verifiedProcess,
                    verifiedThread,
                    identityError)) {
                action.statusText = L"● 结束 Thread 失败 | " + identityError;
                return action;
            }
            const BOOL terminated = ::TerminateThread(verifiedThread.get(), 0);
            const DWORD error = terminated ? ERROR_SUCCESS : ::GetLastError();
            if (!terminated) {
                action.statusText = L"● 结束 Thread 失败 | " + LastErrorText(L"TerminateThread", error);
                return action;
            }
            action.refreshRequired = true;
            action.statusText = L"● 结束 Thread 成功";
            return action;

}
}
