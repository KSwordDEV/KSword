#include "ThreadActions.h"
#include <sstream>
#include <vector>
namespace ks::r3::process_detail::thread_actions {
std::wstring Win32ErrorText(const wchar_t* operation, DWORD error) {
    wchar_t* message = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        reinterpret_cast<LPWSTR>(&message),
        0,
        nullptr);

    std::wstring result = operation ? operation : L"Win32";
    result += L" 失败 (" + std::to_wstring(error) + L")";
    if (length != 0 && message) {
        std::wstring detail(message, length);
        while (!detail.empty() &&
               (detail.back() == L'\r' || detail.back() == L'\n' || detail.back() == L' ')) {
            detail.pop_back();
        }
        if (!detail.empty()) {
            result += L": " + detail;
        }
    }
    if (message) {
        ::LocalFree(message);
    }
    return result;
}
std::wstring DecimalText(std::uint64_t value) {
    return std::to_wstring(value);
}
std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }
    const int required = ::MultiByteToWideChar(
        CP_UTF8,
        0,
        text.data(),
        static_cast<int>(text.size()),
        nullptr,
        0);
    if (required <= 0) {
        return { text.begin(), text.end() };
    }
    std::wstring result(static_cast<std::size_t>(required), L'\0');
    ::MultiByteToWideChar(
        CP_UTF8,
        0,
        text.data(),
        static_cast<int>(text.size()),
        result.data(),
        required);
    return result;
}
}
namespace ks::r3::process_detail {
using namespace thread_actions;
bool OpenVerifiedProcessActionTarget(
    DWORD targetProcessId,
    ULONGLONG expectedProcessCreationTime100ns,
    DWORD requestedProcessAccess,
    ks::r3::common::UniqueHandle& processOut,
    std::wstring& errorText) {
    processOut.reset();
    errorText.clear();
    if (targetProcessId == 0U || expectedProcessCreationTime100ns == 0U) {
        errorText = L"目标进程身份不可用，已取消操作。";
        return false;
    }

    processOut.reset(::OpenProcess(
        requestedProcessAccess | PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        targetProcessId));
    if (!processOut.valid()) {
        errorText = Win32ErrorText(L"OpenProcess", ::GetLastError());
        return false;
    }
    FILETIME processCreationTime{};
    FILETIME processExitTime{};
    FILETIME processKernelTime{};
    FILETIME processUserTime{};
    if (!::GetProcessTimes(
            processOut.get(),
            &processCreationTime,
            &processExitTime,
            &processKernelTime,
            &processUserTime)) {
        errorText = Win32ErrorText(L"GetProcessTimes", ::GetLastError());
        return false;
    }
    const ULONGLONG actualProcessCreationTime100ns =
        (static_cast<ULONGLONG>(processCreationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(processCreationTime.dwLowDateTime);
    if (actualProcessCreationTime100ns == 0U ||
        actualProcessCreationTime100ns != expectedProcessCreationTime100ns) {
        errorText = L"目标进程实例已变更，已取消操作。";
        return false;
    }
    return true;
}
bool OpenVerifiedThreadActionTarget(
    DWORD targetProcessId,
    ULONGLONG expectedProcessCreationTime100ns,
    DWORD targetThreadId,
    ULONGLONG expectedThreadCreationTime100ns,
    DWORD requestedThreadAccess,
    ks::r3::common::UniqueHandle& processOut,
    ks::r3::common::UniqueHandle& threadOut,
    std::wstring& errorText) {
    threadOut.reset();
    if (targetThreadId == 0U || expectedThreadCreationTime100ns == 0U) {
        processOut.reset();
        errorText = L"目标线程身份不可用，已取消操作。";
        return false;
    }
    if (!OpenVerifiedProcessActionTarget(
            targetProcessId,
            expectedProcessCreationTime100ns,
            PROCESS_QUERY_LIMITED_INFORMATION,
            processOut,
            errorText)) {
        return false;
    }

    threadOut.reset(::OpenThread(
        THREAD_QUERY_LIMITED_INFORMATION | requestedThreadAccess,
        FALSE,
        targetThreadId));
    if (!threadOut.valid()) {
        errorText = Win32ErrorText(L"OpenThread", ::GetLastError());
        return false;
    }
    const DWORD actualOwnerProcessId = ::GetProcessIdOfThread(threadOut.get());
    if (actualOwnerProcessId == 0U) {
        errorText = Win32ErrorText(L"GetProcessIdOfThread", ::GetLastError());
        return false;
    }
    if (actualOwnerProcessId != targetProcessId) {
        errorText = L"目标线程已不属于所选进程，已取消操作。";
        return false;
    }

    FILETIME threadCreationTime{};
    FILETIME threadExitTime{};
    FILETIME threadKernelTime{};
    FILETIME threadUserTime{};
    if (!::GetThreadTimes(
            threadOut.get(),
            &threadCreationTime,
            &threadExitTime,
            &threadKernelTime,
            &threadUserTime)) {
        errorText = Win32ErrorText(L"GetThreadTimes", ::GetLastError());
        return false;
    }
    const ULONGLONG actualThreadCreationTime100ns =
        (static_cast<ULONGLONG>(threadCreationTime.dwHighDateTime) << 32U) |
        static_cast<ULONGLONG>(threadCreationTime.dwLowDateTime);
    if (actualThreadCreationTime100ns == 0U ||
        actualThreadCreationTime100ns != expectedThreadCreationTime100ns) {
        errorText = L"目标线程实例已变更，已取消操作。";
        return false;
    }
    return true;
}
ProcessDetailActionResult SuspendDetailThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns) {

            ProcessDetailActionResult result{};
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
                result.statusText = L"● " + identityError;
                return result;
            }
            result.identityMatched = true;
            const DWORD previousCount = ::SuspendThread(verifiedThread.get());
            const DWORD error = previousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            result.win32ErrorKnown = true; result.win32Error = error;
            if (error != ERROR_SUCCESS) {
                result.statusText = L"● " + Win32ErrorText(L"SuspendThread", error);
                return result;
            }
            result.requestSucceeded = true;
            result.refreshRequired = true;
            result.previousSuspendCountKnown = true; result.previousSuspendCount = previousCount;
            result.statusText = L"● 已挂起线程 " + DecimalText(threadId) +
                L"（原挂起计数 " + DecimalText(previousCount) + L"）";
            return result;

}
ProcessDetailActionResult ResumeDetailThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns) {

            ProcessDetailActionResult result{};
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
                result.statusText = L"● " + identityError;
                return result;
            }
            result.identityMatched = true;
            const DWORD previousCount = ::ResumeThread(verifiedThread.get());
            const DWORD error = previousCount == static_cast<DWORD>(-1) ? ::GetLastError() : ERROR_SUCCESS;
            result.win32ErrorKnown = true; result.win32Error = error;
            if (error != ERROR_SUCCESS) {
                result.statusText = L"● " + Win32ErrorText(L"ResumeThread", error);
                return result;
            }
            result.requestSucceeded = true;
            result.refreshRequired = true;
            result.previousSuspendCountKnown = true; result.previousSuspendCount = previousCount;
            result.statusText = L"● 已恢复线程 " + DecimalText(threadId) +
                L"（原挂起计数 " + DecimalText(previousCount) + L"）";
            return result;

}
ProcessDetailActionResult TerminateDetailThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns) {

            ProcessDetailActionResult result{};
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
                result.statusText = L"● " + identityError;
                return result;
            }
            result.identityMatched = true;
            const BOOL terminated = ::TerminateThread(verifiedThread.get(), 1);
            const DWORD error = terminated ? ERROR_SUCCESS : ::GetLastError();
            result.win32ErrorKnown = true; result.win32Error = error;
            if (!terminated) {
                result.statusText = L"● " + Win32ErrorText(L"TerminateThread", error);
                return result;
            }
            result.requestSucceeded = true;
            result.refreshRequired = true;
            result.statusText = L"● 已请求终止线程 " + DecimalText(threadId);
            return result;

}
ProcessDetailActionResult SetDetailThreadAffinity(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns, const ksword::thread_affinity_r3::Rule& rule) {

                ProcessDetailActionResult result{};
                ks::r3::common::UniqueHandle verifiedProcess;
                ks::r3::common::UniqueHandle verifiedThread;
                std::wstring identityError;
                if (!OpenVerifiedThreadActionTarget(
                        targetProcessId,
                        expectedProcessCreationTime100ns,
                        threadId,
                        expectedThreadCreationTime100ns,
                        THREAD_SET_LIMITED_INFORMATION,
                        verifiedProcess,
                        verifiedThread,
                        identityError)) {
                    result.statusText = L"● 设置线程亲和性失败 | " + identityError;
                    return result;
                }
                result.identityMatched = true;
                std::string detailText;
                ksword::thread_affinity_r3::SetOutcome outcome;
                if (!ksword::thread_affinity_r3::SetThreadAffinityRule(
                        threadId,
                        targetProcessId,
                        expectedThreadCreationTime100ns,
                        rule,
                        &detailText, &outcome)) {
                    result.writeAttempted = outcome.writeAttempted; result.writeSucceeded = outcome.writeSucceeded;
                    result.verified = outcome.verified; result.rollbackAttempted = outcome.rollbackAttempted; result.rollbackSucceeded = outcome.rollbackSucceeded;
                    result.statusText = L"● 设置线程亲和性失败 | " +
                        (detailText.empty() ? L"R3 API 调用失败。" : Utf8ToWide(detailText));
                    return result;
                }
                result.requestSucceeded = true;
                result.writeAttempted = outcome.writeAttempted; result.writeSucceeded = outcome.writeSucceeded; result.verified = outcome.verified;
                result.refreshRequired = true;
                result.statusText = L"● 已通过 R3 更新线程 " + DecimalText(threadId) +
                    L" 的 CPU Set 亲和性。";
                return result;

}
}
