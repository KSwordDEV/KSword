#include "pch.h"
#include "ClipboardGuardHook.h"
#include "ClipboardGuardCommon.h"
#include "ClipboardGuardVTableHook.h"
#include <cstring>
#include <type_traits>

namespace apimon
{
#include "ApiMonitorClipboardDefinitions.inc"

    namespace
    {
        struct ClipboardCallClock { LARGE_INTEGER start{}; bool valid = false; };
        struct ClipboardCallDuration { std::uint64_t ticks100ns = 0; bool valid = false; };
        ClipboardCallClock BeginClipboardCall()
        {
            const DWORD saved = ::GetLastError(); ClipboardCallClock clock;
            clock.valid = ::QueryPerformanceCounter(&clock.start) != FALSE;
            ::SetLastError(saved); return clock;
        }
        ClipboardCallDuration EndClipboardCall(const ClipboardCallClock& clock)
        {
            const DWORD saved = ::GetLastError(); LARGE_INTEGER end{}, frequency{};
            ClipboardCallDuration result;
            if (clock.valid && ::QueryPerformanceCounter(&end) && ::QueryPerformanceFrequency(&frequency)
                && frequency.QuadPart > 0 && end.QuadPart >= clock.start.QuadPart)
            {
                const double ticks = static_cast<double>(end.QuadPart - clock.start.QuadPart)
                    * 10000000.0 / static_cast<double>(frequency.QuadPart);
                if (ticks >= 0.0 && ticks < 18446744073709551616.0)
                { result.ticks100ns = static_cast<std::uint64_t>(ticks); result.valid = true; }
            }
            ::SetLastError(saved); return result;
        }
        template<typename T> std::uint64_t ClipboardReturnBits(T value)
        {
            static_assert(std::is_trivially_copyable_v<T> && sizeof(T) <= sizeof(std::uint64_t));
            std::uint64_t bits = 0; std::memcpy(&bits, &value, sizeof(value)); return bits;
        }
    }

    // HookedOpenClipboard 作用：
    // - 处理：OpenClipboard 只是"声明接下来要用剪贴板"，不搬运任何数据，
    //   按方案不在这一层拦截（拦这里会连正常的复制/粘贴 UI 反馈都破坏掉），
    //   只记录事件，始终放行。
    BOOL WINAPI HookedOpenClipboard(HWND ownerWindow)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_openClipboardOriginal(ownerWindow);
        }
        const auto callClock = BeginClipboardCall();
        const BOOL resultValue = g_openClipboardOriginal(ownerWindow);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"OpenClipboard", 0, nullptr, ClipboardPolicyAction::Allow, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, resultValue != FALSE || lastError != ERROR_SUCCESS, resultValue != FALSE ? 0 : static_cast<std::int32_t>(lastError));
        ::SetLastError(lastError);
        return resultValue;
    }

    // HookedCloseClipboard 作用：释放剪贴板锁，同样不搬运数据，且拦截它会让
    // 调用方永久持有剪贴板、破坏其它程序的剪贴板访问，因此始终放行。
    BOOL WINAPI HookedCloseClipboard()
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_closeClipboardOriginal();
        }
        const auto callClock = BeginClipboardCall();
        const BOOL resultValue = g_closeClipboardOriginal();
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"CloseClipboard", 0, nullptr, ClipboardPolicyAction::Allow, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, resultValue != FALSE || lastError != ERROR_SUCCESS, resultValue != FALSE ? 0 : static_cast<std::int32_t>(lastError));
        ::SetLastError(lastError);
        return resultValue;
    }

    // HookedGetClipboardData 作用：
    // - 处理：真正的"读"发生点。命中 BLOCK 策略时完全不调用原函数，直接返回
    //   NULL 并置 ERROR_ACCESS_DENIED，调用方看到的和真的没有该格式数据一样；
    //   放行时才把返回句柄交给 ReportClipboardEvent 尝试取 size/hash。
    HANDLE WINAPI HookedGetClipboardData(const UINT formatValue)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_getClipboardDataOriginal(formatValue);
        }

        const DWORD entryError = ::GetLastError();
        const ClipboardPolicyAction actionValue = ResolveClipboardAction(ClipboardOperationKind::Read);
        if (actionValue == ClipboardPolicyAction::Block)
        {
            ReportClipboardEvent(ClipboardOperationKind::Read, L"User32", L"GetClipboardData", formatValue, nullptr, actionValue, true, ClipboardReturnBits(static_cast<HANDLE>(nullptr)), false, 0, true, static_cast<std::int32_t>(ERROR_ACCESS_DENIED));
            ::SetLastError(ERROR_ACCESS_DENIED);
            return nullptr;
        }

        ::SetLastError(entryError);
        const auto callClock = BeginClipboardCall();
        const HANDLE resultHandle = g_getClipboardDataOriginal(formatValue);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Read, L"User32", L"GetClipboardData", formatValue, resultHandle, actionValue, true, ClipboardReturnBits(resultHandle), duration.valid, duration.ticks100ns, resultHandle != nullptr, 0);
        ::SetLastError(lastError);
        return resultHandle;
    }

    // HookedSetClipboardData 作用：真正的"写"发生点之一。命中 BLOCK 时不调用
    // 原函数，返回 NULL（与 SetClipboardData 失败时的公开语义一致）。
    HANDLE WINAPI HookedSetClipboardData(const UINT formatValue, const HANDLE dataHandle)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_setClipboardDataOriginal(formatValue, dataHandle);
        }

        const DWORD entryError = ::GetLastError();
        const ClipboardPolicyAction actionValue = ResolveClipboardAction(ClipboardOperationKind::Write);
        if (actionValue == ClipboardPolicyAction::Block)
        {
            ReportClipboardEvent(ClipboardOperationKind::Write, L"User32", L"SetClipboardData", formatValue, nullptr, actionValue, true, ClipboardReturnBits(static_cast<HANDLE>(nullptr)), false, 0, true, static_cast<std::int32_t>(ERROR_ACCESS_DENIED));
            ::SetLastError(ERROR_ACCESS_DENIED);
            return nullptr;
        }

        ::SetLastError(entryError);
        const auto callClock = BeginClipboardCall();
        const HANDLE resultHandle = g_setClipboardDataOriginal(formatValue, dataHandle);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Write, L"User32", L"SetClipboardData", formatValue, nullptr, actionValue, true, ClipboardReturnBits(resultHandle), duration.valid, duration.ticks100ns, resultHandle != nullptr, 0);
        ::SetLastError(lastError);
        return resultHandle;
    }

    // HookedEmptyClipboard 作用：
    // - 处理：清空剪贴板本身就是一种"写"（否则"拦截写"只挡住了 SetClipboardData，
    //   EmptyClipboard 仍能把剪贴板清空，留下一个奇怪的半生效状态），
    //   因此同样受 clipboardWriteAction 管控。
    BOOL WINAPI HookedEmptyClipboard()
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_emptyClipboardOriginal();
        }

        const DWORD entryError = ::GetLastError();
        const ClipboardPolicyAction actionValue = ResolveClipboardAction(ClipboardOperationKind::Write);
        if (actionValue == ClipboardPolicyAction::Block)
        {
            ReportClipboardEvent(ClipboardOperationKind::Write, L"User32", L"EmptyClipboard", 0, nullptr, actionValue, true, ClipboardReturnBits(static_cast<BOOL>(FALSE)), false, 0, true, static_cast<std::int32_t>(ERROR_ACCESS_DENIED));
            ::SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }

        ::SetLastError(entryError);
        const auto callClock = BeginClipboardCall();
        const BOOL resultValue = g_emptyClipboardOriginal();
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Write, L"User32", L"EmptyClipboard", 0, nullptr, actionValue, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, resultValue != FALSE || lastError != ERROR_SUCCESS, resultValue != FALSE ? 0 : static_cast<std::int32_t>(lastError));
        ::SetLastError(lastError);
        return resultValue;
    }

    // HookedEnumClipboardFormats 作用：枚举当前剪贴板已提供的格式列表，
    // 受 clipboardEnumAction 管控；命中 BLOCK 时返回 0（等价于"没有更多格式"）。
    UINT WINAPI HookedEnumClipboardFormats(const UINT formatValue)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_enumClipboardFormatsOriginal(formatValue);
        }

        const DWORD entryError = ::GetLastError();
        const ClipboardPolicyAction actionValue = ResolveClipboardAction(ClipboardOperationKind::Enum);
        if (actionValue == ClipboardPolicyAction::Block)
        {
            ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"EnumClipboardFormats", formatValue, nullptr, actionValue, true, ClipboardReturnBits(static_cast<UINT>(0)), false, 0, true, static_cast<std::int32_t>(ERROR_ACCESS_DENIED));
            ::SetLastError(ERROR_ACCESS_DENIED);
            return 0;
        }

        ::SetLastError(entryError);
        const auto callClock = BeginClipboardCall();
        const UINT resultValue = g_enumClipboardFormatsOriginal(formatValue);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"EnumClipboardFormats", formatValue, nullptr, actionValue, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, resultValue != 0, 0);
        ::SetLastError(lastError);
        return resultValue;
    }

    // HookedIsClipboardFormatAvailable 作用：查询某格式是否存在，
    // 命中 BLOCK 时直接回答 FALSE（"这个格式不存在"），最贴近真实拦截语义。
    BOOL WINAPI HookedIsClipboardFormatAvailable(const UINT formatValue)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_isClipboardFormatAvailableOriginal(formatValue);
        }

        const DWORD entryError = ::GetLastError();
        const ClipboardPolicyAction actionValue = ResolveClipboardAction(ClipboardOperationKind::Enum);
        if (actionValue == ClipboardPolicyAction::Block)
        {
            ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"IsClipboardFormatAvailable", formatValue, nullptr, actionValue, true, ClipboardReturnBits(static_cast<BOOL>(FALSE)), false, 0, false, 0);
            ::SetLastError(entryError);
            return FALSE;
        }

        ::SetLastError(entryError);
        const auto callClock = BeginClipboardCall();
        const BOOL resultValue = g_isClipboardFormatAvailableOriginal(formatValue);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"IsClipboardFormatAvailable", formatValue, nullptr, actionValue, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, resultValue != FALSE, 0);
        ::SetLastError(lastError);
        return resultValue;
    }

    // HookedGetPriorityClipboardFormat 作用：按优先级列表选一个当前可用格式，
    // 命中 BLOCK 时返回 0（公开语义："列表里一个都不可用"）。
    int WINAPI HookedGetPriorityClipboardFormat(UINT* const formatPriorityList, const int formatCount)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_getPriorityClipboardFormatOriginal(formatPriorityList, formatCount);
        }

        const DWORD entryError = ::GetLastError();
        const ClipboardPolicyAction actionValue = ResolveClipboardAction(ClipboardOperationKind::Enum);
        if (actionValue == ClipboardPolicyAction::Block)
        {
            ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"GetPriorityClipboardFormat", 0, nullptr, actionValue, true, ClipboardReturnBits(static_cast<int>(0)), false, 0, false, 0);
            ::SetLastError(entryError);
            return 0;
        }

        ::SetLastError(entryError);
        const auto callClock = BeginClipboardCall();
        const int resultValue = g_getPriorityClipboardFormatOriginal(formatPriorityList, formatCount);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Enum, L"User32", L"GetPriorityClipboardFormat", 0, nullptr, actionValue, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, true, 0);
        ::SetLastError(lastError);
        return resultValue;
    }

    // HookedOleGetClipboard 作用：
    // - 处理：和 OpenClipboard 同理，本身不搬运数据，只是拿到一个可以查询/读取
    //   剪贴板内容的 IDataObject 接口，因此不在这里拦截、只记录；
    //   真正的读发生在返回对象的 GetData/QueryGetData/EnumFormatEtc 调用上，
    //   所以这里成功后要给返回对象打虚表补丁。
    HRESULT WINAPI HookedOleGetClipboard(IDataObject** const dataObjectOut)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_oleGetClipboardOriginal(dataObjectOut);
        }

        const auto callClock = BeginClipboardCall();
        const HRESULT resultValue = g_oleGetClipboardOriginal(dataObjectOut);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        if (SUCCEEDED(resultValue) && dataObjectOut != nullptr && *dataObjectOut != nullptr)
        {
            InstallClipboardDataObjectVTableHooksIfNeeded(*dataObjectOut);
        }
        ReportClipboardEvent(ClipboardOperationKind::Enum, L"Ole32", L"OleGetClipboard", 0, nullptr, ClipboardPolicyAction::Allow, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, true, static_cast<std::int32_t>(resultValue));
        ::SetLastError(lastError);
        return resultValue;
    }

    // HookedOleSetClipboard 作用：
    // - 处理：调用方把自己的 IDataObject 注册成新的剪贴板内容，这一步本身就是
    //   "写"的完成点（后续读者的 GetData 会回调到调用方对象，不是这里的原函数），
    //   受 clipboardWriteAction 管控，命中 BLOCK 时不调用原函数、直接报访问拒绝。
    HRESULT WINAPI HookedOleSetClipboard(IDataObject* const dataObject)
    {
        if (IsInlineHookInternalBypassActive())
        {
            return g_oleSetClipboardOriginal(dataObject);
        }

        const DWORD entryError = ::GetLastError();
        const ClipboardPolicyAction actionValue = ResolveClipboardAction(ClipboardOperationKind::Write);
        if (actionValue == ClipboardPolicyAction::Block)
        {
            ReportClipboardEvent(ClipboardOperationKind::Write, L"Ole32", L"OleSetClipboard", 0, nullptr, actionValue, true, ClipboardReturnBits(static_cast<HRESULT>(E_ACCESSDENIED)), false, 0, true, static_cast<std::int32_t>(E_ACCESSDENIED));
            ::SetLastError(entryError);
            return E_ACCESSDENIED;
        }

        ::SetLastError(entryError);
        const auto callClock = BeginClipboardCall();
        const HRESULT resultValue = g_oleSetClipboardOriginal(dataObject);
        const auto duration = EndClipboardCall(callClock);
        const DWORD lastError = ::GetLastError();
        ReportClipboardEvent(ClipboardOperationKind::Write, L"Ole32", L"OleSetClipboard", 0, nullptr, actionValue, true, ClipboardReturnBits(resultValue), duration.valid, duration.ticks100ns, true, static_cast<std::int32_t>(resultValue));
        ::SetLastError(lastError);
        return resultValue;
    }
}
