
#include <Windows.h>
#include <Ole2.h>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <cstdio>
namespace apimon {
enum class ClipboardOperationKind {Read,Write,Enum}; enum class ClipboardPolicyAction {Allow,LogOnly,Block};
static ClipboardPolicyAction policy=ClipboardPolicyAction::Allow; static bool observedKnown; static std::int32_t observedStatus; static unsigned long long observedBits;
bool IsInlineHookInternalBypassActive(){return false;}
ClipboardPolicyAction ResolveClipboardAction(ClipboardOperationKind){SetLastError(88); return policy;}
void ReportClipboardEvent(ClipboardOperationKind,const wchar_t*,const wchar_t*,UINT,HANDLE,ClipboardPolicyAction,bool=true,std::uint64_t bits=0,bool=false,std::uint64_t=0,bool known=true,std::int32_t status=0){observedKnown=known; observedStatus=status; observedBits=bits; SetLastError(99);}
void InstallClipboardDataObjectVTableHooksIfNeeded(IDataObject*){SetLastError(90);}
BOOL WINAPI mockOpen(HWND){SetLastError(5);return FALSE;} UINT WINAPI mockEnum(UINT){SetLastError(17);return 0;} BOOL WINAPI mockFormat(UINT){SetLastError(19);return FALSE;} HRESULT WINAPI mockOle(IDataObject**){SetLastError(21);return E_FAIL;}
auto g_openClipboardOriginal=&mockOpen; auto g_enumClipboardFormatsOriginal=&mockEnum; auto g_isClipboardFormatAvailableOriginal=&mockFormat; auto g_oleGetClipboardOriginal=&mockOle;
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
}
int main(){ using namespace apimon;
 SetLastError(11); if(HookedOpenClipboard(nullptr)!=FALSE || GetLastError()!=5 || !observedKnown || observedStatus!=5 || observedBits!=0) return 1;
 SetLastError(11); if(HookedEnumClipboardFormats(0)!=0 || GetLastError()!=17 || observedKnown) return 2;
 SetLastError(11); if(HookedIsClipboardFormatAvailable(1)!=FALSE || GetLastError()!=19 || observedKnown) return 3;
 SetLastError(11); if(HookedOleGetClipboard(nullptr)!=E_FAIL || GetLastError()!=21 || !observedKnown || observedStatus!=E_FAIL) return 4;
 policy=ClipboardPolicyAction::Block; SetLastError(31); if(HookedEnumClipboardFormats(0)!=0 || GetLastError()!=ERROR_ACCESS_DENIED || !observedKnown || observedStatus!=ERROR_ACCESS_DENIED) return 5;
 SetLastError(31); if(HookedIsClipboardFormatAvailable(1)!=FALSE || GetLastError()!=31 || observedKnown) return 6;
 puts("PASS clipboard status, unknown, policy and last error"); return 0; }
