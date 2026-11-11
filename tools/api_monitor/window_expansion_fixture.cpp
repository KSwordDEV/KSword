#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <type_traits>
namespace ks { namespace winapi_monitor { constexpr unsigned kMaxDetailChars = 1024; enum class EventCategory { Window = 14 }; enum class EventResultKind { StatusCode, StatusUnknown }; } }
template <class T> std::uint64_t ApiReturnBits(T value) {
    if constexpr (std::is_pointer_v<T>) return reinterpret_cast<std::uintptr_t>(value);
    else return static_cast<std::uint64_t>(value);
}
void AppendWideText(wchar_t (&out)[ks::winapi_monitor::kMaxDetailChars], const wchar_t* text) { wcscat_s(out, text); }
void AppendHexText(wchar_t (&out)[ks::winapi_monitor::kMaxDetailChars], std::uint64_t value) {
    wchar_t tmp[32]; swprintf_s(tmp, L"%llx", static_cast<unsigned long long>(value)); wcscat_s(out, tmp);
}
struct ScopedHookGuard { bool bypass() const { return false; } };
int BeginApiCallClock() { return 1; }
int EndApiCallClock(int) { return 2; }
static int events = 0; static int lastCategory = 0; static std::uint64_t lastReturn = 0; static bool hadDuration = false;
static int lastStatus = -1; static std::uint32_t lastApiId = 1; static std::uint64_t lastOperationId = 1;
static ks::winapi_monitor::EventResultKind lastKind = ks::winapi_monitor::EventResultKind::StatusCode;
static wchar_t lastDetail[ks::winapi_monitor::kMaxDetailChars] = {};
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory category, const wchar_t*, const wchar_t*, int status, const wchar_t* detail, bool hasReturn, std::uint64_t value, int duration, std::uint32_t apiId = 0, std::uint64_t operationId = 0, ks::winapi_monitor::EventResultKind resultKind = ks::winapi_monitor::EventResultKind::StatusCode) {
    ++events; lastCategory = static_cast<int>(category); lastReturn = value; hadDuration = hasReturn && duration == 2;
    lastStatus = status; lastApiId = apiId; lastOperationId = operationId; lastKind = resultKind; wcscpy_s(lastDetail, detail); SetLastError(0x1111);
}
#include "APIMonitor_x64/hook/ApiWindowCaptureFormatters.inc"
static decltype(&::GetWindowRect) g_getWindowRectOriginal = ::GetWindowRect;
static decltype(&::SetWindowTextW) g_setWindowTextWOriginal = ::SetWindowTextW;
static BOOL WINAPI FakeClientToScreen(HWND, LPPOINT) { return FALSE; }
static decltype(&::ClientToScreen) g_clientToScreenOriginal = FakeClientToScreen;
// GENERATED_WRAPPERS
int main() {
    HWND window = CreateWindowExW(0, L"STATIC", L"fixture", 0, 0, 0, 40, 40, nullptr, nullptr, GetModuleHandleW(nullptr), nullptr);
    if (!window) return 1;
    RECT directRect{}, hookedRect{};
    SetLastError(0x2468); BOOL direct = GetWindowRect(window, &directRect); DWORD directError = GetLastError();
    SetLastError(0x2468); BOOL hooked = HookedGetWindowRect(window, &hookedRect); DWORD hookedError = GetLastError();
    if (direct != hooked || directError != hookedError || memcmp(&directRect, &hookedRect, sizeof(RECT)) || events != 1 || lastCategory != 14 || lastReturn != ApiReturnBits(hooked) || !hadDuration) return 2;
    HWND invalid = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(1));
    SetLastError(0x2468); direct = GetWindowRect(invalid, &directRect); directError = GetLastError();
    SetLastError(0x2468); hooked = HookedGetWindowRect(invalid, &hookedRect); hookedError = GetLastError();
    if (direct != hooked || directError != hookedError || events != 2 || lastReturn != ApiReturnBits(hooked)) return 3;
    SetLastError(0x2468); direct = SetWindowTextW(window, L"fixture"); directError = GetLastError();
    SetLastError(0x2468); hooked = HookedSetWindowTextW(window, L"fixture"); hookedError = GetLastError();
    if (direct != hooked || directError != hookedError || events != 3 || lastReturn != ApiReturnBits(hooked)) return 4;
    POINT point{11, 22};
    SetLastError(0x2468); hooked = HookedClientToScreen(window, &point); hookedError = GetLastError();
    if (hooked != FALSE || hookedError != 0x2468 || point.x != 11 || point.y != 22 || events != 4 || lastCategory != 14 || lastReturn != 0 || !hadDuration || lastStatus != 0 || lastApiId != 0 || lastOperationId != 0 || lastKind != ks::winapi_monitor::EventResultKind::StatusUnknown || !wcsstr(lastDetail, L"call_failed=1 error=unavailable")) return 5;
    DestroyWindow(window); return 0;
}
