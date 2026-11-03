#include <Windows.h>
#include <cstdint>
#include <cstdio>
struct ScopedHookGuard { bool bypass(){return false;} };
namespace ks::winapi_monitor { enum class EventCategory{Process}; }
void WINAPI mock(){SetLastError(777);}
auto g_coUninitializeOriginal=&mock;
int BeginApiCallClock(){return 0;} int EndApiCallClock(int){SetLastError(888);return 0;}
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,int,const wchar_t*,bool,std::uint64_t,int){SetLastError(999);}
        void WINAPI HookedCoUninitialize()
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { g_coUninitializeOriginal(); return; }
            const auto callClock = BeginApiCallClock();
            g_coUninitializeOriginal();
            const DWORD savedError = ::GetLastError();
            const auto duration = EndApiCallClock(callClock);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Ole32", L"CoUninitialize", 0, L"", false, 0, duration);
            ::SetLastError(savedError);
        }int main(){SetLastError(123);HookedCoUninitialize();if(GetLastError()!=777)return 1;puts("PASS CoUninitialize restores last error");return 0;}
