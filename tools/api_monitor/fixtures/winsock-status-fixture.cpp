
#include <winsock2.h>
#include <Windows.h>
#include <cstdint>
#include <cstdio>
struct ScopedHookGuard { bool bypass(){return false;} };
namespace ks::winapi_monitor { constexpr int kMaxDetailChars=320; enum class EventCategory{Network}; }
int mode=0, statusSeen=0;
int WSAAPI mockSend(SOCKET,const char*,int,int){WSASetLastError(777);return mode ? SOCKET_ERROR : 4;}
auto g_sendOriginal=&mockSend;
int BeginApiCallClock(){return 0;} int EndApiCallClock(int){return 0;}
template<class T> std::uint64_t ApiReturnBits(T v){return static_cast<std::uint64_t>(v);}
template<std::size_t N> void BuildSocketDetail(wchar_t (&)[N],const wchar_t*,SOCKET,std::uint64_t,int,DWORD){WSASetLastError(111);}
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,int status,const wchar_t*,bool,std::uint64_t,int){statusSeen=status; WSASetLastError(999);}
        int WSAAPI HookedSend(SOCKET socketValue, const char* bufferPointer, int bufferLength, int flagsValue)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_sendOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_sendOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue >= 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"send", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), resultValue, static_cast<DWORD>(flagsValue));
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"send",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }
int main(){ mode=0; WSASetLastError(42); if(HookedSend(0,nullptr,4,0)!=4||WSAGetLastError()!=777||GetLastError()!=777||statusSeen!=0)return 1;
 mode=1; WSASetLastError(42); if(HookedSend(0,nullptr,4,0)!=SOCKET_ERROR||WSAGetLastError()!=777||GetLastError()!=777||statusSeen!=777)return 2;
 puts("PASS Winsock success/failure status and error restoration");return 0;}
