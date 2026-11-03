
#include <winsock2.h>
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <memory>
struct ScopedHookGuard{bool bypass(){return false;}};
namespace ks::winapi_monitor { constexpr int kMaxDetailChars=320; enum class EventCategory{Network}; }
struct Op{}; using IoToken=std::shared_ptr<Op>; IoToken BeginIo(SOCKET,LPWSAOVERLAPPED,const wchar_t*,const wchar_t*,ks::winapi_monitor::EventCategory,std::uint64_t,bool){return std::make_shared<Op>();}
std::uint64_t SumWsaBufferLength(LPWSABUF,DWORD){return 8;} void* PrepareIoCallback(IoToken,void*,LPWSAOVERLAPPED_COMPLETION_ROUTINE){return nullptr;}
int mode=0; bool observedBytesKnown=true, observedFlagsKnown=true; DWORD bytesSeen=99; bool finishKnown=true;
int WSAAPI mockRecv(SOCKET,LPWSABUF,DWORD,LPDWORD bytes,LPDWORD flags,LPWSAOVERLAPPED ov,LPWSAOVERLAPPED_COMPLETION_ROUTINE){
 if(mode==0){WSASetLastError(WSA_IO_PENDING);return SOCKET_ERROR;}
 if(mode==1){WSASetLastError(777);return 0;}
 if(ov)return 9; *bytes=55;*flags=7;WSASetLastError(777);return 0;
}
auto g_wsaRecvOriginal=&mockRecv;
int BeginApiCallClock(){return 0;} int EndApiCallClock(int){return 0;}
template<class T> bool TrySafeIoValue(const T* v,T* out){if(!v||!out)return false;__try{*out=*v;return true;}__except(EXCEPTION_EXECUTE_HANDLER){return false;}}
template<class T> std::uint64_t ApiReturnBits(T v){return static_cast<std::uint64_t>(v);}
void FinishIo(IoToken,bool,bool,DWORD,DWORD bytes,bool known){bytesSeen=bytes;finishKnown=known;}
template<std::size_t N> void BuildSocketDetail(wchar_t (&)[N],const wchar_t*,SOCKET,std::uint64_t,long long,DWORD,const sockaddr*,int,bool known,bool flagsKnown){observedBytesKnown=known;observedFlagsKnown=flagsKnown;}
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory,const wchar_t*,const wchar_t*,int,const wchar_t*,bool,std::uint64_t,int){WSASetLastError(999);}
        int WSAAPI HookedWSARecv(SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesReceivedPointer, LPDWORD flagsPointer, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_wsaRecvOriginal(socketValue, buffersPointer, bufferCount, bytesReceivedPointer, flagsPointer, overlappedPointer, completionRoutinePointer);
            }

            const DWORD incomingWin32 = ::GetLastError();
            const int incomingWsa = ::WSAGetLastError();
            const std::uint64_t requestLength = SumWsaBufferLength(buffersPointer, bufferCount);
            auto operation = BeginIo(socketValue, overlappedPointer, L"Ws2_32", L"WSARecv",
                ks::winapi_monitor::EventCategory::Network, requestLength, completionRoutinePointer != nullptr);
            auto replacement = reinterpret_cast<LPWSAOVERLAPPED_COMPLETION_ROUTINE>(PrepareIoCallback(operation, nullptr, completionRoutinePointer));
            if (completionRoutinePointer && !replacement) operation.reset();
            ::WSASetLastError(incomingWsa); ::SetLastError(incomingWin32);
            const auto callClock = BeginApiCallClock();
            const int resultValue = g_wsaRecvOriginal(socketValue, buffersPointer, bufferCount, bytesReceivedPointer, flagsPointer, overlappedPointer, replacement ? replacement : completionRoutinePointer);
            const auto duration = EndApiCallClock(callClock);
            const int savedWsa = ::WSAGetLastError();
            const DWORD savedWin32 = ::GetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            DWORD receivedValue = 0, flagsValue = 0;
            const bool receivedKnown = resultValue == 0 && !overlappedPointer && TrySafeIoValue(bytesReceivedPointer, &receivedValue);
            const bool flagsKnown = resultValue == 0 && !overlappedPointer && TrySafeIoValue(flagsPointer, &flagsValue);
            FinishIo(operation, resultValue == 0 || errorValue == WSA_IO_PENDING,
                resultValue != 0 && errorValue == WSA_IO_PENDING, errorValue, receivedValue, receivedKnown);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"recv", socketValue, requestLength, receivedValue, flagsValue, nullptr, 0, receivedKnown, flagsKnown);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"WSARecv",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }
int main(){OVERLAPPED ov{}; auto poison=reinterpret_cast<DWORD*>(1);
 mode=0; if(HookedWSARecv(0,nullptr,0,poison,poison,&ov,nullptr)!=SOCKET_ERROR || WSAGetLastError()!=WSA_IO_PENDING || observedBytesKnown || observedFlagsKnown || finishKnown) return 1;
 mode=1; if(HookedWSARecv(0,nullptr,0,poison,poison,&ov,nullptr)!=0 || observedBytesKnown || observedFlagsKnown || finishKnown) return 2;
 mode=2; DWORD bytes=0,flags=0; if(HookedWSARecv(0,nullptr,0,&bytes,&flags,nullptr,nullptr)!=0 || !observedBytesKnown || !observedFlagsKnown || !finishKnown || bytesSeen!=55) return 3;
 puts("PASS pending/overlapped poison pointers not read; synchronous outputs known");return 0;}
