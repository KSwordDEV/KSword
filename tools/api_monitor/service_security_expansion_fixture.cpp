#include <windows.h>
#include <bcrypt.h>
#include <objbase.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <type_traits>
namespace ks { namespace winapi_monitor { constexpr unsigned kMaxDetailChars = 1024; enum class EventCategory { Service = 10, Security = 11, Crypto = 12, Com = 13 }; } }
template <class T> std::uint64_t ApiReturnBits(T value) {
    if constexpr (std::is_pointer_v<T>) return reinterpret_cast<std::uintptr_t>(value);
    else return static_cast<std::uint64_t>(value);
}
void AppendWideText(wchar_t (&out)[ks::winapi_monitor::kMaxDetailChars], const wchar_t* text) { wcscat_s(out, text); }
void AppendHexText(wchar_t (&out)[ks::winapi_monitor::kMaxDetailChars], std::uint64_t value) { wchar_t tmp[32]; swprintf_s(tmp, L"%llx", static_cast<unsigned long long>(value)); wcscat_s(out, tmp); }
struct ScopedHookGuard { bool bypass() const { return false; } };
int BeginApiCallClock() { return 1; }
int EndApiCallClock(int) { return 2; }
static int events, lastCategory, lastStatus; static std::uint64_t lastReturn;
void SendRawEventWithMetrics(ks::winapi_monitor::EventCategory category, const wchar_t*, const wchar_t*, int status, const wchar_t*, bool hasReturn, std::uint64_t value, int duration) {
    ++events; lastCategory = static_cast<int>(category); lastStatus = status; lastReturn = value;
    if (!hasReturn || duration != 2) events = -100; SetLastError(0x1111);
}
#include "APIMonitor_x64/hook/ApiServiceSecurityCaptureFormatters.inc"
static decltype(&::CoCreateGuid) g_coCreateGuidOriginal = ::CoCreateGuid;
static decltype(&::CopySid) g_copySidOriginal = ::CopySid;
static decltype(&::BCryptGetProperty) g_bCryptGetPropertyOriginal = ::BCryptGetProperty;
// GENERATED_WRAPPERS
int main() {
    GUID guid{}; SetLastError(0x2468); HRESULT h = HookedCoCreateGuid(&guid);
    if (FAILED(h) || GetLastError()!=0x2468 || events!=1 || lastCategory!=13 || lastStatus!=h || lastReturn!=ApiReturnBits(h)) return 1;
    SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY; BYTE source[SECURITY_MAX_SID_SIZE]{}, dest[SECURITY_MAX_SID_SIZE]{};
    if (!InitializeSid(source, &authority, 1)) return 2;
    SetLastError(0x2468); BOOL b = HookedCopySid(sizeof(dest), dest, source);
    if (!b || GetLastError()!=0x2468 || events!=2 || lastCategory!=11 || lastStatus!=0 || lastReturn!=ApiReturnBits(b) || !EqualSid(source,dest)) return 3;
    SetLastError(0x2468); b = HookedCopySid(0, dest, source); DWORD error=GetLastError();
    if (b || error!=ERROR_INSUFFICIENT_BUFFER || events!=3 || lastStatus!=error || lastReturn!=0) return 4;
    BCRYPT_ALG_HANDLE alg{}; if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0)<0) return 5;
    ULONG length=0, needed=0; SetLastError(0x2468);
    NTSTATUS status=HookedBCryptGetProperty(alg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&length), sizeof(length), &needed, 0);
    if (status<0 || GetLastError()!=0x2468 || length!=32 || needed!=sizeof(length) || events!=4 || lastCategory!=12 || lastStatus!=status || lastReturn!=ApiReturnBits(status)) return 6;
    BCryptCloseAlgorithmProvider(alg,0); return 0;
}
