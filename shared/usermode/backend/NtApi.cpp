#include "NtApi.h"

#include <winternl.h>

namespace ks::r3::common {
namespace {
constexpr LONG kStatusSuccess = 0x00000000L;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr LONG kStatusProcedureNotFound = static_cast<LONG>(0xC000007AUL);
} // namespace

NtApi::NtApi() : querySystemInformation_(nullptr) {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    if (ntdll) {
        querySystemInformation_ = reinterpret_cast<NtQuerySystemInformationFn>(::GetProcAddress(ntdll, "NtQuerySystemInformation"));
    }
}

bool NtApi::available() const {
    return querySystemInformation_ != nullptr;
}

LONG NtApi::querySystemInformation(SystemInformationClass infoClass, void* buffer, ULONG bufferSize, ULONG* returnLength) const {
    if (!querySystemInformation_) {
        return kStatusProcedureNotFound;
    }
    return querySystemInformation_(static_cast<ULONG>(infoClass), buffer, bufferSize, returnLength);
}

std::vector<std::byte> QueryRawSystemInformation(SystemInformationClass infoClass) {
    NtApi api;
    if (!api.available()) {
        return {};
    }

    ULONG size = 1u << 20;
    for (int attempt = 0; attempt < 8; ++attempt) {
        std::vector<std::byte> buffer(size);
        ULONG needed = 0;
        const LONG status = api.querySystemInformation(infoClass, buffer.data(), size, &needed);
        if (status == kStatusSuccess) {
            return buffer;
        }
        if (status != kStatusInfoLengthMismatch && status != kStatusBufferTooSmall) {
            return {};
        }
        size = needed > size ? needed + 0x10000 : size * 2;
    }
    return {};
}

} // namespace ks::r3::common
