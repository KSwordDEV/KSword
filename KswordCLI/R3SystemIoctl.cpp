#include "CommandRegistry.h"
#include "../shared/usermode/backend/system/IoctlDecoder.h"
#include <stdexcept>
namespace ks::cli {
namespace {
Result decode(const Args& a){const auto code=a.u32(L"--code");(void)a.require(L"--code");const auto fields=ks::r3::system_tools::DecodeIoctlCode(ks::r3::system_tools::FormatIoctlCode(code));
    if(fields.state!=ks::r3::system_tools::IoctlDecodeState::Valid)return {4,Json::object({}),{L"Shared CTL_CODE decoder rejected a normalized uint32 value."}};
    return {0,Json::object({{L"source",Json::string(L"shared static CTL_CODE bit projection; no device or driver query")},
        {L"code",Json::hex(fields.code)},{L"normalizedCode",Json::string(ks::r3::system_tools::FormatIoctlCode(fields.code))},{L"codeDecimal",Json::number(fields.code)},
        {L"deviceType",Json::hex(fields.deviceType)},{L"function",Json::hex(fields.function)},{L"access",Json::number(fields.access)},
        {L"accessName",Json::string(ks::r3::system_tools::IoctlAccessName(fields.access))},{L"method",Json::number(fields.method)},
        {L"methodName",Json::string(ks::r3::system_tools::IoctlMethodName(fields.method))},{L"common",Json::boolean(fields.common)},{L"custom",Json::boolean(fields.custom)}}),
        {L"Static numeric decode only: does not identify a driver, prove IOCTL registration/support, validate a buffer ABI, or execute DeviceIoControl. Numeric input follows CLI decimal or 0x hexadecimal rules; all uint32 values (including zero) can be decoded."}};
}
}
void registerSystemIoctl(){
    addCommand({L"system ioctl decode",L"KswordCLI.exe system ioctl decode --code N [--backend r3] [--json]",L"Decode CTL_CODE fields without opening any device.",
        L"Required: --code uint32 (decimal or 0x hexadecimal). Optional: --backend r3, --json.",
        L"Output: code (hex), normalizedCode (8 uppercase hex digits), codeDecimal (uint32), deviceType (16 bits)/function (12 bits) hex, access/method (2 bits) and standard macro names, common (bit 31) and custom (bit 13). Bits can indicate vendor ranges but do not establish actual driver support or request safety. Zero and all uint32 bit patterns are valid decode inputs. No device handle, registry, IOCTL transmission or R0 fallback; help performs no decode or device access.",decode});
}
}
