#include "EtwFilterModel.h"

namespace ks::r3::monitor {
namespace {

GUID MakeGuid(
    const unsigned long data1,
    const unsigned short data2,
    const unsigned short data3,
    const unsigned char b0,
    const unsigned char b1,
    const unsigned char b2,
    const unsigned char b3,
    const unsigned char b4,
    const unsigned char b5,
    const unsigned char b6,
    const unsigned char b7) {
    GUID guid{};
    guid.Data1 = data1;
    guid.Data2 = data2;
    guid.Data3 = data3;
    guid.Data4[0] = b0;
    guid.Data4[1] = b1;
    guid.Data4[2] = b2;
    guid.Data4[3] = b3;
    guid.Data4[4] = b4;
    guid.Data4[5] = b5;
    guid.Data4[6] = b6;
    guid.Data4[7] = b7;
    return guid;
}

// Provider creates one default ETW provider preset. Inputs are the provider
// name, GUID parts, whether it is enabled by default, ETW level and keyword
// mask. Processing keeps the large built-in provider list readable and avoids
// repeating the field order at every call site; output is one preset row for
// the filter dialog and session controller.
EtwProviderPreset Provider(
    const wchar_t* name,
    const unsigned long data1,
    const unsigned short data2,
    const unsigned short data3,
    const unsigned char b0,
    const unsigned char b1,
    const unsigned char b2,
    const unsigned char b3,
    const unsigned char b4,
    const unsigned char b5,
    const unsigned char b6,
    const unsigned char b7,
    const bool enabledByDefault = true,
    const UCHAR level = TRACE_LEVEL_INFORMATION,
    const std::uint64_t keywords = 0) {
    EtwProviderPreset preset;
    preset.name = name;
    preset.providerGuid = MakeGuid(data1, data2, data3, b0, b1, b2, b3, b4, b5, b6, b7);
    preset.enabled = enabledByDefault;
    preset.level = level;
    preset.matchAnyKeyword = keywords;
    return preset;
}

std::vector<EtwProviderPreset> DefaultProviders() {
    // Keep only retained Microsoft-Windows-Kernel* providers in the default ETW
    // filter list. KswordARKLight intentionally removes the original network
    // feature set, so those ETW sources are not added here.
    return {
        Provider(L"Microsoft-Windows-Kernel-Acpi", 0xC514638F, 0x7723, 0x485B, 0xBC, 0xFC, 0x96, 0x56, 0x5D, 0x73, 0x5D, 0x4A, false),
        Provider(L"Microsoft-Windows-Kernel-AppCompat", 0x16A1ADC1, 0x9B7F, 0x4CD9, 0x94, 0xB3, 0xD8, 0x29, 0x6A, 0xB1, 0xB1, 0x30, false),
        Provider(L"Microsoft-Windows-Kernel-Audit-API-Calls", 0xE02A841C, 0x75A3, 0x4FA7, 0xAF, 0xC8, 0xAE, 0x09, 0xCF, 0x9B, 0x7F, 0x23, false),
        Provider(L"Microsoft-Windows-Kernel-Boot", 0x15CA44FF, 0x4D7A, 0x4BAA, 0xBB, 0xA5, 0x09, 0x98, 0x95, 0x5E, 0x53, 0x1E, false),
        Provider(L"Microsoft-Windows-Kernel-BootDiagnostics", 0x96AC7637, 0x5950, 0x4A30, 0xB8, 0xF7, 0xE0, 0x7E, 0x8E, 0x57, 0x34, 0xC1, false),
        Provider(L"Microsoft-Windows-Kernel-Disk", 0xC7BDE69A, 0xE1E0, 0x4177, 0xB6, 0xEF, 0x28, 0x3A, 0xD1, 0x52, 0x52, 0x71),
        Provider(L"Microsoft-Windows-Kernel-EventTracing", 0xB675EC37, 0xBDB6, 0x4648, 0xBC, 0x92, 0xF3, 0xFD, 0xC7, 0x4D, 0x3C, 0xA2, false),
        Provider(L"Microsoft-Windows-Kernel-File", 0xEDD08927, 0x9CC4, 0x4E65, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89),
        Provider(L"Microsoft-Windows-Kernel-General", 0xA68CA8B7, 0x004F, 0xD7B6, 0xA6, 0x98, 0x07, 0xE2, 0xDE, 0x0F, 0x1F, 0x5D),
        Provider(L"Microsoft-Windows-Kernel-Interrupt-Steering", 0x951B41EA, 0xC830, 0x44DC, 0xA6, 0x71, 0xE2, 0xC9, 0x95, 0x88, 0x09, 0xB8, false),
        Provider(L"Microsoft-Windows-Kernel-IO", 0xABF1F586, 0x2E50, 0x4BA8, 0x92, 0x8D, 0x49, 0x04, 0x4E, 0x6F, 0x0D, 0xB7),
        Provider(L"Microsoft-Windows-Kernel-IoTrace", 0xA103CABD, 0x8242, 0x4A93, 0x8D, 0xF5, 0x1C, 0xDF, 0x3B, 0x3F, 0x26, 0xA6, false),
        Provider(L"Microsoft-Windows-Kernel-Licensing-StartServiceTrigger", 0xF5528ADA, 0xBE5F, 0x4F14, 0x8A, 0xEF, 0xA9, 0x5D, 0xE7, 0x28, 0x11, 0x61, false),
        Provider(L"Microsoft-Windows-Kernel-LicensingSqm", 0xA0AF438F, 0x4431, 0x41CB, 0xA6, 0x75, 0xA2, 0x65, 0x05, 0x0E, 0xE9, 0x47, false),
        Provider(L"Microsoft-Windows-Kernel-LiveDump", 0xBEF2AA8E, 0x81CD, 0x11E2, 0xA7, 0xBB, 0x5E, 0xAC, 0x61, 0x88, 0x70, 0x9B, false),
        Provider(L"Microsoft-Windows-Kernel-Memory", 0xD1D93EF7, 0xE1F2, 0x4F45, 0x99, 0x43, 0x03, 0xD2, 0x45, 0xFE, 0x6C, 0x00),
        Provider(L"Microsoft-Windows-Kernel-Pep", 0x5412704E, 0xB2E1, 0x4624, 0x8F, 0xFD, 0x55, 0x77, 0x7B, 0x8F, 0x73, 0x73, false),
        Provider(L"Microsoft-Windows-Kernel-PnP", 0x9C205A39, 0x1250, 0x487D, 0xAB, 0xD7, 0xE8, 0x31, 0xC6, 0x29, 0x05, 0x39),
        Provider(L"Microsoft-Windows-Kernel-PnP-Rundown", 0xB3A0C2C8, 0x83BB, 0x4DDF, 0x9F, 0x8D, 0x4B, 0x22, 0xD3, 0xC3, 0x8A, 0xD7, false),
        Provider(L"Microsoft-Windows-Kernel-Power", 0x331C3B3A, 0x2005, 0x44C2, 0xAC, 0x5E, 0x77, 0x22, 0x0C, 0x37, 0xD6, 0xB4),
        Provider(L"Microsoft-Windows-Kernel-PowerTrigger", 0xAA1F73E8, 0x15FD, 0x45D2, 0xAB, 0xFD, 0xE7, 0xF6, 0x4F, 0x78, 0xEB, 0x11, false),
        Provider(L"Microsoft-Windows-Kernel-Prefetch", 0x5322D61A, 0x9EFA, 0x4BC3, 0xA3, 0xF9, 0x14, 0xBE, 0x95, 0xC1, 0x44, 0xF8, false),
        Provider(L"Microsoft-Windows-Kernel-Process", 0x22FB2CD6, 0x0E7B, 0x422B, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16),
        Provider(L"Microsoft-Windows-Kernel-Processor-Power", 0x0F67E49F, 0xFE51, 0x4E9F, 0xB4, 0x90, 0x6F, 0x29, 0x48, 0xCC, 0x60, 0x27, false),
        Provider(L"Microsoft-Windows-Kernel-Registry", 0x70EB4F03, 0xC1DE, 0x4F73, 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD),
        Provider(L"Microsoft-Windows-Kernel-ShimEngine", 0x0BF2FB94, 0x7B60, 0x4B4D, 0x97, 0x66, 0xE8, 0x2F, 0x65, 0x8D, 0xF5, 0x40, false),
        Provider(L"Microsoft-Windows-Kernel-StoreMgr", 0xA6AD76E3, 0x867A, 0x4635, 0x91, 0xB3, 0x49, 0x04, 0xBA, 0x63, 0x74, 0xD7, false),
        Provider(L"Microsoft-Windows-Kernel-Tm", 0x4CEC9C95, 0xA65F, 0x4591, 0xB5, 0xC4, 0x30, 0x10, 0x0E, 0x51, 0xD8, 0x70, false),
        Provider(L"Microsoft-Windows-Kernel-Tm-Trigger", 0xCE20D1C3, 0xA247, 0x4C41, 0xBC, 0xB8, 0x3C, 0x7F, 0x52, 0xC8, 0xB8, 0x05, false),
        Provider(L"Microsoft-Windows-Kernel-WDI", 0x2FF3E6B7, 0xCB90, 0x4700, 0x96, 0x21, 0x44, 0x3F, 0x38, 0x97, 0x34, 0xED, false),
        Provider(L"Microsoft-Windows-Kernel-WHEA", 0x7B563579, 0x53C8, 0x44E7, 0x82, 0x36, 0x0F, 0x87, 0xB9, 0xFE, 0x65, 0x94, false),
        Provider(L"Microsoft-Windows-Kernel-WSService-StartServiceTrigger", 0x3635D4B6, 0x77E3, 0x4375, 0x81, 0x24, 0xD5, 0x45, 0xB7, 0x14, 0x93, 0x37, false),
        Provider(L"Microsoft-Windows-Kernel-XDV", 0xF029AC39, 0x38F0, 0x4A40, 0xB7, 0xDE, 0x40, 0x4D, 0x24, 0x40, 0x04, 0xCB, false),
        Provider(L"Microsoft-Windows-KernelStreaming", 0x548C4417, 0xCE45, 0x41FF, 0x99, 0xDD, 0x52, 0x8F, 0x01, 0xCE, 0x0F, 0xE1, false)
    };
}

} // namespace

EtwFilterModel::EtwFilterModel() {
    resetDefaults();
}

EtwFilterState EtwFilterModel::state() const {
    return state_;
}

void EtwFilterModel::setState(const EtwFilterState& state) {
    state_ = state;
}

void EtwFilterModel::resetDefaults() {
    state_ = EtwFilterState{};
    state_.providers = DefaultProviders();
    state_.processId = 0;
    state_.minimumLevel = TRACE_LEVEL_VERBOSE;
    state_.onlyCurrentProcess = false;
}

bool EventMatchesFilter(
    const std::uint32_t processId,
    const std::uint8_t level,
    const EtwFilterState& state) {
    if (state.onlyCurrentProcess && processId != ::GetCurrentProcessId()) {
        return false;
    }
    if (state.processId != 0 && processId != state.processId) {
        return false;
    }
    if (state.minimumLevel != 0 && level > state.minimumLevel) {
        return false;
    }
    return true;
}

} // namespace ks::r3::monitor
