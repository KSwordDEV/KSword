#pragma once

#include "../Win32.h"

#include <string>
#include <vector>
#include <cstdint>

namespace ks::r3::system_tools {

// SystemTimeProperty is one name/value pair. Values are already formatted and
// the view never parses them back.
struct SystemTimeProperty {
    std::wstring name;
    std::wstring value;
};

// SystemTimeInfoSection groups properties under one heading so the rendered
// report stays readable without the view knowing what any of the fields mean.
struct SystemTimeInfoSection {
    std::wstring title;
    std::vector<SystemTimeProperty> properties;
};

// SystemTimeInfoSnapshot is one read-only collection pass.
struct SystemTimeInfoSnapshot {
    struct RegistryValue {std::wstring name;DWORD type=0;std::vector<BYTE> data;};
    SYSTEMTIME localTime{},utcTime{};
    TIME_ZONE_INFORMATION zone{};
    DYNAMIC_TIME_ZONE_INFORMATION dynamicZone{};
    DWORD zoneStatus=TIME_ZONE_ID_INVALID,dynamicZoneStatus=TIME_ZONE_ID_INVALID,zoneError=0,dynamicZoneError=0;
    DWORD calendarValidationError=0;
    bool calendarKnown=false,calendarMalformed=false,biasKnown=false,zoneMalformed=false,bootEstimateKnown=false;
    std::int64_t effectiveBiasMinutes=0;
    std::uint64_t utcFileTime=0,uptimeMs=0,estimatedBootFileTime=0;
    bool parametersOpened=false,parametersAbsent=false,parametersComplete=false,parametersLimited=false,parametersMalformed=false;
    LSTATUS parametersOpenError=0,parametersEnumError=0,parametersCloseError=0;
    std::vector<RegistryValue> parameters;
    bool success = false;
    std::wstring diagnosticText;
    std::vector<SystemTimeInfoSection> sections;
};

// CollectSystemTimeInfo gathers clock, time zone, uptime and W32Time settings.
// There is no input; processing only reads system state and the registry;
// output is a section list ready to render. This page is read-only by design:
// changing the clock or the time source from an audit tool would invalidate
// every timestamp the rest of the product just collected.
SystemTimeInfoSnapshot CollectSystemTimeInfo();

// FormatLiveClockLine renders the one-line header the view refreshes once a
// second. There is no input; output is a single line holding local time, UTC
// time and uptime.
std::wstring FormatLiveClockLine();

// RenderSystemTimeReport flattens a snapshot into the text shown in the pane.
std::wstring RenderSystemTimeReport(const SystemTimeInfoSnapshot& snapshot);

} // namespace ks::r3::system_tools
