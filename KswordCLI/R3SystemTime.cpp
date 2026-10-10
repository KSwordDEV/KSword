#include "CommandRegistry.h"
#include "../shared/usermode/backend/system/SystemTimeInfo.h"
#include <algorithm>
#include <cstring>
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::system_tools;
Json calendar(const SYSTEMTIME& t){return Json::object({{L"year",Json::number(t.wYear)},{L"month",Json::number(t.wMonth)},{L"day",Json::number(t.wDay)},
    {L"dayOfWeek",Json::number(t.wDayOfWeek)},{L"hour",Json::number(t.wHour)},{L"minute",Json::number(t.wMinute)},{L"second",Json::number(t.wSecond)},{L"millisecond",Json::number(t.wMilliseconds)}});}
template<std::size_t N> Json name(const wchar_t (&text)[N],bool available,bool& malformed){if(!available)return {};const auto end=std::find(text,text+N,L'\0');if(end==text+N){malformed=true;return {};}return Json::string(std::wstring(text,end));}
Result query(const Args& a){const auto maxBytes=a.u32(L"--max-data-bytes",256);if(!maxBytes||maxBytes>65536)throw std::invalid_argument("--max-data-bytes must be 1..65536");
    const auto snapshot=b::CollectSystemTimeInfo();bool malformed=snapshot.calendarMalformed||snapshot.zoneMalformed||snapshot.parametersMalformed;
    const bool zoneKnown=snapshot.zoneStatus<=TIME_ZONE_ID_DAYLIGHT,dynamicKnown=snapshot.dynamicZoneStatus<=TIME_ZONE_ID_DAYLIGHT;
    bool partial=!zoneKnown||!dynamicKnown||!snapshot.biasKnown||!snapshot.bootEstimateKnown||!snapshot.parametersOpened||!snapshot.parametersComplete||snapshot.parametersLimited||snapshot.parametersCloseError!=ERROR_SUCCESS;
    const auto standardName=name(snapshot.zone.StandardName,zoneKnown,malformed),daylightName=name(snapshot.zone.DaylightName,zoneKnown,malformed),keyName=name(snapshot.dynamicZone.TimeZoneKeyName,dynamicKnown,malformed);
    std::vector<Json> rows,displaySections;for(const auto& value:snapshot.parameters){Json number;bool dataMalformed=false;
        if(value.type==REG_DWORD){if(value.data.size()!=sizeof(DWORD))dataMalformed=true;else{DWORD n=0;std::memcpy(&n,value.data.data(),sizeof(n));number=Json::number(n);}}
        if(value.type==REG_QWORD){if(value.data.size()!=sizeof(std::uint64_t))dataMalformed=true;else{std::uint64_t n=0;std::memcpy(&n,value.data.data(),sizeof(n));number=Json::count(n);}}
        if(value.type==REG_SZ||value.type==REG_EXPAND_SZ||value.type==REG_MULTI_SZ){if(value.data.size()<sizeof(wchar_t)||value.data.size()%sizeof(wchar_t))dataMalformed=true;
            else{std::wstring text(value.data.size()/sizeof(wchar_t),L'\0');std::memcpy(text.data(),value.data.data(),value.data.size());
                if(value.type==REG_MULTI_SZ){if(!(text.size()==1&&text[0]==L'\0')&&(text.size()<2||text[text.size()-1]!=L'\0'||text[text.size()-2]!=L'\0'))dataMalformed=true;}
                else if(std::find(text.begin(),text.end(),L'\0')==text.end())dataMalformed=true;}}
        malformed=malformed||dataMalformed;partial=partial||value.data.size()>maxBytes;
        rows.push_back(Json::object({{L"name",Json::string(value.name)},{L"registryType",Json::number(value.type)},{L"byteCount",Json::count(value.data.size())},
            {L"dataHex",Json::bytes(value.data,maxBytes)},{L"dataTruncated",Json::boolean(value.data.size()>maxBytes)},{L"dataMalformed",Json::boolean(dataMalformed)},
            {L"numericValue",number}}));}
    for(const auto& section:snapshot.sections){std::vector<Json> properties;for(const auto& p:section.properties)properties.push_back(Json::object({{L"nameDisplay",Json::string(p.name)},{L"valueDisplay",Json::string(p.value.substr(0,256))},{L"displayTruncated",Json::boolean(p.value.size()>256)}}));
        displaySections.push_back(Json::object({{L"titleDisplay",Json::string(section.title)},{L"properties",Json::array(properties)}}));}
    return {malformed?4:!snapshot.success?3:partial?6:0,Json::object({{L"source",Json::string(L"Win32 clock/time-zone/tick APIs + HKLM W32Time Parameters")},
        {L"clock",Json::object({{L"calendarKnown",Json::boolean(snapshot.calendarKnown)},{L"utcFileTime",Json::count(snapshot.utcFileTime)},
            {L"calendarValidationWin32Error",snapshot.calendarValidationError?Json::number(snapshot.calendarValidationError):Json{}},{L"utcRaw",calendar(snapshot.utcTime)},{L"localRaw",calendar(snapshot.localTime)},
            {L"utc",snapshot.calendarKnown?calendar(snapshot.utcTime):Json{}},{L"local",snapshot.calendarKnown?calendar(snapshot.localTime):Json{}},{L"atomicSnapshot",Json::boolean(false)}})},
        {L"zone",Json::object({{L"available",Json::boolean(zoneKnown)},{L"stateId",Json::number(snapshot.zoneStatus)},{L"win32Error",zoneKnown?Json{}:Json::number(snapshot.zoneError)},
            {L"standardName",standardName},{L"daylightName",daylightName},{L"baseBiasMinutes",zoneKnown?Json::signedNumber(snapshot.zone.Bias):Json{}},
            {L"malformed",Json::boolean(snapshot.zoneMalformed)},
            {L"standardBiasMinutes",zoneKnown?Json::signedNumber(snapshot.zone.StandardBias):Json{}},{L"daylightBiasMinutes",zoneKnown?Json::signedNumber(snapshot.zone.DaylightBias):Json{}},
            {L"effectiveBiasMinutes",snapshot.biasKnown?Json::signedNumber(static_cast<LONG>(snapshot.effectiveBiasMinutes)):Json{}},
            {L"standardTransitionRaw",zoneKnown?calendar(snapshot.zone.StandardDate):Json{}},{L"daylightTransitionRaw",zoneKnown?calendar(snapshot.zone.DaylightDate):Json{}}})},
        {L"dynamicZone",Json::object({{L"available",Json::boolean(dynamicKnown)},{L"stateId",Json::number(snapshot.dynamicZoneStatus)},
            {L"win32Error",dynamicKnown?Json{}:Json::number(snapshot.dynamicZoneError)},{L"registryKeyName",keyName},
            {L"dynamicDaylightTimeDisabled",dynamicKnown?Json::boolean(snapshot.dynamicZone.DynamicDaylightTimeDisabled!=FALSE):Json{}}})},
        {L"uptime",Json::object({{L"tickCountMs",Json::count(snapshot.uptimeMs)},{L"estimatedBootFileTime",snapshot.bootEstimateKnown?Json::count(snapshot.estimatedBootFileTime):Json{}},
            {L"estimateAvailable",Json::boolean(snapshot.bootEstimateKnown)},{L"authoritativeBootTimestamp",Json::boolean(false)}})},
        {L"w32time",Json::object({{L"path",Json::string(L"HKLM\\SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters")},
            {L"opened",Json::boolean(snapshot.parametersOpened)},{L"absent",Json::boolean(snapshot.parametersAbsent)},{L"complete",Json::boolean(snapshot.parametersComplete)},
            {L"limited",Json::boolean(snapshot.parametersLimited)},{L"openWin32Error",Json::number(static_cast<DWORD>(snapshot.parametersOpenError))},
            {L"enumWin32Error",Json::number(static_cast<DWORD>(snapshot.parametersEnumError))},{L"closeWin32Error",snapshot.parametersOpened?Json::number(static_cast<DWORD>(snapshot.parametersCloseError)):Json{}},
            {L"valueCount",Json::count(rows.size())},{L"values",Json::array(rows)}})},{L"displaySections",Json::array(displaySections)}}),
        {L"Read-only; no clock/time-zone/NTP changes or W32Time resync. GetTickCount64-derived boot estimate is not an authoritative boot record and clock changes can shift it. Clock/time-zone calls are not atomic. Bias uses minutes to add local time to obtain UTC, opposite to a displayed UTC offset. Raw transition dates can describe relative rules (year 0) or disabled DST (month 0); they are not absolute UTC timestamps. W32Time registry settings do not prove synchronization, NTP reachability or service state. No R0 fallback."}};
}
}
void registerSystemTime(){
    addCommand({L"system time query",L"KswordCLI.exe system time query [--max-data-bytes N] [--backend r3] [--json]",L"Read system clock, time zone, uptime estimate and W32Time registry settings.",
        L"Optional: --max-data-bytes 1..65536 (256 raw bytes per registry value), --backend r3, --json.",
        L"Output: raw UTC FILETIME and validated UTC/local calendar fields; time-zone state/availability/native errors, bounded names, base/standard/daylight/effective bias minutes and raw transition rules; dynamic-zone key/DST flag; tickCountMs and available estimated boot FILETIME; W32Time open/enum/close/completeness/limits plus value names/types/raw hex/truncation/malformed/numeric values and original display sections (256 chars per property). u64 times/count/QWORD decimal strings, unknown null. Value preview truncation/registry or zone absence/API failure/estimate unavailable 6, malformed calendar/bias/registry buffers/value layouts 4, complete evidence 0; no clock/zone/time-source mutation, resync, synchronization proof or R0. W32Time walk 100000 values/8 seconds between APIs, render data 16 MiB. Raw transition year 0 is relative, month 0 may mean no DST. Help performs no time/registry queries.",query});
}
}
