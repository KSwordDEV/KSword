#include "SystemTimeInfo.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <limits>

#pragma comment(lib, "Advapi32.lib")

namespace ks::r3::system_tools {
namespace {

constexpr wchar_t kW32TimeParametersKey[] = L"SYSTEM\\CurrentControlSet\\Services\\W32Time\\Parameters";
template<std::size_t N> std::wstring FixedText(const wchar_t (&value)[N]) {return std::wstring(value,std::find(value,value+N,L'\0'));}

std::wstring FormatSystemTime(const SYSTEMTIME& time, const bool withMilliseconds) {
    std::wostringstream stream;
    stream << std::setfill(L'0')
        << time.wYear << L'-' << std::setw(2) << time.wMonth << L'-' << std::setw(2) << time.wDay
        << L' ' << std::setw(2) << time.wHour << L':' << std::setw(2) << time.wMinute
        << L':' << std::setw(2) << time.wSecond;
    if (withMilliseconds) {
        stream << L'.' << std::setw(3) << time.wMilliseconds;
    }
    return stream.str();
}

// FormatBias renders a UTC offset the way a user reads it. Windows stores the
// bias as "minutes to add to local time to get UTC", which is the opposite sign
// of the UTC+08:00 notation everyone expects, so the sign is flipped here.
std::wstring FormatBias(const std::int64_t biasMinutes) {
    const std::int64_t offset = -biasMinutes;
    const wchar_t sign = offset < 0 ? L'-' : L'+';
    const std::int64_t magnitude = offset < 0 ? -offset : offset;
    std::wostringstream stream;
    stream << L"UTC" << sign << std::setfill(L'0') << std::setw(2) << (magnitude / 60)
        << L':' << std::setw(2) << (magnitude % 60)
        << L"（Bias=" << biasMinutes << L" 分钟）";
    return stream.str();
}

std::wstring FormatUptime(const ULONGLONG milliseconds) {
    const ULONGLONG totalSeconds = milliseconds / 1000ULL;
    const ULONGLONG days = totalSeconds / 86400ULL;
    const ULONGLONG hours = (totalSeconds % 86400ULL) / 3600ULL;
    const ULONGLONG minutes = (totalSeconds % 3600ULL) / 60ULL;
    const ULONGLONG seconds = totalSeconds % 60ULL;
    std::wostringstream stream;
    stream << days << L" 天 " << std::setfill(L'0') << std::setw(2) << hours << L':'
        << std::setw(2) << minutes << L':' << std::setw(2) << seconds;
    return stream.str();
}

// EstimateBootTime derives the boot moment from the tick counter. It is an
// estimate on purpose: GetTickCount64 excludes time spent in sleep on some
// configurations, so the value is labelled as derived rather than presented as
// an authoritative boot timestamp.
std::wstring EstimateBootTime(const ULONGLONG uptimeMs) {
    FILETIME nowFileTime{};
    ::GetSystemTimeAsFileTime(&nowFileTime);
    ULARGE_INTEGER now{};
    now.LowPart = nowFileTime.dwLowDateTime;
    now.HighPart = nowFileTime.dwHighDateTime;
    const ULONGLONG uptime100ns = uptimeMs * 10000ULL;
    if(uptimeMs>(std::numeric_limits<ULONGLONG>::max)()/10000ULL)return L"—";
    if (now.QuadPart <= uptime100ns) {
        return L"—";
    }
    ULARGE_INTEGER boot{};
    boot.QuadPart = now.QuadPart - uptime100ns;
    FILETIME bootFileTime{};
    bootFileTime.dwLowDateTime = boot.LowPart;
    bootFileTime.dwHighDateTime = boot.HighPart;
    FILETIME localFileTime{};
    SYSTEMTIME localTime{};
    if (!::FileTimeToLocalFileTime(&bootFileTime, &localFileTime) ||
        !::FileTimeToSystemTime(&localFileTime, &localTime)) {
        return L"—";
    }
    return FormatSystemTime(localTime, false);
}

std::wstring TimeZoneIdText(const DWORD timeZoneId) {
    switch (timeZoneId) {
    case TIME_ZONE_ID_STANDARD:
        return L"标准时间";
    case TIME_ZONE_ID_DAYLIGHT:
        return L"夏令时";
    case TIME_ZONE_ID_UNKNOWN:
        return L"未定义夏令时规则";
    default:
        return L"查询失败";
    }
}

std::wstring FormatBinaryPreview(const std::vector<BYTE>& data) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');
    const std::size_t shown = (std::min)(data.size(), static_cast<std::size_t>(32));
    for (std::size_t index = 0; index < shown; ++index) {
        if (index != 0) {
            stream << L' ';
        }
        stream << std::setw(2) << static_cast<unsigned>(data[index]);
    }
    if (shown < data.size()) {
        stream << L" …（共 " << std::dec << data.size() << L" 字节）";
    }
    return stream.str();
}

std::wstring FormatRegistryValue(const DWORD type, const std::vector<BYTE>& data) {
    switch (type) {
    case REG_SZ:
    case REG_EXPAND_SZ: {
        if (data.size() < sizeof(wchar_t)) {
            return {};
        }
        const auto* text = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t maxChars = data.size() / sizeof(wchar_t);
        return std::wstring(text, ::wcsnlen(text, maxChars));
    }
    case REG_MULTI_SZ: {
        std::wstring joined;
        const auto* cursor = reinterpret_cast<const wchar_t*>(data.data());
        const std::size_t maxChars = data.size() / sizeof(wchar_t);
        std::size_t offset = 0;
        while (offset < maxChars && cursor[offset] != L'\0') {
            const std::size_t length = ::wcsnlen(cursor + offset, maxChars - offset);
            if (!joined.empty()) {
                joined += L" | ";
            }
            joined.append(cursor + offset, length);
            offset += length + 1;
        }
        return joined;
    }
    case REG_DWORD: {
        if (data.size() < sizeof(DWORD)) {
            return {};
        }
        DWORD value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        std::wostringstream stream;
        stream << value << L" (0x" << std::uppercase << std::hex << value << L")";
        return stream.str();
    }
    case REG_QWORD: {
        if (data.size() < sizeof(ULONGLONG)) {
            return {};
        }
        ULONGLONG value = 0;
        std::memcpy(&value, data.data(), sizeof(value));
        std::wostringstream stream;
        stream << value << L" (0x" << std::uppercase << std::hex << value << L")";
        return stream.str();
    }
    default:
        return FormatBinaryPreview(data);
    }
}

// ReadW32TimeParameters enumerates every value rather than reading a hardcoded
// list. The interesting names differ between a domain member, a workgroup
// machine and a Hyper-V guest, and a fixed list would quietly omit exactly the
// setting that explains a wrong clock.
SystemTimeInfoSection ReadW32TimeParameters(SystemTimeInfoSnapshot& snapshot) {
    SystemTimeInfoSection section{};
    section.title = L"NTP / W32Time 配置（HKLM\\" + std::wstring(kW32TimeParametersKey) + L"）";

    HKEY key = nullptr;
    const LSTATUS status = ::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kW32TimeParametersKey, 0, KEY_READ, &key);
    snapshot.parametersOpenError=status;snapshot.parametersAbsent=status==ERROR_FILE_NOT_FOUND||status==ERROR_PATH_NOT_FOUND;
    if (status != ERROR_SUCCESS) {
        section.properties.push_back({ L"读取状态",
            L"无法打开注册表键，错误码 " + std::to_wstring(status) + L"。W32Time 可能未安装。" });
        return section;
    }

    snapshot.parametersOpened=true;std::vector<wchar_t> name(16384,L'\0');const auto started=::GetTickCount64();
    std::vector<BYTE> data(4096);
    for (DWORD index = 0;; ++index) {
        if(index>=100000||::GetTickCount64()-started>8000){snapshot.parametersLimited=true;break;}
        DWORD nameLength = static_cast<DWORD>(name.size());
        DWORD type = 0;
        DWORD dataSize = static_cast<DWORD>(data.size());
        LSTATUS enumStatus = ::RegEnumValueW(key, index, name.data(), &nameLength, nullptr, &type, data.data(), &dataSize);
        if (enumStatus == ERROR_MORE_DATA) {
            if(dataSize>16u*1024u*1024u){snapshot.parametersLimited=true;break;}
            data.resize(dataSize);
            nameLength = static_cast<DWORD>(name.size());
            dataSize = static_cast<DWORD>(data.size());
            enumStatus = ::RegEnumValueW(key, index, name.data(), &nameLength, nullptr, &type, data.data(), &dataSize);
        }
        if (enumStatus != ERROR_SUCCESS) {
            snapshot.parametersComplete=enumStatus==ERROR_NO_MORE_ITEMS;snapshot.parametersEnumError=snapshot.parametersComplete?ERROR_SUCCESS:enumStatus;
            break;
        }
        if(dataSize>data.size()||nameLength>=name.size()){snapshot.parametersMalformed=true;break;}
        std::vector<BYTE> value(data.begin(), data.begin() + dataSize);
        const std::wstring valueName = nameLength > 0 ? std::wstring(name.data(), nameLength) : std::wstring(L"(默认)");
        snapshot.parameters.push_back({std::wstring(name.data(),nameLength),type,value});
        section.properties.push_back({ valueName, FormatRegistryValue(type, value) });
    }
    snapshot.parametersCloseError=::RegCloseKey(key);

    if (section.properties.empty()) {
        section.properties.push_back({ L"读取状态", L"该键下没有任何值。" });
    }
    return section;
}

} // namespace

SystemTimeInfoSnapshot CollectSystemTimeInfo() {
    SystemTimeInfoSnapshot snapshot{};

    SYSTEMTIME localTime{};
    SYSTEMTIME utcTime{};
    ::GetLocalTime(&localTime);
    ::GetSystemTime(&utcTime);
    snapshot.localTime=localTime;snapshot.utcTime=utcTime;FILETIME validated{};
    ::SetLastError(ERROR_SUCCESS);snapshot.calendarKnown=::SystemTimeToFileTime(&utcTime,&validated)!=FALSE&&::SystemTimeToFileTime(&localTime,&validated)!=FALSE&&utcTime.wDayOfWeek<=6&&localTime.wDayOfWeek<=6;
    if(!snapshot.calendarKnown)snapshot.calendarValidationError=::GetLastError();
    snapshot.calendarMalformed=!snapshot.calendarKnown;FILETIME now{};::GetSystemTimeAsFileTime(&now);snapshot.utcFileTime=static_cast<std::uint64_t>(now.dwHighDateTime)<<32|now.dwLowDateTime;

    TIME_ZONE_INFORMATION zone{};
    const DWORD zoneId = ::GetTimeZoneInformation(&zone);
    snapshot.zone=zone;snapshot.zoneStatus=zoneId;if(zoneId==TIME_ZONE_ID_INVALID)snapshot.zoneError=::GetLastError();
    const std::int64_t effectiveBias = static_cast<std::int64_t>(zone.Bias) +
        (zoneId == TIME_ZONE_ID_DAYLIGHT ? zone.DaylightBias
            : zoneId == TIME_ZONE_ID_STANDARD ? zone.StandardBias : 0);
    snapshot.effectiveBiasMinutes=effectiveBias;snapshot.biasKnown=zoneId<=TIME_ZONE_ID_DAYLIGHT&&effectiveBias>=LONG_MIN&&effectiveBias<=LONG_MAX;
    snapshot.zoneMalformed=zoneId!=TIME_ZONE_ID_INVALID&&(zoneId>TIME_ZONE_ID_DAYLIGHT||effectiveBias<LONG_MIN||effectiveBias>LONG_MAX);

    const ULONGLONG uptimeMs = ::GetTickCount64();
    snapshot.uptimeMs=uptimeMs;if(uptimeMs<=(std::numeric_limits<std::uint64_t>::max)()/10000&&snapshot.utcFileTime>uptimeMs*10000){snapshot.bootEstimateKnown=true;snapshot.estimatedBootFileTime=snapshot.utcFileTime-uptimeMs*10000;}

    SystemTimeInfoSection clock{};
    clock.title = L"系统时间";
    clock.properties.push_back({ L"本地时间", FormatSystemTime(localTime, true) });
    clock.properties.push_back({ L"UTC 时间", FormatSystemTime(utcTime, true) });
    clock.properties.push_back({ L"当前有效偏移", FormatBias(effectiveBias) });
    snapshot.sections.push_back(std::move(clock));

    SystemTimeInfoSection timeZone{};
    timeZone.title = L"时区";
    timeZone.properties.push_back({ L"当前状态", TimeZoneIdText(zoneId) });
    timeZone.properties.push_back({ L"标准时间名称", FixedText(zone.StandardName) });
    timeZone.properties.push_back({ L"夏令时名称", FixedText(zone.DaylightName) });
    timeZone.properties.push_back({ L"基准偏移", FormatBias(zone.Bias) });
    timeZone.properties.push_back({ L"标准时间附加偏移", std::to_wstring(zone.StandardBias) + L" 分钟" });
    timeZone.properties.push_back({ L"夏令时附加偏移", std::to_wstring(zone.DaylightBias) + L" 分钟" });

    DYNAMIC_TIME_ZONE_INFORMATION dynamicZone{};
    snapshot.dynamicZoneStatus=::GetDynamicTimeZoneInformation(&dynamicZone);snapshot.dynamicZone=dynamicZone;
    if(snapshot.dynamicZoneStatus==TIME_ZONE_ID_INVALID)snapshot.dynamicZoneError=::GetLastError();
    if (snapshot.dynamicZoneStatus != TIME_ZONE_ID_INVALID) {
        timeZone.properties.push_back({ L"时区注册表键", FixedText(dynamicZone.TimeZoneKeyName) });
        timeZone.properties.push_back({ L"动态夏令时",
            dynamicZone.DynamicDaylightTimeDisabled ? L"已禁用" : L"启用" });
    }
    snapshot.sections.push_back(std::move(timeZone));

    SystemTimeInfoSection uptime{};
    uptime.title = L"运行时长";
    uptime.properties.push_back({ L"开机时长", FormatUptime(uptimeMs) });
    uptime.properties.push_back({ L"GetTickCount64", std::to_wstring(uptimeMs) + L" ms" });
    uptime.properties.push_back({ L"推算开机时间", EstimateBootTime(uptimeMs) });
    snapshot.sections.push_back(std::move(uptime));

    snapshot.sections.push_back(ReadW32TimeParameters(snapshot));
    snapshot.success = true;
    return snapshot;
}

std::wstring FormatLiveClockLine() {
    SYSTEMTIME localTime{};
    SYSTEMTIME utcTime{};
    ::GetLocalTime(&localTime);
    ::GetSystemTime(&utcTime);
    return L"本地 " + FormatSystemTime(localTime, false) +
        L"    UTC " + FormatSystemTime(utcTime, false) +
        L"    已运行 " + FormatUptime(::GetTickCount64());
}

std::wstring RenderSystemTimeReport(const SystemTimeInfoSnapshot& snapshot) {
    if (!snapshot.success) {
        return snapshot.diagnosticText.empty() ? L"系统时间信息收集失败。" : snapshot.diagnosticText;
    }
    std::wstring text;
    for (const SystemTimeInfoSection& section : snapshot.sections) {
        if (!text.empty()) {
            text += L"\r\n";
        }
        text += L"【" + section.title + L"】\r\n";
        for (const SystemTimeProperty& property : section.properties) {
            text += L"  " + property.name + L"：" + property.value + L"\r\n";
        }
    }
    if (!snapshot.diagnosticText.empty()) {
        text += L"\r\n" + snapshot.diagnosticText + L"\r\n";
    }
    return text;
}

} // namespace ks::r3::system_tools
