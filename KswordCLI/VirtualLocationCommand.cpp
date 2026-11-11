#include "CommandRegistry.h"
#include "../shared/usermode/backend/system/VirtualLocation.h"
#include <cmath>
#include <cstring>
#include <locale>
#include <sstream>
#include <stdexcept>

namespace ks::cli {
namespace {
namespace location=ks::r3::location;
bool driver(const Args& a){return a.get(L"--backend",L"r3")==L"r0";}
double number(const Args& a,const wchar_t* name,double fallback,bool required=false) {
    if(!a.has(name)){if(required)throw std::invalid_argument("missing coordinate");return fallback;}
    const auto text=a.get(name);double value=0;std::wistringstream in(text);in.imbue(std::locale::classic());in>>value;
    if(in.fail()||!std::isfinite(value))throw std::invalid_argument("invalid coordinate");in>>std::ws;
    if(!in.eof())throw std::invalid_argument("invalid coordinate");return value;
}
location::CoordinateSystem systemName(const std::wstring& s){if(s==L"wgs84")return location::CoordinateSystem::Wgs84;if(s==L"gcj02")return location::CoordinateSystem::Gcj02;if(s==L"bd09")return location::CoordinateSystem::Bd09;throw std::invalid_argument("coordinate system must be wgs84, gcj02 or bd09");}
Json value(const location::Value& v){return Json::object({{L"known",Json::boolean(v.known)},{L"present",v.known?Json::boolean(v.present):Json{}},
    {L"type",v.present?Json::number(v.type):Json{}},{L"dataHex",v.present?Json::bytes(v.bytes,v.bytes.size()):Json{}},
    {L"win32Error",Json::number(v.win32Error)},{L"deviceOpenFailed",Json::boolean(v.deviceOpenFailed)},
    {L"driverStatus",v.driverStatus?Json::number(v.driverStatus):Json{}},{L"ntStatus",v.driverStatus?Json::hex(static_cast<std::uint32_t>(v.ntStatus)):Json{}}});}
Json operation(const location::Operation& o){return Json::object({{L"success",Json::boolean(o.success)},{L"win32Error",Json::number(o.win32Error)},
    {L"deviceOpenFailed",Json::boolean(o.deviceOpenFailed)},{L"driverStatus",o.driverStatus?Json::number(o.driverStatus):Json{}},{L"ntStatus",o.driverStatus?Json::hex(static_cast<std::uint32_t>(o.ntStatus)):Json{}}});}
Json snapshot(const location::Snapshot& s){std::vector<Json> rows;for(std::size_t i=0;i<5;++i)rows.push_back(Json::object({{L"name",Json::string(location::valueName(i))},
    {L"value",value(s.values[i])},{L"number",s.valid[i]?Json::real(s.numbers[i]):Json{}}}));return Json::object({{L"values",Json::array(rows)},
    {L"coordinatePresent",Json::boolean(s.valid[0]&&s.valid[1])},{L"latitude",s.valid[0]?Json::real(s.numbers[0]):Json{}},{L"longitude",s.valid[1]?Json::real(s.numbers[1]):Json{}}});}
bool complete(const location::Snapshot& s){for(std::size_t i=0;i<5;++i)if(!s.values[i].known || (s.values[i].present&&!s.valid[i]))return false;return true;}
Result query(const Args& a){location::SystemRegistry registry(driver(a));const auto s=location::readDefault(registry);const auto provider=registry.read(true,L"DisableWindowsLocationProvider");
    const auto policy=registry.read(true,L"DisableLocation");const auto consent=location::readConsent(false);const auto desktop=location::readConsent(true);const auto service=location::serviceStatus();bool all=complete(s)&&provider.known&&policy.known&&consent.known&&desktop.known&&service.available;
    bool missingDevice=provider.deviceOpenFailed||policy.deviceOpenFailed;for(const auto& v:s.values)missingDevice=missingDevice||v.deviceOpenFailed;
    return {missingDevice?2:all?0:6,Json::object({{L"source",Json::string(driver(a)?L"R0 registry IOCTL + SCM":L"Win32 registry + SCM")},{L"defaultLocation",snapshot(s)},
        {L"providerPolicy",value(provider)},{L"locationPolicy",value(policy)},{L"systemConsent",value(consent)},{L"desktopConsent",value(desktop)},{L"service",Json::object({{L"available",Json::boolean(service.available)},
        {L"state",service.available?Json::number(service.state):Json{}},{L"win32Error",Json::number(service.error)}})}}),
        {L"Windows default location is a fallback for location-enabled applications; it does not guarantee their live position."}};}
Result change(const Args& a,bool clear){if(!a.has(L"--confirm"))throw std::invalid_argument("missing option --confirm");location::SystemRegistry registry(driver(a));location::Mutation m;
    if(clear)m=location::clearDefault(registry);else {location::Coordinate c;c.latitude=number(a,L"--latitude",0,true);c.longitude=number(a,L"--longitude",0,true);
        c.altitude=number(a,L"--altitude",0);c.errorRadius=number(a,L"--accuracy",0);c.altitudeAccuracy=number(a,L"--altitude-accuracy",0);
        if(c.latitude < -90||c.latitude>90||c.longitude < -180||c.longitude>180||c.errorRadius<0||c.altitudeAccuracy<0)throw std::invalid_argument("coordinate out of range");
        c=location::convert(c,systemName(a.get(L"--coordinate-system",L"wgs84")),location::CoordinateSystem::Wgs84);m=location::writeDefault(registry,c);}
    std::vector<Json> ops;for(std::size_t i=0;i<5;++i)ops.push_back(Json::object({{L"name",Json::string(location::valueName(i))},{L"attempted",Json::boolean(i<m.attempted)},{L"result",i<m.attempted?operation(m.operations[i]):Json{}}}));
    const bool missingDevice=m.completed==0&&m.attempted!=0&&m.operations[0].deviceOpenFailed;
    return {missingDevice?2:m.success?0:m.partial?6:3,Json::object({{L"verified",Json::boolean(m.success)},{L"partial",Json::boolean(m.partial)},
        {L"operations",Json::array(ops)},{L"after",snapshot(m.after)}}),{L"A failure can leave earlier values changed; no rollback is implied."}};}
Result provider(const Args& a){if(!a.has(L"--confirm"))throw std::invalid_argument("missing option --confirm");const auto mode=a.require(L"--state");
    if(mode!=L"disabled"&&mode!=L"default")throw std::invalid_argument("--state must be disabled or default");location::SystemRegistry registry(driver(a));
    const auto action=location::setProvider(registry,mode==L"disabled");const auto after=registry.read(true,L"DisableWindowsLocationProvider");
    DWORD data=0;if(after.bytes.size()==sizeof(data))std::memcpy(&data,after.bytes.data(),sizeof(data));
    const bool verified=action.success&&after.known&&(mode==L"default"?!after.present:after.present&&after.type==REG_DWORD&&after.bytes.size()==sizeof(data)&&data==1);
    return {action.deviceOpenFailed?2:action.success?(verified?0:6):3,Json::object({{L"operation",operation(action)},{L"verified",Json::boolean(verified)},{L"after",value(after)}})};}
Result cache(const Args& a){if(!a.has(L"--confirm"))throw std::invalid_argument("missing option --confirm");const auto o=location::resetServiceCache();const auto s=location::serviceStatus();
    const bool done=o.success&&s.available&&s.state==SERVICE_STOPPED;return {o.success?(done?0:6):3,Json::object({{L"operation",operation(o)},{L"serviceState",s.available?Json::number(s.state):Json{}},
        {L"serviceWin32Error",Json::number(s.error)},{L"verifiedStopped",Json::boolean(done)}}),{L"Matches the GUI cache reset: request lfsvc stop; Windows may restart it on demand."}};}
Result live(const Args& a){const auto timeout=a.u32(L"--timeout-ms",10000);if(timeout<100||timeout>120000)throw std::invalid_argument("--timeout-ms must be 100..120000");
    const auto r=location::liveFix(timeout);return {r.success?0:r.timedOut?6:3,Json::object({{L"source",Json::string(L"WinRT Geolocator")},{L"success",Json::boolean(r.success)},
        {L"timedOut",Json::boolean(r.timedOut)},{L"hresult",Json::hex(static_cast<std::uint32_t>(r.hresult))},{L"latitude",r.success?Json::real(r.coordinate.latitude):Json{}},
        {L"longitude",r.success?Json::real(r.coordinate.longitude):Json{}},{L"altitude",r.success?Json::real(r.coordinate.altitude):Json{}},
        {L"accuracyMeters",r.accuracyKnown?Json::real(r.coordinate.errorRadius):Json{}},{L"altitudeAccuracyMeters",r.altitudeAccuracyKnown?Json::real(r.coordinate.altitudeAccuracy):Json{}},
        {L"positionSource",r.sourceKnown?Json::number(r.source):Json{}}})};}
Result convert(const Args& a){location::Coordinate c;c.latitude=number(a,L"--latitude",0,true);c.longitude=number(a,L"--longitude",0,true);
    if(c.latitude < -90||c.latitude>90||c.longitude < -180||c.longitude>180)throw std::invalid_argument("coordinate out of range");
    const auto from=systemName(a.require(L"--from")),to=systemName(a.require(L"--to"));const auto result=location::convert(c,from,to);
    return {0,Json::object({{L"latitude",Json::real(result.latitude)},{L"longitude",Json::real(result.longitude)}}),{L"GCJ-02/BD-09 conversion is approximate; outside the supported mainland region the WGS/GCJ transform is unchanged."}};}
}
void registerVirtualLocation(){
    const auto addDual=[](Command c){c.supportsR0=true;addCommand(std::move(c));};
    addDual({L"system location query",L"KswordCLI.exe system location query [--backend r3|r0] [--json]",L"Read default location, policy and location service status.",L"Optional: --backend r3|r0, --json.",L"Registry channel is explicit; service state uses SCM. No fallback. Individual values retain native status.",query});
    addDual({L"system location set",L"KswordCLI.exe system location set --latitude N --longitude N [--coordinate-system wgs84|gcj02|bd09] [--altitude N] [--accuracy N] [--altitude-accuracy N] --confirm [--backend r3|r0] [--json]",L"Set the Windows default location after conversion to WGS-84.",L"Required: --latitude, --longitude, --confirm. Optional: --coordinate-system, --altitude, --accuracy, --altitude-accuracy, --backend r3|r0, --json.",L"Writes five REG_SZ values and reads each back; partial writes are not rolled back. Windows default location is not a guarantee of live positioning.",[](const Args& a){return change(a,false);}});
    addDual({L"system location clear",L"KswordCLI.exe system location clear --confirm [--backend r3|r0] [--json]",L"Clear the five default-location values.",L"Required: --confirm. Optional: --backend r3|r0, --json.",L"Leaves the key and unrelated values intact; verifies each value is absent.",[](const Args& a){return change(a,true);}});
    addDual({L"system location provider set",L"KswordCLI.exe system location provider set --state disabled|default --confirm [--backend r3|r0] [--json]",L"Disable the Windows location provider by policy or remove that policy.",L"Required: --state, --confirm. Optional: --backend r3|r0, --json.",L"Uses the selected registry channel and verifies the policy value.",provider});
    addCommand({L"system location service reset-cache",L"KswordCLI.exe system location service reset-cache --confirm [--backend r3] [--json]",L"Request the location service to stop so Windows can refresh its cache.",L"Required: --confirm. Optional: --backend r3, --json.",L"Uses SCM; Windows can restart the demand-start service. A pending stop returns partial.",cache});
    addCommand({L"system location live query",L"KswordCLI.exe system location live query [--timeout-ms N] [--backend r3] [--json]",L"Read one live Windows geolocation fix.",L"Optional: --timeout-ms 100..120000 (10000), --backend r3, --json.",L"Uses WinRT and current user location permissions; timeout cancels the request.",live});
    addCommand({L"system location convert",L"KswordCLI.exe system location convert --latitude N --longitude N --from wgs84|gcj02|bd09 --to wgs84|gcj02|bd09 [--json]",L"Convert coordinates without changing the system.",L"Required: --latitude, --longitude, --from, --to. Optional: --json.",L"GCJ/BD transforms are approximate; WGS/GCJ is unchanged outside the mainland region.",convert});
}
}
