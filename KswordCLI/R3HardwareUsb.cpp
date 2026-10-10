#include "CommandRegistry.h"
#include "../shared/usermode/backend/hardware/UsbTopology.h"
#include <algorithm>
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::hardware_stats;
std::wstring kind(b::UsbNodeKind k){return k==b::UsbNodeKind::HostController?L"controller":k==b::UsbNodeKind::Hub?L"hub":L"device";}
Json value(const std::wstring& s){return s.empty()?Json{}:Json::string(s);}
Json node(const b::UsbNode& n,bool roleKnown,bool& partial,bool& malformed) {
    std::vector<std::pair<std::wstring,Json>> fields;
    for(const auto& [id,e]:n.evidence){partial=partial||(!e.available&&!e.absent);malformed=malformed||e.malformed;
        fields.push_back({id,Json::object({{L"available",Json::boolean(e.available)},{L"absent",Json::boolean(e.absent)},
            {L"malformed",Json::boolean(e.malformed)},{L"propertyType",e.type?Json::number(e.type):Json{}},
            {L"win32Error",e.error?Json::number(e.error):Json{}},{L"configRet",Json::number(e.cmStatus)},
            {L"values",e.available&&!e.numeric?Json::strings(e.values):Json{}},{L"number",e.available&&e.numeric?Json::count(e.number):Json{}}})});
    }
    partial=partial||!n.statusKnown||!roleKnown;
    return Json::object({{L"index",Json::signedNumber(n.index)},{L"parentIndex",n.parentIndex<0?Json{}:Json::signedNumber(n.parentIndex)},
        {L"depth",Json::signedNumber(n.depth)},{L"instanceId",value(n.instanceId)},{L"parentInstanceId",value(n.parentInstanceId)},
        {L"kind",roleKnown?Json::string(kind(n.kind)):Json{}},{L"descriptionDisplay",Json::string(n.description)},
        {L"vendorId",value(n.vendorId)},{L"productId",value(n.productId)},{L"revision",value(n.revision)},
        {L"identitySource",Json::string(n.hardwareIds.empty()?L"instanceId":L"hardwareIds")},
        {L"instanceSerialCandidate",value(n.serialNumber)},{L"address",n.addressKnown?Json::hex(n.address):Json{}},
        {L"hubPortCandidate",roleKnown&&n.kind!=b::UsbNodeKind::HostController&&n.addressKnown?Json::number(n.address):Json{}},
        {L"statusFlags",n.statusKnown?Json::hex(n.statusFlags):Json{}},{L"problemCode",n.statusKnown?Json::number(n.problemCode):Json{}},
        {L"statusConfigRet",Json::number(n.statusResult)},{L"statusDisplay",Json::string(n.statusText)},
        {L"problemDisplay",Json::string(n.problemText)},{L"properties",Json::object(fields)}});
}
Result enumerate(const Args& a) {
    const auto filter=a.get(L"--kind",L"all");if(filter!=L"all"&&filter!=L"controller"&&filter!=L"hub"&&filter!=L"device")throw std::invalid_argument("--kind must be all, controller, hub or device");
    const auto id=a.get(L"--instance-id");if(a.has(L"--instance-id")&&id.empty())throw std::invalid_argument("--instance-id must not be empty");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");
    const auto snapshot=b::EnumerateUsbTopology();std::vector<Json> sources,rows;bool complete=true,malformed=false,partial=false;std::size_t opened=0,matched=0;
    for(const auto& s:snapshot.sources){complete=complete&&s.complete&&!s.skippedCount&&!s.limited;malformed=malformed||s.malformed;if(s.opened)++opened;
        sources.push_back(Json::object({{L"name",Json::string(s.name)},{L"opened",Json::boolean(s.opened)},
            {L"complete",Json::boolean(s.complete)},{L"limited",Json::boolean(s.limited)},{L"malformed",Json::boolean(s.malformed)},
            {L"win32Error",s.win32Error?Json::number(s.win32Error):Json{}},{L"configRet",Json::number(s.cmStatus)},
            {L"examinedCount",Json::number(s.examinedCount)},{L"skippedCount",Json::number(s.skippedCount)}}));}
    const bool roleKnown=snapshot.sources.size()>=2&&snapshot.sources[0].complete&&!snapshot.sources[0].skippedCount&&snapshot.sources[1].complete&&!snapshot.sources[1].skippedCount;
    for(const auto& n:snapshot.nodes){if(!id.empty()&&_wcsicmp(id.c_str(),n.instanceId.c_str()))continue;
        if(filter!=L"all"&&(!roleKnown||filter!=kind(n.kind)))continue;++matched;
        auto data=node(n,roleKnown,partial,malformed);if(rows.size()<limit)rows.push_back(std::move(data));}
    const bool truncated=matched>rows.size();const int code=malformed?4:!opened?3:snapshot.nodes.empty()&&!complete?5:!complete||partial||truncated?6:0;
    return {code,Json::object({{L"source",Json::string(L"present SetupAPI USB/USBSTOR devnodes + USB interface owners")},
        {L"complete",Json::boolean(complete)},{L"roleClassificationComplete",Json::boolean(roleKnown)},{L"sources",Json::array(sources)},
        {L"enumeratedCount",Json::count(snapshot.nodes.size())},{L"matchedCount",Json::count(matched)},{L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},
        {L"truncated",Json::boolean(truncated)},{L"nodes",Json::array(rows)}}),
        code?std::vector<std::wstring>{L"USB sources or selected properties were incomplete, malformed or truncated. Devnode topology does not prove physical hub-port wiring, descriptor serial numbers or negotiated USB speed.",snapshot.diagnosticText}:std::vector<std::wstring>{}};
}
}
void registerHardwareUsb() {
    addCommand({L"hardware usb enum",L"KswordCLI.exe hardware usb enum [--kind all|controller|hub|device] [--instance-id ID] [--limit N] [--backend r3] [--json]",
        L"Enumerate present R3 USB devnode topology and identity candidates.",
        L"Optional: --kind (all), --instance-id exact case-insensitive PnP ID, --limit (1..100000, default 1000), --backend r3, --json.",
        L"Output: six source walks with native completeness/errors, deduplicated nodes with snapshot index/parentIndex/depth/instanceId/parentInstanceId/kind, VID/PID/revision derived from IDs, instanceSerialCandidate, raw address/hubPortCandidate, CM status and typed property arrays. Indices refer to the full snapshot even when filtered. Controllers expose packed PCI address, never a hub-port number. Serial is a devnode-ID candidate, not a USB descriptor query. Missing optional properties are absent; failed sources/CM/fields and truncation return 6, no usable source evidence 5, all source opens failing 3, malformed properties 4. Valid empty complete topology/filter results succeed. Classification failure makes kind unknown. Present devices only; no enable/disable/eject, speed/bandwidth or R0 fallback. Source budget 100000 devnodes per walk; property cap 16 MiB and 4 growth attempts. Text labels preserved from Light are display only.",enumerate});
}
}
