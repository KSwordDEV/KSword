#include "CommandRegistry.h"
#include "../shared/usermode/backend/hardware/BusTopology.h"
#include <stdexcept>
namespace ks::cli {
namespace {
namespace b=ks::r3::hardware_stats;
Json text(const std::wstring& s){return s.empty()?Json{}:Json::string(s);}
Json resources(const b::BusResourceEvidence& e) {
    std::vector<Json> rows;
    for(const auto& r:e.rows)rows.push_back(Json::object({{L"ordinal",Json::number(r.ordinal)},{L"type",Json::number(r.type)},
        {L"kind",text(r.kind)},{L"dataSize",r.sizeKnown?Json::count(r.dataSize):Json{}},
        {L"sizeConfigRet",Json::number(r.sizeStatus)},{L"dataConfigRet",r.sizeKnown&&r.dataSize&&r.dataSize<=16u*1024*1024?Json::number(r.dataStatus):Json{}},
        {L"dataAvailable",Json::boolean(r.dataKnown)},{L"interpreted",Json::boolean(r.interpreted)},{L"malformed",Json::boolean(r.malformed)},
        {L"baseAddress",r.rangeKnown?Json::hex(r.base):Json{}},{L"endAddressInclusive",r.rangeKnown?Json::hex(r.endInclusive):Json{}},
        {L"allocatedNumber",r.numberKnown?Json::number(r.number):Json{}},
        {L"irqSigned",r.kind==L"irq"&&r.numberKnown?Json::signedNumber(static_cast<LONG>(r.number)):Json{}},
        {L"messageSignalledCandidate",r.kind==L"irq"&&r.numberKnown?Json::boolean(r.number>=0x80000000u):Json{}},
        {L"rawPreviewHex",r.dataKnown?Json::bytes(r.rawPreview,256):Json{}},{L"rawPreviewTruncated",Json::boolean(r.dataSize>r.rawPreview.size()&&r.dataKnown)}}));
    return Json::object({{L"available",Json::boolean(e.available)},{L"complete",Json::boolean(e.complete)},
        {L"noConfiguration",Json::boolean(e.noConfiguration)},{L"source",e.available&&!e.noConfiguration?Json::string(e.usedBoot?L"boot":L"allocated"):Json{}},
        {L"allocatedConfigRet",Json::number(e.allocatedStatus)},{L"bootConfigRet",e.bootStatusKnown?Json::number(e.bootStatus):Json{}},
        {L"terminalConfigRet",e.terminalKnown?Json::number(e.terminalStatus):Json{}},{L"limited",Json::boolean(e.limited)},
        {L"malformed",Json::boolean(e.malformed)},{L"descriptorCount",Json::number(e.descriptorCount)},{L"skippedCount",Json::number(e.skippedCount)},
        {L"cleanupComplete",Json::boolean(e.cleanupComplete)},{L"logFreeConfigRet",e.logFreeKnown?Json::number(e.logFreeStatus):Json{}},
        {L"resourceFreeConfigRet",e.resourceFreeKnown?Json::number(e.resourceFreeStatus):Json{}},{L"descriptors",Json::array(rows)}});
}
Json node(const b::BusDeviceRow& n,bool& partial,bool& malformed) {
    std::vector<std::pair<std::wstring,Json>> fields;
    for(const auto& [id,e]:n.evidence){partial=partial||(!e.available&&!e.absent);malformed=malformed||e.malformed;
        fields.push_back({id,Json::object({{L"available",Json::boolean(e.available)},{L"absent",Json::boolean(e.absent)},
            {L"malformed",Json::boolean(e.malformed)},{L"propertyType",e.type?Json::number(e.type):Json{}},
            {L"win32Error",e.error?Json::number(e.error):Json{}},{L"configRet",Json::number(e.cmStatus)},
            {L"values",e.available&&!e.numeric?Json::strings(e.values):Json{}},{L"number",e.available&&e.numeric?Json::count(e.number):Json{}}})});
    }
    const auto address=n.evidence.find(L"address");const bool known=address!=n.evidence.end()&&address->second.available;
    const auto raw=known?address->second.number:0;
    partial=partial||!n.statusKnown||!n.resources.complete;malformed=malformed||n.resources.malformed;
    return Json::object({{L"instanceId",text(n.instanceId)},{L"enumeratorName",text(n.enumeratorName)},
        {L"enumerationSource",Json::string(n.enumerationSource)},{L"descriptionDisplay",Json::string(n.description)},
        {L"busTypeDisplay",text(n.busTypeText)},{L"busTypeGuid",text(n.busTypeGuid)},
        {L"address",known?Json::hex(raw):Json{}},{L"pciDevice",known&&n.enumeratorName==L"PCI"?Json::number(static_cast<DWORD>(raw>>16)):Json{}},
        {L"pciFunction",known&&n.enumeratorName==L"PCI"?Json::number(static_cast<DWORD>(raw&0xffff)):Json{}},
        {L"statusFlags",n.statusKnown?Json::hex(n.statusFlags):Json{}},{L"problemCode",n.statusKnown?Json::number(n.problemCode):Json{}},
        {L"statusConfigRet",Json::number(n.statusResult)},{L"statusDisplay",Json::string(n.statusText)},
        {L"properties",Json::object(fields)},{L"resources",resources(n.resources)},{L"resourceDisplay",Json::string(n.resourceText)}});
}
Result enumerate(const Args& a) {
    const auto scope=a.get(L"--scope",L"common");if(scope!=L"common"&&scope!=L"all")throw std::invalid_argument("--scope must be common or all");
    const auto id=a.get(L"--instance-id"),enumerator=a.get(L"--enumerator");
    if((a.has(L"--instance-id")&&id.empty())||(a.has(L"--enumerator")&&enumerator.empty()))throw std::invalid_argument("identity/enumerator filters must not be empty");
    const auto limit=a.u32(L"--limit",1000);if(!limit||limit>100000)throw std::invalid_argument("--limit must be 1..100000");
    const auto snapshot=b::EnumerateBusDevices(scope==L"all");bool complete=true,partial=false,malformed=false;std::size_t opened=0,matched=0;std::vector<Json> sources,rows;
    for(const auto& s:snapshot.sources){complete=complete&&s.complete&&!s.skippedCount&&!s.limited;malformed=malformed||s.malformed;if(s.opened)++opened;
        sources.push_back(Json::object({{L"name",Json::string(s.name)},{L"opened",Json::boolean(s.opened)},
            {L"complete",Json::boolean(s.complete)},{L"limited",Json::boolean(s.limited)},{L"malformed",Json::boolean(s.malformed)},{L"win32Error",s.win32Error?Json::number(s.win32Error):Json{}},
            {L"configRet",Json::number(s.cmStatus)},{L"examinedCount",Json::number(s.examinedCount)},{L"skippedCount",Json::number(s.skippedCount)}}));}
    for(const auto& r:snapshot.rows){if(!id.empty()&&_wcsicmp(id.c_str(),r.instanceId.c_str()))continue;
        if(!enumerator.empty()&&_wcsicmp(enumerator.c_str(),r.enumeratorName.c_str()))continue;++matched;
        auto value=node(r,partial,malformed);if(rows.size()<limit)rows.push_back(std::move(value));}
    const bool truncated=matched>rows.size();const int code=malformed?4:!opened?3:snapshot.rows.empty()&&!complete?5:!complete||partial||truncated?6:0;
    return {code,Json::object({{L"source",Json::string(L"present SetupAPI devnodes + Configuration Manager resources")},
        {L"scope",Json::string(scope)},{L"complete",Json::boolean(complete)},{L"sources",Json::array(sources)},
        {L"enumeratedCount",Json::count(snapshot.rows.size())},{L"matchedCount",Json::count(matched)},{L"returnedCount",Json::number(static_cast<DWORD>(rows.size()))},
        {L"truncated",Json::boolean(truncated)},{L"devices",Json::array(rows)}}),
        code?std::vector<std::wstring>{L"Sources, selected properties or resource descriptors were incomplete, malformed or truncated. Resource evidence preserves allocated/boot/native query and handle-release states; display text is not used as a success indicator.",snapshot.diagnosticText}:std::vector<std::wstring>{}};
}
}
void registerHardwareBus() {
    addCommand({L"hardware bus enum",L"KswordCLI.exe hardware bus enum [--scope common|all] [--enumerator NAME] [--instance-id ID] [--limit N] [--backend r3] [--json]",
        L"Enumerate R3 bus placement and native PnP resource descriptors.",
        L"Optional: --scope common|all (common: PCI/ACPI/ACPI_HAL/PCIIDE/ROOT), --enumerator exact case-insensitive name, --instance-id exact case-insensitive PnP ID, --limit (1..100000, default 1000), --backend r3, --json.",
        L"Output: separate source completeness/native errors, identities, bus GUID and typed properties, raw address and PCI device/function where applicable, CM state, structured allocated/boot resource query and MEM/MEM64/IO/DMA/IRQ/BUS ranges or numbers with raw preview. Resource end addresses are inclusive. Negative signed IRQ representation is a message-signalled candidate, not an MSI capability query. ALLOC_LOG_CONF is tried first; BOOT_LOG_CONF fallback is labelled, not current allocation. Both CR_NO_MORE_LOG_CONF are valid empty resources; zero-length ResType_None is a valid empty placeholder. Actual access/data/termination errors, unknown descriptor kinds, limits and cleanup failures return 6; malformed properties/ranges/descriptors 4; all source opens failing 3; incomplete empty evidence 5; valid complete empty/filter misses 0. Source cap 100000 devnodes, 4096 resource descriptors/device, 16 MiB/descriptor, 256-byte preview; properties use 16 MiB/4 retries. x64 uses native CM APIs; WOW64 may return CR_CALL_NOT_IMPLEMENTED. Read-only, no resource mutation, PCI config access or R0 fallback; Light display labels are display only.",enumerate});
}
}
