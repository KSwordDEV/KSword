#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/usermode/backend/service/ServiceEnumerator.h"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <iterator>

namespace ks::cli {
namespace {
using ksword::ark::DriverClient;
using ksword::ark::IoResult;

std::wstring boundedAnsi(const char* text, std::size_t capacity) {
    std::size_t length = 0;
    while (length < capacity && text[length]) ++length;
    // Protocol identifiers and diagnostics are ASCII; preserve byte values.
    return std::wstring(text, text + length);
}
std::wstring boundedWide(const wchar_t* text, std::size_t capacity) {
    std::size_t length = 0;
    while (length < capacity && text[length]) ++length;
    return std::wstring(text, text + length);
}
Json transport(const IoResult& io) {
    return Json::object({{L"success",Json::boolean(io.ok)}, {L"deviceOpenFailed",Json::boolean(io.deviceOpenFailed)},
        {L"win32Error",Json::number(io.win32Error)}, {L"bytesReturned",Json::number(io.bytesReturned)}});
}

// Each list has a separately checked header and declared row stride. A failed or
// truncated query is never converted into an empty, apparently complete list.
template<typename Entry>
bool validList(const IoResult& io, const std::vector<std::uint8_t>& buffer, std::size_t offset,
               unsigned long version, unsigned long expectedVersion, unsigned long size,
               unsigned long count, unsigned long total, unsigned long stride) {
    return io.ok && io.bytesReturned <= buffer.size() && io.bytesReturned >= offset && size >= offset &&
        size <= io.bytesReturned && version == expectedVersion && stride >= sizeof(Entry) &&
        count <= total && count <= (size - offset) / stride;
}

Result health(const Args&) {
    using namespace ks::r3::service;
    const auto service = QuerySingleService(L"KswordARK");
    const bool serviceKnown = service.success && !service.entries.empty() && service.entries.front().hasStatus;
    const auto* entry = service.entries.empty() ? nullptr : &service.entries.front();
    Json serviceData = Json::object({{L"name",Json::string(L"KswordARK")},
        {L"querySuccess",Json::boolean(service.success)}, {L"win32Error",Json::number(service.win32Error)},
        {L"state",serviceKnown ? Json::number(entry->currentState) : Json{}},
        {L"binaryPath",entry && entry->hasConfig ? Json::string(entry->binaryPath) : Json{}},
        {L"diagnostic",Json::string(service.diagnosticText)}});

    const DriverClient client;
    std::vector<std::uint8_t> capBuffer(128 * 1024, 0);
    const auto capIo = client.deviceIoControl(IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES, nullptr, 0,
                                               capBuffer.data(), static_cast<unsigned long>(capBuffer.size()));
    constexpr auto capOffset = offsetof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE, entries);
    bool capValid = false, capComplete = false, featuresHealthy = true;
    Json capability = Json::object({{L"transport",transport(capIo)}, {L"valid",Json::boolean(false)}});
    if (capIo.ok && capIo.bytesReturned >= capOffset && capIo.bytesReturned <= capBuffer.size()) {
        const auto* cap = reinterpret_cast<const KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE*>(capBuffer.data());
        capValid = validList<KSWORD_ARK_FEATURE_CAPABILITY_ENTRY>(
            capIo,capBuffer,capOffset,cap->version,KSWORD_ARK_DRIVER_CAPABILITY_PROTOCOL_VERSION,cap->size,
            cap->returnedFeatureCount,cap->totalFeatureCount,cap->entrySize);
        if (capValid) {
            capComplete = cap->returnedFeatureCount == cap->totalFeatureCount;
            std::vector<Json> rows;
            for (unsigned long i=0; i<cap->returnedFeatureCount; ++i) {
                KSWORD_ARK_FEATURE_CAPABILITY_ENTRY item{};
                std::memcpy(&item, capBuffer.data()+capOffset+static_cast<std::size_t>(i)*cap->entrySize, sizeof(item));
                featuresHealthy &= item.state == KSWORD_ARK_FEATURE_STATE_AVAILABLE;
                rows.push_back(Json::object({{L"id",Json::number(item.featureId)},
                    {L"name",Json::string(boundedAnsi(item.featureName,sizeof(item.featureName)))},
                    {L"state",Json::number(item.state)}, {L"stateName",Json::string(boundedAnsi(item.stateName,sizeof(item.stateName)))},
                    {L"requiredDynDataMask",Json::hex(item.requiredDynDataMask)}, {L"presentDynDataMask",Json::hex(item.presentDynDataMask)},
                    {L"dependency",Json::string(boundedAnsi(item.dependencyText,sizeof(item.dependencyText)))},
                    {L"reason",Json::string(boundedAnsi(item.reasonText,sizeof(item.reasonText)))}}));
            }
            capability = Json::object({{L"transport",transport(capIo)}, {L"valid",Json::boolean(true)},
                {L"protocolVersion",Json::hex(cap->driverProtocolVersion)}, {L"statusFlags",Json::hex(cap->statusFlags)},
                {L"dynDataStatusFlags",Json::hex(cap->dynDataStatusFlags)}, {L"dynDataCapabilityMask",Json::hex(cap->dynDataCapabilityMask)},
                {L"lastErrorStatus",Json::hex(static_cast<std::uint32_t>(cap->lastErrorStatus))},
                {L"lastErrorSource",Json::string(boundedAnsi(cap->lastErrorSource,sizeof(cap->lastErrorSource)))},
                {L"lastErrorSummary",Json::string(boundedAnsi(cap->lastErrorSummary,sizeof(cap->lastErrorSummary)))},
                {L"totalCount",Json::number(cap->totalFeatureCount)}, {L"complete",Json::boolean(capComplete)}, {L"features",Json::array(rows)}});
        }
    }

    KSW_QUERY_DYN_STATUS_RESPONSE dyn{};
    IoResult dynIo{};
    if (!capIo.deviceOpenFailed) dynIo = client.deviceIoControl(IOCTL_KSWORD_ARK_QUERY_DYN_STATUS,nullptr,0,&dyn,sizeof(dyn));
    const bool dynValid = dynIo.ok && dynIo.bytesReturned >= sizeof(dyn) && dyn.size >= sizeof(dyn) &&
        dyn.size <= dynIo.bytesReturned && dyn.version == KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
    Json dynamicData = Json::object({{L"transport",transport(dynIo)}, {L"queried",Json::boolean(!capIo.deviceOpenFailed)},
        {L"valid",Json::boolean(dynValid)}, {L"statusFlags",dynValid ? Json::hex(dyn.statusFlags) : Json{}},
        {L"capabilityMask",dynValid ? Json::hex(dyn.capabilityMask) : Json{}},
        {L"lastStatus",dynValid ? Json::hex(static_cast<std::uint32_t>(dyn.lastStatus)) : Json{}},
        {L"fieldCount",dynValid ? Json::number(dyn.fieldCount) : Json{}},
        {L"unavailableReason",dynValid ? Json::string(boundedWide(dyn.unavailableReason,KSW_DYN_REASON_CHARS)) : Json{}}});

    // These dependency lists match the legacy capability computation in
    // dyndata_validate.c.  They are distinct from the V4 missing-item list.
    struct LegacyField { unsigned long id; const wchar_t* name; };
    struct LegacyGroup { const wchar_t* name; unsigned long long mask; const LegacyField* fields; std::size_t count; };
    static constexpr LegacyField processFields[] = {
        {KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID,L"_EPROCESS.UniqueProcessId"},
        {KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS,L"_EPROCESS.ActiveProcessLinks"},
        {KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD,L"_EPROCESS.ThreadListHead"},
        {KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME,L"_EPROCESS.ImageFileName"},
        {KSW_DYN_FIELD_ID_EP_TOKEN,L"_EPROCESS.Token"}};
    static constexpr LegacyField threadFields[] = {
        {KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD,L"_EPROCESS.ThreadListHead"},
        {KSW_DYN_FIELD_ID_KT_PROCESS,L"_KTHREAD.Process"},
        {KSW_DYN_FIELD_ID_ET_CID,L"_ETHREAD.Cid"},
        {KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY,L"_ETHREAD.ThreadListEntry"},
        {KSW_DYN_FIELD_ID_ET_START_ADDRESS,L"_ETHREAD.StartAddress"}};
    static constexpr LegacyField cidFields[] = {
        {KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE,L"PspCidTable"},
        {KSW_DYN_FIELD_ID_HT_TABLE_CODE,L"_HANDLE_TABLE.TableCode"},
        {KSW_DYN_FIELD_ID_HTE_LOW_VALUE,L"_HANDLE_TABLE_ENTRY.LowValue"}};
    static constexpr LegacyGroup groups[] = {
        {L"process-list-fields",KSW_CAP_PROCESS_LIST_FIELDS,processFields,std::size(processFields)},
        {L"thread-list-fields",KSW_CAP_THREAD_LIST_FIELDS,threadFields,std::size(threadFields)},
        {L"cid-table-walk",KSW_CAP_CID_TABLE_WALK,cidFields,std::size(cidFields)}};

    std::vector<std::uint8_t> fieldBuffer(128 * 1024, 0);
    IoResult fieldIo{};
    if (!capIo.deviceOpenFailed) fieldIo = client.deviceIoControl(IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS,nullptr,0,
        fieldBuffer.data(),static_cast<unsigned long>(fieldBuffer.size()));
    constexpr auto fieldOffset = offsetof(KSW_QUERY_DYN_FIELDS_RESPONSE, entries);
    bool fieldValid=false, fieldComplete=false, allGroupFieldsKnown=true, allExpectedFieldsPresent=true, legacyAvailable=true;
    unsigned long fieldCount=0, fieldTotal=0, fieldStride=0;
    if (fieldIo.ok && fieldIo.bytesReturned >= fieldOffset && fieldIo.bytesReturned <= fieldBuffer.size()) {
        const auto* list = reinterpret_cast<const KSW_QUERY_DYN_FIELDS_RESPONSE*>(fieldBuffer.data());
        fieldValid = validList<KSW_DYN_FIELD_ENTRY>(fieldIo,fieldBuffer,fieldOffset,list->version,
            KSWORD_ARK_DYNDATA_PROTOCOL_VERSION,list->size,list->returnedCount,list->totalCount,list->entrySize);
        if (fieldValid) {
            fieldCount=list->returnedCount; fieldTotal=list->totalCount; fieldStride=list->entrySize;
            fieldComplete=fieldCount==fieldTotal;
        }
    }
    std::vector<Json> groupRows;
    for (const auto& group : groups) {
        const bool reportedAvailable = dynValid && (dyn.capabilityMask & group.mask) != 0;
        legacyAvailable &= reportedAvailable;
        bool groupFieldsKnown=fieldValid && fieldComplete;
        std::vector<Json> fields;
        for (std::size_t i=0; i<group.count; ++i) {
            const auto& expected=group.fields[i];
            KSW_DYN_FIELD_ENTRY match{};
            unsigned matches=0;
            for (unsigned long j=0; j<fieldCount; ++j) {
                KSW_DYN_FIELD_ENTRY item{};
                std::memcpy(&item,fieldBuffer.data()+fieldOffset+static_cast<std::size_t>(j)*fieldStride,sizeof(item));
                if (item.fieldId==expected.id) { match=item; ++matches; }
            }
            const bool known=matches==1;
            groupFieldsKnown &= known;
            allExpectedFieldsPresent &= known && (match.flags & KSW_DYN_FIELD_FLAG_PRESENT)!=0;
            fields.push_back(Json::object({{L"id",Json::number(expected.id)}, {L"name",Json::string(expected.name)},
                {L"present",known ? Json::boolean((match.flags & KSW_DYN_FIELD_FLAG_PRESENT)!=0) : Json{}},
                {L"source",known ? Json::string(boundedAnsi(match.sourceName,sizeof(match.sourceName))) : Json{}}}));
        }
        allGroupFieldsKnown &= groupFieldsKnown;
        groupRows.push_back(Json::object({{L"name",Json::string(group.name)}, {L"mask",Json::hex(group.mask)},
            {L"reportedAvailable",dynValid ? Json::boolean(reportedAvailable) : Json{}},
            {L"fieldEvidenceComplete",Json::boolean(groupFieldsKnown)}, {L"fields",Json::array(fields)}}));
    }
    Json legacyFields=Json::object({{L"transport",transport(fieldIo)}, {L"queried",Json::boolean(!capIo.deviceOpenFailed)},
        {L"valid",Json::boolean(fieldValid)}, {L"complete",Json::boolean(fieldComplete && allGroupFieldsKnown)},
        {L"returnedCount",fieldValid ? Json::number(fieldCount) : Json{}},
        {L"totalCount",fieldValid ? Json::number(fieldTotal) : Json{}}, {L"groups",Json::array(groupRows)}});

    std::vector<std::uint8_t> missingBuffer(128 * 1024,0);
    IoResult missingIo{};
    if (!capIo.deviceOpenFailed) missingIo = client.deviceIoControl(IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS,nullptr,0,
        missingBuffer.data(),static_cast<unsigned long>(missingBuffer.size()));
    constexpr auto missingOffset = offsetof(KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE, entries);
    bool missingValid=false, missingComplete=false, missingEmpty=false;
    Json missing = Json::object({{L"transport",transport(missingIo)}, {L"queried",Json::boolean(!capIo.deviceOpenFailed)}, {L"valid",Json::boolean(false)}});
    if (missingIo.ok && missingIo.bytesReturned >= missingOffset && missingIo.bytesReturned <= missingBuffer.size()) {
        const auto* list = reinterpret_cast<const KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE*>(missingBuffer.data());
        missingValid = validList<KSW_DYN_V4_MISSING_ITEM_ENTRY>(missingIo,missingBuffer,missingOffset,
            list->version,KSW_DYN_V4_PROTOCOL_VERSION,list->size,list->returnedCount,list->totalCount,list->entrySize);
        if (missingValid) {
            missingComplete = list->returnedCount == list->totalCount;
            missingEmpty = list->totalCount == 0;
            std::vector<Json> rows;
            for (unsigned long i=0; i<list->returnedCount; ++i) {
                KSW_DYN_V4_MISSING_ITEM_ENTRY item{};
                std::memcpy(&item,missingBuffer.data()+missingOffset+static_cast<std::size_t>(i)*list->entrySize,sizeof(item));
                rows.push_back(Json::object({{L"moduleClassId",Json::number(item.moduleClassId)}, {L"itemId",Json::number(item.itemId)},
                    {L"groupId",Json::number(item.capabilityGroupId)}, {L"missingKind",Json::number(item.missingKind)},
                    {L"name",Json::string(boundedAnsi(item.itemName,sizeof(item.itemName)))},
                    {L"reason",Json::string(boundedAnsi(item.reason,sizeof(item.reason)))}}));
            }
            missing=Json::object({{L"transport",transport(missingIo)}, {L"queried",Json::boolean(true)}, {L"valid",Json::boolean(true)},
                {L"totalCount",Json::number(list->totalCount)}, {L"complete",Json::boolean(missingComplete)}, {L"items",Json::array(rows)}});
        }
    }
    const bool complete = serviceKnown && entry->hasConfig && capValid && capComplete && dynValid && missingValid && missingComplete && fieldComplete && allGroupFieldsKnown;
    const bool healthy = complete && entry->currentState == SERVICE_RUNNING && featuresHealthy && missingEmpty && legacyAvailable && allExpectedFieldsPresent &&
        (dyn.statusFlags & KSW_DYN_STATUS_FLAG_NTOS_ACTIVE) != 0;
    std::vector<std::wstring> diagnostics;
    if (!serviceKnown) diagnostics.push_back(L"SCM service state is unavailable; check service installation and permissions.");
    else if (entry->currentState != SERVICE_RUNNING) diagnostics.push_back(L"KswordARK service is not running. Start it only when authorized, then retry.");
    if (entry && !entry->hasConfig) diagnostics.push_back(L"SCM service image path is unavailable; verify access to service configuration.");
    if (!capValid) diagnostics.push_back(L"Driver capability query failed or returned an incompatible response; verify device access and loaded driver version.");
    if (!dynValid) diagnostics.push_back(L"DynData status is unavailable; check the driver version and run dyn status for details.");
    if (!missingValid) diagnostics.push_back(L"DynData v4 missing-item query is unavailable; this does not imply zero missing items.");
    if (!fieldComplete || !allGroupFieldsKnown) diagnostics.push_back(L"Legacy DynData field evidence is unavailable or incomplete; unknown is not the same as missing.");
    if (fieldComplete && allGroupFieldsKnown && !allExpectedFieldsPresent) diagnostics.push_back(L"One or more legacy crossview dependency fields are not present in the field snapshot.");
    if (dynValid && !legacyAvailable) diagnostics.push_back(L"A legacy crossview field capability is unavailable; compare the listed field evidence and check the exact kernel profile identity.");
    diagnostics.push_back(L"Legacy status, field descriptors and crossview commands are independent snapshots; runtime prerequisites such as exported object types may also prevent a crossview even when fields are present. Win32k capabilities are a separate namespace; inspect window win32k in the intended session.");
    diagnostics.push_back(L"V4 missing items cover the v4 profile only; zero items does not prove legacy capability masks or every feature are complete. Inspect feature reasons, dyn fields and preflight query.");
    return {healthy ? 0 : 6, Json::object({{L"complete",Json::boolean(complete)}, {L"healthy",Json::boolean(healthy)},
        {L"service",serviceData}, {L"capabilities",capability}, {L"dynData",dynamicData}, {L"legacyCrossviewFields",legacyFields}, {L"v4MissingItems",missing}}), diagnostics};
}
}
void registerHealth() {
    addCommand({L"system health", L"KswordCLI.exe system health [--json]",
        L"Summarize read-only driver service, protocol, dynamic symbols and feature availability.",
        L"Optional: --json.",
        L"Does not load or change the driver. Includes legacy process/thread/CID capability masks and field evidence. Each query is an independent snapshot; v4 missing items do not cover legacy or win32k capabilities. Returns 6 for degraded or unavailable evidence.", health});
}
}
