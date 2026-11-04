// Exercise the real health projection with deterministic service and driver replies.
#include "../KswordCLI/HealthCommand.cpp"
#include <cassert>
#include <cstring>

// The current producer computes the byte count using sizeof(response)-sizeof(row),
// while consumers address the member itself. Guard their ABI agreement.
static_assert(offsetof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE, entries) ==
              sizeof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE) - sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY));
static_assert(offsetof(KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE, entries) ==
              KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE_HEADER_SIZE);
static_assert(offsetof(KSW_QUERY_DYN_FIELDS_RESPONSE, entries) ==
              sizeof(KSW_QUERY_DYN_FIELDS_RESPONSE) - sizeof(KSW_DYN_FIELD_ENTRY));

namespace {
int scenario = 0;
}
namespace ks::r3::service {
ServiceEnumerationResult QuerySingleService(const std::wstring&) {
    ServiceEnumerationResult result;
    if (scenario == 1) { result.win32Error = ERROR_SERVICE_DOES_NOT_EXIST; return result; }
    result.success = true;
    ServiceEntry entry;
    entry.hasStatus = true; entry.hasConfig = true; entry.currentState = SERVICE_RUNNING;
    entry.binaryPath = L"C:\\test\\KswordARK.sys";
    result.entries.push_back(entry);
    return result;
}
}
namespace ksword::ark {
IoResult DriverClient::deviceIoControl(unsigned long code, void*, unsigned long, void* output,
                                      unsigned long capacity, DriverHandle*) const {
    IoResult io{};
    if (scenario == 1) { io.deviceOpenFailed = true; io.win32Error = ERROR_FILE_NOT_FOUND; return io; }
    if (code == IOCTL_KSWORD_ARK_QUERY_DRIVER_CAPABILITIES) {
        constexpr auto offset = offsetof(KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE, entries);
        const auto bytes = offset + sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY);
        assert(capacity >= bytes);
        auto* cap = static_cast<KSWORD_ARK_QUERY_DRIVER_CAPABILITIES_RESPONSE*>(output);
        cap->version = KSWORD_ARK_DRIVER_CAPABILITY_PROTOCOL_VERSION;
        cap->driverProtocolVersion = KSWORD_ARK_DRIVER_PROTOCOL_VERSION;
        cap->size = static_cast<unsigned long>(bytes);
        cap->totalFeatureCount = cap->returnedFeatureCount = 1;
        cap->entrySize = scenario == 2 ? 1 : sizeof(KSWORD_ARK_FEATURE_CAPABILITY_ENTRY);
        cap->entries[0].featureId = 42;
        cap->entries[0].state = scenario == 3 ? KSWORD_ARK_FEATURE_STATE_DEGRADED : KSWORD_ARK_FEATURE_STATE_AVAILABLE;
        strcpy_s(cap->entries[0].featureName, "sample");
        strcpy_s(cap->entries[0].reasonText, "missing dependency");
        io.bytesReturned = static_cast<unsigned long>(bytes);
    } else if (code == IOCTL_KSWORD_ARK_QUERY_DYN_STATUS) {
        auto* dyn = static_cast<KSW_QUERY_DYN_STATUS_RESPONSE*>(output);
        dyn->size = sizeof(*dyn); dyn->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
        dyn->statusFlags = KSW_DYN_STATUS_FLAG_NTOS_ACTIVE;
        dyn->capabilityMask = KSW_CAP_PROCESS_LIST_FIELDS | KSW_CAP_THREAD_LIST_FIELDS | KSW_CAP_CID_TABLE_WALK;
        if (scenario == 5) dyn->capabilityMask &= ~KSW_CAP_PROCESS_LIST_FIELDS;
        io.bytesReturned = sizeof(*dyn);
    } else if (code == IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS) {
        if (scenario == 8) { io.win32Error = ERROR_NOT_SUPPORTED; return io; }
        constexpr unsigned long ids[] = {KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID, KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS,
            KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD, KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME, KSW_DYN_FIELD_ID_EP_TOKEN,
            KSW_DYN_FIELD_ID_KT_PROCESS, KSW_DYN_FIELD_ID_ET_CID, KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY,
            KSW_DYN_FIELD_ID_ET_START_ADDRESS, KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE, KSW_DYN_FIELD_ID_HT_TABLE_CODE,
            KSW_DYN_FIELD_ID_HTE_LOW_VALUE};
        constexpr auto offset=offsetof(KSW_QUERY_DYN_FIELDS_RESPONSE, entries);
        const unsigned long count=scenario == 6 ? 1UL : static_cast<unsigned long>(std::size(ids));
        const auto bytes=offset+count*sizeof(KSW_DYN_FIELD_ENTRY);
        assert(capacity >= bytes);
        auto* fields=static_cast<KSW_QUERY_DYN_FIELDS_RESPONSE*>(output);
        fields->size=static_cast<unsigned long>(bytes); fields->version=KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
        fields->entrySize=sizeof(KSW_DYN_FIELD_ENTRY); fields->returnedCount=count;
        fields->totalCount=static_cast<unsigned long>(std::size(ids));
        for(unsigned long i=0;i<count;++i) {
            fields->entries[i].fieldId=ids[i];
            fields->entries[i].flags=((scenario == 5 || scenario == 7) && ids[i] == KSW_DYN_FIELD_ID_EP_TOKEN) ? 0UL : KSW_DYN_FIELD_FLAG_PRESENT;
            strcpy_s(fields->entries[i].sourceName,"PDB Profile");
        }
        io.bytesReturned=static_cast<unsigned long>(bytes);
    } else if (code == IOCTL_KSWORD_ARK_QUERY_DYN_V4_MISSING_ITEMS) {
        if (scenario == 4) { io.win32Error = ERROR_NOT_SUPPORTED; return io; }
        auto* missing = static_cast<KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE*>(output);
        missing->size = offsetof(KSW_QUERY_DYN_V4_MISSING_ITEMS_RESPONSE, entries);
        missing->version = KSW_DYN_V4_PROTOCOL_VERSION;
        missing->entrySize = sizeof(KSW_DYN_V4_MISSING_ITEM_ENTRY);
        io.bytesReturned = missing->size;
    } else { assert(false); }
    io.ok = true;
    return io;
}
}
int main() {
    using namespace ks::cli;
    Args args;
    auto run = [&] { return health(args); };
    auto good = run();
    assert(good.code == 0 && good.data.text.find(L"\"healthy\":true") != std::wstring::npos);
    scenario = 1;
    auto absent = run();
    assert(absent.code == 6 && absent.data.text.find(L"\"deviceOpenFailed\":true") != std::wstring::npos);
    assert(absent.data.text.find(L"\"queried\":false") != std::wstring::npos);
    scenario = 2;
    auto malformed = run();
    assert(malformed.code == 6 && malformed.data.text.find(L"\"valid\":false") != std::wstring::npos);
    scenario = 3;
    auto degraded = run();
    assert(degraded.code == 6 && degraded.data.text.find(L"missing dependency") != std::wstring::npos);
    scenario = 4;
    auto unsupported = run();
    assert(unsupported.code == 6 && unsupported.data.text.find(L"\"win32Error\":50") != std::wstring::npos);
    scenario = 5;
    auto legacyMissing = run();
    assert(legacyMissing.code == 6 && legacyMissing.data.text.find(L"\"name\":\"process-list-fields\",\"mask\":\"0x8000\",\"reportedAvailable\":false") != std::wstring::npos);
    assert(legacyMissing.data.text.find(L"\"name\":\"_EPROCESS.Token\",\"present\":false") != std::wstring::npos);
    assert(legacyMissing.data.text.find(L"\"v4MissingItems\":{") != std::wstring::npos);
    scenario = 6;
    auto truncated = run();
    scenario = 7;
    auto changed = run();
    assert(changed.code == 6);
    scenario = 8;
    auto fieldsUnsupported = run();
    assert(fieldsUnsupported.code == 6);
    assert(truncated.code == 6 && truncated.data.text.find(L"\"fieldEvidenceComplete\":false") != std::wstring::npos);
    assert(truncated.data.text.find(L"\"name\":\"_EPROCESS.Token\",\"present\":null") != std::wstring::npos);
}
