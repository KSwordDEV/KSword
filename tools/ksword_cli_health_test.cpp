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
        dyn->statusFlags = KSW_DYN_STATUS_FLAG_NTOS_ACTIVE; io.bytesReturned = sizeof(*dyn);
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
}
