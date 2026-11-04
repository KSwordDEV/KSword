// Exercise the production CLI against deterministic buffered module replies.
#include "../KswordCLI/R0Modules.cpp"
#include <cassert>
#include <cstring>

namespace { int scenario = 0; }
namespace ksword::ark {
IoResult DriverClient::deviceIoControl(unsigned long code, void* input, unsigned long inputSize,
    void* output, unsigned long capacity, DriverHandle*) const {
    IoResult result{};
    assert(code == IOCTL_KSWORD_ARK_ENUM_MODULES);
    assert(inputSize == sizeof(KSWORD_ARK_ENUM_MODULES_REQUEST));
    const auto& request = *static_cast<KSWORD_ARK_ENUM_MODULES_REQUEST*>(input);
    if (scenario == 1) { result.deviceOpenFailed = true; result.win32Error = ERROR_FILE_NOT_FOUND; return result; }
    constexpr auto header = offsetof(KSWORD_ARK_ENUM_MODULES_RESPONSE, entries);
    assert(capacity >= header + sizeof(KSWORD_ARK_MODULE_ENTRY));
    auto* response = static_cast<KSWORD_ARK_ENUM_MODULES_RESPONSE*>(output);
    response->size = static_cast<unsigned long>(header + sizeof(KSWORD_ARK_MODULE_ENTRY));
    response->version = request.version;
    response->source = request.source;
    response->entrySize = scenario == 2 ? 1 : sizeof(KSWORD_ARK_MODULE_ENTRY);
    response->status = scenario == 3 ? KSWORD_ARK_MODULE_STATUS_PARTIAL : KSWORD_ARK_MODULE_STATUS_COMPLETE;
    response->returnedCount = 1;
    response->processId = request.processId;
    response->processCreateTime100ns = 123456;
    response->totalCount = 1;
    response->entries[0].baseAddress = 0x1000;
    response->entries[0].spanBytes = 0x2000;
    response->entries[0].flags = KSWORD_ARK_MODULE_ROW_PATH_PRESENT;
    wcscpy_s(response->entries[0].path, L"\\Device\\Volume\\sample.dll");
    if (scenario == 3) { response->flags = KSWORD_ARK_MODULE_FLAG_MORE; response->nextCursor = 0x4000; }
    result.ok = true;
    result.bytesReturned = response->size;
    return result;
}
}

int main() {
    ks::cli::Args kernel;
    auto result = ks::cli::enumerate(kernel, false);
    assert(result.code == 0 && result.data.text.find(L"sample.dll") != std::wstring::npos);
    ks::cli::Args process; process.values[L"--pid"] = L"123";
    result = ks::cli::enumerate(process, true);
    assert(result.code == 0 && result.data.text.find(L"123456") != std::wstring::npos);
    scenario = 1; result = ks::cli::enumerate(process, true); assert(result.code == 2);
    scenario = 2; result = ks::cli::enumerate(process, true); assert(result.code == 4);
    scenario = 3; result = ks::cli::enumerate(process, true);
    assert(result.code == 6 && result.data.text.find(L"0x4000") != std::wstring::npos);
    bool rejected = false; process.values[L"--cursor"] = L"0x4000";
    try { (void)ks::cli::enumerate(process, true); } catch (const std::invalid_argument&) { rejected = true; }
    assert(rejected);
    return 0;
}
