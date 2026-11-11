#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/driver/KswordArkModuleIoctl.h"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <utility>

namespace ks::cli {
namespace {
std::wstring boundedPath(const wchar_t* value, std::size_t capacity) {
    std::size_t length = 0;
    while (length < capacity && value[length]) ++length;
    return std::wstring(value, length);
}

Result enumerate(const Args& args, bool process) {
    KSWORD_ARK_ENUM_MODULES_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_MODULE_PROTOCOL_VERSION;
    request.source = process ? KSWORD_ARK_MODULE_SOURCE_PROCESS_IMAGE_MAP : KSWORD_ARK_MODULE_SOURCE_KERNEL_SNAPSHOT;
    request.maxRows = args.u32(L"--max-rows", KSWORD_ARK_MODULE_DEFAULT_ROWS);
    request.cursor = args.integer(L"--cursor", 0);
    request.filterBase = args.integer(L"--base", 0);
    if (!request.maxRows || request.maxRows > KSWORD_ARK_MODULE_MAX_ROWS) throw std::invalid_argument("--max-rows must be 1..512");
    if (args.has(L"--base") && !request.filterBase) throw std::invalid_argument("--base must be nonzero");
    if (request.cursor && request.filterBase) throw std::invalid_argument("--cursor and --base cannot be combined");
    if (process) {
        request.processId = args.u32(L"--pid");
        (void)args.require(L"--pid");
        request.expectedCreateTime100ns = args.integer(L"--creation-time", 0);
        if (!request.processId) throw std::invalid_argument("--pid must be nonzero");
        if (request.cursor && !request.expectedCreateTime100ns) throw std::invalid_argument("--creation-time is required with --cursor");
    }
    constexpr std::size_t header = offsetof(KSWORD_ARK_ENUM_MODULES_RESPONSE, entries);
    std::vector<std::uint8_t> buffer(header + static_cast<std::size_t>(request.maxRows) * sizeof(KSWORD_ARK_MODULE_ENTRY), 0);
    const auto io = ksword::ark::DriverClient().deviceIoControl(IOCTL_KSWORD_ARK_ENUM_MODULES,
        &request, sizeof(request), buffer.data(), static_cast<unsigned long>(buffer.size()));
    if (!io.ok) {
        const int code = io.deviceOpenFailed ? 2 : io.win32Error == ERROR_NOT_SUPPORTED || io.win32Error == ERROR_INVALID_FUNCTION ? 5 : 3;
        return {code, Json::object({{L"win32Error", Json::number(io.win32Error)}, {L"deviceOpenFailed", Json::boolean(io.deviceOpenFailed)}}),
            {L"The R0 module enumeration request could not be completed; verify driver version and access."}};
    }
    if (io.bytesReturned < header || io.bytesReturned > buffer.size()) return {4, Json::object({}), {L"Invalid module response length."}};
    const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_MODULES_RESPONSE*>(buffer.data());
    constexpr std::uint32_t knownFlags = KSWORD_ARK_MODULE_FLAG_MORE | KSWORD_ARK_MODULE_FLAG_PATH_UNAVAILABLE |
        KSWORD_ARK_MODULE_FLAG_SCAN_BUDGET | KSWORD_ARK_MODULE_FLAG_PROCESS_EXITED;
    if (response->version != request.version || response->source != request.source || response->status > KSWORD_ARK_MODULE_STATUS_INVALID ||
        (response->flags & ~knownFlags) != 0 || response->entrySize < sizeof(KSWORD_ARK_MODULE_ENTRY) ||
        response->size < header || response->size > io.bytesReturned || response->returnedCount > request.maxRows ||
        response->returnedCount > (response->size - header) / response->entrySize ||
        ((response->flags & KSWORD_ARK_MODULE_FLAG_MORE) != 0 && !response->nextCursor) ||
        (process && request.expectedCreateTime100ns && response->status == KSWORD_ARK_MODULE_STATUS_COMPLETE &&
         response->processCreateTime100ns != request.expectedCreateTime100ns))
        return {4, Json::object({}), {L"Incompatible or malformed R0 module response."}};
    std::vector<Json> rows;
    for (std::uint32_t i = 0; i < response->returnedCount; ++i) {
        KSWORD_ARK_MODULE_ENTRY row{};
        std::memcpy(&row, buffer.data() + header + static_cast<std::size_t>(i) * response->entrySize, sizeof(row));
        const bool pathKnown = (row.flags & KSWORD_ARK_MODULE_ROW_PATH_PRESENT) != 0;
        const auto path = pathKnown ? boundedPath(row.path, KSWORD_ARK_MODULE_PATH_CHARS) : std::wstring{};
        const auto separator = path.find_last_of(L"\\/");
        const auto name = separator == std::wstring::npos ? path : path.substr(separator + 1);
        rows.push_back(Json::object({{L"base", Json::hex(row.baseAddress)}, {L"spanBytes", Json::count(row.spanBytes)},
            {L"path", pathKnown ? Json::string(path) : Json{}}, {L"name", pathKnown ? Json::string(name) : Json{}},
            {L"flags", Json::hex(row.flags)}, {L"nativeFlags", Json::hex(row.nativeFlags)},
            {L"pathNtStatus", Json::hex(static_cast<std::uint32_t>(row.pathStatus))},
            {L"pathComplete", Json::boolean(pathKnown && !(row.flags & KSWORD_ARK_MODULE_ROW_PATH_TRUNCATED))},
            {L"spanComplete", Json::boolean(!(row.flags & KSWORD_ARK_MODULE_ROW_SPAN_INCOMPLETE))}}));
    }
    const bool complete = response->status == KSWORD_ARK_MODULE_STATUS_COMPLETE && response->flags == 0;
    int code = complete ? 0 : response->status == KSWORD_ARK_MODULE_STATUS_PARTIAL ? 6 :
        static_cast<std::uint32_t>(response->lastStatus) == 0xc00000bbU ? 5 : 3;
    if (complete && request.filterBase && rows.empty()) code = 3;
    std::vector<std::wstring> diagnostics;
    if (process) diagnostics.push_back(L"R0 ZwQueryVirtualMemory MEM_IMAGE mappings, not a PEB loader list or an independent VAD view. spanBytes is the observed mapped span, not PE SizeOfImage. Each page is a separate snapshot.");
    else diagnostics.push_back(L"R0 SystemModuleInformation snapshot; it is not an independent PsLoadedModuleList or hidden-module cross-view. Each page is a separate snapshot.");
    if (!complete) diagnostics.push_back(L"Inspect native status, flags, and nextCursor; incomplete fields or a bounded page are not a complete inventory.");
    if (request.filterBase && rows.empty() && complete) diagnostics.push_back(L"The requested exact image base was not found in this snapshot.");
    return {code, Json::object({{L"source", Json::string(process ? L"R0 ZwQueryVirtualMemory MEM_IMAGE" : L"R0 SystemModuleInformation")},
        {L"protocolVersion", Json::number(response->version)}, {L"queryStatus", Json::number(response->status)},
        {L"ntStatus", Json::hex(static_cast<std::uint32_t>(response->lastStatus))}, {L"flags", Json::hex(response->flags)},
        {L"processId", process ? Json::number(response->processId) : Json{}},
        {L"creationTime", process && response->processCreateTime100ns ? Json::count(response->processCreateTime100ns) : Json{}},
        {L"totalCount", process ? Json{} : Json::number(response->totalCount)}, {L"visitedCount", Json::number(response->visitedCount)},
        {L"returnedCount", Json::number(response->returnedCount)}, {L"complete", Json::boolean(complete)},
        {L"nextCursor", response->nextCursor ? Json::hex(response->nextCursor) : Json{}}, {L"modules", Json::array(rows)}}), diagnostics};
}
}

void registerR0Modules() {
    const auto add = [](bool process) {
        const std::wstring path = process ? L"r0 process-modules" : L"r0 kernel-modules";
        Command command{path,
            process ? L"KswordCLI.exe r0 process-modules --pid PID [--creation-time FILETIME] [--cursor VA] [--base VA] [--max-rows N] [--backend r0] [--json]" :
                L"KswordCLI.exe r0 kernel-modules [--cursor INDEX] [--base VA] [--max-rows N] [--backend r0] [--json]",
            process ? L"Enumerate process image mappings in R0." : L"Enumerate the loaded kernel module snapshot in R0.",
            process ? L"Required: --pid. Optional: --creation-time (required with --cursor), --cursor, --base, --max-rows (1..512), --backend r0, --json." :
                L"Optional: --cursor, --base, --max-rows (1..512), --backend r0, --json.",
            process ? L"R0 ZwQueryVirtualMemory MEM_IMAGE view; base identifies an exact image. Returned creationTime binds later cursor pages. This is not an independent PEB or VAD enumeration; span is observed mapping coverage, not PE SizeOfImage." :
                L"R0 SystemModuleInformation snapshot; base identifies one exact loaded image. Snapshot pages can change between calls and are not an independent hidden-module view.",
            [process](const Args& args) { return enumerate(args, process); }};
        command.supportsR0 = true;
        command.supportsR3 = false;
        command.defaultBackend = L"r0";
        addCommand(std::move(command));
    };
    add(false);
    add(true);
}
}
