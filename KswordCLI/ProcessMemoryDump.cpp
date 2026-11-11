#include "R3ProcessShared.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/driver/KswordArkModuleIoctl.h"
#include "../shared/usermode/backend/process/ProcessModulesSupport.h"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>

namespace ks::cli {
namespace {
namespace module_backend = ks::r3::process_detail;
constexpr std::uint32_t kChunkSize = 64U * 1024U;

bool unsupportedError(DWORD error) {
    return error == ERROR_NOT_SUPPORTED || error == ERROR_INVALID_FUNCTION ||
        error == ERROR_CALL_NOT_IMPLEMENTED || error == ERROR_PROC_NOT_FOUND;
}

struct ModuleIdentity {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    std::wstring path;
};

bool findModule(DWORD pid, std::uint64_t base, ModuleIdentity& identity, DWORD& error) {
    bool ok = false;
    std::wstring detail;
    module_backend::detail::ModuleEnumerationEvidence evidence;
    const auto rows = module_backend::detail::CollectModules(pid, ok, detail, &evidence);
    if (!ok || !evidence.complete) {
        error = evidence.win32Error ? evidence.win32Error : ERROR_PARTIAL_COPY;
        return false;
    }
    bool incompleteMatch = false;
    for (const auto& row : rows) {
        if (row.baseAddress == base && row.infoKnown && row.pathKnown && row.imageSize) {
            identity = {row.baseAddress, row.imageSize, row.modulePath};
            return true;
        }
        if (row.moduleHandle == base && (!row.infoKnown || !row.pathKnown || !row.imageSize))
            incompleteMatch = true;
    }
    error = incompleteMatch ? ERROR_PARTIAL_COPY : ERROR_NOT_FOUND;
    return false;
}

bool sameModule(const ModuleIdentity& a, const ModuleIdentity& b) {
    return a.base == b.base && a.size == b.size && _wcsicmp(a.path.c_str(), b.path.c_str()) == 0;
}

// R0 process module inventory is an observed MEM_IMAGE mapping view. It does
// not establish PEB loader membership or claim PE SizeOfImage.
bool findR0Module(const ksword::ark::DriverClient& client, ksword::ark::DriverHandle& device,
                  DWORD pid, std::uint64_t creation, std::uint64_t base,
                  ModuleIdentity& identity, DWORD& error, long& nativeStatus) {
    KSWORD_ARK_ENUM_MODULES_REQUEST request{};
    request.size = sizeof(request);
    request.version = KSWORD_ARK_MODULE_PROTOCOL_VERSION;
    request.source = KSWORD_ARK_MODULE_SOURCE_PROCESS_IMAGE_MAP;
    request.processId = pid;
    request.expectedCreateTime100ns = creation;
    request.filterBase = base;
    request.maxRows = 1;
    constexpr std::size_t header = offsetof(KSWORD_ARK_ENUM_MODULES_RESPONSE, entries);
    std::vector<std::uint8_t> buffer(header + sizeof(KSWORD_ARK_MODULE_ENTRY), 0);
    const auto io = client.deviceIoControl(IOCTL_KSWORD_ARK_ENUM_MODULES, &request, sizeof(request),
        buffer.data(), static_cast<unsigned long>(buffer.size()), &device);
    if (!io.ok) { error = io.win32Error ? io.win32Error : ERROR_GEN_FAILURE; nativeStatus = io.ntStatus; return false; }
    if (io.bytesReturned < header || io.bytesReturned > buffer.size()) { error = ERROR_INVALID_DATA; return false; }
    const auto* response = reinterpret_cast<const KSWORD_ARK_ENUM_MODULES_RESPONSE*>(buffer.data());
    nativeStatus = response->lastStatus;
    if (response->version != request.version || response->source != request.source ||
        response->processId != pid ||
        response->entrySize < sizeof(KSWORD_ARK_MODULE_ENTRY) || response->size < header ||
        response->size > io.bytesReturned || response->returnedCount > 1 ||
        response->returnedCount > (response->size - header) / response->entrySize) {
        error = ERROR_INVALID_DATA; return false;
    }
    if (response->processCreateTime100ns != creation) { error = ERROR_INVALID_PARAMETER; return false; }
    if (response->status != KSWORD_ARK_MODULE_STATUS_COMPLETE || response->flags != 0 || response->lastStatus < 0) {
        error = static_cast<std::uint32_t>(response->lastStatus) == 0xc00000bbU ? ERROR_NOT_SUPPORTED : ERROR_PARTIAL_COPY;
        return false;
    }
    if (!response->returnedCount) { error = ERROR_NOT_FOUND; return false; }
    KSWORD_ARK_MODULE_ENTRY row{};
    std::memcpy(&row, buffer.data() + header, sizeof(row));
    if (row.baseAddress != base || !row.spanBytes ||
        !(row.flags & KSWORD_ARK_MODULE_ROW_PATH_PRESENT) ||
        (row.flags & (KSWORD_ARK_MODULE_ROW_PATH_TRUNCATED | KSWORD_ARK_MODULE_ROW_SPAN_INCOMPLETE))) {
        error = ERROR_PARTIAL_COPY; return false;
    }
    std::size_t length = 0;
    while (length < KSWORD_ARK_MODULE_PATH_CHARS && row.path[length]) ++length;
    if (!length || length == KSWORD_ARK_MODULE_PATH_CHARS) { error = ERROR_PARTIAL_COPY; return false; }
    identity = {row.baseAddress, row.spanBytes, std::wstring(row.path, length)};
    return true;
}

bool fullVerifiedRead(const ksword::ark::VirtualMemoryReadResult& r, DWORD pid,
                      std::uint64_t address, std::uint32_t bytes) {
    return r.io.ok && (r.version == KSWORD_ARK_MEMORY_PROTOCOL_VERSION_V1 || r.version == KSWORD_ARK_MEMORY_PROTOCOL_VERSION_V2) &&
        r.processId == pid && r.requestedBaseAddress == address && r.requestedBytes == bytes &&
        r.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_OK && r.lookupStatus >= 0 && r.copyStatus >= 0 &&
        r.bytesRead == bytes && r.data.size() == bytes;
}

// A temporary file in the destination directory is published only after a
// full read, close, and identity recheck. Existing destinations are not replaced.
struct TemporaryOutput {
    ks::r3::common::UniqueHandle file;
    std::wstring path;
    ~TemporaryOutput() { file.reset(); if (!path.empty()) DeleteFileW(path.c_str()); }
    bool create(const std::wstring& output, DWORD& error) {
        for (unsigned i = 0; i < 64; ++i) {
            path = output + L".ksword-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(i) + L".tmp";
            file.reset(CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW,
                                   FILE_ATTRIBUTE_NORMAL, nullptr));
            if (file.valid()) return true;
            error = GetLastError();
            if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS) break;
        }
        path.clear();
        return false;
    }
};

Result dump(const Args& args, bool module) {
    const auto backend = args.get(L"--backend", L"r3");
    const auto output = args.require(L"--output");
    const auto pid = args.u32(L"--pid");
    (void)args.require(L"--pid");
    const auto address = args.integer(module ? L"--base" : L"--address");
    (void)args.require(module ? L"--base" : L"--address");
    if (!pid || !address) throw std::invalid_argument("pid and base/address must be positive");
    if (backend != L"r0" && backend != L"r3") throw std::invalid_argument("--backend must be r0 or r3");
    if (args.has(L"--creation-time") && !args.integer(L"--creation-time")) throw std::invalid_argument("--creation-time must be positive");

    // R3 retains a query handle. R0 can operate on a kernel-only target when
    // the caller supplies a real creation time from the R0 process inventory;
    // each verified read compares it against the referenced EPROCESS in kernel.
    std::unique_ptr<process::Lease> lease;
    std::uint64_t creation = args.integer(L"--creation-time", 0);
    if (backend == L"r3" || !creation) {
        lease = std::make_unique<process::Lease>(args, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE |
            (backend == L"r3" ? PROCESS_VM_READ : 0));
        if (!lease->matches || !lease->alive()) return {3, Json::object({{L"target",lease->json()}}),
            {backend == L"r0" ? L"Supply a real --creation-time from R0 process enumeration when the process cannot be opened in R3." :
                L"The process identity could not be retained, did not match, or has exited."}};
        creation = lease->creationTime;
    }
    const auto target = [&] { return Json::object({{L"pid",Json::number(pid)}, {L"creationTime",Json::count(creation)},
        {L"identitySource",Json::string(backend == L"r0" ? L"R0 verified read" : L"retained R3 process handle")},
        {L"r3HandleRetained",Json::boolean(lease && lease->handle.valid())}}); };
    const ksword::ark::DriverClient driver;
    ksword::ark::DriverHandle device;
    if (backend == L"r0") {
        device = driver.openSilently(GENERIC_READ | GENERIC_WRITE);
        if (!device.isValid()) return {2, Json::object({{L"target",target()}, {L"output",Json::string(output)},
            {L"win32Error",Json::number(GetLastError())}}), {L"Could not open the KswordARK device."}};
    }

    ModuleIdentity selected;
    DWORD error = ERROR_SUCCESS;
    long moduleStatus = 0;
    std::uint64_t size = 0;
    if (module) {
        const bool found = backend == L"r0" ? findR0Module(driver, device, pid, creation, address, selected, error, moduleStatus) :
            findModule(pid, address, selected, error);
        if (!found)
            return {error == ERROR_INVALID_DATA ? 4 : error == ERROR_PARTIAL_COPY ? 6 : unsupportedError(error) ? 5 : 3,
                Json::object({{L"target",target()}, {L"win32Error",Json::number(error)},
                    {L"moduleQueryNtStatus",backend == L"r0" ? Json::hex(static_cast<std::uint32_t>(moduleStatus)) : Json{}}}),
                {backend == L"r0" ? L"A complete R0 MEM_IMAGE mapping with matching base, span, and path is required." :
                    L"A complete R3 module snapshot with matching base, size, and path is required."}};
        if ((args.has(L"--image-size") && args.integer(L"--image-size") != selected.size) ||
            (args.has(L"--module-path") && _wcsicmp(args.require(L"--module-path").c_str(), selected.path.c_str()) != 0))
            return {3, Json::object({{L"target",target()}}), {L"Module identity does not match the expected path or size."}};
        size = selected.size;
    } else {
        size = args.integer(L"--size");
        (void)args.require(L"--size");
    }
    if (!size || address > (std::numeric_limits<std::uint64_t>::max)() - size ||
        address + size - 1 > (std::numeric_limits<std::uintptr_t>::max)())
        throw std::invalid_argument("invalid or overflowing address range");

    TemporaryOutput temporary;
    if (!temporary.create(output, error)) return {3, Json::object({{L"target",target()},
        {L"output",Json::string(output)}, {L"win32Error",Json::number(error)}}),
        {L"Could not create a temporary file next to the destination."}};

    Cancellation cancel;
    std::vector<std::uint8_t> buffer(kChunkSize);
    std::uint64_t completed = 0;
    long nativeStatus = 0, lookupStatus = 0;
    std::uint32_t readStatus = 0;
    bool cancelled = false, identityChanged = false, writeError = false, kernelIdentityVerified = false;
    while (completed < size) {
        if (cancel.token->load(std::memory_order_relaxed)) { cancelled = true; break; }
        if (lease && !lease->alive()) { identityChanged = true; break; }
        const auto chunk = static_cast<std::uint32_t>((std::min<std::uint64_t>)(kChunkSize, size - completed));
        const auto current = address + completed;
        bool readOk = false;
        if (backend == L"r3") {
            SIZE_T read = 0;
            const BOOL ok = ReadProcessMemory(lease->handle.get(), reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(current)),
                                              buffer.data(), chunk, &read);
            readOk = ok && read == chunk;
            if (!readOk) error = ok ? ERROR_PARTIAL_COPY : GetLastError();
        } else {
            const auto r = driver.readVirtualMemoryVerified(pid, creation, current, chunk, 0, &device);
            readStatus = r.readStatus; nativeStatus = r.copyStatus; lookupStatus = r.lookupStatus;
            readOk = fullVerifiedRead(r, pid, current, chunk);
            kernelIdentityVerified = readOk;
            if (readOk) std::copy(r.data.begin(), r.data.end(), buffer.begin());
            else { error = r.io.win32Error ? r.io.win32Error : ERROR_PARTIAL_COPY; }
        }
        if (!readOk) break;
        DWORD written = 0;
        const BOOL wrote = WriteFile(temporary.file.get(), buffer.data(), chunk, &written, nullptr);
        if (!wrote || written != chunk) {
            error = wrote ? ERROR_WRITE_FAULT : GetLastError();
            writeError = true; break;
        }
        completed += chunk;
    }

    bool identityValid = !identityChanged && (!lease || lease->alive()) &&
        (backend != L"r0" || kernelIdentityVerified);
    if (backend == L"r0" && identityValid && !cancelled && completed == size) {
        // Recheck the target identity immediately before publication. The
        // verified IOCTL binds each read to an EPROCESS; this is not an atomic
        // snapshot of changing memory, nor a process lifetime lease.
        const auto check = driver.readVirtualMemoryVerified(pid, creation, address + size - 1, 1, 0, &device);
        identityValid = fullVerifiedRead(check, pid, address + size - 1, 1);
        if (!identityValid) {
            readStatus = check.readStatus; nativeStatus = check.copyStatus; lookupStatus = check.lookupStatus;
            error = check.io.win32Error ? check.io.win32Error : ERROR_PARTIAL_COPY;
        }
    }
    if (module && identityValid && completed == size) {
        ModuleIdentity after;
        const bool found = backend == L"r0" ? findR0Module(driver, device, pid, creation, address, after, error, moduleStatus) :
            findModule(pid, address, after, error);
        identityValid = found && sameModule(selected, after) && (!lease || lease->alive());
    }
    const bool readComplete = completed == size && !cancelled && identityValid;
    bool published = false;
    if (readComplete) {
        HANDLE file = temporary.file.release();
        if (!FlushFileBuffers(file)) error = GetLastError();
        if (!CloseHandle(file) && !error) error = GetLastError();
        if (!error) {
            if (MoveFileExW(temporary.path.c_str(), output.c_str(), MOVEFILE_WRITE_THROUGH)) {
                published = true;
                temporary.path.clear();
            } else error = GetLastError();
        }
    }
    const bool complete = readComplete && published;
    bool temporaryRemoved = true;
    DWORD cleanupError = ERROR_SUCCESS;
    if (!published && !temporary.path.empty()) {
        temporary.file.reset();
        if (DeleteFileW(temporary.path.c_str())) temporary.path.clear();
        else { cleanupError = GetLastError(); temporaryRemoved = false; }
    }
    const int code = complete ? 0 : error == ERROR_INVALID_DATA ? 4 : (completed || cancelled || identityChanged) ? 6 :
        (unsupportedError(error) ? 5 : 3);
    return {code, Json::object({{L"target",target()}, {L"source",Json::string(backend)},
        {L"address",Json::hex(address)}, {L"requestedBytes",Json::count(size)}, {L"writtenBytes",Json::count(completed)},
        {L"output",Json::string(output)}, {L"modulePath",module ? Json::string(selected.path) : Json{}},
        {L"moduleRangeSource",module ? Json::string(backend == L"r0" ? L"R0 MEM_IMAGE observed span" : L"R3 module image size") : Json{}},
        {L"moduleQueryNtStatus",module && backend == L"r0" ? Json::hex(static_cast<std::uint32_t>(moduleStatus)) : Json{}},
        {L"complete",Json::boolean(complete)}, {L"published",Json::boolean(published)},
        {L"identityValid",Json::boolean(identityValid)}, {L"cancelled",Json::boolean(cancelled)},
        {L"win32Error",Json::number(error)}, {L"readStatus",backend == L"r0" ? Json::number(readStatus) : Json{}},
        {L"copyNtStatus",backend == L"r0" ? Json::hex(static_cast<std::uint32_t>(nativeStatus)) : Json{}},
        {L"lookupNtStatus",backend == L"r0" ? Json::hex(static_cast<std::uint32_t>(lookupStatus)) : Json{}},
        {L"writeFailed",Json::boolean(writeError)}, {L"temporaryRemoved",Json::boolean(temporaryRemoved)},
        {L"temporaryPath",temporaryRemoved ? Json{} : Json::string(temporary.path)},
        {L"temporaryCleanupWin32Error",Json::number(cleanupError)}}), complete ? std::vector<std::wstring>{
            L"Raw memory bytes; this does not reconstruct a PE image. Memory can change while being read."} :
            std::vector<std::wstring>{temporaryRemoved ?
                L"No output was published: the read, identity verification, or file operation was incomplete." :
                L"No output was published; the partial temporary file could not be removed and its path is reported."}};
}
}

void registerProcessMemoryDump() {
    const auto notes = L"Reads in 64 KiB chunks without zero filling; publishes a new output file only after all bytes, file close and identity checks succeed. Existing files are never replaced. R0 binds every read to the supplied or observed process creation time using the verified-read IOCTL; when R3 cannot open the process, --creation-time is required. R0 module ranges are observed MEM_IMAGE mapping spans, not PEB loader membership or PE SizeOfImage; R3 uses its module snapshot. No PE reconstruction or atomic memory snapshot is implied. Missing/partial evidence is never published as complete.";
    Command region{L"process memory dump",L"KswordCLI.exe process memory dump --pid PID --address VA --size BYTES --output PATH [--creation-time FILETIME] [--backend r0|r3] [--json]",
        L"Save an entire process memory range as raw bytes.",L"Required: --pid, --address, --size, --output. Optional: --creation-time, --backend r0|r3 (r3), --json.",notes,
        [](const Args& args){return dump(args,false);}};
    region.supportsR0 = true;
    addCommand(std::move(region));
    Command module{L"process module dump",L"KswordCLI.exe process module dump --pid PID --base ADDRESS --output PATH [--creation-time FILETIME] [--module-path PATH] [--image-size N] [--backend r0|r3] [--json]",
        L"Save a selected module's complete memory range as raw bytes.",L"Required: --pid, --base, --output. Optional: --creation-time, --module-path, --image-size, --backend r0|r3 (r3), --json.",notes,
        [](const Args& args){return dump(args,true);}};
    module.supportsR0 = true;
    addCommand(std::move(module));
}
}
