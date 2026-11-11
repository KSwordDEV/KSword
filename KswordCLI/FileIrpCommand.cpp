#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cwctype>
#include <stdexcept>

namespace ks::cli {
namespace {
using ksword::ark::FileIrpSubmitRequestParams;
using ksword::ark::FileIrpSubmitResult;

std::wstring nativePath(std::wstring path) {
    if (path.empty()) throw std::invalid_argument("--path must be nonempty");
    std::replace(path.begin(), path.end(), L'/', L'\\');
    const auto starts = [&](const wchar_t* value) { const std::wstring prefix(value); return path.size() >= prefix.size() && _wcsnicmp(path.c_str(), prefix.c_str(), prefix.size()) == 0; };
    if (starts(L"\\??\\") || starts(L"\\Device\\")) return path;
    if (starts(L"\\\\?\\UNC\\")) return L"\\??\\UNC\\" + path.substr(8);
    if (starts(L"\\\\?\\")) return L"\\??\\" + path.substr(4);
    if (starts(L"\\\\")) return L"\\??\\UNC\\" + path.substr(2);
    if (path.size() < 3 || !std::iswalpha(path[0]) || path[1] != L':' || path[2] != L'\\')
        throw std::invalid_argument("--path must be an absolute DOS, UNC or native NT path");
    return L"\\??\\" + path;
}

int transportCode(const FileIrpSubmitResult& result) {
    if (result.io.deviceOpenFailed) return 2;
    if (result.unsupported || result.io.win32Error == ERROR_NOT_SUPPORTED || result.io.win32Error == ERROR_INVALID_FUNCTION) return 5;
    if (result.io.win32Error == ERROR_INVALID_DATA || result.io.win32Error == ERROR_REVISION_MISMATCH) return 4;
    return 3;
}

Json stageStatus(const FileIrpSubmitResult& result, std::uint32_t stage, long status) {
    return (result.stageFlags & stage) != 0 ? Json::hex(static_cast<std::uint32_t>(status)) : Json{};
}

bool completedSuccessfully(long status) {
    // STATUS_TIMEOUT and STATUS_PENDING are informational NTSTATUS values, but
    // neither says the requested operation completed successfully.
    return status >= 0 && status != 0x102 && status != 0x103;
}

Result submit(const Args& args) {
    (void)args.require(L"--confirm");
    FileIrpSubmitRequestParams request{};
    request.ntPath = nativePath(args.require(L"--path"));
    request.majorFunction = args.u32(L"--major"); (void)args.require(L"--major");
    request.minorFunction = args.u32(L"--minor", 0);
    request.targetLayer = args.u32(L"--layer", KSWORD_ARK_FILE_IRP_LAYER_RELATED);
    request.flags = args.u32(L"--flags", 0);
    request.timeoutMs = args.u32(L"--timeout-ms", 0);
    request.desiredAccess = args.u32(L"--access", 0);
    request.shareAccess = args.u32(L"--share", 0);
    request.createDisposition = args.u32(L"--disposition", 0);
    request.createOptions = args.u32(L"--create-options", 0);
    request.fileAttributes = args.u32(L"--attributes", 0);
    request.informationClass = args.u32(L"--information-class", 0);
    request.controlCode = args.u32(L"--control-code", 0);
    request.securityInformation = args.u32(L"--security-information", 0);
    request.lockKey = args.u32(L"--lock-key", 0);
    request.outputBytes = args.u32(L"--output-bytes", 0);
    request.byteOffset = args.integer(L"--offset", 0);
    request.lockLength = args.integer(L"--lock-length", 0);
    request.pattern = args.get(L"--pattern");
    const auto dangerous = args.u32(L"--allow-dangerous", 0);
    if (dangerous > 1) throw std::invalid_argument("--allow-dangerous must be 0 or 1");
    request.uiConfirmed = true;
    request.allowDangerous = dangerous == 1;
    if ((request.flags & (KSWORD_ARK_FILE_IRP_FLAG_UI_CONFIRMED | KSWORD_ARK_FILE_IRP_FLAG_ALLOW_DANGEROUS)) != 0)
        throw std::invalid_argument("confirmation and dangerous flags must use --confirm and --allow-dangerous");
    if (request.majorFunction >= KSWORD_ARK_FILE_IRP_MAJOR_COUNT || request.targetLayer > KSWORD_ARK_FILE_IRP_LAYER_MAX ||
        request.outputBytes > KSWORD_ARK_FILE_IRP_MAX_OUTPUT_BYTES || request.timeoutMs > KSWORD_ARK_FILE_IRP_MAX_TIMEOUT_MS ||
        request.ntPath.size() >= KSWORD_ARK_FILE_IRP_PATH_MAX_CHARS || request.pattern.size() >= KSWORD_ARK_FILE_IRP_NAME_MAX_CHARS)
        throw std::invalid_argument("IRP parameter exceeds protocol bounds");
    if (args.has(L"--input-hex") && args.has(L"--input-file")) throw std::invalid_argument("choose only one input payload");
    if (args.has(L"--input-hex")) request.inputData = parseHexPayload(args.get(L"--input-hex"));
    if (args.has(L"--input-file")) {
        const auto file = readPayloadFile(args.get(L"--input-file"));
        if (file.win32Error) return {3, Json::object({{L"inputWin32Error", Json::number(file.win32Error)}}), {L"Input payload could not be read; no IRP was submitted."}};
        request.inputData = file.bytes;
    }
    if (request.inputData.size() > KSWORD_ARK_FILE_IRP_MAX_INPUT_BYTES) throw std::invalid_argument("IRP input exceeds protocol limit");

    const auto result = ksword::ark::DriverClient().submitFileIrp(request);
    const bool create = (result.stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CREATE) != 0;
    const bool operation = (result.stageFlags & KSWORD_ARK_FILE_IRP_STAGE_OPERATION) != 0;
    const bool cleanup = (result.stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLEANUP) != 0;
    const bool close = (result.stageFlags & KSWORD_ARK_FILE_IRP_STAGE_CLOSE) != 0;
    const bool createOnly = request.majorFunction == 0 || (request.flags & KSWORD_ARK_FILE_IRP_FLAG_CREATE_ONLY) != 0;
    // IoStatus.Information on WRITE is the byte count, not output-buffer use.
    const bool truncated = request.outputBytes != 0 && (result.stageFlags & KSWORD_ARK_FILE_IRP_STAGE_OUTPUT_TRUNCATED) != 0;
    const bool shortWrite = operation && request.majorFunction == 4 && completedSuccessfully(result.operationStatus) && result.information < request.inputData.size();
    const bool shortRead = operation && request.majorFunction == 3 && completedSuccessfully(result.operationStatus) && result.information < request.outputBytes;
    const bool operationOk = create && completedSuccessfully(result.createStatus) && (createOnly || (operation && completedSuccessfully(result.operationStatus)));
    const bool cleanupOk = (!cleanup || completedSuccessfully(result.cleanupStatus)) && close && completedSuccessfully(result.closeStatus);
    int code = 0;
    if (!result.io.ok) code = transportCode(result);
    else if (result.status == KSWORD_ARK_FILE_IRP_STATUS_LAYER_UNAVAILABLE || result.status == KSWORD_ARK_FILE_IRP_STATUS_MAJOR_NOT_ALLOWED) code = 5;
    else if (result.status == KSWORD_ARK_FILE_IRP_STATUS_BUFFER_TOO_SMALL) code = 6;
    else if (result.status != KSWORD_ARK_FILE_IRP_STATUS_OK || !operationOk) code = 3;
    else if (!cleanupOk || truncated || shortWrite || shortRead) code = 6;

    const auto& io = result.io;
    return {code, Json::object({{L"path", Json::string(request.ntPath)}, {L"requestedMajor", Json::number(request.majorFunction)},
        {L"requestedMinor", Json::number(request.minorFunction)}, {L"returnedMajor", result.io.ok ? Json::number(result.majorFunction) : Json{}},
        {L"returnedMinor", result.io.ok ? Json::number(result.minorFunction) : Json{}}, {L"requestedLayer", Json::number(request.targetLayer)},
        {L"resolvedLayer", result.io.ok ? Json::number(result.resolvedLayer) : Json{}}, {L"protocolStatus", result.io.ok ? Json::number(result.status) : Json{}},
        {L"stageFlags", result.io.ok ? Json::hex(result.stageFlags) : Json{}}, {L"createNtStatus", stageStatus(result, KSWORD_ARK_FILE_IRP_STAGE_CREATE, result.createStatus)},
        {L"operationNtStatus", stageStatus(result, KSWORD_ARK_FILE_IRP_STAGE_OPERATION, result.operationStatus)},
        {L"cleanupNtStatus", stageStatus(result, KSWORD_ARK_FILE_IRP_STAGE_CLEANUP, result.cleanupStatus)},
        {L"closeNtStatus", stageStatus(result, KSWORD_ARK_FILE_IRP_STAGE_CLOSE, result.closeStatus)},
        {L"information", operation ? Json::count(result.information) : Json{}}, {L"inputBytes", Json::count(request.inputData.size())},
        {L"requestedOutputBytes", Json::number(request.outputBytes)}, {L"returnedOutputBytes", Json::count(result.outputData.size())},
        {L"outputHex", result.io.ok ? Json::bytes(result.outputData, result.outputData.size()) : Json{}},
        {L"truncated", result.io.ok ? Json::boolean(truncated) : Json{}},
        {L"shortRead", operation && request.majorFunction == 3 && completedSuccessfully(result.operationStatus) ? Json::boolean(shortRead) : Json{}},
        {L"shortWrite", operation && request.majorFunction == 4 && completedSuccessfully(result.operationStatus) ? Json::boolean(shortWrite) : Json{}},
        {L"targetDevice", result.io.ok ? Json::hex(result.targetDeviceAddress) : Json{}}, {L"targetDriver", result.io.ok ? Json::hex(result.targetDriverAddress) : Json{}},
        {L"relatedDevice", result.io.ok ? Json::hex(result.relatedDeviceAddress) : Json{}}, {L"baseFsDevice", result.io.ok ? Json::hex(result.baseFsDeviceAddress) : Json{}},
        {L"vpbDevice", result.io.ok ? Json::hex(result.vpbDeviceAddress) : Json{}}, {L"fileObject", result.io.ok ? Json::hex(result.fileObjectAddress) : Json{}},
        {L"dispatch", result.io.ok ? Json::hex(result.dispatchAddress) : Json{}}, {L"stackSize", result.io.ok ? Json::number(result.targetStackSize) : Json{}},
        {L"targetDeviceFlags", result.io.ok ? Json::hex(result.targetDeviceFlags) : Json{}}, {L"driverName", result.io.ok ? Json::string(result.driverName) : Json{}},
        {L"deviceName", result.io.ok ? Json::string(result.deviceName) : Json{}}, {L"transportOk", Json::boolean(io.ok)}, {L"deviceOpenFailed", Json::boolean(io.deviceOpenFailed)},
        {L"win32Error", Json::number(io.win32Error)}}), {L"CREATE is followed by the requested major and cleanup/close; the driver validates major-specific fields and confirmation. Timeout or failure may leave partial effects; do not retry without checking the target."}};
}
}

void registerFileIrp() {
    Command cmd{L"file irp submit", L"KswordCLI.exe file irp submit --path PATH --major N --confirm [--minor N] [--layer N] [--flags N] [--timeout-ms N] [--access N] [--share N] [--disposition N] [--create-options N] [--attributes N] [--information-class N] [--control-code N] [--security-information N] [--offset N] [--lock-key N] [--lock-length N] [--pattern TEXT] [--input-hex HEX | --input-file PATH] [--output-bytes N] [--allow-dangerous 0|1] [--backend r0] [--json]",
        L"Construct one file-system IRP against the selected driver stack layer.",
        L"Required: --path, --major (0..27), --confirm. Optional: all protocol parameters, --backend r0, --json.",
        L"Path must be absolute. Layer 0/1/2/3 means related/base filesystem/VPB filesystem/device. Input <=64 KiB, output <=256 KiB, timeout <=60000 ms. --allow-dangerous 1 is additionally required for dangerous major functions. Raw flags cannot supply confirmation bits. Reports each actual stage, native NTSTATUS, returned bytes and partial effects. No automatic retry or R3 fallback.", submit};
    cmd.supportsR0 = true;
    cmd.supportsR3 = false;
    cmd.defaultBackend = L"r0";
    addCommand(std::move(cmd));
}
}
