#include "TrustedImageBaseline.h"
#include "../driver/DriverQueries.h"
#include "../../../evidence/PeImageMap.h"
#include "../../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <Windows.h>
#include <wincrypt.h>
#include <algorithm>
#include <limits>

namespace ks::r3::kernel {
namespace {
struct File final {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
bool readFile(HANDLE file, std::vector<std::uint8_t>& bytes) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
        size.QuadPart > 512LL * 1024 * 1024) return false;
    bytes.resize(static_cast<std::size_t>(size.QuadPart));
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const DWORD request = static_cast<DWORD>((std::min)(bytes.size()-offset, std::size_t(1024*1024)));
        DWORD got = 0;
        if (!ReadFile(file, bytes.data()+offset, request, &got, nullptr) || got != request) return false;
        offset += got;
    }
    return true;
}
bool sha256(const std::vector<std::uint8_t>& bytes, std::wstring& out) {
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return false;
    bool ok = CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash) != FALSE;
    if (ok) ok = CryptHashData(hash, bytes.data(), static_cast<DWORD>(bytes.size()), 0) != FALSE;
    BYTE digest[32]{}; DWORD length = sizeof(digest);
    if (ok) ok = CryptGetHashParam(hash, HP_HASHVAL, digest, &length, 0) != FALSE && length == sizeof(digest);
    if (hash) CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    if (!ok) return false;
    static constexpr wchar_t digits[] = L"0123456789abcdef";
    for (BYTE b : digest) { out += digits[b >> 4]; out += digits[b & 15]; }
    return true;
}
}

bool ReadKernelExact(const ksword::ark::DriverClient& client, std::uint64_t address,
                     std::uint32_t length, std::vector<std::uint8_t>& bytes) {
    bytes.clear();
    if (!address || !length || length > KSWORD_ARK_MEMORY_READ_MAX_BYTES) return false;
    const auto read = client.readVirtualMemory(0, address, length, 0);
    if (!read.io.ok || read.version != KSWORD_ARK_MEMORY_PROTOCOL_VERSION ||
        read.headerSize != offsetof(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data) || read.processId != 0 ||
        read.readStatus != KSWORD_ARK_MEMORY_READ_STATUS_OK || read.copyStatus < 0 ||
        (read.fieldFlags & (KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT | KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE)) !=
            (KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT | KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE) ||
        read.requestedBaseAddress != address || read.requestedBytes != length ||
        read.bytesRead != length || read.data.size() != length ||
        (read.fieldFlags & (KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY | KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE)) != 0) return false;
    bytes = read.data;
    return true;
}

bool ReadTrustedImageBaseline(const ksword::ark::DriverClient& client,
                              std::uint64_t address, std::uint32_t length,
                              TrustedImageBaseline& result, std::wstring& error) {
    result = {}; error.clear();
    auto fail = [&](const wchar_t* why) { error = why; return false; };
    if (!address || !length || length > 64U*1024U || address > UINT64_MAX-length)
        return fail(L"Invalid baseline range.");
    std::vector<ks::r3::driver::DriverOverviewRow> modules;
    std::wstring diagnostic;
    ks::r3::driver::DriverEnumerationEvidence evidence;
    if (!ks::r3::driver::QueryModuleInformation(modules, diagnostic, &evidence, false))
        return fail(L"Loaded kernel module inventory unavailable.");
    const ks::r3::driver::DriverOverviewRow* match = nullptr;
    for (const auto& row : modules) {
        if (!row.baseKnown || !row.sizeKnown || !row.pathKnown || !row.rangeValid ||
            address < row.baseAddress || address-row.baseAddress >= row.imageSize ||
            length > row.imageSize-(address-row.baseAddress)) continue;
        if (match) return fail(L"Ambiguous loaded module range.");
        match = &row;
    }
    if (!match) return fail(L"Range is not contained in a uniquely identified loaded module.");
    result.moduleBase = match->baseAddress; result.moduleSize = match->imageSize;
    result.ntPath = match->pathText;
    result.localPath = ks::r3::driver::ResolveKernelImagePathForTrust(match->pathText);
    if (result.localPath.empty()) return fail(L"Module path cannot be resolved for disk read.");
    File file;
    file.value = CreateFileW(result.localPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL|FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file.value == INVALID_HANDLE_VALUE) return fail(L"Cannot open a stable read-only module image.");
    std::vector<std::uint8_t> disk, header;
    if (!readFile(file.value, disk) || !sha256(disk, result.sha256)) return fail(L"Module file read or SHA-256 failed.");
    if (!ReadKernelExact(client, match->baseAddress, 64U*1024U, header)) return fail(L"Loaded PE header read incomplete.");
    const auto diskMap = Ksword::Evidence::BuildPeImageMap(disk, match->baseAddress);
    const auto memoryMap = Ksword::Evidence::BuildPeImageMap(header, match->baseAddress);
    if (!diskMap.valid() || !memoryMap.valid()) return fail(L"Disk or loaded PE header is invalid.");
    const auto& a = diskMap.header; const auto& b = memoryMap.header;
    if (a.machine != b.machine || a.timeDateStamp != b.timeDateStamp || a.sizeOfImage != b.sizeOfImage ||
        a.checkSum != b.checkSum || a.sizeOfImage != match->imageSize)
        return fail(L"Disk and loaded PE identities disagree.");
    const auto signature = client.queryImageSignature(match->pathText, match->baseAddress,
        KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT | KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_MATCH_LOADED_MODULE);
    const auto required = KSWORD_ARK_IMAGE_SIGNATURE_FIELD_SIGNING_LEVEL |
        KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE | KSWORD_ARK_IMAGE_SIGNATURE_FIELD_LOADED_MODULE_NAME_MATCH;
    if (!signature.io.ok || (signature.response.fieldFlags & required) != required ||
        signature.response.signingLevelStatus < 0 || signature.response.loadedModuleStatus < 0 ||
        signature.response.matchedModuleBase != match->baseAddress ||
        signature.response.signingLevel < KSWORD_ARK_SIGNING_LEVEL_AUTHENTICODE ||
        (signature.response.structuralFlags & KSWORD_ARK_IMAGE_SIGNATURE_STRUCT_LOADED_NAME_MISMATCH))
        return fail(L"Cached Code Integrity or loaded-module identity evidence is insufficient.");
    result.signingLevel = signature.response.signingLevel;
    const auto rva = address-match->baseAddress;
    if (rva > UINT32_MAX || !Ksword::Evidence::ReadNormalizedBytes(diskMap, static_cast<std::uint32_t>(rva), length, result.bytes))
        return fail(L"The requested file range cannot be safely normalized or compared.");
    return true;
}
}
