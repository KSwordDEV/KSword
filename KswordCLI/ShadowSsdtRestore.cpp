#include "CommandRegistry.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/usermode/backend/kernel/TrustedImageBaseline.h"

#include <algorithm>
#include <cstdint>
#include <stdexcept>

namespace ks::cli {
namespace {
using ksword::ark::DriverClient;
using ksword::ark::SsdtEntry;
using ks::r3::kernel::TrustedImageBaseline;
struct Snapshot {
    std::uint64_t table = 0;
    std::uint32_t count = 0;
    SsdtEntry row;
    TrustedImageBaseline baseline;
    std::vector<std::uint8_t> current;
};

bool collect(const DriverClient& client, std::uint32_t index, Snapshot& snap, std::wstring& error) {
    snap = {};
    const auto rows = client.enumerateShadowSsdt(KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);
    if (!rows.io.ok || rows.version != KSWORD_ARK_ENUM_SSDT_PROTOCOL_VERSION ||
        rows.returnedCount != rows.entries.size() || rows.returnedCount > rows.totalCount ||
        !rows.serviceTableBase || !rows.serviceCountFromTable || rows.serviceCountFromTable > 16384) {
        error = L"Shadow SSDT enumeration is unavailable or incomplete."; return false;
    }
    const SsdtEntry* found = nullptr;
    const auto required = KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED |
        KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID | KSWORD_ARK_SSDT_ENTRY_FLAG_SHADOW_TABLE |
        KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_VALUE_CAPTURED;
    for (const auto& row : rows.entries) {
        if ((row.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) == 0 || row.serviceIndex != index) continue;
        if (found) { error = L"Multiple entries claim the selected service index."; return false; }
        found = &row;
    }
    if (!found || (found->flags & required) != required || found->tableEntrySize != 4 ||
        index >= rows.serviceCountFromTable || rows.serviceTableBase > UINT64_MAX - std::uint64_t(index)*4 ||
        found->tableEntryAddress != rows.serviceTableBase + std::uint64_t(index)*4) {
        error = L"Selected slot has missing or inconsistent identity evidence."; return false;
    }
    snap.table = rows.serviceTableBase; snap.count = rows.serviceCountFromTable; snap.row = *found;
    if (!ks::r3::kernel::ReadKernelExact(client, found->tableEntryAddress, 4, snap.current)) {
        error = L"Unable to read all current slot bytes."; return false;
    }
    std::uint32_t captured = 0;
    for (unsigned i = 0; i != 4; ++i) captured |= std::uint32_t(snap.current[i]) << (8*i);
    if (found->currentTableValue != captured) { error = L"Slot changed since enumeration."; return false; }
    if (!ks::r3::kernel::ReadTrustedImageBaseline(client, found->tableEntryAddress, 4, snap.baseline, error)) return false;
    if (snap.current == snap.baseline.bytes) { error = L"Selected slot already matches the baseline."; return false; }
    return true;
}

bool same(const Snapshot& a, const Snapshot& b) {
    return a.table == b.table && a.count == b.count && a.row.serviceIndex == b.row.serviceIndex &&
        a.row.tableEntryAddress == b.row.tableEntryAddress && a.row.tableEntrySize == b.row.tableEntrySize &&
        a.current == b.current && a.baseline.bytes == b.baseline.bytes &&
        a.baseline.moduleBase == b.baseline.moduleBase && a.baseline.moduleSize == b.baseline.moduleSize &&
        a.baseline.sha256 == b.baseline.sha256 && _wcsicmp(a.baseline.ntPath.c_str(), b.baseline.ntPath.c_str()) == 0;
}

Json evidence(const Snapshot& s) {
    return Json::object({{L"index",Json::number(s.row.serviceIndex)}, {L"tableBase",Json::hex(s.table)},
        {L"tableCount",Json::number(s.count)}, {L"slotAddress",Json::hex(s.row.tableEntryAddress)},
        {L"currentBytes",Json::bytes(s.current, 4)}, {L"baselineBytes",Json::bytes(s.baseline.bytes, 4)},
        {L"moduleBase",Json::hex(s.baseline.moduleBase)}, {L"moduleSize",Json::number(s.baseline.moduleSize)},
        {L"moduleNtPath",Json::string(s.baseline.ntPath)}, {L"diskPath",Json::string(s.baseline.localPath)},
        {L"diskSha256",Json::string(s.baseline.sha256)}, {L"cachedSigningLevel",Json::number(s.baseline.signingLevel)},
        {L"diskWinTrustVerified",Json::boolean(false)}});
}

bool patchResponse(const ksword::ark::KernelInlinePatchResult& r, std::uint64_t address) {
    return r.io.ok && r.io.bytesReturned >= sizeof(KSWORD_ARK_PATCH_INLINE_HOOK_RESPONSE) &&
        r.version == KSWORD_ARK_KERNEL_HOOK_PROTOCOL_VERSION && r.functionAddress == address;
}

Result run(const Args& args, bool apply) {
    if (!args.has(L"--index")) throw std::invalid_argument("--index is required");
    const auto index = args.u32(L"--index");
    if (apply && (!args.has(L"--confirm") || args.require(L"--confirmation") != L"RESTORE SHADOW SSDT"))
        throw std::invalid_argument("--confirm and --confirmation RESTORE SHADOW SSDT are required");
    DriverClient client;
    Snapshot first; std::wstring why;
    if (!collect(client, index, first, why)) return {5, Json::object({{L"writeAttempted",Json::boolean(false)}}), {why}};
    const auto preflight = client.patchInlineHook(first.row.tableEntryAddress, KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
        4, first.current, first.baseline.bytes, 0);
    const bool ready = patchResponse(preflight, first.row.tableEntryAddress) &&
        preflight.status == KSWORD_ARK_KERNEL_HOOK_STATUS_FORCE_REQUIRED && preflight.bytesPatched == 0;
    if (!ready) return {3, Json::object({{L"snapshot",evidence(first)}, {L"writeAttempted",Json::boolean(false)},
        {L"preflightStatus",Json::number(preflight.status)}, {L"preflightNtStatus",Json::hex(static_cast<std::uint32_t>(preflight.lastStatus))}}),
        {L"R0 preflight did not return FORCE_REQUIRED."}};
    if (!apply) return {0, Json::object({{L"snapshot",evidence(first)}, {L"preflightStatus",Json::number(preflight.status)},
        {L"writeAttempted",Json::boolean(false)}}), {L"Preview only. Cached CI signing level is not a full embedded/catalog WinTrust verification."}};
    const auto expectedTable = args.integer(L"--expected-table");
    const auto expectedCurrent = parseHexPayload(args.require(L"--expected-current"));
    const auto expectedBaseline = parseHexPayload(args.require(L"--expected-baseline"));
    const auto expectedHash = args.require(L"--expected-sha256");
    if (!expectedTable || first.table != expectedTable || first.current != expectedCurrent ||
        first.baseline.bytes != expectedBaseline || _wcsicmp(first.baseline.sha256.c_str(),expectedHash.c_str()) != 0)
        return {3, Json::object({{L"snapshot",evidence(first)}, {L"writeAttempted",Json::boolean(false)}}),
            {L"Snapshot differs from the explicitly confirmed preview."}};
    Snapshot second;
    if (!collect(client, index, second, why) || !same(first,second))
        return {3, Json::object({{L"snapshot",evidence(first)}, {L"writeAttempted",Json::boolean(false)}}),
            {why.empty() ? L"Slot or trusted image evidence changed before commit." : why}};
    const auto commit = client.patchInlineHook(first.row.tableEntryAddress, KSWORD_ARK_INLINE_PATCH_MODE_RESTORE_BYTES,
        4, first.current, first.baseline.bytes, KSWORD_ARK_KERNEL_PATCH_FLAG_FORCE);
    const bool patched = patchResponse(commit, first.row.tableEntryAddress) &&
        commit.status == KSWORD_ARK_KERNEL_HOOK_STATUS_PATCHED && commit.bytesPatched == 4 && commit.lastStatus >= 0;
    std::vector<std::uint8_t> after;
    const bool verified = patched && ks::r3::kernel::ReadKernelExact(client, first.row.tableEntryAddress, 4, after) && after == first.baseline.bytes;
    return {verified ? 0 : 6, Json::object({{L"snapshot",evidence(first)}, {L"writeAttempted",Json::boolean(true)},
        {L"patchStatus",Json::number(commit.status)}, {L"patchNtStatus",Json::hex(static_cast<std::uint32_t>(commit.lastStatus))},
        {L"bytesPatched",Json::number(commit.bytesPatched)}, {L"readbackBytes",Json::bytes(after,4)},
        {L"verified",Json::boolean(verified)}}),
        {verified ? L"Restored slot readback matches the baseline." : L"Commit or readback did not confirm restoration; inspect state before retrying."}};
}
}

void registerShadowSsdtRestore() {
    Command preview{L"kernel shadow-ssdt-baseline", L"KswordCLI.exe kernel shadow-ssdt-baseline --index N [--backend r0] [--json]",
        L"Inspect one Shadow SSDT slot and its identity-checked disk baseline.", L"Required: --index.",
        L"The R0 preflight requests no force. Cached CI is not full WinTrust verification.", [](const Args& a){return run(a,false);}};
    preview.supportsR0 = true; preview.supportsR3 = false; preview.defaultBackend = L"r0"; addCommand(std::move(preview));
    Command restore{L"kernel shadow-ssdt-restore", L"KswordCLI.exe kernel shadow-ssdt-restore --index N --expected-table VA --expected-current HEX --expected-baseline HEX --expected-sha256 SHA256 --confirm --confirmation \"RESTORE SHADOW SSDT\" [--backend r0] [--json]",
        L"Restore a Shadow SSDT slot after exact preview and R0 preflight.", L"All identity options and confirmation are required.",
        L"A wrong kernel table write can crash Windows. Obtain all expected fields from a fresh baseline preview.", [](const Args& a){return run(a,true);}};
    restore.supportsR0 = true; restore.supportsR3 = false; restore.defaultBackend = L"r0"; addCommand(std::move(restore));
}
}
