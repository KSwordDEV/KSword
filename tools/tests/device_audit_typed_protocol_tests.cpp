// Actual R3 query wrapper with a synthetic transport. No driver is opened.
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace
{
    // Independent v1 definition proves that no old prefix offset moved.
    struct V1Entry
    {
        unsigned long size, profileFlags, rowKind, roleHint, status, riskFlags, fieldFlags, confidence;
        unsigned long relationDepth, attachedDepth, deviceType, characteristics, stackSize, alignmentRequirement;
        long lastStatus;
        unsigned long reserved0;
        unsigned long long driverObjectAddress, deviceObjectAddress, attachedDeviceAddress, nextDeviceObjectAddress;
        wchar_t driverName[KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS];
        wchar_t serviceName[KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS];
        wchar_t deviceName[KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS];
        wchar_t imagePath[KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS];
        wchar_t detail[KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS];
    };
    static_assert(sizeof(void*) == 8 && sizeof(unsigned long) == 4 && sizeof(wchar_t) == 2);
    static_assert(sizeof(V1Entry) == KSWORD_ARK_DEVICE_AUDIT_V1_ENTRY_SIZE);
    static_assert(sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY) == sizeof(V1Entry) + 32);
    static_assert(offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, driverObjectAddress) == offsetof(V1Entry, driverObjectAddress));
    static_assert(offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, detail) == offsetof(V1Entry, detail));
    static_assert(offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, integrityStatus) == sizeof(V1Entry) + 8);
    static_assert(offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, integrityReturnedCount) == sizeof(V1Entry) + 12);
    static_assert(offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, integrityTotalCount) == sizeof(V1Entry) + 16);
    static_assert(offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, integrityModuleCount) == sizeof(V1Entry) + 20);
    static_assert(offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, integrityStatusFlags) == sizeof(V1Entry) + 24);
    static_assert((KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT & 0x7FUL) == 0);
    static_assert((KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT & 0xFFUL) == 0);

    enum class Packet { Valid, V1, OldStride, ShortHeader, MissingRows, InvalidRowSize, MissingFlags, ZeroValues,
        TooManyRows, OversizedByteCount, RevisionFailure, OverRequestedRows, WrongProfile, TrailingByte };
    Packet packet = Packet::Valid;
    int calls = 0;
    int checks = 0;
    unsigned long seenControl = 0;
    unsigned long seenBuffer = 0;
    KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST seenRequest{};
    void expect(const bool ok, const char* label)
    {
        ++checks;
        if (!ok) { std::fprintf(stderr, "DEVICE_AUDIT_TYPED_FAILURE=%s\n", label); std::exit(1); }
    }
}

namespace ksword::ark
{
    IoResult DriverClient::deviceIoControl(unsigned long control, void* input, unsigned long inputBytes,
        void* output, unsigned long outputBytes, DriverHandle*) const
    {
        ++calls;
        seenControl = control;
        seenBuffer = outputBytes;
        expect(inputBytes == sizeof(seenRequest), "wrapper sends the complete unchanged request shape");
        std::memcpy(&seenRequest, input, sizeof(seenRequest));
        IoResult io;
        if (packet == Packet::RevisionFailure)
        {
            io.win32Error = ERROR_REVISION_MISMATCH;
            return io;
        }
        auto* response = static_cast<KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE*>(output);
        response->size = sizeof(*response);
        response->version = packet == Packet::V1 ? 1UL : KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION;
        response->entrySize = packet == Packet::OldStride ? sizeof(V1Entry) : sizeof(KSWORD_ARK_DEVICE_AUDIT_ENTRY);
        response->queryStatus = KSWORD_ARK_DEVICE_AUDIT_STATUS_OK;
        response->profileFlags = packet == Packet::WrongProfile ? (seenRequest.profileFlags ^ KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK) : seenRequest.profileFlags;
        response->returnedCount = packet == Packet::TooManyRows ? KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ROWS + 1
            : packet == Packet::OverRequestedRows ? 2 : 1;
        response->totalCount = response->returnedCount;
        auto& entry = response->entries[0];
        entry.size = packet == Packet::InvalidRowSize ? sizeof(V1Entry) : sizeof(entry);
        entry.fieldFlags = packet == Packet::MissingFlags ? 0UL
            : KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT | KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT;
        if (packet != Packet::ZeroValues)
        {
            entry.ownerDriverObjectAddress = 0xFFFFA12345678900ULL;
            entry.integrityStatus = 7;
            entry.integrityReturnedCount = 11;
            entry.integrityTotalCount = 17;
            entry.integrityModuleCount = 23;
            entry.integrityStatusFlags = 0x81234567UL;
        }
        // Deliberately contradictory legacy text must never supply a typed value.
        const wchar_t legacy[] = L"OwnerDriver=0xBAD status=999 rows=999/999 modules=999 statusFlags=0xBAD";
        std::memcpy(entry.detail, legacy, sizeof(legacy));
        io.ok = true;
        constexpr unsigned long header = sizeof(*response) - sizeof(entry);
        io.bytesReturned = packet == Packet::ShortHeader ? header - 1
            : packet == Packet::MissingRows ? header : header + sizeof(entry);
        if (packet == Packet::OverRequestedRows)
        {
            response->entries[1] = entry;
            io.bytesReturned += sizeof(entry);
        }
        if (packet == Packet::TrailingByte) ++io.bytesReturned;
        if (packet == Packet::OversizedByteCount) io.bytesReturned = outputBytes + 1;
        return io;
    }
}

int main()
{
    const ksword::ark::DriverClient client;
    auto result = client.queryDeviceStackAudit(L"\\Driver\\fixture", 32, 16);
    expect(result.io.ok && result.entries.size() == 1 && calls == 1, "actual v2 wrapper accepts one valid packet without extra I/O");
    expect(seenRequest.version == 2 && seenRequest.maxRows == 32 && seenRequest.maxAttachedDepth == 16,
        "wrapper requests v2 while retaining caller budgets");
    expect(seenBuffer == 4U * 1024U * 1024U + 32U * KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ROWS,
        "tail-only output budget preserves the previous row capacity");
    const auto& row = result.entries.front();
    expect(row.ownerDriverObjectAddress == 0xFFFFA12345678900ULL && row.integrityStatus == 7
        && row.integrityReturnedCount == 11 && row.integrityTotalCount == 17
        && row.integrityModuleCount == 23 && row.integrityStatusFlags == 0x81234567UL,
        "all six typed fields retain exact payload values regardless of diagnostic text");
    expect((row.fieldFlags & (KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT | KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT))
        == (KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT | KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT),
        "both validity flags survive response copying");

    for (const auto malformed : {Packet::V1, Packet::OldStride, Packet::ShortHeader, Packet::MissingRows,
        Packet::InvalidRowSize, Packet::TooManyRows, Packet::OversizedByteCount, Packet::RevisionFailure,
        Packet::WrongProfile, Packet::TrailingByte})
    {
        packet = malformed;
        result = client.queryDeviceStackAudit();
        expect(!result.io.ok && result.entries.empty(), "v1 or malformed packets never produce partial or guessed rows");
        expect(result.version == 0 && result.returnedCount == 0 && result.status != KSWORD_ARK_DEVICE_AUDIT_STATUS_OK,
            "rejected packets never publish successful header metadata");
        if (malformed == Packet::V1 || malformed == Packet::OldStride || malformed == Packet::RevisionFailure)
            expect(result.unsupported, "protocol mismatch explicitly reports unsupported");
    }
    packet = Packet::OverRequestedRows;
    result = client.queryDeviceStackAudit(L"", 1, 16);
    expect(!result.io.ok && result.entries.empty() && result.version == 0,
        "response never exceeds the caller's normalized row scope");
    packet = Packet::Valid;
    result = client.queryDeviceStackAudit(L"", 0, 16);
    expect(result.io.ok && seenRequest.maxRows == 0, "zero preserves the protocol's default row scope");
    result = client.queryDeviceStackAudit(L"", KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ROWS + 1, 16);
    expect(result.io.ok && seenRequest.maxRows == KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ROWS + 1,
        "oversized requested scope follows the existing driver clamp without changing the request");
    packet = Packet::MissingFlags;
    result = client.queryInputStackAudit();
    expect(result.io.ok && result.entries.front().fieldFlags == 0 && seenControl == IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT,
        "missing flags remain missing instead of being inferred from diagnostic text");
    packet = Packet::ZeroValues;
    result = client.queryUsbTopologyAudit();
    expect(result.io.ok && result.entries.front().ownerDriverObjectAddress == 0 && result.entries.front().integrityModuleCount == 0
        && result.entries.front().fieldFlags != 0 && seenControl == IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT,
        "valid zero values remain distinguishable from unavailable fields");
    packet = Packet::Valid;
    result = client.queryGpuDisplayWatchdogAudit();
    expect(result.io.ok && seenControl == IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, "GPU profile uses the same v2 validator");
    std::printf("DEVICE_AUDIT_TYPED_CHECKS=%d\nDEVICE_AUDIT_TYPED_FAILURES=0\n", checks);
    return 0;
}
