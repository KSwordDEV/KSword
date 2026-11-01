// Whole production backend, deterministic volume I/O. This does not mount NTFS.
#include "NtfsFastIndex.h"
#include "NtfsIndexRecord.h"
#include <QCoreApplication>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>
using Bytes = std::vector<std::byte>;
using DWORD = std::uint32_t;
using WORD = std::uint16_t;
using LONGLONG = std::int64_t;
using HANDLE = void*;
struct LARGE_INTEGER { LONGLONG QuadPart; };
struct NTFS_VOLUME_DATA_BUFFER {
    LARGE_INTEGER VolumeSerialNumber, TotalClusters, MftValidDataLength;
    DWORD BytesPerSector = 512, BytesPerCluster = 4096, BytesPerFileRecordSegment = 1024;
};
struct NTFS_FILE_RECORD_INPUT_BUFFER { LARGE_INTEGER FileReferenceNumber; };
struct NTFS_FILE_RECORD_OUTPUT_BUFFER {
    LARGE_INTEGER FileReferenceNumber;
    DWORD FileRecordLength;
    unsigned char FileRecordBuffer[1];
};
struct USN_JOURNAL_DATA_V0 {
    std::uint64_t UsnJournalID = 7;
    LONGLONG FirstUsn = 0, NextUsn = 100, LowestValidUsn = 0;
};
struct READ_USN_JOURNAL_DATA_V0 {
    LONGLONG StartUsn = 0;
    DWORD ReasonMask = 0, ReturnOnlyOnClose = 0;
    std::uint64_t UsnJournalID = 0;
};
static const HANDLE INVALID_HANDLE_VALUE = reinterpret_cast<HANDLE>(std::intptr_t{-1});
constexpr DWORD ERROR_SUCCESS = 0, ERROR_ACCESS_DENIED = 5, ERROR_INVALID_DATA = 13;
constexpr DWORD ERROR_FILE_NOT_FOUND = 2, ERROR_HANDLE_EOF = 38;
constexpr DWORD ERROR_JOURNAL_NOT_ACTIVE = 1179, ERROR_JOURNAL_DELETE_IN_PROGRESS = 1178;
constexpr DWORD FSCTL_GET_NTFS_VOLUME_DATA = 1, FSCTL_GET_NTFS_FILE_RECORD = 2;
constexpr DWORD FSCTL_QUERY_USN_JOURNAL = 3, FSCTL_READ_USN_JOURNAL = 4;
constexpr DWORD GENERIC_READ = 1, FILE_SHARE_READ = 1, FILE_SHARE_WRITE = 2, FILE_SHARE_DELETE = 4;
constexpr DWORD OPEN_EXISTING = 3, FILE_BEGIN = 0, FILE_ATTRIBUTE_DIRECTORY = 16;
constexpr int FALSE = 0;
static void put(Bytes& bytes, std::size_t at, std::uint64_t value, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) bytes.at(at + i) = std::byte((value >> (i * 8)) & 255);
}
static Bytes resident(DWORD type, const Bytes& data) {
    Bytes result((24 + data.size() + 7) & ~std::size_t{7});
    put(result, 0, type, 4); put(result, 4, result.size(), 4);
    put(result, 16, data.size(), 4); put(result, 20, 24, 2);
    std::copy(data.begin(), data.end(), result.begin() + 24); return result;
}
static Bytes stream(DWORD type, std::uint64_t low, std::uint64_t count,
    std::uint64_t lcn, std::uint64_t logical) {
    Bytes result(72);
    put(result, 0, type, 4); put(result, 4, result.size(), 4); put(result, 8, 1, 1);
    put(result, 16, low, 8); put(result, 24, low + count - 1, 8); put(result, 32, 64, 2);
    put(result, 40, count * 4096, 8); put(result, 48, logical, 8); put(result, 56, logical, 8);
    put(result, 64, 0x11, 1); put(result, 65, count, 1); put(result, 66, lcn, 1);
    return result;
}
static Bytes record(std::initializer_list<Bytes> attributes, unsigned flags = 1,
    unsigned sequence = 1, std::uint64_t base = 0) {
    Bytes result(1024);
    put(result, 0, 0x454c4946, 4); put(result, 4, 48, 2); put(result, 6, 3, 2);
    put(result, 16, sequence, 2); put(result, 20, 56, 2); put(result, 22, flags, 2);
    put(result, 28, 1024, 4); put(result, 32, base, 8);
    std::size_t at = 56;
    for (const auto& attribute : attributes) {
        std::copy(attribute.begin(), attribute.end(), result.begin() + at); at += attribute.size();
    }
    put(result, at, 0xffffffffU, 4); put(result, 24, at + 4, 4);
    put(result, 48, 0xa55a, 2);
    for (unsigned sector = 0; sector < 2; ++sector) {
        const std::size_t tail = (sector + 1) * 512 - 2;
        result[50 + sector * 2] = result[tail]; result[51 + sector * 2] = result[tail + 1];
        put(result, tail, 0xa55a, 2);
    }
    return result;
}
static Bytes fsctlRecord(Bytes bytes) {
    const auto usa = static_cast<std::size_t>(static_cast<unsigned>(bytes.at(4))
        | (static_cast<unsigned>(bytes.at(5)) << 8));
    for (std::size_t sector = 0; sector < bytes.size() / 512; ++sector) {
        bytes[(sector + 1) * 512 - 2] = bytes.at(usa + (sector + 1) * 2);
        bytes[(sector + 1) * 512 - 1] = bytes.at(usa + (sector + 1) * 2 + 1);
    }
    return bytes;
}

static Bytes file(const std::u16string& name, unsigned size = 17) {
    Bytes filename(66 + name.size() * 2);
    put(filename, 0, (std::uint64_t{1} << 48) | 5, 8);
    put(filename, 64, name.size(), 1); put(filename, 65, 1, 1);
    for (std::size_t i = 0; i < name.size(); ++i) put(filename, 66 + i * 2, name[i], 2);
    return record({resident(0x30, filename), resident(0x80, Bytes(size))}, 1, 2);
}
struct Simulation {
    NTFS_VOLUME_DATA_BUFFER info;
    std::map<std::uint64_t, Bytes> records;
    Bytes storage = Bytes(128 * 4096);
    std::uint64_t offset = 0;
    DWORD error = 0, journalError = 0;
    bool journal = false, metadataChanges = false, mappingChanges = false, shortRead = false;
    bool enforceAlignment = true, cachedTailChanges = false;
    bool nearestLowerRecord = false, malformedRecoveryRecord = false, shortRecoveryRecord = false;
    DWORD recoveryError = 0;
    unsigned recoveryReads = 0;
    std::shared_ptr<std::atomic_bool> cancelDuringRecovery;
    unsigned opens = 0, closes = 0, mappingReads = 0, listReads = 0;
    std::int64_t nextUsn = 100;
    std::vector<std::uint64_t> dirty;
    void seed(bool external = false) {
        info.VolumeSerialNumber.QuadPart = 11; info.TotalClusters.QuadPart = 128;
        info.MftValidDataLength.QuadPart = 8 * 1024;
        if (external) {
            Bytes list(64);
            put(list, 0, 0x80, 4); put(list, 4, 32, 2); put(list, 16, std::uint64_t{1} << 48, 8);
            put(list, 32, 0x80, 4); put(list, 36, 32, 2); put(list, 40, 1, 8);
            put(list, 48, (std::uint64_t{1} << 48) | 7, 8);
            records[0] = record({stream(0x20, 0, 1, 40, list.size()), stream(0x80, 0, 1, 20, 8192)});
            records[7] = record({stream(0x80, 1, 1, 21, 0)}, 1, 1, std::uint64_t{1} << 48);
            std::copy(list.begin(), list.end(), storage.begin() + 40 * 4096);
        } else records[0] = record({stream(0x80, 0, 2, 20, 8192)});
        records[5] = record({}, 3);
        records[6] = file(u"alpha.txt");
        for (const auto& item : records)
            std::copy(item.second.begin(), item.second.end(), storage.begin() + 20 * 4096 + item.first * 1024);
    }
};
static Simulation* simulation = nullptr;
static DWORD GetLastError() { return simulation->error; }
static HANDLE CreateFileW(const wchar_t*, DWORD access, DWORD sharing, void*, DWORD mode, DWORD, void*) {
    if (access != GENERIC_READ || sharing != (FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE) || mode != OPEN_EXISTING)
        throw std::runtime_error("backend did not use a shared read-only volume handle");
    ++simulation->opens; return simulation;
}
static int CloseHandle(HANDLE handle) {
    if (handle != simulation) throw std::runtime_error("wrong handle closed");
    ++simulation->closes; return 1;
}
static int SetFilePointerEx(HANDLE, LARGE_INTEGER offset, void*, DWORD mode) {
    if (offset.QuadPart < 0 || mode != FILE_BEGIN) return FALSE;
    simulation->offset = std::uint64_t(offset.QuadPart); return 1;
}
static int ReadFile(HANDLE, void* output, DWORD size, DWORD* returned, void*) {
    auto& state = *simulation;
    if ((state.enforceAlignment && reinterpret_cast<std::uintptr_t>(output) % std::max<DWORD>(state.info.BytesPerSector, 4096))
        || state.offset % state.info.BytesPerSector || size % state.info.BytesPerSector
        || state.offset > state.storage.size() || size > state.storage.size() - state.offset) {
        state.error = ERROR_INVALID_DATA; return FALSE;
    }
    if (state.offset == 40 * 4096) ++state.listReads;
    *returned = state.shortRead ? size - 1 : size;
    std::memcpy(output, state.storage.data() + state.offset, *returned); return 1;
}
static int DeviceIoControl(HANDLE, DWORD code, void* input, DWORD, void* output, DWORD size, DWORD* returned, void*) {
    auto& state = *simulation;
    if (code == FSCTL_GET_NTFS_VOLUME_DATA) {
        std::memcpy(output, &state.info, sizeof(state.info)); *returned = sizeof(state.info); return 1;
    }
    if (code == FSCTL_GET_NTFS_FILE_RECORD) {
        const auto index = std::uint64_t(static_cast<NTFS_FILE_RECORD_INPUT_BUFFER*>(input)->FileReferenceNumber.QuadPart);
        if (index == 6 || index == 7) {
            ++state.recoveryReads;
            if (state.cancelDuringRecovery) state.cancelDuringRecovery->store(true);
            if (state.recoveryError) { state.error = state.recoveryError; return FALSE; }
        }
        auto found = state.records.find(index);
        if (found == state.records.end() && state.nearestLowerRecord) {
            found = state.records.upper_bound(index);
            if (found != state.records.begin()) --found;
            else found = state.records.end();
        }
        if (found == state.records.end()) { state.error = ERROR_FILE_NOT_FOUND; return FALSE; }
        Bytes bytes = fsctlRecord(found->second);
        if (index == 6 && state.malformedRecoveryRecord) put(bytes, 56 + 4, 0xfffffff8U, 4);
        if (index == 6 && state.cachedTailChanges) put(bytes, 510, u'新', 2);
        if (index == 0) {
            ++state.mappingReads;
            if (state.mappingReads > 1 && state.metadataChanges) put(bytes, 8, 991, 8); // FILE LSN only.
            if (state.mappingReads > 1 && state.mappingChanges) put(bytes, 56 + 66, 22, 1); // A real LCN move.
        }
        const std::size_t header = offsetof(NTFS_FILE_RECORD_OUTPUT_BUFFER, FileRecordBuffer);
        if (size < header + bytes.size()) throw std::runtime_error("output buffer too small");
        auto* result = static_cast<NTFS_FILE_RECORD_OUTPUT_BUFFER*>(output);
        result->FileReferenceNumber.QuadPart = LONGLONG(found->first); result->FileRecordLength = DWORD(bytes.size());
        std::memcpy(static_cast<std::byte*>(output) + header, bytes.data(), bytes.size());
        *returned = DWORD(header + bytes.size() - ((index == 6 && state.shortRecoveryRecord) ? 1 : 0)); return 1;
    }
    if (code == FSCTL_QUERY_USN_JOURNAL) {
        if (!state.journal || state.journalError) {
            state.error = state.journalError ? state.journalError : ERROR_JOURNAL_NOT_ACTIVE; return FALSE;
        }
        USN_JOURNAL_DATA_V0 journal; journal.NextUsn = state.nextUsn;
        std::memcpy(output, &journal, sizeof(journal)); *returned = sizeof(journal); return 1;
    }
    if (code == FSCTL_READ_USN_JOURNAL) {
        Bytes data(8 + state.dirty.size() * 64);
        put(data, 0, std::uint64_t(state.nextUsn), 8);
        std::size_t at = 8;
        for (auto reference : state.dirty) {
            put(data, at, 64, 4); put(data, at + 4, 2, 2); put(data, at + 8, reference, 8);
            put(data, at + 24, std::uint64_t(state.nextUsn - 1), 8); put(data, at + 56, 2, 2);
            put(data, at + 58, 60, 2); put(data, at + 60, u'x', 2); at += 64;
        }
        if (data.size() > size) throw std::runtime_error("journal output buffer too small");
        std::memcpy(output, data.data(), data.size()); *returned = DWORD(data.size()); return 1;
    }
    throw std::runtime_error("unexpected DeviceIoControl");
}
// KSWORD_WHOLE_PRODUCTION_BACKEND
static int checks = 0;
static void check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
static ks::files::NtfsFastIndex::Snapshot build(Simulation& state, const ks::files::NtfsFastIndex::Cancel& cancel = {}) {
    simulation = &state;
    const auto result = ks::files::NtfsFastIndex::build(QStringLiteral("C:\\"), cancel);
    check(state.opens == state.closes, "volume handle leaked"); return result;
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    using Index = ks::files::NtfsFastIndex;
    constexpr std::uint64_t fileReference = (std::uint64_t{2} << 48) | 6;
    try {
        const QString scenario = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral("all");
        if (scenario == QStringLiteral("all") || scenario == QStringLiteral("continuation")) {
            // A continuation's 64-byte nonresident header does not contain the
            // compressed/sparse TotalAllocated field. Its size fields are also
            // undefined; only LowestVcn == 0 owns authoritative stream sizes.
            for (unsigned flags : {0x8000U, 1U, 0x8001U, 0U}) {
                Simulation continuation; continuation.seed();
                auto data = stream(0x80, 4, 1, 21, 0); put(data, 12, flags, 2);
                if (flags == 0x8000U) {
                    // Match the failing live volume's structural metadata,
                    // without copying any names, user payload or disk bytes.
                    data.resize(784); put(data, 4, data.size(), 4);
                    put(data, 16, 30464, 8); put(data, 24, 55183, 8);
                    put(data, 64, 0x12, 1); put(data, 65, 24720, 2);
                    put(data, 67, 21, 1); put(data, 68, 0, 1);
                }
                auto extension = record({data}, 1, 2, fileReference);
                continuation.records[7] = extension;
                std::copy(extension.begin(), extension.end(), continuation.storage.begin() + 20 * 4096 + 7 * 1024);
                const auto result = build(continuation);
                if (!result->complete) std::cerr << "BACKEND_ERROR=" << result->error.toStdString() << '\n';
                check(result->complete && result->error.isEmpty(), "legal compact nonresident continuation rejected by complete backend");
                check(result->entries.value(fileReference).sizeKnown && result->entries.value(fileReference).logicalBytes == 17,
                    "continuation sizes replaced the base file's authoritative size");
                check(result->extensions.contains((std::uint64_t{2} << 48) | 7), "continuation extension identity was lost");
                check(continuation.recoveryReads == 0, "valid compact continuation unnecessarily required FSCTL recovery");

                // Exercise genuinely undefined words independently of the
                // compact sparse-header regression, including non-sparse DATA.
                put(data, 40, UINT64_MAX, 8); put(data, 48, UINT64_MAX, 8); put(data, 56, UINT64_MAX, 8);
                extension = record({data}, 1, 2, fileReference);
                continuation.records[7] = extension;
                std::copy(extension.begin(), extension.end(), continuation.storage.begin() + 20 * 4096 + 7 * 1024);
                const auto undefinedSizes = build(continuation);
                check(undefinedSizes->complete && undefinedSizes->entries.value(fileReference).logicalBytes == 17,
                    "undefined continuation size fields prevented a complete snapshot");
            }
            if (scenario == QStringLiteral("continuation")) {
                std::cout << "NTFS_BACKEND_IO=PASS CHECKS=" << checks << " SCENARIO=continuation\n"; return 0;
            }
        }
        if (scenario == QStringLiteral("all") || scenario == QStringLiteral("record-recovery")) {
            // Raw reads of an active volume can see a torn FILE sector while
            // NTFS can still return a coherent, already-fixed-up cache record.
            Simulation recover; recover.seed();
            put(recover.storage, 20 * 4096 + 6 * 1024 + 510, 0, 2);
            const auto recovered = build(recover);
            if (!recovered->complete) std::cerr << "BACKEND_ERROR=" << recovered->error.toStdString() << '\n';
            check(recovered->complete && recovered->error.isEmpty(), "coherent FSCTL record did not recover a torn raw FILE slot");
            check(Index::fullPath(*recovered, fileReference) == QStringLiteral("C:\\alpha.txt")
                && recovered->entries.value(fileReference).logicalBytes == 17, "record recovery lost the file name or data size");
            check(recover.recoveryReads == 1, "a torn record must use one bounded FSCTL read");

            // A deleted FILE remnant cannot be trusted as a live record. The
            // real FSCTL returns the nearest lower live record for this hole.
            Simulation hole; hole.seed(); hole.nearestLowerRecord = true;
            auto remnant = file(u"deleted.txt"); put(remnant, 510, 0, 2);
            std::copy(remnant.begin(), remnant.end(), hole.storage.begin() + 20 * 4096 + 7 * 1024);
            const auto holes = build(hole);
            check(holes->complete && Index::fullPath(*holes, fileReference) == QStringLiteral("C:\\alpha.txt"),
                "nearest-lower FSCTL response did not identify a deleted slot");
            check(holes->entries.size() == 3 && hole.recoveryReads == 1,
                "nearest-lower record was inserted as the requested deleted identity");

            Simulation unused; unused.seed(); unused.records[6] = record({}, 0, 2);
            put(unused.storage, 20 * 4096 + 6 * 1024 + 510, 0, 2);
            const auto deleted = build(unused);
            check(deleted->complete && !deleted->entries.contains(fileReference) && unused.recoveryReads == 1,
                "a recovered unused logical record retained stale raw file metadata");

            Simulation extension; extension.seed();
            auto coherentExtension = file(u"alias.txt"); put(coherentExtension, 32, fileReference, 8);
            extension.records[7] = coherentExtension;
            auto tornExtension = coherentExtension;
            put(tornExtension, 32, (std::uint64_t{1} << 48) | 5, 8); put(tornExtension, 510, 0, 2);
            std::copy(tornExtension.begin(), tornExtension.end(), extension.storage.begin() + 20 * 4096 + 7 * 1024);
            const auto extended = build(extension);
            constexpr std::uint64_t extensionReference = (std::uint64_t{2} << 48) | 7;
            check(extended->complete && extended->extensions.contains(extensionReference)
                && extended->extensions.value(extensionReference).baseReference == fileReference,
                "recovered extension metadata was read from the stale raw FILE bytes");

            Simulation denied; denied.seed(); denied.recoveryError = ERROR_ACCESS_DENIED;
            put(denied.storage, 20 * 4096 + 6 * 1024 + 510, 0, 2);
            const auto inaccessible = build(denied);
            check(!inaccessible->complete && inaccessible->error.contains(QString::number(ERROR_ACCESS_DENIED))
                && denied.recoveryReads == 1, "recovery permission failure was hidden or retried");

            Simulation invalid; invalid.seed(); invalid.malformedRecoveryRecord = true;
            put(invalid.storage, 20 * 4096 + 6 * 1024 + 510, 0, 2);
            const auto malformed = build(invalid);
            check(!malformed->complete && !malformed->error.isEmpty() && invalid.recoveryReads == 1,
                "malformed logical FSCTL record was accepted as a complete snapshot");

            Simulation shortRecord; shortRecord.seed(); shortRecord.shortRecoveryRecord = true;
            put(shortRecord.storage, 20 * 4096 + 6 * 1024 + 510, 0, 2);
            const auto truncated = build(shortRecord);
            check(!truncated->complete && !truncated->error.isEmpty() && shortRecord.recoveryReads == 1,
                "truncated FSCTL recovery output was accepted as complete");

            Simulation cancelled; cancelled.seed();
            cancelled.cancelDuringRecovery = std::make_shared<std::atomic_bool>(false);
            put(cancelled.storage, 20 * 4096 + 6 * 1024 + 510, 0, 2);
            const auto interrupted = build(cancelled, cancelled.cancelDuringRecovery);
            check(interrupted->cancelled && !interrupted->complete && cancelled.recoveryReads == 1,
                "cancellation during FSCTL recovery published a successful snapshot");
            if (scenario == QStringLiteral("record-recovery")) {
                std::cout << "NTFS_BACKEND_IO=PASS CHECKS=" << checks << " SCENARIO=record-recovery\n"; return 0;
            }
        }
        for (bool external : {false, true}) {
            if ((scenario == QStringLiteral("metadata") && external)
                || (scenario == QStringLiteral("attribute-list") && !external)) continue;
            Simulation state; state.seed(external); state.metadataChanges = !external;
            // Isolate mapping/list negative controls from the old buffer-address
            // defect. The full current matrix enforces physical-sector alignment.
            state.enforceAlignment = scenario == QStringLiteral("all");
            const auto result = build(state);
            if (!result->complete) std::cerr << "BACKEND_ERROR=" << result->error.toStdString() << '\n';
            check(result->complete && result->error.isEmpty(), external
                ? "a valid nonresident MFT attribute list was rejected"
                : "unchanged MFT mapping was rejected after a normal FILE LSN update");
            check(Index::fullPath(*result, fileReference) == QStringLiteral("C:\\alpha.txt"), "full backend lost the searchable file path");
            check(result->entries.value(fileReference).logicalBytes == 17, "full backend lost the file's space accounting");
            check(!external || state.listReads == 2, "nonresident MFT attribute list was not read and revalidated");
            check(external || state.recoveryReads == 0, "healthy raw FILE records unnecessarily used per-record FSCTL reads");
        }
        if (scenario != QStringLiteral("all")) {
            std::cout << "NTFS_BACKEND_IO=PASS CHECKS=" << checks << " SCENARIO=" << scenario.toStdString() << '\n'; return 0;
        }
        {
            // A fragmented MFT can split a record across 512-byte clusters.
            // Physical-sector I/O addresses must stay aligned after filled=512.
            Simulation state; state.seed(); state.info.BytesPerCluster = 512;
            auto data = stream(0x80, 0, 16, 20, 8192);
            data.resize(80); put(data, 4, data.size(), 4); put(data, 40, 8192, 8);
            put(data, 65, 1, 1); put(data, 67, 0x11, 1); put(data, 68, 15, 1); put(data, 69, 40, 1);
            state.records[0] = record({data});
            Bytes logical(8192);
            for (const auto& item : state.records)
                std::copy(item.second.begin(), item.second.end(), logical.begin() + item.first * 1024);
            std::copy(logical.begin(), logical.begin() + 512, state.storage.begin() + 20 * 512);
            std::copy(logical.begin() + 512, logical.end(), state.storage.begin() + 60 * 512);
            const auto result = build(state);
            check(result->complete && Index::fullPath(*result, fileReference) == QStringLiteral("C:\\alpha.txt"),
                "fragmented 512e MFT reads used an unaligned interior buffer");
        }
        {
            Simulation state; state.seed(); state.journal = true;
            const std::u16string name(230, u'文');
            state.records[6] = file(name);
            std::copy(state.records[6].begin(), state.records[6].end(), state.storage.begin() + 20 * 4096 + 6 * 1024);
            const auto previous = build(state);
            check(previous->complete, "cached-tail test baseline failed");
            state.cachedTailChanges = true; state.nextUsn = 200; state.dirty = {fileReference};
            const auto updated = Index::refresh(previous);
            auto changedName = name; changedName[182] = u'新';
            check(updated->complete && updated->entries.value(fileReference).name == QString::fromStdU16String(changedName),
                "FSCTL cache tail content was rejected or replaced by an old USA word");
            check(previous->entries.value(fileReference).name == QString::fromStdU16String(name),
                "cached-tail refresh mutated its previous snapshot");
        }
        {
            Simulation state; state.seed(); state.mappingChanges = true;
            const auto result = build(state);
            check(!result->complete && !result->error.isEmpty(), "a changed MFT physical mapping was published as complete");
        }
        {
            Simulation state; state.seed(true); state.records[7] = record({stream(0x80, 1, 1, 21, 0)}, 1, 2, std::uint64_t{1} << 48);
            const auto result = build(state);
            check(!result->complete && !result->error.isEmpty(), "stale attribute-list extension sequence was accepted");
        }
        {
            Simulation state; state.seed(); state.shortRead = true;
            const auto result = build(state);
            check(!result->complete && result->error.contains(QString::number(ERROR_HANDLE_EOF)), "successful short read did not report EOF");
        }
        {
            Simulation state; state.seed(); auto cancel = std::make_shared<std::atomic_bool>(true);
            const auto result = build(state, cancel);
            check(result->cancelled && !result->complete && state.opens == 0, "pre-cancelled build still opened the volume");
        }
        {
            Simulation state; state.seed(); state.journal = true;
            const auto previous = build(state);
            check(previous->complete && previous->journalAvailable, "journal build did not produce a usable baseline");
            state.nextUsn = 200; state.dirty = {fileReference}; state.records[6] = file(u"beta.txt", 31);
            const auto updated = Index::refresh(previous);
            check(updated->complete && updated->nextUsn == 200, "USN refresh did not publish the new cursor");
            check(Index::fullPath(*updated, fileReference) == QStringLiteral("C:\\beta.txt"), "USN refresh did not update the searchable name");
            check(updated->entries.value(fileReference).logicalBytes == 31, "USN refresh did not update space accounting");
            check(Index::fullPath(*previous, fileReference) == QStringLiteral("C:\\alpha.txt")
                && previous->entries.value(fileReference).logicalBytes == 17, "refresh mutated the old immutable snapshot");
            state.journalError = ERROR_ACCESS_DENIED;
            const auto failed = Index::refresh(updated);
            check(!failed->complete && failed->error.contains(QString::number(ERROR_ACCESS_DENIED))
                && !failed->rebuildRequired, "USN permission failure was disguised as a changed journal");
            check(Index::fullPath(*failed, fileReference) == QStringLiteral("C:\\beta.txt"), "refresh failure discarded the prior snapshot");
            auto cancel = std::make_shared<std::atomic_bool>(true);
            const auto opens = state.opens;
            const auto cancelled = Index::refresh(updated, cancel);
            check(!cancelled->complete && cancelled->cancelled && state.opens == opens, "pre-cancelled refresh performed I/O or reported success");
        }
        std::cout << "NTFS_BACKEND_IO=PASS CHECKS=" << checks << " WHOLE_BACKEND=1 NATIVE_NTFS=0\n";
    } catch (const std::exception& error) {
        std::cerr << "NTFS_BACKEND_IO=FAIL " << error.what() << '\n'; return 1;
    }
}
