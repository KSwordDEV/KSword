#include "NtfsFastIndex.h"
#include "NtfsIndexRecord.h"

#include <QDir>
#include <QSet>
#include <QStringList>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <limits>
#include <vector>

namespace ks::files {
namespace {
constexpr quint64 kRecordMask = 0x0000ffffffffffffULL;
constexpr quint64 kRecordLimit = 20000000ULL;
constexpr DWORD kChunkBytes = 4U * 1024U * 1024U;
constexpr quint64 kDirtyLimit = 2000000ULL;

bool stopped(const NtfsFastIndex::Cancel& cancel) { return cancel && cancel->load(); }
QString failure(const QString& operation, DWORD code = ::GetLastError())
{
    return QStringLiteral("%1失败，Win32 错误 %2。需要以管理员身份读取本地 NTFS 卷。")
        .arg(operation).arg(code);
}
struct Volume {
    HANDLE handle = INVALID_HANDLE_VALUE;
    NTFS_VOLUME_DATA_BUFFER info{};
    ~Volume() { if (handle != INVALID_HANDLE_VALUE) ::CloseHandle(handle); }
};

// DASD volume handles can be noncached even without FILE_FLAG_NO_BUFFERING.
// Every raw read needs a sector-aligned address as well as offset and length.
class SectorBuffer final {
public:
    // 64 KiB also covers 512e drives' physical-sector alignment and every
    // logical sector size admitted by openVolume's geometry validation.
    explicit SectorBuffer(std::size_t length)
        : m_storage(length + kAlignment - 1), m_length(length) {}
    std::byte* data() {
        const auto address = reinterpret_cast<std::uintptr_t>(m_storage.data());
        const auto remainder = address % kAlignment;
        return m_storage.data() + (remainder == 0 ? 0 : kAlignment - remainder);
    }
    std::size_t size() const { return m_length; }
    static constexpr std::size_t alignment() { return kAlignment; }
private:
    static constexpr std::size_t kAlignment = 65536;
    std::vector<std::byte> m_storage;
    std::size_t m_length;
};

bool readRawVolume(Volume& volume, quint64 absolute, DWORD count, std::byte* target,
    SectorBuffer& scratch, QString& error)
{
    if (absolute > static_cast<quint64>(std::numeric_limits<LONGLONG>::max())) {
        error = QStringLiteral("MFT 物理偏移溢出。"); return false;
    }
    // Fragment boundaries may be only one logical cluster apart (including
    // 512-byte clusters on 512e). Keep the I/O address aligned even then.
    auto* destination = reinterpret_cast<std::uintptr_t>(target) % SectorBuffer::alignment() == 0
        ? target : scratch.data();
    LARGE_INTEGER offset{};
    offset.QuadPart = static_cast<LONGLONG>(absolute);
    DWORD read = 0;
    if (!::SetFilePointerEx(volume.handle, offset, nullptr, FILE_BEGIN)
        || !::ReadFile(volume.handle, destination, count, &read, nullptr)) {
        error = failure(QStringLiteral("批量读取 MFT")); return false;
    }
    if (read != count) { error = failure(QStringLiteral("批量读取 MFT"), ERROR_HANDLE_EOF); return false; }
    if (destination != target) std::memcpy(target, destination, count);
    return true;
}

bool openVolume(const QString& requested, Volume& volume, QString& root, QString& error)
{
    root = QDir::toNativeSeparators(requested.trimmed());
    if (root.size() == 2 && root.at(1) == QLatin1Char(':')) root += QLatin1Char('\\');
    if (root.size() != 3 || !root.at(0).isLetter() || root.at(1) != QLatin1Char(':')
        || root.at(2) != QLatin1Char('\\')) {
        error = QStringLiteral("请选择本地 NTFS 盘符根目录，例如 C:\\。");
        return false;
    }
    root[0] = root.at(0).toUpper();
    const std::wstring device = (QStringLiteral("\\\\.\\") + root.left(2)).toStdWString();
    volume.handle = ::CreateFileW(device.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (volume.handle == INVALID_HANDLE_VALUE) { error = failure(QStringLiteral("打开卷")); return false; }
    DWORD returned = 0;
    if (!::DeviceIoControl(volume.handle, FSCTL_GET_NTFS_VOLUME_DATA, nullptr, 0,
        &volume.info, sizeof(volume.info), &returned, nullptr)) {
        error = failure(QStringLiteral("查询 NTFS 元数据")); return false;
    }
    const auto& data = volume.info;
    const DWORD record = data.BytesPerFileRecordSegment;
    if (returned < sizeof(data) || data.BytesPerSector < 256 || data.BytesPerSector > 65536
        || data.BytesPerCluster < data.BytesPerSector || data.BytesPerCluster > 2U * 1024U * 1024U
        || (data.BytesPerCluster & (data.BytesPerCluster - 1)) != 0
        || record < 512 || record > 65536 || (record & (record - 1)) != 0
        || record % data.BytesPerSector != 0 || data.MftValidDataLength.QuadPart <= 0
        || data.TotalClusters.QuadPart <= 0
        || static_cast<quint64>(data.TotalClusters.QuadPart)
            > static_cast<quint64>(std::numeric_limits<LONGLONG>::max()) / data.BytesPerCluster) {
        error = QStringLiteral("NTFS 卷几何或 MFT 长度无效。"); return false;
    }
    return true;
}

bool queryJournal(Volume& volume, USN_JOURNAL_DATA_V0& journal, DWORD& code)
{
    DWORD returned = 0;
    const bool ok = ::DeviceIoControl(volume.handle, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
        &journal, sizeof(journal), &returned, nullptr) != FALSE;
    code = ok ? ERROR_SUCCESS : ::GetLastError();
    if (ok && (returned < sizeof(journal) || journal.NextUsn < 0 || journal.FirstUsn < 0
        || journal.LowestValidUsn < 0 || journal.FirstUsn > journal.NextUsn)) {
        code = ERROR_INVALID_DATA; return false;
    }
    return ok;
}

enum class RecordResult { Present, Missing, Failed };
RecordResult readRecord(Volume& volume, quint64 index, std::vector<std::byte>& record, QString& error)
{
    NTFS_FILE_RECORD_INPUT_BUFFER input{};
    input.FileReferenceNumber.QuadPart = static_cast<LONGLONG>(index);
    const std::size_t header = offsetof(NTFS_FILE_RECORD_OUTPUT_BUFFER, FileRecordBuffer);
    std::vector<std::byte> buffer(header + volume.info.BytesPerFileRecordSegment);
    DWORD returned = 0;
    if (!::DeviceIoControl(volume.handle, FSCTL_GET_NTFS_FILE_RECORD, &input, sizeof(input),
        buffer.data(), static_cast<DWORD>(buffer.size()), &returned, nullptr)) {
        const DWORD code = ::GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_HANDLE_EOF) return RecordResult::Missing;
        error = failure(QStringLiteral("读取 MFT 记录"), code); return RecordResult::Failed;
    }
    if (returned < header) { error = QStringLiteral("MFT 记录返回头不完整。"); return RecordResult::Failed; }
    NTFS_FILE_RECORD_OUTPUT_BUFFER output{};
    std::memcpy(&output, buffer.data(), header);
    if ((static_cast<quint64>(output.FileReferenceNumber.QuadPart) & kRecordMask) != index)
        return RecordResult::Missing; // FSCTL returns the nearest lower live record for a hole.
    if (output.FileRecordLength != volume.info.BytesPerFileRecordSegment
        || returned < header + output.FileRecordLength) {
        error = QStringLiteral("MFT 记录返回长度无效。"); return RecordResult::Failed;
    }
    record.assign(buffer.begin() + header, buffer.begin() + header + output.FileRecordLength);
    return RecordResult::Present;
}

// Only the stream identity and run mapping govern a raw MFT scan. FILE headers,
// USA values and timestamps can change while the same mapping remains valid.
struct MftMapping {
    quint64 baseReference = 0;
    quint64 streamBytes = 0;
    QSet<quint64> records;
    std::vector<ntfs::MftStreamPart> parts;
    std::vector<ntfs::DataExtent> extents;
};

bool readAttributeList(Volume& volume, const std::vector<ntfs::MftStreamPart>& parts,
    std::vector<std::uint64_t>& references, QString& error, const NtfsFastIndex::Cancel& cancel)
{
    constexpr quint64 limit = 16U * 1024U * 1024U;
    if (parts.size() != 1 || parts.front().lowestVcn != 0
        || parts.front().logicalBytes == 0 || parts.front().logicalBytes > limit) {
        error = QStringLiteral("MFT 数据段或属性列表不受支持，无法保证完整扫描。"); return false;
    }
    const auto& part = parts.front();
    const quint64 sectorBytes = volume.info.BytesPerSector;
    const quint64 clusterBytes = volume.info.BytesPerCluster;
    const quint64 length = part.logicalBytes;
    const quint64 padded = (length + sectorBytes - 1) / sectorBytes * sectorBytes;
    SectorBuffer bytes(static_cast<std::size_t>(padded));
    SectorBuffer scratch(static_cast<std::size_t>(std::min<quint64>(kChunkBytes, padded)));
    quint64 filled = 0;
    quint64 expectedVcn = 0;
    for (const auto& extent : part.extents) {
        if (stopped(cancel)) return false;
        if (extent.startVcn != expectedVcn || extent.clusterCount == 0 || extent.sparse
            || extent.startLcn >= static_cast<quint64>(volume.info.TotalClusters.QuadPart)
            || extent.clusterCount > static_cast<quint64>(volume.info.TotalClusters.QuadPart) - extent.startLcn
            || extent.clusterCount > std::numeric_limits<quint64>::max() / clusterBytes
            || extent.clusterCount > std::numeric_limits<quint64>::max() - expectedVcn) {
            error = QStringLiteral("MFT 数据段位置无效。"); return false;
        }
        expectedVcn += extent.clusterCount;
        quint64 within = 0;
        const quint64 extentBytes = extent.clusterCount * clusterBytes;
        while (filled < padded && within < extentBytes) {
            if (stopped(cancel)) return false;
            const DWORD count = static_cast<DWORD>(std::min<quint64>(kChunkBytes,
                std::min(padded - filled, extentBytes - within)));
            const quint64 absolute = extent.startLcn * clusterBytes + within;
            if (!readRawVolume(volume, absolute, count, bytes.data() + filled, scratch, error)) return false;
            filled += count;
            within += count;
        }
    }
    if (filled != padded || part.highestVcn == std::numeric_limits<quint64>::max()
        || expectedVcn != part.highestVcn + 1
        || !ntfs::ParseMftAttributeList(bytes.data(), static_cast<std::size_t>(length), references)) {
        error = QStringLiteral("MFT 数据段或属性列表不受支持，无法保证完整扫描。"); return false;
    }
    return true;
}

bool readMftMapping(Volume& volume, MftMapping& mapping, QString& error,
    const NtfsFastIndex::Cancel& cancel)
{
    std::vector<std::byte> first;
    if (readRecord(volume, 0, first, error) != RecordResult::Present) {
        if (error.isEmpty()) error = QStringLiteral("无法读取 MFT 自身记录。");
        return false;
    }
    ntfs::ParsedRecord base;
    std::vector<std::uint64_t> references;
    std::vector<ntfs::MftStreamPart> attributeListParts;
    if (!ntfs::ParseRecord(first.data(), first.size(), volume.info.BytesPerSector,
            0, base, ntfs::RecordFormat::FileSystemControl) || !base.baseRecord || !base.inUse
        || !ntfs::ParseMftStreamParts(first.data(), first.size(), volume.info.BytesPerSector,
            mapping.parts, references, ntfs::RecordFormat::FileSystemControl, &attributeListParts)) {
        error = QStringLiteral("MFT 数据段或属性列表不受支持，无法保证完整扫描。"); return false;
    }
    mapping.baseReference = base.reference;
    mapping.records.insert(base.reference);
    if (!attributeListParts.empty()) {
        std::vector<std::uint64_t> externalReferences;
        if (!readAttributeList(volume, attributeListParts, externalReferences, error, cancel)) return false;
        references.insert(references.end(), externalReferences.begin(), externalReferences.end());
    }
    for (std::size_t position = 0; position < references.size(); ++position) {
        if (stopped(cancel)) return false;
        const quint64 reference = references[position];
        if ((reference & kRecordMask) == 0) {
            if (reference != base.reference) {
                error = QStringLiteral("MFT 属性列表中的基础记录身份无效。"); return false;
            }
            continue;
        }
        if (mapping.records.contains(reference)) continue;
        if (mapping.records.size() >= 257) {
            error = QStringLiteral("MFT 扩展记录过多。"); return false;
        }
        std::vector<std::byte> bytes;
        if (readRecord(volume, reference & kRecordMask, bytes, error) != RecordResult::Present) {
            if (error.isEmpty()) error = QStringLiteral("MFT 扩展记录已失效。");
            return false;
        }
        ntfs::ParsedRecord parsed;
        quint64 baseReference = 0;
        std::memcpy(&baseReference, bytes.data() + 32, 8);
        if (!ntfs::ParseRecord(bytes.data(), bytes.size(), volume.info.BytesPerSector,
                reference & kRecordMask, parsed, ntfs::RecordFormat::FileSystemControl)
            || parsed.reference != reference || !parsed.inUse || baseReference != base.reference) {
            error = QStringLiteral("MFT 扩展记录身份校验失败。"); return false;
        }
        std::vector<ntfs::MftStreamPart> moreParts;
        std::vector<std::uint64_t> moreReferences;
        if (!ntfs::ParseMftStreamParts(bytes.data(), bytes.size(), volume.info.BytesPerSector,
            moreParts, moreReferences, ntfs::RecordFormat::FileSystemControl)) {
            error = QStringLiteral("MFT 扩展数据段解析失败。"); return false;
        }
        mapping.records.insert(reference);
        mapping.parts.insert(mapping.parts.end(), moreParts.begin(), moreParts.end());
        references.insert(references.end(), moreReferences.begin(), moreReferences.end());
    }
    std::sort(mapping.parts.begin(), mapping.parts.end(), [](const auto& a, const auto& b) { return a.lowestVcn < b.lowestVcn; });
    quint64 expectedVcn = 0;
    const quint64 clusterBytes = volume.info.BytesPerCluster;
    for (const auto& part : mapping.parts) {
        if (part.lowestVcn != expectedVcn || part.highestVcn < part.lowestVcn
            || part.highestVcn == std::numeric_limits<quint64>::max()) {
            error = QStringLiteral("MFT 数据段存在缺口或重叠。"); return false;
        }
        if (part.lowestVcn == 0) mapping.streamBytes = part.logicalBytes;
        for (const auto& extent : part.extents) {
            if (extent.sparse || extent.startLcn >= static_cast<quint64>(volume.info.TotalClusters.QuadPart)
                || extent.clusterCount > static_cast<quint64>(volume.info.TotalClusters.QuadPart) - extent.startLcn) {
                error = QStringLiteral("MFT 数据段位置无效。"); return false;
            }
            mapping.extents.push_back(extent);
        }
        expectedVcn = part.highestVcn + 1;
    }
    const quint64 validBytes = static_cast<quint64>(volume.info.MftValidDataLength.QuadPart);
    if (mapping.streamBytes < validBytes || expectedVcn > std::numeric_limits<quint64>::max() / clusterBytes
        || expectedVcn * clusterBytes < mapping.streamBytes) {
        error = QStringLiteral("MFT 数据段不能覆盖有效数据长度。"); return false;
    }
    return true;
}

bool sameMftMapping(const MftMapping& left, const MftMapping& right)
{
    if (left.baseReference != right.baseReference || left.streamBytes != right.streamBytes
        || left.records != right.records || left.extents.size() != right.extents.size()) return false;
    for (std::size_t i = 0; i < left.extents.size(); ++i) {
        const auto& a = left.extents[i];
        const auto& b = right.extents[i];
        if (a.startVcn != b.startVcn || a.startLcn != b.startLcn
            || a.clusterCount != b.clusterCount || a.sparse != b.sparse) return false;
    }
    return true;
}

void insertRecord(NtfsIndexSnapshot& snapshot, const ntfs::ParsedRecord& parsed,
    const std::byte* bytes)
{
    if (!parsed.inUse) return;
    if (!parsed.baseRecord) {
        NtfsIndexExtension extension;
        std::memcpy(&extension.baseReference, bytes + 32, 8);
        for (const auto& name : parsed.names)
            extension.names.push_back({ name.parentReference, QString::fromStdU16String(name.name) });
        snapshot.extensions.insert(parsed.reference, std::move(extension));
        return;
    }
    NtfsIndexEntry entry;
    entry.fileReference = parsed.reference;
    entry.attributes = parsed.attributes | (parsed.directory ? FILE_ATTRIBUTE_DIRECTORY : 0U);
    entry.logicalBytes = parsed.logicalBytes;
    entry.allocatedBytes = parsed.allocatedBytes;
    entry.sizeKnown = parsed.sizeKnown;
    entry.hasAttributeList = parsed.hasAttributeList;
    entry.attributeListResident = parsed.attributeListResident;
    for (quint64 reference : parsed.attributeReferences) entry.attributeReferences.push_back(reference);
    for (const auto& name : parsed.names) {
        NtfsIndexName item;
        item.parentReference = name.parentReference;
        item.name = QString::fromStdU16String(name.name);
        entry.names.push_back(std::move(item));
    }
    entry.baseNames = entry.names;
    std::sort(entry.names.begin(), entry.names.end(), [](const NtfsIndexName& a, const NtfsIndexName& b) {
        if (a.parentReference != b.parentReference) return a.parentReference < b.parentReference;
        return a.name < b.name;
    });
    if (!entry.names.isEmpty()) {
        entry.parentReference = entry.names.front().parentReference;
        entry.name = entry.names.front().name;
    }
    if ((parsed.reference & kRecordMask) == 5) snapshot.rootReference = parsed.reference;
    snapshot.entries.insert(parsed.reference, std::move(entry));
}

// The journal is read to a captured upper cursor. Changes after that cursor stay
// for the next refresh. We re-read dirty MFT records instead of guessing sizes or
// applying rename pairs to one hard-link name. No per-file handles are opened.
bool replay(Volume& volume, NtfsIndexSnapshot& snapshot, qint64 upper,
    const NtfsFastIndex::Cancel& cancel, const NtfsFastIndex::Progress& progress)
{
    QSet<quint64> dirty;
    std::vector<std::byte> output(1024U * 1024U);
    qint64 cursor = snapshot.nextUsn;
    while (cursor < upper) {
        if (stopped(cancel)) { snapshot.cancelled = true; return false; }
        READ_USN_JOURNAL_DATA_V0 request{};
        request.StartUsn = cursor;
        request.ReasonMask = 0xffffffffU;
        request.ReturnOnlyOnClose = FALSE;
        request.UsnJournalID = snapshot.journalId;
        DWORD returned = 0;
        if (!::DeviceIoControl(volume.handle, FSCTL_READ_USN_JOURNAL, &request, sizeof(request),
            output.data(), static_cast<DWORD>(output.size()), &returned, nullptr)) {
            snapshot.error = failure(QStringLiteral("读取 USN Journal"));
            snapshot.rebuildRequired = true; return false;
        }
        qint64 next = 0;
        if (returned < sizeof(next)) { snapshot.error = QStringLiteral("USN 返回头不完整。"); return false; }
        std::memcpy(&next, output.data(), sizeof(next));
        if (next <= cursor) { snapshot.error = QStringLiteral("USN 游标未前进，请重建索引。"); snapshot.rebuildRequired = true; return false; }
        std::size_t offset = sizeof(next);
        while (offset < returned) {
            DWORD length = 0;
            WORD major = 0;
            if (returned - offset < 8) { snapshot.error = QStringLiteral("USN 记录被截断。"); return false; }
            std::memcpy(&length, output.data() + offset, 4);
            std::memcpy(&major, output.data() + offset + 4, 2);
            if (length < 60 || length % 8 != 0 || length > returned - offset || major != 2) {
                snapshot.error = QStringLiteral("USN 记录版本或长度不受支持，请重建索引。"); snapshot.rebuildRequired = true; return false;
            }
            quint64 reference = 0;
            qint64 usn = 0;
            WORD nameLength = 0, nameOffset = 0;
            std::memcpy(&reference, output.data() + offset + 8, 8);
            std::memcpy(&usn, output.data() + offset + 24, 8);
            std::memcpy(&nameLength, output.data() + offset + 56, 2);
            std::memcpy(&nameOffset, output.data() + offset + 58, 2);
            if (usn < cursor || usn >= next || nameOffset < 60 || nameLength % 2 != 0
                || nameOffset > length || nameLength > length - nameOffset) {
                snapshot.error = QStringLiteral("USN 记录字段无效。"); return false;
            }
            if (usn < upper) dirty.insert(reference & kRecordMask);
            if (static_cast<quint64>(dirty.size()) > kDirtyLimit) {
                snapshot.error = QStringLiteral("USN 变更过多，请重建索引。"); snapshot.rebuildRequired = true; return false;
            }
            offset += length;
        }
        cursor = std::min(next, upper);
    }
    quint64 processed = 0;
    std::vector<std::byte> bytes;
    // Remove every stale incarnation of affected record indexes before accepting
    // their current sequence. One pass avoids an O(files * changes) lookup.
    for (auto it = snapshot.entries.begin(); it != snapshot.entries.end();) {
        if (dirty.contains(it.key() & kRecordMask)) it = snapshot.entries.erase(it);
        else ++it;
    }
    for (auto it = snapshot.extensions.begin(); it != snapshot.extensions.end();) {
        if (dirty.contains(it.key() & kRecordMask) || dirty.contains(it->baseReference & kRecordMask))
            it = snapshot.extensions.erase(it);
        else ++it;
    }
    struct PendingRecord { quint64 index; quint64 expectedReference; quint64 expectedBase; };
    std::vector<PendingRecord> pending;
    pending.reserve(static_cast<std::size_t>(dirty.size()));
    for (quint64 index : dirty) pending.push_back({ index, 0, 0 });
    QSet<quint64> scheduled = dirty;
    QHash<quint64, QPair<quint64, quint64>> expectedIdentities;
    QHash<quint64, QPair<quint64, quint64>> actualIdentities;
    for (std::size_t position = 0; position < pending.size(); ++position) {
        const auto request = pending[position];
        const quint64 reference = request.index;
        if (stopped(cancel)) { snapshot.cancelled = true; return false; }
        const auto result = readRecord(volume, reference & kRecordMask, bytes, snapshot.error);
        if (result == RecordResult::Failed) return false;
        if (result == RecordResult::Present) {
            ntfs::ParsedRecord parsed;
            if (!ntfs::ParseRecord(bytes.data(), bytes.size(), volume.info.BytesPerSector,
                reference & kRecordMask, parsed, ntfs::RecordFormat::FileSystemControl)) {
                snapshot.error = QStringLiteral("USN 变更记录校验失败，请重试或重建索引。"); return false;
            }
            quint64 actualBase = 0;
            std::memcpy(&actualBase, bytes.data() + 32, 8);
            if (parsed.inUse) actualIdentities.insert(reference, { parsed.reference, actualBase });
            if ((request.expectedReference && parsed.reference != request.expectedReference)
                || (request.expectedBase && actualBase != request.expectedBase)) {
                snapshot.error = QStringLiteral("USN 变更扩展记录身份已变化，请重建索引。");
                snapshot.rebuildRequired = true; return false;
            }
            if (parsed.hasAttributeList && !parsed.attributeListResident) {
                snapshot.error = QStringLiteral("变更文件包含非驻留属性列表，需要重建 MFT 索引。");
                snapshot.rebuildRequired = true; return false;
            }
            insertRecord(snapshot, parsed, bytes.data());
            std::vector<std::uint64_t> references = parsed.attributeReferences;
            if (!parsed.baseRecord && actualBase != 0) references.push_back(actualBase);
            for (quint64 extension : references) {
                const quint64 index = extension & kRecordMask;
                if (index == reference) {
                    if (extension != parsed.reference) {
                        snapshot.error = QStringLiteral("USN 属性列表包含过期的文件引用，请重建索引。");
                        snapshot.rebuildRequired = true; return false;
                    }
                    continue;
                }
                const quint64 base = parsed.baseRecord ? parsed.reference : actualBase;
                const QPair<quint64, quint64> identity{ extension, extension == base ? 0 : base };
                const auto existing = expectedIdentities.constFind(index);
                if (existing != expectedIdentities.cend() && existing.value() != identity) {
                    snapshot.error = QStringLiteral("USN 属性列表中的扩展引用冲突，请重建索引。");
                    snapshot.rebuildRequired = true; return false;
                }
                expectedIdentities.insert(index, identity);
                if (scheduled.contains(index)) continue;
                if (pending.size() >= kDirtyLimit) {
                    snapshot.error = QStringLiteral("USN 变更过多，请重建索引。");
                    snapshot.rebuildRequired = true; return false;
                }
                scheduled.insert(index);
                pending.push_back({ index, identity.first, identity.second });
            }
        } else if (request.expectedReference) {
            snapshot.error = QStringLiteral("USN 变更扩展记录已不存在，请重建索引。");
            snapshot.rebuildRequired = true; return false;
        }
        ++processed;
        if (progress && (processed % 1024 == 0 || processed == static_cast<quint64>(pending.size())))
            progress(processed, static_cast<quint64>(pending.size()));
    }
    for (auto it = expectedIdentities.cbegin(); it != expectedIdentities.cend(); ++it) {
        const auto actual = actualIdentities.constFind(it.key());
        if (actual == actualIdentities.cend() || actual.value() != it.value()) {
            snapshot.error = QStringLiteral("USN 属性列表引用身份校验失败，请重建索引。");
            snapshot.rebuildRequired = true; return false;
        }
    }
    USN_JOURNAL_DATA_V0 after{};
    DWORD code = 0;
    if (!queryJournal(volume, after, code)) {
        snapshot.error = failure(QStringLiteral("查询 USN Journal"), code);
        snapshot.rebuildRequired = code == ERROR_JOURNAL_NOT_ACTIVE || code == ERROR_JOURNAL_DELETE_IN_PROGRESS;
        return false;
    }
    if (after.UsnJournalID != snapshot.journalId
        || cursor < std::max(after.FirstUsn, after.LowestValidUsn)) {
        snapshot.error = QStringLiteral("USN Journal 已重置或覆盖，请重建索引。");
        snapshot.rebuildRequired = true; return false;
    }
    snapshot.nextUsn = upper;
    return true;
}

void finish(NtfsIndexSnapshot& snapshot, const NtfsFastIndex::Cancel& cancel = NtfsFastIndex::Cancel())
{
    snapshot.complete = false;
    if (cancel && cancel->load()) { snapshot.cancelled = true; return; }
    quint64 visits = 0;
    auto cancelled = [&]() {
        if ((visits++ % 1024 == 0) && cancel && cancel->load()) {
            snapshot.cancelled = true;
            return true;
        }
        return false;
    };
    // FILE_NAME attributes can reside in extension records. Keep their identity
    // separately so a later rename/deletion does not retain obsolete aliases.
    for (auto it = snapshot.entries.begin(); it != snapshot.entries.end(); ++it) {
        if (cancelled()) return;
        it->names = it->baseNames;
    }
    for (auto it = snapshot.extensions.cbegin(); it != snapshot.extensions.cend(); ++it) {
        if (cancelled()) return;
        auto base = snapshot.entries.find(it->baseReference);
        if (base == snapshot.entries.end()) continue; // Stale base sequence is never reused.
        if (!base->hasAttributeList || !base->attributeListResident
            || !base->attributeReferences.contains(it.key())) continue;
        for (const auto& name : it->names) {
            const bool exists = std::any_of(base->names.cbegin(), base->names.cend(), [&](const auto& item) {
                return item.parentReference == name.parentReference && item.name == name.name;
            });
            if (!exists) base->names.push_back(name);
        }
    }
    for (auto it = snapshot.entries.begin(); it != snapshot.entries.end(); ++it) {
        if (cancelled()) return;
        std::sort(it->names.begin(), it->names.end(), [](const auto& a, const auto& b) {
            if (a.parentReference != b.parentReference) return a.parentReference < b.parentReference;
            return a.name < b.name;
        });
        it->name = it->names.isEmpty() ? QString() : it->names.front().name;
        it->parentReference = it->names.isEmpty() ? 0 : it->names.front().parentReference;
    }
    snapshot.unknownSizeCount = 0;
    snapshot.namesIncompleteCount = 0;
    for (auto it = snapshot.entries.cbegin(); it != snapshot.entries.cend(); ++it) {
        if (cancelled()) return;
        if (!it->isDirectory() && !it->sizeKnown) ++snapshot.unknownSizeCount;
        if (it->hasAttributeList && !it->attributeListResident) ++snapshot.namesIncompleteCount;
    }
    snapshot.complete = true;
    snapshot.status = snapshot.journalAvailable
        ? QStringLiteral("MFT 索引已就绪；USN 增量可用。默认数据流按文件引用去重，硬链接只计一次；未知大小不计入空间总计。")
        : QStringLiteral("MFT 静态索引已就绪；此卷未启用 USN Journal，变更后需要重建。默认数据流按文件引用去重，未知大小不计入空间总计。");
    if (snapshot.namesIncompleteCount != 0)
        snapshot.status = QStringLiteral("MFT 索引已完成，但有 %1 个文件的非驻留属性列表未解析；搜索名称可能不完整，未知大小不计入空间总计。")
            .arg(snapshot.namesIncompleteCount);
}
} // namespace

NtfsFastIndex::Snapshot NtfsFastIndex::build(const QString& volumeRoot,
    const Cancel& cancel, const Progress& progress)
{
    auto snapshot = std::make_shared<NtfsIndexSnapshot>();
    if (stopped(cancel)) { snapshot->cancelled = true; return snapshot; }
    Volume volume;
    if (!openVolume(volumeRoot, volume, snapshot->volumeRoot, snapshot->error)) return snapshot;
    snapshot->volumeSerial = static_cast<quint64>(volume.info.VolumeSerialNumber.QuadPart);
    USN_JOURNAL_DATA_V0 journal{};
    DWORD code = 0;
    snapshot->journalAvailable = queryJournal(volume, journal, code);
    if (!snapshot->journalAvailable && code != ERROR_JOURNAL_NOT_ACTIVE && code != ERROR_JOURNAL_DELETE_IN_PROGRESS) {
        snapshot->error = failure(QStringLiteral("查询 USN Journal"), code); return snapshot;
    }
    if (snapshot->journalAvailable) {
        snapshot->journalId = journal.UsnJournalID;
        snapshot->nextUsn = journal.NextUsn; // Capture BEFORE enumerating the MFT.
    }
    const quint64 validBytes = static_cast<quint64>(volume.info.MftValidDataLength.QuadPart);
    const DWORD recordBytes = volume.info.BytesPerFileRecordSegment;
    const quint64 total = validBytes / recordBytes;
    if (validBytes % recordBytes != 0 || total == 0 || total > kRecordLimit) {
        snapshot->error = QStringLiteral("MFT 记录数超过索引上限或长度未对齐。"); return snapshot;
    }
    MftMapping mapping;
    if (!readMftMapping(volume, mapping, snapshot->error, cancel)) {
        if (stopped(cancel)) snapshot->cancelled = true;
        return snapshot;
    }
    const auto& extents = mapping.extents;
    const quint64 clusterBytes = volume.info.BytesPerCluster;
    SectorBuffer chunk(kChunkBytes);
    SectorBuffer scratch(kChunkBytes);
    quint64 logical = 0;
    std::size_t extentIndex = 0;
    while (logical < validBytes) {
        if (stopped(cancel)) { snapshot->cancelled = true; return snapshot; }
        const DWORD wanted = static_cast<DWORD>(std::min<quint64>(chunk.size(), validBytes - logical));
        DWORD filled = 0;
        while (filled < wanted) {
            const quint64 location = logical + filled;
            while (extentIndex < extents.size()
                && location / clusterBytes >= extents[extentIndex].startVcn + extents[extentIndex].clusterCount) ++extentIndex;
            if (extentIndex == extents.size() || location / clusterBytes < extents[extentIndex].startVcn) {
                snapshot->error = QStringLiteral("MFT 读取范围未映射。"); return snapshot;
            }
            const auto& extent = extents[extentIndex];
            const quint64 within = location - extent.startVcn * clusterBytes;
            const DWORD count = static_cast<DWORD>(std::min<quint64>(wanted - filled, extent.clusterCount * clusterBytes - within));
            const quint64 absolute = extent.startLcn * clusterBytes + within;
            if (!readRawVolume(volume, absolute, count, chunk.data() + filled, scratch, snapshot->error)) return snapshot;
            filled += count;
        }
        for (DWORD offset = 0; offset < wanted; offset += recordBytes) {
            const quint64 index = (logical + offset) / recordBytes;
            // Only FILE slots are parsed; BAAD remains an explicit failure.
            // Raw reads on a live volume can see a torn or deleted FILE slot.
            // Ask NTFS for that exact record before abandoning the snapshot.
            if (std::memcmp(chunk.data() + offset, "BAAD", 4) == 0) {
                snapshot->error = QStringLiteral("MFT 包含损坏记录，无法完成索引。"); return snapshot;
            }
            if (std::memcmp(chunk.data() + offset, "FILE", 4) != 0) continue;
            ntfs::ParsedRecord parsed;
            const std::byte* record = chunk.data() + offset;
            std::vector<std::byte> currentRecord;
            if (!ntfs::ParseRecord(chunk.data() + offset, recordBytes, volume.info.BytesPerSector, index, parsed)) {
                if (stopped(cancel)) { snapshot->cancelled = true; return snapshot; }
                const auto result = readRecord(volume, index, currentRecord, snapshot->error);
                if (stopped(cancel)) { snapshot->cancelled = true; return snapshot; }
                if (result == RecordResult::Failed) return snapshot;
                // FSCTL returns a lower live record when the requested slot is
                // free. readRecord verifies its identity; never insert it here.
                if (result == RecordResult::Missing) continue;
                if (!ntfs::ParseRecord(currentRecord.data(), currentRecord.size(), volume.info.BytesPerSector,
                        index, parsed, ntfs::RecordFormat::FileSystemControl)) {
                    snapshot->error = QStringLiteral("MFT 记录校验失败，卷可能正在变化；请重试。"); return snapshot;
                }
                record = currentRecord.data();
            }
            insertRecord(*snapshot, parsed, record);
        }
        logical += wanted;
        if (progress) progress(logical / recordBytes, total);
    }
    if (snapshot->rootReference == 0) { snapshot->error = QStringLiteral("MFT 根目录记录不可用。"); return snapshot; }
    // Raw mapping must remain stable for the duration of the scan. A growing or
    // relocated MFT is retried; replaying names cannot repair a missed MFT run.
    MftMapping currentMapping;
    NTFS_VOLUME_DATA_BUFFER currentInfo{};
    DWORD currentInfoBytes = 0;
    if (!::DeviceIoControl(volume.handle, FSCTL_GET_NTFS_VOLUME_DATA, nullptr, 0,
        &currentInfo, sizeof(currentInfo), &currentInfoBytes, nullptr)) {
        snapshot->error = failure(QStringLiteral("查询 NTFS 元数据")); return snapshot;
    }
    if (currentInfoBytes < sizeof(currentInfo)
        || currentInfo.VolumeSerialNumber.QuadPart != volume.info.VolumeSerialNumber.QuadPart
        || currentInfo.BytesPerSector != volume.info.BytesPerSector
        || currentInfo.BytesPerCluster != volume.info.BytesPerCluster
        || currentInfo.BytesPerFileRecordSegment != volume.info.BytesPerFileRecordSegment
        || currentInfo.MftValidDataLength.QuadPart != volume.info.MftValidDataLength.QuadPart) {
        snapshot->error = QStringLiteral("扫描期间 MFT 布局或长度已变化，请重试。"); return snapshot;
    }
    if (!readMftMapping(volume, currentMapping, snapshot->error, cancel)) {
        if (stopped(cancel)) snapshot->cancelled = true;
        return snapshot;
    }
    if (!sameMftMapping(mapping, currentMapping)) {
        snapshot->error = QStringLiteral("扫描期间 MFT 布局或长度已变化，请重试。"); return snapshot;
    }
    if (snapshot->journalAvailable) {
        USN_JOURNAL_DATA_V0 after{};
        if (!queryJournal(volume, after, code)) {
            snapshot->error = failure(QStringLiteral("查询 USN Journal"), code); return snapshot;
        }
        if (after.UsnJournalID != snapshot->journalId
            || snapshot->nextUsn < std::max(after.FirstUsn, after.LowestValidUsn)) {
            snapshot->error = QStringLiteral("扫描期间 USN Journal 已覆盖，请重建索引。"); snapshot->rebuildRequired = true; return snapshot;
        }
        if (!replay(volume, *snapshot, after.NextUsn, cancel, progress)) return snapshot;
    }
    finish(*snapshot, cancel);
    return snapshot;
}

NtfsFastIndex::Snapshot NtfsFastIndex::refresh(const Snapshot& previous,
    const Cancel& cancel, const Progress& progress)
{
    if (!previous) return build(QString(), cancel, progress);
    auto output = std::make_shared<NtfsIndexSnapshot>(*previous);
    output->complete = false;
    output->error.clear();
    output->status.clear();
    output->cancelled = false;
    output->rebuildRequired = false;
    if (stopped(cancel)) { output->cancelled = true; return output; }
    if (!previous->complete || !previous->journalAvailable) {
        output->error = QStringLiteral("此索引没有可用的 USN 增量基线，请重建。"); output->rebuildRequired = true; return output;
    }
    Volume volume;
    QString root;
    if (!openVolume(previous->volumeRoot, volume, root, output->error)) return output;
    USN_JOURNAL_DATA_V0 journal{};
    DWORD code = 0;
    if (static_cast<quint64>(volume.info.VolumeSerialNumber.QuadPart) != previous->volumeSerial) {
        output->error = QStringLiteral("卷身份或 USN Journal 已变化，请重建索引。"); output->rebuildRequired = true; return output;
    }
    if (!queryJournal(volume, journal, code)) {
        output->error = failure(QStringLiteral("查询 USN Journal"), code);
        output->rebuildRequired = code == ERROR_JOURNAL_NOT_ACTIVE || code == ERROR_JOURNAL_DELETE_IN_PROGRESS;
        return output;
    }
    if (journal.UsnJournalID != previous->journalId
        || previous->nextUsn < std::max(journal.FirstUsn, journal.LowestValidUsn)
        || previous->nextUsn > journal.NextUsn) {
        output->error = QStringLiteral("卷身份或 USN Journal 已变化，请重建索引。"); output->rebuildRequired = true; return output;
    }
    if (!replay(volume, *output, journal.NextUsn, cancel, progress)) {
        // Never publish a half-applied journal as a usable newer snapshot.
        auto failureSnapshot = std::make_shared<NtfsIndexSnapshot>(*previous);
        failureSnapshot->complete = false;
        failureSnapshot->error = output->error;
        failureSnapshot->status.clear();
        failureSnapshot->cancelled = output->cancelled;
        failureSnapshot->rebuildRequired = output->rebuildRequired;
        return failureSnapshot;
    }
    finish(*output, cancel);
    if (output->cancelled) {
        auto cancelledSnapshot = std::make_shared<NtfsIndexSnapshot>(*previous);
        cancelledSnapshot->complete = false;
        cancelledSnapshot->cancelled = true;
        cancelledSnapshot->status.clear();
        return cancelledSnapshot;
    }
    return output;
}

QString NtfsFastIndex::fullPath(const NtfsIndexSnapshot& snapshot, quint64 reference)
{
    if (reference == snapshot.rootReference) return snapshot.volumeRoot;
    QStringList components;
    QSet<quint64> visited;
    for (int depth = 0; depth < 1024; ++depth) {
        if (reference == snapshot.rootReference)
            return snapshot.volumeRoot + components.join(QLatin1Char('\\'));
        if (visited.contains(reference)) return {};
        visited.insert(reference);
        const auto it = snapshot.entries.constFind(reference);
        if (it == snapshot.entries.cend() || it->name.isEmpty()) return {};
        components.prepend(it->name);
        reference = it->parentReference;
    }
    return {};
}
} // namespace ks::files
