#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace ks::cli::action_analyze::archive {

inline constexpr std::size_t kSegmentHeaderBytes = 96;
inline constexpr std::size_t kBlockHeaderBytes = 80;
inline constexpr std::size_t kRecordHeaderBytes = 32;
inline constexpr std::uint32_t kMaxDecodedBlockBytes = 8u * 1024u * 1024u;
inline constexpr std::uint32_t kMaxStoredBlockBytes = 9u * 1024u * 1024u;
inline constexpr std::uint32_t kMaxBlockRecords = 32768;
inline constexpr std::uint64_t kMaxSegmentBytes = 1024ull * 1024ull * 1024ull;
inline constexpr std::uint32_t kRequiredRecord = 1u;

// UUID 使用 RFC 字节顺序。调用方可从规范文本转换后传入。
using ArchiveUuid = std::array<std::uint8_t, 16>;

enum class StreamKind : std::uint32_t {
    Raw = 1,
    Records = 2,
    Control = 3,
    Analysis = 4,
};

struct SegmentIdentity {
    StreamKind stream = StreamKind::Records;
    std::uint64_t ordinal = 1;
    ArchiveUuid project{};
    ArchiveUuid sample{};
};

struct SegmentHeader {
    SegmentIdentity identity;
    std::uint64_t createdUtc100ns = 0;
};

struct QpcRange {
    std::uint64_t minimum = 0;
    std::uint64_t maximum = 0;
};

struct StoredRecord {
    std::uint16_t type = 0;
    std::uint16_t schemaVersion = 1;
    std::uint32_t flags = 0;
    std::uint64_t sequence = 0;
    std::vector<std::uint8_t> payload;
};

struct RecordView {
    std::uint16_t type = 0;
    std::uint16_t schemaVersion = 0;
    std::uint32_t flags = 0;
    std::uint64_t sequence = 0;
    std::uint64_t offset = 0;
    const std::uint8_t* payload = nullptr;
    std::uint32_t payloadBytes = 0;
    // 仅标明类型编号列在目录中、记录头声明 v1。正文语义由调用方验证。
    bool catalogTypeV1 = false;
};

struct BlockInfo {
    std::uint64_t offset = 0;
    std::uint64_t endOffset = 0;
    std::uint64_t ordinal = 0;
    std::uint64_t firstSequence = 0;
    std::uint64_t lastSequence = 0;
    std::optional<QpcRange> receiveQpc;
    std::uint32_t recordCount = 0;
};

enum class SegmentIssue {
    None,
    Magic,
    HeaderCrc,
    Version,
    HeaderLength,
    Flags,
    Reserved,
    Stream,
    Identity,
    Ordinal,
    BlockLength,
    RecordCount,
    Sequence,
    QpcRange,
    Codec,
    StoredCrc,
    DecodedCrc,
    RecordLength,
    RecordSchema,
    RecordPayloadCrc,
    SegmentLimit,
    EndOfFile,
    FileOpen,
    FileSize,
    FileRead,
    FileWrite,
    FileFlush,
    FileClose,
};

struct SegmentError {
    SegmentIssue issue = SegmentIssue::None;
    std::uint64_t offset = 0;
    std::uint32_t win32Error = 0;
};

std::uint32_t Crc32c(const std::uint8_t* data, std::size_t bytes) noexcept;

} // namespace ks::cli::action_analyze::archive
