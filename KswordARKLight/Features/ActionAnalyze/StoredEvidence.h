#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace Ksword::Features::ActionAnalyze {

struct SegmentIdentity {
    std::string projectId;
    std::string sampleId;
    std::uint32_t streamKind = 0;
    std::uint64_t ordinal = 0;
    bool operator==(const SegmentIdentity&) const = default;
};

struct EvidenceRecord {
    std::uint64_t offset = 0;
    std::uint64_t blockOrdinal = 0;
    std::uint64_t sequence = 0;
    std::uint16_t type = 0;
    std::uint16_t schemaVersion = 0;
    std::uint32_t flags = 0;
    std::uint32_t payloadBytes = 0;
    std::optional<std::uint64_t> eventOrdinal;
    std::optional<std::uint64_t> sourceDictionaryId;
    std::optional<std::uint64_t> epochDictionaryId;
    std::optional<std::uint64_t> receiveQpc;
    std::optional<std::uint64_t> rawSequence;
    std::optional<std::uint64_t> actorObjectId;
    std::optional<std::uint64_t> targetObjectId;
    std::optional<std::uint64_t> threadObjectId;
    std::optional<std::uint32_t> headerPid;
    std::optional<std::uint32_t> headerTid;
    std::uint16_t category = 0;
    std::uint32_t eventKind = 0;
    std::optional<Ksword::Evidence::ArchivedEtwObservation> etw; // 归档声明的 ETW 记录上下文。
    std::wstring preview;
};

struct SegmentEvidence {
    std::optional<SegmentIdentity> identity;
    std::uint64_t createdUtc100ns = 0;
    std::uint64_t fileBytes = 0;
    std::uint64_t framedBytes = 0;
    std::uint64_t decodedPrefixBytes = 0;
    std::optional<std::uint64_t> lastBlockOrdinal; // 最后一个完整解码块的序号。
    std::optional<std::uint64_t> lastSequence; // 最后一个完整解码块的末记录序号。
    std::uint64_t failureOffset = 0;
    std::size_t blocks = 0;
    std::size_t records = 0;
    std::size_t opaqueOptionalRecords = 0;
    std::size_t opaqueRequiredRecords = 0;
    std::string diagnostic;
    std::uint32_t systemError = 0;
    std::wstring fileIdentity;
    std::vector<EvidenceRecord> rows;
};

inline constexpr std::size_t kEvidenceRows = 4096;
inline constexpr std::uint64_t kEvidenceScanBytes = 64ULL * 1024 * 1024;

// The caller supplies one immutable byte extent and an exact sequential reader.
// Return a nonzero native error if the span cannot be filled.
using ReadExact = std::function<std::uint32_t(std::span<std::uint8_t>)>;
SegmentEvidence ReadStoredEvidence(std::uint64_t size, const ReadExact& read,
    const SegmentIdentity* expected = nullptr);

SegmentEvidence OpenStoredEvidence(const std::wstring& path);

// 读取调用方持有的同步只读句柄。可选端点限定本次投影，fileBytes 仍表示物理长度。
SegmentEvidence ReadOpenStoredEvidence(HANDLE file, std::optional<std::uint64_t> endOffset,
    const SegmentIdentity* expected = nullptr);

} // namespace Ksword::Features::ActionAnalyze
