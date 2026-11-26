#include "MemorySnapshotReader.h"
#include "ProjectStorage.h"

#include <bcrypt.h>
#include <algorithm>

namespace Ksword::ActionAnalyze {
namespace {
using namespace ProjectStorage;
namespace archive = ks::cli::action_analyze::archive;
namespace memory = ks::cli::action_analyze::memory;
using V = Evidence::JsonValue;

// The archive uses decimal strings for 64-bit fields and JSON UInt for native enums/PIDs.
bool GetNumber(const V& value, std::string_view key, std::uint64_t& out)
{
    const auto* field = value.find(key);
    return field && ((field->type() == Evidence::JsonType::UInt && field->tryGetU64(out)) ||
        ProjectStorage::GetNumber(value, key, out));
}

bool Bool(const V& value, std::string_view key, bool& out)
{
    const auto* field = value.find(key);
    return field && field->tryGetBool(out);
}

bool Range(const V& value, memory::Range& out)
{
    return Fields(value, {"base", "bytes"}) && GetNumber(value, "base", out.base) &&
        GetNumber(value, "bytes", out.length) && out.base && out.length && out.base <= UINT64_MAX - out.length;
}

bool Hash(std::string_view bytes, std::string_view expected)
{
    BCRYPT_ALG_HANDLE provider = nullptr;
    if (BCryptOpenAlgorithmProvider(&provider, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) return false;
    unsigned char digest[32]{};
    const auto status = BCryptHash(provider, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())), static_cast<ULONG>(bytes.size()), digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(provider, 0);
    if (status < 0) return false;
    constexpr char digits[] = "0123456789abcdef";
    std::string text;
    for (auto byte : digest) { text += digits[byte >> 4]; text += digits[byte & 15]; }
    return text == expected;
}

bool Issue(const V* value)
{
    std::uint64_t stage = 0, error = 0;
    std::int64_t native = 0;
    return value && Fields(*value, {"stage", "win32Error", "ntStatus"}) &&
        GetNumber(*value, "stage", stage) && stage <= static_cast<unsigned>(memory::Stage::HashContent) &&
        GetNumber(*value, "win32Error", error) && error <= UINT32_MAX && value->find("ntStatus") &&
        (IsNull(*value, "ntStatus") || (value->find("ntStatus")->tryGetI64(native) && native >= INT32_MIN && native <= INT32_MAX));
}

bool Mapping(const V* value)
{
    if (!value) return false;
    if (value->isNull()) return true;
    memory::Range region;
    std::uint64_t number = 0;
    if (!Fields(*value, {"region", "allocationBase", "state", "type", "protection", "allocationProtection"}) ||
        !value->find("region") || !Range(*value->find("region"), region) || !GetNumber(*value, "allocationBase", number)) return false;
    for (const auto key : {"state", "type", "protection", "allocationProtection"})
        if (!GetNumber(*value, key, number) || number > UINT32_MAX) return false;
    return true;
}

bool OptionalNumber(const V& value, std::string_view key, std::optional<std::uint64_t>& out)
{
    if (IsNull(value, key)) { out.reset(); return true; }
    std::uint64_t number = 0;
    if (!GetNumber(value, key, number)) return false;
    out = number;
    return true;
}

struct HistoricalStop {
    std::uint64_t pid = 0, creation = 0, serial = 0, revision = 0;
    std::string group, stop, backend;
    bool operator==(const HistoricalStop&) const = default;
};

bool StopContext(const V* value, std::uint64_t targetPid, std::uint64_t targetCreation,
    std::optional<HistoricalStop>& out)
{
    if (!value) return false;
    if (value->isNull()) { out.reset(); return true; }
    HistoricalStop token;
    const auto* pid = value->find("pid");
    if (!Fields(*value, {"pid", "creationFileTime", "groupId", "stopId", "backendInstanceId", "eventSerial", "stateRevision"}) ||
        !pid || pid->type() != Evidence::JsonType::UInt || !pid->tryGetU64(token.pid) || token.pid != targetPid ||
        !ProjectStorage::GetNumber(*value, "creationFileTime", token.creation) || token.creation != targetCreation ||
        !GetUuid(*value, "groupId", token.group) || !GetUuid(*value, "stopId", token.stop) ||
        !GetUuid(*value, "backendInstanceId", token.backend) ||
        !ProjectStorage::GetNumber(*value, "eventSerial", token.serial) || !token.serial ||
        !ProjectStorage::GetNumber(*value, "stateRevision", token.revision) || !token.revision) return false;
    out = std::move(token);
    return true;
}

// Historical context is checked and preserved, never converted into live owner tokens.
bool ReadContext(const V* value, std::uint64_t pid, std::uint64_t creation)
{
    if (!value) return true; // Original live writer has no readContext field.
    std::string source, stage;
    bool held = false;
    std::uint64_t error = 0;
    std::optional<HistoricalStop> before, after;
    const auto* nativeError = value->find("win32Error");
    if (!Fields(*value, {"source", "stage", "win32Error", "before", "after", "heldAtBothChecks"}) ||
        !GetString(*value, "source", source) || !GetString(*value, "stage", stage) || !IsText(stage, 256) ||
        !nativeError || nativeError->type() != Evidence::JsonType::UInt || !nativeError->tryGetU64(error) || error > UINT32_MAX ||
        !Bool(*value, "heldAtBothChecks", held) || !StopContext(value->find("before"), pid, creation, before) ||
        !StopContext(value->find("after"), pid, creation, after)) return false;
    if (source == "live-read") return !before && !after && !held;
    return source == "held-event" && before && (!held || (after && *before == *after));
}

bool PlanFields(const V& value)
{
    if (value.find("readContext")) return Fields(value, {"kind", "projectId", "sampleId", "trackingEpoch", "target", "range", "source",
        "atomicProcessSnapshot", "allocationGenerationVerified", "qpcFrequency", "readContext"});
    return Fields(value, {"kind", "projectId", "sampleId", "trackingEpoch", "target", "range", "source",
        "atomicProcessSnapshot", "allocationGenerationVerified", "qpcFrequency"});
}

class Decoder {
public:
    Decoder(std::string_view project, std::string_view sample) : project_(project), sample_(sample) {}
    ArchivedMemorySnapshot snapshot;
    bool ended = false;

    bool Record(const archive::DecodedRecord& record)
    {
        const auto* raw = std::get_if<archive::RawRecordV1>(&record.body);
        if (!raw || ended) return false;
        const auto json = Evidence::ParseJson(raw->metadataJson);
        if (!json.ok()) return false;
        const auto& value = json.value;
        if (!planned_) {
            const auto* range = value.find("range");
            const auto* target = value.find("target");
            bool atomic = true, generation = true;
            std::string epoch, machine, boot, instance;
            std::uint64_t pid = 0, created = 0, frequency = 0;
            if (!raw->inlineRawData.empty() || !PlanFields(value) ||
                !IsString(value, "kind", "selected-memory-plan-v1") || !IsString(value, "projectId", project_) ||
                !IsString(value, "sampleId", sample_) || !GetUuid(value, "trackingEpoch", epoch) || !range || !Range(*range, snapshot.range) ||
                snapshot.range.length > 16 * 1024 * 1024 || !IsString(value, "source", "read-only-memory-sample") ||
                !Bool(value, "atomicProcessSnapshot", atomic) || atomic || !Bool(value, "allocationGenerationVerified", generation) || generation ||
                !GetNumber(value, "qpcFrequency", frequency) || !target ||
                !Fields(*target, {"machineId", "bootId", "processInstanceId", "pid", "creationFileTime"}) ||
                !GetString(*target, "machineId", machine) || machine.empty() || !GetString(*target, "bootId", boot) || boot.empty() ||
                !GetString(*target, "processInstanceId", instance) || instance.empty() || !GetNumber(*target, "pid", pid) || !pid || pid >= UINT32_MAX ||
                !GetNumber(*target, "creationFileTime", created) || !created || !ReadContext(value.find("readContext"), pid, created)) return false;
            snapshot.plan = value;
            next_ = snapshot.range.base;
            planned_ = true;
            return true;
        }
        if (IsString(value, "kind", "selected-memory-page-v1")) {
            if (snapshot.pages.size() >= memory::kMaxTrackedPages) return false;
            memory::Range range;
            std::string state, sha;
            std::uint64_t pageBase = 0;
            std::optional<std::uint64_t> begin, end, returned;
            if (!Fields(value, {"kind", "pageBase", "range", "state", "mappingBefore", "mappingAfter", "issue", "additionalIssue",
                    "readBeginQpc", "readEndQpc", "returnedBytes", "sha256"}) || !value.find("range") || !Range(*value.find("range"), range) ||
                range.base != next_ || range.base + range.length > snapshot.range.base + snapshot.range.length ||
                !GetNumber(value, "pageBase", pageBase) || pageBase > range.base || !GetString(value, "state", state) ||
                !Mapping(value.find("mappingBefore")) || !Mapping(value.find("mappingAfter")) || !Issue(value.find("issue")) ||
                (!IsNull(value, "additionalIssue") && !Issue(value.find("additionalIssue"))) ||
                !OptionalNumber(value, "readBeginQpc", begin) || !OptionalNumber(value, "readEndQpc", end) ||
                begin.has_value() != end.has_value() || (begin && *begin > *end) || !OptionalNumber(value, "returnedBytes", returned)) return false;
            if (state == "sampled") {
                if (raw->inlineRawData.size() != range.length || !returned || *returned != range.length || !begin ||
                    !GetHash(value, "sha256", sha) || !Hash(raw->inlineRawData, sha) ||
                    IsNull(value, "mappingBefore") || IsNull(value, "mappingAfter") ||
                    Evidence::WriteJson(*value.find("mappingBefore")) != Evidence::WriteJson(*value.find("mappingAfter"))) return false;
                snapshot.capturedBytes += range.length;
            } else {
                constexpr std::string_view failures[]{"not-committed", "guarded", "unsafe-read-attributes", "not-readable", "query-failed",
                    "read-failed", "mapping-unstable", "hash-failed"};
                if (std::find(std::begin(failures), std::end(failures), state) == std::end(failures) ||
                    !raw->inlineRawData.empty() || !IsNull(value, "sha256")) return false;
                ++snapshot.unavailablePages;
            }
            snapshot.pages.push_back({value, range, std::string(raw->inlineRawData), record.recordSequence, record.recordOffset});
            next_ += range.length;
            return true;
        }
        bool complete = false, allVisited = false;
        std::uint64_t captured = 0, unavailable = 0, visited = 0, state = 0;
        std::optional<std::uint64_t> begin, end;
        if (!raw->inlineRawData.empty() || !Fields(value, {"kind", "completeRange", "capturedBytes", "unavailablePages", "visitedPages", "allPagesVisited",
                "state", "issue", "beginQpc", "endQpc"}) || !IsString(value, "kind", "selected-memory-end-v1") ||
            !Bool(value, "completeRange", complete) || !Bool(value, "allPagesVisited", allVisited) ||
            !GetNumber(value, "capturedBytes", captured) || captured != snapshot.capturedBytes ||
            !GetNumber(value, "unavailablePages", unavailable) || unavailable != snapshot.unavailablePages ||
            !GetNumber(value, "visitedPages", visited) || visited != snapshot.pages.size() ||
            !GetNumber(value, "state", state) || state > static_cast<unsigned>(memory::State::Failed) ||
            !Issue(value.find("issue")) || !OptionalNumber(value, "beginQpc", begin) || !OptionalNumber(value, "endQpc", end) ||
            (end && (!begin || *end < *begin)) || (allVisited && next_ != snapshot.range.base + snapshot.range.length)) return false;
        const bool actual = allVisited && end && next_ == snapshot.range.base + snapshot.range.length && !unavailable &&
            captured == snapshot.range.length && state == static_cast<unsigned>(memory::State::Stopped);
        if (actual != complete) return false;
        snapshot.completeRange = complete;
        snapshot.end = value;
        ended = true;
        return true;
    }
private:
    std::string_view project_, sample_;
    bool planned_ = false;
    std::uint64_t next_ = 0;
};
} // namespace

ProjectResult ReadMemorySnapshot(const ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence, ArchivedMemorySnapshot& out)
{
    out = {};
    if (!project.Info()) return Failure(ProjectError::NotOpen, "project");
    Decoder decoder(project.Info()->projectId, sampleId);
    bool valid = true;
    const auto visitor = [&](const auto&, const auto&, const auto& records) {
        for (const auto& record : records) if (!decoder.Record(record)) { valid = false; return false; }
        return true;
    };
    archive::RawEvidenceScanResult checked;
    const ProjectRawEvidenceRead read{project.Info()->projectId, sampleId, ordinal, std::nullopt, previousSequence,
        visitor, 32 * 1024 * 1024, ProjectEvidenceLane::MemorySnapshots};
    const auto status = project.ReadRawEvidenceSegment(read, checked, &decoder.snapshot.sha256);
    if (!status) return status;
    if (!valid || !decoder.ended || !checked.checked || !checked.VerifiedBoundary(*checked.checked) || !IsHash(decoder.snapshot.sha256))
        return Failure(ProjectError::Corrupt, "memorySnapshotSemanticOrBoundary");
    decoder.snapshot.boundary = *checked.checked;
    out = std::move(decoder.snapshot);
    return {};
}

ProjectResult SelectMemorySnapshotBytes(const ArchivedMemorySnapshot& snapshot, memory::Range range, std::string& out)
{
    out.clear();
    if (!range.length || range.base < snapshot.range.base || range.base > UINT64_MAX - range.length ||
        range.base + range.length > snapshot.range.base + snapshot.range.length)
        return Failure(ProjectError::InvalidArgument, "memoryExportRange");
    std::string bytes;
    auto next = range.base;
    const auto end = range.base + range.length;
    for (const auto& page : snapshot.pages) {
        const auto pageEnd = page.range.base + page.range.length;
        if (pageEnd <= next || page.range.base >= end) continue;
        if (page.range.base > next || page.bytes.size() != page.range.length)
            return Failure(ProjectError::RecoveryRequired, "memoryExportGap");
        const auto count = (std::min)(pageEnd, end) - next;
        bytes.append(page.bytes, static_cast<std::size_t>(next - page.range.base), static_cast<std::size_t>(count));
        next += count;
        if (next == end) { out = std::move(bytes); return {}; }
    }
    return Failure(ProjectError::RecoveryRequired, "memoryExportUnvisitedRange");
}
} // namespace Ksword::ActionAnalyze
