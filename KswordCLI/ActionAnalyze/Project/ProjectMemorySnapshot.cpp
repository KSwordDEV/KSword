#include "ProjectMemorySnapshot.h"

#include "ProjectStorage.h"
#include "../Control/ProcessGroupMemorySnapshot.h"

#include <bcrypt.h>

#include <limits>

namespace Ksword::ActionAnalyze {
namespace {
namespace memory = ks::cli::action_analyze::memory;
namespace archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
using V = Evidence::JsonValue;

// 所有地址、长度和 QPC 均以十进制字符串编码，不经 JSON 浮点数舍入。
V RangeJson(const memory::Range& range)
{
    return Object({{"base", Number(range.base)}, {"bytes", Number(range.length)}});
}

V MappingJson(const std::optional<memory::Mapping>& mapping)
{
    if (!mapping) return V::makeNull();
    return Object({{"region", RangeJson(mapping->region)}, {"allocationBase", Number(mapping->allocationBase)},
        {"state", V::makeUInt(mapping->state)}, {"type", V::makeUInt(mapping->type)},
        {"protection", V::makeUInt(mapping->protection)}, {"allocationProtection", V::makeUInt(mapping->allocationProtection)}});
}

V IssueJson(const memory::Issue& issue)
{
    // 原生错误和枚举阶段都留存；没有错误与未实际读取由页状态另外区分。
    return Object({{"stage", V::makeUInt(static_cast<std::uint32_t>(issue.stage))},
        {"win32Error", V::makeUInt(issue.win32Error)},
        {"ntStatus", issue.ntStatus ? V::makeInt(*issue.ntStatus) : V::makeNull()}});
}

const char* PageState(memory::PageStatus status)
{
    using enum memory::PageStatus;
    switch (status) {
    case NotCommitted: return "not-committed";
    case Guarded: return "guarded";
    case UnsafeReadAttributes: return "unsafe-read-attributes";
    case NotReadable: return "not-readable";
    case QueryFailed: return "query-failed";
    case ReadFailed: return "read-failed";
    case MappingUnstable: return "mapping-unstable";
    case HashFailed: return "hash-failed";
    case Sampled: return "sampled";
    }
    return "unknown";
}

std::string Digest(const memory::Sha256& hash)
{
    constexpr char digits[] = "0123456789abcdef"; // 采样器计算的原字节摘要，保持原始算法与字节序。
    std::string text;
    text.reserve(hash.size() * 2);
    for (const auto byte : hash) {
        text.push_back(digits[byte >> 4]);
        text.push_back(digits[byte & 15]);
    }
    return text;
}

V PageJson(const memory::PageObservation& page)
{
    return Object({{"kind", Text("selected-memory-page-v1")}, {"pageBase", Number(page.pageBase)},
        {"range", RangeJson(page.sampledRange)}, {"state", Text(PageState(page.status))},
        {"mappingBefore", MappingJson(page.before)}, {"mappingAfter", MappingJson(page.after)},
        {"issue", IssueJson(page.issue)}, {"additionalIssue", page.additionalIssue ? IssueJson(*page.additionalIssue) : V::makeNull()},
        {"readBeginQpc", page.readQpc ? Number(page.readQpc->begin) : V::makeNull()},
        {"readEndQpc", page.readQpc ? Number(page.readQpc->end) : V::makeNull()},
        {"returnedBytes", page.returnedBytes ? Number(*page.returnedBytes) : V::makeNull()},
        {"sha256", page.content ? Text(Digest(page.content->sha256)) : V::makeNull()}});
}

struct Row {
    std::string metadata; // 整段同步写入及回读期间保持稳定的元数据原文。
    std::string_view bytes; // 借用已冻结的快照字节，缺口记录为空。
};

// 归档前重算捕获页原字节摘要；调用者声明的 sha256 必须与实际字节一致。
class PageDigestVerifier final {
public:
    PageDigestVerifier()
    {
        open_ = BCryptOpenAlgorithmProvider(&provider_, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0;
    }
    ~PageDigestVerifier()
    {
        if (provider_) BCryptCloseAlgorithmProvider(provider_, 0);
    }
    PageDigestVerifier(const PageDigestVerifier&) = delete;
    PageDigestVerifier& operator=(const PageDigestVerifier&) = delete;

    bool Matches(std::string_view bytes, const memory::Sha256& expected) const
    {
        if (!open_ || bytes.size() > static_cast<std::size_t>((std::numeric_limits<ULONG>::max)())) return false;
        memory::Sha256 digest{};
        if (BCryptHash(provider_, nullptr, 0, const_cast<PUCHAR>(reinterpret_cast<const UCHAR*>(bytes.data())),
            static_cast<ULONG>(bytes.size()), digest.data(), static_cast<ULONG>(digest.size())) < 0) {
            return false;
        }
        return digest == expected;
    }

private:
    BCRYPT_ALG_HANDLE provider_ = nullptr;
    bool open_ = false;
};

ProjectResult PrepareRows(const ProjectDocument& project, const memory::SelectedMemorySnapshot& snapshot,
    std::vector<Row>& rows, ProjectMemorySnapshotReceipt& receipt, const V* readContext)
{
    const auto& plan = snapshot.plan; // 保存请求时身份，不能用写入时的当前选区替换。
    // 准入拒绝或读前取消没有页观察，不能刷成“已核验”的空内存段。
    // 实际访问但全部失败的页仍可归档诊断，不要求 captured 非空。
    if (!snapshot.round || snapshot.round->pages.empty()) {
        return Failure(ProjectError::InvalidArgument, "memorySnapshotNotObserved");
    }
    if (!plan.range.base || !plan.range.length || !plan.target.pid || !plan.target.creationFileTime100ns ||
        plan.range.length > (std::numeric_limits<std::uint64_t>::max)() - plan.range.base ||
        snapshot.captured.size() > memory::kMaxTrackedPages ||
        (snapshot.round && snapshot.round->pages.size() > memory::kMaxTrackedPages)) {
        return Failure(ProjectError::InvalidArgument, "memorySnapshotRange");
    }
    const auto identity = Object({{"machineId", Text(plan.target.machineId)}, {"bootId", Text(plan.target.bootId)},
        {"processInstanceId", Text(plan.target.processInstanceId)}, {"pid", V::makeUInt(plan.target.pid)},
        {"creationFileTime", Number(plan.target.creationFileTime100ns)}});
    Evidence::JsonObject fields{{"kind", Text("selected-memory-plan-v1")}, {"projectId", Text(project.Info()->projectId)},
        {"sampleId", Text(plan.sampleId)}, {"trackingEpoch", Text(plan.trackingEpoch)}, {"target", identity},
        {"range", RangeJson(plan.range)}, {"source", Text("read-only-memory-sample")},
        {"atomicProcessSnapshot", V::makeBool(false)}, {"allocationGenerationVerified", V::makeBool(false)},
        {"qpcFrequency", Number(snapshot.status.qpcFrequency)}};
    if (readContext) fields.emplace_back("readContext", *readContext);
    rows.push_back({Evidence::WriteJson(Object(std::move(fields))), {}});

    std::size_t capturedIndex = 0; // 原字节只与对应成功页配对，不能按列表首行推断后续页。
    std::uint64_t nextAddress = plan.range.base; // 严格要求已访问页是所选范围的连续前缀。
    const PageDigestVerifier digest; // 每个捕获页重算摘要，拒绝字节与采样声明不一致的快照。
    if (snapshot.round) {
        if (snapshot.round->effectivePlan.target != plan.target || snapshot.round->effectivePlan.sampleId != plan.sampleId ||
            snapshot.round->effectivePlan.trackingEpoch != plan.trackingEpoch || snapshot.round->effectivePlan.range != plan.range) {
            return Failure(ProjectError::InvalidArgument, "memorySnapshotIdentity");
        }
        for (const auto& page : snapshot.round->pages) {
            const auto& range = page.sampledRange;
            if (range.base != nextAddress || !range.length || range.length > plan.range.base + plan.range.length - nextAddress) {
                return Failure(ProjectError::InvalidArgument, "memorySnapshotPageOrder");
            }
            nextAddress += range.length;
            std::string_view bytes; // 不成功的页只保留错误及区域元数据，无伪造的补齐字节。
            if (page.status == memory::PageStatus::Sampled && page.content) {
                if (capturedIndex == snapshot.captured.size()) return Failure(ProjectError::InvalidArgument, "memorySnapshotMissingBytes");
                const auto& captured = snapshot.captured[capturedIndex++];
                const std::string_view candidate{reinterpret_cast<const char*>(captured.bytes.data()),
                    captured.bytes.size()};
                if (captured.observation.sampledRange != range || !captured.observation.content ||
                    captured.observation.content->sha256 != page.content->sha256 ||
                    captured.bytes.size() != range.length || !digest.Matches(candidate, page.content->sha256)) {
                    return Failure(ProjectError::InvalidArgument, "memorySnapshotBytesMismatch");
                }
                bytes = candidate;
                receipt.capturedBytes += bytes.size();
            } else {
                ++receipt.unavailablePages;
            }
            rows.push_back({Evidence::WriteJson(PageJson(page)), bytes});
        }
    }
    if (capturedIndex != snapshot.captured.size()) return Failure(ProjectError::InvalidArgument, "memorySnapshotExtraBytes");
    const bool complete = snapshot.round && snapshot.round->allPagesVisited && snapshot.round->endQpc &&
        nextAddress == plan.range.base + plan.range.length && receipt.unavailablePages == 0 &&
        receipt.capturedBytes == plan.range.length && snapshot.status.state == memory::State::Stopped;
    if (complete != snapshot.completeRange) return Failure(ProjectError::InvalidArgument, "memorySnapshotCompleteness");
    receipt.completeRange = complete;
    const auto end = Object({{"kind", Text("selected-memory-end-v1")}, {"completeRange", V::makeBool(complete)},
        {"capturedBytes", Number(receipt.capturedBytes)}, {"unavailablePages", Number(receipt.unavailablePages)},
        {"visitedPages", Number(snapshot.round ? snapshot.round->pages.size() : 0)},
        {"allPagesVisited", V::makeBool(snapshot.round && snapshot.round->allPagesVisited)},
        {"state", V::makeUInt(static_cast<std::uint32_t>(snapshot.status.state))}, {"issue", IssueJson(snapshot.status.issue)},
        {"beginQpc", snapshot.round ? Number(snapshot.round->beginQpc) : V::makeNull()},
        {"endQpc", snapshot.round && snapshot.round->endQpc ? Number(*snapshot.round->endQpc) : V::makeNull()}});
    rows.push_back({Evidence::WriteJson(end), {}});
    return {};
}
} // namespace

static ProjectResult WriteSnapshot(ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    const memory::SelectedMemorySnapshot& snapshot, ProjectMemorySnapshotReceipt& out, const V* readContext)
{
    out = {};
    out.ordinal = ordinal;
    const auto* info = project.Info(); // 写入的项目和采样来自已打开的真实目录。
    if (!info) return Failure(ProjectError::NotOpen, "project");
    if (sampleId != snapshot.plan.sampleId) return Failure(ProjectError::InvalidArgument, "memorySnapshotSample");
    std::vector<Row> rows; // 最多 64 个页记录及首尾，字节仍借用本次显式快照。
    if (const auto prepared = PrepareRows(project, snapshot, rows, out, readContext); !prepared) return prepared;
    const auto append = [&](archive::RawEvidenceArchive& writer) -> ProjectResult {
        for (const auto& row : rows) {
            const archive::RawEvidenceInput input{row.metadata, row.bytes}; // 一页一个完整块，失败不提交后续页。
            const auto receipt = writer.Append(std::span(&input, 1));
            if (receipt.result.status != archive::SegmentWriteStatus::Ok) {
                // 停止后续页，由 Finish 原样上报底层错误；重复段号保持真实 AlreadyExists 语义。
                return {};
            }
        }
        return {};
    };
    const ProjectRawEvidenceWrite write{info->projectId, sampleId, ordinal, previousSequence, append,
        ProjectEvidenceLane::MemorySnapshots};
    if (const auto written = project.WriteRawEvidenceSegment(write, out.raw); !written) return written;
    if (!out.raw.flushed) return Failure(ProjectError::IoError, "memorySnapshotFlush");

    std::size_t checkedRows = 0; // 同一读句柄回读原元数据与全部原字节，避免只检查文件存在。
    bool matches = true;
    const auto visitor = [&](const auto&, const auto&, const std::vector<archive::DecodedRecord>& records) {
        for (const auto& record : records) {
            const auto* body = std::get_if<archive::RawRecordV1>(&record.body);
            if (!body || checkedRows == rows.size() || body->metadataJson != rows[checkedRows].metadata ||
                body->inlineRawData != rows[checkedRows].bytes) {
                matches = false;
                return false;
            }
            ++checkedRows;
        }
        return true;
    };
    const ProjectRawEvidenceRead read{info->projectId, sampleId, ordinal, std::nullopt, previousSequence,
        visitor, std::nullopt, ProjectEvidenceLane::MemorySnapshots};
    archive::RawEvidenceScanResult checked;
    if (const auto readback = project.ReadRawEvidenceSegment(read, checked, &out.sha256); !readback) return readback;
    if (!matches || checkedRows != rows.size() || !checked.VerifiedBoundary(*out.raw.flushed) || !IsHash(out.sha256)) {
        return Failure(ProjectError::Corrupt, "memorySnapshotReadback");
    }
    out.verified = true;
    return {};
}

ProjectResult WriteSelectedMemorySnapshot(ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    const memory::SelectedMemorySnapshot& snapshot, ProjectMemorySnapshotReceipt& out)
{
    return WriteSnapshot(project, sampleId, ordinal, previousSequence, snapshot, out, nullptr);
}

ProjectResult WriteProcessGroupMemorySnapshot(ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    const ks::cli::action_analyze::control::ProcessMemorySnapshotResult& capture,
    ProjectMemorySnapshotReceipt& out)
{
    namespace native = ks::cli::action_analyze::control;
    out = {};
    out.ordinal = ordinal;
    const auto& plan = capture.request.plan;
    if (!capture.snapshot || plan.sampleId != sampleId || capture.snapshot->plan.sampleId != plan.sampleId ||
        capture.snapshot->plan.trackingEpoch != plan.trackingEpoch || capture.snapshot->plan.target != plan.target ||
        capture.snapshot->plan.range != plan.range || !capture.stage || !*capture.stage || !IsText(capture.stage, 256))
        return Failure(ProjectError::InvalidArgument, "memorySnapshotReadContext");
    const auto stopJson = [](const std::optional<native::ProcessGroupStop>& stop) -> V {
        if (!stop) return V::makeNull();
        return Object({{"pid", V::makeUInt(stop->target.pid)}, {"creationFileTime", Number(stop->target.creationFileTime)},
            {"groupId", Text(stop->groupId)}, {"stopId", Text(stop->stopId)},
            {"backendInstanceId", Text(stop->event.backendInstanceId)}, {"eventSerial", Number(stop->event.serial)},
            {"stateRevision", Number(stop->stateRevision)}});
    };
    const bool held = capture.request.source == native::ProcessMemorySource::HeldEvent;
    if (held) {
        const auto& before = capture.before;
        if (!capture.request.stop || !before || *before != *capture.request.stop ||
            !IsUuid(before->groupId) || !IsUuid(before->stopId) || !IsUuid(before->event.backendInstanceId) ||
            !before->event.serial || !before->stateRevision ||
            before->target.pid != plan.target.pid || before->target.creationFileTime != plan.target.creationFileTime100ns ||
            (capture.after && (capture.after->target != before->target || !IsUuid(capture.after->groupId) ||
                !IsUuid(capture.after->stopId) || !IsUuid(capture.after->event.backendInstanceId) ||
                !capture.after->event.serial || !capture.after->stateRevision)) ||
            (capture.heldAtBothChecks && (!capture.after || *capture.after != *before)))
            return Failure(ProjectError::InvalidArgument, "memorySnapshotHeldContext");
    } else if (capture.request.source != native::ProcessMemorySource::LiveRead || capture.request.stop ||
        capture.before || capture.after || capture.heldAtBothChecks) {
        return Failure(ProjectError::InvalidArgument, "memorySnapshotLiveContext");
    }
    const auto context = Object({{"source", Text(held ? "held-event" : "live-read")}, {"stage", Text(capture.stage)},
        {"win32Error", V::makeUInt(capture.win32Error)}, {"before", stopJson(capture.before)},
        {"after", stopJson(capture.after)}, {"heldAtBothChecks", V::makeBool(capture.heldAtBothChecks)}});
    return WriteSnapshot(project, sampleId, ordinal, previousSequence, *capture.snapshot, out, &context);
}

} // namespace Ksword::ActionAnalyze
