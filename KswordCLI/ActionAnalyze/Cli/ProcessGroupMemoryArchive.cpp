#include "ProcessGroupMemoryArchive.h"

#include "../Project/MemorySnapshotReader.h"
#include "../Project/ProjectStorage.h"

#include <utility>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
using V = JsonValue;
constexpr std::uint64_t kMemorySegmentLimit = 4096; // 与独立内存快照命令保持同一段数上限。

// 会话响应的字符串工厂，避免把文件诊断拼成可执行 JSON。
V Text(std::string_view value)
{
    return V::makeString(std::string(value));
}

// 地址和归档端点始终以十进制字符串无损输出。
V Count(std::uint64_t value)
{
    return Text(std::to_string(value));
}

// 项目错误与原生错误分开保留，不能把保存失败表现成空结果成功。
V Issue(const project::ProjectResult& issue)
{
    return V::makeObject({{"id", Text(project::ProjectErrorName(issue.error))},
        {"stage", Text(issue.detail)}, {"win32Error", V::makeUInt(issue.nativeError)}});
}

// 只有底层真实回执提供的端点才输出，未写入与未刷盘保持为空。
V Boundary(const std::optional<archive::RawEvidenceBoundary>& boundary)
{
    if (!boundary) {
        return V::makeNull();
    }
    return V::makeObject({{"byteOffset", Count(boundary->byteOffset)},
        {"blockOrdinal", Count(boundary->blockOrdinal)}, {"lastSequence", Count(boundary->lastSequence)}});
}
} // namespace

project::ProjectResult ProcessGroupMemoryArchive::Bind(const std::wstring& path, std::string_view sampleId)
{
    if (path.empty()) {
        if (!sampleId.empty()) {
            return storage::Failure(project::ProjectError::InvalidArgument, "sample-requires-project");
        }
        return {};
    }
    if (!sampleId.empty() && !storage::IsUuid(sampleId)) {
        return storage::Failure(project::ProjectError::InvalidArgument, "canonical-sample-required");
    }
    if (const auto opened = project_.Open(path, project::ProjectAccess::ReadWrite); !opened) { // 项目原生单写租约。
        return opened;
    }
    if (sampleId.empty()) {
        const auto revision = project_.Info()->revisionId; // 新采样必须冻结启动前真实提交的配置修订。
        if (const auto created = project_.CreateSample("Process group memory investigation", sample_, revision); !created) {
            return created;
        }
    } else {
        project::SampleRecord record; // 指定采样的冻结配置与身份，不改写其原始修订。
        if (const auto read = project_.ReadSample(sampleId, record); !read) {
            return read;
        }
        sample_ = std::move(record.info);
    }
    // 既有坏尾只封锁归档通道，仍允许原控制会话查询和清退；错误在 hello 中明确呈现。
    if (const auto positioned = FindAppendPosition(); !positioned) {
        laneBlocked_ = true;
        laneFailure_ = positioned;
    }
    return {};
}

const std::string& ProcessGroupMemoryArchive::SampleId() const noexcept
{
    return sample_.sampleId;
}

project::ProjectResult ProcessGroupMemoryArchive::FindAppendPosition()
{
    // 每段沿同一已核验前序读取，遇到首个损坏段即停止，禁止越过坏尾另开段。
    for (nextOrdinal_ = 1; nextOrdinal_ <= kMemorySegmentLimit; ++nextOrdinal_) {
        project::ArchivedMemorySnapshot existing; // 本段原字节与语义校验后的独立读回。
        const auto read = project::ReadMemorySnapshot(project_, sample_.sampleId, nextOrdinal_, previousSequence_, existing); // 原通道读回。
        if (read.error == project::ProjectError::NotFound) {
            return {};
        }
        if (!read) {
            laneBlocked_ = true;
            laneFailure_ = read;
            return read;
        }
        previousSequence_ = existing.boundary.lastSequence;
    }
    return storage::Failure(project::ProjectError::LimitExceeded, "memorySnapshotCount");
}

V ProcessGroupMemoryArchive::Describe() const
{
    const auto* info = project_.Info(); // 租约固定的真实项目，不根据当前参数重新打开。
    return V::makeObject({{"bound", V::makeBool(info != nullptr)},
        {"projectId", info ? Text(info->projectId) : V::makeNull()},
        {"sampleId", info ? Text(sample_.sampleId) : V::makeNull()},
        {"revisionId", info ? Text(sample_.revisionId) : V::makeNull()},
        {"snapshotId", info ? Text(sample_.snapshotId) : V::makeNull()},
        {"stream", Text("raw-memory")}, {"laneBlocked", V::makeBool(laneBlocked_)},
        {"laneFailure", laneBlocked_ ? Issue(laneFailure_) : V::makeNull()},
        {"lastWrite", lastWrite_ ? V::makeObject({{"ordinal", Count(lastWrite_->ordinal)},
            {"verified", V::makeBool(lastWrite_->verified)}, {"written", Boundary(lastWrite_->raw.written)},
            {"flushed", Boundary(lastWrite_->raw.flushed)}}) : V::makeNull()},
        {"nextOrdinal", info ? Count(nextOrdinal_) : V::makeNull()},
        {"displayedCaptureId", displayed_ ? Text(displayed_->request.plan.trackingEpoch) : V::makeNull()},
        {"displayedCaptureSaved", V::makeBool(saved_.has_value())}});
}

void ProcessGroupMemoryArchive::Remember(control::ProcessMemorySnapshotResult capture)
{
    if (!capture.snapshot || !capture.snapshot->round) {
        return;
    }
    displayed_ = std::move(capture);
    saved_.reset();
}

V ProcessGroupMemoryArchive::Failure(project::ProjectResult issue) const
{
    return V::makeObject({{"saved", V::makeBool(false)}, {"error", Issue(issue)},
        {"archive", Describe()}});
}

V ProcessGroupMemoryArchive::Save(std::string_view captureId, std::string_view sampleId)
{
    if (!project_.Info()) {
        return Failure(storage::Failure(project::ProjectError::NotOpen, "memory-project-not-bound"));
    }
    if (sampleId != sample_.sampleId) {
        return Failure(storage::Failure(project::ProjectError::InvalidArgument, "memory-save-wrong-sample"));
    }
    if (!displayed_ || captureId != displayed_->request.plan.trackingEpoch) {
        return Failure(storage::Failure(project::ProjectError::StaleRevision, "memory-save-displayed-capture-required"));
    }
    if (displayed_->request.plan.sampleId != sample_.sampleId) {
        return Failure(storage::Failure(project::ProjectError::InvalidArgument, "memory-save-capture-sample-mismatch"));
    }
    if (saved_) {
        return *saved_;
    }
    if (laneBlocked_) {
        return Failure(laneFailure_);
    }
    if (nextOrdinal_ > kMemorySegmentLimit) {
        return Failure(storage::Failure(project::ProjectError::LimitExceeded, "memorySnapshotCount"));
    }

    project::ProjectMemorySnapshotReceipt receipt; // 写入端保存原字节、readContext 和刷盘／回读端点。
    // 副作用开始前先关闭续写资格，异常或不完整回执也不能绕过坏尾再次追加。
    laneBlocked_ = true;
    laneFailure_ = storage::Failure(project::ProjectError::RecoveryRequired, "memory-save-unconfirmed");
    const auto written = project::WriteProcessGroupMemorySnapshot(project_, sample_.sampleId, nextOrdinal_,
        previousSequence_, *displayed_, receipt); // 只消费当前已显示的冻结快照，不调用活读取器。
    lastWrite_ = receipt;
    if (!written) {
        laneFailure_ = written;
        return Failure(written);
    }
    project::ArchivedMemorySnapshot archived; // 使用规范读端返回最终保存信息及完整 readContext。
    const auto read = project::ReadMemorySnapshot(project_, sample_.sampleId, nextOrdinal_, previousSequence_, archived); // 同一段精确回查。
    if (!read) {
        laneFailure_ = read;
        return Failure(read);
    }
    if (!receipt.verified || !receipt.raw.flushed || archived.sha256 != receipt.sha256 ||
        archived.boundary.byteOffset != receipt.raw.flushed->byteOffset ||
        archived.boundary.lastSequence != receipt.raw.flushed->lastSequence) {
        laneFailure_ = storage::Failure(project::ProjectError::Corrupt, "memory-save-readback-mismatch");
        return Failure(laneFailure_);
    }

    const auto* context = archived.plan.find("readContext"); // 保留原 Live/Held、before/after 和持有核对，不按现在停点重写。
    const auto ordinal = nextOrdinal_; // 本次已落盘段号，在推进下一段前冻结回执。
    saved_ = V::makeObject({{"saved", V::makeBool(true)}, {"captureId", Text(captureId)},
        {"projectId", Text(project_.Info()->projectId)}, {"sampleId", Text(sample_.sampleId)},
        {"stream", Text("raw-memory")}, {"ordinal", Count(ordinal)},
        {"sha256", Text(archived.sha256)}, {"verified", V::makeBool(true)},
        {"capturedBytes", Count(archived.capturedBytes)}, {"unavailablePages", Count(archived.unavailablePages)},
        {"completeRange", V::makeBool(archived.completeRange)}, {"endOffset", Count(archived.boundary.byteOffset)},
        {"lastSequence", Count(archived.boundary.lastSequence)},
        {"readContext", context ? *context : V::makeNull()}, {"atomicProcessSnapshot", V::makeBool(false)}});
    // 成功回执也冻结完成后才恢复追加资格，避免分配异常留下可再次写入的半确认结果。
    previousSequence_ = archived.boundary.lastSequence;
    ++nextOrdinal_;
    laneBlocked_ = false;
    laneFailure_ = {};
    return *saved_;
}

} // namespace ks::cli::action_analyze
