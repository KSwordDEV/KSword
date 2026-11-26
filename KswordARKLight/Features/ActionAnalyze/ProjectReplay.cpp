#include "ProjectReplay.h"

#include "../../../KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <deque>
#include <filesystem>
#include <iterator>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {

namespace Project = Ksword::ActionAnalyze;
namespace Storage = Project::ProjectStorage;
namespace Archive = ks::cli::action_analyze::archive;
constexpr wchar_t kManifestName[] = L"project.ksaproj"; // 正式项目清单的固定名称。
constexpr std::uint64_t kSelectionRawBytes = 16ULL * 1024 * 1024;

// 将共享项目错误保留给桌面状态区，兼顾项目错误类型和具体失败步骤。
std::string ReplayDiagnostic(const Project::ProjectResult& result) {
    return std::string(Project::ProjectErrorName(result.error)) + "/" + result.detail;
}

// 校验并固定用户选择的本地项目根。只读打开期间保留其父目录身份。
Project::ProjectResult PinProjectRoot(const std::wstring& path, Storage::Directory& root) {
    const std::filesystem::path manifest(path); // 保留原始 UTF-16 路径。
    if (!manifest.is_absolute() || !IsProjectReplayManifest(path)) {
        return Storage::Failure(Project::ProjectError::InvalidArgument, "replayManifest");
    }
    return Storage::OpenRoot(manifest.parent_path().wstring(), false, false, root);
}

// 返回无法发布的新请求回执，控件层继续保留上次提交的数据和详情。
ProjectReplayEvidence ReplayFailure(const Project::ProjectResult& result) {
    ProjectReplayEvidence evidence; // 失败时没有段身份或预览行。
    evidence.raw.diagnostic = ReplayDiagnostic(result);
    evidence.raw.systemError = result.nativeError;
    return evidence;
}

// 只有专用读取器在同一只读句柄核验首尾和原包成功后，才投影这批单源线索。
ProjectReplayEvidence ReadCallbackProjectReplay(const Project::ProjectDocument& project, const ProjectReplayRequest& request) {
    Project::ProjectCallbackEvidenceReceipt receipt;
    if (const auto status = Project::ReadInitialCallbackEvidence(project, request.sampleId, receipt); !status) {
        return ReplayFailure(status);
    }

    ProjectReplayEvidence result;
    auto& raw = result.raw;
    raw.identity = SegmentIdentity{std::move(receipt.projectId), std::move(receipt.sampleId),
        static_cast<std::uint32_t>(Archive::StreamKind::Raw), receipt.segmentOrdinal};
    raw.fileBytes = raw.framedBytes = raw.decodedPrefixBytes = receipt.boundary.byteOffset;
    raw.lastBlockOrdinal = receipt.boundary.blockOrdinal;
    raw.lastSequence = receipt.boundary.lastSequence;
    raw.blocks = 1; // 专用格式仅允许一个完整块。
    raw.records = receipt.records.size() + 2; // 计划和尾记是帧记录，不是结果行。
    raw.rows.reserve(receipt.records.size());
    const auto hint = [](std::uint32_t id) { return id ? std::to_wstring(id) : L"未知"; };
    for (const auto& source : receipt.records) {
        const auto& event = source.event;
        auto& row = raw.rows.emplace_back();
        row.sequence = source.rawSequence;
        row.offset = source.rawOffset;
        row.blockOrdinal = receipt.boundary.blockOrdinal;
        row.segmentOrdinal = receipt.segmentOrdinal;
        row.type = 3; // 专用读取器只接受 Stored RawRecord v1。
        row.schemaVersion = 1;
        row.payloadBytes = static_cast<std::uint32_t>(source.inlineOffset - source.rawOffset -
            Archive::kRecordHeaderBytes + sizeof(event));
        row.callback = CallbackReplayObservation{event.sequence, source.inlineOffset, static_cast<std::uint32_t>(sizeof(event)),
            event.originatingProcessId, event.originatingThreadId, event.targetProcessId, event.targetThreadId, event.timeUtc100ns};
        row.preview = L"回调上下文 PID/TID 提示：" + hint(row.callback->contextPid) + L" / " + hint(row.callback->contextTid) +
            L"\r\n目标 PID/TID 提示：" + hint(row.callback->targetPid) + L" / " + hint(row.callback->targetTid) +
            L"\r\n来源时间（FILETIME）：" + (event.timeUtc100ns > 0 ? std::to_wstring(event.timeUtc100ns) : L"未知") +
            L"\r\n内联原包字节偏移：" + std::to_wstring(row.callback->inlineOffset) +
            L"    原包长度：" + std::to_wstring(row.callback->inlineBytes) + L" B";
    }
    result.callback = CallbackReplayBatch{std::move(receipt.plan), receipt.end, std::move(receipt.prefixSha256)};
    return result;
}

void AppendRecentRows(std::deque<EvidenceRecord>& recent, std::vector<EvidenceRecord>& segmentRows) {
    for (auto& row : segmentRows) {
        if (recent.size() == kEvidenceRows) recent.pop_front();
        recent.push_back(std::move(row));
    }
}

ProjectReplayEvidence ApiCheckpointUnavailable(bool legacy) {
    ProjectReplayEvidence result;
    result.checkpoint.kind = ReplayCheckpointKind::PassiveApi;
    result.checkpoint.state = legacy ? CheckpointState::NotPublished : CheckpointState::Pending;
    if (!legacy) result.checkpoint.pendingOrdinal = 1;
    result.raw.diagnostic = legacy ? "apiCheckpointLegacyUnpublished" : "checkpointPending";
    return result;
}

// 同一只读句柄内核验整个提交段，仅在校验成功后发布回调暂存的记录。
ProjectReplayEvidence ReadApiProjectReplay(const Project::ProjectDocument& project, const ProjectReplayRequest& request,
    ProjectReplayMode mode, std::optional<bool>& mixedEtw) {
    ProjectReplayEvidence result;
    result.checkpoint.kind = ReplayCheckpointKind::PassiveApi;
    std::deque<EvidenceRecord> recent;
    Project::ProjectApiCheckpoint committed;
    Ksword::Evidence::ApiTransferCandidateWindow<EvidenceRecord> transfers(
        {request.projectId, request.sampleId, {}, {}}); // 全前缀共享有界链状态，独立于事件表窗口。
    std::string sourceEpoch; // 经首段计划核验的来源代次。

    for (std::uint64_t ordinal = 1; ordinal != 0; ++ordinal) {
        SegmentEvidence staged; // 本段核验失败时随迭代丢弃，保留已发布前缀。
        auto stagedTransfers = transfers; // 本段未通过散列及检查点前不发布链路。
        auto stagedEpoch = sourceEpoch; // 来源声明同样随整段事务提交。
        const auto status = Project::ReadApiCheckpoint(project, request.sampleId, ordinal,
            committed.ordinal ? &committed : nullptr, committed,
            [&](const Archive::SegmentIdentity& identity, const Archive::BlockInfo& block,
                 const std::vector<Archive::DecodedRecord>& records) {
                if (stagedEpoch.empty()) {
                    if (records.empty()) return false;
                    const auto& planRaw = std::get<Archive::RawRecordV1>(records.front().body); // 已由共享读取器验证计划。
                    const auto plan = Ksword::Evidence::ParseJson(planRaw.metadataJson);
                    if (!plan.ok() || !Storage::GetUuid(plan.value, "sourceEpoch", stagedEpoch)) return false;
                }
                ++staged.blocks;
                staged.records += records.size();
                for (const auto& record : records) {
                    const auto* raw = std::get_if<Archive::RawRecordV1>(&record.body);
                    if (!raw) return false;
                    auto row = PreviewCommittedApiRecord(block, record, *raw, identity.ordinal);
                    if (const auto clue = Project::ReadCommittedApiClue(*raw)) {
                        stagedTransfers.Accept(*clue, row, identity.ordinal, record.recordSequence, stagedEpoch);
                    }
                    if (!row.apiClue.empty()) ++staged.apiClues;
                    staged.rows.push_back(std::move(row));
                }
                return true;
            });

        if (!status) {
            result.checkpoint.state = status.error == Project::ProjectError::NotFound ? CheckpointState::Pending : CheckpointState::Partial;
            result.checkpoint.pendingOrdinal = ordinal;
            result.raw.diagnostic = ReplayDiagnostic(status);
            result.raw.systemError = status.nativeError;
            break;
        }

        mixedEtw = committed.mixedEtw; // 仅接受已核验的冻结计划声明。
        transfers = std::move(stagedTransfers);
        transfers.CommitSegment(ordinal, committed.rawSha256); // 检查点与整段核验成功后提交。
        sourceEpoch = std::move(stagedEpoch);
        // 快照身份锚定采样，记录仍保留各自段号。线索总数覆盖所有已验证段。
        staged.identity = SegmentIdentity{request.projectId, request.sampleId, static_cast<std::uint32_t>(Archive::StreamKind::Raw), 1};
        staged.fileBytes = committed.rawFileBytes;
        staged.framedBytes = staged.decodedPrefixBytes = committed.rawEnd.byteOffset;
        staged.lastBlockOrdinal = committed.rawEnd.blockOrdinal;
        staged.lastSequence = committed.rawEnd.lastSequence;
        staged.apiClues += result.raw.apiClues;
        for (auto& row : staged.rows) {
            ApplyCommittedApiClueSource(row, committed.source);
        }
        AppendRecentRows(recent, staged.rows);
        result.raw = std::move(staged);
        result.checkpoint.lastVerifiedOrdinal = ordinal;
        result.checkpoint.rawEnd = committed.rawEnd.byteOffset;
        result.checkpoint.apiArchiveSource = committed.source;
        result.checkpoint.recordedRuleSourceSha256 = committed.ruleSourceSha256;
        result.apiSourcePackets = committed.lastSourceSequence;

        if (committed.finalSegment) {
            if (!committed.startup.isNull())
            {
                // 原回放worker在终段验证后冻结快照，不回查当前PID或调用Agent。
                result.checkpoint.apiStartupJson = Ksword::Evidence::WriteJson(committed.startup);
            }
            result.checkpoint.state = CheckpointState::Verified;
            break;
        }
        if (mode == ProjectReplayMode::SelectionPreview) {
            result.checkpoint.state = CheckpointState::PreviewLimited;
            break;
        }
    }

    result.raw.rows.assign(std::make_move_iterator(recent.begin()), std::make_move_iterator(recent.end()));
    result.raw.transferCandidates.assign(transfers.Candidates().begin(), transfers.Candidates().end());
    result.raw.transferCandidateCount = transfers.CandidateCount();
    result.raw.apcTransferCandidates.assign(transfers.ApcCandidates().begin(), transfers.ApcCandidates().end());
    result.raw.apcTransferCandidateCount = transfers.ApcCandidateCount();
    result.raw.contextTransferCandidates.assign(transfers.ContextCandidates().begin(), transfers.ContextCandidates().end());
    result.raw.contextTransferCandidateCount = transfers.ContextCandidateCount();
    result.raw.sectionMapRequests.assign(transfers.Maps().begin(), transfers.Maps().end());
    result.raw.evictedSectionMaps = transfers.EvictedMaps();
    for (auto& mapping : result.raw.sectionMapRequests) // 同一已核验前缀中的映射来源声明。
    {
        if (result.checkpoint.apiArchiveSource)
        {
            ApplyCommittedApiClueSource(mapping.row, *result.checkpoint.apiArchiveSource);
        }
    }
    for (auto& candidate : result.raw.contextTransferCandidates) // candidate 只属于已核验提交前缀。
    {
        if (result.checkpoint.apiArchiveSource)
        {
            ApplyCommittedApiClueSource(candidate.write, *result.checkpoint.apiArchiveSource);
            ApplyCommittedApiClueSource(candidate.context, *result.checkpoint.apiArchiveSource);
        }
    }
    result.raw.evictedTransferWrites = transfers.EvictedWrites();
    for (auto& candidate : result.raw.apcTransferCandidates) // 只给已提交前缀中的 APC 双方附来源。
    {
        if (result.checkpoint.apiArchiveSource)
        {
            ApplyCommittedApiClueSource(candidate.write, *result.checkpoint.apiArchiveSource);
            ApplyCommittedApiClueSource(candidate.queue, *result.checkpoint.apiArchiveSource);
        }
    }
    for (auto& candidate : result.raw.transferCandidates) {
        if (result.checkpoint.apiArchiveSource) {
            ApplyCommittedApiClueSource(candidate.write, *result.checkpoint.apiArchiveSource);
            ApplyCommittedApiClueSource(candidate.threadCreate, *result.checkpoint.apiArchiveSource);
        }
    }
    const auto native = Ksword::Evidence::ReadNativeExecutionHistory(project, request.sampleId); // 原项目后台读任务。
    result.raw.nativeExecution = Ksword::Evidence::ProjectApiNativeExecution<EvidenceRecord>(
        {request.projectId, request.sampleId, {}, {}}, native, result.raw.transferCandidates,
        result.raw.apcTransferCandidates, result.raw.contextTransferCandidates,
        result.raw.sectionMapRequests, result.raw.evictedSectionMaps);
    return result;
}

// 通过固定目录句柄读取指定段。已发布段从同一文件句柄复核散列、身份和端点。
SegmentEvidence ReadRawSegment(const Storage::Directory& directory, const ProjectReplayRequest& request,
    std::uint64_t ordinal, const Project::ProjectEtwCheckpoint* checkpoint, ProjectReplayMode mode) {
    const auto digits = std::to_wstring(ordinal); // 规范段文件名的十进制编号。
    const auto name = std::wstring(20 - digits.size(), L'0') + digits + L".ksaseg"; // 项目内固定文件名。
    Storage::Handle file; // 禁止其它句柄在本次读回期间写入或删除文件。
    if (const auto status = Storage::OpenFile(directory, name, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, file); !status) {
        return ReplayFailure(status).raw;
    }
    const SegmentIdentity expected{request.projectId, request.sampleId, 1, ordinal}; // 正确的 raw 段头身份。
    if (!checkpoint) {
        if (mode == ProjectReplayMode::SelectionPreview) {
            LARGE_INTEGER size{};
            if (!::GetFileSizeEx(file.get(), &size)) {
                return ReplayFailure(Storage::WinFailure("replayRawSize", ::GetLastError())).raw;
            }
            if (static_cast<std::uint64_t>(size.QuadPart) > kSelectionRawBytes) {
                SegmentEvidence limited;
                limited.diagnostic = "replaySelectionLimit";
                return limited;
            }
        }
        auto result = ReadOpenStoredEvidence(file.get(), std::nullopt, &expected, StoredReadMode::LegacyProject);
        std::string hash; // 与实际原包读取共用句柄，完整导入通过后才填写映射摘要。
        if (result.diagnostic.empty() && Storage::HashArchivePrefix(file.get(), result.decodedPrefixBytes, hash))
        {
            for (auto& mapping : result.sectionMapRequests)
            {
                mapping.sha256 = hash;
            }
        }
        return result;
    }

    const auto& end = checkpoint->raw.end; // 检查点限定的完整块水位。
    std::string hash; // 从实际用于投影的文件读回的已提交前缀摘要。
    if (const auto status = Storage::HashArchivePrefix(file.get(), end.byteOffset, hash); !status) {
        return ReplayFailure(status).raw;
    }
    if (hash != checkpoint->raw.sha256) {
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayRawHash")).raw;
    }
    auto segment = ReadOpenStoredEvidence(file.get(), end.byteOffset, &expected, StoredReadMode::KeepLatest);
    if (segment.diagnostic.empty() && (segment.decodedPrefixBytes != end.byteOffset ||
        segment.lastBlockOrdinal != end.blockOrdinal || segment.lastSequence != end.lastSequence)) {
        segment.diagnostic = "replayRawProjection";
    }
    return segment;
}

// 首标记缺失时识别专用段或旧档；持续计划等待首次发布。
ProjectReplayEvidence ReadBeforeFirstCheckpoint(const Project::ProjectDocument& project,
    const Storage::Directory& directory, const ProjectReplayRequest& request, ProjectReplayMode mode) {
    ProjectReplayEvidence result; // 在项目回退与等待中只提交允许展示的内容。
    result.raw = ReadRawSegment(directory, request, 1, nullptr, mode);
    if (result.raw.diagnostic == kCallbackProjectRequired) return ReadCallbackProjectReplay(project, request);
    if (result.raw.diagnostic == kUnsupportedRawSource) return result;
    if (result.raw.identity && result.raw.blocks == 0 && result.raw.diagnostic.empty()) {
        // 裸段头不能证明已登记采样成功产出空批次；独立段诊断入口仍可显示段头。
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayRawHeaderOnly"));
    }
    if (result.raw.apiFollowRequiresCheckpoint.has_value()) {
        // 探测可能失败或看不到稍后出现的首段；回退句柄遇到跟随计划时不扫描剩余记录。
        return ApiCheckpointUnavailable(!*result.raw.apiFollowRequiresCheckpoint);
    }
    if (result.raw.continuousEtwPlan) {
        result.raw = {};
        result.raw.diagnostic = "checkpointPending";
        result.checkpoint.state = CheckpointState::Pending;
        result.checkpoint.pendingOrdinal = 1;
    } else {
        result.checkpoint.state = CheckpointState::NotPublished;
    }
    if (result.raw.diagnostic.empty() && !result.raw.continuousEtwPlan && !result.callback)
    {
        const auto native = Ksword::Evidence::ReadNativeExecutionHistory(project, request.sampleId); // 同一项目后台任务。
        result.raw.nativeExecution = Ksword::Evidence::ProjectApiNativeExecution<EvidenceRecord>(
            {request.projectId, request.sampleId, {}, {}}, native, result.raw.transferCandidates,
            result.raw.apcTransferCandidates, result.raw.contextTransferCandidates,
            result.raw.sectionMapRequests, result.raw.evictedSectionMaps);
    }
    return result;
}

ProjectReplayEvidence ReadEtwProjectReplay(const Project::ProjectDocument& project, const Storage::Directory& root,
    const ProjectReplayRequest& request, ProjectReplayMode mode, Project::ProjectEvidenceLane lane) {
    const bool mixed = lane == Project::ProjectEvidenceLane::MixedEtw;
    const auto sampleName = Storage::WideAscii(request.sampleId);
    Storage::Directory rawDirectory;
    const auto openRaw = [&] { return Storage::OpenDirectory(root,
        {L"samples", sampleName, mixed ? L"raw-etw" : L"raw"}, rawDirectory); };
    ProjectReplayEvidence result;
    if (mixed) result.checkpoint.kind = ReplayCheckpointKind::Etw;
    std::deque<EvidenceRecord> rows;
    std::uint64_t lastSequence = 0; // 仅在当前流中检查连续性，不与 API 序号做比较。
    for (std::uint64_t ordinal = 1; ordinal != 0; ++ordinal) {
        Project::ProjectEtwCheckpoint checkpoint;
        auto status = project.ReadEtwCheckpoint(request.sampleId, checkpoint, ordinal, lane);
        const bool missingMarker = status.error == Project::ProjectError::NotFound;
        if (missingMarker && ordinal == 1 && !mixed) {
            if (const auto opened = openRaw(); !opened) return ReplayFailure(opened);
            return ReadBeforeFirstCheckpoint(project, rawDirectory, request, mode);
        }
        if (status && (lastSequence == UINT64_MAX || checkpoint.planRawSequence != lastSequence + 1)) {
            status = Storage::Failure(Project::ProjectError::Corrupt, "replayRawSequence");
        }
        if (status && ordinal == 1) status = openRaw();
        auto segment = status ? ReadRawSegment(rawDirectory, request, ordinal, &checkpoint, mode) : ReplayFailure(status).raw;
        if (!segment.diagnostic.empty()) {
            result.checkpoint.state = missingMarker ? CheckpointState::Pending : CheckpointState::Partial;
            result.checkpoint.pendingOrdinal = ordinal;
            result.raw.diagnostic = std::move(segment.diagnostic);
            result.raw.systemError = segment.systemError;
            result.raw.failureOffset = segment.failureOffset;
            break;
        }

        if (mixed) {
            for (auto& row : segment.rows) row.mixedEtwLane = true;
        }
        AppendRecentRows(rows, segment.rows);
        lastSequence = checkpoint.raw.end.lastSequence;
        result.raw = std::move(segment);
        result.checkpoint.lastVerifiedOrdinal = ordinal;
        result.checkpoint.recordsEnd = checkpoint.records.end.byteOffset;
        result.checkpoint.kind = ReplayCheckpointKind::Etw;
        result.checkpoint.rawEnd = checkpoint.raw.end.byteOffset;
        if (checkpoint.finalSegment) {
            result.checkpoint.state = CheckpointState::Verified;
            break;
        }
        if (mode == ProjectReplayMode::SelectionPreview) {
            result.checkpoint.state = CheckpointState::PreviewLimited;
            break;
        }
    }
    if (result.raw.identity) {
        result.raw.identity->ordinal = 1; // 逻辑结果锚定整次采样，行内保留实际段号。
        result.raw.rows.assign(std::make_move_iterator(rows.begin()), std::make_move_iterator(rows.end()));
    }
    return result;
}

} // namespace

std::wstring CallbackReplayDetails(const CallbackReplayBatch& batch) {
    const auto ascii = [](std::string_view text) { return std::wstring(text.begin(), text.end()); };
    const auto count = [](std::optional<std::uint64_t> value) { return value ? std::to_wstring(*value) : L"未知"; };
    const auto& end = batch.end;
    using Project::CallbackBatchState;
    const wchar_t* state = L"未知";
    switch (end.state) {
    case CallbackBatchState::CaughtUp: state = L"已到本次快照上界"; break;
    case CallbackBatchState::MoreAvailable: state = L"还有后续记录"; break;
    case CallbackBatchState::SnapshotRace: state = L"快照竞态"; break;
    case CallbackBatchState::NotRead: break;
    }
    return L"来源（归档声明）：" + ascii(Project::kProjectCallbackSourceId) +
        L"    来源代次：" + ascii(batch.plan.sourceEpoch) +
        L"\r\n来源游标（请求后 / 下次 / 快照上界）：" + std::to_wstring(batch.plan.afterSequence) + L" / " +
        std::to_wstring(end.nextSequence) + L" / " + std::to_wstring(end.latestSequence) + L" · " + state +
        L"\r\n原生返回 / 请求上限：" + std::to_wstring(end.returnedCount) + L" / " + std::to_wstring(batch.plan.maxRecords) +
        L"    环覆盖丢失：" + count(end.lostBeforeFirst) + L"    环累计丢弃：" + count(end.droppedCount) +
        L"\r\n采集覆盖：未知。PID/TID 仅是提示；进程、线程实例以及写入、执行和跨进程归因均未核验。" +
        L"\r\nraw 段 SHA-256：" + ascii(batch.prefixSha256) + L"\r\n";
}

std::wstring ReplayDiagnosticText(const SegmentEvidence& evidence) {
    if (evidence.diagnostic == kCallbackProjectOnly) return L"请打开此回调归档所属的工程并选择对应采样";
    auto text = std::wstring(evidence.diagnostic.begin(), evidence.diagnostic.end()) + L" @ " +
        std::to_wstring(evidence.failureOffset) + L" B";
    if (evidence.systemError) text += L" (Win32 " + std::to_wstring(evidence.systemError) + L")";
    return text;
}

static std::wstring RawCheckpointExtent(const ReplayCheckpoint& checkpoint) {
    return L"raw/" + std::to_wstring(checkpoint.lastVerifiedOrdinal) + L" " + std::to_wstring(checkpoint.rawEnd) + L" B";
}

// 只有核验后的合作计划能够替换既有的被动 API 回放名称。
static const wchar_t* ApiCheckpointName(const ReplayCheckpoint& checkpoint) {
    return checkpoint.apiArchiveSource == Ksword::Evidence::ApiMonitorArchiveSource::CooperativePipe ? L"合作 API" : L"被动 API";
}

std::wstring DescribeReplayCheckpoint(const ReplayCheckpoint& checkpoint, const SegmentEvidence& evidence) {
    const bool api = checkpoint.kind == ReplayCheckpointKind::PassiveApi;
    if (checkpoint.state == CheckpointState::Verified) {
        auto status = api ? std::wstring(ApiCheckpointName(checkpoint)) + L" 终态检查点已验证 · " + RawCheckpointExtent(checkpoint) :
            L"终态检查点已验证 · records/" + std::to_wstring(checkpoint.lastVerifiedOrdinal) +
            L" " + std::to_wstring(checkpoint.recordsEnd) + L" B";
        if (evidence.fileBytes > evidence.decodedPrefixBytes) status += L" · raw 尾部未纳入";
        return status;
    }
    if (checkpoint.state == CheckpointState::Pending || checkpoint.state == CheckpointState::Partial) {
        auto status = L"已核验至第 " + std::to_wstring(checkpoint.lastVerifiedOrdinal) + L" 段 · 第 " +
            std::to_wstring(checkpoint.pendingOrdinal) +
            (checkpoint.state == CheckpointState::Pending ? L" 段检查点尚未发布" : L" 段核验失败 · " + ReplayDiagnosticText(evidence));
        if (api) status += std::wstring(L" · ") + ApiCheckpointName(checkpoint) + L" " + RawCheckpointExtent(checkpoint);
        return status;
    }
    return {};
}

std::wstring DescribeReplayPreview(const ReplayCheckpoint& checkpoint, const SegmentEvidence& evidence) {
    std::wstring text;
    if (checkpoint.state == CheckpointState::PreviewLimited) {
        text = L" · 已核验首段，点击回放可读取后续段";
    } else if (checkpoint.state == CheckpointState::NotPublished) {
        text = evidence.apiClues ? L" · API 导入尾记已核验" : L" · 仅查看 raw 段，未发布终态检查点";
    } else if (checkpoint.state == CheckpointState::Verified) {
        text = L" · 首段终态检查点已核验";
    }
    if (checkpoint.kind == ReplayCheckpointKind::PassiveApi) {
        text += std::wstring(L" · ") + ApiCheckpointName(checkpoint) + L" " + RawCheckpointExtent(checkpoint);
    }
    if (!evidence.diagnostic.empty()) text += L" · 部分可读 · " + ReplayDiagnosticText(evidence);
    return text;
}

std::wstring DescribeMixedReplay(const ProjectReplayEvidence& evidence) {
    if (!evidence.mixedEtw) return {};
    const auto describe = [](const wchar_t* label, const wchar_t* path, const ReplayCheckpoint& checkpoint,
                             const SegmentEvidence& raw) {
        std::wstring text = label;
        if (checkpoint.lastVerifiedOrdinal) {
            text += std::wstring(L" · ") + path + L"/" + std::to_wstring(checkpoint.lastVerifiedOrdinal) + L" · " +
                std::to_wstring(checkpoint.rawEnd) + L" B";
        } else {
            text += L" · 无已核验段";
        }
        switch (checkpoint.state) {
        case CheckpointState::Verified: text += L" · 终态检查点已验证"; break;
        case CheckpointState::PreviewLimited: text += L" · 已核验首段"; break;
        case CheckpointState::Pending:
            text += L" · 第 " + std::to_wstring(checkpoint.pendingOrdinal) + L" 段检查点尚未发布"; break;
        case CheckpointState::Partial:
            text += L" · 第 " + std::to_wstring(checkpoint.pendingOrdinal) + L" 段核验失败 · " + ReplayDiagnosticText(raw); break;
        case CheckpointState::NotPublished: text += L" · 旧档未发布检查点"; break;
        default: break;
        }
        if (raw.fileBytes > raw.decodedPrefixBytes) text += L" · 未纳入未提交尾部";
        return text;
    };
    return describe(ApiCheckpointName(evidence.checkpoint), L"raw", evidence.checkpoint, evidence.raw) + L"\r\n" +
        describe(L"ETW", L"raw-etw", evidence.mixedEtw->checkpoint, evidence.mixedEtw->raw);
}

bool IsProjectReplayManifest(const std::wstring& path) {
    const auto name = std::filesystem::path(path).filename().wstring(); // 只比较最终分量。
    return CompareStringOrdinal(name.c_str(), -1, kManifestName, -1, TRUE) == CSTR_EQUAL;
}

ProjectReplayCatalog ReadProjectReplayCatalog(const std::wstring& manifestPath) {
    ProjectReplayCatalog catalog; // 只在全部页面通过项目校验后交付选择数据。
    catalog.manifestPath = manifestPath;
    Storage::Directory root; // 与后续文档打开同一已固定的项目根。
    Project::ProjectDocument project; // 后台线程独占的只读项目。
    auto status = PinProjectRoot(manifestPath, root); // 逐组件拒绝不安全路径。
    if (status) status = project.Open(manifestPath, Project::ProjectAccess::ReadOnly);
    if (status) {
        const auto& info = *project.Info(); // 此次目录所绑定的已提交项目代次。
        catalog.projectId = info.projectId;
        catalog.revisionId = info.revisionId;
        catalog.recoveredPrevious = info.recoveredPrevious;
        catalog.breakpointDefinitions = info.settings.breakpointDefinitions; // 与原目录共用已打开的项目快照，不在UI读文件。
        catalog.choices.reserve(static_cast<std::size_t>(info.sampleCount));
        while (catalog.choices.size() < info.sampleCount) {
            std::vector<Project::SampleInfo> page; // 共享目录支持的单页数据。
            status = project.ListSamples(catalog.choices.size(), Project::kProjectCatalogPageSize, page);
            if (!status) break;
            if (page.empty()) {
                status = Storage::Failure(Project::ProjectError::Corrupt, "replayCatalogCount");
                break;
            }
            for (auto& sample : page) {
                catalog.choices.push_back({std::move(sample.title), {manifestPath, info.projectId,
                    std::move(sample.sampleId), std::move(sample.descriptionHash)}});
            }
        }
    }

    // 目录任一页失败时丢弃草稿候选。旧结果仍由控件层持有。
    if (!status) {
        catalog.choices.clear();
        catalog.diagnostic = ReplayDiagnostic(status);
        catalog.systemError = status.nativeError;
    }
    return catalog;
}

ProjectReplayCatalog CreateProjectReplayCatalog(const std::wstring& directory) {
    ProjectReplayCatalog catalog;
    const std::filesystem::path root(directory);
    catalog.manifestPath = (root / kManifestName).wstring();
    Project::ProjectDocument project;
    const auto name = root.filename().u8string();
    const std::string title(reinterpret_cast<const char*>(name.data()), name.size());
    const auto status = root.is_absolute() ? project.Create(directory, {title, ""}) :
        Storage::Failure(Project::ProjectError::InvalidArgument, "replayProjectPath");
    if (status) {
        catalog.projectId = project.Info()->projectId;
        catalog.revisionId = project.Info()->revisionId;
    } else {
        catalog.diagnostic = ReplayDiagnostic(status);
        catalog.systemError = status.nativeError;
    }
    return catalog;
}

ProjectReplayEvidence ReadProjectReplay(const ProjectReplayRequest& request, ProjectReplayMode mode) {
    Storage::Directory root; // 固定清单所在的本地目录及祖先句柄。
    if (const auto status = PinProjectRoot(request.manifestPath, root); !status) return ReplayFailure(status);
    Project::ProjectDocument project; // 当前读取所绑定的已提交项目快照。
    if (const auto status = project.Open(request.manifestPath, Project::ProjectAccess::ReadOnly); !status) {
        return ReplayFailure(status);
    }
    if (request.projectId != project.Info()->projectId) {
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayProjectId"));
    }
    Project::SampleRecord sample; // 经过目录、描述散列及冻结配置校验的真实采样。
    if (const auto status = project.ReadSample(request.sampleId, sample); !status) return ReplayFailure(status);
    if (request.descriptionHash != sample.info.descriptionHash) {
        return ReplayFailure(Storage::Failure(Project::ProjectError::Corrupt, "replayDescriptionHash"));
    }

    Project::ApiFollowArchiveKind api = Project::ApiFollowArchiveKind::Other;
    const bool hasApi = Project::ProbeApiFollowArchive(project, sample.info.sampleId, api) &&
        api != Project::ApiFollowArchiveKind::Other;
    std::optional<bool> expectsMixed;
    ProjectReplayEvidence primary;
    if (hasApi) {
        primary = api == Project::ApiFollowArchiveKind::Legacy ? ApiCheckpointUnavailable(true) :
            ReadApiProjectReplay(project, request, mode, expectsMixed);
        if (expectsMixed == false) return primary;
    }

    // API 首段不可用时仍尝试独立核验混采 ETW。专用流从不降级为无检查点的旧档预览。
    auto etw = ReadEtwProjectReplay(project, root, request, mode, Project::ProjectEvidenceLane::MixedEtw);
    if (expectsMixed == true || etw.raw.identity) {
        if (!hasApi) {
            primary = ReadApiProjectReplay(project, request, mode, expectsMixed);
            if (expectsMixed == false) return primary;
        }
        primary.mixedEtw = MixedEtwReplay{std::move(etw.raw), etw.checkpoint};
        return primary;
    }
    if (hasApi) return primary;
    return ReadEtwProjectReplay(project, root, request, mode, Project::ProjectEvidenceLane::Primary);
}

} // namespace Ksword::Features::ActionAnalyze
