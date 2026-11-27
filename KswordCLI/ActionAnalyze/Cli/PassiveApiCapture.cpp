#include "PassiveApiCapture.h"

#include "../Project/ProjectStorage.h"
#include "../Rules/BehaviorPresets.h"

#include <algorithm>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
using namespace Ksword::ActionAnalyze;
using namespace Ksword::ActionAnalyze::ProjectStorage;
using Ksword::Evidence::PassiveApiTailState;
namespace Monitor = ks::winapi_monitor;
using Tail = Ksword::Evidence::PassiveApiArchiveTail;
using V = Ksword::Evidence::JsonValue;
using Clock = std::chrono::steady_clock;

constexpr std::size_t kQueueRows = 256; // 段内待写包总数。
constexpr std::size_t kBehaviorRows = 32; // 实时回执独立保留的最近行为释义数，不代表完整档案。
constexpr unsigned kFinalPolls = 4; // 收尾最多再读取四个有界批次。
constexpr auto kFinalBudget = std::chrono::milliseconds(250); // 每轮开始前检查的单调预算。
constexpr auto kPollInterval = std::chrono::milliseconds(50); // 限制前台请求触发的文件扫描频率。
constexpr auto kCommitInterval = std::chrono::seconds(1); // 非空批次的常规提交周期。
static_assert(kQueueRows >= Tail::kMaxPollRows);

// 将归档声明和文件观察转换为稳定的 CLI 状态名。
const char* TailState(PassiveApiTailState state)
{
    switch (state) {
    case PassiveApiTailState::Unopened: return "unopened";
    case PassiveApiTailState::Reading: return "reading";
    case PassiveApiTailState::AtTail: return "at-tail";
    case PassiveApiTailState::PartialLine: return "partial-line";
    case PassiveApiTailState::Sealed: return "sealed";
    case PassiveApiTailState::UnconfirmedEnd: return "unconfirmed-end";
    case PassiveApiTailState::TruncatedTail: return "truncated-tail";
    case PassiveApiTailState::WriterFailed: return "writer-failed";
    case PassiveApiTailState::ReceiptMismatch: return "receipt-mismatch";
    case PassiveApiTailState::SourceChanged: return "source-changed";
    case PassiveApiTailState::IdentityMismatch: return "identity-mismatch";
    case PassiveApiTailState::InvalidRecord: return "invalid-record";
    case PassiveApiTailState::ReadFailed: return "read-failed";
    case PassiveApiTailState::Cutoff: return "cutoff";
    }
    return "unknown";
}

// 从同一已授权句柄读取卷、文件和初始长度。路径不进入项目证据或查询结果。
ProjectResult Identify(HANDLE file, std::uint64_t& volume, std::string& id, std::uint64_t& initialBytes)
{
    FILE_ID_INFO identity{}; // 卷序列号和卷内文件标识。
    LARGE_INTEGER size{}; // 打开时实际可读的长度。
    if (!GetFileInformationByHandleEx(file, FileIdInfo, &identity, sizeof(identity)) || !GetFileSizeEx(file, &size)) {
        return WinFailure("apiArchiveIdentity", GetLastError());
    }
    constexpr char digits[] = "0123456789abcdef"; // 固定十六进制顺序保留文件 ID 字节。
    id.reserve(sizeof(identity.FileId.Identifier) * 2);
    for (const auto byte : identity.FileId.Identifier) {
        id.push_back(digits[byte >> 4]);
        id.push_back(digits[byte & 15]);
    }
    volume = identity.VolumeSerialNumber;
    initialBytes = static_cast<std::uint64_t>(size.QuadPart);
    return {};
}

// 返回行的原始包视图，将其用于序列化和实际回读比对。
std::string_view PacketBytes(const Ksword::Evidence::ArchivedApiMonitorClue& row)
{
    return {reinterpret_cast<const char*>(&row.packet), sizeof(row.packet)};
}

// 只从尾读器已验证的行取身份。创建时间来自原归档字段，不能用请求值或 PID 补填。
bool MatchesFrozenSource(const Ksword::Evidence::ArchivedApiMonitorClue& row,
    const Ksword::Evidence::PassiveApiSource& source) noexcept
{
    return row.readerCreation != 0 && row.readerCreation == source.readerCreation &&
        row.packet.pid == source.readerPid && row.packet.sessionIdentity == source.sessionIdentity;
}

// 识别生产方的安装声明。控制包的零返回码只用于确认声明类型。
bool IsHooksInstalledNotice(const Monitor::ApiMonitorEventPacket& packet) noexcept
{
    using Ksword::Evidence::ApiMonitorPacketText;
    return packet.eventKind == static_cast<std::uint32_t>(Monitor::EventKind::ApiCall) &&
        packet.category == static_cast<std::uint32_t>(Monitor::EventCategory::Internal) &&
        packet.resultKind == static_cast<std::uint32_t>(Monitor::EventResultKind::StatusCode) &&
        packet.resultCode == 0 && ApiMonitorPacketText(packet.moduleName) == L"Agent" &&
        ApiMonitorPacketText(packet.apiName) == L"HooksInstalled";
}

// 判断已验原包是否为普通 API 行。业务返回值不影响归档观察，异步阶段和覆盖包另有类型。
bool IsOrdinaryApiCall(const Monitor::ApiMonitorEventPacket& packet) noexcept
{
    using Ksword::Evidence::ApiMonitorPacketText;
    const auto module = ApiMonitorPacketText(packet.moduleName); // 仅接受非空且在包内终止的模块名。
    return packet.eventKind == static_cast<std::uint32_t>(Monitor::EventKind::ApiCall) &&
        packet.category != static_cast<std::uint32_t>(Monitor::EventCategory::Internal) &&
        !module.empty() && module != L"Agent" && !ApiMonitorPacketText(packet.apiName).empty();
}
} // namespace

using namespace Ksword::ActionAnalyze;
using namespace Ksword::ActionAnalyze::ProjectStorage;

ProjectResult PassiveApiCapture::Open(std::string_view path, Ksword::Evidence::PassiveApiSource source)
{
    if (!IsText(path, 4096)) {
        return Failure(ProjectError::InvalidArgument, "apiArchivePath");
    }
    const auto length = static_cast<int>(path.size()); // 已检查的 UTF-8 路径字节数。
    const auto wideLength = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), length, nullptr, 0); // UTF-16 长度。
    if (!wideLength) {
        return WinFailure("apiArchivePathEncoding", GetLastError());
    }
    std::wstring absolute(static_cast<std::size_t>(wideLength), L'\0'); // 调用方指定的驱动器绝对路径。
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path.data(), length, absolute.data(), wideLength)) {
        return WinFailure("apiArchivePathEncoding", GetLastError());
    }
    std::replace(absolute.begin(), absolute.end(), L'/', L'\\');
    const auto split = absolute.rfind(L'\\'); // 源目录和最后一个文件名组件的分界。
    if (absolute.size() < 4 || absolute[1] != L':' || absolute[2] != L'\\' || split <= 2) {
        return Failure(ProjectError::InvalidArgument, "apiArchiveAbsolutePath");
    }
    const auto fileName = std::wstring_view(absolute).substr(split + 1); // 仅接受明确指定的 JSONL 归档。
    constexpr std::wstring_view extension = L".jsonl";
    if (fileName.size() <= extension.size() ||
        CompareStringOrdinal(fileName.data() + fileName.size() - extension.size(), static_cast<int>(extension.size()),
            extension.data(), static_cast<int>(extension.size()), TRUE) != CSTR_EQUAL) {
        return Failure(ProjectError::InvalidArgument, "apiArchiveExtension");
    }

    // 复用本地盘和重解析点校验。保留目录句柄至读端取得自己的同源句柄。
    Directory directory;
    if (const auto result = OpenRoot(absolute.substr(0, split), false, false, directory); !result) {
        return result;
    }
    Handle file;
    if (const auto result = OpenFile(directory, fileName, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, file); !result) {
        return result;
    }
    auto reader = std::make_unique<Tail>(); // 未经资格核验的句柄在此函数内清退。
    if (const auto error = reader->Open(file.get(), source); error != ERROR_SUCCESS) {
        return WinFailure("apiArchiveOpen", error);
    }
    if (const auto result = Identify(file.get(), volumeSerial_, fileId_, initialBytes_); !result) {
        return result;
    }
    pending_.reserve(kQueueRows);
    status_ = reader->Status();
    reader_ = std::move(reader);
    return {};
}

ProjectResult PassiveApiCapture::BeginProject(ProjectDocument& project, const PassiveApiStartRequest& request,
    SampleInfo& sample, std::string& epoch, PassiveApiStartStage& failedStage)
{
    failedStage = PassiveApiStartStage::Project;
    const auto* info = project.Info(); // 只在登记新目录行前借用当前快照。
    if (!info || info->access != ProjectAccess::ReadWrite) {
        return Failure(info ? ProjectError::ReadOnly : ProjectError::NotOpen, "apiArchiveProject");
    }
    if (info->projectId != request.projectId || info->revisionId != request.revisionId) {
        return Failure(ProjectError::StaleRevision, "apiArchiveRevision");
    }

    failedStage = PassiveApiStartStage::Source;
    if (reader_ || ended_) {
        return Failure(ProjectError::AlreadyOpen, "apiArchiveAlreadyStarted");
    }
    if (const auto opened = Open(request.path, request.source); !opened) {
        return opened;
    }

    failedStage = PassiveApiStartStage::Session;
    std::string newEpoch; // 新会话仅在采样登记完成后发布给调用方。
    if (const auto created = NewId(newEpoch); !created) {
        return created;
    }
    const auto revisionHash = info->revisionHash; // 采样登记可能刷新项目快照。
    const auto semanticHash = info->configSemanticHash;

    failedStage = PassiveApiStartStage::Sample;
    SampleInfo frozen; // 新登记的真实采样与配置修订。
    if (const auto created = project.CreateSample(request.title, frozen, request.revisionId); !created) {
        return created;
    }

    ruleDatabase_ = Rules::LoadApiPresetDatabase(); // 规则不可用时仍保留独立的原始采集。
    ruleFailed_ = !ruleDatabase_.error.empty();
    // 只归档固定的来源身份；授权文件路径不落入证据计划。
    JsonObject plan{{"kind", Text(kApiFollowPlanKind)}, {"projectId", Text(request.projectId)},
        {"session", Object({{"id", Text(frozen.sampleId)}, {"epoch", Text(newEpoch)}})},
        {"revisionId", Text(frozen.revisionId)}, {"snapshotId", Text(frozen.snapshotId)},
        {"revisionHash", Text(revisionHash)}, {"configSemanticHash", Text(semanticHash)},
        {"sourceEpoch", Text(newEpoch)}, {"file", FileIdentity()}, {"readerPid", V::makeUInt(request.source.readerPid)},
        {"readerCreation100ns", Number(request.source.readerCreation)}, {"sessionIdentity", Number(request.source.sessionIdentity)},
        {"durationMs", V::makeUInt(request.durationMs)}, {"identity", Text("archive-consistency-only")},
        {"checkpointRequired", V::makeBool(true)}};
    if (!ruleDatabase_.presetSet.empty()) {
        plan.emplace_back("rulePresetSet", Text(ruleDatabase_.presetSet));
        plan.emplace_back("ruleSourceSha256", Text(ruleDatabase_.sourceSha256));
    }
    if (request.mixedEtw) plan.emplace_back("mixedEtw", V::makeBool(true));
    plan_ = Object(std::move(plan));
    sample = std::move(frozen);
    epoch = std::move(newEpoch);
    return {};
}

bool PassiveApiCapture::Tick(ProjectDocument& project, std::string_view sampleId)
{
    const auto now = Clock::now(); // 实际会话调度时间。
    if (now < nextPoll_) {
        return true;
    }
    nextPoll_ = now + kPollInterval;
    ReadBatch();
    // 本轮结束时提交满批，下轮可以直接读入。空轮次也会提交已到时的积压。
    if (pending_.size() > kQueueRows - Tail::kMaxPollRows || (!pending_.empty() && now >= nextCommit_)) {
        if (!Commit(project, sampleId)) {
            return false;
        }
    }
    return reader_->CanPoll();
}

void PassiveApiCapture::ReadBatch()
{
    auto rows = reader_->Poll(); // 连故障前面的有效行也由本批交付。
    if (pending_.empty() && !rows.empty()) {
        nextCommit_ = Clock::now() + kCommitInterval;
    }
    for (auto& row : rows) {
        diagnosis_.Observe(row); // 只读取尾读器已验过的行，包括同批坏行前的有效前缀。
        // 声明和普通原包各自保留第一条。同一批次可能同时包含两种证据。
        if ((!hooksInstalledSequence_ || !firstApiSequence_) && MatchesFrozenSource(row, status_.source)) {
            if (!hooksInstalledSequence_ && IsHooksInstalledNotice(row.packet)) {
                hooksInstalledSequence_ = row.sourceSequence;
            }
            if (!firstApiSequence_ && IsOrdinaryApiCall(row.packet)) {
                firstApiSequence_ = row.sourceSequence;
            }
        }
        if (row.clue) {
            latestClue_ = row.clue;
            latestClueSequence_ = row.sourceSequence;
            ++clueRows_;
        }
        pending_.push_back(std::move(row));
    }
    status_ = reader_->Status();
}

void PassiveApiCapture::Finish(ProjectDocument& project, std::string_view sampleId, std::string_view reason)
{
    if (ended_) {
        return;
    }
    // 首次归档错误后停止读取。正常停止冻结可见长度，原写入方可继续工作。
    if (writeResult_ && reader_->FreezeVisibleEnd()) {
        const auto deadline = Clock::now() + kFinalBudget; // 后续同源读取的协作截止时刻。
        for (unsigned i = 0; i < kFinalPolls && reader_->CanPoll() && Clock::now() < deadline; ++i) {
            if (pending_.size() > kQueueRows - Tail::kMaxPollRows && !Commit(project, sampleId)) {
                break;
            }
            if (Clock::now() >= deadline) {
                break;
            }
            ReadBatch();
        }
    }
    status_ = reader_->Status();
    reader_.reset();
    ended_ = true;
    if (writeResult_) {
        (void)Commit(project, sampleId, reason);
    }
    pending_.clear(); // 读取已验证到的尾部仍由状态计数反映。
}

V PassiveApiCapture::FileIdentity() const
{
    return Object({{"volumeSerial", Number(volumeSerial_)}, {"fileId", Text(fileId_)},
        {"initialVisibleBytes", Number(initialBytes_)}});
}

JsonObject PassiveApiCapture::SourceReportFields() const
{
    const auto nullable = [](const std::optional<std::uint64_t>& value) -> V {
        return value ? Number(*value) : V::makeNull();
    }; // 保留未提供的统计及尚未设置的截止边界。
    return {{"kind", Text("passive-api-archive")}, {"state", Text(TailState(status_.state))},
        {"readerPid", V::makeUInt(status_.source.readerPid)},
        {"readerCreation100ns", Number(status_.source.readerCreation)},
        {"sessionIdentity", Number(status_.source.sessionIdentity)}, {"identity", Text("archive-consistency-only")},
        {"validatedRows", Number(status_.validatedRows)}, {"validatedBytes", Number(status_.validatedBytes)},
        {"visibleBytes", nullable(status_.visibleBytes)}, {"clueRows", Number(clueRows_)},
        {"reportedAgentDrops", nullable(status_.reportedAgentDrops)}, {"cutoffBytes", nullable(status_.cutoffBytes)},
        {"cutoffReached", V::makeBool(status_.state == PassiveApiTailState::Cutoff)},
        {"partialLineBytes", Number(status_.partialLineBytes)},
        {"writerReceipt", V::makeNull()}, {"coverage", Text("unknown")},
        {"win32Error", V::makeUInt(status_.win32Error)}};
}

V PassiveApiCapture::SourceReport() const
{
    auto fields = SourceReportFields(); // 保留实时回执已有的字段及其语义。
    V latest = V::makeNull(); // 实时投影的线索可处于待写状态。
    if (latestClue_) {
        std::string name; // 线索目录的导出名均为 ASCII。
        for (const auto character : latestClue_->api) {
            name.push_back(static_cast<char>(character));
        }
        latest = Object({{"api", Text(name)}, {"family", Text(latestClue_->family)},
            {"sourceSequence", Number(latestClueSequence_)},
            {"rawVerified", V::makeBool(latestClueSequence_ <= recordedRows_)}});
    }
    fields.emplace_back("latestClue", std::move(latest));
    fields.emplace_back("diagnosis", diagnosis_.Report(status_, ended_));
    return Object(std::move(fields));
}

V PassiveApiCapture::ArchiveReport() const
{
    return Object({{"status", Text(!writeResult_ ? "failed" : checkpoint_ ? "raw-verified" : "pending")},
        {"segmentOrdinal", Number(checkpoint_ ? checkpoint_->ordinal : 0)}, {"recordedRows", Number(recordedRows_)},
        {"pendingRows", Number(pending_.size())}, {"queueDropped", Number(0)},
        {"unconfirmedRows", Number(!writeResult_ ? status_.validatedRows - recordedRows_ : 0)},
        {"lastSequence", checkpoint_ ? Number(checkpoint_->rawEnd.lastSequence) : V::makeNull()},
        {"flushedBytes", checkpoint_ ? Number(checkpoint_->rawEnd.byteOffset) : V::makeNull()},
        {"error", writeResult_ ? V::makeNull() : Text(writeResult_.detail)},
        {"win32Error", V::makeUInt(writeResult_.nativeError)}});
}

std::string_view PassiveApiCapture::ReadinessState() const noexcept
{
    if (!writeResult_) {
        return "archive-interrupted";
    }
    // 正常停止需要读完冻结边界且恰好结束在完整行后。损坏或未排空时不报告无匹配。
    const bool inputComplete = status_.state == PassiveApiTailState::Cutoff && status_.partialLineBytes == 0;
    if ((ended_ && !inputComplete) || (!ended_ && !reader_->CanPoll())) {
        return "source-interrupted";
    }
    if (firstRaw_) {
        return "observed";
    }
    if (ended_) {
        return "stopped-no-match";
    }
    return hooksInstalledSequence_ ? "attached" : "awaiting-attach";
}

V PassiveApiCapture::ReadinessReport() const
{
    // 停止或中断后仍保留历史声明及已提交坐标。实际连接状态由既有诊断单独描述。
    return Object({{"state", Text(ReadinessState())},
        {"hooksInstalledSourceSequence", hooksInstalledSequence_ ? Number(hooksInstalledSequence_) : V::makeNull()},
        {"firstRaw", firstRaw_ ? Object({{"segmentOrdinal", Number(firstRaw_->segmentOrdinal)},
            {"rawSequence", Number(firstRaw_->rawSequence)}, {"sourceSequence", Number(firstRaw_->sourceSequence)}})
            : V::makeNull()}});
}

V PassiveApiCapture::RulesReport() const
{
    // 位置在归档发布后一次写入。终段和读失败保留最后一次有效位置。
    V latest = V::makeNull(); // 本次没有规则命中时保留显式空值。
    if (latestRuleRaw_ && latestRule_) {
        const auto& position = *latestRuleRaw_; // 已提交检查点内的原包位置。
        Ksword::Evidence::JsonObject fields{{"ruleId", Text(latestRule_->ruleId)},
            {"segmentOrdinal", Number(position.segmentOrdinal)}, {"rawSequence", Number(position.rawSequence)},
            {"sourceSequence", Number(position.sourceSequence)}};
        if (const auto& behavior = latestRule_->behavior) { // 与末条分类命中共享原始坐标。
            fields.emplace_back("behavior", Object({{"ruleId", Text(behavior->ruleId)}, {"evidence", Text(behavior->evidence)},
                {"summary", Text(behavior->summary)}, {"summaryZh", behavior->summaryZh.empty() ? V::makeNull() : Text(behavior->summaryZh)}}));
        }
        latest = V::makeObject(std::move(fields));
    }
    Ksword::Evidence::JsonArray behaviors; // 仅投影已提交批次保留的行为窗口，不读档或重新求值。
    for (const auto& entry : recentBehaviors_) {
        const auto& match = entry.match; // 原批次的命中值及两套序号。
        const auto& behavior = *match.behavior; // 进入独立窗口前已确认存在的行为释义。
        behaviors.push_back(Object({{"segmentOrdinal", Number(entry.segmentOrdinal)},
            {"rawSequence", Number(match.rawSequence)}, {"sourceSequence", Number(match.sourceSequence)},
            {"api", Text(match.api)}, {"ruleId", Text(match.ruleId)},
            {"behavior", Object({{"ruleId", Text(behavior.ruleId)}, {"evidence", Text(behavior.evidence)},
                {"summary", Text(behavior.summary)}, {"summaryZh", Text(behavior.summaryZh)}})}}));
    }
    return Object({{"presetSet", ruleDatabase_.presetSet.empty() ? V::makeNull() : Text(ruleDatabase_.presetSet)},
        {"sourceSha256", ruleDatabase_.sourceSha256.empty() ? V::makeNull() : Text(ruleDatabase_.sourceSha256)},
        {"configError", ruleDatabase_.error.empty() ? V::makeNull() : Text(ruleDatabase_.error)}, {"profile", Text("by-category")},
        {"coverage", Text("unknown")}, {"state", Text(ruleFailed_ ? "evaluation-failed" : "ready")},
        {"matchedRows", Number(ruleMatches_)}, {"latest", std::move(latest)},
        {"behaviorMatches", Number(behaviorMatches_)},
        {"behaviorWindowTruncated", V::makeBool(behaviorMatches_ > recentBehaviors_.size())},
        {"recentBehaviors", V::makeArray(std::move(behaviors))}});
}

void PassiveApiCapture::ObserveCommittedRules(const ProjectApiCheckpoint& committed) noexcept
{
    if (ruleFailed_ || pending_.empty()) {
        return;
    }
    auto report = Rules::AnalyzeCommittedApiPresetBatch(ruleDatabase_, pending_, committed.planRawSequence,
        committed.previousSourceSequence);
    if (report.error != Rules::ApiPresetError::None) {
        ruleFailed_ = true;
        return;
    }
    if (!report.matches.empty()) {
        const auto& last = report.matches.back(); // 同一检查点内按源归档顺序的最后一次命中。
        ruleMatches_ += report.matches.size();
        // 复用本次已提交批次的求值结果，只将带行为释义的命中按原顺序纳入有界历史。
        for (const auto& match : report.matches) {
            if (!match.behavior) {
                continue;
            }
            ++behaviorMatches_;
            if (recentBehaviors_.size() == kBehaviorRows) {
                recentBehaviors_.erase(recentBehaviors_.begin());
            }
            recentBehaviors_.push_back({committed.ordinal, match});
        }
        latestRuleRaw_ = RawPosition{committed.ordinal, last.rawSequence, last.sourceSequence};
        latestRule_ = std::move(report.matches.back());
    }
}

bool PassiveApiCapture::Incomplete() const noexcept
{
    return ended_ && (!writeResult_ || status_.state != PassiveApiTailState::Cutoff || status_.partialLineBytes != 0);
}

std::string_view PassiveApiCapture::FailureReason() const noexcept
{
    return writeResult_ ? "source-unavailable" : "archive-unavailable";
}

bool PassiveApiCapture::Commit(ProjectDocument& project, std::string_view sampleId,
    std::optional<std::string_view> reason)
{
    // 一个段以冻结计划开头，末尾可选跟随终态。原始包总是内联保存。
    std::vector<std::string> metadata;
    metadata.reserve(pending_.size() + 2);
    metadata.push_back(Ksword::Evidence::WriteJson(plan_));
    for (const auto& row : pending_) {
        metadata.push_back(Ksword::Evidence::WriteJson(Object({{"kind", Text(kApiFollowPacketKind)},
            {"sourceSequence", Number(row.sourceSequence)}, {"readerCreation100ns", Number(row.readerCreation)}})));
    }
    if (reason) {
        metadata.push_back(Ksword::Evidence::WriteJson(Object({{"kind", Text(kApiFollowEndKind)},
            {"stopReason", Text(*reason)}, {"source", Object(SourceReportFields())}})));
    }
    std::vector<archive::RawEvidenceInput> inputs; // 借用本轮元数据及原包至写入和回读结束。
    inputs.reserve(metadata.size());
    inputs.push_back({metadata.front(), {}});
    for (std::size_t i = 0; i < pending_.size(); ++i) {
        inputs.push_back({metadata[i + 1], PacketBytes(pending_[i])});
    }
    if (reason) {
        inputs.push_back({metadata.back(), {}});
    }

    const auto& projectId = project.Info()->projectId; // 活会话持有并验证的同一项目写租约。
    const auto nextOrdinal = checkpoint_ ? checkpoint_->ordinal + 1 : 1; // 只写已发布前缀后的新段。
    const auto previous = checkpoint_ ? checkpoint_->rawEnd.lastSequence : 0; // 前段实际封装序号。
    if (!nextOrdinal) {
        writeResult_ = Failure(ProjectError::LimitExceeded, "apiArchiveOrdinal");
        return false;
    }
    archive::RawEvidenceReceipt receipt; // 本次实际写出、关闭和刷盘结果。
    writeResult_ = project.WriteRawEvidenceSegment({projectId, sampleId, nextOrdinal, previous,
        [&inputs](archive::RawEvidenceArchive& writer) -> ProjectResult {
            const auto result = writer.Append(inputs); // 写一块有界记录。
            if (result.result.status == archive::SegmentWriteStatus::Ok) {
                return {};
            }
            return Failure(ProjectError::IoError, "apiArchiveRawWrite", result.result.error.win32Error);
        }}, receipt);
    if (!writeResult_) {
        return false;
    }
    if (!receipt.flushed || receipt.result.status != archive::SegmentWriteStatus::Ok) {
        writeResult_ = Failure(ProjectError::Corrupt, "apiArchiveRawFlush");
        return false;
    }

    // 同句柄逐包回读并核对散列，发布成功后才推进实时回执。
    ProjectApiCheckpoint committed; // 当前段的候选水位，失败时保留上次结果。
    writeResult_ = PublishApiCheckpoint(project, sampleId, nextOrdinal, receipt, inputs,
        checkpoint_ ? &*checkpoint_ : nullptr, committed);
    if (!writeResult_) {
        return false;
    }
    // 回读已逐条比对本段原包和元数据。计划记录在首位，连续的包在其后按源行号排列。
    if (!firstRaw_ && firstApiSequence_ > committed.previousSourceSequence &&
        firstApiSequence_ <= committed.lastSourceSequence) {
        const auto offset = firstApiSequence_ - committed.previousSourceSequence; // 计划记录后的包序偏移。
        firstRaw_ = RawPosition{committed.ordinal, committed.planRawSequence + offset, firstApiSequence_};
    }
    recordedRows_ = committed.lastSourceSequence;
    ObserveCommittedRules(committed);
    checkpoint_ = std::move(committed);
    pending_.clear();
    return true;
}

} // namespace ks::cli::action_analyze
