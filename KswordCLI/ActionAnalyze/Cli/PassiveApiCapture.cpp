#include "PassiveApiCapture.h"

#include "../Project/ProjectStorage.h"

#include <algorithm>
#include <utility>

namespace ks::cli::action_analyze {
namespace {
using namespace Ksword::ActionAnalyze;
using namespace Ksword::ActionAnalyze::ProjectStorage;
using Ksword::Evidence::PassiveApiTailState;
using Tail = Ksword::Evidence::PassiveApiArchiveTail;
using V = Ksword::Evidence::JsonValue;
using Clock = std::chrono::steady_clock;

constexpr std::size_t kQueueRows = 256; // 段内待写包总数。
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

void PassiveApiCapture::SetPlan(V plan)
{
    plan_ = std::move(plan);
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
    recordedRows_ = committed.lastSourceSequence;
    checkpoint_ = std::move(committed);
    pending_.clear();
    return true;
}

} // namespace ks::cli::action_analyze
