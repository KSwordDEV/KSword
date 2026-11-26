#include "NativeExecutionJournal.h"

#include "../Project/ProjectStorage.h"
#include "../Project/SampleImageDefinition.h"

#include <algorithm>
#include <charconv>
#include <filesystem>

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace storage = project::ProjectStorage;
using V = JsonValue;

V Text(std::string_view value) { return V::makeString(std::string(value)); }
V Count(std::uint64_t value) { return Text(std::to_string(value)); }

V Boundary(const std::optional<archive::RawEvidenceBoundary>& value)
{
    return value ? V::makeObject({{"byteOffset", Count(value->byteOffset)},
        {"blockOrdinal", Count(value->blockOrdinal)}, {"lastSequence", Count(value->lastSequence)}}) : V::makeNull();
}

V Issue(const project::ProjectResult& status)
{
    return status ? V::makeNull() : V::makeObject({{"errorId", Text(project::ProjectErrorName(status.error))},
        {"stage", Text(status.detail)}, {"win32Error", V::makeUInt(status.nativeError)}});
}

NativeExecutionSaveReply Invalid(const char* id, const char* message)
{
    return {false, FaultJson({id, message, std::nullopt, 1, "cli", 0, "native-execution-save"})};
}

// 枚举实际固定目录，不能因中间缺段把更后的既有证据当作可覆盖的空档。
project::ProjectResult ExistingOrdinals(const std::wstring& path, std::string_view sample,
    std::wstring_view lane, std::uint64_t& count)
{
    auto rootPath = std::filesystem::path(path);
    const auto leaf = rootPath.filename().wstring();
    if (CompareStringOrdinal(leaf.c_str(), -1, L"project.ksaproj", -1, TRUE) == CSTR_EQUAL) {
        rootPath = rootPath.parent_path();
        if (rootPath.empty()) rootPath = L".";
    }
    storage::Directory root, raw;
    if (const auto status = storage::OpenRoot(rootPath.wstring(), false, false, root); !status) return status;
    const auto opened = storage::OpenDirectory(root, {L"samples", storage::WideAscii(sample), lane}, raw);
    if (opened.error == project::ProjectError::NotFound) return {};
    if (!opened) return opened;
    std::error_code error;
    std::uint64_t maximum = 0;
    std::filesystem::directory_iterator entry(raw.path, error), end;
    if (error) return storage::WinFailure("nativeExecutionDirectory", static_cast<DWORD>(error.value()));
    for (; entry != end; entry.increment(error)) {
        if (error) return storage::WinFailure("nativeExecutionDirectory", static_cast<DWORD>(error.value()));
        const auto name = entry->path().filename().wstring();
        if (name.size() != 27 || name.substr(20) != L".ksaseg")
            return storage::Failure(project::ProjectError::RecoveryRequired, "nativeExecutionSegmentName");
        std::uint64_t ordinal = 0;
        for (std::size_t index = 0; index < 20; ++index) {
            const auto digit = name[index];
            if (digit < L'0' || digit > L'9' || ordinal > (UINT64_MAX - (digit - L'0')) / 10)
                return storage::Failure(project::ProjectError::RecoveryRequired, "nativeExecutionSegmentName");
            ordinal = ordinal * 10 + (digit - L'0');
        }
        if (!ordinal || count == UINT64_MAX)
            return storage::Failure(project::ProjectError::LimitExceeded, "nativeExecutionSegmentCount");
        maximum = (std::max)(maximum, ordinal);
        ++count;
    }
    if (error) return storage::WinFailure("nativeExecutionDirectory", static_cast<DWORD>(error.value()));
    // 固定长度规范文件名一一对应段号；count==max 当且仅当从1起无缺口。
    return count == maximum ? project::ProjectResult{} :
        storage::Failure(project::ProjectError::RecoveryRequired, "nativeExecutionSegmentGap");
}
} // namespace

project::ProjectResult InspectNativeJournalLane(const std::wstring& path, std::string_view sample,
    std::wstring_view lane, std::uint64_t& count)
{
    count = 0;
    if (lane != L"raw-native" && lane != L"raw-memory")
        return storage::Failure(project::ProjectError::InvalidArgument, "nativeJournalLane");
    return ExistingOrdinals(path, sample, lane, count);
}

project::ProjectResult ReadNativeExecutionChain(const project::ProjectDocument& document,
    std::string_view sample, std::uint64_t ordinal, project::ArchivedNativeExecution& out)
{
    out = {};
    if (!ordinal)
        return storage::Failure(project::ProjectError::LimitExceeded, "nativeExecutionOrdinal");
    std::optional<std::uint64_t> previous = 0;
    for (std::uint64_t index = 1;; ++index) {
        if (const auto status = project::ReadNativeExecution(document, sample, index, previous, out); !status) {
            out = {};
            return status;
        }
        previous = out.end.lastSequence;
        if (index == ordinal) break;
    }
    return {};
}

project::ProjectResult NativeExecutionJournal::Open(const std::wstring& path, std::string_view sampleId)
{
    if (const auto status = project_.Open(path, project::ProjectAccess::ReadWrite); !status) return status;
    if (sampleId.empty()) {
        project::SampleInfo sample;
        const auto revision = project_.Info()->revisionId;
        if (const auto status = project_.CreateSample("Native execution evidence", sample, revision); !status) return status;
        sampleId_ = sample.sampleId;
    } else {
        project::SampleRecord sample;
        if (const auto status = project_.ReadSample(sampleId, sample); !status) return status;
        sampleId_ = sample.info.sampleId;
    }
    std::uint64_t count = 0;
    if (const auto status = InspectNativeJournalLane(path, sampleId_, L"raw-native", count); !status) return status;
    if (count == UINT64_MAX)
        return storage::Failure(project::ProjectError::LimitExceeded, "nativeExecutionOrdinal");
    for (std::uint64_t ordinal = 1; ordinal <= count; ++ordinal) {
        project::ArchivedNativeExecution checked;
        if (const auto status = project::ReadNativeExecution(project_, sampleId_, ordinal, previousSequence_, checked); !status)
            return status;
        previousSequence_ = checked.end.lastSequence;
        ++nextOrdinal_;
    }
    return memory_.Open(project_, path, sampleId_);
}

V NativeExecutionJournal::Describe() const
{
    return V::makeObject({{"projectId", Text(project_.Info()->projectId)}, {"sampleId", Text(sampleId_)},
        {"breakpointDefinitionId", definitionId_.empty() ? V::makeNull() : Text(definitionId_)},
        {"stream", Text("raw-native")}, {"nextOrdinal", Count(nextOrdinal_)},
        {"sessionSaveLimit", Count(kNativeExecutionSessionSaveLimit)}, {"writerLeaseHeld", V::makeBool(true)},
        {"memoryArchive", memory_.Describe()}});
}

// 从原sample的冻结配置查找定义，明确限制当前已支持的RVA入口，不把调试符号当PE导出。
project::ProjectResult NativeExecutionJournal::ResolveImageDefinition(std::string_view definitionId,
    const std::wstring& modulePath, std::uint32_t& rva, std::optional<std::string>& imageSha256)
{
    if (const auto status = project::ResolveSampleImageDefinition(project_, sampleId_, definitionId, modulePath, rva, &imageSha256); !status)
    {
        return status;
    }
    definitionId_ = definitionId; // 仅登记已真正解析到的冻结定义身份。
    return {};
}

NativeSessionApiReply NativeExecutionJournal::CaptureApi(const Request& request, bool jsonl,
    const control::OwnerIdentity& identity, control::NativeDebugOwner& owner)
{
    // 不另开writer；API错误或部分结果不改动执行/内存lane的游标及失败回执。
    return CaptureNativeSessionApi(project_, sampleId_, request, jsonl, identity, owner);
}

NativeExecutionSaveReply NativeExecutionJournal::Save(const Request& request, bool jsonl,
    const control::OwnerIdentity& identity, control::NativeDebugOwner& owner)
{
    std::string stop, revision;
    if (jsonl) {
        const auto* params = request.params.asObject();
        const auto* expected = request.expected ? request.expected->asObject() : nullptr;
        const auto* stopField = request.expected ? request.expected->find("stopId") : nullptr;
        const auto* revisionField = request.expected ? request.expected->find("stateRevision") : nullptr;
        if (!request.session || request.session->id != identity.sessionId || request.session->epoch != identity.epoch ||
            !params || !params->empty() || !expected || expected->size() != 2 || !stopField || !revisionField ||
            !stopField->tryGetString(stop) || !revisionField->tryGetString(revision))
            return Invalid("invalid-execution-save", "Save requires the current session, empty params and expected stopId/stateRevision");
    } else {
        const auto* args = request.params.asArray();
        if (request.expected || !args || args->size() != 2 || !(*args)[0].tryGetString(stop) || !(*args)[1].tryGetString(revision))
            return Invalid("invalid-execution-save", "Usage: execution-save STOP_ID STATE_REVISION");
    }
    std::uint64_t expectedRevision = 0;
    const auto parsed = std::from_chars(revision.data(), revision.data() + revision.size(), expectedRevision);
    if (stop.empty() || stop.size() > kRequestIdBytes || !expectedRevision || parsed.ec != std::errc{} ||
        parsed.ptr != revision.data() + revision.size() || revision != std::to_string(expectedRevision))
        return Invalid("invalid-execution-save", "Invalid stopId or canonical revision");

    // 不采用上一轮投影或外来文档；Query 与保存均由当前串行控制线程发起。
    const auto state = owner.Query();
    const auto observed = control::NativeExecutionFromOwnedStop(state);
    if (!observed || observed->stopId != stop || observed->stateRevision != expectedRevision ||
        identity.sampleId != sampleId_ || observed->event.backendInstanceId != identity.backendInstanceId)
        return Invalid("stale-execution-stop", "Query a current owned execution stop before saving");
    if (const auto found = saved_.find(observed->event.serial); found != saved_.end()) return {true, found->second};
    if (failedWrite_) return {false, *failedWrite_};
    if (nextOrdinal_ == UINT64_MAX || saved_.size() >= kNativeExecutionSessionSaveLimit)
        return Invalid("execution-save-limit", "Native execution saves are limited to 4096 per session or ordinal space is exhausted");

    project::ProjectNativeExecutionReceipt receipt;
    const auto written = project::WriteNativeExecution(project_, identity, nextOrdinal_, previousSequence_, state, receipt);
    auto report = V::makeObject({{"projectId", Text(project_.Info()->projectId)}, {"sampleId", Text(sampleId_)},
        {"stream", Text("raw-native")}, {"ordinal", Count(nextOrdinal_)}, {"segmentVerified", V::makeBool(receipt.verified)},
        {"sha256", receipt.sha256.empty() ? V::makeNull() : Text(receipt.sha256)},
        {"event", V::makeObject({{"backendInstanceId", Text(observed->event.backendInstanceId)}, {"serial", Count(observed->event.serial)}})},
        {"stopId", Text(stop)}, {"stateRevision", Count(expectedRevision)},
        {"raw", V::makeObject({{"written", Boundary(receipt.raw.written)}, {"flushed", Boundary(receipt.raw.flushed)},
            {"status", V::makeUInt(static_cast<unsigned>(receipt.raw.result.status))},
            {"issue", V::makeUInt(static_cast<unsigned>(receipt.raw.result.error.issue))},
            {"errorOffset", Count(receipt.raw.result.error.offset)},
            {"win32Error", V::makeUInt(receipt.raw.result.error.win32Error)},
            {"inputIssue", V::makeUInt(static_cast<unsigned>(receipt.raw.inputIssue))},
            {"rejectedInput", receipt.raw.rejectedInput ? Count(*receipt.raw.rejectedInput) : V::makeNull()}})},
        {"error", Issue(written)}, {"appendBlocked", V::makeBool(!written)}});
    if (!written) {
        failedWrite_ = report; // 失败不跳段、不重写；保留首次真实写入与刷盘回执。
        return {false, std::move(report)};
    }
    previousSequence_ = receipt.raw.flushed->lastSequence;
    ++nextOrdinal_;
    saved_.emplace(observed->event.serial, report);
    return {true, std::move(report)};
}
} // namespace ks::cli::action_analyze
