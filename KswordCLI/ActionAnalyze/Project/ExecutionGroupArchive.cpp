#include "ExecutionGroupArchive.h"
#include "ProjectStorage.h"
#include "SampleImageDefinition.h"

#include <algorithm>

namespace Ksword::ActionAnalyze {
namespace native = ks::cli::action_analyze::control;
namespace {
using V = Evidence::JsonValue;

// 输入Windows项目路径，输出严格UTF-8 JSON文本；转换失败保持null而不截断目录身份。
V Path(const std::wstring& path)
{
    if (path.empty())
    {
        return V::makeString({});
    }
    const auto bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(),
        static_cast<int>(path.size()), nullptr, 0, nullptr, nullptr); // 完整路径需要的UTF-8字节数。
    if (!bytes)
    {
        return V::makeNull();
    }
    std::string text(static_cast<std::size_t>(bytes), '\0'); // 本次目录的无损编码结果。
    return WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, path.data(), static_cast<int>(path.size()),
        text.data(), bytes, nullptr, nullptr) ? V::makeString(std::move(text)) : V::makeNull();
}

// 输入独立项目结果，输出明确的错误或null；不以集合当前Held代替存储成功。
V Issue(const ProjectResult& status)
{
    return status ? V::makeNull() : V::makeObject({
        {"errorId", V::makeString(ProjectErrorName(status.error))},
        {"stage", V::makeString(status.detail)}, {"win32Error", V::makeUInt(status.nativeError)}});
}

// 输入独立写入边界，输出无损原坐标；无刷盘边界保持null。
V Boundary(const std::optional<ks::cli::action_analyze::archive::RawEvidenceBoundary>& boundary)
{
    return boundary ? V::makeObject({{"byteOffset", ProjectStorage::Number(boundary->byteOffset)},
        {"blockOrdinal", ProjectStorage::Number(boundary->blockOrdinal)},
        {"lastSequence", ProjectStorage::Number(boundary->lastSequence)}}) : V::makeNull();
}

// 输入最近保存或首次失败值，输出原事件与存储回执；不输出可用作Continue的停止票据。
V Saved(const std::shared_ptr<const ExecutionGroupExecutionSave>& saved)
{
    if (!saved)
    {
        return V::makeNull();
    }
    const auto& owner = saved->owner; // 此保存实际所属的原成员身份。
    const auto& observation = saved->observation; // 未构成执行证据时保持null。
    const auto& receipt = saved->receipt; // 未实际尝试写入时没有段坐标。
    V event = V::makeNull(); // 原执行事件只作历史定位，不制造新的控制请求。
    if (observation)
    {
        event = V::makeObject({{"backendInstanceId", V::makeString(observation->event.backendInstanceId)},
            {"serial", ProjectStorage::Number(observation->event.serial)},
            {"pid", V::makeUInt(observation->pid)},
            {"creationFileTime", ProjectStorage::Number(observation->processCreationFileTime)},
            {"instructionAddress", ProjectStorage::Number(observation->instructionAddress)},
            {"observation", V::makeString(observation->kind == native::NativeExecutionKind::InstructionCompleted
                ? "instruction-completed" : "execution-enter-attempt")}});
    }
    // 写入与刷盘状态全部独立保留；已核验坐标不掩盖后续首次追加失败。
    return V::makeObject({{"owner", V::makeObject({{"sampleId", V::makeString(owner.sampleId)},
        {"sessionId", V::makeString(owner.sessionId)}, {"epoch", V::makeString(owner.epoch)},
        {"backendInstanceId", V::makeString(owner.backendInstanceId)}})},
        {"error", Issue(saved->status)}, {"event", std::move(event)},
        {"ordinal", receipt ? ProjectStorage::Number(receipt->ordinal) : V::makeNull()},
        {"segmentVerified", V::makeBool(receipt && receipt->verified)},
        {"sha256", receipt && !receipt->sha256.empty() ? V::makeString(receipt->sha256) : V::makeNull()},
        {"written", receipt ? Boundary(receipt->raw.written) : V::makeNull()},
        {"flushed", receipt ? Boundary(receipt->raw.flushed) : V::makeNull()},
        {"rawStatus", receipt ? V::makeUInt(static_cast<unsigned>(receipt->raw.result.status)) : V::makeNull()},
        {"rawIssue", receipt ? V::makeUInt(static_cast<unsigned>(receipt->raw.result.error.issue)) : V::makeNull()},
        {"rawErrorOffset", receipt ? ProjectStorage::Number(receipt->raw.result.error.offset) : V::makeNull()},
        {"rawWin32Error", receipt ? V::makeUInt(receipt->raw.result.error.win32Error) : V::makeNull()}});
}
} // namespace

// 同一份文档服务三端历史回执；路径严格转UTF-8，数字保持无损字符串。
Evidence::JsonValue DescribeExecutionGroupArchive(const ExecutionGroupArchiveView& view)
{
    return V::makeObject({{"configured", V::makeBool(view.configured)},
        {"directory", Path(view.directory)},
        {"projectId", V::makeString(view.projectId)}, {"sampleId", V::makeString(view.sampleId)},
        {"setupError", Issue(view.setup)}, {"writerLeaseHeld", V::makeBool(view.writerHeld)},
        {"stream", V::makeString("raw-native")}, {"duplicate", V::makeBool(view.duplicate)},
        {"appendBlocked", V::makeBool(view.appendBlocked)}, {"saved", Saved(view.saved)},
        {"firstFailure", Saved(view.firstFailure)}});
}

// 准备只在集合Start前执行；失败没有原生责任，不保留无用writer租约。
bool ExecutionGroupArchive::Prepare(const std::wstring& directory, bool openExisting)
{
    if (project_ || view_.configured)
    {
        view_.setup = {ProjectError::InvalidArgument, 0, "executionGroupArchiveAlreadyUsed"};
        return false;
    }
    view_.directory = directory;
    view_.configured = !directory.empty();
    if (directory.empty())
    {
        view_.setup = openExisting
            ? ProjectResult{ProjectError::InvalidArgument, 0, "executionGroupProjectDirectoryRequired"} : ProjectResult{};
        return static_cast<bool>(view_.setup);
    }

    // 项目模式在请求时冻结，不以目录是否存在来猜新建还是打开。
    project_.emplace();
    view_.setup = openExisting ? project_->Open(directory, ProjectAccess::ReadWrite)
        : project_->Create(directory, {"Execution group observations", "Explicit member execution evidence"});
    if (view_.setup)
    {
        view_.projectId = project_->Info()->projectId;
        SampleInfo sample; // 所有成员附加前创建本轮采样，失败不启动任一目标。
        view_.setup = project_->CreateSample("Execution group observations", sample);
        if (view_.setup)
        {
            view_.sampleId = sample.sampleId;
            view_.writerHeld = true;
        }
    }
    if (!view_.setup)
    {
        project_->Close();
        project_.reset(); // 保留实际失败和已创建项目身份，但归还尚未使用的writer。
    }
    return static_cast<bool>(view_.setup);
}

// 输入Start冻结的完整目录；先解析副本再统一提交，任何定义错误都在首个附加前停止。
bool ExecutionGroupArchive::ResolveSites(std::vector<native::ExecutionGroupSite>& sites)
{
    auto resolved = sites; // 失败时不把部分成员的继承散列写回原目录。
    for (auto& site : resolved)
    {
        if (site.definitionId.empty())
        {
            continue; // 手工站点保持原语义，不要求必须存在项目定义。
        }
        if (!project_ || !view_.writerHeld || site.address || !site.rva || !site.exactExport.empty())
        {
            view_.setup = {ProjectError::InvalidArgument, 0, "executionGroupDefinitionProjectRvaRequired"};
            break;
        }
        std::uint32_t rva = 0; // 仅由本轮sample冻结配置解析，不读取项目后来修订。
        std::optional<std::string> hash; // 冻结的期望映像约束，由原native核验实际文件。
        view_.setup = ResolveSampleImageDefinition(*project_, view_.sampleId, site.definitionId, site.modulePath, rva, &hash);
        if (!view_.setup)
        {
            break;
        }
        if (*site.rva != rva || (site.imageSha256 && hash && site.imageSha256 != hash))
        {
            view_.setup = {ProjectError::InvalidArgument, 0, "executionGroupDefinitionSiteMismatch"};
            break; // 手工输入不能覆盖冻结RVA或弱化已保存的映像散列。
        }
        if (hash)
        {
            site.imageSha256 = std::move(hash); // 未手填散列时继承冻结定义，不从磁盘同名文件补值。
        }
    }
    if (!view_.setup)
    {
        Close(); // 尚未启动任一成员；失败直接释放本次未使用的项目写租约。
        return false;
    }
    sites = std::move(resolved);
    return true;
}

// 显式保存只回读已有owner；不会自动求值条件、暂停其它成员或保存上一次事件。
void ExecutionGroupArchive::Save(native::OwnedExecutionGroup& group,
    const native::ExecutionGroupSessionEntry& displayed)
{
    auto saved = std::make_shared<ExecutionGroupExecutionSave>(); // 本次所有失败路径均有独立回执。
    saved->owner = displayed.owner;
    view_.saved = saved;
    view_.duplicate = false;
    if (!project_ || !view_.writerHeld || !view_.setup || view_.sampleId.empty())
    {
        saved->status = {ProjectError::NotOpen, 0, "executionGroupArchiveRequired"};
        return;
    }
    const auto current = group.QueryWithoutCondition(); // 不处理其它成员的假条件或合作Gate。
    const auto member = std::find_if(current.members.begin(), current.members.end(), [&](const auto& item) {
        return item.owner == displayed.owner;
    });
    if (member == current.members.end() || member->owner.sampleId != view_.sampleId ||
        !native::OwnedExecutionGroup::Matches(displayed.control, member->control))
    {
        saved->status = {ProjectError::InvalidArgument, 0, "executionGroupExecutionStopChanged"};
        return;
    }
    saved->observation = native::NativeExecutionFromOwnedStop(member->control);
    if (!saved->observation)
    {
        saved->status = {ProjectError::InvalidArgument, 0, "executionGroupExecutionEvidenceRequired"};
        return; // ManualPause或普通写入停点不伪造执行观察。
    }

    // backend/serial在成员间独立；旧事件重放即使遇到后来坏尾也只能返回原坐标。
    const auto& event = saved->observation->event; // 本次实际执行事件，不使用客户端索引。
    const auto key = std::make_pair(event.backendInstanceId, event.serial); // 原成员事件唯一键。
    if (const auto found = journal_.find(key); found != journal_.end())
    {
        view_.saved = found->second;
        view_.duplicate = true;
        return;
    }
    if (view_.appendBlocked)
    {
        saved->status = {ProjectError::IoError, 0, "executionGroupExecutionAppendBlocked"};
        return;
    }
    if (journal_.size() >= 4096 || ordinal_ == UINT64_MAX)
    {
        saved->status = {ProjectError::LimitExceeded, 0, "executionGroupExecutionSaveLimit"};
        return;
    }

    // 在写入前分配去重节点，异常后不能以同一事件重试覆盖可能已写的段。
    journal_.emplace(key, saved);
    saved->status = {ProjectError::IoError, 0, "executionGroupExecutionWriteInterrupted"};
    view_.appendBlocked = true;
    view_.firstFailure = saved;
    saved->receipt.emplace();
    saved->status = WriteNativeExecution(*project_, member->owner, ordinal_, previousSequence_, member->control, *saved->receipt);
    if (!saved->status)
    {
        return; // 原始写入/刷盘/核验失败留在本回执，不跳段追加。
    }
    previousSequence_ = saved->receipt->raw.flushed->lastSequence;
    ++ordinal_;
    view_.appendBlocked = false;
    view_.firstFailure.reset();
}

// 调用方已确认全体原owner clean；项目释放不会抹去最后保存坐标及失败诊断。
void ExecutionGroupArchive::Close()
{
    if (project_)
    {
        project_->Close();
        project_.reset();
    }
    view_.writerHeld = false;
}

} // namespace Ksword::ActionAnalyze
