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
    Evidence::JsonArray automatic; // 仅投影最近非空自动批次，完整历史仍读raw-native而非不断膨胀响应。
    for (const auto& saved : view.automatic)
    {
        automatic.push_back(Saved(saved));
    }
    return V::makeObject({{"configured", V::makeBool(view.configured)},
        {"directory", Path(view.directory)},
        {"projectId", V::makeString(view.projectId)}, {"sampleId", V::makeString(view.sampleId)},
        {"setupError", Issue(view.setup)}, {"writerLeaseHeld", V::makeBool(view.writerHeld)},
        {"memberSetupError", view.memberSetup ? Issue(*view.memberSetup) : V::makeNull()},
        {"apiOwner", view.api ? V::makeObject({{"sampleId", V::makeString(view.apiOwner.sampleId)},
            {"sessionId", V::makeString(view.apiOwner.sessionId)}, {"epoch", V::makeString(view.apiOwner.epoch)},
            {"backendInstanceId", V::makeString(view.apiOwner.backendInstanceId)}}) : V::makeNull()},
        {"apiAdmissionError", view.api ? Issue(view.api->admission) : V::makeNull()},
        {"stream", V::makeString("raw-native")}, {"duplicate", V::makeBool(view.duplicate)},
        {"appendBlocked", V::makeBool(view.appendBlocked)}, {"saved", Saved(view.saved)},
        {"firstFailure", Saved(view.firstFailure)},
        {"autoSaveExecution", V::makeBool(view.autoSaveExecution)}, {"autoSaveStopped", V::makeBool(view.autoSaveStopped)},
        {"automaticError", Issue(view.automaticStatus)},
        {"verifiedExecutionSaves", ProjectStorage::Number(view.verifiedExecutionSaves)},
        {"automatic", V::makeArray(std::move(automatic))}});
}

// 输入内存读取/归档纯值，输出统一正文；最多64页，每页只预览32个原字节，完整字节仍在原快照和归档。
Evidence::JsonValue DescribeExecutionGroupMemory(const ExecutionGroupMemoryView& view)
{
    const auto stop = [](const std::optional<native::ProcessGroupStop>& value) {
        return value ? V::makeObject({{"pid", V::makeUInt(value->target.pid)},
            {"creationFileTime", ProjectStorage::Number(value->target.creationFileTime)},
            {"groupId", V::makeString(value->groupId)}, {"stopId", V::makeString(value->stopId)},
            {"backendInstanceId", V::makeString(value->event.backendInstanceId)},
            {"serial", ProjectStorage::Number(value->event.serial)},
            {"stateRevision", ProjectStorage::Number(value->stateRevision)}}) : V::makeNull();
    }; // 真实读前/读后停点保持独立；无后置确认时保持null。
    const auto source = [](const std::shared_ptr<const native::ProcessMemorySnapshotResult>& value) {
        if (!value)
        {
            return V::makeNull();
        }
        const auto& plan = value->request.plan; // 结果只绑定读取时冻结的真实身份与范围。
        return V::makeObject({{"sampleId", V::makeString(plan.sampleId)},
            {"trackingEpoch", V::makeString(plan.trackingEpoch)}, {"pid", V::makeUInt(plan.target.pid)},
            {"creationFileTime", ProjectStorage::Number(plan.target.creationFileTime100ns)},
            {"processInstanceId", V::makeString(plan.target.processInstanceId)},
            {"address", ProjectStorage::Number(plan.range.base)}, {"bytes", ProjectStorage::Number(plan.range.length)}});
    };
    V read = V::makeNull(); // 未读取不能冒充成功空快照。
    if (view.capture)
    {
        const auto& capture = *view.capture; // 请求、读前后停点和实际页来自同一次原会话读取。
        Evidence::JsonArray pages; // 有界页状态，失败页也保留诊断，不补零字节。
        if (capture.snapshot && capture.snapshot->round)
        {
            for (const auto& page : capture.snapshot->round->pages)
            {
                pages.push_back(V::makeObject({{"base", ProjectStorage::Number(page.pageBase)},
                    {"address", ProjectStorage::Number(page.sampledRange.base)}, {"bytes", ProjectStorage::Number(page.sampledRange.length)},
                    {"status", V::makeUInt(static_cast<unsigned>(page.status))}, {"win32Error", V::makeUInt(page.issue.win32Error)},
                    {"returnedBytes", page.returnedBytes ? ProjectStorage::Number(*page.returnedBytes) : V::makeNull()}}));
            }
        }
        Evidence::JsonArray previews; // 每个成功子范围最多32字节，完整内容不截断写入raw-memory。
        if (capture.snapshot)
        {
            constexpr char hex[] = "0123456789abcdef"; // 十六进制预览不借系统代码页解释原字节。
            for (const auto& page : capture.snapshot->captured)
            {
                std::string text; // 本页成功字节的有界预览；失败页不会出现空白填充。
                const auto count = (std::min)(page.bytes.size(), std::size_t{32});
                for (std::size_t index = 0; index < count; ++index)
                {
                    text.push_back(hex[page.bytes[index] >> 4]);
                    text.push_back(hex[page.bytes[index] & 15]);
                }
                previews.push_back(V::makeObject({{"address", ProjectStorage::Number(page.observation.sampledRange.base)},
                    {"capturedBytes", ProjectStorage::Number(page.bytes.size())}, {"previewHex", V::makeString(std::move(text))}}));
            }
        }
        read = V::makeObject({{"source", source(view.capture)}, {"stage", V::makeString(capture.stage)},
            {"win32Error", V::makeUInt(capture.win32Error)}, {"heldAtBothChecks", V::makeBool(capture.heldAtBothChecks)},
            {"before", stop(capture.before)}, {"after", stop(capture.after)},
            {"completeRange", V::makeBool(capture.snapshot && capture.snapshot->completeRange)},
            {"samplerState", capture.snapshot ? V::makeUInt(static_cast<unsigned>(capture.snapshot->status.state)) : V::makeNull()},
            {"pages", V::makeArray(std::move(pages))}, {"previews", V::makeArray(std::move(previews))}});
    }
    const auto& receipt = view.receipt; // 存储坐标属于savedSource，不能贴到后来新读取上。
    return V::makeObject({{"read", std::move(read)}, {"error", Issue(view.status)},
        {"appendBlocked", V::makeBool(view.appendBlocked)}, {"duplicate", V::makeBool(view.duplicate)},
        {"savedSource", source(view.savedSource)}, {"stream", V::makeString("raw-memory")},
        {"ordinal", receipt ? ProjectStorage::Number(receipt->ordinal) : V::makeNull()},
        {"segmentVerified", V::makeBool(receipt && receipt->verified)},
        {"sha256", receipt ? V::makeString(receipt->sha256) : V::makeNull()},
        {"written", receipt ? Boundary(receipt->raw.written) : V::makeNull()},
        {"flushed", receipt ? Boundary(receipt->raw.flushed) : V::makeNull()}});
}

// 准备只在集合Start前执行；失败没有原生责任，不保留无用writer租约。
bool ExecutionGroupArchive::Prepare(const std::wstring& directory, bool openExisting, bool autoSaveExecution)
{
    if (project_ || view_.configured)
    {
        view_.setup = {ProjectError::InvalidArgument, 0, "executionGroupArchiveAlreadyUsed"};
        return false;
    }
    view_.directory = directory;
    view_.configured = !directory.empty();
    view_.autoSaveExecution = autoSaveExecution;
    if (directory.empty())
    {
        view_.setup = (openExisting || autoSaveExecution)
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
    if (!ResolveSitesForSample(sites, view_.setup))
    {
        Close(); // Start尚未附加成员，失败可归还未使用writer；活集合追加不走此分支。
        return false;
    }
    return true;
}

// 输入本轮新增目录和独立状态槽；全部成功才替换目录，失败保留原站点和原项目租约。
bool ExecutionGroupArchive::ResolveSitesForSample(std::vector<native::ExecutionGroupSite>& sites, ProjectResult& status)
{
    status = {};
    auto resolved = sites; // 失败时不把部分成员的继承散列写回原目录。
    for (auto& site : resolved)
    {
        if (site.definitionId.empty())
        {
            continue; // 手工站点保持原语义，不要求必须存在项目定义。
        }
        if (!project_ || !view_.writerHeld || site.address || !site.rva || !site.exactExport.empty())
        {
            status = {ProjectError::InvalidArgument, 0, "executionGroupDefinitionProjectRvaRequired"};
            break;
        }
        std::uint32_t rva = 0; // 仅由本轮sample冻结配置解析，不读取项目后来修订。
        std::optional<std::string> hash; // 冻结的期望映像约束，由原native核验实际文件。
        std::optional<BreakpointCondition> condition; // 定义条件与映像约束一起由同一冻结sample读取。
        status = ResolveSampleImageDefinition(*project_, view_.sampleId, site.definitionId, site.modulePath, rva, &hash, &condition);
        if (!status)
        {
            break;
        }
        if (*site.rva != rva || (site.imageSha256 && hash && site.imageSha256 != hash))
        {
            status = {ProjectError::InvalidArgument, 0, "executionGroupDefinitionSiteMismatch"};
            break; // 手工输入不能覆盖冻结RVA或弱化已保存的映像散列。
        }
        if (hash)
        {
            site.imageSha256 = std::move(hash); // 未手填散列时继承冻结定义，不从磁盘同名文件补值。
        }
        status = PrepareSampleImageCondition(condition, site.conditionSource, site.condition);
        if (!status)
        {
            break; // 仍在目录副本中准备，任何失败都不附加本批新成员。
        }
    }
    if (!status)
    {
        return false;
    }
    sites = std::move(resolved);
    return true;
}

// 输入明确追加请求，沿原worker和冻结sample解析；不创建第二writer，也不改写已有成员目录。
native::ExecutionGroupResult ExecutionGroupArchive::AppendMembers(native::OwnedExecutionGroup& group,
    std::vector<native::ExecutionGroupSite> sites, bool explicitlyAuthorized, std::string_view collectionId)
{
    auto current = group.QueryWithoutCondition(); // 不求条件或继续任何已有成员。
    view_.memberSetup.reset();
    if (!explicitlyAuthorized || collectionId != current.collectionId || !native::OwnedExecutionGroup::CanAppendMembers(current))
    {
        return group.AppendMembers(std::move(sites), explicitlyAuthorized, collectionId); // 核心统一返回真实准入拒绝。
    }
    view_.memberSetup.emplace(); // 与初次setup分开，错误不阻塞已有成员保存/清退。
    if (!ResolveSitesForSample(sites, *view_.memberSetup))
    {
        // 没有可提交的完整目录；让原集合保留一份真实拒绝回执，定义失败细节独立留在memberSetup。
        return group.AppendMembers({}, explicitlyAuthorized, collectionId);
    }
    return group.AppendMembers(std::move(sites), explicitlyAuthorized, collectionId);
}

// 输入本次原成员和明确来源请求，输出独立API回执；原调试线程继续持有全部停止责任。
void ExecutionGroupArchive::CaptureApi(native::OwnedExecutionGroup& group,
    const native::ExecutionGroupSessionEntry& displayed, const NativeBoundApiRequest& request,
    const std::atomic_bool& cancel, const NativeBoundApiStartup& onStartup)
{
    auto result = std::make_shared<NativeBoundApiResult>(); // 先公布本次身份，任何拒绝不能沿用上轮成功。
    result->request = request;
    result->sampleId = view_.sampleId;
    result->projectId = view_.projectId;
    view_.api = result;
    view_.apiOwner = displayed.owner;
    view_.apiBefore = {};
    view_.apiAfter = {};
    if (!project_ || !view_.writerHeld || !view_.setup)
    {
        result->rejection = NativeBoundApiRejection::ProjectUnavailable;
        result->admission = {ProjectError::NotOpen, 0, "executionGroupApiProjectRequired"};
        return;
    }
    const auto before = group.QueryWithoutCondition(); // 无条件回读全部成员，不自动释放同伴假条件。
    const auto member = std::find_if(before.members.begin(), before.members.end(), [&](const auto& item) {
        return item.owner == displayed.owner;
    }); // 只认本集合原owner，不从PID草稿或列表首行生成目标。
    if (member == before.members.end() || member->owner.sampleId != view_.sampleId ||
        member->control.pid != displayed.control.pid ||
        member->control.processCreationTime != displayed.control.processCreationTime ||
        !member->control.attached || !displayed.control.attached)
    {
        result->rejection = NativeBoundApiRejection::NativeUnavailable;
        result->admission = {ProjectError::InvalidArgument, 0, "executionGroupApiMemberChanged"};
        return;
    }
    view_.apiBefore = member->control;
    result->nativeTarget = {member->control.pid, member->control.processCreationTime, member->control.attached};
    const bool sourceIsMember = std::any_of(before.members.begin(), before.members.end(), [&](const auto& item) {
        return item.site.pid == request.sourcePid;
    }); // 任一集合目标都不能成为本次装载来源，避免在另一个已暂停owner内等待Agent。
    if (sourceIsMember)
    {
        result->rejection = NativeBoundApiRejection::SourceIsNativeTarget;
        result->admission = {ProjectError::InvalidArgument, 0, "executionGroupApiSourceIsMember"};
        return;
    }
    result->admission = {ProjectError::IoError, 0, "executionGroupApiCaptureInterrupted"}; // 异常路径不留下默认成功诊断。
    *result = CaptureNativeBoundApi(*project_, view_.sampleId, request, result->nativeTarget, cancel, onStartup);
    const auto after = group.QueryWithoutCondition(); // API清退后只回读，不Continue、不保存成员执行事件。
    const auto current = std::find_if(after.members.begin(), after.members.end(), [&](const auto& item) {
        return item.owner == displayed.owner;
    }); // 后置丢失保持空值，不能把前置快照当作仍持有的确认。
    if (current != after.members.end())
    {
        view_.apiAfter = current->control;
    }
}

// 输入唯一原成员与明确范围，输出逐页读取；失败不降级为实时读取，也不沿用旧成功字节。
void ExecutionGroupArchive::CaptureMemory(native::OwnedExecutionGroup& group,
    const native::ExecutionGroupSessionEntry& displayed, std::uint64_t address, std::uint64_t bytes,
    const std::atomic_bool* cancel)
{
    namespace memory = ks::cli::action_analyze::memory;
    memory::Plan plan; // 身份来自冻结原成员，不从当前输入框或候选对象补值。
    plan.sampleId = displayed.owner.sampleId;
    plan.target = {displayed.owner.sessionId, displayed.owner.epoch, displayed.control.processInstanceId,
        displayed.control.pid, displayed.control.processCreationTime}; // machine/boot沿用原生页的会话局部标签。
    plan.range = {address, bytes};
    plan.rounds = 2; // 单次CaptureSelectedMemory只实际读取首轮；复用共享Plan的最小轮数约定。
    plan.authorizedOwnedProcess = true; // 仅原集合Start明确授权过的精确成员能通过后续owner核对。
    auto rejected = std::make_shared<native::ProcessMemorySnapshotResult>(); // 参数失败也公布此次范围，旧结果不冒充新读取。
    rejected->request.plan = plan;
    rejected->request.source = native::ProcessMemorySource::HeldEvent;
    view_.memory.capture = rejected;
    view_.memory.duplicate = false;
    if (!address || !bytes || bytes > 64ull * 4096 || address > UINT64_MAX - bytes || !ProjectStorage::NewId(plan.trackingEpoch))
    {
        rejected->stage = "execution-group-memory-invalid-range";
        rejected->win32Error = ERROR_INVALID_PARAMETER;
        return;
    }
    view_.memory.capture = std::make_shared<const native::ProcessMemorySnapshotResult>(group.CaptureMemory(displayed, plan, cancel));
}

// 输入当前实际读取对象，独立追加raw-memory；先占段状态，异常或坏尾不能被后续保存越过。
void ExecutionGroupArchive::SaveMemory(const std::shared_ptr<const native::ProcessMemorySnapshotResult>& displayed)
{
    auto& memory = view_.memory; // 保存状态和读取状态分别保留，后续Capture不覆盖首次追加失败。
    memory.duplicate = false;
    if (memory.appendBlocked)
    {
        return;
    }
    if (!project_ || !view_.writerHeld || !displayed || displayed != memory.capture ||
        displayed->request.plan.sampleId != view_.sampleId || !displayed->snapshot ||
        !displayed->snapshot->round || displayed->snapshot->round->pages.empty())
    {
        memory.status = {ProjectError::InvalidArgument, 0, "executionGroupMemorySnapshotRequired"};
        return;
    }
    if (displayed == memory.savedSource)
    {
        memory.duplicate = true;
        memory.status = {};
        return;
    }
    if (memoryOrdinal_ == UINT64_MAX)
    {
        memory.status = {ProjectError::LimitExceeded, 0, "executionGroupMemoryOrdinalLimit"};
        return;
    }
    memory.savedSource = displayed;
    memory.receipt.emplace();
    memory.status = {ProjectError::IoError, 0, "executionGroupMemoryWriteInterrupted"};
    memory.appendBlocked = true; // 即使写入器抛异常，catch发布时也能看见真实未决追加。
    memory.status = WriteProcessGroupMemorySnapshot(*project_, view_.sampleId, memoryOrdinal_, memoryPrevious_, *displayed, *memory.receipt);
    if (memory.status && memory.receipt->verified && memory.receipt->raw.flushed)
    {
        memoryPrevious_ = memory.receipt->raw.flushed->lastSequence;
        ++memoryOrdinal_;
        memory.appendBlocked = false;
    }
}

// 输入唯一成员的完整显示停点，保存原执行事件；内存读取本身不产生执行证据。
void ExecutionGroupArchive::Save(native::OwnedExecutionGroup& group,
    const native::ExecutionGroupSessionEntry& displayed)
{
    SaveEvent(group, displayed, view_.saved, view_.duplicate); // 手动保存不被后台自动批次覆盖。
}

// 输入正常条件处理后的集合快照，只写当前新执行事件；不在Capture/Memory的无条件读侧隐式调用。
void ExecutionGroupArchive::Observe(native::OwnedExecutionGroup& group, const native::ExecutionGroupResult& observed)
{
    if (!view_.autoSaveExecution || view_.autoSaveStopped || !view_.writerHeld || !view_.setup)
    {
        return;
    }
    try
    {
        bool startedBatch = false; // 无新事件时保留上次自动回执，而不是每250ms抹成空成功。
        for (const auto& member : observed.members)
        {
            const auto execution = native::NativeExecutionFromOwnedStop(member.control); // ManualPause/写停点没有执行证据。
            if (!execution || journal_.contains({execution->event.backendInstanceId, execution->event.serial}))
            {
                continue;
            }
            if (!startedBatch)
            {
                view_.automatic.clear();
                startedBatch = true;
            }
            view_.automatic.emplace_back(); // 先保留发布位置，写入异常也不会仅显示旧成功。
            bool duplicate = false; // 共用保存器二次回读时仍以完整事件核验，不依赖上次GUI投影。
            view_.autoSaveStopped = true; // 仅当本次完整成功后复位；异常及存储失败不循环重试。
            SaveEvent(group, {member.owner, member.control}, view_.automatic.back(), duplicate);
            view_.automaticStatus = view_.automatic.back()->status;
            if (!view_.automaticStatus)
            {
                return; // 不Continue、不重建writer；原成员的停止和恢复责任保持原样。
            }
            view_.autoSaveStopped = false;
        }
    }
    catch (...)
    {
        view_.autoSaveStopped = true;
        view_.automaticStatus = {ProjectError::IoError, 0, "executionGroupAutomaticSaveInterrupted"};
        // 可选归档失败不传播成主会话Close；写入器已有appendBlocked及firstFailure仍保留原坏尾责任。
    }
}

// 手动与自动保存共用原写入链和原生核验；published指向各自回执，不相互覆盖最近操作。
void ExecutionGroupArchive::SaveEvent(native::OwnedExecutionGroup& group,
    const native::ExecutionGroupSessionEntry& displayed,
    std::shared_ptr<const ExecutionGroupExecutionSave>& published, bool& duplicate)
{
    auto saved = std::make_shared<ExecutionGroupExecutionSave>(); // 本次所有失败路径均有独立回执。
    saved->owner = displayed.owner;
    published = saved;
    duplicate = false;
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
        published = found->second;
        duplicate = true;
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
    ++view_.verifiedExecutionSaves;
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
