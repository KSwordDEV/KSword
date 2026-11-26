#include "LightProcessGroupMemory.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <utility>

namespace Ksword::Features::ActionAnalyze {

namespace memory = ks::cli::action_analyze::memory;
namespace process_group_native = ks::cli::action_analyze::control;

namespace {

// 只去除两端空格；不改动文本内部内容，解析保持无符号严格规则。
std::wstring_view TrimSpaces(std::wstring_view text)
{
    while (!text.empty() && text.front() == L' ') text.remove_prefix(1);
    while (!text.empty() && text.back() == L' ') text.remove_suffix(1);
    return text;
}

// 无符号严格解析：hexAllowed 时接受 0x/0X 前缀十六进制、否则只接受十进制。
// 拒绝空文本、非法字符、正负号及 64 位溢出；0 值由调用方按字段给出独立阶段。
std::optional<std::uint64_t> ParseUnsigned64(std::wstring_view text, bool hexAllowed)
{
    text = TrimSpaces(text);
    if (text.empty()) return std::nullopt;
    unsigned base = 10; // 默认十进制；只有明确 0x/0X 前缀才切换十六进制。
    if (hexAllowed && text.size() >= 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
        base = 16;
        text.remove_prefix(2);
        if (text.empty()) return std::nullopt; // "0x" 后必须有至少一位数字。
    }
    std::uint64_t value = 0;
    for (const wchar_t character : text) {
        unsigned digit = 0;
        if (character >= L'0' && character <= L'9') {
            digit = static_cast<unsigned>(character - L'0');
        } else if (base == 16 && character >= L'a' && character <= L'f') {
            digit = static_cast<unsigned>(character - L'a') + 10;
        } else if (base == 16 && character >= L'A' && character <= L'F') {
            digit = static_cast<unsigned>(character - L'A') + 10;
        } else {
            return std::nullopt; // 出现任意非法字符（含正负号、内部空格）即整体拒绝。
        }
        if (value > (std::numeric_limits<std::uint64_t>::max)() / base) return std::nullopt; // 乘法溢出。
        value *= base;
        if (value > (std::numeric_limits<std::uint64_t>::max)() - digit) return std::nullopt; // 加法溢出。
        value += digit;
    }
    return value;
}

// 地址、QPC 等无符号值统一输出为 0x 小写十六进制，与页内其他地址显示一致。
std::wstring ToHex(std::uint64_t value)
{
    static constexpr wchar_t digits[] = L"0123456789abcdef";
    std::wstring text = L"0x";
    if (!value) text.push_back(L'0');
    bool leading = true;
    for (int shift = 60; shift >= 0; shift -= 4) {
        const auto nibble = static_cast<unsigned>((value >> shift) & 15);
        if (nibble || !leading) {
            leading = false;
            text.push_back(digits[nibble]);
        }
    }
    return text;
}

// 采样页状态的稳定文本；与项目归档中的页状态编码一一对应。
const wchar_t* PageStateName(memory::PageStatus status)
{
    using enum memory::PageStatus;
    switch (status) {
    case NotCommitted: return L"未提交";
    case Guarded: return L"保护页";
    case UnsafeReadAttributes: return L"属性读取不安全";
    case NotReadable: return L"不可读";
    case QueryFailed: return L"查询失败";
    case ReadFailed: return L"读取失败";
    case MappingUnstable: return L"映射不稳定";
    case HashFailed: return L"散列失败";
    case Sampled: return L"已采样";
    }
    return L"未知";
}

// 追加一行"字段: 值"；字段文本按行组织，便于共享字段视图逐行解析。
void AppendField(std::wstring& text, std::wstring_view field, const std::wstring& value)
{
    text.append(field);
    text.append(L": ");
    text.append(value);
    text.push_back(L'\n');
}

} // namespace

bool PrepareHeldMemoryRequest(const process_group_native::ProcessGroupResult& group, const process_group_native::ProcessGroupTarget& target,
    std::string_view trackingEpoch, const std::wstring& baseText, const std::wstring& bytesText,
    process_group_native::ProcessMemorySnapshotRequest& out, LightMemoryInputRejection& rejection)
{
    LightMemoryInputRejection failure; // 先按字段优先级收集首个失败，成功才写 out。
    const auto base = ParseUnsigned64(baseText, true); // 起始地址明确 0x 十六进制、否则十进制。
    const auto bytes = ParseUnsigned64(bytesText, false); // 范围字节数只接受十进制。
    if (!base) {
        failure = TrimSpaces(std::wstring_view(baseText)).empty()
            ? LightMemoryInputRejection{LightMemoryInputStage::BaseEmpty, "lightMemoryBaseEmpty"}
            : LightMemoryInputRejection{LightMemoryInputStage::BaseInvalid, "lightMemoryBaseInvalid"};
    } else if (!*base) {
        failure = {LightMemoryInputStage::BaseZero, "lightMemoryBaseZero"};
    }
    if (failure.stage == LightMemoryInputStage::None) {
        if (!bytes) {
            failure = TrimSpaces(std::wstring_view(bytesText)).empty()
                ? LightMemoryInputRejection{LightMemoryInputStage::BytesEmpty, "lightMemoryBytesEmpty"}
                : LightMemoryInputRejection{LightMemoryInputStage::BytesInvalid, "lightMemoryBytesInvalid"};
        } else if (!*bytes) {
            failure = {LightMemoryInputStage::BytesZero, "lightMemoryBytesZero"};
        }
    }
    if (failure.stage == LightMemoryInputStage::None && base && bytes &&
        *bytes > (std::numeric_limits<std::uint64_t>::max)() - *base) {
        failure = {LightMemoryInputStage::RangeOverflow, "lightMemoryRangeOverflow"};
    }
    if (failure.stage == LightMemoryInputStage::None && trackingEpoch.empty()) {
        failure = {LightMemoryInputStage::EpochEmpty, "lightMemoryEpochEmpty"};
    }

    // 目标必须属于当前已配置集合，并持有完整的 HeldComplete 原生停点；历史令牌与图行不算凭据。
    if (failure.stage == LightMemoryInputStage::None) {
        const auto member = std::find_if(group.members.begin(), group.members.end(),
            [&](const process_group_native::ProcessGroupMember& item) { return item.target == target; });
        if (member == group.members.end() || !member->stop || !member->control || !member->control->group ||
            member->control->group->state != process_group_native::GroupState::HeldComplete) {
            failure = {LightMemoryInputStage::MemberNotHeld, "lightMemoryMemberNotHeld"};
        }
    }

    if (failure.stage != LightMemoryInputStage::None) {
        rejection = failure;
        return false;
    }

    // 此处 member 已通过上面的 HeldComplete 核对；重新定位以取得完整令牌与采样身份。
    const auto member = std::find_if(group.members.begin(), group.members.end(),
        [&](const process_group_native::ProcessGroupMember& item) { return item.target == target; });

    process_group_native::ProcessMemorySnapshotRequest request; // 全部字段来自点击时冻结的界面身份。
    request.source = process_group_native::ProcessMemorySource::HeldEvent; // 页面只暴露停点期间只读通道。
    request.stop = *member->stop; // 原样复制完整令牌，不在本端拆改或重放部分字段。
    request.plan.sampleId = member->control->group->sampleId; // 与原生组同一采样，底层再次核对。
    request.plan.trackingEpoch = std::string(trackingEpoch); // 控制者代次；重新打开必须换新代次。
    // machine/boot 为本会话局部标签，仅满足底层标签非空要求，不宣称系统机器或启动身份。
    request.plan.target = {member->control->group->sessionId, member->control->group->epoch,
        member->control->processInstanceId, target.pid, target.creationFileTime};
    request.plan.range = {*base, *bytes}; // 64 页上限由底层按真实页大小复核，这里不新增限制。
    request.plan.rounds = 2; // 共享 Plan 要求至少两轮；单次 CaptureSelectedMemory 只取首轮后 Stop。
    request.plan.authorizedOwnedProcess = true; // 仅配置时明确授权的精确成员可以到达此处。
    rejection = {};
    out = std::move(request);
    return true;
}

std::wstring FormatLightProcessGroupMemory(const process_group_native::ProcessMemorySnapshotResult& read)
{
    std::wstring text;
    const auto& plan = read.request.plan; // 结果保持读取时的精确请求，不借用当前输入草稿。
    AppendField(text, L"目标 PID", std::to_wstring(plan.target.pid));
    AppendField(text, L"创建 FILETIME", std::to_wstring(plan.target.creationFileTime100ns));
    AppendField(text, L"范围起点", ToHex(plan.range.base));
    AppendField(text, L"范围字节数", std::to_wstring(plan.range.length));
    AppendField(text, L"采样 ID", std::wstring(plan.sampleId.begin(), plan.sampleId.end()));
    AppendField(text, L"来源", read.request.source == process_group_native::ProcessMemorySource::HeldEvent
        ? std::wstring(L"HeldEvent（原生停点期间只读采样）") : std::wstring(L"LiveRead"));
    AppendField(text, L"读前停点", read.before
        ? std::wstring(read.before->stopId.begin(), read.before->stopId.end()) : std::wstring(L"无"));
    AppendField(text, L"读后停点", read.after
        ? std::wstring(read.after->stopId.begin(), read.after->stopId.end()) : std::wstring(L"无"));
    AppendField(text, L"读取前后同一停点", read.heldAtBothChecks ? std::wstring(L"是") : std::wstring(L"否"));
    for (const auto* stop : {&read.before, &read.after}) {
        if (!*stop) {
            continue; // 未取得的前后停点不能由当前owner状态补造。
        }
        text += stop == &read.before ? L"读取前完整停点\n" : L"读取后完整停点\n";
        AppendField(text, L"停止组 ID", std::wstring((*stop)->groupId.begin(), (*stop)->groupId.end()));
        AppendField(text, L"后端实例 ID", std::wstring((*stop)->event.backendInstanceId.begin(), (*stop)->event.backendInstanceId.end()));
        AppendField(text, L"原生事件序号", std::to_wstring((*stop)->event.serial));
        AppendField(text, L"状态修订", std::to_wstring((*stop)->stateRevision));
    }
    AppendField(text, L"原生诊断", std::wstring(read.stage, read.stage + std::strlen(read.stage)));
    AppendField(text, L"Win32 错误", std::to_wstring(read.win32Error));
    if (!read.snapshot) return text; // 未取得快照时没有页级证据可投影。

    const auto& snapshot = *read.snapshot; // 成功页原字节仅存在于此快照，失败无补零。
    const auto state = snapshot.status.state; // 投影采样器真实状态，拒绝与成功空结果分别展示。
    const wchar_t* stateText = L"采样尚未开始";
    switch (state) {
    case memory::State::Stopped: stateText = L"采样已停止"; break;
    case memory::State::Rejected: stateText = L"采样被拒绝"; break;
    case memory::State::Failed: stateText = L"采样失败"; break;
    case memory::State::Canceled: stateText = L"采样已取消"; break;
    case memory::State::TargetExited: stateText = L"采样目标已退出"; break;
    case memory::State::Completed: stateText = L"采样已完成"; break;
    case memory::State::Active: stateText = L"采样进行中"; break;
    default: break;
    }
    const auto visited = snapshot.round ? snapshot.round->pages.size() : 0; // 未访问页不能冒充读取失败页。
    AppendField(text, L"采样状态", stateText);
    AppendField(text, L"采样诊断阶段码", std::to_wstring(static_cast<int>(snapshot.status.issue.stage)));
    AppendField(text, L"采样 Win32 错误", std::to_wstring(snapshot.status.issue.win32Error));
    AppendField(text, L"计划页数", std::to_wstring(snapshot.status.plannedPages));
    AppendField(text, L"已访问页数", std::to_wstring(visited));
    AppendField(text, L"未访问页数", std::to_wstring(snapshot.status.plannedPages > visited
        ? snapshot.status.plannedPages - visited : 0));
    if (snapshot.status.issue.ntStatus) {
        AppendField(text, L"NTSTATUS", ToHex(static_cast<std::uint32_t>(*snapshot.status.issue.ntStatus)));
    }
    std::uint64_t capturedBytes = 0; // 真实成功字节总和。
    for (const auto& page : snapshot.captured) capturedBytes += page.bytes.size();
    AppendField(text, L"成功页数", std::to_wstring(snapshot.captured.size()));
    AppendField(text, L"失败页数", std::to_wstring(snapshot.status.unavailablePages));
    AppendField(text, L"实际读取字节数", std::to_wstring(capturedBytes));
    AppendField(text, L"所选范围完整", snapshot.completeRange ? std::wstring(L"是") : std::wstring(L"否"));
    AppendField(text, L"QPC 频率", std::to_wstring(snapshot.status.qpcFrequency));
    if (snapshot.round) {
        AppendField(text, L"采样开始 QPC", std::to_wstring(snapshot.round->beginQpc));
        AppendField(text, L"采样结束 QPC", snapshot.round->endQpc
            ? std::to_wstring(*snapshot.round->endQpc) : std::wstring(L"无"));
        for (const auto& page : snapshot.round->pages) {
            text.append(L"采样页 " + ToHex(page.pageBase) + L"\n");
            AppendField(text, L"  页状态", std::wstring(PageStateName(page.status)));
            AppendField(text, L"  Win32 错误", std::to_wstring(page.issue.win32Error));
            AppendField(text, L"  采样范围字节数", std::to_wstring(page.sampledRange.length));
            if (page.readQpc) {
                AppendField(text, L"  读取 QPC",
                    ToHex(page.readQpc->begin) + L" .. " + ToHex(page.readQpc->end));
            } else {
                AppendField(text, L"  读取 QPC", L"无");
            }
        }
    }
    for (const auto& page : snapshot.captured) {
        // 有界预览：每页最多 256 字节十六进制；完整原字节仍只在快照与归档中。
        const auto preview = std::min(page.bytes.size(), kLightMemoryPreviewBytesPerPage);
        std::wstring hex;
        hex.reserve(preview * 3);
        for (std::size_t index = 0; index < preview; ++index) {
            if (index) hex.push_back(L' ');
            static constexpr wchar_t digits[] = L"0123456789abcdef";
            hex.push_back(digits[page.bytes[index] >> 4]);
            hex.push_back(digits[page.bytes[index] & 15]);
        }
        text.append(L"成功页字节 " + ToHex(page.observation.sampledRange.base) + L"\n");
        AppendField(text, L"  实际读取字节数", std::to_wstring(page.bytes.size()));
        AppendField(text, L"  前 256 字节预览", hex);
    }
    return text;
}

std::wstring FormatLightProcessGroupMemoryArchive(const LightProcessGroupMemoryProjectView& view)
{
    std::wstring text;
    if (!view.projectDirectory.empty() || !view.projectResult) {
        // 无项目且从未失败时不占用篇幅；只要项目存在或有过失败，就保留完整身份与回执。
        AppendField(text, L"项目路径", view.projectDirectory);
        AppendField(text, L"采样 ID", std::wstring(view.sampleId.begin(), view.sampleId.end()));
        const std::string_view detail(view.projectResult.detail); // 原稳定ASCII诊断转换成宽字符展示。
        AppendField(text, L"项目结果", std::wstring(detail.begin(), detail.end()));
        AppendField(text, L"Win32 错误", std::to_wstring(view.projectResult.nativeError));
    }
    if (view.archiveBlocked) {
        // blocked 诊断与失败回执持续保留；新的读取不得抹掉，清退后选新项目才能重新开始。
        text.append(L"原内存段写入或回读失败，已保留现场并停止追加；新读取不清除本诊断。\n");
    }
    if (!view.archive) return text;
    const auto& receipt = *view.archive; // 保存回执与本次读取分别呈现。
    if (view.archiveSource) {
        const auto& plan = view.archiveSource->request.plan; // 归档来源独立于最新读取及当前编辑草稿。
        AppendField(text, L"归档目标 PID", std::to_wstring(plan.target.pid));
        AppendField(text, L"归档创建 FILETIME", std::to_wstring(plan.target.creationFileTime100ns));
        AppendField(text, L"归档范围起点", ToHex(plan.range.base));
        AppendField(text, L"归档范围字节数", std::to_wstring(plan.range.length));
    }
    AppendField(text, L"raw-memory 段号", std::to_wstring(receipt.ordinal));
    AppendField(text, L"实际归档字节数", std::to_wstring(receipt.capturedBytes));
    AppendField(text, L"失败页数", std::to_wstring(receipt.unavailablePages));
    AppendField(text, L"所选范围完整", receipt.completeRange ? std::wstring(L"是") : std::wstring(L"否"));
    AppendField(text, L"同步回读核验", receipt.verified ? std::wstring(L"是") : std::wstring(L"否"));
    for (const auto* boundary : {&receipt.raw.written, &receipt.raw.flushed}) {
        const auto name = boundary == &receipt.raw.written ? L"内存写入坐标" : L"内存刷盘坐标";
        AppendField(text, name, *boundary ? std::to_wstring((*boundary)->byteOffset) + L" / " +
            std::to_wstring((*boundary)->blockOrdinal) + L" / " + std::to_wstring((*boundary)->lastSequence) : L"未取得");
    }
    AppendField(text, L"SHA-256", std::wstring(receipt.sha256.begin(), receipt.sha256.end()));
    return text;
}

project::ProjectResult LightProcessGroupMemoryState::CreateNewProject(const std::wstring& path,
    process_group_native::OwnerIdentity& owner)
{
    project::ProjectResult result; // 项目创建与采样登记的真实回执。
    project::SampleInfo sample; // 成功登记后才有有效 sampleId。
    if (!sampleId_.empty() || (project_ && project_->Info())) {
        return {project::ProjectError::AlreadyOpen, 0, "lightMemoryProjectAlreadyOpen"}; // 不替换仍持租约的原项目。
    }
    projectDirectory_ = path; // Create失败或半创建时保留真实请求目录，便于用户恢复。
    try {
        if (!project_) project_.emplace(); // 惰性构造项目文档；写租约归本状态独占。
        // Create 拒绝已存在项目，绝不抢占其他页面的活动写租约。
        result = project_->Create(path, {"Light process group memory snapshots", "Explicit read-only selected ranges"});
        if (result) result = project_->CreateSample("Selected process memory", sample);
    } catch (...) {
        result = {project::ProjectError::IoError, 0, "lightMemoryProjectException"};
    }
    projectResult_ = result;
    if (!result) {
        if (project_) {
            project_->Close(); // 失败尚未绑定原生组，释放半创建writer但不删除目录。
        }
        return result;
    }
    // 新项目是全新目录与全新 raw-memory lane；旧项目中被 blocked 的失败段保留在原目录，
    // 不迁移、不覆盖，本端从此在新 lane 从段号 1 重新开始。
    archiveBlocked_ = false;
    archive_.reset();
    archiveSource_.reset();
    nextMemoryOrdinal_ = 1;
    previousMemorySequence_ = 0;
    sampleId_ = sample.sampleId;
    projectDirectory_ = path;
    owner.sampleId = sampleId_; // 成功时更新 owner 采样；持有会话据此重建原生组。
    return result;
}

void LightProcessGroupMemoryState::CloseProject()
{
    if (project_) {
        project_->Close(); // 原owner清退后才调用；原sample与归档投影留给页面回看。
    }
}

std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> LightProcessGroupMemoryState::Read(
    process_group_native::OwnedProcessGroup& group, const process_group_native::ProcessMemorySnapshotRequest& request)
{
    process_group_native::ProcessMemorySnapshotResult result; // 请求身份与读前读后证据由底层保留。
    if (request.source != process_group_native::ProcessMemorySource::HeldEvent || !request.stop) {
        // 页面只暴露 HeldEvent 通道；缺完整令牌直接拒绝，不回退 Live 实时读取。
        result.request = request;
        result.stage = "light-process-memory-held-only";
        result.win32Error = ERROR_INVALID_PARAMETER;
    } else {
        // 与 Continue/Close 处于同一串行 owner；完整令牌与 sample 一致性由底层读前读后核对。
        result = process_group_native::CaptureProcessGroupMemory(group, request);
    }
    lastMemory_ = std::make_shared<const process_group_native::ProcessMemorySnapshotResult>(std::move(result));
    if (!archiveBlocked_) {
        archive_.reset(); // blocked 的失败段身份持续保留，新读取不得抹掉。
        archiveSource_.reset();
    }
    return lastMemory_;
}

project::ProjectResult LightProcessGroupMemoryState::Save(
    const std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult>& displayed)
{
    project::ProjectResult result;
    if (archiveBlocked_) {
        return projectResult_; // 首次坏尾回执保留，新点击不覆盖原始拒绝原因。
    }
    if (!project_ || !project_->Info() || !displayed || displayed != lastMemory_ ||
        !lastMemory_->snapshot || !lastMemory_->snapshot->round || lastMemory_->snapshot->round->pages.empty() ||
        lastMemory_->request.plan.sampleId != sampleId_) {
        // 只保存当前显示的同一指针不可变结果；blocked 期间拒绝追加，避免越过坏尾。
        result = {project::ProjectError::InvalidArgument, 0, "lightMemorySnapshotSelection"};
        projectResult_ = result;
        return result;
    }
    project::ProjectMemorySnapshotReceipt receipt; // 只提交完整成功页原字节。
    archiveSource_ = displayed;
    try {
        const auto ordinal = nextMemoryOrdinal_; // 仅前段核验成功后推进段号与前序。
        result = project::WriteProcessGroupMemorySnapshot(*project_, sampleId_, ordinal,
            previousMemorySequence_, *lastMemory_, receipt); // 完整保留source及前后原生停点身份。
    } catch (...) {
        // 写入是否落盘未知时不得覆盖重试或越过尾段；保留失败回执供现场检查。
        archiveBlocked_ = true;
        archive_ = std::move(receipt);
        result = {project::ProjectError::RecoveryRequired, 0, "lightMemorySaveException"};
        projectResult_ = result;
        return result;
    }
    if (result && receipt.verified && receipt.raw.flushed) {
        previousMemorySequence_ = receipt.raw.flushed->lastSequence; // 前序取真实末序号，不是段号。
        ++nextMemoryOrdinal_;
    } else {
        archiveBlocked_ = true; // 失败保留原段并阻止追加；不跳段不覆盖。
    }
    archive_ = std::move(receipt);
    projectResult_ = result;
    return result;
}

LightProcessGroupMemoryProjectView LightProcessGroupMemoryState::ProjectView() const
{
    LightProcessGroupMemoryProjectView view; // 仅复制值；跨线程发布由持有会话负责。
    view.projectDirectory = projectDirectory_;
    view.sampleId = sampleId_;
    view.projectResult = projectResult_;
    view.archive = archive_;
    view.archiveSource = archiveSource_;
    view.archiveBlocked = archiveBlocked_;
    return view;
}

std::shared_ptr<const process_group_native::ProcessMemorySnapshotResult> LightProcessGroupMemoryState::LatestRead() const
{
    return lastMemory_;
}

const std::string& LightProcessGroupMemoryState::SampleId() const
{
    return sampleId_;
}

} // namespace Ksword::Features::ActionAnalyze
