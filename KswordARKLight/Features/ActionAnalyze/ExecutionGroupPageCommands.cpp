#include "ExecutionGroupPageState.h"
#include "NativeSessionApiFields.h"
#include "../../../KswordCLI/ActionAnalyze/Control/NativeBreakpointImageIdentity.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"
#include "../../Ui/ExportUtil.h"
#include "../../../shared/evidence/NumericTextParse.h"
#include <algorithm>
#include <cwchar>
#include <limits>

namespace Ksword::Features::ActionAnalyze::execution_group_page {
namespace {
bool Number(HWND control, std::uint64_t& value, int radix, bool optional = false)
{
    auto text = InputText(control);
    if (text.empty()) { value = 0; return optional; }
    std::string ascii;
    for (const auto ch : text) {
        if (ch > 127) return false;
        ascii.push_back(static_cast<char>(ch));
    }
    auto input = ksword::evidence::NumericTextTrim(ascii);
    if (radix == 16 && input.size() > 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) input.remove_prefix(2);
    return ksword::evidence::NumericTextParseDigits(input, radix, value);
}

// 输入当前表单，成功输出冻结站点；失败在页面保留原因，不访问目标或模块文件。
bool Site(Page& page, execution_native::ExecutionGroupSite& site)
{
    std::uint64_t pid = 0, rva = 0;
    if (!Number(page.inputs[Pid], pid, 10) || !pid || pid > UINT32_MAX ||
        !Number(page.inputs[Creation], site.creationFileTime, 10) || !site.creationFileTime) {
        page.error = L"PID及创建FILETIME必须是非零十进制数；可先读取PID身份。";
        return false;
    }
    site.pid = static_cast<std::uint32_t>(pid);
    site.modulePath = InputText(page.inputs[Module]);
    const auto exportName = InputText(page.inputs[Export]);
    if (!exportName.empty()) {
        const int bytes = ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, exportName.data(),
            static_cast<int>(exportName.size()), nullptr, 0, nullptr, nullptr);
        if (!bytes || bytes > 4096) { page.error = L"导出名不是有效的UTF-8文本或超过4096字节。"; return false; }
        site.exactExport.resize(bytes);
        ::WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, exportName.data(), static_cast<int>(exportName.size()),
            site.exactExport.data(), bytes, nullptr, nullptr);
    }
    const bool hasRva = !InputText(page.inputs[Rva]).empty();
    if (hasRva) {
        if (!Number(page.inputs[Rva], rva, 16) || !rva || rva > UINT32_MAX) {
            page.error = L"RVA必须是非零32位十六进制数，并由操作者确认是指令边界。";
            return false;
        }
        site.rva = static_cast<std::uint32_t>(rva);
    }
    const bool hasAddress = !InputText(page.inputs[Address]).empty();
    if (!Number(page.inputs[Address], site.address, 16, true) || (hasAddress && !site.address) ||
        !Number(page.inputs[Range], site.rangeBytes, 10, true)) {
        page.error = L"私有地址按十六进制、范围字节数按十进制填写；私有地址不得为0。";
        return false;
    }
    if (site.address) {
        if (!site.modulePath.empty() || hasRva || !exportName.empty() ||
            (site.rangeBytes && (site.address % 4096 || site.rangeBytes % 4096 ||
                site.address > UINT64_MAX - site.rangeBytes))) {
            page.error = L"私有站点不能同时填写模块。范围非零时起点及长度须4KiB对齐，地址范围不能溢出。";
            return false;
        }
    } else {
        const auto& path = site.modulePath;
        if (site.rangeBytes || path.size() <= 3 || path.size() > 32767 ||
            !((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) ||
            path[1] != L':' || path[2] != L'\\' || path.find_first_of(L"\"\r\n") != std::wstring::npos ||
            hasRva == !site.exactExport.empty()) {
            page.error = L"模块站点需填写绝对DOS路径及RVA或精确导出名之一；不能填写私有范围。";
            return false;
        }
    }
    // 模块站点才冻结用户期望散列；私有地址保留隐藏输入，但不会将其放入请求。
    if (!site.address)
    {
        if (site.rva)
        {
            const auto definition = InputText(page.inputs[DefinitionId]); // 模块RVA严格保留定义原文，不允许窄化Unicode。
            for (const auto character : definition)
            {
                if (character > 127)
                {
                    page.error = L"冻结断点定义ID须为空或规范UUID，且只适用于模块RVA。";
                    return false;
                }
                site.definitionId.push_back(static_cast<char>(character));
            }
            if (!site.definitionId.empty() && !Ksword::ActionAnalyze::ProjectStorage::IsUuid(site.definitionId))
            {
                page.error = L"冻结断点定义ID须为空或规范UUID，且只适用于模块RVA。";
                return false;
            }
        }
        const auto expected = InputText(page.inputs[ImageSha256]); // 保留原文，不自动去空白或转小写。
        if (!expected.empty())
        {
            std::string hash; // 仅将完整ASCII原文转为后端文本，拒绝宽字符截断造成的伪合法散列。
            for (const auto character : expected)
            {
                if (character > 127)
                {
                    page.error = L"映像SHA256须为空或64位小写十六进制。";
                    return false;
                }
                hash.push_back(static_cast<char>(character));
            }
            if (!execution_native::ValidNativeImageSha256(hash))
            {
                page.error = L"映像SHA256须为空或64位小写十六进制。";
                return false;
            }
            site.imageSha256 = hash; // 只传约束，由原生owner核验实际装载文件；不按路径重新打开。
        }
    }
    site.conditionSource = InputText(page.inputs[Condition]);
    const auto prepared = execution_native::PrepareDataWatchCondition(site.conditionSource);
    if (prepared.diagnostic) {
        page.error = L"条件未通过编译：" + Widen(prepared.diagnostic);
        return false;
    }
    site.condition = prepared.predicate;
    return true;
}

// 显式载入所选保存草稿，包括模块期望散列；私有站点保留已有隐藏输入，不读取control测量值。
void LoadDraft(Page& page)
{
    const auto index = ::SendMessageW(page.draft, CB_GETCURSEL, 0, 0);
    if (index < 0 || static_cast<std::size_t>(index) >= page.sites.size()) return;
    const auto& site = page.sites[static_cast<std::size_t>(index)];
    const auto hex = [](std::uint64_t value) {
        wchar_t buffer[24]{};
        swprintf_s(buffer, L"0x%llX", static_cast<unsigned long long>(value));
        return std::wstring(buffer);
    };
    const std::array<std::wstring, FieldCount> values{std::to_wstring(site.pid), std::to_wstring(site.creationFileTime),
        site.modulePath, site.rva ? hex(*site.rva) : L"", Widen(site.exactExport), site.address ? hex(site.address) : L"",
        site.rangeBytes ? std::to_wstring(site.rangeBytes) : L"", site.conditionSource,
        site.address ? InputText(page.inputs[ImageSha256]) : site.imageSha256 ? Widen(*site.imageSha256) : L"",
        site.rva ? Widen(site.definitionId) : InputText(page.inputs[DefinitionId])};
    for (std::size_t i = 0; i < FieldCount; ++i) ::SetWindowTextW(page.inputs[i], values[i].c_str());
    // 载入只改变编辑草稿；旧集合来源和成员选择保持不变。
    Layout(page); // 地址机制决定散列行显隐；私有站点载入不抹去之前隐藏的散列输入。
}
}

void RefreshDraft(Page& page)
{
    const auto previous = ::SendMessageW(page.draft, CB_GETCURSEL, 0, 0);
    ::SendMessageW(page.draft, CB_RESETCONTENT, 0, 0);
    for (const auto& site : page.sites) {
        const auto title = std::to_wstring(site.pid) + L" / " + std::to_wstring(site.creationFileTime) + L" / " + SiteText(site);
        ::SendMessageW(page.draft, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(title.c_str()));
    }
    if (!page.sites.empty()) ::SendMessageW(page.draft, CB_SETCURSEL,
        previous < 0 ? 0 : (std::min)(static_cast<std::size_t>(previous), page.sites.size() - 1), 0);
}

void Command(Page& page, int id)
{
    page.error.clear();
    if (id == kAppendMembers)
    {
        // 输入当前表单与授权，输出按值请求；待追加目录与下一轮草稿列表分别保留。
        execution_native::ExecutionGroupSite site; // Site统一准备完整身份、站点与条件。
        if (page.retiring || page.shown.busy || page.shown.closing ||
            !execution_native::OwnedExecutionGroup::CanAppendMembers(page.shown.result) ||
            ::SendMessageW(page.authorized, BM_GETCHECK, 0, 0) != BST_CHECKED)
        {
            page.error = L"本轮集合不可追加，请确认授权、剩余名额及原集合状态。";
        }
        else if (Site(page, site))
        {
            LightExecutionGroupRequest request; // 不使用当前成员行号或下一轮草稿作为新目标。
            request.command = LightExecutionGroupCommand::AppendMembers;
            request.sites.push_back(std::move(site));
            request.authorized = true;
            request.collectionId = page.shown.result.collectionId;
            if (!page.session.Submit(std::move(request)))
            {
                page.error = L"原集合未受理追加请求，请刷新后重试。";
            }
        }
    }
    else if (id == kAdd) {
        execution_native::ExecutionGroupSite site;
        if (Site(page, site)) {
            if (std::any_of(page.sites.begin(), page.sites.end(), [&](const auto& prior) { return prior.pid == site.pid; }))
                page.error = L"每个PID只能登记一个站点；请先移除原草稿项。";
            else { page.sites.push_back(std::move(site)); RefreshDraft(page); }
        }
    } else if (id == kRemove) {
        const auto index = ::SendMessageW(page.draft, CB_GETCURSEL, 0, 0);
        if (index >= 0 && static_cast<std::size_t>(index) < page.sites.size()) {
            page.sites.erase(page.sites.begin() + index);
            RefreshDraft(page);
        }
    } else if (id == kLoadDraft) {
        LoadDraft(page);
    } else if (id == kClose) {
        page.session.Close();
    } else if (id == kCopy) {
        const auto document = page.document;
        if (!Ui::CopyTextToClipboard(page.hwnd, document, L"执行集合正文")) page.error = L"正文复制失败。";
    } else if (id == kExportText) {
        std::wstring error;
        const auto document = page.document; // 文件选择器可泵送计时消息，导出必须保留点击时的同一正文。
        const auto result = Ui::SaveUtf8TextFileWithDialog(page.hwnd, L"execution-group.txt", L"导出执行集合正文",
            L"文本文件 (*.txt)\0*.txt\0", L"txt", document, &error);
        if (result == Ui::SaveTextFileResult::Failed) page.error = L"正文导出失败：" + error;
    } else if (id == kQuery && !page.shown.active) {
        const auto error = page.session.StartWorker();
        if (error) page.error = L"执行集合后台会话未启动，Win32=" + std::to_wstring(error);
    } else {
        LightExecutionGroupRequest request;
        bool submit = true;
        if (id == kStart) {
            request.command = LightExecutionGroupCommand::Start;
            request.sites = page.sites; // 冻结全部身份、站点、原条件及编译谓词。
            request.authorized = ::SendMessageW(page.authorized, BM_GETCHECK, 0, 0) == BST_CHECKED;
            request.projectDirectory = InputText(page.projectDirectory); // 原样冻结目录，不随稍后编辑重定向写入。
            request.openExistingProject = ::SendMessageW(page.openProject, BM_GETCHECK, 0, 0) == BST_CHECKED;
            request.holdPeersOnHit = ::SendMessageW(page.holdPeersOnHit, BM_GETCHECK, 0, 0) == BST_CHECKED; // 冻结本轮策略。
            request.autoSaveExecution = ::SendMessageW(page.autoSaveExecution, BM_GETCHECK, 0, 0) == BST_CHECKED; // 与项目目录一同冻结。
            if (request.sites.empty() || !request.authorized) {
                page.error = L"请加入明确站点并明确授权整个集合。";
                submit = false;
            }
            else if (request.autoSaveExecution && request.projectDirectory.empty())
            {
                page.error = L"自动保存执行观察需要项目目录。";
                submit = false; // 保留全部草稿，不创建worker项目或附加任何目标。
            }
        } else if (id == kReadMemory) {
            request.command = LightExecutionGroupCommand::ReadMemory;
            const auto rows = SelectedRows(page); // 原读取只绑定点击时唯一完整Held成员。
            if (rows.size() != 1 || !execution_native::OwnedExecutionGroup::Matches(
                page.shown.result.members[static_cast<std::size_t>(rows.front())].control,
                page.shown.result.members[static_cast<std::size_t>(rows.front())].control))
            {
                page.error = L"读取内存须单选持有完整停点的原成员，允许主动暂停。";
                submit = false;
            }
            else if (!Number(page.memoryInputs[0], request.address, 16) || !request.address ||
                !Number(page.memoryInputs[1], request.bytes, 10) || !request.bytes ||
                request.bytes > 64ull * 4096 || request.address > UINT64_MAX - request.bytes)
            {
                page.error = L"内存起点须为非零十六进制地址，长度为1–262144十进制字节，且不能溢出。";
                submit = false;
            }
            else
            {
                const auto& member = page.shown.result.members[static_cast<std::size_t>(rows.front())]; // 冻结原owner与完整停点。
                request.sessions.push_back({member.owner, member.control});
            }
        } else if (id == kSaveMemory) {
            request.command = LightExecutionGroupCommand::SaveMemory;
            request.memorySource = page.shown.archive.memory.capture; // 保存来源与当前行分离，后端按原对象核对。
        } else if (id == kCaptureApi) {
            request.command = LightExecutionGroupCommand::CaptureApi;
            const auto rows = SelectedRows(page); // 确认前固定原成员，不能在模态返回后按新选区换目标。
            if (rows.size() != 1 || !page.shown.archive.writerHeld)
            {
                page.error = L"同采样API须配置本轮项目并单选仍附加的原成员。";
                submit = false;
            }
            else
            {
                const auto member = page.shown.result.members[static_cast<std::size_t>(rows.front())]; // 跨模态保留完整纯值。
                const auto collection = page.shown.result.collectionId; // 集合变更后不提交旧确认。
                request.sessions.push_back({member.owner, member.control});
                submit = CollectLightNativeSessionApi(page.hwnd, page.apiInputs[0], page.apiInputs[1], page.apiInputs[2],
                    {member.control.pid, member.control.processCreationTime, member.control.attached}, request.api, page.error);
                if (submit && collection != page.shown.result.collectionId)
                {
                    page.error = L"确认期间集合已变更，请重新选择来源和原成员。";
                    submit = false;
                }
            }
        } else if (id == kSaveExecution) {
            request.command = LightExecutionGroupCommand::SaveExecution;
            const auto rows = SelectedRows(page); // 只保存点击时唯一原成员，不按PID输入或首行选择。
            if (rows.size() != 1 || !page.shown.archive.writerHeld)
            {
                page.error = L"保存须配置本轮项目并单选当前执行停点。";
                submit = false;
            }
            else
            {
                const auto& member = page.shown.result.members[static_cast<std::size_t>(rows.front())]; // 完整原owner和事件快照。
                if (!execution_native::NativeExecutionFromOwnedStop(member.control))
                {
                    page.error = L"当前停点不是执行进入或已完成的单指令事件；主动暂停不能保存为执行观察。";
                    submit = false;
                }
                else
                {
                    request.sessions.push_back({member.owner, member.control});
                }
            }
        } else if (id == kAddRange) {
            request.command = LightExecutionGroupCommand::AddRange;
            const auto rows = SelectedRows(page);
            if (rows.size() != 1 || !execution_native::OwnedExecutionGroup::CanAddRangeMember(
                    page.shown.result.members[static_cast<std::size_t>(rows.front())])) {
                page.error = L"追加范围须单选当前原集合的完整Held NX成员，允许主动暂停；请刷新或重新选择。";
                submit = false;
            } else {
                // 只冻结点击时选中成员的完整control；PID/模块/条件草稿不参与成员定位。
                request.stops.push_back(page.shown.result.members[static_cast<std::size_t>(rows.front())].control);
                if (!Number(page.inputs[Address], request.address, 16) || !request.address ||
                    !Number(page.inputs[Range], request.bytes, 10) || !request.bytes ||
                    request.address % 4096 || request.bytes % 4096 ||
                    request.address > UINT64_MAX - request.bytes) {
                    page.error = L"追加NX范围：起点按十六进制、长度按十进制字节填写；均须非零且4KiB对齐，地址范围不能溢出。";
                    submit = false;
                }
            }
        } else if (id == kIdentify) {
            std::uint64_t pid = 0;
            request.command = LightExecutionGroupCommand::Identify;
            if (!Number(page.inputs[Pid], pid, 10) || !pid || pid > UINT32_MAX) {
                page.error = L"请填写有效的十进制PID。";
                submit = false;
            } else request.identityPid = static_cast<std::uint32_t>(pid);
        } else if (id == kQuery) {
            request.command = LightExecutionGroupCommand::Query;
        } else {
            const auto rows = SelectedRows(page);
            request.all = id == kContinueAll || id == kPauseAll;
            const bool groupAction = id == kPauseAll || id == kPauseSelected || id == kContinueAll || id == kContinueSelected;
            const auto freeze = [&](const execution_native::ExecutionGroupMember& member) {
                if (groupAction) request.sessions.push_back({member.owner, member.control});
                else request.stops.push_back(member.control); // 步进仍只使用选中原成员的完整停点。
            };
            if (request.all) {
                // 固定全集原样提交，包含已达目标及失败成员；由原group整批核对和决定实际动作。
                for (const auto& member : page.shown.result.members) freeze(member);
            } else {
                for (const auto row : rows) freeze(page.shown.result.members[static_cast<std::size_t>(row)]);
            }
            if (groupAction ? request.sessions.empty() : request.stops.empty()) {
                page.error = L"没有可操作的成员，请选择当前集合成员。";
                submit = false;
            }
            if (id == kPauseAll || id == kPauseSelected) request.command = LightExecutionGroupCommand::Pause;
            else if (id == kContinueAll || id == kContinueSelected) request.command = LightExecutionGroupCommand::Continue;
            else {
                if (request.stops.size() != 1) { page.error = L"步进和中止步进必须只选一个原成员。"; submit = false; }
                request.command = id == kCancelStep ? LightExecutionGroupCommand::CancelStep : LightExecutionGroupCommand::Step;
                request.stepMode = id == kStepOut ? execution_native::NativeStepMode::Out :
                    id == kStepOver ? execution_native::NativeStepMode::OverCall : execution_native::NativeStepMode::Into;
            }
        }
        if (submit && !page.session.Submit(std::move(request))) page.error = L"会话忙、正在清退或尚未完成上次清退；草稿和原结果已保留。";
    }
    Refresh(page);
}
}
