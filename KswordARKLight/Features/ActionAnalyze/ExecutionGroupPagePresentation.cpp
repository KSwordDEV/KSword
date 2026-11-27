#include "ExecutionGroupPageState.h"
#include "NativeSessionApiFields.h"
#include "ApiTransferPresentation.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/MenuUtil.h"
#include <algorithm>
#include <cwchar>

namespace Ksword::Features::ActionAnalyze::execution_group_page {
namespace {
constexpr std::array<const wchar_t*, 11> kTitles{L"PID", L"创建 FILETIME", L"执行站点", L"原生阶段", L"清退确认",
    L"后端身份", L"停止组", L"事件序号", L"状态修订", L"原生错误", L"最近操作回执"};

std::wstring Hex(std::uint64_t value)
{
    wchar_t buffer[24]{};
    swprintf_s(buffer, L"0x%llX", static_cast<unsigned long long>(value));
    return buffer;
}

bool Eligible(const execution_native::ExecutionGroupMember& member)
{
    // 步进需要精确Held；条件资格复用原group，不能把允许混合的运行成员当作步进停点。
    return execution_native::OwnedExecutionGroup::Matches(member.control, member.control) &&
        execution_native::OwnedExecutionGroup::CanContinueMember(member);
}

struct BatchEligibility {
    bool validPause = true;
    bool validContinue = true;
    bool needsPause = false;
    bool needsContinue = false;

    void Include(const execution_native::ExecutionGroupMember& member)
    {
        using Group = execution_native::OwnedExecutionGroup;
        validPause = Group::CanPauseMember(member) && validPause;
        validContinue = Group::CanContinueMember(member) && validContinue;
        needsPause = needsPause || Group::MatchesPause(member.control, member.control);
        needsContinue = needsContinue || Group::Matches(member.control, member.control);
    }

    bool Pause() const { return validPause && needsPause; }
    bool Continue() const { return validContinue && needsContinue; }
};

std::wstring OutcomeText(const execution_native::ExecutionGroupOutcome& outcome)
{
    const std::string_view disposition = outcome.disposition ? outcome.disposition : "";
    const auto label = disposition == "already-held" ? L"已持有停点" :
        disposition == "already-running" ? L"已运行" : L"动作回执";
    auto text = std::wstring(label) + L" / " + Widen(disposition) +
        (outcome.actionAttempted ? L" / 已调用原会话" : L" / 未调用原会话");
    if (outcome.actionAttempted) {
        text += L" / " + Widen(outcome.control.stage ? outcome.control.stage : "") +
            L" / Win32=" + std::to_wstring(outcome.control.win32Error);
    }
    return text;
}

std::wstring MemberOutcomeText(const execution_native::ExecutionGroupResult& result,
    const execution_native::ExecutionGroupMember& member)
{
    if (!result.operation) return L"尚无操作";
    const auto& operation = *result.operation;
    const auto found = std::find_if(operation.outcomes.begin(), operation.outcomes.end(), [&](const auto& outcome) {
        return outcome.pid == member.site.pid && outcome.creationFileTime == member.site.creationFileTime;
    });
    if (found != operation.outcomes.end()) return OutcomeText(*found);
    return operation.admitted ? L"本次未请求此成员" : L"整批前置核对未通过";
}

std::array<std::wstring, 11> Cells(const execution_native::ExecutionGroupResult& result,
    const execution_native::ExecutionGroupMember& member)
{
    const auto& state = member.control;
    return {std::to_wstring(member.site.pid), std::to_wstring(member.site.creationFileTime), SiteText(member.site),
        state.breakpoint && state.breakpoint->waitingForModule ? L"等待模块加载" :
            Widen(state.stage ? state.stage : ""), state.clean ? L"已结清" : L"未结清",
        Widen(member.owner.backendInstanceId), state.group ? Widen(state.group->groupId) : L"无",
        state.responsibility ? std::to_wstring(state.responsibility->event.serial) : L"无",
        state.group ? std::to_wstring(state.group->stateRevision) : L"无", std::to_wstring(state.win32Error),
        MemberOutcomeText(result, member)};
}

void NativeText(std::wstring& text, const execution_native::NativeControlResult& state)
{
    text += L"\r\n原生阶段=" + Widen(state.stage ? state.stage : "") + L"  status=" + std::to_wstring(static_cast<int>(state.status)) +
        L"  Win32=" + std::to_wstring(state.win32Error) + L"  attached=" + std::to_wstring(state.attached) + L"  clean=" + std::to_wstring(state.clean);
    text += L"\r\nPID=" + std::to_wstring(state.pid) + L" creation=" + std::to_wstring(state.processCreationTime) +
        L" processInstance=" + Widen(state.processInstanceId);
    text += state.stopReason == execution_native::NativeStopReason::ManualPause ? L"\r\n停止原因=主动暂停（跳过命中条件，可继续，不可步进）" :
        state.stopReason == execution_native::NativeStopReason::NativeStep ? L"\r\n停止原因=原生步进" :
        state.stopReason == execution_native::NativeStopReason::Breakpoint ? L"\r\n停止原因=断点命中" : L"\r\n停止原因=无";
    if (state.responsibility) {
        const auto& stop = *state.responsibility;
        text += L"\r\nstopId=" + Widen(stop.stopId) + L" groupId=" + Widen(stop.groupId) +
            L" event=" + Widen(stop.event.backendInstanceId) + L"/" + std::to_wstring(stop.event.serial) +
            L" eventState=" + std::to_wstring(static_cast<int>(stop.state)) + L" origin=" + Widen(stop.actualEventThread.threadId);
    }
    if (state.group) {
        const auto& group = *state.group;
        text += L"\r\nsample=" + Widen(group.sampleId) + L" session=" + Widen(group.sessionId) + L" epoch=" + Widen(group.epoch) +
            L"\r\nstateRevision=" + std::to_wstring(group.stateRevision) + L" membershipRevision=" + std::to_wstring(group.membershipRevision) +
            L" membershipSHA256=" + Widen(group.membershipSha256) + L" historical=" + std::to_wstring(group.historical);
        for (const auto& member : group.members)
            text += L"\r\n  thread=" + Widen(member.threadId) + L" state=" + std::to_wstring(static_cast<int>(member.state)) +
                L" evidence=" + std::to_wstring(static_cast<int>(member.evidence)) + L" stop=" + (member.stopId ? Widen(*member.stopId) : L"无");
    }
    if (state.pending) {
        const auto& pending = *state.pending;
        text += L"\r\npending event=" + Widen(pending.event.backendInstanceId) + L"/" + std::to_wstring(pending.event.serial) +
            L" pid=" + std::to_wstring(pending.pid) + L" tid=" + std::to_wstring(pending.tid) +
            L" code=" + std::to_wstring(pending.eventCode) + L" indeterminate=" + std::to_wstring(pending.continuationIndeterminate);
    }
    for (const auto& thread : state.frozenThreads)
        text += L"\r\n冻结线程=" + Widen(thread.identity.threadId) + L" process=" + Widen(thread.identity.processInstanceId) +
            L" TID=" + std::to_wstring(thread.tid) + L" creation=" + std::to_wstring(thread.creationTime);
    if (state.breakpoint) {
        const auto& binding = *state.breakpoint;
        text += binding.waitingForModule ? L"\r\n等待模块加载；设点成功前没有执行覆盖。" : L""; // 与原实际绑定字段共用详情文档。
        text += L"\r\n实际绑定 request=" + Widen(binding.requestId) + L" state=" + std::to_wstring(static_cast<int>(binding.state)) +
            L" stage=" + Widen(binding.stage ? binding.stage : "") + L" Win32=" + std::to_wstring(binding.win32Error) +
            L"\r\nmoduleBase=" + Hex(binding.moduleBase) + L" address=" + Hex(binding.address) + L" RVA=" + Hex(binding.rva) +
            L" rangeBytes=" + std::to_wstring(binding.rangeBytes) + L" enrolledThreads=" + std::to_wstring(binding.enrolledThreads);
        // 实际散列只取原生control的成功核验值，不以用户输入或磁盘路径查询替代。
        text += L"\r\n实际装载文件 SHA256=" + (binding.imageSha256 ? Widen(*binding.imageSha256) : L"无实际测量值");
        std::uint64_t totalRangeBytes = 0;
        bool totalValid = true; // 汇总只在uint64可表示时显示，不能因解除页数额度而回绕。
        for (const auto& range : binding.executionRanges) {
            text += L"\r\n成功NX范围 base=" + Hex(range.base) + L" bytes=" + std::to_wstring(range.bytes) +
                L" pages=" + std::to_wstring(range.bytes / 4096) + L" allocationBase=" + Hex(range.allocationBase);
            if (range.bytes > UINT64_MAX - totalRangeBytes) totalValid = false;
            else totalRangeBytes += range.bytes;
        }
        if (!binding.executionRanges.empty())
        {
            text += L"\r\n已纳入范围合计=" + (totalValid ? std::to_wstring(totalRangeBytes) + L" 字节 / " +
                std::to_wstring(totalRangeBytes / 4096) + L" 页" : std::wstring(L"不可用")); // 与CLI/Qt相同，汇总实际成功目录。
        }
    }
    if (state.executionRange) {
        const auto& range = *state.executionRange;
        const auto& stop = range.request.stop;
        text += L"\r\n追加NX范围回执 stage=" + Widen(range.stage ? range.stage : "") +
            L" Win32=" + std::to_wstring(range.win32Error) + L" added=" + std::to_wstring(range.added) +
            L" rollbackComplete=" + std::to_wstring(range.rollbackComplete) +
            L"\r\n请求范围 address=" + Hex(range.request.address) + L" bytes=" + std::to_wstring(range.request.bytes) +
            L"\r\n范围事务 request=" + Widen(stop.requestId) + L" group=" + Widen(stop.groupId) + L" stop=" + Widen(stop.stopId) +
            L"\r\n原事件=" + Widen(stop.event.backendInstanceId) + L"/" + std::to_wstring(stop.event.serial) +
            L" 请求状态修订=" + std::to_wstring(stop.expectedStateRevision) + L" 核验状态修订=" + std::to_wstring(range.stateRevision) +
            L"\r\n原owner sample=" + Widen(stop.owner.sampleId) + L" session=" + Widen(stop.owner.sessionId) +
            L" epoch=" + Widen(stop.owner.epoch) + L" backend=" + Widen(stop.owner.backendInstanceId);
    }
    if (state.breakpointHit) text += L"\r\n真实命中地址=" + Hex(state.breakpointHit->address);
    if (state.armedPause) {
        const auto& pause = *state.armedPause;
        text += L"\r\n主动暂停 request=" + Widen(pause.request.requestId) + L" state=" + std::to_wstring(static_cast<int>(pause.state)) +
            L" stage=" + Widen(pause.stage ? pause.stage : "") + L" Win32=" + std::to_wstring(pause.win32Error) +
            L" group=" + (pause.groupId ? Widen(*pause.groupId) : L"尚无停点组");
    }
    if (state.step) {
        const auto& step = *state.step;
        text += L"\r\n步进 stage=" + Widen(step.stage ? step.stage : "") + L" Win32=" + std::to_wstring(step.win32Error) +
            L" state=" + std::to_wstring(static_cast<int>(step.state)) + L" restored=" + std::to_wstring(step.resourcesRestored) +
            L"\r\nstep request=" + Widen(step.request.release.requestId) + L" backend=" + Widen(step.request.release.owner.backendInstanceId) +
            L" event=" + std::to_wstring(step.request.release.event.serial) + L" thread=" + Widen(step.request.thread.threadId) +
            L" startIP=" + Hex(step.startIp) + L" startSP=" + Hex(step.startSp);
    }
    if (state.registers) {
        // 成员详情直接消费共用冻结字段目录；不再只投影三个寄存器。
        for (const auto& field : execution_native::NativeStopRegisterFields) {
            std::wstring label(field.name, field.name + std::char_traits<char>::length(field.name));
            for (auto& character : label) {
                if (character >= L'a' && character <= L'z') character -= L'a' - L'A';
            }
            text += L"\r\n" + label + L"=" + Hex((*state.registers).*(field.value));
        }
    }
    if (state.releaseRequestId) text += L"\r\ncontinue request=" + Widen(*state.releaseRequestId);
    if (state.firstRecoveryFailure) text += L"\r\n首次未决恢复=" + Widen(state.firstRecoveryFailure->stage ? state.firstRecoveryFailure->stage : "") +
        L" Win32=" + std::to_wstring(state.firstRecoveryFailure->win32Error);
}
}

std::wstring InputText(HWND control)
{
    const int length = ::GetWindowTextLengthW(control);
    std::wstring value(static_cast<std::size_t>(length) + 1, L'\0');
    const int read = ::GetWindowTextW(control, value.data(), length + 1);
    value.resize(static_cast<std::size_t>((std::max)(0, read)));
    return value;
}

std::wstring Widen(std::string_view text)
{
    if (text.empty()) return {};
    const int count = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!count) return L"[无效UTF-8]";
    std::wstring value(count, L'\0');
    ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), value.data(), count);
    return value;
}

// 输入冻结站点，返回列表和草稿选择器的紧凑文本；期望散列不是原生测量结果。
std::wstring SiteText(const execution_native::ExecutionGroupSite& site)
{
    if (site.address) return L"私有 " + Hex(site.address) + (site.rangeBytes ? L" / " + std::to_wstring(site.rangeBytes) + L" 字节NX范围" : L" / 单地址");
    auto text = site.modulePath + (site.rva ? L" + " + Hex(*site.rva) : L" ! " + Widen(site.exactExport)); // 路径和站点保持原身份。
    if (site.imageSha256)
    {
        text += L" / 期望 SHA256 " + Widen(site.imageSha256->substr(0, 12)) + L"…"; // 列表简写，完整值在同源正文保留。
    }
    return text;
}

std::wstring GroupStateText(execution_native::ExecutionGroupState state)
{
    using State = execution_native::ExecutionGroupState;
    switch (state) {
    case State::Idle: return L"未启动";
    case State::Active: return L"采集中";
    case State::HeldPartial: return L"部分成员持有停点";
    case State::HeldComplete: return L"全部成员各自持有停点";
    case State::PartialFailure: return L"部分失败，成功成员仍保留";
    case State::RecoveryRequired: return L"恢复责任未结清";
    case State::Closing: return L"清退中";
    case State::Closed: return L"已关闭";
    }
    return L"未知状态";
}

std::vector<int> SelectedRows(const Page& page)
{
    std::vector<int> rows;
    for (int row = ListView_GetNextItem(page.members, -1, LVNI_SELECTED); row >= 0;
        row = ListView_GetNextItem(page.members, row, LVNI_SELECTED))
        if (static_cast<std::size_t>(row) < page.shown.result.members.size()) rows.push_back(row);
    return rows;
}

void RebuildColumns(Page& page)
{
    Ui::ScopedListViewRedrawLock lock(page.members);
    Ui::ClearListViewColumns(page.members);
    page.columns.clear();
    page.displayedRows.clear();
    for (std::size_t i = 0; i < page.visibleColumns.size(); ++i) {
        if (!page.visibleColumns[i]) continue;
        Ui::AddListViewColumn(page.members, {static_cast<int>(page.columns.size()), Ui::Scale(i == 2 ? 260 : i == 0 ? 72 : 160), LVCFMT_LEFT, kTitles[i]});
        page.columns.push_back(static_cast<int>(i));
    }
}

void HeaderMenu(Page& page, POINT point)
{
    // 复用共享菜单构造/追踪入口，列身份固定，不借用当前显示位置。
    std::vector<Ui::PopupMenuItem> items;
    for (std::size_t i = 0; i < kTitles.size(); ++i)
        items.push_back({static_cast<UINT>(59000 + i), kTitles[i], false, i != 0, page.visibleColumns[i]});
    const auto selected = Ui::ShowPopupMenuForCommand(page.hwnd, point, items);
    if (selected > 59000 && selected < 59000 + kTitles.size()) {
        const auto index = selected - 59000;
        page.visibleColumns[index] = !page.visibleColumns[index];
        ::SendMessageW(page.preset, CB_SETCURSEL, 2, 0);
        RebuildColumns(page);
        Refresh(page);
    }
}

void RefreshText(Page& page)
{
    const auto& result = page.shown.result;
    std::wstring text = L"执行集合=" + Widen(result.collectionId) + L"\r\n来源=本端原生执行所有者逐成员回读；非原子冻结\r\n采样 FILETIME=" +
        std::to_wstring(page.shown.observedFileTime) + L"\r\n状态=" + GroupStateText(result.state) + L" clean=" + std::to_wstring(result.clean);
    if (page.shown.archive.configured || !page.shown.archive.setup)
    {
        // 原规范JSON同时供CLI响应与Qt字段文档使用；Light复制/导出只消费这一份完整正文。
        const auto archive = Ksword::ActionAnalyze::DescribeExecutionGroupArchive(page.shown.archive); // 不访问当前PID或路径草稿。
        text += L"\r\n\r\n[执行观察归档]\r\n" + Widen(Ksword::Evidence::WriteJson(archive));
    }
    text += L"\r\n命中联停策略=" + std::wstring(result.holdPeersOnHit ? L"已启用" : L"未启用");
    if (result.peerHold)
    {
        const auto& hold = *result.peerHold; // 原触发者与每项初始Pause回执；当前是否Held仍读上方成员状态。
        text += L"\r\n\r\n[最近命中联停回执]\r\n触发owner=" + Widen(hold.triggerOwner.backendInstanceId) +
            L"\r\n触发事件=" + Widen(hold.triggerEvent.backendInstanceId) + L"/" + std::to_wstring(hold.triggerEvent.serial);
        for (const auto& outcome : hold.outcomes)
        {
            text += L"\r\n成员=" + std::to_wstring(outcome.pid) + L"/" + std::to_wstring(outcome.creationFileTime) +
                L" 分类=" + Widen(outcome.disposition) + L" 实际调用=" + std::to_wstring(outcome.actionAttempted);
            NativeText(text, outcome.control); // 保留每项原生错误、暂停责任和绑定，不以第一项代表全集。
        }
    }
    if (page.shown.archive.api)
    {
        text += FormatLightNativeSessionApi(*page.shown.archive.api); // 完整正文沿用现有源/覆盖/归档/清退字段。
        text += L"\r\nAPI目标原owner=" + Widen(page.shown.archive.apiOwner.backendInstanceId);
        text += L"\r\n[API采集前原成员]";
        NativeText(text, page.shown.archive.apiBefore);
        text += L"\r\n[API采集后原成员]";
        NativeText(text, page.shown.archive.apiAfter); // 后置回读缺失保持空值，不以旧Held冒充。
    }
    if (page.shown.archive.memory.capture || page.shown.archive.memory.receipt)
    {
        text += L"\r\n[停点内存读取与归档]\r\n" + Widen(Ksword::Evidence::WriteJson(
            Ksword::ActionAnalyze::DescribeExecutionGroupMemory(page.shown.archive.memory))); // 同源完整正文参与查找、复制和导出。
    }
    if (page.shown.apiStartup)
    {
        text += FormatLightNativeSessionApiProgress(*page.shown.apiStartup); // 同一250ms展示周期读取在途进度。
    }
    if (page.shown.apiCheckpoint && page.shown.apiRules)
    {
        // 复用原字段正文和完整复制/导出路径，不增加第二个日志窗口或现场读盘。
        const auto& checkpoint = *page.shown.apiCheckpoint; // 该通知实际完成发布的段，不是当前收包计数。
        const auto& rules = *page.shown.apiRules; // 最近命中可来自较早段，始终显示它自己的原段号。
        text += L"\r\n\r\n[API已提交运行进度]\r\n采样=" + Widen(checkpoint.sampleId) +
            L"\r\n归档坐标=raw/" + std::to_wstring(checkpoint.ordinal) + L" #" +
            std::to_wstring(checkpoint.rawEnd.lastSequence) + L"\r\n原包序号=" +
            std::to_wstring(checkpoint.lastSourceSequence) + L"\r\n段SHA256=" + Widen(checkpoint.rawSha256);
        text += L"\r\n终段=" + std::wstring(checkpoint.finalSegment ? L"是" : L"否") +
            L"\r\n规则命中=" + std::to_wstring(rules.matchedRows) +
            L"\r\n规则内容SHA256=" + Widen(rules.sourceSha256);
        if (rules.failed)
        {
            text += L"\r\n规则派生失败=" + Widen(rules.configError); // 原包已发布与派生失败分别呈现。
        }
        if (rules.latest)
        {
            const auto& match = *rules.latest; // 原规则回执，不在UI线程重新求值或升级行为结论。
            text += L"\r\n最近命中=raw/" + std::to_wstring(rules.latestSegment) + L" #" +
                std::to_wstring(match.rawSequence) + L" · " + Widen(match.api) + L" · " + Widen(match.ruleId);
            if (match.behavior)
            {
                text += L"\r\n行为释义=" + Widen(match.behavior->summaryZh) +
                    L"\r\n规则证据=" + Widen(match.behavior->evidence);
            }
        }
    }
    const bool fields = ::SendMessageW(page.textMode, CB_GETCURSEL, 0, 0) == 0;
    if (fields) {
        // 草稿选择与右侧活成员分开显示；用户编辑输入不会改写此处已经保存的站点来源。
        const auto draftIndex = ::SendMessageW(page.draft, CB_GETCURSEL, 0, 0); // 只定位保存草稿，不授活控制权。
        if (draftIndex >= 0 && static_cast<std::size_t>(draftIndex) < page.sites.size())
        {
            const auto& site = page.sites[static_cast<std::size_t>(draftIndex)]; // 完整期望值随保存项保留。
            text += L"\r\n\r\n选中草稿=" + std::to_wstring(site.pid) + L" / " + std::to_wstring(site.creationFileTime) +
                L"\r\n草稿执行站点=" + SiteText(site) +
                L"\r\n草稿期望映像 SHA256=" + (site.imageSha256 ? Widen(*site.imageSha256) : L"未指定");
            text += L"\r\n冻结断点定义ID=" + Widen(site.definitionId); // 原草稿引用，不冒充已激活。
            for (const auto& origin : page.evidenceDrafts) // 手动改站点后不再显示不匹配的旧来源。
            {
                if (site.pid == origin.pid && site.creationFileTime == origin.creationFileTime &&
                    site.address == origin.address && site.rangeBytes == origin.rangeBytes)
                {
                    text += L"\r\n[草稿证据来源]\r\nprojectId=" + Widen(origin.projectId) +
                        L"\r\nsampleId=" + Widen(origin.sampleId) + L"\r\nraw-native=" + std::to_wstring(origin.nativeOrdinal) +
                        L"\r\nSHA256=" + Widen(origin.nativeSha256); // 同一正文供搜索、复制和导出。
                }
            }
        }
        if (page.shown.apiTransfers)
        {
            // 原文本详情保留搜索、复制与导出；共享格式化器不把候选升级为执行证据。
            text += ApiTransferProgress(*page.shown.apiTransfers);
        }
        const auto selected = SelectedRows(page);
        if (selected.empty()) text += L"\r\n请选择成员查看冻结站点、原生身份和完整票据。";
        for (const auto index : selected) {
            const auto& member = result.members[static_cast<std::size_t>(index)];
            text += L"\r\n\r\n成员 " + std::to_wstring(member.site.pid) + L" / " + std::to_wstring(member.site.creationFileTime) +
                L"\r\n冻结站点=" + SiteText(member.site) + L"\r\n冻结条件=" + member.site.conditionSource +
                L"\r\nowner sample=" + Widen(member.owner.sampleId) + L" session=" + Widen(member.owner.sessionId) +
                L" epoch=" + Widen(member.owner.epoch) + L" backend=" + Widen(member.owner.backendInstanceId) +
                L"\r\n初次附加受理=" + std::to_wstring(member.attachAccepted) + L" 条件 true/false/unknown=" +
                std::to_wstring(member.condition.trueCount) + L"/" + std::to_wstring(member.condition.falseCount) + L"/" + std::to_wstring(member.condition.unknownCount);
            text += L"\r\n最近操作回执=" + MemberOutcomeText(result, member);
            text += L"\r\n冻结期望映像 SHA256=" + (member.site.imageSha256 ? Widen(*member.site.imageSha256) : L"未指定"); // 与实际装载文件测量值分列。
            text += L"\r\n已核对冻结断点定义ID=" + Widen(member.site.definitionId); // 原worker启动前已核对的sample引用。
            if (member.condition.last) {
                const auto& last = *member.condition.last;
                text += L"\r\n最近条件 event=" + std::to_wstring(last.event.serial) + L" group=" + Widen(last.groupId) +
                    L" revision=" + std::to_wstring(last.stateRevision) + L" truth=" + std::to_wstring(static_cast<int>(last.evaluation.truth)) +
                    L" releaseError=" + std::to_wstring(last.releaseError);
            }
            NativeText(text, member.control);
        }
    } else if (result.operation) {
        const auto& operation = *result.operation;
        text += L"\r\n\r\n最近显式操作（不被Query替换） action=" + std::to_wstring(static_cast<int>(operation.action)) +
            L" admitted=" + std::to_wstring(operation.admitted) + L"\r\nstage=" + Widen(operation.stage ? operation.stage : "") +
            L" Win32=" + std::to_wstring(operation.win32Error) + L"\r\n操作回执 FILETIME=" + std::to_wstring(page.shown.operationFileTime);
        for (const auto& outcome : operation.outcomes) {
            text += L"\r\n\r\n请求成员 " + std::to_wstring(outcome.pid) + L" / " + std::to_wstring(outcome.creationFileTime) +
                L"\r\n成员操作结果=" + OutcomeText(outcome);
            const auto member = std::find_if(result.members.begin(), result.members.end(), [&](const auto& item)
            {
                return item.site.pid == outcome.pid && item.site.creationFileTime == outcome.creationFileTime;
            }); // 使用原集合冻结站点，不用下一轮草稿替换本次结果的期望散列。
            if (member != result.members.end())
            {
                text += L"\r\n冻结期望映像 SHA256=" + (member->site.imageSha256 ? Widen(*member->site.imageSha256) : L"未指定");
            }
            if (!outcome.actionAttempted)
                text += L"\r\n以下为原会话回读快照；本成员未产生新的暂停或释放回执。";
            NativeText(text, outcome.control);
        }
    } else text += L"\r\n尚无显式操作回执。";
    if (text != page.document) {
        DWORD selectionStart = 0, selectionEnd = 0;
        ::SendMessageW(page.text, EM_GETSEL, reinterpret_cast<WPARAM>(&selectionStart), reinterpret_cast<LPARAM>(&selectionEnd));
        const auto firstLine = ::SendMessageW(page.text, EM_GETFIRSTVISIBLELINE, 0, 0);
        page.document = std::move(text);
        ::SetWindowTextW(page.text, page.document.c_str());
        ::SendMessageW(page.text, EM_SETSEL, selectionStart, selectionEnd);
        ::SendMessageW(page.text, EM_LINESCROLL, 0, firstLine - ::SendMessageW(page.text, EM_GETFIRSTVISIBLELINE, 0, 0));
    }
}

void Refresh(Page& page)
{
    const auto selected = SelectedRows(page);
    const int focused = ListView_GetNextItem(page.members, -1, LVNI_FOCUSED);
    std::optional<std::pair<std::uint32_t, std::uint64_t>> focusedIdentity;
    if (focused >= 0 && static_cast<std::size_t>(focused) < page.shown.result.members.size()) {
        const auto& site = page.shown.result.members[static_cast<std::size_t>(focused)].site;
        focusedIdentity = std::pair{site.pid, site.creationFileTime};
    }
    std::vector<std::pair<std::uint32_t, std::uint64_t>> identities;
    for (const auto row : selected) {
        const auto& site = page.shown.result.members[static_cast<std::size_t>(row)].site;
        identities.emplace_back(site.pid, site.creationFileTime);
    }
    page.shown = page.session.ReadStatus(); // 只复制worker快照，不查询系统或原生owner。
    std::vector<std::vector<std::wstring>> nextRows;
    for (const auto& member : page.shown.result.members) {
        const auto cells = Cells(page.shown.result, member);
        std::vector<std::wstring> visible;
        for (const auto column : page.columns) visible.push_back(cells[static_cast<std::size_t>(column)]);
        nextRows.push_back(std::move(visible));
    }
    // 相同状态不重建清单，保留键盘多选锚点及列宽，不按固定成员数裁剪。
    if (nextRows != page.displayedRows) {
        page.publishing = true;
        Ui::ScopedListViewRedrawLock lock(page.members);
        Ui::ClearListViewRows(page.members);
        int row = 0;
        for (const auto& member : page.shown.result.members) {
            Ui::InsertListViewTextRow(page.members, nextRows[static_cast<std::size_t>(row)]);
            if (std::find(identities.begin(), identities.end(), std::pair{member.site.pid, member.site.creationFileTime}) != identities.end())
                ListView_SetItemState(page.members, row, LVIS_SELECTED, LVIS_SELECTED);
            if (focusedIdentity && *focusedIdentity == std::pair{member.site.pid, member.site.creationFileTime})
                ListView_SetItemState(page.members, row, LVIS_FOCUSED, LVIS_FOCUSED);
            ++row;
        }
        page.displayedRows = std::move(nextRows);
        page.publishing = false;
    }
    if (page.shown.identityRevision != page.identityRevision) {
        page.identityRevision = page.shown.identityRevision;
        page.identityPid = page.shown.identityPid;
        page.identityCreation = page.shown.identityCreation;
        if (page.identityPid) {
            const auto message = L"回读 PID=" + std::to_wstring(page.identityPid) + L" creation=" + std::to_wstring(page.identityCreation) +
                L" Win32=" + std::to_wstring(page.shown.identityError);
            ::SetWindowTextW(page.identity, message.c_str());
            // 不把返回较晚的身份覆盖到另一个PID或用户已填写的创建时间。
            if (page.identityCreation && InputText(page.inputs[Pid]) == std::to_wstring(page.identityPid) && InputText(page.inputs[Creation]).empty())
                ::SetWindowTextW(page.inputs[Creation], std::to_wstring(page.identityCreation).c_str());
            Layout(page); // 身份回执按实际换行高度排版，保留参数滚动责任。
        }
    }
    const bool ready = page.shown.active && !page.shown.busy && !page.retiring;
    const bool controls = ready && !page.shown.closing;
    const bool autoSave = ::SendMessageW(page.autoSaveExecution, BM_GETCHECK, 0, 0) == BST_CHECKED; // Start前的自动归档草稿。
    const bool openProject = ::SendMessageW(page.openProject, BM_GETCHECK, 0, 0) == BST_CHECKED; // 显式已有项目模式，不能猜测路径存在性。
    const bool directoryMissing = InputText(page.projectDirectory).empty(); // 草稿目录为空时不允许依赖项目的启动。
    const bool archiveReady = !(autoSave || openProject) || !directoryMissing; // 与原worker附加前的Prepare约束一致。
    const auto rows = SelectedRows(page);
    BatchEligibility all, subset;
    for (const auto& member : page.shown.result.members) all.Include(member);
    for (const auto row : rows) subset.Include(page.shown.result.members[static_cast<std::size_t>(row)]);
    ::EnableWindow(page.start, controls && page.shown.canStart && archiveReady && !page.sites.empty() &&
        ::SendMessageW(page.authorized, BM_GETCHECK, 0, 0) == BST_CHECKED);
    ::EnableWindow(page.appendMembers, controls && execution_native::OwnedExecutionGroup::CanAppendMembers(page.shown.result) &&
        ::SendMessageW(page.authorized, BM_GETCHECK, 0, 0) == BST_CHECKED); // 原核心资格，失败清退时不扩张责任。
    ::EnableWindow(page.identify, controls);
    ::EnableWindow(page.projectDirectory, controls && page.shown.canStart); // 活writer不跟随路径草稿变化。
    ::EnableWindow(page.openProject, controls && page.shown.canStart);
    ::EnableWindow(page.holdPeersOnHit, controls && page.shown.canStart); // 运行中只显示Start冻结的策略。
    ::EnableWindow(page.autoSaveExecution, controls && page.shown.canStart); // 后续参数编辑不得热改自动保存。
    ::EnableWindow(page.query, !page.retiring && (!page.shown.active || (ready && !page.shown.canStart)));
    const auto queryTitle = page.shown.active ? L"刷新原集合" : L"重试后台会话";
    if (InputText(page.query) != queryTitle) ::SetWindowTextW(page.query, queryTitle);
    ::EnableWindow(page.continueAll, controls && all.Continue());
    ::EnableWindow(page.continueSelected, controls && subset.Continue());
    ::EnableWindow(page.pauseAll, controls && all.Pause());
    ::EnableWindow(page.pauseSelected, controls && subset.Pause());
    const auto* state = rows.size() == 1 ? &page.shown.result.members[static_cast<std::size_t>(rows.front())].control : nullptr;
    ::EnableWindow(page.addRange, controls && state && execution_native::OwnedExecutionGroup::CanAddRangeMember(
        page.shown.result.members[static_cast<std::size_t>(rows.front())]));
    for (const auto button : {page.stepInto, page.stepOver, page.stepOut})
        ::EnableWindow(button, controls && state && Eligible(page.shown.result.members[static_cast<std::size_t>(rows.front())]) &&
            state->stopReason != execution_native::NativeStopReason::ManualPause);
    ::EnableWindow(page.cancelStep, controls && state && state->step && state->step->state == execution_native::NativeStepState::Running);
    ::EnableWindow(page.saveExecution, controls && state && page.shown.archive.writerHeld &&
        execution_native::NativeExecutionFromOwnedStop(*state).has_value()); // 不借用Continue资格伪造执行证据。
    const bool apiAllowed = controls && state && page.shown.archive.writerHeld && state->attached; // 不要求目标继续或命中条件通过。
    ::EnableWindow(page.captureApi, apiAllowed);
    const bool memoryAllowed = controls && state && execution_native::OwnedExecutionGroup::Matches(*state, *state); // 条件不通过也可只读原停点。
    ::EnableWindow(page.readMemory, memoryAllowed);
    for (const auto input : page.memoryInputs)
    {
        ::EnableWindow(input, controls); // 范围是待执行草稿，不跟随后来选区重写旧结果。
    }
    const auto& memory = page.shown.archive.memory; // 保存资格取实际读取及本轮writer，与当前选择分开。
    ::EnableWindow(page.saveMemory, controls && page.shown.archive.writerHeld && !memory.appendBlocked &&
        memory.capture && memory.capture->snapshot && memory.capture->snapshot->round &&
        !memory.capture->snapshot->round->pages.empty());
    for (const auto input : page.apiInputs)
    {
        ::EnableWindow(input, apiAllowed); // 草稿编辑不改变已经开始的采集身份。
    }
    ::EnableWindow(page.close, page.shown.active && !page.shown.closedClean);
    auto status = GroupStateText(page.shown.result.state) + L" / 成员 " + std::to_wstring(page.shown.result.members.size()) +
        L" / 草稿 " + std::to_wstring(page.sites.size()) + (page.shown.busy ? L" / 后台处理中" : L"") +
        (page.shown.closing ? L" / 清退未结清，可再次清退" : L"");
    if (!page.error.empty()) status += L"\r\n" + page.error;
    if (page.shown.canStart && !archiveReady)
    {
        // 明确禁用原因，不把尚未执行的归档配置错误呈现为目标控制失败。
        status += autoSave ? L"\r\n自动保存执行观察需要项目目录。" : L"\r\n打开项目并新建采样需要项目目录。";
    }
    if (!page.shown.diagnostic.empty()) status += L"\r\n" + page.shown.diagnostic;
    if (!page.shown.archive.setup || (page.shown.archive.saved && !page.shown.archive.saved->status))
    {
        const auto& failure = !page.shown.archive.setup ? page.shown.archive.setup : page.shown.archive.saved->status; // 存储诊断与控制结果分列。
        status += L"\r\n执行观察归档 / " + Widen(failure.detail) + L" / Win32 " + std::to_wstring(failure.nativeError);
    }
    if (page.shown.archive.memberSetup && !*page.shown.archive.memberSetup)
    {
        const auto& failure = *page.shown.archive.memberSetup; // 与旧成员保存失败分开，不释放旧writer。
        status += L"\r\n追加表单目标到本轮集合 / " + Widen(failure.detail) + L" / Win32 " + std::to_wstring(failure.nativeError);
    }
    if (page.shown.archive.autoSaveStopped)
    {
        status += L"\r\n自动保存已停止；原控制状态不变，请查看归档回执。";
    }
    if (InputText(page.status) != status) ::SetWindowTextW(page.status, status.c_str());
    RefreshText(page);
}
}
