#include "ExecutionGroupPageState.h"
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
        text += L"\r\n实际绑定 request=" + Widen(binding.requestId) + L" state=" + std::to_wstring(static_cast<int>(binding.state)) +
            L" stage=" + Widen(binding.stage ? binding.stage : "") + L" Win32=" + std::to_wstring(binding.win32Error) +
            L"\r\nmoduleBase=" + Hex(binding.moduleBase) + L" address=" + Hex(binding.address) + L" RVA=" + Hex(binding.rva) +
            L" rangeBytes=" + std::to_wstring(binding.rangeBytes) + L" enrolledThreads=" + std::to_wstring(binding.enrolledThreads);
        std::uint64_t totalRangeBytes = 0;
        for (const auto& range : binding.executionRanges) {
            text += L"\r\n成功NX范围 base=" + Hex(range.base) + L" bytes=" + std::to_wstring(range.bytes) +
                L" pages=" + std::to_wstring(range.bytes / 4096) + L" allocationBase=" + Hex(range.allocationBase);
            totalRangeBytes += range.bytes;
        }
        if (!binding.executionRanges.empty())
        {
            text += L"\r\n已纳入范围合计=" + std::to_wstring(totalRangeBytes) + L" 字节 / " +
                std::to_wstring(totalRangeBytes / 4096) + L" 页"; // 与CLI/Qt相同，汇总实际成功目录。
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

std::wstring SiteText(const execution_native::ExecutionGroupSite& site)
{
    if (site.address) return L"私有 " + Hex(site.address) + (site.rangeBytes ? L" / " + std::to_wstring(site.rangeBytes) + L" 字节NX范围" : L" / 单地址");
    return site.modulePath + (site.rva ? L" + " + Hex(*site.rva) : L" ! " + Widen(site.exactExport));
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
    const bool fields = ::SendMessageW(page.textMode, CB_GETCURSEL, 0, 0) == 0;
    if (fields) {
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
    // 相同状态不重建清单，保留键盘多选锚点及列宽；成员最多16个。
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
    const auto rows = SelectedRows(page);
    BatchEligibility all, subset;
    for (const auto& member : page.shown.result.members) all.Include(member);
    for (const auto row : rows) subset.Include(page.shown.result.members[static_cast<std::size_t>(row)]);
    ::EnableWindow(page.start, controls && page.shown.canStart && !page.sites.empty() && ::SendMessageW(page.authorized, BM_GETCHECK, 0, 0) == BST_CHECKED);
    ::EnableWindow(page.identify, controls);
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
    ::EnableWindow(page.close, page.shown.active && !page.shown.closedClean);
    auto status = GroupStateText(page.shown.result.state) + L" / 成员 " + std::to_wstring(page.shown.result.members.size()) +
        L" / 草稿 " + std::to_wstring(page.sites.size()) + (page.shown.busy ? L" / 后台处理中" : L"") +
        (page.shown.closing ? L" / 清退未结清，可再次清退" : L"");
    if (!page.error.empty()) status += L"\r\n" + page.error;
    if (!page.shown.diagnostic.empty()) status += L"\r\n" + page.shown.diagnostic;
    if (InputText(page.status) != status) ::SetWindowTextW(page.status, status.c_str());
    RefreshText(page);
}
}
