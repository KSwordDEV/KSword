#include "ProcessGroupPage.h"

#include "LightProcessGroupSession.h"
#include "ProcessGroupPageState.h"

#include "../../Ui/Controls.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/TextFindSupport.h"
#include "../../Ui/Theme.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <algorithm>
#include <array>
#include <commctrl.h>
#include <cwchar>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace Ksword::Features::ActionAnalyze {
namespace process_group_page {

constexpr wchar_t kPageClass[] = L"KswordARKLight.ActionAnalyzeProcessGroup";
constexpr UINT_PTR kDisplayTimer = 1;
constexpr UINT kDisplayIntervalMs = 250;

using Ui::Scale;

// 把 ASCII 诊断标识转成宽字符串，原样保留底层阶段名。
std::wstring Widen(std::string_view text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const char character : text) wide.push_back(static_cast<wchar_t>(static_cast<unsigned char>(character)));
    return wide;
}

// 集合状态文字。直接取组层汇总，不用首行成员状态代表全组。
const wchar_t* GroupStateText(group_native::ProcessGroupState state) {
    switch (state) {
    case group_native::ProcessGroupState::Idle: return L"尚未配置集合";
    case group_native::ProcessGroupState::Ready: return L"集合已核验，尚未暂停";
    case group_native::ProcessGroupState::Active: return L"已受理，等待成员回执";
    case group_native::ProcessGroupState::HeldPartial: return L"部分成员持有停点";
    case group_native::ProcessGroupState::HeldComplete: return L"全部成员持有停点";
    case group_native::ProcessGroupState::Closing: return L"正在清退原集合";
    case group_native::ProcessGroupState::Closed: return L"原集合已清退";
    case group_native::ProcessGroupState::RecoveryRequired: return L"原集合仍有恢复责任";
    }
    return L"状态未知";
}

// 成员状态文字。每个成员用自己的原生回执，不用首行代表全组。
const wchar_t* MemberStateText(group_native::NativeControlStatus status) {
    switch (status) {
    case group_native::NativeControlStatus::Idle: return L"尚未附加";
    case group_native::NativeControlStatus::Accepted: return L"已受理，等待停点";
    case group_native::NativeControlStatus::Held: return L"持有原生停点";
    case group_native::NativeControlStatus::Released: return L"已继续，等待脱离";
    case group_native::NativeControlStatus::Detached: return L"已脱离";
    case group_native::NativeControlStatus::Ended: return L"目标已退出";
    case group_native::NativeControlStatus::ClosePending: return L"清退未完成";
    case group_native::NativeControlStatus::Closed: return L"已清退";
    case group_native::NativeControlStatus::Rejected: return L"操作被拒绝";
    case group_native::NativeControlStatus::RecoveryRequired: return L"恢复未确认";
    }
    return L"状态未知";
}

// 票据动作文字。恢复动作使用原继续票据，暂停与继续各自占用新票据。
const wchar_t* ActionText(group_native::ProcessGroupAction action) {
    switch (action) {
    case group_native::ProcessGroupAction::Pause: return L"暂停";
    case group_native::ProcessGroupAction::Continue: return L"继续";
    case group_native::ProcessGroupAction::Recover: return L"恢复";
    }
    return L"未知动作";
}

// 文件时间转本地可读时间；无法转换时保留原始 FILETIME 数值。
std::wstring FormatFileTime(std::uint64_t fileTime) {
    if (!fileTime) return L"未记录";
    FILETIME utc{}; // UTC FILETIME 原始数值。
    utc.dwLowDateTime = static_cast<DWORD>(fileTime & 0xFFFFFFFFULL);
    utc.dwHighDateTime = static_cast<DWORD>(fileTime >> 32);
    FILETIME local{}; SYSTEMTIME system{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &system)) {
        return std::to_wstring(fileTime);
    }
    wchar_t text[32]{};
    swprintf_s(text, L"%04u-%02u-%02u %02u:%02u:%02u", system.wYear, system.wMonth, system.wDay,
        system.wHour, system.wMinute, system.wSecond);
    return text;
}

// 读取十进制无符号数。空输入或非法字符返回 0 并标记失败。
std::uint64_t ReadDecimal(HWND input, bool& ok) {
    wchar_t digits[24]{};
    const int length = ::GetWindowTextW(input, digits, static_cast<int>(std::size(digits)));
    ok = length > 0;
    std::uint64_t value = 0;
    for (int index = 0; index < length; ++index) {
        if (digits[index] < L'0' || digits[index] > L'9') {
            ok = false;
            return 0;
        }
        const auto digit = static_cast<std::uint64_t>(digits[index] - L'0');
        if (value > (UINT64_MAX - digit) / 10) {
            ok = false;
            return 0;
        }
        value = value * 10 + digit;
    }
    ok = ok && value != 0;
    return value;
}

// 列出当前被选中的列表行。多选与单选都按真实选中集合读取。
std::vector<int> SelectedRows(HWND listView) {
    std::vector<int> rows;
    for (int row = ListView_GetNextItem(listView, -1, LVNI_SELECTED); row >= 0;
        row = ListView_GetNextItem(listView, row, LVNI_SELECTED)) {
        rows.push_back(row);
    }
    return rows;
}

// 按当前界面显示的成员回执重建列表行。行与目标身份一一对应，刷新后仍可按行取回。
void RebuildMembers(Page& page) {
    const auto selected = SelectedRows(page.members);
    std::vector<group_native::ProcessGroupTarget> selectedTargets;
    for (const int row : selected) {
        if (row >= 0 && static_cast<std::size_t>(row) < page.rowTargets.size()) {
            selectedTargets.push_back(page.rowTargets[static_cast<std::size_t>(row)]);
        }
    }

    std::vector<std::vector<std::wstring>> rows;
    std::vector<group_native::ProcessGroupTarget> targets;
    const auto& result = page.shown.result;
    if (page.configured && !page.configuring && !result.members.empty()) {
        for (const auto& member : result.members) {
            const std::wstring state = member.control ? MemberStateText(member.control->status) : L"尚未暂停";
            const std::wstring clean = member.clean ? L"是" : L"否";
            rows.push_back({std::to_wstring(member.target.pid), state, clean}); // 清单只留紧凑三列，完整身份和诊断在详情。
            targets.push_back(member.target);
        }
    } else {
        for (const auto& draft : page.draft) {
            rows.push_back({std::to_wstring(draft.pid), page.configured ? L"已冻结，未建立集合" : L"草稿，尚未核验", L""});
            targets.push_back(draft);
        }
    }
    Ui::ReplaceListViewRowsCapped(page.members, rows);
    page.rowTargets = std::move(targets);

    // 重建后按真实身份恢复选中项，刷新不会静默丢掉用户的操作范围。
    for (std::size_t index = 0; index < page.rowTargets.size(); ++index) {
        const auto& target = page.rowTargets[index];
        const bool kept = std::any_of(selectedTargets.begin(), selectedTargets.end(),
            [&](const group_native::ProcessGroupTarget& item) { return item == target; });
        if (kept) {
            ListView_SetItemState(page.members, static_cast<int>(index), LVIS_SELECTED | LVIS_FOCUSED,
                LVIS_SELECTED | LVIS_FOCUSED);
        }
    }
}

// 汇总真实成员状态。部分持有、完整持有与失败分别统计，不用首行代表全组。
struct MemberSummary {
    std::size_t total = 0;
    std::size_t held = 0;    // 持有当前精确停点令牌的成员数。
    std::size_t failed = 0;   // 原生回执报错或被拒绝的成员数。
    std::size_t detached = 0; // 已脱离、已退出或已清退的成员数。
};

MemberSummary Summarize(const group_native::ProcessGroupResult& result) {
    MemberSummary summary; // 逐成员统计，不从首行推断。
    for (const auto& member : result.members) {
        ++summary.total;
        if (member.stop) ++summary.held;
        if (member.control && (member.control->win32Error != 0 ||
            member.control->status == group_native::NativeControlStatus::Rejected ||
            member.control->status == group_native::NativeControlStatus::RecoveryRequired)) {
            ++summary.failed;
        }
        if (member.control && (member.control->status == group_native::NativeControlStatus::Detached ||
            member.control->status == group_native::NativeControlStatus::Ended ||
            member.control->status == group_native::NativeControlStatus::Closed)) {
            ++summary.detached;
        }
    }
    return summary;
}

// 组状态区文字：组层汇总、持有统计、失败统计与最近回读时间分开呈现。
std::wstring BuildStatusText(const Page& page) {
    const auto& result = page.shown.result;
    const auto summary = Summarize(result);
    std::wstring text = L"集合状态：";
    text += GroupStateText(result.state);
    text += L"　成员 " + std::to_wstring(summary.total);
    text += L"　持有停点 " + std::to_wstring(summary.held);
    text += L"　失败 " + std::to_wstring(summary.failed);
    text += L"　已脱离 " + std::to_wstring(summary.detached);
    text += L"　清退确认 " + std::wstring(result.clean ? L"是" : L"否");
    if (result.stage) {
        text += L"　组层诊断 " + Widen(result.stage) + L" / Win32 " + std::to_wstring(result.win32Error);
    }
    text += L"　最近回读 " + FormatFileTime(page.shown.observedFileTime);
    if (page.shown.closing && !page.shown.closedClean) {
        text += L"\r\n原所有者清退未确认，集合责任仍保留，可按原继续票据恢复或再次清退。";
    }
    if (page.shown.failed) {
        text += L"\r\n" + page.shown.diagnostic;
    }
    if (!page.inputError.empty()) {
        text += L"\r\n" + page.inputError;
    }
    return text;
}

// 详情区文字：选中成员的真实诊断与选中票据的逐成员回执。
std::wstring BuildDetailText(const Page& page) {
    std::wstring text;
    const auto selected = SelectedRows(page.members);
    if ((!page.configured || page.configuring || page.shown.result.members.empty()) && !selected.empty()) {
        const int row = selected.front(); // 未执行草稿与旧结果分开，不用新行索引标注旧成员。
        if (row >= 0 && static_cast<std::size_t>(row) < page.draft.size()) {
            const auto& draft = page.draft[static_cast<std::size_t>(row)];
            text += L"输入实例PID " + std::to_wstring(draft.pid) + L" / 创建FILETIME " +
                std::to_wstring(draft.creationFileTime) + L"\r\n尚无已核验集合成员，不具有活控制资格。";
        }
    } else if (!selected.empty()) {
        const int row = selected.front();
        if (row >= 0 && static_cast<std::size_t>(row) < page.shown.result.members.size()) {
            const auto& member = page.shown.result.members[static_cast<std::size_t>(row)];
            text += L"选中成员 PID " + std::to_wstring(member.target.pid);
            text += L"　创建 FILETIME " + std::to_wstring(member.target.creationFileTime) + L"\r\n";
            text += L"成员状态：" + std::wstring(member.control ? MemberStateText(member.control->status) : L"尚未暂停");
            text += L"　清退确认 " + std::wstring(member.clean ? L"是" : L"否");
            if (member.control) {
                text += L"　附加 " + std::wstring(member.control->attached ? L"是" : L"否");
                text += L"　冻结线程 " + std::to_wstring(member.control->frozenThreads.size());
                text += L"\r\n原生诊断 " + Widen(member.control->stage);
                text += L" / Win32 " + std::to_wstring(member.control->win32Error);
                if (member.control->pending) {
                    text += L"　事件序号 " + std::to_wstring(member.control->pending->event.serial);
                    text += L"　账本持有 " + std::wstring(member.control->pending->ledgerOwned ? L"是" : L"否");
                }
            }
            if (member.stop) {
                text += L"\r\n停止组 ID " + Widen(member.stop->groupId);
                text += L"　停点 ID " + Widen(member.stop->stopId);
                text += L"　后端实例 ID " + Widen(member.stop->event.backendInstanceId);
                text += L"　事件序号 " + std::to_wstring(member.stop->event.serial);
                text += L"　状态修订 " + std::to_wstring(member.stop->stateRevision);
            } else {
                text += L"\r\n当前没有可继续的精确停点令牌。";
            }
        }
    } else {
        text += L"未选择成员。选中列表行可查看该成员的真实回执。";
    }

    const int ticket = static_cast<int>(::SendMessageW(page.history, CB_GETCURSEL, 0, 0));
    const auto& history = page.shown.history;
    if (ticket >= 0 && static_cast<std::size_t>(ticket) < history.size()) {
        const auto& operation = history[static_cast<std::size_t>(ticket)];
        text += L"\r\n\r\n历史票据 " + Widen(operation.requestId);
        text += L"　动作 " + std::wstring(ActionText(operation.action));
        text += L"\r\n首次准入：" + std::to_wstring(static_cast<int>(operation.ledgerResult)) +
            L" / " + Widen(operation.stage) + L" / Win32 " + std::to_wstring(operation.win32Error);
        text += L"　成员回执 " + std::to_wstring(operation.outcomes.size()) + L"\r\n";
        for (const auto& outcome : operation.outcomes) {
            text += L"PID " + std::to_wstring(outcome.target.pid) + L"　创建 " +
                std::to_wstring(outcome.target.creationFileTime) + L"　";
            text += Widen(outcome.control.stage) + L" / Win32 " + std::to_wstring(outcome.control.win32Error) + L"\r\n";
        }
    }
    if (page.shown.lastCommandResult) {
        const auto& last = *page.shown.lastCommandResult; // Duplicate顶层不替代原operation准入结果。
        text += L"\r\n\r\n最近显式操作：" + Widen(last.stage) + L" / Win32 " +
            std::to_wstring(last.win32Error) + L" / ledger " + std::to_wstring(static_cast<int>(last.ledgerResult));
        if (last.operation) {
            text += L"\r\n原票据准入：" + Widen(last.operation->requestId) + L" / " +
                Widen(last.operation->stage) + L" / Win32 " + std::to_wstring(last.operation->win32Error) +
                L" / ledger " + std::to_wstring(static_cast<int>(last.operation->ledgerResult));
        }
    }
    text += L"\r\n" + FormatLightProcessGroupMemoryArchive(page.shown.memoryProject);
    if (page.shown.memory) text += L"\r\n" + FormatLightProcessGroupMemory(*page.shown.memory);
    return text;
}

// 重建历史票据下拉框。保留用户当前选择的票据，选择本身不产生任何原生动作。
void RebuildHistory(Page& page) {
    const auto old = ::SendMessageW(page.history, CB_GETCURSEL, 0, 0); // 不能把消息常量当作索引。
    std::wstring keep;
    if (old >= 0) {
        const auto length = ::SendMessageW(page.history, CB_GETLBTEXTLEN, old, 0);
        if (length >= 0) {
            keep.resize(static_cast<std::size_t>(length) + 1);
            ::SendMessageW(page.history, CB_GETLBTEXT, old, reinterpret_cast<LPARAM>(keep.data()));
            keep.resize(static_cast<std::size_t>(length));
        }
    }
    ::SendMessageW(page.history, CB_RESETCONTENT, 0, 0);
    for (const auto& operation : page.shown.history) {
        const std::wstring label = Widen(operation.requestId) + L" · " + ActionText(operation.action);
        ::SendMessageW(page.history, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
    }
    if (!keep.empty()) {
        const auto index = static_cast<int>(::SendMessageW(page.history, CB_FINDSTRINGEXACT, -1,
            reinterpret_cast<LPARAM>(keep.c_str())));
        if (index >= 0) ::SendMessageW(page.history, CB_SETCURSEL, static_cast<WPARAM>(index), 0);
    }
    if (::SendMessageW(page.history, CB_GETCURSEL, 0, 0) < 0 && !page.shown.history.empty()) {
        ::SendMessageW(page.history, CB_SETCURSEL, static_cast<WPARAM>(page.shown.history.size() - 1), 0);
    }
}

// 身份读取结果的文字：路径、真实创建时间、来源与读取时间。
std::wstring BuildIdentityText(const Page& page) {
    const auto& identity = page.shown.identity;
    if (!identity) {
        return L"尚未读取身份。输入 PID 后点击“读取身份”，系统会回读真实创建时间与映像路径。";
    }
    std::wstring text;
    text += L"路径 " + (identity->imagePath.empty() ? std::wstring(L"未取得") : identity->imagePath) + L"\r\n";
    text += L"真实创建 FILETIME " + std::to_wstring(identity->target.creationFileTime);
    if (identity->expectedCreation) {
        text += L"　草稿填写 " + std::to_wstring(*identity->expectedCreation);
        text += identity->creationMatched ? L"（一致）" : L"（与系统回读不一致）";
    }
    text += L"\r\n来源 本端进程句柄身份回读　读取时间 " + FormatFileTime(identity->observedFileTime);
    if (identity->error) {
        text += L"　Win32 " + std::to_wstring(identity->error);
    }
    return text;
}

// 采集当前草稿身份。PID 必填，创建 FILETIME 可选；缺失时由身份读取补齐。
bool ReadDraftTarget(Page& page, group_native::ProcessGroupTarget& target, std::wstring& error) {
    bool pidOk = false;
    bool creationOk = false;
    const auto pid = ReadDecimal(page.pid, pidOk);
    const auto creation = ReadDecimal(page.creation, creationOk);
    if (!pidOk || pid > 0xFFFFFFFFULL) {
        error = L"请输入有效的十进制 PID。";
        ::SetFocus(page.pid);
        return false;
    }
    target.pid = static_cast<std::uint32_t>(pid);
    target.creationFileTime = creationOk ? creation : 0;
    if (::GetWindowTextLengthW(page.creation) > 0 && !creationOk) {
        error = L"创建 FILETIME 必须是非零十进制数。";
        ::SetFocus(page.creation);
        return false;
    }
    return true;
}

// 按当前回执更新控件状态。按钮可用性由真实资格决定，不由首行推断。
void PublishToolbar(Page& page) {
    if (!page.controlPort || !page.controlSource) return;
    LightNativeControlState state;
    const std::array controls{page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected, page.recover, page.close};
    const auto begin = static_cast<std::size_t>(LightNativeControlAction::PauseAll);
    for (std::size_t index = 0; index < controls.size(); ++index) {
        state.enabled[begin + index] = !page.retiring && ::IsWindowEnabled(controls[index]);
    }
    const auto selected = SelectedRows(page.members);
    state.scope = L"本集合 · 成员 " + std::to_wstring(page.shown.result.members.size()) +
        L" · 原集合页已选 " + std::to_wstring(selected.size());
    if (!page.configured) state.scope += L" · 尚未配置";
    for (const auto& member : page.shown.result.members) {
        state.scope += L"\r\nPID " + std::to_wstring(member.target.pid) + L" · 创建 FILETIME " +
            std::to_wstring(member.target.creationFileTime);
        for (const int row : selected) {
            if (row >= 0 && static_cast<std::size_t>(row) < page.rowTargets.size() &&
                page.rowTargets[static_cast<std::size_t>(row)] == member.target) {
                state.scope += L" · 所选";
                break;
            }
        }
    }
    const auto ticket = ::SendMessageW(page.history, CB_GETCURSEL, 0, 0);
    if (ticket >= 0 && static_cast<std::size_t>(ticket) < page.shown.history.size()) {
        const auto& operation = page.shown.history[static_cast<std::size_t>(ticket)];
        state.scope += L"\r\n原集合页当前票据 " + Widen(operation.requestId) + L" · " + ActionText(operation.action);
    }
    page.controlPort->Publish(page.controlSource, std::move(state));
}

void UpdateControls(Page& page) {
    const auto& result = page.shown.result;
    const auto summary = Summarize(result);
    const auto selected = SelectedRows(page.members);
    const bool busy = page.shown.busy;
    const bool retiring = page.retiring;
    // 冻结后不替换集合身份；只有确认清退后才可以重新配置新集合。
    const bool editable = !page.configured && !page.configuring;

    const auto enable = [&](HWND control, bool value) {
        if (::IsWindowEnabled(control) != static_cast<BOOL>(value)) ::EnableWindow(control, value);
    };
    enable(page.pid, !retiring && editable);
    enable(page.creation, !retiring && editable);
    enable(page.identityButton, !retiring && editable && !busy);
    enable(page.addButton, !retiring && editable && page.draft.size() < group_native::kOwnedProcessGroupLimit);
    enable(page.removeButton, !retiring && editable && !selected.empty());
    enable(page.authorized, !retiring && editable);
    enable(page.configureButton, !retiring && editable && !busy && !page.draft.empty() &&
        ::SendMessageW(page.authorized, BM_GETCHECK, 0, 0) == BST_CHECKED);

    const bool ready = !retiring && !busy && page.configured && !page.shown.failed &&
        !page.shown.closing && !page.shown.closedClean; // 后台状态未知时只保留原恢复、回查与清退入口。
    enable(page.pauseAll, ready && summary.total > 0);
    enable(page.pauseSelected, ready && summary.total > 0 && !selected.empty());
    // 继续需要每个目标都持有当前精确令牌；缺一则整组不提交。
    const auto allHeld = summary.total > 0 && summary.held == summary.total;
    enable(page.continueAll, ready && allHeld);
    enable(page.continueSelected, ready && !selected.empty() && [&] {
        for (const int row : selected) {
            if (row < 0 || static_cast<std::size_t>(row) >= result.members.size()) return false;
            if (!result.members[static_cast<std::size_t>(row)].stop) return false;
        }
        return true;
    }());
    enable(page.refresh, !retiring && !busy && page.configured);
    enable(page.recover, !retiring && !busy && page.configured && !page.shown.closedClean && [&] {
        const int ticket = static_cast<int>(::SendMessageW(page.history, CB_GETCURSEL, 0, 0));
        const auto& history = page.shown.history;
        return ticket >= 0 && static_cast<std::size_t>(ticket) < history.size() &&
            history[static_cast<std::size_t>(ticket)].action == group_native::ProcessGroupAction::Continue;
    }());
    enable(page.close, !retiring && !busy && page.configured && !page.shown.closedClean);
    enable(page.newCollection, !retiring && !busy && page.configured && page.shown.closedClean);
    enable(page.projectDirectory, !retiring && editable);
    enable(page.readMemory, ready && selected.size() == 1 && [&] {
        const int row = selected.front(); // 每次只允许一个当前完整Held成员。
        if (row < 0 || static_cast<std::size_t>(row) >= result.members.size()) return false;
        const auto& member = result.members[static_cast<std::size_t>(row)];
        return member.stop && member.control && member.control->group &&
            member.control->group->state == group_native::GroupState::HeldComplete;
    }());
    const auto& memory = page.shown.memory; // 保存旧结果不要求当前列表仍选中原目标。
    enable(page.saveMemory, ready && !page.shown.memoryProject.sampleId.empty() &&
        !page.shown.memoryProject.archiveBlocked && memory && memory->snapshot && memory->snapshot->round &&
        !memory->snapshot->round->pages.empty());
    enable(page.copyDetails, !page.detailText.empty());
    enable(page.exportDetails, !page.detailText.empty());
    PublishToolbar(page); // 选择变化同样发布，但从不提交原生控制或查询。
}

// 把界面状态投影到控件。文字未变化时不重写，避免无变化刷新。
void Refresh(Page& page) {
    page.shown = page.session.ReadStatus();

    if (page.configuring && !page.shown.busy && (page.shown.failed ||
        page.shown.completedCommand == LightProcessGroupCommand::Configure)) {
        page.configuring = false; // 配置被拒也解开等待态，但原冻结身份须清退后显式新建才替换。
    }
    if (page.shownRevision != page.shown.revision) {
        page.rebuilding = true; // 禁止程序更新列表时的同步通知读取半份行身份。
        RebuildMembers(page);
        RebuildHistory(page);
        page.rebuilding = false;
        page.shownRevision = page.shown.revision;
    }

    const auto identityText = BuildIdentityText(page);
    if (identityText != page.identityText) {
        page.identityText = identityText;
        ::SetWindowTextW(page.identityView, identityText.c_str());
    }
    const auto statusText = BuildStatusText(page);
    if (statusText != page.statusText) {
        page.statusText = statusText;
        ::SetWindowTextW(page.status, statusText.c_str());
    }
    const auto detail = BuildDetailText(page);
    if (detail != page.detailText) {
        page.detailText = detail;
        ::SetWindowTextW(page.details, detail.c_str());
    }
    UpdateControls(page);
    if (!::IsWindowVisible(page.hwnd) && !page.shown.busy && (!page.configured || page.shown.closedClean)) {
        ::KillTimer(page.hwnd, kDisplayTimer); // 隐藏页清退后停止原显示唤醒，不遗留空闲轮询。
    }
}

// 读取身份。只读核对，不附加任何调试器，也不改变集合。
void IdentifyTarget(Page& page) {
    group_native::ProcessGroupTarget target;
    std::wstring error;
    if (!ReadDraftTarget(page, target, error)) {
        page.inputError = error;
        Refresh(page);
        return;
    }
    LightProcessGroupRequest request;
    request.command = LightProcessGroupCommand::Identify;
    request.identityPid = target.pid;
    request.identityCreation = target.creationFileTime
        ? std::optional<std::uint64_t>(target.creationFileTime) : std::nullopt;
    if (!page.session.Submit(std::move(request))) {
        page.inputError = L"本端会话未受理该操作，请稍候重试。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

// 加入草稿集合。同一 PID 只能加入一次，数量不超过底层上限。
void AddTarget(Page& page) {
    group_native::ProcessGroupTarget target;
    std::wstring error;
    if (!ReadDraftTarget(page, target, error)) {
        page.inputError = error;
        Refresh(page);
        return;
    }
    if (target.creationFileTime == 0) {
        // 创建时间缺失时使用刚刚读回的真实身份，不猜测数值。
        const auto& identity = page.shown.identity;
        if (!identity || identity->error || identity->target.pid != target.pid || identity->target.creationFileTime == 0) {
            page.inputError = L"请先读取该 PID 的真实身份，或手动填写创建 FILETIME。";
            Refresh(page);
            return;
        }
        target.creationFileTime = identity->target.creationFileTime;
    }
    const auto duplicate = std::any_of(page.draft.begin(), page.draft.end(),
        [&](const group_native::ProcessGroupTarget& item) { return item.pid == target.pid; });
    if (duplicate) {
        page.inputError = L"同一 PID 只能加入一次。";
        Refresh(page);
        return;
    }
    if (page.draft.size() >= group_native::kOwnedProcessGroupLimit) {
        page.inputError = L"集合上限为 16 个进程实例。";
        Refresh(page);
        return;
    }
    page.draft.push_back(target);
    page.shownRevision = UINT64_MAX; // 草稿变化只刷新本地列表，不触发原生Query。
    page.inputError.clear();
    Refresh(page);
}

// 移除草稿成员。只在冻结前生效，已冻结的集合不替换身份。
void RemoveTarget(Page& page) {
    const auto selected = SelectedRows(page.members);
    if (page.configured || selected.empty()) return;
    std::vector<group_native::ProcessGroupTarget> kept;
    for (std::size_t index = 0; index < page.draft.size(); ++index) {
        const bool drop = std::any_of(selected.begin(), selected.end(),
            [&](int row) { return row == static_cast<int>(index); });
        if (!drop) kept.push_back(page.draft[index]);
    }
    page.draft = std::move(kept);
    page.shownRevision = UINT64_MAX;
    page.inputError.clear();
    Refresh(page);
}

// 冻结并配置集合。授权必须来自当前勾选状态，配置只核对身份。
void ConfigureCollection(Page& page) {
    if (page.configured || page.configuring || page.draft.empty()) return;
    const bool authorized = ::SendMessageW(page.authorized, BM_GETCHECK, 0, 0) == BST_CHECKED;
    if (!authorized) {
        page.inputError = L"请先勾选本轮明确授权。";
        Refresh(page);
        return;
    }
    LightProcessGroupRequest request;
    request.command = LightProcessGroupCommand::Configure;
    request.targets = page.draft; // 冻结这一刻的成员身份。
    request.authorized = true;
    const int length = ::GetWindowTextLengthW(page.projectDirectory); // Configure前冻结路径，worker不借用控件。
    request.newProjectDirectory.resize(static_cast<std::size_t>(length) + 1);
    request.newProjectDirectory.resize(static_cast<std::size_t>(::GetWindowTextW(page.projectDirectory,
        request.newProjectDirectory.data(), length + 1)));
    if (!page.session.Submit(std::move(request))) {
        page.inputError = L"本端会话未受理该操作，请稍候重试。";
    } else {
        page.inputError.clear();
        page.configuring = true;
        page.configured = true; // 入队即冻结成员草稿，Idle拒绝不偷偷重新开放编辑。
        page.shownRevision = UINT64_MAX;
    }
    Refresh(page);
}

// 暂停集合。范围是全部成员或当前选中的成员，身份在点击时冻结。
void PauseMembers(Page& page, bool selectedOnly) {
    if (!page.configured) return;
    std::vector<group_native::ProcessGroupTarget> targets;
    if (selectedOnly) {
        for (const int row : SelectedRows(page.members)) {
            if (row >= 0 && static_cast<std::size_t>(row) < page.rowTargets.size()) {
                targets.push_back(page.rowTargets[static_cast<std::size_t>(row)]);
            }
        }
    } else {
        targets = page.rowTargets;
    }
    if (targets.empty()) return;
    LightProcessGroupRequest request;
    request.command = LightProcessGroupCommand::Pause;
    request.requestId = page.session.NextRequestId();
    request.targets = std::move(targets);
    if (!page.session.Submit(std::move(request))) {
        page.inputError = L"本端会话未受理该操作，请稍候重试。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

// 继续集合。必须复制每个目标当前的完整停止令牌，缺一则整组不提交。
void ContinueMembers(Page& page, bool selectedOnly) {
    if (!page.configured) return;
    const auto& members = page.shown.result.members;
    const auto rows = selectedOnly ? SelectedRows(page.members) : std::vector<int>();
    const std::size_t count = selectedOnly ? rows.size() : members.size();
    std::vector<group_native::ProcessGroupStop> stops;
    for (std::size_t index = 0; index < count; ++index) {
        const std::size_t member = selectedOnly ? static_cast<std::size_t>(rows[index]) : index;
        if (member >= members.size() || !members[member].stop) {
            page.inputError = L"仍有成员没有当前精确停点令牌，整组继续未提交。";
            Refresh(page);
            return;
        }
        stops.push_back(*members[member].stop); // 点击时按值复制的完整令牌。
    }
    if (stops.empty()) return;
    LightProcessGroupRequest request;
    request.command = LightProcessGroupCommand::Continue;
    request.requestId = page.session.NextRequestId();
    request.stops = std::move(stops);
    if (!page.session.Submit(std::move(request))) {
        page.inputError = L"本端会话未受理该操作，请稍候重试。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

// 按原继续票据恢复。恢复使用原票据号，不占用新的组层序号。
void RecoverTicket(Page& page) {
    const int ticket = static_cast<int>(::SendMessageW(page.history, CB_GETCURSEL, 0, 0));
    const auto& history = page.shown.history;
    if (ticket < 0 || static_cast<std::size_t>(ticket) >= history.size()) return;
    const auto& operation = history[static_cast<std::size_t>(ticket)];
    if (operation.action != group_native::ProcessGroupAction::Continue) {
        page.inputError = L"只有继续票据可以按原票据恢复。";
        Refresh(page);
        return;
    }
    LightProcessGroupRequest request;
    request.command = LightProcessGroupCommand::Recover;
    request.requestId = operation.requestId; // 原继续票据号。
    if (!page.session.Submit(std::move(request))) {
        page.inputError = L"本端会话未受理该操作，请稍候重试。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

// 请求原所有者清退。未确认时同一 owner 继续存活。
void CloseCollection(Page& page) {
    if (!page.configured) return;
    page.session.Close();
    page.inputError.clear();
    Refresh(page);
}

// 工具条同步进入原页面，再核验资格并沿原函数冻结成员/完整停点/原继续票据。
void SubmitControl(Page& page, LightNativeControlAction action) {
    const bool selectedOnly = action == LightNativeControlAction::PauseSelected ||
        action == LightNativeControlAction::ContinueSelected;
    const auto selection = [&] {
        std::vector<group_native::ProcessGroupTarget> targets;
        for (const int row : SelectedRows(page.members)) {
            if (row >= 0 && static_cast<std::size_t>(row) < page.rowTargets.size())
                targets.push_back(page.rowTargets[static_cast<std::size_t>(row)]);
        }
        return targets;
    };
    const auto selected = selectedOnly ? selection() : std::vector<group_native::ProcessGroupTarget>{};
    const auto targets = page.rowTargets; // 全集也冻结精确PID+creation，不能在Refresh后换成新集合。
    const auto frozenStops = [&] {
        std::vector<group_native::ProcessGroupStop> stops;
        for (const auto& member : page.shown.result.members) {
            if (selectedOnly && std::find(selected.begin(), selected.end(), member.target) == selected.end()) continue;
            if (member.stop) stops.push_back(*member.stop);
        }
        return stops;
    };
    const bool continuing = action == LightNativeControlAction::ContinueAll || action == LightNativeControlAction::ContinueSelected;
    const auto stops = continuing ? frozenStops() : std::vector<group_native::ProcessGroupStop>{};
    const auto currentTicket = [&]() -> std::string {
        const auto row = ::SendMessageW(page.history, CB_GETCURSEL, 0, 0);
        return row >= 0 && static_cast<std::size_t>(row) < page.shown.history.size()
            ? page.shown.history[static_cast<std::size_t>(row)].requestId : std::string{};
    };
    const auto ticket = action == LightNativeControlAction::Recover ? currentTicket() : std::string{};
    Refresh(page); // 只复制后台已发布快照，绝不调用QueryMembers。
    if (page.retiring) return;
    if (targets != page.rowTargets || (selectedOnly && selected != selection()) ||
        (continuing && stops != frozenStops()) ||
        (action == LightNativeControlAction::Recover && (ticket.empty() || ticket != currentTicket()))) {
        page.inputError = L"原集合成员选择或继续票据已更新，请在原集合页确认后重新执行。";
        Refresh(page);
        return; // 回读不能静默把请求改成另一成员或默认的新票据。
    }
    switch (action) {
    case LightNativeControlAction::PauseAll:
        if (::IsWindowEnabled(page.pauseAll)) PauseMembers(page, false);
        break;
    case LightNativeControlAction::PauseSelected:
        if (::IsWindowEnabled(page.pauseSelected)) PauseMembers(page, true);
        break;
    case LightNativeControlAction::ContinueAll:
        if (::IsWindowEnabled(page.continueAll)) ContinueMembers(page, false);
        break;
    case LightNativeControlAction::ContinueSelected:
        if (::IsWindowEnabled(page.continueSelected)) ContinueMembers(page, true);
        break;
    case LightNativeControlAction::Recover:
        if (::IsWindowEnabled(page.recover)) RecoverTicket(page);
        break;
    case LightNativeControlAction::CloseGroup:
        if (::IsWindowEnabled(page.close)) CloseCollection(page);
        break;
    default: break;
    }
}

// 请求一次真实回读。刷新只问原所有者，不产生新的原生副作用。
void QueryMembers(Page& page) {
    LightProcessGroupRequest request;
    request.command = LightProcessGroupCommand::Query;
    if (!page.session.Submit(std::move(request))) {
        page.inputError = L"本端会话未受理该操作，请稍候重试。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

// 复制输入框原文作为本次请求草稿；返回独立字符串，不向worker传HWND。
std::wstring InputText(HWND control)
{
    const int length = ::GetWindowTextLengthW(control); // 以字符数分配含结尾零的缓冲。
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    text.resize(static_cast<std::size_t>(::GetWindowTextW(control, text.data(), length + 1)));
    return text;
}

// 显式读取或保存；范围与完整令牌/原capture均在点击时冻结，选择变化不改写旧结果。
void MemoryAction(Page& page, bool save)
{
    LightProcessGroupRequest request; // 同原session的唯一入队槽，不创建第二控制器。
    if (save) {
        request.command = LightProcessGroupCommand::SaveMemory;
        request.memoryToSave = page.shown.memory;
    } else {
        const auto rows = SelectedRows(page.members); // 仅开放单个精确Held成员的范围读取。
        if (rows.size() != 1 || rows.front() < 0 ||
            static_cast<std::size_t>(rows.front()) >= page.rowTargets.size()) return;
        std::string trackingEpoch; // 每次显式读取独立代次，machine/boot仍取原session/epoch。
        if (!Ksword::ActionAnalyze::ProjectStorage::NewId(trackingEpoch)) {
            page.inputError = L"无法生成本次读取代次，读取未提交。";
            Refresh(page);
            return;
        }
        group_native::ProcessMemorySnapshotRequest capture; // 纯值解析器复制原完整停点和同sample身份。
        LightMemoryInputRejection rejection;
        if (!PrepareHeldMemoryRequest(page.shown.result, page.rowTargets[static_cast<std::size_t>(rows.front())],
            trackingEpoch, InputText(page.memoryBase), InputText(page.memoryBytes), capture, rejection)) {
            page.inputError = L"内存范围或停点无效：" + Widen(rejection.detail);
            Refresh(page);
            return;
        }
        request.command = LightProcessGroupCommand::ReadMemory;
        request.memory = std::move(capture);
    }
    if (!page.session.Submit(std::move(request))) {
        page.inputError = L"本端会话未受理该操作，请稍候重试。";
    } else {
        page.inputError.clear();
    }
    Refresh(page);
}

// 只开放下一集合草稿，不更改旧sample/内存结果；真正身份切换仍须显式Configure。
void NewCollection(Page& page)
{
    if (!page.shown.closedClean || page.shown.busy) return;
    page.configured = false;
    page.configuring = false;
    page.draft.clear();
    page.inputError.clear();
    page.shownRevision = UINT64_MAX;
    ::SendMessageW(page.authorized, BM_SETCHECK, BST_UNCHECKED, 0); // 新集合必须再次明确授权。
    Refresh(page);
}

// 明确键盘遍历顺序；参数焦点由共享正文揭示，列表/详情保留自身箭头与滚动语义。
LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data)
{
    auto& page = *reinterpret_cast<Page*>(data); // 子控件随页根销毁，不把引用交给后台。
    if (message == WM_KEYDOWN && wp == VK_TAB) {
        const std::array order{page.pid, page.creation, page.identityButton, page.identityView, page.authorized,
            page.addButton, page.removeButton, page.projectDirectory, page.memoryBase, page.memoryBytes,
            page.configureButton, page.pauseAll, page.pauseSelected, page.continueAll, page.continueSelected,
            page.refresh, page.recover, page.close, page.newCollection, page.readMemory, page.saveMemory,
            page.members, page.history, page.copyDetails, page.exportDetails, page.details}; // 不依赖跨Body/Page父级的原生Z序。
        int index = static_cast<int>(std::find(order.begin(), order.end(), hwnd) - order.begin());
        const int direction = (::GetKeyState(VK_SHIFT) & 0x8000) ? -1 : 1; // Shift+Tab反向且只选可用控件。
        const int count = static_cast<int>(order.size());
        for (int step = 0; step < count; ++step) {
            index = (index + direction + count) % count;
            const HWND next = order[static_cast<std::size_t>(index)];
            if (::IsWindowEnabled(next) && ::IsWindowVisible(next)) {
                page.parameters.Reveal(next);
                ::SetFocus(next);
                break;
            }
        }
        return 0;
    }
    if (message == WM_KEYDOWN && wp == VK_RETURN) {
        const int id = ::GetDlgCtrlID(hwnd); // 只把明确按钮的Enter转成点击，不吞列表/编辑器输入。
        if (id == kIdentify || id == kAdd || id == kRemove || id == kConfigure ||
            (id >= kPauseAll && id <= kClose && id != kHistory && id != kDetails && id != kStatus) ||
            id == kNewCollection || id == kReadMemory || id == kSaveMemory || id == kCopyDetails || id == kExportDetails) {
            if (!(lp & (1LL << 30)) && ::IsWindowEnabled(hwnd)) ::SendMessageW(hwnd, BM_CLICK, 0, 0);
            return 0;
        }
    }
    return ::DefSubclassProc(hwnd, message, wp, lp);
}

LRESULT CALLBACK PageProc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* page = reinterpret_cast<Page*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto owned = std::make_unique<Page>();
        owned->hwnd = hwnd;
        const auto* port = static_cast<const std::shared_ptr<LightNativeControlPort>*>(
            reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        if (port) owned->controlPort = *port;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    if (!page) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_CREATE: {
        const auto error = page->session.Start();
        if (error) return -1;
        if (!CreateControls(*page)) return -1;
        if (page->controlPort) {
            page->controlSource = std::make_shared<LightNativeControlSource>();
            page->controlSource->submit = [page](LightNativeControlAction action) { SubmitControl(*page, action); };
            page->controlPort->Bind(true, page->controlSource);
            PublishToolbar(*page);
        }
        return 0;
    }
    case WM_SIZE: {
        Layout(*page);
        return 0;
    }
    case WM_SHOWWINDOW:
        if (wp) {
            Refresh(*page);
            ::SetTimer(hwnd, kDisplayTimer, kDisplayIntervalMs, nullptr);
        } else if (!page->controlPort || !page->configured || page->shown.closedClean) {
            ::KillTimer(hwnd, kDisplayTimer); // 只停隐藏页的投影唤醒，原worker继续维护真实责任。
        }
        break;
    case WM_TIMER:
        if (wp == kDisplayTimer) {
            Refresh(*page); // 原显示timer只复制本地快照，为总览同步资格，不添加原生Query。
            return 0;
        }
        break;
    case WM_DRAWITEM:
        if (wp == kConfigure || wp == kClose) {
            Ui::DrawThemedButton(*reinterpret_cast<const DRAWITEMSTRUCT*>(lp));
            return TRUE;
        }
        break;
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT:
    case WM_CTLCOLORLISTBOX: {
        const auto child = reinterpret_cast<HWND>(lp);
        const auto dc = reinterpret_cast<HDC>(wp);
        auto& theme = Ui::AppTheme();
        if (child == page->hint || child == page->pidLabel || child == page->creationLabel ||
            child == page->projectLabel || child == page->memoryBaseLabel || child == page->memoryBytesLabel) {
            return Ui::PaintLabelBackground(dc, child, theme.windowBrush(), theme.textColor);
        }
        ::SetTextColor(dc, theme.textColor);
        ::SetBkColor(dc, theme.panelColor);
        return reinterpret_cast<LRESULT>(theme.panelBrush());
    }
    case WM_COMMAND:
        if (LOWORD(wp) == kAuthorized && HIWORD(wp) == BN_CLICKED) {
            // 勾选状态只影响按钮可用性，不会提交任何原生动作。
            UpdateControls(*page);
            return 0;
        }
        if (LOWORD(wp) == kHistory && HIWORD(wp) == CBN_SELCHANGE) {
            // 选择票据只更新详情显示，不触发原生动作。
            Refresh(*page);
            return 0;
        }
        if (HIWORD(wp) == BN_CLICKED && !page->retiring) {
            switch (LOWORD(wp)) {
            case kIdentify: IdentifyTarget(*page); return 0;
            case kAdd: AddTarget(*page); return 0;
            case kRemove: RemoveTarget(*page); return 0;
            case kConfigure: ConfigureCollection(*page); return 0;
            case kPauseAll: SubmitControl(*page, LightNativeControlAction::PauseAll); return 0;
            case kPauseSelected: SubmitControl(*page, LightNativeControlAction::PauseSelected); return 0;
            case kContinueAll: SubmitControl(*page, LightNativeControlAction::ContinueAll); return 0;
            case kContinueSelected: SubmitControl(*page, LightNativeControlAction::ContinueSelected); return 0;
            case kRefresh: QueryMembers(*page); return 0;
            case kRecover: SubmitControl(*page, LightNativeControlAction::Recover); return 0;
            case kClose: SubmitControl(*page, LightNativeControlAction::CloseGroup); return 0;
            case kNewCollection: NewCollection(*page); return 0;
            case kReadMemory: MemoryAction(*page, false); return 0;
            case kSaveMemory: MemoryAction(*page, true); return 0;
            case kCopyDetails:
                if (!Ui::CopyTextToClipboard(hwnd, page->detailText, L"进程集合详情")) {
                    page->inputError = L"复制详情失败，原文仍保留。";
                    Refresh(*page);
                }
                return 0;
            case kExportDetails: {
                std::wstring error; // 原完整文档冻结在调用时，取消不更改原结果。
                const auto saved = Ui::SaveUtf8TextFileWithDialog(hwnd, L"process-group-details.txt",
                    L"导出进程集合详情", L"文本文件 (*.txt)\0*.txt\0", L"txt", page->detailText, &error);
                if (saved == Ui::SaveTextFileResult::Failed) {
                    page->inputError = error;
                    Refresh(*page);
                }
                return 0;
            }
            }
        }
        break;
    case WM_NOTIFY:
        if (reinterpret_cast<const NMHDR*>(lp)->idFrom == kMembers && !page->rebuilding) {
            UpdateControls(*page);
            const auto detail = BuildDetailText(*page);
            if (detail != page->detailText) {
                page->detailText = detail;
                ::SetWindowTextW(page->details, detail.c_str());
            }
            return 0;
        }
        break;
    case Ui::kBeginNativeRetirementMessage:
        page->retiring = true;
        page->session.BeginRetirement();
        Refresh(*page);
        return 0;
    case Ui::kPollNativeRetirementMessage:
        // 原生责任未结清时不允许页面消失；同一 owner 继续存活。
        return page->session.Ready() ? 0 : 1;
    case Ui::kCancelNativeRetirementMessage:
        page->retiring = false;
        page->session.CancelRetirement();
        Refresh(*page);
        return 0;
    case WM_DESTROY:
        if (page->controlSource) {
            page->controlSource->submit = {};
            page->controlPort->Unbind(true, page->controlSource);
            page->controlSource.reset();
        }
        return 0;
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kDisplayTimer);
        if (page->tooltip) ::DestroyWindow(page->tooltip);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete page;
        break;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}

} // namespace process_group_page

HWND CreateProcessGroupPage(HWND parent, const RECT& bounds) {
    return CreateProcessGroupPage(parent, bounds, {});
}

HWND CreateProcessGroupPage(HWND parent, const RECT& bounds, const std::shared_ptr<LightNativeControlPort>& port) {
    using namespace process_group_page; // 工厂只绑定自有业务页，不向外暴露内部Page状态。
    WNDCLASSW wc{};
    wc.lpfnWndProc = PageProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ui::AppTheme().windowBrush();
    wc.lpszClassName = kPageClass;
    if (!::RegisterClassW(&wc) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    return ::CreateWindowExW(WS_EX_CONTROLPARENT, kPageClass, L"进程集合控制",
        WS_CHILD | WS_CLIPCHILDREN, bounds.left, bounds.top,
        bounds.right - bounds.left, bounds.bottom - bounds.top, parent, nullptr,
        wc.hInstance, const_cast<std::shared_ptr<LightNativeControlPort>*>(&port));
}

} // namespace Ksword::Features::ActionAnalyze
