#include "WindowToolsHotkeyView.h"

#include "WindowToolsCommon.h"
#include "../../Core/Common.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::WindowTools {
namespace {

constexpr wchar_t kHotkeyViewClass[] = L"KswordARKLight.WindowTools.HotkeyView";

constexpr int kProbeButtonId = 67301;
constexpr int kRangeComboId = 67302;
constexpr int kWarningTextId = 67303;
constexpr int kFilterBarId = 67304;
constexpr int kHotkeyListId = 67305;
constexpr int kLoadingOverlayId = 67306;
constexpr int kRefreshButtonId = 67307;
constexpr int kExportButtonId = 67308;

constexpr UINT kMenuCopyRow = 67661;
constexpr UINT kMenuCopyVisible = 67662;
constexpr UINT kMenuProbe = 67663;

constexpr UINT kMsgProbeCompleted = WM_APP + 677;
constexpr UINT kMsgFilterCompleted = WM_APP + 678;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 4 + kRowHeight * 3;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 5;

// kProbeHotkeyId is reused for every probe. Each registration is released before
// the next one is attempted, so one id is enough and the thread-local hotkey id
// space is never filled up by a run that is interrupted partway.
constexpr int kProbeHotkeyId = 0x4B57;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct ModifierChoice final {
    UINT value;
    const wchar_t* name;
};

constexpr ModifierChoice kModifiers[] = {
    { MOD_CONTROL, L"Ctrl" },
    { MOD_ALT,     L"Alt" },
    { MOD_SHIFT,   L"Shift" },
    { MOD_WIN,     L"Win" },
};

struct KeyChoice final {
    UINT virtualKey;
    const wchar_t* name;
};

constexpr KeyChoice kNamedKeys[] = {
    { VK_ESCAPE,     L"Esc" },
    { VK_TAB,        L"Tab" },
    { VK_SPACE,      L"Space" },
    { VK_RETURN,     L"Enter" },
    { VK_BACK,       L"Backspace" },
    { VK_INSERT,     L"Insert" },
    { VK_DELETE,     L"Delete" },
    { VK_HOME,       L"Home" },
    { VK_END,        L"End" },
    { VK_PRIOR,      L"PageUp" },
    { VK_NEXT,       L"PageDown" },
    { VK_LEFT,       L"Left" },
    { VK_UP,         L"Up" },
    { VK_RIGHT,      L"Right" },
    { VK_DOWN,       L"Down" },
    { VK_SNAPSHOT,   L"PrintScreen" },
    { VK_PAUSE,      L"Pause" },
    { VK_OEM_3,      L"`" },
    { VK_OEM_MINUS,  L"-" },
    { VK_OEM_PLUS,   L"=" },
    { VK_OEM_4,      L"[" },
    { VK_OEM_6,      L"]" },
    { VK_OEM_5,      L"\\" },
    { VK_OEM_1,      L";" },
    { VK_OEM_7,      L"'" },
    { VK_OEM_COMMA,  L"," },
    { VK_OEM_PERIOD, L"." },
    { VK_OEM_2,      L"/" },
};

struct HotkeyProbeEntry final {
    UINT modifiers = 0;
    UINT virtualKey = 0;
    std::wstring combination;
    std::wstring modifierText;
    std::wstring keyText;
    bool available = false;
    DWORD error = 0;
};

struct HotkeyProbeResult final {
    std::vector<HotkeyProbeEntry> entries;
    std::size_t occupied = 0;
    std::size_t available = 0;
};

struct HotkeyFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

struct HotkeyViewState final {
    HWND hwnd = nullptr;
    HWND probeButton = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND rangeCombo = nullptr;
    HWND warningText = nullptr;
    HWND filterBar = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView hotkeyList;
    HotkeyProbeResult probe;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"尚未探测。点击“开始探测”前请先阅读上方说明。";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    bool hasProbeResult = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<HotkeyProbeResult>> probeTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<HotkeyFilterResult>> filterTask;
};

std::wstring ModifierText(const UINT modifiers) {
    std::wstring text;
    for (const ModifierChoice& modifier : kModifiers) {
        if ((modifiers & modifier.value) != 0) {
            if (!text.empty()) {
                text += L"+";
            }
            text += modifier.name;
        }
    }
    return text;
}

// ProbeKey is the runtime form of one key in the probe matrix. It owns its
// display name so the matrix can mix generated names (A-Z, 0-9, F1-F24) with the
// static table above without any of them pointing into a temporary.
struct ProbeKey final {
    UINT virtualKey = 0;
    std::wstring name;
};

// BuildProbeKeys assembles the key half of the probe matrix. The set is limited
// to keys an application can realistically claim as a global hotkey; probing all
// 256 virtual-key codes would multiply the run time without adding anything a
// user would recognize in the result table.
std::vector<ProbeKey> BuildProbeKeys() {
    std::vector<ProbeKey> keys;
    keys.reserve(26 + 10 + 24 + sizeof(kNamedKeys) / sizeof(kNamedKeys[0]));
    for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
        keys.push_back({ static_cast<UINT>(letter), std::wstring(1, letter) });
    }
    for (wchar_t digit = L'0'; digit <= L'9'; ++digit) {
        keys.push_back({ static_cast<UINT>(digit), std::wstring(1, digit) });
    }
    for (int index = 0; index < 24; ++index) {
        keys.push_back({ static_cast<UINT>(VK_F1 + index), L"F" + std::to_wstring(index + 1) });
    }
    for (const KeyChoice& named : kNamedKeys) {
        keys.push_back({ named.virtualKey, named.name });
    }
    return keys;
}

// ProbeHotkeys runs the whole matrix on an AsyncSnapshotTask worker.
//
// RegisterHotKey is called with a null window on purpose. Passing an HWND would
// require that window to belong to the calling thread, which the worker does not
// own; with nullptr the registration is bound to the worker's own message queue
// instead, so nothing about this probe can reach the UI thread's input state.
// Any registration that survives an early exit dies with the worker thread.
//
// The hold is released immediately after a successful registration, but it is a
// real hold: a keystroke that lands in that gap is delivered to this thread and
// discarded. That is the entire cost of the only user-mode technique available.
HotkeyProbeResult ProbeHotkeys() {
    HotkeyProbeResult result;
    const std::vector<ProbeKey> keys = BuildProbeKeys();
    const UINT modifierMaskCount = 1u << (sizeof(kModifiers) / sizeof(kModifiers[0]));
    result.entries.reserve(static_cast<std::size_t>(modifierMaskCount - 1) * keys.size());

    for (UINT mask = 1; mask < modifierMaskCount; ++mask) {
        UINT modifiers = 0;
        for (std::size_t bit = 0; bit < sizeof(kModifiers) / sizeof(kModifiers[0]); ++bit) {
            if ((mask & (1u << bit)) != 0) {
                modifiers |= kModifiers[bit].value;
            }
        }
        const std::wstring modifierText = ModifierText(modifiers);

        for (const ProbeKey& key : keys) {
            HotkeyProbeEntry entry;
            entry.modifiers = modifiers;
            entry.virtualKey = key.virtualKey;
            entry.modifierText = modifierText;
            entry.keyText = key.name;
            entry.combination = modifierText + L"+" + entry.keyText;

            if (::RegisterHotKey(nullptr, kProbeHotkeyId, modifiers, key.virtualKey)) {
                ::UnregisterHotKey(nullptr, kProbeHotkeyId);
                entry.available = true;
                ++result.available;
            } else {
                entry.error = ::GetLastError();
                ++result.occupied;
            }
            result.entries.push_back(std::move(entry));
        }
    }
    return result;
}

std::wstring StatusTextFor(const HotkeyProbeEntry& entry) {
    if (entry.available) {
        return L"可用（当前无人占用）";
    }
    if (entry.error == ERROR_HOTKEY_ALREADY_REGISTERED) {
        return L"已被占用";
    }
    return L"注册被拒绝";
}

std::wstring ErrorTextFor(const HotkeyProbeEntry& entry) {
    if (entry.available) {
        return L"—";
    }
    return std::to_wstring(entry.error) + L"：" + Ksword::Core::LastErrorMessage(entry.error);
}

int SelectedRange(const HotkeyViewState& state) {
    const LRESULT selection = state.rangeCombo ? ::SendMessageW(state.rangeCombo, CB_GETCURSEL, 0, 0) : 0;
    return selection == CB_ERR ? 0 : static_cast<int>(selection);
}

void BuildRows(HotkeyViewState& state) {
    const int range = SelectedRange(state);
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(state.probe.entries.size());
    for (std::size_t index = 0; index < state.probe.entries.size(); ++index) {
        const HotkeyProbeEntry& entry = state.probe.entries[index];
        if ((range == 1 && entry.available) || (range == 2 && !entry.available)) {
            continue;
        }
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = entry.combination;
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(entry.combination);
        row.cells.push_back(entry.modifierText);
        row.cells.push_back(entry.keyText);
        row.cells.push_back(StatusTextFor(entry));
        row.cells.push_back(ErrorTextFor(entry));
        // An occupied combination is the finding; an available one is only the
        // absence of a finding, so the table highlights the former.
        if (!entry.available) {
            row.textColor = Ksword::Ui::AppTheme().accentDarkColor;
        }
        rows.push_back(std::move(row));
    }
    auto shared = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.hotkeyList.setRows(*shared);
    state.filterRows = std::move(shared);
    ++state.displayGeneration;
}

void ApplyHotkeyFilter(HotkeyViewState& state, HotkeyFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.hotkeyList.hwnd()) {
        return;
    }
    state.hotkeyList.setVisibleIndexes(std::move(result.visibleIndexes));
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(state.hotkeyList.visibleIndexes().size()) + L" / " +
            std::to_wstring(state.hotkeyList.rows().size()) + L" 项。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void RequestHotkeyFilter(HotkeyViewState& state, std::wstring query) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const auto rows = state.filterRows;
    const std::uint64_t generation = state.displayGeneration;
    const bool useRegex = state.filterUseRegex;
    if (!state.filterTask || !rows) {
        return;
    }
    state.filterTask->request(
        [rows, generation, useRegex, query = state.filterQuery]() mutable {
            HotkeyFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<HotkeyFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"热键筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            ApplyHotkeyFilter(state, std::move(*result));
        });
}

// BeginProbe is only reachable from an explicit user action. The page never
// probes on creation or on a tab switch, because the probe briefly takes hotkeys
// away from whoever owns them and that is not something to do behind the user's
// back every time a tab is clicked.
void BeginProbe(HotkeyViewState& state) {
    if (!state.probeTask || state.probeTask->running()) {
        state.statusText = L"探测正在进行中。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    if (state.probeButton) {
        ::EnableWindow(state.probeButton, FALSE);
    }
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    state.statusText = L"正在后台探测热键占用情况…";
    Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在逐个尝试注册热键组合…");
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.probeTask->request(
        [] { return ProbeHotkeys(); },
        [&state](std::uint64_t, std::optional<HotkeyProbeResult>&& result, std::exception_ptr error) {
            if (state.probeButton) {
                ::EnableWindow(state.probeButton, TRUE);
            }
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, state.hasProbeResult ? TRUE : FALSE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !result.has_value()) {
                state.statusText = L"热键探测异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::size_t total = result->entries.size();
            const std::size_t occupied = result->occupied;
            const std::size_t available = result->available;
            state.probe = std::move(*result);
            state.hasProbeResult = true;
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            BuildRows(state);
            state.statusText = L"共探测 " + std::to_wstring(total) + L" 个组合：可用 " +
                std::to_wstring(available) + L" 个，无法注册 " + std::to_wstring(occupied) +
                L" 个（已被其他程序占用或系统保留）。";
            RequestHotkeyFilter(state,
                state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void ExportVisibleRows(HotkeyViewState& state) {
    const std::wstring text = Ksword::Ui::BuildVisibleVirtualListTsv(
        { L"组合", L"修饰键", L"主键", L"状态", L"错误码" }, state.hotkeyList);
    if (text.empty()) {
        state.statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(state.hwnd, L"hotkey_probe.tsv", L"导出热键占用探测",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved: state.statusText = L"热键可见结果已导出。"; break;
    case Ksword::Ui::SaveTextFileResult::Cancelled: state.statusText = L"已取消导出热键结果。"; break;
    case Ksword::Ui::SaveTextFileResult::Failed: state.statusText = L"导出热键结果失败：" + error; break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void ShowContextMenu(HotkeyViewState& state, const POINT screenPoint) {
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool hasRows = !state.hotkeyList.rows().empty();
    ::AppendMenuW(menu, MF_STRING | (hasRows ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING | (hasRows ? MF_ENABLED : MF_GRAYED), kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuProbe, L"重新探测");

    const int command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(command)) {
    case kMenuCopyRow:
        state.statusText = CopyTextToClipboard(state.hwnd, RowsAsTsv(state.hotkeyList, false, kColumnCount))
            ? L"已复制选中行。" : L"复制失败。";
        break;
    case kMenuCopyVisible:
        state.statusText = CopyTextToClipboard(state.hwnd, RowsAsTsv(state.hotkeyList, true, kColumnCount))
            ? L"已复制可见行。" : L"复制失败。";
        break;
    case kMenuProbe:
        BeginProbe(state);
        return;
    default:
        return;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void LayoutView(HotkeyViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    int cursorX = kGap;
    if (state.probeButton) {
        ::MoveWindow(state.probeButton, cursorX, kGap, 96, kRowHeight, TRUE);
    }
    cursorX += 96 + kGap;
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, cursorX, kGap, 64, kRowHeight, TRUE);
    }
    cursorX += 64 + kGap;
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, cursorX, kGap, 78, kRowHeight, TRUE);
    }
    cursorX += 78 + kGap;
    if (state.rangeCombo) {
        ::MoveWindow(state.rangeCombo, cursorX, kGap, 150, kRowHeight * 6, TRUE);
    }

    const int secondRowY = kGap * 2 + kRowHeight;
    if (state.warningText) {
        ::MoveWindow(state.warningText, kGap, secondRowY + 3, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int thirdRowY = kGap * 3 + kRowHeight * 2;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, thirdRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int listTop = kHeaderHeight;
    const int listHeight = (std::max)(0, height - kStatusHeight - listTop - kGap);
    if (HWND list = state.hotkeyList.hwnd()) {
        ::MoveWindow(list, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, listTop, (std::max)(0, width - kGap * 2), listHeight, TRUE);
    }
}

bool CreateChildControls(HotkeyViewState& state) {
    HWND hwnd = state.hwnd;
    state.probeButton = Ksword::Ui::CreateButton(hwnd, kProbeButtonId, L"开始探测", 0, 0, 0, 0);
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = Ksword::Ui::CreateButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.warningText = Ksword::Ui::CreateText(hwnd, kWarningTextId,
        L"探测方式：逐个尝试 RegisterHotKey，成功即说明该组合未被占用，随后立即注销。"
        L"探测过程中本程序会极短暂地持有这些组合，此刻按下的对应快捷键可能不会到达它原本的程序。",
        0, 0, 0, 0);
    state.filterBar = Ksword::Ui::CreateFilterBar(hwnd, kFilterBarId, L"筛选组合、修饰键、主键与状态", 0, 0, 0, 0);
    state.rangeCombo = ::CreateWindowExW(0, WC_COMBOBOXW, L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0, 0, 0, 0, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kRangeComboId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.probeButton || !state.refreshButton || !state.exportButton || !state.warningText || !state.filterBar || !state.rangeCombo) {
        return false;
    }
    ::EnableWindow(state.refreshButton, FALSE);
    for (const wchar_t* label : { L"全部组合", L"仅已占用", L"仅可用" }) {
        ::SendMessageW(state.rangeCombo, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label));
    }
    ::SendMessageW(state.rangeCombo, CB_SETCURSEL, 1, 0);

    if (!state.hotkeyList.create(hwnd, kHotkeyListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS)) {
        return false;
    }
    state.hotkeyList.addColumns({
        { 0, 180, LVCFMT_LEFT, L"组合" },
        { 1, 140, LVCFMT_LEFT, L"修饰键" },
        { 2, 110, LVCFMT_LEFT, L"主键" },
        { 3, 160, LVCFMT_LEFT, L"状态" },
        { 4, 380, LVCFMT_LEFT, L"错误码" },
    });
    if (HWND list = state.hotkeyList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK HotkeyViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<HotkeyViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<HotkeyViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->probeTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<HotkeyProbeResult>>(hwnd, kMsgProbeCompleted);
            state->filterTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<HotkeyFilterResult>>(hwnd, kMsgFilterCompleted);
            LayoutView(*state);
        }
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutView(*state);
        }
        return 0;
    case WM_COMMAND:
        if (state) {
            const int id = LOWORD(wParam);
            const int notification = HIWORD(wParam);
            if (id == kFilterBarId && notification == EN_CHANGE) {
                RequestHotkeyFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar));
                return 0;
            }
            if (id == kRangeComboId && notification == CBN_SELCHANGE) {
                // The range combo changes which entries become rows, so the row
                // snapshot and every visible index derived from it are rebuilt.
                BuildRows(*state);
                RequestHotkeyFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar));
                return 0;
            }
            if (notification == BN_CLICKED && id == kProbeButtonId) {
                BeginProbe(*state);
                return 0;
            }
            if (notification == BN_CLICKED && id == kRefreshButtonId) {
                if (state->hasProbeResult) {
                    BeginProbe(*state);
                }
                return 0;
            }
            if (notification == BN_CLICKED && id == kExportButtonId) {
                ExportVisibleRows(*state);
                return 0;
            }
        }
        break;
    case WM_NOTIFY:
        if (state) {
            const auto* header = reinterpret_cast<const NMHDR*>(lParam);
            if (header) {
                LRESULT result = 0;
                if (state->hotkeyList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->hotkeyList.hwnd() && header->code == NM_RCLICK) {
                    POINT point{};
                    ::GetCursorPos(&point);
                    ShowContextMenu(*state, point);
                    return 0;
                }
            }
        }
        break;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetBkMode(dc, TRANSPARENT);
        ::SetTextColor(dc, state && reinterpret_cast<HWND>(lParam) == state->warningText
            ? Ksword::Ui::AppTheme().mutedTextColor
            : Ksword::Ui::AppTheme().textColor);
        return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_PAINT:
        if (state) {
            PAINTSTRUCT paint{};
            HDC dc = ::BeginPaint(hwnd, &paint);
            RECT client{};
            ::GetClientRect(hwnd, &client);
            ::FillRect(dc, &client, Ksword::Ui::AppTheme().windowBrush());
            RECT statusRect{ kGap, client.bottom - kStatusHeight, client.right - kGap, client.bottom };
            Ksword::Ui::DrawTextLine(dc, state->statusText, statusRect,
                Ksword::Ui::AppTheme().mutedTextColor, Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    default:
        if (state) {
            if (msg == kMsgProbeCompleted && state->probeTask) {
                state->probeTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->probeTask) {
                state->probeTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->hotkeyList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureHotkeyViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = HotkeyViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kHotkeyViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateHotkeyProbeView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureHotkeyViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kHotkeyViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

} // namespace Ksword::Features::WindowTools
