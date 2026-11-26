#include "ProjectBreakpointPane.h"
#include "ActionAnalyzePage.h"
#include "LightNativeControlToolbar.h"
#include "../../Ui/Controls.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Dpi.h"
#include "../../Ui/ParameterWorkspace.h"
#include "../../Ui/Theme.h"
#include "../../../shared/usermode/backend/process/ProcessControls.h"

#include <algorithm>
#include <array>
#include <commctrl.h>
#include <commdlg.h>
#include <cwchar>
#include <iterator>
#include <memory>
#include <shellapi.h>
#include <utility>

namespace Ksword::Features::ActionAnalyze {
namespace {
constexpr wchar_t kClass[] = L"KswordLight.ProjectBreakpointPane";
constexpr UINT kCatalog = WM_APP + 974;
constexpr int kChoice = 58701, kPrepare = 58702;
using Ui::Scale;
struct Pane {
    HWND hwnd = nullptr, content = nullptr, title = nullptr, choice = nullptr, reason = nullptr, prepareButton = nullptr;
    Ui::ParameterWorkspace parameters;
    ProjectReplayCatalog catalog;
    std::function<bool(const LightImageExecutionDraft&)> prepare;
    HIMAGELIST prepareImages = nullptr;
    bool preparing = false;
    bool retiring = false;
};

const Ksword::ActionAnalyze::BreakpointDefinition* Selected(const Pane& pane) {
    const auto index = ::SendMessageW(pane.choice, CB_GETCURSEL, 0, 0);
    return pane.catalog.breakpointDefinitions && index >= 0 && static_cast<std::size_t>(index) < pane.catalog.breakpointDefinitions->size()
        ? &(*pane.catalog.breakpointDefinitions)[static_cast<std::size_t>(index)] : nullptr;
}

std::wstring Unsupported(const Ksword::ActionAnalyze::BreakpointDefinition* row) {
    if (!row) return L"打开项目后选择已保存断点定义；这里只载入实时草稿，不设置断点。";
    if (row->breakpointDefinitionId.empty()) return L"所选定义没有已保存的稳定ID，不能载入。";
    if (!row->enabled) return L"所选定义已禁用；请先在定义来源中启用并重新打开项目。";
    const auto* rva = std::get_if<Ksword::ActionAnalyze::BreakpointRva>(&row->location);
    if (!rva) return L"符号/PDB位置暂不支持实时载入；调试符号不会当成PE导出名。";
    if (!rva->rva) return L"仅支持非零32位RVA定义；RVA 0不能载入。";
    return {};
}

void Refresh(Pane& pane) {
    const auto* row = Selected(pane);
    const auto unavailable = Unsupported(row);
    ::EnableWindow(pane.prepareButton, !pane.preparing && !pane.retiring && unavailable.empty());
    std::wstring text = unavailable.empty()
        ? L"选择目标中已加载的同名模块文件后载入原页；PID、创建时间和条件保留，用户点开始才附加。" : unavailable;
    if (row && unavailable.empty() && row->module.imageSha256)
    {
        text += L"\r\n开始时从本轮sample冻结定义读取imageSha256，由原生准入核对CREATE_PROCESS/LOAD_DLL调试事件中的真实映像文件SHA-256，通过后才武装。文件散列核对不证明内存页未被修改。";
        text += L"\r\n定义imageSha256：" + std::wstring(row->module.imageSha256->begin(), row->module.imageSha256->end());
    }
    if (row) text += L"\r\n定义ID：" + std::wstring(row->breakpointDefinitionId.begin(), row->breakpointDefinitionId.end());
    if (!pane.catalog.projectId.empty()) text += L"\r\n项目：" + std::wstring(pane.catalog.projectId.begin(), pane.catalog.projectId.end());
    ::SetWindowTextW(pane.reason, text.c_str());
}

int TextHeight(HWND label, int width) {
    std::wstring text(static_cast<std::size_t>(::GetWindowTextLengthW(label)) + 1, L'\0');
    ::GetWindowTextW(label, text.data(), static_cast<int>(text.size()));
    const auto dc = ::GetDC(label);
    if (!dc) return Scale(56);
    const auto previous = ::SelectObject(dc, Ui::SystemUIFont());
    RECT bounds{0, 0, width, 0};
    ::DrawTextW(dc, text.c_str(), -1, &bounds, DT_CALCRECT | DT_WORDBREAK | DT_NOPREFIX);
    ::SelectObject(dc, previous);
    ::ReleaseDC(label, dc);
    return (std::max)(Scale(24), static_cast<int>(bounds.bottom));
}

// 整个定义区复用共享滚动正文，固定动作自然换行，原总览仍独立保留主要空间。
void Layout(Pane& pane) {
    if (!pane.content) return;
    RECT area{};
    ::GetClientRect(pane.hwnd, &area);
    const int edge = Scale(6), gap = Scale(8), row = Scale(28);
    const int width = (std::max)(1, static_cast<int>(area.right) - 2 * edge);
    const int bodyWidth = (std::max)(1, width - ::GetSystemMetrics(SM_CXVSCROLL));
    const int titleHeight = TextHeight(pane.title, bodyWidth), reasonHeight = TextHeight(pane.reason, bodyWidth);
    const int naturalHeight = titleHeight + gap + row + gap + reasonHeight;
    const int viewport = (std::max)(1, (std::min)(naturalHeight, static_cast<int>(area.bottom) / 3));
    ::MoveWindow(pane.title, 0, 0, bodyWidth, titleHeight, TRUE);
    ::MoveWindow(pane.choice, 0, titleHeight + gap, bodyWidth, Scale(240), TRUE);
    ::MoveWindow(pane.reason, 0, titleHeight + gap + row + gap, bodyWidth, reasonHeight, TRUE);
    pane.parameters.Layout(edge, edge, width, viewport, naturalHeight);
    const std::array actions{pane.prepareButton};
    const int actionHeight = Ui::LayoutParameterActions(actions, edge, edge + viewport + gap, width, Scale(220), row, gap);
    const int top = edge + viewport + gap + actionHeight + gap;
    ::MoveWindow(pane.content, 0, top, area.right, (std::max)(1, static_cast<int>(area.bottom) - top), TRUE);
}

void Prepare(Pane& pane) {
    const auto* selected = Selected(pane);
    if (pane.preparing || pane.retiring || !Unsupported(selected).empty() || !pane.prepare) return;
    const auto row = *selected; // 文件选择的模态消息期间原项目可更新；冻结所选定义值。
    const auto projectId = pane.catalog.projectId, revisionId = pane.catalog.revisionId;
    const auto projectPath = pane.catalog.manifestPath; // 模态选择期间冻结原项目路径，不借用后来目录。
    const auto module = ks::r3::process::Utf8ToWide(row.module.name);
    std::wstring path(32768, L'\0');
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = pane.hwnd;
    dialog.lpstrFilter = L"模块 (*.dll;*.exe)\0*.dll;*.exe\0所有文件 (*.*)\0*.*\0";
    dialog.lpstrTitle = L"选择目标中已加载的同名模块";
    dialog.lpstrFile = path.data();
    dialog.nMaxFile = static_cast<DWORD>(path.size());
    dialog.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_DONTADDTORECENT;
    pane.preparing = true;
    ::EnableWindow(pane.prepareButton, FALSE);
    if (::GetOpenFileNameW(&dialog)) {
        path.resize(std::wcslen(path.c_str()));
        const auto slash = path.find_last_of(L"\\/");
        const auto name = slash == std::wstring::npos ? path : path.substr(slash + 1);
        if (pane.retiring || pane.catalog.projectId != projectId || pane.catalog.revisionId != revisionId || pane.catalog.manifestPath != projectPath) {
            ::MessageBoxW(pane.hwnd, L"选择模块期间原项目已变化或正在清退，请重新选择定义。", L"项目已变化", MB_OK | MB_ICONINFORMATION);
        } else if (module.empty() || ::CompareStringOrdinal(name.c_str(), -1, module.c_str(), -1, TRUE) != CSTR_EQUAL) {
            ::MessageBoxW(pane.hwnd, L"所选文件名必须与已保存定义的模块名一致。未载入草稿。", L"模块名不匹配", MB_OK | MB_ICONINFORMATION);
        } else {
            const LightImageExecutionDraft draft{path, std::get<Ksword::ActionAnalyze::BreakpointRva>(row.location).rva,
                row.breakpointDefinitionId, projectPath, projectId};
            if (!pane.prepare(draft)) ::MessageBoxW(pane.hwnd,
                L"未载入草稿：原会话仍活跃、用户取消替换，或目标页面不可用。请在原页核对并清退后重试。",
                L"实时模块断点", MB_OK | MB_ICONINFORMATION);
        }
    }
    pane.preparing = false;
    Refresh(pane);
    Layout(pane);
}

LRESULT CALLBACK Navigate(HWND hwnd, UINT message, WPARAM wp, LPARAM lp, UINT_PTR, DWORD_PTR data) {
    auto& pane = *reinterpret_cast<Pane*>(data);
    if (message == WM_KEYDOWN && wp == VK_TAB) {
        const bool reverse = (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
        if (hwnd == pane.choice && reverse) ::SendMessageW(::GetParent(pane.hwnd), kFocusLightNativeToolbar, TRUE, 0);
        else if (hwnd == pane.choice && !reverse && ::IsWindowEnabled(pane.prepareButton)) ::SetFocus(pane.prepareButton);
        else if (hwnd == pane.prepareButton && reverse) ::SetFocus(pane.choice);
        else if (const HWND next = ::GetNextDlgTabItem(pane.content, nullptr, reverse)) ::SetFocus(next);
        pane.parameters.Reveal(::GetFocus());
        return 0;
    }
    if (message == WM_KEYDOWN && wp == VK_RETURN && hwnd == pane.prepareButton) {
        if (!(lp & (1LL << 30)) && ::IsWindowEnabled(hwnd)) ::SendMessageW(hwnd, BM_CLICK, 0, 0);
        return 0;
    }
    if (message == WM_CHAR && (wp == L'\t' || wp == L'\r')) return 0;
    return ::DefSubclassProc(hwnd, message, wp, lp);
}

LRESULT CALLBACK Proc(HWND hwnd, UINT message, WPARAM wp, LPARAM lp) {
    auto* pane = reinterpret_cast<Pane*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        auto owned = std::make_unique<Pane>();
        owned->hwnd = hwnd;
        owned->prepare = *static_cast<std::function<bool(const LightImageExecutionDraft&)>*>(reinterpret_cast<CREATESTRUCTW*>(lp)->lpCreateParams);
        pane = owned.release();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pane));
    }
    if (!pane) return ::DefWindowProcW(hwnd, message, wp, lp);
    switch (message) {
    case WM_CREATE: {
        if (!pane->parameters.Create(hwnd)) return -1;
        pane->title = Ui::CreateText(pane->parameters.Body(), 0, L"已保存断点定义 → 实时模块草稿", 0, 0, 1, 1);
        pane->choice = ::CreateWindowExW(0, WC_COMBOBOXW, L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | WS_VSCROLL,
            0, 0, 1, 1, pane->parameters.Body(), reinterpret_cast<HMENU>(kChoice), ::GetModuleHandleW(nullptr), nullptr);
        pane->reason = Ui::CreateText(pane->parameters.Body(), 0, L"", 0, 0, 1, 1);
        pane->prepareButton = Ui::CreateButton(hwnd, kPrepare, L"载入实时模块断点草稿", 0, 0, 1, 1);
        if (!pane->title || !pane->choice || !pane->reason || !pane->prepareButton) return -1;
        for (const HWND label : {pane->reason, pane->title}) {
            const auto style = ::GetWindowLongPtrW(label, GWL_STYLE);
            ::SetWindowLongPtrW(label, GWL_STYLE, (style & ~static_cast<LONG_PTR>(SS_TYPEMASK)) | SS_LEFT);
        }
        for (const auto control : {pane->choice, pane->prepareButton})
            if (!::SetWindowSubclass(control, Navigate, 1, reinterpret_cast<DWORD_PTR>(pane))) return -1;
        SHSTOCKICONINFO icon{sizeof(icon)};
        if (SUCCEEDED(::SHGetStockIconInfo(SIID_LINK, SHGSI_ICON | SHGSI_SMALLICON, &icon))) {
            pane->prepareImages = ::ImageList_Create(Scale(16), Scale(16), ILC_COLOR32 | ILC_MASK, 1, 0);
            if (pane->prepareImages && ::ImageList_AddIcon(pane->prepareImages, icon.hIcon) >= 0) {
                BUTTON_IMAGELIST images{};
                images.himl = pane->prepareImages;
                images.margin = {Scale(6), 0, Scale(4), 0};
                images.uAlign = BUTTON_IMAGELIST_ALIGN_LEFT;
                ::SendMessageW(pane->prepareButton, BCM_SETIMAGELIST, 0, reinterpret_cast<LPARAM>(&images));
            }
            ::DestroyIcon(icon.hIcon);
        }
        const RECT initial{0, 0, 1, 1};
        pane->content = CreateActionAnalyzePage(hwnd, initial);
        if (!pane->content) return -1;
        ::ShowWindow(pane->content, SW_SHOWNA);
        Ui::SetWindowFontRecursive(hwnd);
        Refresh(*pane);
        Layout(*pane);
        return 0;
    }
    case kCatalog: {
        const auto& incoming = *reinterpret_cast<const ProjectReplayCatalog*>(lp);
        std::string selectedId;
        if (const auto* previous = Selected(*pane); previous && pane->catalog.projectId == incoming.projectId)
            selectedId = previous->breakpointDefinitionId;
        pane->catalog.projectId = incoming.projectId;
        pane->catalog.revisionId = incoming.revisionId;
        pane->catalog.manifestPath = incoming.manifestPath; // 载入草稿必须携带同一次发布的原项目路径。
        pane->catalog.breakpointDefinitions = incoming.breakpointDefinitions; // 只复制后台定义，不复制整份采样目录或证据。
        ::SendMessageW(pane->choice, CB_RESETCONTENT, 0, 0);
        if (pane->catalog.breakpointDefinitions) for (const auto& row : *pane->catalog.breakpointDefinitions) {
            auto label = ks::r3::process::Utf8ToWide(row.module.name) + L" · " + std::wstring(row.breakpointDefinitionId.begin(), row.breakpointDefinitionId.end());
            if (const auto* rva = std::get_if<Ksword::ActionAnalyze::BreakpointRva>(&row.location)) label += L" · RVA " + std::to_wstring(rva->rva);
            else label += L" · 符号/PDB";
            const auto index = ::SendMessageW(pane->choice, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(label.c_str()));
            if (index < 0) {
                ::SendMessageW(pane->choice, CB_RESETCONTENT, 0, 0);
                ::SetWindowTextW(pane->reason, L"无法显示断点定义列表，请重新打开项目。");
                ::EnableWindow(pane->prepareButton, FALSE);
                Layout(*pane);
                return 0;
            }
            if (row.breakpointDefinitionId == selectedId) ::SendMessageW(pane->choice, CB_SETCURSEL, index, 0);
        }
        if (::SendMessageW(pane->choice, CB_GETCURSEL, 0, 0) < 0 && pane->catalog.breakpointDefinitions && !pane->catalog.breakpointDefinitions->empty())
            ::SendMessageW(pane->choice, CB_SETCURSEL, 0, 0);
        Refresh(*pane);
        Layout(*pane);
        return 0;
    }
    case WM_SIZE: Layout(*pane); return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == kChoice && HIWORD(wp) == CBN_SELCHANGE) { Refresh(*pane); Layout(*pane); return 0; }
        if (LOWORD(wp) == kPrepare && HIWORD(wp) == BN_CLICKED) { Prepare(*pane); return 0; }
        break;
    case kFocusLightNativeToolbar:
        if (wp) {
            const HWND entry = ::IsWindowEnabled(pane->prepareButton) ? pane->prepareButton : pane->choice;
            pane->parameters.Reveal(entry);
            ::SetFocus(entry);
            return 1;
        }
        return ::SendMessageW(::GetParent(hwnd), message, wp, lp); // 原总览的正向边界仍回到原工具条。
    case Ui::kBeginNativeRetirementMessage: pane->retiring = true; Refresh(*pane); return 0;
    case Ui::kCancelNativeRetirementMessage: pane->retiring = false; Refresh(*pane); return 0;
    case WM_ERASEBKGND: {
        RECT area{};
        ::GetClientRect(hwnd, &area);
        ::FillRect(reinterpret_cast<HDC>(wp), &area, Ui::AppTheme().windowBrush());
        return 1;
    }
    case WM_CTLCOLORSTATIC: return Ui::PaintLabelBackground(reinterpret_cast<HDC>(wp), reinterpret_cast<HWND>(lp), Ui::AppTheme().windowBrush(), Ui::AppTheme().textColor);
    case WM_CTLCOLORLISTBOX:
        ::SetTextColor(reinterpret_cast<HDC>(wp), Ui::AppTheme().textColor);
        ::SetBkColor(reinterpret_cast<HDC>(wp), Ui::AppTheme().panelColor);
        return reinterpret_cast<LRESULT>(Ui::AppTheme().panelBrush());
    case WM_NCDESTROY:
        if (pane->prepareImages) ::ImageList_Destroy(pane->prepareImages);
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        delete pane;
        break;
    }
    return ::DefWindowProcW(hwnd, message, wp, lp);
}
}

void PublishProjectBreakpointCatalog(HWND source, const ProjectReplayCatalog& catalog) {
    if (!catalog.diagnostic.empty()) return;
    for (HWND host = ::GetParent(source); host; host = ::GetParent(host)) {
        wchar_t type[96]{};
        ::GetClassNameW(host, type, static_cast<int>(std::size(type)));
        if (std::wcscmp(type, kClass) == 0) {
            ::SendMessageW(host, kCatalog, 0, reinterpret_cast<LPARAM>(&catalog));
            return;
        }
    }
}

HWND CreateProjectBreakpointPane(HWND parent, const RECT& bounds, std::function<bool(const LightImageExecutionDraft&)> prepare) {
    WNDCLASSW type{};
    type.lpfnWndProc = Proc;
    type.hInstance = ::GetModuleHandleW(nullptr);
    type.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = Ui::AppTheme().windowBrush();
    type.lpszClassName = kClass;
    if (!::RegisterClassW(&type) && ::GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    return ::CreateWindowExW(WS_EX_CONTROLPARENT, kClass, L"项目断点入口", WS_CHILD | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top, parent, nullptr, type.hInstance, &prepare);
}
}
