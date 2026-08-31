#include "WindowToolsHierarchyView.h"

#include "WindowToolsCommon.h"
#include "../../Core/EntityRef.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/ExportUtil.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TextFindSupport.h"
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

constexpr wchar_t kHierarchyViewClass[] = L"KswordARKLight.WindowTools.HierarchyView";
constexpr wchar_t kHierarchyReportViewClass[] = L"KswordARKLight.WindowTools.HierarchyReportView";

constexpr int kRefreshButtonId = 67201;
constexpr int kFilterBarId = 67202;
constexpr int kWindowListId = 67203;
constexpr int kReportEditId = 67204;
constexpr int kLoadingOverlayId = 67205;
constexpr int kExportButtonId = 67206;

constexpr UINT kMenuCopyReport = 67641;
constexpr UINT kMenuCopyRow = 67642;
constexpr UINT kMenuCopyVisible = 67643;
constexpr UINT kMenuRefresh = 67644;
constexpr UINT kMenuOpenProcess = 67645;

constexpr UINT kMsgRefreshCompleted = WM_APP + 675;
constexpr UINT kMsgFilterCompleted = WM_APP + 676;

constexpr int kGap = 6;
constexpr int kRowHeight = 24;
constexpr int kHeaderHeight = kGap * 3 + kRowHeight * 2;
constexpr int kStatusHeight = 22;
constexpr int kColumnCount = 5;

// kAncestorChainLimit stops the parent walk from running forever. A well-formed
// chain ends at the desktop in a handful of steps; a handle that keeps returning
// a new parent means the tree changed under the walk, and a bound is the only
// way to leave that loop.
constexpr int kAncestorChainLimit = 32;
constexpr DWORD kDwmwaExtendedFrameBounds = 9;
constexpr DWORD kDwmwaCloaked = 14;
constexpr DWORD kDwmCloakedApp = 0x00000001;
constexpr DWORD kDwmCloakedShell = 0x00000002;
constexpr DWORD kDwmCloakedInherited = 0x00000004;

int Width(const RECT& rc) {
    return rc.right > rc.left ? static_cast<int>(rc.right - rc.left) : 0;
}

int Height(const RECT& rc) {
    return rc.bottom > rc.top ? static_cast<int>(rc.bottom - rc.top) : 0;
}

struct HierarchyFilterResult final {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::wstring selectedStableKey;
    std::vector<std::size_t> visibleIndexes;
};

struct HierarchyViewState final {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND exportButton = nullptr;
    HWND filterBar = nullptr;
    HWND reportEdit = nullptr;
    HWND loadingOverlay = nullptr;
    Ksword::Ui::VirtualListView windowList;
    std::vector<TopLevelWindowInfo> windows;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring statusText = L"正在枚举顶层窗口…";
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t displayGeneration = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<std::vector<TopLevelWindowInfo>>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<HierarchyFilterResult>> filterTask;
};

// DpiApi resolves the per-window DPI entry points at run time.
//
// These arrived in Windows 10 1607 and the SDK only declares them for a matching
// _WIN32_WINNT. Binding them late keeps this page working on an older target
// without gating the whole project's minimum version on one diagnostic field,
// and it lets the report say "本系统不提供" instead of failing to start.
struct DpiApi final {
    using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
    using GetWindowDpiAwarenessContextFn = void* (WINAPI*)(HWND);
    using GetAwarenessFromDpiAwarenessContextFn = int(WINAPI*)(void*);
    using GetDpiFromDpiAwarenessContextFn = UINT(WINAPI*)(void*);
    using AreDpiAwarenessContextsEqualFn = BOOL(WINAPI*)(void*, void*);

    GetDpiForWindowFn getDpiForWindow = nullptr;
    GetWindowDpiAwarenessContextFn getWindowContext = nullptr;
    GetAwarenessFromDpiAwarenessContextFn getAwareness = nullptr;
    GetDpiFromDpiAwarenessContextFn getDpiFromContext = nullptr;
    AreDpiAwarenessContextsEqualFn contextsEqual = nullptr;
};

// DwmApi is deliberately resolved at runtime. DwmGetWindowAttribute is useful
// evidence when it exists, but this diagnostic field must not add a load-time
// dwmapi dependency or narrow the systems on which Lite starts.
struct DwmApi final {
    using GetWindowAttributeFn = HRESULT(WINAPI*)(HWND, DWORD, PVOID, DWORD);

    GetWindowAttributeFn getWindowAttribute = nullptr;
};

const DpiApi& LoadDpiApi() {
    static const DpiApi api = [] {
        DpiApi loaded{};
        HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
        if (!user32) {
            return loaded;
        }
        loaded.getDpiForWindow =
            reinterpret_cast<DpiApi::GetDpiForWindowFn>(::GetProcAddress(user32, "GetDpiForWindow"));
        loaded.getWindowContext =
            reinterpret_cast<DpiApi::GetWindowDpiAwarenessContextFn>(::GetProcAddress(user32, "GetWindowDpiAwarenessContext"));
        loaded.getAwareness =
            reinterpret_cast<DpiApi::GetAwarenessFromDpiAwarenessContextFn>(::GetProcAddress(user32, "GetAwarenessFromDpiAwarenessContext"));
        loaded.getDpiFromContext =
            reinterpret_cast<DpiApi::GetDpiFromDpiAwarenessContextFn>(::GetProcAddress(user32, "GetDpiFromDpiAwarenessContext"));
        loaded.contextsEqual =
            reinterpret_cast<DpiApi::AreDpiAwarenessContextsEqualFn>(::GetProcAddress(user32, "AreDpiAwarenessContextsEqual"));
        return loaded;
    }();
    return api;
}

const DwmApi& LoadDwmApi() {
    static const DwmApi api = [] {
        DwmApi loaded{};
        HMODULE module = ::GetModuleHandleW(L"dwmapi.dll");
        if (!module) {
            module = ::LoadLibraryW(L"dwmapi.dll");
        }
        if (module) {
            loaded.getWindowAttribute = reinterpret_cast<DwmApi::GetWindowAttributeFn>(
                ::GetProcAddress(module, "DwmGetWindowAttribute"));
        }
        return loaded;
    }();
    return api;
}

// DpiContextSentinel builds one of the DPI_AWARENESS_CONTEXT pseudo-handles.
// They are small negative values rather than real pointers, which is why they
// can be reconstructed here without the SDK macros.
void* DpiContextSentinel(const std::intptr_t value) {
    return reinterpret_cast<void*>(value);
}

std::wstring DescribeDpiContext(void* context) {
    if (!context) {
        return L"(无)";
    }
    const DpiApi& api = LoadDpiApi();
    if (api.contextsEqual) {
        struct NamedContext final {
            std::intptr_t value;
            const wchar_t* name;
        };
        static const NamedContext kNamed[] = {
            { -1, L"DPI_AWARENESS_CONTEXT_UNAWARE" },
            { -2, L"DPI_AWARENESS_CONTEXT_SYSTEM_AWARE" },
            { -3, L"DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE" },
            { -4, L"DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2" },
            { -5, L"DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED" },
        };
        for (const NamedContext& named : kNamed) {
            if (api.contextsEqual(context, DpiContextSentinel(named.value))) {
                return named.name;
            }
        }
    }
    if (api.getAwareness) {
        switch (api.getAwareness(context)) {
        case 0: return L"DPI_AWARENESS_UNAWARE";
        case 1: return L"DPI_AWARENESS_SYSTEM_AWARE";
        case 2: return L"DPI_AWARENESS_PER_MONITOR_AWARE";
        default: break;
        }
    }
    return L"未知上下文 " + PointerText(reinterpret_cast<std::uint64_t>(context));
}

void AppendLine(std::wstring& text, const std::wstring& line) {
    text += line;
    text += L"\r\n";
}

void AppendSection(std::wstring& text, const wchar_t* title) {
    if (!text.empty()) {
        AppendLine(text, L"");
    }
    AppendLine(text, std::wstring(L"==== ") + title + L" ====");
}

void AppendField(std::wstring& text, const wchar_t* label, const std::wstring& value) {
    AppendLine(text, std::wstring(L"  ") + label + L"：" + value);
}

void AppendBits(std::wstring& text, const std::vector<std::wstring>& bits) {
    for (const std::wstring& bit : bits) {
        AppendLine(text, L"    " + bit);
    }
}

// AppendBasics writes the identity block. The window is revalidated by the
// caller, so everything here is a plain read.
void AppendBasics(std::wstring& text, HWND hwnd) {
    DWORD processId = 0;
    const DWORD threadId = ::GetWindowThreadProcessId(hwnd, &processId);
    std::wstring title = WindowTitleText(hwnd);
    if (title.empty()) {
        title = L"(无标题)";
    }
    AppendSection(text, L"基本信息");
    AppendField(text, L"窗口句柄", HwndText(hwnd));
    AppendField(text, L"标题", title);
    AppendField(text, L"类名", WindowClassText(hwnd));
    AppendField(text, L"进程", ProcessNameFromId(processId) + L"（PID " + std::to_wstring(processId) + L"）");
    AppendField(text, L"线程 ID", std::to_wstring(threadId));
    AppendField(text, L"可见 / 启用 / 最小化 / 最大化",
        std::wstring(::IsWindowVisible(hwnd) ? L"是" : L"否") + L" / " +
        (::IsWindowEnabled(hwnd) ? L"是" : L"否") + L" / " +
        (::IsIconic(hwnd) ? L"是" : L"否") + L" / " +
        (::IsZoomed(hwnd) ? L"是" : L"否"));
    AppendField(text, L"Unicode 窗口", ::IsWindowUnicode(hwnd) ? L"是" : L"否（窗口过程按 ANSI 收消息）");
}

// AppendAncestry writes the three GetAncestor results plus the walked chain.
//
// The three are not interchangeable: GA_PARENT stops at the immediate parent,
// GA_ROOT climbs to the top-level window, and GA_ROOTOWNER follows the owner
// links past it. A dialog owned by a main window has a different GA_ROOT and
// GA_ROOTOWNER, and that difference is usually the answer to "which window does
// this really belong to".
void AppendAncestry(std::wstring& text, HWND hwnd) {
    AppendSection(text, L"祖先链");
    AppendField(text, L"GetAncestor(GA_PARENT)", DescribeWindowBrief(::GetAncestor(hwnd, GA_PARENT)));
    AppendField(text, L"GetAncestor(GA_ROOT)", DescribeWindowBrief(::GetAncestor(hwnd, GA_ROOT)));
    AppendField(text, L"GetAncestor(GA_ROOTOWNER)", DescribeWindowBrief(::GetAncestor(hwnd, GA_ROOTOWNER)));
    AppendField(text, L"GetParent()", DescribeWindowBrief(::GetParent(hwnd)));
    AppendField(text, L"GetWindow(GW_OWNER)", DescribeWindowBrief(::GetWindow(hwnd, GW_OWNER)));

    AppendLine(text, L"  逐级父窗口（GA_PARENT 向上直到桌面）：");
    HWND current = ::GetAncestor(hwnd, GA_PARENT);
    int level = 0;
    while (current && level < kAncestorChainLimit) {
        AppendLine(text, L"    [" + std::to_wstring(level) + L"] " + DescribeWindowBrief(current));
        HWND next = ::GetAncestor(current, GA_PARENT);
        if (next == current) {
            break;
        }
        current = next;
        ++level;
    }
    if (level == 0) {
        AppendLine(text, L"    (无父窗口，已是顶层窗口)");
    } else if (level >= kAncestorChainLimit) {
        AppendLine(text, L"    (链长超过上限，已停止)");
    }
}

// AppendZOrder locates the window inside the top-level Z order.
//
// The index is computed by walking GW_HWNDNEXT from GetTopWindow rather than by
// reusing the list snapshot, because the snapshot is as old as the last refresh
// and Z order changes on every click somewhere else on the desktop.
void AppendZOrder(std::wstring& text, HWND hwnd) {
    AppendSection(text, L"Z 序");
    HWND root = ::GetAncestor(hwnd, GA_ROOT);
    int index = -1;
    int total = 0;
    for (HWND current = ::GetTopWindow(nullptr); current != nullptr; current = ::GetWindow(current, GW_HWNDNEXT)) {
        if (current == root && index < 0) {
            index = total;
        }
        ++total;
    }
    AppendField(text, L"顶层 Z 序位置", index >= 0
        ? L"第 " + std::to_wstring(index + 1) + L" / 共 " + std::to_wstring(total) + L"（序号越小越靠上）"
        : std::wstring(L"未在顶层 Z 序中找到（可能是子窗口或已关闭）"));
    AppendField(text, L"GetWindow(GW_HWNDPREV)", DescribeWindowBrief(::GetWindow(root, GW_HWNDPREV)));
    AppendField(text, L"GetWindow(GW_HWNDNEXT)", DescribeWindowBrief(::GetWindow(root, GW_HWNDNEXT)));
    AppendField(text, L"最顶层标志 WS_EX_TOPMOST",
        (static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE)) & WS_EX_TOPMOST) != 0 ? L"是" : L"否");
}

void AppendStyles(std::wstring& text, HWND hwnd) {
    const DWORD style = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_STYLE));
    const DWORD exStyle = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
    const bool isChild = (style & WS_CHILD) != 0;

    AppendSection(text, L"窗口样式");
    AppendField(text, L"GWL_STYLE", HexText(style, 8));
    AppendBits(text, DecodeWindowStyleBits(style, isChild));

    AppendSection(text, L"扩展样式");
    AppendField(text, L"GWL_EXSTYLE", HexText(exStyle, 8));
    AppendBits(text, DecodeWindowExStyleBits(exStyle));
}

// AppendClassInfo reports the class through two different doors.
//
// GetClassLongPtr takes an HWND and therefore works for any window on the
// desktop. GetClassInfoExW takes a class name and only finds classes registered
// in this process or marked CS_GLOBALCLASS, so it fails for most foreign
// windows. Both are shown because the failure itself is information: it tells
// the user the class lives in another process, not that the query broke.
void AppendClassInfo(std::wstring& text, HWND hwnd) {
    AppendSection(text, L"类信息");
    const std::wstring className = WindowClassText(hwnd);
    const DWORD classStyle = static_cast<DWORD>(::GetClassLongPtrW(hwnd, GCL_STYLE));
    const ULONG_PTR classAtom = ::GetClassLongPtrW(hwnd, GCW_ATOM);
    const ULONG_PTR classWndProc = ::GetClassLongPtrW(hwnd, GCLP_WNDPROC);
    const LONG_PTR windowWndProc = ::GetWindowLongPtrW(hwnd, GWLP_WNDPROC);

    AppendField(text, L"类名", className);
    AppendField(text, L"类原子 GCW_ATOM", HexText(classAtom, 4));
    AppendField(text, L"类样式 GCL_STYLE", HexText(classStyle, 8));
    AppendBits(text, DecodeClassStyleBits(classStyle));
    AppendField(text, L"类窗口过程 GCLP_WNDPROC", PointerText(static_cast<std::uint64_t>(classWndProc)));
    AppendField(text, L"实例窗口过程 GWLP_WNDPROC",
        PointerText(static_cast<std::uint64_t>(static_cast<ULONG_PTR>(windowWndProc))));
    AppendLine(text, classWndProc != static_cast<ULONG_PTR>(windowWndProc)
        ? L"    注：两者不同，通常说明该窗口被子类化。跨进程读到的可能是系统代理值，不能据此下结论。"
        : L"    注：两者相同，未观察到子类化痕迹。");
    AppendField(text, L"类额外字节 GCL_CBCLSEXTRA",
        std::to_wstring(static_cast<std::uint64_t>(::GetClassLongPtrW(hwnd, GCL_CBCLSEXTRA))));
    AppendField(text, L"窗口额外字节 GCL_CBWNDEXTRA",
        std::to_wstring(static_cast<std::uint64_t>(::GetClassLongPtrW(hwnd, GCL_CBWNDEXTRA))));

    WNDCLASSEXW classInfo{};
    classInfo.cbSize = sizeof(classInfo);
    bool resolved = false;
    if (!className.empty()) {
        resolved = ::GetClassInfoExW(::GetModuleHandleW(nullptr), className.c_str(), &classInfo) != FALSE;
        if (!resolved) {
            resolved = ::GetClassInfoExW(nullptr, className.c_str(), &classInfo) != FALSE;
        }
    }
    if (resolved) {
        AppendField(text, L"GetClassInfoExW", L"成功（该类在本进程可见）");
        AppendField(text, L"  style", HexText(classInfo.style, 8));
        AppendField(text, L"  lpfnWndProc", PointerText(reinterpret_cast<std::uint64_t>(classInfo.lpfnWndProc)));
        AppendField(text, L"  cbClsExtra / cbWndExtra",
            std::to_wstring(classInfo.cbClsExtra) + L" / " + std::to_wstring(classInfo.cbWndExtra));
        AppendField(text, L"  hInstance", PointerText(reinterpret_cast<std::uint64_t>(classInfo.hInstance)));
    } else {
        AppendField(text, L"GetClassInfoExW",
            L"失败：该窗口类未在本进程注册，也不是全局类。上面基于 HWND 的字段仍然有效。");
    }
}

void AppendGeometry(std::wstring& text, HWND hwnd) {
    AppendSection(text, L"几何");
    RECT windowRect{};
    RECT clientRect{};
    ::GetWindowRect(hwnd, &windowRect);
    ::GetClientRect(hwnd, &clientRect);
    AppendField(text, L"GetWindowRect（屏幕坐标）", RectText(windowRect));
    AppendField(text, L"GetClientRect（客户区坐标）", RectText(clientRect));

    POINT clientOrigin{ 0, 0 };
    if (::ClientToScreen(hwnd, &clientOrigin)) {
        AppendField(text, L"客户区左上角屏幕坐标",
            L"(" + std::to_wstring(clientOrigin.x) + L", " + std::to_wstring(clientOrigin.y) + L")");
        AppendField(text, L"非客户区边距（左 / 上）",
            std::to_wstring(clientOrigin.x - windowRect.left) + L" / " +
            std::to_wstring(clientOrigin.y - windowRect.top));
    }
}

void AppendDpi(std::wstring& text, HWND hwnd) {
    AppendSection(text, L"DPI 感知");
    const DpiApi& api = LoadDpiApi();
    if (api.getDpiForWindow) {
        const UINT dpi = api.getDpiForWindow(hwnd);
        AppendField(text, L"GetDpiForWindow", dpi != 0
            ? std::to_wstring(dpi) + L"（缩放 " + std::to_wstring(dpi * 100 / 96) + L"%）"
            : std::wstring(L"0（调用失败）"));
    } else {
        AppendField(text, L"GetDpiForWindow", L"本系统不提供该 API");
    }

    if (api.getWindowContext) {
        void* context = api.getWindowContext(hwnd);
        AppendField(text, L"GetWindowDpiAwarenessContext", DescribeDpiContext(context));
        if (context && api.getDpiFromContext) {
            const UINT contextDpi = api.getDpiFromContext(context);
            AppendField(text, L"GetDpiFromDpiAwarenessContext",
                contextDpi != 0 ? std::to_wstring(contextDpi) : std::wstring(L"0（上下文非固定 DPI）"));
        }
    } else {
        AppendField(text, L"GetWindowDpiAwarenessContext", L"本系统不提供该 API");
    }
}

std::wstring CloakStateText(const DWORD flags) {
    if (flags == 0) {
        return L"未 Cloak";
    }
    std::vector<std::wstring> sources;
    if ((flags & kDwmCloakedApp) != 0) {
        sources.push_back(L"应用");
    }
    if ((flags & kDwmCloakedShell) != 0) {
        sources.push_back(L"Shell");
    }
    if ((flags & kDwmCloakedInherited) != 0) {
        sources.push_back(L"继承");
    }
    std::wstring text = L"已 Cloak " + HexText(flags, 8);
    if (!sources.empty()) {
        text += L"（";
        for (std::size_t index = 0; index < sources.size(); ++index) {
            if (index != 0) {
                text += L" / ";
            }
            text += sources[index];
        }
        text += L"）";
    }
    return text;
}

std::wstring HresultText(const HRESULT status) {
    return HexText(static_cast<std::uint32_t>(status), 8);
}

std::wstring LayeredFlagsText(const DWORD flags) {
    std::wstring text = HexText(flags, 8);
    std::vector<std::wstring> names;
    if ((flags & LWA_ALPHA) != 0) {
        names.push_back(L"LWA_ALPHA");
    }
    if ((flags & LWA_COLORKEY) != 0) {
        names.push_back(L"LWA_COLORKEY");
    }
    if (!names.empty()) {
        text += L"（";
        for (std::size_t index = 0; index < names.size(); ++index) {
            if (index != 0) {
                text += L" / ";
            }
            text += names[index];
        }
        text += L"）";
    }
    return text;
}

// AppendCompositionState adds a small, explicit read-only composition block to
// the per-window report. Each query is independent so an unsupported DWM field
// never hides the documented User32 evidence or turns into a page-level error.
void AppendCompositionState(std::wstring& text, HWND hwnd) {
    AppendSection(text, L"合成与分层状态（只读）");

    const DwmApi& dwm = LoadDwmApi();
    if (!dwm.getWindowAttribute) {
        AppendField(text, L"DwmGetWindowAttribute", L"Unsupported（dwmapi.dll 或入口不可用）");
    } else {
        DWORD cloaked = 0;
        const HRESULT cloakStatus = dwm.getWindowAttribute(hwnd, kDwmwaCloaked, &cloaked, sizeof(cloaked));
        AppendField(text, L"DWMWA_CLOAKED", SUCCEEDED(cloakStatus)
            ? CloakStateText(cloaked)
            : L"Partial（HRESULT " + HresultText(cloakStatus) + L"）");

        RECT extendedFrame{};
        const HRESULT frameStatus = dwm.getWindowAttribute(
            hwnd, kDwmwaExtendedFrameBounds, &extendedFrame, sizeof(extendedFrame));
        AppendField(text, L"DWMWA_EXTENDED_FRAME_BOUNDS", SUCCEEDED(frameStatus)
            ? RectText(extendedFrame)
            : L"Partial（HRESULT " + HresultText(frameStatus) + L"）");
    }

    DWORD affinity = WDA_NONE;
    ::SetLastError(ERROR_SUCCESS);
    if (::GetWindowDisplayAffinity(hwnd, &affinity)) {
        AppendField(text, L"GetWindowDisplayAffinity", DisplayAffinityText(affinity, true));
    } else {
        AppendField(text, L"GetWindowDisplayAffinity",
            L"Partial（Win32=" + std::to_wstring(::GetLastError()) + L"）");
    }

    const DWORD exStyle = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
    if ((exStyle & WS_EX_LAYERED) == 0) {
        AppendField(text, L"GetLayeredWindowAttributes", L"不适用（未设置 WS_EX_LAYERED）");
    } else {
        COLORREF colorKey = 0;
        BYTE alpha = 0;
        DWORD flags = 0;
        ::SetLastError(ERROR_SUCCESS);
        if (::GetLayeredWindowAttributes(hwnd, &colorKey, &alpha, &flags)) {
            AppendField(text, L"GetLayeredWindowAttributes",
                L"Alpha=" + std::to_wstring(alpha) +
                L"  ColorKey=" + HexText(colorKey, 8) +
                L"  Flags=" + LayeredFlagsText(flags));
        } else {
            AppendField(text, L"GetLayeredWindowAttributes",
                L"Partial（Win32=" + std::to_wstring(::GetLastError()) + L"）");
        }
    }
}

std::wstring BuildHierarchyReport(HWND hwnd) {
    if (!hwnd) {
        return L"在左侧选择一个窗口，这里会显示它的祖先链、Z 序、样式位、类信息、几何与 DPI 感知上下文。";
    }
    if (!::IsWindow(hwnd)) {
        return L"该窗口句柄已失效（窗口已关闭）。请刷新窗口列表后重试。";
    }

    std::wstring text;
    AppendBasics(text, hwnd);
    AppendAncestry(text, hwnd);
    AppendZOrder(text, hwnd);
    AppendStyles(text, hwnd);
    AppendClassInfo(text, hwnd);
    AppendGeometry(text, hwnd);
    AppendDpi(text, hwnd);
    AppendCompositionState(text, hwnd);
    return text;
}

int SelectedModelIndex(const HierarchyViewState& state) {
    const HWND list = state.windowList.hwnd();
    const int selected = list ? ListView_GetNextItem(list, -1, LVNI_SELECTED) : -1;
    const auto& visible = state.windowList.visibleIndexes();
    if (selected < 0 || static_cast<std::size_t>(selected) >= visible.size()) {
        return -1;
    }
    const std::size_t modelIndex = visible[static_cast<std::size_t>(selected)];
    return modelIndex < state.windows.size() ? static_cast<int>(modelIndex) : -1;
}

HWND SelectedWindowHandle(const HierarchyViewState& state) {
    const int index = SelectedModelIndex(state);
    return index >= 0 ? state.windows[static_cast<std::size_t>(index)].hwnd : nullptr;
}

void ShowReportForSelection(HierarchyViewState& state) {
    if (!state.reportEdit) {
        return;
    }
    const std::wstring report = BuildHierarchyReport(SelectedWindowHandle(state));
    ::SetWindowTextW(state.reportEdit, report.c_str());
}

// SelectRowAtPoint makes row commands act on the window under the pointer,
// instead of retaining a selection that belongs to a different HWND.
void SelectRowAtPoint(HierarchyViewState& state, const POINT screenPoint) {
    const HWND list = state.windowList.hwnd();
    if (!list) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(list, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int clickedItem = ListView_SubItemHitTest(list, &hit);
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (clickedItem >= 0 && static_cast<std::size_t>(clickedItem) < state.windowList.visibleIndexes().size()) {
        ListView_SetItemState(list, clickedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ShowReportForSelection(state);
}

// CurrentProcessIdForWindow re-reads the owner from the live HWND. A snapshot
// PID is deliberately not used because a window can close or be recycled while
// the diagnostics page is open.
DWORD CurrentProcessIdForWindow(const HWND hwnd) {
    if (!hwnd || !::IsWindow(hwnd)) {
        return 0;
    }
    DWORD processId = 0;
    return ::GetWindowThreadProcessId(hwnd, &processId) != 0U ? processId : 0U;
}

std::wstring StableKeyFromListItem(const HierarchyViewState& state, const int item) {
    const auto& visible = state.windowList.visibleIndexes();
    const auto& rows = state.windowList.rows();
    if (item < 0 || static_cast<std::size_t>(item) >= visible.size()) {
        return {};
    }
    const std::size_t sourceIndex = visible[static_cast<std::size_t>(item)];
    return sourceIndex < rows.size() ? rows[sourceIndex].stableKey : std::wstring{};
}

void ApplyHierarchyFilter(HierarchyViewState& state, HierarchyFilterResult result) {
    if (result.generation != state.displayGeneration || result.query != state.filterQuery ||
        result.useRegex != state.filterUseRegex || !state.windowList.hwnd()) {
        return;
    }

    state.windowList.setVisibleIndexes(std::move(result.visibleIndexes));
    const auto& visible = state.windowList.visibleIndexes();
    const auto& rows = state.windowList.rows();
    int selectedItem = -1;
    for (std::size_t item = 0; item < visible.size(); ++item) {
        const std::size_t sourceIndex = visible[item];
        if (sourceIndex < rows.size() && rows[sourceIndex].stableKey == result.selectedStableKey) {
            selectedItem = static_cast<int>(item);
            break;
        }
    }

    HWND list = state.windowList.hwnd();
    ListView_SetItemState(list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    if (selectedItem >= 0) {
        ListView_SetItemState(list, selectedItem, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(list, selectedItem, FALSE);
    } else if (!visible.empty()) {
        ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ShowReportForSelection(state);
    if (!result.query.empty()) {
        state.statusText = L"筛选结果 " + std::to_wstring(visible.size()) + L" / " +
            std::to_wstring(rows.size()) + L" 个窗口。";
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void RequestHierarchyFilter(HierarchyViewState& state, std::wstring query, std::wstring selectedStableKey) {
    state.filterQuery = std::move(query);
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const auto rows = state.filterRows;
    const std::uint64_t generation = state.displayGeneration;
    const bool useRegex = state.filterUseRegex;
    if (!state.filterTask || !rows) {
        return;
    }
    state.filterTask->request(
        [rows, generation, useRegex, query = state.filterQuery,
            selectedStableKey = std::move(selectedStableKey)]() mutable {
            HierarchyFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.selectedStableKey = std::move(selectedStableKey);
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<HierarchyFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                state.statusText = L"窗口筛选任务异常结束，已保留当前结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            ApplyHierarchyFilter(state, std::move(*result));
        });
}

void BuildRows(HierarchyViewState& state) {
    std::vector<Ksword::Ui::VirtualListRow> rows;
    rows.reserve(state.windows.size());
    for (std::size_t index = 0; index < state.windows.size(); ++index) {
        const TopLevelWindowInfo& info = state.windows[index];
        Ksword::Ui::VirtualListRow row{};
        row.stableKey = HwndText(info.hwnd);
        row.itemData = static_cast<LPARAM>(index);
        row.cells.reserve(kColumnCount);
        row.cells.push_back(HwndText(info.hwnd));
        row.cells.push_back(info.title.empty() ? L"(无标题)" : info.title);
        row.cells.push_back(info.className);
        row.cells.push_back(std::to_wstring(info.processId));
        row.cells.push_back(info.processName);
        rows.push_back(std::move(row));
    }
    auto shared = std::make_shared<std::vector<Ksword::Ui::VirtualListRow>>(std::move(rows));
    state.windowList.setRows(*shared);
    state.filterRows = std::move(shared);
    ++state.displayGeneration;
}

void BeginRefresh(HierarchyViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    const bool firstLoad = state.windowList.rows().empty();
    state.statusText = state.refreshTask->running() ? L"刷新已排队，等待当前快照完成…" : L"正在后台枚举顶层窗口…";
    if (state.refreshButton) {
        ::EnableWindow(state.refreshButton, FALSE);
    }
    if (firstLoad) {
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在枚举顶层窗口…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.refreshTask->request(
        [] { return EnumerateTopLevelWindowInfo(); },
        [&state](std::uint64_t, std::optional<std::vector<TopLevelWindowInfo>>&& snapshot, std::exception_ptr error) {
            if (state.refreshButton) {
                ::EnableWindow(state.refreshButton, TRUE);
            }
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !snapshot.has_value()) {
                state.statusText = L"窗口枚举异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const std::wstring selectedStableKey =
                StableKeyFromListItem(state, ListView_GetNextItem(state.windowList.hwnd(), -1, LVNI_SELECTED));
            const std::size_t total = snapshot->size();
            state.windows = std::move(*snapshot);
            BuildRows(state);
            state.statusText = L"共 " + std::to_wstring(total) + L" 个顶层窗口，选中一行查看完整诊断。";
            RequestHierarchyFilter(state,
                state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery,
                selectedStableKey);
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

std::wstring ReportText(const HierarchyViewState& state) {
    const int length = state.reportEdit ? ::GetWindowTextLengthW(state.reportEdit) : 0;
    if (length <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(length) + 1U, L'\0');
    const int copied = ::GetWindowTextW(state.reportEdit, text.data(), length + 1);
    text.resize(copied > 0 ? static_cast<std::size_t>(copied) : 0U);
    return text;
}

void ExportVisibleRows(HierarchyViewState& state) {
    const std::wstring text = Ksword::Ui::BuildVisibleVirtualListTsv(
        { L"窗口句柄", L"标题", L"类名", L"PID", L"进程" }, state.windowList);
    if (text.empty()) {
        state.statusText = L"没有可导出的可见结果。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    std::wstring error;
    switch (Ksword::Ui::SaveUtf8TextFileWithDialog(state.hwnd, L"window_hierarchy.tsv", L"导出窗口层级诊断",
        L"TSV (*.tsv)\0*.tsv\0All Files (*.*)\0*.*\0", L"tsv", text, &error)) {
    case Ksword::Ui::SaveTextFileResult::Saved: state.statusText = L"窗口层级可见结果已导出。"; break;
    case Ksword::Ui::SaveTextFileResult::Cancelled: state.statusText = L"已取消导出窗口层级结果。"; break;
    case Ksword::Ui::SaveTextFileResult::Failed: state.statusText = L"导出窗口层级结果失败：" + error; break;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// OpenSelectedWindowProcess routes only the current owner PID observed from a
// live HWND. The process page resolves that PID again before it opens details.
void OpenSelectedWindowProcess(HierarchyViewState& state) {
    const HWND hwnd = SelectedWindowHandle(state);
    const DWORD processId = CurrentProcessIdForWindow(hwnd);
    if (processId == 0U) {
        state.statusText = L"所选窗口已关闭或无法读取当前所属 PID。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }

    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = processId;
    state.statusText = Ksword::Ui::RequestEntityNavigation(state.hwnd, request)
        ? L"已请求打开当前窗口所属 PID " + std::to_wstring(processId) +
            L" 的进程详细信息；目标页会重新确认当前进程实例。"
        : L"无法导航到当前窗口所属的进程实例。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void ShowContextMenu(HierarchyViewState& state, const POINT screenPoint) {
    SelectRowAtPoint(state, screenPoint);
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const HWND selectedWindow = SelectedWindowHandle(state);
    const bool hasSelection = selectedWindow != nullptr;
    const bool hasCurrentProcess = CurrentProcessIdForWindow(selectedWindow) != 0U;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyReport, L"复制诊断报告");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制选中行");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyVisible, L"复制可见行");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasCurrentProcess ? MF_ENABLED : MF_GRAYED),
        kMenuOpenProcess, L"查看当前窗口所属进程的详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新");

    const int command = ::TrackPopupMenu(
        menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);

    switch (static_cast<UINT>(command)) {
    case kMenuCopyReport:
        state.statusText = CopyTextToClipboard(state.hwnd, ReportText(state)) ? L"已复制诊断报告。" : L"复制失败。";
        break;
    case kMenuCopyRow:
        state.statusText = CopyTextToClipboard(state.hwnd, RowsAsTsv(state.windowList, false, kColumnCount))
            ? L"已复制选中行。" : L"复制失败。";
        break;
    case kMenuCopyVisible:
        state.statusText = CopyTextToClipboard(state.hwnd, RowsAsTsv(state.windowList, true, kColumnCount))
            ? L"已复制可见行。" : L"复制失败。";
        break;
    case kMenuOpenProcess:
        OpenSelectedWindowProcess(state);
        return;
    case kMenuRefresh:
        BeginRefresh(state);
        return;
    default:
        return;
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

void LayoutView(HierarchyViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);

    int cursorX = kGap;
    if (state.refreshButton) {
        ::MoveWindow(state.refreshButton, cursorX, kGap, 64, kRowHeight, TRUE);
    }
    cursorX += 64 + kGap;
    if (state.exportButton) {
        ::MoveWindow(state.exportButton, cursorX, kGap, 78, kRowHeight, TRUE);
    }
    const int secondRowY = kGap * 2 + kRowHeight;
    if (state.filterBar) {
        ::MoveWindow(state.filterBar, kGap, secondRowY, (std::max)(120, width - kGap * 2), kRowHeight, TRUE);
    }

    const int contentTop = kHeaderHeight;
    const int contentHeight = (std::max)(0, height - kStatusHeight - contentTop - kGap);
    const int listWidth = (std::max)(160, (width - kGap * 3) * 45 / 100);
    if (HWND list = state.windowList.hwnd()) {
        ::MoveWindow(list, kGap, contentTop, listWidth, contentHeight, TRUE);
    }
    if (state.loadingOverlay) {
        ::MoveWindow(state.loadingOverlay, kGap, contentTop, listWidth, contentHeight, TRUE);
    }
    if (state.reportEdit) {
        const int reportLeft = kGap * 2 + listWidth;
        ::MoveWindow(state.reportEdit, reportLeft, contentTop,
            (std::max)(0, width - reportLeft - kGap), contentHeight, TRUE);
    }
}

bool CreateChildControls(HierarchyViewState& state) {
    HWND hwnd = state.hwnd;
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"刷新", 0, 0, 0, 0);
    state.exportButton = Ksword::Ui::CreateButton(hwnd, kExportButtonId, L"导出 TSV", 0, 0, 0, 0);
    state.filterBar = Ksword::Ui::CreateFilterBar(hwnd, kFilterBarId, L"筛选句柄、标题、类名与进程", 0, 0, 0, 0);
    if (!state.refreshButton || !state.exportButton || !state.filterBar) {
        return false;
    }

    if (!state.windowList.create(hwnd, kWindowListId, 0, 0, 1, 1, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.windowList.addColumns({
        { 0, 130, LVCFMT_LEFT, L"窗口句柄" },
        { 1, 220, LVCFMT_LEFT, L"标题" },
        { 2, 170, LVCFMT_LEFT, L"类名" },
        { 3, 70,  LVCFMT_RIGHT, L"PID" },
        { 4, 150, LVCFMT_LEFT, L"进程" },
    });
    if (HWND list = state.windowList.hwnd()) {
        ListView_SetExtendedListViewStyle(list,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES | LVS_EX_LABELTIP);
    }

    state.reportEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
            ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 1, 1, hwnd, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kReportEditId)),
        ::GetModuleHandleW(nullptr), nullptr);
    if (!state.reportEdit) {
        return false;
    }
    Ksword::Ui::AttachTextFindSupport(state.reportEdit);

    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    if (!state.loadingOverlay) {
        return false;
    }

    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

LRESULT CALLBACK HierarchyViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    auto* state = reinterpret_cast<HierarchyViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    switch (msg) {
    case WM_NCCREATE: {
        auto owned = std::make_unique<HierarchyViewState>();
        owned->hwnd = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
        return TRUE;
    }
    case WM_CREATE:
        if (state) {
            if (!CreateChildControls(*state)) {
                return -1;
            }
            state->refreshTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<std::vector<TopLevelWindowInfo>>>(hwnd, kMsgRefreshCompleted);
            state->filterTask =
                std::make_unique<Ksword::Ui::AsyncSnapshotTask<HierarchyFilterResult>>(hwnd, kMsgFilterCompleted);
            LayoutView(*state);
            ShowReportForSelection(*state);
            BeginRefresh(*state);
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
                RequestHierarchyFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar),
                    StableKeyFromListItem(*state, ListView_GetNextItem(state->windowList.hwnd(), -1, LVNI_SELECTED)));
                return 0;
            }
            if (notification == BN_CLICKED && id == kRefreshButtonId) {
                BeginRefresh(*state);
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
                if (state->windowList.handleNotify(*header, result)) {
                    return result;
                }
                if (header->hwndFrom == state->windowList.hwnd() && header->code == LVN_ITEMCHANGED) {
                    const auto* changed = reinterpret_cast<const NMLISTVIEW*>(lParam);
                    if (changed && (changed->uNewState & LVIS_SELECTED) != 0) {
                        ShowReportForSelection(*state);
                    }
                    return 0;
                }
                if (header->hwndFrom == state->windowList.hwnd() && header->code == NM_RCLICK) {
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
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        if (state && reinterpret_cast<HWND>(lParam) == state->reportEdit) {
            ::SetBkColor(dc, Ksword::Ui::AppTheme().panelColor);
            return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().panelBrush());
        }
        ::SetBkMode(dc, TRANSPARENT);
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
            if (msg == kMsgRefreshCompleted && state->refreshTask) {
                state->refreshTask->consume(hwnd, wParam, lParam);
                return 0;
            }
            if (msg == kMsgFilterCompleted && state->filterTask) {
                state->filterTask->consume(hwnd, wParam, lParam);
                return 0;
            }
        }
        if (msg == WM_NCDESTROY && state) {
            if (state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state->filterTask) {
                state->filterTask->cancel();
            }
            state->windowList.detach();
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        }
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureHierarchyViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = HierarchyViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kHierarchyViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

struct HierarchyReportViewState final {
    HWND hwnd = nullptr;
    HWND reportEdit = nullptr;
};

HierarchyReportViewState* ReportStateFromWindow(HWND hwnd) {
    return reinterpret_cast<HierarchyReportViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

void LayoutHierarchyReportView(HierarchyReportViewState& state) {
    RECT client{};
    ::GetClientRect(state.hwnd, &client);
    const int width = Width(client);
    const int height = Height(client);
    if (state.reportEdit) {
        ::MoveWindow(state.reportEdit, kGap, 30, (std::max)(1, width - kGap * 2),
            (std::max)(1, height - 30 - kGap), TRUE);
    }
}

LRESULT CALLBACK HierarchyReportViewProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    HierarchyReportViewState* state = ReportStateFromWindow(hwnd);
    if (msg == WM_NCCREATE) {
        auto owned = std::make_unique<HierarchyReportViewState>();
        owned->hwnd = hwnd;
        state = owned.get();
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(owned.release()));
    }
    switch (msg) {
    case WM_NCCREATE:
        return TRUE;
    case WM_CREATE:
        if (!state) {
            return -1;
        }
        state->reportEdit = ::CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_VSCROLL | WS_HSCROLL |
                ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
            0, 0, 1, 1, hwnd, nullptr, ::GetModuleHandleW(nullptr), nullptr);
        if (!state->reportEdit) {
            return -1;
        }
        Ksword::Ui::AttachTextFindSupport(state->reportEdit);
        Ksword::Ui::SetWindowFontRecursive(hwnd);
        ::SetWindowTextW(state->reportEdit, BuildHierarchyReport(nullptr).c_str());
        LayoutHierarchyReportView(*state);
        return 0;
    case WM_SIZE:
        if (state) {
            LayoutHierarchyReportView(*state);
        }
        return 0;
    case WM_CTLCOLORSTATIC: {
        HDC dc = reinterpret_cast<HDC>(wParam);
        ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
        if (state && reinterpret_cast<HWND>(lParam) == state->reportEdit) {
            ::SetBkColor(dc, Ksword::Ui::AppTheme().panelColor);
            return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().panelBrush());
        }
        ::SetBkMode(dc, TRANSPARENT);
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
            RECT titleRect{ kGap, 0, client.right - kGap, 30 };
            Ksword::Ui::DrawTextLine(dc, L"窗口层级诊断（跟随左侧窗口选择）", titleRect,
                Ksword::Ui::AppTheme().textColor, Ksword::Ui::SystemUIFont(),
                DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
            ::EndPaint(hwnd, &paint);
            return 0;
        }
        break;
    case WM_NCDESTROY:
        delete state;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

bool EnsureHierarchyReportViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }
    WNDCLASSW windowClass{};
    windowClass.lpfnWndProc = HierarchyReportViewProc;
    windowClass.hInstance = ::GetModuleHandleW(nullptr);
    windowClass.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    windowClass.lpszClassName = kHierarchyReportViewClass;
    registered = ::RegisterClassW(&windowClass) != 0 || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
    return registered;
}

} // namespace

HWND CreateWindowHierarchyView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureHierarchyViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kHierarchyViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

HWND CreateWindowHierarchyReportView(HWND parent, const RECT& bounds) {
    if (!parent || !EnsureHierarchyReportViewClass()) {
        return nullptr;
    }
    return ::CreateWindowExW(
        0, kHierarchyReportViewClass, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top,
        parent, nullptr, ::GetModuleHandleW(nullptr), nullptr);
}

void UpdateWindowHierarchyReportView(HWND reportView, HWND selectedWindow) {
    HierarchyReportViewState* state = ReportStateFromWindow(reportView);
    if (!state || !state->reportEdit) {
        return;
    }
    const std::wstring report = BuildHierarchyReport(selectedWindow);
    ::SetWindowTextW(state->reportEdit, report.c_str());
}

} // namespace Ksword::Features::WindowTools
