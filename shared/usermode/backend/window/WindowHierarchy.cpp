#include "WindowHierarchy.h"
#include <algorithm>
#include <array>
#include <cwchar>
#include <sstream>
#include <iomanip>
#include <set>
#include <chrono>
namespace ks::r3::window_tools {
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
    struct Library {
        HMODULE module = ::GetModuleHandleW(L"dwmapi.dll");
        bool owned = false;
        Library() {if (!module) {module = ::LoadLibraryW(L"dwmapi.dll");owned = module != nullptr;}}
        ~Library() {if (owned) ::FreeLibrary(module);}
    };
    static const Library library;
    static const DwmApi api = [] {
        DwmApi loaded{};
        HMODULE module = library.module;
        if (module) {
            loaded.getWindowAttribute = reinterpret_cast<DwmApi::GetWindowAttributeFn>(
                ::GetProcAddress(module, "DwmGetWindowAttribute"));
        }
        return loaded;
    }();
    return api;
}
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
void AppendZOrder(std::wstring& text, HWND hwnd) {
    AppendSection(text, L"Z 序");
    HWND root = ::GetAncestor(hwnd, GA_ROOT);
    int index = -1;
    int total = 0;
    std::set<HWND> visited;const auto started = std::chrono::steady_clock::now();
    for (HWND current = ::GetTopWindow(nullptr); current != nullptr; current = ::GetWindow(current, GW_HWNDNEXT)) {
        if (!visited.insert(current).second || total>=100000 || std::chrono::steady_clock::now()-started>std::chrono::seconds(8)) break;
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
HierarchySnapshot QueryHierarchySnapshot(HWND hwnd) {
    HierarchySnapshot s;if (!::IsWindow(hwnd)) return s;s.threadId = ::GetWindowThreadProcessId(hwnd,&s.processId);
    if (!s.threadId || !s.processId) return s;s.found = true;
    const auto append = [&s](HierarchyField field) {s.fields.push_back(std::move(field));};
    const auto pointer = [&](const wchar_t* name,const auto& query) {
        ::SetLastError(ERROR_SUCCESS);const auto value = query();const auto error = ::GetLastError();HierarchyField f;
        f.name = name;f.kind = HierarchyValueKind::Pointer;f.number = reinterpret_cast<std::uintptr_t>(value);f.available = value || !error;
        f.domain = L"win32";f.errorKnown = !f.available;f.error = error;append(f);return value;
    };
    pointer(L"parent",[&]{return ::GetParent(hwnd);});pointer(L"ancestorParent",[&]{return ::GetAncestor(hwnd,GA_PARENT);});
    const auto root = pointer(L"root",[&]{return ::GetAncestor(hwnd,GA_ROOT);});
    pointer(L"rootOwner",[&]{return ::GetAncestor(hwnd,GA_ROOTOWNER);});pointer(L"owner",[&]{return ::GetWindow(hwnd,GW_OWNER);});
    pointer(L"previous",[&]{return ::GetWindow(root,GW_HWNDPREV);});pointer(L"next",[&]{return ::GetWindow(root,GW_HWNDNEXT);});
    std::set<HWND> ancestors;::SetLastError(ERROR_SUCCESS);auto current = ::GetAncestor(hwnd,GA_PARENT);if (!current) s.chainError = ::GetLastError();
    for (int i = 0;current && i<kAncestorChainLimit;++i) {
        if (!ancestors.insert(current).second) {s.chainCycle = true;break;}
        s.parentChain.push_back(current);::SetLastError(ERROR_SUCCESS);const auto next = ::GetAncestor(current,GA_PARENT);
        if (!next && ::GetLastError()) {s.chainError = ::GetLastError();break;}current = next;
    }
    s.chainComplete = !current && !s.chainError;s.chainLimited = current && !s.chainCycle && s.parentChain.size()>=kAncestorChainLimit;
    std::set<HWND> order;const auto started = std::chrono::steady_clock::now();::SetLastError(ERROR_SUCCESS);current = ::GetTopWindow(nullptr);
    if (!current) {s.zError = ::GetLastError();s.zComplete = !s.zError;}
    while (current) {
        if (!order.insert(current).second) {s.zCycle = true;break;}
        if (s.zCount>=100000 || std::chrono::steady_clock::now()-started>std::chrono::seconds(8)) {s.zLimited = true;break;}
        if (current == root) s.zIndex = static_cast<int>(s.zCount);++s.zCount;::SetLastError(ERROR_SUCCESS);
        const auto next = ::GetWindow(current,GW_HWNDNEXT);if (!next) {s.zError = ::GetLastError();s.zComplete = !s.zError;break;}current = next;
    }
    const auto scalar = [&](const wchar_t* name,const auto& query,HierarchyValueKind kind) {
        ::SetLastError(ERROR_SUCCESS);const auto value = query();const auto error = ::GetLastError();HierarchyField f;
        f.name = name;f.kind = kind;f.number = kind == HierarchyValueKind::Unsigned ? static_cast<DWORD>(value) : static_cast<std::uint64_t>(static_cast<std::uintptr_t>(value));f.signedNumber = static_cast<std::int64_t>(value);
        f.available = value != 0 || !error;f.domain = L"win32";f.errorKnown = !f.available;f.error = error;append(f);return f;
    };
    const auto style = scalar(L"style",[&]{return ::GetWindowLongPtrW(hwnd,GWL_STYLE);},HierarchyValueKind::Unsigned);
    const auto exStyle = scalar(L"exStyle",[&]{return ::GetWindowLongPtrW(hwnd,GWL_EXSTYLE);},HierarchyValueKind::Unsigned);
    const auto classStyle = scalar(L"classStyle",[&]{return ::GetClassLongPtrW(hwnd,GCL_STYLE);},HierarchyValueKind::Unsigned);
    scalar(L"classAtom",[&]{return ::GetClassLongPtrW(hwnd,GCW_ATOM);},HierarchyValueKind::Unsigned);
    scalar(L"classProcedure",[&]{return ::GetClassLongPtrW(hwnd,GCLP_WNDPROC);},HierarchyValueKind::Pointer);
    scalar(L"windowProcedure",[&]{return ::GetWindowLongPtrW(hwnd,GWLP_WNDPROC);},HierarchyValueKind::Pointer);
    scalar(L"classExtraBytes",[&]{return ::GetClassLongPtrW(hwnd,GCL_CBCLSEXTRA);},HierarchyValueKind::Unsigned);
    scalar(L"windowExtraBytes",[&]{return ::GetClassLongPtrW(hwnd,GCL_CBWNDEXTRA);},HierarchyValueKind::Unsigned);
    for (const auto& pair:{std::pair{L"styleBits",&style},std::pair{L"exStyleBits",&exStyle},std::pair{L"classStyleBits",&classStyle}}) {
        HierarchyField f;f.name = pair.first;f.kind = HierarchyValueKind::Strings;f.available = pair.second->available;
        if (f.available) {const auto bits = static_cast<DWORD>(pair.second->number);
            f.strings = pair.first == std::wstring(L"styleBits") ? DecodeWindowStyleBits(bits,(bits&WS_CHILD)!=0) : pair.first == std::wstring(L"exStyleBits") ? DecodeWindowExStyleBits(bits) : DecodeClassStyleBits(bits);}
        append(f);
    }
    std::array<wchar_t,512> className{};::SetLastError(ERROR_SUCCESS);const auto classLength = ::GetClassNameW(hwnd,className.data(),static_cast<int>(className.size()));
    const std::wstring name = classLength>0 ? std::wstring(className.data(),static_cast<std::size_t>(classLength)) : std::wstring{};
    HierarchyField classNameField;classNameField.name = L"className";classNameField.kind = HierarchyValueKind::Text;classNameField.available = classLength>0 && classLength<static_cast<int>(className.size())-1;
    classNameField.text = name;classNameField.domain = L"win32";classNameField.errorKnown = classLength<=0;classNameField.error = ::GetLastError();append(classNameField);
    WNDCLASSEXW cls{};cls.cbSize = sizeof(cls);bool local = false;DWORD classError = ERROR_SUCCESS;
    if (!name.empty()) {local = ::GetClassInfoExW(::GetModuleHandleW(nullptr),name.c_str(),&cls) != FALSE;
        if (!local) {::SetLastError(ERROR_SUCCESS);local = ::GetClassInfoExW(nullptr,name.c_str(),&cls) != FALSE;if (!local) classError = ::GetLastError();}}
    HierarchyField registration;registration.name = L"callerClassRegistration";registration.kind = HierarchyValueKind::Boolean;
    registration.available = local;registration.number = local;registration.notApplicable = !local && classError == ERROR_CLASS_DOES_NOT_EXIST;registration.domain = L"win32";registration.errorKnown = !local;registration.error = classError;append(registration);
    if (local) {
        for (const auto& item:{std::pair{L"callerClassProcedure",reinterpret_cast<std::uintptr_t>(cls.lpfnWndProc)},std::pair{L"callerClassInstance",reinterpret_cast<std::uintptr_t>(cls.hInstance)}}) {
            HierarchyField f;f.name = item.first;f.kind = HierarchyValueKind::Pointer;f.available = true;f.number = item.second;append(f);
        }
        for (const auto& item:{std::pair{L"callerClassStyle",cls.style},std::pair{L"callerClassExtraBytes",static_cast<UINT>(cls.cbClsExtra)},std::pair{L"callerWindowExtraBytes",static_cast<UINT>(cls.cbWndExtra)}}) {
            HierarchyField f;f.name = item.first;f.available = true;f.number = item.second;append(f);
        }
    }
    for (const auto* id:{L"windowRect",L"clientRect"}) {
        ::SetLastError(ERROR_SUCCESS);
        HierarchyField f;f.name = id;f.kind = HierarchyValueKind::Rectangle;f.domain = L"win32";
        f.available = std::wstring(id) == L"windowRect" ? ::GetWindowRect(hwnd,&f.rectangle) != FALSE : ::GetClientRect(hwnd,&f.rectangle) != FALSE;
        if (!f.available) {f.errorKnown = true;f.error = ::GetLastError();}append(f);
    }
    HierarchyField origin;origin.name = L"clientOriginScreen";origin.kind = HierarchyValueKind::Point;origin.domain = L"win32";
    ::SetLastError(ERROR_SUCCESS);
    origin.available = ::ClientToScreen(hwnd,&origin.point) != FALSE;if (!origin.available) {origin.errorKnown = true;origin.error = ::GetLastError();}append(origin);
    const auto& dpi = LoadDpiApi();void* context = nullptr;
    if (dpi.getWindowContext) {context = dpi.getWindowContext(hwnd);HierarchyField f;f.name = L"dpiContext";f.kind = HierarchyValueKind::Pointer;f.available = context != nullptr;f.number = reinterpret_cast<std::uintptr_t>(context);append(f);}
    else {HierarchyField f;f.name = L"dpiContext";append(f);}
    if (context) {HierarchyField f;f.name = L"dpiContextDisplay";f.kind = HierarchyValueKind::Text;f.available = true;f.text = DescribeDpiContext(context);append(f);}
    for (const auto* id:{L"windowDpi",L"contextDpi",L"dpiAwareness"}) {
        HierarchyField f;f.name = id;f.kind = std::wstring(id) == L"dpiAwareness" ? HierarchyValueKind::Signed : HierarchyValueKind::Unsigned;
        if (std::wstring(id) == L"windowDpi" && dpi.getDpiForWindow) {f.number = dpi.getDpiForWindow(hwnd);f.available = f.number != 0;}
        if (std::wstring(id) == L"contextDpi" && context && dpi.getDpiFromContext) {f.number = dpi.getDpiFromContext(context);f.available = f.number != 0;f.notApplicable = !f.available;}
        if (std::wstring(id) == L"dpiAwareness" && context && dpi.getAwareness) {f.signedNumber = dpi.getAwareness(context);f.available = f.signedNumber>=0;}
        append(f);
    }
    const auto& dwm = LoadDwmApi();
    for (const auto& pair:{std::pair{L"cloaked",kDwmwaCloaked},std::pair{L"extendedFrameBounds",kDwmwaExtendedFrameBounds}}) {
        HierarchyField f;f.name = pair.first;f.domain = L"hresult";f.kind = pair.second == kDwmwaCloaked ? HierarchyValueKind::Unsigned : HierarchyValueKind::Rectangle;
        if (dwm.getWindowAttribute) {DWORD cloak = 0;const auto status = pair.second == kDwmwaCloaked ? dwm.getWindowAttribute(hwnd,pair.second,&cloak,sizeof(cloak)) : dwm.getWindowAttribute(hwnd,pair.second,&f.rectangle,sizeof(f.rectangle));
            f.available = status == S_OK;f.errorKnown = true;f.error = static_cast<DWORD>(status);f.number = cloak;}
        append(f);
    }
    HierarchyField capture;capture.name = L"displayAffinity";capture.domain = L"win32";DWORD policy = 0;::SetLastError(ERROR_SUCCESS);
    capture.available = ::GetWindowDisplayAffinity(hwnd,&policy) != FALSE;capture.number = policy;if (!capture.available) {capture.errorKnown = true;capture.error = ::GetLastError();}append(capture);
    HierarchyField layered;layered.name = L"layeredAttributes";layered.kind = HierarchyValueKind::Strings;layered.domain = L"win32";
    if (exStyle.available && !(exStyle.number&WS_EX_LAYERED)) layered.notApplicable = true;
    else if (exStyle.available) {COLORREF color = 0;BYTE alpha = 0;DWORD flags = 0;::SetLastError(ERROR_SUCCESS);
        layered.available = ::GetLayeredWindowAttributes(hwnd,&color,&alpha,&flags) != FALSE;
        if (layered.available) {
            for (const auto& item:{std::pair{L"layeredAlpha",static_cast<DWORD>(alpha)},std::pair{L"layeredColorKey",color},std::pair{L"layeredFlags",flags}}) {HierarchyField f;f.name = item.first;f.available = true;f.number = item.second;append(f);}
            layered.strings = {LayeredFlagsText(flags)};
        } else {layered.errorKnown = true;layered.error = ::GetLastError();}}
    append(layered);DWORD afterPid = 0;const auto afterTid = ::GetWindowThreadProcessId(hwnd,&afterPid);s.stable = ::IsWindow(hwnd) && afterPid == s.processId && afterTid == s.threadId;return s;
}
}
