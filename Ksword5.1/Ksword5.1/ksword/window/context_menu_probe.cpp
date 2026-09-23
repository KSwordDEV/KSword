// ============================================================
// context_menu_probe.cpp
// 作用：
// 1) 找出右键菜单的目标窗口；
// 2) 用 PostMessage(WM_CONTEXTMENU) 触发菜单、用 WinEvent 钩子精确计时、用
//    PostMessage(WM_CANCELMODE/WM_CLOSE) 关闭菜单，全程不产生任何输入事件；
// 3) 汇总采样窗口内目标进程的 CPU 消耗，给出"在算 / 在等"判定。
// ============================================================

#include "context_menu_probe.h"

#include <algorithm>
#include <atomic>

namespace ks::window
{
namespace
{
    // 菜单弹窗的窗口类名：user32 的所有弹出菜单都是这个类。
    constexpr wchar_t kMenuWindowClassName[] = L"#32768";

    // 桌面图标列表宿主类名：桌面视图（DefView）内部承载图标的就是它。
    constexpr wchar_t kShellDefViewClassName[] = L"SHELLDLL_DefView";

    // 资源管理器窗口类名（Win10 与老版本各一种）。
    constexpr wchar_t kCabinetWindowClassName[] = L"CabinetWClass";
    constexpr wchar_t kExploreWindowClassName[] = L"ExploreWClass";

    // ReadWindowClassName：读取窗口类名。
    // 入参 window：目标窗口；返回：类名（失败时为空字符串）。
    std::wstring ReadWindowClassName(HWND window)
    {
        wchar_t buffer[256] = {};
        const int length = ::GetClassNameW(window, buffer, static_cast<int>(std::size(buffer)));
        return length > 0 ? std::wstring(buffer, static_cast<std::size_t>(length)) : std::wstring();
    }

    // EnumerateTopLevelWindows：收集当前桌面上所有可见顶层窗口。
    // 入参：无；返回：窗口句柄数组（供后续按子窗口类名筛选）。
    std::vector<HWND> EnumerateTopLevelWindows()
    {
        std::vector<HWND> windows;

        // 回调只做收集，不做过滤，过滤逻辑放到后面便于复用。
        ::EnumWindows(
            [](HWND window, LPARAM context) -> BOOL
            {
                auto* output = reinterpret_cast<std::vector<HWND>*>(context);
                if (::IsWindowVisible(window))
                {
                    output->push_back(window);
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&windows));

        return windows;
    }

    // FindDefViewUnder：在指定窗口的直接子窗口里找 SHELLDLL_DefView。
    // 入参 parent：父窗口；返回：DefView 句柄，未找到返回 nullptr。
    HWND FindDefViewUnder(HWND parent)
    {
        for (HWND child = ::GetWindow(parent, GW_CHILD);
             child != nullptr;
             child = ::GetWindow(child, GW_HWNDNEXT))
        {
            if (ReadWindowClassName(child) == kShellDefViewClassName)
            {
                return child;
            }
        }
        return nullptr;
    }

    // FindMenuWindow：查找当前存在的菜单弹窗。
    // 入参：无；返回：菜单窗口句柄，没有则返回 nullptr。
    HWND FindMenuWindow()
    {
        return ::FindWindowW(kMenuWindowClassName, nullptr);
    }

    // CloseAnyOpenMenu：把可能残留的菜单关掉。
    // 说明：只投递窗口消息（WM_CANCELMODE / WM_CLOSE），不注入键盘鼠标。
    // 入参：无；返回：无。
    void CloseAnyOpenMenu()
    {
        // 最多尝试若干轮：菜单的关闭是异步的，投递后需要给它一点时间。
        for (int attempt = 0; attempt < 6; ++attempt)
        {
            HWND menu = FindMenuWindow();
            if (menu == nullptr)
            {
                return;
            }
            ::PostMessageW(menu, WM_CANCELMODE, 0, 0);
            ::PostMessageW(menu, WM_CLOSE, 0, 0);
            ::Sleep(40);
        }
    }

    // QueryProcessCpuMs：读取进程累计 CPU 时间（用户态 + 内核态，单位毫秒）。
    // 入参 process：已打开的进程句柄；返回：累计 CPU 毫秒；读失败返回 -1。
    double QueryProcessCpuMs(HANDLE process)
    {
        FILETIME createTime = {};
        FILETIME exitTime = {};
        FILETIME kernelTime = {};
        FILETIME userTime = {};
        if (!::GetProcessTimes(process, &createTime, &exitTime, &kernelTime, &userTime))
        {
            return -1.0;
        }

        // FILETIME 以 100 纳秒为单位；换算成毫秒需要除以 10000。
        const auto toMilliseconds = [](const FILETIME& value) -> double
        {
            ULARGE_INTEGER merged = {};
            merged.LowPart = value.dwLowDateTime;
            merged.HighPart = value.dwHighDateTime;
            return static_cast<double>(merged.QuadPart) / 10000.0;
        };
        return toMilliseconds(kernelTime) + toMilliseconds(userTime);
    }

    // 采样线程内的 WinEvent 接收状态。
    // 说明：WinEvent 回调在安装钩子的线程上被调用（本函数所在线程自己泵消息），
    // 因此这两个变量天然只被同一线程访问，用 atomic 只是为了明确语义。
    std::atomic<bool> g_menuPopupObserved{ false };
    std::atomic<long long> g_menuPopupTick{ 0 };

    // MenuEventCallback：WinEvent 回调，记录菜单弹出的高精度时刻。
    // 入参：事件号与窗口句柄（其余参数本项目不使用）。
    // 返回：无。
    void CALLBACK MenuEventCallback(
        HWINEVENTHOOK, DWORD event, HWND, LONG, LONG, DWORD, DWORD)
    {
        if (event == EVENT_SYSTEM_MENUPOPUPSTART)
        {
            LARGE_INTEGER counter = {};
            ::QueryPerformanceCounter(&counter);
            g_menuPopupTick.store(counter.QuadPart);
            g_menuPopupObserved.store(true);
        }
    }

    // WaitForMenuWithMessagePump：在等待菜单出现期间泵本线程消息，让 WinEvent 回调得以执行。
    // 入参 timeoutCounter：等待截止的 QPC 计数；frequency：QPC 频率。
    // 返回：观测到菜单返回 true，超时返回 false。
    bool WaitForMenuWithMessagePump(long long timeoutCounter, long long frequency)
    {
        MSG message = {};
        for (;;)
        {
            if (g_menuPopupObserved.load())
            {
                return true;
            }

            // 收到消息就派发，保证 WinEvent 回调被执行；没有消息则短暂让出 CPU。
            while (::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
            {
                ::TranslateMessage(&message);
                ::DispatchMessageW(&message);
            }

            LARGE_INTEGER counter = {};
            ::QueryPerformanceCounter(&counter);
            if (counter.QuadPart >= timeoutCounter)
            {
                return g_menuPopupObserved.load();
            }
            ::Sleep(1);
        }
    }

    // ResolveDesktopTriggerPoint：计算桌面上下发右键的屏幕坐标。
    // 说明：取屏幕右下方向的一块空白区域，避开左上角的图标列。
    // 入参：无；返回：屏幕坐标（物理像素）。
    POINT ResolveDesktopTriggerPoint()
    {
        POINT point = {};
        point.x = std::max(10L, ::GetSystemMetrics(SM_CXSCREEN) - 420L);
        point.y = std::max(10L, ::GetSystemMetrics(SM_CYSCREEN) - 420L);
        return point;
    }

    // ResolveWindowTriggerPoint：计算指定窗口内部下发的屏幕坐标。
    // 入参 window：目标窗口；返回：屏幕坐标。
    POINT ResolveWindowTriggerPoint(HWND window)
    {
        RECT rect = {};
        ::GetWindowRect(window, &rect);
        POINT point = {};
        // 取靠下位置：列表项从顶部开始排，底部通常是空白区。
        point.x = rect.left + 300;
        point.y = rect.bottom - 60;
        return point;
    }
}  // namespace

HWND FindProbeTargetWindow(const MenuProbeContext context, std::string* diagnosticOut)
{
    // 桌面空白处：桌面视图挂在 Progman 或某个 WorkerW 之下（两种布局都要覆盖），
    // 实际接收 WM_CONTEXTMENU 的是 DefView 里的图标列表窗口。
    if (context == MenuProbeContext::DesktopBackground)
    {
        for (HWND topLevel : EnumerateTopLevelWindows())
        {
            HWND defView = FindDefViewUnder(topLevel);
            if (defView == nullptr)
            {
                continue;
            }
            HWND iconList = ::GetWindow(defView, GW_CHILD);
            if (iconList != nullptr)
            {
                return iconList;
            }
        }
        if (diagnosticOut != nullptr)
        {
            *diagnosticOut = "未找到桌面视图窗口（Explorer 未运行或桌面未被枚举到）";
        }
        return nullptr;
    }

    // 文件夹空白处：任意一个可见的资源管理器窗口的 DefView。
    for (HWND topLevel : EnumerateTopLevelWindows())
    {
        const std::wstring className = ReadWindowClassName(topLevel);
        if (className != kCabinetWindowClassName && className != kExploreWindowClassName)
        {
            continue;
        }
        if (HWND defView = FindDefViewUnder(topLevel); defView != nullptr)
        {
            return defView;
        }
    }
    if (diagnosticOut != nullptr)
    {
        *diagnosticOut = "未找到已打开的文件夹窗口（本上下文需要先打开一个资源管理器窗口）";
    }
    return nullptr;
}

MenuProbeMeasurement MeasureMenuOpenLatency(
    const MenuProbeContext context,
    const unsigned long targetProcessId,
    const MenuProbeOptions& options)
{
    MenuProbeMeasurement measurement;

    // 目标窗口：拿不到就整节不做，并把原因交给调用方展示（覆盖缺口不能当"没差异"）。
    std::string windowDiagnostic;
    HWND target = FindProbeTargetWindow(context, &windowDiagnostic);
    if (target == nullptr)
    {
        measurement.attempted = false;
        measurement.diagnostic = windowDiagnostic;
        measurement.verdict = "unknown";
        return measurement;
    }

    // 目标进程句柄：只用于读 CPU 时间；读不到不影响耗时测量，只影响"在算/在等"判定。
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, targetProcessId);
    const auto processCpuBefore = process != nullptr ? QueryProcessCpuMs(process) : -1.0;

    LARGE_INTEGER frequency = {};
    ::QueryPerformanceFrequency(&frequency);

    // 安装 WinEvent 钩子：只订阅菜单弹出/关闭，跳过本进程自身的事件。
    HWINEVENTHOOK hook = ::SetWinEventHook(
        EVENT_SYSTEM_MENUPOPUPSTART,
        EVENT_SYSTEM_MENUPOPUPEND,
        nullptr,
        MenuEventCallback,
        0,
        0,
        WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    if (hook == nullptr)
    {
        if (process != nullptr)
        {
            ::CloseHandle(process);
        }
        measurement.attempted = false;
        measurement.diagnostic = "SetWinEventHook 失败，无法精确计时";
        measurement.verdict = "unknown";
        return measurement;
    }

    const POINT triggerPoint = context == MenuProbeContext::DesktopBackground
        ? ResolveDesktopTriggerPoint()
        : ResolveWindowTriggerPoint(target);
    const LPARAM packedPoint = MAKELPARAM(triggerPoint.x, triggerPoint.y);

    LARGE_INTEGER wallStart = {};
    ::QueryPerformanceCounter(&wallStart);

    measurement.attempted = true;
    const int sampleCount = std::max(1, options.samples);
    for (int index = 0; index < sampleCount; ++index)
    {
        // 每次采样前先确保没有残留菜单，否则计时起点会算错。
        CloseAnyOpenMenu();
        g_menuPopupObserved.store(false);
        g_menuPopupTick.store(0);

        LARGE_INTEGER start = {};
        ::QueryPerformanceCounter(&start);
        ::PostMessageW(target, WM_CONTEXTMENU, reinterpret_cast<WPARAM>(target), packedPoint);

        LARGE_INTEGER deadline = {};
        deadline.QuadPart = start.QuadPart
            + frequency.QuadPart * std::max(1, options.perSampleTimeoutMs) / 1000;
        const bool observed = WaitForMenuWithMessagePump(deadline.QuadPart, frequency.QuadPart);

        MenuProbeSample sample;
        if (observed)
        {
            const long long popupTick = g_menuPopupTick.load();
            sample.menuSeen = true;
            sample.openMs = popupTick > start.QuadPart
                ? static_cast<double>(popupTick - start.QuadPart) * 1000.0
                    / static_cast<double>(frequency.QuadPart)
                : 0.0;
        }
        measurement.samples.push_back(sample);

        CloseAnyOpenMenu();
        if (options.gapMs > 0)
        {
            ::Sleep(static_cast<DWORD>(options.gapMs));
        }
    }

    LARGE_INTEGER wallEnd = {};
    ::QueryPerformanceCounter(&wallEnd);
    measurement.wallMs = static_cast<double>(wallEnd.QuadPart - wallStart.QuadPart) * 1000.0
        / static_cast<double>(frequency.QuadPart);

    const auto processCpuAfter = process != nullptr ? QueryProcessCpuMs(process) : -1.0;
    if (processCpuBefore >= 0.0 && processCpuAfter >= processCpuBefore && measurement.wallMs > 0.0)
    {
        measurement.processCpuMeasured = true;
        measurement.processCpuMs = processCpuAfter - processCpuBefore;
        measurement.cpuRatio = measurement.processCpuMs / measurement.wallMs;
    }

    // 汇总统计：只统计真正看到菜单的采样。
    std::vector<double> successful;
    for (const MenuProbeSample& sample : measurement.samples)
    {
        if (sample.menuSeen)
        {
            successful.push_back(sample.openMs);
        }
    }
    if (successful.empty())
    {
        measurement.diagnostic = "全部采样都没有观测到菜单出现（可能被策略禁用或被其它程序接管）";
        measurement.verdict = "unknown";
    }
    else
    {
        std::sort(successful.begin(), successful.end());
        measurement.minMs = successful.front();
        measurement.maxMs = successful.back();
        measurement.medianMs = successful[successful.size() / 2];

        // 判定：CPU 占比够高说明确实在计算；否则就是在等外部对象。
        if (measurement.processCpuMeasured)
        {
            measurement.verdict =
                measurement.cpuRatio >= kMenuProbeComputingRatio ? "computing" : "waiting";
        }
        else
        {
            measurement.verdict = "unknown";
            measurement.diagnostic = "无法读取目标进程 CPU 时间，未给出在算/在等判定";
        }
    }

    ::UnhookWinEvent(hook);
    if (process != nullptr)
    {
        ::CloseHandle(process);
    }
    return measurement;
}
}  // namespace ks::window
