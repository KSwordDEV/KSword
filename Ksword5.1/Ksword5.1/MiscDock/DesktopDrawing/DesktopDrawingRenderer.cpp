#include "DesktopDrawingRenderer.h"

#include <algorithm>
#include <cmath>
#include <cwchar>

#pragma comment(lib, "Gdi32.lib")
#pragma comment(lib, "User32.lib")

namespace
{
    // 只改变本次调用的线程上下文；返回 Qt 事件循环前必须还原。
    class PhysicalPixels final
    {
    public:
        PhysicalPixels()
        {
            const HMODULE user32 = ::GetModuleHandleW(L"user32.dll");
            m_setContext = user32 ? reinterpret_cast<SetContext>(
                ::GetProcAddress(user32, "SetThreadDpiAwarenessContext")) : nullptr;
            if (m_setContext)
            {
                m_previous = m_setContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            }
        }
        ~PhysicalPixels()
        {
            if (m_setContext && m_previous)
            {
                m_setContext(m_previous);
            }
        }

    private:
        using SetContext = DPI_AWARENESS_CONTEXT(WINAPI*)(DPI_AWARENESS_CONTEXT);
        SetContext m_setContext = nullptr;
        DPI_AWARENESS_CONTEXT m_previous = nullptr;
    };

    // 锁屏、UAC 安全桌面或输入桌面切换后停止，不跨桌面继续写屏。
    bool isCurrentInputDesktop()
    {
        const HDESK input = ::OpenInputDesktop(0, FALSE, DESKTOP_READOBJECTS);
        if (!input)
        {
            return false;
        }
        wchar_t inputName[256]{};
        wchar_t threadName[256]{};
        DWORD required = 0;
        const bool same = ::GetUserObjectInformationW(input, UOI_NAME,
            inputName, sizeof(inputName), &required)
            && ::GetUserObjectInformationW(::GetThreadDesktop(::GetCurrentThreadId()),
                UOI_NAME, threadName, sizeof(threadName), &required)
            && std::wcscmp(inputName, threadName) == 0;
        ::CloseDesktop(input);
        return same;
    }

    BOOL CALLBACK collectDisplay(HMONITOR monitor, HDC, LPRECT, LPARAM context)
    {
        MONITORINFOEXW info{};
        info.cbSize = sizeof(info);
        if (::GetMonitorInfoW(monitor, &info))
        {
            auto& displays = *reinterpret_cast<std::vector<ks::misc::desktop_drawing::Display>*>(context);
            displays.push_back({ monitor, info.rcMonitor, info.szDevice,
                (info.dwFlags & MONITORINFOF_PRIMARY) != 0 });
        }
        return TRUE;
    }

    // 只请求受影响区域重绘，不回贴启动时的屏幕截图，避免覆盖后来出现的内容。
    BOOL CALLBACK repaintWindow(HWND window, LPARAM context)
    {
        if (!::IsWindowVisible(window) || ::IsIconic(window))
        {
            return TRUE;
        }
        const auto& dirty = *reinterpret_cast<const RECT*>(context);
        RECT bounds{}, overlap{};
        if (::GetWindowRect(window, &bounds) && ::IntersectRect(&overlap, &bounds, &dirty))
        {
            POINT origin{};
            if (::ClientToScreen(window, &origin))
            {
                ::OffsetRect(&overlap, -origin.x, -origin.y);
                // 不使用 UPDATENOW / ERASENOW，避免被外部窗口的消息处理阻塞。
                ::RedrawWindow(window, &overlap, nullptr,
                    RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN);
            }
        }
        return TRUE;
    }

    bool paintPattern(HDC dc, const ks::misc::desktop_drawing::Options& options)
    {
        using ks::misc::desktop_drawing::Pattern;
        const int x = options.display.bounds.left + options.x;
        const int y = options.display.bounds.top + options.y;
        const int radius = options.size / 2;
        switch (options.pattern)
        {
        case Pattern::Cross:
        {
            const POINT horizontal[] = { { x - radius, y }, { x + radius, y } };
            const POINT vertical[] = { { x, y - radius }, { x, y + radius } };
            return ::Polyline(dc, horizontal, 2) && ::Polyline(dc, vertical, 2);
        }
        case Pattern::Circle:
            return ::Ellipse(dc, x - radius, y - radius, x + radius, y + radius) != FALSE;
        case Pattern::Rectangle:
            return ::Rectangle(dc, x - radius, y - radius, x + radius, y + radius) != FALSE;
        case Pattern::Diamond:
        {
            const POINT points[] = { { x, y - radius }, { x + radius, y },
                { x, y + radius }, { x - radius, y }, { x, y - radius } };
            return ::Polyline(dc, points, 5) != FALSE;
        }
        case Pattern::Star:
        {
            POINT points[11]{};
            constexpr double pi = 3.14159265358979323846;
            for (int index = 0; index < 10; ++index)
            {
                const double angle = -pi / 2.0 + index * pi / 5.0;
                const double distance = radius * (index % 2 == 0 ? 1.0 : 0.382);
                points[index] = { x + static_cast<LONG>(std::lround(std::cos(angle) * distance)),
                    y + static_cast<LONG>(std::lround(std::sin(angle) * distance)) };
            }
            points[10] = points[0];
            return ::Polyline(dc, points, 11) != FALSE;
        }
        }
        return false;
    }
}

namespace ks::misc::desktop_drawing
{
    std::vector<Display> enumerateDisplays()
    {
        const PhysicalPixels physicalPixels;
        std::vector<Display> displays;
        if (!::EnumDisplayMonitors(nullptr, nullptr, collectDisplay, reinterpret_cast<LPARAM>(&displays)))
        {
            displays.clear();
        }
        std::stable_sort(displays.begin(), displays.end(), [](const Display& left, const Display& right)
            { return left.primary && !right.primary; });
        return displays;
    }

    Renderer::~Renderer()
    {
        stop();
    }

    DrawResult Renderer::start(const Options& options)
    {
        stop();
        m_options = options;
        m_options.size = std::clamp(options.size, 16, 1024);
        m_options.lineWidth = std::clamp(options.lineWidth, 1, 32);
        m_pen = ::CreatePen(PS_SOLID, m_options.lineWidth, m_options.color);
        if (!m_pen)
        {
            return DrawResult::ResourceFailure;
        }
        const DrawResult result = drawFrame();
        if (result != DrawResult::Success)
        {
            stop();
        }
        return result;
    }

    DrawResult Renderer::drawFrame()
    {
        if (!m_pen)
        {
            return DrawResult::ResourceFailure;
        }
        if (!isCurrentInputDesktop())
        {
            return DrawResult::DesktopUnavailable;
        }
        const PhysicalPixels physicalPixels;
        MONITORINFOEXW display{};
        display.cbSize = sizeof(display);
        if (!::GetMonitorInfoW(m_options.display.handle, &display)
            || !::EqualRect(&display.rcMonitor, &m_options.display.bounds)
            || m_options.display.name != display.szDevice)
        {
            return DrawResult::DisplayChanged;
        }
        const int x = display.rcMonitor.left + m_options.x;
        const int y = display.rcMonitor.top + m_options.y;
        const int margin = m_options.size / 2 + m_options.lineWidth + 2;
        const RECT patternBounds{ x - margin, y - margin, x + margin + 1, y + margin + 1 };
        if (!::IntersectRect(&m_dirtyBounds, &patternBounds, &display.rcMonitor))
        {
            return DrawResult::DisplayChanged;
        }

        const HDC dc = ::GetDC(nullptr);
        if (!dc)
        {
            return DrawResult::ResourceFailure;
        }
        const int saved = ::SaveDC(dc);
        bool painted = false;
        if (saved != 0)
        {
            const HGDIOBJ oldPen = ::SelectObject(dc, m_pen);
            const HGDIOBJ oldBrush = ::SelectObject(dc, ::GetStockObject(HOLLOW_BRUSH));
            const int clipped = ::IntersectClipRect(dc, m_dirtyBounds.left,
                m_dirtyBounds.top, m_dirtyBounds.right, m_dirtyBounds.bottom);
            if (oldPen && oldPen != HGDI_ERROR && oldBrush && oldBrush != HGDI_ERROR
                && clipped != ERROR && clipped != NULLREGION && ::SetROP2(dc, R2_COPYPEN))
            {
                m_hasDrawn = true; // 即使绘制中途失败，停止时也清理可能写入的部分。
                painted = paintPattern(dc, m_options);
                const BOOL flushed = ::GdiFlush();
                painted = painted && flushed;
            }
            ::RestoreDC(dc, saved);
        }
        ::ReleaseDC(nullptr, dc); // 同一线程、同一帧内释放，不持有显示 DC。
        return painted ? DrawResult::Success : DrawResult::DrawFailure;
    }

    void Renderer::stop()
    {
        if (m_pen)
        {
            ::DeleteObject(m_pen);
            m_pen = nullptr;
        }
        if (m_hasDrawn)
        {
            m_hasDrawn = false;
            const PhysicalPixels physicalPixels;
            ::RedrawWindow(nullptr, &m_dirtyBounds, nullptr,
                RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN);
            ::EnumWindows(repaintWindow, reinterpret_cast<LPARAM>(&m_dirtyBounds));
        }
    }
}
