#pragma once

#include <windows.h>

#include <string>
#include <vector>

namespace ks::misc::desktop_drawing
{
    enum class Pattern { Cross, Circle, Rectangle, Diamond, Star };
    enum class DrawResult { Success, DesktopUnavailable, DisplayChanged, ResourceFailure, DrawFailure };

    struct Display
    {
        HMONITOR handle = nullptr;
        RECT bounds{}; // Win32 物理像素；副屏允许负原点。
        std::wstring name;
        bool primary = false;
    };

    struct Options
    {
        Display display;
        Pattern pattern = Pattern::Star;
        int x = 0; // 相对所选显示器左上角的物理像素。
        int y = 0;
        int size = 160;
        int lineWidth = 3;
        COLORREF color = RGB(255, 80, 80);
    };

    // 与 Qt 的逻辑屏幕坐标分离，枚举与绘制使用同一套 DPI 上下文。
    std::vector<Display> enumerateDisplays();

    // 所有方法只能在创建者的 UI 线程调用。每帧取得并释放屏幕 DC，
    // 不创建 HWND，不获取目标进程句柄，也不修改目标窗口的 Z-order。
    class Renderer final
    {
    public:
        Renderer() = default;
        ~Renderer();
        Renderer(const Renderer&) = delete;
        Renderer& operator=(const Renderer&) = delete;

        DrawResult start(const Options& options);
        DrawResult drawFrame();
        void stop();

    private:
        Options m_options;
        HPEN m_pen = nullptr;
        RECT m_dirtyBounds{};
        bool m_hasDrawn = false;
    };
}
