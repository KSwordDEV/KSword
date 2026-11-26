#pragma once

#include "../Core/Win32Lean.h"
#include <span>

namespace Ksword::Ui {

// 固定参数动作按实际可用宽度换行；arrange=false仅测量，返回占用高度，不创建控件。
int LayoutParameterActions(std::span<const HWND> controls, int x, int y, int width,
    int preferredWidth, int rowHeight, int gap, bool arrange = true);

// 原生参数工作区的独立滚动正文；动作栏和结果仍由页面固定布局，不包裹结果视口。
class ParameterWorkspace final {
public:
    // 创建正文视口并将其输入/命令转发给页面；失败返回false，不创建业务会话。
    bool Create(HWND page);
    // 返回参数控件唯一父窗口；参数正文只有本视口负责滚动。
    HWND Body() const;
    // 重新分配实际视口和正文自然高度；保持原滚动位置并在缩小时夹紧。
    void Layout(int x, int y, int width, int height, int contentHeight) const;
    // 键盘Tab聚焦参数时滚动到该控件，不移动动作栏或结果选择。
    void Reveal(HWND control) const;
private:
    HWND viewport_ = nullptr; // 拥有垂直滚动条的原生子窗口。
    HWND body_ = nullptr; // 全部参数的自然高度画布。
};
}
