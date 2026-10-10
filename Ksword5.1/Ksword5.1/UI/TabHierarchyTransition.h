#pragma once

class QTabWidget;

namespace ks::ui
{
    // 父级在惰性子页创建前登记，第一轮切换也能保存原页面身份和方向。
    void InstallParentTabTransition(QTabWidget* parentTabs);

    // childTabs 是明确登记的子级导航；根据父级 Tab 的实际左右位置滑动子栏。
    // 只绘制短暂的栏位快照，不搬动页面、改变业务索引或重新构建内容。
    void InstallChildTabTransition(QTabWidget* childTabs);
}
