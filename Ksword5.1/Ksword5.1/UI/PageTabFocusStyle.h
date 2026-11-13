#pragma once

class QTabBar;

namespace ks::ui
{
    // 普通模式隐藏共享页签焦点框，无鼠标模式恢复；不改变焦点策略。
    void InstallMouseAwareTabFocus(QTabBar* bar);
}
