#pragma once

// ADS 标签栏的溢出滚动、左右导航和保存布局的复位支持。

#include <QObject>
#include <QString>

namespace ads
{
    class CDockManager;
}

namespace ks::ui
{
    // 安装鼠标/触控板横向滚动和仅在溢出时显示的左右箭头。
    //
    // 必须挂在管理器上而不是"启动时扫一遍"：标签栏会**后来才出现** ——
    // 浮动容器、restoreState 之后、以及新建 Dock 都会造出新的标签栏。
    // 本函数同时处理已存在的和后续新建的（订阅 dockAreaCreated）。
    //
    // 幂等：重复调用不会装上第二份过滤器。
    void installDockTabWheelScrolling(ads::CDockManager* dockManager);

    // 删除已保存的停靠布局文件，让下一次启动回到默认排列。
    //
    // 返回 true 表示"之后确实不会再读到旧布局"——包括文件本来就不存在的情况。
    // 之所以把删除单独暴露出来：调用方还必须阻止**本次退出时把旧布局又存回去**，
    // 那一步只有 MainWindow 知道怎么做。
    bool discardSavedDockLayout(const QString& layoutConfigPath);
}
