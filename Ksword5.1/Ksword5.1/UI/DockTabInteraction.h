#pragma once

// 顶部 ADS 停靠标签的两个可达性缺口，都是真机上撞出来的：
//
//   1. 标签溢出之后**滚不动**。ads::CDockAreaTabBar 派生自 QAbstractScrollArea
//      并声明了 wheelEvent，但实测滚轮无效，而 ADS 是预编译库、改不了内部。
//   2. 标签顺序**可以拖乱、无法复位**。布局持久化在 exe 目录下的
//      config/ksword_ads_layout.bin，用户唯一的出路是手动去删那个文件。
//
// 两件事都只能在 ADS 外面补，所以单独放一个文件，而不是继续往一万两千行的
// MainWindow.cpp 里塞。

#include <QObject>
#include <QString>

namespace ads
{
    class CDockManager;
}

namespace ks::ui
{
    // 给 ADS 的标签栏补上横向滚轮滚动。
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
