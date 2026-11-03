#pragma once
#include <QEvent>

class QObject;

// 应用内界面动画总开关：
// - 默认启用，由设置页“界面动画”下发，运行时即时生效；
// - 与系统“减少动画”(SPI_GETCLIENTAREAANIMATION) 相互独立，任一关闭即不播放动画；
// - 只覆盖界面过渡动画：滚动缓动、页签切换、弹层淡入、浮动滚动条淡出等；
//   不影响图表采样插值等数据呈现动画。
namespace ks::ui
{
    void SetGlobalUiAnimationsEnabled(bool enabled);
    bool AreUiAnimationsEnabled();
    QEvent::Type UiAnimationsChangedEventType();
    void ObserveUiAnimations(QObject* observer);
}
