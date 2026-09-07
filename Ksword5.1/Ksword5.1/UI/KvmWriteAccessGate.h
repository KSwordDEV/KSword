// KvmWriteAccessGate.h
//
// R-1 写权限门的唯一开启入口。
//
// 拆出来的理由是口径必须唯一：开启写权限的确认框有一个持久化的
// suppressionKey，用户勾了「不再提示」之后是按这个 key 记住的。只要有第二处
// 自己拼一遍确认文案，勾过的用户就会在另一个入口被重新弹一次——而两处文案一旦
// 有一个字不同，就再也说不清用户到底同意过什么。所以标题栏 KVM 菜单和对话框里
// 的就地开启都走这一个函数，文案与 key 都只存在于这里一份。

#pragma once

class QWidget;

namespace ks::ui
{
    // requestKvmWriteAccess：确保 R-1 写权限已开启，返回调用方能不能继续往下做。
    //
    // 已经开着就直接返回 true，不打扰用户；关着才弹统一的高危确认，用户确认后
    // 才真正落盘开启。返回 false 表示用户拒绝了，此时写权限保持关闭，调用方应当
    // 原地停下，而不是接着发任何会改写状态的请求。
    //
    // 只碰 QSettings，不发 IOCTL，因此可以在 UI 线程直接调用；也必须在 UI 线程
    // 调用，因为它会弹模态对话框。
    bool requestKvmWriteAccess(QWidget* parent);
}
