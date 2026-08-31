#pragma once

// ============================================================
// ThreadAffinityMenu.h
// 作用：
// - 复用 Ksword5.1 进程 CPU 亲和性右键矩阵的交互，提供单线程 CPU Set 菜单；
// - 菜单写入只经 shared/ThreadAffinityR3.h 的 Win32 R3 API，不接触驱动。
// ============================================================

#include <Windows.h>

#include <cstdint>
#include <functional>

#include <QIcon>
#include <QString>

class QMenu;

namespace ks::process
{
    using ThreadAffinityMenuResultHandler = std::function<void(bool, const QString&)>;

    // addThreadAffinitySubMenu 将“线程亲和性”CPU Set 矩阵追加到现有右键菜单。
    // targetThreadCreationTime100ns 为零时菜单会保持可见但禁用，避免 TID 复用误写。
    QMenu* addThreadAffinitySubMenu(
        QMenu* parentMenu,
        const QIcon& icon,
        DWORD targetProcessId,
        DWORD targetThreadId,
        std::uint64_t targetThreadCreationTime100ns,
        const QString& menuStyle,
        ThreadAffinityMenuResultHandler resultHandler);
}
