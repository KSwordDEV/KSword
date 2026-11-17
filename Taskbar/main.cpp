#include "Taskbar.h"
#include "DisplayRestartMonitor.h"
#include "../shared/rescue/SosHotkeyLauncher.h"
#include "TaskbarEarthquakeClient.h"
#include "TaskbarNotificationService.h"
#include "TaskbarRestartCoordinator.h"
#include "TaskbarSharedState.h"

#include <QtWidgets/QApplication>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QList>
#include <QScreen>
#include <QVector>
#include <memory>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

namespace
{
    // initializeProcessDpiAwareness:
    // - Input: none.
    // - Processing: sets process DPI awareness before QApplication is created.
    // - Return: none; the process falls back to system DPI awareness on older Windows builds.
    void initializeProcessDpiAwareness()
    {
        HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
        if (user32ModuleHandle != nullptr)
        {
            using SetDpiAwarenessContextFunction = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
            const SetDpiAwarenessContextFunction setContextFunction =
                reinterpret_cast<SetDpiAwarenessContextFunction>(
                    ::GetProcAddress(user32ModuleHandle, "SetProcessDpiAwarenessContext"));
            if (setContextFunction != nullptr)
            {
                if (setContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
                {
                    return;
                }
                if (setContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE))
                {
                    return;
                }
            }
        }

        // Older Windows fallback: keep at least system-DPI-aware coordinates.
        ::SetProcessDPIAware();
    }
}

int main(int argc, char* argv[])
{
    std::unique_ptr<void, decltype(&::CloseHandle)> instanceGuard(nullptr, &::CloseHandle);
    // 启用 OpenGLES，沿用原任务栏绘制路径，避免改动 Qt 渲染策略。
    QCoreApplication::setAttribute(Qt::AA_UseOpenGLES);

    // Set DPI awareness before QApplication so QScreen geometry and AppBar math agree.
    initializeProcessDpiAwareness();

    // QApplication 管理所有 Taskbar 窗口、屏幕事件和共享状态对象生命周期。
    QApplication app(argc, argv);

    // PID 感知重启的接替实例必须在创建窗口、AppBar 和后台采样线程前等待旧进程退出。
    if (!TaskbarRestartCoordinator::waitForPredecessorIfRequested())
    {
        return 2;
    }
    // PID handoff must finish before claiming the singleton, otherwise settings
    // and display-change restarts would be rejected by their predecessor.
    const HANDLE instanceHandle = ::CreateMutexExW(nullptr, L"Local\\KSword.Taskbar.Instance", 0, SYNCHRONIZE);
    const DWORD instanceError = ::GetLastError();
    instanceGuard.reset(instanceHandle);
    if (!instanceHandle) return 2;
    if (instanceError == ERROR_ALREADY_EXISTS) return 0;

    // SOS 键盘钩子尽早启动：
    // - 独立高优先级线程安装 WH_KEYBOARD_LL；
    // - 只检测 S O S Enter 固定序列；
    // - 命中后交给 Ksword5.1.exe 的救援监护入口。
    SosHotkeyLauncher sosHotkeyLauncher(QCoreApplication::applicationDirPath());
    sosHotkeyLauncher.start();

    // 显示器变化监控器在屏幕数量或分辨率变化时自动拉起新进程并退出旧进程。
    DisplayRestartMonitor displayRestartMonitor(&app);

    // 共享状态只启动一次采样，多个显示器窗口只共享数据，不重复打开音频/CPU/网络采样器。
    TaskbarSharedState sharedState(&app);
    sharedState.start();

    // 地震客户端与系统通知服务均为进程唯一：所有桌面接收同一来源状态和同一通知队列。
    TaskbarEarthquakeClient earthquakeClient(&app);
    earthquakeClient.start();
    TaskbarNotificationService notificationService(&earthquakeClient, &app);

    // 每个显示器创建一个完全相同的 Taskbar 窗口，并分别向系统申请顶部 AppBar 边缘。
    QVector<Taskbar*> windows;
    const QList<QScreen*> screens = QGuiApplication::screens();
    windows.reserve(screens.size());

    for (QScreen* screen : screens) {
        Taskbar* window = new Taskbar(screen, &sharedState, &notificationService);
        windows.append(window);
        window->show();
    }

    return app.exec();
}
