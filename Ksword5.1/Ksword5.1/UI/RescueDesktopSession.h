#pragma once

#include <QAbstractNativeEventFilter>
#include <QObject>
#include <QPointer>
#include <thread>
#include "../../../shared/rescue/RescueDesktopWin32.h"

class QApplication;
class QMainWindow;

namespace ks::ui
{
    // 先 initializeBeforeQt，再 install/attachWindow；普通启动为无操作。
    // 救援模式保存原桌面名称，核验继承句柄，安装应用内第二层输入检查。
    class RescueDesktopSession final : public QObject, public QAbstractNativeEventFilter
    {
    public:
        RescueDesktopSession() = default;
        ~RescueDesktopSession() override;
        DWORD initializeBeforeQt(); // 普通启动与救援就绪返回 ERROR_SUCCESS，失败返回 Win32 错误。
        // 返回本实例是否为经过句柄校验的救援实例。
        bool active() const
        {
            return active_;
        }
        void install(QApplication& application); // Qt 创建后立即装入原生/Qt 输入过滤器。
        void attachWindow(QMainWindow& window); // 加入返回工具栏并在事件循环就绪后发回就绪事件。

    protected:
        bool nativeEventFilter(const QByteArray& type, void* message, qintptr* result) override;
        bool eventFilter(QObject* watched, QEvent* event) override;

    private:
        void monitorHost(); // 独立线程等监护进程退出，Qt 阻塞时也能尝试恢复原桌面。
        void restoreAfterHostExit(); // 仅在自己的救援桌面活动时切回原桌面。
        ks::rescue::ClientHandles handles_; // 由监护进程白名单继承的四个句柄。
        std::wstring originalName_; // 原输入桌面对象名，不作为救援桌面按名称打开的凭据。
        QPointer<QApplication> application_; // 防止 QApplication 销毁后访问原生过滤器注册表。
        HANDLE stopMonitor_ = nullptr; // 本实例退出时唤醒监护等待线程。
        std::thread monitor_; // 不依赖 UI 消息循环的监护进程退出观察者。
        bool active_ = false; // 只有完整校验并绑定桌面后才置位。
    };
}
