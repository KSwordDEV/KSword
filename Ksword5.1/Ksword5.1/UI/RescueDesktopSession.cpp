#include "../Framework.h"
#include "RescueDesktopSession.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QEvent>
#include <QLabel>
#include <QMainWindow>
#include <QStyle>
#include <QTimer>
#include <QToolBar>
#include <QToolButton>
#include <shellapi.h>
#include <cerrno>
#include <cwchar>
#include <limits>

namespace
{
    // 输入十进制内部句柄参数，拒绝负数、尾随字符和截断；输出 0 表示格式错误。
    HANDLE ParseHandle(const wchar_t* text)
    {
        if (!text || *text < L'0' || *text > L'9')
        {
            return nullptr;
        }
        wchar_t* end = nullptr; // 数字解析结束位置。
        errno = 0;
        const unsigned long long value = std::wcstoull(text, &end, 10); // 不使用有符号指针转换。
        if (errno != 0 || *end != L'\0' || value == 0
            || value > std::numeric_limits<ULONG_PTR>::max())
        {
            return nullptr;
        }
        return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(value));
    }

    // 校验继承事件或进程仍可等待、尚未置位。日志保留角色和等待结果。
    DWORD CheckPendingHandle(const HANDLE handle, const wchar_t* role)
    {
        const DWORD state = ::WaitForSingleObject(handle, 0);
        if (state == WAIT_TIMEOUT)
        {
            return ERROR_SUCCESS;
        }
        DWORD error = state == WAIT_FAILED ? ::GetLastError() : ERROR_INVALID_DATA;
        if (error == ERROR_SUCCESS)
        {
            error = ERROR_INVALID_HANDLE;
        }
        ks::rescue::LogStage(L"client.handle_invalid", error, state, role);
        return error;
    }
}

namespace ks::ui
{
    RescueDesktopSession::~RescueDesktopSession()
    {
        // 先通知监护进程返回桌面，再停止自己的备用观察线程并释放继承句柄。
        if (active_)
        {
            ::SetEvent(handles_.leave);
        }
        if (stopMonitor_)
        {
            ::SetEvent(stopMonitor_);
        }
        if (monitor_.joinable())
        {
            monitor_.join();
        }
        if (application_)
        {
            application_->removeNativeEventFilter(this);
            application_->removeEventFilter(this);
        }
        if (stopMonitor_)
        {
            ::CloseHandle(stopMonitor_);
        }
        if (handles_.ready)
        {
            ::CloseHandle(handles_.ready);
        }
        if (handles_.leave)
        {
            ::CloseHandle(handles_.leave);
        }
        if (handles_.host)
        {
            ::CloseHandle(handles_.host);
        }
        // 已绑定到当前线程的 HDESK 由 Windows 随进程退出释放，不能提前 CloseDesktop。
    }

    DWORD RescueDesktopSession::initializeBeforeQt()
    {
        int count = 0; // Windows 原生命令行参数数量。
        wchar_t** arguments = ::CommandLineToArgvW(::GetCommandLineW(), &count);
        if (!arguments)
        {
            const DWORD error = ::GetLastError();
            ks::rescue::LogStage(L"client.arguments_failed", error);
            return error;
        }
        bool requested = false; // 参数出现但不合法时必须停止，不能绕过救援约束。
        for (int index = 1; index < count; ++index)
        {
            requested = requested || std::wstring(arguments[index]) == ks::rescue::kClientArgument;
        }
        if (!requested)
        {
            ::LocalFree(arguments);
            return ERROR_SUCCESS;
        }
        ks::rescue::LogStage(L"client.initializing", ERROR_SUCCESS, static_cast<DWORD>(count));
        if (count != 8 || std::wstring(arguments[1]) != ks::rescue::kClientArgument)
        {
            ::LocalFree(arguments);
            ks::rescue::LogStage(L"client.arguments_invalid", ERROR_INVALID_PARAMETER);
            return ERROR_INVALID_PARAMETER;
        }

        const std::wstring expectedName = arguments[2]; // 监护进程生成的精确救援桌面名。
        handles_.desktop = reinterpret_cast<HDESK>(ParseHandle(arguments[3]));
        handles_.ready = ParseHandle(arguments[4]);
        handles_.leave = ParseHandle(arguments[5]);
        handles_.host = ParseHandle(arguments[6]);
        originalName_ = arguments[7];
        ::LocalFree(arguments);

        // 核验内部参数及所有继承对象，再决定是否需要切换线程。
        if (originalName_.empty() || originalName_.find_first_of(L"\\/\"") != std::wstring::npos)
        {
            ks::rescue::LogStage(L"client.desktop_arguments_invalid", ERROR_INVALID_NAME);
            return ERROR_INVALID_NAME;
        }
        if (const DWORD error = CheckPendingHandle(handles_.ready, L"ready"); error != ERROR_SUCCESS)
        {
            return error;
        }
        if (const DWORD error = CheckPendingHandle(handles_.leave, L"leave"); error != ERROR_SUCCESS)
        {
            return error;
        }
        if (const DWORD error = CheckPendingHandle(handles_.host, L"host"); error != ERROR_SUCCESS)
        {
            return error;
        }

        if (const DWORD error = ks::rescue::BindClientDesktop(handles_.desktop, expectedName);
            error != ERROR_SUCCESS)
        {
            return error;
        }
        ks::rescue::LogStage(L"client.desktop_verified", ERROR_SUCCESS, 0, expectedName);
        stopMonitor_ = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!stopMonitor_)
        {
            const DWORD error = ::GetLastError();
            ks::rescue::LogStage(L"client.stop_event_failed", error);
            return error;
        }
        // 观察监护退出的线程和 Qt 过滤器只在当前桌面核验通过后启用。
        try
        {
            monitor_ = std::thread(&RescueDesktopSession::monitorHost, this);
        }
        catch (...)
        {
            ks::rescue::LogStage(L"client.monitor_start_failed", ERROR_NO_SYSTEM_RESOURCES);
            return ERROR_NO_SYSTEM_RESOURCES;
        }
        active_ = true;
        return ERROR_SUCCESS;
    }

    void RescueDesktopSession::install(QApplication& application)
    {
        if (!active_)
        {
            return;
        }
        application_ = &application;
        application.setProperty("ksword_rescue_desktop", true);
        application.installNativeEventFilter(this);
        application.installEventFilter(this);
        QObject::connect(&application, &QCoreApplication::aboutToQuit, this, [this]()
        {
            ::SetEvent(handles_.leave);
        });
        auto* timer = new QTimer(this); // UI 正常时及时响应监护进程的返回请求。
        QObject::connect(timer, &QTimer::timeout, this, [this]()
        {
            if (::WaitForSingleObject(handles_.leave, 0) == WAIT_OBJECT_0 && application_)
            {
                application_->quit();
            }
        });
        timer->start(200);
    }

    bool RescueDesktopSession::nativeEventFilter(const QByteArray&, void* message, qintptr* result)
    {
        const auto* input = static_cast<const MSG*>(message); // Qt 转交的原始 Windows 消息。
        if (!active_ || !input || (!ks::rescue::IsMouseMessage(input->message)
            && !ks::rescue::IsKeyboardMessage(input->message)))
        {
            return false;
        }
        INPUT_MESSAGE_SOURCE source{}; // Windows 识别的设备类型/消息来源。
        if (!::GetCurrentInputMessageSource(&source)
            || !ks::rescue::AcceptInputSource(input->message, source))
        {
            if (result)
            {
                *result = 0;
            }
            return true;
        }
        return false;
    }

    bool RescueDesktopSession::eventFilter(QObject* watched, QEvent* event)
    {
        // 同时拒绝应用队列制造的鼠标/键盘事件，普通启动不会安装本过滤器。
        if (active_ && event && !event->spontaneous())
        {
            switch (event->type())
            {
            case QEvent::MouseButtonPress:
            case QEvent::MouseButtonRelease:
            case QEvent::MouseButtonDblClick:
            case QEvent::KeyPress:
            case QEvent::KeyRelease:
            case QEvent::Wheel:
                return true;
            default:
                break;
            }
        }
        return QObject::eventFilter(watched, event);
    }

    void RescueDesktopSession::attachWindow(QMainWindow& window)
    {
        if (!active_)
        {
            return;
        }
        // 救援状态和返回入口固定在主窗口工具栏，普通窗口仍保持原布局。
        auto* bar = new QToolBar(&window); // 不可浮动的救援操作栏。
        bar->setObjectName(QStringLiteral("ksword_rescue_toolbar"));
        bar->setMovable(false);
        bar->setFloatable(false);
        bar->setStyleSheet(QStringLiteral(
            "QToolBar { background: palette(base); color: palette(text); border: none; }"));
        auto* label = new QLabel(bar); // 向用户说明当前处于隔离桌面。
        ks::i18n::LanguageManager::instance().bindText(label,
            QStringLiteral("rescue.desktop.status"), QStringLiteral("救援桌面"));
        bar->addWidget(label);
        auto* button = new QToolButton(bar); // 物理鼠标可用的返回入口。
        KswordTheme::ApplyCompactIconButtonMetrics(button);
        button->setIcon(window.style()->standardIcon(QStyle::SP_ArrowBack));
        ks::i18n::LanguageManager::instance().bindToolTip(button,
            QStringLiteral("rescue.desktop.return"),
            QStringLiteral("返回原桌面并关闭救援实例（Ctrl+Alt+Shift+F10）"));
        QObject::connect(button, &QToolButton::clicked, &window, [&window, this]()
        {
            ::SetEvent(handles_.leave);
            window.close();
        });
        bar->addWidget(button);
        window.addToolBar(Qt::TopToolBarArea, bar);

        // 最后安装，先于通用快捷键过滤器拒绝非物理输入；主事件循环运行后才宣布就绪。
        application_->removeEventFilter(this);
        application_->installEventFilter(this);
        QTimer::singleShot(0, &window, [this]()
        {
            ::SetEvent(handles_.ready);
        });
    }

    void RescueDesktopSession::monitorHost()
    {
        HANDLE waiting[] = { stopMonitor_, handles_.host }; // stop 优先，正常析构不会触发备用恢复。
        if (::WaitForMultipleObjects(2, waiting, FALSE, INFINITE) == WAIT_OBJECT_0 + 1)
        {
            restoreAfterHostExit();
            ::SetEvent(handles_.leave);
        }
    }

    void RescueDesktopSession::restoreAfterHostExit()
    {
        if (!ks::rescue::IsInputDesktop(handles_.desktop))
        {
            return;
        }
        // 监护进程意外退出时，备用线程可按原桌面名恢复，不等待 Qt 事件循环。
        const HDESK original = ::OpenDesktopW(originalName_.c_str(), 0, FALSE, DESKTOP_SWITCHDESKTOP);
        if (original)
        {
            ::SwitchDesktop(original);
            ::CloseDesktop(original);
        }
    }
}
