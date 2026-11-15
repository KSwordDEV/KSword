#include "UacDesk.h"
#include "UacScanWorker.h"

#include <QApplication>
#include <QCommandLineParser>
#include <QDir>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QRandomGenerator>
#include <QStyleHints>

#include <Windows.h>

namespace
{
    void initializeProcessDpiAwareness()
    {
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        if (user32)
        {
            using SetDpiAwarenessContextFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
            const auto setContext = reinterpret_cast<SetDpiAwarenessContextFn>(
                GetProcAddress(user32, "SetProcessDpiAwarenessContext"));
            if (setContext &&
                (setContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) ||
                 setContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE)))
            {
                return;
            }
        }
        SetProcessDPIAware();
    }

    void qtMessageHandler(QtMsgType, const QMessageLogContext&, const QString&)
    {
        // Suppress Qt diagnostics, including its default debugger/stderr output.
    }

    QString valueAfter(const QStringList& args, const QString& prefix)
    {
        for (const QString& arg : args)
            if (arg.startsWith(prefix)) return arg.mid(prefix.size());
        return {};
    }

    bool hasArg(const QStringList& args, const QString& value)
    {
        return args.contains(value, Qt::CaseInsensitive);
    }

    QStringList stageArgs(const QString& stage, const QString& handoff, DWORD parentPid, quint64 parentCreation)
    {
        QStringList args{QStringLiteral("--ksword-uac-stage=") + stage};
        if (!handoff.isEmpty()) args.push_back(QStringLiteral("--ksword-uac-handoff=") + handoff);
        if (parentPid != 0 && parentCreation != 0)
        {
            args.push_back(QStringLiteral("--ksword-parent-pid=") + QString::number(parentPid));
            args.push_back(QStringLiteral("--ksword-parent-creation-time=") + QString::number(parentCreation));
        }
        return args;
    }

    void parentIdentityForKsword(DWORD& parentPid, quint64& parentCreation)
    {
        parentPid = 0;
        parentCreation = 0;
        PROCESSENTRY32W entry{sizeof(entry)};
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return;
        DWORD candidatePid = 0;
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
            if (entry.th32ProcessID == GetCurrentProcessId()) { candidatePid = entry.th32ParentProcessID; break; }
        CloseHandle(snapshot);
        if (candidatePid == 0) return;
        ProcessIdentity parent;
        if (!ProcessInspector::query(candidatePid, parent)) return;
        if (QFileInfo(parent.imagePath).fileName().compare(QStringLiteral("Ksword5.1.exe"), Qt::CaseInsensitive) != 0) return;
        parentPid = parent.pid;
        parentCreation = parent.creationTime;
    }

    bool acquireOwner(DWORD sessionId, HANDLE& mutex)
    {
        const QString name = QStringLiteral("Global\\KswordUacDesk.Owner.%1").arg(sessionId);
        mutex = CreateMutexW(nullptr, TRUE, name.toStdWString().c_str());
        return mutex != nullptr && GetLastError() != ERROR_ALREADY_EXISTS;
    }

    int runInitial(const QString& executable, const QStringList& args)
    {
        const DWORD session = PrivilegeStage::currentSessionId();
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("initial: entered args=%1").arg(args.join(QLatin1Char(' '))));
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("initial: elevated=%1, system=%2, uiAccess=%3, session=%4, desktop=%5")
                       .arg(PrivilegeStage::isProcessElevated() ? 1 : 0)
                       .arg(PrivilegeStage::isSystem() ? 1 : 0)
                       .arg(PrivilegeStage::hasUiAccess() ? 1 : 0)
                       .arg(session)
                       .arg(PrivilegeStage::currentDesktopName()));
        DWORD parentPid = 0;
        quint64 parentCreation = 0;
        parentIdentityForKsword(parentPid, parentCreation);
        HANDLE ready = CreateEventW(nullptr, TRUE, FALSE, QStringLiteral("Global\\KswordUacDesk.Ready.%1").arg(GetCurrentProcessId()).toStdWString().c_str());
        if (!ready)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("initial: CreateEvent failed"));
            return 2;
        }
        const QString handoff = QStringLiteral("Global\\KswordUacDesk.Ready.%1").arg(GetCurrentProcessId());
        QStringList next = stageArgs(QStringLiteral("system"), handoff, parentPid, parentCreation);
        QString error;
        const bool launched = PrivilegeStage::isProcessElevated()
            ? PrivilegeStage::launchSystemStage(executable, next, QStringLiteral("winsta0\\Winlogon"), session, error)
            : PrivilegeStage::launchAdminStage(executable, stageArgs(QStringLiteral("admin"), handoff, parentPid, parentCreation), error);
        if (!launched)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("initial: stage launch failed: %1").arg(error.isEmpty() ? QStringLiteral("ShellExecuteExW 失败或未返回错误") : error));
            CloseHandle(ready);
            return 3;
        }
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("initial: child stage created, waiting for handoff"));
        const DWORD wait = WaitForSingleObject(ready, 10000);
        CloseHandle(ready);
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("initial: handoff wait result=%1").arg(wait));
        return wait == WAIT_OBJECT_0 ? 0 : 4;
    }

    int runAdmin(const QString& executable, const QStringList& args)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("admin: entered args=%1").arg(args.join(QLatin1Char(' '))));
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("admin: elevated=%1, system=%2, uiAccess=%3, session=%4, desktop=%5")
                       .arg(PrivilegeStage::isProcessElevated() ? 1 : 0)
                       .arg(PrivilegeStage::isSystem() ? 1 : 0)
                       .arg(PrivilegeStage::hasUiAccess() ? 1 : 0)
                       .arg(PrivilegeStage::currentSessionId())
                       .arg(PrivilegeStage::currentDesktopName()));
        if (!PrivilegeStage::isProcessElevated())
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("admin: process is not elevated"));
            return 5;
        }
        QString handoff = valueAfter(args, QStringLiteral("--ksword-uac-handoff="));
        HANDLE ready = handoff.isEmpty() ? nullptr : OpenEventW(SYNCHRONIZE, FALSE, handoff.toStdWString().c_str());
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("admin: handoff=%1 eventHandle=%2").arg(handoff).arg(reinterpret_cast<quintptr>(ready), 0, 16));
        if (handoff.isEmpty())
        {
            handoff = QStringLiteral("Global\\KswordUacDesk.Ready.%1").arg(GetCurrentProcessId());
            ready = CreateEventW(nullptr, TRUE, FALSE, handoff.toStdWString().c_str());
        }
        QString error;
        const DWORD parentPid = valueAfter(args, QStringLiteral("--ksword-parent-pid=")).toULongLong();
        const quint64 parentCreation = valueAfter(args, QStringLiteral("--ksword-parent-creation-time=")).toULongLong();
        const bool launched = PrivilegeStage::launchSystemStage(executable, stageArgs(QStringLiteral("system"), handoff, parentPid, parentCreation),
                                                                 QStringLiteral("winsta0\\Winlogon"), PrivilegeStage::currentSessionId(), error);
        if (!launched)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("admin: SYSTEM stage launch failed: %1").arg(error));
            if (ready) CloseHandle(ready);
            return 6;
        }
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("admin: SYSTEM stage created, waiting for handoff"));
        if (ready) WaitForSingleObject(ready, 10000);
        if (ready) CloseHandle(ready);
        return 0;
    }

    int runSystem(const QString& executable, const QStringList& args, QApplication& app)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: entered args=%1").arg(args.join(QLatin1Char(' '))));
        app.setQuitOnLastWindowClosed(false);
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: elevated=%1, system=%2, uiAccess=%3, session=%4, desktop=%5")
                       .arg(PrivilegeStage::isProcessElevated() ? 1 : 0)
                       .arg(PrivilegeStage::isSystem() ? 1 : 0)
                       .arg(PrivilegeStage::hasUiAccess() ? 1 : 0)
                       .arg(PrivilegeStage::currentSessionId())
                       .arg(PrivilegeStage::currentDesktopName()));
        if (!PrivilegeStage::isSystem() || !PrivilegeStage::hasUiAccess())
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: identity check failed; refusing to run UI"));
            return 7;
        }
        if (PrivilegeStage::currentDesktopName().compare(QStringLiteral("Winlogon"), Qt::CaseInsensitive) != 0)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: current desktop is not Winlogon; refusing to run UI"));
            return 8;
        }
        HANDLE owner = nullptr;
        if (!acquireOwner(PrivilegeStage::currentSessionId(), owner))
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: another active owner already exists or mutex creation failed"));
            if (owner) CloseHandle(owner);
            return 9;
        }
        // Keep ownership until the monitor, window, and workers are destroyed.
        const std::unique_ptr<void, decltype(&CloseHandle)> ownerLease(owner, &CloseHandle);

        HANDLE parent = nullptr;
        const DWORD parentPid = valueAfter(args, QStringLiteral("--ksword-parent-pid=")).toULongLong();
        const quint64 parentCreation = valueAfter(args, QStringLiteral("--ksword-parent-creation-time=")).toULongLong();
        if (parentPid != 0 && parentCreation != 0)
        {
            parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
            if (!parent || processCreationTime(parent) != parentCreation)
            {
                if (parent) CloseHandle(parent);
                KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: Ksword5.1 parent identity check failed"));
                return 10;
            }
        }

        app.setApplicationName(QStringLiteral("KswordUacDesk"));
        // Keep the standalone companion aligned with Ksword's normal UI:
        // start from the Qt/Windows system font baseline and set the rendering
        // strategy before any widgets are constructed.  Do not force a font
        // family here; Windows selects the appropriate localized fallback.
        QFont systemFont = app.font();
        // Match Ksword's CJK fallback behavior.  Some configured/system font
        // families do not contain Chinese glyphs; without an explicit fallback
        // Qt may choose SimSun, which makes the diagnostic text look unrelated
        // to the main application.  The first family remains the system font.
        if (QFontDatabase::families().contains(QStringLiteral("Microsoft YaHei UI"), Qt::CaseInsensitive))
        {
            QStringList families{systemFont.family(), QStringLiteral("Microsoft YaHei UI")};
            systemFont.setFamilies(families);
        }
        systemFont.setStyleStrategy(QFont::PreferAntialias);
        QApplication::setFont(systemFont);
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: inherited system font family=%1 fallback=%2 pointSize=%3 antialias=1")
                       .arg(systemFont.family())
                       .arg(systemFont.families().join(QStringLiteral(",")))
                       .arg(systemFont.pointSizeF(), 0, 'f', 2));
        UacDeskWindow window;
        window.setInitialStatus(QStringLiteral("SYSTEM/UIAccess 已接管，正在等待 UAC 安全桌面事件"));
        if (!window.setParentWatch(parent, parentCreation))
        {
            return 11;
        }
        QObject::connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, &window,
                         [&window](Qt::ColorScheme) { window.refreshAppearance(); });

        UacEventMonitor monitor;
        monitor.onDesktopChanged = [&window] {
            // WinEvent/ETW only wakes the short polling window.  All window
            // enumeration and AppInfo memory reading stays in the existing
            // worker, while the Qt thread only changes timer/UI state.
            QTimer::singleShot(0, &window, [&window] {
                window.notifyUacActivity();
                window.refreshNow();
            });
        };
        monitor.start();
        // The companion is intentionally hidden until a positive UAC window
        // match is produced.  Winlogon is also used by the lock screen, so
        // showing the window at startup would leak the panel onto the lock UI.
        QTimer::singleShot(0, &window, [&window] { window.refreshNow(); });
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: UIAccess window started and monitor attached"));
        const QString handoff = valueAfter(args, QStringLiteral("--ksword-uac-handoff="));
        if (!handoff.isEmpty())
        {
            HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, handoff.toStdWString().c_str());
            if (ready) { SetEvent(ready); CloseHandle(ready); }
        }
        const int code = app.exec();
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system: QApplication::exec returned code=%1").arg(code));
        return code;
    }
}

int main(int argc, char* argv[])
{
    initializeProcessDpiAwareness();
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("process-entry: argc=%1").arg(argc));
    qInstallMessageHandler(&qtMessageHandler);
    QApplication bootstrap(argc, argv);
    const QString executable = QCoreApplication::applicationFilePath();
    const QStringList args = QCoreApplication::arguments();
    const QString stage = valueAfter(args, QStringLiteral("--ksword-uac-stage="));
    if (stage.compare(QStringLiteral("collector"), Qt::CaseInsensitive) == 0)
        return runUacScanCollector(args);
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("process-entry: stage=%1 executable=%2").arg(stage, executable));
    if (stage.compare(QStringLiteral("admin"), Qt::CaseInsensitive) == 0)
        return runAdmin(executable, args);
    if (stage.compare(QStringLiteral("system"), Qt::CaseInsensitive) == 0)
        return runSystem(executable, args, bootstrap);
    return runInitial(executable, args);
}
