#include "X64DbgNavigation.h"
#include "../Internationalization/LanguageManager.h"
#include <Windows.h>
#include <QAction>
#include <QApplication>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QProcess>
#include <QSettings>
#include <QTimer>

namespace ks::ui::x64dbg_navigation
{
    namespace
    {
        QString text(const char* key, const QString& fallback)
        { return ks::i18n::LanguageManager::instance().text(QString::fromLatin1(key), fallback); }
        void failure(QWidget* owner, const QString& message)
        {
            auto* dialog = new QMessageBox(QMessageBox::Warning,
                text("x64dbg.navigation.title", QStringLiteral("x64dbg 导航")), message, QMessageBox::Ok, owner);
            dialog->setAttribute(Qt::WA_DeleteOnClose); dialog->open();
        }
        QString launcher()
        { return QDir(QApplication::applicationDirPath()).filePath(QStringLiteral("plugin/x96dbg/KswordX96dbgLauncher.exe")); }
        QString settingsPath()
        { return QDir(QApplication::applicationDirPath()).filePath(QStringLiteral("x64dbg-navigation.ini")); }
        QHash<QString, QPointer<QProcess>> requests;
        QString errorMessage(const QString& code, int win32Error)
        {
            if (code == QStringLiteral("navigation_not_confirmed") && win32Error == ERROR_IO_PENDING)
                return text("x64dbg.navigation.pending", QStringLiteral("导航已提交，但结果尚未确认。请检查现有 x64dbg 窗口；不会自动重试。调试执行状态未改变。"));
            if (code == QStringLiteral("navigation_bridge_missing"))
                return text("x64dbg.navigation.bridge_missing", QStringLiteral("缺少导航桥接插件。请将 KSwordNavigation.dp64 放入所选 x64dbg 的 plugins 目录；32 位使用 KSwordNavigation.dp32。"));
            if (code == QStringLiteral("target_already_debugged_without_bridge") || code == QStringLiteral("debugger_owner_unknown"))
                return text("x64dbg.navigation.busy", QStringLiteral("目标已由未连接的调试器占用，或无法确认调试器身份。请在现有 x64dbg 中加载导航桥接插件后重试。"));
            if (code == QStringLiteral("x32dbg_not_configured") || code == QStringLiteral("debugger_architecture_mismatch"))
                return text("x64dbg.navigation.architecture", QStringLiteral("缺少与目标位数匹配的调试器。请在“x64dbg 设置”中选择包含 x32dbg/x64dbg 的安装目录。"));
            if (code == QStringLiteral("target_changed") || code == QStringLiteral("target_unavailable"))
                return text("x64dbg.navigation.target_changed", QStringLiteral("原目标进程已退出、身份已改变，或当前权限无法访问。请重新选择目标。"));
            return text("x64dbg.navigation.failed", QStringLiteral("未能确认 x64dbg 已完成定位（%1，Win32=%2）。现有调试会话保持原状。"))
                .arg(code).arg(win32Error);
        }
    }
    quint64 ProcessCreateTime100ns(quint32 pid) noexcept
    {
        if (pid == 0)
        {
            return 0;
        }
        const HANDLE process = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid); // 持有当前对象直至核验结束。
        if (process == nullptr)
        {
            return 0;
        }
        FILETIME created{}, exited{}, kernel{}, user{};
        // 已退出进程即使仍有句柄也不能成为新的导航目标。
        const bool ok = GetProcessId(process) == pid
            && WaitForSingleObject(process, 0) == WAIT_TIMEOUT
            && GetProcessTimes(process, &created, &exited, &kernel, &user) != FALSE;
        CloseHandle(process);
        return ok ? (static_cast<quint64>(created.dwHighDateTime) << 32) | created.dwLowDateTime : 0;
    }
    void Configure(QWidget* owner)
    {
        QSettings settings(settingsPath(), QSettings::IniFormat);
        const QString previous = settings.value(QStringLiteral("debugger")).toString();
        const QString selected = QFileDialog::getOpenFileName(owner,
            text("x64dbg.navigation.select_installation", QStringLiteral("选择 x64dbg.exe 或 x32dbg.exe（需安装导航桥接插件）")), previous,
            QStringLiteral("x64dbg/x32dbg (x64dbg.exe x32dbg.exe)"));
        if (!selected.isEmpty()) { settings.setValue(QStringLiteral("debugger"), QFileInfo(selected).absoluteFilePath()); settings.sync(); }
    }
    void Open(QWidget* owner, const Target& supplied)
    {
        const Target target = supplied; // 保留原目标身份，不把当前 PID 的身份写回旧快照。
        const IdentityStatus identity = CheckCapturedIdentity(target, ProcessCreateTime100ns);
        if (identity != IdentityStatus::Matching)
        {
            failure(owner, errorMessage(QStringLiteral("target_changed"), ERROR_INVALID_STATE));
            return;
        }
        if (!QFileInfo::exists(launcher()))
        {
            failure(owner, text("x64dbg.navigation.launcher_missing", QStringLiteral("请先安装或更新 x96dbg 插件，导航需要新版 KswordX96dbgLauncher.exe。")));
            return;
        }
        // A repeated click on the same target/address uses the current request.
        // Separate addresses serialize in the launcher and reuse its confirmed
        // debugger session, instead of opening duplicate debugging processes.
        const QString key = QStringLiteral("%1:%2:%3:%4").arg(target.pid).arg(target.processCreateTime100ns).arg(target.address).arg(static_cast<int>(target.view));
        if (requests.value(key) != nullptr) return;
        QStringList arguments{QStringLiteral("--ksword-plugin"), QStringLiteral("navigate"), QStringLiteral("--"),
            QStringLiteral("--pid"), QString::number(target.pid), QStringLiteral("--create-time"), QString::number(target.processCreateTime100ns),
            QStringLiteral("--address"), QString::number(target.address), QStringLiteral("--view"),
            target.view == View::Dump ? QStringLiteral("dump") : QStringLiteral("cpu")};
        QSettings settings(settingsPath(), QSettings::IniFormat);
        const QString debugger = settings.value(QStringLiteral("debugger")).toString();
        if (!debugger.isEmpty()) arguments << QStringLiteral("--debugger") << debugger;
        auto* process = new QProcess(qApp); requests.insert(key, process);
        const QPointer<QWidget> ownerGuard(owner);
        auto* output = new QByteArray();
        auto* timer = new QTimer(process); timer->setSingleShot(true);
        QObject::connect(process, &QProcess::readyReadStandardOutput, process, [process, output]() {
            const QByteArray incoming = process->readAllStandardOutput();
            if (output->size() < 65536) output->append(incoming.left(65536 - output->size()));
        });
        QObject::connect(timer, &QTimer::timeout, process, [process]() {
            process->setProperty("navigationTimedOut", true);
            // This is only our command helper. It does not own the independently
            // launched debugger or target and cannot terminate them.
            process->kill();
        });
        QObject::connect(process, &QProcess::errorOccurred, process, [process, key, ownerGuard, output](QProcess::ProcessError error) {
            if (error != QProcess::FailedToStart) return;
            requests.remove(key);
            failure(ownerGuard, text("x64dbg.navigation.start_failed", QStringLiteral("无法启动 x64dbg 导航助手：%1")).arg(process->errorString()));
            delete output; process->deleteLater();
        });
        QObject::connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), process,
            [process, timer, key, target, ownerGuard, output](int exitCode, QProcess::ExitStatus status) {
                timer->stop(); output->append(process->readAllStandardOutput()); requests.remove(key);
                bool confirmed = false; QString code = QStringLiteral("navigation_not_confirmed"); int error = ERROR_TIMEOUT;
                for (const auto& line : output->split('\n'))
                {
                    const QJsonObject packet = QJsonDocument::fromJson(line).object();
                    if (packet.value(QStringLiteral("protocol")).toString() != QStringLiteral("ksword-plugin/1")
                        || packet.value(QStringLiteral("plugin_id")).toString() != QStringLiteral("x96dbg")) continue;
                    if (packet.value(QStringLiteral("event")).toString() == QStringLiteral("error"))
                    { code = packet.value(QStringLiteral("code")).toString(); error = packet.value(QStringLiteral("win32_error")).toInt(); }
                    if (packet.value(QStringLiteral("event")).toString() == QStringLiteral("navigation_complete"))
                    {
                        bool timeOk = false, addressOk = false;
                        const auto time = packet.value(QStringLiteral("create_time")).toString().toULongLong(&timeOk);
                        const auto address = packet.value(QStringLiteral("address")).toString().toULongLong(&addressOk);
                        confirmed = timeOk && addressOk && packet.value(QStringLiteral("target_pid")).toDouble() == target.pid
                            && time == target.processCreateTime100ns && (target.address == 0 || address == target.address);
                    }
                }
                if (status != QProcess::NormalExit || exitCode != 0 || !confirmed) failure(ownerGuard, errorMessage(code, error));
                delete output; process->deleteLater();
            });
        process->start(launcher(), arguments); timer->start(35000);
    }
    void AddAction(QMenu* menu, QWidget* owner, const Target& supplied)
    {
        if (menu == nullptr || supplied.pid == 0)
        {
            return;
        }
        const Target target = supplied; // 菜单动作必须绑定原记录，不能在菜单打开时补授身份。
        QAction* action = menu->addAction(target.address == 0
            ? text("x64dbg.navigation.open_process", QStringLiteral("在 x64dbg 中打开进程"))
            : target.view == View::Dump
                ? text("x64dbg.navigation.open_dump", QStringLiteral("在 x64dbg 中打开内存"))
                : text("x64dbg.navigation.open_disassembly", QStringLiteral("在 x64dbg 中打开反汇编")));
        action->setEnabled(HasCapturedIdentity(target.pid, target.processCreateTime100ns));
        QObject::connect(action, &QAction::triggered, owner, [owner, target]() {
            Open(owner, target);
        });
        QAction* configure = menu->addAction(text("x64dbg.navigation.settings", QStringLiteral("x64dbg 设置…")));
        QObject::connect(configure, &QAction::triggered, owner, [owner]() {
            Configure(owner);
        });
    }
}
