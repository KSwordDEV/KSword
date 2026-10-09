#pragma once

#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeAccessPage.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <QApplication>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QLineEdit>
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include <QPushButton>
#include <QTableWidget>
#include <QTemporaryFile>
#include <QThread>
#include <QThreadPool>
#include <functional>
#include <memory>
#include <stdexcept>

// Creates only a disposable file under fixtureDirectory. All tested system objects are opened
// for read/query permissions; this fixture never sets security, registry values or service state.
inline int RunPrivilegeAccessPageChecks(const QString& fixtureDirectory = QString(), QWidget* owner = nullptr)
{
    int checks = 0;
    auto require = [&checks](bool passed, const char* description)
    {
        if (!passed) throw std::runtime_error(description);
        ++checks;
    };
    auto until = [](const std::function<bool()>& ready)
    {
        QElapsedTimer elapsed; elapsed.start();
        while (elapsed.elapsed() < 30000)
        {
            QApplication::processEvents(QEventLoop::AllEvents, 5);
            if (ready()) return true;
            QThread::msleep(1);
        }
        return false;
    };
    auto translated = [](const char* key, const QString& source)
    { return ks::i18n::contextText(QString::fromLatin1(key), source); };
    const QString allowed = translated("privilege.workbench.access.allowed", QStringLiteral("描述符允许"));
    const QString probeOpened = translated("privilege.workbench.access.report.probe_opened",
        QStringLiteral("实际打开：所选主令牌已获准打开同一对象并关闭句柄；这仅证明该时刻的句柄申请成功。"));
    const QString directory = fixtureDirectory.isEmpty() ? QCoreApplication::applicationDirPath() : fixtureDirectory;
    require(QDir().mkpath(directory), "Access test fixture directory must exist");
    QTemporaryFile fixture(QDir(directory).filePath(QStringLiteral("privilege-access-XXXXXX.txt")));
    fixture.setAutoRemove(true);
    require(fixture.open(), "Create disposable access fixture");
    constexpr char seed[] = "KSword access probe: read-only contents\n\0binary-tail";
    const QByteArray original(seed, sizeof(seed) - 1);
    require(fixture.write(original) == original.size() && fixture.flush(), "Write disposable fixture seed");
    const QString path = fixture.fileName();
    fixture.close();
    auto unchanged = [&]()
    {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) && file.readAll() == original;
    };
    require(unchanged(), "Fixture seed must round-trip before tests");

    struct Controls
    {
        QLineEdit *pid = nullptr, *path = nullptr, *mask = nullptr;
        QComboBox* kind = nullptr;
        QPushButton *assess = nullptr, *probe = nullptr;
        CodeEditorWidget* report = nullptr;
        QTableWidget* aces = nullptr;
    };
    auto controls = [](QWidget* page)
    {
        return Controls{page->findChild<QLineEdit*>(QStringLiteral("privilege_access_pid")),
            page->findChild<QLineEdit*>(QStringLiteral("privilege_access_path")),
            page->findChild<QLineEdit*>(QStringLiteral("privilege_access_mask")),
            page->findChild<QComboBox*>(QStringLiteral("privilege_access_kind")),
            page->findChild<QPushButton*>(QStringLiteral("privilege_access_assess")),
            page->findChild<QPushButton*>(QStringLiteral("privilege_access_probe")),
            page->findChild<CodeEditorWidget*>(QStringLiteral("privilege_access_report")),
            page->findChild<QTableWidget*>(QStringLiteral("privilege_access_aces"))};
    };
    // 使用实际内置编辑器检查报告边界，夹具不会操作真实账户或写系统对象。
    auto setRequest = [&](const Controls& c, int kind, const QString& target, DWORD mask)
    {
        c.pid->setText(QString::number(GetCurrentProcessId()));
        c.kind->setCurrentIndex(kind);
        c.path->setText(target);
        c.mask->setText(QStringLiteral("0x%1").arg(mask, 0, 16));
    };
    auto assess = [&](const Controls& c)
    {
        c.assess->click();
        require(until([&]() { return c.assess->isEnabled() && c.aces->isEnabled(); }), "Access descriptor assessment timed out");
    };
    auto probe = [&](const Controls& c)
    {
        require(c.probe->isEnabled(), "Actual handle probe requires a successful descriptor anchor");
        c.probe->click();
        require(until([&]() { return c.assess->isEnabled() && c.aces->isEnabled(); }), "Actual handle probe timed out");
        require(c.report->text().contains(probeOpened), "Actual handle probe must verify the same object identity");
    };
    std::unique_ptr<QWidget> page(ks::privilege::createAccessDiagnosticPage(owner));
    page->show();
    const auto c = controls(page.get());
    require(c.pid && c.path && c.mask && c.kind && c.assess && c.probe && c.report && c.aces,
        "Production access page must expose expected controls");
    require(c.kind->count() == 3 && c.kind->itemData(0).toInt() == 0
        && c.kind->itemData(1).toInt() == 1 && c.kind->itemData(2).toInt() == 2,
        "Object kind mapping must remain file/registry/service");
    require(c.report->isReadOnly(), "Built-in access report editor must be read-only");
    require(!c.probe->isEnabled(), "Unassessed targets must not permit an actual probe");
    setRequest(c, 0, path, READ_CONTROL | FILE_READ_DATA);
    assess(c);
    require(c.probe->isEnabled(), "Own temporary file descriptor must be assessable");
    const QString document = c.report->text();
    require(document.contains(QStringLiteral("SDDL:")) && document.contains(path), "File assessment must report descriptor and bound target");
    QString nativeLine;
    for (const auto& line : document.split(QChar('\n')))
        if (line.startsWith(QStringLiteral("AccessCheck"))) nativeLine = line;
    require(nativeLine.contains(allowed), "Native descriptor assessment must permit read-only fixture access");
    require(document.contains(QStringLiteral("AuthzAccessCheck")), "Authz assessment must be shown separately");
    require(!document.contains(probeOpened), "Descriptor assessment alone must not claim a successful actual open");
    require(c.aces->rowCount() > 0, "Inherited fixture DACL must populate ACE explanation rows");
    require(unchanged(), "Descriptor assessment must leave file bytes unchanged");
    HANDLE beforeToken = nullptr;
    const bool hadToken = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &beforeToken) != FALSE;
    const DWORD beforeError = hadToken ? ERROR_SUCCESS : GetLastError();
    if (beforeToken) CloseHandle(beforeToken);
    probe(c);
    HANDLE afterToken = nullptr;
    const bool hasToken = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &afterToken) != FALSE;
    const DWORD afterError = hasToken ? ERROR_SUCCESS : GetLastError();
    if (afterToken) CloseHandle(afterToken);
    require(hadToken == hasToken && beforeError == afterError, "Actual probe must leave the GUI thread identity unchanged");
    require(unchanged(), "Actual handle open/close must leave file bytes unchanged");

    // A validation failure must not leave the previous allowed/probe-success report visible.
    c.pid->setText(QStringLiteral("0")); c.assess->click();
    require(!c.probe->isEnabled() && !c.report->text().contains(probeOpened)
        && !c.report->text().contains(allowed), "Invalid zero PID must invalidate old allowed evidence");
    c.pid->setText(QString::number(MAXDWORD));
    assess(c);
    require(!c.probe->isEnabled() && !c.report->text().contains(allowed)
        && !c.report->text().contains(probeOpened), "Nonexistent process must not be presented as allowed");
    require(!c.report->text().trimmed().isEmpty(), "Invalid PID must have a visible diagnostic");
    setRequest(c, 0, path + QStringLiteral(".does-not-exist"), READ_CONTROL | FILE_READ_DATA);
    assess(c);
    require(!c.probe->isEnabled() && !c.report->text().contains(allowed)
        && !c.report->text().contains(probeOpened), "Nonexistent target path must not be presented as allowed");
    require(unchanged(), "Failed probes must leave the existing fixture unchanged");

    QString registryTarget;
    for (const wchar_t* name : {L"Environment", L"Software", L""})
    {
        HKEY key = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, name, 0, READ_CONTROL | KEY_QUERY_VALUE | KEY_WOW64_64KEY, &key) == ERROR_SUCCESS)
        {
            RegCloseKey(key);
            registryTarget = QStringLiteral("HKCU") + (name[0] ? QStringLiteral("\\") + QString::fromWCharArray(name) : QString());
            break;
        }
    }
    require(!registryTarget.isEmpty(), "A safe existing current-user registry key must be readable");
    setRequest(c, 1, registryTarget, READ_CONTROL | KEY_QUERY_VALUE);
    assess(c);
    require(c.probe->isEnabled() && c.report->text().contains(registryTarget), "HKCU descriptor must resolve under selected user SID");
    probe(c);
    require(unchanged(), "Registry checks must leave the file fixture unchanged");

    // Service coverage is optional if the current account cannot query any of these services.
    QString serviceName;
    const SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (manager)
    {
        for (const wchar_t* name : {L"EventLog", L"Spooler", L"Winmgmt", L"Dnscache"})
        {
            const SC_HANDLE service = OpenServiceW(manager, name, READ_CONTROL | SERVICE_QUERY_STATUS);
            if (!service) continue;
            CloseServiceHandle(service); serviceName = QString::fromWCharArray(name); break;
        }
        CloseServiceHandle(manager);
    }
    if (!serviceName.isEmpty())
    {
        setRequest(c, 2, serviceName, READ_CONTROL | SERVICE_QUERY_STATUS);
        assess(c);
        require(c.probe->isEnabled(), "Readable service descriptor must produce a retained object anchor");
        probe(c);
        require(unchanged(), "Service handle queries must leave file bytes unchanged");
    }

    setRequest(c, 0, path, READ_CONTROL | FILE_READ_DATA);
    c.assess->click(); page.reset();
    require(QThreadPool::globalInstance()->waitForDone(30000), "Destroyed access page must let read-only assessment workers finish");
    QApplication::processEvents(QEventLoop::AllEvents, 5);
    require(unchanged(), "Destroying page during descriptor assessment must not alter file");
    std::unique_ptr<QWidget> probePage(ks::privilege::createAccessDiagnosticPage(owner));
    probePage->show(); const auto pc = controls(probePage.get());
    setRequest(pc, 0, path, READ_CONTROL | FILE_READ_DATA); assess(pc);
    require(pc.probe->isEnabled(), "Destruction fixture must have a valid probe anchor");
    pc.probe->click(); probePage.reset();
    require(QThreadPool::globalInstance()->waitForDone(30000), "Destroyed access page must release dedicated impersonation probe safely");
    QApplication::processEvents(QEventLoop::AllEvents, 5);
    require(unchanged(), "Destroying page during handle probe must not alter file");
    return checks;
}
