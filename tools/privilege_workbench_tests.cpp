// Runs the production pages and Windows read-only collectors; performs no account/policy writes.
#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeAccountPages.h"
#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeTokenPages.h"
#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeAccessPage.h"
#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeSnapshotPage.h"
#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeSnapshotModel.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "../Ksword5.1/Ksword5.1/theme.h"
#include "privilege_token_pages_tests.h"
#include "privilege_access_page_tests.h"
#include "../Ksword5.1/Ksword5.1/PrivilegeDock/PrivilegeAccessBackend.h"
#include "../Ksword5.1/Ksword5.1/MiscDock/DiskEditor/StorageControllerResearchDialog.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFont>
#include <QFontDatabase>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QThread>
#include <QThreadPool>
#include <QTimer>
#include <QTreeWidget>

#include <cstdio>
#include <cstdlib>
#include <memory>

// 夹具只替换设置开关；不会确认或发起任何真实控制器操作。
namespace ks::settings
{
    bool dangerousActionConfirmationsSuppressed()
    {
        return false;
    }
}

namespace
{
    int assertions = 0;
    void require(bool condition, const char* description)
    {
        ++assertions;
        if (!condition) { std::fprintf(stderr, "FAIL: %s\n", description); std::exit(1); }
    }

    QJsonObject section(QJsonArray entries = {}, QJsonArray errors = {})
    { return {{QStringLiteral("entries"), entries}, {QStringLiteral("errors"), errors}}; }
    QJsonObject entry(const QString& key, const QJsonValue& value)
    { return {{QStringLiteral("key"), key}, {QStringLiteral("value"), value}}; }
    QJsonObject snapshot(QJsonObject policy, QJsonObject token = section())
    {
        return {{QStringLiteral("schema"), QStringLiteral("ksword.permission.snapshot")},
            {QStringLiteral("version"), 1}, {QStringLiteral("computer"), QStringLiteral("fixture")},
            {QStringLiteral("capturedUtc"), QStringLiteral("2026-10-07T15:00:00.000Z")}, {QStringLiteral("tokenIncluded"), true},
            {QStringLiteral("policy"), policy}, {QStringLiteral("token"), token}};
    }

    void testDifferences()
    {
        using namespace ks::privilege;
        QString error;
        const auto a = snapshot(section({entry(QStringLiteral("keep"), true), entry(QStringLiteral("remove"), "x"), entry(QStringLiteral("change"), false)}));
        const auto b = snapshot(section({entry(QStringLiteral("change"), true), entry(QStringLiteral("add"), "y"), entry(QStringLiteral("keep"), true)}));
        auto differences = comparePermissionSnapshots(a, b, &error);
        require(error.isEmpty() && differences.size() == 3, "adds/removals/modifications independently compared");
        require(differences[0].kind == SnapshotDifference::Kind::Added, "stable sorted addition");
        require(differences[1].kind == SnapshotDifference::Kind::Modified, "changed flag");
        require(differences[2].kind == SnapshotDifference::Kind::Removed, "stable sorted removal");
        require(comparePermissionSnapshots(a, a, &error).isEmpty() && error.isEmpty(), "identical snapshots have no differences");
        const auto partialBefore = snapshot(section({entry(QStringLiteral("keep"), true)}, {QStringLiteral("access denied")}));
        differences = comparePermissionSnapshots(partialBefore, b, &error);
        require(differences.size() == 2, "partial before retains known items");
        for (const auto& row : differences) require(row.kind == SnapshotDifference::Kind::Uncertain, "missing in partial baseline is not an addition");
        differences = comparePermissionSnapshots(a, partialBefore, &error);
        require(differences.size() == 2, "partial after retains known items");
        for (const auto& row : differences) require(row.kind == SnapshotDifference::Kind::Uncertain, "missing in partial current is not a removal");
        auto invalid = a;
        invalid.insert(QStringLiteral("version"), 2);
        require(!validatePermissionSnapshot(invalid, &error) && !error.isEmpty(), "reject unknown version");
        invalid = a; invalid.insert(QStringLiteral("policy"), section({entry(QStringLiteral("same"), true), entry(QStringLiteral("same"), false)}));
        require(!validatePermissionSnapshot(invalid, &error), "reject duplicate evidence keys");
        invalid = a; invalid.insert(QStringLiteral("policy"), section({QJsonObject{{QStringLiteral("key"), QStringLiteral("missing")}}}));
        require(!validatePermissionSnapshot(invalid, &error), "reject missing evidence value");
        invalid = a; invalid.insert(QStringLiteral("policy"), section({entry(QStringLiteral("null"), QJsonValue(QJsonValue::Null))}));
        require(!validatePermissionSnapshot(invalid, &error), "reject null evidence value");
        invalid = a; invalid.insert(QStringLiteral("policy"), section({}, {5}));
        require(!validatePermissionSnapshot(invalid, &error), "reject malformed diagnostic");
        invalid = b; invalid.insert(QStringLiteral("computer"), QStringLiteral("another"));
        require(comparePermissionSnapshots(a, invalid, &error).isEmpty() && !error.isEmpty(), "reject cross-computer local policy comparison");
        require(comparePermissionSnapshots(snapshot(section({entry(QStringLiteral("type"), "1")})), snapshot(section({entry(QStringLiteral("type"), 1)})), &error).size() == 1,
            "typed values cannot collapse string/number identity");
        require(validatePermissionSnapshot(QJsonDocument::fromJson(QJsonDocument(a).toJson()).object(), &error), "snapshot export/import roundtrip");
        auto unknown = entry(QStringLiteral("value"), QStringLiteral("access denied"));
        unknown.insert(QStringLiteral("state"), QStringLiteral("unreadable"));
        differences = comparePermissionSnapshots(snapshot(section(), section({entry(QStringLiteral("value"), true)})),
            snapshot(section(), section({unknown})), &error);
        require(differences.size() == 1 && differences[0].kind == SnapshotDifference::Kind::Uncertain, "unreadable endpoint is not a modification");
        invalid = a; invalid.insert(QStringLiteral("tokenIncluded"), QStringLiteral("true"));
        require(!validatePermissionSnapshot(invalid, &error), "reject non-boolean capture options");
        invalid = a; invalid.insert(QStringLiteral("policy"), section({entry(QStringLiteral("object"), QJsonObject{})}));
        require(!validatePermissionSnapshot(invalid, &error), "reject non-scalar evidence values");
        differences = comparePermissionSnapshots(snapshot(section({entry(QStringLiteral("account/S-1/enabled"), false)})),
            snapshot(section({entry(QStringLiteral("account/S-1/enabled"), true)})), &error);
        require(differences.size() == 1 && differences[0].kind == SnapshotDifference::Kind::Enabled, "account enabled change has a specific action label");
        differences = comparePermissionSnapshots(snapshot(section(), section({entry(QStringLiteral("privileges/SeDebugPrivilege/enabled"), "1")})),
            snapshot(section(), section({entry(QStringLiteral("privileges/SeDebugPrivilege/enabled"), "0")})), &error);
        require(differences.size() == 1 && differences[0].kind == SnapshotDifference::Kind::Disabled, "token disabled change has a specific action label");
        auto invalidState = entry(QStringLiteral("state"), true);
        invalidState.insert(QStringLiteral("state"), 1);
        require(!validatePermissionSnapshot(snapshot(section({invalidState})), &error), "reject non-string evidence state");
    }

    void drain(int milliseconds)
    {
        QElapsedTimer timer; timer.start();
        while (timer.elapsed() < milliseconds)
        { QApplication::processEvents(QEventLoop::AllEvents, 20); QThread::msleep(5); }
    }

    void testCollectors()
    {
        const auto token = ks::privilege::captureTokenSnapshot(GetCurrentProcessId());
        require(token.value(QStringLiteral("entries")).isArray(), "real token collector returns entries");
        require(token.value(QStringLiteral("errors")).isArray(), "real token collector reports partial coverage");
        require(!token.value(QStringLiteral("entries")).toArray().isEmpty(), "own token fields can be read");
        const auto metadata = token.value(QStringLiteral("metadata")).toObject();
        require(metadata.value(QStringLiteral("creationTime100ns")).toString().toULongLong() != 0, "token read anchored to process creation time");
        const auto missing = ks::privilege::captureTokenSnapshot(0xFFFFFFFCUL);
        require(!missing.value(QStringLiteral("errors")).toArray().isEmpty(), "nonexistent process reports errors, not empty success");
        const auto policy = ks::privilege::captureAccountPolicySnapshot();
        QString error;
        require(ks::privilege::validatePermissionSnapshot(snapshot(policy, token), &error), "real policy/token snapshot obeys persistence contract");
        require(ks::privilege::comparePermissionSnapshots(snapshot(policy, token), snapshot(policy, token), &error).isEmpty() && error.isEmpty(),
            "unchanged real canonical evidence has no differences");
    }

    // 真实编辑器与内存日志缓冲回归，不枚举账户、不调用 LSA 或设备接口。
    void testEditorsAndControllerLog()
    {
        using namespace ks::privilege::access::detail;
        Result evidence;
        evidence.request.pid = 123;
        evidence.request.path = QStringLiteral("C:/fixture/raw [value]: 7");
        evidence.request.desired = READ_CONTROL;
        evidence.descriptorSddl = QStringLiteral("D:(A;;RC;;;WD)");
        evidence.labelError = ERROR_ACCESS_DENIED;
        const auto document = buildAccessDocument(evidence);
        const QString report = document.toPlainText(true);
        ks::ui::StructuredFieldView editor;
        editor.setDocument(document);
        require(!(editor.tree()->model()->flags(editor.tree()->model()->index(0, 0)) & Qt::ItemIsEditable), "native report fields remain read-only");
        require(editor.plainText() == report, "native editor exports the only report model without a text mirror");
        require(report.contains(evidence.request.path), "report preserves dynamic object text");
        require(report.contains(evidence.descriptorSddl), "report preserves descriptor evidence");

        ks::misc::detail::ControllerLogBuffer log;
        for (int index = 0; index < 700; ++index)
        {
            const QString entry = QStringLiteral("[%1] block-%2").arg(index).arg(index);
            const int discarded = log.append(entry);
            require(discarded == (index >= 500 ? 1 : 0), "log discards only the oldest excess block");
            require(log.blockCount() == std::min(index + 1, 500), "log keeps the 500-block budget");
        }
        require(log.text().startsWith(QStringLiteral("[200] block-200")), "log retains oldest surviving block");
        require(log.text().endsWith(QStringLiteral("[699] block-699")), "log retains latest complete block");
        require(log.append(QStringLiteral("raw A\nraw B\nraw C")) == 3, "multiline append enforces block rather than entry budget");
        require(log.blockCount() == 500 && log.text().endsWith(QStringLiteral("raw A\nraw B\nraw C")),
            "multiline log remains intact within the block budget");
        CodeEditorWidget rawEditor;
        rawEditor.setReadOnly(true);
        rawEditor.setRawText(log.text());
        require(rawEditor.text() == log.text(), "actual built-in editor preserves raw log lines");

        // 构造隐藏页面即可核验布局；不 show，因而不会触发查询接口的 showEvent。
        ks::misc::StorageControllerResearchDialog controller;
        auto* controllerLog = controller.findChild<CodeEditorWidget*>(QStringLiteral("storage_controller_log"));
        require(controllerLog && controllerLog->isReadOnly(), "production controller page uses read-only built-in editor");
        require(controllerLog->maximumHeight() == 120, "controller log retains its 120-pixel height cap");
        std::unique_ptr<QWidget> access(ks::privilege::createAccessDiagnosticPage(nullptr));
        auto* accessReport = access->findChild<ks::ui::StructuredFieldView*>(QStringLiteral("privilege_access_report"));
        require(accessReport && accessReport->tree()->editTriggers() == QAbstractItemView::NoEditTriggers,
            "production access page uses read-only native report fields");
    }

    void testPages(const QString& screenshotDirectory)
    {
        using Factory = QWidget* (*)(QWidget*);
        const Factory factories[]{[](QWidget* parent) { return ks::privilege::createAccountManagementPage(parent); }, ks::privilege::createGroupsPage,
            ks::privilege::createRightsPage, ks::privilege::createTokenComparePage,
            ks::privilege::createAccessDiagnosticPage, ks::privilege::createIdentityLaunchPage,
            ks::privilege::createPermissionSnapshotPage};
        int index = 0;
        for (Factory factory : factories)
        {
            std::unique_ptr<QWidget> page(factory(nullptr));
            page->resize(1000, 720); page->show(); drain(80);
            require(!page->findChildren<QTableWidget*>().isEmpty(), "production page has data presentation");
            require(!page->findChildren<QPushButton*>().isEmpty(), "production page has actions");
            if (!screenshotDirectory.isEmpty()) require(page->grab().save(screenshotDirectory + QStringLiteral("/privilege-review-page-%1.png").arg(index)), "save actual page render");
            // Exercise destruction with asynchronous initial queries still in flight.
            page.reset(); drain(30); ++index;
        }
        {
            std::unique_ptr<QWidget> sessions(ks::privilege::createSessionsPage(nullptr));
            sessions->resize(1000, 720); sessions->show(); drain(80);
            require(sessions->findChildren<QTableWidget*>().size() >= 2, "sessions and linked processes have separate views");
            if (!screenshotDirectory.isEmpty()) require(sessions->grab().save(screenshotDirectory + QStringLiteral("/privilege-review-sessions.png")), "render sessions");
        }
        drain(100);
        require(QThreadPool::globalInstance()->waitForDone(30000), "page destruction leaves workers completing within bound");
        drain(30);
    }
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    const int fontId = QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    const QStringList families = QFontDatabase::applicationFontFamilies(fontId);
    app.setFont(QFont(families.isEmpty() ? QStringLiteral("Microsoft YaHei UI") : families.first(), 9));
    ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"));
    testDifferences();
    testEditorsAndControllerLog();
    const bool offlineOnly = argc > 2 && QString::fromLocal8Bit(argv[2]) == QStringLiteral("--offline-only");
    if (offlineOnly)
    {
        std::printf("PASS: %d offline assertions (actual editors, production report and bounded log; no account/LSA/device I/O)\n", assertions);
        return 0;
    }
    testCollectors();
    try
    {
        assertions += RunPrivilegeTokenPagesChecks();
        assertions += RunPrivilegeAccessPageChecks(argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString());
    }
    catch (const std::exception& error) { std::fprintf(stderr, "FAIL token/session/access UI: %s\n", error.what()); return 1; }
    testPages(argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString());
    require(ks::i18n::LanguageManager::instance().setLanguage(QStringLiteral("en-US")), "load English language pack");
    const auto translatedTab = ks::i18n::contextText(QStringLiteral("privilege.workbench.tab.tokens"), QStringLiteral("令牌对比"));
    if (translatedTab != QStringLiteral("Token comparison")) std::fprintf(stderr, "Translated tab: %s\n", translatedTab.toUtf8().constData());
    require(translatedTab == QStringLiteral("Token comparison"), "workbench tabs have real English translations");
    testPages(QString());
    std::printf("PASS: %d assertions (production pages, Windows read-only collectors, snapshot model)\n", assertions);
    return 0;
}
