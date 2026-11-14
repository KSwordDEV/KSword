#include "../Ksword5.1/Ksword5.1/Framework/BackgroundTaskRegistry.h"
#include "../Ksword5.1/Ksword5.1/UI/ShortcutRegistry.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "../Taskbar/SosHotkeyLauncher.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QThread>
#include <QKeyEvent>
#include <QSettings>
#include <QDir>
#include <QFile>
#include <QTimer>
#include <cstdio>

// Translation is an adapter here; registry, Qt timers, ownership and persistence
// are the actual production implementations. No windows or global keys are used.
namespace ks::i18n
{
    struct LanguageManager::State {};
    LanguageManager::LanguageManager() : QObject(nullptr) {}
    LanguageManager::~LanguageManager() = default;
    LanguageManager& LanguageManager::instance() { static LanguageManager value; return value; }
    QString LanguageManager::text(const QString& key, const QString& fallback) const { return fallback.isEmpty() ? key : fallback; }
    QString LanguageManager::sourceText(const QString& value) const { return value; }
    QString LanguageManager::displayText(const QString& value) const { return value; }
    bool LanguageManager::eventFilter(QObject* object, QEvent* event) { return QObject::eventFilter(object, event); }
}

namespace
{
    int checks = 0, failures = 0;
    void check(bool value, const char* label)
    {
        ++checks;
        if (!value) { ++failures; std::printf("FAIL %s\n", label); }
    }
    void pump(int milliseconds)
    {
        QEventLoop loop;
        QTimer::singleShot(milliseconds, &loop, &QEventLoop::quit);
        loop.exec();
    }
    void shortcutTests(const QString& path)
    {
        using ks::ui::ShortcutRegistry;
        ShortcutRegistry registry(nullptr, path);
        check(registry.define({"one", "One", "application", {}, QKeySequence("Ctrl+A"), {}}), "define command");
        check(registry.define({"two", "Two", "application", {}, QKeySequence("Ctrl+B"), {}}), "define second command");
        check(!registry.define({"one", "Wrong", "other", {}, QKeySequence("Ctrl+A"), {}}), "reject id reused for another context");
        QObject owner;
        QKeySequence applied;
        check(registry.attach("one", &owner, [&](const QKeySequence& keys, QString*) { applied = keys; return true; }), "attach target");
        check(applied == QKeySequence("Ctrl+A"), "initial binding applied");
        QObject hint;
        registry.setShortcutHint("one", &hint, QStringLiteral("Command description"));
        check(hint.property("toolTip").toString().contains(QKeySequence("Ctrl+A").toString(QKeySequence::NativeText)), "tooltip initially uses actual binding");
        QString error;
        check(!registry.rebind("one", QKeySequence("Ctrl+B"), &error) && !error.isEmpty(), "reject overlap with another command");
        check(applied == QKeySequence("Ctrl+A"), "conflict leaves physical target unchanged");
        check(registry.rebind("one", QKeySequence("Ctrl+Shift+A"), &error), "rebind and persist");
        check(applied == QKeySequence("Ctrl+Shift+A"), "target receives new binding");
        check(hint.property("toolTip").toString().endsWith(QKeySequence("Ctrl+Shift+A").toString(QKeySequence::NativeText)), "tooltip follows successful rebind");
        check(!registry.rebind("one", QKeySequence("A, B"), &error), "single chord command rejects sequence");
        ShortcutRegistry loaded(nullptr, path);
        check(loaded.define({"one", "One", "application", {}, QKeySequence("Ctrl+A"), {}}), "define in fresh registry");
        check(loaded.binding("one") == applied, "persisted binding reloaded before target creation");
        check(registry.rebind("one", {}, &error) && applied.isEmpty(), "clear binding disables only that command");
        check(hint.property("toolTip").toString() == QStringLiteral("Command description"), "clearing removes the stale shortcut hint");
        check(registry.binding("two") == QKeySequence("Ctrl+B"), "clearing preserves unrelated binding");
        ShortcutRegistry disabled(nullptr, path);
        disabled.define({"one", "One", "application", {}, QKeySequence("Ctrl+A"), {}});
        check(disabled.binding("one").isEmpty(), "empty binding survives restart");
        check(registry.restoreDefault("one", &error), "restore default binding");
        check(applied == QKeySequence("Ctrl+A"), "default applied to existing target");
        check(!QSettings(path, QSettings::IniFormat).contains("shortcuts/one"), "default restoration removes override");
        ShortcutRegistry::Command fixed{"fixed", "Fixed", "system", "Fixed recovery", QKeySequence("Ctrl+Alt+F10"), {}};
        fixed.editable = false;
        registry.define(fixed);
        check(!registry.rebind("fixed", {}, &error), "fixed recovery cannot be unbound");
        QObject badOwner;
        registry.define({"bad", "Bad", "other", {}, QKeySequence("Ctrl+D"), {}});
        QKeySequence first, second;
        registry.attach("bad", &owner, [&](const QKeySequence& keys, QString*) { first = keys; return true; });
        registry.attach("bad", &badOwner, [&](const QKeySequence& keys, QString*) {
            if (keys == QKeySequence("Ctrl+E")) return false;
            second = keys; return true;
        });
        check(!registry.rebind("bad", QKeySequence("Ctrl+E"), &error), "setter failure is reported");
        check(first == QKeySequence("Ctrl+D") && second == first, "partial setter application rolls back all targets");
        check(registry.binding("bad") == first, "failed edit preserves registry state");
        auto* transient = new QObject;
        registry.attach("two", transient, [](const QKeySequence&, QString*) { return true; });
        delete transient;
        check(registry.rebind("two", QKeySequence("Ctrl+Z"), &error), "destroyed target is never called");
        registry.define({"refresh", "Refresh", "page", {}, QKeySequence(Qt::Key_F5), {}});
        QKeyEvent f5(QEvent::KeyPress, Qt::Key_F5, Qt::NoModifier);
        check(registry.matches("refresh", &f5), "event adapter uses current binding");
        registry.rebind("refresh", QKeySequence(Qt::Key_F6), &error);
        check(!registry.matches("refresh", &f5), "old binding stops matching immediately");
        registry.define({"reentrant", "Reentrant", "page", {}, QKeySequence("Ctrl+R"), {}});
        registry.attach("reentrant", &owner, [&](const QKeySequence& keys, QString*) {
            if (keys == QKeySequence("Ctrl+T"))
                for (int i = 0; i < 100; ++i) registry.define({QString::number(i), "Lazy", "page", {}, {}, {}});
            return true;
        });
        check(registry.rebind("reentrant", QKeySequence("Ctrl+T"), &error), "target may cause registry rehash safely");
    }
    void taskTests(const QString& path)
    {
        using ks::ui::BackgroundTaskRegistry;
        BackgroundTaskRegistry registry(nullptr, path);
        QTimer timer;
        timer.setInterval(5);
        BackgroundTaskRegistry::Policy policy;
        policy.minimumIntervalMs = 1;
        policy.maximumIntervalMs = 200;
        bool eligible = true, inFlight = false;
        policy.eligible = [&]() { return eligible; };
        policy.inFlight = [&]() { return inFlight; };
        check(registry.addTimer("sample", "Sample", "Test", &timer, policy), "register existing timer");
        check(!timer.isActive(), "registration never starts business task");
        check(registry.addTimer("sample", "Sample", "Test", &timer, policy), "idempotent registration");
        QTimer duplicate;
        check(!registry.addTimer("sample", "Duplicate", "Test", &duplicate, policy), "reject duplicate singleton task");
        int duplicateDispatches = 0;
        QObject::connect(&duplicate, &QTimer::timeout, [&]() { ++duplicateDispatches; });
        duplicate.start(1); pump(15);
        check(duplicateDispatches == 0 && !duplicate.isActive(), "rejected duplicate cannot create a second polling loop");
        timer.start(); pump(35);
        auto before = registry.snapshot().front().dispatches;
        check(before > 0, "observe real timer dispatches");
        QString error;
        check(registry.setPaused("sample", true, &error), "pause existing task");
        pump(25);
        check(registry.snapshot().front().dispatches == before && !timer.isActive(), "paused task produces no callbacks");
        timer.start(); pump(25);
        check(registry.snapshot().front().dispatches == before && !timer.isActive(), "owner restart cannot bypass explicit pause");
        check(registry.setInterval("sample", 15, &error) && !timer.isActive(), "interval edit does not unpause");
        check(registry.setPaused("sample", false, &error), "resume task");
        pump(35);
        check(registry.snapshot().front().dispatches > before, "resumed task dispatches");
        inFlight = true;
        check(registry.snapshot().front().inFlight, "in-flight state comes from business owner");
        check(!registry.setInterval("sample", 0, &error) && timer.interval() == 15, "reject busy-loop interval without mutation");
        check(!registry.setInterval("sample", 201, &error), "enforce maximum interval");
        registry.setPaused("sample", true);
        eligible = false;
        registry.setPaused("sample", false);
        check(!timer.isActive(), "resume respects owner eligibility");
        BackgroundTaskRegistry fresh(nullptr, path);
        QTimer reloaded; reloaded.setInterval(5);
        fresh.addTimer("sample", "Sample", "Test", &reloaded, policy);
        check(reloaded.interval() == 15 && !reloaded.isActive(), "persisted interval restored without starting task");
        check(registry.restoreDefault("sample", &error) && timer.interval() == 5, "restore timer default");
        check(!QSettings(path, QSettings::IniFormat).contains("polling/sample"), "default timer removes persisted override");
        policy.canPause = false; policy.canChangeInterval = false; policy.restriction = "Critical drain";
        duplicate.setInterval(10);
        check(registry.addTimer("protected", "Protected", "Test", &duplicate, policy), "register protected task");
        check(!registry.setPaused("protected", true, &error) && !error.isEmpty(), "protected task refuses pause with reason");
        check(!registry.setInterval("protected", 50, &error), "protected task refuses interval change");
        QTimer once; once.setSingleShot(true);
        check(!registry.addTimer("once", "Once", "Test", &once, policy), "one-shot work is not misclassified as persistent polling");
        auto* temporary = new QTimer;
        temporary->setInterval(10);
        policy.allowMultipleInstances = true;
        check(registry.addTimer("temporary", "Temporary", "Test", temporary, policy), "temporary instance is registered");
        const int count = registry.snapshot().size();
        delete temporary;
        check(registry.snapshot().size() == count - 1, "owner destruction removes its task");
        check(!registry.setPaused("missing", true, &error), "stale task identity is rejected");
        auto* nativeOwner = new QObject;
        bool nativeRunning = true, nativePaused = false;
        check(registry.addExternal("native", "Native", "Test", nativeOwner,
            {[&]() { return nativeRunning; }, [&]() { return nativePaused; },
             [&](bool paused) { nativePaused = paused; return true; }}, "Native lifecycle"), "register native event task");
        check(registry.setPaused("native", true, &error) && nativePaused, "native pause delegates to business flow");
        check(registry.isPaused("native"), "native paused state is read back");
        check(registry.setPaused("native", false, &error) && !nativePaused, "native resume uses same flow");
        nativeRunning = false;
        check(!registry.setPaused("native", true, &error), "inactive native task cannot be started by Pause");
        check(!registry.setInterval("native", 100, &error), "event task does not invent a polling interval");
        const int nativeCount = registry.snapshot().size();
        delete nativeOwner;
        check(registry.snapshot().size() == nativeCount - 1, "native task is removed with its owner");
    }

    void rescueLaunchFeedbackTests()
    {
        std::atomic<DWORD> error{0};
        std::atomic_int started{0}, finished{0};
        SosHotkeyLauncher launcher(QCoreApplication::applicationDirPath(), QCoreApplication::applicationFilePath(),
            [&](DWORD code) { error.store(code); }, [&](bool active) { if (active) ++started; else ++finished; });
        check(launcher.start(false), "menu dispatcher can start without installing a keyboard hook");
        launcher.requestLaunch();
        QElapsedTimer deadline; deadline.start();
        while (!error.load() && deadline.elapsed() < 5000) QThread::msleep(5);
        check(started.load() == 1 && finished.load() == 1, "real child process completion releases the pending state");
        check(error.load() == ERROR_NOT_READY, "child startup failure is delivered to the caller");
        error.store(0);
        launcher.requestLaunch(); deadline.restart();
        while (!error.load() && deadline.elapsed() < 5000) QThread::msleep(5);
        check(started.load() == 2 && error.load() == ERROR_NOT_READY, "failed launch can be retried immediately");
        launcher.stop();
    }
}
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().contains(QStringLiteral("--ksword-rescue-host"))) return ERROR_NOT_READY;
    const QDir directory(QCoreApplication::applicationDirPath());
    const QString shortcuts = directory.filePath("RuntimeControlTests.shortcuts.ini");
    const QString polling = directory.filePath("RuntimeControlTests.polling.ini");
    if (QFile::exists(shortcuts) || QFile::exists(polling))
    {
        std::printf("Test settings already exist in the fixed output directory; refusing to overwrite.\n");
        return 2;
    }
    check(directory.exists(), "fixed test output directory");
    shortcutTests(shortcuts);
    taskTests(polling);
    rescueLaunchFeedbackTests();
    check(QFile::remove(shortcuts), "remove owned shortcut test settings");
    check(QFile::remove(polling), "remove owned polling test settings");
    std::printf("RUNTIME_CONTROL_TESTS=%s checks=%d failures=%d\n", failures ? "FAIL" : "PASS", checks, failures);
    return failures ? 1 : 0;
}
