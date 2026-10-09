// 真实生产任务核心与两个显示端的离屏回归；所有请求都是合成数据。
#include "../Ksword5.1/Ksword5.1/Framework.h"
#include "../Ksword5.1/Ksword5.1/Framework/TaskSnapshotFeed.h"
#include "../Ksword5.1/Ksword5.1/Framework/ProgressDockWidget.h"
#include "../Ksword5.1/Ksword5.1/Framework/NotificationCardManager.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QEvent>
#include <QLabel>
#include <QMessageBox>
#include <QPointer>
#include <QProgressBar>
#include <QScrollBar>
#include <QScrollArea>
#include <QTest>
#include <QTimer>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <thread>

namespace
{
    unsigned checks = 0; // 断言计数，只在夹具 UI 主线程递增。

    // require：失败立即给出用例原因和非零退出，不把崩溃/超时当作成功。
    void require(const bool condition, const char* message)
    {
        ++checks;
        if (!condition)
        {
            std::cerr << "TASK_FAIL [" << checks << "]: " << message << '\n';
            std::exit(1);
        }
    }

    // taskAt：复制指定任务；调用方的快照仍是不可变历史，不借内部容器指针。
    kProgressTask taskAt(const kProgress& manager, const int pid)
    {
        for (const kProgressTask& task : manager.SnapshotWithRevision()->tasks)
        {
            if (task.pid == pid)
            {
                return task;
            }
        }
        require(false, "expected task is present in the production snapshot");
        return {};
    }

    // publish：执行实际单例 feed 并排空 Qt 事件；不会调用任何真实枚举业务。
    void publish()
    {
        ks::ui::TaskSnapshotFeed::instance().refreshNow();
        QApplication::processEvents();
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    }

    // findCard：通过生产身份属性找到卡片，避免依赖标题翻译或表格行号。
    QWidget* findCard(QWidget* const root, const int pid)
    {
        for (QWidget* widget : root->findChildren<QWidget*>(QStringLiteral("task_card")))
        {
            if (widget->property("task_pid").toInt() == pid)
            {
                return widget;
            }
        }
        return nullptr;
    }

    QWidget* findNotification(const int pid)
    {
        for (QWidget* widget : QApplication::topLevelWidgets())
        {
            if (widget->objectName() == QStringLiteral("task_notification") &&
                widget->property("task_pid").toInt() == pid && widget->isVisible())
            {
                return widget;
            }
        }
        return nullptr;
    }

    // stateAndLifetime：覆盖旧完成语义、明确终态、重复任务、owner 与历史上限。
    void stateAndLifetime()
    {
        kProgress manager;
        QObject owner;
        const int legacy = manager.add(&owner, "legacy task", "start");
        manager.set(legacy, "刷新失败", 0, 100.0f);
        require(taskAt(manager, legacy).state == kProgressState::LegacyCompleted,
            "legacy failure text at 100 percent never becomes structured success");
        require(taskAt(manager, legacy).hiddenInList, "legacy completion hides immediately");
        const auto oldSnapshot = manager.SnapshotWithRevision();
        manager.set(legacy, "late result", 0, 20.0f);
        require(manager.SnapshotWithRevision() == oldSnapshot, "late one-shot update cannot reopen its terminal");

        const int failed = manager.add(&owner, "explicit failure", "start");
        manager.set(failed, "partial", 0, 35.0f);
        require(manager.finish(failed, kProgressState::Failure, "failure evidence"), "explicit failure accepted");
        require(taskAt(manager, failed).state == kProgressState::Failure, "failure retains its exact enum");
        require(taskAt(manager, failed).progress == 0.35f, "failure does not fake one hundred percent progress");
        require(!taskAt(manager, failed).hiddenInList, "explicit outcome is briefly visible");
        require(!manager.finish(failed, kProgressState::Success, "late success"), "terminal result is claimed once");
        require(!manager.finish(99999, kProgressState::Failure, "unknown"), "unknown task cannot be finished");
        const int invalid = manager.add(&owner, "invalid finish", "start");
        require(!manager.finish(invalid, kProgressState::Running, "bad state"), "finish rejects nonterminal state");
        require(!manager.finish(invalid, kProgressState::LegacyCompleted, "bad state"), "legacy state is reserved for compatibility");

        // 同名可复用任务只占一个 owner 槽；显式轮次令牌隔离迟到结果。
        const int reusable = manager.addReusable(&owner, "reusable", "first");
        require(manager.addReusable(&owner, "reusable", "duplicate") == reusable, "owner and name deduplicate reusable slot");
        const std::uint64_t first = manager.beginCycle(reusable, "cycle one");
        manager.set(reusable, first, "partial one", 0, 30.0f);
        const std::uint64_t second = manager.beginCycle(reusable, "cycle two");
        require(second > first, "explicit restart returns a new generation token");
        const auto secondSnapshot = manager.SnapshotWithRevision();
        manager.set(reusable, first, "stale update", 0, 90.0f);
        require(!manager.finish(reusable, first, kProgressState::Failure, "stale failure"), "old generation finish rejected");
        manager.set(reusable, "unguarded old caller", 0, 50.0f);
        require(manager.SnapshotWithRevision() == secondSnapshot, "old and unguarded updates cannot mutate protected generation");
        require(manager.finish(reusable, second, kProgressState::Canceled, "canceled"), "same generation cancellation accepted");
        manager.set(reusable, second, "late running", 0, 10.0f);
        require(taskAt(manager, reusable).state == kProgressState::Canceled, "late token update cannot revive cancellation");
        manager.set(reusable, "unguarded revive", 0, 10.0f);
        require(taskAt(manager, reusable).state == kProgressState::Canceled, "unguarded update cannot revive explicit terminal");
        require(manager.beginCycle(legacy, "invalid restart") == 0, "one-shot tasks do not support cycle restart");

        // 旧周期接口维持兼容，但以 LegacyCompleted 标明没有结果证据。
        const int compatibility = manager.addReusable(&owner, "compatibility", "start");
        manager.set(compatibility, "old finish", 0, 1.0f);
        manager.set(compatibility, "next sample", 0, 20.0f);
        require(taskAt(manager, compatibility).state == kProgressState::Running, "legacy reusable cycle remains compatible");
        require(taskAt(manager, compatibility).generation == 2, "legacy reuse still records a separate generation");
        require(manager.SnapshotWithRevision() == manager.SnapshotWithRevision(), "same revision shares the exact snapshot object");
        require(oldSnapshot->tasks.size() == 1 && oldSnapshot->tasks.front().state == kProgressState::LegacyCompleted,
            "held snapshot is immutable after later updates");

        // 多次单次任务完成只保留 256 项；复用槽不因历史裁剪丢失调用方 PID。
        kProgress history;
        const int retained = history.addReusable(&owner, "retained", "start");
        history.set(retained, "done", 0, 100.0f);
        for (int index = 0; index < 330; ++index)
        {
            const int pid = history.add(&owner, "historical task", "start");
            require(history.finish(pid, kProgressState::Success, "done"), "each unique history task finishes");
        }
        const auto bounded = history.SnapshotWithRevision();
        require(bounded->tasks.size() == 257, "terminal one-shot history is bounded while reusable slot survives");
        require(taskAt(history, retained).retainedForReuse, "reusable handle survives history pruning");

        // 非全局管理器连接必须回到自身；manager 先销毁也不留下 owner 回调。
        kProgress owned;
        auto* transientOwner = new QObject();
        owned.add(transientOwner, "owned", "start");
        owned.addReusable(transientOwner, "owned reusable", "start");
        const auto held = owned.SnapshotWithRevision();
        delete transientOwner;
        require(owned.SnapshotWithRevision()->tasks.empty(), "owner destruction removes both task kinds from their manager");
        require(held->tasks.size() == 2, "owner destruction cannot mutate a reader's old snapshot");
        auto* survivingOwner = new QObject();
        {
            kProgress shortLived;
            shortLived.add(survivingOwner, "short lifetime", "start");
        }
        delete survivingOwner;
        require(true, "local manager destructor disconnects surviving owner");
    }

    // concurrentSnapshots：使用真实管理器的锁及共享快照，不运行 Qt 对象后台访问。
    void concurrentSnapshots()
    {
        kProgress manager;
        QObject uiOwner;
        int rejectedPid = -1;
        std::thread invalidOwnerWorker([&manager, &uiOwner, &rejectedPid]()
        {
            rejectedPid = manager.add(&uiOwner, "invalid owner thread", "start");
        });
        invalidOwnerWorker.join();
        require(rejectedPid == 0 && manager.SnapshotWithRevision()->tasks.empty(),
            "worker cannot register a task by borrowing a UI-owned QObject");
        std::vector<int> pids;
        for (int index = 0; index < 6; ++index)
        {
            pids.push_back(manager.add("concurrent", "start"));
        }
        const auto initial = manager.SnapshotWithRevision();
        std::atomic<int> completed{ 0 }; // 后台完成计数，不借任何 QWidget。
        std::vector<std::thread> workers;
        for (const int pid : pids)
        {
            workers.emplace_back([&manager, &completed, pid]()
            {
                for (int step = 0; step < 150; ++step)
                {
                    manager.set(pid, std::to_string(step), step, static_cast<float>(step % 90) / 100.0f);
                }
                manager.finish(pid, kProgressState::Success, "finished");
                ++completed;
            });
        }
        std::size_t revision = 0; // 每个共享快照自身携带一致的修订号。
        for (int readIndex = 0; readIndex < 128; ++readIndex)
        {
            const auto snapshot = manager.SnapshotWithRevision();
            require(snapshot->revision >= revision, "shared snapshot revisions never move backwards under concurrent writes");
            revision = snapshot->revision;
            for (const kProgressTask& task : snapshot->tasks)
            {
                require(task.progress >= 0 && task.progress <= 1, "all concurrently copied progress is normalized");
            }
            std::this_thread::yield();
        }
        for (std::thread& worker : workers)
        {
            worker.join();
        }
        require(completed.load() == 6, "all worker completions are observed before lifetime teardown");
        require(initial->tasks.front().progress == 0, "initial shared snapshot stays immutable under writer concurrency");
        for (const int pid : pids)
        {
            require(taskAt(manager, pid).state == kProgressState::Success, "all concurrent tasks retain explicit successful outcome");
        }
    }

    // waitingTransitions：真实 QMessageBox 仅自动拒绝，不操纵真实进程或系统状态。
    void waitingTransitions(QObject* const owner)
    {
        const int pid = kPro.addReusable(owner, "waiting test", "start");
        QTimer::singleShot(0, qApp, [pid]()
        {
            require(taskAt(kPro, pid).state == kProgressState::Waiting, "legacy UI exposes structured waiting state");
            kPro.set(pid, "background progress while waiting", 0, 0.25f);
            require(taskAt(kPro, pid).state == kProgressState::Waiting,
                "background intermediate progress cannot end the active choice wait");
            for (QWidget* widget : QApplication::topLevelWidgets())
            {
                if (auto* box = qobject_cast<QMessageBox*>(widget))
                {
                    box->reject();
                }
            }
        });
        require(kPro.UI(pid, "fixture prompt", std::vector<std::string>{ "fixture choice" }) == 0,
            "synthetic choice is canceled without external action");
        require(taskAt(kPro, pid).state == kProgressState::Running, "same generation resumes progress after choice dismissal");

        // 嵌套 Qt 循环里重启新轮次，旧对话框的收尾不能改写新轮状态。
        std::uint64_t newGeneration = 0;
        QTimer::singleShot(0, qApp, [&newGeneration, pid]()
        {
            newGeneration = kPro.beginCycle(pid, "restarted during choice");
            for (QWidget* widget : QApplication::topLevelWidgets())
            {
                if (auto* box = qobject_cast<QMessageBox*>(widget))
                {
                    box->reject();
                }
            }
        });
        kPro.UI(pid, "fixture prompt", std::vector<std::string>{ "fixture choice" });
        require(taskAt(kPro, pid).generation == newGeneration, "old choice restoration cannot overwrite the restarted generation");
        require(taskAt(kPro, pid).state == kProgressState::Running, "new generation stays running after old dialog closes");
        QTimer::singleShot(0, qApp, [pid, newGeneration]()
        {
            require(kPro.finish(pid, newGeneration, kProgressState::Canceled, "finished while waiting"),
                "terminal completion during choice wait is accepted exactly once");
            for (QWidget* widget : QApplication::topLevelWidgets())
            {
                if (auto* box = qobject_cast<QMessageBox*>(widget))
                {
                    box->reject();
                }
            }
        });
        kPro.UI(pid, "fixture prompt", std::vector<std::string>{ "fixture choice" });
        require(taskAt(kPro, pid).state == kProgressState::Canceled,
            "choice restoration cannot revive a task finished while waiting");
    }

    // reentrantFeed：首个消费者发布新数据时，后续消费者不能先收到新修订再收到旧修订。
    void reentrantFeed()
    {
        QObject owner;
        QObject first;
        QObject second;
        auto& feed = ks::ui::TaskSnapshotFeed::instance();
        bool armed = false; // 首发订阅不触发重入，只在指定任务更新时触发一次。
        int pid = 0;
        std::vector<std::size_t> revisions;
        feed.subscribe(&first, [&armed, &feed, &pid](const ks::ui::TaskSnapshotFeed::Snapshot&)
        {
            if (armed)
            {
                armed = false;
                kPro.set(pid, "reentrant newer data", 0, 0.5f);
                feed.refreshNow();
            }
        });
        feed.subscribe(&second, [&revisions](const ks::ui::TaskSnapshotFeed::Snapshot& snapshot)
        {
            revisions.push_back(snapshot->revision);
        });
        pid = kPro.add(&owner, "reentrant feed fixture", "old data");
        armed = true;
        feed.refreshNow();
        publish();
        require(revisions.size() >= 3, "reentrant feed publishes both initial and subsequent versions");
        for (std::size_t index = 1; index < revisions.size(); ++index)
        {
            require(revisions[index] >= revisions[index - 1], "all consumers see monotonically ordered feed revisions under reentry");
        }
        require(feed.current() == kPro.SnapshotWithRevision(), "queued reentrant refresh converges to current shared snapshot");
    }

    // 首发回调也可能重入刷新；const 引用必须指向本轮的局部快照而非可变成员。
    void initialSubscriptionSnapshot()
    {
        QObject owner;
        QObject receiver;
        auto& feed = ks::ui::TaskSnapshotFeed::instance();
        const int pid = kPro.add(&owner, "initial subscription fixture", "first");
        bool firstCall = true;
        feed.subscribe(&receiver, [&feed, &firstCall, pid](const ks::ui::TaskSnapshotFeed::Snapshot& snapshot)
        {
            if (!firstCall)
            {
                return;
            }
            firstCall = false;
            const auto firstSnapshot = snapshot;
            kPro.set(pid, "new data during initial callback", 0, 0.4f);
            feed.refreshNow();
            require(snapshot == firstSnapshot && snapshot->revision == firstSnapshot->revision,
                "initial consumer holds its original snapshot identity across reentrant refresh");
        });
    }

    // 注册前刷新可能触发已有消费者关闭新窗口或发布器；只能借 QPointer 探活。
    void subscriptionLifetime()
    {
        QObject owner;
        QObject destroyer;
        auto& feed = ks::ui::TaskSnapshotFeed::instance();
        auto* incoming = new QObject();
        const QPointer<QObject> incomingGuard(incoming);
        bool armed = false;
        unsigned deliveries = 0;
        feed.subscribe(&destroyer, [&armed, incoming](const ks::ui::TaskSnapshotFeed::Snapshot&)
        {
            if (armed)
            {
                armed = false;
                delete incoming;
            }
        });
        kPro.add(&owner, "receiver deletion fixture", "start");
        armed = true;
        feed.subscribe(incoming, [&deliveries](const ks::ui::TaskSnapshotFeed::Snapshot&) { ++deliveries; });
        require(incomingGuard.isNull() && deliveries == 0,
            "existing consumer can destroy incoming receiver before registration without callback or UAF");

        // feed 自身销毁同样令 subscribe 停止，不借用释放后的订阅表成员。
        QObject secondDestroyer;
        QObject secondIncoming;
        const QPointer<ks::ui::TaskSnapshotFeed> feedGuard(&feed);
        bool destroyFeed = false;
        feed.subscribe(&secondDestroyer, [&destroyFeed, &feed](const ks::ui::TaskSnapshotFeed::Snapshot&)
        {
            if (destroyFeed)
            {
                destroyFeed = false;
                delete &feed;
            }
        });
        kPro.add(&owner, "feed deletion fixture", "start");
        destroyFeed = true;
        feed.subscribe(&secondIncoming, [&deliveries](const ks::ui::TaskSnapshotFeed::Snapshot&) { ++deliveries; });
        require(feedGuard.isNull() && deliveries == 0,
            "existing consumer can destroy feed during subscribe refresh without UAF");
        require(ks::ui::TaskSnapshotFeed::instance().parent() == qApp,
            "application recreates and owns its feed after explicit teardown");
    }

    // realViews：生产 QWidget/通知类使用同一 snapshot，验证真实卡片身份和用户可见状态。
    void realViews()
    {
        QWidget host;
        host.resize(680, 520);
        host.show();
        ProgressDockWidget dock(&host);
        dock.resize(360, 400);
        dock.show();
        ks::ui::NotificationCardManager notifications(&host, &host);
        ks::settings::AppearanceSettings settings;
        settings.notificationCardsEnabled = true;
        settings.notificationDisplayPlacement = ks::settings::NotificationDisplayPlacement::MainWindow;
        notifications.applySettings(settings);
        QObject owner;
        const int pid = kPro.add(&owner, "task view fixture", "phase one");
        publish();
        QPointer<QWidget> card = findCard(&dock, pid);
        QPointer<QWidget> toast = findNotification(pid);
        require(card != nullptr && toast != nullptr, "both production views display the same task");
        require(toast->windowFlags().testFlag(Qt::WindowTransparentForInput), "notification card keeps native input transparency");
        require(dock.property("task_snapshot_revision") == notifications.property("task_snapshot_revision"),
            "both views render the same atomically captured revision");

        // 修改进度、创建其它任务、强制主题、改设置都不更换此 PID 的控件。
        kPro.set(pid, "phase two", 0, 44.0f);
        publish();
        require(findCard(&dock, pid) == card && findNotification(pid) == toast, "progress update reuses both card identities");
        const int other = kPro.add(&owner, "other task", "start");
        publish();
        require(findCard(&dock, pid) == card && findNotification(pid) == toast, "unrelated task insertion preserves card identities");

        // 超出工作区的任务继续由原有溢出判定负责；增量更新保留用户滚动位置。
        bool overflowed = false;
        for (int index = 0; index < 12; ++index)
        {
            const int overflowPid = kPro.add(&owner, "overflow fixture", "start");
            publish();
            overflowed = overflowed || notifications.isProgressTaskOverflowed(overflowPid)
                || notifications.isProgressTaskOverflowed(pid);
        }
        require(overflowed, "existing notification overflow routing remains active");
        auto* scroll = dock.findChild<QScrollArea*>();
        QApplication::processEvents();
        scroll->verticalScrollBar()->setValue(40);
        const int scrollValue = scroll->verticalScrollBar()->value();
        kPro.set(pid, "phase two", 0, 45.0f);
        publish();
        require(scroll->verticalScrollBar()->value() == scrollValue, "progress-only update preserves dock scroll position");
        notifications.applySettings(settings);
        require(findNotification(pid) == toast, "settings force refresh reuses the notification widget");
        auto* title = card->findChild<QLabel*>(QStringLiteral("task_title"));
        const QString oldStyle = title->styleSheet();
        KswordTheme::SetPrimaryAccentColor(QStringLiteral("#bc378f"));
        KswordTheme::SetDarkModeEnabled(true);
        dock.refreshThemeVisuals();
        notifications.refreshVisuals();
        require(findCard(&dock, pid) == card && findNotification(pid) == toast, "theme refresh does not delete task widgets");
        require(title->styleSheet() != oldStyle, "existing task title recomputes actual theme color");

        // 切换真实语言包后两个现存标题都重新翻译；缺少语言条目会令夹具失败。
        QString languageError;
        require(ks::i18n::LanguageManager::instance().setLanguage(QStringLiteral("en-US"), &languageError),
            "production language manager loads English pack");
        publish();
        require(ks::ui::TaskStateText(kProgressState::Running) == QStringLiteral("Running"), "task running state is translated by the real English pack");
        require(title->text().contains(QStringLiteral("Running")), "dock retranslated its existing running title");
        auto* toastTitle = toast->findChild<QLabel*>(QStringLiteral("ksNotificationCardTitle"));
        require(toastTitle->text().contains(QStringLiteral("Running")), "notification retranslated its existing running title");
        require(findCard(&dock, pid) == card && findNotification(pid) == toast, "language change preserves both widget identities");

        // 明确失败显示状态并保留执行比例；到期后两视图一起移除，历史仍可查询。
        require(kPro.finish(pid, kProgressState::Failure, "fixture error"), "visible task accepts explicit failure");
        publish();
        require(findCard(&dock, pid) == card && findNotification(pid) == toast, "terminal display updates same task card");
        require(title->text().contains(QStringLiteral("Failed")), "explicit failure is visibly distinct from success");
        require(!card->findChild<QProgressBar*>(QStringLiteral("task_progress"))->isVisible(), "terminal card does not show misleading completion percentage");
        const auto terminalSnapshot = kPro.SnapshotWithRevision();
        QTest::qWait(4150);
        publish();
        require(findCard(&dock, pid) == nullptr && findNotification(pid) == nullptr, "both views expire the same explicit terminal presentation");
        require(taskAt(kPro, pid).state == kProgressState::Failure && taskAt(kPro, pid).hiddenInList,
            "expired task retains failure outcome in bounded history");
        require(!terminalSnapshot->tasks.empty(), "held terminal snapshot survives later display expiration");
        require(kPro.finish(other, kProgressState::Success, "done"), "second visible task can complete explicitly");
        publish();
        require(findCard(&dock, other) != nullptr, "other completed card is briefly visible with its own identity");
        waitingTransitions(&owner);
    }
}

int main(int argc, char** argv)
{
    // 仅 QApplication/offscreen 实际控件，禁止调用生产 main、服务枚举或系统剪贴板。
    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    QString languageError;
    require(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"), &languageError),
        "production language manager initializes fixture packs");
    stateAndLifetime();
    concurrentSnapshots();
    initialSubscriptionSnapshot();
    subscriptionLifetime();
    reentrantFeed();
    realViews();
    publish();
    std::cout << "TASK_CENTER_RESULT=SUCCESS\nTASK_CENTER_CHECKS=" << checks << '\n';
    return 0;
}
