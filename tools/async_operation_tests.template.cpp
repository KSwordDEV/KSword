// 真实 Qt 事件循环、线程池与生产完整异步方法夹具；后端只处理值身份，不碰目标进程。
#include "../Ksword5.1/Ksword5.1/UI/AsyncOperation.h"

#include <QApplication>
#include <QCheckBox>
#include <QElapsedTimer>
#include <QEvent>
#include <QLabel>
#include <QMenu>
#include <QPointer>
#include <QTreeWidget>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using ks::ui::AsyncOperation;
using ks::ui::AsyncOperationOutcome;
using ks::ui::AsyncOperationToken;
static int checks = 0; // 主线程断言总数。
static void check(bool condition, const char* reason)
{
    if (!condition) throw std::runtime_error(reason);
    ++checks;
}

// 所有等待都有五秒上限，worker 不依赖定时猜测，测试主动释放每个 gate。
struct Gate
{
    std::mutex mutex; // 进入/放行共用同步锁。
    std::condition_variable condition; // worker 与主线程同步点。
    bool entered = false; // 查询已经开始。
    bool released = false; // 主线程已经允许返回。
    void block()
    {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        condition.notify_all();
        if (!condition.wait_for(lock, std::chrono::seconds(5), [this] { return released; }))
            throw std::runtime_error("gate timeout");
    }
    void await()
    {
        std::unique_lock<std::mutex> lock(mutex);
        if (!condition.wait_for(lock, std::chrono::seconds(5), [this] { return entered; }))
            throw std::runtime_error("worker did not enter");
    }
    void release()
    {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
        condition.notify_all();
    }
};

template<class Predicate>
static void pumpUntil(Predicate predicate)
{
    QElapsedTimer timer; // 防事件循环失败无限等待。
    timer.start();
    while (!predicate() && timer.elapsed() < 5000)
    {
        QCoreApplication::processEvents(QEventLoop::AllEvents, 5);
        std::this_thread::yield();
    }
    check(predicate(), "UI completion timed out");
}

// 菜单屏障使用真实 QMenu 显隐；保留旧延期回调，主动验证最坏的旧回放情况。
namespace ks::ui
{
    static QPointer<QMenu> barrierMenu; // 仅属于测试 UI 线程的当前菜单。
    static std::vector<std::function<void()>> deferredCommits; // 暂存生产调用的延期动作。
    bool IsItemViewUiCommitBlockedByContextMenu(const QList<QAbstractItemView*>&)
    {
        return !barrierMenu.isNull() && barrierMenu->isVisible();
    }
    bool DeferItemViewUiCommitIfContextMenuOpen(QObject*, const QString&,
        const QList<QAbstractItemView*>& views, std::function<void()> callback)
    {
        if (!IsItemViewUiCommitBlockedByContextMenu(views)) return false;
        deferredCommits.push_back(std::move(callback));
        return true;
    }
    static void replayDeferred()
    {
        auto callbacks = std::move(deferredCommits); // 回放期间允许再次延期。
        deferredCommits.clear();
        for (auto& callback : callbacks) callback();
    }
}

// 生产日志和全局进度仅作为线程安全观测端点；不替换生产请求/控制器逻辑。
struct kLogEvent {};
struct LogStream
{
    template<class Value> LogStream& operator<<(const Value&) { return *this; }
};
static LogStream info, dbg, warn;
static int eol = 0;
struct ProgressProbe
{
    std::mutex mutex; // 后台拒绝投递也可收尾。
    int ended = 0; // 收到有限进度100%的次数。
    int addReusable(QObject*, const char*, const char*) { return 1; }
    void set(int, const char*, int, float value)
    {
        if (value >= 1.0f && (value == 1.0f || value == 100.0f))
        {
            std::lock_guard<std::mutex> lock(mutex);
            ++ended;
        }
    }
    int count()
    {
        std::lock_guard<std::mutex> lock(mutex);
        return ended;
    }
} kPro;

namespace KswordTheme { static QColor PrimaryBlueColor = Qt::blue; }
static QColor statusErrorColor() { return Qt::red; }
static QColor statusIdleColor() { return Qt::gray; }
static QString buildStateLabelStyle(const QColor& color, int)
{
    return QStringLiteral("color:%1;").arg(color.name());
}

// 固定后端只记录完整值身份；控制器线程池和生产方法均保持真实实现。
static std::shared_ptr<Gate> queryGate; // 下一次后端查询的可控同步门。
static std::atomic_int queryCount{0}; // 实际执行查询的数量。
namespace ks::process
{
    struct ProcessRecord { std::uint32_t pid = 1; std::uint64_t creationTime100ns = 10; };
    struct ModuleSnapshot
    {
        std::vector<int> modules; // 用 PID 标识可断言的结果。
        std::vector<int> threads; // 与正式结果同形的线程列表。
        std::string diagnosticText; // 后台诊断文本。
    };
    static ModuleSnapshot EnumerateProcessModulesAndThreadsIfIdentityMatches(
        std::uint32_t pid, std::uint64_t creationTime, bool)
    {
        ++queryCount;
        if (queryGate) queryGate->block();
        if (pid == 99) throw std::runtime_error("backend failure");
        if (!creationTime) return {};
        return {{static_cast<int>(pid)}, {}, {}};
    }
}

// 最小页面只替换构造与后端依赖；下方函数由脚本从当前生产文件完整抽取。
struct DestructionAudit
{
    std::function<void()> inspect; // 在派生成员销毁阶段检查门禁已由析构体关闭。
    ~DestructionAudit() { if (inspect) inspect(); }
};

class ProcessDetailWindow : public QWidget
{
public:
    struct ModuleRefreshResult
    {
        ks::process::ModuleSnapshot moduleSnapshot; // 按值查询结果。
        std::uint64_t elapsedMs = 0; // 查询耗时。
        bool includeSignatureCheck = false; // 签名选项。
    };
    ~ProcessDetailWindow() override;
    ks::process::ProcessRecord m_baseRecord; // 生产身份字段。
    QCheckBox* m_signatureCheckBox = new QCheckBox(this);
    QLabel* m_moduleStatusLabel = new QLabel(this);
    QTreeWidget* m_moduleTable = new QTreeWidget(this);
    std::vector<int> m_moduleRecords;
    bool m_moduleRefreshing = false;
    std::unique_ptr<AsyncOperation> m_moduleOperation;
    bool m_moduleInitialRefreshStarted = false;
    bool m_firstModuleRefreshDone = false;
    std::uint64_t m_moduleRefreshTicket = 0;
    int m_moduleRefreshProgressPid = 0;
    int applied = 0; // 只在正式 apply 调用 rebuild 时递增。
    DestructionAudit destructionAudit; // 先于控制器成员销毁，验证析构体关闭顺序。
    void requestAsyncModuleRefresh(bool forceRefresh);
    bool tryApplyModuleRefreshResult(std::uint64_t, std::uint32_t, std::uint64_t,
        const ModuleRefreshResult&);
    void applyModuleRefreshResult(const ModuleRefreshResult&);
    void updateModuleStatusLabel(const QString&, bool);
    void rebuildModuleTable() { ++applied; }
};

class HandleDock : public QWidget
{
public:
    struct HandleRow
    {
        std::uint32_t processId = 1;
        std::uint64_t processCreationTime = 10;
        std::uint64_t handleValue = 20;
        std::uint64_t objectAddress = 30;
        std::uint16_t typeIndex = 1;
    };
    struct HandleDetailField { QString keyText; QString valueText; };
    struct HandleDetailRefreshResult
    {
        std::vector<HandleDetailField> fields;
        std::uint64_t elapsedMs = 0;
        QString diagnosticText;
    };
    ~HandleDock() override;
    bool hasSelection = true;
    HandleRow currentRow;
    QLabel* m_handleDetailStatusLabel = new QLabel(this);
    QTreeWidget* m_handleDetailTable = new QTreeWidget(this);
    bool m_handleDetailRefreshInProgress = false;
    std::unique_ptr<AsyncOperation> m_handleDetailOperation;
    std::uint64_t m_handleDetailRefreshTicket = 0;
    int m_handleDetailRefreshProgressPid = 0;
    HandleDock() { m_handleDetailTable->setColumnCount(2); }
    HandleRow* selectedHandleRow() { return hasSelection ? &currentRow : nullptr; }
    void requestHandleDetailRefresh(bool);
    bool tryApplyHandleDetailRefreshResult(std::uint64_t, const HandleRow&, const HandleDetailRefreshResult&);
    void applyHandleDetailRefreshResult(std::uint64_t, const HandleDetailRefreshResult&);
    void showHandleDetailPlaceholder(const QString&);
    static HandleDetailRefreshResult buildHandleDetailRefreshResult(const HandleRow& row)
    {
        ++queryCount;
        if (queryGate) queryGate->block();
        if (row.processId == 99) throw std::runtime_error("handle failure");
        return {{{QStringLiteral("handle"), QString::number(row.handleValue)}}, 1, {}};
    }
};

__PRODUCTION_MODULE__
__PRODUCTION_HANDLE__

static void testControllerLifecycle()
{
    QObject owner; // 控制器的真实 Qt 接收器所有者。
    AsyncOperation operation(&owner);
    std::atomic_int finished{0}; // CAS 一次收尾计数。
    std::atomic_int executed{0}; // 实际 worker 执行次数。
    int applied = 0; // 最后应用的值。
    auto gate = std::make_shared<Gate>();
    auto worker = [gate, &executed](const int& value, const AsyncOperationToken&)
    {
        ++executed;
        if (value == 1) gate->block();
        return value;
    };
    auto apply = [&applied](int value, std::uint64_t) { applied = value; return true; };
    auto failure = [](std::exception_ptr) { throw std::runtime_error("unexpected failure"); };
    auto cleanup = [&finished](AsyncOperationOutcome) { ++finished; };
    operation.submit<int, int>(1, worker, apply, failure, cleanup);
    gate->await();
    operation.submit<int, int>(2, worker, apply, failure, cleanup);
    const auto latest = operation.submit<int, int>(3, worker, apply, failure, cleanup);
    check(operation.hasPending() && operation.isBusy(), "latest request not coalesced");
    check(finished == 1 && executed == 1, "superseded pending was executed or not settled");
    gate->release();
    pumpUntil([&] { return !operation.isInFlight(); });
    check(applied == 3 && executed == 2 && finished == 3, "latest generation did not win");
    check(operation.generation() == latest && !operation.hasPending(), "pending remained after finish");

    // worker 异常与 apply 异常都只收尾一次并释放 busy。
    int failures = 0;
    operation.submit<int, int>(1, [](const int&, const AsyncOperationToken&) -> int
    { throw std::runtime_error("worker failure"); }, apply,
        [&failures](std::exception_ptr) { ++failures; }, cleanup);
    pumpUntil([&] { return !operation.isInFlight(); });
    operation.submit<int, int>(1, [](const int& value, const AsyncOperationToken&) { return value; },
        [](int, std::uint64_t) -> bool { throw std::runtime_error("apply failure"); },
        [&failures](std::exception_ptr) { ++failures; }, cleanup);
    pumpUntil([&] { return !operation.isInFlight(); });
    check(failures == 2 && finished == 5, "exception cleanup duplicated or missing");

    // 真实 Qt 丢弃已排队完成 functor，active/pending 必须都结束。
    gate = std::make_shared<Gate>();
    operation.submit<int, int>(1, [gate](const int& value, const AsyncOperationToken&)
    { gate->block(); return value; }, apply, failure, cleanup);
    gate->await();
    operation.submit<int, int>(2, worker, apply, failure, cleanup);
    gate->release();
    check(QThreadPool::globalInstance()->waitForDone(5000), "worker remained blocked");
    QCoreApplication::removePostedEvents(&operation, QEvent::MetaCall);
    check(!operation.isBusy() && !operation.hasPending() && !operation.isInFlight(), "dropped queue leaked lane");
    check(finished == 7, "dropped queue lost cleanup");
    operation.submit<int, int>(4, worker, apply, failure, cleanup);
    pumpUntil([&] { return !operation.isInFlight(); });
    check(applied == 4 && finished == 8, "lane could not recover after Qt dropped queue");

    // 取消释放 busy/pending；已运行查询返回前不启动第二个实际 worker。
    gate = std::make_shared<Gate>();
    operation.submit<int, int>(1, [gate](const int& value, const AsyncOperationToken&)
    { gate->block(); return value; }, apply, failure, cleanup);
    gate->await();
    operation.submit<int, int>(2, worker, apply, failure, cleanup);
    operation.cancel();
    check(!operation.isBusy() && !operation.hasPending() && operation.isInFlight(), "cancel state incorrect");
    check(finished == 10, "cancel did not settle active and pending exactly once");
    gate->release();
    pumpUntil([&] { return !operation.isInFlight(); });
    check(finished == 10 && applied == 4, "canceled completion applied or double settled");
}

static void testProductionModule()
{
    queryGate = std::make_shared<Gate>();
    auto page = std::make_unique<ProcessDetailWindow>();
    page->requestAsyncModuleRefresh(true);
    queryGate->await();
    page->m_baseRecord.pid = 2;
    page->requestAsyncModuleRefresh(true);
    queryGate->release();
    pumpUntil([&] { return !page->m_moduleOperation->isInFlight(); });
    check(page->applied == 1 && page->m_moduleRecords.front() == 2, "production module old result applied");
    check(!page->m_moduleRefreshing && page->m_firstModuleRefreshDone, "production module busy leaked");
    queryGate.reset();

    // 真菜单延期后发新请求，旧回放不得覆写新 generation。
    QMenu menu;
    ks::ui::barrierMenu = &menu;
    menu.addAction(QStringLiteral("fixture"));
    menu.show();
    page->requestAsyncModuleRefresh(true);
    pumpUntil([] { return !ks::ui::deferredCommits.empty(); });
    const auto oldTicket = page->m_moduleRefreshTicket;
    page->m_baseRecord.pid = 3;
    page->requestAsyncModuleRefresh(true);
    check(page->m_moduleOperation->generation() != oldTicket, "module generation not invalidated during menu");
    menu.hide();
    ks::ui::replayDeferred();
    pumpUntil([&] { return !page->m_moduleOperation->isInFlight(); });
    check(page->m_moduleRecords.front() == 3 && page->applied == 2, "module stale menu replay committed");

    // 排队完成期间 PID 相同但创建时间改变，必须拒绝该旧进程实例。
    page->requestAsyncModuleRefresh(true);
    check(QThreadPool::globalInstance()->waitForDone(5000), "module worker did not finish");
    ++page->m_baseRecord.creationTime100ns;
    pumpUntil([&] { return !page->m_moduleOperation->isInFlight(); });
    check(page->applied == 2, "module creation identity not checked before apply");

    // 生产页析构先 close：先排队再销毁，以及销毁后才投递均只有一次收尾。
    auto queued = std::make_unique<ProcessDetailWindow>();
    queued->requestAsyncModuleRefresh(true);
    check(QThreadPool::globalInstance()->waitForDone(5000), "queued module unfinished");
    const int before = kPro.count();
    queued.reset();
    QCoreApplication::processEvents();
    check(kPro.count() == before + 1, "queued owner destruction did not settle once");
    queryGate = std::make_shared<Gate>();
    auto late = std::make_unique<ProcessDetailWindow>();
    late->requestAsyncModuleRefresh(true);
    queryGate->await();
    const int beforeLate = kPro.count();
    bool closedBeforeMembers = false;
    late->destructionAudit.inspect = [&closedBeforeMembers, lane = late->m_moduleOperation.get(), beforeLate]()
    {
        closedBeforeMembers = !lane->isBusy() && !lane->isInFlight() && kPro.count() == beforeLate + 1;
    };
    late.reset();
    check(closedBeforeMembers, "module lane closed only after derived member destruction");
    check(kPro.count() == beforeLate + 1, "destructor waited until derived members gone");
    queryGate->release();
    check(QThreadPool::globalInstance()->waitForDone(5000), "late module remained blocked");
    QCoreApplication::processEvents();
    check(kPro.count() == beforeLate + 1, "late delivery double settled");
    queryGate.reset();
}

static void testControllerFailureEdges()
{
    QObject owner;
    AsyncOperation operation(&owner);
    std::atomic_int finished{0}; // 重复完成/异常竞争时只允许一次收尾。
    int failures = 0;
    operation.submit<int, int>(1, [](const int&, const AsyncOperationToken& token)
    {
        token.deliver(std::string("wrong erased payload"));
        return 7;
    }, [](int, std::uint64_t) { return true; },
        [&failures](std::exception_ptr) { ++failures; },
        [&finished](AsyncOperationOutcome outcome)
        {
            if (outcome == AsyncOperationOutcome::Failed) ++finished;
        });
    check(QThreadPool::globalInstance()->waitForDone(5000), "duplicate delivery worker unfinished");
    pumpUntil([&] { return !operation.isInFlight(); });
    QCoreApplication::processEvents();
    check(failures == 1 && finished == 1, "bad any or duplicate delivery leaked/double settled");

    // 真实 UI apply 嵌套销毁所属 QObject，控制器不能继续访问自己或页面。
    auto nestedOwner = std::make_unique<QObject>();
    auto* nestedOperation = new AsyncOperation(nestedOwner.get());
    std::atomic_int nestedFinished{0};
    nestedOperation->submit<int, int>(1, [](const int& value, const AsyncOperationToken&) { return value; },
        [&nestedOwner](int, std::uint64_t) { nestedOwner.reset(); return true; },
        [](std::exception_ptr) {}, [&nestedFinished](AsyncOperationOutcome outcome)
        {
            if (outcome == AsyncOperationOutcome::OwnerClosed) ++nestedFinished;
        });
    pumpUntil([&] { return nestedOwner == nullptr; });
    check(nestedFinished == 1, "nested apply destruction did not settle safely");

    // apply 内部发新请求后抛错，旧错误回调不得覆盖最新请求的页面状态。
    int obsoleteFailures = 0;
    int newestValue = 0;
    std::atomic_int reentrantFinished{0};
    operation.submit<int, int>(1,
        [](const int& value, const AsyncOperationToken&) { return value; },
        [&operation, &newestValue, &reentrantFinished](int, std::uint64_t) -> bool
        {
            operation.submit<int, int>(2,
                [](const int& value, const AsyncOperationToken&) { return value; },
                [&newestValue](int value, std::uint64_t) { newestValue = value; return true; },
                [](std::exception_ptr) {},
                [&reentrantFinished](AsyncOperationOutcome) { ++reentrantFinished; });
            throw std::runtime_error("obsolete apply failure");
        }, [&obsoleteFailures](std::exception_ptr) { ++obsoleteFailures; },
        [&reentrantFinished](AsyncOperationOutcome) { ++reentrantFinished; });
    pumpUntil([&operation] { return !operation.isInFlight(); });
    check(newestValue == 2 && obsoleteFailures == 0 && reentrantFinished == 2,
        "obsolete error callback ran after newer generation accepted");

    // closed 控制器拒绝新请求且不触发保存的页面状态回调。
    int stateChanges = 0;
    int rejected = 0;
    operation.setStateChangedCallback([&stateChanges] { ++stateChanges; });
    operation.close();
    const auto ticket = operation.submit<int, int>(1,
        [](const int& value, const AsyncOperationToken&) { return value; },
        [](int, std::uint64_t) { return true; }, [](std::exception_ptr) {},
        [&rejected](AsyncOperationOutcome outcome)
        {
            if (outcome == AsyncOperationOutcome::OwnerClosed) ++rejected;
        });
    check(ticket == 0 && rejected == 1 && stateChanges == 0, "closed lane touched UI or accepted request");
}

// 独立重入探针先在修复前运行，可由 AddressSanitizer 检查同步销毁后的读取。
static bool callbackInProgress = false;
static bool callableDestroyedWhileRunning = false;
struct CallbackLifetime
{
    ~CallbackLifetime()
    {
        if (callbackInProgress) callableDestroyedWhileRunning = true;
    }
};

static void testCallbackReentry(const std::string& mode)
{
    auto owner = std::make_unique<QObject>();
    auto* operation = new AsyncOperation(owner.get());
    std::atomic_int ended{0}; // 控制器关闭仍应立即值化收尾。
    int started = 0; // 状态回调触发的次数。
    operation->setStateChangedCallback([&owner, operation, &started, mode,
        lifetime = std::make_shared<CallbackLifetime>()]()
    {
        callbackInProgress = true;
        ++started;
        if (mode == "--state-submit" || (mode == "--state-finish" && !operation->isBusy()))
            owner.reset();
        callbackInProgress = false;
    });
    operation->submit<int, int>(1,
        [](const int& value, const AsyncOperationToken&) { return value; },
        [operation, mode](int, std::uint64_t) -> bool
        {
            if (mode == "--close-throw")
            {
                operation->close();
                throw std::runtime_error("apply closed then threw");
            }
            return true;
        }, [](std::exception_ptr) {}, [&ended](AsyncOperationOutcome) { ++ended; });
    if (mode == "--state-submit")
    {
        check(owner == nullptr && ended == 1 && started == 1, "submit destruction outcome incorrect");
    }
    else if (mode == "--state-finish")
    {
        pumpUntil([&owner] { return owner == nullptr; });
        check(ended == 1 && started == 2, "finish destruction outcome incorrect");
    }
    else
    {
        pumpUntil([operation] { return !operation->isInFlight(); });
        check(ended == 1, "apply-close exception did not settle once");
    }
    check(!callableDestroyedWhileRunning, "stateChanged callable destroyed during its invocation");
}

static void testProductionHandle()
{
    auto page = std::make_unique<HandleDock>();
    queryGate = std::make_shared<Gate>();
    page->requestHandleDetailRefresh(false);
    queryGate->await();
    page->currentRow.handleValue = 77;
    page->requestHandleDetailRefresh(false);
    queryGate->release();
    pumpUntil([&] { return !page->m_handleDetailOperation->isInFlight(); });
    check(page->m_handleDetailTable->topLevelItem(0)->text(1) == QStringLiteral("77"), "handle latest selection lost");
    check(!page->m_handleDetailRefreshInProgress, "handle busy remained set");
    queryGate.reset();

    QMenu menu;
    ks::ui::barrierMenu = &menu;
    menu.addAction(QStringLiteral("fixture"));
    menu.show();
    page->requestHandleDetailRefresh(true);
    pumpUntil([] { return !ks::ui::deferredCommits.empty(); });
    ++page->currentRow.objectAddress;
    menu.hide();
    ks::ui::replayDeferred();
    check(!page->m_handleDetailOperation->isInFlight(), "handle identity rejection retained deferred slot");
    check(page->m_handleDetailTable->topLevelItem(0)->text(1) == QStringLiteral("77"), "reused handle committed");
    page->currentRow.processId = 99;
    page->requestHandleDetailRefresh(true);
    pumpUntil([&] { return !page->m_handleDetailOperation->isInFlight(); });
    check(page->m_handleDetailStatusLabel->text().contains(QStringLiteral("失败")), "production handle exception path absent");
    check(!page->m_handleDetailRefreshInProgress, "production handle error leaked busy");

    // 选中清除同时取消正在查询及最新 pending，placeholder 不能被旧结果覆盖。
    page->currentRow.processId = 1;
    queryGate = std::make_shared<Gate>();
    page->requestHandleDetailRefresh(true);
    queryGate->await();
    page->currentRow.handleValue = 88;
    page->requestHandleDetailRefresh(false);
    page->hasSelection = false;
    page->requestHandleDetailRefresh(false);
    check(!page->m_handleDetailOperation->isBusy() && !page->m_handleDetailOperation->hasPending(),
        "handle clear selection retained busy/pending");
    queryGate->release();
    pumpUntil([&] { return !page->m_handleDetailOperation->isInFlight(); });
    check(page->m_handleDetailTable->topLevelItemCount() == 0, "old handle completion replaced placeholder");
    queryGate.reset();
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    try
    {
        if (argc > 1)
        {
            testCallbackReentry(argv[1]);
            std::cout << "ASYNC_REENTRY_RESULT=PASS\n";
            return 0;
        }
        testControllerLifecycle();
        testControllerFailureEdges();
        testProductionModule();
        testProductionHandle();
        check(QThreadPool::globalInstance()->waitForDone(5000), "final thread pool not drained");
        std::cout << "ASYNC_OPERATION_CHECKS=" << checks << "\nASYNC_OPERATION_RESULT=PASS\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "ASYNC_OPERATION_RESULT=FAIL " << error.what() << '\n';
        return 1;
    }
}
