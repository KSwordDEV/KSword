// 使用真实 Qt dispatcher/QPointer，注入生产 Search 线程体、stop 和析构；后端只有阻塞内存门。
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QPointer>
#include <QStringList>
#include <QThread>
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <mutex>
#include <thread>
#include "UI/AsyncUiDispatcher.h"

namespace fixture
{
std::atomic_uint checks{0}; // 实际执行断言数，后台门与主线程共用安全计数。
void require(const bool ok, const char* message)
{
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", message); std::abort(); }
}
struct Button { bool enabled = true; void setEnabled(bool value) { enabled = value; } };
struct Timer { void stop() {} };
struct Gate
{
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool released = false;
    void block()
    {
        std::unique_lock<std::mutex> lock(mutex);
        entered = true;
        condition.notify_all();
        require(condition.wait_for(lock, std::chrono::seconds(5), [this] { return released; }), "gate release timeout");
    }
    void awaitEntered()
    {
        std::unique_lock<std::mutex> lock(mutex);
        require(condition.wait_for(lock, std::chrono::seconds(5), [this] { return entered; }), "worker enter timeout");
    }
    void release()
    {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
        condition.notify_all();
    }
};
}
struct kLogEvent {};
struct Log { template<class T> Log& operator<<(const T&) { return *this; } } info;
constexpr int eol = 0;
struct Progress { unsigned completions = 0; void set(int, const char*, int, float value) { if (value >= 100) ++completions; } } kPro;

class RegistryDock final : public QObject
{
public:
    struct SearchOptions { int viewBits = 0; quint64 generation = 0; };
    std::atomic_bool m_searchRunning{false};
    std::atomic_bool m_searchStopFlag{false};
    std::unique_ptr<std::thread> m_searchThread;
    std::shared_ptr<ks::ui::AsyncUiDispatcher> m_uiDispatcher = std::make_shared<ks::ui::AsyncUiDispatcher>(this);
    std::shared_ptr<std::atomic_bool> m_operationsClosed = std::make_shared<std::atomic_bool>(false);
    std::shared_ptr<std::atomic_bool> m_documentCancel;
    fixture::Button searchButton, stopButton;
    fixture::Timer timer;
    fixture::Button* m_searchButton = &searchButton;
    fixture::Button* m_stopSearchButton = &stopButton;
    fixture::Timer* m_searchFlushTimer = &timer;
    fixture::Gate* gate = nullptr;
    quint64 m_searchGeneration = 0;
    bool m_lastSearchStopped = false;
    std::size_t m_searchScannedKeys = 0, m_searchHitCount = 0;
    int m_progressPid = 17;
    unsigned commits = 0;
    QString status; // 正式 stop 路径展示的当前状态。
    std::atomic_bool backendFinished{false};
    ~RegistryDock() override;
    void startSearchAsync();
    void stopSearch(bool waitForThread);
    void flushPendingSearchRows() { ++commits; }
    void updateStatusBar(const QString& value) { status = value; }
    void searchRegistryPath(const QString&, bool, const QString&, const SearchOptions&,
        std::size_t* scanned, std::size_t* hits)
    {
        if (gate) gate->block();
        *scanned += 64;
        *hits += 2;
        backendFinished.store(true);
    }
};

void RegistryDock::startSearchAsync()
{
//@@PREFIX@@
    const QString keyword = QStringLiteral("fixture");
    const QStringList roots{QStringLiteral("HKEY_CURRENT_USER")};
    SearchOptions options;
    options.generation = ++m_searchGeneration;
    const bool r0 = false;
    m_searchRunning.store(true);
    m_searchStopFlag.store(false);
    backendFinished.store(false);
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
//@@WORKER@@
}
//@@STOP@@
//@@DESTRUCTOR@@

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    using fixture::require;
    const auto finish = [](RegistryDock& dock) {
        QElapsedTimer deadline;
        deadline.start();
        while (dock.m_searchRunning.load() && deadline.elapsed() < 5000)
        { QCoreApplication::processEvents(); QThread::msleep(1); }
        require(!dock.m_searchRunning.load(), "search completion timeout");
    };
    {
        RegistryDock dock;
        dock.startSearchAsync(); finish(dock);
        require(!dock.m_searchThread, "completion joins and releases its exact worker");
        dock.startSearchAsync(); finish(dock);
        require(dock.commits == 2 && kPro.completions == 2, "repeat search returns two real completions");
    }
    {
        fixture::Gate gate;
        RegistryDock dock;
        dock.gate = &gate;
        dock.startSearchAsync(); gate.awaitEntered();
        dock.stopSearch(false);
        require(dock.m_searchThread && dock.m_searchThread->joinable(), "interactive stop retains unique join ownership");
        gate.release(); finish(dock);
        require(dock.m_lastSearchStopped && dock.commits == 1, "canceled worker reports stopped actual result");
    }
    {
        RegistryDock dock;
        dock.startSearchAsync();
        while (!dock.backendFinished.load()) QThread::msleep(1);
        dock.stopSearch(true); // 销毁/换视图增代次，已排队旧完成不能重新提交。
        QCoreApplication::processEvents();
        require(dock.commits == 0 && !dock.m_searchThread, "old generation completion discarded");
    }
    {
        fixture::Gate gate;
        auto dock = std::make_unique<RegistryDock>();
        dock->gate = &gate;
        dock->startSearchAsync(); gate.awaitEntered();
        std::atomic_bool returned{false};
        std::thread releaser([&] {
            QThread::msleep(30);
            require(!returned.load(), "destructor waits while backend still borrows page members");
            gate.release();
        });
        dock.reset(); returned.store(true);
        releaser.join();
        QCoreApplication::processEvents();
        require(returned.load(), "destructor joins backend and closes queued dispatcher");
    }
    std::printf("REGISTRY_SEARCH_LIFETIME checks=%u failures=0 real_registry_calls=0\n", fixture::checks.load());
}
