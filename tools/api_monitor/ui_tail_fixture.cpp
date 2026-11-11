#include <Windows.h>
#include <QApplication>
#include <QCheckBox>
#include <QElapsedTimer>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QPointer>
#include <QTimer>
#include <QThread>
#include <iostream>
#include "MonitorDock/WinAPIEventArchive.h"
#include "MonitorDock/WinAPIEventTableModel.h"
#include "UI/VisibleTableWidget.h"
#include "UI/TableInteractionSupport.h"

// Only translation and the menu-open state are inert. Archive, model, proxy,
// async workers, bounded filtering, row notifications and Qt layouts are real.
namespace ks::i18n {
QString SourceTextSnapshot::displayText(const QString& text) const { return text; }
struct LanguageManager::State {};
LanguageManager::LanguageManager() : m_state(std::make_unique<State>()) {}
LanguageManager::~LanguageManager() = default;
LanguageManager& LanguageManager::instance() { static LanguageManager manager; return manager; }
QString LanguageManager::sourceText(const QString& text) const { return text; }
bool LanguageManager::eventFilter(QObject*, QEvent*) { return false; }
}
namespace ks::ui {
bool menuOpen = false;
std::function<void()> afterMenu;
bool DeferTableUiCommitIfContextMenuOpen(QObject*, const QString&, const QList<QTableView*>&, std::function<void()> resume)
{
    if (!menuOpen) return false;
    afterMenu = std::move(resume); return true;
}
}
struct FakeTimeline { void appendRecord(const WinAPIEventRef&) {} };
class WinAPIDock : public QWidget
{
public:
    QTableView* m_eventTable = nullptr;
    QCheckBox* m_eventKeepBottomCheck = nullptr;
    WinAPIEventTableModel* m_eventModel = nullptr;
    WinAPIEventFilterModel* m_eventProxy = nullptr;
    WinAPIEventArchive m_eventArchive{20000, WinAPIEventArchive::memoryCapacity};
    std::mutex m_pendingMutex;
    std::deque<WinAPIEventRef> m_pendingRows;
    std::size_t m_evictedRows = 0;
    FakeTimeline* m_apiTimeline = nullptr;
    std::deque<WinAPIEventRef> m_eventProjectionQueue;
    WinAPIEventRef m_restoreSelectedEvent, m_restoreTopEvent;
    bool m_eventProjectionStale = true, m_eventProjectionPumpScheduled = false;
    bool m_eventTailFollowScheduled = false;
    static constexpr std::size_t kUiFlushRowLimit = 512;
    static constexpr int kUiFlushBudgetMs = 4;
    WinAPIEventRef eventRecordAt(int) const;
    void acceptPendingEventRows(bool drainAll = false);
    void applyEventState(const WinAPIEventRow&) {}
    void projectEventRows();
    void initializeEventTailFollow();
    void scheduleEventTailFollow();
    void flushPendingRows() { projectEventRows(); }
    void append(std::uint64_t sequence)
    {
        auto record = std::make_shared<WinAPIEventRecord>(); record->sequence = sequence;
        record->value.time100nsText = QString::number(sequence).rightJustified(12, QLatin1Char('0'));
        record->value.apiText = sequence % 7 ? QStringLiteral("other") : QStringLiteral("needle");
        record->value.resultText = QStringLiteral("OK");
        record->searchText = record->value.apiText;
        m_eventArchive.append(record);
        if (!m_eventProjectionStale) m_eventProjectionQueue.push_back(record);
    }
    void drain()
    {
        do { projectEventRows(); QCoreApplication::processEvents(); }
        while (m_eventProjectionStale || !m_eventProjectionQueue.empty());
    }
};
// PRODUCTION_METHODS
static int checks = 0;
#define CHECK(x) do { ++checks; if (!(x)) { std::cerr << "FAIL " << __LINE__ << " check=" << checks << ": " #x "\n"; return 19; } } while (false)
static bool settle(const std::function<bool()>& done)
{
    QElapsedTimer timer; timer.start();
    do {
        QCoreApplication::processEvents(); QCoreApplication::processEvents();
        if (done()) return true; QThread::msleep(1);
    } while (timer.elapsed() < 30000);
    return false;
}
int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    {
        WinAPIDock dock; QTableView table; dock.m_eventTable = &table;
        for (std::uint64_t i = 1; i <= 12000; ++i) {
            auto record = std::make_shared<WinAPIEventRecord>(); record->sequence = i;
            dock.m_pendingRows.push_back(record);
        }
        dock.acceptPendingEventRows();
        CHECK(dock.m_eventArchive.size() == 512 && dock.m_pendingRows.size() == 11488);
        while (!dock.m_pendingRows.empty()) dock.acceptPendingEventRows();
        CHECK(dock.m_eventArchive.size() == 12000 && dock.m_eventArchive.evictedCount() == 0);
        for (std::uint64_t i = 12001; i <= 13000; ++i) {
            auto record = std::make_shared<WinAPIEventRecord>(); record->sequence = i; dock.m_pendingRows.push_back(record);
        }
        dock.acceptPendingEventRows(true);
        CHECK(dock.m_pendingRows.empty() && dock.m_eventArchive.size() == 13000);
    }
    {
        WinAPIDock dock; QTableView table; QCheckBox follow;
        WinAPIEventTableModel model(&table); WinAPIEventFilterModel proxy(&table);
        proxy.setSourceModel(&model); table.setModel(&proxy); table.resize(900, 500); table.show();
        dock.m_eventTable = &table; dock.m_eventModel = &model; dock.m_eventProxy = &proxy;
        dock.m_eventKeepBottomCheck = &follow; follow.setChecked(true); dock.initializeEventTailFollow();
        for (std::uint64_t i = 1; i <= 12000; ++i) {
            auto record = std::make_shared<WinAPIEventRecord>(); record->sequence = i;
            record->value.apiText = QStringLiteral("kernelbase.dll!GetFileAttributesW");
            record->value.pidTidText = QStringLiteral("1 / 2"); dock.m_pendingRows.push_back(record);
        }
        qint64 maxBatchMs = 0;
        while (!dock.m_pendingRows.empty() || !dock.m_eventProjectionQueue.empty() || dock.m_eventProjectionStale) {
            QElapsedTimer tick; tick.start(); dock.acceptPendingEventRows(); dock.projectEventRows();
            maxBatchMs = std::max(maxBatchMs, tick.elapsed()); QCoreApplication::processEvents();
        }
        CHECK(model.rowCount() == 12000 && dock.m_eventArchive.evictedCount() == 0);
        std::cout << "12000-row bounded refresh: max batch " << maxBatchMs << " ms\n";
    }
    {
        WinAPIEventTableModel source; WinAPIEventFilterModel proxy;
        proxy.setSourceModel(&source);
        std::vector<WinAPIEventRef> rows;
        for (const auto sequence : {11ULL, 2ULL, 9ULL}) {
            auto record = std::make_shared<WinAPIEventRecord>(); record->sequence = sequence; record->generation = 1;
            record->value.sourcePid = 12; record->value.sourceCreationTime100ns = 42;
            record->value.durationCaptured = sequence != 9;
            record->value.duration100ns = sequence == 11 ? 0 : 12345;
            record->value.time100nsText = QString::number(sequence);
            record->value.apiText = QStringLiteral("user32.dll!Example");
            record->searchText = record->value.apiText;
            record->value.pidTidText = QStringLiteral("12 / 34");
            record->value.detailText = sequence == 9 ? QStringLiteral("target=0x123 strongTyped=0 params=raw")
                : QStringLiteral("target=0x123 caller=0xb strongTyped=0 params=raw");
            rows.push_back(record);
        }
        source.append(rows);
        CHECK(source.columnCount() == ks::monitor::ColumnCount);
        CHECK(source.index(0, ks::monitor::Module).data().toString() == QStringLiteral("user32.dll"));
        CHECK(source.index(0, ks::monitor::CallerAddress).data().toString() == QStringLiteral("0xb"));
        CHECK(source.index(0, ks::monitor::ReturnValue).data().toString() == QStringLiteral("-"));
        CHECK(source.index(0, ks::monitor::Duration).data().toString() == QStringLiteral("0.0000 ms"));
        CHECK(source.index(1, ks::monitor::Duration).data().toString() == QStringLiteral("1.2345 ms"));
        CHECK(source.index(2, ks::monitor::Duration).data().toString() == QStringLiteral("-"));
        CHECK(ks::monitor::EventSortValue(rows[0], ks::monitor::Duration).toULongLong() == 0);
        CHECK(!ks::monitor::EventSortValue(rows[2], ks::monitor::Duration).isValid());
        ks::winapi_monitor::CallerSnapshot snap;
        snap.status = ks::winapi_monitor::CallerSnapshotStatus::Available;
        snap.request = {1, 11, 12, 42, 11}; snap.state = MEM_COMMIT; snap.type = MEM_IMAGE;
        snap.mappedPath = L"\\Device\\HarddiskVolume1\\Windows\\example.dll";
        auto wrong = snap; wrong.request.creationTime100ns = 43;
        source.setCallerSnapshot(rows[0], wrong);
        CHECK(source.index(0, ks::monitor::CallerModule).data().toString() == QStringLiteral("-"));
        source.setCallerSnapshot(rows[0], snap);
        CHECK(source.index(0, ks::monitor::CallerModule).data().toString() == QStringLiteral("example.dll [snapshot]"));
        CHECK(source.index(0, ks::monitor::MemoryKind).data().toString() == QStringLiteral("image [snapshot]"));
        CHECK(source.index(1, ks::monitor::CallerModule).data().toString() == QStringLiteral("-"));
        auto newer = snap; newer.observedTime100ns = 20; newer.mappedPath = L"newer.dll";
        auto older = snap; older.observedTime100ns = 10; older.mappedPath = L"older.dll";
        source.setCallerSnapshot(rows[0], newer); source.setCallerSnapshot(rows[0], older);
        CHECK(source.index(0, ks::monitor::CallerModule).data().toString() == QStringLiteral("newer.dll [snapshot]"));
        proxy.sort(ks::monitor::Sequence, Qt::AscendingOrder);
        CHECK(proxy.index(0, ks::monitor::Sequence).data().toString() == QStringLiteral("2"));
        CHECK(proxy.index(2, ks::monitor::Sequence).data().toString() == QStringLiteral("11"));
        WinAPIEventExportSnapshot exported; exported.rows = rows; exported.continuousSort = true;
        exported.callerColumns = source.callerColumns();
        CHECK(exported.displayedCells(rows[0])[ks::monitor::CallerModule] == source.index(0, ks::monitor::CallerModule).data().toString());
        exported.sortColumn = ks::monitor::CallerAddress;
        for (const auto order : {Qt::AscendingOrder, Qt::DescendingOrder}) {
            proxy.sort(ks::monitor::CallerAddress, order); exported.sortOrder = order;
            const auto sorted = exported.orderedRows();
            for (int index = 0; index < proxy.rowCount(); ++index) {
                CHECK(source.recordAt(proxy.mapToSource(proxy.index(index, 0)).row()) == sorted[static_cast<std::size_t>(index)]);
            }
        }
        source.setKeyword(QStringLiteral("Example"));
        source.setTimeRange(true, 2, 9);
        CHECK(settle([&]() { return !source.filterPending(); }));
        CHECK(proxy.rowCount() == 2);
        auto later = std::make_shared<WinAPIEventRecord>(); later->sequence = 12;
        later->value.apiText = QStringLiteral("user32.dll!Example"); later->searchText = later->value.apiText;
        later->value.time100nsText = QStringLiteral("12"); source.append({later});
        CHECK(proxy.rowCount() == 2);
        source.setTimeRange(false, 0, 0);
        CHECK(settle([&]() { return !source.filterPending(); }));
        CHECK(proxy.rowCount() == 4);
    }
    {
        WinAPIEventTableModel source;
        std::vector<WinAPIEventRef> rows;
        for (std::uint64_t i = 1; i <= 513; ++i) {
            auto record = std::make_shared<WinAPIEventRecord>();
            record->generation = 1; record->sequence = i;
            record->value.sourcePid = 12; record->value.sourceCreationTime100ns = 42;
            record->value.detailText = QStringLiteral("target=0x1 caller=0xb strongTyped=0 params=raw");
            rows.push_back(record);
        }
        source.append(rows);
        for (const auto& record : rows) {
            ks::winapi_monitor::CallerSnapshot snap;
            snap.status = ks::winapi_monitor::CallerSnapshotStatus::Available;
            snap.request = {1, record->sequence, 12, 42, 11}; snap.state = MEM_COMMIT; snap.type = MEM_PRIVATE;
            source.setCallerSnapshot(record, snap);
        }
        CHECK(source.callerColumns().size() == 513);
        CHECK(source.index(0, ks::monitor::MemoryKind).data().toString() == QStringLiteral("private [snapshot]"));
        CHECK(source.index(512, ks::monitor::MemoryKind).data().toString() == QStringLiteral("private [snapshot]"));
        source.clear(); CHECK(source.callerColumns().empty());
    }
    {
        WinAPIEventTableModel source;
        FILETIME created{}, exited{}, kernel{}, user{};
        CHECK(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user));
        const auto identity = (std::uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        const auto address = reinterpret_cast<std::uintptr_t>(&GetCurrentProcessId);
        std::vector<WinAPIEventRef> rows;
        for (std::uint64_t i = 1; i <= 100000; ++i) {
            auto record = std::make_shared<WinAPIEventRecord>();
            record->generation = 7; record->sequence = i;
            record->value.sourcePid = GetCurrentProcessId(); record->value.sourceCreationTime100ns = identity;
            record->value.detailText = QStringLiteral("target=0x1 caller=0x%1 strongTyped=0 params=raw").arg(address, 0, 16);
            rows.push_back(record);
        }
        WinAPIEventFilterModel proxy; proxy.setSourceModel(&source);
        QElapsedTimer resolutionTime; resolutionTime.start();
        source.append(rows);
        CHECK(settle([&]() { return source.callerColumns().size() == rows.size(); }));
        std::cout << "100000 automatic caller snapshots: " << resolutionTime.elapsed() << " ms\n";
        CHECK(source.index(0, ks::monitor::CallerModule).data().toString() != QStringLiteral("-"));
        CHECK(source.index(99999, ks::monitor::MemoryKind).data().toString() == QStringLiteral("image [snapshot]"));
        CHECK(proxy.rowCount() == 100000);
        source.trimFront(50000); CHECK(source.callerColumns().size() == 50000);
        CHECK(ks::ui::AsyncCleanupRegistry::global().pending() > 0);
        ks::ui::AsyncCleanupRegistry::global().beginShutdown();
        CHECK(settle([]() { return ks::ui::AsyncCleanupRegistry::global().pending() == 0; }));
        ks::ui::AsyncCleanupRegistry::global().cancelShutdown();
        source.clear(); CHECK(source.callerColumns().empty());
    }
    const bool filters = argc > 1 && QByteArray(argv[1]) == "filter";
    for (const auto mode : {QAbstractItemView::ScrollPerItem, QAbstractItemView::ScrollPerPixel})
    {
        WinAPIDock dock; ks::ui::TableActionTableView table; QCheckBox follow;
        auto* model = new WinAPIEventTableModel(&table); auto* proxy = new WinAPIEventFilterModel(&table);
        proxy->setSourceModel(model); table.setModel(proxy);
        dock.m_eventTable = &table; dock.m_eventModel = model; dock.m_eventProxy = proxy;
        dock.m_eventKeepBottomCheck = &follow; follow.setChecked(true);
        table.resize(900, 500); table.setVerticalScrollMode(mode); table.setWordWrap(false);
        table.verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
        table.show(); QCoreApplication::processEvents(); dock.initializeEventTailFollow();
        for (std::uint64_t i = 1; i <= 25000; ++i) dock.append(i);
        dock.drain();
        const auto atBottom = [&]() { return table.verticalScrollBar()->value() == table.verticalScrollBar()->maximum(); };
        CHECK(settle(atBottom)); CHECK(model->rowCount() == 20000);
        CHECK(dock.eventRecordAt(0)->sequence == 5001);
        table.setCurrentIndex(proxy->index(0, 0)); table.scrollToBottom();
        for (std::uint64_t next = 25001; next <= 35000; next += 400)
        {
            for (std::uint64_t i = next; i < next + 400; ++i) dock.append(i);
            dock.drain(); CHECK(settle(atBottom));
            CHECK(dock.eventRecordAt(proxy->rowCount() - 1)->sequence == next + 399);
        }
        CHECK(!table.hasAutoScroll());
        // Late geometry must not strand the view at its old maximum.
        table.verticalHeader()->setDefaultSectionSize(30);
        CHECK(settle(atBottom));
        follow.setChecked(false);
        table.scrollTo(proxy->index(10000, 0), QAbstractItemView::PositionAtTop);
        const auto anchor = dock.eventRecordAt(table.indexAt(QPoint(0, 0)).row());
        for (std::uint64_t i = 35001; i <= 35400; ++i) dock.append(i);
        dock.drain();
        CHECK(dock.eventRecordAt(table.indexAt(QPoint(0, 0)).row()) == anchor);
        CHECK(table.hasAutoScroll());
        // A queued old follow cannot override a subsequent checkbox change.
        follow.setChecked(true); follow.setChecked(false);
        const int readingPosition = table.verticalScrollBar()->value();
        QCoreApplication::processEvents(); CHECK(table.verticalScrollBar()->value() == readingPosition);
        follow.setChecked(true); CHECK(settle(atBottom));
        if (filters)
        {
            int resets = 0; QObject::connect(model, &QAbstractItemModel::modelReset, &table, [&]() { ++resets; });
            model->setKeyword(QStringLiteral("NEEDLE"));
            CHECK(settle([&]() { return !model->filterPending() && atBottom(); }));
            int expected = 0; for (const auto& row : dock.m_eventArchive.snapshot()) if (row->sequence % 7 == 0) ++expected;
            CHECK(proxy->rowCount() == expected); CHECK(resets == 0);
            table.setCurrentIndex(proxy->index(0, 0)); table.scrollToBottom();
            model->setKeyword(QStringLiteral("other"));
            CHECK(settle([&]() { return !model->filterPending() && atBottom(); }));
            CHECK(proxy->rowCount() == model->rowCount() - expected);
            model->setKeyword(QStringLiteral("not-present")); model->setKeyword(QStringLiteral("needle")); model->setKeyword({});
            CHECK(settle([&]() { return !model->filterPending() && atBottom(); }));
            CHECK(proxy->rowCount() == model->rowCount()); CHECK(resets == 0);
            model->setKeyword(QStringLiteral("needle"));
            for (std::uint64_t i = 35401; i <= 37400; ++i) dock.append(i);
            dock.drain(); CHECK(settle([&]() { return !model->filterPending() && atBottom(); }));
            for (int row = 0; row < proxy->rowCount(); ++row) CHECK(dock.eventRecordAt(row)->sequence % 7 == 0);
            model->setKeyword({}); model->clear(); QCoreApplication::processEvents(); CHECK(model->rowCount() == 0);
        }
        // Sorting and menu barriers retain the same live model and native bars.
        proxy->sort(0, Qt::DescendingOrder); CHECK(settle(atBottom));
        ks::ui::menuOpen = true; table.verticalHeader()->setDefaultSectionSize(40);
        dock.scheduleEventTailFollow();
        CHECK(settle([]() { return bool(ks::ui::afterMenu); }));
        ks::ui::menuOpen = false; auto resume = std::move(ks::ui::afterMenu); resume(); CHECK(settle(atBottom));
        model->close();
    }
    if (filters)
    {
        // A large value-only model retains substantially more than 12,000 rows.
        const int stressRows = std::clamp(qEnvironmentVariableIntValue("KSWORD_APIMON_STRESS_ROWS"), 200000, 1000000);
        WinAPIEventArchive archive; WinAPIEventTableModel model; WinAPIEventFilterModel proxy;
        proxy.setSourceModel(&model);
        std::vector<WinAPIEventRef> batch;
        for (std::uint64_t i = 1; i <= static_cast<std::uint64_t>(stressRows); ++i) {
            auto row = std::make_shared<WinAPIEventRecord>(); row->sequence = i;
            row->value.apiText = i == 1 ? QStringLiteral("user32.dll!GetMessageW") : QStringLiteral("retained"); row->searchText = row->value.apiText;
            archive.append(row); batch.push_back(std::move(row));
            if (batch.size() == 2048) { model.append(batch); batch.clear(); }
        }
        model.append(batch); CHECK(archive.size() == static_cast<std::size_t>(stressRows)); CHECK(model.rowCount() == stressRows);
        CHECK(model.recordAt(stressRows - 1)->sequence == static_cast<std::uint64_t>(stressRows));
        CHECK(proxy.rowCount() == stressRows);
        int resets = 0, pulses = 0;
        QObject::connect(&model, &QAbstractItemModel::modelReset, &app, [&]() { ++resets; });
        QTimer heartbeat; heartbeat.setInterval(1);
        QObject::connect(&heartbeat, &QTimer::timeout, &app, [&]() { ++pulses; }); heartbeat.start();
        QElapsedTimer elapsed; elapsed.start();
        model.setKeyword(QStringLiteral("absent"));
        CHECK(settle([&]() { return !model.filterPending(); }));
        CHECK(!model.index(stressRows - 1, 0).data(WinAPIEventTableModel::AcceptedRole).toBool());
        CHECK(proxy.rowCount() == 0);
        CHECK(resets == 0 && pulses > 1);
        std::cout << stressRows << "-row model+proxy filter ms=" << elapsed.elapsed() << " heartbeat=" << pulses << "\n";
        model.setKeyword({}); CHECK(settle([&]() { return !model.filterPending(); }));
        CHECK(model.index(stressRows - 1, 0).data(WinAPIEventTableModel::AcceptedRole).toBool());
        CHECK(proxy.rowCount() == stressRows);
        auto rules = std::make_shared<ks::monitor::WinAPIFilterSnapshot>();
        rules->postFunctions.insert(ks::monitor::WinAPIFilterSnapshot::functionKey(QStringLiteral("USER32.DLL"), QStringLiteral("GetMessageW")));
        model.setEventRules(rules); CHECK(settle([&]() { return !model.filterPending(); }));
        CHECK(proxy.rowCount() == stressRows - 1); CHECK(!model.index(0, 0).data(WinAPIEventTableModel::AcceptedRole).toBool());
        auto live = std::make_shared<WinAPIEventRecord>(); live->value.apiText = QStringLiteral("user32.dll!GetMessageW");
        live->searchText = live->value.apiText; model.append({live}); CHECK(proxy.rowCount() == stressRows - 1);
        model.setEventRules(std::make_shared<ks::monitor::WinAPIFilterSnapshot>());
        CHECK(settle([&]() { return !model.filterPending(); })); CHECK(proxy.rowCount() == stressRows + 1);
        model.close();
        WinAPIEventArchive bounded(1000000, 8192);
        for (const auto& row : archive.snapshot()) bounded.append(row);
        CHECK(bounded.size() > 0 && bounded.size() < 100); CHECK(bounded.estimatedMemoryBytes() <= 8192);
        CHECK(bounded.evictedCount() == static_cast<std::size_t>(stressRows) - bounded.size());
    }
    std::cout << "PASS " << checks << " production WinAPI model/" << (filters ? "filter" : "tail") << " checks\n";
}
