// Actual Qt model/view and worker-lifetime fixtures. No capture session, driver,
// live symbols, clipboard or external process is used by this test executable.
#include "../Ksword5.1/Ksword5.1/MemoryDock/PoolAllocationAnalysisWidget.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include <QApplication>
#include <QComboBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QStyle>
#include <QTableView>
#include <QTemporaryFile>
#include <QTest>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <limits>
#include <thread>

namespace ks::evidence::pool {
// Resolve production entry points so the fixture links only the real widget
// and language manager. Every worker test injects its controlled provider.
TraceReadResult ReadPoolAllocationTrace(const std::wstring&, const std::atomic_bool&, const TraceReadOptions&) {
    std::cerr << "Unexpected production ETL reader in UI fixture\n"; std::abort();
}
std::vector<std::wstring> ResolvePoolTraceStack(const TraceReadResult&, const Group&, const std::atomic_bool&) {
    std::cerr << "Unexpected production symbols in UI fixture\n"; std::abort();
}
}

namespace {
using namespace ks::evidence::pool;
int checks = 0;
void require(bool ok, const char* label) {
    ++checks;
    if (!ok) { std::cerr << "FAIL " << checks << ": " << label << '\n'; std::exit(1); }
}
template<class F> bool until(F ready, int maximum = 3000) {
    QElapsedTimer clock; clock.start();
    do { QApplication::processEvents(); if (ready()) return true; QTest::qWait(2); }
    while (clock.elapsed() < maximum);
    return false;
}
template<class T> T* child(PoolAllocationAnalysisWidget& widget, const char* name) {
    auto* result = widget.findChild<T*>(QString::fromLatin1(name));
    require(result != nullptr, name); return result;
}
std::uint64_t raw(QTableView* table, int row, int column) {
    return table->model()->index(row, column).data(Qt::UserRole + 2).toULongLong();
}
TraceReadResult fixture(const QString& file) {
    TraceReadResult trace; trace.completed = true; trace.lossCountsKnown = true;
    trace.analysis.finished = true;
    TraceImage kernel; kernel.id = 4; kernel.base = 0x8000; kernel.size = 0x1000;
    kernel.path = L"C:\\Windows\\System32\\NTOSKRNL.EXE";
    TraceImage first; first.id = 1; first.base = 0x1000; first.size = 0x1000;
    first.path = file.toStdWString();
    TraceImage remote; remote.id = 2; remote.base = 0x2000; remote.size = 0x1000;
    remote.path = L"\\\\not-a-host-for-fixture.invalid\\share\\remote.sys";
    TraceImage reloaded = first; reloaded.id = 3; reloaded.base = 0x3000;
    trace.images = {kernel, first, remote, reloaded};
    Group a; a.groupId = 50; a.tag = 0x41414141; a.poolType = 0;
    a.stack = {0x8004, 0x1004}; a.frameImageIds = {4, 1};
    a.allocatedBytes = 100; a.allocatedCount = 2; a.pairedFreedBytes = 30;
    a.pairedFreedCount = 1; a.outstandingBytes = 70; a.outstandingCount = 1;
    a.representativeTimestamp = 800; a.representativePid = 4; a.representativeTid = 23;
    Group b = a; b.groupId = 10; b.stack[1] = 0x1008; b.allocatedBytes = 200;
    b.pairedFreedBytes = 180; b.outstandingBytes = 20;
    Group c = a; c.groupId = 99; c.tag = 0x42424242; c.stack = {0x8008, 0x2008};
    c.frameImageIds = {4, 2}; c.allocatedBytes = 300; c.pairedFreedBytes = 300;
    c.outstandingBytes = 0; c.outstandingCount = 0;
    Group session = a; session.groupId = 70; session.sessionId = 4;
    session.stack = {0x800c, 0x3008}; session.frameImageIds = {4, 3};
    session.allocatedBytes = 400; session.pairedFreedBytes = 50; session.outstandingBytes = 350;
    trace.analysis.groups = {a, b, c, session}; return trace;
}
struct Gate {
    std::atomic_bool entered{false}, cancelled{false}, release{false}, exited{false};
};
void gated(const std::shared_ptr<Gate>& gate, const std::atomic_bool& cancel) {
    gate->entered.store(true);
    while (!gate->release.load()) {
        if (cancel.load()) gate->cancelled.store(true);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    if (cancel.load()) gate->cancelled.store(true);
    gate->exited.store(true);
}
void exerciseModel(const TraceReadResult& trace) {
    PoolAllocationAnalysisWidget widget; widget.resize(760, 680); widget.show();
    widget.setResultForTesting(trace); QApplication::processEvents();
    auto* table = child<QTableView>(widget, "pool_analysis_table");
    auto* grouping = child<QComboBox>(widget, "pool_analysis_grouping");
    auto* stacks = child<QComboBox>(widget, "pool_analysis_stacks");
    auto* frames = child<CodeEditorWidget>(widget, "pool_analysis_frames");
    auto* filter = child<QLineEdit>(widget, "pool_analysis_filter");
    auto* module = child<QPushButton>(widget, "pool_analysis_module");
    require(table->model()->rowCount() == 3, "tag grouping separates ordinary and session pool");
    require(raw(table, 0, 5) == 350 && raw(table, 1, 5) == 90, "numeric default sort orders outstanding bytes");
    table->selectRow(1); QApplication::processEvents();
    require(stacks->count() == 2, "tag aggregation retains both complete source stacks");
    require(raw(table, 1, 1) == 300 && raw(table, 1, 3) == 210, "tag counters sum allocation and paired release independently");
    stacks->setCurrentIndex(1); QApplication::processEvents();
    require(stacks->currentData().toULongLong() == 10 && frames->text().contains(QStringLiteral("0x1008")), "group identity selects original second stack");
    require(frames->text().contains(QStringLiteral("0x8004")) && frames->text().contains(QStringLiteral("[image 1]")), "detail preserves kernel helper and historical image offsets");
    QString opened; widget.setOpenModuleDetails([&opened](const QString& path) { opened = path; });
    require(module->isEnabled(), "non-kernel historical source with a real local path enables navigation");
    module->click(); require(opened == QFileInfo(QString::fromStdWString(trace.images[1].path)).absoluteFilePath(), "navigation picks non-kernel source instead of ntoskrnl helper");
    table->sortByColumn(1, Qt::DescendingOrder); QApplication::processEvents();
    table->selectRow(0); QApplication::processEvents();
    require(stacks->currentData().toULongLong() == 70 && frames->text().contains(QStringLiteral("0x3008")), "sorting follows stable group IDs instead of old row indexes");
    filter->setText(QStringLiteral("BBBB")); QApplication::processEvents();
    require(table->model()->rowCount() == 1, "filter applies to underlying group tags");
    table->selectRow(0); QApplication::processEvents();
    require(stacks->currentData().toULongLong() == 99, "filtered selection uses original identity");
    require(!module->isEnabled(), "untrusted UNC history never enables local navigation");
    filter->clear(); grouping->setCurrentIndex(1); QApplication::processEvents();
    require(table->model()->rowCount() == 4, "complete stack mode retains each group");
    table->sortByColumn(1, Qt::AscendingOrder); table->selectRow(0); QApplication::processEvents();
    require(stacks->currentData().toULongLong() == 50, "complete stack numeric sort remains bound to its stable group");
    grouping->setCurrentIndex(2); QApplication::processEvents();
    require(table->model()->rowCount() == 3, "historical module mode keeps separate reloaded image IDs");
    filter->setText(QFileInfo(QString::fromStdWString(trace.images[1].path)).fileName()); QApplication::processEvents();
    require(table->model()->rowCount() == 2, "module filter finds historical source groups");
}
void exerciseResolution(const TraceReadResult& trace) {
    PoolAllocationAnalysisWidget widget; widget.setResultForTesting(trace);
    auto* table = child<QTableView>(widget, "pool_analysis_table");
    auto* stacks = child<QComboBox>(widget, "pool_analysis_stacks");
    auto* resolve = child<QPushButton>(widget, "pool_analysis_resolve");
    auto* frames = child<CodeEditorWidget>(widget, "pool_analysis_frames");
    auto gate = std::make_shared<Gate>();
    widget.setProvidersForTesting({}, [gate](const TraceReadResult&, const Group& group, const std::atomic_bool& cancel) {
        gated(gate, cancel); return std::vector<std::wstring>(group.stack.size(), L"STALE_LOCAL_SYMBOL");
    });
    table->selectRow(1); stacks->setCurrentIndex(0); resolve->click();
    require(until([&] { return gate->entered.load(); }), "selected stack resolver runs in controlled worker");
    stacks->setCurrentIndex(1);
    require(until([&] { return gate->cancelled.load(); }), "changing selected stack cancels its old resolution");
    gate->release.store(true);
    require(until([&] { return resolve->isEnabled(); }), "cancelled symbol worker finishes without blocking UI");
    require(!frames->text().contains(QStringLiteral("STALE_LOCAL_SYMBOL")), "old symbols cannot publish into new selected group");
    widget.setProvidersForTesting({}, [](const TraceReadResult&, const Group& group, const std::atomic_bool&) {
        return std::vector<std::wstring>(group.stack.size(), L"LOCAL_SYMBOL_OK");
    });
    resolve->click();
    require(until([&] { return frames->text().contains(QStringLiteral("LOCAL_SYMBOL_OK")); }), "completed selected stack symbols appear alongside raw frames");
}
void exerciseReaderLifetime(const TraceReadResult& trace) {
    auto gate = std::make_shared<Gate>();
    auto* widget = new PoolAllocationAnalysisWidget;
    widget->setProvidersForTesting([gate, trace](const std::wstring&, const std::atomic_bool& cancel) {
        gated(gate, cancel); return trace;
    }, {});
    widget->analyzeFile(QStringLiteral("controlled.etl"));
    require(until([&] { return gate->entered.load(); }), "controlled reader entered worker");
    QElapsedTimer timer; timer.start(); delete widget;
    require(timer.elapsed() < 100, "widget destruction cancels without joining a blocked worker");
    require(until([&] { return gate->cancelled.load(); }), "detached worker observes owner destruction cancellation");
    gate->release.store(true); require(until([&] { return gate->exited.load(); }), "destroyed-owner worker completes using only shared state");
    QApplication::processEvents();

    PoolAllocationAnalysisWidget replaced;
    auto first = std::make_shared<Gate>(); auto calls = std::make_shared<std::atomic_int>(0);
    replaced.setProvidersForTesting([first, calls, trace](const std::wstring&, const std::atomic_bool& cancel) {
        const auto call = calls->fetch_add(1);
        if (call == 0) gated(first, cancel);
        auto result = trace; result.analysis.groups.resize(1); result.analysis.groups[0].groupId = call == 0 ? 111 : 222;
        return result;
    }, {});
    replaced.analyzeFile(QStringLiteral("first.etl"));
    require(until([&] { return first->entered.load(); }), "first file reader started");
    replaced.analyzeFile(QStringLiteral("replacement.etl"));
    require(until([&] { return first->cancelled.load(); }), "new file request cancels active reader");
    require(calls->load() == 1, "replacement file waits instead of spawning unbounded simultaneous readers");
    first->release.store(true);
    auto* table = child<QTableView>(replaced, "pool_analysis_table");
    auto* stacks = child<QComboBox>(replaced, "pool_analysis_stacks");
    require(until([&] { return calls->load() == 2 && table->model()->rowCount() == 1; }), "replacement request starts after prior worker retires");
    require(stacks->currentData().toULongLong() == 222, "cancelled first file result never replaces latest result");

    PoolAllocationAnalysisWidget cancelled;
    auto stop = std::make_shared<Gate>();
    cancelled.setProvidersForTesting([stop, trace](const std::wstring&, const std::atomic_bool& cancel) {
        gated(stop, cancel); return trace;
    }, {});
    cancelled.analyzeFile(QStringLiteral("cancel.etl"));
    require(until([&] { return stop->entered.load(); }), "cancel button fixture entered reader");
    child<QPushButton>(cancelled, "pool_analysis_cancel")->click();
    require(until([&] { return stop->cancelled.load(); }), "cancel button requests cooperative reader cancellation");
    stop->release.store(true);
    auto* cancelOpen = child<QPushButton>(cancelled, "pool_analysis_open");
    require(until([&] { return cancelOpen->isEnabled(); }), "cancelled reader retires and restores controls");
    const auto text = child<QLabel>(cancelled, "pool_analysis_status")->text();
    require(text.contains(QStringLiteral("incomplete")) || text.contains(QStringLiteral("不完整")), "cancelled replay reports incomplete result even if provider returns complete");
}
void exerciseCallbackLifetime(const TraceReadResult& trace) {
    QPointer<PoolAllocationAnalysisWidget> widget = new PoolAllocationAnalysisWidget;
    widget->setResultForTesting(trace);
    widget->setOpenModuleDetails([&widget](const QString&) { delete widget.data(); });
    auto* table = child<QTableView>(*widget, "pool_analysis_table"); table->selectRow(1);
    auto* open = child<QPushButton>(*widget, "pool_analysis_module"); require(open->isEnabled(), "callback lifetime fixture has reliable source file");
    open->click(); require(widget.isNull(), "module navigation can destroy its originating widget safely");
}
void exerciseGapSemantics(const TraceReadResult& trace) {
    PoolAllocationAnalysisWidget widget;
    auto partial = trace; partial.analysis.coverageComplete = false;
    partial.analysis.stackCoverageComplete = false; partial.analysis.lifetimePairingAvailable = false;
    partial.lossCountsKnown = false; partial.lossMarkers = 7;
    partial.analysis.stats.decodeFailures = 5; partial.unsupportedPoolEvents = 5;
    widget.setResultForTesting(partial);
    auto* status = child<QLabel>(widget, "pool_analysis_status");
    auto* summary = child<QLabel>(widget, "pool_analysis_summary");
    require(status->text().contains(QStringLiteral("incomplete evidence")), "successful file replay distinguishes incomplete evidence coverage");
    require(status->text().contains(QStringLiteral("Lifetime pairing is unavailable")), "unknown loss positions explicitly disable lifecycle conclusions");
    require(summary->text().contains(QStringLiteral("Unknown loss counts")) && summary->text().contains(QStringLiteral("loss markers 7")), "loss counters stay unknown while observed loss marker count is retained");
    require(summary->text().contains(QStringLiteral("decode failures 5")), "unsupported pool events are not double counted as decode failures");
    auto saturated = trace; saturated.analysis.groups.resize(2);
    saturated.analysis.groups[0].allocatedBytes = (std::numeric_limits<std::uint64_t>::max)() - 10;
    saturated.analysis.groups[1].allocatedBytes = 100;
    widget.setResultForTesting(std::move(saturated));
    auto* table = child<QTableView>(widget, "pool_analysis_table");
    require(table->model()->index(0, 1).data().toString().startsWith(QChar(0x2265)), "cross-group aggregation overflow is displayed as a lower bound");
    require(table->model()->index(0, 1).data(Qt::ToolTipRole).toString().contains(QStringLiteral("lower bound")), "saturated aggregate explains its precision loss");
}
void exerciseBoundedProjection(const TraceReadResult& trace) {
    auto large = trace; large.analysis.groups.clear();
    Group group = trace.analysis.groups.front(); group.stack.assign(100, 0x8004); group.frameImageIds.assign(100, 4);
    for (std::uint64_t id = 1; id <= 10000; ++id) { group.groupId = id; large.analysis.groups.push_back(group); }
    PoolAllocationAnalysisWidget widget; QElapsedTimer timer; timer.start(); widget.setResultForTesting(std::move(large));
    const auto elapsed = timer.elapsed();
    auto* table = child<QTableView>(widget, "pool_analysis_table");
    auto* stacks = child<QComboBox>(widget, "pool_analysis_stacks");
    require(table->model()->rowCount() == 1 && stacks->count() == 10000, "bounded million-frame result retains all groups with a lazy stack selector");
    stacks->setCurrentIndex(9999);
    require(stacks->currentData().toULongLong() == 10000, "last group remains directly accessible in lazy stack model");
    std::cout << "Bounded projection: 10000 groups / 1000000 frames in " << elapsed << " ms\n";
}
void exerciseGeometryAndLanguage(const TraceReadResult& trace, const QString& output) {
    for (const auto& language : {QStringLiteral("en-US"), QStringLiteral("zh-CN")}) {
        QString error; require(ks::i18n::LanguageManager::instance().setLanguage(language, &error), "real checked-in language pack loads");
        for (const bool dark : {false, true}) {
            auto palette = QApplication::style()->standardPalette();
            if (dark) {
                palette.setColor(QPalette::Window, QColor(38, 38, 38)); palette.setColor(QPalette::Base, QColor(30, 30, 30));
                palette.setColor(QPalette::Text, QColor(230, 230, 230)); palette.setColor(QPalette::WindowText, QColor(230, 230, 230));
                palette.setColor(QPalette::Button, QColor(48, 48, 48)); palette.setColor(QPalette::ButtonText, QColor(230, 230, 230));
                palette.setColor(QPalette::AlternateBase, QColor(44, 44, 44)); palette.setColor(QPalette::PlaceholderText, QColor(175, 175, 175));
            }
            QApplication::setPalette(palette);
            PoolAllocationAnalysisWidget widget; widget.setResultForTesting(trace); widget.show();
            auto* open = child<QPushButton>(widget, "pool_analysis_open");
            if (language == QStringLiteral("en-US")) require(open->text() == QStringLiteral("Open ETL"), "English packed source text renders correctly");
            else require(open->text().contains(QStringLiteral("打开")), "Chinese packed source text uses translated source entry");
            for (const int width : {420, 760, 1280}) {
                widget.resize(width, 680); QApplication::processEvents();
                if (widget.width() != width) {
                    std::cerr << "Geometry actual=" << widget.width() << " requested=" << width
                        << " minimum=" << widget.minimumSizeHint().width() << '\n';
                    for (auto* control : widget.findChildren<QWidget*>())
                        if (!control->objectName().isEmpty()) std::cerr << control->objectName().toStdString()
                            << " width=" << control->width() << " minimumHint=" << control->minimumSizeHint().width() << '\n';
                }
                require(widget.width() == width, "word wrapping and compact combo permit narrow host geometry");
                for (auto* control : widget.findChildren<QPushButton*>()) {
                    const auto bounds = QRect(control->mapTo(&widget, QPoint()), control->size());
                    require(bounds.left() >= 0 && bounds.right() < widget.width(), "visible action buttons remain inside narrow widget");
                }
                for (auto* control : widget.findChildren<QComboBox*>()) {
                    const auto bounds = QRect(control->mapTo(&widget, QPoint()), control->size());
                    require(bounds.left() >= 0 && bounds.right() < widget.width(), "long historical stack labels do not widen combo geometry");
                }
                const auto image = widget.grab();
                require(image.save(QDir(output).filePath(QStringLiteral("pool-analysis-%1-%2-%3.png")
                    .arg(language, dark ? QStringLiteral("dark") : QStringLiteral("light"), QString::number(width)))), "Qt widget screenshot saved for visual review");
            }
        }
    }
}
}

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", QByteArray("offscreen"));
    QApplication app(argc, argv);
    // Windows offscreen plugin versions may not enumerate system fonts. Load
    // concrete CJK and fixed fonts before claiming rendered geometry or QA.
    const int cjkFont = QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    require(cjkFont >= 0, "offscreen fixture explicitly loads a CJK font");
    const auto families = QFontDatabase::applicationFontFamilies(cjkFont);
    require(!families.isEmpty(), "loaded CJK font exposes a usable family");
    app.setFont(QFont(families.front(), 9));
    require(QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/consola.ttf")) >= 0,
        "offscreen fixture explicitly loads its fixed font");
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/cour.ttf"));
    QString error; require(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("en-US"), &error), "language manager initializes real packs");
    QTemporaryFile module; require(module.open(), "local module-path fixture created");
    const auto trace = fixture(module.fileName());
    const auto output = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QDir::current().filePath(QStringLiteral(".codex-build-logs"));
    require(QDir().mkpath(output), "fixture output directory available");
    exerciseModel(trace); exerciseResolution(trace); exerciseReaderLifetime(trace); exerciseCallbackLifetime(trace);
    exerciseGapSemantics(trace); exerciseBoundedProjection(trace);
    exerciseGeometryAndLanguage(trace, output);
    std::cout << "Pool allocation UI: " << checks << " checks passed\n"; return 0;
}
