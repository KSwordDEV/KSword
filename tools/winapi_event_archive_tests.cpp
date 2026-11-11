#include <Windows.h>
#include <QCoreApplication>
#include <iostream>
#include "MonitorDock/WinAPIEventArchive.h"
#include "MonitorDock/MonitorCanonicalExport.h"

// Only transport of an immutable language value is faked. Archive, filters,
// shared search matching, immutable references and sorting are production code.
namespace ks::i18n
{
QString SourceTextSnapshot::displayText(const QString& source) const
{
    return source == QStringLiteral("RawCategory") ? QStringLiteral("DisplayedCategory") : source;
}
}
static int assertions = 0;
#define CHECK(x) do { ++assertions; if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 19; } } while (false)
struct StringSink {
    QString text;
    bool writeText(const QString& value) { text += value; return true; }
    bool rowsCompleted() { return true; }
};
static WinAPIEventRef row(std::uint64_t sequence, QString api = {})
{
    auto value = std::make_shared<WinAPIEventRecord>();
    value->generation = 9; value->sequence = sequence;
    value->value.apiText = api.isEmpty() ? QString::number(sequence) : api;
    value->value.categoryText = QStringLiteral("RawCategory");
    value->value.detailText = QString(7000, QLatin1Char('x'));
    value->searchText = WinAPIEventFields(value->value).join(QStringLiteral(" | "));
    return value;
}
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    WinAPIEventArchive archive(12000, static_cast<std::size_t>(-1));
    const auto first = row(1); archive.append(first);
    CHECK(first->value.categoryCode == static_cast<std::uint32_t>(ks::winapi_monitor::EventCategory::Unknown));
    const auto old = archive.snapshot();
    for (std::uint64_t i = 2; i <= 30000; ++i) archive.append(row(i));
    CHECK(archive.size() == 12000); CHECK(archive.snapshot().front()->sequence == 18001);
    const auto previousEvicted = archive.evictedCount();
    archive.setMemoryCapacity(50000); CHECK(archive.size() > 0 && archive.size() < 12000);
    CHECK(archive.evictedCount() == previousEvicted + 12000 - archive.size());
    archive.setMemoryCapacity(static_cast<std::size_t>(-1));
    CHECK(!archive.contains(first)); CHECK(old.front() == first);
    const auto revision = archive.revision(); archive.append(archive.snapshot().back()); CHECK(archive.revision() == revision);
    WinAPIEventExportSnapshot snapshot;
    snapshot.rows = archive.snapshot(); snapshot.sessionGeneration = 9; snapshot.archiveRevision = archive.revision();
    const auto snapshotSize = snapshot.rows.size();
    archive.clear(); CHECK(snapshot.rows.size() == snapshotSize); CHECK(snapshot.rows.front()->value.detailText.size() == 7000);
    snapshot.rows = {row(1, QStringLiteral("z")), row(2, QStringLiteral("a")), row(3, QStringLiteral("a"))};
    snapshot.businessKeyword = QStringLiteral("Z"); CHECK(snapshot.matches(snapshot.rows[0])); CHECK(!snapshot.matches(snapshot.rows[1]));
    snapshot.businessKeyword.clear(); snapshot.search.active = true; snapshot.search.query = QStringLiteral("displayed"); snapshot.search.columns = {1}; CHECK(snapshot.matches(snapshot.rows[0]));
    auto rules = std::make_shared<ks::monitor::WinAPIFilterSnapshot>();
    rules->postFunctions.insert(ks::monitor::WinAPIFilterSnapshot::functionKey(QStringLiteral("user32.dll"), QStringLiteral("GetMessageW")));
    snapshot.eventRules = rules;
    CHECK(!snapshot.matches(row(4, QStringLiteral("user32.dll!GetMessageW"))));
    snapshot.eventRules.reset();
    snapshot.search.columns = {2}; CHECK(!snapshot.matches(snapshot.rows[0]));
    snapshot.search.active = false; CHECK(snapshot.matches(snapshot.rows[0]));
    snapshot.continuousSort = true; snapshot.sortColumn = 2;
    auto ordered = snapshot.orderedRows(); CHECK(ordered[0]->sequence == 2); CHECK(ordered[1]->sequence == 3); CHECK(ordered[2]->sequence == 1);
    snapshot.sortOrder = Qt::DescendingOrder; CHECK(snapshot.orderedRows()[0]->sequence == 1);
    snapshot.continuousSort = false; CHECK(snapshot.orderedRows()[0]->sequence == 1);
    auto sample = std::make_shared<WinAPIEventRecord>();
    sample->sequence = 10; sample->value.apiText = QStringLiteral("user32.dll!GetMessageW");
    sample->value.pidTidText = QStringLiteral("12 / 34"); sample->value.resultText = QStringLiteral("OK");
    sample->value.time100nsText = QStringLiteral("134380539646649023");
    sample->value.detailText = QStringLiteral("Raw ABI fallback target=0x111 caller=0xABC123 strongTyped=0 params=raw");
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::Module) == QStringLiteral("user32.dll"));
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::Api) == QStringLiteral("GetMessageW"));
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::CallerAddress) == QStringLiteral("0xABC123"));
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::ReturnValue) == QStringLiteral("-"));
    sample->value.capturedReturnValue = QStringLiteral("0x123456");
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::ReturnValue) == QStringLiteral("0x123456"));
    CHECK(ks::monitor::EventSortValue(sample, ks::monitor::ReturnValue).toULongLong() == 0x123456);
    snapshot.businessKeyword = QStringLiteral("0x123456"); CHECK(snapshot.matches(sample)); snapshot.businessKeyword.clear();
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::Tid) == QStringLiteral("34"));
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::Time).contains(QChar(':')));
    sample->sessionBase100ns = 134380539646659023ULL;
    CHECK(ks::monitor::EventColumnText(sample, ks::monitor::RelativeTime) == QStringLiteral("-1.0000 ms"));
    CHECK(ks::monitor::EventSortValue(sample, ks::monitor::RelativeTime).toLongLong() == -10000);
    CHECK(FirstWinAPIEventTime(0, sample->value) == 134380539646649023ULL);
    CHECK(FirstWinAPIEventTime(99, sample->value) == 99);
    sample->value.timestamp100ns = 123; CHECK(FirstWinAPIEventTime(0, sample->value) == 123);
    CHECK(ks::monitor::EventInTimeRange(sample, {true, 123, 123}));
    sample->value.timestamp100ns = 0;
    sample->value.internalEvent = true; CHECK(FirstWinAPIEventTime(0, sample->value) == 0); sample->value.internalEvent = false;
    sample->value.sourceProcessName = QStringLiteral("dwm.exe"); snapshot.businessKeyword = QStringLiteral("DWM.EXE");
    CHECK(snapshot.matches(sample)); snapshot.businessKeyword.clear();

    CHECK(snapshot.displayedCells(sample).size() == ks::monitor::ColumnCount);
    snapshot.timeRange = {true, 134380539646649023ULL, 134380539646649023ULL}; CHECK(snapshot.matches(sample));
    snapshot.timeRange = {true, 1, 10}; CHECK(!snapshot.matches(sample));
    snapshot.timeRange = {};
    auto oldSample = std::make_shared<WinAPIEventRecord>(*sample); oldSample->value.detailText = QStringLiteral("target=0x111 strongTyped=0");
    CHECK(ks::monitor::EventColumnText(oldSample, ks::monitor::CallerAddress) == QStringLiteral("-"));
    oldSample->value.resultText = QStringLiteral("未采集");
    CHECK(ks::monitor::EventColumnText(oldSample, ks::monitor::Status) == QStringLiteral("-"));
    CHECK(ks::monitor::EventColumnText(oldSample, ks::monitor::CaptureKind) == QStringLiteral("Raw"));
    auto strongSample = std::make_shared<WinAPIEventRecord>(*sample);
    strongSample->value.detailText = QStringLiteral("typed");
    strongSample->value.durationCaptured = true;
    CHECK(ks::monitor::EventColumnText(strongSample, ks::monitor::CaptureKind) == QStringLiteral("Strong"));
    const auto exportCells = snapshot.displayedCells(strongSample);
    CHECK(exportCells.size() == ks::monitor::ColumnCount);
    CHECK(exportCells[ks::monitor::Module] == QStringLiteral("user32.dll"));
    CHECK(exportCells[ks::monitor::Duration] == QStringLiteral("0.0000 ms"));
    CHECK(exportCells[ks::monitor::CaptureKind] == QStringLiteral("Strong"));
    strongSample->value.detailText = QStringLiteral("a,\"b\"");
    snapshot.headers.clear();
    for (int column = 0; column < ks::monitor::ColumnCount; ++column) snapshot.headers << QString::number(column);
    ks::monitor::PreparedCanonicalExport<WinAPIEventExportSnapshot> csv;
    csv.source = std::make_shared<const WinAPIEventExportSnapshot>(snapshot);
    csv.rows = {strongSample}; csv.format = ks::monitor::CanonicalExportFormat::QuotedCsv;
    StringSink sink;
    CHECK(ks::monitor::FormatCanonicalMonitorExport(csv, sink));
    CHECK(sink.text.contains(QStringLiteral("\"user32.dll\"")));
    CHECK(sink.text.contains(QStringLiteral("\"0.0000 ms\"")));
    CHECK(sink.text.contains(QStringLiteral("\"a,\"\"b\"\"\"")));
    auto phaseSample = std::make_shared<WinAPIEventRecord>(*sample); phaseSample->value.detailText = QStringLiteral("[提交 #42] foo");
    CHECK(ks::monitor::EventColumnText(phaseSample, ks::monitor::OperationId) == QStringLiteral("42"));
    snapshot.rows = {row(11), row(2), row(9)}; snapshot.sortColumn = ks::monitor::Sequence;
    snapshot.continuousSort = true; snapshot.sortOrder = Qt::AscendingOrder;
    CHECK(snapshot.orderedRows()[0]->sequence == 2 && snapshot.orderedRows()[2]->sequence == 11);
    CHECK(old.front()->value.detailText.size() == 7000);
    std::cout << "PASS " << assertions << " actual WinAPI archive/search/order/full-value assertions; no widgets or monitoring\n";
}
