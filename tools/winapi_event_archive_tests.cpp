#include <Windows.h>
#include <QCoreApplication>
#include <iostream>
#include "MonitorDock/WinAPIEventArchive.h"

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
    const auto old = archive.snapshot();
    for (std::uint64_t i = 2; i <= 30000; ++i) archive.append(row(i));
    CHECK(archive.size() == 12000); CHECK(archive.snapshot().front()->sequence == 18001);
    CHECK(!archive.contains(first)); CHECK(old.front() == first);
    const auto revision = archive.revision(); archive.append(archive.snapshot().back()); CHECK(archive.revision() == revision);
    WinAPIEventExportSnapshot snapshot;
    snapshot.rows = archive.snapshot(); snapshot.sessionGeneration = 9; snapshot.archiveRevision = archive.revision();
    archive.clear(); CHECK(snapshot.rows.size() == 12000); CHECK(snapshot.rows.front()->value.detailText.size() == 7000);
    snapshot.rows = {row(1, QStringLiteral("z")), row(2, QStringLiteral("a")), row(3, QStringLiteral("a"))};
    snapshot.businessKeyword = QStringLiteral("Z"); CHECK(snapshot.matches(snapshot.rows[0])); CHECK(!snapshot.matches(snapshot.rows[1]));
    snapshot.businessKeyword.clear(); snapshot.search.active = true; snapshot.search.query = QStringLiteral("displayed"); snapshot.search.columns = {1}; CHECK(snapshot.matches(snapshot.rows[0]));
    snapshot.search.columns = {2}; CHECK(!snapshot.matches(snapshot.rows[0]));
    snapshot.search.active = false; CHECK(snapshot.matches(snapshot.rows[0]));
    snapshot.continuousSort = true; snapshot.sortColumn = 2;
    auto ordered = snapshot.orderedRows(); CHECK(ordered[0]->sequence == 2); CHECK(ordered[1]->sequence == 3); CHECK(ordered[2]->sequence == 1);
    snapshot.sortOrder = Qt::DescendingOrder; CHECK(snapshot.orderedRows()[0]->sequence == 1);
    snapshot.continuousSort = false; CHECK(snapshot.orderedRows()[0]->sequence == 1);
    CHECK(old.front()->value.detailText.size() == 7000);
    std::cout << "PASS " << assertions << " actual WinAPI archive/search/order/full-value assertions; no widgets or monitoring\n";
}
