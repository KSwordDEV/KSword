#include <Windows.h>
#include "__PROCESS_HEADER__"
#include <QDateTime>
#include <QDir>
#include <QHash>
#include <QSet>
#include <QString>
#include <QVariant>
#include <algorithm>
#include <cassert>
#include <deque>
#include <iostream>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>

constexpr std::uint64_t KernelOnlyCreationTimeSeed = 0xFFFFFFFF00000000ULL;
namespace ks::process { __IDENTITY__ }
QString processContextText(const char*, const QString& fallback) { return fallback; }
struct CheckBox { bool isChecked() const { return false; } };
struct ProcessDock {
    __TYPES__
    bool active = true, tree = true, friendly = false;
    QString search;
    bool m_activityTableSnapshotProjectionValid = false;
    std::uint64_t m_activityTableSnapshotRecordingTick = 1, m_activityRecordingStartTick100ns = 1;
    std::uint64_t m_activityTableSnapshotSequence = 0;
    int m_activityTableSnapshotIndex = 0;
    std::deque<ProcessActivitySample> m_activitySamples;
    std::unordered_map<std::string, CacheEntry> m_activityTableSnapshotRecords, m_cacheByIdentity;
    std::unordered_set<std::uint32_t> m_hiddenProcessPidSet;
    CheckBox* m_showKswordHiddenProcessCheck = nullptr;
    QSet<std::uint32_t> liveWindows;
    mutable int windowEnumerations = 0;
    int m_friendlySortColumn = static_cast<int>(TableColumn::Name);
    Qt::SortOrder m_friendlySortOrder = Qt::AscendingOrder;
    QHash<QString, bool> m_friendlyExpandedStateByKey;
    mutable std::vector<ks::process::ProcessRecord> m_friendlySyntheticRecords;
    bool isProcessActivityTableSnapshotActive() const { return active; }
    bool isTreeModeEnabled() const { return tree; }
    bool isFriendlyViewEnabled() const { return friendly; }
    QSet<std::uint32_t> collectVisibleWindowPidSet() const { ++windowEnumerations; return liveWindows; }
    QVariant processNumericSortValue(const ks::process::ProcessRecord& r, TableColumn column) const {
        return column == TableColumn::Cpu ? QVariant(r.cpuPercent) : QVariant();
    }
    QString formatColumnText(const ks::process::ProcessRecord& r, TableColumn, int) const {
        return QString::fromStdString(r.processName);
    }
    QString currentProcessSearchText() const { return search; }
    bool processRecordMatchesSearch(const ks::process::ProcessRecord& record) const {
        return search.isEmpty() || QString::fromStdString(record.processName).contains(search);
    }
    __METHODS__
};
using Point = ProcessDock::ProcessActivityProcessPoint;
using Sample = ProcessDock::ProcessActivitySample;
Point point(std::uint32_t pid, std::uint32_t parent, std::uint64_t created, const char* name) {
    Point p;
    p.pid = pid; p.parentPid = parent; p.creationTime100ns = created;
    p.processName = name; p.cpuPercent = pid / 10.0; p.privateWorkingSetBytes = pid * 4096ULL;
    p.privateWorkingSetKnown = true;
    return p;
}
int main() {
    ProcessDock dock;
    Sample first;
    first.sequence = 10;
    first.processes = {point(30,20,300,"child"), point(20,10,200,"middle"), point(10,0,100,"root"),
        point(40,999,400,"orphan"), point(50,60,100,"reused-child"), point(60,0,500,"new-parent"),
        point(70,10,0,"unknown-time"), point(80,10,KernelOnlyCreationTimeSeed+80,"synthetic-time"),
        point(90,90,600,"self")};
    dock.captureProcessActivityParentIdentities(first);
    assert(first.processes[0].parentCreationTime100ns == 200);
    assert(first.processes[1].parentCreationTime100ns == 100);
    for (std::size_t i = 3; i < first.processes.size(); ++i) assert(first.processes[i].parentCreationTime100ns == 0);
    first.processes[2].hasVisibleWindow = true;
    dock.m_activitySamples.push_back(first);
    dock.rebuildProcessActivityTableSnapshotRecords();
    auto rows = dock.buildActivitySnapshotDisplayOrder();
    assert(rows.size() == first.processes.size());
    const auto find = [&rows](std::uint32_t pid) -> const ProcessDock::DisplayRow& {
        return *std::find_if(rows.begin(),rows.end(),[pid](const auto& r) { return r.record->pid == pid; });
    };
    assert(find(10).depth == 0 && find(10).hasChildren);
    assert(find(20).depth == 1 && find(20).hasChildren);
    assert(find(30).depth == 2 && !find(30).hasChildren);
    assert(find(40).record->parentPid == 999 && find(40).depth == 0);
    for (auto pid : {50U,70U,80U,90U}) assert(find(pid).depth == 0);
    assert(find(30).record->privateWorkingSetBytes == first.processes[0].privateWorkingSetBytes);

    // Header sorting/search only change this projection; rebuilding retains the selected sample.
    dock.tree = false;
    rows = dock.buildActivitySnapshotDisplayOrder();
    for (const auto& row : rows) assert(row.depth == 0 && !row.hasChildren);
    dock.tree = true; dock.search = QStringLiteral("child");
    rows = dock.buildActivitySnapshotDisplayOrder();
    assert(rows.size() == 2);
    for (const auto& row : rows) assert(row.depth == 0);
    dock.search.clear();
    rows = dock.buildActivitySnapshotDisplayOrder();
    assert(find(30).depth == 2);

    // The next sample reuses PID 10. Its younger identity cannot inherit the old children.
    Sample next = first; next.sequence = 11;
    next.processes[2].creationTime100ns = 1000;
    dock.captureProcessActivityParentIdentities(next);
    dock.m_activitySamples.push_back(next); dock.m_activityTableSnapshotIndex = 1;
    dock.rebuildProcessActivityTableSnapshotRecords(); rows = dock.buildActivitySnapshotDisplayOrder();
    assert(find(20).depth == 0 && find(30).depth == 1);
    dock.m_activityTableSnapshotIndex = 0;
    dock.rebuildProcessActivityTableSnapshotRecords(); rows = dock.buildActivitySnapshotDisplayOrder();
    assert(find(20).depth == 1 && find(30).depth == 2);

    // Eviction of a selected sample preserves its independent records and parent identities.
    dock.m_activitySamples.pop_front(); dock.m_activityTableSnapshotIndex = -1;
    dock.rebuildProcessActivityTableSnapshotRecords(); rows = dock.buildActivitySnapshotDisplayOrder();
    assert(find(30).depth == 2 && find(20).record->parentCreationTime100ns == 100);

    // Checked friendly view has the same group/application projection in history and live mode.
    dock.friendly = true;
    dock.liveWindows = {40,50}; // Current window owners must not rewrite the old application family.
    dock.m_friendlyExpandedStateByKey.insert(QStringLiteral("friendly:app:10"), true);
    rows = dock.buildActivitySnapshotDisplayOrder();
    const auto aggregates = std::count_if(rows.begin(),rows.end(),[](const auto& r) {
        return r.rowKind == ProcessDock::ProcessTableRowKind::ApplicationAggregate;
    });
    assert(aggregates == 1);
    const auto aggregate = std::find_if(rows.begin(),rows.end(),[](const auto& r) {
        return r.rowKind == ProcessDock::ProcessTableRowKind::ApplicationAggregate;
    });
    assert(aggregate->record->pid == 10 && aggregate->actionIdentityKeys.size() == 3);
    assert(aggregate->record->privateWorkingSetBytes == (10ULL+20+30)*4096);
    assert(dock.windowEnumerations == 0);
    // Unknown/synthetic identities are deliberately stricter in history than legacy live trees.
    for (auto it=dock.m_activityTableSnapshotRecords.begin();it!=dock.m_activityTableSnapshotRecords.end();) {
        if (it->second.record.pid==70 || it->second.record.pid==80) it=dock.m_activityTableSnapshotRecords.erase(it); else ++it;
    }
    rows = dock.buildActivitySnapshotDisplayOrder();
    using Layout = std::tuple<ProcessDock::ProcessTableRowKind,std::uint32_t,int,QString>;
    std::vector<Layout> historicalLayout;
    for (const auto& row : rows) historicalLayout.emplace_back(row.rowKind,row.record->pid,row.depth,row.syntheticTitle);
    dock.m_cacheByIdentity = dock.m_activityTableSnapshotRecords;
    dock.liveWindows = {10};
    dock.active = false;
    const auto liveRows = dock.buildFriendlyDisplayOrder();
    assert(liveRows.size() == historicalLayout.size());
    for (std::size_t i=0;i<liveRows.size();++i) {
        assert(Layout(liveRows[i].rowKind,liveRows[i].record->pid,liveRows[i].depth,liveRows[i].syntheticTitle)==historicalLayout[i]);
    }
    assert(dock.windowEnumerations == 1);
    dock.active = true;
    dock.search = QStringLiteral("child");
    rows = dock.buildActivitySnapshotDisplayOrder();
    assert(rows.size() == 2);
    for (const auto& row : rows) assert(row.rowKind == ProcessDock::ProcessTableRowKind::Process && row.depth == 0);
    dock.search.clear();
    dock.friendly = false;

    // Missing/mismatched parent identities, equal-time cycles and deep chains stay bounded.
    std::vector<ks::process::ProcessRecord> records(20000);
    std::vector<ProcessDock::DisplayRow> input;
    for (std::size_t i = 0; i < records.size(); ++i) {
        auto& r = records[i]; r.pid = static_cast<std::uint32_t>(i + 1); r.creationTime100ns = i + 1;
        r.parentPid = static_cast<std::uint32_t>(i); r.parentCreationTime100ns = i;
        ProcessDock::DisplayRow row; row.record = &r; input.push_back(row);
    }
    rows = dock.buildProcessTreeDisplayOrder(input,true);
    assert(rows.size() == records.size() && rows.back().depth == 19999);
    records[0].parentPid = 2; records[0].parentCreationTime100ns = 2; records[0].creationTime100ns = 2;
    rows = dock.buildProcessTreeDisplayOrder(input,true);
    assert(rows.size() == records.size());
    records[1].parentCreationTime100ns = 999;
    rows = dock.buildProcessTreeDisplayOrder(input,true);
    const auto child = std::find_if(rows.begin(),rows.end(),[](const auto& r){return r.record->pid==2;});
    assert(child->depth == 0);
    std::cout << "PASS: production capture/replay, historical tree/flat/search/friendly, live/history grouping agreement, PID reuse, orphan, eviction, cycle and 20000-node chain\n";
}
