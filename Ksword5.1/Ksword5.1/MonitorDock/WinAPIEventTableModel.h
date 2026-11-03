#pragma once

#include "WinAPISessionBackend.h"
#include "WinAPIEventColumns.h"
#include "../../../shared/ApiMonitorCallerSnapshot.h"
#include "../UI/AsyncOperation.h"
#include "../UI/AsyncCleanupRegistry.h"
#include "../UI/AsyncUiDispatcher.h"
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QTimer>
#include <functional>

// Values and row notifications only. No per-cell items, widgets, or persistent
// indexes are allocated for the retained event window.
class WinAPIEventTableModel final : public QAbstractTableModel
{
public:
    static constexpr int AcceptedRole = Qt::UserRole + 32;
    static constexpr int SortRole = Qt::UserRole + 33;
    explicit WinAPIEventTableModel(QObject* parent = nullptr);
    ~WinAPIEventTableModel() override;
    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;
    WinAPIEventRef recordAt(int row) const;
    int rowForRecord(const WinAPIEventRef& record) const;
    void append(const std::vector<WinAPIEventRef>& records);
    void trimFront(int count);
    void clear();
    void setCallerSnapshot(const WinAPIEventRef& record, const ks::winapi_monitor::CallerSnapshot& snapshot);
    const ks::monitor::CallerColumnMap& callerColumns() const { return m_callerColumns; }
    void setKeyword(QString keyword);
    void setEventRules(std::shared_ptr<const ks::monitor::WinAPIFilterSnapshot> rules);
    void setTimeRange(bool enabled, std::uint64_t first, std::uint64_t last);
    ks::monitor::EventTimeRange timeRange() const { return m_timeRange; }
    bool filterPending() const { return m_filterPending; }
    bool filterFailed() const { return m_filterFailed; }
    float filterProgress() const;
    void close();
    std::function<void()> filterStateChanged;
private:
    bool eventFilter(QObject* watched, QEvent* event) override;
    struct Row { WinAPIEventRef record; bool accepted; };
    struct FilterWork { QString keyword; ks::monitor::EventTimeRange timeRange; std::shared_ptr<const ks::monitor::WinAPIFilterSnapshot> rules; std::vector<std::pair<std::uint64_t, WinAPIEventRef>> rows; };
    using Matches = std::vector<std::pair<std::uint64_t, bool>>;
    void captureFilterRows();
    void applyFilterRows();
    void notifyFilterState();
    void pumpCallerSnapshots();
    int storeCallerSnapshot(const WinAPIEventRef& record, const ks::winapi_monitor::CallerSnapshot& snapshot);
    void stopCallerSnapshots();
    std::deque<Row> m_rows;
    // Values are retained only for records still in the model.
    ks::monitor::CallerColumnMap m_callerColumns;
    std::shared_ptr<ks::winapi_monitor::CallerSnapshotResolver> m_callerResolver;
    std::shared_ptr<ks::ui::AsyncCleanupRegistry::Lease> m_callerLease;
    std::shared_ptr<ks::ui::AsyncUiDispatcher> m_callerDispatcher;
    std::unordered_map<std::uint64_t, std::weak_ptr<const WinAPIEventRecord>> m_callerRequests;
    std::uint64_t m_callerCursor = 0, m_callerRequestId = 0;
    QTimer m_callerTimer;
    std::unordered_map<const WinAPIEventRecord*, std::uint64_t> m_ordinals;
    std::uint64_t m_firstOrdinal = 0, m_nextOrdinal = 0, m_filterRevision = 0;
    std::uint64_t m_filterBegin = 0, m_filterCursor = 0, m_filterEnd = 0;
    QString m_keyword;
    ks::monitor::EventTimeRange m_timeRange;
    std::shared_ptr<const ks::monitor::WinAPIFilterSnapshot> m_rules;
    std::shared_ptr<FilterWork> m_filterWork;
    std::shared_ptr<const Matches> m_filterMatches;
    std::size_t m_filterApplyCursor = 0;
    ks::ui::AsyncOperation* m_filterOperation;
    QTimer m_captureTimer, m_applyTimer;
    bool m_filterPending = false, m_filterFailed = false, m_closed = false;
};

class WinAPIEventFilterModel final : public QSortFilterProxyModel
{
public:
    explicit WinAPIEventFilterModel(QObject* parent = nullptr) : QSortFilterProxyModel(parent)
    { setFilterRole(WinAPIEventTableModel::AcceptedRole); setSortRole(WinAPIEventTableModel::SortRole); setSortLocaleAware(true); }
protected:
    bool lessThan(const QModelIndex& left, const QModelIndex& right) const override
    {
        if (QSortFilterProxyModel::lessThan(left, right)) return true;
        if (QSortFilterProxyModel::lessThan(right, left)) return false;
        return left.row() < right.row();
    }
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override
    { return sourceModel()->index(row, 0, parent).data(WinAPIEventTableModel::AcceptedRole).toBool(); }
};
