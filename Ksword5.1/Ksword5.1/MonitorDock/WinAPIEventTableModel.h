#pragma once

#include "WinAPISessionBackend.h"
#include "../UI/AsyncOperation.h"
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
    void setKeyword(QString keyword);
    bool filterPending() const { return m_filterPending; }
    bool filterFailed() const { return m_filterFailed; }
    void close();
    std::function<void()> filterStateChanged;
private:
    bool eventFilter(QObject* watched, QEvent* event) override;
    struct Row { WinAPIEventRef record; bool accepted; };
    struct FilterWork { QString keyword; std::vector<std::pair<std::uint64_t, QString>> rows; };
    using Matches = std::vector<std::pair<std::uint64_t, bool>>;
    void captureFilterRows();
    void applyFilterRows();
    void notifyFilterState();
    std::deque<Row> m_rows;
    std::unordered_map<const WinAPIEventRecord*, std::uint64_t> m_ordinals;
    std::uint64_t m_firstOrdinal = 0, m_nextOrdinal = 0, m_filterRevision = 0;
    std::uint64_t m_filterCursor = 0, m_filterEnd = 0;
    QString m_keyword;
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
    { setFilterRole(WinAPIEventTableModel::AcceptedRole); }
protected:
    bool filterAcceptsRow(int row, const QModelIndex& parent) const override
    { return sourceModel()->index(row, 0, parent).data(WinAPIEventTableModel::AcceptedRole).toBool(); }
};
