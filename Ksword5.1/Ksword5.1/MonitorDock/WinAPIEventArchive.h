#pragma once

#include "WinAPISessionBackend.h"
#include "WinAPIEventColumns.h"
#include "../Internationalization/LanguageManager.h"
#include "UI/TableSearchFilterSnapshot.h"
#include <unordered_set>
#include <QCollator>
#include <algorithm>

// GUI-owned bounded canonical record ledger. Hidden pages and menu barriers do
// not stop acceptance; only the widget projection waits. Immutable refs retain
// their data after eviction, clear, generation changes, filtering or export.
class WinAPIEventArchive final
{
public:
    static constexpr std::size_t capacity = 1000000;
    static constexpr std::size_t memoryCapacity = 512ULL * 1024 * 1024;
    explicit WinAPIEventArchive(std::size_t rowLimit = capacity, std::size_t byteLimit = memoryCapacity)
        : m_rowLimit(std::max<std::size_t>(1, rowLimit)), m_byteLimit(byteLimit) {}
    WinAPIEventRef append(WinAPIEventRef row)
    {
        if (!row) return {};
        const auto [present, inserted] = m_present.insert(row.get());
        if (!inserted) return {};
        try { m_rows.push_back(row); }
        catch (...) { m_present.erase(present); throw; }
        ++m_revision;
        m_bytes += estimatedBytes(row);
        WinAPIEventRef firstEvicted;
        while (m_rows.size() > m_rowLimit || (m_rows.size() > 1 && m_bytes > m_byteLimit))
        {
            auto evicted = std::move(m_rows.front());
            m_rows.pop_front(); m_present.erase(evicted.get()); m_bytes -= estimatedBytes(evicted); ++m_evicted;
            if (!firstEvicted) firstEvicted = std::move(evicted);
        }
        return firstEvicted;
    }
    void clear() { m_rows.clear(); m_present.clear(); m_bytes = 0; m_evicted = 0; ++m_revision; }
    bool contains(const WinAPIEventRef& row) const { return row && m_present.contains(row.get()); }
    std::size_t size() const { return m_rows.size(); }
    std::uint64_t revision() const { return m_revision; }
    std::size_t estimatedMemoryBytes() const { return m_bytes; }
    std::size_t evictedCount() const { return m_evicted; }
    void setMemoryCapacity(std::size_t bytes)
    {
        m_byteLimit = bytes;
        while (m_rows.size() > 1 && m_bytes > m_byteLimit) {
            auto row = std::move(m_rows.front()); m_rows.pop_front();
            m_present.erase(row.get()); m_bytes -= estimatedBytes(row); ++m_evicted;
        }
    }
    std::vector<WinAPIEventRef> snapshot() const { return {m_rows.begin(), m_rows.end()}; }
private:
    static std::size_t estimatedBytes(const WinAPIEventRef& row)
    {
        const auto& v = row->value;
        return sizeof(WinAPIEventRecord) + 128 + 2 * static_cast<std::size_t>(row->searchText.size()
            + v.time100nsText.size() + v.categoryText.size() + v.apiText.size() + v.resultText.size()
            + v.pidTidText.size() + v.detailText.size() + v.agentStatus.size() + v.sourceProcessName.size() + v.capturedReturnValue.size() + v.capturedCallStack.size());
    }
    std::deque<WinAPIEventRef> m_rows;
    std::unordered_set<const WinAPIEventRecord*> m_present;
    std::uint64_t m_revision = 0;
    std::size_t m_rowLimit, m_byteLimit, m_bytes = 0, m_evicted = 0;
};

// Frozen source, conditions and translation values. The exporter evaluates the
// same business substring and shared search predicate without visiting a table,
// including when API coverage is the current result tab.
struct WinAPIEventExportSnapshot
{
    std::vector<WinAPIEventRef> rows;
    ks::monitor::CallerColumnMap callerColumns; // Frozen UI snapshot values, not historical mappings.
    QString businessKeyword, lossSummary;
    ks::monitor::EventTimeRange timeRange;
    std::shared_ptr<const ks::monitor::WinAPIFilterSnapshot> eventRules;
    QStringList headers;
    ks::ui::TableSearchResultFilterSpec search;
    ks::i18n::SourceTextSnapshot language;
    std::uint64_t sessionGeneration = 0, archiveRevision = 0;
    std::uint32_t targetPid = 0;
    bool continuousSort = false;
    int sortColumn = -1;
    Qt::SortOrder sortOrder = Qt::AscendingOrder;
    QCollator collator;
    QStringList displayedCells(const WinAPIEventRef& record) const
    {
        if (!record) return {};
        auto cells = ks::monitor::EventColumnTexts(record, &callerColumns);
        for (auto& cell : cells) cell = language.displayText(cell);
        return cells;
    }
    std::vector<WinAPIEventRef> orderedRows() const
    {
        if (!continuousSort || sortColumn < 0 || sortColumn >= ks::monitor::ColumnCount) return rows;
        struct SortRow { WinAPIEventRef record; QVariant value; std::size_t ordinal; };
        std::vector<SortRow> keyed;
        keyed.reserve(rows.size());
        for (std::size_t ordinal = 0; ordinal < rows.size(); ++ordinal)
            keyed.push_back({rows[ordinal], ks::monitor::EventSortValue(rows[ordinal], sortColumn, &callerColumns), ordinal});
        std::stable_sort(keyed.begin(), keyed.end(), [this](const auto& left, const auto& right) {
            int order = 0;
            if (!left.value.isValid() || !right.value.isValid())
                order = int(right.value.isValid()) - int(left.value.isValid());
            else if (left.value.metaType().id() == QMetaType::ULongLong && right.value.metaType().id() == QMetaType::ULongLong) {
                const auto a = left.value.toULongLong(), b = right.value.toULongLong();
                order = a < b ? -1 : a > b ? 1 : 0;
            } else if (left.value.metaType().id() == QMetaType::LongLong && right.value.metaType().id() == QMetaType::LongLong) {
                const auto a = left.value.toLongLong(), b = right.value.toLongLong();
                order = a < b ? -1 : a > b ? 1 : 0;
            } else order = collator.compare(language.displayText(left.value.toString()), language.displayText(right.value.toString()));
            if (order == 0) return sortOrder == Qt::AscendingOrder
                ? left.ordinal < right.ordinal : left.ordinal > right.ordinal;
            return sortOrder == Qt::AscendingOrder ? order < 0 : order > 0;
        });
        std::vector<WinAPIEventRef> ordered;
        ordered.reserve(keyed.size());
        for (auto& row : keyed) ordered.push_back(std::move(row.record));
        return ordered;
    }
    bool matches(const WinAPIEventRef& record) const
    {
        return record && (businessKeyword.isEmpty()
            || record->searchText.contains(businessKeyword, Qt::CaseInsensitive)
            || record->value.sourceProcessName.contains(businessKeyword, Qt::CaseInsensitive)
            || record->value.capturedReturnValue.contains(businessKeyword, Qt::CaseInsensitive))
            && (record->value.internalEvent || !eventRules || !eventRules->rejectsApi(record->value.apiText, false))
            && ks::monitor::EventInTimeRange(record, timeRange)
            && (!search.active || ks::ui::MatchTableSearchResultFilterCells(search.query, search.columns,
                [this, &record](int column) {
                    return column >= 0 && column < ks::monitor::ColumnCount
                        ? language.displayText(ks::monitor::EventColumnText(record, column, &callerColumns)) : QString();
                }));
    }
};
