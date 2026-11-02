#include "WinAPIEventTableModel.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ThemeItemForeground.h"
#include "../UI/TableInteractionSupport.h"
#include <QElapsedTimer>
#include <QEvent>
#include <QPointer>
#include <QTableView>
#include <algorithm>

WinAPIEventTableModel::WinAPIEventTableModel(QObject* parent)
    : QAbstractTableModel(parent), m_filterOperation(new ks::ui::AsyncOperation(this))
{
    m_captureTimer.setSingleShot(true); m_applyTimer.setSingleShot(true);
    connect(&m_captureTimer, &QTimer::timeout, this, [this]() { captureFilterRows(); });
    connect(&m_applyTimer, &QTimer::timeout, this, [this]() { applyFilterRows(); });
    if (parent) parent->installEventFilter(this);
}
WinAPIEventTableModel::~WinAPIEventTableModel() { close(); }
void WinAPIEventTableModel::close()
{
    m_closed = true; ++m_filterRevision; m_captureTimer.stop(); m_applyTimer.stop();
    m_filterOperation->close(); filterStateChanged = {};
}
int WinAPIEventTableModel::rowCount(const QModelIndex& parent) const
{ return parent.isValid() ? 0 : static_cast<int>(m_rows.size()); }
int WinAPIEventTableModel::columnCount(const QModelIndex& parent) const
{ return parent.isValid() ? 0 : 6; }
WinAPIEventRef WinAPIEventTableModel::recordAt(int row) const
{ return row >= 0 && row < rowCount() ? m_rows[static_cast<std::size_t>(row)].record : WinAPIEventRef{}; }
int WinAPIEventTableModel::rowForRecord(const WinAPIEventRef& record) const
{
    const auto found = m_ordinals.find(record.get());
    return found == m_ordinals.end() ? -1 : static_cast<int>(found->second - m_firstOrdinal);
}
QVariant WinAPIEventTableModel::data(const QModelIndex& index, int role) const
{
    const auto record = recordAt(index.row());
    if (!index.isValid() || !record || index.column() < 0 || index.column() >= 6) return {};
    const auto& row = record->value;
    if (role == AcceptedRole) return m_rows[static_cast<std::size_t>(index.row())].accepted;
    if (role == Qt::UserRole && index.column() == 0) return record->searchText;
    if (role == ks::ui::kThemeItemForegroundRole)
    {
        if (row.internalEvent && (index.column() == 1 || index.column() == 2)) return int(ks::ui::ItemForegroundRole::Info);
        if (!row.internalEvent && row.resultKnown && row.resultText != QStringLiteral("OK") && index.column() == 3)
            return int(ks::ui::ItemForegroundRole::Error);
        return {};
    }
    if (role != Qt::DisplayRole && role != Qt::ToolTipRole) return {};
    QString text;
    switch (index.column()) {
    case 0: text = row.time100nsText; break;
    case 1: text = row.categoryText; break;
    case 2: text = row.apiText; break;
    case 3: text = row.resultText; break;
    case 4: text = row.pidTidText; break;
    case 5: text = row.detailText; break;
    }
    return ks::i18n::sourceText(text);
}
QVariant WinAPIEventTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole) return {};
    if (orientation == Qt::Vertical) return QString::number(m_firstOrdinal + static_cast<std::uint64_t>(section) + 1);
    static const QStringList headers{QStringLiteral("时间(100ns)"), QStringLiteral("分类"), QStringLiteral("API"),
        QStringLiteral("结果"), QStringLiteral("PID/TID"), QStringLiteral("详情")};
    return section >= 0 && section < headers.size() ? ks::i18n::sourceText(headers[section]) : QVariant{};
}
void WinAPIEventTableModel::append(const std::vector<WinAPIEventRef>& records)
{
    if (records.empty()) return;
    beginInsertRows({}, rowCount(), rowCount() + static_cast<int>(records.size()) - 1);
    for (const auto& record : records)
    {
        m_ordinals.emplace(record.get(), m_nextOrdinal++);
        m_rows.push_back({record, (m_keyword.isEmpty() || record->searchText.contains(m_keyword, Qt::CaseInsensitive))
            && (record->value.internalEvent || !m_rules || !m_rules->rejectsApi(record->value.apiText, false))});
    }
    endInsertRows();
}
void WinAPIEventTableModel::trimFront(int count)
{
    count = std::min(count, rowCount()); if (count <= 0) return;
    auto retired = std::make_shared<std::deque<Row>>();
    beginRemoveRows({}, 0, count - 1);
    for (int i = 0; i < count; ++i)
    {
        m_ordinals.erase(m_rows.front().record.get());
        retired->push_back(std::move(m_rows.front())); m_rows.pop_front(); ++m_firstOrdinal;
    }
    endRemoveRows();
    QThreadPool::globalInstance()->start([retired = std::move(retired)]() {});
}
void WinAPIEventTableModel::clear()
{
    ++m_filterRevision; m_filterOperation->cancel(); m_captureTimer.stop(); m_applyTimer.stop();
    m_filterWork.reset(); m_filterMatches.reset(); m_filterPending = false; m_filterFailed = false;
    auto retired = std::make_shared<std::deque<Row>>();
    auto retiredIds = std::make_shared<decltype(m_ordinals)>();
    beginResetModel(); retired->swap(m_rows); retiredIds->swap(m_ordinals); m_firstOrdinal = m_nextOrdinal; endResetModel();
    QThreadPool::globalInstance()->start([retired = std::move(retired), retiredIds = std::move(retiredIds)]() {});
    notifyFilterState();
}
void WinAPIEventTableModel::setKeyword(QString keyword)
{
    keyword = keyword.trimmed(); if (m_closed || (keyword == m_keyword && !m_filterFailed)) return;
    m_keyword = std::move(keyword); ++m_filterRevision; m_filterOperation->cancel(); m_applyTimer.stop();
    m_filterMatches.reset(); m_filterWork = std::make_shared<FilterWork>(); m_filterWork->keyword = m_keyword; m_filterWork->rules = m_rules;
    m_filterCursor = m_firstOrdinal; m_filterEnd = m_nextOrdinal; m_filterPending = true; m_filterFailed = false;
    m_captureTimer.start(0); notifyFilterState();
}
void WinAPIEventTableModel::setEventRules(std::shared_ptr<const ks::monitor::WinAPIFilterSnapshot> rules)
{
    m_rules = std::move(rules);
    // Force the existing bounded asynchronous scan even if the text did not change.
    m_filterFailed = true;
    setKeyword(m_keyword);
}
void WinAPIEventTableModel::captureFilterRows()
{
    if (m_closed || !m_filterWork) return;
    QElapsedTimer budget; budget.start(); int count = 0;
    m_filterCursor = std::max(m_filterCursor, m_firstOrdinal);
    while (m_filterCursor < m_filterEnd && count++ < 2048 && budget.elapsed() < 4)
    {
        const auto row = recordAt(static_cast<int>(m_filterCursor - m_firstOrdinal));
        if (row) m_filterWork->rows.emplace_back(m_filterCursor, row);
        ++m_filterCursor;
    }
    if (m_filterCursor < m_filterEnd) { m_captureTimer.start(0); return; }
    const auto revision = m_filterRevision;
    auto request = std::move(m_filterWork);
    m_filterOperation->submit<std::shared_ptr<FilterWork>, std::shared_ptr<const Matches>>(std::move(request),
        [](const std::shared_ptr<FilterWork>& work, const ks::ui::AsyncOperationToken& token) {
            auto result = std::make_shared<Matches>(); result->reserve(work->rows.size());
            for (const auto& [ordinal, row] : work->rows) {
                if (token.isCanceled()) break;
                result->emplace_back(ordinal, (work->keyword.isEmpty() || row->searchText.contains(work->keyword, Qt::CaseInsensitive))
                    && (row->value.internalEvent || !work->rules || !work->rules->rejectsApi(row->value.apiText, false)));
            }
            return std::shared_ptr<const Matches>(std::move(result));
        },
        [this, revision](const std::shared_ptr<const Matches>& result, std::uint64_t) {
            if (m_closed || revision != m_filterRevision) return true;
            m_filterMatches = result; m_filterApplyCursor = 0; m_applyTimer.start(0); return true;
        },
        [this, revision](std::exception_ptr) {
            if (!m_closed && revision == m_filterRevision) { m_filterPending = false; m_filterFailed = true; notifyFilterState(); }
        });
}
void WinAPIEventTableModel::applyFilterRows()
{
    if (m_closed || !m_filterMatches) return;
    const QPointer<WinAPIEventTableModel> guard(this);
    auto* table = qobject_cast<QTableView*>(parent());
    if (table && !table->isVisible()) return;
    if (table && ks::ui::DeferTableUiCommitIfContextMenuOpen(this, QStringLiteral("winapi-filter-rows"), {table},
        [guard]() { if (guard) guard->m_applyTimer.start(0); })) return;
    QElapsedTimer budget; budget.start(); int count = 0, first = -1, last = -1;
    while (m_filterApplyCursor < m_filterMatches->size() && count++ < 512 && budget.elapsed() < 4)
    {
        const auto [ordinal, accepted] = (*m_filterMatches)[m_filterApplyCursor++];
        if (ordinal < m_firstOrdinal || ordinal >= m_nextOrdinal) continue;
        const int row = static_cast<int>(ordinal - m_firstOrdinal);
        if (m_rows[static_cast<std::size_t>(row)].accepted == accepted) continue;
        m_rows[static_cast<std::size_t>(row)].accepted = accepted;
        if (first < 0) first = row; last = row;
    }
    if (first >= 0) emit dataChanged(index(first, 0), index(last, 5), {AcceptedRole});
    if (m_filterApplyCursor < m_filterMatches->size()) m_applyTimer.start(0);
    else { m_filterMatches.reset(); m_filterPending = false; }
    notifyFilterState();
}
void WinAPIEventTableModel::notifyFilterState() { if (filterStateChanged) filterStateChanged(); }
bool WinAPIEventTableModel::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == parent() && event->type() == QEvent::Show && m_filterMatches) m_applyTimer.start(0);
    return QAbstractTableModel::eventFilter(watched, event);
}
