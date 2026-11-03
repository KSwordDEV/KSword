#include "WinAPIEventTableModel.h"
#include "WinAPIEventColumns.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ThemeItemForeground.h"
#include "../UI/TableInteractionSupport.h"
#include "../theme.h"
#include <QBrush>
#include <QElapsedTimer>
#include <QEvent>
#include <QPointer>
#include <QTableView>
#include <algorithm>
#include <thread>

WinAPIEventTableModel::WinAPIEventTableModel(QObject* parent)
    : QAbstractTableModel(parent), m_callerDispatcher(std::make_shared<ks::ui::AsyncUiDispatcher>(this)), m_filterOperation(new ks::ui::AsyncOperation(this))
{
    m_captureTimer.setSingleShot(true); m_applyTimer.setSingleShot(true);
    m_callerTimer.setInterval(40);
    connect(&m_callerTimer, &QTimer::timeout, this, [this]() { pumpCallerSnapshots(); });
    connect(&m_captureTimer, &QTimer::timeout, this, [this]() { captureFilterRows(); });
    connect(&m_applyTimer, &QTimer::timeout, this, [this]() { applyFilterRows(); });
    if (parent) parent->installEventFilter(this);
}
WinAPIEventTableModel::~WinAPIEventTableModel() { close(); }
void WinAPIEventTableModel::close()
{
    m_closed = true; ++m_filterRevision; m_captureTimer.stop(); m_applyTimer.stop();
    m_callerDispatcher->close();
    stopCallerSnapshots();
    m_filterOperation->close(); filterStateChanged = {};
}
int WinAPIEventTableModel::rowCount(const QModelIndex& parent) const
{ return parent.isValid() ? 0 : static_cast<int>(m_rows.size()); }
int WinAPIEventTableModel::columnCount(const QModelIndex& parent) const
{ return parent.isValid() ? 0 : ks::monitor::ColumnCount; }
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
    if (!index.isValid() || !record || index.column() < 0 || index.column() >= ks::monitor::ColumnCount) return {};
    const auto& row = record->value;
    if (role == SortRole) {
        const auto value = ks::monitor::EventSortValue(record, index.column(), &m_callerColumns);
        return value.metaType().id() == QMetaType::QString ? QVariant(ks::i18n::sourceText(value.toString())) : value;
    }
    if (role == AcceptedRole) return m_rows[static_cast<std::size_t>(index.row())].accepted;
    if (role == Qt::BackgroundRole && index.column() == ks::monitor::Duration && row.durationCaptured) {
        const auto ticks = row.duration100ns; // 10,000 ticks per millisecond.
        const int level = ticks < 10 ? 0 : ticks < 100 ? 1 : ticks < 1000 ? 2 : ticks < 10000 ? 3 : 4;
        QColor color = KswordTheme::PrimaryAccentColor();
        color.setAlpha(20 + level * 22);
        return QBrush(color);
    }
    if (role == Qt::UserRole && index.column() == 0) return record->searchText;
    if (role == ks::ui::kThemeItemForegroundRole)
    {
        if (row.internalEvent && (index.column() == 1 || index.column() == 2)) return int(ks::ui::ItemForegroundRole::Info);
        if (!row.internalEvent && row.resultKnown && row.resultText != QStringLiteral("OK") && index.column() == 3)
            return int(ks::ui::ItemForegroundRole::Error);
        return {};
    }
    if (role == Qt::ToolTipRole && index.column() == ks::monitor::RelativeTime)
        return QStringLiteral("相对于本会话首次采集的业务事件；系统时钟调整或事件乱序可能出现负值。");
    if (role != Qt::DisplayRole && role != Qt::ToolTipRole) return {};
    return ks::i18n::sourceText(ks::monitor::EventColumnText(record, index.column(), &m_callerColumns));
}
void WinAPIEventTableModel::setCallerSnapshot(const WinAPIEventRef& record, const ks::winapi_monitor::CallerSnapshot& snapshot)
{
    const int row = storeCallerSnapshot(record, snapshot);
    if (row >= 0) emit dataChanged(index(row, ks::monitor::CallerModule), index(row, ks::monitor::MemoryKind), {Qt::DisplayRole, SortRole});
}
int WinAPIEventTableModel::storeCallerSnapshot(const WinAPIEventRef& record, const ks::winapi_monitor::CallerSnapshot& snapshot)
{
    using ks::winapi_monitor::CallerSnapshotStatus;
    if (!record || rowForRecord(record) < 0 || snapshot.status != CallerSnapshotStatus::Available
        || snapshot.request.generation != record->generation || snapshot.request.sequence != record->sequence
        || snapshot.request.pid != record->value.sourcePid || !snapshot.request.creationTime100ns
        || snapshot.request.creationTime100ns != record->value.sourceCreationTime100ns) return -1;
    bool addressOk = false;
    const auto address = ks::monitor::EventColumnText(record, ks::monitor::CallerAddress).toULongLong(&addressOk, 16);
    if (!addressOk || !address || snapshot.request.address != address) return -1;
    const int row = rowForRecord(record);
    QString module = QString::fromStdWString(snapshot.mappedPath);
    if (!module.isEmpty()) module = module.section(QChar('\\'), -1).section(QChar('/'), -1);
    QString kind;
    if (snapshot.state != MEM_COMMIT) kind = QStringLiteral("uncommitted");
    else if (snapshot.type == MEM_IMAGE) kind = QStringLiteral("image");
    else if (snapshot.type == MEM_PRIVATE) kind = QStringLiteral("private");
    else if (snapshot.type == MEM_MAPPED) kind = QStringLiteral("mapped");
    else kind = QStringLiteral("unknown");
    const auto existing = m_callerColumns.find(record.get());
    if (existing != m_callerColumns.end() && existing->second.observedTime100ns > snapshot.observedTime100ns) return -1;
    const bool changed = existing == m_callerColumns.end() || existing->second.module != module || existing->second.memoryKind != kind;
    m_callerColumns[record.get()] = {std::move(module), std::move(kind), snapshot.observedTime100ns};
    return changed ? row : -1;
}
void WinAPIEventTableModel::pumpCallerSnapshots()
{
    using Resolver = ks::winapi_monitor::CallerSnapshotResolver;
    if (m_closed) { m_callerTimer.stop(); return; }
    int first = -1, last = -1;
    if (m_callerResolver) {
        for (const auto& snapshot : m_callerResolver->drain()) {
            const auto found = m_callerRequests.find(snapshot.request.requestId);
            if (found == m_callerRequests.end()) continue;
            const auto record = found->second.lock();
            m_callerRequests.erase(found);
            const int row = storeCallerSnapshot(record, snapshot);
            if (row >= 0) { if (first < 0 || row < first) first = row; if (row > last) last = row; }
        }
    }
    if (first >= 0) emit dataChanged(index(first, ks::monitor::CallerModule), index(last, ks::monitor::MemoryKind), {Qt::DisplayRole, SortRole});
    if (m_callerResolver && m_callerResolver->isStopping()) { m_callerTimer.stop(); return; }
    m_callerCursor = std::max(m_callerCursor, m_firstOrdinal);
    QElapsedTimer budget; budget.start();
    while (m_callerCursor < m_nextOrdinal && m_callerRequests.size() < Resolver::ResultCapacity && budget.elapsed() < 2) {
        const auto record = recordAt(static_cast<int>(m_callerCursor - m_firstOrdinal));
        if (!record || m_callerColumns.find(record.get()) != m_callerColumns.end()
            || !record->generation || !record->sequence || !record->value.sourcePid || !record->value.sourceCreationTime100ns) {
            ++m_callerCursor; continue;
        }
        bool ok = false;
        const auto address = ks::monitor::EventColumnText(record, ks::monitor::CallerAddress).toULongLong(&ok, 16);
        if (!ok || !address) { ++m_callerCursor; continue; }
        if (!m_callerResolver) {
            try {
                auto resolver = std::make_shared<Resolver>();
                std::weak_ptr<Resolver> weak = resolver;
                const auto dispatcher = m_callerDispatcher;
                const QPointer<WinAPIEventTableModel> guard(this);
                auto lease = ks::ui::AsyncCleanupRegistry::global().acquire([weak, dispatcher, guard] {
                    if (auto value = weak.lock()) value->requestStop();
                    dispatcher->post([guard] { if (guard) guard->stopCallerSnapshots(); });
                });
                if (!lease) { resolver->stop(); m_callerTimer.stop(); return; }
                m_callerResolver = std::move(resolver); m_callerLease = std::move(lease);
            } catch (...) { m_callerTimer.stop(); return; }
        }
        const auto requestId = ++m_callerRequestId;
        const ks::winapi_monitor::CallerSnapshotRequest request{record->generation, record->sequence,
            record->value.sourcePid, record->value.sourceCreationTime100ns, address, requestId};
        m_callerRequests.emplace(requestId, record);
        const auto submitted = m_callerResolver->submit(request);
        if (submitted != Resolver::SubmitStatus::Accepted) {
            m_callerRequests.erase(requestId);
            if (submitted == Resolver::SubmitStatus::Invalid) { ++m_callerCursor; continue; }
            if (submitted == Resolver::SubmitStatus::Stopped || submitted == Resolver::SubmitStatus::ResourceFailure) m_callerTimer.stop();
            return;
        }
        ++m_callerCursor;
    }
    if (m_callerCursor >= m_nextOrdinal && m_callerRequests.empty()) m_callerTimer.stop();
}
void WinAPIEventTableModel::stopCallerSnapshots()
{
    m_callerTimer.stop(); m_callerRequests.clear();
    m_callerCursor = m_firstOrdinal;
    auto resolver = std::move(m_callerResolver); auto lease = std::move(m_callerLease);
    if (!resolver) return;
    resolver->requestStop();
    try { std::thread([resolver, lease] { resolver->stop(); }).detach(); }
    catch (...) { resolver->stop(); }
}
QVariant WinAPIEventTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role != Qt::DisplayRole) return {};
    if (orientation == Qt::Vertical) return QString::number(m_firstOrdinal + static_cast<std::uint64_t>(section) + 1);
    static const QStringList headers{QStringLiteral("时间"), QStringLiteral("分类"), QStringLiteral("API"),
        QStringLiteral("状态码"), QStringLiteral("PID/TID"), QStringLiteral("序号"), QStringLiteral("目标模块"),
        QStringLiteral("PID"), QStringLiteral("TID"), QStringLiteral("参数摘要"), QStringLiteral("返回值"),
        QStringLiteral("耗时"), QStringLiteral("调用者模块"), QStringLiteral("调用者地址"), QStringLiteral("内存归属"),
        QStringLiteral("事件阶段"), QStringLiteral("关联 ID"), QStringLiteral("采集方式"), QStringLiteral("时间(100ns)"),
        QStringLiteral("进程名"), QStringLiteral("相对时间"), QStringLiteral("详情")};
    return section >= 0 && section < headers.size() ? ks::i18n::sourceText(headers[section]) : QVariant{};
}
void WinAPIEventTableModel::append(const std::vector<WinAPIEventRef>& records)
{
    if (records.empty()) return;
    beginInsertRows({}, rowCount(), rowCount() + static_cast<int>(records.size()) - 1);
    for (const auto& record : records)
    {
        m_ordinals.emplace(record.get(), m_nextOrdinal++);
        m_rows.push_back({record, (m_keyword.isEmpty() || (record->searchText.contains(m_keyword, Qt::CaseInsensitive) || record->value.sourceProcessName.contains(m_keyword, Qt::CaseInsensitive) || record->value.capturedReturnValue.contains(m_keyword, Qt::CaseInsensitive)))
            && (record->value.internalEvent || !m_rules || !m_rules->rejectsApi(record->value.apiText, false))
            && ks::monitor::EventInTimeRange(record, m_timeRange)});
    }
    endInsertRows();
    if (!m_callerTimer.isActive()) m_callerTimer.start();
}
void WinAPIEventTableModel::trimFront(int count)
{
    count = std::min(count, rowCount()); if (count <= 0) return;
    auto retired = std::make_shared<std::deque<Row>>();
    beginRemoveRows({}, 0, count - 1);
    for (int i = 0; i < count; ++i)
    {
        m_ordinals.erase(m_rows.front().record.get());
        m_callerColumns.erase(m_rows.front().record.get());
        retired->push_back(std::move(m_rows.front())); m_rows.pop_front(); ++m_firstOrdinal;
    }
    endRemoveRows();
    QThreadPool::globalInstance()->start([retired = std::move(retired)]() {});
}
void WinAPIEventTableModel::clear()
{
    m_callerColumns.clear();
    ++m_filterRevision; m_filterOperation->cancel(); m_captureTimer.stop(); m_applyTimer.stop();
    m_filterWork.reset(); m_filterMatches.reset(); m_filterPending = false; m_filterFailed = false;
    auto retired = std::make_shared<std::deque<Row>>();
    auto retiredIds = std::make_shared<decltype(m_ordinals)>();
    beginResetModel(); retired->swap(m_rows); retiredIds->swap(m_ordinals); m_firstOrdinal = m_nextOrdinal; endResetModel();
    m_callerCursor = m_firstOrdinal;
    QThreadPool::globalInstance()->start([retired = std::move(retired), retiredIds = std::move(retiredIds)]() {});
    notifyFilterState();
}
void WinAPIEventTableModel::setKeyword(QString keyword)
{
    keyword = keyword.trimmed(); if (m_closed || (keyword == m_keyword && !m_filterFailed)) return;
    m_keyword = std::move(keyword); ++m_filterRevision; m_filterOperation->cancel(); m_applyTimer.stop();
    m_filterMatches.reset(); m_filterWork = std::make_shared<FilterWork>(); m_filterWork->keyword = m_keyword; m_filterWork->rules = m_rules; m_filterWork->timeRange = m_timeRange;
    m_filterBegin = m_filterCursor = m_firstOrdinal; m_filterEnd = m_nextOrdinal; m_filterPending = true; m_filterFailed = false;
    m_captureTimer.start(0); notifyFilterState();
}
void WinAPIEventTableModel::setEventRules(std::shared_ptr<const ks::monitor::WinAPIFilterSnapshot> rules)
{
    m_rules = std::move(rules);
    // Force the existing bounded asynchronous scan even if the text did not change.
    m_filterFailed = true;
    setKeyword(m_keyword);
}
void WinAPIEventTableModel::setTimeRange(bool enabled, std::uint64_t first, std::uint64_t last)
{
    if (first > last) std::swap(first, last);
    if (m_closed || (m_timeRange.enabled == enabled && (!enabled || (m_timeRange.first == first && m_timeRange.last == last)))) return;
    m_timeRange = {enabled, first, last};
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
                result->emplace_back(ordinal, (work->keyword.isEmpty() || (row->searchText.contains(work->keyword, Qt::CaseInsensitive) || row->value.sourceProcessName.contains(work->keyword, Qt::CaseInsensitive) || row->value.capturedReturnValue.contains(work->keyword, Qt::CaseInsensitive)))
                    && (row->value.internalEvent || !work->rules || !work->rules->rejectsApi(row->value.apiText, false))
                    && ks::monitor::EventInTimeRange(row, work->timeRange));
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
    if (first >= 0) emit dataChanged(index(first, 0), index(last, ks::monitor::ColumnCount - 1), {AcceptedRole});
    if (m_filterApplyCursor < m_filterMatches->size()) m_applyTimer.start(0);
    else { m_filterMatches.reset(); m_filterPending = false; }
    notifyFilterState();
}
void WinAPIEventTableModel::notifyFilterState() { if (filterStateChanged) filterStateChanged(); }
float WinAPIEventTableModel::filterProgress() const
{
    if (!m_filterPending) return 100.0f;
    if (m_filterWork) {
        const auto total = m_filterEnd - m_filterBegin;
        return total ? 40.0f * float(std::min(m_filterCursor, m_filterEnd) - m_filterBegin) / float(total) : 40.0f;
    }
    if (!m_filterMatches) return 40.0f; // Background matching has no determinate progress.
    return m_filterMatches->empty() ? 99.0f : 60.0f + 39.0f * float(m_filterApplyCursor) / float(m_filterMatches->size());
}
bool WinAPIEventTableModel::eventFilter(QObject* watched, QEvent* event)
{
    if (watched == parent() && event->type() == QEvent::Show && m_filterMatches) m_applyTimer.start(0);
    return QAbstractTableModel::eventFilter(watched, event);
}
