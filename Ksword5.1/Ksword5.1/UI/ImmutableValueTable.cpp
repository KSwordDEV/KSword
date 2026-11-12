#include "./KeyboardItemActivation.h"
#include "ImmutableValueTable.h"
#include "TableRowFilterSupport.h"
#include "TableInteractionSupport.h"
#include "TableCompleteExport.h"
#include <QEvent>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QPointer>
#include <QPromise>
#include <QRunnable>
#include <QShowEvent>
#include <QThreadPool>
#include <atomic>
#include <tuple>

namespace ks::ui
{
    namespace
    {
        template<typename... Values> void retire(Values... values) noexcept
        {
            // The queued closure owns its values even if a queue is cleared. Only an
            // allocation/scheduling exception falls back to immediate destruction.
            try
            {
                auto retired = std::make_tuple(std::move(values)...);
                auto task = std::unique_ptr<QRunnable>(QRunnable::create([retired = std::move(retired)] {}));
                QThreadPool::globalInstance()->start(task.get());
                task.release();
            }
            catch (...) {}
        }
        struct Prepared
        {
            ImmutableTableViewValues projection;
            QString error;
        };
        using PreparedValue = std::shared_ptr<const Prepared>;
    }
    struct ImmutableValueTable::State
    {
        QVector<ImmutableTableHeader> headers;
        ImmutableValueTableModel* model = nullptr;
        SourceFactory factory;
        ImmutableTableSource source;
        ImmutableTableViewValues pendingProjection;
        QPointer<QFutureWatcher<PreparedValue>> watcher;
        std::shared_ptr<std::atomic<quint64>> revision = std::make_shared<std::atomic<quint64>>(0);
        quint64 dataRevision = 0, sourceRevision = 0, contentRevision = 0, notifiedContent = 0, pendingRevision = 0;
        QString query, currentKey;
        QSet<QString> selectedKeys;
        std::function<bool(const ImmutableTableRow&)> accepts;
        int currentColumn = 0, sortColumn = -1;
        Qt::SortOrder sortOrder = Qt::AscendingOrder;
        bool keepPreviousInteractive = false;
        bool pending = false, running = false, applying = false, notifySelection = false, publishing = false, deferred = false;
    };

    ImmutableValueTable::ImmutableValueTable(QWidget* parent, QVector<ImmutableTableHeader> headers)
        : TableActionTableView(parent), m_state(std::make_unique<State>())
    {
        auto& state = *m_state;
        state.headers = std::move(headers);
        state.model = new ImmutableValueTableModel(static_cast<int>(state.headers.size()), [this](int section) {
            const auto& header = m_state->headers[section];
            return header.key.isEmpty() ? ks::i18n::sourceText(header.source) : ks::i18n::contextText(header.key, header.source);
        }, this);
        setModel(state.model);
        RegisterCompleteExportTableProducer(this, [this] {
            CompleteExportPublishedTable published;
            const auto projection = m_state->model->projection();
            published.values = projection;
            published.sourceIdentity = QStringLiteral("immutable-value-table:%1")
                .arg(reinterpret_cast<quintptr>(this), 0, 16);
            published.sourceVersion = m_state->model->version();
            published.rows = projection ? static_cast<int>(projection->rows.size()) : 0;
            published.columns = columnCount();
            published.cell = [](const void* value, int row, int column) {
                return ImmutableTableDisplayCell(*static_cast<const ImmutableTableProjection*>(value), row, column);
            };
            return published;
        });
        setEditTriggers(QAbstractItemView::NoEditTriggers);
        setSelectionBehavior(QAbstractItemView::SelectRows);
        setSelectionMode(QAbstractItemView::SingleSelection);
        setWordWrap(false);
        horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        horizontalHeader()->setStretchLastSection(true);
        verticalHeader()->hide();
        SetTableRowFilterBusinessOwnership(this, TableRowFilterBusinessOwnership::ExclusiveSharedIdentity);
        ks::i18n::LanguageManager::instance().setRuntimeTranslationManaged(this);
        state.model->sortRequested = [this](int column, Qt::SortOrder order) {
            m_state->sortColumn = column; m_state->sortOrder = order; request(false);
        };
        connect(selectionModel(), &QItemSelectionModel::currentChanged, this, [this](const QModelIndex& current) {
            auto& state = *m_state;
            if (state.applying) return;
            const auto* row = state.model->rowAt(current.row());
            state.currentKey = row ? row->key : QString();
            if (current.isValid()) state.currentColumn = current.column();
            const QPointer<ImmutableValueTable> alive(this);
            if (currentRowChanged) currentRowChanged();
            if (alive && m_state->keepPreviousInteractive && isPreparing()) request(false);
        });
        connect(selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] {
            auto& state = *m_state;
            if (state.applying) return;
            state.selectedKeys.clear();
            for (const auto& index : selectionModel()->selectedRows())
                if (const auto* row = state.model->rowAt(index.row())) state.selectedKeys.insert(row->key);
            if (state.keepPreviousInteractive && isPreparing()) request(false);
        });
        ks::ui::InstallKeyboardItemActivation(this);
        connect(this, &QTableView::doubleClicked, this, [this](const QModelIndex& index) {
            if (rowDoubleClicked) rowDoubleClicked(index.row());
        });
        horizontalHeader()->setSortIndicator(-1, Qt::AscendingOrder);
        setSortingEnabled(true);
    }

    ImmutableValueTable::~ImmutableValueTable()
    {
        auto& state = *m_state;
        ++*state.revision;
        if (state.watcher)
        {
            disconnect(state.watcher, nullptr, this, nullptr);
            if (state.watcher->isFinished() && state.watcher->future().resultCount()) retire(state.watcher->result());
            state.watcher->setFuture({});
        }
        state.applying = true;
        state.model->sortRequested = {};
        auto* model = state.model;
        auto projection = model->take();
        disconnect(selectionModel(), nullptr, this, nullptr);
        setModel(nullptr);
        delete model;
        state.model = nullptr;
        retire(std::move(state.factory), std::move(state.accepts), std::move(state.selectedKeys), std::move(state.source), std::move(state.pendingProjection), std::move(projection));
    }

    void ImmutableValueTable::setSourceFactory(SourceFactory factory)
    {
        retire(std::move(m_state->factory));
        m_state->factory = std::move(factory);
        ++m_state->contentRevision;
        request(true);
    }
    void ImmutableValueTable::clearRows()
    {
        auto& state = *m_state;
        const QPointer<ImmutableValueTable> alive(this);
        state.currentKey.clear();
        state.selectedKeys.clear();
        retire(std::move(state.source), std::move(state.pendingProjection));
        setSourceFactory([](const auto&) { return MakeImmutableTableSource({}); });
        if (!alive) return;
        if (state.publishing) return;
        state.publishing = true;
        state.applying = true;
        retire(state.model->replace({}));
        if (!alive) return;
        state.applying = false;
        state.publishing = false;
        if (state.pendingProjection && isVisible())
        {
            auto pending = std::move(state.pendingProjection);
            publish(std::move(pending), state.pendingRevision);
            if (!alive) return;
        }
        startPending();
    }
    void ImmutableValueTable::setKeepPreviousProjectionInteractive(bool keep)
    {
        m_state->keepPreviousInteractive = keep;
        if (keep) setEnabled(true);
    }
    void ImmutableValueTable::setQuery(const QString& query)
    {
        if (query == m_state->query) return;
        m_state->query = query;
        request(false);
    }
    void ImmutableValueTable::setRowPredicate(std::function<bool(const ImmutableTableRow&)> accepts)
    {
        retire(std::move(m_state->accepts));
        m_state->accepts = std::move(accepts);
        request(false);
    }
    int ImmutableValueTable::rowCount() const { return m_state->model->rowCount(); }
    int ImmutableValueTable::columnCount() const { return m_state->model->columnCount(); }
    int ImmutableValueTable::currentRow() const { return !m_state->currentKey.isEmpty() && currentIndex().isValid() ? currentIndex().row() : -1; }
    QVariant ImmutableValueTable::cell(int row, int column, int role) const { return m_state->model->index(row, column).data(role); }
    QVariant ImmutableValueTable::currentCell(int column, int role) const { return cell(currentRow(), column, role); }
    QString ImmutableValueTable::rowKey(int row) const { const auto* value = m_state->model->rowAt(row); return value ? value->key : QString(); }
    void ImmutableValueTable::selectRow(int row, int column) { selectKey(rowKey(row), column); }
    void ImmutableValueTable::selectKey(const QString& key, int column)
    {
        m_state->notifySelection = m_state->notifySelection || m_state->currentKey != key;
        m_state->currentKey = key;
        m_state->currentColumn = column;
        m_state->selectedKeys = key.isEmpty() ? QSet<QString>{} : QSet<QString>{key};
        request(false);
    }
    ImmutableTableSource ImmutableValueTable::canonicalSource() const { return m_state->source; }
    bool ImmutableValueTable::isPreparing() const { return m_state->running || m_state->pending || m_state->deferred || static_cast<bool>(m_state->pendingProjection); }

    void ImmutableValueTable::request(bool formatting)
    {
        auto& state = *m_state;
        ++*state.revision;
        if (formatting) ++state.dataRevision;
        state.pending = true;
        state.deferred = false;
        const QPointer<ImmutableValueTable> alive(this);
        if (!state.keepPreviousInteractive) setEnabled(false);
        if (!alive) return;
        retire(std::move(state.pendingProjection));
        startPending();
    }

    void ImmutableValueTable::startPending()
    {
        auto& state = *m_state;
        if (state.running || !state.pending) return;
        const bool formatting = state.dataRevision != state.sourceRevision;
        if (!isVisible() && !formatting) return;
        state.running = true; state.pending = false;
        const auto revision = state.revision->load(), dataRevision = state.dataRevision;
        const auto ticket = state.revision;
        const auto factory = state.factory;
        const auto source = state.source;
        const auto query = state.query, currentKey = state.currentKey;
        const auto selectedKeys = state.selectedKeys;
        const auto accepts = state.accepts;
        const int sortColumn = state.sortColumn;
        const auto sortOrder = state.sortOrder;
        const auto translator = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
        auto promise = std::make_shared<QPromise<PreparedValue>>();
        promise->start();
        auto* watcher = new QFutureWatcher<PreparedValue>(this);
        state.watcher = watcher;
        connect(watcher, &QFutureWatcher<PreparedValue>::finished, this, [this, watcher, revision, dataRevision] {
            // Resetting to the default (finished, result-less) future can post
            // another finished notification before deleteLater is delivered.
            disconnect(watcher, nullptr, this, nullptr);
            auto result = watcher->future().resultCount() > 0 ? watcher->result() : PreparedValue{};
            const QPointer<ImmutableValueTable> completionOwner(this);
            watcher->setFuture({});
            if (!completionOwner) { retire(std::move(result)); return; }
            watcher->deleteLater();
            auto& state = *m_state;
            state.watcher = nullptr; state.running = false;
            if (result && dataRevision == state.dataRevision && result->projection)
            {
                retire(std::move(state.source));
                state.source = result->projection->source;
                state.sourceRevision = dataRevision;
            }
            const QPointer<ImmutableValueTable> alive(this);
            if (revision == state.revision->load())
            {
                const QString error = result ? result->error : QStringLiteral("后台任务发生异常。");
                if (!error.isEmpty())
                {
                    // A failed replacement keeps the previous projection usable. Enabling
                    // may synchronously close the owner or request newer data.
                    setEnabled(true);
                    if (alive && revision == m_state->revision->load() && preparationFailed)
                        preparationFailed(ks::i18n::sourceText(error));
                }
                else if (result->projection)
                {
                    if (isVisible()) publish(result->projection, revision);
                    else { state.pendingProjection = result->projection; state.pendingRevision = revision; }
                }
            }
            retire(std::move(result));
            if (alive) startPending();
        });
        watcher->setFuture(promise->future());
        QThreadPool::globalInstance()->start(QRunnable::create([promise, factory, source, formatting, translator,
            query, sortColumn, sortOrder, currentKey, selectedKeys, accepts, revision, ticket] {
            auto result = std::make_shared<Prepared>();
            try
            {
                const auto values = formatting && factory ? factory(translator) : source;
                if (formatting && factory && !values)
                {
                    // 工厂主动返回空数据源与后台异常分开报告，避免伪装成通用异常。
                    result->error = QStringLiteral("表格数据源工厂返回空数据源。");
                }
                else
                {
                    // A prepared source may be reused even if only the query became obsolete.
                    result->projection = ProjectImmutableTable(values, query, sortColumn, sortOrder, currentKey,
                        [ticket, revision] { return ticket->load() != revision; }, selectedKeys, accepts);
                    if (!result->projection)
                    {
                        auto prepared = std::make_shared<ImmutableTableProjection>();
                        prepared->source = values;
                        result->projection = std::move(prepared);
                    }
                }
                // Allocate the independent retirement alias on worker, before GUI publication.
                if (result->projection) result->projection = RetainCompleteExportSnapshot(result->projection);
            }
            catch (const std::exception& exception) { result->error = QString::fromUtf8(exception.what()); }
            catch (...) { result->error = QStringLiteral("后台任务发生异常。"); }
            promise->addResult(std::move(result)); promise->finish();
        }));
    }

    void ImmutableValueTable::publish(ImmutableTableViewValues projection, quint64 revision)
    {
        auto& state = *m_state;
        if (revision != state.revision->load()) { retire(std::move(projection)); return; }
        if (state.publishing)
        {
            retire(std::move(state.pendingProjection));
            state.pendingProjection = std::move(projection); state.pendingRevision = revision;
            return;
        }
        const QPointer<ImmutableValueTable> alive(this);
        const bool deferred = DeferTablePresentationIfValueCaptureOpen(this, QStringLiteral("immutable-value-table"), {this},
            [alive, projection, revision] { if (alive) alive->publish(projection, revision); });
        if (!alive) { retire(std::move(projection)); return; }
        state.deferred = deferred;
        if (deferred) return;
        state.publishing = true;
        state.applying = true;
        const int selected = projection->currentRow;
        const QString previousVisibleKey = rowKey(currentIndex().row());
        const QString nextVisibleKey = selected >= 0 ? state.currentKey : QString();
        const bool lost = !state.currentKey.isEmpty()
            && (!projection->source || !projection->source->byKey.contains(state.currentKey));
        retire(state.model->replace(projection, revision));
        if (!alive) { retire(std::move(projection)); return; }
        state.publishing = false;
        if (revision == state.revision->load() && isVisible())
        {
            if (selected >= 0)
            {
                const auto index = state.model->index(selected, state.currentColumn);
                selectionModel()->setCurrentIndex(index, QItemSelectionModel::NoUpdate);
                if (!alive) { retire(std::move(projection)); return; }
                if (revision == state.revision->load() && selectionMode() == QAbstractItemView::SingleSelection)
                    selectionModel()->select(index, QItemSelectionModel::Select | QItemSelectionModel::Rows);
                if (!alive) { retire(std::move(projection)); return; }
            }
            if (revision == state.revision->load() && selectionMode() != QAbstractItemView::SingleSelection)
            {
                QItemSelection selectedRows;
                for (const auto& range : projection->selectedRanges)
                    selectedRows.select(state.model->index(range.first, 0), state.model->index(range.second, columnCount() - 1));
                selectionModel()->select(selectedRows, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                if (!alive) { retire(std::move(projection)); return; }
            }
            if (revision == state.revision->load())
            {
                state.selectedKeys = projection->selectedKeys;
                if (lost) state.currentKey.clear();
                state.applying = false;
                setEnabled(true);
                if (!alive) { retire(std::move(projection)); return; }
                if (revision != state.revision->load())
                {
                    retire(std::move(projection));
                    startPending();
                    return;
                }
                const bool requestedSelectionNotification = std::exchange(state.notifySelection, false);
                const bool notifySelection = lost || previousVisibleKey != nextVisibleKey
                    || requestedSelectionNotification;
                if (notifySelection && currentRowChanged) currentRowChanged();
                if (!alive) { retire(std::move(projection)); return; }
                if (revision == state.revision->load() && state.notifiedContent != state.contentRevision)
                {
                    state.notifiedContent = state.contentRevision;
                    if (sourceReady) sourceReady();
                    if (!alive) { retire(std::move(projection)); return; }
                }
            }
        }
        else if (revision == state.revision->load())
        { state.pendingProjection = projection; state.pendingRevision = revision; }
        state.applying = false;
        retire(std::move(projection));
        if (state.pendingProjection && isVisible())
        {
            auto pending = std::move(state.pendingProjection);
            const auto pendingRevision = state.pendingRevision;
            publish(std::move(pending), pendingRevision);
            if (!alive) return;
        }
        startPending();
    }

    void ImmutableValueTable::showEvent(QShowEvent* event)
    {
        const QPointer<ImmutableValueTable> alive(this);
        TableActionTableView::showEvent(event);
        if (!alive) return;
        if (m_state->pendingProjection)
        { auto projection = std::move(m_state->pendingProjection); publish(std::move(projection), m_state->pendingRevision); }
        if (alive) startPending();
    }
    void ImmutableValueTable::changeEvent(QEvent* event)
    {
        const QPointer<ImmutableValueTable> changeOwner(this);
        TableActionTableView::changeEvent(event);
        if (!changeOwner) return;
        if (event->type() == QEvent::LanguageChange)
        {
            const QPointer<ImmutableValueTable> alive(this);
            m_state->model->languageChanged();
            if (alive) request(true);
        }
    }
}
