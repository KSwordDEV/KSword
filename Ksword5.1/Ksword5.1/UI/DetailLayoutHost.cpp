#include "DetailLayoutHost.h"
#include "./DetailDialogChrome.h"

#include "CodeEditorWidget.h"
#include "EmbeddedRowDelegate.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QApplication>
#include <QBoxLayout>
#include <QDialog>
#include <QEvent>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QScreen>
#include <QScopeGuard>
#include <QSplitter>
#include <QTableWidget>
#include <QTableView>
#include <QTableWidgetItem>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QThreadPool>
#include <QVBoxLayout>

#include <algorithm>
#include <utility>

namespace
{
    int visibleTreeColumn(QTreeWidget* tree)
    {
        const auto* header = tree->header();
        for (int visual = 0; visual < header->count(); ++visual)
        {
            const int column = header->logicalIndex(visual);
            const int left = header->sectionViewportPosition(column);
            if (!header->isSectionHidden(column) && left < tree->viewport()->width()
                && left + header->sectionSize(column) > 0) return column;
        }
        return -1;
    }
    // This branch serves actual text documents and logs only.
    void setMirrorText(CodeEditorWidget* target, CodeEditorWidget*, const QString& text)
    {
        if (target && target->text() != text)
        {
            target->setRawText(text); // 相同报告不清空文档、选择和高亮缓存。
        }
    }

    CodeEditorWidget* createReadOnlyInlineEditor(
        QWidget* parentWidget, CodeEditorWidget* source, const QString& detailText)
    {
        auto* textEditor = new CodeEditorWidget(parentWidget);
        textEditor->setReadOnly(true);
        setMirrorText(textEditor, source, detailText);
        // 源行控制几何，报告内容的最小尺寸不传播回整个结果视图。
        textEditor->setMinimumSize(0, 0);
        return textEditor;
    }

}

ks::ui::DetailLayoutHost::DetailLayoutHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget)
    : QObject(ownerWidget),
      m_tableView(tableView),
      m_detailEditor(detailEditor),
      m_ownerWidget(ownerWidget)
{
    initializeConnections();
    scheduleHostUiInitialization();
    m_constructing = false;
}

ks::ui::DetailLayoutHost::DetailLayoutHost(
    QAbstractItemView* tableView,
    CodeEditorWidget* detailEditor,
    QWidget* ownerWidget,
    const DetailPaneBinding& binding)
    : QObject(ownerWidget),
      m_tableView(tableView),
      m_detailEditor(detailEditor),
      m_ownerWidget(ownerWidget)
{
    m_explicitBinding = true;
    bindPanels(binding);
    initializeConnections();
    scheduleHostUiInitialization();
    m_constructing = false;
}

ks::ui::DetailLayoutHost::DetailLayoutHost(
    QAbstractItemView* view, StructuredFieldView* fields, QWidget* owner)
    : QObject(owner), m_tableView(view), m_structuredView(fields), m_ownerWidget(owner)
{
    initializeConnections();
    scheduleHostUiInitialization();
    m_constructing = false;
}

ks::ui::DetailLayoutHost::DetailLayoutHost(
    QAbstractItemView* view, StructuredFieldView* fields, QWidget* owner,
    const DetailPaneBinding& binding)
    : QObject(owner), m_tableView(view), m_structuredView(fields), m_ownerWidget(owner)
{
    m_explicitBinding = true;
    bindPanels(binding);
    initializeConnections();
    scheduleHostUiInitialization();
    m_constructing = false;
}

ks::ui::DetailLayoutHost::~DetailLayoutHost()
{
    // 宿主销毁前恢复行高和页面原 delegate，避免共享视图留下临时包装器。
    clearEmbeddedDetails();
    destroyFloatingWindow();
}

void ks::ui::DetailLayoutHost::initializeHostUi()
{
    ensureManagedSplitter();
    if (!isBound())
    {
        return;
    }

    if (!m_toggleBar.isNull())
    {
        return;
    }

    // 固定宽度按钮不能直接成为纵向 QSplitter 子项，否则它的 maximumWidth 会把整个
    // 分隔器横向尺寸压窄。使用横向可扩展的承载条，只让中间箭头保持紧凑宽度。
    m_toggleBar = new QWidget(m_splitter.data());
    m_toggleBar->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_toggleBar->setMinimumWidth(0);
    m_toggleBar->setMaximumWidth(QWIDGETSIZE_MAX);
    m_toggleBar->setFixedHeight(18);

    QHBoxLayout* toggleLayout = new QHBoxLayout(m_toggleBar.data());
    toggleLayout->setContentsMargins(0, 0, 0, 0);
    toggleLayout->setSpacing(0);
    toggleLayout->addStretch(1);

    m_toggleButton = new QToolButton(m_toggleBar.data());
    m_toggleButton->setAutoRaise(true);
    m_toggleButton->setArrowType(m_bottomExpanded ? Qt::DownArrow : Qt::UpArrow);
    m_toggleButton->setFocusPolicy(Qt::NoFocus);
    m_toggleButton->setFixedSize(44, 18);
    m_toggleButton->setToolTip(ks::i18n::text(
        QStringLiteral("detail.layout.toggle.tooltip"),
        QStringLiteral("展开或收起当前行详情")));
    toggleLayout->addWidget(m_toggleButton.data(), 0, Qt::AlignCenter);
    toggleLayout->addStretch(1);

    // 箭头作为分隔器中间项，折叠时正好停留在表格下沿，展开后位于表格与详情之间。
    m_splitter->insertWidget(1, m_toggleBar.data());
}

void ks::ui::DetailLayoutHost::prepareHostUi()
{
    if (m_constructing || m_preparingHostUi) return;
    const QPointer<DetailLayoutHost> self(this);
    m_preparingHostUi = true;
    const auto finished = qScopeGuard([self]() { if (self) self->m_preparingHostUi = false; });
    if (m_splitter.isNull() || m_detailPane.isNull()) initializeHostUi();
    if (self.isNull()) return;
    if (!m_splitter.isNull() && !m_detailPane.isNull())
    {
        initializeConnections();
        if (self.isNull() || !isBound()) return;
        const QPointer<QSplitter> preparedSplitter = m_splitter;
        const QPointer<QWidget> preparedMainPane = m_tablePane;
        const QPointer<QWidget> preparedDetailPane = m_detailPane;
        // applyScheme advances this generation once for its own scheme change;
        // any other advance means a synchronous callback rebound the host.
        const quint64 generation = m_bindingGeneration;
        const auto previousScheme = m_scheme;
        applyScheme(m_requestedScheme);
        if (self.isNull() || !isBound() || m_splitter != preparedSplitter
            || m_tablePane != preparedMainPane || m_detailPane != preparedDetailPane
            || m_bindingGeneration != generation + (m_scheme != previousScheme ? 1u : 0u)) return;
        const quint64 appliedGeneration = m_bindingGeneration;
        updateEmbeddedEditorGeometries();
        if (self.isNull() || !isBound() || m_bindingGeneration != appliedGeneration
            || m_splitter != preparedSplitter || m_tablePane != preparedMainPane
            || m_detailPane != preparedDetailPane) return;
        // A compatibility wrapper created under an already visible parent is
        // auto-shown later by Qt. Finish only that pending implicit show now;
        // an explicitly hidden or explicitly bound splitter keeps its owner.
        const QPointer<QWidget> parent = m_splitter->parentWidget();
        if (!m_explicitBinding && parent && parent->isVisible() && m_splitter->isHidden()
            && !m_splitter->testAttribute(Qt::WA_WState_ExplicitShowHide))
        {
            if (!applyLayoutStep([this]() { m_splitter->show(); })) return;
            if (parent && parent->layout()
                && !applyLayoutStep([parent]() { if (parent && parent->layout()) parent->layout()->activate(); })) return;
        }
        m_hostUiInitializationScheduled = false;
        ++m_hostUiInitializationGeneration;
    }
}

void ks::ui::DetailLayoutHost::scheduleHostUiInitialization()
{
    // Compatibility hosts also observe their real layout/show boundary. Child
    // construction still only schedules work until the full panels are mounted.
    if (!m_ownerWidget.isNull()) m_ownerWidget->installEventFilter(this);
    if (m_hostUiInitializationScheduled || m_ownerWidget.isNull())
    {
        return;
    }
    m_hostUiInitializationScheduled = true;
    const quint64 generation = ++m_hostUiInitializationGeneration;
    QTimer::singleShot(0, this,
        [this, generation]()
        {
            if (!m_hostUiInitializationScheduled || generation != m_hostUiInitializationGeneration) return;
            m_hostUiInitializationScheduled = false;
            prepareHostUi();
        });
}

// 显式契约只接受完整的两个直接面板；构造期间尚未挂载时留给 queued 重试。
void ks::ui::DetailLayoutHost::ensureManagedSplitter()
{
    if (!m_explicitBinding)
    {
        resolveCompatiblePanels();
        return;
    }
    if (m_requestedSplitter.isNull() || m_requestedMainPane.isNull()
        || m_requestedDetailPane.isNull() || m_tableView.isNull() || (detailWidget() == nullptr))
    {
        return;
    }
    QSplitter* const splitter = m_requestedSplitter.data();
    QWidget* const mainPane = m_requestedMainPane.data();
    QWidget* const detailPane = m_requestedDetailPane.data();
    if (mainPane == detailPane || mainPane->parentWidget() != splitter
        || detailPane->parentWidget() != splitter || splitter->indexOf(mainPane) != 0
        || (splitter->indexOf(detailPane) != 1 && splitter->indexOf(detailPane) != 2)
        || (mainPane != m_tableView && !mainPane->isAncestorOf(m_tableView.data()))
        || (detailPane != detailWidget() && !detailPane->isAncestorOf(detailWidget())))
    {
        return;
    }
    const int expectedCount = m_toggleBar.isNull() ? 2 : 3;
    if (splitter->count() != expectedCount)
    {
        return;
    }
    m_splitter = splitter;
    m_tablePane = mainPane;
    m_detailPane = detailPane;
    detailWidget()->setMinimumHeight(0);
    detailWidget()->setMaximumHeight(QWIDGETSIZE_MAX);
}

void ks::ui::DetailLayoutHost::handleViewClicked(
    const QPersistentModelIndex& sourceIndex)
{
    if (!m_detailsEnabled || !sourceIndex.isValid())
    {
        return;
    }

    observeModel();
    const quint64 generation = m_bindingGeneration;
    switch (m_scheme)
    {
    case ks::settings::DetailDisplayScheme::Embedded:
        // 原页面的选择回调先更新 CodeEditorWidget，本处再把最新文本镜像到行内视图。
        QTimer::singleShot(0, this, [this, sourceIndex, generation]()
            {
                if (generation == m_bindingGeneration
                    && m_scheme == ks::settings::DetailDisplayScheme::Embedded
                    && sourceIndex.isValid() && !m_tableView.isNull()
                    && sourceIndex.model() == m_tableView->model())
                {
                    toggleEmbeddedDetail(sourceIndex.sibling(sourceIndex.row(), 0));
                }
            });
        break;
    case ks::settings::DetailDisplayScheme::Floating:
        QTimer::singleShot(0, this, [this, sourceIndex, generation]()
        {
            if (generation == m_bindingGeneration && sourceIndex.isValid()
                && m_scheme == ks::settings::DetailDisplayScheme::Floating)
            {
                showFloatingWindow();
            }
        });
        break;
    case ks::settings::DetailDisplayScheme::BottomCollapsed:
        updateBottomExpanded(true);
        break;
    case ks::settings::DetailDisplayScheme::Right:
    default:
        break;
    }
}

void ks::ui::DetailLayoutHost::handleDetailChanged(const QString& detailText)
{
    if (m_scheme == ks::settings::DetailDisplayScheme::Floating && !m_floatingEditor.isNull()
        && !m_floatingWindow.isNull() && m_floatingWindow->isVisible())
    {
        setMirrorText(m_floatingEditor.data(), m_detailEditor.data(), detailText);
    }

    if (m_scheme != ks::settings::DetailDisplayScheme::Embedded || m_tableView.isNull())
    {
        return;
    }

    const QModelIndex rawCurrentIndex = m_tableView->currentIndex();
    const QPersistentModelIndex currentIndex(
        rawCurrentIndex.isValid()
            ? rawCurrentIndex.sibling(rawCurrentIndex.row(), 0)
            : QModelIndex());
    const auto entry = m_embeddedEntries.value(currentIndex);
    if (!entry) return;
    if (entry->detailText != detailText)
    {
        auto retired = std::move(entry->detailText);
        auto reading = std::move(entry->textState);
        entry->detailText = detailText;
        QThreadPool::globalInstance()->start([retired = std::move(retired), reading = std::move(reading)]() mutable
            { retired.clear(); reading.reset(); });
    }
    if (!entry->textEditor.isNull())
        setMirrorText(entry->textEditor.data(), m_detailEditor.data(), detailText);
}

void ks::ui::DetailLayoutHost::handleFieldDocumentChanged()
{
    if (m_structuredView.isNull()) return;
    const auto document = m_structuredView->document();
    // 隐藏的复用弹窗不重建文档；showFloatingWindow会在显示前读取同一源的最新快照。
    if (!m_floatingFields.isNull() && !m_floatingWindow.isNull() && m_floatingWindow->isVisible())
    {
        m_floatingFields->setDocument(document);
    }
    if (m_scheme != ks::settings::DetailDisplayScheme::Embedded || m_tableView.isNull()) return;
    const QModelIndex current = m_tableView->currentIndex();
    const QPersistentModelIndex row(current.isValid() ? current.sibling(current.row(), 0) : QModelIndex());
    const auto entry = m_embeddedEntries.value(row);
    if (!entry) return;
    auto retired = std::move(entry->document);
    auto reading = std::move(entry->fieldState);
    entry->document = document;
    QThreadPool::globalInstance()->start([retired = std::move(retired), reading = std::move(reading)]() mutable
        { retired = {}; reading.reset(); });
    if (!entry->fieldView.isNull()) entry->fieldView->setDocument(document);
}

void ks::ui::DetailLayoutHost::toggleEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex)
{
    if (!sourceIndex.isValid() || (detailWidget() == nullptr))
    {
        return;
    }
    if (removeEmbeddedEntry(sourceIndex))
    {
        setSourceExpandedIndicator(sourceIndex, false);
        return;
    }

    if (qobject_cast<QTableView*>(m_tableView.data()) != nullptr)
    {
        insertTableEmbeddedDetail(sourceIndex, m_detailEditor.isNull() ? QString() : m_detailEditor->text());
    }
    else if (qobject_cast<QTreeWidget*>(m_tableView.data()) != nullptr)
    {
        insertTreeEmbeddedDetail(sourceIndex, m_detailEditor.isNull() ? QString() : m_detailEditor->text());
    }
}

void ks::ui::DetailLayoutHost::insertTableEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex,
    const QString& detailText)
{
    QTableView* tableWidget = qobject_cast<QTableView*>(m_tableView.data());
    if (tableWidget == nullptr || sourceIndex.row() < 0)
    {
        return;
    }

    const int sourceRow = sourceIndex.row();
    // 以展开前实际可视矩形作为基准。rowHeight() 取的是表头 section 状态，
    // 在排序/异步填充后的布局更新窗口内可能与 viewport 中的行高不同，
    // 会让详情编辑器下移一整行并留下空白。
    // visualRect 不包含网格线，反复还原它会让源行每次减少 1px；保存逻辑行高。
    const int originalHeight = std::max(1, tableWidget->rowHeight(sourceRow));
    constexpr int inlineDetailHeight = 128;

    installEmbeddedRowDelegate();
    auto entry = std::make_shared<EmbeddedEntry>();
    entry->sourceIndex = sourceIndex;
    entry->originalRowHeight = originalHeight;
    entry->detailHeight = inlineDetailHeight;
    entry->structured = !m_structuredView.isNull();
    entry->detailText = detailText;
    if (entry->structured)
    {
        entry->document = m_structuredView->document();
        entry->presentation = m_structuredView->presentation();
    }
    m_embeddedEntries.insert(sourceIndex, entry);
    ++m_embeddedRevision;
    const QPointer<DetailLayoutHost> alive(this);
    tableWidget->setRowHeight(sourceRow, originalHeight + inlineDetailHeight);
    if (!alive) return;
    updateEmbeddedEditorGeometries();
    setSourceExpandedIndicator(sourceIndex, true);
}

void ks::ui::DetailLayoutHost::insertTreeEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex,
    const QString& detailText)
{
    QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data());
    QTreeWidgetItem* sourceItem = treeWidget != nullptr
        ? treeWidget->itemFromIndex(sourceIndex)
        : nullptr;
    if (treeWidget == nullptr || sourceItem == nullptr)
    {
        return;
    }

    const QSize originalSizeHint = sourceItem->sizeHint(0);
    const int visibleColumn = visibleTreeColumn(treeWidget);
    const int originalHeight = std::max(1, treeWidget->visualRect(
        QModelIndex(sourceIndex).siblingAtColumn(std::max(0, visibleColumn))).height());
    constexpr int inlineDetailHeight = 128;

    installEmbeddedRowDelegate();
    auto entry = std::make_shared<EmbeddedEntry>();
    entry->sourceIndex = sourceIndex;
    entry->originalRowHeight = originalHeight;
    entry->detailHeight = inlineDetailHeight;
    entry->structured = !m_structuredView.isNull();
    entry->detailText = detailText;
    if (entry->structured)
    {
        entry->document = m_structuredView->document();
        entry->presentation = m_structuredView->presentation();
    }
    entry->treeSourceItem = sourceItem;
    entry->originalSizeHint = originalSizeHint;
    m_embeddedEntries.insert(sourceIndex, entry);
    ++m_embeddedRevision;
    const QPointer<DetailLayoutHost> alive(this);
    if (!m_embeddedTreeUniformRowsCaptured)
    {
        m_embeddedTreeUniformRows = treeWidget->uniformRowHeights();
        m_embeddedTreeUniformRowsCaptured = true;
        treeWidget->setUniformRowHeights(false); // expanded rows have distinct logical heights
        if (!alive) return;
    }
    sourceItem->setSizeHint(0, QSize(-1, originalHeight + inlineDetailHeight));
    if (!alive) return;
    updateEmbeddedEditorGeometries();
    setSourceExpandedIndicator(sourceIndex, true);
}

bool ks::ui::DetailLayoutHost::removeEmbeddedEntry(
    const QPersistentModelIndex& sourceIndex)
{
    const auto found = m_embeddedEntries.find(sourceIndex);
    if (found == m_embeddedEntries.end()) return false;
    const auto entry = found.value();
    m_embeddedEntries.erase(found);
    m_activeEmbeddedRows.remove(sourceIndex);
    ++m_embeddedRevision;
    const QPointer<DetailLayoutHost> alive(this);
    restoreEmbeddedEntryLayout(*entry);
    if (!alive) return true;
    if (entry->editorWidget) delete entry->editorWidget.data();
    if (!alive) return true;
    if (m_embeddedEntries.isEmpty() && m_embeddedTreeUniformRowsCaptured)
    {
        m_embeddedTreeUniformRowsCaptured = false;
        if (auto* tree = qobject_cast<QTreeWidget*>(m_tableView.data()))
            tree->setUniformRowHeights(m_embeddedTreeUniformRows);
        if (!alive) return true;
    }
    // Canonical snapshots can be large; release their values away from the GUI.
    QThreadPool::globalInstance()->start([document = std::move(entry->document),
        text = std::move(entry->detailText), fields = std::move(entry->fieldState),
        reading = std::move(entry->textState)]() mutable
    { document = {}; text.clear(); fields.reset(); reading.reset(); });
    updateEmbeddedEditorGeometries();
    return true;
}

void ks::ui::DetailLayoutHost::clearEmbeddedDetails()
{
    const QPointer<DetailLayoutHost> self(this);
    auto entries = std::move(m_embeddedEntries);
    m_embeddedEntries.clear(); m_activeEmbeddedRows.clear();
    auto textPool = std::move(m_textEditorPool); m_textEditorPool.clear();
    auto fieldPool = std::move(m_fieldEditorPool); m_fieldEditorPool.clear();
    ++m_embeddedRevision;
    m_embeddedIndicatorsDirty = true;
    for (const auto& entry : entries)
    {
        restoreEmbeddedEntryLayout(*entry);
        if (!self) return;
        if (entry->editorWidget) delete entry->editorWidget.data();
        if (!self) return;
        QThreadPool::globalInstance()->start([document = std::move(entry->document),
            text = std::move(entry->detailText), fields = std::move(entry->fieldState),
            reading = std::move(entry->textState)]() mutable
        { document = {}; text.clear(); fields.reset(); reading.reset(); });
    }
    for (const auto& editor : textPool) { if (editor) delete editor.data(); if (!self) return; }
    for (const auto& editor : fieldPool) { if (editor) delete editor.data(); if (!self) return; }
    if (m_embeddedTreeUniformRowsCaptured)
    {
        m_embeddedTreeUniformRowsCaptured = false;
        if (auto* tree = qobject_cast<QTreeWidget*>(m_tableView.data()))
            tree->setUniformRowHeights(m_embeddedTreeUniformRows);
        if (!self) return;
    }
    restoreEmbeddedRowDelegate();
    if (self) updateEmbeddedEditorGeometries();
}

void ks::ui::DetailLayoutHost::prepareDataRebuild()
{
    // 原地 setData 不会发 reset/layout signal，因此业务重建入口必须显式取消旧点击。
    ++m_bindingGeneration;
    m_layoutRestorations.clear();
    clearEmbeddedDetails();
}

void ks::ui::DetailLayoutHost::installEmbeddedRowDelegate()
{
    if (m_tableView.isNull() || m_tableView->model() == nullptr) return;
    if (!m_embeddedRowDelegate.isNull()
        && m_tableView->itemDelegate() != m_embeddedRowDelegate.data())
        restoreEmbeddedRowDelegate(); // an external replacement remains authoritative
    if (m_embeddedRowDelegate.isNull())
    {
        QAbstractItemDelegate* source = m_tableView->itemDelegate();
        if (!source) return;
        m_embeddedSourceDelegate = source;
        m_embeddedRowDelegate = new EmbeddedRowDelegate(source,
            [this](const QModelIndex& index) { return embeddedOriginalRowHeight(index); }, this);
        m_tableView->setItemDelegate(m_embeddedRowDelegate.data());
    }
    // Per-column delegates override the default in Qt. Wrap only explicitly
    // registered columns, preserving their paint/editor/help implementations.
    const int columns = m_tableView->model()->columnCount(m_tableView->rootIndex());
    for (int column = 0; column < columns; ++column)
    {
        QAbstractItemDelegate* source = m_tableView->itemDelegateForColumn(column);
        auto found = m_embeddedColumnDelegates.find(column);
        if (found != m_embeddedColumnDelegates.end() && source == found->wrapper) continue;
        if (found != m_embeddedColumnDelegates.end())
        {
            if (found->wrapper) found->wrapper->deleteLater();
            m_embeddedColumnDelegates.erase(found);
        }
        if (!source) continue;
        auto* wrapper = new EmbeddedRowDelegate(source,
            [this](const QModelIndex& index) { return embeddedOriginalRowHeight(index); }, this);
        m_embeddedColumnDelegates.insert(column, {source,wrapper});
        m_tableView->setItemDelegateForColumn(column, wrapper);
    }
}

void ks::ui::DetailLayoutHost::restoreEmbeddedRowDelegate()
{
    const QPointer<DetailLayoutHost> self(this);
    const auto columns = std::move(m_embeddedColumnDelegates);
    m_embeddedColumnDelegates.clear();
    for (auto it = columns.cbegin(); it != columns.cend(); ++it)
    {
        if (m_tableView && it->wrapper && m_tableView->itemDelegateForColumn(it.key()) == it->wrapper)
            m_tableView->setItemDelegateForColumn(it.key(), it->source.data());
        if (!self) return;
        if (it->wrapper) it->wrapper->deleteLater();
    }
    if (m_tableView && m_embeddedRowDelegate && m_embeddedSourceDelegate
        && m_tableView->itemDelegate() == m_embeddedRowDelegate)
        m_tableView->setItemDelegate(m_embeddedSourceDelegate.data());
    if (!self) return;
    if (m_embeddedRowDelegate) m_embeddedRowDelegate->deleteLater();
    m_embeddedRowDelegate.clear();
    m_embeddedSourceDelegate.clear();
    if (m_tableView && m_tableView->viewport()) m_tableView->viewport()->update();
}

int ks::ui::DetailLayoutHost::embeddedOriginalRowHeight(const QModelIndex& modelIndex) const
{
    if (!modelIndex.isValid())
    {
        return -1;
    }

    const auto source = modelIndex.sibling(modelIndex.row(), 0);
    const auto entry = m_embeddedEntries.value(QPersistentModelIndex(source));
    return entry ? entry->originalRowHeight : -1;
}

void ks::ui::DetailLayoutHost::restoreEmbeddedEntryLayout(const EmbeddedEntry& entry)
{
    if (!m_tableView.isNull() && entry.sourceIndex.isValid()
        && entry.sourceIndex.model() == m_tableView->model())
    {
        if (QTableView* tableWidget = qobject_cast<QTableView*>(m_tableView.data()))
        {
            if (entry.originalRowHeight > 0)
            {
                tableWidget->setRowHeight(entry.sourceIndex.row(), entry.originalRowHeight);
            }
        }
        else if (entry.treeSourceItem != nullptr && !entry.originalSizeHint.isNull())
        {
            entry.treeSourceItem->setSizeHint(0, entry.originalSizeHint.toSize());
        }
    }
}

void ks::ui::DetailLayoutHost::updateEmbeddedEditorGeometries()
{
    if (m_embeddedGeometryScheduled) return;
    m_embeddedGeometryScheduled = true;
    QTimer::singleShot(0, this, [this]
    {
        m_embeddedGeometryScheduled = false;
        flushEmbeddedEditorGeometries();
    });
}

QList<QPersistentModelIndex> ks::ui::DetailLayoutHost::visibleEmbeddedRows() const
{
    QList<QPersistentModelIndex> rows;
    if (!m_tableView || !m_tableView->isVisible() || !m_tableView->model()
        || !m_tableView->viewport() || m_embeddedEntries.isEmpty()) return rows;
    const int bottom = m_tableView->viewport()->height();
    if (auto* table = qobject_cast<QTableView*>(m_tableView.data()))
    {
        for (int y = 0; y < bottom;)
        {
            const int row = table->rowAt(y);
            if (row < 0) break;
            const QPersistentModelIndex id(table->model()->index(row, 0, table->rootIndex()));
            if (m_embeddedEntries.contains(id)) rows.append(id);
            y = std::max(y + 1, table->rowViewportPosition(row) + table->rowHeight(row));
        }
    }
    else if (auto* tree = qobject_cast<QTreeWidget*>(m_tableView.data()))
    {
        // Probe the visible viewport, never traverse all expanded identities or
        // all model descendants. indexBelow skips hidden/collapsed tree rows.
        const int column = visibleTreeColumn(tree);
        if (column < 0) return rows;
        const int x = std::clamp(tree->header()->sectionViewportPosition(column)
            + tree->header()->sectionSize(column) / 2, 0, std::max(0, tree->viewport()->width() - 1));
        QModelIndex row;
        for (int y = 0; y < bottom && !row.isValid(); ++y) row = tree->indexAt(QPoint(x, y));
        while (row.isValid())
        {
            row = row.siblingAtColumn(column);
            const QRect rect = tree->visualRect(row);
            if (rect.top() >= bottom) break;
            const QPersistentModelIndex id(row.sibling(row.row(), 0));
            if (rect.bottom() >= 0 && m_embeddedEntries.contains(id)) rows.append(id);
            row = tree->indexBelow(row);
        }
    }
    return rows;
}

void ks::ui::DetailLayoutHost::releaseEmbeddedEditor(const std::shared_ptr<EmbeddedEntry>& entry)
{
    if (!entry || !entry->editorWidget) return;
    if (entry->fieldView) entry->fieldState = entry->fieldView->captureViewState();
    if (entry->textEditor) entry->textState = entry->textEditor->captureReadOnlyViewState();
    const QPointer<QWidget> editor = entry->editorWidget;
    if (entry->fieldView) m_fieldEditorPool.append(entry->fieldView);
    if (entry->textEditor) m_textEditorPool.append(entry->textEditor);
    entry->fieldView.clear(); entry->textEditor.clear(); entry->editorWidget.clear();
    m_activeEmbeddedRows.remove(entry->sourceIndex);
    editor->hide(); // caller checks the host/revision after synchronous events
}

bool ks::ui::DetailLayoutHost::realizeEmbeddedEntry(const std::shared_ptr<EmbeddedEntry>& entry)
{
    if (entry->editorWidget) return true;
    const QPointer<DetailLayoutHost> alive(this);
    const quint64 revision = m_embeddedRevision, binding = m_bindingGeneration;
    const auto current = [&] { return alive && m_embeddedRevision == revision
        && m_bindingGeneration == binding && m_tableView && m_tableView->viewport(); };
    if (entry->structured)
    {
        QPointer<StructuredFieldView> fields;
        while (!m_fieldEditorPool.isEmpty() && !fields) fields = m_fieldEditorPool.takeLast();
        if (!fields)
        {
            fields = new StructuredFieldView(m_tableView->viewport());
            if (!current()) { if (fields) fields->deleteLater(); return false; }
            entry->fieldView = fields; entry->editorWidget = fields;
            m_activeEmbeddedRows.insert(entry->sourceIndex);
            fields->setValueModelProjection();
            if (!current()) return false;
            fields->setMinimumSize(0, 0);
        }
        entry->fieldView = fields; entry->editorWidget = fields;
        m_activeEmbeddedRows.insert(entry->sourceIndex);
        fields->setDocument(entry->document);
        if (!current() || !fields) return false;
        const auto state = entry->fieldState;
        fields->restoreViewState(state);
        if (!current() || !fields) return false;
        if (!state) fields->setPresentation(entry->presentation);
    }
    else
    {
        QPointer<CodeEditorWidget> editor;
        while (!m_textEditorPool.isEmpty() && !editor) editor = m_textEditorPool.takeLast();
        if (!editor)
        {
            editor = new CodeEditorWidget(m_tableView->viewport());
            if (!current()) { if (editor) editor->deleteLater(); return false; }
            entry->textEditor = editor; entry->editorWidget = editor;
            m_activeEmbeddedRows.insert(entry->sourceIndex);
            editor->setReadOnly(true);
            if (!current() || !editor) return false;
            editor->setMinimumSize(0, 0);
        }
        entry->textEditor = editor; entry->editorWidget = editor;
        m_activeEmbeddedRows.insert(entry->sourceIndex);
        editor->setRawText(entry->detailText);
        if (!current() || !editor) return false;
        // The caller restores reading state after final geometry/show, when
        // the real text viewport and its scrollbar ranges are available.
    }
    return current() && entry->editorWidget;
}

void ks::ui::DetailLayoutHost::trimEmbeddedEditorPool()
{
    // One spare per kind avoids churn at a row boundary. Pool size follows the
    // current viewport, never the number of rows the user has ever expanded.
    const QPointer<DetailLayoutHost> alive(this);
    while (m_textEditorPool.size() > 1)
    { const auto editor = m_textEditorPool.takeLast(); if (editor) editor->deleteLater(); if (!alive) return; }
    while (m_fieldEditorPool.size() > 1)
    { const auto editor = m_fieldEditorPool.takeLast(); if (editor) editor->deleteLater(); if (!alive) return; }
}

void ks::ui::DetailLayoutHost::flushEmbeddedEditorGeometries()
{
    if (!m_tableView || !m_tableView->viewport()) return;
    const QPointer<DetailLayoutHost> alive(this);
    const QPointer<QWidget> viewport(m_tableView->viewport());
    const quint64 binding = m_bindingGeneration, revision = m_embeddedRevision;
    const auto current = [&] { return alive && viewport && binding == m_bindingGeneration
        && revision == m_embeddedRevision && m_tableView; };
    const auto rows = m_scheme == ks::settings::DetailDisplayScheme::Embedded
        ? visibleEmbeddedRows() : QList<QPersistentModelIndex>();
    const QSet<QPersistentModelIndex> visible(rows.cbegin(), rows.cend());
    const auto active = m_activeEmbeddedRows; // bounded by the previous viewport
    for (const auto& id : active)
    {
        if (!visible.contains(id)) releaseEmbeddedEditor(m_embeddedEntries.value(id));
        if (!current()) return;
    }
    for (const auto& id : rows)
    {
        const auto entry = m_embeddedEntries.value(id);
        if (!entry || !id.isValid()) continue;
        QRect rect;
        if (auto* table = qobject_cast<QTableView*>(m_tableView.data()))
            rect = QRect(0, table->rowViewportPosition(id.row()), viewport->width(), table->rowHeight(id.row()));
        else if (auto* tree = qobject_cast<QTreeWidget*>(m_tableView.data()))
        {
            const int column = visibleTreeColumn(tree);
            if (column >= 0) rect = tree->visualRect(QModelIndex(id).siblingAtColumn(column));
        }
        rect.setTop(rect.top() + std::max(0, entry->originalRowHeight));
        rect.setLeft(0); rect.setWidth(viewport->width());
        rect.setHeight(std::min(rect.height(), std::max(1, entry->detailHeight)));
        if (rect.isEmpty() || !viewport->rect().intersects(rect))
        { releaseEmbeddedEditor(entry); if (!current()) return; continue; }
        const bool restoreTextState = !entry->structured && !entry->editorWidget;
        if (!realizeEmbeddedEntry(entry) || !current()) return;
        const QPointer<QWidget> editor = entry->editorWidget;
        if (!editor) continue;
        if (editor->geometry() != rect) editor->setGeometry(rect);
        if (!current()) return;
        if (!editor) continue;
        if (editor->isHidden()) { editor->show(); if (!current()) return; if (editor) editor->raise(); }
        if (!current()) return;
        if (restoreTextState && entry->textEditor)
        {
            const auto reading = entry->textState;
            entry->textEditor->restoreReadOnlyViewState(reading);
            if (!current()) return;
        }
    }
    trimEmbeddedEditorPool();
}

void ks::ui::DetailLayoutHost::refreshEmbeddedIndicators()
{
    if (m_tableView.isNull() || m_scheme != ks::settings::DetailDisplayScheme::Embedded) return;
    m_embeddedIndicatorsDirty = true;
    if (!m_tableView->isVisible()) return;
    installEmbeddedRowDelegate();
    m_embeddedIndicatorsDirty = false;
    if (m_tableView && m_tableView->viewport()) m_tableView->viewport()->update();
}

void ks::ui::DetailLayoutHost::scheduleEmbeddedIndicatorRefresh()
{
    if (m_scheme != ks::settings::DetailDisplayScheme::Embedded || !m_tableView) return;
    m_embeddedIndicatorsDirty = true;
    if (m_indicatorRefreshScheduled || !m_tableView->isVisible()) return;
    m_indicatorRefreshScheduled = true;
    QTimer::singleShot(0, this, [this]() {
        m_indicatorRefreshScheduled = false;
        if (m_embeddedIndicatorsDirty) refreshEmbeddedIndicators();
    });
}

void ks::ui::DetailLayoutHost::setSourceExpandedIndicator(
    const QPersistentModelIndex& sourceIndex, bool)
{
    if (m_tableView && m_tableView->viewport() && sourceIndex.isValid())
        m_tableView->viewport()->update(m_tableView->visualRect(sourceIndex));
}

void ks::ui::DetailLayoutHost::showFloatingWindow()
{
    if ((detailWidget() == nullptr) || m_ownerWidget.isNull())
    {
        return;
    }
    const QPointer<DetailLayoutHost> self(this);
    const quint64 generation = m_bindingGeneration;
    const bool windowWasVisible = !m_floatingWindow.isNull() && m_floatingWindow->isVisible();
    if (m_floatingWindow.isNull())
    {
        QDialog* detailWindow = new QDialog(m_ownerWidget.data(), Qt::Window);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, false);
        detailWindow->setModal(false);
        detailWindow->setWindowTitle(ks::i18n::text(
            QStringLiteral("detail.layout.window.title"),
            QStringLiteral("详情")));
        detailWindow->setStyleSheet(QStringLiteral(
            "QDialog{background:%1;color:%2;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex()));

        QVBoxLayout* windowLayout = new QVBoxLayout(detailWindow);
        windowLayout->setContentsMargins(8, 8, 8, 8);
        QWidget* floatingEditor = nullptr;
        if (!m_structuredView.isNull())
        {
            auto* fields = new StructuredFieldView(detailWindow);
            fields->setPresentation(m_structuredView->presentation());
            fields->setDocument(m_structuredView->document());
            m_floatingFields = fields;
            floatingEditor = fields;
        }
        else
        {
            auto* editor = new CodeEditorWidget(detailWindow);
            editor->setReadOnly(true);
            setMirrorText(editor, m_detailEditor.data(), m_detailEditor->text());
            m_floatingEditor = editor;
            floatingEditor = editor;
        }
        windowLayout->addWidget(floatingEditor, 1);
        ApplyDetailDialogChrome(detailWindow);

        QScreen* targetScreen = m_ownerWidget->screen();
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (targetScreen != nullptr)
        {
            const QRect availableRect = targetScreen->availableGeometry();
            const QSize initialSize(
                std::max(320, availableRect.width() / 3),
                std::max(240, availableRect.height() / 3));
            detailWindow->resize(initialSize);
            detailWindow->move(availableRect.center() - QPoint(
                initialSize.width() / 2,
                initialSize.height() / 2));
        }

        detailWindow->installEventFilter(this);
        m_floatingWindow = detailWindow;

    }
    else if (!m_floatingFields.isNull() && !m_structuredView.isNull())
    {
        m_floatingFields->setDocument(m_structuredView->document());
    }
    else if (!m_floatingEditor.isNull())
    {
        setMirrorText(m_floatingEditor.data(), m_detailEditor.data(), m_detailEditor->text());
    }

    // 窗口已显示时只刷新文本，不能因表格选择变化再次抢走焦点。
    // 首次创建或用户关闭后重新唤出时，才执行显示和激活。
    if (!self.isNull() && generation == m_bindingGeneration && !windowWasVisible)
    {
        const QPointer<QDialog> window = m_floatingWindow;
        const auto current = [&]()
        {
            return !self.isNull() && self->m_bindingGeneration == generation
                && !window.isNull() && self->m_floatingWindow == window;
        };
        if (!current())
        {
            return;
        }
        window->setWindowOpacity(1.0);
        if (!current())
        {
            return;
        }
        window->show();
        // Show 同步回调可能已经切回嵌入槽并清空成员，旧窗口不得继续激活。
        if (!current())
        {
            return;
        }
        window->raise();
        if (current())
        {
            window->activateWindow();
        }
    }
}

void ks::ui::DetailLayoutHost::destroyFloatingWindow()
{
    // 先解除成员关联，close 的同步回调即使删除宿主也不再访问成员。
    const QPointer<QDialog> window = m_floatingWindow;
    m_floatingFields.clear();
    m_floatingEditor.clear();
    m_floatingWindow.clear();
    if (!window.isNull())
    {
        window->removeEventFilter(this);
        window->close();
        if (!window.isNull())
        {
            window->deleteLater();
        }
    }
}

bool ks::ui::DetailLayoutHost::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    const QPointer<DetailLayoutHost> self(this);
    const QPointer<QObject> watched(watchedObject);
    if (eventObject != nullptr)
    {
        if (watchedObject == m_tableView.data())
        {
            if (eventObject->type() == QEvent::Show || eventObject->type() == QEvent::LayoutRequest)
            {
                observeModel();
                if (!self.isNull() && m_scheme == ks::settings::DetailDisplayScheme::Embedded)
                    refreshEmbeddedIndicators();
                if (self.isNull())
                {
                    return watched.isNull();
                }
            }
        }
        if ((watchedObject == m_requestedSplitter.data() || watchedObject == m_ownerWidget.data())
            && (eventObject->type() == QEvent::ChildAdded || eventObject->type() == QEvent::LayoutRequest
                || eventObject->type() == QEvent::Show || eventObject->type() == QEvent::ShowToParent) && !isBound())
        {
            // Show runs inside QWidgetPrivate::showChildren: changing this
            // subtree there can invalidate Qt's traversal. The owner's
            // ShowToParent follows show_helper; visible LayoutRequest is the
            // corresponding safe boundary for dynamically mounted panels.
            if (!m_constructing && ((watchedObject == m_ownerWidget.data()
                && eventObject->type() == QEvent::ShowToParent)
                || (eventObject->type() == QEvent::LayoutRequest && m_ownerWidget
                    && m_ownerWidget->isVisible())))
            {
                prepareHostUi();
                if (self.isNull()) return watched.isNull();
            }
            if (!isBound()) scheduleHostUiInitialization();
        }
    }
    if (!m_tableView.isNull() && watchedObject == m_tableView->viewport() && eventObject != nullptr)
    {
        switch (eventObject->type())
        {
        case QEvent::Show:
        case QEvent::Hide:
        case QEvent::Resize:
        case QEvent::Scroll:
        case QEvent::LayoutRequest:
            updateEmbeddedEditorGeometries();
            if (self.isNull())
            {
                return watched.isNull();
            }
            break;
        default:
            break;
        }
    }
    if (watchedObject == m_floatingWindow.data() && eventObject != nullptr)
    {
        if (eventObject->type() == QEvent::WindowActivate)
        {
            m_floatingWindow->setWindowOpacity(1.0);
        }
        else if (eventObject->type() == QEvent::WindowDeactivate)
        {
            m_floatingWindow->setWindowOpacity(0.30);
        }
    }
    if (watched.isNull()) return true;
    return !self.isNull() && QObject::eventFilter(watchedObject, eventObject);
}
