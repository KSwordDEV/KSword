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
#include <QSplitter>
#include <QTableWidget>
#include <QTableView>
#include <QTableWidgetItem>
#include <QTimer>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <utility>

namespace
{
    // 专用角色避开页面普遍使用的 Qt::UserRole 缓存索引。
    constexpr int OriginalDecorationRole = Qt::UserRole + 411;
    constexpr int OriginalDecorationCapturedRole = Qt::UserRole + 412;

    QIcon embeddedIndicatorIcon(const bool expanded)
    {
        return QIcon(expanded
            ? QStringLiteral(":/Icon/detail_node_expanded.svg")
            : QStringLiteral(":/Icon/detail_node_collapsed.svg"));
    }

    // This branch serves actual text documents and logs only.
    void setMirrorText(CodeEditorWidget* target, CodeEditorWidget*, const QString& text)
    {
        target->setRawText(text);
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

void ks::ui::DetailLayoutHost::scheduleHostUiInitialization()
{
    if (m_hostUiInitializationScheduled || m_ownerWidget.isNull())
    {
        return;
    }
    m_hostUiInitializationScheduled = true;
    QTimer::singleShot(0, this,
        [this]()
        {
            const QPointer<DetailLayoutHost> self(this);
            m_hostUiInitializationScheduled = false;
            if (m_splitter.isNull() || m_detailPane.isNull())
            {
                initializeHostUi();
            }
            if (self.isNull())
            {
                return;
            }
            if (!m_splitter.isNull() && !m_detailPane.isNull())
            {
                initializeConnections();
                if (self.isNull())
                {
                    return;
                }
                applyScheme(m_requestedScheme);
                if (self.isNull())
                {
                    return;
                }
                updateEmbeddedEditorGeometries();
            }
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
    if (!sourceIndex.isValid())
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
    if (m_scheme == ks::settings::DetailDisplayScheme::Floating && !m_floatingEditor.isNull())
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
    for (EmbeddedEntry& entry : m_embeddedEntries)
    {
        if (!entry.textEditor.isNull() && entry.sourceIndex.isValid() &&
            currentIndex.isValid() && entry.sourceIndex == currentIndex)
        {
            setMirrorText(entry.textEditor.data(), m_detailEditor.data(), detailText);
        }
    }
}

void ks::ui::DetailLayoutHost::handleFieldDocumentChanged()
{
    if (m_structuredView.isNull()) return;
    const auto document = m_structuredView->document();
    if (!m_floatingFields.isNull()) m_floatingFields->setDocument(document);
    if (m_scheme != ks::settings::DetailDisplayScheme::Embedded || m_tableView.isNull()) return;
    const QModelIndex current = m_tableView->currentIndex();
    const QPersistentModelIndex row(current.isValid() ? current.sibling(current.row(), 0) : QModelIndex());
    for (auto& entry : m_embeddedEntries)
        if (!entry.fieldView.isNull() && entry.sourceIndex.isValid() && entry.sourceIndex == row)
            entry.fieldView->setDocument(document);
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

    // 先安装包装 delegate 并登记原始高度，再增大行高，避免一次重绘中把源文本画入详情区。
    installEmbeddedRowDelegate();
    EmbeddedEntry entry;
    QWidget* textEditor = nullptr;
    if (!m_structuredView.isNull())
    {
        auto* fields = new StructuredFieldView(tableWidget->viewport());
        fields->setPresentation(m_structuredView->presentation());
        fields->setDocument(m_structuredView->document());
        entry.fieldView = fields;
        textEditor = fields;
    }
    else
    {
        auto* editor = createReadOnlyInlineEditor(tableWidget->viewport(), m_detailEditor.data(), detailText);
        entry.textEditor = editor;
        textEditor = editor;
    }
    entry.sourceIndex = sourceIndex;
    entry.editorWidget = textEditor;
    entry.originalRowHeight = originalHeight;
    entry.detailHeight = inlineDetailHeight;
    m_embeddedEntries.append(entry);
    tableWidget->setRowHeight(sourceRow, originalHeight + inlineDetailHeight);
    textEditor->show();
    updateEmbeddedEditorGeometries();
    QTimer::singleShot(0, this, [this]() { updateEmbeddedEditorGeometries(); });
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
    const int originalHeight = std::max(1, treeWidget->visualRect(sourceIndex).height());
    constexpr int inlineDetailHeight = 128;

    // 树节点同样先登记裁剪高度，再改变 size hint，保证首次重绘也使用原始行高。
    installEmbeddedRowDelegate();
    EmbeddedEntry entry;
    QWidget* textEditor = nullptr;
    if (!m_structuredView.isNull())
    {
        auto* fields = new StructuredFieldView(treeWidget->viewport());
        fields->setPresentation(m_structuredView->presentation());
        fields->setDocument(m_structuredView->document());
        entry.fieldView = fields;
        textEditor = fields;
    }
    else
    {
        auto* editor = createReadOnlyInlineEditor(treeWidget->viewport(), m_detailEditor.data(), detailText);
        entry.textEditor = editor;
        textEditor = editor;
    }
    entry.sourceIndex = sourceIndex;
    entry.editorWidget = textEditor;
    entry.treeSourceItem = sourceItem;
    entry.originalRowHeight = originalHeight;
    entry.detailHeight = inlineDetailHeight;
    entry.originalSizeHint = originalSizeHint;
    m_embeddedEntries.append(entry);
    sourceItem->setSizeHint(0, QSize(-1, originalHeight + inlineDetailHeight));
    textEditor->show();
    updateEmbeddedEditorGeometries();
    QTimer::singleShot(0, this, [this]() { updateEmbeddedEditorGeometries(); });
    setSourceExpandedIndicator(sourceIndex, true);
}

bool ks::ui::DetailLayoutHost::removeEmbeddedEntry(
    const QPersistentModelIndex& sourceIndex)
{
    for (int entryIndex = 0; entryIndex < m_embeddedEntries.size(); ++entryIndex)
    {
        EmbeddedEntry& entry = m_embeddedEntries[entryIndex];
        if (!entry.sourceIndex.isValid() || entry.sourceIndex != sourceIndex)
        {
            continue;
        }

        restoreEmbeddedEntryLayout(entry);
        if (!entry.editorWidget.isNull())
        {
            delete entry.editorWidget.data();
        }
        m_embeddedEntries.removeAt(entryIndex);
        if (m_embeddedEntries.isEmpty())
        {
            restoreEmbeddedRowDelegate();
        }
        updateEmbeddedEditorGeometries();
        return true;
    }
    return false;
}

void ks::ui::DetailLayoutHost::clearEmbeddedDetails()
{
    const QPointer<DetailLayoutHost> self(this);
    if (m_tableView.isNull())
    {
        m_embeddedEntries.clear();
        restoreEmbeddedRowDelegate();
        return;
    }

    m_indicatorRefreshScheduled = false;
    // 先分离本轮记录，行高/编辑器清理同步触发的回调不能重复遍历同一容器。
    const auto entries = std::move(m_embeddedEntries);
    m_embeddedEntries.clear();
    for (const EmbeddedEntry& entry : entries)
    {
        restoreEmbeddedEntryLayout(entry);
        if (self.isNull())
        {
            return;
        }
        if (!entry.editorWidget.isNull())
        {
            delete entry.editorWidget.data();
        }
        if (self.isNull())
        {
            return;
        }
    }
    m_embeddedEntries.clear();
    restoreEmbeddedRowDelegate();
    if (self.isNull())
    {
        return;
    }
    m_pendingIndicatorIndexes.clear();
    ++m_indicatorGeneration;
    restoreEmbeddedIndicators();
    if (self.isNull())
    {
        return;
    }
    updateEmbeddedEditorGeometries();
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
    if (m_tableView.isNull() ||
        (!m_embeddedRowDelegate.isNull() &&
         m_tableView->itemDelegate() == m_embeddedRowDelegate.data()))
    {
        return;
    }

    // 当前视图未设置 delegate 时由 Qt 保证回退默认绘制；无需安装无源包装器。
    QAbstractItemDelegate* sourceDelegate = m_tableView->itemDelegate();
    if (sourceDelegate == nullptr)
    {
        return;
    }

    // 源 delegate 仅借用，所有权仍由页面视图保持；包装器随详情宿主销毁。
    m_embeddedSourceDelegate = sourceDelegate;
    m_embeddedRowDelegate = new EmbeddedRowDelegate(
        sourceDelegate,
        [this](const QModelIndex& modelIndex)
        {
            return embeddedOriginalRowHeight(modelIndex);
        },
        this);
    m_tableView->setItemDelegate(m_embeddedRowDelegate.data());
    if (m_tableView->viewport() != nullptr)
    {
        m_tableView->viewport()->update();
    }
}

void ks::ui::DetailLayoutHost::restoreEmbeddedRowDelegate()
{
    const QPointer<DetailLayoutHost> self(this);
    if (!m_tableView.isNull() && !m_embeddedRowDelegate.isNull() &&
        m_tableView->itemDelegate() == m_embeddedRowDelegate.data() &&
        !m_embeddedSourceDelegate.isNull())
    {
        // 只在当前 delegate 仍是本包装器时恢复，避免覆盖页面运行期替换的 delegate。
        m_tableView->setItemDelegate(m_embeddedSourceDelegate.data());
        if (self.isNull())
        {
            return;
        }
        if (m_tableView->viewport() != nullptr)
        {
            m_tableView->viewport()->update();
        }
    }

    // deleteLater 保证 Qt 不会在当前绘制调用栈内销毁仍可能被访问的 delegate。
    if (!m_embeddedRowDelegate.isNull())
    {
        m_embeddedRowDelegate->deleteLater();
    }
    m_embeddedRowDelegate.clear();
    m_embeddedSourceDelegate.clear();
}

int ks::ui::DetailLayoutHost::embeddedOriginalRowHeight(const QModelIndex& modelIndex) const
{
    if (!modelIndex.isValid())
    {
        return -1;
    }

    // 每列都会分别调用 delegate；统一比较第 0 列的稳定源索引以匹配同一逻辑行。
    const QModelIndex sourceIndex = modelIndex.sibling(modelIndex.row(), 0);
    for (const EmbeddedEntry& entry : m_embeddedEntries)
    {
        if (entry.sourceIndex.isValid() && entry.sourceIndex == sourceIndex)
        {
            return entry.originalRowHeight;
        }
    }
    return -1;
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
    if (m_tableView.isNull())
    {
        return;
    }
    const QPointer<DetailLayoutHost> self(this);
    const quint64 generation = m_bindingGeneration;
    const QPointer<QWidget> viewport(m_tableView->viewport());
    if (viewport.isNull())
    {
        return;
    }
    // Move/Resize/Show 回调可同步切模式并清空 live 列表，只遍历本轮弱引用快照。
    const auto entries = m_embeddedEntries;
    const auto current = [&]()
    {
        return !self.isNull() && self->m_bindingGeneration == generation && !viewport.isNull();
    };
    for (const EmbeddedEntry& entry : entries)
    {
        if (entry.editorWidget.isNull() || !entry.sourceIndex.isValid())
        {
            continue;
        }
        QRect itemRect = m_tableView->visualRect(entry.sourceIndex);
        if (!itemRect.isValid() || itemRect.height() <= 0 || !viewport->rect().intersects(itemRect))
        {
            entry.editorWidget->setVisible(false);
            if (!current())
            {
                return;
            }
            continue;
        }
        const int topPadding = qMax(0, entry.originalRowHeight);
        const int detailHeight = qMax(1, entry.detailHeight);
        QRect editorRect = itemRect;
        editorRect.setTop(editorRect.top() + topPadding);
        editorRect.setLeft(0);
        editorRect.setWidth(viewport->width());
        editorRect.setBottom(qMin(itemRect.bottom(), editorRect.top() + detailHeight - 1));
        if (editorRect.height() <= 0)
        {
            entry.editorWidget->setVisible(false);
            if (!current())
            {
                return;
            }
            continue;
        }
        entry.editorWidget->setGeometry(editorRect);
        if (!current())
        {
            return;
        }
        if (entry.editorWidget.isNull())
        {
            continue;
        }
        entry.editorWidget->setVisible(true);
        if (!current())
        {
            return;
        }
        if (entry.editorWidget.isNull())
        {
            continue;
        }
        entry.editorWidget->raise();
        if (!current())
        {
            return;
        }
    }
}

void ks::ui::DetailLayoutHost::refreshEmbeddedIndicators()
{
    if (m_tableView.isNull() || m_scheme != ks::settings::DetailDisplayScheme::Embedded)
    {
        return;
    }
    const int rowCount = m_tableView->model() != nullptr
        ? m_tableView->model()->rowCount()
        : 0;
    queueEmbeddedIndicatorRows(QModelIndex(), 0, rowCount - 1);
}

void ks::ui::DetailLayoutHost::scheduleEmbeddedIndicatorRefresh()
{
    if (m_indicatorRefreshScheduled)
    {
        return;
    }
    m_indicatorRefreshScheduled = true;
    QTimer::singleShot(0, this,
        [this]()
        {
            m_indicatorRefreshScheduled = false;
            refreshEmbeddedIndicators();
        });
}

void ks::ui::DetailLayoutHost::queueEmbeddedIndicatorRows(
    const QModelIndex& parentIndex,
    const int firstRow,
    const int lastRow)
{
    if (m_tableView.isNull() || m_tableView->model() == nullptr || firstRow > lastRow)
    {
        return;
    }
    ++m_indicatorGeneration;
    m_pendingIndicatorIndexes.clear();
    const int boundedFirst = qMax(0, firstRow);
    const int boundedLast = qMin(lastRow, m_tableView->model()->rowCount(parentIndex) - 1);
    for (int row = boundedFirst; row <= boundedLast; ++row)
    {
        const QModelIndex index = m_tableView->model()->index(row, 0, parentIndex);
        if (index.isValid())
        {
            m_pendingIndicatorIndexes.append(QPersistentModelIndex(index));
        }
    }
    if (!m_indicatorBatchScheduled)
    {
        m_indicatorBatchScheduled = true;
        const quint64 generation = m_indicatorGeneration;
        QTimer::singleShot(0, this, [this, generation]() { processEmbeddedIndicatorBatch(generation); });
    }
}

void ks::ui::DetailLayoutHost::processEmbeddedIndicatorBatch(const quint64 generation)
{
    if (generation != m_indicatorGeneration || m_scheme != ks::settings::DetailDisplayScheme::Embedded ||
        m_tableView.isNull() || m_tableView->model() == nullptr)
    {
        m_indicatorBatchScheduled = false;
        if (generation != m_indicatorGeneration && !m_pendingIndicatorIndexes.isEmpty() &&
            m_scheme == ks::settings::DetailDisplayScheme::Embedded)
        {
            m_indicatorBatchScheduled = true;
            const quint64 currentGeneration = m_indicatorGeneration;
            QTimer::singleShot(0, this,
                [this, currentGeneration]() { processEmbeddedIndicatorBatch(currentGeneration); });
        }
        return;
    }
    int processed = 0;
    while (!m_pendingIndicatorIndexes.isEmpty() && processed < 128)
    {
        const QPersistentModelIndex index = m_pendingIndicatorIndexes.takeLast();
        if (!index.isValid())
        {
            continue;
        }
        installEmbeddedIndicator(index, false);
        if (qobject_cast<QTreeWidget*>(m_tableView.data()) != nullptr)
        {
            const int childCount = m_tableView->model()->rowCount(index);
            for (int child = 0; child < childCount; ++child)
            {
                const QModelIndex childIndex = m_tableView->model()->index(child, 0, index);
                if (childIndex.isValid())
                {
                    m_pendingIndicatorIndexes.append(QPersistentModelIndex(childIndex));
                }
            }
        }
        ++processed;
    }
    if (!m_pendingIndicatorIndexes.isEmpty())
    {
        QTimer::singleShot(0, this, [this, generation]() { processEmbeddedIndicatorBatch(generation); });
        return;
    }
    m_indicatorBatchScheduled = false;
    for (const EmbeddedEntry& entry : std::as_const(m_embeddedEntries))
    {
        if (entry.sourceIndex.isValid())
        {
            setSourceExpandedIndicator(entry.sourceIndex, true);
        }
    }
}

void ks::ui::DetailLayoutHost::installEmbeddedIndicator(
    const QPersistentModelIndex& sourceIndex,
    const bool expanded)
{
    if (m_tableView.isNull() || !sourceIndex.isValid())
    {
        return;
    }
    if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
    {
        QTableWidgetItem* firstItem = tableWidget->item(sourceIndex.row(), 0);
        if (firstItem == nullptr)
        {
            return;
        }
        if (!firstItem->data(OriginalDecorationCapturedRole).toBool())
        {
            firstItem->setData(OriginalDecorationRole, firstItem->data(Qt::DecorationRole));
            firstItem->setData(OriginalDecorationCapturedRole, true);
            m_indicatorIndexes.append(sourceIndex);
        }
        firstItem->setIcon(embeddedIndicatorIcon(expanded));
    }
    else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data()))
    {
        QTreeWidgetItem* item = treeWidget->itemFromIndex(sourceIndex);
        if (item == nullptr)
        {
            return;
        }
        if (!item->data(0, OriginalDecorationCapturedRole).toBool())
        {
            item->setData(0, OriginalDecorationRole, item->data(0, Qt::DecorationRole));
            item->setData(0, OriginalDecorationCapturedRole, true);
            m_indicatorIndexes.append(sourceIndex);
        }
        item->setIcon(0, embeddedIndicatorIcon(expanded));
    }
}

void ks::ui::DetailLayoutHost::restoreEmbeddedIndicators()
{
    for (const QPersistentModelIndex& sourceIndex : std::as_const(m_indicatorIndexes))
    {
        if (!sourceIndex.isValid())
        {
            continue;
        }
        if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
        {
            QTableWidgetItem* firstItem = tableWidget->item(sourceIndex.row(), 0);
            if (firstItem != nullptr && firstItem->data(OriginalDecorationCapturedRole).toBool())
            {
                firstItem->setData(Qt::DecorationRole, firstItem->data(OriginalDecorationRole));
                firstItem->setData(OriginalDecorationRole, QVariant());
                firstItem->setData(OriginalDecorationCapturedRole, false);
            }
        }
        else if (QTreeWidget* treeWidget = qobject_cast<QTreeWidget*>(m_tableView.data()))
        {
            QTreeWidgetItem* item = treeWidget->itemFromIndex(sourceIndex);
            if (item != nullptr && item->data(0, OriginalDecorationCapturedRole).toBool())
            {
                item->setData(0, Qt::DecorationRole, item->data(0, OriginalDecorationRole));
                item->setData(0, OriginalDecorationRole, QVariant());
                item->setData(0, OriginalDecorationCapturedRole, false);
            }
        }
    }
    m_indicatorIndexes.clear();
}

void ks::ui::DetailLayoutHost::setSourceExpandedIndicator(
    const QPersistentModelIndex& sourceIndex,
    const bool expanded)
{
    installEmbeddedIndicator(sourceIndex, expanded);
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
    if (eventObject != nullptr)
    {
        if (watchedObject == m_tableView.data())
        {
            if (eventObject->type() == QEvent::Show || eventObject->type() == QEvent::LayoutRequest)
            {
                observeModel();
                if (self.isNull())
                {
                    return true;
                }
            }
        }
        if ((watchedObject == m_requestedSplitter.data() || watchedObject == m_ownerWidget.data())
            && (eventObject->type() == QEvent::ChildAdded || eventObject->type() == QEvent::LayoutRequest
                || eventObject->type() == QEvent::Show) && !isBound())
        {
            scheduleHostUiInitialization();
        }
    }
    if (!m_tableView.isNull() && watchedObject == m_tableView->viewport() && eventObject != nullptr)
    {
        switch (eventObject->type())
        {
        case QEvent::Resize:
        case QEvent::Scroll:
        case QEvent::LayoutRequest:
            updateEmbeddedEditorGeometries();
            if (self.isNull())
            {
                return true;
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
    return self.isNull() || QObject::eventFilter(watchedObject, eventObject);
}
