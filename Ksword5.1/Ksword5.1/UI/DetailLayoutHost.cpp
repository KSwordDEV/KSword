#include "DetailLayoutHost.h"

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
#include <QPlainTextEdit>
#include <QScreen>
#include <QSplitter>
#include <QTableWidget>
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

    // directChildUnder：返回 widget 在 ancestor 下的第一层子控件，用于识别分隔器面板。
    QWidget* directChildUnder(QWidget* widget, QWidget* ancestor)
    {
        QWidget* childWidget = widget;
        while (childWidget != nullptr && childWidget->parentWidget() != ancestor)
        {
            childWidget = childWidget->parentWidget();
        }
        return childWidget != nullptr && childWidget->parentWidget() == ancestor
            ? childWidget
            : nullptr;
    }

    // findSharedSplitter：从表格祖先向上查找同时包含详情编辑器的分隔器。
    QSplitter* findSharedSplitter(QAbstractItemView* tableView, CodeEditorWidget* detailEditor)
    {
        QWidget* ancestorWidget = tableView;
        while (ancestorWidget != nullptr)
        {
            QSplitter* splitter = qobject_cast<QSplitter*>(ancestorWidget);
            if (splitter != nullptr && splitter->isAncestorOf(detailEditor))
            {
                // 只有表格和详情处于 splitter 的不同直接面板时才接管它。
                // 页面常见的外层 splitter 可能同时包住整个表格页，误认它会在折叠时
                // 把承载表格的整块面板一起隐藏，最终只剩一个箭头。
                QWidget* tablePane = directChildUnder(tableView, splitter);
                QWidget* detailPane = directChildUnder(detailEditor, splitter);
                if (tablePane != nullptr && detailPane != nullptr && tablePane != detailPane)
                {
                    return splitter;
                }
            }
            ancestorWidget = ancestorWidget->parentWidget();
        }
        return nullptr;
    }

    // findCommonParent：找到两个控件最近的共同 QWidget 祖先。
    QWidget* findCommonParent(QWidget* firstWidget, QWidget* secondWidget)
    {
        for (QWidget* firstParent = firstWidget; firstParent != nullptr;
            firstParent = firstParent->parentWidget())
        {
            for (QWidget* secondParent = secondWidget; secondParent != nullptr;
                secondParent = secondParent->parentWidget())
            {
                if (firstParent == secondParent)
                {
                    return firstParent;
                }
            }
        }
        return nullptr;
    }

    // createReadOnlyInlineEditor：创建方案三使用的普通只读文本框。
    QPlainTextEdit* createReadOnlyInlineEditor(QWidget* parentWidget, const QString& detailText)
    {
        QPlainTextEdit* textEditor = new QPlainTextEdit(parentWidget);
        textEditor->setReadOnly(true);
        textEditor->setPlainText(detailText);
        textEditor->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        // 编辑器直接覆盖在视图 viewport 中，由源行高度决定几何，不能把自身最小高度
        // 传播给整张表格或树。
        textEditor->setMinimumSize(0, 0);
        textEditor->setContextMenuPolicy(Qt::DefaultContextMenu);
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
    initializeHostUi();
    initializeConnections();
    scheduleHostUiInitialization();
}

ks::ui::DetailLayoutHost::~DetailLayoutHost()
{
    // 宿主销毁前恢复行高和页面原 delegate，避免共享视图留下临时包装器。
    clearEmbeddedDetails();
    destroyFloatingWindow();
}

void ks::ui::DetailLayoutHost::setTableView(QAbstractItemView* tableView)
{
    if (tableView == nullptr || m_tableView == tableView)
    {
        return;
    }
    m_tableView = tableView;
    initializeConnections();
    scheduleHostUiInitialization();
}

void ks::ui::DetailLayoutHost::setDetailEditor(CodeEditorWidget* detailEditor)
{
    if (detailEditor == nullptr || m_detailEditor == detailEditor)
    {
        return;
    }
    m_detailEditor = detailEditor;
    initializeConnections();
    scheduleHostUiInitialization();
}

CodeEditorWidget* ks::ui::DetailLayoutHost::detailEditor() const
{
    return m_detailEditor.data();
}

void ks::ui::DetailLayoutHost::initializeHostUi()
{
    ensureManagedSplitter();
    if (m_splitter.isNull())
    {
        return;
    }

    if (!m_toggleBar.isNull())
    {
        return;
    }

    if (!m_detailPane.isNull() && m_tablePane.isNull())
    {
        m_tablePane = directChildUnder(m_tableView.data(), m_splitter.data());
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
    m_toggleButton->setArrowType(Qt::UpArrow);
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
            m_hostUiInitializationScheduled = false;
            if (m_splitter.isNull() || m_detailPane.isNull())
            {
                initializeHostUi();
            }
            if (!m_splitter.isNull() && !m_detailPane.isNull())
            {
                applyScheme(m_scheme);
                updateEmbeddedEditorGeometries();
            }
        });
}

void ks::ui::DetailLayoutHost::ensureManagedSplitter()
{
    if (m_tableView.isNull() || m_detailEditor.isNull())
    {
        return;
    }

    QSplitter* sharedSplitter = findSharedSplitter(m_tableView.data(), m_detailEditor.data());
    if (sharedSplitter != nullptr)
    {
        m_splitter = sharedSplitter;
        m_tablePane = directChildUnder(m_tableView.data(), sharedSplitter);
        m_detailPane = directChildUnder(m_detailEditor.data(), sharedSplitter);
        if (m_tablePane == nullptr || m_detailPane == nullptr || m_tablePane == m_detailPane)
        {
            m_splitter.clear();
            m_tablePane.clear();
            m_detailPane.clear();
            return;
        }
        m_detailEditor->setMinimumHeight(0);
        m_detailEditor->setMaximumHeight(QWIDGETSIZE_MAX);
        return;
    }

    // 直接布局页面没有既有 QSplitter：保留原控件对象，仅把两者包装进统一分隔器。
    QWidget* commonParent = findCommonParent(m_tableView.data(), m_detailEditor.data());
    QBoxLayout* commonLayout = commonParent != nullptr
        ? qobject_cast<QBoxLayout*>(commonParent->layout())
        : nullptr;
    if (commonParent == nullptr || commonLayout == nullptr)
    {
        return;
    }

    QWidget* tablePane = directChildUnder(m_tableView.data(), commonParent);
    QWidget* detailPane = directChildUnder(m_detailEditor.data(), commonParent);
    if (tablePane == nullptr || detailPane == nullptr || tablePane == detailPane)
    {
        return;
    }

    const int tableIndex = commonLayout->indexOf(tablePane);
    const int detailIndex = commonLayout->indexOf(detailPane);
    const int insertionIndex = std::max(0, std::min(tableIndex, detailIndex));
    commonLayout->removeWidget(tablePane);
    commonLayout->removeWidget(detailPane);

    QSplitter* splitter = new QSplitter(Qt::Vertical, commonParent);
    tablePane->setParent(splitter);
    detailPane->setParent(splitter);
    splitter->addWidget(tablePane);
    splitter->addWidget(detailPane);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    commonLayout->insertWidget(insertionIndex, splitter, 1);

    m_splitter = splitter;
    m_tablePane = tablePane;
    m_detailPane = detailPane;
    m_detailEditor->setMinimumHeight(0);
    m_detailEditor->setMaximumHeight(QWIDGETSIZE_MAX);
}

void ks::ui::DetailLayoutHost::initializeConnections()
{
    if (!m_tableView.isNull())
    {
        // UniqueConnection 与成员 lambda 不兼容，因此用动态属性保证每个视图只绑定一次。
        if (!m_tableView->property("kswordDetailLayoutConnected").toBool())
        {
            m_tableView->setProperty("kswordDetailLayoutConnected", true);
            if (m_tableView->viewport() != nullptr)
            {
                m_tableView->viewport()->installEventFilter(this);
            }
            connect(m_tableView.data(), &QAbstractItemView::clicked, this,
                [this](const QModelIndex& modelIndex)
                {
                    handleViewClicked(QPersistentModelIndex(modelIndex));
                });

            if (m_tableView->model() != nullptr)
            {
                connect(m_tableView->model(), &QAbstractItemModel::rowsInserted, this,
                    [this](const QModelIndex&, int, int)
                    {
                        if (m_scheme != ks::settings::DetailDisplayScheme::Embedded)
                        {
                            return;
                        }
                        scheduleEmbeddedIndicatorRefresh();
                    });
                connect(m_tableView->model(), &QAbstractItemModel::modelAboutToBeReset, this,
                    [this]()
                    {
                        clearEmbeddedDetails();
                    });
                connect(m_tableView->model(), &QAbstractItemModel::layoutAboutToBeChanged, this,
                    [this]()
                    {
                        // QPersistentModelIndex 会在排序布局完成后跟随数据项移动，但
                        // QHeaderView 的行高仍绑定排序前的逻辑行。必须在索引重映射前
                        // 恢复原行高并移除覆盖编辑器，避免旧行残留空白、新行详情被裁剪。
                        clearEmbeddedDetails();
                    });
            }
        }
    }

    if (!m_detailEditor.isNull() &&
        !m_detailEditor->property("kswordDetailLayoutConnected").toBool())
    {
        m_detailEditor->setProperty("kswordDetailLayoutConnected", true);
        connect(m_detailEditor.data(), &CodeEditorWidget::contentChanged, this,
            [this](const QString& detailText) { handleDetailChanged(detailText); });
    }

    if (!m_toggleButton.isNull())
    {
        connect(m_toggleButton.data(), &QToolButton::clicked, this,
            [this]() { updateBottomExpanded(!m_bottomExpanded); });
    }
}

void ks::ui::DetailLayoutHost::applyScheme(
    const ks::settings::DetailDisplayScheme scheme)
{
    if (m_splitter.isNull() || m_detailPane.isNull())
    {
        m_scheme = scheme;
        scheduleHostUiInitialization();
        return;
    }

    if (m_scheme == ks::settings::DetailDisplayScheme::Embedded &&
        scheme != ks::settings::DetailDisplayScheme::Embedded)
    {
        clearEmbeddedDetails();
    }
    if (m_scheme == ks::settings::DetailDisplayScheme::Floating &&
        scheme != ks::settings::DetailDisplayScheme::Floating)
    {
        destroyFloatingWindow();
    }

    const bool schemeChanged = m_scheme != scheme;
    m_scheme = scheme;
    if (!m_toggleBar.isNull())
    {
        m_toggleBar->setVisible(scheme == ks::settings::DetailDisplayScheme::BottomCollapsed);
    }
    if (!m_tablePane.isNull())
    {
        m_tablePane->setVisible(true);
        m_tablePane->setMinimumSize(0, 0);
        m_tablePane->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
    }
    switch (scheme)
    {
    case ks::settings::DetailDisplayScheme::Right:
        m_splitter->setOrientation(Qt::Horizontal);
        m_detailPane->setMinimumSize(0, 0);
        m_detailPane->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
        m_detailPane->setVisible(true);
        if (schemeChanged)
        {
            // 右侧详情默认约占 18%，保留拖动手柄供当前页面继续调整。
            setManagedSplitterSizes(820, 0, 180);
        }
        break;
    case ks::settings::DetailDisplayScheme::Embedded:
        m_splitter->setOrientation(Qt::Vertical);
        m_detailPane->setVisible(false);
        m_detailPane->setMinimumHeight(0);
        m_detailPane->setMaximumHeight(0);
        if (schemeChanged)
        {
            setManagedSplitterSizes(1000, 0, 0);
        }
        refreshEmbeddedIndicators();
        break;
    case ks::settings::DetailDisplayScheme::Floating:
        m_splitter->setOrientation(Qt::Vertical);
        m_detailPane->setVisible(false);
        m_detailPane->setMinimumHeight(0);
        m_detailPane->setMaximumHeight(0);
        if (schemeChanged)
        {
            setManagedSplitterSizes(1000, 0, 0);
        }
        break;
    case ks::settings::DetailDisplayScheme::BottomCollapsed:
    default:
        m_splitter->setOrientation(Qt::Vertical);
        if (schemeChanged || (!m_bottomExpanded && m_detailPane->isVisible()))
        {
            m_bottomExpanded = false;
            updateBottomExpanded(false);
        }
        break;
    }
    updateEmbeddedEditorGeometries();
}

void ks::ui::DetailLayoutHost::setManagedSplitterSizes(
    const int tableSize,
    const int toggleSize,
    const int detailSize)
{
    if (m_splitter.isNull())
    {
        return;
    }
    // QSplitter 会把 setSizes 的相对值按当前可用空间归一化。使用非零表格尺寸，
    // 即使页面尚未 show 或窗口刚切换 tab，也不会把业务面板压成 0。
    const int safeTable = std::max(1, tableSize);
    const int safeToggle = std::max(0, toggleSize);
    const int safeDetail = std::max(0, detailSize);
    m_splitter->setSizes({ safeTable, safeToggle, safeDetail });
}

void ks::ui::DetailLayoutHost::updateBottomExpanded(const bool expanded)
{
    if (m_scheme != ks::settings::DetailDisplayScheme::BottomCollapsed ||
        m_detailPane.isNull())
    {
        return;
    }
    m_bottomExpanded = expanded;
    m_detailPane->setMinimumHeight(0);
    if (expanded)
    {
        m_detailPane->setMaximumHeight(QWIDGETSIZE_MAX);
        m_detailPane->setVisible(true);
    }
    else
    {
        m_detailPane->setVisible(false);
        m_detailPane->setMaximumHeight(0);
    }
    if (!m_toggleButton.isNull())
    {
        m_toggleButton->setArrowType(expanded ? Qt::DownArrow : Qt::UpArrow);
        m_toggleButton->setToolTip(ks::i18n::text(
            expanded
                ? QStringLiteral("detail.layout.collapse.tooltip")
                : QStringLiteral("detail.layout.expand.tooltip"),
            expanded
                ? QStringLiteral("收起当前行详情")
                : QStringLiteral("展开当前行详情")));
    }
    if (expanded && !m_splitter.isNull())
    {
        setManagedSplitterSizes(720, 18, 240);
    }
    else if (!m_splitter.isNull())
    {
        setManagedSplitterSizes(1000, 18, 0);
    }
}

void ks::ui::DetailLayoutHost::handleViewClicked(
    const QPersistentModelIndex& sourceIndex)
{
    if (!sourceIndex.isValid())
    {
        return;
    }

    switch (m_scheme)
    {
    case ks::settings::DetailDisplayScheme::Embedded:
        // 原页面的选择回调先更新 CodeEditorWidget，本处再把最新文本镜像到行内视图。
        QTimer::singleShot(0, this, [this, sourceIndex]()
            {
                if (sourceIndex.isValid())
                {
                    toggleEmbeddedDetail(sourceIndex.sibling(sourceIndex.row(), 0));
                }
            });
        break;
    case ks::settings::DetailDisplayScheme::Floating:
        QTimer::singleShot(0, this, [this]() { showFloatingWindow(); });
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
        m_floatingEditor->setRawText(detailText);
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
            entry.textEditor->setPlainText(detailText);
        }
    }
}

void ks::ui::DetailLayoutHost::toggleEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex)
{
    if (!sourceIndex.isValid() || m_detailEditor.isNull())
    {
        return;
    }
    if (removeEmbeddedEntry(sourceIndex))
    {
        setSourceExpandedIndicator(sourceIndex, false);
        return;
    }

    if (qobject_cast<QTableWidget*>(m_tableView.data()) != nullptr)
    {
        insertTableEmbeddedDetail(sourceIndex, m_detailEditor->text());
    }
    else if (qobject_cast<QTreeWidget*>(m_tableView.data()) != nullptr)
    {
        insertTreeEmbeddedDetail(sourceIndex, m_detailEditor->text());
    }
}

void ks::ui::DetailLayoutHost::insertTableEmbeddedDetail(
    const QPersistentModelIndex& sourceIndex,
    const QString& detailText)
{
    QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data());
    if (tableWidget == nullptr || sourceIndex.row() < 0)
    {
        return;
    }

    const int sourceRow = sourceIndex.row();
    // 以展开前实际可视矩形作为基准。rowHeight() 取的是表头 section 状态，
    // 在排序/异步填充后的布局更新窗口内可能与 viewport 中的行高不同，
    // 会让详情编辑器下移一整行并留下空白。
    const int originalHeight = std::max(1, tableWidget->visualRect(sourceIndex).height());
    constexpr int inlineDetailHeight = 128;

    // 先安装包装 delegate 并登记原始高度，再增大行高，避免一次重绘中把源文本画入详情区。
    installEmbeddedRowDelegate();
    QPlainTextEdit* textEditor = createReadOnlyInlineEditor(tableWidget->viewport(), detailText);
    EmbeddedEntry entry;
    entry.sourceIndex = sourceIndex;
    entry.textEditor = textEditor;
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
    QPlainTextEdit* textEditor = createReadOnlyInlineEditor(treeWidget->viewport(), detailText);
    EmbeddedEntry entry;
    entry.sourceIndex = sourceIndex;
    entry.textEditor = textEditor;
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
        if (!entry.textEditor.isNull())
        {
            delete entry.textEditor.data();
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
    if (m_tableView.isNull())
    {
        m_embeddedEntries.clear();
        restoreEmbeddedRowDelegate();
        return;
    }

    m_indicatorRefreshScheduled = false;
    for (const EmbeddedEntry& entry : std::as_const(m_embeddedEntries))
    {
        restoreEmbeddedEntryLayout(entry);
        if (!entry.textEditor.isNull())
        {
            delete entry.textEditor.data();
        }
    }
    m_embeddedEntries.clear();
    restoreEmbeddedRowDelegate();
    m_pendingIndicatorIndexes.clear();
    ++m_indicatorGeneration;
    restoreEmbeddedIndicators();
    updateEmbeddedEditorGeometries();
}

void ks::ui::DetailLayoutHost::prepareDataRebuild()
{
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
    if (!m_tableView.isNull() && !m_embeddedRowDelegate.isNull() &&
        m_tableView->itemDelegate() == m_embeddedRowDelegate.data() &&
        !m_embeddedSourceDelegate.isNull())
    {
        // 只在当前 delegate 仍是本包装器时恢复，避免覆盖页面运行期替换的 delegate。
        m_tableView->setItemDelegate(m_embeddedSourceDelegate.data());
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
    if (!m_tableView.isNull())
    {
        if (QTableWidget* tableWidget = qobject_cast<QTableWidget*>(m_tableView.data()))
        {
            if (entry.sourceIndex.isValid() && entry.originalRowHeight > 0)
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
    QWidget* viewport = m_tableView->viewport();
    if (viewport == nullptr)
    {
        return;
    }
    for (const EmbeddedEntry& entry : std::as_const(m_embeddedEntries))
    {
        if (entry.textEditor.isNull() || !entry.sourceIndex.isValid())
        {
            continue;
        }
        QRect itemRect = m_tableView->visualRect(entry.sourceIndex);
        if (!itemRect.isValid() || itemRect.height() <= 0 || !viewport->rect().intersects(itemRect))
        {
            entry.textEditor->setVisible(false);
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
            entry.textEditor->setVisible(false);
            continue;
        }
        entry.textEditor->setGeometry(editorRect);
        entry.textEditor->setVisible(true);
        entry.textEditor->raise();
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
    if (m_detailEditor.isNull() || m_ownerWidget.isNull())
    {
        return;
    }
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
        CodeEditorWidget* floatingEditor = new CodeEditorWidget(detailWindow);
        floatingEditor->setReadOnly(true);
        floatingEditor->setRawText(m_detailEditor->text());
        windowLayout->addWidget(floatingEditor, 1);

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
        m_floatingEditor = floatingEditor;
    }
    else if (!m_floatingEditor.isNull())
    {
        m_floatingEditor->setRawText(m_detailEditor->text());
    }

    // 窗口已显示时只刷新文本，不能因表格选择变化再次抢走焦点。
    // 首次创建或用户关闭后重新唤出时，才执行显示和激活。
    if (!windowWasVisible)
    {
        m_floatingWindow->setWindowOpacity(1.0);
        m_floatingWindow->show();
        m_floatingWindow->raise();
        m_floatingWindow->activateWindow();
    }
}

void ks::ui::DetailLayoutHost::destroyFloatingWindow()
{
    if (!m_floatingWindow.isNull())
    {
        m_floatingWindow->removeEventFilter(this);
        m_floatingWindow->close();
        m_floatingWindow->deleteLater();
    }
    m_floatingEditor.clear();
    m_floatingWindow.clear();
}

bool ks::ui::DetailLayoutHost::eventFilter(QObject* watchedObject, QEvent* eventObject)
{
    if (!m_tableView.isNull() && watchedObject == m_tableView->viewport() && eventObject != nullptr)
    {
        switch (eventObject->type())
        {
        case QEvent::Resize:
        case QEvent::Scroll:
        case QEvent::LayoutRequest:
            updateEmbeddedEditorGeometries();
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
    return QObject::eventFilter(watchedObject, eventObject);
}
