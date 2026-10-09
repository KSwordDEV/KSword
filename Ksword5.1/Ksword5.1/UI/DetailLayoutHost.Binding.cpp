#include "DetailLayoutHost.h"
#include "CodeEditorWidget.h"
#include "../Internationalization/LanguageManager.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QScrollBar>
#include <QSplitter>
#include <QTableWidget>
#include <QTableView>
#include <QToolButton>
#include <QTreeWidget>
#include <algorithm>

namespace ks::ui
{
    void DetailLayoutHost::setTableView(QAbstractItemView* tableView)
    {
        if (tableView == nullptr)
        {
            return;
        }
        if (m_tableView == tableView)
        {
            observeModel();
            return;
        }
        clearEmbeddedDetails();
        disconnectViewBindings();
        ++m_bindingGeneration;
        m_tableView = tableView;
        initializeConnections();
        scheduleHostUiInitialization();
    }

    void DetailLayoutHost::setDetailEditor(CodeEditorWidget* detailEditor)
    {
        if (detailEditor == nullptr || m_detailEditor == detailEditor)
        {
            return;
        }
        QObject::disconnect(m_editorConnection);
        clearEmbeddedDetails();
        destroyFloatingWindow();
        ++m_bindingGeneration;
        m_structuredView.clear();
        m_detailEditor = detailEditor;
        initializeConnections();
        scheduleHostUiInitialization();
    }

    CodeEditorWidget* DetailLayoutHost::detailEditor() const
    {
        return m_detailEditor.data();
    }

    StructuredFieldView* DetailLayoutHost::structuredView() const
    {
        return m_structuredView.data();
    }

    QWidget* DetailLayoutHost::detailWidget() const
    {
        return !m_structuredView.isNull() ? static_cast<QWidget*>(m_structuredView.data())
            : static_cast<QWidget*>(m_detailEditor.data());
    }

    bool DetailLayoutHost::hasExplicitBinding() const
    {
        return m_explicitBinding;
    }

    bool DetailLayoutHost::supportsInlineDetails() const
    {
        return qobject_cast<QTableView*>(m_tableView.data()) != nullptr
            || qobject_cast<QTreeWidget*>(m_tableView.data()) != nullptr;
    }

    ks::settings::DetailDisplayScheme DetailLayoutHost::requestedScheme() const
    {
        return m_requestedScheme;
    }

    ks::settings::DetailDisplayScheme DetailLayoutHost::effectiveScheme() const
    {
        return m_scheme;
    }

    // 每个 Qt 变更步骤都可能同步发 Show/Hide/Resize，回调后必须重新确认宿主和轮次。
    bool DetailLayoutHost::applyLayoutStep(std::function<void()> step)
    {
        const QPointer<DetailLayoutHost> self(this);
        const quint64 generation = m_bindingGeneration;
        step();
        return !self.isNull() && self->m_bindingGeneration == generation && self->isBound();
    }

    bool DetailLayoutHost::isBound() const
    {
        return !m_splitter.isNull() && !m_tablePane.isNull() && !m_detailPane.isNull()
            && !m_tableView.isNull() && !(detailWidget() == nullptr)
            && m_tablePane->parentWidget() == m_splitter && m_detailPane->parentWidget() == m_splitter
            && (m_tablePane == m_tableView || m_tablePane->isAncestorOf(m_tableView.data()))
            && (m_detailPane == detailWidget() || m_detailPane->isAncestorOf(detailWidget()));
    }

    bool DetailLayoutHost::bindPanels(const DetailPaneBinding& binding)
    {
        if (binding.splitter == nullptr || binding.mainPane == nullptr || binding.detailPane == nullptr
            || binding.mainPane == binding.detailPane || m_tableView.isNull() || (detailWidget() == nullptr)
            || (binding.mainPane != m_tableView && !binding.mainPane->isAncestorOf(m_tableView.data()))
            || (binding.detailPane != detailWidget() && !binding.detailPane->isAncestorOf(detailWidget())))
        {
            return false;
        }
        // 重复注册同一布局不删除箭头，也不覆盖用户当前的展开和拖动比例。
        if (m_explicitBinding && m_requestedSplitter == binding.splitter
            && m_requestedMainPane == binding.mainPane && m_requestedDetailPane == binding.detailPane)
        {
            return isBound();
        }
        const QPointer<DetailLayoutHost> self(this);
        clearEmbeddedDetails();
        if (self.isNull())
        {
            return false;
        }
        destroyFloatingWindow();
        if (self.isNull())
        {
            return false;
        }
        ++m_bindingGeneration;
        if (!m_requestedSplitter.isNull())
        {
            m_requestedSplitter->removeEventFilter(this);
        }
        if (!m_toggleBar.isNull())
        {
            m_toggleBar->hide();
            if (self.isNull())
            {
                return false;
            }
            m_toggleBar->deleteLater();
            m_toggleBar.clear();
            m_toggleButton.clear();
        }
        // 旧详情槽恢复可布局状态，新的显隐只由新布局策略负责。
        if (!m_detailPane.isNull())
        {
            m_detailPane->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX);
            if (self.isNull())
            {
                return false;
            }
            m_detailPane->show();
            if (self.isNull())
            {
                return false;
            }
        }
        m_splitter.clear();
        m_tablePane.clear();
        m_detailPane.clear();
        m_explicitBinding = true;
        m_requestedSplitter = binding.splitter;
        m_requestedMainPane = binding.mainPane;
        m_requestedDetailPane = binding.detailPane;
        binding.splitter->installEventFilter(this);
        if (!m_ownerWidget.isNull())
        {
            m_ownerWidget->installEventFilter(this);
        }
        if (!m_constructing)
        {
            initializeHostUi();
            if (self.isNull())
            {
                return false;
            }
        }
        initializeConnections();
        scheduleHostUiInitialization();
        return isBound();
    }

    bool DetailLayoutHost::bindModel(QAbstractItemModel* model)
    {
        if (m_tableView.isNull() || model == nullptr)
        {
            return false;
        }
        // Item-based 控件不能替换内部模型，通用 QTableView/QTreeView 才可换绑。
        if ((qobject_cast<QTableWidget*>(m_tableView.data()) != nullptr
            || qobject_cast<QTreeWidget*>(m_tableView.data()) != nullptr) && m_tableView->model() != model)
        {
            return false;
        }
        if (m_tableView->model() != model)
        {
            clearEmbeddedDetails();
            ++m_bindingGeneration;
            m_tableView->setModel(model);
        }
        observeModel();
        return true;
    }

    // 换视图时旧连接和过滤器全部撤销，旧模型再变化也不能修改新页面。
    void DetailLayoutHost::disconnectViewBindings()
    {
        for (const QMetaObject::Connection& connection : m_viewConnections)
        {
            QObject::disconnect(connection);
        }
        m_viewConnections.clear();
        for (const QMetaObject::Connection& connection : m_modelConnections)
        {
            QObject::disconnect(connection);
        }
        m_modelConnections.clear();
        m_observedModel.clear();
        if (!m_tableView.isNull())
        {
            m_tableView->removeEventFilter(this);
            if (m_tableView->viewport() != nullptr)
            {
                m_tableView->viewport()->removeEventFilter(this);
            }
        }
    }

    void DetailLayoutHost::initializeConnections()
    {
        if (!m_tableView.isNull() && m_viewConnections.isEmpty())
        {
            m_tableView->installEventFilter(this);
            m_tableView->viewport()->installEventFilter(this);
            m_viewConnections.append(connect(m_tableView.data(), &QAbstractItemView::clicked, this,
                [this](const QModelIndex& index) { handleViewClicked(QPersistentModelIndex(index)); }));
            const auto scrolled = [this]() { updateEmbeddedEditorGeometries(); };
            m_viewConnections.append(connect(m_tableView->verticalScrollBar(), &QScrollBar::valueChanged, this, scrolled));
            m_viewConnections.append(connect(m_tableView->horizontalScrollBar(), &QScrollBar::valueChanged, this, scrolled));
        }
        observeModel();
        // 文本和箭头使用连接句柄去重，不用锁死第一次绑定的 QWidget 动态属性。
        QObject::disconnect(m_editorConnection);
        if (!m_detailEditor.isNull())
        {
            m_editorConnection = connect(m_detailEditor.data(), &CodeEditorWidget::contentChanged, this,
                [this](const QString& text) { handleDetailChanged(text); });
        }
        else if (!m_structuredView.isNull())
        {
            m_editorConnection = connect(m_structuredView.data(), &StructuredFieldView::documentChanged,
                this, [this] { handleFieldDocumentChanged(); });
        }
        QObject::disconnect(m_toggleConnection);
        if (!m_toggleButton.isNull())
        {
            m_toggleConnection = connect(m_toggleButton.data(), &QToolButton::clicked, this,
                [this]() { updateBottomExpanded(!m_bottomExpanded); });
        }
    }

    void DetailLayoutHost::observeModel()
    {
        QAbstractItemModel* const model = m_tableView.isNull() ? nullptr : m_tableView->model();
        if (m_observedModel == model)
        {
            return;
        }
        clearEmbeddedDetails();
        m_layoutRestorations.clear();
        ++m_bindingGeneration;
        for (const QMetaObject::Connection& connection : m_modelConnections)
        {
            QObject::disconnect(connection);
        }
        m_modelConnections.clear();
        m_observedModel = model;
        if (model == nullptr)
        {
            return;
        }
        // 必须在持久索引重映射/删除前恢复行高和 delegate，不能等 layoutChanged。
        const auto rebuilding = [this]()
        {
            // Item 控件的内部模型可能在 QWidget 基类析构时 reset，此时视图接口已销毁。
            if (qobject_cast<QAbstractItemView*>(m_tableView.data()) == nullptr)
            {
                return;
            }
            m_layoutRestorations.clear();
            ++m_bindingGeneration;
            clearEmbeddedDetails();
        };
        const auto sorting = [this]()
        {
            if (qobject_cast<QAbstractItemView*>(m_tableView.data()) == nullptr)
            {
                return;
            }
            // Qt 表头可能已缓存排序前尺寸；排序后还要按重映射索引再还原一次。
            m_layoutRestorations = m_embeddedEntries;
            ++m_bindingGeneration;
            clearEmbeddedDetails();
        };
        const auto changed = [this]()
        {
            if (qobject_cast<QAbstractItemView*>(m_tableView.data()) == nullptr)
            {
                return;
            }
            scheduleEmbeddedIndicatorRefresh();
            updateEmbeddedEditorGeometries();
        };
        m_modelConnections.append(connect(model, &QAbstractItemModel::modelAboutToBeReset, this, rebuilding));
        m_modelConnections.append(connect(model, &QAbstractItemModel::layoutAboutToBeChanged, this, sorting));
        m_modelConnections.append(connect(model, &QAbstractItemModel::rowsAboutToBeRemoved, this, rebuilding));
        m_modelConnections.append(connect(model, &QAbstractItemModel::rowsAboutToBeMoved, this, rebuilding));
        m_modelConnections.append(connect(model, &QAbstractItemModel::columnsAboutToBeRemoved, this, rebuilding));
        m_modelConnections.append(connect(model, &QAbstractItemModel::rowsInserted, this, changed));
        m_modelConnections.append(connect(model, &QAbstractItemModel::modelReset, this, changed));
        m_modelConnections.append(connect(model, &QAbstractItemModel::layoutChanged, this, [this, changed]()
        {
            for (const EmbeddedEntry& entry : m_layoutRestorations)
            {
                restoreEmbeddedEntryLayout(entry);
            }
            m_layoutRestorations.clear();
            changed();
        }));
    }

    // 请求与有效模式分离：普通树视图回退到右侧详情槽，保存的全局选择不被改写。
    void DetailLayoutHost::applyScheme(const ks::settings::DetailDisplayScheme requested)
    {
        const QPointer<DetailLayoutHost> self(this);
        const quint64 initialGeneration = m_bindingGeneration;
        m_requestedScheme = requested;
        const auto scheme = requested == ks::settings::DetailDisplayScheme::Embedded && !supportsInlineDetails()
            ? ks::settings::DetailDisplayScheme::Right : requested;
        if (!isBound())
        {
            m_scheme = scheme;
            scheduleHostUiInitialization();
            return;
        }
        if (m_scheme == ks::settings::DetailDisplayScheme::Embedded && scheme != m_scheme)
        {
            clearEmbeddedDetails();
            if (self.isNull() || self->m_bindingGeneration != initialGeneration)
            {
                return;
            }
        }
        if (m_scheme == ks::settings::DetailDisplayScheme::Floating && scheme != m_scheme)
        {
            destroyFloatingWindow();
            if (self.isNull())
            {
                return;
            }
        }
        const bool changed = m_scheme != scheme;
        m_scheme = scheme;
        if (changed)
        {
            ++m_bindingGeneration;
        }
        if (!m_toggleBar.isNull() && !applyLayoutStep([this, scheme]()
            { m_toggleBar->setVisible(scheme == ks::settings::DetailDisplayScheme::BottomCollapsed); }))
        {
            return;
        }
        if (!applyLayoutStep([this]() { m_tablePane->setVisible(true); })
            || !applyLayoutStep([this]() { m_tablePane->setMinimumSize(0, 0); })
            || !applyLayoutStep([this]() { m_tablePane->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX); }))
        {
            return;
        }
        switch (scheme)
        {
        case ks::settings::DetailDisplayScheme::Right:
            applyRightStrategy(changed);
            break;
        case ks::settings::DetailDisplayScheme::Embedded:
            applyInlineStrategy(changed);
            break;
        case ks::settings::DetailDisplayScheme::Floating:
            applyFloatingStrategy(changed);
            break;
        case ks::settings::DetailDisplayScheme::BottomCollapsed:
        default:
            applyBottomStrategy(changed);
            break;
        }
        if (!self.isNull() && self->isBound())
        {
            self->updateEmbeddedEditorGeometries();
        }
    }

    void DetailLayoutHost::setManagedSplitterSizes(const int tableSize, const int toggleSize, const int detailSize)
    {
        if (!m_splitter.isNull())
        {
            m_splitter->setSizes({std::max(1, tableSize), std::max(0, toggleSize), std::max(0, detailSize)});
        }
    }

    void DetailLayoutHost::updateBottomExpanded(const bool expanded)
    {
        if (m_scheme != ks::settings::DetailDisplayScheme::BottomCollapsed || !isBound())
        {
            return;
        }
        m_bottomExpanded = expanded;
        if (!applyLayoutStep([this]() { m_detailPane->setMinimumHeight(0); })
            || !applyLayoutStep([this, expanded]() { m_detailPane->setMaximumHeight(expanded ? QWIDGETSIZE_MAX : 0); })
            || !applyLayoutStep([this, expanded]() { m_detailPane->setVisible(expanded); }))
        {
            return;
        }
        if (!m_toggleButton.isNull())
        {
            if (!applyLayoutStep([this, expanded]() { m_toggleButton->setArrowType(expanded ? Qt::DownArrow : Qt::UpArrow); })
                || !applyLayoutStep([this, expanded]()
                {
                    m_toggleButton->setToolTip(ks::i18n::text(
                        expanded ? QStringLiteral("detail.layout.collapse.tooltip") : QStringLiteral("detail.layout.expand.tooltip"),
                        expanded ? QStringLiteral("收起当前行详情") : QStringLiteral("展开当前行详情")));
                }))
            {
                return;
            }
        }
        setManagedSplitterSizes(expanded ? 720 : 1000, 18, expanded ? 240 : 0);
    }

    // 四种策略只负责布局和显隐，文本镜像与业务模型始终保持原来的对象。
    void DetailLayoutHost::applyRightStrategy(const bool changed)
    {
        if (!applyLayoutStep([this]() { m_splitter->setOrientation(Qt::Horizontal); })
            || !applyLayoutStep([this]() { m_detailPane->setMinimumSize(0, 0); })
            || !applyLayoutStep([this]() { m_detailPane->setMaximumSize(QWIDGETSIZE_MAX, QWIDGETSIZE_MAX); })
            || !applyLayoutStep([this]() { m_detailPane->show(); }))
        {
            return;
        }
        if (changed)
        {
            setManagedSplitterSizes(820, 0, 180);
        }
    }

    void DetailLayoutHost::applyInlineStrategy(const bool changed)
    {
        if (!applyLayoutStep([this]() { m_splitter->setOrientation(Qt::Vertical); })
            || !applyLayoutStep([this]() { m_detailPane->hide(); })
            || !applyLayoutStep([this]() { m_detailPane->setMinimumHeight(0); })
            || !applyLayoutStep([this]() { m_detailPane->setMaximumHeight(0); }))
        {
            return;
        }
        if (changed)
        {
            setManagedSplitterSizes(1000, 0, 0);
        }
        refreshEmbeddedIndicators();
    }

    void DetailLayoutHost::applyFloatingStrategy(const bool changed)
    {
        if (!applyLayoutStep([this]() { m_splitter->setOrientation(Qt::Vertical); })
            || !applyLayoutStep([this]() { m_detailPane->hide(); })
            || !applyLayoutStep([this]() { m_detailPane->setMinimumHeight(0); })
            || !applyLayoutStep([this]() { m_detailPane->setMaximumHeight(0); }))
        {
            return;
        }
        if (changed)
        {
            setManagedSplitterSizes(1000, 0, 0);
        }
    }

    void DetailLayoutHost::applyBottomStrategy(const bool changed)
    {
        if (!applyLayoutStep([this]() { m_splitter->setOrientation(Qt::Vertical); }))
        {
            return;
        }
        // 父页面尚未 show 时 isVisible 为 false，仍须明确隐藏默认折叠的详情槽。
        if (changed || (!m_bottomExpanded && !m_detailPane->isHidden()))
        {
            m_bottomExpanded = false;
            updateBottomExpanded(false);
        }
    }
}
