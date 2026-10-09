#pragma once

// ============================================================
// DetailLayoutHost.h
// 作用：
// - 把严格命中页面的“数据视图 + CodeEditorWidget”统一适配为四种详情布局；
// - 页面仍负责生成详情文本，本类只负责布局、展开状态和文本镜像；
// - 使用 QPersistentModelIndex 跟踪源项，行内详情只修改视图几何，不改业务模型。
// ============================================================

#include "../SettingsDock/AppearanceSettings.h"
#include "StructuredFieldView.h"

#include <QList>
#include <QMetaObject>
#include <QObject>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QString>
#include <QVariant>
#include <QtGlobal>
#include <functional>

class CodeEditorWidget;
class QAbstractItemView;
class QAbstractItemDelegate;
class QAbstractItemModel;
class QDialog;
class QEvent;
class QSplitter;
class QToolButton;
class QTreeWidgetItem;
class QWidget;

namespace ks::ui
{
    class EmbeddedRowDelegate;

    // 页面明确给出三个布局对象，宿主不猜测祖先、不替换业务主面板。
    struct DetailPaneBinding
    {
        QSplitter* splitter = nullptr; // 页面拥有的分隔器，可在构造末尾挂载面板。
        QWidget* mainPane = nullptr;   // 直接承载数据视图的完整主面板。
        QWidget* detailPane = nullptr; // 直接承载原详情编辑器的完整详情槽。
    };

    // DetailLayoutHost：单个页面的详情布局控制器。
    // 调用方式：页面完成表格和 CodeEditorWidget 创建后交给 DetailLayoutRegistry 注册。
    class DetailLayoutHost final : public QObject
    {
    public:
        // 构造函数：记录视图、详情编辑器和页面宿主，在页面构造结束后延迟建立统一分隔器。
        // 入参 tableView/detailEditor/ownerWidget：数据视图、原详情控件和页面宿主。
        DetailLayoutHost(
            QAbstractItemView* tableView,
            CodeEditorWidget* detailEditor,
            QWidget* ownerWidget);
        // 新页面使用显式布局入口；暂未加入 splitter 的面板延迟到构造结束后绑定。
        DetailLayoutHost(
            QAbstractItemView* tableView,
            CodeEditorWidget* detailEditor,
            QWidget* ownerWidget,
            const DetailPaneBinding& binding);
        DetailLayoutHost(QAbstractItemView* view, StructuredFieldView* fields, QWidget* owner);
        DetailLayoutHost(QAbstractItemView* view, StructuredFieldView* fields, QWidget* owner,
            const DetailPaneBinding& binding);
        ~DetailLayoutHost() override;

        // setTableView / setDetailEditor：供注册表或页面在延迟创建控件后重新绑定。
        // 入参为目标控件；无业务返回值。
        void setTableView(QAbstractItemView* tableView);
        void setDetailEditor(CodeEditorWidget* detailEditor);
        bool bindPanels(const DetailPaneBinding& binding);
        bool bindModel(QAbstractItemModel* model);
        bool hasExplicitBinding() const;
        bool isBound() const;
        // 通用表视图支持逻辑行高；普通树视图回退到可见右侧槽，不改业务模型 sizeHint。
        bool supportsInlineDetails() const;
        ks::settings::DetailDisplayScheme requestedScheme() const;
        ks::settings::DetailDisplayScheme effectiveScheme() const;

        // applyScheme：切换当前页面布局；会清理旧模式的临时行内视图/窗口状态。
        void applyScheme(ks::settings::DetailDisplayScheme scheme);

        // clearEmbeddedDetails：移除所有行内详情并恢复源行图标。
        void clearEmbeddedDetails();

        // prepareDataRebuild：页面重建表格数据前调用；取消旧排队点击并清理行内详情。
        void prepareDataRebuild();

        // detailEditor：返回当前页面原始 CodeEditorWidget，供注册表去重。
        CodeEditorWidget* detailEditor() const;
        StructuredFieldView* structuredView() const;
        QWidget* detailWidget() const;

    protected:
        // eventFilter：监听独立窗口激活状态，按要求切换 100%/30% 不透明度。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // EmbeddedEntry：保存一个源行与其行内详情控件的稳定对应关系。
        struct EmbeddedEntry
        {
            QPersistentModelIndex sourceIndex;
            QPointer<CodeEditorWidget> textEditor;
            QPointer<StructuredFieldView> fieldView;
            QPointer<QWidget> editorWidget;
            QTreeWidgetItem* treeSourceItem = nullptr;
            int originalRowHeight = -1;
            int detailHeight = 128;
            QVariant originalSizeHint;
        };

        // initializeHostUi / scheduleHostUiInitialization / initializeConnections：
        // 延迟到页面构造完成后创建统一分隔器、箭头并绑定文本/点击事件。
        void initializeHostUi();
        void scheduleHostUiInitialization();
        void initializeConnections();

        // ensureManagedSplitter：复用既有分隔器或把直接布局中的表格/详情包装进新分隔器。
        void ensureManagedSplitter();
        // 旧 registerHost 唯一允许推断父布局的兼容适配层。
        void resolveCompatiblePanels();
        void observeModel();
        void disconnectViewBindings();
        void applyRightStrategy(bool changed);
        void applyInlineStrategy(bool changed);
        void applyFloatingStrategy(bool changed);
        void applyBottomStrategy(bool changed);
        bool applyLayoutStep(std::function<void()> step);

        // updateBottomExpanded：更新下方详情显隐、箭头方向和默认分隔比例。
        void updateBottomExpanded(bool expanded);
        void setManagedSplitterSizes(int tableSize, int toggleSize, int detailSize);

        // handleViewClicked：按当前方案处理一次用户行点击。
        void handleViewClicked(const QPersistentModelIndex& sourceIndex);

        // handleDetailChanged：同步原详情文本到当前行内视图或独立窗口。
        void handleDetailChanged(const QString& detailText);
        void handleFieldDocumentChanged();

        // toggleEmbeddedDetail：为当前源行显示或移除统一只读报告详情。
        void toggleEmbeddedDetail(const QPersistentModelIndex& sourceIndex);

        // insertTableEmbeddedDetail / insertTreeEmbeddedDetail：
        // 只扩展源行的视图高度并覆盖只读文本框，不向业务模型插入任何行或节点。
        void insertTableEmbeddedDetail(const QPersistentModelIndex& sourceIndex, const QString& detailText);
        void insertTreeEmbeddedDetail(const QPersistentModelIndex& sourceIndex, const QString& detailText);

        // installEmbeddedRowDelegate / restoreEmbeddedRowDelegate：
        // 仅在存在展开行时安装绘制包装器，并在最后一行收起时恢复页面原 delegate。
        void installEmbeddedRowDelegate();
        void restoreEmbeddedRowDelegate();

        // embeddedOriginalRowHeight：按当前绘制索引返回展开前行高，非展开行返回 -1。
        int embeddedOriginalRowHeight(const QModelIndex& modelIndex) const;

        // removeEmbeddedEntry：移除指定源行的行内详情；返回 true 表示已找到并移除。
        bool removeEmbeddedEntry(const QPersistentModelIndex& sourceIndex);

        // 行内详情布局与指示器均在视图层维护，批量节点按事件循环分片处理。
        void updateEmbeddedEditorGeometries();
        void restoreEmbeddedEntryLayout(const EmbeddedEntry& entry);
        void refreshEmbeddedIndicators();
        void scheduleEmbeddedIndicatorRefresh();
        void queueEmbeddedIndicatorRows(const QModelIndex& parentIndex, int firstRow, int lastRow);
        void processEmbeddedIndicatorBatch(quint64 generation);
        void restoreEmbeddedIndicators();
        void setSourceExpandedIndicator(const QPersistentModelIndex& sourceIndex, bool expanded);
        void installEmbeddedIndicator(const QPersistentModelIndex& sourceIndex, bool expanded);

        // showFloatingWindow / destroyFloatingWindow：管理当前页面唯一的非模态详情窗口。
        void showFloatingWindow();
        void destroyFloatingWindow();

        QPointer<QAbstractItemView> m_tableView;       // m_tableView：页面原始表格或树。
        QPointer<CodeEditorWidget> m_detailEditor;     // m_detailEditor：页面原始详情编辑器。
        QPointer<StructuredFieldView> m_structuredView;
        QPointer<QWidget> m_ownerWidget;               // m_ownerWidget：生命周期宿主。
        QPointer<QSplitter> m_splitter;                // m_splitter：统一承载表格和原详情区。
        QPointer<QWidget> m_tablePane;                 // m_tablePane：分隔器中承载业务表格的完整面板。
        QPointer<QWidget> m_detailPane;                // m_detailPane：分隔器中的完整详情面板。
        QPointer<QSplitter> m_requestedSplitter;       // 显式布局构造期间的分隔器。
        QPointer<QWidget> m_requestedMainPane;         // 显式主面板，禁止退回祖先推断。
        QPointer<QWidget> m_requestedDetailPane;       // 显式详情槽，禁止接管整个页面。
        QPointer<QAbstractItemModel> m_observedModel;  // 当前 signal 所属模型。
        QList<QMetaObject::Connection> m_viewConnections; // 点击、滚动等视图连接句柄。
        QList<QMetaObject::Connection> m_modelConnections; // 换模型时明确断开的连接句柄。
        QMetaObject::Connection m_editorConnection;    // 原详情文本镜像连接。
        QMetaObject::Connection m_toggleConnection;    // 箭头连接，不用动态属性去重。
        QPointer<QWidget> m_toggleBar;                  // m_toggleBar：占满页面宽度的箭头承载条，避免固定宽按钮压窄分隔器。
        QPointer<QToolButton> m_toggleButton;           // m_toggleButton：下方折叠方案的箭头按钮。
        QPointer<QDialog> m_floatingWindow;             // m_floatingWindow：当前页面唯一详情窗口。
        QPointer<StructuredFieldView> m_floatingFields;
        QPointer<CodeEditorWidget> m_floatingEditor;    // m_floatingEditor：独立窗口中的只读镜像编辑器。
        QPointer<QAbstractItemDelegate> m_embeddedSourceDelegate; // m_embeddedSourceDelegate：行内展开前页面正在使用的 delegate。
        QPointer<EmbeddedRowDelegate> m_embeddedRowDelegate; // m_embeddedRowDelegate：限制展开行源单元格绘制区域的包装 delegate。
        QList<EmbeddedEntry> m_embeddedEntries;         // m_embeddedEntries：当前已展开的多行详情。
        QList<EmbeddedEntry> m_layoutRestorations;       // 排序后再按重映射索引还原逻辑行高。
        ks::settings::DetailDisplayScheme m_scheme =
            ks::settings::DetailDisplayScheme::BottomCollapsed;
        ks::settings::DetailDisplayScheme m_requestedScheme =
            ks::settings::DetailDisplayScheme::BottomCollapsed; // 保留全局请求，能力回退不改设置。
        bool m_constructing = true;                     // 构造期间只排队，避免 Show 回调销毁半构造宿主。
        bool m_bottomExpanded = false;                  // m_bottomExpanded：下方详情是否展开。
        bool m_explicitBinding = false;                 // 是否启用页面显式布局契约。
        quint64 m_bindingGeneration = 0;                // 取消换布局/模型前 queued 点击。
        bool m_hostUiInitializationScheduled = false;   // m_hostUiInitializationScheduled：页面构造结束后的延迟初始化是否已排队。
        bool m_indicatorBatchScheduled = false;         // m_indicatorBatchScheduled：节点图标分片任务是否已排队。
        bool m_indicatorRefreshScheduled = false;       // m_indicatorRefreshScheduled：批量数据更新后的图标刷新是否已合并。
        quint64 m_indicatorGeneration = 0;              // m_indicatorGeneration：取消过期图标遍历的代次。
        QList<QPersistentModelIndex> m_indicatorIndexes; // m_indicatorIndexes：已保存原始图标的源项。
        QList<QPersistentModelIndex> m_pendingIndicatorIndexes; // m_pendingIndicatorIndexes：待分片处理的源项。
    };
}
