#pragma once

// ============================================================
// GlobalUiSearch.h
// 作用：
// 1) 提供标题栏“搜索”模式的全局页面文本搜索：
//    遍历各主功能 Dock 的控件树，收集标签/按钮/分组框/页签/表头/
//    占位符/下拉项等可见文本并做关键词匹配；
// 2) 在标题栏输入框下方弹出结果面板，每条结果直接显示
//    匹配文本与“Dock › 内部页签 › 分组”形式的页面路径；
// 3) 激活结果时自动初始化并置前目标 Dock、逐层切换内部
//    Tab/Stacked 页、滚动到目标控件，并以主题强调色脉冲高亮；
// 4) 组件不直接依赖 MainWindow：Dock 列表、懒加载初始化与
//    Dock 激活均通过回调注入，便于复用与单元验证。
// ============================================================

#include <QObject>
#include <QList>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QString>
#include <QVector>

#include <functional>

class QCheckBox;
class QEvent;
class QFrame;
class QLabel;
class QLineEdit;
class QListWidget;
class QProgressBar;
class QTabBar;
class QTableView;
class QTimer;
class QWidget;

namespace ads
{
    class CDockWidget;
}

namespace ks::ui
{
    // UiSearchScope：标题栏搜索的三个作用域，Tab/Shift+Tab 循环切换。
    enum class UiSearchScope
    {
        Global,
        CurrentPage,
        CurrentTable
    };

    // ============================================================
    // UiSearchHit
    // 说明：
    // - 描述一条页面文本搜索命中；
    // - dock 与目标控件都用 QPointer 持有，激活时先判空防止悬空。
    // ============================================================
    struct UiSearchHit
    {
        QPointer<ads::CDockWidget> pageDockWidget; // pageDockWidget：命中文本所属的主功能 Dock。
        QPointer<QWidget> targetWidget;            // targetWidget：承载命中文本的具体控件（页签命中时为页签对应页面）。
        QPointer<QTableView> targetTableView;      // targetTableView：表格单元格命中所属表格，普通 UI 命中为空。
        QPersistentModelIndex targetModelIndex;    // targetModelIndex：表格单元格命中的稳定模型索引。
        QString matchedText;                       // matchedText：命中控件的完整原始文本（单行化处理后）。
        QString pagePathText;                      // pagePathText：形如“内核 › 回调审计”的页面路径文本。
        int matchRank = 2;                         // matchRank：排序权重（0=整串相等，1=前缀，2=包含）。
    };

    // ============================================================
    // GlobalUiSearchController
    // 说明：
    // - 标题栏搜索模式的总控：防抖搜索、结果弹层、键盘导航、
    //   结果激活跳转与目标高亮；
    // - 弹层实现为宿主主窗口的子控件（非独立顶层窗口），
    //   避免无边框窗口下焦点/激活状态被弹窗抢占。
    // ============================================================
    class GlobalUiSearchController final : public QObject
    {
        Q_OBJECT

    public:
        // DockListProvider：返回参与搜索的 Dock 列表（按展示顺序）。
        using DockListProvider = std::function<QList<ads::CDockWidget*>()>;
        // DockPreparer：确保 Dock 懒加载内容已初始化（重入安全）。
        using DockPreparer = std::function<void(ads::CDockWidget*)>;
        // DockActivator：把 Dock 置前并设为当前页签（含关闭态恢复）。
        using DockActivator = std::function<void(ads::CDockWidget*)>;

        // 构造函数：
        // - 作用：创建搜索控制器并安装输入框/应用级事件过滤器；
        // - 调用：MainWindow 初始化标题栏后创建；
        // - 传入 popupHostWindow：结果弹层的父窗口（主窗口）；
        // - 传入 searchInputEdit：标题栏中间输入框；
        // - 传入 popupAnchorWidget：弹层水平对齐的锚点控件（输入组容器）；
        // - 传入 parentObject：Qt 父对象。
        GlobalUiSearchController(
            QWidget* popupHostWindow,
            QLineEdit* searchInputEdit,
            QWidget* popupAnchorWidget,
            QObject* parentObject = nullptr);

        // 析构函数：撤销仍然生效的通用表格行过滤。
        ~GlobalUiSearchController() override;

        // setDockListProvider：
        // - 作用：注入参与搜索的 Dock 列表回调；
        // - 调用：MainWindow 接线时调用一次。
        void setDockListProvider(DockListProvider dockListProvider);

        // setDockPreparer：
        // - 作用：注入 Dock 懒加载初始化回调（搜索前逐个调用）；
        // - 调用：MainWindow 接线时调用一次。
        void setDockPreparer(DockPreparer dockPreparer);

        // setDockActivator：
        // - 作用：注入 Dock 置前激活回调（激活结果时调用）；
        // - 调用：MainWindow 接线时调用一次。
        void setDockActivator(DockActivator dockActivator);

        // activateForTable：
        // - 作用：由表格内搜索框/按钮切到“当前表格”范围，并同步顶部输入框；
        // - focusTopInput=true 时把键盘焦点跳到顶部，false 时保留表格内输入焦点。
        void activateForTable(
            QTableView* tableView,
            const QString& queryText,
            bool focusTopInput);

        // searchScopeDisplayText：返回标题栏当前应展示的范围文本。
        QString searchScopeDisplayText() const;

    signals:
        // requestSearchInputActivation：请求标题栏切回搜索模式，可选择是否抢占焦点。
        void requestSearchInputActivation(bool focusTopInput);

        // searchScopeDisplayTextChanged：范围变化后刷新标题栏模式标签和提示。
        void searchScopeDisplayTextChanged(const QString& displayText);


    public slots:
        // handleQueryEdited：
        // - 作用：接收标题栏搜索文本变化并触发防抖搜索；
        // - 触发：CustomTitleBar::searchTextEdited；
        // - 传入 queryText：当前输入框文本（未修剪）。
        void handleQueryEdited(const QString& queryText);

        // setSearchInputActive：
        // - 作用：同步标题栏当前是否处于“搜索”输入模式；
        // - 触发：CustomTitleBar::inputModeChanged；
        // - 传入 searchModeActive：false 时立即收起结果弹层。
        void setSearchInputActive(bool searchModeActive);

        // setSearchResultsOnly：切换通用表格的结果专显过滤。
        void setSearchResultsOnly(bool checked);

        // dismissPopup：
        // - 作用：收起结果弹层并停止未决的防抖搜索。
        void dismissPopup();

    protected:
        // eventFilter：
        // - 作用：
        //   1) 输入框：Up/Down 选择结果、Enter 激活、Esc 收起、
        //      聚焦时按需重新展示结果；
        //   2) 宿主窗口：尺寸/位置变化时重新贴齐弹层、失活时收起；
        //   3) 应用级：点击弹层与输入组之外区域时收起。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    private:
        // ensurePopupCreated：
        // - 作用：首次需要时构建搜索选项、结果列表与空态提示。
        void ensurePopupCreated();

        // refreshSearchOptionControls：同步弹层中的范围下拉与结果专显状态。
        void refreshSearchOptionControls();

        // showOptionsOnlyPopup：空查询时仍显示可操作的搜索范围与结果专显控件。
        void showOptionsOnlyPopup();

        // runSearchNow：
        // - 作用：启动一次异步分片搜索（防抖定时器到期或显式触发）；
        // - 说明：查询过短时等效于收起弹层；每次启动都会使在途扫描作废，
        //   相同查询已在扫描中时直接续用当前扫描。
        void runSearchNow();

        // processNextSearchChunk：
        // - 作用：处理一个搜索分片（初始化并扫描一个 Dock），
        //   然后通过 singleShot(0) 让出事件循环再排下一片；
        // - 传入 searchGeneration：本次搜索的代数，与当前代数不符时
        //   说明扫描已被新搜索/取消替代，直接丢弃。
        void processNextSearchChunk(quint64 searchGeneration);

        // finishAsyncSearch：
        // - 作用：所有分片完成（或命中封顶）后收尾：排序命中、
        //   隐藏进度行、填充结果列表并按结果尺寸重排弹层。
        void finishAsyncSearch();

        // updateSearchProgressUi：
        // - 作用：刷新进度行文案“正在搜索：Dock 名（n/N）”；
        // - 传入 dockTitleText：当前正在扫描的 Dock 标题。
        void updateSearchProgressUi(const QString& dockTitleText);

        // rebuildResultList：
        // - 作用：按命中列表重建弹层列表项（含富文本高亮与路径行）。
        void rebuildResultList();

        // showPopupPanel：
        // - 作用：应用当前主题样式、计算尺寸并显示/置前弹层。
        void showPopupPanel();

        // repositionPopupPanel：
        // - 作用：把弹层水平居中贴到锚点下方并夹取进宿主窗口范围。
        void repositionPopupPanel();

        // activateHitAtRow：
        // - 作用：激活列表某一行对应的搜索命中；
        // - 传入 rowIndex：列表行号，越界时忽略。
        void activateHitAtRow(int rowIndex);

        // moveSelection：
        // - 作用：键盘上下键在结果列表中移动当前行（带边界夹取）；
        // - 传入 rowDelta：+1 向下，-1 向上。
        void moveSelection(int rowDelta);

        // isQueryLongEnough：
        // - 作用：判断查询是否达到最小搜索长度；
        // - 规则：≥2 个字符，或单个 CJK 等宽字符（U+2E80 起）。
        static bool isQueryLongEnough(const QString& queryText);

        // isCurrentQueryLongEnough：当前表格允许任意单字符，其余范围沿用全局降噪规则。
        bool isCurrentQueryLongEnough(const QString& queryText) const;

        // setSearchScope/cycleSearchScope：设置或循环搜索范围，并重启当前查询。
        void setSearchScope(UiSearchScope searchScope);
        void cycleSearchScope(int direction);

        // resolveCurrentPageDock/resolveCurrentTable：从最近交互上下文解析当前页面与表格。
        ads::CDockWidget* resolveCurrentPageDock() const;
        QTableView* resolveCurrentTable() const;

        // refreshSearchScopeDisplayText：生成“全局/当前页面/当前表格（名称）”并通知标题栏。
        void refreshSearchScopeDisplayText();

        // clear/applySearchResultFilters：按当前范围撤销或应用通用表格行过滤。
        void clearSearchResultFilters();
        void applySearchResultFilterToTable(QTableView* tableView);
        void applySearchResultFiltersToDock(
            ads::CDockWidget* dockWidget,
            bool visiblePageOnly);

    private:
        QPointer<QWidget> m_popupHostWindow;      // m_popupHostWindow：弹层父窗口（主窗口）。
        QPointer<QLineEdit> m_searchInputEdit;    // m_searchInputEdit：标题栏中间输入框。
        QPointer<QWidget> m_popupAnchorWidget;    // m_popupAnchorWidget：弹层对齐锚点（输入组容器）。

        DockListProvider m_dockListProvider;      // m_dockListProvider：Dock 列表回调。
        DockPreparer m_dockPreparer;              // m_dockPreparer：Dock 懒加载初始化回调。
        DockActivator m_dockActivator;            // m_dockActivator：Dock 置前激活回调。

        QFrame* m_popupPanel = nullptr;           // m_popupPanel：结果弹层容器（宿主窗口子控件）。
        QWidget* m_searchOptionsRow = nullptr;    // m_searchOptionsRow：范围与结果专显选项行。
        QLabel* m_searchScopeLabel = nullptr;     // m_searchScopeLabel：搜索范围标签。
        QTabBar* m_searchScopeTabs = nullptr;     // m_searchScopeTabs：全局/当前页面/当前表格横向切换。
        QCheckBox* m_searchResultsOnlyCheck = nullptr; // m_searchResultsOnlyCheck：仅显示命中行。
        QListWidget* m_resultListWidget = nullptr;// m_resultListWidget：结果列表。
        QLabel* m_emptyHintLabel = nullptr;       // m_emptyHintLabel：无结果时的空态提示。
        QWidget* m_searchProgressRow = nullptr;   // m_searchProgressRow：扫描进行中的进度行容器。
        QLabel* m_searchProgressLabel = nullptr;  // m_searchProgressLabel：进度文案“正在搜索：Dock 名（n/N）”。
        QProgressBar* m_searchProgressBar = nullptr; // m_searchProgressBar：按 Dock 数推进的进度条。
        QTimer* m_searchDebounceTimer = nullptr;  // m_searchDebounceTimer：输入防抖定时器。

        QString m_pendingQueryText;               // m_pendingQueryText：最近一次输入的查询文本。
        QString m_activeQueryText;                // m_activeQueryText：当前异步扫描采用的查询快照。
        QVector<UiSearchHit> m_currentHitList;    // m_currentHitList：当前命中列表（完成后与列表行一一对应）。
        QList<QPointer<ads::CDockWidget>> m_pendingSearchDockList; // m_pendingSearchDockList：本次扫描的 Dock 快照队列。
        int m_nextSearchDockIndex = 0;            // m_nextSearchDockIndex：下一个待扫描 Dock 的队列索引。
        quint64 m_searchGeneration = 0;           // m_searchGeneration：搜索代数；新搜索/取消时自增使在途分片作废。
        bool m_searchInProgress = false;          // m_searchInProgress：当前是否有异步扫描在进行。
        bool m_searchModeActive = true;           // m_searchModeActive：标题栏是否处于搜索输入模式。
        bool m_showPopupOnNextSearchInputFocus = false; // m_showPopupOnNextSearchInputFocus：仅表格搜索入口允许下一次顶部输入框获焦时展开弹层。
        bool m_searchResultsOnly = false;         // m_searchResultsOnly：是否隐藏通用表格中的非命中行。
        UiSearchScope m_searchScope = UiSearchScope::Global; // m_searchScope：用户当前选择的搜索范围。
        UiSearchScope m_activeSearchScope = UiSearchScope::Global; // m_activeSearchScope：在途搜索采用的范围快照。
        QPointer<QTableView> m_targetTableView;     // m_targetTableView：表格入口显式指定的目标表格。
        QPointer<QTableView> m_recentTableView;     // m_recentTableView：最近鼠标/键盘交互过的表格。
        QPointer<ads::CDockWidget> m_recentPageDockWidget; // m_recentPageDockWidget：最近交互控件所属 Dock。
        QPointer<QTableView> m_pendingDirectTableView; // m_pendingDirectTableView：当前表格范围待扫描对象。
        QList<QPointer<QTableView>> m_filteredTableViewList; // m_filteredTableViewList：当前由通用搜索附加过滤的表格。
    };

    // ActivateGlobalUiSearchForTable：表格通用入口调用当前主窗口搜索控制器。
    void ActivateGlobalUiSearchForTable(
        QTableView* tableView,
        const QString& queryText = QString(),
        bool focusTopInput = true);
}
