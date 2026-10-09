#pragma once

// ============================================================
// RegistryDock.h
// 作用：
// 1) 提供类似 regedit 的注册表浏览与编辑能力；
// 2) 支持键树导航、值表展示、创建/删除/重命名/编辑；
// 3) 支持 .reg 导入导出与后台全文搜索，避免阻塞 UI。
// ============================================================

#include "../Framework.h"
#include "../UI/AsyncUiDispatcher.h"

#include <QWidget>
#include <QVector>
#include <QStringList>

#include <atomic>      // std::atomic_bool：搜索线程运行状态控制。
#include <deque>       // std::deque：搜索结果 FIFO 队列，避免头部消费搬移。
#include <memory>      // std::unique_ptr：后台线程对象托管。
#include <mutex>       // std::mutex：跨线程结果队列保护。
#include <thread>      // std::thread：后台搜索线程。
#include <vector>      // std::vector：结果缓存与历史路径容器。

// Qt 前置声明：降低头文件耦合，减少编译时长。
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QSplitter;
class QStatusBar;
class QTabWidget;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class RegistryOptimizationPage;
class RegistryValueEditorWidget;
class QComboBox;
class QCheckBox;
class QTabBar;
class QScrollArea;
struct RegistryDocument;
struct RegistryAccessContext;
struct RegistryKeyListing;
struct RegistryApplyResult;

// ============================================================
// RegistryDock
// 说明：
// - 左侧树：注册表键层级导航；
// - 右侧表：当前键的值列表与搜索结果；
// - 所有重型操作（搜索/导入导出）在后台线程执行。
// ============================================================
class RegistryDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：初始化 UI、根键节点与信号槽；
    // - 参数 parent：Qt 父控件。
    explicit RegistryDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：安全停止后台搜索线程与刷新计时器。
    ~RegistryDock() override;

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void changeEvent(QEvent* event) override;

private:
    // SearchOptions：
    // - 作用：封装搜索时的匹配范围选项。
    struct SearchOptions
    {
        bool searchKeyName = true;      // 是否匹配键名。
        bool searchValueName = true;    // 是否匹配值名。
        bool searchValueData = true;    // 是否匹配值数据文本。
        bool caseSensitive = false;     // 是否大小写敏感。
        bool recursive = true;
        bool exactMatch = false;
        int viewBits = 0;
        int valueType = -1;
        QByteArray binaryPattern;
        int maximumDepth = 128;
        quint64 generation = 0;
    };

    struct PendingValueChange
    {
        QString keyPath;
        QString name;
        DWORD beforeType = REG_NONE;
        QByteArray beforeData;
        bool beforeExists = false;
        DWORD afterType = REG_NONE;
        QByteArray afterData;
        bool deleteValue = false;
        int viewBits = 0;
        bool useR0 = false;
        QString result;
    };

    // PendingSearchRow：
    // - 作用：后台搜索线程产生的待刷入 UI 行数据。
    struct PendingSearchRow
    {
        QString keyPathText;            // 命中的键完整路径。
        QString valueNameText;          // 命中的值名（键命中时可为空）。
        QString rawValueName;           // 值的原始 Win32 名称；默认值为真正的空字符串。
        QString valueTypeText;          // 值类型（键命中时为<Key>）。
        QString valueDataPreviewText;   // 值数据预览。
        QString hitSourceText;          // 命中来源（KeyName/ValueName/ValueData）。
        bool isKeyResult = false;       // 是否为键命中；false 时为值命中。
        int viewBits = 0;               // 搜索启动时真实 WOW64 视图。
        bool useR0 = false;              // 此行实际来源，HKCR 保留 Win32 合并语义。
    };

private:
    // ===================== UI 初始化 =====================
    void initializeUi();
    void initializeConnections();
    void initializeRootItems();
    void initializeWorkbenchControls();
    RegistryAccessContext accessContext() const;
    RegistryAccessContext accessContextForPath(const QString& path) const;
    void loadSelectedValue();
    bool preserveEditorDraft();
    bool stageEditorValue();
    void discardEditorValue();
    void updatePendingChanges();
    void applyPendingChanges();
    void restoreLastChanges();
    void filterCurrentValues();
    void appendValueRows(const std::shared_ptr<const RegistryKeyListing>& listing,
        int offset, quint64 generation, const QString& selectedName);
    void showNavigationMenu();
    void addLocationTab(const QString& path);
    void backupCurrentKey();
    void restoreBackup();
    // 预览与提交保留调用方冻结通道；文档已携带明确的 WOW64 视图。
    void previewRegistryDocument(const RegistryDocument& document, const QString& title, bool useR0 = false);
    void showKeyPermissions();
    void openOfflineHive();
    void openRelatedItem();

    // ===================== 导航与刷新 =====================
    void navigateToPath(const QString& registryPath, bool recordHistory);
    void refreshCurrentKey(bool keepSelection);
    void refreshValueTable();
    void updateStatusBar(const QString& messageText);
    void selectTreeItemByPath(const QString& registryPath);
    void ensureTreeItemLoaded(QTreeWidgetItem* item);

    // ===================== 右键菜单与编辑 =====================
    void showTreeContextMenu(const QPoint& localPos);
    void showValueContextMenu(const QPoint& localPos);
    void createSubKey();
    void createValue();
    void renameSelectedObject();
    void deleteSelectedObject();
    // deleteSearchResultValue：
    // - 作用：按搜索行保存的完整键路径与原始值名删除一个注册表值。
    // - 说明：捕获目标和视图/通道，暂存后由共享事务提交。
    void deleteSearchResultValue(const QString& keyPath, const QString& rawValueName,
        const RegistryAccessContext* capturedContext = nullptr);
    // deleteSearchResultKey：
    // - 作用：按搜索行保存的完整键路径递归删除一个非根注册表键。
    // - 说明：当前浏览位置落在目标子树内时，删除后回退到目标父键。
    void deleteSearchResultKey(const QString& keyPath,
        const RegistryAccessContext* capturedContext = nullptr);
    void editSelectedValue();
    void copyCurrentPathToClipboard();
    // copyCurrentKernelPathToClipboard：
    // - 作用：把当前键路径转换为 \REGISTRY\... 后写入剪贴板。
    void copyCurrentKernelPathToClipboard();
    // copySelectedValueKernelPathToClipboard：
    // - 作用：把当前值（或当前键）路径转换为 \REGISTRY\... 后写入剪贴板。
    void copySelectedValueKernelPathToClipboard();
    // readSelectedValueByR0：
    // - 作用：通过 KswordARK 驱动读取当前选中注册表值。
    void readSelectedValueByR0();
    // readDefaultValueByR0：
    // - 作用：通过 KswordARK 驱动读取当前键默认值。
    void readDefaultValueByR0();
    // readRegistryValueByR0：
    // - 作用：内部公共实现，输入值名后调用 R0 只读 IOCTL。
    void readRegistryValueByR0(const QString& valueName);
    // refreshRegistryDriverModeIndicator：
    // - 作用：刷新路径栏后的 R0 注册表读写状态标识。
    void refreshRegistryDriverModeIndicator();
    // shouldUseRegistryR0：
    // - 作用：判断当前注册表页是否应优先使用驱动读写。
    bool shouldUseRegistryR0() const;
    // ===================== 导入导出 =====================
    void exportCurrentKeyAsync();
    void importRegFileAsync();

    // ===================== 搜索能力 =====================
    void startSearchAsync();
    void stopSearch(bool waitForThread);
    void flushPendingSearchRows();
    void enqueuePendingSearchRow(PendingSearchRow&& row);
    void searchRegistryRecursive(
        HKEY rootKey,
        const QString& subPath,
        const QString& keyword,
        const SearchOptions& options,
        std::size_t* scannedKeyCount,
        std::size_t* hitCount);
    // searchRegistryRecursiveByR0：
    // - 作用：R0 在线时用驱动枚举完成后台搜索，避免搜索路径绕回 Win32。
    void searchRegistryRecursiveByR0(
        const QString& kernelKeyPath,
        const QString& displayKeyPath,
        const QString& keyword,
        const SearchOptions& options,
        std::size_t* scannedKeyCount,
        std::size_t* hitCount);
    void searchRegistryPath(const QString& path, bool useR0, const QString& keyword,
        const SearchOptions& options, std::size_t* scanned, std::size_t* hits);

    // ===================== WinAPI 工具 =====================
    static bool parseRegistryPath(const QString& pathText, HKEY* rootKeyOut, QString* subPathOut);
    static QString normalizeRegistryPath(const QString& pathText);
    static QString rootKeyToText(HKEY rootKey);
    static QString valueTypeToText(DWORD valueType);
    static QString formatValueData(DWORD valueType, const QByteArray& valueData);
    static QString winErrorText(LONG errorCode);

private:
    // ===================== 顶层布局 =====================
    QVBoxLayout* m_rootLayout = nullptr;         // 根布局。
    QTabWidget* m_registryTabWidget = nullptr;   // 注册表 Dock 顶层 Tab（编辑/系统优化）。
    QWidget* m_registryEditorPage = nullptr;     // 现有注册表编辑页容器。
    QVBoxLayout* m_registryEditorLayout = nullptr; // 注册表编辑页内部布局。
    RegistryOptimizationPage* m_optimizationPage = nullptr; // JSON 驱动的系统优化页。
    QWidget* m_toolBarWidget = nullptr;          // 顶部工具栏容器。
    QHBoxLayout* m_toolBarLayout = nullptr;      // 顶部工具栏布局。

    // ===================== 顶部控件 =====================
    QPushButton* m_backButton = nullptr;         // 后退导航按钮。
    QPushButton* m_forwardButton = nullptr;      // 前进导航按钮。
    QPushButton* m_refreshButton = nullptr;      // 刷新按钮。
    QPushButton* m_newKeyButton = nullptr;       // 新建键按钮。
    QPushButton* m_newValueButton = nullptr;     // 新建值按钮。
    QPushButton* m_renameButton = nullptr;       // 重命名按钮。
    QPushButton* m_deleteButton = nullptr;       // 删除按钮。
    QPushButton* m_importButton = nullptr;       // 导入 .reg 按钮。
    QPushButton* m_exportButton = nullptr;       // 导出 .reg 按钮。
    QPushButton* m_searchButton = nullptr;       // 启动搜索按钮。
    QPushButton* m_stopSearchButton = nullptr;   // 停止搜索按钮。
    QLineEdit* m_pathEdit = nullptr;             // 路径输入框。
    QLabel* m_driverRegistryModeLabel = nullptr; // R0 注册表读写状态标识。
    QLineEdit* m_searchEdit = nullptr;           // 搜索关键字输入框。

    // ===================== 主体区域 =====================
    QSplitter* m_mainSplitter = nullptr;         // 左右分割器。
    QTreeWidget* m_keyTree = nullptr;            // 注册表键树。
    QTabWidget* m_rightTabWidget = nullptr;      // 右侧 Tab（值/搜索结果）。
    QTableWidget* m_valueTable = nullptr;        // 当前键值列表。
    QTableWidget* m_searchResultTable = nullptr; // 搜索结果表。

    // ===================== 状态栏 =====================
    QStatusBar* m_statusBar = nullptr;           // 状态栏。
    QLabel* m_pathStatusLabel = nullptr;         // 当前路径文本。
    QLabel* m_summaryStatusLabel = nullptr;      // 摘要状态文本。

    // ===================== 导航状态 =====================
    QString m_currentPath;                       // 当前选中注册表路径。
    std::vector<QString> m_navigationHistory;    // 导航历史。
    int m_navigationIndex = -1;                  // 当前历史索引。

    // ===================== 搜索线程状态 =====================
    std::atomic_bool m_searchRunning{ false };   // 搜索线程是否运行中。
    std::atomic_bool m_searchStopFlag{ false };  // 搜索线程停止标志。
    std::unique_ptr<std::thread> m_searchThread; // 搜索线程对象。
    std::shared_ptr<ks::ui::AsyncUiDispatcher> m_uiDispatcher; // 晚到的导入/导出与搜索消息受页面关闭门禁保护。
    std::mutex m_pendingMutex;                   // 待刷入搜索结果队列锁。
    std::deque<PendingSearchRow> m_pendingRows;  // 有界待刷入搜索结果 FIFO 队列。
    QTimer* m_searchFlushTimer = nullptr;        // UI 节流刷新定时器。

    // ===================== 进度与统计 =====================
    int m_progressPid = 0;                       // 进度条任务 PID。
    std::size_t m_searchScannedKeys = 0;         // 搜索扫描键数量统计。
    std::size_t m_searchHitCount = 0;            // 搜索命中数量统计。
    std::atomic_size_t m_searchSkipped{0};
    std::atomic_size_t m_searchDropped{0};
    bool m_lastSearchStopped = false;
    quint64 m_searchGeneration = 0;
    int m_activeLocationIndex = 0;

    QTabBar* m_locationTabs = nullptr;
    QLineEdit* m_filterEdit = nullptr;
    QComboBox* m_viewCombo = nullptr;
    QComboBox* m_searchScopeCombo = nullptr;
    QComboBox* m_searchTypeCombo = nullptr;
    QCheckBox* m_matchKeysCheck = nullptr;
    QCheckBox* m_matchNamesCheck = nullptr;
    QCheckBox* m_matchDataCheck = nullptr;
    QCheckBox* m_matchCaseCheck = nullptr;
    QCheckBox* m_matchExactCheck = nullptr;
    RegistryValueEditorWidget* m_valueEditor = nullptr;
    QScrollArea* m_detailScroll = nullptr;
    QLabel* m_editorContextLabel = nullptr;
    QLabel* m_editorSourceLabel = nullptr;
    QLabel* m_editorStatusLabel = nullptr;
    QPushButton* m_stageButton = nullptr;
    QPushButton* m_discardButton = nullptr;
    QPushButton* m_applyChangesButton = nullptr;
    QTableWidget* m_changesTable = nullptr;
    QStringList m_favoritePaths;
    QString m_editorPath;
    QString m_editorName;
    QByteArray m_editorOriginalData;
    DWORD m_editorOriginalType = REG_NONE;
    bool m_editorReady = false;
    bool m_valuesActive = false;
    QPushButton* m_detailToggle = nullptr;
    int m_editorViewBits = 0;
    bool m_editorUseR0 = false;
    quint64 m_editorGeneration = 0;
    quint64 m_valueLoadGeneration = 0;
    int m_viewBits = 0;
    bool m_applyingChanges = false;
    std::shared_ptr<std::atomic_bool> m_operationsClosed = std::make_shared<std::atomic_bool>(false);
    QVector<PendingValueChange> m_pendingChanges;
    QVector<PendingValueChange> m_lastChanges;
    std::shared_ptr<RegistryApplyResult> m_lastDocumentResult;
    std::shared_ptr<std::atomic_bool> m_documentCancel;
};
