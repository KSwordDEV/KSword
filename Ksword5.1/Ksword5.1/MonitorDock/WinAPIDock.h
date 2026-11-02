#pragma once

namespace ks::monitor { class MonitorCanonicalExport; }

// ============================================================
// WinAPIDock.h
// 作用：
// 1) 提供 “WinAPI” 独立 Dock 页面；
// 2) 负责选择目标进程、配置 Agent DLL 路径并启动 API 监控；
// 3) 通过命名管道接收 APIMonitor_x64 DLL 回传的 API 事件。
// ============================================================

#include "../Framework.h"
#include "WinApiMonitorProtocol.h"
#include "../../../shared/ApiMonitorCoverage.h"
#include "../../../shared/ApiMonitorInjectionBroker.h"

#include "../UI/AsyncUiDispatcher.h"
#include "WinAPISessionBackend.h"
#include "WinAPIEventArchive.h"
#include <QPersistentModelIndex>
#include "../UI/AsyncOperation.h"
#include "UI/RetainedCleanupJob.h"
#include <QByteArray>
#include <QStringList>
#include <QString>  // QString：事件文本、样式文本与会话路径缓存。
#include <QWidget>  // QWidget：WinAPIDock 的直接基类。

#include <atomic>   // std::atomic_bool/std::atomic_uintptr_t：会话线程与管道句柄状态控制。
#include <cstddef>  // std::size_t：待显示事件队列容量与刷新批次大小。
#include <cstdint>  // std::uint32_t/std::uintptr_t：PID 与句柄数值桥接。
#include <deque>    // std::deque：高频事件的有界 FIFO 队列。
#include <memory>   // std::unique_ptr：后台线程对象托管。
#include <mutex>    // std::mutex：保护待刷入事件队列。
#include <thread>   // std::thread：进程刷新与命名管道读取线程。
#include <unordered_map>
#include <vector>   // std::vector：进程快照与待刷新事件缓存。

class WinAPIEventTableModel;
class WinAPIEventFilterModel;

class QCheckBox;
class QComboBox;
class QLineEdit;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QTableView;
class QAbstractItemModel;
class QTabWidget;
class QTableWidgetItem;
class QTimer;
class QSpinBox;
class QToolButton;
class QVBoxLayout;
class QWidget;
class QPoint;

class WinAPIDock final : public QWidget
{
    friend class MonitorDock; // Read already-built result tabs for the cold navigation value catalog.
public:
    // 构造函数：
    // - 作用：初始化 WinAPI 监控页 UI、连接和后台刷新定时器；
    // - 参数 parent：Qt 父控件。
    explicit WinAPIDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：停止命名管道线程，确保对象释放后无后台回调继续访问成员。
    ~WinAPIDock() override;

    // notifyPageActivated：
    // - 作用：在页签真正切换到 WinAPI 页面时触发轻量激活逻辑；
    // - 调用：MonitorDock 切到 WinAPI 子页时调用，用于按需刷新进程快照。
    void notifyPageActivated();

public:
    // EventColumn：
    // - 作用：定义 API 事件表列索引；
    // - 调用：插入事件、导出和右键菜单时统一按列访问。
    enum EventColumn
    {
        EventColumnTime100ns = 0,
        EventColumnCategory,
        EventColumnApi,
        EventColumnResult,
        EventColumnPidTid,
        EventColumnDetail,
        EventColumnCount
    };

    // FakeRuleColumn:
    // - Purpose: keep the Fake Success rule table column indexes stable across UI, validation, and INI serialization.
    // - Use: add/remove/serialize code reads table cells by these constants rather than repeating numeric indexes.
    enum FakeRuleColumn
    {
        FakeRuleColumnModule = 0,
        FakeRuleColumnApi,
        FakeRuleColumnReturnType,
        FakeRuleColumnReturnValue,
        FakeRuleColumnLastErrorKind,
        FakeRuleColumnLastErrorValue,
        FakeRuleColumnX86StackBytes,
        FakeRuleColumnCount
    };

    // EventRow：
    // - 作用：缓存一行待刷入 UI 的 API 事件；
    // - internalEvent：是否是 UI/Agent 自己生成的内部状态事件。
    enum class HookState { Waiting, Installing, Active, Partial, Failed, Removed };

    using EventRow = WinAPIEventRow;
    using CoverageDisplayRow = WinAPICoverageDisplayRow;
    using EventExportSnapshot = WinAPIEventExportSnapshot;
    EventExportSnapshot freezeVisibleEventRowsForExport();

protected:
    // changeEvent 将主题重着色排队，不启动监控或改变任何会话状态。
    void changeEvent(QEvent* event) override;

private:
    void initializeUi();
    void initializeConnections();
    void updateActionState();
    void updateStatusLabel();
    QString eventLossSummary();

    void refreshProcessListAsync();
    void populateProcessSelector(const std::vector<ks::process::ProcessRecord>& processList);
    void updateProcessSelectorStatus();
    bool currentSelectedPid(std::uint32_t* pidOut) const;
    void browseAgentDllPath();

    void startMonitoring();
    void stopMonitoring();
    void stopMonitoringInternal(bool waitForThread);
    void terminateHooksForSelectedProcess();
    QString freezeSessionOptions() const;
    void pollSessionBackend();

    void appendInternalEvent(const QString& categoryText, const QString& apiText, const QString& detailText);
    QString fakeSuccessRulesIniText() const;
    bool validateFakeSuccessRules(QString* errorTextOut) const;
    void addFakeSuccessRuleFromInputs();
    void removeSelectedFakeSuccessRule();

    using CoverageViewState = WinAPICoverageViewState;
    void flushCoverageUpdates();
    void initializeCoverageTable();
    void refreshCoverageDefinitionHash();
    void updateCoverageView();
    void resetCoverageView();
    void markCoverageStale();
    void flushPendingRows();
    void initializeEventProjection();
    void acceptPendingEventRows();
    void applyEventState(const EventRow& rowValue);
    void projectEventRows();
    void initializeEventTailFollow();
    void scheduleEventTailFollow();
    void clearCanonicalEvents();
    WinAPIEventRef eventRecordAt(int row) const;

    void applyEventFilter();
    void clearEventFilter();
    void exportVisibleRowsToTsv();
    void updateEventExportAction();
    void showEventContextMenu(const QPoint& position);
    void showEventDetailDialog(int rowValue);

    static QString blueButtonStyle();
    static QString blueInputStyle();
    static QString blueHeaderStyle();
    static QString eventCategoryText(std::uint32_t categoryValue);
    static QString defaultDllPathHint();
    static QString defaultRawHookModulesText();
    static QString defaultRawHookDenyListText();
    static QString resultCodeText(std::int32_t resultCodeValue);
    static QString now100nsText();
    static bool tryParseUint32Text(const QString& textValue, std::uint32_t* valueOut);
    static QTableWidgetItem* createReadOnlyItem(const QString& textValue);

private:
    QVBoxLayout* m_rootLayout = nullptr;               // m_rootLayout：根布局。
    QWidget* m_processPanel = nullptr;                 // m_processPanel：顶部进程下拉选择面板。
    QWidget* m_sessionPanel = nullptr;                 // m_sessionPanel：左侧 WinAPI Agent 会话配置面板。
    QWidget* m_filterPanel = nullptr;                  // m_filterPanel：底部事件筛选面板。

    QLabel* m_processIconLabel = nullptr;              // m_processIconLabel：显示当前候选/选中进程的系统图标。
    QComboBox* m_processCombo = nullptr;               // m_processCombo：可编辑进程下拉框，用户输入进程名/PID 后从候选中选择。
    QPushButton* m_processRefreshButton = nullptr;     // m_processRefreshButton：刷新进程列表按钮。
    QLabel* m_processStatusLabel = nullptr;            // m_processStatusLabel：进程下拉框匹配/选择状态文本。

    QLineEdit* m_manualPidEdit = nullptr;              // m_manualPidEdit：手动输入 PID 的高级兜底文本框。
    QLineEdit* m_agentDllPathEdit = nullptr;           // m_agentDllPathEdit：Agent DLL 路径文本框。
    QPushButton* m_browseAgentDllButton = nullptr;     // m_browseAgentDllButton：浏览 DLL 按钮。
    QCheckBox* m_hookFileCheck = nullptr;              // m_hookFileCheck：是否启用文件 API 监控。
    QCheckBox* m_hookRegistryCheck = nullptr;          // m_hookRegistryCheck：是否启用注册表 API 监控。
    QCheckBox* m_hookNetworkCheck = nullptr;           // m_hookNetworkCheck：是否启用网络 API 监控。
    QCheckBox* m_hookProcessCheck = nullptr;           // m_hookProcessCheck：是否启用进程 API 监控。
    QCheckBox* m_hookLoaderCheck = nullptr;            // m_hookLoaderCheck：是否启用加载器 API 监控。
    QCheckBox* m_hookClipboardCheck = nullptr;         // m_hookClipboardCheck：是否启用剪贴板 API 监控（独立分类，不随"进程 API"一起装）。
    QCheckBox* m_autoInjectChildCheck = nullptr;       // m_autoInjectChildCheck：是否在 CreateProcessW 成功后自动注入子进程。
    QCheckBox* m_rawFallbackCheck = nullptr;           // m_rawFallbackCheck：是否启用未强类型覆盖导出的 Raw ABI 兜底 Hook。
    QCheckBox* m_rawDefaultDenyListCheck = nullptr;    // m_rawDefaultDenyListCheck：是否启用默认高频/高风险 Raw 黑名单。
    QPlainTextEdit* m_rawModuleListEdit = nullptr;     // m_rawModuleListEdit：Raw 兜底扫描模块列表，多行编辑。
    QPlainTextEdit* m_rawDenyListEdit = nullptr;       // m_rawDenyListEdit：用户额外 Raw 黑名单，多行编辑，独立于内置默认黑名单。
    QLineEdit* m_fakeModuleEdit = nullptr;             // m_fakeModuleEdit：Fake Success 精确匹配模块名。
    QLineEdit* m_fakeApiEdit = nullptr;                // m_fakeApiEdit：Fake Success 精确匹配导出 API 名。
    QComboBox* m_fakeReturnTypeCombo = nullptr;        // m_fakeReturnTypeCombo：Fake Success 返回值模板。
    QLineEdit* m_fakeReturnValueEdit = nullptr;        // m_fakeReturnValueEdit：Fake Success 标量返回值。
    QComboBox* m_fakeLastErrorKindCombo = nullptr;     // m_fakeLastErrorKindCombo：Fake Success 是否设置 LastError/WSAError。
    QLineEdit* m_fakeLastErrorValueEdit = nullptr;     // m_fakeLastErrorValueEdit：Fake Success 错误码数值。
    QLineEdit* m_fakeX86StackBytesEdit = nullptr;      // x86 Fake 的可选 ret N 字节数。
    QCheckBox* m_fakeRawFallbackCheck = nullptr;       // m_fakeRawFallbackCheck：是否允许 Fake Success 对未强类型 API 使用 Raw 标量返回桩。
    QPushButton* m_fakeAddRuleButton = nullptr;        // m_fakeAddRuleButton：把输入区内容应用到规则表。
    QPushButton* m_fakeRemoveRuleButton = nullptr;     // m_fakeRemoveRuleButton：删除规则表当前选中行。
    QPushButton* m_fakeApplyRuleButton = nullptr;      // m_fakeApplyRuleButton：按当前规则表启动并应用 Fake Success 会话。
    QPushButton* m_fakeStopRuleButton = nullptr;       // m_fakeStopRuleButton：停止当前 Fake Success/WinAPI Agent 会话。
    QLabel* m_fakeRuleStatusLabel = nullptr;           // m_fakeRuleStatusLabel：Fake Success 规则数量/限制说明。
    QTableWidget* m_fakeRuleTable = nullptr;           // m_fakeRuleTable：Fake Success 精确规则表。
    QPushButton* m_startButton = nullptr;              // m_startButton：启动 WinAPI 监控按钮。
    QPushButton* m_stopButton = nullptr;               // m_stopButton：停止 WinAPI 监控按钮。
    QPushButton* m_terminateHookButton = nullptr;      // m_terminateHookButton：手动终止目标进程 Hook 按钮。
    ks::monitor::MonitorCanonicalExport* m_eventExport = nullptr;
    QPushButton* m_exportButton = nullptr;             // m_exportButton：导出当前可见事件按钮。
    QPushButton* m_clearEventButton = nullptr;         // m_clearEventButton：清空事件表按钮。
    QLabel* m_sessionStatusLabel = nullptr;            // m_sessionStatusLabel：会话状态文本。

    QLineEdit* m_eventFilterEdit = nullptr;            // m_eventFilterEdit：全字段事件过滤框。
    QPushButton* m_eventFilterClearButton = nullptr;   // m_eventFilterClearButton：清空事件过滤按钮。
    QCheckBox* m_eventKeepBottomCheck = nullptr;       // m_eventKeepBottomCheck：是否自动滚动到底部。
    QSpinBox* m_eventMemoryBudget = nullptr;
    QLabel* m_diskArchiveStatus = nullptr;
    QPushButton* m_openDiskArchiveButton = nullptr;
    QLabel* m_eventFilterStatusLabel = nullptr;        // m_eventFilterStatusLabel：过滤结果状态文本。
    QTableView* m_eventTable = nullptr;                // 轻量事件模型，仅绘制当前视口。
    WinAPIEventTableModel* m_eventModel = nullptr;
    WinAPIEventFilterModel* m_eventProxy = nullptr;
    bool m_itemThemeRefreshScheduled = false; // 主题事件合并标志；不会改变过滤关键词或可见行计数。

    QTabWidget* m_resultTabs = nullptr;
    QComboBox* m_coveragePidCombo = nullptr;
    QLineEdit* m_coverageFilterEdit = nullptr;
    QLabel* m_coverageStatusLabel = nullptr;
    QTableView* m_coverageTable = nullptr;
    QAbstractItemModel* m_coverageModel = nullptr;
    std::shared_ptr<ks::ui::AsyncUiDispatcher> m_coverageDispatcher;
    QByteArray m_coverageDefinitionHash;
    std::uint64_t m_coverageFilterTicket = 0;
    bool m_coverageFilterRunning = false;
    std::shared_ptr<std::atomic_bool> m_coverageFilterDeliveryDropped, m_coverageHashDeliveryDropped;
    bool m_coverageDebouncePending = false;
    bool m_coverageDebounceDue = false;
    bool m_coverageHashPending = false;
    bool m_coverageHashDirty = false;
    bool m_coverageDirty = true;
    std::unordered_map<std::uint32_t, CoverageViewState> m_pendingCoverage, m_coverageViews;
    std::vector<ks::process::ProcessRecord> m_processList; // m_processList：当前系统进程快照。
    static constexpr std::size_t kPendingRowCapacity = 24000; // 后台队列上限，积压时丢弃最旧事件以保护内存与延迟。
    static constexpr std::size_t kUiFlushRowLimit = 2048;     // 单个 GUI tick 的值投影批次上限。
    static constexpr int kUiFlushBudgetMs = 4;                // 单个 GUI tick 的渲染时间预算。
    static constexpr std::uint32_t kPipeReconnectLimit = 3;  // 旧会话切换时读端可容忍的瞬时断线次数，避免新 Agent 建管道前 UI 放弃读取。

    std::deque<WinAPIEventRef> m_pendingRows;                    // m_pendingRows：后台线程待刷入的有界 FIFO 事件队列。
    WinAPIEventArchive m_eventArchive;
    std::deque<WinAPIEventRef> m_eventProjectionQueue;
    WinAPIEventRef m_restoreSelectedEvent, m_restoreTopEvent;
    bool m_eventProjectionStale = true, m_eventProjectionWasVisible = false, m_eventProjectionPumpScheduled = false;
    bool m_eventTailFollowScheduled = false;
    std::mutex m_pendingMutex;                             // m_pendingMutex：保护待刷入事件队列。
    std::unordered_map<std::uint32_t, std::uint64_t> m_agentDroppedRows;
    std::size_t m_evictedRows = 0;
    std::size_t m_pendingDroppedRows = 0;                   // m_pendingDroppedRows：因队列或渲染预算丢弃的事件数。
    std::shared_ptr<WinAPISessionBackend> m_sessionBackend;
    std::shared_ptr<ks::ui::RetainedCleanupJob> m_sessionCleanup;
    ks::ui::AsyncOperation* m_sessionOperation = nullptr;
    bool m_startupReported = false, m_stopReported = false;
    bool m_stopping = false;
    std::uint64_t m_reportedCleanupAttempt = 0;
    std::atomic_bool m_processRefreshPending{ false };     // m_processRefreshPending：进程刷新是否进行中。
    HookState m_hookState = HookState::Waiting;
    bool m_definitionMismatch = false;
    std::atomic_uint64_t m_sessionGeneration{ 0 };
    std::atomic_bool m_pipeRunning{ false };               // m_pipeRunning：当前监控会话是否在运行。
    std::atomic_bool m_pipeConnected{ false };             // m_pipeConnected：是否已成功连上 Agent 管道。
    QTimer* m_uiFlushTimer = nullptr;                      // m_uiFlushTimer：批量刷新事件表的定时器。
    int m_sessionProgressPid = 0;                          // m_sessionProgressPid：kPro 任务卡片 ID。
    std::uint32_t m_currentSessionPid = 0;                 // m_currentSessionPid：当前监控中的目标 PID。
    std::uint32_t m_residentAgentPid = 0;                  // m_residentAgentPid：已成功注入且仍可能常驻 Agent 的 PID。
    std::uint64_t m_residentAgentCreationTime100ns = 0;    // m_residentAgentCreationTime100ns：常驻 Agent 所属进程实例的创建时间，防 PID 复用。
    QString m_currentSessionId;                            // m_currentSessionId：每次启动唯一标识，防 stop/start 过快时遗漏停止标记。
    qint64 m_lastProcessRefreshMs = 0;                     // m_lastProcessRefreshMs：上次完成进程快照的时间戳（ms）。
    QString m_eventFilterKeyword; // Existing rows are immutable; rescan only when the keyword changes.
    int m_visibleEventCount = 0;
    bool m_hasActivatedOnce = false;                       // m_hasActivatedOnce：是否已经至少激活过一次页面。
};
