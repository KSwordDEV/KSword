#pragma once

// ============================================================
// WinAPIDock.h
// 作用：
// 1) 提供 “WinAPI” 独立 Dock 页面；
// 2) 负责选择目标进程、配置 Agent DLL 路径并启动 API 监控；
// 3) 通过命名管道接收 APIMonitor_x64 DLL 回传的 API 事件。
// ============================================================

#include "../Framework.h"
#include "WinApiMonitorProtocol.h"

#include <QString>  // QString：事件文本、样式文本与会话路径缓存。
#include <QWidget>  // QWidget：WinAPIDock 的直接基类。

#include <atomic>   // std::atomic_bool/std::atomic_uintptr_t：会话线程与管道句柄状态控制。
#include <cstddef>  // std::size_t：待显示事件队列容量与刷新批次大小。
#include <cstdint>  // std::uint32_t/std::uintptr_t：PID 与句柄数值桥接。
#include <deque>    // std::deque：高频事件的有界 FIFO 队列。
#include <memory>   // std::unique_ptr：后台线程对象托管。
#include <mutex>    // std::mutex：保护待刷入事件队列。
#include <thread>   // std::thread：进程刷新与命名管道读取线程。
#include <vector>   // std::vector：进程快照与待刷新事件缓存。

class QCheckBox;
class QComboBox;
class QLineEdit;
class QLabel;
class QPlainTextEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QToolButton;
class QVBoxLayout;
class QWidget;
class QPoint;

class WinAPIDock final : public QWidget
{
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
        FakeRuleColumnCount
    };

    // EventRow：
    // - 作用：缓存一行待刷入 UI 的 API 事件；
    // - internalEvent：是否是 UI/Agent 自己生成的内部状态事件。
    struct EventRow
    {
        QString time100nsText;
        QString categoryText;
        QString apiText;
        QString resultText;
        QString pidTidText;
        QString detailText;
        bool internalEvent = false;
    };

private:
    void initializeUi();
    void initializeConnections();
    void updateActionState();
    void updateStatusLabel();

    void refreshProcessListAsync();
    void populateProcessSelector(const std::vector<ks::process::ProcessRecord>& processList);
    void updateProcessSelectorStatus();
    bool currentSelectedPid(std::uint32_t* pidOut) const;
    void browseAgentDllPath();

    void startMonitoring();
    void stopMonitoring();
    void stopMonitoringInternal(bool waitForThread);
    void terminateHooksForSelectedProcess();
    bool prepareSessionArtifacts(std::uint32_t pidValue, QString* errorTextOut);
    bool writeSessionConfigFile(QString* errorTextOut) const;

    // hasResidentAgentForProcess：
    // - 作用：通过 PID 与创建时间确认同一进程实例是否仍可复用已加载 Agent。
    // - 返回：可复用时为 true；身份不匹配时会清除缓存。
    bool hasResidentAgentForProcess(std::uint32_t pidValue);

    // rememberResidentAgentForProcess：
    // - 作用：在成功注入后记录目标进程身份，供同一 Dock 内下一会话避免重复 LoadLibraryW。
    void rememberResidentAgentForProcess(std::uint32_t pidValue);
    void appendInternalEvent(const QString& categoryText, const QString& apiText, const QString& detailText);
    QString fakeSuccessRulesIniText() const;
    bool validateFakeSuccessRules(QString* errorTextOut) const;
    void addFakeSuccessRuleFromInputs();
    void removeSelectedFakeSuccessRule();

    void startPipeReadThread();
    void startChildPipeReadThread(std::uint32_t childPidValue);
    void closeChildPipeHandles();
    void joinChildPipeThreads();
    void writeChildStopFlags();
    void enqueuePendingRow(EventRow rowValue);
    void flushPendingRows();
    void appendEventRow(const EventRow& rowValue);

    void applyEventFilter();
    void clearEventFilter();
    void exportVisibleRowsToTsv();
    void showEventContextMenu(const QPoint& position);
    void showEventDetailDialog(int rowValue);

    static QString blueButtonStyle();
    static QString blueInputStyle();
    static QString blueHeaderStyle();
    static QString buildStatusStyle(const QString& colorHex);
    static QString monitorInfoColorHex();
    static QString monitorSuccessColorHex();
    static QString monitorWarningColorHex();
    static QString monitorErrorColorHex();
    static QString monitorIdleColorHex();
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
    QToolButton* m_sessionCollapseButton = nullptr;    // m_sessionCollapseButton：唯一配置折叠标题按钮，统一收纳目标进程、Agent 与 Fake Success。
    QWidget* m_sessionCollapseContent = nullptr;       // m_sessionCollapseContent：唯一折叠内容区，上部进程选择、下部左右配置。
    QSplitter* m_topSplitter = nullptr;                // m_topSplitter：Agent 会话与 Fake Success 的左右分栏。
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
    QCheckBox* m_autoInjectChildCheck = nullptr;       // m_autoInjectChildCheck：是否在 CreateProcessW 成功后自动注入子进程。
    QCheckBox* m_rawFallbackCheck = nullptr;           // m_rawFallbackCheck：是否启用未强类型覆盖导出的 Raw ABI 兜底 Hook。
    QCheckBox* m_rawDefaultDenyListCheck = nullptr;    // m_rawDefaultDenyListCheck：是否启用默认高频/高风险 Raw 黑名单。
    QPlainTextEdit* m_rawModuleListEdit = nullptr;     // m_rawModuleListEdit：Raw 兜底扫描模块列表，多行编辑。
    QPlainTextEdit* m_rawDenyListEdit = nullptr;       // m_rawDenyListEdit：用户额外 Raw 黑名单，多行编辑，独立于内置默认黑名单。
    QLineEdit* m_fakeModuleEdit = nullptr;             // m_fakeModuleEdit：Fake Success 精确匹配模块名。
    QLineEdit* m_fakeApiEdit = nullptr;                // m_fakeApiEdit：Fake Success 精确匹配导出 API 名。
    QComboBox* m_fakeReturnTypeCombo = nullptr;        // m_fakeReturnTypeCombo：Fake Success 返回值模板。
    QLineEdit* m_fakeReturnValueEdit = nullptr;        // m_fakeReturnValueEdit：Fake Success 写入 RAX 的返回值。
    QComboBox* m_fakeLastErrorKindCombo = nullptr;     // m_fakeLastErrorKindCombo：Fake Success 是否设置 LastError/WSAError。
    QLineEdit* m_fakeLastErrorValueEdit = nullptr;     // m_fakeLastErrorValueEdit：Fake Success 错误码数值。
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
    QPushButton* m_exportButton = nullptr;             // m_exportButton：导出当前可见事件按钮。
    QPushButton* m_clearEventButton = nullptr;         // m_clearEventButton：清空事件表按钮。
    QLabel* m_sessionStatusLabel = nullptr;            // m_sessionStatusLabel：会话状态文本。

    QLineEdit* m_eventFilterEdit = nullptr;            // m_eventFilterEdit：全字段事件过滤框。
    QPushButton* m_eventFilterClearButton = nullptr;   // m_eventFilterClearButton：清空事件过滤按钮。
    QCheckBox* m_eventKeepBottomCheck = nullptr;       // m_eventKeepBottomCheck：是否自动滚动到底部。
    QLabel* m_eventFilterStatusLabel = nullptr;        // m_eventFilterStatusLabel：过滤结果状态文本。
    QTableWidget* m_eventTable = nullptr;              // m_eventTable：API 事件结果表。

    std::vector<ks::process::ProcessRecord> m_processList; // m_processList：当前系统进程快照。
    static constexpr std::size_t kPendingRowCapacity = 24000; // 后台队列上限，积压时丢弃最旧事件以保护内存与延迟。
    static constexpr std::size_t kUiFlushRowLimit = 160;      // 单个 GUI tick 最多渲染的事件数。
    static constexpr int kUiFlushBudgetMs = 4;                // 单个 GUI tick 的渲染时间预算。
    static constexpr std::uint32_t kPipeReconnectLimit = 3;  // 旧会话切换时读端可容忍的瞬时断线次数，避免新 Agent 建管道前 UI 放弃读取。

    std::deque<EventRow> m_pendingRows;                    // m_pendingRows：后台线程待刷入的有界 FIFO 事件队列。
    std::mutex m_pendingMutex;                             // m_pendingMutex：保护待刷入事件队列。
    std::size_t m_pendingDroppedRows = 0;                   // m_pendingDroppedRows：因队列或渲染预算丢弃的事件数。
    std::unique_ptr<std::thread> m_pipeThread;             // m_pipeThread：命名管道读取线程。
    std::vector<std::unique_ptr<std::thread>> m_childPipeThreads; // m_childPipeThreads：自动注入子进程后的子管道读取线程。
    std::vector<std::uintptr_t> m_childPipeHandleValues;   // m_childPipeHandleValues：子管道句柄快照，用于停止时打断阻塞 ReadFile。
    std::vector<std::uint32_t> m_childSessionPids;          // m_childSessionPids：已发现的自动注入子进程 PID，用于写停止标记。
    std::mutex m_childPipeMutex;                           // m_childPipeMutex：保护子管道线程/句柄/PID 容器。
    std::atomic_bool m_processRefreshPending{ false };     // m_processRefreshPending：进程刷新是否进行中。
    std::atomic_bool m_pipeRunning{ false };               // m_pipeRunning：当前监控会话是否在运行。
    std::atomic_bool m_pipeConnected{ false };             // m_pipeConnected：是否已成功连上 Agent 管道。
    std::atomic_bool m_pipeStopFlag{ false };              // m_pipeStopFlag：命名管道线程停止信号。
    std::atomic_uintptr_t m_pipeHandleValue{ 0 };          // m_pipeHandleValue：后台线程持有的管道句柄数值。
    std::atomic_uint32_t m_pipeReconnectAttempts{ 0 };     // m_pipeReconnectAttempts：当前会话已使用的读端短暂断线重连次数。
    QTimer* m_uiFlushTimer = nullptr;                      // m_uiFlushTimer：批量刷新事件表的定时器。
    int m_sessionProgressPid = 0;                          // m_sessionProgressPid：kPro 任务卡片 ID。
    std::uint32_t m_currentSessionPid = 0;                 // m_currentSessionPid：当前监控中的目标 PID。
    std::uint32_t m_residentAgentPid = 0;                  // m_residentAgentPid：已成功注入且仍可能常驻 Agent 的 PID。
    std::uint64_t m_residentAgentCreationTime100ns = 0;    // m_residentAgentCreationTime100ns：常驻 Agent 所属进程实例的创建时间，防 PID 复用。
    QString m_currentPipeName;                             // m_currentPipeName：当前命名管道名。
    QString m_currentConfigPath;                           // m_currentConfigPath：当前会话配置文件路径。
    QString m_currentStopFlagPath;                         // m_currentStopFlagPath：当前停止标记文件路径。
    QString m_currentSessionId;                            // m_currentSessionId：每次启动唯一标识，防 stop/start 过快时遗漏停止标记。
    qint64 m_lastProcessRefreshMs = 0;                     // m_lastProcessRefreshMs：上次完成进程快照的时间戳（ms）。
    bool m_eventFilterActive = false;                      // m_eventFilterActive：是否需要在事件到达时执行全表筛选。
    bool m_hasActivatedOnce = false;                       // m_hasActivatedOnce：是否已经至少激活过一次页面。
};
