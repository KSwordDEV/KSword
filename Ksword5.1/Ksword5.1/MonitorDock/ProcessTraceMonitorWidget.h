#pragma once

// ============================================================
// ProcessTraceMonitorWidget.h
// 作用：
// 1) 为“监控”模块提供首个“进程定向监控”标签页；
// 2) 允许用户选择一个或多个目标进程，并在运行期维护目标进程树；
// 3) 以 ETW 为主、进程快照为辅，尽可能保留与目标进程相关的行为事件；
// 4) 提供事件筛选、导出、复制与跳转进程详情等交互能力。
// ============================================================

#include "ProcessTraceTimelineWidget.h"
#include "../Framework.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../UI/StructuredFieldView.h"

#include <QWidget>

#include <atomic>         // std::atomic_bool：后台监控状态控制。
#include <cstddef>        // std::size_t：事件队列容量与单次刷新批次。
#include <cstdint>        // std::uint32_t/std::uint64_t：PID、时间戳等固定宽度类型。
#include <deque>          // std::deque：高频 ETW 事件的有界 FIFO 队列。
#include <memory>         // std::unique_ptr：后台线程托管。
#include <mutex>          // std::mutex：保护待刷入事件队列与运行期进程树。
#include <thread>         // std::thread：ETW 会话线程与辅助刷新线程。
#include <unordered_map>  // std::unordered_map：按 PID 保存运行期进程树节点。
#include <vector>         // std::vector：目标列表、事件缓存、Provider 列表。

class QCheckBox;
class QComboBox;
class QEvent;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QSplitter;
class QTableWidget;
class QTableWidgetItem;
class QTimer;
class QVBoxLayout;

struct _EVENT_RECORD;
class ProcessTraceMonitorWidget final : public QWidget
{
public:
    // 构造函数：
    // - 作用：初始化目标进程选择区、控制栏、事件表与筛选器；
    // - 参数 parent：Qt 父控件。
    explicit ProcessTraceMonitorWidget(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：停止后台 ETW 会话与辅助定时器，确保线程安全退出。
    ~ProcessTraceMonitorWidget() override;

public:
    // AvailableProcessColumn：
    // - 作用：定义“可选进程”表格列序；
    // - 调用：刷新可选进程列表与过滤时统一按列索引访问。
    enum AvailableProcessColumn
    {
        AvailableProcessColumnPid = 0,
        AvailableProcessColumnName,
        AvailableProcessColumnPath,
        AvailableProcessColumnUser,
        AvailableProcessColumnCount
    };

    // TargetProcessColumn：
    // - 作用：定义“监控目标”表格列序；
    // - 调用：刷新目标列表与显示状态时复用。
    enum TargetProcessColumn
    {
        TargetProcessColumnState = 0,
        TargetProcessColumnPid,
        TargetProcessColumnName,
        TargetProcessColumnPath,
        TargetProcessColumnUser,
        TargetProcessColumnRemark,
        TargetProcessColumnCount
    };

    // EventColumn：
    // - 作用：定义“行为事件”表格列序；
    // - 调用：插入事件、右键菜单和筛选逻辑统一按列访问。
    enum EventColumn
    {
        EventColumnTime100ns = 0,
        EventColumnType,
        EventColumnProvider,
        EventColumnEventId,
        EventColumnEventName,
        EventColumnPidTid,
        EventColumnProcess,
        EventColumnRootPid,
        EventColumnRelation,
        EventColumnDetail,
        EventColumnActivityId,
        EventColumnCount
    };

    // ProviderEntry：
    // - 作用：描述一个已解析成功的 ETW Provider；
    // - providerName：Provider 显示名称；
    // - providerGuidText：Provider GUID 文本；
    // - providerTypeText：本项目定义的事件类型（进程/文件/网络等）。
    struct ProviderEntry
    {
        QString providerName;
        QString providerGuidText;
        QString providerTypeText;
    };

    // TargetProcessEntry：
    // - 作用：保存用户显式选择的监控根进程；
    // - pid：根进程 PID；
    // - processName：根进程名；
    // - imagePath：根进程路径；
    // - userName：根进程所属用户；
    // - creationTime100ns：创建时间，用于区分 PID 复用；
    // - alive：当前快照下是否仍存活；
    // - remarkText：补充说明，例如“手动添加”或错误原因。
    struct TargetProcessEntry
    {
        std::uint32_t pid = 0;
        QString processName;
        QString imagePath;
        QString userName;
        std::uint64_t creationTime100ns = 0;
        bool alive = false;
        QString remarkText;
    };

    // RuntimeTrackedProcess：
    // - 作用：保存运行期目标进程树中的任意节点；
    // - pid：当前节点 PID；
    // - parentPid：父 PID，用于展示与追踪；
    // - rootPid：该节点最终归属的根 PID；
    // - processName/imagePath：节点名称与路径；
    // - creationTime100ns：创建时间，用于辅助确认；
    // - alive：当前快照下节点是否仍存活；
    // - isRoot：该节点是否就是用户选定的根节点；
    // - staleSnapshotRounds：连续多少轮快照未再次命中，用于死节点回收；
    // - lastRelatedEventTime100ns：最后一次被相关事件命中的时间戳，用于审计与清理。
    struct RuntimeTrackedProcess
    {
        std::uint32_t pid = 0;
        std::uint32_t parentPid = 0;
        std::uint32_t rootPid = 0;
        QString processName;
        QString imagePath;
        std::uint64_t creationTime100ns = 0;
        bool alive = false;
        bool isRoot = false;
        std::uint32_t staleSnapshotRounds = 0;
        std::uint64_t lastRelatedEventTime100ns = 0;
    };

    // EtwPropertyValue：
    // - 作用：保存单个 ETW 顶层属性的解析结果；
    // - nameText：属性名；
    // - valueText：可读文本值；
    // - numericAvailable：是否成功解析为数值；
    // - numericValue：数值形式，便于做 PID/ParentPid 识别。
    struct EtwPropertyValue
    {
        QString nameText;
        QString valueText;
        bool numericAvailable = false;
        std::uint64_t numericValue = 0;
    };

    // CapturedEventRow：
    // - 作用：保存一行待刷入 UI 的行为事件；
    // - time100nsText：100ns 时间戳文本；
    // - typeText：事件类型（进程/文件/注册表/网络等）；
    // - providerText：Provider 名称；
    // - eventId：事件 ID；
    // - eventName：事件名；
    // - pidText：PID/TID 文本；
    // - processText：关联进程文本；
    // - rootPidText：归属根 PID 文本；
    // - relationText：根进程/子进程/属性关联等说明；
    // - detailDocument：属性与元信息的唯一结构化快照；
    // - activityIdText：ActivityId 文本。
    struct CapturedEventRow
    {
        std::uint64_t time100ns = 0;
        QString time100nsText;
        QString typeText;
        QString providerText;
        int eventId = 0;
        QString eventName;
        QString pidText;
        QString processText;
        QString rootPidText;
        QString relationText;
        ks::ui::FieldDocument detailDocument;
        QString activityIdText;
    };

private:
    // event：
    // - 作用：监听全局调色板/样式变化，刷新本页自定义 Collapse 的动态样式；
    // - 处理：先交给 QWidget 基类，再按事件类型重刷折叠面板；
    // - 返回：返回 QWidget::event 的处理结果。
    bool event(QEvent* eventPointer) override;

    // ========================= UI 初始化 =========================
    void initializeUi();
    void initializeConnections();
    // createConfigurationCollapseSection：
    // - 作用：创建进程定向页的默认展开配置折叠段；
    // - 入参 parentWidget/titleText/contentWidget/expanded 分别控制父控件、标题、内容页和初始状态；
    // - 返回：可直接加入根布局的折叠段 QWidget。
    QWidget* createConfigurationCollapseSection(
        QWidget* parentWidget,
        const QString& titleText,
        QWidget* contentWidget,
        bool expanded) const;
    void updateActionState();
    void updateStatusLabel();

    // ========================= 目标进程选择 ======================
    void refreshAvailableProcessListAsync();
    void populateAvailableProcessTable(const std::vector<ks::process::ProcessRecord>& processList);
    void applyAvailableProcessFilter();
    void addSelectedAvailableProcesses();
    void addManualProcessByPid();
    void createSuspendedTargetProcess();
    void addTargetProcessByPid(std::uint32_t pidValue, const QString& sourceText);
    void updateTargetProcessRemarkByPid(std::uint32_t pidValue, const QString& remarkText);
    // upsertAutoTrackedProcessInTargetList：
    // - 作用：把 ETW 识别到的新子进程同步到“监控目标”列表；
    // - 调用：ETW 线程通过 QueuedConnection 回到 UI 线程后调用；
    // - 入参 pidValue：子进程 PID；
    // - 入参 parentPidValue：拉起该子进程的父 PID；
    // - 入参 processNameText/processPathText：ETW 属性里带出的进程名与路径提示；
    // - 入参 creationTime100ns：创建时间（若 ETW 暂未提供则为 0）；
    // - 出参：无（内部更新 m_targetProcessList 与目标表格）。
    void upsertAutoTrackedProcessInTargetList(
        std::uint32_t pidValue,
        std::uint32_t parentPidValue,
        const QString& processNameText,
        const QString& processPathText,
        std::uint64_t creationTime100ns);
    // removeTrackedProcessFromTargetListByPid：
    // - 作用：当 ETW 明确报告进程退出时，从监听列表自动取消追踪；
    // - 调用：ETW 线程通过 QueuedConnection 回到 UI 线程后调用；
    // - 入参 pidValue：需要移除的 PID；
    // - 入参 reasonText：本次移除的原因说明（用于日志审计）；
    // - 出参：无（内部更新 m_targetProcessList 与目标表格）。
    void removeTrackedProcessFromTargetListByPid(
        std::uint32_t pidValue,
        const QString& reasonText);
    void refreshTargetTable();
    void removeSelectedTargetProcesses();
    void clearTargetProcesses();
    // showAvailableContextMenu：
    // - 作用：为“可选进程”表提供只读复制和加入监控目标菜单；
    // - 调用：表格右键 CustomContextMenu 信号触发；
    // - 入参 position：viewport 内部坐标；出参：无，菜单动作直接更新剪贴板或目标列表。
    void showAvailableContextMenu(const QPoint& position);
    void showTargetContextMenu(const QPoint& position);

    // ========================= 事件筛选与导出 =====================
    void applyEventFilter();
    void clearEventFilter();
    void scheduleEventFilterApply();
    bool hasAnyEventFilterActive() const;
    void updateEventFilterStatusText(int visibleCount, int totalCount);
    // applyTimelineSelection：
    // - 作用：接收时间轴控件发出的绝对起止时间；
    // - 处理：记录内部时间选区并触发现有事件表筛选；
    // - 返回：无返回值。
    void applyTimelineSelection(std::uint64_t start100ns, std::uint64_t end100ns);
    // refreshTimelineRange：
    // - 作用：根据采集开始/停止状态更新时间轴左右边界；
    // - 入参 captureFinished：true 表示右侧固定为停止时间，false 表示右侧跟随当前时间；
    // - 返回：无返回值。
    void refreshTimelineRange(bool captureFinished);
    // refreshTimelinePoints：
    // - 作用：把轻量事件点缓存推送给时间轴控件重绘；
    // - 返回：无返回值。
    void refreshTimelinePoints();
    // isTimelineFilterActive：
    // - 作用：判断用户是否已经通过时间轴启用额外时间过滤；
    // - 返回：true 表示 applyEventFilter 需要叠加时间范围判断。
    bool isTimelineFilterActive() const;
    void flushPendingRows();
    void appendEventRow(const CapturedEventRow& rowValue);
    ks::ui::FieldDocument eventDocumentForRow(int row) const;
    void openEventDetailViewerForRow(int row) const;
    void showEventContextMenu(const QPoint& position);
    void exportVisibleRowsToTsv();

    // ========================= 监控流程 ==========================
    void startMonitoring();
    void stopMonitoring();
    void stopMonitoringInternal(bool waitForThread);
    void setMonitoringPaused(bool paused);
    void refreshTrackedProcessSnapshotAsync();
    void seedTrackedProcessTree(const std::vector<ks::process::ProcessRecord>& processList);
    void syncTrackedProcessTree(const std::vector<ks::process::ProcessRecord>& processList);
    void pruneStaleTrackedProcesses();

    // ========================= ETW 采集 ==========================
    static void WINAPI processTraceEtwCallback(struct _EVENT_RECORD* eventRecordPtr);
    void enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    bool buildRelevantEventRow(
        const struct _EVENT_RECORD* eventRecordPtr,
        const QString& providerNameText,
        const QString& providerTypeText,
        const std::vector<EtwPropertyValue>& propertyList,
        CapturedEventRow* rowOut);
    bool extractEventProperties(
        const struct _EVENT_RECORD* eventRecordPtr,
        std::vector<EtwPropertyValue>* propertyListOut) const;
    ks::ui::FieldDocument buildEventDetailDocument(
        const QString& providerGuidText,
        const struct _EVENT_RECORD* eventRecordPtr,
        const std::vector<EtwPropertyValue>& propertyList) const;

    // ========================= 文本与样式辅助 ====================
    static QString blueButtonStyle();
    static QString blueInputStyle();
    static QString blueHeaderStyle();
    static QString collapsePanelStyle();
    static QString collapseHeaderButtonStyle();
    static void refreshCollapseTheme(QWidget* rootWidget);
    static QString providerTypeFromName(const QString& providerNameText);
    static QString now100nsText();
    static std::uint64_t currentSystemTime100ns();
    static QString guidToText(const GUID& guidValue);
    static QString queryEtwEventName(const struct _EVENT_RECORD* eventRecordPtr);
    static bool textMatch(
        const QString& sourceText,
        const QString& patternText,
        bool useRegex,
        Qt::CaseSensitivity caseSensitivity);
    static bool tryParseUint32Text(const QString& textValue, std::uint32_t* valueOut);
    static QTableWidgetItem* createReadOnlyItem(const QString& textValue);

private:
    // ========================= 顶层控件 =========================
    QVBoxLayout* m_rootLayout = nullptr;                 // m_rootLayout：根布局。
    QWidget* m_configurationCollapseWidget = nullptr;    // m_configurationCollapseWidget：默认展开的进程定向配置折叠段。
    QWidget* m_configurationPanel = nullptr;             // m_configurationPanel：折叠段内承载进程选择、控制栏与筛选器的内容页。
    QSplitter* m_topSplitter = nullptr;                  // m_topSplitter：顶部左右分栏。
    QWidget* m_availablePanel = nullptr;                 // m_availablePanel：可选进程面板。
    QWidget* m_targetPanel = nullptr;                    // m_targetPanel：监控目标面板。
    QWidget* m_controlPanel = nullptr;                   // m_controlPanel：控制栏面板。
    QWidget* m_filterPanel = nullptr;                    // m_filterPanel：事件筛选面板。

    // ========================= 可选进程区 =======================
    QLineEdit* m_availableFilterEdit = nullptr;          // m_availableFilterEdit：可选进程过滤框。
    QPushButton* m_availableRefreshButton = nullptr;     // m_availableRefreshButton：刷新进程列表按钮。
    QPushButton* m_createTargetButton = nullptr;         // m_createTargetButton：创建并挂起监控目标按钮。
    QPushButton* m_addSelectedButton = nullptr;          // m_addSelectedButton：添加选中进程按钮。
    QLineEdit* m_manualPidEdit = nullptr;                // m_manualPidEdit：手动输入 PID 框。
    QPushButton* m_addManualPidButton = nullptr;         // m_addManualPidButton：按 PID 添加按钮。
    QLabel* m_availableStatusLabel = nullptr;            // m_availableStatusLabel：可选进程状态文本。
    QTableWidget* m_availableTable = nullptr;            // m_availableTable：当前系统进程表。

    // ========================= 监控目标区 =======================
    QPushButton* m_removeTargetButton = nullptr;         // m_removeTargetButton：移除选中目标按钮。
    QPushButton* m_clearTargetButton = nullptr;          // m_clearTargetButton：清空目标按钮。
    QLabel* m_targetStatusLabel = nullptr;               // m_targetStatusLabel：目标列表状态文本。
    QTableWidget* m_targetTable = nullptr;               // m_targetTable：监控监听列表（含手动目标与自动子进程）。

    // ========================= 控制栏 ===========================
    QPushButton* m_startButton = nullptr;                // m_startButton：开始监控按钮。
    QPushButton* m_stopButton = nullptr;                 // m_stopButton：停止监控按钮。
    QPushButton* m_pauseButton = nullptr;                // m_pauseButton：暂停/继续按钮。
    QPushButton* m_exportButton = nullptr;               // m_exportButton：导出事件按钮。
    QLabel* m_statusLabel = nullptr;                     // m_statusLabel：整体监控状态标签。

    // ========================= 事件筛选区 =======================
    QComboBox* m_eventTypeCombo = nullptr;              // m_eventTypeCombo：事件类型筛选下拉框。
    QLineEdit* m_eventProviderFilterEdit = nullptr;     // m_eventProviderFilterEdit：Provider 筛选框。
    QLineEdit* m_eventProcessFilterEdit = nullptr;      // m_eventProcessFilterEdit：进程/根 PID 筛选框。
    QLineEdit* m_eventNameFilterEdit = nullptr;         // m_eventNameFilterEdit：事件名筛选框。
    QLineEdit* m_eventDetailFilterEdit = nullptr;       // m_eventDetailFilterEdit：详情筛选框。
    QLineEdit* m_eventGlobalFilterEdit = nullptr;       // m_eventGlobalFilterEdit：全字段筛选框。
    QCheckBox* m_eventRegexCheck = nullptr;             // m_eventRegexCheck：是否启用正则。
    QCheckBox* m_eventCaseCheck = nullptr;              // m_eventCaseCheck：是否大小写敏感。
    QCheckBox* m_eventInvertCheck = nullptr;            // m_eventInvertCheck：是否反向匹配。
    QCheckBox* m_eventKeepBottomCheck = nullptr;        // m_eventKeepBottomCheck：是否保持贴底。
    QPushButton* m_eventClearFilterButton = nullptr;    // m_eventClearFilterButton：清空筛选按钮。
    QLabel* m_eventFilterStatusLabel = nullptr;         // m_eventFilterStatusLabel：筛选结果统计文本。
    ProcessTraceTimelineWidget* m_eventTimelineWidget = nullptr; // m_eventTimelineWidget：ETW 事件瀑布流时间轴。
    QTableWidget* m_eventTable = nullptr;               // m_eventTable：行为事件结果表。

    // ========================= 后台状态 =========================
    std::vector<ks::process::ProcessRecord> m_availableProcessList; // m_availableProcessList：可选进程快照。
    std::vector<TargetProcessEntry> m_targetProcessList;            // m_targetProcessList：用户选择的根进程列表。
    std::vector<ProviderEntry> m_activeProviderList;                // m_activeProviderList：本轮监控成功启用的 Provider。
    std::unordered_map<std::uint32_t, RuntimeTrackedProcess> m_trackedProcessMap; // m_trackedProcessMap：运行期目标进程树。
    static constexpr std::size_t kPendingRowCapacity = 24000;       // 待显示事件上限，积压时丢弃最旧事件。
    static constexpr std::size_t kUiFlushRowLimit = 160;            // 单个 GUI tick 最多写入的行数。
    static constexpr int kUiFlushBudgetMs = 4;                       // 单个 GUI tick 的渲染时间预算。

    std::deque<CapturedEventRow> m_pendingRows;                     // m_pendingRows：后台待刷入 UI 的有界 FIFO 队列。
    std::vector<ProcessTraceTimelineEventPoint> m_timelineEventPoints; // m_timelineEventPoints：时间轴绘制用轻量事件缓存。
    std::mutex m_runtimeMutex;                                      // m_runtimeMutex：保护目标进程树与 Provider 列表。
    std::mutex m_pendingMutex;                                      // m_pendingMutex：保护待刷新事件队列。
    std::size_t m_pendingDroppedRows = 0;                            // m_pendingDroppedRows：因积压保护丢弃的事件数。
    std::atomic_bool m_captureRunning{ false };                     // m_captureRunning：ETW 监听是否在运行。
    std::atomic_bool m_capturePaused{ false };                      // m_capturePaused：ETW 监听是否处于暂停态。
    std::atomic_bool m_captureStopFlag{ false };                    // m_captureStopFlag：后台线程停止信号。
    std::atomic_bool m_availableRefreshPending{ false };            // m_availableRefreshPending：可选进程刷新是否进行中。
    std::atomic_bool m_runtimeRefreshPending{ false };              // m_runtimeRefreshPending：运行期快照刷新是否进行中。
    std::unique_ptr<std::thread> m_captureThread;                   // m_captureThread：ETW 会话线程。
    QTimer* m_uiUpdateTimer = nullptr;                              // m_uiUpdateTimer：事件表节流刷新定时器。
    QTimer* m_eventFilterDebounceTimer = nullptr;                   // m_eventFilterDebounceTimer：事件筛选节流定时器。
    QTimer* m_runtimeRefreshTimer = nullptr;                        // m_runtimeRefreshTimer：运行期快照辅助定时器。
    int m_captureProgressPid = 0;                                   // m_captureProgressPid：进度条任务 ID。
    std::atomic<std::uint64_t> m_sessionHandle{ 0 };                // m_sessionHandle：ETW 会话句柄。
    std::atomic<std::uint64_t> m_traceHandle{ 0 };                  // m_traceHandle：ETW 消费句柄。
    std::uint64_t m_captureStartTime100ns = 0;                      // m_captureStartTime100ns：本轮监控起点时间。
    std::uint64_t m_captureStopTime100ns = 0;                       // m_captureStopTime100ns：本轮监控停止时间。
    std::uint64_t m_timelineSelectionStart100ns = 0;                // m_timelineSelectionStart100ns：时间轴框选起点。
    std::uint64_t m_timelineSelectionEnd100ns = 0;                  // m_timelineSelectionEnd100ns：时间轴框选终点。
    bool m_timelineUserSelectionActive = false;                     // m_timelineUserSelectionActive：用户是否已启用时间框选。
    qint64 m_lastTimelineRefreshMs = 0;                             // m_lastTimelineRefreshMs：上次向时间轴复制事件点的时间。
    QString m_sessionName;                                          // m_sessionName：本轮 ETW 会话名。
    std::shared_ptr<ks::ui::AsyncUiDispatcher> m_uiDispatcher;        // 辅助快照晚完成时不借用已释放控件或应用。
};
