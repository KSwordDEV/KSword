#pragma once

// ============================================================
// MonitorDock.h
// 作用：
// 1) 实现监控页“WMI / ETW”双侧边栏 Tab；
// 2) 提供 WMI Provider 枚举、事件类选择、订阅控制与事件展示；
// 3) 提供 ETW Provider 枚举、参数配置、实时结果表与导出能力。
// ============================================================

#include "ProcessTraceTimelineWidget.h"
#include "../Framework.h"

#include <QElapsedTimer>
#include <QByteArray>
#include <QHash>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStringList>
#include <QWidget>

#include <atomic>      // std::atomic_bool：后台订阅状态控制。
#include <condition_variable> // std::condition_variable：等待 ETW 后台归档扫描安全退出。
#include <cstdint>     // std::uint32_t：PID 等固定宽度整数。
#include <deque>       // std::deque：高频 ETW 事件的有界 FIFO 队列。
#include <functional>  // std::function：筛选匹配回调。
#include <memory>      // std::unique_ptr：线程对象托管。
#include <mutex>       // std::mutex：ETW 待刷新队列并发保护。
#include <string>      // std::string：日志输出与 COM 文本桥接。
#include <thread>      // std::thread：WMI 订阅后台线程。
#include <unordered_map> // std::unordered_map：字段映射缓存。
#include <utility>     // std::pair：筛选字段键值映射。
#include <vector>      // std::vector：Provider/事件快照容器。

// Qt 前置声明：减少头文件编译依赖。
class QCheckBox;
class QComboBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QListWidget;
class QListWidgetItem;
class QPlainTextEdit;
class QPushButton;
class QSortFilterProxyModel;
class QSpinBox;
class QStandardItemModel;
class QTableWidget;
class QTableWidgetItem;
class QTableView;
class QTabWidget;
class QTimer;
class QEvent;
class QScrollArea;
class QVBoxLayout;
class QGridLayout;
class QShowEvent;
class QBarSet;
class QChartView;
class QLineSeries;
class QValueAxis;
class CodeEditorWidget;
class WinAPIDock;
class ProcessTraceMonitorWidget;
class DirectKernelCallMonitorWidget;
class KernelCallbackMonitorWidget;

// COM 前置声明：避免在头文件引入大量 WMI 头。
struct IWbemClassObject;
struct IWbemLocator;
struct IWbemServices;
struct IEnumWbemClassObject;
struct _EVENT_RECORD;

class MonitorDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：初始化 WMI/ETW 页面、连接信号槽并执行首轮枚举。
    // - 参数 parent：Qt 父控件。
    explicit MonitorDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：停止后台线程与定时器，确保资源释放。
    ~MonitorDock() override;

    // activateMonitorTab：
    // - 作用：把监控页内部子页切到指定 tab；
    // - 调用：MainWindow 需要把启动默认页或跳转目标定位到“WinAPI / WMI / ETW / 进程定向”时调用。
    void activateMonitorTab(const QString& tabKey);

protected:
    // event：
    // - 作用：捕获主题/调色板变化并刷新动态样式；
    // - 入参 eventPointer：Qt 分发的事件对象；
    // - 返回：true 表示事件被当前控件或基类处理。
    bool event(QEvent* eventPointer) override;

    // showEvent：
    // - 首次显示时再触发 WMI/ETW Provider 枚举；
    // - 避免主窗口启动阶段并发拉起多路后台发现任务。
    void showEvent(QShowEvent* event) override;

private:
    // WmiProviderEntry：
    // - 作用：保存单个 WMI Provider 表格行信息。
    struct WmiProviderEntry
    {
        QString providerName;      // Provider 名称。
        QString nameSpaceText;     // 命名空间。
        QString clsidText;         // CLSID 文本。
        int eventClassCount = 0;   // 支持事件类数量。
        bool subscribable = false; // 是否可订阅。
    };

    // EtwProviderEntry：
    // - 作用：保存 ETW Provider 基础信息。
    struct EtwProviderEntry
    {
        QString providerName;      // Provider 名称。
        QString providerGuidText;  // Provider GUID 字符串。
    };

    // EtwSessionEntry：
    // - 作用：保存系统中一个活动 ETW 会话的快照信息；
    // - 调用：ETW 会话栏枚举、展示与停止指定会话时复用。
    struct EtwSessionEntry
    {
        QString sessionName;
        QString modeText;
        QString bufferText;
        quint32 eventsLost = 0;
        QString logFilePath;
    };

public:
    // ========================= ETW 双筛选器 ==========================
    // EtwFilterStage：
    // - 作用：区分“前置筛选（不捕获）”与“后置筛选（仅隐藏显示）”。
    enum class EtwFilterStage : int
    {
        Pre = 0,
        Post = 1
    };

    // EtwStringMatchMode：
    // - 作用：字符串匹配模式；底层统一编译为正则表达式执行。
    enum class EtwStringMatchMode : int
    {
        Regex = 0,
        Exact = 1,
        Contains = 2,
        Prefix = 3,
        Suffix = 4
    };

    // EtwFilterFieldType：
    // - 作用：标记筛选字段值类型，驱动编译与匹配策略。
    enum class EtwFilterFieldType : int
    {
        Text = 0,
        Number = 1,
        NumberOrText = 2,
        Ip = 3,
        Port = 4,
        TimeRange = 5
    };

    // EtwFilterFieldId：
    // - 作用：统一标识 ETW 筛选字段，便于规则编译后快速匹配。
    enum class EtwFilterFieldId : int
    {
        ProviderName = 0,
        ProviderGuid,
        ProviderCategory,
        EventId,
        EventName,
        Task,
        Opcode,
        Level,
        KeywordMask,
        HeaderPid,
        HeaderTid,
        ActivityId,
        TimestampRange,
        ResourceType,
        Action,
        Target,
        Status,
        DetailKeyword,
        TargetPid,
        ParentPid,
        TargetTid,
        ProcessName,
        ImagePath,
        CommandLine,
        FilePath,
        FileOldPath,
        FileNewPath,
        FileOperation,
        FileStatusCode,
        FileAccessMask,
        RegistryKeyPath,
        RegistryValueName,
        RegistryHive,
        RegistryOperation,
        RegistryStatus,
        SourceIp,
        SourcePort,
        DestinationIp,
        DestinationPort,
        Protocol,
        Direction,
        Domain,
        Host,
        AuditResult,
        UserText,
        SidText,
        SecurityPid,
        SecurityTid,
        SecurityLevel,
        ScriptHostProcess,
        ScriptKeyword,
        ScriptTaskName,
        WmiClassName,
        WmiNamespace
    };

    struct EtwFilterNumericRange
    {
        std::uint64_t minValue = 0;
        std::uint64_t maxValue = 0;
    };

    struct EtwFilterIpRange
    {
        std::uint32_t minValue = 0;
        std::uint32_t maxValue = 0;
    };

    struct EtwFilterPortRange
    {
        std::uint16_t minValue = 0;
        std::uint16_t maxValue = 0;
    };

    struct EtwFilterFieldUiState
    {
        EtwFilterFieldId fieldId = EtwFilterFieldId::ProviderName;
        QString fieldKey;
        QString fieldLabel;
        QLineEdit* inputEdit = nullptr;
    };

    struct EtwFilterCategoryCheckUiState
    {
        QString categoryText;
        QCheckBox* checkBox = nullptr;
    };

    struct EtwSimpleFilterCheckUiState
    {
        QString valueText;
        QCheckBox* checkBox = nullptr;
    };

    struct EtwSimpleFilterUiState
    {
        QWidget* panelWidget = nullptr;
        QCheckBox* enabledCheck = nullptr;
        QPushButton* clearButton = nullptr;
        QLabel* stateLabel = nullptr;
        QLineEdit* pidEdit = nullptr;
        QLineEdit* processNameEdit = nullptr;
        QLineEdit* filePathEdit = nullptr;
        QLineEdit* eventIdEdit = nullptr;
        QLineEdit* eventNameEdit = nullptr;
        QLineEdit* registryPathEdit = nullptr;
        QLineEdit* networkAddressEdit = nullptr;
        QLineEdit* networkPortEdit = nullptr;
        QLineEdit* statusEdit = nullptr;
        QLineEdit* customProviderEdit = nullptr;
        QLineEdit* customActionEdit = nullptr;
        QTimer* applyDebounceTimer = nullptr;
        std::vector<EtwSimpleFilterCheckUiState> providerCheckList;
        std::vector<EtwSimpleFilterCheckUiState> actionCheckList;
    };

    struct EtwFilterRuleGroupUiState
    {
        int groupId = 0;
        QWidget* containerWidget = nullptr;
        QLabel* titleLabel = nullptr;
        QCheckBox* enabledCheck = nullptr;
        QPushButton* removeGroupButton = nullptr;

        QComboBox* stringModeCombo = nullptr;
        QCheckBox* caseSensitiveCheck = nullptr;
        QCheckBox* invertCheck = nullptr;
        QCheckBox* detailVisibleColumnsCheck = nullptr;
        QCheckBox* detailMatchAllFieldsCheck = nullptr;

        std::vector<EtwFilterFieldUiState> fieldList;
        std::vector<EtwFilterCategoryCheckUiState> categoryCheckList;
    };

    // EtwSimpleFilterModel：
    // - 作用：保存与 Qt 控件解耦的简易筛选输入；
    // - 导入时先在临时模型中完成解析和编译，避免无效配置污染当前界面。
    struct EtwSimpleFilterModel
    {
        bool enabled = true;                         // enabled：是否启用本阶段简易筛选。
        QString pidText;                             // pidText：PID 单值或范围列表。
        QString processNameText;                     // processNameText：进程名包含条件。
        QString filePathText;                        // filePathText：文件路径包含条件。
        QString eventIdText;                         // eventIdText：事件 ID 单值或范围列表。
        QString eventNameText;                       // eventNameText：事件名包含条件。
        QString registryPathText;                    // registryPathText：注册表路径包含条件。
        QString networkAddressText;                  // networkAddressText：IPv4、CIDR 或地址范围。
        QString networkPortText;                     // networkPortText：网络端口单值或范围。
        QString statusText;                          // statusText：状态文本包含条件。
        QString customProviderText;                  // customProviderText：自定义 Provider 名称或 GUID。
        QString customActionText;                    // customActionText：自定义行为文本。
        QStringList providerPresetNameList;          // providerPresetNameList：已选 Provider 预设。
        QStringList actionPresetList;                // actionPresetList：已选行为预设。
    };

    // EtwFilterRuleFieldModel：
    // - 作用：保存详细规则组中的一个字段输入及其稳定字段身份。
    struct EtwFilterRuleFieldModel
    {
        EtwFilterFieldId fieldId = EtwFilterFieldId::ProviderName; // fieldId：运行时字段枚举。
        QString fieldKey;                           // fieldKey：配置文件中的稳定字段键。
        QString fieldLabel;                         // fieldLabel：编译错误中使用的字段名称。
        QString inputText;                          // inputText：用户输入的原始规则文本。
    };

    // EtwFilterRuleGroupModel：
    // - 作用：保存一个与控件无关的详细筛选规则组。
    struct EtwFilterRuleGroupModel
    {
        int groupId = 0;                            // groupId：本次模型内的规则组标识。
        bool enabled = true;                        // enabled：是否启用当前规则组。
        EtwStringMatchMode stringMode = EtwStringMatchMode::Regex; // stringMode：字符串匹配方式。
        bool caseSensitive = false;                 // caseSensitive：字符串是否区分大小写。
        bool invertMatch = false;                   // invertMatch：是否反向匹配规则组。
        bool detailVisibleColumnsOnly = false;      // detailVisibleColumnsOnly：Detail 是否仅匹配可见列。
        bool detailMatchAllFields = true;           // detailMatchAllFields：Detail 是否匹配全部字段。
        QStringList providerCategoryList;           // providerCategoryList：已选 Provider 分类。
        std::vector<EtwFilterRuleFieldModel> fieldList; // fieldList：非空字段规则列表。
    };

    // EtwFilterConfigModel：
    // - 作用：一次性承载前置/后置简易规则和详细规则；
    // - 该模型通过全部编译后才允许提交到 UI、运行时和默认配置。
    struct EtwFilterConfigModel
    {
        EtwSimpleFilterModel preSimpleFilter;        // preSimpleFilter：前置简易筛选模型。
        EtwSimpleFilterModel postSimpleFilter;       // postSimpleFilter：后置简易筛选模型。
        std::vector<EtwFilterRuleGroupModel> preGroupList;  // preGroupList：前置详细规则。
        std::vector<EtwFilterRuleGroupModel> postGroupList; // postGroupList：后置详细规则。
    };

    struct EtwFilterRuleFieldCompiled
    {
        EtwFilterFieldId fieldId = EtwFilterFieldId::ProviderName;
        QString fieldKey;
        QString fieldLabel;
        EtwFilterFieldType fieldType = EtwFilterFieldType::Text;
        bool requiresDecodedPayload = false;
        std::vector<QRegularExpression> regexRuleList;
        std::vector<EtwFilterNumericRange> numericRangeList;
        std::vector<EtwFilterIpRange> ipRangeList;
        std::vector<EtwFilterPortRange> portRangeList;
    };

    struct EtwFilterRuleGroupCompiled
    {
        int groupId = 0;
        int displayIndex = 0;
        bool enabled = true;
        EtwStringMatchMode stringMode = EtwStringMatchMode::Regex;
        bool caseSensitive = false;
        bool invertMatch = false;
        bool detailVisibleColumnsOnly = false;
        bool detailMatchAllFields = true;
        bool requiresDecodedPayload = false;
        std::vector<EtwFilterRuleFieldCompiled> fieldList;

        bool hasAnyCondition() const
        {
            return !fieldList.empty();
        }
    };

    struct EtwSimpleFilterCompiled
    {
        bool enabled = true;
        std::vector<EtwFilterNumericRange> pidRangeList;
        std::vector<EtwFilterNumericRange> eventIdRangeList;
        std::vector<EtwFilterIpRange> networkAddressRangeList;
        std::vector<EtwFilterPortRange> networkPortRangeList;
        QStringList providerPresetNameList;
        QStringList providerCustomTokenList;
        QStringList actionPresetList;
        QStringList actionCustomTokenList;
        QStringList processNameTokenList;
        QStringList filePathTokenList;
        QStringList eventNameTokenList;
        QStringList registryPathTokenList;
        QStringList statusTokenList;

        bool hasAnyCondition() const
        {
            return enabled
                && (!pidRangeList.empty()
                    || !eventIdRangeList.empty()
                    || !networkAddressRangeList.empty()
                    || !networkPortRangeList.empty()
                    || !providerPresetNameList.empty()
                    || !providerCustomTokenList.empty()
                    || !actionPresetList.empty()
                    || !actionCustomTokenList.empty()
                    || !processNameTokenList.empty()
                    || !filePathTokenList.empty()
                    || !eventNameTokenList.empty()
                    || !registryPathTokenList.empty()
                    || !statusTokenList.empty());
        }

        bool requiresDecodedPayload() const
        {
            return hasAnyCondition()
                && (!pidRangeList.empty()
                    || !networkAddressRangeList.empty()
                    || !networkPortRangeList.empty()
                    || !actionPresetList.empty()
                    || !actionCustomTokenList.empty()
                    || !processNameTokenList.empty()
                    || !filePathTokenList.empty()
                    || !registryPathTokenList.empty()
                    || !statusTokenList.empty());
        }
    };

    struct EtwFilterStageCompiledSnapshot
    {
        EtwSimpleFilterCompiled simpleFilter;
        std::vector<EtwFilterRuleGroupCompiled> detailedGroupList;
    };

    // EtwFilterConfigCompiledModel：
    // - 作用：保存临时配置模型四条路径的完整编译结果；
    // - 只有四条路径都成功时才会替换当前运行时筛选器。
    struct EtwFilterConfigCompiledModel
    {
        EtwSimpleFilterCompiled preSimpleFilter;     // preSimpleFilter：前置简易规则编译结果。
        EtwSimpleFilterCompiled postSimpleFilter;    // postSimpleFilter：后置简易规则编译结果。
        std::vector<EtwFilterRuleGroupCompiled> preGroupList;  // preGroupList：前置详细规则编译结果。
        std::vector<EtwFilterRuleGroupCompiled> postGroupList; // postGroupList：后置详细规则编译结果。
    };

    struct EtwCapturedEventRow
    {
        std::uint64_t archiveSequence = 0;
        bool decodedReady = false;
        QString timestampText;
        std::uint64_t timestampValue = 0;
        QString providerName;
        QString providerGuid;
        QString providerCategory;
        int eventId = 0;
        QString eventName;
        int task = 0;
        QString taskName;
        int opcode = 0;
        QString opcodeName;
        int level = 0;
        QString levelText;
        std::uint64_t keywordMaskValue = 0;
        QString keywordMaskText;
        std::uint32_t headerPid = 0;
        std::uint32_t headerTid = 0;
        QString activityId;
        QString pidTidText;
        QString detailSummary;
        QString detailJson;
        QString detailVisibleText;
        QString detailAllText;

        QString resourceTypeText;
        QString actionText;
        QString targetText;
        QString statusText;

        std::uint32_t targetPid = 0;
        bool targetPidValid = false;
        std::uint32_t parentPid = 0;
        bool parentPidValid = false;
        std::uint32_t targetTid = 0;
        bool targetTidValid = false;

        QString processNameText;
        QString imagePathText;
        QString commandLineText;

        QString filePathText;
        QString fileOldPathText;
        QString fileNewPathText;
        QString fileOperationText;
        QString fileStatusCodeText;
        QString fileAccessMaskText;

        QString registryKeyPathText;
        QString registryValueNameText;
        QString registryHiveText;
        QString registryOperationText;
        QString registryStatusText;

        QString sourceIpText;
        std::uint32_t sourceIpValue = 0;
        bool sourceIpValid = false;
        std::uint16_t sourcePort = 0;
        bool sourcePortValid = false;
        QString destinationIpText;
        std::uint32_t destinationIpValue = 0;
        bool destinationIpValid = false;
        std::uint16_t destinationPort = 0;
        bool destinationPortValid = false;
        QString protocolText;
        QString directionText;
        QString domainText;
        QString hostText;

        QString auditResultText;
        QString userText;
        QString sidText;
        std::uint32_t securityPid = 0;
        bool securityPidValid = false;
        std::uint32_t securityTid = 0;
        bool securityTidValid = false;
        QString securityLevelText;

        QString scriptHostProcessText;
        QString scriptKeywordText;
        QString scriptTaskNameText;
        QString wmiClassNameText;
        QString wmiNamespaceText;
    };

public:
    // ArkRiskCenterEntry：
    // - 作用：保存 ARK 风险中心的一行聚合结果；
    // - 输入：由 MonitorDock 的只读查询聚合生成；
    // - 返回行为：纯数据对象，供表格、详情和 JSON/CSV 导出复用。
    struct ArkRiskCenterEntry
    {
        QString sourceName;
        QString category;
        QString title;
        QString detail;
        QString riskScoreText;
        double riskScore = 0.0;
        QJsonObject payload;
    };

private:
    // ========================= UI 初始化 =========================
    void initializeUi();
    void initializePerformancePanel();
    void initializeWmiTab();
    void initializeEtwTab();
    // initializeArkRiskCenterTab 作用：
    // - 构建只读 ARK 风险中心页，聚合 Memory/Process/Driver/Callback/Hook 发现；
    // - 提供 JSON/CSV 导出入口；
    // - 不新增 KernelDock 页面，也不提供危险写按钮。
    void initializeArkRiskCenterTab();

    // ensureDirectKernelCallTabInitialized 作用：
    // - 输入：无，读取 m_directKernelCallHostPage 与 m_directKernelCallWidget；
    // - 处理：首次进入“直接内核调用”页时再创建真实控件和 syscall 映射；
    // - 返回：无返回值，控件挂入宿主布局后由 Qt 父子树释放。
    void ensureDirectKernelCallTabInitialized();
    void ensureKernelCallbackTabInitialized();
    void ensureWinApiTabInitialized();

    // triggerDeferredDiscoveryForCurrentTab 作用：
    // - 输入：无，读取当前内部 Tab；
    // - 处理：仅在用户进入 WMI/ETW 页时触发对应首轮 Provider/会话发现；
    // - 返回：无返回值，实际枚举仍走后台线程。
    void triggerDeferredDiscoveryForCurrentTab();
    void initializeConnections();
    // refreshArkRiskCenterAsync 作用：
    // - 异步汇总多个 ArkDriverClient 只读查询的风险发现；
    // - 按 riskScore 排序并回填表格；
    // - 返回值：无。
    void refreshArkRiskCenterAsync();
    // rebuildArkRiskCenterTable 作用：
    // - 按当前过滤条件重建 ARK 风险中心表格；
    // - 只做缓存投影，不再次发起 R0 调用；
    // - 返回值：无。
    void rebuildArkRiskCenterTable();
    // showArkRiskCenterDetailForCurrentRow 作用：
    // - 展示风险中心当前选中行的结构化 JSON 与摘要；
    // - 只读取本地缓存，不访问驱动；
    // - 返回值：无。
    void showArkRiskCenterDetailForCurrentRow() const;
    // exportArkRiskCenterAsJson / exportArkRiskCenterAsCsv 作用：
    // - 将当前风险中心缓存导出为 JSON 或 CSV；
    // - 若缓存为空则提示未集成或无结果；
    // - 返回值：无。
    void exportArkRiskCenterAsJson() const;
    void exportArkRiskCenterAsCsv() const;
    void refreshPerformanceCharts();
    bool sampleCpuUsage(double* cpuUsageOut);
    bool sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut);
    bool sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut);
    void appendLineSample(
        QLineSeries* series,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double value);

    // ========================= WMI 功能 ==========================
    void refreshWmiProvidersAsync();
    void refreshWmiEventClassesAsync();
    // updateWmiSubscribePanelCompactLayout：
    // - 作用：按当前事件类数量动态收敛“WMI订阅”右侧面板中的事件类表高度；
    // - 调用：初始化订阅UI后调用一次，事件类刷新完成后再次调用；
    // - 入参/出参：无（直接读取并更新成员控件尺寸）。
    void updateWmiSubscribePanelCompactLayout();
    void applyWmiProviderFilter();
    void startWmiSubscription();
    void stopWmiSubscription();
    void setWmiSubscriptionPaused(bool paused);
    void enqueueWmiEventRow(
        const QString& providerName,
        const QString& className,
        const QString& pidAndName,
        const QString& detailText);
    void applyWmiEventFilter();
    void clearWmiEventFilter();
    void flushWmiPendingRows();
    void appendWmiEventRow(
        const QString& providerName,
        const QString& className,
        const QString& pidAndName,
        const QString& detailText);
    void exportWmiRowsToTsv();
    void openWmiEventDetailViewerForRow(int row) const;
    void showWmiEventContextMenu(const QPoint& position);

    // ========================= ETW 功能 ==========================
    void refreshEtwProvidersAsync();
    void refreshEtwSessionsAsync();
    void stopSelectedEtwSessions();
    void startEtwCapture();
    void stopEtwCapture();
    void setEtwCapturePaused(bool paused);
    void updateEtwCaptureActionState();
    // flushEtwPendingRows：
    // - 作用：把 ETW 后台线程积攒的事件批量刷入表格和时间轴缓存；
    // - 入参 captureFinished：true 表示刷新后按停止状态固定时间轴右边界；
    // - 返回：无返回值。
    void flushEtwPendingRows(bool captureFinished);
    // applyEtwTimelineSelection：
    // - 作用：接收 ETW 时间轴控件发出的“已扣除暂停区间”的有效起止时间；
    // - 处理：记录有效时间窗口并复用后置筛选流程隐藏表格行；
    // - 返回：无返回值。
    void applyEtwTimelineSelection(std::uint64_t start100ns, std::uint64_t end100ns);
    // etwRawTimestampToTimelineTimestamp：
    // - 作用：把 ETW 原始绝对 100ns 时间戳转换为扣除暂停区间后的时间轴时间；
    // - 入参 rawTimestamp100ns：事件或范围边界的原始 ETW 时间戳；
    // - 返回：可交给时间轴控件绘制/筛选的有效时间戳。
    std::uint64_t etwRawTimestampToTimelineTimestamp(std::uint64_t rawTimestamp100ns) const;
    // closeEtwTimelinePauseInterval：
    // - 作用：在继续监听时把当前暂停段固化为闭区间；
    // - 入参 resumeTime100ns：恢复监听瞬间的原始系统时间；
    // - 返回：无返回值。
    void closeEtwTimelinePauseInterval(std::uint64_t resumeTime100ns);
    // refreshEtwTimelineRange：
    // - 作用：根据 ETW 监听运行/暂停/停止状态更新时间轴左右边界；
    // - 入参 captureFinished：true 表示右侧固定为停止有效时间，false 表示右侧跟随运行有效时间；
    // - 返回：无返回值。
    void refreshEtwTimelineRange(bool captureFinished);
    // refreshEtwTimelinePoints：
    // - 作用：把 ETW 已捕获事件的轻量点缓存推送给时间轴重绘；
    // - 返回：无返回值。
    void refreshEtwTimelinePoints();
    // isEtwTimelineFilterActive：
    // - 作用：判断用户是否已经通过 ETW 时间轴启用时间窗口筛选；
    // - 返回：true 表示后置筛选需要额外叠加时间范围判断。
    bool isEtwTimelineFilterActive() const;
    // prepareEtwArchiveSession：创建本轮 ETW 全量归档目录并重置 10 秒分段状态。
    bool prepareEtwArchiveSession(QString* errorTextOut);
    // archiveEtwCapturedRow：把一条完成前置筛选和解码的事件写入磁盘归档，再允许进入 UI 镜像队列。
    bool archiveEtwCapturedRow(EtwCapturedEventRow* rowData);
    // finishEtwArchiveSession：将待写数据压缩成块并封存当前分段；可重复调用。
    void finishEtwArchiveSession(bool flushToPhysicalDisk = true);
    // rebuildEtwArchiveFilterAsync：流式扫描已封存分段，只保留最近 6000 条命中结果。
    void rebuildEtwArchiveFilterAsync();
    // scheduleEtwArchiveFilterRebuild：合并连续规则/时间轴变更，避免重复并发扫描归档。
    void scheduleEtwArchiveFilterRebuild();
    // ETW 归档扫描使用计数式生命周期保护，析构时取消并等待后台任务退出。
    bool beginEtwArchiveBackgroundTask();
    void endEtwArchiveBackgroundTask();
    void cancelAndWaitEtwArchiveBackgroundTasks();
    // replaceEtwRowsWithSnapshot：用后台筛选结果替换 UI 窗口，完整归档仍留在磁盘。
    void replaceEtwRowsWithSnapshot(
        std::deque<EtwCapturedEventRow> rows,
        std::uint64_t totalMatchCount,
        std::uint64_t scannedRowCount,
        std::uint64_t scannedMaxSequence);
    // updateEtwCollapseHeight：
    // - 作用：触发 ETW 独立折叠区重新计算几何尺寸；
    // - 说明：当前折叠区不再使用 QToolBox，因此不会强制保留一个展开页。
    void updateEtwCollapseHeight();
    static void WINAPI etwEventRecordCallback(struct _EVENT_RECORD* eventRecordPtr);
    void enqueueEtwEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr);
    void appendEtwEventRow(
        const QString& providerName,
        int eventId,
        const QString& eventName,
        std::uint32_t pidValue,
        std::uint32_t tidValue,
        const QString& detailJson,
        const QString& activityIdText);
    void exportEtwRowsToTsv(bool visibleOnly = true);
    void openEtwEventDetailViewerForRow(int row) const;
    void showEtwEventContextMenu(const QPoint& position);

    // ========================= ETW 双筛选 ========================
    void initializeEtwFilterPanels();
    QWidget* createEtwSimpleFilterPanel(EtwFilterStage stage, QWidget* parentWidget);
    EtwSimpleFilterUiState& etwSimpleFilterUi(EtwFilterStage stage);
    const EtwSimpleFilterUiState& etwSimpleFilterUi(EtwFilterStage stage) const;
    void scheduleEtwSimpleFilterApply(EtwFilterStage stage);
    void clearEtwSimpleFilter(EtwFilterStage stage, bool applyRules = true);
    void updateEtwSimpleFilterStateLabel(EtwFilterStage stage);
    // captureEtwSimpleFilterModel / captureEtwFilterGroupModels：
    // - 作用：只读快照当前控件值，供编译和持久化复用。
    EtwSimpleFilterModel captureEtwSimpleFilterModel(EtwFilterStage stage) const;
    std::vector<EtwFilterRuleGroupModel> captureEtwFilterGroupModels(EtwFilterStage stage) const;
    EtwFilterConfigModel captureEtwFilterConfigModel() const;
    // tryCompileEtwSimpleFilterModel / tryCompileEtwFilterGroupModels：
    // - 作用：不访问 Qt 控件，在临时模型上完成全部语义验证与编译。
    bool tryCompileEtwSimpleFilterModel(
        EtwFilterStage stage,
        const EtwSimpleFilterModel& filterModel,
        EtwSimpleFilterCompiled& compiledFilterOut,
        QString& errorTextOut) const;
    bool tryCompileEtwFilterGroupModels(
        EtwFilterStage stage,
        const std::vector<EtwFilterRuleGroupModel>& groupModelList,
        std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
        QString& errorTextOut) const;
    bool tryCompileEtwFilterConfigModel(
        const EtwFilterConfigModel& filterModel,
        EtwFilterConfigCompiledModel& compiledModelOut,
        QString& errorTextOut) const;
    bool tryCompileEtwSimpleFilter(
        EtwFilterStage stage,
        EtwSimpleFilterCompiled& compiledFilterOut,
        QString& errorTextOut) const;
    void addEtwFilterRuleGroup(EtwFilterStage stage);
    void removeEtwFilterRuleGroup(EtwFilterStage stage, int groupId);
    void rebuildEtwFilterRuleGroupUi(EtwFilterStage stage);
    void clearEtwFilterGroups(EtwFilterStage stage, bool resetTimelineSelection = false);
    void applyEtwFilterRules(EtwFilterStage stage);
    void applyEtwPostFilterToTable(int firstRow = 0, bool updateStateLabel = true);
    void updateEtwFilterStateLabel(EtwFilterStage stage);
    bool tryCompileEtwFilterGroups(
        EtwFilterStage stage,
        std::vector<EtwFilterRuleGroupCompiled>& compiledGroupsOut,
        QString& errorTextOut) const;
    EtwFilterRuleGroupUiState* findEtwFilterRuleGroupById(EtwFilterStage stage, int groupId);
    const EtwFilterRuleGroupUiState* findEtwFilterRuleGroupById(EtwFilterStage stage, int groupId) const;
    QString etwFilterConfigPath() const;
    // tryParseEtwFilterConfigModel：
    // - 作用：严格解析支持版本的 JSON，并在临时模型中规范化字段和预设值。
    bool tryParseEtwFilterConfigModel(
        const QByteArray& jsonData,
        EtwFilterConfigModel& filterModelOut) const;
    QJsonObject serializeEtwFilterConfigModel(const EtwFilterConfigModel& filterModel) const;
    bool saveEtwFilterConfigModelToPath(
        const EtwFilterConfigModel& filterModel,
        const QString& filePath,
        bool showErrorDialog) const;
    // commitEtwFilterConfigModel：
    // - 作用：在 UI 线程中一次性切换界面、运行时规则和前置线程快照。
    void commitEtwFilterConfigModel(
        const EtwFilterConfigModel& filterModel,
        EtwFilterConfigCompiledModel compiledModel);
    bool saveEtwFilterConfigToPath(const QString& filePath, bool showErrorDialog) const;
    bool loadEtwFilterConfigFromPath(
        const QString& filePath,
        bool showErrorDialog,
        bool persistAsDefault = false);
    void saveEtwFilterConfigToDefaultPath(bool showDialog) const;
    void loadEtwFilterConfigFromDefaultPath(bool showDialog);
    void importEtwFilterConfigFromUserSelectedPath();
    void exportEtwFilterConfigToUserSelectedPath() const;

    // ========================= 停止流程 ==========================
    // stopWmiSubscriptionInternal：
    // - 作用：停止 WMI 订阅，可选同步等待线程退出；
    // - 参数 waitForThread=true 时用于析构安全退出，false 时用于 UI 非阻塞停止。
    void stopWmiSubscriptionInternal(bool waitForThread);

    // stopEtwCaptureInternal：
    // - 作用：停止 ETW 捕获，可选同步等待线程退出；
    // - 参数 waitForThread=true 时用于析构安全退出，false 时用于 UI 非阻塞停止。
    void stopEtwCaptureInternal(bool waitForThread);

private:
    // ========================= 顶层布局 =========================
    QVBoxLayout* m_rootLayout = nullptr;    // 根布局。
    QWidget* m_perfPanel = nullptr;         // 顶部性能图面板。
    QGridLayout* m_perfPanelLayout = nullptr; // 顶部性能图布局。
    QTimer* m_perfUpdateTimer = nullptr;    // 性能图刷新定时器（默认1秒）。
    QTabWidget* m_sideTabWidget = nullptr;  // 侧边栏 Tab 容器。
    ProcessTraceMonitorWidget* m_processTraceWidget = nullptr; // m_processTraceWidget：进程定向监控子页。
    QWidget* m_kernelCallbackHostPage = nullptr; // 内核回调监控延迟加载宿主页。
    KernelCallbackMonitorWidget* m_kernelCallbackWidget = nullptr; // 真正的内核回调监控控件。
    QWidget* m_directKernelCallHostPage = nullptr; // m_directKernelCallHostPage：直接内核调用延迟加载宿主页。
    DirectKernelCallMonitorWidget* m_directKernelCallWidget = nullptr; // m_directKernelCallWidget：直接内核调用监控子页。
    QWidget* m_winApiPage = nullptr;        // m_winApiPage：WinAPI 子页宿主容器。
    WinAPIDock* m_winApiWidget = nullptr;   // m_winApiWidget：真正的 WinAPI 监控控件。
    QWidget* m_arkRiskCenterPage = nullptr;  // m_arkRiskCenterPage：ARK 风险中心页宿主。
    QPushButton* m_arkRiskRefreshButton = nullptr; // 风险中心刷新按钮。
    QPushButton* m_arkRiskExportJsonButton = nullptr; // 风险中心 JSON 导出按钮。
    QPushButton* m_arkRiskExportCsvButton = nullptr; // 风险中心 CSV 导出按钮。
    QLineEdit* m_arkRiskFilterEdit = nullptr; // 风险中心全字段过滤框。
    QCheckBox* m_arkRiskHighOnlyCheck = nullptr; // 仅显示高风险记录。
    QLabel* m_arkRiskStatusLabel = nullptr; // 风险中心状态标签。
    QTableWidget* m_arkRiskTable = nullptr; // 风险中心结果表。
    CodeEditorWidget* m_arkRiskDetailEdit = nullptr; // 风险中心详情文本，使用统一只读代码编辑器。

    QChartView* m_cpuChartView = nullptr;      // CPU 条形图视图。
    QChartView* m_memoryChartView = nullptr;   // 内存条形图视图。
    QChartView* m_diskChartView = nullptr;     // 磁盘折线图视图。
    QChartView* m_networkChartView = nullptr;  // 网络折线图视图。
    QBarSet* m_cpuBarSet = nullptr;            // CPU 单柱数据集。
    QBarSet* m_memoryBarSet = nullptr;         // 内存单柱数据集。
    QLineSeries* m_diskReadSeries = nullptr;   // 磁盘读速率折线。
    QLineSeries* m_diskWriteSeries = nullptr;  // 磁盘写速率折线。
    QLineSeries* m_networkRxSeries = nullptr;  // 网络下载速率折线。
    QLineSeries* m_networkTxSeries = nullptr;  // 网络上传速率折线。
    QValueAxis* m_diskAxisX = nullptr;         // 磁盘图 X 轴。
    QValueAxis* m_diskAxisY = nullptr;         // 磁盘图 Y 轴。
    QValueAxis* m_networkAxisX = nullptr;      // 网络图 X 轴。
    QValueAxis* m_networkAxisY = nullptr;      // 网络图 Y 轴。
    int m_perfHistoryLength = 60;                        // 折线图保留点数。
    int m_perfSampleCounter = 0;                         // 当前采样序号。
    std::uint64_t m_lastCpuIdleTime = 0;                // 上次 CPU Idle 时间戳。
    std::uint64_t m_lastCpuKernelTime = 0;              // 上次 CPU Kernel 时间戳。
    std::uint64_t m_lastCpuUserTime = 0;                // 上次 CPU User 时间戳。
    bool m_cpuSampleValid = false;                      // CPU 采样是否已初始化。
    std::uint64_t m_lastNetworkRxBytes = 0;             // 上次网络累计接收字节。
    std::uint64_t m_lastNetworkTxBytes = 0;             // 上次网络累计发送字节。
    qint64 m_lastNetworkSampleMs = 0;                   // 上次网络采样时间（ms）。
    void* m_diskPerfQueryHandle = nullptr;              // PDH 查询句柄（磁盘性能）。
    void* m_diskReadCounterHandle = nullptr;            // PDH 磁盘读计数器句柄。
    void* m_diskWriteCounterHandle = nullptr;           // PDH 磁盘写计数器句柄。

    // ========================= WMI 页 ===========================
    QWidget* m_wmiPage = nullptr;                  // WMI 主页面。
    QVBoxLayout* m_wmiLayout = nullptr;            // WMI 页面布局。
    QWidget* m_wmiTopConfigPanel = nullptr;        // WMI 顶部独立折叠区。
    QHBoxLayout* m_wmiTopConfigLayout = nullptr;   // WMI 顶部折叠区横向布局。
    QWidget* m_wmiProviderPanel = nullptr;         // Provider 面板。
    QVBoxLayout* m_wmiProviderPanelLayout = nullptr; // Provider 面板布局。
    QHBoxLayout* m_wmiProviderControlLayout = nullptr; // Provider 控制栏布局。
    QLineEdit* m_wmiProviderFilterEdit = nullptr;  // Provider 过滤框。
    QPushButton* m_wmiProviderRefreshButton = nullptr; // Provider 刷新按钮。
    QLabel* m_wmiProviderStatusLabel = nullptr;    // Provider 状态文本。
    QTableView* m_wmiProviderTableView = nullptr;  // Provider 表格视图。
    QStandardItemModel* m_wmiProviderModel = nullptr; // Provider 数据模型。
    QSortFilterProxyModel* m_wmiProviderProxyModel = nullptr; // Provider 过滤模型。

    QWidget* m_wmiSubscribePanel = nullptr;        // WMI 订阅面板。
    QVBoxLayout* m_wmiSubscribeLayout = nullptr;   // WMI 订阅布局。
    QHBoxLayout* m_wmiEventClassControlLayout = nullptr; // 事件类控制栏。
    QPushButton* m_wmiSelectAllClassesButton = nullptr;  // 全选按钮。
    QPushButton* m_wmiSelectNoneClassesButton = nullptr; // 全不选按钮。
    QPushButton* m_wmiSelectWin32ClassesButton = nullptr; // 仅Win32按钮。
    QTableWidget* m_wmiEventClassTable = nullptr;  // 事件类选择表。
    QPlainTextEdit* m_wmiWhereEditor = nullptr;    // WHERE 条件编辑框。
    QComboBox* m_wmiWhereTemplateCombo = nullptr;  // WHERE 模板下拉框。
    QHBoxLayout* m_wmiSubscribeControlLayout = nullptr; // 订阅控制栏。
    QPushButton* m_wmiStartSubscribeButton = nullptr; // 开始订阅按钮。
    QPushButton* m_wmiStopSubscribeButton = nullptr;  // 停止订阅按钮。
    QPushButton* m_wmiPauseSubscribeButton = nullptr; // 暂停/继续按钮。
    QPushButton* m_wmiExportButton = nullptr;         // 导出结果按钮。
    QLabel* m_wmiSubscribeStatusLabel = nullptr;    // 订阅状态文本。
    QLineEdit* m_wmiEventGlobalFilterEdit = nullptr; // WMI 全字段筛选框。
    QLineEdit* m_wmiEventProviderFilterEdit = nullptr; // WMI Provider筛选框。
    QLineEdit* m_wmiEventClassFilterEdit = nullptr; // WMI 事件类筛选框。
    QLineEdit* m_wmiEventPidFilterEdit = nullptr; // WMI PID/进程筛选框。
    QLineEdit* m_wmiEventDetailFilterEdit = nullptr; // WMI 详情筛选框。
    QCheckBox* m_wmiEventRegexCheck = nullptr; // WMI 筛选是否启用正则。
    QCheckBox* m_wmiEventCaseCheck = nullptr; // WMI 筛选是否大小写敏感。
    QCheckBox* m_wmiEventInvertCheck = nullptr; // WMI 筛选是否反向匹配。
    QCheckBox* m_wmiEventKeepBottomCheck = nullptr; // WMI 表格是否保持贴底滚动。
    QPushButton* m_wmiEventFilterClearButton = nullptr; // WMI 筛选清空按钮。
    QLabel* m_wmiEventFilterStatusLabel = nullptr; // WMI 筛选结果状态文本。
    QTableWidget* m_wmiEventTable = nullptr;        // WMI 事件结果表。

    std::vector<WmiProviderEntry> m_wmiProviders; // Provider 缓存。
    std::atomic_bool m_wmiSubscribeRunning{ false }; // 订阅运行状态。
    std::atomic_bool m_wmiSubscribePaused{ false };  // 订阅暂停状态。
    std::atomic_bool m_wmiSubscribeStopFlag{ false }; // 订阅停止信号。
    std::unique_ptr<std::thread> m_wmiSubscribeThread; // WMI 后台订阅线程。
    int m_wmiProviderRefreshProgressPid = 0;          // WMI Provider 刷新进度 PID。
    int m_wmiSubscribeProgressPid = 0;                // WMI 订阅进度 PID。
    std::vector<QStringList> m_wmiPendingRows;        // WMI 待刷入 UI 的事件缓存。
    std::mutex m_wmiPendingMutex;                     // WMI 事件缓存互斥锁。
    QTimer* m_wmiUiUpdateTimer = nullptr;             // WMI UI 节流刷新定时器。

    // ========================= ETW 页 ===========================
    QWidget* m_etwPage = nullptr;                    // ETW 主页面。
    QVBoxLayout* m_etwLayout = nullptr;              // ETW 页面布局。
    QWidget* m_etwCollapseHostWidget = nullptr;      // ETW 独立折叠区宿主。
    QVBoxLayout* m_etwCollapseHostLayout = nullptr;  // ETW 独立折叠区布局。
    QWidget* m_etwProviderPanel = nullptr;           // ETW Provider 面板。
    QVBoxLayout* m_etwProviderPanelLayout = nullptr; // ETW Provider 布局。
    QHBoxLayout* m_etwProviderControlLayout = nullptr; // ETW 控制栏。
    QPushButton* m_etwProviderRefreshButton = nullptr; // ETW 刷新按钮。
    QLabel* m_etwProviderStatusLabel = nullptr;      // ETW 状态标签。
    QWidget* m_etwSessionPanel = nullptr;            // ETW 会话面板。
    QVBoxLayout* m_etwSessionPanelLayout = nullptr;  // ETW 会话布局。
    QHBoxLayout* m_etwSessionControlLayout = nullptr; // ETW 会话控制栏。
    QPushButton* m_etwSessionRefreshButton = nullptr; // ETW 会话刷新按钮。
    QPushButton* m_etwSessionStopButton = nullptr;   // ETW 会话停止按钮。
    QLabel* m_etwSessionStatusLabel = nullptr;       // ETW 会话状态标签。
    QTableWidget* m_etwSessionTable = nullptr;       // ETW 会话表。
    QComboBox* m_etwPresetCategoryCombo = nullptr;   // ETW 预置模板分类筛选下拉框。
    QListWidget* m_etwPresetProviderList = nullptr;  // ETW 预置常用 Provider 勾选列表。
    QListWidget* m_etwProviderList = nullptr;        // ETW Provider 复选列表。
    QLineEdit* m_etwManualProviderEdit = nullptr;    // 手动输入 Provider。
    QComboBox* m_etwLevelCombo = nullptr;            // 级别设置。
    QLineEdit* m_etwKeywordMaskEdit = nullptr;       // 关键字掩码输入。
    QSpinBox* m_etwBufferSizeSpin = nullptr;         // 缓冲区大小输入。
    QSpinBox* m_etwMinBufferSpin = nullptr;          // 最小缓冲区数输入。
    QSpinBox* m_etwMaxBufferSpin = nullptr;          // 最大缓冲区数输入。
    QHBoxLayout* m_etwCaptureControlLayout = nullptr; // ETW 控制栏布局。
    QPushButton* m_etwStartButton = nullptr;         // ETW 开始按钮。
    QPushButton* m_etwStopButton = nullptr;          // ETW 停止按钮。
    QPushButton* m_etwPauseButton = nullptr;         // ETW 暂停按钮。
    QPushButton* m_etwExportButton = nullptr;        // ETW 导出按钮。
    QLabel* m_etwCaptureStatusLabel = nullptr;       // ETW 状态文本。
    EtwSimpleFilterUiState m_etwPreSimpleFilterUi;    // ETW 简易前置筛选控件。
    EtwSimpleFilterUiState m_etwPostSimpleFilterUi;   // ETW 简易后置筛选控件。
    QWidget* m_etwPreFilterPanel = nullptr;          // 前置筛选面板。
    QWidget* m_etwPostFilterPanel = nullptr;         // 后置筛选面板。
    QVBoxLayout* m_etwPreFilterPanelLayout = nullptr; // 前置筛选布局。
    QVBoxLayout* m_etwPostFilterPanelLayout = nullptr; // 后置筛选布局。
    QPushButton* m_etwPreFilterAddGroupButton = nullptr; // 前置筛选新增组按钮。
    QPushButton* m_etwPreFilterApplyButton = nullptr; // 前置筛选应用按钮。
    QPushButton* m_etwPreFilterClearButton = nullptr; // 前置筛选清空按钮。
    QPushButton* m_etwPreFilterLoadDefaultButton = nullptr; // 前置筛选加载默认配置按钮。
    QPushButton* m_etwPreFilterSaveDefaultButton = nullptr; // 前置筛选保存默认配置按钮。
    QPushButton* m_etwPreFilterImportButton = nullptr; // 前置筛选导入配置按钮。
    QPushButton* m_etwPreFilterExportButton = nullptr; // 前置筛选导出配置按钮。
    QLabel* m_etwPreFilterStateLabel = nullptr;      // 前置筛选状态汇总标签。
    QScrollArea* m_etwPreFilterScrollArea = nullptr; // 前置筛选滚动容器。
    QWidget* m_etwPreFilterGroupHostWidget = nullptr; // 前置筛选规则组宿主。
    QVBoxLayout* m_etwPreFilterGroupHostLayout = nullptr; // 前置筛选规则组布局。
    QPushButton* m_etwPostFilterAddGroupButton = nullptr; // 后置筛选新增组按钮。
    QPushButton* m_etwPostFilterApplyButton = nullptr; // 后置筛选应用按钮。
    QPushButton* m_etwPostFilterClearButton = nullptr; // 后置筛选清空按钮。
    QPushButton* m_etwPostFilterLoadDefaultButton = nullptr; // 后置筛选加载默认配置按钮。
    QPushButton* m_etwPostFilterSaveDefaultButton = nullptr; // 后置筛选保存默认配置按钮。
    QPushButton* m_etwPostFilterImportButton = nullptr; // 后置筛选导入配置按钮。
    QPushButton* m_etwPostFilterExportButton = nullptr; // 后置筛选导出配置按钮。
    QLabel* m_etwPostFilterStateLabel = nullptr;      // 后置筛选状态汇总标签。
    QScrollArea* m_etwPostFilterScrollArea = nullptr; // 后置筛选滚动容器。
    QWidget* m_etwPostFilterGroupHostWidget = nullptr; // 后置筛选规则组宿主。
    QVBoxLayout* m_etwPostFilterGroupHostLayout = nullptr; // 后置筛选规则组布局。
    ProcessTraceTimelineWidget* m_etwTimelineWidget = nullptr; // ETW 事件瀑布流时间轴。
    QTableWidget* m_etwEventTable = nullptr;         // ETW 事件表。
    QTimer* m_etwUiUpdateTimer = nullptr;            // 高频 ETW 的 UI 批量刷新定时器。
    QTimer* m_etwArchiveFilterDebounceTimer = nullptr; // ETW 全量后置筛选防抖定时器。

    std::vector<EtwProviderEntry> m_etwProviders;    // ETW Provider 缓存。
    QHash<QString, QString> m_etwCaptureProviderNames; // 当前 ETW 会话的 GUID 到显示名快照。
    std::vector<EtwSessionEntry> m_etwSessions;      // ETW 会话缓存。
    int m_etwPreFilterNextGroupId = 1;               // 前置筛选规则组递增ID。
    int m_etwPostFilterNextGroupId = 1;              // 后置筛选规则组递增ID。
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>> m_etwPreFilterRuleGroupUiList; // 前置筛选UI原始规则组。
    std::vector<std::unique_ptr<EtwFilterRuleGroupUiState>> m_etwPostFilterRuleGroupUiList; // 后置筛选UI原始规则组。
    EtwSimpleFilterCompiled m_etwPreSimpleFilterCompiled; // 已编译的简易前置筛选。
    EtwSimpleFilterCompiled m_etwPostSimpleFilterCompiled; // 已编译的简易后置筛选。
    std::vector<EtwFilterRuleGroupCompiled> m_etwPreFilterCompiledGroupList; // 前置筛选编译规则组。
    std::vector<EtwFilterRuleGroupCompiled> m_etwPostFilterCompiledGroupList; // 后置筛选编译规则组。
    std::shared_ptr<const EtwFilterStageCompiledSnapshot> m_etwPreFilterCompiledSnapshot; // ETW回调使用的前置筛选快照。
    std::mutex m_etwPreFilterSnapshotMutex;          // 前置筛选快照互斥锁。
    std::deque<EtwCapturedEventRow> m_etwPendingRows; // ETW 待刷入 UI 的有界 FIFO 队列。
    std::deque<EtwCapturedEventRow> m_etwCapturedRows; // ETW 已捕获事件缓存（后置筛选仅隐藏）。
    std::deque<ProcessTraceTimelineEventPoint> m_etwTimelineEventPoints; // ETW 时间轴绘制用有效时间点缓存。
    std::mutex m_etwPendingMutex;                    // ETW 待刷入队列互斥锁。
    std::atomic<std::uint64_t> m_etwUiSkippedRows{ 0 }; // 仅 UI 镜像未展示的事件数，归档中仍完整保留。
    std::atomic<std::uint64_t> m_etwSourceEventsLost{ 0 }; // ETW 会话自身报告的源事件丢失数，必须显式告警。
    QElapsedTimer m_etwTimelineRefreshTimer;         // 时间轴重绘节流计时器。
    QString m_etwArchiveDirectory;                  // 当前捕获会话的全量归档目录。
    QString m_etwArchiveActiveSegmentPath;          // 当前正在写入的 10 秒分段。
    QStringList m_etwArchiveClosedSegmentPaths;     // 已封存、可供后台筛选读取的分段。
    QByteArray m_etwArchiveWriteBuffer;              // 未压缩聚合缓冲区，约 1 MiB 时写成 Zstandard 块。
    std::mutex m_etwArchiveMutex;                    // 写入、封存与筛选快照互斥锁。
    std::uintptr_t m_etwArchiveFileHandle = 0;       // Win32 归档文件句柄，0 表示未打开。
    std::uint64_t m_etwArchiveSegmentStart100ns = 0; // 当前分段首条事件时间。
    std::uint64_t m_etwArchiveNextSequence = 0;      // 本轮全量归档事件序号。
    std::uint32_t m_etwArchiveSegmentIndex = 0;      // 分段文件递增编号。
    std::atomic_bool m_etwArchiveWriteFailed{ false }; // 任一归档写入失败后停止继续接收事件。
    std::atomic<std::uint64_t> m_etwArchiveFilterTicket{ 0 }; // 后台全量筛选取消票据。
    std::atomic<std::uint64_t> m_etwSessionRefreshTicket{ 0 }; // ETW 会话枚举请求票据，阻止旧 detached 结果回填。
    std::atomic<std::uint64_t> m_etwArchiveSessionGeneration{ 0 }; // 捕获会话代次，阻止旧任务读取新会话。
    std::mutex m_etwArchiveTaskMutex;                // 后台筛选/导出任务生命周期互斥锁。
    std::condition_variable m_etwArchiveTaskCondition; // 析构等待后台归档任务退出。
    std::size_t m_etwArchiveBackgroundTaskCount = 0; // 当前仍可能访问本对象的归档后台任务数。
    bool m_etwArchiveTaskShutdown = false;            // 析构开始后禁止创建新归档后台任务。
    std::atomic_bool m_etwCaptureRunning{ false };   // ETW 捕获运行状态。
    std::atomic_bool m_etwCapturePaused{ false };    // ETW 捕获暂停状态。
    std::atomic_bool m_etwCaptureStopFlag{ false };  // ETW 捕获停止信号。
    std::unique_ptr<std::thread> m_etwCaptureThread; // ETW 后台线程。
    int m_etwCaptureProgressPid = 0;                 // ETW 捕获进度 PID。
    int m_etwSessionRefreshProgressPid = 0;          // ETW 会话刷新/结束进度 PID。
    std::atomic<std::uint64_t> m_etwSessionHandle{ 0 }; // ETW 会话句柄（TRACEHANDLE）。
    std::atomic<std::uint64_t> m_etwTraceHandle{ 0 };   // ETW 消费句柄（TRACEHANDLE）。
    QString m_etwSessionName;                        // ETW 会话名（Stop/Query 复用）。
    std::uint64_t m_etwCaptureStartTime100ns = 0;     // ETW 时间轴左边界时间。
    std::uint64_t m_etwCaptureStopTime100ns = 0;      // ETW 时间轴停止时右边界时间。
    std::uint64_t m_etwTimelinePauseTime100ns = 0;    // ETW 暂停时冻结的时间轴右边界。
    std::vector<std::pair<std::uint64_t, std::uint64_t>> m_etwTimelinePauseIntervals; // ETW 已完成暂停区间列表。
    std::uint64_t m_etwTimelineSelectionStart100ns = 0; // ETW 有效时间轴框选起点。
    std::uint64_t m_etwTimelineSelectionEnd100ns = 0;   // ETW 有效时间轴框选终点。
    bool m_etwTimelineUserSelectionActive = false;    // 用户是否已启用 ETW 时间框选。
    bool m_wmiInitialDiscoveryDone = false;          // m_wmiInitialDiscoveryDone：WMI 页是否已触发首轮发现。
    bool m_etwInitialDiscoveryDone = false;          // m_etwInitialDiscoveryDone：ETW 页是否已触发首轮发现。
    bool m_arkRiskCenterInitialDiscoveryDone = false; // 风险中心是否已完成首轮汇总。
    bool m_arkRiskRefreshInProgress = false;         // 风险中心后台刷新互斥标记。
    std::uint64_t m_arkRiskRefreshTicket = 0;        // 风险中心刷新票据。
    std::vector<ArkRiskCenterEntry> m_arkRiskCenterEntries; // 风险中心缓存。
};
