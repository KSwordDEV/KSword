#include "../UI/StructuredFieldView.h"
#pragma once

// ============================================================
// ServiceDock.h
// 作用：
// 1) 提供独立的服务管理 Dock 页面（目录位于 ServerDock）；
// 2) 展示 Win32 服务列表，支持筛选、排序、状态统计；
// 3) 提供结构化详情页与常用服务控制动作。
// ============================================================

#include "../Framework.h"

#include <QWidget>
#include <QStringList>

#include <atomic>   // std::atomic_bool：后台刷新状态标记。
#include <cstdint>  // std::uint32_t：PID 等数值字段。
#include <memory>   // std::unique_ptr：后台线程托管。
#include <thread>   // std::thread：服务枚举后台线程。
#include <vector>   // std::vector：服务缓存容器。

#include <winsvc.h> // DWORD/SERVICE_*/SC_ACTION_* 常量与结构。

class QComboBox;
class QCheckBox;
class QPlainTextEdit;
class QRadioButton;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QSplitter;
class QSpinBox;
class QTableWidget;
class QToolButton;
class QTabWidget;
class QVBoxLayout;
class CodeEditorWidget;

class ServiceDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数作用：
    // - 初始化 ServiceDock UI；
    // - 绑定交互逻辑；
    // - 页面首次显示时触发异步枚举。
    // 参数 parent：Qt 父控件。
    explicit ServiceDock(QWidget* parent = nullptr);

    // 析构函数作用：
    // - 停止并回收后台线程，防止窗口销毁后悬挂访问。
    ~ServiceDock() override;

    // focusServiceByName 作用：
    // - 按服务名定位并选中对应行；
    // - 供 StartupDock/MainWindow 跨页跳转调用。
    // 参数 serviceNameText：目标服务短名。
    void focusServiceByName(const QString& serviceNameText);

protected:
    // showEvent 作用：
    // - 页面第一次显示时发起首轮服务刷新；
    // - 避免主窗口启动阶段被全量服务枚举阻塞。
    void showEvent(QShowEvent* event) override;

public:
    // ServiceColumn：
    // - 作用：统一服务主表列索引，避免硬编码魔法数字。
    enum class ServiceColumn : int
    {
        Name = 0,      // Name：服务名。
        DisplayName,   // DisplayName：显示名称。
        State,         // State：运行状态文本。
        StartType,     // StartType：启动类型文本。
        Pid,           // Pid：关联 PID。
        Account,       // Account：启动账户。
        Risk,          // Risk：风险摘要。
        Count          // Count：列总数。
    };

    // SortMode：
    // - 作用：定义主列表排序模式。
    enum class SortMode : int
    {
        NameAsc = 0,       // NameAsc：按显示名/服务名升序。
        StatePriority,     // StatePriority：运行中优先。
        StartTypePriority  // StartTypePriority：自动启动优先。
    };

    // ServiceEntry：
    // - 作用：统一承载一条服务记录；
    // - 供主列表、详情页、动作判断复用。
    struct ServiceEntry
    {
        QString serviceNameText;      // serviceNameText：服务短名（唯一键）。
        QString displayNameText;      // displayNameText：服务显示名。
        QString descriptionText;      // descriptionText：服务描述文本。
        QString imagePathText;        // imagePathText：尽量提取后的镜像路径。
        QString commandLineText;      // commandLineText：原始 BinaryPath。
        QString accountText;          // accountText：服务启动账户。
        QString stateText;            // stateText：运行状态文本。
        QString startTypeText;        // startTypeText：启动类型文本。
        QString serviceTypeText;      // serviceTypeText：服务类型文本。
        QString errorControlText;     // errorControlText：错误控制文本。
        QString serviceDllPathText;   // serviceDllPathText：服务 DLL 路径（svchost 类服务）。
        QString sourceStatusText;     // sourceStatusText：SCM 与注册表交叉比对后的来源状态。
        QString riskSummaryText;      // riskSummaryText：风险摘要文本。
        QStringList riskTagList;      // riskTagList：风险标签列表。
        std::uint32_t processId = 0;  // processId：当前服务关联 PID。
        DWORD currentState = 0;       // currentState：SERVICE_STATUS_PROCESS::dwCurrentState。
        DWORD controlsAccepted = 0;   // controlsAccepted：当前可接受控制位掩码。
        DWORD startTypeValue = 0;     // startTypeValue：配置启动类型原始值。
        DWORD serviceTypeValue = 0;   // serviceTypeValue：配置服务类型原始值。
        DWORD errorControlValue = 0;  // errorControlValue：配置错误控制原始值。
        bool delayedAutoStart = false; // delayedAutoStart：是否延迟自动启动。
        bool scmRecordPresent = false; // scmRecordPresent：本轮 EnumServicesStatusEx 是否返回该服务。
        bool registryKeyPresent = false; // registryKeyPresent：注册表 Services 根键是否存在同名项。
        bool registryScanCompleted = false; // registryScanCompleted：独立注册表扫描是否完整结束。
        bool hasRisk = false;         // hasRisk：是否命中至少一个风险标签。
    };

    // toServiceColumn 作用：
    // - 把列枚举转换为 int 索引。
    static int toServiceColumn(ServiceColumn column);

private:
    // ServiceRecoverySettings：
    // - 作用：缓存“恢复”页可编辑配置；
    // - 供读取 Win32 配置、回填 UI、保存回服务配置三处复用。
    struct ServiceRecoverySettings
    {
        SC_ACTION_TYPE firstActionType = SC_ACTION_NONE;    // firstActionType：第一次失败动作。
        SC_ACTION_TYPE secondActionType = SC_ACTION_NONE;   // secondActionType：第二次失败动作。
        SC_ACTION_TYPE subsequentActionType = SC_ACTION_NONE; // subsequentActionType：后续失败动作。
        int resetPeriodDays = 0;                            // resetPeriodDays：重置失败计数天数。
        int restartDelayMinutes = 1;                        // restartDelayMinutes：重启服务延迟分钟。
        bool failureActionsFlag = false;                    // failureActionsFlag：非崩溃失败也执行恢复。
        QString rebootMessageText;                          // rebootMessageText：重启系统提示文本。
        QString programPathText;                            // programPathText：恢复操作程序路径。
        QString programArgumentsText;                       // programArgumentsText：恢复操作命令行参数。
        bool appendFailureCount = false;                    // appendFailureCount：是否追加 /fail=%1%。
    };

    // ===================== 初始化 =====================
    void initializeUi();
    void initializeToolbar();
    void initializeContent();
    void initializeDetailTabs();
    void initializeConnections();

    // ===================== 刷新与枚举 =====================
    void requestAsyncRefresh(bool forceRefresh);
    void applyRefreshResult(std::vector<ServiceEntry> serviceList, const QString& errorText, bool success);
    void enumerateServiceList(std::vector<ServiceEntry>* serviceListOut, QString* errorTextOut) const;
    bool querySingleServiceByName(const QString& serviceNameText, ServiceEntry* entryOut, QString* errorTextOut) const;

    // ===================== 列表与详情 =====================
    void rebuildServiceTable();
    bool entryMatchesCurrentFilter(const ServiceEntry& entry) const;
    bool serviceLessThan(const ServiceEntry& left, const ServiceEntry& right) const;
    void updateSummaryText();
    void syncToolbarStateWithSelection();
    void onServiceSelectionChanged();
    void updateDetailViewsFromSelection();
    ks::ui::FieldDocument buildAuditTabText(const ServiceEntry& entry) const;
    QString buildBasicInfoText(const ServiceEntry& entry) const;
    QString buildConfigInfoText(const ServiceEntry& entry) const;
    ks::ui::FieldDocument buildDependencyDetailText(const ServiceEntry& entry) const;
    ks::ui::FieldDocument buildTriggerDetailText(const ServiceEntry& entry) const;
    ks::ui::FieldDocument buildSecurityDetailText(const ServiceEntry& entry) const;
    ks::ui::FieldDocument buildRiskDetailText(const ServiceEntry& entry) const;
    ks::ui::FieldDocument buildExportDetailText(const ServiceEntry& entry) const;
    void initializeGeneralTab();
    void initializeLogonTab();
    void initializeRecoveryTab();
    void initializeDependencyTab();
    void initializeAuditTab();
    void refreshGeneralTabUiState();
    void refreshLogonTabUiState();
    void refreshRecoveryTabUiState();
    void populateGeneralTab(const ServiceEntry& entry);
    void populateLogonTab(const ServiceEntry& entry);
    void populateRecoveryTab(const ServiceEntry& entry);
    void populateDependencyTab(const ServiceEntry& entry);
    void populateAuditTab(const ServiceEntry& entry);
    void applyGeneralTabChanges();
    void applyLogonTabChanges();
    void applyRecoveryTabChanges();
    void browseLogonAccount();
    void browseRecoveryProgramPath();

    // ===================== 交互与动作 =====================
    void showServiceContextMenu(const QPoint& localPos);
    void refreshSelectedService();
    void startSelectedService();
    void stopSelectedService();
    void pauseSelectedService();
    void continueSelectedService();
    void deleteSelectedService();
    void deleteSelectedServiceAndFile();
    void deleteSelectedServiceInternal(bool deleteBinaryFile);
    void applySelectedStartType();
    void copySelectedServiceName();
    void openSelectedServiceRegistryPath();
    void openSelectedBinaryLocation();
    void openSelectedServiceDllLocation();
    void openSelectedBinaryProperties();
    void jumpToSelectedProcessDetail();
    void jumpToSelectedHandleFilter();
    void jumpToFileDockBinaryDetail();
    void jumpToFileDockServiceDllDetail();
    void exportCurrentListAsTsv();
    void exportSelectedServiceAsJson();
    bool controlSelectedService(
        DWORD desiredAccess,
        const QString& actionText,
        DWORD controlCode,
        bool useStartService,
        DWORD expectedState,
        bool highRiskAction);

    // ===================== 工具 =====================
    QString selectedServiceName() const;
    int findServiceIndexByName(const QString& serviceNameText) const;
    void applyServiceUpdateToCache(const ServiceEntry& updatedEntry);
    QString queryServiceDllPathByName(const QString& serviceNameText) const;
    bool isServiceFilePresent(const QString& filePathText) const;
    bool queryServiceFailureSettings(
        const QString& serviceNameText,
        ServiceRecoverySettings* settingsOut,
        QString* errorTextOut) const;
    bool applyServiceFailureSettings(
        const QString& serviceNameText,
        const ServiceRecoverySettings& settings,
        QString* errorTextOut) const;

private:
    // ===================== 顶层布局 =====================
    QVBoxLayout* m_rootLayout = nullptr;      // m_rootLayout：根布局。
    QWidget* m_toolbarWidget = nullptr;       // m_toolbarWidget：顶部工具栏容器。
    QHBoxLayout* m_toolbarLayout = nullptr;   // m_toolbarLayout：顶部工具栏布局。
    QSplitter* m_contentSplitter = nullptr;   // m_contentSplitter：左右分栏容器。

    // ===================== 工具栏控件 =====================
    QToolButton* m_refreshAllButton = nullptr;      // m_refreshAllButton：刷新全部服务。
    QToolButton* m_refreshCurrentButton = nullptr;  // m_refreshCurrentButton：刷新当前服务详情。
    QToolButton* m_startButton = nullptr;           // m_startButton：启动服务。
    QToolButton* m_stopButton = nullptr;            // m_stopButton：停止服务。
    QToolButton* m_pauseButton = nullptr;           // m_pauseButton：暂停服务。
    QToolButton* m_continueButton = nullptr;        // m_continueButton：继续服务。
    QToolButton* m_applyStartTypeButton = nullptr;  // m_applyStartTypeButton：应用启动类型修改。
    QToolButton* m_runningOnlyButton = nullptr;     // m_runningOnlyButton：仅显示运行中。
    QToolButton* m_autoStartOnlyButton = nullptr;   // m_autoStartOnlyButton：仅显示自动启动。
    QToolButton* m_riskOnlyButton = nullptr;        // m_riskOnlyButton：仅显示高风险服务。
    QLineEdit* m_filterEdit = nullptr;              // m_filterEdit：关键词过滤输入框。
    QComboBox* m_sortCombo = nullptr;               // m_sortCombo：排序模式选择框。
    QComboBox* m_startTypeCombo = nullptr;          // m_startTypeCombo：启动类型修改选择框。
    QLabel* m_summaryLabel = nullptr;               // m_summaryLabel：列表统计状态栏。

    // ===================== 主列表与详情 =====================
    QTableWidget* m_serviceTable = nullptr;   // m_serviceTable：服务主列表。
    QTabWidget* m_detailTabWidget = nullptr;  // m_detailTabWidget：右侧详情页容器。

    QWidget* m_generalTabPage = nullptr;              // m_generalTabPage：常规属性页。
    QWidget* m_logonTabPage = nullptr;                // m_logonTabPage：登录属性页。
    QWidget* m_recoveryTabPage = nullptr;             // m_recoveryTabPage：恢复属性页。
    QWidget* m_dependencyTabPage = nullptr;           // m_dependencyTabPage：依存关系页。
    QWidget* m_auditTabPage = nullptr;                // m_auditTabPage：审计页。

    // 常规页控件：
    // - 模拟 services.msc 的“常规”页布局；
    // - 允许修改显示名、描述、启动类型与延迟自动启动。
    QLineEdit* m_generalServiceNameEdit = nullptr;    // m_generalServiceNameEdit：服务名只读框。
    QLineEdit* m_generalDisplayNameEdit = nullptr;    // m_generalDisplayNameEdit：显示名编辑框。
    QLineEdit* m_generalBinaryPathEdit = nullptr;     // m_generalBinaryPathEdit：镜像路径只读框。
    QPlainTextEdit* m_generalDescriptionEdit = nullptr; // m_generalDescriptionEdit：描述编辑框。
    QComboBox* m_generalStartTypeCombo = nullptr;     // m_generalStartTypeCombo：启动类型下拉框。
    QCheckBox* m_generalDelayedAutoCheck = nullptr;   // m_generalDelayedAutoCheck：延迟自动启动复选框。
    QLabel* m_generalStateValueLabel = nullptr;       // m_generalStateValueLabel：当前状态标签。
    QLabel* m_generalPidValueLabel = nullptr;         // m_generalPidValueLabel：PID 标签。
    QLabel* m_generalAccountValueLabel = nullptr;     // m_generalAccountValueLabel：账户标签。
    QLabel* m_generalTypeValueLabel = nullptr;        // m_generalTypeValueLabel：服务类型标签。
    QLabel* m_generalErrorControlValueLabel = nullptr; // m_generalErrorControlValueLabel：错误控制标签。
    QToolButton* m_generalStartButton = nullptr;      // m_generalStartButton：常规页启动按钮。
    QToolButton* m_generalStopButton = nullptr;       // m_generalStopButton：常规页停止按钮。
    QToolButton* m_generalPauseButton = nullptr;      // m_generalPauseButton：常规页暂停按钮。
    QToolButton* m_generalContinueButton = nullptr;   // m_generalContinueButton：常规页继续按钮。
    QToolButton* m_generalApplyButton = nullptr;      // m_generalApplyButton：常规页应用按钮。
    QToolButton* m_generalReloadButton = nullptr;     // m_generalReloadButton：常规页重载按钮。

    // 登录页控件：
    // - 模拟 services.msc 的“登录”页布局；
    // - 允许切换 LocalSystem / 指定账户并修改交互桌面标志。
    QRadioButton* m_logonLocalSystemRadio = nullptr;  // m_logonLocalSystemRadio：本地系统账户单选框。
    QCheckBox* m_logonDesktopInteractCheck = nullptr; // m_logonDesktopInteractCheck：允许与桌面交互。
    QRadioButton* m_logonAccountRadio = nullptr;      // m_logonAccountRadio：此帐户单选框。
    QLineEdit* m_logonAccountEdit = nullptr;          // m_logonAccountEdit：登录帐户编辑框。
    QLineEdit* m_logonPasswordEdit = nullptr;         // m_logonPasswordEdit：密码编辑框。
    QLineEdit* m_logonConfirmPasswordEdit = nullptr;  // m_logonConfirmPasswordEdit：确认密码编辑框。
    QToolButton* m_logonBrowseButton = nullptr;       // m_logonBrowseButton：浏览帐户按钮。
    QToolButton* m_logonApplyButton = nullptr;        // m_logonApplyButton：登录页应用按钮。
    QToolButton* m_logonReloadButton = nullptr;       // m_logonReloadButton：登录页重载按钮。

    // 恢复页控件：
    // - 模拟 services.msc 的“恢复”页布局；
    // - 允许修改失败动作、重置周期、命令与失败动作标志。
    QComboBox* m_recoveryFirstActionCombo = nullptr;  // m_recoveryFirstActionCombo：第一次失败动作下拉框。
    QComboBox* m_recoverySecondActionCombo = nullptr; // m_recoverySecondActionCombo：第二次失败动作下拉框。
    QComboBox* m_recoverySubsequentActionCombo = nullptr; // m_recoverySubsequentActionCombo：后续失败动作下拉框。
    QSpinBox* m_recoveryResetDaysSpin = nullptr;      // m_recoveryResetDaysSpin：重置失败计数天数。
    QSpinBox* m_recoveryRestartMinutesSpin = nullptr; // m_recoveryRestartMinutesSpin：重启服务延迟分钟。
    QCheckBox* m_recoveryFailureActionsFlagCheck = nullptr; // m_recoveryFailureActionsFlagCheck：错误停止也执行恢复。
    QLineEdit* m_recoveryRebootMessageEdit = nullptr; // m_recoveryRebootMessageEdit：重启消息编辑框。
    QLineEdit* m_recoveryProgramEdit = nullptr;       // m_recoveryProgramEdit：程序路径编辑框。
    QLineEdit* m_recoveryArgumentsEdit = nullptr;     // m_recoveryArgumentsEdit：参数编辑框。
    QCheckBox* m_recoveryAppendFailCountCheck = nullptr; // m_recoveryAppendFailCountCheck：是否追加 /fail=%1%。
    QToolButton* m_recoveryBrowseProgramButton = nullptr; // m_recoveryBrowseProgramButton：浏览程序按钮。
    QToolButton* m_recoveryApplyButton = nullptr;     // m_recoveryApplyButton：恢复页应用按钮。
    QToolButton* m_recoveryReloadButton = nullptr;    // m_recoveryReloadButton：恢复页重载按钮。

    // 依存关系 / 审计页控件：
    // - 非可写数据继续走文本编辑器展示；
    // - 满足“可操作项不放在文本编辑器里”的要求。
    ks::ui::StructuredFieldView* m_dependencyEditor = nullptr;   // m_dependencyEditor：依存关系文本编辑器（只读）。
    ks::ui::StructuredFieldView* m_auditEditor = nullptr;        // m_auditEditor：审计文本编辑器（只读）。

    // ===================== 数据与状态 =====================
    std::vector<ServiceEntry> m_serviceList;          // m_serviceList：服务缓存列表。
    std::atomic_bool m_refreshInProgress{ false };    // m_refreshInProgress：后台刷新进行中标志。
    std::atomic_bool m_refreshQueued{ false };        // m_refreshQueued：刷新排队标志。
    std::unique_ptr<std::thread> m_refreshThread;     // m_refreshThread：后台枚举线程句柄。
    bool m_initialRefreshDone = false;                // m_initialRefreshDone：首轮懒加载完成标志。
    int m_progressPid = 0;                            // m_progressPid：当前进度任务 PID。
    QString m_pendingFocusServiceName;                // m_pendingFocusServiceName：跨页跳转待定位服务名。
    bool m_detailUiSyncInProgress = false;            // m_detailUiSyncInProgress：回填右侧属性页时的信号屏蔽标志。
};
