#pragma once

// ============================================================
// ApplicationControlPage.h
// 作用：
// 1) 在 MiscDock 内提供“应用控制”诊断和受控编辑页；
// 2) 聚合 AppLocker、WDAC / Code Integrity、Defender / ASR、平台安全、事件日志和文件诊断；
// 3) 支持查看、复制、导出，以及经过确认的 AppLocker、WDAC 和 Defender 配置编辑。
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <cstdint>
#include <utility>
#include <vector>

class QLabel;
class QComboBox;
class QLineEdit;
class CodeEditorWidget;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QVBoxLayout;
class QPoint;

namespace ks::misc
{
    // ApplicationControlPage：
    // - 输入：Qt 父控件；
    // - 处理：异步采集 AppLocker / WDAC / Defender / Platform / CodeIntegrity / 文件诊断信息；
    // - 输出：通过表格、状态标签和文本框展示诊断数据，并提供受控的配置编辑入口。
    class ApplicationControlPage final : public QWidget
    {
    public:
        // 构造函数：
        // - parent 为 Qt 父控件；
        // - 创建 UI 并立即发起一次后台刷新。
        explicit ApplicationControlPage(QWidget* parent = nullptr);

        // 析构函数：
        // - 页面采用 Qt 对象树管理控件；
        // - 后台任务使用 QPointer 回投，无需显式收尾。
        ~ApplicationControlPage() override = default;

    private:
        // AppLockerRuleRecord：AppLocker 规则行的只读展示模型。
        struct AppLockerRuleRecord
        {
            QString idText;             // idText：规则唯一 ID，用于右键编辑和删除。
            QString collectionText;     // collectionText：规则集合显示名。
            QString actionText;         // actionText：Allow / Deny。
            QString userText;           // userText：用户或组文本。
            QString sidText;            // sidText：SID 原值。
            QString conditionTypeText;  // conditionTypeText：Publisher / Path / Hash。
            QString conditionText;      // conditionText：路径、发布者或哈希摘要。
            QString descriptionText;    // descriptionText：规则描述。
            QString riskText;          // riskText：风险标记文本。
        };

        // PolicyFileRecord：WDAC / Code Integrity 策略文件信息。
        struct PolicyFileRecord
        {
            QString pathText;      // pathText：文件路径。
            QString existsText;    // existsText：是否存在。
            QString sizeText;      // sizeText：文件大小。
            QString modifiedText;  // modifiedText：修改时间。
            QString countText;     // countText：策略数量/分片数量。
            QString detailText;    // detailText：补充说明。
        };

        // EventRecord：Code Integrity 事件日志行。
        struct EventRecord
        {
            QString timeText;      // timeText：事件时间。
            QString idText;        // idText：事件 ID。
            QString levelText;    // levelText：事件级别。
            QString verdictText;  // verdictText：允许/阻止/审计/其他。
            QString messageText;  // messageText：摘要消息。
        };

        // KeyValueRecord：Defender/状态类表格行。
        struct KeyValueRecord
        {
            QString nameText;     // nameText：字段名。
            QString valueText;    // valueText：字段值。
            QString detailText;   // detailText：补充说明。
        };

    private:
        // initializeUi：
        // - 创建顶部工具栏和五个子页；
        // - 无输入参数，无返回值。
        void initializeUi();

        // buildAppLockerPage：
        // - 构建 AppLocker 查看页；
        // - 返回以本页面为父对象的新建子页控件，由调用方加入 m_tabWidget。
        QWidget* buildAppLockerPage();

        // buildWdacPage：
        // - 构建 WDAC / Code Integrity 查看页；
        // - 返回以本页面为父对象的新建子页控件，由调用方加入 m_tabWidget。
        QWidget* buildWdacPage();

        // buildDefenderPage：
        // - 构建 Defender / ASR 查看页；
        // - 返回以本页面为父对象的新建子页控件，由调用方加入 m_tabWidget。
        QWidget* buildDefenderPage();

        // buildPlatformPage：
        // - 构建 CI / VBS / Hyper-V / Driver Trust / BAM 只读诊断页；
        // - 返回以本页面为父对象的新建子页控件，由调用方加入 m_tabWidget。
        QWidget* buildPlatformPage();

        // buildEventLogPage：
        // - 构建事件日志页；
        // - 返回以本页面为父对象的新建子页控件，由调用方加入 m_tabWidget。
        QWidget* buildEventLogPage();

        // buildFileDiagnosisPage：
        // - 构建文件诊断页；
        // - 返回以本页面为父对象的新建子页控件，由调用方加入 m_tabWidget。
        QWidget* buildFileDiagnosisPage();

        // editAppLockerPolicy：
        // - 读取本地 AppLocker XML 策略，在编辑器中确认后以 Replace 模式写回；
        // - 无输入参数，无返回值。
        void editAppLockerPolicy();

        // editWdacPolicy：
        // - 编辑用户选择的 WDAC 源 XML；可选编译并通过 CiTool 部署；
        // - sourcePath 为空时弹出文件选择对话框，非空时直接编辑该路径；
        // - 无返回值；已有配置写入在途时直接返回，不重入。
        void editWdacPolicy(const QString& sourcePath = QString());

        // editDefenderSetting：
        // - 编辑 Defender 表格中当前选中的受支持配置项；
        // - 无输入参数，无返回值。
        void editDefenderSetting();

        // runPowerShellMutationAsync：
        // - 在后台执行已由 UI 确认的配置写入脚本，并在成功后刷新页面；
        // - operationName 为用户可读操作名，scriptText 为写入脚本；
        // - 无返回值。
        void runPowerShellMutationAsync(const QString& operationName, const QString& scriptText);

        // 三个可编辑页面的右键菜单；全局设施会自动追加复制和 TSV 导出。
        void showAppLockerContextMenu(const QPoint& localPosition);
        void showWdacContextMenu(const QPoint& localPosition);
        void showDefenderContextMenu(const QPoint& localPosition);

        // AppLocker 路径规则、WDAC 源 XML、Defender / ASR 的新增和删除操作。
        void addAppLockerRule();
        void editAppLockerRule(int row);
        void deleteAppLockerRule();
        void addWdacPolicy();
        void deleteWdacPolicy();
        void addDefenderAsrRule();
        void deleteDefenderSetting();

        // initializeTable：
        // - 为表格设置统一的只读、行选择和右键菜单行为；
        // - table 为目标表格，传 nullptr 时直接返回；
        // - stretchLastColumn 决定最后一列是否吸收剩余宽度；
        // - 无返回值。
        void initializeTable(QTableWidget* table, bool stretchLastColumn = true);

        // refreshAsync：
        // - 后台采集 AppLocker / WDAC / Defender / Event Log 诊断数据；
        // - 无返回值，结果回投到 UI 线程。
        void refreshAsync();

        // applyRefreshResult：
        // - 在 UI 线程应用后台刷新结果；
        // - refreshGeneration 必须等于当前代次，旧任务结果会被丢弃；
        // - 无返回值。
        void applyRefreshResult(
            std::uint64_t refreshGeneration,
            QString statusText,
            QString appLockerSummary,
            QString wdacSummary,
            QString defenderSummary,
            QString platformSummary,
            QString eventSummary,
            QVector<AppLockerRuleRecord> appLockerRules,
            QVector<PolicyFileRecord> policyFiles,
            QVector<EventRecord> events,
            QVector<KeyValueRecord> defenderRows,
            QVector<KeyValueRecord> platformRows);

        // runFileDiagnosisAsync：
        // - 对输入文件路径做只读诊断；
        // - 无返回值，结果回投到 UI 线程。
        void runFileDiagnosisAsync();

        // applyFileDiagnosisResult：
        // - 在 UI 线程应用文件诊断结果；
        // - 无返回值。
        void applyFileDiagnosisResult(QString summaryText, QVector<KeyValueRecord> rows);

        // exportCurrentTableTsv：
        // - 导出当前激活页的主表格为 TSV；
        // - 无返回值，失败通过消息框提示。
        void exportCurrentTableTsv();

        // currentExportTable：
        // - 获取当前激活页对应的导出表格；
        // - 返回 nullptr 表示当前页无可导出表格。
        QTableWidget* currentExportTable() const;


        // tableToTsv：
        // - 把表格全部内容导出为 TSV 文本；
        // - selectedOnly=true 时仅导出当前选中行；
        // - 返回 TSV 字符串。
        QString tableToTsv(QTableWidget* table, bool selectedOnly) const;

        // runPowerShellCaptureText：
        // - 异步线程内通过 powershell.exe 执行脚本并抓取标准输出；
        // - scriptText 为 PowerShell 脚本；
        // - timeoutMs 为超时时间；
        // - 返回执行输出，失败时返回空串并可带错误说明。
        static QString runPowerShellCaptureText(const QString& scriptText, int timeoutMs, QString* errorTextOut);

        // parseAppLockerPolicyXml：
        // - 从 Get-AppLockerPolicy -Effective -Xml 输出中解析规则；
        // - xmlText 为 XML 文本；
        // - 返回解析结果和摘要文本。
        static std::pair<QVector<AppLockerRuleRecord>, QString> parseAppLockerPolicyXml(const QString& xmlText);

        // buildAppLockerRiskText：
        // - 根据 AppLocker 规则生成风险标记；
        // - 返回多行风险文本或空串。
        static QString buildAppLockerRiskText(
            const QString& actionText,
            const QString& sidText,
            const QString& conditionTypeText,
            const QString& conditionText);

        // parseEventsJson：
        // - 将 PowerShell JSON 输出转换为事件表行；
        // - jsonText 为原始 JSON；
        // - 返回事件行和摘要文本。
        static std::pair<QVector<EventRecord>, QString> parseEventsJson(const QString& jsonText);

        // parseDefenderJson：
        // - 将 Defender PowerShell JSON 输出转换为键值表行；
        // - jsonText 为原始 JSON；
        // - 返回键值表行和摘要文本。
        static std::pair<QVector<KeyValueRecord>, QString> parseDefenderJson(const QString& jsonText);

        // rebuildEventTable：
        // - 输入：读取当前缓存事件与事件分类筛选控件；
        // - 处理：按允许/阻止/审计/事件过滤，并重建事件表；
        // - 返回：无返回值。
        void rebuildEventTable();

        // selectedEventLimit：
        // - 输入：读取事件条数下拉框；
        // - 处理：将 UI 文本转换为 PowerShell -MaxEvents 使用的数量；
        // - 返回：正整数事件上限。
        int selectedEventLimit() const;

        // buildPathMatchHint：
        // - 用调用方提供的 AppLocker 规则快照对指定路径生成可能命中提示；
        // - filePathText 为输入路径，appLockerRules 为只读快照；
        // - 返回命中摘要。
        static QString buildPathMatchHint(
            const QString& filePathText,
            const QVector<AppLockerRuleRecord>& appLockerRules);

    private:
        QVBoxLayout* m_rootLayout = nullptr;        // m_rootLayout：页面根布局。
        QWidget* m_toolbarWidget = nullptr;         // m_toolbarWidget：顶部工具栏容器。
        QPushButton* m_refreshButton = nullptr;     // m_refreshButton：刷新按钮。
        QPushButton* m_exportButton = nullptr;      // m_exportButton：导出按钮。
        QPushButton* m_appLockerEditButton = nullptr; // m_appLockerEditButton：AppLocker 策略编辑按钮。
        QPushButton* m_wdacEditButton = nullptr;      // m_wdacEditButton：WDAC 源策略编辑按钮。
        QPushButton* m_defenderEditButton = nullptr;  // m_defenderEditButton：Defender 配置编辑按钮。
        QLabel* m_statusLabel = nullptr;            // m_statusLabel：总体状态标签。
        QTabWidget* m_tabWidget = nullptr;          // m_tabWidget：五个子页的总 Tab。

        QWidget* m_appLockerPage = nullptr;         // m_appLockerPage：AppLocker 页面。
        QWidget* m_wdacPage = nullptr;              // m_wdacPage：WDAC / Code Integrity 页面。
        QWidget* m_defenderPage = nullptr;          // m_defenderPage：Defender / ASR 页面。
        QWidget* m_eventPage = nullptr;             // m_eventPage：事件日志页面。
        QWidget* m_fileDiagnosisPage = nullptr;      // m_fileDiagnosisPage：文件诊断页面。

        CodeEditorWidget* m_appLockerSummary = nullptr;   // m_appLockerSummary：AppLocker 说明文本。
        QTableWidget* m_appLockerTable = nullptr;       // m_appLockerTable：AppLocker 规则表。
        CodeEditorWidget* m_wdacSummary = nullptr;        // m_wdacSummary：WDAC 说明文本。
        QTableWidget* m_policyFileTable = nullptr;      // m_policyFileTable：WDAC 策略文件表。
        QTableWidget* m_codeIntegrityEventTable = nullptr; // m_codeIntegrityEventTable：Code Integrity 事件表。
        CodeEditorWidget* m_defenderSummary = nullptr;    // m_defenderSummary：Defender 状态文本。
        QTableWidget* m_defenderTable = nullptr;        // m_defenderTable：Defender 键值表。
        QWidget* m_platformPage = nullptr;              // m_platformPage：平台安全页面。
        CodeEditorWidget* m_platformSummary = nullptr;    // m_platformSummary：平台安全状态文本。
        QTableWidget* m_platformTable = nullptr;        // m_platformTable：平台安全键值表。
        CodeEditorWidget* m_eventSummary = nullptr;       // m_eventSummary：事件日志文本。
        QTableWidget* m_eventTable = nullptr;           // m_eventTable：事件表。
        QComboBox* m_eventVerdictFilterCombo = nullptr; // m_eventVerdictFilterCombo：事件分类筛选器。
        QComboBox* m_eventLimitCombo = nullptr;         // m_eventLimitCombo：事件读取数量选择。
        QLineEdit* m_filePathEdit = nullptr;            // m_filePathEdit：文件诊断输入框。
        QPushButton* m_fileBrowseButton = nullptr;      // m_fileBrowseButton：浏览按钮。
        QPushButton* m_fileDiagnoseButton = nullptr;    // m_fileDiagnoseButton：诊断按钮。
        CodeEditorWidget* m_fileDiagnosisSummary = nullptr; // m_fileDiagnosisSummary：文件诊断说明文本。
        QTableWidget* m_fileDiagnosisTable = nullptr;   // m_fileDiagnosisTable：文件诊断结果表。

        QVector<AppLockerRuleRecord> m_appLockerRules;  // m_appLockerRules：最近一次 AppLocker 规则快照。
        QVector<EventRecord> m_eventRows;               // m_eventRows：最近一次完整事件日志缓存。
        QVector<KeyValueRecord> m_platformRows;         // m_platformRows：最近一次平台安全诊断缓存。
        std::uint64_t m_refreshGeneration = 0;           // m_refreshGeneration：UI 线程维护的刷新代次，阻止旧结果回写。
        int m_pendingMutationCount = 0;                  // m_pendingMutationCount：正在执行的配置写入任务数。
        bool m_appLockerModuleAvailable = false;         // m_appLockerModuleAvailable：当前系统是否提供 AppLocker 管理模块。
    };
}
