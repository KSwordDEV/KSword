#pragma once

// ============================================================
// HandleDock.h
// 作用：
// - 提供“句柄”Dock 页面，包含“Handle Table / Object Header / Object Type”三个 Tab；
// - Handle Table 页只负责句柄解码、过滤和风险标记；
// - Object Header 页只负责当前选中句柄的对象头、类型归属和证据展示；
// - Object Type 页复刻原内核对象类型视图，并为句柄页提供类型名映射。
// ============================================================

#include "../Framework.h"
#include "./HandleFilterConfig.h"
#include "HandleObjectTypeWorker.h"
#include "../UI/AsyncOperation.h"
#include "../../../shared/driver/KswordArkHandleIoctl.h"

#include <QHash>
#include <QIcon>
#include <QWidget>
#include <QVector>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

class QCheckBox;
class QComboBox;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPoint;
class QPushButton;
class QShowEvent;
class QSpinBox;
class QTabWidget;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;

namespace ks::handle
{
    enum class HandleTreeItemKind : int
    {
        RuleSummary = 1,
        HandleRow,
        LoadMore,
        LazyPlaceholder
    };

    constexpr int HandleTreeItemKindRole = Qt::UserRole + 101;
    constexpr int HandleTreeRuleIdRole = Qt::UserRole + 102;
    constexpr int HandleTreeRuleOrderRole = Qt::UserRole + 103;
    constexpr int HandleTreeSourceRowIndexRole = Qt::UserRole + 104;
}

class HandleDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数作用：
    // - 创建句柄页面全部控件与多 Tab 结构；
    // - 初始化筛选条件、右键菜单、异步刷新入口。
    // 调用方法：MainWindow 创建 HandleDock(this)。
    // 传入 parent：Qt 父对象。
    // 传出：无（通过对象状态持有 UI 与缓存）。
    explicit HandleDock(QWidget* parent = nullptr);
    // 派生成员销毁前关闭详情异步门禁，再由成员删除 QObject 子对象。
    ~HandleDock() override;

    // focusProcessId 作用：
    // - 外部调用时把 PID 过滤框切换为目标 PID；
    // - 自动切到“句柄列表”Tab，并可选立即触发刷新。
    // 调用方法：MainWindow::focusHandleDockByPid 调用本函数。
    // 传入 processId：目标进程 PID；triggerRefresh：是否立即刷新。
    // 传出：无（内部更新 UI 状态与刷新任务）。
    void focusProcessId(std::uint32_t processId, bool triggerRefresh);
    void focusProcessIds(const QVector<quint32>& processIds, bool triggerRefresh);

protected:
    // showEvent 作用：
    // - 页面首次可见时触发对象类型与句柄首轮刷新；
    // - 避免主窗口启动阶段被重查询拖慢。
    // 调用方法：Qt 自动回调。
    // 传入 event：显示事件对象。
    // 传出：无。
    void showEvent(QShowEvent* event) override;

private:
    // HandleTableColumn 作用：
    // - 统一定义句柄列表列索引，杜绝魔法数字。
    enum class HandleTableColumn : int
    {
        ProcessId = 0,   // ProcessId：所属进程 PID。
        ProcessName,     // ProcessName：进程名。
        HandleValue,     // HandleValue：句柄值（十六进制）。
        TypeIndex,       // TypeIndex：对象类型索引。
        ObjectName,      // ObjectName：对象名称（可为空）。
        ObjectAddress,   // ObjectAddress：内核对象地址（十六进制）。
        GrantedAccess,   // GrantedAccess：访问掩码（十六进制）。
        Attributes,      // Attributes：句柄属性文本。
        HandleCount,     // HandleCount：对象当前 HandleCount。
        PointerCount,    // PointerCount：对象当前 PointerCount。
        Source,          // Source：本行句柄来自用户态快照、DuplicateHandle 解析或 R0 HandleTable。
        DecodeStatus,    // DecodeStatus：R0 解码状态或用户态解析状态。
        DiffStatus,      // DiffStatus：用户态/R0 差异状态。
        Count            // Count：列总数。
    };

    // ObjectTypeTableColumn 作用：
    // - 统一定义对象类型页列索引；
    // - 与旧 KernelDock 对象类型列保持同语义。
    enum class ObjectTypeTableColumn : int
    {
        TypeIndex = 0,      // TypeIndex：类型编号。
        TypeName,           // TypeName：类型名。
        ObjectCount,        // ObjectCount：对象总数。
        HandleCount,        // HandleCount：句柄总数。
        AccessMask,         // AccessMask：访问掩码。
        SecurityRequired,   // SecurityRequired：是否需要安全检查。
        MaintainCount,      // MaintainCount：是否维护句柄计数。
        Count               // Count：列总数。
    };

    // HandleEnumMode 作用：
    // - 描述句柄刷新时使用的枚举来源；
    // - UserSnapshot 保持原 NtQuerySystemInformation 路径，DuplicateHandle 表示用户态快照并解析对象信息，KernelHandleTable 表示 R0 直接读 HandleTable。
    enum class HandleEnumMode : int
    {
        UserSnapshot = 0,    // UserSnapshot：仅用户态系统句柄快照，不强制解析对象名。
        DuplicateHandle,     // DuplicateHandle：用户态快照 + DuplicateHandle 解析对象计数/名称。
        KernelHandleTable    // KernelHandleTable：R0 目标进程 HandleTable 枚举。
    };

    // HandleDiffStatus 作用：
    // - 表示 R0/R3 两种枚举路径的差异关系；
    // - 用于 Phase-4 差异视图过滤。
    enum class HandleDiffStatus : int
    {
        NotCompared = 0, // NotCompared：当前模式未做双源对比。
        UserOnly,        // UserOnly：仅用户态快照可见。
        KernelOnly,      // KernelOnly：仅 R0 HandleTable 可见。
        Both             // Both：两者均可见。
    };

    // HandleRow 作用：
    // - UI 层展示用的单行句柄记录；
    // - 字段全部为最终渲染态，避免主线程做二次转换。
    struct HandleRow
    {
        std::uint32_t processId = 0;       // processId：句柄所属进程 PID。
        std::uint64_t processCreationTime = 0; // processCreationTime：进程创建时间，关闭前复核 PID 身份。
        QString processName;               // processName：句柄所属进程名。
        std::uint64_t handleValue = 0;     // handleValue：句柄数值。
        std::uint16_t typeIndex = 0;       // typeIndex：内核对象类型索引。
        QString typeName;                  // typeName：对象类型名。
        QString objectName;                // objectName：对象名称文本。
        std::uint64_t objectAddress = 0;   // objectAddress：对象地址。
        std::uint32_t grantedAccess = 0;   // grantedAccess：访问掩码。
        std::uint32_t attributes = 0;      // attributes：句柄属性位。
        std::uint32_t handleCount = 0;     // handleCount：对象句柄计数。
        std::uint32_t pointerCount = 0;    // pointerCount：对象指针计数。
        bool basicInfoAvailable = false;   // basicInfoAvailable：是否成功读取 ObjectBasicInformation。
        bool objectNameAvailable = false;  // objectNameAvailable：是否成功完成对象名查询（允许结果为空串）。
        bool objectNameFailed = false;     // objectNameFailed：对象名查询已尝试但失败。
        bool objectNameFromFallback = false; // objectNameFromFallback：对象名是否来自类型专用回退查询。
        HandleEnumMode sourceMode = HandleEnumMode::UserSnapshot; // sourceMode：记录本行主要来源。
        HandleDiffStatus diffStatus = HandleDiffStatus::NotCompared; // diffStatus：R0/R3 差异状态。
        std::uint32_t decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE; // decodeStatus：R0 解码状态或用户态解析状态。
        std::uint32_t r0FieldFlags = 0; // r0FieldFlags：R0 返回的字段可用位。
        std::uint64_t r0DynDataCapabilityMask = 0; // r0DynDataCapabilityMask：R0 枚举时的 DynData capability。
        std::uint32_t epObjectTableOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // epObjectTableOffset：EPROCESS.ObjectTable 偏移。
        std::uint32_t htHandleContentionEventOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // htHandleContentionEventOffset：HandleTable 解锁偏移。
        std::uint32_t obDecodeShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // obDecodeShift：对象指针解码 shift。
        std::uint32_t obAttributesShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // obAttributesShift：属性解码 shift。
        std::uint32_t otNameOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // otNameOffset：OBJECT_TYPE.Name 偏移。
        std::uint32_t otIndexOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE; // otIndexOffset：OBJECT_TYPE.Index 偏移。
    };

    // HandleRefreshOptions 作用：
    // - 把主线程当前过滤配置打包后传给后台线程；
    // - 避免后台线程直接访问 Qt 控件。
    struct HandleRefreshOptions
    {
        bool hasPidFilter = false;                 // hasPidFilter：是否启用 PID 过滤。
        std::uint32_t pidFilter = 0;               // pidFilter：目标 PID。
        QString keywordText;                       // keywordText：关键字（小写）。
        QString typeFilterText;                    // typeFilterText：类型过滤文本。
        bool onlyNamed = false;                    // onlyNamed：仅显示“有对象名”的句柄。
        bool resolveObjectName = true;             // resolveObjectName：是否尝试解析对象名。
        int nameResolveBudget = 300;               // nameResolveBudget：对象名解析预算数量。
        HandleEnumMode enumMode = HandleEnumMode::DuplicateHandle; // enumMode：本轮刷新选择的枚举模式。
        HandleDiffStatus diffFilter = HandleDiffStatus::NotCompared; // diffFilter：差异状态过滤。
        std::unordered_map<std::uint16_t, std::string> typeNameCacheByIndex; // typeNameCacheByIndex：上一轮类型缓存。
        std::unordered_map<std::uint16_t, std::string> typeNameMapFromObjectTab; // typeNameMapFromObjectTab：对象类型页产出的映射。
    };

    // HandleRefreshResult 作用：
    // - 后台线程返回给主线程的句柄刷新结果；
    // - 包含句柄行、类型列表与状态文案。
    struct HandleRefreshResult
    {
        std::vector<HandleRow> rows;               // rows：过滤后的句柄行结果。
        std::vector<QString> availableTypeList;    // availableTypeList：本轮可选类型列表。
        std::unordered_map<std::uint16_t, std::string> updatedTypeNameCacheByIndex; // updatedTypeNameCacheByIndex：更新后的类型缓存。
        std::size_t totalHandleCount = 0;          // totalHandleCount：系统总句柄数（枚举层）。
        std::size_t visibleHandleCount = 0;        // visibleHandleCount：过滤后可见句柄数。
        std::size_t basicInfoResolvedCount = 0;    // basicInfoResolvedCount：成功读取 BasicInformation 的句柄数量。
        std::size_t resolvedNameCount = 0;         // resolvedNameCount：成功解析对象名数量。
        std::size_t fallbackNameCount = 0;         // fallbackNameCount：通过类型专用回退拿到对象名的数量。
        std::size_t objectTypeMappedCount = 0;     // objectTypeMappedCount：通过对象类型页映射命中的数量。
        std::size_t kernelHandleCount = 0;         // kernelHandleCount：R0 HandleTable 返回数量。
        std::size_t userOnlyCount = 0;             // userOnlyCount：差异视图中仅用户态可见数量。
        std::size_t kernelOnlyCount = 0;           // kernelOnlyCount：差异视图中仅 R0 可见数量。
        std::size_t bothCount = 0;                 // bothCount：差异视图中双源均可见数量。
        std::uint64_t elapsedMs = 0;               // elapsedMs：后台耗时毫秒。
        QString diagnosticText;                    // diagnosticText：诊断信息（失败/降级/预算等）。
        bool snapshotScopedToPid = false;          // snapshotScopedToPid：本轮快照是否只枚举单个 PID。
        std::uint32_t scopedProcessId = 0;         // scopedProcessId：单 PID 快照的目标 PID。
    };

    // ObjectTypeRefreshResult 作用：
    // - 后台线程返回给主线程的对象类型刷新结果；
    // - 包含对象类型行与 typeIndex 映射。
    struct ObjectTypeRefreshResult
    {
        std::vector<HandleObjectTypeEntry> rows;   // rows：对象类型行列表。
        std::unordered_map<std::uint16_t, std::string> typeNameMapByIndex; // typeNameMapByIndex：类型名映射。
        std::uint64_t elapsedMs = 0;               // elapsedMs：刷新耗时毫秒。
        QString diagnosticText;                    // diagnosticText：诊断文本。
    };

    // HandleDetailField 作用：
    // - 表示句柄详情面板中的一条键值记录；
    // - 供异步详情结果回填到详情树控件。
    struct HandleDetailField
    {
        QString keyText;     // keyText：字段名。
        QString valueText;   // valueText：字段值。
    };

    // HandleDetailRefreshResult 作用：
    // - 表示句柄详情后台查询结果；
    // - 包含通用字段、类型专用字段与诊断信息。
    struct HandleDetailRefreshResult
    {
        std::vector<HandleDetailField> fields; // fields：详情键值列表。
        QString diagnosticText;                // diagnosticText：诊断信息。
        std::uint64_t elapsedMs = 0;           // elapsedMs：详情查询耗时。
    };

    struct HandleRuleMatchState
    {
        QString ruleId;
        QString ruleName;
        bool enabled = true;
        std::vector<std::size_t> rowIndices;
        std::size_t loadedCount = 0;
        QTreeWidgetItem* summaryItem = nullptr;
    };

private:
    // initializeUi 作用：
    // - 创建页面布局与多 Tab 容器；
    // - 构建 Handle Table / Object Header / Object Type 三个页签。
    // 调用方法：构造函数内部调用一次。
    // 传入/传出：无。
    void initializeUi();

    // initializeHandleListTab 作用：
    // - 构建 Handle Table Tab 的规则工具栏、全局采集设置、状态栏和结果树；
    // - 绑定图标按钮与控件样式。
    // 调用方法：initializeUi 内部调用。
    // 传入/传出：无。
    void initializeHandleListTab();

    // initializeObjectHeaderTab 作用：
    // - 构建 Object Header Tab 的只读详情树；
    // - 该页展示当前选中句柄的对象头、类型归属和风险标记。
    // 调用方法：initializeUi 内部调用。
    // 传入/传出：无。
    void initializeObjectHeaderTab();

    // initializeObjectTypeTab 作用：
    // - 构建 Object Type Tab（原 Kernel 对象类型视图）；
    // - 提供过滤、刷新、详情面板。
    // 调用方法：initializeUi 内部调用。
    // 传入/传出：无。
    void initializeObjectTypeTab();

    // initializeHandleTable 作用：
    // - 初始化句柄列表列、排序、选择行为；
    // - 统一列宽与右键策略。
    // 调用方法：initializeHandleListTab 内部调用。
    // 传入/传出：无。
    void initializeHandleTable();

    // initializeObjectTypeTable 作用：
    // - 初始化对象类型表列与交互行为；
    // - 与原 KernelDock 对象类型页保持一致列语义。
    // 调用方法：initializeObjectTypeTab 内部调用。
    // 传入/传出：无。
    void initializeObjectTypeTable();

    // initializeConnections 作用：
    // - 连接刷新按钮、筛选控件、右键菜单与详情联动；
    // - 把用户交互绑定到刷新管线。
    // 调用方法：构造函数内部调用一次。
    // 传入/传出：无。
    void initializeConnections();

    // requestAsyncRefresh 作用：
    // - 发起异步句柄刷新任务；
    // - 用 ticket 防止旧结果覆盖新结果。
    // 调用方法：按钮点击、筛选变化、首次显示时调用。
    // 传入 forceRefresh：true 允许强制拉起；false 遇到进行中任务则忽略。
    // 传出：无（结果通过 applyHandleRefreshResult 回填）。
    void requestAsyncRefresh(bool forceRefresh);

    // requestAsyncRefreshWithoutTypePrecondition 作用：
    // - 启动实际句柄枚举后台任务，不再检查对象类型映射是否已就绪；
    // - 仅供 requestAsyncRefresh 的正常路径和对象类型快照失败时的兜底路径调用。
    // 调用方法：requestAsyncRefresh / applyObjectTypeRefreshResult 内部调用。
    // 传入 forceRefresh：true 表示进行中时记录待执行请求；false 表示进行中时忽略。
    // 传出：无（结果通过 applyHandleRefreshResult 回填）。
    void requestAsyncRefreshWithoutTypePrecondition(bool forceRefresh);

    // requestObjectTypeRefreshAsync 作用：
    // - 发起异步对象类型刷新任务；
    // - 成功后更新 typeIndex->typeName 映射供句柄枚举复用。
    // 调用方法：对象类型页刷新按钮、首次显示时调用。
    // 传入 forceRefresh：true 强制刷新；false 忽略并发。
    // 传出：无（结果通过 applyObjectTypeRefreshResult 回填）。
    void requestObjectTypeRefreshAsync(bool forceRefresh);

    // applyHandleRefreshResult 作用：
    // - 在主线程应用句柄刷新结果；
    // - 更新缓存、类型下拉、状态文字，并在类型映射可用后更新表格。
    // 调用方法：后台任务完成后 invokeMethod 回调。
    // 传入 refreshTicket：任务序号；refreshResult：后台结果对象。
    // 传出：无。
    void applyHandleRefreshResult(std::uint64_t refreshTicket, const HandleRefreshResult& refreshResult);

    // applyObjectTypeRefreshResult 作用：
    // - 在主线程应用对象类型刷新结果；
    // - 更新对象类型表与类型映射缓存，并回刷句柄类型名。
    // 调用方法：对象类型后台任务完成后回调。
    // 传入 refreshTicket：任务序号；refreshResult：后台结果对象。
    // 传出：无。
    void applyObjectTypeRefreshResult(std::uint64_t refreshTicket, const ObjectTypeRefreshResult& refreshResult);

    // rebuildHandleTable 作用：
    // - 根据规则匹配状态重建摘要树，不自动创建完整句柄行；
    // - 明细由规则展开事件按 300 条批量创建。
    // 调用方法：applyHandleRefreshResult / syncHandleTypeNamesFromObjectTypeMap 内部调用。
    // 传入/传出：无。
    void rebuildHandleTable();

    // applyLocalHandleFilters 作用：
    // - 对当前完整句柄快照做本地过滤，不重新枚举系统句柄；
    // - 用于 PID/类型/关键字等轻量交互，避免反复重型刷新。
    // 调用方法：过滤条件变更、句柄刷新完成且可渲染时调用。
    // 传入/传出：无。
    void applyLocalHandleFilters();

    // applyLocalHandleFilters 作用：
    // - 对当前完整句柄快照做本地过滤，并按需重建图形界面表格；
    // - 句柄枚举先完成但对象类型映射尚未到达时，只更新 m_rows 缓存，不触发表格渲染。
    // 调用方法：applyHandleRefreshResult / syncHandleTypeNamesFromObjectTypeMap / applyLocalHandleFilters 调用。
    // 传入 rebuildTable：true 立即重建表格；false 仅更新过滤缓存。
    // 传出：无。
    void applyLocalHandleFilters(bool rebuildTable);

    void rebuildRuleSummaryTree();
    void appendNextRuleResultBatch(const QString& ruleId);
    QTreeWidgetItem* createHandleTreeRow(std::size_t sourceRowIndex);
    void scheduleProcessIconResolution(
        const QVector<qulonglong>& sourceRowIndices,
        const QVector<QTreeWidgetItem*>& itemList);
    HandleRuleMatchState* findRuleMatchState(const QString& ruleId);
    const HandleRuleMatchState* findRuleMatchState(const QString& ruleId) const;
    const ks::handle::HandleFilterRule* findActiveRule(const QString& ruleId) const;
    bool handleRowMatchesRule(
        const HandleRow& row,
        const ks::handle::HandleFilterRule& rule) const;
    void updateHandleSummaryStatus();
    void sortLoadedRuleRows(int column, Qt::SortOrder order);

    void loadFilterConfiguration();
    void saveFilterConfiguration() const;
    void applyFilterGlobalSettingsToControls();
    void collectFilterGlobalSettingsFromControls();
    void showRuleManagerDialog(const QString& initiallySelectedRuleId = QString());
    bool showRuleEditorDialog(
        ks::handle::HandleFilterRule* ruleInOut,
        const QVector<ks::handle::HandleFilterRule>& existingRules);
    void importFilterConfiguration();
    void exportFilterConfiguration() const;
    void exportRuleResults(const QString& ruleId = QString()) const;
    void returnToSavedFilters();
    QString buildRuleConditionSummary(const ks::handle::HandleFilterRule& rule) const;

    // rebuildObjectTypeTable 作用：
    // - 根据 m_objectTypeRows 重建对象类型表；
    // - 支持按关键词过滤类型名与编号。
    // 调用方法：对象类型刷新完成、过滤框变更时调用。
    // 传入 filterKeyword：过滤关键字（可为空）。
    // 传出：无。
    void rebuildObjectTypeTable(const QString& filterKeyword);

    // collectHandleRefreshOptions 作用：
    // - 从持久化全局设置读取采集配置并封装线程安全结构；
    // - 仅临时单 PID 筛选允许收窄后台枚举范围。
    // 调用方法：requestAsyncRefresh 内部调用。
    // 传入/传出：无，返回 HandleRefreshOptions。
    HandleRefreshOptions collectHandleRefreshOptions() const;

    // updateTypeFilterItems 作用：
    // - 根据刷新结果重建“类型过滤”下拉项；
    // - 保留用户之前选择，避免刷新后重置。
    // 调用方法：applyHandleRefreshResult 内部调用。
    // 传入 availableTypeList：本轮类型列表。
    // 传出：无。
    void updateTypeFilterItems(const std::vector<QString>& availableTypeList);

    // refreshTypeFilterItemsFromAllRows 作用：
    // - 根据完整句柄快照重建类型过滤下拉项；
    // - 用于对象类型映射更新后同步过滤选项。
    // 调用方法：applyHandleRefreshResult / syncHandleTypeNamesFromObjectTypeMap 调用。
    // 传入/传出：无。
    void refreshTypeFilterItemsFromAllRows();

    // syncHandleTypeNamesFromObjectTypeMap 作用：
    // - 在对象类型页刷新完成后，把当前已缓存句柄行的类型名就地同步；
    // - 避免再次触发一次重型句柄枚举，从而减少 UI 卡顿。
    // 调用方法：applyObjectTypeRefreshResult 内部调用。
    // 传入/传出：无。
    void syncHandleTypeNamesFromObjectTypeMap();

    // requestHandleDetailRefresh 作用：
    // - 对当前选中句柄异步拉取详细信息；
    // - 详情包含通用字段与按类型分支的专用信息。
    // 调用方法：选中行切换、手动刷新详情时调用。
    // 传入 forceRefresh：true 强制刷新；选择变化请求均合并为最新行快照。
    // 传出：无。
    void requestHandleDetailRefresh(bool forceRefresh);

    // applyHandleDetailRefreshResult 作用：
    // - 在主线程应用句柄详情异步结果；
    // - 回填详情表和状态文本。
    // 调用方法：详情后台任务完成后回调。
    // 传入 refreshTicket：详情刷新序号；refreshResult：详情结果。
    // 传出：无。
    void applyHandleDetailRefreshResult(std::uint64_t refreshTicket, const HandleDetailRefreshResult& refreshResult);
    // 核验代次与句柄/进程实例后提交；菜单延期重放再次走同一验证入口。
    bool tryApplyHandleDetailRefreshResult(std::uint64_t refreshTicket,
        const HandleRow& expectedRow, const HandleDetailRefreshResult& refreshResult);

    // updateHandleStatusLabel 作用：
    // - 统一更新句柄页状态标签文本与颜色；
    // - 在刷新中/完成态使用不同样式。
    // 调用方法：requestAsyncRefresh、applyHandleRefreshResult 调用。
    // 传入 statusText：显示文本；refreshing：是否处于刷新中。
    // 传出：无。
    void updateHandleStatusLabel(const QString& statusText, bool refreshing);

    // updateObjectTypeStatusLabel 作用：
    // - 更新对象类型页状态标签文本与颜色；
    // - 用于展示对象类型刷新状态。
    // 调用方法：requestObjectTypeRefreshAsync、applyObjectTypeRefreshResult 调用。
    // 传入 statusText：状态文本；refreshing：是否刷新中。
    // 传出：无。
    void updateObjectTypeStatusLabel(const QString& statusText, bool refreshing);

    // focusObjectTypeByIndex 作用：
    // - 切换到对象类型 Tab 并定位指定 typeIndex；
    // - 若未命中则仅设置过滤条件。
    // 调用方法：句柄列表右键“转到对象类型”调用。
    // 传入 typeIndex：目标类型索引。
    // 传出：无。
    void focusObjectTypeByIndex(std::uint16_t typeIndex);

    // showHandleTableContextMenu 作用：
    // - 在句柄表上弹出右键菜单；
    // - 只提供复制、跳转和刷新等只读动作。
    // 调用方法：QTreeWidget::customContextMenuRequested 回调。
    // 传入 localPosition：表格局部坐标。
    // 传出：无。
    void showHandleTableContextMenu(const QPoint& localPosition);

    // showHandleHeaderContextMenu 作用：
    // - 在句柄表头弹出列管理菜单；
    // - 支持显示/隐藏列，补足基础列系统能力。
    // 调用方法：QHeaderView::customContextMenuRequested 回调。
    // 传入 localPosition：表头局部坐标。
    // 传出：无。
    void showHandleHeaderContextMenu(const QPoint& localPosition);

    // showObjectTypeDetailByCurrentRow 作用：
    // - 根据对象类型表当前行刷新详情文本；
    // - 复刻原 KernelDock 对象类型详情。
    // 调用方法：currentCellChanged 回调。
    // 传入/传出：无。
    void showObjectTypeDetailByCurrentRow();

    // showHandleDetailPlaceholder 作用：
    // - 在无选中句柄或详情未就绪时显示占位内容；
    // - 避免详情区域残留旧数据。
    // 调用方法：初始化、过滤后无选中项时调用。
    // 传入 messageText：占位说明文本。
    // 传出：无。
    void showHandleDetailPlaceholder(const QString& messageText);

    // selectedHandleRow 作用：
    // - 读取当前选中句柄行对应的缓存记录；
    // - 返回可修改指针供动作函数使用。
    // 调用方法：右键动作执行前调用。
    // 传入/传出：无，返回 HandleRow*（无选中时返回 nullptr）。
    HandleRow* selectedHandleRow();

    // copyCurrentHandleCell 作用：
    // - 复制当前句柄单元格文本到剪贴板；
    // - 用于快速审计字段值。
    // 调用方法：右键菜单“复制单元格”。
    // 传入/传出：无。
    void copyCurrentHandleCell();

    // copyCurrentHandleRow 作用：
    // - 复制当前句柄整行（TAB 分隔）到剪贴板；
    // - 便于粘贴到表格工具或日志。
    // 调用方法：右键菜单“复制整行”。
    // 传入/传出：无。
    void copyCurrentHandleRow();

    // closeCurrentHandle 作用：
    // - 对菜单捕获的独立句柄快照执行 R3 或 R0 关闭；
    // - 成功后自动触发刷新；
    // 传入 row：独立行快照；useDriver：选择 R0。
    void closeHandleRow(const HandleRow& row, bool useDriver);

    // closeSameTypeHandlesInCurrentProcess 作用：
    // - 关闭“同 PID + 同 TypeIndex”的一组句柄；
    // - 用于批量处置异常句柄，提升句柄管理能力；
    // - 当前默认 UI 不再暴露该入口。
    // 传入/传出：无。
    void closeSameTypeHandlesInCurrentProcess();

    // buildHandleRefreshResult 作用：
    // - 后台线程核心：枚举系统句柄并按条件筛选；
    // - 优先使用对象类型页映射生成类型名，再补充兜底查询。
    // 调用方法：requestAsyncRefresh 在后台线程中调用。
    // 传入 options：刷新配置。
    // 传出：HandleRefreshResult（按值返回）。
    static HandleRefreshResult buildHandleRefreshResult(const HandleRefreshOptions& options);

    // buildObjectTypeRefreshResult 作用：
    // - 后台线程核心：刷新对象类型快照并构建 typeIndex 映射；
    // - 供对象类型 Tab 和句柄列表共享。
    // 调用方法：requestObjectTypeRefreshAsync 在后台线程调用。
    // 传入：无。
    // 传出：ObjectTypeRefreshResult（按值返回）。
    static ObjectTypeRefreshResult buildObjectTypeRefreshResult();

    // closeRemoteHandle 作用：
    // - 封装关闭远程进程句柄的 Win32 操作；
    // - 返回布尔结果与详细错误文本。
    // 调用方法：closeCurrentHandle / closeSameTypeHandlesInCurrentProcess 调用。
    // 传入 processId：目标 PID；handleValue：目标句柄值。
    // 传出 detailTextOut：动作详情；返回 true/false。
    static bool closeRemoteHandle(const HandleRow& expectedRow, std::string& detailTextOut);

    // buildHandleDetailRefreshResult 作用：
    // - 后台线程核心：按句柄类型生成专用详情；
    // - 支持 File/Key/Process/Thread/Token/Section/Event/Mutant 等类型的增强展示。
    // 调用方法：requestHandleDetailRefresh 在线程池中调用。
    // 传入 row：当前选中句柄行快照。
    // 传出：HandleDetailRefreshResult（按值返回）。
    static HandleDetailRefreshResult buildHandleDetailRefreshResult(const HandleRow& row);

    // formatHex 作用：统一把数值转为 0x 前缀十六进制文本。
    // 调用方法：表格渲染时调用。
    // 传入 value：64 位值；width：最小宽度（补零）。
    // 传出：QString 文本。
    static QString formatHex(std::uint64_t value, int width = 0);

    // formatOptionalObjectCount 作用：
    // - 统一格式化 HandleCount/PointerCount 文本；
    // - 区分“值为 0”和“未查到”两种状态。
    // 调用方法：句柄列表与详情面板渲染时调用。
    // 传入 countValue：计数字段值；countAvailable：是否成功查到。
    // 传出：QString 文本。
    static QString formatOptionalObjectCount(std::uint32_t countValue, bool countAvailable);

    // formatObjectNameDisplayText 作用：
    // - 统一格式化对象名列与详情面板文本；
    // - 区分“未查询 / 未查到 / 无名称 / 有名称”四种状态。
    // 调用方法：句柄列表与详情面板渲染时调用。
    // 传入 row：当前句柄行数据。
    // 传出：QString 文本。
    static QString formatObjectNameDisplayText(const HandleRow& row);

    // formatTypeIndexDisplayText 作用：
    // - 把 TypeIndex 列格式化为“类型名 + 编号”可读文本；
    // - 已解析类型时显示如“Directory (50)”；未解析时仅显示编号。
    // 调用方法：句柄表渲染与类型名同步时调用。
    // 传入 typeIndex：类型索引；typeName：类型名称。
    // 传出：QString 文本。
    static QString formatTypeIndexDisplayText(std::uint16_t typeIndex, const QString& typeName);

    // formatHandleAttributes 作用：
    // - 把句柄属性位转换为可读文本（INHERIT/PROTECT/AUDIT）；
    // - 未命中时回退“None”。
    // 调用方法：表格渲染时调用。
    // 传入 attributes：原始属性位。
    // 传出：QString 文本。
    static QString formatHandleAttributes(std::uint32_t attributes);

    // formatHandleSourceText 作用：把行来源枚举转换为 UI 文本。
    // 调用方法：句柄表渲染、详情面板和过滤时调用。
    // 传入 mode：来源枚举值。
    // 传出：QString 文本。
    static QString formatHandleSourceText(HandleEnumMode mode);

    // formatHandleDecodeStatusText 作用：把 R0 解码状态或用户态状态转换为 UI 文本。
    // 调用方法：句柄表渲染、详情面板和过滤时调用。
    // 传入 status：KSWORD_ARK_HANDLE_DECODE_STATUS_*。
    // 传出：QString 文本。
    static QString formatHandleDecodeStatusText(std::uint32_t status);

    // formatHandleDiffStatusText 作用：把差异状态转换为 UI 文本。
    // 调用方法：句柄表渲染、详情面板和过滤时调用。
    // 传入 status：HandleDiffStatus。
    // 传出：QString 文本。
    static QString formatHandleDiffStatusText(HandleDiffStatus status);

    // resolveHandleEnumModeFromText 作用：把 UI 下拉框文本转换为枚举模式。
    // 调用方法：collectHandleRefreshOptions 内部调用。
    // 传入 modeText：下拉框当前文本。
    // 传出：HandleEnumMode。
    static HandleEnumMode resolveHandleEnumModeFromText(const QString& modeText);

    // resolveHandleDiffFilterFromText 作用：把 UI 下拉框文本转换为差异过滤枚举。
    // 调用方法：collectHandleRefreshOptions/applyLocalHandleFilters 内部调用。
    // 传入 filterText：下拉框当前文本。
    // 传出：HandleDiffStatus。
    static HandleDiffStatus resolveHandleDiffFilterFromText(const QString& filterText);

    // resolveProcessIconForRow 作用：
    // - 仅为当前句柄快照中的 PID + 创建时间实例解析并缓存进程图标；
    // - 不能确认实例时返回默认图标，避免 PID 复用后错误归属路径或图标。
    // 调用方法：重建句柄表时调用。
    // 传入 row：携带进程实例身份的句柄快照行。
    // 传出：QIcon 进程图标；无法确认实例时回退默认图标。
    QIcon resolveProcessIconForRow(const HandleRow& row);

    // queryProcessImagePathCached 作用：
    // - 查询并缓存指定进程实例对应的映像路径；
    // - 校验与路径查询共用一个进程句柄，避免 PID 复用导致错配。
    // 调用方法：resolveProcessIconForRow 内部调用。
    // 传入 processId / expectedCreationTime：目标进程实例身份。
    // 传出：QString 进程路径；身份无法确认或查询失败时返回空字符串。
    QString queryProcessImagePathCached(std::uint32_t processId, std::uint64_t expectedCreationTime);

    // decodeGrantedAccessText 作用：
    // - 按对象类型把 GrantedAccess 位掩码翻译成语义权限文本；
    // - 用于列表 tooltip 与详情面板增强可读性。
    // 调用方法：句柄表渲染与详情构建时调用。
    // 传入 typeName：对象类型名；grantedAccess：访问掩码。
    // 传出：QString 语义权限文本。
    static QString decodeGrantedAccessText(const QString& typeName, std::uint32_t grantedAccess);

private:
    QVBoxLayout* m_rootLayout = nullptr;         // m_rootLayout：页面根布局。
    QTabWidget* m_tabWidget = nullptr;           // m_tabWidget：句柄模块 Tab 容器。

    QWidget* m_handleListPage = nullptr;         // m_handleListPage：Handle Table 页容器。
    QVBoxLayout* m_handleListLayout = nullptr;   // m_handleListLayout：Handle Table 页布局。
    QHBoxLayout* m_toolbarLayout = nullptr;      // m_toolbarLayout：Handle Table 顶部工具栏布局。
    QPushButton* m_refreshButton = nullptr;      // m_refreshButton：句柄刷新按钮（图标化）。
    QPushButton* m_manageFilterButton = nullptr;
    QPushButton* m_importFilterButton = nullptr;
    QPushButton* m_exportFilterButton = nullptr;
    QPushButton* m_exportResultsButton = nullptr;
    QPushButton* m_returnSavedFilterButton = nullptr;
    QComboBox* m_enumModeCombo = nullptr;        // m_enumModeCombo：枚举模式下拉。
    QCheckBox* m_resolveNameCheckBox = nullptr;  // m_resolveNameCheckBox：是否开启对象名解析。
    QSpinBox* m_nameBudgetSpinBox = nullptr;     // m_nameBudgetSpinBox：对象名解析预算。
    QLabel* m_statusLabel = nullptr;             // m_statusLabel：句柄刷新状态文本。
    QTreeWidget* m_tableWidget = nullptr;        // m_tableWidget：句柄列表表格。
    QWidget* m_objectHeaderPage = nullptr;       // m_objectHeaderPage：Object Header 页容器。
    QVBoxLayout* m_objectHeaderLayout = nullptr; // m_objectHeaderLayout：Object Header 页布局。
    QLabel* m_handleDetailStatusLabel = nullptr; // m_handleDetailStatusLabel：Object Header 状态文本。
    QTreeWidget* m_handleDetailTable = nullptr;  // m_handleDetailTable：Object Header 键值表。

    QWidget* m_objectTypePage = nullptr;         // m_objectTypePage：Object Type 页容器。
    QVBoxLayout* m_objectTypeLayout = nullptr;   // m_objectTypeLayout：Object Type 页布局。
    QHBoxLayout* m_objectTypeToolLayout = nullptr; // m_objectTypeToolLayout：Object Type 工具栏布局。
    QPushButton* m_refreshObjectTypeButton = nullptr; // m_refreshObjectTypeButton：对象类型刷新按钮。
    QLineEdit* m_objectTypeFilterEdit = nullptr; // m_objectTypeFilterEdit：对象类型过滤输入框。
    QLabel* m_objectTypeStatusLabel = nullptr;   // m_objectTypeStatusLabel：对象类型状态文本。
    QTreeWidget* m_objectTypeTable = nullptr;    // m_objectTypeTable：对象类型列表表格。
    QTreeWidget* m_objectTypeDetailTable = nullptr; // m_objectTypeDetailTable：对象类型详情（键值对表）。

    bool m_refreshInProgress = false;            // m_refreshInProgress：句柄刷新互斥标记。
    bool m_refreshPending = false;               // m_refreshPending：刷新进行中期间记录的待执行刷新请求。
    bool m_objectTypeRefreshInProgress = false;  // m_objectTypeRefreshInProgress：对象类型刷新互斥标记。
    bool m_objectTypeRefreshPending = false;     // m_objectTypeRefreshPending：对象类型刷新待执行请求标记。
    bool m_handleDetailRefreshInProgress = false; // m_handleDetailRefreshInProgress：句柄详情刷新互斥标记。
    std::unique_ptr<ks::ui::AsyncOperation> m_handleDetailOperation; // 详情请求合并与一次收尾控制器。
    bool m_handleRenderDeferredUntilTypeMap = false; // m_handleRenderDeferredUntilTypeMap：句柄枚举已完成但表格渲染正等待对象类型映射。
    bool m_initialRefreshDone = false;           // m_initialRefreshDone：首轮刷新是否已完成。
    std::uint64_t m_refreshTicket = 0;           // m_refreshTicket：句柄刷新序号，防止乱序覆盖。
    std::uint64_t m_objectTypeRefreshTicket = 0; // m_objectTypeRefreshTicket：对象类型刷新序号。
    std::uint64_t m_handleDetailRefreshTicket = 0; // m_handleDetailRefreshTicket：句柄详情刷新序号。
    int m_refreshProgressPid = 0;                // m_refreshProgressPid：句柄刷新 kPro 任务 PID。
    int m_objectTypeRefreshProgressPid = 0;      // m_objectTypeRefreshProgressPid：对象类型刷新 kPro 任务 PID。
    int m_handleDetailRefreshProgressPid = 0;    // m_handleDetailRefreshProgressPid：句柄详情刷新 kPro 任务 PID。

    std::vector<HandleRow> m_allRows;            // m_allRows：完整句柄快照缓存。
    std::vector<HandleRow> m_rows;               // 兼容旧的整表渲染路径；规则树使用 m_allRows 索引。
    ks::handle::HandleFilterDocument m_filterDocument;
    ks::handle::HandleFilterRule m_temporaryFilterRule;
    bool m_temporaryFilterActive = false;
    bool m_snapshotScopedToTemporarySinglePid = false;
    std::uint32_t m_snapshotScopedProcessId = 0;
    std::vector<HandleRuleMatchState> m_ruleMatchStates;
    std::vector<QString> m_availableHandleTypeList;
    std::size_t m_totalRuleMatchCount = 0;
    std::size_t m_lastEnumeratedHandleCount = 0;
    std::size_t m_lastResolvedNameCount = 0;
    std::size_t m_lastObjectTypeMappedCount = 0;
    std::size_t m_lastKernelHandleCount = 0;
    std::uint64_t m_lastRefreshElapsedMs = 0;
    QString m_lastRefreshDiagnosticText;
    int m_handleSortColumn = -1;
    Qt::SortOrder m_handleSortOrder = Qt::AscendingOrder;
    std::vector<HandleObjectTypeEntry> m_objectTypeRows; // m_objectTypeRows：对象类型行缓存。
    std::unordered_map<std::uint16_t, std::string> m_typeNameCacheByIndex; // m_typeNameCacheByIndex：句柄刷新阶段生成的类型缓存。
    std::unordered_map<std::uint16_t, std::string> m_typeNameMapByIndexFromObjectTab; // m_typeNameMapByIndexFromObjectTab：对象类型页映射缓存。
    QHash<QString, QIcon> m_processIconCacheByIdentity; // m_processIconCacheByIdentity：PID + 创建时间 -> 图标缓存。
    QHash<QString, QString> m_processImagePathCacheByIdentity; // m_processImagePathCacheByIdentity：PID + 创建时间 -> 路径缓存。
    std::uint64_t m_processIconResolveGeneration = 0; // m_processIconResolveGeneration：进程图标后台解析代次，重建句柄表时递增以淘汰在途结果。
    std::shared_ptr<std::atomic_bool> m_processIconResolveCancelFlag; // m_processIconResolveCancelFlag：进程图标后台解析取消位，重建句柄表时置位让上一轮扫描尽快退出。
    std::vector<QTreeWidgetItem*> m_handleTableItemsByRowIndex; // 兼容旧整表图标回填路径。
};
