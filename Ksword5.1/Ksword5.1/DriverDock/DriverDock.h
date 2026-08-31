#pragma once

// ============================================================
// DriverDock.h
// 作用：
// 1) 提供驱动服务枚举与状态查看能力；
// 2) 提供驱动服务注册、更新、挂载、卸载、删除能力；
// 3) 提供已加载内核模块枚举能力；
// 4) 通过 KswordARK R0 回调捕获内核 DbgPrint/DbgPrintEx/KdPrintEx 输出；
// 5) 提供只读 DriverObject / DeviceObject / MajorFunction / FastIo 诊断页；
// 6) 提供 Module Cross-View、Driver Integrity 和 Unloaded/PiDDB 证据页。
// ============================================================

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverClient.h"

#include <QPointer>
#include <QWidget>

#include <atomic>   // std::atomic_bool：调试捕获线程运行标记。
#include <cstdint>  // std::uint32_t/std::uint64_t：状态值与地址值。
#include <memory>   // std::unique_ptr：线程对象托管。
#include <string>   // std::string：错误文本桥接与日志输出。
#include <thread>   // std::thread：后台调试输出捕获线程。
#include <vector>   // std::vector：驱动服务与模块快照容器。

// Qt 前置声明：减少头文件编译耦合。
class QCheckBox;
class QButtonGroup;
class QComboBox;
class CodeEditorWidget;
class QColor;
class QEvent;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QRadioButton;
class QShowEvent;
class QSplitter;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QVBoxLayout;
class KernelThreadAuditTab;

// DriverDock：
// - 驱动页主控件；
// - 内含“概览/操作/调试输出”三个页签；
// - 所有驱动管理动作均通过 SCM API 实现。
class DriverDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：初始化 UI、绑定信号槽并执行首轮刷新。
    // - 参数 parent：Qt 父控件指针。
    explicit DriverDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：停止调试捕获线程并回收资源。
    ~DriverDock() override;

    // attachKswordSelfDriverPage：
    // - 输入 page：KernelDock 持有的“Ksword自身驱动”容器；
    // - 输入 fallbackOwner：DriverDock 析构时接回页面的原始所有者；
    // - 处理：将动态偏移/驱动状态作为驱动 Dock 一级页展示，不复制业务逻辑；
    // - 输出：无，重复调用同一页面时保持幂等。
    void attachKswordSelfDriverPage(QWidget* page, QWidget* fallbackOwner);

protected:
    // showEvent：
    // - 首次显示时再执行驱动服务/模块枚举；
    // - 避免主窗口启动阶段同步扫描 SCM 和内核模块。
    void showEvent(QShowEvent* event) override;

    // changeEvent：
    // - 作用：语言切换后重绘 DriverDock 的表头；
    // - 处理：控件文本由 LanguageManager 绑定更新，表头由本类集中重建；
    // - 返回：无。
    void changeEvent(QEvent* event) override;

private:
    // DriverServiceRecord：
    // - 作用：描述一条驱动服务记录的展示字段。
    struct DriverServiceRecord
    {
        QString serviceName;           // 服务名（唯一键，SCM 主键）。
        QString displayName;           // 显示名（可为空）。
        QString binaryPath;            // 驱动镜像路径（ImagePath）。
        QString description;           // 服务描述文本（可为空）。
        std::uint32_t currentState = 0;// 当前服务状态（SERVICE_* 常量值）。
        std::uint32_t startType = 0;   // 启动类型（BOOT/SYSTEM/AUTO/DEMAND/DISABLED）。
        std::uint32_t errorControl = 0;// 错误控制级别（IGNORE/NORMAL/SEVERE/CRITICAL）。
        std::uint32_t serviceType = 0; // 服务类型（目标应为 SERVICE_KERNEL_DRIVER）。
    };

    // LoadedKernelModuleRecord：
    // - 作用：描述一条已加载内核模块（驱动映像）记录。
    struct LoadedKernelModuleRecord
    {
        QString moduleName;            // 模块文件名（如 xxx.sys）。
        QString imagePath;             // 内核可见路径（通常为 \SystemRoot\...）。
        std::uint64_t baseAddress = 0; // 基址（十六进制展示）。
    };

    enum class LoadedModuleSignatureState : std::uint32_t
    {
        Pending = 0U,
        PathUnavailable,
        InvalidTrust,
        TrustedEmbedded,
        TrustedCatalog
    };

    // LoadedModuleSignatureEvidence：
    // - 只缓存不依赖当前语言的签名语义、错误码和文件标识；
    // - UI 线程按当前语言生成表格、筛选文本、提示与详情，语言切换无需重新扫描。
    struct LoadedModuleSignatureEvidence
    {
        LoadedModuleSignatureState state = LoadedModuleSignatureState::Pending;
        QString verificationPath;
        QString fileIdentifier;
        QString catalogPath;
        QString signerCertificateName;
        std::int32_t embeddedTrustStatus = 0;
        std::int32_t catalogTrustStatus = 0;
        std::uint32_t catalogLookupError = 0U;
        bool catalogAttempted = false;
        bool catalogTrustStatusAvailable = false;
    };

    // LoadedModuleEvidenceRecord：
    // - 作用：保存单个已加载模块的 R0 证据聚合结果；
    // - 数据只用于 DriverDock 展示，不触发卸载、移除或修复动作。
    struct LoadedModuleEvidenceRecord
    {
        QString moduleName;            // moduleName：被聚合的模块名。
        LoadedModuleSignatureEvidence signatureEvidence; // signatureEvidence：语言无关的 embedded/catalog 信任证据。
        QString driverObjectName;      // driverObjectName：成功解析到的 DriverObject 名称。
        QString driverObjectStatusText;// driverObjectStatusText：DriverObject 查询状态展示文本。
        QString driverStartMatchText;  // driverStartMatchText：DriverStart 与模块基址比对文本。
        QString majorFunctionStatusText;// majorFunctionStatusText：MajorFunction 外跳摘要。
        QString iatEatStatusText;      // iatEatStatusText：IAT/EAT 可疑项摘要。
        QString inlineHookStatusText;  // inlineHookStatusText：Inline Hook 可疑项摘要。
        QString callbackStatusText;    // callbackStatusText：Callback 引用摘要。
        QString detailText;            // detailText：详情区可复制的证据明细。
        std::uint64_t driverObjectAddress = 0; // driverObjectAddress：只读证据查询返回的精确对象地址。
        std::uint64_t communicationRejectDispatchAddress = 0; // communicationRejectDispatchAddress：R0 系统拒绝入口。
        bool queryAttempted = false;   // queryAttempted：是否已经尝试聚合。
        bool driverObjectResolved = false; // driverObjectResolved：DriverObject 是否解析成功。
        bool driverStartKnown = false; // driverStartKnown：DriverStart 是否有有效值。
        bool driverStartMatchesBase = false; // driverStartMatchesBase：DriverStart 是否等于模块基址。
        bool communicationStateKnown = false; // communicationStateKnown：通信控制 QUERY 是否返回有效业务状态。
        bool communicationActive = false; // communicationActive：是否仍有本功能拥有的致盲槽位。
        bool communicationConflict = false; // communicationConflict：是否有第三方改写导致的粘性冲突。
        bool hasMajorFunctionExternalJump = false; // hasMajorFunctionExternalJump：是否存在 MajorFunction 外跳。
        bool hasIatEatSuspicious = false; // hasIatEatSuspicious：是否存在 IAT/EAT 可疑项。
        bool hasInlineHookSuspicious = false; // hasInlineHookSuspicious：是否存在 Inline Hook 可疑项。
        bool hasCallbackReference = false; // hasCallbackReference：是否存在回调引用该模块。
        bool hasScanError = false;     // hasScanError：是否存在 IO/协议/解析错误。
        std::uint32_t communicationActiveMask = 0; // communicationActiveMask：当前由系统拒绝入口接管的槽位。
        std::uint32_t communicationOwnedMask = 0; // communicationOwnedMask：当前仍由本功能拥有恢复资格的槽位。
        std::uint32_t communicationConflictMask = 0; // communicationConflictMask：不可自动恢复的粘性冲突槽位。
        std::uint32_t communicationGeneration = 0; // communicationGeneration：R0 记录代次。
        std::uint32_t majorFunctionIntentionalBlindCount = 0; // majorFunctionIntentionalBlindCount：已由本功能有意致盲的外跳数。
        std::uint32_t majorFunctionExternalCount = 0; // majorFunctionExternalCount：外跳 MajorFunction 数量。
        std::uint32_t iatEatSuspiciousCount = 0; // iatEatSuspiciousCount：IAT/EAT 可疑项数量。
        std::uint32_t inlineHookSuspiciousCount = 0; // inlineHookSuspiciousCount：Inline Hook 可疑项数量。
        std::uint32_t callbackReferenceCount = 0; // callbackReferenceCount：引用该模块的回调数量。
    };

    // DebugOutputLineRecord：区分应用生成的本地化提示与驱动原始输出。
    struct DebugOutputLineRecord
    {
        QString timePrefix;
        QString sourceText;
        QString localizedSuffixSource;
        bool translateSourceText = false;
    };

private:
    // ========================= UI 初始化 =========================
    // initializeUi：
    // - 作用：构建驱动页顶层布局与三个子页签。
    void initializeUi();

    // initializeServiceTab：
    // - 作用：构建“驱动服务”页（SCM 服务列表与服务筛选）。
    void initializeServiceTab();

    // initializeKernelModuleTab：
    // - 作用：构建“内核模块”页（已加载模块与统一详情编辑器）。
    void initializeKernelModuleTab();

    // initializeOperateTab：
    // - 作用：构建“驱动操作”页（注册/挂载/卸载/删除）。
    void initializeOperateTab();

    // initializeDebugOutputTab：
    // - 作用：构建“调试输出”页（R0 回调控制与输出框）。
    void initializeDebugOutputTab();

    // initializeObjectInfoTab：
    // - 构建 Phase-9 “对象信息”页；
    // - 通过 ArkDriverClient 查询 DriverObject、MajorFunction 和 DeviceObject 链。
    void initializeObjectInfoTab();

    // initializeModuleCrossViewTab：
    // - 构建只读 Module Cross-View 证据页；
    // - 主要展示 DriverObject / DriverSection / DeviceChain / Service 相关证据；
    // - 不提供修复、补丁或任意写按钮。
    void initializeModuleCrossViewTab();

    // initializeIntegrityTab：
    // - 构建“驱动完整性”页；
    // - 展示 DriverObject、MajorFunction、FastIo、LDR 和 CPU entry evidence；
    // - 不提供卸载、修复或任意写操作。
    void initializeIntegrityTab();

    // initializeUnloadedPiddbTab：
    // - 按 issue 截图构建“已卸载驱动”页；
    // - 支持 MmUnloadedDrivers / PiDDBCacheTable / g_KernelHashBucketList 三来源；
    // - 查询/过滤/详情保持只读；PiDDB 来源另提供强确认的精确表项管理动作。
    void initializeUnloadedPiddbTab();

    // initializeSystemThreadTab：
    // - 构建“系统线程”一级页；
    // - 复用 KernelThreadAuditTab 与 ArkDriverClient 现有线程协议。
    void initializeSystemThreadTab();

    // initializeConnections：
    // - 作用：连接全部控件信号与业务槽函数。
    void initializeConnections();

    // applyTranslatedHeaders：按当前语言重建 DriverDock 所有已创建表格的列标题。
    void applyTranslatedHeaders();

    // ========================= 数据刷新 =========================
    // refreshDriverServiceRecords：
    // - 作用：刷新驱动服务缓存并重建服务表格。
    void refreshDriverServiceRecords();

    // refreshLoadedKernelModuleRecords：
    // - 作用：刷新已加载内核模块缓存并重建模块表格。
    void refreshLoadedKernelModuleRecords();

    // refreshLoadedModuleEvidenceAsync：
    // - 作用：使用现有 ArkDriverClient R0 查询能力聚合模块证据；
    // - 处理逻辑：后台线程查询 DriverObject/Hook/Callback，再回投 UI；
    // - 返回：无；结果写入 m_loadedModuleEvidenceCache。
    void refreshLoadedModuleEvidenceAsync();

    // rebuildLoadedModuleEvidenceViews：
    // - 作用：把当前证据缓存回填到模块表格和详情区；
    // - 处理逻辑：逐行按源索引更新证据列，并刷新当前选中模块详情；
    // - 返回：无。
    void rebuildLoadedModuleEvidenceViews();

    // updateLoadedModuleEvidenceStatusText：
    // - 按缓存语义重新生成聚合摘要；
    // - 语言切换时无需重跑 R0/签名后台扫描。
    void updateLoadedModuleEvidenceStatusText();

    // showSelectedModuleEvidenceDetail：
    // - 作用：展示当前选中模块的证据明细；
    // - 处理逻辑：从表格行映射到证据缓存，填充 CodeEditorWidget；
    // - 返回：无。
    void showSelectedModuleEvidenceDetail();

    // querySelectedDriverObjectInfo：
    // - 根据对象页输入的 \Driver\Name 查询 R0 DriverObject；
    // - 后台执行，完成后回填基础字段、MajorFunction 表和 DeviceObject 表。
    void querySelectedDriverObjectInfo();

    // applyDriverObjectQueryResult：
    // - 回填 Phase-9 DriverObject 查询结果；
    // - 参数 result 为 ArkDriverClient 解析后的结构化响应。
    void applyDriverObjectQueryResult(const ksword::ark::DriverObjectQueryResult& result);

    // rebuildDriverObjectEvidenceViews：
    // - 作用：按当前 DriverObject 查询结果和完整性缓存刷新 DriverObject / DriverExtension / FastIo 子页；
    // - 处理逻辑：只做本地表格投影，不重新访问驱动；
    // - 返回：无。
    void rebuildDriverObjectEvidenceViews();

    // fillObjectDriverNameFromSelection：
    // - 从概览页当前选中服务名推导 \Driver\Name；
    // - 便于用户双击服务后直接查询对象。
    void fillObjectDriverNameFromSelection();

    // refreshDriverIntegrityAsync：
    // - 异步调用 ArkDriverClient::queryDriverIntegrity / queryKernelCpuIntegrity；
    // - 参数 cpuOnly 为 true 时只请求 CPU/IDT/MSR 证据；
    // - 返回：无，结果回填 m_driverIntegrityCache。
    void refreshDriverIntegrityAsync(bool cpuOnly);

    // rebuildDriverIntegrityTable：
    // - 按当前缓存和风险过滤重绘完整性证据表；
    // - 不重新访问驱动；
    // - 返回：无。
    void rebuildDriverIntegrityTable();

    // rebuildModuleCrossViewTable：
    // - 作用：按当前 Driver Integrity 缓存重绘 Module Cross-View 证据表；
    // - 处理逻辑：只显示 ModuleView / PsLoadedModules / DriverObject / DriverSection / DeviceChain / Service 等证据；
    // - 返回：无。
    void rebuildModuleCrossViewTable();

    // refreshUnloadedDriversAsync：
    // - 作用：后台调用 ArkDriverClient 查询当前选中的已卸载驱动来源；
    // - 处理逻辑：来源切换或刷新按钮触发，旧 ticket 结果不会覆盖新来源；
    // - 返回：无，结果回投 UI 线程。
    void refreshUnloadedDriversAsync();

    // applyUnloadedDriverQueryResult：
    // - 输入：查询 ticket 与 ArkDriverClient 统一结果；
    // - 处理逻辑：校验 ticket、更新缓存/状态并重绘过滤视图；
    // - 返回：无。
    void applyUnloadedDriverQueryResult(
        std::uint64_t ticket,
        ksword::ark::UnloadedDriverQueryResult result);

    // rebuildUnloadedPiddbTable：
    // - 作用：按当前来源缓存、字段下拉框、关键词和正则开关重绘表格；
    // - 处理逻辑：只做本地过滤，不重新访问驱动；
    // - 返回：无。
    void rebuildUnloadedPiddbTable();

    // selectedPiDdbEntryIdentity：
    // - 作用：把截图页当前选中的 PiDDB 统一行转换为删除协议所需的精确身份；
    // - 处理逻辑：同时校验当前来源、查询状态、缓存索引和必需字段；
    // - 返回：仅在所选行可安全进入 R0 预检时返回 true。
    bool selectedPiDdbEntryIdentity(ksword::ark::PiDdbEntry* identity) const;

    // deleteSelectedPiDdbEntry：
    // - 作用：对当前选中的 PiDDB 行执行精确身份预检和强确认删除；
    // - 处理逻辑：复用 R0 preflight、固定短语确认和删除后同锁复核；
    // - 返回：无；成功后重新查询当前 PiDDB 来源。
    void deleteSelectedPiDdbEntry();

    // showSelectedDriverIntegrityDetail：
    // - 展示当前选中完整性证据行的详情文本；
    // - 处理逻辑：通过表格 UserRole 中的缓存索引读取 m_driverIntegrityCache；
    // - 返回：无。
    void showSelectedDriverIntegrityDetail();

    // showUnloadedPiddbContextMenu：
    // - 输入：已卸载驱动表格内的局部坐标；
    // - 处理逻辑：弹出详情/复制/刷新菜单，不提供删除或清理动作；
    // - 返回：无，用户选择后执行本地 UI 操作。
    void showUnloadedPiddbContextMenu(const QPoint& localPosition);

    // showSelectedUnloadedPiddbDetailDialog：
    // - 输入：无，读取当前选中的已卸载驱动表格行；
    // - 处理逻辑：用缓存索引展开原始来源字段，并放入 CodeEditorWidget 弹窗；
    // - 返回：无，弹窗关闭后不修改任何 R0/R3 状态。
    void showSelectedUnloadedPiddbDetailDialog();

    // copySelectedUnloadedPiddbRow：
    // - 输入：无，读取当前选中表格行；
    // - 处理逻辑：把可见列序列化为 TSV 后写入剪贴板；
    // - 返回：无。
    void copySelectedUnloadedPiddbRow();

    // copyVisibleUnloadedPiddbRows：
    // - 输入：无，遍历当前筛选后的全部可见行；
    // - 处理逻辑：把表头和全部可见行序列化为 TSV 后写入剪贴板；
    // - 返回：无。
    void copyVisibleUnloadedPiddbRows();

    // showServiceTableContextMenu：
    // - 在驱动服务列表右键弹出操作菜单；
    // - 同时提供 SCM 停止和分级 R0 DriverObject 强制卸载。
    void showServiceTableContextMenu(const QPoint& localPosition);

    // showModuleTableContextMenu：
    // - 在已加载模块列表右键弹出操作菜单；
    // - 模块证据仍可刷新/复制；R0 强卸载默认使用非破坏性清理 flags。
    void showModuleTableContextMenu(const QPoint& localPosition);

    // querySelectedModuleKernelSignature：
    // - 使用模块表路径和基址调用 R0 签名证据查询；
    // - 结果写入模块证据详情区，不调用 WinTrust。
    void querySelectedModuleKernelSignature();

    // dumpSelectedModuleMemory：
    // - 输入为进入右键菜单前捕获的模块名、路径和基址快照；
    // - 由 R0 校验已加载模块身份与映像大小；
    // - 后台分页读取内核映像，只在完整成功后以不覆盖的原子重命名提交用户所选文件。
    void dumpSelectedModuleMemory(
        const QString& moduleName,
        const QString& rawPath,
        std::uint64_t moduleBase);

    // stopDriverServiceFromServiceRow：
    // - 从服务列表选中行读取 SCM 服务名并通过 ControlService(SERVICE_CONTROL_STOP) 停止；
    // - 不调用 R0 DriverObject 强卸载，避免对活动驱动执行不安全强拆。
    void stopDriverServiceFromServiceRow(int rowIndex);

    // scUnloadAndCleanupDriver：
    // - 输入为进入右键菜单前捕获的不可变 SCM 服务名与规范化驱动路径；
    // - 严格等待 SERVICE_STOPPED，停后再次验证配置路径和独占引用；
    // - 仅在 DeleteService 成功后删除驱动文件，任一前置门槛失败均不触碰注册表或文件。
    void scUnloadAndCleanupDriver(
        const QString& serviceName,
        const QString& normalizedBinaryPath);

    // forceUnloadDriverFromServiceRow：
    // - 将当前服务名规范化为 \Driver\Name 并调用 ArkDriverClient；
    // - false 仅直接调用 DriverUnload；true 执行固定顺序的 DriverObject 强拆。
    void forceUnloadDriverFromServiceRow(int rowIndex, bool destructiveCleanup = false);

    // forceUnloadDriverFromModuleRow：
    // - 使用模块基址请求 R0 反查 DriverObject 并执行分级强制卸载；
    // - removeCallbacksFirst 为 true 时请求 R0 在 DriverObject 处理成功后移除可验证回调；
    // - destructiveCleanup 为 true 时才允许持久中和/删 DeviceObject/ObMakeTemporaryObject。
    void forceUnloadDriverFromModuleRow(int rowIndex, bool removeCallbacksFirst = false, bool destructiveCleanup = false);

    // controlDriverCommunication：
    // - 使用确认前复制的模块基址、canonical DriverObject 和对象地址作为不可变目标；
    // - restoreCommunication 为 true 时按 R0 保存记录执行可恢复撤销；
    // - 不重读可能刷新的表格行，操作异步执行并在完成后刷新模块证据。
    void controlDriverCommunication(
        std::uint64_t moduleBase,
        const QString& moduleName,
        const QString& driverObjectName,
        std::uint64_t expectedDriverObjectAddress,
        bool restoreCommunication);

    // queryDriverObjectForModuleEvidence：
    // - 作用：按模块名推导 DriverObject 名称并查询 R0 对象诊断；
    // - 处理逻辑：依次尝试 \Driver、\FileSystem、\FileSystem\Filters 候选；
    // - 返回：true 表示解析到 DriverObject，false 表示无可用对象。
    static bool queryDriverObjectForModuleEvidence(
        const LoadedKernelModuleRecord& moduleRecord,
        ksword::ark::DriverObjectQueryResult& resultOut,
        QString& attemptedNamesTextOut);

    // collectEvidenceForLoadedModules：
    // - 作用：批量收集一轮模块证据；
    // - 处理逻辑：复用 ArkDriverClient 现有接口，不新增 R0 协议；
    // - 返回：每个模块对应一个 LoadedModuleEvidenceRecord。
    static std::vector<LoadedModuleEvidenceRecord> collectEvidenceForLoadedModules(
        const std::vector<LoadedKernelModuleRecord>& moduleRecords);

    // verifyLoadedModuleSignature：
    // - 先验证 embedded Authenticode，再用系统 Catalog 进行 catalog-only fallback；
    // - 仅完整链与 whole-chain revocation 都成功时标记可信，离线/未知均保持无效。
    static LoadedModuleSignatureEvidence verifyLoadedModuleSignature(
        const QString& rawImagePath);

    // buildPendingModuleEvidenceRecord：
    // - 作用：构造尚未聚合证据时的占位记录；
    // - 处理逻辑：所有证据列填入“待扫描”，详情区说明后台查询方式；
    // - 返回：LoadedModuleEvidenceRecord 占位对象。
    static LoadedModuleEvidenceRecord buildPendingModuleEvidenceRecord(
        const LoadedKernelModuleRecord& moduleRecord);

    // moduleEvidenceStatusColor：
    // - 作用：按证据状态选择表格前景色；
    // - 处理逻辑：可疑为红色，解析失败/引用为橙色，正常为绿色；
    // - 返回：可直接设置到 QBrush 的 QColor。
    static QColor moduleEvidenceStatusColor(const LoadedModuleEvidenceRecord& evidence);

    static bool moduleSignatureCheckAttempted(
        const LoadedModuleEvidenceRecord& evidence);
    static bool moduleSignatureTrusted(
        const LoadedModuleEvidenceRecord& evidence);
    static QString moduleSignatureStatusText(
        const LoadedModuleEvidenceRecord& evidence);
    static QString moduleSignatureDetailText(
        const LoadedModuleEvidenceRecord& evidence);
    static QString localizedModuleEvidenceText(const QString& sourceText);

    // rebuildDriverServiceTableByFilter：
    // - 作用：按过滤关键词重建驱动服务表格。
    void rebuildDriverServiceTableByFilter();

    // rebuildLoadedModuleTable：
    // - 作用：按当前缓存重建已加载模块表格。
    void rebuildLoadedModuleTable();

    // syncOperateFormBySelectedService：
    // - 作用：把选中服务行参数同步到操作表单。
    void syncOperateFormBySelectedService();

    // refreshSelectedServiceStateToForm：
    // - 作用：按表单服务名回查 SCM 并刷新状态日志。
    void refreshSelectedServiceStateToForm();

    // ========================= 驱动操作 =========================
    // registerOrUpdateDriverService：
    // - 作用：注册新驱动服务，或更新已存在服务配置。
    void registerOrUpdateDriverService();

    // loadSelectedDriverService：
    // - 作用：启动（挂载）表单中的目标驱动服务。
    void loadSelectedDriverService();

    // unloadSelectedDriverService：
    // - 作用：停止（卸载）表单中的目标驱动服务。
    void unloadSelectedDriverService();

    // deleteSelectedDriverService：
    // - 作用：删除表单中的目标驱动服务。
    void deleteSelectedDriverService();

    // ========================= 调试输出 =========================
    // startDebugOutputCapture：
    // - 作用：启动 R0 内核调试输出捕获线程。
    void startDebugOutputCapture();

    // stopDebugOutputCapture：
    // - 作用：停止 R0 内核调试输出捕获线程。
    void stopDebugOutputCapture();

    // runKernelDebugOutputCaptureLoop：
    // - 作用：线程函数，通过 ArkDriverClient 增量读取 R0 环形缓冲区。
    void runKernelDebugOutputCaptureLoop();

    // updateDebugCaptureButtonState：
    // - 作用：刷新调试捕获按钮启用状态与提示文本。
    void updateDebugCaptureButtonState();

    // ========================= 输出辅助 =========================
    // appendOperateLogLine：
    // - 作用：向“驱动操作日志”窗口追加一行带时间戳文本。
    // - 参数 logText：待追加的日志正文。
    void appendOperateLogLine(const QString& logText);

    // appendDebugOutputLine：
    // - 作用：追加驱动原始输出；仅可选后缀参与语言切换。
    void appendDebugOutputLine(
        const QString& debugText,
        const QString& localizedSuffixSource = QString());

    // appendLocalizedDebugOutputLine：追加应用生成的提示，并保留规范源文本供热切换。
    void appendLocalizedDebugOutputLine(const QString& sourceText);

    // refreshDebugOutputLines：按当前语言重建应用提示，驱动原始消息保持不变。
    void refreshDebugOutputLines();

    // clearDebugOutputLines：同步清空界面与用于重翻译的记录。
    void clearDebugOutputLines();

    // ========================= 静态工具函数 =========================
    // queryDriverServiceRecords：
    // - 作用：从 SCM 枚举全部驱动服务并填充输出容器。
    // - 参数 recordListOut：输出服务记录列表。
    // - 参数 errorTextOut：失败时输出错误文本，可空。
    // - 返回：true=成功；false=失败。
    static bool queryDriverServiceRecords(
        std::vector<DriverServiceRecord>& recordListOut,
        std::string* errorTextOut = nullptr);

    // queryLoadedKernelModuleRecords：
    // - 作用：枚举当前已加载内核模块并填充输出容器。
    // - 参数 recordListOut：输出模块记录列表。
    // - 参数 errorTextOut：失败时输出错误文本，可空。
    // - 返回：true=成功；false=失败。
    static bool queryLoadedKernelModuleRecords(
        std::vector<LoadedKernelModuleRecord>& recordListOut,
        std::string* errorTextOut = nullptr);

    // serviceStateToText：
    // - 作用：把服务状态值转换为中文文本。
    static QString serviceStateToText(std::uint32_t stateValue);

    // startTypeToText：
    // - 作用：把启动类型值转换为中文文本。
    static QString startTypeToText(std::uint32_t startTypeValue);

    // errorControlToText：
    // - 作用：把错误控制值转换为中文文本。
    static QString errorControlToText(std::uint32_t errorControlValue);

    // formatWin32ErrorText：
    // - 作用：把 Win32 错误码格式化为“十进制 + 文本”。
    static QString formatWin32ErrorText(std::uint32_t win32ErrorCode);

    // trimQuotedText：
    // - 作用：去掉路径文本首尾成对双引号。
    static QString trimQuotedText(const QString& textValue);

    // normalizeDriverBinaryPath：
    // - 作用：规整驱动镜像路径（必要时自动补双引号）。
    static QString normalizeDriverBinaryPath(const QString& pathText);

private:
    // ========================= 顶层布局 =========================
    QVBoxLayout* m_rootLayout = nullptr; // 根布局。
    QTabWidget* m_tabWidget = nullptr;   // 子页签容器。
    KernelThreadAuditTab* m_systemThreadAuditTab = nullptr; // 系统线程一级审计页。
    QWidget* m_kswordSelfDriverPage = nullptr; // 从 KernelDock 迁移的自身驱动容器。
    QPointer<QWidget> m_kswordSelfDriverFallbackOwner; // 析构时接回自身驱动容器的所有者。
    int m_kswordSelfDriverTabIndex = -1; // 自身驱动页在 DriverDock 中的索引。

    // ========================= 页签1：驱动服务 =========================
    QWidget* m_servicePage = nullptr;                // 驱动服务页容器。
    QVBoxLayout* m_serviceLayout = nullptr;          // 驱动服务页主布局。
    QWidget* m_overviewPage = nullptr;               // 兼容旧布局状态的服务页别名容器。
    QVBoxLayout* m_overviewLayout = nullptr;         // 服务页主布局兼容指针。
    QHBoxLayout* m_overviewToolLayout = nullptr;     // 服务页工具栏布局。
    QLineEdit* m_serviceFilterEdit = nullptr;        // 服务列表过滤输入框。
    QPushButton* m_refreshServiceButton = nullptr;   // 刷新服务按钮。
    QLabel* m_overviewStatusLabel = nullptr;         // 服务页状态标签。
    QTableWidget* m_serviceTable = nullptr;          // 驱动服务表格。

    // ========================= 页签2：内核模块 =========================
    QWidget* m_kernelModulePage = nullptr;           // 内核模块页容器。
    QVBoxLayout* m_kernelModuleLayout = nullptr;     // 内核模块页主布局。
    QHBoxLayout* m_kernelModuleToolLayout = nullptr; // 内核模块工具栏布局。
    QPushButton* m_refreshModuleButton = nullptr;    // 刷新模块按钮。
    QPushButton* m_refreshModuleEvidenceButton = nullptr; // 刷新模块证据按钮。
    QLineEdit* m_moduleFilterEdit = nullptr;         // 内核模块列表过滤输入框。
    QTableWidget* m_moduleTable = nullptr;            // 已加载模块表格。
    CodeEditorWidget* m_moduleEvidenceDetailEditor = nullptr; // 模块证据详情编辑器。
    QLabel* m_moduleEvidenceStatusLabel = nullptr;   // 模块证据聚合状态标签。
    bool m_moduleEvidenceQuerying = false;           // 模块证据后台查询中标记。
    std::uint64_t m_moduleEvidenceQueryTicket = 0;   // 模块证据查询序号。
    bool m_moduleDumpRunning = false;                // 模块 R0 Dump 后台任务运行标记。
    bool m_scCleanupRunning = false;                 // SCM 卸载并清理文件/服务注册后台任务标记。

    // ========================= 页签2：驱动操作 =========================
    QWidget* m_operatePage = nullptr;                 // 操作页容器。
    QVBoxLayout* m_operateLayout = nullptr;           // 操作页主布局。
    QLineEdit* m_serviceNameEdit = nullptr;           // 服务名输入框。
    QLineEdit* m_displayNameEdit = nullptr;           // 显示名输入框。
    QLineEdit* m_binaryPathEdit = nullptr;            // 驱动路径输入框。
    QLineEdit* m_descriptionEdit = nullptr;           // 服务描述输入框。
    QComboBox* m_startTypeCombo = nullptr;            // 启动类型下拉框。
    QComboBox* m_errorControlCombo = nullptr;         // 错误控制下拉框。
    QPushButton* m_browsePathButton = nullptr;        // 浏览路径按钮。
    QPushButton* m_registerOrUpdateButton = nullptr;  // 注册/更新按钮。
    QPushButton* m_loadDriverButton = nullptr;        // 挂载按钮。
    QPushButton* m_unloadDriverButton = nullptr;      // 卸载按钮。
    QPushButton* m_deleteServiceButton = nullptr;     // 删除服务按钮。
    QPushButton* m_refreshStateButton = nullptr;      // 刷新状态按钮。
    QPlainTextEdit* m_operateLogOutput = nullptr;     // 操作日志输出框。

    // ========================= 页签3：调试输出 =========================
    QWidget* m_debugOutputPage = nullptr;             // 调试输出页容器。
    QVBoxLayout* m_debugOutputLayout = nullptr;       // 调试输出页主布局。
    QHBoxLayout* m_debugToolLayout = nullptr;         // 调试输出工具栏布局。
    QPushButton* m_startCaptureButton = nullptr;      // 启动捕获按钮。
    QPushButton* m_stopCaptureButton = nullptr;       // 停止捕获按钮。
    QPushButton* m_clearDebugOutputButton = nullptr;  // 清空输出按钮。
    QPushButton* m_copyDebugOutputButton = nullptr;   // 复制输出按钮。
    QLabel* m_debugCaptureStatusLabel = nullptr;      // 捕获状态标签。
    QPlainTextEdit* m_debugOutputEdit = nullptr;      // 调试输出文本框。
    std::vector<DebugOutputLineRecord> m_debugOutputLines; // 调试输出原始记录，最多保留 2000 行。

    // ========================= 页签4：对象信息 =========================
    QWidget* m_objectInfoPage = nullptr;              // 对象信息页容器。
    QVBoxLayout* m_objectInfoLayout = nullptr;        // 对象信息页主布局。
    QHBoxLayout* m_objectInfoToolLayout = nullptr;    // 对象信息页工具栏布局。
    QLineEdit* m_objectDriverNameEdit = nullptr;      // \Driver\Name 输入框。
    QPushButton* m_fillObjectDriverNameButton = nullptr; // 从选中服务填充按钮。
    QPushButton* m_queryObjectInfoButton = nullptr;   // R0 查询按钮。
    QPushButton* m_objectEvidenceRefreshButton = nullptr; // 刷新 Driver/Integrity 证据按钮。
    QLabel* m_objectInfoStatusLabel = nullptr;        // 查询状态标签。
    CodeEditorWidget* m_objectInfoSummaryEdit = nullptr;// DriverObject 摘要。
    QTabWidget* m_objectDetailTabWidget = nullptr;    // DriverObject 细分页签容器。
    QWidget* m_driverObjectPage = nullptr;            // DriverObject 诊断页。
    QWidget* m_deviceObjectPage = nullptr;            // DeviceObject 诊断页。
    QWidget* m_driverExtensionPage = nullptr;         // DriverExtension 诊断页。
    QWidget* m_majorFunctionPage = nullptr;           // MajorFunction 诊断页。
    QWidget* m_fastIoPage = nullptr;                  // FastIo 诊断页。
    CodeEditorWidget* m_driverObjectPageSummaryEdit = nullptr; // DriverObject 页摘要。
    QTableWidget* m_driverObjectEvidenceTable = nullptr;      // DriverObject / DriverSection 证据表。
    QTableWidget* m_majorFunctionTable = nullptr;     // MajorFunction 表。
    QTableWidget* m_deviceObjectTable = nullptr;      // DeviceObject/AttachedDevice 表。
    QTableWidget* m_driverExtensionEvidenceTable = nullptr;   // DriverExtension / DeviceChain 证据表。
    QTableWidget* m_fastIoEvidenceTable = nullptr;             // FastIo 证据表。
    QLabel* m_driverExtensionStatusLabel = nullptr;   // DriverExtension 页状态标签。
    QLabel* m_fastIoStatusLabel = nullptr;            // FastIo 页状态标签。
    bool m_objectInfoQuerying = false;                // 查询中标记。
    std::uint64_t m_objectInfoQueryTicket = 0;        // 查询序号。

    // ========================= 页签5：模块 Cross-View =========================
    QWidget* m_moduleCrossViewPage = nullptr;         // 模块 Cross-View 页容器。
    QVBoxLayout* m_moduleCrossViewLayout = nullptr;   // 模块 Cross-View 主布局。
    QHBoxLayout* m_moduleCrossViewToolLayout = nullptr; // 模块 Cross-View 工具栏布局。
    QPushButton* m_moduleCrossViewRefreshButton = nullptr; // 刷新按钮。
    QLabel* m_moduleCrossViewStatusLabel = nullptr;    // 状态标签。
    QTableWidget* m_moduleCrossViewTable = nullptr;    // 模块 Cross-View 表。

    // ========================= 页签5：驱动完整性 =========================
    QWidget* m_integrityPage = nullptr;               // 驱动完整性页容器。
    QVBoxLayout* m_integrityLayout = nullptr;         // 完整性页主布局。
    QHBoxLayout* m_integrityToolLayout = nullptr;     // 完整性页工具栏布局。
    QLineEdit* m_integrityDriverNameEdit = nullptr;   // 可选 \Driver\Name 输入框。
    QLineEdit* m_integrityModuleBaseEdit = nullptr;   // 可选模块基址输入框。
    QPushButton* m_integrityFillFromSelectionButton = nullptr; // 从当前选择填充 DriverObject 名称。
    QPushButton* m_integrityRefreshButton = nullptr;  // 查询 DriverObject/LDR/FastIo/CPU 证据。
    QPushButton* m_integrityCpuOnlyButton = nullptr;  // 查询 CPU entry evidence。
    QCheckBox* m_integrityRiskOnlyCheck = nullptr;    // 仅显示风险项。
    QSpinBox* m_integrityMaxRowsSpin = nullptr;       // 最大返回行数。
    QLabel* m_integrityStatusLabel = nullptr;         // 查询状态标签。
    QTableWidget* m_integrityTable = nullptr;         // 完整性证据表。
    CodeEditorWidget* m_integrityDetailEdit = nullptr; // 完整性详情编辑器，只读展示原始 R0 明细。
    bool m_integrityQuerying = false;                 // 完整性查询中标记。
    std::uint64_t m_integrityQueryTicket = 0;         // 完整性查询序号。

    // ========================= 页签6：已卸载驱动 =========================
    QWidget* m_unloadedPiddbPage = nullptr;           // 已卸载驱动页容器。
    QVBoxLayout* m_unloadedPiddbLayout = nullptr;     // 已卸载驱动主布局。
    QHBoxLayout* m_unloadedPiddbSourceLayout = nullptr; // 三来源单选布局。
    QHBoxLayout* m_unloadedPiddbFilterLayout = nullptr; // 字段/关键词/正则/数量布局。
    QPushButton* m_unloadedPiddbRefreshButton = nullptr; // 重新查询当前来源按钮。
    QPushButton* m_unloadedPiddbDeleteButton = nullptr; // 仅精确 PiDDB 行可用的强确认管理按钮。
    QButtonGroup* m_unloadedPiddbSourceGroup = nullptr; // 三来源互斥组。
    QRadioButton* m_unloadedPiddbMmSourceRadio = nullptr; // MmUnloadedDrivers 来源。
    QRadioButton* m_unloadedPiddbPiDdbSourceRadio = nullptr; // PiDDBCacheTable 来源。
    QRadioButton* m_unloadedPiddbCiSourceRadio = nullptr; // g_KernelHashBucketList 来源。
    QComboBox* m_unloadedPiddbFieldCombo = nullptr;   // 过滤字段下拉框。
    QLineEdit* m_unloadedPiddbFilterEdit = nullptr;   // 关键词或正则输入框。
    QCheckBox* m_unloadedPiddbRegexCheck = nullptr;   // 是否使用正则表达式。
    QLabel* m_unloadedPiddbCountLabel = nullptr;      // 当前可见行数量。
    QLabel* m_unloadedPiddbStatusLabel = nullptr;     // 当前来源查询状态。
    QTableWidget* m_unloadedPiddbTable = nullptr;     // 六列已卸载驱动表。
    ksword::ark::UnloadedDriverQueryResult m_lastUnloadedDriverResult; // 最近查询元信息。
    std::vector<ksword::ark::UnloadedDriverEntry> m_unloadedDriverCache; // 当前来源原始行。
    bool m_unloadedDriverQuerying = false;            // 后台查询中标记。
    std::uint64_t m_unloadedDriverQueryTicket = 0;    // 来源切换/查询序号。

    // ========================= 数据缓存 =========================
    std::vector<DriverServiceRecord> m_driverServiceCache;      // 驱动服务缓存。
    std::vector<LoadedKernelModuleRecord> m_loadedModuleCache;  // 已加载模块缓存。
    std::vector<LoadedModuleEvidenceRecord> m_loadedModuleEvidenceCache; // 模块证据缓存。
    ksword::ark::DriverObjectQueryResult m_lastDriverObjectQueryResult; // 最近一次 DriverObject 查询结果缓存。
    std::vector<ksword::ark::DriverIntegrityEvidenceEntry> m_driverIntegrityCache; // 驱动完整性证据缓存。
    ksword::ark::DriverIntegrityResult m_lastDriverIntegrityResult; // 最近一次完整性查询元信息。
    bool m_hasDriverObjectQueryResult = false;          // 是否已有 DriverObject 查询结果可回填。
    bool m_initialRefreshDone = false;                          // 首次显示时是否已完成首轮刷新。

    // ========================= 调试捕获线程状态 =========================
    std::atomic_bool m_kernelDebugCaptureRunning{ false };   // R0 捕获线程运行标记。
    std::unique_ptr<std::thread> m_kernelDebugCaptureThread; // R0 捕获线程对象。
};
