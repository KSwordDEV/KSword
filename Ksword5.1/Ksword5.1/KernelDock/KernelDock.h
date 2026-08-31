#pragma once

// ============================================================
// KernelDock.h
// 作用说明：
// 1) 提供“对象命名空间遍历”标签页（默认页）；
// 2) 提供“原子表遍历”标签页；
// 3) 提供“SSDT 遍历”标签页；
// 4) 保留旧版“NtQuery 信息”标签页到历史页；
// 5) 全部耗时查询走后台线程，避免阻塞 UI 线程。
// ============================================================

#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"

#include <QWidget>
#include <QString>

#include <atomic>   // std::atomic_bool：控制异步刷新互斥。
#include <cstdint>  // std::uintXX_t：固定宽度整数。
#include <vector>   // std::vector：缓存表格快照行。

namespace ksword::kernel_dock_internal
{
    // kernelText：
    // - 输入：稳定语境键与中文源文本；
    // - 处理：中文继续返回调用点原文，英文按 KernelDock 具体页面语境解析；
    // - 返回：当前语言下的界面或诊断文本。
    inline QString kernelText(const char* const contextKey, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(contextKey), sourceText);
    }
}

// Qt 前置声明：减少头文件耦合。
class QPoint;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QPushButton;
class QComboBox;
class QProgressBar;
class QTableWidget;
class QTabWidget;
class QTreeWidget;
class QVBoxLayout;
class QEvent;
class QShowEvent;
class CodeEditorWidget;
class CallbackInterceptController;
class KernelDockCidTab;
class KernelDockIpcTab;
class KernelKnowledgeTab;

// ============================================================
// KernelObjectTypeEntry
// 作用：
// - 保存 R3 ObjectTypesInformation 统计；
// - Object Type Matrix 会按 typeIndex 合并 R0 ObTypeIndexTable 证据。
// ============================================================
struct KernelObjectTypeEntry
{
    std::uint32_t typeIndex = 0;                 // typeIndex：对象类型编号。
    QString typeNameText;                        // typeNameText：对象类型名。
    std::uint64_t totalObjectCount = 0;          // totalObjectCount：对象数量。
    std::uint64_t totalHandleCount = 0;          // totalHandleCount：句柄数量。
    std::uint32_t validAccessMask = 0;           // validAccessMask：访问掩码。
    bool securityRequired = false;               // securityRequired：是否要求安全检查。
    bool maintainHandleCount = false;            // maintainHandleCount：是否维护句柄计数。
    std::uint32_t poolType = 0;                  // poolType：池类型。
    std::uint32_t defaultPagedPoolCharge = 0;    // defaultPagedPoolCharge：分页池默认配额。
    std::uint32_t defaultNonPagedPoolCharge = 0; // defaultNonPagedPoolCharge：非分页池默认配额。
    bool r3Present = true;                       // r3Present：R3 ObjectTypesInformation 是否包含该行。
    bool r0Present = false;                      // r0Present：R0 表槽是否包含有效 OBJECT_TYPE 地址。
    std::uint32_t r0Status = 0;                  // r0Status：逐槽 R0 验证状态。
    std::uint32_t r0FieldFlags = 0;              // r0FieldFlags：R0 已验证字段位图。
    long r0LastStatus = 0;                       // r0LastStatus：逐槽读取/验证 NTSTATUS。
    std::uint64_t r0ObjectTypeAddress = 0;       // r0ObjectTypeAddress：ObTypeIndexTable 槽指针。
    std::uint64_t r0IdentityHash = 0;            // r0IdentityHash：槽地址/索引/名称稳定身份哈希。
    QString r0TypeNameText;                      // r0TypeNameText：R0 从 OBJECT_TYPE.Name 读取的名称。
    QString r0ValidationText;                    // r0ValidationText：面向 UI 的交叉验证摘要。
};

// ============================================================
// KernelNtQueryResultEntry
// 作用：
// - 表示一次 NtQuery 查询结果；
// - 保存表格列信息与完整详情文本。
// ============================================================
struct KernelNtQueryResultEntry
{
    QString categoryText;     // categoryText：类别（系统/进程/线程/对象/令牌/导出）。
    QString functionNameText; // functionNameText：调用函数名。
    QString queryItemText;    // queryItemText：查询项名称。
    long statusCode = 0;      // statusCode：NTSTATUS 原始码。
    QString statusText;       // statusText：可读状态文本。
    QString summaryText;      // summaryText：表格摘要文本。
    QString detailText;       // detailText：详情面板完整文本。
};

// ============================================================
// KernelObjectNamespaceEntry
// 作用：
// - 表示对象管理器命名空间的一条枚举结果；
// - 同时承载“目录路径 + 枚举 API + 对象详情 + 操作信息”。
// ============================================================
struct KernelObjectNamespaceEntry
{
    QString rootPathText;            // rootPathText：根目录（如 \Device）。
    QString scopeDescriptionText;    // scopeDescriptionText：该根目录用途说明。
    QString directoryPathText;       // directoryPathText：当前被枚举目录路径。
    QString objectNameText;          // objectNameText：对象名。
    QString objectTypeText;          // objectTypeText：对象类型（Directory/SymbolicLink 等）。
    QString fullPathText;            // fullPathText：对象完整路径。
    QString enumApiText;             // enumApiText：本条记录使用的枚举 API。
    QString symbolicLinkTargetText;  // symbolicLinkTargetText：符号链接目标（非链接可为空）。
    QString statusText;              // statusText：状态文本（成功/失败 + 码）。
    QString detailText;              // detailText：详情面板展示文本。
    long statusCode = 0;             // statusCode：原始 NTSTATUS。
    bool querySucceeded = false;     // querySucceeded：枚举是否成功。
    bool isDirectory = false;        // isDirectory：该对象是否目录类型。
    bool isSymbolicLink = false;     // isSymbolicLink：该对象是否符号链接类型。
};

// ============================================================
// KernelAtomEntry
// 作用：
// - 表示原子表中的一条记录；
// - 统一承载 Atom 值、名称、来源与详情。
// ============================================================
struct KernelAtomEntry
{
    std::uint16_t atomValue = 0; // atomValue：Atom 十进制值。
    QString atomNameText;        // atomNameText：Atom 名称。
    QString sourceText;          // sourceText：来源（GlobalAtom/ClipboardFormat 等）。
    QString statusText;          // statusText：状态文本。
    QString detailText;          // detailText：详情文本。
    bool querySucceeded = false; // querySucceeded：该条目是否有效。
};

// ============================================================
// KernelSsdtEntry
// 作用：
// - 表示一条 SSDT 相关条目；
// - 保存服务索引、Zw 导出地址、表项地址及详情。
// ============================================================
struct KernelSsdtEntry
{
    std::uint32_t serviceIndex = 0;      // serviceIndex：服务索引（仅在 indexResolved=true 时有效）。
    std::uint32_t flags = 0;             // flags：驱动返回的标志位。
    std::uint64_t zwRoutineAddress = 0;  // zwRoutineAddress：Zw* 导出例程地址。
    std::uint64_t serviceRoutineAddress = 0; // serviceRoutineAddress：SSDT 表项解析出的服务例程地址。
    std::uint64_t serviceTableBase = 0;  // serviceTableBase：驱动返回的服务表基址。
    std::uint64_t tableEntryAddress = 0; // tableEntryAddress：SSDT 槽位本身的内核地址。
    std::uint64_t currentTableValue = 0; // currentTableValue：当前编码槽值。
    std::uint64_t cleanTableValue = 0;   // cleanTableValue：磁盘映像同 RVA 编码槽值。
    std::uint32_t tableEntrySize = 0;    // tableEntrySize：编码槽宽度。
    std::vector<std::uint8_t> currentTableBytes; // currentTableBytes：当前槽位小端字节。
    std::vector<std::uint8_t> cleanTableBytes;   // cleanTableBytes：已校验磁盘基线字节。
    QString cleanBaselinePath;           // cleanBaselinePath：已验证磁盘映像路径。
    QString cleanBaselineStatus;         // cleanBaselineStatus：身份/差异诊断。
    QString serviceNameText;             // serviceNameText：服务名称（Zw*）。
    QString moduleNameText;              // moduleNameText：模块名。
    QString statusText;                  // statusText：状态文本（索引解析/表项解析等）。
    QString detailText;                  // detailText：详情文本。
    bool indexResolved = false;          // indexResolved：是否成功从桩码提取服务索引。
    bool cleanBaselineAvailable = false; // cleanBaselineAvailable：是否获得身份匹配的磁盘槽位。
    bool cleanBaselineDiffers = false;   // cleanBaselineDiffers：当前槽位是否与基线不同。
    bool querySucceeded = false;         // querySucceeded：该条目是否有效。
};

// ============================================================
// KernelInlineHookEntry
// 作用：
// - 表示内核导出函数开头的 Inline Hook 检测结果；
// - 保存函数地址、跳转目标、模块归属、字节快照和 UI 详情文本。
// ============================================================
struct KernelInlineHookEntry
{
    std::uint32_t status = 0;               // status：R0 行状态。
    std::uint32_t hookType = 0;             // hookType：Inline Hook 指令形态。
    std::uint32_t flags = 0;                // flags：R0 诊断标志。
    std::uint32_t originalByteCount = 0;    // originalByteCount：R0 观察基线字节数，不代表磁盘原始字节。
    std::uint32_t currentByteCount = 0;     // currentByteCount：当前字节数。
    std::uint64_t functionAddress = 0;      // functionAddress：函数入口地址。
    std::uint64_t targetAddress = 0;        // targetAddress：解析出的跳转目标。
    std::uint64_t moduleBase = 0;           // moduleBase：所属模块基址。
    std::uint64_t targetModuleBase = 0;     // targetModuleBase：目标模块基址。
    QString moduleNameText;                 // moduleNameText：所属模块名。
    QString functionNameText;               // functionNameText：导出函数名。
    QString targetModuleNameText;           // targetModuleNameText：目标模块名。
    QString hookTypeText;                   // hookTypeText：Hook 类型文本。
    QString statusText;                     // statusText：状态文本。
    QString diskBaselineStatusText;         // diskBaselineStatusText：磁盘基线与内存字节的差异状态。
    QString diskBaselinePathText;           // diskBaselinePathText：磁盘基线来源文件路径。
    QString currentBytesText;               // currentBytesText：当前字节十六进制文本。
    QString observedBytesText;              // observedBytesText：R0 观察基线十六进制文本，不代表磁盘原始字节。
    QString diskBytesText;                  // diskBytesText：R3 从磁盘同 RVA 读取的基线字节文本。
    QString detailText;                     // detailText：详情文本。
    std::vector<std::uint8_t> currentBytes; // currentBytes：当前字节缓存。
    std::vector<std::uint8_t> observedBytes; // observedBytes：R0 返回的观察基线字节缓存。
    std::vector<std::uint8_t> diskBytes;    // diskBytes：R3 磁盘基线字节缓存。
    std::uint64_t diskBaselineRva = 0;      // diskBaselineRva：函数地址相对模块基址的 RVA。
    bool diskBaselineAvailable = false;     // diskBaselineAvailable：是否成功取得磁盘基线。
    bool diskBaselineDiffers = false;       // diskBaselineDiffers：内存字节是否不同于磁盘基线。
};

// ============================================================
// KernelIatEatHookEntry
// 作用：
// - 表示内核模块 IAT/EAT 指针检测结果；
// - 保存 thunk/EAT 项、目标地址、声明导入模块和状态文本。
// ============================================================
struct KernelIatEatHookEntry
{
    std::uint32_t hookClass = 0;          // hookClass：IAT 或 EAT。
    std::uint32_t status = 0;             // status：R0 行状态。
    std::uint32_t flags = 0;              // flags：R0 诊断标志。
    std::uint32_t ordinal = 0;            // ordinal：导出序号或 thunk 序号。
    std::uint64_t moduleBase = 0;         // moduleBase：所属模块基址。
    std::uint64_t thunkAddress = 0;       // thunkAddress：IAT thunk 或 EAT 项地址。
    std::uint64_t currentTarget = 0;      // currentTarget：当前目标地址。
    std::uint64_t expectedTarget = 0;     // expectedTarget：期望目标地址。
    std::uint64_t targetModuleBase = 0;   // targetModuleBase：目标模块基址。
    QString classText;                    // classText：IAT/EAT 文本。
    QString statusText;                   // statusText：状态文本。
    QString moduleNameText;               // moduleNameText：所属模块名。
    QString importModuleNameText;         // importModuleNameText：IAT 声明导入模块。
    QString functionNameText;             // functionNameText：函数名/占位符。
    QString targetModuleNameText;         // targetModuleNameText：当前目标模块名。
    QString detailText;                   // detailText：详情文本。
};

// KernelTimerDpcEntry：TimerTable 页的一条已归属模块的展示记录。
struct KernelTimerDpcEntry
{
    std::uint16_t processorGroup = 0;
    std::uint16_t processorNumber = 0;
    std::uint32_t bucketIndex = 0;
    std::uint32_t flags = 0;
    std::uint32_t timerType = 0;
    std::int32_t period = 0;
    std::int64_t dueTime = 0;
    std::uint64_t timerAddress = 0;
    std::uint64_t dpcAddress = 0;
    std::uint64_t deferredRoutine = 0;
    std::uint64_t deferredContext = 0;
    QString moduleNameText;
    QString statusText;
    QString detailText;
};


// ============================================================
// KernelCallbackEnumEntry
// 作用：
// - 表示 R0 回调遍历返回的一条记录；
// - 保存回调类别、来源、地址、模块、状态和详情文本。
// ============================================================
struct KernelCallbackEnumEntry
{
    std::uint32_t callbackClass = 0;       // callbackClass：回调类别。
    std::uint32_t source = 0;              // source：枚举来源。
    std::uint32_t status = 0;              // status：R0 行状态。
    std::uint32_t fieldFlags = 0;          // fieldFlags：有效字段位图。
    std::uint32_t trustFlags = 0;          // trustFlags：可信来源位；旧协议未返回时保持 0。
    std::uint32_t removeBehavior = 0;      // removeBehavior：R0 推荐的移除行为；旧协议未返回时保持 0。
    std::uint32_t removeFlags = 0;         // removeFlags：兼容旧 UI 命名，镜像 removeBehavior。
    std::uint32_t operationMask = 0;       // operationMask：操作掩码。
    std::uint32_t objectTypeMask = 0;      // objectTypeMask：对象类型掩码。
    std::uint32_t registrationType = 0;    // registrationType：具体注册 API/链类型。
    std::uint64_t generation = 0;          // generation：v3 稳定快照令牌；旧协议未返回时保持 0。
    long lastStatus = 0;                   // lastStatus：底层 NTSTATUS。
    std::uint64_t callbackAddress = 0;     // callbackAddress：回调函数或对象地址。
    std::uint64_t contextAddress = 0;      // contextAddress：上下文或扩展诊断值。
    std::uint64_t registrationAddress = 0; // registrationAddress：注册句柄/cookie。
    std::uint64_t identityHash = 0;        // identityHash：v3 稳定逐行身份哈希；旧协议未返回时保持 0。
    std::uint64_t rawStorageValue = 0;     // rawStorageValue：R0 原始注册槽值；旧协议未返回时保持 0。
    std::uint64_t moduleBase = 0;          // moduleBase：所属模块基址。
    std::uint32_t moduleSize = 0;          // moduleSize：所属模块大小。
    QString classText;                     // classText：类别文本。
    QString registrationTypeText;          // registrationTypeText：Legacy/Ex/Ex2 等具体类型文本。
    QString sourceText;                    // sourceText：来源文本。
    QString sourceTrustText;               // sourceTrustText：可信/公开 API/fallback/unsupported 来源展示文本。
    QString removePolicyText;              // removePolicyText：安全移除、候选、实验或不可移除策略文本。
    QString statusText;                    // statusText：状态文本。
    QString nameText;                      // nameText：回调/过滤器名称。
    QString altitudeText;                  // altitudeText：Altitude。
    QString modulePathText;                // modulePathText：模块路径。
    QString companyText;                   // companyText：模块版本资源中的公司。
    QString fileVersionText;               // fileVersionText：模块文件版本。
    QString fileDescriptionText;           // fileDescriptionText：模块文件描述。
    QString detailText;                    // detailText：详情文本。
    bool requiresSecondConfirmation = false; // requiresSecondConfirmation：移除动作是否需要二次确认。
    bool fallbackPatternOnly = false;      // fallbackPatternOnly：当前来源是否仅为 fallback/pattern 诊断。
};

// ============================================================
// KernelDynDataModuleIdentity
// 作用：
// - 表示 DynData 精确匹配时使用的内核模块身份；
// - 统一承载模块名、PE Machine、TimeDateStamp、SizeOfImage 和加载基址。
// ============================================================
struct KernelDynDataModuleIdentity
{
    bool present = false;                // present：模块当前是否已加载并被 R0 识别。
    std::uint32_t classId = 0;           // classId：System Informer DynData profile class。
    std::uint32_t machine = 0;           // machine：PE FileHeader.Machine。
    std::uint32_t timeDateStamp = 0;     // timeDateStamp：PE FileHeader.TimeDateStamp。
    std::uint32_t sizeOfImage = 0;       // sizeOfImage：PE OptionalHeader.SizeOfImage。
    std::uint64_t imageBase = 0;         // imageBase：模块加载基址。
    QString moduleNameText;              // moduleNameText：模块文件名。
};

// ============================================================
// KernelDynDataSummary
// 作用：
// - 表示动态偏移页顶部摘要；
// - 同时缓存 status/fields 两类 IOCTL 的成功状态和 R0 诊断字段。
// ============================================================
struct KernelDynDataSummary
{
    bool statusQueryOk = false;          // statusQueryOk：QUERY_DYN_STATUS 是否成功。
    bool fieldsQueryOk = false;          // fieldsQueryOk：QUERY_DYN_FIELDS 是否成功。
    std::uint32_t statusFlags = 0;       // statusFlags：KSW_DYN_STATUS_FLAG_* 位图。
    std::uint32_t systemInformerDataVersion = 0; // systemInformerDataVersion：System Informer 数据版本。
    std::uint32_t systemInformerDataLength = 0;  // systemInformerDataLength：KphDynConfig 字节长度。
    long lastStatus = 0;                 // lastStatus：R0 最后一次 DynData 激活 NTSTATUS。
    std::uint32_t matchedProfileClass = 0; // matchedProfileClass：匹配到的 profile class。
    std::uint32_t matchedProfileOffset = 0; // matchedProfileOffset：匹配字段 payload 偏移。
    std::uint32_t matchedFieldsId = 0;   // matchedFieldsId：保留字段集标识。
    std::uint32_t fieldCount = 0;        // fieldCount：R0 声明字段总数。
    std::uint64_t capabilityMask = 0;    // capabilityMask：KSW_CAP_* 能力位图。
    KernelDynDataModuleIdentity ntoskrnl; // ntoskrnl：当前内核模块身份。
    KernelDynDataModuleIdentity lxcore;  // lxcore：可选 WSL/lxcore 模块身份。
    QString unavailableReasonText;       // unavailableReasonText：R0 不可用原因。
    QString statusIoMessageText;         // statusIoMessageText：R3 状态查询诊断文本。
    QString fieldsIoMessageText;         // fieldsIoMessageText：R3 字段查询诊断文本。
    bool pdbProfileScanAttempted = false; // pdbProfileScanAttempted：是否扫描过本地 JSON profile。
    bool pdbProfileFound = false;         // pdbProfileFound：是否找到与当前 ntoskrnl identity 精确匹配的 profile。
    bool pdbProfileApplied = false;       // pdbProfileApplied：R0 是否接受并应用了 PDB profile。
    long pdbProfileStatus = 0;            // pdbProfileStatus：R0 apply 返回的 NTSTATUS。
    std::uint32_t pdbProfileAppliedFields = 0; // pdbProfileAppliedFields：R0 应用字段数。
    std::uint32_t pdbProfileRejectedFields = 0; // pdbProfileRejectedFields：R0 拒绝字段数。
    std::uint32_t pdbProfileUnknownFields = 0;  // pdbProfileUnknownFields：R0 不支持字段数。
    std::uint32_t pdbProfileIgnoredJsonFields = 0; // pdbProfileIgnoredJsonFields：R3 忽略的 JSON 未知字段数。
    QString pdbProfileSourceText;         // pdbProfileSourceText：profile 来源，区分 compact pack 与散落 JSON。
    QString pdbProfileNameText;           // pdbProfileNameText：匹配 profile 名称。
    QString pdbProfilePathText;           // pdbProfilePathText：匹配 profile 文件路径。
    QString pdbProfileMessageText;        // pdbProfileMessageText：R0/R3 profile 诊断消息。
    QString pdbProfileIoMessageText;      // pdbProfileIoMessageText：apply IOCTL 传输诊断。
    bool dynDataV4ModulesQueryOk = false; // dynDataV4ModulesQueryOk：v4 modules 状态查询是否成功。
    bool dynDataV4ModulesUnsupported = false; // dynDataV4ModulesUnsupported：旧驱动是否缺少 v4 modules 查询入口。
    std::uint32_t dynDataV4ModulesTotalCount = 0; // dynDataV4ModulesTotalCount：R0 观察到的 v4 module 总数。
    std::uint32_t dynDataV4ModulesReturnedCount = 0; // dynDataV4ModulesReturnedCount：R0 本次返回的 v4 module 行数。
    QString dynDataV4ModulesIoMessageText; // dynDataV4ModulesIoMessageText：v4 modules 查询 IO 诊断文本。
    bool dynDataV4CapabilityGroupsQueryOk = false; // dynDataV4CapabilityGroupsQueryOk：v4 capability groups 查询是否成功。
    bool dynDataV4CapabilityGroupsUnsupported = false; // dynDataV4CapabilityGroupsUnsupported：旧驱动是否缺少 capability groups 查询入口。
    std::uint32_t dynDataV4CapabilityGroupsTotalCount = 0; // dynDataV4CapabilityGroupsTotalCount：R0 观察到的 capability group 总数。
    std::uint32_t dynDataV4CapabilityGroupsReturnedCount = 0; // dynDataV4CapabilityGroupsReturnedCount：R0 本次返回的 capability group 行数。
    QString dynDataV4CapabilityGroupsIoMessageText; // dynDataV4CapabilityGroupsIoMessageText：capability groups 查询 IO 诊断文本。
    bool dynDataV4MissingItemsQueryOk = false; // dynDataV4MissingItemsQueryOk：v4 missing items 查询是否成功。
    bool dynDataV4MissingItemsUnsupported = false; // dynDataV4MissingItemsUnsupported：旧驱动是否缺少 missing items 查询入口。
    std::uint32_t dynDataV4MissingItemsTotalCount = 0; // dynDataV4MissingItemsTotalCount：R0 观察到的 missing item 总数。
    std::uint32_t dynDataV4MissingItemsReturnedCount = 0; // dynDataV4MissingItemsReturnedCount：R0 本次返回的 missing item 行数。
    QString dynDataV4MissingItemsIoMessageText; // dynDataV4MissingItemsIoMessageText：missing items 查询 IO 诊断文本。
    bool dynDataV4ItemsQueryOk = false; // dynDataV4ItemsQueryOk：v4 已接受 item 清单查询是否成功。
    bool dynDataV4ItemsUnsupported = false; // dynDataV4ItemsUnsupported：旧驱动是否缺少 v4 items 查询入口。
    std::uint32_t dynDataV4ItemsTotalCount = 0; // dynDataV4ItemsTotalCount：R0 观察到的 accepted item 总数。
    std::uint32_t dynDataV4ItemsReturnedCount = 0; // dynDataV4ItemsReturnedCount：R0 本次返回的 accepted item 行数。
    QString dynDataV4ItemsIoMessageText; // dynDataV4ItemsIoMessageText：v4 items 查询 IO 诊断文本。
};

// ============================================================
// KernelDynDataFieldEntry
// 作用：
// - 表示动态偏移字段表的一行；
// - 保存字段来源、可用状态、能力依赖和详情文本。
// ============================================================
struct KernelDynDataFieldEntry
{
    std::uint32_t fieldId = 0;           // fieldId：KSW_DYN_FIELD_ID_*。
    std::uint32_t flags = 0;             // flags：KSW_DYN_FIELD_FLAG_*。
    std::uint32_t source = 0;            // source：KSW_DYN_FIELD_SOURCE_*。
    std::uint32_t offset = 0;            // offset：字段偏移；不可用时为哨兵值。
    std::uint64_t capabilityMask = 0;    // capabilityMask：本字段参与的 KSW_CAP_* 位。
    QString fieldNameText;               // fieldNameText：字段名。
    QString sourceNameText;              // sourceNameText：来源名。
    QString featureNameText;             // featureNameText：所属功能名。
    QString statusText;                  // statusText：可用/缺失状态。
    QString detailText;                  // detailText：详情面板文本。
};

// ============================================================
// KernelDynDataV4ItemEntry
// 作用：
// - 表示 DynData v4 accepted item 表的一行；
// - 保存 R0 已接受并缓存的 PDB item，便于确认 profile 不是只有摘要。
// ============================================================
struct KernelDynDataV4ItemEntry
{
    std::uint32_t moduleClassId = 0;      // moduleClassId：KSW_DYN_PROFILE_CLASS_* 模块类别。
    std::uint32_t itemIndex = 0;          // itemIndex：该模块内的 R0 存储序号。
    std::uint32_t itemId = 0;             // itemId：v4 item 稳定编号。
    std::uint32_t itemKind = 0;           // itemKind：StructOffset/GlobalRva/FunctionRva 等类型。
    std::uint32_t flags = 0;              // flags：required/optional 等 item 标志。
    std::uint32_t capabilityGroupId = 0;  // capabilityGroupId：所属 capability group。
    std::uint64_t value = 0;              // value：valueLow/valueHigh 合并后的 64 位值。
    QString kindText;                     // kindText：itemKind 的人类可读文本。
    QString flagsText;                    // flagsText：flags 的人类可读文本。
    QString auxText;                      // auxText：aux0..aux3 辅助字段摘要。
    QString detailText;                   // detailText：完整明细文本。
};

// ============================================================
// KernelDriverStatusSummary
// 作用：
// - 表示 Phase 1 统一驱动状态查询的摘要；
// - 缓存协议版本、安全策略、DynData 状态和最近一次 R0 错误。
// ============================================================
struct KernelDriverStatusSummary
{
    bool queryOk = false;                    // queryOk：统一能力 IOCTL 是否成功。
    bool driverLoaded = false;               // driverLoaded：R3 是否成功打开并查询 KswordARK 驱动。
    bool protocolOk = false;                 // protocolOk：R0 协议版本是否匹配当前 R3 期望。
    bool dynDataMissing = true;              // dynDataMissing：DynData 是否缺失或未命中 ntos profile。
    bool limited = true;                     // limited：是否处于能力受限状态。
    std::uint32_t version = 0;               // version：能力查询协议版本。
    std::uint32_t driverProtocolVersion = 0; // driverProtocolVersion：R0 主协议版本。
    std::uint32_t statusFlags = 0;           // statusFlags：KSWORD_ARK_DRIVER_STATUS_FLAG_*。
    std::uint32_t securityPolicyFlags = 0;   // securityPolicyFlags：KSWORD_ARK_SECURITY_POLICY_*。
    std::uint32_t dynDataStatusFlags = 0;    // dynDataStatusFlags：KSW_DYN_STATUS_FLAG_*。
    long lastErrorStatus = 0;                // lastErrorStatus：最近一次 R0 记录的 NTSTATUS。
    std::uint32_t totalFeatureCount = 0;     // totalFeatureCount：R0 声明的功能总数。
    std::uint32_t returnedFeatureCount = 0;  // returnedFeatureCount：本次响应返回的功能行数。
    std::uint64_t dynDataCapabilityMask = 0; // dynDataCapabilityMask：当前 DynData capability 位图。
    bool dynDataStatusQueryOk = false;       // dynDataStatusQueryOk：QUERY_DYN_STATUS 是否成功。
    bool dynDataFieldsQueryOk = false;       // dynDataFieldsQueryOk：QUERY_DYN_FIELDS 是否成功。
    bool ntoskrnlIdentityPresent = false;    // ntoskrnlIdentityPresent：R0 是否识别到当前 ntoskrnl 身份。
    bool localPdbProfileMatched = false;     // localPdbProfileMatched：本地 pack 是否精确匹配当前 ntoskrnl。
    bool pdbProfileActive = false;           // pdbProfileActive：R0 当前是否已应用 PDB profile。
    bool callbackProfileActive = false;      // callbackProfileActive：R0 当前是否已应用 callback PDB profile。
    bool trustedPdbOffsetsActive = false;    // trustedPdbOffsetsActive：是否已有可信 PDB 偏移参与当前 DynData。
    bool callbackNotifyTrusted = false;      // callbackNotifyTrusted：notify 数组全局 RVA 是否由 profile 覆盖。
    bool callbackRegistryTrusted = false;    // callbackRegistryTrusted：registry 回调全局 RVA 是否由 profile 覆盖。
    bool callbackObjectTrusted = false;      // callbackObjectTrusted：object callback 结构偏移是否由 profile 覆盖。
    std::uint32_t dynDataSystemInformerDataVersion = 0; // dynDataSystemInformerDataVersion：内置 System Informer DynData 版本。
    std::uint32_t dynDataSystemInformerDataLength = 0;  // dynDataSystemInformerDataLength：内置 DynData 配置字节数。
    std::uint32_t dynDataMatchedProfileClass = 0; // dynDataMatchedProfileClass：R0 匹配到的 profile class。
    std::uint32_t dynDataMatchedProfileOffset = 0; // dynDataMatchedProfileOffset：R0 匹配字段 payload 偏移。
    std::uint32_t dynDataMatchedFieldsId = 0; // dynDataMatchedFieldsId：R0 匹配字段集标识。
    std::uint32_t dynDataFieldCount = 0;      // dynDataFieldCount：R0 声明的 DynData 字段总数。
    std::uint32_t dynDataReturnedFieldCount = 0; // dynDataReturnedFieldCount：字段列表本次返回行数。
    std::uint32_t dynDataPresentFieldCount = 0; // dynDataPresentFieldCount：当前可用字段数。
    std::uint32_t dynDataRequiredMissingCount = 0; // dynDataRequiredMissingCount：必需字段缺失数。
    std::uint32_t dynDataPdbProfileFieldCount = 0; // dynDataPdbProfileFieldCount：来源为 PDB profile 的可用字段数。
    std::uint32_t dynDataRuntimePatternFieldCount = 0; // dynDataRuntimePatternFieldCount：来源为 runtime pattern 的可用字段数。
    std::uint32_t dynDataSystemInformerFieldCount = 0; // dynDataSystemInformerFieldCount：来源为 System Informer 的可用字段数。
    std::uint32_t dynDataExtraTableFieldCount = 0; // dynDataExtraTableFieldCount：来源为 Ksword extra table 的可用字段数。
    std::uint32_t dynDataUnavailableFieldCount = 0; // dynDataUnavailableFieldCount：当前不可用字段数。
    bool dynDataActiveProcessLinksPresent = false; // dynDataActiveProcessLinksPresent：R0 当前是否公开了 _EPROCESS.ActiveProcessLinks 偏移。
    std::uint32_t dynDataActiveProcessLinksOffset = 0xFFFFFFFFU; // dynDataActiveProcessLinksOffset：R0 当前生效的 ActiveProcessLinks 偏移。
    std::uint32_t dynDataActiveProcessLinksSource = 0; // dynDataActiveProcessLinksSource：R0 当前 ActiveProcessLinks 偏移来源。
    std::uint32_t ntoskrnlClassId = 0;       // ntoskrnlClassId：当前 ntoskrnl profile class。
    std::uint32_t ntoskrnlMachine = 0;       // ntoskrnlMachine：当前 ntoskrnl PE Machine。
    std::uint32_t ntoskrnlTimeDateStamp = 0; // ntoskrnlTimeDateStamp：当前 ntoskrnl PE TimeDateStamp。
    std::uint32_t ntoskrnlSizeOfImage = 0;   // ntoskrnlSizeOfImage：当前 ntoskrnl PE SizeOfImage。
    std::uint64_t ntoskrnlImageBase = 0;     // ntoskrnlImageBase：当前 ntoskrnl 加载基址。
    QString ntoskrnlModuleNameText;          // ntoskrnlModuleNameText：当前 ntoskrnl 模块名。
    std::uint32_t localPdbProfilePackProfileCount = 0; // localPdbProfilePackProfileCount：命中 pack 声明的 profile 总数。
    std::uint32_t localPdbProfileFieldCount = 0; // localPdbProfileFieldCount：命中 profile 声明字段数。
    std::uint32_t localPdbProfileTypedItemCount = 0; // localPdbProfileTypedItemCount：命中 profile 声明 v3 typed items 数。
    std::uint32_t localPdbProfileCallbackItemCount = 0; // localPdbProfileCallbackItemCount：命中 profile 声明 callbackItems 数。
    bool localPdbProfileActiveProcessLinksPresent = false; // localPdbProfileActiveProcessLinksPresent：本地 pack 是否包含 ActiveProcessLinks。
    std::uint32_t localPdbProfileActiveProcessLinksOffset = 0xFFFFFFFFU; // localPdbProfileActiveProcessLinksOffset：本地 pack 提取的 ActiveProcessLinks 偏移。
    double localPdbProfileCoveragePercent = -1.0; // localPdbProfileCoveragePercent：release_sync 写入的 profile 覆盖率，负数表示未知。
    QString localPdbProfileNameText;         // localPdbProfileNameText：本地 pack 命中的 profile 名。
    QString localPdbProfileVersionText;      // localPdbProfileVersionText：从 profile 名提取的 Windows 版本号。
    QString localPdbProfilePathText;         // localPdbProfilePathText：命中 pack 文件路径。
    QString dynDataUnavailableReasonText;    // dynDataUnavailableReasonText：R0 DynData 不可用原因。
    QString dynDataStatusIoMessageText;      // dynDataStatusIoMessageText：DynData 状态 IO 诊断。
    QString dynDataFieldsIoMessageText;      // dynDataFieldsIoMessageText：DynData 字段 IO 诊断。
    QString localPdbProfileMessageText;      // localPdbProfileMessageText：本地 pack 匹配诊断。
    QString lastErrorSourceText;             // lastErrorSourceText：最近错误来源。
    QString lastErrorSummaryText;            // lastErrorSummaryText：最近错误摘要。
    QString ioMessageText;                   // ioMessageText：R3 IO 诊断文本。
};

// ============================================================
// KernelDriverCapabilityEntry
// 作用：
// - 表示统一能力矩阵的一行；
// - 保存功能名、状态、安全策略依赖、DynData 依赖和详情文本。
// ============================================================
struct KernelDriverCapabilityEntry
{
    std::uint32_t featureId = 0;             // featureId：KSWORD_ARK_FEATURE_ID_*。
    std::uint32_t state = 0;                 // state：KSWORD_ARK_FEATURE_STATE_*。
    std::uint32_t flags = 0;                 // flags：KSWORD_ARK_FEATURE_FLAG_*。
    std::uint32_t requiredPolicyFlags = 0;   // requiredPolicyFlags：启用所需安全策略位。
    std::uint32_t deniedPolicyFlags = 0;     // deniedPolicyFlags：当前策略缺失位。
    std::uint64_t requiredDynDataMask = 0;   // requiredDynDataMask：启用所需 KSW_CAP_* 位。
    std::uint64_t presentDynDataMask = 0;    // presentDynDataMask：当前已满足 KSW_CAP_* 位。
    QString featureNameText;                 // featureNameText：功能名。
    QString stateNameText;                   // stateNameText：功能状态名。
    QString dependencyText;                  // dependencyText：依赖字段说明。
    QString reasonText;                      // reasonText：不可用/降级原因。
    QString detailText;                      // detailText：详情面板文本。
};

// ============================================================
// KernelDock
// 作用：
// - 内核分析主控件；
// - 管理对象命名空间/原子表/SSDT/历史 NtQuery/驱动回调页面；
// - 管理异步刷新、筛选、详情联动与右键菜单操作。
// ============================================================
class KernelDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：初始化 UI、连接信号槽并触发首轮异步刷新。
    // - 参数 parent：Qt 父控件。
    explicit KernelDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 资源由 Qt 父子机制与容器自动释放。
    ~KernelDock() override = default;

    // requestDynDataRefresh：
    // - 作用：对外触发 DynData 页初始化和异步刷新。
    void requestDynDataRefresh();

    // kswordSelfDriverPage：
    // - 输入：无；
    // - 处理：返回包含“动态偏移/驱动状态”二级页的容器；
    // - 输出：非拥有指针，由 MainWindow 挂到 DriverDock，业务逻辑仍由 KernelDock 管理。
    QWidget* kswordSelfDriverPage() const;

    // ensureCurrentTabReadyForDisplay：
    // - 输入：无，使用当前顶层 Tab 索引；
    // - 处理：确保当前 Tab 的真实 UI 已初始化，并安排一次重绘；
    // - 返回：无返回值。供 MainWindow 在 ADS 恢复布局/显示后兜底调用。
    void ensureCurrentTabReadyForDisplay();

    // focusProcessProtectTab：
    // - 输入：无；
    // - 处理：切换到“内核审计与回调 -> 驱动回调 -> 进程保护”；
    // - 返回：无；供进程页快捷入口复用同一套回调保护页面。
    void focusProcessProtectTab();

    // displayStateSummary：
    // - 输入：无；
    // - 处理：汇总顶层 Tab、当前页和对象命名空间内层 Tab 的可见/尺寸/初始化状态；
    // - 返回：用于启动黑屏排查的紧凑日志文本。
    QString displayStateSummary() const;

protected:
    // eventFilter：
    // - 处理迁移到 DriverDock 的自身驱动容器首次真正可见事件；
    // - 只安排当前二级页的一次幂等首刷，不接管页面业务所有权。
    bool eventFilter(QObject* watched, QEvent* event) override;

    // showEvent：
    // - 输入 event：Qt 显示事件；
    // - 处理：内核 Dock 被 ADS 延迟挂载/恢复后，再次确保当前内部页真实初始化；
    // - 返回：无返回值。
    void showEvent(QShowEvent* event) override;

private:
    // ==================== UI 初始化 ====================
    // initializeUi：
    // - 作用：创建根布局与顶层 Tab 容器。
    void initializeUi();

    // initializeObjectNamespaceTab：
    // - 作用：创建“对象命名空间遍历”页（默认页）。
    void initializeObjectNamespaceTab();

    // initializeAtomTableTab：
    // - 作用：创建“原子表遍历”页。
    void initializeAtomTableTab();

    // initializeNtQueryTab：
    // - 作用：创建“历史 NtQuery 信息”页。
    void initializeNtQueryTab();

    // initializeSsdtTab：
    // - 作用：创建“SSDT 遍历”页。
    void initializeSsdtTab();

    // initializeIoManagementTab：
    // - 输入：无；
    // - 处理：创建 I/O 管理主页面及 SSDT、ShadowSSDT、IDT、GDT、IOCTLS 横向子页；
    // - 返回：无。
    void initializeIoManagementTab();

    // initializeDynDataTab：
    // - 作用：创建“动态偏移”诊断页。
    void initializeDynDataTab();

    // initializeDriverStatusTab：
    // - 作用：创建“驱动状态”页，展示统一状态卡片和能力矩阵。
    void initializeDriverStatusTab();

    // initializeCallbackInterceptTab：
    // - 作用：创建“驱动回调”页签（规则组/规则编辑/导入导出/应用/状态）。
    void initializeCallbackInterceptTab();

    // initializeCallbackRemovePanel：
    // - 输入：无，依赖已经创建的“回调遍历”页布局作为宿主。
    // - 处理：在“回调遍历”页底部创建手动回调移除面板，复用旧版类型/地址/结果详情控件。
    // - 返回：无；函数内部通过成员指针记录控件，重复调用会直接返回。
    void initializeCallbackRemovePanel();

    // initializeCallbackEnumTab：
    // - 作用：创建“回调遍历”页签，展示 R0 枚举到的回调记录。
    void initializeCallbackEnumTab();

    // initializeShadowSsdtTab：
    // - 作用：创建“SSSDT解析”页签，展示 win32k/win32u shadow syscall 信息。
    void initializeShadowSsdtTab();

    // initializeInlineHookTab：
    // - 作用：创建“Inline Hook 检测 & 摘除”页签，提供扫描和强制摘除入口。
    void initializeInlineHookTab();

    // initializeIatEatHookTab：
    // - 作用：创建“IAT/EAT 钩子检测”页签，展示导入/导出表可疑指针。
    void initializeIatEatHookTab();

    // initializeTimerDpcTab：创建 DynData v4 驱动的 KTIMER/KDPC 只读枚举页。
    void initializeTimerDpcTab();

    // initializeCrossViewTab：
    // - 作用：创建只读 CID / cross-view 页。
    void initializeCrossViewTab();

    // initializeIpcTab：
    // - 作用：创建只读 IPC / NamedPipe / ALPC 聚合页。
    void initializeIpcTab();

    // openKnowledgeRoute：
    // - 输入 routeId：知识文章声明的稳定站内观察路由；
    // - 处理：只切换到当前 KernelDock 已有的只读页面，不启动写操作；
    // - 返回：无，未知路由静默保持知识页。
    void openKnowledgeRoute(const QString& routeId);

    // initializeConnections：
    // - 作用：绑定按钮、筛选框、表格联动与右键菜单。
    void initializeConnections();

    // ensureTabInitialized：
    // - 作用：按需初始化指定 Tab 的 UI 与首次数据加载。
    // - 参数 tabIndex：顶层 Tab 索引。
    void ensureTabInitialized(int tabIndex);

    // ensureSelfDriverCurrentTabRefreshed：
    // - 外层自身驱动页可见或内部页切换后延迟一轮复核；
    // - 动态偏移与驱动状态各自最多自动首刷一次。
    void ensureSelfDriverCurrentTabRefreshed();

    // ensureIoManagementTabInitialized：
    // - 输入 innerTabIndex：I/O 管理内部横向子页索引；
    // - 处理：仅为 SSDT/ShadowSSDT 启动原有惰性 UI 与首次刷新；
    // - 返回：无，IDT/GDT 自行在首次显示时加载，IOCTLS 无后台查询。
    void ensureIoManagementTabInitialized(int innerTabIndex);

    // ==================== 异步刷新 ====================
    // refreshObjectNamespaceAsync：
    // - 作用：后台刷新对象命名空间枚举结果。
    void refreshObjectNamespaceAsync();

    // refreshAtomTableAsync：
    // - 作用：后台刷新原子表枚举结果。
    void refreshAtomTableAsync();

    // refreshNtQueryAsync：
    // - 作用：后台刷新历史 NtQuery 结果。
    void refreshNtQueryAsync();

    // refreshSsdtAsync：
    // - 作用：后台刷新 SSDT 遍历结果。
    void refreshSsdtAsync();
    void restoreSelectedSsdtBaseline();

    // refreshDynDataAsync：
    // - 作用：后台查询 R0 DynData 状态、字段列表和 capability 位图。
    void refreshDynDataAsync();

    // refreshDriverStatusAsync：
    // - 作用：后台查询 Phase 1 统一驱动能力、协议、安全策略和最近错误。
    void refreshDriverStatusAsync();

    // refreshCallbackEnumAsync：
    // - 作用：后台调用 ArkDriverClient 枚举回调记录。
    void refreshCallbackEnumAsync();

    // refreshShadowSsdtAsync：
    // - 作用：后台调用 ArkDriverClient 解析 SSSDT/Shadow SSDT。
    void refreshShadowSsdtAsync();
    void restoreSelectedShadowSsdtBaseline();

    // refreshInlineHooksAsync：
    // - 作用：后台扫描内核模块导出函数 Inline Hook。
    void refreshInlineHooksAsync();

    // refreshIatEatHooksAsync：
    // - 作用：后台扫描内核模块 IAT/EAT 可疑指针。
    void refreshIatEatHooksAsync();

    // refreshTimerDpcAsync：后台枚举每 CPU TimerTable 并解析例程模块归属。
    void refreshTimerDpcAsync();

    // refreshTimerDpcAfterDynDataAsync：先完成 DynData profile 应用，再枚举 Timer/DPC。
    void refreshTimerDpcAfterDynDataAsync();

    // ==================== 表格渲染 ====================
    // rebuildObjectNamespaceTable：
    // - 作用：根据筛选关键词重建对象命名空间树。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildObjectNamespaceTable(const QString& filterKeyword);

    // rebuildObjectNamespacePropertyTable：
    // - 作用：重建“对象属性项/值”表，展示当前节点或对象记录的详细字段。
    // - 参数 entry：当前对象记录；为 nullptr 时展示树节点摘要。
    // - 参数 nodeNameText：树节点名称（entry 为 nullptr 时使用）。
    // - 参数 nodeTypeText：树节点类型（entry 为 nullptr 时使用）。
    // - 参数 nodePathText：树节点路径（entry 为 nullptr 时使用）。
    // - 参数 nodeDescriptionText：树节点说明（entry 为 nullptr 时使用）。
    void rebuildObjectNamespacePropertyTable(
        const KernelObjectNamespaceEntry* entry,
        const QString& nodeNameText,
        const QString& nodeTypeText,
        const QString& nodePathText,
        const QString& nodeDescriptionText);

    // selectFirstObjectNamespaceEntryItem：
    // - 作用：在树中定位并选中第一条对象记录节点（非根/目录摘要节点）。
    void selectFirstObjectNamespaceEntryItem();

    // showTabInitializingProgress：
    // - 作用：页签惰性初始化前显示顶部不确定进度条，减少空白等待感。
    // - 参数 tabIndex：目标页签索引；参数 titleText：页签中文名称。
    void showTabInitializingProgress(int tabIndex, const QString& titleText);

    // hideTabInitializingProgress：
    // - 作用：页签内容构建完成后隐藏初始化进度条。
    void hideTabInitializingProgress();

    // updateTabIconContrast：
    // - 作用：根据当前选中页签重绘 Tab 图标颜色，确保蓝底高亮时图标为白色。
    void updateTabIconContrast();

    // rebuildAtomTable：
    // - 作用：根据筛选关键词重建原子表格。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildAtomTable(const QString& filterKeyword);

    // rebuildNtQueryTable：
    // - 作用：重建历史 NtQuery 结果表格。
    void rebuildNtQueryTable();

    // rebuildSsdtTable：
    // - 作用：根据筛选关键词重建 SSDT 结果表格。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildSsdtTable(const QString& filterKeyword);

    // rebuildDynDataFieldTable：
    // - 作用：根据筛选关键词重建动态偏移字段表。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildDynDataFieldTable(const QString& filterKeyword);

    // rebuildDynDataV4ItemTable：
    // - 作用：重建 v4 accepted item 明细表。
    // - 参数 filterKeyword：预留筛选关键词，当前与字段筛选框共用。
    void rebuildDynDataV4ItemTable(const QString& filterKeyword);

    // rebuildDriverCapabilityTable：
    // - 作用：根据筛选关键词重建驱动能力矩阵。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildDriverCapabilityTable(const QString& filterKeyword);

    // rebuildCallbackEnumTable：
    // - 作用：根据筛选关键词重建回调遍历表。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildCallbackEnumTable(const QString& filterKeyword);

    // rebuildShadowSsdtTable：
    // - 作用：根据筛选关键词重建 SSSDT 表格。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildShadowSsdtTable(const QString& filterKeyword);

    // rebuildInlineHookTable：
    // - 作用：根据筛选关键词重建 Inline Hook 表格。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildInlineHookTable(const QString& filterKeyword);

    // rebuildIatEatHookTable：
    // - 作用：根据筛选关键词重建 IAT/EAT Hook 表格。
    // - 参数 filterKeyword：筛选关键词（空表示不过滤）。
    void rebuildIatEatHookTable(const QString& filterKeyword);

    void rebuildTimerDpcTable(const QString& filterKeyword);

    // ==================== 详情联动 ====================
    // showObjectNamespaceDetailByCurrentRow：
    // - 作用：根据当前选中行显示对象命名空间详情。
    void showObjectNamespaceDetailByCurrentRow();

    // showAtomDetailByCurrentRow：
    // - 作用：根据当前选中行显示原子详情。
    void showAtomDetailByCurrentRow();

    // showNtQueryDetailByCurrentRow：
    // - 作用：根据当前选中行显示 NtQuery 详情。
    void showNtQueryDetailByCurrentRow();

    // showSsdtDetailByCurrentRow：
    // - 作用：根据当前选中行显示 SSDT 详情。
    void showSsdtDetailByCurrentRow();

    // showDynDataDetailByCurrentRow：
    // - 作用：根据当前选中行显示动态偏移字段详情。
    void showDynDataDetailByCurrentRow();

    // showDriverCapabilityDetailByCurrentRow：
    // - 作用：根据当前选中行显示功能依赖、策略和 DynData 位图详情。
    void showDriverCapabilityDetailByCurrentRow();

    // showCallbackEnumDetailByCurrentRow：
    // - 作用：根据当前选中行显示回调遍历详情。
    void showCallbackEnumDetailByCurrentRow();

    // showCallbackEnumDetail：
    // - 作用：显示表格或 Minifilter 树传入的同一份回调详情。
    void showCallbackEnumDetail(const KernelCallbackEnumEntry* entry);

    // showShadowSsdtDetailByCurrentRow：
    // - 作用：根据当前选中行显示 SSSDT 详情。
    void showShadowSsdtDetailByCurrentRow();

    // showInlineHookDetailByCurrentRow：
    // - 作用：根据当前选中行显示 Inline Hook 详情。
    void showInlineHookDetailByCurrentRow();

    // showIatEatHookDetailByCurrentRow：
    // - 作用：根据当前选中行显示 IAT/EAT Hook 详情。
    void showIatEatHookDetailByCurrentRow();

    void showTimerDpcDetailByCurrentRow();

    void showTimerDpcContextMenu(const QPoint& localPosition);

    // ==================== 右键菜单 ====================
    // showObjectNamespaceContextMenu：
    // - 作用：弹出对象命名空间表格右键菜单（复制 + 对象操作）。
    // - 参数 localPosition：表格视口坐标。
    void showObjectNamespaceContextMenu(const QPoint& localPosition);

    // showAtomContextMenu：
    // - 作用：弹出原子表格右键菜单（复制 + 原子操作）。
    // - 参数 localPosition：表格视口坐标。
    void showAtomContextMenu(const QPoint& localPosition);

    // showCallbackEnumContextMenu：
    // - 作用：弹出回调遍历表格右键菜单；
    // - 支持复制当前列、指定栏目、选中行和详情；
    // - 右键动作对 Ctrl 多选后的所有选中行生效。
    // 参数 localPosition：表格视口坐标。
    // 返回值：无。
    void showCallbackEnumContextMenu(const QPoint& localPosition);

    // showShadowSsdtContextMenu：
    // - 作用：弹出 SSSDT 表格右键复制菜单。
    // - 参数 localPosition：表格视口坐标。
    void showShadowSsdtContextMenu(const QPoint& localPosition);

    // showInlineHookContextMenu：
    // - 作用：弹出 Inline Hook 表格右键菜单，支持复制和摘除选中项。
    // - 参数 localPosition：表格视口坐标。
    void showInlineHookContextMenu(const QPoint& localPosition);

    // showIatEatHookContextMenu：
    // - 作用：弹出 IAT/EAT Hook 表格右键复制菜单。
    // - 参数 localPosition：表格视口坐标。
    void showIatEatHookContextMenu(const QPoint& localPosition);

    // patchSelectedInlineHookWithNop：
    // - 作用：对当前选中的 Inline Hook 先普通请求，再经用户确认后 force NOP 摘除。
    void patchSelectedInlineHookWithNop();

    // ==================== 当前行索引辅助 ====================
    // currentObjectNamespaceSourceIndex：
    // - 作用：读取对象命名空间当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentObjectNamespaceSourceIndex(std::size_t& sourceIndexOut) const;

    // currentAtomSourceIndex：
    // - 作用：读取原子表当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentAtomSourceIndex(std::size_t& sourceIndexOut) const;

    // currentSsdtSourceIndex：
    // - 作用：读取 SSDT 表当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentSsdtSourceIndex(std::size_t& sourceIndexOut) const;

    // currentDynDataFieldSourceIndex：
    // - 作用：读取动态偏移字段表当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentDynDataFieldSourceIndex(std::size_t& sourceIndexOut) const;

    // currentDriverCapabilitySourceIndex：
    // - 作用：读取能力矩阵当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentDriverCapabilitySourceIndex(std::size_t& sourceIndexOut) const;

    // currentCallbackEnumSourceIndex：
    // - 作用：读取回调遍历当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentCallbackEnumSourceIndex(std::size_t& sourceIndexOut) const;

    // currentShadowSsdtSourceIndex：
    // - 作用：读取 SSSDT 当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentShadowSsdtSourceIndex(std::size_t& sourceIndexOut) const;

    // currentInlineHookSourceIndex：
    // - 作用：读取 Inline Hook 当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentInlineHookSourceIndex(std::size_t& sourceIndexOut) const;

    // currentIatEatHookSourceIndex：
    // - 作用：读取 IAT/EAT 当前行映射到缓存向量的索引。
    // - 传出 sourceIndexOut：缓存索引。
    // - 返回：true=读取成功；false=无选中或越界。
    bool currentIatEatHookSourceIndex(std::size_t& sourceIndexOut) const;

    // currentObjectNamespaceEntry：
    // - 作用：返回对象命名空间当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelObjectNamespaceEntry* currentObjectNamespaceEntry() const;

    // currentAtomEntry：
    // - 作用：返回原子表当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelAtomEntry* currentAtomEntry() const;

    // currentSsdtEntry：
    // - 作用：返回 SSDT 表当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelSsdtEntry* currentSsdtEntry() const;

    // currentDynDataFieldEntry：
    // - 作用：返回动态偏移字段表当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelDynDataFieldEntry* currentDynDataFieldEntry() const;

    // currentDriverCapabilityEntry：
    // - 作用：返回能力矩阵当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelDriverCapabilityEntry* currentDriverCapabilityEntry() const;

    // currentCallbackEnumEntry：
    // - 作用：返回回调遍历当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelCallbackEnumEntry* currentCallbackEnumEntry() const;

    // currentShadowSsdtEntry：
    // - 作用：返回 SSSDT 当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelSsdtEntry* currentShadowSsdtEntry() const;

    // currentInlineHookEntry：
    // - 作用：返回 Inline Hook 当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelInlineHookEntry* currentInlineHookEntry() const;

    // currentIatEatHookEntry：
    // - 作用：返回 IAT/EAT 当前选中项。
    // - 返回：命中返回指针；否则 nullptr。
    const KernelIatEatHookEntry* currentIatEatHookEntry() const;

private:
    // ==================== 根级控件 ====================
    QVBoxLayout* m_rootLayout = nullptr; // m_rootLayout：KernelDock 根布局。
    QTabWidget* m_tabWidget = nullptr;   // m_tabWidget：顶层 Tab 容器。
    QProgressBar* m_tabInitializingProgressBar = nullptr; // m_tabInitializingProgressBar：Tab 初始化顶部不确定进度条。
    QLabel* m_tabInitializingStatusLabel = nullptr;       // m_tabInitializingStatusLabel：Tab 初始化状态提示文字。
    int m_objectNamespaceTabIndex = -1;  // m_objectNamespaceTabIndex：对象命名空间页签索引。
    int m_atomTabIndex = -1;             // m_atomTabIndex：原子表页签索引。
    int m_ioManagementTabIndex = -1;     // m_ioManagementTabIndex：I/O 管理顶层页签索引。
    int m_ioSsdtTabIndex = -1;           // m_ioSsdtTabIndex：I/O 管理内部 SSDT 子页索引。
    int m_ioShadowSsdtTabIndex = -1;     // m_ioShadowSsdtTabIndex：内部 ShadowSSDT 子页索引。
    int m_ioIdtTabIndex = -1;            // m_ioIdtTabIndex：内部 IDT 子页索引。
    int m_ioGdtTabIndex = -1;            // m_ioGdtTabIndex：内部 GDT 子页索引。
    int m_ioIoctlTabIndex = -1;          // m_ioIoctlTabIndex：内部 IOCTLS 解码器子页索引。
    int m_dynDataTabIndex = -1;          // m_dynDataTabIndex：自身驱动内部 DynData 总览页索引。
    int m_dynDataProfileTabIndex = -1;   // m_dynDataProfileTabIndex：自身驱动内部 PDB Profile 页索引。
    int m_driverStatusTabIndex = -1;      // m_driverStatusTabIndex：自身驱动内部状态页索引。
    int m_ntQueryTabIndex = -1;          // m_ntQueryTabIndex：历史 NtQuery 页签索引。
    int m_kernelAuditTabIndex = -1;       // m_kernelAuditTabIndex：内核审计与回调顶层页索引。
    int m_callbackTabIndex = -1;         // m_callbackTabIndex：审计内部驱动回调页索引。
    int m_callbackEnumTabIndex = -1;     // m_callbackEnumTabIndex：审计内部回调遍历页索引。
    int m_inlineHookTabIndex = -1;       // m_inlineHookTabIndex：审计内部 Inline Hook 页索引。
    int m_iatEatHookTabIndex = -1;       // m_iatEatHookTabIndex：审计内部 IAT/EAT 页索引。
    int m_hvmTabIndex = -1;              // m_hvmTabIndex：VT-x/EPT 生命周期与证据页签索引。
    int m_slatIommuTabIndex = -1;        // m_slatIommuTabIndex：SLAT/IOMMU 只读取证页签索引。
    int m_textIntegrityTabIndex = -1;    // m_textIntegrityTabIndex：代码完整性只读扫描页签索引。
    int m_vbsPostureTabIndex = -1;       // m_vbsPostureTabIndex：VBS/HVCI 姿态页签索引。
    int m_timerDpcTabIndex = -1;          // m_timerDpcTabIndex：KTIMER/DPC 页签索引。
    int m_crossViewTabIndex = -1;        // m_crossViewTabIndex：CID/交叉视图页签索引。
    int m_ipcTabIndex = -1;              // m_ipcTabIndex：IPC/NamedPipe/ALPC 页签索引。
    int m_workQueueThreadTabIndex = -1;   // m_workQueueThreadTabIndex：工作队列线程审计页索引。
    int m_knowledgeTabIndex = -1;         // m_knowledgeTabIndex：71 专题内核知识中心页签索引。
    KernelKnowledgeTab* m_knowledgeTab = nullptr; // m_knowledgeTab：可检索知识中心实例。
    bool m_objectNamespaceTabInitialized = false; // m_objectNamespaceTabInitialized：对象命名空间页是否已初始化。
    bool m_atomTabInitialized = false;            // m_atomTabInitialized：原子表页是否已初始化。
    bool m_ssdtTabInitialized = false;            // m_ssdtTabInitialized：SSDT 页是否已初始化。
    bool m_dynDataTabInitialized = false;          // m_dynDataTabInitialized：动态偏移页是否已初始化。
    bool m_driverStatusTabInitialized = false;     // m_driverStatusTabInitialized：驱动状态页是否已初始化。
    bool m_selfDriverRefreshCheckPending = false;  // m_selfDriverRefreshCheckPending：可见性延迟复核是否已排队。
    bool m_dynDataFirstRefreshTriggered = false;   // m_dynDataFirstRefreshTriggered：动态偏移是否已自动首刷。
    bool m_driverStatusFirstRefreshTriggered = false; // m_driverStatusFirstRefreshTriggered：驱动状态是否已自动首刷。
    bool m_ntQueryTabInitialized = false;         // m_ntQueryTabInitialized：历史 NtQuery 页是否已初始化。
    bool m_callbackTabInitialized = false;        // m_callbackTabInitialized：驱动回调页是否已初始化。
    bool m_callbackEnumTabInitialized = false;    // m_callbackEnumTabInitialized：回调遍历页是否已初始化。
    bool m_shadowSsdtTabInitialized = false;      // m_shadowSsdtTabInitialized：SSSDT 页是否已初始化。
    bool m_inlineHookTabInitialized = false;      // m_inlineHookTabInitialized：Inline Hook 页是否已初始化。
    bool m_iatEatHookTabInitialized = false;      // m_iatEatHookTabInitialized：IAT/EAT 页是否已初始化。
    bool m_timerDpcTabInitialized = false;        // m_timerDpcTabInitialized：KTIMER/DPC 页是否已初始化。
    bool m_crossViewTabInitialized = false;       // m_crossViewTabInitialized：CID 页是否已初始化。
    bool m_ipcTabInitialized = false;             // m_ipcTabInitialized：IPC 页是否已初始化。

    // ==================== 对象命名空间页 ====================
    QWidget* m_objectNamespacePage = nullptr;                  // m_objectNamespacePage：对象命名空间页容器。
    QVBoxLayout* m_objectNamespaceLayout = nullptr;            // m_objectNamespaceLayout：对象命名空间页布局。
    QTabWidget* m_objectNamespaceInnerTabWidget = nullptr;      // m_objectNamespaceInnerTabWidget：对象命名空间内部能力页签。
    QWidget* m_objectNamespaceOverviewPage = nullptr;           // m_objectNamespaceOverviewPage：对象命名空间总览页。
    QVBoxLayout* m_objectNamespaceOverviewLayout = nullptr;     // m_objectNamespaceOverviewLayout：对象命名空间总览页布局。
    QHBoxLayout* m_objectNamespaceToolLayout = nullptr;        // m_objectNamespaceToolLayout：对象命名空间工具栏布局。
    QPushButton* m_refreshObjectNamespaceButton = nullptr;     // m_refreshObjectNamespaceButton：对象命名空间刷新按钮。
    QLineEdit* m_objectNamespaceFilterEdit = nullptr;          // m_objectNamespaceFilterEdit：对象命名空间关键词过滤输入框。
    QLabel* m_objectNamespaceStatusLabel = nullptr;            // m_objectNamespaceStatusLabel：对象命名空间状态文本。
    QTreeWidget* m_objectNamespaceTree = nullptr;              // m_objectNamespaceTree：对象命名空间树（文件管理器式结构）。
    QTableWidget* m_objectNamespacePropertyTable = nullptr;    // m_objectNamespacePropertyTable：对象属性项/值表。
    CodeEditorWidget* m_objectNamespaceDetailEditor = nullptr; // m_objectNamespaceDetailEditor：对象命名空间详情编辑器（只读）。

    // ==================== 原子表页 ====================
    QWidget* m_atomPage = nullptr;                  // m_atomPage：原子表页容器。
    QVBoxLayout* m_atomLayout = nullptr;            // m_atomLayout：原子表页布局。
    QHBoxLayout* m_atomToolLayout = nullptr;        // m_atomToolLayout：原子表工具栏布局。
    QPushButton* m_refreshAtomButton = nullptr;     // m_refreshAtomButton：原子表刷新按钮。
    QLineEdit* m_atomFilterEdit = nullptr;          // m_atomFilterEdit：原子关键词过滤输入框。
    QLabel* m_atomStatusLabel = nullptr;            // m_atomStatusLabel：原子表状态文本。
    QTableWidget* m_atomTable = nullptr;            // m_atomTable：原子结果表。
    CodeEditorWidget* m_atomDetailEditor = nullptr; // m_atomDetailEditor：原子详情编辑器（只读）。

    // ==================== 历史 NtQuery 页 ====================
    QWidget* m_ntQueryPage = nullptr;                  // m_ntQueryPage：历史 NtQuery 页容器。
    QVBoxLayout* m_ntQueryLayout = nullptr;            // m_ntQueryLayout：历史 NtQuery 页布局。
    QHBoxLayout* m_ntQueryToolLayout = nullptr;        // m_ntQueryToolLayout：历史 NtQuery 工具栏布局。
    QPushButton* m_refreshNtQueryButton = nullptr;     // m_refreshNtQueryButton：历史 NtQuery 刷新按钮。
    QLabel* m_ntQueryStatusLabel = nullptr;            // m_ntQueryStatusLabel：历史 NtQuery 状态文本。
    QTableWidget* m_ntQueryTable = nullptr;            // m_ntQueryTable：历史 NtQuery 结果表。
    CodeEditorWidget* m_ntQueryDetailEditor = nullptr; // m_ntQueryDetailEditor：历史 NtQuery 详情编辑器（只读）。

    // ==================== I/O 管理聚合页 ====================
    QWidget* m_ioManagementPage = nullptr;              // m_ioManagementPage：I/O 管理顶层页容器。
    QVBoxLayout* m_ioManagementLayout = nullptr;         // m_ioManagementLayout：I/O 管理根布局。
    QTabWidget* m_ioManagementInnerTabWidget = nullptr;  // m_ioManagementInnerTabWidget：横向五子页容器。

    // ==================== 内核审计与回调聚合页 ====================
    QWidget* m_kernelAuditPage = nullptr;                // m_kernelAuditPage：四项审计业务的顶层容器。
    QVBoxLayout* m_kernelAuditLayout = nullptr;           // m_kernelAuditLayout：聚合页根布局。
    QTabWidget* m_kernelAuditInnerTabWidget = nullptr;    // m_kernelAuditInnerTabWidget：Inline/IAT/回调二级页。

    // ==================== Ksword自身驱动迁移容器 ====================
    QWidget* m_selfDriverPage = nullptr;                 // m_selfDriverPage：交给 DriverDock 展示的容器。
    QVBoxLayout* m_selfDriverLayout = nullptr;            // m_selfDriverLayout：自身驱动容器布局。
    QTabWidget* m_selfDriverInnerTabWidget = nullptr;     // m_selfDriverInnerTabWidget：动态偏移/状态二级页。

    // ==================== SSDT 子页 ====================
    QWidget* m_ssdtPage = nullptr;                     // m_ssdtPage：SSDT 页容器。
    QVBoxLayout* m_ssdtLayout = nullptr;               // m_ssdtLayout：SSDT 页布局。
    QHBoxLayout* m_ssdtToolLayout = nullptr;           // m_ssdtToolLayout：SSDT 工具栏布局。
    QPushButton* m_refreshSsdtButton = nullptr;        // m_refreshSsdtButton：SSDT 刷新按钮。
    QPushButton* m_restoreSsdtButton = nullptr;        // m_restoreSsdtButton：按验证磁盘基线恢复槽位。
    QLineEdit* m_ssdtFilterEdit = nullptr;             // m_ssdtFilterEdit：SSDT 筛选输入框。
    QLabel* m_ssdtStatusLabel = nullptr;               // m_ssdtStatusLabel：SSDT 状态文本。
    QTableWidget* m_ssdtTable = nullptr;               // m_ssdtTable：SSDT 结果表。
    CodeEditorWidget* m_ssdtDetailEditor = nullptr;    // m_ssdtDetailEditor：SSDT 详情编辑器（只读）。

    // ==================== ShadowSSDT 子页 ====================
    QWidget* m_shadowSsdtPage = nullptr;               // m_shadowSsdtPage：SSSDT 页容器。
    QVBoxLayout* m_shadowSsdtLayout = nullptr;         // m_shadowSsdtLayout：SSSDT 页布局。
    QHBoxLayout* m_shadowSsdtToolLayout = nullptr;     // m_shadowSsdtToolLayout：SSSDT 工具栏布局。
    QPushButton* m_refreshShadowSsdtButton = nullptr;  // m_refreshShadowSsdtButton：SSSDT 刷新按钮。
    QLineEdit* m_shadowSsdtFilterEdit = nullptr;       // m_shadowSsdtFilterEdit：SSSDT 筛选框。
    QLabel* m_shadowSsdtStatusLabel = nullptr;         // m_shadowSsdtStatusLabel：SSSDT 状态文本。
    QTableWidget* m_shadowSsdtTable = nullptr;         // m_shadowSsdtTable：SSSDT 表格。
    CodeEditorWidget* m_shadowSsdtDetailEditor = nullptr; // m_shadowSsdtDetailEditor：SSSDT 详情文本框。

    // ==================== Inline Hook 页 ====================
    QWidget* m_inlineHookPage = nullptr;                    // m_inlineHookPage：Inline Hook 页容器。
    QVBoxLayout* m_inlineHookLayout = nullptr;              // m_inlineHookLayout：Inline Hook 页布局。
    QHBoxLayout* m_inlineHookToolLayout = nullptr;          // m_inlineHookToolLayout：Inline Hook 工具栏布局。
    QPushButton* m_refreshInlineHookButton = nullptr;       // m_refreshInlineHookButton：刷新按钮。
    QPushButton* m_patchInlineHookButton = nullptr;         // m_patchInlineHookButton：NOP 摘除按钮。
    QLineEdit* m_inlineHookFilterEdit = nullptr;            // m_inlineHookFilterEdit：本地筛选框。
    QLineEdit* m_inlineHookModuleEdit = nullptr;            // m_inlineHookModuleEdit：R0 模块过滤框。
    QComboBox* m_inlineHookIncludeCombo = nullptr;          // m_inlineHookIncludeCombo：扫描范围选项。
    QLabel* m_inlineHookStatusLabel = nullptr;              // m_inlineHookStatusLabel：状态文本。
    QTableWidget* m_inlineHookTable = nullptr;              // m_inlineHookTable：Inline Hook 表格。
    CodeEditorWidget* m_inlineHookDetailEditor = nullptr;   // m_inlineHookDetailEditor：详情文本框。

    // ==================== IAT/EAT Hook 页 ====================
    QWidget* m_iatEatHookPage = nullptr;                    // m_iatEatHookPage：IAT/EAT 页容器。
    QWidget* m_timerDpcPage = nullptr;                       // m_timerDpcPage：KTIMER/DPC 页容器。
    QWidget* m_crossViewPage = nullptr;                    // m_crossViewPage：CID / cross-view 页容器。
    QWidget* m_ipcPage = nullptr;                          // m_ipcPage：IPC / ALPC / NamedPipe 页容器。
    QVBoxLayout* m_iatEatHookLayout = nullptr;              // m_iatEatHookLayout：IAT/EAT 页布局。
    QHBoxLayout* m_iatEatHookToolLayout = nullptr;          // m_iatEatHookToolLayout：IAT/EAT 工具栏布局。
    QPushButton* m_refreshIatEatHookButton = nullptr;       // m_refreshIatEatHookButton：刷新按钮。
    QLineEdit* m_iatEatHookFilterEdit = nullptr;            // m_iatEatHookFilterEdit：本地筛选框。
    QLineEdit* m_iatEatHookModuleEdit = nullptr;            // m_iatEatHookModuleEdit：R0 模块过滤框。
    QComboBox* m_iatEatHookIncludeCombo = nullptr;          // m_iatEatHookIncludeCombo：IAT/EAT 范围选项。
    QLabel* m_iatEatHookStatusLabel = nullptr;              // m_iatEatHookStatusLabel：状态文本。
    QTableWidget* m_iatEatHookTable = nullptr;              // m_iatEatHookTable：IAT/EAT 表格。
    CodeEditorWidget* m_iatEatHookDetailEditor = nullptr;   // m_iatEatHookDetailEditor：详情文本框。

    // ==================== KTIMER/DPC 页 ====================
    QVBoxLayout* m_timerDpcLayout = nullptr;
    QHBoxLayout* m_timerDpcToolLayout = nullptr;
    QPushButton* m_refreshTimerDpcButton = nullptr;
    QLineEdit* m_timerDpcFilterEdit = nullptr;
    QLabel* m_timerDpcStatusLabel = nullptr;
    QTableWidget* m_timerDpcTable = nullptr;
    CodeEditorWidget* m_timerDpcDetailEditor = nullptr;

    // ==================== 动态偏移页 ====================
    QHBoxLayout* m_dynDataToolLayout = nullptr;        // m_dynDataToolLayout：动态偏移工具栏布局。
    QPushButton* m_refreshDynDataButton = nullptr;     // m_refreshDynDataButton：动态偏移刷新按钮。
    QPushButton* m_copyDynDataReportButton = nullptr;  // m_copyDynDataReportButton：复制诊断报告按钮。
    QLineEdit* m_dynDataFilterEdit = nullptr;          // m_dynDataFilterEdit：动态偏移字段筛选输入框。
    QLabel* m_dynDataStatusLabel = nullptr;            // m_dynDataStatusLabel：动态偏移状态文本。
    QTableWidget* m_dynDataSummaryTable = nullptr;     // m_dynDataSummaryTable：动态偏移摘要表。
    QTableWidget* m_dynDataFieldTable = nullptr;       // m_dynDataFieldTable：动态偏移字段表。
    CodeEditorWidget* m_dynDataDetailEditor = nullptr; // m_dynDataDetailEditor：动态偏移详情编辑器（只读）。
    QWidget* m_dynDataOverviewPage = nullptr;          // m_dynDataOverviewPage：动态偏移总览页。
    QVBoxLayout* m_dynDataOverviewLayout = nullptr;    // m_dynDataOverviewLayout：动态偏移总览页布局。
    QWidget* m_dynDataProfilePage = nullptr;           // m_dynDataProfilePage：PDB profile 状态页。
    QVBoxLayout* m_dynDataProfileLayout = nullptr;     // m_dynDataProfileLayout：PDB profile 状态页布局。
    QLabel* m_dynDataProfileStatusLabel = nullptr;     // m_dynDataProfileStatusLabel：PDB profile 状态标签。
    QTableWidget* m_dynDataProfileSummaryTable = nullptr; // m_dynDataProfileSummaryTable：PDB profile 摘要表。
    QTableWidget* m_dynDataV4ItemTable = nullptr; // m_dynDataV4ItemTable：PDB profile v4 accepted item 明细表。
    CodeEditorWidget* m_dynDataProfileDetailEditor = nullptr; // m_dynDataProfileDetailEditor：PDB profile 详情编辑器。

    // ==================== 驱动状态页 ====================
    QWidget* m_driverStatusPage = nullptr;                  // m_driverStatusPage：驱动状态页容器。
    QVBoxLayout* m_driverStatusLayout = nullptr;            // m_driverStatusLayout：驱动状态页布局。
    QHBoxLayout* m_driverStatusToolLayout = nullptr;        // m_driverStatusToolLayout：驱动状态工具栏布局。
    QPushButton* m_refreshDriverStatusButton = nullptr;     // m_refreshDriverStatusButton：刷新统一能力按钮。
    QPushButton* m_copyDriverStatusReportButton = nullptr;  // m_copyDriverStatusReportButton：复制诊断报告按钮。
    QLineEdit* m_driverStatusFilterEdit = nullptr;          // m_driverStatusFilterEdit：能力矩阵筛选输入框。
    QLabel* m_driverStatusLabel = nullptr;                  // m_driverStatusLabel：整体状态文本。
    QTableWidget* m_driverStatusSummaryTable = nullptr;     // m_driverStatusSummaryTable：驱动状态摘要表。
    QTableWidget* m_driverCapabilityTable = nullptr;        // m_driverCapabilityTable：能力矩阵表。
    CodeEditorWidget* m_driverCapabilityDetailEditor = nullptr; // m_driverCapabilityDetailEditor：能力详情编辑器。

    // ==================== 驱动回调页 ====================
    QWidget* m_callbackInterceptPage = nullptr;                     // m_callbackInterceptPage：驱动回调页容器。
    CallbackInterceptController* m_callbackInterceptController = nullptr; // m_callbackInterceptController：驱动回调页控制器。
    QWidget* m_callbackEnumPage = nullptr;                          // m_callbackEnumPage：回调遍历页容器。
    QVBoxLayout* m_callbackEnumLayout = nullptr;                    // m_callbackEnumLayout：回调遍历页布局。
    QHBoxLayout* m_callbackEnumToolLayout = nullptr;                // m_callbackEnumToolLayout：回调遍历工具栏布局。
    QPushButton* m_refreshCallbackEnumButton = nullptr;             // m_refreshCallbackEnumButton：回调遍历刷新按钮。
    QLineEdit* m_callbackEnumFilterEdit = nullptr;                  // m_callbackEnumFilterEdit：回调遍历筛选输入框。
    QLabel* m_callbackEnumStatusLabel = nullptr;                    // m_callbackEnumStatusLabel：回调遍历状态文本。
    QTableWidget* m_callbackEnumTable = nullptr;                    // m_callbackEnumTable：回调遍历表。
    QTreeWidget* m_minifilterCallbackTree = nullptr;                // m_minifilterCallbackTree：Filter -> Pre/Post 回调树。
    CodeEditorWidget* m_callbackEnumDetailEditor = nullptr;         // m_callbackEnumDetailEditor：回调遍历详情文本框。
    QWidget* m_callbackRemoveContentWidget = nullptr;               // m_callbackRemoveContentWidget：嵌入在回调遍历页底部的移除面板容器。
    QVBoxLayout* m_callbackRemoveLayout = nullptr;                  // m_callbackRemoveLayout：回调移除面板内部布局。
    QHBoxLayout* m_callbackRemoveToolLayout = nullptr;              // m_callbackRemoveToolLayout：回调移除工具栏布局。
    QComboBox* m_callbackRemoveTypeCombo = nullptr;                 // m_callbackRemoveTypeCombo：回调类型下拉框。
    QLineEdit* m_callbackRemoveAddressEdit = nullptr;               // m_callbackRemoveAddressEdit：回调地址输入框。
    QPushButton* m_callbackRemoveButton = nullptr;                  // m_callbackRemoveButton：执行移除按钮。
    QLabel* m_callbackRemoveStatusLabel = nullptr;                  // m_callbackRemoveStatusLabel：状态文本。

    // ==================== 数据缓存 ====================
    std::vector<KernelObjectNamespaceEntry> m_objectNamespaceRows; // m_objectNamespaceRows：对象命名空间快照行。
    std::vector<KernelAtomEntry> m_atomRows;                       // m_atomRows：原子快照行。
    std::vector<KernelNtQueryResultEntry> m_ntQueryResults;        // m_ntQueryResults：历史 NtQuery 快照行。
    std::vector<KernelSsdtEntry> m_ssdtRows;                       // m_ssdtRows：SSDT 快照行。
    KernelDynDataSummary m_dynDataSummary;                         // m_dynDataSummary：动态偏移摘要快照。
    std::vector<KernelDynDataFieldEntry> m_dynDataRows;            // m_dynDataRows：动态偏移字段快照行。
    std::vector<KernelDynDataV4ItemEntry> m_dynDataV4ItemRows;      // m_dynDataV4ItemRows：v4 accepted item 快照行。
    KernelDriverStatusSummary m_driverStatusSummary;               // m_driverStatusSummary：统一驱动状态摘要快照。
    std::vector<KernelDriverCapabilityEntry> m_driverCapabilityRows; // m_driverCapabilityRows：能力矩阵快照行。
    std::vector<KernelCallbackEnumEntry> m_callbackEnumRows;        // m_callbackEnumRows：回调遍历快照行。
    std::vector<KernelSsdtEntry> m_shadowSsdtRows;                  // m_shadowSsdtRows：SSSDT 快照行。
    std::vector<KernelInlineHookEntry> m_inlineHookRows;            // m_inlineHookRows：Inline Hook 快照行。
    std::vector<KernelIatEatHookEntry> m_iatEatHookRows;            // m_iatEatHookRows：IAT/EAT 快照行。
    std::vector<KernelTimerDpcEntry> m_timerDpcRows;                 // m_timerDpcRows：KTIMER/DPC 快照行。

    // ==================== 刷新状态 ====================
    std::atomic_bool m_objectNamespaceRefreshRunning{ false }; // m_objectNamespaceRefreshRunning：对象命名空间刷新状态。
    std::atomic_bool m_atomRefreshRunning{ false };            // m_atomRefreshRunning：原子表刷新状态。
    std::atomic_bool m_ntQueryRefreshRunning{ false };         // m_ntQueryRefreshRunning：历史 NtQuery 刷新状态。
    std::atomic_bool m_ssdtRefreshRunning{ false };            // m_ssdtRefreshRunning：SSDT 刷新状态。
    std::atomic_bool m_dynDataRefreshRunning{ false };         // m_dynDataRefreshRunning：动态偏移刷新状态。
    std::atomic_bool m_driverStatusRefreshRunning{ false };    // m_driverStatusRefreshRunning：驱动状态刷新状态。
    std::atomic_bool m_callbackEnumRefreshRunning{ false };    // m_callbackEnumRefreshRunning：回调遍历刷新状态。
    std::atomic_bool m_shadowSsdtRefreshRunning{ false };      // m_shadowSsdtRefreshRunning：SSSDT 刷新状态。
    std::atomic_bool m_inlineHookRefreshRunning{ false };      // m_inlineHookRefreshRunning：Inline Hook 刷新状态。
    std::atomic_bool m_iatEatHookRefreshRunning{ false };      // m_iatEatHookRefreshRunning：IAT/EAT 刷新状态。
    std::atomic_bool m_timerDpcRefreshRunning{ false };        // m_timerDpcRefreshRunning：KTIMER/DPC 刷新状态。
    std::atomic_bool m_timerDpcRefreshAfterDynData{ false };   // m_timerDpcRefreshAfterDynData：DynData 完成后自动重试 Timer/DPC。
};
