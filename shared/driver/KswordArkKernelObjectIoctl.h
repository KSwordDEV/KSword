#pragma once

#include "KswordArkAlpcIoctl.h"

// ============================================================
// KswordArkKernelObjectIoctl.h
// 作用：
// - 定义 CID table、Kernel Object 摘要、IPC 摘要的只读 R3/R0 协议；
// - 当前协议只返回审计证据和降级状态，不提供 patch/delete/unlink/remove；
// - 所有 IOCTL 均使用 METHOD_BUFFERED + FILE_ANY_ACCESS。
// ============================================================

#define KSWORD_ARK_KERNEL_OBJECT_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_CID_TABLE             0x878UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_KERNEL_OBJECT_SUMMARY 0x879UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_IPC_SUMMARY          0x87AUL
#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_OBJECT_TYPE_TABLE     0x87BUL
#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_OBJECT_TYPE_PROCEDURES 0x87CUL

#define IOCTL_KSWORD_ARK_ENUM_CID_TABLE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUM_CID_TABLE, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_KERNEL_OBJECT_SUMMARY, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_IPC_SUMMARY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_IPC_SUMMARY, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUM_OBJECT_TYPE_TABLE, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUM_OBJECT_TYPE_PROCEDURES, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_PROCESS 0x00000001UL
#define KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_THREAD  0x00000002UL
#define KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_PROCESS | KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_THREAD)

#define KSWORD_ARK_CID_OBJECT_KIND_UNKNOWN 0UL
#define KSWORD_ARK_CID_OBJECT_KIND_PROCESS 1UL
#define KSWORD_ARK_CID_OBJECT_KIND_THREAD  2UL

#define KSWORD_ARK_CID_ENTRY_FLAG_DANGLING      0x00000001UL
#define KSWORD_ARK_CID_ENTRY_FLAG_TYPE_MISMATCH 0x00000002UL
#define KSWORD_ARK_CID_ENTRY_FLAG_REFERENCED    0x00000004UL

#define KSWORD_ARK_CID_ENUM_STATUS_UNAVAILABLE          0UL
#define KSWORD_ARK_CID_ENUM_STATUS_OK                   1UL
#define KSWORD_ARK_CID_ENUM_STATUS_PARTIAL              2UL
#define KSWORD_ARK_CID_ENUM_STATUS_DYNDATA_MISSING      3UL
#define KSWORD_ARK_CID_ENUM_STATUS_PSPCID_UNAVAILABLE   4UL
#define KSWORD_ARK_CID_ENUM_STATUS_TYPE_UNAVAILABLE     5UL
#define KSWORD_ARK_CID_ENUM_STATUS_BUFFER_TRUNCATED     6UL
#define KSWORD_ARK_CID_ENUM_STATUS_BUDGET_EXHAUSTED     7UL

#define KSWORD_ARK_OBJECT_SUMMARY_FLAG_BY_CID           0x00000001UL
#define KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_TYPE     0x00000002UL
#define KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_COUNTERS 0x00000004UL
#define KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_OBJECT_SUMMARY_FLAG_BY_CID | \
     KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_TYPE | \
     KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_COUNTERS)

#define KSWORD_ARK_OBJECT_SUMMARY_FIELD_OBJECT_PRESENT        0x00000001UL
#define KSWORD_ARK_OBJECT_SUMMARY_FIELD_TYPE_PRESENT          0x00000002UL
#define KSWORD_ARK_OBJECT_SUMMARY_FIELD_TYPE_NAME_PRESENT     0x00000004UL
#define KSWORD_ARK_OBJECT_SUMMARY_FIELD_TYPE_INDEX_PRESENT    0x00000008UL
#define KSWORD_ARK_OBJECT_SUMMARY_FIELD_POINTER_COUNT_PRESENT 0x00000010UL
#define KSWORD_ARK_OBJECT_SUMMARY_FIELD_HANDLE_COUNT_PRESENT  0x00000020UL

#define KSWORD_ARK_OBJECT_HEADER_STATUS_UNAVAILABLE       0UL
#define KSWORD_ARK_OBJECT_HEADER_STATUS_PROFILE_MISSING   1UL
#define KSWORD_ARK_OBJECT_HEADER_STATUS_PARTIAL_PROFILE   2UL
#define KSWORD_ARK_OBJECT_HEADER_STATUS_AVAILABLE         3UL

#define KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNAVAILABLE           0UL
#define KSWORD_ARK_OBJECT_SUMMARY_STATUS_OK                    1UL
#define KSWORD_ARK_OBJECT_SUMMARY_STATUS_PARTIAL               2UL
#define KSWORD_ARK_OBJECT_SUMMARY_STATUS_UNSUPPORTED_TARGET    3UL
#define KSWORD_ARK_OBJECT_SUMMARY_STATUS_LOOKUP_FAILED         4UL
#define KSWORD_ARK_OBJECT_SUMMARY_STATUS_TYPE_QUERY_FAILED     5UL
#define KSWORD_ARK_OBJECT_SUMMARY_STATUS_COUNTERS_UNAVAILABLE  6UL

#define KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALPC     0x00000001UL
#define KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_PIPE     0x00000002UL
#define KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_MAILSLOT 0x00000004UL
#define KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALPC | \
     KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_PIPE | \
     KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_MAILSLOT)

#define KSWORD_ARK_IPC_SUMMARY_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_IPC_SUMMARY_STATUS_OK          1UL
#define KSWORD_ARK_IPC_SUMMARY_STATUS_PARTIAL     2UL
#define KSWORD_ARK_IPC_SUMMARY_STATUS_STUB        3UL
#define KSWORD_ARK_IPC_SUMMARY_STATUS_FAILED      4UL

#define KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS 96U
#define KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS 160U
#define KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE 0xFFFFFFFFUL

#define KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES 0x00000001UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX 0x00000002UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_NAMES | \
     KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_VALIDATE_INDEX)

#define KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TRUNCATED 0x00000001UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_DYNDATA_ACTIVE 0x00000002UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_TABLE_VALIDATED 0x00000004UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_SNAPSHOT_HASH_VALID 0x00000008UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_RESPONSE_FLAG_NAMESPACE_NAMES 0x00000010UL

#define KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_UNAVAILABLE 0UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_OK 1UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_PARTIAL 2UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_DYNDATA_MISSING 3UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_NOT_FOUND 4UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_TABLE_AMBIGUOUS 5UL
#define KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_BUFFER_TRUNCATED 6UL

#define KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_OK 1UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_PARTIAL 2UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_INDEX_MISMATCH 3UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_STATUS_READ_FAILED 4UL

#define KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_ADDRESS 0x00000001UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_NAME 0x00000002UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX 0x00000004UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_INDEX_MATCH 0x00000008UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_KNOWN_TYPE 0x00000010UL
#define KSWORD_ARK_OBJECT_TYPE_ENTRY_FIELD_IDENTITY_HASH 0x00000020UL

#define KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS 256UL

typedef struct _KSWORD_ARK_ENUM_CID_TABLE_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long maxEntries;
    unsigned long maxVisitCount;
    unsigned long startCid;
    unsigned long endCid;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_ENUM_CID_TABLE_REQUEST;

typedef struct _KSWORD_ARK_CID_TABLE_ENTRY
{
    unsigned long cidValue;
    unsigned long handleIndex;
    unsigned long expectedObjectKind;
    unsigned long lookupStatus;
    unsigned long flags;
    long referenceStatus;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long objectAddress;
} KSWORD_ARK_CID_TABLE_ENTRY;

typedef struct _KSWORD_ARK_ENUM_CID_TABLE_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long flags;
    unsigned long visitedCount;
    unsigned long maxVisitCount;
    long lastStatus;
    unsigned long reserved;
    unsigned long long pspCidTableAddress;
    unsigned long long dynDataCapabilityMask;
    unsigned long htTableCodeOffset;
    unsigned long hteLowValueOffset;
    KSWORD_ARK_CID_TABLE_ENTRY entries[1];
} KSWORD_ARK_ENUM_CID_TABLE_RESPONSE;

typedef struct _KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long targetKind;
    unsigned long cidValue;
    unsigned long long expectedObjectAddress;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_REQUEST;

typedef struct _KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long startIndex;
    unsigned long maxEntries;
} KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_REQUEST;

typedef struct _KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY
{
    unsigned long size;
    unsigned long typeIndex;
    unsigned long status;
    unsigned long fieldFlags;
    long lastStatus;
    unsigned long reserved;
    unsigned long long objectTypeAddress;
    unsigned long long identityHash;
    wchar_t typeName[KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS];
} KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY;

typedef struct _KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long flags;
    long lastStatus;
    unsigned long nextIndex;
    unsigned long long tableAddress;
    unsigned long long dynDataCapabilityMask;
    unsigned long long snapshotHash;
    unsigned long otNameOffset;
    unsigned long otIndexOffset;
    unsigned long reserved0;
    unsigned long reserved1;
    KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY entries[1];
} KSWORD_ARK_ENUM_OBJECT_TYPE_TABLE_RESPONSE;

typedef struct _KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long fieldFlags;
    unsigned long targetKind;
    unsigned long cidValue;
    long lookupStatus;
    long typeStatus;
    long counterStatus;
    unsigned long objectHeaderStatus;
    unsigned long typeIndex;
    unsigned long pointerCount;
    unsigned long handleCount;
    unsigned long reserved0;
    unsigned long long objectAddress;
    unsigned long long expectedObjectAddress;
    unsigned long long objectTypeAddress;
    unsigned long long dynDataCapabilityMask;
    unsigned long otNameOffset;
    unsigned long otIndexOffset;
    wchar_t typeName[KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS];
    wchar_t detail[KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS];
} KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE;

typedef struct _KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long processId;
    unsigned long reserved0;
    unsigned long long handleValue;
    unsigned long maxEntries;
    unsigned long reserved1;
} KSWORD_ARK_QUERY_IPC_SUMMARY_REQUEST;

typedef struct _KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long fieldFlags;
    unsigned long processId;
    unsigned long alpcStatus;
    unsigned long namedPipeStatus;
    unsigned long mailslotStatus;
    long lastStatus;
    unsigned long reserved0;
    unsigned long long handleValue;
    unsigned long long alpcObjectAddress;
    unsigned long long dynDataCapabilityMask;
    wchar_t alpcTypeName[KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS];
    wchar_t detail[KSWORD_ARK_KERNEL_OBJECT_DETAIL_CHARS];
} KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE;

/*
 * ObjectType 方法指针完整性（issue #200）。
 *
 * OBJECT_TYPE 里嵌着的初始化器有八个方法指针（Dump/Open/Close/Delete/Parse/
 * Security/QueryName/OkayToClose）。改其中任何一个就能截获对应类型对象上的每一次
 * 打开/解析/关闭，而对象类型表（ObTypeIndexTable）本身、类型对象地址都毫无变化，
 * 所以只核对一级地址的检测看不到它。
 *
 * 这些成员的偏移不在任何 DynData 表里，本协议也不假设它：R0 用运行时自验证
 * 去发现方法指针块的起点（layoutState），验证不过就如实上报 UNVERIFIED，
 * 绝不在布局没把握时给出"被劫持"的结论。
 */
#define KSWORD_ARK_OBJECT_TYPE_PROCEDURES_PROTOCOL_VERSION 1UL

// 方法种类，同时也是 entry.procedureKind 的取值。
#define KSWORD_ARK_OBJTYPE_PROC_DUMP           0UL
#define KSWORD_ARK_OBJTYPE_PROC_OPEN           1UL
#define KSWORD_ARK_OBJTYPE_PROC_CLOSE          2UL
#define KSWORD_ARK_OBJTYPE_PROC_DELETE         3UL
#define KSWORD_ARK_OBJTYPE_PROC_PARSE          4UL
#define KSWORD_ARK_OBJTYPE_PROC_SECURITY       5UL
#define KSWORD_ARK_OBJTYPE_PROC_QUERY_NAME     6UL
#define KSWORD_ARK_OBJTYPE_PROC_OKAY_TO_CLOSE  7UL
#define KSWORD_ARK_OBJTYPE_PROC_COUNT          8UL

// 方法指针块布局的自验证结论（response.layoutState）。
#define KSWORD_ARK_OBJTYPE_LAYOUT_UNAVAILABLE  0UL  // 连类型表都没定位到。
#define KSWORD_ARK_OBJTYPE_LAYOUT_VALIDATED    1UL  // 多数核心类型的整块指针都通过归属核对。
#define KSWORD_ARK_OBJTYPE_LAYOUT_UNVERIFIED   2UL  // 找到候选但证据不足，行仅供参考。

// response.reserved0 低 32 位 = layoutReason：布局没通过自验证时"为什么没通过"，
// 让人别去错误的方向查（这条链路不依赖 DynData，也不依赖任何导出符号）。
#define KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NONE               0UL
#define KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NO_MODULE_SNAPSHOT 1UL  // 没取到已加载模块快照，无法归属任何指针。
#define KSWORD_ARK_OBJTYPE_LAYOUT_REASON_TOO_FEW_TYPES      2UL  // 能读到窗口的对象类型太少，统计没有意义。
#define KSWORD_ARK_OBJTYPE_LAYOUT_REASON_NO_DOMINANT_ANCHOR 3UL  // 没有哪个偏移上出现"多个类型共享的 nt 内指针"这一唯一优势解。
#define KSWORD_ARK_OBJTYPE_LAYOUT_REASON_BLOCK_SHAPE_FAILED 4UL  // 锚点找到了，但八槽块的形状没通过全类型一致性核对。
#define KSWORD_ARK_OBJTYPE_LAYOUT_REASON_OUT_OF_MEMORY      5UL

// response.flags：有对象类型的表槽读取失败而被跳过（结果是部分的，不能当成"全部干净"）。
#define KSWORD_ARK_OBJTYPE_RESPONSE_FLAG_SKIPPED_TYPES 0x00010000UL

// entry.entryFlags
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_NULL_POINTER   0x00000001UL  // 指针为空（合法：很多类型不实现该方法）。
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_MODULE      0x00000002UL  // 落在某个已加载模块内。
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_IN_CORE_KERNEL 0x00000004UL  // 该模块是 ntoskrnl / hal。
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_EXEC_SECTION   0x00000008UL  // 落在该模块的可执行节。
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_CORE_TYPE      0x00000010UL  // 该类型是 ntoskrnl 自己创建的核心类型。
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_DETOUR         0x00000020UL  // 预留，本版本 R0 未实现入口跳板检查，恒为 0；UI 不得声称做过该检查。
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_READ_FAILED    0x00000040UL  // 指针槽读取失败。
// 该行所属的对象类型有硬判据能判"隐藏行为"：核心类型（地址范围判据）本就有；非核心类型
// 只在同一类型里 >=3 个槽落在 ntoskrnl 可执行节内时才有——这时单槽被劫持会让 ntoskrnl 槽
// 降到 2 个、异常槽变成 1 个，触发"类型内一致性"判据（见 KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK
// 在非核心类型上的置位条件）。没有这个标志不代表"干净"，只代表这一类型本版本给不出硬判据，
// 例如同一类型两个以上槽同时被劫持、或该类型原本就只有 0-2 个 ntoskrnl 槽。
#define KSWORD_ARK_OBJTYPE_ENTRY_FLAG_TYPE_JUDGED    0x00000080UL

typedef struct _KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long startIndex;   // 续读起点：上一页响应的 nextIndex（\ObjectTypes 枚举序号）。
    unsigned long maxEntries;   // 0 = 用驱动默认上限。
} KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_REQUEST;

typedef struct _KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY
{
    unsigned long size;
    unsigned long typeIndex;        // \ObjectTypes 目录的枚举序号（不是 ObTypeIndexTable 槽位，也不是 OBJECT_TYPE.Index）。
    unsigned long procedureKind;    // KSWORD_ARK_OBJTYPE_PROC_*。
    unsigned long riskFlags;        // KSWORD_ARK_DRIVER_INTEGRITY_RISK_*，R3 据此高亮。
    unsigned long entryFlags;       // KSWORD_ARK_OBJTYPE_ENTRY_FLAG_*。
    unsigned long ownerModuleSize;
    long lastStatus;
    unsigned long reserved;
    unsigned long long objectTypeAddress;
    unsigned long long slotAddress;          // OBJECT_TYPE 内该指针槽的地址。
    unsigned long long targetAddress;        // 指针值。
    unsigned long long ownerModuleBase;
    unsigned long long detourTargetAddress;  // 入口跳板的最终落点；无跳板为 0。
    wchar_t typeName[KSWORD_ARK_KERNEL_OBJECT_TYPE_NAME_CHARS];
    wchar_t ownerModule[64];
    wchar_t sectionName[16];
} KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY;

typedef struct _KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_RESPONSE
{
    unsigned long version;
    unsigned long status;           // 复用 KSWORD_ARK_OBJECT_TYPE_TABLE_STATUS_* 语义。
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long flags;
    long lastStatus;
    unsigned long nextIndex;
    unsigned long layoutState;      // KSWORD_ARK_OBJTYPE_LAYOUT_*。
    unsigned long procedureBlockOffset;  // 方法指针块相对 OBJECT_TYPE 的偏移；未验证为 0。
    unsigned long layoutAnchorTypes;     // 参与统计的对象类型数（能读到窗口的类型）。
    unsigned long layoutAnchorAgree;     // 锚点偏移上"共享同一个 nt 内指针"的类型数（众数出现次数）。
    unsigned long long tableAddress;     // 恒为 0：本查询不经过 ObTypeIndexTable。
    unsigned long long reserved0;        // 低 32 位 = layoutReason（KSWORD_ARK_OBJTYPE_LAYOUT_REASON_*）。
    KSWORD_ARK_OBJECT_TYPE_PROCEDURE_ENTRY entries[1];
} KSWORD_ARK_ENUM_OBJECT_TYPE_PROCEDURES_RESPONSE;
