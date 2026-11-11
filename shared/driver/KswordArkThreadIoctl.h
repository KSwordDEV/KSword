#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkThreadIoctl.h
// 作用：
// - 定义 R3/R0 线程扩展枚举协议；
// - 线程基础列表仍可由 R3 NtQuerySystemInformation 提供；
// - KTHREAD 栈边界和 I/O counter 由本协议按 DynData capability 补齐。
// ============================================================

#define KSWORD_ARK_THREAD_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_THREAD 0x80B
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_CROSSVIEW 0x837UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_DETAIL 0x83DUL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_RUNTIME_FIELDS 0x83FUL
#define KSWORD_ARK_IOCTL_FUNCTION_TERMINATE_THREAD 0x84FUL
#define KSWORD_ARK_IOCTL_FUNCTION_SET_THREAD_SUSPENDED 0x850UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_THREAD 0x851UL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_THREAD_VERIFIED 0x8D5UL

#define IOCTL_KSWORD_ARK_ENUM_THREAD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUM_THREAD, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_THREAD_CROSSVIEW \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_CROSSVIEW, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

// 线程运行时详情协议：
// - 输入：只接受 TID 和可选 PID 过滤，R0 自行 PsLookupThreadByThreadId；
// - 处理：按 ETHREAD/KTHREAD PDB 偏移只读采样 Cid、链表、启动地址、栈和 I/O 计数；
// - 输出：固定响应包，R3 可直接渲染成人可读详情。
#define IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_DETAIL, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_THREAD_RUNTIME_FIELDS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

// 指定线程终止协议：
// - 输入：TID、所属 PID 和线程退出状态；R0 仅通过 ID 自行引用对象；
// - 处理：验证 ETHREAD 当前仍属于请求 PID 后，结束这一条指定线程；
// - 输出：无；完成状态通过 DeviceIoControl 成功与否以及驱动日志返回。
#define IOCTL_KSWORD_ARK_TERMINATE_THREAD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_TERMINATE_THREAD, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_TERMINATE_THREAD_REQUEST
{
    unsigned long threadId;
    unsigned long processId;
    long exitStatus;
    unsigned long reserved;
} KSWORD_ARK_TERMINATE_THREAD_REQUEST;

// 指定线程挂起/恢复协议：
// - 输入：TID、所属 PID 和 action；R0 重新引用 ETHREAD 并验证所属关系；
// - action：KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND 或 RESUME；
// - 输出：无；驱动日志记录操作前的 suspend count。
#define IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_THREAD_SUSPENDED, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_THREAD_SUSPEND_ACTION_SUSPEND 1UL
#define KSWORD_ARK_THREAD_SUSPEND_ACTION_RESUME  2UL

typedef struct _KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST
{
    unsigned long threadId;
    unsigned long processId;
    unsigned long action;
    unsigned long reserved;
} KSWORD_ARK_SET_THREAD_SUSPENDED_REQUEST;

// Dedicated identity-checked ordinary thread operations. A distinct IOCTL is
// necessary: an older driver accepts oversized legacy requests but ignores
// appended identity, which must never silently weaken a verified command.
#define IOCTL_KSWORD_ARK_CONTROL_THREAD_VERIFIED \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_CONTROL_THREAD_VERIFIED, \
        METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KSWORD_ARK_THREAD_VERIFIED_VERSION 1UL
#define KSWORD_ARK_THREAD_VERIFIED_QUERY 0UL
#define KSWORD_ARK_THREAD_VERIFIED_SUSPEND 1UL
#define KSWORD_ARK_THREAD_VERIFIED_RESUME 2UL
#define KSWORD_ARK_THREAD_VERIFIED_TERMINATE 3UL
#define KSWORD_ARK_THREAD_VERIFIED_CONFIRMED 0x00000001UL
#define KSWORD_ARK_THREAD_VERIFIED_FIELD_IDENTITY 0x00000001UL
#define KSWORD_ARK_THREAD_VERIFIED_FIELD_PREVIOUS_COUNT 0x00000002UL

typedef struct _KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long threadId;
    unsigned long action;
    unsigned long flags;
    unsigned long long expectedProcessCreationTime100ns;
    unsigned long long expectedThreadCreationTime100ns;
    long exitStatus;
    unsigned long reserved;
} KSWORD_ARK_CONTROL_THREAD_VERIFIED_REQUEST;

typedef struct _KSWORD_ARK_CONTROL_THREAD_VERIFIED_RESPONSE
{
    unsigned long size;
    unsigned long version;
    long status;
    unsigned long fieldFlags;
    unsigned long processId;
    unsigned long threadId;
    unsigned long action;
    unsigned long previousSuspendCount;
    unsigned long long processCreationTime100ns;
    unsigned long long threadCreationTime100ns;
} KSWORD_ARK_CONTROL_THREAD_VERIFIED_RESPONSE;

// 驱动/System 线程控制协议：
// - 只接受 PID 4 的系统线程；R0 自行读取真实启动地址和创建时间；
// - 危险动作执行前必须精确匹配 TID + StartAddress + CreateTime100ns；
// - 拒绝 ntoskrnl 第一模块、当前 WDF 驱动实体范围、当前 IOCTL 执行线程和身份不一致请求；
// - terminate/suspend 必须携带 UI_CONFIRMED，resume 作为恢复动作可直接执行。
#define IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_CONTROL_DRIVER_THREAD, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND   1UL
#define KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME    2UL
#define KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE 3UL

#define KSWORD_ARK_DRIVER_THREAD_CONTROL_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_VALID_MASK \
    KSWORD_ARK_DRIVER_THREAD_CONTROL_FLAG_UI_CONFIRMED

// terminateMethod 只在 ACTION_TERMINATE 时生效。所有后端均为实验性：
// - PspTerminateThreadByPointer：未文档化、按 ETHREAD 指针进入终止流程；
// - Zw/NtTerminateThread：按内核句柄请求线程终止；
// - Normal APC：在目标系统线程 PASSIVE_LEVEL 上调用 PsTerminateSystemThread；
// - Special -> Normal APC：Special Kernel APC 只负责在 APC_LEVEL 排入下一段，
//   最终仍由 PASSIVE_LEVEL 的 Normal Kernel APC 调用 PsTerminateSystemThread。
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE                   0UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER         1UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT               2UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC             3UL
#define KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC  4UL

typedef struct _KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long threadId;
    unsigned long action;
    unsigned long flags;
    unsigned long terminateMethod;
    unsigned long long expectedStartAddress;
    unsigned long long expectedCreateTime100ns;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_CONTROL_DRIVER_THREAD_REQUEST;

// 线程 runtime field sample 请求：
// - 输入：threadId 定位 ETHREAD，processId 只做可选一致性上下文展示；
// - 处理：items 与进程协议共用，不接受 R3 传入对象地址；
// - 返回：共用 KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE。
typedef struct _KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long threadId;
    unsigned long processId;
    unsigned long itemCount;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long reserved2;
    KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST items[1];
} KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST;

#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_STACK    0x00000001UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_IO       0x00000002UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_SCAN_CID_TABLE   0x00000004UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE 0x00000008UL
#define KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_STACK | \
     KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_IO | \
     KSWORD_ARK_ENUM_THREAD_FLAG_INCLUDE_WORKER_STATE)

#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK 0x00000001UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST 0x00000002UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE   0x00000004UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START      0x00000008UL
#define KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK | \
     KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST | \
     KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE | \
     KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START)

#define KSWORD_ARK_THREAD_FLAG_KERNEL_ENUMERATED                0x00000001UL
#define KSWORD_ARK_THREAD_FLAG_HIDDEN_FROM_ACTIVE_THREAD_LIST   0x00000002UL
#define KSWORD_ARK_THREAD_FLAG_OWNER_PROCESS_HIDDEN             0x00000004UL
#define KSWORD_ARK_THREAD_FLAG_ACTIVE_EX_WORKER                  0x00000008UL

#define KSWORD_ARK_THREAD_FIELD_INITIAL_STACK_PRESENT          0x00000001UL
#define KSWORD_ARK_THREAD_FIELD_STACK_LIMIT_PRESENT            0x00000002UL
#define KSWORD_ARK_THREAD_FIELD_STACK_BASE_PRESENT             0x00000004UL
#define KSWORD_ARK_THREAD_FIELD_KERNEL_STACK_PRESENT           0x00000008UL
#define KSWORD_ARK_THREAD_FIELD_READ_OPERATION_COUNT_PRESENT   0x00000010UL
#define KSWORD_ARK_THREAD_FIELD_WRITE_OPERATION_COUNT_PRESENT  0x00000020UL
#define KSWORD_ARK_THREAD_FIELD_OTHER_OPERATION_COUNT_PRESENT  0x00000040UL
#define KSWORD_ARK_THREAD_FIELD_READ_TRANSFER_COUNT_PRESENT    0x00000080UL
#define KSWORD_ARK_THREAD_FIELD_WRITE_TRANSFER_COUNT_PRESENT   0x00000100UL
#define KSWORD_ARK_THREAD_FIELD_OTHER_TRANSFER_COUNT_PRESENT   0x00000200UL
#define KSWORD_ARK_THREAD_FIELD_ACTIVE_EX_WORKER_PRESENT       0x00000400UL

#define KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE     0UL
#define KSWORD_ARK_THREAD_R0_STATUS_OK              1UL
#define KSWORD_ARK_THREAD_R0_STATUS_PARTIAL         2UL
#define KSWORD_ARK_THREAD_R0_STATUS_DYNDATA_MISSING 3UL
#define KSWORD_ARK_THREAD_R0_STATUS_READ_FAILED     4UL

#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IDENTITY 0x00000001UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_LISTS    0x00000002UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START    0x00000004UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_STACK    0x00000008UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IO       0x00000010UL
#define KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IDENTITY | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_LISTS | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_START | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_STACK | \
     KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_IO)

#define KSWORD_ARK_THREAD_DETAIL_FIELD_PUBLIC_IDENTITY       0x00000001UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_OBJECT_ADDRESS        0x00000002UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_ETHREAD_CID           0x00000004UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_THREAD_LIST_ENTRY     0x00000008UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_START_ADDRESS         0x00000010UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_WIN32_START_ADDRESS   0x00000020UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_KTHREAD_PROCESS       0x00000040UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_STACK_LIMITS          0x00000080UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_IO_COUNTERS           0x00000100UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_OFFSET_SOURCES        0x00000200UL
#define KSWORD_ARK_THREAD_DETAIL_FIELD_KERNEL_GLOBALS        0x00000400UL

typedef struct _KSWORD_ARK_THREAD_DETAIL_OFFSETS
{
    unsigned long etCid;
    unsigned long etThreadListEntry;
    unsigned long etStartAddress;
    unsigned long etWin32StartAddress;
    unsigned long ktProcess;
    unsigned long ktInitialStack;
    unsigned long ktStackLimit;
    unsigned long ktStackBase;
    unsigned long ktKernelStack;
    unsigned long ktReadOperationCount;
    unsigned long ktWriteOperationCount;
    unsigned long ktOtherOperationCount;
    unsigned long ktReadTransferCount;
    unsigned long ktWriteTransferCount;
    unsigned long ktOtherTransferCount;
} KSWORD_ARK_THREAD_DETAIL_OFFSETS;

// 线程 detail 偏移来源包：
// - 输入：R0 当前 KSW_DYN_STATE.KernelSources；
// - 处理：与 offsets 字段一一对应，记录 System Informer/PDB profile/runtime pattern；
// - 返回：结构体本身无返回值，仅供 R3 解释线程字段来源。
typedef struct _KSWORD_ARK_THREAD_DETAIL_SOURCES
{
    unsigned long etCid;
    unsigned long etThreadListEntry;
    unsigned long etStartAddress;
    unsigned long etWin32StartAddress;
    unsigned long ktProcess;
    unsigned long ktInitialStack;
    unsigned long ktStackLimit;
    unsigned long ktStackBase;
    unsigned long ktKernelStack;
    unsigned long ktReadOperationCount;
    unsigned long ktWriteOperationCount;
    unsigned long ktOtherOperationCount;
    unsigned long ktReadTransferCount;
    unsigned long ktWriteTransferCount;
    unsigned long ktOtherTransferCount;
} KSWORD_ARK_THREAD_DETAIL_SOURCES;

typedef struct _KSWORD_ARK_THREAD_DETAIL_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long threadId;
    unsigned long processId;
} KSWORD_ARK_THREAD_DETAIL_REQUEST;

typedef struct _KSWORD_ARK_THREAD_DETAIL_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long threadId;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long requestedFlags;
    long lastStatus;
    unsigned long reserved;
    unsigned long long dynDataCapabilityMask;
    unsigned long long missingCapabilityMask;
    unsigned long long threadObjectAddress;
    unsigned long long processObjectAddress;
    unsigned long long cidUniqueProcess;
    unsigned long long cidUniqueThread;
    unsigned long long threadListEntryFlink;
    unsigned long long threadListEntryBlink;
    unsigned long long startAddress;
    unsigned long long win32StartAddress;
    unsigned long long kthreadProcessObject;
    unsigned long long initialStack;
    unsigned long long stackLimit;
    unsigned long long stackBase;
    unsigned long long kernelStack;
    unsigned long long readOperationCount;
    unsigned long long writeOperationCount;
    unsigned long long otherOperationCount;
    unsigned long long readTransferCount;
    unsigned long long writeTransferCount;
    unsigned long long otherTransferCount;
    KSWORD_ARK_THREAD_DETAIL_OFFSETS offsets;
    KSWORD_ARK_THREAD_DETAIL_SOURCES sources;
    KSWORD_ARK_RUNTIME_KERNEL_GLOBALS kernelGlobals;
    wchar_t detail[KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS];
} KSWORD_ARK_THREAD_DETAIL_RESPONSE;

typedef struct _KSWORD_ARK_ENUM_THREAD_REQUEST
{
    unsigned long flags;
    unsigned long processId;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_ENUM_THREAD_REQUEST;

typedef struct _KSWORD_ARK_THREAD_ENTRY
{
    unsigned long threadId;
    unsigned long processId;
    unsigned long flags;
    unsigned long fieldFlags;
    unsigned long r0Status;
    unsigned long stackFieldSource;
    unsigned long ioFieldSource;
    unsigned long reserved;
    unsigned long long initialStack;
    unsigned long long stackLimit;
    unsigned long long stackBase;
    unsigned long long kernelStack;
    unsigned long long readOperationCount;
    unsigned long long writeOperationCount;
    unsigned long long otherOperationCount;
    unsigned long long readTransferCount;
    unsigned long long writeTransferCount;
    unsigned long long otherTransferCount;
    unsigned long ktInitialStackOffset;
    unsigned long ktStackLimitOffset;
    unsigned long ktStackBaseOffset;
    unsigned long ktKernelStackOffset;
    unsigned long ktReadOperationCountOffset;
    unsigned long ktWriteOperationCountOffset;
    unsigned long ktOtherOperationCountOffset;
    unsigned long ktReadTransferCountOffset;
    unsigned long ktWriteTransferCountOffset;
    unsigned long ktOtherTransferCountOffset;
    unsigned long long dynDataCapabilityMask;
} KSWORD_ARK_THREAD_ENTRY;

typedef struct _KSWORD_ARK_ENUM_THREAD_RESPONSE
{
    unsigned long version;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    KSWORD_ARK_THREAD_ENTRY entries[1];
} KSWORD_ARK_ENUM_THREAD_RESPONSE;

typedef struct _KSWORD_ARK_THREAD_CROSSVIEW_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long processId;
    unsigned long startTid;
    unsigned long endTid;
    unsigned long maxNodes;
    unsigned long reserved0;
    unsigned long reserved1;
} KSWORD_ARK_THREAD_CROSSVIEW_REQUEST;

typedef struct _KSWORD_ARK_THREAD_CROSSVIEW_ROW
{
    unsigned long long objectAddress;
    unsigned long long processObjectAddress;
    unsigned long long startAddress;
    unsigned long processId;
    unsigned long threadId;
    unsigned long sourceMask;
    unsigned long anomalyFlags;
    unsigned long long dynDataCapabilityMask;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    long lastStatus;
    unsigned long confidence;
    char imageName[16];
    char detail[KSWORD_ARK_CROSSVIEW_DETAIL_CHARS];
    unsigned long publicThreadId;
    unsigned long threadListThreadId;
    unsigned long cidTableThreadId;
    unsigned long publicProcessId;
    unsigned long threadListProcessId;
    unsigned long cidTableProcessId;
    long publicWalkStatus;
    long threadListStatus;
    long cidTableStatus;
    long startAddressStatus;
    unsigned long detailStatus;
    unsigned long denoiseFlags;
} KSWORD_ARK_THREAD_CROSSVIEW_ROW;

typedef struct _KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long reserved;
    unsigned long long dynDataCapabilityMask;
    unsigned long long missingCapabilityMask;
    long lastStatus;
    unsigned long reserved2;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    KSWORD_ARK_THREAD_CROSSVIEW_ROW entries[1];
} KSWORD_ARK_THREAD_CROSSVIEW_RESPONSE;
