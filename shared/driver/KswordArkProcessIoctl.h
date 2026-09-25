#pragma once

// ============================================================
// KswordArkProcessIoctl.h
// Purpose:
// - Shared IOCTL code and request struct for R3 <-> R0 process actions.
// - This file must be included by both user mode and kernel mode.
// ============================================================

#if defined(_WIN32) && !defined(_KERNEL_MODE) && !defined(_NTDDK_) && !defined(_NTIFS_)
// User-mode translation units may include this shared protocol header before
// any Windows SDK I/O-control header.  Pull in windows.h for SDK base types and
// winioctl.h for CTL_CODE/access-mask macros first; the fallback definitions
// below remain reserved for unusual minimal include environments.
#include <windows.h>
#include <winioctl.h>
#endif

#ifndef FILE_DEVICE_UNKNOWN
#define FILE_DEVICE_UNKNOWN 0x00000022
#endif

#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif

#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

#ifndef FILE_WRITE_ACCESS
#define FILE_WRITE_ACCESS 0x0002
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#define KSWORD_ARK_IOCTL_DEVICE_TYPE FILE_DEVICE_UNKNOWN
#define KSWORD_ARK_IOCTL_FUNCTION_TERMINATE_PROCESS 0x801
#define KSWORD_ARK_IOCTL_FUNCTION_SUSPEND_PROCESS 0x802
/*
 * 恢复是挂起的对称操作，不是它的一个标志位。
 *
 * 用独立功能码而不是给挂起请求加一个 resume 位：那种借字段的做法会让一条破坏性
 * 操作和它的逆操作共用同一个访问控制与同一条审计记录，事后分不出某次调用到底
 * 挂起了还是恢复了。
 */
#define KSWORD_ARK_IOCTL_FUNCTION_RESUME_PROCESS 0x834UL
#define KSWORD_ARK_IOCTL_FUNCTION_SET_PPL_LEVEL 0x803
#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_PROCESS 0x805
#define KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_VISIBILITY 0x822UL
#define KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_SPECIAL_FLAGS 0x824UL
#define KSWORD_ARK_IOCTL_FUNCTION_DKOM_PROCESS 0x825UL
#define KSWORD_ARK_IOCTL_FUNCTION_INJECT_PROCESS 0x833UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_CROSSVIEW 0x836UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_DETAIL 0x83CUL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_RUNTIME_FIELDS 0x83EUL
#define KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_INTEGRITY 0x84CUL
#define KSWORD_ARK_IOCTL_FUNCTION_PROCESS_TOKEN_PRIVILEGES 0x855UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_TOKEN_PRIVILEGES 0x853UL
#define KSWORD_ARK_IOCTL_FUNCTION_ADJUST_PROCESS_TOKEN_PRIVILEGE 0x854UL

#define IOCTL_KSWORD_ARK_TERMINATE_PROCESS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_TERMINATE_PROCESS, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_TERMINATE_PROCESS_REQUEST
{
    unsigned long processId;
    long exitStatus;
    // Bind the PID/CID-like value to the EPROCESS instance selected by R3.
    // Zero keeps compatibility for callers that do not have stable identity data.
    unsigned long long expectedCreateTime100ns;
} KSWORD_ARK_TERMINATE_PROCESS_REQUEST;

#define IOCTL_KSWORD_ARK_SUSPEND_PROCESS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SUSPEND_PROCESS, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_SUSPEND_PROCESS_REQUEST
{
    unsigned long processId;
} KSWORD_ARK_SUSPEND_PROCESS_REQUEST;

#define IOCTL_KSWORD_ARK_RESUME_PROCESS     CTL_CODE(         KSWORD_ARK_IOCTL_DEVICE_TYPE,         KSWORD_ARK_IOCTL_FUNCTION_RESUME_PROCESS,         METHOD_BUFFERED,         FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_RESUME_PROCESS_REQUEST
{
    unsigned long processId;
} KSWORD_ARK_RESUME_PROCESS_REQUEST;

#define IOCTL_KSWORD_ARK_SET_PPL_LEVEL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_PPL_LEVEL, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// ------------------------------------------------------------
// EPROCESS.Protection（PS_PROTECTION）位域
// ------------------------------------------------------------
// 单字节布局：Type 位 0-2、Audit 位 3、Signer 位 4-7。
// IOCTL 名沿用历史的 SET_PPL_LEVEL，但协议本身同时覆盖 PPL 与完整 PP：
// - LIGHT(1) 是 PPL（PsProtectedTypeProtectedLight），同级 signer 之间可互相打开；
// - FULL(2) 是 PP（PsProtectedTypeProtected），比同 signer 的 PPL 更强，
//   连 PPL 进程也无法取得它的高权限句柄。
// 两者只差类型位，签名级别按 signer 查表，因此 R3 只要换 Type 就能在 PPL / PP
// 之间切换，不需要新的 IOCTL。
#define KSWORD_PS_PROTECTED_TYPE_NONE  ((unsigned char)0x00)
#define KSWORD_PS_PROTECTED_TYPE_LIGHT ((unsigned char)0x01)
#define KSWORD_PS_PROTECTED_TYPE_FULL  ((unsigned char)0x02)

#define KSWORD_PS_PROTECTED_SIGNER_NONE_VALUE         ((unsigned char)0x00)
#define KSWORD_PS_PROTECTED_SIGNER_AUTHENTICODE_VALUE ((unsigned char)0x01)
#define KSWORD_PS_PROTECTED_SIGNER_CODEGEN_VALUE      ((unsigned char)0x02)
#define KSWORD_PS_PROTECTED_SIGNER_ANTIMALWARE_VALUE  ((unsigned char)0x03)
#define KSWORD_PS_PROTECTED_SIGNER_LSA_VALUE          ((unsigned char)0x04)
#define KSWORD_PS_PROTECTED_SIGNER_WINDOWS_VALUE      ((unsigned char)0x05)
#define KSWORD_PS_PROTECTED_SIGNER_WINTCB_VALUE       ((unsigned char)0x06)
#define KSWORD_PS_PROTECTED_SIGNER_WINSYSTEM_VALUE    ((unsigned char)0x07)
#define KSWORD_PS_PROTECTED_SIGNER_APP_VALUE          ((unsigned char)0x08)

// 组装 Protection 字节。Audit 位不参与：本驱动没有它的签名级别映射，带上会被拒。
#define KSWORD_PS_PROTECTION_MAKE(protectedType, signerValue) \
    ((unsigned char)((((unsigned char)(signerValue)) << 4) | ((unsigned char)(protectedType) & 0x07)))

typedef struct _KSWORD_ARK_SET_PPL_LEVEL_REQUEST
{
    unsigned long processId;
    unsigned char protectionLevel;
    unsigned char reserved[3];
} KSWORD_ARK_SET_PPL_LEVEL_REQUEST;

#define IOCTL_KSWORD_ARK_SET_PROCESS_INTEGRITY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_INTEGRITY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_PROCESS_INTEGRITY_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_PROCESS_INTEGRITY_FLAG_UI_CONFIRMED 0x00000001UL

#define KSWORD_ARK_PROCESS_INTEGRITY_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_PROCESS_INTEGRITY_STATUS_APPLIED 1UL
#define KSWORD_ARK_PROCESS_INTEGRITY_STATUS_FAILED 2UL

typedef struct _KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long integrityRid;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_SET_PROCESS_INTEGRITY_REQUEST;

typedef struct _KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long integrityRid;
    unsigned long status;
    long lastStatus;
} KSWORD_ARK_SET_PROCESS_INTEGRITY_RESPONSE;

#define IOCTL_KSWORD_ARK_PROCESS_TOKEN_PRIVILEGES \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_PROCESS_TOKEN_PRIVILEGES, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_TOKEN_PRIVILEGES, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ADJUST_PROCESS_TOKEN_PRIVILEGE, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

// 进程令牌特权协议：
// - QUERY 返回目标主令牌当前持有的 LUID 与属性，名称由 R3 通过
//   LookupPrivilegeNameW 本地解析，避免把可变长字符串放入内核协议；
// - ADJUST 按 LUID 批量启用、禁用或永久移除特权；
// - expectedCreateTime100ns 绑定 PID 对应的进程实例，防止详情窗口或右键菜单
//   停留期间 PID 被复用后修改到另一个进程。
// - origin/main 的 QUERY/ADJUST 双 IOCTL 协议保留用于兼容。
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES 64UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE 0xFFFFFFFFUL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_CONFIRMATION_TOKEN 0x4B535750UL

#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_QUERY 1UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_OPERATION_ADJUST 2UL

#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_KEEP 0UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_ENABLE 1UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_DISABLE 2UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_REMOVE 3UL

#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FLAG_ALLOW_REMOVE 0x00000002UL

typedef struct _KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long flags;
} KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_REQUEST;

#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_OK 1UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_PARTIAL 2UL
#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_FAILED 3UL
typedef struct _KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY
{
    unsigned long luidLowPart;
    long luidHighPart;
    unsigned long attributes;
    unsigned long action;
} KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY;

typedef struct _KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long status;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    long lastStatus;
    KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY entries[1];
} KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE;

#define KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE_HEADER_SIZE \
    ((unsigned long)(sizeof(KSWORD_ARK_QUERY_PROCESS_TOKEN_PRIVILEGES_RESPONSE) - \
        sizeof(KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY)))

typedef struct _KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long luidLowPart;
    long luidHighPart;
    unsigned long action;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_REQUEST;

typedef struct _KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long processId;
    unsigned long luidLowPart;
    long luidHighPart;
    unsigned long action;
    unsigned long status;
    long lastStatus;
} KSWORD_ARK_ADJUST_PROCESS_TOKEN_PRIVILEGE_RESPONSE;

typedef struct _KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long operation;
    unsigned long processId;
    unsigned long flags;
    unsigned long entryCount;
    unsigned long long expectedCreateTime100ns;
    unsigned long confirmationToken;
    unsigned long reserved;
    KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY entries[KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES];
} KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_REQUEST;

typedef struct _KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long operation;
    unsigned long processId;
    unsigned long status;
    unsigned long entryCount;
    unsigned long requestedCount;
    unsigned long appliedCount;
    unsigned long failedIndex;
    long lastStatus;
    unsigned long long processCreateTime100ns;
    unsigned long reserved;
    KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ENTRY entries[KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_MAX_ENTRIES];
} KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_RESPONSE;

#define IOCTL_KSWORD_ARK_ENUM_PROCESS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_ENUM_PROCESS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_ENUM_PROCESS_PROTOCOL_VERSION 3UL
#define KSWORD_ARK_ENUM_PROCESS_FLAG_SCAN_CID_TABLE 0x00000001UL

// Phase-2 EPROCESS offset sentinel shared by R0 protocol and R3 UI models.
// Keep it local to the process protocol so user mode does not include driver-only
// ark_dyndata.h just to compare unavailable offsets.
#define KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE 0xFFFFFFFFUL

#define KSWORD_ARK_PROCESS_FLAG_KERNEL_ENUMERATED 0x00000001UL
#define KSWORD_ARK_PROCESS_FLAG_HIDDEN_FROM_ACTIVE_LIST 0x00000002UL
#define KSWORD_ARK_PROCESS_FLAG_HIDDEN_BY_KSWORD_UI 0x00000004UL
// CID-table specific evidence flags.
// Inputs:
// - CID_TABLE_ENUMERATED marks rows observed directly through PspCidTable.
// - CID_TABLE_REFERENCE_FAILED marks rows whose CID slot decoded to a process
//   object type, but R0 could not take a stable reference for detail sampling.
// - TERMINATING_OR_EXITED marks rows whose EPROCESS.ObjectTable is already NULL.
// Processing:
// - These flags are diagnostic evidence only. R3 must not synthesize a main-list
//   hidden-process row unless the independent object reference and complete
//   ActiveProcessLinks comparison flags are also present.
// Return behavior:
// - The CID value remains available to the diagnostic/CrossView view, while
//   weak evidence is excluded from the trusted main process list.
#define KSWORD_ARK_PROCESS_FLAG_CID_TABLE_ENUMERATED       0x00000008UL
#define KSWORD_ARK_PROCESS_FLAG_CID_TABLE_REFERENCE_FAILED 0x00000010UL
#define KSWORD_ARK_PROCESS_FLAG_TERMINATING_OR_EXITED      0x00000020UL
// CID_OBJECT_REFERENCE_STABLE means the decoded CID object was independently
// referenced through ObReferenceObjectByPointer and passed type, identity,
// lifetime and (when available) ObjectTable checks.
#define KSWORD_ARK_PROCESS_FLAG_CID_OBJECT_REFERENCE_STABLE 0x00000040UL
// CID_TABLE_UNCONFIRMED keeps weak or incomplete CID evidence in diagnostics;
// it is an explicit veto for the trusted R3 hidden-process predicate.
#define KSWORD_ARK_PROCESS_FLAG_CID_TABLE_UNCONFIRMED      0x00000080UL

#define KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE 1UL
#define KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE 2UL
#define KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL 3UL

// Process visibility flags select the exact reversible R0 operation.
// Inputs:
// - PATCH_UNIQUE_PID changes _EPROCESS.UniqueProcessId to a Ksword-tagged PID.
// - UNLINK_ACTIVE_LIST removes _EPROCESS.ActiveProcessLinks from the active list.
// Processing:
// - HIDE accepts either flag or both flags; flags==0 keeps the legacy combined mode
//   for old R3 clients.
// Return behavior:
// - The fixed response status remains KSWORD_ARK_PROCESS_VISIBILITY_STATUS_*.
#define KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID 0x00000001UL
#define KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST 0x00000002UL
#define KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH \
    (KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID | \
     KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST)

#define KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE 1UL
#define KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN 2UL
#define KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED 3UL

// Process field flags describe which optional Phase-2 values are valid.
// The old v1 fields remain at the beginning of KSWORD_ARK_PROCESS_ENTRY.
#define KSWORD_ARK_PROCESS_FIELD_SESSION_PRESENT                 0x00000001UL
#define KSWORD_ARK_PROCESS_FIELD_IMAGE_PATH_PRESENT              0x00000002UL
#define KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT              0x00000004UL
#define KSWORD_ARK_PROCESS_FIELD_SIGNATURE_LEVEL_PRESENT         0x00000008UL
#define KSWORD_ARK_PROCESS_FIELD_SECTION_SIGNATURE_LEVEL_PRESENT 0x00000010UL
#define KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE          0x00000020UL
#define KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_VALUE_PRESENT      0x00000040UL
#define KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE        0x00000080UL
#define KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_VALUE_PRESENT    0x00000100UL

// Field source labels are intentionally protocol-local so ProcessIoctl.h does
// not depend on the DynData protocol header and can remain the base include.
#define KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE             0UL
#define KSWORD_ARK_PROCESS_FIELD_SOURCE_PUBLIC_API              1UL
#define KSWORD_ARK_PROCESS_FIELD_SOURCE_SYSTEM_INFORMER_DYNDATA 2UL
#define KSWORD_ARK_PROCESS_FIELD_SOURCE_RUNTIME_PATTERN         3UL
#define KSWORD_ARK_PROCESS_FIELD_SOURCE_PDB_PROFILE             4UL

// R0 status summarizes how complete the extended row is for UI presentation.
#define KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE     0UL
#define KSWORD_ARK_PROCESS_R0_STATUS_OK              1UL
#define KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL         2UL
#define KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING 3UL
#define KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED     4UL

#define KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS 260U

// Cross-view source bits are shared by the process and thread protocols so R3
// can render one evidence column regardless of row type.
#define KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK 0x00000001UL
#define KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST 0x00000002UL
#define KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE   0x00000004UL
#define KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST 0x00000008UL

// Cross-view anomaly bits are intentionally evidence-only. The R0 collectors
// never repair, hide, unlink, clear, kill, or otherwise mutate target objects.
#define KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY                     0x00000001UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY                  0x00000002UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST     0x00000004UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE       0x00000008UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_ORPHAN                0x00000010UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST   0x00000020UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_START_ADDRESS_OUTSIDE_MODULE 0x00000040UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_DANGLING_OBJECT              0x00000080UL
#define KSWORD_ARK_CROSSVIEW_ANOMALY_PID_FIELD_MISMATCH           0x00000100UL

#define KSWORD_ARK_CROSSVIEW_STATUS_UNKNOWN            0UL
#define KSWORD_ARK_CROSSVIEW_STATUS_OK                 1UL
#define KSWORD_ARK_CROSSVIEW_STATUS_PARTIAL            2UL
#define KSWORD_ARK_CROSSVIEW_STATUS_CAPABILITY_MISSING 3UL
#define KSWORD_ARK_CROSSVIEW_STATUS_READ_FAILED        4UL

// Cross-view detail statuses describe the row-level collector outcome after
// capability gating, guarded reads, and source merge checks.
#define KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_UNKNOWN       0UL
#define KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_OK            1UL
#define KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_PARTIAL       2UL
#define KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_UNSUPPORTED   3UL
#define KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_READ_FAILED   4UL
#define KSWORD_ARK_CROSSVIEW_DETAIL_STATUS_DATA_MISMATCH 5UL

// Cross-view denoise flags make transient or partial evidence explicit without
// guessing undocumented terminating fields when the PDB profile lacks them.
#define KSWORD_ARK_CROSSVIEW_DENOISE_PARTIAL_EVIDENCE       0x00000001UL
#define KSWORD_ARK_CROSSVIEW_DENOISE_READ_FAILURE           0x00000002UL
#define KSWORD_ARK_CROSSVIEW_DENOISE_REFERENCE_FAILURE      0x00000004UL
#define KSWORD_ARK_CROSSVIEW_DENOISE_POSSIBLE_TERMINATING   0x00000008UL
#define KSWORD_ARK_CROSSVIEW_DENOISE_UNSUPPORTED_PDB_FIELD  0x00000010UL

// Cross-view field provenance values mirror DynData item sources so R3 can show
// whether offsets came from PDB, runtime pattern resolution, or were missing.
#define KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_UNAVAILABLE     0UL
#define KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_SYSTEM_INFORMER 1UL
#define KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_RUNTIME_PATTERN 2UL
#define KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_EXTRA_TABLE     3UL
#define KSWORD_ARK_CROSSVIEW_FIELD_SOURCE_PDB_PROFILE     4UL

#define KSWORD_ARK_CROSSVIEW_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_CROSSVIEW_DETAIL_CHARS 96U
#define KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES 8192UL
#define KSWORD_ARK_CROSSVIEW_HARD_MAX_NODES 16384UL

#define KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK 0x00000001UL
#define KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ACTIVE_LIST 0x00000002UL
#define KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE   0x00000004UL
#define KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK | \
     KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ACTIVE_LIST | \
     KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE)

typedef struct _KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS
{
    unsigned long epUniqueProcessId;
    unsigned long epActiveProcessLinks;
    unsigned long epThreadListHead;
    unsigned long epImageFileName;
    unsigned long etCid;
    unsigned long etThreadListEntry;
    unsigned long etStartAddress;
    unsigned long etWin32StartAddress;
    unsigned long ktProcess;
    unsigned long htTableCode;
    unsigned long hteLowValue;
    unsigned long pspCidTableRva;
    unsigned long long pspCidTableAddress;
    unsigned long reserved;
    unsigned long epUniqueProcessIdSource;
    unsigned long epActiveProcessLinksSource;
    unsigned long epThreadListHeadSource;
    unsigned long epImageFileNameSource;
    unsigned long etCidSource;
    unsigned long etThreadListEntrySource;
    unsigned long etStartAddressSource;
    unsigned long etWin32StartAddressSource;
    unsigned long ktProcessSource;
    unsigned long htTableCodeSource;
    unsigned long hteLowValueSource;
    unsigned long pspCidTableSource;
} KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS;

typedef struct _KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long startPid;
    unsigned long endPid;
    unsigned long maxNodes;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long reserved2;
} KSWORD_ARK_PROCESS_CROSSVIEW_REQUEST;

typedef struct _KSWORD_ARK_PROCESS_CROSSVIEW_ROW
{
    unsigned long long objectAddress;
    unsigned long long startAddress;
    unsigned long processId;
    unsigned long parentProcessId;
    unsigned long sourceMask;
    unsigned long anomalyFlags;
    unsigned long long dynDataCapabilityMask;
    KSWORD_ARK_CROSSVIEW_FIELD_OFFSETS fieldOffsets;
    long lastStatus;
    unsigned long confidence;
    char imageName[16];
    char detail[KSWORD_ARK_CROSSVIEW_DETAIL_CHARS];
    unsigned long publicProcessId;
    unsigned long activeListProcessId;
    unsigned long cidTableProcessId;
    long publicWalkStatus;
    long activeListStatus;
    long cidTableStatus;
    unsigned long detailStatus;
    unsigned long denoiseFlags;
} KSWORD_ARK_PROCESS_CROSSVIEW_ROW;

typedef struct _KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE
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
    KSWORD_ARK_PROCESS_CROSSVIEW_ROW entries[1];
} KSWORD_ARK_PROCESS_CROSSVIEW_RESPONSE;

#define IOCTL_KSWORD_ARK_QUERY_PROCESS_CROSSVIEW \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_CROSSVIEW, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

// 进程运行时详情协议：
// - 输入：只接受 PID 和展示 flags，不接受 R3 传入的 EPROCESS 地址；
// - 处理：R0 通过 PsLookupProcessByProcessId 定位对象，再按 DynData/PDB 偏移只读采样；
// - 输出：固定响应包，字段缺失时用 fieldFlags/missingCapabilityMask/detail 解释原因。
#define IOCTL_KSWORD_ARK_QUERY_PROCESS_DETAIL \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_DETAIL, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_PROCESS_RUNTIME_FIELDS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PROCESS_RUNTIME_FIELDS, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS 256U
#define KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS 16U

// 通用 runtime field sample 协议：
// - 输入：R3 只提交 PDB deep JSON 中的 runtimeItemId、offset、size；
// - 处理：R0 仅从自身 lookup/reference 得到的 EPROCESS/ETHREAD 基址读取小字段；
// - 返回：每个字段的状态、原始小字节和值摘要，不接受也不回写任意 R3 内核指针。
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_ITEMS 64UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES 16UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_OFFSET 0x8000UL

#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN         0UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_OK              1UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_PARTIAL         2UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_LOOKUP_FAILED   3UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_INVALID_REQUEST 4UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_TRUNCATED       5UL

#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_UNKNOWN         0UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OK              1UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_OFFSET_REJECTED 2UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_SIZE_REJECTED   3UL
#define KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_READ_FAILED     4UL

typedef struct _KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST
{
    unsigned long runtimeItemId;
    unsigned long offset;
    unsigned long size;
    unsigned long flags;
} KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST;

typedef struct _KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long processId;
    unsigned long itemCount;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long reserved2;
    unsigned long reserved3;
    KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ITEM_REQUEST items[1];
} KSWORD_ARK_PROCESS_RUNTIME_FIELD_SAMPLE_REQUEST;

typedef struct _KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW
{
    unsigned long runtimeItemId;
    unsigned long offset;
    unsigned long size;
    unsigned long status;
    unsigned long bytesRead;
    unsigned long flags;
    long lastStatus;
    unsigned long reserved;
    unsigned long long valueU64;
    unsigned char sampleBytes[KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_VALUE_BYTES];
} KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW;

typedef struct _KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long flags;
    long lastStatus;
    unsigned long reserved;
    unsigned long long objectAddress;
    unsigned long long dynDataCapabilityMask;
    KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW entries[1];
} KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE;

#define KSWORD_ARK_DETAIL_STATUS_UNKNOWN            0UL
#define KSWORD_ARK_DETAIL_STATUS_OK                 1UL
#define KSWORD_ARK_DETAIL_STATUS_PARTIAL            2UL
#define KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED        3UL
#define KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED      4UL
#define KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING 5UL
#define KSWORD_ARK_DETAIL_STATUS_READ_FAILED        6UL

#define KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_PUBLIC_IDENTITY 0x00000001UL
#define KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_LIST_LINKS      0x00000002UL
#define KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_OBJECT_POINTERS 0x00000004UL
#define KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_TOKEN_FASTREF   0x00000008UL
#define KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_PROTECTION      0x00000010UL
#define KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_PUBLIC_IDENTITY | \
     KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_LIST_LINKS | \
     KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_OBJECT_POINTERS | \
     KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_TOKEN_FASTREF | \
     KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_PROTECTION)

#define KSWORD_ARK_PROCESS_DETAIL_FIELD_PUBLIC_IDENTITY       0x00000001UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_ADDRESS        0x00000002UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_UNIQUE_PROCESS_ID     0x00000004UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_ACTIVE_PROCESS_LINKS  0x00000008UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_THREAD_LIST_HEAD      0x00000010UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_IMAGE_FILE_NAME       0x00000020UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_TOKEN_FASTREF         0x00000040UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_TABLE          0x00000080UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_OBJECT        0x00000100UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_PROTECTION            0x00000200UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_SIGNATURE_LEVEL       0x00000400UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_SIGNATURE     0x00000800UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_OFFSET_SOURCES        0x00001000UL
#define KSWORD_ARK_PROCESS_DETAIL_FIELD_KERNEL_GLOBALS        0x00002000UL

// 运行时 detail 通用内核全局 RVA 包：
// - 输入：R0 DynData/PDB profile EX 中已校验的 GlobalRva item；
// - 处理：R0 返回 RVA、来源以及按当前 ntoskrnl imageBase 推导出的只读地址；
// - 返回：结构体本身无返回值，仅供 R3 展示 PspCidTable/模块链表等证据来源。
typedef struct _KSWORD_ARK_RUNTIME_KERNEL_GLOBALS
{
    unsigned long pspCidTableRva;
    unsigned long psLoadedModuleListRva;
    unsigned long mmUnloadedDriversRva;
    unsigned long piDdbCacheTableRva;
    unsigned long keServiceDescriptorTableShadowRva;
    unsigned long mmLastUnloadedDriverRva;
    unsigned long pspCidTableSource;
    unsigned long psLoadedModuleListSource;
    unsigned long mmUnloadedDriversSource;
    unsigned long piDdbCacheTableSource;
    unsigned long keServiceDescriptorTableShadowSource;
    unsigned long mmLastUnloadedDriverSource;
    unsigned long long pspCidTableAddress;
    unsigned long long psLoadedModuleListAddress;
    unsigned long long mmUnloadedDriversAddress;
    unsigned long long piDdbCacheTableAddress;
    unsigned long long keServiceDescriptorTableShadowAddress;
    unsigned long long mmLastUnloadedDriverAddress;
} KSWORD_ARK_RUNTIME_KERNEL_GLOBALS;

typedef struct _KSWORD_ARK_PROCESS_DETAIL_OFFSETS
{
    unsigned long epUniqueProcessId;
    unsigned long epActiveProcessLinks;
    unsigned long epThreadListHead;
    unsigned long epImageFileName;
    unsigned long epToken;
    unsigned long epObjectTable;
    unsigned long epSectionObject;
    unsigned long epProtection;
    unsigned long epSignatureLevel;
    unsigned long epSectionSignatureLevel;
} KSWORD_ARK_PROCESS_DETAIL_OFFSETS;

// 进程 detail 偏移来源包：
// - 输入：R0 当前 KSW_DYN_STATE.KernelSources；
// - 处理：与 offsets 同名一一对应，记录 System Informer/PDB profile/runtime pattern；
// - 返回：结构体本身无返回值，仅用于 UI 把 offset 解释成人可读来源。
typedef struct _KSWORD_ARK_PROCESS_DETAIL_SOURCES
{
    unsigned long epUniqueProcessId;
    unsigned long epActiveProcessLinks;
    unsigned long epThreadListHead;
    unsigned long epImageFileName;
    unsigned long epToken;
    unsigned long epObjectTable;
    unsigned long epSectionObject;
    unsigned long epProtection;
    unsigned long epSignatureLevel;
    unsigned long epSectionSignatureLevel;
} KSWORD_ARK_PROCESS_DETAIL_SOURCES;

typedef struct _KSWORD_ARK_PROCESS_DETAIL_REQUEST
{
    unsigned long version;
    unsigned long flags;
    unsigned long processId;
    unsigned long reserved;
} KSWORD_ARK_PROCESS_DETAIL_REQUEST;

typedef struct _KSWORD_ARK_PROCESS_DETAIL_RESPONSE
{
    unsigned long version;
    unsigned long status;
    unsigned long processId;
    unsigned long fieldFlags;
    unsigned long requestedFlags;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    unsigned long long dynDataCapabilityMask;
    unsigned long long missingCapabilityMask;
    unsigned long long processObjectAddress;
    unsigned long long uniqueProcessIdValue;
    unsigned long long activeProcessLinksFlink;
    unsigned long long activeProcessLinksBlink;
    unsigned long long threadListHeadFlink;
    unsigned long long threadListHeadBlink;
    unsigned long long tokenFastRef;
    unsigned long long tokenObjectAddress;
    unsigned long long objectTableAddress;
    unsigned long long sectionObjectAddress;
    unsigned char protection;
    unsigned char signatureLevel;
    unsigned char sectionSignatureLevel;
    unsigned char reservedByte;
    char imageName[KSWORD_ARK_RUNTIME_IMAGE_NAME_CHARS];
    KSWORD_ARK_PROCESS_DETAIL_OFFSETS offsets;
    KSWORD_ARK_PROCESS_DETAIL_SOURCES sources;
    KSWORD_ARK_RUNTIME_KERNEL_GLOBALS kernelGlobals;
    wchar_t detail[KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS];
} KSWORD_ARK_PROCESS_DETAIL_RESPONSE;

typedef struct _KSWORD_ARK_ENUM_PROCESS_REQUEST
{
    unsigned long flags;
    unsigned long startPid;
    unsigned long endPid;
    unsigned long reserved;
} KSWORD_ARK_ENUM_PROCESS_REQUEST;

typedef struct _KSWORD_ARK_PROCESS_ENTRY
{
    // v1 fixed fields: keep these first for backward-compatible parsers.
    unsigned long processId;
    unsigned long parentProcessId;
    unsigned long flags;
    unsigned long reserved;
    char imageName[16];

    // v2 public/process fields.
    unsigned long sessionId;
    unsigned long fieldFlags;
    unsigned long r0Status;
    unsigned long sessionSource;

    // v2 EPROCESS protection bytes and their field provenance.
    unsigned char protection;
    unsigned char signatureLevel;
    unsigned char sectionSignatureLevel;
    unsigned char reservedByte;
    unsigned long protectionSource;
    unsigned long signatureLevelSource;
    unsigned long sectionSignatureLevelSource;

    // v2 EPROCESS object pointers and DynData provenance.
    unsigned long objectTableSource;
    unsigned long sectionObjectSource;
    unsigned long imagePathSource;
    unsigned long reserved2;
    unsigned long protectionOffset;
    unsigned long signatureLevelOffset;
    unsigned long sectionSignatureLevelOffset;
    unsigned long objectTableOffset;
    unsigned long sectionObjectOffset;
    unsigned long long objectTableAddress;
    unsigned long long sectionObjectAddress;
    unsigned long long dynDataCapabilityMask;

    // v2 full image path. UTF-16 code units are used without requiring WCHAR in
    // this shared header, so R3 can copy them into std::wstring directly.
    unsigned short imagePath[KSWORD_ARK_PROCESS_IMAGE_PATH_CHARS];

    // v3 stable process identity sampled from the referenced EPROCESS object.
    // Zero means the CID evidence row could not be referenced safely.
    unsigned long long creationTime100ns;
} KSWORD_ARK_PROCESS_ENTRY;

typedef struct _KSWORD_ARK_ENUM_PROCESS_RESPONSE
{
    unsigned long version;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    KSWORD_ARK_PROCESS_ENTRY entries[1];
} KSWORD_ARK_ENUM_PROCESS_RESPONSE;

#define IOCTL_KSWORD_ARK_SET_PROCESS_VISIBILITY \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_VISIBILITY, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

typedef struct _KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST
{
    unsigned long processId;
    unsigned long action;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_SET_PROCESS_VISIBILITY_REQUEST;

typedef struct _KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE
{
    unsigned long version;
    unsigned long processId;
    unsigned long status;
    unsigned long hiddenCount;
    long lastStatus;
    unsigned long reserved;
} KSWORD_ARK_SET_PROCESS_VISIBILITY_RESPONSE;

#define IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_SET_PROCESS_SPECIAL_FLAGS, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION  1UL
#define KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION 2UL
#define KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION        3UL

#define KSWORD_ARK_PROCESS_SPECIAL_FLAG_BREAK_ON_TERMINATION 0x00000001UL
#define KSWORD_ARK_PROCESS_SPECIAL_FLAG_APC_INSERT_DISABLED  0x00000002UL

#define KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNKNOWN          0UL
#define KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED          1UL
#define KSWORD_ARK_PROCESS_SPECIAL_STATUS_PARTIAL          2UL
#define KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNSUPPORTED      3UL
#define KSWORD_ARK_PROCESS_SPECIAL_STATUS_LOOKUP_FAILED    4UL
#define KSWORD_ARK_PROCESS_SPECIAL_STATUS_OPERATION_FAILED 5UL

typedef struct _KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST
{
    unsigned long version;
    unsigned long processId;
    unsigned long action;
    unsigned long flags;
    // The driver validates this timestamp after resolving the target EPROCESS.
    // Zero preserves compatibility for callers without a stable snapshot.
    unsigned long long expectedCreateTime100ns;
} KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_REQUEST;

typedef struct _KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE
{
    unsigned long version;
    unsigned long processId;
    unsigned long action;
    unsigned long status;
    unsigned long appliedFlags;
    unsigned long touchedThreadCount;
    long lastStatus;
    unsigned long reserved;
} KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS_RESPONSE;

#define IOCTL_KSWORD_ARK_DKOM_PROCESS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_DKOM_PROCESS, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE 1UL

#define KSWORD_ARK_PROCESS_DKOM_STATUS_UNKNOWN          0UL
#define KSWORD_ARK_PROCESS_DKOM_STATUS_REMOVED          1UL
#define KSWORD_ARK_PROCESS_DKOM_STATUS_NOT_FOUND        2UL
#define KSWORD_ARK_PROCESS_DKOM_STATUS_UNSUPPORTED      3UL
#define KSWORD_ARK_PROCESS_DKOM_STATUS_LOOKUP_FAILED    4UL
#define KSWORD_ARK_PROCESS_DKOM_STATUS_OPERATION_FAILED 5UL

typedef struct _KSWORD_ARK_DKOM_PROCESS_REQUEST
{
    unsigned long version;
    unsigned long processId;
    unsigned long action;
    unsigned long flags;
} KSWORD_ARK_DKOM_PROCESS_REQUEST;

typedef struct _KSWORD_ARK_DKOM_PROCESS_RESPONSE
{
    unsigned long version;
    unsigned long processId;
    unsigned long action;
    unsigned long status;
    unsigned long removedEntries;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    unsigned long long pspCidTableAddress;
    unsigned long long processObjectAddress;
} KSWORD_ARK_DKOM_PROCESS_RESPONSE;

#define IOCTL_KSWORD_ARK_INJECT_PROCESS \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_INJECT_PROCESS, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES (256UL * 1024UL)

#define KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH   1UL
#define KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE  2UL

#define KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD  0x00000002UL

#define KSWORD_ARK_PROCESS_INJECT_STATUS_UNKNOWN             0UL
#define KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED            1UL
#define KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST     2UL
#define KSWORD_ARK_PROCESS_INJECT_STATUS_PROCESS_OPEN_FAILED 3UL
#define KSWORD_ARK_PROCESS_INJECT_STATUS_ALLOC_FAILED        4UL
#define KSWORD_ARK_PROCESS_INJECT_STATUS_WRITE_FAILED        5UL
#define KSWORD_ARK_PROCESS_INJECT_STATUS_THREAD_FAILED       6UL
#define KSWORD_ARK_PROCESS_INJECT_STATUS_WAIT_FAILED         7UL

typedef struct _KSWORD_ARK_INJECT_PROCESS_REQUEST
{
    unsigned long version;
    unsigned long processId;
    unsigned long injectType;
    unsigned long flags;
    unsigned long payloadBytes;
    unsigned long reserved;
    unsigned long long entryPointAddress;
    unsigned long long parameterAddress;
    unsigned char payload[1];
} KSWORD_ARK_INJECT_PROCESS_REQUEST;

typedef struct _KSWORD_ARK_INJECT_PROCESS_RESPONSE
{
    unsigned long version;
    unsigned long processId;
    unsigned long injectType;
    unsigned long status;
    unsigned long flags;
    unsigned long bytesWritten;
    long lastStatus;
    long waitStatus;
    unsigned long long entryPointAddress;
    unsigned long long parameterAddress;
    unsigned long long remoteBaseAddress;
    unsigned long long remoteRegionSize;
} KSWORD_ARK_INJECT_PROCESS_RESPONSE;
