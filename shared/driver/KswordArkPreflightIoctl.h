#pragma once

#include "KswordArkSafetyIoctl.h"
#include "KswordArkTrustIoctl.h"
#include "KswordArkFileMonitorIoctl.h"

// ============================================================
// KswordArkPreflightIoctl.h
// 作用：
// - 定义 Phase-16 发布前驱动自检协议；
// - R0 汇总 DynData、安全策略、IOCTL 注册、minifilter、CI 等运行时状态；
// - Driver Verifier、跨系统兼容性、R3 UI 验收等外部测试只报告 NotRun，不伪造通过。
// ============================================================

#define KSWORD_ARK_PREFLIGHT_PROTOCOL_VERSION 1UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PREFLIGHT 0x81CUL

#define IOCTL_KSWORD_ARK_QUERY_PREFLIGHT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_PREFLIGHT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_EXTERNAL_GATES 0x00000001UL
#define KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_ALL \
    (KSWORD_ARK_PREFLIGHT_QUERY_FLAG_INCLUDE_EXTERNAL_GATES)

#define KSWORD_ARK_PREFLIGHT_STATUS_UNKNOWN 0UL
#define KSWORD_ARK_PREFLIGHT_STATUS_PASS    1UL
#define KSWORD_ARK_PREFLIGHT_STATUS_WARN    2UL
#define KSWORD_ARK_PREFLIGHT_STATUS_FAIL    3UL
#define KSWORD_ARK_PREFLIGHT_STATUS_NOT_RUN 4UL

#define KSWORD_ARK_PREFLIGHT_FIELD_DYNDATA_PRESENT      0x00000001UL
#define KSWORD_ARK_PREFLIGHT_FIELD_IOCTL_REGISTRY       0x00000002UL
#define KSWORD_ARK_PREFLIGHT_FIELD_SAFETY_POLICY        0x00000004UL
#define KSWORD_ARK_PREFLIGHT_FIELD_FILE_MONITOR         0x00000008UL
#define KSWORD_ARK_PREFLIGHT_FIELD_TRUST_CI             0x00000010UL
#define KSWORD_ARK_PREFLIGHT_FIELD_EXTERNAL_GATES       0x00000020UL

#define KSWORD_ARK_PREFLIGHT_BUILD_UNKNOWN 0UL
#define KSWORD_ARK_PREFLIGHT_BUILD_DEBUG   1UL
#define KSWORD_ARK_PREFLIGHT_BUILD_RELEASE 2UL

#define KSWORD_ARK_PREFLIGHT_ARCH_UNKNOWN 0UL
#define KSWORD_ARK_PREFLIGHT_ARCH_X64     1UL
#define KSWORD_ARK_PREFLIGHT_ARCH_ARM64   2UL

#define KSWORD_ARK_PREFLIGHT_CHECK_DRIVER_BUILD        1UL
#define KSWORD_ARK_PREFLIGHT_CHECK_DYNDATA_TOLERANCE   2UL
#define KSWORD_ARK_PREFLIGHT_CHECK_IOCTL_REGISTRY      3UL
#define KSWORD_ARK_PREFLIGHT_CHECK_SAFETY_POLICY       4UL
#define KSWORD_ARK_PREFLIGHT_CHECK_FILE_MONITOR        5UL
#define KSWORD_ARK_PREFLIGHT_CHECK_CODE_INTEGRITY      6UL
#define KSWORD_ARK_PREFLIGHT_CHECK_SIGNING_PIPELINE    7UL
#define KSWORD_ARK_PREFLIGHT_CHECK_DRIVER_VERIFIER     8UL
#define KSWORD_ARK_PREFLIGHT_CHECK_LOAD_UNLOAD         9UL
#define KSWORD_ARK_PREFLIGHT_CHECK_OBJECT_LIFETIME     10UL
#define KSWORD_ARK_PREFLIGHT_CHECK_R3_DEGRADED_UI      11UL
#define KSWORD_ARK_PREFLIGHT_CHECK_OS_BUILD_SUPPORT    12UL

#define KSWORD_ARK_PREFLIGHT_CHECK_NAME_CHARS 80U
#define KSWORD_ARK_PREFLIGHT_CHECK_DETAIL_CHARS 192U

typedef struct _KSWORD_ARK_QUERY_PREFLIGHT_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_PREFLIGHT_REQUEST;

typedef struct _KSWORD_ARK_PREFLIGHT_CHECK_ENTRY
{
    unsigned long checkId;
    unsigned long status;
    long ntstatus;
    unsigned long reserved;
    char checkName[KSWORD_ARK_PREFLIGHT_CHECK_NAME_CHARS];
    char detail[KSWORD_ARK_PREFLIGHT_CHECK_DETAIL_CHARS];
} KSWORD_ARK_PREFLIGHT_CHECK_ENTRY;

typedef struct _KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long overallStatus;
    unsigned long fieldFlags;
    unsigned long totalCheckCount;
    unsigned long returnedCheckCount;
    unsigned long entrySize;
    unsigned long buildConfiguration;
    unsigned long targetArchitecture;
    unsigned long ioctlRegistryCount;
    unsigned long ioctlDuplicateCount;
    unsigned long dynDataStatusFlags;
    long dynDataLastStatus;
    unsigned long reserved0;
    unsigned long long dynDataCapabilityMask;
    unsigned long safetyPolicyFlags;
    unsigned long safetyPolicyGeneration;
    unsigned long fileMonitorRuntimeFlags;
    unsigned long fileMonitorQueuedCount;
    unsigned long fileMonitorDroppedCount;
    long fileMonitorRegisterStatus;
    long fileMonitorStartStatus;
    unsigned long trustFieldFlags;
    unsigned long codeIntegrityOptions;
    long codeIntegrityStatus;
    unsigned long secureBootEnabled;
    unsigned long secureBootCapable;
    unsigned long reserved1;
    KSWORD_ARK_PREFLIGHT_CHECK_ENTRY checks[1];
} KSWORD_ARK_QUERY_PREFLIGHT_RESPONSE;
