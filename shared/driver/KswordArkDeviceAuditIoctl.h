#pragma once

#include "KswordArkKernelIoctl.h"
#include <stddef.h>

// ============================================================
// KswordArkDeviceAuditIoctl.h
// 作用：
// - 定义 R3 <-> R0 设备/输入/USB/GPU 只读审计协议；
// - 协议只返回设备对象、驱动对象、链路关系和风险提示；
// - 协议不代表任何写入、卸载、解绑、禁用或 hook 动作。
// ============================================================

#define KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION_V1 1UL
#define KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION_V2 2UL
#define KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION KSWORD_ARK_DEVICE_AUDIT_PROTOCOL_VERSION_V2

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_DEVICE_STACK_AUDIT           0x8E0UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_INPUT_STACK_AUDIT            0x8E1UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_USB_TOPOLOGY_AUDIT           0x8E2UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT   0x8E3UL

#define IOCTL_KSWORD_ARK_QUERY_DEVICE_STACK_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_DEVICE_STACK_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_INPUT_STACK_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_INPUT_STACK_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_USB_TOPOLOGY_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_USB_TOPOLOGY_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define IOCTL_KSWORD_ARK_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_GPU_DISPLAY_WATCHDOG_AUDIT, \
        METHOD_BUFFERED, \
        FILE_ANY_ACCESS)

#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK            0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK             0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY            0x00000004UL
#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG    0x00000008UL

#define KSWORD_ARK_DEVICE_AUDIT_PROFILE_ALL \
    (KSWORD_ARK_DEVICE_AUDIT_PROFILE_DEVICE_STACK | \
     KSWORD_ARK_DEVICE_AUDIT_PROFILE_INPUT_STACK | \
     KSWORD_ARK_DEVICE_AUDIT_PROFILE_USB_TOPOLOGY | \
     KSWORD_ARK_DEVICE_AUDIT_PROFILE_GPU_DISPLAY_WATCHDOG)

#define KSWORD_ARK_DEVICE_AUDIT_STATUS_UNAVAILABLE         0UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_OK                  1UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL             2UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND           3UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_BUFFER_TRUNCATED    4UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED        5UL
#define KSWORD_ARK_DEVICE_AUDIT_STATUS_UNSUPPORTED         6UL

#define KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY    1UL
#define KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW        2UL

#define KSWORD_ARK_DEVICE_AUDIT_ROLE_UNKNOWN               0UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_PDO                   1UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_FDO                   2UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_UPPER_FILTER          3UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_LOWER_FILTER          4UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER          5UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER            6UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_COMPOSITE             7UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE             8UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER            9UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY               10UL
#define KSWORD_ARK_DEVICE_AUDIT_ROLE_WATCHDOG              11UL

#define KSWORD_ARK_DEVICE_AUDIT_FIELD_DRIVER_NAME_PRESENT      0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_SERVICE_NAME_PRESENT     0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_DEVICE_NAME_PRESENT      0x00000004UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_IMAGE_PATH_PRESENT       0x00000008UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_DETAIL_PRESENT           0x00000010UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_ATTACHED_PRESENT         0x00000020UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_NEXT_PRESENT             0x00000040UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT     0x00000080UL
#define KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT 0x00000100UL

#define KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_TRUNCATED        0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_PARTIAL          0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_RESPONSE_FLAG_EMPTY            0x00000004UL

#define KSWORD_ARK_DEVICE_AUDIT_RISK_NONE                      0x00000000UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_UNAVAILABLE               0x00000001UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_QUERY_FAILED              0x00000002UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_NAME_MISSING              0x00000004UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_IMAGE_PATH_MISSING        0x00000008UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_DEVICE_LOOP               0x00000010UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_ATTACHED_LOOP             0x00000020UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_CROSS_DRIVER_ATTACH       0x00000040UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_ROLE_AMBIGUOUS            0x00000080UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_STACK_TRUNCATED           0x00000100UL
#define KSWORD_ARK_DEVICE_AUDIT_RISK_INTEGRITY_PARTIAL         0x00000200UL

#define KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS              1024UL
#define KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ROWS                 1024UL
#define KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH      16UL
#define KSWORD_ARK_DEVICE_AUDIT_HARD_MAX_ATTACHED_DEPTH         64UL

#define KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS  KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS KSWORD_ARK_DRIVER_SERVICE_KEY_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS  KSWORD_ARK_DRIVER_DEVICE_NAME_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS   KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS
#define KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS       256U

typedef struct _KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST
{
    // 说明：这是一个只读审计请求头，用于限定版本、页大小和单目标筛选。
    // 输入：R3 传入版本号、profileFlags、最大行数、最大附加深度和可选目标名。
    // 处理：R0 只做校验和归一化，不会修改系统策略或遍历未知对象链。
    // 返回：无返回值；结构体由 IOCTL 输入缓冲区直接承载。
    unsigned long size;
    unsigned long version;
    unsigned long profileFlags;
    unsigned long maxRows;
    unsigned long maxAttachedDepth;
    unsigned long reserved0;
    wchar_t targetName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS];
} KSWORD_ARK_QUERY_DEVICE_AUDIT_REQUEST;

typedef struct _KSWORD_ARK_DEVICE_AUDIT_ENTRY
{
    // 说明：这是设备/驱动审计的统一输出行，既可以表示 summary，也可以表示设备链证据。
    // 输入：由 R0 从 DriverObject integrity 证据转换而来，或在失败时合成部分行。
    // 处理：字段只承载地址、名称、状态和风险提示，不触发任何写入动作。
    // 返回：无返回值；结构体被放入可变长响应体 entries[]。
    unsigned long size;
    unsigned long profileFlags;
    unsigned long rowKind;
    unsigned long roleHint;
    unsigned long status;
    unsigned long riskFlags;
    unsigned long fieldFlags;
    unsigned long confidence;
    unsigned long relationDepth;
    unsigned long attachedDepth;
    unsigned long deviceType;
    unsigned long characteristics;
    unsigned long stackSize;
    unsigned long alignmentRequirement;
    long lastStatus;
    unsigned long reserved0;
    unsigned long long driverObjectAddress;
    unsigned long long deviceObjectAddress;
    unsigned long long attachedDeviceAddress;
    unsigned long long nextDeviceObjectAddress;
    wchar_t driverName[KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS];
    wchar_t serviceName[KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS];
    wchar_t deviceName[KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS];
    wchar_t imagePath[KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS];
    wchar_t detail[KSWORD_ARK_DEVICE_AUDIT_DETAIL_CHARS];
    // v2: actual metadata from the existing integrity snapshot. detail[] is diagnostic only.
    // The v1 prefix stays byte-for-byte stable; new R3 requires the complete v2 row.
    unsigned long long ownerDriverObjectAddress;
    unsigned long integrityStatus;
    unsigned long integrityReturnedCount;
    unsigned long integrityTotalCount;
    unsigned long integrityModuleCount;
    unsigned long integrityStatusFlags;
    unsigned long reserved1;
} KSWORD_ARK_DEVICE_AUDIT_ENTRY;

#define KSWORD_ARK_DEVICE_AUDIT_V1_ENTRY_SIZE \
    ((unsigned long)offsetof(KSWORD_ARK_DEVICE_AUDIT_ENTRY, ownerDriverObjectAddress))

typedef struct _KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE
{
    // 说明：这是可变长审计响应头，后面紧跟 entries[]。
    // 输入：R0 填写查询结果、返回计数和状态汇总。
    // 处理：R3 通过 returnedCount 和 entrySize 逐行枚举。
    // 返回：无返回值；结构体直接写入 METHOD_BUFFERED 输出缓冲区。
    unsigned long size;
    unsigned long version;
    unsigned long queryStatus;
    unsigned long profileFlags;
    unsigned long responseFlags;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long targetCount;
    unsigned long driverCount;
    unsigned long deviceCount;
    long lastStatus;
    unsigned long reserved0;
    KSWORD_ARK_DEVICE_AUDIT_ENTRY entries[1];
} KSWORD_ARK_QUERY_DEVICE_AUDIT_RESPONSE;
