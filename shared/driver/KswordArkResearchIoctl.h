#pragma once

#include "KswordArkProcessIoctl.h"

#ifndef FILE_READ_ACCESS
#define FILE_READ_ACCESS 0x0001
#endif

// ============================================================
// KswordArkResearchIoctl.h
// 作用：
// - 为《第二规划》71 个专题提供稳定、只读、可版本化的 R3/R0 证据入口；
// - 返回当前 IOCTL 请求上下文、CPU/时间快照、WDF/WDM 对象链，
//   并由 R0 实时确认该专题所依赖的业务 IOCTL 是否在中央表注册；
// - 这是证据编排协议，不代替各业务 IOCTL 的实际采集，也不把运行时
//   unsupported/partial 伪装成 clean。
// ============================================================

#define KSWORD_ARK_RESEARCH_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_RESEARCH_TOPIC 0x90EUL

// 响应包含内核对象/handler 地址；控制设备允许 World 只读，因此有意要求
// 读写句柄，把地址型证据限制到 Administrators/SYSTEM。该 access bit 不是 mutation。
#define IOCTL_KSWORD_ARK_QUERY_RESEARCH_TOPIC \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_RESEARCH_TOPIC, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

// Topic ID 与 KernelKnowledgeCatalog.cpp 中 71 项的顺序一致；
// 新增/删除/重排任何一项都必须同时更新静态校验器。
#define KSWORD_ARK_RESEARCH_TOPIC_EXECUTION_CHAIN                  1UL
#define KSWORD_ARK_RESEARCH_TOPIC_ADDRESS_SPACES                   2UL
#define KSWORD_ARK_RESEARCH_TOPIC_HANDLES_REFERENCES               3UL
#define KSWORD_ARK_RESEARCH_TOPIC_STATUS_CODES                     4UL
#define KSWORD_ARK_RESEARCH_TOPIC_IRQL_CONTEXT                     5UL
#define KSWORD_ARK_RESEARCH_TOPIC_SYNCHRONIZATION                  6UL
#define KSWORD_ARK_RESEARCH_TOPIC_DRIVER_LIFECYCLE                 7UL
#define KSWORD_ARK_RESEARCH_TOPIC_WDM_KMDF                         8UL
#define KSWORD_ARK_RESEARCH_TOPIC_IOCTL_CHAIN                      9UL
#define KSWORD_ARK_RESEARCH_TOPIC_DEBUGGING_DUMPS                 10UL
#define KSWORD_ARK_RESEARCH_TOPIC_OBJECT_MANAGER                  11UL
#define KSWORD_ARK_RESEARCH_TOPIC_OBJECT_DIRECTORIES              12UL
#define KSWORD_ARK_RESEARCH_TOPIC_SYMBOLIC_LINKS                  13UL
#define KSWORD_ARK_RESEARCH_TOPIC_OBJECT_HEADER                   14UL
#define KSWORD_ARK_RESEARCH_TOPIC_OBJECT_SECURITY                 15UL
#define KSWORD_ARK_RESEARCH_TOPIC_PSP_CID_TABLE                   16UL
#define KSWORD_ARK_RESEARCH_TOPIC_CID_OBJECT_RELATIONS            17UL
#define KSWORD_ARK_RESEARCH_TOPIC_HANDLE_TABLE_TABLECODE          18UL
#define KSWORD_ARK_RESEARCH_TOPIC_PROCESS_CROSS_VIEW              19UL
#define KSWORD_ARK_RESEARCH_TOPIC_PROCESS_VS_CID_HANDLES          20UL
#define KSWORD_ARK_RESEARCH_TOPIC_CROSS_VIEW_VISUALIZATION        21UL
#define KSWORD_ARK_RESEARCH_TOPIC_EXECUTIVE_THREAD_OBJECTS        22UL
#define KSWORD_ARK_RESEARCH_TOPIC_PROCESS_LIFECYCLE               23UL
#define KSWORD_ARK_RESEARCH_TOPIC_SCHEDULER                       24UL
#define KSWORD_ARK_RESEARCH_TOPIC_DISPATCHER_OBJECTS              25UL
#define KSWORD_ARK_RESEARCH_TOPIC_APC_DPC_WORK_ITEMS              26UL
#define KSWORD_ARK_RESEARCH_TOPIC_PROCESS_ATTACH                  27UL
#define KSWORD_ARK_RESEARCH_TOPIC_SESSION_SILO_PICO               28UL
#define KSWORD_ARK_RESEARCH_TOPIC_PAGE_TABLES                     29UL
#define KSWORD_ARK_RESEARCH_TOPIC_PAGE_FAULT_WORKING_SET          30UL
#define KSWORD_ARK_RESEARCH_TOPIC_VAD                             31UL
#define KSWORD_ARK_RESEARCH_TOPIC_PFN_DATABASE                    32UL
#define KSWORD_ARK_RESEARCH_TOPIC_SECTION_CONTROL_AREA            33UL
#define KSWORD_ARK_RESEARCH_TOPIC_MDL_DMA                         34UL
#define KSWORD_ARK_RESEARCH_TOPIC_POOL                            35UL
#define KSWORD_ARK_RESEARCH_TOPIC_EXECUTABLE_MEMORY_EVIDENCE      36UL
#define KSWORD_ARK_RESEARCH_TOPIC_IRP_LIFECYCLE                   37UL
#define KSWORD_ARK_RESEARCH_TOPIC_DRIVER_DEVICE_FILE_OBJECTS      38UL
#define KSWORD_ARK_RESEARCH_TOPIC_MINIFILTER                      39UL
#define KSWORD_ARK_RESEARCH_TOPIC_CACHE_MEMORY_MANAGER            40UL
#define KSWORD_ARK_RESEARCH_TOPIC_FILESYSTEMS                     41UL
#define KSWORD_ARK_RESEARCH_TOPIC_STORAGE_STACK                   42UL
#define KSWORD_ARK_RESEARCH_TOPIC_NETWORK_REDIRECTOR              43UL
#define KSWORD_ARK_RESEARCH_TOPIC_REGISTRY_VIEWS                  44UL
#define KSWORD_ARK_RESEARCH_TOPIC_CONFIGURATION_MANAGER           45UL
#define KSWORD_ARK_RESEARCH_TOPIC_REGISTRY_CALLBACKS              46UL
#define KSWORD_ARK_RESEARCH_TOPIC_REGISTRY_TRANSACTIONS           47UL
#define KSWORD_ARK_RESEARCH_TOPIC_TOKEN                           48UL
#define KSWORD_ARK_RESEARCH_TOPIC_AUTHENTICATION_STACK            49UL
#define KSWORD_ARK_RESEARCH_TOPIC_PROTECTED_PROCESS               50UL
#define KSWORD_ARK_RESEARCH_TOPIC_CODE_INTEGRITY                  51UL
#define KSWORD_ARK_RESEARCH_TOPIC_VBS_HVCI                        52UL
#define KSWORD_ARK_RESEARCH_TOPIC_PATCHGUARD                      53UL
#define KSWORD_ARK_RESEARCH_TOPIC_NETWORK_STACK                   54UL
#define KSWORD_ARK_RESEARCH_TOPIC_WFP_NDIS                        55UL
#define KSWORD_ARK_RESEARCH_TOPIC_AFD_NSI                         56UL
#define KSWORD_ARK_RESEARCH_TOPIC_ALPC                            57UL
#define KSWORD_ARK_RESEARCH_TOPIC_IPC                             58UL
#define KSWORD_ARK_RESEARCH_TOPIC_WIN32K_GUI                      59UL
#define KSWORD_ARK_RESEARCH_TOPIC_PNP                             60UL
#define KSWORD_ARK_RESEARCH_TOPIC_DEVICE_STACK                    61UL
#define KSWORD_ARK_RESEARCH_TOPIC_ACPI_PCI                        62UL
#define KSWORD_ARK_RESEARCH_TOPIC_USB_HID                         63UL
#define KSWORD_ARK_RESEARCH_TOPIC_GPU_TDR                         64UL
#define KSWORD_ARK_RESEARCH_TOPIC_POWER_MANAGEMENT                65UL
#define KSWORD_ARK_RESEARCH_TOPIC_CALLBACKS                       66UL
#define KSWORD_ARK_RESEARCH_TOPIC_EXTERNAL_CALLBACKS              67UL
#define KSWORD_ARK_RESEARCH_TOPIC_HOOK_EVIDENCE                   68UL
#define KSWORD_ARK_RESEARCH_TOPIC_CPU_CONTROL_STATE               69UL
#define KSWORD_ARK_RESEARCH_TOPIC_TRACING                         70UL
#define KSWORD_ARK_RESEARCH_TOPIC_EVIDENCE_TIMELINE               71UL
#define KSWORD_ARK_RESEARCH_TOPIC_COUNT                           71UL

#define KSWORD_ARK_RESEARCH_DEFAULT_MAX_ENTRIES 12UL
#define KSWORD_ARK_RESEARCH_HARD_MAX_ENTRIES    16UL
#define KSWORD_ARK_RESEARCH_ENTRY_NAME_CHARS    96U
#define KSWORD_ARK_RESEARCH_COMMON_ENTRY_COUNT   4UL
#define KSWORD_ARK_RESEARCH_MAX_TOPIC_IOCTLS     4UL
#define KSWORD_ARK_RESEARCH_MIN_TOTAL_ENTRIES \
    (KSWORD_ARK_RESEARCH_COMMON_ENTRY_COUNT + 1UL)
#define KSWORD_ARK_RESEARCH_MAX_TOTAL_ENTRIES \
    (KSWORD_ARK_RESEARCH_COMMON_ENTRY_COUNT + \
        KSWORD_ARK_RESEARCH_MAX_TOPIC_IOCTLS)

#define KSWORD_ARK_RESEARCH_STATUS_OK               0UL
#define KSWORD_ARK_RESEARCH_STATUS_TRUNCATED        1UL
#define KSWORD_ARK_RESEARCH_STATUS_SOURCE_MISSING   2UL
#define KSWORD_ARK_RESEARCH_STATUS_INVALID_REQUEST  3UL

#define KSWORD_ARK_RESEARCH_RESPONSE_TRUNCATED          0x00000001UL
#define KSWORD_ARK_RESEARCH_RESPONSE_RUNTIME_DEPENDENT  0x00000002UL
#define KSWORD_ARK_RESEARCH_RESPONSE_DYNDATA_DEPENDENT  0x00000004UL
#define KSWORD_ARK_RESEARCH_RESPONSE_R3_CROSS_VIEW      0x00000008UL
#define KSWORD_ARK_RESEARCH_RESPONSE_PRIVATE_LAYOUT     0x00000010UL
#define KSWORD_ARK_RESEARCH_RESPONSE_FIRMWARE_EVIDENCE  0x00000020UL
#define KSWORD_ARK_RESEARCH_RESPONSE_PRIVACY_GUARDED    0x00000040UL

#define KSWORD_ARK_RESEARCH_SOURCE_PUBLIC_KERNEL_API 0x00000001UL
#define KSWORD_ARK_RESEARCH_SOURCE_WDF               0x00000002UL
#define KSWORD_ARK_RESEARCH_SOURCE_IOCTL_REGISTRY    0x00000004UL
#define KSWORD_ARK_RESEARCH_SOURCE_DYNDATA_PDB       0x00000008UL
#define KSWORD_ARK_RESEARCH_SOURCE_RUNTIME_SNAPSHOT  0x00000010UL
#define KSWORD_ARK_RESEARCH_SOURCE_R3_PUBLIC_API     0x00000020UL
#define KSWORD_ARK_RESEARCH_SOURCE_FIRMWARE          0x00000040UL
#define KSWORD_ARK_RESEARCH_SOURCE_EVENT_STREAM      0x00000080UL

#define KSWORD_ARK_RESEARCH_ENTRY_REQUEST_CONTEXT  1UL
#define KSWORD_ARK_RESEARCH_ENTRY_PROCESSOR_CONTEXT 2UL
#define KSWORD_ARK_RESEARCH_ENTRY_CLOCK_SNAPSHOT   3UL
#define KSWORD_ARK_RESEARCH_ENTRY_WDF_WDM_CHAIN    4UL
#define KSWORD_ARK_RESEARCH_ENTRY_IOCTL_SOURCE     5UL

#define KSWORD_ARK_RESEARCH_EVIDENCE_AVAILABLE   1UL
#define KSWORD_ARK_RESEARCH_EVIDENCE_UNAVAILABLE 2UL

#define KSWORD_ARK_RESEARCH_CONFIDENCE_RUNTIME  100UL
#define KSWORD_ARK_RESEARCH_CONFIDENCE_REGISTRY 100UL

typedef struct _KSWORD_ARK_QUERY_RESEARCH_TOPIC_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long topicId;
    unsigned long maxEntries;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_RESEARCH_TOPIC_REQUEST;

typedef struct _KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY
{
    unsigned long size;
    unsigned long kind;
    unsigned long sourceMask;
    unsigned long state;
    unsigned long confidence;
    unsigned long fieldId;
    long lastStatus;
    unsigned long ioControlCode;
    unsigned long functionNumber;
    unsigned long method;
    unsigned long access;
    unsigned long registryFlags;
    unsigned long long requiredCapability;
    unsigned long long value0;
    unsigned long long value1;
    unsigned long long value2;
    unsigned long long value3;
    char name[KSWORD_ARK_RESEARCH_ENTRY_NAME_CHARS];
} KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY;

typedef struct _KSWORD_ARK_QUERY_RESEARCH_TOPIC_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long topicId;
    unsigned long queryStatus;
    unsigned long responseFlags;
    unsigned long totalCount;
    unsigned long returnedCount;
    unsigned long entrySize;
    unsigned long registeredIoctlCount;
    unsigned long duplicateIoctlCount;
    long lastStatus;
    unsigned long currentIrql;
    unsigned long requestorMode;
    unsigned long requestorModeMirror;
    unsigned long processorGroup;
    unsigned long processorNumber;
    unsigned long activeGroupCount;
    unsigned long activeProcessorCount;
    unsigned long requestorProcessId;
    unsigned long requestorThreadId;
    unsigned long reserved;
    unsigned long long systemTime100ns;
    unsigned long long interruptTime100ns;
    unsigned long long performanceCounter;
    unsigned long long performanceFrequency;
    unsigned long long driverObjectAddress;
    unsigned long long driverImageBase;
    unsigned long long driverImageSize;
    unsigned long long deviceObjectAddress;
    unsigned long long topAttachedDeviceAddress;
    unsigned long long deviceObjectPhysicalAddress;
    KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY entries[1];
} KSWORD_ARK_QUERY_RESEARCH_TOPIC_RESPONSE;

#define KSWORD_ARK_RESEARCH_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_QUERY_RESEARCH_TOPIC_RESPONSE) - \
        sizeof(KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY))
