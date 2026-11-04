#pragma once

#include "KswordArkProcessIoctl.h"

// Read-only loaded-image inventories; both sources execute in kernel mode.
#define KSWORD_ARK_IOCTL_FUNCTION_ENUM_MODULES 0x935UL
#define IOCTL_KSWORD_ARK_ENUM_MODULES \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_ENUM_MODULES, METHOD_BUFFERED, FILE_READ_ACCESS)

#define KSWORD_ARK_MODULE_PROTOCOL_VERSION 1UL
#define KSWORD_ARK_MODULE_SOURCE_KERNEL_SNAPSHOT 1UL
#define KSWORD_ARK_MODULE_SOURCE_PROCESS_IMAGE_MAP 2UL
#define KSWORD_ARK_MODULE_DEFAULT_ROWS 128UL
#define KSWORD_ARK_MODULE_MAX_ROWS 512UL
#define KSWORD_ARK_MODULE_PATH_CHARS 260U
#define KSWORD_ARK_MODULE_STATUS_COMPLETE 0UL
#define KSWORD_ARK_MODULE_STATUS_PARTIAL 1UL
#define KSWORD_ARK_MODULE_STATUS_UNAVAILABLE 2UL
#define KSWORD_ARK_MODULE_STATUS_INVALID 3UL
#define KSWORD_ARK_MODULE_FLAG_MORE 0x00000001UL
#define KSWORD_ARK_MODULE_FLAG_PATH_UNAVAILABLE 0x00000002UL
#define KSWORD_ARK_MODULE_FLAG_SCAN_BUDGET 0x00000004UL
#define KSWORD_ARK_MODULE_FLAG_PROCESS_EXITED 0x00000008UL
#define KSWORD_ARK_MODULE_ROW_PATH_PRESENT 0x00000001UL
#define KSWORD_ARK_MODULE_ROW_PATH_TRUNCATED 0x00000002UL
#define KSWORD_ARK_MODULE_ROW_SPAN_INCOMPLETE 0x00000004UL

typedef struct _KSWORD_ARK_ENUM_MODULES_REQUEST
{
    unsigned long size;
    unsigned long version;
    unsigned long source;
    unsigned long processId;
    unsigned long maxRows;
    unsigned long reserved;
    unsigned long long expectedCreateTime100ns;
    unsigned long long cursor;
    unsigned long long filterBase;
} KSWORD_ARK_ENUM_MODULES_REQUEST;

typedef struct _KSWORD_ARK_MODULE_ENTRY
{
    unsigned long long baseAddress;
    // Kernel: image size from SystemModuleInformation. Process: observed
    // address span of MEM_IMAGE regions; it is not a PE SizeOfImage claim.
    unsigned long long spanBytes;
    unsigned long flags;
    long pathStatus;
    unsigned long nativeFlags;
    unsigned long reserved;
    wchar_t path[KSWORD_ARK_MODULE_PATH_CHARS];
} KSWORD_ARK_MODULE_ENTRY;

typedef struct _KSWORD_ARK_ENUM_MODULES_RESPONSE
{
    unsigned long size;
    unsigned long version;
    unsigned long source;
    unsigned long status;
    long lastStatus;
    unsigned long flags;
    unsigned long entrySize;
    unsigned long returnedCount;
    // Kernel snapshot total only. Process traversal does not pre-count.
    unsigned long totalCount;
    unsigned long visitedCount;
    unsigned long processId;
    unsigned long reserved;
    unsigned long long processCreateTime100ns;
    // Kernel: next snapshot index. Process: next VA. Zero means exhausted.
    unsigned long long nextCursor;
    KSWORD_ARK_MODULE_ENTRY entries[1];
} KSWORD_ARK_ENUM_MODULES_RESPONSE;

#define KSWORD_ARK_ENUM_MODULES_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_ENUM_MODULES_RESPONSE, entries)
