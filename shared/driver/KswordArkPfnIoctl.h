#pragma once
#include "KswordArkMemoryIoctl.h"

// Read-only, bounded physical-page evidence. No caller pointers or arbitrary
// native information classes cross this interface. PFNs are always 4 KiB units.
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PFN_BATCH 0x91CUL
#define IOCTL_KSWORD_ARK_QUERY_PFN_BATCH CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_PFN_BATCH, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KSWORD_ARK_PFN_VERSION 1UL
#define KSWORD_ARK_PFN_MAX_PAGES 4096UL
#define KSWORD_ARK_PFN_MAX_RANGES 512UL
// Range requests with count zero retain the original 512-row ABI. New callers
// may retry with an explicit larger output capacity, up to 1 MiB of rows.
#define KSWORD_ARK_PFN_RANGE_CAPACITY_LIMIT 65536UL
#define KSWORD_ARK_PFN_MAX_OWNERS 16384UL
#define KSWORD_ARK_PFN_RANGES 1UL
#define KSWORD_ARK_PFN_PAGES 2UL
#define KSWORD_ARK_PFN_OWNERS 3UL
// This operation appends count unsigned-64 PFNs after KSWORD_ARK_PFN_REQUEST.
#define KSWORD_ARK_PFN_IDENTITIES 4UL
#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_PFN_MAPPINGS 0x91DUL
#define IOCTL_KSWORD_ARK_QUERY_PFN_MAPPINGS CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_PFN_MAPPINGS, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define KSWORD_ARK_PFN_MAX_MAPPINGS 256UL

typedef struct _KSWORD_ARK_PFN_REQUEST {
    unsigned long version;
    unsigned long operation;
    unsigned long count;
    unsigned long reserved;
    unsigned long long firstPfn;
} KSWORD_ARK_PFN_REQUEST;

typedef struct _KSWORD_ARK_PFN_RANGE {
    unsigned long long firstPfn;
    unsigned long long pageCount;
} KSWORD_ARK_PFN_RANGE;

typedef struct _KSWORD_ARK_PFN_IDENTITY {
    unsigned long long frame;
    unsigned long long pfn;
    unsigned long long backing;
} KSWORD_ARK_PFN_IDENTITY;

typedef struct _KSWORD_ARK_PFN_OWNER {
    unsigned long long processKey;
    unsigned long processId;
    unsigned long sessionId;
    char imageName[16];
} KSWORD_ARK_PFN_OWNER;

// Payload contains count range/identity/owner records selected by operation.
// A failing nativeStatus never makes zero-initialized records valid evidence.
typedef struct _KSWORD_ARK_PFN_RESPONSE {
    unsigned long version;
    unsigned long operation;
    long nativeStatus;
    unsigned long count;
    unsigned long long timestamp100ns;
} KSWORD_ARK_PFN_RESPONSE;

// Caller supplies resident user VAs; the driver reads PTEs without paging them in.
// createTime prevents PID reuse from silently changing the inspected process.
typedef struct _KSWORD_ARK_PFN_MAPPING_REQUEST {
    unsigned long version;
    unsigned long processId;
    unsigned long count;
    unsigned long reserved;
    unsigned long long createTime;
    unsigned long long addresses[KSWORD_ARK_PFN_MAX_MAPPINGS];
} KSWORD_ARK_PFN_MAPPING_REQUEST;

typedef struct _KSWORD_ARK_PFN_MAPPING {
    unsigned long long pfn;
    unsigned long pageSize;
    long status;
} KSWORD_ARK_PFN_MAPPING;

typedef struct _KSWORD_ARK_PFN_MAPPING_RESPONSE {
    unsigned long version;
    unsigned long count;
    KSWORD_ARK_PFN_MAPPING entries[KSWORD_ARK_PFN_MAX_MAPPINGS];
} KSWORD_ARK_PFN_MAPPING_RESPONSE;
