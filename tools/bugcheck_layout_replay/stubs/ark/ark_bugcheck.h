#pragma once

#include <ntddk.h>

#define KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES (8UL * 1024UL * 1024UL)

// The replay only needs bugcheck layout/runtime types. Keep the controller packets opaque
// so bugcheck_internal.h remains parseable without pulling the complete shared IOCTL graph.
typedef struct _KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST;
typedef struct _KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE;
