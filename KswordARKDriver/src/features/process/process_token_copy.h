#pragma once

// Native token definitions must precede the project's ntddk-based driver headers.
#include <ntifs.h>
// R0/R3 requests and receipts have exactly one shared definition.
#include "driver/KswordArkProcessIoctl.h"

// Replace the target's private token field while retaining both verified process objects.
NTSTATUS KswordARKProcessCopyToken(
    _In_ const KSWORD_ARK_COPY_PROCESS_TOKEN_REQUEST* Request,
    _Inout_ KSWORD_ARK_COPY_PROCESS_TOKEN_RESPONSE* Response);
