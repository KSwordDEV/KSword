#pragma once
#include "ark/ark_dyndata.h"
#include "driver/KswordArkProcessIoctl.h"

// All sampling requires a caller-owned process reference at PASSIVE_LEVEL.
VOID KswordARKProcessSampleLifetime(
    _Inout_ KSWORD_ARK_PROCESS_ENTRY* Entry,
    _In_ PEPROCESS Process,
    _In_ const KSW_DYN_STATE* DynState);

// Completes the independent CID-thread cross-check for this response only.
VOID KswordARKProcessFinalizeLifetime(
    _Inout_ KSWORD_ARK_ENUM_PROCESS_RESPONSE* Response,
    _In_ const KSW_DYN_STATE* DynState);
