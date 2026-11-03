#pragma once
#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkManagedNetworkIoctl.h"

EXTERN_C_START
VOID KswordARKNetworkManagedUninitialize(VOID);
NTSTATUS KswordARKNetworkIoctlControlManagedPolicy(WDFDEVICE Device, WDFREQUEST Request,
    size_t InputBufferLength, size_t OutputBufferLength, size_t* BytesReturned);
NTSTATUS KswordARKNetworkIoctlQueryManagedPolicies(WDFDEVICE Device, WDFREQUEST Request,
    size_t InputBufferLength, size_t OutputBufferLength, size_t* BytesReturned);
EXTERN_C_END
