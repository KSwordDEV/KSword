#pragma once

#include "ark/ark_driver.h"

EXTERN_C_START

// 在 DriverEntry 发布设备之前解析新内核的分配入口。
_IRQL_requires_(PASSIVE_LEVEL)
VOID KswordARKInitializePoolCompatibility(VOID);

PVOID
KswordARKAllocateNonPagedPool(
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG PoolTag
    );

EXTERN_C_END
