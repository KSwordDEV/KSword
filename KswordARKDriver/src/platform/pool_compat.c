/*++

Module Name:

    pool_compat.c

Abstract:

    Nonpaged-pool allocation compatibility for kernels that do not export
    ExAllocatePool2.

Environment:

    Kernel-mode Driver Framework

--*/

#include "pool_compat.h"

typedef PVOID
(NTAPI* KSW_EX_ALLOCATE_POOL2_ROUTINE)(
    _In_ POOL_FLAGS Flags,
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG Tag
    );

// DriverEntry 是唯一写者；请求路径只读取已经选定的分配入口。
static KSW_EX_ALLOCATE_POOL2_ROUTINE g_KswordArkAllocatePool2;

_IRQL_requires_(PASSIVE_LEVEL)
VOID KswordARKInitializePoolCompatibility(VOID)
{
    // 用静态名称解析可选导出，避免分配路径在 DISPATCH_LEVEL 进行查找。
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ExAllocatePool2");
    // 不提供该导出的内核留下 NULL，后续分配直接使用现有兼容路径。
    g_KswordArkAllocatePool2 = (KSW_EX_ALLOCATE_POOL2_ROUTINE)MmGetSystemRoutineAddress(&routineName);
}

PVOID
KswordARKAllocateNonPagedPool(
    _In_ SIZE_T NumberOfBytes,
    _In_ ULONG PoolTag
    )
/*++

Routine Description:

    Allocate nonpaged memory without creating a static ExAllocatePool2 import.
    New kernels use ExAllocatePool2; earlier kernels fall back to
    ExAllocatePoolWithTag with the non-executable nonpaged pool type.

Arguments:

    NumberOfBytes - Number of bytes requested by the caller.
    PoolTag - Four-character allocation tag owned by the caller.

Return Value:

    Allocated nonpaged buffer, or NULL when the request cannot be satisfied.

--*/
{
    // 两种分配器均拒绝空请求。
    if (NumberOfBytes == 0U) {
        // 保持既有零长度调用约定。
        return NULL;
    }

    // 入口在首次分配前确定，后续无需加锁或重新解析。
    if (g_KswordArkAllocatePool2 != NULL) {
        // 保持非分页池、字节数和调用方标签的原始约定。
        return g_KswordArkAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, PoolTag);
    }

#pragma warning(push)
#pragma warning(disable:4996)
    // 缺少 ExAllocatePool2 的内核沿用不可执行非分页池。
    return ExAllocatePoolWithTag(NonPagedPoolNx, NumberOfBytes, PoolTag);
#pragma warning(pop)
}
