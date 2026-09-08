/*++

Module Name:

    hvm_memory.h

Abstract:

    Declares ring -1 memory access: a private page-table window that reaches
    physical memory without calling the documented memory-manager routines.

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL entry.

--*/

#pragma once

#include "hvm_runtime.h"

EXTERN_C_START

/*
 * Reserve the private window and discover the page-table self-map.  Failure is
 * not fatal: every access falls back to MmCopyMemory and reports that the
 * hook-free path was unavailable.
 */
VOID
KswordARKHvmMemoryInitialize(
    VOID
    );

/* Release the private window and restore its original page-table entry. */
VOID
KswordARKHvmMemoryShutdown(
    VOID
    );

/* Execute one versioned ring -1 memory request. */
NTSTATUS
KswordARKHvmMemoryExecute(
    _In_ const KSWORD_ARK_HVM_MEMORY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_MEMORY_RESPONSE* Response
    );

/*
 * 解析一个进程当前真正在用的层次基址。
 *
 * 附加到进程里读寄存器，而不是读 EPROCESS 的 DirectoryTableBase：那个偏移
 * Windows 不公开，写死了在下一次更新后会**静默**读错——错的 CR3 照样能走表、
 * 照样产出一个物理地址。
 *
 * 导出给 hvm_process 用。让它自己再写一份走表器只会多一份会分叉的实现。
 */
NTSTATUS
KswordARKHvmMemoryResolveProcessDirectoryBase(
    _In_ ULONG ProcessId,
    _Out_ ULONGLONG* DirectoryBase
    );

/*
 * 用给定的层次基址翻译一个虚拟地址。大页在终止走表的那一级解析，所以 2 MiB
 * 与 1 GiB 映射得到的物理地址与处理器算出来的一致。
 */
NTSTATUS
KswordARKHvmMemoryTranslate(
    _In_ ULONGLONG DirectoryBase,
    _In_ ULONGLONG VirtualAddress,
    _Out_ ULONGLONG* PhysicalAddress
    );

EXTERN_C_END
