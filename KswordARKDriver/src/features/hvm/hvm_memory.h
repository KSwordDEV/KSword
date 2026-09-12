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

/*
 * Publish the page-table self-map base this module discovered.
 *
 * Returns FALSE when discovery never succeeded, in which case no caller may
 * derive a page-table entry address.
 *
 * Exposed so the VM-exit-safe windows do not repeat the discovery.  The slot
 * is randomized per boot but the same for every address space, and finding it
 * costs a probe of up to 512 candidates plus MmIsAddressValid on each - work
 * that belongs on an initialization path exactly once.  Having a second copy
 * of the search would also mean a second chance to get the sign-extension
 * masking wrong, and that mistake does not fault: it silently edits an entry
 * that maps nothing.
 */
BOOLEAN
KswordARKHvmMemorySelfMapBase(
    _Out_ ULONGLONG* SelfMapBase
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
/*
 * LeafEntry 给出终止这次走表的那一项，可以传 NULL 不要。
 *
 * R-1 注入跨页找空隙时必须看它：候选页要既可执行（NX 位为零）又是用户页
 * （U/S 位置位）。只拿到物理地址判断不了这两件事，而把载荷放进一页不可执行的
 * 内存里，表现是注入装上了却永远不触发——和成功在外面看不出区别。
 */
NTSTATUS
KswordARKHvmMemoryTranslate(
    _In_ ULONGLONG DirectoryBase,
    _In_ ULONGLONG VirtualAddress,
    _Out_ ULONGLONG* PhysicalAddress,
    _Out_opt_ ULONGLONG* LeafEntry
    );

EXTERN_C_END
