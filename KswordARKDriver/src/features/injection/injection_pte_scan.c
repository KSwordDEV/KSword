/*++

Module Name:

    injection_pte_scan.c

Abstract:

    Read-only page-table range scan that reports user-space executable leaves.

    这是注入痕迹检查的**第三个视图**（R3 VirtualQuery / R0 VAD 之外）。它回答的
    问题只有一个：**处理器实际会把哪些用户页当代码执行**。VAD 和 VirtualQueryEx
    给的都是"内存管理器记的保护属性"，而真正决定能不能执行的是页表里的 NX 位；
    两者不一致时，硬件那一侧才是执行的事实。DFRWS 2019 提出的 PteMalfind 就是
    冲这个差值去的。

    刻意不做的事：
      * 不看 Dirty 位并据此下结论。Dirty 是"自上次清除以来被写过"，不是历史日志，
        把它当"这页被改过"是错的。原始项值一并返回，要看自己看。
      * 不改任何页表项。本模块没有写路径。
      * 不锁地址空间。扫描期间目标会变；协议用游标续扫 + 不一致计数表达这件事，
        不假装原子快照。

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL only.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_injection_scan.h"
#include "../../platform/pool_compat.h"

#if defined(_M_AMD64) || defined(_M_X64)
#include <intrin.h>
#endif

/*
 * 这几个例程声明在 ntifs.h 而不是 ntddk.h 里，本驱动不 include ntifs.h。
 * ApcState 用 PVOID + 固定大小字节数组承接，理由同 memory_pagetable.c：
 * KAPC_STATE 的定义也在 ntifs.h。
 */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTKERNELAPI
VOID
KeStackAttachProcess(
    _Inout_ PVOID Process,
    _Out_ PVOID ApcState
    );

NTKERNELAPI
VOID
KeUnstackDetachProcess(
    _In_ PVOID ApcState
    );

// 与 memory_pagetable.c 共用的 x64 分页常量。重复定义会让两边悄悄漂移，
// 所以这里只引用协议头里已有的 KSWORD_ARK_PAGE_TABLE_* 标志位，
// 物理地址掩码按 Intel SDM 的定义在本文件内声明一次。
#define KSW_INJ_PTE_PRESENT_BIT   0x0000000000000001ULL
#define KSW_INJ_PTE_WRITE_BIT     0x0000000000000002ULL
#define KSW_INJ_PTE_USER_BIT      0x0000000000000004ULL
#define KSW_INJ_PTE_LARGE_BIT     0x0000000000000080ULL
#define KSW_INJ_PTE_NX_BIT        0x8000000000000000ULL
#define KSW_INJ_PTE_ADDR_4KB_MASK 0x000FFFFFFFFFF000ULL
#define KSW_INJ_PTE_ADDR_2MB_MASK 0x000FFFFFFFE00000ULL
#define KSW_INJ_PTE_ADDR_1GB_MASK 0x000FFFFFC0000000ULL

#define KSW_INJ_ENTRIES_PER_TABLE 512U
#define KSW_INJ_TABLE_BYTES       4096U
// CR4.LA57。五级分页下这个四级遍历是错的，必须拒绝而不是按四级硬走 ——
// memory_pagetable.c 的 walker 也是同一条口径。
#define KSW_INJ_CR4_LA57_BIT      (1ULL << 12)

EXTERN_C ULONG64 KswordARKInjectionUserAddressLimit(VOID);

typedef struct _KSW_INJ_PTE_TABLE
{
    ULONG64 Entries[KSW_INJ_ENTRIES_PER_TABLE];
} KSW_INJ_PTE_TABLE;

typedef struct _KSW_INJ_PTE_SCAN_STATE
{
    KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE* Response;
    size_t EntryCapacity;
    ULONG MaxTableReads;
    ULONG64 RangeEnd;
    BOOLEAN IncludeNonExecutable;
    BOOLEAN IncludeSupervisor;
    BOOLEAN Truncated;

    // 当前正在累积的段。PageCount 为 0 表示没有在累积。
    ULONG64 RunStartVa;
    ULONG64 RunNextVa;
    ULONG64 RunFirstPhysical;
    ULONG64 RunFirstValue;
    ULONG RunPageSize;
    ULONG RunPageCount;
    ULONG RunEffectiveFlags;
    ULONG RunEntryFlags;
} KSW_INJ_PTE_SCAN_STATE;

static NTSTATUS
KswordARKInjectionReadPhysicalTable(
    _In_ ULONG64 PhysicalAddress,
    _Out_ KSW_INJ_PTE_TABLE* Table
    )
/*++

Routine Description:

    整页读一张页表。中文说明：逐项读 8 字节要 512 次 MmCopyMemory，一次范围扫描
    会做上百万次调用；整页读把它降到一次。页表页恒为 4 KiB 对齐。

Return Value:

    STATUS_SUCCESS 表示完整读到 4096 字节。

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Table == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Table, sizeof(*Table));

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.PhysicalAddress.QuadPart = (LONGLONG)PhysicalAddress;

    __try {
        status = MmCopyMemory(
            Table,
            copyAddress,
            KSW_INJ_TABLE_BYTES,
            MM_COPY_MEMORY_PHYSICAL,
            &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copied = 0U;
    }

    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (copied != KSW_INJ_TABLE_BYTES) {
        return STATUS_PARTIAL_COPY;
    }
    return STATUS_SUCCESS;
}

static ULONG
KswordARKInjectionMergeFlags(
    _In_ ULONG64 Pml4e,
    _In_ ULONG64 Pdpte,
    _In_ ULONG64 Pde,
    _In_ ULONG64 Leaf,
    _In_ BOOLEAN LeafIsPte
    )
/*++

Routine Description:

    合并逐级项得到**生效**权限。中文说明：x64 分页里，写权限和用户权限是逐级
    相与，NX 是逐级相或。只看叶子项会把一段其实不可写的页报成可写。

--*/
{
    ULONG flags = 0UL;
    // 大页时叶子就是 PDE/PDPTE 本身，调用方已经把它同时传进 Pde/Leaf，
    // 再与一次不改变结果，所以这里不分支。
    ULONG64 writable = Pml4e & Pdpte & Pde & Leaf & KSW_INJ_PTE_WRITE_BIT;
    ULONG64 user = Pml4e & Pdpte & Pde & Leaf & KSW_INJ_PTE_USER_BIT;
    ULONG64 nx = (Pml4e | Pdpte | Pde | Leaf) & KSW_INJ_PTE_NX_BIT;

    flags |= KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT;
    if (writable != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE;
    }
    if (user != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_USER;
    }
    if (nx != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_NX;
    }
    if ((Leaf & KSW_INJ_PTE_LARGE_BIT) != 0ULL && !LeafIsPte) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE;
    }
    if ((Leaf & 0x20ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_ACCESSED;
    }
    if ((Leaf & 0x40ULL) != 0ULL) {
        flags |= KSWORD_ARK_PAGE_TABLE_FLAG_DIRTY;
    }
    return flags;
}

static VOID
KswordARKInjectionFlushRun(
    _Inout_ KSW_INJ_PTE_SCAN_STATE* State
    )
/*++

Routine Description:

    把当前累积的段写进响应。中文说明：缓冲满时置 Truncated 而不是丢弃，
    调用方据此续扫。

--*/
{
    KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY* entry = NULL;

    if (State->RunPageCount == 0UL) {
        return;
    }
    if ((size_t)State->Response->returnedCount >= State->EntryCapacity) {
        State->Truncated = TRUE;
        State->Response->nextCursorAddress = State->RunStartVa;
        State->Response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_CURSOR_PRESENT;
        State->RunPageCount = 0UL;
        return;
    }

    entry = &State->Response->entries[State->Response->returnedCount];
    entry->startVa = State->RunStartVa;
    entry->byteLength = State->RunNextVa - State->RunStartVa;
    entry->firstPhysicalAddress = State->RunFirstPhysical;
    entry->firstEntryValue = State->RunFirstValue;
    entry->pageSize = State->RunPageSize;
    entry->pageCount = State->RunPageCount;
    entry->effectiveFlags = State->RunEffectiveFlags;
    entry->entryFlags = State->RunEntryFlags;
    ++State->Response->returnedCount;
    State->Response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_ENTRIES_PRESENT;
    State->RunPageCount = 0UL;
}

static VOID
KswordARKInjectionAppendLeaf(
    _Inout_ KSW_INJ_PTE_SCAN_STATE* State,
    _In_ ULONG64 VirtualAddress,
    _In_ ULONG64 PhysicalAddress,
    _In_ ULONG64 EntryValue,
    _In_ ULONG PageSize,
    _In_ ULONG EffectiveFlags
    )
{
    ULONG entryFlags = 0UL;
    const ULONG64 pageBytes = (ULONG64)PageSize;

    if ((EffectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) == 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_EXECUTABLE;
    }
    if ((EffectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE) != 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_WRITABLE;
    }
    if ((EffectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_USER;
    }
    if ((EffectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE) != 0UL) {
        entryFlags |= KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_LARGE_PAGE;
    }

    if ((entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_EXECUTABLE) != 0UL) {
        State->Response->executablePageCount +=
            (ULONG)(pageBytes / KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_4KB);
    }

    // 段合并条件：地址连续、页大小相同、生效权限完全相同。
    if (State->RunPageCount != 0UL &&
        State->RunNextVa == VirtualAddress &&
        State->RunPageSize == PageSize &&
        State->RunEffectiveFlags == EffectiveFlags) {
        State->RunNextVa += pageBytes;
        ++State->RunPageCount;
        return;
    }

    KswordARKInjectionFlushRun(State);
    if (State->Truncated) {
        return;
    }
    State->RunStartVa = VirtualAddress;
    State->RunNextVa = VirtualAddress + pageBytes;
    State->RunFirstPhysical = PhysicalAddress;
    State->RunFirstValue = EntryValue;
    State->RunPageSize = PageSize;
    State->RunPageCount = 1UL;
    State->RunEffectiveFlags = EffectiveFlags;
    State->RunEntryFlags = entryFlags;
}

static BOOLEAN
KswordARKInjectionLeafWanted(
    _In_ const KSW_INJ_PTE_SCAN_STATE* State,
    _In_ ULONG EffectiveFlags
    )
{
    const BOOLEAN executable = ((EffectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_NX) == 0UL);
    const BOOLEAN user = ((EffectiveFlags & KSWORD_ARK_PAGE_TABLE_FLAG_USER) != 0UL);

    if (!user && !State->IncludeSupervisor) {
        return FALSE;
    }
    if (!executable && !State->IncludeNonExecutable) {
        return FALSE;
    }
    return TRUE;
}

NTSTATUS
KswordARKDriverScanProcessExecutablePte(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    在目标进程的页表上做范围扫描，报出用户态可执行叶子页。

Return Value:

    STATUS_SUCCESS 表示 IOCTL 已产出可读响应（失败情形写在 response->status 里）。

--*/
{
    KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE* response = NULL;
    KSW_INJ_PTE_SCAN_STATE state;
    KSW_INJ_PTE_TABLE* pml4 = NULL;
    KSW_INJ_PTE_TABLE* pdpt = NULL;
    KSW_INJ_PTE_TABLE* pd = NULL;
    KSW_INJ_PTE_TABLE* pt = NULL;
    PEPROCESS processObject = NULL;
    DECLSPEC_ALIGN(16) UCHAR apcState[128];
    BOOLEAN attached = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 cr3 = 0ULL;
    ULONG64 rangeStart = 0ULL;
    ULONG64 rangeEnd = 0ULL;
    ULONG64 scanFrom = 0ULL;
    ULONG maxEntries = 0UL;
    ULONG maxTableReads = 0UL;
    ULONG pml4Index = 0UL;

    if (BytesWrittenOut == NULL || OutputBuffer == NULL || Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_SCAN_PROCESS_EXECUTABLE_PTE_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY);
    response->processId = Request->processId;
    response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    *BytesWrittenOut = KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_IRQL_REJECTED;
        response->lastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_SUCCESS;
    }
    if (Request->processId == 0UL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    rangeStart = Request->startAddress & ~((ULONG64)PAGE_SIZE - 1ULL);
    rangeEnd = (Request->endAddress == 0ULL)
        ? (KswordARKInjectionUserAddressLimit() + 1ULL)
        : Request->endAddress;
    if (rangeEnd > KswordARKInjectionUserAddressLimit() + 1ULL) {
        rangeEnd = KswordARKInjectionUserAddressLimit() + 1ULL;
    }
    scanFrom = (Request->cursorAddress != 0ULL) ? Request->cursorAddress : rangeStart;
    scanFrom &= ~((ULONG64)PAGE_SIZE - 1ULL);
    if (scanFrom < rangeStart) {
        scanFrom = rangeStart;
    }
    if (rangeEnd <= scanFrom) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_INVALID_RANGE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    maxEntries = Request->maxEntries;
    if (maxEntries == 0UL) {
        maxEntries = KSWORD_ARK_INJECTION_PTE_LIMIT_DEFAULT;
    }
    if (maxEntries > KSWORD_ARK_INJECTION_PTE_LIMIT_MAX) {
        maxEntries = KSWORD_ARK_INJECTION_PTE_LIMIT_MAX;
    }
    maxTableReads = Request->maxTableReads;
    if (maxTableReads == 0UL) {
        maxTableReads = KSWORD_ARK_INJECTION_PTE_TABLE_READS_DEFAULT;
    }
    if (maxTableReads > KSWORD_ARK_INJECTION_PTE_TABLE_READS_MAX) {
        maxTableReads = KSWORD_ARK_INJECTION_PTE_TABLE_READS_MAX;
    }

    RtlZeroMemory(&state, sizeof(state));
    state.Response = response;
    state.EntryCapacity =
        (OutputBufferLength - KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY);
    if (state.EntryCapacity > (size_t)maxEntries) {
        state.EntryCapacity = (size_t)maxEntries;
    }
    if (state.EntryCapacity == 0U) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_BUFFER_TOO_SMALL;
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        return STATUS_SUCCESS;
    }
    state.MaxTableReads = maxTableReads;
    state.RangeEnd = rangeEnd;
    state.IncludeNonExecutable =
        (Request->flags & KSWORD_ARK_INJECTION_PTE_FLAG_INCLUDE_NON_EXECUTABLE) != 0UL;
    state.IncludeSupervisor =
        (Request->flags & KSWORD_ARK_INJECTION_PTE_FLAG_INCLUDE_SUPERVISOR) != 0UL;

    status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    /*
     * 四张表页各留一块。合起来 16 KiB，放栈上会直接吃掉内核栈的一大半，
     * 所以走非分页池。
     */
    pml4 = (KSW_INJ_PTE_TABLE*)KswordARKAllocateNonPagedPool(
        sizeof(KSW_INJ_PTE_TABLE) * 4U, 'jnIK');
    if (pml4 == NULL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }
    pdpt = pml4 + 1;
    pd = pml4 + 2;
    pt = pml4 + 3;

    // 五级分页下这个四级遍历会解错每一个地址。拒绝，不降级硬走。
    if ((__readcr4() & KSW_INJ_CR4_LA57_BIT) != 0ULL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = STATUS_NOT_SUPPORTED;
        ExFreePool(pml4);
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }

    /*
     * 附加到目标进程只为读 CR3 —— Windows 不公开稳定的 EPROCESS.DirectoryTableBase
     * 偏移，所以不硬编码版本相关偏移。页表本身按物理地址读，不依赖当前地址空间，
     * 因此读完 CR3 立刻脱离。
     */
    __try {
        RtlZeroMemory(apcState, sizeof(apcState));
        KeStackAttachProcess((PVOID)processObject, apcState);
        attached = TRUE;
        cr3 = __readcr3() & KSW_INJ_PTE_ADDR_4KB_MASK;
        KeUnstackDetachProcess(apcState);
        attached = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (attached) {
            KeUnstackDetachProcess(apcState);
            attached = FALSE;
        }
        cr3 = 0ULL;
    }

    if (cr3 == 0ULL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = STATUS_NOT_FOUND;
        ExFreePool(pml4);
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }
    response->cr3PhysicalAddress = cr3;
    response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_CR3_PRESENT;
    response->scannedBegin = scanFrom;

    status = KswordARKInjectionReadPhysicalTable(cr3, pml4);
    ++response->tableReads;
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = status;
        ExFreePool(pml4);
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }

    /*
     * 自顶向下遍历，只下降到 present 的子树。整段不存在的地址空间因此一次
     * 表读都不花 —— 用户空间绝大部分是空的，逐页问是不可能跑完的。
     */
    for (pml4Index = (ULONG)((scanFrom >> 39) & 0x1FFULL);
         pml4Index < KSW_INJ_ENTRIES_PER_TABLE && !state.Truncated;
         ++pml4Index) {
        const ULONG64 pml4e = pml4->Entries[pml4Index];
        ULONG64 pml4Base = ((ULONG64)pml4Index) << 39;
        ULONG pdptIndex = 0UL;

        if (pml4Base >= rangeEnd) {
            break;
        }
        if ((pml4e & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
            continue;
        }
        if (response->tableReads >= state.MaxTableReads) {
            state.Truncated = TRUE;
            response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_BUDGET_EXHAUSTED;
            response->nextCursorAddress = pml4Base;
            break;
        }
        status = KswordARKInjectionReadPhysicalTable(pml4e & KSW_INJ_PTE_ADDR_4KB_MASK, pdpt);
        ++response->tableReads;
        if (!NT_SUCCESS(status)) {
            ++response->failedTableReads;
            continue;
        }

        /*
         * 内层一律从 0 起，靠下面 "整段在游标之前就 continue" 跳过。用索引算起点
         * 在跨级边界上很容易差一格，而多转几百次整数比较根本不花时间 ——
         * 真正贵的是表读，那一步已经被 present 位和范围判断挡在外面了。
         */
        for (pdptIndex = 0UL;
             pdptIndex < KSW_INJ_ENTRIES_PER_TABLE && !state.Truncated;
             ++pdptIndex) {
            const ULONG64 pdpte = pdpt->Entries[pdptIndex];
            const ULONG64 pdptBase = pml4Base | (((ULONG64)pdptIndex) << 30);
            ULONG pdIndex = 0UL;

            if (pdptBase >= rangeEnd) {
                break;
            }
            if (pdptBase + (1ULL << 30) <= scanFrom) {
                continue;
            }
            if ((pdpte & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
                continue;
            }
            if ((pdpte & KSW_INJ_PTE_LARGE_BIT) != 0ULL) {
                const ULONG flags = KswordARKInjectionMergeFlags(pml4e, pdpte, pdpte, pdpte, FALSE);
                if (KswordARKInjectionLeafWanted(&state, flags) && pdptBase >= scanFrom) {
                    KswordARKInjectionAppendLeaf(
                        &state,
                        pdptBase,
                        pdpte & KSW_INJ_PTE_ADDR_1GB_MASK,
                        pdpte,
                        KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_1GB,
                        flags);
                }
                continue;
            }
            if (response->tableReads >= state.MaxTableReads) {
                state.Truncated = TRUE;
                response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_BUDGET_EXHAUSTED;
                response->nextCursorAddress = pdptBase;
                break;
            }
            status = KswordARKInjectionReadPhysicalTable(pdpte & KSW_INJ_PTE_ADDR_4KB_MASK, pd);
            ++response->tableReads;
            if (!NT_SUCCESS(status)) {
                ++response->failedTableReads;
                continue;
            }

            for (pdIndex = 0UL;
                 pdIndex < KSW_INJ_ENTRIES_PER_TABLE && !state.Truncated;
                 ++pdIndex) {
                const ULONG64 pde = pd->Entries[pdIndex];
                const ULONG64 pdBase = pdptBase | (((ULONG64)pdIndex) << 21);
                ULONG ptIndex = 0UL;

                if (pdBase >= rangeEnd) {
                    break;
                }
                if (pdBase + (1ULL << 21) <= scanFrom) {
                    continue;
                }
                if ((pde & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
                    continue;
                }
                if ((pde & KSW_INJ_PTE_LARGE_BIT) != 0ULL) {
                    const ULONG flags = KswordARKInjectionMergeFlags(pml4e, pdpte, pde, pde, FALSE);
                    if (KswordARKInjectionLeafWanted(&state, flags) && pdBase >= scanFrom) {
                        KswordARKInjectionAppendLeaf(
                            &state,
                            pdBase,
                            pde & KSW_INJ_PTE_ADDR_2MB_MASK,
                            pde,
                            KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_2MB,
                            flags);
                    }
                    continue;
                }
                if (response->tableReads >= state.MaxTableReads) {
                    state.Truncated = TRUE;
                    response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_BUDGET_EXHAUSTED;
                    response->nextCursorAddress = pdBase;
                    break;
                }
                status = KswordARKInjectionReadPhysicalTable(pde & KSW_INJ_PTE_ADDR_4KB_MASK, pt);
                ++response->tableReads;
                if (!NT_SUCCESS(status)) {
                    ++response->failedTableReads;
                    continue;
                }

                for (ptIndex = 0UL;
                     ptIndex < KSW_INJ_ENTRIES_PER_TABLE && !state.Truncated;
                     ++ptIndex) {
                    const ULONG64 pte = pt->Entries[ptIndex];
                    const ULONG64 pageVa = pdBase | (((ULONG64)ptIndex) << 12);
                    ULONG flags = 0UL;

                    if (pageVa >= rangeEnd) {
                        break;
                    }
                    if (pageVa < scanFrom) {
                        continue;
                    }
                    if ((pte & KSW_INJ_PTE_PRESENT_BIT) == 0ULL) {
                        continue;
                    }
                    flags = KswordARKInjectionMergeFlags(pml4e, pdpte, pde, pte, TRUE);
                    if (!KswordARKInjectionLeafWanted(&state, flags)) {
                        continue;
                    }
                    KswordARKInjectionAppendLeaf(
                        &state,
                        pageVa,
                        pte & KSW_INJ_PTE_ADDR_4KB_MASK,
                        pte,
                        KSWORD_ARK_PAGE_TABLE_PAGE_SIZE_4KB,
                        flags);
                }
            }
        }
    }

    if (!state.Truncated) {
        KswordARKInjectionFlushRun(&state);
    }
    response->scannedEnd = state.Truncated
        ? response->nextCursorAddress
        : rangeEnd;

    if (state.Truncated) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED;
    } else if (response->failedTableReads != 0UL) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL;
    } else {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_OK;
    }

    *BytesWrittenOut =
        KSWORD_ARK_INJECTION_PTE_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount *
         sizeof(KSWORD_ARK_PROCESS_EXECUTABLE_PTE_ENTRY));
    response->size = (ULONG)*BytesWrittenOut;

    ExFreePool(pml4);
    ObDereferenceObject(processObject);
    return STATUS_SUCCESS;
}
