/*++

Module Name:

    injection_vad.c

Abstract:

    Read-only VAD tree enumeration for the injection-trace scan backend.

    这是注入痕迹检查的**第二个区域视图**。它必须直接读 EPROCESS.VadRoot 的
    平衡树，而不能转调 ZwQueryVirtualMemory —— 后者和 R3 的 VirtualQueryEx 是
    同一个来源，拿它去交叉核对等于自己和自己比，任何一致性都不构成证据。

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL only.

--*/

#include "ark/ark_driver.h"
#include "ark/ark_injection_scan.h"
#include "ark/ark_dyndata.h"
#include "../dyndata/dyndata_v4_internal.h" // Keep the optional observer offsets inside this read-only VAD request.
#include "../../platform/kernel_object_probe.h"

/*
 * 这几个例程声明在 ntifs.h 而不是 ntddk.h 里，本驱动不 include ntifs.h。
 * 与 features/memory/memory_pagetable.c 同一口径手工声明。
 */
NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

// MMVAD_SHORT / MMVAD 的布局与 features/section/section_support.c 保持一致。
// 这里重新声明而不是共享头文件，是因为本模块只需要 Core 的前半段；把 section
// 的完整结构拉进来会引入它对 ControlArea 布局的额外假设。
typedef struct _KSW_INJ_MMVAD_SHORT
{
    union _KSW_INJ_NODE_UNION
    {
        struct _KSW_INJ_NODE_FIELDS
        {
            struct _KSW_INJ_MMVAD_SHORT* NextVad;
            PVOID ExtraCreateInfo;
        } NodeFields;
        RTL_BALANCED_NODE VadNode;
    } NodeUnion;
    ULONG StartingVpn;
    ULONG EndingVpn;
#ifdef _WIN64
    UCHAR StartingVpnHigh;
    UCHAR EndingVpnHigh;
    UCHAR CommitChargeHigh;
    union _KSW_INJ_HIGHER_UNION
    {
        UCHAR SpareNT64VadUChar;
        struct _KSW_INJ_HIGHER_FIELDS
        {
            UCHAR EndingVpnHigher : 4;
            UCHAR CommitChargeHigher : 4;
        } HigherFields;
    } HigherUnion;
#endif
    LONG ReferenceCount;
    EX_PUSH_LOCK PushLock;
    ULONG LongFlags;
    ULONG LongFlags1;
#ifdef _WIN64
    union _KSW_INJ_U5
    {
        ULONG_PTR EventListULongPtr;
        UCHAR StartingVpnHigher : 4;
    } u5;
#else
    PVOID EventList;
#endif
} KSW_INJ_MMVAD_SHORT, *PKSW_INJ_MMVAD_SHORT;

typedef struct _KSW_INJ_MMVAD
{
    KSW_INJ_MMVAD_SHORT Core;
    ULONG LongFlags2;
    PVOID Subsection;
    PVOID FirstPrototypePte;
    PVOID LastContiguousPte;
    LIST_ENTRY ViewLinks;
    PVOID ProcessUnion;
} KSW_INJ_MMVAD, *PKSW_INJ_MMVAD;

/*
 * MMVAD_FLAGS 的位位置（Win10/11 x64）。DynData 只验证了 VadRoot 的偏移，
 * **没有**验证这些位的位置，所以解出来的值一律带 FLAGS_LAYOUT_ASSUMED 标记，
 * 上层不得拿它做矛盾判定。原始 LongFlags 始终一并返回。
 */
#define KSW_INJ_VAD_FLAGS_VADTYPE_SHIFT       4U
#define KSW_INJ_VAD_FLAGS_VADTYPE_MASK        0x7U
#define KSW_INJ_VAD_FLAGS_PROTECTION_SHIFT    7U
#define KSW_INJ_VAD_FLAGS_PROTECTION_MASK     0x1FU
#define KSW_INJ_VAD_FLAGS_PRIVATE_MEMORY_BIT  (1UL << 20)

// 用户地址空间上界。LA57 下和四级页表下不是一个值，所以取运行期的
// MmHighestUserAddress，不写死常量。
ULONG64
KswordARKInjectionUserAddressLimit(VOID)
{
    return (ULONG64)(ULONG_PTR)MmHighestUserAddress;
}

BOOLEAN
KswordARKInjectionReadKernel(
    _In_ const VOID* Address,
    _Out_writes_bytes_(Size) VOID* Buffer,
    _In_ SIZE_T Size
    )
/*++

Routine Description:

    PASSIVE_LEVEL 下的容错内核读。中文说明：VAD 节点地址来自被扫描进程的
    内核结构，任何一个指针都可能已经被释放或改写，所以一律走 MmCopyMemory
    的虚拟地址路径并包异常，绝不直接解引用。

Return Value:

    TRUE 表示完整读到 Size 字节。

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copied = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Address == NULL || Buffer == NULL || Size == 0U) {
        return FALSE;
    }
    if (!KswordARKKernelProbeRangeIsResident(Address, Size)) {
        return FALSE;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)Address;

    __try {
        status = MmCopyMemory(Buffer, copyAddress, Size, MM_COPY_MEMORY_VIRTUAL, &copied);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copied = 0U;
    }
    return NT_SUCCESS(status) && copied == Size;
}

static ULONG64
KswordARKInjectionVadStartVa(
    _In_ const KSW_INJ_MMVAD_SHORT* Core
    )
{
#ifdef _WIN64
    ULONG_PTR higher = Core->u5.StartingVpnHigher;
    ULONG_PTR high = Core->StartingVpnHigh;
    ULONG_PTR low = Core->StartingVpn;
    return (ULONG64)((low | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (ULONG64)((ULONG_PTR)Core->StartingVpn << PAGE_SHIFT);
#endif
}

static ULONG64
KswordARKInjectionVadEndVaExclusive(
    _In_ const KSW_INJ_MMVAD_SHORT* Core
    )
{
#ifdef _WIN64
    ULONG_PTR higher = Core->HigherUnion.HigherFields.EndingVpnHigher;
    ULONG_PTR high = Core->EndingVpnHigh;
    ULONG_PTR low = Core->EndingVpn;
    return (ULONG64)(((low + 1U) | ((high | (higher << 8)) << 32)) << PAGE_SHIFT);
#else
    return (ULONG64)(((ULONG_PTR)Core->EndingVpn + 1U) << PAGE_SHIFT);
#endif
}

static NTSTATUS
KswordARKInjectionReadVadRoot(
    _In_ PEPROCESS ProcessObject,
    _In_ const KSW_DYN_STATE* DynState,
    _Out_ PVOID* RootOut,
    _Out_ ULONG* RootOffsetOut
    )
/*++

Routine Description:

    读 EPROCESS.VadRoot。中文说明：VadRoot 是 RTL_AVL_TREE，其首个字段就是
    根节点指针。偏移必须来自 DynData 且针对当前 build 可用；不可用时直接
    失败，绝不用相近版本的偏移继续读。

Return Value:

    STATUS_NOT_SUPPORTED 表示没有可用偏移；STATUS_SUCCESS 时 *RootOut 可能为 NULL
    （空树是合法状态）。

--*/
{
    ULONG offset = 0U;
    PVOID root = NULL;

    if (RootOut == NULL || RootOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *RootOut = NULL;
    *RootOffsetOut = 0U;

    if (ProcessObject == NULL || DynState == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    offset = DynState->Kernel.EpVadRoot;
    if (offset == KSW_DYN_OFFSET_UNAVAILABLE || offset == 0U) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!KswordARKInjectionReadKernel(
            (const UCHAR*)ProcessObject + offset,
            &root,
            sizeof(root))) {
        return STATUS_ACCESS_VIOLATION;
    }
    *RootOut = root;
    *RootOffsetOut = offset;
    return STATUS_SUCCESS;
}

static VOID
KswordARKInjectionReadVadIntegrityInputs(
    _In_ PEPROCESS ProcessObject,
    _In_ const KSW_DYN_STATE* DynState,
    _Out_ PVOID* VadHintOut,
    _Out_ ULONG* VadCountOut,
    _Inout_ ULONG* FieldFlags
    )
/*++

Routine Description:

    读断链检查要用的两项：EPROCESS.VadHint 与 EPROCESS.VadCount。
    中文说明：两者都是可选的 —— 偏移不可用时对应的标志位不置，上层据此知道
    这一项"没查"，而不是"查了等于 0"。缺一项不影响另一项。

--*/
{
    ULONG offset = 0U;

    *VadHintOut = NULL;
    *VadCountOut = 0U;

    if (ProcessObject == NULL || DynState == NULL) {
        return;
    }

    offset = DynState->Kernel.EpVadHint;
    if (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0U) {
        PVOID hint = NULL;
        if (KswordARKInjectionReadKernel(
                (const UCHAR*)ProcessObject + offset, &hint, sizeof(hint))) {
            *VadHintOut = hint;
            *FieldFlags |= KSWORD_ARK_INJECTION_FIELD_VAD_HINT_PRESENT;
        }
    }

    offset = DynState->Kernel.EpVadCount;
    if (offset != KSW_DYN_OFFSET_UNAVAILABLE && offset != 0U) {
        ULONG count = 0U;
        if (KswordARKInjectionReadKernel(
                (const UCHAR*)ProcessObject + offset, &count, sizeof(count))) {
            *VadCountOut = count;
            *FieldFlags |= KSWORD_ARK_INJECTION_FIELD_VAD_COUNT_PRESENT;
        }
    }
}

typedef struct _KSW_INJ_VAD_WALK_STATE
{
    PVOID Stack[KSWORD_ARK_INJECTION_VAD_MAX_DEPTH];
    ULONG Depth;
    BOOLEAN DepthOverflow;
    ULONG UnreadableNodes;
    ULONG VisitedNodes;
    // 断链检查的账。ParentMismatch 只在能读到父节点时才累加 —— 读不到父节点
    // 记进 UnreadableNodes，不冒充"结构不一致"。
    ULONG ParentMismatchNodes;
    BOOLEAN VadHintVisited;
    PVOID VadHint;
} KSW_INJ_VAD_WALK_STATE;

/*
 * RTL_BALANCED_NODE.ParentValue 的低位是平衡位（Red:1 / Balance:2），
 * 取父指针必须先掩掉。掩错会把一个正常节点算成"父指针不一致"。
 */
#define KSW_INJ_PARENT_VALUE_MASK (~(ULONG_PTR)0x3)

static VOID
KswordARKInjectionCheckParentLink(
    _Inout_ KSW_INJ_VAD_WALK_STATE* State,
    _In_ PVOID Node,
    _In_ const KSW_INJ_MMVAD_SHORT* Core,
    _In_ PVOID Root
    )
/*++

Routine Description:

    核对一个节点的父指针是否回指得上。中文说明：摘链的常见做法是改写父节点的
    孩子指针，但不修被摘节点自己的 ParentValue，也不修被接上来的子树的
    ParentValue —— 于是树上会留下"我认它当爹、它不认我这个儿子"的节点。

    读不到父节点时**什么都不记**：那是读失败，不是结构不一致。把两者混在一起
    会让"内存换出去了"报成"树被改过"。

--*/
{
    ULONG_PTR parentValue = 0U;
    PVOID parent = NULL;
    KSW_INJ_MMVAD_SHORT parentCore;

    parentValue = (ULONG_PTR)Core->NodeUnion.VadNode.ParentValue & KSW_INJ_PARENT_VALUE_MASK;
    parent = (PVOID)parentValue;

    if (parent == NULL || parent == Node) {
        /*
         * 根节点的两种表示：ParentValue 为 0，或者指向自己。都是正常的。
         * 但**只有根**可以这样；别的节点这样就是断了。
         */
        if (Node != Root) {
            ++State->ParentMismatchNodes;
        }
        return;
    }
    if (!KswordARKInjectionReadKernel(parent, &parentCore, sizeof(parentCore))) {
        return;  // 读不到父节点 —— 不是判据，别记
    }
    if (parentCore.NodeUnion.VadNode.Children[0] != Node &&
        parentCore.NodeUnion.VadNode.Children[1] != Node) {
        ++State->ParentMismatchNodes;
    }
}

static BOOLEAN
KswordARKInjectionVadWalkPush(
    _Inout_ KSW_INJ_VAD_WALK_STATE* State,
    _In_ PVOID Node
    )
{
    if (State->Depth >= KSWORD_ARK_INJECTION_VAD_MAX_DEPTH) {
        // 真实 AVL 树不会有这个深度。到这里说明树被改写或我们把非树内存当成了
        // 树在走 —— 停下来并把不一致标出去，不要继续跟指针。
        State->DepthOverflow = TRUE;
        return FALSE;
    }
    State->Stack[State->Depth++] = Node;
    return TRUE;
}

NTSTATUS
KswordARKDriverEnumerateProcessVad(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_ENUMERATE_PROCESS_VAD_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    枚举目标进程的 VAD 树。中序遍历，按 StartingVpn 升序返回；命中条目上限时
    通过 nextCursorVpn 续扫。

Return Value:

    STATUS_SUCCESS 表示 IOCTL 已产出可读响应（失败情形写在 response->status 里）。

--*/
{
    KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE* response = NULL;
    KSW_DYN_STATE dynState;
    BOOLEAN observerLayout = FALSE; // A private VAD projection cannot grant other process capabilities.
    KSW_INJ_VAD_WALK_STATE walk;
    PEPROCESS processObject = NULL;
    PVOID root = NULL;
    PVOID current = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    size_t entryCapacity = 0U;
    ULONG maxEntries = 0UL;
    ULONG rootOffset = 0U;
    ULONG64 rangeStart = 0ULL;
    ULONG64 rangeEnd = 0ULL;
    ULONG64 cursorVpn = 0ULL;
    BOOLEAN truncated = FALSE;

    if (BytesWrittenOut == NULL || OutputBuffer == NULL || Request == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_ENUMERATE_PROCESS_VAD_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_INJECTION_SCAN_PROTOCOL_VERSION;
    response->size = (ULONG)KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE;
    response->entrySize = sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY);
    response->processId = Request->processId;
    response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_UNAVAILABLE;
    response->lastStatus = STATUS_SUCCESS;
    *BytesWrittenOut = KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE;

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

    rangeStart = Request->startAddress;
    rangeEnd = (Request->endAddress == 0ULL)
        ? (KswordARKInjectionUserAddressLimit() + 1ULL)
        : Request->endAddress;
    if (rangeEnd <= rangeStart) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_INVALID_RANGE;
        response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    cursorVpn = Request->cursorVpn;

    maxEntries = Request->maxEntries;
    if (maxEntries == 0UL) {
        maxEntries = KSWORD_ARK_INJECTION_VAD_LIMIT_DEFAULT;
    }
    if (maxEntries > KSWORD_ARK_INJECTION_VAD_LIMIT_MAX) {
        maxEntries = KSWORD_ARK_INJECTION_VAD_LIMIT_MAX;
    }
    entryCapacity =
        (OutputBufferLength - KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY);
    if (entryCapacity > (size_t)maxEntries) {
        entryCapacity = (size_t)maxEntries;
    }
    if (entryCapacity == 0U) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_BUFFER_TOO_SMALL;
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);
    if (!dynState.Kernel.EpVadRoot || dynState.Kernel.EpVadRoot == KSW_DYN_OFFSET_UNAVAILABLE) {
        KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT layout; // Copy one verified PE/RSDS generation.
        if (KswordARKDynDataV4SnapshotProcessObserver(&layout)) {
            dynState.Kernel.EpVadRoot = layout.VadRoot; // Three offsets are local to this stack frame.
            dynState.Kernel.EpVadHint = layout.VadHint; // Optional integrity witness for the existing walk.
            dynState.Kernel.EpVadCount = layout.VadCount; // No global state or writable IOCTL consumes this copy.
            observerLayout = TRUE; // Require a coherent user-address root below.
        }
    }

    status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &processObject);
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PROCESS_LOOKUP_FAILED;
        response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    status = KswordARKInjectionReadVadRoot(processObject, &dynState, &root, &rootOffset);
    if (status == STATUS_NOT_SUPPORTED) {
        // 没有经过验证的 VadRoot 偏移 —— 明确降级，不猜。
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_DYNDATA_MISSING;
        response->lastStatus = status;
        response->profileVerified = 0UL;
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED;
        response->lastStatus = status;
        ObDereferenceObject(processObject);
        return STATUS_SUCCESS;
    }

    if (observerLayout && root != NULL) {
        KSW_INJ_MMVAD_SHORT candidate; // Validate the referenced process's actual root before walking it.
        ULONG64 firstVa, endVa; // Check the inclusive/exclusive user-space extent.
        if ((ULONG_PTR)root < (ULONG_PTR)MmSystemRangeStart || ((ULONG_PTR)root & (sizeof(PVOID)-1)) ||
            !KswordARKInjectionReadKernel(root, &candidate, sizeof(candidate))) {
            response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED; // No readable kernel node at the reported root.
            response->lastStatus = STATUS_PARTIAL_COPY; // Keep unavailable pages distinct from no VADs.
            ObDereferenceObject(processObject); return STATUS_SUCCESS; // Release the validated process object.
        }
        firstVa = KswordARKInjectionVadStartVa(&candidate); // Reuse the normal node decoder.
        endVa = KswordARKInjectionVadEndVaExclusive(&candidate); // Reject wrap and implausible target ranges.
        if (firstVa >= endVa || endVa-1ULL > KswordARKInjectionUserAddressLimit()) {
            response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_WALK_FAILED; // Cannot treat a non-VAD as evidence.
            response->lastStatus = STATUS_DATA_ERROR; // This is a structural mismatch.
            ObDereferenceObject(processObject); return STATUS_SUCCESS; // Fail closed without losing ownership balance.
        }
    }
    response->profileVerified = 1UL;
    response->vadRootOffset = rootOffset;
    response->vadRootAddress = (ULONG64)(ULONG_PTR)root;
    response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_ROOT_PRESENT;

    RtlZeroMemory(&walk, sizeof(walk));
    {
        PVOID hint = NULL;
        ULONG count = 0U;
        KswordARKInjectionReadVadIntegrityInputs(
            processObject, &dynState, &hint, &count, &response->fieldFlags);
        walk.VadHint = hint;
        response->vadHintAddress = (ULONG64)(ULONG_PTR)hint;
        response->vadCount = count;
        if (observerLayout && !root && (count || hint)) {
            response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL; // An empty root and nonempty corroborating metadata disagree.
            response->lastStatus = STATUS_DATA_ERROR; // Do not publish an empty success.
            ObDereferenceObject(processObject); return STATUS_SUCCESS; // End this read-only request.
        }
    }
    current = root;

    /*
     * 迭代中序遍历。刻意不用递归：内核栈只有 12-24 KiB，一棵被改写的"树"能让
     * 递归直接踩穿栈。显式栈有硬上限，超了就停并标不一致。
     */
    while ((current != NULL || walk.Depth > 0U) && !truncated) {
        /*
         * 只读 MMVAD_SHORT。私有 VAD **就是** MMVAD_SHORT，它后面的
         * Subsection/ViewLinks 根本不存在；按 sizeof(MMVAD) 整读会跨出这次分配，
         * 短 VAD 恰好落在页尾时还会让常驻探测失败，于是一条正常的私有区域被
         * 记成"节点读不到"。Subsection 只在确认不是私有内存时单独再读一次。
         */
        KSW_INJ_MMVAD_SHORT core;
        ULONG64 startVa = 0ULL;
        ULONG64 endVa = 0ULL;
        ULONG64 startVpn = 0ULL;
        KSWORD_ARK_PROCESS_VAD_ENTRY* entry = NULL;

        if (current != NULL) {
            if (!KswordARKInjectionVadWalkPush(&walk, current)) {
                break;
            }
            if (!KswordARKInjectionReadKernel(current, &core, sizeof(core))) {
                ++walk.UnreadableNodes;
                --walk.Depth;          // 这一层读不到，退回上一层继续
                current = NULL;
                continue;
            }
            current = core.NodeUnion.VadNode.Children[0];
            continue;
        }

        current = walk.Stack[--walk.Depth];
        if (!KswordARKInjectionReadKernel(current, &core, sizeof(core))) {
            ++walk.UnreadableNodes;
            current = NULL;
            continue;
        }
        ++walk.VisitedNodes;
        KswordARKInjectionCheckParentLink(&walk, current, &core, root);
        if (walk.VadHint != NULL && current == walk.VadHint) {
            walk.VadHintVisited = TRUE;
        }

        startVa = KswordARKInjectionVadStartVa(&core);
        endVa = KswordARKInjectionVadEndVaExclusive(&core);
        startVpn = startVa >> PAGE_SHIFT;

        if (endVa > startVa && startVa < rangeEnd && endVa > rangeStart &&
            startVpn >= cursorVpn) {
            if ((size_t)response->returnedCount >= entryCapacity) {
                // 缓冲满：把下一条的 VPN 作为游标交回去，让调用方续扫。
                truncated = TRUE;
                response->nextCursorVpn = startVpn;
                response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_CURSOR_PRESENT;
                break;
            }
            entry = &response->entries[response->returnedCount];
            entry->startVa = startVa;
            entry->endVaExclusive = endVa;
            entry->vadNodeAddress = (ULONG64)(ULONG_PTR)current;
            entry->vadFlagsRaw = core.LongFlags;
            entry->vadType =
                (core.LongFlags >> KSW_INJ_VAD_FLAGS_VADTYPE_SHIFT) &
                KSW_INJ_VAD_FLAGS_VADTYPE_MASK;
            entry->protection =
                (core.LongFlags >> KSW_INJ_VAD_FLAGS_PROTECTION_SHIFT) &
                KSW_INJ_VAD_FLAGS_PROTECTION_MASK;
            entry->entryFlags = KSWORD_ARK_INJECTION_VAD_FLAG_FLAGS_LAYOUT_ASSUMED;
            if ((core.LongFlags & KSW_INJ_VAD_FLAGS_PRIVATE_MEMORY_BIT) != 0UL) {
                entry->entryFlags |= KSWORD_ARK_INJECTION_VAD_FLAG_PRIVATE_MEMORY;
            } else {
                /*
                 * 只有确认不是私有内存才去读长 VAD 的 Subsection/FirstPrototypePte。
                 * PrivateMemory 的位位置是假定的，所以这一步仍然走容错读：
                 * 位猜错时结果是"读不到 -> 留 0"，不是越界。
                 */
                PVOID subsection = NULL;
                PVOID prototypePte = NULL;
                if (KswordARKInjectionReadKernel(
                        (const UCHAR*)current + FIELD_OFFSET(KSW_INJ_MMVAD, Subsection),
                        &subsection,
                        sizeof(subsection)) &&
                    subsection != NULL) {
                    entry->entryFlags |= KSWORD_ARK_INJECTION_VAD_FLAG_HAS_SUBSECTION;
                    entry->entryFlags |= KSWORD_ARK_INJECTION_VAD_FLAG_LONG_VAD;
                    entry->subsection = (ULONG64)(ULONG_PTR)subsection;
                }
                if (KswordARKInjectionReadKernel(
                        (const UCHAR*)current + FIELD_OFFSET(KSW_INJ_MMVAD, FirstPrototypePte),
                        &prototypePte,
                        sizeof(prototypePte))) {
                    entry->firstPrototypePte = (ULONG64)(ULONG_PTR)prototypePte;
                }
            }
            ++response->returnedCount;
            response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_ENTRIES_PRESENT;
        } else if (endVa <= startVa) {
            ++walk.UnreadableNodes;
        }

        current = core.NodeUnion.VadNode.Children[1];
    }

    response->visitedCount = walk.VisitedNodes;
    response->unreadableNodeCount = walk.UnreadableNodes;
    response->parentMismatchNodes = walk.ParentMismatchNodes;
    response->vadHintVisited = walk.VadHintVisited ? 1UL : 0UL;
    if (walk.DepthOverflow) {
        response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_INCONSISTENT_WALK;
    }

    /*
     * 断链判据只在**整棵树都走完**时成立。这三个条件缺一不可：
     *   - 没有截断（否则 visitedCount 本来就少）
     *   - 没有起始游标（续扫的后半段不会重走前半段）
     *   - 没有节点读不到、没有深度溢出（漏掉的子树会让计数天然对不上）
     * 范围过滤**不影响** visitedCount —— 遍历仍然走全树，过滤只作用在返回条目上，
     * 所以这里不把 rangeStart/rangeEnd 列进条件。
     *
     * 少一个条件就会把"这次没走完"报成"有节点被摘出去了"，那是本功能最不能犯的
     * 那类错：它会在正常机器上稳定误报。
     */
    if (!truncated && cursorVpn == 0ULL && walk.UnreadableNodes == 0UL && !walk.DepthOverflow) {
        response->fieldFlags |= KSWORD_ARK_INJECTION_FIELD_INTEGRITY_VALID;
    }

    if (truncated) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED;
    } else if (walk.UnreadableNodes != 0UL || walk.DepthOverflow) {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL;
    } else {
        response->status = KSWORD_ARK_INJECTION_SCAN_STATUS_OK;
    }

    *BytesWrittenOut =
        KSWORD_ARK_INJECTION_VAD_RESPONSE_HEADER_SIZE +
        ((size_t)response->returnedCount * sizeof(KSWORD_ARK_PROCESS_VAD_ENTRY));
    response->size = (ULONG)*BytesWrittenOut;

    ObDereferenceObject(processObject);
    return STATUS_SUCCESS;
}
