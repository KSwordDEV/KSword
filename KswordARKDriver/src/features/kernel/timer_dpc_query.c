/*++

Module Name:

    timer_dpc_query.c

Abstract:

    Read-only, DynData v4-backed KTIMER/KDPC enumeration.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../dyndata/dyndata_v4_internal.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h" // 候选地址统一通过安全读取器访问。
#include "timer_dpc_decode.h" // 每次快照验证 KTIMER.Dpc 的真实存储方式。

#define KSW_TIMER_DPC_POOL_TAG 'pDTK'

#if defined(_M_AMD64) || defined(_M_X64)
#define KSW_TIMER_DPC_RUNTIME_PRCB_BYTES 0x00010000UL
#define KSW_TIMER_DPC_RUNTIME_LIST_BUDGET 4096UL
#define KSW_TIMER_DPC_RUNTIME_MIN_BUCKETS 64UL
#define KSW_TIMER_DPC_RUNTIME_MAX_ENTRY_BYTES 0x80UL
#endif

typedef struct _KSW_TIMER_DPC_BUILDER
{
    KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE* Response;
    SIZE_T OutputBufferLength;
    ULONG Capacity;
    ULONG MaxEntries;
    ULONG MaxEntriesPerBucket;
    ULONG64* SeenTimers;
    ULONG SeenCount;
    KSW_DYN_V4_TIMER_DPC_LAYOUT Layout;
    KSW_TIMER_DPC_DECODER Decoder; // 当前启动参数经自建定时器校准，不跨查询缓存。
} KSW_TIMER_DPC_BUILDER;

static BOOLEAN
KswordARKTimerDpcIsKernelAddress(
    _In_ ULONG64 Address
    )
{
#if defined(_M_AMD64) || defined(_M_X64)
    return Address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart &&
        (Address >> 48U) == 0xFFFFULL;
#else
    return Address >= (ULONG64)(ULONG_PTR)MmSystemRangeStart;
#endif
}

static BOOLEAN
KswordARKTimerDpcAddAddress(
    _In_ ULONG64 Base,
    _In_ ULONG Offset,
    _Out_ ULONG64* AddressOut
    )
{
    if (AddressOut == NULL || Base > ~0ULL - (ULONG64)Offset) { // 无符号 64 位上界不依赖非 WDK 宏。
        return FALSE;
    }
    *AddressOut = Base + (ULONG64)Offset;
    return KswordARKTimerDpcIsKernelAddress(*AddressOut);
}

static BOOLEAN
KswordARKTimerDpcReadMemory(
    _In_ ULONG64 Address,
    _Out_writes_bytes_(BytesToRead) PVOID Destination,
    _In_ SIZE_T BytesToRead
    )
{
    if (Destination == NULL || BytesToRead == 0U ||
        !KswordARKTimerDpcIsKernelAddress(Address) ||
        Address > ~0ULL - (ULONG64)(BytesToRead - 1U) || // 拒绝范围尾部溢出。
        !KswordARKTimerDpcIsKernelAddress(Address + (ULONG64)(BytesToRead - 1U)) ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return FALSE;
    }

    if (!KswordARKRuntimeReadMemory( // 统一使用 MmCopyMemory，完整复制才可解释字段。
            (const VOID*)(ULONG_PTR)Address, Destination, BytesToRead)) {
        RtlZeroMemory(Destination, BytesToRead); // 失败时清除可能复制的部分字段。
        return FALSE; // 不把部分复制视为有效对象。
    }
    return TRUE;
}

#if defined(_M_AMD64) || defined(_M_X64)
static BOOLEAN
KswordARKTimerDpcAddressInsidePrcb(
    _In_ ULONG64 Address,
    _In_ ULONG64 PrcbAddress,
    _In_ SIZE_T Bytes
    )
/*++

Routine Description:

    Bound one candidate range to the current processor's conservative KPRCB
    window.  The private KPRCB type size is deliberately not assumed.

Return Value:

    TRUE when the entire range is contained by the non-wrapping window.

--*/
{
    ULONG64 prcbEnd = 0ULL;

    if (!KswordARKTimerDpcIsKernelAddress(PrcbAddress) ||
        PrcbAddress > ~0ULL - KSW_TIMER_DPC_RUNTIME_PRCB_BYTES) { // 保证 PRCB 窗口加法不回绕。
        return FALSE;
    }
    prcbEnd = PrcbAddress + KSW_TIMER_DPC_RUNTIME_PRCB_BYTES;
    return Address >= PrcbAddress && Address < prcbEnd &&
        Bytes <= (SIZE_T)(prcbEnd - Address);
}

static BOOLEAN
KswordARKTimerDpcListHeadValid(
    _In_ ULONG64 HeadAddress
    )
/*++

Routine Description:

    Validate an empty or populated LIST_ENTRY head with reciprocal first/last
    links.  This is the semantic gate used after the probe reaches KPRCB data.

Return Value:

    TRUE for a reciprocal bounded list head; otherwise FALSE.

--*/
{
    LIST_ENTRY head;
    LIST_ENTRY first;
    LIST_ENTRY last;
    ULONG64 forward = 0ULL;
    ULONG64 backward = 0ULL;

    RtlZeroMemory(&head, sizeof(head));
    RtlZeroMemory(&first, sizeof(first));
    RtlZeroMemory(&last, sizeof(last));
    if (!KswordARKTimerDpcReadMemory(HeadAddress, &head, sizeof(head))) {
        return FALSE;
    }
    forward = (ULONG64)(ULONG_PTR)head.Flink;
    backward = (ULONG64)(ULONG_PTR)head.Blink;
    if (forward == HeadAddress || backward == HeadAddress) {
        return (forward == HeadAddress && backward == HeadAddress) ? TRUE : FALSE;
    }
    if (!KswordARKTimerDpcIsKernelAddress(forward) ||
        !KswordARKTimerDpcIsKernelAddress(backward) ||
        !KswordARKTimerDpcReadMemory(forward, &first, sizeof(first)) ||
        !KswordARKTimerDpcReadMemory(backward, &last, sizeof(last))) {
        return FALSE;
    }
    return ((ULONG64)(ULONG_PTR)first.Blink == HeadAddress &&
            (ULONG64)(ULONG_PTR)last.Flink == HeadAddress)
        ? TRUE
        : FALSE;
}

static ULONG64
KswordARKTimerDpcWalkProbeToPrcb(
    _In_ ULONG64 ProbeLinkAddress,
    _In_ ULONG64 PrcbAddress,
    _In_ BOOLEAN WalkForward
    )
/*++

Routine Description:

    Follow one direction of a live probe timer's reciprocal list until the
    walk reaches the embedded bucket head inside the current KPRCB.

Return Value:

    Candidate bucket-head address, or zero on corruption/budget exhaustion.

--*/
{
    ULONG64 currentAddress = ProbeLinkAddress;
    ULONG step = 0UL;

    for (step = 0UL; step < KSW_TIMER_DPC_RUNTIME_LIST_BUDGET; ++step) {
        LIST_ENTRY current;
        LIST_ENTRY next;
        ULONG64 nextAddress = 0ULL;

        RtlZeroMemory(&current, sizeof(current));
        RtlZeroMemory(&next, sizeof(next));
        if (!KswordARKTimerDpcReadMemory(currentAddress, &current, sizeof(current))) {
            return 0ULL;
        }
        nextAddress = WalkForward
            ? (ULONG64)(ULONG_PTR)current.Flink
            : (ULONG64)(ULONG_PTR)current.Blink;
        if (nextAddress == 0ULL || nextAddress == ProbeLinkAddress ||
            !KswordARKTimerDpcIsKernelAddress(nextAddress) ||
            !KswordARKTimerDpcReadMemory(nextAddress, &next, sizeof(next))) {
            return 0ULL;
        }
        if (WalkForward) {
            if ((ULONG64)(ULONG_PTR)next.Blink != currentAddress) {
                return 0ULL;
            }
        }
        else if ((ULONG64)(ULONG_PTR)next.Flink != currentAddress) {
            return 0ULL;
        }

        if (KswordARKTimerDpcAddressInsidePrcb(
                nextAddress,
                PrcbAddress,
                sizeof(LIST_ENTRY))) {
            return KswordARKTimerDpcListHeadValid(nextAddress)
                ? nextAddress
                : 0ULL;
        }
        currentAddress = nextAddress;
    }
    return 0ULL;
}

static ULONG
KswordARKTimerDpcCountBucketRun(
    _In_ ULONG64 KnownHeadAddress,
    _In_ ULONG64 PrcbAddress,
    _In_ ULONG EntryBytes,
    _Out_ ULONG64* FirstHeadAddressOut
    )
/*++

Routine Description:

    Expand from one proven bucket head across a regular KPRCB list-head array.
    Only reciprocal heads count, and both directions are bounded by the KPRCB
    window and the public protocol's hard bucket limit.

Return Value:

    Number of contiguous heads for this stride; zero for invalid input.

--*/
{
    ULONG64 firstAddress = KnownHeadAddress;
    ULONG64 cursorAddress = KnownHeadAddress;
    ULONG beforeCount = 0UL;
    ULONG afterCount = 0UL;

    if (FirstHeadAddressOut == NULL || EntryBytes < sizeof(LIST_ENTRY) ||
        (EntryBytes & (sizeof(PVOID) - 1UL)) != 0UL) {
        return 0UL;
    }
    *FirstHeadAddressOut = 0ULL;

    while (beforeCount < KSWORD_ARK_TIMER_DPC_MAX_BUCKETS - 1UL &&
           cursorAddress >= PrcbAddress + EntryBytes) {
        const ULONG64 previousAddress = cursorAddress - EntryBytes;

        if (!KswordARKTimerDpcAddressInsidePrcb(
                previousAddress,
                PrcbAddress,
                sizeof(LIST_ENTRY)) ||
            !KswordARKTimerDpcListHeadValid(previousAddress)) {
            break;
        }
        firstAddress = previousAddress;
        cursorAddress = previousAddress;
        beforeCount += 1UL;
    }

    cursorAddress = KnownHeadAddress;
    while (beforeCount + afterCount < KSWORD_ARK_TIMER_DPC_MAX_BUCKETS - 1UL &&
           cursorAddress <= ~0ULL - EntryBytes) { // 保证下个桶头地址不回绕。
        const ULONG64 nextAddress = cursorAddress + EntryBytes;

        if (!KswordARKTimerDpcAddressInsidePrcb(
                nextAddress,
                PrcbAddress,
                sizeof(LIST_ENTRY)) ||
            !KswordARKTimerDpcListHeadValid(nextAddress)) {
            break;
        }
        cursorAddress = nextAddress;
        afterCount += 1UL;
    }

    *FirstHeadAddressOut = firstAddress;
    return beforeCount + afterCount + 1UL;
}

static BOOLEAN
KswordARKTimerDpcResolveBucketArray(
    _In_ ULONG64 KnownHeadAddress,
    _In_ ULONG64 PrcbAddress,
    _Out_ ULONG64* FirstHeadAddressOut,
    _Out_ ULONG* EntryBytesOut,
    _Out_ ULONG* BucketCountOut
    )
/*++

Routine Description:

    Select the unique regular bucket-array stride with the strongest live
    structural evidence.  A power-of-two run of at least 64 heads is required;
    ties fail closed instead of choosing a version guess.

Return Value:

    TRUE when one unique strongest layout was recovered.

--*/
{
    ULONG entryBytes = 0UL;
    ULONG bestCount = 0UL;
    ULONG bestEntryBytes = 0UL;
    ULONG64 bestFirstAddress = 0ULL;
    BOOLEAN ambiguous = FALSE;

    if (FirstHeadAddressOut == NULL || EntryBytesOut == NULL ||
        BucketCountOut == NULL) {
        return FALSE;
    }
    *FirstHeadAddressOut = 0ULL;
    *EntryBytesOut = 0UL;
    *BucketCountOut = 0UL;

    for (entryBytes = (ULONG)sizeof(LIST_ENTRY);
         entryBytes <= KSW_TIMER_DPC_RUNTIME_MAX_ENTRY_BYTES;
         entryBytes += (ULONG)sizeof(PVOID)) {
        ULONG64 firstAddress = 0ULL;
        const ULONG count = KswordARKTimerDpcCountBucketRun(
            KnownHeadAddress,
            PrcbAddress,
            entryBytes,
            &firstAddress);

        if (count < KSW_TIMER_DPC_RUNTIME_MIN_BUCKETS ||
            count > KSWORD_ARK_TIMER_DPC_MAX_BUCKETS ||
            (count & (count - 1UL)) != 0UL) {
            continue;
        }
        if (count > bestCount) {
            bestCount = count;
            bestEntryBytes = entryBytes;
            bestFirstAddress = firstAddress;
            ambiguous = FALSE;
        }
        else if (count == bestCount &&
                 (entryBytes != bestEntryBytes || firstAddress != bestFirstAddress)) {
            ambiguous = TRUE;
        }
    }

    if (bestCount == 0UL || ambiguous || bestFirstAddress < PrcbAddress ||
        bestFirstAddress - PrcbAddress > MAXULONG ||
        bestCount > MAXULONG / bestEntryBytes) {
        return FALSE;
    }
    *FirstHeadAddressOut = bestFirstAddress;
    *EntryBytesOut = bestEntryBytes;
    *BucketCountOut = bestCount;
    return TRUE;
}

static NTSTATUS
KswordARKTimerDpcResolveRuntimeLayout(
    _Out_ KSW_DYN_V4_TIMER_DPC_LAYOUT* LayoutOut
    )
/*++

Routine Description:

    Recover a normalized Timer/DPC enumeration layout without PDB data.  A
    long-due probe KTIMER is inserted on the affinity-pinned current processor,
    both reciprocal list directions must reach the same KPRCB bucket head, and
    the surrounding regular bucket array must have a unique strongest stride.
    Public WDK KTIMER/KDPC member offsets complete the read-only layout.

Return Value:

    STATUS_SUCCESS for a fully validated runtime layout; otherwise a fail-closed
    capability or data status.  The probe is cancelled on every exit path.

--*/
{
    KTIMER probeTimer;
    LARGE_INTEGER dueTime;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY targetAffinity;
    GROUP_AFFINITY previousAffinity;
    ULONG64 prcbAddress = 0ULL;
    ULONG64 probeLinkAddress = 0ULL;
    ULONG64 forwardHead = 0ULL;
    ULONG64 backwardHead = 0ULL;
    ULONG64 firstHead = 0ULL;
    ULONG entryBytes = 0UL;
    ULONG bucketCount = 0UL;
    BOOLEAN affinitySet = FALSE;
    BOOLEAN timerSet = FALSE;
    NTSTATUS status = STATUS_NOT_SUPPORTED;

    if (LayoutOut == NULL || KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    RtlZeroMemory(&probeTimer, sizeof(probeTimer));
    RtlZeroMemory(&processorNumber, sizeof(processorNumber));
    RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
    RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));

    KeGetCurrentProcessorNumberEx(&processorNumber);
    if (processorNumber.Number >= sizeof(KAFFINITY) * 8UL) {
        return STATUS_NOT_SUPPORTED;
    }
    targetAffinity.Group = processorNumber.Group;
    targetAffinity.Mask = ((KAFFINITY)1) << processorNumber.Number;
    KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
    affinitySet = TRUE;

    __try {
        prcbAddress = (ULONG64)(ULONG_PTR)KeGetPcr()->CurrentPrcb;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        goto Exit;
    }
    if (!KswordARKTimerDpcIsKernelAddress(prcbAddress)) {
        status = STATUS_DATA_ERROR;
        goto Exit;
    }

    KeInitializeTimerEx(&probeTimer, NotificationTimer);
    dueTime.QuadPart = -6000000000LL;
    (VOID)KeSetTimerEx(&probeTimer, dueTime, 0L, NULL);
    timerSet = TRUE;
    probeLinkAddress = (ULONG64)(ULONG_PTR)&probeTimer.TimerListEntry;

    forwardHead = KswordARKTimerDpcWalkProbeToPrcb(
        probeLinkAddress,
        prcbAddress,
        TRUE);
    backwardHead = KswordARKTimerDpcWalkProbeToPrcb(
        probeLinkAddress,
        prcbAddress,
        FALSE);
    if (forwardHead == 0ULL || forwardHead != backwardHead ||
        !KswordARKTimerDpcResolveBucketArray(
            forwardHead,
            prcbAddress,
            &firstHead,
            &entryBytes,
            &bucketCount)) {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    LayoutOut->KprcbTimerTable = (ULONG)(firstHead - prcbAddress);
    LayoutOut->TimerTableTimerEntries = 0UL;
    LayoutOut->TimerTableEntryLock = 0UL;
    LayoutOut->TimerTableEntryEntry = 0UL;
    LayoutOut->TimerTableEntryTime = 0UL;
    LayoutOut->TimerTimerListEntry = (ULONG)FIELD_OFFSET(KTIMER, TimerListEntry);
    LayoutOut->TimerDueTime = (ULONG)FIELD_OFFSET(KTIMER, DueTime);
    LayoutOut->TimerDpc = (ULONG)FIELD_OFFSET(KTIMER, Dpc);
    LayoutOut->TimerType = (ULONG)FIELD_OFFSET(KTIMER, Header.Type);
    LayoutOut->TimerPeriod = (ULONG)FIELD_OFFSET(KTIMER, Period);
    LayoutOut->DpcDeferredRoutine = (ULONG)FIELD_OFFSET(KDPC, DeferredRoutine);
    LayoutOut->DpcDeferredContext = (ULONG)FIELD_OFFSET(KDPC, DeferredContext);
    LayoutOut->TimerTableTypeSize = bucketCount * entryBytes;
    LayoutOut->TimerTableEntryTypeSize = entryBytes;
    LayoutOut->TimerTypeSize = (ULONG)sizeof(KTIMER);
    LayoutOut->DpcTypeSize = (ULONG)sizeof(KDPC);
    status = STATUS_SUCCESS;

Exit:
    if (timerSet) {
        (VOID)KeCancelTimer(&probeTimer);
    }
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&previousAffinity);
    }
    if (!NT_SUCCESS(status)) {
        RtlZeroMemory(LayoutOut, sizeof(*LayoutOut));
    }
    return status;
}
#endif

static BOOLEAN
KswordARKTimerDpcLayoutValid(
    _In_ const KSW_DYN_V4_TIMER_DPC_LAYOUT* Layout,
    _Out_ ULONG* BucketCountOut
    )
{
    ULONG remainingBytes = 0UL;
    ULONG bucketCount = 0UL;

    if (Layout == NULL || BucketCountOut == NULL) {
        return FALSE;
    }
    *BucketCountOut = 0UL;

    if (Layout->KprcbTimerTable == 0UL ||
        Layout->TimerTableTypeSize == 0UL ||
        Layout->TimerTableEntryTypeSize < sizeof(LIST_ENTRY) ||
        Layout->TimerTableEntryTypeSize > 0x100UL ||
        Layout->TimerTableTimerEntries >= Layout->TimerTableTypeSize ||
        Layout->TimerTableEntryEntry > Layout->TimerTableEntryTypeSize - sizeof(LIST_ENTRY) ||
        Layout->TimerTypeSize < sizeof(LIST_ENTRY) ||
        Layout->TimerTimerListEntry > Layout->TimerTypeSize - sizeof(LIST_ENTRY) ||
        Layout->TimerDueTime > Layout->TimerTypeSize - sizeof(LONGLONG) ||
        Layout->TimerDpc > Layout->TimerTypeSize - sizeof(PVOID) ||
        Layout->TimerType >= Layout->TimerTypeSize ||
        Layout->TimerPeriod > Layout->TimerTypeSize - sizeof(LONG) ||
        Layout->DpcTypeSize < sizeof(PVOID) ||
        Layout->DpcDeferredRoutine > Layout->DpcTypeSize - sizeof(PVOID) ||
        Layout->DpcDeferredContext > Layout->DpcTypeSize - sizeof(PVOID)) {
        return FALSE;
    }

    remainingBytes = Layout->TimerTableTypeSize - Layout->TimerTableTimerEntries;
    bucketCount = remainingBytes / Layout->TimerTableEntryTypeSize;
    if (bucketCount == 0UL || bucketCount > KSWORD_ARK_TIMER_DPC_MAX_BUCKETS) {
        return FALSE;
    }

    *BucketCountOut = bucketCount;
    return TRUE;
}

static BOOLEAN
KswordARKTimerDpcAlreadySeen(
    _Inout_ KSW_TIMER_DPC_BUILDER* Builder,
    _In_ ULONG64 TimerAddress
    )
{
    ULONG index = 0UL;
    for (index = 0UL; index < Builder->SeenCount; ++index) {
        if (Builder->SeenTimers[index] == TimerAddress) {
            Builder->Response->duplicateCount += 1UL;
            Builder->Response->statusFlags |= KSWORD_ARK_TIMER_DPC_STATUS_DUPLICATE_SKIPPED;
            return TRUE;
        }
    }
    if (Builder->SeenCount < Builder->MaxEntries) {
        Builder->SeenTimers[Builder->SeenCount] = TimerAddress;
        Builder->SeenCount += 1UL;
    }
    return FALSE;
}

static VOID
KswordARKTimerDpcMarkReadFailure(
    _Inout_ KSW_TIMER_DPC_BUILDER* Builder,
    _In_ BOOLEAN CorruptChain
    )
{
    Builder->Response->readFailureCount += 1UL;
    Builder->Response->statusFlags |=
        KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
        KSWORD_ARK_TIMER_DPC_STATUS_READ_FAILED;
    if (CorruptChain) {
        Builder->Response->corruptBucketCount += 1UL;
        Builder->Response->statusFlags |= KSWORD_ARK_TIMER_DPC_STATUS_CORRUPT_CHAIN;
    }
}

static VOID
KswordARKTimerDpcEmitTimer(
    _Inout_ KSW_TIMER_DPC_BUILDER* Builder,
    _In_ USHORT ProcessorGroup,
    _In_ UCHAR ProcessorNumber,
    _In_ ULONG BucketIndex,
    _In_ ULONG64 TimerAddress
    )
{
    KSWORD_ARK_TIMER_DPC_ENTRY row;
    ULONG64 fieldAddress = 0ULL;
    ULONG64 dpcAddress = 0ULL;
    ULONG64 encodedDpc = 0ULL; // KTIMER.Dpc 在新系统中包含编码，不能直接当地址。
    UCHAR timerType = 0U;
    BOOLEAN timerFieldsComplete = TRUE;

    RtlZeroMemory(&row, sizeof(row));
    row.processorGroup = ProcessorGroup;
    row.processorNumber = ProcessorNumber;
    row.bucketIndex = BucketIndex;
    row.timerAddress = TimerAddress;

    if (!KswordARKTimerDpcAddAddress(TimerAddress, Builder->Layout.TimerDueTime, &fieldAddress) ||
        !KswordARKTimerDpcReadMemory(fieldAddress, &row.dueTime, sizeof(row.dueTime))) {
        timerFieldsComplete = FALSE;
    }
    if (!KswordARKTimerDpcAddAddress(TimerAddress, Builder->Layout.TimerPeriod, &fieldAddress) ||
        !KswordARKTimerDpcReadMemory(fieldAddress, &row.period, sizeof(row.period))) {
        timerFieldsComplete = FALSE;
    }
    if (!KswordARKTimerDpcAddAddress(TimerAddress, Builder->Layout.TimerType, &fieldAddress) ||
        !KswordARKTimerDpcReadMemory(fieldAddress, &timerType, sizeof(timerType))) {
        timerFieldsComplete = FALSE;
    }
    row.timerType = timerType;
    if (row.period != 0) {
        row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_PERIODIC;
    }

    if (KswordARKTimerDpcAddAddress(TimerAddress, Builder->Layout.TimerDpc, &fieldAddress) &&
        KswordARKTimerDpcReadMemory(fieldAddress, &encodedDpc, sizeof(encodedDpc)) &&
        KswordARKTimerDpcDecodePointer(&Builder->Decoder, TimerAddress, encodedDpc, &dpcAddress)) { // 先解码再验证地址。
        row.dpcAddress = dpcAddress; // 只向用户态返回已解码的对象地址，包括真正的 NULL。
        if (dpcAddress != 0ULL) {
            row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_DPC_PRESENT;
            if (KswordARKTimerDpcIsKernelAddress(dpcAddress) &&
                KswordARKTimerDpcAddAddress(dpcAddress, Builder->Layout.DpcDeferredRoutine, &fieldAddress) &&
                KswordARKTimerDpcReadMemory(fieldAddress, &row.deferredRoutine, sizeof(row.deferredRoutine)) &&
                KswordARKTimerDpcAddAddress(dpcAddress, Builder->Layout.DpcDeferredContext, &fieldAddress) &&
                KswordARKTimerDpcReadMemory(fieldAddress, &row.deferredContext, sizeof(row.deferredContext))) {
                row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_DPC_FIELDS_PRESENT;
            }
            else {
                timerFieldsComplete = FALSE;
            }
        }
    }
    else {
        timerFieldsComplete = FALSE;
    }

    if (!timerFieldsComplete) {
        row.flags |= KSWORD_ARK_TIMER_DPC_ENTRY_READ_PARTIAL;
        Builder->Response->readFailureCount += 1UL;
        Builder->Response->statusFlags |=
            KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
            KSWORD_ARK_TIMER_DPC_STATUS_READ_FAILED;
    }

    Builder->Response->totalCount += 1UL;
    if (Builder->Response->returnedCount < Builder->Capacity) {
        Builder->Response->entries[Builder->Response->returnedCount] = row;
        Builder->Response->returnedCount += 1UL;
    }
    else {
        Builder->Response->statusFlags |=
            KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
            KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED;
    }
}

static BOOLEAN
KswordARKTimerDpcEnumerateBucket(
    _Inout_ KSW_TIMER_DPC_BUILDER* Builder,
    _In_ USHORT ProcessorGroup,
    _In_ UCHAR ProcessorNumber,
    _In_ ULONG BucketIndex,
    _In_ ULONG64 ListHeadAddress
    )
{
    LIST_ENTRY headLinks;
    ULONG64 currentAddress = 0ULL;
    ULONG64 expectedBackLink = ListHeadAddress;
    ULONG traversalCount = 0UL;

    RtlZeroMemory(&headLinks, sizeof(headLinks));
    if (!KswordARKTimerDpcReadMemory(ListHeadAddress, &headLinks, sizeof(headLinks))) {
        KswordARKTimerDpcMarkReadFailure(Builder, TRUE);
        return TRUE;
    }

    currentAddress = (ULONG64)(ULONG_PTR)headLinks.Flink;
    if (currentAddress == ListHeadAddress) {
        return TRUE;
    }
    if (!KswordARKTimerDpcIsKernelAddress(currentAddress)) {
        KswordARKTimerDpcMarkReadFailure(Builder, TRUE);
        return TRUE;
    }

    while (currentAddress != ListHeadAddress) {
        LIST_ENTRY currentLinks;
        ULONG64 timerAddress = 0ULL;
        ULONG64 nextAddress = 0ULL;

        if (Builder->SeenCount >= Builder->MaxEntries) {
            Builder->Response->statusFlags |=
                KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
                KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED;
            return FALSE;
        }
        if (traversalCount >= Builder->MaxEntriesPerBucket) {
            Builder->Response->corruptBucketCount += 1UL;
            Builder->Response->statusFlags |=
                KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL |
                KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED |
                KSWORD_ARK_TIMER_DPC_STATUS_CORRUPT_CHAIN;
            return TRUE;
        }

        RtlZeroMemory(&currentLinks, sizeof(currentLinks));
        if (!KswordARKTimerDpcReadMemory(currentAddress, &currentLinks, sizeof(currentLinks))) {
            KswordARKTimerDpcMarkReadFailure(Builder, TRUE);
            return TRUE;
        }
        if ((ULONG64)(ULONG_PTR)currentLinks.Blink != expectedBackLink ||
            currentAddress < (ULONG64)Builder->Layout.TimerTimerListEntry) {
            KswordARKTimerDpcMarkReadFailure(Builder, TRUE);
            return TRUE;
        }

        timerAddress = currentAddress - (ULONG64)Builder->Layout.TimerTimerListEntry;
        if (!KswordARKTimerDpcIsKernelAddress(timerAddress)) {
            KswordARKTimerDpcMarkReadFailure(Builder, TRUE);
            return TRUE;
        }
        if (!KswordARKTimerDpcAlreadySeen(Builder, timerAddress)) {
            KswordARKTimerDpcEmitTimer(
                Builder,
                ProcessorGroup,
                ProcessorNumber,
                BucketIndex,
                timerAddress);
        }

        nextAddress = (ULONG64)(ULONG_PTR)currentLinks.Flink;
        if (nextAddress != ListHeadAddress &&
            (!KswordARKTimerDpcIsKernelAddress(nextAddress) || nextAddress == currentAddress)) {
            KswordARKTimerDpcMarkReadFailure(Builder, TRUE);
            return TRUE;
        }
        expectedBackLink = currentAddress;
        currentAddress = nextAddress;
        traversalCount += 1UL;
    }
    return TRUE;
}

NTSTATUS
KswordARKDriverEnumerateTimerDpc(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_TIMER_DPC_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSWORD_ARK_ENUM_TIMER_DPC_REQUEST requestCopy;
    KSW_TIMER_DPC_BUILDER builder;
    ULONG bucketCount = 0UL;
    ULONG activeProcessorCount = 0UL;
    ULONG processorIndex = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || BytesWrittenOut == NULL ||
        OutputBufferLength < KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    *BytesWrittenOut = 0U;
    RtlZeroMemory(&requestCopy, sizeof(requestCopy));
    requestCopy.version = KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION;
    requestCopy.maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES;
    requestCopy.maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET;
    if (Request != NULL) {
        requestCopy = *Request;
    }
    if (requestCopy.version != KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if (requestCopy.maxEntries == 0UL || requestCopy.maxEntries > KSWORD_ARK_TIMER_DPC_MAX_ENTRIES) {
        requestCopy.maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES;
    }
    if (requestCopy.maxEntriesPerBucket == 0UL ||
        requestCopy.maxEntriesPerBucket > KSWORD_ARK_TIMER_DPC_MAX_BUCKET_BUDGET) {
        requestCopy.maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    RtlZeroMemory(&builder, sizeof(builder));
    builder.Response = (KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE*)OutputBuffer;
    builder.OutputBufferLength = OutputBufferLength;
    builder.Capacity = (ULONG)((OutputBufferLength - KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE) /
        sizeof(KSWORD_ARK_TIMER_DPC_ENTRY));
    builder.MaxEntries = requestCopy.maxEntries;
    builder.MaxEntriesPerBucket = requestCopy.maxEntriesPerBucket;
    builder.Response->version = KSWORD_ARK_TIMER_DPC_PROTOCOL_VERSION;
    builder.Response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK;
    builder.Response->entrySize = sizeof(KSWORD_ARK_TIMER_DPC_ENTRY);

#if !defined(_M_AMD64) && !defined(_M_X64)
    builder.Response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_NOT_SUPPORTED;
    builder.Response->lastStatus = STATUS_NOT_SUPPORTED;
    *BytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
    return STATUS_SUCCESS;
#else
    status = KswordARKDynDataV4SnapshotTimerDpcLayout(&builder.Layout);
    if (!NT_SUCCESS(status)) {
        status = KswordARKTimerDpcResolveRuntimeLayout(&builder.Layout);
    }
    if (!NT_SUCCESS(status)) {
        builder.Response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING;
        builder.Response->statusFlags = KSWORD_ARK_TIMER_DPC_STATUS_DYNDATA_MISSING;
        builder.Response->lastStatus = status;
        *BytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    if (!KswordARKTimerDpcLayoutValid(&builder.Layout, &bucketCount)) {
        builder.Response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_INVALID_LAYOUT;
        builder.Response->lastStatus = STATUS_DATA_ERROR;
        *BytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    builder.Response->bucketCount = bucketCount;
    (VOID)KswordARKTimerDpcInitializeDecoder( // 失败时 Decoder 保持无效，各条目仍报告部分读取。
        builder.Layout.TimerDpc, &builder.Decoder);

    builder.SeenTimers = (ULONG64*)KswordARKAllocateNonPagedPool(
        (SIZE_T)builder.MaxEntries * sizeof(ULONG64),
        KSW_TIMER_DPC_POOL_TAG);
    if (builder.SeenTimers == NULL) {
        builder.Response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL;
        builder.Response->statusFlags = KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL;
        builder.Response->lastStatus = STATUS_INSUFFICIENT_RESOURCES;
        *BytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    RtlZeroMemory(builder.SeenTimers, (SIZE_T)builder.MaxEntries * sizeof(ULONG64));

    activeProcessorCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (processorIndex = 0UL; processorIndex < activeProcessorCount; ++processorIndex) {
        PROCESSOR_NUMBER processorNumber;
        GROUP_AFFINITY targetAffinity;
        GROUP_AFFINITY previousAffinity;
        ULONG64 prcbAddress = 0ULL;
        ULONG64 timerTableAddress = 0ULL;
        ULONG bucketIndex = 0UL;
        BOOLEAN continueProcessors = TRUE;

        RtlZeroMemory(&processorNumber, sizeof(processorNumber));
        if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(processorIndex, &processorNumber)) ||
            processorNumber.Number >= (sizeof(KAFFINITY) * 8UL)) {
            KswordARKTimerDpcMarkReadFailure(&builder, FALSE);
            continue;
        }

        RtlZeroMemory(&targetAffinity, sizeof(targetAffinity));
        RtlZeroMemory(&previousAffinity, sizeof(previousAffinity));
        targetAffinity.Group = processorNumber.Group;
        targetAffinity.Mask = ((KAFFINITY)1) << processorNumber.Number;
        KeSetSystemGroupAffinityThread(&targetAffinity, &previousAffinity);
        __try {
            prcbAddress = (ULONG64)(ULONG_PTR)KeGetPcr()->CurrentPrcb;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            prcbAddress = 0ULL;
        }

        if (!KswordARKTimerDpcIsKernelAddress(prcbAddress) ||
            !KswordARKTimerDpcAddAddress(prcbAddress, builder.Layout.KprcbTimerTable, &timerTableAddress)) {
            KswordARKTimerDpcMarkReadFailure(&builder, FALSE);
        }
        else {
            builder.Response->processorCount += 1UL;
            for (bucketIndex = 0UL; bucketIndex < bucketCount; ++bucketIndex) {
                ULONG64 bucketOffset =
                    (ULONG64)builder.Layout.TimerTableTimerEntries +
                    ((ULONG64)bucketIndex * (ULONG64)builder.Layout.TimerTableEntryTypeSize) +
                    (ULONG64)builder.Layout.TimerTableEntryEntry;
                ULONG64 listHeadAddress = 0ULL;

                if (bucketOffset > MAXULONG ||
                    !KswordARKTimerDpcAddAddress(timerTableAddress, (ULONG)bucketOffset, &listHeadAddress)) {
                    KswordARKTimerDpcMarkReadFailure(&builder, TRUE);
                    break;
                }
                builder.Response->bucketsVisited += 1UL;
                continueProcessors = KswordARKTimerDpcEnumerateBucket(
                    &builder,
                    processorNumber.Group,
                    processorNumber.Number,
                    bucketIndex,
                    listHeadAddress);
                if (!continueProcessors) {
                    break;
                }
            }
        }
        KeRevertToUserGroupAffinityThread(&previousAffinity);
        if (!continueProcessors) {
            break;
        }
    }

    ExFreePoolWithTag(builder.SeenTimers, KSW_TIMER_DPC_POOL_TAG);
    builder.SeenTimers = NULL;
    if (builder.Response->statusFlags != 0UL) {
        builder.Response->queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL;
    }
    builder.Response->lastStatus = STATUS_SUCCESS;
    *BytesWrittenOut = KSWORD_ARK_ENUM_TIMER_DPC_RESPONSE_HEADER_SIZE +
        ((SIZE_T)builder.Response->returnedCount * sizeof(KSWORD_ARK_TIMER_DPC_ENTRY));
    return STATUS_SUCCESS;
#endif
}
