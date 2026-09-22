/*++

Module Name:

    object_header_fallback.c

Abstract:

    Resolve OBJECT_HEADER counter locations without private symbols.  The body
    displacement must be encoded independently by ObGetObjectType and object
    reference/dereference exports.  The pointer-count candidate is then proved
    by a balanced temporary reference before either counter is published.

Environment:

    Kernel mode, read-only query paths at PASSIVE_LEVEL.

--*/

#include "object_header_fallback.h"
#include "../../platform/runtime_signature_scan.h"

extern POBJECT_TYPE* PsProcessType;
extern POBJECT_TYPE* PsThreadType;
NTSYSAPI NTSTATUS NTAPI PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);
NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);
NTKERNELAPI POBJECT_TYPE NTAPI ObGetObjectType(_In_ PVOID Object);

#define KSW_OBJECT_HEADER_SCAN_BYTES       0x0100UL
#define KSW_OBJECT_HEADER_MIN_BODY_OFFSET  0x0010UL
#define KSW_OBJECT_HEADER_MAX_BODY_OFFSET  0x0100UL
#define KSW_OBJECT_HEADER_MAX_COUNT        0x40000000ULL

typedef struct _KSW_OBJECT_HEADER_ANCHOR_CODE
{
    UCHAR Bytes[KSW_OBJECT_HEADER_SCAN_BYTES];
    ULONG ScanBytes;
    BOOLEAN Present;
} KSW_OBJECT_HEADER_ANCHOR_CODE, *PKSW_OBJECT_HEADER_ANCHOR_CODE;

static volatile LONG g_KswordObjectHeaderLayoutState = 0L;
static ULONG g_KswordObjectHeaderBodyOffset = 0UL;
static ULONG g_KswordObjectHeaderHandleCountOffset = 0UL;

static BOOLEAN
KswordARKObjectHeaderResolveHandleCountOffset(
    _In_ const KSW_OBJECT_HEADER_ANCHOR_CODE* Dereference,
    _In_ ULONG BodyOffset,
    _Out_ ULONG* HandleCountOffsetOut
    );

static PVOID
KswordARKObjectHeaderResolveRoutine(
    _In_z_ PCWSTR Name
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, Name);
    return MmGetSystemRoutineAddress(&routineName);
}

static BOOLEAN
KswordARKObjectHeaderCaptureAnchor(
    _In_z_ PCWSTR Name,
    _In_ ULONG ScanBytes,
    _Out_ KSW_OBJECT_HEADER_ANCHOR_CODE* Anchor
    )
{
    PVOID routine = NULL;

    if (Anchor == NULL || ScanBytes == 0UL ||
        ScanBytes > sizeof(Anchor->Bytes)) {
        return FALSE;
    }
    RtlZeroMemory(Anchor, sizeof(*Anchor));
    routine = KswordARKObjectHeaderResolveRoutine(Name);
    if (routine == NULL ||
        !KswordARKRuntimeReadMemory(
            routine,
            Anchor->Bytes,
            ScanBytes)) {
        return FALSE;
    }
    Anchor->ScanBytes = ScanBytes;
    Anchor->Present = TRUE;
    return TRUE;
}

static VOID
KswordARKObjectHeaderMarkCandidate(
    _Inout_updates_(CandidateCount) UCHAR* Candidates,
    _In_ ULONG CandidateCount,
    _In_ CHAR NegativeDisplacement
    )
{
    ULONG bodyOffset = 0UL;

    if (Candidates == NULL || NegativeDisplacement >= 0) {
        return;
    }
    bodyOffset = (ULONG)(-(LONG)NegativeDisplacement);
    if (bodyOffset < KSW_OBJECT_HEADER_MIN_BODY_OFFSET ||
        bodyOffset > KSW_OBJECT_HEADER_MAX_BODY_OFFSET ||
        (bodyOffset & (sizeof(ULONG_PTR) - 1U)) != 0U ||
        bodyOffset >= CandidateCount) {
        return;
    }
    Candidates[bodyOffset] = 1U;
}

static VOID
KswordARKObjectHeaderCollectBodyCandidates(
    _In_ const KSW_OBJECT_HEADER_ANCHOR_CODE* Anchor,
    _Out_writes_(CandidateCount) UCHAR* Candidates,
    _In_ ULONG CandidateCount
    )
{
    ULONG index = 0UL;

    RtlZeroMemory(Candidates, CandidateCount);
    if (Anchor == NULL || !Anchor->Present) {
        return;
    }
    for (index = 0UL; index + 6UL < Anchor->ScanBytes; ++index) {
        const UCHAR* code = Anchor->Bytes;

        // lea reg,[rcx-negative_disp8]
        if (code[index] == 0x48U && code[index + 1UL] == 0x8DU &&
            (code[index + 2UL] & 0xC7U) == 0x41U) {
            KswordARKObjectHeaderMarkCandidate(
                Candidates,
                CandidateCount,
                (CHAR)code[index + 3UL]);
        }
        // add rcx,negative_disp8
        if (code[index] == 0x48U && code[index + 1UL] == 0x83U &&
            code[index + 2UL] == 0xC1U) {
            KswordARKObjectHeaderMarkCandidate(
                Candidates,
                CandidateCount,
                (CHAR)code[index + 3UL]);
        }
        // lock xadd qword ptr [reg-negative_disp8],reg
        if (code[index] == 0xF0U && code[index + 1UL] == 0x48U &&
            code[index + 2UL] == 0x0FU && code[index + 3UL] == 0xC1U &&
            (code[index + 4UL] & 0xC0U) == 0x40U) {
            KswordARKObjectHeaderMarkCandidate(
                Candidates,
                CandidateCount,
                (CHAR)code[index + 5UL]);
        }
    }
}

static BOOLEAN
KswordARKObjectHeaderResolveBodyOffsetFromAnchors(
    _In_ const KSW_OBJECT_HEADER_ANCHOR_CODE* GetType,
    _In_ const KSW_OBJECT_HEADER_ANCHOR_CODE* Dereference,
    _In_ const KSW_OBJECT_HEADER_ANCHOR_CODE* ReferenceWithTag,
    _Out_ ULONG* BodyOffsetOut
    )
{
    UCHAR getTypeCandidates[KSW_OBJECT_HEADER_MAX_BODY_OFFSET + 1UL];
    UCHAR dereferenceCandidates[KSW_OBJECT_HEADER_MAX_BODY_OFFSET + 1UL];
    UCHAR referenceCandidates[KSW_OBJECT_HEADER_MAX_BODY_OFFSET + 1UL];
    ULONG offset = 0UL;
    ULONG acceptedOffset = 0UL;
    ULONG acceptedCount = 0UL;

    if (BodyOffsetOut == NULL) {
        return FALSE;
    }
    KswordARKObjectHeaderCollectBodyCandidates(
        GetType, getTypeCandidates, RTL_NUMBER_OF(getTypeCandidates));
    KswordARKObjectHeaderCollectBodyCandidates(
        Dereference, dereferenceCandidates, RTL_NUMBER_OF(dereferenceCandidates));
    KswordARKObjectHeaderCollectBodyCandidates(
        ReferenceWithTag, referenceCandidates, RTL_NUMBER_OF(referenceCandidates));

    for (offset = KSW_OBJECT_HEADER_MIN_BODY_OFFSET;
        offset <= KSW_OBJECT_HEADER_MAX_BODY_OFFSET;
        offset += sizeof(ULONG_PTR)) {
        ULONG support = (ULONG)getTypeCandidates[offset] +
            (ULONG)dereferenceCandidates[offset] +
            (ULONG)referenceCandidates[offset];

        if (support >= 2UL) {
            acceptedOffset = offset;
            acceptedCount += 1UL;
        }
    }
    if (acceptedCount != 1UL) {
        return FALSE;
    }
    *BodyOffsetOut = acceptedOffset;
    return TRUE;
}

static NTSTATUS
KswordARKObjectHeaderResolveCachedLayout(
    _Out_ ULONG* BodyOffsetOut,
    _Out_ ULONG* HandleCountOffsetOut
    )
{
    LONG state = 0L;
    ULONG spin = 0UL;

    if (BodyOffsetOut == NULL || HandleCountOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    state = InterlockedCompareExchange(&g_KswordObjectHeaderLayoutState, 0L, 0L);
    if (state == 2L) {
        *BodyOffsetOut = g_KswordObjectHeaderBodyOffset;
        *HandleCountOffsetOut = g_KswordObjectHeaderHandleCountOffset;
        return STATUS_SUCCESS;
    }
    if (state < 0L) {
        return STATUS_NOT_SUPPORTED;
    }

    if (InterlockedCompareExchange(
            &g_KswordObjectHeaderLayoutState,
            1L,
            0L) == 0L) {
        KSW_OBJECT_HEADER_ANCHOR_CODE getType;
        KSW_OBJECT_HEADER_ANCHOR_CODE dereference;
        KSW_OBJECT_HEADER_ANCHOR_CODE referenceWithTag;
        ULONG bodyOffset = 0UL;
        ULONG handleOffset = 0UL;
        BOOLEAN resolved = FALSE;

        resolved = KswordARKObjectHeaderCaptureAnchor(
                L"ObGetObjectType", 0x40UL, &getType) &&
            KswordARKObjectHeaderCaptureAnchor(
                L"ObfDereferenceObject", 0x80UL, &dereference) &&
            KswordARKObjectHeaderCaptureAnchor(
                L"ObfReferenceObjectWithTag", 0x80UL, &referenceWithTag) &&
            KswordARKObjectHeaderResolveBodyOffsetFromAnchors(
                &getType,
                &dereference,
                &referenceWithTag,
                &bodyOffset);
        if (!resolved) {
            InterlockedExchange(&g_KswordObjectHeaderLayoutState, -1L);
            return STATUS_NOT_SUPPORTED;
        }

        // HandleCount is not read by every ObfDereferenceObject build.  Keep
        // it optional so a missing secondary pattern cannot discard the
        // independently proved body/PointerCount layout.
        (VOID)KswordARKObjectHeaderResolveHandleCountOffset(
            &dereference,
            bodyOffset,
            &handleOffset);
        g_KswordObjectHeaderBodyOffset = bodyOffset;
        g_KswordObjectHeaderHandleCountOffset = handleOffset;
        InterlockedExchange(&g_KswordObjectHeaderLayoutState, 2L);
        *BodyOffsetOut = bodyOffset;
        *HandleCountOffsetOut = handleOffset;
        return STATUS_SUCCESS;
    }

    for (spin = 0UL; spin < 4096UL; ++spin) {
        YieldProcessor();
        state = InterlockedCompareExchange(
            &g_KswordObjectHeaderLayoutState,
            0L,
            0L);
        if (state != 1L) {
            break;
        }
    }
    if (state != 2L) {
        return (state < 0L) ? STATUS_NOT_SUPPORTED : STATUS_RETRY;
    }
    *BodyOffsetOut = g_KswordObjectHeaderBodyOffset;
    *HandleCountOffsetOut = g_KswordObjectHeaderHandleCountOffset;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKObjectHeaderResolveBodyOffsetFallback(
    _Out_ ULONG* BodyOffsetOut
    )
{
    ULONG handleCountOffset = 0UL;

    if (BodyOffsetOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    return KswordARKObjectHeaderResolveCachedLayout(
        BodyOffsetOut,
        &handleCountOffset);
}

static BOOLEAN
KswordARKObjectHeaderResolveHandleCountOffset(
    _In_ const KSW_OBJECT_HEADER_ANCHOR_CODE* Dereference,
    _In_ ULONG BodyOffset,
    _Out_ ULONG* HandleCountOffsetOut
    )
{
    ULONG index = 0UL;
    ULONG candidate = 0UL;
    ULONG candidateCount = 0UL;

    if (Dereference == NULL || !Dereference->Present ||
        HandleCountOffsetOut == NULL) {
        return FALSE;
    }
    for (index = 0UL; index + 9UL < Dereference->ScanBytes; ++index) {
        const UCHAR* code = Dereference->Bytes;
        UCHAR headerRegister = 0U;
        ULONG search = 0UL;

        if (code[index] != 0x48U || code[index + 1UL] != 0x8DU ||
            (code[index + 2UL] & 0xC7U) != 0x41U ||
            (CHAR)code[index + 3UL] >= 0 ||
            (ULONG)(-(LONG)(CHAR)code[index + 3UL]) != BodyOffset) {
            continue;
        }
        headerRegister = (UCHAR)((code[index + 2UL] >> 3U) & 7U);
        for (search = index + 4UL;
            search + 5UL < Dereference->ScanBytes && search <= index + 80UL;
            ++search) {
            if (code[search] == 0xF0U && code[search + 1UL] == 0x48U &&
                code[search + 2UL] == 0x0FU && code[search + 3UL] == 0xC1U &&
                (code[search + 4UL] & 0xC0U) == 0x00U &&
                (code[search + 4UL] & 7U) == headerRegister) {
                ULONG readSearch = 0UL;

                for (readSearch = search + 5UL;
                    readSearch + 3UL < Dereference->ScanBytes &&
                        readSearch <= search + 48UL;
                    ++readSearch) {
                    UCHAR displacement = 0U;

                    if (code[readSearch] != 0x48U ||
                        code[readSearch + 1UL] != 0x8BU ||
                        (code[readSearch + 2UL] & 0xC0U) != 0x40U ||
                        (code[readSearch + 2UL] & 7U) != headerRegister) {
                        continue;
                    }
                    displacement = code[readSearch + 3UL];
                    if (displacement == 0U || displacement > 0x20U ||
                        (displacement & (sizeof(ULONG_PTR) - 1U)) != 0U) {
                        continue;
                    }
                    if (candidateCount == 0UL || candidate == displacement) {
                        candidate = displacement;
                        candidateCount = 1UL;
                    }
                    else {
                        return FALSE;
                    }
                }
                break;
            }
        }
    }
    if (candidateCount != 1UL) {
        return FALSE;
    }
    *HandleCountOffsetOut = candidate;
    return TRUE;
}

NTSTATUS
KswordARKObjectHeaderQueryFallback(
    _In_ PVOID Object,
    _Out_ KSW_OBJECT_HEADER_FALLBACK_RESULT* Result
    )
{
    ULONG bodyOffset = 0UL;
    ULONG handleOffset = 0UL;
    ULONG_PTR header = 0U;
    LONG_PTR pointerBefore = 0;
    LONG_PTR pointerDuring = 0;
    LONG_PTR pointerAfter = 0;
    LONG_PTR handleCount = 0;
    BOOLEAN handleCountValid = FALSE;

    if (Object == NULL || Result == NULL ||
        KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(*Result));
    if (!NT_SUCCESS(KswordARKObjectHeaderResolveCachedLayout(
            &bodyOffset,
            &handleOffset)) ||
        (ULONG_PTR)Object < bodyOffset) {
        return STATUS_NOT_SUPPORTED;
    }
    header = (ULONG_PTR)Object - bodyOffset;
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)header,
            &pointerBefore,
            sizeof(pointerBefore)) ||
        pointerBefore <= 0 ||
        (ULONG64)pointerBefore > KSW_OBJECT_HEADER_MAX_COUNT) {
        return STATUS_DATA_ERROR;
    }

    if (handleOffset != 0UL &&
        KswordARKRuntimeReadMemory(
            (const VOID*)(header + handleOffset),
            &handleCount,
            sizeof(handleCount)) &&
        handleCount >= 0 &&
        (ULONG64)handleCount <= KSW_OBJECT_HEADER_MAX_COUNT &&
        handleCount <= pointerBefore) {
        handleCountValid = TRUE;
    }

    ObReferenceObject(Object);
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)header,
            &pointerDuring,
            sizeof(pointerDuring))) {
        ObDereferenceObject(Object);
        return STATUS_PARTIAL_COPY;
    }
    ObDereferenceObject(Object);
    if (!KswordARKRuntimeReadMemory(
            (const VOID*)header,
            &pointerAfter,
            sizeof(pointerAfter)) ||
        pointerDuring != pointerBefore + 1 ||
        pointerAfter != pointerBefore ||
        (ULONG64)pointerDuring > MAXULONG) {
        return STATUS_DATA_ERROR;
    }

    Result->ValidFields = KSW_OBJECT_HEADER_FALLBACK_FIELD_POINTER_COUNT;
    Result->BodyOffset = bodyOffset;
    Result->PointerCountOffset = 0UL;
    Result->PointerCount = (ULONG)pointerAfter;
    if (handleCountValid && (ULONG64)handleCount <= MAXULONG) {
        Result->ValidFields |= KSW_OBJECT_HEADER_FALLBACK_FIELD_HANDLE_COUNT;
        Result->HandleCountOffset = handleOffset;
        Result->HandleCount = (ULONG)handleCount;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKObjectHeaderReferenceObjectSafe(
    _In_ PVOID Object,
    _In_ HANDLE ObjectId,
    _In_ POBJECT_TYPE ExpectedObjectType
    )
{
    PVOID referenced = NULL;
    NTSTATUS status;

    if (Object == NULL || ObjectId == NULL || ExpectedObjectType == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (PsProcessType != NULL && ExpectedObjectType == *PsProcessType) {
        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId(ObjectId, &process);
        referenced = process;
    }
    else if (PsThreadType != NULL && ExpectedObjectType == *PsThreadType) {
        PETHREAD thread = NULL;
        status = PsLookupThreadByThreadId(ObjectId, &thread);
        referenced = thread;
    }
    else {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (referenced == NULL) {
        return STATUS_DATA_ERROR;
    }
    /* Only the lookup result owns a reference; never dereference the candidate
       on failure. An ID recycled to a different address is not this observation. */
    if (referenced != Object) {
        ObDereferenceObject(referenced);
        return STATUS_REVISION_MISMATCH;
    }
    if (ObGetObjectType(referenced) != ExpectedObjectType) {
        ObDereferenceObject(referenced);
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    return STATUS_SUCCESS;
}
