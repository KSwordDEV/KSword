/*++

Module Name:

    bugcheck_bgp.c

Abstract:

    Fail-closed physical-machine BGP resolver and crash-time drawing adapter.
    The private-kernel feature resolver follows the DriverGUI BgpDraw backend.

--*/

#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"
#include "../../platform/pool_compat.h"
#include "../../platform/runtime_signature_scan.h"

#include <aux_klib.h>
#include <ntimage.h>

#include "Generated/BgpSignatures.h"

#define KSWORD_ARK_BGP_POOL_TAG 'pBgK'
#define KSWORD_ARK_BGP_SCAN_POOL_TAG 'sBgK'
#define KSWORD_ARK_BGP_MAX_IMAGE_SECTIONS 96UL
#define KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE (64UL * 1024UL)
#define KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES \
    (KSWORD_ARK_BGP_FEATURE_CLEAR | KSWORD_ARK_BGP_FEATURE_DRAW | \
     KSWORD_ARK_BGP_FEATURE_ACQUIRE | KSWORD_ARK_BGP_FEATURE_RELEASE | \
     KSWORD_ARK_BGP_FEATURE_RESOLUTION | KSWORD_ARK_BGP_FEATURE_BPP | \
     KSWORD_ARK_BGP_FEATURE_PARSE | KSWORD_ARK_BGP_FEATURE_DESTROY)

typedef struct _KSWORD_ARK_BGP_IMAGE_SECTION
{
    UCHAR Name[IMAGE_SIZEOF_SHORT_NAME];
    ULONG VirtualAddress;
    ULONG VirtualSize;
    ULONG Characteristics;
} KSWORD_ARK_BGP_IMAGE_SECTION, *PKSWORD_ARK_BGP_IMAGE_SECTION;

typedef struct _KSWORD_ARK_BGP_IMAGE_VIEW
{
    PUCHAR ImageBase;
    ULONG ImageSize;
    ULONG SectionCount;
    KSWORD_ARK_BGP_IMAGE_SECTION Sections[KSWORD_ARK_BGP_MAX_IMAGE_SECTIONS];
} KSWORD_ARK_BGP_IMAGE_VIEW, *PKSWORD_ARK_BGP_IMAGE_VIEW;

KSWORD_ARK_BGP_CONTEXT g_KswordArkBgp;

VOID
KswordARKBugcheckBgpRecordStage(
    _In_ LONG Stage,
    _In_ NTSTATUS Status
    )
{
    LONG timelineIndex;

    timelineIndex = InterlockedIncrement(&g_KswordArkBgp.TimelineCount) - 1;
    InterlockedExchange(&g_KswordArkBgp.Stage, Stage);
    if (timelineIndex >= 0 &&
        timelineIndex < (LONG)RTL_NUMBER_OF(g_KswordArkBgp.Timeline)) {
        InterlockedExchange(
            &g_KswordArkBgp.Timeline[timelineIndex].Status,
            (LONG)Status);
        InterlockedExchange(
            &g_KswordArkBgp.Timeline[timelineIndex].Stage,
            Stage);
    }
}

static PVOID
KswordARKBugcheckBgpGetExport(
    _In_z_ PCWSTR Name
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, Name);
    return MmGetSystemRoutineAddress(&routineName);
}

static BOOLEAN
KswordARKBugcheckBgpRvaRangeValid(
    _In_ ULONG ImageSize,
    _In_ ULONG Rva,
    _In_ SIZE_T RequiredBytes
    )
{
    return ImageSize != 0UL &&
        RequiredBytes != 0U &&
        Rva < ImageSize &&
        RequiredBytes <= (SIZE_T)(ImageSize - Rva);
}

static BOOLEAN
KswordARKBugcheckBgpAddressForRva(
    _In_ const KSWORD_ARK_BGP_IMAGE_VIEW* View,
    _In_ ULONG Rva,
    _In_ SIZE_T RequiredBytes,
    _Out_ PUCHAR* AddressOut
    )
{
    ULONG_PTR base;

    if (View == NULL || AddressOut == NULL || View->ImageBase == NULL ||
        !KswordARKBugcheckBgpRvaRangeValid(
            View->ImageSize,
            Rva,
            RequiredBytes)) {
        return FALSE;
    }

    base = (ULONG_PTR)View->ImageBase;
    if (base > MAXULONG_PTR - Rva) {
        return FALSE;
    }
    *AddressOut = (PUCHAR)(base + Rva);
    return TRUE;
}

static BOOLEAN
KswordARKBugcheckBgpInitializeImageView(
    _In_reads_bytes_(ImageSize) PUCHAR ImageBase,
    _In_ ULONG ImageSize,
    _Out_ PKSWORD_ARK_BGP_IMAGE_VIEW View
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG ntHeadersRva;
    ULONG sectionHeadersRva;
    ULONG sectionHeadersBytes;
    ULONG sectionIndex;
    ULONG_PTR base;
    PUCHAR ntHeadersAddress;

    if (View == NULL) {
        return FALSE;
    }
    RtlZeroMemory(View, sizeof(*View));
    if (ImageBase == NULL || ImageSize < sizeof(dosHeader) ||
        !KswordARKRuntimeReadMemory(
            ImageBase,
            &dosHeader,
            sizeof(dosHeader)) ||
        dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0) {
        return FALSE;
    }

    base = (ULONG_PTR)ImageBase;
    ntHeadersRva = (ULONG)dosHeader.e_lfanew;
    if (!KswordARKBugcheckBgpRvaRangeValid(
            ImageSize,
            ntHeadersRva,
            sizeof(ntHeaders)) ||
        base > MAXULONG_PTR - ntHeadersRva) {
        return FALSE;
    }
    ntHeadersAddress = (PUCHAR)(base + ntHeadersRva);
    if (!KswordARKRuntimeReadMemory(
            ntHeadersAddress,
            &ntHeaders,
            sizeof(ntHeaders)) ||
        ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 ||
        ntHeaders.FileHeader.SizeOfOptionalHeader <
            sizeof(IMAGE_OPTIONAL_HEADER64) ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage == 0UL ||
        ntHeaders.OptionalHeader.SizeOfImage > ImageSize ||
        ntHeaders.FileHeader.NumberOfSections == 0U ||
        ntHeaders.FileHeader.NumberOfSections >
            KSWORD_ARK_BGP_MAX_IMAGE_SECTIONS) {
        return FALSE;
    }

    if (ntHeadersRva >
            MAXULONG - FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) ||
        ntHeadersRva + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) >
            MAXULONG - ntHeaders.FileHeader.SizeOfOptionalHeader) {
        return FALSE;
    }
    sectionHeadersRva =
        ntHeadersRva +
        FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        ntHeaders.FileHeader.SizeOfOptionalHeader;
    sectionHeadersBytes =
        (ULONG)ntHeaders.FileHeader.NumberOfSections *
        (ULONG)sizeof(IMAGE_SECTION_HEADER);
    if (!KswordARKBugcheckBgpRvaRangeValid(
            ntHeaders.OptionalHeader.SizeOfImage,
            sectionHeadersRva,
            sectionHeadersBytes)) {
        return FALSE;
    }

    if (base > MAXULONG_PTR - ntHeaders.OptionalHeader.SizeOfImage) {
        return FALSE;
    }
    View->ImageBase = ImageBase;
    View->ImageSize = ntHeaders.OptionalHeader.SizeOfImage;

    for (sectionIndex = 0;
         sectionIndex < ntHeaders.FileHeader.NumberOfSections;
         ++sectionIndex) {
        IMAGE_SECTION_HEADER sectionHeader;
        PKSWORD_ARK_BGP_IMAGE_SECTION section;
        ULONG sectionHeaderRva;
        ULONG sectionSize;
        ULONG priorIndex;
        PUCHAR sectionHeaderAddress;

        sectionHeaderRva = sectionHeadersRva +
            sectionIndex * (ULONG)sizeof(sectionHeader);
        if (!KswordARKBugcheckBgpRvaRangeValid(
                View->ImageSize,
                sectionHeaderRva,
                sizeof(sectionHeader)) ||
            !KswordARKBugcheckBgpAddressForRva(
                View,
                sectionHeaderRva,
                sizeof(sectionHeader),
                &sectionHeaderAddress) ||
            !KswordARKRuntimeReadMemory(
                sectionHeaderAddress,
                &sectionHeader,
                sizeof(sectionHeader))) {
            RtlZeroMemory(View, sizeof(*View));
            return FALSE;
        }

        sectionSize = max(
            sectionHeader.Misc.VirtualSize,
            sectionHeader.SizeOfRawData);
        if (sectionSize == 0UL) {
            continue;
        }
        if (!KswordARKBugcheckBgpRvaRangeValid(
                View->ImageSize,
                sectionHeader.VirtualAddress,
                sectionSize)) {
            RtlZeroMemory(View, sizeof(*View));
            return FALSE;
        }

        for (priorIndex = 0;
             priorIndex < View->SectionCount;
             ++priorIndex) {
            const KSWORD_ARK_BGP_IMAGE_SECTION* prior;
            ULONG priorEnd;
            ULONG sectionEnd;

            prior = &View->Sections[priorIndex];
            priorEnd = prior->VirtualAddress + prior->VirtualSize;
            sectionEnd = sectionHeader.VirtualAddress + sectionSize;
            if (sectionHeader.VirtualAddress < priorEnd &&
                prior->VirtualAddress < sectionEnd) {
                RtlZeroMemory(View, sizeof(*View));
                return FALSE;
            }
        }

        section = &View->Sections[View->SectionCount++];
        RtlCopyMemory(
            section->Name,
            sectionHeader.Name,
            sizeof(section->Name));
        section->VirtualAddress = sectionHeader.VirtualAddress;
        section->VirtualSize = sectionSize;
        section->Characteristics = sectionHeader.Characteristics;
    }

    if (View->SectionCount == 0UL) {
        RtlZeroMemory(View, sizeof(*View));
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordARKBugcheckBgpAddressInSection(
    _In_ const KSWORD_ARK_BGP_IMAGE_VIEW* View,
    _In_opt_ PVOID Address,
    _In_ SIZE_T RequiredBytes,
    _In_ BOOLEAN AllowPaged
    )
{
    ULONG_PTR addressValue;
    ULONG_PTR imageBase;
    ULONG_PTR addressRva;
    ULONG sectionIndex;

    if (View == NULL || View->ImageBase == NULL || Address == NULL ||
        RequiredBytes == 0U) {
        return FALSE;
    }
    addressValue = (ULONG_PTR)Address;
    imageBase = (ULONG_PTR)View->ImageBase;
    if (addressValue < imageBase) {
        return FALSE;
    }
    addressRva = addressValue - imageBase;
    if (addressRva > MAXULONG ||
        !KswordARKBugcheckBgpRvaRangeValid(
            View->ImageSize,
            (ULONG)addressRva,
            RequiredBytes)) {
        return FALSE;
    }

    for (sectionIndex = 0;
         sectionIndex < View->SectionCount;
         ++sectionIndex) {
        const KSWORD_ARK_BGP_IMAGE_SECTION* section;
        ULONG offsetInSection;

        section = &View->Sections[sectionIndex];
        if ((ULONG)addressRva < section->VirtualAddress ||
            (ULONG)addressRva >=
                section->VirtualAddress + section->VirtualSize) {
            continue;
        }
        offsetInSection = (ULONG)addressRva - section->VirtualAddress;
        if (RequiredBytes >
                (SIZE_T)(section->VirtualSize - offsetInSection) ||
            (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0UL ||
            (!AllowPaged &&
             (section->Characteristics & IMAGE_SCN_MEM_NOT_PAGED) == 0UL)) {
            return FALSE;
        }
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN
KswordARKBugcheckBgpMatches(
    _In_reads_bytes_(Signature->Length) const UCHAR* Address,
    _In_ const BGP_SIGNATURE* Signature
    )
{
    ULONG byteIndex;

    for (byteIndex = 0; byteIndex < Signature->Length; ++byteIndex) {
        if (Signature->Mask[byteIndex] == 'x' &&
            Address[byteIndex] != Signature->Bytes[byteIndex]) {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOLEAN
KswordARKBugcheckBgpSectionNameMatches(
    _In_reads_(IMAGE_SIZEOF_SHORT_NAME) const UCHAR* Actual,
    _In_z_ const CHAR* Expected
    )
{
    ULONG characterIndex;

    for (characterIndex = 0;
         characterIndex < IMAGE_SIZEOF_SHORT_NAME;
         ++characterIndex) {
        if ((CHAR)Actual[characterIndex] != Expected[characterIndex]) {
            return FALSE;
        }
        if (Actual[characterIndex] == '\0') {
            return TRUE;
        }
    }

    return Expected[IMAGE_SIZEOF_SHORT_NAME] == '\0';
}

static BOOLEAN
KswordARKBugcheckBgpDecodeRelativeCallAt(
    _In_reads_bytes_(Length) const UCHAR* Bytes,
    _In_ ULONG Length,
    _In_ ULONG Offset,
    _In_ ULONG_PTR OriginalAddress,
    _Out_ PVOID* TargetOut
    )
{
    LONG displacement;
    ULONG_PTR nextInstruction;
    ULONG_PTR target;
    ULONG_PTR magnitude;

    if (Bytes == NULL || TargetOut == NULL || Offset > Length ||
        Length - Offset < 5UL || Bytes[Offset] != 0xE8U ||
        OriginalAddress > MAXULONG_PTR - Offset) {
        return FALSE;
    }
    *TargetOut = NULL;

    nextInstruction = OriginalAddress + Offset;
    if (nextInstruction > MAXULONG_PTR - 5UL) {
        return FALSE;
    }
    nextInstruction += 5UL;
    RtlCopyMemory(&displacement, Bytes + Offset + 1UL, sizeof(displacement));

    if (displacement >= 0) {
        if (nextInstruction > MAXULONG_PTR - (ULONG)displacement) {
            return FALSE;
        }
        target = nextInstruction + (ULONG)displacement;
    } else {
        magnitude = (ULONG_PTR)(-(LONGLONG)displacement);
        if (nextInstruction < magnitude) {
            return FALSE;
        }
        target = nextInstruction - magnitude;
    }

    *TargetOut = (PVOID)target;
    return TRUE;
}

static VOID
KswordARKBugcheckBgpAcceptSignatureMatch(
    _In_ const KSWORD_ARK_BGP_IMAGE_VIEW* View,
    _In_ const BGP_SIGNATURE* Signature,
    _In_ PUCHAR OriginalMatch,
    _In_reads_bytes_(Signature->Length) const UCHAR* SnapshotMatch,
    _Inout_updates_(BgpSignatureCount) PVOID* Addresses,
    _Inout_updates_(BgpSignatureCount) const BGP_SIGNATURE** MatchedSignatures,
    _Inout_updates_(BgpSignatureCount) PVOID* DirectCallTargets,
    _Inout_updates_(BgpSignatureCount) BOOLEAN* Ambiguous
    )
{
    PVOID directCallTarget;
    PVOID resolvedAddress;
    ULONG_PTR matchAddress;
    ULONG targetIndex;

    if (View == NULL || Signature == NULL || OriginalMatch == NULL ||
        SnapshotMatch == NULL || Addresses == NULL ||
        MatchedSignatures == NULL || DirectCallTargets == NULL ||
        Ambiguous == NULL) {
        return;
    }

    targetIndex = Signature->Target;
    matchAddress = (ULONG_PTR)OriginalMatch;
    if (targetIndex >= BgpSignatureCount ||
        matchAddress < Signature->EntryOffset) {
        return;
    }
    resolvedAddress = (PVOID)(matchAddress - Signature->EntryOffset);
    if (!KswordARKBugcheckBgpAddressInSection(
            View,
            resolvedAddress,
            1U,
            Signature->AllowPaged)) {
        return;
    }

    directCallTarget = NULL;
    if (Signature->DirectCallOffset != MAXULONG) {
        if (!KswordARKBugcheckBgpDecodeRelativeCallAt(
                SnapshotMatch,
                Signature->Length,
                Signature->DirectCallOffset,
                matchAddress,
                &directCallTarget) ||
            !KswordARKBugcheckBgpAddressInSection(
                View,
                directCallTarget,
                1U,
                TRUE)) {
            return;
        }
    } else if ((Signature->SemanticFlags &
                BGP_SEMANTIC_REQUIRE_DIRECT_CALL) != 0UL) {
        return;
    }

    if (Addresses[targetIndex] == NULL) {
        Addresses[targetIndex] = resolvedAddress;
        MatchedSignatures[targetIndex] = Signature;
        DirectCallTargets[targetIndex] = directCallTarget;
    } else if (Addresses[targetIndex] != resolvedAddress ||
               DirectCallTargets[targetIndex] != directCallTarget) {
        Ambiguous[targetIndex] = TRUE;
    }
}

static NTSTATUS
KswordARKBugcheckBgpValidateSignatureTable(
    _Out_ PULONG MaximumAnchorPrefix,
    _Out_ PULONG MaximumAnchorSuffix
    )
{
    ULONG bucketIndex;
    ULONG signatureIndex;

    if (MaximumAnchorPrefix == NULL || MaximumAnchorSuffix == NULL ||
        BGP_SIGNATURE_ANCHOR_BUCKETS == 0UL ||
        (BGP_SIGNATURE_ANCHOR_BUCKETS &
         (BGP_SIGNATURE_ANCHOR_BUCKETS - 1UL)) != 0UL ||
        g_BgpSignatureAnchorBuckets[0] != 0UL ||
        g_BgpSignatureAnchorBuckets[BGP_SIGNATURE_ANCHOR_BUCKETS] !=
            BGP_SIGNATURE_TABLE_COUNT) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *MaximumAnchorPrefix = 0UL;
    *MaximumAnchorSuffix = 0UL;
    for (bucketIndex = 0;
         bucketIndex < BGP_SIGNATURE_ANCHOR_BUCKETS;
         ++bucketIndex) {
        if (g_BgpSignatureAnchorBuckets[bucketIndex] >
                g_BgpSignatureAnchorBuckets[bucketIndex + 1UL] ||
            g_BgpSignatureAnchorBuckets[bucketIndex + 1UL] >
                BGP_SIGNATURE_TABLE_COUNT) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }
    }

    for (signatureIndex = 0;
         signatureIndex < BGP_SIGNATURE_TABLE_COUNT;
         ++signatureIndex) {
        const BGP_SIGNATURE* signature;
        ULONG nameIndex;
        ULONG anchorSuffix;
        BOOLEAN sectionNameTerminated;

        signature = &g_BgpSignatures[signatureIndex];
        sectionNameTerminated = FALSE;
        if (signature->Section != NULL) {
            for (nameIndex = 0;
                 nameIndex <= IMAGE_SIZEOF_SHORT_NAME;
                 ++nameIndex) {
                if (signature->Section[nameIndex] == '\0') {
                    sectionNameTerminated = TRUE;
                    break;
                }
            }
        }

        if (signature->Bytes == NULL || signature->Mask == NULL ||
            !sectionNameTerminated || signature->Length < sizeof(ULONG) ||
            signature->AnchorOffset >
                signature->Length - sizeof(ULONG) ||
            signature->Target >= BgpSignatureCount ||
            (signature->DirectCallOffset != MAXULONG &&
             (signature->DirectCallOffset > signature->Length ||
              signature->Length - signature->DirectCallOffset < 5UL)) ||
            ((signature->SemanticFlags &
              BGP_SEMANTIC_REQUIRE_DIRECT_CALL) != 0UL &&
             signature->DirectCallOffset == MAXULONG)) {
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        anchorSuffix = signature->Length - signature->AnchorOffset;
        *MaximumAnchorPrefix = max(
            *MaximumAnchorPrefix,
            signature->AnchorOffset);
        *MaximumAnchorSuffix = max(
            *MaximumAnchorSuffix,
            anchorSuffix);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKBugcheckBgpScanSignatures(
    _In_ const KSWORD_ARK_BGP_IMAGE_VIEW* View,
    _Inout_updates_(BgpSignatureCount) PVOID* Addresses,
    _Inout_updates_(BgpSignatureCount) const BGP_SIGNATURE** MatchedSignatures,
    _Inout_updates_(BgpSignatureCount) PVOID* DirectCallTargets,
    _Inout_updates_(BgpSignatureCount) BOOLEAN* Ambiguous
    )
{
    PUCHAR snapshot;
    ULONG maximumAnchorPrefix;
    ULONG maximumAnchorSuffix;
    ULONG snapshotCapacity;
    ULONG sectionIndex;
    NTSTATUS status;

    if (View == NULL || Addresses == NULL || MatchedSignatures == NULL ||
        DirectCallTargets == NULL || Ambiguous == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    maximumAnchorPrefix = 0UL;
    maximumAnchorSuffix = 0UL;
    status = KswordARKBugcheckBgpValidateSignatureTable(
        &maximumAnchorPrefix,
        &maximumAnchorSuffix);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE >
            MAXULONG - maximumAnchorPrefix ||
        KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE + maximumAnchorPrefix >
            MAXULONG - maximumAnchorSuffix) {
        return STATUS_INTEGER_OVERFLOW;
    }
    snapshotCapacity =
        KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE +
        maximumAnchorPrefix +
        maximumAnchorSuffix;
    snapshot = (PUCHAR)KswordARKAllocateNonPagedPool(
        snapshotCapacity,
        KSWORD_ARK_BGP_SCAN_POOL_TAG);
    if (snapshot == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = STATUS_SUCCESS;
    for (sectionIndex = 0;
         sectionIndex < View->SectionCount;
         ++sectionIndex) {
        const KSWORD_ARK_BGP_IMAGE_SECTION* section;
        ULONG scanLimit;
        ULONG scanStart;
        ULONG signatureIndex;
        BOOLEAN relevantSection;

        section = &View->Sections[sectionIndex];
        if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0UL ||
            (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0UL ||
            section->VirtualSize < sizeof(ULONG)) {
            continue;
        }

        relevantSection = FALSE;
        for (signatureIndex = 0;
             signatureIndex < BGP_SIGNATURE_TABLE_COUNT;
             ++signatureIndex) {
            if (KswordARKBugcheckBgpSectionNameMatches(
                    section->Name,
                    g_BgpSignatures[signatureIndex].Section)) {
                relevantSection = TRUE;
                break;
            }
        }
        if (!relevantSection) {
            continue;
        }

        scanLimit = section->VirtualSize - sizeof(ULONG) + 1UL;
        scanStart = 0UL;
        while (scanStart < scanLimit) {
            PUCHAR sourceAddress;
            NTSTATUS abortStatus;
            ULONG scanEnd;
            ULONG readStart;
            ULONG readEnd;
            ULONG readBytes;
            ULONG anchorPosition;

            // 每个 64 KiB 快照块都是可取消边界，卸载不再等待完整内核映像扫描结束。
            abortStatus = KswordARKBugcheckControlCheckAbort();
            if (!NT_SUCCESS(abortStatus)) {
                status = abortStatus;
                goto Exit;
            }

            scanEnd = scanStart + min(
                KSWORD_ARK_BGP_SCAN_ANCHOR_STRIDE,
                scanLimit - scanStart);
            readStart = scanStart > maximumAnchorPrefix
                ? scanStart - maximumAnchorPrefix
                : 0UL;
            readEnd = scanEnd;
            if (maximumAnchorSuffix > section->VirtualSize - readEnd) {
                readEnd = section->VirtualSize;
            } else {
                readEnd += maximumAnchorSuffix;
            }
            readBytes = readEnd - readStart;
            if (readBytes == 0UL || readBytes > snapshotCapacity ||
                section->VirtualAddress > MAXULONG - readStart ||
                !KswordARKBugcheckBgpAddressForRva(
                    View,
                    section->VirtualAddress + readStart,
                    readBytes,
                    &sourceAddress)) {
                status = STATUS_INVALID_IMAGE_FORMAT;
                goto Exit;
            }
            if (!KswordARKRuntimeReadMemory(
                    sourceAddress,
                    snapshot,
                    readBytes)) {
                status = STATUS_PARTIAL_COPY;
                goto Exit;
            }

            for (anchorPosition = scanStart;
                 anchorPosition < scanEnd;
                 ++anchorPosition) {
                ULONG anchor;
                ULONG anchorSnapshotOffset;
                ULONG bucket;
                ULONG bucketEnd;

                anchorSnapshotOffset = anchorPosition - readStart;
                if (anchorSnapshotOffset > readBytes ||
                    readBytes - anchorSnapshotOffset < sizeof(anchor)) {
                    status = STATUS_INVALID_IMAGE_FORMAT;
                    goto Exit;
                }
                RtlCopyMemory(
                    &anchor,
                    snapshot + anchorSnapshotOffset,
                    sizeof(anchor));
                bucket = anchor & (BGP_SIGNATURE_ANCHOR_BUCKETS - 1UL);
                signatureIndex = g_BgpSignatureAnchorBuckets[bucket];
                bucketEnd = g_BgpSignatureAnchorBuckets[bucket + 1UL];
                for (;
                     signatureIndex < bucketEnd;
                     ++signatureIndex) {
                    const BGP_SIGNATURE* signature;
                    PUCHAR originalCandidate;
                    const UCHAR* snapshotCandidate;
                    ULONG candidatePosition;
                    ULONG candidateSnapshotOffset;
                    ULONG candidateRva;

                    signature = &g_BgpSignatures[signatureIndex];
                    if (signature->AnchorValue != anchor ||
                        signature->AnchorOffset > anchorPosition) {
                        continue;
                    }
                    candidatePosition =
                        anchorPosition - signature->AnchorOffset;
                    if (signature->EntryOffset > candidatePosition ||
                        signature->Length >
                            section->VirtualSize - candidatePosition ||
                        (!signature->AllowPaged &&
                         (section->Characteristics &
                          IMAGE_SCN_MEM_NOT_PAGED) == 0UL) ||
                        !KswordARKBugcheckBgpSectionNameMatches(
                            section->Name,
                            signature->Section) ||
                        candidatePosition < readStart) {
                        continue;
                    }

                    candidateSnapshotOffset =
                        candidatePosition - readStart;
                    if (candidateSnapshotOffset > readBytes ||
                        signature->Length >
                            readBytes - candidateSnapshotOffset ||
                        section->VirtualAddress >
                            MAXULONG - candidatePosition) {
                        status = STATUS_INVALID_IMAGE_FORMAT;
                        goto Exit;
                    }
                    candidateRva =
                        section->VirtualAddress + candidatePosition;
                    if (!KswordARKBugcheckBgpAddressForRva(
                            View,
                            candidateRva,
                            signature->Length,
                            &originalCandidate)) {
                        status = STATUS_INVALID_IMAGE_FORMAT;
                        goto Exit;
                    }

                    snapshotCandidate =
                        snapshot + candidateSnapshotOffset;
                    if (KswordARKBugcheckBgpMatches(
                            snapshotCandidate,
                            signature)) {
                        KswordARKBugcheckBgpAcceptSignatureMatch(
                            View,
                            signature,
                            originalCandidate,
                            snapshotCandidate,
                            Addresses,
                            MatchedSignatures,
                            DirectCallTargets,
                            Ambiguous);
                    }
                }
            }
            scanStart = scanEnd;
        }
    }

Exit:
    ExFreePoolWithTag(snapshot, KSWORD_ARK_BGP_SCAN_POOL_TAG);
    return status;
}

static NTSTATUS
KswordARKBugcheckBgpGetKernelImage(
    _Out_ PUCHAR* ImageBase,
    _Out_ PULONG ImageSize
    )
{
    PAUX_MODULE_EXTENDED_INFO modules;
    ULONG requiredBytes;
    NTSTATUS status;

    *ImageBase = NULL;
    *ImageSize = 0;
    requiredBytes = 0;

    status = AuxKlibInitialize();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = AuxKlibQueryModuleInformation(
        &requiredBytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        NULL);
    if (!NT_SUCCESS(status) || requiredBytes < sizeof(AUX_MODULE_EXTENDED_INFO)) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

    modules = (PAUX_MODULE_EXTENDED_INFO)KswordARKAllocateNonPagedPool(
        requiredBytes,
        KSWORD_ARK_BGP_POOL_TAG);
    if (modules == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = AuxKlibQueryModuleInformation(
        &requiredBytes,
        sizeof(AUX_MODULE_EXTENDED_INFO),
        modules);
    if (NT_SUCCESS(status)) {
        *ImageBase = (PUCHAR)modules[0].BasicInfo.ImageBase;
        *ImageSize = modules[0].ImageSize;
    }

    ExFreePoolWithTag(modules, KSWORD_ARK_BGP_POOL_TAG);
    return status;
}

static BOOLEAN
KswordARKBugcheckBgpCrashTargetsAreNonPaged(
    _In_ const KSWORD_ARK_BGP_IMAGE_VIEW* View,
    _In_reads_(BgpSignatureCount) PVOID* Addresses
    )
{
    const ULONG crashTargets[] = {
        BgpSignatureClear,
        BgpSignatureDraw,
        BgpSignatureAcquire,
        BgpSignatureRelease,
        BgpSignatureResolution,
        BgpSignatureBpp
    };
    ULONG targetIndex;

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(crashTargets);
         ++targetIndex) {
        ULONG signatureTarget;

        signatureTarget = crashTargets[targetIndex];
        if (!KswordARKBugcheckBgpAddressInSection(
                View,
                Addresses[signatureTarget],
                1U,
                FALSE)) {
            return FALSE;
        }
    }

    return TRUE;
}

NTSTATUS
KswordARKBugcheckBgpResolveFunctions(
    VOID
    )
{
    KSWORD_ARK_BGP_IMAGE_VIEW imageView;
    PUCHAR imageBase;
    ULONG imageSize;
    PVOID addresses[BgpSignatureCount] = { NULL };
    const BGP_SIGNATURE* matchedSignatures[BgpSignatureCount] = { NULL };
    PVOID directCallTargets[BgpSignatureCount] = { NULL };
    BOOLEAN ambiguous[BgpSignatureCount] = { FALSE };
    PKSWORD_ARK_INBV_ACQUIRE_DISPLAY_OWNERSHIP acquireOwnership;
    PVOID semanticBpp;
    NTSTATUS status;
    ULONG targetIndex;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&imageView, sizeof(imageView));
    imageBase = NULL;
    imageSize = 0;
    semanticBpp = NULL;
    InterlockedExchange(&g_KswordArkBgp.ResolvedSnapshotReady, 0);
    KeMemoryBarrier();
    status = KswordARKBugcheckBgpGetKernelImage(&imageBase, &imageSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (!KswordARKBugcheckBgpInitializeImageView(
            imageBase,
            imageSize,
            &imageView)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    status = KswordARKBugcheckBgpScanSignatures(
        &imageView,
        addresses,
        matchedSignatures,
        directCallTargets,
        ambiguous);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(addresses);
         ++targetIndex) {
        if (ambiguous[targetIndex]) {
            addresses[targetIndex] = NULL;
            matchedSignatures[targetIndex] = NULL;
            directCallTargets[targetIndex] = NULL;
        }
    }

    if (addresses[BgpSignatureClear] != NULL &&
        addresses[BgpSignatureDraw] != NULL &&
        directCallTargets[BgpSignatureClear] != NULL &&
        directCallTargets[BgpSignatureClear] ==
            directCallTargets[BgpSignatureDraw] &&
        KswordARKBugcheckBgpAddressInSection(
            &imageView,
            directCallTargets[BgpSignatureClear],
            1U,
            FALSE)) {
        semanticBpp = directCallTargets[BgpSignatureClear];
    }

    // Require the BPP entry to have its own unique signature in addition to
    // being the common direct-call target of Clear and Draw.  This avoids a
    // second live image read after the bounded scan snapshot is released.
    if (semanticBpp == NULL ||
        addresses[BgpSignatureBpp] != semanticBpp ||
        matchedSignatures[BgpSignatureBpp] == NULL) {
        addresses[BgpSignatureBpp] = NULL;
        matchedSignatures[BgpSignatureBpp] = NULL;
    }

    if (!KswordARKBugcheckBgpCrashTargetsAreNonPaged(
            &imageView,
            addresses) ||
        !KswordARKBugcheckBgpAddressInSection(
            &imageView,
            addresses[BgpSignatureParse],
            1U,
            TRUE) ||
        !KswordARKBugcheckBgpAddressInSection(
            &imageView,
            addresses[BgpSignatureDestroy],
            1U,
            TRUE)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(addresses);
         ++targetIndex) {
        if (addresses[targetIndex] == NULL ||
            matchedSignatures[targetIndex] == NULL) {
            return STATUS_PROCEDURE_NOT_FOUND;
        }
    }

    acquireOwnership =
        (PKSWORD_ARK_INBV_ACQUIRE_DISPLAY_OWNERSHIP)
            KswordARKBugcheckBgpGetExport(L"InbvAcquireDisplayOwnership");
    if (acquireOwnership == NULL ||
        !KswordARKBugcheckBgpAddressInSection(
            &imageView,
            (PVOID)(ULONG_PTR)acquireOwnership,
            1U,
            FALSE)) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Publish only after every pointer and semantic relationship has passed.
    // Bugcheck callbacks consume this fixed nonpaged context and never rescan
    // ntoskrnl or decode live instructions at HIGH_LEVEL.
    g_KswordArkBgp.Clear =
        (PKSWORD_ARK_BGP_CLEAR_SCREEN)addresses[BgpSignatureClear];
    g_KswordArkBgp.Draw =
        (PKSWORD_ARK_BGP_DRAW_RECTANGLE)addresses[BgpSignatureDraw];
    g_KswordArkBgp.Acquire =
        (PKSWORD_ARK_BGP_LOCK)addresses[BgpSignatureAcquire];
    g_KswordArkBgp.Release =
        (PKSWORD_ARK_BGP_LOCK)addresses[BgpSignatureRelease];
    g_KswordArkBgp.GetResolution =
        (PKSWORD_ARK_BGP_GET_RESOLUTION)addresses[BgpSignatureResolution];
    g_KswordArkBgp.GetBpp =
        (PKSWORD_ARK_BGP_GET_BPP)addresses[BgpSignatureBpp];
    g_KswordArkBgp.ParseBitmap =
        (PKSWORD_ARK_BGP_PARSE_BITMAP)addresses[BgpSignatureParse];
    g_KswordArkBgp.DestroyRectangle =
        (PKSWORD_ARK_BGP_DESTROY_RECTANGLE)addresses[BgpSignatureDestroy];
    g_KswordArkBgp.AcquireOwnership = acquireOwnership;
    for (targetIndex = 0;
         targetIndex < RTL_NUMBER_OF(addresses);
         ++targetIndex) {
        g_KswordArkBgp.SignatureFamily[targetIndex] =
            matchedSignatures[targetIndex]->Family;
    }
    g_KswordArkBgp.FeatureMask =
        KSWORD_ARK_BGP_ALL_PRIVATE_FEATURES |
        KSWORD_ARK_BGP_FEATURE_INBV;
    KeMemoryBarrier();
    InterlockedExchange(&g_KswordArkBgp.ResolvedSnapshotReady, 1);

    return STATUS_SUCCESS;
}

/*
 * The private nt!Bgp* routines are deliberately absent from the kernel GFIDS
 * table on supported systems, even though Windows itself calls them directly.
 * Keep CFG enabled for the complete driver and suppress it only in these
 * non-inlined adapters after the resolver has validated the kernel image,
 * executable/nonpaged section, signature family, semantic relationship, and
 * uniqueness of every published address.  This prevents guard_icall_bugcheck
 * without turning a missing GFIDS entry into a global BGP feature disable.
 */
static
DECLSPEC_NOINLINE
PVOID
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeGetResolution(
    _Out_ PVOID Resolution
    )
{
    return g_KswordArkBgp.GetResolution(Resolution);
}

static
DECLSPEC_NOINLINE
ULONG
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeGetBpp(
    VOID
    )
{
    return g_KswordArkBgp.GetBpp();
}

static
DECLSPEC_NOINLINE
VOID
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeAcquireOwnership(
    VOID
    )
{
    g_KswordArkBgp.AcquireOwnership();
}

static
DECLSPEC_NOINLINE
VOID
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeAcquire(
    VOID
    )
{
    g_KswordArkBgp.Acquire();
}

DECLSPEC_NOINLINE
VOID
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeRelease(
    VOID
    )
{
    g_KswordArkBgp.Release();
}

static
DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeClear(
    _In_ ULONG ArgbColor
    )
{
    return g_KswordArkBgp.Clear(ArgbColor);
}

static
DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeDraw(
    _In_ PVOID Rectangle,
    _In_ const VOID* Position
    )
{
    return g_KswordArkBgp.Draw(Rectangle, Position);
}

DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeParseBitmap(
    _In_ const VOID* Bitmap,
    _Out_ PVOID* Rectangle
    )
{
    return g_KswordArkBgp.ParseBitmap(Bitmap, Rectangle);
}

DECLSPEC_NOINLINE
NTSTATUS
DECLSPEC_GUARDNOCF
KswordARKBugcheckBgpInvokeDestroyRectangle(
    _In_opt_ PVOID Rectangle
    )
{
    return g_KswordArkBgp.DestroyRectangle(Rectangle);
}

NTSTATUS
KswordARKBugcheckBgpReadScreen(
    _Out_ PKSWORD_ARK_BGP_SCREEN_INFO Screen
    )
{
    ULONG resolution[3];
    ULONG bitsPerPixel;

    RtlZeroMemory(resolution, sizeof(resolution));
    RtlZeroMemory(Screen, sizeof(*Screen));
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.ResolvedSnapshotReady,
            0,
            0) == 0 ||
        g_KswordArkBgp.GetResolution == NULL ||
        g_KswordArkBgp.GetBpp == NULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (KswordARKBugcheckBgpInvokeGetResolution(resolution) == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    bitsPerPixel = KswordARKBugcheckBgpInvokeGetBpp();
    g_KswordArkBgp.ProbeWidth = resolution[0];
    g_KswordArkBgp.ProbeHeight = resolution[1];
    g_KswordArkBgp.ProbeBpp = bitsPerPixel;
    // Treat the pre-ownership BPP sentinel as a deferred screen probe because
    // some BGP implementations also hide the resolution until ownership.
    if (bitsPerPixel == KSWORD_ARK_BGP_UNOWNED_BPP) {
        Screen->Width = resolution[0];
        Screen->Height = resolution[1];
        Screen->BitsPerPixel = bitsPerPixel;
        return STATUS_SUCCESS;
    }

    // Require a complete supported mode after BGP exposes the real screen.
    if (resolution[0] == 0 ||
        resolution[1] == 0 ||
        (bitsPerPixel != 24UL && bitsPerPixel != 32UL)) {
        return STATUS_NOT_SUPPORTED;
    }

    Screen->Width = resolution[0];
    Screen->Height = resolution[1];
    Screen->BitsPerPixel = bitsPerPixel;
    return STATUS_SUCCESS;
}

ULONG
KswordARKBugcheckBgpGetCurrentBpp(
    VOID
    )
{
    return g_KswordArkBgp.Screen.BitsPerPixel;
}

NTSTATUS
KswordARKBugcheckBgpValidateBitmap(
    _In_reads_bytes_(BitmapLength) const VOID* Bitmap,
    _In_ ULONG BitmapLength
    )
{
    const KSWORD_ARK_BGP_BITMAP_FILE_HEADER* fileHeader;
    const KSWORD_ARK_BGP_BITMAP_INFO_HEADER* infoHeader;
    ULONG64 rowBytes;
    ULONG64 requiredBytes;

    if (Bitmap == NULL ||
        BitmapLength <
            sizeof(KSWORD_ARK_BGP_BITMAP_FILE_HEADER) +
            sizeof(KSWORD_ARK_BGP_BITMAP_INFO_HEADER)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    fileHeader = (const KSWORD_ARK_BGP_BITMAP_FILE_HEADER*)Bitmap;
    infoHeader = (const KSWORD_ARK_BGP_BITMAP_INFO_HEADER*)(
        (const UCHAR*)Bitmap + sizeof(*fileHeader));
    if (fileHeader->Type != 0x4D42U ||
        fileHeader->Size > BitmapLength ||
        fileHeader->Size < fileHeader->PixelOffset ||
        fileHeader->PixelOffset < sizeof(*fileHeader) + sizeof(*infoHeader) ||
        infoHeader->Size != sizeof(*infoHeader) ||
        infoHeader->Width <= 0 ||
        infoHeader->Height <= 0 ||
        infoHeader->Planes != 1U ||
        infoHeader->Compression != 0UL ||
        (infoHeader->BitsPerPixel != 24U &&
         infoHeader->BitsPerPixel != 32U)) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if (g_KswordArkBgp.Screen.Width != 0 &&
        g_KswordArkBgp.Screen.Height != 0 &&
        (g_KswordArkBgp.Screen.BitsPerPixel == 24UL ||
         g_KswordArkBgp.Screen.BitsPerPixel == 32UL) &&
        ((ULONG)infoHeader->Width > g_KswordArkBgp.Screen.Width ||
         (ULONG)infoHeader->Height > g_KswordArkBgp.Screen.Height)) {
        return STATUS_NOT_SUPPORTED;
    }

    rowBytes =
        (((ULONG64)(ULONG)infoHeader->Width *
          infoHeader->BitsPerPixel + 31ULL) / 32ULL) * 4ULL;
    requiredBytes =
        (ULONG64)fileHeader->PixelOffset +
        rowBytes * (ULONG)infoHeader->Height;
    if (rowBytes > MAXULONG ||
        requiredBytes > BitmapLength ||
        requiredBytes > fileHeader->Size) {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpBeginDraw(
    VOID
    )
{
    KSWORD_ARK_BGP_SCREEN_INFO crashScreen;
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_KswordArkBgp.DrawStarted, 1, 0) != 0) {
        return STATUS_DEVICE_BUSY;
    }
    KeMemoryBarrier();
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.ResourceUpdateActive,
            0,
            0) != 0) {
        status = STATUS_DEVICE_BUSY;
        InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
        KswordARKBugcheckBgpRecordStage(
            (LONG)(KswordArkBgpStageRejected | 4UL),
            status);
        return status;
    }

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageCallbackEntered,
        STATUS_SUCCESS);
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.ResolvedSnapshotReady,
            0,
            0) == 0 ||
        InterlockedCompareExchange(
            &g_KswordArkBgp.State,
            0,
            0) != KswordArkBgpStateArmed ||
        g_KswordArkBgp.AcquireOwnership == NULL ||
        g_KswordArkBgp.Acquire == NULL ||
        g_KswordArkBgp.Release == NULL) {
        status = STATUS_DEVICE_NOT_READY;
        InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
        KswordARKBugcheckBgpRecordStage(
            (LONG)(KswordArkBgpStageRejected | 1UL),
            status);
        return status;
    }

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageOwnershipBefore,
        STATUS_PENDING);
    KswordARKBugcheckBgpInvokeAcquireOwnership();
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageOwnershipAfter,
        STATUS_SUCCESS);

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageAcquireBefore,
        STATUS_PENDING);
    KswordARKBugcheckBgpInvokeAcquire();
    InterlockedExchange(&g_KswordArkBgp.LockHeld, 1);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageAcquireAfter,
        STATUS_SUCCESS);

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageScreenBefore,
        STATUS_PENDING);
    status = KswordARKBugcheckBgpReadScreen(&crashScreen);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    if (NT_SUCCESS(status)) {
        g_KswordArkBgp.Screen = crashScreen;
    }
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageScreenAfter,
        status);
    if (!NT_SUCCESS(status) ||
        (crashScreen.BitsPerPixel != 24UL &&
         crashScreen.BitsPerPixel != 32UL) ||
        g_KswordArkBgp.RequiredWidth > crashScreen.Width ||
        g_KswordArkBgp.RequiredHeight > crashScreen.Height) {
        status = NT_SUCCESS(status) ? STATUS_NOT_SUPPORTED : status;
        InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
        InterlockedExchange(
            &g_KswordArkBgp.State,
            KswordArkBgpStateRejected);
        KswordARKBugcheckBgpRecordStage(
            (LONG)(KswordArkBgpStageRejected | 2UL),
            status);
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseBefore,
            STATUS_PENDING);
        KswordARKBugcheckBgpInvokeRelease();
        InterlockedExchange(&g_KswordArkBgp.LockHeld, 0);
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseAfter,
            STATUS_SUCCESS);
        return status;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpClearScreen(
    _In_ ULONG ArgbColor
    )
{
    NTSTATUS status;

    if (InterlockedCompareExchange(&g_KswordArkBgp.LockHeld, 0, 0) == 0 ||
        g_KswordArkBgp.Clear == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageClearBefore,
        STATUS_PENDING);
    status = KswordARKBugcheckBgpInvokeClear(ArgbColor);
    InterlockedExchange(&g_KswordArkBgp.ClearStatus, (LONG)status);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageClearAfter,
        status);
    return status;
}

NTSTATUS
KswordARKBugcheckBgpDrawRectangle(
    _In_ PVOID Rectangle,
    _In_ LONG X,
    _In_ LONG Y
    )
{
    KSWORD_ARK_BGP_POSITION position;
    NTSTATUS status;

    if (Rectangle == NULL ||
        InterlockedCompareExchange(&g_KswordArkBgp.LockHeld, 0, 0) == 0 ||
        g_KswordArkBgp.Draw == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (InterlockedCompareExchange(
            &g_KswordArkBgp.DrawStageStarted,
            1,
            0) == 0) {
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageDrawBefore,
            STATUS_PENDING);
    }

    position.X = X;
    position.Y = Y;
    status = KswordARKBugcheckBgpInvokeDraw(Rectangle, &position);
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, (LONG)status);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    return status;
}

VOID
KswordARKBugcheckBgpFinishDraw(
    _In_ NTSTATUS DrawStatus
    )
{
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.DrawStageStarted,
            1,
            0) == 0) {
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageDrawBefore,
            DrawStatus);
    }
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, (LONG)DrawStatus);
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)DrawStatus);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageDrawAfter,
        DrawStatus);

    if (InterlockedExchange(&g_KswordArkBgp.LockHeld, 0) != 0 &&
        g_KswordArkBgp.Release != NULL) {
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseBefore,
            STATUS_PENDING);
        KswordARKBugcheckBgpInvokeRelease();
        KswordARKBugcheckBgpRecordStage(
            KswordArkBgpStageReleaseAfter,
            STATUS_SUCCESS);
    }

    InterlockedIncrement64(&g_KswordArkBgp.DrawCount);
    InterlockedExchange(
        &g_KswordArkBgp.State,
        NT_SUCCESS(DrawStatus)
            ? KswordArkBgpStateDrawn
            : KswordArkBgpStateRejected);
    KswordARKBugcheckBgpRecordStage(
        KswordArkBgpStageComplete,
        DrawStatus);
}
