// Selective NT PDB facts used by the read-only process, thread and VAD queries.
#include "dyndata_v4_internal.h"
#include "../bugcheck/bugcheck_identity.h"
#include "ark/ark_push_lock.h"
#include <ntimage.h>
#include <ntstrsafe.h>

// Return the fixed destination for a single accepted structure member.
static ULONG* KswObserverField(KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT* layout, ULONG id)
{
    switch (id) { // No global, code RVA or write-side field is consumed.
    case KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID: return &layout->Pid;
    case KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS: return &layout->ActiveLinks;
    case KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD: return &layout->ThreadHead;
    case KSW_DYN_FIELD_ID_ET_CID: return &layout->Cid;
    case KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY: return &layout->ThreadEntry;
    case KSW_DYN_FIELD_ID_ET_START_ADDRESS: return &layout->ThreadStart;
    case KSW_DYN_FIELD_ID_KT_PROCESS: return &layout->ThreadProcess;
    case KSW_DYN_FIELD_ID_EP_VAD_ROOT: return &layout->VadRoot;
    case KSW_DYN_FIELD_ID_EP_VAD_HINT: return &layout->VadHint;
    case KSW_DYN_FIELD_ID_EP_VAD_COUNT: return &layout->VadCount;
    default: return NULL; // Unrelated fields cannot enter the read-only packet.
    }
}

// Ten unique facts are required; validate metadata before copying scalar offsets.
static BOOLEAN KswObserverDecode(const KSW_DYN_V4_ITEM_PACKET* items, ULONG count,
    KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT* layout)
{
    ULONG i; // Bounded packet index.
    RtlZeroMemory(layout, sizeof(*layout)); // Zero is unavailable for all ten members.
    if (count != 10UL) return FALSE; // No missing or extra item is accepted.
    for (i = 0; i < count; ++i) { // Decode the allowlisted group only.
        const KSW_DYN_V4_ITEM_PACKET* item = &items[i]; // Immutable item snapshot.
        ULONG* field = KswObserverField(layout, item->itemId); // Select a compile-time member.
        if (field == NULL || *field != 0 || item->capabilityGroupId != KSW_DYN_V4_CAPABILITY_GROUP_PROCESS_ENUM_READONLY ||
            item->flags != KSW_DYN_V4_ITEM_FLAG_REQUIRED || item->itemKind != KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
            !item->valueLow || item->valueLow > KSW_DYN_PROFILE_OFFSET_MAX || (item->valueLow & 7UL) ||
            item->valueHigh || item->aux0 || item->aux1 || item->aux2 || item->aux3) return FALSE; // Require bounded, pointer-aligned scalars.
        *field = item->valueLow; // Store once after validation.
    }
    return TRUE; // All and only the ten known fields were decoded.
}

// Match bounded packet text without treating the wire buffer as a terminated string.
static BOOLEAN KswObserverAsciiEqual(const CHAR* expected, size_t expectedCap, const CHAR* supplied, size_t suppliedCap)
{
    size_t a = 0, b = 0, i; // Bound both strings before comparing.
    if (!NT_SUCCESS(RtlStringCbLengthA(expected, expectedCap, &a)) ||
        !NT_SUCCESS(RtlStringCbLengthA(supplied, suppliedCap, &b)) || !a || a != b) return FALSE; // No truncation or prefix matching.
    for (i = 0; i < a; ++i) { // ASCII-only case folding is sufficient for RSDS names and hex.
        CHAR x = expected[i], y = supplied[i]; // Both offsets are in bounds.
        if (x >= 'a' && x <= 'z') x = (CHAR)(x-'a'+'A'); // Fold the trusted side.
        if (y >= 'a' && y <= 'z') y = (CHAR)(y-'a'+'A'); // Fold the submitted side.
        if (x != y) return FALSE; // Reject an identity mismatch.
    }
    return TRUE; // Exact bounded match.
}

// Verify the loaded image, including CodeView GUID/Age, before admitting this special group.
NTSTATUS KswordARKDynDataV4VerifyProcessObserverProfile(const KSW_APPLY_DYN_PROFILE_V4_REQUEST* request,
    const KSW_DYN_MODULE_IDENTITY_PACKET* loaded)
{
    KSWORD_BUGCHECK_IMAGE_ID image; // Reuse the bounded production PE/RSDS reader.
    KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT layout; // Temporary normalized values.
    GUID guid; // Aligned copy of the CodeView GUID.
    CHAR text[33]; // Production profile GUID uses the conventional compact symbol-server spelling.
    if (request->capabilityGroupCount != 1 || request->capabilityGroups[0].flags ||
        request->capabilityGroups[0].requiredItemCount != 10 || request->capabilityGroups[0].optionalItemCount ||
        loaded->classId != KSW_DYN_PROFILE_CLASS_NTOSKRNL || loaded->machine != IMAGE_FILE_MACHINE_AMD64 ||
        !KswObserverDecode(request->items, request->itemCount, &layout)) return STATUS_INVALID_PARAMETER; // Preserve existing state on malformed input.
    KswordARKBugcheckIdentityRead((ULONG_PTR)loaded->imageBase, loaded->sizeOfImage, NULL, &image); // Read only this loaded NT image.
    if (!NT_SUCCESS(image.Status) || (image.Flags & (KSWORD_BUGCHECK_ID_RSDS|KSWORD_BUGCHECK_ID_PE)) !=
        (KSWORD_BUGCHECK_ID_RSDS|KSWORD_BUGCHECK_ID_PE) || image.ImageSize != loaded->sizeOfImage ||
        image.TimeDateStamp != loaded->timeDateStamp || image.PdbAge != request->module.pdb.pdbAge ||
        !KswObserverAsciiEqual(image.PdbName, sizeof(image.PdbName), request->module.pdb.pdbName,
            sizeof(request->module.pdb.pdbName))) return STATUS_REVISION_MISMATCH; // Do not use offsets from another image or PDB.
    RtlCopyMemory(&guid, image.PdbGuid, sizeof(guid)); // Respect GUID field endianness.
    if (!NT_SUCCESS(RtlStringCbPrintfA(text, sizeof(text), "%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
        guid.Data1, (unsigned int)guid.Data2, (unsigned int)guid.Data3, (unsigned int)guid.Data4[0], (unsigned int)guid.Data4[1],
        (unsigned int)guid.Data4[2], (unsigned int)guid.Data4[3], (unsigned int)guid.Data4[4], (unsigned int)guid.Data4[5],
        (unsigned int)guid.Data4[6], (unsigned int)guid.Data4[7]))) return STATUS_DATA_ERROR; // Refuse incomplete GUID formatting.
    return KswObserverAsciiEqual(text, sizeof(text), request->module.pdb.pdbGuid,
        sizeof(request->module.pdb.pdbGuid)) ? STATUS_SUCCESS : STATUS_REVISION_MISMATCH; // Compare the complete compact GUID.
}

BOOLEAN KswordARKDynDataV4SnapshotProcessObserver(KSW_DYN_V4_PROCESS_OBSERVER_LAYOUT* layout)
{
    const KSW_DYN_V4_MODULE_STATE* nt = &g_KswordDynDataV4State.Modules[0]; // NTOS has a stable, non-unloadable slot.
    BOOLEAN matched = FALSE; // Start unavailable on every query.
    if (!layout) return FALSE; // A destination is required.
    KswordARKAcquirePushLockShared(&g_KswordDynDataV4Lock); // Never mix items from different commits.
    if (nt->Occupied && nt->PublicEntry.module.image.classId == KSW_DYN_PROFILE_CLASS_NTOSKRNL &&
        nt->PublicEntry.capabilityGroupCount == 1 && (nt->PublicEntry.statusFlags & KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) &&
        nt->Groups[0].PublicEntry.groupId == KSW_DYN_V4_CAPABILITY_GROUP_PROCESS_ENUM_READONLY) {
        matched = KswObserverDecode(nt->Items, nt->StoredItemCount, layout); // Only the exact protected packet reaches these three consumers.
    }
    KswordARKReleasePushLockShared(&g_KswordDynDataV4Lock); // No global capability or legacy DynData field is mutated.
    if (!matched) RtlZeroMemory(layout, sizeof(*layout)); // Do not expose partial offsets.
    return matched; // Successful offsets belong only to the caller's local context.
}
