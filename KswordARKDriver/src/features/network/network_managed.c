#include <ntifs.h>
#ifndef NDIS630
#define NDIS630 1
#endif
#include <ndis.h>
#include <initguid.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include "network_internal.h"
#include "../../dispatch/ioctl_validation.h"
#include "../../platform/pool_compat.h"

#define MANAGED_TAG 'mNsK'
#define MANAGED_LAYER_COUNT 4U
C_ASSERT(sizeof(KSWORD_ARK_NETWORK_MANAGED_PREFIX) == 24);
C_ASSERT(sizeof(KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY) == 816);
C_ASSERT(sizeof(KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST) == 832);
C_ASSERT(sizeof(KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE) == 32);
C_ASSERT(sizeof(KSWORD_ARK_NETWORK_MANAGED_QUERY_RESPONSE) == 52256);

typedef struct _MANAGED_ROW {
    KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY Policy;
    PEPROCESS Process;
} MANAGED_ROW;
typedef struct _MANAGED_STATE {
    EX_RUNDOWN_REF Rundown;
    EX_PUSH_LOCK ControlLock;
    KSPIN_LOCK RowsLock;
    PDEVICE_OBJECT DeviceObject;
    HANDLE Engine;
    UINT32 Callouts[MANAGED_LAYER_COUNT];
    UINT64 Filters[MANAGED_LAYER_COUNT];
    BOOLEAN EngineReady;
    BOOLEAN NotifyRegistered;
    NTSTATUS LastStatus;
    NTSTATUS NotifyStatus;
    ULONG Count;
    ULONG Generation;
    MANAGED_ROW Rows[KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES];
} MANAGED_STATE;

static MANAGED_STATE* g_ManagedState;
static BOOLEAN g_ManagedShutdown;
DEFINE_GUID(KswordManagedSublayer, 0x0cf41c80, 0x183e, 0x494a, 0xa3, 0xeb, 0x51, 0x87, 0x13, 0x94, 0x60, 0x10);
static const GUID ManagedCalloutKeys[MANAGED_LAYER_COUNT] = {
    {0x0cf41c81,0x183e,0x494a,{0xa3,0xeb,0x51,0x87,0x13,0x94,0x60,0x10}},
    {0x0cf41c82,0x183e,0x494a,{0xa3,0xeb,0x51,0x87,0x13,0x94,0x60,0x10}},
    {0x0cf41c83,0x183e,0x494a,{0xa3,0xeb,0x51,0x87,0x13,0x94,0x60,0x10}},
    {0x0cf41c84,0x183e,0x494a,{0xa3,0xeb,0x51,0x87,0x13,0x94,0x60,0x10}}
};
static const GUID* const ManagedLayers[MANAGED_LAYER_COUNT] = {
    &FWPM_LAYER_ALE_AUTH_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
    &FWPM_LAYER_ALE_AUTH_CONNECT_V6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6
};

static BOOLEAN ManagedIdEmpty(const UCHAR id[16])
{
    ULONG index; UCHAR bits = 0;
    for (index = 0; index < 16; ++index) bits |= id[index];
    return bits == 0;
}
static BOOLEAN ManagedPrefixValid(const KSWORD_ARK_NETWORK_MANAGED_PREFIX* prefix)
{
    ULONG index, bits;
    if (prefix->family != 4 && prefix->family != 6) return FALSE;
    bits = prefix->family == 4 ? 32UL : 128UL;
    if (prefix->prefixLength > bits) return FALSE;
    for (index = 0; index < 16; ++index) {
        const ULONG offset = index * 8UL;
        const ULONG kept = prefix->prefixLength > offset ? min(8UL, prefix->prefixLength - offset) : 0UL;
        const UCHAR hostMask = (UCHAR)(kept == 8 ? 0 : (0xffU >> kept));
        if ((prefix->address[index] & hostMask) != 0) return FALSE;
    }
    return TRUE;
}
static BOOLEAN ManagedPolicyValid(const KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY* policy)
{
    ULONG index;
    if (ManagedIdEmpty(policy->policyId) || policy->reserved0 || policy->reserved1
        || (policy->flags & ~KSWORD_ARK_NETWORK_MANAGED_ENABLED)
        || !policy->directionMask || (policy->directionMask & ~KSWORD_ARK_NETWORK_DIRECTION_BOTH)
        || policy->prefixCount > KSWORD_ARK_NETWORK_MANAGED_MAX_PREFIXES) return FALSE;
    if (policy->processId ? policy->creationTime100ns == 0 : policy->creationTime100ns != 0 || policy->prefixCount == 0) return FALSE;
    for (index = 0; index < policy->prefixCount; ++index)
        if (!ManagedPrefixValid(&policy->prefixes[index])) return FALSE;
    return TRUE;
}
static BOOLEAN ManagedPolicyMatches(const KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY* policy,
    ULONG direction, ULONG processId, ULONG family, const UCHAR remote[16], BOOLEAN remoteKnown)
{
    ULONG index, byte;
    if (policy->prefixCount > KSWORD_ARK_NETWORK_MANAGED_MAX_PREFIXES || (family != 4 && family != 6)) return FALSE;
    if (!(policy->flags & KSWORD_ARK_NETWORK_MANAGED_ENABLED)
        || (policy->flags & KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED)
        || !(policy->directionMask & direction)
        || (policy->processId && policy->processId != processId)) return FALSE;
    if (policy->prefixCount == 0) return policy->processId != 0;
    if (!remoteKnown) return FALSE;
    for (index = 0; index < policy->prefixCount; ++index) {
        const KSWORD_ARK_NETWORK_MANAGED_PREFIX* prefix = &policy->prefixes[index];
        BOOLEAN matched = TRUE;
        const UCHAR* address = remote;
        if (prefix->family != family) {
            // Dual-IP sockets can authorize IPv4 traffic at the V6 ALE layer.
            // An IPv4 rule also covers its exact ::ffff:a.b.c.d representation.
            if (prefix->family != 4 || family != 6 || remote[10] != 0xff || remote[11] != 0xff) continue;
            for (byte = 0; byte < 10; ++byte) if (remote[byte] != 0) { matched = FALSE; break; }
            if (!matched) continue;
            address = remote + 12;
        }
        if (prefix->prefixLength > (prefix->family == 4 ? 32UL : 128UL)) continue;
        for (byte = 0; byte < (prefix->prefixLength + 7UL) / 8UL; ++byte) {
            const ULONG kept = min(8UL, prefix->prefixLength - byte * 8UL);
            const UCHAR mask = (UCHAR)(0xffU << (8UL - kept));
            if ((address[byte] & mask) != prefix->address[byte]) { matched = FALSE; break; }
        }
        if (matched) return TRUE;
    }
    return FALSE;
}

static MANAGED_STATE* ManagedAcquire(VOID)
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    MANAGED_STATE* state; KIRQL irql;
    KeAcquireSpinLock(&runtime->ClassifyRuleLock, &irql);
    state = g_ManagedState;
    if (state && !ExAcquireRundownProtection(&state->Rundown)) state = NULL;
    KeReleaseSpinLock(&runtime->ClassifyRuleLock, irql);
    return state;
}
static VOID ManagedRelease(MANAGED_STATE* state) { ExReleaseRundownProtection(&state->Rundown); }

static VOID ManagedProcessNotify(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO info)
{
    MANAGED_STATE* state; KIRQL irql; ULONG index;
    UNREFERENCED_PARAMETER(pid);
    if (info) return;
    state = ManagedAcquire(); if (!state) return;
    KeAcquireSpinLock(&state->RowsLock, &irql);
    for (index = 0; index < KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES; ++index) {
        MANAGED_ROW* row = &state->Rows[index];
        if (row->Process == process && !(row->Policy.flags & KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED)) {
            row->Policy.flags &= ~KSWORD_ARK_NETWORK_MANAGED_ENABLED;
            row->Policy.flags |= KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED; ++state->Generation;
        }
    }
    KeReleaseSpinLock(&state->RowsLock, irql); ManagedRelease(state);
}
static MANAGED_STATE* ManagedCreate(WDFDEVICE device)
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    MANAGED_STATE* state; KIRQL irql;
    KswordARKAcquirePushLockExclusive(&runtime->Lock);
    if (!g_ManagedState && !g_ManagedShutdown && device != WDF_NO_HANDLE) {
        state = (MANAGED_STATE*)KswordARKAllocateNonPagedPool(sizeof(MANAGED_STATE), MANAGED_TAG);
        if (state) {
            RtlZeroMemory(state, sizeof(*state)); ExInitializeRundownProtection(&state->Rundown);
            ExInitializePushLock(&state->ControlLock); KeInitializeSpinLock(&state->RowsLock);
            state->DeviceObject = WdfDeviceWdmGetDeviceObject(device); state->LastStatus = STATUS_DEVICE_NOT_READY;
            KeAcquireSpinLock(&runtime->ClassifyRuleLock, &irql); g_ManagedState = state;
            KeReleaseSpinLock(&runtime->ClassifyRuleLock, irql);
            state->NotifyStatus = PsSetCreateProcessNotifyRoutineEx(ManagedProcessNotify, FALSE);
            state->NotifyRegistered = NT_SUCCESS(state->NotifyStatus);
        }
    }
    state = ManagedAcquire(); KswordARKReleasePushLockExclusive(&runtime->Lock); return state;
}

static VOID NTAPI ManagedClassify(const FWPS_INCOMING_VALUES0* values,
    const FWPS_INCOMING_METADATA_VALUES0* metadata, VOID* layerData,
    const FWPS_FILTER0* filter, UINT64 flowContext, FWPS_CLASSIFY_OUT0* output)
{
    MANAGED_STATE* state; KIRQL irql; ULONG direction = 0, family = 0, field = 0, index, pid = 0;
    UCHAR remote[16] = {0}; BOOLEAN known = FALSE, blocked = FALSE;
    UNREFERENCED_PARAMETER(layerData); UNREFERENCED_PARAMETER(filter); UNREFERENCED_PARAMETER(flowContext);
    if (!values || !output || !(output->rights & FWPS_RIGHT_ACTION_WRITE)) return;
    output->actionType = FWP_ACTION_CONTINUE;
    switch (values->layerId) {
    case FWPS_LAYER_ALE_AUTH_CONNECT_V4: direction = KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND; family = 4; field = FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS; break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V4: direction = KSWORD_ARK_NETWORK_DIRECTION_INBOUND; family = 4; field = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V4_IP_REMOTE_ADDRESS; break;
    case FWPS_LAYER_ALE_AUTH_CONNECT_V6: direction = KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND; family = 6; field = FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS; break;
    case FWPS_LAYER_ALE_AUTH_RECV_ACCEPT_V6: direction = KSWORD_ARK_NETWORK_DIRECTION_INBOUND; family = 6; field = FWPS_FIELD_ALE_AUTH_RECV_ACCEPT_V6_IP_REMOTE_ADDRESS; break;
    default: return;
    }
    if (metadata && (metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) && metadata->processId <= MAXULONG) pid = (ULONG)metadata->processId;
    if (values->incomingValue && field < values->valueCount) {
        const FWP_VALUE0* value = &values->incomingValue[field].value;
        if (family == 4 && value->type == FWP_UINT32) {
            const UINT32 address = value->uint32;
            remote[0] = (UCHAR)(address >> 24); remote[1] = (UCHAR)(address >> 16);
            remote[2] = (UCHAR)(address >> 8); remote[3] = (UCHAR)address; known = TRUE;
        } else if (family == 6 && value->type == FWP_BYTE_ARRAY16_TYPE && value->byteArray16) {
            RtlCopyMemory(remote, value->byteArray16->byteArray16, sizeof(remote)); known = TRUE;
        }
    }
    state = ManagedAcquire(); if (!state) return;
    KeAcquireSpinLock(&state->RowsLock, &irql);
    for (index = 0; index < KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES; ++index) {
        if (ManagedPolicyMatches(&state->Rows[index].Policy, direction, pid, family, remote, known)) { blocked = TRUE; break; }
    }
    KeReleaseSpinLock(&state->RowsLock, irql); ManagedRelease(state);
    if (blocked) { output->actionType = FWP_ACTION_BLOCK; output->rights &= ~FWPS_RIGHT_ACTION_WRITE; }
}
static NTSTATUS NTAPI ManagedNotify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* key, FWPS_FILTER0* filter)
{
    UNREFERENCED_PARAMETER(type); UNREFERENCED_PARAMETER(key); UNREFERENCED_PARAMETER(filter); return STATUS_SUCCESS;
}
static VOID ManagedCloseEngine(MANAGED_STATE* state)
{
    ULONG index;
    if (state->Engine) {
        for (index = 0; index < MANAGED_LAYER_COUNT; ++index) if (state->Filters[index]) {
            (VOID)FwpmFilterDeleteById0(state->Engine, state->Filters[index]); state->Filters[index] = 0;
        }
        (VOID)FwpmEngineClose0(state->Engine); state->Engine = NULL;
    }
    for (index = 0; index < MANAGED_LAYER_COUNT; ++index) if (state->Callouts[index]) {
        (VOID)FwpsCalloutUnregisterById0(state->Callouts[index]); state->Callouts[index] = 0;
    }
    state->EngineReady = FALSE;
}
static NTSTATUS ManagedAddFilters(MANAGED_STATE* state, UINT64 ids[MANAGED_LAYER_COUNT])
{
    ULONG index; NTSTATUS status;
    for (index = 0; index < MANAGED_LAYER_COUNT; ++index) {
        FWPM_FILTER0 filter; RtlZeroMemory(&filter, sizeof(filter));
        filter.displayData.name = L"KSword managed connection policy";
        filter.layerKey = *ManagedLayers[index]; filter.subLayerKey = KswordManagedSublayer;
        filter.weight.type = FWP_UINT8; filter.weight.uint8 = 15;
        filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN; filter.action.calloutKey = ManagedCalloutKeys[index];
        status = FwpmFilterAdd0(state->Engine, &filter, NULL, &ids[index]); if (!NT_SUCCESS(status)) return status;
    }
    return STATUS_SUCCESS;
}
static NTSTATUS ManagedEnsureEngine(MANAGED_STATE* state)
{
    NTSTATUS status; ULONG index; FWPM_SESSION0 session; FWPM_SUBLAYER0 sublayer;
    if (state->EngineReady) return STATUS_SUCCESS;
    ManagedCloseEngine(state);
    for (index = 0; index < MANAGED_LAYER_COUNT; ++index) {
        FWPS_CALLOUT0 callout; RtlZeroMemory(&callout, sizeof(callout));
        callout.calloutKey = ManagedCalloutKeys[index]; callout.classifyFn = ManagedClassify; callout.notifyFn = ManagedNotify;
        status = FwpsCalloutRegister0(state->DeviceObject, &callout, &state->Callouts[index]); if (!NT_SUCCESS(status)) goto failed;
    }
    RtlZeroMemory(&session, sizeof(session)); session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.displayData.name = L"KSword managed network session";
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &state->Engine); if (!NT_SUCCESS(status)) goto failed;
    status = FwpmTransactionBegin0(state->Engine, 0); if (!NT_SUCCESS(status)) goto failed;
    RtlZeroMemory(&sublayer, sizeof(sublayer)); sublayer.subLayerKey = KswordManagedSublayer;
    sublayer.displayData.name = L"KSword managed policies"; sublayer.weight = 0x7000;
    status = FwpmSubLayerAdd0(state->Engine, &sublayer, NULL); if (!NT_SUCCESS(status)) goto abort;
    for (index = 0; index < MANAGED_LAYER_COUNT; ++index) {
        FWPM_CALLOUT0 callout; RtlZeroMemory(&callout, sizeof(callout)); callout.calloutKey = ManagedCalloutKeys[index];
        callout.applicableLayer = *ManagedLayers[index]; callout.displayData.name = L"KSword managed connection callout";
        status = FwpmCalloutAdd0(state->Engine, &callout, NULL, NULL); if (!NT_SUCCESS(status)) goto abort;
    }
    status = ManagedAddFilters(state, state->Filters); if (!NT_SUCCESS(status)) goto abort;
    status = FwpmTransactionCommit0(state->Engine); if (!NT_SUCCESS(status)) goto abort;
    state->EngineReady = TRUE; state->LastStatus = STATUS_SUCCESS; return STATUS_SUCCESS;
abort:
    (VOID)FwpmTransactionAbort0(state->Engine);
failed:
    ManagedCloseEngine(state); state->LastStatus = status; return status;
}
static NTSTATUS ManagedReauthorize(MANAGED_STATE* state, BOOLEAN* engineHealthy)
{
    UINT64 ids[MANAGED_LAYER_COUNT] = {0}; ULONG index; NTSTATUS status = FwpmTransactionBegin0(state->Engine, 0);
    *engineHealthy = TRUE;
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_INVALID_HANDLE || status == STATUS_FWP_SESSION_ABORTED) *engineHealthy = FALSE;
        return status;
    }
    for (index = 0; index < MANAGED_LAYER_COUNT; ++index) if (state->Filters[index]) {
        status = FwpmFilterDeleteById0(state->Engine, state->Filters[index]); if (!NT_SUCCESS(status)) goto failed;
    }
    status = ManagedAddFilters(state, ids); if (!NT_SUCCESS(status)) goto failed;
    status = FwpmTransactionCommit0(state->Engine); if (!NT_SUCCESS(status)) goto failed;
    RtlCopyMemory(state->Filters, ids, sizeof(ids)); return STATUS_SUCCESS;
failed:
    if (!NT_SUCCESS(FwpmTransactionAbort0(state->Engine))) *engineHealthy = FALSE;
    return status;
}

static VOID ManagedRefreshExited(MANAGED_STATE* state)
{
    ULONG index; KIRQL irql;
    // ControlLock owns object references. Exit status is queried at PASSIVE,
    // never under the classify spin lock or from a DISPATCH-level callout.
    for (index = 0; index < KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES; ++index) {
        MANAGED_ROW* row = &state->Rows[index];
        if (row->Process && PsGetProcessExitStatus(row->Process) != STATUS_PENDING) {
            KeAcquireSpinLock(&state->RowsLock, &irql);
            if (!(row->Policy.flags & KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED)) {
                row->Policy.flags &= ~KSWORD_ARK_NETWORK_MANAGED_ENABLED;
                row->Policy.flags |= KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED; ++state->Generation;
            }
            KeReleaseSpinLock(&state->RowsLock, irql);
        }
    }
}
static ULONG ManagedCapabilities(const MANAGED_STATE* state)
{
    if (!state->EngineReady) return 0;
    return KSWORD_ARK_NETWORK_MANAGED_CAP_IPV4 | KSWORD_ARK_NETWORK_MANAGED_CAP_IPV6
        | KSWORD_ARK_NETWORK_MANAGED_CAP_CIDR
        | (state->NotifyRegistered ? KSWORD_ARK_NETWORK_MANAGED_CAP_PROCESS_INSTANCE : 0UL);
}
static VOID ManagedControlHeader(MANAGED_STATE* state, KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE* response,
    ULONG result, NTSTATUS status)
{
    KIRQL irql;
    RtlZeroMemory(response, sizeof(*response)); response->version = KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION;
    response->size = sizeof(*response); response->status = result; response->lastStatus = status;
    if (!state) return;
    KeAcquireSpinLock(&state->RowsLock, &irql);
    response->policyCount = state->Count; response->generation = state->Generation;
    KeReleaseSpinLock(&state->RowsLock, irql); response->capabilities = ManagedCapabilities(state);
}
static NTSTATUS ManagedReferenceProcess(MANAGED_STATE* state,
    const KSWORD_ARK_NETWORK_MANAGED_POLICY_ENTRY* policy, PEPROCESS* output)
{
    PEPROCESS process = NULL; NTSTATUS status;
    *output = NULL; if (!policy->processId) return STATUS_SUCCESS;
    if (!state->NotifyRegistered) return state->NotifyStatus;
    status = PsLookupProcessByProcessId(ULongToHandle(policy->processId), &process);
    if (!NT_SUCCESS(status)) return status;
    if ((ULONGLONG)PsGetProcessCreateTimeQuadPart(process) != policy->creationTime100ns) status = STATUS_INVALID_CID;
    else if (PsGetProcessExitStatus(process) != STATUS_PENDING) status = STATUS_PROCESS_IS_TERMINATING;
    if (!NT_SUCCESS(status)) { ObDereferenceObject(process); return status; }
    *output = process; return STATUS_SUCCESS;
}
static NTSTATUS ManagedApply(MANAGED_STATE* state, const KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST* request)
{
    MANAGED_ROW previous, candidate; ULONG index, slot = MAXULONG, empty = MAXULONG;
    NTSTATUS status; KIRQL irql; BOOLEAN engineHealthy;
    RtlZeroMemory(&candidate, sizeof(candidate)); RtlZeroMemory(&previous, sizeof(previous));
    ManagedRefreshExited(state);
    KeAcquireSpinLock(&state->RowsLock, &irql);
    for (index = 0; index < KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES; ++index) {
        if (ManagedIdEmpty(state->Rows[index].Policy.policyId)) { if (empty == MAXULONG) empty = index; }
        else if (RtlCompareMemory(state->Rows[index].Policy.policyId, request->policy.policyId, 16) == 16) { slot = index; break; }
    }
    if (slot != MAXULONG) previous = state->Rows[slot];
    KeReleaseSpinLock(&state->RowsLock, irql);
    if (slot == MAXULONG && request->action != KSWORD_ARK_NETWORK_MANAGED_UPSERT) return STATUS_NOT_FOUND;
    if (slot == MAXULONG) slot = empty;
    if (slot == MAXULONG) return STATUS_QUOTA_EXCEEDED;
    if (request->action == KSWORD_ARK_NETWORK_MANAGED_UPSERT) {
        candidate.Policy = request->policy;
        RtlZeroMemory(&candidate.Policy.prefixes[candidate.Policy.prefixCount],
            (KSWORD_ARK_NETWORK_MANAGED_MAX_PREFIXES - candidate.Policy.prefixCount) * sizeof(candidate.Policy.prefixes[0]));
        status = ManagedReferenceProcess(state, &candidate.Policy, &candidate.Process); if (!NT_SUCCESS(status)) return status;
    } else if (request->action != KSWORD_ARK_NETWORK_MANAGED_REMOVE) {
        candidate = previous;
        if (request->action == KSWORD_ARK_NETWORK_MANAGED_ENABLE) {
            if (candidate.Process && ((candidate.Policy.flags & KSWORD_ARK_NETWORK_MANAGED_PROCESS_EXITED)
                || PsGetProcessExitStatus(candidate.Process) != STATUS_PENDING
                || (ULONGLONG)PsGetProcessCreateTimeQuadPart(candidate.Process) != candidate.Policy.creationTime100ns)) return STATUS_PROCESS_IS_TERMINATING;
            candidate.Policy.flags |= KSWORD_ARK_NETWORK_MANAGED_ENABLED;
        } else candidate.Policy.flags &= ~KSWORD_ARK_NETWORK_MANAGED_ENABLED;
    }
    status = ManagedEnsureEngine(state); if (!NT_SUCCESS(status)) {
        if (request->action == KSWORD_ARK_NETWORK_MANAGED_UPSERT && candidate.Process) ObDereferenceObject(candidate.Process);
        return status;
    }
    KeAcquireSpinLock(&state->RowsLock, &irql);
    state->Rows[slot] = candidate;
    if (ManagedIdEmpty(previous.Policy.policyId)) ++state->Count;
    if (request->action == KSWORD_ARK_NETWORK_MANAGED_REMOVE) --state->Count;
    ++state->Generation;
    KeReleaseSpinLock(&state->RowsLock, irql);
    // Changing only the callout's private table does not reauthorize existing
    // ALE flows. An atomic filter remove/add triggers policy-change reauthorization.
    status = ManagedReauthorize(state, &engineHealthy);
    if (!NT_SUCCESS(status)) {
        KeAcquireSpinLock(&state->RowsLock, &irql);
        state->Rows[slot] = previous;
        if (ManagedIdEmpty(previous.Policy.policyId)) --state->Count;
        if (request->action == KSWORD_ARK_NETWORK_MANAGED_REMOVE) ++state->Count;
        ++state->Generation; KeReleaseSpinLock(&state->RowsLock, irql);
        if (request->action == KSWORD_ARK_NETWORK_MANAGED_UPSERT && candidate.Process) ObDereferenceObject(candidate.Process);
        if (!engineHealthy) ManagedCloseEngine(state);
    } else if ((request->action == KSWORD_ARK_NETWORK_MANAGED_UPSERT || request->action == KSWORD_ARK_NETWORK_MANAGED_REMOVE) && previous.Process) {
        ObDereferenceObject(previous.Process);
    }
    ManagedRefreshExited(state); state->LastStatus = status; return status;
}

NTSTATUS KswordARKNetworkIoctlControlManagedPolicy(WDFDEVICE device, WDFREQUEST request,
    size_t inputLength, size_t outputLength, size_t* returned)
{
    KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST* input = NULL;
    KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST* copy = NULL;
    KSWORD_ARK_NETWORK_MANAGED_CONTROL_RESPONSE* output = NULL;
    MANAGED_STATE* state = NULL; NTSTATUS status; size_t actual = 0;
    ULONG result = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
    UNREFERENCED_PARAMETER(inputLength); UNREFERENCED_PARAMETER(outputLength);
    if (!returned || KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_PARAMETER;
    *returned = 0;
    status = KswordARKValidateDeviceIoControlWriteAccess(request); if (!NT_SUCCESS(status)) return status;
    status = KswordARKRetrieveRequiredInputBuffer(request, sizeof(*input), (PVOID*)&input, &actual); if (!NT_SUCCESS(status)) return status;
    if (input->version != KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION || input->size != sizeof(*input) || input->reserved
        || input->action < KSWORD_ARK_NETWORK_MANAGED_UPSERT || input->action > KSWORD_ARK_NETWORK_MANAGED_DISABLE
        || ManagedIdEmpty(input->policy.policyId)
        || (input->action == KSWORD_ARK_NETWORK_MANAGED_UPSERT && !ManagedPolicyValid(&input->policy))) return STATUS_INVALID_PARAMETER;
    copy = (KSWORD_ARK_NETWORK_MANAGED_CONTROL_REQUEST*)KswordARKAllocateNonPagedPool(sizeof(*copy), MANAGED_TAG);
    if (!copy) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(copy, input, sizeof(*copy));
    status = KswordARKRetrieveRequiredOutputBuffer(request, sizeof(*output), (PVOID*)&output, &actual);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(copy, MANAGED_TAG); return status; }
    state = ManagedCreate(device);
    if (!state) {
        ManagedControlHeader(NULL, output, KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE, STATUS_DEVICE_NOT_READY);
    } else {
        KswordARKAcquirePushLockExclusive(&state->ControlLock);
        status = ManagedApply(state, copy);
        if (NT_SUCCESS(status)) result = copy->action == KSWORD_ARK_NETWORK_MANAGED_REMOVE ? KSWORD_ARK_NETWORK_STATUS_CLEARED
            : copy->action == KSWORD_ARK_NETWORK_MANAGED_DISABLE ? KSWORD_ARK_NETWORK_STATUS_DISABLED : KSWORD_ARK_NETWORK_STATUS_APPLIED;
        else if (!state->EngineReady) result = KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
        ManagedControlHeader(state, output, result, status);
        KswordARKReleasePushLockExclusive(&state->ControlLock); ManagedRelease(state);
    }
    ExFreePoolWithTag(copy, MANAGED_TAG); *returned = sizeof(*output); return STATUS_SUCCESS;
}
NTSTATUS KswordARKNetworkIoctlQueryManagedPolicies(WDFDEVICE device, WDFREQUEST request,
    size_t inputLength, size_t outputLength, size_t* returned)
{
    KSWORD_ARK_NETWORK_MANAGED_QUERY_RESPONSE* output = NULL;
    MANAGED_STATE* state; NTSTATUS status; size_t actual = 0; ULONG index, written = 0; KIRQL irql;
    UNREFERENCED_PARAMETER(outputLength);
    if (!returned || inputLength || KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_PARAMETER;
    *returned = 0;
    status = KswordARKRetrieveRequiredOutputBuffer(request, sizeof(*output), (PVOID*)&output, &actual); if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(output, sizeof(*output)); output->version = KSWORD_ARK_NETWORK_MANAGED_PROTOCOL_VERSION; output->size = sizeof(*output);
    state = ManagedCreate(device);
    if (!state) { output->status = KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE; output->lastStatus = STATUS_DEVICE_NOT_READY; }
    else {
        KswordARKAcquirePushLockExclusive(&state->ControlLock);
        status = ManagedEnsureEngine(state); ManagedRefreshExited(state);
        output->status = NT_SUCCESS(status) ? KSWORD_ARK_NETWORK_STATUS_APPLIED : KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE;
        output->lastStatus = status; output->capabilities = ManagedCapabilities(state);
        KeAcquireSpinLock(&state->RowsLock, &irql);
        for (index = 0; index < KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES; ++index)
            if (!ManagedIdEmpty(state->Rows[index].Policy.policyId)) output->policies[written++] = state->Rows[index].Policy;
        output->policyCount = written; output->generation = state->Generation;
        KeReleaseSpinLock(&state->RowsLock, irql);
        KswordARKReleasePushLockExclusive(&state->ControlLock); ManagedRelease(state);
    }
    *returned = sizeof(*output); return STATUS_SUCCESS;
}
VOID KswordARKNetworkManagedUninitialize(VOID)
{
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    MANAGED_STATE* state; KIRQL irql; ULONG index;
    KswordARKAcquirePushLockExclusive(&runtime->Lock);
    KeAcquireSpinLock(&runtime->ClassifyRuleLock, &irql); g_ManagedShutdown = TRUE; state = g_ManagedState; g_ManagedState = NULL;
    KeReleaseSpinLock(&runtime->ClassifyRuleLock, irql); KswordARKReleasePushLockExclusive(&runtime->Lock);
    if (!state) return;
    ExWaitForRundownProtectionRelease(&state->Rundown);
    if (state->NotifyRegistered) (VOID)PsSetCreateProcessNotifyRoutineEx(ManagedProcessNotify, TRUE);
    ManagedCloseEngine(state);
    for (index = 0; index < KSWORD_ARK_NETWORK_MANAGED_MAX_POLICIES; ++index)
        if (state->Rows[index].Process) ObDereferenceObject(state->Rows[index].Process);
    ExFreePoolWithTag(state, MANAGED_TAG);
}
