#include "hvm_debug.h"
#include "hvm_runtime.h"
#include "../debugger/debugger.h"
#include "hvm_vmcs.h"
#include "../../platform/pool_compat.h"

/* PsGetThreadTeb is resolved once; no Windows routine runs in VMX root. */
typedef PVOID (NTAPI* KSW_DEBUG_GET_TEB)(PETHREAD Thread);
/* Keep notification publication separate from mutable breakpoint metadata. */
static KSW_DEBUG_GET_TEB g_DebugGetTeb = NULL;
/* Publish support only after both lifetime callbacks are installed. */
static BOOLEAN g_DebugNotifications = FALSE;
/* Distinguish a reused slot from the publication observed by an exit callback. */
static volatile LONG g_DebugPublication = 0L;
/* Resolve target objects from IDs rather than trusting user pointers. */
NTSYSAPI NTSTATUS NTAPI PsLookupThreadByThreadId(HANDLE ThreadId, PETHREAD* Thread);
/* Read thread ownership only at PASSIVE_LEVEL. */
NTKERNELAPI PEPROCESS PsGetThreadProcess(PETHREAD Thread);
/* Resolve thread identity without using private ETHREAD offsets. */
NTKERNELAPI HANDLE PsGetThreadProcessId(PETHREAD Thread);
/* Check termination after publication to close the notification race. */
NTKERNELAPI BOOLEAN PsIsThreadTerminating(PETHREAD Thread);
/* Attach only while pinning the requested user page. */
NTKERNELAPI VOID KeStackAttachProcess(PVOID Process, PVOID ApcState);
/* Always restore the original address space after pinning. */
NTKERNELAPI VOID KeUnstackDetachProcess(PVOID ApcState);

/* Revoke stops without changing EPT, waiting, allocating, or dropping pins. */
static VOID KswordARKHvmDebugThreadNotify(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    /* Fetch the fixed runtime that owns the bounded slot array. */
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    /* Walk only exiting threads. */
    ULONG index;
    /* Creation does not retire any debugger scope. */
    UNREFERENCED_PARAMETER(ProcessId);
    /* Return without touching lifetime state on creation. */
    if (Create || runtime == NULL) { return; }
    /* Scan every preallocated record without following Windows objects. */
    for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
        /* Snapshot the publication token before inspecting its thread identity. */
        LONG publication = InterlockedCompareExchange(&runtime->DebugSlots[index].Enabled, 0L, 0L);
        /* Select the published record for the exact exiting TID. */
        if (publication != 0L && runtime->DebugSlots[index].ThreadId == HandleToULong(ThreadId)) {
            /* Disable injection before the TEB can be reused. */
            (void)InterlockedCompareExchange(&runtime->DebugSlots[index].Enabled, 0L, publication);
        }
    }
}

/* A debugger exit revokes its stops even if its DLL cleanup never runs. */
static VOID KswordARKHvmDebugProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    /* Fetch the fixed runtime that owns every debugger lease. */
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    /* Bound the revocation scan. */
    ULONG index;
    /* Process objects are intentionally not dereferenced in this callback. */
    UNREFERENCED_PARAMETER(Process);
    /* Creation has no retiring debugger lease. */
    if (CreateInfo != NULL || runtime == NULL) { return; }
    /* Scan only the preallocated debugger table. */
    for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
        /* Snapshot the publication token before inspecting debugger ownership. */
        LONG publication = InterlockedCompareExchange(&runtime->DebugSlots[index].Enabled, 0L, 0L);
        /* Match the authoritative requestor identity saved at installation. */
        if (publication != 0L && runtime->DebugSlots[index].OwnerProcessId == HandleToULong(ProcessId)) {
            /* Stop injecting before the debugger's debug object disappears. */
            (void)InterlockedCompareExchange(&runtime->DebugSlots[index].Enabled, 0L, publication);
        }
    }
    KswordARKDebuggerProcessExit(HandleToULong(ProcessId));
}

NTSTATUS KswordARKHvmDebugInitialize(VOID)
{
    /* Resolve the sole Windows routine used for thread scope during installation. */
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"PsGetThreadTeb");
    /* Preserve registration failures without publishing partial support. */
    NTSTATUS status;
    /* Resolve the routine once while the driver is initializing. */
    g_DebugGetTeb = (KSW_DEBUG_GET_TEB)MmGetSystemRoutineAddress(&name);
    /* Refuse scope that cannot be established from a public thread identity. */
    if (g_DebugGetTeb == NULL) { return STATUS_NOT_SUPPORTED; }
    /* Register revocation before exposing a debugger stop. */
    status = PsSetCreateThreadNotifyRoutine(KswordARKHvmDebugThreadNotify);
    /* Preserve the exact registration failure. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Register requesting-debugger exit revocation as well. */
    status = PsSetCreateProcessNotifyRoutineEx(KswordARKHvmDebugProcessNotify, FALSE);
    /* Roll back the first registration when the second failed. */
    if (!NT_SUCCESS(status)) {
        /* Drain every possible first callback. */
        (void)PsRemoveCreateThreadNotifyRoutine(KswordARKHvmDebugThreadNotify);
        /* Return the authoritative registration failure. */
        return status;
    }
    /* Publish a complete lifetime guard. */
    g_DebugNotifications = TRUE;
    /* Report full notification registration. */
    return STATUS_SUCCESS;
}

VOID KswordARKHvmDebugShutdown(VOID)
{
    /* Nothing was published when initialization failed. */
    if (!g_DebugNotifications) { return; }
    /* Drain requesting-debugger exit notifications. */
    (void)PsSetCreateProcessNotifyRoutineEx(KswordARKHvmDebugProcessNotify, TRUE);
    /* Drain target-thread exit notifications. */
    (void)PsRemoveCreateThreadNotifyRoutine(KswordARKHvmDebugThreadNotify);
    /* Withdraw capability only after both callbacks have drained. */
    g_DebugNotifications = FALSE;
}

/* Passive-only retirement; the runtime lock and zero resident count are required. */
static VOID KswordARKHvmDebugFreeSlot(KSW_HVM_DEBUG_SLOT* Slot)
{
    /* Withdraw the publication before releasing backing resources. */
    InterlockedExchange(&Slot->Enabled, 0L);
    /* Release the pinned user page only after every VM-exit reader is stopped. */
    if (Slot->Mdl != NULL) {
        /* Restore the memory manager's page-lock reference. */
        MmUnlockPages(Slot->Mdl);
        /* Release the descriptor allocated at installation. */
        IoFreeMdl(Slot->Mdl);
    }
    /* Release the target-thread lifetime reference. */
    if (Slot->Thread != NULL) { ObDereferenceObject(Slot->Thread); }
    /* Make the stopped record reusable. */
    RtlZeroMemory(Slot, sizeof(*Slot));
}

VOID KswordARKHvmDebugResetLocked(KSW_HVM_RUNTIME* Runtime)
{
    /* Bound all resource retirement to the fixed slot capacity. */
    ULONG index;
    /* Never release a page that a resident exit path may still name. */
    if (InterlockedCompareExchange(&Runtime->ResidentProcessorCount, 0L, 0L) != 0L) { return; }
    /* Retire every record while the runtime mutation lock is held. */
    for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
        /* Release the record's pinned backing page and thread reference. */
        KswordARKHvmDebugFreeSlot(&Runtime->DebugSlots[index]);
    }
}

/* Build metadata and pin one stable backing page without reading private offsets. */
static NTSTATUS KswordARKHvmDebugPin(const KSWORD_ARK_HVM_DEBUG_REQUEST* Request, KSW_HVM_DEBUG_SLOT* Slot)
{
    /* Attach state is opaque, naturally aligned, and larger than KAPC_STATE. */
    DECLSPEC_ALIGN(16) UCHAR attachState[128];
    /* Track whether the descriptor owns a successful page-lock reference. */
    BOOLEAN locked = FALSE;
    /* Preserve lookup or probing failure. */
    NTSTATUS status;
    /* Reference the target thread by the requested TID. */
    status = PsLookupThreadByThreadId(ULongToHandle(Request->threadId), &Slot->Thread);
    /* Return without pinning when identity lookup failed. */
    if (!NT_SUCCESS(status)) { return status; }
    /* Reject a recycled TID or the wrong owning process. */
    if (HandleToULong(PsGetThreadProcessId(Slot->Thread)) != Request->processId) {
        /* Return the exact identity failure to passive cleanup. */
        return STATUS_INVALID_CID;
    }
    /* Resolve the user-mode TEB before any VMX-root publication. */
    Slot->Teb = (ULONGLONG)(ULONG_PTR)g_DebugGetTeb(Slot->Thread);
    /* System threads have no user-mode scope and are never debugger targets. */
    if (Slot->Teb == 0ULL) { return STATUS_NOT_SUPPORTED; }
    /* Allocate the descriptor before attaching to the target address space. */
    Slot->Mdl = IoAllocateMdl((PVOID)(ULONG_PTR)Request->address, Request->length, FALSE, FALSE, NULL);
    /* Report the allocation failure without dereferencing user memory. */
    if (Slot->Mdl == NULL) { return STATUS_INSUFFICIENT_RESOURCES; }
    /* Establish the target's user-mode virtual-address interpretation. */
    KeStackAttachProcess(PsGetThreadProcess(Slot->Thread), attachState);
    /* Probing user memory may raise; the attach must always be unwound. */
    __try {
        /* Pin the requested original page with user-mode access checks. */
        MmProbeAndLockPages(Slot->Mdl, UserMode, IoReadAccess);
        /* Publish ownership of the lock reference only after success. */
        locked = TRUE;
        /* Preserve a successful pinning result. */
        status = STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Convert the probing exception into a typed request failure. */
        status = GetExceptionCode();
    }
    /* Return to the IOCTL caller's original address space. */
    KeUnstackDetachProcess(attachState);
    /* A failed probe never owns a page-lock reference. */
    if (!locked) {
        /* Release only the allocated descriptor. */
        IoFreeMdl(Slot->Mdl);
        /* Keep later cleanup from unlocking an unpinned descriptor. */
        Slot->Mdl = NULL;
        /* Return the precise probing failure. */
        return status;
    }
    /* Resolve the pinned page's stable PFN, independent of future PTE remaps. */
    Slot->PhysicalPage = (ULONGLONG)MmGetMdlPfnArray(Slot->Mdl)[0] << PAGE_SHIFT;
    /* Complete passive target binding. */
    return STATUS_SUCCESS;
}

NTSTATUS KswordARKHvmDebugControl(const KSWORD_ARK_HVM_DEBUG_REQUEST* Request,
    KSWORD_ARK_HVM_DEBUG_RESPONSE* Response, ULONG OwnerProcessId)
{
    /* Use the authoritative runtime lock shared by every EPT mutation. */
    KSW_HVM_RUNTIME* runtime = KswordARKHvmGetRuntime();
    /* Preserve the complete outcome for the adapter. */
    NTSTATUS status = STATUS_SUCCESS;
    /* Bound every metadata traversal. */
    ULONG index;
    /* Select one owned or unused record. */
    KSW_HVM_DEBUG_SLOT* slot = NULL;
    /* Keep the large existing EPT response off the kernel stack. */
    KSWORD_ARK_HVM_EPT_RULE_RESPONSE* ruleResponse = NULL;
    /* Build the existing authoritative EPT rule request. */
    KSWORD_ARK_HVM_EPT_RULE_REQUEST rule = { 0 };
    /* Initialize every response member before validation. */
    RtlZeroMemory(Response, sizeof(*Response));
    /* Publish the independent debugger protocol identity. */
    Response->version = KSWORD_ARK_HVM_DEBUG_VERSION;
    /* Publish the fixed response size. */
    Response->size = sizeof(*Response);
    /* Validate the exact fixed request contract and requestor scope. */
    if (Request->version != KSWORD_ARK_HVM_DEBUG_VERSION || Request->size != sizeof(*Request) ||
        Request->operation > KSWORD_ARK_HVM_DEBUG_REVOKE ||
        (Request->flags & ~KSWORD_ARK_HVM_DEBUG_FLAG_CONFIRMED) != 0UL || OwnerProcessId <= 4UL) {
        /* Report a typed validation failure. */
        Response->status = STATUS_INVALID_PARAMETER;
        /* Return a complete protocol response. */
        return STATUS_SUCCESS;
    }
    /* Keep APC delivery out of the push-lock critical section. */
    KeEnterCriticalRegion();
    /* Serialize metadata with lifecycle transitions and ordinary EPT rules. */
    KswordARKAcquirePushLockExclusive(&runtime->Lock);
    /* 独占不附加会话保留全部 EPT/策略身份，查询仍可读取。 */
    if (KswordARKNoAttachReserved() && Request->operation != KSWORD_ARK_HVM_DEBUG_QUERY) {
        /* 预约检查位于同一运行时锁内，不能与 OPEN 形成检查后写入竞态。 */
        KswordARKReleasePushLockExclusive(&runtime->Lock);
        /* 此拒绝没有修改资源或通用协议台账。 */
        KeLeaveCriticalRegion();
        /* 电源停止后 residentCount=0 也不能接管保留资源。 */
        return STATUS_DEVICE_BUSY;
    }
    /* Publish capability only with a complete lifecycle and MTF restoration path. */
    Response->supported = g_DebugNotifications && runtime->BackendId == KSWORD_ARK_HVM_BACKEND_VMX &&
        (runtime->FeatureFlags & (KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG | KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED)) ==
        (KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG | KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED) ? 1UL : 0UL;
    /* Count published owned records and select one candidate. */
    for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
        /* Bind one fixed record without following guest pointers. */
        KSW_HVM_DEBUG_SLOT* candidate = &runtime->DebugSlots[index];
        /* Count only this caller's published stops. */
        if (candidate->OwnerProcessId == OwnerProcessId && candidate->Enabled != 0L) { ++Response->activeCount; }
        /* Select a free slot for installation or the caller's exact removal ID. */
        if ((Request->operation == KSWORD_ARK_HVM_DEBUG_ADD && slot == NULL && candidate->Id == 0UL) ||
            (Request->operation == KSWORD_ARK_HVM_DEBUG_REMOVE && candidate->Id == Request->breakpointId && candidate->OwnerProcessId == OwnerProcessId)) {
            /* Save the candidate for the transaction. */
            slot = candidate;
        }
        /* Revocation can safely run while residency is active; it only disables injection. */
        if (Request->operation == KSWORD_ARK_HVM_DEBUG_REVOKE && candidate->OwnerProcessId == OwnerProcessId) {
            /* Withdraw the caller's published stop atomically. */
            InterlockedExchange(&candidate->Enabled, 0L);
        }
    }
    /* Queries and emergency revocation do not mutate EPT or backing references. */
    if (Request->operation == KSWORD_ARK_HVM_DEBUG_QUERY || Request->operation == KSWORD_ARK_HVM_DEBUG_REVOKE) { goto Complete; }
    /* Require explicit debugger confirmation for every installation/removal. */
    if ((Request->flags & KSWORD_ARK_HVM_DEBUG_FLAG_CONFIRMED) == 0UL) { status = STATUS_ACCESS_DENIED; goto Complete; }
    /* Do not publish an unprotected debugger stop. */
    if (Response->supported == 0UL) { status = STATUS_NOT_SUPPORTED; goto Complete; }
    /* Mutations obey the existing stopped-residency EPT contract. */
    if (InterlockedCompareExchange(&runtime->ResidentProcessorCount, 0L, 0L) != 0L ||
        (runtime->StateFlags & KSWORD_ARK_HVM_STATE_BUSY) != 0L) { status = STATUS_DEVICE_BUSY; goto Complete; }
    /* Preserve missing-ID and bounded-capacity failures. */
    if (slot == NULL) { status = Request->operation == KSWORD_ARK_HVM_DEBUG_ADD ? STATUS_INSUFFICIENT_RESOURCES : STATUS_NOT_FOUND; goto Complete; }
    /* Allocate the existing large response using the established nonpaged helper. */
    ruleResponse = (KSWORD_ARK_HVM_EPT_RULE_RESPONSE*)KswordARKAllocateNonPagedPool(sizeof(*ruleResponse), 'DbHK');
    /* Stop before mutating any state when allocation failed. */
    if (ruleResponse == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto Complete; }
    /* Bind the existing EPT protocol exactly. */
    rule.version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    /* Publish the complete existing request size. */
    rule.size = sizeof(rule);
    /* Carry explicit confirmation through the existing EPT gate. */
    rule.flags = KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED;
    /* Carry the existing confirmation token. */
    rule.confirmationToken = KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN;
    /* Installation binds a single validated user thread and one pinned page. */
    if (Request->operation == KSWORD_ARK_HVM_DEBUG_ADD) {
        /* Reject kernel/system scope, nonarchitectural registers, and cross-page ranges. */
        if (Request->processId <= 4UL || Request->threadId == 0UL || Request->debugRegister >= 4UL ||
            Request->length == 0UL || Request->length > 8UL || Request->address == 0ULL ||
            Request->address > (ULONGLONG)(ULONG_PTR)MmHighestUserAddress ||
            (Request->address & 0xFFFULL) + Request->length > 0x1000ULL ||
            (Request->access != 3UL && Request->access != KSWORD_ARK_HVM_EPT_ACCESS_WRITE && Request->access != KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE)) {
            /* Reject the complete invalid target without pinning it. */
            status = STATUS_INVALID_PARAMETER;
            /* Leave the selected slot unused. */
            goto Complete;
        }
        /* Pin backing and reference thread identity at PASSIVE_LEVEL. */
        status = KswordARKHvmDebugPin(Request, slot);
        /* Release partial references after any pinning failure. */
        if (!NT_SUCCESS(status)) { KswordARKHvmDebugFreeSlot(slot); goto Complete; }
        /* Reject overlap with ordinary rules whose disposition could override a debug stop. */
        for (index = 0UL; index < KSWORD_ARK_HVM_MAX_EPT_RULES; ++index) {
            /* Bind one authoritative existing permission rule. */
            const KSW_HVM_EPT_RULE_SLOT* existingRule = &runtime->EptRules[index];
            /* Track whether that rule belongs to debugger metadata. */
            BOOLEAN debugOwned = FALSE;
            /* Bound the ownership lookup. */
            ULONG ownerIndex;
            /* Skip rules that do not cover the new pinned page. */
            if (!existingRule->Active || existingRule->PhysicalAddress > slot->PhysicalPage ||
                ((slot->PhysicalPage - existingRule->PhysicalAddress) >> PAGE_SHIFT) >= existingRule->PageCount) { continue; }
            /* Resolve ownership from immutable driver metadata rather than caller flags. */
            for (ownerIndex = 0UL; ownerIndex < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++ownerIndex) {
                /* Match the exact existing assigned rule identity. */
                if (runtime->DebugSlots[ownerIndex].Id != 0UL && runtime->DebugSlots[ownerIndex].RuleId == existingRule->RuleId) { debugOwned = TRUE; break; }
            }
            /* Ordinary strict/watch/enforce rules must not be bypassed by #DB injection. */
            if (!debugOwned) { status = STATUS_DEVICE_BUSY; KswordARKHvmDebugFreeSlot(slot); goto Complete; }
        }
        /* Reuse an already-owned page rule when access permissions are identical. */
        for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
            /* Select an existing debugger rule for the same stable page/mask. */
            KSW_HVM_DEBUG_SLOT* existing = &runtime->DebugSlots[index];
            /* A record with an ID owns its rule even after lifetime revocation. */
            if (existing->Id != 0UL && existing->PhysicalPage == slot->PhysicalPage && existing->Access == Request->access) {
                /* Share the one authoritative EPT rule across thread scopes. */
                slot->RuleId = existing->RuleId;
                /* Stop after the exact permission match. */
                break;
            }
        }
        /* Install permissions through the existing EPT rule implementation. */
        if (slot->RuleId == 0UL) {
            /* Request a new one-instruction grant/restoration rule. */
            rule.operation = KSWORD_ARK_HVM_EPT_RULE_ADD;
            /* Always restore permissions after a single instruction. */
            rule.flags |= KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE | KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG;
            /* Remove only the requested architectural access permissions. */
            rule.deniedAccess = Request->access;
            /* Bind the pinned physical backing page. */
            rule.physicalAddress = slot->PhysicalPage;
            /* Bound one debugger stop to one EPT page. */
            rule.pageCount = 1ULL;
            /* Execute while holding the same authoritative runtime lock. */
            status = KswordARKHvmEptRuleControlLocked(runtime, &rule, ruleResponse, TRUE);
            /* Convert protocol-level rejection into the debugger result. */
            if (NT_SUCCESS(status)) { status = ruleResponse->lastStatus; }
            /* Retire partial backing when permissions were rejected. */
            if (!NT_SUCCESS(status)) { KswordARKHvmDebugFreeSlot(slot); goto Complete; }
            /* Retain the actual assigned rule identity. */
            slot->RuleId = ruleResponse->ruleId;
        }
        /* Allocate a nonzero monotonically increasing debugger identity. */
        slot->Id = ++runtime->NextDebugId;
        /* Skip zero on wrap to preserve the free-record sentinel. */
        if (slot->Id == 0UL) { slot->Id = ++runtime->NextDebugId; }
        /* Bind the actual WDF requestor rather than a caller-supplied owner. */
        slot->OwnerProcessId = OwnerProcessId;
        /* Bind the validated target thread identifier. */
        slot->ThreadId = Request->threadId;
        /* Select the DR6 hit bit recognized by debugger frontends. */
        slot->DebugRegister = Request->debugRegister;
        /* Preserve the requested R/W/X semantics. */
        slot->Access = Request->access;
        /* Preserve execution address and data-range metadata. */
        slot->Address = Request->address;
        /* Publish fully initialized metadata before VM-exit may consult it. */
        KeMemoryBarrier();
        /* Enable the complete debugger record atomically. */
        InterlockedExchange(&slot->Enabled, InterlockedIncrement(&g_DebugPublication));
        /* Reserve zero exclusively for a withdrawn record, including wraparound. */
        if (slot->Enabled == 0L) { InterlockedExchange(&slot->Enabled, InterlockedIncrement(&g_DebugPublication)); }
        /* Retire a target that exited before publication completed. */
        if (PsIsThreadTerminating(slot->Thread)) { InterlockedExchange(&slot->Enabled, 0L); }
        /* Preserve lifetime revocation as an explicit installation failure. */
        if (slot->Enabled == 0L) { status = STATUS_THREAD_IS_TERMINATING; }
        /* Publish the assigned debugger stop, including a revoked record needing retirement. */
        Response->breakpointId = slot->Id;
        /* Publish the authoritative backing rule. */
        Response->ruleId = slot->RuleId;
    } else {
        /* Detect another record still owning the shared EPT rule. */
        BOOLEAN shared = FALSE;
        /* Withdraw this exact stop before its backing resources are retired. */
        InterlockedExchange(&slot->Enabled, 0L);
        /* Scan bounded ownership rather than dropping another debugger's rule. */
        for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
            /* Select any other record owning the same rule identity. */
            if (&runtime->DebugSlots[index] != slot && runtime->DebugSlots[index].Id != 0UL && runtime->DebugSlots[index].RuleId == slot->RuleId) { shared = TRUE; }
        }
        /* Remove permissions only when the last debugger record retires. */
        if (!shared) {
            /* Name the exact existing rule to remove. */
            rule.operation = KSWORD_ARK_HVM_EPT_RULE_REMOVE;
            /* Carry the pinned rule's actual identity. */
            rule.ruleId = slot->RuleId;
            /* Retire through the authoritative EPT rule implementation. */
            status = KswordARKHvmEptRuleControlLocked(runtime, &rule, ruleResponse, TRUE);
            /* Preserve protocol-level failure, keeping the pin for recovery. */
            if (NT_SUCCESS(status)) { status = ruleResponse->lastStatus; }
        }
        /* Release backing only after rule retirement succeeded. */
        if (NT_SUCCESS(status)) { KswordARKHvmDebugFreeSlot(slot); }
    }
Complete:
    /* Publish the post-transaction number of this debugger's enabled records. */
    Response->activeCount = 0UL;
    /* Count only the caller's fully enabled leases. */
    for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
        /* Keep revoked records out of the active capability count. */
        if (runtime->DebugSlots[index].OwnerProcessId == OwnerProcessId && runtime->DebugSlots[index].Enabled != 0L) { ++Response->activeCount; }
    }
    /* Publish the exact operation outcome. */
    Response->status = status;
    /* Retire the temporary large response without touching pinned target pages. */
    if (ruleResponse != NULL) { ExFreePoolWithTag(ruleResponse, 'DbHK'); }
    /* Release the one lock shared by lifecycle and EPT mutations. */
    KswordARKReleasePushLockExclusive(&runtime->Lock);
    /* Restore ordinary APC delivery outside the mutation lock. */
    KeLeaveCriticalRegion();
    /* Complete the fixed protocol packet even for operation-level rejection. */
    return STATUS_SUCCESS;
}

#if defined(_M_AMD64)
ULONG KswordARKHvmDebugMatchExit(KSW_HVM_RESIDENT_VCPU* Context, ULONGLONG PhysicalAddress, ULONG Access, ULONGLONG* Teb)
{
    /* Read only architectural VMCS state in VMX root. */
    SIZE_T gs = 0U, ss = 0U, dr7 = 0U, flags = 0U, rip = 0U;
    /* Aggregate architectural hit bits across overlapping debugger scopes. */
    ULONG mask = 0UL, index;
    /* Default to an unbound thread on any failed VMCS read. */
    *Teb = 0ULL;
    /* Every scope field is required before a guest debug exception is considered. */
    if (KswordARKHvmVmcsFieldLoad(0x6810UL, &gs) != 0U || KswordARKHvmVmcsFieldLoad(0x4818UL, &ss) != 0U ||
        KswordARKHvmVmcsFieldLoad(0x681AUL, &dr7) != 0U || KswordARKHvmVmcsFieldLoad(0x6820UL, &flags) != 0U ||
        KswordARKHvmVmcsFieldLoad(0x681EUL, &rip) != 0U) { return 0UL; }
    /* Publish the architectural user TEB for deferred data-stop validation. */
    *Teb = (ULONGLONG)gs;
    /* Scan only fixed, nonpaged, immutable published records. */
    for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
        /* Reference one preallocated metadata record. */
        const KSW_HVM_DEBUG_SLOT* slot = &Context->Runtime->DebugSlots[index];
        /* Reject revoked scope, another physical page, another TEB, or RF-suppressed execution. */
        if (slot->Enabled != 0L && slot->PhysicalPage == (PhysicalAddress & ~0xFFFULL) &&
            KswordArkHvmDebugMatch(Access, slot->Access, slot->DebugRegister, (ULONGLONG)dr7,
                (ULONGLONG)flags, (ULONG)(((ULONGLONG)ss >> 5) & 3ULL), (ULONGLONG)gs, slot->Teb, (ULONGLONG)rip, slot->Address)) {
            /* Report the debugger's corresponding architectural register bit. */
            mask |= 1UL << slot->DebugRegister;
        }
    }
    /* Return exact execution scope or documented EPT page-level data scope. */
    return mask;
}

BOOLEAN KswordARKHvmDebugInject(ULONG Mask)
{
    /* Preserve an already pending guest event rather than overwriting it. */
    SIZE_T entry = 0U, interruptibility = 0U;
    /* MOV-SS blocking and a pending event forbid an immediate #DB injection. */
    if (Mask == 0UL || KswordARKHvmVmcsFieldLoad(0x4016UL, &entry) != 0U ||
        KswordARKHvmVmcsFieldLoad(0x4824UL, &interruptibility) != 0U ||
        (entry & 0x80000000ULL) != 0U || (interruptibility & 2U) != 0U) { return FALSE; }
    /* Preserve architecturally required DR6 bits and report only selected hit slots. */
    __writedr(6, (__readdr(6) & ~0xFULL) | (ULONGLONG)(Mask & 0xFUL) | 0xFFFF0FF0ULL);
    /* Inject hardware exception vector one with no error code. */
    return KswordARKHvmVmcsFieldStore(0x4016UL, 0x80000301ULL) == 0U;
}

BOOLEAN KswordARKHvmDebugMonitorTrap(KSW_HVM_RESIDENT_VCPU* Context)
{
    /* Capture the pending hit before resetting the one-step record. */
    ULONG pending = Context->DebugPendingMask;
    /* Filter each pending register through the still-published lifetime scope. */
    ULONG mask = 0UL, index;
    /* Read the post-instruction thread, ring, and debug-enable state. */
    SIZE_T gs = 0U, ss = 0U, dr7 = 0U;
    /* Retire the pending state on every monitor-trap path. */
    Context->DebugPendingMask = 0UL;
    /* Ordinary EPT restoration has no debugger stop to inject. */
    if (pending == 0UL) { return TRUE; }
    /* Require all architectural fields for an actual data-instruction completion. */
    if (KswordARKHvmVmcsFieldLoad(0x6810UL, &gs) != 0U || KswordARKHvmVmcsFieldLoad(0x4818UL, &ss) != 0U ||
        KswordARKHvmVmcsFieldLoad(0x681AUL, &dr7) != 0U) { return FALSE; }
    /* An intervening interrupt or context switch must retry instead of reporting a false completion. */
    if ((ULONGLONG)gs != Context->DebugPendingTeb || (((ULONGLONG)ss >> 5) & 3ULL) != 3ULL) { return TRUE; }
    /* Retire individual slots cleared by detach or target/debugger exit. */
    for (index = 0UL; index < KSWORD_ARK_HVM_DEBUG_MAX_SLOTS; ++index) {
        /* Bind one immutable bounded metadata record. */
        const KSW_HVM_DEBUG_SLOT* slot = &Context->Runtime->DebugSlots[index];
        /* Preserve only enabled data stops for this exact architectural thread. */
        if (slot->Enabled != 0L && slot->DebugRegister < 4UL && (slot->Access & KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE) == 0UL &&
            (pending & (1UL << slot->DebugRegister)) != 0UL && slot->Teb == (ULONGLONG)gs &&
            (dr7 & (3ULL << (slot->DebugRegister * 2UL))) != 0ULL) { mask |= 1UL << slot->DebugRegister; }
    }
    /* No revoked pending stop may inject a stale guest exception. */
    if (mask == 0UL) { return TRUE; }
    /* Deliver the data stop only after the original instruction and leaf restoration. */
    return KswordARKHvmDebugInject(mask);
}
#else
/* Non-AMD64 drivers never publish the VMX debugger capability. */
ULONG KswordARKHvmDebugMatchExit(KSW_HVM_RESIDENT_VCPU* Context, ULONGLONG PhysicalAddress, ULONG Access, ULONGLONG* Teb)
{
    /* Preserve the portable ABI without executing architectural instructions. */
    UNREFERENCED_PARAMETER(Context); UNREFERENCED_PARAMETER(PhysicalAddress); UNREFERENCED_PARAMETER(Access);
    /* Publish no bound thread on this architecture. */
    *Teb = 0ULL;
    /* Report no guest breakpoint. */
    return 0UL;
}
/* Unsupported architectures cannot inject VMX events. */
BOOLEAN KswordARKHvmDebugInject(ULONG Mask) { UNREFERENCED_PARAMETER(Mask); return FALSE; }
/* Unsupported architectures have no deferred VMX debugger state. */
BOOLEAN KswordARKHvmDebugMonitorTrap(KSW_HVM_RESIDENT_VCPU* Context) { UNREFERENCED_PARAMETER(Context); return FALSE; }
#endif
