/* Pure routing; no MSR, port, guest-memory, RIP or exception-injection side effects. */
#include "hvm_svm_nested_route.h"

/* Ownership decisions use immutable VMCB and permission snapshots from the same VMRUN. */
unsigned int KswSvmNestedRouteExit(const KSW_SVM_VMCB* Outer,
    const KSW_SVM_VMCB* Inner, const KSW_NSVM_PERMISSION_VIEW* OuterMaps,
    const KSW_NSVM_PERMISSION_VIEW* InnerMaps, KSW_SVM_U64 Code,
    KSW_SVM_U64 Info1, unsigned int Msr, KSW_NSVM_EXIT_ROUTE* Result)
{
    /* Unknown is a retained fault until an explicit architecture path classifies it. */
    const KSW_NSVM_EXIT_ROUTE empty = {0};
    /* Raw bitmap results must not be confused with the two-bit ownership set. */
    unsigned int outer, inner;
    /* A missing output cannot produce an undocumented routing choice. */
    if (!Result) { return KSW_NSVM_ROUTE_FAULT; }
    /* Keep the complete raw code, including hardware INVALID=-1. */
    *Result = empty; Result->Code = Code; Result->Info1 = Info1;
    /* The combined hardware image cannot be used as a source ownership bitmap. */
    if (!Outer || !Inner) { return Result->Action; }
    /* NPF must be translated to determine whether L0 or L1 caused it. */
    if (Code == KSW_SVM_EXIT_NPF) { Result->Action = KSW_NSVM_ROUTE_NPF; return Result->Action; }
    /* Permission-protected exits need the specific MSR/port bits, not the coarse intercept. */
    if (Code == KSW_SVM_EXIT_MSR || Code == 0x7bULL) {
        /* A view from a different entry must not authorize the captured source VMCB. */
        if (!OuterMaps || !InnerMaps ||
            ((OuterMaps->Flags ^ (unsigned int)KswSvmRead64(Outer, KSW_VMCB_MISC1)) & KSW_NSVM_PERMISSION_FLAGS) ||
            ((InnerMaps->Flags ^ (unsigned int)KswSvmRead64(Inner, KSW_VMCB_MISC1)) & KSW_NSVM_PERMISSION_FLAGS)) {
            /* Report inconsistent ownership rather than silently assuming the map is disabled. */
            Result->Owners = KSW_NSVM_OWNER_INVALID; return Result->Action;
        }
        /* Malformed direction/width metadata remains an explicit invalid ownership result. */
        Result->Owners = KswSvmNestedPermissionOwners(OuterMaps, InnerMaps, Code, Info1, Msr);
    } else {
        /* Every baseline intercept uses its own corresponding CR/DR/exception/misc bit. */
        outer = KswSvmNestedInterceptRequested(Outer, Code);
        /* L1 request is read independently of L0's mandatory intercept set. */
        inner = KswSvmNestedInterceptRequested(Inner, Code);
        /* Unsupported extension exit numbers cannot become bitmap indices. */
        if (outer == KSW_NSVM_INTERCEPT_UNKNOWN || inner == KSW_NSVM_INTERCEPT_UNKNOWN) { return Result->Action; }
        /* Build an ownership set that can represent shared intercepts without priority loss. */
        Result->Owners = (outer ? KSW_NSVM_OWNER_L0 : 0) | (inner ? KSW_NSVM_OWNER_L1 : 0);
    }
    /* An impossible exit or malformed permission record must remain diagnosable. */
    if (!Result->Owners || (Result->Owners & KSW_NSVM_OWNER_INVALID)) { return Result->Action; }
    /* Physical INTR/NMI/SMI/INIT are still pending in hardware after interception.
       Reflecting them without GIF/masking arbitration can livelock the physical CPU. */
    if (Code >= 0x60ULL && Code <= 0x63ULL) {
        /* The event arbiter, not ordinary instruction emulation, owns this decision. */
        Result->Action = KSW_NSVM_ROUTE_ASYNC; return Result->Action;
    }
    /* Reflect first even when L0 requested the same exit; do not pre-execute the operation. */
    if (Result->Owners & KSW_NSVM_OWNER_L1) { Result->Action = KSW_NSVM_ROUTE_REFLECT; }
    /* L0 must still have an implemented handler before resuming this guest. */
    else { Result->Action = KSW_NSVM_ROUTE_EMULATE; }
    /* No guest register, memory, instruction pointer or injection field changed. */
    return Result->Action;
}
