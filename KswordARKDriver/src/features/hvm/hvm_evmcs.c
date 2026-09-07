/*++

Module Name:

    hvm_evmcs.c

Abstract:

    Implements Hyper-V TLFS CPUID discovery without build-number guesses.
    Root-partition and incomplete VP-assist ownership remain explicit partial
    states rather than being advertised as an active eVMCS implementation.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_evmcs.h"

#if defined(_M_AMD64)
#include <intrin.h>

/* Name the TLFS hypervisor vendor and maximum-leaf CPUID leaf. */
#define KSW_HV_CPUID_VENDOR_AND_MAX 0x40000000UL
/* Name the TLFS interface-identification CPUID leaf. */
#define KSW_HV_CPUID_INTERFACE 0x40000001UL
/* Name the TLFS partition-privilege CPUID leaf. */
#define KSW_HV_CPUID_FEATURES 0x40000003UL
/* Name the TLFS implementation-recommendation CPUID leaf. */
#define KSW_HV_CPUID_RECOMMENDATIONS 0x40000004UL
/* Name the TLFS nested-virtualization feature CPUID leaf. */
#define KSW_HV_CPUID_NESTED_FEATURES 0x4000000AUL
/* Encode the TLFS Hv#1 interface signature. */
#define KSW_HV_INTERFACE_SIGNATURE 0x31237648UL
/* Identify the root-only CreatePartitions privilege. */
#define KSW_HV_PARTITION_PRIVILEGE_CREATE_PARTITIONS 0x00000001UL
/* Identify the TLFS recommendation to use the eVMCS interface. */
#define KSW_HV_RECOMMEND_EVMCS (1UL << 14)

VOID
KswordARKHvmEvmcsDiscover(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    int registers[4] = { 0 };
    ULONG maximumLeaf = 0UL;
    ULONG interfaceSignature = 0UL;
    ULONG partitionPrivileges = 0UL;
    ULONG recommendations = 0UL;
    UCHAR versionLow = 0U;
    UCHAR versionHigh = 0U;
    USHORT version = 0U;

    /* Reject a missing runtime before executing CPUID. */
    if (Runtime == NULL) {
        /* Return without publishing partial capability state. */
        return;
    }
    /* Initialize eVMCS status to an explicit unavailable baseline. */
    Runtime->EvmcsState =
        KSWORD_ARK_HVM_EVMCS_STATE_UNAVAILABLE;
    /* Initialize implementation maturity to unsupported. */
    Runtime->EvmcsImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    /* Initialize the discovered version to zero. */
    Runtime->EvmcsVersion = 0U;
    /* Clear stale TLFS partition and VP-assist evidence. */
    Runtime->EvmcsFlags = 0UL;
    /* Clear stale VP-assist MSR evidence. */
    Runtime->EvmcsVpAssistMsr = 0ULL;
    /* Stop when CPUID does not report an active hypervisor. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) == 0ULL) {
        /* Return with the explicit unavailable baseline. */
        return;
    }
    /* Read the TLFS vendor string and maximum synthetic leaf. */
    __cpuid(registers, (int)KSW_HV_CPUID_VENDOR_AND_MAX);
    /* Preserve the maximum synthetic CPUID leaf. */
    maximumLeaf = (ULONG)registers[0];
    /* Stop unless the complete Hv#1 nested feature range is available. */
    if (maximumLeaf < KSW_HV_CPUID_NESTED_FEATURES) {
        /* Return with the explicit unavailable baseline. */
        return;
    }
    /* Read and validate the TLFS interface signature. */
    __cpuid(registers, (int)KSW_HV_CPUID_INTERFACE);
    /* Preserve the synthetic interface signature. */
    interfaceSignature = (ULONG)registers[0];
    /* Stop unless Hyper-V advertises the Hv#1 interface. */
    if (interfaceSignature != KSW_HV_INTERFACE_SIGNATURE) {
        /* Return with the explicit unavailable baseline. */
        return;
    }
    /* Read partition privilege evidence without guessing Windows builds. */
    __cpuid(registers, (int)KSW_HV_CPUID_FEATURES);
    /* Preserve the TLFS partition privilege mask. */
    partitionPrivileges = (ULONG)registers[1];
    /* Read the TLFS implementation recommendations. */
    __cpuid(registers, (int)KSW_HV_CPUID_RECOMMENDATIONS);
    /* Preserve the recommendation mask from EAX. */
    recommendations = (ULONG)registers[0];
    /* Require the explicit TLFS eVMCS recommendation. */
    if ((recommendations & KSW_HV_RECOMMEND_EVMCS) == 0UL) {
        /* Return with the explicit unavailable baseline. */
        return;
    }
    /* Read the TLFS nested-virtualization feature leaf. */
    __cpuid(registers, (int)KSW_HV_CPUID_NESTED_FEATURES);
    /* Decode the lowest supported eVMCS version from EAX bits seven through zero. */
    versionLow = (UCHAR)((ULONG)registers[0] & 0xFFUL);
    /* Decode the highest supported eVMCS version from EAX bits fifteen through eight. */
    versionHigh =
        (UCHAR)(((ULONG)registers[0] >> 8) & 0xFFUL);
    /* Require the currently defined eVMCS version one inside the range. */
    if (versionLow > 1U ||
        versionHigh < 1U) {
        /* Return with the explicit unavailable baseline. */
        return;
    }
    /* Select the only eVMCS structure version currently defined by TLFS. */
    version = 1U;
    /* Publish capability evidence independently from activation state. */
    Runtime->FeatureFlags |=
        KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_CAPABLE;
    /* Preserve the exact TLFS-advertised version. */
    Runtime->EvmcsVersion = version;
    /* Publish the capability-only state before partition validation. */
    Runtime->EvmcsState =
        KSWORD_ARK_HVM_EVMCS_STATE_CAPABILITY_ONLY;
    /* Publish capability-only maturity before partition validation. */
    Runtime->EvmcsImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
    /* Refuse root-partition eVMCS because TLFS supports guest partitions only. */
    if ((partitionPrivileges &
            KSW_HV_PARTITION_PRIVILEGE_CREATE_PARTITIONS) != 0UL) {
        /* Publish the TLFS root-partition boundary. */
        Runtime->EvmcsFlags |=
            KSWORD_ARK_HVM_EVMCS_FLAG_ROOT_PARTITION;
        /* Preserve capability evidence while refusing an unsupported owner. */
        return;
    }
    /* Publish version-one capability when the advertised range includes it. */
    if (version >= 1U) {
        /* Publish the protocol-visible eVMCS v1 feature. */
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_V1;
        /* Publish that v1 structures are discoverable but remain partial. */
        Runtime->EvmcsState =
            KSWORD_ARK_HVM_EVMCS_STATE_V1_PARTIAL;
        /* Publish explicit partial maturity until VP-assist ownership is active. */
        Runtime->EvmcsImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
        /* Publish protocol-visible partial state. */
        KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL);
    }
}

NTSTATUS
KswordARKHvmEvmcsValidate(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONGLONG vpAssistMsr = 0ULL;

    /* Reject a missing runtime before evaluating discovered TLFS state. */
    if (Runtime == NULL) {
        /* Return the exact caller-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require a guest-partition eVMCS v1 capability path. */
    if (Runtime->EvmcsState !=
            KSWORD_ARK_HVM_EVMCS_STATE_V1_PARTIAL ||
        Runtime->EvmcsVersion < 1U) {
        /* Return the explicit unsupported partition or feature result. */
        return STATUS_NOT_SUPPORTED;
    }
    /* Read the current VP-assist-page MSR without changing outer ownership. */
    __try {
        /* Capture the exact current VP-assist-page MSR value. */
        vpAssistMsr =
            __readmsr(KSW_HV_X64_MSR_VP_ASSIST_PAGE);
        /* Publish that the TLFS VP-assist MSR was readable. */
        Runtime->EvmcsFlags |=
            KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_READABLE;
        /* Preserve the complete current VP-assist MSR value. */
        Runtime->EvmcsVpAssistMsr = vpAssistMsr;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        /* Preserve explicit partial maturity after a virtual-MSR fault. */
        Runtime->EvmcsImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
        /* Return the exact virtual-MSR exception. */
        return GetExceptionCode();
    }
    /* Detect an outer owner before allocating or replacing any assist page. */
    if ((vpAssistMsr & 0x1ULL) != 0ULL) {
        /* Publish the active VP-assist-page state. */
        Runtime->EvmcsFlags |=
            KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_ENABLED;
        /* Publish explicit ownership conflict without modifying the page. */
        Runtime->EvmcsFlags |=
            KSWORD_ARK_HVM_EVMCS_FLAG_OWNERSHIP_CONFLICT;
    }
    /*
     * The current protocol deliberately reports PARTIAL until a per-VP assist
     * page can be exclusively saved, replaced, and restored on every CPU.
     */
    Runtime->EvmcsImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL;
    /* Preserve protocol-visible partial state. */
    KswordARKHvmStateSet(Runtime, KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL);
    /* Return not-implemented so callers cannot mistake validation for active. */
    return STATUS_NOT_IMPLEMENTED;
}

#else

VOID
KswordARKHvmEvmcsDiscover(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
}

NTSTATUS
KswordARKHvmEvmcsValidate(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Return the explicit architecture boundary. */
    return STATUS_NOT_SUPPORTED;
}

#endif
