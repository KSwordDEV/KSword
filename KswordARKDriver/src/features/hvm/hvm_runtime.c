/*++

Module Name:

    hvm_runtime.c

Abstract:

    Owns the VT-x capability snapshot, per-processor VMX regions, serialized
    lifecycle control, VMXON/VMXOFF validation, and an explicitly confirmed
    one-shot VMCALL guest.  EPT hierarchy construction is implemented by the
    dedicated builder module.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_internal.h"
#include "hvm_guest.h"
#include "hvm_ept.h"
#include "hvm_event.h"
#include "hvm_evmcs.h"
#include "hvm_mtrr.h"
#include "hvm_nested.h"
#include "hvm_resident.h"

#if defined(_M_AMD64)
#include <intrin.h>

NTKERNELAPI VOID
KeGenericCallDpc(
    _In_ PKDEFERRED_ROUTINE Routine,
    _In_opt_ PVOID Context
    );

NTKERNELAPI LOGICAL
KeSignalCallDpcSynchronize(
    _Inout_ PVOID SystemArgument2
    );

NTKERNELAPI VOID
KeSignalCallDpcDone(
    _In_ PVOID SystemArgument1
    );

#define KSW_HVM_IA32_VMX_PINBASED_CTLS 0x481UL
#define KSW_HVM_IA32_VMX_EXIT_CTLS 0x483UL
#define KSW_HVM_IA32_VMX_ENTRY_CTLS 0x484UL
#define KSW_HVM_IA32_VMX_MISC 0x485UL
#define KSW_HVM_IA32_VMX_TRUE_PINBASED_CTLS 0x48DUL
#define KSW_HVM_IA32_VMX_TRUE_EXIT_CTLS 0x48FUL
#define KSW_HVM_IA32_VMX_TRUE_ENTRY_CTLS 0x490UL
#define KSW_HVM_IA32_VMX_PROCBASED_CTLS3 0x492UL
#define KSW_HVM_IA32_VMX_EXIT_CTLS2 0x493UL
#define KSW_HVM_VMX_ACTIVATE_TERTIARY (1ULL << 17)
#define KSW_HVM_VMX_ACTIVATE_SECONDARY (1ULL << 31)
#define KSW_HVM_VMX_EXIT_ACTIVATE_SECONDARY (1ULL << 31)
#define KSW_HVM_VMX_ENABLE_EPT (1ULL << 1)
#define KSW_HVM_VMX_ENABLE_VPID (1ULL << 5)

/* 这些槽位只保存架构上应当跨逻辑处理器一致的原始能力事实。 */
typedef enum _KSW_HVM_CAPABILITY_SLOT
{
    KswordHvmCapFeatureControl = 0,
    KswordHvmCapVmxBasic,
    KswordHvmCapCr0Fixed0,
    KswordHvmCapCr0Fixed1,
    KswordHvmCapCr4Fixed0,
    KswordHvmCapCr4Fixed1,
    KswordHvmCapPrimaryControls,
    KswordHvmCapTruePrimaryControls,
    KswordHvmCapSecondaryControls,
    KswordHvmCapTertiaryControls,
    KswordHvmCapExitControls,
    KswordHvmCapTrueExitControls,
    KswordHvmCapSecondaryExitControls,
    KswordHvmCapEntryControls,
    KswordHvmCapTrueEntryControls,
    KswordHvmCapPinControls,
    KswordHvmCapTruePinControls,
    KswordHvmCapVmxMisc,
    KswordHvmCapEptVpid,
    KswordHvmCapCpuidMaxBasic,
    KswordHvmCapCpuid7Subleaf0Ebx,
    KswordHvmCapCpuid7Subleaf0EcxEdx,
    KswordHvmCapCpuid7Subleaf1EaxEdx,
    KswordHvmCapCpuidDSubleaf1EaxEcx,
    KswordHvmCapCpuidMaxExtended,
    KswordHvmCapCpuidExtended1Edx,
    KswordHvmCapCpuidExtended8Eax,
    KswordHvmCapCpuid7MaxSubleaf,
    KswordHvmCapCount
} KSW_HVM_CAPABILITY_SLOT;

typedef struct _KSW_HVM_CAPABILITY_VERIFY_CONTEXT
{
    ULONGLONG Reference[KswordHvmCapCount];
    volatile LONG SampleCount;
    volatile LONG FailureCount;
    volatile LONG MismatchCount;
    volatile LONG FirstMismatchProcessor;
    volatile LONG FirstMismatchSlot;
} KSW_HVM_CAPABILITY_VERIFY_CONTEXT;
#endif

#define KSW_HVM_LIFECYCLE_BUGCHECK_CODE 0x00020001UL
#define KSW_HVM_POWER_FAILURE_SIGNATURE 0x48564D50UL
#define KSW_HVM_UNLOAD_FAILURE_SIGNATURE 0x48564D55UL

static KSW_HVM_RUNTIME g_KswordHvm;

KSW_HVM_RUNTIME*
KswordARKHvmGetRuntime(
    VOID
    )
{
    /* Return the process-wide nonpaged runtime for VM-exit telemetry. */
    return &g_KswordHvm;
}

static VOID
KswordARKHvmCopyAscii(
    _Out_writes_(DestinationChars) CHAR* Destination,
    _In_ ULONG DestinationChars,
    _In_reads_bytes_(SourceBytes) const CHAR* Source,
    _In_ ULONG SourceBytes
    )
{
    ULONG copyBytes = 0UL;

    /* Keep every protocol string bounded and NUL terminated. */
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    RtlZeroMemory(Destination, DestinationChars);
    if (Source == NULL || SourceBytes == 0UL) {
        return;
    }
    copyBytes = SourceBytes < (DestinationChars - 1UL)
        ? SourceBytes
        : (DestinationChars - 1UL);
    RtlCopyMemory(Destination, Source, copyBytes);
}

#if defined(_M_AMD64)
static NTSTATUS
KswordARKHvmSampleCapabilityFacts(
    _Out_writes_(KswordHvmCapCount) ULONGLONG* Sample
    )
{
    int registers[4] = { 0 };
    ULONGLONG vmxBasic = 0ULL;
    ULONGLONG primaryControls = 0ULL;
    ULONGLONG secondaryControls = 0ULL;
    ULONGLONG exitControls = 0ULL;
    ULONG maxBasicLeaf = 0UL;
    ULONG maxStructuredSubleaf = 0UL;
    ULONG maxExtendedLeaf = 0UL;

    if (Sample == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(
        Sample,
        sizeof(ULONGLONG) * KswordHvmCapCount);

    /* 每个受门控的 MSR 都使用同一颗逻辑处理器上的门控位判断。 */
    __try {
        Sample[KswordHvmCapFeatureControl] =
            __readmsr(KSW_IA32_FEATURE_CONTROL);
        vmxBasic = __readmsr(KSW_IA32_VMX_BASIC);
        Sample[KswordHvmCapVmxBasic] = vmxBasic;
        Sample[KswordHvmCapCr0Fixed0] =
            __readmsr(KSW_IA32_VMX_CR0_FIXED0);
        Sample[KswordHvmCapCr0Fixed1] =
            __readmsr(KSW_IA32_VMX_CR0_FIXED1);
        Sample[KswordHvmCapCr4Fixed0] =
            __readmsr(KSW_IA32_VMX_CR4_FIXED0);
        Sample[KswordHvmCapCr4Fixed1] =
            __readmsr(KSW_IA32_VMX_CR4_FIXED1);

        primaryControls = __readmsr(KSW_IA32_VMX_PROCBASED_CTLS);
        exitControls = __readmsr(KSW_HVM_IA32_VMX_EXIT_CTLS);
        Sample[KswordHvmCapPrimaryControls] = primaryControls;
        Sample[KswordHvmCapExitControls] = exitControls;
        Sample[KswordHvmCapEntryControls] =
            __readmsr(KSW_HVM_IA32_VMX_ENTRY_CTLS);
        Sample[KswordHvmCapPinControls] =
            __readmsr(KSW_HVM_IA32_VMX_PINBASED_CTLS);
        Sample[KswordHvmCapVmxMisc] =
            __readmsr(KSW_HVM_IA32_VMX_MISC);

        if ((vmxBasic & (1ULL << 55)) != 0ULL) {
            Sample[KswordHvmCapTruePrimaryControls] =
                __readmsr(KSW_IA32_VMX_TRUE_PROCBASED_CTLS);
            Sample[KswordHvmCapTrueExitControls] =
                __readmsr(KSW_HVM_IA32_VMX_TRUE_EXIT_CTLS);
            Sample[KswordHvmCapTrueEntryControls] =
                __readmsr(KSW_HVM_IA32_VMX_TRUE_ENTRY_CTLS);
            Sample[KswordHvmCapTruePinControls] =
                __readmsr(KSW_HVM_IA32_VMX_TRUE_PINBASED_CTLS);
        }

        if (((primaryControls >> 32) &
                KSW_HVM_VMX_ACTIVATE_SECONDARY) != 0ULL) {
            secondaryControls =
                __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
            Sample[KswordHvmCapSecondaryControls] =
                secondaryControls;
            if (((secondaryControls >> 32) &
                    (KSW_HVM_VMX_ENABLE_EPT |
                     KSW_HVM_VMX_ENABLE_VPID)) != 0ULL) {
                Sample[KswordHvmCapEptVpid] =
                    __readmsr(KSW_IA32_VMX_EPT_VPID_CAP);
            }
        }
        if (((primaryControls >> 32) &
                KSW_HVM_VMX_ACTIVATE_TERTIARY) != 0ULL) {
            Sample[KswordHvmCapTertiaryControls] =
                __readmsr(KSW_HVM_IA32_VMX_PROCBASED_CTLS3);
        }
        if (((exitControls >> 32) &
                KSW_HVM_VMX_EXIT_ACTIVATE_SECONDARY) != 0ULL) {
            Sample[KswordHvmCapSecondaryExitControls] =
                __readmsr(KSW_HVM_IA32_VMX_EXIT_CTLS2);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    /* CPUID 只采样能力叶，排除缓存、核心类型等按处理器变化的叶。 */
    __cpuid(registers, 0);
    maxBasicLeaf = (ULONG)registers[0];
    Sample[KswordHvmCapCpuidMaxBasic] = maxBasicLeaf;
    if (maxBasicLeaf >= 7UL) {
        __cpuidex(registers, 7, 0);
        maxStructuredSubleaf = (ULONG)registers[0];
        Sample[KswordHvmCapCpuid7MaxSubleaf] =
            maxStructuredSubleaf;
        Sample[KswordHvmCapCpuid7Subleaf0Ebx] =
            (ULONG)registers[1];
        Sample[KswordHvmCapCpuid7Subleaf0EcxEdx] =
            ((ULONGLONG)(ULONG)registers[2] << 32) |
            (ULONG)registers[3];
        if (maxStructuredSubleaf >= 1UL) {
            __cpuidex(registers, 7, 1);
            Sample[KswordHvmCapCpuid7Subleaf1EaxEdx] =
                ((ULONGLONG)(ULONG)registers[0] << 32) |
                (ULONG)registers[3];
        }
    }
    if (maxBasicLeaf >= 0xDUL) {
        __cpuidex(registers, 0xD, 1);
        Sample[KswordHvmCapCpuidDSubleaf1EaxEcx] =
            ((ULONGLONG)(ULONG)registers[0] << 32) |
            (ULONG)registers[2];
    }

    __cpuid(registers, (int)0x80000000UL);
    maxExtendedLeaf = (ULONG)registers[0];
    Sample[KswordHvmCapCpuidMaxExtended] = maxExtendedLeaf;
    if (maxExtendedLeaf >= 0x80000001UL) {
        __cpuid(registers, (int)0x80000001UL);
        Sample[KswordHvmCapCpuidExtended1Edx] =
            (ULONG)registers[3];
    }
    if (maxExtendedLeaf >= 0x80000008UL) {
        __cpuid(registers, (int)0x80000008UL);
        Sample[KswordHvmCapCpuidExtended8Eax] =
            (ULONG)registers[0];
    }
    return STATUS_SUCCESS;
}

static VOID
KswordARKHvmVerifyCapabilitiesDpc(
    _In_ struct _KDPC* Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    )
{
    KSW_HVM_CAPABILITY_VERIFY_CONTEXT* context =
        (KSW_HVM_CAPABILITY_VERIFY_CONTEXT*)DeferredContext;
    ULONGLONG sample[KswordHvmCapCount] = { 0 };
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG slot = 0UL;
    ULONG processor = KeGetCurrentProcessorNumberEx(NULL);

    UNREFERENCED_PARAMETER(Dpc);
    status = KswordARKHvmSampleCapabilityFacts(sample);
    if (!NT_SUCCESS(status)) {
        InterlockedIncrement(&context->FailureCount);
    } else {
        for (slot = 0UL; slot < KswordHvmCapCount; ++slot) {
            if (sample[slot] == context->Reference[slot]) {
                continue;
            }
            if (InterlockedIncrement(&context->MismatchCount) == 1L) {
                context->FirstMismatchProcessor = (LONG)processor;
                context->FirstMismatchSlot = (LONG)slot;
            }
            break;
        }
    }
    InterlockedIncrement(&context->SampleCount);
    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

static NTSTATUS
KswordARKHvmVerifyUniformCapabilities(
    VOID
    )
{
    KSW_HVM_CAPABILITY_VERIFY_CONTEXT context = { 0 };
    ULONG processorCountBefore = 0UL;
    ULONG processorCountAfter = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    status = KswordARKHvmSampleCapabilityFacts(context.Reference);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    context.FirstMismatchProcessor = -1L;
    context.FirstMismatchSlot = -1L;
    processorCountBefore =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (processorCountBefore == 0UL ||
        processorCountBefore > KSWORD_ARK_HVM_MAX_PROCESSORS) {
        return STATUS_NOT_SUPPORTED;
    }

    KeGenericCallDpc(KswordARKHvmVerifyCapabilitiesDpc, &context);
    processorCountAfter =
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (processorCountAfter != processorCountBefore ||
        context.SampleCount != (LONG)processorCountBefore ||
        context.FailureCount != 0L ||
        context.MismatchCount != 0L) {
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN
KswordARKHvmReadCapabilities(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    int registers[4] = { 0 };
    CHAR vendor[13] = { 0 };
    CHAR hypervisorVendor[13] = { 0 };
    ULONG leaf1Ecx = 0UL;
    ULONGLONG primaryControls = 0ULL;
    ULONGLONG secondaryControls = 0ULL;

    /* CPUID leaf zero provides an exact CPU vendor identity. */
    __cpuid(registers, 0);
    RtlCopyMemory(vendor + 0, &registers[1], sizeof(ULONG));
    RtlCopyMemory(vendor + 4, &registers[3], sizeof(ULONG));
    RtlCopyMemory(vendor + 8, &registers[2], sizeof(ULONG));
    KswordARKHvmCopyAscii(
        Runtime->CpuVendor,
        RTL_NUMBER_OF(Runtime->CpuVendor),
        vendor,
        12UL);
    if (RtlCompareMemory(vendor, "GenuineIntel", 12UL) != 12UL) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        Runtime->LastStatus = STATUS_NOT_SUPPORTED;
        return FALSE;
    }
    Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_INTEL;

    /* Leaf one exposes both VMX and an already-active hypervisor. */
    __cpuid(registers, 1);
    leaf1Ecx = (ULONG)registers[2];
    if ((leaf1Ecx & (1UL << 5)) != 0UL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_VMX;
    }
    if ((leaf1Ecx & (1UL << 31)) != 0UL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT;
        __cpuid(registers, (int)0x40000000UL);
        RtlCopyMemory(hypervisorVendor + 0, &registers[1], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 4, &registers[2], sizeof(ULONG));
        RtlCopyMemory(hypervisorVendor + 8, &registers[3], sizeof(ULONG));
        KswordARKHvmCopyAscii(
            Runtime->HypervisorVendor,
            RTL_NUMBER_OF(Runtime->HypervisorVendor),
            hypervisorVendor,
            12UL);
    }

    /* Stop before VMX MSR access when CPUID does not advertise VMX. */
    if ((Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_VMX) == 0ULL) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        Runtime->LastStatus = STATUS_NOT_SUPPORTED;
        return FALSE;
    }

    /* VMX-specific MSRs are read under SEH to fail closed on a virtual CPU. */
    __try {
        Runtime->FeatureControl = __readmsr(KSW_IA32_FEATURE_CONTROL);
        Runtime->VmxBasic = __readmsr(KSW_IA32_VMX_BASIC);
        Runtime->Cr0Fixed0 = __readmsr(KSW_IA32_VMX_CR0_FIXED0);
        Runtime->Cr0Fixed1 = __readmsr(KSW_IA32_VMX_CR0_FIXED1);
        Runtime->Cr4Fixed0 = __readmsr(KSW_IA32_VMX_CR4_FIXED0);
        Runtime->Cr4Fixed1 = __readmsr(KSW_IA32_VMX_CR4_FIXED1);
        primaryControls =
            __readmsr(
                (Runtime->VmxBasic & (1ULL << 55)) != 0ULL
                ? KSW_IA32_VMX_TRUE_PROCBASED_CTLS
                : KSW_IA32_VMX_PROCBASED_CTLS);
        secondaryControls =
            __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
        Runtime->VmxEptVpidCapabilities =
            __readmsr(KSW_IA32_VMX_EPT_VPID_CAP);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
        Runtime->LastStatus = GetExceptionCode();
        return FALSE;
    }

    /* Decode the firmware gate without changing IA32_FEATURE_CONTROL. */
    if ((Runtime->FeatureControl & 0x1ULL) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED;
    }
    if ((Runtime->FeatureControl & 0x4ULL) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX;
    }
    if ((Runtime->VmxBasic & (1ULL << 55)) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS;
    }

    /* The high dword of each control MSR is its allowed-one mask. */
    if ((((secondaryControls >> 32) & (1ULL << 1)) != 0ULL) &&
        ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_PAGE_WALK_4) != 0ULL)) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_WB) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_WB;
    }
    if ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_PAGE_WALK_4) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_2MB) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_2MB;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_AD) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_EPT_AD;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_INVEPT) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_INVEPT;
    }
    if ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_INVEPT_SINGLE) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE;
    }
    if ((Runtime->VmxEptVpidCapabilities &
            KSW_EPT_CAP_INVEPT_ALL) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_INVEPT_ALL;
    }
    if ((Runtime->VmxEptVpidCapabilities & KSW_EPT_CAP_VPID) != 0ULL) {
        Runtime->FeatureFlags |= KSWORD_ARK_HVM_FEATURE_VPID;
    }
    /* Publish monitor-trap support from the primary allowed-one mask. */
    if ((((primaryControls >> 32) &
            (1ULL << 27)) != 0ULL)) {
        /* Publish the protocol-visible monitor-trap feature. */
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG;
    }

    /*
     * A virtual CPU that exposes VMX while setting the hypervisor-present bit
     * is a nested-capable candidate.  The later self-test remains opt-in and
     * is the authoritative proof.
     */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (Runtime->FeatureFlags & KSWORD_ARK_HVM_FEATURE_VMX) != 0ULL) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED;
    }

    /* Firmware-disabled VMX is reported distinctly from unsupported silicon. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX) == 0ULL) {
        Runtime->QueryStatus =
            KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED;
        Runtime->LastStatus = STATUS_HV_FEATURE_UNAVAILABLE;
        return FALSE;
    }

    /* Advertise the bounded guest only when its complete EPT baseline exists. */
    if ((Runtime->FeatureFlags &
            (KSWORD_ARK_HVM_FEATURE_EPT |
             KSWORD_ARK_HVM_FEATURE_EPT_WB |
             KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
             KSWORD_ARK_HVM_FEATURE_EPT_2MB)) ==
        (KSWORD_ARK_HVM_FEATURE_EPT |
         KSWORD_ARK_HVM_FEATURE_EPT_WB |
         KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
         KSWORD_ARK_HVM_FEATURE_EPT_2MB)) {
        Runtime->FeatureFlags |=
            KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST |
            KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY |
            KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT |
            KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING |
            KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT;
    }

    /* A usable capability snapshot is now available. */
    Runtime->QueryStatus = KSWORD_ARK_HVM_QUERY_STATUS_OK;
    Runtime->LastStatus = STATUS_SUCCESS;
    return TRUE;
}
#endif

NTSTATUS
KswordARKHvmArmUnloadGuard(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    PVOID previous = NULL;

    /* Refuse residency unless KMDF installed an unload entry we can preserve. */
    if (Runtime == NULL ||
        Runtime->DriverObject == NULL ||
        Runtime->OriginalDriverUnload == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Treat the exact already-armed state as idempotent success. */
    if (InterlockedCompareExchange(
            &Runtime->UnloadGuardArmed,
            1L,
            1L) != 0L) {
        return Runtime->DriverObject->DriverUnload == NULL
            ? STATUS_SUCCESS
            : STATUS_INVALID_DEVICE_STATE;
    }
    /* Remove only the exact unload entry captured after WdfDriverCreate. */
    previous = InterlockedCompareExchangePointer(
        (PVOID volatile*)&Runtime->DriverObject->DriverUnload,
        NULL,
        (PVOID)Runtime->OriginalDriverUnload);
    if (previous != (PVOID)Runtime->OriginalDriverUnload) {
        /* Never overwrite a third-party or otherwise unexpected entry. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    InterlockedExchange(&Runtime->UnloadGuardArmed, 1L);
    Runtime->StateFlags |= KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmDisarmUnloadGuard(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    PVOID previous = NULL;

    /* Nothing was removed when the guard is already idle. */
    if (Runtime == NULL ||
        InterlockedCompareExchange(
            &Runtime->UnloadGuardArmed,
            0L,
            0L) == 0L) {
        return STATUS_SUCCESS;
    }
    if (Runtime->DriverObject == NULL ||
        Runtime->OriginalDriverUnload == NULL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    /* Restore the original entry only when the guarded slot is still NULL. */
    previous = InterlockedCompareExchangePointer(
        (PVOID volatile*)&Runtime->DriverObject->DriverUnload,
        (PVOID)Runtime->OriginalDriverUnload,
        NULL);
    if (previous != NULL &&
        previous != (PVOID)Runtime->OriginalDriverUnload) {
        /* Preserve the guard state instead of clobbering an unexpected owner. */
        return STATUS_INVALID_DEVICE_STATE;
    }
    InterlockedExchange(&Runtime->UnloadGuardArmed, 0L);
    Runtime->StateFlags &= ~KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED;
    return STATUS_SUCCESS;
}

VOID
KswordARKHvmInvalidatePowerResumeEvidence(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;

    if (Runtime == NULL) {
        return;
    }
    /* Require a fresh per-CPU VMXON/VMXOFF proof after every S0 transition. */
    Runtime->SelfTestPassedProcessorCount = 0UL;
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_SELF_TESTED |
          KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
          KSWORD_ARK_HVM_STATE_GUEST_READY |
          KSWORD_ARK_HVM_STATE_GUEST_RUNNING |
          KSWORD_ARK_HVM_STATE_GUEST_EXITED |
          KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
          KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
          KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING);
    Runtime->ResidentImplementation =
        Runtime->ResidentStartAllowed
            ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
            : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        Runtime->Processors[index].Row.stateFlags &=
            ~(KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED |
              KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED |
              KSWORD_ARK_HVM_CPU_STATE_EXCEPTION |
              KSWORD_ARK_HVM_CPU_STATE_CONFLICT |
              KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED |
              KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED |
              KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED |
              KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE |
              KSWORD_ARK_HVM_CPU_STATE_STOP_REQUESTED |
              KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED);
        Runtime->Processors[index].Row.vmxInstructionResult = 0UL;
        Runtime->Processors[index].Row.lastStatus =
            STATUS_DEVICE_NOT_READY;
    }
}

static NTSTATUS
KswordARKHvmCompleteDeferredPowerResumeLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* State two means S0 resumed while an HVM operation was still draining. */
    if (InterlockedCompareExchange(
            &Runtime->PowerTransitionPending,
            0L,
            0L) != 2L) {
        return STATUS_SUCCESS;
    }
    /* Never reopen entry while an operation, context, or rollback is live. */
    if (Runtime->Busy ||
        InterlockedCompareExchange(
            &Runtime->ResidentContextPreparing,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &Runtime->ResidentProcessorCount,
            0L,
            0L) != 0L ||
        (Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED) != 0UL) {
        return STATUS_DEVICE_BUSY;
    }
    /* Restore unload ownership before publishing the reopened lifecycle. */
    status = KswordARKHvmDisarmUnloadGuard(Runtime);
    if (NT_SUCCESS(status)) {
        KswordARKHvmInvalidatePowerResumeEvidence(Runtime);
        InterlockedExchange(&Runtime->PowerTransitionPending, 0L);
        Runtime->StateFlags &=
            ~KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING;
    }
    return status;
}

static VOID NTAPI
KswordARKHvmPowerStateCallback(
    _In_opt_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
    )
{
    KSW_HVM_RUNTIME* runtime =
        (KSW_HVM_RUNTIME*)CallbackContext;
    KIRQL oldIrql = PASSIVE_LEVEL;
    NTSTATUS status = STATUS_SUCCESS;

    /* Process only the system working-state lock notification. */
    if (runtime == NULL ||
        Argument1 != (PVOID)(ULONG_PTR)PO_CB_SYSTEM_STATE_LOCK) {
        return;
    }
    if ((ULONG_PTR)Argument2 == FALSE) {
        /* Block every new resident transition before waiting for its spin gate. */
        InterlockedExchange(&runtime->PowerTransitionPending, 1L);
        InterlockedIncrement(&runtime->PowerTransitionGeneration);
        InterlockedOr(
            (volatile LONG*)&runtime->StateFlags,
            (LONG)KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING);
        /* Synchronously complete all-CPU VMXOFF before leaving S0. */
        status = KswordARKHvmResidentStop(runtime);
        runtime->LastStatus = status;
        InterlockedIncrement((volatile LONG*)&runtime->Generation);
        if (!NT_SUCCESS(status)) {
            InterlockedOr(
                (volatile LONG*)&runtime->StateFlags,
                (LONG)(KSWORD_ARK_HVM_STATE_FAULTED |
                    KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED));
            /* Never enter a non-S0 state while any CPU still runs this VMM. */
            if (InterlockedCompareExchange(
                    &runtime->ResidentProcessorCount,
                    0L,
                    0L) != 0L) {
                KeBugCheckEx(
                    KSW_HVM_LIFECYCLE_BUGCHECK_CODE,
                    (ULONG_PTR)KSW_HVM_POWER_FAILURE_SIGNATURE,
                    (ULONG_PTR)runtime->ResidentProcessorCount,
                    (ULONG_PTR)status,
                    (ULONG_PTR)runtime->StateFlags);
            }
        }
        return;
    }

    /* Mark S0 resumed, then reopen only after every HVM operation drains. */
    KeAcquireSpinLock(&runtime->ResidentTransitionLock, &oldIrql);
    InterlockedExchange(&runtime->PowerTransitionPending, 2L);
    if (runtime->Busy ||
        InterlockedCompareExchange(
            &runtime->ResidentContextPreparing,
            0L,
            0L) != 0L) {
        /* Keep the gate closed until the active control path discards its work. */
        status = STATUS_DEVICE_BUSY;
    } else {
        status =
            KswordARKHvmCompleteDeferredPowerResumeLocked(runtime);
    }
    KeReleaseSpinLock(&runtime->ResidentTransitionLock, oldIrql);
    runtime->LastStatus = status;
    InterlockedIncrement((volatile LONG*)&runtime->Generation);
}

static VOID
KswordARKHvmProcessorChangeCallback(
    _In_opt_ PVOID CallbackContext,
    _In_ PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT ChangeContext,
    _Inout_ PNTSTATUS OperationStatus
    )
{
    KSW_HVM_RUNTIME* runtime =
        (KSW_HVM_RUNTIME*)CallbackContext;

    /* Preserve the exact prepared/self-tested CPU set until full teardown. */
    if (runtime != NULL &&
        ChangeContext != NULL &&
        OperationStatus != NULL &&
        ChangeContext->State == KeProcessorAddStartNotify &&
        NT_SUCCESS(*OperationStatus) &&
        ((runtime->StateFlags &
             (KSWORD_ARK_HVM_STATE_BUSY |
              KSWORD_ARK_HVM_STATE_RESOURCES_READY |
              KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
              KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
              KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING)) != 0UL)) {
        *OperationStatus = STATUS_DEVICE_BUSY;
    }
}

static VOID
KswordARKHvmFreeResourcesLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
    ULONG index = 0UL;
    NTSTATUS residentStatus = STATUS_SUCCESS;

    /* Drain active or retained resident contexts before releasing VMX pages. */
    residentStatus = KswordARKHvmResidentStop(Runtime);
    /* Preserve resources while any processor or unload guard remains unsafe. */
    if (!NT_SUCCESS(residentStatus) ||
        InterlockedCompareExchange(
            &Runtime->ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /* Publish explicit rollback-required evidence. */
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
        /* Preserve the authoritative stop failure. */
        Runtime->LastStatus = residentStatus;
        /* Return without releasing live VMX resources. */
        return;
    }
    /* Restore baseline EPT leaves before releasing split table pages. */
    KswordARKHvmEptResetLocked(Runtime);

    /* Free per-processor VMXON and VMCS pages symmetrically. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        if (Runtime->Processors[index].VmxonVirtual != NULL) {
            MmFreeContiguousMemory(
                Runtime->Processors[index].VmxonVirtual);
        }
        if (Runtime->Processors[index].VmcsVirtual != NULL) {
            MmFreeContiguousMemory(
                Runtime->Processors[index].VmcsVirtual);
        }
        RtlZeroMemory(
            &Runtime->Processors[index],
            sizeof(Runtime->Processors[index]));
    }

    /* Every EPT table page is tracked exactly once in the allocation ledger. */
    for (index = 0UL; index < Runtime->EptPageCount; ++index) {
        if (Runtime->EptPages[index].VirtualAddress != NULL) {
            MmFreeContiguousMemory(
                Runtime->EptPages[index].VirtualAddress);
        }
    }

    /* Clear all resource-derived state while preserving capability evidence. */
    RtlZeroMemory(Runtime->Processors, sizeof(Runtime->Processors));
    RtlZeroMemory(Runtime->EptPages, sizeof(Runtime->EptPages));
    RtlZeroMemory(Runtime->EptPdpt, sizeof(Runtime->EptPdpt));
    RtlZeroMemory(Runtime->EptPd, sizeof(Runtime->EptPd));
    RtlZeroMemory(&Runtime->Mtrr, sizeof(Runtime->Mtrr));
    Runtime->EptPml4 = NULL;
    Runtime->ProcessorCount = 0UL;
    Runtime->PreparedProcessorCount = 0UL;
    Runtime->SelfTestPassedProcessorCount = 0UL;
    Runtime->ResidentProcessorCount = 0L;
    Runtime->EptRuleCount = 0UL;
    Runtime->EptPageCount = 0UL;
    Runtime->EptPml4Entries = 0UL;
    Runtime->EptPdptEntries = 0UL;
    Runtime->EptLargePageEntries = 0UL;
    Runtime->EptPointer = 0ULL;
    Runtime->MappedRamBytes = 0ULL;
    Runtime->HighestMappedPhysicalAddress = 0ULL;
    Runtime->VmExitCount = 0ULL;
    Runtime->LastExitQualification = 0ULL;
    Runtime->LastGuestRip = 0ULL;
    Runtime->LastGuestRsp = 0ULL;
    Runtime->LastExitReason = KSWORD_ARK_HVM_EXIT_REASON_NONE;
    Runtime->LastExitInstructionLength = 0UL;
    Runtime->LastVmInstructionError = 0UL;
    Runtime->LastLaunchProcessorGroup = 0xFFFFU;
    Runtime->LastLaunchProcessorNumber = 0xFFU;
    Runtime->LastLaunchWasNested = 0U;
    Runtime->ResidentImplementation =
        Runtime->ResidentStartAllowed
            ? KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY
            : KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    Runtime->EptImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_RESOURCES_READY |
          KSWORD_ARK_HVM_STATE_EPT_READY |
          KSWORD_ARK_HVM_STATE_SELF_TESTED |
          KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
          KSWORD_ARK_HVM_STATE_EPT_TRUNCATED |
          KSWORD_ARK_HVM_STATE_GUEST_READY |
          KSWORD_ARK_HVM_STATE_GUEST_RUNNING |
          KSWORD_ARK_HVM_STATE_GUEST_EXITED |
          KSWORD_ARK_HVM_STATE_NESTED_ACTIVE |
          KSWORD_ARK_HVM_STATE_NESTED_VALIDATED |
          KSWORD_ARK_HVM_STATE_RESIDENT_STARTING |
          KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE |
          KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING |
          KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE |
          KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
}

PVOID
KswordARKHvmAllocateEptPageLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Out_ PHYSICAL_ADDRESS* PhysicalAddress
    )
{
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    PVOID page = NULL;

    /* Enforce a bounded allocation ledger before allocating nonpaged memory. */
    if (PhysicalAddress == NULL) {
        return NULL;
    }
    PhysicalAddress->QuadPart = 0LL;
    if (Runtime->EptPageCount >= KSW_HVM_MAX_EPT_PAGES) {
        return NULL;
    }
    highest.QuadPart = MAXLONGLONG;
    page = MmAllocateContiguousMemorySpecifyCache(
        (SIZE_T)KSW_HVM_PAGE_BYTES,
        lowest,
        highest,
        boundary,
        MmCached);
    if (page == NULL) {
        return NULL;
    }

    /* Zero table pages before exposing their physical address to EPT. */
    RtlZeroMemory(page, (SIZE_T)KSW_HVM_PAGE_BYTES);
    *PhysicalAddress = MmGetPhysicalAddress(page);
    Runtime->EptPages[Runtime->EptPageCount].VirtualAddress = page;
    Runtime->EptPages[Runtime->EptPageCount].PhysicalAddress =
        *PhysicalAddress;
    Runtime->EptPageCount += 1UL;
    return page;
}

static NTSTATUS
KswordARKHvmAllocateProcessorResourcesLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    )
{
#if defined(_M_AMD64)
    PHYSICAL_ADDRESS lowest = { 0 };
    PHYSICAL_ADDRESS highest = { 0 };
    PHYSICAL_ADDRESS boundary = { 0 };
    USHORT groupCount = 0U;
    USHORT group = 0U;
    ULONG processorIndex = 0UL;
    ULONG revision = (ULONG)(Runtime->VmxBasic & 0x7FFFFFFFULL);

    /* Enumerate every active group without exceeding the stable protocol cap. */
    highest.QuadPart = MAXLONGLONG;
    groupCount = KeQueryActiveGroupCount();
    for (group = 0U;
         group < groupCount &&
            processorIndex < KSWORD_ARK_HVM_MAX_PROCESSORS;
         ++group) {
        /* Query the exact active mask for this processor group. */
        KAFFINITY activeMask = KeQueryGroupAffinity(group);
        UCHAR processorNumber = 0U;

        /* Group masks are at most 64 bits on supported Windows targets. */
        for (processorNumber = 0U;
             processorNumber < (UCHAR)(sizeof(KAFFINITY) * 8U) &&
                processorIndex < KSWORD_ARK_HVM_MAX_PROCESSORS;
             ++processorNumber) {
            KSW_HVM_CPU_RESOURCE* cpu = NULL;

            /* Skip offline and absent logical processors. */
            if ((activeMask &
                    (((KAFFINITY)1) << processorNumber)) == 0) {
                continue;
            }
            cpu = &Runtime->Processors[processorIndex];
            cpu->Row.processorGroup = group;
            cpu->Row.processorNumber = processorNumber;
            cpu->Row.vmxInstructionResult = 0xFFU;
            cpu->Row.lastExitReason =
                KSWORD_ARK_HVM_EXIT_REASON_NONE;
            /*
             * Publish the in-progress slot to cleanup before either allocation;
             * this prevents a partial VMXON/VMCS pair from escaping rollback.
             */
            Runtime->ProcessorCount = processorIndex + 1UL;

            /* VMXON and VMCS regions are independent physical 4-KiB pages. */
            cpu->VmxonVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            cpu->VmcsVirtual =
                MmAllocateContiguousMemorySpecifyCache(
                    (SIZE_T)KSW_HVM_PAGE_BYTES,
                    lowest,
                    highest,
                    boundary,
                    MmCached);
            if (cpu->VmxonVirtual == NULL ||
                cpu->VmcsVirtual == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            /* Both regions start with the CPU-advertised VMCS revision ID. */
            RtlZeroMemory(
                cpu->VmxonVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            RtlZeroMemory(
                cpu->VmcsVirtual,
                (SIZE_T)KSW_HVM_PAGE_BYTES);
            *(volatile ULONG*)cpu->VmxonVirtual = revision;
            *(volatile ULONG*)cpu->VmcsVirtual = revision;
            cpu->VmxonPhysical =
                MmGetPhysicalAddress(cpu->VmxonVirtual);
            cpu->VmcsPhysical =
                MmGetPhysicalAddress(cpu->VmcsVirtual);
            cpu->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY;
            cpu->Row.lastStatus = STATUS_SUCCESS;
            Runtime->PreparedProcessorCount += 1UL;
            processorIndex += 1UL;
        }
    }
    Runtime->ProcessorCount = processorIndex;
    if (Runtime->ProcessorCount == 0UL) {
        return STATUS_NOT_FOUND;
    }
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Runtime);
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS
KswordARKHvmPrepareLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Do not replace live resource state with a second allocation set. */
    if ((Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) != 0UL) {
        return STATUS_ALREADY_REGISTERED;
    }

    /* Nested preparation is accepted only when VMX is explicitly exposed. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (((Request->flags &
              KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) ||
         ((Runtime->FeatureFlags &
              KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED) == 0ULL))) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

#if defined(_M_AMD64)
    /* 在任何资源分配或 VMXON 之前验证全部逻辑处理器能力一致。 */
    status = KswordARKHvmVerifyUniformCapabilities();
    if (!NT_SUCCESS(status)) {
        return status;
    }
#else
    return STATUS_NOT_SUPPORTED;
#endif

    /* Capture MTRR state before choosing EPT leaf memory types. */
    status = KswordARKHvmMtrrCapture(&Runtime->Mtrr);
    /* Stop when memory typing cannot be established safely. */
    if (!NT_SUCCESS(status)) {
        /* Release any stale partial state before returning the failure. */
        KswordARKHvmFreeResourcesLocked(Runtime);
        /* Return the authoritative MTRR capture failure. */
        return status;
    }

    /* Allocate every per-CPU VMX pair before creating the EPT hierarchy. */
    status = KswordARKHvmAllocateProcessorResourcesLocked(Runtime);
    if (!NT_SUCCESS(status)) {
        KswordARKHvmFreeResourcesLocked(Runtime);
        return status;
    }
    status = KswordARKHvmBuildEptLocked(Runtime);
    if (!NT_SUCCESS(status)) {
        KswordARKHvmFreeResourcesLocked(Runtime);
        return status;
    }

    /* Resource readiness is published only after both allocation phases pass. */
    Runtime->StateFlags |=
        KSWORD_ARK_HVM_STATE_RESOURCES_READY;
    /* Publish active EPT maturity only after the complete hierarchy exists. */
    Runtime->EptImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE;
    return STATUS_SUCCESS;
}

#if defined(_M_AMD64)
static NTSTATUS
KswordARKHvmSelfTestProcessor(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSW_HVM_CPU_RESOURCE* Cpu
    )
{
    GROUP_AFFINITY targetAffinity = { 0 };
    GROUP_AFFINITY oldAffinity = { 0 };
    KIRQL oldIrql = PASSIVE_LEVEL;
    ULONGLONG originalCr0 = 0ULL;
    ULONGLONG originalCr4 = 0ULL;
    ULONGLONG requiredCr0 = 0ULL;
    ULONGLONG requiredCr4 = 0ULL;
    unsigned __int64 vmxonPhysical = 0ULL;
    UCHAR vmxResult = 0xFFU;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN affinitySet = FALSE;
    BOOLEAN transitionLockHeld = FALSE;
    BOOLEAN cr4Changed = FALSE;

    /* Bind the current system thread to the exact resource-owning processor. */
    targetAffinity.Group = Cpu->Row.processorGroup;
    targetAffinity.Mask =
        ((KAFFINITY)1) << Cpu->Row.processorNumber;
    KeSetSystemGroupAffinityThread(
        &targetAffinity,
        &oldAffinity);
    affinitySet = TRUE;

    /* Serialize the local VMX window against the system power callback. */
    KeAcquireSpinLock(&Runtime->ResidentTransitionLock, &oldIrql);
    transitionLockHeld = TRUE;
    __try {
        /* A leaving-S0 callback always wins before any new VMXON. */
        if (InterlockedCompareExchange(
                &Runtime->PowerTransitionPending,
                0L,
                0L) != 0L) {
            status = STATUS_POWER_STATE_INVALID;
            __leave;
        }
        originalCr0 = __readcr0();
        originalCr4 = __readcr4();
        requiredCr0 =
            (originalCr0 | Runtime->Cr0Fixed0) &
            Runtime->Cr0Fixed1;
        requiredCr4 =
            ((originalCr4 | Runtime->Cr4Fixed0) &
                Runtime->Cr4Fixed1) |
            KSW_CR4_VMXE;

        /*
         * Never steal a VMX root already owned by another component, and never
         * alter CR0 or clear a live CR4 feature merely to make the test pass.
         */
        if ((originalCr4 & KSW_CR4_VMXE) != 0ULL ||
            requiredCr0 != originalCr0 ||
            (requiredCr4 & originalCr4) != originalCr4) {
            Cpu->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_CONFLICT;
            status = STATUS_CONFLICTING_ADDRESSES;
            __leave;
        }

        /* Enter VMX root briefly using the page assigned to this processor. */
        __writecr4(requiredCr4);
        cr4Changed = TRUE;
        vmxonPhysical =
            (unsigned __int64)Cpu->VmxonPhysical.QuadPart;
        vmxResult = __vmx_on(&vmxonPhysical);
        Cpu->Row.vmxInstructionResult = vmxResult;
        Cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED;
        if (vmxResult != 0U) {
            status = STATUS_HV_OPERATION_FAILED;
            __leave;
        }

        /* A successful VMXON is immediately paired with VMXOFF. */
        (void)__vmx_off();
        Cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED;
        status = STATUS_SUCCESS;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED |
            KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
        status = GetExceptionCode();
    }

    /* Restore the original control register before lowering IRQL. */
    if (cr4Changed) {
        __try {
            __writecr4(originalCr4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            Cpu->Row.stateFlags |=
                KSWORD_ARK_HVM_CPU_STATE_EXCEPTION;
        }
    }
    if (transitionLockHeld) {
        KeReleaseSpinLock(&Runtime->ResidentTransitionLock, oldIrql);
    }
    if (affinitySet) {
        KeRevertToUserGroupAffinityThread(&oldAffinity);
    }
    Cpu->Row.lastStatus = status;
    return status;
}
#endif

static NTSTATUS
KswordARKHvmSelfTestLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request
    )
{
#if defined(_M_AMD64)
    ULONG index = 0UL;
    ULONG passed = 0UL;
    NTSTATUS firstFailure = STATUS_SUCCESS;
    LONG powerGeneration = 0L;
    KIRQL oldIrql = PASSIVE_LEVEL;

    /* The test operates only on a complete prepared resource set. */
    if ((Runtime->StateFlags &
            KSWORD_ARK_HVM_STATE_RESOURCES_READY) == 0UL) {
        return STATUS_DEVICE_NOT_READY;
    }
    powerGeneration = InterlockedCompareExchange(
        &Runtime->PowerTransitionGeneration,
        0L,
        0L);

    /* Nested execution requires a second explicit opt-in at self-test time. */
    if ((Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL &&
        (Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    /* Test each processor independently and retain every local result row. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        NTSTATUS status =
            KswordARKHvmSelfTestProcessor(
                Runtime,
                &Runtime->Processors[index]);
        if (NT_SUCCESS(status)) {
            passed += 1UL;
        } else if (NT_SUCCESS(firstFailure)) {
            firstFailure = status;
        }
    }
    /* Publish one coherent test epoch, never a pre/post-sleep mixture. */
    KeAcquireSpinLock(&Runtime->ResidentTransitionLock, &oldIrql);
    if (InterlockedCompareExchange(
            &Runtime->PowerTransitionPending,
            0L,
            0L) != 0L ||
        InterlockedCompareExchange(
            &Runtime->PowerTransitionGeneration,
            0L,
            0L) != powerGeneration) {
        KswordARKHvmInvalidatePowerResumeEvidence(Runtime);
        KeReleaseSpinLock(&Runtime->ResidentTransitionLock, oldIrql);
        return STATUS_POWER_STATE_INVALID;
    }
    Runtime->SelfTestPassedProcessorCount = passed;
    Runtime->StateFlags |= KSWORD_ARK_HVM_STATE_SELF_TESTED;
    if (passed == Runtime->ProcessorCount &&
        Runtime->ProcessorCount != 0UL) {
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
            KSWORD_ARK_HVM_STATE_GUEST_READY;
        KeReleaseSpinLock(&Runtime->ResidentTransitionLock, oldIrql);
        return STATUS_SUCCESS;
    }
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
          KSWORD_ARK_HVM_STATE_GUEST_READY);
    KeReleaseSpinLock(&Runtime->ResidentTransitionLock, oldIrql);
    return NT_SUCCESS(firstFailure)
        ? STATUS_UNSUCCESSFUL
        : firstFailure;
#else
    UNREFERENCED_PARAMETER(Runtime);
    UNREFERENCED_PARAMETER(Request);
    return STATUS_NOT_SUPPORTED;
#endif
}

static NTSTATUS
KswordARKHvmLaunchGuestLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request
    )
{
#if defined(_M_AMD64)
    KSW_HVM_CPU_RESOURCE* cpu = NULL;
    KSW_HVM_GUEST_LAUNCH_INPUT launchInput = { 0 };
    KSW_HVM_GUEST_LAUNCH_RESULT launchResult = { 0 };
    ULONG index = 0UL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    BOOLEAN nestedLaunch = FALSE;
    LONG powerGeneration = 0L;

    /* Bind every prerequisite and VMX transition to one power epoch. */
    powerGeneration = InterlockedCompareExchange(
        &Runtime->PowerTransitionGeneration,
        0L,
        0L);
    if (InterlockedCompareExchange(
            &Runtime->PowerTransitionPending,
            0L,
            0L) != 0L) {
        return STATUS_POWER_STATE_INVALID;
    }
    /* Require a complete prepared and self-tested backend before VM entry. */
    if ((Runtime->StateFlags &
            (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
             KSWORD_ARK_HVM_STATE_EPT_READY |
             KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
             KSWORD_ARK_HVM_STATE_GUEST_READY)) !=
        (KSWORD_ARK_HVM_STATE_RESOURCES_READY |
         KSWORD_ARK_HVM_STATE_EPT_READY |
         KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED |
         KSWORD_ARK_HVM_STATE_GUEST_READY)) {
        return STATUS_DEVICE_NOT_READY;
    }
    /* Require the one-shot semantic bit so the command cannot drift silently. */
    if ((Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST) == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Detect whether this launch would execute as an explicitly nested guest. */
    nestedLaunch =
        (Runtime->FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL;
    /* Reject nested execution unless both exposure and explicit opt-in exist. */
    if (nestedLaunch &&
        (((Request->flags &
              KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED) == 0UL) ||
         ((Runtime->FeatureFlags &
              KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED) == 0ULL))) {
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }

    /* Clear the previous launch's per-CPU evidence before selecting a target. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        Runtime->Processors[index].Row.stateFlags &=
            ~(KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED |
              KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED |
              KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED);
        Runtime->Processors[index].Row.lastExitReason =
            KSWORD_ARK_HVM_EXIT_REASON_NONE;
    }
    /* Select the first processor whose VMXON/VMXOFF self-test succeeded. */
    for (index = 0UL; index < Runtime->ProcessorCount; ++index) {
        if ((Runtime->Processors[index].Row.stateFlags &
                KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED) != 0UL) {
            cpu = &Runtime->Processors[index];
            break;
        }
    }
    /* Refuse VM entry when no processor retained a passing self-test. */
    if (cpu == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Copy the exact processor identity into the launch contract. */
    launchInput.ProcessorGroup = cpu->Row.processorGroup;
    /* Copy the group-relative processor number into the launch contract. */
    launchInput.ProcessorNumber = cpu->Row.processorNumber;
    /* Publish whether the launch is intentionally nested. */
    launchInput.NestedLaunch = nestedLaunch ? 1U : 0U;
    /* Reference the processor-owned VMXON physical page. */
    launchInput.VmxonPhysical = cpu->VmxonPhysical;
    /* Reference the processor-owned VMCS physical page. */
    launchInput.VmcsPhysical = cpu->VmcsPhysical;
    /* Copy the VMCS revision/control mode evidence. */
    launchInput.VmxBasic = Runtime->VmxBasic;
    /* Copy the CR0 required-one mask. */
    launchInput.Cr0Fixed0 = Runtime->Cr0Fixed0;
    /* Copy the CR0 allowed-one mask. */
    launchInput.Cr0Fixed1 = Runtime->Cr0Fixed1;
    /* Copy the CR4 required-one mask. */
    launchInput.Cr4Fixed0 = Runtime->Cr4Fixed0;
    /* Copy the CR4 allowed-one mask. */
    launchInput.Cr4Fixed1 = Runtime->Cr4Fixed1;
    /* Reference the prepared RAM identity-map EPT pointer. */
    launchInput.EptPointer = Runtime->EptPointer;
    /* Serialize the exact transient VMX window against power notification. */
    launchInput.TransitionLock = &Runtime->ResidentTransitionLock;
    launchInput.PowerTransitionPending =
        &Runtime->PowerTransitionPending;
    launchInput.PowerTransitionGeneration =
        &Runtime->PowerTransitionGeneration;
    launchInput.ExpectedPowerTransitionGeneration = powerGeneration;

    /* Replace the previous one-shot state with an observable running state. */
    Runtime->StateFlags &=
        ~(KSWORD_ARK_HVM_STATE_GUEST_EXITED |
          KSWORD_ARK_HVM_STATE_NESTED_VALIDATED);
    /* Publish guest-running state before entering VMX root. */
    Runtime->StateFlags |= KSWORD_ARK_HVM_STATE_GUEST_RUNNING;
    /* Preserve the selected processor identity for both success and failure. */
    Runtime->LastLaunchProcessorGroup = cpu->Row.processorGroup;
    /* Preserve the selected group-relative processor number. */
    Runtime->LastLaunchProcessorNumber = cpu->Row.processorNumber;
    /* Preserve the launch environment as protocol-visible evidence. */
    Runtime->LastLaunchWasNested = nestedLaunch ? 1U : 0U;
    /* Execute the bounded guest and wait for its exit continuation. */
    status = KswordARKHvmLaunchControlledGuest(
        &launchInput,
        &launchResult);
    /* Clear transient one-shot guest-running state after the launch returns. */
    Runtime->StateFlags &=
        ~KSWORD_ARK_HVM_STATE_GUEST_RUNNING;

    /* Preserve the exact final VMX instruction result on the selected CPU. */
    cpu->Row.vmxInstructionResult =
        launchResult.VmxInstructionResult;
    /* Preserve the launch status on the selected CPU row. */
    cpu->Row.lastStatus = status;
    /* Publish current-VMCS evidence when VMPTRLD completed. */
    if (launchResult.VmcsLoaded != 0U) {
        cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED;
    }
    /* Publish successful VM-entry evidence only when a host exit occurred. */
    if (launchResult.GuestLaunched != 0U) {
        cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED;
    }
    /* Publish VM-exit dispatch evidence and increment its monotonic counter. */
    if (launchResult.VmExitHandled != 0U) {
        cpu->Row.stateFlags |=
            KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED;
        Runtime->VmExitCount += 1ULL;
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_GUEST_EXITED;
        Runtime->LastExitReason =
            launchResult.Exit.Reason &
            KSW_HVM_VMEXIT_REASON_BASIC_MASK;
        cpu->Row.lastExitReason =
            Runtime->LastExitReason;
    } else {
        Runtime->LastExitReason =
            KSWORD_ARK_HVM_EXIT_REASON_NONE;
    }
    /* Preserve exit qualification even when the exit was unexpected. */
    Runtime->LastExitQualification =
        launchResult.Exit.Qualification;
    /* Preserve the guest instruction pointer at the exit boundary. */
    Runtime->LastGuestRip = launchResult.Exit.GuestRip;
    /* Preserve the guest stack pointer at the exit boundary. */
    Runtime->LastGuestRsp = launchResult.Exit.GuestRsp;
    /* Preserve the decoded VM-exit instruction length. */
    Runtime->LastExitInstructionLength =
        launchResult.Exit.InstructionLength;
    /* Prefer launch-time VMfail detail, then retain exit-time diagnostic state. */
    Runtime->LastVmInstructionError =
        launchResult.VmInstructionError != 0UL
        ? launchResult.VmInstructionError
        : launchResult.Exit.VmInstructionError;
    /* Record that nested VM entry and the expected VMCALL exit both completed. */
    if (NT_SUCCESS(status) && nestedLaunch) {
        Runtime->StateFlags |=
            KSWORD_ARK_HVM_STATE_NESTED_VALIDATED;
    }
    return status;
#else
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Runtime);
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Request);
    return STATUS_NOT_SUPPORTED;
#endif
}

static ULONG
KswordARKHvmControlStatusFromNtStatus(
    _In_ ULONG Command,
    _In_ NTSTATUS Status
    )
{
    /* Map backend failures to stable UI-facing protocol states. */
    if (NT_SUCCESS(Status)) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_OK;
    }
    if (Status == STATUS_ALREADY_REGISTERED) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED;
    }
    if (Status == STATUS_DEVICE_NOT_READY) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED;
    }
    if (Status == STATUS_HV_FEATURE_UNAVAILABLE) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT;
    }
    if (Status == STATUS_NOT_SUPPORTED) {
        if (Command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED) {
            return
                KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED;
        }
        return KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU;
    }
    if (Status == STATUS_INSUFFICIENT_RESOURCES) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
    }
    if (Status == STATUS_NOT_IMPLEMENTED) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION;
    }
    if (Status == STATUS_REVISION_MISMATCH) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED;
    }
    if (Status == STATUS_POWER_STATE_INVALID) {
        return
            KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED;
    }
    if (Status == STATUS_INVALID_DEVICE_STATE) {
        return
            KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED;
    }
    if (Command == KSWORD_ARK_HVM_CONTROL_START_RESIDENT ||
        Command == KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED;
    }
    if (Command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
        Status == STATUS_UNEXPECTED_IO_ERROR) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT;
    }
    if (Command == KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED;
    }
    if (Command == KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
        return KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED;
    }
    return KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
}

NTSTATUS
KswordARKHvmInitialize(
    VOID
    )
{
    /* Initialize the lock before publishing any observable runtime state. */
    RtlZeroMemory(&g_KswordHvm, sizeof(g_KswordHvm));
    ExInitializePushLock(&g_KswordHvm.Lock);
    KeInitializeSpinLock(&g_KswordHvm.ResidentTransitionLock);
    g_KswordHvm.Initialized = TRUE;
    g_KswordHvm.StateFlags = KSWORD_ARK_HVM_STATE_INITIALIZED;
    g_KswordHvm.Generation = 1UL;
    g_KswordHvm.LastExitReason =
        KSWORD_ARK_HVM_EXIT_REASON_NONE;
    g_KswordHvm.LastLaunchProcessorGroup = 0xFFFFU;
    g_KswordHvm.LastLaunchProcessorNumber = 0xFFU;
    g_KswordHvm.ResidentImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    g_KswordHvm.EptImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    g_KswordHvm.NestedImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    g_KswordHvm.EvmcsImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    g_KswordHvm.NestedState =
        KSWORD_ARK_HVM_NESTED_STATE_DISABLED;
    g_KswordHvm.EvmcsState =
        KSWORD_ARK_HVM_EVMCS_STATE_UNAVAILABLE;
    /* Initialize the nonpaged event ring before any control operation. */
    KswordARKHvmEventInitialize();

#if defined(_M_AMD64)
    /* Capability failure disables HVM only; it does not fail driver startup. */
    if (KswordARKHvmReadCapabilities(&g_KswordHvm)) {
        /*
         * Keep resident mode unavailable until WdfDriverCreate installs the
         * final unload entry and every lifecycle callback binds successfully.
         * Nonresident VMX and EPT research capabilities remain available.
         */
        g_KswordHvm.ResidentImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
        /* Publish EPT capability without claiming a prepared hierarchy. */
        g_KswordHvm.EptImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
        /* Publish nested capability without claiming instruction dispatch. */
        g_KswordHvm.NestedImplementation =
            KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
        /* Publish capability-only nested state. */
        g_KswordHvm.NestedState =
            KSWORD_ARK_HVM_NESTED_STATE_CAPABILITY_ONLY;
        /* Discover TLFS eVMCS capability from synthetic CPUID leaves. */
        KswordARKHvmEvmcsDiscover(&g_KswordHvm);
    }
#else
    g_KswordHvm.QueryStatus =
        KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU;
    g_KswordHvm.LastStatus = STATUS_NOT_SUPPORTED;
#endif
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEnableResidentLifecycle(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
#if defined(_M_AMD64)
    static const ULONGLONG requiredFeatures =
        KSWORD_ARK_HVM_FEATURE_INTEL |
        KSWORD_ARK_HVM_FEATURE_VMX |
        KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED |
        KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX |
        KSWORD_ARK_HVM_FEATURE_EPT |
        KSWORD_ARK_HVM_FEATURE_EPT_WB |
        KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL |
        KSWORD_ARK_HVM_FEATURE_EPT_2MB |
        KSWORD_ARK_HVM_FEATURE_INVEPT |
        KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE;
    UNICODE_STRING callbackName =
        RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES objectAttributes;
    NTSTATUS status = STATUS_SUCCESS;

    /* AMD and every other non-Intel vendor remain a hard driver-side denial. */
    if (DriverObject == NULL || !g_KswordHvm.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }
    if (g_KswordHvm.QueryStatus != KSWORD_ARK_HVM_QUERY_STATUS_OK) {
        return g_KswordHvm.LastStatus;
    }
    if ((g_KswordHvm.FeatureFlags & requiredFeatures) !=
        requiredFeatures) {
        g_KswordHvm.LastStatus = STATUS_NOT_SUPPORTED;
        return STATUS_NOT_SUPPORTED;
    }
    /* Resident mode never co-owns VT-x with Hyper-V or another hypervisor. */
    if ((g_KswordHvm.FeatureFlags &
            KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT) != 0ULL) {
        g_KswordHvm.LastStatus = STATUS_HV_FEATURE_UNAVAILABLE;
        return STATUS_HV_FEATURE_UNAVAILABLE;
    }
    if (DriverObject->DriverUnload == NULL) {
        g_KswordHvm.LastStatus = STATUS_INVALID_DEVICE_STATE;
        return STATUS_INVALID_DEVICE_STATE;
    }

    /* Capture the final KMDF unload entry before publishing resident support. */
    g_KswordHvm.DriverObject = DriverObject;
    g_KswordHvm.OriginalDriverUnload = DriverObject->DriverUnload;
    g_KswordHvm.ProcessorChangeRegistration =
        KeRegisterProcessorChangeCallback(
            KswordARKHvmProcessorChangeCallback,
            &g_KswordHvm,
            0UL);
    if (g_KswordHvm.ProcessorChangeRegistration == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }

    InitializeObjectAttributes(
        &objectAttributes,
        &callbackName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    status = ExCreateCallback(
        &g_KswordHvm.PowerStateCallbackObject,
        &objectAttributes,
        FALSE,
        TRUE);
    if (!NT_SUCCESS(status)) {
        goto Failure;
    }
    g_KswordHvm.PowerStateCallbackRegistration =
        ExRegisterCallback(
            g_KswordHvm.PowerStateCallbackObject,
            KswordARKHvmPowerStateCallback,
            &g_KswordHvm);
    if (g_KswordHvm.PowerStateCallbackRegistration == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Failure;
    }

    /* Publish resident/EPT controls only after every fail-closed guard exists. */
    g_KswordHvm.FeatureFlags |=
        KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM |
        KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS |
        KSWORD_ARK_HVM_FEATURE_EPT_RULES |
        KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD |
        KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD |
        KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD |
        KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED;
    g_KswordHvm.ResidentStartAllowed = TRUE;
    g_KswordHvm.ResidentImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY;
    g_KswordHvm.LastStatus = STATUS_SUCCESS;
    return STATUS_SUCCESS;

Failure:
    /* Roll back partial callback ownership before leaving resident disabled. */
    if (g_KswordHvm.PowerStateCallbackRegistration != NULL) {
        ExUnregisterCallback(
            g_KswordHvm.PowerStateCallbackRegistration);
        g_KswordHvm.PowerStateCallbackRegistration = NULL;
    }
    if (g_KswordHvm.PowerStateCallbackObject != NULL) {
        ObDereferenceObject(g_KswordHvm.PowerStateCallbackObject);
        g_KswordHvm.PowerStateCallbackObject = NULL;
    }
    if (g_KswordHvm.ProcessorChangeRegistration != NULL) {
        KeDeregisterProcessorChangeCallback(
            g_KswordHvm.ProcessorChangeRegistration);
        g_KswordHvm.ProcessorChangeRegistration = NULL;
    }
    g_KswordHvm.DriverObject = NULL;
    g_KswordHvm.OriginalDriverUnload = NULL;
    g_KswordHvm.ResidentStartAllowed = FALSE;
    g_KswordHvm.ResidentImplementation =
        KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED;
    g_KswordHvm.LastStatus = status;
    return status;
#else
    UNREFERENCED_PARAMETER(DriverObject);
    return STATUS_NOT_SUPPORTED;
#endif
}

VOID
KswordARKHvmUninitialize(
    VOID
    )
{
    PCALLBACK_OBJECT powerCallbackObject = NULL;
    PVOID powerCallbackRegistration = NULL;
    PVOID processorChangeRegistration = NULL;

    /* Unload is serialized against query/control before releasing pages. */
    if (!g_KswordHvm.Initialized) {
        return;
    }
    /* Block new residency before draining either lifecycle callback. */
    g_KswordHvm.ResidentStartAllowed = FALSE;
    InterlockedExchange(
        &g_KswordHvm.PowerTransitionPending,
        1L);
    powerCallbackRegistration =
        g_KswordHvm.PowerStateCallbackRegistration;
    powerCallbackObject =
        g_KswordHvm.PowerStateCallbackObject;
    processorChangeRegistration =
        g_KswordHvm.ProcessorChangeRegistration;
    g_KswordHvm.PowerStateCallbackRegistration = NULL;
    g_KswordHvm.PowerStateCallbackObject = NULL;
    g_KswordHvm.ProcessorChangeRegistration = NULL;
    if (powerCallbackRegistration != NULL) {
        ExUnregisterCallback(powerCallbackRegistration);
    }
    if (processorChangeRegistration != NULL) {
        KeDeregisterProcessorChangeCallback(
            processorChangeRegistration);
    }
    KeEnterCriticalRegion();
    KswordARKAcquirePushLockExclusive(&g_KswordHvm.Lock);
    KswordARKHvmFreeResourcesLocked(&g_KswordHvm);
    /* Publish uninitialized only after every resident CPU completed VMXOFF. */
    if (InterlockedCompareExchange(
            &g_KswordHvm.ResidentProcessorCount,
            0L,
            0L) == 0L) {
        KIRQL oldIrql = PASSIVE_LEVEL;

        /* Restore the captured KMDF unload entry after complete VMXOFF. */
        KeAcquireSpinLock(
            &g_KswordHvm.ResidentTransitionLock,
            &oldIrql);
        if (!NT_SUCCESS(
                KswordARKHvmDisarmUnloadGuard(&g_KswordHvm))) {
            g_KswordHvm.StateFlags |=
                KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
        }
        KeReleaseSpinLock(
            &g_KswordHvm.ResidentTransitionLock,
            oldIrql);
        /* Publish completed HVM teardown. */
        g_KswordHvm.Initialized = FALSE;
    } else {
        /* Preserve explicit rollback-required evidence on unsafe unload. */
        g_KswordHvm.StateFlags |=
            KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED;
        /* Returning would unmap code still executing from resident host state. */
        KeBugCheckEx(
            KSW_HVM_LIFECYCLE_BUGCHECK_CODE,
            (ULONG_PTR)KSW_HVM_UNLOAD_FAILURE_SIGNATURE,
            (ULONG_PTR)g_KswordHvm.ResidentProcessorCount,
            (ULONG_PTR)g_KswordHvm.LastStatus,
            (ULONG_PTR)g_KswordHvm.StateFlags);
    }
    KswordARKReleasePushLockExclusive(&g_KswordHvm.Lock);
    KeLeaveCriticalRegion();
    if (powerCallbackObject != NULL) {
        ObDereferenceObject(powerCallbackObject);
    }
    g_KswordHvm.DriverObject = NULL;
    g_KswordHvm.OriginalDriverUnload = NULL;
}

NTSTATUS
KswordARKHvmQuery(
    _Out_ KSWORD_ARK_QUERY_HVM_RESPONSE* Response
    )
{
    ULONG index = 0UL;
    ULONG eventCount = 0UL;
    ULONG droppedEventCount = 0UL;

    /* A fixed response makes status queries deterministic across UI refreshes. */
    if (Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    if (!g_KswordHvm.Initialized) {
        return STATUS_DEVICE_NOT_READY;
    }

    /* Snapshot all state under a shared push lock. */
    KeEnterCriticalRegion();
    KswordARKAcquirePushLockShared(&g_KswordHvm.Lock);
    Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    Response->queryStatus = g_KswordHvm.Busy
        ? KSWORD_ARK_HVM_QUERY_STATUS_BUSY
        : g_KswordHvm.QueryStatus;
    Response->stateFlags = g_KswordHvm.StateFlags |
        (g_KswordHvm.Busy ? KSWORD_ARK_HVM_STATE_BUSY : 0UL);
    Response->generation = g_KswordHvm.Generation;
    Response->processorCount = g_KswordHvm.ProcessorCount;
    Response->preparedProcessorCount =
        g_KswordHvm.PreparedProcessorCount;
    Response->selfTestPassedProcessorCount =
        g_KswordHvm.SelfTestPassedProcessorCount;
    Response->residentProcessorCount =
        (ULONG)InterlockedCompareExchange(
            &g_KswordHvm.ResidentProcessorCount,
            0L,
            0L);
    Response->residentImplementation =
        g_KswordHvm.ResidentImplementation;
    Response->eptImplementation =
        g_KswordHvm.EptImplementation;
    Response->nestedImplementation =
        g_KswordHvm.NestedImplementation;
    Response->evmcsImplementation =
        g_KswordHvm.EvmcsImplementation;
    Response->eptRuleCount =
        g_KswordHvm.EptRuleCount;
    KswordARKHvmEventGetCounts(
        &eventCount,
        &droppedEventCount);
    Response->eventCount = eventCount;
    Response->droppedEventCount =
        droppedEventCount;
    Response->nestedState =
        g_KswordHvm.NestedState;
    Response->evmcsState =
        g_KswordHvm.EvmcsState;
    Response->evmcsVersion =
        g_KswordHvm.EvmcsVersion;
    Response->evmcsFlags =
        g_KswordHvm.EvmcsFlags;
    Response->evmcsVpAssistMsr =
        g_KswordHvm.EvmcsVpAssistMsr;
    Response->eptPageCount = g_KswordHvm.EptPageCount;
    Response->eptPml4Entries = g_KswordHvm.EptPml4Entries;
    Response->eptPdptEntries = g_KswordHvm.EptPdptEntries;
    Response->eptLargePageEntries =
        g_KswordHvm.EptLargePageEntries;
    Response->featureFlags = g_KswordHvm.FeatureFlags;
    Response->vmxBasic = g_KswordHvm.VmxBasic;
    Response->vmxEptVpidCapabilities =
        g_KswordHvm.VmxEptVpidCapabilities;
    Response->featureControl = g_KswordHvm.FeatureControl;
    Response->cr0Fixed0 = g_KswordHvm.Cr0Fixed0;
    Response->cr0Fixed1 = g_KswordHvm.Cr0Fixed1;
    Response->cr4Fixed0 = g_KswordHvm.Cr4Fixed0;
    Response->cr4Fixed1 = g_KswordHvm.Cr4Fixed1;
    Response->eptPointer = g_KswordHvm.EptPointer;
    Response->mappedRamBytes = g_KswordHvm.MappedRamBytes;
    Response->highestMappedPhysicalAddress =
        g_KswordHvm.HighestMappedPhysicalAddress;
    Response->vmExitCount = g_KswordHvm.VmExitCount;
    Response->lastExitQualification =
        g_KswordHvm.LastExitQualification;
    Response->lastGuestRip = g_KswordHvm.LastGuestRip;
    Response->lastGuestRsp = g_KswordHvm.LastGuestRsp;
    Response->lastExitReason = g_KswordHvm.LastExitReason;
    Response->lastExitInstructionLength =
        g_KswordHvm.LastExitInstructionLength;
    Response->lastVmInstructionError =
        g_KswordHvm.LastVmInstructionError;
    Response->lastLaunchProcessorGroup =
        g_KswordHvm.LastLaunchProcessorGroup;
    Response->lastLaunchProcessorNumber =
        g_KswordHvm.LastLaunchProcessorNumber;
    Response->lastLaunchWasNested =
        g_KswordHvm.LastLaunchWasNested;
    Response->lastStatus = g_KswordHvm.LastStatus;
    KswordARKHvmCopyAscii(
        Response->cpuVendor,
        RTL_NUMBER_OF(Response->cpuVendor),
        g_KswordHvm.CpuVendor,
        RTL_NUMBER_OF(g_KswordHvm.CpuVendor));
    KswordARKHvmCopyAscii(
        Response->hypervisorVendor,
        RTL_NUMBER_OF(Response->hypervisorVendor),
        g_KswordHvm.HypervisorVendor,
        RTL_NUMBER_OF(g_KswordHvm.HypervisorVendor));
    for (index = 0UL;
         index < g_KswordHvm.ProcessorCount &&
            index < KSWORD_ARK_HVM_MAX_PROCESSORS;
         ++index) {
        Response->processors[index] =
            g_KswordHvm.Processors[index].Row;
    }
    KswordARKReleasePushLockShared(&g_KswordHvm.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmControl(
    _In_ const KSWORD_ARK_CONTROL_HVM_REQUEST* Request,
    _Out_ KSWORD_ARK_CONTROL_HVM_RESPONSE* Response
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS deferredResumeStatus = STATUS_SUCCESS;
    ULONG oldStateFlags = 0UL;
    ULONG oldGeneration = 0UL;
    ULONG eventCount = 0UL;
    ULONG droppedEventCount = 0UL;
    ULONG allowedFlags = 0UL;
    KIRQL deferredResumeIrql = PASSIVE_LEVEL;

    /* Validate the complete versioned request before acquiring the state lock. */
    if (Request == NULL || Response == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Response, sizeof(*Response));
    Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    Response->size = sizeof(*Response);
    /* Select the exact flag vocabulary accepted by this command. */
    switch (Request->command) {
    case KSWORD_ARK_HVM_CONTROL_PREPARE:
        /* Prepare may opt in to an already exposed nested host only. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED;
        /* Stop after selecting the prepare flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_SELF_TEST:
        /* Self-test additionally requires the explicit force bit. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED;
        /* Stop after selecting the self-test flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_TEARDOWN:
    case KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT:
        /* Teardown and stop accept no feature-enabling side flags. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED;
        /* Stop after selecting the stop flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST:
        /* One-shot launch requires its semantic marker and optional nesting. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST;
        /* Stop after selecting the one-shot flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_START_RESIDENT:
        /* Resident start accepts event and partial nested-dispatch selection. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX;
        /* Stop after selecting the resident-start flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED:
        /* Validation accepts only explicit nested/eVMCS discovery selectors. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE |
            KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
            KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS;
        /* Stop after selecting the validation flag set. */
        break;
    case KSWORD_ARK_HVM_CONTROL_RESET_FAULT:
        /* Fault reset accepts confirmation and force only. */
        allowedFlags =
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED |
            KSWORD_ARK_HVM_CONTROL_FLAG_FORCE;
        /* Stop after selecting the reset flag set. */
        break;
    default:
        /* Leave the mask empty so the existing command check rejects it. */
        allowedFlags = 0UL;
        /* Stop after selecting the invalid-command sentinel. */
        break;
    }
    if (Request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->reserved[0] != 0UL ||
        Request->reserved[1] != 0UL ||
        (Request->flags & ~allowedFlags) != 0UL ||
        Request->confirmationToken !=
            KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN ||
        (Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED) == 0UL ||
        (Request->command != KSWORD_ARK_HVM_CONTROL_PREPARE &&
         Request->command != KSWORD_ARK_HVM_CONTROL_SELF_TEST &&
         Request->command != KSWORD_ARK_HVM_CONTROL_TEARDOWN &&
         Request->command !=
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
         Request->command !=
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT &&
         Request->command !=
            KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT &&
         Request->command !=
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED &&
         Request->command !=
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT)) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    /* Require one explicit partial subsystem selector for validation. */
    if (Request->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED &&
        (Request->flags &
            (KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX |
             KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS)) == 0UL) {
        /* Publish the stable invalid-request protocol status. */
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        /* Publish the authoritative flag-contract failure. */
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the complete protocol-level rejection. */
        return STATUS_SUCCESS;
    }
    if ((Request->command == KSWORD_ARK_HVM_CONTROL_SELF_TEST ||
         Request->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST ||
         Request->command ==
            KSWORD_ARK_HVM_CONTROL_START_RESIDENT ||
         Request->command ==
            KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED ||
         Request->command ==
            KSWORD_ARK_HVM_CONTROL_RESET_FAULT) &&
        (Request->flags & KSWORD_ARK_HVM_CONTROL_FLAG_FORCE) == 0UL) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED;
        Response->lastStatus = STATUS_ACCESS_DENIED;
        return STATUS_SUCCESS;
    }
    if (Request->command ==
            KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST &&
        (Request->flags &
            KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST) == 0UL) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }
    if (!g_KswordHvm.Initialized) {
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED;
        Response->lastStatus = STATUS_DEVICE_NOT_READY;
        return STATUS_SUCCESS;
    }

    /* Serialize all lifecycle changes and honor generation-bound requests. */
    KeEnterCriticalRegion();
    KswordARKAcquirePushLockExclusive(&g_KswordHvm.Lock);
    oldStateFlags = g_KswordHvm.StateFlags;
    oldGeneration = g_KswordHvm.Generation;
    if (g_KswordHvm.Busy) {
        status = STATUS_DEVICE_BUSY;
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_BUSY;
        goto Complete;
    }
    if (Request->expectedGeneration != 0UL &&
        Request->expectedGeneration != g_KswordHvm.Generation) {
        status = STATUS_REVISION_MISMATCH;
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED;
        goto Complete;
    }
    if (g_KswordHvm.QueryStatus != KSWORD_ARK_HVM_QUERY_STATUS_OK) {
        status = g_KswordHvm.LastStatus;
        Response->status =
            g_KswordHvm.QueryStatus ==
                KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED
            ? KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED
            : KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU;
        goto Complete;
    }
    /* Keep all new HVM work closed until the S0 transition fully drains. */
    if (InterlockedCompareExchange(
            &g_KswordHvm.PowerTransitionPending,
            0L,
            0L) != 0L &&
        Request->command != KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT) {
        status = STATUS_POWER_STATE_INVALID;
        Response->status =
            KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED;
        goto Complete;
    }

    /* Publish busy state while the selected lifecycle command executes. */
    g_KswordHvm.Busy = TRUE;
    g_KswordHvm.StateFlags |= KSWORD_ARK_HVM_STATE_BUSY;
    if (Request->command == KSWORD_ARK_HVM_CONTROL_PREPARE) {
        status = KswordARKHvmPrepareLocked(
            &g_KswordHvm,
            Request);
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_SELF_TEST) {
        status = KswordARKHvmSelfTestLocked(
            &g_KswordHvm,
            Request);
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST) {
        status = KswordARKHvmLaunchGuestLocked(
            &g_KswordHvm,
            Request);
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_START_RESIDENT) {
        /* Enter resident VMX only through the all-processor rendezvous. */
        status = KswordARKHvmResidentStart(
            &g_KswordHvm,
            Request->flags);
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT) {
        /* Leave resident VMX through the all-processor rollback path. */
        status = KswordARKHvmResidentStop(
            &g_KswordHvm);
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED) {
        NTSTATUS nestedStatus = STATUS_SUCCESS;
        NTSTATUS evmcsStatus = STATUS_SUCCESS;

        /* Validate nested VMX only when its partial subsystem was selected. */
        if ((Request->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX) != 0UL) {
            /* Validate bounded VMX dispatch without claiming L2 active. */
            nestedStatus = KswordARKHvmNestedValidate(
                &g_KswordHvm);
        }
        /* Validate TLFS eVMCS only when the caller explicitly requests it. */
        if ((Request->flags &
                KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS) != 0UL) {
            /* Evaluate guest-partition eVMCS v1 capability and ownership. */
            evmcsStatus = KswordARKHvmEvmcsValidate(
                &g_KswordHvm);
        }
        /* Prefer a hard failure from either selected subsystem. */
        if (!NT_SUCCESS(nestedStatus) &&
            nestedStatus != STATUS_NOT_IMPLEMENTED) {
            status = nestedStatus;
        } else if (!NT_SUCCESS(evmcsStatus) &&
            evmcsStatus != STATUS_NOT_IMPLEMENTED) {
            status = evmcsStatus;
        } else if (nestedStatus == STATUS_NOT_IMPLEMENTED ||
                   evmcsStatus == STATUS_NOT_IMPLEMENTED) {
            /* Preserve explicit partial maturity when no hard failure exists. */
            status = STATUS_NOT_IMPLEMENTED;
        } else {
            /* Both selected capability validations completed successfully. */
            status = STATUS_SUCCESS;
        }
    } else if (Request->command ==
        KSWORD_ARK_HVM_CONTROL_RESET_FAULT) {
        /* Refuse fault reset while any processor remains resident. */
        if (InterlockedCompareExchange(
                &g_KswordHvm.ResidentProcessorCount,
                0L,
                0L) != 0L) {
            /* Preserve the exact active-lifecycle conflict. */
            status = STATUS_DEVICE_BUSY;
        } else {
            /* Clear only recoverable fault and rollback evidence. */
            g_KswordHvm.StateFlags &=
                ~(KSWORD_ARK_HVM_STATE_FAULTED |
                  KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED);
            /* Publish successful recoverable fault reset. */
            status = STATUS_SUCCESS;
        }
    } else {
        /* Stop resident VMX and release every reversible resource. */
        KswordARKHvmFreeResourcesLocked(&g_KswordHvm);
        /* Report incomplete teardown while any CPU still owns VMX resources. */
        status = InterlockedCompareExchange(
            &g_KswordHvm.ResidentProcessorCount,
            0L,
            0L) == 0L
            ? STATUS_SUCCESS
            : STATUS_HV_OPERATION_FAILED;
    }
    g_KswordHvm.Busy = FALSE;
    g_KswordHvm.StateFlags &= ~KSWORD_ARK_HVM_STATE_BUSY;
    /* Finish a resume that waited for this exact control operation to drain. */
    KeAcquireSpinLock(
        &g_KswordHvm.ResidentTransitionLock,
        &deferredResumeIrql);
    deferredResumeStatus =
        KswordARKHvmCompleteDeferredPowerResumeLocked(&g_KswordHvm);
    KeReleaseSpinLock(
        &g_KswordHvm.ResidentTransitionLock,
        deferredResumeIrql);
    if (!NT_SUCCESS(deferredResumeStatus) &&
        deferredResumeStatus != STATUS_DEVICE_BUSY &&
        NT_SUCCESS(status)) {
        status = deferredResumeStatus;
    }
    g_KswordHvm.LastStatus = status;
    if (!NT_SUCCESS(status) &&
        status != STATUS_NOT_IMPLEMENTED &&
        status != STATUS_POWER_STATE_INVALID &&
        status != STATUS_DEVICE_BUSY) {
        g_KswordHvm.StateFlags |= KSWORD_ARK_HVM_STATE_FAULTED;
    } else if (NT_SUCCESS(status)) {
        g_KswordHvm.StateFlags &= ~KSWORD_ARK_HVM_STATE_FAULTED;
    }
    g_KswordHvm.Generation += 1UL;
    Response->status =
        KswordARKHvmControlStatusFromNtStatus(
            Request->command,
            status);

Complete:
    /* Always return a complete before/after lifecycle summary. */
    Response->oldStateFlags = oldStateFlags;
    Response->newStateFlags = g_KswordHvm.StateFlags;
    Response->oldGeneration = oldGeneration;
    Response->newGeneration = g_KswordHvm.Generation;
    Response->preparedProcessorCount =
        g_KswordHvm.PreparedProcessorCount;
    Response->selfTestPassedProcessorCount =
        g_KswordHvm.SelfTestPassedProcessorCount;
    Response->failedProcessorCount =
        g_KswordHvm.ProcessorCount >=
            g_KswordHvm.SelfTestPassedProcessorCount
        ? g_KswordHvm.ProcessorCount -
            g_KswordHvm.SelfTestPassedProcessorCount
        : 0UL;
    Response->residentProcessorCount =
        (ULONG)InterlockedCompareExchange(
            &g_KswordHvm.ResidentProcessorCount,
            0L,
            0L);
    Response->residentImplementation =
        g_KswordHvm.ResidentImplementation;
    Response->eptImplementation =
        g_KswordHvm.EptImplementation;
    Response->nestedImplementation =
        g_KswordHvm.NestedImplementation;
    Response->evmcsImplementation =
        g_KswordHvm.EvmcsImplementation;
    Response->eptRuleCount =
        g_KswordHvm.EptRuleCount;
    KswordARKHvmEventGetCounts(
        &eventCount,
        &droppedEventCount);
    Response->eventCount = eventCount;
    /* Keep the intentionally unreturned dropped count warning-free. */
    UNREFERENCED_PARAMETER(droppedEventCount);
    Response->eptPageCount = g_KswordHvm.EptPageCount;
    Response->eptPointer = g_KswordHvm.EptPointer;
    Response->mappedRamBytes = g_KswordHvm.MappedRamBytes;
    Response->vmExitCount = g_KswordHvm.VmExitCount;
    Response->lastExitQualification =
        g_KswordHvm.LastExitQualification;
    Response->lastGuestRip = g_KswordHvm.LastGuestRip;
    Response->lastGuestRsp = g_KswordHvm.LastGuestRsp;
    Response->lastExitReason = g_KswordHvm.LastExitReason;
    Response->lastExitInstructionLength =
        g_KswordHvm.LastExitInstructionLength;
    Response->lastVmInstructionError =
        g_KswordHvm.LastVmInstructionError;
    Response->launchProcessorGroup =
        g_KswordHvm.LastLaunchProcessorGroup;
    Response->launchProcessorNumber =
        g_KswordHvm.LastLaunchProcessorNumber;
    Response->launchWasNested =
        g_KswordHvm.LastLaunchWasNested;
    Response->lastStatus = status;
    KswordARKReleasePushLockExclusive(&g_KswordHvm.Lock);
    KeLeaveCriticalRegion();
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmEptRuleControl(
    _In_ const KSWORD_ARK_HVM_EPT_RULE_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EPT_RULE_RESPONSE* Response
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /* Validate the complete fixed protocol contract before locking. */
    if (Request == NULL ||
        Response == NULL ||
        Request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        (Request->flags &
            ~(KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
              KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE |
              KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED)) != 0UL ||
        (Request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_ADD &&
         Request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_REMOVE &&
         Request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_CLEAR &&
         Request->operation !=
            KSWORD_ARK_HVM_EPT_RULE_QUERY)) {
        /* Return the exact fixed-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reject fields that are meaningless for a read-only rule query. */
    if (Request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_QUERY &&
        (Request->flags != 0UL ||
         Request->confirmationToken != 0UL ||
         Request->expectedGeneration != 0UL ||
         Request->deniedAccess != 0UL ||
         Request->physicalAddress != 0ULL ||
         Request->pageCount != 0ULL)) {
        /* Return the exact operation-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require a clean identifier-only removal contract. */
    if (Request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_REMOVE &&
        (Request->ruleId == 0UL ||
         Request->deniedAccess != 0UL ||
         Request->physicalAddress != 0ULL ||
         Request->pageCount != 0ULL ||
         (Request->flags &
            (KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE)) != 0UL)) {
        /* Return the exact removal-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require a field-free clear request beyond confirmation metadata. */
    if (Request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_CLEAR &&
        (Request->ruleId != 0UL ||
         Request->deniedAccess != 0UL ||
         Request->physicalAddress != 0ULL ||
         Request->pageCount != 0ULL ||
         (Request->flags &
            (KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG |
             KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE)) != 0UL)) {
        /* Return the exact clear-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Require add requests to allocate a new stable rule identifier. */
    if (Request->operation ==
            KSWORD_ARK_HVM_EPT_RULE_ADD &&
        Request->ruleId != 0UL) {
        /* Return the exact add-field contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Reject rule control before runtime initialization. */
    if (!g_KswordHvm.Initialized) {
        /* Return the explicit lifecycle boundary. */
        return STATUS_DEVICE_NOT_READY;
    }
    /* Serialize rule table, EPT split, and cross-CPU invalidation changes. */
    KeEnterCriticalRegion();
    /* Acquire exclusive lifecycle ownership for the complete rule operation. */
    ExAcquirePushLockExclusive(&g_KswordHvm.Lock);
    /* Reject concurrent long-running lifecycle mutation. */
    if (g_KswordHvm.Busy) {
        /* Initialize the complete busy protocol response. */
        RtlZeroMemory(Response, sizeof(*Response));
        /* Publish the response protocol identity. */
        Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        /* Publish the complete fixed response size. */
        Response->size = sizeof(*Response);
        /* Publish an explicit partial/busy result. */
        Response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
        /* Publish the authoritative busy NTSTATUS. */
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* Select protocol-level success after writing the fixed response. */
        status = STATUS_SUCCESS;
    } else if (Request->operation !=
                   KSWORD_ARK_HVM_EPT_RULE_QUERY &&
               InterlockedCompareExchange(
                   &g_KswordHvm.ResidentProcessorCount,
                   0L,
                   0L) != 0L) {
        /*
         * Resident VM exits scan rules without taking this PASSIVE_LEVEL lock.
         * Keep the entire rule table and every split leaf immutable until all
         * VCPUs have committed their guest-stack return.
         */
        RtlZeroMemory(Response, sizeof(*Response));
        /* Publish the fixed response identity for the fail-closed rejection. */
        Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
        Response->size = sizeof(*Response);
        /* Reuse the existing partial result with authoritative busy detail. */
        Response->status =
            KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL;
        Response->lastStatus = STATUS_DEVICE_BUSY;
        /* No rule, split entry, generation, or EPT translation was changed. */
        status = STATUS_SUCCESS;
    } else {
        /* Execute the bounded EPT rule operation under lifecycle ownership. */
        status = KswordARKHvmEptRuleControlLocked(
            &g_KswordHvm,
            Request,
            Response);
    }
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&g_KswordHvm.Lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Return the complete protocol operation result. */
    return status;
}

NTSTATUS
KswordARKHvmEventControl(
    _In_ const KSWORD_ARK_HVM_EVENT_QUERY_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE* Response
    )
{
    /* Validate the complete fixed protocol contract. */
    if (Request == NULL ||
        Response == NULL ||
        Request->version != KSWORD_ARK_HVM_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->flags != 0UL ||
        Request->reserved != 0UL ||
        (Request->operation !=
            KSWORD_ARK_HVM_EVENT_QUERY_READ &&
         Request->operation !=
            KSWORD_ARK_HVM_EVENT_QUERY_CLEAR)) {
        /* Return the exact fixed-contract failure. */
        return STATUS_INVALID_PARAMETER;
    }
    /* Execute read-only sequence snapshot without lifecycle locking. */
    if (Request->operation ==
        KSWORD_ARK_HVM_EVENT_QUERY_READ) {
        /* Return the bounded sequence-validated event batch. */
        return KswordARKHvmEventQuery(
            Request,
            Response);
    }
    /* Serialize reset against resident lifecycle mutation. */
    KeEnterCriticalRegion();
    /* Acquire exclusive lifecycle ownership for the complete ring reset. */
    ExAcquirePushLockExclusive(&g_KswordHvm.Lock);
    /* Refuse reset while VM-exit writers can still publish concurrently. */
    if (InterlockedCompareExchange(
            &g_KswordHvm.ResidentProcessorCount,
            0L,
            0L) != 0L) {
        /* Release exclusive lifecycle ownership. */
        ExReleasePushLockExclusive(&g_KswordHvm.Lock);
        /* Leave the critical region after releasing the push lock. */
        KeLeaveCriticalRegion();
        /* Return the explicit active-writer conflict. */
        return STATUS_DEVICE_BUSY;
    }
    /* Reset the complete stopped event ring. */
    KswordARKHvmEventReset();
    /* Clear protocol-visible retained-event state. */
    g_KswordHvm.StateFlags &=
        ~KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE;
    /* Initialize the complete empty response. */
    RtlZeroMemory(Response, sizeof(*Response));
    /* Publish the response protocol identity. */
    Response->version = KSWORD_ARK_HVM_PROTOCOL_VERSION;
    /* Publish the complete fixed response size. */
    Response->size = sizeof(*Response);
    /* Release exclusive lifecycle ownership. */
    ExReleasePushLockExclusive(&g_KswordHvm.Lock);
    /* Leave the critical region after releasing the push lock. */
    KeLeaveCriticalRegion();
    /* Complete the stopped event reset successfully. */
    return STATUS_SUCCESS;
}
