/*++

Module Name:

    hvm_internal.h

Abstract:

    Defines the private HVM runtime shared by lifecycle, EPT, resident VMX,
    nested-VMX, eVMCS, and event modules.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_runtime.h"

/* Define the architectural page size used by VMX and EPT structures. */
#define KSW_HVM_PAGE_BYTES 0x1000ULL
/* Define the large EPT leaf size used by the baseline identity map. */
#define KSW_HVM_LARGE_PAGE_BYTES 0x200000ULL
/* Define the byte span covered by one EPT page-directory. */
#define KSW_HVM_ONE_GIB 0x40000000ULL
/* Define the byte span covered by one EPT PML4 entry. */
#define KSW_HVM_ONE_512_GIB 0x8000000000ULL
/* Bound the identity map to a deliberate eight-TiB research window. */
#define KSW_HVM_MAX_PML4_ENTRIES 16UL
/* Bound the number of simultaneously split two-MiB EPT leaves. */
#define KSW_HVM_MAX_EPT_SPLITS 256UL
/* Reserve enough allocation-ledger entries for sparse tables and splits. */
#define KSW_HVM_MAX_EPT_PAGES \
    (1UL + KSW_HVM_MAX_PML4_ENTRIES + \
        (KSW_HVM_MAX_PML4_ENTRIES * 512UL) + \
        KSW_HVM_MAX_EPT_SPLITS)
/* Bound every physical address accepted by the EPT backend. */
#define KSW_HVM_MAX_MAPPED_PHYSICAL \
    (KSW_HVM_ONE_512_GIB * KSW_HVM_MAX_PML4_ENTRIES)
/* Bound one per-processor resident VM-exit stack. */
#define KSW_HVM_RESIDENT_HOST_STACK_BYTES 0x8000UL

/* Name the VMX feature-control model-specific register. */
#define KSW_IA32_FEATURE_CONTROL 0x3AUL
/* Name the VMX basic capability model-specific register. */
#define KSW_IA32_VMX_BASIC 0x480UL
/* Name the VMX CR0 required-one model-specific register. */
#define KSW_IA32_VMX_CR0_FIXED0 0x486UL
/* Name the VMX CR0 allowed-one model-specific register. */
#define KSW_IA32_VMX_CR0_FIXED1 0x487UL
/* Name the VMX CR4 required-one model-specific register. */
#define KSW_IA32_VMX_CR4_FIXED0 0x488UL
/* Name the VMX CR4 allowed-one model-specific register. */
#define KSW_IA32_VMX_CR4_FIXED1 0x489UL
/* Name the secondary processor-control capability register. */
#define KSW_IA32_VMX_PROCBASED_CTLS2 0x48BUL
/* Name the legacy primary processor-control capability register. */
#define KSW_IA32_VMX_PROCBASED_CTLS 0x482UL
/* Name the true primary processor-control capability register. */
#define KSW_IA32_VMX_TRUE_PROCBASED_CTLS 0x48EUL
/* Name the EPT and VPID capability model-specific register. */
#define KSW_IA32_VMX_EPT_VPID_CAP 0x48CUL
/* Name the Hyper-V VP-assist-page model-specific register. */
#define KSW_HV_X64_MSR_VP_ASSIST_PAGE 0x40000073UL

/* Identify the CR4 bit that enables VMX instructions. */
#define KSW_CR4_VMXE (1ULL << 13)

/* Define the EPT read permission bit. */
#define KSW_EPT_READ 0x1ULL
/* Define the EPT write permission bit. */
#define KSW_EPT_WRITE 0x2ULL
/* Define the EPT execute permission bit. */
#define KSW_EPT_EXECUTE 0x4ULL
/* Define the EPT memory-type field shift. */
#define KSW_EPT_MEMORY_TYPE_SHIFT 3UL
/* Define the EPT large-page marker. */
#define KSW_EPT_LARGE_PAGE (1ULL << 7)
/* Define the physical-address portion of an EPT entry. */
#define KSW_EPT_PHYSICAL_MASK 0x000FFFFFFFFFF000ULL

/* Identify four-level EPT page-walk capability. */
#define KSW_EPT_CAP_PAGE_WALK_4 (1ULL << 6)
/* Identify EPT execute-only leaf translation capability. */
#define KSW_EPT_CAP_EXECUTE_ONLY (1ULL << 0)
/* Identify write-back EPT memory-type capability. */
#define KSW_EPT_CAP_WB (1ULL << 14)
/* Identify two-MiB EPT leaf capability. */
#define KSW_EPT_CAP_2MB (1ULL << 16)
/* Identify INVEPT instruction capability. */
#define KSW_EPT_CAP_INVEPT (1ULL << 20)
/* Identify EPT accessed-and-dirty capability. */
#define KSW_EPT_CAP_AD (1ULL << 21)
/* Identify single-context INVEPT capability. */
#define KSW_EPT_CAP_INVEPT_SINGLE (1ULL << 25)
/* Identify all-context INVEPT capability. */
#define KSW_EPT_CAP_INVEPT_ALL (1ULL << 26)
/* Identify VPID capability. */
#define KSW_EPT_CAP_VPID (1ULL << 32)

/* Bound the variable-MTRR snapshot to the architectural low-byte count. */
#define KSW_HVM_MAX_VARIABLE_MTRRS 32UL

/* Describe one processor-owned VMXON and VMCS allocation pair. */
typedef struct _KSW_HVM_CPU_RESOURCE
{
    /* Preserve the protocol-visible processor state. */
    KSWORD_ARK_HVM_CPU_ROW Row;
    /* Retain the processor-owned VMXON virtual address. */
    PVOID VmxonVirtual;
    /* Retain the processor-owned VMXON physical address. */
    PHYSICAL_ADDRESS VmxonPhysical;
    /* Retain the processor-owned VMCS virtual address. */
    PVOID VmcsVirtual;
    /* Retain the processor-owned VMCS physical address. */
    PHYSICAL_ADDRESS VmcsPhysical;
} KSW_HVM_CPU_RESOURCE;

/* Track one contiguous page allocated for an EPT hierarchy. */
typedef struct _KSW_HVM_EPT_PAGE
{
    /* Retain the kernel virtual address used for cleanup. */
    PVOID VirtualAddress;
    /* Retain the physical address encoded into a parent EPT entry. */
    PHYSICAL_ADDRESS PhysicalAddress;
} KSW_HVM_EPT_PAGE;

/* Describe one variable MTRR range after mask decoding. */
typedef struct _KSW_HVM_MTRR_RANGE
{
    /* Retain the inclusive physical base of the MTRR range. */
    ULONGLONG Base;
    /* Retain the exclusive physical end of the MTRR range. */
    ULONGLONG End;
    /* Retain the Intel memory-type encoding. */
    UCHAR Type;
    /* Record whether the architectural valid bit was present. */
    UCHAR Valid;
    /* Keep the structure naturally aligned without undefined padding data. */
    USHORT Reserved;
} KSW_HVM_MTRR_RANGE;

/* Preserve an immutable MTRR snapshot used while building EPT leaves. */
typedef struct _KSW_HVM_MTRR_STATE
{
    /* Record whether MTRRs are globally enabled. */
    BOOLEAN Enabled;
    /* Record whether fixed-range MTRRs are enabled. */
    BOOLEAN FixedEnabled;
    /* Retain the default Intel memory-type encoding. */
    UCHAR DefaultType;
    /* Retain the number of valid variable-range records. */
    UCHAR VariableCount;
    /* Retain all architecturally discoverable fixed-range type bytes. */
    UCHAR FixedTypes[88];
    /* Retain the decoded variable MTRR records. */
    KSW_HVM_MTRR_RANGE Variable[KSW_HVM_MAX_VARIABLE_MTRRS];
} KSW_HVM_MTRR_STATE;

/* Describe one active protocol-visible EPT rule. */
typedef struct _KSW_HVM_EPT_RULE_SLOT
{
    /* Record whether the slot contains an active rule. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[3];
    /* Retain the stable protocol-visible rule identifier. */
    ULONG RuleId;
    /* Retain the permissions removed from each target page. */
    ULONG DeniedAccess;
    /* Retain the rule behavior flags. */
    ULONG Flags;
    /* Retain the first page-aligned guest physical address. */
    ULONGLONG PhysicalAddress;
    /* Retain the number of covered four-KiB pages. */
    ULONGLONG PageCount;
} KSW_HVM_EPT_RULE_SLOT;

/* Track one two-MiB EPT leaf that was split into four-KiB entries. */
typedef struct _KSW_HVM_EPT_SPLIT
{
    /* Record whether the split ledger slot is active. */
    BOOLEAN Active;
    /* Keep the structure explicitly initialized across architectures. */
    UCHAR Reserved0[7];
    /* Retain the aligned guest physical base represented by the page table. */
    ULONGLONG PhysicalBase;
    /* Retain the writable virtual address of the page table. */
    PVOID PageTable;
    /* Retain the page-table physical address encoded into the parent PDE. */
    PHYSICAL_ADDRESS PageTablePhysical;
    /* Retain the writable parent PDE address for merge and invalidation. */
    volatile ULONGLONG* ParentEntry;
    /* Retain the original two-MiB identity leaf. */
    ULONGLONG OriginalEntry;
} KSW_HVM_EPT_SPLIT;

/* Own the serialized HVM capability, lifecycle, EPT, and telemetry state. */
typedef struct _KSW_HVM_RUNTIME
{
    /* Serialize PASSIVE_LEVEL lifecycle and protocol operations. */
    EX_PUSH_LOCK Lock;
    /* Publish whether runtime initialization completed. */
    BOOLEAN Initialized;
    /* Publish whether one serialized control operation is executing. */
    BOOLEAN Busy;
    /* Keep explicit padding initialized for stable crash-dump inspection. */
    USHORT Reserved0;
    /* Publish protocol-visible lifecycle flags. */
    ULONG StateFlags;
    /* Publish the generation used for compare-before control requests. */
    ULONG Generation;
    /* Publish the stable query status. */
    ULONG QueryStatus;
    /* Preserve the last authoritative NTSTATUS. */
    NTSTATUS LastStatus;
    /* Preserve the number of enumerated processors. */
    ULONG ProcessorCount;
    /* Preserve the number of allocated processor resource pairs. */
    ULONG PreparedProcessorCount;
    /* Preserve the number of successful VMXON/VMXOFF tests. */
    ULONG SelfTestPassedProcessorCount;
    /* Publish the number of processors currently in VMX non-root mode. */
    volatile LONG ResidentProcessorCount;
    /* Publish resident-lifecycle implementation maturity. */
    ULONG ResidentImplementation;
    /* Publish EPT-rule implementation maturity. */
    ULONG EptImplementation;
    /* Publish nested-VMX implementation maturity. */
    ULONG NestedImplementation;
    /* Publish eVMCS implementation maturity. */
    ULONG EvmcsImplementation;
    /* Publish the current nested-VMX state. */
    ULONG NestedState;
    /* Publish the current eVMCS state. */
    ULONG EvmcsState;
    /* Publish the TLFS eVMCS version discovered from CPUID. */
    USHORT EvmcsVersion;
    /* Keep explicit padding initialized for deterministic snapshots. */
    USHORT Reserved1;
    /* Publish TLFS partition and VP-assist ownership evidence. */
    ULONG EvmcsFlags;
    /* Preserve the current VP-assist-page MSR value when readable. */
    ULONGLONG EvmcsVpAssistMsr;
    /* Preserve the number of active EPT rules. */
    ULONG EptRuleCount;
    /* Preserve the number of allocated EPT table pages. */
    ULONG EptPageCount;
    /* Preserve the number of populated EPT PML4 entries. */
    ULONG EptPml4Entries;
    /* Preserve the number of populated EPT PDPT entries. */
    ULONG EptPdptEntries;
    /* Preserve the number of populated two-MiB EPT leaves. */
    ULONG EptLargePageEntries;
    /* Preserve decoded protocol capability flags. */
    ULONGLONG FeatureFlags;
    /* Preserve IA32_VMX_BASIC evidence. */
    ULONGLONG VmxBasic;
    /* Preserve IA32_VMX_EPT_VPID_CAP evidence. */
    ULONGLONG VmxEptVpidCapabilities;
    /* Preserve IA32_FEATURE_CONTROL evidence. */
    ULONGLONG FeatureControl;
    /* Preserve IA32_VMX_CR0_FIXED0 evidence. */
    ULONGLONG Cr0Fixed0;
    /* Preserve IA32_VMX_CR0_FIXED1 evidence. */
    ULONGLONG Cr0Fixed1;
    /* Preserve IA32_VMX_CR4_FIXED0 evidence. */
    ULONGLONG Cr4Fixed0;
    /* Preserve IA32_VMX_CR4_FIXED1 evidence. */
    ULONGLONG Cr4Fixed1;
    /* Preserve the active EPT pointer. */
    ULONGLONG EptPointer;
    /* Preserve the number of identity-mapped RAM bytes. */
    ULONGLONG MappedRamBytes;
    /* Preserve the exclusive upper physical mapping boundary. */
    ULONGLONG HighestMappedPhysicalAddress;
    /* Preserve a monotonic VM-exit count. */
    volatile LONG64 VmExitCount;
    /* Preserve the last VM-exit qualification. */
    volatile LONG64 LastExitQualification;
    /* Preserve the last guest instruction pointer. */
    volatile LONG64 LastGuestRip;
    /* Preserve the last guest stack pointer. */
    volatile LONG64 LastGuestRsp;
    /* Preserve the last basic VM-exit reason. */
    volatile LONG LastExitReason;
    /* Preserve the last VM-exit instruction length. */
    volatile LONG LastExitInstructionLength;
    /* Preserve the last VM-instruction error. */
    volatile LONG LastVmInstructionError;
    /* Preserve the group of the last one-shot launch. */
    USHORT LastLaunchProcessorGroup;
    /* Preserve the group-relative CPU of the last one-shot launch. */
    UCHAR LastLaunchProcessorNumber;
    /* Preserve whether the last one-shot launch was nested. */
    UCHAR LastLaunchWasNested;
    /* Preserve the processor vendor string. */
    CHAR CpuVendor[KSWORD_ARK_HVM_VENDOR_CHARS];
    /* Preserve the hypervisor vendor string. */
    CHAR HypervisorVendor[KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS];
    /* Own every per-processor VMX resource pair. */
    KSW_HVM_CPU_RESOURCE Processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
    /* Track every EPT allocation exactly once. */
    KSW_HVM_EPT_PAGE EptPages[KSW_HVM_MAX_EPT_PAGES];
    /* Retain the EPT PML4 virtual address. */
    PVOID EptPml4;
    /* Retain each sparse EPT PDPT virtual address. */
    PVOID EptPdpt[KSW_HVM_MAX_PML4_ENTRIES];
    /* Retain each sparse EPT page-directory virtual address. */
    PVOID EptPd[KSW_HVM_MAX_PML4_ENTRIES][512];
    /* Retain the immutable MTRR snapshot used to type EPT leaves. */
    KSW_HVM_MTRR_STATE Mtrr;
    /* Retain every protocol-visible EPT rule. */
    KSW_HVM_EPT_RULE_SLOT EptRules[KSWORD_ARK_HVM_MAX_EPT_RULES];
    /* Retain every split two-MiB EPT leaf. */
    KSW_HVM_EPT_SPLIT EptSplits[KSW_HVM_MAX_EPT_SPLITS];
    /* Serialize resident VMX transition commits against power notification. */
    KSPIN_LOCK ResidentTransitionLock;
    /* Reference this image's driver object for the unload interlock. */
    PDRIVER_OBJECT DriverObject;
    /* Preserve the exact KMDF-installed unload entry while residency is active. */
    PDRIVER_UNLOAD OriginalDriverUnload;
    /* Reference the system-defined power-state callback object. */
    PCALLBACK_OBJECT PowerStateCallbackObject;
    /* Own the power-state callback registration. */
    PVOID PowerStateCallbackRegistration;
    /* Own the processor-add veto callback registration. */
    PVOID ProcessorChangeRegistration;
    /* Publish host-stack construction so a power callback never frees it. */
    volatile LONG ResidentContextPreparing;
    /* Publish 0=idle, 1=leaving S0, 2=resumed while context prep drains. */
    volatile LONG PowerTransitionPending;
    /* Increment once whenever the power manager begins leaving S0. */
    volatile LONG PowerTransitionGeneration;
    /* Publish whether DriverUnload is currently removed from DriverObject. */
    volatile LONG UnloadGuardArmed;
    /* Fail-closed resident lifecycle gate, enabled only after all guards bind. */
    BOOLEAN ResidentStartAllowed;
    /* Keep the tail deterministic for crash-dump inspection. */
    UCHAR Reserved2[7];
} KSW_HVM_RUNTIME;

EXTERN_C_START

/* Allocate one zeroed EPT page and record it in the runtime ledger. */
PVOID
KswordARKHvmAllocateEptPageLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _Out_ PHYSICAL_ADDRESS* PhysicalAddress
    );

/* Return the process-wide HVM runtime for nonblocking VM-exit telemetry. */
KSW_HVM_RUNTIME*
KswordARKHvmGetRuntime(
    VOID
    );

/* Remove the exact captured KMDF unload entry before resident VMX entry. */
NTSTATUS
KswordARKHvmArmUnloadGuard(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Restore the captured unload entry after every resident CPU completed VMXOFF. */
NTSTATUS
KswordARKHvmDisarmUnloadGuard(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/* Invalidate pre-sleep VMX evidence before reopening resident start. */
VOID
KswordARKHvmInvalidatePowerResumeEvidence(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

EXTERN_C_END
