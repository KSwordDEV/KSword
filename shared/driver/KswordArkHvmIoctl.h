#pragma once

#include "KswordArkProcessIoctl.h"

/*
 * The HVM protocol separates capability discovery from implementation state.
 * A capability-only or partial result must never be interpreted as a resident
 * hypervisor.  ACTIVE is published only after every selected processor has
 * entered VMX non-root operation and the rollback rendezvous is available.
 */
#define KSWORD_ARK_HVM_PROTOCOL_VERSION 4UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM   0x8CAUL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM 0x8CBUL
// 0x8CC-0x8CD are occupied by driver-dispatch and SLAT/IOMMU on main.
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE 0x8B8UL
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS   0x8B9UL
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_MEMORY   0x8BAUL

#define IOCTL_KSWORD_ARK_QUERY_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KSWORD_ARK_CONTROL_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EPT_RULE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EVENTS \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/*
 * Ring -1 memory access.  Reads are as privileged as writes here because the
 * access path deliberately avoids the documented memory-manager entry points,
 * so the whole interface requires write access rather than only the mutating
 * half of it.
 */
#define IOCTL_KSWORD_ARK_HVM_MEMORY \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_MEMORY, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_VENDOR_CHARS 16U
#define KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS 16U
#define KSWORD_ARK_HVM_MAX_PROCESSORS 256UL
#define KSWORD_ARK_HVM_MAX_EPT_RULES 128UL
#define KSWORD_ARK_HVM_MAX_EVENT_ROWS 64UL

#define KSWORD_ARK_HVM_FEATURE_INTEL                  0x0000000000000001ULL
#define KSWORD_ARK_HVM_FEATURE_VMX                    0x0000000000000002ULL
#define KSWORD_ARK_HVM_FEATURE_FEATURE_CONTROL_LOCKED 0x0000000000000004ULL
#define KSWORD_ARK_HVM_FEATURE_VMX_OUTSIDE_SMX        0x0000000000000008ULL
#define KSWORD_ARK_HVM_FEATURE_TRUE_CONTROLS          0x0000000000000010ULL
#define KSWORD_ARK_HVM_FEATURE_EPT                    0x0000000000000020ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_WB                 0x0000000000000040ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_4_LEVEL            0x0000000000000080ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_2MB                0x0000000000000100ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_AD                 0x0000000000000200ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT                 0x0000000000000400ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT_SINGLE          0x0000000000000800ULL
#define KSWORD_ARK_HVM_FEATURE_INVEPT_ALL             0x0000000000001000ULL
#define KSWORD_ARK_HVM_FEATURE_VPID                   0x0000000000002000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERVISOR_PRESENT     0x0000000000004000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_EXPOSED     0x0000000000008000ULL
#define KSWORD_ARK_HVM_FEATURE_ONE_SHOT_GUEST          0x0000000000010000ULL
#define KSWORD_ARK_HVM_FEATURE_VMEXIT_TELEMETRY        0x0000000000020000ULL
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_VMM            0x0000000000040000ULL
#define KSWORD_ARK_HVM_FEATURE_MULTICORE_RENDEZVOUS     0x0000000000080000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_4KB_SPLIT            0x0000000000100000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_RULES                0x0000000000200000ULL
#define KSWORD_ARK_HVM_FEATURE_EPT_EVENT_RING           0x0000000000400000ULL
#define KSWORD_ARK_HVM_FEATURE_MTRR_AWARE_EPT           0x0000000000800000ULL
#define KSWORD_ARK_HVM_FEATURE_MONITOR_TRAP_FLAG        0x0000000001000000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_DISPATCH      0x0000000002000000ULL
#define KSWORD_ARK_HVM_FEATURE_NESTED_VMX_ACTIVE        0x0000000004000000ULL
#define KSWORD_ARK_HVM_FEATURE_SHADOW_EPT               0x0000000008000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_CAPABLE     0x0000000010000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_V1          0x0000000020000000ULL
#define KSWORD_ARK_HVM_FEATURE_HYPERV_EVMCS_ACTIVE      0x0000000040000000ULL
#define KSWORD_ARK_HVM_FEATURE_VMX_INSTRUCTION_EMULATION 0x0000000080000000ULL
#define KSWORD_ARK_HVM_FEATURE_POWER_STATE_GUARD         0x0000000100000000ULL
#define KSWORD_ARK_HVM_FEATURE_PROCESSOR_TOPOLOGY_GUARD  0x0000000200000000ULL
#define KSWORD_ARK_HVM_FEATURE_DRIVER_UNLOAD_GUARD       0x0000000400000000ULL
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_LIFECYCLE_GUARDED 0x0000000800000000ULL
/*
 * The MSR bitmap is what makes residency survivable: without it every RDMSR
 * and WRMSR exits unconditionally into a dispatcher that cannot complete them.
 */
#define KSWORD_ARK_HVM_FEATURE_MSR_BITMAP                 0x0000001000000000ULL
/* The dispatcher completes every unconditional exit instead of devirtualizing. */
#define KSWORD_ARK_HVM_FEATURE_EXIT_EMULATION             0x0000002000000000ULL
/* A timed soak proved residency survives ordinary system activity. */
#define KSWORD_ARK_HVM_FEATURE_RESIDENT_SUSTAINED         0x0000004000000000ULL

#define KSWORD_ARK_HVM_STATE_INITIALIZED      0x00000001UL
#define KSWORD_ARK_HVM_STATE_RESOURCES_READY  0x00000002UL
#define KSWORD_ARK_HVM_STATE_EPT_READY        0x00000004UL
#define KSWORD_ARK_HVM_STATE_SELF_TESTED      0x00000008UL
#define KSWORD_ARK_HVM_STATE_SELF_TEST_PASSED 0x00000010UL
#define KSWORD_ARK_HVM_STATE_BUSY             0x00000020UL
#define KSWORD_ARK_HVM_STATE_FAULTED          0x00000040UL
#define KSWORD_ARK_HVM_STATE_EPT_TRUNCATED    0x00000080UL
#define KSWORD_ARK_HVM_STATE_GUEST_READY      0x00000100UL
#define KSWORD_ARK_HVM_STATE_GUEST_RUNNING    0x00000200UL
#define KSWORD_ARK_HVM_STATE_GUEST_EXITED     0x00000400UL
#define KSWORD_ARK_HVM_STATE_NESTED_ACTIVE    0x00000800UL
#define KSWORD_ARK_HVM_STATE_NESTED_VALIDATED 0x00001000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_STARTING 0x00002000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_ACTIVE   0x00004000UL
#define KSWORD_ARK_HVM_STATE_RESIDENT_STOPPING 0x00008000UL
#define KSWORD_ARK_HVM_STATE_EPT_RULES_ACTIVE  0x00010000UL
#define KSWORD_ARK_HVM_STATE_EVENTS_AVAILABLE  0x00020000UL
#define KSWORD_ARK_HVM_STATE_NESTED_PARTIAL    0x00040000UL
#define KSWORD_ARK_HVM_STATE_EVMCS_PARTIAL     0x00080000UL
#define KSWORD_ARK_HVM_STATE_ROLLBACK_REQUIRED 0x00100000UL
#define KSWORD_ARK_HVM_STATE_POWER_TRANSITION_PENDING 0x00200000UL
#define KSWORD_ARK_HVM_STATE_UNLOAD_GUARD_ARMED       0x00400000UL

#define KSWORD_ARK_HVM_CPU_STATE_RESOURCE_READY  0x00000001UL
#define KSWORD_ARK_HVM_CPU_STATE_SELF_TESTED     0x00000002UL
#define KSWORD_ARK_HVM_CPU_STATE_VMXON_SUCCEEDED 0x00000004UL
#define KSWORD_ARK_HVM_CPU_STATE_EXCEPTION       0x00000008UL
#define KSWORD_ARK_HVM_CPU_STATE_CONFLICT        0x00000010UL
#define KSWORD_ARK_HVM_CPU_STATE_VMCS_LOADED      0x00000020UL
#define KSWORD_ARK_HVM_CPU_STATE_GUEST_LAUNCHED   0x00000040UL
#define KSWORD_ARK_HVM_CPU_STATE_VMEXIT_HANDLED   0x00000080UL
#define KSWORD_ARK_HVM_CPU_STATE_RESIDENT_ACTIVE  0x00000100UL
#define KSWORD_ARK_HVM_CPU_STATE_STOP_REQUESTED   0x00000200UL
#define KSWORD_ARK_HVM_CPU_STATE_DEVIRTUALIZED    0x00000400UL
#define KSWORD_ARK_HVM_CPU_STATE_NESTED_PARTIAL   0x00000800UL
#define KSWORD_ARK_HVM_CPU_STATE_EVMCS_PARTIAL    0x00001000UL

#define KSWORD_ARK_HVM_QUERY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_QUERY_STATUS_UNSUPPORTED_CPU       1UL
#define KSWORD_ARK_HVM_QUERY_STATUS_FIRMWARE_DISABLED     2UL
#define KSWORD_ARK_HVM_QUERY_STATUS_HYPERVISOR_CONFLICT   3UL
#define KSWORD_ARK_HVM_QUERY_STATUS_RESOURCES_UNAVAILABLE 4UL
#define KSWORD_ARK_HVM_QUERY_STATUS_SELF_TEST_FAILED      5UL
#define KSWORD_ARK_HVM_QUERY_STATUS_BUSY                  6UL
#define KSWORD_ARK_HVM_QUERY_STATUS_PARTIAL               7UL
#define KSWORD_ARK_HVM_QUERY_STATUS_ROLLBACK_REQUIRED     8UL

#define KSWORD_ARK_HVM_IMPLEMENTATION_UNSUPPORTED     0UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_PARTIAL         2UL
#define KSWORD_ARK_HVM_IMPLEMENTATION_ACTIVE          3UL

#define KSWORD_ARK_HVM_CONTROL_PREPARE   1UL
#define KSWORD_ARK_HVM_CONTROL_SELF_TEST 2UL
#define KSWORD_ARK_HVM_CONTROL_TEARDOWN  3UL
#define KSWORD_ARK_HVM_CONTROL_LAUNCH_TEST_GUEST 4UL
/*
 * START_RESIDENT is available only when the driver publishes the guarded
 * resident-lifecycle feature.  The driver must stop every VCPU before a power
 * transition and must prevent image unload while any VCPU remains resident.
 */
#define KSWORD_ARK_HVM_CONTROL_START_RESIDENT 5UL
#define KSWORD_ARK_HVM_CONTROL_STOP_RESIDENT  6UL
#define KSWORD_ARK_HVM_CONTROL_VALIDATE_NESTED 7UL
#define KSWORD_ARK_HVM_CONTROL_RESET_FAULT     8UL
/*
 * SOAK starts residency, holds it for the requested bounded window, and stops
 * it again.  It is the only control that proves residency survives ordinary
 * system activity rather than merely entering and leaving VMX non-root once.
 */
#define KSWORD_ARK_HVM_CONTROL_SOAK            9UL

/* Bound one soak window so a stuck request can never hold VMX indefinitely. */
#define KSWORD_ARK_HVM_SOAK_MAX_MILLISECONDS 30000UL
/* Keep a soak long enough for scheduler, timer and MSR activity to occur. */
#define KSWORD_ARK_HVM_SOAK_MIN_MILLISECONDS 100UL

#define KSWORD_ARK_HVM_CONTROL_FLAG_UI_CONFIRMED 0x00000001UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_FORCE        0x00000002UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ALLOW_NESTED 0x00000004UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ONE_SHOT_GUEST 0x00000008UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EPT_EVENTS 0x00000010UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_NESTED_VMX 0x00000020UL
#define KSWORD_ARK_HVM_CONTROL_FLAG_ENABLE_EVMCS      0x00000040UL

#define KSWORD_ARK_HVM_CONTROL_CONFIRMATION_TOKEN 0x48564D43UL

#define KSWORD_ARK_HVM_CONTROL_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_UNSUPPORTED_CPU       3UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_FIRMWARE_DISABLED     4UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_HYPERVISOR_CONFLICT   5UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_ALREADY_PREPARED      6UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_NOT_PREPARED          7UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_RESOURCE_FAILED       8UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_SELF_TEST_FAILED      9UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_VERIFY_FAILED         10UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_BUSY                  11UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_GUEST_LAUNCH_FAILED   12UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_UNEXPECTED_VMEXIT     13UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_PARTIAL_IMPLEMENTATION 14UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_RENDEZVOUS_FAILED      15UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_ROLLBACK_REQUIRED      16UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_NESTED_UNSUPPORTED     17UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_EVMCS_UNSUPPORTED      18UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_POWER_TRANSITION_BLOCKED 19UL
#define KSWORD_ARK_HVM_CONTROL_STATUS_LIFECYCLE_GUARD_FAILED   20UL

#define KSWORD_ARK_HVM_EXIT_REASON_NONE   0xFFFFFFFFUL
#define KSWORD_ARK_HVM_EXIT_REASON_VMCALL 18UL
#define KSWORD_ARK_HVM_EXIT_REASON_EPT_VIOLATION 48UL
#define KSWORD_ARK_HVM_EXIT_REASON_EPT_MISCONFIGURATION 49UL
#define KSWORD_ARK_HVM_EXIT_REASON_INVEPT 50UL
#define KSWORD_ARK_HVM_EXIT_REASON_INVVPID 53UL
#define KSWORD_ARK_HVM_EXIT_REASON_MONITOR_TRAP 37UL

#define KSWORD_ARK_HVM_EPT_ACCESS_READ    0x00000001UL
#define KSWORD_ARK_HVM_EPT_ACCESS_WRITE   0x00000002UL
#define KSWORD_ARK_HVM_EPT_ACCESS_EXECUTE 0x00000004UL

#define KSWORD_ARK_HVM_EPT_RULE_ADD    1UL
#define KSWORD_ARK_HVM_EPT_RULE_REMOVE 2UL
#define KSWORD_ARK_HVM_EPT_RULE_CLEAR  3UL
#define KSWORD_ARK_HVM_EPT_RULE_QUERY  4UL

#define KSWORD_ARK_HVM_EPT_RULE_FLAG_LOG          0x00000001UL
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_ALLOW_ONCE   0x00000002UL
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_UI_CONFIRMED 0x00000004UL
/*
 * ENFORCE turns a rule from a tripwire into durable denial: the access is
 * refused with an injected #PF and residency continues, instead of recording
 * the hit and devirtualizing.  Unlike ALLOW_ONCE it never edits the shared EPT
 * leaf, so it is safe on any processor count.
 *
 * The guest sees a page fault at an address its own page tables map, which is
 * exactly what denial means here.  Kernel-mode targets can therefore bugcheck
 * the moment a driver touches the protected page - that is the intended
 * behavior of a deny rule, not a defect, and it is why the flag requires
 * explicit confirmation.
 *
 * A rule can only deny an access whose guest-linear address the CPU reported,
 * because CR2 has to be set for the injected fault to mean anything.  When it
 * is unavailable the rule falls back to tripwire behavior.
 */
#define KSWORD_ARK_HVM_EPT_RULE_FLAG_ENFORCE      0x00000008UL

#define KSWORD_ARK_HVM_EPT_RULE_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_SPLIT_FAILED          6UL
#define KSWORD_ARK_HVM_EPT_RULE_STATUS_PARTIAL               7UL

#define KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT          1UL
#define KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION   2UL
#define KSWORD_ARK_HVM_EVENT_TYPE_NESTED_VMX      3UL
#define KSWORD_ARK_HVM_EVENT_TYPE_FATAL_EXIT      4UL
#define KSWORD_ARK_HVM_EVENT_TYPE_LIFECYCLE       5UL

#define KSWORD_ARK_HVM_EVENT_QUERY_READ  1UL
#define KSWORD_ARK_HVM_EVENT_QUERY_CLEAR 2UL

#define KSWORD_ARK_HVM_NESTED_STATE_DISABLED        0UL
#define KSWORD_ARK_HVM_NESTED_STATE_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_NESTED_STATE_DISPATCH_READY  2UL
#define KSWORD_ARK_HVM_NESTED_STATE_L1_VMXON        3UL
#define KSWORD_ARK_HVM_NESTED_STATE_VMCS12_CURRENT  4UL
#define KSWORD_ARK_HVM_NESTED_STATE_L2_PARTIAL      5UL

#define KSWORD_ARK_HVM_EVMCS_STATE_UNAVAILABLE     0UL
#define KSWORD_ARK_HVM_EVMCS_STATE_CAPABILITY_ONLY 1UL
#define KSWORD_ARK_HVM_EVMCS_STATE_V1_PARTIAL       2UL
#define KSWORD_ARK_HVM_EVMCS_STATE_ACTIVE           3UL

#define KSWORD_ARK_HVM_EVMCS_FLAG_ROOT_PARTITION      0x00000001UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_READABLE  0x00000002UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_VP_ASSIST_ENABLED   0x00000004UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_OWNERSHIP_CONFLICT  0x00000008UL
#define KSWORD_ARK_HVM_EVMCS_FLAG_CLEAN_FIELDS        0x00000010UL

typedef struct _KSWORD_ARK_HVM_CPU_ROW
{
    unsigned short processorGroup;
    unsigned char processorNumber;
    unsigned char vmxInstructionResult;
    unsigned long stateFlags;
    long lastStatus;
    unsigned long lastExitReason;
    unsigned long long vmExitCount;
    unsigned long nestedState;
    unsigned short evmcsVersion;
    unsigned short reserved;
} KSWORD_ARK_HVM_CPU_ROW;

typedef struct _KSWORD_ARK_QUERY_HVM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_HVM_REQUEST;

typedef struct _KSWORD_ARK_QUERY_HVM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long queryStatus;
    unsigned long stateFlags;
    unsigned long generation;
    unsigned long processorCount;
    unsigned long preparedProcessorCount;
    unsigned long selfTestPassedProcessorCount;
    unsigned long residentProcessorCount;
    unsigned long residentImplementation;
    unsigned long eptImplementation;
    unsigned long nestedImplementation;
    unsigned long evmcsImplementation;
    unsigned long eptRuleCount;
    unsigned long eventCount;
    unsigned long droppedEventCount;
    unsigned long nestedState;
    unsigned long evmcsState;
    unsigned short evmcsVersion;
    unsigned short reservedVersion;
    unsigned long evmcsFlags;
    unsigned long reservedEvmcs;
    unsigned long long evmcsVpAssistMsr;
    unsigned long eptPageCount;
    unsigned long eptPml4Entries;
    unsigned long eptPdptEntries;
    unsigned long eptLargePageEntries;
    unsigned long long featureFlags;
    unsigned long long vmxBasic;
    unsigned long long vmxEptVpidCapabilities;
    unsigned long long featureControl;
    unsigned long long cr0Fixed0;
    unsigned long long cr0Fixed1;
    unsigned long long cr4Fixed0;
    unsigned long long cr4Fixed1;
    unsigned long long eptPointer;
    unsigned long long mappedRamBytes;
    unsigned long long highestMappedPhysicalAddress;
    unsigned long long vmExitCount;
    unsigned long long lastExitQualification;
    unsigned long long lastGuestRip;
    unsigned long long lastGuestRsp;
    unsigned long lastExitReason;
    unsigned long lastExitInstructionLength;
    unsigned long lastVmInstructionError;
    unsigned short lastLaunchProcessorGroup;
    unsigned char lastLaunchProcessorNumber;
    unsigned char lastLaunchWasNested;
    long lastStatus;
    unsigned long reserved;
    char cpuVendor[KSWORD_ARK_HVM_VENDOR_CHARS];
    char hypervisorVendor[KSWORD_ARK_HVM_HYPERVISOR_VENDOR_CHARS];
    KSWORD_ARK_HVM_CPU_ROW processors[KSWORD_ARK_HVM_MAX_PROCESSORS];
} KSWORD_ARK_QUERY_HVM_RESPONSE;

typedef struct _KSWORD_ARK_CONTROL_HVM_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long command;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    /* Requested soak window in milliseconds; only SOAK reads this field. */
    unsigned long soakMilliseconds;
    unsigned long reserved;
} KSWORD_ARK_CONTROL_HVM_REQUEST;

typedef struct _KSWORD_ARK_CONTROL_HVM_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long oldStateFlags;
    unsigned long newStateFlags;
    unsigned long oldGeneration;
    unsigned long newGeneration;
    unsigned long preparedProcessorCount;
    unsigned long selfTestPassedProcessorCount;
    unsigned long failedProcessorCount;
    unsigned long residentProcessorCount;
    unsigned long residentImplementation;
    unsigned long eptImplementation;
    unsigned long nestedImplementation;
    unsigned long evmcsImplementation;
    unsigned long eptRuleCount;
    unsigned long eventCount;
    unsigned long eptPageCount;
    unsigned long lastExitReason;
    unsigned long long eptPointer;
    unsigned long long mappedRamBytes;
    unsigned long long vmExitCount;
    unsigned long long lastExitQualification;
    unsigned long long lastGuestRip;
    unsigned long long lastGuestRsp;
    unsigned long lastExitInstructionLength;
    unsigned long lastVmInstructionError;
    unsigned short launchProcessorGroup;
    unsigned char launchProcessorNumber;
    unsigned char launchWasNested;
    long lastStatus;
    unsigned long reserved2;
    /* Milliseconds residency actually held during the last soak. */
    unsigned long soakElapsedMilliseconds;
    /*
     * Processors that left VMX non-root on their own during the soak.  Any
     * nonzero value means an exit reason reached the fail-closed path, so the
     * soak did not prove sustained residency.
     */
    unsigned long soakUnexpectedDevirtualizations;
} KSWORD_ARK_CONTROL_HVM_RESPONSE;

typedef struct _KSWORD_ARK_HVM_EPT_RULE_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long expectedGeneration;
    unsigned long ruleId;
    /*
     * EPT permissions removed while resident.  This is a tripwire mask, not a
     * durable access-control guarantee: a strict hit records and devirtualizes
     * without injecting an exception, so the same native access may retry and
     * succeed after VMXOFF.  Removing READ also removes WRITE; when execute-only
     * EPT is unsupported it removes EXECUTE as well.
     */
    unsigned long deniedAccess;
    unsigned long long physicalAddress;
    unsigned long long pageCount;
} KSWORD_ARK_HVM_EPT_RULE_REQUEST;

typedef struct _KSWORD_ARK_HVM_EPT_RULE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long ruleId;
    unsigned long ruleCount;
    unsigned long generation;
    unsigned long implementation;
    /* Effective tripwire mask after architectural permission normalization. */
    unsigned long deniedAccess;
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long long pageCount;
    long lastStatus;
    unsigned long reserved2;
} KSWORD_ARK_HVM_EPT_RULE_RESPONSE;

typedef struct _KSWORD_ARK_HVM_EVENT_ROW
{
    unsigned long long sequence;
    unsigned long long timestamp;
    unsigned long long guestPhysicalAddress;
    unsigned long long guestLinearAddress;
    unsigned long long guestRip;
    unsigned long long qualification;
    unsigned short processorGroup;
    unsigned char processorNumber;
    unsigned char reserved0;
    unsigned long type;
    unsigned long exitReason;
    unsigned long access;
    unsigned long ruleId;
    long status;
    unsigned long reserved1;
} KSWORD_ARK_HVM_EVENT_ROW;

typedef struct _KSWORD_ARK_HVM_EVENT_QUERY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long maxRows;
    unsigned long long afterSequence;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_HVM_EVENT_QUERY_REQUEST;

typedef struct _KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long returnedRows;
    unsigned long availableRows;
    /* Rows overwritten or unavailable in this nonblocking sequence snapshot. */
    unsigned long droppedRows;
    unsigned long reserved;
    unsigned long long newestSequence;
    KSWORD_ARK_HVM_EVENT_ROW rows[KSWORD_ARK_HVM_MAX_EVENT_ROWS];
} KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE;

/*
 * Ring -1 memory access.
 *
 * The point of this interface is not that it can read memory - the kernel can
 * already do that - but that it reaches memory without calling the documented
 * memory-manager routines an attacker or a competing product may have hooked.
 * It rewrites a private page-table entry and reads through its own window.
 *
 * When the self-map discovery that window depends on fails, the driver falls
 * back to MmCopyMemory and says so in usedDirectWindow, so a caller can always
 * tell whether the hook-free path was actually taken.
 */
#define KSWORD_ARK_HVM_MEMORY_PROTOCOL_VERSION 1UL

/* Bound one transfer so METHOD_BUFFERED request snapshots stay small. */
#define KSWORD_ARK_HVM_MEMORY_MAX_BYTES 1024UL

#define KSWORD_ARK_HVM_MEMORY_OP_READ_PHYSICAL  1UL
#define KSWORD_ARK_HVM_MEMORY_OP_WRITE_PHYSICAL 2UL
#define KSWORD_ARK_HVM_MEMORY_OP_READ_VIRTUAL   3UL
#define KSWORD_ARK_HVM_MEMORY_OP_WRITE_VIRTUAL  4UL
#define KSWORD_ARK_HVM_MEMORY_OP_TRANSLATE      5UL
/* Report whether the private window is available without touching memory. */
#define KSWORD_ARK_HVM_MEMORY_OP_QUERY_WINDOW   6UL

#define KSWORD_ARK_HVM_MEMORY_FLAG_UI_CONFIRMED 0x00000001UL
/* Refuse the request outright when the private window is unavailable. */
#define KSWORD_ARK_HVM_MEMORY_FLAG_REQUIRE_WINDOW 0x00000002UL

/* Reuse the HVM control token so one confirmation vocabulary covers the area. */
#define KSWORD_ARK_HVM_MEMORY_CONFIRMATION_TOKEN 0x48564D43UL

#define KSWORD_ARK_HVM_MEMORY_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_WINDOW_UNAVAILABLE    3UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_ADDRESS_INVALID       4UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_TRANSLATION_FAILED    5UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_ACCESS_FAILED         6UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_PARTIAL               7UL
#define KSWORD_ARK_HVM_MEMORY_STATUS_BUSY                  8UL

typedef struct _KSWORD_ARK_HVM_MEMORY_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long length;
    /* Physical address for physical operations, virtual for the rest. */
    unsigned long long address;
    /*
     * Target page-directory base for virtual operations.  Zero means the
     * address is resolved through the page tables of the current process.
     */
    unsigned long long directoryBase;
    unsigned char data[KSWORD_ARK_HVM_MEMORY_MAX_BYTES];
} KSWORD_ARK_HVM_MEMORY_REQUEST;

typedef struct _KSWORD_ARK_HVM_MEMORY_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long bytesTransferred;
    /* Physical address the access actually resolved to. */
    unsigned long long physicalAddress;
    /* Nonzero when the private page-table window carried the access. */
    unsigned char usedDirectWindow;
    /* Nonzero when the private window exists at all on this system. */
    unsigned char windowReady;
    unsigned short reserved0;
    long ntStatus;
    unsigned char data[KSWORD_ARK_HVM_MEMORY_MAX_BYTES];
} KSWORD_ARK_HVM_MEMORY_RESPONSE;

/*
 * EPT split views: one guest-physical page backed by two different frames
 * depending on how it is accessed.
 *
 * CLOAK backs execution with the real page and every read or write with a
 * shadow, so code keeps running while memory scanners see whatever the shadow
 * holds.  HOOK is the mirror image: reads and writes see the real page while
 * execution is redirected into a shadow that carries the patched instructions,
 * which is a breakpoint no byte comparison can find.
 *
 * Both are implemented by flipping the shared EPT leaf on violation and
 * restoring it on the following monitor-trap exit, exactly like an allow-once
 * rule.  That makes them subject to the same constraint: the leaf is shared by
 * every processor, so a view is only safe while exactly one VCPU is resident.
 * Multi-processor views need per-processor EPT hierarchies, which this
 * protocol version does not provide.
 */
#define KSWORD_ARK_HVM_VIEW_PROTOCOL_VERSION 1UL

/* Bound the number of simultaneously installed views. */
#define KSWORD_ARK_HVM_MAX_VIEWS 32UL
/* One view covers exactly one four-KiB page, which is the shadow's size. */
#define KSWORD_ARK_HVM_VIEW_PAGE_BYTES 4096UL

#define KSWORD_ARK_IOCTL_FUNCTION_HVM_VIEW 0x8BBUL
#define IOCTL_KSWORD_ARK_HVM_VIEW \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_VIEW, METHOD_BUFFERED, FILE_WRITE_ACCESS)

#define KSWORD_ARK_HVM_VIEW_OP_ADD    1UL
#define KSWORD_ARK_HVM_VIEW_OP_REMOVE 2UL
#define KSWORD_ARK_HVM_VIEW_OP_CLEAR  3UL
#define KSWORD_ARK_HVM_VIEW_OP_QUERY  4UL

/* Execution sees the real page; reads and writes see the shadow. */
#define KSWORD_ARK_HVM_VIEW_KIND_CLOAK 1UL
/* Reads and writes see the real page; execution runs from the shadow. */
#define KSWORD_ARK_HVM_VIEW_KIND_HOOK  2UL

#define KSWORD_ARK_HVM_VIEW_FLAG_UI_CONFIRMED 0x00000001UL
/* Seed the shadow from the target page instead of the supplied bytes. */
#define KSWORD_ARK_HVM_VIEW_FLAG_SEED_FROM_TARGET 0x00000002UL
/* Seed the shadow with zeroes instead of the supplied bytes. */
#define KSWORD_ARK_HVM_VIEW_FLAG_SEED_ZERO 0x00000004UL
/* Record every view flip in the HVM event ring. */
#define KSWORD_ARK_HVM_VIEW_FLAG_LOG 0x00000008UL

#define KSWORD_ARK_HVM_VIEW_STATUS_OK                    0UL
#define KSWORD_ARK_HVM_VIEW_STATUS_INVALID_REQUEST       1UL
#define KSWORD_ARK_HVM_VIEW_STATUS_CONFIRMATION_REQUIRED 2UL
#define KSWORD_ARK_HVM_VIEW_STATUS_NOT_PREPARED          3UL
#define KSWORD_ARK_HVM_VIEW_STATUS_NOT_FOUND             4UL
#define KSWORD_ARK_HVM_VIEW_STATUS_TABLE_FULL            5UL
#define KSWORD_ARK_HVM_VIEW_STATUS_SPLIT_FAILED          6UL
/* The page already carries a view or an EPT rule; they cannot share a leaf. */
#define KSWORD_ARK_HVM_VIEW_STATUS_LEAF_CONFLICT         7UL
/* CLOAK needs execute-only EPT leaves, which this processor cannot encode. */
#define KSWORD_ARK_HVM_VIEW_STATUS_EXECUTE_ONLY_UNSUPPORTED 8UL
/* Views flip the shared leaf, so more than one resident VCPU is refused. */
#define KSWORD_ARK_HVM_VIEW_STATUS_MULTIPROCESSOR_UNSAFE 9UL
#define KSWORD_ARK_HVM_VIEW_STATUS_RESOURCE_FAILED       10UL

typedef struct _KSWORD_ARK_HVM_VIEW_ROW
{
    unsigned long viewId;
    unsigned long kind;
    unsigned long flags;
    unsigned long reserved;
    unsigned long long physicalAddress;
    unsigned long long shadowPhysicalAddress;
    /* Times the leaf flipped to the secondary view since installation. */
    unsigned long long flipCount;
} KSWORD_ARK_HVM_VIEW_ROW;

typedef struct _KSWORD_ARK_HVM_VIEW_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long operation;
    unsigned long kind;
    unsigned long flags;
    unsigned long confirmationToken;
    unsigned long viewId;
    unsigned long expectedGeneration;
    unsigned long long physicalAddress;
    unsigned char shadow[KSWORD_ARK_HVM_VIEW_PAGE_BYTES];
} KSWORD_ARK_HVM_VIEW_REQUEST;

typedef struct _KSWORD_ARK_HVM_VIEW_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long viewId;
    unsigned long viewCount;
    unsigned long generation;
    unsigned long returnedRows;
    unsigned long reserved;
    long lastStatus;
    unsigned long reserved2;
    KSWORD_ARK_HVM_VIEW_ROW rows[KSWORD_ARK_HVM_MAX_VIEWS];
} KSWORD_ARK_HVM_VIEW_RESPONSE;
