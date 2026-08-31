#pragma once

#include "KswordArkProcessIoctl.h"

/*
 * The HVM protocol separates capability discovery from implementation state.
 * A capability-only or partial result must never be interpreted as a resident
 * hypervisor.  ACTIVE is published only after every selected processor has
 * entered VMX non-root operation and the rollback rendezvous is available.
 */
#define KSWORD_ARK_HVM_PROTOCOL_VERSION 3UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM   0x8CAUL
#define KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM 0x8CBUL
// 0x8CC-0x8CD are occupied by driver-dispatch and SLAT/IOMMU on main.
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE 0x8B8UL
#define KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS   0x8B9UL

#define IOCTL_KSWORD_ARK_QUERY_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_QUERY_HVM, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KSWORD_ARK_CONTROL_HVM \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_CONTROL_HVM, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EPT_RULE \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EPT_RULE, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define IOCTL_KSWORD_ARK_HVM_EVENTS \
    CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, KSWORD_ARK_IOCTL_FUNCTION_HVM_EVENTS, METHOD_BUFFERED, FILE_WRITE_ACCESS)

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
    unsigned long reserved[2];
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
