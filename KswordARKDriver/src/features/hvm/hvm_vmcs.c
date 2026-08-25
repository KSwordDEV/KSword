/*++

Module Name:

    hvm_vmcs.c

Abstract:

    Builds one long-mode VMCS from the current processor state and captures
    deterministic VM-exit telemetry for the controlled one-shot guest.

Environment:

    Kernel-mode Driver Framework.

--*/

#include "hvm_vmcs.h"

#if defined(_M_AMD64)
#include <intrin.h>

#define KSW_IA32_SYSENTER_CS  0x174UL
#define KSW_IA32_SYSENTER_ESP 0x175UL
#define KSW_IA32_SYSENTER_EIP 0x176UL
#define KSW_IA32_DEBUGCTL     0x1D9UL
#define KSW_IA32_PAT          0x277UL
#define KSW_IA32_S_CET        0x6A2UL
#define KSW_IA32_INTERRUPT_SSP_TABLE 0x6A8UL
#define KSW_IA32_PKRS         0x6E1UL
#define KSW_IA32_UINTR_MISC   0x988UL
#define KSW_IA32_FRED_RSP1    0x1CDUL
#define KSW_IA32_FRED_RSP2    0x1CEUL
#define KSW_IA32_FRED_RSP3    0x1CFUL
#define KSW_IA32_FRED_STKLVLS 0x1D0UL
#define KSW_IA32_FRED_SSP1    0x1D1UL
#define KSW_IA32_FRED_SSP2    0x1D2UL
#define KSW_IA32_FRED_SSP3    0x1D3UL
#define KSW_IA32_FRED_CONFIG  0x1D4UL
#define KSW_IA32_FS_BASE      0xC0000100UL
#define KSW_IA32_GS_BASE      0xC0000101UL
#define KSW_IA32_EFER         0xC0000080UL

#define KSW_IA32_VMX_PINBASED_CTLS      0x481UL
#define KSW_IA32_VMX_PROCBASED_CTLS     0x482UL
#define KSW_IA32_VMX_EXIT_CTLS          0x483UL
#define KSW_IA32_VMX_ENTRY_CTLS         0x484UL
#define KSW_IA32_VMX_PROCBASED_CTLS2    0x48BUL
#define KSW_IA32_VMX_TRUE_PINBASED_CTLS 0x48DUL
#define KSW_IA32_VMX_TRUE_PROCBASED_CTLS 0x48EUL
#define KSW_IA32_VMX_TRUE_EXIT_CTLS     0x48FUL
#define KSW_IA32_VMX_TRUE_ENTRY_CTLS    0x490UL
#define KSW_IA32_VMX_EXIT_CTLS2         0x493UL

#define KSW_VMX_BASIC_TRUE_CONTROLS (1ULL << 55)
#define KSW_VMX_PRIMARY_HLT_EXITING (1UL << 7)
#define KSW_VMX_PRIMARY_SECONDARY_CONTROLS (1UL << 31)
#define KSW_VMX_SECONDARY_EPT (1UL << 1)
#define KSW_VMX_SECONDARY_RDTSCP (1UL << 3)
#define KSW_VMX_SECONDARY_INVPCID (1UL << 12)
#define KSW_VMX_SECONDARY_XSAVES (1UL << 20)
#define KSW_VMX_SECONDARY_USER_WAIT (1UL << 26)
#define KSW_VMX_SECONDARY_PCONFIG (1UL << 27)
#define KSW_VMX_EXIT_SAVE_DEBUG_CONTROLS (1UL << 2)
#define KSW_VMX_EXIT_HOST_64_BIT (1UL << 9)
#define KSW_VMX_EXIT_SAVE_PAT (1UL << 18)
#define KSW_VMX_EXIT_LOAD_PAT (1UL << 19)
#define KSW_VMX_EXIT_SAVE_EFER (1UL << 20)
#define KSW_VMX_EXIT_LOAD_EFER (1UL << 21)
#define KSW_VMX_EXIT_CLEAR_UINV (1UL << 27)
#define KSW_VMX_EXIT_LOAD_CET (1UL << 28)
#define KSW_VMX_EXIT_LOAD_PKRS (1UL << 29)
#define KSW_VMX_EXIT_SECONDARY_CONTROLS (1UL << 31)
#define KSW_VMX_SECONDARY_EXIT_SAVE_FRED (1ULL << 0)
#define KSW_VMX_SECONDARY_EXIT_LOAD_FRED (1ULL << 1)
#define KSW_VMX_ENTRY_LOAD_DEBUG_CONTROLS (1UL << 2)
#define KSW_VMX_ENTRY_IA32E_GUEST (1UL << 9)
#define KSW_VMX_ENTRY_LOAD_PAT (1UL << 14)
#define KSW_VMX_ENTRY_LOAD_EFER (1UL << 15)
#define KSW_VMX_ENTRY_LOAD_UINV (1UL << 19)
#define KSW_VMX_ENTRY_LOAD_CET (1UL << 20)
#define KSW_VMX_ENTRY_LOAD_PKRS (1UL << 22)
#define KSW_VMX_ENTRY_LOAD_FRED (1UL << 23)
#define KSW_CR4_CET (1ULL << 23)
#define KSW_CR4_PKS (1ULL << 24)
#define KSW_CR4_UINTR (1ULL << 25)
#define KSW_CR4_FRED (1ULL << 32)
#define KSW_CET_SHADOW_STACK_ENABLED (1ULL << 0)
#define KSW_VMX_SEGMENT_UNUSABLE (1UL << 16)

#define KSW_VMCS_GUEST_ES_SELECTOR 0x0800UL
#define KSW_VMCS_GUEST_CS_SELECTOR 0x0802UL
#define KSW_VMCS_GUEST_SS_SELECTOR 0x0804UL
#define KSW_VMCS_GUEST_DS_SELECTOR 0x0806UL
#define KSW_VMCS_GUEST_FS_SELECTOR 0x0808UL
#define KSW_VMCS_GUEST_GS_SELECTOR 0x080AUL
#define KSW_VMCS_GUEST_LDTR_SELECTOR 0x080CUL
#define KSW_VMCS_GUEST_TR_SELECTOR 0x080EUL
#define KSW_VMCS_HOST_ES_SELECTOR 0x0C00UL
#define KSW_VMCS_HOST_CS_SELECTOR 0x0C02UL
#define KSW_VMCS_HOST_SS_SELECTOR 0x0C04UL
#define KSW_VMCS_HOST_DS_SELECTOR 0x0C06UL
#define KSW_VMCS_HOST_FS_SELECTOR 0x0C08UL
#define KSW_VMCS_HOST_GS_SELECTOR 0x0C0AUL
#define KSW_VMCS_HOST_TR_SELECTOR 0x0C0CUL
#define KSW_VMCS_GUEST_UINV 0x0814UL

#define KSW_VMCS_XSS_EXITING_BITMAP 0x202CUL
#define KSW_VMCS_PCONFIG_EXITING_BITMAP 0x203EUL
#define KSW_VMCS_SECONDARY_EXIT_CONTROLS 0x2044UL
#define KSW_VMCS_INJECTED_EVENT_DATA 0x2052UL
#define KSW_VMCS_EPT_POINTER 0x201AUL
#define KSW_VMCS_GUEST_LINK_POINTER 0x2800UL
#define KSW_VMCS_GUEST_DEBUGCTL 0x2802UL
#define KSW_VMCS_GUEST_PAT 0x2804UL
#define KSW_VMCS_GUEST_EFER 0x2806UL
#define KSW_VMCS_GUEST_PKRS 0x2818UL
#define KSW_VMCS_GUEST_FRED_CONFIG 0x281AUL
#define KSW_VMCS_GUEST_FRED_RSP1 0x281CUL
#define KSW_VMCS_GUEST_FRED_RSP2 0x281EUL
#define KSW_VMCS_GUEST_FRED_RSP3 0x2820UL
#define KSW_VMCS_GUEST_FRED_STKLVLS 0x2822UL
#define KSW_VMCS_GUEST_FRED_SSP1 0x2824UL
#define KSW_VMCS_GUEST_FRED_SSP2 0x2826UL
#define KSW_VMCS_GUEST_FRED_SSP3 0x2828UL
#define KSW_VMCS_HOST_PAT 0x2C00UL
#define KSW_VMCS_HOST_EFER 0x2C02UL
#define KSW_VMCS_HOST_PKRS 0x2C06UL
#define KSW_VMCS_HOST_FRED_CONFIG 0x2C08UL
#define KSW_VMCS_HOST_FRED_RSP1 0x2C0AUL
#define KSW_VMCS_HOST_FRED_RSP2 0x2C0CUL
#define KSW_VMCS_HOST_FRED_RSP3 0x2C0EUL
#define KSW_VMCS_HOST_FRED_STKLVLS 0x2C10UL
#define KSW_VMCS_HOST_FRED_SSP1 0x2C12UL
#define KSW_VMCS_HOST_FRED_SSP2 0x2C14UL
#define KSW_VMCS_HOST_FRED_SSP3 0x2C16UL

#define KSW_VMCS_PIN_CONTROLS 0x4000UL
#define KSW_VMCS_PRIMARY_CONTROLS 0x4002UL
#define KSW_VMCS_EXCEPTION_BITMAP 0x4004UL
#define KSW_VMCS_PAGE_FAULT_MASK 0x4006UL
#define KSW_VMCS_PAGE_FAULT_MATCH 0x4008UL
#define KSW_VMCS_CR3_TARGET_COUNT 0x400AUL
#define KSW_VMCS_EXIT_CONTROLS 0x400CUL
#define KSW_VMCS_EXIT_MSR_STORE_COUNT 0x400EUL
#define KSW_VMCS_EXIT_MSR_LOAD_COUNT 0x4010UL
#define KSW_VMCS_ENTRY_CONTROLS 0x4012UL
#define KSW_VMCS_ENTRY_MSR_LOAD_COUNT 0x4014UL
#define KSW_VMCS_ENTRY_INTERRUPTION_INFO 0x4016UL
#define KSW_VMCS_ENTRY_EXCEPTION_ERROR 0x4018UL
#define KSW_VMCS_ENTRY_INSTRUCTION_LENGTH 0x401AUL
#define KSW_VMCS_TPR_THRESHOLD 0x401CUL
#define KSW_VMCS_SECONDARY_CONTROLS 0x401EUL

#define KSW_VMCS_INSTRUCTION_ERROR 0x4400UL
#define KSW_VMCS_EXIT_REASON 0x4402UL
#define KSW_VMCS_EXIT_INSTRUCTION_LENGTH 0x440CUL

#define KSW_VMCS_GUEST_ES_LIMIT 0x4800UL
#define KSW_VMCS_GUEST_CS_LIMIT 0x4802UL
#define KSW_VMCS_GUEST_SS_LIMIT 0x4804UL
#define KSW_VMCS_GUEST_DS_LIMIT 0x4806UL
#define KSW_VMCS_GUEST_FS_LIMIT 0x4808UL
#define KSW_VMCS_GUEST_GS_LIMIT 0x480AUL
#define KSW_VMCS_GUEST_LDTR_LIMIT 0x480CUL
#define KSW_VMCS_GUEST_TR_LIMIT 0x480EUL
#define KSW_VMCS_GUEST_GDTR_LIMIT 0x4810UL
#define KSW_VMCS_GUEST_IDTR_LIMIT 0x4812UL
#define KSW_VMCS_GUEST_ES_ACCESS 0x4814UL
#define KSW_VMCS_GUEST_CS_ACCESS 0x4816UL
#define KSW_VMCS_GUEST_SS_ACCESS 0x4818UL
#define KSW_VMCS_GUEST_DS_ACCESS 0x481AUL
#define KSW_VMCS_GUEST_FS_ACCESS 0x481CUL
#define KSW_VMCS_GUEST_GS_ACCESS 0x481EUL
#define KSW_VMCS_GUEST_LDTR_ACCESS 0x4820UL
#define KSW_VMCS_GUEST_TR_ACCESS 0x4822UL
#define KSW_VMCS_GUEST_INTERRUPTIBILITY 0x4824UL
#define KSW_VMCS_GUEST_ACTIVITY 0x4826UL
#define KSW_VMCS_GUEST_SMBASE 0x4828UL
#define KSW_VMCS_GUEST_SYSENTER_CS 0x482AUL
#define KSW_VMCS_HOST_SYSENTER_CS 0x4C00UL

#define KSW_VMCS_CR0_MASK 0x6000UL
#define KSW_VMCS_CR4_MASK 0x6002UL
#define KSW_VMCS_CR0_SHADOW 0x6004UL
#define KSW_VMCS_CR4_SHADOW 0x6006UL
#define KSW_VMCS_EXIT_QUALIFICATION 0x6400UL

#define KSW_VMCS_GUEST_CR0 0x6800UL
#define KSW_VMCS_GUEST_CR3 0x6802UL
#define KSW_VMCS_GUEST_CR4 0x6804UL
#define KSW_VMCS_GUEST_ES_BASE 0x6806UL
#define KSW_VMCS_GUEST_CS_BASE 0x6808UL
#define KSW_VMCS_GUEST_SS_BASE 0x680AUL
#define KSW_VMCS_GUEST_DS_BASE 0x680CUL
#define KSW_VMCS_GUEST_FS_BASE 0x680EUL
#define KSW_VMCS_GUEST_GS_BASE 0x6810UL
#define KSW_VMCS_GUEST_LDTR_BASE 0x6812UL
#define KSW_VMCS_GUEST_TR_BASE 0x6814UL
#define KSW_VMCS_GUEST_GDTR_BASE 0x6816UL
#define KSW_VMCS_GUEST_IDTR_BASE 0x6818UL
#define KSW_VMCS_GUEST_DR7 0x681AUL
#define KSW_VMCS_GUEST_RSP 0x681CUL
#define KSW_VMCS_GUEST_RIP 0x681EUL
#define KSW_VMCS_GUEST_RFLAGS 0x6820UL
#define KSW_VMCS_GUEST_PENDING_DEBUG 0x6822UL
#define KSW_VMCS_GUEST_SYSENTER_ESP 0x6824UL
#define KSW_VMCS_GUEST_SYSENTER_EIP 0x6826UL
#define KSW_VMCS_GUEST_S_CET 0x6828UL
#define KSW_VMCS_GUEST_SSP 0x682AUL
#define KSW_VMCS_GUEST_INTERRUPT_SSP_TABLE 0x682CUL

#define KSW_VMCS_HOST_CR0 0x6C00UL
#define KSW_VMCS_HOST_CR3 0x6C02UL
#define KSW_VMCS_HOST_CR4 0x6C04UL
#define KSW_VMCS_HOST_FS_BASE 0x6C06UL
#define KSW_VMCS_HOST_GS_BASE 0x6C08UL
#define KSW_VMCS_HOST_TR_BASE 0x6C0AUL
#define KSW_VMCS_HOST_GDTR_BASE 0x6C0CUL
#define KSW_VMCS_HOST_IDTR_BASE 0x6C0EUL
#define KSW_VMCS_HOST_SYSENTER_ESP 0x6C10UL
#define KSW_VMCS_HOST_SYSENTER_EIP 0x6C12UL
#define KSW_VMCS_HOST_RSP 0x6C14UL
#define KSW_VMCS_HOST_RIP 0x6C16UL
#define KSW_VMCS_HOST_S_CET 0x6C18UL
#define KSW_VMCS_HOST_SSP 0x6C1AUL
#define KSW_VMCS_HOST_INTERRUPT_SSP_TABLE 0x6C1CUL

typedef struct _KSW_HVM_SEGMENT_STATE
{
    USHORT Selector;
    ULONG Limit;
    ULONG AccessRights;
    ULONGLONG Base;
} KSW_HVM_SEGMENT_STATE;

typedef struct _KSW_HVM_VMCS_WRITE
{
    SIZE_T Field;
    SIZE_T Value;
} KSW_HVM_VMCS_WRITE;

/* Keep every assembly-written segment snapshot offset compile-time checked. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Gdtr) == 0);
/* Keep the packed IDTR offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Idtr) == 10);
/* Keep the packed ES offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Es) == 20);
/* Keep the packed CS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Cs) == 22);
/* Keep the packed SS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Ss) == 24);
/* Keep the packed DS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Ds) == 26);
/* Keep the packed FS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Fs) == 28);
/* Keep the packed GS offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Gs) == 30);
/* Keep the packed LDTR offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Ldtr) == 32);
/* Keep the packed TR offset synchronized with hvm_entry.asm. */
C_ASSERT(FIELD_OFFSET(KSW_HVM_SEGMENT_SNAPSHOT, Tr) == 34);

static ULONG
KswordARKHvmAdjustControls(
    _In_ ULONG Desired,
    _In_ ULONGLONG Capability
    )
{
    ULONG mustBeOne = 0UL;
    ULONG mayBeOne = 0UL;

    /* Decode the low required-one mask from the control capability MSR. */
    mustBeOne = (ULONG)(Capability & 0xFFFFFFFFULL);
    /* Decode the high allowed-one mask from the same capability MSR. */
    mayBeOne = (ULONG)(Capability >> 32);
    /* Preserve required bits and clear every unsupported requested bit. */
    return (Desired | mustBeOne) & mayBeOne;
}

static NTSTATUS
KswordARKHvmReadSegment(
    _In_ const KSW_HVM_SEGMENT_SNAPSHOT* Snapshot,
    _In_ USHORT Selector,
    _Out_ KSW_HVM_SEGMENT_STATE* Segment
    )
{
    const UCHAR* table = NULL;
    ULONG tableLimit = 0UL;
    ULONG descriptorOffset = 0UL;
    UCHAR descriptor[16] = { 0 };
    ULONG rawLimit = 0UL;
    ULONGLONG rawBase = 0ULL;

    /* Validate both fixed arguments before dereferencing descriptor memory. */
    if (Snapshot == NULL || Segment == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Publish a deterministic unusable descriptor for a null selector. */
    RtlZeroMemory(Segment, sizeof(*Segment));
    /* Preserve the selector exactly as captured for guest-state programming. */
    Segment->Selector = Selector;
    /* Mark null segments unusable as required by VM-entry validation. */
    if ((Selector & 0xFFF8U) == 0U) {
        Segment->AccessRights = KSW_VMX_SEGMENT_UNUSABLE;
        return STATUS_SUCCESS;
    }

    /* Use the GDT for ordinary kernel selectors. */
    if ((Selector & 0x4U) == 0U) {
        table = (const UCHAR*)(ULONG_PTR)Snapshot->Gdtr.Base;
        tableLimit = Snapshot->Gdtr.Limit;
    } else {
        KSW_HVM_SEGMENT_STATE ldt = { 0 };

        /* Reject a recursive LDT lookup when no LDTR is active. */
        if ((Snapshot->Ldtr & 0xFFF8U) == 0U ||
            (Snapshot->Ldtr & 0x4U) != 0U) {
            return STATUS_INVALID_PARAMETER;
        }
        /* Resolve the LDT system descriptor from the GDT first. */
        if (!NT_SUCCESS(KswordARKHvmReadSegment(
                Snapshot,
                Snapshot->Ldtr,
                &ldt))) {
            return STATUS_INVALID_PARAMETER;
        }
        /* Use the resolved LDT base and limit for the target descriptor. */
        table = (const UCHAR*)(ULONG_PTR)ldt.Base;
        tableLimit = ldt.Limit;
    }

    /* Convert the selector index into an eight-byte descriptor offset. */
    descriptorOffset = (ULONG)(Selector & 0xFFF8U);
    /* Require a complete legacy descriptor within the selected table. */
    if (table == NULL ||
        descriptorOffset > tableLimit ||
        tableLimit - descriptorOffset < 7UL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Copy the descriptor through a guarded access because GDT/LDT is dynamic. */
    __try {
        RtlCopyMemory(descriptor, table + descriptorOffset, 8U);
        /* System descriptors carry the high base dword in the next slot. */
        if ((descriptor[5] & 0x10U) == 0U &&
            tableLimit - descriptorOffset >= 15UL) {
            RtlCopyMemory(descriptor + 8, table + descriptorOffset + 8UL, 8U);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
    /* Require the complete high-base slot for every active system descriptor. */
    if ((descriptor[5] & 0x10U) == 0U &&
        tableLimit - descriptorOffset < 15UL) {
        return STATUS_INVALID_PARAMETER;
    }

    /* Decode the 20-bit descriptor limit. */
    rawLimit =
        (ULONG)descriptor[0] |
        ((ULONG)descriptor[1] << 8) |
        ((ULONG)(descriptor[6] & 0x0FU) << 16);
    /* Expand page-granular limits to their inclusive byte limit. */
    if ((descriptor[6] & 0x80U) != 0U) {
        rawLimit = (rawLimit << 12) | 0xFFFUL;
    }
    /* Decode the low 32 bits of the descriptor base. */
    rawBase =
        ((ULONGLONG)descriptor[2]) |
        ((ULONGLONG)descriptor[3] << 8) |
        ((ULONGLONG)descriptor[4] << 16) |
        ((ULONGLONG)descriptor[7] << 24);
    /* Decode the high system-segment base when the descriptor owns it. */
    if ((descriptor[5] & 0x10U) == 0U) {
        rawBase |=
            ((ULONGLONG)descriptor[8]) << 32 |
            ((ULONGLONG)descriptor[9]) << 40 |
            ((ULONGLONG)descriptor[10]) << 48 |
            ((ULONGLONG)descriptor[11]) << 56;
    }
    /* Publish the normalized byte limit. */
    Segment->Limit = rawLimit;
    /* Publish the VMCS-format access-rights field. */
    Segment->AccessRights =
        (ULONG)descriptor[5] |
        ((ULONG)(descriptor[6] & 0xF0U) << 8);
    /* Publish the complete descriptor base. */
    Segment->Base = rawBase;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKHvmWriteVmcs(
    _In_reads_(WriteCount) const KSW_HVM_VMCS_WRITE* Writes,
    _In_ ULONG WriteCount,
    _Out_ ULONG* VmInstructionError
    )
{
    ULONG index = 0UL;

    /* Reject an invalid write ledger before invoking VMX instructions. */
    if (Writes == NULL || VmInstructionError == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Clear the diagnostic until an instruction reports a valid failure. */
    *VmInstructionError = 0UL;
    /* Apply each field in deterministic order and stop at the first failure. */
    for (index = 0UL; index < WriteCount; ++index) {
        UCHAR result = 0U;

        /* Write the encoded field through the compiler VMX intrinsic. */
        result = __vmx_vmwrite(Writes[index].Field, Writes[index].Value);
        /* Continue only when VMWRITE reports success. */
        if (result == 0U) {
            continue;
        }
        /* Read the extended VM-instruction error when VMfailValid is reported. */
        if (result == 1U) {
            SIZE_T instructionError = 0U;

            /* Preserve a readable VMCS error code when VMREAD succeeds. */
            if (__vmx_vmread(
                    (SIZE_T)KSW_VMCS_INSTRUCTION_ERROR,
                    &instructionError) == 0U) {
                *VmInstructionError = (ULONG)instructionError;
            }
        }
        return STATUS_HV_OPERATION_FAILED;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmConfigureVmcs(
    _In_ const KSW_HVM_VMCS_INPUT* Input,
    _Out_ ULONG* VmInstructionError
    )
{
    KSW_HVM_SEGMENT_SNAPSHOT snapshot = { 0 };
    KSW_HVM_SEGMENT_STATE es = { 0 };
    KSW_HVM_SEGMENT_STATE cs = { 0 };
    KSW_HVM_SEGMENT_STATE ss = { 0 };
    KSW_HVM_SEGMENT_STATE ds = { 0 };
    KSW_HVM_SEGMENT_STATE fs = { 0 };
    KSW_HVM_SEGMENT_STATE gs = { 0 };
    KSW_HVM_SEGMENT_STATE ldtr = { 0 };
    KSW_HVM_SEGMENT_STATE tr = { 0 };
    ULONGLONG pinCapability = 0ULL;
    ULONGLONG primaryCapability = 0ULL;
    ULONGLONG secondaryCapability = 0ULL;
    ULONGLONG exitCapability = 0ULL;
    ULONGLONG entryCapability = 0ULL;
    ULONGLONG secondaryExitCapability = 0ULL;
    ULONGLONG guestCr0 = 0ULL;
    ULONGLONG guestCr4 = 0ULL;
    ULONGLONG hardwareCr4 = 0ULL;
    ULONGLONG fsBase = 0ULL;
    ULONGLONG gsBase = 0ULL;
    ULONGLONG pat = 0ULL;
    ULONGLONG efer = 0ULL;
    ULONGLONG debugControl = 0ULL;
    ULONGLONG sysenterCs = 0ULL;
    ULONGLONG sysenterEsp = 0ULL;
    ULONGLONG sysenterEip = 0ULL;
    ULONGLONG nativeSCet = 0ULL;
    ULONGLONG nativeSsp = 0ULL;
    ULONGLONG nativeInterruptSspTable = 0ULL;
    ULONGLONG nativePkrs = 0ULL;
    ULONGLONG nativeUinv = 0ULL;
    ULONGLONG nativeFredConfig = 0ULL;
    ULONGLONG nativeFredRsp1 = 0ULL;
    ULONGLONG nativeFredRsp2 = 0ULL;
    ULONGLONG nativeFredRsp3 = 0ULL;
    ULONGLONG nativeFredStackLevels = 0ULL;
    ULONGLONG nativeFredSsp1 = 0ULL;
    ULONGLONG nativeFredSsp2 = 0ULL;
    ULONGLONG nativeFredSsp3 = 0ULL;
    ULONG pinControls = 0UL;
    ULONG primaryControls = 0UL;
    ULONG secondaryControls = 0UL;
    ULONG exitControls = 0UL;
    ULONG entryControls = 0UL;
    ULONG secondaryExitControls = 0UL;
    ULONG requiredInstructionControls = 0UL;
    ULONG maxBasicLeaf = 0UL;
    ULONG maxStructuredSubleaf = 0UL;
    ULONG maxExtendedLeaf = 0UL;
    int registers[4] = { 0 };
    BOOLEAN cetCpuSupported = FALSE;
    BOOLEAN pksCpuSupported = FALSE;
    BOOLEAN uintrCpuSupported = FALSE;
    BOOLEAN uintrXsaveSupported = FALSE;
    BOOLEAN fredCpuSupported = FALSE;
    BOOLEAN cetStateSupported = FALSE;
    BOOLEAN pkrsStateSupported = FALSE;
    BOOLEAN uinvStateSupported = FALSE;
    BOOLEAN fredStateSupported = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    /* Validate fixed inputs before reading processor state or MSRs. */
    if (Input == NULL || VmInstructionError == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Initialize the diagnostic before any fallible operation. */
    *VmInstructionError = 0UL;
    /* Capture descriptor tables and selectors on the launch processor. */
    KswordARKHvmCaptureSegments(&snapshot);
    /* Resolve every guest-visible segment from its active descriptor table. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Es, &es);
    /* Stop when the ES descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve CS after ES succeeds. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Cs, &cs);
    /* Stop when the CS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve SS after CS succeeds. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Ss, &ss);
    /* Stop when the SS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve DS after SS succeeds. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Ds, &ds);
    /* Stop when the DS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve FS after DS succeeds. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Fs, &fs);
    /* Stop when the FS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve GS after FS succeeds. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Gs, &gs);
    /* Stop when the GS descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve LDTR after ordinary data segments succeed. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Ldtr, &ldtr);
    /* Stop when an active LDTR descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }
    /* Resolve the mandatory task-register descriptor last. */
    status = KswordARKHvmReadSegment(&snapshot, snapshot.Tr, &tr);
    /* Stop when the task-register descriptor cannot be represented safely. */
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* 按当前处理器已经向 Windows 暴露的 CPUID 能力生成指令放行掩码。 */
    __cpuid(registers, 0);
    maxBasicLeaf = (ULONG)registers[0];
    if (maxBasicLeaf >= 7UL) {
        __cpuidex(registers, 7, 0);
        maxStructuredSubleaf = (ULONG)registers[0];
        if (((ULONG)registers[1] & (1UL << 10)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_INVPCID;
        }
        if (((ULONG)registers[2] & (1UL << 5)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_USER_WAIT;
        }
        if (((ULONG)registers[3] & (1UL << 18)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_PCONFIG;
        }
        cetCpuSupported =
            (((ULONG)registers[2] & (1UL << 7)) != 0UL) ||
            (((ULONG)registers[3] & (1UL << 20)) != 0UL);
        pksCpuSupported =
            ((ULONG)registers[2] & (1UL << 31)) != 0UL;
        uintrCpuSupported =
            ((ULONG)registers[3] & (1UL << 5)) != 0UL;
        if (maxStructuredSubleaf >= 1UL) {
            __cpuidex(registers, 7, 1);
            fredCpuSupported =
                ((ULONG)registers[0] & (1UL << 17)) != 0UL;
        }
    }
    if (maxBasicLeaf >= 0xDUL) {
        __cpuidex(registers, 0xD, 1);
        if (((ULONG)registers[0] & (1UL << 3)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_XSAVES;
        }
        uintrXsaveSupported =
            ((ULONG)registers[2] & (1UL << 14)) != 0UL;
    }
    __cpuid(registers, (int)0x80000000UL);
    maxExtendedLeaf = (ULONG)registers[0];
    if (maxExtendedLeaf >= 0x80000001UL) {
        __cpuid(registers, (int)0x80000001UL);
        if (((ULONG)registers[3] & (1UL << 27)) != 0UL) {
            requiredInstructionControls |= KSW_VMX_SECONDARY_RDTSCP;
        }
    }

    /* Read VMX controls and long-mode state under exception protection. */
    __try {
        /* Select true control MSRs when IA32_VMX_BASIC advertises them. */
        if ((Input->VmxBasic & KSW_VMX_BASIC_TRUE_CONTROLS) != 0ULL) {
            pinCapability = __readmsr(KSW_IA32_VMX_TRUE_PINBASED_CTLS);
            primaryCapability = __readmsr(KSW_IA32_VMX_TRUE_PROCBASED_CTLS);
            exitCapability = __readmsr(KSW_IA32_VMX_TRUE_EXIT_CTLS);
            entryCapability = __readmsr(KSW_IA32_VMX_TRUE_ENTRY_CTLS);
        } else {
            pinCapability = __readmsr(KSW_IA32_VMX_PINBASED_CTLS);
            primaryCapability = __readmsr(KSW_IA32_VMX_PROCBASED_CTLS);
            exitCapability = __readmsr(KSW_IA32_VMX_EXIT_CTLS);
            entryCapability = __readmsr(KSW_IA32_VMX_ENTRY_CTLS);
        }
        /* Read secondary controls independently of the true-control mode. */
        secondaryCapability = __readmsr(KSW_IA32_VMX_PROCBASED_CTLS2);
        /* 仅在主退出控制允许激活时读取二级 VM-exit 控制能力。 */
        if ((((ULONG)(exitCapability >> 32)) &
                KSW_VMX_EXIT_SECONDARY_CONTROLS) != 0UL) {
            secondaryExitCapability =
                __readmsr(KSW_IA32_VMX_EXIT_CTLS2);
        }
        /* Capture long-mode bases and model-specific guest/host state. */
        fsBase = __readmsr(KSW_IA32_FS_BASE);
        /* Capture the active kernel GS base. */
        gsBase = __readmsr(KSW_IA32_GS_BASE);
        /* Preserve PAT across the one-shot transition. */
        pat = __readmsr(KSW_IA32_PAT);
        /* Preserve EFER and its long-mode bits across the transition. */
        efer = __readmsr(KSW_IA32_EFER);
        /* 保存调试控制状态，供成对的 VM-entry/exit 控制字段使用。 */
        debugControl = __readmsr(KSW_IA32_DEBUGCTL);
        /* Preserve SYSENTER state for both guest and host. */
        sysenterCs = __readmsr(KSW_IA32_SYSENTER_CS);
        /* Preserve the SYSENTER stack pointer. */
        sysenterEsp = __readmsr(KSW_IA32_SYSENTER_ESP);
        /* Preserve the SYSENTER instruction pointer. */
        sysenterEip = __readmsr(KSW_IA32_SYSENTER_EIP);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    hardwareCr4 = __readcr4();
    cetStateSupported =
        cetCpuSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_LOAD_CET) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_CET) != 0UL);
    pkrsStateSupported =
        pksCpuSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_LOAD_PKRS) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_PKRS) != 0UL);
    uinvStateSupported =
        uintrCpuSupported &&
        uintrXsaveSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_CLEAR_UINV) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_UINV) != 0UL);
    fredStateSupported =
        fredCpuSupported &&
        ((((ULONG)(exitCapability >> 32)) &
            KSW_VMX_EXIT_SECONDARY_CONTROLS) != 0UL) &&
        ((((ULONG)(entryCapability >> 32)) &
            KSW_VMX_ENTRY_LOAD_FRED) != 0UL) &&
        ((((ULONG)(secondaryExitCapability >> 32)) &
            (KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
             KSW_VMX_SECONDARY_EXIT_LOAD_FRED)) ==
            (KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
             KSW_VMX_SECONDARY_EXIT_LOAD_FRED));

    /* 已经启用的处理器状态没有完整 VMCS 传输能力时必须在 VM-entry 前拒绝。 */
    if ((!cetStateSupported &&
            (hardwareCr4 & KSW_CR4_CET) != 0ULL) ||
        (!pkrsStateSupported &&
            (hardwareCr4 & KSW_CR4_PKS) != 0ULL) ||
        (!uinvStateSupported &&
            (hardwareCr4 & KSW_CR4_UINTR) != 0ULL) ||
        (!fredStateSupported &&
            (hardwareCr4 & KSW_CR4_FRED) != 0ULL)) {
        return STATUS_NOT_SUPPORTED;
    }

    /* 只读取 CPU 与 VMX 控制共同支持的可选状态寄存器。 */
    __try {
        if (cetStateSupported) {
            nativeSCet = __readmsr(KSW_IA32_S_CET);
            nativeInterruptSspTable =
                __readmsr(KSW_IA32_INTERRUPT_SSP_TABLE);
            if (Input->ResidentMode == 0U &&
                (hardwareCr4 & KSW_CR4_CET) != 0ULL &&
                (nativeSCet & KSW_CET_SHADOW_STACK_ENABLED) != 0ULL) {
                nativeSsp = KswordARKHvmAsmReadSsp();
                if (nativeSsp == 0ULL) {
                    status = STATUS_NOT_SUPPORTED;
                    __leave;
                }
            }
        }
        if (pkrsStateSupported) {
            nativePkrs = __readmsr(KSW_IA32_PKRS);
        }
        if (uinvStateSupported) {
            nativeUinv =
                (__readmsr(KSW_IA32_UINTR_MISC) >> 32) & 0xFFULL;
        }
        if (fredStateSupported) {
            nativeFredConfig = __readmsr(KSW_IA32_FRED_CONFIG);
            nativeFredRsp1 = __readmsr(KSW_IA32_FRED_RSP1);
            nativeFredRsp2 = __readmsr(KSW_IA32_FRED_RSP2);
            nativeFredRsp3 = __readmsr(KSW_IA32_FRED_RSP3);
            nativeFredStackLevels =
                __readmsr(KSW_IA32_FRED_STKLVLS);
            nativeFredSsp1 = __readmsr(KSW_IA32_FRED_SSP1);
            nativeFredSsp2 = __readmsr(KSW_IA32_FRED_SSP2);
            nativeFredSsp3 = __readmsr(KSW_IA32_FRED_SSP3);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Long mode takes the architecturally active FS base from its MSR. */
    fs.Base = fsBase;
    /* Long mode takes the architecturally active GS base from its MSR. */
    gs.Base = gsBase;
    /* Keep guest CR0 within the fixed-bit envelope advertised by the CPU. */
    guestCr0 = (__readcr0() | Input->Cr0Fixed0) & Input->Cr0Fixed1;
    /* Keep guest CR4 within fixed bits under explicit nested-VMX policy. */
    guestCr4 =
        (((Input->EnableNestedVmx != 0U
            ? (hardwareCr4 | (1ULL << 13))
            : (hardwareCr4 & ~(1ULL << 13))) |
            Input->Cr4Fixed0)) &
        Input->Cr4Fixed1;
    /* Request only the pin controls required by the capability MSR. */
    pinControls = KswordARKHvmAdjustControls(0UL, pinCapability);
    /* Activate secondary controls and reserve HLT exits for one-shot guests. */
    primaryControls = KswordARKHvmAdjustControls(
        (Input->ResidentMode == 0U
            ? KSW_VMX_PRIMARY_HLT_EXITING
            : 0UL) |
            KSW_VMX_PRIMARY_SECONDARY_CONTROLS,
        primaryCapability);
    /* 同时启用 EPT 与 Windows 已经通过 CPUID 观察到的指令执行门控。 */
    secondaryControls = KswordARKHvmAdjustControls(
        KSW_VMX_SECONDARY_EPT |
            requiredInstructionControls,
        secondaryCapability);
    /* 成对保存调试、PAT、EFER 与受支持的扩展处理器状态。 */
    exitControls = KswordARKHvmAdjustControls(
        KSW_VMX_EXIT_SAVE_DEBUG_CONTROLS |
            KSW_VMX_EXIT_HOST_64_BIT |
            KSW_VMX_EXIT_SAVE_PAT |
            KSW_VMX_EXIT_LOAD_PAT |
            KSW_VMX_EXIT_SAVE_EFER |
            KSW_VMX_EXIT_LOAD_EFER |
            (uinvStateSupported
                ? KSW_VMX_EXIT_CLEAR_UINV
                : 0UL) |
            (cetStateSupported
                ? KSW_VMX_EXIT_LOAD_CET
                : 0UL) |
            (pkrsStateSupported
                ? KSW_VMX_EXIT_LOAD_PKRS
                : 0UL) |
            (fredStateSupported
                ? KSW_VMX_EXIT_SECONDARY_CONTROLS
                : 0UL),
        exitCapability);
    /* VM-entry 使用与 VM-exit 对称的状态加载控制。 */
    entryControls = KswordARKHvmAdjustControls(
        KSW_VMX_ENTRY_LOAD_DEBUG_CONTROLS |
            KSW_VMX_ENTRY_IA32E_GUEST |
            KSW_VMX_ENTRY_LOAD_PAT |
            KSW_VMX_ENTRY_LOAD_EFER |
            (uinvStateSupported
                ? KSW_VMX_ENTRY_LOAD_UINV
                : 0UL) |
            (cetStateSupported
                ? KSW_VMX_ENTRY_LOAD_CET
                : 0UL) |
            (pkrsStateSupported
                ? KSW_VMX_ENTRY_LOAD_PKRS
                : 0UL) |
            (fredStateSupported
                ? KSW_VMX_ENTRY_LOAD_FRED
                : 0UL),
        entryCapability);
    if (fredStateSupported) {
        secondaryExitControls = KswordARKHvmAdjustControls(
            (ULONG)(KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
                KSW_VMX_SECONDARY_EXIT_LOAD_FRED),
            secondaryExitCapability);
    }

    /* Reject hardware that cannot activate the required secondary controls. */
    if ((primaryControls & KSW_VMX_PRIMARY_SECONDARY_CONTROLS) == 0UL ||
        (secondaryControls & KSW_VMX_SECONDARY_EPT) == 0UL ||
        (secondaryControls & requiredInstructionControls) !=
            requiredInstructionControls ||
        (exitControls & KSW_VMX_EXIT_HOST_64_BIT) == 0UL ||
        (entryControls & KSW_VMX_ENTRY_IA32E_GUEST) == 0UL) {
        return STATUS_NOT_SUPPORTED;
    }
    /* 调试状态必须成对保存与加载，禁止只完成单向切换。 */
    if (((exitControls & KSW_VMX_EXIT_SAVE_DEBUG_CONTROLS) != 0UL) !=
        ((entryControls & KSW_VMX_ENTRY_LOAD_DEBUG_CONTROLS) != 0UL)) {
        return STATUS_NOT_SUPPORTED;
    }
    if ((cetStateSupported &&
            ((exitControls & KSW_VMX_EXIT_LOAD_CET) == 0UL ||
             (entryControls & KSW_VMX_ENTRY_LOAD_CET) == 0UL)) ||
        (pkrsStateSupported &&
            ((exitControls & KSW_VMX_EXIT_LOAD_PKRS) == 0UL ||
             (entryControls & KSW_VMX_ENTRY_LOAD_PKRS) == 0UL)) ||
        (uinvStateSupported &&
            ((exitControls & KSW_VMX_EXIT_CLEAR_UINV) == 0UL ||
             (entryControls & KSW_VMX_ENTRY_LOAD_UINV) == 0UL)) ||
        (fredStateSupported &&
            (((exitControls &
                KSW_VMX_EXIT_SECONDARY_CONTROLS) == 0UL) ||
             ((entryControls & KSW_VMX_ENTRY_LOAD_FRED) == 0UL) ||
             ((secondaryExitControls &
                (ULONG)(KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
                    KSW_VMX_SECONDARY_EXIT_LOAD_FRED)) !=
                (ULONG)(KSW_VMX_SECONDARY_EXIT_SAVE_FRED |
                    KSW_VMX_SECONDARY_EXIT_LOAD_FRED))))) {
        return STATUS_NOT_SUPPORTED;
    }

    /* Build the complete fixed VMCS write ledger on the launch stack. */
    {
        const KSW_HVM_VMCS_WRITE writes[] = {
            { KSW_VMCS_PIN_CONTROLS, pinControls },
            { KSW_VMCS_PRIMARY_CONTROLS, primaryControls },
            { KSW_VMCS_SECONDARY_CONTROLS, secondaryControls },
            { KSW_VMCS_EXIT_CONTROLS, exitControls },
            { KSW_VMCS_ENTRY_CONTROLS, entryControls },
            { KSW_VMCS_EXCEPTION_BITMAP, 0U },
            { KSW_VMCS_PAGE_FAULT_MASK, 0U },
            { KSW_VMCS_PAGE_FAULT_MATCH, 0U },
            { KSW_VMCS_CR3_TARGET_COUNT, 0U },
            { KSW_VMCS_EXIT_MSR_STORE_COUNT, 0U },
            { KSW_VMCS_EXIT_MSR_LOAD_COUNT, 0U },
            { KSW_VMCS_ENTRY_MSR_LOAD_COUNT, 0U },
            { KSW_VMCS_ENTRY_INTERRUPTION_INFO, 0U },
            { KSW_VMCS_ENTRY_EXCEPTION_ERROR, 0U },
            { KSW_VMCS_ENTRY_INSTRUCTION_LENGTH, 0U },
            { KSW_VMCS_TPR_THRESHOLD, 0U },
            { KSW_VMCS_EPT_POINTER, (SIZE_T)Input->EptPointer },
            { KSW_VMCS_GUEST_LINK_POINTER, (SIZE_T)MAXULONGLONG },
            { KSW_VMCS_GUEST_DEBUGCTL, (SIZE_T)debugControl },
            { KSW_VMCS_CR0_MASK, 0U },
            { KSW_VMCS_CR4_MASK, 0U },
            { KSW_VMCS_CR0_SHADOW, (SIZE_T)guestCr0 },
            { KSW_VMCS_CR4_SHADOW, (SIZE_T)guestCr4 },
            { KSW_VMCS_GUEST_ES_SELECTOR, es.Selector },
            { KSW_VMCS_GUEST_CS_SELECTOR, cs.Selector },
            { KSW_VMCS_GUEST_SS_SELECTOR, ss.Selector },
            { KSW_VMCS_GUEST_DS_SELECTOR, ds.Selector },
            { KSW_VMCS_GUEST_FS_SELECTOR, fs.Selector },
            { KSW_VMCS_GUEST_GS_SELECTOR, gs.Selector },
            { KSW_VMCS_GUEST_LDTR_SELECTOR, ldtr.Selector },
            { KSW_VMCS_GUEST_TR_SELECTOR, tr.Selector },
            { KSW_VMCS_GUEST_ES_LIMIT, es.Limit },
            { KSW_VMCS_GUEST_CS_LIMIT, cs.Limit },
            { KSW_VMCS_GUEST_SS_LIMIT, ss.Limit },
            { KSW_VMCS_GUEST_DS_LIMIT, ds.Limit },
            { KSW_VMCS_GUEST_FS_LIMIT, fs.Limit },
            { KSW_VMCS_GUEST_GS_LIMIT, gs.Limit },
            { KSW_VMCS_GUEST_LDTR_LIMIT, ldtr.Limit },
            { KSW_VMCS_GUEST_TR_LIMIT, tr.Limit },
            { KSW_VMCS_GUEST_GDTR_LIMIT, snapshot.Gdtr.Limit },
            { KSW_VMCS_GUEST_IDTR_LIMIT, snapshot.Idtr.Limit },
            { KSW_VMCS_GUEST_ES_ACCESS, es.AccessRights },
            { KSW_VMCS_GUEST_CS_ACCESS, cs.AccessRights },
            { KSW_VMCS_GUEST_SS_ACCESS, ss.AccessRights },
            { KSW_VMCS_GUEST_DS_ACCESS, ds.AccessRights },
            { KSW_VMCS_GUEST_FS_ACCESS, fs.AccessRights },
            { KSW_VMCS_GUEST_GS_ACCESS, gs.AccessRights },
            { KSW_VMCS_GUEST_LDTR_ACCESS, ldtr.AccessRights },
            { KSW_VMCS_GUEST_TR_ACCESS, tr.AccessRights },
            { KSW_VMCS_GUEST_INTERRUPTIBILITY, 0U },
            { KSW_VMCS_GUEST_ACTIVITY, 0U },
            { KSW_VMCS_GUEST_SMBASE, 0U },
            { KSW_VMCS_GUEST_CR0, (SIZE_T)guestCr0 },
            { KSW_VMCS_GUEST_CR3, (SIZE_T)__readcr3() },
            { KSW_VMCS_GUEST_CR4, (SIZE_T)guestCr4 },
            { KSW_VMCS_GUEST_ES_BASE, (SIZE_T)es.Base },
            { KSW_VMCS_GUEST_CS_BASE, (SIZE_T)cs.Base },
            { KSW_VMCS_GUEST_SS_BASE, (SIZE_T)ss.Base },
            { KSW_VMCS_GUEST_DS_BASE, (SIZE_T)ds.Base },
            { KSW_VMCS_GUEST_FS_BASE, (SIZE_T)fs.Base },
            { KSW_VMCS_GUEST_GS_BASE, (SIZE_T)gs.Base },
            { KSW_VMCS_GUEST_LDTR_BASE, (SIZE_T)ldtr.Base },
            { KSW_VMCS_GUEST_TR_BASE, (SIZE_T)tr.Base },
            { KSW_VMCS_GUEST_GDTR_BASE, (SIZE_T)snapshot.Gdtr.Base },
            { KSW_VMCS_GUEST_IDTR_BASE, (SIZE_T)snapshot.Idtr.Base },
            { KSW_VMCS_GUEST_DR7, (SIZE_T)__readdr(7) },
            { KSW_VMCS_GUEST_RSP, (SIZE_T)Input->GuestStackPointer },
            { KSW_VMCS_GUEST_RIP, (SIZE_T)Input->GuestInstructionPointer },
            { KSW_VMCS_GUEST_RFLAGS,
                (SIZE_T)(Input->GuestRflags != 0ULL
                    ? (Input->GuestRflags | 0x2ULL)
                    : 0x2ULL) },
            { KSW_VMCS_GUEST_PENDING_DEBUG, 0U },
            { KSW_VMCS_GUEST_SYSENTER_CS, (SIZE_T)sysenterCs },
            { KSW_VMCS_GUEST_SYSENTER_ESP, (SIZE_T)sysenterEsp },
            { KSW_VMCS_GUEST_SYSENTER_EIP, (SIZE_T)sysenterEip },
            { KSW_VMCS_GUEST_PAT, (SIZE_T)pat },
            { KSW_VMCS_GUEST_EFER, (SIZE_T)efer },
            { KSW_VMCS_HOST_ES_SELECTOR, es.Selector & 0xFFF8U },
            { KSW_VMCS_HOST_CS_SELECTOR, cs.Selector & 0xFFF8U },
            { KSW_VMCS_HOST_SS_SELECTOR, ss.Selector & 0xFFF8U },
            { KSW_VMCS_HOST_DS_SELECTOR, ds.Selector & 0xFFF8U },
            { KSW_VMCS_HOST_FS_SELECTOR, fs.Selector & 0xFFF8U },
            { KSW_VMCS_HOST_GS_SELECTOR, gs.Selector & 0xFFF8U },
            { KSW_VMCS_HOST_TR_SELECTOR, tr.Selector & 0xFFF8U },
            { KSW_VMCS_HOST_SYSENTER_CS, (SIZE_T)sysenterCs },
            { KSW_VMCS_HOST_CR0, (SIZE_T)__readcr0() },
            { KSW_VMCS_HOST_CR3, (SIZE_T)__readcr3() },
            { KSW_VMCS_HOST_CR4, (SIZE_T)__readcr4() },
            { KSW_VMCS_HOST_FS_BASE, (SIZE_T)fsBase },
            { KSW_VMCS_HOST_GS_BASE, (SIZE_T)gsBase },
            { KSW_VMCS_HOST_TR_BASE, (SIZE_T)tr.Base },
            { KSW_VMCS_HOST_GDTR_BASE, (SIZE_T)snapshot.Gdtr.Base },
            { KSW_VMCS_HOST_IDTR_BASE, (SIZE_T)snapshot.Idtr.Base },
            { KSW_VMCS_HOST_SYSENTER_ESP, (SIZE_T)sysenterEsp },
            { KSW_VMCS_HOST_SYSENTER_EIP, (SIZE_T)sysenterEip },
            { KSW_VMCS_HOST_RSP, (SIZE_T)Input->HostStackPointer },
            { KSW_VMCS_HOST_RIP, (SIZE_T)Input->HostInstructionPointer },
            { KSW_VMCS_HOST_PAT, (SIZE_T)pat },
            { KSW_VMCS_HOST_EFER, (SIZE_T)efer }
        };

        /* 先写入所有处理器都实现的基础字段。 */
        status = KswordARKHvmWriteVmcs(
            writes,
            (ULONG)RTL_NUMBER_OF(writes),
            VmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    /* XSAVES 和 PCONFIG 放行后显式清零对应退出位图。 */
    if ((secondaryControls & KSW_VMX_SECONDARY_XSAVES) != 0UL) {
        const KSW_HVM_VMCS_WRITE writes[] = {
            { KSW_VMCS_XSS_EXITING_BITMAP, 0U }
        };

        status = KswordARKHvmWriteVmcs(
            writes,
            (ULONG)RTL_NUMBER_OF(writes),
            VmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if ((secondaryControls & KSW_VMX_SECONDARY_PCONFIG) != 0UL) {
        const KSW_HVM_VMCS_WRITE writes[] = {
            { KSW_VMCS_PCONFIG_EXITING_BITMAP, 0U }
        };

        status = KswordARKHvmWriteVmcs(
            writes,
            (ULONG)RTL_NUMBER_OF(writes),
            VmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (cetStateSupported) {
        const KSW_HVM_VMCS_WRITE writes[] = {
            { KSW_VMCS_GUEST_S_CET, (SIZE_T)nativeSCet },
            { KSW_VMCS_GUEST_SSP, (SIZE_T)nativeSsp },
            { KSW_VMCS_GUEST_INTERRUPT_SSP_TABLE,
                (SIZE_T)nativeInterruptSspTable },
            { KSW_VMCS_HOST_S_CET, 0U },
            { KSW_VMCS_HOST_SSP, 0U },
            { KSW_VMCS_HOST_INTERRUPT_SSP_TABLE, 0U }
        };

        /* VM-exit 在根模式关闭 CET，VM-entry 恢复客户机原始状态。 */
        status = KswordARKHvmWriteVmcs(
            writes,
            (ULONG)RTL_NUMBER_OF(writes),
            VmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (pkrsStateSupported) {
        const KSW_HVM_VMCS_WRITE writes[] = {
            { KSW_VMCS_GUEST_PKRS, (SIZE_T)nativePkrs },
            { KSW_VMCS_HOST_PKRS, 0U }
        };

        /* 客户机保留原始 PKRS，根模式使用不限制访问的状态。 */
        status = KswordARKHvmWriteVmcs(
            writes,
            (ULONG)RTL_NUMBER_OF(writes),
            VmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (uinvStateSupported) {
        const KSW_HVM_VMCS_WRITE writes[] = {
            { KSW_VMCS_GUEST_UINV, (SIZE_T)nativeUinv }
        };

        status = KswordARKHvmWriteVmcs(
            writes,
            (ULONG)RTL_NUMBER_OF(writes),
            VmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    if (fredStateSupported) {
        const KSW_HVM_VMCS_WRITE writes[] = {
            { KSW_VMCS_SECONDARY_EXIT_CONTROLS,
                (SIZE_T)secondaryExitControls },
            { KSW_VMCS_GUEST_FRED_CONFIG,
                (SIZE_T)nativeFredConfig },
            { KSW_VMCS_GUEST_FRED_RSP1,
                (SIZE_T)nativeFredRsp1 },
            { KSW_VMCS_GUEST_FRED_RSP2,
                (SIZE_T)nativeFredRsp2 },
            { KSW_VMCS_GUEST_FRED_RSP3,
                (SIZE_T)nativeFredRsp3 },
            { KSW_VMCS_GUEST_FRED_STKLVLS,
                (SIZE_T)nativeFredStackLevels },
            { KSW_VMCS_GUEST_FRED_SSP1,
                (SIZE_T)nativeFredSsp1 },
            { KSW_VMCS_GUEST_FRED_SSP2,
                (SIZE_T)nativeFredSsp2 },
            { KSW_VMCS_GUEST_FRED_SSP3,
                (SIZE_T)nativeFredSsp3 },
            { KSW_VMCS_HOST_FRED_CONFIG,
                (SIZE_T)nativeFredConfig },
            { KSW_VMCS_HOST_FRED_RSP1,
                (SIZE_T)nativeFredRsp1 },
            { KSW_VMCS_HOST_FRED_RSP2,
                (SIZE_T)nativeFredRsp2 },
            { KSW_VMCS_HOST_FRED_RSP3,
                (SIZE_T)nativeFredRsp3 },
            { KSW_VMCS_HOST_FRED_STKLVLS,
                (SIZE_T)nativeFredStackLevels },
            { KSW_VMCS_HOST_FRED_SSP1,
                (SIZE_T)nativeFredSsp1 },
            { KSW_VMCS_HOST_FRED_SSP2,
                (SIZE_T)nativeFredSsp2 },
            { KSW_VMCS_HOST_FRED_SSP3,
                (SIZE_T)nativeFredSsp3 },
            { KSW_VMCS_INJECTED_EVENT_DATA, 0U }
        };

        status = KswordARKHvmWriteVmcs(
            writes,
            (ULONG)RTL_NUMBER_OF(writes),
            VmInstructionError);
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKHvmReadVmExitTelemetry(
    _Out_ KSW_HVM_VMEXIT_TELEMETRY* Telemetry
    )
{
    SIZE_T value = 0U;

    /* Reject a missing telemetry destination before VMREAD. */
    if (Telemetry == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    /* Clear every field so a partial failure never exposes stale state. */
    RtlZeroMemory(Telemetry, sizeof(*Telemetry));
    /* Read the full exit-reason field, including entry-failure information. */
    if (__vmx_vmread(KSW_VMCS_EXIT_REASON, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Preserve only the protocol-visible 32-bit exit reason. */
    Telemetry->Reason = (ULONG)value;
    /* Read the exit qualification associated with the basic reason. */
    if (__vmx_vmread(KSW_VMCS_EXIT_QUALIFICATION, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Publish the complete natural-width qualification. */
    Telemetry->Qualification = (ULONGLONG)value;
    /* Read the guest instruction pointer at the point of exit. */
    if (__vmx_vmread(KSW_VMCS_GUEST_RIP, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Publish the guest instruction pointer. */
    Telemetry->GuestRip = (ULONGLONG)value;
    /* Read the guest stack pointer at the point of exit. */
    if (__vmx_vmread(KSW_VMCS_GUEST_RSP, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Publish the guest stack pointer. */
    Telemetry->GuestRsp = (ULONGLONG)value;
    /* Read the instruction length for deterministic VMCALL evidence. */
    if (__vmx_vmread(KSW_VMCS_EXIT_INSTRUCTION_LENGTH, &value) != 0U) {
        return STATUS_HV_OPERATION_FAILED;
    }
    /* Publish the bounded instruction length. */
    Telemetry->InstructionLength = (ULONG)value;
    /* Read the VM-instruction error field as additional diagnostic evidence. */
    if (__vmx_vmread(KSW_VMCS_INSTRUCTION_ERROR, &value) == 0U) {
        Telemetry->VmInstructionError = (ULONG)value;
    }
    return STATUS_SUCCESS;
}

#else

NTSTATUS
KswordARKHvmConfigureVmcs(
    _In_ const KSW_HVM_VMCS_INPUT* Input,
    _Out_ ULONG* VmInstructionError
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Input);
    /* Publish an empty diagnostic when a destination was supplied. */
    if (VmInstructionError != NULL) {
        *VmInstructionError = 0UL;
    }
    return STATUS_NOT_SUPPORTED;
}

NTSTATUS
KswordARKHvmReadVmExitTelemetry(
    _Out_ KSW_HVM_VMEXIT_TELEMETRY* Telemetry
    )
{
    /* Keep non-x64 builds explicit and warning-free. */
    UNREFERENCED_PARAMETER(Telemetry);
    return STATUS_NOT_SUPPORTED;
}

#endif
