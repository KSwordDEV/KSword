/* Owned VMCB12 admission and VMCB02 construction; no guest pointer dereferences. */
#pragma once
#include "hvm_svm_nested_state.h"
#include "hvm_svm_nested_permissions.h"

#define KSW_NSVM_ENTRY_OK 0U
#define KSW_NSVM_ENTRY_INVALID 1U
#define KSW_NSVM_ENTRY_UNSUPPORTED 2U
/* A software support restriction must not masquerade as architectural INVALID. */
typedef struct _KSW_NSVM_ENTRY_POLICY {
    /* Virtual capabilities already admitted on the current physical CPU. */
    unsigned int PhysicalBits, AsidCount;
    /* Explicit implemented EFER/CR4 subsets, not guesses from a different CPU. */
    KSW_SVM_U64 EferSupported, Cr4Supported;
} KSW_NSVM_ENTRY_POLICY;

typedef struct _KSW_NSVM_ENTRY_RESULT {
    /* Offset/value identify the rejected field without losing its raw contents. */
    unsigned int Status, Offset;
    KSW_SVM_U64 Value;
} KSW_NSVM_ENTRY_RESULT;

/* This baseline requires NPT and excludes extended interrupt/SEV/LBR controls. */
unsigned int KswSvmNestedValidateEntry(const KSW_SVM_VMCB* Inner,
    const KSW_NSVM_ENTRY_POLICY* Policy, KSW_NSVM_ENTRY_RESULT* Result);
/* Hardware controls contain L0-owned physical addresses and a processor-local ASID. */
unsigned int KswSvmNestedBuildEntry(KSW_SVM_VMCB* Destination,
    const KSW_SVM_VMCB* Outer, const KSW_SVM_VMCB* Inner,
    const KSW_NSVM_ENTRY_POLICY* Policy, KSW_SVM_U64 RootPa,
    KSW_SVM_U64 MsrPa, KSW_SVM_U64 IoPa, unsigned int Asid,
    KSW_NSVM_ENTRY_RESULT* Result);
/* Invalid entry writes only architecturally returned diagnostic fields. */
void KswSvmNestedInvalidExit(KSW_SVM_VMCB* Inner);
/* SavedL1 is owned and may be updated; all other GPRs remain with the calling CPU. */
void KswSvmNestedRestoreL1(KSW_SVM_VMCB* Destination, KSW_SVM_VMCB* SavedL1,
    const KSW_SVM_VMCB* CurrentL2);
