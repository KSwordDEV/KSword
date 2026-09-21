/* Architectural VMCB writeback through an immutable, L0-owned outer mapping. */
#pragma once
#include "hvm_svm_nested_operand.h"

/* Operations select a fixed field whitelist, never a guest-supplied arbitrary mask. */
#define KSW_NSVM_SAVE_VMEXIT 1U
#define KSW_NSVM_SAVE_INVALID 2U
#define KSW_NSVM_SAVE_VMSAVE 3U

/* Commit must validate/map the entire RAM page before writing any field.
   Same-VMCB concurrent use is the virtual VMM's synchronization responsibility.
   A failure after any write must report progress; it cannot be blindly retried. */
typedef int (*KSW_NSVM_COMMIT_VMCB)(void* Context, KSW_SVM_U64 HostPa,
    const KSW_SVM_VMCB* Image, unsigned int Operation, unsigned int NestedPaging,
    unsigned int* WordsWritten);

/* Return an aligned word's architecturally writable bits, zero for every other field. */
KSW_SVM_U64 KswSvmNestedWritebackMask(unsigned int Offset,
    unsigned int Operation, unsigned int NestedPaging);
/* ExpectedHostPa binds the result to the captured operand, including nonidentity NPT01. */
unsigned int KswSvmNestedWriteback(const KSW_NSVM_OPERAND_IO* Io,
    KSW_SVM_U64 GuestPa, KSW_SVM_U64 ExpectedHostPa, const KSW_SVM_VMCB* Image,
    unsigned int Operation, unsigned int NestedPaging, KSW_NSVM_COMMIT_VMCB Commit,
    KSW_NSVM_OPERAND_RESULT* Result);
