/* L1 physical operands are translated through NPT01 before any host RAM access. */
#pragma once
#include "hvm_svm_nested_npt.h"

/* Caller owns the outer translation lifetime and provides a CPU-private RAM reader. */
typedef struct _KSW_NSVM_OPERAND_IO {
    /* NCR3 and PAT belong to L0, never the untrusted VMCB12. */
    KSW_SVM_U64 Root, Pat;
    /* These are the prepared outer CPU's paging capabilities. */
    unsigned int PhysicalBits, Page1Gb, Nx;
    /* The callback validates RAM ownership and performs one aligned physical read. */
    KSW_NNPT_READ Read;
    /* Context must not contain a window shared with another running processor. */
    void* Context;
} KSW_NSVM_OPERAND_IO;

/* Results distinguish a denied outer mapping from a missing physical operand. */
typedef struct _KSW_NSVM_OPERAND_RESULT {
    /* Success is published only after copying and rechecking the translation. */
    unsigned int Status, Words;
    /* No transient host mapping pointer escapes the callback. */
    KSW_SVM_U64 GuestPa, HostPa;
} KSW_NSVM_OPERAND_RESULT;

/* Destination is one owned 4-KiB buffer; on failure all its bytes become zero.
   Translation rechecks detect remaps, not unsynchronized writes to the data page. */
unsigned int KswSvmNestedReadOperandPage(const KSW_NSVM_OPERAND_IO* Io,
    KSW_SVM_U64 GuestPa, unsigned char* Destination, KSW_NSVM_OPERAND_RESULT* Result);
