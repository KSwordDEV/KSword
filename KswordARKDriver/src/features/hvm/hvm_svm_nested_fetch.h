/* Bounded instruction capture through L1 paging and NPT01, without guest-pointer dereferences. */
#pragma once
#include "hvm_svm_nested_operand.h"
/* NRIP bounds the already intercepted instruction; no speculative next-page fetch is performed. */
unsigned KswSvmNestedFetchInstruction(const KSW_NSVM_OPERAND_IO* Io,
    const KSW_SVM_VMCB* Current, unsigned char Bytes[15], unsigned* Length);
/* Decode only the SVM operand instructions whose exit code was independently observed. */
unsigned KswSvmNestedDecodeSvmOperand(const unsigned char* Bytes, unsigned Length,
    KSW_SVM_U64 ExitCode, unsigned LongCode, unsigned Default32,
    KSW_SVM_U64 Accumulator, KSW_SVM_U64* Operand, unsigned* AddressBits);
