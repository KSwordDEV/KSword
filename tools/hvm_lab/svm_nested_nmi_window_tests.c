/* Offline source fixtures only; simulated outputs do not prove hardware tracing or NMI delivery. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_nmi_window.h"
#define CHECK(x) do { if (!(x)) { printf("nmi-window:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
int main(void)
{
    KSW_SVM_VMCB current = {0};
    KSW_NSVM_NMI_WINDOW window = {0};
    KswSvmWrite64(&current, KSW_VMCB_RFLAGS, 0x202);
    KswSvmWrite64(&current, KSW_VMCB_EVENT, 0x80000b0eULL);
    KswSvmWrite32(&current, 8, 1U << 14);
    CHECK(KswSvmNestedNmiWindowArm(&current, 7, &window));
    CHECK(KswSvmRead64(&current, KSW_VMCB_EVENT) == 0x80000b0eULL);
    CHECK(!KswSvmNestedNmiWindowArm(&current, 8, &window));
    KswSvmWrite64(&current, KSW_VMCB_EXITCODE, 0x41);
    KswSvmWrite64(&current, KSW_VMCB_DR6, 1ULL << 14);
    KswSvmWrite64(&current, KSW_VMCB_RFLAGS, 0x303); /* Guest changed CF; observer may only remove its tracing flags. */
    CHECK(KswSvmNestedNmiWindowRestore(&current, &window) == KSW_NSVM_NMI_WINDOW_DB);
    CHECK(KswSvmRead64(&current, KSW_VMCB_RFLAGS) == 0x203);
    CHECK((unsigned)KswSvmRead64(&current, 8) == (1U << 14) && !window.Applied);
    CHECK(KswSvmRead64(&current, KSW_VMCB_EVENT) == 0x80000b0eULL);
    CHECK(KswSvmNestedNmiWindowRestore(&current, &window) == KSW_NSVM_NMI_WINDOW_FAULT);
    KswSvmWrite64(&current, KSW_VMCB_RFLAGS, 0x302); /* Existing guest tracing is not monitor-owned. */
    CHECK(KswSvmNestedNmiWindowArm(&current, 7, &window));
    KswSvmWrite64(&current, KSW_VMCB_DR6, 1ULL << 14);
    CHECK(KswSvmNestedNmiWindowRestore(&current, &window) == KSW_NSVM_NMI_WINDOW_EXIT);
    CHECK(KswSvmRead64(&current, KSW_VMCB_DR6) & (1ULL << 14));
    window.Attempts = 64;
    CHECK(!KswSvmNestedNmiWindowArm(&current, 7, &window));
    CHECK(KswSvmNestedNmiWindowArm(&current, 8, &window));
    KswSvmWrite64(&current, KSW_VMCB_EXITCODE, KSW_SVM_EXIT_INVALID);
    CHECK(KswSvmNestedNmiWindowRestore(&current, &window) == KSW_NSVM_NMI_WINDOW_FAULT && window.Applied);
    puts("nested NMI-window fixtures passed (simulated outputs)");
    return 0;
}
