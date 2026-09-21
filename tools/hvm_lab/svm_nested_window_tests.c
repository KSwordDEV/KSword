/* Offline window-control cases only; no real interrupt delivery is exercised. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_window.h"
#define CHECK(x) do { if (!(x)) { printf("window:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
int main(void)
{
    KSW_SVM_VMCB vmcb;
    KSW_NSVM_IRQ_WINDOW window;
    unsigned exit = 99;
    const KSW_SVM_U64 exception = 0x8000030dULL | (1ULL << 11);
    memset(&vmcb, 0, sizeof(vmcb)); memset(&window, 0, sizeof(window));
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, (1ULL << 24) | 3);
    KswSvmWrite32(&vmcb, KSW_VMCB_MISC1, 1U << 18);
    KswSvmWrite64(&vmcb, KSW_VMCB_EVENT, exception);
    CHECK(KswSvmNestedIrqWindowArm(&vmcb, 0x80000061ULL, 42, &window));
    CHECK(window.Applied && window.Token == 42);
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_EVENT) == exception);
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) == ((0x61ULL << 32) | (1ULL << 24) | 0x60103ULL));
    CHECK((KswSvmRead64(&vmcb, KSW_VMCB_MISC1) & (1U << 4)) != 0);
    CHECK(!KswSvmNestedIrqWindowArm(&vmcb, 0x80000062ULL, 43, &window));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x400);
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, (KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) & ~15ULL) | 7);
    CHECK(KswSvmNestedIrqWindowRestore(&vmcb, &window, &exit) && !exit && !window.Applied);
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) == ((1ULL << 24) | 7));
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_MISC1) == (1U << 18));
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_EVENT) == exception);
    CHECK(!KswSvmNestedIrqWindowRestore(&vmcb, &window, &exit));
    KswSvmWrite64(&vmcb, KSW_VMCB_EVENT, 0);
    CHECK(KswSvmNestedIrqWindowArm(&vmcb, 0x80000091ULL, 44, &window));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x64);
    CHECK(KswSvmNestedIrqWindowRestore(&vmcb, &window, &exit) && exit);
    CHECK(!KswSvmNestedIrqWindowArm(&vmcb, 0x80000202ULL, 45, &window));
    CHECK(!KswSvmNestedIrqWindowArm(&vmcb, 0x80000008ULL, 45, &window));
    CHECK(!KswSvmNestedIrqWindowArm(&vmcb, 0x80000091ULL, 0, &window));
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) | 256);
    CHECK(!KswSvmNestedIrqWindowArm(&vmcb, 0x80000091ULL, 45, &window));
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, 0);
    CHECK(KswSvmNestedIrqWindowArm(&vmcb, 0x80000091ULL, 45, &window));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, KSW_SVM_EXIT_INVALID);
    CHECK(!KswSvmNestedIrqWindowRestore(&vmcb, &window, &exit) && window.Applied);
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x72);
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, 0);
    CHECK(!KswSvmNestedIrqWindowRestore(&vmcb, &window, &exit) && window.Applied);
    puts("nested window source cases passed"); return 0;
}
