/* Hardware-output fixtures for IRET observation. These do not execute IRET, SVM or debug traps. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_iret.h"
#define CHECK(x) do { if (!(x)) { printf("iret:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
static KSW_NSVM_IRET step;
static KSW_SVM_VMCB vmcb;
static void reset(void)
{
    memset(&step, 0, sizeof(step)); memset(&vmcb, 0, sizeof(vmcb));
    KswSvmWrite64(&vmcb, KSW_VMCB_RIP, 0x1000);
    KswSvmWrite64(&vmcb, KSW_VMCB_RFLAGS, 0x202);
    KswSvmWrite32(&vmcb, KSW_VMCB_MISC1, (1U << 20) | (1U << 18));
    KswSvmWrite32(&vmcb, 0x008, 0x4000);
}
int main(void)
{
    reset();
    CHECK(KswSvmNestedIretRequest(&step));
    CHECK(!KswSvmNestedIretRequest(&step));
    CHECK(KswSvmNestedIretArm(&vmcb, &step));
    CHECK(!(KswSvmRead64(&vmcb, KSW_VMCB_MISC1) & (1ULL << 20)));
    CHECK((unsigned)KswSvmRead64(&vmcb, 0x008) == ~0U);
    CHECK(!KswSvmNestedIretArm(&vmcb, &step));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x4d); /* #GP at original IRET. */
    CHECK(KswSvmNestedIretObserve(&vmcb, &step) == KSW_NSVM_IRET_CONTINUE);
    CHECK(!step.Completed && !step.Requested && !step.Applied);
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_RFLAGS) == 0x202);
    CHECK((unsigned)KswSvmRead64(&vmcb, 0x008) == 0x4000);

    reset();
    CHECK(KswSvmNestedIretRequest(&step) && KswSvmNestedIretArm(&vmcb, &step));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, KSW_SVM_EXIT_NPF);
    CHECK(KswSvmNestedIretObserve(&vmcb, &step) == KSW_NSVM_IRET_CONTINUE && step.Requested);
    CHECK(KswSvmNestedIretArm(&vmcb, &step));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x41);
    KswSvmWrite64(&vmcb, KSW_VMCB_DR6, 1ULL << 14);
    KswSvmWrite64(&vmcb, KSW_VMCB_RFLAGS, 2); /* Same-RIP successful return, TF popped clear. */
    CHECK(KswSvmNestedIretObserve(&vmcb, &step) == KSW_NSVM_IRET_MONITOR_DB);
    CHECK(step.Completed && !step.Requested && !KswSvmRead64(&vmcb, KSW_VMCB_DR6));
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_RFLAGS) == 2);

    reset();
    KswSvmWrite64(&vmcb, KSW_VMCB_RFLAGS, 0x302); /* Original guest tracing remains guest-owned. */
    CHECK(KswSvmNestedIretRequest(&step) && KswSvmNestedIretArm(&vmcb, &step));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x41);
    KswSvmWrite64(&vmcb, KSW_VMCB_DR6, 1ULL << 14);
    CHECK(KswSvmNestedIretObserve(&vmcb, &step) == KSW_NSVM_IRET_RETIRED);
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_DR6) & (1ULL << 14));

    reset();
    CHECK(KswSvmNestedIretRequest(&step) && KswSvmNestedIretArm(&vmcb, &step));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x41);
    KswSvmWrite64(&vmcb, KSW_VMCB_DR6, (1ULL << 14) | 1ULL); /* Simultaneous real B0 cannot disappear. */
    KswSvmWrite64(&vmcb, KSW_VMCB_RFLAGS, 0x302); /* IRET itself set TF: do not rewind popped flags. */
    CHECK(KswSvmNestedIretObserve(&vmcb, &step) == KSW_NSVM_IRET_RETIRED);
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_DR6) == 1 && KswSvmRead64(&vmcb, KSW_VMCB_RFLAGS) == 0x302);

    reset();
    CHECK(KswSvmNestedIretRequest(&step) && KswSvmNestedIretArm(&vmcb, &step));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, 0x60); /* INTR before IRET, no progress. */
    CHECK(KswSvmNestedIretObserve(&vmcb, &step) == KSW_NSVM_IRET_CONTINUE);
    CHECK(!step.Requested && !step.Completed);
    CHECK(KswSvmNestedIretRequest(&step) && KswSvmNestedIretArm(&vmcb, &step));
    KswSvmWrite64(&vmcb, KSW_VMCB_EXITCODE, KSW_SVM_EXIT_INVALID);
    CHECK(KswSvmNestedIretObserve(&vmcb, &step) == KSW_NSVM_IRET_FAULT && step.Applied);
    puts("IRET observation fixtures passed (simulated hardware only)");
    return 0;
}
