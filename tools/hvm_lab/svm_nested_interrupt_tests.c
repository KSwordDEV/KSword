/* Offline source cases; no physical IRQ/NMI, IF/GIF or SVM instruction is executed. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_interrupt.h"
#define CHECK(x) do { if (!(x)) { printf("interrupt:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
static KSW_NSVM_SESSION session;
int main(void)
{
    KSW_SVM_VMCB vmcb;
    KSW_NSVM_INTERRUPT_OVERLAY overlay;
    unsigned reflected = 0;
    memset(&vmcb, 0, sizeof(vmcb)); memset(&overlay, 0, sizeof(overlay));
    KswSvmWrite32(&vmcb, KSW_VMCB_MISC1, 1U << 18);
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, (0x51ULL << 32) | 0x50103ULL);
    CHECK(KswSvmNestedInterruptPrepare(&vmcb, &session, 0, &overlay));
    CHECK(overlay.Applied && overlay.ForcedMask && overlay.SuppressedVirq && !overlay.HostIf);
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) == ((0x51ULL << 32) | 0x1050003ULL));
    CHECK(KswSvmNestedInterceptRequested(&vmcb, 0x61) == 1);
    CHECK(!KswSvmNestedInterruptPrepare(&vmcb, &session, 0, &overlay));
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, (KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) & ~15ULL) | 7);
    CHECK(KswSvmNestedInterruptRestore(&vmcb, 3, 1, &overlay));
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) == ((0x51ULL << 32) | 0x50107ULL));
    CHECK(KswSvmNestedInterceptRequested(&vmcb, 0x61) == 0);
    CHECK(!KswSvmNestedInterruptRestore(&vmcb, 3, 1, &overlay));
    CHECK(KswSvmNestedInterruptPrepare(&vmcb, &session, 1, &overlay));
    CHECK(!overlay.ForcedMask && !overlay.HostIf);
    CHECK(KswSvmNestedInterruptRestore(&vmcb, 11, 1, &overlay));
    CHECK((KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) & 15) == 11);
    session.Phase = KSW_NSVM_SESSION_L2;
    KswSvmWrite64(&session.L1, KSW_VMCB_RFLAGS, 0x202);
    KswSvmWrite64(&vmcb, KSW_VMCB_INTCTL, 1ULL << 24);
    CHECK(!KswSvmNestedInterruptPrepare(&vmcb, &session, 0, &overlay));
    CHECK(KswSvmNestedInterruptPrepare(&vmcb, &session, 1, &overlay));
    CHECK(overlay.HostIf == 1 && !overlay.ForcedMask);
    CHECK(KswSvmNestedInterruptRestore(&vmcb, 15, 0, &overlay));
    CHECK(KswSvmRead64(&vmcb, KSW_VMCB_INTCTL) == (1ULL << 24));
    KswSvmWrite32(&session.Vmcb12, KSW_VMCB_MISC1, 3);
    CHECK(KswSvmNestedPhysicalEvent(&session, 1, 0x60, &reflected) == KSW_NSVM_INTERRUPT_REFLECT);
    CHECK(KswSvmNestedPhysicalEvent(&session, 1, 0x61, &reflected) == KSW_NSVM_INTERRUPT_ACK_NMI && reflected);
    CHECK(KswSvmNestedPhysicalEvent(&session, 1, 0x62, &reflected) == KSW_NSVM_INTERRUPT_UNSUPPORTED);
    CHECK(KswSvmNestedPhysicalEvent(&session, 1, 0x63, &reflected) == KSW_NSVM_INTERRUPT_UNSUPPORTED);
    KswSvmWrite32(&session.Vmcb12, KSW_VMCB_MISC1, 0);
    CHECK(KswSvmNestedPhysicalEvent(&session, 1, 0x60, &reflected) == KSW_NSVM_INTERRUPT_FAULT);
    session.Phase = KSW_NSVM_SESSION_IDLE;
    CHECK(KswSvmNestedPhysicalEvent(&session, 0, 0x61, &reflected) == KSW_NSVM_INTERRUPT_ACK_NMI && !reflected);
    CHECK(KswSvmNestedPhysicalEvent(&session, 1, 0x61, &reflected) == KSW_NSVM_INTERRUPT_FAULT);
    puts("nested interrupt-overlay cases passed"); return 0;
}
