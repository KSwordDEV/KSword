/* Portable coordinator integration. All hardware outputs/callbacks below are simulated. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_machine.h"
#define CHECK(x) do { if (!(x)) { printf("machine:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
typedef struct _MODEL {
    KSW_NSVM_MACHINE machine;
    KSW_NSVM_EXECUTION execution;
    KSW_NSVM_SESSION session;
    KSW_NSVM_SESSION_IO io;
    KSW_NSVM_MSRS msrs;
    KSW_NMMU_CONFIG mmu;
    KSW_NSHADOW shadow;
    KSW_SVM_XSTATE_LAYOUT xstate;
    KSW_SVM_VMCB current;
    KSW_SVM_U64 gpr[16], xcr0, xss;
    unsigned tpr, ackValue, ackCalls, commitCalls, failCommit, failWrite;
} MODEL;
static MODEL model;

static unsigned read_tpr(void* context) { return ((MODEL*)context)->tpr; }
static int write_tpr(void* context, unsigned value)
{
    MODEL* m = context;
    if (m->failWrite || value > 15) { return 0; }
    m->tpr = value; return 1;
}
static unsigned acknowledge(void* context)
{
    MODEL* m = context;
    ++m->ackCalls; return m->ackValue;
}
static int commit_nmi(void* context, unsigned count)
{
    MODEL* m = context;
    ++m->commitCalls;
    return !m->failCommit && count == 1 && m->ackValue == 1;
}
static void cpuid(void* context, unsigned leaf, unsigned subleaf, unsigned words[4])
{
    (void)context; (void)leaf; (void)subleaf;
    words[0] = 0x8000000aU; words[1] = 0x68747541U;
    words[2] = 0x444d4163U; words[3] = 0x69746e65U;
}
static void initialize(void)
{
    MODEL* m = &model;
    memset(m, 0, sizeof(*m));
    m->machine.Execution = &m->execution;
    m->machine.Io.Context = m; m->machine.Io.ReadTpr = read_tpr;
    m->machine.Io.WriteTpr = write_tpr; m->machine.Io.AcknowledgeNmi = acknowledge;
    m->machine.Io.CommitNmi = commit_nmi;
    m->execution.Current = &m->current; m->execution.Gpr = m->gpr;
    m->execution.Session = &m->session; m->execution.Io = &m->io;
    m->execution.Registers.Svm = &m->msrs; m->execution.Registers.ExposeSvm = 1;
    m->execution.Registers.GuestXss = &m->xss; m->execution.GuestXcr0 = &m->xcr0;
    m->execution.PreparedXcr0 = m->xcr0 = 3;
    m->io.Mmu = &m->mmu; m->io.Shadow = &m->shadow;
    m->xstate.Ready = 1; m->xstate.User = 3;
    m->execution.Cpuid.Xstate = &m->xstate; m->execution.Cpuid.Read = cpuid;
    m->ackValue = 1;
    KswSvmWrite64(&m->current, KSW_VMCB_RIP, 0x10000);
    KswSvmWrite64(&m->current, KSW_VMCB_RFLAGS, 0x202);
    KswSvmWrite32(&m->current, KSW_VMCB_MISC1, 1U << 18);
}
static void hardware_exit(KSW_SVM_U64 code, KSW_SVM_U64 event)
{
    KswSvmWrite64(&model.current, KSW_VMCB_EXITCODE, code);
    KswSvmWrite64(&model.current, KSW_VMCB_EXITINTINFO, event);
    KswSvmWrite64(&model.current, KSW_VMCB_NRIP,
        KswSvmRead64(&model.current, KSW_VMCB_RIP) + 2);
    KswSvmWrite64(&model.current, KSW_VMCB_RAX, 0);
    model.gpr[1] = 0;
}
static int ordinary_cycle(void)
{
    KSW_NSVM_MACHINE* m = &model.machine;
    initialize();
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_READY);
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    CHECK(m->Overlay.Applied && m->Transitions == 1);
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_FAULT);
    hardware_exit(KSW_SVM_EXIT_CPUID, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(!m->Overlay.Applied && KswSvmRead64(&model.current, KSW_VMCB_RIP) == 0x10002);
    CHECK(KswSvmRead64(&model.current, KSW_VMCB_RAX) == 0x8000000aU);
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_READY);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_FAULT); /* Duplicate raw exit. */
    model.msrs.Efer = KSW_SVM_EFER_SVME;
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_OWNER);
    model.msrs.Efer = 0; model.execution.Gif = 0;
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_GIF);
    return 0;
}
static int irq_window(void)
{
    KSW_SVM_U64 token;
    KSW_NSVM_MACHINE* m = &model.machine;
    initialize();
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
    CHECK(KswSvmNestedPendingPush(&model.execution.Pending, 0x80000050ULL, 0, &token));
    KswSvmWrite64(&model.current, KSW_VMCB_RFLAGS, 2); /* Guest IF blocks initial IRQ. */
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    CHECK(m->IrqWindow.Applied && !m->ArmedToken && model.execution.Pending.Count == 1);
    CHECK(!(KswSvmRead64(&model.current, KSW_VMCB_EVENT) & (1ULL << 31)));
    KswSvmWrite64(&model.current, KSW_VMCB_RFLAGS, 0x202);
    hardware_exit(0x64, 0); /* VINTR before IDT delivery, while V_IRQ remains set. */
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(!m->IrqWindow.Applied && !m->Overlay.Applied && model.execution.Pending.Count == 1);
    CHECK(KswSvmRead64(&model.current, KSW_VMCB_RIP) == 0x10000);
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    CHECK(m->ArmedToken == token && !m->IrqWindow.Applied);
    CHECK(KswSvmRead64(&model.current, KSW_VMCB_EVENT) == 0x80000050ULL);
    hardware_exit(KSW_SVM_EXIT_CPUID, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(!model.execution.Pending.Count && model.execution.Pending.Delivered == 1 && !m->ArmedToken);
    return 0;
}
static int nmi_ownership(void)
{
    KSW_NSVM_MACHINE* m = &model.machine;
    const KSW_NSVM_PENDING_ITEM* item;
    initialize();
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
    model.execution.Gif = model.execution.GifRequested = 0;
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    CHECK(KswSvmRead64(&model.current, KSW_VMCB_MISC1) & 2ULL);
    hardware_exit(0x61, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(model.ackCalls == 1 && model.commitCalls == 1 && !m->NmiCount);
    item = KswSvmNestedPendingLookup(&model.execution.Pending, m->PhysicalNmiToken);
    CHECK(item && item->Physical && !item->Owner && !item->Interrupted);
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_EVENTS);
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    CHECK(!m->ArmedToken); /* Closed GIF retains ownership without injecting. */
    model.msrs.Efer = KSW_SVM_EFER_SVME;
    hardware_exit(0x84, 0); /* Virtual STGI, processed by the real instruction engine. */
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(model.execution.Gif == 1);
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    CHECK(m->ArmedToken == m->PhysicalNmiToken);
    hardware_exit(KSW_SVM_EXIT_CPUID, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(model.execution.Pending.Delivered == 1 && !model.execution.Pending.Count);
    /* No assertion here claims physical NMI-blocking/IRET hardware correctness. */
    return 0;
}
static int retained_failures(void)
{
    KSW_NSVM_MACHINE* m = &model.machine;
    KSW_SVM_U64 token;
    unsigned index;
    initialize(); model.tpr = 16;
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_FAULT && !m->Initialized);
    initialize();
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
    CHECK(KswSvmNestedPendingPush(&model.execution.Pending, 0x80000050ULL, 0, &token));
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    hardware_exit(KSW_SVM_EXIT_INVALID, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_FAULT);
    CHECK(m->ArmedToken == token && m->Overlay.Applied && model.execution.Pending.Count == 1);
    CHECK(!model.execution.Pending.Delivered);

    initialize();
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
    model.execution.Gif = model.execution.GifRequested = 0; model.failCommit = 1;
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    hardware_exit(0x61, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_FAULT);
    CHECK(m->NmiCount == 1 && model.execution.Pending.Count == 1);
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_FAULT);

    initialize();
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
    model.execution.Gif = model.execution.GifRequested = 0;
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        CHECK(KswSvmNestedPendingPush(&model.execution.Pending, 0x80000050ULL, 0, &token));
    }
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    hardware_exit(0x61, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_FAULT);
    CHECK(!model.ackCalls && !model.commitCalls && model.execution.Pending.Count == KSW_NSVM_PENDING_CAPACITY);
    return 0;
}
int main(void)
{
    if (ordinary_cycle() || irq_window() || nmi_ownership() || retained_failures()) { return 1; }
    puts("nested coordinator integration fixtures passed (simulated hardware only)");
    return 0;
}
