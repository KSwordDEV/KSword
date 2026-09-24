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
__declspec(align(4096)) static KSW_SVM_U64 npfTables[4][512];
static KSW_NSHADOW_PAGE npfPages[4];

static int npf_read(void* context, KSW_SVM_U64 pa, KSW_SVM_U64* value)
{
    (void)context;
    if (pa == 0x1000) { *value = 0x2067; return 1; }
    if (pa == 0x2000) { *value = 0xe7; return 1; }
    if (pa == 0x3000) { *value = 0x4067; return 1; }
    if (pa == 0x4000) { *value = 0xe7; return 1; }
    return 0;
}
static int npf_compare(void* context, KSW_SVM_U64 pa, KSW_SVM_U64 expected, KSW_SVM_U64 bits)
{
    KSW_SVM_U64 value;
    return npf_read(context, pa, &value) && value == expected && (value & bits) == bits;
}

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
    /* SVM instruction tests execute in protected mode, as required by admission. */
    KswSvmWrite64(&m->current, KSW_VMCB_CR0, 1);
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
    m->HeldNmiGuard = 1;
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_FAULT);
    m->HeldNmiGuard = 0; m->IrqWindow.Applied = 1;
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_FAULT);
    m->IrqWindow.Applied = 0;
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
    CHECK(m->HeldNmiGuard && (KswSvmRead64(&model.current, KSW_VMCB_MISC1) & (1ULL << 20)));
    model.msrs.Efer = KSW_SVM_EFER_SVME;
    hardware_exit(0x84, 0); /* Virtual STGI, processed by the real instruction engine. */
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(model.execution.Gif == 1);
    CHECK(KswSvmRead64(&model.current, KSW_VMCB_RIP) == 0x10002);
    CHECK(!(KswSvmRead64(&model.current, KSW_VMCB_EVENT) & (1ULL << 31)));
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    CHECK(m->ArmedToken == m->PhysicalNmiToken);
    CHECK(m->HeldNmiGuard && m->NmiBlocked && m->NmiHardwareMask);
    hardware_exit(KSW_SVM_EXIT_CPUID, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(model.execution.Pending.Delivered == 1 && !model.execution.Pending.Count);
    /* No assertion here claims physical NMI-blocking/IRET hardware correctness. */
    return 0;
}
static int held_nmi_iret(void)
{
    KSW_NSVM_MACHINE* m = &model.machine;
    const KSW_NSVM_PENDING_ITEM* item;
    initialize();
    CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
    model.execution.Gif = model.execution.GifRequested = 0;
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
    hardware_exit(0x61, 0);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY && m->HeldNmiGuard);
    hardware_exit(0x74, 0); /* IRET is intercepted before it can unmask the physical NMI source. */
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY && m->Iret.Requested);
    CHECK(!m->HeldNmiGuard && !m->Overlay.Applied && !model.execution.Gif);
    CHECK(KswSvmRead64(&model.current, KSW_VMCB_RIP) == 0x10000);
    item = KswSvmNestedPendingLookup(&model.execution.Pending, m->PhysicalNmiToken);
    CHECK(item && item->Physical && !item->Interrupted && model.execution.Pending.Count == 1);
    CHECK(model.ackCalls == 1 && model.commitCalls == 1 && !model.execution.Pending.Delivered);
    CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_FAULT);
    CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY && m->Iret.Applied);
    CHECK(!(KswSvmRead64(&model.current, KSW_VMCB_MISC1) & (1ULL << 20)));
    hardware_exit(0x41, 0);
    KswSvmWrite64(&model.current, KSW_VMCB_RIP, 0x20000);
    KswSvmWrite64(&model.current, KSW_VMCB_RFLAGS, 2); /* IRET popped TF=0. */
    KswSvmWrite64(&model.current, KSW_VMCB_DR6, 1ULL << 14);
    CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
    CHECK(!m->Iret.Requested && !m->NmiHardwareMask && !m->NmiBlocked);
    CHECK(model.execution.Pending.Count == 1 && !model.execution.Gif);
    CHECK(KswSvmRead64(&model.current, KSW_VMCB_RIP) == 0x20000);
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
static int nmi_collision(void)
{
    KSW_NSVM_MACHINE* m = &model.machine;
    KSW_SVM_U64 token;
    unsigned collision;
    for (collision = 0; collision < 2; ++collision) {
        initialize();
        CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
        CHECK(KswSvmNestedPendingPush(&model.execution.Pending, 0x80000202ULL, 0, &token));
        if (collision) { KswSvmWrite64(&model.current, KSW_VMCB_EVENT, 0x80000b0eULL); }
        else { KswSvmWrite64(&model.current, 0x068, 1); }
        CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
        CHECK(m->NmiWindow.Applied && !m->ArmedToken && model.execution.Pending.Count == 1);
        CHECK(KswSvmRead64(&model.current, KSW_VMCB_EVENT) == (collision ? 0x80000b0eULL : 0));
        CHECK(KswSvmNestedMachineCanStop(m) == KSW_NSVM_STOP_FAULT);
        hardware_exit(0x41, 0);
        KswSvmWrite64(&model.current, KSW_VMCB_DR6, 1ULL << 14);
        KswSvmWrite64(&model.current, 0x068, 0);
        CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
        CHECK(!m->NmiWindow.Applied && !m->Overlay.Applied && model.execution.Pending.Count == 1);
        CHECK(!KswSvmRead64(&model.current, KSW_VMCB_EVENT));
        CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY && m->ArmedToken == token);
        hardware_exit(KSW_SVM_EXIT_CPUID, 0);
        CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY && !model.execution.Pending.Count);
    }
    return 0;
}
static int software_int_npf(void)
{
    unsigned injected, i, cycle;
    for (injected = 0; injected < 2; ++injected) {
        KSW_NSVM_MACHINE* m = &model.machine;
        initialize();
        CHECK(KswSvmNestedMachineInitialize(m) == KSW_NSVM_MACHINE_READY);
        model.session.Phase = KSW_NSVM_SESSION_L2;
        model.session.Lease.Token = 0x871d8;
        model.session.Permissions.Ready = 1;
        model.mmu.InnerRoot = 0x1000; model.mmu.OuterRoot = 0x3000;
        model.mmu.InnerBits = model.mmu.OuterBits = 45;
        model.mmu.InnerPage1Gb = model.mmu.OuterPage1Gb = 1;
        model.mmu.InnerNx = model.mmu.OuterNx = 1;
        model.mmu.InnerPat = model.mmu.OuterPat = model.mmu.HardwarePat = 0x0007010600070106ULL;
        for (i = 0; i < 4; ++i) {
            npfPages[i].Words = npfTables[i]; npfPages[i].Physical = 0x100000 + i * 4096ULL;
        }
        CHECK(KswSvmNestedShadowInitialize(&model.shadow, npfPages, 4, 45) == KSW_NSHADOW_OK);
        model.mmu.Epoch = model.shadow.Epoch;
        model.execution.MmuIo.Read = npf_read; model.execution.MmuIo.CompareOr = npf_compare;
        KswSvmWrite64(&model.current, KSW_VMCB_RIP, 0xfffff806305fd103ULL);
        KswSvmWrite64(&model.current, KSW_VMCB_EVENT, injected ? 0x8000042d : 0);
        KswSvmWrite64(&model.current, KSW_VMCB_NRIP, injected ? 0xfffff806305fd10aULL : 0);
        for (cycle = 0; cycle < 3; ++cycle) {
            CHECK(KswSvmNestedMachineEntry(m) == KSW_NSVM_MACHINE_READY);
            CHECK(model.execution.EventEntry.Valid && model.execution.EventEntry.Owner == 0x871d8);
            hardware_exit(KSW_SVM_EXIT_NPF, 0x8000042d);
            KswSvmWrite64(&model.current, KSW_VMCB_NRIP, 0);
            KswSvmWrite64(&model.current, KSW_VMCB_EVENT, 0);
            KswSvmWrite64(&model.current, KSW_VMCB_EXITINFO1, 0x100000004ULL);
            KswSvmWrite64(&model.current, KSW_VMCB_EXITINFO2, 0x60932d0 + cycle * 4096ULL);
            CHECK(KswSvmNestedMachineExit(m) == KSW_NSVM_MACHINE_READY);
            CHECK(!m->Overlay.Applied && model.session.Phase == KSW_NSVM_SESSION_L2);
            CHECK(model.execution.Translation.Status == 0 && model.execution.NpfRetries == 0);
            CHECK(model.shadow.Used == 4);
            CHECK(KswSvmRead64(&model.current, KSW_VMCB_RIP) == 0xfffff806305fd103ULL);
            CHECK(KswSvmRead64(&model.current, KSW_VMCB_EVENT) == (injected ? 0x8000042dULL : 0));
            CHECK(KswSvmRead64(&model.current, KSW_VMCB_NRIP) == (injected ? 0xfffff806305fd10aULL : 0));
            CHECK(KswSvmRead64(&model.current, KSW_VMCB_EXITINTINFO) == 0x8000042d);
        }
    }
    return 0;
}

int main(void)
{
    if (ordinary_cycle() || irq_window() || nmi_ownership() || held_nmi_iret() || retained_failures() || nmi_collision() || software_int_npf()) { return 1; }
    puts("nested coordinator integration fixtures passed (simulated hardware only)");
    return 0;
}
