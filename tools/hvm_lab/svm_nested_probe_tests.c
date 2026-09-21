/* Run the production exit dispatcher as a host state machine, without SVM instructions. */
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_runtime.h"
#include <stdio.h>
#include <string.h>

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static KSW_SVM_CPU cpu;
static KSW_SVM_NESTED nested;
static KSW_SVM_VMCB guest, operand[2];
static KSW_NPT outer;
static unsigned char stack[KSW_SVM_STACK_BYTES];
static unsigned char msrpm[KSW_NSVM_MSRPM_BYTES], iopm[KSW_NSVM_IOPM_BYTES];
static unsigned char merged[KSW_NSVM_MSRPM_BYTES + KSW_NSVM_IOPM_BYTES];
__declspec(align(4096)) static KSW_SVM_U64 shadow[8][512];
static KSW_SVM_U64 memory[64][512];
static ULONGLONG fakeRip;
static unsigned traces;
void KswordSvmTrace(KSW_SVM_CPU* c, ULONG stage) { (void)c; (void)stage; ++traces; }
void KswordSvmAsmGuestResume(void) { }
void KswordSvmAsmNestedProbe(void) { }
void KswordSvmAsmNestedPayload(void) { }
int KswordSvmNestedRead(void* context, KSW_SVM_U64 address, KSW_SVM_U64* value)
{
    (void)context;
    if ((address & 7) || address >= sizeof(memory)) { return 0; }
    if (address >= 0x10000 && address < 0x11000) { memcpy(value, (unsigned char*)operand + (size_t)(address - 0x10000), 8); return 1; }
    if (address >= 0x20000 && address < 0x22000) { memcpy(value, msrpm + (size_t)(address - 0x20000), 8); return 1; }
    if (address >= 0x22000 && address < 0x25000) { memcpy(value, iopm + (size_t)(address - 0x22000), 8); return 1; }
    *value = memory[address >> 12][(address & 4095) / 8];
    return 1;
}
int KswordSvmNestedCompareOr(void* context, KSW_SVM_U64 address, KSW_SVM_U64 expected, KSW_SVM_U64 bits)
{
    KSW_SVM_U64* slot;
    (void)context;
    if ((address & 7) || address >= sizeof(memory)) { return 0; }
    slot = &memory[address >> 12][(address & 4095) / 8];
    if (*slot != expected) { return 0; }
    *slot |= bits;
    return 1;
}
int KswordSvmNestedCommitVmcb(void* context, KSW_SVM_U64 pa, const KSW_SVM_VMCB* image,
    unsigned operation, unsigned np, unsigned* written)
{
    unsigned offset;
    (void)context; *written = 0;
    if (pa != 0x10000) { return 0; }
    for (offset = 0; offset < 4096; offset += 8) {
        KSW_SVM_U64 mask = KswSvmNestedWritebackMask(offset, operation, np);
        if (mask) {
            KswSvmWrite64(operand, offset, (KswSvmRead64(operand, offset) & ~mask) | (KswSvmRead64(image, offset) & mask));
            ++*written;
        }
    }
    return 1;
}
static int initialize(void)
{
    unsigned i;
    memset(&cpu, 0, sizeof(cpu));
    memset(&nested, 0, sizeof(nested));
    memset(&guest, 0, sizeof(guest));
    memset(memory, 0, sizeof(memory));
    cpu.Guest = &guest;
    memset(msrpm, 0, sizeof(msrpm));
    memset(iopm, 0, sizeof(iopm));
    cpu.Msrpm = msrpm; cpu.Iopm = iopm;
    msrpm[0x820] = 3; /* EFER read/write, independent APM offset. */
    cpu.Nested = &nested;
    cpu.Caps.PhysicalBits = 45;
    cpu.Caps.AsidCount = 64; cpu.Caps.Efer = 0xd01; cpu.Caps.Cr4 = 1ULL << 18;
    cpu.HostXcr0 = cpu.GuestXcr0 = 0xe7;
    cpu.XstateLayout.Ready = 1; cpu.XstateLayout.User = 0xe7; cpu.XstateLayout.Features = 0xf;
    cpu.XstateLayout.Component[2][0] = 256; cpu.XstateLayout.Component[2][1] = 576;
    cpu.XstateLayout.Component[5][0] = 64; cpu.XstateLayout.Component[5][1] = 1088;
    cpu.XstateLayout.Component[6][0] = 512; cpu.XstateLayout.Component[6][1] = 1152;
    cpu.XstateLayout.Component[7][0] = 1024; cpu.XstateLayout.Component[7][1] = 1664;
    cpu.Caps.Page1Gb = TRUE;
    cpu.Caps.Pat = 0x0007010600070106ULL;
    cpu.OriginalEfer = 0xd01;
    cpu.LaunchRsp = 0xabc000;
    cpu.LaunchFlags = 0x202;
    cpu.Gpr[3] = 0x1122334455667788ULL;
    nested.Operand = operand;
    nested.OperandPa = 0x10000;
    nested.MergedMaps = merged;
    nested.MergedMapsPa = 0x80000;
    nested.Stack = stack;
    nested.Outer = &outer;
    outer.RootPa = 0x1000;
    outer.AddressMask = KswNptAddressMask(45);
    for (i = 0; i < 8; ++i) { nested.Pages[i].Words = shadow[i]; nested.Pages[i].Physical = 0x100000 + 4096ULL * i; }
    CHECK(KswSvmNestedShadowInitialize(&nested.Shadow, nested.Pages, 8, 45) == KSW_NSHADOW_OK);
    memory[1][0] = 0x2007;
    memory[2][0] = 0x3007;
    memory[3][0] = 0x4007;
    for (i = 0; i < 64; ++i) { memory[4][i] = 4096ULL * i | 7; }
    KswSvmWrite64(&guest, KSW_VMCB_CR3, 0x12345000);
    KswSvmWrite64(&guest, KSW_VMCB_CR4, cpu.Caps.Cr4);
    KswSvmWrite64(&guest, KSW_VMCB_EFER, 0x1d01);
    KswSvmWrite64(&guest, KSW_VMCB_RFLAGS, 0x202);
    KswSvmWrite64(&guest, KSW_VMCB_GS, 0xaabbccdd);
    KswSvmWrite32(&guest, KSW_VMCB_MISC1, (1U << 18) | KSW_NSVM_MSR_PROT);
    KswSvmWrite32(&guest, KSW_VMCB_MISC2, 1);
    KswSvmWrite32(&guest, KSW_VMCB_ASID, 1);
    KswSvmWrite64(&guest, KSW_VMCB_NP, 1);
    KswSvmWrite64(&guest, KSW_VMCB_NCR3, outer.RootPa);
    KswSvmWrite64(&guest, KSW_VMCB_PAT, cpu.Caps.Pat);
    KswSvmWrite64(&guest, KSW_VMCB_MSRPM, 0x20000);
    KswSvmWrite64(&guest, KSW_VMCB_IOPM, 0x22000);
    CHECK(KswordSvmNestedBuildProbe(&cpu) == STATUS_SUCCESS);
    CHECK(nested.Sequence == 1 && !nested.Entries && !nested.Reflections);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_RAX) == nested.OperandPa);
    fakeRip = 0x8000;
    traces = 0;
    return 0;
}
static ULONG emit(ULONGLONG code, ULONGLONG rax)
{
    KswSvmWrite64(&guest, KSW_VMCB_EXITCODE, code);
    KswSvmWrite64(&guest, KSW_VMCB_RAX, rax);
    KswSvmWrite64(&guest, KSW_VMCB_RIP, fakeRip);
    KswSvmWrite64(&guest, KSW_VMCB_NRIP, fakeRip + 3);
    fakeRip += 3;
    return KswordSvmNestedProbeExit(&cpu);
}
static ULONG write_msr(ULONG msr, ULONGLONG value)
{
    cpu.Gpr[1] = msr;
    cpu.Gpr[2] = value >> 32;
    KswSvmWrite64(&guest, KSW_VMCB_EXITINFO1, 1);
    return emit(KSW_SVM_EXIT_MSR, (ULONG)value);
}
static int begin(void)
{
    cpu.Gpr[1] = KSW_SVM_CALL_SIGNATURE;
    cpu.Gpr[2] = KSW_NSVM_BEGIN;
    CHECK(emit(KSW_SVM_EXIT_VMMCALL, nested.OperandPa) == 0);
    CHECK(nested.Begun && nested.OriginalGpr[3] == 0x1122334455667788ULL);
    KswSvmWrite64(&guest, KSW_VMCB_RFLAGS, 2);
    cpu.Gpr[1] = cpu.Gpr[2] = 0;
    CHECK(emit(0x8d, 1) == 0 && cpu.GuestXcr0 == 1 && nested.Xcr0Writes == 1);
    CHECK(write_msr(KSW_SVM_MSR_EFER, 0x1d01) == 0);
    CHECK(write_msr(KSW_SVM_MSR_HSAVE, nested.OperandPa + 4096) == 0);
    KswSvmWrite32(operand, KSW_VMCB_ASID, 0);
    CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 0);
    CHECK(nested.Session.InvalidEntries == 1 && !nested.Entries && !nested.RunningL2);
    CHECK(KswSvmRead64(operand, KSW_VMCB_EXITCODE) == ~0ULL);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_RIP) == fakeRip);
    KswSvmWrite32(operand, KSW_VMCB_ASID, 1);
    CHECK(emit(0x84, nested.OperandPa) == 0);
    return 0;
}
static int test_roundtrip(void)
{
    ULONGLONG continuation;
    if (initialize() || begin()) { return 1; }
    KswSvmWrite64(operand, KSW_VMCB_GS, 0xbeef);
    CHECK(emit(0x82, nested.OperandPa) == 0 && KswSvmRead64(&guest, KSW_VMCB_GS) == 0xbeef);
    continuation = fakeRip + 3;
    CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 0);
    CHECK(nested.RunningL2 && nested.Entries == 1 && !nested.Reflections);
    CHECK(nested.Session.Permissions.Ready == 1 && merged[0x820] == 3);
    CHECK(nested.LastOperand.Status == KSW_NNPT_OK && nested.LastOperand.Words == 512);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_MSRPM) == 0x80000);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_IOPM) == 0x82000);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_NCR3) == nested.Pages[0].Physical);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_RIP) == (ULONGLONG)(ULONG_PTR)KswordSvmAsmNestedPayload);
    KswSvmWrite64(&guest, KSW_VMCB_EXITINFO1, KSW_NMMU_FINAL | 6);
    KswSvmWrite64(&guest, KSW_VMCB_EXITINFO2, 0x2123);
    KswSvmWrite64(&guest, KSW_VMCB_EXITINTINFO, 0x1080000b0dULL);
    CHECK(emit(KSW_SVM_EXIT_NPF, 0) == 0);
    CHECK(nested.Faults == 1 && nested.LastTranslation.Status == KSW_NNPT_OK && nested.Shadow.Used == 4);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_EVENT) == 0x1080000b0dULL);
    KswSvmWrite64(&guest, KSW_VMCB_EXITINTINFO, 0);
    CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_INNER_MARKER) == 0);
    CHECK(!nested.RunningL2 && nested.Reflections == 1 && nested.LastMarker == KSW_NSVM_INNER_MARKER);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_RIP) == continuation);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_RAX) == nested.OperandPa);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_MSRPM) == 0x20000);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_IOPM) == 0x22000);
    CHECK(KswSvmRead64(operand, KSW_VMCB_EXITCODE) == KSW_SVM_EXIT_CPUID);
    CHECK(KswSvmRead64(operand, KSW_VMCB_GS) == 0xbeef);
    CHECK(cpu.GuestXcr0 == 1); /* Reflection must not implicitly restore L1's XCR0. */
    cpu.Gpr[1] = cpu.Gpr[2] = 0;
    CHECK(emit(0x8d, cpu.HostXcr0) == 0 && cpu.GuestXcr0 == 0xe7 && nested.Xcr0Writes == 2);
    CHECK(emit(0x83, nested.OperandPa) == 0);
    CHECK(emit(0x84, nested.OperandPa) == 0 && nested.VirtualGif);
    CHECK(write_msr(KSW_SVM_MSR_HSAVE, 0) == 0);
    CHECK(write_msr(KSW_SVM_MSR_EFER, 0xd01) == 0);
    cpu.Gpr[3] = 0xdeaddead;
    CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_DONE_MARKER) == 1);
    CHECK(cpu.Result == STATUS_SUCCESS && !nested.RunningL2 && traces == 0);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_RSP) == cpu.LaunchRsp && KswSvmRead64(&guest, KSW_VMCB_RFLAGS) == 0x202);
    CHECK(KswSvmRead64(&guest, KSW_VMCB_GS) == 0xaabbccdd && cpu.Gpr[3] == 0x1122334455667788ULL);
    CHECK(nested.Sequence == 1); /* Only real native MSR readback may publish an even sequence. */
    return 0;
}
static int test_failures(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 9; ++scenario) {
        if (initialize() || begin()) { return 1; }
        if (scenario == 0) { CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_DONE_MARKER) == 1); }
        if (scenario == 1) { CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa + 4096) == 1); }
        if (scenario == 2) { CHECK(write_msr(KSW_SVM_MSR_EFER, 0xffff) == 1); }
        if (scenario == 3) {
            KswSvmWrite64(&guest, KSW_VMCB_RFLAGS, 0x202);
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 1);
        }
        if (scenario == 7) {
            KswSvmWrite64(operand, KSW_VMCB_MSRPM, 0x70000);
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 1);
            CHECK(!nested.Session.Permissions.Ready && !nested.Entries);
        }
        if (scenario == 8) {
            /* Hardware CPUID trapped by L0 cannot falsely count as an L1-requested exit. */
            KswSvmWrite32(operand, KSW_VMCB_MISC1, KSW_NSVM_MSR_PROT);
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 0);
            CHECK(emit(KSW_SVM_EXIT_CPUID, KSW_NSVM_INNER_MARKER) == 1);
            CHECK(!nested.Reflections);
        }
        if (scenario >= 4 && scenario < 7) {
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 0);
            if (scenario == 4) { CHECK(emit(KSW_SVM_EXIT_CPUID, 0) == 1); }
            if (scenario == 5) { CHECK(emit(KSW_SVM_EXIT_INVALID, 0) == 1); }
            if (scenario == 6) {
                KswSvmWrite64(&guest, KSW_VMCB_EXITINFO1, KSW_NMMU_FINAL | 6);
                KswSvmWrite64(&guest, KSW_VMCB_EXITINFO2, 1ULL << 45);
                CHECK(emit(KSW_SVM_EXIT_NPF, 0) == 1);
            }
        }
        CHECK(!NT_SUCCESS(cpu.Result) && !nested.RunningL2 && traces == 1);
        CHECK(KswSvmRead64(&guest, KSW_VMCB_RSP) == cpu.LaunchRsp);
        CHECK(KswSvmRead64(&guest, KSW_VMCB_CR3) == 0x12345000);
        CHECK(cpu.Gpr[3] == 0x1122334455667788ULL);
        CHECK(cpu.GuestXcr0 == cpu.HostXcr0); /* Only the bounded abort restores the entry mask. */
    }
    return 0;
}
static int test_nonidentity_permissions(void)
{
    if (initialize() || begin()) { return 1; }
    /* These L1 GPAs are not equal to the owned physical map addresses. */
    memory[4][48] = 0x20007; memory[4][49] = 0x21007;
    KswSvmWrite64(operand, KSW_VMCB_MSRPM, 0x30000);
    CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 0);
    CHECK(nested.LastOperand.GuestPa == 0x31000 && nested.LastOperand.HostPa == 0x21000);
    CHECK(nested.Session.Permissions.Ready && nested.Session.Permissions.Msr[0x820] == 3 && merged[0x820] == 3);
    /* Outer protections survive an inner map containing no requested intercepts. */
    if (initialize() || begin()) { return 1; }
    KswSvmWrite64(operand, KSW_VMCB_MSRPM, 0x30000);
    CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 0);
    CHECK(nested.Session.Permissions.Msr[0x820] == 0 && merged[0x820] == 3);
    return 0;
}
static int test_xcr0_failures(void)
{
    unsigned scenario;
    for (scenario = 0; scenario < 7; ++scenario) {
        if (initialize() || begin()) { return 1; }
        cpu.Gpr[1] = cpu.Gpr[2] = 0;
        switch (scenario) {
        case 0: /* Duplicated reduction may not masquerade as the required restoration. */
            CHECK(emit(0x8d, 1) == 1); break;
        case 1: /* Full mask restored before inner reflection is not an exercised transition. */
            CHECK(emit(0x8d, cpu.HostXcr0) == 1); break;
        case 2: /* Host policy must never expand to an unallocated component. */
            CHECK(emit(0x8d, 0x207) == 1); break;
        case 3: /* A malformed architectural operand must not reach the assembler. */
            CHECK(emit(0x8d, 5) == 1); break;
        case 4: /* VMEXIT/VMRUN cannot reset a shared XCR0 register implicitly. */
            cpu.GuestXcr0 = cpu.HostXcr0;
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 1); break;
        case 5: /* A shortened probe omitting XSETBV may not reach the inner entry. */
            nested.Xcr0Writes = 0;
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 1); break;
        case 6: /* Interrupted inner execution must also restore the bounded Windows mask. */
            CHECK(emit(KSW_SVM_EXIT_VMRUN, nested.OperandPa) == 0);
            CHECK(emit(0x8d, 1) == 1); break;
        }
        CHECK(!NT_SUCCESS(cpu.Result) && !nested.RunningL2);
        CHECK(cpu.GuestXcr0 == cpu.HostXcr0);
    }
    if (initialize()) { return 1; }
    cpu.HostXcr0 = 0x207; /* Unknown component dependencies need an implementation first. */
    CHECK(KswordSvmNestedBuildProbe(&cpu) == STATUS_NOT_SUPPORTED);
    cpu.HostXcr0 = 1; /* Root C requires a prepared native SSE state. */
    CHECK(KswordSvmNestedBuildProbe(&cpu) == STATUS_NOT_SUPPORTED);
    return 0;
}
int main(void)
{
    if (test_roundtrip() || test_failures() || test_nonidentity_permissions() || test_xcr0_failures()) { return 1; }
    printf("SVM_PRODUCTION_DISPATCH_CHECKS=%u RESULT=PASS (simulated exits, no hardware)\n", checks);
    return 0;
}
