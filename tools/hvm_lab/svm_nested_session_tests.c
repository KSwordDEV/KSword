/* Production transaction tests; eight host threads simulate independent nested vCPUs. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_session.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
typedef struct _MODEL {
    KSW_NSVM_SESSION session;
    KSW_NSVM_SESSION_IO io;
    KSW_NSVM_OWNER_TABLE owners;
    KSW_NMMU_CONFIG mmu;
    KSW_NSHADOW shadow;
    KSW_NSHADOW_PAGE pages[4];
    KSW_SVM_U64 ram[16][512];
    KSW_SVM_VMCB current, before;
    unsigned char msr[8192], iopm[12288], mergedMsr[8192], mergedIo[12288];
    unsigned failCommit, commitCalls, iterations, id;
} MODEL;
static MODEL model[8];
__declspec(align(4096)) static KSW_SVM_U64 tables[8][4][512];

static int read_word(void* context, KSW_SVM_U64 pa, KSW_SVM_U64* value)
{
    MODEL* m = context;
    if ((pa & 7) || pa >= sizeof(m->ram)) { return 0; }
    *value = m->ram[pa >> 12][(pa & 4095) / 8]; return 1;
}
static int commit(void* context, KSW_SVM_U64 pa, const KSW_SVM_VMCB* image,
    unsigned op, unsigned np, unsigned* written)
{
    MODEL* m = context;
    unsigned offset;
    *written = 0; ++m->commitCalls;
    if (pa != 0x6000 || m->failCommit == 1) { return 0; }
    for (offset = 0; offset < 4096; offset += 8) {
        KSW_SVM_U64 mask = KswSvmNestedWritebackMask(offset, op, np);
        if (mask) {
            m->ram[6][offset / 8] = (m->ram[6][offset / 8] & ~mask) | (KswSvmRead64(image, offset) & mask);
            ++*written;
            if (m->failCommit == 2) { return 0; }
        }
    }
    return 1;
}
static int initialize(MODEL* m, unsigned id)
{
    unsigned i;
    KSW_SVM_VMCB* operand;
    memset(m, 0, sizeof(*m)); m->id = id;
    m->io.Owners = &m->owners; m->io.CpuIdentity = id;
    m->ram[1][0] = 0x2007; m->ram[2][0] = 0x3007; m->ram[3][0] = 0x4007;
    m->ram[4][9] = 0x6007;
    operand = (KSW_SVM_VMCB*)m->ram[6];
    KswSvmWrite64(operand, KSW_VMCB_EFER, 0x1d01);
    KswSvmWrite64(operand, KSW_VMCB_CR0, 0x80010001);
    KswSvmWrite64(operand, KSW_VMCB_CR4, 0x20);
    ((unsigned char*)operand)[KSW_VMCB_CS + 3] = 2;
    KswSvmWrite64(operand, KSW_VMCB_NP, 1);
    KswSvmWrite64(operand, KSW_VMCB_NCR3, 0x7000);
    KswSvmWrite64(operand, KSW_VMCB_PAT, 0x0606060606060606ULL);
    KswSvmWrite64(operand, KSW_VMCB_RIP, 0x12000 + id * 0x1000);
    KswSvmWrite64(operand, KSW_VMCB_RSP, 0xabc000 + id * 0x1000);
    KswSvmWrite32(operand, KSW_VMCB_ASID, 1);
    KswSvmWrite32(operand, KSW_VMCB_MISC2, 1);
    KswSvmWrite32(operand, KSW_VMCB_MISC1, 1U << 18);
    m->current = *operand;
    KswSvmWrite64(&m->current, KSW_VMCB_RIP, 0x8000);
    KswSvmWrite64(&m->current, KSW_VMCB_NRIP, 0x8003);
    KswSvmWrite64(&m->current, KSW_VMCB_RAX, 0x9000);
    KswSvmWrite64(&m->current, KSW_VMCB_RSP, 0x100000);
    KswSvmWrite64(&m->current, KSW_VMCB_PAT, 0x0007010600070106ULL);
    for (i = 0; i < 4; ++i) { m->pages[i].Words = tables[id][i]; m->pages[i].Physical = 0x100000 + id * 0x10000 + i * 4096ULL; }
    if (KswSvmNestedShadowInitialize(&m->shadow, m->pages, 4, 45)) { return 0; }
    m->io.Policy.PhysicalBits = 45; m->io.Policy.AsidCount = 64;
    m->io.Policy.Cr4Supported = 0x20; m->io.Policy.EferSupported = 0x1d01;
    m->io.Operand.Root = 0x1000; m->io.Operand.Pat = 0x0007010600070106ULL;
    m->io.Operand.PhysicalBits = 45; m->io.Operand.Page1Gb = 1; m->io.Operand.Nx = 1;
    m->io.Operand.Read = read_word; m->io.Operand.Context = m; m->io.Commit = commit;
    m->io.MergedMsr = m->mergedMsr; m->io.MergedIo = m->mergedIo;
    m->io.MsrPa = 0x400000 + id * 0x10000; m->io.IoPa = m->io.MsrPa + 8192; m->io.Asid = id + 1;
    m->io.OuterPermissions.Flags = KSW_NSVM_MSR_PROT | KSW_NSVM_IOIO_PROT;
    m->io.OuterPermissions.Msr = m->msr; m->io.OuterPermissions.Io = m->iopm;
    m->msr[0x820] = 3; m->io.Shadow = &m->shadow; m->io.Mmu = &m->mmu;
    m->before = m->current;
    return 1;
}
static unsigned enter(MODEL* m)
{
    return KswSvmNestedSessionEnter(&m->session, &m->io, &m->current, 0x9000);
}
static void exit_cpuid(MODEL* m)
{
    KswSvmWrite64(&m->current, KSW_VMCB_EXITCODE, 0x72);
    KswSvmWrite64(&m->current, KSW_VMCB_RAX, 0x44550000 + m->id);
    KswSvmWrite64(&m->current, KSW_VMCB_CR2, 0x98760000 + m->id);
}
static int test_transitions(void)
{
    MODEL* m = &model[0];
    KSW_SVM_VMCB* operand = (KSW_SVM_VMCB*)m->ram[6];
    KSW_SVM_U64 epoch;
    CHECK(initialize(m, 0));
    KswSvmWrite32(operand, KSW_VMCB_ASID, 0);
    CHECK(enter(m) == KSW_NSVM_ACTION_INVALID);
    CHECK(m->session.Phase == 0 && m->session.InvalidEntries == 1 && !m->session.Entries && !m->session.VirtualGif);
    CHECK(KswSvmRead64(operand, KSW_VMCB_EXITCODE) == ~0ULL);
    CHECK(KswSvmRead64(&m->current, KSW_VMCB_RIP) == 0x8003);
    CHECK(KswSvmRead64(&m->current, KSW_VMCB_RAX) == 0x9000);
    /* A corrected operand can enter immediately; no native restart/launch snapshot is needed. */
    KswSvmWrite32(operand, KSW_VMCB_ASID, 1);
    KswSvmWrite64(&m->current, KSW_VMCB_NRIP, 0x8006);
    epoch = m->shadow.Epoch;
    CHECK(enter(m) == KSW_NSVM_ACTION_ENTER);
    CHECK(m->session.Phase == 1 && m->session.Entries == 1 && m->shadow.Epoch == epoch + 1);
    CHECK(m->session.OperandPa == 0x9000 && m->session.OperandHostPa == 0x6000);
    CHECK(m->mmu.InnerPat == 0x0007010600070106ULL && m->mmu.InnerRoot == 0x7000);
    CHECK(KswSvmRead64(&m->current, KSW_VMCB_PAT) == 0x0606060606060606ULL);
    CHECK(enter(m) == KSW_NSVM_ACTION_FAULT && m->session.Phase == 1);
    exit_cpuid(m);
    CHECK(KswSvmNestedSessionReflect(&m->session, &m->io, &m->current) == KSW_NSVM_ACTION_RETURN);
    CHECK(m->session.Phase == 0 && m->session.Returns == 1 && !m->session.VirtualGif);
    CHECK(KswSvmRead64(&m->current, KSW_VMCB_RIP) == 0x8006);
    CHECK(KswSvmRead64(&m->current, KSW_VMCB_RAX) == 0x9000);
    CHECK(KswSvmRead64(&m->current, KSW_VMCB_CR2) == 0x98760000);
    CHECK(KswSvmRead64(operand, KSW_VMCB_RAX) == 0x44550000);
    CHECK(KswSvmRead64(operand, KSW_VMCB_NCR3) == 0x7000);
    CHECK(initialize(m, 0));
    KswSvmWrite64(operand, KSW_VMCB_NP, 0);
    CHECK(enter(m) == KSW_NSVM_ACTION_UNSUPPORTED && !m->commitCalls);
    CHECK(!memcmp(&m->current, &m->before, 4096));
    CHECK(initialize(m, 0));
    CHECK(enter(m) == 0); exit_cpuid(m); m->before = m->current; m->failCommit = 2;
    CHECK(KswSvmNestedSessionReflect(&m->session, &m->io, &m->current) == KSW_NSVM_ACTION_FAULT);
    CHECK(m->session.Phase == 2 && m->session.OperandResult.Words == 1 && !m->session.Returns);
    CHECK(!memcmp(&m->current, &m->before, 4096));
    CHECK(enter(m) == KSW_NSVM_ACTION_FAULT);
    CHECK(initialize(m, 0));
    CHECK(enter(m) == 0);
    KswSvmWrite64(&m->current, KSW_VMCB_EXITCODE, ~0ULL);
    CHECK(KswSvmNestedSessionReflect(&m->session, &m->io, &m->current) == KSW_NSVM_ACTION_FAULT);
    CHECK(!m->commitCalls && m->session.Phase == 2);
    return 0;
}
/* Regression for consumed IRQ68 surviving a reflected CR4-write and being injected again. */
static int test_event_consumption(void)
{
    MODEL* m = &model[0];
    KSW_SVM_VMCB* operand = (KSW_SVM_VMCB*)m->ram[6];
    unsigned interrupted;
    for (interrupted = 0; interrupted < 2; ++interrupted) {
        CHECK(initialize(m, 0));
        KswSvmWrite64(operand, KSW_VMCB_EVENT, 0x80000068ULL);
        CHECK(enter(m) == KSW_NSVM_ACTION_ENTER);
        CHECK(KswSvmRead64(&m->current, KSW_VMCB_EVENT) == 0x80000068ULL);
        /* Hardware clears EVENTINJ on exit; interrupted delivery lives in EXITINTINFO. */
        KswSvmWrite64(&m->current, KSW_VMCB_EVENT, 0);
        KswSvmWrite64(&m->current, KSW_VMCB_EXITCODE, interrupted ? 0x400 : 0x14);
        KswSvmWrite64(&m->current, KSW_VMCB_EXITINTINFO, interrupted ? 0x80000068ULL : 0);
        CHECK(KswSvmNestedSessionReflect(&m->session, &m->io, &m->current) == KSW_NSVM_ACTION_RETURN);
        CHECK(KswSvmRead64(operand, KSW_VMCB_EVENT) == 0);
        CHECK(KswSvmRead64(operand, KSW_VMCB_EXITINTINFO) == (interrupted ? 0x80000068ULL : 0));
        /* L1 does not touch EVENTINJ: the next VMRUN must not replay the consumed request. */
        KswSvmWrite64(&m->current, KSW_VMCB_NRIP, KswSvmRead64(&m->current, KSW_VMCB_RIP) + 3);
        CHECK(enter(m) == KSW_NSVM_ACTION_ENTER);
        CHECK(KswSvmRead64(&m->current, KSW_VMCB_EVENT) == 0);
        exit_cpuid(m);
        CHECK(KswSvmNestedSessionReflect(&m->session, &m->io, &m->current) == KSW_NSVM_ACTION_RETURN);
        /* A deliberate new L1 injection remains allowed; this is not global IRQ suppression. */
        KswSvmWrite64(operand, KSW_VMCB_EVENT, 0x80000069ULL);
        KswSvmWrite64(&m->current, KSW_VMCB_NRIP, KswSvmRead64(&m->current, KSW_VMCB_RIP) + 3);
        CHECK(enter(m) == KSW_NSVM_ACTION_ENTER);
        CHECK(KswSvmRead64(&m->current, KSW_VMCB_EVENT) == 0x80000069ULL);
    }
    /* Invalid virtual VMRUN also completes with an architectural exit, not a pending request. */
    CHECK(initialize(m, 0));
    KswSvmWrite32(operand, KSW_VMCB_ASID, 0);
    KswSvmWrite64(operand, KSW_VMCB_EVENT, 0x1234567880000b0dULL);
    CHECK(enter(m) == KSW_NSVM_ACTION_INVALID);
    CHECK(KswSvmRead64(operand, KSW_VMCB_EVENT) == 0);
    return 0;
}
static int cache_roundtrip(MODEL* m)
{
    KSW_SVM_U64 next = KswSvmRead64(&m->current, KSW_VMCB_RIP) + 3;
    KswSvmWrite64(&m->current, KSW_VMCB_NRIP, next);
    CHECK(enter(m) == KSW_NSVM_ACTION_ENTER);
    CHECK(((unsigned char*)&m->current)[KSW_VMCB_TLB] == 1);
    exit_cpuid(m);
    CHECK(KswSvmNestedSessionReflect(&m->session, &m->io, &m->current) == KSW_NSVM_ACTION_RETURN);
    CHECK(KswSvmRead64(&m->current, KSW_VMCB_RIP) == next);
    return 0;
}
static int test_cache_lifetime(void)
{
    MODEL* m = &model[0];
    KSW_SVM_VMCB* operand = (KSW_SVM_VMCB*)m->ram[6];
    KSW_NSVM_LEASE other = {0};
    KSW_NMMU_RESULT mapping = {0};
    KSW_SVM_U64 epoch, token;
    unsigned scenario, i;
    for (scenario = 0; scenario < 17; ++scenario) {
        CHECK(initialize(m, 0)); m->io.ReuseNpt = 1;
        CHECK(cache_roundtrip(m) == 0);
        epoch = m->shadow.Epoch;
        mapping.Status = KSW_NNPT_OK; mapping.Gpa = 0x1000; mapping.Epoch = epoch; mapping.Leaf = 0x3067;
        mapping.Inner.Complete = mapping.Outer.Complete = 1;
        mapping.Inner.InputAddress = 0x1000; mapping.Inner.Address = 0x2000;
        mapping.Outer.InputAddress = 0x2000; mapping.Outer.Address = 0x3000;
        mapping.Inner.Permissions = mapping.Outer.Permissions = 7;
        mapping.Inner.LeafShift = mapping.Outer.LeafShift = 12;
        CHECK(KswSvmNestedShadowInstall(&m->shadow, &mapping) == KSW_NSHADOW_OK);
        for (i = 0; i < 8; ++i) {
            CHECK(cache_roundtrip(m) == 0);
            CHECK(m->shadow.Epoch == epoch);
            CHECK(m->shadow.Used == 4 && m->pages[0].Words[0] == (m->pages[1].Physical | 7ULL));
            CHECK(m->pages[3].Words[1] == 0x3067);
        }
        switch (scenario) {
        case 0: ((unsigned char*)operand)[KSW_VMCB_TLB] = 1; break;
        case 1: ((unsigned char*)operand)[KSW_VMCB_TLB] = 3; break;
        case 2: ((unsigned char*)operand)[KSW_VMCB_TLB] = 7; break;
        case 3: KswSvmWrite32(operand, KSW_VMCB_ASID, 2); break;
        case 4: KswSvmWrite64(operand, KSW_VMCB_NCR3, 0x8000); break;
        case 5: KswSvmWrite64(&m->current, KSW_VMCB_CR3, 0x1000); break;
        case 6: KswSvmWrite64(&m->current, KSW_VMCB_PAT, 0x0606060606060606ULL); break;
        case 7: KswSvmWrite64(&m->current, KSW_VMCB_CR4, 0x30); break;
        case 8: KswSvmWrite64(&m->current, KSW_VMCB_EFER, 0x1501); break;
        case 9: KswSvmWrite64(&m->current, KSW_VMCB_CR0, 0x80010011); break;
        case 10: m->mmu.OuterRoot = 0x2000; break;
        case 11: m->mmu.OuterPat = 0x0606060606060606ULL; break;
        case 12: m->mmu.HardwarePat = 0x0606060606060606ULL; break;
        case 13: m->io.ReuseNpt = 0; break;
        case 14:
            token = m->session.CacheOwnerToken;
            CHECK(KswSvmNestedOwnerAcquire(&m->owners, 0x6000, 1, &other) == KSW_NSVM_LEASE_OK);
            CHECK(other.PreviousToken == token);
            CHECK(KswSvmNestedOwnerRelease(&m->owners, &other));
            break;
        case 15:
            CHECK(KswSvmNestedSessionInvalidate(&m->session, &m->io, 0x12345000, 1) == KSW_NSVM_ACTION_RETURN);
            CHECK(m->pages[0].Words[0] == 0);
            break;
        default:
            CHECK(KswSvmNestedShadowReset(&m->shadow) == KSW_NSHADOW_OK);
            CHECK(m->pages[0].Words[0] == 0);
            break;
        }
        CHECK(cache_roundtrip(m) == 0);
        CHECK(m->shadow.Epoch > epoch && m->pages[0].Words[0] == 0 && m->shadow.Used == 1);
        CHECK(KswSvmNestedShadowInstall(&m->shadow, &mapping) == KSW_NSHADOW_STALE);
        mapping.Epoch = m->shadow.Epoch; mapping.Leaf = 0x5065;
        mapping.Outer.Address = 0x5000; mapping.Inner.Permissions = 5;
        CHECK(KswSvmNestedShadowInstall(&m->shadow, &mapping) == KSW_NSHADOW_OK);
        CHECK(m->pages[3].Words[1] == 0x5065);
        epoch = m->shadow.Epoch;
        ((unsigned char*)operand)[KSW_VMCB_TLB] = 0;
        m->io.ReuseNpt = 1;
        CHECK(cache_roundtrip(m) == 0);
        CHECK(m->shadow.Epoch == epoch);
    }
    return 0;
}
static int cache_transfer(MODEL* m, KSW_SVM_U64 pa, unsigned save)
{
    KSW_SVM_U64 next = KswSvmRead64(&m->current, KSW_VMCB_RIP) + 3;
    KswSvmWrite64(&m->current, KSW_VMCB_NRIP, next);
    CHECK(KswSvmNestedSessionTransfer(&m->session, &m->io, &m->current, pa, save) == KSW_NSVM_ACTION_RETURN);
    CHECK(!m->session.Lease.Token && m->session.Phase == KSW_NSVM_SESSION_IDLE);
    KswSvmWrite64(&m->current, KSW_VMCB_RIP, next);
    return 0;
}
static int test_cache_transfer_chain(void)
{
    MODEL* m = &model[0];
    KSW_NMMU_RESULT mapping = {0};
    KSW_NSVM_LEASE other = {0};
    KSW_SVM_U64 epoch, token;
    unsigned scenario, i;
    for (scenario = 0; scenario < 6; ++scenario) {
        CHECK(initialize(m, 0)); m->io.ReuseNpt = 1;
        m->ram[4][10] = 0x7007;
        memcpy(m->ram[7], m->ram[6], 4096);
        CHECK(cache_roundtrip(m) == 0);
        epoch = m->shadow.Epoch;
        mapping.Status = KSW_NNPT_OK; mapping.Gpa = 0x1000; mapping.Epoch = epoch; mapping.Leaf = 0x3067;
        mapping.Inner.Complete = mapping.Outer.Complete = 1;
        mapping.Inner.InputAddress = 0x1000; mapping.Inner.Address = 0x2000;
        mapping.Outer.InputAddress = 0x2000; mapping.Outer.Address = 0x3000;
        mapping.Inner.Permissions = mapping.Outer.Permissions = 7;
        mapping.Inner.LeafShift = mapping.Outer.LeafShift = 12;
        CHECK(KswSvmNestedShadowInstall(&m->shadow, &mapping) == KSW_NSHADOW_OK);
        for (i = 0; i < 8; ++i) {
            CHECK(cache_transfer(m, 0x9000, 1) == 0);
            token = m->session.CacheOwnerToken;
            CHECK(cache_transfer(m, 0xa000, 0) == 0);
            CHECK(m->session.CacheOwnerToken == token);
            CHECK(cache_transfer(m, 0x9000, 0) == 0);
            CHECK(cache_roundtrip(m) == 0);
            CHECK(m->shadow.Epoch == epoch && m->shadow.Used == 4);
            CHECK(m->pages[3].Words[1] == 0x3067);
        }
        token = m->session.CacheOwnerToken;
        if (scenario < 2) {
            CHECK(KswSvmNestedOwnerAcquire(&m->owners, 0x6000, scenario, &other) == KSW_NSVM_LEASE_OK);
            CHECK(KswSvmNestedOwnerRelease(&m->owners, &other));
            CHECK(cache_transfer(m, 0x9000, scenario) == 0);
            CHECK(m->session.CacheOwnerToken == token);
        } else if (scenario < 4) {
            m->failCommit = scenario - 1;
            KswSvmWrite64(&m->current, KSW_VMCB_NRIP, KswSvmRead64(&m->current, KSW_VMCB_RIP) + 3);
            CHECK(KswSvmNestedSessionTransfer(&m->session, &m->io, &m->current, 0x9000, 1) == KSW_NSVM_ACTION_FAULT);
            CHECK(m->session.CacheOwnerToken == token && m->session.Lease.Token);
            CHECK(m->session.Phase == KSW_NSVM_SESSION_FAULTED);
            CHECK(m->session.OperandResult.Words == (scenario == 3 ? 1U : 0U));
            continue;
        } else if (scenario == 4) {
            CHECK(cache_transfer(m, 0x9000, 0) == 0);
            ((unsigned char*)m->ram[6])[KSW_VMCB_TLB] = 1;
        } else {
            CHECK(cache_transfer(m, 0x9000, 1) == 0);
            KswSvmWrite64((KSW_SVM_VMCB*)m->ram[6], KSW_VMCB_NCR3, 0x8000);
        }
        CHECK(cache_roundtrip(m) == 0);
        CHECK(m->shadow.Epoch > epoch && m->shadow.Used == 1 && !m->pages[0].Words[0]);
        CHECK(KswSvmNestedShadowInstall(&m->shadow, &mapping) == KSW_NSHADOW_STALE);
    }
    return 0;
}
static DWORD WINAPI run_parallel(void* argument)
{
    MODEL* m = argument;
    unsigned iteration;
    for (iteration = 0; iteration < 100; ++iteration) {
        KSW_SVM_U64 next = KswSvmRead64(&m->current, KSW_VMCB_RIP) + 3;
        KswSvmWrite64(&m->current, KSW_VMCB_NRIP, next);
        if (enter(m) != 0 || m->session.Phase != 1 || m->mergedMsr[0x820] != 3 ||
            KswSvmRead64(&m->current, KSW_VMCB_NCR3) != m->pages[0].Physical) { return 1; }
        exit_cpuid(m); SwitchToThread();
        if (KswSvmNestedSessionReflect(&m->session, &m->io, &m->current) != 1 ||
            KswSvmRead64(&m->current, KSW_VMCB_RIP) != next ||
            KswSvmRead64(&m->current, KSW_VMCB_RAX) != 0x9000 ||
            KswSvmRead64(&m->current, KSW_VMCB_CR2) != 0x98760000 + m->id || m->session.Phase) { return 2; }
        ++m->iterations;
    }
    return 0;
}
int main(void)
{
    HANDLE threads[8]; unsigned i; DWORD resultCode;
    if (test_transitions() || test_event_consumption() || test_cache_lifetime() || test_cache_transfer_chain()) { return 1; }
    for (i = 0; i < 8; ++i) { CHECK(initialize(&model[i], i)); threads[i] = CreateThread(NULL, 0, run_parallel, &model[i], 0, NULL); CHECK(threads[i]); }
    CHECK(WaitForMultipleObjects(8, threads, TRUE, 30000) == WAIT_OBJECT_0);
    for (i = 0; i < 8; ++i) {
        CHECK(GetExitCodeThread(threads[i], &resultCode) && resultCode == 0); CloseHandle(threads[i]);
        CHECK(model[i].iterations == 100 && model[i].session.Entries == 100 && model[i].session.Returns == 100);
    }
    printf("SVM_SESSION_CHECKS=%u RESULT=PASS (8 host threads x 100 simulated transitions; no hardware)\n", checks);
    return 0;
}
