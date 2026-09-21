/* Exercise admission and architectural host return using the production builder. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_entry.h"

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static KSW_SVM_VMCB inner, outer, combined, saved;
static KSW_NSVM_ENTRY_POLICY policy = {45, 64, 0x1d01, 0x800020};
static KSW_NSVM_ENTRY_RESULT result;

static void initialize(void)
{
    memset(&inner, 0, sizeof(inner));
    memset(&outer, 0, sizeof(outer));
    memset(&combined, 0xa5, sizeof(combined));
    KswSvmWrite64(&inner, KSW_VMCB_EFER, 0x1d01);
    KswSvmWrite64(&inner, KSW_VMCB_CR0, 0x80010001);
    KswSvmWrite64(&inner, KSW_VMCB_CR4, 0x20);
    ((unsigned char*)&inner)[KSW_VMCB_CS + 3] = 2;
    KswSvmWrite64(&inner, KSW_VMCB_PAT, 0x0007010600070106ULL);
    KswSvmWrite64(&inner, KSW_VMCB_NP, 1);
    KswSvmWrite64(&inner, KSW_VMCB_NCR3, 0x1000);
    KswSvmWrite64(&inner, KSW_VMCB_MSRPM, 0x2001);
    KswSvmWrite64(&inner, KSW_VMCB_IOPM, 0x4002);
    KswSvmWrite32(&inner, KSW_VMCB_MISC2, 1);
    KswSvmWrite32(&inner, KSW_VMCB_ASID, 63);
}

static int rejected(unsigned offset, KSW_SVM_U64 value, unsigned status)
{
    initialize();
    KswSvmWrite64(&inner, offset, value);
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == status);
    CHECK(result.Offset == offset && result.Value == value && result.Status == status);
    return 0;
}

static int test_admission(void)
{
    unsigned type, vector, valid;
    initialize();
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == KSW_NSVM_ENTRY_OK);
    CHECK(result.Status == 0 && result.Offset == 0 && result.Value == 0);
    if (rejected(KSW_VMCB_CR0, 0x100000000ULL, 1) || rejected(KSW_VMCB_CR0, 0x20000001, 1) ||
        rejected(KSW_VMCB_EFER, 0xd01, 1) || rejected(KSW_VMCB_DR7, 1ULL << 32, 1) ||
        rejected(KSW_VMCB_DR6, 1ULL << 32, 1) || rejected(KSW_VMCB_ASID, 0, 1) ||
        rejected(KSW_VMCB_ASID, 64, 1) || rejected(KSW_VMCB_MISC2, 0, 1) ||
        rejected(KSW_VMCB_MSRPM, (1ULL << 45) - 4096, 1) ||
        rejected(KSW_VMCB_IOPM, (1ULL << 45) - 8192, 1) ||
        rejected(KSW_VMCB_EFER, 0x80001d01, 2) || rejected(KSW_VMCB_CR4, 0x100020, 2) ||
        rejected(KSW_VMCB_NP, 0, 2) || rejected(KSW_VMCB_NP, 3, 2) ||
        rejected(KSW_VMCB_NCR3, 0x1008, 2) || rejected(KSW_VMCB_S_CET, 1, 2) ||
        rejected(0xb8, 1, 2) || rejected(0x14, 1, 2) || rejected(KSW_VMCB_DEBUGCTL, 1, 2) ||
        rejected(0x68, 2, 2) || rejected(KSW_VMCB_INTCTL, 1ULL << 25, 2)) { return 1; }
    initialize();
    KswSvmWrite64(&inner, KSW_VMCB_CR4, 0);
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == 1 && result.Offset == KSW_VMCB_CR4);
    /* Paged real mode is explicitly permitted when long mode is not requested. */
    KswSvmWrite64(&inner, KSW_VMCB_EFER, 0x1000);
    KswSvmWrite64(&inner, KSW_VMCB_CR0, 0x80000000);
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == 0);
    initialize();
    ((unsigned char*)&inner)[KSW_VMCB_CS + 3] = 6;
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == 1 && result.Offset == KSW_VMCB_CS);
    initialize();
    KswSvmWrite64(&inner, KSW_VMCB_CR4, 0x800020);
    KswSvmWrite64(&inner, KSW_VMCB_CR0, 0x80000001);
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == 1 && result.Offset == KSW_VMCB_CR0);
    initialize();
    KswSvmWrite64(&inner, KSW_VMCB_RIP, 0x1234000000000000ULL);
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == 0);
    for (type = 0; type < 256; ++type) {
        initialize();
        KswSvmWrite64(&inner, KSW_VMCB_PAT, (KswSvmRead64(&inner, KSW_VMCB_PAT) & ~255ULL) | type);
        CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) ==
            ((type > 7 || type == 2 || type == 3) ? 1U : 0U));
    }
    /* Disabled EVENTINJ ignores stale type/vector/reserved fields. */
    for (valid = 0; valid < 2; ++valid) {
        for (type = 0; type < 8; ++type) {
            for (vector = 0; vector < 256; ++vector) {
                unsigned expected = 0;
                initialize();
                KswSvmWrite64(&inner, KSW_VMCB_EVENT, ((KSW_SVM_U64)valid << 31) | (type << 8) | vector);
                if (valid && ((type != 0 && type != 2 && type != 3 && type != 4) ||
                    (type == 3 && (vector == 2 || vector == 5 || vector > 31)))) { expected = 1; }
                CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == expected);
            }
        }
    }
    initialize();
    KswSvmWrite64(&inner, KSW_VMCB_EVENT, 0x7ffff000);
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == 0);
    KswSvmWrite64(&inner, KSW_VMCB_EVENT, 0xfffff000);
    CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) == 2);
    for (type = 0; type < 256; ++type) {
        initialize();
        ((unsigned char*)&inner)[KSW_VMCB_TLB] = (unsigned char)type;
        CHECK(KswSvmNestedValidateEntry(&inner, &policy, &result) ==
            ((type == 0 || type == 1 || type == 3 || type == 7) ? 0U : 2U));
    }
    CHECK(KswSvmNestedValidateEntry(NULL, &policy, &result) == 2);
    CHECK(KswSvmNestedValidateEntry(&inner, NULL, &result) == 2);
    return 0;
}

static int test_build(void)
{
    unsigned offset;
    initialize();
    KswSvmWrite64(&outer, KSW_VMCB_GS + 8, 0x11111111);
    KswSvmWrite64(&inner, KSW_VMCB_GS + 8, 0x22222222);
    KswSvmWrite64(&outer, KSW_VMCB_STAR, 0x33333333);
    KswSvmWrite64(&inner, KSW_VMCB_STAR, 0x44444444);
    KswSvmWrite64(&inner, KSW_VMCB_RAX, 0x1234);
    KswSvmWrite64(&inner, KSW_VMCB_RIP, 0x5678);
    KswSvmWrite64(&inner, KSW_VMCB_RSP, 0x9abc);
    KswSvmWrite64(&outer, 0x50, ~0ULL - 8);
    KswSvmWrite64(&inner, 0x50, 10);
    for (offset = 0; offset < 0x14; offset += 4) { KswSvmWrite32(&outer, offset, 0x101); }
    KswSvmWrite32(&inner, KSW_VMCB_MISC1, 0x40000);
    KswSvmWrite32(&inner, KSW_VMCB_CLEAN, ~0U);
    KswSvmWrite64(&inner, KSW_VMCB_INTCTL, 0xab01080103ULL);
    KswSvmWrite64(&inner, KSW_VMCB_EVENT, 0x80000480);
    KswSvmWrite64(&inner, KSW_VMCB_NRIP, 0x567a);
    KswSvmWrite64(&inner, 0x68, 1);
    CHECK(KswSvmNestedBuildEntry(&combined, &outer, &inner, &policy, 0x9000, 0xa000, 0xc000, 2, &result) == 0);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_GS + 8) == 0x11111111);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_STAR) == 0x33333333);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_RAX) == 0x1234);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_RIP) == 0x5678);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_RSP) == 0x9abc);
    CHECK(KswSvmRead64(&combined, 0x50) == 1);
    CHECK(*(unsigned*)(combined.control + KSW_VMCB_MISC1) == 0x40101);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_NCR3) == 0x9000);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_MSRPM) == 0xa000);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_IOPM) == 0xc000);
    CHECK(*(unsigned*)(combined.control + KSW_VMCB_ASID) == 2);
    CHECK(combined.control[KSW_VMCB_TLB] == 1);
    CHECK(*(unsigned*)(combined.control + KSW_VMCB_CLEAN) == 0);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_INTCTL) == 0xab01080103ULL);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_EVENT) == 0x80000480);
    CHECK(KswSvmRead64(&combined, KSW_VMCB_NRIP) == 0x567a);
    CHECK(KswSvmRead64(&combined, 0x68) == 1);
    saved = combined;
    CHECK(KswSvmNestedBuildEntry(&combined, &outer, &inner, &policy, 0x9001, 0xa000, 0xc000, 2, &result) == 2);
    CHECK(memcmp(&saved, &combined, sizeof(saved)) == 0);
    KswSvmWrite32(&inner, KSW_VMCB_ASID, 0);
    CHECK(KswSvmNestedBuildEntry(&combined, &outer, &inner, &policy, 0x9000, 0xa000, 0xc000, 2, &result) == 1);
    CHECK(memcmp(&saved, &combined, sizeof(saved)) == 0);
    KswSvmWrite32(&inner, KSW_VMCB_ASID, 1);
    CHECK(KswSvmNestedBuildEntry(&outer, &outer, &inner, &policy, 0x9000, 0xa000, 0xc000, 2, &result) == 0);
    CHECK(memcmp(&saved, &outer, sizeof(saved)) == 0);
    CHECK(KswSvmNestedBuildEntry(&inner, &outer, &inner, &policy, 0x9000, 0xa000, 0xc000, 2, &result) == 2);
    return 0;
}

static int test_return(void)
{
    unsigned index;
    initialize();
    memset(&inner, 0x5a, sizeof(inner));
    saved = inner;
    KswSvmNestedInvalidExit(&inner);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_EXITCODE) == ~0ULL);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_EXITINFO1) == 0);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_EXITINFO2) == 0);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_EXITINTINFO) == 0);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_EVENT) == 0);
    for (index = 0; index < 4096; ++index) {
        if ((index < KSW_VMCB_EXITCODE || index >= KSW_VMCB_EXITCODE + 32) &&
            (index < KSW_VMCB_EVENT || index >= KSW_VMCB_EVENT + 8)) {
            CHECK(((unsigned char*)&inner)[index] == ((unsigned char*)&saved)[index]);
        }
    }
    initialize();
    KswSvmWrite64(&outer, KSW_VMCB_RAX, 0x1000);
    KswSvmWrite64(&outer, KSW_VMCB_RIP, 0x2000);
    KswSvmWrite64(&outer, KSW_VMCB_RSP, 0x3000);
    KswSvmWrite64(&outer, KSW_VMCB_CR3, 0x4000);
    KswSvmWrite64(&outer, KSW_VMCB_RFLAGS, 0x30202);
    KswSvmWrite64(&inner, KSW_VMCB_CR2, 0x5555);
    KswSvmWrite64(&inner, KSW_VMCB_DR6, 0x6666);
    KswSvmWrite64(&inner, KSW_VMCB_GS + 8, 0x7777);
    KswSvmWrite64(&inner, KSW_VMCB_STAR, 0x8888);
    KswSvmNestedRestoreL1(&inner, &outer, &inner);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_RAX) == 0x1000);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_RIP) == 0x2000);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_RSP) == 0x3000);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_CR3) == 0x4000);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_RFLAGS) == 0x202);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_CR0) == 1);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_DR7) == 0x400);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_CR2) == 0x5555);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_DR6) == 0x6666);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_GS + 8) == 0x7777);
    CHECK(KswSvmRead64(&inner, KSW_VMCB_STAR) == 0x8888);
    return 0;
}

int main(void)
{
    if (test_admission() || test_build() || test_return()) { return 1; }
    printf("SVM nested entry: %u checks passed\n", checks);
    return 0;
}
