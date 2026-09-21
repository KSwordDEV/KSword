/* Test production operand capture with nonidentity mappings and failing RAM reads. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_operand.h"

static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static KSW_SVM_U64 ram[16][512];
static unsigned char output[4096];
static KSW_NSVM_OPERAND_IO io;
static KSW_NSVM_OPERAND_RESULT result;
static KSW_SVM_U64 failAt, mutateBits;
static unsigned payloadReads;

static int read_word(void* context, KSW_SVM_U64 address, KSW_SVM_U64* value)
{
    (void)context;
    if ((address & 7) || address >= sizeof(ram) || address == failAt) { return 0; }
    *value = ram[address >> 12][(address & 4095) >> 3];
    if (address >= 0x6000 && address < 0x7000) {
        ++payloadReads;
        if (address == 0x6ff8) { ram[4][9] ^= mutateBits; }
    }
    return 1;
}
static void reset(void)
{
    unsigned i;
    memset(ram, 0, sizeof(ram)); memset(output, 0xaa, sizeof(output));
    ram[1][0] = 0x2007; ram[2][0] = 0x3007; ram[3][0] = 0x4007;
    ram[4][9] = 0x6007; /* L1 GPA 0x9000 maps to host PA 0x6000. */
    for (i = 0; i < 512; ++i) { ram[6][i] = 0x0807060504030201ULL ^ i; }
    io.Root = 0x1000; io.Pat = 0x0007010600070106ULL;
    io.PhysicalBits = 45; io.Page1Gb = 1; io.Nx = 1; io.Read = read_word; io.Context = NULL;
    failAt = ~0ULL; mutateBits = 0; payloadReads = 0;
}
static int cleared(void)
{
    unsigned i;
    for (i = 0; i < sizeof(output); ++i) { if (output[i]) { return 0; } }
    return 1;
}
int main(void)
{
    unsigned i;
    reset();
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_OK);
    CHECK(result.HostPa == 0x6000 && result.GuestPa == 0x9000 && result.Words == 512);
    CHECK(!memcmp(output, ram[6], 4096));
    /* Inject failure in every one of the 512 reads, not just at page boundaries. */
    for (i = 0; i < 512; ++i) {
        reset(); failAt = 0x6000 + (KSW_SVM_U64)i * 8;
        CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_UNREADABLE);
        CHECK(result.Words == i && cleared());
    }
    reset(); ram[4][9] = 0;
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_FAULT);
    CHECK(!payloadReads && cleared());
    reset(); ram[4][9] &= ~4ULL;
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_FAULT);
    CHECK(!payloadReads && cleared());
    reset(); ram[4][9] |= 0x18; /* PAT index 3 is UC, not safe for the WB RAM window. */
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_UNSUPPORTED);
    CHECK(!payloadReads && cleared());
    reset(); failAt = 0x1000;
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_UNREADABLE);
    CHECK(!payloadReads && cleared());
    reset(); mutateBits = 0x1000; /* Change the mapped frame during the copy. */
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_RETRY);
    CHECK(result.Words == 512 && cleared());
    reset(); mutateBits = 2; /* Permission changes also invalidate the copied image. */
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_RETRY);
    reset(); mutateBits = 0x60; /* Hardware A/D writes alone must not cause a false retry. */
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, output, &result) == KSW_NNPT_OK);
    CHECK(!memcmp(output, ram[6], 4096));
    reset();
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9001, output, &result) == KSW_NNPT_UNSUPPORTED);
    CHECK(cleared());
    CHECK(KswSvmNestedReadOperandPage(&io, 1ULL << 45, output, &result) == KSW_NNPT_UNSUPPORTED);
    CHECK(KswSvmNestedReadOperandPage(NULL, 0x9000, output, &result) == KSW_NNPT_UNSUPPORTED);
    CHECK(KswSvmNestedReadOperandPage(&io, 0x9000, NULL, &result) == KSW_NNPT_UNSUPPORTED);
    reset(); ram[3][0] = 0x87; /* A 2-MiB outer leaf is valid for operand capture. */
    CHECK(KswSvmNestedReadOperandPage(&io, 0x6000, output, &result) == KSW_NNPT_OK);
    CHECK(result.HostPa == 0x6000 && !memcmp(output, ram[6], 4096));
    reset(); ram[2][0] = 0x87; /* Likewise for a 1-GiB outer leaf. */
    CHECK(KswSvmNestedReadOperandPage(&io, 0x6000, output, &result) == KSW_NNPT_OK);
    CHECK(result.HostPa == 0x6000 && !memcmp(output, ram[6], 4096));
    printf("SVM_OPERAND_CHECKS=%u RESULT=PASS (no hardware executed)\n", checks);
    return 0;
}
