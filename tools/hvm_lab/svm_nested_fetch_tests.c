/* Offline source cases. Execution is deliberately deferred; these do not execute SVM instructions. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_fetch.h"
#define CHECK(x) do { if (!(x)) { printf("fetch:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
static KSW_SVM_U64 ram[16][512];
static unsigned failRead;
static int read_word(void* context, KSW_SVM_U64 address, KSW_SVM_U64* value)
{
    (void)context;
    if (failRead || address >= sizeof(ram) || (address & 7)) { return 0; }
    *value = ram[address >> 12][(address & 4095) >> 3]; return 1;
}
int main(void)
{
    const unsigned char raw[] = {0x0f, 0x01, 0xd8};
    const unsigned char prefixed[] = {0xf3, 0x67, 0x0f, 0x01, 0xd8};
    unsigned char repeated[] = {0x67, 0x67, 0x0f, 0x01, 0xda}, bytes[15];
    KSW_SVM_VMCB vmcb;
    KSW_NSVM_OPERAND_IO io = {0};
    KSW_SVM_U64 operand = 0;
    unsigned bits = 0, length = 0, index;
    KSW_SVM_SEGMENT* cs;
    CHECK(KswSvmNestedDecodeSvmOperand(raw, 3, 0x80, 1, 0, 0x123456789abcdef0ULL, &operand, &bits) == KSW_NNPT_OK);
    CHECK(bits == 64 && operand == 0x123456789abcdef0ULL);
    CHECK(KswSvmNestedDecodeSvmOperand(prefixed, 5, 0x80, 1, 0, 0x123456789abcdef0ULL, &operand, &bits) == KSW_NNPT_OK);
    CHECK(bits == 32 && operand == 0x9abcdef0ULL);
    CHECK(KswSvmNestedDecodeSvmOperand(repeated, 5, 0x82, 1, 0, 0x123456789abcdef0ULL, &operand, &bits) == KSW_NNPT_OK);
    CHECK(bits == 32 && operand == 0x9abcdef0ULL);
    CHECK(KswSvmNestedDecodeSvmOperand(raw, 3, 0x80, 0, 1, ~0ULL, &operand, &bits) == KSW_NNPT_OK && bits == 32 && operand == 0xffffffffULL);
    CHECK(KswSvmNestedDecodeSvmOperand(prefixed, 5, 0x80, 0, 1, ~0ULL, &operand, &bits) == KSW_NNPT_OK && bits == 16 && operand == 0xffffULL);
    CHECK(KswSvmNestedDecodeSvmOperand(raw, 3, 0x80, 0, 0, ~0ULL, &operand, &bits) == KSW_NNPT_OK && bits == 16);
    CHECK(KswSvmNestedDecodeSvmOperand(prefixed, 5, 0x80, 0, 0, ~0ULL, &operand, &bits) == KSW_NNPT_OK && bits == 32);
    CHECK(KswSvmNestedDecodeSvmOperand(raw, 3, 0x82, 1, 0, 0, &operand, &bits) == KSW_NNPT_RETRY);
    repeated[0] = 0xf0;
    CHECK(KswSvmNestedDecodeSvmOperand(repeated, 5, 0x82, 1, 0, 0, &operand, &bits) == KSW_NNPT_RETRY);
    repeated[0] = 0x48;
    CHECK(KswSvmNestedDecodeSvmOperand(repeated, 5, 0x82, 1, 0, 0, &operand, &bits) == KSW_NNPT_OK);
    CHECK(KswSvmNestedDecodeSvmOperand(repeated, 5, 0x82, 0, 1, 0, &operand, &bits) == KSW_NNPT_RETRY);
    memset(&vmcb, 0, sizeof(vmcb));
    io.Root = 0x1000; io.Pat = 6; io.PhysicalBits = 48; io.Page1Gb = 1; io.Nx = 1; io.Read = read_word;
    ram[1][0] = 0x2007; ram[2][0] = 0x3007; ram[3][0] = 0x87;
    ram[4][256] = 0x5007; ram[5][0] = 0x6007; ram[6][0] = 0x7007;
    ram[7][0] = 0x8007; ram[7][1] = 0x9007;
    KswSvmWrite64(&vmcb, KSW_VMCB_EFER, 0xd00);
    KswSvmWrite64(&vmcb, KSW_VMCB_CR0, 0x80000001);
    KswSvmWrite64(&vmcb, KSW_VMCB_CR4, 0x20);
    KswSvmWrite64(&vmcb, KSW_VMCB_CR3, 0x4000);
    cs = (KSW_SVM_SEGMENT*)((unsigned char*)&vmcb + KSW_VMCB_CS);
    /* VMCB attributes use a compact format, with L at bit nine. */
    cs->attributes = 0x29b;
    KswSvmWrite64(&vmcb, KSW_VMCB_RIP, 0xffff800000000ffeULL);
    KswSvmWrite64(&vmcb, KSW_VMCB_NRIP, 0xffff800000001003ULL);
    for (index = 0; index < sizeof(prefixed); ++index) { ((unsigned char*)ram)[0x8ffe + index] = prefixed[index]; }
    CHECK(KswSvmNestedFetchInstruction(&io, &vmcb, bytes, &length) == KSW_NNPT_OK);
    CHECK(length == sizeof(prefixed) && !memcmp(bytes, prefixed, sizeof(prefixed)));
    ram[7][1] = 0;
    CHECK(KswSvmNestedFetchInstruction(&io, &vmcb, bytes, &length) == KSW_NNPT_RETRY && !length && !bytes[0]);
    ram[7][1] = 0x9007;
    ram[4][256] |= 1ULL << 63;
    CHECK(KswSvmNestedFetchInstruction(&io, &vmcb, bytes, &length) == KSW_NNPT_RETRY && !length);
    ram[4][256] &= ~(1ULL << 63);
    KswSvmWrite64(&vmcb, KSW_VMCB_CR4, 0x1020);
    CHECK(KswSvmNestedFetchInstruction(&io, &vmcb, bytes, &length) == KSW_NNPT_UNSUPPORTED);
    KswSvmWrite64(&vmcb, KSW_VMCB_CR4, 0x20); failRead = 1;
    CHECK(KswSvmNestedFetchInstruction(&io, &vmcb, bytes, &length) == KSW_NNPT_UNREADABLE && !length);
    puts("nested fetch source cases passed"); return 0;
}
