/* Verify nonidentity output translation, fixed masks and failure publication. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_writeback.h"
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_state.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static KSW_SVM_U64 memory[8][512];
static KSW_NSVM_OPERAND_IO io;
static KSW_NSVM_OPERAND_RESULT result;
static KSW_SVM_VMCB source, expected;
static unsigned calls, fail, reads;
static KSW_SVM_U64 mutate;
static int read_word(void* context, KSW_SVM_U64 pa, KSW_SVM_U64* value)
{
    (void)context;
    if ((pa & 7) || pa >= sizeof(memory)) { return 0; }
    ++reads; *value = memory[pa >> 12][(pa & 4095) / 8];
    if (reads == 4) { memory[4][9] ^= mutate; }
    return 1;
}
static int commit(void* context, KSW_SVM_U64 pa, const KSW_SVM_VMCB* image,
    unsigned operation, unsigned np, unsigned* written)
{
    unsigned offset;
    (void)context; ++calls; *written = 0;
    if (pa != 0x6000 || fail == 1) { return 0; }
    for (offset = 0; offset < 4096; offset += 8) {
        KSW_SVM_U64 mask = KswSvmNestedWritebackMask(offset, operation, np);
        if (mask) {
            memory[6][offset / 8] = (memory[6][offset / 8] & ~mask) | (KswSvmRead64(image, offset) & mask);
            ++*written;
            if (fail == 2) { return 0; }
        }
    }
    return 1;
}
static void reset(void)
{
    memset(memory, 0, sizeof(memory));
    memset(&source, 0x5a, sizeof(source));
    memset(memory[6], 0xa5, 4096);
    memcpy(&expected, memory[6], 4096);
    memory[1][0] = 0x2007; memory[2][0] = 0x3007; memory[3][0] = 0x4007;
    memory[4][9] = 0x6007;
    io.Root = 0x1000; io.Pat = 0x0007010600070106ULL;
    io.PhysicalBits = 45; io.Page1Gb = 1; io.Nx = 1; io.Read = read_word; io.Context = NULL;
    calls = fail = reads = 0; mutate = 0;
}
static unsigned run(unsigned op)
{
    return KswSvmNestedWriteback(&io, 0x9000, 0x6000, &source, op, 1, commit, &result);
}
int main(void)
{
    unsigned op, np, offset;
    for (op = 1; op <= 3; ++op) {
        for (np = 0; np < 2; ++np) {
            reset();
            CHECK(KswSvmNestedWriteback(&io, 0x9000, 0x6000, &source, op, np, commit, &result) == 0);
            CHECK(calls == 1 && result.HostPa == 0x6000 && result.GuestPa == 0x9000 && result.Words);
            /* Compare against the independent field-copy implementation, not our masks. */
            if (op == 1) { KswSvmNestedReflectExit(&expected, &source, np); }
            if (op == 2) { memcpy((unsigned char*)&expected + 0x70, (unsigned char*)&source + 0x70, 32); }
            if (op == 3) { KswSvmNestedCopyVmload(&expected, &source); }
            CHECK(!memcmp(&expected, memory[6], 4096));
            /* Pointer/control ownership never changes, whatever the source's raw bytes. */
            for (offset = 0; offset < 0x60; ++offset) { CHECK(((unsigned char*)memory[6])[offset] == 0xa5); }
            CHECK(KswSvmNestedWritebackMask(1, op, np) == 0);
            CHECK(KswSvmNestedWritebackMask(4096, op, np) == 0);
        }
    }
    reset(); memory[4][9] &= ~2ULL;
    CHECK(run(1) == KSW_NNPT_FAULT && !calls && !result.Words);
    CHECK(!memcmp(&expected, memory[6], 4096));
    reset(); memory[4][9] = 0x7007;
    CHECK(run(1) == KSW_NNPT_RETRY && !calls && !result.Words);
    reset(); memory[4][9] |= 0x18;
    CHECK(run(1) == KSW_NNPT_UNSUPPORTED && !calls);
    reset(); mutate = 0x1000;
    CHECK(run(1) == KSW_NNPT_RETRY && !calls && !result.Words);
    reset(); mutate = 0x60;
    CHECK(run(1) == 0 && calls == 1);
    reset(); fail = 1;
    CHECK(run(1) == KSW_NNPT_UNREADABLE && calls == 1 && result.Words == 0);
    CHECK(!memcmp(&expected, memory[6], 4096));
    reset(); fail = 2;
    CHECK(run(1) == KSW_NNPT_UNREADABLE && calls == 1 && result.Words == 1);
    CHECK(memcmp(&expected, memory[6], 4096) != 0);
    reset();
    CHECK(run(0) == KSW_NNPT_UNSUPPORTED && !calls);
    CHECK(run(4) == KSW_NNPT_UNSUPPORTED && !calls);
    CHECK(KswSvmNestedWriteback(&io, 0x9001, 0x6000, &source, 1, 1, commit, &result) == KSW_NNPT_UNSUPPORTED);
    CHECK(KswSvmNestedWriteback(&io, 0x9000, 0x6001, &source, 1, 1, commit, &result) == KSW_NNPT_UNSUPPORTED);
    CHECK(KswSvmNestedWriteback(NULL, 0x9000, 0x6000, &source, 1, 1, commit, &result) == KSW_NNPT_UNSUPPORTED);
    CHECK(!calls);
    printf("SVM_WRITEBACK_CHECKS=%u RESULT=PASS (no hardware)\n", checks);
    return 0;
}
