/* Production policy tests: no privileged instructions or driver loading. */
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_xstate.h"
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static unsigned geometry[64][4];
static void cpuid_fixture(void* context, unsigned leaf, unsigned subleaf, unsigned words[4])
{
    (void)context; (void)leaf;
    memcpy(words, geometry[subleaf], sizeof(geometry[0]));
}
static int layout_tests(void)
{
    KSW_SVM_XSTATE_LAYOUT layout;
    KSW_SVM_U64 xss = 0x800;
    unsigned words[4];
    memset(geometry, 0, sizeof(geometry));
    memset(&layout, 0, sizeof(layout));
    geometry[0][0] = 0xe7;
    geometry[1][0] = 0xf; geometry[1][2] = 0x800;
    geometry[2][0] = 256; geometry[2][1] = 576;
    geometry[5][0] = 64; geometry[5][1] = 1088;
    geometry[6][0] = 512; geometry[6][1] = 1152;
    geometry[7][0] = 1024; geometry[7][1] = 1664;
    geometry[11][0] = 16; geometry[11][2] = 1;
    CHECK(KswSvmXstateLayoutCapture(&layout, 0xe7, 0x800, 2448, 1, cpuid_fixture, NULL));
    CHECK(KswSvmXstateCpuid(&layout, 1, 0, 0, words) && words[0] == 0xe7 && words[1] == 576 && words[2] == 2688);
    CHECK(KswSvmXstateCpuid(&layout, 7, 0, 0, words) && words[1] == 832);
    CHECK(KswSvmXstateCpuid(&layout, 0xe7, 0x800, 1, words) && words[1] == 2448 && words[2] == 0x800);
    CHECK(KswSvmXstateCpuid(&layout, 1, 0x800, 1, words) && words[1] == 592);
    CHECK(KswSvmXstateCpuid(&layout, 1, 0, 11, words) && words[0] == 16 && words[1] == 0 && words[2] == 1);
    CHECK(KswSvmXstateCpuid(&layout, 1, 0, 64, words) && !(words[0] | words[1] | words[2] | words[3]));
    CHECK(!KswSvmXstateCpuid(&layout, 5, 0, 0, words));
    CHECK(!KswSvmXstateLayoutCapture(&layout, 0xe7, 0x800, 2447, 1, cpuid_fixture, NULL) && !layout.Ready);
    geometry[11][2] = 3; /* Alignment padding is meaningful with a small guest mask. */
    CHECK(KswSvmXstateLayoutCapture(&layout, 0xe7, 0x800, 2448, 1, cpuid_fixture, NULL));
    CHECK(KswSvmXstateCpuid(&layout, 7, 0x800, 1, words) && words[1] == 848);
    geometry[5][1] = 576; /* Overlap is forbidden even though the root saves compacted data. */
    CHECK(!KswSvmXstateLayoutCapture(&layout, 0xe7, 0x800, 2448, 1, cpuid_fixture, NULL));
    geometry[5][1] = 1088;
    geometry[11][2] = 2; /* A supervisor bitmap cannot name a user-managed descriptor. */
    CHECK(!KswSvmXstateLayoutCapture(&layout, 0xe7, 0x800, 2448, 1, cpuid_fixture, NULL));
    geometry[11][2] = 1;
    CHECK(!KswSvmXstateLayoutCapture(&layout, 0xe7, 0x800, 2688, 0, cpuid_fixture, NULL));
    CHECK(KswSvmXstateLayoutCapture(&layout, 0xe7, 0, 2688, 0, cpuid_fixture, NULL));
    CHECK(KswSvmXstateCpuid(&layout, 1, 0, 11, words) && !words[0]); /* No stale previous XSS descriptor exposed. */
    CHECK(KswSvmXssWrite(0x800, 0xf, 0, 0, &xss) == KSW_SVM_XCR_OK && !xss);
    CHECK(KswSvmXssWrite(0x800, 0xf, 0, 0x800, &xss) == KSW_SVM_XCR_OK && xss == 0x800);
    CHECK(KswSvmXssWrite(0x800, 0xf, 0, 0x1000, &xss) == KSW_SVM_XCR_GP && xss == 0x800);
    CHECK(KswSvmXssWrite(0x800, 7, 0, 0, &xss) == KSW_SVM_XCR_GP && xss == 0x800);
    CHECK(KswSvmXssWrite(0x800, 0xf, 3, 0, &xss) == KSW_SVM_XCR_GP && xss == 0x800);
    CHECK(KswSvmXssWrite(0x1000, 0xf, 0, 0, &xss) == KSW_SVM_XCR_UNSUPPORTED);
    return 0;
}
int main(void)
{
    const KSW_SVM_U64 masks[] = { 1, 3, 7, 0xe7 };
    KSW_SVM_U64 current;
    unsigned i, j, value, expected, result;
    for (value = 0; value < 65536; ++value) {
        expected = value == 1 || value == 3 || value == 7 || value == 0xe7;
        CHECK(KswSvmXcr0MaskValid(value) == (int)expected);
        for (i = 0; i < 4; ++i) {
            current = 0xfeed;
            result = KswSvmXcr0Write(masks[i], 1ULL << 18, 0, 0, value, &current);
            CHECK(result == ((expected && !(value & ~masks[i])) ? KSW_SVM_XCR_OK : KSW_SVM_XCR_GP));
            CHECK(current == (result == KSW_SVM_XCR_OK ? value : 0xfeedULL));
        }
    }
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 64; ++j) {
            current = masks[i];
            if ((1ULL << j) & masks[i]) { continue; }
            CHECK(KswSvmXcr0Write(masks[i], 1ULL << 18, 0, 0, masks[i] | (1ULL << j), &current) == KSW_SVM_XCR_GP);
            CHECK(current == masks[i]); /* Upper reserved bits cannot silently truncate. */
        }
    }
    for (i = 1; i < 4; ++i) {
        current = 7;
        CHECK(KswSvmXcr0Write(7, 1ULL << 18, i, 0, 1, &current) == KSW_SVM_XCR_GP && current == 7);
        CHECK(KswSvmXcr0Write(7, 1ULL << 18, 0, i, 1, &current) == KSW_SVM_XCR_GP && current == 7);
        CHECK(KswSvmXcr0Write(7, 0, i, i, 1, &current) == KSW_SVM_XCR_UD && current == 7);
    }
    current = 7;
    CHECK(KswSvmXcr0Write(7, 0, 0, 0, 1, &current) == KSW_SVM_XCR_UD && current == 7);
    CHECK(KswSvmXcr0Write(5, 1ULL << 18, 0, 0, 1, &current) == KSW_SVM_XCR_UNSUPPORTED && current == 7);
    CHECK(KswSvmXcr0Write(7, 1ULL << 18, 0, 0, 1, NULL) == KSW_SVM_XCR_UNSUPPORTED);
    CHECK(KswSvmXcr0Write(0xe7, 1ULL << 18, 0, 0, 1, &current) == KSW_SVM_XCR_OK && current == 1);
    CHECK(KswSvmXcr0Write(0xe7, 1ULL << 18, 0, 0, 0xe7, &current) == KSW_SVM_XCR_OK && current == 0xe7);
    if (layout_tests()) { return 1; }
    printf("SVM_XSTATE_POLICY_CHECKS=%u RESULT=PASS (no hardware)\n", checks);
    return 0;
}
