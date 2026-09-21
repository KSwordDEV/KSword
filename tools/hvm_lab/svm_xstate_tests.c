/* Production policy tests: no privileged instructions or driver loading. */
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_xstate.h"
#include <stdio.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
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
    printf("SVM_XSTATE_POLICY_CHECKS=%u RESULT=PASS (no hardware)\n", checks);
    return 0;
}
