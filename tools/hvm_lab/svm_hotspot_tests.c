#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_hotspots.h"
#define CHECK(x) do { if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static KSWORD_HVM_HOTSPOTS hot;
int main(void)
{
    unsigned i, level;
    unsigned long long sum;
    KswSvmHotObserve(&hot, 0, 0x7c, 0x1234, 0, 0, 0xc0000080);
    KswSvmHotObserve(&hot, 0, 0x7c, 0x1234, 1, 0, 0xc0000080);
    KswSvmHotObserve(&hot, 1, 0x7c, 0x1234, 0, 0, 0xc0000080);
    CHECK(hot.levels[0].msrs[0].reads == 1 && hot.levels[0].msrs[0].writes == 1);
    CHECK(hot.levels[1].msrs[0].reads == 1 && hot.levels[1].msrs[0].writes == 0);
    for (i = 0; i < 100; ++i) KswSvmHotObserve(&hot, 1, 0x400, i, 0x100000004ULL, i * 4096ULL, 0);
    KswSvmHotObserve(&hot, 1, ~0ULL, 0, 0, 0, 0);
    KswSvmHotObserve(&hot, 1, 0x8000000000000000ULL, 0, 0, 0, 0);
    CHECK(hot.levels[1].npf == 100 && hot.levels[1].invalid == 1 && hot.levels[1].other == 1);
    for (i = 0; i < KSW_HVM_HOT_MSR_SLOTS; ++i) KswSvmHotObserve(&hot, 0, 0x7c, 0, 0, 0, i);
    CHECK(hot.levels[0].msrUsed == KSW_HVM_HOT_MSR_SLOTS && hot.levels[0].msrOverflow == 1);
    KswSvmHotObserve(&hot, 0, 0x7c, 0, 0, 0, 0xc0000080);
    CHECK(hot.levels[0].msrs[0].reads == 2); /* Full table must retain old identities. */
    KswSvmHotObserve(&hot, 0, 0x7c, 0, 2, 0, 0xc0000080);
    CHECK(hot.levels[0].invalidMsrDirection == 1 && hot.levels[0].msrs[0].invalidDirection == 1);
    for (level = 0; level < 2; ++level) {
        KSWORD_HVM_HOT_LEVEL* r = &hot.levels[level];
        sum = r->npf + r->invalid + r->other;
        for (i = 0; i < 256; ++i) sum += r->codes[i];
        CHECK(sum == r->total);
        sum = r->msrOverflow;
        for (i = 0; i < r->msrUsed; ++i) sum += r->msrs[i].reads + r->msrs[i].writes + r->msrs[i].invalidDirection;
        CHECK(sum == r->codes[0x7c]);
    }
    KswSvmHotObserve(&hot, 99, 0, 0, 0, 0, 0);
    CHECK(hot.invalidLevel == 1);
    hot.levels[0].total = ~0ULL;
    KswSvmHotObserve(&hot, 0, 0x72, 0, 0, 0, 0);
    CHECK(hot.saturated && hot.levels[0].total == ~0ULL);
    memset(&hot, 0, sizeof(hot));
    CHECK(!hot.valid && !hot.saturated && !hot.levels[0].total);
    puts("PASS hotspots: level isolation, exact buckets, sparse codes, MSR overflow, saturation (offline)");
    return 0;
}
