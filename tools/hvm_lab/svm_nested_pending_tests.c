/* Future offline regression for acknowledged events; does not execute SVM or APIC operations. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_pending.h"
#define CHECK(x) do { if (!(x)) { printf("pending:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
int main(void)
{
    KSW_NSVM_PENDING pending;
    const KSW_NSVM_PENDING_ITEM* item;
    KSW_SVM_U64 low, high, nmi, alien, token, before, transfer;
    unsigned index;
    memset(&pending, 0, sizeof(pending));
    CHECK(!KswSvmNestedPendingPush(&pending, 0x80000b0dULL, 0, &token));
    CHECK(!KswSvmNestedPendingPush(&pending, 0x180000050ULL, 0, &token));
    CHECK(KswSvmNestedPendingPush(&pending, 0x80000050ULL, 0, &low));
    CHECK(KswSvmNestedPendingPush(&pending, 0x800000e0ULL, 0, &high));
    CHECK(KswSvmNestedPendingPush(&pending, 0x80000202ULL, 0, &nmi));
    CHECK(KswSvmNestedPendingPush(&pending, 0x80000202ULL, 0x1001, &alien));
    CHECK(KswSvmNestedPendingOwned(&pending, 0) == 3);
    CHECK(KswSvmNestedPendingOwned(&pending, 0x1001) == 1);
    CHECK(!KswSvmNestedPendingSelect(&pending, 0, 0, 0, 0));
    item = KswSvmNestedPendingSelect(&pending, 0, 1, 1, 15);
    CHECK(item && item->Token == nmi);
    CHECK(KswSvmNestedPendingArm(&pending, nmi));
    CHECK(!KswSvmNestedPendingArm(&pending, nmi));
    CHECK(!KswSvmNestedPendingObserve(&pending, nmi, 0, 0));
    CHECK(pending.Count == 4 && pending.Delivered == 0);
    CHECK(KswSvmNestedPendingObserve(&pending, nmi, 1, 0x80000202ULL));
    CHECK(pending.Count == 4 && pending.Retried == 1);
    CHECK(KswSvmNestedPendingArm(&pending, nmi));
    CHECK(!KswSvmNestedPendingObserve(&pending, nmi, 1, 0x800000e0ULL));
    CHECK(pending.Count == 4);
    CHECK(KswSvmNestedPendingObserve(&pending, nmi, 1, 0));
    CHECK(pending.Count == 3 && pending.Delivered == 1);
    CHECK(!KswSvmNestedPendingObserve(&pending, nmi, 1, 0));
    item = KswSvmNestedPendingSelect(&pending, 0, 1, 1, 5);
    CHECK(item && item->Token == high);
    CHECK(!KswSvmNestedPendingTransfer(&pending, high, 0x80000050ULL));
    CHECK(!KswSvmNestedPendingTransfer(&pending, high, 0x800000e0ULL));
    CHECK(KswSvmNestedPendingArm(&pending, high));
    CHECK(!KswSvmNestedPendingTransfer(&pending, high, 0x800000e0ULL));
    CHECK(KswSvmNestedPendingObserve(&pending, high, 1, 0x800000e0ULL));
    CHECK(KswSvmNestedPendingTransfer(&pending, high, 0x800000e0ULL));
    CHECK(!KswSvmNestedPendingSelect(&pending, 0, 1, 1, 5));
    CHECK(KswSvmNestedPendingArm(&pending, low));
    CHECK(KswSvmNestedPendingObserve(&pending, low, 1, 0));
    CHECK(KswSvmNestedPendingOwned(&pending, 0) == 0);
    CHECK(KswSvmNestedPendingOwned(&pending, 0x1001) == 1);
    transfer = 77;
    CHECK(!KswSvmNestedPendingPrepareTransfer(&pending, 0x1001, alien, 0x80000202ULL, &transfer));
    CHECK(transfer == 77 && pending.Count == 1);
    CHECK(KswSvmNestedPendingArm(&pending, alien));
    CHECK(!KswSvmNestedPendingObserve(&pending, alien, 2, 0));
    CHECK(KswSvmNestedPendingObserve(&pending, alien, 1, 0x80000202ULL));
    CHECK(KswSvmNestedPendingPrepareTransfer(&pending, 0x1001, alien, 0x80000202ULL, &transfer));
    CHECK(transfer == alien);
    CHECK(KswSvmNestedPendingTransfer(&pending, alien, 0x80000202ULL));
    CHECK(!KswSvmNestedPendingTransfer(&pending, alien, 0x80000202ULL));
    CHECK(KswSvmNestedPendingPrepareTransfer(&pending, 0x1001, alien, 0, &transfer));
    CHECK(transfer == 0);
    for (index = 0; index < KSW_NSVM_PENDING_CAPACITY; ++index) {
        CHECK(KswSvmNestedPendingPush(&pending, 0x80000050ULL, 0, &token));
    }
    before = pending.Serial;
    CHECK(!KswSvmNestedPendingPush(&pending, 0x80000202ULL, 0, &token));
    CHECK(pending.Count == KSW_NSVM_PENDING_CAPACITY && pending.Serial == before);
    memset(&pending, 0, sizeof(pending)); pending.Serial = ~0ULL;
    CHECK(!KswSvmNestedPendingPush(&pending, 0x80000050ULL, 0, &token));
    CHECK(pending.Count == 0);
    puts("nested pending-event ledger passed");
    return 0;
}
