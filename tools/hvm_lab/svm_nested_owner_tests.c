/* Windows host threads exercise atomic authority only; these tests execute no SVM. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_owner.h"
static KSW_NSVM_OWNER_TABLE owners;
static unsigned checks;
static volatile LONG entered, failures;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
static DWORD WINAPI contender(void* argument)
{
    unsigned id = (unsigned)(ULONG_PTR)argument, round, attempts, status;
    for (round = 0; round < 100; ++round) {
        KSW_NSVM_LEASE lease = {0};
        for (attempts = 0; attempts < 100000; ++attempts) {
            status = KswSvmNestedOwnerAcquire(&owners, 0x12345000, id, &lease);
            if (status == KSW_NSVM_LEASE_OK) { break; }
            if (status != KSW_NSVM_LEASE_BUSY) { InterlockedIncrement(&failures); return 1; }
            SwitchToThread(); /* R3 scheduler pressure; never a root-level wait. */
        }
        if (!lease.Token) { InterlockedIncrement(&failures); return 1; }
        if (InterlockedIncrement(&entered) != 1) { InterlockedIncrement(&failures); }
        SwitchToThread();
        InterlockedDecrement(&entered);
        if (!KswSvmNestedOwnerRelease(&owners, &lease)) { InterlockedIncrement(&failures); return 1; }
    }
    return 0;
}
int main(void)
{
    KSW_NSVM_LEASE first = {0}, second = {0}, stale;
    HANDLE threads[8];
    unsigned i;
    CHECK(KswSvmNestedOwnerAcquire(&owners, 0, 0x10002, &first) == KSW_NSVM_LEASE_OK);
    CHECK(first.CpuIdentity == 0x10002 && !KswSvmNestedOwnersIdle(&owners));
    CHECK(KswSvmNestedOwnerAcquire(&owners, 0, 0x10003, &second) == KSW_NSVM_LEASE_BUSY && !second.Token);
    stale = first;
    CHECK(KswSvmNestedOwnerRelease(&owners, &first));
    CHECK(KswSvmNestedOwnerAcquire(&owners, 0, 0x10003, &second) == KSW_NSVM_LEASE_OK);
    CHECK(!KswSvmNestedOwnerRelease(&owners, &stale) && second.Token);
    CHECK(KswSvmNestedOwnerRelease(&owners, &second));
    CHECK(!KswSvmNestedOwnerRelease(&owners, &second) && KswSvmNestedOwnersIdle(&owners));
    CHECK(KswSvmNestedOwnerAcquire(&owners, 3, 0, &first) == KSW_NSVM_LEASE_INVALID);
    CHECK(KswSvmNestedOwnerAcquire(&owners, 1ULL << 52, 0, &first) == KSW_NSVM_LEASE_INVALID);
    for (i = 0; i < 8; ++i) { threads[i] = CreateThread(NULL, 0, contender, (void*)(ULONG_PTR)i, 0, NULL); CHECK(threads[i] != NULL); }
    CHECK(WaitForMultipleObjects(8, threads, TRUE, 30000) == WAIT_OBJECT_0);
    for (i = 0; i < 8; ++i) { CloseHandle(threads[i]); }
    CHECK(!failures && !entered && KswSvmNestedOwnersIdle(&owners));
    memset(&owners, 0, sizeof(owners));
    for (i = 0; i < KSW_NSVM_OWNER_SLOTS; ++i) {
        CHECK(KswSvmNestedOwnerAcquire(&owners, (KSW_SVM_U64)i << 12, 0, &first) == KSW_NSVM_LEASE_OK);
        CHECK(KswSvmNestedOwnerRelease(&owners, &first));
    }
    CHECK(KswSvmNestedOwnerAcquire(&owners, (KSW_SVM_U64)KSW_NSVM_OWNER_SLOTS << 12, 0, &first) == KSW_NSVM_LEASE_FULL);
    CHECK(KswSvmNestedOwnerAcquire(&owners, 0, 0, &first) == KSW_NSVM_LEASE_OK); /* Existing permanent key remains usable. */
    CHECK(KswSvmNestedOwnerRelease(&owners, &first));
    owners.Serial = 0x3fffffffffffffffLL;
    CHECK(KswSvmNestedOwnerAcquire(&owners, 0, 0, &first) == KSW_NSVM_LEASE_FULL);
    printf("SVM_OWNER_CHECKS=%u RESULT=PASS (host atomics, no hardware virtualization)\n", checks);
    return 0;
}
