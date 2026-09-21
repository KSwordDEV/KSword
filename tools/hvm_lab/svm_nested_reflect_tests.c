/* Reflection boundary fixtures: the writeback callback is simulated, never hardware execution. */
#include <stdio.h>
#include <string.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_execute.h"
#define CHECK(x) do { if (!(x)) { printf("reflect:%u: %s\n", (unsigned)__LINE__, #x); return 1; } } while (0)
static KSW_NSVM_EXECUTION execution;
static KSW_NSVM_SESSION session;
static KSW_NSVM_SESSION_IO io;
static KSW_SVM_VMCB current;
static unsigned calls, fail, observedCount;

/* Replace only the already separately tested VMCB writeback transaction boundary. */
unsigned KswSvmNestedSessionReflect(KSW_NSVM_SESSION* Session,
    const KSW_NSVM_SESSION_IO* Io, KSW_SVM_VMCB* Current)
{
    (void)Io;
    ++calls;
    observedCount = execution.Pending.Count;
    if (fail) { Session->Phase = KSW_NSVM_SESSION_FAULTED; return KSW_NSVM_ACTION_FAULT; }
    Session->Phase = KSW_NSVM_SESSION_IDLE; Session->Lease.Token = 0;
    memset(Current, 0, sizeof(*Current));
    return KSW_NSVM_ACTION_RETURN;
}

static void initialize(void)
{
    memset(&execution, 0, sizeof(execution)); memset(&session, 0, sizeof(session));
    memset(&io, 0, sizeof(io)); memset(&current, 0, sizeof(current));
    calls = fail = observedCount = 0;
    execution.Current = &current; execution.Session = &session; execution.Io = &io;
    execution.Gif = execution.GifRequested = 1;
    session.Phase = KSW_NSVM_SESSION_L2; session.OperandHostPa = 0x2000; session.Lease.Token = 7;
}

int main(void)
{
    KSW_SVM_U64 token, other;
    initialize();
    CHECK(KswSvmNestedReturnL1(NULL) == KSW_NSVM_EXEC_FAULT);
    CHECK(KswSvmNestedReturnL1(&execution) == KSW_NSVM_EXEC_RESUME);
    CHECK(calls == 1 && !execution.Gif && !execution.GifRequested);
    CHECK(KswSvmNestedReturnL1(&execution) == KSW_NSVM_EXEC_FAULT && calls == 1);

    initialize();
    CHECK(KswSvmNestedPendingPush(&execution.Pending, 0x80000050ULL, 0x2001, &token));
    execution.RetryEventToken = token;
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000050ULL);
    CHECK(KswSvmNestedReturnL1(&execution) == KSW_NSVM_EXEC_EVENT_BLOCKED);
    CHECK(!calls && execution.Pending.Count == 1 && session.Lease.Token == 7);
    CHECK(KswSvmNestedPendingArm(&execution.Pending, token));
    CHECK(KswSvmNestedPendingObserve(&execution.Pending, token, 1, 0x80000050ULL));
    CHECK(KswSvmNestedPendingPush(&execution.Pending, 0x80000060ULL, 0x2001, &other));
    CHECK(KswSvmNestedReturnL1(&execution) == KSW_NSVM_EXEC_EVENT_BLOCKED && !calls);
    CHECK(KswSvmNestedPendingArm(&execution.Pending, other));
    CHECK(KswSvmNestedPendingObserve(&execution.Pending, other, 1, 0));
    CHECK(KswSvmNestedPendingPush(&execution.Pending, 0x80000070ULL, 0, &other));
    CHECK(KswSvmNestedReturnL1(&execution) == KSW_NSVM_EXEC_RESUME);
    CHECK(calls == 1 && observedCount == 2 && execution.Pending.Count == 1);
    CHECK(KswSvmNestedPendingLookup(&execution.Pending, other));
    CHECK(!KswSvmNestedPendingLookup(&execution.Pending, token) && !execution.RetryEventToken);
    CHECK(execution.Pending.Delivered == 1); /* Transfer itself is not a hardware delivery. */

    initialize();
    CHECK(KswSvmNestedPendingPush(&execution.Pending, 0x80000202ULL, 0x2001, &token));
    CHECK(KswSvmNestedPendingArm(&execution.Pending, token));
    CHECK(KswSvmNestedPendingObserve(&execution.Pending, token, 1, 0x80000202ULL));
    execution.RetryEventToken = token;
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000050ULL);
    CHECK(KswSvmNestedReturnL1(&execution) == KSW_NSVM_EXEC_EVENT_BLOCKED && !calls);
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000202ULL);
    fail = 1;
    CHECK(KswSvmNestedReturnL1(&execution) == KSW_NSVM_EXEC_FAULT);
    CHECK(calls == 1 && observedCount == 1 && execution.Pending.Count == 1);
    CHECK(session.Lease.Token == 7 && execution.RetryEventToken == token && execution.Gif == 1);
    puts("nested reflection boundary fixtures passed");
    return 0;
}
