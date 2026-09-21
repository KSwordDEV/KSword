/* Offline cases for event ownership and aggregation. Not a physical IRQ/NMI test. */
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_nested_event.h"
#include <stdio.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { printf("FAIL %u: %s\n", __LINE__, #x); return 1; } } while (0)
int main(void)
{
    KSW_SVM_VMCB current = {0}, inner = {0};
    KSW_NSVM_EVENT_PLAN plan;
    unsigned first, second;
    const unsigned contributory[] = {0, 10, 11, 12, 13, 21, 29, 30};
    KswSvmWrite64(&current, KSW_VMCB_RIP, 0x1234);
    for (first = 0; first < sizeof(contributory) / sizeof(contributory[0]); ++first) {
        for (second = 0; second < sizeof(contributory) / sizeof(contributory[0]); ++second) {
            KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000300ULL | contributory[first]);
            CHECK(KswSvmNestedExceptionPlan(&current, &inner, contributory[second], 0xbeef, 0, &plan) == KSW_NSVM_EVENT_INJECT);
            CHECK(plan.Event == 0x80000b08 && !plan.WriteCr2);
        }
    }
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000b0e);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 13, 1, 0, &plan) == KSW_NSVM_EVENT_INJECT && plan.Event == 0x80000b08);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 14, 5, 0xabc, &plan) == KSW_NSVM_EVENT_INJECT && plan.Event == 0x80000b08);
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000b0d);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 14, 5, 0xabc, &plan) == KSW_NSVM_EVENT_INJECT && plan.Event == 0x580000b0eULL);
    CHECK(KswSvmNestedExceptionInject(&current, &plan, 0));
    CHECK(KswSvmRead64(&current, KSW_VMCB_CR2) == 0xabc && KswSvmRead64(&current, KSW_VMCB_RIP) == 0x1234);
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000b08);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 14, 0, 0xabc, &plan) == KSW_NSVM_EVENT_SHUTDOWN);
    KswSvmWrite32(&inner, KSW_VMCB_MISC1, 1U << 31);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 14, 0, 0xabc, &plan) == KSW_NSVM_EVENT_REFLECT && plan.ExitCode == 0x7f);
    KswSvmWrite32(&inner, 8, 1U << 14); /* #PF interception precedes shutdown aggregation. */
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 14, 5, 0xabc, &plan) == KSW_NSVM_EVENT_REFLECT && plan.ExitCode == 0x4e && plan.Info1 == 5 && plan.Info2 == 0xabc);
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000b0d);
    KswSvmWrite32(&inner, 8, 1U << 8);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 13, 0, 0, &plan) == KSW_NSVM_EVENT_REFLECT && plan.ExitCode == 0x48);
    memset(&inner, 0, sizeof(inner));
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000091);
    KswSvmWrite64(&current, KSW_VMCB_EVENT, 0xfeed);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 14, 2, 0x777, &plan) == KSW_NSVM_EVENT_INJECT && plan.Deferred == 0x80000091);
    CHECK(!KswSvmNestedExceptionInject(&current, &plan, 0) && KswSvmRead64(&current, KSW_VMCB_EVENT) == 0xfeed);
    CHECK(KswSvmNestedExceptionInject(&current, &plan, 1));
    KswSvmWrite64(&current, KSW_VMCB_EXITINTINFO, 0x80000202);
    CHECK(KswSvmNestedExceptionPlan(&current, &inner, 6, 0, 0, &plan) == KSW_NSVM_EVENT_INJECT && plan.Deferred == 0x80000202);
    printf("SVM_EVENT_PLAN_CHECKS=%u RESULT=PASS (no physical events)\n", checks);
    return 0;
}
