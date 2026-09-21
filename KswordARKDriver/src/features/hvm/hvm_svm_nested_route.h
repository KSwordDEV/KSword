/* Exit ownership is decided before any emulation mutates registers or pending events. */
#pragma once
#include "hvm_svm_nested_state.h"
#include "hvm_svm_nested_permissions.h"

/* Unknown/inconsistent hardware exits must not silently reenter a guest. */
#define KSW_NSVM_ROUTE_FAULT 0U
#define KSW_NSVM_ROUTE_REFLECT 1U
#define KSW_NSVM_ROUTE_EMULATE 2U
#define KSW_NSVM_ROUTE_NPF 3U
#define KSW_NSVM_ROUTE_ASYNC 4U

typedef struct _KSW_NSVM_EXIT_ROUTE {
    /* Both owners may request one intercept; L1 reflection precedes L0 side effects. */
    unsigned int Action, Owners;
    /* Original exit metadata is retained regardless of the chosen owner. */
    KSW_SVM_U64 Code, Info1;
} KSW_NSVM_EXIT_ROUTE;

/* NPF and physical asynchronous events require their dedicated arbiters.
   EMULATE designates L0 ownership, not proof that a handler implements the exit. */
unsigned int KswSvmNestedRouteExit(const KSW_SVM_VMCB* Outer,
    const KSW_SVM_VMCB* Inner, const KSW_NSVM_PERMISSION_VIEW* OuterMaps,
    const KSW_NSVM_PERMISSION_VIEW* InnerMaps, KSW_SVM_U64 Code,
    KSW_SVM_U64 Info1, unsigned int Msr, KSW_NSVM_EXIT_ROUTE* Result);
