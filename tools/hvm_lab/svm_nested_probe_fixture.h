/* Host-only platform substitutes; never included by the driver build. */
#pragma once
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_arch.h"
#include "../../KswordARKDriver/src/features/hvm/hvm_svm_xstate.h"
#include "../../shared/driver/KswordArkHvmIoctl.h"
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define KSW_SVM_STACK_BYTES 32768UL
typedef struct _KSW_HVM_PHYS_WINDOW KSW_HVM_PHYS_WINDOW;
typedef struct _KSW_NPT {
    ULONGLONG RootPa, AddressMask;
} KSW_NPT;
typedef struct _KSW_SVM_CPU {
    KSW_SVM_VMCB* Guest;
    void* Msrpm;
    void* Iopm;
    ULONGLONG Gpr[16], LaunchRsp, LaunchFlags, OriginalEfer;
    ULONGLONG HostXcr0, GuestXcr0;
    ULONGLONG HostXss, GuestXss;
    KSW_SVM_XSTATE_LAYOUT XstateLayout;
    struct { ULONG PhysicalBits, AsidCount, XsaveFeatures; BOOLEAN Page1Gb; ULONGLONG Pat, VmCr, Efer, Cr4; } Caps;
    NTSTATUS Result;
    struct _KSW_SVM_NESTED* Nested;
} KSW_SVM_CPU;
void KswordSvmTrace(KSW_SVM_CPU* Cpu, ULONG Stage);
void KswordSvmAsmGuestResume(void);
