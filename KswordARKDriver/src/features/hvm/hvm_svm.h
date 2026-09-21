/* Processor-owned AMD backend state; all hardware pages are nonpaged. */
#pragma once
#include "hvm_internal.h"
#include "hvm_metrics.h"
#include "hvm_svm_arch.h"
#include "hvm_svm_xstate.h"

/* Bound the static NPT allocation ledger to 64 MiB of hardware tables. */
#define KSW_NPT_MAX_PAGES 16384UL
/* Per-processor stack is private to the SVM host loop. */
#define KSW_SVM_STACK_BYTES 32768UL
/* Bound nonblocking per-processor exit evidence. */
#define KSW_SVM_TRACE_ROWS 64UL

/* Own every table allocation until all processors have stopped. */
typedef struct _KSW_NPT {
    /* Virtual table pages, recorded before publishing a parent entry. */
    PVOID* Pages;
    /* Number of owned table pages. */
    ULONG PageCount;
    /* Physical address of the PML4. */
    ULONGLONG RootPa;
    /* Exclusive, complete guest physical coverage. */
    ULONGLONG Limit;
    /* Address-width mask. */
    ULONGLONG AddressMask;
    /* Host PAT index for WB. */
    ULONG WbIndex;
    /* Host PAT index for UC. */
    ULONG UcIndex;
    /* Allow a one-GiB leaf only when enumerated. */
    BOOLEAN Page1Gb;
    /* Immutable RAM inventory retained for nested physical-operand admission. */
    PPHYSICAL_MEMORY_RANGE Ranges;
} KSW_NPT;

/* One immutable-capability snapshot per processor. */
typedef struct _KSW_SVM_CAPS {
    /* Maximum supported extended CPUID leaf. */
    ULONG MaxLeaf;
    /* Enumerated ASID count including reserved zero. */
    ULONG AsidCount;
    /* CPUID.8000000A EDX. */
    ULONG Features;
    /* Physical-address width accepted by NPT. */
    ULONG PhysicalBits;
    /* Valid register mask: VM_CR=1, EFER=2, HSAVE=4, PAT=8. */
    ULONG Valid;
    /* Last exception while reading privileged evidence. */
    NTSTATUS Exception;
    /* Firmware SVM gate. */
    ULONGLONG VmCr;
    /* Original virtualization ownership evidence. */
    ULONGLONG Efer;
    /* Existing HSAVE ownership must never be overwritten blindly. */
    ULONGLONG Hsave;
    /* Cache layout must remain identical on every participating CPU. */
    ULONGLONG Pat;
    /* Admission refusal and independent extended-state observation validity. */
    ULONG RejectReason, StateValid, Cpuid1Ecx, XsaveFeatures;
    /* Read-only architectural state, never inferred from CPUID support alone. */
    ULONGLONG Cr4, Xcr0, Xss;
    /* Valid only when CET was enumerated and both MSRs were read successfully. */
    ULONGLONG Scet, Isst;
    /* Current-thread user CET observations for bounded self-test return verification. */
    ULONGLONG Ucet, Pl3Ssp;
    /* CPUID.7.0 ECX.CET_SS; unsupported CPUs must not touch CET MSRs. */
    ULONG CetPresent;
    /* The VMM may filter one-GiB page support. */
    BOOLEAN Page1Gb;
    /* Explicit SVM instruction availability. */
    BOOLEAN Svm;
} KSW_SVM_CAPS;

/* Raw, CPU-local, seqlock-protected telemetry. */
typedef struct _KSW_SVM_TRACE {
    /* Odd while a writer is modifying the record. */
    volatile LONG Sequence;
    /* Stage follows the shared diagnostic stage namespace. */
    ULONG Stage;
    /* Exact architecture exit code, including INVALID. */
    ULONGLONG ExitCode;
    /* Raw exit operands. */
    ULONGLONG Info1, Info2;
    /* Guest continuation and address-space identity. */
    ULONGLONG Rip, Rsp, Cr3;
    /* Next-RIP and event injection evidence. */
    ULONGLONG Nrip, Event;
    /* CPU-local timestamp; not a cross-CPU wall clock. */
    ULONGLONG Tsc;
} KSW_SVM_TRACE;

/* Assembly consumes only the fixed prefix, whose offsets are asserted below. */
typedef struct _KSW_SVM_CPU {
    /* 00: hardware VMCB physical address. */
    ULONGLONG GuestPa;
    /* 08: host extended state image physical address. */
    ULONGLONG HostPa;
    /* 10: guest VMCB kernel mapping. */
    KSW_SVM_VMCB* Guest;
    /* 18: dedicated host stack top. */
    ULONGLONG StackTop;
    /* 20: original launch stack/continuation. */
    ULONGLONG LaunchRsp;
    /* 28: XSAVE area, 64-byte aligned. */
    PVOID Xstate;
    /* 30: requested XCR0 | XSS bits, paired with the selected save format. */
    ULONGLONG XstateMask;
    /* 38: original EFER before this CPU entered SVM. */
    ULONGLONG OriginalEfer;
    /* 40: original VM_HSAVE_PA. */
    ULONGLONG OriginalHsave;
    /* 48: GPR slots in x86 register-number order. RSP/RAX also live in VMCB. */
    ULONGLONG Gpr[16];
    /* C8: executable launch result. */
    NTSTATUS Result;
    /* CC: nonzero until the native continuation has completed. */
    volatile LONG Active;
    /* D0: stop request observed by the private VMMCALL handler. */
    volatile LONG StopRequested;
    /* D4: one-shot self-test exits directly to the launch continuation. */
    ULONG SelfTest;
    /* D8: captured RFLAGS before CLGI/CLI. */
    ULONGLONG LaunchFlags;
    /* E0: original CR0 while the host temporarily clears TS/EM for XSAVE. */
    ULONGLONG HostCr0;
    /* E8: permanently mapped System address space for VMRUN host state. */
    ULONGLONG HostCr3;
    /* F0: native-return scratch (RSP, RIP, RFLAGS). */
    ULONGLONG ReturnRsp, ReturnRip, ReturnFlags;
    /* 108: physical address written to VM_HSAVE_PA before launch. */
    ULONGLONG HsavePa;
    /* 110: zero selects XSAVE64; one selects compacted XSAVES64/XRSTORS64. */
    ULONG XstateCompacted;
    /* 114: CET MSRs exist and native return must restore ISST_ADDR/S_CET. */
    ULONG CetPresent;
    /* 118: immutable root XCR0, paired with the preallocated save-area layout. */
    ULONGLONG HostXcr0;
    /* 120: current guest XCR0; VMRUN/VMEXIT do not switch this register. */
    ULONGLONG GuestXcr0;
    /* 128/130: root save enablement and the independently virtualized guest XSS. */
    ULONGLONG HostXss, GuestXss;
    /* Resource and runtime ownership beyond the assembly prefix. */
    KSW_HVM_RUNTIME* Runtime;
    /* Public row owns processor identity and common states. */
    KSW_HVM_CPU_RESOURCE* Resource;
    /* Captured capability image used for all entry checks. */
    KSW_SVM_CAPS Caps;
    /* Host extended-state page, separate from hardware HSAVE. */
    KSW_SVM_VMCB* Host;
    /* Hardware private host-save page and its physical address. */
    PVOID Hsave;
    /* MSR permission map. */
    PVOID Msrpm;
    /* I/O permission map. */
    PVOID Iopm;
    /* Allocation bases retained for release. */
    PVOID Stack, XstateAllocation;
    /* XSAVE capacity; XCR0 changes are validated against this before entry. */
    ULONG XstateBytes;
    /* Pinned CPUID geometry for guest-mask-aware leaf D responses. */
    KSW_SVM_XSTATE_LAYOUT XstateLayout;
    /* Entry-stage evidence independent of VMX status bits. */
    volatile LONG Stage;
    /* Per-CPU self-test success marker. */
    ULONG TestPassed;
    /* Prevent a second VMMCALL after a native return whose ownership readback failed. */
    ULONG NativeReturnSeen;
    /* Preserve the originating failure across a successful cleanup rendezvous. */
    NTSTATUS FailureStatus;
    /* Stage associated with the original failed entry/stop. */
    ULONG FailureStage;
    /* Published ring position; only current processor writes. */
    ULONG TracePosition;
    /* Number of actual VMRUN attempts (each requests full TLB invalidation). */
    ULONGLONG TlbRequests;
    /* Fixed-capacity raw exit history. */
    KSW_SVM_TRACE Trace[KSW_SVM_TRACE_ROWS];
    /* Optional bounded nested-probe state; appended after every assembly-visible field. */
    struct _KSW_SVM_NESTED* Nested;
} KSW_SVM_CPU;
/* Assert all assembly-visible anchors against the C compiler. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, Gpr) == 0x48);
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, Result) == 0xc8);
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, LaunchFlags) == 0xd8);
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, HostCr3) == 0xe8);
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, ReturnRsp) == 0xf0);
/* The assembler uses this final fixed-prefix field during initial ownership setup. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, HsavePa) == 0x108);
/* Keep the format selector and optional native-return MSR guard paired with MASM. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, XstateCompacted) == 0x110);
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, CetPresent) == 0x114);
/* Switching masks must not change any preceding assembly-visible offsets. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, HostXcr0) == 0x118);
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, GuestXcr0) == 0x120);
/* XSS is not automatically switched by VMRUN/VMEXIT either. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, HostXss) == 0x128);
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, GuestXss) == 0x130);
/* MASM native restoration consumes these exact ordinary-VMCB offsets. */
C_ASSERT(KSW_VMCB_S_CET == 0x5e0 && KSW_VMCB_SSP == 0x5e8 && KSW_VMCB_ISST == 0x5f0);

/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, GuestPa) == 0x0);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, HostPa) == 0x8);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, Guest) == 0x10);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, StackTop) == 0x18);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, LaunchRsp) == 0x20);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, Xstate) == 0x28);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, XstateMask) == 0x30);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, OriginalEfer) == 0x38);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, OriginalHsave) == 0x40);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, Active) == 0xcc);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, StopRequested) == 0xd0);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, SelfTest) == 0xd4);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, HostCr0) == 0xe0);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, ReturnRip) == 0xf8);
/* Fixed assembly prefix field; never insert data ahead of this member. */
C_ASSERT(FIELD_OFFSET(KSW_SVM_CPU, ReturnFlags) == 0x100);

/* Runtime-private state, allocated only by prepare. */
typedef struct _KSW_SVM_STATE {
    /* Shared immutable identity map. */
    KSW_NPT Npt;
    /* Per-processor ownership array. */
    KSW_SVM_CPU* Cpus;
    /* Frozen topology size. */
    ULONG Count;
    /* Power generation that produced the self-test evidence. */
    LONG TestedPowerGeneration;
    /* Preparation and execution must use the same power epoch. */
    LONG PreparedPowerGeneration;
} KSW_SVM_STATE;

/* PASSIVE_LEVEL resource and capability helpers. */
NTSTATUS KswordSvmProbeCpu(KSW_SVM_CAPS* Caps);
NTSTATUS KswordSvmProbe(KSW_HVM_RUNTIME* Runtime);
NTSTATUS KswordSvmValidateFlags(KSW_HVM_RUNTIME* Runtime, ULONG Flags);
NTSTATUS KswordSvmPrepare(KSW_HVM_RUNTIME* Runtime, ULONG Flags);
VOID KswordSvmRelease(KSW_HVM_RUNTIME* Runtime);
NTSTATUS KswordSvmSelfTest(KSW_HVM_RUNTIME* Runtime, ULONG Flags);
NTSTATUS KswordSvmStart(KSW_HVM_RUNTIME* Runtime, ULONG Flags);
NTSTATUS KswordSvmStop(KSW_HVM_RUNTIME* Runtime);
NTSTATUS KswordNptBuild(KSW_NPT* Npt, const KSW_SVM_CAPS* Caps);
VOID KswordNptRelease(KSW_NPT* Npt);
/* Processor-pinned, nonpageable execution helpers. */
NTSTATUS KswordSvmBuildVmcb(KSW_SVM_CPU* Cpu);
NTSTATUS KswordSvmEnterCurrent(KSW_SVM_CPU* Cpu);
/* Called only after the assembly continuation has returned to native Windows. */
BOOLEAN KswordSvmVerifyNativeState(KSW_SVM_CPU* Cpu);
VOID KswordSvmTrace(KSW_SVM_CPU* Cpu, ULONG Stage);
ULONG KswordSvmExit(KSW_SVM_CPU* Cpu);
/* AMD assembly wrappers, never called on Intel. */
NTSTATUS KswordSvmAsmLaunch(KSW_SVM_CPU* Cpu);
ULONGLONG KswordSvmAsmCall(ULONGLONG Operation);
VOID KswordSvmAsmCaptureSegments(KSW_SVM_VMCB* Vmcb);
VOID KswordSvmAsmGuestResume(VOID);
VOID KswordSvmAsmTestGuest(VOID);
/* The caller holds the shared runtime lock across diagnostic resource reads. */
VOID KswordSvmMetrics(KSW_HVM_RUNTIME* Runtime, KSWORD_ARK_HVM_METRICS_RESPONSE* Response);

/* KD-only one-shot fault controls: stage 1=allocation, 2=before entry, 3=after continuation. */
extern volatile LONG g_KswSvmFaultStage;
/* Windows global index is checked against the frozen topology before use. */
extern volatile LONG g_KswSvmFaultCpu;
/* An explicit debugger write of one arms precisely one matching fault. */
extern volatile LONG g_KswSvmFaultArmed;
/* No registry, command-line or user-mode production interface enables these hooks. */
BOOLEAN KswordSvmFault(ULONG Stage, ULONG Cpu);
