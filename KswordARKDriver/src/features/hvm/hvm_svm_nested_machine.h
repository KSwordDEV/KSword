/* Execution/event transaction coordinator. It never issues VMRUN or calls a Windows ISR. */
#pragma once
#include "hvm_svm_nested_execute.h"
#include "hvm_svm_nested_interrupt.h"
#define KSW_NSVM_MACHINE_READY 0U
#define KSW_NSVM_MACHINE_FAULT 1U
#define KSW_NSVM_MACHINE_UNSUPPORTED 2U
#define KSW_NSVM_MACHINE_WINDOW 3U
#define KSW_NSVM_MACHINE_SHUTDOWN 4U
#define KSW_NSVM_STOP_READY 0U
#define KSW_NSVM_STOP_L2 1U
#define KSW_NSVM_STOP_OWNER 2U
#define KSW_NSVM_STOP_EVENTS 3U
#define KSW_NSVM_STOP_GIF 4U
#define KSW_NSVM_STOP_FAULT 5U
typedef struct _KSW_NSVM_MACHINE_IO {
    /* Returns an actual hardware acknowledgement count; it must remain retained until CommitNmi. */
    unsigned (*AcknowledgeNmi)(void* Context);
    /* Clear only an exact acknowledgement count after it was successfully queued. */
    int (*CommitNmi)(void* Context, unsigned Count);
    /* These callbacks run only with complete root state and closed physical GIF/IF. */
    unsigned (*ReadTpr)(void* Context);
    int (*WriteTpr)(void* Context, unsigned Value);
    /* Callback context is processor-owned nonpageable storage. */
    void* Context;
} KSW_NSVM_MACHINE_IO;
typedef struct _KSW_NSVM_MACHINE {
    /* The execution descriptor and every nested resource outlive this coordinator. */
    KSW_NSVM_EXECUTION* Execution;
    KSW_NSVM_MACHINE_IO Io;
    /* Controls are restored before interpreting raw exits or reflecting them to L1. */
    KSW_NSVM_INTERRUPT_OVERLAY Overlay;
    /* Exactly one queued event can be bound to a hardware entry attempt. */
    KSW_SVM_U64 ArmedToken, ArmedEvent, ArmedOwner;
    /* Preserve raw action/event and transition counts independently of guest instruction emulation. */
    KSW_SVM_U64 LastExit, Transitions;
    unsigned LastAction, LastPhysicalAction, NmiCount;
    /* One initial TPR observation is needed before any guest CR8 execution. */
    unsigned Initialized;
} KSW_NSVM_MACHINE;
/* Call on the pinned CPU after binding trusted callbacks and before the first hardware entry. */
unsigned KswSvmNestedMachineInitialize(KSW_NSVM_MACHINE* Machine);
/* Current must still contain the raw real VMEXIT; no caller may clear EVENTINFO first. */
unsigned KswSvmNestedMachineExit(KSW_NSVM_MACHINE* Machine);
/* Prepare the next attempt. WINDOW requires a separate execution-window operation, never VMRUN. */
unsigned KswSvmNestedMachineEntry(KSW_NSVM_MACHINE* Machine);
/* Query on the owner CPU; a remote summary is not an all-CPU stop acknowledgement. */
unsigned KswSvmNestedMachineCanStop(const KSW_NSVM_MACHINE* Machine);
