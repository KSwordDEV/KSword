#pragma once
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <winioctl.h>
#include <array>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include "../../shared/driver/KswordArkHvmNoAttachIoctl.h"
using NTSTATUS = LONG;

#define NTKERNELAPI
#define NT_SUCCESS(value) ((value) >= 0)
#define PAGE_SIZE 4096UL
#define PAGE_SHIFT 12
#define KSW_EPT_READ 1ULL
#define KSW_EPT_WRITE 2ULL
#define KSW_EPT_EXECUTE 4ULL
#define KSW_IA32_VMX_PROCBASED_CTLS2 0x48BUL
#define KSW_HVM_EXIT_ACTION_RESUME 0UL
#define KSW_HVM_EXIT_ACTION_DEVIRTUALIZE 1UL
#define KSW_HVM_EXIT_ACTION_FATAL 2UL
#define WDF_NO_HANDLE nullptr
#define WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(type, name)
#define KeMemoryBarrier MemoryBarrier
#define __readmsr fixtureReadMsr
#define __readdr fixtureReadDr
#define __writedr fixtureWriteDr
#define __writecr2 fixtureWriteCr2
#define NormalPagePriority 0UL
#define MdlMappingNoExecute 0x40000000UL
#define MdlMappingNoWrite 0x80000000UL
#define NtCurrentProcess GetCurrentProcess
#define MemoryBasicInformation 0
using EX_PUSH_LOCK = unsigned long long;
using PEPROCESS = void*;
using PETHREAD = void*;
using WDFWORKITEM = void*;
using WDFFILEOBJECT = void*;
using PRKPROCESS = void*;
struct KAPC_STATE { unsigned char opaque[128]; };
void KeStackAttachProcess(void*, void*);
void KeUnstackDetachProcess(void*);
struct PHYSICAL_ADDRESS { long long QuadPart; };
struct FixtureMdl { unsigned long long address, pfn; bool locked; };
using PMDL = FixtureMdl*;
enum { UserMode = 1, IoReadAccess = 1 };
struct KSW_HVM_EPT_PAGE { void* VirtualAddress; PHYSICAL_ADDRESS PhysicalAddress; };
struct KSW_HVM_RUNTIME
{
    KSW_HVM_EPT_PAGE EptPages[512]{};
    unsigned long EptPageCount = 0, EptRuleCount = 0, ProcessDispositionCount = 0;
    bool LocalEptArmed = false, EptpSwitchArmed = false;
    void* EptPml4 = nullptr;
    unsigned long long EptPointer = 0, FeatureFlags = 0, HighestMappedPhysicalAddress = 0;
    volatile LONG ResidentProcessorCount = 0;
};
struct KSW_HVM_GPR_FRAME
{
    unsigned long long Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, R8, R9, R10, R11, R12, R13, R14, R15;
};
struct KSW_HVM_RESIDENT_VCPU
{
    KSW_HVM_RUNTIME* Runtime = nullptr;
    unsigned long ProcessorIndex = 0;
    NTSTATUS LastStatus = STATUS_SUCCESS;
    BOOLEAN NoAttachBypass = FALSE;
    unsigned long long NoAttachWatchGeneration = 0;
    BOOLEAN NoAttachTfArmed = FALSE;
    unsigned long long NoAttachTfPin = 0, NoAttachTfBitmap = 0;
};
static_assert(sizeof(KSW_HVM_GPR_FRAME) == 120);
KSW_HVM_RUNTIME* KswordARKHvmGetRuntime();
void* KswordARKHvmAllocateEptPageLocked(KSW_HVM_RUNTIME*, PHYSICAL_ADDRESS*);
NTSTATUS KswordARKHvmResidentInvalidateEpt(unsigned long long);
unsigned char KswordARKHvmAsmInveptSingle(unsigned long long);
unsigned char KswordARKHvmVmcsFieldLoad(unsigned long, SIZE_T*);
unsigned char KswordARKHvmVmcsFieldStore(unsigned long, SIZE_T);
BOOLEAN KswordARKHvmResidentDeactivateCurrent(KSW_HVM_RESIDENT_VCPU*, unsigned long, BOOLEAN);
void* KeGetCurrentThread();
unsigned long long fixtureReadMsr(unsigned long);
unsigned long long fixtureReadDr(int);
void fixtureWriteDr(int, unsigned long long);
void fixtureWriteCr2(unsigned long long);
void* MmGetSystemAddressForMdlSafe(PMDL, unsigned long);
NTSTATUS ZwQueryVirtualMemory(HANDLE, void*, int, MEMORY_BASIC_INFORMATION*, SIZE_T, SIZE_T*);
PMDL IoAllocateMdl(void*, unsigned long, BOOLEAN, BOOLEAN, void*);
void MmProbeAndLockPages(PMDL, int, int);
unsigned long long* MmGetMdlPfnArray(PMDL);
void MmUnlockPages(PMDL);
void IoFreeMdl(PMDL);
inline void* MmHighestUserAddress = reinterpret_cast<void*>(0x00007FFFFFFEFFFFULL);
