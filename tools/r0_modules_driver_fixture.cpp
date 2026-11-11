// The runner inserts the production module inventory functions at the marker.
#define NOMINMAX
#include <Windows.h>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <cstddef>
#include "../shared/driver/KswordArkModuleIoctl.h"

using NTSTATUS = LONG;
using PEPROCESS = void*;
#define STATUS_SUCCESS ((NTSTATUS)0)
#ifndef STATUS_PENDING
#define STATUS_PENDING ((NTSTATUS)0x103L)
#endif
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000dL)
#endif
#define STATUS_INVALID_CID ((NTSTATUS)0xc000000bL)
#define STATUS_PROCESS_IS_TERMINATING ((NTSTATUS)0xc000010aL)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xc0000004L)
#define STATUS_DATA_ERROR ((NTSTATUS)0xc000003eL)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bbL)
#define NT_SUCCESS(x) (((NTSTATUS)(x)) >= 0)
#define KSW_HOOK_SCAN_TAG 0x1234UL
#define OBJ_KERNEL_HANDLE 0x200UL
#define KernelMode 0
#undef RtlCopyMemory
#undef RtlZeroMemory
#define RtlCopyMemory(d,s,n) std::memcpy((d),(s),(n))
#define RtlZeroMemory(d,n) std::memset((d),0,(n))
#define ULongToHandle(x) reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(x))
struct UNICODE_STRING { USHORT Length, MaximumLength; PWSTR Buffer; };
struct KSW_HOOK_SYSTEM_MODULE_ENTRY { HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags; USHORT LoadOrderIndex, InitOrderIndex, LoadCount, OffsetToFileName; UCHAR FullPathName[256]; };
struct KSW_HOOK_SYSTEM_MODULE_INFORMATION { ULONG NumberOfModules; KSW_HOOK_SYSTEM_MODULE_ENTRY Modules[1]; };
static PVOID MmHighestUserAddress = reinterpret_cast<PVOID>(0x7fff);
static PVOID fakeProcessType = reinterpret_cast<PVOID>(1);
static PVOID* PsProcessType = &fakeProcessType;
static bool fakeExited = false, malformedRegion = false, fakeNameFailure = false, malformedKernel = false;
static unsigned references = 0, handles = 0;
static NTSTATUS KswordARKHookBuildModuleSnapshot(KSW_HOOK_SYSTEM_MODULE_INFORMATION**, ULONG*);
static void KswordARKHookCopyBoundedAnsiToWide(const UCHAR*, ULONG, PWCHAR, ULONG);
static void ExFreePoolWithTag(void*, ULONG);
static NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS*);
static LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS);
static NTSTATUS PsGetProcessExitStatus(PEPROCESS);
static NTSTATUS ObOpenObjectByPointer(PEPROCESS, ULONG, void*, ULONG, PVOID, int, HANDLE*);
static NTSTATUS ZwQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
static NTSTATUS ZwClose(HANDLE);
static void ObDereferenceObject(PEPROCESS);
static ULONGLONG KeQueryInterruptTime();

/*SOURCE_INSERT*/

static NTSTATUS KswordARKHookBuildModuleSnapshot(KSW_HOOK_SYSTEM_MODULE_INFORMATION** output, ULONG* bytes) {
    *bytes = static_cast<ULONG>(offsetof(KSW_HOOK_SYSTEM_MODULE_INFORMATION, Modules) + 2 * sizeof(KSW_HOOK_SYSTEM_MODULE_ENTRY));
    *output = static_cast<KSW_HOOK_SYSTEM_MODULE_INFORMATION*>(std::calloc(1, *bytes));
    (*output)->NumberOfModules = malformedKernel ? 100 : 2;
    (*output)->Modules[0].ImageBase = reinterpret_cast<PVOID>(0x1000); (*output)->Modules[0].ImageSize = 4096;
    (*output)->Modules[1].ImageBase = reinterpret_cast<PVOID>(0x2000); (*output)->Modules[1].ImageSize = 8192;
    strcpy_s(reinterpret_cast<char*>((*output)->Modules[0].FullPathName), 256, "kernel.sys");
    strcpy_s(reinterpret_cast<char*>((*output)->Modules[1].FullPathName), 256, "driver.sys");
    return STATUS_SUCCESS;
}
static void KswordARKHookCopyBoundedAnsiToWide(const UCHAR* input, ULONG inputBytes, PWCHAR output, ULONG chars) {
    ULONG i = 0; for (; i + 1 < chars && i < inputBytes && input[i]; ++i) output[i] = input[i]; output[i] = 0;
}
static void ExFreePoolWithTag(void* pointer, ULONG) { std::free(pointer); }
static NTSTATUS PsLookupProcessByProcessId(HANDLE, PEPROCESS* process) { *process = reinterpret_cast<void*>(1); ++references; return STATUS_SUCCESS; }
static LONGLONG PsGetProcessCreateTimeQuadPart(PEPROCESS) { return 123456; }
static NTSTATUS PsGetProcessExitStatus(PEPROCESS) { return fakeExited ? STATUS_SUCCESS : STATUS_PENDING; }
static NTSTATUS ObOpenObjectByPointer(PEPROCESS, ULONG, void*, ULONG, PVOID, int, HANDLE* handle) { *handle = reinterpret_cast<HANDLE>(1); ++handles; return STATUS_SUCCESS; }
static NTSTATUS ZwClose(HANDLE) { --handles; return STATUS_SUCCESS; }
static void ObDereferenceObject(PEPROCESS) { --references; }
static ULONGLONG KeQueryInterruptTime() { return 0; }
static NTSTATUS ZwQueryVirtualMemory(HANDLE, PVOID address, ULONG informationClass, PVOID output, SIZE_T, PSIZE_T returned) {
    auto value = reinterpret_cast<ULONG_PTR>(address);
    if (informationClass == 2) {
        if (fakeNameFailure) return STATUS_NOT_SUPPORTED;
        auto* name = static_cast<KSW_MODULE_NAME_BUFFER*>(output);
        name->Name.Buffer = name->Storage;
        wcscpy_s(name->Storage, L"\\Device\\Volume\\sample.dll");
        name->Name.Length = static_cast<USHORT>(wcslen(name->Storage) * sizeof(WCHAR));
        *returned = sizeof(*name); return STATUS_SUCCESS;
    }
    auto* info = static_cast<KSW_MODULE_BASIC_INFORMATION*>(output);
    ULONG_PTR base, end, allocation = 0;
    if (value < 0x1000) { base = 0; end = 0x1000; }
    else if (value < 0x2000) { base = 0x1000; end = 0x2000; allocation = 0x1000; }
    else if (value < 0x3000) { base = 0x2000; end = 0x3000; allocation = 0x1000; }
    else if (value < 0x4000) { base = 0x3000; end = 0x4000; allocation = 0x1000; }
    else if (value < 0x5000) { base = 0x4000; end = 0x5000; }
    else if (value < 0x6000) { base = 0x5000; end = 0x6000; allocation = 0x5000; }
    else { base = 0x6000; end = 0x8000; }
    info->BaseAddress = reinterpret_cast<PVOID>(base); info->AllocationBase = reinterpret_cast<PVOID>(allocation);
    info->RegionSize = malformedRegion ? 0 : end - base; info->State = base == 0x3000 ? MEM_RESERVE : allocation ? MEM_COMMIT : MEM_FREE;
    info->Type = allocation && base != 0x3000 ? MEM_IMAGE : 0; *returned = sizeof(*info); return STATUS_SUCCESS;
}

int main() {
    alignas(KSWORD_ARK_ENUM_MODULES_RESPONSE) unsigned char storage[offsetof(KSWORD_ARK_ENUM_MODULES_RESPONSE, entries) + 2 * sizeof(KSWORD_ARK_MODULE_ENTRY)]{};
    auto* response = reinterpret_cast<KSWORD_ARK_ENUM_MODULES_RESPONSE*>(storage);
    KSWORD_ARK_ENUM_MODULES_REQUEST request{}; request.processId = 123;
    KswordModuleKernel(&request, response, 1);
    assert(response->returnedCount == 1 && response->nextCursor == 1 && response->status == KSWORD_ARK_MODULE_STATUS_PARTIAL);
    std::memset(storage, 0, sizeof(storage)); request.cursor = 1; KswordModuleKernel(&request, response, 2);
    assert(response->returnedCount == 1 && response->entries[0].baseAddress == 0x2000 && response->status == KSWORD_ARK_MODULE_STATUS_COMPLETE);
    std::memset(storage, 0, sizeof(storage)); request.cursor = 0; malformedKernel = true; KswordModuleKernel(&request, response, 2);
    assert(response->returnedCount == 0 && response->lastStatus == STATUS_DATA_ERROR); malformedKernel = false;
    std::memset(storage, 0, sizeof(storage)); request.cursor = 0; KswordModuleProcess(&request, response, 1);
    assert(response->returnedCount == 1 && response->entries[0].baseAddress == 0x1000 && response->entries[0].spanBytes == 0x3000);
    assert(response->nextCursor == 0x5000 && response->status == KSWORD_ARK_MODULE_STATUS_PARTIAL && !handles && !references);
    std::memset(storage, 0, sizeof(storage)); request.cursor = 0x5000; request.expectedCreateTime100ns = 123456; KswordModuleProcess(&request, response, 1);
    assert(response->returnedCount == 1 && response->entries[0].baseAddress == 0x5000 && response->status == KSWORD_ARK_MODULE_STATUS_COMPLETE);
    std::memset(storage, 0, sizeof(storage)); request.cursor = 0; request.filterBase = 0x1000; KswordModuleProcess(&request, response, 1);
    assert(response->returnedCount == 1 && response->entries[0].spanBytes == 0x3000 && response->status == KSWORD_ARK_MODULE_STATUS_COMPLETE);
    std::memset(storage, 0, sizeof(storage)); fakeNameFailure = true; KswordModuleProcess(&request, response, 1);
    assert(response->returnedCount == 1 && (response->flags & KSWORD_ARK_MODULE_FLAG_PATH_UNAVAILABLE) && response->status == KSWORD_ARK_MODULE_STATUS_PARTIAL); fakeNameFailure = false;
    std::memset(storage, 0, sizeof(storage)); request.expectedCreateTime100ns = 1; KswordModuleProcess(&request, response, 1);
    assert(response->status == KSWORD_ARK_MODULE_STATUS_INVALID && response->lastStatus == STATUS_INVALID_CID && !handles && !references);
    std::memset(storage, 0, sizeof(storage)); request.cursor = 0; request.filterBase = 0; request.expectedCreateTime100ns = 0; malformedRegion = true; KswordModuleProcess(&request, response, 1);
    assert(response->lastStatus == STATUS_DATA_ERROR && response->status == KSWORD_ARK_MODULE_STATUS_UNAVAILABLE && !handles && !references);
    return 0;
}
