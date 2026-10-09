/*++

Module Name:

    process_inject.c

Abstract:

    R0-backed user-process injection helpers for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

NTSYSAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId,
    _Outptr_ PEPROCESS* Process
    );

NTKERNELAPI
NTSTATUS
ObOpenObjectByPointer(
    _In_ PVOID Object,
    _In_ ULONG HandleAttributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Out_ PHANDLE Handle
    );

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    _In_ PEPROCESS FromProcess,
    _In_reads_bytes_(BufferSize) PVOID FromAddress,
    _In_ PEPROCESS ToProcess,
    _Out_writes_bytes_(BufferSize) PVOID ToAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T NumberOfBytesCopied
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwAllocateVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID* BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    );

/*
 * KSWORD_ZW_CREATE_THREAD_EX_FN:
 * - Inputs: the target process handle, user entry point, optional argument, and stack options.
 * - Processing: matches the kernel ZwCreateThreadEx routine signature used to create the remote thread.
 * - Returns: NTSTATUS and optionally writes the created thread handle.
 */
typedef
NTSTATUS
(NTAPI* KSWORD_ZW_CREATE_THREAD_EX_FN)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PVOID StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags,
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PVOID AttributeList
    );

// 中文说明：已导出的 RTL 包装器可创建用户线程，参数顺序与 ZwCreateThreadEx 不同。
typedef NTSTATUS (NTAPI* KSWORD_RTL_CREATE_USER_THREAD_FN)(
    HANDLE ProcessHandle, PSECURITY_DESCRIPTOR SecurityDescriptor,
    BOOLEAN CreateSuspended, ULONG ZeroBits, SIZE_T MaximumStackSize,
    SIZE_T CommittedStackSize, PVOID StartAddress, PVOID Parameter,
    PHANDLE ThreadHandle, PCLIENT_ID ClientId);

/*
 * ZwWaitForSingleObject:
 * - Inputs: a kernel handle, alertable-wait flag, and optional relative timeout.
 * - Processing: waits for the remote thread handle created by ZwCreateThreadEx.
 * - Returns: NTSTATUS from the kernel wait operation.
 */
NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif

#ifndef PROCESS_CREATE_THREAD
#define PROCESS_CREATE_THREAD (0x0002)
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION (0x0008)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE (0x0020)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ (0x0010)
#endif

#ifndef THREAD_ALL_ACCESS
#define THREAD_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)
#endif

#ifndef MEM_COMMIT
#define MEM_COMMIT 0x00001000UL
#endif

#ifndef MEM_RESERVE
#define MEM_RESERVE 0x00002000UL
#endif

#ifndef MEM_RELEASE
#define MEM_RELEASE 0x00008000UL
#endif

#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x04UL
#endif

#ifndef PAGE_EXECUTE_READWRITE
#define PAGE_EXECUTE_READWRITE 0x40UL
#endif

#define KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_INJECT_PROCESS_REQUEST, payload)

static BOOLEAN
KswordARKInjectIsUserAddress(
    _In_ ULONG64 Address
    )
{
    return Address != 0ULL &&
        Address <= (ULONG64)(ULONG_PTR)MmHighestUserAddress;
}

/*
 * KswordARKInjectResolveZwCreateThreadEx:
 * - Inputs: none.
 * - Processing: resolves ZwCreateThreadEx at runtime because some WDK import libraries do not expose it.
 * - Returns: callable routine pointer, or NULL when the running kernel does not export the routine.
 */
static KSWORD_ZW_CREATE_THREAD_EX_FN
KswordARKInjectResolveZwCreateThreadEx(
    VOID
    )
{
    UNICODE_STRING routineName;

    RtlInitUnicodeString(&routineName, L"ZwCreateThreadEx");
    return (KSWORD_ZW_CREATE_THREAD_EX_FN)MmGetSystemRoutineAddress(&routineName);
}

static NTSTATUS
KswordARKInjectOpenProcess(
    _In_ ULONG ProcessId,
    _Out_ HANDLE* ProcessHandleOut,
    _Outptr_ PEPROCESS* ProcessObjectOut
    )
{
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    const ACCESS_MASK desiredAccess =
        PROCESS_CREATE_THREAD |
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE |
        PROCESS_VM_READ;

    if (ProcessHandleOut == NULL || ProcessObjectOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ProcessHandleOut = NULL;
    *ProcessObjectOut = NULL;

    status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &processObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /*
     * Open the exact object returned by PsLookupProcessByProcessId. Reopening by
     * numeric PID can select a different process if the target exits and the PID
     * is reused between lookup and handle creation.
     */
    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        desiredAccess,
        *PsProcessType,
        KernelMode,
        &processHandle);

    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(processObject);
        return status;
    }

    *ProcessHandleOut = processHandle;
    *ProcessObjectOut = processObject;
    return STATUS_SUCCESS;
}

static ULONG
KswordARKInjectStatusFromNtStatus(
    _In_ ULONG PhaseStatus,
    _In_ NTSTATUS Status
    )
{
    UNREFERENCED_PARAMETER(Status);
    return PhaseStatus;
}

NTSTATUS
KswordARKDriverInjectProcess(
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_INJECT_PROCESS_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_reads_bytes_(InputBufferLength) const KSWORD_ARK_INJECT_PROCESS_REQUEST* Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
{
    HANDLE processHandle = NULL;
    HANDLE threadHandle = NULL;
    PEPROCESS processObject = NULL;
    PVOID remoteBase = NULL;
    SIZE_T remoteRegionSize = 0U;
    SIZE_T bytesCopied = 0U;
    PVOID entryPoint = NULL;
    PVOID parameterAddress = NULL;
    ULONG allocationProtect = PAGE_READWRITE;
    BOOLEAN freeRemoteRegionOnFailure = FALSE;
    KSWORD_ZW_CREATE_THREAD_EX_FN createThreadEx = NULL;
    KSWORD_RTL_CREATE_USER_THREAD_FN createUserThread = NULL; // 保存真实 RTL 导出，禁止扫描 syscall 桩。
    NTSTATUS status = STATUS_SUCCESS;

    if (Response == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(KSWORD_ARK_INJECT_PROCESS_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    RtlZeroMemory(Response, OutputBufferLength);
    Response->version = KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION;
    Response->processId = Request->processId;
    Response->injectType = Request->injectType;
    Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_UNKNOWN;
    Response->flags = Request->flags;
    Response->lastStatus = STATUS_SUCCESS;
    Response->waitStatus = STATUS_SUCCESS;
    Response->entryPointAddress = Request->entryPointAddress;
    Response->parameterAddress = Request->parameterAddress;
    *BytesWrittenOut = sizeof(*Response);

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        Request->version != KSWORD_ARK_PROCESS_INJECT_PROTOCOL_VERSION ||
        Request->processId <= 4UL ||
        Request->payloadBytes == 0UL ||
        Request->payloadBytes > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES ||
        InputBufferLength < KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE ||
        (SIZE_T)Request->payloadBytes >
            (InputBufferLength - KSWORD_ARK_INJECT_REQUEST_HEADER_SIZE)) {
        Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    if (Request->injectType == KSWORD_ARK_PROCESS_INJECT_TYPE_DLL_PATH) {
        if ((Request->payloadBytes % sizeof(WCHAR)) != 0U ||
            ((const WCHAR*)Request->payload)[(Request->payloadBytes / sizeof(WCHAR)) - 1U] != L'\0' ||
            !KswordARKInjectIsUserAddress(Request->entryPointAddress)) {
            Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
            Response->lastStatus = STATUS_INVALID_PARAMETER;
            return STATUS_SUCCESS;
        }
        entryPoint = (PVOID)(ULONG_PTR)Request->entryPointAddress;
        allocationProtect = PAGE_READWRITE;
    }
    else if (Request->injectType == KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE) {
        allocationProtect = PAGE_EXECUTE_READWRITE;
    }
    else {
        Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_SUCCESS;
    }

    status = KswordARKInjectOpenProcess(Request->processId, &processHandle, &processObject);
    if (!NT_SUCCESS(status)) {
        Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_PROCESS_OPEN_FAILED;
        Response->lastStatus = status;
        return STATUS_SUCCESS;
    }

    remoteRegionSize = (SIZE_T)Request->payloadBytes;
    status = ZwAllocateVirtualMemory(
        processHandle,
        &remoteBase,
        0,
        &remoteRegionSize,
        MEM_COMMIT | MEM_RESERVE,
        allocationProtect);
    Response->remoteBaseAddress = (ULONG64)(ULONG_PTR)remoteBase;
    Response->remoteRegionSize = (ULONG64)remoteRegionSize;
    if (!NT_SUCCESS(status) || remoteBase == NULL) {
        Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_ALLOC_FAILED;
        Response->lastStatus = status;
        goto Exit;
    }
    freeRemoteRegionOnFailure = TRUE;

    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)Request->payload,
        processObject,
        remoteBase,
        (SIZE_T)Request->payloadBytes,
        KernelMode,
        &bytesCopied);
    Response->bytesWritten = (ULONG)bytesCopied;
    if (!NT_SUCCESS(status) || bytesCopied != (SIZE_T)Request->payloadBytes) {
        Response->status = KswordARKInjectStatusFromNtStatus(
            KSWORD_ARK_PROCESS_INJECT_STATUS_WRITE_FAILED,
            status);
        Response->lastStatus = NT_SUCCESS(status) ? STATUS_PARTIAL_COPY : status; // 短写也必须报告失败。
        goto Exit;
    }

    if (Request->injectType == KSWORD_ARK_PROCESS_INJECT_TYPE_SHELLCODE) {
        entryPoint = remoteBase;
        parameterAddress = (PVOID)(ULONG_PTR)Request->parameterAddress;
    }
    else {
        parameterAddress = remoteBase;
    }
    Response->entryPointAddress = (ULONG64)(ULONG_PTR)entryPoint;
    Response->parameterAddress = (ULONG64)(ULONG_PTR)parameterAddress;

    if (!KswordARKInjectIsUserAddress((ULONG64)(ULONG_PTR)entryPoint)) {
        Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INVALID_REQUEST;
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    createThreadEx = KswordARKInjectResolveZwCreateThreadEx();
    if (createThreadEx == NULL) {
        UNICODE_STRING routineName; // ZwCreateThreadEx 并非所有内核都导出。
        RtlInitUnicodeString(&routineName, L"RtlCreateUserThread"); // 使用内核实际导出的 RTL 线程创建包装器。
        createUserThread = (KSWORD_RTL_CREATE_USER_THREAD_FN)MmGetSystemRoutineAddress(&routineName); // 不使用用户态函数地址。
        if (createUserThread == NULL) { // 两个导出均不存在时保留具体不支持结果。
            Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_THREAD_FAILED; // 未创建线程。
            Response->lastStatus = STATUS_NOT_SUPPORTED; // 不伪造成功。
            goto Exit; // 回收尚未执行的远端分配。
        }
    }

    if (createThreadEx != NULL) { // 保留已导出 Zw 入口的原有调用约定。
        status = createThreadEx(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        processHandle,
        entryPoint,
        parameterAddress,
        0,
        0,
        0,
        0,
        NULL);
    } else { // RTL 内核包装器使用 OBJ_KERNEL_HANDLE 创建线程句柄。
        status = createUserThread(processHandle, NULL, FALSE, 0UL, 0U, 0U,
            entryPoint, parameterAddress, &threadHandle, NULL); // DLL 与 shellcode 共用远端入口和参数。
    }
    if (!NT_SUCCESS(status)) {
        Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_THREAD_FAILED;
        Response->lastStatus = status;
        goto Exit;
    }
    freeRemoteRegionOnFailure = FALSE;

    if ((Request->flags & KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD) != 0UL) {
        LARGE_INTEGER timeout;
        timeout.QuadPart = -10LL * 1000LL * 1000LL * 10LL;
        status = ZwWaitForSingleObject(threadHandle, FALSE, &timeout);
        Response->waitStatus = status;
        if (status != STATUS_SUCCESS) { // STATUS_TIMEOUT 是非负值，但线程尚未结束。
            Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_WAIT_FAILED;
            Response->lastStatus = status;
            goto Exit;
        }
    }

    Response->status = KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    Response->lastStatus = STATUS_SUCCESS;

Exit:
    if (threadHandle != NULL) {
        ZwClose(threadHandle);
        threadHandle = NULL;
    }
    if (freeRemoteRegionOnFailure && remoteBase != NULL && processHandle != NULL) {
        PVOID freeBase = remoteBase;
        SIZE_T freeRegionSize = 0U;
        (void)ZwFreeVirtualMemory(
            processHandle,
            &freeBase,
            &freeRegionSize,
            MEM_RELEASE);
    }
    if (processHandle != NULL) {
        ZwClose(processHandle);
        processHandle = NULL;
    }
    if (processObject != NULL) {
        ObDereferenceObject(processObject);
        processObject = NULL;
    }
    return STATUS_SUCCESS;
}
