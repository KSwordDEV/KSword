/*++

Module Name:

    process_memory.c

Abstract:

    Phase-11 read-only process virtual memory helpers for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"

#include <ntstrsafe.h>

// 取得已引用进程对象的真实创建时间，不通过用户态句柄推断身份。
NTKERNELAPI LONGLONG NTAPI PsGetProcessCreateTimeQuadPart(_In_ PEPROCESS Process);

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
ZwQueryVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ ULONG MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

#ifndef OBJ_KERNEL_HANDLE
#define OBJ_KERNEL_HANDLE 0x00000200L
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION (0x0400)
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ (0x0010)
#endif

#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE (0x0020)
#endif

#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION (0x0008)
#endif

#ifndef STATUS_PARTIAL_COPY
#define STATUS_PARTIAL_COPY ((NTSTATUS)0x8000000DL)
#endif

#ifndef STATUS_BUFFER_OVERFLOW
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005L)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

#ifndef STATUS_REQUEST_NOT_ACCEPTED
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#ifndef STATUS_DATA_ERROR
#define STATUS_DATA_ERROR ((NTSTATUS)0xC000003EL)
#endif

#define KSWORD_ARK_MEMORY_BASIC_INFORMATION_CLASS 0UL
#define KSWORD_ARK_MEMORY_MAPPED_FILENAME_INFORMATION_CLASS 2UL
#define KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE, data)
#define KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE \
    FIELD_OFFSET(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST, data)

/*
 * KswordARKMemoryRwCanary
 * Inputs:
 * - No input; this is a dedicated exported writable test cell.
 * Processing:
 * - Kernel-memory read/write UI can target this address to verify the R0
 *   kernel VA read/write path without modifying real kernel state.
 * Return behavior:
 * - No function return; callers read/write its bytes through the normal memory
 *   IOCTL path.  The value is intentionally volatile and exported so it is kept
 *   in the image and can be located by RVA from the PE export table.
 */
__declspec(dllexport) volatile ULONGLONG KswordARKMemoryRwCanary =
    0x1122334455667788ULL;

typedef struct _KSWORD_ARK_MEMORY_BASIC_INFORMATION
{
    PVOID BaseAddress;
    PVOID AllocationBase;
    ULONG AllocationProtect;
    SIZE_T RegionSize;
    ULONG State;
    ULONG Protect;
    ULONG Type;
} KSWORD_ARK_MEMORY_BASIC_INFORMATION;

typedef struct _KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_BUFFER
{
    UNICODE_STRING Name;
    WCHAR Buffer[KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS];
} KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_BUFFER;

static BOOLEAN
KswordARKMemoryIsUserAddressRange(
    _In_ ULONG64 BaseAddress,
    _In_ SIZE_T Length
    )
/*++

Routine Description:

    检查读取范围是否完全位于用户地址空间。中文说明：Phase-11 第一版只做
    进程用户虚拟内存，只读路径不允许借机读取内核地址或形成环绕区间。

Arguments:

    BaseAddress - 请求起始地址。
    Length - 请求长度，允许为零。

Return Value:

    TRUE 表示范围可交给 MmCopyVirtualMemory；FALSE 表示应拒绝。

--*/
{
    ULONG64 endAddress = 0ULL;
    ULONG64 highestUserAddress = (ULONG64)(ULONG_PTR)MmHighestUserAddress;

    if (Length == 0U) {
        return TRUE;
    }

    endAddress = BaseAddress + (ULONG64)Length - 1ULL;
    if (endAddress < BaseAddress) {
        return FALSE;
    }

    return endAddress <= highestUserAddress;
}

static BOOLEAN
KswordARKMemoryIsKernelAddressRange(
    _In_ ULONG64 BaseAddress,
    _In_ SIZE_T Length
    )
/*++

Routine Description:

    Validate a kernel virtual-address read range without touching memory.
    中文说明：该检查只验证高半区和回绕，不保证页面 present；真正访问由
    MmCopyMemory 完成，避免坏地址导致 bugcheck。

Arguments:

    BaseAddress - Requested kernel virtual address.
    Length - Requested byte count.

Return Value:

    TRUE if the range is syntactically a kernel VA range.

--*/
{
    ULONG64 endAddress = 0ULL;
    ULONG64 highestUserAddress = (ULONG64)(ULONG_PTR)MmHighestUserAddress;

    if (Length == 0U) {
        return TRUE;
    }

    endAddress = BaseAddress + (ULONG64)Length - 1ULL;
    if (endAddress < BaseAddress) {
        return FALSE;
    }

    return BaseAddress > highestUserAddress;
}

static NTSTATUS
KswordARKMemoryCopyKernelVirtualMemory(
    _In_ ULONG64 SourceAddress,
    _Out_writes_bytes_(BytesToRead) UCHAR* Destination,
    _In_ SIZE_T BytesToRead,
    _Out_ SIZE_T* BytesCopiedOut
    )
/*++

Routine Description:

    Copy kernel virtual memory into a caller-owned response buffer. 中文说明：
    使用 MmCopyMemory 的 virtual 模式读取内核地址；函数只读，不修改目标内存。

Arguments:

    SourceAddress - Kernel virtual source address.
    Destination - Output buffer.
    BytesToRead - Bytes requested.
    BytesCopiedOut - Receives bytes copied by MmCopyMemory.

Return Value:

    STATUS_SUCCESS or the MmCopyMemory/exception status.

--*/
{
    MM_COPY_ADDRESS copyAddress;
    SIZE_T copiedBytes = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Destination == NULL || BytesCopiedOut == NULL || BytesToRead == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesCopiedOut = 0U;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&copyAddress, sizeof(copyAddress));
    copyAddress.VirtualAddress = (PVOID)(ULONG_PTR)SourceAddress;
    __try {
        status = MmCopyMemory(
            Destination,
            copyAddress,
            BytesToRead,
            MM_COPY_MEMORY_VIRTUAL,
            &copiedBytes);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        copiedBytes = 0U;
    }

    *BytesCopiedOut = copiedBytes;
    return status;
}

static NTSTATUS
KswordARKMemoryWriteKernelVirtualMemory(
    _In_ ULONG64 DestinationAddress,
    _In_reads_bytes_(BytesToWrite) const UCHAR* Source,
    _In_ SIZE_T BytesToWrite,
    _Out_ SIZE_T* BytesWrittenOut
    )
/*++

Routine Description:

    Write bytes into kernel virtual memory under SEH protection. 中文说明：该路径
    仅在 R3 明确传入 KERNEL_ADDRESS + FORCE 后使用；函数不改页保护，目标页
    必须本身可写。

Arguments:

    DestinationAddress - Kernel virtual destination address.
    Source - Caller-provided bytes from METHOD_BUFFERED input.
    BytesToWrite - Number of bytes to write.
    BytesWrittenOut - Receives bytes copied before failure.

Return Value:

    STATUS_SUCCESS when all bytes were written; otherwise an exception/status code.

--*/
{
    SIZE_T writeOffset = 0U;
    NTSTATUS status = STATUS_SUCCESS;

    if (Source == NULL || BytesWrittenOut == NULL || BytesToWrite == 0U) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (KeGetCurrentIrql() > APC_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    while (writeOffset < BytesToWrite) {
        volatile UCHAR* destinationByte =
            (volatile UCHAR*)(ULONG_PTR)(DestinationAddress + (ULONG64)writeOffset);
        UCHAR verifyByte = 0U;

        /*
         * Use volatile byte stores and immediate read-back verification.  A
         * plain RtlCopyMemory can report no exception even when the caller later
         * observes unchanged data through a different path; verification makes
         * the IOCTL result reflect the actual persisted byte value.
         */
        __try {
            *destinationByte = Source[writeOffset];
            KeMemoryBarrier();
            verifyByte = *destinationByte;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            status = GetExceptionCode();
            break;
        }

        if (verifyByte != Source[writeOffset]) {
            status = STATUS_DATA_ERROR;
            break;
        }

        writeOffset += 1U;
    }

    *BytesWrittenOut = writeOffset;
    return (writeOffset == BytesToWrite) ? STATUS_SUCCESS : status;
}

static NTSTATUS
KswordARKMemoryOpenProcessForQuery(
    _In_ ULONG ProcessId,
    _In_ ACCESS_MASK DesiredAccess,
    _Out_ HANDLE* ProcessHandleOut,
    _Outptr_ PEPROCESS* ProcessObjectOut
    )
/*++

Routine Description:

    以只读查询所需权限打开目标进程，同时保留 PEPROCESS 引用。中文说明：先
    通过 PID 引用对象，再用 ObOpenObjectByPointer 在 KernelMode 下为同一对象
    创建句柄，避免 PID 退出并复用后查询落到另一进程。

Arguments:

    ProcessId - 目标 PID。
    DesiredAccess - ZwQueryVirtualMemory/MmCopyVirtualMemory 所需权限。
    ProcessHandleOut - 接收内核句柄；调用方必须 ZwClose。
    ProcessObjectOut - 接收 EPROCESS 引用；调用方必须 ObDereferenceObject。

Return Value:

    STATUS_SUCCESS 或底层打开/引用失败状态。

--*/
{
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    NTSTATUS status = STATUS_SUCCESS;

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
     * Bind the returned handle to the referenced process object. Reopening by
     * numeric PID after PsLookupProcessByProcessId can select a recycled PID.
     */
    status = ObOpenObjectByPointer(
        processObject,
        OBJ_KERNEL_HANDLE,
        NULL,
        DesiredAccess,
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

static VOID
KswordARKMemoryCopyUnicodeStringToFixedBuffer(
    _Out_writes_(DestinationChars) WCHAR* Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ const UNICODE_STRING* Source,
    _Out_ ULONG* CharsCopiedOut,
    _Out_ BOOLEAN* TruncatedOut
    )
/*++

Routine Description:

    将 UNICODE_STRING 安全复制到协议固定宽字符数组。中文说明：协议数组永远
    保留尾零，R3 可直接按 length 或尾零构造 std::wstring/QString。

Arguments:

    Destination - 目标固定数组。
    DestinationChars - 目标数组 WCHAR 容量。
    Source - 来源 UNICODE_STRING，可为空。
    CharsCopiedOut - 接收复制字符数，不含尾零。
    TruncatedOut - 接收是否截断。

Return Value:

    None.

--*/
{
    ULONG sourceChars = 0UL;
    ULONG charsToCopy = 0UL;

    if (CharsCopiedOut != NULL) {
        *CharsCopiedOut = 0UL;
    }
    if (TruncatedOut != NULL) {
        *TruncatedOut = FALSE;
    }
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    RtlZeroMemory(Destination, (SIZE_T)DestinationChars * sizeof(WCHAR));
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return;
    }

    sourceChars = (ULONG)(Source->Length / sizeof(WCHAR));
    charsToCopy = sourceChars;
    if (charsToCopy >= DestinationChars) {
        charsToCopy = DestinationChars - 1UL;
        if (TruncatedOut != NULL) {
            *TruncatedOut = TRUE;
        }
    }

    if (charsToCopy > 0UL) {
        RtlCopyMemory(
            Destination,
            Source->Buffer,
            (SIZE_T)charsToCopy * sizeof(WCHAR));
    }
    if (CharsCopiedOut != NULL) {
        *CharsCopiedOut = charsToCopy;
    }
}

NTSTATUS
KswordARKDriverQueryVirtualMemory(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_QUERY_VIRTUAL_MEMORY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    查询目标进程某地址所在虚拟内存区域。中文说明：此函数只调用
    ZwQueryVirtualMemory，不读取页内容，不修改目标进程；MappedFilename 是可选
    诊断字段，失败不会导致基础区域信息丢失。

Arguments:

    OutputBuffer - 响应缓冲区。
    OutputBufferLength - 响应缓冲区长度。
    Request - 请求包，包含 PID、地址和 flags。
    BytesWrittenOut - 接收固定响应长度。

Return Value:

    STATUS_SUCCESS 表示响应包有效；具体查询结果写入 response->queryStatus。

--*/
{
    KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE* response = NULL;
    KSWORD_ARK_MEMORY_BASIC_INFORMATION basicInformation;
    KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_BUFFER mappedNameBuffer;
    HANDLE processHandle = NULL;
    PEPROCESS processObject = NULL;
    SIZE_T returnedBytes = 0U;
    ULONG requestFlags = 0UL;
    BOOLEAN nameTruncated = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (Request->processId == 0UL || Request->processId <= 4UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!KswordARKMemoryIsUserAddressRange(Request->baseAddress, 1U)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    RtlZeroMemory(&basicInformation, sizeof(basicInformation));
    RtlZeroMemory(&mappedNameBuffer, sizeof(mappedNameBuffer));

    response = (KSWORD_ARK_QUERY_VIRTUAL_MEMORY_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->processId = Request->processId;
    response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_UNAVAILABLE;
    response->openStatus = STATUS_SUCCESS;
    response->basicStatus = STATUS_NOT_SUPPORTED;
    response->mappedFileNameStatus = STATUS_NOT_SUPPORTED;
    response->source = KSWORD_ARK_MEMORY_SOURCE_R0_ZW_QUERY_VIRTUAL_MEMORY;
    response->requestedBaseAddress = Request->baseAddress;
    response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE;

    requestFlags = Request->flags;
    if (requestFlags == 0UL) {
        requestFlags = KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_ALL;
    }

    status = KswordARKMemoryOpenProcessForQuery(
        Request->processId,
        PROCESS_QUERY_INFORMATION,
        &processHandle,
        &processObject);
    response->openStatus = status;
    if (!NT_SUCCESS(status)) {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_PROCESS_OPEN_FAILED;
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = ZwQueryVirtualMemory(
        processHandle,
        (PVOID)(ULONG_PTR)Request->baseAddress,
        KSWORD_ARK_MEMORY_BASIC_INFORMATION_CLASS,
        &basicInformation,
        sizeof(basicInformation),
        &returnedBytes);
    response->basicStatus = status;
    if (NT_SUCCESS(status)) {
        response->baseAddress = (ULONG64)(ULONG_PTR)basicInformation.BaseAddress;
        response->allocationBase = (ULONG64)(ULONG_PTR)basicInformation.AllocationBase;
        response->allocationProtect = basicInformation.AllocationProtect;
        response->regionSize = (ULONG64)basicInformation.RegionSize;
        response->state = basicInformation.State;
        response->protect = basicInformation.Protect;
        response->type = basicInformation.Type;
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT;
    }
    else {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_QUERY_FAILED;
        goto Exit;
    }

    if ((requestFlags & KSWORD_ARK_MEMORY_QUERY_FLAG_INCLUDE_MAPPED_FILE_NAME) != 0UL) {
        mappedNameBuffer.Name.Buffer = mappedNameBuffer.Buffer;
        mappedNameBuffer.Name.Length = 0U;
        mappedNameBuffer.Name.MaximumLength = (USHORT)sizeof(mappedNameBuffer.Buffer);

        returnedBytes = 0U;
        status = ZwQueryVirtualMemory(
            processHandle,
            (PVOID)(ULONG_PTR)Request->baseAddress,
            KSWORD_ARK_MEMORY_MAPPED_FILENAME_INFORMATION_CLASS,
            &mappedNameBuffer,
            sizeof(mappedNameBuffer),
            &returnedBytes);
        response->mappedFileNameStatus = status;
        if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
            KswordARKMemoryCopyUnicodeStringToFixedBuffer(
                response->mappedFileName,
                KSWORD_ARK_MEMORY_MAPPED_FILE_NAME_CHARS,
                &mappedNameBuffer.Name,
                &response->mappedFileNameLengthChars,
                &nameTruncated);
            if (response->mappedFileNameLengthChars > 0UL) {
                response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_MAPPED_FILE_NAME_PRESENT;
            }
            if (nameTruncated || status == STATUS_BUFFER_OVERFLOW) {
                response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_MAPPED_FILE_NAME_TRUNCATED;
            }
        }
        else {
            response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_NAME_FAILED;
        }
    }

Exit:
    if (processHandle != NULL) {
        ZwClose(processHandle);
        processHandle = NULL;
    }
    if (processObject != NULL) {
        ObDereferenceObject(processObject);
        processObject = NULL;
    }

    if (response->queryStatus == KSWORD_ARK_MEMORY_QUERY_STATUS_UNAVAILABLE) {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_OK;
    }
    else if ((response->fieldFlags & KSWORD_ARK_MEMORY_FIELD_BASIC_PRESENT) != 0UL &&
        response->queryStatus != KSWORD_ARK_MEMORY_QUERY_STATUS_OK) {
        response->queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_PARTIAL;
    }

    *BytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverReadVirtualMemoryInternal(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST* Request,
    _In_ ULONGLONG ExpectedCreationTime100ns,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    从目标进程用户地址空间复制一段内存到响应包。中文说明：第一版只读，使用
    MmCopyVirtualMemory；任何失败都写入响应状态，R3 负责在视图内展示 NTSTATUS，
    不需要弹窗刷屏。

Arguments:

    OutputBuffer - 响应缓冲区，头部后紧跟 data。
    OutputBufferLength - 响应缓冲区长度。
    Request - 请求包，包含 PID、起始地址和读取长度。
    BytesWrittenOut - 接收实际响应字节数。

Return Value:

    STATUS_SUCCESS 表示响应包有效；读取失败细节写入 response->readStatus。

--*/
{
    KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE* response = NULL;
    PEPROCESS processObject = NULL;
    SIZE_T bytesCopied = 0U;
    SIZE_T bytesAvailable = 0U;
    SIZE_T bytesToRead = 0U;
    BOOLEAN zeroFillUnreadable = FALSE;
    BOOLEAN readKernelAddress = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    readKernelAddress =
        ((Request->flags & KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS) != 0UL) ? TRUE : FALSE;

    if (!readKernelAddress && (Request->processId == 0UL || Request->processId <= 4UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Request->bytesToRead > KSWORD_ARK_MEMORY_READ_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Request->bytesToRead == 0U) {
        RtlZeroMemory(OutputBuffer, OutputBufferLength);
        response = (KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*)OutputBuffer;
        response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
        response->headerSize = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        response->processId = readKernelAddress ? 0UL : Request->processId;
        response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        response->lookupStatus = STATUS_SUCCESS;
        response->copyStatus = STATUS_SUCCESS;
        response->source = readKernelAddress
            ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
            : KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_VIRTUAL_MEMORY;
        response->requestedBaseAddress = Request->baseAddress;
        response->requestedBytes = 0UL;
        response->maxBytesPerRequest = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
        response->fieldFlags |= readKernelAddress
            ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
            : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE;
        *BytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }
    if (readKernelAddress) {
        if (!KswordARKMemoryIsKernelAddressRange(Request->baseAddress, (SIZE_T)Request->bytesToRead)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else if (!KswordARKMemoryIsUserAddressRange(Request->baseAddress, (SIZE_T)Request->bytesToRead)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);

    response = (KSWORD_ARK_READ_VIRTUAL_MEMORY_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->headerSize = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
    response->processId = readKernelAddress ? 0UL : Request->processId;
    response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE;
    response->lookupStatus = STATUS_SUCCESS;
    response->copyStatus = STATUS_NOT_SUPPORTED;
    response->source = readKernelAddress
        ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
        : KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_VIRTUAL_MEMORY;
    response->requestedBaseAddress = Request->baseAddress;
    response->requestedBytes = Request->bytesToRead;
    response->maxBytesPerRequest = KSWORD_ARK_MEMORY_READ_MAX_BYTES;
    response->fieldFlags |= readKernelAddress
        ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
        : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE;
    zeroFillUnreadable =
        ((Request->flags & KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE) != 0UL) ? TRUE : FALSE;

    bytesAvailable = OutputBufferLength - KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
    bytesToRead = (SIZE_T)Request->bytesToRead;
    if (bytesToRead > bytesAvailable) {
        response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_BUFFER_TOO_SMALL;
        *BytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    if (readKernelAddress) {
        SIZE_T copyOffset = 0U;
        SIZE_T readableBytes = 0U;
        NTSTATUS firstCopyFailure = STATUS_SUCCESS;
        BOOLEAN anyCopyFailure = FALSE;

        while (copyOffset < bytesToRead) {
            SIZE_T chunkBytes = bytesToRead - copyOffset;
            SIZE_T chunkCopied = 0U;
            NTSTATUS chunkStatus = STATUS_SUCCESS;

            if (chunkBytes > PAGE_SIZE) {
                chunkBytes = PAGE_SIZE;
            }

            chunkStatus = KswordARKMemoryCopyKernelVirtualMemory(
                Request->baseAddress + (ULONG64)copyOffset,
                response->data + copyOffset,
                chunkBytes,
                &chunkCopied);
            readableBytes += chunkCopied;
            if (!NT_SUCCESS(chunkStatus) || chunkCopied != chunkBytes) {
                anyCopyFailure = TRUE;
                if (NT_SUCCESS(firstCopyFailure) && !NT_SUCCESS(chunkStatus)) {
                    firstCopyFailure = chunkStatus;
                }
            }
            copyOffset += chunkBytes;
        }

        if (anyCopyFailure && NT_SUCCESS(firstCopyFailure)) {
            firstCopyFailure = STATUS_PARTIAL_COPY;
        }
        response->copyStatus = anyCopyFailure ? firstCopyFailure : STATUS_SUCCESS;
        response->bytesRead = zeroFillUnreadable
            ? Request->bytesToRead
            : (ULONG)readableBytes;
        bytesCopied = zeroFillUnreadable ? bytesToRead : readableBytes;

        if (bytesCopied > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT;
        }
        if (!anyCopyFailure && readableBytes == bytesToRead) {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        }
        else if (readableBytes > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
            if (zeroFillUnreadable) {
                response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE;
            }
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY;
        }
        else {
            if (zeroFillUnreadable) {
                response->fieldFlags |=
                    KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT |
                    KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY |
                    KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE;
                bytesCopied = bytesToRead;
                response->bytesRead = Request->bytesToRead;
                response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED;
            }
            else {
                response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED;
            }
        }

        *BytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE + bytesCopied;
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &processObject);
    response->lookupStatus = status;
    if (!NT_SUCCESS(status)) {
        response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED;
        *BytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE;
        return STATUS_SUCCESS;
    }

    // 独立校验读取在同一已引用对象上比较真实创建时间，失配不调用复制。
    if (ExpectedCreationTime100ns != 0ULL &&
        (ULONGLONG)PsGetProcessCreateTimeQuadPart(processObject) != ExpectedCreationTime100ns) {
        response->lookupStatus = STATUS_INVALID_CID; // 保留可辨的身份失配状态。
        response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED; // 不发布任何数据。
        ObDereferenceObject(processObject); // 释放刚引用的目标进程对象。
        *BytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE; // 只返回固定响应头。
        return STATUS_SUCCESS; // 协议回执有效，读取本身失败。
    }

    if (zeroFillUnreadable) {
        SIZE_T copyOffset = 0U;
        SIZE_T readableBytes = 0U;
        NTSTATUS firstCopyFailure = STATUS_SUCCESS;
        BOOLEAN anyCopyFailure = FALSE;

        while (copyOffset < bytesToRead) {
            SIZE_T chunkBytes = bytesToRead - copyOffset;
            SIZE_T chunkCopied = 0U;
            NTSTATUS chunkStatus = STATUS_SUCCESS;

            if (chunkBytes > PAGE_SIZE) {
                chunkBytes = PAGE_SIZE;
            }

            chunkStatus = MmCopyVirtualMemory(
                processObject,
                (PVOID)(ULONG_PTR)(Request->baseAddress + (ULONG64)copyOffset),
                PsGetCurrentProcess(),
                response->data + copyOffset,
                chunkBytes,
                KernelMode,
                &chunkCopied);
            readableBytes += chunkCopied;
            if (!NT_SUCCESS(chunkStatus) || chunkCopied != chunkBytes) {
                anyCopyFailure = TRUE;
                if (NT_SUCCESS(firstCopyFailure) && !NT_SUCCESS(chunkStatus)) {
                    firstCopyFailure = chunkStatus;
                }
            }
            copyOffset += chunkBytes;
        }

        status = anyCopyFailure ? firstCopyFailure : STATUS_SUCCESS;
        response->copyStatus = status;
        response->bytesRead = Request->bytesToRead;
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT;
        bytesCopied = bytesToRead;

        if (!anyCopyFailure && readableBytes == bytesToRead) {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        }
        else {
            response->fieldFlags |=
                KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY |
                KSWORD_ARK_MEMORY_FIELD_ZERO_FILLED_UNREADABLE;
            response->readStatus = (readableBytes > 0U) ?
                KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY :
                KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED;
        }
    }
    else {
        status = MmCopyVirtualMemory(
            processObject,
            (PVOID)(ULONG_PTR)Request->baseAddress,
            PsGetCurrentProcess(),
            response->data,
            bytesToRead,
            KernelMode,
            &bytesCopied);
        response->copyStatus = status;
        response->bytesRead = (ULONG)bytesCopied;
        if (bytesCopied > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_READ_DATA_PRESENT;
        }

        if (NT_SUCCESS(status) && bytesCopied == bytesToRead) {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_OK;
        }
        else if (bytesCopied > 0U || status == STATUS_PARTIAL_COPY) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY;
        }
        else {
            response->readStatus = KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED;
        }
    }

    ObDereferenceObject(processObject);
    processObject = NULL;

    *BytesWrittenOut = KSWORD_ARK_MEMORY_READ_RESPONSE_HEADER_SIZE + bytesCopied;
    return STATUS_SUCCESS;
}

// 旧请求保留原有 PID 读取语义，确保已发布客户端兼容。
NTSTATUS
KswordARKDriverReadVirtualMemory(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
{
    return KswordARKDriverReadVirtualMemoryInternal(OutputBuffer, OutputBufferLength, Request, 0ULL, BytesWrittenOut); // 旧协议不声明创建时间。
}

// 新协议只调用含真实进程创建时间的同对象读取路径。
NTSTATUS
KswordARKDriverReadVirtualMemoryVerified(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_READ_VIRTUAL_MEMORY_VERIFIED_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    )
{
    KSWORD_ARK_READ_VIRTUAL_MEMORY_REQUEST legacyRequest = { 0 }; // 复用原读取数据路径与响应。
    if (Request == NULL || Request->size != sizeof(*Request) ||
        Request->version != KSWORD_ARK_VERIFIED_MEMORY_READ_VERSION ||
        Request->expectedCreationTime100ns == 0ULL || Request->bytesToRead == 0UL ||
        (Request->flags & ~KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE) != 0UL || Request->reserved != 0UL) {
        return STATUS_INVALID_PARAMETER; // 拒绝不完整身份、空读、未知选项和内核地址模式。
    }
    legacyRequest.flags = Request->flags; // 只允许可选的零填充标记。
    legacyRequest.processId = Request->processId; // 进程 PID 必须与创建时间一起验证。
    legacyRequest.baseAddress = Request->baseAddress; // 用户地址范围由共享路径校验。
    legacyRequest.bytesToRead = Request->bytesToRead; // 复制长度沿用既有上限。
    return KswordARKDriverReadVirtualMemoryInternal(OutputBuffer, OutputBufferLength, &legacyRequest,
        Request->expectedCreationTime100ns, BytesWrittenOut); // 在引用对象上检查后再复制。
}

NTSTATUS
KswordARKDriverWriteVirtualMemory(
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_WRITE_VIRTUAL_MEMORY_REQUEST* Request,
    _In_ size_t RequestBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    将 R3 提交的差异块写入目标进程用户地址空间。中文说明：调用方只传输已经
    与备份比对后的连续变化块；R0 仍会重新做 PID、范围、长度和输入缓冲校验。

Arguments:

    OutputBuffer - 固定响应缓冲区。
    OutputBufferLength - 响应缓冲区长度。
    Request - METHOD_BUFFERED 输入请求，头部后紧跟待写字节。
    RequestBufferLength - WDF 返回的实际输入缓冲长度。
    BytesWrittenOut - 接收固定响应长度。

Return Value:

    STATUS_SUCCESS 表示响应包有效；写入失败细节写入 response->writeStatus。

--*/
{
    KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE* response = NULL;
    PEPROCESS processObject = NULL;
    SIZE_T bytesCopied = 0U;
    SIZE_T bytesToWrite = 0U;
    SIZE_T requiredInputBytes = 0U;
    BOOLEAN writeKernelAddress = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (RequestBufferLength < KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE) {
        return STATUS_INVALID_PARAMETER;
    }
    writeKernelAddress =
        ((Request->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_KERNEL_ADDRESS) != 0UL) ? TRUE : FALSE;

    if (!writeKernelAddress && (Request->processId == 0UL || Request->processId <= 4UL)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Request->bytesToWrite == 0UL ||
        Request->bytesToWrite > KSWORD_ARK_MEMORY_WRITE_MAX_BYTES) {
        return STATUS_INVALID_PARAMETER;
    }

    bytesToWrite = (SIZE_T)Request->bytesToWrite;
    if (bytesToWrite > (MAXSIZE_T - KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE)) {
        return STATUS_INVALID_PARAMETER;
    }
    requiredInputBytes = KSWORD_ARK_MEMORY_WRITE_REQUEST_HEADER_SIZE + bytesToWrite;
    if (RequestBufferLength < requiredInputBytes) {
        return STATUS_INVALID_PARAMETER;
    }
    if (writeKernelAddress) {
        if (!KswordARKMemoryIsKernelAddressRange(Request->baseAddress, bytesToWrite)) {
            return STATUS_INVALID_PARAMETER;
        }
    }
    else if (!KswordARKMemoryIsUserAddressRange(Request->baseAddress, bytesToWrite)) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_WRITE_VIRTUAL_MEMORY_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_MEMORY_PROTOCOL_VERSION;
    response->size = sizeof(*response);
    response->processId = writeKernelAddress ? 0UL : Request->processId;
    response->fieldFlags =
        (writeKernelAddress
            ? KSWORD_ARK_MEMORY_FIELD_ADDRESS_KERNEL_RANGE
            : KSWORD_ARK_MEMORY_FIELD_ADDRESS_USER_RANGE) |
        KSWORD_ARK_MEMORY_FIELD_WRITE_DATA_PRESENT;
    response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_UNAVAILABLE;
    response->lookupStatus = STATUS_SUCCESS;
    response->copyStatus = STATUS_NOT_SUPPORTED;
    response->source = writeKernelAddress
        ? KSWORD_ARK_MEMORY_SOURCE_R0_MM_COPY_KERNEL_VIRTUAL
        : KSWORD_ARK_MEMORY_SOURCE_R0_MM_WRITE_VIRTUAL_MEMORY;
    response->requestedBaseAddress = Request->baseAddress;
    response->requestedBytes = Request->bytesToWrite;
    response->maxBytesPerRequest = KSWORD_ARK_MEMORY_WRITE_MAX_BYTES;

    if ((Request->flags & KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE) != 0UL) {
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_FORCE_WRITE_USED;
    }

    if (writeKernelAddress) {
        status = KswordARKMemoryWriteKernelVirtualMemory(
            Request->baseAddress,
            Request->data,
            bytesToWrite,
            &bytesCopied);
        response->copyStatus = status;
        response->bytesWritten = (ULONG)bytesCopied;

        if (NT_SUCCESS(status) && bytesCopied == bytesToWrite) {
            response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_OK;
        }
        else if (bytesCopied > 0U) {
            response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
            response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_PARTIAL_COPY;
        }
        else {
            response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_COPY_FAILED;
        }

        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = PsLookupProcessByProcessId(ULongToHandle(Request->processId), &processObject);
    response->lookupStatus = status;
    if (!NT_SUCCESS(status)) {
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_PROCESS_LOOKUP_FAILED;
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    status = MmCopyVirtualMemory(
        PsGetCurrentProcess(),
        (PVOID)Request->data,
        processObject,
        (PVOID)(ULONG_PTR)Request->baseAddress,
        bytesToWrite,
        KernelMode,
        &bytesCopied);
    response->copyStatus = status;
    response->bytesWritten = (ULONG)bytesCopied;

    if (NT_SUCCESS(status) && bytesCopied == bytesToWrite) {
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_OK;
    }
    else if (bytesCopied > 0U || status == STATUS_PARTIAL_COPY) {
        response->fieldFlags |= KSWORD_ARK_MEMORY_FIELD_PARTIAL_COPY;
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_PARTIAL_COPY;
    }
    else {
        response->writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_COPY_FAILED;
    }

    ObDereferenceObject(processObject);
    processObject = NULL;

    *BytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
