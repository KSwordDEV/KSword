#pragma once

#include <ntddk.h>
#include <wdf.h>
#include "driver/KswordArkThreadIoctl.h"

EXTERN_C_START

// Verified control resolves and checks the referenced process/thread identity.
NTSTATUS KswordARKThreadIoctlControlVerified(
    _In_ WDFDEVICE Device, _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength, _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);

// DriverEntry 调用一次以初始化线程终止 APC 的全局生命周期注册表。
VOID
KswordARKThreadApcInitialize(
    VOID
    );

// 驱动卸载最前阶段调用；停止排队、取消队列项并等待所有 APC 回调退出。
VOID
KswordARKThreadApcUninitialize(
    VOID
    );

NTSTATUS
KswordARKDriverEnumerateThreads(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_ENUM_THREAD_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * KswordARKDriverTerminateThreadById
 * Inputs:
 * - ProcessId and ThreadId identify one target thread; ExitStatus supplies its
 *   termination status.
 * Processing:
 * - Resolves the process with the CID-first termination resolver, references
 *   the ETHREAD by TID, verifies ownership, then ends only that thread.
 * Return behavior:
 * - Returns STATUS_SUCCESS when the specified thread is terminated or already
 *   terminating; otherwise returns validation, resolution, or termination status.
 */
NTSTATUS
KswordARKDriverTerminateThreadById(
    _In_opt_ WDFDEVICE Device,
    _In_ ULONG ProcessId,
    _In_ ULONG ThreadId,
    _In_ NTSTATUS ExitStatus
    );

// 对已引用 ETHREAD 执行强制终止；调用方负责身份/模块安全校验和对象引用生命周期。
NTSTATUS
KswordARKDriverTerminateReferencedThread(
    _In_ PETHREAD ThreadObject,
    _In_ NTSTATUS ExitStatus
    );

// 实验性原始后端：不在两种 API 之间自动回退，便于 UI/日志准确显示实际调用。
NTSTATUS
KswordARKDriverTerminateReferencedThreadPsp(
    _In_ PETHREAD ThreadObject,
    _In_ NTSTATUS ExitStatus
    );

NTSTATUS
KswordARKDriverTerminateReferencedThreadZwOrNt(
    _In_ PETHREAD ThreadObject,
    _In_ NTSTATUS ExitStatus
    );

// 将 PsTerminateSystemThread 安排到目标系统线程自身上下文执行。
// SpecialToNormal=FALSE：直接排入 Normal Kernel APC；
// SpecialToNormal=TRUE：先排 Special Kernel APC，再由其排入 Normal Kernel APC。
NTSTATUS
KswordARKDriverQueueTerminateSystemThreadApc(
    _In_ PETHREAD ThreadObject,
    _In_ BOOLEAN SpecialToNormal
    );

// 对已引用且归属核对通过的普通进程线程排入进程终止 APC。
NTSTATUS
KswordARKDriverQueueTerminateProcessApc(
    _In_ PETHREAD ThreadObject,
    _In_ PEPROCESS ProcessObject,
    _In_ NTSTATUS ExitStatus
    );

/*
 * KswordARKThreadIoctlTerminate
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_TERMINATE_THREAD.
 * Processing:
 * - Validates the fixed request, evaluates process-termination safety policy,
 *   then forwards the requested PID/TID pair to the thread backend.
 * Return behavior:
 * - Returns validation, safety, or backend status and writes request size on success.
 */
NTSTATUS
KswordARKThreadIoctlTerminate(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

/*
 * KswordARKThreadIoctlSetSuspended
 * Inputs:
 * - WDF request buffer for IOCTL_KSWORD_ARK_SET_THREAD_SUSPENDED.
 * Processing:
 * - Validates PID/TID/action, applies suspend safety policy when needed, then
 *   opens a kernel thread handle after verifying ETHREAD ownership.
 * Return behavior:
 * - Returns validation, safety, ownership, or Zw/Nt suspend/resume status.
 */
NTSTATUS
KswordARKThreadIoctlSetSuspended(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

/*
 * KswordARKThreadIoctlControlDriverThread
 * Inputs:
 * - Fixed IOCTL_KSWORD_ARK_CONTROL_DRIVER_THREAD request.
 * Processing:
 * - Revalidates PID 4 identity, live start address, loaded-driver ownership,
 *   protected-module exclusions, and central safety policy before mutation.
 * Return behavior:
 * - Returns validation, policy, or suspend/resume/terminate backend status.
 */
NTSTATUS
KswordARKThreadIoctlControlDriverThread(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

/*
 * KswordARKDriverQueryThreadDetail
 * Inputs:
 * - Response/OutputBufferLength describe a fixed METHOD_BUFFERED response.
 * - Request supplies a TID and optional PID consistency check.
 * Processing:
 * - References ETHREAD by TID and samples PDB/DynData-backed fields with guarded
 *   reads.
 * Return behavior:
 * - Returns STATUS_SUCCESS when response.status contains the query outcome.
 */
NTSTATUS
KswordARKDriverQueryThreadDetail(
    _Out_writes_bytes_(OutputBufferLength) KSWORD_ARK_THREAD_DETAIL_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_opt_ const KSWORD_ARK_THREAD_DETAIL_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * KswordARKThreadIoctlQueryDetail
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_THREAD_DETAIL.
 * Processing:
 * - Retrieves fixed request/response buffers and forwards to the feature backend.
 * Return behavior:
 * - Returns WDF retrieval status or backend status; BytesReturned is fixed
 *   response size on success.
 */
NTSTATUS
KswordARKThreadIoctlQueryDetail(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

/*
 * KswordARKDriverQueryThreadRuntimeFields
 * Inputs:
 * - OutputBuffer/OutputBufferLength describe a variable METHOD_BUFFERED response.
 * - Request/InputBufferLength describe TID/PID plus PDB runtime field sample items.
 * Processing:
 * - References ETHREAD by TID and reads only bounded small fields from that object.
 * Return behavior:
 * - Returns STATUS_SUCCESS when response metadata is valid; row statuses carry
 *   individual sampling results.
 */
NTSTATUS
KswordARKDriverQueryThreadRuntimeFields(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) KSWORD_ARK_RUNTIME_FIELD_SAMPLE_RESPONSE* Response,
    _In_ size_t OutputBufferLength,
    _In_reads_bytes_(InputBufferLength) const KSWORD_ARK_THREAD_RUNTIME_FIELD_SAMPLE_REQUEST* Request,
    _In_ size_t InputBufferLength,
    _Out_ size_t* BytesWrittenOut
    );

/*
 * KswordARKThreadIoctlQueryRuntimeFields
 * Inputs:
 * - WDF request buffers for IOCTL_KSWORD_ARK_QUERY_THREAD_RUNTIME_FIELDS.
 * Processing:
 * - Retrieves variable buffers and forwards to the thread runtime sampler backend.
 * Return behavior:
 * - Returns validation/backend NTSTATUS and writes the actual response byte count.
 */
NTSTATUS
KswordARKThreadIoctlQueryRuntimeFields(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    );

EXTERN_C_END
