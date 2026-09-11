/*++

Module Name:

    io_queue.c

Abstract:

    This file contains queue setup plus read/stop callbacks.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "driver/KswordArkWindowBandIoctl.h"
#include "io_queue.tmh"

#ifdef ALLOC_PRAGMA
#pragma alloc_text (PAGE, KswordARKDriverQueueInitialize)
#endif

NTSTATUS
KswordARKDriverQueueInitialize(
    _In_ WDFDEVICE Device,
    _In_ BOOLEAN PowerManaged
    )
/*++

Routine Description:

     Configure the default queue and callbacks.

Arguments:

    Device - Handle to a framework device object.
    PowerManaged - TRUE only for the compatibility PnP device. Control devices
        never participate in power management, so their default queue must be
        created with PowerManaged explicitly cleared instead of WdfUseDefault.

Return Value:

    NTSTATUS

--*/
{
    WDFQUEUE queue;
    NTSTATUS status;
    WDF_IO_QUEUE_CONFIG queueConfig;

    PAGED_CODE();

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(
        &queueConfig,
        WdfIoQueueDispatchParallel
        );

    // 显式写死电源管理属性，排除不同 KMDF 版本对 WdfUseDefault 的解析差异。
    queueConfig.PowerManaged = PowerManaged ? WdfTrue : WdfFalse;
    queueConfig.EvtIoDeviceControl = KswordARKDriverEvtIoDeviceControl;
    queueConfig.EvtIoRead = KswordARKDriverEvtIoRead;
    // EvtIoStop 只在电源管理队列上有意义，控制设备队列必须留空。
    queueConfig.EvtIoStop = PowerManaged ? KswordARKDriverEvtIoStop : NULL;

    status = WdfIoQueueCreate(
        Device,
        &queueConfig,
        WDF_NO_OBJECT_ATTRIBUTES,
        &queue
        );

    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfIoQueueCreate failed %!STATUS!", status);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
KswordARKDriverEvtIoInCallerContext(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request
    )
{
    WDF_REQUEST_PARAMETERS parameters;
    NTSTATUS status = STATUS_SUCCESS;

    WDF_REQUEST_PARAMETERS_INIT(&parameters);
    WdfRequestGetParameters(Request, &parameters);
    if (parameters.Type == WdfRequestTypeDeviceControl &&
        (parameters.Parameters.DeviceIoControl.IoControlCode == IOCTL_KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY ||
         parameters.Parameters.DeviceIoControl.IoControlCode == IOCTL_KSWORD_ARK_WINDOW_BAND)) {
        KswordARKDriverDispatchDeviceControl(
            Device,
            WDF_NO_HANDLE,
            Request,
            parameters.Parameters.DeviceIoControl.OutputBufferLength,
            parameters.Parameters.DeviceIoControl.InputBufferLength,
            parameters.Parameters.DeviceIoControl.IoControlCode);
        return;
    }

    status = WdfDeviceEnqueueRequest(Device, Request);
    if (!NT_SUCCESS(status)) {
        TraceEvents(
            TRACE_LEVEL_ERROR,
            TRACE_QUEUE,
            "WdfDeviceEnqueueRequest failed %!STATUS!",
            status);
        WdfRequestComplete(Request, status);
    }
}


VOID
KswordARKDriverEvtIoRead(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t Length
    )
/*++

Routine Description:

    This event is invoked when the framework receives IRP_MJ_READ request.

Arguments:

    Queue - Handle to the queue object.
    Request - Handle to a framework request object.
    Length - Requested output length in bytes.

Return Value:

    VOID

--*/
{
    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PVOID outputBuffer = NULL;
    size_t outputBufferLength = 0;
    size_t bytesWritten = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(Length);

    status = WdfRequestRetrieveOutputBuffer(
        Request,
        1,
        &outputBuffer,
        &outputBufferLength);
    if (!NT_SUCCESS(status)) {
        TraceEvents(TRACE_LEVEL_ERROR, TRACE_QUEUE, "WdfRequestRetrieveOutputBuffer failed %!STATUS!", status);
        WdfRequestCompleteWithInformation(Request, status, 0);
        return;
    }

    status = KswordARKDriverReadNextLogLine(
        device,
        outputBuffer,
        outputBufferLength,
        &bytesWritten);
    WdfRequestCompleteWithInformation(Request, status, bytesWritten);
}

VOID
KswordARKDriverEvtIoStop(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ ULONG ActionFlags
)
/*++

Routine Description:

    This event is invoked for a power-managed queue before the device leaves D0.

Arguments:

    Queue - Handle to the queue object.
    Request - Handle to a framework request object.
    ActionFlags - Bitwise OR of one or more WDF_REQUEST_STOP_ACTION_FLAGS values.

Return Value:

    VOID

--*/
{
    TraceEvents(
        TRACE_LEVEL_INFORMATION,
        TRACE_QUEUE,
        "%!FUNC! Queue 0x%p, Request 0x%p ActionFlags %d",
        Queue,
        Request,
        ActionFlags);

    UNREFERENCED_PARAMETER(Queue);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(ActionFlags);
}
