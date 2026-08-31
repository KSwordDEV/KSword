/*++

Module Name:

    bugcheck_ioctl.c

Abstract:

    Silent optional BGRA32 bitmap upload for the VMware bugcheck panel.

--*/

#include "bugcheck_internal.h"
#include "bugcheck_panel.h"

NTSTATUS
KswordARKBugcheckIoctlConfigureDiagnostics(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_REQUEST* input = NULL;
    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE* output = NULL;
    NTSTATUS status;

    // 控制器在 DriverEntry 已保存设备对象，handler 仍显式标记本参数未参与业务决策。
    UNREFERENCED_PARAMETER(Device);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0U;

    // 请求和响应均为固定长度 METHOD_BUFFERED 包，长度不足直接由统一调度层返回失败。
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(*input),
        (PVOID*)&input,
        NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*input)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        sizeof(*output),
        (PVOID*)&output,
        NULL);
    if (!NT_SUCCESS(status) || OutputBufferLength < sizeof(*output)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    // 功能级失败写入响应状态，IOCTL 本身成功完成，R3 可得到精确准备阶段摘要。
    status = KswordARKBugcheckControlConfigure(input, output);
    if (NT_SUCCESS(status)) {
        *BytesReturned = sizeof(*output);
    }
    return status;
}

NTSTATUS
KswordARKBugcheckIoctlSetBitmap(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0;
    }
    return STATUS_NOT_SUPPORTED;
#else
    KSWORD_ARK_BUGCHECK_BITMAP_HEADER* header;
    ULONGLONG expectedStride;
    ULONGLONG expectedBytes;
    size_t requiredBytes;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_BUGCHECK_BITMAP_HEADER),
        (PVOID*)&header,
        NULL);
    if (!NT_SUCCESS(status) || InputBufferLength < sizeof(*header)) {
        return NT_SUCCESS(status) ? STATUS_BUFFER_TOO_SMALL : status;
    }

    expectedStride = (ULONGLONG)header->width * 4ULL;
    expectedBytes = expectedStride * (ULONGLONG)header->height;
    if (header->version != KSWORD_ARK_BUGCHECK_BITMAP_PROTOCOL_VERSION ||
        header->size != sizeof(*header) ||
        header->magic != KSWORD_ARK_BUGCHECK_BITMAP_MAGIC ||
        header->format != KSWORD_ARK_BUGCHECK_BITMAP_FORMAT_BGRA32 ||
        header->flags != 0 || header->reserved0 != 0 || header->reserved1 != 0 ||
        header->width == 0 || header->height == 0 ||
        header->width > KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH ||
        header->height > KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT ||
        expectedStride != header->stride ||
        expectedBytes == 0 ||
        expectedBytes > KSWORD_ARK_BUGCHECK_BITMAP_MAX_BYTES ||
        expectedBytes != header->dataLength) {
        return STATUS_INVALID_PARAMETER;
    }

    requiredBytes = sizeof(*header) + (size_t)header->dataLength;
    if (requiredBytes < sizeof(*header) || InputBufferLength < requiredBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // The legacy VMware uploader remains protocol-compatible while that
    // backend is screened from the active physical-machine drawing path.
    if (!g_KswordArkBugcheckState.Svga.Mapped) {
        return STATUS_SUCCESS;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBugcheckState.Bitmap.Uploading,
            1,
            0) != 0) {
        return STATUS_DEVICE_BUSY;
    }

    // Make the crash path fall back to the built-in text while the single
    // backing buffer is changing. Metadata becomes visible before Valid=1.
    InterlockedExchange(&g_KswordArkBugcheckState.Bitmap.Valid, 0);
    KeMemoryBarrier();
    RtlCopyMemory(
        g_KswordArkBugcheckBitmapPixels,
        ((PUCHAR)header) + sizeof(*header),
        header->dataLength);
    g_KswordArkBugcheckState.Bitmap.Width = header->width;
    g_KswordArkBugcheckState.Bitmap.Height = header->height;
    g_KswordArkBugcheckState.Bitmap.Stride = header->stride;
    g_KswordArkBugcheckState.Bitmap.DataLength = header->dataLength;
    g_KswordArkBugcheckState.Bitmap.BrandColorRgb =
        header->brandColorRgb & 0x00FFFFFFUL;
    if (g_KswordArkBugcheckState.Bitmap.BrandColorRgb == 0) {
        g_KswordArkBugcheckState.Bitmap.BrandColorRgb = 0x0078D4UL;
    }
    KeMemoryBarrier();
    InterlockedExchange(&g_KswordArkBugcheckState.Bitmap.Valid, 1);
    InterlockedExchange(&g_KswordArkBugcheckState.Bitmap.Uploading, 0);
    return STATUS_SUCCESS;
#endif
}

NTSTATUS
KswordARKBugcheckIoctlSetVerdictResources(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
#if !KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ENABLED
    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(InputBufferLength);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned != NULL) {
        *BytesReturned = 0;
    }
    return STATUS_NOT_SUPPORTED;
#else
    PVOID packet;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Device);
    UNREFERENCED_PARAMETER(OutputBufferLength);
    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (InputBufferLength <
            sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER) ||
        InputBufferLength > MAXULONG) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    packet = NULL;
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_HEADER),
        &packet,
        NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return KswordARKBugcheckPanelInstallVerdictResources(
        packet,
        (ULONG)InputBufferLength);
#endif
}
