/* Backend 3 PoC 内部头：对外只暴露一个 IOCTL handler 作为 ioctl_registry 条目。 */
#pragma once
/* WDF 请求与基本 NT 类型。 */
#include <ntifs.h>
#include <wdf.h>
/* 共享协议定义。 */
#include "driver/KswordArkKernelNoAttachProbeIoctl.h"

/* ioctl_registry 调用的公开入口；返回通用 NTSTATUS。 */
NTSTATUS
KswordARKKernelNoAttachProbeIoctl(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned);
