/* 捕获写验证：同一个已持有磁盘上下文上检查 native GUID，再同后端回读原始范围。 */
#include "storage_forensics_internal.h"
#include <ntdddisk.h>

NTSTATUS
KswordStorageValidateCapturedIdentity(
    const KSW_STORAGE_DISK_CONTEXT* Context,
    ULONG DiskNumber,
    const UCHAR* ExpectedGuid,
    PULONG ProtocolStatus)
{
    /* 默认错误为真实后端失败，任何验证失败都没有写入动作。 */
    *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
    /* GUID 查询固定结构只由当前句柄返回，绝不重新打开磁盘路径。 */
    STORAGE_DEVICE_NUMBER_EX identity = { 0 };
    /* 实际返回字节数必须覆盖完整 GUID 和结构头。 */
    ULONG_PTR returned = 0U;
    /* 在同一对象上获取 GUID；数字设备号只作附加一致性验证。 */
    NTSTATUS status = KswordStorageSendHandleIoctl(Context->Handle,
        IOCTL_STORAGE_GET_DEVICE_NUMBER_EX, NULL, 0U, &identity, sizeof(identity), &returned);
    /* 设备移除或权限等真实I/O失败不能误报unsupported后重新按设备号读取。 */
    if (!NT_SUCCESS(status)) {
        /* 仅明确的能力拒绝允许宿主做已清GUID的只读兼容展示。 */
        if (status == STATUS_NOT_SUPPORTED || status == STATUS_INVALID_DEVICE_REQUEST
            || status == STATUS_INVALID_PARAMETER) {
            /* 该对象不实现GUID查询能力。 */
            *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED;
        }
        /* 普通失败保持最初的IO_FAILED分类，不允许unsupported回退。 */
        return status;
    }
    /* 成功但截短或结构不完整同样不能证明强身份。 */
    if (returned < sizeof(identity) || identity.Version < sizeof(identity)
        || identity.Size < sizeof(identity) || identity.DeviceType != FILE_DEVICE_DISK) {
        /* 标明不能取得强身份，界面可继续只读查看。 */
        *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED;
        /* 保留实际失败状态或将不完整身份归为不支持。 */
        return STATUS_NOT_SUPPORTED;
    }
    /* 全零 GUID 不提供设备身份，即使用户也发零 GUID 也必须拒绝。 */
    const GUID zeroGuid = { 0 };
    /* 验证 native 16 字节布局，不经文本、字节序或设备号重新查找转换。 */
    if (RtlCompareMemory(&identity.DeviceGuid, &zeroGuid, sizeof(zeroGuid)) == sizeof(zeroGuid)
        || identity.DeviceNumber != DiskNumber
        || RtlCompareMemory(&identity.DeviceGuid, ExpectedGuid,
            sizeof(identity.DeviceGuid)) != sizeof(identity.DeviceGuid)) {
        /* 来源改变不允许进入原值回读和写入。 */
        *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED;
        /* 稳定 NTSTATUS 表明当前对象已经不是捕获来源。 */
        return STATUS_WRONG_VOLUME;
    }

    /* 返回强身份验证成功，读写均继续使用相同上下文。 */
    *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_OK;
    /* 本函数只查询当前持有对象，不读取或写入其他设备。 */
    return STATUS_SUCCESS;
}

/* 捕获写在强身份检查通过后，复用同一上下文的原值读取与逐字节比较。 */
NTSTATUS
KswordStorageValidateCapturedWrite(
    const KSW_STORAGE_DISK_CONTEXT* Context,
    const KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST* Request,
    PVOID TransferBuffer,
    PULONG ProtocolStatus)
{
    /* 查询仍发生在写业务已打开并持续持有的上下文上。 */
    NTSTATUS status = KswordStorageValidateCapturedIdentity(Context, Request->diskNumber,
        Request->expectedDeviceGuid, ProtocolStatus);
    /* 任一身份失败都不能进入原值回读。 */
    if (!NT_SUCCESS(status)) {
        /* 来源改变与不支持均保持原始状态。 */
        return status;
    }
    /* 后续读取失败的默认协议分类是I/O失败。 */
    *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;

    /* 原字节只从与后续写相同的句柄或下层设备读取。 */
    ULONG transferred = 0U;
    /* 正常堆栈后端沿用当前同步句柄，而非以 DiskNumber 重新读取。 */
    if (Request->backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK) {
        /* 磁盘偏移由前置范围校验保证可表示且位于设备中。 */
        LARGE_INTEGER offset;
        /* 传递冻结偏移给同句柄读请求。 */
        offset.QuadPart = (LONGLONG)Request->offset;
        /* 同步读取完成信息只在当前函数存活期间使用。 */
        IO_STATUS_BLOCK ioStatus = { 0 };
        /* 不写磁盘；先取得完整旧字节。 */
        status = ZwReadFile(Context->Handle, NULL, NULL, NULL, &ioStatus,
            TransferBuffer, Request->length, &offset, NULL);
        /* 成功也须限制返回长度，禁止短读或异常大完成量冒充完整原值。 */
        if (NT_SUCCESS(status)) {
            /* 精确核对由后端返回的原始完成量。 */
            if (ioStatus.Information != Request->length) {
                /* 截短或异常完成量没有可安全比较的整个捕获范围。 */
                return STATUS_DEVICE_DATA_ERROR;
            }
            /* 保存已证明的完整读取长度。 */
            transferred = Request->length;
        }
    } else {
        /* 已引用下层对象与后续写使用同一选择函数。 */
        PDEVICE_OBJECT device = KswordStorageSelectBackendDevice(Context, Request->backend);
        /* 同一对象、同一偏移、同一后端进行读取，且不设置写入 FUA。 */
        status = KswordStorageSendDeviceReadWrite(device, IRP_MJ_READ, Request->offset,
            TransferBuffer, Request->length, FALSE, &transferred);
    }
    /* 不完整读取永远不能进入替换载荷拷贝和磁盘写入。 */
    if (!NT_SUCCESS(status) || transferred != Request->length) {
        /* 保留真实后端错误，成功短读规范为设备数据错误。 */
        return NT_SUCCESS(status) ? STATUS_DEVICE_DATA_ERROR : status;
    }
    /* 逐字节比较冻结原值，任何外部变化都要让操作者重新捕获。 */
    if (RtlCompareMemory(TransferBuffer, Request->data, Request->length) != Request->length) {
        /* 明确原值变化，不以写确认掩盖来源不一致。 */
        *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_ORIGINAL_CHANGED;
        /* 稳定状态表示源内容已经换代。 */
        return STATUS_REVISION_MISMATCH;
    }
    /* GUID 与原字节验证均通过，调用者仍执行原有后端写及完成量校验。 */
    *ProtocolStatus = KSWORD_ARK_RAW_DISK_STATUS_OK;
    /* 此函数自身只读，不修改任何设备字节。 */
    return STATUS_SUCCESS;
}
