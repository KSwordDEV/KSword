#pragma once
#include "ark/ark_driver.h"
#include <ntddscsi.h>

// 私有磁盘上下文：句柄及所有设备引用属于一次打开，捕获验证不重新按设备号寻址。
typedef struct _KSW_STORAGE_DISK_CONTEXT
{
    HANDLE Handle; // 已打开的唯一同步磁盘句柄。
    PFILE_OBJECT FileObject; // 从同一句柄引用的文件对象。
    PDEVICE_OBJECT NamedDevice; // 从文件对象派生的设备，不按路径重查。
    PDEVICE_OBJECT TopDevice; // 当前已引用堆栈顶部。
    PDEVICE_OBJECT PortDevice; // 同堆栈已引用的存储端口设备。
    PDEVICE_OBJECT ControllerDevice; // 同堆栈已引用的最底层设备。
    ULONG LogicalSectorSize; // 逻辑扇区字节数，约束对齐。
    ULONG PhysicalSectorSize; // 物理扇区字节数。
    ULONGLONG DiskSizeBytes; // 设备容量，约束范围。
    ULONG BusType; // 总线类型供后端能力判断。
    ULONG CapabilityFlags; // 系统盘、离线等既有门禁。
    SCSI_ADDRESS ScsiAddress; // 当前对象的SCSI地址。
    WCHAR Path[KSWORD_ARK_RAW_DISK_PATH_CHARS]; // 首次打开使用的冻结路径。
    WCHAR Model[KSWORD_ARK_RAW_DISK_MODEL_CHARS]; // 当前对象查询到的型号。
    WCHAR Serial[KSWORD_ARK_RAW_DISK_SERIAL_CHARS]; // 当前对象查询到的序列号。
} KSW_STORAGE_DISK_CONTEXT, *PKSW_STORAGE_DISK_CONTEXT;


// 仅供同 feature 的捕获验证复用；无新增 IOCTL 或公共 R3/R0 协议副本。
NTSTATUS KswordStorageSendHandleIoctl(HANDLE Handle, ULONG IoctlCode, PVOID InputBuffer,
    ULONG InputLength, PVOID OutputBuffer, ULONG OutputLength, PULONG_PTR InformationOut);
PDEVICE_OBJECT KswordStorageSelectBackendDevice(const KSW_STORAGE_DISK_CONTEXT* Context, ULONG Backend);
NTSTATUS KswordStorageSendDeviceReadWrite(PDEVICE_OBJECT DeviceObject, UCHAR MajorFunction,
    ULONGLONG Offset, PVOID Buffer, ULONG Length, BOOLEAN ForceUnitAccess, PULONG BytesTransferredOut);

// 在同一持有的上下文上验证GUID及原字节；返回稳定协议原因与原始NTSTATUS。
NTSTATUS KswordStorageValidateCapturedIdentity(const KSW_STORAGE_DISK_CONTEXT* Context,
    ULONG DiskNumber, const UCHAR* ExpectedGuid, PULONG ProtocolStatus);
NTSTATUS KswordStorageValidateCapturedWrite(const KSW_STORAGE_DISK_CONTEXT* Context,
    const KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST* Request, PVOID TransferBuffer, PULONG ProtocolStatus);
