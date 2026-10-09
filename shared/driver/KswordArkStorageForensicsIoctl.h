#pragma once

#include "KswordArkProcessIoctl.h"

// ============================================================
// KswordArkStorageForensicsIoctl.h
// 作用：
// - 定义物理磁盘多后端取证读写的唯一 R3/R0 协议；
// - 查询接口只返回能力与边界，不隐式切换访问后端；
// - 写入接口要求显式确认令牌，并由 R0 再执行系统盘与范围预检。
// ============================================================

#define KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION 1UL
// 仅捕获读/写请求使用 V2；查询、普通读写请求及所有响应保持 V1。
#define KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_VERSION 2UL
#define KSWORD_ARK_RAW_DISK_CAPTURED_READ_VERSION 2UL

#define KSWORD_ARK_IOCTL_FUNCTION_QUERY_RAW_DISK_BACKEND 0x8C4UL
#define KSWORD_ARK_IOCTL_FUNCTION_READ_RAW_DISK          0x8C5UL
#define KSWORD_ARK_IOCTL_FUNCTION_WRITE_RAW_DISK         0x8C6UL

#define IOCTL_KSWORD_ARK_QUERY_RAW_DISK_BACKEND \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_QUERY_RAW_DISK_BACKEND, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS)

#define IOCTL_KSWORD_ARK_READ_RAW_DISK \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_READ_RAW_DISK, \
        METHOD_BUFFERED, \
        FILE_READ_ACCESS)

#define IOCTL_KSWORD_ARK_WRITE_RAW_DISK \
    CTL_CODE( \
        KSWORD_ARK_IOCTL_DEVICE_TYPE, \
        KSWORD_ARK_IOCTL_FUNCTION_WRITE_RAW_DISK, \
        METHOD_BUFFERED, \
        FILE_WRITE_ACCESS)

#define KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK 1UL
#define KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT  2UL
#define KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER    3UL

#define KSWORD_ARK_RAW_DISK_CAP_WINDOWS_STACK 0x00000001UL
#define KSWORD_ARK_RAW_DISK_CAP_STORAGE_PORT  0x00000002UL
#define KSWORD_ARK_RAW_DISK_CAP_CONTROLLER    0x00000004UL
#define KSWORD_ARK_RAW_DISK_CAP_READ           0x00000010UL
#define KSWORD_ARK_RAW_DISK_CAP_WRITE          0x00000020UL
#define KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK    0x00000040UL
#define KSWORD_ARK_RAW_DISK_CAP_OFFLINE        0x00000080UL
#define KSWORD_ARK_RAW_DISK_CAP_SCSI_ADDRESS   0x00000100UL
#define KSWORD_ARK_RAW_DISK_CAP_NVME           0x00000200UL
#define KSWORD_ARK_RAW_DISK_CAP_ATA            0x00000400UL

#define KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_READ  0x00000001UL
#define KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE      0x00000002UL
#define KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_WRITE 0x00000004UL
#define KSWORD_ARK_RAW_DISK_FLAG_FUA                     0x00000008UL

#define KSWORD_ARK_RAW_DISK_STATUS_OK                  0UL
#define KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST     1UL
#define KSWORD_ARK_RAW_DISK_STATUS_DISK_NOT_FOUND      2UL
#define KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE 3UL
#define KSWORD_ARK_RAW_DISK_STATUS_RANGE_INVALID       4UL
#define KSWORD_ARK_RAW_DISK_STATUS_ALIGNMENT_REQUIRED  5UL
#define KSWORD_ARK_RAW_DISK_STATUS_SYSTEM_DISK_BLOCKED 6UL
#define KSWORD_ARK_RAW_DISK_STATUS_ACCESS_DENIED       7UL
#define KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED           8UL
#define KSWORD_ARK_RAW_DISK_STATUS_BUFFER_TOO_SMALL    9UL
#define KSWORD_ARK_RAW_DISK_STATUS_NOT_SUPPORTED       10UL
// 捕获来源 GUID 已更换，或原始字节已改变时禁止写入。
#define KSWORD_ARK_RAW_DISK_STATUS_SOURCE_CHANGED      11UL
#define KSWORD_ARK_RAW_DISK_STATUS_ORIGINAL_CHANGED    12UL

#define KSWORD_ARK_RAW_DISK_CONFIRMATION_TOKEN 0x4B445746UL
#define KSWORD_ARK_RAW_DISK_DEFAULT_SECTOR_SIZE 512UL
#define KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES (256UL * 1024UL)
#define KSWORD_ARK_RAW_DISK_MODEL_CHARS 96U
#define KSWORD_ARK_RAW_DISK_SERIAL_CHARS 96U
#define KSWORD_ARK_RAW_DISK_PATH_CHARS 160U
#define KSWORD_ARK_RAW_DISK_DETAIL_CHARS 256U

typedef struct _KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long diskNumber;
    unsigned long requestedBackend;
    unsigned long flags;
    unsigned long reserved;
} KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST,
  *PKSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST;

typedef struct _KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long capabilityFlags;
    unsigned long diskNumber;
    unsigned long requestedBackend;
    unsigned long availableBackendMask;
    unsigned long logicalSectorSize;
    unsigned long physicalSectorSize;
    unsigned long busType;
    unsigned long pathId;
    unsigned long targetId;
    unsigned long lun;
    long lastStatus;
    unsigned long reserved;
    unsigned long long diskSizeBytes;
    wchar_t devicePath[KSWORD_ARK_RAW_DISK_PATH_CHARS];
    wchar_t model[KSWORD_ARK_RAW_DISK_MODEL_CHARS];
    wchar_t serial[KSWORD_ARK_RAW_DISK_SERIAL_CHARS];
    wchar_t detail[KSWORD_ARK_RAW_DISK_DETAIL_CHARS];
} KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE,
  *PKSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE;

typedef struct _KSWORD_ARK_RAW_DISK_READ_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long diskNumber;
    unsigned long backend;
    unsigned long flags;
    unsigned long length;
    unsigned long reserved0;
    unsigned long reserved1;
    unsigned long long offset;
} KSWORD_ARK_RAW_DISK_READ_REQUEST,
  *PKSWORD_ARK_RAW_DISK_READ_REQUEST;

// 捕获读保留旧40字节前缀，只从已核验 GUID 的同一打开对象返回内容。
typedef struct _KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST
{
    unsigned long version; // 仅捕获读请求使用 V2。
    unsigned long size; // 固定56字节，拒绝截短/附加内容。
    unsigned long diskNumber; // 首次打开设备号。
    unsigned long backend; // 唯一指定的读取后端。
    unsigned long flags; // 保留系统盘读取确认。
    unsigned long length; // 长度上限256KiB。
    unsigned long reserved0; // 必须为零。
    unsigned long reserved1; // 必须为零。
    unsigned long long offset; // 冻结设备偏移。
    unsigned char expectedDeviceGuid[16]; // native GUID 字节，不使用文本布局。
} KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST,
  *PKSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST;

typedef struct _KSWORD_ARK_RAW_DISK_READ_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long backendUsed;
    unsigned long bytesTransferred;
    unsigned long logicalSectorSize;
    long lastStatus;
    unsigned long reserved;
    unsigned char data[1];
} KSWORD_ARK_RAW_DISK_READ_RESPONSE,
  *PKSWORD_ARK_RAW_DISK_READ_RESPONSE;

#define KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_RAW_DISK_READ_RESPONSE, data))

typedef struct _KSWORD_ARK_RAW_DISK_WRITE_REQUEST
{
    unsigned long version;
    unsigned long size;
    unsigned long diskNumber;
    unsigned long backend;
    unsigned long flags;
    unsigned long length;
    unsigned long confirmationToken;
    unsigned long reserved;
    unsigned long long offset;
    unsigned char data[1];
} KSWORD_ARK_RAW_DISK_WRITE_REQUEST,
  *PKSWORD_ARK_RAW_DISK_WRITE_REQUEST;

#define KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_RAW_DISK_WRITE_REQUEST, data))

// V2 保留 V1 的 40 字节前缀，随后是 native GUID16 和两段等长字节：原值、替换值。
typedef struct _KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST
{
    unsigned long version; // 必须为捕获写专用版本 2，旧驱动不能按 V1 降级解释。
    unsigned long size; // 必须严格等于 header + 2 * length。
    unsigned long diskNumber; // 捕获时的设备号，只用于首次打开。
    unsigned long backend; // 捕获时选择的读写后端。
    unsigned long flags; // 保留既有显式确认与系统盘门禁。
    unsigned long length; // 两段数据各自长度，范围 1..256 KiB。
    unsigned long confirmationToken; // 保留既有写确认令牌。
    unsigned long reserved; // 必须为零，禁止未声明的扩展。
    unsigned long long offset; // 捕获的对齐磁盘偏移。
    unsigned char expectedDeviceGuid[16]; // STORAGE_DEVICE_NUMBER_EX.DeviceGuid 的 native 布局。
    unsigned char data[1]; // original[length] 后紧接 replacement[length]。
} KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST,
  *PKSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST;

#define KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_HEADER_SIZE \
    ((unsigned long)FIELD_OFFSET(KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST, data))

typedef struct _KSWORD_ARK_RAW_DISK_WRITE_RESPONSE
{
    unsigned long version;
    unsigned long size;
    unsigned long status;
    unsigned long backendUsed;
    unsigned long bytesTransferred;
    unsigned long logicalSectorSize;
    long lastStatus;
    unsigned long reserved;
} KSWORD_ARK_RAW_DISK_WRITE_RESPONSE,
  *PKSWORD_ARK_RAW_DISK_WRITE_RESPONSE;
