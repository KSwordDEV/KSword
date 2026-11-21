/*++

Module Name:

    hwid_dispatch_hooks.c

Abstract:

    Dispatch-hook completion helpers for the HWID page.

Environment:

    Kernel-mode Driver Framework

--*/

#include <ntifs.h>

#include "hwid_dispatch_hooks.h"
#include "../../platform/pool_compat.h"

#include <ata.h>
#include <mountdev.h>
#include <mountmgr.h>
#include <ntdddisk.h>
#include <ntddscsi.h>
#include <ntstrsafe.h>

NTSYSAPI
ULONG
NTAPI
RtlRandomEx(
    _Inout_ PULONG Seed
    );

typedef struct _KSW_HWID_COMPLETION_CONTEXT
{
    PVOID SystemBuffer;
    PVOID UserBuffer;
    ULONG BufferLength;
    ULONG IoControlCode;
    ULONG TargetFlag;
    UCHAR OldControl;
    PVOID OldContext;
    PIO_COMPLETION_ROUTINE OldRoutine;
    KSWORD_ARK_HWID_DISPATCH_PROFILE Profile;
} KSW_HWID_COMPLETION_CONTEXT, *PKSW_HWID_COMPLETION_CONTEXT;

typedef struct _KSW_HWID_IDSECTOR
{
    USHORT wGenConfig;
    USHORT wNumCyls;
    USHORT wReserved;
    USHORT wNumHeads;
    USHORT wBytesPerTrack;
    USHORT wBytesPerSector;
    USHORT wSectorsPerTrack;
    USHORT wVendorUnique[3];
    CHAR sSerialNumber[20];
    USHORT wBufferType;
    USHORT wBufferSize;
    USHORT wECCSize;
    CHAR sFirmwareRev[8];
    CHAR sModelNumber[40];
    USHORT wMoreVendorUnique;
    USHORT wDoubleWordIO;
    USHORT wCapabilities;
    USHORT wReserved1;
    USHORT wPIOTiming;
    USHORT wDMATiming;
    USHORT wBS;
    USHORT wNumCurrentCyls;
    USHORT wNumCurrentHeads;
    USHORT wNumCurrentSectorsPerTrack;
    ULONG ulCurrentSectorCapacity;
    USHORT wMultSectorStuff;
    ULONG ulTotalAddressableSectors;
    USHORT wSingleWordDMA;
    USHORT wMultiWordDMA;
    UCHAR bThisReserved[128];
} KSW_HWID_IDSECTOR, *PKSW_HWID_IDSECTOR;

#define KSW_HWID_POOL_TAG 'dHwK'
#define KSW_HWID_NVIDIA_SMIL_IOCTL 0x8DE0008UL
#define KSW_HWID_NVIDIA_SMIL_MAX_BYTES 512UL
#define KSW_HWID_NSI_PROXY_ARP_IOCTL 0x0012001BUL
#define KSW_HWID_ARP_TABLE_IOCTL 0x0012000FUL

static ULONG
KswordARKHwidBoundedAnsiLength(
    _In_reads_bytes_(TextBytes) const CHAR* Text,
    _In_ ULONG TextBytes
    )
{
    ULONG textIndex = 0UL;

    /* 中文说明：固定长度硬件字符串不一定以 NUL 结束，因此这里只在边界内扫描。 */
    if (Text == NULL || TextBytes == 0UL) {
        return 0UL;
    }

    for (textIndex = 0UL; textIndex < TextBytes; ++textIndex) {
        if (Text[textIndex] == '\0') {
            break;
        }
    }

    return textIndex;
}

static ULONG
KswordARKHwidWideToAnsi(
    _In_reads_(SourceChars) const WCHAR* Source,
    _In_ ULONG SourceChars,
    _Out_writes_bytes_(DestinationBytes) CHAR* Destination,
    _In_ ULONG DestinationBytes
    )
{
    ULONG sourceIndex = 0UL;
    ULONG copiedBytes = 0UL;

    /* 中文说明：协议使用 WCHAR，驱动查询返回多为 ASCII 字段，这里做保守窄化。 */
    if (Source == NULL || Destination == NULL || DestinationBytes == 0UL) {
        return 0UL;
    }

    for (sourceIndex = 0UL; sourceIndex < SourceChars && copiedBytes + 1UL < DestinationBytes; ++sourceIndex) {
        WCHAR currentChar = Source[sourceIndex];
        if (currentChar == L'\0') {
            break;
        }
        Destination[copiedBytes] = currentChar <= 0x7fU ? (CHAR)currentChar : '?';
        ++copiedBytes;
    }

    Destination[copiedBytes] = '\0';
    return copiedBytes;
}

static VOID
KswordARKHwidFillRandomAscii(
    _Out_writes_bytes_(DestinationBytes) CHAR* Destination,
    _In_ ULONG DestinationBytes
    )
{
    static const CHAR alphabet[] = "QWERTYUIOPASDFGHJKLZXCVBNMzxcvbnmasdfghjklqwertyuiop0123456789";
    LARGE_INTEGER tickCount;
    ULONG seed = 0UL;
    ULONG byteIndex = 0UL;

    /* 中文说明：随机化只作用于返回缓冲，不修改物理设备或内存表。 */
    if (Destination == NULL || DestinationBytes == 0UL) {
        return;
    }

    KeQueryTickCount(&tickCount);
    seed = (ULONG)(tickCount.LowPart ^ tickCount.HighPart ^ (ULONG)(ULONG_PTR)Destination);
    for (byteIndex = 0UL; byteIndex < DestinationBytes; ++byteIndex) {
        Destination[byteIndex] = alphabet[RtlRandomEx(&seed) % (RTL_NUMBER_OF(alphabet) - 1U)];
    }
}

static VOID
KswordARKHwidFillRandomGuid(
    _Out_ GUID* Guid
    )
{
    LARGE_INTEGER tickCount;
    ULONG seed = 0UL;
    ULONG* guidWords = (ULONG*)Guid;
    ULONG wordIndex = 0UL;

    /* 中文说明：GPT GUID 随机化只改写本次 IOCTL 输出中的 GUID 字节。 */
    if (Guid == NULL) {
        return;
    }

    KeQueryTickCount(&tickCount);
    seed = (ULONG)(tickCount.LowPart ^ tickCount.HighPart ^ (ULONG)(ULONG_PTR)Guid);
    for (wordIndex = 0UL; wordIndex < (sizeof(*Guid) / sizeof(ULONG)); ++wordIndex) {
        guidWords[wordIndex] = RtlRandomEx(&seed);
    }
}

static VOID
KswordARKHwidRewriteFixedAnsiField(
    _Out_writes_bytes_(FieldBytes) CHAR* Field,
    _In_ ULONG FieldBytes,
    _In_reads_(KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS) const WCHAR* CustomText,
    _In_ ULONG DiskMode
    )
{
    CHAR temporaryText[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS] = { 0 };
    ULONG copiedBytes = 0UL;

    /* 中文说明：ATA/SMART 字段是定长字段，不能依赖 strlen 读取越界。 */
    if (Field == NULL || FieldBytes == 0UL) {
        return;
    }

    if (DiskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM) {
        KswordARKHwidFillRandomAscii(Field, FieldBytes);
        return;
    }

    RtlZeroMemory(Field, FieldBytes);
    if (DiskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM) {
        copiedBytes = KswordARKHwidWideToAnsi(
            CustomText,
            KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS,
            temporaryText,
            sizeof(temporaryText));
        if (copiedBytes != 0UL) {
            RtlCopyMemory(Field, temporaryText, min(copiedBytes, FieldBytes));
        }
    }
}

static VOID
KswordARKHwidRewriteOffsetAnsiField(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ ULONG FieldOffset,
    _In_reads_(KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS) const WCHAR* CustomText,
    _In_ ULONG DiskMode
    )
{
    CHAR temporaryText[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS] = { 0 };
    CHAR* fieldText = NULL;
    ULONG availableBytes = 0UL;
    ULONG fieldBytes = 0UL;
    ULONG copiedBytes = 0UL;

    /* 中文说明：STORAGE_DEVICE_DESCRIPTOR 用 offset 指向 NUL 结束字符串。 */
    // 描述符的固定头包含偏移及长度字段，不是可写的设备字符串。
    if (Buffer == NULL || FieldOffset < (ULONG)FIELD_OFFSET(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties) ||
        FieldOffset >= BufferBytes) {
        return;
    }

    fieldText = (CHAR*)(Buffer + FieldOffset);
    availableBytes = BufferBytes - FieldOffset;
    fieldBytes = KswordARKHwidBoundedAnsiLength(fieldText, availableBytes);
    if (fieldBytes == 0UL || fieldBytes >= availableBytes) {
        return;
    }

    if (DiskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_RANDOM) {
        KswordARKHwidFillRandomAscii(fieldText, fieldBytes);
        return;
    }

    RtlZeroMemory(fieldText, fieldBytes);
    if (DiskMode == KSWORD_ARK_HWID_DISPATCH_DISK_MODE_CUSTOM) {
        copiedBytes = KswordARKHwidWideToAnsi(
            CustomText,
            KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS,
            temporaryText,
            sizeof(temporaryText));
        if (copiedBytes != 0UL) {
            RtlCopyMemory(fieldText, temporaryText, min(copiedBytes, fieldBytes));
        }
    }
}

static ULONG
KswordARKHwidCompletionLength(
    _In_ const KSW_HWID_COMPLETION_CONTEXT* Context,
    _In_ PIRP Irp
    )
{
    ULONG_PTR informationBytes = 0U;

    /* 标准存储查询的 Information 是实际返回长度；调用方容量不代表有效数据。 */
    if (Context == NULL || Irp == NULL) {
        return 0UL;
    }

    informationBytes = Irp->IoStatus.Information;
    // 私有控制请求可能另行返回数据；保留原约定，映射访问另受 MDL 长度限制。
    if (informationBytes == 0U && (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA ||
        Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY)) {
        // 此处仅给出请求声明的上限。
        return Context->BufferLength;
    }
    // 始终在指针宽度下比较，零字节的标准响应也返回零。
    if (informationBytes < (ULONG_PTR)Context->BufferLength) {
        return (ULONG)informationBytes;
    }

    return Context->BufferLength;
}

static VOID
KswordARKHwidRewriteStorageDescriptor(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile
    )
{
    PSTORAGE_DEVICE_DESCRIPTOR descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)Buffer;

    /* 中文说明：磁盘序列号路径只处理 StorageDeviceProperty 的输出描述符。 */
    if (Buffer == NULL || Profile == NULL || BufferBytes < sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        return;
    }

    // 设备返回的 Size 可能小于调用方缓冲区；字符串必须完整落在描述符内。
    BufferBytes = min(BufferBytes, descriptor->Size);
    KswordARKHwidRewriteOffsetAnsiField(Buffer, BufferBytes, descriptor->SerialNumberOffset, Profile->diskSerial, Profile->diskMode);
    KswordARKHwidRewriteOffsetAnsiField(Buffer, BufferBytes, descriptor->ProductIdOffset, Profile->diskProduct, Profile->diskMode);
    KswordARKHwidRewriteOffsetAnsiField(Buffer, BufferBytes, descriptor->ProductRevisionOffset, Profile->diskRevision, Profile->diskMode);
}

static VOID
KswordARKHwidRewriteAtaPassThrough(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile
    )
{
    PATA_PASS_THROUGH_EX passThrough = (PATA_PASS_THROUGH_EX)Buffer;
    PIDENTIFY_DEVICE_DATA identity = NULL;
    // 与 ATA_PASS_THROUGH_EX.DataBufferOffset 使用相同位宽，避免 x64 截断。
    ULONG_PTR dataOffset = 0U;

    /* 中文说明：ATA identify 数据在 DataBufferOffset 指向的定长结构中。 */
    if (Buffer == NULL || Profile == NULL || BufferBytes < sizeof(ATA_PASS_THROUGH_EX)) {
        return;
    }

    // 完成时命令字已经被设备状态覆盖；请求进入时已检查命令，这里只校验返回区。
    dataOffset = passThrough->DataBufferOffset;
    // 数据必须在头部之后，且实际传输量与返回缓冲区都能容纳 IDENTIFY 结构。
    if (passThrough->Length != sizeof(*passThrough) || dataOffset < sizeof(*passThrough) ||
        passThrough->DataTransferLength < sizeof(IDENTIFY_DEVICE_DATA) ||
        dataOffset > BufferBytes || BufferBytes - dataOffset < sizeof(IDENTIFY_DEVICE_DATA)) {
        return;
    }

    identity = (PIDENTIFY_DEVICE_DATA)(Buffer + dataOffset);
    KswordARKHwidRewriteFixedAnsiField((CHAR*)identity->SerialNumber, sizeof(identity->SerialNumber), Profile->diskSerial, Profile->diskMode);
    KswordARKHwidRewriteFixedAnsiField((CHAR*)identity->ModelNumber, sizeof(identity->ModelNumber), Profile->diskProduct, Profile->diskMode);
    KswordARKHwidRewriteFixedAnsiField((CHAR*)identity->FirmwareRevision, sizeof(identity->FirmwareRevision), Profile->diskRevision, Profile->diskMode);
}

static VOID
KswordARKHwidRewriteSmartData(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile
    )
{
    PSENDCMDOUTPARAMS smartOutput = (PSENDCMDOUTPARAMS)Buffer;
    PKSW_HWID_IDSECTOR identifyData = NULL;
    ULONG requiredBytes = FIELD_OFFSET(SENDCMDOUTPARAMS, bBuffer) + sizeof(KSW_HWID_IDSECTOR);

    /* 中文说明：SMART_RCV_DRIVE_DATA 返回的 identify 扇区是旧版定长布局。 */
    // SMART 可以在 IOCTL 成功时报告设备错误，且 cBufferSize 才是有效负载长度。
    if (Buffer == NULL || Profile == NULL || BufferBytes < requiredBytes ||
        smartOutput->DriverStatus.bDriverError != 0U || smartOutput->cBufferSize < sizeof(*identifyData)) {
        return;
    }

    identifyData = (PKSW_HWID_IDSECTOR)smartOutput->bBuffer;
    KswordARKHwidRewriteFixedAnsiField(identifyData->sSerialNumber, sizeof(identifyData->sSerialNumber), Profile->diskSerial, Profile->diskMode);
    KswordARKHwidRewriteFixedAnsiField(identifyData->sModelNumber, sizeof(identifyData->sModelNumber), Profile->diskProduct, Profile->diskMode);
    KswordARKHwidRewriteFixedAnsiField(identifyData->sFirmwareRev, sizeof(identifyData->sFirmwareRev), Profile->diskRevision, Profile->diskMode);
}

static VOID
KswordARKHwidRewritePartitionBuffer(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ ULONG IoControlCode,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile
    )
{
    PPARTITION_INFORMATION_EX partitionInfo = (PPARTITION_INFORMATION_EX)Buffer;
    PDRIVE_LAYOUT_INFORMATION_EX layoutInfo = (PDRIVE_LAYOUT_INFORMATION_EX)Buffer;

    /* 中文说明：partmgr 路径只随机化查询输出中的 GPT GUID。 */
    if (Buffer == NULL || Profile == NULL ||
        (Profile->behaviorFlags & KSWORD_ARK_HWID_DISPATCH_FLAG_DISK_GUID_RANDOM) == 0UL) {
        return;
    }

    if (IoControlCode == IOCTL_DISK_GET_PARTITION_INFO_EX &&
        BufferBytes >= sizeof(PARTITION_INFORMATION_EX) &&
        partitionInfo->PartitionStyle == PARTITION_STYLE_GPT) {
        KswordARKHwidFillRandomGuid(&partitionInfo->Gpt.PartitionId);
    }
    else if (IoControlCode == IOCTL_DISK_GET_DRIVE_LAYOUT_EX &&
        BufferBytes >= sizeof(DRIVE_LAYOUT_INFORMATION_EX) &&
        layoutInfo->PartitionStyle == PARTITION_STYLE_GPT) {
        KswordARKHwidFillRandomGuid(&layoutInfo->Gpt.DiskId);
    }
}

static VOID
KswordARKHwidRewriteMountBuffer(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ ULONG IoControlCode,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile
    )
{
    PMOUNTMGR_MOUNT_POINTS mountPoints = (PMOUNTMGR_MOUNT_POINTS)Buffer;
    PMOUNTDEV_UNIQUE_ID uniqueId = (PMOUNTDEV_UNIQUE_ID)Buffer;
    ULONG pointIndex = 0UL;
    ULONG requiredBytes = 0UL;

    /* 中文说明：MountMgr 路径只清理返回值长度字段，不写卷引导扇区。 */
    if (Buffer == NULL || Profile == NULL ||
        (Profile->behaviorFlags & KSWORD_ARK_HWID_DISPATCH_FLAG_VOLUME_ID_CLEAN) == 0UL) {
        return;
    }

    if (IoControlCode == IOCTL_MOUNTMGR_QUERY_POINTS && BufferBytes >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
        if (mountPoints->NumberOfMountPoints >
            ((MAXULONG - FIELD_OFFSET(MOUNTMGR_MOUNT_POINTS, MountPoints)) / sizeof(MOUNTMGR_MOUNT_POINT))) {
            return;
        }
        requiredBytes = FIELD_OFFSET(MOUNTMGR_MOUNT_POINTS, MountPoints) +
            (mountPoints->NumberOfMountPoints * sizeof(MOUNTMGR_MOUNT_POINT));
        if (requiredBytes > BufferBytes) {
            return;
        }
        for (pointIndex = 0UL; pointIndex < mountPoints->NumberOfMountPoints; ++pointIndex) {
            mountPoints->MountPoints[pointIndex].UniqueIdLength = 0U;
            mountPoints->MountPoints[pointIndex].SymbolicLinkNameLength = 0U;
        }
    }
    else if (IoControlCode == IOCTL_MOUNTDEV_QUERY_UNIQUE_ID && BufferBytes >= sizeof(MOUNTDEV_UNIQUE_ID)) {
        uniqueId->UniqueIdLength = 0U;
    }
}

static VOID
KswordARKHwidRewriteNvidiaBuffer(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile
    )
{
    static const CHAR gpuPrefix[] = "GPU-";
    CHAR replacementText[KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS] = { 0 };
    ULONG replacementBytes = 0UL;
    ULONG scanIndex = 0UL;
    ULONG writeBytes = 0UL;

    /* 中文说明：NVIDIA SMIL 路径只在返回缓冲中替换 GPU- 后续文本。 */
    if (Buffer == NULL || Profile == NULL || BufferBytes <= sizeof(gpuPrefix)) {
        return;
    }

    replacementBytes = KswordARKHwidWideToAnsi(
        Profile->gpuSerial,
        KSWORD_ARK_HWID_DISPATCH_TEXT_CHARS,
        replacementText,
        sizeof(replacementText));
    if (replacementBytes == 0UL) {
        KswordARKHwidFillRandomAscii(replacementText, 16UL);
        replacementText[16] = '\0';
        replacementBytes = 16UL;
    }

    for (scanIndex = 0UL; scanIndex + sizeof(gpuPrefix) < BufferBytes; ++scanIndex) {
        if (RtlCompareMemory(Buffer + scanIndex, gpuPrefix, sizeof(gpuPrefix) - 1U) == sizeof(gpuPrefix) - 1U) {
            writeBytes = min(replacementBytes, BufferBytes - scanIndex - (ULONG)(sizeof(gpuPrefix) - 1U));
            RtlCopyMemory(Buffer + scanIndex + sizeof(gpuPrefix) - 1U, replacementText, writeBytes);
            break;
        }
    }
}

static VOID
KswordARKHwidRewriteNsiBuffer(
    _Inout_updates_bytes_(BufferBytes) UCHAR* Buffer,
    _In_ ULONG BufferBytes,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile
    )
{
    /* 中文说明：NSI/ARP 路径只在用户勾选 ARP 清理时清零返回表。 */
    if (Buffer == NULL || BufferBytes == 0UL || Profile == NULL ||
        (Profile->behaviorFlags & KSWORD_ARK_HWID_DISPATCH_FLAG_ARP_TABLE_CLEAN) == 0UL) {
        return;
    }

    RtlZeroMemory(Buffer, BufferBytes);
}

static VOID
KswordARKHwidRewriteSystemBuffer(
    _In_ const KSW_HWID_COMPLETION_CONTEXT* Context,
    _In_ PIRP Irp
    )
{
    UCHAR* buffer = NULL;
    ULONG bufferBytes = 0UL;

    /* 中文说明：大多数目标 IOCTL 使用 METHOD_BUFFERED，优先处理 SystemBuffer。 */
    if (Context == NULL || Irp == NULL || Context->SystemBuffer == NULL || !NT_SUCCESS(Irp->IoStatus.Status)) {
        return;
    }

    buffer = (UCHAR*)Context->SystemBuffer;
    bufferBytes = KswordARKHwidCompletionLength(Context, Irp);
    if (bufferBytes == 0UL) {
        return;
    }

    if (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_DISK) {
        if (Context->IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
            KswordARKHwidRewriteStorageDescriptor(buffer, bufferBytes, &Context->Profile);
        }
        else if (Context->IoControlCode == IOCTL_ATA_PASS_THROUGH) {
            KswordARKHwidRewriteAtaPassThrough(buffer, bufferBytes, &Context->Profile);
        }
        else if (Context->IoControlCode == SMART_RCV_DRIVE_DATA) {
            KswordARKHwidRewriteSmartData(buffer, bufferBytes, &Context->Profile);
        }
    }
    else if (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR) {
        KswordARKHwidRewritePartitionBuffer(buffer, bufferBytes, Context->IoControlCode, &Context->Profile);
    }
    else if (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR) {
        KswordARKHwidRewriteMountBuffer(buffer, bufferBytes, Context->IoControlCode, &Context->Profile);
    }
    else if (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY) {
        KswordARKHwidRewriteNsiBuffer(buffer, bufferBytes, &Context->Profile);
    }
}

static VOID
KswordARKHwidRewriteDirectOrUserBuffer(
    _In_ const KSW_HWID_COMPLETION_CONTEXT* Context,
    _In_ PIRP Irp
    )
{
    UCHAR* buffer = NULL;
    ULONG bufferBytes = 0UL;

    /* 只有这两个私有控制路径使用此分支；存储查询不应映射额外的 MDL。 */
    if (Context == NULL || Irp == NULL || !NT_SUCCESS(Irp->IoStatus.Status) ||
        (Context->TargetFlag != KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA &&
         Context->TargetFlag != KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY)) {
        return;
    }

    bufferBytes = KswordARKHwidCompletionLength(Context, Irp);
    if (bufferBytes == 0UL) {
        return;
    }

    // 完成阶段只使用当前 IRP 仍持有的 MDL，避免使用派遣时缓存的旧描述符。
    if (Irp->MdlAddress != NULL) {
        // 单个映射仅覆盖这一段 MDL，不能把后续页段或调用方容量当作连续空间。
        bufferBytes = min(bufferBytes, MmGetMdlByteCount(Irp->MdlAddress));
        buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
        if (buffer != NULL) {
            if (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA) {
                KswordARKHwidRewriteNvidiaBuffer(buffer, min(bufferBytes, KSW_HWID_NVIDIA_SMIL_MAX_BYTES), &Context->Profile);
            }
            else if (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY) {
                KswordARKHwidRewriteNsiBuffer(buffer, bufferBytes, &Context->Profile);
            }
        }
        // MDL 是本次传输的缓冲区，映射失败时不能改写另一个用户地址。
        return;
    }

    // 没有 MDL 时才使用该私有请求记录的缓冲地址。
    if (Context->UserBuffer != NULL) {
        PEPROCESS requestorProcess = NULL;
        KAPC_STATE apcState;
        BOOLEAN attached = FALSE;

        /* 完成例程可在 DISPATCH_LEVEL 运行；用户地址探测和附加只能在 <= APC_LEVEL。 */
        if (KeGetCurrentIrql() > APC_LEVEL) {
            return;
        }

        if (Irp->RequestorMode != KernelMode) {
            requestorProcess = IoGetRequestorProcess(Irp);
            if (requestorProcess == NULL) {
                return;
            }
            if (requestorProcess != PsGetCurrentProcess()) {
                KeStackAttachProcess(requestorProcess, &apcState);
                attached = TRUE;
            }
        }

        __try {
            ULONG writableBytes = Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA ?
                min(bufferBytes, KSW_HWID_NVIDIA_SMIL_MAX_BYTES) : bufferBytes;
            if (Irp->RequestorMode != KernelMode) {
                ProbeForWrite(Context->UserBuffer, writableBytes, sizeof(UCHAR));
            }
            buffer = (UCHAR*)Context->UserBuffer;
            if (Context->TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA) {
                KswordARKHwidRewriteNvidiaBuffer(buffer, writableBytes, &Context->Profile);
            }
            else {
                KswordARKHwidRewriteNsiBuffer(buffer, writableBytes, &Context->Profile);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            NOTHING;
        }

        if (attached != FALSE) {
            KeUnstackDetachProcess(&apcState);
        }
    }
}

static NTSTATUS
KswordARKHwidCompletionRoutine(
    _In_ PDEVICE_OBJECT Device,
    _Inout_ PIRP Irp,
    _In_opt_ PVOID Context
    )
{
    PKSW_HWID_COMPLETION_CONTEXT completionContext = (PKSW_HWID_COMPLETION_CONTEXT)Context;
    PIO_COMPLETION_ROUTINE oldRoutine = NULL;
    PVOID oldContext = NULL;
    UCHAR oldControl = 0U;
    BOOLEAN callOldRoutine = FALSE;
    NTSTATUS completionStatus = STATUS_SUCCESS;

    /* 中文说明：完成例程先改写返回缓冲，再恢复并调用原完成例程。 */
    if (completionContext != NULL) {
        oldRoutine = completionContext->OldRoutine;
        oldContext = completionContext->OldContext;
        oldControl = completionContext->OldControl;
        /*
         * 中文说明：改写只在请求成功时做——失败或取消的 IRP，输出缓冲的内容没有意义，
         * 目标驱动甚至可能根本没往里写过。但上下文无论成败都必须在这里释放：
         * 这是全模块唯一的 KSW_HWID_POOL_TAG 释放点，漏一次就是一次非分页池泄漏。
         */
        if (Irp != NULL && NT_SUCCESS(Irp->IoStatus.Status)) {
            KswordARKHwidRewriteSystemBuffer(completionContext, Irp);
            KswordARKHwidRewriteDirectOrUserBuffer(completionContext, Irp);
        }
        ExFreePoolWithTag(completionContext, KSW_HWID_POOL_TAG);
    }

    if (Irp != NULL) {
        completionStatus = Irp->IoStatus.Status;
        // I/O 管理器分别判断完成状态与取消标志，任一已登记条件满足即调用上层一次。
        callOldRoutine =
            (NT_SUCCESS(completionStatus) && ((oldControl & SL_INVOKE_ON_SUCCESS) != 0U)) ||
            (!NT_SUCCESS(completionStatus) && ((oldControl & SL_INVOKE_ON_ERROR) != 0U)) ||
            (Irp->Cancel && ((oldControl & SL_INVOKE_ON_CANCEL) != 0U));
    }

    /*
     * 中文说明：本模块覆盖了这个栈位置原有的完成例程，IoCompleteRequest 已经把该位置
     * 消费掉，不会再替它调用原例程——所以"是否调用"只能由上面按 OldControl 的
     * SL_INVOKE_ON_* 位与完成状态重建出来的 callOldRoutine 决定。
     * 不能再与 Irp->StackCount 相与：StackCount 是 IRP 分配时的栈位置总数，
     * 与"上层是否安装过完成例程"无关，拿它当闸门会在单层设备栈上静默吞掉上层的回调。
     */
    if (oldRoutine != NULL && callOldRoutine != FALSE) {
        return oldRoutine(Device, Irp, oldContext);
    }

    // 已弹出最上层时没有可写的上层栈位置，不能在 IRP 分配边界外传播 pending。
    if (Irp != NULL && Irp->PendingReturned && Irp->CurrentLocation <= Irp->StackCount) {
        // 仅在仍有上层栈位置、且没有原完成例程负责传播时标记 pending。
        IoMarkIrpPending(Irp);
    }

    return STATUS_SUCCESS;
}



static BOOLEAN
KswordARKHwidShouldHookIoctl(
    _In_ ULONG TargetFlag,
    _In_ ULONG IoControlCode,
    _In_opt_ PVOID SystemBuffer,
    _In_ ULONG InputBufferLength
    )
{
    PSTORAGE_PROPERTY_QUERY storageQuery = (PSTORAGE_PROPERTY_QUERY)SystemBuffer;

    /* 中文说明：根据目标驱动和 IOCTL 类型决定是否挂接完成例程。 */
    if (TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_DISK) {
        if (IoControlCode == IOCTL_STORAGE_QUERY_PROPERTY) {
            return SystemBuffer != NULL &&
                InputBufferLength >= sizeof(STORAGE_PROPERTY_QUERY) &&
                storageQuery->PropertyId == StorageDeviceProperty &&
                storageQuery->QueryType == PropertyStandardQuery;
        }
        // ATA 透传也承载普通扇区读写，只有 IDENTIFY 读请求返回设备标识结构。
        if (IoControlCode == IOCTL_ATA_PASS_THROUGH) {
            // 输入命令字必须在下层将其替换为设备状态之前读取。
            const ATA_PASS_THROUGH_EX* ata = (const ATA_PASS_THROUGH_EX*)SystemBuffer;
            // 仅匹配布局完整且方向为读的 ATA / ATAPI IDENTIFY。
            return ata != NULL && InputBufferLength >= sizeof(*ata) &&
                ata->Length == sizeof(*ata) &&
                (ata->AtaFlags & (ATA_FLAGS_DATA_IN | ATA_FLAGS_DATA_OUT)) == ATA_FLAGS_DATA_IN &&
                (ata->CurrentTaskFile[6] == ID_CMD || ata->CurrentTaskFile[6] == ATAPI_ID_CMD);
        }
        // 同一个 SMART IOCTL 也会返回健康属性；不能把这些数据当设备标识覆盖。
        if (IoControlCode == SMART_RCV_DRIVE_DATA) {
            // bBuffer 是可变长输入，读取命令字只要求固定头完整。
            const SENDCMDINPARAMS* smart = (const SENDCMDINPARAMS*)SystemBuffer;
            // 只接受明确请求 ATA 或 ATAPI 标识数据的命令。
            return smart != NULL && InputBufferLength >= (ULONG)FIELD_OFFSET(SENDCMDINPARAMS, bBuffer) &&
                (smart->irDriveRegs.bCommandReg == ID_CMD || smart->irDriveRegs.bCommandReg == ATAPI_ID_CMD);
        }
        // 其他磁盘请求由原驱动原样处理。
        return FALSE;
    }

    if (TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_PARTMGR) {
        return IoControlCode == IOCTL_DISK_GET_PARTITION_INFO_EX ||
            IoControlCode == IOCTL_DISK_GET_DRIVE_LAYOUT_EX;
    }

    if (TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_MOUNTMGR) {
        return IoControlCode == IOCTL_MOUNTMGR_QUERY_POINTS ||
            IoControlCode == IOCTL_MOUNTDEV_QUERY_UNIQUE_ID;
    }

    if (TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NVIDIA) {
        return IoControlCode == KSW_HWID_NVIDIA_SMIL_IOCTL;
    }

    if (TargetFlag == KSWORD_ARK_HWID_DISPATCH_TARGET_NSIPROXY) {
        return IoControlCode == KSW_HWID_NSI_PROXY_ARP_IOCTL ||
            IoControlCode == KSW_HWID_ARP_TABLE_IOCTL;
    }

    return FALSE;
}

BOOLEAN
KswordARKHwidPrepareDispatchCompletion(
    _Inout_ PIRP Irp,
    _Inout_ PIO_STACK_LOCATION IoStack,
    _In_ ULONG TargetFlag
    )
{
    PKSW_HWID_COMPLETION_CONTEXT completionContext = NULL;
    ULONG inputBufferLength = 0UL;
    ULONG outputBufferLength = 0UL;
    ULONG ioControlCode = 0UL;

    /* 中文说明：该入口在被 hook 的目标驱动派遣函数内运行，只安装完成例程。 */
    if (Irp == NULL || IoStack == NULL) {
        return FALSE;
    }

    ioControlCode = IoStack->Parameters.DeviceIoControl.IoControlCode;
    inputBufferLength = IoStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = IoStack->Parameters.DeviceIoControl.OutputBufferLength;
    if (!KswordARKHwidShouldHookIoctl(TargetFlag, ioControlCode, Irp->AssociatedIrp.SystemBuffer, inputBufferLength)) {
        return FALSE;
    }

    completionContext = (PKSW_HWID_COMPLETION_CONTEXT)KswordARKAllocateNonPagedPool(
        sizeof(*completionContext),
        KSW_HWID_POOL_TAG);
    if (completionContext == NULL) {
        return FALSE;
    }

    RtlZeroMemory(completionContext, sizeof(*completionContext));
    completionContext->SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
    completionContext->UserBuffer = Irp->UserBuffer;
    completionContext->BufferLength = outputBufferLength;
    completionContext->IoControlCode = ioControlCode;
    completionContext->TargetFlag = TargetFlag;
    completionContext->OldControl = IoStack->Control;
    completionContext->OldContext = IoStack->Context;
    completionContext->OldRoutine = IoStack->CompletionRoutine;
    // 到这里已选中目标 IOCTL，直接在其完成上下文中保存一致的配置。
    KswordARKHwidSnapshotActiveProfile(&completionContext->Profile);

    IoStack->Context = completionContext;
    IoStack->CompletionRoutine = KswordARKHwidCompletionRoutine;
    /*
     * 中文说明：三个 SL_INVOKE_ON_* 位必须全置。completionContext 只有完成例程里那一处
     * 释放点，而完成例程只在 Control 里对应位与完成状态匹配时才被调用——只置
     * SL_INVOKE_ON_SUCCESS 的话，IRP 一旦以非成功状态完成，这块非分页池就再没人回收。
     * 这不是罕见路径：STORAGE_QUERY_PROPERTY / MOUNTMGR_QUERY_POINTS 的标准用法是先用
     * 小缓冲探长度、拿 STATUS_BUFFER_OVERFLOW；ATA_PASS_THROUGH 在 NVMe 上普遍返回
     * STATUS_INVALID_DEVICE_REQUEST。原完成例程的调用条件另按 OldControl 判定，不受影响。
     */
    IoStack->Control |= SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
    return TRUE;
}
