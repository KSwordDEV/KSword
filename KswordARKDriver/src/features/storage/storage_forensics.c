/*++

Module Name:

    storage_forensics.c

Abstract:

    Implements bounded physical-disk discovery and raw I/O backends.  The
    normal backend uses the named disk stack, the storage-port backend skips
    the upper disk object, and the controller backend targets the deepest
    reachable device object only for an offline disk.

Environment:

    Kernel mode, PASSIVE_LEVEL.

--*/

#include "ark/ark_driver.h"
#include "storage_forensics_internal.h"
#include "../../platform/pool_compat.h"

#include <ntdddisk.h>
#include <ntstrsafe.h>

#define KSW_STORAGE_FORENSICS_POOL_TAG 'frSK'
#define KSW_STORAGE_FORENSICS_DESCRIPTOR_BYTES 1024UL
#define KSW_STORAGE_FORENSICS_MAX_STACK_DEPTH 32UL


/*
 * These documented kernel exports are declared by ntifs.h rather than the
 * ntddk surface used by the rest of this driver.  Declare only the two exact
 * contracts needed here to avoid mixing the two umbrella headers.
 */
NTSYSAPI
NTSTATUS
NTAPI
ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

NTSYSAPI
NTSTATUS
NTAPI
ZwCancelIoFileEx(
    _In_ HANDLE FileHandle,
    _In_ PIO_STATUS_BLOCK IoRequestToCancel,
    _Out_ PIO_STATUS_BLOCK IoStatusBlock
    );

NTKERNELAPI
PDEVICE_OBJECT
IoGetLowerDeviceObject(
    _In_ PDEVICE_OBJECT DeviceObject
    );

/* Raw storage requests must not leave an IOCTL worker blocked forever. */
#define KSW_STORAGE_IO_TIMEOUT_SECONDS 30LL
#define KSW_STORAGE_RELATIVE_IO_TIMEOUT_100NS \
    (-(KSW_STORAGE_IO_TIMEOUT_SECONDS * 10LL * 1000LL * 1000LL))

static VOID
KswordStorageReleaseContext(
    _Inout_ KSW_STORAGE_DISK_CONTEXT* Context
    )
/*++

Routine Description:

    Releases every referenced object and handle owned by a disk context.

--*/
{
    /* A referenced controller object is released independently. */
    if (Context->ControllerDevice != NULL) {
        /* Drop the controller device reference acquired while walking down. */
        ObDereferenceObject(Context->ControllerDevice);
        /* Clear the field so repeated cleanup remains safe. */
        Context->ControllerDevice = NULL;
    }

    /* A referenced port object is released independently. */
    if (Context->PortDevice != NULL) {
        /* Drop the port device reference acquired while walking down. */
        ObDereferenceObject(Context->PortDevice);
        /* Clear the field so repeated cleanup remains safe. */
        Context->PortDevice = NULL;
    }

    /* The top-of-stack reference was acquired explicitly. */
    if (Context->TopDevice != NULL) {
        /* Release the top-of-stack device object. */
        ObDereferenceObject(Context->TopDevice);
        /* Clear the field so repeated cleanup remains safe. */
        Context->TopDevice = NULL;
    }

    /* 文件对象引用来自已打开句柄，不再进行第二次路径解析。 */
    if (Context->FileObject != NULL) {
        /* 释放同一句柄引用的文件对象及其所持有的命名设备关联。 */
        ObDereferenceObject(Context->FileObject);
        /* Clear both borrowed fields after the reference is gone. */
        Context->FileObject = NULL;
        /* NamedDevice is borrowed from FileObject and must not be dereferenced. */
        Context->NamedDevice = NULL;
    }

    /* ZwCreateFile returned a kernel handle for metadata and stack I/O. */
    if (Context->Handle != NULL) {
        /* Close the disk handle in the caller process context. */
        ZwClose(Context->Handle);
        /* Clear the field so repeated cleanup remains safe. */
        Context->Handle = NULL;
    }
}

NTSTATUS
KswordStorageSendHandleIoctl(
    _In_ HANDLE Handle,
    _In_ ULONG IoctlCode,
    _In_reads_bytes_opt_(InputLength) PVOID InputBuffer,
    _In_ ULONG InputLength,
    _Out_writes_bytes_opt_(OutputLength) PVOID OutputBuffer,
    _In_ ULONG OutputLength,
    _Out_opt_ PULONG_PTR InformationOut
    )
/*++

Routine Description:

    Sends one synchronous buffered device-control request to a disk handle.

--*/
{
    /* The synchronous handle still requires a caller-owned I/O status block. */
    IO_STATUS_BLOCK ioStatus = { 0 };
    /* Submit the device control request to the opened physical disk. */
    NTSTATUS status = ZwDeviceIoControlFile(
        Handle,
        NULL,
        NULL,
        NULL,
        &ioStatus,
        IoctlCode,
        InputBuffer,
        InputLength,
        OutputBuffer,
        OutputLength);

    /* A pending request must be waited before reading its status or output. */
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        NTSTATUS waitStatus;

        /* Bound the first wait so a wedged storage stack cannot pin this worker forever. */
        timeout.QuadPart = KSW_STORAGE_RELATIVE_IO_TIMEOUT_100NS;
        waitStatus = ZwWaitForSingleObject(Handle, FALSE, &timeout);
        if (waitStatus == STATUS_TIMEOUT) {
            IO_STATUS_BLOCK cancelStatus = { 0 };

            /* Cancel this exact request rather than every operation issued on the handle. */
            (VOID)ZwCancelIoFileEx(Handle, &ioStatus, &cancelStatus);
            /* ioStatus is stack-owned; do not return until the cancelled request is final. */
            waitStatus = ZwWaitForSingleObject(Handle, FALSE, NULL);
            status = NT_SUCCESS(waitStatus) ? STATUS_IO_TIMEOUT : waitStatus;
        }
        else if (NT_SUCCESS(waitStatus)) {
            /* Replace the wait status with the actual I/O completion status. */
            status = ioStatus.Status;
        }
        else {
            IO_STATUS_BLOCK cancelStatus = { 0 };

            /* Preserve lifetime safety even for an unexpected non-alertable wait failure. */
            (VOID)ZwCancelIoFileEx(Handle, &ioStatus, &cancelStatus);
            (VOID)ZwWaitForSingleObject(Handle, FALSE, NULL);
            status = waitStatus;
        }
    }

    /* Return the completed byte count when the caller requested it. */
    if (InformationOut != NULL) {
        /* Only completed bytes reported by the target are exposed. */
        *InformationOut = NT_SUCCESS(status) ? ioStatus.Information : 0U;
    }

    /* Propagate the target stack result without translating it. */
    return status;
}

static BOOLEAN
KswordStorageGuidEquals(
    _In_ const GUID* Left,
    _In_ const GUID* Right
    )
/*++

Routine Description:

    Compares two disk identifiers without relying on a user-mode helper.

--*/
{
    /* A bytewise comparison is valid because GUID has no ignored fields. */
    return RtlCompareMemory(Left, Right, sizeof(GUID)) == sizeof(GUID);
}

static BOOLEAN
KswordStorageIsSystemDisk(
    _In_ HANDLE Handle
    )
/*++

Routine Description:

    Matches the physical disk layout identifier against loader-reported boot
    and system disk identifiers.

--*/
{
    /* The extended loader record covers both MBR signatures and GPT GUIDs. */
    BOOTDISK_INFORMATION_EX bootInfo = { 0 };
    /* Reserve enough space for the fixed layout header used by this check. */
    UCHAR layoutBuffer[sizeof(DRIVE_LAYOUT_INFORMATION_EX) + (sizeof(PARTITION_INFORMATION_EX) * 4U)] = { 0 };
    /* Interpret the local byte buffer as the documented layout structure. */
    PDRIVE_LAYOUT_INFORMATION_EX layout = (PDRIVE_LAYOUT_INFORMATION_EX)layoutBuffer;
    /* Track the bytes returned only for defensive validation. */
    ULONG_PTR information = 0U;
    /* Query the loader-owned boot and system disk identities. */
    NTSTATUS status = IoGetBootDiskInformation(
        (PBOOTDISK_INFORMATION)&bootInfo,
        sizeof(bootInfo));

    /* A failed loader query is treated conservatively by the write path. */
    if (!NT_SUCCESS(status)) {
        /* Unknown identity is classified as system-sensitive. */
        return TRUE;
    }

    /* Query the candidate disk layout and its stable identifier. */
    status = KswordStorageSendHandleIoctl(
        Handle,
        IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
        NULL,
        0U,
        layoutBuffer,
        sizeof(layoutBuffer),
        &information);

    /* Missing layout identity is also treated conservatively. */
    if (!NT_SUCCESS(status) || information < FIELD_OFFSET(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry)) {
        /* Unknown identity is classified as system-sensitive. */
        return TRUE;
    }

    /* Compare MBR signatures when the target disk uses an MBR layout. */
    if (layout->PartitionStyle == PARTITION_STYLE_MBR) {
        /* Either the boot or system signature makes this a protected disk. */
        return layout->Mbr.Signature == bootInfo.BootDeviceSignature
            || layout->Mbr.Signature == bootInfo.SystemDeviceSignature;
    }

    /* Compare GPT disk identifiers when the target disk uses GPT. */
    if (layout->PartitionStyle == PARTITION_STYLE_GPT) {
        /* A GPT boot identifier is valid only when the loader says it is GPT. */
        if (bootInfo.BootDeviceIsGpt
            && KswordStorageGuidEquals(&layout->Gpt.DiskId, &bootInfo.BootDeviceGuid)) {
            /* The candidate disk contains the boot partition. */
            return TRUE;
        }

        /* A GPT system identifier is valid only when the loader says it is GPT. */
        if (bootInfo.SystemDeviceIsGpt
            && KswordStorageGuidEquals(&layout->Gpt.DiskId, &bootInfo.SystemDeviceGuid)) {
            /* The candidate disk contains the system partition. */
            return TRUE;
        }
    }

    /* No loader identity matched the candidate disk. */
    return FALSE;
}

static VOID
KswordStorageCopyDescriptorText(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ size_t DestinationChars,
    _In_reads_bytes_(DescriptorBytes) const UCHAR* Descriptor,
    _In_ ULONG DescriptorBytes,
    _In_ ULONG TextOffset
    )
/*++

Routine Description:

    Converts one bounded ANSI storage descriptor string to a wide string.

--*/
{
    /* Start with a valid empty destination for every failure path. */
    Destination[0] = L'\0';

    /* A zero or out-of-range descriptor offset contains no usable text. */
    if (TextOffset == 0U || TextOffset >= DescriptorBytes) {
        /* Leave the destination empty. */
        return;
    }

    /* Point at the descriptor string after validating its first byte. */
    const CHAR* source = (const CHAR*)(Descriptor + TextOffset);
    /* Bound the scan by the remaining descriptor bytes. */
    const ULONG remaining = DescriptorBytes - TextOffset;
    /* Count only bytes before the first terminator. */
    ULONG sourceChars = 0U;

    /* Scan the descriptor string without crossing the returned buffer. */
    while (sourceChars < remaining && source[sourceChars] != '\0') {
        /* Advance over one bounded ANSI character. */
        sourceChars += 1U;
    }

    /* Convert no more characters than the destination can hold. */
    const ULONG copyChars = (ULONG)min((size_t)sourceChars, DestinationChars - 1U);

    /* Storage descriptors use printable ASCII for these identity fields. */
    for (ULONG index = 0U; index < copyChars; ++index) {
        /* Widen the unsigned byte without applying a locale transform. */
        Destination[index] = (WCHAR)(UCHAR)source[index];
    }

    /* Terminate the wide destination explicitly. */
    Destination[copyChars] = L'\0';
}

static VOID
KswordStorageCaptureLowerDevices(
    _Inout_ KSW_STORAGE_DISK_CONTEXT* Context
    )
/*++

Routine Description:

    Captures independently referenced lower targets for the two bypass modes.

--*/
{
    /* Start at the top object returned by IoGetAttachedDeviceReference. */
    PDEVICE_OBJECT current = Context->TopDevice;
    /* Track how many lower objects were followed to bound malformed stacks. */
    ULONG depth = 0U;

    /* A missing top object leaves both bypass backends unavailable. */
    if (current == NULL) {
        /* No stack can be walked. */
        return;
    }

    /* The first lower object is the storage-port bypass target. */
    PDEVICE_OBJECT lower = IoGetLowerDeviceObject(current);

    /* Save the first lower target with its reference already held. */
    if (lower != NULL) {
        /* The context now owns the reference returned for this device. */
        Context->PortDevice = lower;
        /* Continue the walk from the first lower device. */
        current = lower;
        /* Record the first successful descent. */
        depth = 1U;
    }

    /* Walk to the deepest reachable target with a strict depth bound. */
    while (lower != NULL && depth < KSW_STORAGE_FORENSICS_MAX_STACK_DEPTH) {
        /* Acquire a reference to the next lower device. */
        PDEVICE_OBJECT next = IoGetLowerDeviceObject(current);

        /* Reaching the bottom finishes the controller-target search. */
        if (next == NULL) {
            /* Exit without acquiring another reference. */
            break;
        }

        /* Release the previous candidate controller reference, if any. */
        if (Context->ControllerDevice != NULL) {
            /* The final context retains only the deepest candidate. */
            ObDereferenceObject(Context->ControllerDevice);
        }

        /* Store the newly referenced deeper device as the current candidate. */
        Context->ControllerDevice = next;
        /* Continue walking from the new candidate. */
        current = next;
        /* Advance the strict stack-depth budget. */
        depth += 1U;
        /* Keep the loop condition synchronized with the current candidate. */
        lower = next;
    }

    /* A one-layer stack can use the same lower target for controller mode. */
    if (Context->ControllerDevice == NULL && Context->PortDevice != NULL) {
        /* Take a second independent reference for the controller field. */
        ObReferenceObject(Context->PortDevice);
        /* Both fields now own a separate reference to the same bottom object. */
        Context->ControllerDevice = Context->PortDevice;
    }
}

/* 只为显式请求FUA的可写句柄传递写透选项；查询、读取及普通写保持原行为。 */
static ULONG
KswordStorageOpenOptions(
    ACCESS_MASK DesiredAccess,
    BOOLEAN ForceUnitAccess)
{
    /* 所有磁盘句柄保持同步非警报I/O及非目录语义。 */
    ULONG options = FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT;
    /* 请求FUA只影响写操作；写透请求不构成硬件掉电持久化保证。 */
    if ((DesiredAccess & FILE_WRITE_DATA) != 0U && ForceUnitAccess) {
        /* Windows堆栈后端通过ZwWriteFile使用同一写透句柄。 */
        options |= FILE_WRITE_THROUGH;
    }
    /* 下层后端仍由原有SL_WRITE_THROUGH标志传递请求。 */
    return options;
}

static NTSTATUS
KswordStorageOpenContext(
    _In_ ULONG DiskNumber,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ BOOLEAN ForceUnitAccess,
    _Out_ KSW_STORAGE_DISK_CONTEXT* Context
    )
/*++

Routine Description:

    Opens one physical disk and collects size, geometry, identity and stack
    targets required by every raw-I/O backend.

--*/
{
    /* Zero every owned field before any operation that can fail. */
    RtlZeroMemory(Context, sizeof(*Context));
    /* Build the Win32 physical-disk kernel path used by ZwCreateFile. */
    NTSTATUS status = RtlStringCchPrintfW(
        Context->Path,
        RTL_NUMBER_OF(Context->Path),
        L"\\??\\PhysicalDrive%lu",
        DiskNumber);

    /* Reject a path formatting failure before constructing object attributes. */
    if (!NT_SUCCESS(status)) {
        /* Propagate the bounded string helper error. */
        return status;
    }

    /* Wrap the physical-disk path for native object-manager APIs. */
    UNICODE_STRING diskPath = { 0 };
    /* Initialize the counted string from the context-owned buffer. */
    RtlInitUnicodeString(&diskPath, Context->Path);
    /* Kernel handles prevent accidental reuse by the requesting process. */
    OBJECT_ATTRIBUTES attributes;
    /* Configure a case-insensitive kernel-handle open. */
    InitializeObjectAttributes(
        &attributes,
        &diskPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL);
    /* The synchronous handle reports all completion through this local block. */
    IO_STATUS_BLOCK ioStatus = { 0 };

    /* Open the whole-disk object without requesting destructive share exclusion. */
    status = ZwCreateFile(
        &Context->Handle,
        DesiredAccess | SYNCHRONIZE,
        &attributes,
        &ioStatus,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        KswordStorageOpenOptions(DesiredAccess, ForceUnitAccess),
        NULL,
        0U);

    /* A missing or inaccessible disk ends context initialization. */
    if (!NT_SUCCESS(status)) {
        /* Normalize the unused handle field for cleanup. */
        Context->Handle = NULL;
        /* Return the disk-open result. */
        return status;
    }

    /* 从已打开句柄引用同一个文件对象，不能再按可复用的磁盘号重新解析路径。 */
    status = ObReferenceObjectByHandle(
        Context->Handle,
        0U,
        *IoFileObjectType,
        KernelMode,
        (PVOID*)&Context->FileObject,
        NULL);

    /* Stack bypass modes require a named device object. */
    if (!NT_SUCCESS(status)) {
        /* Release the already opened handle before returning. */
        KswordStorageReleaseContext(Context);
        /* Propagate the object lookup result. */
        return status;
    }

    /* 同句柄的文件对象决定命名设备，后续所有下层对象也只从这里派生。 */
    Context->NamedDevice = IoGetRelatedDeviceObject(Context->FileObject);

    /* Acquire an independent reference to the current top of the disk stack. */
    Context->TopDevice = IoGetAttachedDeviceReference(Context->NamedDevice);
    /* Capture lower objects for explicitly selected bypass backends. */
    KswordStorageCaptureLowerDevices(Context);

    /* Use the documented default until geometry provides a better value. */
    Context->LogicalSectorSize = KSWORD_ARK_RAW_DISK_DEFAULT_SECTOR_SIZE;
    /* Physical sector size defaults to the logical size. */
    Context->PhysicalSectorSize = Context->LogicalSectorSize;
    /* Query the disk byte length through the named stack. */
    GET_LENGTH_INFORMATION lengthInfo = { 0 };
    /* Ignore the returned-byte count because the structure is fixed size. */
    status = KswordStorageSendHandleIoctl(
        Context->Handle,
        IOCTL_DISK_GET_LENGTH_INFO,
        NULL,
        0U,
        &lengthInfo,
        sizeof(lengthInfo),
        NULL);

    /* Preserve the valid non-negative disk length. */
    if (NT_SUCCESS(status) && lengthInfo.Length.QuadPart > 0) {
        /* Convert the signed documented field to the unsigned protocol field. */
        Context->DiskSizeBytes = (ULONGLONG)lengthInfo.Length.QuadPart;
    }

    /* Query the logical sector geometry. */
    DISK_GEOMETRY geometry = { 0 };
    /* The legacy geometry structure is sufficient for BytesPerSector. */
    status = KswordStorageSendHandleIoctl(
        Context->Handle,
        IOCTL_DISK_GET_DRIVE_GEOMETRY,
        NULL,
        0U,
        &geometry,
        sizeof(geometry),
        NULL);

    /* Replace the default only with a nonzero device value. */
    if (NT_SUCCESS(status) && geometry.BytesPerSector != 0U) {
        /* Save the device-reported logical sector size. */
        Context->LogicalSectorSize = geometry.BytesPerSector;
        /* Keep the physical fallback synchronized with the logical sector. */
        Context->PhysicalSectorSize = geometry.BytesPerSector;
    }

    /* Ask for the device descriptor that carries bus and identity metadata. */
    STORAGE_PROPERTY_QUERY propertyQuery = { 0 };
    /* Select the standard storage-device descriptor. */
    propertyQuery.PropertyId = StorageDeviceProperty;
    /* Request the current descriptor without an additional query payload. */
    propertyQuery.QueryType = PropertyStandardQuery;
    /* Keep descriptor storage bounded and stack-local. */
    UCHAR descriptorBuffer[KSW_STORAGE_FORENSICS_DESCRIPTOR_BYTES] = { 0 };
    /* Receive the actual descriptor byte count for offset validation. */
    ULONG_PTR descriptorBytes = 0U;
    /* Query the descriptor through the regular disk stack. */
    status = KswordStorageSendHandleIoctl(
        Context->Handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &propertyQuery,
        sizeof(propertyQuery),
        descriptorBuffer,
        sizeof(descriptorBuffer),
        &descriptorBytes);

    /* Parse only a complete fixed descriptor header. */
    if (NT_SUCCESS(status) && descriptorBytes >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
        /* Interpret the documented fixed header at the front of the buffer. */
        PSTORAGE_DEVICE_DESCRIPTOR descriptor = (PSTORAGE_DEVICE_DESCRIPTOR)descriptorBuffer;
        /* Preserve the bus type for backend capability decisions. */
        Context->BusType = (ULONG)descriptor->BusType;
        /* Convert the bounded product identifier to protocol text. */
        KswordStorageCopyDescriptorText(
            Context->Model,
            RTL_NUMBER_OF(Context->Model),
            descriptorBuffer,
            (ULONG)descriptorBytes,
            descriptor->ProductIdOffset);
        /* Convert the bounded serial identifier to protocol text. */
        KswordStorageCopyDescriptorText(
            Context->Serial,
            RTL_NUMBER_OF(Context->Serial),
            descriptorBuffer,
            (ULONG)descriptorBytes,
            descriptor->SerialNumberOffset);
    }

    /* Query the physical-sector alignment descriptor when supported. */
    RtlZeroMemory(&propertyQuery, sizeof(propertyQuery));
    /* Select the access-alignment property. */
    propertyQuery.PropertyId = StorageAccessAlignmentProperty;
    /* Request the current descriptor. */
    propertyQuery.QueryType = PropertyStandardQuery;
    /* Receive the fixed alignment descriptor. */
    STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR alignment = { 0 };
    /* Submit the alignment property query. */
    status = KswordStorageSendHandleIoctl(
        Context->Handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        &propertyQuery,
        sizeof(propertyQuery),
        &alignment,
        sizeof(alignment),
        NULL);

    /* Accept only a nonzero physical-sector result. */
    if (NT_SUCCESS(status) && alignment.BytesPerPhysicalSector != 0U) {
        /* Save the physical-sector granularity for user warnings. */
        Context->PhysicalSectorSize = alignment.BytesPerPhysicalSector;
    }

    /* Query the port path/target/lun tuple when the disk exposes SCSI addressing. */
    RtlZeroMemory(&Context->ScsiAddress, sizeof(Context->ScsiAddress));
    /* Submit the fixed SCSI address query. */
    status = KswordStorageSendHandleIoctl(
        Context->Handle,
        IOCTL_SCSI_GET_ADDRESS,
        NULL,
        0U,
        &Context->ScsiAddress,
        sizeof(Context->ScsiAddress),
        NULL);

    /* Record the availability of the address tuple. */
    if (NT_SUCCESS(status)) {
        /* Advertise a valid SCSI address in the response capabilities. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_SCSI_ADDRESS;
    }

    /* Every successfully opened disk supports the named-stack read backend. */
    Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_WINDOWS_STACK;
    /* Every backend in this module is bounded to explicit read requests. */
    Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_READ;

    /* A captured first-lower target enables storage-port bypass reads. */
    if (Context->PortDevice != NULL) {
        /* Advertise the storage-port target. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_STORAGE_PORT;
    }

    /* Determine whether the disk is offline using documented disk attributes. */
    GET_DISK_ATTRIBUTES diskAttributes = { 0 };
    /* Seed the version field required by the disk class driver. */
    diskAttributes.Version = sizeof(diskAttributes);
    /* Query attributes through the named disk stack. */
    status = KswordStorageSendHandleIoctl(
        Context->Handle,
        IOCTL_DISK_GET_DISK_ATTRIBUTES,
        NULL,
        0U,
        &diskAttributes,
        sizeof(diskAttributes),
        NULL);

    /* Advertise offline state only when the class driver returned it. */
    if (NT_SUCCESS(status)
        && (diskAttributes.Attributes & DISK_ATTRIBUTE_OFFLINE) != 0ULL) {
        /* Offline disks are eligible for the deepest backend. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_OFFLINE;
    }

    /* Protect loader-identified boot and system disks. */
    if (KswordStorageIsSystemDisk(Context->Handle)) {
        /* Mark the disk so both R0 policy and R3 UI can enforce the boundary. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK;
    }

    /* Identify NVMe transports for accurate UI backend descriptions. */
    if (Context->BusType == BusTypeNvme) {
        /* Advertise native NVMe transport metadata. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_NVME;
    }

    /* Identify common ATA/AHCI transport families. */
    if (Context->BusType == BusTypeAta
        || Context->BusType == BusTypeSata
        || Context->BusType == BusTypeAtapi) {
        /* Advertise ATA-family transport metadata. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_ATA;
    }

    /* The deepest target is enabled only for a confirmed offline disk. */
    if (Context->ControllerDevice != NULL
        && (Context->CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_OFFLINE) != 0U) {
        /* Advertise the controller-target backend. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_CONTROLLER;
    }

    /* Writes are available only when the caller obtained a writable handle. */
    if ((DesiredAccess & FILE_WRITE_DATA) != 0U) {
        /* Advertise write support after the access check succeeded. */
        Context->CapabilityFlags |= KSWORD_ARK_RAW_DISK_CAP_WRITE;
    }

    /* Context initialization succeeded even when optional metadata was absent. */
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordStorageAllocateAlignedBuffer(
    _In_ ULONG Length,
    _In_ ULONG Alignment,
    _Outptr_ PVOID* AllocationOut,
    _Outptr_ PVOID* AlignedBufferOut
    )
/*++

Routine Description:

    Allocates a nonpaged transfer buffer aligned to the logical-sector size.

--*/
{
    /* Reject missing output pointers before allocating pool. */
    if (AllocationOut == NULL || AlignedBufferOut == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear both outputs before a possible allocation failure. */
    *AllocationOut = NULL;
    /* Clear the aligned view independently. */
    *AlignedBufferOut = NULL;
    /* Normalize unsupported alignment values to the protocol default. */
    ULONG effectiveAlignment = Alignment;

    /* A zero or non-power-of-two value cannot be used by ALIGN_UP_BY. */
    if (effectiveAlignment == 0U
        || (effectiveAlignment & (effectiveAlignment - 1U)) != 0U) {
        /* Use the protocol default sector alignment. */
        effectiveAlignment = KSWORD_ARK_RAW_DISK_DEFAULT_SECTOR_SIZE;
    }

    /* Reject arithmetic overflow before adding alignment padding. */
    if (Length > MAXULONG - effectiveAlignment) {
        /* The allocation length cannot be represented. */
        return STATUS_INTEGER_OVERFLOW;
    }

    /* Allocate padding so the returned view can be aligned inside the block. */
    PVOID allocation = KswordARKAllocateNonPagedPool(
        (SIZE_T)Length + effectiveAlignment,
        KSW_STORAGE_FORENSICS_POOL_TAG);

    /* Propagate pool exhaustion without exposing a partial output. */
    if (allocation == NULL) {
        /* No transfer buffer is available. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Round the first usable address up to the requested alignment. */
    PVOID aligned = (PVOID)ALIGN_UP_BY((ULONG_PTR)allocation, effectiveAlignment);
    /* Return the allocation base for ExFreePool. */
    *AllocationOut = allocation;
    /* Return the aligned transfer view for I/O. */
    *AlignedBufferOut = aligned;
    /* The allocation and alignment operation completed. */
    return STATUS_SUCCESS;
}

PDEVICE_OBJECT
KswordStorageSelectBackendDevice(
    _In_ const KSW_STORAGE_DISK_CONTEXT* Context,
    _In_ ULONG Backend
    )
/*++

Routine Description:

    Maps a bypass backend identifier to an already referenced device object.

--*/
{
    /* The first-lower object implements the storage-port bypass mode. */
    if (Backend == KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT) {
        /* Return the captured first-lower target. */
        return Context->PortDevice;
    }

    /* The deepest object implements the offline controller-target mode. */
    if (Backend == KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER) {
        /* Return the captured deepest target. */
        return Context->ControllerDevice;
    }

    /* The named-stack backend is handled through ZwReadFile or ZwWriteFile. */
    return NULL;
}

NTSTATUS
KswordStorageSendDeviceReadWrite(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ UCHAR MajorFunction,
    _In_ ULONGLONG Offset,
    _Inout_updates_bytes_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ForceUnitAccess,
    _Out_ PULONG BytesTransferredOut
    )
/*++

Routine Description:

    Builds one synchronous read or write IRP directly for a selected lower
    device object.

--*/
{
    /* Reject a missing target before allocating an IRP. */
    if (DeviceObject == NULL || BytesTransferredOut == NULL) {
        /* The backend target is unavailable. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the byte count before the request is submitted. */
    *BytesTransferredOut = 0U;
    /* A kernel event owns completion synchronization for the built IRP. */
    KEVENT completionEvent;
    /* Initialize the event in the non-signaled state. */
    KeInitializeEvent(&completionEvent, NotificationEvent, FALSE);
    /* The completion routine writes the final I/O status here. */
    IO_STATUS_BLOCK ioStatus = { 0 };
    /* Convert the protocol offset to the signed LARGE_INTEGER API type. */
    LARGE_INTEGER byteOffset;
    /* Preserve the full 64-bit byte offset. */
    byteOffset.QuadPart = (LONGLONG)Offset;
    /* Build an IRP that reflects the target device buffering flags. */
    PIRP irp = IoBuildSynchronousFsdRequest(
        MajorFunction,
        DeviceObject,
        Buffer,
        Length,
        &byteOffset,
        &completionEvent,
        &ioStatus);

    /* IRP allocation failure is reported before touching the target. */
    if (irp == NULL) {
        /* The I/O manager could not allocate the request. */
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Access the next stack location owned by the target driver. */
    PIO_STACK_LOCATION stack = IoGetNextIrpStackLocation(irp);
    /* Permit removable media reads after an operator-selected disk refresh. */
    stack->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

    /* A write can request hardware-level unit access where the stack honors it. */
    if (MajorFunction == IRP_MJ_WRITE && ForceUnitAccess) {
        /* Set the documented write-through stack flag. */
        stack->Flags |= SL_WRITE_THROUGH;
    }

    /* Send the fully built request to the explicitly selected target. */
    NTSTATUS status = IoCallDriver(DeviceObject, irp);

    /* Wait only when the target retained the request asynchronously. */
    if (status == STATUS_PENDING) {
        LARGE_INTEGER timeout;
        NTSTATUS waitStatus;

        /* Bound the normal wait so a lower storage driver cannot hold the worker forever. */
        timeout.QuadPart = KSW_STORAGE_RELATIVE_IO_TIMEOUT_100NS;
        waitStatus = KeWaitForSingleObject(
            &completionEvent,
            Executive,
            KernelMode,
            FALSE,
            &timeout);
        if (waitStatus == STATUS_TIMEOUT) {
            /* Request cancellation while the caller-owned event/IOSB/buffer are still alive. */
            (VOID)IoCancelIrp(irp);
            /* A final drain is mandatory before returning stack storage to the caller. */
            waitStatus = KeWaitForSingleObject(
                &completionEvent,
                Executive,
                KernelMode,
                FALSE,
                NULL);
            status = NT_SUCCESS(waitStatus) ? STATUS_IO_TIMEOUT : waitStatus;
        }
        else if (NT_SUCCESS(waitStatus)) {
            /* Read the final completion status after the event is signaled. */
            status = ioStatus.Status;
        }
        else {
            /* Unexpected wait failures still require cancellation and completion drainage. */
            (VOID)IoCancelIrp(irp);
            (VOID)KeWaitForSingleObject(
                &completionEvent,
                Executive,
                KernelMode,
                FALSE,
                NULL);
            status = waitStatus;
        }
    }

    /* 完成量只能是实际请求范围内的字节数，失败时的部分完成同样如实保留。 */
    if (ioStatus.Information <= (ULONG_PTR)Length) {
        /* 请求长度已限额到ULONG，不把真实短完成补成整个请求长度。 */
        *BytesTransferredOut = (ULONG)ioStatus.Information;
    } else if (NT_SUCCESS(status)) {
        /* 成功却报告超量属于无效回执，不能截断后冒充完整读取或写入。 */
        status = STATUS_DEVICE_DATA_ERROR;
    }

    /* Propagate the selected device object's completion status. */
    return status;
}

static NTSTATUS
KswordStorageValidateTransfer(
    _In_ const KSW_STORAGE_DISK_CONTEXT* Context,
    _In_ ULONGLONG Offset,
    _In_ ULONG Length
    )
/*++

Routine Description:

    Enforces bounded, sector-aligned raw disk I/O ranges.

--*/
{
    /* Transfers must be non-empty and remain under the protocol budget. */
    if (Length == 0U || Length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES) {
        /* Reject invalid or unbounded transfer lengths. */
        return STATUS_INVALID_BUFFER_SIZE;
    }

    /* Both offset and length must align to the logical sector. */
    if ((Offset % Context->LogicalSectorSize) != 0ULL
        || (Length % Context->LogicalSectorSize) != 0U) {
        /* Raw disk requests cannot be silently widened. */
        return STATUS_DATATYPE_MISALIGNMENT;
    }

    /* An unknown disk length cannot safely authorize raw transfer ranges. */
    if (Context->DiskSizeBytes == 0ULL) {
        /* Treat missing capacity metadata as an unavailable backend. */
        return STATUS_DEVICE_NOT_READY;
    }

    /* Check addition overflow before comparing the transfer end. */
    if (Offset > MAXULONGLONG - Length) {
        /* The requested range cannot be represented. */
        return STATUS_INTEGER_OVERFLOW;
    }

    /* Reject any range extending beyond the physical disk. */
    if (Offset + Length > Context->DiskSizeBytes) {
        /* The requested range crosses the disk boundary. */
        return STATUS_END_OF_FILE;
    }

    /* Every range check succeeded. */
    return STATUS_SUCCESS;
}

static ULONG
KswordStorageMapStatus(
    _In_ NTSTATUS Status
    )
/*++

Routine Description:

    Maps kernel status values to stable protocol status identifiers.

--*/
{
    /* Successful requests have the stable OK identifier. */
    if (NT_SUCCESS(Status)) {
        /* Return the protocol success status. */
        return KSWORD_ARK_RAW_DISK_STATUS_OK;
    }

    /* Translate common validation and availability failures. */
    switch (Status) {
    case STATUS_INVALID_PARAMETER:
    case STATUS_INVALID_BUFFER_SIZE:
    case STATUS_INFO_LENGTH_MISMATCH:
        return KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
    case STATUS_NO_SUCH_DEVICE:
    case STATUS_OBJECT_NAME_NOT_FOUND:
    case STATUS_OBJECT_PATH_NOT_FOUND:
        return KSWORD_ARK_RAW_DISK_STATUS_DISK_NOT_FOUND;
    case STATUS_NOT_SUPPORTED:
    case STATUS_DEVICE_NOT_READY:
        return KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
    case STATUS_END_OF_FILE:
    case STATUS_INTEGER_OVERFLOW:
        return KSWORD_ARK_RAW_DISK_STATUS_RANGE_INVALID;
    case STATUS_DATATYPE_MISALIGNMENT:
        return KSWORD_ARK_RAW_DISK_STATUS_ALIGNMENT_REQUIRED;
    case STATUS_ACCESS_DENIED:
    case STATUS_PRIVILEGE_NOT_HELD:
        return KSWORD_ARK_RAW_DISK_STATUS_ACCESS_DENIED;
    case STATUS_BUFFER_TOO_SMALL:
    case STATUS_BUFFER_OVERFLOW:
        return KSWORD_ARK_RAW_DISK_STATUS_BUFFER_TOO_SMALL;
    default:
        return KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
    }
}

NTSTATUS
KswordARKStorageQueryRawDiskBackend(
    _In_ const KSWORD_ARK_QUERY_RAW_DISK_BACKEND_REQUEST* Request,
    _Out_ KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE* Response
    )
/*++

Routine Description:

    Returns one disk's bounded raw-I/O backend capabilities and identity.

--*/
{
    /* Reject missing protocol pointers before writing a response. */
    if (Request == NULL || Response == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Initialize the fixed response before validating caller-controlled fields. */
    RtlZeroMemory(Response, sizeof(*Response));
    /* Publish the response protocol version. */
    Response->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    /* Publish the complete response size. */
    Response->size = sizeof(*Response);
    /* Echo the requested disk number for UI correlation. */
    Response->diskNumber = Request->diskNumber;
    /* Echo the requested backend without silently changing it. */
    Response->requestedBackend = Request->requestedBackend;

    /* Enforce the exact version and minimum request size. */
    if (Request->version != KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION
        || Request->size < sizeof(*Request)) {
        /* Report stable protocol validation status. */
        Response->status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        /* Preserve the kernel validation detail. */
        Response->lastStatus = STATUS_REVISION_MISMATCH;
        /* Return a protocol-level error to the IOCTL handler. */
        return STATUS_REVISION_MISMATCH;
    }

    /* Collect read-only disk metadata and stack targets. */
    KSW_STORAGE_DISK_CONTEXT context;
    /* Open the candidate disk with read-only data and attribute access. */
    NTSTATUS status = KswordStorageOpenContext(
        Request->diskNumber,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        FALSE,
        &context);

    /* Return a fully initialized failure response when the disk cannot open. */
    if (!NT_SUCCESS(status)) {
        /* Map the kernel failure to a stable protocol status. */
        Response->status = KswordStorageMapStatus(status);
        /* Preserve the raw kernel status for diagnostics. */
        Response->lastStatus = status;
        /* Copy a bounded diagnostic string. */
        (void)RtlStringCchPrintfW(
            Response->detail,
            RTL_NUMBER_OF(Response->detail),
            L"Physical disk %lu could not be opened (0x%08X).",
            Request->diskNumber,
            (ULONG)status);
        /* Propagate the disk open failure. */
        return status;
    }

    /* Publish the collected capability flags. */
    Response->capabilityFlags = context.CapabilityFlags;
    /* Build the compact mask used by backend selectors. */
    Response->availableBackendMask = 0U;

    /* Add the regular stack backend bit. */
    if ((context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_WINDOWS_STACK) != 0U) {
        /* Backend identifiers are one-based and map to mask positions. */
        Response->availableBackendMask |= 1UL << (KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK - 1U);
    }

    /* Add the storage-port backend bit. */
    if ((context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_STORAGE_PORT) != 0U) {
        /* Backend identifiers are one-based and map to mask positions. */
        Response->availableBackendMask |= 1UL << (KSWORD_ARK_RAW_DISK_BACKEND_STORAGE_PORT - 1U);
    }

    /* Add the deepest offline backend bit. */
    if ((context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_CONTROLLER) != 0U) {
        /* Backend identifiers are one-based and map to mask positions. */
        Response->availableBackendMask |= 1UL << (KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER - 1U);
    }

    /* Publish all stable geometry and transport fields. */
    Response->logicalSectorSize = context.LogicalSectorSize;
    /* Publish the physical-sector warning granularity. */
    Response->physicalSectorSize = context.PhysicalSectorSize;
    /* Publish the documented storage bus type. */
    Response->busType = context.BusType;
    /* Publish the SCSI path field when available. */
    Response->pathId = context.ScsiAddress.PathId;
    /* Publish the SCSI target field when available. */
    Response->targetId = context.ScsiAddress.TargetId;
    /* Publish the SCSI logical-unit field when available. */
    Response->lun = context.ScsiAddress.Lun;
    /* Publish the physical disk size. */
    Response->diskSizeBytes = context.DiskSizeBytes;
    /* Copy the bounded physical-disk path. */
    (void)RtlStringCchCopyW(
        Response->devicePath,
        RTL_NUMBER_OF(Response->devicePath),
        context.Path);
    /* Copy the bounded model identifier. */
    (void)RtlStringCchCopyW(
        Response->model,
        RTL_NUMBER_OF(Response->model),
        context.Model);
    /* Copy the bounded serial identifier. */
    (void)RtlStringCchCopyW(
        Response->serial,
        RTL_NUMBER_OF(Response->serial),
        context.Serial);

    /* Validate an explicitly requested backend against the capability mask. */
    if (Request->requestedBackend != 0U
        && (Request->requestedBackend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
            || (Response->availableBackendMask
                & (1UL << (Request->requestedBackend - 1U))) == 0U)) {
        /* Report that the selected backend cannot serve this disk. */
        Response->status = KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
        /* Use a stable kernel status for unsupported selection. */
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Explain the exact selection failure. */
        (void)RtlStringCchPrintfW(
            Response->detail,
            RTL_NUMBER_OF(Response->detail),
            L"Backend %lu is unavailable for physical disk %lu.",
            Request->requestedBackend,
            Request->diskNumber);
        /* Release every context-owned reference before returning. */
        KswordStorageReleaseContext(&context);
        /* Return a transport-neutral unsupported status. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Report a successful capability query. */
    Response->status = KSWORD_ARK_RAW_DISK_STATUS_OK;
    /* Preserve an explicit successful NTSTATUS. */
    Response->lastStatus = STATUS_SUCCESS;
    /* Summarize the enforced boundary for the UI. */
    (void)RtlStringCchPrintfW(
        Response->detail,
        RTL_NUMBER_OF(Response->detail),
        L"Backends=0x%X, sector=%lu/%lu, offline=%s, system=%s.",
        Response->availableBackendMask,
        Response->logicalSectorSize,
        Response->physicalSectorSize,
        (context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_OFFLINE) != 0U ? L"yes" : L"no",
        (context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U ? L"yes" : L"no");
    /* Release every context-owned reference after copying metadata. */
    KswordStorageReleaseContext(&context);
    /* The capability query completed successfully. */
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKStorageReadRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_READ_REQUEST* Request,
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    Reads one aligned, bounded disk range through the explicitly selected
    backend.

--*/
{
    /* Reject missing pointers before accessing caller buffers. */
    if (Request == NULL || OutputBuffer == NULL || BytesWrittenOut == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Clear the completion count for every failure path. */
    *BytesWrittenOut = 0U;
    /* Interpret the caller output as the variable protocol response. */
    PKSWORD_ARK_RAW_DISK_READ_RESPONSE response =
        (PKSWORD_ARK_RAW_DISK_READ_RESPONSE)OutputBuffer;

    /* The fixed response header must always fit. */
    if (OutputBufferLength < KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE) {
        /* No protocol response can be returned. */
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Initialize only the fixed response header before validation. */
    RtlZeroMemory(response, KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE);
    /* Publish the current protocol version. */
    response->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    /* Publish the fixed response header size initially. */
    response->size = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
    /* Echo the selected backend. */
    response->backendUsed = Request->backend;

    /* 捕获读只升级请求版本，响应头仍是V1的32字节。 */
    BOOLEAN capturedRead = Request->version == KSWORD_ARK_RAW_DISK_CAPTURED_READ_VERSION;
    /* 仅适配器已经完整复制V2固定结构后才能把旧前缀解释为扩展请求。 */
    const KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST* capturedRequest =
        (const KSWORD_ARK_RAW_DISK_CAPTURED_READ_REQUEST*)Request;

    /* Validate the fixed request and backend identifier. */
    if ((!capturedRead && Request->version != KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION)
        || (capturedRead && (Request->size != sizeof(*capturedRequest) || Request->reserved0 != 0U
            || Request->reserved1 != 0U || Request->length == 0U
            || Request->length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES))
        || Request->size < sizeof(*Request)
        || Request->backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
        || Request->backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER) {
        /* Report stable validation status. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        /* Preserve the validation status. */
        response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Return the initialized header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Reject the malformed request. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Ensure the variable response data fits the WDF output buffer. */
    if (Request->length > OutputBufferLength - KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE) {
        /* Report the stable buffer-size failure. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_BUFFER_TOO_SMALL;
        /* Preserve the kernel buffer status. */
        response->lastStatus = STATUS_BUFFER_TOO_SMALL;
        /* Return the initialized header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Reject the undersized caller buffer. */
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Open the disk through its regular stack and capture bypass targets. */
    KSW_STORAGE_DISK_CONTEXT context;
    /* Reads require data and attribute access only. */
    NTSTATUS status = KswordStorageOpenContext(
        Request->diskNumber,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        FALSE,
        &context);

    /* Stop before allocating transfer memory when the disk cannot open. */
    if (!NT_SUCCESS(status)) {
        /* Report the stable disk-open failure. */
        response->status = KswordStorageMapStatus(status);
        /* Preserve the kernel status. */
        response->lastStatus = status;
        /* Return the initialized response header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Propagate the disk-open failure. */
        return status;
    }

    /* Publish the actual sector granularity before transfer validation. */
    response->logicalSectorSize = context.LogicalSectorSize;
    /* Enforce the system-disk read confirmation for bypass backends. */
    if ((context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U
        && Request->backend != KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
        && (Request->flags & KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_READ) == 0U) {
        /* Report the protected-system-disk boundary. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_SYSTEM_DISK_BLOCKED;
        /* Preserve the access decision as a kernel status. */
        response->lastStatus = STATUS_ACCESS_DENIED;
        /* Return the initialized response header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Deny the bypass read without explicit caller confirmation. */
        return STATUS_ACCESS_DENIED;
    }

    /* The controller-target backend is restricted to offline media. */
    if (Request->backend == KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
        && (context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_CONTROLLER) == 0U) {
        /* Report backend unavailability. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
        /* Preserve the unsupported status. */
        response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Return the initialized response header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Reject the unsupported backend. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Validate length, alignment and disk boundary before I/O. */
    status = KswordStorageValidateTransfer(
        &context,
        Request->offset,
        Request->length);

    /* Return the exact range validation failure. */
    if (!NT_SUCCESS(status)) {
        /* Map the failure to the stable protocol status. */
        response->status = KswordStorageMapStatus(status);
        /* Preserve the kernel status. */
        response->lastStatus = status;
        /* Return the initialized response header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Propagate the range failure. */
        return status;
    }

    /* 强身份只在上面已打开且持续持有的同一对象上验证，阻止A→B→A夹读误归源。 */
    if (capturedRead) {
        /* 协议状态将设备改变与不支持分开，前者不能兼容回退。 */
        ULONG protocolStatus = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
        /* GUID校验和最终读取共享同句柄/设备引用，不按DiskNumber重新打开。 */
        status = KswordStorageValidateCapturedIdentity(&context, Request->diskNumber,
            capturedRequest->expectedDeviceGuid, &protocolStatus);
        /* 身份失败不提供任何可贴错误来源的字节。 */
        if (!NT_SUCCESS(status)) {
            /* 返回稳定来源/能力状态供界面处理。 */
            response->status = protocolStatus;
            /* 保存原始NTSTATUS。 */
            response->lastStatus = status;
            /* 仅返回已初始化的固定响应头。 */
            *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
            /* 释放这一打开对象，不尝试第二个设备。 */
            KswordStorageReleaseContext(&context);
            /* 此出口没有读取数据或写入动作。 */
            return status;
        }
    }

    /* Allocate an aligned nonpaged buffer for every disk backend. */
    PVOID allocation = NULL;
    /* The aligned view is copied into the buffered IOCTL response after I/O. */
    PVOID transferBuffer = NULL;
    /* Request alignment matching the logical disk sector. */
    status = KswordStorageAllocateAlignedBuffer(
        Request->length,
        context.LogicalSectorSize,
        &allocation,
        &transferBuffer);

    /* Stop cleanly on pool exhaustion. */
    if (!NT_SUCCESS(status)) {
        /* Report the stable I/O failure. */
        response->status = KswordStorageMapStatus(status);
        /* Preserve the allocation failure. */
        response->lastStatus = status;
        /* Return the initialized response header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Propagate the allocation failure. */
        return status;
    }

    /* Start with no transferred bytes. */
    ULONG transferred = 0U;

    /* Use the named physical-disk stack for backend one. */
    if (Request->backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK) {
        /* Convert the absolute byte offset to the ZwReadFile type. */
        LARGE_INTEGER byteOffset;
        /* Preserve the caller's full 64-bit offset. */
        byteOffset.QuadPart = (LONGLONG)Request->offset;
        /* Receive synchronous completion metadata. */
        IO_STATUS_BLOCK ioStatus = { 0 };
        /* Read through the named disk stack. */
        status = ZwReadFile(
            context.Handle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            transferBuffer,
            Request->length,
            &byteOffset,
            NULL);

        /* 只保留请求范围内的实际完成量，包括失败时后端报告的部分完成。 */
        if (ioStatus.Information <= (ULONG_PTR)Request->length) {
            /* 真实短读仍由完整捕获客户端拒绝，不补零或扩大已读取范围。 */
            transferred = (ULONG)ioStatus.Information;
        } else if (NT_SUCCESS(status)) {
            /* 超量成功回执无法证明内容完整，禁止截断后发布捕获证据。 */
            status = STATUS_DEVICE_DATA_ERROR;
        }
    } else {
        /* Select the independently referenced lower target. */
        PDEVICE_OBJECT target = KswordStorageSelectBackendDevice(
            &context,
            Request->backend);
        /* Submit a direct read IRP to the selected lower device. */
        status = KswordStorageSendDeviceReadWrite(
            target,
            IRP_MJ_READ,
            Request->offset,
            transferBuffer,
            Request->length,
            FALSE,
            &transferred);
    }

    /* Copy completed bytes into the METHOD_BUFFERED output only on success. */
    if (NT_SUCCESS(status)) {
        /* Preserve exactly the bytes reported by the selected backend. */
        RtlCopyMemory(response->data, transferBuffer, transferred);
        /* Publish the transferred byte count. */
        response->bytesTransferred = transferred;
        /* Publish the full variable response size. */
        response->size = (ULONG)(KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE + transferred);
        /* Report stable protocol success. */
        response->status = KSWORD_ARK_RAW_DISK_STATUS_OK;
        /* Preserve successful kernel completion. */
        response->lastStatus = STATUS_SUCCESS;
        /* Return the full variable response. */
        *BytesWrittenOut = response->size;
    } else {
        /* Map the backend failure to a stable protocol status. */
        response->status = KswordStorageMapStatus(status);
        /* Preserve the raw backend failure. */
        response->lastStatus = status;
        /* Return only the initialized response header. */
        *BytesWrittenOut = KSWORD_ARK_RAW_DISK_READ_RESPONSE_HEADER_SIZE;
    }

    /* Release the transfer allocation base. */
    ExFreePoolWithTag(allocation, KSW_STORAGE_FORENSICS_POOL_TAG);
    /* Release the disk handle and referenced stack objects. */
    KswordStorageReleaseContext(&context);
    /* Propagate the selected backend completion status. */
    return status;
}

NTSTATUS
KswordARKStorageWriteRawDisk(
    _In_ const KSWORD_ARK_RAW_DISK_WRITE_REQUEST* Request,
    _In_ size_t InputBufferLength,
    _Out_ KSWORD_ARK_RAW_DISK_WRITE_RESPONSE* Response
    )
/*++

Routine Description:

    Writes one aligned disk range after protocol, safety-policy, system-disk
    and offline-backend checks.

--*/
{
    /* Reject missing protocol pointers before writing a response. */
    if (Request == NULL || Response == NULL) {
        /* The caller contract was invalid. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Initialize the complete fixed response. */
    RtlZeroMemory(Response, sizeof(*Response));
    /* Publish the current protocol version. */
    Response->version = KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION;
    /* Publish the fixed response size. */
    Response->size = sizeof(*Response);
    /* Echo the selected backend. */
    Response->backendUsed = Request->backend;

    /* V2 捕获写保留旧前缀，但变量载荷是 GUID 之后的两段等长字节。 */
    BOOLEAN capturedWrite = Request->version == KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_VERSION;
    /* 只在完整 V2 固定头通过后访问 GUID 与捕获字节。 */
    const KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST* capturedRequest =
        (const KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_REQUEST*)Request;
    /* 所有长度先限制，保证 header + 2 * length 计算没有溢出。 */
    if (capturedWrite && (Request->length == 0U
        || Request->length > KSWORD_ARK_RAW_DISK_MAX_TRANSFER_BYTES
        || Request->reserved != 0U
        || InputBufferLength != (size_t)KSWORD_ARK_RAW_DISK_CAPTURED_WRITE_HEADER_SIZE + 2U * Request->length
        || Request->size != InputBufferLength)) {
        /* 捕获包必须精确匹配结构和两个载荷，不能截短或附加未声明数据。 */
        Response->status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        /* 拒绝在验证和任何磁盘打开之前完成。 */
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* 不尝试把 V2 改成 V1。 */
        return STATUS_INVALID_PARAMETER;
    }

    /* Validate fixed fields and the variable input length. */
    if ((!capturedWrite && Request->version != KSWORD_ARK_STORAGE_FORENSICS_PROTOCOL_VERSION)
        || Request->size < KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE
        || Request->backend < KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK
        || Request->backend > KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
        || Request->confirmationToken != KSWORD_ARK_RAW_DISK_CONFIRMATION_TOKEN
        || (Request->flags & KSWORD_ARK_RAW_DISK_FLAG_UI_CONFIRMED_WRITE) == 0U
        || Request->length > InputBufferLength - min(
            InputBufferLength,
            (size_t)KSWORD_ARK_RAW_DISK_WRITE_REQUEST_HEADER_SIZE)) {
        /* Report stable protocol validation status. */
        Response->status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        /* Preserve the kernel validation status. */
        Response->lastStatus = STATUS_INVALID_PARAMETER;
        /* Reject the malformed or unconfirmed request. */
        return STATUS_INVALID_PARAMETER;
    }

    /* Open the disk with explicit write data access. */
    KSW_STORAGE_DISK_CONTEXT context;
    /* Request both data directions because some stacks require read access for metadata. */
    NTSTATUS status = KswordStorageOpenContext(
        Request->diskNumber,
        FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES,
        (Request->flags & KSWORD_ARK_RAW_DISK_FLAG_FUA) != 0U,
        &context);

    /* Return a stable failure when write access cannot be obtained. */
    if (!NT_SUCCESS(status)) {
        /* Map the disk-open failure. */
        Response->status = KswordStorageMapStatus(status);
        /* Preserve the raw kernel status. */
        Response->lastStatus = status;
        /* Propagate the disk-open failure. */
        return status;
    }

    /* Publish the actual logical-sector size. */
    Response->logicalSectorSize = context.LogicalSectorSize;

    /* System disks require the stronger explicit confirmation flag. */
    if ((context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_SYSTEM_DISK) != 0U
        && (Request->flags & KSWORD_ARK_RAW_DISK_FLAG_ALLOW_SYSTEM_DISK_WRITE) == 0U) {
        /* Report the protected system-disk boundary. */
        Response->status = KSWORD_ARK_RAW_DISK_STATUS_SYSTEM_DISK_BLOCKED;
        /* Preserve the access decision. */
        Response->lastStatus = STATUS_ACCESS_DENIED;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Deny the write before safety-policy evaluation. */
        return STATUS_ACCESS_DENIED;
    }

    /* The deepest backend is enabled only for offline media. */
    if (Request->backend == KSWORD_ARK_RAW_DISK_BACKEND_CONTROLLER
        && (context.CapabilityFlags & KSWORD_ARK_RAW_DISK_CAP_CONTROLLER) == 0U) {
        /* Report backend unavailability. */
        Response->status = KSWORD_ARK_RAW_DISK_STATUS_BACKEND_UNAVAILABLE;
        /* Preserve the unsupported status. */
        Response->lastStatus = STATUS_NOT_SUPPORTED;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Reject the unsafe backend selection. */
        return STATUS_NOT_SUPPORTED;
    }

    /* Validate length, alignment and disk boundary before policy evaluation. */
    status = KswordStorageValidateTransfer(
        &context,
        Request->offset,
        Request->length);

    /* Stop on an invalid raw disk range. */
    if (!NT_SUCCESS(status)) {
        /* Map the range failure. */
        Response->status = KswordStorageMapStatus(status);
        /* Preserve the raw kernel status. */
        Response->lastStatus = status;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Propagate the range failure. */
        return status;
    }

    /* Allocate an aligned nonpaged transfer buffer. */
    PVOID allocation = NULL;
    /* This aligned view is supplied to the disk stack. */
    PVOID transferBuffer = NULL;
    /* Align the buffer to the disk's logical sector. */
    status = KswordStorageAllocateAlignedBuffer(
        Request->length,
        context.LogicalSectorSize,
        &allocation,
        &transferBuffer);

    /* Stop cleanly on pool exhaustion. */
    if (!NT_SUCCESS(status)) {
        /* Map the allocation failure. */
        Response->status = KswordStorageMapStatus(status);
        /* Preserve the allocation status. */
        Response->lastStatus = status;
        /* Release the opened disk and referenced stack objects. */
        KswordStorageReleaseContext(&context);
        /* Propagate the allocation failure. */
        return status;
    }

    /* 复制新载荷之前在当前句柄及设备对象上检查身份和原字节。 */
    if (capturedWrite) {
        /* 稳定协议状态由只读捕获验证器提供。 */
        ULONG protocolStatus = KSWORD_ARK_RAW_DISK_STATUS_IO_FAILED;
        /* 全过程使用上面一次打开且保持引用的同一 context。 */
        status = KswordStorageValidateCapturedWrite(&context, capturedRequest, transferBuffer, &protocolStatus);
        /* 任何身份、原值或读取失败都不能触发写入。 */
        if (!NT_SUCCESS(status)) {
            /* 将拒绝原因返回给 UI，而不是把它伪装成完整写入。 */
            Response->status = protocolStatus;
            /* 保存底层 NTSTATUS 供诊断。 */
            Response->lastStatus = status;
            /* 释放唯一对齐传输分配。 */
            ExFreePoolWithTag(allocation, KSW_STORAGE_FORENSICS_POOL_TAG);
            /* 释放同一已打开上下文，绝不按设备号重开。 */
            KswordStorageReleaseContext(&context);
            /* 此出口没有任何 IRP_MJ_WRITE 或 ZwWriteFile。 */
            return status;
        }
    }
    /* V2 使用第二段新值；V1 使用原有40字节头之后的载荷。 */
    const UCHAR* replacement = capturedWrite ? capturedRequest->data + Request->length : Request->data;
    /* 将已验证范围的新值复制到同一个对齐写缓冲。 */
    RtlCopyMemory(transferBuffer, replacement, Request->length);
    /* Start with no transferred bytes. */
    ULONG transferred = 0U;

    /* Use the named physical-disk stack for backend one. */
    if (Request->backend == KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK) {
        /* Convert the absolute byte offset to the ZwWriteFile type. */
        LARGE_INTEGER byteOffset;
        /* Preserve the caller's full 64-bit offset. */
        byteOffset.QuadPart = (LONGLONG)Request->offset;
        /* Receive synchronous completion metadata. */
        IO_STATUS_BLOCK ioStatus = { 0 };
        /* Write through the named disk stack. */
        status = ZwWriteFile(
            context.Handle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            transferBuffer,
            Request->length,
            &byteOffset,
            NULL);

        /* 短写或失败的部分写入必须保留真实完成量，不能隐藏可能生效的字节。 */
        if (ioStatus.Information <= (ULONG_PTR)Request->length) {
            /* 整体状态仍由后端和后续捕获完整性检查共同决定。 */
            transferred = (ULONG)ioStatus.Information;
        } else if (NT_SUCCESS(status)) {
            /* 超量成功不属于合法写回回执，禁止截断后标成完整成功。 */
            status = STATUS_DEVICE_DATA_ERROR;
        }
    } else {
        /* Select the independently referenced lower target. */
        PDEVICE_OBJECT target = KswordStorageSelectBackendDevice(
            &context,
            Request->backend);
        /* Submit a direct write IRP to the selected lower device. */
        status = KswordStorageSendDeviceReadWrite(
            target,
            IRP_MJ_WRITE,
            Request->offset,
            transferBuffer,
            Request->length,
            (Request->flags & KSWORD_ARK_RAW_DISK_FLAG_FUA) != 0U,
            &transferred);
    }

    /* V2 成功必须完整覆盖捕获范围，短写不可返回完整成功。 */
    if (capturedWrite && NT_SUCCESS(status) && transferred != Request->length) {
        /* 保留实际 transferred 字节数，但将事务回执标成失败。 */
        status = STATUS_DEVICE_DATA_ERROR;
    }

    /* Publish the completed write result. */
    Response->status = KswordStorageMapStatus(status);
    /* Publish the exact backend transfer size. */
    Response->bytesTransferred = transferred;
    /* Preserve the selected backend's raw completion status. */
    Response->lastStatus = status;
    /* Release the aligned transfer allocation. */
    ExFreePoolWithTag(allocation, KSW_STORAGE_FORENSICS_POOL_TAG);
    /* Release the disk handle and referenced stack objects. */
    KswordStorageReleaseContext(&context);
    /* Propagate the selected backend completion status. */
    return status;
}
