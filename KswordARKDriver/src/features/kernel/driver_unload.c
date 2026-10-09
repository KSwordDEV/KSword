/*++

Module Name:

    driver_unload.c

Abstract:

    Force DriverObject unload by name.

Environment:

    Kernel-mode Driver Framework

--*/

#define KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL 1
#include "../callback/callback_external_core.h"

#include "ark/ark_driver.h"
#include "ark/ark_thread.h"
#include "driver_integrity.h"
#include "../thread/work_queue_fallback.h" // 强卸载预检也必须支持无 PsGetNextProcessThread 导出的内核。
#include "../../platform/pool_compat.h"

#include <ntstrsafe.h>

/* 中文说明：默认等待 DriverUnload 系统线程 3 秒，避免 UI 无限阻塞。 */
#define KSW_DRIVER_UNLOAD_DEFAULT_TIMEOUT_MS 3000UL
/* 中文说明：最大等待 30 秒，防止恶意/异常 DriverUnload 挂死调用者。 */
#define KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS 30000UL
/* 中文说明：卸载线程上下文使用独立 tag，便于 pool 泄漏排查。 */
#define KSW_DRIVER_UNLOAD_TAG 'uDsK'
/* 中文说明：对象目录枚举缓冲 tag，用于服务名和 DriverObject 名不一致时兜底。 */
#define KSW_DRIVER_UNLOAD_DIRECTORY_TAG 'dDsK'
/* 中文说明：DeviceObject 清理最多遍历 128 个节点，避免损坏链表造成无限循环。 */
#define KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT 128UL
/* 中文说明：对象目录单条查询缓冲 16KB，足够容纳异常长对象名。 */
#define KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES (16UL * 1024UL)
/* 中文说明：每个目录最多扫描 4096 项，避免异常对象目录导致长时间占用 IOCTL。 */
#define KSW_DRIVER_UNLOAD_DIRECTORY_MAX_ENTRIES 4096UL
/* 中文说明：按模块基址强力清理最多尝试 256 个回调，防止异常枚举导致 IOCTL 长时间占用。 */
#define KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT 256UL
/* 中文说明：线程证据扫描最多遍历 4096 个进程，避免异常系统链路拖死 IOCTL。 */
#define KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_PROCESSES 4096UL
/* 中文说明：线程扫描/强拆终止最多遍历 65536 个线程。 */
#define KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_THREADS 65536UL
/* 中文说明：强拆逐线程等待 1 秒；未确认退出时不继续调用目标 DriverUnload。 */
#define KSW_DRIVER_UNLOAD_THREAD_TERMINATE_WAIT_MS 1000UL
/* 中文说明：封入口后最多做三轮终止/复扫，收敛并发新建的目标驱动线程。 */
#define KSW_DRIVER_UNLOAD_THREAD_TERMINATE_PASSES 3UL

/* 中文说明：SystemModuleInformation 用于把回调地址映射到内核模块基址。 */
#define KSW_DRIVER_UNLOAD_SYSTEM_MODULE_CLASS 11UL
/* 中文说明：强卸载前最多检查 128 个 DeviceObject，和删除上限保持一致。 */
#define KSW_DRIVER_UNLOAD_PREFLIGHT_DEVICE_LIMIT KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT
/* 中文说明：预检的大型只读工作区使用独立 tag，避免占用内核线程栈。 */
#define KSW_DRIVER_UNLOAD_PREFLIGHT_TAG 'pDsK'
/* 中文说明：释放最后一个 DriverObject 引用后短暂重试，等待对象管理器/loader 完成同步清理。 */
#define KSW_DRIVER_UNLOAD_POST_VERIFY_RETRIES 5UL
/* 中文说明：每次闭环验证之间等待 20ms，避免 IOCTL 长时间占用。 */
#define KSW_DRIVER_UNLOAD_POST_VERIFY_DELAY_MS 20UL

#ifndef STATUS_REQUEST_NOT_ACCEPTED
/* 中文说明：旧 WDK 头缺失时补齐策略拒绝状态码，用于 preflight 拒绝。 */
#define STATUS_REQUEST_NOT_ACCEPTED ((NTSTATUS)0xC00000D0L)
#endif

#ifndef STATUS_DRIVER_BLOCKED_CRITICAL
/* 中文说明：旧 WDK 头缺失时补齐核心驱动拒绝状态码。 */
#define STATUS_DRIVER_BLOCKED_CRITICAL ((NTSTATUS)0xC000036BL)
#endif

#ifndef THREAD_ALL_ACCESS
/* 中文说明：旧 WDK 头缺失时补齐线程全访问掩码，供 PsCreateSystemThread 使用。 */
#define THREAD_ALL_ACCESS 0x001FFFFFUL
#endif

#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION 0x0040UL // 中文说明：公开线程查询访问位，旧 WDK 未定义时补齐。
#endif

#ifndef DIRECTORY_QUERY
/* 中文说明：部分 WDK 头不暴露目录对象访问位，按 NT 定义补齐 DIRECTORY_QUERY。 */
#define DIRECTORY_QUERY 0x0001
#endif

#ifndef STATUS_NO_MORE_ENTRIES
/* 中文说明：ZwQueryDirectoryObject 扫描结束时常返回该 warning status。 */
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif

#ifndef STATUS_IMAGE_ALREADY_LOADED
/* 中文说明：旧 WDK 头缺失时补齐“镜像仍在 loader list 中”的失败状态。 */
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xC000010EL)
#endif

/* 中文说明：ZwQueryDirectoryObject 返回的单条对象目录信息布局。 */
typedef struct _KSW_OBJECT_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} KSW_OBJECT_DIRECTORY_INFORMATION, *PKSW_OBJECT_DIRECTORY_INFORMATION;

/* 中文说明：命名 DriverObject 引用入口，和 driver_object_query.c 保持同一策略。 */
NTSYSAPI
NTSTATUS
NTAPI
ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName,
    _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE PassedAccessState,
    _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType,
    _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext,
    _Out_ PVOID* Object
    );

/* 中文说明：IoDriverObjectType 用于 ObReferenceObjectByName 的类型约束。 */
extern POBJECT_TYPE* IoDriverObjectType;

/* 中文说明：ObMakeTemporaryObject 让命名对象在引用计数归零后可被对象管理器回收。 */
NTSYSAPI
VOID
NTAPI
ObMakeTemporaryObject(
    _In_ PVOID Object
    );

/* 中文说明：优先使用 Windows 自己的 I/O 管理器卸载路径，而不是只手工调用 DriverUnload。 */
NTSYSAPI
NTSTATUS
NTAPI
ZwUnloadDriver(
    _In_ PUNICODE_STRING DriverServiceName
    );

/* 中文说明：打开 NT 对象目录，用于按 ServiceKeyName 兜底查找 DriverObject。 */
NTSYSAPI
NTSTATUS
NTAPI
ZwOpenDirectoryObject(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

/* 中文说明：枚举 NT 对象目录项，参考 SKT64 目录扫描思路但使用公开 Zw 接口。 */
NTSYSAPI
NTSTATUS
NTAPI
ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
    );

/* 中文说明：查询系统模块表，用于验证回调函数地址属于目标模块。 */
NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

/* 中文说明：动态解析 PsGetNextProcess，供强卸载 preflight 只读扫描线程驻留证据。 */
typedef PEPROCESS(NTAPI* KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_FN)(
    _In_opt_ PEPROCESS Process
    );

/* 中文说明：动态解析 PsGetNextProcessThread，供强卸载 preflight 只读扫描线程驻留证据。 */
typedef PETHREAD(NTAPI* KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_THREAD_FN)(
    _In_ PEPROCESS Process,
    _In_opt_ PETHREAD Thread
    );

/* 中文说明：卸载线程上下文由父线程和工作线程共同持有，最后一个引用负责释放。 */
typedef struct _KSW_DRIVER_UNLOAD_CONTEXT
{
    volatile LONG ReferenceCount;
    PDRIVER_OBJECT DriverObject;
    ULONG Flags;
    NTSTATUS UnloadStatus;
    NTSTATUS CleanupStatus;
    PDRIVER_UNLOAD DriverUnload;
    ULONG DeletedDeviceCount;
    ULONG DetachedDeviceCount;
    ULONG ThreadCandidates;
    ULONG ThreadsTerminated;
    ULONG ThreadFailures;
    NTSTATUS ThreadLastStatus;
    ULONG CallbackCandidates;
    ULONG CallbacksRemoved;
    ULONG CallbackFailures;
    NTSTATUS CallbackLastStatus;
    ULONG CleanupFlagsApplied;
    BOOLEAN AttemptDirectUnload;
    ULONGLONG DriverStart;
    ULONGLONG DriverEnd;
    WCHAR ServiceRegistryPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS];
} KSW_DRIVER_UNLOAD_CONTEXT, *PKSW_DRIVER_UNLOAD_CONTEXT;

/* 中文说明：保存 DriverObject 入口点和设备标志，使卸载前强拆失败时可以回滚。 */
typedef struct _KSW_DRIVER_UNLOAD_ENTRY_TRANSACTION
{
    PFAST_IO_DISPATCH OriginalFastIoDispatch;
    PDRIVER_DISPATCH OriginalMajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1UL];
    PDEVICE_OBJECT DeviceObjects[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG OriginalDeviceFlags[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG DeviceCount;
    BOOLEAN Applied;
} KSW_DRIVER_UNLOAD_ENTRY_TRANSACTION, *PKSW_DRIVER_UNLOAD_ENTRY_TRANSACTION;

/* 中文说明：DriverObject 强拆阶段的目标镜像驻留线程处理结果。 */
typedef struct _KSW_DRIVER_UNLOAD_THREAD_CLEANUP_RESULT
{
    ULONG Candidates;
    ULONG Terminated;
    ULONG Failures;
    NTSTATUS LastStatus;
} KSW_DRIVER_UNLOAD_THREAD_CLEANUP_RESULT, *PKSW_DRIVER_UNLOAD_THREAD_CLEANUP_RESULT;

/* 中文说明：ZwUnloadDriver 线程上下文不保存 DriverObject，避免额外对象引用阻塞系统卸载。 */
typedef struct _KSW_DRIVER_UNLOAD_ZW_CONTEXT
{
    volatile LONG ReferenceCount;
    NTSTATUS UnloadStatus;
    WCHAR ServiceRegistryPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS];
} KSW_DRIVER_UNLOAD_ZW_CONTEXT, *PKSW_DRIVER_UNLOAD_ZW_CONTEXT;
static VOID
KswordARKDriverUnloadReleaseContext(
    _Inout_ PKSW_DRIVER_UNLOAD_CONTEXT Context
    )
{
    if (Context != NULL &&
        InterlockedDecrement(&Context->ReferenceCount) == 0L) {
        ExFreePoolWithTag(Context, KSW_DRIVER_UNLOAD_TAG);
    }
}

static VOID
KswordARKDriverUnloadReleaseZwContext(
    _Inout_ PKSW_DRIVER_UNLOAD_ZW_CONTEXT Context
    )
{
    if (Context != NULL &&
        InterlockedDecrement(&Context->ReferenceCount) == 0L) {
        ExFreePoolWithTag(Context, KSW_DRIVER_UNLOAD_TAG);
    }
}

/* 中文说明：ZwQuerySystemInformation(SystemModuleInformation) 的单项布局。 */
typedef struct _KSW_DRIVER_UNLOAD_SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} KSW_DRIVER_UNLOAD_SYSTEM_MODULE_ENTRY, *PKSW_DRIVER_UNLOAD_SYSTEM_MODULE_ENTRY;

/* 中文说明：系统模块表头，Modules 为变长数组首元素。 */
typedef struct _KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION
{
    ULONG NumberOfModules;
    KSW_DRIVER_UNLOAD_SYSTEM_MODULE_ENTRY Modules[1];
} KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION, *PKSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION;

/* 中文说明：强力清理回调的聚合计数，最终回填到 R3 响应。 */
typedef struct _KSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT
{
    ULONG Candidates;
    ULONG Removed;
    ULONG Failures;
    NTSTATUS LastStatus;
} KSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT, *PKSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT;

/* 中文说明：强卸载 preflight 的目标模块回调驻留证据，不直接改写回调表。 */
typedef struct _KSW_DRIVER_UNLOAD_CALLBACK_EVIDENCE_RESULT
{
    ULONG Enumerated;
    ULONG Matched;
    ULONG Removable;
    ULONG NonRemovable;
    NTSTATUS LastStatus;
    BOOLEAN Truncated;
} KSW_DRIVER_UNLOAD_CALLBACK_EVIDENCE_RESULT, *PKSW_DRIVER_UNLOAD_CALLBACK_EVIDENCE_RESULT;

/* 中文说明：loader 链和镜像 PE 头的只读一致性证据，不执行摘链或擦头。 */
typedef struct _KSW_DRIVER_UNLOAD_LOADER_IMAGE_EVIDENCE
{
    NTSTATUS LoaderLinkStatus;
    NTSTATUS ImageHeaderStatus;
    ULONG ImageHeaderSizeOfImage;
    ULONG ImageNtHeaderOffset;
    BOOLEAN LoaderLinkChecked;
    BOOLEAN LoaderLinkMismatch;
    BOOLEAN ImageHeaderChecked;
    BOOLEAN InvalidImageHeader;
} KSW_DRIVER_UNLOAD_LOADER_IMAGE_EVIDENCE, *PKSW_DRIVER_UNLOAD_LOADER_IMAGE_EVIDENCE;

/* 中文说明：卸载前预检结果，所有字段只用于决定是否允许执行破坏性步骤。 */
typedef struct _KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT
{
    BOOLEAN AllowZwUnload;
    BOOLEAN AllowDirectUnload;
    BOOLEAN AllowDestructiveCleanup;
    BOOLEAN HasServiceRegistryPath;
    BOOLEAN HasDriverUnload;
    BOOLEAN HasValidDynData;
    BOOLEAN HasPdbBackedDynData;
    BOOLEAN HasValidDriverObjectOffsets;
    BOOLEAN HasValidLoaderEvidence;
    BOOLEAN HasDeviceChain;
    BOOLEAN HasCrossDriverAttach;
    BOOLEAN HasDeviceLoop;
    BOOLEAN HasAttachedDevice;
    BOOLEAN HasBusyDeviceReference;
    BOOLEAN HasThreadScan;
    BOOLEAN HasModuleResidentThreads;
    BOOLEAN HasCallbackScan;
    BOOLEAN HasModuleCallbacks;
    BOOLEAN HasNonRemovableModuleCallbacks;
    BOOLEAN HasLoaderLinkCheck;
    BOOLEAN HasLoaderLinkMismatch;
    BOOLEAN HasImageHeaderCheck;
    BOOLEAN HasInvalidImageHeader;
    BOOLEAN IsCoreKernelModule;
    BOOLEAN IsSelfModule;
    ULONGLONG DriverStart;
    ULONGLONG DriverEnd;
    ULONGLONG LoaderEntryAddress;
    ULONGLONG LoaderDllBase;
    ULONG LoaderSizeOfImage;
    ULONG ScannedProcessCount;
    ULONG ScannedThreadCount;
    ULONG ModuleResidentThreadCount;
    NTSTATUS ThreadScanStatus;
    ULONG CallbackEnumeratedCount;
    ULONG ModuleCallbackCount;
    ULONG RemovableModuleCallbackCount;
    ULONG NonRemovableModuleCallbackCount;
    NTSTATUS CallbackScanStatus;
    NTSTATUS LoaderLinkStatus;
    NTSTATUS ImageHeaderStatus;
    ULONG ImageHeaderSizeOfImage;
    ULONG ImageNtHeaderOffset;
    NTSTATUS Status;
    WCHAR ServiceRegistryPath[KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS];
} KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT, *PKSW_DRIVER_UNLOAD_PREFLIGHT_RESULT;

/* 中文说明：DynData 快照和设备访问表在嵌套证据扫描期间统一放入非分页池。 */
typedef struct _KSW_DRIVER_UNLOAD_PREFLIGHT_WORKSPACE
{
    KSW_DYN_STATE DynState;
    PDEVICE_OBJECT VisitedDevices[KSW_DRIVER_UNLOAD_PREFLIGHT_DEVICE_LIMIT];
} KSW_DRIVER_UNLOAD_PREFLIGHT_WORKSPACE, *PKSW_DRIVER_UNLOAD_PREFLIGHT_WORKSPACE;

/* 中文说明：把内部 preflight 结果压缩成 handler 可打印的诊断快照。 */
static VOID
KswordARKDriverUnloadCapturePreflightDiagnostics(
    _Out_ KSW_DRIVER_UNLOAD_DIAGNOSTICS* Diagnostics,
    _In_ const KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Preflight
    )
{
    if (Diagnostics == NULL || Preflight == NULL) {
        return;
    }

    Diagnostics->preflightStatus = Preflight->Status;
    Diagnostics->allowZwUnload = Preflight->AllowZwUnload;
    Diagnostics->allowDirectUnload = Preflight->AllowDirectUnload;
    Diagnostics->allowDestructiveCleanup = Preflight->AllowDestructiveCleanup;
    Diagnostics->hasServiceRegistryPath = Preflight->HasServiceRegistryPath;
    Diagnostics->hasDriverUnload = Preflight->HasDriverUnload;
    Diagnostics->hasValidDynData = Preflight->HasValidDynData;
    Diagnostics->hasPdbBackedDynData = Preflight->HasPdbBackedDynData;
    Diagnostics->hasValidDriverObjectOffsets = Preflight->HasValidDriverObjectOffsets;
    Diagnostics->hasValidLoaderEvidence = Preflight->HasValidLoaderEvidence;
    Diagnostics->hasDeviceChain = Preflight->HasDeviceChain;
    Diagnostics->hasCrossDriverAttach = Preflight->HasCrossDriverAttach;
    Diagnostics->hasDeviceLoop = Preflight->HasDeviceLoop;
    Diagnostics->hasAttachedDevice = Preflight->HasAttachedDevice;
    Diagnostics->hasBusyDeviceReference = Preflight->HasBusyDeviceReference;
    Diagnostics->hasThreadScan = Preflight->HasThreadScan;
    Diagnostics->hasModuleResidentThreads = Preflight->HasModuleResidentThreads;
    Diagnostics->hasCallbackScan = Preflight->HasCallbackScan;
    Diagnostics->hasModuleCallbacks = Preflight->HasModuleCallbacks;
    Diagnostics->hasNonRemovableModuleCallbacks = Preflight->HasNonRemovableModuleCallbacks;
    Diagnostics->hasLoaderLinkCheck = Preflight->HasLoaderLinkCheck;
    Diagnostics->hasLoaderLinkMismatch = Preflight->HasLoaderLinkMismatch;
    Diagnostics->hasImageHeaderCheck = Preflight->HasImageHeaderCheck;
    Diagnostics->hasInvalidImageHeader = Preflight->HasInvalidImageHeader;
    Diagnostics->isCoreKernelModule = Preflight->IsCoreKernelModule;
    Diagnostics->isSelfModule = Preflight->IsSelfModule;
    Diagnostics->driverStart = Preflight->DriverStart;
    Diagnostics->loaderEntryAddress = Preflight->LoaderEntryAddress;
    Diagnostics->loaderDllBase = Preflight->LoaderDllBase;
    Diagnostics->loaderSizeOfImage = Preflight->LoaderSizeOfImage;
    Diagnostics->scannedProcessCount = Preflight->ScannedProcessCount;
    Diagnostics->scannedThreadCount = Preflight->ScannedThreadCount;
    Diagnostics->moduleResidentThreadCount = Preflight->ModuleResidentThreadCount;
    Diagnostics->threadScanStatus = Preflight->ThreadScanStatus;
    Diagnostics->callbackEnumeratedCount = Preflight->CallbackEnumeratedCount;
    Diagnostics->moduleCallbackCount = Preflight->ModuleCallbackCount;
    Diagnostics->removableModuleCallbackCount = Preflight->RemovableModuleCallbackCount;
    Diagnostics->nonRemovableModuleCallbackCount = Preflight->NonRemovableModuleCallbackCount;
    Diagnostics->callbackScanStatus = Preflight->CallbackScanStatus;
    Diagnostics->loaderLinkStatus = Preflight->LoaderLinkStatus;
    Diagnostics->imageHeaderStatus = Preflight->ImageHeaderStatus;
    Diagnostics->imageHeaderSizeOfImage = Preflight->ImageHeaderSizeOfImage;
    Diagnostics->imageNtHeaderOffset = Preflight->ImageNtHeaderOffset;
}

/* 中文说明：进程 Ex notify 函数签名，供批量移除时调用公开 Ps* 移除 API。 */
typedef VOID
(*KSW_DRIVER_UNLOAD_PROCESS_NOTIFY_EX)(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

/* 中文说明：线程 notify 函数签名，供 PsRemoveCreateThreadNotifyRoutine 使用。 */
typedef VOID
(*KSW_DRIVER_UNLOAD_THREAD_NOTIFY)(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

/* 中文说明：镜像加载 notify 函数签名，供 PsRemoveLoadImageNotifyRoutine 使用。 */
typedef VOID
(*KSW_DRIVER_UNLOAD_IMAGE_NOTIFY)(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

/* 中文说明：ASCII 范围宽字符大写化，只用于 NT 对象目录名和服务名比较。 */
static WCHAR
KswordARKDriverUnloadUpcaseAscii(
    _In_ WCHAR Character
    )
{
    if (Character >= L'a' && Character <= L'z') {
        return (WCHAR)(Character - L'a' + L'A');
    }
    return Character;
}

/* 中文说明：比较两个 NUL 结尾宽字符串前缀，忽略 ASCII 大小写。 */
static BOOLEAN
KswordARKDriverUnloadStartsWithInsensitive(
    _In_z_ const WCHAR* Text,
    _In_z_ const WCHAR* Prefix
    )
{
    ULONG index = 0UL;

    // 输入：两个 NUL 结尾字符串；处理：逐字符 ASCII 大小写归一化。
    // 返回：Text 带 Prefix 前缀时为 TRUE；任一参数为空或字符不匹配时为 FALSE。
    if (Text == NULL || Prefix == NULL) {
        return FALSE;
    }

    while (Prefix[index] != L'\0') {
        if (KswordARKDriverUnloadUpcaseAscii(Text[index]) !=
            KswordARKDriverUnloadUpcaseAscii(Prefix[index])) {
            return FALSE;
        }
        ++index;
    }

    return TRUE;
}

/* 中文说明：比较有限长 ANSI 文件名是否以指定后缀结尾，大小写不敏感。 */
static BOOLEAN
KswordARKDriverUnloadAnsiEndsWithInsensitive(
    _In_reads_bytes_(TextBytes) const UCHAR* Text,
    _In_ ULONG TextBytes,
    _In_z_ PCSTR Suffix
    )
{
    ULONG textChars = 0UL;
    ULONG suffixChars = 0UL;
    ULONG index = 0UL;

    // 输入：SystemModuleInformation 中的有限长 ANSI 文件名和 NUL 结尾后缀。
    // 处理：先计算实际长度，再从尾部逐字符 ASCII 小写比较。
    // 返回：Text 以后缀结尾时 TRUE；输入无效、长度不足或不匹配时 FALSE。
    if (Text == NULL || TextBytes == 0UL || Suffix == NULL) {
        return FALSE;
    }
    while (textChars < TextBytes && Text[textChars] != '\0') {
        ++textChars;
    }
    while (Suffix[suffixChars] != '\0') {
        ++suffixChars;
    }
    if (suffixChars == 0UL || textChars < suffixChars) {
        return FALSE;
    }
    for (index = 0UL; index < suffixChars; ++index) {
        CHAR left = (CHAR)Text[textChars - suffixChars + index];
        CHAR right = Suffix[index];
        if (left >= 'A' && left <= 'Z') {
            left = (CHAR)(left + ('a' - 'A'));
        }
        if (right >= 'A' && right <= 'Z') {
            right = (CHAR)(right + ('a' - 'A'));
        }
        if (left != right) {
            return FALSE;
        }
    }
    return TRUE;
}

/* 中文说明：判断 NT 对象路径是否带指定前缀，比较过程大小写不敏感。 */
static BOOLEAN
KswordARKDriverUnloadNameHasPrefix(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ObjectName,
    _In_z_ const WCHAR* Prefix
    )
{
    ULONG index = 0UL;

    if (ObjectName == NULL || Prefix == NULL) {
        return FALSE;
    }

    while (Prefix[index] != L'\0') {
        WCHAR left = KswordARKDriverUnloadUpcaseAscii(ObjectName[index]);
        WCHAR right = KswordARKDriverUnloadUpcaseAscii(Prefix[index]);

        if (left != right) {
            return FALSE;
        }
        ++index;
    }

    return TRUE;
}

/* 中文说明：从 \Driver\X 或 \FileSystem\Filters\X 中提取最后一级对象名。 */
static NTSTATUS
KswordARKDriverUnloadExtractLeafName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ObjectName,
    _Out_writes_(LeafChars) PWCHAR LeafName,
    _In_ ULONG LeafChars
    )
{
    ULONG index = 0UL;
    ULONG leafStart = 0UL;

    if (ObjectName == NULL || LeafName == NULL || LeafChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    LeafName[0] = L'\0';
    while (index < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS &&
        ObjectName[index] != L'\0') {
        if (ObjectName[index] == L'\\') {
            leafStart = index + 1UL;
        }
        ++index;
    }
    if (index == 0UL || leafStart >= index) {
        return STATUS_INVALID_PARAMETER;
    }

    return RtlStringCchCopyW(LeafName, LeafChars, ObjectName + leafStart);
}

/* 中文说明：计算固定 NUL 结尾 WCHAR 字符串长度，最多检查协议允许长度。 */
static ULONG
KswordARKDriverUnloadCountFixedStringChars(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* Text
    )
{
    ULONG chars = 0UL;

    if (Text == NULL) {
        return 0UL;
    }

    while (chars < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS &&
        Text[chars] != L'\0') {
        ++chars;
    }
    return chars;
}

/* 中文说明：把 UNICODE_STRING 安全复制为 NUL 结尾固定缓冲。 */
static NTSTATUS
KswordARKDriverUnloadCopyUnicodeToFixed(
    _In_opt_ PCUNICODE_STRING SourceName,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
{
    ULONG charsToCopy = 0UL;

    // 输入：内核 UNICODE_STRING 和固定输出缓冲。
    // 处理：按 Length 限定复制，不要求 SourceName 自身 NUL 结尾。
    // 返回：成功复制返回 STATUS_SUCCESS；无来源或缓冲无效返回参数错误。
    if (SourceName == NULL ||
        SourceName->Buffer == NULL ||
        SourceName->Length == 0 ||
        Destination == NULL ||
        DestinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    charsToCopy = (ULONG)(SourceName->Length / sizeof(WCHAR));
    if (charsToCopy == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (charsToCopy >= DestinationChars) {
        charsToCopy = DestinationChars - 1UL;
    }

    RtlCopyMemory(Destination, SourceName->Buffer, (SIZE_T)charsToCopy * sizeof(WCHAR));
    Destination[charsToCopy] = L'\0';
    return STATUS_SUCCESS;
}

/* 中文说明：前置声明，供注册表路径构造逻辑复用最后一级对象名提取。 */
static NTSTATUS
KswordARKDriverUnloadExtractLeafName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ObjectName,
    _Out_writes_(LeafChars) PWCHAR LeafName,
    _In_ ULONG LeafChars
    );

/* 中文说明：由 DriverObject/ServiceKeyName 推导 ZwUnloadDriver 需要的服务注册表路径。 */
static NTSTATUS
KswordARKDriverUnloadBuildServiceRegistryPath(
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* NormalizedDriverName,
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars
    )
{
    WCHAR serviceName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    // 输入：已引用 DriverObject 和规范化对象名。
    // 处理：优先使用 DriverExtension->ServiceKeyName；如果已经是注册表绝对路径则原样使用；
    //      否则按服务名拼到 HKLM\SYSTEM\CurrentControlSet\Services。
    // 返回：输出完整 NT 注册表路径，失败时返回对应 NTSTATUS。
    if (Destination == NULL || DestinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    Destination[0] = L'\0';

    __try {
        if (DriverObject != NULL && DriverObject->DriverExtension != NULL) {
            status = KswordARKDriverUnloadCopyUnicodeToFixed(
                &DriverObject->DriverExtension->ServiceKeyName,
                serviceName,
                RTL_NUMBER_OF(serviceName));
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status) || serviceName[0] == L'\0') {
        if (NormalizedDriverName != NULL &&
            NT_SUCCESS(KswordARKDriverUnloadExtractLeafName(
                NormalizedDriverName,
                serviceName,
                RTL_NUMBER_OF(serviceName)))) {
            status = STATUS_SUCCESS;
        }
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    if (KswordARKDriverUnloadStartsWithInsensitive(
        serviceName,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\")) {
        return RtlStringCchCopyW(Destination, DestinationChars, serviceName);
    }
    if (KswordARKDriverUnloadStartsWithInsensitive(serviceName, L"System\\CurrentControlSet\\Services\\")) {
        return RtlStringCchPrintfW(
            Destination,
            DestinationChars,
            L"\\Registry\\Machine\\%ws",
            serviceName);
    }
    if (KswordARKDriverUnloadStartsWithInsensitive(serviceName, L"\\System\\CurrentControlSet\\Services\\")) {
        return RtlStringCchPrintfW(
            Destination,
            DestinationChars,
            L"\\Registry\\Machine%ws",
            serviceName);
    }

    return RtlStringCchPrintfW(
        Destination,
        DestinationChars,
        L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%ws",
        serviceName);
}

/* 中文说明：比较 UNICODE_STRING 的最后一级名称和固定字符串，忽略 ASCII 大小写。 */
static BOOLEAN
KswordARKDriverUnloadUnicodeLeafEqualsFixed(
    _In_opt_ PCUNICODE_STRING SourceName,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ExpectedLeaf
    )
{
    ULONG sourceChars = 0UL;
    ULONG expectedChars = 0UL;
    ULONG leafStart = 0UL;
    ULONG leafChars = 0UL;
    ULONG index = 0UL;

    if (SourceName == NULL ||
        SourceName->Buffer == NULL ||
        SourceName->Length == 0 ||
        ExpectedLeaf == NULL) {
        return FALSE;
    }

    sourceChars = (ULONG)(SourceName->Length / sizeof(WCHAR));
    expectedChars = KswordARKDriverUnloadCountFixedStringChars(ExpectedLeaf);
    if (sourceChars == 0UL || expectedChars == 0UL ||
        expectedChars >= KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) {
        return FALSE;
    }

    for (index = 0UL; index < sourceChars; ++index) {
        if (SourceName->Buffer[index] == L'\\') {
            leafStart = index + 1UL;
        }
    }
    if (leafStart >= sourceChars) {
        return FALSE;
    }

    leafChars = sourceChars - leafStart;
    if (leafChars != expectedChars) {
        return FALSE;
    }

    for (index = 0UL; index < expectedChars; ++index) {
        WCHAR left = KswordARKDriverUnloadUpcaseAscii(SourceName->Buffer[leafStart + index]);
        WCHAR right = KswordARKDriverUnloadUpcaseAscii(ExpectedLeaf[index]);

        if (left != right) {
            return FALSE;
        }
    }

    return TRUE;
}

/* 中文说明：判断一个已引用 DriverObject 是否属于指定服务名。 */
static BOOLEAN
KswordARKDriverUnloadDriverObjectMatchesServiceLeaf(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ServiceLeaf
    )
{
    BOOLEAN matches = FALSE;

    if (DriverObject == NULL || ServiceLeaf == NULL) {
        return FALSE;
    }

    __try {
        if (DriverObject->DriverExtension != NULL &&
            KswordARKDriverUnloadUnicodeLeafEqualsFixed(
                &DriverObject->DriverExtension->ServiceKeyName,
                ServiceLeaf)) {
            matches = TRUE;
        }
        else if (KswordARKDriverUnloadUnicodeLeafEqualsFixed(
            &DriverObject->DriverName,
            ServiceLeaf)) {
            matches = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        matches = FALSE;
    }

    return matches;
}

/* 中文说明：把共享协议中的名称复制为完整 DriverObject 对象路径。 */
static NTSTATUS
KswordARKDriverUnloadBuildObjectName(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* SourceName,
    _Out_writes_(DestinationChars) PWCHAR DestinationName,
    _In_ ULONG DestinationChars
    )
{
    ULONG inputChars = 0UL;
    NTSTATUS status = STATUS_SUCCESS;

    if (SourceName == NULL || DestinationName == NULL || DestinationChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    DestinationName[0] = L'\0';

    while (inputChars < KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS &&
        SourceName[inputChars] != L'\0') {
        ++inputChars;
    }
    if (inputChars == 0UL || inputChars >= KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) {
        return STATUS_INVALID_PARAMETER;
    }

    if (SourceName[0] == L'\\') {
        /*
         * 中文说明：R3 手工输入完整对象路径时保持原样，支持 \Driver\X、
         * \FileSystem\X 以及 \FileSystem\Filters\X 等真实 DriverObject 名称。
         */
        status = RtlStringCchCopyNW(
            DestinationName,
            DestinationChars,
            SourceName,
            inputChars);
    }
    else {
        status = RtlStringCchPrintfW(
            DestinationName,
            DestinationChars,
            L"\\Driver\\%ws",
            SourceName);
    }

    return status;
}

/* 中文说明：打开一个对象目录，失败时返回底层 NTSTATUS。 */
static NTSTATUS
KswordARKDriverUnloadOpenDirectory(
    _In_z_ const WCHAR* DirectoryName,
    _Out_ HANDLE* DirectoryHandleOut
    )
{
    UNICODE_STRING directoryName;
    OBJECT_ATTRIBUTES objectAttributes;

    if (DirectoryName == NULL || DirectoryHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DirectoryHandleOut = NULL;
    RtlInitUnicodeString(&directoryName, DirectoryName);
    InitializeObjectAttributes(
        &objectAttributes,
        &directoryName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL);

    return ZwOpenDirectoryObject(
        DirectoryHandleOut,
        DIRECTORY_QUERY,
        &objectAttributes);
}

/* 中文说明：尝试引用一个完整 DriverObject 对象路径，成功时返回已引用对象。 */
static NTSTATUS
KswordARKDriverUnloadReferenceCandidateName(
    _In_z_ const WCHAR* CandidateName,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR NormalizedNameOut,
    _In_ ULONG NameChars
    )
{
    UNICODE_STRING objectName;
    NTSTATUS status = STATUS_SUCCESS;

    if (CandidateName == NULL ||
        DriverObjectOut == NULL ||
        NormalizedNameOut == NULL ||
        NameChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriverObjectOut = NULL;
    status = RtlStringCchCopyW(NormalizedNameOut, NameChars, CandidateName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&objectName, NormalizedNameOut);
    /* 中文说明：ObReferenceObjectByName 返回对象引用而不是句柄，不能带 OBJ_KERNEL_HANDLE。 */
    status = ObReferenceObjectByName(
        &objectName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        *IoDriverObjectType,
        KernelMode,
        NULL,
        (PVOID*)DriverObjectOut);
    if (!NT_SUCCESS(status)) {
        *DriverObjectOut = NULL;
    }
    return status;
}

/* 中文说明：拼接“目录路径 + 子对象名”为完整候选 DriverObject 路径。 */
static NTSTATUS
KswordARKDriverUnloadBuildDirectoryCandidateName(
    _In_z_ const WCHAR* DirectoryName,
    _In_ PCUNICODE_STRING EntryName,
    _Out_writes_(CandidateChars) PWCHAR CandidateName,
    _In_ ULONG CandidateChars
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG directoryChars = 0UL;

    if (DirectoryName == NULL ||
        EntryName == NULL ||
        EntryName->Buffer == NULL ||
        EntryName->Length == 0 ||
        CandidateName == NULL ||
        CandidateChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    CandidateName[0] = L'\0';
    status = RtlStringCchCopyW(CandidateName, CandidateChars, DirectoryName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    directoryChars = KswordARKDriverUnloadCountFixedStringChars(CandidateName);
    if (directoryChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (CandidateName[directoryChars - 1UL] != L'\\') {
        status = RtlStringCchCatW(CandidateName, CandidateChars, L"\\");
        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    return RtlStringCchCatNW(
        CandidateName,
        CandidateChars,
        EntryName->Buffer,
        (size_t)(EntryName->Length / sizeof(WCHAR)));
}

/* 中文说明：在一个对象目录中按 ServiceKeyName/DriverName 兜底查找 DriverObject。 */
static NTSTATUS
KswordARKDriverUnloadReferenceByServiceLeafInDirectory(
    _In_z_ const WCHAR* DirectoryName,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ServiceLeaf,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR NormalizedNameOut,
    _In_ ULONG NameChars
    )
{
    HANDLE directoryHandle = NULL;
    PKSW_OBJECT_DIRECTORY_INFORMATION entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS finalStatus = STATUS_OBJECT_NAME_NOT_FOUND;

    if (DirectoryName == NULL ||
        ServiceLeaf == NULL ||
        DriverObjectOut == NULL ||
        NormalizedNameOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriverObjectOut = NULL;
    status = KswordARKDriverUnloadOpenDirectory(DirectoryName, &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    entry = (PKSW_OBJECT_DIRECTORY_INFORMATION)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (scannedEntries < KSW_DRIVER_UNLOAD_DIRECTORY_MAX_ENTRIES) {
        WCHAR candidateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        PDRIVER_OBJECT candidateObject = NULL;
        NTSTATUS candidateStatus = STATUS_SUCCESS;

        RtlZeroMemory(entry, KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
            TRUE,
            restartScan,
            &queryContext,
            &returnLength);
        restartScan = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            finalStatus = STATUS_OBJECT_NAME_NOT_FOUND;
            break;
        }
        if (!NT_SUCCESS(status)) {
            finalStatus = status;
            break;
        }

        ++scannedEntries;
        if (entry->Name.Buffer == NULL || entry->Name.Length == 0) {
            continue;
        }

        candidateStatus = KswordARKDriverUnloadBuildDirectoryCandidateName(
            DirectoryName,
            &entry->Name,
            candidateName,
            RTL_NUMBER_OF(candidateName));
        if (!NT_SUCCESS(candidateStatus)) {
            finalStatus = candidateStatus;
            continue;
        }

        candidateStatus = KswordARKDriverUnloadReferenceCandidateName(
            candidateName,
            &candidateObject,
            NormalizedNameOut,
            NameChars);
        if (!NT_SUCCESS(candidateStatus)) {
            if (candidateStatus != STATUS_OBJECT_TYPE_MISMATCH) {
                finalStatus = candidateStatus;
            }
            continue;
        }

        if (KswordARKDriverUnloadDriverObjectMatchesServiceLeaf(candidateObject, ServiceLeaf)) {
            *DriverObjectOut = candidateObject;
            ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
            ZwClose(directoryHandle);
            return STATUS_SUCCESS;
        }

        ObDereferenceObject(candidateObject);
    }

    ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ZwClose(directoryHandle);
    return finalStatus;
}

/* 中文说明：参考 SKT64 遍历对象目录的思路，用 ServiceKeyName 处理名称不一致的驱动。 */
static NTSTATUS
KswordARKDriverUnloadReferenceByServiceLeaf(
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* ServiceLeaf,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR NormalizedNameOut,
    _In_ ULONG NameChars
    )
{
    static const WCHAR* const directoriesToScan[] = {
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters"
    };
    ULONG directoryIndex = 0UL;
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;

    if (ServiceLeaf == NULL || DriverObjectOut == NULL || NormalizedNameOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriverObjectOut = NULL;
    for (directoryIndex = 0UL;
        directoryIndex < RTL_NUMBER_OF(directoriesToScan);
        ++directoryIndex) {
        NTSTATUS scanStatus = KswordARKDriverUnloadReferenceByServiceLeafInDirectory(
            directoriesToScan[directoryIndex],
            ServiceLeaf,
            DriverObjectOut,
            NormalizedNameOut,
            NameChars);

        if (NT_SUCCESS(scanStatus)) {
            return STATUS_SUCCESS;
        }
        if (scanStatus != STATUS_OBJECT_NAME_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_PATH_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_TYPE_MISMATCH) {
            status = scanStatus;
        }
    }

    return status;
}

/* 中文说明：判断 DriverObject 的镜像基址是否等于模块表中的基址。 */
static BOOLEAN
KswordARKDriverUnloadDriverObjectMatchesModuleBase(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONGLONG TargetModuleBase
    )
{
    BOOLEAN matches = FALSE;

    if (DriverObject == NULL || TargetModuleBase == 0ULL) {
        return FALSE;
    }

    __try {
        if ((ULONGLONG)(ULONG_PTR)DriverObject->DriverStart == TargetModuleBase) {
            matches = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        matches = FALSE;
    }

    return matches;
}

/* 中文说明：在一个对象目录中按模块基址反查 DriverObject。 */
static NTSTATUS
KswordARKDriverUnloadReferenceByModuleBaseInDirectory(
    _In_z_ const WCHAR* DirectoryName,
    _In_ ULONGLONG TargetModuleBase,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR NormalizedNameOut,
    _In_ ULONG NameChars
    )
{
    HANDLE directoryHandle = NULL;
    PKSW_OBJECT_DIRECTORY_INFORMATION entry = NULL;
    ULONG queryContext = 0UL;
    ULONG returnLength = 0UL;
    ULONG scannedEntries = 0UL;
    BOOLEAN restartScan = TRUE;
    BOOLEAN scanComplete = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS finalStatus = STATUS_OBJECT_NAME_NOT_FOUND;
    PDRIVER_OBJECT matchedObject = NULL;
    WCHAR matchedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };

    if (DirectoryName == NULL ||
        TargetModuleBase == 0ULL ||
        DriverObjectOut == NULL ||
        NormalizedNameOut == NULL ||
        NameChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriverObjectOut = NULL;
    status = KswordARKDriverUnloadOpenDirectory(DirectoryName, &directoryHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    entry = (PKSW_OBJECT_DIRECTORY_INFORMATION)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (entry == NULL) {
        ZwClose(directoryHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    while (scannedEntries < KSW_DRIVER_UNLOAD_DIRECTORY_MAX_ENTRIES) {
        WCHAR candidateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        WCHAR candidateNormalizedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        PDRIVER_OBJECT candidateObject = NULL;
        NTSTATUS candidateStatus = STATUS_SUCCESS;

        RtlZeroMemory(entry, KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES);
        status = ZwQueryDirectoryObject(
            directoryHandle,
            entry,
            KSW_DRIVER_UNLOAD_DIRECTORY_QUERY_BYTES,
            TRUE,
            restartScan,
            &queryContext,
            &returnLength);
        restartScan = FALSE;
        if (status == STATUS_NO_MORE_ENTRIES) {
            /* 中文说明：完整扫描结束后才能证明模块基址在本目录中唯一。 */
            scanComplete = TRUE;
            break;
        }
        if (!NT_SUCCESS(status)) {
            /* 中文说明：目录扫描中断时不能把已找到的首个对象当成唯一身份。 */
            finalStatus = status;
            break;
        }

        ++scannedEntries;
        if (entry->Name.Buffer == NULL || entry->Name.Length == 0) {
            continue;
        }

        candidateStatus = KswordARKDriverUnloadBuildDirectoryCandidateName(
            DirectoryName,
            &entry->Name,
            candidateName,
            RTL_NUMBER_OF(candidateName));
        if (!NT_SUCCESS(candidateStatus)) {
            finalStatus = candidateStatus;
            continue;
        }

        candidateStatus = KswordARKDriverUnloadReferenceCandidateName(
            candidateName,
            &candidateObject,
            candidateNormalizedName,
            RTL_NUMBER_OF(candidateNormalizedName));
        if (!NT_SUCCESS(candidateStatus)) {
            if (candidateStatus != STATUS_OBJECT_TYPE_MISMATCH) {
                finalStatus = candidateStatus;
            }
            continue;
        }

        if (KswordARKDriverUnloadDriverObjectMatchesModuleBase(candidateObject, TargetModuleBase)) {
            /* 中文说明：第二个同基址 DriverObject 使模块基址身份产生歧义。 */
            if (matchedObject != NULL) {
                /* 中文说明：释放第二个候选引用，不把任一对象交给调用方。 */
                ObDereferenceObject(candidateObject);
                /* 中文说明：释放先前保留的首个匹配引用。 */
                ObDereferenceObject(matchedObject);
                /* 中文说明：清空本地指针避免公共清理路径重复释放。 */
                matchedObject = NULL;
                /* 中文说明：用稳定碰撞状态拒绝不唯一身份。 */
                finalStatus = STATUS_OBJECT_NAME_COLLISION;
                /* 中文说明：无需继续扫描，本目录已经证明歧义。 */
                break;
            }

            /* 中文说明：暂存首个匹配并继续完整扫描以证明唯一性。 */
            matchedObject = candidateObject;
            /* 中文说明：只保存真正匹配项的规范对象名。 */
            (VOID)RtlStringCchCopyW(
                matchedName,
                RTL_NUMBER_OF(matchedName),
                candidateNormalizedName);
            /* 中文说明：对象引用已转移给 matchedObject，禁止落入普通释放。 */
            candidateObject = NULL;
            /* 中文说明：继续枚举本目录中的其它对象。 */
            continue;
        }

        ObDereferenceObject(candidateObject);
    }

    /* 中文说明：达到固定扫描上限时不能证明唯一，按失败关闭。 */
    if (!scanComplete &&
        finalStatus == STATUS_OBJECT_NAME_NOT_FOUND) {
        /* 中文说明：保留明确上限状态供调用方诊断。 */
        finalStatus = STATUS_BUFFER_OVERFLOW;
    }
    /* 中文说明：只有完整扫描且恰有一个匹配时才发布引用。 */
    if (scanComplete &&
        matchedObject != NULL &&
        finalStatus == STATUS_OBJECT_NAME_NOT_FOUND) {
        /* 中文说明：把唯一引用的所有权转移给调用方。 */
        *DriverObjectOut = matchedObject;
        /* 中文说明：输出唯一匹配的规范对象名。 */
        (VOID)RtlStringCchCopyW(
            NormalizedNameOut,
            NameChars,
            matchedName);
        /* 中文说明：释放临时目录查询缓冲。 */
        ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        /* 中文说明：关闭本次对象目录句柄。 */
        ZwClose(directoryHandle);
        /* 中文说明：本目录中的模块基址身份唯一。 */
        return STATUS_SUCCESS;
    }
    /* 中文说明：扫描失败、碰撞或未完成时释放暂存的首个引用。 */
    if (matchedObject != NULL) {
        /* 中文说明：失败路径不向调用方泄露对象引用。 */
        ObDereferenceObject(matchedObject);
    }
    ExFreePoolWithTag(entry, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ZwClose(directoryHandle);
    return finalStatus;
}

/* 中文说明：按模块基址扫描对象目录，供强卸载和通信阻断功能共享精确 DriverObject 身份。 */
NTSTATUS
KswordARKDriverReferenceObjectByModuleBase(
    _In_ ULONGLONG TargetModuleBase,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR NormalizedNameOut,
    _In_ ULONG NameChars
    )
{
    static const WCHAR* const directoriesToScan[] = {
        L"\\Driver",
        L"\\FileSystem",
        L"\\FileSystem\\Filters"
    };
    ULONG directoryIndex = 0UL;
    NTSTATUS status = STATUS_OBJECT_NAME_NOT_FOUND;
    PDRIVER_OBJECT matchedObject = NULL;
    WCHAR matchedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };

    if (TargetModuleBase == 0ULL ||
        DriverObjectOut == NULL ||
        NormalizedNameOut == NULL ||
        NameChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    *DriverObjectOut = NULL;
    /* 中文说明：失败路径不保留上一次调用者缓冲中的对象名。 */
    NormalizedNameOut[0] = L'\0';
    for (directoryIndex = 0UL;
        directoryIndex < RTL_NUMBER_OF(directoriesToScan);
        ++directoryIndex) {
        PDRIVER_OBJECT directoryMatch = NULL;
        WCHAR directoryMatchName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
        NTSTATUS scanStatus = KswordARKDriverUnloadReferenceByModuleBaseInDirectory(
            directoriesToScan[directoryIndex],
            TargetModuleBase,
            &directoryMatch,
            directoryMatchName,
            RTL_NUMBER_OF(directoryMatchName));

        if (NT_SUCCESS(scanStatus)) {
            /* 中文说明：跨目录第二个同基址对象同样构成身份歧义。 */
            if (matchedObject != NULL) {
                /* 中文说明：释放当前目录返回的唯一匹配引用。 */
                ObDereferenceObject(directoryMatch);
                /* 中文说明：释放先前目录保留的匹配引用。 */
                ObDereferenceObject(matchedObject);
                /* 中文说明：不向调用方返回任一歧义对象。 */
                return STATUS_OBJECT_NAME_COLLISION;
            }

            /* 中文说明：保留首个目录匹配并继续扫描其它允许目录。 */
            matchedObject = directoryMatch;
            /* 中文说明：保存首个匹配的规范对象名。 */
            (VOID)RtlStringCchCopyW(
                matchedName,
                RTL_NUMBER_OF(matchedName),
                directoryMatchName);
            /* 中文说明：标记已经找到候选但尚未证明跨目录唯一。 */
            status = STATUS_SUCCESS;
            /* 中文说明：继续下一允许目录。 */
            continue;
        }
        /* 中文说明：目录内部已经发现同基址碰撞时立即失败。 */
        if (scanStatus == STATUS_OBJECT_NAME_COLLISION) {
            /* 中文说明：释放先前目录可能保留的唯一匹配。 */
            if (matchedObject != NULL) {
                /* 中文说明：碰撞路径不保留引用。 */
                ObDereferenceObject(matchedObject);
            }
            /* 中文说明：把稳定碰撞状态返回所有调用者。 */
            return scanStatus;
        }
        if (scanStatus != STATUS_OBJECT_NAME_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_PATH_NOT_FOUND &&
            scanStatus != STATUS_OBJECT_TYPE_MISMATCH) {
            /* 中文说明：若已找到匹配但其它目录扫描失败，也不能证明唯一。 */
            if (matchedObject != NULL) {
                /* 中文说明：释放尚未发布的唯一候选引用。 */
                ObDereferenceObject(matchedObject);
                /* 中文说明：清空本地指针避免后续误发布。 */
                matchedObject = NULL;
            }
            /* 中文说明：任一目录无法完整扫描时都不能证明跨目录唯一。 */
            return scanStatus;
        }
    }

    /* 中文说明：三个允许目录完整扫描后发布唯一匹配。 */
    if (matchedObject != NULL && NT_SUCCESS(status)) {
        /* 中文说明：把唯一 DriverObject 引用交给调用方。 */
        *DriverObjectOut = matchedObject;
        /* 中文说明：回填唯一对象的规范目录名。 */
        (VOID)RtlStringCchCopyW(
            NormalizedNameOut,
            NameChars,
            matchedName);
        /* 中文说明：模块基址在所有允许目录中唯一。 */
        return STATUS_SUCCESS;
    }
    /* 中文说明：失败状态不会留下未发布引用。 */
    return status;
}

/* 中文说明：只有对象名/路径未找到时才尝试其它目录，避免掩盖权限或参数错误。 */
static BOOLEAN
KswordARKDriverUnloadShouldTryAlternateName(
    _In_ NTSTATUS Status
    )
{
    return (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
        Status == STATUS_OBJECT_PATH_NOT_FOUND ||
        Status == STATUS_NOT_FOUND) ? TRUE : FALSE;
}

/* 中文说明：按对象名引用 DriverObject，不接受 R3 传入地址。 */
static NTSTATUS
KswordARKDriverUnloadReferenceByName(
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* Request,
    _Outptr_ PDRIVER_OBJECT* DriverObjectOut,
    _Out_writes_(NameChars) PWCHAR NormalizedNameOut,
    _In_ ULONG NameChars
    )
{
    WCHAR firstCandidate[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR leafName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    WCHAR alternateName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    if (Request == NULL || DriverObjectOut == NULL || NormalizedNameOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DriverObjectOut = NULL;
    NormalizedNameOut[0] = L'\0';

    if ((Request->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT) != 0UL &&
        Request->targetModuleBase != 0ULL) {
        status = KswordARKDriverReferenceObjectByModuleBase(
            Request->targetModuleBase,
            DriverObjectOut,
            NormalizedNameOut,
            NameChars);
        if (NT_SUCCESS(status) || !KswordARKDriverUnloadShouldTryAlternateName(status)) {
            return status;
        }
    }

    status = KswordARKDriverUnloadBuildObjectName(
        Request->driverName,
        firstCandidate,
        RTL_NUMBER_OF(firstCandidate));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKDriverUnloadReferenceCandidateName(
        firstCandidate,
        DriverObjectOut,
        NormalizedNameOut,
        NameChars);
    if (NT_SUCCESS(status) || !KswordARKDriverUnloadShouldTryAlternateName(status)) {
        return status;
    }

    /*
     * 中文说明：SCM 服务名不总是等于 DriverObject 的 \Driver\ 名称。
     * 文件系统和 mini-filter 常见对象目录是 \FileSystem\ 或
     * \FileSystem\Filters\，因此在“对象未找到”时按最后一级名称兜底。
     */
    if (!NT_SUCCESS(KswordARKDriverUnloadExtractLeafName(
        firstCandidate,
        leafName,
        RTL_NUMBER_OF(leafName)))) {
        return status;
    }

    if (!KswordARKDriverUnloadNameHasPrefix(firstCandidate, L"\\FileSystem\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\FileSystem\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = KswordARKDriverUnloadReferenceCandidateName(
                alternateName,
                DriverObjectOut,
                NormalizedNameOut,
                NameChars);
            if (NT_SUCCESS(alternateStatus) ||
                !KswordARKDriverUnloadShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    if (!KswordARKDriverUnloadNameHasPrefix(firstCandidate, L"\\FileSystem\\Filters\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\FileSystem\\Filters\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = KswordARKDriverUnloadReferenceCandidateName(
                alternateName,
                DriverObjectOut,
                NormalizedNameOut,
                NameChars);
            if (NT_SUCCESS(alternateStatus) ||
                !KswordARKDriverUnloadShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    if (!KswordARKDriverUnloadNameHasPrefix(firstCandidate, L"\\Driver\\")) {
        NTSTATUS alternateStatus = RtlStringCchPrintfW(
            alternateName,
            RTL_NUMBER_OF(alternateName),
            L"\\Driver\\%ws",
            leafName);
        if (NT_SUCCESS(alternateStatus)) {
            alternateStatus = KswordARKDriverUnloadReferenceCandidateName(
                alternateName,
                DriverObjectOut,
                NormalizedNameOut,
                NameChars);
            if (NT_SUCCESS(alternateStatus) ||
                !KswordARKDriverUnloadShouldTryAlternateName(alternateStatus)) {
                return alternateStatus;
            }
            status = alternateStatus;
        }
    }

    status = KswordARKDriverUnloadReferenceByServiceLeaf(
        leafName,
        DriverObjectOut,
        NormalizedNameOut,
        NameChars);
    if (NT_SUCCESS(status) || !KswordARKDriverUnloadShouldTryAlternateName(status)) {
        return status;
    }

    return status;
}

/* 中文说明：判断回调枚举行是否可以由公开/受控路径尝试移除。 */
static BOOLEAN
KswordARKDriverUnloadCallbackEntryIsRemovable(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry
    )
{
    if (Entry == NULL) {
        return FALSE;
    }
    if ((Entry->fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) == 0UL) {
        return FALSE;
    }
    if (Entry->callbackAddress == 0ULL) {
        return FALSE;
    }

    switch (Entry->callbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return TRUE;
    default:
        return FALSE;
    }
}

/* 中文说明：把枚举回调类别转换成移除 IOCTL 使用的类别值。 */
static ULONG
KswordARKDriverUnloadCallbackClassToRemoveType(
    _In_ ULONG CallbackClass
    )
{
    switch (CallbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
    default:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    }
}

/* 中文说明：构建系统模块快照，用于把回调地址严格归属到目标模块。 */
static NTSTATUS
KswordARKDriverUnloadBuildModuleSnapshot(
    _Outptr_result_bytebuffer_(*BufferBytesOut) KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION** ModuleInfoOut,
    _Out_ ULONG* BufferBytesOut
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;

    if (ModuleInfoOut == NULL || BufferBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ModuleInfoOut = NULL;
    *BufferBytesOut = 0UL;

    status = ZwQuerySystemInformation(
        KSW_DRIVER_UNLOAD_SYSTEM_MODULE_CLASS,
        NULL,
        0UL,
        &requiredBytes);
    if (requiredBytes == 0UL) {
        return NT_SUCCESS(status) ? STATUS_NOT_FOUND : status;
    }

#pragma warning(push)
#pragma warning(disable:4996)
    moduleInfo = (KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        requiredBytes,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(
        KSW_DRIVER_UNLOAD_SYSTEM_MODULE_CLASS,
        moduleInfo,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        return status;
    }

    *ModuleInfoOut = moduleInfo;
    *BufferBytesOut = requiredBytes;
    return STATUS_SUCCESS;
}

/* 中文说明：判断某个地址是否落入指定模块基址对应的镜像范围。 */
static BOOLEAN
KswordARKDriverUnloadAddressBelongsToModuleBase(
    _In_opt_ const KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONGLONG Address,
    _In_ ULONGLONG TargetModuleBase
    )
{
    ULONG moduleIndex = 0UL;

    if (ModuleInfo == NULL || Address == 0ULL || TargetModuleBase == 0ULL) {
        return FALSE;
    }

    for (moduleIndex = 0UL; moduleIndex < ModuleInfo->NumberOfModules; ++moduleIndex) {
        const KSW_DRIVER_UNLOAD_SYSTEM_MODULE_ENTRY* moduleEntry = &ModuleInfo->Modules[moduleIndex];
        const ULONGLONG moduleBase = (ULONGLONG)(ULONG_PTR)moduleEntry->ImageBase;
        const ULONGLONG moduleEnd = moduleBase + (ULONGLONG)moduleEntry->ImageSize;

        if (moduleBase != TargetModuleBase) {
            continue;
        }
        if (Address >= moduleBase && Address < moduleEnd) {
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

/* 中文说明：判断枚举行是否属于目标模块；非函数地址类必须已有 moduleBase 字段。 */
static BOOLEAN
KswordARKDriverUnloadCallbackEntryMatchesModuleBase(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry,
    _In_opt_ const KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION* ModuleInfo,
    _In_ ULONGLONG TargetModuleBase
    )
{
    if (Entry == NULL || TargetModuleBase == 0ULL) {
        return FALSE;
    }
    if ((Entry->fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE) != 0UL &&
        Entry->moduleBase == TargetModuleBase) {
        return TRUE;
    }
    if ((Entry->fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0UL) {
        return FALSE;
    }
    return KswordARKDriverUnloadAddressBelongsToModuleBase(
        ModuleInfo,
        Entry->callbackAddress,
        TargetModuleBase);
}

/* 中文说明：调用单条外部回调移除路径，并把状态聚合到结果计数。 */
static VOID
KswordARKDriverUnloadRemoveOneCallbackEntry(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry,
    _Inout_ KSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT* CleanupResult
    )
{
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST removeRequest;
    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE removeResponse;
    NTSTATUS removeStatus = STATUS_SUCCESS;

    if (Entry == NULL || CleanupResult == NULL) {
        return;
    }

    RtlZeroMemory(&removeRequest, sizeof(removeRequest));
    RtlZeroMemory(&removeResponse, sizeof(removeResponse));
    removeRequest.size = sizeof(removeRequest);
    removeRequest.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    removeRequest.callbackClass = KswordARKDriverUnloadCallbackClassToRemoveType(Entry->callbackClass);
    removeRequest.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
    removeRequest.callbackAddress = Entry->callbackAddress;
    removeResponse.size = sizeof(removeResponse);
    removeResponse.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
    removeResponse.callbackClass = removeRequest.callbackClass;
    removeResponse.callbackAddress = removeRequest.callbackAddress;

    switch (removeRequest.callbackClass) {
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS:
        removeStatus = PsSetCreateProcessNotifyRoutineEx(
            (KSW_DRIVER_UNLOAD_PROCESS_NOTIFY_EX)(ULONG_PTR)removeRequest.callbackAddress,
            TRUE);
        if (removeStatus == STATUS_PROCEDURE_NOT_FOUND || removeStatus == STATUS_INVALID_PARAMETER) {
            removeStatus = PsSetCreateProcessNotifyRoutine(
                (PCREATE_PROCESS_NOTIFY_ROUTINE)(ULONG_PTR)removeRequest.callbackAddress,
                TRUE);
        }
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD:
        removeStatus = PsRemoveCreateThreadNotifyRoutine(
            (KSW_DRIVER_UNLOAD_THREAD_NOTIFY)(ULONG_PTR)removeRequest.callbackAddress);
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE:
        removeStatus = PsRemoveLoadImageNotifyRoutine(
            (KSW_DRIVER_UNLOAD_IMAGE_NOTIFY)(ULONG_PTR)removeRequest.callbackAddress);
        break;

    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT:
    case KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER:
        removeStatus = KswordArkCallbackExternalRemoveByRequest(
            &removeRequest,
            &removeResponse);
        break;

    default:
        removeStatus = STATUS_INVALID_PARAMETER;
        break;
    }

    if (NT_SUCCESS(removeStatus)) {
        CleanupResult->Removed += 1UL;
    }
    else {
        CleanupResult->Failures += 1UL;
        CleanupResult->LastStatus = removeStatus;
    }
}

/* 中文说明：按模块基址只读统计残留回调，作为是否允许强拆的证据。 */
static NTSTATUS
KswordARKDriverUnloadInspectCallbacksByModuleBase(
    _In_ ULONGLONG TargetModuleBase,
    _Out_ KSW_DRIVER_UNLOAD_CALLBACK_EVIDENCE_RESULT* EvidenceResult
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG responseBytes = 0UL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE* enumResponse = NULL;
    ULONG entryIndex = 0UL;
    ULONG parsedEntries = 0UL;

    /*
     * 输入：目标驱动模块基址和证据输出结构。
     * 处理：复用现有回调枚举路径建立只读快照，按 moduleBase 或回调地址范围
     *      判断归属目标模块，并区分可由受控 API 移除与不可安全移除的条目。
     * 返回：基础枚举成功返回 STATUS_SUCCESS；内存/模块快照失败返回具体状态。
     */
    if (EvidenceResult == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(EvidenceResult, sizeof(*EvidenceResult));
    EvidenceResult->LastStatus = STATUS_SUCCESS;
    if (TargetModuleBase == 0ULL) {
        EvidenceResult->LastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKDriverUnloadBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status)) {
        EvidenceResult->LastStatus = status;
        return status;
    }

    responseBytes = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) +
        ((KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT - 1UL) * sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
#pragma warning(push)
#pragma warning(disable:4996)
    enumResponse = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        responseBytes,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (enumResponse == NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        EvidenceResult->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(enumResponse, responseBytes);
    enumResponse->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE);
    enumResponse->version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
    enumResponse->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
    enumResponse->lastStatus = STATUS_SUCCESS;

    {
        KSWORD_ARK_CALLBACK_ENUM_BUILDER builder;

        RtlZeroMemory(&builder, sizeof(builder));
        builder.Entries = enumResponse->entries;
        builder.EntryCapacity = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
        builder.LastStatus = STATUS_SUCCESS;
        KswordArkCallbackEnumSnapshotBegin(&builder);
        KswordArkCallbackEnumAddMinifilters(&builder);
        KswordArkCallbackEnumAddPrivateCallbacks(&builder);
        KswordArkCallbackExternalAddCallbacks(&builder);
        KswordArkCallbackEnumSnapshotFinalize(&builder);
        enumResponse->totalCount = builder.TotalCount;
        enumResponse->returnedCount = builder.ReturnedCount;
        enumResponse->flags = builder.Flags;
        enumResponse->lastStatus = builder.LastStatus;
        enumResponse->enumerationGeneration = builder.SnapshotHash;
        enumResponse->snapshotHash = builder.SnapshotHash;
    }

    parsedEntries = enumResponse->returnedCount;
    if (parsedEntries > KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT) {
        parsedEntries = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
    }
    EvidenceResult->Enumerated = parsedEntries;
    EvidenceResult->Truncated =
        (enumResponse->totalCount > enumResponse->returnedCount) ? TRUE : FALSE;
    EvidenceResult->LastStatus = enumResponse->lastStatus;

    for (entryIndex = 0UL; entryIndex < parsedEntries; ++entryIndex) {
        const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = &enumResponse->entries[entryIndex];

        if (!KswordARKDriverUnloadCallbackEntryMatchesModuleBase(
            entry,
            moduleInfo,
            TargetModuleBase)) {
            continue;
        }

        EvidenceResult->Matched += 1UL;
        if (KswordARKDriverUnloadCallbackEntryIsRemovable(entry)) {
            EvidenceResult->Removable += 1UL;
        }
        else {
            EvidenceResult->NonRemovable += 1UL;
        }
    }

    ExFreePoolWithTag(enumResponse, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    return STATUS_SUCCESS;
}

/* 中文说明：按模块基址枚举并移除可验证回调，避免目标残留模块继续靠回调运行。 */
static NTSTATUS
KswordARKDriverUnloadRemoveCallbacksByModuleBase(
    _In_ ULONGLONG TargetModuleBase,
    _Out_ KSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT* CleanupResult
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    KSW_DRIVER_UNLOAD_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    ULONG responseBytes = 0UL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE* enumResponse = NULL;
    ULONG entryIndex = 0UL;
    ULONG parsedEntries = 0UL;

    if (CleanupResult == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(CleanupResult, sizeof(*CleanupResult));
    CleanupResult->LastStatus = STATUS_SUCCESS;
    if (TargetModuleBase == 0ULL) {
        CleanupResult->LastStatus = STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }

    status = KswordARKDriverUnloadBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (!NT_SUCCESS(status)) {
        CleanupResult->LastStatus = status;
        return status;
    }

    responseBytes = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) +
        ((KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT - 1UL) * sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
#pragma warning(push)
#pragma warning(disable:4996)
    enumResponse = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        responseBytes,
        KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
#pragma warning(pop)
    if (enumResponse == NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
        CleanupResult->LastStatus = STATUS_INSUFFICIENT_RESOURCES;
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(enumResponse, responseBytes);
    enumResponse->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE);
    enumResponse->version = KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION;
    enumResponse->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
    enumResponse->lastStatus = STATUS_SUCCESS;

    {
        KSWORD_ARK_CALLBACK_ENUM_BUILDER builder;

        RtlZeroMemory(&builder, sizeof(builder));
        builder.Entries = enumResponse->entries;
        builder.EntryCapacity = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
        builder.LastStatus = STATUS_SUCCESS;
        KswordArkCallbackEnumSnapshotBegin(&builder);
        KswordArkCallbackEnumAddMinifilters(&builder);
        KswordArkCallbackEnumAddPrivateCallbacks(&builder);
        KswordArkCallbackExternalAddCallbacks(&builder);
        KswordArkCallbackEnumSnapshotFinalize(&builder);
        enumResponse->totalCount = builder.TotalCount;
        enumResponse->returnedCount = builder.ReturnedCount;
        enumResponse->flags = builder.Flags;
        enumResponse->lastStatus = builder.LastStatus;
        enumResponse->enumerationGeneration = builder.SnapshotHash;
        enumResponse->snapshotHash = builder.SnapshotHash;
    }

    parsedEntries = enumResponse->returnedCount;
    if (parsedEntries > KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT) {
        parsedEntries = KSW_DRIVER_UNLOAD_MAX_CALLBACK_CLEANUP_COUNT;
    }

    for (entryIndex = 0UL; entryIndex < parsedEntries; ++entryIndex) {
        const KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = &enumResponse->entries[entryIndex];

        if (!KswordARKDriverUnloadCallbackEntryIsRemovable(entry)) {
            continue;
        }
        if (!KswordARKDriverUnloadCallbackEntryMatchesModuleBase(
            entry,
            moduleInfo,
            TargetModuleBase)) {
            continue;
        }
        CleanupResult->Candidates += 1UL;
        KswordARKDriverUnloadRemoveOneCallbackEntry(entry, CleanupResult);
    }

    ExFreePoolWithTag(enumResponse, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    ExFreePoolWithTag(moduleInfo, KSW_DRIVER_UNLOAD_DIRECTORY_TAG);
    return CleanupResult->Failures == 0UL ? STATUS_SUCCESS : CleanupResult->LastStatus;
}

/* 中文说明：强制卸载后用于中和目标 DriverObject 的拒绝 IRP stub。 */
static NTSTATUS
KswordARKDriverUnloadRejectedDispatch(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    // 输入：系统分发到已被强制中和 DriverObject 的设备对象和 IRP。
    // 处理：不访问目标驱动私有扩展，只把 IRP 以 STATUS_DELETE_PENDING 完成。
    // 返回：STATUS_DELETE_PENDING，提示调用方设备正在删除/不可用。
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Irp != NULL) {
        Irp->IoStatus.Status = STATUS_DELETE_PENDING;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }
    return STATUS_DELETE_PENDING;
}

/* 中文说明：可选中和 dispatch 表，和 SKT64 的 force unload 语义对齐但由 flag 控制。 */
static VOID
KswordARKDriverUnloadClearDispatchUnsafe(
    _Inout_ PDRIVER_OBJECT DriverObject
    )
{
    if (DriverObject == NULL) {
        return;
    }

    __try {
        ULONG majorIndex = 0UL;
        DriverObject->FastIoDispatch = NULL;
        for (majorIndex = 0UL; majorIndex <= IRP_MJ_MAXIMUM_FUNCTION; ++majorIndex) {
            DriverObject->MajorFunction[majorIndex] = KswordARKDriverUnloadRejectedDispatch;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        (VOID)0;
    }
}

/* 中文说明：只读快照 DriverObject 入口点和设备对象标志，并引用设备对象保活。 */
static NTSTATUS
KswordARKDriverUnloadSnapshotEntryTransaction(
    _In_ PDRIVER_OBJECT DriverObject,
    _Out_ KSW_DRIVER_UNLOAD_ENTRY_TRANSACTION* Transaction
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG actualDeviceCount = 0UL;
    ULONG majorIndex = 0UL;
    ULONG deviceIndex = 0UL;

    /*
     * 输入：已引用目标 DriverObject 和空事务结构。
     * 处理：先通过公开 IoEnumerateDeviceObjectList 获取带引用的设备快照，再读取
     *      FastIo、全部 MajorFunction 和设备原始 Flags；本函数不修改目标对象。
     * 返回：完整快照成功时 STATUS_SUCCESS；容量、对象归属或访问失败时返回错误。
     */
    if (DriverObject == NULL || Transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Transaction, sizeof(*Transaction));

    status = IoEnumerateDeviceObjectList(
        DriverObject,
        Transaction->DeviceObjects,
        sizeof(Transaction->DeviceObjects),
        &actualDeviceCount);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (actualDeviceCount > KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
        for (deviceIndex = 0UL;
             deviceIndex < KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT;
             ++deviceIndex) {
            if (Transaction->DeviceObjects[deviceIndex] != NULL) {
                ObDereferenceObject(Transaction->DeviceObjects[deviceIndex]);
                Transaction->DeviceObjects[deviceIndex] = NULL;
            }
        }
        return STATUS_BUFFER_OVERFLOW;
    }
    Transaction->DeviceCount = actualDeviceCount;

    __try {
        Transaction->OriginalFastIoDispatch = DriverObject->FastIoDispatch;
        for (majorIndex = 0UL;
             majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
             ++majorIndex) {
            Transaction->OriginalMajorFunction[majorIndex] =
                DriverObject->MajorFunction[majorIndex];
        }
        for (deviceIndex = 0UL;
             deviceIndex < Transaction->DeviceCount;
             ++deviceIndex) {
            if (Transaction->DeviceObjects[deviceIndex] == NULL ||
                Transaction->DeviceObjects[deviceIndex]->DriverObject != DriverObject) {
                status = STATUS_OBJECT_TYPE_MISMATCH;
                break;
            }
            Transaction->OriginalDeviceFlags[deviceIndex] =
                Transaction->DeviceObjects[deviceIndex]->Flags;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (!NT_SUCCESS(status)) {
        for (deviceIndex = 0UL;
             deviceIndex < Transaction->DeviceCount;
             ++deviceIndex) {
            if (Transaction->DeviceObjects[deviceIndex] != NULL) {
                ObDereferenceObject(Transaction->DeviceObjects[deviceIndex]);
                Transaction->DeviceObjects[deviceIndex] = NULL;
            }
        }
        Transaction->DeviceCount = 0UL;
    }
    return status;
}

/* 中文说明：在完整事务快照存在时原子中和 dispatch 并阻断新设备打开。 */
static NTSTATUS
KswordARKDriverUnloadApplyEntryTransaction(
    _Inout_ PDRIVER_OBJECT DriverObject,
    _Inout_ KSW_DRIVER_UNLOAD_ENTRY_TRANSACTION* Transaction
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /*
     * 输入：目标 DriverObject 和已成功建立的入口点事务快照。
     * 处理：标记事务已应用，再设置拒绝 dispatch、清空 FastIo 并为快照设备设置
     *      DO_DEVICE_INITIALIZING；异常由调用方统一执行回滚。
     * 返回：全部写入成功时 STATUS_SUCCESS；异常时返回异常 NTSTATUS。
     */
    if (DriverObject == NULL || Transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    Transaction->Applied = TRUE;
    __try {
        ULONG majorIndex = 0UL;
        ULONG deviceIndex = 0UL;

        DriverObject->FastIoDispatch = NULL;
        for (majorIndex = 0UL;
             majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
             ++majorIndex) {
            DriverObject->MajorFunction[majorIndex] =
                KswordARKDriverUnloadRejectedDispatch;
        }
        for (deviceIndex = 0UL;
             deviceIndex < Transaction->DeviceCount;
             ++deviceIndex) {
            (VOID)InterlockedOr(
                (volatile LONG*)&Transaction->DeviceObjects[deviceIndex]->Flags,
                (LONG)DO_DEVICE_INITIALIZING);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

/* 中文说明：恢复入口点事务保存的 FastIo、MajorFunction 和设备初始化标志位。 */
static NTSTATUS
KswordARKDriverUnloadRollbackEntryTransaction(
    _Inout_ PDRIVER_OBJECT DriverObject,
    _Inout_ KSW_DRIVER_UNLOAD_ENTRY_TRANSACTION* Transaction
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    /*
     * 输入：仍被引用的目标 DriverObject 和此前应用过的事务快照。
     * 处理：仅在 Applied=TRUE 时恢复全部可逆入口字段及原始初始化标志位；
     *      其它并发更新的设备 Flags 保持不变，避免回滚覆盖目标驱动新状态。
     * 返回：恢复成功时 STATUS_SUCCESS；写回异常时返回异常 NTSTATUS。
     */
    if (DriverObject == NULL || Transaction == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!Transaction->Applied) {
        return STATUS_SUCCESS;
    }

    __try {
        ULONG majorIndex = 0UL;
        ULONG deviceIndex = 0UL;

        DriverObject->FastIoDispatch = Transaction->OriginalFastIoDispatch;
        for (majorIndex = 0UL;
             majorIndex <= IRP_MJ_MAXIMUM_FUNCTION;
             ++majorIndex) {
            DriverObject->MajorFunction[majorIndex] =
                Transaction->OriginalMajorFunction[majorIndex];
        }
        for (deviceIndex = 0UL;
             deviceIndex < Transaction->DeviceCount;
             ++deviceIndex) {
            volatile LONG* flagsAddress =
                (volatile LONG*)&Transaction->DeviceObjects[deviceIndex]->Flags;

            if ((Transaction->OriginalDeviceFlags[deviceIndex] & DO_DEVICE_INITIALIZING) != 0UL) {
                (VOID)InterlockedOr(flagsAddress, (LONG)DO_DEVICE_INITIALIZING);
            }
            else {
                (VOID)InterlockedAnd(flagsAddress, (LONG)(~DO_DEVICE_INITIALIZING));
            }
        }
        Transaction->Applied = FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }
    return status;
}

/* 中文说明：释放入口事务持有的设备对象引用，不修改已经提交的目标字段。 */
static VOID
KswordARKDriverUnloadReleaseEntryTransaction(
    _Inout_ KSW_DRIVER_UNLOAD_ENTRY_TRANSACTION* Transaction
    )
{
    ULONG deviceIndex = 0UL;

    /*
     * 输入：成功快照过设备对象的事务。
     * 处理：逐个归还 IoEnumerateDeviceObjectList 增加的对象引用并清空计数。
     * 返回：无；可用于成功提交或回滚完成后的对称清理。
     */
    if (Transaction == NULL) {
        return;
    }
    for (deviceIndex = 0UL;
         deviceIndex < Transaction->DeviceCount;
         ++deviceIndex) {
        if (Transaction->DeviceObjects[deviceIndex] != NULL) {
            ObDereferenceObject(Transaction->DeviceObjects[deviceIndex]);
            Transaction->DeviceObjects[deviceIndex] = NULL;
        }
    }
    Transaction->DeviceCount = 0UL;
}

/* 中文说明：可选清理 DriverUnload 指针，避免右键重复触发同一个卸载入口。 */
static VOID
KswordARKDriverUnloadClearUnloadPointerUnsafe(
    _Inout_ PDRIVER_OBJECT DriverObject
    )
{
    if (DriverObject == NULL) {
        return;
    }

    __try {
        DriverObject->DriverUnload = NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        (VOID)0;
    }
}

/* 中文说明：在删除设备或中和 DriverObject 前，先尽量阻断新的外部打开。 */
static NTSTATUS
KswordARKDriverUnloadBlockNewDeviceCreatesUnsafe(
    _Inout_ PDRIVER_OBJECT DriverObject,
    _Out_opt_ ULONG* BlockedDeviceCountOut
    )
{
    PDEVICE_OBJECT deviceCursor = NULL;
    PDEVICE_OBJECT deviceList[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG deviceCount = 0UL;
    ULONG deviceIndex = 0UL;
    NTSTATUS validationStatus = STATUS_SUCCESS;

    /*
     * 输入：仍被本线程引用的目标 DriverObject，以及可选的阻断计数输出。
     * 处理：先快照并校验 DeviceObject->NextDevice 链，确认无环且每个节点仍属于
     *      同一 DriverObject；随后设置公开的 DO_DEVICE_INITIALIZING 标志，作为
     *      IoLockRemoveDevice 不可用时的 best-effort 访问阻断，不触碰私有 DeviceLock。
     * 返回：链表校验和标记均成功时返回 STATUS_SUCCESS；否则返回具体失败码。
     */
    if (BlockedDeviceCountOut != NULL) {
        *BlockedDeviceCountOut = 0UL;
    }
    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(deviceList, sizeof(deviceList));

    __try {
        deviceCursor = DriverObject->DeviceObject;
        while (deviceCursor != NULL) {
            ULONG previousIndex = 0UL;

            if (deviceCount >= KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
                validationStatus = STATUS_BUFFER_OVERFLOW;
                break;
            }
            for (previousIndex = 0UL; previousIndex < deviceCount; ++previousIndex) {
                if (deviceList[previousIndex] == deviceCursor) {
                    validationStatus = STATUS_INVALID_DEVICE_REQUEST;
                    break;
                }
            }
            if (!NT_SUCCESS(validationStatus)) {
                break;
            }
            if (deviceCursor->DriverObject != DriverObject) {
                validationStatus = STATUS_OBJECT_TYPE_MISMATCH;
                break;
            }

            deviceList[deviceCount] = deviceCursor;
            deviceCount += 1UL;
            deviceCursor = deviceCursor->NextDevice;
        }

        if (!NT_SUCCESS(validationStatus)) {
            return validationStatus;
        }

        for (deviceIndex = 0UL; deviceIndex < deviceCount; ++deviceIndex) {
            (VOID)InterlockedOr(
                (volatile LONG*)&deviceList[deviceIndex]->Flags,
                (LONG)DO_DEVICE_INITIALIZING);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (BlockedDeviceCountOut != NULL) {
        *BlockedDeviceCountOut = deviceCount;
    }
    return STATUS_SUCCESS;
}

/* 中文说明：目标没有 DriverUnload 时，按原始 DeviceObject->NextDevice 链删除设备。 */
static NTSTATUS
KswordARKDriverUnloadDeleteDeviceObjectsUnsafe(
    _Inout_ PDRIVER_OBJECT DriverObject,
    _In_ BOOLEAN DetachDeviceStacks,
    _Out_ ULONG* DeletedDeviceCountOut,
    _Out_ ULONG* DetachedDeviceCountOut
    )
{
    PDEVICE_OBJECT deviceCursor = NULL;
    PDEVICE_OBJECT deviceList[KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT];
    ULONG deviceCount = 0UL;
    ULONG deletedDeviceCount = 0UL;
    ULONG detachedDeviceCount = 0UL;
    NTSTATUS validationStatus = STATUS_SUCCESS;

    if (DeletedDeviceCountOut == NULL || DetachedDeviceCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *DeletedDeviceCountOut = 0UL;
    *DetachedDeviceCountOut = 0UL;

    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(deviceList, sizeof(deviceList));

    /*
     * 中文说明：删除 DeviceObject 无法回滚，因此先完整快照并校验链表。
     * 如果链表过长、成环或混入其它 DriverObject，直接失败，不先删一半。
     */
    __try {
        deviceCursor = DriverObject->DeviceObject;
        while (deviceCursor != NULL) {
            ULONG previousIndex = 0UL;
            PDEVICE_OBJECT nextDevice = NULL;

            if (deviceCount >= KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
                validationStatus = STATUS_BUFFER_OVERFLOW;
                break;
            }
            for (previousIndex = 0UL; previousIndex < deviceCount; ++previousIndex) {
                if (deviceList[previousIndex] == deviceCursor) {
                    validationStatus = STATUS_INVALID_DEVICE_REQUEST;
                    break;
                }
            }
            if (!NT_SUCCESS(validationStatus)) {
                break;
            }
            if (deviceCursor->DriverObject != DriverObject) {
                validationStatus = STATUS_OBJECT_TYPE_MISMATCH;
                break;
            }
            if (!DetachDeviceStacks &&
                (deviceCursor->AttachedDevice != NULL ||
                    deviceCursor->ReferenceCount != 0)) {
                validationStatus = STATUS_DEVICE_BUSY;
                break;
            }

            nextDevice = deviceCursor->NextDevice;
            deviceList[deviceCount] = deviceCursor;
            deviceCount += 1UL;
            deviceCursor = nextDevice;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    if (!NT_SUCCESS(validationStatus)) {
        return validationStatus;
    }

    __try {
        ULONG deleteIndex = 0UL;
        for (deleteIndex = 0UL; deleteIndex < deviceCount; ++deleteIndex) {
            if (DetachDeviceStacks) {
                PDEVICE_OBJECT lowerDevice = NULL;
                ULONG detachGuard = 0UL;

                /*
                 * 先从当前目标设备向上逐层断开，再断开目标设备和下层的关联。
                 * IoDetachDevice 只接受下层 DeviceObject；IoGetLowerDeviceObject
                 * 返回的引用必须在解除关联后释放。
                 */
                while (deviceList[deleteIndex]->AttachedDevice != NULL &&
                    detachGuard < KSW_DRIVER_UNLOAD_MAX_DEVICE_DELETE_COUNT) {
                    IoDetachDevice(deviceList[deleteIndex]);
                    detachedDeviceCount += 1UL;
                    detachGuard += 1UL;
                }
                if (deviceList[deleteIndex]->AttachedDevice != NULL) {
                    *DeletedDeviceCountOut = deletedDeviceCount;
                    *DetachedDeviceCountOut = detachedDeviceCount;
                    return STATUS_BUFFER_OVERFLOW;
                }

                lowerDevice = IoGetLowerDeviceObject(deviceList[deleteIndex]);
                if (lowerDevice != NULL) {
                    IoDetachDevice(lowerDevice);
                    detachedDeviceCount += 1UL;
                    ObDereferenceObject(lowerDevice);
                }
            }
            IoDeleteDevice(deviceList[deleteIndex]);
            deletedDeviceCount += 1UL;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *DeletedDeviceCountOut = deletedDeviceCount;
        *DetachedDeviceCountOut = detachedDeviceCount;
        return GetExceptionCode();
    }

    *DeletedDeviceCountOut = deletedDeviceCount;
    *DetachedDeviceCountOut = detachedDeviceCount;
    return DriverObject->DeviceObject == NULL ? STATUS_SUCCESS : STATUS_DEVICE_BUSY;
}

/* Verify one DeviceObject chain entry is not busy before destructive fallback. */
static NTSTATUS
KswordARKDriverUnloadCheckDeviceObjectIdleUnsafe(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PDEVICE_OBJECT DeviceObject,
    _Out_ PDEVICE_OBJECT* NextDeviceOut
    )
{
    // Inputs: target DriverObject, one DeviceObject from its NextDevice chain, and an output slot.
    // Processing: read owner, next, attached, and ReferenceCount while guarded by SEH.
    // Return: STATUS_SUCCESS when the device can participate in direct unload; otherwise a blocking NTSTATUS.
    if (DriverObject == NULL || DeviceObject == NULL || NextDeviceOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *NextDeviceOut = NULL;
    __try {
        if (DeviceObject->DriverObject != DriverObject) {
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        if (DeviceObject->AttachedDevice != NULL) {
            return STATUS_DEVICE_BUSY;
        }
        if (DeviceObject->ReferenceCount != 0) {
            return STATUS_DEVICE_BUSY;
        }
        *NextDeviceOut = DeviceObject->NextDevice;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }

    return STATUS_SUCCESS;
}

/* 中文说明：检查 DriverUnload 返回后是否已经清空 DeviceObject 链。 */
static NTSTATUS
KswordARKDriverUnloadRequireNoDeviceObjectsUnsafe(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    // 输入：仍被本线程引用的目标 DriverObject。
    // 处理：只读检查 DeviceObject 链首；不遍历、不删除、不修正。
    // 返回：无设备返回 STATUS_SUCCESS；仍有设备返回 STATUS_DEVICE_BUSY；异常透传异常码。
    if (DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    __try {
        return DriverObject->DeviceObject == NULL
            ? STATUS_SUCCESS
            : STATUS_DEVICE_BUSY;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

/* 中文说明：从 DriverObject 基址加 DynData 偏移安全读取一个指针字段。 */
static BOOLEAN
KswordARKDriverUnloadReadPointerFieldByOffset(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG FieldOffset,
    _Out_ PVOID* ValueOut
    )
{
    const UCHAR* fieldAddress = NULL;

    // 输入：已引用 DriverObject、PDB/DynData 字段偏移和输出指针。
    // 处理：拒绝缺失偏移，用 MmCopyMemory 包装函数读取目标字段。
    // 返回：读取成功且完整时 TRUE；任何参数、偏移或内存读取失败时 FALSE。
    if (DriverObject == NULL ||
        ValueOut == NULL ||
        !KswordARKDriverIntegrityOffsetPresent(FieldOffset)) {
        return FALSE;
    }

    *ValueOut = NULL;
    fieldAddress = (const UCHAR*)DriverObject + (SIZE_T)FieldOffset;
    return KswordARKHookReadMemorySafe(fieldAddress, ValueOut, sizeof(*ValueOut));
}

/* 中文说明：从 DriverObject 基址加 DynData 偏移安全读取一个 ULONG 字段。 */
static BOOLEAN
KswordARKDriverUnloadReadUlongFieldByOffset(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG FieldOffset,
    _Out_ ULONG* ValueOut
    )
{
    const UCHAR* fieldAddress = NULL;

    // 输入：已引用 DriverObject、PDB/DynData 字段偏移和输出 ULONG。
    // 处理：拒绝缺失偏移，用 MmCopyMemory 包装函数读取目标字段。
    // 返回：读取成功且完整时 TRUE；任何参数、偏移或内存读取失败时 FALSE。
    if (DriverObject == NULL ||
        ValueOut == NULL ||
        !KswordARKDriverIntegrityOffsetPresent(FieldOffset)) {
        return FALSE;
    }

    *ValueOut = 0UL;
    fieldAddress = (const UCHAR*)DriverObject + (SIZE_T)FieldOffset;
    return KswordARKHookReadMemorySafe(fieldAddress, ValueOut, sizeof(*ValueOut));
}

/* 中文说明：验证 PDB/DynData _DRIVER_OBJECT 偏移和当前 WDK 视图一致。 */
static BOOLEAN
KswordARKDriverUnloadValidateDriverObjectOffsets(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ const KSW_DYN_STATE* DynState
    )
{
    PVOID driverStart = NULL;
    ULONG driverSize = 0UL;
    PVOID driverSection = NULL;
    PVOID driverUnload = NULL;
    PVOID majorFunction = NULL;
    PVOID expectedMajorFunction = NULL;

    // 输入：目标 DriverObject 和已经通过身份匹配的 DynData 快照。
    // 处理：只读读取 PDB profile 给出的关键 _DRIVER_OBJECT 字段，并与当前 WDK 结构访问结果交叉比较。
    // 返回：全部关键字段一致时 TRUE；任一字段缺失、读取失败或不一致时 FALSE。
    if (DriverObject == NULL || DynState == NULL) {
        return FALSE;
    }

    if (!KswordARKDriverUnloadReadPointerFieldByOffset(
            DriverObject,
            DynState->Kernel.DoDriverStart,
            &driverStart) ||
        !KswordARKDriverUnloadReadUlongFieldByOffset(
            DriverObject,
            DynState->Kernel.DoDriverSize,
            &driverSize) ||
        !KswordARKDriverUnloadReadPointerFieldByOffset(
            DriverObject,
            DynState->Kernel.DoDriverSection,
            &driverSection) ||
        !KswordARKDriverUnloadReadPointerFieldByOffset(
            DriverObject,
            DynState->Kernel.DoDriverUnload,
            &driverUnload) ||
        !KswordARKDriverUnloadReadPointerFieldByOffset(
            DriverObject,
            DynState->Kernel.DoMajorFunction,
            &majorFunction)) {
        return FALSE;
    }

    expectedMajorFunction = (PVOID)(ULONG_PTR)DriverObject->MajorFunction[0];
    if (driverStart != DriverObject->DriverStart ||
        driverSize != DriverObject->DriverSize ||
        driverSection != DriverObject->DriverSection ||
        driverUnload != (PVOID)(ULONG_PTR)DriverObject->DriverUnload ||
        majorFunction != expectedMajorFunction) {
        return FALSE;
    }

    return TRUE;
}

/* 中文说明：确认卸载强路径依赖的 DynData 字段来自 PDB 或实时结构校验兜底。 */
static BOOLEAN
KswordARKDriverUnloadDynDataSourceTrusted(
    _In_ ULONG Source
    )
{
    // 输入：一个 DynData 字段来源。
    // 处理：仅接受精确 PDB profile 或经过唯一命中与结构复核的 runtime pattern。
    // 返回：来源可用于强卸载预检时 TRUE；其它来源 FALSE。
    return (Source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE ||
            Source == KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN)
        ? TRUE
        : FALSE;
}

/* 中文说明：保留旧函数名以兼容诊断 ABI，其语义现为“强校验 DynData 可用”。 */
static BOOLEAN
KswordARKDriverUnloadHasPdbBackedDynData(
    _In_ const KSW_DYN_STATE* DynState
    )
{
    // 输入：当前 DynData 快照。
    // 处理：检查强卸载依赖的 _DRIVER_OBJECT、_KLDR_DATA_TABLE_ENTRY 和 PsLoadedModuleList 字段来源。
    // 返回：所有关键字段均来自 PDB 或经过结构复核的 runtime pattern 时 TRUE；否则 FALSE。
    if (DynState == NULL) {
        return FALSE;
    }

    return KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.DoDriverStart) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.DoDriverSize) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.DoDriverSection) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.DoMajorFunction) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.DoDriverUnload) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.KldrInLoadOrderLinks) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.KldrDllBase) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelSources.KldrSizeOfImage) &&
        KswordARKDriverUnloadDynDataSourceTrusted(DynState->KernelGlobalSources.PsLoadedModuleList);
}

/* 中文说明：确认线程入口证据扫描依赖的 ETHREAD 偏移来自可信解析来源。 */
static BOOLEAN
KswordARKDriverUnloadHasPdbBackedThreadDynData(
    _In_ const KSW_DYN_STATE* DynState
    )
{
    /*
     * 输入：当前 DynData 快照。
     * 处理：强制要求 ETHREAD.StartAddress 来自 PDB 或结构校验兜底；
     *      Win32StartAddress 可选，但如果存在也必须是同等级可信来源。
     * 返回：线程扫描可安全使用时 TRUE；缺少/弱来源时 FALSE。
     */
    if (DynState == NULL) {
        return FALSE;
    }
    if (!KswordARKDriverIntegrityOffsetPresent(DynState->Kernel.EtStartAddress) ||
        !KswordARKDriverUnloadDynDataSourceTrusted(
            DynState->KernelSources.EtStartAddress)) {
        return FALSE;
    }
    if (KswordARKDriverIntegrityOffsetPresent(DynState->Kernel.EtWin32StartAddress) &&
        !KswordARKDriverUnloadDynDataSourceTrusted(
            DynState->KernelSources.EtWin32StartAddress)) {
        return FALSE;
    }
    return TRUE;
}

/* 中文说明：动态解析 PsGetNextProcess，失败时返回 NULL 而不是硬依赖导入。 */
static KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_FN
KswordARKDriverUnloadResolvePsGetNextProcess(
    VOID
    )
{
    UNICODE_STRING routineName;

    // 输入：无。
    // 处理：通过 MmGetSystemRoutineAddress 查询公开导出，兼容不同 WDK/系统导出面。
    // 返回：可调用函数指针；系统不支持时返回 NULL。
    RtlInitUnicodeString(&routineName, L"PsGetNextProcess");
    return (KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_FN)MmGetSystemRoutineAddress(&routineName);
}

/* 中文说明：动态解析 PsGetNextProcessThread，失败时返回 NULL 而不是硬依赖导入。 */
static KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_THREAD_FN
KswordARKDriverUnloadResolvePsGetNextProcessThread(
    VOID
    )
{
    UNICODE_STRING routineName;

    // 输入：无。
    // 处理：通过 MmGetSystemRoutineAddress 查询公开导出，只用于只读枚举线程。
    // 返回：可调用函数指针；系统不支持时返回 NULL。
    RtlInitUnicodeString(&routineName, L"PsGetNextProcessThread");
    return (KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_THREAD_FN)MmGetSystemRoutineAddress(&routineName);
}

/* 中文说明：按 DynData 偏移从 ETHREAD 读取 64 位地址字段。 */
static BOOLEAN
KswordARKDriverUnloadReadThreadAddressField(
    _In_ PETHREAD ThreadObject,
    _In_ ULONG FieldOffset,
    _Out_ ULONGLONG* AddressOut
    )
{
    const UCHAR* fieldAddress = NULL;

    // 输入：已引用 ETHREAD、PDB-backed 字段偏移和输出地址槽。
    // 处理：用安全内存读取包装访问 ETHREAD 字段，不直接信任指针可读性。
    // 返回：完整读取到地址时 TRUE；参数无效、偏移缺失或读取失败时 FALSE。
    if (ThreadObject == NULL ||
        AddressOut == NULL ||
        !KswordARKDriverIntegrityOffsetPresent(FieldOffset)) {
        return FALSE;
    }

    *AddressOut = 0ULL;
    fieldAddress = (const UCHAR*)ThreadObject + (SIZE_T)FieldOffset;
    return KswordARKHookReadMemorySafe(fieldAddress, AddressOut, sizeof(*AddressOut));
}

/* 中文说明：判断线程入口地址是否落在目标驱动镜像范围内。 */
static BOOLEAN
KswordARKDriverUnloadAddressInImageRange(
    _In_ ULONGLONG Address,
    _In_ ULONGLONG ImageStart,
    _In_ ULONGLONG ImageEnd
    )
{
    // 输入：待判断地址和 [ImageStart, ImageEnd) 半开区间。
    // 处理：只做整数范围判断，调用方保证范围来自 loader/DriverObject 交叉证据。
    // 返回：地址落在目标模块镜像内时 TRUE，否则 FALSE。
    if (Address == 0ULL || ImageStart == 0ULL || ImageEnd <= ImageStart) {
        return FALSE;
    }
    return (Address >= ImageStart && Address < ImageEnd) ? TRUE : FALSE;
}

static BOOLEAN
KswordARKDriverUnloadThreadIsTerminated(
    _In_ PETHREAD ThreadObject
    )
{
    LARGE_INTEGER zeroTimeout;
    NTSTATUS waitStatus = STATUS_SUCCESS;

    if (ThreadObject == NULL) {
        return TRUE;
    }
    zeroTimeout.QuadPart = 0LL;
    waitStatus = KeWaitForSingleObject(
        ThreadObject,
        Executive,
        KernelMode,
        FALSE,
        &zeroTimeout);
    return waitStatus == STATUS_SUCCESS ? TRUE : FALSE;
}

/* 中文说明：只读扫描仍从目标模块入口运行的线程，作为强卸载阻断证据。 */
static NTSTATUS KswordARKDriverUnloadScanSystemThreadSnapshot(
    ULONGLONG ImageStart, ULONGLONG ImageEnd, ULONG* ScannedProcesses,
    ULONG* ScannedThreads, ULONG* ResidentThreads)
{
    KSW_WORK_QUEUE_SYSTEM_THREAD_SNAPSHOT snapshot; // 真实 System TID 快照，不猜扫线程 ID。
    ULONG index; // 有界线程下标。
    NTSTATUS status = KswordARKWorkQueueCaptureSystemThreads(&snapshot); // 复用生产快照解析与截断检测。
    typedef NTSTATUS (NTAPI* KSW_UNLOAD_QUERY_THREAD_FN)(HANDLE, ULONG, PVOID, ULONG, PULONG); // ZwQueryInformationThread 的系统调用 ABI。
    KSW_UNLOAD_QUERY_THREAD_FN queryThread; // 动态查询公开线程入口字段。
    UNICODE_STRING routineName; // 真实导出名字。
    if (!NT_SUCCESS(status)) return status; // 缺快照不能证明没有目标线程。
    if (snapshot.Truncated) { // 截断扫描不允许卸载继续。
        KswordARKWorkQueueReleaseSystemThreads(&snapshot); // 释放快照。
        return STATUS_BUFFER_OVERFLOW; // 明确不完整证据。
    }
    RtlInitUnicodeString(&routineName, L"ZwQueryInformationThread"); // 不依赖私有 ETHREAD 字段偏移。
    queryThread = (KSW_UNLOAD_QUERY_THREAD_FN)MmGetSystemRoutineAddress(&routineName); // 解析线程查询入口。
    if (queryThread == NULL) { // 未提供查询入口时保留拒绝。
        KswordARKWorkQueueReleaseSystemThreads(&snapshot); // 释放池数组。
        return STATUS_NOT_SUPPORTED; // 无可靠入口证据。
    }
    *ScannedProcesses = 1UL; // 原业务只认 System 进程驱动线程。
    for (index = 0UL; index < snapshot.Count; ++index) { // 引用并复核每个真实 TID。
        PETHREAD thread = NULL; // 对象管理器引用。
        HANDLE handle = NULL; // 查询用内核句柄。
        PVOID startAddress = NULL; // ThreadQuerySetWin32StartAddress 返回值。
        NTSTATUS threadStatus = PsLookupThreadByThreadId(ULongToHandle(snapshot.Entries[index].ThreadId), &thread); // 过滤快照后退出的线程。
        if (!NT_SUCCESS(threadStatus)) continue; // 已退出对象不会占用目标模块。
        if (PsGetThreadProcess(thread) != PsInitialSystemProcess || KswordARKDriverUnloadThreadIsTerminated(thread)) { // 拒绝 TID 复用或已终止对象。
            ObDereferenceObject(thread); // 释放身份引用。
            continue; // 不纳入驻留线程。
        }
        ++*ScannedThreads; // 统计已引用且归属 System 的活跃线程。
        threadStatus = ObOpenObjectByPointer(thread, OBJ_KERNEL_HANDLE, NULL, THREAD_QUERY_INFORMATION, *PsThreadType, KernelMode, &handle); // 通过确切对象创建查询句柄。
        if (NT_SUCCESS(threadStatus)) { // 使用官方查询获取真实线程入口。
            threadStatus = queryThread(handle, 9UL, &startAddress, sizeof(startAddress), NULL); // ThreadQuerySetWin32StartAddress。
            ZwClose(handle); // 每个查询句柄只关闭一次。
        }
        if (!NT_SUCCESS(threadStatus) && !KswordARKDriverUnloadThreadIsTerminated(thread)) status = threadStatus; // 活跃线程查询失败必须阻断卸载。
        if (NT_SUCCESS(threadStatus) &&
            (KswordARKDriverUnloadAddressInImageRange((ULONGLONG)(ULONG_PTR)startAddress, ImageStart, ImageEnd) ||
             KswordARKDriverUnloadAddressInImageRange(snapshot.Entries[index].StartAddress, ImageStart, ImageEnd))) ++*ResidentThreads; // 两条真实系统证据任一命中即驻留。
        ObDereferenceObject(thread); // 完成当前线程引用生命周期。
    }
    KswordARKWorkQueueReleaseSystemThreads(&snapshot); // 释放快照所有权。
    return status; // 不用缺少私有偏移或非导出枚举函数否决可靠公共查询。
}

/* 中文说明：优先沿用精确字段扫描，缺导出或偏移时使用公开线程入口查询。 */
static NTSTATUS
KswordARKDriverUnloadScanModuleResidentThreads(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONGLONG ImageStart,
    _In_ ULONGLONG ImageEnd,
    _Out_ ULONG* ScannedProcessCountOut,
    _Out_ ULONG* ScannedThreadCountOut,
    _Out_ ULONG* ResidentThreadCountOut
    )
{
    KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_FN psGetNextProcess = NULL;
    KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_THREAD_FN psGetNextProcessThread = NULL;
    PEPROCESS processCursor = NULL;
    ULONG scannedProcesses = 0UL;
    ULONG scannedThreads = 0UL;
    ULONG residentThreads = 0UL;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN stopScan = FALSE;

    /*
     * 输入：目标镜像范围和 PDB-backed ETHREAD 入口偏移。
     * 处理：通过公开 PsGetNextProcess/PsGetNextProcessThread 遍历已引用线程，
     *      读取 StartAddress/Win32StartAddress 并统计落在目标模块内的线程。
     * 返回：扫描完成返回 STATUS_SUCCESS；导出/偏移不可用或达到上限返回对应状态。
     *      本函数只产生证据，不终止线程、不改 ETHREAD、不触碰 CID 表。
     */
    if (ScannedProcessCountOut == NULL ||
        ScannedThreadCountOut == NULL ||
        ResidentThreadCountOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *ScannedProcessCountOut = 0UL;
    *ScannedThreadCountOut = 0UL;
    *ResidentThreadCountOut = 0UL;

    if (DynState == NULL || ImageStart == 0ULL || ImageEnd <= ImageStart) {
        return STATUS_INVALID_PARAMETER;
    }
    psGetNextProcess = KswordARKDriverUnloadResolvePsGetNextProcess();
    psGetNextProcessThread = KswordARKDriverUnloadResolvePsGetNextProcessThread();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL ||
        !KswordARKDriverUnloadHasPdbBackedThreadDynData(DynState)) { // 非导出 API 和缺私有字段不应阻止公共查询。
        return KswordARKDriverUnloadScanSystemThreadSnapshot(ImageStart, ImageEnd,
            ScannedProcessCountOut, ScannedThreadCountOut, ResidentThreadCountOut); // 仍保留完整驻留线程阻断证据。
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = NULL;
        PETHREAD threadCursor = NULL;

        scannedProcesses += 1UL;
        threadCursor = psGetNextProcessThread(processCursor, NULL);
        while (threadCursor != NULL) {
            PETHREAD nextThread = NULL;
            ULONGLONG startAddress = 0ULL;
            ULONGLONG win32StartAddress = 0ULL;
            BOOLEAN matchesTarget = FALSE;

            scannedThreads += 1UL;
            if (KswordARKDriverUnloadReadThreadAddressField(
                    threadCursor,
                    DynState->Kernel.EtStartAddress,
                    &startAddress) &&
                KswordARKDriverUnloadAddressInImageRange(startAddress, ImageStart, ImageEnd)) {
                matchesTarget = TRUE;
            }
            if (!matchesTarget &&
                KswordARKDriverIntegrityOffsetPresent(DynState->Kernel.EtWin32StartAddress) &&
                KswordARKDriverUnloadReadThreadAddressField(
                    threadCursor,
                    DynState->Kernel.EtWin32StartAddress,
                    &win32StartAddress) &&
                KswordARKDriverUnloadAddressInImageRange(win32StartAddress, ImageStart, ImageEnd)) {
                matchesTarget = TRUE;
            }
            if (matchesTarget &&
                (PsGetThreadProcess(threadCursor) != PsInitialSystemProcess ||
                    KswordARKDriverUnloadThreadIsTerminated(threadCursor))) {
                /*
                 * 中文说明：强拆只把 System 进程内、尚未退出且入口属于目标镜像的
                 * 线程认定为“驱动创建的线程”；用户线程和已终止 ETHREAD 不计入。
                 */
                matchesTarget = FALSE;
            }
            if (matchesTarget) {
                residentThreads += 1UL;
            }

            if (scannedThreads >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_THREADS) {
                status = STATUS_BUFFER_OVERFLOW;
                ObDereferenceObject(threadCursor);
                stopScan = TRUE;
                break;
            }

            nextThread = psGetNextProcessThread(processCursor, threadCursor);
            ObDereferenceObject(threadCursor);
            threadCursor = nextThread;
        }

        if (scannedProcesses >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_PROCESSES) {
            status = STATUS_BUFFER_OVERFLOW;
            stopScan = TRUE;
        }

        if (!stopScan) {
            nextProcess = psGetNextProcess(processCursor);
        }
        ObDereferenceObject(processCursor);
        if (stopScan) {
            break;
        }
        processCursor = nextProcess;
    }

    *ScannedProcessCountOut = scannedProcesses;
    *ScannedThreadCountOut = scannedThreads;
    *ResidentThreadCountOut = residentThreads;
    return status;
}

static NTSTATUS
KswordARKDriverUnloadTerminateModuleThreadsUnsafe(
    _In_ const KSW_DYN_STATE* DynState,
    _In_ ULONGLONG ImageStart,
    _In_ ULONGLONG ImageEnd,
    _Out_ PKSW_DRIVER_UNLOAD_THREAD_CLEANUP_RESULT Result
    )
{
    KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_FN psGetNextProcess = NULL;
    KSW_DRIVER_UNLOAD_PS_GET_NEXT_PROCESS_THREAD_FN psGetNextProcessThread = NULL;
    PEPROCESS processCursor = NULL;
    ULONG scannedProcesses = 0UL;
    ULONG scannedThreads = 0UL;
    NTSTATUS aggregateStatus = STATUS_SUCCESS;

    /*
     * 输入：经 loader/PDB 证据确认的目标镜像范围。
     * 处理：只处理 System 进程中入口仍位于目标镜像、且尚未退出的线程；
     *      逐个强制终止并等待 ETHREAD 进入 signaled 状态。任何一个线程未确认
     *      退出都返回失败，调用方不得继续进入 DriverUnload。
     * 返回：全部候选均确认退出时 STATUS_SUCCESS，并回填候选/成功/失败计数。
     */
    if (Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(Result, sizeof(*Result));
    Result->LastStatus = STATUS_SUCCESS;

    if (DynState == NULL || ImageStart == 0ULL || ImageEnd <= ImageStart) {
        Result->LastStatus = STATUS_INVALID_PARAMETER;
        return Result->LastStatus;
    }
    if (!KswordARKDriverUnloadHasPdbBackedThreadDynData(DynState)) {
        Result->LastStatus = STATUS_REQUEST_NOT_ACCEPTED;
        return Result->LastStatus;
    }

    psGetNextProcess = KswordARKDriverUnloadResolvePsGetNextProcess();
    psGetNextProcessThread = KswordARKDriverUnloadResolvePsGetNextProcessThread();
    if (psGetNextProcess == NULL || psGetNextProcessThread == NULL) {
        Result->LastStatus = STATUS_NOT_SUPPORTED;
        return Result->LastStatus;
    }

    processCursor = psGetNextProcess(NULL);
    while (processCursor != NULL) {
        PEPROCESS nextProcess = NULL;
        PETHREAD threadCursor = NULL;
        BOOLEAN stopScan = FALSE;

        scannedProcesses += 1UL;
        threadCursor = psGetNextProcessThread(processCursor, NULL);
        while (threadCursor != NULL) {
            PETHREAD nextThread = NULL;
            ULONGLONG startAddress = 0ULL;
            ULONGLONG win32StartAddress = 0ULL;
            BOOLEAN matchesTarget = FALSE;

            /*
             * 先取得下一条引用，再终止当前线程；目标退出可能从进程线程链摘除，
             * 不能在终止后再以当前 ETHREAD 继续枚举。
             */
            nextThread = psGetNextProcessThread(processCursor, threadCursor);
            scannedThreads += 1UL;

            if (PsGetThreadProcess(threadCursor) == PsInitialSystemProcess &&
                !KswordARKDriverUnloadThreadIsTerminated(threadCursor)) {
                if (KswordARKDriverUnloadReadThreadAddressField(
                        threadCursor,
                        DynState->Kernel.EtStartAddress,
                        &startAddress) &&
                    KswordARKDriverUnloadAddressInImageRange(startAddress, ImageStart, ImageEnd)) {
                    matchesTarget = TRUE;
                }
                if (!matchesTarget &&
                    KswordARKDriverIntegrityOffsetPresent(DynState->Kernel.EtWin32StartAddress) &&
                    KswordARKDriverUnloadReadThreadAddressField(
                        threadCursor,
                        DynState->Kernel.EtWin32StartAddress,
                        &win32StartAddress) &&
                    KswordARKDriverUnloadAddressInImageRange(
                        win32StartAddress,
                        ImageStart,
                        ImageEnd)) {
                    matchesTarget = TRUE;
                }
            }

            if (matchesTarget) {
                LARGE_INTEGER waitInterval;
                NTSTATUS terminateStatus = STATUS_SUCCESS;
                NTSTATUS waitStatus = STATUS_SUCCESS;

                Result->Candidates += 1UL;
                terminateStatus = KswordARKDriverTerminateReferencedThread(
                    threadCursor,
                    STATUS_CANCELLED);
                if (NT_SUCCESS(terminateStatus)) {
                    waitInterval.QuadPart =
                        -((LONGLONG)KSW_DRIVER_UNLOAD_THREAD_TERMINATE_WAIT_MS * 10LL * 1000LL);
                    waitStatus = KeWaitForSingleObject(
                        threadCursor,
                        Executive,
                        KernelMode,
                        FALSE,
                        &waitInterval);
                }
                /* STATUS_TIMEOUT is NT_SUCCESS-compatible but the thread is still live. */
                if (NT_SUCCESS(terminateStatus) && waitStatus == STATUS_SUCCESS) {
                    Result->Terminated += 1UL;
                }
                else {
                    Result->Failures += 1UL;
                    Result->LastStatus = !NT_SUCCESS(terminateStatus)
                        ? terminateStatus
                        : waitStatus;
                    aggregateStatus = Result->LastStatus;
                }
            }

            ObDereferenceObject(threadCursor);
            threadCursor = nextThread;

            if (scannedThreads >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_THREADS) {
                aggregateStatus = STATUS_BUFFER_OVERFLOW;
                Result->LastStatus = aggregateStatus;
                if (threadCursor != NULL) {
                    ObDereferenceObject(threadCursor);
                    threadCursor = NULL;
                }
                stopScan = TRUE;
                break;
            }
        }

        if (scannedProcesses >= KSW_DRIVER_UNLOAD_THREAD_SCAN_MAX_PROCESSES) {
            aggregateStatus = STATUS_BUFFER_OVERFLOW;
            Result->LastStatus = aggregateStatus;
            stopScan = TRUE;
        }
        if (!stopScan) {
            nextProcess = psGetNextProcess(processCursor);
        }
        ObDereferenceObject(processCursor);
        if (stopScan) {
            break;
        }
        processCursor = nextProcess;
    }

    if (Result->Failures != 0UL && NT_SUCCESS(aggregateStatus)) {
        aggregateStatus = Result->LastStatus != STATUS_SUCCESS
            ? Result->LastStatus
            : STATUS_UNSUCCESSFUL;
    }
    return aggregateStatus;
}

/* 中文说明：只读校验 loader 链表节点的前后向链接是否仍互相指回目标节点。 */
static NTSTATUS
KswordARKDriverUnloadInspectLoaderLinkCoherence(
    _In_ ULONGLONG LinkAddress,
    _Out_ BOOLEAN* MismatchOut
    )
{
    LIST_ENTRY selfLinks;
    LIST_ENTRY flinkLinks;
    LIST_ENTRY blinkLinks;
    ULONGLONG flinkAddress = 0ULL;
    ULONGLONG blinkAddress = 0ULL;

    /*
     * 输入：目标 KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks 的内核地址。
     * 处理：安全读取目标节点、Flink 节点和 Blink 节点；要求 Flink->Blink 与
     *      Blink->Flink 均指回目标节点。这里仅做证据校验，不摘链、不修链。
     * 返回：链路一致返回 STATUS_SUCCESS；读取失败或链路不一致返回具体状态。
     */
    if (MismatchOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *MismatchOut = FALSE;
    if (LinkAddress == 0ULL) {
        *MismatchOut = TRUE;
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&selfLinks, sizeof(selfLinks));
    RtlZeroMemory(&flinkLinks, sizeof(flinkLinks));
    RtlZeroMemory(&blinkLinks, sizeof(blinkLinks));
    if (!KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)LinkAddress,
            &selfLinks,
            sizeof(selfLinks))) {
        *MismatchOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }

    flinkAddress = (ULONGLONG)(ULONG_PTR)selfLinks.Flink;
    blinkAddress = (ULONGLONG)(ULONG_PTR)selfLinks.Blink;
    if (flinkAddress == 0ULL || blinkAddress == 0ULL) {
        *MismatchOut = TRUE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (!KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)flinkAddress,
            &flinkLinks,
            sizeof(flinkLinks)) ||
        !KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)blinkAddress,
            &blinkLinks,
            sizeof(blinkLinks))) {
        *MismatchOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    if ((ULONGLONG)(ULONG_PTR)flinkLinks.Blink != LinkAddress ||
        (ULONGLONG)(ULONG_PTR)blinkLinks.Flink != LinkAddress) {
        *MismatchOut = TRUE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    return STATUS_SUCCESS;
}

/* 中文说明：只读校验目标内核镜像 PE 头是否仍可解析，检测被擦头/损坏状态。 */
static NTSTATUS
KswordARKDriverUnloadInspectImageHeader(
    _In_ ULONGLONG ImageBase,
    _In_ ULONG ExpectedSizeOfImage,
    _Out_ ULONG* HeaderSizeOfImageOut,
    _Out_ ULONG* NtHeaderOffsetOut,
    _Out_ BOOLEAN* InvalidHeaderOut
    )
{
    IMAGE_DOS_HEADER dosHeader;
    IMAGE_NT_HEADERS64 ntHeaders;
    ULONG ntHeaderOffset = 0UL;

    /*
     * 输入：目标模块基址和 loader 记录的 SizeOfImage。
     * 处理：安全读取 DOS/NT 头，校验 MZ/PE/PE32+ 与 SizeOfImage 一致性。
     * 返回：PE 头有效返回 STATUS_SUCCESS；头被擦除、偏移异常或大小不一致时
     *      返回失败状态。函数只读内存，不擦 PE 头、不修复头。
     */
    if (HeaderSizeOfImageOut == NULL ||
        NtHeaderOffsetOut == NULL ||
        InvalidHeaderOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *HeaderSizeOfImageOut = 0UL;
    *NtHeaderOffsetOut = 0UL;
    *InvalidHeaderOut = FALSE;
    if (ImageBase == 0ULL) {
        *InvalidHeaderOut = TRUE;
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&dosHeader, sizeof(dosHeader));
    RtlZeroMemory(&ntHeaders, sizeof(ntHeaders));
    if (!KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)ImageBase,
            &dosHeader,
            sizeof(dosHeader))) {
        *InvalidHeaderOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0 ||
        dosHeader.e_lfanew > 0x1000) {
        *InvalidHeaderOut = TRUE;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    ntHeaderOffset = (ULONG)dosHeader.e_lfanew;
    if (!KswordARKHookReadMemorySafe(
            (const VOID*)(ULONG_PTR)(ImageBase + (ULONGLONG)ntHeaderOffset),
            &ntHeaders,
            sizeof(ntHeaders))) {
        *InvalidHeaderOut = TRUE;
        return STATUS_ACCESS_VIOLATION;
    }
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE ||
        ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders.OptionalHeader.SizeOfImage == 0UL) {
        *InvalidHeaderOut = TRUE;
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    *HeaderSizeOfImageOut = ntHeaders.OptionalHeader.SizeOfImage;
    *NtHeaderOffsetOut = ntHeaderOffset;
    if (ExpectedSizeOfImage != 0UL &&
        ntHeaders.OptionalHeader.SizeOfImage != ExpectedSizeOfImage) {
        *InvalidHeaderOut = TRUE;
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    return STATUS_SUCCESS;
}

/* 中文说明：聚合 loader 链和 PE 头一致性证据，供强卸载 preflight 使用。 */
static VOID
KswordARKDriverUnloadInspectLoaderAndImageEvidence(
    _In_opt_ const KSW_DRIVER_INTEGRITY_LDR_TARGET* LoaderTarget,
    _In_ ULONGLONG ImageBase,
    _In_ ULONG ExpectedSizeOfImage,
    _Out_ KSW_DRIVER_UNLOAD_LOADER_IMAGE_EVIDENCE* EvidenceOut
    )
{
    /*
     * 输入：由 PsLoadedModuleList 找到的目标 loader 记录和镜像基址。
     * 处理：分别做 loader link 双向一致性校验和 PE 头校验。
     * 返回：通过 EvidenceOut 输出状态和计数；函数本身无返回值。
     */
    if (EvidenceOut == NULL) {
        return;
    }
    RtlZeroMemory(EvidenceOut, sizeof(*EvidenceOut));
    EvidenceOut->LoaderLinkStatus = STATUS_REQUEST_NOT_ACCEPTED;
    EvidenceOut->ImageHeaderStatus = STATUS_REQUEST_NOT_ACCEPTED;

    if (LoaderTarget != NULL && LoaderTarget->Found && LoaderTarget->LinkAddress != 0ULL) {
        EvidenceOut->LoaderLinkChecked = TRUE;
        EvidenceOut->LoaderLinkStatus = KswordARKDriverUnloadInspectLoaderLinkCoherence(
            LoaderTarget->LinkAddress,
            &EvidenceOut->LoaderLinkMismatch);
        if (!NT_SUCCESS(EvidenceOut->LoaderLinkStatus)) {
            EvidenceOut->LoaderLinkMismatch = TRUE;
        }
    }

    if (ImageBase != 0ULL) {
        EvidenceOut->ImageHeaderChecked = TRUE;
        EvidenceOut->ImageHeaderStatus = KswordARKDriverUnloadInspectImageHeader(
            ImageBase,
            ExpectedSizeOfImage,
            &EvidenceOut->ImageHeaderSizeOfImage,
            &EvidenceOut->ImageNtHeaderOffset,
            &EvidenceOut->InvalidImageHeader);
        if (!NT_SUCCESS(EvidenceOut->ImageHeaderStatus)) {
            EvidenceOut->InvalidImageHeader = TRUE;
        }
    }
}

/* 中文说明：读取卸载目标的只读前置证据，并决定是否允许系统卸载或强力清理。 */
static NTSTATUS
KswordARKDriverUnloadBuildPreflightResult(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* NormalizedDriverName,
    _In_ ULONGLONG TargetModuleBase,
    _In_ ULONG Flags,
    _Out_ KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Result
    )
{
    KSW_DRIVER_UNLOAD_PREFLIGHT_WORKSPACE* workspace = NULL;
    KSW_DYN_STATE* dynState = NULL;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    const KSW_HOOK_SYSTEM_MODULE_ENTRY* targetModule = NULL;
    KSW_DRIVER_INTEGRITY_LDR_TARGET ldrTarget;
    KSW_DRIVER_UNLOAD_LOADER_IMAGE_EVIDENCE loaderImageEvidence;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS evidenceStatus = STATUS_SUCCESS;
    ULONGLONG driverStart = 0ULL;
    ULONGLONG driverEnd = 0ULL;
    const BOOLEAN teardownRequested =
        ((Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) != 0UL &&
            (Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) != 0UL)
        ? TRUE
        : FALSE;

    if (DriverObject == NULL || Result == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    UNREFERENCED_PARAMETER(moduleInfoBytes);

    workspace = (KSW_DRIVER_UNLOAD_PREFLIGHT_WORKSPACE*)KswordARKAllocateNonPagedPool(
        sizeof(*workspace),
        KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
    if (workspace == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(workspace, sizeof(*workspace));
    dynState = &workspace->DynState;

    RtlZeroMemory(Result, sizeof(*Result));
    RtlZeroMemory(&ldrTarget, sizeof(ldrTarget));
    RtlZeroMemory(&loaderImageEvidence, sizeof(loaderImageEvidence));

    Result->AllowDirectUnload = FALSE;
    Result->AllowZwUnload = FALSE;
    Result->AllowDestructiveCleanup =
        (Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) != 0UL ? TRUE : FALSE;

    __try {
        driverStart = (ULONGLONG)(ULONG_PTR)DriverObject->DriverStart;
        driverEnd = driverStart + (ULONGLONG)DriverObject->DriverSize;
        Result->HasDriverUnload = (DriverObject->DriverUnload != NULL) ? TRUE : FALSE;
        status = KswordARKDriverUnloadBuildServiceRegistryPath(
            DriverObject,
            NormalizedDriverName,
            Result->ServiceRegistryPath,
            RTL_NUMBER_OF(Result->ServiceRegistryPath));
        Result->HasServiceRegistryPath = NT_SUCCESS(status) ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return status;
    }

    if (driverStart == 0ULL ||
        driverEnd <= driverStart ||
        driverEnd < driverStart) {
        Result->AllowDirectUnload = FALSE;
        Result->AllowZwUnload = FALSE;
        Result->AllowDestructiveCleanup = FALSE;
        Result->Status = STATUS_INVALID_PARAMETER;
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return Result->Status;
    }
    Result->DriverStart = driverStart;
    Result->DriverEnd = driverEnd;

    if (TargetModuleBase != 0ULL &&
        TargetModuleBase != driverStart) {
        Result->AllowDirectUnload = FALSE;
        Result->AllowZwUnload = FALSE;
        Result->AllowDestructiveCleanup = FALSE;
        Result->Status = STATUS_OBJECT_TYPE_MISMATCH;
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return Result->Status;
    }

    KswordARKDynDataSnapshot(dynState);
    Result->AllowDirectUnload = Result->HasDriverUnload;
    Result->AllowZwUnload = Result->HasServiceRegistryPath;
    Result->HasValidDynData =
        dynState->Initialized &&
        dynState->NtosActive &&
        (dynState->CapabilityMask & KSW_CAP_DRIVER_OBJECT_FIELDS) != 0ULL &&
        (dynState->CapabilityMask & KSW_CAP_KERNEL_MODULE_LIST_FIELDS) != 0ULL &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.DoDriverStart) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.DoDriverSize) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.DoDriverSection) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.DoMajorFunction) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.DoDriverUnload) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.KldrDllBase) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.KldrSizeOfImage) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->Kernel.KldrInLoadOrderLinks) &&
        KswordARKDriverIntegrityOffsetPresent(dynState->KernelGlobals.PsLoadedModuleList);
    Result->HasPdbBackedDynData = KswordARKDriverUnloadHasPdbBackedDynData(dynState);

    status = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (NT_SUCCESS(status) && moduleInfo != NULL) {
        targetModule = KswordARKDriverIntegrityFindModuleForAddress(moduleInfo, driverStart);
        Result->IsCoreKernelModule = KswordARKDriverIntegrityIsCoreKernelModule(targetModule);
        if (targetModule != NULL) {
            const UCHAR* fileName = NULL;
            ULONG fileNameBytes = 0UL;

            KswordARKHookGetModuleFileName(targetModule, &fileName, &fileNameBytes);
            if (KswordARKDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "KswordARK.sys")) {
                Result->IsSelfModule = TRUE;
            }
            if (KswordARKDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntoskrnl.exe") ||
                KswordARKDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntkrnlmp.exe") ||
                KswordARKDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntkrnlpa.exe") ||
                KswordARKDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "ntkrpamp.exe") ||
                KswordARKDriverUnloadAnsiEndsWithInsensitive(fileName, fileNameBytes, "hal.dll")) {
                Result->IsCoreKernelModule = TRUE;
            }
        }
    }
    else {
        evidenceStatus = status;
        status = STATUS_SUCCESS;
    }

    if (!Result->IsSelfModule &&
        Result->ServiceRegistryPath[0] != L'\0') {
        const WCHAR* leafName = Result->ServiceRegistryPath;
        if (KswordARKDriverUnloadStartsWithInsensitive(
            Result->ServiceRegistryPath,
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\")) {
            const ULONG prefixChars = KswordARKDriverUnloadCountFixedStringChars(
                L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\");
            leafName = Result->ServiceRegistryPath + prefixChars;
        }
        if (KswordARKDriverUnloadStartsWithInsensitive(leafName, L"KswordARK")) {
            Result->IsSelfModule = TRUE;
        }
    }

    if (Result->HasValidDynData) {
        status = KswordARKDriverIntegrityFindLoadedModule(dynState, driverStart, &ldrTarget);
        if (NT_SUCCESS(status) && ldrTarget.Found) {
            const ULONGLONG driverSize = (ULONGLONG)DriverObject->DriverSize;
            Result->LoaderEntryAddress = ldrTarget.EntryAddress;
            Result->LoaderDllBase = ldrTarget.DllBase;
            Result->LoaderSizeOfImage = ldrTarget.SizeOfImage;
            if (ldrTarget.DllBase == driverStart &&
                ldrTarget.SizeOfImage != 0UL &&
                (ULONGLONG)ldrTarget.SizeOfImage == driverSize &&
                ((ULONGLONG)(ULONG_PTR)DriverObject->DriverSection == 0ULL ||
                    (ULONGLONG)(ULONG_PTR)DriverObject->DriverSection == ldrTarget.EntryAddress)) {
                Result->HasValidLoaderEvidence = TRUE;
            }
            else {
                evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
                Result->HasValidLoaderEvidence = FALSE;
            }
        }
        else {
            evidenceStatus = status;
            Result->HasValidLoaderEvidence = FALSE;
        }
        status = STATUS_SUCCESS;
    }

    KswordARKDriverUnloadInspectLoaderAndImageEvidence(
        Result->HasValidLoaderEvidence ? &ldrTarget : NULL,
        driverStart,
        Result->LoaderSizeOfImage != 0UL ? Result->LoaderSizeOfImage : (ULONG)DriverObject->DriverSize,
        &loaderImageEvidence);
    Result->HasLoaderLinkCheck = loaderImageEvidence.LoaderLinkChecked;
    Result->HasLoaderLinkMismatch = loaderImageEvidence.LoaderLinkMismatch;
    Result->HasImageHeaderCheck = loaderImageEvidence.ImageHeaderChecked;
    Result->HasInvalidImageHeader = loaderImageEvidence.InvalidImageHeader;
    Result->LoaderLinkStatus = loaderImageEvidence.LoaderLinkStatus;
    Result->ImageHeaderStatus = loaderImageEvidence.ImageHeaderStatus;
    Result->ImageHeaderSizeOfImage = loaderImageEvidence.ImageHeaderSizeOfImage;
    Result->ImageNtHeaderOffset = loaderImageEvidence.ImageNtHeaderOffset;
    if ((loaderImageEvidence.LoaderLinkMismatch ||
            loaderImageEvidence.InvalidImageHeader) &&
        evidenceStatus == STATUS_SUCCESS) {
        evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
    }

    if (Result->HasValidDynData && Result->HasValidLoaderEvidence) {
        Result->HasValidDriverObjectOffsets =
            KswordARKDriverUnloadValidateDriverObjectOffsets(DriverObject, dynState);
        if (!Result->HasValidDriverObjectOffsets && evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
        }
    }

    Result->ThreadScanStatus = KswordARKDriverUnloadScanModuleResidentThreads(
        dynState,
        driverStart,
        driverEnd,
        &Result->ScannedProcessCount,
        &Result->ScannedThreadCount,
        &Result->ModuleResidentThreadCount);
    if (NT_SUCCESS(Result->ThreadScanStatus)) {
        Result->HasThreadScan = TRUE;
        if (Result->ModuleResidentThreadCount != 0UL) {
            Result->HasModuleResidentThreads = TRUE;
            if (evidenceStatus == STATUS_SUCCESS) {
                evidenceStatus = STATUS_DEVICE_BUSY;
            }
        }
    }
    else {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = Result->ThreadScanStatus;
        }
        Result->AllowDestructiveCleanup = FALSE;
        Result->AllowDirectUnload = FALSE;
    }

    {
        KSW_DRIVER_UNLOAD_CALLBACK_EVIDENCE_RESULT callbackEvidence;

        RtlZeroMemory(&callbackEvidence, sizeof(callbackEvidence));
        Result->CallbackScanStatus = KswordARKDriverUnloadInspectCallbacksByModuleBase(
            driverStart,
            &callbackEvidence);
        if (NT_SUCCESS(Result->CallbackScanStatus)) {
            Result->HasCallbackScan = TRUE;
            Result->CallbackEnumeratedCount = callbackEvidence.Enumerated;
            Result->ModuleCallbackCount = callbackEvidence.Matched;
            Result->RemovableModuleCallbackCount = callbackEvidence.Removable;
            Result->NonRemovableModuleCallbackCount = callbackEvidence.NonRemovable;
            if (callbackEvidence.Matched != 0UL) {
                Result->HasModuleCallbacks = TRUE;
            }
            if (callbackEvidence.NonRemovable != 0UL) {
                Result->HasNonRemovableModuleCallbacks = TRUE;
            }
        }
        else {
            if (evidenceStatus == STATUS_SUCCESS) {
                evidenceStatus = Result->CallbackScanStatus;
            }
            Result->AllowDestructiveCleanup = FALSE;
            Result->AllowDirectUnload = FALSE;
        }
    }

    __try {
        PDEVICE_OBJECT rootDevice = DriverObject->DeviceObject;
        ULONG visitedCount = 0UL;
        PDEVICE_OBJECT* visited = workspace->VisitedDevices;

        while (rootDevice != NULL) {
            PDEVICE_OBJECT nextDevice = NULL;
            ULONG previousIndex = 0UL;
            NTSTATUS deviceIdleStatus = STATUS_SUCCESS;

            Result->HasDeviceChain = TRUE;
            if (visitedCount >= KSW_DRIVER_UNLOAD_PREFLIGHT_DEVICE_LIMIT) {
                if (evidenceStatus == STATUS_SUCCESS) {
                    evidenceStatus = STATUS_BUFFER_OVERFLOW;
                }
                break;
            }
            for (previousIndex = 0UL; previousIndex < visitedCount; ++previousIndex) {
                if (visited[previousIndex] == rootDevice) {
                    Result->HasDeviceLoop = TRUE;
                    break;
                }
            }
            if (Result->HasDeviceLoop) {
                break;
            }
            visited[visitedCount++] = rootDevice;

            deviceIdleStatus = KswordARKDriverUnloadCheckDeviceObjectIdleUnsafe(
                DriverObject,
                rootDevice,
                &nextDevice);
            if (deviceIdleStatus == STATUS_OBJECT_TYPE_MISMATCH) {
                Result->HasCrossDriverAttach = TRUE;
                break;
            }
            if (deviceIdleStatus == STATUS_DEVICE_BUSY) {
                if (rootDevice->AttachedDevice != NULL) {
                    Result->HasAttachedDevice = TRUE;
                }
                if (rootDevice->ReferenceCount != 0) {
                    Result->HasBusyDeviceReference = TRUE;
                }
                if (evidenceStatus == STATUS_SUCCESS) {
                    evidenceStatus = STATUS_DEVICE_BUSY;
                }
                break;
            }
            if (!NT_SUCCESS(deviceIdleStatus)) {
                if (evidenceStatus == STATUS_SUCCESS) {
                    evidenceStatus = deviceIdleStatus;
                }
                break;
            }

            rootDevice = nextDevice;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        evidenceStatus = status;
        status = STATUS_SUCCESS;
    }

    if (Result->IsSelfModule || Result->IsCoreKernelModule) {
        Result->AllowDirectUnload = FALSE;
        Result->AllowZwUnload = FALSE;
        Result->AllowDestructiveCleanup = FALSE;
        Result->Status = STATUS_DRIVER_BLOCKED_CRITICAL;
        if (moduleInfo != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
        }
        ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
        return Result->Status;
    }

    if (Result->HasDeviceLoop || Result->HasCrossDriverAttach) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_INVALID_DEVICE_REQUEST;
        }
        Result->AllowDestructiveCleanup = FALSE;
    }
    if ((Result->HasAttachedDevice || Result->HasBusyDeviceReference) &&
        (!teardownRequested ||
            (Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS) == 0UL)) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_DEVICE_BUSY;
        }
        Result->AllowDestructiveCleanup = FALSE;
        Result->AllowDirectUnload = FALSE;
    }
    if (Result->HasModuleResidentThreads &&
        (!teardownRequested ||
            (Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS) == 0UL)) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_DEVICE_BUSY;
        }
        Result->AllowDestructiveCleanup = FALSE;
    }
    if (Result->HasNonRemovableModuleCallbacks ||
        (Result->HasModuleCallbacks &&
            (Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) == 0UL)) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_DEVICE_BUSY;
        }
        Result->AllowDestructiveCleanup = FALSE;
    }
    if (Result->HasLoaderLinkMismatch || Result->HasInvalidImageHeader) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
        }
        Result->AllowDestructiveCleanup = FALSE;
        Result->AllowDirectUnload = FALSE;
    }

    if (!Result->HasServiceRegistryPath) {
        Result->AllowZwUnload = FALSE;
    }
    if (!Result->HasValidDynData ||
        !Result->HasPdbBackedDynData ||
        !Result->HasValidLoaderEvidence) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_REQUEST_NOT_ACCEPTED;
        }
        Result->AllowDestructiveCleanup = FALSE;
        Result->AllowDirectUnload = FALSE;
    }
    if (!Result->HasValidDriverObjectOffsets) {
        if (evidenceStatus == STATUS_SUCCESS) {
            evidenceStatus = STATUS_OBJECT_TYPE_MISMATCH;
        }
        Result->AllowDestructiveCleanup = FALSE;
        Result->AllowDirectUnload = FALSE;
    }

    if (moduleInfo != NULL) {
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    ExFreePoolWithTag(workspace, KSW_DRIVER_UNLOAD_PREFLIGHT_TAG);
    Result->Status = evidenceStatus;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordARKDriverUnloadApplyPreUnloadTeardownUnsafe(
    _Inout_ PKSW_DRIVER_UNLOAD_CONTEXT UnloadContext
    )
{
    KSW_DYN_STATE dynState;
    KSW_DRIVER_UNLOAD_ENTRY_TRANSACTION entryTransaction;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS rollbackStatus = STATUS_SUCCESS;
    ULONG terminatePass = 0UL;
    ULONG remainingThreads = 0UL;
    ULONG scannedProcesses = 0UL;
    ULONG scannedThreads = 0UL;

    /*
     * DriverObject 强拆的事务前半段：
     * 1. 重新验证 PDB-backed ETHREAD 字段并完成一次只读线程扫描；
     * 2. 保存 MajorFunction/FastIo/Device Flags 后才阻断新的外部入口；
     * 3. 线程或回调清理失败时恢复全部可逆入口字段；
     * 4. 全部成功后提交事务，调用方才允许进入 DriverUnload。
     */
    if (UnloadContext == NULL || UnloadContext->DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if ((UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) == 0UL) {
        return STATUS_SUCCESS;
    }
    if ((UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) == 0UL ||
        (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD) == 0UL ||
        (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS) == 0UL) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&entryTransaction, sizeof(entryTransaction));
    KswordARKDynDataSnapshot(&dynState);
    if (!KswordARKDriverUnloadHasPdbBackedThreadDynData(&dynState)) {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }

    status = KswordARKDriverUnloadScanModuleResidentThreads(
        &dynState,
        UnloadContext->DriverStart,
        UnloadContext->DriverEnd,
        &scannedProcesses,
        &scannedThreads,
        &remainingThreads);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = KswordARKDriverUnloadSnapshotEntryTransaction(
        UnloadContext->DriverObject,
        &entryTransaction);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordARKDriverUnloadApplyEntryTransaction(
        UnloadContext->DriverObject,
        &entryTransaction);
    if (!NT_SUCCESS(status)) {
        goto RollbackEntryTransaction;
    }
    UnloadContext->CleanupFlagsApplied |=
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD;

    for (terminatePass = 0UL;
        terminatePass < KSW_DRIVER_UNLOAD_THREAD_TERMINATE_PASSES;
        ++terminatePass) {
        KSW_DRIVER_UNLOAD_THREAD_CLEANUP_RESULT threadResult;

        RtlZeroMemory(&threadResult, sizeof(threadResult));
        threadResult.LastStatus = STATUS_SUCCESS;
        status = KswordARKDriverUnloadTerminateModuleThreadsUnsafe(
            &dynState,
            UnloadContext->DriverStart,
            UnloadContext->DriverEnd,
            &threadResult);
        UnloadContext->ThreadCandidates += threadResult.Candidates;
        UnloadContext->ThreadsTerminated += threadResult.Terminated;
        UnloadContext->ThreadFailures += threadResult.Failures;
        if (threadResult.LastStatus != STATUS_SUCCESS) {
            UnloadContext->ThreadLastStatus = threadResult.LastStatus;
        }
        if (!NT_SUCCESS(status)) {
            goto RollbackEntryTransaction;
        }

        remainingThreads = 0UL;
        scannedProcesses = 0UL;
        scannedThreads = 0UL;
        status = KswordARKDriverUnloadScanModuleResidentThreads(
            &dynState,
            UnloadContext->DriverStart,
            UnloadContext->DriverEnd,
            &scannedProcesses,
            &scannedThreads,
            &remainingThreads);
        if (!NT_SUCCESS(status)) {
            UnloadContext->ThreadLastStatus = status;
            goto RollbackEntryTransaction;
        }
        if (remainingThreads == 0UL) {
            break;
        }
    }
    if (remainingThreads != 0UL) {
        UnloadContext->ThreadCandidates += remainingThreads;
        UnloadContext->ThreadFailures += remainingThreads;
        UnloadContext->ThreadLastStatus = STATUS_DEVICE_BUSY;
        status = STATUS_DEVICE_BUSY;
        goto RollbackEntryTransaction;
    }

    UnloadContext->CleanupFlagsApplied |=
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS;

    if ((UnloadContext->Flags &
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) != 0UL) {
        KSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT callbackResult;

        RtlZeroMemory(&callbackResult, sizeof(callbackResult));
        callbackResult.LastStatus = STATUS_SUCCESS;
        status = KswordARKDriverUnloadRemoveCallbacksByModuleBase(
            UnloadContext->DriverStart,
            &callbackResult);
        UnloadContext->CallbackCandidates = callbackResult.Candidates;
        UnloadContext->CallbacksRemoved = callbackResult.Removed;
        UnloadContext->CallbackFailures = callbackResult.Failures;
        UnloadContext->CallbackLastStatus = callbackResult.LastStatus;
        if (!NT_SUCCESS(status)) {
            goto RollbackEntryTransaction;
        }
        UnloadContext->CleanupFlagsApplied |=
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE;
    }
    KswordARKDriverUnloadReleaseEntryTransaction(&entryTransaction);
    return STATUS_SUCCESS;

RollbackEntryTransaction:
    rollbackStatus = KswordARKDriverUnloadRollbackEntryTransaction(
        UnloadContext->DriverObject,
        &entryTransaction);
    UnloadContext->CleanupFlagsApplied &=
        ~KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD;
    KswordARKDriverUnloadReleaseEntryTransaction(&entryTransaction);
    return NT_SUCCESS(rollbackStatus) ? status : rollbackStatus;
}

/* 中文说明：执行强制卸载后的附加清理，所有动作都必须由有效 flag 明确启用。 */
static NTSTATUS
KswordARKDriverUnloadApplyCleanupUnsafe(
    _Inout_ PKSW_DRIVER_UNLOAD_CONTEXT UnloadContext,
    _In_ BOOLEAN DriverUnloadWasCalled
    )
{
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    BOOLEAN allowPersistentCleanup = FALSE;
    BOOLEAN deleteDeviceObjects = FALSE;
    BOOLEAN clearDispatchForPath = FALSE;
    BOOLEAN dispatchCleared = FALSE;
    BOOLEAN blockNewDeviceAccess = FALSE;
    ULONG clearDispatchFlag = 0UL;

    if (UnloadContext == NULL || UnloadContext->DriverObject == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    allowPersistentCleanup =
        (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) != 0UL
        ? TRUE
        : FALSE;
    if (!allowPersistentCleanup) {
        return STATUS_SUCCESS;
    }

    deleteDeviceObjects =
        (!DriverUnloadWasCalled &&
            (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD) != 0UL) ||
        ((UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS) != 0UL)
        ? TRUE
        : FALSE;

    if (DriverUnloadWasCalled &&
        (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD) != 0UL) {
        clearDispatchForPath = TRUE;
        clearDispatchFlag = KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD;
    }
    else if (!DriverUnloadWasCalled &&
        (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD) != 0UL) {
        clearDispatchForPath = TRUE;
        clearDispatchFlag = KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD;
    }

    /*
     * 中文说明：参考强卸载方案的“先阻断外部访问”阶段。公开 WDK 没有
     * IoLockRemoveDevice，因此在显式 destructive fallback 中先用拒绝 IRP stub
     * 中和 dispatch 表，并在删除设备前把设备重新标为 initializing，减少新的
     * create/IRP 进入目标驱动代码窗口。
     */
    blockNewDeviceAccess = (clearDispatchForPath || deleteDeviceObjects) ? TRUE : FALSE;
    if (clearDispatchForPath) {
        KswordARKDriverUnloadClearDispatchUnsafe(UnloadContext->DriverObject);
        UnloadContext->CleanupFlagsApplied |= clearDispatchFlag;
        dispatchCleared = TRUE;
    }
    if (blockNewDeviceAccess) {
        NTSTATUS blockStatus = KswordARKDriverUnloadBlockNewDeviceCreatesUnsafe(
            UnloadContext->DriverObject,
            NULL);
        if (!NT_SUCCESS(blockStatus)) {
            return blockStatus;
        }
    }

    if (deleteDeviceObjects) {
        ULONG deletedDeviceCount = 0UL;
        ULONG detachedDeviceCount = 0UL;
        const BOOLEAN detachDeviceStacks =
            (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS) != 0UL
            ? TRUE
            : FALSE;
        NTSTATUS deleteStatus = KswordARKDriverUnloadDeleteDeviceObjectsUnsafe(
            UnloadContext->DriverObject,
            detachDeviceStacks,
            &deletedDeviceCount,
            &detachedDeviceCount);
        UnloadContext->DeletedDeviceCount = deletedDeviceCount;
        UnloadContext->DetachedDeviceCount = detachedDeviceCount;
        UnloadContext->CleanupFlagsApplied |=
            (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS) != 0UL
            ? KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS
            : KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD;
        if (detachDeviceStacks) {
            UnloadContext->CleanupFlagsApplied |=
                KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS;
        }
        if (!NT_SUCCESS(deleteStatus)) {
            return deleteStatus;
        }
    }
    if (DriverUnloadWasCalled && !deleteDeviceObjects) {
        NTSTATUS noDeviceStatus = KswordARKDriverUnloadRequireNoDeviceObjectsUnsafe(
            UnloadContext->DriverObject);
        if (!NT_SUCCESS(noDeviceStatus)) {
            return noDeviceStatus;
        }
    }

    if ((UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT) != 0UL) {
        __try {
            ObMakeTemporaryObject(UnloadContext->DriverObject);
            UnloadContext->CleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode();
        }
    }
    if ((UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER) != 0UL) {
        KswordARKDriverUnloadClearUnloadPointerUnsafe(UnloadContext->DriverObject);
        UnloadContext->CleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER;
    }
    if (DriverUnloadWasCalled &&
        (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD) != 0UL) {
        if (!dispatchCleared) {
            KswordARKDriverUnloadClearDispatchUnsafe(UnloadContext->DriverObject);
            UnloadContext->CleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD;
            dispatchCleared = TRUE;
        }
    }
    if (!DriverUnloadWasCalled &&
        (UnloadContext->Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD) != 0UL) {
        if (!dispatchCleared) {
            KswordARKDriverUnloadClearDispatchUnsafe(UnloadContext->DriverObject);
            UnloadContext->CleanupFlagsApplied |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD;
            dispatchCleared = TRUE;
        }
    }

    return cleanupStatus;
}

/* 中文说明：将 R3 请求 flags 降级为 R0 实际允许执行的 flags。 */
static ULONG
KswordARKDriverUnloadSanitizeFlags(
    _In_ ULONG RequestedFlags
    )
{
    // 输入：R3 原始强卸载 flags。
    // 处理：保留定位类 flag；若没有 ALLOW_DESTRUCTIVE_CLEANUP，则清除所有持久改写/移除类 flag。
    // 返回：R0 本次实际执行的 flags，用于回填响应并驱动后续逻辑。
    const ULONG mutatingMask =
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;

    if ((RequestedFlags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) == 0UL) {
        return RequestedFlags & ~mutatingMask;
    }
    return RequestedFlags;
}

/* 中文说明：目标没有 DriverUnload 时，判断是否仍需进入后处理分支。 */
static BOOLEAN
KswordARKDriverUnloadShouldCleanupWithoutUnload(
    _In_ ULONG Flags
    )
{
    // 输入：R3 传入的强卸载 flags。
    // 处理：仅当显式允许持久清理且携带具体清理位时才返回 TRUE。
    // 返回：TRUE 表示没有 DriverUnload 也要执行后处理；FALSE 表示直接报告缺少 DriverUnload。
    if ((Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP) == 0UL) {
        return FALSE;
    }
    if ((Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD) != 0UL) {
        return TRUE;
    }
    if ((Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER) != 0UL) {
        return TRUE;
    }
    if ((Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD) != 0UL) {
        return TRUE;
    }
    if ((Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS) != 0UL) {
        return TRUE;
    }
    if ((Flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT) != 0UL) {
        return TRUE;
    }
    return FALSE;
}

/* 中文说明：判断本次请求是否显式要求 DriverObject 后处理/中和。 */
static BOOLEAN
KswordARKDriverUnloadHasCleanupRequest(
    _In_ ULONG Flags
    )
{
    // 输入：R3 传入的强制卸载 flags。
    // 处理：只检查会改变 DriverObject/回调状态的清理位，不依赖 FORCE_CLEANUP 组合宏。
    // 返回：TRUE 表示调用 DriverUnload 前后还请求了额外清理动作；FALSE 表示只调用 DriverUnload。
    const ULONG cleanupMask =
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS |
        KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN;

    return ((Flags & cleanupMask) != 0UL) ? TRUE : FALSE;
}

/* 中文说明：把 preflight 的“成功但不可执行”状态归一成明确拒绝码。 */
static NTSTATUS
KswordARKDriverUnloadPreflightDenyStatus(
    _In_opt_ const KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Preflight
    )
{
    // 输入：卸载前预检结果，可为空。
    // 处理：优先保留 preflight 中已经计算出的具体失败原因；若状态仍为成功，
    //      根据关键布尔证据补一个稳定 NTSTATUS，避免 R3 看到 lastStatus=0。
    // 返回：可直接写入 response->lastStatus / waitStatus 的失败 NTSTATUS。
    if (Preflight == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!NT_SUCCESS(Preflight->Status)) {
        return Preflight->Status;
    }
    if (Preflight->IsSelfModule || Preflight->IsCoreKernelModule) {
        return STATUS_DRIVER_BLOCKED_CRITICAL;
    }
    if (Preflight->HasDeviceLoop || Preflight->HasCrossDriverAttach) {
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    if (!Preflight->HasThreadScan) {
        return NT_SUCCESS(Preflight->ThreadScanStatus)
            ? STATUS_REQUEST_NOT_ACCEPTED
            : Preflight->ThreadScanStatus;
    }
    if (!Preflight->HasCallbackScan) {
        return NT_SUCCESS(Preflight->CallbackScanStatus)
            ? STATUS_REQUEST_NOT_ACCEPTED
            : Preflight->CallbackScanStatus;
    }
    if (Preflight->HasModuleResidentThreads) {
        return STATUS_DEVICE_BUSY;
    }
    if (Preflight->HasModuleCallbacks) {
        return STATUS_DEVICE_BUSY;
    }
    if (Preflight->HasLoaderLinkMismatch || Preflight->HasInvalidImageHeader) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (Preflight->HasAttachedDevice || Preflight->HasBusyDeviceReference) {
        return STATUS_DEVICE_BUSY;
    }
    if (!Preflight->HasValidDriverObjectOffsets ||
        (Preflight->DriverStart != 0ULL &&
            Preflight->LoaderDllBase != 0ULL &&
            Preflight->LoaderDllBase != Preflight->DriverStart)) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if (!Preflight->HasValidDynData ||
        !Preflight->HasPdbBackedDynData ||
        !Preflight->HasValidLoaderEvidence) {
        return STATUS_REQUEST_NOT_ACCEPTED;
    }
    if (!Preflight->HasServiceRegistryPath && !Preflight->HasDriverUnload) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    return STATUS_REQUEST_NOT_ACCEPTED;
}

/* 中文说明：集中判断是否允许从系统卸载失败降级到 direct DriverUnload/中和。 */
static BOOLEAN
KswordARKDriverUnloadCanUseDestructiveFallback(
    _In_opt_ const KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Preflight,
    _In_ ULONG Flags
    )
{
    // 输入：preflight 证据和已经过 sanitize 的请求 flags。
    // 处理：要求 ALLOW_DESTRUCTIVE_CLEANUP、PDB-backed DynData、loader 对齐、
    //      live _DRIVER_OBJECT 偏移自检全部通过，并且确实有可执行动作。
    // 返回：TRUE 表示可以进入强制 fallback；FALSE 表示必须只返回失败状态。
    if (Preflight == NULL) {
        return FALSE;
    }
    if (!Preflight->AllowDestructiveCleanup ||
        !Preflight->HasValidDynData ||
        !Preflight->HasPdbBackedDynData ||
        !Preflight->HasValidDriverObjectOffsets ||
        !Preflight->HasValidLoaderEvidence ||
        !Preflight->HasThreadScan ||
        !Preflight->HasCallbackScan) {
        return FALSE;
    }
    if (!KswordARKDriverUnloadHasCleanupRequest(Flags)) {
        return FALSE;
    }
    if (!Preflight->AllowDirectUnload &&
        !KswordARKDriverUnloadShouldCleanupWithoutUnload(Flags)) {
        return FALSE;
    }
    return TRUE;
}

/* 中文说明：仅在 Zw 卸载成功但闭环仍 busy 时，判断是否允许做后置中和。 */
/* 中文说明：判断本次强制 fallback 是否允许在 DriverUnload 前先移除目标模块回调。 */
static BOOLEAN
KswordARKDriverUnloadCanPreCleanupCallbacks(
    _In_opt_ const KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Preflight,
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* Request
    )
{
    // 输入：preflight 证据和本地请求快照。
    // 处理：回调清理只在模块基址明确、基址与 DriverStart 一致、且强制 fallback
    //      已经满足 PDB-backed 安全门时启用；服务名路径不带基址时拒绝回调清理。
    // 返回：TRUE 表示可以调用按模块基址回调清理；FALSE 表示不能执行该高危步骤。
    if (Preflight == NULL || Request == NULL) {
        return FALSE;
    }
    if ((Request->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) == 0UL ||
        (Request->flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT) == 0UL ||
        Request->targetModuleBase == 0ULL) {
        return FALSE;
    }
    if (Request->targetModuleBase != Preflight->DriverStart) {
        return FALSE;
    }
    return KswordARKDriverUnloadCanUseDestructiveFallback(Preflight, Request->flags);
}

/* 中文说明：纯系统卸载线程；只携带服务注册表路径，不额外持有 DriverObject 引用。 */
static VOID
KswordARKDriverUnloadZwThreadRoutine(
    _In_opt_ PVOID StartContext
    )
{
    PKSW_DRIVER_UNLOAD_ZW_CONTEXT unloadContext = (PKSW_DRIVER_UNLOAD_ZW_CONTEXT)StartContext;
    UNICODE_STRING serviceRegistryPath;
    NTSTATUS threadStatus = STATUS_INVALID_PARAMETER;

    if (unloadContext == NULL || unloadContext->ServiceRegistryPath[0] == L'\0') {
        if (unloadContext != NULL) {
            KswordARKDriverUnloadReleaseZwContext(unloadContext);
        }
        PsTerminateSystemThread(threadStatus);
        return;
    }

    RtlInitUnicodeString(&serviceRegistryPath, unloadContext->ServiceRegistryPath);
    threadStatus = ZwUnloadDriver(&serviceRegistryPath);
    unloadContext->UnloadStatus = threadStatus;
    KswordARKDriverUnloadReleaseZwContext(unloadContext);
    PsTerminateSystemThread(threadStatus);
}

/* 中文说明：运行不持有 DriverObject 引用的纯 ZwUnloadDriver 路径。 */
static NTSTATUS
KswordARKDriverUnloadRunZwOnly(
    _In_reads_(KSWORD_ARK_DRIVER_IMAGE_PATH_CHARS) const WCHAR* ServiceRegistryPath,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ NTSTATUS* WaitStatusOut,
    _Out_ NTSTATUS* UnloadStatusOut
    )
{
    HANDLE threadHandle = NULL;
    PETHREAD threadObject = NULL;
    LARGE_INTEGER timeoutInterval;
    PKSW_DRIVER_UNLOAD_ZW_CONTEXT zwContext = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    // 输入：完整 Services 注册表路径和等待超时。
    // 处理：在系统线程中调用 ZwUnloadDriver；上下文只保存路径，不保存 DriverObject。
    // 返回：等待失败/超时直接返回对应状态；等待成功时返回 ZwUnloadDriver 的 NTSTATUS。
    if (ServiceRegistryPath == NULL ||
        ServiceRegistryPath[0] == L'\0' ||
        WaitStatusOut == NULL ||
        UnloadStatusOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *WaitStatusOut = STATUS_SUCCESS;
    *UnloadStatusOut = STATUS_PENDING;

#pragma warning(push)
#pragma warning(disable:4996)
    zwContext = (PKSW_DRIVER_UNLOAD_ZW_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(*zwContext),
        KSW_DRIVER_UNLOAD_TAG);
#pragma warning(pop)
    if (zwContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(zwContext, sizeof(*zwContext));
    zwContext->ReferenceCount = 2L;
    status = RtlStringCchCopyW(
        zwContext->ServiceRegistryPath,
        RTL_NUMBER_OF(zwContext->ServiceRegistryPath),
        ServiceRegistryPath);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(zwContext, KSW_DRIVER_UNLOAD_TAG);
        return status;
    }
    zwContext->UnloadStatus = STATUS_PENDING;

    if (TimeoutMilliseconds == 0UL) {
        TimeoutMilliseconds = KSW_DRIVER_UNLOAD_DEFAULT_TIMEOUT_MS;
    }
    if (TimeoutMilliseconds > KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS) {
        TimeoutMilliseconds = KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS;
    }

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        KswordARKDriverUnloadZwThreadRoutine,
        zwContext);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(zwContext, KSW_DRIVER_UNLOAD_TAG);
        return status;
    }

    status = ObReferenceObjectByHandle(
        threadHandle,
        SYNCHRONIZE,
        *PsThreadType,
        KernelMode,
        (PVOID*)&threadObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(threadHandle);
        KswordARKDriverUnloadReleaseZwContext(zwContext);
        return status;
    }
    timeoutInterval.QuadPart = -((LONGLONG)TimeoutMilliseconds * 10LL * 1000LL);
    *WaitStatusOut = KeWaitForSingleObject(
        threadObject,
        Executive,
        KernelMode,
        FALSE,
        &timeoutInterval);
    ObDereferenceObject(threadObject);
    ZwClose(threadHandle);

    if (*WaitStatusOut != STATUS_SUCCESS) {
        KswordARKDriverUnloadReleaseZwContext(zwContext);
        return *WaitStatusOut;
    }

    *UnloadStatusOut = zwContext->UnloadStatus;
    status = *UnloadStatusOut;
    KswordARKDriverUnloadReleaseZwContext(zwContext);
    return status;
}

/* Verify that no named DriverObject can be referenced after the final local dereference. */
static NTSTATUS
KswordARKDriverUnloadVerifyDriverObjectGone(
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* Request,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* NormalizedDriverName
    )
{
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST verifyRequest;
    PDRIVER_OBJECT referencedObject = NULL;
    WCHAR verifiedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    NTSTATUS status = STATUS_SUCCESS;

    // Inputs: original request snapshot and the normalized object path found before unload.
    // Processing: try the same lookup path used by the operation, but fall back to the exact
    // normalized name so module-base requests cannot hide a still-named DriverObject.
    // Return: STATUS_SUCCESS only when the object is no longer referenceable; otherwise a
    // blocking NTSTATUS that is safe to expose as the unload result.
    if (Request == NULL || NormalizedDriverName == NULL || NormalizedDriverName[0] == L'\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&verifyRequest, sizeof(verifyRequest));
    RtlCopyMemory(&verifyRequest, Request, sizeof(verifyRequest));
    status = KswordARKDriverUnloadReferenceByName(
        &verifyRequest,
        &referencedObject,
        verifiedName,
        RTL_NUMBER_OF(verifiedName));
    if (NT_SUCCESS(status)) {
        ObDereferenceObject(referencedObject);
        return STATUS_DEVICE_BUSY;
    }
    if (!KswordARKDriverUnloadShouldTryAlternateName(status) &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        return status;
    }

    RtlZeroMemory(&verifyRequest, sizeof(verifyRequest));
    verifyRequest.version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
    (VOID)RtlStringCchCopyW(
        verifyRequest.driverName,
        RTL_NUMBER_OF(verifyRequest.driverName),
        NormalizedDriverName);
    status = KswordARKDriverUnloadReferenceByName(
        &verifyRequest,
        &referencedObject,
        verifiedName,
        RTL_NUMBER_OF(verifiedName));
    if (NT_SUCCESS(status)) {
        ObDereferenceObject(referencedObject);
        return STATUS_DEVICE_BUSY;
    }
    if (!KswordARKDriverUnloadShouldTryAlternateName(status) &&
        status != STATUS_OBJECT_TYPE_MISMATCH) {
        return status;
    }

    return STATUS_SUCCESS;
}

/* Verify that the target image left both loader-list and module-list views. */
static NTSTATUS
KswordARKDriverUnloadVerifyLoaderGone(
    _In_ const KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Preflight
    )
{
    KSW_DYN_STATE dynState;
    KSW_DRIVER_INTEGRITY_LDR_TARGET ldrTarget;
    KSW_HOOK_SYSTEM_MODULE_INFORMATION* moduleInfo = NULL;
    ULONG moduleInfoBytes = 0UL;
    NTSTATUS loaderStatus = STATUS_SUCCESS;
    NTSTATUS moduleStatus = STATUS_SUCCESS;
    BOOLEAN checkedAnyView = FALSE;

    // Inputs: preflight evidence containing the exact DriverStart/module base.
    // Processing: re-walk PsLoadedModuleList with PDB-backed offsets, then compare the
    // public SystemModuleInformation snapshot. Both are read-only checks.
    // Return: STATUS_SUCCESS when no view still owns the target base; failure when the
    // image is still listed or when every verification view is unavailable.
    if (Preflight == NULL || Preflight->DriverStart == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&dynState, sizeof(dynState));
    RtlZeroMemory(&ldrTarget, sizeof(ldrTarget));
    KswordARKDynDataSnapshot(&dynState);
    if (dynState.Initialized &&
        dynState.NtosActive &&
        KswordARKDriverUnloadHasPdbBackedDynData(&dynState)) {
        checkedAnyView = TRUE;
        loaderStatus = KswordARKDriverIntegrityFindLoadedModule(
            &dynState,
            Preflight->DriverStart,
            &ldrTarget);
        if (NT_SUCCESS(loaderStatus) && ldrTarget.Found) {
            return STATUS_IMAGE_ALREADY_LOADED;
        }
        if (!NT_SUCCESS(loaderStatus) &&
            loaderStatus != STATUS_NOT_FOUND) {
            return loaderStatus;
        }
    }

    moduleStatus = KswordARKHookBuildModuleSnapshot(&moduleInfo, &moduleInfoBytes);
    if (NT_SUCCESS(moduleStatus) && moduleInfo != NULL) {
        checkedAnyView = TRUE;
        if (KswordARKDriverIntegrityFindModuleForAddress(
                moduleInfo,
                Preflight->DriverStart) != NULL) {
            ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
            return STATUS_IMAGE_ALREADY_LOADED;
        }
        ExFreePoolWithTag(moduleInfo, KSW_HOOK_SCAN_TAG);
    }
    else if (!checkedAnyView) {
        return moduleStatus;
    }

    return checkedAnyView ? STATUS_SUCCESS : STATUS_REQUEST_NOT_ACCEPTED;
}

/* Close the ReactOS-style strong-unload loop after local references are released. */
static NTSTATUS
KswordARKDriverUnloadVerifyClosedLoop(
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* Request,
    _In_reads_(KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS) const WCHAR* NormalizedDriverName,
    _In_ const KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Preflight
    )
{
    ULONG attemptIndex = 0UL;
    NTSTATUS lastStatus = STATUS_SUCCESS;
    LARGE_INTEGER delayInterval;

    // Inputs: request snapshot, normalized DriverObject name, and preflight loader evidence.
    // Processing: retry a short bounded object/loader verification window after the final
    // ObDereferenceObject, because object-manager and image-unload side effects may complete
    // just after the unload worker exits.
    // Return: STATUS_SUCCESS when both object and image are gone; otherwise the most specific
    // failure from the last verification pass.
    if (Request == NULL || NormalizedDriverName == NULL || Preflight == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    delayInterval.QuadPart = -((LONGLONG)KSW_DRIVER_UNLOAD_POST_VERIFY_DELAY_MS * 10LL * 1000LL);
    for (attemptIndex = 0UL;
        attemptIndex < KSW_DRIVER_UNLOAD_POST_VERIFY_RETRIES;
        ++attemptIndex) {
        NTSTATUS objectStatus = KswordARKDriverUnloadVerifyDriverObjectGone(
            Request,
            NormalizedDriverName);
        NTSTATUS loaderStatus = STATUS_SUCCESS;

        if (NT_SUCCESS(objectStatus)) {
            loaderStatus = KswordARKDriverUnloadVerifyLoaderGone(Preflight);
            if (NT_SUCCESS(loaderStatus)) {
                return STATUS_SUCCESS;
            }
            lastStatus = loaderStatus;
        }
        else {
            lastStatus = objectStatus;
        }

        if (attemptIndex + 1UL < KSW_DRIVER_UNLOAD_POST_VERIFY_RETRIES) {
            (VOID)KeDelayExecutionThread(
                KernelMode,
                FALSE,
                &delayInterval);
        }
    }

    return NT_SUCCESS(lastStatus) ? STATUS_REQUEST_NOT_ACCEPTED : lastStatus;
}

/* 中文说明：系统线程实际调用 DriverUnload，隔离调用栈和等待超时。 */
static VOID
KswordARKDriverUnloadThreadRoutine(
    _In_opt_ PVOID StartContext
    )
{
    PKSW_DRIVER_UNLOAD_CONTEXT unloadContext = (PKSW_DRIVER_UNLOAD_CONTEXT)StartContext;
    NTSTATUS threadStatus = STATUS_INVALID_PARAMETER;

    if (unloadContext == NULL || unloadContext->DriverObject == NULL) {
        if (unloadContext != NULL) {
            KswordARKDriverUnloadReleaseContext(unloadContext);
        }
        PsTerminateSystemThread(threadStatus);
        return;
    }

    unloadContext->UnloadStatus = STATUS_SUCCESS;
    unloadContext->CleanupStatus = STATUS_SUCCESS;
    unloadContext->DriverUnload = unloadContext->DriverObject->DriverUnload;

    unloadContext->CleanupStatus =
        KswordARKDriverUnloadApplyPreUnloadTeardownUnsafe(unloadContext);
    if (!NT_SUCCESS(unloadContext->CleanupStatus)) {
        unloadContext->UnloadStatus = unloadContext->CleanupStatus;
    }
    else if (unloadContext->AttemptDirectUnload && unloadContext->DriverUnload != NULL) {
        __try {
            unloadContext->DriverUnload(unloadContext->DriverObject);
            unloadContext->UnloadStatus = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            unloadContext->UnloadStatus = GetExceptionCode();
        }
        if (NT_SUCCESS(unloadContext->UnloadStatus)) {
            unloadContext->CleanupStatus = KswordARKDriverUnloadApplyCleanupUnsafe(
                unloadContext,
                TRUE);
        }
    }
    else if (KswordARKDriverUnloadShouldCleanupWithoutUnload(unloadContext->Flags)) {
        unloadContext->CleanupStatus = KswordARKDriverUnloadApplyCleanupUnsafe(
            unloadContext,
            FALSE);
        unloadContext->UnloadStatus = STATUS_PROCEDURE_NOT_FOUND;
    }
    else {
        unloadContext->UnloadStatus = STATUS_PROCEDURE_NOT_FOUND;
    }

    /* 中文说明：线程持有的 DriverObject 引用在这里释放，父线程只释放自己的引用。 */
    threadStatus = unloadContext->UnloadStatus;
    ObDereferenceObject(unloadContext->DriverObject);
    KswordARKDriverUnloadReleaseContext(unloadContext);
    PsTerminateSystemThread(threadStatus);
}

/* 中文说明：启动系统线程并等待卸载结果。 */
static NTSTATUS
KswordARKDriverUnloadRunThread(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ ULONG Flags,
    _In_ ULONG TimeoutMilliseconds,
    _Out_ NTSTATUS* WaitStatusOut,
    _Out_ NTSTATUS* UnloadStatusOut,
    _Out_ NTSTATUS* CleanupStatusOut,
    _Out_ PDRIVER_UNLOAD* DriverUnloadOut,
    _Out_ ULONG* CleanupFlagsAppliedOut,
    _Out_ ULONG* DeletedDeviceCountOut,
    _Out_ ULONG* DetachedDeviceCountOut,
    _Out_ ULONG* ThreadCandidatesOut,
    _Out_ ULONG* ThreadsTerminatedOut,
    _Out_ ULONG* ThreadFailuresOut,
    _Out_ NTSTATUS* ThreadLastStatusOut,
    _Out_ ULONG* CallbackCandidatesOut,
    _Out_ ULONG* CallbacksRemovedOut,
    _Out_ ULONG* CallbackFailuresOut,
    _Out_ NTSTATUS* CallbackLastStatusOut,
    _In_opt_ const KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT* Preflight
    )
{
    HANDLE threadHandle = NULL;
    PETHREAD threadObject = NULL;
    LARGE_INTEGER timeoutInterval;
    PKSW_DRIVER_UNLOAD_CONTEXT unloadContext = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (DriverObject == NULL ||
        WaitStatusOut == NULL ||
        UnloadStatusOut == NULL ||
        CleanupStatusOut == NULL ||
        DriverUnloadOut == NULL ||
        CleanupFlagsAppliedOut == NULL ||
        DeletedDeviceCountOut == NULL ||
        DetachedDeviceCountOut == NULL ||
        ThreadCandidatesOut == NULL ||
        ThreadsTerminatedOut == NULL ||
        ThreadFailuresOut == NULL ||
        ThreadLastStatusOut == NULL ||
        CallbackCandidatesOut == NULL ||
        CallbacksRemovedOut == NULL ||
        CallbackFailuresOut == NULL ||
        CallbackLastStatusOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *WaitStatusOut = STATUS_SUCCESS;
    *UnloadStatusOut = STATUS_SUCCESS;
    *CleanupStatusOut = STATUS_SUCCESS;
    *DriverUnloadOut = DriverObject->DriverUnload;
    *CleanupFlagsAppliedOut = 0UL;
    *DeletedDeviceCountOut = 0UL;
    *DetachedDeviceCountOut = 0UL;
    *ThreadCandidatesOut = 0UL;
    *ThreadsTerminatedOut = 0UL;
    *ThreadFailuresOut = 0UL;
    *ThreadLastStatusOut = STATUS_SUCCESS;
    *CallbackCandidatesOut = 0UL;
    *CallbacksRemovedOut = 0UL;
    *CallbackFailuresOut = 0UL;
    *CallbackLastStatusOut = STATUS_SUCCESS;

#pragma warning(push)
#pragma warning(disable:4996)
    unloadContext = (PKSW_DRIVER_UNLOAD_CONTEXT)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(*unloadContext),
        KSW_DRIVER_UNLOAD_TAG);
#pragma warning(pop)
    if (unloadContext == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* 中文说明：卸载线程可能超时后继续运行，因此上下文不能放在父线程栈上。 */
    RtlZeroMemory(unloadContext, sizeof(*unloadContext));
    unloadContext->ReferenceCount = 2L;
    unloadContext->DriverObject = DriverObject;
    unloadContext->Flags = Flags;
    unloadContext->UnloadStatus = STATUS_PENDING;
    unloadContext->CleanupStatus = STATUS_SUCCESS;
    unloadContext->DriverUnload = DriverObject->DriverUnload;
    unloadContext->ThreadLastStatus = STATUS_SUCCESS;
    unloadContext->CallbackLastStatus = STATUS_SUCCESS;
    unloadContext->AttemptDirectUnload =
        (Preflight != NULL &&
            Preflight->AllowDirectUnload &&
            Preflight->HasValidDynData &&
            Preflight->HasPdbBackedDynData &&
            Preflight->HasValidDriverObjectOffsets &&
            Preflight->HasValidLoaderEvidence) ? TRUE : FALSE;
    if (Preflight != NULL) {
        unloadContext->DriverStart = Preflight->DriverStart;
        unloadContext->DriverEnd = Preflight->DriverEnd;
        (VOID)RtlStringCchCopyW(
            unloadContext->ServiceRegistryPath,
            RTL_NUMBER_OF(unloadContext->ServiceRegistryPath),
            Preflight->ServiceRegistryPath);
    }
    ObReferenceObject(DriverObject);

    if (TimeoutMilliseconds == 0UL) {
        TimeoutMilliseconds = KSW_DRIVER_UNLOAD_DEFAULT_TIMEOUT_MS;
    }
    if (TimeoutMilliseconds > KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS) {
        TimeoutMilliseconds = KSW_DRIVER_UNLOAD_MAX_TIMEOUT_MS;
    }

    status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        KswordARKDriverUnloadThreadRoutine,
        unloadContext);
    if (!NT_SUCCESS(status)) {
        ObDereferenceObject(DriverObject);
        ExFreePoolWithTag(unloadContext, KSW_DRIVER_UNLOAD_TAG);
        return status;
    }

    status = ObReferenceObjectByHandle(
        threadHandle,
        SYNCHRONIZE,
        *PsThreadType,
        KernelMode,
        (PVOID*)&threadObject,
        NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(threadHandle);
        KswordARKDriverUnloadReleaseContext(unloadContext);
        return status;
    }
    timeoutInterval.QuadPart = -((LONGLONG)TimeoutMilliseconds * 10LL * 1000LL);
    *WaitStatusOut = KeWaitForSingleObject(
        threadObject,
        Executive,
        KernelMode,
        FALSE,
        &timeoutInterval);
    ObDereferenceObject(threadObject);
    ZwClose(threadHandle);

    if (*WaitStatusOut != STATUS_SUCCESS) {
        KswordARKDriverUnloadReleaseContext(unloadContext);
        return *WaitStatusOut;
    }

    *UnloadStatusOut = unloadContext->UnloadStatus;
    *CleanupStatusOut = unloadContext->CleanupStatus;
    *DriverUnloadOut = unloadContext->DriverUnload;
    *CleanupFlagsAppliedOut = unloadContext->CleanupFlagsApplied;
    *DeletedDeviceCountOut = unloadContext->DeletedDeviceCount;
    *DetachedDeviceCountOut = unloadContext->DetachedDeviceCount;
    *ThreadCandidatesOut = unloadContext->ThreadCandidates;
    *ThreadsTerminatedOut = unloadContext->ThreadsTerminated;
    *ThreadFailuresOut = unloadContext->ThreadFailures;
    *ThreadLastStatusOut = unloadContext->ThreadLastStatus;
    *CallbackCandidatesOut = unloadContext->CallbackCandidates;
    *CallbacksRemovedOut = unloadContext->CallbacksRemoved;
    *CallbackFailuresOut = unloadContext->CallbackFailures;
    *CallbackLastStatusOut = unloadContext->CallbackLastStatus;

    if (*DriverUnloadOut == NULL &&
        unloadContext->CleanupFlagsApplied != 0UL &&
        NT_SUCCESS(*CleanupStatusOut)) {
        *UnloadStatusOut = STATUS_SUCCESS;
        status = STATUS_SUCCESS;
    }
    else {
        status = !NT_SUCCESS(*CleanupStatusOut) ? *CleanupStatusOut : *UnloadStatusOut;
    }

    KswordARKDriverUnloadReleaseContext(unloadContext);
    return status;
}

NTSTATUS
KswordARKDriverForceUnloadDriver(
    _Out_writes_bytes_to_(OutputBufferLength, *BytesWrittenOut) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _In_ const KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST* Request,
    _Out_ size_t* BytesWrittenOut,
    _Out_opt_ KSW_DRIVER_UNLOAD_DIAGNOSTICS* Diagnostics
    )
/*++

Routine Description:

    Force-unload a DriverObject by name. 中文说明：第一优先路径只调用目标
    DriverObject->DriverUnload；当目标没有 DriverUnload 时，只有显式 flag
    才清 dispatch 表，不主动删除 DeviceObject。

Arguments:

    OutputBuffer - 固定响应缓冲。
    OutputBufferLength - 输出缓冲长度。
    Request - R3 请求，包含 DriverObject 名称和 flags。
    BytesWrittenOut - 返回写入字节数。

Return Value:

    STATUS_SUCCESS 表示响应包有效；底层卸载结果写入 response->lastStatus。

--*/
{
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE* response = NULL;
    KSWORD_ARK_FORCE_UNLOAD_DRIVER_REQUEST requestSnapshot;
    PDRIVER_OBJECT driverObject = NULL;
    WCHAR normalizedName[KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS] = { 0 };
    KSW_DRIVER_UNLOAD_PREFLIGHT_RESULT preflightResult;
    NTSTATUS status = STATUS_SUCCESS;
    NTSTATUS waitStatus = STATUS_SUCCESS;
    NTSTATUS unloadStatus = STATUS_SUCCESS;
    NTSTATUS cleanupStatus = STATUS_SUCCESS;
    NTSTATUS callbackCleanupStatus = STATUS_SUCCESS;
    PDRIVER_UNLOAD driverUnload = NULL;
    ULONG cleanupFlagsApplied = 0UL;
    ULONG deletedDeviceCount = 0UL;
    ULONG detachedDeviceCount = 0UL;
    ULONG threadCandidates = 0UL;
    ULONG threadsTerminated = 0UL;
    ULONG threadFailures = 0UL;
    NTSTATUS threadLastStatus = STATUS_SUCCESS;
    ULONG requestedFlags = 0UL;
    BOOLEAN directCallRequested = FALSE;
    BOOLEAN teardownRequested = FALSE;
    KSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT callbackCleanupResult;
    KSW_DRIVER_UNLOAD_CALLBACK_CLEANUP_RESULT teardownCallbackCleanupResult;

    if (Diagnostics != NULL) {
        RtlZeroMemory(Diagnostics, sizeof(*Diagnostics));
    }

    if (OutputBuffer == NULL || Request == NULL || BytesWrittenOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    RtlZeroMemory(&preflightResult, sizeof(preflightResult)); // 预检构建失败也必须可诊断。
    RtlZeroMemory(&callbackCleanupResult, sizeof(callbackCleanupResult));
    callbackCleanupResult.LastStatus = STATUS_SUCCESS;
    RtlZeroMemory(&teardownCallbackCleanupResult, sizeof(teardownCallbackCleanupResult));
    teardownCallbackCleanupResult.LastStatus = STATUS_SUCCESS;
    *BytesWrittenOut = 0U;
    if (OutputBufferLength < sizeof(KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /*
     * 中文说明：IOCTL_KSWORD_ARK_FORCE_UNLOAD_DRIVER 使用 METHOD_BUFFERED；
     * KMDF 可能让输入请求和输出响应指向同一块 SystemBuffer。
     * 后续会清零输出缓冲，因此必须先把 R3 请求完整复制到本地栈变量。
     */
    RtlCopyMemory(&requestSnapshot, Request, sizeof(requestSnapshot));
    requestedFlags = requestSnapshot.flags;
    if (Diagnostics != NULL) {
        Diagnostics->requestedFlags = requestedFlags;
    }

    RtlZeroMemory(OutputBuffer, OutputBufferLength);
    response = (KSWORD_ARK_FORCE_UNLOAD_DRIVER_RESPONSE*)OutputBuffer;
    response->version = KSWORD_ARK_FORCE_UNLOAD_DRIVER_PROTOCOL_VERSION;
    response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNKNOWN;
    response->reserved = requestedFlags;
    requestSnapshot.flags = KswordARKDriverUnloadSanitizeFlags(requestSnapshot.flags);
    if ((requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) != 0UL) {
        /*
         * 一个强拆模式位对应一条固定、不可重排的 R0 流程。调用方不能只挑
         * 某几个阶段，避免出现“删设备但未封入口”或“调 unload 但线程仍驻留”。
         */
        requestSnapshot.flags |=
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN_STAGES;
    }
    directCallRequested =
        (requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DIRECT_UNLOAD_CALL) != 0UL
        ? TRUE
        : FALSE;
    teardownRequested =
        (requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN) != 0UL
        ? TRUE
        : FALSE;
    if (Diagnostics != NULL) {
        Diagnostics->sanitizedFlags = requestSnapshot.flags;
    }
    response->flags = requestSnapshot.flags;
    response->lastStatus = STATUS_SUCCESS;
    response->waitStatus = STATUS_SUCCESS;
    response->callbackLastStatus = STATUS_SUCCESS;

    /*
     * 中文说明：强制卸载保留给恶意驱动处置场景，但默认只调用 DriverUnload。
     * 任何会持久改写 DriverObject、删除 DeviceObject 或移除回调的动作都必须
     * 同时带 ALLOW_DESTRUCTIVE_CLEANUP；旧 R3 的 FORCE_CLEANUP 会被降级，避免
     * 失败后留下半清理状态，导致目标驱动后续真实卸载时 bugcheck。
     */

    status = KswordARKDriverUnloadReferenceByName(
        &requestSnapshot,
        &driverObject,
        normalizedName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
    if (Diagnostics != NULL) {
        Diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_REFERENCE;
        Diagnostics->referenceStatus = status;
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_REFERENCE_FAILED;
        response->lastStatus = status;
        if (normalizedName[0] != L'\0') {
            /* 中文说明：失败时也回填规范化对象名，便于 R3 日志确认实际解析目标。 */
            (VOID)RtlStringCchCopyW(
                response->driverName,
                KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
                normalizedName);
        }
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    response->driverUnloadAddress = (ULONGLONG)(ULONG_PTR)driverObject->DriverUnload;
    RtlStringCchCopyW(
        response->driverName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS,
        normalizedName);

    /*
     * 中文说明：communication blind 和通用 IRP 编辑器都会持有目标对象引用
     * 与原始 dispatch。强卸载前必须先 RESTORE 或显式 ABANDON，避免丢失恢复
     * 身份；门禁同时匹配已引用对象和原始请求模块基址。
     */
    ULONG blockingFlags = 0UL; // 逐类记录未恢复记录，避免短路判断隐藏 busy 来源。
    if (KswordARKDriverCommunicationHasBlockingRecord(driverObject, requestSnapshot.targetModuleBase)) {
        blockingFlags |= KSWORD_ARK_UNLOAD_DIAG_COMMUNICATION; // 通信入口尚未恢复。
    }
    if (KswordARKDriverDispatchHasBlockingRecord(driverObject, requestSnapshot.targetModuleBase)) {
        blockingFlags |= KSWORD_ARK_UNLOAD_DIAG_DISPATCH; // dispatch 编辑尚未恢复。
    }
    if (KswordARKDriverImageHasBlockingRecord(driverObject, requestSnapshot.targetModuleBase)) {
        blockingFlags |= KSWORD_ARK_UNLOAD_DIAG_IMAGE_EDIT; // 映像编辑尚未恢复。
    }
    if (Diagnostics != NULL) {
        Diagnostics->blockingFlags = blockingFlags; // 保留精确阻塞项，未改变卸载许可。
    }
    if (blockingFlags != 0UL) {
        /* 中文说明：沿用固定 operation-failed 响应状态承载可重试的 busy 原因。 */
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        /* 中文说明：lastStatus 明确要求调用方先恢复通信入口。 */
        response->lastStatus = STATUS_DEVICE_BUSY;
        /* 中文说明：waitStatus 同步 busy，避免 UI 把该结果误判为等待超时。 */
        response->waitStatus = STATUS_DEVICE_BUSY;
        /* 中文说明：返回完整固定响应供 R3 展示恢复建议。 */
        *BytesWrittenOut = sizeof(*response);
        /* 中文说明：释放本次 force-unload 解析获得的临时对象引用。 */
        ObDereferenceObject(driverObject);
        /* 中文说明：协议层调用成功，具体拒绝原因位于响应状态。 */
        return STATUS_SUCCESS;
    }

    status = KswordARKDriverUnloadBuildPreflightResult(
        driverObject,
        normalizedName,
        requestSnapshot.targetModuleBase,
        requestSnapshot.flags,
        &preflightResult);
    if (Diagnostics != NULL) {
        Diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_PREFLIGHT;
        Diagnostics->preflightBuildStatus = status;
        KswordARKDriverUnloadCapturePreflightDiagnostics(Diagnostics, &preflightResult); // 保留失败预检已经得到的证据。
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        response->lastStatus = status;
        response->waitStatus = status;
        *BytesWrittenOut = sizeof(*response);
        ObDereferenceObject(driverObject);
        return STATUS_SUCCESS;
    }

    if (!preflightResult.AllowDirectUnload &&
        !preflightResult.AllowZwUnload &&
        !preflightResult.AllowDestructiveCleanup) {
        const NTSTATUS denyStatus = KswordARKDriverUnloadPreflightDenyStatus(&preflightResult);
        if (Diagnostics != NULL) {
            Diagnostics->preflightDenyStatus = denyStatus;
        }
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        response->lastStatus = denyStatus;
        response->waitStatus = denyStatus;
        *BytesWrittenOut = sizeof(*response);
        ObDereferenceObject(driverObject);
        return STATUS_SUCCESS;
    }

    if (!preflightResult.AllowDestructiveCleanup) {
        const ULONG destructiveMask =
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_ON_NO_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_AFTER_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_UNLOAD_POINTER |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ON_NO_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DELETE_DEVICE_OBJECTS_ALWAYS |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_CLEAR_DISPATCH_BEFORE_UNLOAD |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_TERMINATE_MODULE_THREADS |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DETACH_DEVICE_STACKS |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_DRIVER_OBJECT_TEARDOWN |
            KSWORD_ARK_DRIVER_UNLOAD_FLAG_ALLOW_DESTRUCTIVE_CLEANUP;
        requestSnapshot.flags &= ~destructiveMask;
        teardownRequested = FALSE;
    }
    if (Diagnostics != NULL) {
        Diagnostics->finalFlags = requestSnapshot.flags;
    }
    response->flags = requestSnapshot.flags;

    /*
     * 中文说明：ZwUnloadDriver 必须在不持有目标 DriverObject 引用的状态下执行。
     * ObReferenceObjectByName 得到的引用只用于 preflight；真正系统卸载前先释放。
     * 如果系统卸载失败且 preflight 允许强制路径，再重新引用对象进入手工卸载。
     */
    ObDereferenceObject(driverObject);
    driverObject = NULL;

    if (preflightResult.AllowZwUnload && !directCallRequested) {
        status = KswordARKDriverUnloadRunZwOnly(
            preflightResult.ServiceRegistryPath,
            requestSnapshot.timeoutMilliseconds,
            &waitStatus,
            &unloadStatus);
        if (Diagnostics != NULL) {
            Diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW;
            Diagnostics->zwRunStatus = status;
            Diagnostics->zwWaitStatus = waitStatus;
            Diagnostics->zwUnloadStatus = unloadStatus;
        }
        cleanupStatus = STATUS_SUCCESS;
        if (NT_SUCCESS(status)) {
            /*
             * 中文说明：ZwUnloadDriver 的返回值只说明系统卸载路径已正常返回，
             * 不能单独证明 DriverObject 已经不可引用、镜像也已离开 loader 视图。
             * 因此普通路径也必须通过同一闭环验证；验证失败时，如果调用方显式
             * 允许 destructive fallback，则继续进入 direct fallback，否则把失败
             * 原因回填给 R3，避免 UI 把“未真正卸载”显示成成功。
             */
            NTSTATUS verifyStatus = KswordARKDriverUnloadVerifyClosedLoop(
                &requestSnapshot,
                normalizedName,
                &preflightResult);
            if (Diagnostics != NULL) {
                Diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_ZW_VERIFY;
                Diagnostics->zwVerifyStatus = verifyStatus;
            }
            if (NT_SUCCESS(verifyStatus)) {
                response->lastStatus = status;
                response->waitStatus = waitStatus;
                response->cleanupFlagsApplied = 0UL;
                response->deletedDeviceCount = 0UL;
                response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED;
                *BytesWrittenOut = sizeof(*response);
                return STATUS_SUCCESS;
            }
            status = verifyStatus;
        }
        if (NT_SUCCESS(status) ||
            !KswordARKDriverUnloadCanUseDestructiveFallback(&preflightResult, requestSnapshot.flags)) {
            const NTSTATUS reportStatus = NT_SUCCESS(status)
                ? KswordARKDriverUnloadPreflightDenyStatus(&preflightResult)
                : status;
            if (Diagnostics != NULL && Diagnostics->preflightDenyStatus == STATUS_SUCCESS) {
                Diagnostics->preflightDenyStatus = NT_SUCCESS(status)
                    ? reportStatus
                    : KswordARKDriverUnloadPreflightDenyStatus(&preflightResult);
            }
            response->lastStatus = reportStatus;
            response->waitStatus = waitStatus;
            response->cleanupFlagsApplied = 0UL;
            response->deletedDeviceCount = 0UL;
            response->status = (reportStatus == STATUS_TIMEOUT || waitStatus == STATUS_TIMEOUT)
                ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_WAIT_TIMEOUT
                : KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
            *BytesWrittenOut = sizeof(*response);
            return STATUS_SUCCESS;
        }
    }

    if ((KswordARKDriverUnloadHasCleanupRequest(requestSnapshot.flags) &&
            !KswordARKDriverUnloadCanUseDestructiveFallback(
                &preflightResult,
                requestSnapshot.flags)) ||
        (!KswordARKDriverUnloadHasCleanupRequest(requestSnapshot.flags) &&
            (!directCallRequested || !preflightResult.AllowDirectUnload))) {
        const NTSTATUS denyStatus = KswordARKDriverUnloadPreflightDenyStatus(&preflightResult);
        if (Diagnostics != NULL) {
            Diagnostics->preflightDenyStatus = denyStatus;
        }
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
        response->lastStatus = denyStatus;
        response->waitStatus = denyStatus;
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }
    /*
     * 中文说明：ReactOS/I/O 管理器卸载模型不是“只调用 DriverUnload”。
     * direct fallback 只有在 DriverUnload 清空设备链后，把 DriverObject 标记为
     * temporary，并释放本驱动持有的最后引用，才有机会进入对象删除与镜像卸载
     * 闭环。因此进入强制 fallback 后 R0 自动补上 MAKE_TEMPORARY_OBJECT。
     */
    if (KswordARKDriverUnloadHasCleanupRequest(requestSnapshot.flags)) {
        requestSnapshot.flags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT;
    }
    if ((requestSnapshot.flags & KSWORD_ARK_DRIVER_UNLOAD_FLAG_REMOVE_CALLBACKS_BY_MODULE_BASE) != 0UL &&
        requestSnapshot.targetModuleBase == 0ULL &&
        preflightResult.DriverStart != 0ULL) {
        /*
         * 中文说明：R3 按 DriverObject 名称发起卸载时可能没有携带模块基址。
         * preflight 已经用 DriverObject/loader 证据确认 DriverStart，因此这里把
         * 可信的 DriverStart 作为内部回调清理目标，避免要求用户态重复传地址。
         */
        requestSnapshot.targetModuleBase = preflightResult.DriverStart;
        requestSnapshot.flags |= KSWORD_ARK_DRIVER_UNLOAD_FLAG_TARGET_MODULE_BASE_PRESENT;
    }
    if (Diagnostics != NULL) {
        Diagnostics->finalFlags = requestSnapshot.flags;
    }
    response->flags = requestSnapshot.flags;

    status = KswordARKDriverUnloadReferenceByName(
        &requestSnapshot,
        &driverObject,
        normalizedName,
        KSWORD_ARK_DRIVER_OBJECT_NAME_CHARS);
    if (Diagnostics != NULL) {
        Diagnostics->referenceStatus = status;
    }
    if (!NT_SUCCESS(status)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_REFERENCE_FAILED;
        response->lastStatus = status;
        response->waitStatus = waitStatus;
        *BytesWrittenOut = sizeof(*response);
        return STATUS_SUCCESS;
    }

    response->driverObjectAddress = (ULONGLONG)(ULONG_PTR)driverObject;
    response->driverUnloadAddress = (ULONGLONG)(ULONG_PTR)driverObject->DriverUnload;

    if (!teardownRequested &&
        KswordARKDriverUnloadCanPreCleanupCallbacks(&preflightResult, &requestSnapshot)) {
        callbackCleanupStatus = KswordARKDriverUnloadRemoveCallbacksByModuleBase(
            requestSnapshot.targetModuleBase,
            &callbackCleanupResult);
        response->callbackCandidates = callbackCleanupResult.Candidates;
        response->callbacksRemoved = callbackCleanupResult.Removed;
        response->callbackFailures = callbackCleanupResult.Failures;
        response->callbackLastStatus = callbackCleanupResult.LastStatus;
        if (!NT_SUCCESS(callbackCleanupStatus) &&
            response->callbackLastStatus == STATUS_SUCCESS) {
            response->callbackLastStatus = callbackCleanupStatus;
        }
    }

    status = KswordARKDriverUnloadRunThread(
        driverObject,
        requestSnapshot.flags,
        requestSnapshot.timeoutMilliseconds,
        &waitStatus,
        &unloadStatus,
        &cleanupStatus,
        &driverUnload,
        &cleanupFlagsApplied,
        &deletedDeviceCount,
        &detachedDeviceCount,
        &threadCandidates,
        &threadsTerminated,
        &threadFailures,
        &threadLastStatus,
        &teardownCallbackCleanupResult.Candidates,
        &teardownCallbackCleanupResult.Removed,
        &teardownCallbackCleanupResult.Failures,
        &teardownCallbackCleanupResult.LastStatus,
        &preflightResult);
    if (Diagnostics != NULL) {
        Diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT;
        Diagnostics->directRunStatus = status;
        Diagnostics->directWaitStatus = waitStatus;
        Diagnostics->directUnloadStatus = unloadStatus;
        Diagnostics->directCleanupStatus = cleanupStatus;
    }

    response->driverUnloadAddress = (ULONGLONG)(ULONG_PTR)driverUnload;
    response->lastStatus = status;
    response->waitStatus = waitStatus;
    response->cleanupFlagsApplied = cleanupFlagsApplied;
    response->deletedDeviceCount = deletedDeviceCount;
    response->detachedDeviceCount = detachedDeviceCount;
    response->threadCandidates = threadCandidates;
    response->threadsTerminated = threadsTerminated;
    response->threadFailures = threadFailures;
    response->threadLastStatus = threadLastStatus;
    if (teardownRequested) {
        callbackCleanupResult = teardownCallbackCleanupResult;
    }
    response->callbackCandidates = callbackCleanupResult.Candidates;
    response->callbacksRemoved = callbackCleanupResult.Removed;
    response->callbackFailures = callbackCleanupResult.Failures;
    response->callbackLastStatus = callbackCleanupResult.LastStatus;

    if (driverObject != NULL) {
        ObDereferenceObject(driverObject);
        driverObject = NULL;
    }
    if (NT_SUCCESS(status) &&
        NT_SUCCESS(cleanupStatus) &&
        cleanupFlagsApplied != 0UL &&
        (cleanupFlagsApplied & KSWORD_ARK_DRIVER_UNLOAD_FLAG_MAKE_TEMPORARY_OBJECT) != 0UL) {
        NTSTATUS verifyStatus = KswordARKDriverUnloadVerifyClosedLoop(
            &requestSnapshot,
            normalizedName,
            &preflightResult);
        if (Diagnostics != NULL) {
            Diagnostics->stages |= KSW_DRIVER_UNLOAD_DIAG_STAGE_DIRECT_VERIFY;
            Diagnostics->directVerifyStatus = verifyStatus;
        }
        if (!NT_SUCCESS(verifyStatus)) {
            status = verifyStatus;
            cleanupStatus = verifyStatus;
            response->lastStatus = verifyStatus;
        }
    }

    if (status == STATUS_TIMEOUT || waitStatus == STATUS_TIMEOUT) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_WAIT_TIMEOUT;
    }
    else if (!NT_SUCCESS(cleanupStatus)) {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_CLEANUP_FAILED;
    }
    else if (driverUnload == NULL && unloadStatus == STATUS_PROCEDURE_NOT_FOUND) {
        response->status = NT_SUCCESS(cleanupStatus) &&
            KswordARKDriverUnloadHasCleanupRequest(requestSnapshot.flags)
            ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP
            : KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_MISSING;
    }
    else if (NT_SUCCESS(status)) {
        response->status = teardownRequested
            ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_FORCED_CLEANUP
            : (directCallRequested
                ? KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOAD_ROUTINE_CALLED
                : KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNLOADED);
    }
    else {
        response->status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_OPERATION_FAILED;
    }

    if (Diagnostics != NULL && Diagnostics->finalFlags == 0UL) {
        Diagnostics->finalFlags = requestSnapshot.flags;
    }
    *BytesWrittenOut = sizeof(*response);
    return STATUS_SUCCESS;
}
