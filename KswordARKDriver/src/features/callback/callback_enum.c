/*++

Module Name:

    callback_enum.c

Abstract:

    Implements the read-only callback traversal IOCTL for KswordARK.

Environment:

    Kernel-mode Driver Framework

--*/

#include <fltKernel.h>
#include "callback_internal.h"
#define KSWORD_ARK_CALLBACK_EXTERNAL_ENABLE_FULL 1
#include "callback_external_core.h"
#include "callback_extended_kernel.h"
#include "ark/ark_dyndata.h"
#include "callback_global_fallback.h" // PE 函数边界、完整容器校验和统一安全读取。

#define KSWORD_ARK_CALLBACK_ENUM_TAG 'eCbK'
#define KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES 4096UL
#define KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES 0x300UL
#define KSWORD_ARK_CALLBACK_ENUM_NOTIFY_SLOT_COUNT 64UL
#define KSWORD_ARK_CALLBACK_ENUM_LIST_WALK_LIMIT 512UL
#define KSWORD_ARK_CALLBACK_ENUM_OBJECT_TYPE_SCAN_BYTES 0x300UL
#define KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_BACK_BYTES 0x80L
#define KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_FORWARD_BYTES 0x180L
#define KSWORD_ARK_CALLBACK_ENUM_FAST_REF_MASK (~(ULONG_PTR)0x0FULL)
#define KSWORD_ARK_CALLBACK_ENUM_MAX_PDB_STRUCT_OFFSET 0x1000UL
#define SystemModuleInformation 11UL

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef struct _KSWORD_ARK_CALLBACK_ENUM_CODE_CANDIDATE
{
    ULONG64 Address;
    LONG RelativeOffset;
} KSWORD_ARK_CALLBACK_ENUM_CODE_CANDIDATE;

typedef struct _KSWORD_ARK_CALLBACK_ENUM_OBJECT_SCAN_RESULT
{
    ULONG64 PreOperation;
    ULONG64 PostOperation;
    ULONG OperationMask;
    ULONG64 RegistrationBlock;
    BOOLEAN UsedPdbOffsets;
} KSWORD_ARK_CALLBACK_ENUM_OBJECT_SCAN_RESULT;

// 中文说明：用本驱动 ObRegisterCallbacks 的真实返回值校准常见布局，绝不把链指针当句柄。
static BOOLEAN KswordArkCallbackEnumCalibrateObjectHandle(ULONG64 Head, POBJECT_TYPE ObjectType)
{
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime(); // 真实注册句柄的唯一已知来源。
    ULONG64 ownHandle = runtime != NULL ? (ULONG64)(ULONG_PTR)runtime->ObRegistrationHandle : 0ULL; // 无自身注册不得校准。
    LIST_ENTRY link; // 遍历字段安全读取。
    ULONG64 node; // 当前列表项。
    ULONG index; // 有界预算。
    if (ownHandle == 0ULL || !KswordARKRuntimeReadMemory((PVOID)(ULONG_PTR)Head, &link, sizeof(link))) return FALSE; // 不能凭非零候选校准。
    node = (ULONG64)(ULONG_PTR)link.Flink; // 从真实头节点开始。
    for (index = 0UL; index < 512UL && node != 0ULL && node != Head; ++index) { // 限制损坏链的读取。
        ULONG64 values[7]; // LIST_ENTRY、Operations/Active、CallbackEntry、ObjectType、Pre/Post。
        if (!KswordARKRuntimeReadMemory((PVOID)(ULONG_PTR)node, values, sizeof(values))) return FALSE; // 完整结构才可解释。
        if (values[3] == ownHandle && values[4] == (ULONG64)(ULONG_PTR)ObjectType &&
            (ULONG)values[2] == (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE) && values[5] != 0ULL && values[6] == 0ULL) return TRUE; // 匹配自身公共注册配置与真实句柄。
        node = values[0]; // 不从邻近内存猜 registration。
    }
    return FALSE; // 未找到真实自身项则保留只读启发式展示。
}

typedef struct _KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT
{
    ULONG Source;
    ULONG TrustFlags;
    ULONG RemoveBehavior;
    ULONG ExtraFieldFlags;
    PCWSTR DetailPrefix;
} KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT;

typedef struct _KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE
{
    KSW_DYN_STATE State;
    BOOLEAN Active;
    ULONG64 NtosImageBase;
    ULONG NtosImageSize;
} KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE;

/* 中文说明：编译期锁定 V2/V3 的线缆布局，避免 R0/R3 因对齐差异解析错页。 */
C_ASSERT(sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2) == 24U);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2, entries) == 32U);
C_ASSERT(sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST) == 40U);
C_ASSERT(FIELD_OFFSET(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE, entries) == 48U);

typedef enum _KSWORD_ARK_CALLBACK_ENUM_OBJECT_LIST_STATE
{
    KswordArkCallbackEnumObjectListInvalid = 0,
    KswordArkCallbackEnumObjectListEmpty = 1,
    KswordArkCallbackEnumObjectListNonEmpty = 2
} KSWORD_ARK_CALLBACK_ENUM_OBJECT_LIST_STATE;

static const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT g_KswordArkCallbackEnumPdbNotifySourceContext = {
    KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE,
    KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED,
    KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API | KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION,
    KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED,
    L"PDB callback profile trusted notify array"
};

static const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT g_KswordArkCallbackEnumPdbRegistrySourceContext = {
    KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE,
    KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED,
    KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_NONE,
    KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED,
    L"PDB callback profile trusted registry list"
};

static const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT g_KswordArkCallbackEnumPdbObjectSourceContext = {
    KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE,
    KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE |
        KSWORD_ARK_CALLBACK_TRUST_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_TRUST_STORAGE_VALIDATED |
        KSWORD_ARK_CALLBACK_TRUST_STRUCTURE_SIGNATURE,
    KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
        KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION,
    KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_PROFILE_GATED |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE,
    L"PDB callback profile trusted object list"
};

/* 中文说明：两个常量分别限定兼容 V2 和快照 V3 响应的 entries 起始偏移。 */
static const ULONG g_KswordArkCallbackEnumHeaderBytesV3 =
    (ULONG)(sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE) - sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
static const ULONG g_KswordArkCallbackEnumHeaderBytesV2 =
    (ULONG)(sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2) - sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));

_Must_inspect_result_
static NTSTATUS
KswordArkCallbackEnumResolveModuleByAddress(
    _In_ ULONG64 CallbackAddress,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ ULONG64* ModuleBaseOut,
    _Out_opt_ ULONG* ModuleSizeOut
    );

extern NTSTATUS
KswordArkRegistryCallback(
    _In_opt_ PVOID callbackContext,
    _In_opt_ PVOID argument1,
    _In_opt_ PVOID argument2
    );

extern VOID
KswordArkProcessCreateNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

extern VOID
KswordArkThreadCreateNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

extern VOID
KswordArkLoadImageNotify(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo
    );

extern OB_PREOP_CALLBACK_STATUS
KswordArkObjectPreOperation(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

extern FLT_PREOP_CALLBACK_STATUS
FLTAPI
KswordArkMinifilterPreOperation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Outptr_result_maybenull_ PVOID* CompletionContext
    );

VOID
KswordArkCallbackEnumCopyWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_z_ PCWSTR Source
    )
/*++

Routine Description:

    把 NUL 结尾的宽字符串复制到固定响应字段。中文说明：函数总是截断并
    终止字符串，因此 R3 可以按固定字段安全转换。

Arguments:

    Destination - 输出宽字符缓冲区。
    DestinationChars - 输出缓冲区容量，单位为 WCHAR。
    Source - 可选输入宽字符串。

Return Value:

    无返回值。

--*/
{
    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    Destination[0] = L'\0';
    if (Source == NULL) {
        return;
    }

    (VOID)RtlStringCchCopyNW(Destination, (size_t)DestinationChars, Source, (size_t)(DestinationChars - 1UL));
    Destination[DestinationChars - 1UL] = L'\0';
}

VOID
KswordArkCallbackEnumCopyUnicode(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_opt_ PCUNICODE_STRING Source
    )
{
    size_t copyChars = 0U;

    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    Destination[0] = L'\0';
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return;
    }

    copyChars = (size_t)(Source->Length / sizeof(WCHAR));
    if (copyChars >= (size_t)DestinationChars) {
        copyChars = (size_t)DestinationChars - 1U;
    }

    RtlCopyMemory(Destination, Source->Buffer, copyChars * sizeof(WCHAR));
    Destination[copyChars] = L'\0';
}

static VOID
KswordArkCallbackEnumCopyAnsiPathToWide(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_reads_bytes_(SourceBytes) const UCHAR* Source,
    _In_ ULONG SourceBytes
    )
{
    ULONG index = 0UL;

    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }

    Destination[0] = L'\0';
    if (Source == NULL || SourceBytes == 0UL) {
        return;
    }

    for (index = 0UL; index + 1UL < DestinationChars && index < SourceBytes; ++index) {
        if (Source[index] == '\0') {
            break;
        }
        Destination[index] = (WCHAR)Source[index];
    }

    Destination[index] = L'\0';
}

VOID
KswordArkCallbackEnumInitModuleCache(
    _Out_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    初始化模块缓存结构。中文说明：缓存只在一次 IOCTL 枚举周期内使用，避免
    每解析一个回调地址都重复查询 SystemModuleInformation。

Arguments:

    ModuleCache - 输出模块缓存。

Return Value:

    无返回值。

--*/
{
    if (ModuleCache == NULL) {
        return;
    }

    ModuleCache->ModuleInfo = NULL;
    ModuleCache->ModuleInfoBytes = 0UL;
}

VOID
KswordArkCallbackEnumFreeModuleCache(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    释放模块缓存。中文说明：函数仅释放本枚举路径分配的非分页池，并把指针清零
    防止后续误用。

Arguments:

    ModuleCache - 输入输出模块缓存。

Return Value:

    无返回值。

--*/
{
    if (ModuleCache == NULL) {
        return;
    }

    if (ModuleCache->ModuleInfo != NULL) {
        ExFreePool(ModuleCache->ModuleInfo);
        ModuleCache->ModuleInfo = NULL;
    }
    ModuleCache->ModuleInfoBytes = 0UL;
}

_Must_inspect_result_
NTSTATUS
KswordArkCallbackEnumEnsureModuleCache(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache
    )
/*++

Routine Description:

    按需填充系统模块缓存。中文说明：私有回调扫描需要频繁判断候选函数地址是否
    落在已加载内核模块内，缓存后可减少 ZwQuerySystemInformation 开销。

Arguments:

    ModuleCache - 输入输出模块缓存。

Return Value:

    成功返回 STATUS_SUCCESS；分配或查询失败返回对应 NTSTATUS。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;

    if (ModuleCache == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ModuleCache->ModuleInfo != NULL) {
        return STATUS_SUCCESS;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH || requiredBytes == 0UL) {
        return STATUS_UNSUCCESSFUL;
    }

    ModuleCache->ModuleInfo = (KSWORD_ARK_CALLBACK_MODULE_INFORMATION*)KswordArkAllocateNonPaged(
        requiredBytes,
        KSWORD_ARK_CALLBACK_ENUM_TAG);
    if (ModuleCache->ModuleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ModuleCache->ModuleInfoBytes = requiredBytes;

    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        ModuleCache->ModuleInfo,
        requiredBytes,
        &requiredBytes);
    if (!NT_SUCCESS(status)) {
        KswordArkCallbackEnumFreeModuleCache(ModuleCache);
        return status;
    }

    return STATUS_SUCCESS;
}

_Must_inspect_result_
NTSTATUS
KswordArkCallbackEnumResolveModuleByAddressCached(
    _Inout_opt_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 CallbackAddress,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ ULONG64* ModuleBaseOut,
    _Out_opt_ ULONG* ModuleSizeOut
    )
/*++

Routine Description:

    使用缓存的系统模块表解析地址所属模块。中文说明：该函数不解引用回调函数
    地址，仅做数值范围比较，适合私有结构扫描后的候选地址过滤。

Arguments:

    ModuleCache - 可选模块缓存；为 NULL 时走原有一次性查询函数。
    CallbackAddress - 输入回调函数地址。
    ModulePath - 输出模块路径。
    ModulePathChars - 模块路径缓冲区容量。
    ModuleBaseOut - 可选输出模块基址。
    ModuleSizeOut - 可选输出模块大小。

Return Value:

    命中返回 STATUS_SUCCESS；未命中返回 STATUS_NOT_FOUND；缓存初始化失败返回
    对应 NTSTATUS。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG moduleIndex = 0UL;

    if (ModulePath == NULL || ModulePathChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    ModulePath[0] = L'\0';
    if (ModuleBaseOut != NULL) {
        *ModuleBaseOut = 0ULL;
    }
    if (ModuleSizeOut != NULL) {
        *ModuleSizeOut = 0UL;
    }
    if (CallbackAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (ModuleCache == NULL) {
        return KswordArkCallbackEnumResolveModuleByAddress(
            CallbackAddress,
            ModulePath,
            ModulePathChars,
            ModuleBaseOut,
            ModuleSizeOut);
    }

    status = KswordArkCallbackEnumEnsureModuleCache(ModuleCache);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (moduleIndex = 0UL; moduleIndex < ModuleCache->ModuleInfo->NumberOfModules; ++moduleIndex) {
        const KSWORD_ARK_CALLBACK_MODULE_ENTRY* moduleEntry =
            &ModuleCache->ModuleInfo->Modules[moduleIndex];
        const ULONG64 moduleBase = (ULONG64)(ULONG_PTR)moduleEntry->ImageBase;
        const ULONG64 moduleEnd = moduleBase + (ULONG64)moduleEntry->ImageSize;
        if (CallbackAddress < moduleBase || CallbackAddress >= moduleEnd) {
            continue;
        }

        if (ModuleBaseOut != NULL) {
            *ModuleBaseOut = moduleBase;
        }
        if (ModuleSizeOut != NULL) {
            *ModuleSizeOut = moduleEntry->ImageSize;
        }
        KswordArkCallbackEnumCopyAnsiPathToWide(
            ModulePath,
            ModulePathChars,
            moduleEntry->FullPathName,
            RTL_NUMBER_OF(moduleEntry->FullPathName));
        return STATUS_SUCCESS;
    }

    return STATUS_NOT_FOUND;
}

BOOLEAN
KswordArkCallbackEnumIsKernelModuleAddress(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 CandidateAddress
    )
/*++

Routine Description:

    判断候选地址是否位于任一已加载内核模块。中文说明：私有结构字段扫描会产生
    多个指针候选，本过滤用于优先保留真正代码地址。

Arguments:

    ModuleCache - 模块缓存。
    CandidateAddress - 候选地址。

Return Value:

    位于模块范围返回 TRUE；否则返回 FALSE。

--*/
{
    WCHAR modulePath[4];

    RtlZeroMemory(modulePath, sizeof(modulePath));
    return NT_SUCCESS(KswordArkCallbackEnumResolveModuleByAddressCached(
        ModuleCache,
        CandidateAddress,
        modulePath,
        RTL_NUMBER_OF(modulePath),
        NULL,
        NULL));
}

BOOLEAN
KswordArkCallbackEnumReadMemory(
    _In_ const VOID* SourceAddress,
    _Out_writes_bytes_(BytesToRead) VOID* DestinationBuffer,
    _In_ SIZE_T BytesToRead
    )
/*++

Routine Description:

    用统一安全读取器读取内核内存。中文说明：私有回调数组和链表没有公开同步契约，
    因此所有字段读取都必须短路径、边界化并能承受无效地址。

Arguments:

    SourceAddress - 输入源地址。
    DestinationBuffer - 输出缓冲区。
    BytesToRead - 读取字节数。

Return Value:

    完整读取返回 TRUE；地址无效、短读、参数错误或高 IRQL 返回 FALSE。

--*/
{
    if (SourceAddress == NULL || DestinationBuffer == NULL || BytesToRead == 0U) {
        return FALSE;
    }
    // 中文说明：候选地址必须用 MmCopyMemory 完整复制；高于 APC_LEVEL 时拒绝读取。
    return KswordARKRuntimeReadMemory(SourceAddress, DestinationBuffer, BytesToRead);
}

static BOOLEAN
KswordArkCallbackEnumReadUchar(
    _In_ ULONG64 Address,
    _Out_ UCHAR* ValueOut
    )
/*++

Routine Description:

    读取一个 UCHAR。中文说明：用于机器码模式匹配，所有访问均经过异常保护。

Arguments:

    Address - 输入地址。
    ValueOut - 输出字节。

Return Value:

    成功返回 TRUE；失败返回 FALSE。

--*/
{
    UCHAR value = 0U;

    if (ValueOut == NULL) {
        return FALSE;
    }
    if (!KswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)Address, &value, sizeof(value))) {
        *ValueOut = 0U;
        return FALSE;
    }
    *ValueOut = value;
    return TRUE;
}

static BOOLEAN
KswordArkCallbackEnumReadPointer(
    _In_ ULONG64 Address,
    _Out_ ULONG64* ValueOut
    )
/*++

Routine Description:

    读取一个指针宽度的值。中文说明：回调数组槽、链表字段和对象类型字段均通过
    该函数读取，避免裸解引用私有地址。

Arguments:

    Address - 输入指针值所在地址。
    ValueOut - 输出读取到的指针值。

Return Value:

    成功返回 TRUE；失败返回 FALSE。

--*/
{
    ULONG_PTR value = 0U;

    if (ValueOut == NULL) {
        return FALSE;
    }
    if (!KswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)Address, &value, sizeof(value))) {
        *ValueOut = 0ULL;
        return FALSE;
    }
    *ValueOut = (ULONG64)value;
    return TRUE;
}

static BOOLEAN
KswordArkCallbackEnumReadUlong(
    _In_ ULONG64 Address,
    _Out_ ULONG* ValueOut
    )
/*++

Routine Description:

    读取 ULONG 值。中文说明：用于读取对象回调 operation 掩码、notify enable mask
    等诊断字段。

Arguments:

    Address - 输入字段地址。
    ValueOut - 输出 ULONG。

Return Value:

    成功返回 TRUE；失败返回 FALSE。

--*/
{
    ULONG value = 0UL;

    if (ValueOut == NULL) {
        return FALSE;
    }
    if (!KswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)Address, &value, sizeof(value))) {
        *ValueOut = 0UL;
        return FALSE;
    }
    *ValueOut = value;
    return TRUE;
}

static BOOLEAN
KswordArkCallbackEnumReadListEntry(
    _In_ ULONG64 Address,
    _Out_ LIST_ENTRY* ListEntryOut
    )
/*++

Routine Description:

    读取 LIST_ENTRY。中文说明：注册表和对象回调链表遍历只读取 Flink/Blink，
    不修改链表内容。

Arguments:

    Address - 输入 LIST_ENTRY 地址。
    ListEntryOut - 输出链表项。

Return Value:

    成功返回 TRUE；失败返回 FALSE。

--*/
{
    if (ListEntryOut == NULL) {
        return FALSE;
    }
    return KswordArkCallbackEnumReadMemory(
        (PVOID)(ULONG_PTR)Address,
        ListEntryOut,
        sizeof(*ListEntryOut));
}

static BOOLEAN
KswordArkCallbackEnumReadUnicodeString(
    _In_ ULONG64 Address,
    _Out_ UNICODE_STRING* UnicodeStringOut
    )
/*++

Routine Description:

    读取 UNICODE_STRING 描述符。中文说明：仅复制描述符本身，实际字符串缓冲会在
    复制函数中再次做边界检查。

Arguments:

    Address - 输入 UNICODE_STRING 地址。
    UnicodeStringOut - 输出描述符。

Return Value:

    成功返回 TRUE；失败返回 FALSE。

--*/
{
    if (UnicodeStringOut == NULL) {
        return FALSE;
    }
    return KswordArkCallbackEnumReadMemory(
        (PVOID)(ULONG_PTR)Address,
        UnicodeStringOut,
        sizeof(*UnicodeStringOut));
}

static BOOLEAN
KswordArkCallbackEnumLooksLikeKernelPointer(
    _In_ ULONG64 CandidateAddress
    )
/*++

Routine Description:

    对候选内核指针做快速形态检查。中文说明：该函数只做地址范围和对齐检查，
    真正代码指针还需要模块表命中过滤。

Arguments:

    CandidateAddress - 候选地址。

Return Value:

    看起来像内核指针返回 TRUE；否则返回 FALSE。

--*/
{
    if (CandidateAddress == 0ULL) {
        return FALSE;
    }
    if (CandidateAddress < (ULONG64)(ULONG_PTR)MmUserProbeAddress) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordArkCallbackEnumPdbSourceIsProfile(
    _In_ ULONG Source
    )
/*++

Routine Description:

    Checks whether one DynData field was supplied by the applied PDB callback
    profile. This keeps trusted callback rows tied to PDB sourced fields only,
    instead of treating unavailable or runtime-pattern values as trusted.

Arguments:

    Source - DynData source identifier stored next to one callback RVA/offset.

Return Value:

    TRUE when Source is KSW_DYN_FIELD_SOURCE_PDB_PROFILE; otherwise FALSE.

--*/
{
    return Source == KSW_DYN_FIELD_SOURCE_PDB_PROFILE;
}

static BOOLEAN
KswordArkCallbackEnumPdbOffsetAvailable(
    _In_ ULONG Offset,
    _In_ ULONG Source
    )
/*++

Routine Description:

    Validates a PDB callback structure offset before it is used to index into a
    private kernel structure. Processing rejects unavailable, non-PDB sourced,
    or excessively large offsets so the caller can fall back to existing
    heuristic scanning.

Arguments:

    Offset - Structure offset captured in KSW_DYN_STATE.CallbackOffsets.
    Source - Source tag captured in KSW_DYN_STATE.CallbackOffsetSources.

Return Value:

    TRUE when the offset is PDB-sourced and within the callback enum safety
    window; otherwise FALSE.

--*/
{
    if (!KswordArkCallbackEnumPdbSourceIsProfile(Source)) {
        return FALSE;
    }
    if (Offset == KSW_DYN_OFFSET_UNAVAILABLE) {
        return FALSE;
    }
    if (Offset > KSWORD_ARK_CALLBACK_ENUM_MAX_PDB_STRUCT_OFFSET) {
        return FALSE;
    }
    return TRUE;
}

static NTSTATUS
KswordArkCallbackEnumCaptureDynDataProfile(
    _Out_ KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE* ProfileOut
    )
/*++

Routine Description:

    Captures the current DynData snapshot and extracts the callback PDB profile
    identity gate used by this file. Processing requires CallbackProfileActive,
    a present ntoskrnl identity, a non-zero image base, and a non-zero
    SizeOfImage before any RVA is allowed to become a VA.

Arguments:

    ProfileOut - Receives a zeroed profile wrapper and the copied DynData state.

Return Value:

    STATUS_SUCCESS when the callback profile identity is usable. A failure
    status means callers must keep the legacy pattern fallback behavior.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE profile;

    if (ProfileOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&profile, sizeof(profile));
    KswordARKDynDataSnapshot(&profile.State);

    if (!profile.State.CallbackProfileActive) {
        *ProfileOut = profile;
        return STATUS_NOT_SUPPORTED;
    }
    if (profile.State.Ntoskrnl.present == 0UL ||
        profile.State.Ntoskrnl.imageBase == 0ULL ||
        profile.State.Ntoskrnl.sizeOfImage == 0UL) {
        *ProfileOut = profile;
        return STATUS_NOT_FOUND;
    }
    if (!KswordArkCallbackEnumLooksLikeKernelPointer(profile.State.Ntoskrnl.imageBase)) {
        *ProfileOut = profile;
        return STATUS_ACCESS_VIOLATION;
    }

    profile.Active = TRUE;
    profile.NtosImageBase = profile.State.Ntoskrnl.imageBase;
    profile.NtosImageSize = profile.State.Ntoskrnl.sizeOfImage;
    *ProfileOut = profile;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordArkCallbackEnumPdbRvaToVa(
    _In_ const KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE* Profile,
    _In_ ULONG GlobalRva,
    _In_ ULONG GlobalSource,
    _In_ SIZE_T ProbeBytes,
    _Out_ ULONG64* AddressOut
    )
/*++

Routine Description:

    Converts one PDB callback global RVA to a kernel VA. Processing enforces
    the callback profile identity gate, PDB field source, rva < SizeOfImage,
    integer-overflow safety, kernel-address shape, and a small readable probe.

Arguments:

    Profile - Captured callback DynData profile wrapper.
    GlobalRva - RVA from KSW_DYN_STATE.CallbackGlobals.
    GlobalSource - Source tag from KSW_DYN_STATE.CallbackGlobalSources.
    ProbeBytes - Number of bytes to read as a basic VA readability check.
    AddressOut - Receives imageBase + GlobalRva on success.

Return Value:

    STATUS_SUCCESS when the RVA was converted and probed successfully. Any
    failure status tells the caller to use the existing private pattern path.

--*/
{
    UCHAR probeBuffer[sizeof(LIST_ENTRY)];
    ULONG64 address = 0ULL;

    if (AddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *AddressOut = 0ULL;
    if (Profile == NULL || !Profile->Active || !Profile->State.CallbackProfileActive) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!KswordArkCallbackEnumPdbSourceIsProfile(GlobalSource)) {
        return STATUS_NOT_FOUND;
    }
    if (GlobalRva == 0UL || GlobalRva == KSW_DYN_OFFSET_UNAVAILABLE) {
        return STATUS_NOT_FOUND;
    }
    if (GlobalRva >= Profile->NtosImageSize) {
        return STATUS_NOT_FOUND;
    }
    if (ProbeBytes > sizeof(probeBuffer)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (ProbeBytes != 0U && ((ULONG64)GlobalRva + (ULONG64)ProbeBytes) > (ULONG64)Profile->NtosImageSize) {
        return STATUS_NOT_FOUND;
    }
    if (Profile->NtosImageBase > (((ULONG64)~0ULL) - (ULONG64)GlobalRva)) {
        return STATUS_INTEGER_OVERFLOW;
    }

    address = Profile->NtosImageBase + (ULONG64)GlobalRva;
    if (!KswordArkCallbackEnumLooksLikeKernelPointer(address)) {
        return STATUS_ACCESS_VIOLATION;
    }
    if (ProbeBytes != 0U) {
        RtlZeroMemory(probeBuffer, sizeof(probeBuffer));
        if (!KswordArkCallbackEnumReadMemory((PVOID)(ULONG_PTR)address, probeBuffer, ProbeBytes)) {
            return STATUS_ACCESS_VIOLATION;
        }
    }

    *AddressOut = address;
    return STATUS_SUCCESS;
}

static VOID
KswordArkCallbackEnumApplySourceContext(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* SourceContext
    )
/*++

Routine Description:

    Applies source, trust, removal-behavior, and extra field flags to one
    callback enumeration row. Processing is intentionally additive for
    fieldFlags so existing row-specific fields remain intact.

Arguments:

    Entry - Callback enumeration row being populated.
    SourceContext - Optional traversal source metadata. NULL leaves the row as
        already initialized by the caller.

Return Value:

    No return value.

--*/
{
    if (Entry == NULL || SourceContext == NULL) {
        return;
    }

    Entry->source = SourceContext->Source;
    Entry->trustFlags = SourceContext->TrustFlags;
    Entry->removeBehavior = SourceContext->RemoveBehavior;
    Entry->fieldFlags |= SourceContext->ExtraFieldFlags;
}

static ULONG64
KswordArkCallbackEnumResolveRelativeAddress(
    _In_ ULONG64 InstructionAddress,
    _In_ ULONG DisplacementOffset
    )
/*++

Routine Description:

    解析 x64 RIP-relative/call 相对地址。中文说明：兼容 SKT64 的实现语义，
    结果为 InstructionAddress + Offset + sizeof(INT32) + disp32。

Arguments:

    InstructionAddress - 指令起始地址。
    DisplacementOffset - disp32 在指令中的偏移。

Return Value:

    成功返回解析出的绝对地址；读取失败返回 0。

--*/
{
    LONG displacement = 0L;

    if (InstructionAddress == 0ULL) {
        return 0ULL;
    }
    if (!KswordArkCallbackEnumReadMemory(
        (PVOID)(ULONG_PTR)(InstructionAddress + DisplacementOffset),
        &displacement,
        sizeof(displacement))) {
        return 0ULL;
    }

    return InstructionAddress + (ULONG64)DisplacementOffset + sizeof(LONG) + (LONG64)displacement;
}

static PVOID
KswordArkCallbackEnumGetSystemRoutine(
    _In_z_ PCWSTR RoutineName
    )
/*++

Routine Description:

    解析 ntoskrnl 导出例程。中文说明：用 MmGetSystemRoutineAddress 获取公开导出，
    再从导出函数代码定位私有全局变量。

Arguments:

    RoutineName - 输入导出例程名。

Return Value:

    成功返回例程地址；失败返回 NULL。

--*/
{
    UNICODE_STRING routineNameString;

    RtlInitUnicodeString(&routineNameString, RoutineName);
    return MmGetSystemRoutineAddress(&routineNameString);
}

static BOOLEAN
KswordArkCallbackEnumFindCodePattern(
    _In_ ULONG64 StartAddress,
    _In_ ULONG ScanBytes,
    _In_reads_bytes_(PatternBytes) const UCHAR* Pattern,
    _In_reads_bytes_(PatternBytes) const UCHAR* Mask,
    _In_ ULONG PatternBytes,
    _Out_ ULONG64* MatchAddressOut
    )
/*++

Routine Description:

    在指定代码窗口内查找字节模式。中文说明：Mask 中非零字节表示必须精确匹配，
    零字节表示通配；读取失败时跳过当前候选。

Arguments:

    StartAddress - 扫描起始地址。
    ScanBytes - 最大扫描长度。
    Pattern - 模式字节数组。
    Mask - 掩码字节数组。
    PatternBytes - 模式长度。
    MatchAddressOut - 输出命中地址。

Return Value:

    命中返回 TRUE；未命中返回 FALSE。

--*/
{
    ULONG offset = 0UL;
    ULONG patternIndex = 0UL;

    if (MatchAddressOut == NULL) {
        return FALSE;
    }
    *MatchAddressOut = 0ULL;
    if (StartAddress == 0ULL || Pattern == NULL || Mask == NULL || PatternBytes == 0UL || ScanBytes < PatternBytes) {
        return FALSE;
    }

    for (offset = 0UL; offset <= ScanBytes - PatternBytes; ++offset) {
        BOOLEAN matched = TRUE;
        for (patternIndex = 0UL; patternIndex < PatternBytes; ++patternIndex) {
            UCHAR value = 0U;
            if (!KswordArkCallbackEnumReadUchar(StartAddress + offset + patternIndex, &value)) {
                matched = FALSE;
                break;
            }
            if (Mask[patternIndex] != 0U && value != Pattern[patternIndex]) {
                matched = FALSE;
                break;
            }
        }
        if (matched) {
            *MatchAddressOut = StartAddress + offset;
            return TRUE;
        }
    }

    return FALSE;
}

_Must_inspect_result_
static NTSTATUS
KswordArkCallbackEnumResolveModuleByAddress(
    _In_ ULONG64 CallbackAddress,
    _Out_writes_(ModulePathChars) PWCHAR ModulePath,
    _In_ ULONG ModulePathChars,
    _Out_opt_ ULONG64* ModuleBaseOut,
    _Out_opt_ ULONG* ModuleSizeOut
    )
/*++

Routine Description:

    根据回调地址解析所属内核模块。中文说明：实现只读取系统模块列表，不
    解引用回调地址本身，因此适合诊断类只读枚举路径。

Arguments:

    CallbackAddress - 输入回调函数地址。
    ModulePath - 输出模块路径。
    ModulePathChars - 模块路径缓冲区容量。
    ModuleBaseOut - 可选输出模块基址。
    ModuleSizeOut - 可选输出模块大小。

Return Value:

    成功解析返回 STATUS_SUCCESS；未命中返回 STATUS_NOT_FOUND；查询失败返回
    对应 NTSTATUS。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG requiredBytes = 0UL;
    ULONG moduleIndex = 0UL;
    KSWORD_ARK_CALLBACK_MODULE_INFORMATION* moduleInfo = NULL;

    if (ModulePath == NULL || ModulePathChars == 0UL) {
        return STATUS_INVALID_PARAMETER;
    }

    ModulePath[0] = L'\0';
    if (ModuleBaseOut != NULL) {
        *ModuleBaseOut = 0ULL;
    }
    if (ModuleSizeOut != NULL) {
        *ModuleSizeOut = 0UL;
    }
    if (CallbackAddress == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0UL, &requiredBytes);
    if (status != STATUS_INFO_LENGTH_MISMATCH || requiredBytes == 0UL) {
        return STATUS_UNSUCCESSFUL;
    }

    moduleInfo = (KSWORD_ARK_CALLBACK_MODULE_INFORMATION*)KswordArkAllocateNonPaged(
        requiredBytes,
        KSWORD_ARK_CALLBACK_ENUM_TAG);
    if (moduleInfo == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, requiredBytes, &requiredBytes);
    if (!NT_SUCCESS(status)) {
        ExFreePool(moduleInfo);
        return status;
    }

    for (moduleIndex = 0UL; moduleIndex < moduleInfo->NumberOfModules; ++moduleIndex) {
        const KSWORD_ARK_CALLBACK_MODULE_ENTRY* moduleEntry = &moduleInfo->Modules[moduleIndex];
        const ULONG64 moduleBase = (ULONG64)(ULONG_PTR)moduleEntry->ImageBase;
        const ULONG64 moduleEnd = moduleBase + (ULONG64)moduleEntry->ImageSize;
        if (CallbackAddress < moduleBase || CallbackAddress >= moduleEnd) {
            continue;
        }

        if (ModuleBaseOut != NULL) {
            *ModuleBaseOut = moduleBase;
        }
        if (ModuleSizeOut != NULL) {
            *ModuleSizeOut = moduleEntry->ImageSize;
        }
        KswordArkCallbackEnumCopyAnsiPathToWide(
            ModulePath,
            ModulePathChars,
            moduleEntry->FullPathName,
            RTL_NUMBER_OF(moduleEntry->FullPathName));
        ExFreePool(moduleInfo);
        return STATUS_SUCCESS;
    }

    ExFreePool(moduleInfo);
    return STATUS_NOT_FOUND;
}

KSWORD_ARK_CALLBACK_ENUM_ENTRY*
KswordArkCallbackEnumReserveEntry(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    ULONG entryIndex = 0UL;

    if (Builder == NULL ||
        (Builder->EntryCapacity != 0UL && Builder->Entries == NULL)) {
        return NULL;
    }

    KswordArkCallbackEnumSnapshotCommitPending(Builder);

    /* 中文说明：先记录全量序号；分页前的行仍要完整枚举，保证 totalCount 稳定。 */
    entryIndex = Builder->TotalCount;
    Builder->TotalCount += 1UL;
    if (entryIndex < Builder->StartIndex) {
        RtlZeroMemory(&Builder->ScratchEntry, sizeof(Builder->ScratchEntry));
        Builder->ScratchEntry.size = sizeof(Builder->ScratchEntry);
        Builder->PendingEntry = &Builder->ScratchEntry;
        return &Builder->ScratchEntry;
    }

    /* 中文说明：当前页写满后继续用 scratch 行完成只读遍历和总数统计。 */
    if (Builder->ReturnedCount >= Builder->EntryCapacity) {
        Builder->Flags |= KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED;
        RtlZeroMemory(&Builder->ScratchEntry, sizeof(Builder->ScratchEntry));
        Builder->ScratchEntry.size = sizeof(Builder->ScratchEntry);
        Builder->PendingEntry = &Builder->ScratchEntry;
        return &Builder->ScratchEntry;
    }

    entry = &Builder->Entries[Builder->ReturnedCount];
    Builder->ReturnedCount += 1UL;
    RtlZeroMemory(entry, sizeof(*entry));
    entry->size = sizeof(*entry);
    Builder->PendingEntry = entry;
    return entry;
}

static VOID
KswordArkCallbackEnumFinalizeModule(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Entry == NULL || Entry->callbackAddress == 0ULL) {
        return;
    }

    status = KswordArkCallbackEnumResolveModuleByAddress(
        Entry->callbackAddress,
        Entry->modulePath,
        RTL_NUMBER_OF(Entry->modulePath),
        &Entry->moduleBase,
        &Entry->moduleSize);
    if (NT_SUCCESS(status)) {
        Entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE;
        Entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        Entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_RESOLVED;
        Entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_WITHIN_MODULE;
    }
    else {
        Entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        Entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_MISSING;
        Entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_MODULE_UNRESOLVED;
    }
}

VOID
KswordArkCallbackEnumFinalizeModuleCached(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_ENTRY* Entry
    )
/*++

Routine Description:

    使用模块缓存补全回调记录的模块字段。中文说明：私有扫描会产生大量记录，
    缓存版可减少系统模块查询次数。

Arguments:

    ModuleCache - 模块缓存。
    Entry - 输入输出回调枚举行。

Return Value:

    无返回值。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;

    if (Entry == NULL || Entry->callbackAddress == 0ULL) {
        return;
    }

    status = KswordArkCallbackEnumResolveModuleByAddressCached(
        ModuleCache,
        Entry->callbackAddress,
        Entry->modulePath,
        RTL_NUMBER_OF(Entry->modulePath),
        &Entry->moduleBase,
        &Entry->moduleSize);
    if (NT_SUCCESS(status)) {
        Entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE;
        Entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        Entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_RESOLVED;
        Entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_WITHIN_MODULE;
    }
    else {
        Entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNER_MODULE_RANGE;
        Entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_OWNER_MODULE_MISSING;
        Entry->ownerRangeState = KSWORD_ARK_CALLBACK_OWNER_RANGE_MODULE_UNRESOLVED;
    }
}

static VOID
KswordArkCallbackEnumCopyUnicodeSafe(
    _Out_writes_(DestinationChars) PWCHAR Destination,
    _In_ ULONG DestinationChars,
    _In_ const UNICODE_STRING* Source
    )
/*++

Routine Description:

    带异常保护地复制私有结构中的 UNICODE_STRING 字符串。中文说明：注册表和对象
    回调 altitude 来自私有链表，复制时限制最大长度并验证缓冲地址。

Arguments:

    Destination - 输出固定宽字符缓冲。
    DestinationChars - 输出缓冲容量。
    Source - 输入 UNICODE_STRING 描述符。

Return Value:

    无返回值。

--*/
{
    USHORT copyBytes = 0U;

    if (Destination == NULL || DestinationChars == 0UL) {
        return;
    }
    Destination[0] = L'\0';
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0U) {
        return;
    }
    if (Source->Length > Source->MaximumLength && Source->MaximumLength != 0U) {
        return;
    }
    if (Source->Length > (USHORT)((DestinationChars - 1UL) * sizeof(WCHAR))) {
        copyBytes = (USHORT)((DestinationChars - 1UL) * sizeof(WCHAR));
    }
    else {
        copyBytes = Source->Length;
    }
    if (copyBytes == 0U) {
        return;
    }
    if (!MmIsAddressValid(Source->Buffer) ||
        !MmIsAddressValid((PUCHAR)Source->Buffer + copyBytes - sizeof(WCHAR))) {
        return;
    }

    __try {
        RtlCopyMemory(Destination, Source->Buffer, copyBytes);
        Destination[copyBytes / sizeof(WCHAR)] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Destination[0] = L'\0';
    }
}

static VOID
KswordArkCallbackEnumAddSelfRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _In_ ULONG RegisteredMask,
    _In_ ULONG RequiredMask,
    _In_ ULONG CallbackClass,
    _In_ ULONG RegistrationType,
    _In_ ULONG OperationMask,
    _In_ ULONG ObjectTypeMask,
    _In_ ULONG64 CallbackAddress,
    _In_ ULONG64 ContextAddress,
    _In_ ULONG64 RegistrationAddress,
    _In_opt_z_ PCWSTR NameText,
    _In_opt_z_ PCWSTR AltitudeText,
    _In_opt_z_ PCWSTR DetailText
    )
/*++

Routine Description:

    写入 Ksword 自身注册的回调记录。中文说明：这些地址来自本驱动编译单元，
    不需要扫描系统私有链表即可准确展示当前 Ksword runtime 是否在线。

Arguments:

    Builder - 枚举响应构建器。
    RegisteredMask - runtime 中的已注册回调位图。
    RequiredMask - 当前记录对应的必需位。
    CallbackClass - 回调类别。
    RegistrationType - 具体注册 API 类型。
    OperationMask - 回调操作掩码。
    ObjectTypeMask - 对象类型掩码。
    CallbackAddress - 回调函数地址。
    ContextAddress - 回调上下文地址。
    RegistrationAddress - cookie 或 registration handle。
    NameText - 展示名称。
    AltitudeText - 可选 altitude 文本。
    DetailText - 详情文本。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = CallbackClass;
    entry->registrationType = RegistrationType;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF;
    entry->status = ((RegisteredMask & RequiredMask) != 0UL)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD;
    entry->operationMask = OperationMask;
    entry->objectTypeMask = ObjectTypeMask;
    if ((ObjectTypeMask & KSWORD_ARK_OBJECT_OP_TYPE_DESKTOP) != 0UL) {
        entry->registrationType = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DESKTOP_OBJECT;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    entry->callbackAddress = CallbackAddress;
    entry->contextAddress = ContextAddress;
    entry->registrationAddress = RegistrationAddress;

    if (CallbackAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS;
    }
    if (ContextAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS;
    }
    if (RegistrationAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    }
    if (OperationMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK;
    }
    if (ObjectTypeMask != 0UL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK;
    }
    if (RegistrationType != KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    if (NameText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
        KswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), NameText);
    }
    if (AltitudeText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        KswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), AltitudeText);
    }

    KswordArkCallbackEnumCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), DetailText);
    KswordArkCallbackEnumFinalizeModule(entry);
}

VOID
KswordArkCallbackEnumAddUnsupportedRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _In_ ULONG CallbackClass,
    _In_opt_z_ PCWSTR NameText,
    _In_opt_z_ PCWSTR DetailText
    )
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = CallbackClass;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    entry->lastStatus = STATUS_NOT_SUPPORTED;
    if (NameText != NULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
        KswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), NameText);
    }
    KswordArkCallbackEnumCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), DetailText);
}

static VOID
KswordArkCallbackEnumAddSelfCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    枚举 KswordARK 自身注册到系统中的回调。中文说明：runtime 持有注册位图、
    registry cookie 和 Ob registration handle，因此这些行能准确反映驱动状态。

Arguments:

    Builder - 枚举响应构建器。

Return Value:

    无返回值。

--*/
{
    ULONG registeredMask = 0UL;
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime();
    const ULONG64 contextAddress = (ULONG64)(ULONG_PTR)runtime;

    if (runtime != NULL) {
        registeredMask = runtime->RegisteredCallbacksMask;
    }

    KswordArkCallbackEnumAddSelfRow(
        Builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_REG_OP_ALL,
        0UL,
        (ULONG64)(ULONG_PTR)KswordArkRegistryCallback,
        contextAddress,
        (runtime != NULL) ? (ULONG64)runtime->RegistryCookie.QuadPart : 0ULL,
        L"KswordArkRegistryCallback",
        L"385201.5141",
        L"CmRegisterCallbackEx 注册表回调；外部 CmCallbackListHead 私有链表由“私有结构枚举”阶段另行展示。");

    KswordArkCallbackEnumAddSelfRow(
        Builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_PROCESS,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX,
        KSWORD_ARK_PROCESS_OP_CREATE,
        0UL,
        (ULONG64)(ULONG_PTR)KswordArkProcessCreateNotifyEx,
        contextAddress,
        0ULL,
        L"KswordArkProcessCreateNotifyEx",
        NULL,
        L"PsSetCreateProcessNotifyRoutineEx 进程创建回调；外部 Psp notify 数组由“私有结构枚举”阶段另行展示。");

    KswordArkCallbackEnumAddSelfRow(
        Builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_THREAD,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT,
        0UL,
        (ULONG64)(ULONG_PTR)KswordArkThreadCreateNotify,
        contextAddress,
        0ULL,
        L"KswordArkThreadCreateNotify",
        NULL,
        L"PsSetCreateThreadNotifyRoutine 线程创建/退出回调；外部 Psp notify 数组由“私有结构枚举”阶段另行展示。");

    KswordArkCallbackEnumAddSelfRow(
        Builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_IMAGE,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_IMAGE_OP_LOAD,
        0UL,
        (ULONG64)(ULONG_PTR)KswordArkLoadImageNotify,
        contextAddress,
        0ULL,
        L"KswordArkLoadImageNotify",
        NULL,
        L"PsSetLoadImageNotifyRoutine 镜像加载回调；外部 Psp notify 数组由“私有结构枚举”阶段另行展示。");

    KswordArkCallbackEnumAddSelfRow(
        Builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_OBJECT,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_OBJECT_OP_HANDLE_CREATE | KSWORD_ARK_OBJECT_OP_HANDLE_DUPLICATE,
        KSWORD_ARK_OBJECT_OP_TYPE_PROCESS | KSWORD_ARK_OBJECT_OP_TYPE_THREAD,
        (ULONG64)(ULONG_PTR)KswordArkObjectPreOperation,
        contextAddress,
        (runtime != NULL) ? (ULONG64)(ULONG_PTR)runtime->ObRegistrationHandle : 0ULL,
        L"KswordArkObjectPreOperation",
        L"385201.5142",
        L"ObRegisterCallbacks 对象句柄回调；仅覆盖 Process/Thread Handle Create/Duplicate。");

    KswordArkCallbackEnumAddSelfRow(
        Builder,
        registeredMask,
        KSWORD_ARK_CALLBACK_REGISTERED_MINIFILTER,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER,
        KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN,
        KSWORD_ARK_MINIFILTER_OP_ALL,
        0UL,
        (ULONG64)(ULONG_PTR)KswordArkMinifilterPreOperation,
        contextAddress,
        (runtime != NULL) ? (ULONG64)(ULONG_PTR)runtime->MiniFilterHandle : 0ULL,
        L"KswordArkMinifilterPreOperation",
        L"385210",
        L"FltRegisterFilter 文件系统微过滤器回调；同时服务文件监控和自定义回调规则。");

    KswordArkCallbackExtendedAddSelfBugcheckCallbacks(Builder);
}

static VOID
KswordArkCallbackEnumAddLocateRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _In_ ULONG CallbackClass,
    _In_opt_z_ PCWSTR NameText,
    _In_ ULONG64 LocatedAddress,
    _In_ NTSTATUS LocateStatus,
    _In_opt_z_ PCWSTR DetailText
    )
/*++

Routine Description:

    写入一个私有全局定位诊断行。中文说明：定位行帮助 R3 判断本机内核版本上
    SKT64 风格特征是否命中，并显示全局数组或链表头地址。

Arguments:

    Builder - 枚举响应构建器。
    CallbackClass - 回调类别。
    NameText - 展示名称。
    LocatedAddress - 定位到的全局地址。
    LocateStatus - 定位状态。
    DetailText - 详情文本。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = CallbackClass;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
    entry->status = NT_SUCCESS(LocateStatus)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED;
    entry->lastStatus = LocateStatus;
    entry->registrationAddress = LocatedAddress;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
    if (LocatedAddress != 0ULL) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    }
    KswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), NameText);
    KswordArkCallbackEnumCopyWide(entry->detail, RTL_NUMBER_OF(entry->detail), DetailText);
}

static BOOLEAN
KswordArkCallbackEnumFallbackExecutableProbe(
    _In_opt_ PVOID Context, _In_ ULONG_PTR Address)
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE* moduleCache = (KSWORD_ARK_CALLBACK_MODULE_CACHE*)Context; // 一次 IOCTL 共用模块快照。
    KSW_RUNTIME_IMAGE_VIEW view; // 模块 PE 节只在本次短验证中使用。
    ULONG64 base = 0ULL; // 找到回调所属的真实已加载模块。
    ULONG size = 0UL; // 完整映像大小供 PE 验证。
    WCHAR path[4]; // 路径无需展示，只取模块边界。
    if (!NT_SUCCESS(KswordArkCallbackEnumResolveModuleByAddressCached(moduleCache,
            (ULONG64)Address, path, RTL_NUMBER_OF(path), &base, &size)) ||
        !KswordARKRuntimeInitializeImageView((PVOID)(ULONG_PTR)base, size, &view)) {
        return FALSE; // 不以仅落入模块范围作为可执行函数证明。
    }
    return KswordARKRuntimeAddressIsExecutable(&view, Address, 1U); // 数据节指针不能作为函数。
}

static BOOLEAN
KswordArkCallbackEnumFallbackRegistryLayoutProbe(
    _In_opt_ PVOID Context, _In_ ULONG_PTR Head)
{
    UNREFERENCED_PARAMETER(Context); // 现有校准器读取当前自注册 Cookie/context/function 三元组。
    return KswordArkCallbackRegistryLayoutValidated((ULONG64)Head); // 无活跃自注册时不猜固定前缀。
}

static NTSTATUS
KswordArkCallbackEnumLocateValidatedGlobal(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ KSW_CALLBACK_GLOBAL_FAMILY Family, _Out_ ULONG64* AddressOut)
{
    KSW_RUNTIME_IMAGE_VIEW* view = NULL; // 避免在深层调用栈保存大型节视图。
    KSWORD_ARK_CALLBACK_RUNTIME* runtime = KswordArkCallbackGetRuntime(); // 当前自注册状态供家族身份验证。
    ULONG registeredBit = 0UL; // 每个通知家族各有当前注册位。
    ULONG_PTR knownCallback = 0U; // 只有注册位活跃才要求该函数出现在容器中。
    ULONG_PTR address = 0U; // 回退失败始终为零。
    NTSTATUS status = STATUS_SUCCESS; // 保留精确失败原因供现有诊断行显示。
    if (AddressOut == NULL) { // 先验证输出。
        return STATUS_INVALID_PARAMETER; // 无输出缓冲区时停止。
    }
    *AddressOut = 0ULL; // 未确认结构前不发布任何猜测。
    status = KswordArkCallbackEnumEnsureModuleCache(ModuleCache); // 当前枚举模块表必须完整可用。
    if (!NT_SUCCESS(status)) { // 模块枚举失败不能绕过可执行节验证。
        return status; // 保留模块枚举失败原因。
    }
    if (ModuleCache->ModuleInfo == NULL || ModuleCache->ModuleInfo->NumberOfModules == 0UL) {
        return STATUS_NOT_FOUND; // 没有当前 ntoskrnl 映像视图。
    }
    switch (Family) { // 当前已注册的已知函数给结构证据增加家族身份约束。
    case KswCallbackGlobalProcess: // 进程家族。
        registeredBit = KSWORD_ARK_CALLBACK_REGISTERED_PROCESS; // 只使用对应家族注册位。
        knownCallback = (ULONG_PTR)KswordArkProcessCreateNotifyEx; // 必须是本家族精确函数地址。
        break; // 家族身份选择完成。
    case KswCallbackGlobalThread: // 线程家族。
        registeredBit = KSWORD_ARK_CALLBACK_REGISTERED_THREAD; // 只使用对应家族注册位。
        knownCallback = (ULONG_PTR)KswordArkThreadCreateNotify; // 必须是本家族精确函数地址。
        break; // 家族身份选择完成。
    case KswCallbackGlobalImage: // 映像家族。
        registeredBit = KSWORD_ARK_CALLBACK_REGISTERED_IMAGE; // 只使用对应家族注册位。
        knownCallback = (ULONG_PTR)KswordArkLoadImageNotify; // 必须是本家族精确函数地址。
        break; // 家族身份选择完成。
    case KswCallbackGlobalRegistry: // 注册表家族。
        registeredBit = KSWORD_ARK_CALLBACK_REGISTERED_REGISTRY; // 只使用对应家族注册位。
        knownCallback = (ULONG_PTR)KswordArkRegistryCallback; // 必须是本家族精确函数地址。
        break; // 家族身份选择完成。
    default: // 非回调家族不扫描。
        return STATUS_INVALID_PARAMETER; // 不接受未知家族。
    }
    if (runtime == NULL || (runtime->RegisteredCallbacksMask & registeredBit) == 0UL) { // 不要求已失效注册。
        knownCallback = 0U; // 只保留当前活跃注册作为家族身份依据。
    }
    view = (KSW_RUNTIME_IMAGE_VIEW*)KswordArkAllocateNonPaged(sizeof(*view), KSWORD_ARK_CALLBACK_ENUM_TAG); // 固定视图预算。
    if (view == NULL) { // 不降级为不校验的扫描。
        return STATUS_INSUFFICIENT_RESOURCES; // 内存不足不扫描。
    }
    if (!KswordARKRuntimeInitializeImageView(ModuleCache->ModuleInfo->Modules[0].ImageBase,
            ModuleCache->ModuleInfo->Modules[0].ImageSize, view)) {
        ExFreePoolWithTag(view, KSWORD_ARK_CALLBACK_ENUM_TAG); // 释放视图。
        return STATUS_INVALID_IMAGE_FORMAT; // 当前内核 PE 不完整时停止。
    }
    status = KswordArkCallbackGlobalFallbackResolve(view, Family, knownCallback,
        KswordArkCallbackEnumFallbackExecutableProbe, KswordArkCallbackEnumFallbackRegistryLayoutProbe,
        ModuleCache, &address); // 两级公开导出调用图、唯一 writable 全局、完整双快照容器。
    ExFreePoolWithTag(view, KSWORD_ARK_CALLBACK_ENUM_TAG); // 不缓存可能因模块卸载失效的视图。
    *AddressOut = (ULONG64)address; // 仅唯一通过的地址非零。
    return status; // 保留 pattern 来源与既有非 PDB 信任等级。
}

static NTSTATUS
KswordArkCallbackEnumLocatePspNotifyEnableMask(
    _Out_ ULONG64* MaskAddressOut
    )
/*++

Routine Description:

    定位 PspNotifyEnableMask 私有全局。中文说明：该值不是回调项本身，但能辅助
    判断 Psp notify 路径是否处于启用状态。

Arguments:

    MaskAddressOut - 输出 mask 地址。

Return Value:

    成功返回 STATUS_SUCCESS；未命中返回 STATUS_NOT_FOUND。

--*/
{
    ULONG64 exportAddress = (ULONG64)(ULONG_PTR)KswordArkCallbackEnumGetSystemRoutine(L"PsSetLoadImageNotifyRoutineEx");
    ULONG64 matchAddress = 0ULL;
    ULONG64 maskAddress = 0ULL;
    static const UCHAR maskPattern[] = { 0x8BU, 0x05U, 0x00U, 0x00U, 0x00U, 0x00U, 0xA8U };
    static const UCHAR maskMask[] = { 1U, 1U, 0U, 0U, 0U, 0U, 1U };

    if (MaskAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *MaskAddressOut = 0ULL;
    if (exportAddress == 0ULL) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!KswordArkCallbackEnumFindCodePattern(
        exportAddress,
        KSWORD_ARK_CALLBACK_ENUM_PRIVATE_SCAN_BYTES,
        maskPattern,
        maskMask,
        sizeof(maskPattern),
        &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    maskAddress = KswordArkCallbackEnumResolveRelativeAddress(matchAddress, 2UL);
    if (maskAddress == 0ULL || !MmIsAddressValid((PVOID)(ULONG_PTR)maskAddress)) {
        return STATUS_NOT_FOUND;
    }

    *MaskAddressOut = maskAddress;
    return STATUS_SUCCESS;
}

static NTSTATUS
KswordArkCallbackEnumLocateObpCallPreOperationCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _Out_ ULONG64* RoutineAddressOut
    )
/*++

Routine Description:

    定位 ObpCallPreOperationCallbacks 内部例程。中文说明：SKT64 从 ntoskrnl 代码
    中匹配调用点；Ksword 复用该模式并限制在内核模块镜像范围内扫描。

Arguments:

    ModuleCache - 模块缓存。
    RoutineAddressOut - 输出内部例程地址。

Return Value:

    成功返回 STATUS_SUCCESS；未命中返回 STATUS_NOT_FOUND。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 ntBase = 0ULL;
    ULONG ntSize = 0UL;
    ULONG64 matchAddress = 0ULL;
    ULONG64 routineAddress = 0ULL;
    static const UCHAR pattern[] = {
        0xE8U, 0x00U, 0x00U, 0x00U, 0x00U,
        0x85U, 0xC0U, 0x78U, 0x00U,
        0x45U, 0x84U, 0x00U, 0x75U, 0x00U, 0x8BU
    };
    static const UCHAR mask[] = {
        1U, 0U, 0U, 0U, 0U,
        1U, 1U, 1U, 0U,
        1U, 1U, 0U, 1U, 0U, 1U
    };

    if (RoutineAddressOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *RoutineAddressOut = 0ULL;

    status = KswordArkCallbackEnumEnsureModuleCache(ModuleCache);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (ModuleCache->ModuleInfo == NULL || ModuleCache->ModuleInfo->NumberOfModules == 0UL) {
        return STATUS_NOT_FOUND;
    }

    ntBase = (ULONG64)(ULONG_PTR)ModuleCache->ModuleInfo->Modules[0].ImageBase;
    ntSize = ModuleCache->ModuleInfo->Modules[0].ImageSize;
    if (ntBase == 0ULL || ntSize < sizeof(pattern)) {
        return STATUS_NOT_FOUND;
    }

    if (!KswordArkCallbackEnumFindCodePattern(ntBase, ntSize, pattern, mask, sizeof(pattern), &matchAddress)) {
        return STATUS_NOT_FOUND;
    }

    routineAddress = KswordArkCallbackEnumResolveRelativeAddress(matchAddress, 1UL);
    if (routineAddress == 0ULL || !KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, routineAddress)) {
        return STATUS_NOT_FOUND;
    }

    *RoutineAddressOut = routineAddress;
    return STATUS_SUCCESS;
}

static VOID
KswordArkCallbackEnumClassifyNotifyRegistration(
    _In_ ULONG CallbackClass,
    _In_ ULONG64 ContextAddress,
    _Out_ ULONG* RegistrationTypeOut,
    _Outptr_ PCWSTR* RegistrationNameOut
    )
/*++

Routine Description:

    识别进程、线程与镜像 Notify 的注册 API。中文说明：这些 Psp 数组把
    Legacy/Ex 变体编码在 EX_CALLBACK_ROUTINE_BLOCK.Context 中；未知值
    保守保留为 Unknown，不把私有布局推断伪装成已确认类型。

Arguments:

    CallbackClass - 回调类别。
    ContextAddress - routine block 的 Context 原始值。
    RegistrationTypeOut - 输出共享协议注册类型。
    RegistrationNameOut - 输出名称后缀。

Return Value:

    无返回值。

--*/
{
    if (RegistrationTypeOut == NULL || RegistrationNameOut == NULL) {
        return;
    }

    *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN;
    *RegistrationNameOut = L"Unknown";

    if (CallbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS) {
        switch (ContextAddress) {
        case 0ULL:
            *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_LEGACY;
            *RegistrationNameOut = L"Legacy";
            break;

        case 2ULL:
            *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX;
            *RegistrationNameOut = L"Ex";
            break;

        case 6ULL:
            *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX2;
            *RegistrationNameOut = L"Ex2";
            break;

        default:
            break;
        }
    }
    else if (CallbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD) {
        switch (ContextAddress) {
        case 0ULL:
            *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_LEGACY;
            *RegistrationNameOut = L"Legacy";
            break;

        case 1ULL:
            *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_NON_SYSTEM;
            *RegistrationNameOut = L"Ex/NonSystem";
            break;

        case 2ULL:
            *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_SUBSYSTEMS;
            *RegistrationNameOut = L"Ex/Subsystems";
            break;

        default:
            break;
        }
    }
    else if (CallbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE) {
        switch (ContextAddress) {
        case 0ULL:
            *RegistrationTypeOut = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_LEGACY_OR_EX_DEFAULT;
            *RegistrationNameOut = L"Legacy/ExDefault";
            break;

        case 1ULL:
            *RegistrationTypeOut =
                KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_EX_CONFLICTING_ARCHITECTURE;
            *RegistrationNameOut = L"Ex/ConflictingArchitecture";
            break;

        default:
            break;
        }
    }
}

static VOID
KswordArkCallbackEnumAddNotifyArrayEntry(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG CallbackClass,
    _In_ ULONG OperationMask,
    _In_ ULONG SlotIndex,
    _In_ ULONG64 SlotAddress,
    _In_ ULONG64 FastRefValue,
    _In_ ULONG64 RoutineBlock,
    _In_ ULONG64 FunctionAddress,
    _In_ ULONG64 ContextAddress,
    _In_opt_z_ PCWSTR NamePrefix,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* SourceContext,
    _In_ ULONG SourceRva
    )
/*++

Routine Description:

    写入一个 Psp notify 数组项。中文说明：数组槽保存 EX_FAST_REF，低 4 位是
    引用计数，清除低位后得到 EX_CALLBACK_ROUTINE_BLOCK，再读取 Function/Context。

Arguments:

    Builder - 枚举响应构建器。
    ModuleCache - 模块缓存。
    CallbackClass - 回调类别。
    OperationMask - 操作掩码。
    SlotIndex - 数组槽索引。
    SlotAddress - 数组槽地址。
    FastRefValue - 原始 EX_FAST_REF 值。
    RoutineBlock - 解码后的 routine block 地址。
    FunctionAddress - 回调函数地址。
    ContextAddress - 回调上下文地址。
    NamePrefix - 行名称前缀。
    SourceContext - 可选来源元数据；PDB 路径用它标记 trusted/source/remove。
    SourceRva - PDB 全局 RVA；非 PDB 路径传 0，仅用于 detail 诊断。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;
    ULONG registrationType = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN;
    PCWSTR registrationName = L"Unknown";

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = CallbackClass;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    entry->operationMask = OperationMask;
    KswordArkCallbackEnumClassifyNotifyRegistration(
        CallbackClass,
        ContextAddress,
        &registrationType,
        &registrationName);
    entry->registrationType = registrationType;
    if (registrationType != KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_UNKNOWN) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    entry->callbackAddress = FunctionAddress;
    entry->contextAddress = ContextAddress;
    entry->registrationAddress = SlotAddress;
    KswordArkCallbackEnumApplySourceContext(entry, SourceContext);
    if (SourceContext != NULL &&
        (SourceContext->ExtraFieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE) != 0UL) {
        entry->rawStorageValue = FastRefValue;
    }
    if (SourceContext == NULL) {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    if (CallbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS ||
        CallbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD ||
        CallbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE) {
        (VOID)RtlStringCbPrintfW(
            entry->name,
            sizeof(entry->name),
            L"%ws/%ws[%lu]",
            (NamePrefix != NULL) ? NamePrefix : L"PspNotify",
            registrationName,
            (unsigned long)SlotIndex);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->name,
            sizeof(entry->name),
            L"%ws[%lu]",
            (NamePrefix != NULL) ? NamePrefix : L"PspNotify",
            (unsigned long)SlotIndex);
    }
    if (SourceContext != NULL && SourceContext->Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"%ws；RegistrationType=%ws，RVA=0x%08lX，slot=0x%p，EX_FAST_REF=0x%llX，RoutineBlock=0x%p，Function=0x%p，Context=0x%p。",
            (SourceContext->DetailPrefix != NULL) ? SourceContext->DetailPrefix : L"PDB callback profile trusted notify array",
            registrationName,
            (unsigned long)SourceRva,
            (PVOID)(ULONG_PTR)SlotAddress,
            FastRefValue,
            (PVOID)(ULONG_PTR)RoutineBlock,
            (PVOID)(ULONG_PTR)FunctionAddress,
            (PVOID)(ULONG_PTR)ContextAddress);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"Psp notify 私有数组项；RegistrationType=%ws，fallback=pattern scan，slot=0x%p，EX_FAST_REF=0x%llX，RoutineBlock=0x%p，Function=0x%p，Context=0x%p。",
            registrationName,
            (PVOID)(ULONG_PTR)SlotAddress,
            FastRefValue,
            (PVOID)(ULONG_PTR)RoutineBlock,
            (PVOID)(ULONG_PTR)FunctionAddress,
            (PVOID)(ULONG_PTR)ContextAddress);
    }
    KswordArkCallbackEnumFinalizeModuleCached(ModuleCache, entry);
}

static ULONG
KswordArkCallbackEnumAddNotifyArray(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG CallbackClass,
    _In_ ULONG OperationMask,
    _In_ ULONG64 ArrayAddress,
    _In_opt_z_ PCWSTR NamePrefix,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* SourceContext,
    _In_ ULONG SourceRva
    )
/*++

Routine Description:

    遍历 Psp notify 私有数组。中文说明：该函数只读 EX_FAST_REF 数组，不调用
    移除 API，不改写任何槽位；每个候选函数必须命中内核模块表才展示。

Arguments:

    Builder - 枚举响应构建器。
    ModuleCache - 模块缓存。
    CallbackClass - 回调类别。
    OperationMask - 操作掩码。
    ArrayAddress - 私有数组地址。
    NamePrefix - 行名称前缀。
    SourceContext - 可选来源元数据；NULL 表示保留旧 pattern fallback 标记。
    SourceRva - PDB 全局 RVA；非 PDB 路径传 0，仅用于 detail 诊断。

Return Value:

    返回枚举到的有效回调数量。

--*/
{
    ULONG slotIndex = 0UL;
    ULONG addedCount = 0UL;
    BOOLEAN removeTarget = Builder->RemoveMatchRequest != NULL &&
        Builder->RemoveMatchRequest->callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS &&
        CallbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS; // 仅对新增进程注销复核记录读取失败。
    BOOLEAN emptyContainer = TRUE; // 只有完整读取且所有槽为零才能证明空数组。

    if (ArrayAddress == 0ULL) {
        return 0UL;
    }

    for (slotIndex = 0UL; slotIndex < KSWORD_ARK_CALLBACK_ENUM_NOTIFY_SLOT_COUNT; ++slotIndex) {
        ULONG64 slotAddress = ArrayAddress + ((ULONG64)slotIndex * sizeof(ULONG_PTR));
        ULONG64 fastRefValue = 0ULL;
        ULONG64 routineBlock = 0ULL;
        ULONG64 functionAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;

        if (!KswordArkCallbackEnumReadPointer(slotAddress, &fastRefValue)) {
            emptyContainer = FALSE; // 未读到不能证明空槽。
            if (removeTarget) { Builder->RemoveQueryStatus = STATUS_PARTIAL_COPY; } // 后置不能把读失败当注销成功。
            continue;
        }
        if (fastRefValue == 0ULL) {
            continue;
        }
        emptyContainer = FALSE; // 数组包含注册，即使后续显示字段无法解析也不是空数组。

        routineBlock = fastRefValue & (ULONG64)KSWORD_ARK_CALLBACK_ENUM_FAST_REF_MASK;
        if (!KswordArkCallbackEnumLooksLikeKernelPointer(routineBlock)) {
            if (removeTarget) { Builder->RemoveQueryStatus = STATUS_DATA_ERROR; } // 非法存储不能作为缺失证据。
            continue;
        }
        if (!KswordArkCallbackEnumReadPointer(routineBlock + sizeof(ULONG_PTR), &functionAddress)) {
            if (removeTarget) { Builder->RemoveQueryStatus = STATUS_PARTIAL_COPY; } // 保留目标数组读取失败。
            continue;
        }
        if (!KswordArkCallbackEnumReadPointer(routineBlock + (2ULL * sizeof(ULONG_PTR)), &contextAddress)) {
            if (removeTarget) { // 注册标记读取失败时不能把零值误判为 Legacy。
                Builder->RemoveQueryStatus = STATUS_PARTIAL_COPY; // 明确无法识别当前子类型。
                continue; // 不发布伪造的传统注册行。
            } // 结束注销复核保护。
            contextAddress = 0ULL;
        }
        if (!KswordArkCallbackEnumLooksLikeKernelPointer(functionAddress)) {
            if (removeTarget) { Builder->RemoveQueryStatus = STATUS_DATA_ERROR; } // 非法函数不能证明目标已消失。
            continue;
        }
        if (!KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, functionAddress)) {
            if (removeTarget) { Builder->RemoveQueryStatus = STATUS_NOT_FOUND; } // 模块查询缺失不等于注销成功。
            continue;
        }

        KswordArkCallbackEnumAddNotifyArrayEntry(
            Builder,
            ModuleCache,
            CallbackClass,
            OperationMask,
            slotIndex,
            slotAddress,
            fastRefValue,
            routineBlock,
            functionAddress,
            contextAddress,
            NamePrefix,
            SourceContext,
            SourceRva);
        addedCount += 1UL;
    }

    if (removeTarget && emptyContainer) { Builder->RemoveTargetContainerEmpty = TRUE; } // 最后一项注销后可确认完整空数组。

    return addedCount;
}

static VOID
KswordArkCallbackEnumAddRegistryEntry(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG EntryIndex,
    _In_ ULONG64 EntryAddress,
    _In_ ULONG64 FunctionAddress,
    _In_ ULONG64 ContextAddress,
    _In_ ULONG64 Cookie, // 零值表示布局未通过自身注册校准。
    _In_ const UNICODE_STRING* AltitudeString,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* SourceContext,
    _In_ ULONG SourceRva
    )
/*++

Routine Description:

    写入一个 Cm registry callback 链表项。中文说明：不同 Windows 版本的私有
    结构存在漂移，因此本函数只写入已经被模块表验证过的 Function 候选。

Arguments:

    Builder - 枚举响应构建器。
    ModuleCache - 模块缓存。
    EntryIndex - 链表序号。
    EntryAddress - 链表节点地址。
    FunctionAddress - 回调函数地址。
    ContextAddress - 回调上下文地址。
    AltitudeString - 可选 altitude 描述符。
    SourceContext - 可选来源元数据；PDB 路径用它标记 trusted/source。
    SourceRva - CmCallbackListHead PDB RVA；非 PDB 路径传 0，仅用于 detail 诊断。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    entry->operationMask = KSWORD_ARK_REG_OP_ALL;
    entry->callbackAddress = FunctionAddress;
    entry->contextAddress = ContextAddress;
    entry->registrationAddress = EntryAddress;
    entry->rawStorageValue = EntryAddress; // 始终保存真实存储节点，不误作注销 Cookie。
    KswordArkCallbackEnumApplySourceContext(entry, SourceContext); // 先应用来源，随后发布该行的真实 Cookie 能力。
    if (Cookie != 0ULL) { // 本次链布局已经校准，Cookie 是值而非指针。
        entry->registrationAddress = Cookie; // CmUnRegisterCallback 的实际参数。
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE; // 保持候选等级，不伪装 verified。
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_STRUCTURE_SIGNATURE; // 自注册三元组证明结构。
        entry->removeBehavior = KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
            KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION; // 仅使用正规注销 API。
    } // 结束 Cookie 发布。
    if (SourceContext == NULL) {
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    (VOID)RtlStringCbPrintfW(
        entry->name,
        sizeof(entry->name),
        L"CmCallback[%lu]",
        (unsigned long)EntryIndex);
    if (AltitudeString != NULL) {
        KswordArkCallbackEnumCopyUnicodeSafe(
            entry->altitude,
            RTL_NUMBER_OF(entry->altitude),
            AltitudeString);
        if (entry->altitude[0] != L'\0') {
            entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        }
    }
    if (SourceContext != NULL && SourceContext->Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"%ws；CmCallbackListHead RVA=0x%08lX，Entry=0x%p，Function=0x%p，Context=0x%p；cookie/字段恢复未标记 verified remove。",
            (SourceContext->DetailPrefix != NULL) ? SourceContext->DetailPrefix : L"PDB callback profile trusted registry list",
            (unsigned long)SourceRva,
            (PVOID)(ULONG_PTR)EntryAddress,
            (PVOID)(ULONG_PTR)FunctionAddress,
            (PVOID)(ULONG_PTR)ContextAddress);
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"CmCallbackListHead 私有链表项；fallback=pattern scan，Entry=0x%p，Function=0x%p，Context=0x%p。",
            (PVOID)(ULONG_PTR)EntryAddress,
            (PVOID)(ULONG_PTR)FunctionAddress,
            (PVOID)(ULONG_PTR)ContextAddress);
    }
    KswordArkCallbackEnumFinalizeModuleCached(ModuleCache, entry);
}

static BOOLEAN
KswordArkCallbackEnumFindRegistryFields(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 EntryAddress,
    _Out_ ULONG64* FunctionAddressOut,
    _Out_ ULONG64* ContextAddressOut,
    _Out_ UNICODE_STRING* AltitudeStringOut
    )
/*++

Routine Description:

    从 Cm callback 私有节点中启发式识别 Function/Context/Altitude 字段。中文说明：
    优先选择能解析到内核模块的指针作为函数地址，再在其邻近字段寻找上下文和
    altitude 描述符。

Arguments:

    ModuleCache - 模块缓存。
    EntryAddress - 链表节点地址。
    FunctionAddressOut - 输出函数地址。
    ContextAddressOut - 输出上下文地址。
    AltitudeStringOut - 输出 altitude 描述符。

Return Value:

    成功识别函数地址返回 TRUE；否则返回 FALSE。

--*/
{
    LONG offset = 0L;
    ULONG64 functionAddress = 0ULL;
    ULONG64 contextAddress = 0ULL;
    UNICODE_STRING altitudeString;

    RtlZeroMemory(&altitudeString, sizeof(altitudeString));
    if (FunctionAddressOut == NULL || ContextAddressOut == NULL || AltitudeStringOut == NULL) {
        return FALSE;
    }
    *FunctionAddressOut = 0ULL;
    *ContextAddressOut = 0ULL;
    RtlZeroMemory(AltitudeStringOut, sizeof(*AltitudeStringOut));

    for (offset = 0x10L; offset <= 0x100L; offset += (LONG)sizeof(ULONG_PTR)) {
        ULONG64 candidate = 0ULL;
        if (!KswordArkCallbackEnumReadPointer(EntryAddress + (ULONG64)offset, &candidate)) {
            continue;
        }
        if (!KswordArkCallbackEnumLooksLikeKernelPointer(candidate)) {
            continue;
        }
        if (!KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, candidate)) {
            continue;
        }

        functionAddress = candidate;
        if (offset >= (LONG)sizeof(ULONG_PTR)) {
            (VOID)KswordArkCallbackEnumReadPointer(
                EntryAddress + (ULONG64)(offset - (LONG)sizeof(ULONG_PTR)),
                &contextAddress);
        }
        if (contextAddress == 0ULL) {
            (VOID)KswordArkCallbackEnumReadPointer(
                EntryAddress + (ULONG64)(offset + (LONG)sizeof(ULONG_PTR)),
                &contextAddress);
        }
        break;
    }

    if (functionAddress == 0ULL) {
        return FALSE;
    }

    for (offset = 0x10L; offset <= 0x120L; offset += (LONG)sizeof(USHORT)) {
        UNICODE_STRING candidateString;
        RtlZeroMemory(&candidateString, sizeof(candidateString));
        if (!KswordArkCallbackEnumReadUnicodeString(EntryAddress + (ULONG64)offset, &candidateString)) {
            continue;
        }
        if (candidateString.Buffer == NULL ||
            candidateString.Length == 0U ||
            candidateString.Length > 128U ||
            candidateString.MaximumLength < candidateString.Length ||
            (candidateString.Length % sizeof(WCHAR)) != 0U) {
            continue;
        }
        if (!MmIsAddressValid(candidateString.Buffer)) {
            continue;
        }

        altitudeString = candidateString;
        break;
    }

    *FunctionAddressOut = functionAddress;
    *ContextAddressOut = contextAddress;
    *AltitudeStringOut = altitudeString;
    return TRUE;
}

static ULONG
KswordArkCallbackEnumAddRegistryList(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 ListHeadAddress,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* SourceContext,
    _In_ ULONG SourceRva
    )
/*++

Routine Description:

    遍历 CmCallbackListHead 私有链表。中文说明：链表遍历设定最大节点数并校验
    LIST_ENTRY 指针，避免私有结构异常导致长循环。

Arguments:

    Builder - 枚举响应构建器。
    ModuleCache - 模块缓存。
    ListHeadAddress - 链表头地址。
    SourceContext - 可选来源元数据；NULL 表示保留旧 pattern fallback 标记。
    SourceRva - CmCallbackListHead PDB RVA；非 PDB 路径传 0，仅用于 detail 诊断。

Return Value:

    返回枚举到的有效注册表回调数量。

--*/
{
    LIST_ENTRY listHead;
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 currentAddress = 0ULL;

    RtlZeroMemory(&listHead, sizeof(listHead));
    if (ListHeadAddress == 0ULL ||
        !KswordArkCallbackEnumReadListEntry(ListHeadAddress, &listHead)) {
        KswordArkCallbackRecordRemoveQueryFailure(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY, STATUS_DATA_ERROR); // 目标读取失败不能证明已消失。
        return 0UL;
    }

    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    const BOOLEAN cookieLayoutValidated = KswordArkCallbackRegistryLayoutValidated(ListHeadAddress); // 同一次链头通过自 Cookie 校准。
    if (Builder->RemoveMatchRequest != NULL &&
        Builder->RemoveMatchRequest->callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY &&
        (ULONG64)(ULONG_PTR)listHead.Flink == ListHeadAddress &&
        (ULONG64)(ULONG_PTR)listHead.Blink == ListHeadAddress) { // 公共链已经安全读到正常空容器。
        Builder->RemoveTargetContainerEmpty = TRUE; // 注销最后一项后允许确认真实空链。
    } // 结束空容器证据。
    while (currentAddress != 0ULL &&
        currentAddress != ListHeadAddress &&
        index < KSWORD_ARK_CALLBACK_ENUM_LIST_WALK_LIMIT) {
        LIST_ENTRY currentEntry;
        ULONG64 functionAddress = 0ULL;
        ULONG64 contextAddress = 0ULL;
        UNICODE_STRING altitudeString;
        ULONG64 cookie = 0ULL; // 未通过校准时不得猜测 Cookie。

        RtlZeroMemory(&currentEntry, sizeof(currentEntry));
        RtlZeroMemory(&altitudeString, sizeof(altitudeString));
        if (!KswordArkCallbackEnumReadListEntry(currentAddress, &currentEntry)) {
            KswordArkCallbackRecordRemoveQueryFailure(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY, STATUS_DATA_ERROR); // 目标读取失败不能证明已消失。
            break;
        }
        if (currentEntry.Flink == NULL || currentEntry.Blink == NULL) {
            KswordArkCallbackRecordRemoveQueryFailure(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY, STATUS_DATA_ERROR); // 目标读取失败不能证明已消失。
            break;
        }

        if (KswordArkCallbackEnumFindRegistryFields(
            ModuleCache,
            currentAddress,
            &functionAddress,
            &contextAddress,
            &altitudeString)) {
            if (cookieLayoutValidated) { // 覆盖启发式 Function/Context 为已校准前缀。
                if (!KswordArkCallbackRegistryReadIdentity(currentAddress, &cookie, &contextAddress, &functionAddress)) {
                    KswordArkCallbackRecordRemoveQueryFailure(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY, STATUS_RETRY); // 读取失败不能用作不存在证据。
                    break; // 当前节点失效则停止遍历。
                } // 结束当前参数读取。
            } // 结束已校准参数恢复。
            KswordArkCallbackEnumAddRegistryEntry(
                Builder,
                ModuleCache,
                index,
                currentAddress,
                functionAddress,
                contextAddress,
                cookie, // 传入真实 Cookie 或零值。
                &altitudeString,
                SourceContext,
                SourceRva);
            addedCount += 1UL;
        }

        currentAddress = (ULONG64)(ULONG_PTR)currentEntry.Flink;
        index += 1UL;
    }

    if (currentAddress != ListHeadAddress) { // 未完成完整注册链，不能报告注销已确认。
        KswordArkCallbackRecordRemoveQueryFailure(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY, STATUS_DATA_ERROR); // 保留具体查询失败。
    } // 结束完整性检查。
    return addedCount;
}

static BOOLEAN
KswordArkCallbackEnumObjectNodeLooksValid(
    _In_ ULONG64 NodeAddress
    )
/*++

Routine Description:

    对对象回调链表节点做基础校验。中文说明：对象类型私有链表没有公开结构，
    这里只校验 LIST_ENTRY 形态，真正回调函数再由模块表确认。

Arguments:

    NodeAddress - 候选 LIST_ENTRY 地址。

Return Value:

    看起来可遍历返回 TRUE；否则返回 FALSE。

--*/
{
    LIST_ENTRY entry;

    RtlZeroMemory(&entry, sizeof(entry));
    if (NodeAddress == 0ULL || !KswordArkCallbackEnumReadListEntry(NodeAddress, &entry)) {
        return FALSE;
    }
    if (entry.Flink == NULL || entry.Blink == NULL) {
        return FALSE;
    }
    if ((ULONG64)(ULONG_PTR)entry.Flink < (ULONG64)(ULONG_PTR)MmUserProbeAddress ||
        (ULONG64)(ULONG_PTR)entry.Blink < (ULONG64)(ULONG_PTR)MmUserProbeAddress) {
        return FALSE;
    }
    return TRUE;
}

static BOOLEAN
KswordArkCallbackEnumFindObjectTypeCallbackListHead(
    _In_ POBJECT_TYPE ObjectType,
    _Out_ ULONG64* ListHeadAddressOut
    )
/*++

Routine Description:

    在 OBJECT_TYPE 私有结构中寻找 CallbackList 链表头。中文说明：该结构版本相关，
    因此函数只在对象类型前若干字节中寻找满足“双向链表且非空”的候选头。

Arguments:

    ObjectType - 输入对象类型指针。
    ListHeadAddressOut - 输出链表头地址。

Return Value:

    找到非空链表头返回 TRUE；否则返回 FALSE。

--*/
{
    ULONG offset = 0UL;
    ULONG64 objectTypeAddress = (ULONG64)(ULONG_PTR)ObjectType;

    if (ListHeadAddressOut == NULL) {
        return FALSE;
    }
    *ListHeadAddressOut = 0ULL;
    if (ObjectType == NULL || objectTypeAddress == 0ULL) {
        return FALSE;
    }

    for (offset = 0x40UL; offset < KSWORD_ARK_CALLBACK_ENUM_OBJECT_TYPE_SCAN_BYTES; offset += (ULONG)sizeof(ULONG_PTR)) {
        ULONG64 headAddress = objectTypeAddress + offset;
        LIST_ENTRY headEntry;
        ULONG64 flinkAddress = 0ULL;
        ULONG64 blinkAddress = 0ULL;
        LIST_ENTRY firstEntry;

        RtlZeroMemory(&headEntry, sizeof(headEntry));
        RtlZeroMemory(&firstEntry, sizeof(firstEntry));
        if (!KswordArkCallbackEnumReadListEntry(headAddress, &headEntry)) {
            continue;
        }

        flinkAddress = (ULONG64)(ULONG_PTR)headEntry.Flink;
        blinkAddress = (ULONG64)(ULONG_PTR)headEntry.Blink;
        if (flinkAddress == 0ULL || blinkAddress == 0ULL || flinkAddress == headAddress) {
            continue;
        }
        if (!KswordArkCallbackEnumObjectNodeLooksValid(flinkAddress)) {
            continue;
        }
        if (!KswordArkCallbackEnumReadListEntry(flinkAddress, &firstEntry)) {
            continue;
        }
        if ((ULONG64)(ULONG_PTR)firstEntry.Blink != headAddress &&
            (ULONG64)(ULONG_PTR)headEntry.Blink != flinkAddress) {
            continue;
        }

        *ListHeadAddressOut = headAddress;
        return TRUE;
    }

    return FALSE;
}

static KSWORD_ARK_CALLBACK_ENUM_OBJECT_LIST_STATE
KswordArkCallbackEnumFindObjectTypeCallbackListHeadPdb(
    _In_ POBJECT_TYPE ObjectType,
    _In_ ULONG CallbackListOffset,
    _Out_ ULONG64* ListHeadAddressOut
    )
/*++

Routine Description:

    Locates OBJECT_TYPE.CallbackList from a PDB supplied structure offset.
    Processing computes ObjectType + CallbackListOffset, reads the LIST_ENTRY
    head, and accepts either an empty self-referential list or a non-empty list
    whose first node links back to the computed head.

Arguments:

    ObjectType - Input OBJECT_TYPE pointer.
    CallbackListOffset - PDB offset of _OBJECT_TYPE.CallbackList.
    ListHeadAddressOut - Receives the computed list head VA on success.

Return Value:

    Returns KswordArkCallbackEnumObjectListNonEmpty when the PDB offset
    produced a readable/reasonable non-empty list head, KswordArkCallbackEnumObjectListEmpty
    when the head is readable but empty/self-referential, and
    KswordArkCallbackEnumObjectListInvalid when the offset is unusable and the
    caller must fall back to the existing object-type heuristic scan.

--*/
{
    ULONG64 objectTypeAddress = (ULONG64)(ULONG_PTR)ObjectType;
    ULONG64 headAddress = 0ULL;
    LIST_ENTRY headEntry;
    ULONG64 flinkAddress = 0ULL;
    ULONG64 blinkAddress = 0ULL;

    if (ListHeadAddressOut == NULL) {
        return KswordArkCallbackEnumObjectListInvalid;
    }
    *ListHeadAddressOut = 0ULL;
    if (ObjectType == NULL || objectTypeAddress == 0ULL) {
        return KswordArkCallbackEnumObjectListInvalid;
    }
    if (objectTypeAddress > (((ULONG64)~0ULL) - (ULONG64)CallbackListOffset)) {
        return KswordArkCallbackEnumObjectListInvalid;
    }

    headAddress = objectTypeAddress + (ULONG64)CallbackListOffset;
    RtlZeroMemory(&headEntry, sizeof(headEntry));
    if (!KswordArkCallbackEnumReadListEntry(headAddress, &headEntry)) {
        return KswordArkCallbackEnumObjectListInvalid;
    }

    flinkAddress = (ULONG64)(ULONG_PTR)headEntry.Flink;
    blinkAddress = (ULONG64)(ULONG_PTR)headEntry.Blink;
    if (flinkAddress == headAddress && blinkAddress == headAddress) {
        *ListHeadAddressOut = headAddress;
        return KswordArkCallbackEnumObjectListEmpty;
    }
    if (flinkAddress == 0ULL || blinkAddress == 0ULL) {
        return KswordArkCallbackEnumObjectListInvalid;
    }
    if (!KswordArkCallbackEnumObjectNodeLooksValid(flinkAddress)) {
        return KswordArkCallbackEnumObjectListInvalid;
    }
    if (blinkAddress < (ULONG64)(ULONG_PTR)MmUserProbeAddress) {
        return KswordArkCallbackEnumObjectListInvalid;
    }

    {
        LIST_ENTRY firstEntry;
        RtlZeroMemory(&firstEntry, sizeof(firstEntry));
        if (!KswordArkCallbackEnumReadListEntry(flinkAddress, &firstEntry)) {
            return KswordArkCallbackEnumObjectListInvalid;
        }
        if ((ULONG64)(ULONG_PTR)firstEntry.Blink != headAddress) {
            return KswordArkCallbackEnumObjectListInvalid;
        }
    }

    *ListHeadAddressOut = headAddress;
    return KswordArkCallbackEnumObjectListNonEmpty;
}

static BOOLEAN
KswordArkCallbackEnumFindObjectCallbackFieldsPdb(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE* Profile,
    _In_ ULONG64 NodeAddress,
    _Out_ KSWORD_ARK_CALLBACK_ENUM_OBJECT_SCAN_RESULT* ResultOut
    )
/*++

Routine Description:

    Reads _CALLBACK_ENTRY_ITEM fields using PDB supplied offsets. Processing
    derives the entry-item base from EntryItemList when available, then reads
    PreOperation, PostOperation, Operations, and CallbackEntry directly. Function
    pointers must resolve to a loaded kernel module before the result is trusted.

Arguments:

    ModuleCache - Module cache used to validate callback function pointers.
    Profile - Captured callback DynData profile containing PDB offsets/sources.
    NodeAddress - Current LIST_ENTRY node address from OBJECT_TYPE.CallbackList.
    ResultOut - Receives parsed callback fields.

Return Value:

    TRUE when direct PDB-offset parsing finds at least one valid callback
    function. FALSE means the caller should use the existing heuristic parser.

--*/
{
    const KSW_DYN_CALLBACK_OFFSETS* offsets = NULL;
    const KSW_DYN_CALLBACK_OFFSETS* sources = NULL;
    ULONG64 entryItemBase = NodeAddress;
    ULONG64 preOperation = 0ULL;
    ULONG64 postOperation = 0ULL;
    ULONG64 callbackEntry = 0ULL;
    ULONG64 registrationProbe = 0ULL;
    ULONG operationMask = 0UL;
    KSWORD_ARK_CALLBACK_ENUM_OBJECT_SCAN_RESULT result;

    if (Profile == NULL || !Profile->Active || ResultOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(ResultOut, sizeof(*ResultOut));
    RtlZeroMemory(&result, sizeof(result));

    offsets = &Profile->State.CallbackOffsets;
    sources = &Profile->State.CallbackOffsetSources;
    if (!KswordArkCallbackEnumPdbOffsetAvailable(
            offsets->CallbackEntryItemEntryList,
            sources->CallbackEntryItemEntryList) ||
        !KswordArkCallbackEnumPdbOffsetAvailable(
            offsets->CallbackEntryItemPreOperation,
            sources->CallbackEntryItemPreOperation) ||
        !KswordArkCallbackEnumPdbOffsetAvailable(
            offsets->CallbackEntryItemPostOperation,
            sources->CallbackEntryItemPostOperation) ||
        !KswordArkCallbackEnumPdbOffsetAvailable(
            offsets->CallbackEntryItemOperations,
            sources->CallbackEntryItemOperations) ||
        !KswordArkCallbackEnumPdbOffsetAvailable(
            offsets->CallbackEntryItemCallbackEntry,
            sources->CallbackEntryItemCallbackEntry)) {
        return FALSE;
    }

    if (NodeAddress < (ULONG64)offsets->CallbackEntryItemEntryList) {
        return FALSE;
    }
    entryItemBase = NodeAddress - (ULONG64)offsets->CallbackEntryItemEntryList;

    if (!KswordArkCallbackEnumReadPointer(
            entryItemBase + (ULONG64)offsets->CallbackEntryItemPreOperation,
            &preOperation) ||
        !KswordArkCallbackEnumReadPointer(
            entryItemBase + (ULONG64)offsets->CallbackEntryItemPostOperation,
            &postOperation) ||
        !KswordArkCallbackEnumReadUlong(
            entryItemBase + (ULONG64)offsets->CallbackEntryItemOperations,
            &operationMask) ||
        !KswordArkCallbackEnumReadPointer(
            entryItemBase + (ULONG64)offsets->CallbackEntryItemCallbackEntry,
            &callbackEntry)) {
        return FALSE;
    }

    if (preOperation != 0ULL) {
        if (!KswordArkCallbackEnumLooksLikeKernelPointer(preOperation) ||
            !KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, preOperation)) {
            return FALSE;
        }
        result.PreOperation = preOperation;
    }
    if (postOperation != 0ULL) {
        if (!KswordArkCallbackEnumLooksLikeKernelPointer(postOperation) ||
            !KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, postOperation)) {
            return FALSE;
        }
        result.PostOperation = postOperation;
    }
    if (result.PreOperation == 0ULL && result.PostOperation == 0ULL) {
        return FALSE;
    }
    if ((operationMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE)) == 0UL ||
        (operationMask & ~(OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE | 0xFFFF0000UL)) != 0UL) {
        return FALSE;
    }
    if (callbackEntry == 0ULL || !KswordArkCallbackEnumLooksLikeKernelPointer(callbackEntry)) {
        return FALSE;
    }
    if (callbackEntry == entryItemBase ||
        callbackEntry == NodeAddress ||
        KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, callbackEntry) ||
        !KswordArkCallbackEnumReadPointer(callbackEntry, &registrationProbe)) {
        return FALSE;
    }

    result.OperationMask = operationMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE);
    result.RegistrationBlock = callbackEntry;
    result.UsedPdbOffsets = TRUE;
    *ResultOut = result;
    return TRUE;
}

static BOOLEAN
KswordArkCallbackEnumFindObjectCallbackFields(
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG64 NodeAddress,
    _In_ POBJECT_TYPE ObjectType, // 校准布局只用于同一对象类型列表。
    _In_ BOOLEAN Calibrated, // 来自当前链的自身真实句柄核对。
    _Out_ KSWORD_ARK_CALLBACK_ENUM_OBJECT_SCAN_RESULT* ResultOut
    )
/*++

Routine Description:

    从对象回调私有节点中识别 Pre/PostOperation、Operations 和 Registration 字段。
    中文说明：Pre/PostOperation 指针必须落在已加载内核模块；Operations 掩码在
    邻近 ULONG 字段中启发式读取。

Arguments:

    ModuleCache - 模块缓存。
    NodeAddress - 链表节点地址。
    ResultOut - 输出识别结果。

Return Value:

    找到至少一个回调函数返回 TRUE；否则返回 FALSE。

--*/
{
    LONG offset = 0L;
    KSWORD_ARK_CALLBACK_ENUM_OBJECT_SCAN_RESULT result;

    RtlZeroMemory(&result, sizeof(result));
    if (ResultOut == NULL) {
        return FALSE;
    }
    RtlZeroMemory(ResultOut, sizeof(*ResultOut));

    if (Calibrated) { // 只在真实自身注册确认布局后读取准确字段。
        ULONG64 fields[7]; // 常见 CALLBACK_ENTRY_ITEM 的完整关键前缀。
        if (!KswordARKRuntimeReadMemory((PVOID)(ULONG_PTR)NodeAddress, fields, sizeof(fields)) ||
            fields[4] != (ULONG64)(ULONG_PTR)ObjectType || fields[3] == NodeAddress ||
            !KswordArkCallbackEnumLooksLikeKernelPointer(fields[3]) ||
            ((ULONG)fields[2] & ~(OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE)) != 0UL ||
            (ULONG)fields[2] == 0UL) return FALSE; // 字段必须符合实际对象和操作语义。
        result.OperationMask = (ULONG)fields[2]; // 不从邻近整数猜 Operations。
        result.PreOperation = fields[5]; // 校准的 PreOperation 槽。
        result.PostOperation = fields[6]; // 校准的 PostOperation 槽，可为零。
        if ((result.PreOperation != 0ULL && !KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, result.PreOperation)) ||
            (result.PostOperation != 0ULL && !KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, result.PostOperation))) return FALSE; // 拒绝非模块函数。
        result.RegistrationBlock = fields[3]; // 真实 CallbackEntry 字段值，而不是 Flink/Blink。
        *ResultOut = result; // 保留 fallback 来源，不提升为 PDB verified。
        return result.PreOperation != 0ULL || result.PostOperation != 0ULL; // 无回调项不发布。
    }

    for (offset = KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_BACK_BYTES * -1L;
        offset <= KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_FORWARD_BYTES;
        offset += (LONG)sizeof(ULONG_PTR)) {
        ULONG64 fieldAddress = 0ULL;
        ULONG64 candidate = 0ULL;

        if (offset < 0L && NodeAddress < (ULONG64)(-offset)) {
            continue;
        }
        fieldAddress = (offset < 0L)
            ? NodeAddress - (ULONG64)(-offset)
            : NodeAddress + (ULONG64)offset;
        if (!KswordArkCallbackEnumReadPointer(fieldAddress, &candidate)) {
            continue;
        }
        if (!KswordArkCallbackEnumLooksLikeKernelPointer(candidate)) {
            continue;
        }
        if (!KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, candidate)) {
            continue;
        }

        if (result.PreOperation == 0ULL) {
            result.PreOperation = candidate;
        }
        else if (result.PostOperation == 0ULL && candidate != result.PreOperation) {
            result.PostOperation = candidate;
            break;
        }
    }

    if (result.PreOperation == 0ULL && result.PostOperation == 0ULL) {
        return FALSE;
    }

    for (offset = -0x40L; offset <= 0x80L; offset += (LONG)sizeof(ULONG)) {
        ULONG candidateMask = 0UL;
        ULONG64 fieldAddress = 0ULL;
        if (offset < 0L && NodeAddress < (ULONG64)(-offset)) {
            continue;
        }
        fieldAddress = (offset < 0L)
            ? NodeAddress - (ULONG64)(-offset)
            : NodeAddress + (ULONG64)offset;
        if (!KswordArkCallbackEnumReadUlong(fieldAddress, &candidateMask)) {
            continue;
        }
        if ((candidateMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE)) != 0UL &&
            (candidateMask & ~(OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE | 0xFFFF0000UL)) == 0UL) {
            result.OperationMask = candidateMask & (OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE);
            break;
        }
    }
    if (result.OperationMask == 0UL) {
        result.OperationMask = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    }

    for (offset = KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_BACK_BYTES * -1L;
        offset <= KSWORD_ARK_CALLBACK_ENUM_POINTER_SCAN_FORWARD_BYTES;
        offset += (LONG)sizeof(ULONG_PTR)) {
        ULONG64 fieldAddress = 0ULL;
        ULONG64 candidate = 0ULL;
        if (offset < 0L && NodeAddress < (ULONG64)(-offset)) {
            continue;
        }
        fieldAddress = (offset < 0L)
            ? NodeAddress - (ULONG64)(-offset)
            : NodeAddress + (ULONG64)offset;
        if (!KswordArkCallbackEnumReadPointer(fieldAddress, &candidate)) {
            continue;
        }
        if (candidate == 0ULL ||
            candidate == result.PreOperation ||
            candidate == result.PostOperation) {
            continue;
        }
        if (KswordArkCallbackEnumLooksLikeKernelPointer(candidate) && !KswordArkCallbackEnumIsKernelModuleAddress(ModuleCache, candidate)) {
            break; // 未校准候选只作只读函数展示，不发布猜测的 RegistrationHandle。
        }
    }

    *ResultOut = result;
    return TRUE;
}

static VOID
KswordArkCallbackEnumAddObjectCallbackEntry(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ ULONG EntryIndex,
    _In_ ULONG ObjectTypeMask,
    _In_z_ PCWSTR ObjectTypeName,
    _In_ ULONG64 NodeAddress,
    _In_ ULONG64 CallbackAddress,
    _In_ ULONG OperationMask,
    _In_ ULONG64 RegistrationBlock,
    _In_ BOOLEAN IsPostOperation,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* SourceContext,
    _In_ BOOLEAN UsedPdbOffsets,
    _In_opt_ const KSW_DYN_CALLBACK_OFFSETS* PdbOffsets
    )
/*++

Routine Description:

    写入一个 ObRegisterCallbacks 私有链表候选。中文说明：同一个节点可能有 Pre
    和 Post 两个函数，函数地址命中模块表后分别展示。

Arguments:

    Builder - 枚举响应构建器。
    ModuleCache - 模块缓存。
    EntryIndex - 链表序号。
    ObjectTypeMask - 对象类型掩码。
    ObjectTypeName - 对象类型展示名。
    NodeAddress - 链表节点地址。
    CallbackAddress - 回调函数地址。
    OperationMask - Ob operation 掩码。
    RegistrationBlock - 注册块候选地址。
    IsPostOperation - TRUE 表示 PostOperation；FALSE 表示 PreOperation。
    SourceContext - 可选来源元数据；PDB 路径用它标记 trusted/source。
    UsedPdbOffsets - TRUE 表示字段来自 PDB offset；FALSE 表示启发式字段恢复。
    PdbOffsets - 可选 PDB offset 结构；仅在 trusted path 详情里打印实际偏移值。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OPERATION_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_OBJECT_TYPE_MASK |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_RAW_STORAGE_VALUE |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_STORAGE_ADDRESS;
    entry->operationMask = OperationMask;
    entry->objectTypeMask = ObjectTypeMask;
    if ((ObjectTypeMask & KSWORD_ARK_OBJECT_OP_TYPE_DESKTOP) != 0UL) {
        entry->registrationType = KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DESKTOP_OBJECT;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_TYPE;
    }
    entry->callbackAddress = CallbackAddress;
    // The list node is only diagnostic storage identity. It is never a valid
    // RegistrationHandle and therefore travels separately from registrationAddress.
    entry->rawStorageValue = NodeAddress;
    KswordArkCallbackEnumApplySourceContext(entry, SourceContext);
    if (UsedPdbOffsets && SourceContext != NULL && RegistrationBlock != 0ULL) {
        // _CALLBACK_ENTRY_ITEM.CallbackEntry is the value returned by
        // ObRegisterCallbacks. Only a profile-gated exact field read may publish it.
        entry->registrationAddress = RegistrationBlock;
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
    }
    else {
        // Heuristic scans cannot prove the private structure version, but the UI
        // exposes a high-risk candidate path when the candidate block is present.
        entry->contextAddress = RegistrationBlock;
        if (RegistrationBlock != 0ULL) {
            entry->registrationAddress = RegistrationBlock;
            entry->removeBehavior = KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION;
            entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE; // 只有当前链用真实自身句柄校准后才有 RegistrationBlock。
        }
        entry->fieldFlags &= ~(KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE |
            KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE);
        entry->trustFlags |= KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN;
    }

    (VOID)RtlStringCbPrintfW(
        entry->name,
        sizeof(entry->name),
        L"Ob%wsCallback[%ws:%lu]",
        IsPostOperation ? L"Post" : L"Pre",
        ObjectTypeName,
        (unsigned long)EntryIndex);
    if (SourceContext != NULL && SourceContext->Source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE) {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"%ws；fieldPath=%ws，ObjectType=%ws，Node=0x%p，%wsOperation=0x%p，Operations=0x%lX，%ws=0x%p，offsets[EntryList=0x%lX,Pre=0x%lX,Post=0x%lX,Ops=0x%lX,CallbackEntry=0x%lX]。",
            (SourceContext->DetailPrefix != NULL) ? SourceContext->DetailPrefix : L"PDB callback profile trusted object list",
            UsedPdbOffsets ? L"PDB offsets" : L"heuristic fallback",
            ObjectTypeName,
            (PVOID)(ULONG_PTR)NodeAddress,
            IsPostOperation ? L"Post" : L"Pre",
            (PVOID)(ULONG_PTR)CallbackAddress,
            (unsigned long)OperationMask,
            UsedPdbOffsets ? L"CallbackEntry" : L"RegistrationBlock",
            (PVOID)(ULONG_PTR)RegistrationBlock,
            (unsigned long)((PdbOffsets != NULL) ? PdbOffsets->CallbackEntryItemEntryList : 0UL),
            (unsigned long)((PdbOffsets != NULL) ? PdbOffsets->CallbackEntryItemPreOperation : 0UL),
            (unsigned long)((PdbOffsets != NULL) ? PdbOffsets->CallbackEntryItemPostOperation : 0UL),
            (unsigned long)((PdbOffsets != NULL) ? PdbOffsets->CallbackEntryItemOperations : 0UL),
            (unsigned long)((PdbOffsets != NULL) ? PdbOffsets->CallbackEntryItemCallbackEntry : 0UL));
    }
    else {
        (VOID)RtlStringCbPrintfW(
            entry->detail,
            sizeof(entry->detail),
            L"OBJECT_TYPE CallbackList 私有链表候选；fallback=heuristic scan，ObjectType=%ws，Node=0x%p，%wsOperation=0x%p，Operations=0x%lX，RegistrationBlock=0x%p。",
            ObjectTypeName,
            (PVOID)(ULONG_PTR)NodeAddress,
            IsPostOperation ? L"Post" : L"Pre",
            (PVOID)(ULONG_PTR)CallbackAddress,
            (unsigned long)OperationMask,
            (PVOID)(ULONG_PTR)RegistrationBlock);
    }
    KswordArkCallbackEnumFinalizeModuleCached(ModuleCache, entry);
}
static ULONG
KswordArkCallbackEnumAddObjectTypeCallbackList(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _Inout_ KSWORD_ARK_CALLBACK_MODULE_CACHE* ModuleCache,
    _In_ POBJECT_TYPE ObjectType,
    _In_ ULONG ObjectTypeMask,
    _In_z_ PCWSTR ObjectTypeName,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE* Profile,
    _In_opt_ const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* SourceContext
    )
/*++

Routine Description:

    枚举一个对象类型的 Ob callback 私有链表。中文说明：PDB profile 可用时先
    使用 _OBJECT_TYPE.CallbackList 和 _CALLBACK_ENTRY_ITEM 字段 offset；字段
    不全或读取失败时保留原有启发式扫描。

Arguments:

    Builder - 枚举响应构建器。
    ModuleCache - 模块缓存。
    ObjectType - 目标对象类型。
    ObjectTypeMask - 对象类型掩码。
    ObjectTypeName - 对象类型文本。
    Profile - 可选 PDB callback profile；NULL 表示只走旧启发式。
    SourceContext - 可选来源元数据；PDB 路径用它标记 trusted/source。

Return Value:

    返回枚举到的有效对象回调函数数量。

--*/
{
    ULONG64 listHeadAddress = 0ULL;
    LIST_ENTRY listHead;
    ULONG index = 0UL;
    ULONG addedCount = 0UL;
    ULONG64 currentAddress = 0ULL;
    KSWORD_ARK_CALLBACK_ENUM_OBJECT_LIST_STATE listHeadState = KswordArkCallbackEnumObjectListInvalid;
    BOOLEAN usingPdbListHead = FALSE;
    BOOLEAN calibratedHandle = FALSE; // 同一次目标链枚举的活跃自身句柄校准结果。

    RtlZeroMemory(&listHead, sizeof(listHead));
    if (Profile != NULL &&
        Profile->Active &&
        KswordArkCallbackEnumPdbOffsetAvailable(
            Profile->State.CallbackOffsets.ObjectTypeCallbackList,
            Profile->State.CallbackOffsetSources.ObjectTypeCallbackList) &&
        (listHeadState = KswordArkCallbackEnumFindObjectTypeCallbackListHeadPdb(
            ObjectType,
            Profile->State.CallbackOffsets.ObjectTypeCallbackList,
            &listHeadAddress)) != KswordArkCallbackEnumObjectListInvalid) {
        usingPdbListHead = TRUE;
    }
    if (!usingPdbListHead) {
        if (!KswordArkCallbackEnumFindObjectTypeCallbackListHead(ObjectType, &listHeadAddress)) {
            return 0UL;
        }
        Profile = NULL;
        SourceContext = NULL;
    }
    if (!KswordArkCallbackEnumReadListEntry(listHeadAddress, &listHead)) {
        return 0UL;
    }
    calibratedHandle = KswordArkCallbackEnumCalibrateObjectHandle(listHeadAddress, ObjectType); // 新快照重新核对，不缓存失效自身句柄。
    currentAddress = (ULONG64)(ULONG_PTR)listHead.Flink;
    while (currentAddress != 0ULL &&
        currentAddress != listHeadAddress &&
        index < KSWORD_ARK_CALLBACK_ENUM_LIST_WALK_LIMIT) {
        LIST_ENTRY currentEntry;
        KSWORD_ARK_CALLBACK_ENUM_OBJECT_SCAN_RESULT scanResult;

        RtlZeroMemory(&currentEntry, sizeof(currentEntry));
        RtlZeroMemory(&scanResult, sizeof(scanResult));
        if (!KswordArkCallbackEnumReadListEntry(currentAddress, &currentEntry)) {
            break;
        }
        if (!KswordArkCallbackEnumFindObjectCallbackFieldsPdb(
                ModuleCache,
                Profile,
                currentAddress,
                &scanResult) &&
            !KswordArkCallbackEnumFindObjectCallbackFields(ModuleCache, currentAddress, ObjectType, calibratedHandle, &scanResult)) {
            currentAddress = (ULONG64)(ULONG_PTR)currentEntry.Flink;
            index += 1UL;
            continue;
        }
        if (scanResult.PreOperation != 0ULL) {
            const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* rowSourceContext =
                (scanResult.UsedPdbOffsets && SourceContext != NULL) ? SourceContext : NULL;
            KswordArkCallbackEnumAddObjectCallbackEntry(
                Builder,
                ModuleCache,
                index,
                ObjectTypeMask,
                ObjectTypeName,
                currentAddress,
                scanResult.PreOperation,
                scanResult.OperationMask,
                scanResult.RegistrationBlock,
                FALSE,
                rowSourceContext,
                scanResult.UsedPdbOffsets,
                (Profile != NULL) ? &Profile->State.CallbackOffsets : NULL);
            addedCount += 1UL;
        }
        if (scanResult.PostOperation != 0ULL) {
            const KSWORD_ARK_CALLBACK_ENUM_SOURCE_CONTEXT* rowSourceContext =
                (scanResult.UsedPdbOffsets && SourceContext != NULL) ? SourceContext : NULL;
            KswordArkCallbackEnumAddObjectCallbackEntry(
                Builder,
                ModuleCache,
                index,
                ObjectTypeMask,
                ObjectTypeName,
                currentAddress,
                scanResult.PostOperation,
                scanResult.OperationMask,
                scanResult.RegistrationBlock,
                TRUE,
                rowSourceContext,
                scanResult.UsedPdbOffsets,
                (Profile != NULL) ? &Profile->State.CallbackOffsets : NULL);
            addedCount += 1UL;
        }

        currentAddress = (ULONG64)(ULONG_PTR)currentEntry.Flink;
        index += 1UL;
    }

    if (usingPdbListHead &&
        listHeadState == KswordArkCallbackEnumObjectListEmpty) {
        if (Builder->RemoveMatchRequest != NULL &&
            Builder->RemoveMatchRequest->callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT &&
            (Builder->RemoveMatchRequest->objectTypeMask & ObjectTypeMask) != 0UL &&
            currentAddress == listHeadAddress) { // 已有 PDB offset 的目标对象类型链为空。
            Builder->RemoveTargetContainerEmpty = TRUE; // 避免旧 empty/unsupported 行否定已验证的空容器。
        } // 结束目标空链证据。
        return addedCount;
    }

    return addedCount;
}

VOID
KswordArkCallbackEnumAddPrivateCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    枚举系统私有回调结构。中文说明：实现参考 SKT64 的特征定位方式，只读遍历
    Psp notify 数组、Cm 回调链表和 Process/Thread OBJECT_TYPE 回调链表。

Arguments:

    Builder - 枚举响应构建器。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE moduleCache;
    KSWORD_ARK_CALLBACK_ENUM_DYNDATA_PROFILE pdbProfile;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 processArray = 0ULL;
    ULONG64 threadArray = 0ULL;
    ULONG64 imageArray = 0ULL;
    ULONG64 notifyEnableMask = 0ULL;
    ULONG64 cmListHead = 0ULL;
    ULONG64 obpCallPreOperationCallbacks = 0ULL;
    ULONG addedCount = 0UL;
    ULONG notifyMaskValue = 0UL;
    WCHAR detailText[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS];

    KswordArkCallbackEnumInitModuleCache(&moduleCache);
    RtlZeroMemory(&pdbProfile, sizeof(pdbProfile));
    (VOID)KswordArkCallbackEnumCaptureDynDataProfile(&pdbProfile);

    status = KswordArkCallbackEnumLocatePspNotifyEnableMask(&notifyEnableMask);
    if (NT_SUCCESS(status)) {
        (VOID)KswordArkCallbackEnumReadUlong(notifyEnableMask, &notifyMaskValue);
    }
    KswordArkCallbackEnumAddLocateRow(
        Builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
        L"PspNotifyEnableMask",
        notifyEnableMask,
        status,
        NT_SUCCESS(status)
            ? L"已定位 PspNotifyEnableMask；用于诊断进程/线程/镜像 notify 全局启用状态。"
            : L"未能定位 PspNotifyEnableMask；不影响后续数组特征扫描。");

    status = KswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.State.CallbackGlobals.PspCreateProcessNotifyRoutine,
            pdbProfile.State.CallbackGlobalSources.PspCreateProcessNotifyRoutine,
            sizeof(ULONG_PTR),
            &processArray);
    if (NT_SUCCESS(status)) {
        addedCount = KswordArkCallbackEnumAddNotifyArray(
            Builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
            KSWORD_ARK_PROCESS_OP_CREATE,
            processArray,
            L"PspCreateProcessNotifyRoutine",
            &g_KswordArkCallbackEnumPdbNotifySourceContext,
            pdbProfile.State.CallbackGlobals.PspCreateProcessNotifyRoutine);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 PspCreateProcessNotifyRoutine VA 0x%p，但未找到可验证的 EX_FAST_REF 槽。",
                (unsigned long)pdbProfile.State.CallbackGlobals.PspCreateProcessNotifyRoutine,
                (PVOID)(ULONG_PTR)processArray);
            KswordArkCallbackEnumAddUnsupportedRow(
                Builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
                L"PspCreateProcessNotifyRoutine empty",
                detailText);
        }
    }
    else {
        const NTSTATUS pdbStatus = status;
        status = KswordArkCallbackEnumLocateValidatedGlobal(&moduleCache, KswCallbackGlobalProcess, &processArray);
        RtlZeroMemory(detailText, sizeof(detailText));
        if (!NT_SUCCESS(status)) {
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"未能通过 PsSetCreateProcessNotifyRoutine 特征定位进程 notify 数组。PDB path status=0x%08lX, CallbackProfileActive=%lu, RVA=0x%08lX, Source=%lu。",
                (unsigned long)pdbStatus,
                (unsigned long)pdbProfile.State.CallbackProfileActive,
                (unsigned long)pdbProfile.State.CallbackGlobals.PspCreateProcessNotifyRoutine,
                (unsigned long)pdbProfile.State.CallbackGlobalSources.PspCreateProcessNotifyRoutine);
        }
        KswordArkCallbackEnumAddLocateRow(
            Builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
            L"PspCreateProcessNotifyRoutine",
            processArray,
            status,
            NT_SUCCESS(status)
                ? L"已定位 PspCreateProcessNotifyRoutine 私有数组，开始遍历 EX_FAST_REF 槽。"
                : detailText);
        if (NT_SUCCESS(status)) {
            addedCount = KswordArkCallbackEnumAddNotifyArray(
                Builder,
                &moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
                KSWORD_ARK_PROCESS_OP_CREATE,
                processArray,
                L"PspCreateProcessNotifyRoutine",
                NULL,
                0UL);
            if (addedCount == 0UL) {
                KswordArkCallbackEnumAddUnsupportedRow(
                    Builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS,
                    L"PspCreateProcessNotifyRoutine empty",
                    L"已定位进程 notify 数组，但未找到能解析到模块的有效 EX_CALLBACK_ROUTINE_BLOCK。");
            }
        }
    }

    status = KswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.State.CallbackGlobals.PspCreateThreadNotifyRoutine,
            pdbProfile.State.CallbackGlobalSources.PspCreateThreadNotifyRoutine,
            sizeof(ULONG_PTR),
            &threadArray);
    if (NT_SUCCESS(status)) {
        addedCount = KswordArkCallbackEnumAddNotifyArray(
            Builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
            KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT,
            threadArray,
            L"PspCreateThreadNotifyRoutine",
            &g_KswordArkCallbackEnumPdbNotifySourceContext,
            pdbProfile.State.CallbackGlobals.PspCreateThreadNotifyRoutine);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 PspCreateThreadNotifyRoutine VA 0x%p，但未找到可验证的 EX_FAST_REF 槽。",
                (unsigned long)pdbProfile.State.CallbackGlobals.PspCreateThreadNotifyRoutine,
                (PVOID)(ULONG_PTR)threadArray);
            KswordArkCallbackEnumAddUnsupportedRow(
                Builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
                L"PspCreateThreadNotifyRoutine empty",
                detailText);
        }
    }
    else {
        const NTSTATUS pdbStatus = status;
        status = KswordArkCallbackEnumLocateValidatedGlobal(&moduleCache, KswCallbackGlobalThread, &threadArray);
        RtlZeroMemory(detailText, sizeof(detailText));
        if (!NT_SUCCESS(status)) {
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"未能通过 PsRemoveCreateThreadNotifyRoutine 特征定位线程 notify 数组。PDB path status=0x%08lX, CallbackProfileActive=%lu, RVA=0x%08lX, Source=%lu。",
                (unsigned long)pdbStatus,
                (unsigned long)pdbProfile.State.CallbackProfileActive,
                (unsigned long)pdbProfile.State.CallbackGlobals.PspCreateThreadNotifyRoutine,
                (unsigned long)pdbProfile.State.CallbackGlobalSources.PspCreateThreadNotifyRoutine);
        }
        KswordArkCallbackEnumAddLocateRow(
            Builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
            L"PspCreateThreadNotifyRoutine",
            threadArray,
            status,
            NT_SUCCESS(status)
                ? L"已定位 PspCreateThreadNotifyRoutine 私有数组，开始遍历 EX_FAST_REF 槽。"
                : detailText);
        if (NT_SUCCESS(status)) {
            addedCount = KswordArkCallbackEnumAddNotifyArray(
                Builder,
                &moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
                KSWORD_ARK_THREAD_OP_CREATE | KSWORD_ARK_THREAD_OP_EXIT,
                threadArray,
                L"PspCreateThreadNotifyRoutine",
                NULL,
                0UL);
            if (addedCount == 0UL) {
                KswordArkCallbackEnumAddUnsupportedRow(
                    Builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD,
                    L"PspCreateThreadNotifyRoutine empty",
                    L"已定位线程 notify 数组，但未找到能解析到模块的有效 EX_CALLBACK_ROUTINE_BLOCK。");
            }
        }
    }

    status = KswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.State.CallbackGlobals.PspLoadImageNotifyRoutine,
            pdbProfile.State.CallbackGlobalSources.PspLoadImageNotifyRoutine,
            sizeof(ULONG_PTR),
            &imageArray);
    if (NT_SUCCESS(status)) {
        addedCount = KswordArkCallbackEnumAddNotifyArray(
            Builder,
            &moduleCache,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
            KSWORD_ARK_IMAGE_OP_LOAD,
            imageArray,
            L"PspLoadImageNotifyRoutine",
            &g_KswordArkCallbackEnumPdbNotifySourceContext,
            pdbProfile.State.CallbackGlobals.PspLoadImageNotifyRoutine);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 PspLoadImageNotifyRoutine VA 0x%p，但未找到可验证的 EX_FAST_REF 槽。",
                (unsigned long)pdbProfile.State.CallbackGlobals.PspLoadImageNotifyRoutine,
                (PVOID)(ULONG_PTR)imageArray);
            KswordArkCallbackEnumAddUnsupportedRow(
                Builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
                L"PspLoadImageNotifyRoutine empty",
                detailText);
        }
    }
    else {
        const NTSTATUS pdbStatus = status;
        status = KswordArkCallbackEnumLocateValidatedGlobal(&moduleCache, KswCallbackGlobalImage, &imageArray);
        RtlZeroMemory(detailText, sizeof(detailText));
        if (!NT_SUCCESS(status)) {
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"未能通过 PsSetLoadImageNotifyRoutineEx 特征定位镜像 notify 数组。PDB path status=0x%08lX, CallbackProfileActive=%lu, RVA=0x%08lX, Source=%lu。",
                (unsigned long)pdbStatus,
                (unsigned long)pdbProfile.State.CallbackProfileActive,
                (unsigned long)pdbProfile.State.CallbackGlobals.PspLoadImageNotifyRoutine,
                (unsigned long)pdbProfile.State.CallbackGlobalSources.PspLoadImageNotifyRoutine);
        }
        KswordArkCallbackEnumAddLocateRow(
            Builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
            L"PspLoadImageNotifyRoutine",
            imageArray,
            status,
            NT_SUCCESS(status)
                ? L"已定位 PspLoadImageNotifyRoutine 私有数组，开始遍历 EX_FAST_REF 槽。"
                : detailText);
        if (NT_SUCCESS(status)) {
            addedCount = KswordArkCallbackEnumAddNotifyArray(
                Builder,
                &moduleCache,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
                KSWORD_ARK_IMAGE_OP_LOAD,
                imageArray,
                L"PspLoadImageNotifyRoutine",
                NULL,
                0UL);
            if (addedCount == 0UL) {
                KswordArkCallbackEnumAddUnsupportedRow(
                    Builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE,
                    L"PspLoadImageNotifyRoutine empty",
                    L"已定位镜像 notify 数组，但未找到能解析到模块的有效 EX_CALLBACK_ROUTINE_BLOCK。");
            }
        }
    }

    if (NT_SUCCESS(KswordArkCallbackEnumPdbRvaToVa(
            &pdbProfile,
            pdbProfile.State.CallbackGlobals.CmCallbackListHead,
            pdbProfile.State.CallbackGlobalSources.CmCallbackListHead,
            sizeof(LIST_ENTRY),
            &cmListHead))) {
        addedCount = KswordArkCallbackEnumAddRegistryList(
            Builder,
            &moduleCache,
            cmListHead,
            &g_KswordArkCallbackEnumPdbRegistrySourceContext,
            pdbProfile.State.CallbackGlobals.CmCallbackListHead);
        if (addedCount == 0UL) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已使用 PDB RVA 0x%08lX 转换出 CmCallbackListHead VA 0x%p，但链表为空或字段恢复未稳定。",
                (unsigned long)pdbProfile.State.CallbackGlobals.CmCallbackListHead,
                (PVOID)(ULONG_PTR)cmListHead);
            KswordArkCallbackEnumAddUnsupportedRow(
                Builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
                L"CmCallbackListHead empty",
                detailText);
        }
    }
    else {
        status = KswordArkCallbackEnumLocateValidatedGlobal(&moduleCache, KswCallbackGlobalRegistry, &cmListHead);
        KswordArkCallbackEnumAddLocateRow(
            Builder,
            KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
            L"CmCallbackListHead",
            cmListHead,
            status,
            NT_SUCCESS(status)
                ? L"已定位 CmCallbackListHead 私有链表，开始保守遍历并识别 Function/Altitude。"
                : L"未能通过 CmUnRegisterCallback 特征定位注册表回调链表头。");
        if (NT_SUCCESS(status)) {
            addedCount = KswordArkCallbackEnumAddRegistryList(
                Builder,
                &moduleCache,
                cmListHead,
                NULL,
                0UL);
            if (addedCount == 0UL) {
                KswordArkCallbackEnumAddUnsupportedRow(
                    Builder,
                    KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY,
                    L"CmCallbackListHead empty",
                    L"已定位注册表回调链表头，但未找到能解析到模块的 Function 字段。");
            }
        }
    }

    status = KswordArkCallbackEnumLocateObpCallPreOperationCallbacks(&moduleCache, &obpCallPreOperationCallbacks);
    KswordArkCallbackEnumAddLocateRow(
        Builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
        L"ObpCallPreOperationCallbacks",
        obpCallPreOperationCallbacks,
        status,
        NT_SUCCESS(status)
            ? L"已定位 ObpCallPreOperationCallbacks 内部例程；对象回调项继续从 OBJECT_TYPE CallbackList 启发式枚举。"
            : L"未能通过 ntoskrnl 特征定位 ObpCallPreOperationCallbacks；仍会尝试 OBJECT_TYPE 链表启发式枚举。");

    addedCount = 0UL;
    if (PsProcessType != NULL && *PsProcessType != NULL) {
        addedCount += KswordArkCallbackEnumAddObjectTypeCallbackList(
            Builder,
            &moduleCache,
            *PsProcessType,
            KSWORD_ARK_OBJECT_OP_TYPE_PROCESS,
            L"Process",
            &pdbProfile,
            pdbProfile.Active ? &g_KswordArkCallbackEnumPdbObjectSourceContext : NULL);
    }
    if (PsThreadType != NULL && *PsThreadType != NULL) {
        addedCount += KswordArkCallbackEnumAddObjectTypeCallbackList(
            Builder,
            &moduleCache,
            *PsThreadType,
            KSWORD_ARK_OBJECT_OP_TYPE_THREAD,
            L"Thread",
            &pdbProfile,
            pdbProfile.Active ? &g_KswordArkCallbackEnumPdbObjectSourceContext : NULL);
    }
    if (ExDesktopObjectType != NULL && *ExDesktopObjectType != NULL) {
        addedCount += KswordArkCallbackEnumAddObjectTypeCallbackList(
            Builder,
            &moduleCache,
            *ExDesktopObjectType,
            KSWORD_ARK_OBJECT_OP_TYPE_DESKTOP,
            L"Desktop",
            &pdbProfile,
            pdbProfile.Active ? &g_KswordArkCallbackEnumPdbObjectSourceContext : NULL);
    }
    if (addedCount == 0UL) {
        if (pdbProfile.Active &&
            KswordArkCallbackEnumPdbOffsetAvailable(
                pdbProfile.State.CallbackOffsets.ObjectTypeCallbackList,
                pdbProfile.State.CallbackOffsetSources.ObjectTypeCallbackList)) {
            RtlZeroMemory(detailText, sizeof(detailText));
            (VOID)RtlStringCbPrintfW(
                detailText,
                sizeof(detailText),
                L"已尝试 PDB _OBJECT_TYPE.CallbackList offset 0x%08lX 及 _CALLBACK_ENTRY_ITEM offsets [EntryList=0x%08lX,Pre=0x%08lX,Post=0x%08lX,Ops=0x%08lX,CallbackEntry=0x%08lX]；未能识别非空对象回调链表。",
                (unsigned long)pdbProfile.State.CallbackOffsets.ObjectTypeCallbackList,
                (unsigned long)pdbProfile.State.CallbackOffsets.CallbackEntryItemEntryList,
                (unsigned long)pdbProfile.State.CallbackOffsets.CallbackEntryItemPreOperation,
                (unsigned long)pdbProfile.State.CallbackOffsets.CallbackEntryItemPostOperation,
                (unsigned long)pdbProfile.State.CallbackOffsets.CallbackEntryItemOperations,
                (unsigned long)pdbProfile.State.CallbackOffsets.CallbackEntryItemCallbackEntry);
            KswordArkCallbackEnumAddUnsupportedRow(
                Builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
                L"OBJECT_TYPE CallbackList empty",
                detailText);
        }
        else {
            KswordArkCallbackEnumAddUnsupportedRow(
                Builder,
                KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT,
                L"OBJECT_TYPE CallbackList empty",
                L"未能在 Process/Thread/Desktop OBJECT_TYPE 私有区域识别非空 CallbackList；对象回调结构随版本变化较大。");
        }
    }

    if (notifyMaskValue != 0UL) {
        KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = KswordArkCallbackEnumReserveEntry(Builder);
        if (entry != NULL) {
            entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS;
            entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
            entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
            entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS;
            entry->contextAddress = notifyMaskValue;
            entry->registrationAddress = notifyEnableMask;
            KswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), L"PspNotifyEnableMask value");
            (VOID)RtlStringCbPrintfW(
                entry->detail,
                sizeof(entry->detail),
                L"PspNotifyEnableMask=0x%08lX，Address=0x%p；该值仅用于诊断 notify 路径启用状态。",
                (unsigned long)notifyMaskValue,
                (PVOID)(ULONG_PTR)notifyEnableMask);
        }
    }

    KswordArkCallbackEnumFreeModuleCache(&moduleCache);
}

static VOID
KswordArkCallbackEnumAddSystemInformerDynDataRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    把 System Informer DynData 的回调相关字段写入诊断行。中文说明：当前
    Ksword 已经 vendored kphdyn 数据，本行明确展示 ETW 私有结构偏移是否命中。

Arguments:

    Builder - 枚举响应构建器。

Return Value:

    无返回值。

--*/
{
    KSW_DYN_STATE dynState;
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    RtlZeroMemory(&dynState, sizeof(dynState));
    KswordARKDynDataSnapshot(&dynState);

    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
    entry->status = ((dynState.CapabilityMask & KSW_CAP_ETW_GUID_FIELDS) != 0ULL)
        ? KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
        : KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    entry->lastStatus = dynState.LastStatus;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS;
    entry->contextAddress = ((ULONG64)dynState.Kernel.EgeGuid << 32) |
        (ULONG64)dynState.Kernel.EreGuidEntry;
    KswordArkCallbackEnumCopyWide(
        entry->name,
        RTL_NUMBER_OF(entry->name),
        L"System Informer DynData: ETW offsets");
    (VOID)RtlStringCbPrintfW(
        entry->detail,
        sizeof(entry->detail),
        L"已复用 third_party/systeminformer_dyn/kphdyn 数据；NtosActive=%lu，EgeGuid=0x%08lX，EreGuidEntry=0x%08lX，cap=0x%llX。",
        (unsigned long)(dynState.NtosActive ? 1UL : 0UL),
        (unsigned long)dynState.Kernel.EgeGuid,
        (unsigned long)dynState.Kernel.EreGuidEntry,
        dynState.CapabilityMask);
}

static VOID
KswordArkCallbackEnumAddUnsupportedKinds(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    添加仍未覆盖类别的说明行。中文说明：进程、线程、镜像、注册表、对象和
    WFP 已由其它阶段处理；此处只保留 ETW 仍缺少安全全局入口的说明。

Arguments:

    Builder - 枚举响应构建器。

Return Value:

    无返回值。

--*/
{
    KswordArkCallbackEnumAddSystemInformerDynDataRow(Builder);
    KswordArkCallbackEnumAddUnsupportedRow(
        Builder,
        KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER,
        L"ETW providers/consumers",
        L"System Informer DynData 暴露 EgeGuid/EreGuidEntry 偏移，但仍需安全定位 ETW 全局表入口；当前仅标记未支持。");
}

NTSTATUS
KswordArkCallbackEnumRevalidateRemoveRequest(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST* RequestPacket,
    _In_ BOOLEAN RequireGenerationMatch,
    _In_ BOOLEAN MatchIdentity, // 控制前置身份核对或后置注册存在性核对。
    _Out_ BOOLEAN* MatchPresentOut,
    _Out_opt_ ULONG* MatchedFieldFlagsOut,
    _Out_opt_ ULONG64* MatchedRegistrationAddressOut,
    _Out_opt_ ULONG64* CurrentGenerationOut,
    _Out_opt_ ULONG64* MatchedContextAddressOut, // 可选输出重新枚举得到的 API 上下文。
    _Out_opt_ ULONG* MatchedRegistrationTypeOut // 可选输出重新枚举得到的注册子类型。
    )
/*++

Routine Description:

    Rebuilds the kernel registration sources exposed by the default V3 R3
    enumeration, omitting unrelated WFP/Minifilter queries. Before unregistering,
    matches the selected registration keys against one currently enumerated row;
    after unregistering, checks registration presence independently of display
    metadata. No private address supplied by R3 is dereferenced here.

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_BUILDER builder;

    if (RequestPacket == NULL || MatchPresentOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *MatchPresentOut = FALSE;
    if (MatchedContextAddressOut != NULL) { // 未匹配时上下文保持零。
        *MatchedContextAddressOut = 0ULL; // 清空可选上下文输出。
    } // 结束上下文初始化。
    if (MatchedRegistrationTypeOut != NULL) { // 未匹配时子类型保持未知。
        *MatchedRegistrationTypeOut = 0UL; // 清空可选子类型输出。
    } // 结束子类型初始化。
    if (MatchedFieldFlagsOut != NULL) {
        *MatchedFieldFlagsOut = 0UL;
    }
    if (MatchedRegistrationAddressOut != NULL) {
        *MatchedRegistrationAddressOut = 0ULL;
    }
    if (CurrentGenerationOut != NULL) {
        *CurrentGenerationOut = 0ULL;
    }

    RtlZeroMemory(&builder, sizeof(builder));
    builder.LastStatus = STATUS_SUCCESS;
    builder.RemoveMatchRequest = RequestPacket;
    builder.RemoveMatchIdentity = MatchIdentity; // 保存本次匹配契约。
    KswordArkCallbackEnumSnapshotBegin(&builder);
    if (RequestPacket->callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER) { // 单独重建 Filter Manager 对象与对应回调，隔离无关内核枚举失败。
        KswordArkCallbackEnumAddMinifilters(&builder); // 前置恢复所属对象，后置只读公开对象集合。
    } else if (RequestPacket->callbackClass == KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS) { // 进程注册由实际 notify 数组证明，不能用自身缓存行确认存在。
        KswordArkCallbackEnumAddPrivateCallbacks(&builder); // 不引入 BugCheck/NMI 等无关扩展读取错误。
    } else { // 保持其它回调原有来源与顺序。
        KswordArkCallbackEnumAddSelfCallbacks(&builder); // 重建原有自身记录。
        KswordArkCallbackEnumAddPrivateCallbacks(&builder); // 重建原有内核私有注册。
        KswordArkCallbackExtendedAddSpecialCallbacks(&builder); // 重建特殊注册。
        KswordArkCallbackExtendedAddBugcheckCallbacks(&builder); // 只重建注销需要的内核注册行。
        KswordArkCallbackExtendedAddObjectCallbacks(&builder); // 排除无关 WFP 和 Minifilter 查询失败。
        KswordArkCallbackExtendedAddSystemCallbacks(&builder); // 保持各来源内部顺序和行身份一致。
        KswordArkCallbackExtendedAddNmiCallbacks(&builder); // NMI 仍使用自身定位和结构验证。
    } // 结束类别隔离。
    KswordArkCallbackEnumSnapshotFinalize(&builder);

    if (builder.SnapshotRowCount != builder.TotalCount || !NT_SUCCESS(builder.LastStatus)) {
        return NT_SUCCESS(builder.LastStatus) ? STATUS_DATA_ERROR : builder.LastStatus;
    }
    if (CurrentGenerationOut != NULL) {
        *CurrentGenerationOut = builder.SnapshotHash;
    }
    if (RequireGenerationMatch &&
        RequestPacket->enumerationGeneration != builder.SnapshotHash) {
        return STATUS_RETRY;
    }
    if (builder.RemoveMatchCount > 1UL) {
        return STATUS_DATA_ERROR;
    }
    if (builder.RemoveMatchCount == 0UL && !NT_SUCCESS(builder.RemoveQueryStatus)) { // 未匹配且目标查询失败不能作为不存在证据。
        return builder.RemoveQueryStatus; // 保留相关查询失败，无关类别失败不阻断注销。
    } // 结束缺失确认能力检查。
    if (builder.RemoveMatchCount == 1UL) {
        *MatchPresentOut = TRUE;
        if (MatchedFieldFlagsOut != NULL) {
            *MatchedFieldFlagsOut = builder.RemoveMatchedFieldFlags |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION |
                KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH;
        }
        if (MatchedRegistrationAddressOut != NULL) {
            *MatchedRegistrationAddressOut = builder.RemoveMatchedRegistrationAddress;
        }
        if (MatchedContextAddressOut != NULL) { // 只发布唯一匹配行的上下文。
            *MatchedContextAddressOut = builder.RemoveMatchedContextAddress; // 返回 API 上下文。
        } // 结束上下文输出。
        if (MatchedRegistrationTypeOut != NULL) { // 只发布唯一匹配行的注册子类型。
            *MatchedRegistrationTypeOut = builder.RemoveMatchedRegistrationType; // 返回注册子类型。
        } // 结束子类型输出。
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKCallbackIoctlEnumCallbacks(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* CompleteBytesOut
    )
/*++

Routine Description:

    处理 IOCTL_KSWORD_ARK_ENUM_CALLBACKS。中文说明：该 IOCTL 只读遍历当前可稳定
    获取的回调信息，优先返回 Ksword 自身注册项和 Filter Manager minifilter 列表。

Arguments:

    Request - 当前 WDF 请求。
    InputBufferLength - 输入缓冲区长度。
    OutputBufferLength - 输出缓冲区长度。
    CompleteBytesOut - 输出实际完成字节数。

Return Value:

    成功返回 STATUS_SUCCESS；参数或缓冲区不合法返回对应 NTSTATUS。

--*/
{
    /* 中文说明：下列变量先按最保守默认值初始化，完成协议协商后才写响应。 */
    NTSTATUS status = STATUS_SUCCESS;
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t inputLength = 0U;
    size_t outputLength = 0U;
    ULONG requestFlags = KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL;
    ULONG requestMaxEntries = KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES;
    ULONG requestStartIndex = 0UL;
    ULONG requestVersion = 0UL;
    ULONG snapshotPolicy = KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_NONE;
    ULONG expectedTotalCount = 0UL;
    ULONG responseHeaderBytes = 0UL;
    ULONG outputCapacity = 0UL;
    ULONG nextIndex = 0UL;
    ULONG legacyEntryIndex = 0UL;
    ULONG64 expectedSnapshotHash = 0ULL;
    BOOLEAN snapshotChanged = FALSE;
    KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2* requestPacketV2 = NULL;
    KSWORD_ARK_ENUM_CALLBACKS_REQUEST* requestPacket = NULL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2* responsePacketV2 = NULL;
    KSWORD_ARK_ENUM_CALLBACKS_RESPONSE* responsePacket = NULL;
    KSWORD_ARK_CALLBACK_ENUM_BUILDER builder;

    /* 中文说明：WDF 完成长度是必需输出，所有失败路径都保持其为零。 */
    if (CompleteBytesOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *CompleteBytesOut = 0U;

    if (InputBufferLength < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2) ||
        OutputBufferLength < g_KswordArkCallbackEnumHeaderBytesV2) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 中文说明：先按最短 V2 请求取缓冲，以允许新驱动服务旧 R3。 */
    status = WdfRequestRetrieveInputBuffer(
        Request,
        sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2),
        &inputBuffer,
        &inputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (inputLength < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    requestPacketV2 = (KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2*)inputBuffer;
    requestVersion = requestPacketV2->version;
    /* 中文说明：V3 才读取快照契约字段；V2 严格保持历史 24 字节布局。 */
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION) {
        if (inputLength < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST)) {
            return STATUS_BUFFER_TOO_SMALL;
        }
        requestPacket = (KSWORD_ARK_ENUM_CALLBACKS_REQUEST*)inputBuffer;
        if (requestPacket->size < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST)) {
            return STATUS_INVALID_PARAMETER;
        }
        expectedSnapshotHash = requestPacket->expectedSnapshotHash;
        expectedTotalCount = requestPacket->expectedTotalCount;
        snapshotPolicy = requestPacket->snapshotPolicy;
        responseHeaderBytes = g_KswordArkCallbackEnumHeaderBytesV3;
    }
    else if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION_V2) {
        if (requestPacketV2->size < sizeof(KSWORD_ARK_ENUM_CALLBACKS_REQUEST_V2)) {
            return STATUS_INVALID_PARAMETER;
        }
        responseHeaderBytes = g_KswordArkCallbackEnumHeaderBytesV2;
    }
    else {
        return STATUS_INVALID_PARAMETER;
    }

    /* 中文说明：未知快照策略以及缺少期望哈希的强匹配请求均直接拒绝。 */
    if (snapshotPolicy != KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_NONE &&
        snapshotPolicy != KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH) {
        return STATUS_INVALID_PARAMETER;
    }
    if (snapshotPolicy == KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH &&
        expectedSnapshotHash == 0ULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (OutputBufferLength < responseHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 中文说明：响应头长度跟随协商版本，禁止把 V3 字段写入 V2 缓冲。 */
    status = WdfRequestRetrieveOutputBuffer(
        Request,
        responseHeaderBytes,
        &outputBuffer,
        &outputLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (outputLength < responseHeaderBytes) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* 中文说明：规范化枚举类别、页大小和起始索引，限制单次内核工作量。 */
    requestFlags = requestPacketV2->flags;
    if (requestFlags == 0UL) {
        requestFlags = KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL;
    }
    if ((requestFlags & (~KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL)) != 0UL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (requestPacketV2->maxEntries != 0UL) {
        requestMaxEntries = requestPacketV2->maxEntries;
    }
    requestStartIndex = requestPacketV2->startIndex;
    if (requestMaxEntries > KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES) {
        requestMaxEntries = KSWORD_ARK_CALLBACK_ENUM_MAX_ENTRIES;
    }

    /* 中文说明：输出先整体清零，再仅按协商版本初始化对应响应头。 */
    RtlZeroMemory(outputBuffer, outputLength);
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION) {
        responsePacket = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE*)outputBuffer;
        responsePacket->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE);
        responsePacket->version = requestVersion;
        responsePacket->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
        responsePacket->lastStatus = STATUS_SUCCESS;
    }
    else {
        responsePacketV2 = (KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2*)outputBuffer;
        responsePacketV2->size = sizeof(KSWORD_ARK_ENUM_CALLBACKS_RESPONSE_V2);
        responsePacketV2->version = requestVersion;
        responsePacketV2->entrySize = sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY);
        responsePacketV2->lastStatus = STATUS_SUCCESS;
    }

    /* 中文说明：实际页容量同时受输出缓冲和请求上限约束。 */
    if (outputLength > responseHeaderBytes) {
        outputCapacity = (ULONG)((outputLength - responseHeaderBytes) / sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));
    }
    if (outputCapacity > requestMaxEntries) {
        outputCapacity = requestMaxEntries;
    }

    /* 中文说明：所有类别必须完整逻辑枚举，分页外行通过 ScratchEntry 参与哈希。 */
    RtlZeroMemory(&builder, sizeof(builder));
    builder.Entries = (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION)
        ? responsePacket->entries
        : responsePacketV2->entries;
    builder.EntryCapacity = outputCapacity;
    builder.StartIndex = requestStartIndex;
    builder.LastStatus = STATUS_SUCCESS;
    KswordArkCallbackEnumSnapshotBegin(&builder);

    /* 中文说明：类别标志只影响逻辑数据集组成，不改变快照算法。 */
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_KSWORD_SELF) != 0UL) {
        KswordArkCallbackEnumAddSelfCallbacks(&builder);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_MINIFILTERS) != 0UL) {
        KswordArkCallbackEnumAddMinifilters(&builder);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_PRIVATE) != 0UL) {
        KswordArkCallbackEnumAddPrivateCallbacks(&builder);
        KswordArkCallbackExtendedAddSpecialCallbacks(&builder);
        KswordArkCallbackExternalAddCallbacks(&builder);
    }
    if ((requestFlags & KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_UNSUPPORTED) != 0UL) {
        KswordArkCallbackEnumAddUnsupportedKinds(&builder);
    }

    /* 中文说明：最终化会提交尾行、发布行身份以及整份有序快照哈希。 */
    KswordArkCallbackEnumSnapshotFinalize(&builder);
    /* 中文说明：内部计数不一致表示枚举器漏提交了行，向 R3 暴露数据错误。 */
    if (builder.SnapshotRowCount != builder.TotalCount) {
        builder.LastStatus = STATUS_DATA_ERROR;
    }
    /* 中文说明：续页契约不匹配时不返回混合数据，并提示 R3 从第一页重试。 */
    if (snapshotPolicy == KSWORD_ARK_CALLBACK_SNAPSHOT_POLICY_REQUIRE_MATCH &&
        (builder.SnapshotHash != expectedSnapshotHash ||
         builder.TotalCount != expectedTotalCount)) {
        snapshotChanged = TRUE;
        builder.Flags |= KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED;
        builder.LastStatus = STATUS_RETRY;
        builder.ReturnedCount = 0UL;
    }
    /* 中文说明：旧协议不得发布 V3 独占标志，保持旧客户端行为可预测。 */
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION_V2) {
        /* 中文说明：V2 行中的哈希字段历史上保留为零，兼容响应必须清除 V3 派生值。 */
        for (legacyEntryIndex = 0UL;
             legacyEntryIndex < builder.ReturnedCount;
             ++legacyEntryIndex) {
            builder.Entries[legacyEntryIndex].enumerationGeneration = 0ULL;
            builder.Entries[legacyEntryIndex].identityHash = 0ULL;
            builder.Entries[legacyEntryIndex].fieldFlags &=
                ~(KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTITY_HASH |
                  KSWORD_ARK_CALLBACK_ENUM_FIELD_ENUMERATION_GENERATION);
        }
        builder.Flags &=
            ~(KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_HASH_VALID |
              KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_IDENTITY_HASH_VALID |
              KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_SNAPSHOT_CHANGED);
    }

    /* 中文说明：计算下一页索引；快照变化时显式归零以触发整轮重启。 */
    if (!snapshotChanged &&
        requestStartIndex <= builder.TotalCount &&
        builder.ReturnedCount <= (builder.TotalCount - requestStartIndex)) {
        nextIndex = requestStartIndex + builder.ReturnedCount;
    }
    else if (snapshotChanged) {
        nextIndex = 0UL;
    }
    else {
        nextIndex = builder.TotalCount;
    }
    if (!snapshotChanged && nextIndex < builder.TotalCount) {
        builder.Flags |= KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_MORE_DATA;
    }

    /* 中文说明：根据协商版本分别写头，V3 额外发布代次和快照哈希。 */
    if (requestVersion == KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION) {
        responsePacket->totalCount = builder.TotalCount;
        responsePacket->returnedCount = builder.ReturnedCount;
        responsePacket->flags = builder.Flags;
        responsePacket->lastStatus = builder.LastStatus;
        responsePacket->nextIndex = nextIndex;
        responsePacket->enumerationGeneration = builder.SnapshotHash;
        responsePacket->snapshotHash = builder.SnapshotHash;
    }
    else {
        responsePacketV2->totalCount = builder.TotalCount;
        responsePacketV2->returnedCount = builder.ReturnedCount;
        responsePacketV2->flags = builder.Flags;
        responsePacketV2->lastStatus = builder.LastStatus;
        responsePacketV2->nextIndex = nextIndex;
    }
    /* 中文说明：WDF 完成长度仅包含响应头和实际返回的连续条目。 */
    *CompleteBytesOut = (size_t)responseHeaderBytes +
        ((size_t)builder.ReturnedCount * sizeof(KSWORD_ARK_CALLBACK_ENUM_ENTRY));

    /* 中文说明：枚举级异常通过响应 lastStatus 表达，IOCTL 传输本身保持成功。 */
    return STATUS_SUCCESS;
}
