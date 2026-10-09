/*++

Module Name:

    callback_external_wfp.c

Abstract:

    WFP callout enumeration and safe removal through public WFP management APIs.

Environment:

    Kernel-mode Driver Framework

--*/

#include "callback_external_wfp.h"
#include <ntimage.h>
#include "../../platform/runtime_signature_scan.h" // 候选 PE 字段统一安全读取。

#define KSWORD_ARK_WFP_ENUM_PAGE_SIZE 64U
#define KSWORD_ARK_WFP_MAX_CALLOUT_ID 0xFFFFFFFFULL

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10U
#endif

typedef struct _SEC_WINNT_AUTH_IDENTITY_W SEC_WINNT_AUTH_IDENTITY_W;

typedef struct _KSWORD_ARK_FWPM_DISPLAY_DATA0
{
    WCHAR* name;
    WCHAR* description;
} KSWORD_ARK_FWPM_DISPLAY_DATA0;

typedef struct _KSWORD_ARK_FWPM_SESSION0
{
    GUID sessionKey;
    KSWORD_ARK_FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    UINT32 txnWaitTimeoutInMSec;
    ULONG processId;
    SID* sid;
    WCHAR* username;
    BOOLEAN kernelMode;
} KSWORD_ARK_FWPM_SESSION0;

typedef struct _KSWORD_ARK_FWPM_CALLOUT_ENUM_TEMPLATE0
{
    GUID* providerKey;
    GUID layerKey;
} KSWORD_ARK_FWPM_CALLOUT_ENUM_TEMPLATE0;

typedef struct _KSWORD_ARK_FWPM_CALLOUT0
{
    GUID calloutKey;
    KSWORD_ARK_FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    struct
    {
        UINT32 size;
        UINT8* data;
    } providerData;
    GUID applicableLayer;
    UINT32 calloutId;
} KSWORD_ARK_FWPM_CALLOUT0;

typedef NTSTATUS (*KSWORD_ARK_WFP_ENGINE_OPEN)(
    _In_opt_ const WCHAR* ServerName,
    _In_ UINT32 AuthnService,
    _In_opt_ SEC_WINNT_AUTH_IDENTITY_W* AuthIdentity,
    _In_opt_ const KSWORD_ARK_FWPM_SESSION0* Session,
    _Out_ HANDLE* EngineHandle);
typedef NTSTATUS (*KSWORD_ARK_WFP_ENGINE_CLOSE)(_In_ HANDLE EngineHandle);
typedef NTSTATUS (*KSWORD_ARK_WFP_CALLOUT_CREATE_ENUM_HANDLE)(
    _In_ HANDLE EngineHandle,
    _In_opt_ const KSWORD_ARK_FWPM_CALLOUT_ENUM_TEMPLATE0* EnumTemplate,
    _Out_ HANDLE* EnumHandle);
typedef NTSTATUS (*KSWORD_ARK_WFP_CALLOUT_DESTROY_ENUM_HANDLE)(
    _In_ HANDLE EngineHandle,
    _In_ HANDLE EnumHandle);
typedef NTSTATUS (*KSWORD_ARK_WFP_CALLOUT_ENUM)(
    _In_ HANDLE EngineHandle,
    _In_ HANDLE EnumHandle,
    _In_ UINT32 NumEntriesRequested,
    _Outptr_result_buffer_(*NumEntriesReturned) KSWORD_ARK_FWPM_CALLOUT0*** Entries,
    _Out_ UINT32* NumEntriesReturned);
typedef NTSTATUS (*KSWORD_ARK_WFP_CALLOUT_GET_BY_ID)(
    _In_ HANDLE EngineHandle,
    _In_ UINT32 Id,
    _Outptr_ KSWORD_ARK_FWPM_CALLOUT0** Callout);
typedef NTSTATUS (*KSWORD_ARK_WFP_CALLOUT_DELETE_BY_ID)(
    _In_ HANDLE EngineHandle,
    _In_ UINT32 Id);
typedef VOID (*KSWORD_ARK_WFP_FREE_MEMORY)(_Inout_ VOID** Pointer);

typedef struct _KSWORD_ARK_WFP_API
{
    KSWORD_ARK_WFP_ENGINE_OPEN EngineOpen;
    KSWORD_ARK_WFP_ENGINE_CLOSE EngineClose;
    KSWORD_ARK_WFP_CALLOUT_CREATE_ENUM_HANDLE CalloutCreateEnumHandle;
    KSWORD_ARK_WFP_CALLOUT_DESTROY_ENUM_HANDLE CalloutDestroyEnumHandle;
    KSWORD_ARK_WFP_CALLOUT_ENUM CalloutEnum;
    KSWORD_ARK_WFP_CALLOUT_GET_BY_ID CalloutGetById;
    KSWORD_ARK_WFP_CALLOUT_DELETE_BY_ID CalloutDeleteById;
    KSWORD_ARK_WFP_FREE_MEMORY FreeMemory;
} KSWORD_ARK_WFP_API;

static BOOLEAN
KswordArkWfpAnsiPathContains(
    _In_reads_bytes_(TextBytes) const UCHAR* Text,
    _In_ ULONG TextBytes,
    _In_z_ const CHAR* Needle
    )
/*++

Routine Description:

    在系统模块 ANSI 路径中搜索小写子串。中文说明：只读固定模块路径字段，
    用于识别已加载的 fwpkclnt.sys。

Arguments:

    Text - 输入模块路径。
    TextBytes - 输入路径字段长度。
    Needle - 输入小写 ASCII 子串。

Return Value:

    命中返回 TRUE；否则返回 FALSE。

--*/
{
    ULONG textIndex = 0UL;

    if (Text == NULL || TextBytes == 0UL || Needle == NULL) {
        return FALSE;
    }

    for (textIndex = 0UL; textIndex < TextBytes && Text[textIndex] != '\0'; ++textIndex) {
        ULONG needleIndex = 0UL;

        for (needleIndex = 0UL; Needle[needleIndex] != '\0'; ++needleIndex) {
            UCHAR current = 0U;

            if (textIndex + needleIndex >= TextBytes) {
                return FALSE;
            }
            current = Text[textIndex + needleIndex];
            if (current == '\0') {
                return FALSE;
            }
            if (current >= 'A' && current <= 'Z') {
                current = (UCHAR)(current - 'A' + 'a');
            }
            if ((CHAR)current != Needle[needleIndex]) {
                break;
            }
        }
        if (Needle[needleIndex] == '\0') {
            return TRUE;
        }
    }

    return FALSE;
}

static BOOLEAN
KswordArkWfpRvaValid(
    _In_ ULONG Rva,
    _In_ ULONG Size,
    _In_ ULONG ImageSize
    )
/*++

Routine Description:

    校验 PE RVA 范围。中文说明：所有导出目录字段必须完全落在镜像范围内，
    溢出或空范围都视为不可用。

Arguments:

    Rva - 输入 RVA。
    Size - 输入区域大小。
    ImageSize - 输入镜像大小。

Return Value:

    范围可信返回 TRUE；否则返回 FALSE。

--*/
{
    if (Rva == 0UL || Size == 0UL || ImageSize == 0UL) {
        return FALSE;
    }
    if (Size > ImageSize || Rva >= ImageSize || Size > ImageSize - Rva) {
        return FALSE;
    }
    return TRUE;
}

// 单次模块快照与逐导出解析结果，不跨请求缓存候选地址。
typedef struct _KSWORD_ARK_WFP_RESOLUTION
{
    NTSTATUS ModuleStatus; // 模块查询/定位状态。
    ULONG64 ModuleBase; // 本次 fwpkclnt 基址。
    ULONG ModuleSize; // 本次映像范围。
    PVOID Addresses[8]; // 八个精确导出地址。
    NTSTATUS Statuses[8]; // 八个独立解析状态。
} KSWORD_ARK_WFP_RESOLUTION;

// 前六项是枚举所需；后两项仅用于移除。
static const CHAR* const KswordArkWfpExportNames[8] = {
    "FwpmEngineOpen0", "FwpmEngineClose0", "FwpmCalloutCreateEnumHandle0",
    "FwpmCalloutDestroyEnumHandle0", "FwpmCalloutEnum0", "FwpmFreeMemory0",
    "FwpmCalloutGetById0", "FwpmCalloutDeleteById0"
};

// 允许零 RVA 的 DOS header，安全读取完整字段，避免把换出页面误判成导出缺失。
static BOOLEAN
KswordArkWfpReadImage(ULONG64 Base, ULONG ImageSize, ULONG Rva, PVOID Buffer, ULONG Size)
{
    if (Base == 0ULL || Size > ImageSize || Rva > ImageSize - Size) {
        return FALSE; // 字段必须完整在映像中。
    }
    return KswordARKRuntimeReadMemory((PVOID)(ULONG_PTR)(Base + Rva), Buffer, Size); // 不直接解引用 PE。
}

// 区分不可读、PE 格式错误、缺失名称与 forwarder；仅发布精确导出地址。
static NTSTATUS
KswordArkWfpResolveExport(ULONG64 Base, ULONG Size, const CHAR* RoutineName, PVOID* AddressOut)
{
    IMAGE_DOS_HEADER dos; // 本地 DOS header。
    IMAGE_NT_HEADERS64 nt; // 本地 x64 NT header。
    IMAGE_EXPORT_DIRECTORY dir; // 本地导出目录。
    ULONG exportRva = 0UL; // 导出范围起点。
    ULONG exportSize = 0UL; // 导出范围长度。
    ULONG index = 0UL; // 有界名称索引。
    SIZE_T nameLength = strlen(RoutineName) + 1U; // 精确名称比较含终止符。

    *AddressOut = NULL; // 失败不得保留入口。
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE; // WFP 管理 API 需要 PASSIVE_LEVEL。
    }
    if (!KswordArkWfpReadImage(Base, Size, 0UL, &dos, sizeof(dos))) {
        return STATUS_PARTIAL_COPY; // 记录 header 读取失败。
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0) {
        return STATUS_INVALID_IMAGE_FORMAT; // 拒绝无效 DOS header。
    }
    if (!KswordArkWfpReadImage(Base, Size, (ULONG)dos.e_lfanew, &nt, sizeof(nt))) {
        return STATUS_PARTIAL_COPY; // NT header 必须完整复制。
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) {
        return STATUS_INVALID_IMAGE_FORMAT; // 只解析 x64 PE 导出。
    }
    exportRva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress; // 取导出 RVA。
    exportSize = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size; // 取导出大小。
    if (!KswordArkWfpRvaValid(exportRva, exportSize, Size)) {
        return STATUS_INVALID_IMAGE_FORMAT; // 导出范围必须完整。
    }
    if (!KswordArkWfpReadImage(Base, Size, exportRva, &dir, sizeof(dir))) {
        return STATUS_PARTIAL_COPY; // 导出目录可能位于分页映像。
    }
    if (dir.NumberOfNames == 0UL || dir.NumberOfNames > Size / sizeof(ULONG) ||
        dir.NumberOfFunctions > Size / sizeof(ULONG) ||
        !KswordArkWfpRvaValid(dir.AddressOfNames, dir.NumberOfNames * sizeof(ULONG), Size) ||
        !KswordArkWfpRvaValid(dir.AddressOfNameOrdinals, dir.NumberOfNames * sizeof(USHORT), Size) ||
        !KswordArkWfpRvaValid(dir.AddressOfFunctions, dir.NumberOfFunctions * sizeof(ULONG), Size)) {
        return STATUS_INVALID_IMAGE_FORMAT; // 先检查数量，避免数组大小乘法溢出。
    }
    for (index = 0UL; index < dir.NumberOfNames; ++index) {
        ULONG nameRva = 0UL; // 当前名称位置。
        ULONG functionRva = 0UL; // 当前函数位置。
        USHORT ordinal = 0U; // 当前 ordinal。
        CHAR name[64] = { 0 }; // 只比较安全复制的名称。

        if (!KswordArkWfpReadImage(Base, Size, dir.AddressOfNames + index * sizeof(ULONG), &nameRva, sizeof(nameRva)) ||
            !KswordArkWfpReadImage(Base, Size, dir.AddressOfNameOrdinals + index * sizeof(USHORT), &ordinal, sizeof(ordinal))) {
            return STATUS_PARTIAL_COPY; // 数组读取失败不能当成导出缺失。
        }
        if (nameLength > sizeof(name) || !KswordArkWfpRvaValid(nameRva, (ULONG)nameLength, Size)) {
            return STATUS_INVALID_IMAGE_FORMAT; // 不越界比较名称。
        }
        if (!KswordArkWfpReadImage(Base, Size, nameRva, name, (ULONG)nameLength)) {
            return STATUS_PARTIAL_COPY; // 保留名称页读取失败。
        }
        if (memcmp(name, RoutineName, nameLength) != 0) {
            continue; // 继续查找精确名称。
        }
        if (ordinal >= dir.NumberOfFunctions) {
            return STATUS_INVALID_IMAGE_FORMAT; // ordinal 必须有效。
        }
        if (!KswordArkWfpReadImage(Base, Size, dir.AddressOfFunctions + ordinal * sizeof(ULONG), &functionRva, sizeof(functionRva))) {
            return STATUS_PARTIAL_COPY; // 安全读取匹配的入口 RVA。
        }
        if (functionRva >= exportRva && functionRva - exportRva < exportSize) {
            return STATUS_NOT_SUPPORTED; // 不调用 forwarder 字符串。
        }
        if (!KswordArkWfpRvaValid(functionRva, 1UL, Size)) {
            return STATUS_INVALID_IMAGE_FORMAT; // 入口必须属于本映像。
        }
        *AddressOut = (PVOID)(ULONG_PTR)(Base + functionRva); // 仅发布校验后的地址。
        return STATUS_SUCCESS; // 精确导出找到。
    }
    return STATUS_PROCEDURE_NOT_FOUND; // 完整扫描后报告缺失。
}

// 使用一份模块快照解析八个导出，只要求当前操作需要的能力。
static NTSTATUS
KswordArkWfpResolveApi(KSWORD_ARK_WFP_API* ApiOut, KSWORD_ARK_WFP_RESOLUTION* Resolution, BOOLEAN ForRemoval)
{
    KSWORD_ARK_CALLBACK_MODULE_CACHE cache; // 单请求模块快照。
    ULONG index = 0UL; // 模块与导出索引。
    ULONG capacity = 0UL; // 真实模块表容量。
    BOOLEAN ready = TRUE; // 当前操作的能力结果。

    RtlZeroMemory(ApiOut, sizeof(*ApiOut)); // 清空 API 表。
    RtlZeroMemory(Resolution, sizeof(*Resolution)); // 清空诊断。
    KswordArkCallbackEnumInitModuleCache(&cache); // 初始化快照。
    Resolution->ModuleStatus = KswordArkCallbackEnumEnsureModuleCache(&cache); // 保留查询状态。
    if (NT_SUCCESS(Resolution->ModuleStatus) && cache.ModuleInfo != NULL) {
        if (cache.ModuleInfoBytes < (ULONG)FIELD_OFFSET(KSWORD_ARK_CALLBACK_MODULE_INFORMATION, Modules)) {
            Resolution->ModuleStatus = STATUS_INFO_LENGTH_MISMATCH; // 拒绝不完整表头。
        }
        else {
            capacity = (cache.ModuleInfoBytes - FIELD_OFFSET(KSWORD_ARK_CALLBACK_MODULE_INFORMATION, Modules)) / sizeof(KSWORD_ARK_CALLBACK_MODULE_ENTRY); // 按实际缓冲计算容量。
            Resolution->ModuleStatus = STATUS_NOT_FOUND; // 未定位到模块的状态。
            if (cache.ModuleInfo->NumberOfModules > capacity) {
                Resolution->ModuleStatus = STATUS_INFO_LENGTH_MISMATCH; // 拒绝越界模块数量。
            }
            else {
                for (index = 0UL; index < cache.ModuleInfo->NumberOfModules; ++index) {
                    const KSWORD_ARK_CALLBACK_MODULE_ENTRY* module = &cache.ModuleInfo->Modules[index]; // 本地模块快照项。
                    if (KswordArkWfpAnsiPathContains(module->FullPathName, RTL_NUMBER_OF(module->FullPathName), "fwpkclnt.sys")) {
                        Resolution->ModuleBase = (ULONG64)(ULONG_PTR)module->ImageBase; // 记录基址。
                        Resolution->ModuleSize = module->ImageSize; // 记录范围。
                        Resolution->ModuleStatus = STATUS_SUCCESS; // 定位成功。
                        break; // 全部导出使用同一映像。
                    }
                }
            }
        }
    }
    KswordArkCallbackEnumFreeModuleCache(&cache); // 释放本次查询内存。
    KswordArkCallbackLogFormat("Info", "WFP resolve module: status=0x%08X base=0x%I64X size=0x%08X removal=%u.",
        (unsigned int)Resolution->ModuleStatus, Resolution->ModuleBase, (unsigned int)Resolution->ModuleSize, ForRemoval ? 1U : 0U); // 模块定位日志。
    for (index = 0UL; index < RTL_NUMBER_OF(KswordArkWfpExportNames); ++index) {
        Resolution->Statuses[index] = NT_SUCCESS(Resolution->ModuleStatus)
            ? KswordArkWfpResolveExport(Resolution->ModuleBase, Resolution->ModuleSize, KswordArkWfpExportNames[index], &Resolution->Addresses[index])
            : Resolution->ModuleStatus; // 每个导出保留独立状态。
        KswordArkCallbackLogFormat("Info", "WFP resolve export: name=%s status=0x%08X address=0x%I64X required=%u.",
            KswordArkWfpExportNames[index], (unsigned int)Resolution->Statuses[index], (ULONG64)(ULONG_PTR)Resolution->Addresses[index],
            (index < 6UL || ForRemoval) ? 1U : 0U); // 成功和失败都可对照。
        if ((index < 6UL || ForRemoval) && !NT_SUCCESS(Resolution->Statuses[index])) {
            ready = FALSE; // 移除专用导出不阻断枚举。
        }
    }
    ApiOut->EngineOpen = (KSWORD_ARK_WFP_ENGINE_OPEN)Resolution->Addresses[0]; // 引擎打开。
    ApiOut->EngineClose = (KSWORD_ARK_WFP_ENGINE_CLOSE)Resolution->Addresses[1]; // 引擎关闭。
    ApiOut->CalloutCreateEnumHandle = (KSWORD_ARK_WFP_CALLOUT_CREATE_ENUM_HANDLE)Resolution->Addresses[2]; // 枚举句柄创建。
    ApiOut->CalloutDestroyEnumHandle = (KSWORD_ARK_WFP_CALLOUT_DESTROY_ENUM_HANDLE)Resolution->Addresses[3]; // 枚举句柄释放。
    ApiOut->CalloutEnum = (KSWORD_ARK_WFP_CALLOUT_ENUM)Resolution->Addresses[4]; // 枚举数据读取。
    ApiOut->FreeMemory = (KSWORD_ARK_WFP_FREE_MEMORY)Resolution->Addresses[5]; // WFP 内存释放。
    ApiOut->CalloutGetById = (KSWORD_ARK_WFP_CALLOUT_GET_BY_ID)Resolution->Addresses[6]; // 移除前 ID 校验。
    ApiOut->CalloutDeleteById = (KSWORD_ARK_WFP_CALLOUT_DELETE_BY_ID)Resolution->Addresses[7]; // 公开移除 API。
    return ready ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED; // 保留原能力失败状态，细节另行输出。
}

static NTSTATUS
KswordArkWfpOpenEngine(
    _In_ const KSWORD_ARK_WFP_API* Api,
    _Out_ HANDLE* EngineHandleOut
    )
/*++

Routine Description:

    打开 WFP engine 会话。中文说明：WFP 管理 API 要求 PASSIVE_LEVEL，本函数
    先做 IRQL 门控。

Arguments:

    Api - 输入 API 表。
    EngineHandleOut - 输出 engine handle。

Return Value:

    成功返回 STATUS_SUCCESS；上下文不安全返回 STATUS_NOT_SUPPORTED。

--*/
{
    if (Api == NULL || Api->EngineOpen == NULL || EngineHandleOut == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *EngineHandleOut = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_NOT_SUPPORTED;
    }
    return Api->EngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, EngineHandleOut);
}

static VOID
KswordArkWfpAddRow(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder,
    _In_ const KSWORD_ARK_FWPM_CALLOUT0* Callout,
    _In_ BOOLEAN Removable
    )
/*++

Routine Description:

    写入 WFP callout 枚举行。中文说明：公开 FWPM_CALLOUT0 不暴露内核函数
    地址，因此 callbackAddress 存放 calloutId，并使用 IDENTIFIER 字段标志。

Arguments:

    Builder - 输入输出枚举构建器。
    Callout - 输入 WFP callout。

Return Value:

    无返回值。

--*/
{
    KSWORD_ARK_CALLBACK_ENUM_ENTRY* entry = NULL;

    if (Builder == NULL || Callout == NULL) {
        return;
    }
    entry = KswordArkCallbackEnumReserveEntry(Builder);
    if (entry == NULL) {
        return;
    }

    entry->callbackClass = KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT;
    entry->source = KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API;
    entry->status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    entry->fieldFlags = KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER |
        KSWORD_ARK_CALLBACK_ENUM_FIELD_NAME;
    if (Removable) {
        entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE; // 移除 API 完整才发布候选。
    }
    entry->callbackAddress = (ULONG64)Callout->calloutId;
    entry->registrationAddress = (ULONG64)Callout->calloutId;
    entry->lastStatus = STATUS_SUCCESS;

    if (Callout->displayData.name != NULL) {
        KswordArkCallbackEnumCopyWide(entry->name, RTL_NUMBER_OF(entry->name), Callout->displayData.name);
    }
    else {
        (VOID)RtlStringCbPrintfW(entry->name, sizeof(entry->name), L"WFP Callout #%lu", (unsigned long)Callout->calloutId);
    }
    if (Callout->displayData.description != NULL) {
        KswordArkCallbackEnumCopyWide(entry->altitude, RTL_NUMBER_OF(entry->altitude), Callout->displayData.description);
        if (entry->altitude[0] != L'\0') {
            entry->fieldFlags |= KSWORD_ARK_CALLBACK_ENUM_FIELD_ALTITUDE;
        }
    }
    (VOID)RtlStringCbPrintfW(
        entry->detail,
        sizeof(entry->detail),
        L"WFP FWPM_CALLOUT0；CalloutId=%lu，Flags=0x%08lX；公开 API 不返回 classify/notify 函数地址，移除使用 FwpmCalloutDeleteById0。",
        (unsigned long)Callout->calloutId,
        (unsigned long)Callout->flags);
}

VOID
KswordArkCallbackExternalWfpAddCallbacks(
    _Inout_ KSWORD_ARK_CALLBACK_ENUM_BUILDER* Builder
    )
/*++

Routine Description:

    枚举 WFP callout。中文说明：只使用公开 Fwpm* 管理 API，不扫描或修改 BFE
    内部链表；API 不可用时写入不支持说明行。

Arguments:

    Builder - 输入输出枚举构建器。

Return Value:

    无返回值。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE engineHandle = NULL;
    HANDLE enumHandle = NULL;
    UINT32 returnedCount = 0U;
    KSWORD_ARK_WFP_API api;
    KSWORD_ARK_WFP_RESOLUTION resolution; // 本次模块与导出证据。

    if (Builder == NULL) {
        return;
    }
    RtlZeroMemory(&api, sizeof(api));

    status = KswordArkWfpResolveApi(&api, &resolution, FALSE);
    if (!NT_SUCCESS(status)) {
        Builder->LastStatus = status;
        WCHAR detail[KSWORD_ARK_CALLBACK_ENUM_DETAIL_CHARS] = { 0 }; // 回执暴露定位结果。
        ULONG exportIndex = 0UL; // 缺失导出索引。
        (VOID)RtlStringCbPrintfW(detail, sizeof(detail), L"fwpkclnt.sys moduleStatus=0x%08X base=0x%I64X size=0x%08X；逐导出地址/状态见驱动日志 WFP resolve。",
            (unsigned int)resolution.ModuleStatus, resolution.ModuleBase, (unsigned int)resolution.ModuleSize); // 模块结果与导出结果分开。
        KswordArkCallbackEnumAddUnsupportedRow(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT, L"WFP callout enumeration", detail); // 原失败行保留。
        for (exportIndex = 0UL; exportIndex < 6UL; ++exportIndex) {
            if (!NT_SUCCESS(resolution.Statuses[exportIndex])) {
                (VOID)RtlStringCbPrintfW(detail, sizeof(detail), L"%S status=0x%08X；缺失=0xC000007A，读取失败=0x8000000D，PE 格式错误=0xC000007B，forwarder 不支持=0xC00000BB。",
                    KswordArkWfpExportNames[exportIndex], (unsigned int)resolution.Statuses[exportIndex]); // 名称与真实状态直接展示。
                KswordArkCallbackEnumAddUnsupportedRow(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT, L"WFP export resolution", detail); // 使用原行协议。
            }
        }
        return;
    }

    status = KswordArkWfpOpenEngine(&api, &engineHandle);
    if (!NT_SUCCESS(status)) {
        Builder->LastStatus = status;
        KswordArkCallbackEnumAddUnsupportedRow(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT, L"WFP callout enumeration", L"FwpmEngineOpen0 失败或当前 IRQL 不满足 PASSIVE_LEVEL。");
        return;
    }

    status = api.CalloutCreateEnumHandle(engineHandle, NULL, &enumHandle);
    if (!NT_SUCCESS(status)) {
        Builder->LastStatus = status;
        (VOID)api.EngineClose(engineHandle);
        KswordArkCallbackEnumAddUnsupportedRow(Builder, KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT, L"WFP callout enumeration", L"FwpmCalloutCreateEnumHandle0 失败，无法获取枚举快照。");
        return;
    }

    do {
        KSWORD_ARK_FWPM_CALLOUT0** entries = NULL;
        UINT32 entryIndex = 0U;
        returnedCount = 0U;

        status = api.CalloutEnum(engineHandle, enumHandle, KSWORD_ARK_WFP_ENUM_PAGE_SIZE, &entries, &returnedCount);
        if (!NT_SUCCESS(status)) {
            Builder->LastStatus = status;
            if (entries != NULL) {
                VOID* freePointer = entries;
                api.FreeMemory(&freePointer);
            }
            break;
        }
        for (entryIndex = 0U; entryIndex < returnedCount; ++entryIndex) {
            if (entries != NULL && entries[entryIndex] != NULL) {
                KswordArkWfpAddRow(Builder, entries[entryIndex], api.CalloutGetById != NULL && api.CalloutDeleteById != NULL); // 单独判断移除能力。
            }
        }
        if (entries != NULL) {
            VOID* freePointer = entries;
            api.FreeMemory(&freePointer);
        }
    } while (returnedCount == KSWORD_ARK_WFP_ENUM_PAGE_SIZE);

    (VOID)api.CalloutDestroyEnumHandle(engineHandle, enumHandle);
    (VOID)api.EngineClose(engineHandle);
}

NTSTATUS
KswordArkCallbackExternalWfpRemove(
    _In_ const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST* RequestPacket,
    _Inout_ KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE* ResponsePacket
    )
/*++

Routine Description:

    通过 calloutId 移除 WFP callout。中文说明：先用 FwpmCalloutGetById0 验证
    该 ID 来自当前可枚举对象，再调用 FwpmCalloutDeleteById0。

Arguments:

    RequestPacket - 输入请求，callbackAddress 承载 calloutId。
    ResponsePacket - 输入输出响应。

Return Value:

    成功返回 STATUS_SUCCESS；不可验证或 API 不可用返回对应 NTSTATUS。

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    HANDLE engineHandle = NULL;
    KSWORD_ARK_FWPM_CALLOUT0* callout = NULL;
    UINT32 calloutId = 0U;
    KSWORD_ARK_WFP_API api;
    KSWORD_ARK_WFP_RESOLUTION resolution; // 本次模块与导出证据。

    if (RequestPacket == NULL || ResponsePacket == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (RequestPacket->callbackClass != KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT ||
        RequestPacket->callbackAddress == 0ULL || RequestPacket->callbackAddress > KSWORD_ARK_WFP_MAX_CALLOUT_ID) {
        return STATUS_INVALID_PARAMETER;
    }

    calloutId = (UINT32)RequestPacket->callbackAddress;
    RtlZeroMemory(&api, sizeof(api));
    status = KswordArkWfpResolveApi(&api, &resolution, TRUE); // 移除保留全部 API 要求。
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = KswordArkWfpOpenEngine(&api, &engineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = api.CalloutGetById(engineHandle, calloutId, &callout);
    if (!NT_SUCCESS(status) || callout == NULL) {
        (VOID)api.EngineClose(engineHandle);
        return status;
    }

    ResponsePacket->mappingFlags |= KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
        KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
    if (callout->displayData.name != NULL) {
        KswordArkCallbackEnumCopyWide(ResponsePacket->serviceName, RTL_NUMBER_OF(ResponsePacket->serviceName), callout->displayData.name);
    }

    {
        VOID* freePointer = callout;
        api.FreeMemory(&freePointer);
        callout = NULL;
    }

    status = api.CalloutDeleteById(engineHandle, calloutId);
    (VOID)api.EngineClose(engineHandle);
    return status;
}
