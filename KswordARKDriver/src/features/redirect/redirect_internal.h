#pragma once

#include <fltKernel.h>
#include <ntstrsafe.h>
#include <wdf.h>

#include "ark/ark_redirect.h"
#include "ark/ark_log.h"

#define KSWORD_ARK_REDIRECT_TAG_RULES 'rRsK'
#define KSWORD_ARK_REDIRECT_TAG_PATH  'pRsK'

typedef struct _KSWORD_ARK_REDIRECT_RUNTIME
{
    EX_PUSH_LOCK Lock;
    WDFDEVICE Device;
    LARGE_INTEGER RegistryCookie;
    NTSTATUS RegistryRegisterStatus;
    ULONG RuntimeFlags;
    ULONG FileRuleCount;
    ULONG RegistryRuleCount;
    ULONG Generation;
    volatile LONG64 FileRedirectHits;
    volatile LONG64 RegistryRedirectHits;
    KSWORD_ARK_REDIRECT_RULE Rules[KSWORD_ARK_REDIRECT_MAX_RULES];
} KSWORD_ARK_REDIRECT_RUNTIME;

EXTERN_C_START

// 中文说明：在规则发布前解析 DOS 盘符符号链接，卷内相对路径保持原样。
NTSTATUS KswordARKRedirectNormalizeFilePath(_Inout_updates_(KSWORD_ARK_REDIRECT_PATH_CHARS) WCHAR* Path);

KSWORD_ARK_REDIRECT_RUNTIME*
KswordARKRedirectGetRuntime(
    VOID
    );

VOID
KswordARKRedirectLogFormat(
    _In_z_ PCSTR LevelText,
    _In_z_ _Printf_format_string_ PCSTR FormatText,
    ...
    );

ULONG
KswordARKRedirectCountRulesByTypeLocked(
    _In_ const KSWORD_ARK_REDIRECT_RUNTIME* Runtime,
    _In_ ULONG Type
    );

BOOLEAN
KswordARKRedirectIsRulePathValid(
    _In_ const WCHAR* Text,
    _In_ ULONG MaxChars,
    _Out_ USHORT* LengthCharsOut
    );

NTSTATUS
KswordARKRedirectCopyUnicodeToAllocatedString(
    _In_ const UNICODE_STRING* Source,
    _Out_ UNICODE_STRING* Destination,
    _In_ ULONG PoolTag
    );

NTSTATUS
KswordARKRedirectFindMatchLocked(
    _In_ KSWORD_ARK_REDIRECT_RUNTIME* Runtime,
    _In_ ULONG Type,
    _In_ ULONG ProcessId,
    _In_ const UNICODE_STRING* SourcePath,
    _Out_ KSWORD_ARK_REDIRECT_RULE* MatchedRuleOut
    );

NTSTATUS
KswordARKRedirectRegistryRegister(
    _In_ KSWORD_ARK_REDIRECT_RUNTIME* Runtime,
    _In_ PDRIVER_OBJECT DriverObject
    );

VOID
KswordARKRedirectRegistryUnregister(
    _In_ KSWORD_ARK_REDIRECT_RUNTIME* Runtime
    );

EXTERN_C_END
