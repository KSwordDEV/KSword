#pragma once

#include <ntddk.h>

#include "KswordArkStartupProtocol.h"

EXTERN_C_START

//
// 启动 breadcrumb 模块。DriverEntry 的每一个致命步骤在调用前登记阶段号，
// 失败时把阶段号与原始 NTSTATUS 持久化到服务的 Parameters 键，
// 使得只在少数机器上出现的加载失败（SCM 只报 Win32 31）可以离线定位。
//

VOID
KswordArkStartupBreadcrumbInitialize(
    _In_opt_ PDRIVER_OBJECT DriverObject,
    _In_opt_ PCUNICODE_STRING RegistryPath
    );

VOID
KswordArkStartupStage(
    _In_ KSWORD_ARK_START_STAGE Stage
    );

NTSTATUS
KswordArkStartupFailure(
    _In_ KSWORD_ARK_START_STAGE Stage,
    _In_ NTSTATUS Status
    );

VOID
KswordArkStartupNoteCallbackMask(
    _In_ ULONG CallbackMask
    );

VOID
KswordArkStartupReady(
    VOID
    );

ULONG
KswordArkStartupGetOsBuildNumber(
    VOID
    );

BOOLEAN
KswordArkStartupIsOsBuildSupported(
    VOID
    );

EXTERN_C_END
