#pragma once

/*
 * 中文说明：
 * 1) 本头文件声明 HWID Dispatch hook 的 IRP 完成例程安装入口；
 * 2) IOCTL 层负责启用/卸载 MajorFunction hook，本模块只负责识别目标 IOCTL 并改写返回缓冲；
 * 3) 完成例程在 IRP 完成时释放安装方传入的在途计数，卸载路径依赖该计数等待本模块代码退出；
 * 4) 该模块不包含物理内存扫描、SMBIOS 物理表写入或卷引导扇区直写逻辑。
 */

#include "ark/ark_driver.h"
#include "driver/KswordArkHwidIoctl.h"

BOOLEAN
KswordARKHwidPrepareDispatchCompletion(
    _Inout_ PIRP Irp,
    _Inout_ PIO_STACK_LOCATION IoStack,
    _In_ ULONG TargetFlag,
    _In_ const KSWORD_ARK_HWID_DISPATCH_PROFILE* Profile,
    _Inout_ volatile LONG* CompletionInFlightCounter
    );
