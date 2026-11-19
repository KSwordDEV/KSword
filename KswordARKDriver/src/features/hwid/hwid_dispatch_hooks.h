#pragma once

/*
 * 中文说明：
 * 1) 本头文件声明 HWID 请求的配置快照与 IRP 完成例程安装入口；
 * 2) IOCTL 层负责启用/卸载 MajorFunction hook，本模块只负责识别目标 IOCTL 并改写返回缓冲；
 * 3) 该模块不包含物理内存扫描、SMBIOS 物理表写入或卷引导扇区直写逻辑。
 */

#include "ark/ark_driver.h"
#include "driver/KswordArkHwidIoctl.h"

// 将控制端发布的同一版配置复制到该 IRP 的非分页完成上下文。
VOID
KswordARKHwidSnapshotActiveProfile(
    _Out_ KSWORD_ARK_HWID_DISPATCH_PROFILE* Destination
    );

BOOLEAN
KswordARKHwidPrepareDispatchCompletion(
    _Inout_ PIRP Irp,
    _Inout_ PIO_STACK_LOCATION IoStack,
    _In_ ULONG TargetFlag
    );
