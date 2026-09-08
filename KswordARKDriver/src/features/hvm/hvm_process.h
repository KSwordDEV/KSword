/*++

Module Name:

    hvm_process.h

Abstract:

    R-1 层的进程处置：按地址空间拒绝执行，再决定拒绝时给客户机什么。

    协议侧的完整语义写在 shared/driver/KswordArkHvmIoctl.h 的 HVM_PROCESS 段，
    这里只补驱动内部才看得见的三条约束：

    1. 作用域靠 CR3-load exiting。没有它就不知道哪个地址空间正在跑，拒绝会落到
       全机器头上而不是一个进程头上，所以缺这一位是拒绝而不是降级。
    2. 受限层次由 EPTP 切换后端构造，构造要分页与写 EPT 表，只能在常驻停着时做
       —— 与 EPT 规则、分离视图同一条规矩，理由也一样：常驻期间退出路径不持锁
       读这些表，而新分配的页可能带着陈旧的 EPT 标签。
    3. 退出路径上的两个入口（CR3 装载、EPT 违规）都不加锁读这张表。表只在常驻
       停着时被改，这一点由上面第 2 条保证。

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* 退出路径要对这次执行做什么。 */
typedef enum _KSW_HVM_PROCESS_ACTION
{
    /* 这一页不归本模块管，调用方按原有路径继续。 */
    KswHvmProcessActionNone = 0,
    /* 注入 #PF(present)，指令不退休、状态不变，撤销后原地继续。 */
    KswHvmProcessActionFreeze = 1,
    /* 注入 #UD，由客户机自己的未处理异常路径拆掉这个进程。 */
    KswHvmProcessActionTerminate = 2,
    /*
     * 这一条已经被解除，但本处理器还卡在受限层次里。
     *
     * 调用方把 EPT_POINTER 换回基座并直接恢复，不注入任何东西。没有这条动作，
     * 常驻期间的解除就只对"还没进来的核"有效，而已经在自旋的那个核会一直冻着。
     */
    KswHvmProcessActionResume = 3
} KSW_HVM_PROCESS_ACTION;

/* 执行一次版本化的进程处置操作，自行获取生命周期所有权。 */
NTSTATUS
KswordARKHvmProcessControl(
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* Response
    );

/* 同上，但由已持有运行时锁的调用方使用。 */
NTSTATUS
KswordARKHvmProcessControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_PROCESS_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_PROCESS_RESPONSE* Response
    );

/*
 * 地址空间切进来时选层次。
 *
 * 在 CR3 装载退出里调用，返回 TRUE 表示 *TargetEptp 是这次进入要用的层次。
 * 返回 FALSE 表示没有任何一条处置命中这个地址空间——调用方应当切回基座。
 *
 * 比较只看层次物理页帧：CR3 低位带 PCID 与标志位，连着比会让开了 PCID 的机器
 * 上每次命中都失手，而失手的表现是"功能装上了却什么都没发生"。
 */
BOOLEAN
KswordARKHvmProcessSelectHierarchy(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestCr3,
    _Out_ ULONGLONG* TargetEptp
    );

/*
 * EPT 违规落在某条处置的页上时该做什么。
 *
 * 只在受限层次下才可能命中：非目标地址空间从不在受限层次里运行。命中时记一次
 * 拦截并返回要注入的动作；没命中返回 None，调用方按原有路径继续。
 */
KSW_HVM_PROCESS_ACTION
KswordARKHvmProcessHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access
    );

/* 常驻停止或拆卸时清空整张表并释放它占用的层次。调用方持运行时锁。 */
VOID
KswordARKHvmProcessResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

EXTERN_C_END
