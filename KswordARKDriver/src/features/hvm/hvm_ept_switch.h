/*
 * hvm_ept_switch.h
 *
 * 驱动侧「切 EPTP」分离视图后端的入口。
 *
 * 纯算术、位布局与切换状态机住在 shared/driver/KswordArkHvmEptSwitch.h，由内核
 * 与宿主机单测**共用同一份实现**。本模块只放带副作用的那一半：页池、层次构造、
 * EPTP 台账、释放。状态结构 KSW_HVM_EPTSW 定义在 hvm_internal.h，与其它嵌进
 * 运行时的记录（视图槽、MSR 策略槽）放在一起。
 *
 * 与 hvm_ept_local 的关系是**互斥**，不是叠加。两者都在解决「翻转一张叶不能让
 * 别的处理器看见」，但手段相反：私有层次把叶的**写**限制在一个处理器上，而这套
 * 后端运行期根本不写叶 —— 它换掉本处理器 VMCS 的 EPT_POINTER，指向一套内容
 * 不同、但只有一张叶不同的完整层次。协议层在任何分配之前就拒绝同时请求两者
 * （hvm_runtime.c），所以本模块可以假定 LocalEptArmed 为假。
 *
 * 这套后端存在的**唯一理由**是能力而不是性能：写叶 + monitor-trap 那套需要
 * Monitor Trap Flag，而嵌套 Hyper-V 不向客户机通告它；这套需要 execute-only
 * EPT 叶，那一位在同一台机器上实测可用。
 */

#pragma once

#include "hvm_internal.h"

/* 前进性台账的类型出现在下面的接口里，必须用共享头里**真的**那一个。 */
#include "driver/KswordArkHvmEptSwitch.h"

EXTERN_C_START

/*
 * 保留页池并建立台账，**不构造任何次层次**。
 *
 * 在 PREPARE 里、基座 EPT 建好之后调用，且只在 EptpSwitchArmed 为真时调用。
 * 预算放不下就在**一页都还没分配**的时候拒绝 —— 分配到一半再失败会让一台
 * 碎片化的机器把启动停在无法描述的中间态。
 */
NTSTATUS
KswordARKHvmEptSwitchReserve(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/*
 * 为一张叶构造一套次层次，返回它的层次索引（1..LeafCapacity，0 是基座）。
 *
 * 复制根到叶的四张表，只把路径上的那一项改成指向副本，叶本身写成次值。
 * 副本没有点名的一切仍与基座共享 —— 这既是「只有这一张叶不同」为**构造性**
 * 成立的原因，也是开销只有四页而不是一整套层次的原因。
 *
 * SharedPageTable 是基座里覆盖这张叶的 4KiB 页表（来自 EPT split）。调用方必须
 * 先确保 split 存在：在这里现split 会在持有池的同时向共享账本要页。
 */
NTSTATUS
KswordARKHvmEptSwitchBuildLeaf(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG LeafPhysical,
    _In_ ULONGLONG PrimaryEntry,
    _In_ ULONGLONG SecondaryEntry,
    _In_ const volatile ULONGLONG* SharedPageTable,
    _Out_ ULONG* HierarchyIndex
    );

/*
 * 按处理器走表的方式复核一套已构造的层次。
 *
 * **不是同义反复**：写入走的是 level[3]，复核从 level[0] 出发沿着被改写的父项
 * 往下走。索引算错一级、或父项被重指到错误的页，都会让这次行走落到别处 ——
 * 而那种错误**没有别的症状**：层次在结构上仍然合法，处理器会照用不误。
 */
NTSTATUS
KswordARKHvmEptSwitchVerifyLeaf(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG HierarchyIndex
    );

/*
 * 为一次 EPT 违规算出该切到哪套层次，并把这次切换记进本处理器的前进性台账。
 *
 * 返回 STATUS_SUCCESS 时 *TargetEptp 就是要写进 VMCS 的值。
 * 返回**任何**失败都必须走 fail-closed（与今天「翻转失败」同一条路径），
 * 不要切过去等下一次退出把它解决掉：
 *
 *   STATUS_NOT_SUPPORTED      —— 规划器拒绝。每一条拒绝理由都对应一种
 *                                「不拒绝就会静默死锁或静默泄露」的输入。
 *   STATUS_POSSIBLE_DEADLOCK  —— 这次切换不带来前进。典型来源是一条指令的
 *                                取指与操作数分别需要两张不同视图页的次值，
 *                                两半各自都可服务，于是会无限切换而 RIP 不动。
 *
 * 本函数只做决策与记账，**不碰 VMCS，也不发 INVEPT**。
 */
NTSTATUS
KswordARKHvmEptSwitchPlanViolation(
    _In_ const KSW_HVM_RUNTIME* Runtime,
    _Inout_ KSWORD_ARK_HVM_EPTSW_PROGRESS* Progress,
    _In_ ULONG ActiveIndex,
    _In_ ULONG LeafSlot,
    _In_ ULONG Access,
    _In_ ULONG Kind,
    _In_ ULONGLONG GuestRip,
    _In_ ULONGLONG GuestPhysical,
    _Out_ ULONG* NextIndex,
    _Out_ ULONGLONG* TargetEptp
    );

/* 释放一套次层次的台账。页留在池里（记录拥有固定切片），可重复调用。 */
VOID
KswordARKHvmEptSwitchReleaseLeaf(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONG HierarchyIndex
    );

/*
 * 释放页池并把台账清成确定状态。可重复调用，也容忍 Runtime 为 NULL，
 * 这样每一条失败路径与拆卸路径都不需要额外的守卫。
 */
VOID
KswordARKHvmEptSwitchRelease(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

EXTERN_C_END
