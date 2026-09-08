/*++

Module Name:

    hvm_inject.h

Abstract:

    R-1 层的进程注入：分离视图 + 线程劫持。协议语义见 KswordArkHvmIoctl.h 的
    HVM_INJECT 段，这里只补驱动内部才看得见的部分。

    触发点是**视图自己的第一次执行违规**，不是另装一个拒绝。理由：这一页已经被
    KIND_HOOK 视图占着，再给它装一份执行拒绝就是给同一张叶要两套层次，而视图
    后端一张叶只建一套。复用视图违规既省掉那套冲突，也保证了顺序——RIP 只在
    执行视图已经选好之后才被改，载荷因此一定是从影子页里取到的。

Environment:

    Kernel-mode Driver Framework, PASSIVE_LEVEL control, VMX root dispatch.

--*/

#pragma once

#include "hvm_internal.h"

EXTERN_C_START

/* 执行一次版本化的注入操作，自行获取生命周期所有权。 */
NTSTATUS
KswordARKHvmInjectControl(
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* Response
    );

/* 同上，但由已持有运行时锁的调用方使用。 */
NTSTATUS
KswordARKHvmInjectControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_INJECT_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_INJECT_RESPONSE* Response
    );

/*
 * 视图切换已经完成、即将 RESUME 时问一次：这一页要不要劫持 RIP。
 *
 * 返回 TRUE 表示 *NewRip 是要写进 VMCS 的新 RIP。返回 FALSE 表示这次违规与注入
 * 无关，调用方按原路继续。
 *
 * 只在三个条件同时成立时返回 TRUE：这一页有一条注入、当前 CR3 就是它的目标、
 * 而且它还没被执行过。CR3 这一条不能省——视图装在客户物理页上，是全机器可见的，
 * 别的进程执行同一张物理页时不该被拖去跑载荷。
 */
BOOLEAN
KswordARKHvmInjectHijackRip(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_ ULONGLONG GuestCr3,
    _In_ ULONGLONG GuestRip,
    _Out_ ULONGLONG* NewRip
    );

/* 常驻停止或拆卸时清空整张表并摘掉它占用的视图。调用方持运行时锁。 */
VOID
KswordARKHvmInjectResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

EXTERN_C_END
