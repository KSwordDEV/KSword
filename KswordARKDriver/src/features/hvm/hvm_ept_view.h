/*++

Module Name:

    hvm_ept_view.h

Abstract:

    Declares EPT split views: one guest-physical page backed by two different
    frames depending on whether it is executed or read.

Environment:

    Kernel-mode Driver Framework.

--*/

#pragma once

#include "hvm_ept.h"

EXTERN_C_START

/*
 * Execute one versioned EPT view operation, acquiring lifecycle ownership.
 * Mutating operations are refused while any processor is resident, because the
 * VM-exit path reads the view table without taking this PASSIVE_LEVEL lock.
 */
NTSTATUS
KswordARKHvmEptViewControl(
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* Response
    );

/* Execute one versioned EPT view operation under the runtime lock. */
NTSTATUS
KswordARKHvmEptViewControlLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ const KSWORD_ARK_HVM_VIEW_REQUEST* Request,
    _Out_ KSWORD_ARK_HVM_VIEW_RESPONSE* Response
    );

/* Restore every leaf and release every shadow before EPT pages are freed. */
VOID
KswordARKHvmEptViewResetLocked(
    _Inout_ KSW_HVM_RUNTIME* Runtime
    );

/*
 * Report whether every installed view is served by switching EPT_POINTER
 * rather than by flipping a shared leaf.
 *
 * This is the property the multicore gates actually care about. A leaf flip
 * edits a table every processor walks, so on a shared hierarchy the window is
 * visible machine-wide; a hierarchy switch writes only this processor's VMCS
 * and its index is per-VCPU, so it carries no such window.
 *
 * Asking the views directly, rather than asking whether the switching backend
 * is armed, is deliberate. The two agree today - an armed install that cannot
 * build or verify its hierarchy is refused outright and never falls back to
 * the base (hvm_ept_view.c, the EptpSwitchArmed branch of the add path) - but
 * that is three separate facts holding at once, and the failure mode if any of
 * them ever stops holding is a shared-leaf flip on a multicore box: silent
 * data corruption with no exit, no event and no bugcheck. A predicate over the
 * installed records cannot be broken that way.
 *
 * An empty table returns TRUE: there is nothing that could flip a leaf.
 * Caller must hold the runtime lock.
 */
BOOLEAN
KswordARKHvmEptViewAllSwitchBackedLocked(
    _In_ const KSW_HVM_RUNTIME* Runtime
    );

/*
 * 视图命中时选了哪条服务方式。
 *
 * 存在的理由是两个后端在退出路径上**必须走不同的收尾**：写叶那套要武装
 * monitor-trap 才回得来，切 EPTP 那套一旦武装了就死在下一次 VM entry
 * （在没有 MTF 的机器上 VMWRITE 会成功、VM entry 才失败）。用一个返回值
 * 兼表两种结局，就是把这个区别交给调用方去记得 —— 而忘记的代价是静默
 * 掉出 VMX。
 */
typedef struct _KSW_HVM_EPT_VIEW_SWITCH
{
    /* TRUE 表示由 EPTP 切换服务：调用方**不要**武装 monitor-trap。 */
    BOOLEAN Requested;
    /* 保持后面的 32 位成员自然对齐。 */
    UCHAR Reserved0[3];
    /* 违规叶在视图表里的槽号（0 基），即层次索引减一。 */
    ULONG LeafSlot;
    /* 这张视图的种类，切换规划器据此取主/次权限。 */
    ULONG Kind;
    /* 保持结构在两种架构下都显式初始化。 */
    ULONG Reserved1;
} KSW_HVM_EPT_VIEW_SWITCH;

/*
 * Service one view violation.
 *
 * With the default backend this flips the view's leaf to its secondary value
 * for a single instruction and the caller arms monitor-trap to restore it,
 * which is the same mechanism allow-once rules use.
 *
 * With the EPTP-switching backend **no leaf is written**: the secondary value
 * already lives in that leaf's own hierarchy, so the function only reports
 * which leaf and which kind, and the caller switches the pointer instead.
 */
BOOLEAN
KswordARKHvmEptViewHandleViolation(
    _Inout_ KSW_HVM_RUNTIME* Runtime,
    _In_ ULONGLONG GuestPhysicalAddress,
    _In_ ULONG Access,
    _In_opt_ const KSW_HVM_EPT_LOCAL* Local,
    _Out_ KSW_HVM_EPT_TRANSIENT* Transient,
    _Out_ ULONG* ViewId,
    _Out_ KSW_HVM_EPT_VIEW_SWITCH* Switch
    );

EXTERN_C_END
