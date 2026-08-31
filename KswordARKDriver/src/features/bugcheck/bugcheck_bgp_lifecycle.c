/*++

Module Name:

    bugcheck_bgp_lifecycle.c

Abstract:

    PASSIVE_LEVEL lifecycle, bitmap parsing, arming, and secondary-dump
    snapshot support for the physical BGP renderer.

--*/

#include "bugcheck_bgp.h"
#include "bugcheck_bgp_internal.h"

VOID
KswordARKBugcheckBgpRecordPreparation(
    _In_ KSWORD_ARK_BGP_PREPARATION_STAGE Stage,
    _In_ NTSTATUS Status
    )
{
    // Publish the status first so a reader that observes the new stage also
    // observes the status belonging to that operation.
    InterlockedExchange(&g_KswordArkBgp.PreparationStatus, (LONG)Status);
    KeMemoryBarrier();
    InterlockedExchange(&g_KswordArkBgp.PreparationStage, (LONG)Stage);
}

NTSTATUS
KswordARKBugcheckBgpInitialize(
    VOID
    )
{
    KSWORD_ARK_BGP_SCREEN_INFO screen;
    NTSTATUS status;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&g_KswordArkBgp, sizeof(g_KswordArkBgp));
    InterlockedExchange(
        &g_KswordArkBgp.State,
        KswordArkBgpStateUninitialized);
    KswordARKBugcheckBgpRecordPreparation(
        KswordArkBgpPreparationResolveFunctions,
        STATUS_PENDING);
    InterlockedExchange(&g_KswordArkBgp.ClearStatus, STATUS_PENDING);
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, STATUS_PENDING);

    status = KswordARKBugcheckBgpResolveFunctions();
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
    KswordARKBugcheckBgpRecordPreparation(
        KswordArkBgpPreparationResolveFunctions,
        status);
    if (NT_SUCCESS(status)) {
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationReadScreen,
            STATUS_PENDING);
        status = KswordARKBugcheckBgpReadScreen(&screen);
        InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)status);
        KswordARKBugcheckBgpRecordPreparation(
            KswordArkBgpPreparationReadScreen,
            status);
        if (NT_SUCCESS(status)) {
            g_KswordArkBgp.Screen = screen;
        }
    }

    if (!NT_SUCCESS(status)) {
        InterlockedExchange(
            &g_KswordArkBgp.State,
            KswordArkBgpStateQueryOnly);
        return status;
    }

    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateReady);
    KswordARKBugcheckBgpRecordPreparation(
        KswordArkBgpPreparationBackendReady,
        STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckBgpShutdown(
    VOID
    )
{
    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateUnloading);
    if (InterlockedExchange(&g_KswordArkBgp.LockHeld, 0) != 0 &&
        g_KswordArkBgp.Release != NULL) {
        KswordARKBugcheckBgpInvokeRelease();
    }
    KeMemoryBarrier();
    InterlockedExchange(&g_KswordArkBgp.ResolvedSnapshotReady, 0);
    g_KswordArkBgp.Clear = NULL;
    g_KswordArkBgp.Draw = NULL;
    g_KswordArkBgp.Acquire = NULL;
    g_KswordArkBgp.Release = NULL;
    g_KswordArkBgp.GetResolution = NULL;
    g_KswordArkBgp.GetBpp = NULL;
    g_KswordArkBgp.ParseBitmap = NULL;
    g_KswordArkBgp.DestroyRectangle = NULL;
    g_KswordArkBgp.AcquireOwnership = NULL;
    g_KswordArkBgp.FeatureMask = 0UL;
    g_KswordArkBgp.RequiredWidth = 0;
    g_KswordArkBgp.RequiredHeight = 0;
}

NTSTATUS
KswordARKBugcheckBgpGetScreenInfo(
    _Out_ PKSWORD_ARK_BGP_SCREEN_INFO Screen
    )
{
    if (Screen == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.State,
            0,
            0) != KswordArkBgpStateReady) {
        RtlZeroMemory(Screen, sizeof(*Screen));
        return STATUS_DEVICE_NOT_READY;
    }

    *Screen = g_KswordArkBgp.Screen;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpParseBitmap(
    _In_reads_bytes_(BitmapLength) const VOID* Bitmap,
    _In_ ULONG BitmapLength,
    _Out_ PVOID* Rectangle
    )
{
    PVOID parsedRectangle;
    LONG state;
    NTSTATUS abortStatus;
    NTSTATUS status;

    if (Rectangle == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *Rectangle = NULL;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    abortStatus = KswordARKBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        return abortStatus;
    }
    state = InterlockedCompareExchange(&g_KswordArkBgp.State, 0, 0);
    if ((state != KswordArkBgpStateReady &&
         state != KswordArkBgpStateArmed) ||
        (state == KswordArkBgpStateArmed &&
         InterlockedCompareExchange(
             &g_KswordArkBgp.ResourceUpdateActive,
             0,
             0) == 0) ||
        InterlockedCompareExchange(
            &g_KswordArkBgp.ResolvedSnapshotReady,
            0,
            0) == 0 ||
        g_KswordArkBgp.ParseBitmap == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    status = KswordARKBugcheckBgpValidateBitmap(Bitmap, BitmapLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    parsedRectangle = NULL;
    status = KswordARKBugcheckBgpInvokeParseBitmap(
        Bitmap,
        &parsedRectangle);
    if (!NT_SUCCESS(status) || parsedRectangle == NULL) {
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    // 私有解析器返回后再检查一次预算；已创建的矩形必须在传播取消前立即销毁。
    abortStatus = KswordARKBugcheckControlCheckAbort();
    if (!NT_SUCCESS(abortStatus)) {
        (VOID)KswordARKBugcheckBgpInvokeDestroyRectangle(parsedRectangle);
        return abortStatus;
    }

    *Rectangle = parsedRectangle;
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKBugcheckBgpBeginResourceUpdate(
    VOID
    )
{
    LONG state;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    state = InterlockedCompareExchange(&g_KswordArkBgp.State, 0, 0);
    if (state != KswordArkBgpStateReady &&
        state != KswordArkBgpStateArmed) {
        return STATUS_DEVICE_NOT_READY;
    }
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.ResourceUpdateActive,
            1,
            0) != 0) {
        return STATUS_DEVICE_BUSY;
    }
    KeMemoryBarrier();
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.DrawStarted,
            0,
            0) != 0) {
        InterlockedExchange(&g_KswordArkBgp.ResourceUpdateActive, 0);
        return STATUS_DEVICE_BUSY;
    }
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckBgpEndResourceUpdate(
    VOID
    )
{
    KeMemoryBarrier();
    InterlockedExchange(&g_KswordArkBgp.ResourceUpdateActive, 0);
}

VOID
KswordARKBugcheckBgpDestroyRectangle(
    _In_opt_ PVOID Rectangle
    )
{
    if (Rectangle != NULL &&
        InterlockedCompareExchange(
            &g_KswordArkBgp.ResolvedSnapshotReady,
            0,
            0) != 0 &&
        g_KswordArkBgp.DestroyRectangle != NULL) {
        (VOID)KswordARKBugcheckBgpInvokeDestroyRectangle(Rectangle);
    }
}

NTSTATUS
KswordARKBugcheckBgpArm(
    _In_ ULONG RequiredWidth,
    _In_ ULONG RequiredHeight
    )
{
    if (InterlockedCompareExchange(
            &g_KswordArkBgp.ResolvedSnapshotReady,
            0,
            0) == 0 ||
        InterlockedCompareExchange(
            &g_KswordArkBgp.State,
            0,
            0) != KswordArkBgpStateReady ||
        RequiredWidth == 0 ||
        RequiredHeight == 0) {
        return STATUS_NOT_SUPPORTED;
    }

    // Defer the size check when BGP deliberately hides the screen mode until
    // InbvAcquireDisplayOwnership runs inside the bugcheck callback.
    if (g_KswordArkBgp.Screen.BitsPerPixel !=
            KSWORD_ARK_BGP_UNOWNED_BPP &&
        (RequiredWidth > g_KswordArkBgp.Screen.Width ||
         RequiredHeight > g_KswordArkBgp.Screen.Height)) {
        return STATUS_NOT_SUPPORTED;
    }

    g_KswordArkBgp.RequiredWidth = RequiredWidth;
    g_KswordArkBgp.RequiredHeight = RequiredHeight;
    InterlockedExchange(&g_KswordArkBgp.DrawStarted, 0);
    InterlockedExchange(&g_KswordArkBgp.ResourceUpdateActive, 0);
    InterlockedExchange(&g_KswordArkBgp.DrawStageStarted, 0);
    InterlockedExchange(&g_KswordArkBgp.Stage, KswordArkBgpStageIdle);
    InterlockedExchange(&g_KswordArkBgp.ClearStatus, STATUS_PENDING);
    InterlockedExchange(&g_KswordArkBgp.DrawStatus, STATUS_PENDING);
    InterlockedExchange(&g_KswordArkBgp.TimelineCount, 0);
    RtlZeroMemory(g_KswordArkBgp.Timeline, sizeof(g_KswordArkBgp.Timeline));
    InterlockedExchange(&g_KswordArkBgp.LastStatus, STATUS_SUCCESS);
    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateArmed);
    return STATUS_SUCCESS;
}

VOID
KswordARKBugcheckBgpRejectPreparation(
    _In_ NTSTATUS Status
    )
{
    InterlockedExchange(&g_KswordArkBgp.LastStatus, (LONG)Status);
    InterlockedExchange(&g_KswordArkBgp.PreparationStatus, (LONG)Status);
    InterlockedExchange(&g_KswordArkBgp.State, KswordArkBgpStateRejected);
    KswordARKBugcheckBgpRecordStage(
        (LONG)(KswordArkBgpStageRejected | 3UL),
        Status);
}
VOID
KswordARKBugcheckBgpSnapshot(
    _Out_ PKSWORD_ARK_BGP_DUMP_STATE Snapshot
    )
{
    LONG timelineCount;
    ULONG timelineIndex;

    if (Snapshot == NULL) {
        return;
    }

    RtlZeroMemory(Snapshot, sizeof(*Snapshot));
    Snapshot->Version = 2UL;
    Snapshot->Size = sizeof(*Snapshot);
    Snapshot->State = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.State,
        0,
        0);
    Snapshot->PreparationStage = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.PreparationStage,
        0,
        0);
    Snapshot->PreparationStatus = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.PreparationStatus,
        0,
        0);
    Snapshot->Stage = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.Stage,
        0,
        0);
    Snapshot->LastStatus = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.LastStatus,
        0,
        0);
    Snapshot->ClearStatus = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.ClearStatus,
        0,
        0);
    Snapshot->DrawStatus = (ULONG)InterlockedCompareExchange(
        &g_KswordArkBgp.DrawStatus,
        0,
        0);
    Snapshot->FeatureMask = g_KswordArkBgp.FeatureMask;
    Snapshot->ScreenWidth = g_KswordArkBgp.Screen.Width;
    Snapshot->ScreenHeight = g_KswordArkBgp.Screen.Height;
    Snapshot->ScreenBpp = g_KswordArkBgp.Screen.BitsPerPixel;
    Snapshot->RequiredWidth = g_KswordArkBgp.RequiredWidth;
    Snapshot->RequiredHeight = g_KswordArkBgp.RequiredHeight;
    Snapshot->DrawCount = (ULONG64)InterlockedCompareExchange64(
        &g_KswordArkBgp.DrawCount,
        0,
        0);
    RtlCopyMemory(
        Snapshot->SignatureFamily,
        g_KswordArkBgp.SignatureFamily,
        sizeof(Snapshot->SignatureFamily));

    timelineCount = InterlockedCompareExchange(
        &g_KswordArkBgp.TimelineCount,
        0,
        0);
    if (timelineCount < 0) {
        timelineCount = 0;
    }
    Snapshot->TimelineCount = min(
        (ULONG)timelineCount,
        (ULONG)RTL_NUMBER_OF(Snapshot->Timeline));
    for (timelineIndex = 0;
         timelineIndex < Snapshot->TimelineCount;
         ++timelineIndex) {
        Snapshot->Timeline[timelineIndex].Stage =
            (ULONG)InterlockedCompareExchange(
                &g_KswordArkBgp.Timeline[timelineIndex].Stage,
                0,
                0);
        Snapshot->Timeline[timelineIndex].Status =
            (ULONG)InterlockedCompareExchange(
                &g_KswordArkBgp.Timeline[timelineIndex].Status,
                0,
                0);
    }
}
