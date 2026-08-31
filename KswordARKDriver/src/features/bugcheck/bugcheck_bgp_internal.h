#pragma once

#include "bugcheck_bgp.h"

typedef NTSTATUS
(*PKSWORD_ARK_BGP_CLEAR_SCREEN)(
    _In_ ULONG ArgbColor
    );

typedef NTSTATUS
(*PKSWORD_ARK_BGP_DRAW_RECTANGLE)(
    _In_ PVOID Rectangle,
    _In_ const VOID* Position
    );

typedef VOID
(*PKSWORD_ARK_BGP_LOCK)(
    VOID
    );

typedef PVOID
(*PKSWORD_ARK_BGP_GET_RESOLUTION)(
    _Out_ PVOID Resolution
    );

typedef ULONG
(*PKSWORD_ARK_BGP_GET_BPP)(
    VOID
    );

typedef NTSTATUS
(*PKSWORD_ARK_BGP_PARSE_BITMAP)(
    _In_ const VOID* Bitmap,
    _Out_ PVOID* Rectangle
    );

typedef NTSTATUS
(*PKSWORD_ARK_BGP_DESTROY_RECTANGLE)(
    _In_opt_ PVOID Rectangle
    );

typedef VOID
(*PKSWORD_ARK_INBV_ACQUIRE_DISPLAY_OWNERSHIP)(
    VOID
    );

typedef struct _KSWORD_ARK_BGP_POSITION
{
    LONG X;
    LONG Y;
} KSWORD_ARK_BGP_POSITION, *PKSWORD_ARK_BGP_POSITION;

#pragma pack(push, 1)
typedef struct _KSWORD_ARK_BGP_BITMAP_FILE_HEADER
{
    USHORT Type;
    ULONG Size;
    USHORT Reserved1;
    USHORT Reserved2;
    ULONG PixelOffset;
} KSWORD_ARK_BGP_BITMAP_FILE_HEADER, *PKSWORD_ARK_BGP_BITMAP_FILE_HEADER;

typedef struct _KSWORD_ARK_BGP_BITMAP_INFO_HEADER
{
    ULONG Size;
    LONG Width;
    LONG Height;
    USHORT Planes;
    USHORT BitsPerPixel;
    ULONG Compression;
    ULONG ImageSize;
    LONG XPelsPerMeter;
    LONG YPelsPerMeter;
    ULONG ColorsUsed;
    ULONG ColorsImportant;
} KSWORD_ARK_BGP_BITMAP_INFO_HEADER, *PKSWORD_ARK_BGP_BITMAP_INFO_HEADER;
#pragma pack(pop)

typedef struct _KSWORD_ARK_BGP_CONTEXT
{
    PKSWORD_ARK_BGP_CLEAR_SCREEN Clear;
    PKSWORD_ARK_BGP_DRAW_RECTANGLE Draw;
    PKSWORD_ARK_BGP_LOCK Acquire;
    PKSWORD_ARK_BGP_LOCK Release;
    PKSWORD_ARK_BGP_GET_RESOLUTION GetResolution;
    PKSWORD_ARK_BGP_GET_BPP GetBpp;
    PKSWORD_ARK_BGP_PARSE_BITMAP ParseBitmap;
    PKSWORD_ARK_BGP_DESTROY_RECTANGLE DestroyRectangle;
    PKSWORD_ARK_INBV_ACQUIRE_DISPLAY_OWNERSHIP AcquireOwnership;
    volatile LONG ResolvedSnapshotReady;
    ULONG FeatureMask;
    ULONG SignatureFamily[KSWORD_ARK_BGP_SIGNATURE_COUNT];
    KSWORD_ARK_BGP_SCREEN_INFO Screen;
    ULONG RequiredWidth;
    ULONG RequiredHeight;
    volatile LONG State;
    volatile LONG PreparationStage;
    volatile LONG PreparationStatus;
    ULONG ProbeWidth;
    ULONG ProbeHeight;
    ULONG ProbeBpp;
    volatile LONG Stage;
    volatile LONG DrawStarted;
    volatile LONG ResourceUpdateActive;
    volatile LONG LockHeld;
    volatile LONG DrawStageStarted;
    volatile LONG64 DrawCount;
    volatile LONG LastStatus;
    volatile LONG ClearStatus;
    volatile LONG DrawStatus;
    volatile LONG TimelineCount;
    struct
    {
        volatile LONG Stage;
        volatile LONG Status;
    } Timeline[KSWORD_ARK_BGP_TIMELINE_COUNT];
} KSWORD_ARK_BGP_CONTEXT, *PKSWORD_ARK_BGP_CONTEXT;

extern KSWORD_ARK_BGP_CONTEXT g_KswordArkBgp;

// Resolver and rectangle preparation use the controller-owned deadline and unload cancellation.
NTSTATUS
KswordARKBugcheckControlCheckAbort(
    VOID
    );

VOID
KswordARKBugcheckBgpRecordStage(
    _In_ LONG Stage,
    _In_ NTSTATUS Status
    );

NTSTATUS
KswordARKBugcheckBgpResolveFunctions(
    VOID
    );

NTSTATUS
KswordARKBugcheckBgpReadScreen(
    _Out_ PKSWORD_ARK_BGP_SCREEN_INFO Screen
    );

// Invoke the validated private BGP parser without applying CFG to the private
// kernel target itself.  The resolver remains responsible for validating the
// target image, section, signature family, and uniqueness before publication.
NTSTATUS
KswordARKBugcheckBgpInvokeParseBitmap(
    _In_ const VOID* Bitmap,
    _Out_ PVOID* Rectangle
    );

// Invoke the validated private BGP rectangle destructor through the same
// narrowly scoped no-CFG boundary used by the remaining private BGP calls.
NTSTATUS
KswordARKBugcheckBgpInvokeDestroyRectangle(
    _In_opt_ PVOID Rectangle
    );

// Invoke the validated private BGP lock release routine without extending the
// CFG exception to the lifecycle caller or any unrelated driver code.
VOID
KswordARKBugcheckBgpInvokeRelease(
    VOID
    );

NTSTATUS
KswordARKBugcheckBgpValidateBitmap(
    _In_reads_bytes_(BitmapLength) const VOID* Bitmap,
    _In_ ULONG BitmapLength
    );
