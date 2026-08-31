#pragma once

#include <ntddk.h>

#include "bugcheck_internal.h"

#define KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH 640UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT 480UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH 1024UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_FULL_HEIGHT 768UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH 1280UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_HEIGHT 720UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_WIDTH 240UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_HEIGHT 84UL
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_X 16L
#define KSWORD_ARK_BUGCHECK_LAYOUT_LOGO_Y 12L

#define KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_RED 5U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_GREEN 15U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BACKGROUND_BLUE 33U
#define KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_RED 226U
#define KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_GREEN 232U
#define KSWORD_ARK_BUGCHECK_LAYOUT_TEXT_BLUE 244U
#define KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_RED 68U
#define KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_GREEN 126U
#define KSWORD_ARK_BUGCHECK_LAYOUT_ACCENT_BLUE 255U
#define KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_RED 148U
#define KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_GREEN 163U
#define KSWORD_ARK_BUGCHECK_LAYOUT_MUTED_BLUE 190U
#define KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_RED 255U
#define KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_GREEN 92U
#define KSWORD_ARK_BUGCHECK_LAYOUT_WARNING_BLUE 104U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_RED 24U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_GREEN 45U
#define KSWORD_ARK_BUGCHECK_LAYOUT_BORDER_BLUE 75U

typedef enum _KSWORD_ARK_BUGCHECK_LAYOUT_COLOR
{
    KswordArkBugcheckLayoutColorText = 0,
    KswordArkBugcheckLayoutColorAccent,
    KswordArkBugcheckLayoutColorMuted,
    KswordArkBugcheckLayoutColorWarning,
    KswordArkBugcheckLayoutColorCount
} KSWORD_ARK_BUGCHECK_LAYOUT_COLOR;

typedef enum _KSWORD_ARK_BUGCHECK_LAYOUT_FRAME
{
    KswordArkBugcheckLayoutFrameCompactColumn = 0,
    KswordArkBugcheckLayoutFrameCompactWide,
    KswordArkBugcheckLayoutFrameFullTopLeft,
    KswordArkBugcheckLayoutFrameFullTopMiddle,
    KswordArkBugcheckLayoutFrameFullTopRight,
    KswordArkBugcheckLayoutFrameFullMiddleLeft,
    KswordArkBugcheckLayoutFrameFullMiddleMiddle,
    KswordArkBugcheckLayoutFrameFullMiddleRight,
    KswordArkBugcheckLayoutFrameFullBottomLeft,
    KswordArkBugcheckLayoutFrameFullBottomRight,
    KswordArkBugcheckLayoutFrameDetailedTopLeft,
    KswordArkBugcheckLayoutFrameDetailedTopMiddle,
    KswordArkBugcheckLayoutFrameDetailedTopRight,
    KswordArkBugcheckLayoutFrameDetailedMiddleThread,
    KswordArkBugcheckLayoutFrameDetailedMiddleStack,
    KswordArkBugcheckLayoutFrameDetailedMiddleModule,
    KswordArkBugcheckLayoutFrameDetailedMiddleBlackbox,
    KswordArkBugcheckLayoutFrameDetailedBottomCpu,
    KswordArkBugcheckLayoutFrameDetailedBottomDump,
    KswordArkBugcheckLayoutFrameDetailedBottomEvent,
    KswordArkBugcheckLayoutFrameDetailedBottomHelp,
    KswordArkBugcheckLayoutFrameCount
} KSWORD_ARK_BUGCHECK_LAYOUT_FRAME;

typedef NTSTATUS
(*PKSWORD_ARK_BUGCHECK_LAYOUT_DRAW_TEXT)(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_z_ PCSTR Text,
    _In_ ULONG ColorIndex
    );

typedef NTSTATUS
(*PKSWORD_ARK_BUGCHECK_LAYOUT_DRAW_FRAME)(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame
    );

typedef NTSTATUS
(*PKSWORD_ARK_BUGCHECK_LAYOUT_DRAW_VERDICT)(
    _In_opt_ PVOID Context,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ ULONG Classification
    );

typedef struct _KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS
{
    PVOID Context;
    ULONG Width;
    ULONG Height;
    PKSWORD_ARK_BUGCHECK_LAYOUT_DRAW_TEXT DrawText;
    PKSWORD_ARK_BUGCHECK_LAYOUT_DRAW_FRAME DrawFrame;
    PKSWORD_ARK_BUGCHECK_LAYOUT_DRAW_VERDICT DrawVerdict;
} KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS,
  *PKSWORD_ARK_BUGCHECK_LAYOUT_CANVAS;

BOOLEAN
KswordARKBugcheckLayoutIsCompact(
    _In_ ULONG Width,
    _In_ ULONG Height
    );

BOOLEAN
KswordARKBugcheckLayoutIsDetailed(
    _In_ ULONG Width,
    _In_ ULONG Height
    );

LONG
KswordARKBugcheckLayoutOriginX(
    _In_ ULONG Width,
    _In_ ULONG Height
    );

BOOLEAN
KswordARKBugcheckLayoutGetFrameMetrics(
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame,
    _Out_ PULONG Width,
    _Out_ PULONG Height
    );

NTSTATUS
KswordARKBugcheckLayoutDraw(
    _In_ const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    );
