/*++

Module Name:

    bugcheck_layout.c

Abstract:

    Shared crash-safe information layout for the BGP and VMware framebuffer
    bugcheck renderers. The implementation formats only captured data and uses
    caller-supplied drawing callbacks without allocation or pageable services.

--*/

#include "bugcheck_layout.h"
#include "bugcheck_decode.h"

#include <ntstrsafe.h>
#include <stdarg.h>

typedef struct _KSWORD_ARK_BUGCHECK_LAYOUT_FRAME_METRICS
{
    ULONG Width;
    ULONG Height;
} KSWORD_ARK_BUGCHECK_LAYOUT_FRAME_METRICS;

typedef struct _KSWORD_ARK_BUGCHECK_LAYOUT_WRITER
{
    const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas;
    LONG OriginX;
    NTSTATUS Status;
    CHAR Line[KSWORD_ARK_BUGCHECK_PANEL_LINE_CHARS];
} KSWORD_ARK_BUGCHECK_LAYOUT_WRITER;

static const KSWORD_ARK_BUGCHECK_LAYOUT_FRAME_METRICS
    g_KswordArkBugcheckLayoutFrames[KswordArkBugcheckLayoutFrameCount] = {
        { 296UL, 112UL },
        { 608UL, 126UL },
        { 344UL, 184UL },
        { 312UL, 184UL },
        { 328UL, 184UL },
        { 344UL, 174UL },
        { 312UL, 174UL },
        { 328UL, 174UL },
        { 484UL, 176UL },
        { 500UL, 176UL },
        { 470UL, 207UL },
        { 350UL, 207UL },
        { 416UL, 207UL },
        { 314UL, 162UL },
        { 328UL, 162UL },
        { 278UL, 162UL },
        { 316UL, 162UL },
        { 480UL, 205UL },
        { 348UL, 205UL },
        { 412UL, 98UL },
        { 412UL, 103UL }
    };

C_ASSERT(
    RTL_NUMBER_OF(g_KswordArkBugcheckLayoutFrames) ==
    KswordArkBugcheckLayoutFrameCount);

BOOLEAN
KswordARKBugcheckLayoutIsDetailed(
    _In_ ULONG Width,
    _In_ ULONG Height
    )
{
    // Keep one predictable two-column information hierarchy on physical 2K
    // displays as well as virtual crash modes.  The legacy dense renderer
    // remains compiled for reference but is no longer selected.
    UNREFERENCED_PARAMETER(Width);
    UNREFERENCED_PARAMETER(Height);
    return FALSE;
}

BOOLEAN
KswordARKBugcheckLayoutIsCompact(
    _In_ ULONG Width,
    _In_ ULONG Height
    )
{
    // The 640x480 crash fallback needs its dedicated two-column layout.
    return !KswordARKBugcheckLayoutIsDetailed(Width, Height) &&
        (Width < KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH ||
         Height < KSWORD_ARK_BUGCHECK_LAYOUT_FULL_HEIGHT);
}

LONG
KswordARKBugcheckLayoutOriginX(
    _In_ ULONG Width,
    _In_ ULONG Height
    )
{
    ULONG canvasWidth;

    // Center whichever fixed canvas the current crash mode can safely fit.
    if (KswordARKBugcheckLayoutIsDetailed(Width, Height)) {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_DETAILED_WIDTH;
    } else if (KswordARKBugcheckLayoutIsCompact(Width, Height)) {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH;
    } else {
        canvasWidth = KSWORD_ARK_BUGCHECK_LAYOUT_FULL_WIDTH;
    }
    if (Width > canvasWidth) {
        return (LONG)((Width - canvasWidth) / 2UL);
    }
    return 0L;
}

BOOLEAN
KswordARKBugcheckLayoutGetFrameMetrics(
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame,
    _Out_ PULONG Width,
    _Out_ PULONG Height
    )
{
    if (Width == NULL || Height == NULL ||
        Frame < KswordArkBugcheckLayoutFrameCompactColumn ||
        Frame >= KswordArkBugcheckLayoutFrameCount) {
        return FALSE;
    }

    *Width = g_KswordArkBugcheckLayoutFrames[Frame].Width;
    *Height = g_KswordArkBugcheckLayoutFrames[Frame].Height;
    return TRUE;
}

static VOID
KswordARKBugcheckLayoutClipLine(
    _Inout_updates_z_(Capacity) PCHAR Text,
    _In_ ULONG Capacity,
    _In_ ULONG MaximumCharacters
    )
{
    SIZE_T length;

    if (Text == NULL || Capacity == 0 || MaximumCharacters == 0) {
        return;
    }
    if (MaximumCharacters >= Capacity) {
        MaximumCharacters = Capacity - 1UL;
    }

    length = 0;
    while (length + 1UL < Capacity && Text[length] != '\0') {
        ++length;
    }
    if (length <= MaximumCharacters) {
        return;
    }

    if (MaximumCharacters > 3UL) {
        Text[MaximumCharacters - 3UL] = '.';
        Text[MaximumCharacters - 2UL] = '.';
        Text[MaximumCharacters - 1UL] = '.';
    }
    Text[MaximumCharacters] = '\0';
}

static VOID
KswordARKBugcheckLayoutWriteFormatted(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ ULONG ColorIndex,
    _In_ ULONG MaximumCharacters,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    va_list arguments;

    if (Writer == NULL || !NT_SUCCESS(Writer->Status)) {
        return;
    }

    va_start(arguments, Format);
    Writer->Status = RtlStringCbVPrintfA(
        Writer->Line,
        sizeof(Writer->Line),
        Format,
        arguments);
    va_end(arguments);
    if (!NT_SUCCESS(Writer->Status)) {
        return;
    }

    KswordARKBugcheckLayoutClipLine(
        Writer->Line,
        (ULONG)RTL_NUMBER_OF(Writer->Line),
        MaximumCharacters);
    Writer->Status = Writer->Canvas->DrawText(
        Writer->Canvas->Context,
        Writer->OriginX + X,
        Y,
        Writer->Line,
        ColorIndex);
}

static VOID
KswordARKBugcheckLayoutWriteFrame(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ KSWORD_ARK_BUGCHECK_LAYOUT_FRAME Frame
    )
{
    if (Writer == NULL || !NT_SUCCESS(Writer->Status)) {
        return;
    }

    Writer->Status = Writer->Canvas->DrawFrame(
        Writer->Canvas->Context,
        Writer->OriginX + X,
        Y,
        Frame);
}

static BOOLEAN
KswordARKBugcheckLayoutWriteVerdict(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ ULONG Classification
    )
{
    NTSTATUS status;

    if (Writer == NULL || !NT_SUCCESS(Writer->Status) ||
        Writer->Canvas->DrawVerdict == NULL) {
        return FALSE;
    }
    status = Writer->Canvas->DrawVerdict(
        Writer->Canvas->Context,
        Writer->OriginX + X,
        Y,
        Classification);
    if (NT_SUCCESS(status)) {
        return TRUE;
    }
    if (status != STATUS_NOT_FOUND &&
        status != STATUS_DEVICE_NOT_READY &&
        status != STATUS_DEVICE_BUSY) {
        Writer->Status = status;
    }
    return FALSE;
}

static PCSTR
KswordARKBugcheckLayoutModuleText(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    // Resolver notes are not evidence and therefore stay off the screen.
    if (Diagnostics->CandidateModule[0] == '\0' ||
        Diagnostics->CandidateModule[0] == '(') {
        return NULL;
    }
    // A cached basename is safe to display as the primary module evidence.
    return Diagnostics->CandidateModule;
}

static BOOLEAN
KswordARKBugcheckLayoutHasProcess(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    return Diagnostics->ProcessObject != 0 &&
        Diagnostics->ProcessName[0] != '\0';
}

static ULONG
KswordARKBugcheckLayoutTextLength(
    _In_opt_z_ PCSTR Text,
    _In_ ULONG MaximumLength
    )
{
    ULONG length;

    // Bound every scan because module names live in a fixed crash snapshot.
    length = 0;
    while (Text != NULL && length < MaximumLength && Text[length] != '\0') {
        ++length;
    }
    // The caller uses the bounded result only to choose a fixed layout branch.
    return length;
}

static PCSTR
KswordARKBugcheckLayoutCriticalObjectText(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics
    )
{
    if (Diagnostics->Parameter2 == 0) {
        return "PROCESS";
    }
    if (Diagnostics->Parameter2 == 1) {
        return "THREAD";
    }
    return "UNKNOWN";
}

static BOOLEAN
KswordARKBugcheckLayoutTextStartsWith(
    _In_opt_z_ PCSTR Text,
    _In_z_ PCSTR Prefix
    )
{
    // Null strings cannot satisfy a semantic prefix check.
    if (Text == NULL || Prefix == NULL) {
        return FALSE;
    }
    // Compare only the fixed prefix so the crash path needs no CRT helper.
    while (*Prefix != '\0') {
        if (*Text != *Prefix) {
            return FALSE;
        }
        ++Text;
        ++Prefix;
    }
    // Every prefix character matched the candidate text.
    return TRUE;
}

static BOOLEAN
KswordARKBugcheckLayoutShouldShowParameter(
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG ParameterIndex,
    _In_ ULONG_PTR Value
    )
{
    PCSTR role;

    // Decode the documented role without dereferencing the captured value.
    role = KswordARKBugcheckDecodeParameterRole(Diagnostics, ParameterIndex);
    // Reserved fields never help the first-look diagnosis.
    if (KswordARKBugcheckLayoutTextStartsWith(role, "RESERVED")) {
        return FALSE;
    }
    // Any nonzero documented or generic value remains available as evidence.
    if (Value != 0) {
        return TRUE;
    }
    // A semantic zero can encode PROCESS, READ, IRQL 0, or another real state.
    return !KswordARKBugcheckLayoutTextStartsWith(role, "PARAMETER");
}

static VOID
KswordARKBugcheckLayoutWriteTechnicalParameter(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ LONG X,
    _In_ LONG Y,
    _In_ ULONG MaximumCharacters,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG ParameterIndex,
    _In_ ULONG_PTR Value
    )
{
    KswordARKBugcheckLayoutWriteFormatted(
        Writer,
        X,
        Y,
        KswordArkBugcheckLayoutColorText,
        MaximumCharacters,
        "P%lu %s  0x%p",
        ParameterIndex,
        KswordARKBugcheckDecodeParameterRole(Diagnostics, ParameterIndex),
        (PVOID)Value);
}

static ULONG
KswordARKBugcheckLayoutWriteTechnicalParameters(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ LONG X,
    _In_ LONG StartY,
    _In_ ULONG MaximumCharacters,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG MaximumLines
    )
{
    ULONG_PTR values[4];
    ULONG parameterIndex;
    ULONG lineCount;

    // Snapshot the four fixed bugcheck values into bounded stack storage.
    values[0] = Diagnostics->Parameter1;
    values[1] = Diagnostics->Parameter2;
    values[2] = Diagnostics->Parameter3;
    values[3] = Diagnostics->Parameter4;
    // Emit only semantic or nonzero values and never exceed the panel budget.
    lineCount = 0;
    for (parameterIndex = 1;
         parameterIndex <= RTL_NUMBER_OF(values) && lineCount < MaximumLines;
         ++parameterIndex) {
        if (!KswordARKBugcheckLayoutShouldShowParameter(
                Diagnostics,
                parameterIndex,
                values[parameterIndex - 1UL])) {
            continue;
        }
        KswordARKBugcheckLayoutWriteTechnicalParameter(
            Writer,
            X,
            StartY + (LONG)(lineCount * 22UL),
            MaximumCharacters,
            Diagnostics,
            parameterIndex,
            values[parameterIndex - 1UL]);
        ++lineCount;
    }
    // The caller uses the count to place one optional context line.
    return lineCount;
}

static PCSTR
KswordARKBugcheckLayoutHumanCauseText(
    _In_ ULONG BugCheckCode
    )
{
    switch (BugCheckCode) {
    case 0x0000000A:
        return "KERNEL CODE ACCESSED INVALID MEMORY AT HIGH IRQL.";
    case 0x000000D1:
        return "A DRIVER ACCESSED INVALID MEMORY AT HIGH IRQL.";
    case 0x0000001E:
    case 0x0000003B:
    case 0x0000007E:
        return "A KERNEL EXCEPTION WAS NOT HANDLED.";
    case 0x00000050:
        return "KERNEL CODE ACCESSED AN INVALID MEMORY PAGE.";
    case 0x000000BE:
        return "KERNEL CODE TRIED TO WRITE PROTECTED MEMORY.";
    case 0x0000009F:
        return "A DRIVER DID NOT COMPLETE A POWER TRANSITION.";
    case 0x000000EF:
        return "A WINDOWS CRITICAL PROCESS TERMINATED.";
    case 0x00000116:
    case 0x00000117:
        return "THE DISPLAY DRIVER OR GPU STOPPED RESPONDING.";
    case 0x00000124:
        return "HARDWARE REPORTED AN UNRECOVERABLE ERROR.";
    case 0x00000133:
        return "A DPC OR INTERRUPT HANDLER TOOK TOO LONG.";
    default:
        return "WINDOWS STOPPED TO PROTECT SYSTEM DATA.";
    }
}

static PCSTR
KswordARKBugcheckLayoutFallbackVerdictText(
    _In_ ULONG Classification
    )
{
    switch (Classification) {
    case KSWORD_ARK_BUGCHECK_MODULE_OURS:
        return "KSWORDARK MAY BE INVOLVED.";
    case KSWORD_ARK_BUGCHECK_MODULE_MICROSOFT:
        return "MICROSOFT CODE IS INVOLVED.";
    case KSWORD_ARK_BUGCHECK_MODULE_THIRD_PARTY:
        return "THIRD-PARTY CODE IS INVOLVED.";
    default:
        return "NO CULPRIT IS CONFIRMED.";
    }
}

static VOID
KswordARKBugcheckLayoutWriteHeader(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ BOOLEAN Compact
    )
{
    // The neutral product label establishes context without competing for focus.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 280L, 18L, KswordArkBugcheckLayoutColorMuted,
        Compact ? 40UL : 42UL,
        "KSWORD ARK CRASH DIAGNOSTICS");
    // The symbolic bugcheck name is the first high-contrast diagnostic fact.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 280L, 42L, KswordArkBugcheckLayoutColorAccent,
        Compact ? 40UL : 42UL,
        "%s", KswordARKBugcheckName(Diagnostics->BugCheckCode));
    // The numeric stop code is the page's only red signal and visual anchor.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 280L, 66L, KswordArkBugcheckLayoutColorWarning,
        Compact ? 40UL : 42UL,
        "0x%08lX", Diagnostics->BugCheckCode);

    // Prefer the pre-rendered Windows UI-font verdict whenever it is ready.
    if (!KswordARKBugcheckLayoutWriteVerdict(
            Writer,
            Compact ? 304L : 688L,
            Compact ? 94L : 12L,
            Diagnostics->CandidateClass)) {
        LONG verdictX;
        LONG verdictY;
        ULONG maximumCharacters;

        verdictX = Compact ? 304L : 688L;
        verdictY = Compact ? 94L : 20L;
        maximumCharacters = Compact ? 35UL : 34UL;
        // The crash-safe fallback stays white like the normal verdict card.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer,
            verdictX,
            verdictY,
            KswordArkBugcheckLayoutColorText,
            maximumCharacters,
            "%s",
            KswordARKBugcheckLayoutFallbackVerdictText(
                Diagnostics->CandidateClass));
        // One concise line explains where final attribution comes from.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer,
            verdictX,
            verdictY + 20L,
            KswordArkBugcheckLayoutColorText,
            maximumCharacters,
            "FINAL ATTRIBUTION NEEDS THE DUMP.");
    }
}

static VOID
KswordARKBugcheckLayoutDrawCompact(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    PCSTR moduleText;
    ULONG moduleLength;
    ULONG_PTR values[4];
    ULONG parameterIndex;

    // Compact rendering intentionally excludes callback and cache telemetry.
    UNREFERENCED_PARAMETER(CallbackMask);
    UNREFERENCED_PARAMETER(ModuleCount);
    // Resolve the optional module basename once for the evidence branch.
    moduleText = KswordARKBugcheckLayoutModuleText(Diagnostics);
    // Measure only the fixed snapshot capacity to select one- or two-line text.
    moduleLength = KswordARKBugcheckLayoutTextLength(
        moduleText,
        KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL);
    // Keep the raw values bounded on the stack for one optional fallback fact.
    values[0] = Diagnostics->Parameter1;
    values[1] = Diagnostics->Parameter2;
    values[2] = Diagnostics->Parameter3;
    values[3] = Diagnostics->Parameter4;
    // Preserve the two-panel compact geometry used by 640x480 crash modes.
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 292L, KswordArkBugcheckLayoutFrameCompactColumn);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 328L, 292L, KswordArkBugcheckLayoutFrameCompactColumn);

    // The left panel contains only the strongest evidence available now.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 302L, KswordArkBugcheckLayoutColorMuted, 29UL,
        "PRIMARY EVIDENCE");
    if (moduleText != NULL &&
        Diagnostics->CandidateClass != KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN) {
        // A resolved module is the highest-value compact attribution result.
        if (moduleLength > 32UL) {
            // A long basename receives two complete lines instead of ellipsis.
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 24L, 320L, KswordArkBugcheckLayoutColorAccent, 32UL,
                "%.*s", 32, moduleText);
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 24L, 338L, KswordArkBugcheckLayoutColorAccent, 32UL,
                "%s", moduleText + 32UL);
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 28L, 356L, KswordArkBugcheckLayoutColorText, 29UL,
                "%s / %s",
                KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass),
                KswordARKBugcheckConfidenceText(
                    Diagnostics->CandidateConfidence));
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 28L, 374L, KswordArkBugcheckLayoutColorMuted, 29UL,
                "P%lu IP  0x%p",
                Diagnostics->CandidateParameter,
                (PVOID)Diagnostics->FaultAddress);
        } else {
            // Short basenames leave room for both offset and code address.
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 24L, 320L, KswordArkBugcheckLayoutColorAccent, 32UL,
                "%s", moduleText);
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 28L, 338L, KswordArkBugcheckLayoutColorText, 29UL,
                "%s / %s",
                KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass),
                KswordARKBugcheckConfidenceText(
                    Diagnostics->CandidateConfidence));
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 28L, 356L, KswordArkBugcheckLayoutColorText, 29UL,
                "OFFSET  0x%p", (PVOID)Diagnostics->CandidateModuleOffset);
            if (Diagnostics->FaultAddress != 0) {
                // The documented code address remains visible without clutter.
                KswordARKBugcheckLayoutWriteFormatted(
                    Writer, 28L, 374L, KswordArkBugcheckLayoutColorMuted, 29UL,
                    "CODE IP  0x%p", (PVOID)Diagnostics->FaultAddress);
            }
        }
    } else if (Diagnostics->BugCheckCode == 0x000000EF &&
               KswordARKBugcheckLayoutHasProcess(Diagnostics)) {
        // For 0xEF, the cached critical process is evidence, not the culprit.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 320L, KswordArkBugcheckLayoutColorAccent, 29UL,
            "%s / PID %Iu",
            Diagnostics->ProcessName,
            Diagnostics->ProcessId);
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 338L, KswordArkBugcheckLayoutColorText, 29UL,
            "CRITICAL %s",
            KswordARKBugcheckLayoutCriticalObjectText(Diagnostics));
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 356L, KswordArkBugcheckLayoutColorText, 29UL,
            "OBJECT  0x%p", (PVOID)Diagnostics->ProcessObject);
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 374L, KswordArkBugcheckLayoutColorMuted, 29UL,
            "ROOT CAUSE NEEDS DUMP STACK");
    } else if (KswordARKBugcheckLayoutHasProcess(Diagnostics)) {
        // Non-0xEF process hits identify crash context, never the culprit.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 320L, KswordArkBugcheckLayoutColorAccent, 29UL,
            "%s / PID %Iu",
            Diagnostics->ProcessName,
            Diagnostics->ProcessId);
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 338L, KswordArkBugcheckLayoutColorText, 29UL,
            "CRASH CONTEXT");
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 356L, KswordArkBugcheckLayoutColorMuted, 29UL,
            "CONTEXT ONLY; NOT THE CULPRIT");
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 374L, KswordArkBugcheckLayoutColorMuted, 29UL,
            "ROOT CAUSE NEEDS DUMP STACK");
    } else {
        // A failed live attribution consumes only two lines, never a full card.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 320L, KswordArkBugcheckLayoutColorMuted, 29UL,
            "NO SAFE LIVE ATTRIBUTION");
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 28L, 340L, KswordArkBugcheckLayoutColorText, 29UL,
            "ANALYZE THE SAVED DUMP STACK");
        for (parameterIndex = 1;
             parameterIndex <= RTL_NUMBER_OF(values);
             ++parameterIndex) {
            if (!KswordARKBugcheckLayoutShouldShowParameter(
                    Diagnostics,
                    parameterIndex,
                    values[parameterIndex - 1UL])) {
                continue;
            }
            // One compact parameter preserves context without crowding the card.
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 28L, 366L, KswordArkBugcheckLayoutColorMuted, 29UL,
                "P%lu %s",
                parameterIndex,
                KswordARKBugcheckDecodeParameterRole(
                    Diagnostics,
                    parameterIndex));
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 28L, 384L, KswordArkBugcheckLayoutColorText, 29UL,
                "0x%p", (PVOID)values[parameterIndex - 1UL]);
            break;
        }
    }

    // The right card is deliberately limited to three actionable steps.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 302L, KswordArkBugcheckLayoutColorMuted, 29UL,
        "NEXT ACTION");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 326L, KswordArkBugcheckLayoutColorText, 29UL,
        "1  KEEP THE CRASH DUMP");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 350L, KswordArkBugcheckLayoutColorText, 29UL,
        "2  ANALYZE IN KSWORDARK");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 340L, 374L, KswordArkBugcheckLayoutColorText, 29UL,
        "3  ATTACH DUMP WHEN REPORTING");

    // The 228..284 band remains empty for Windows dump progress text.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 16L, 442L, KswordArkBugcheckLayoutColorMuted, 68UL,
        "WINDOWS IS WRITING THE CRASH DUMP. DO NOT POWER OFF.");
}

static VOID
KswordARKBugcheckLayoutDrawFull(
    _Inout_ KSWORD_ARK_BUGCHECK_LAYOUT_WRITER* Writer,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    PCSTR moduleText;
    ULONG moduleLength;
    ULONG parameterLines;

    // Runtime callback and cache telemetry never belong on the user surface.
    UNREFERENCED_PARAMETER(CallbackMask);
    UNREFERENCED_PARAMETER(ModuleCount);
    // Resolve the optional module basename before selecting the evidence path.
    moduleText = KswordARKBugcheckLayoutModuleText(Diagnostics);
    // Measure within the fixed snapshot so long names receive a complete row.
    moduleLength = KswordARKBugcheckLayoutTextLength(
        moduleText,
        KSWORD_ARK_BUGCHECK_MODULE_NAME_CHARS - 1UL);

    // Retain the accepted four-panel geometry and restore generous whitespace.
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 156L, KswordArkBugcheckLayoutFrameFullBottomLeft);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 508L, 156L, KswordArkBugcheckLayoutFrameFullBottomRight);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 16L, 348L, KswordArkBugcheckLayoutFrameFullBottomLeft);
    KswordARKBugcheckLayoutWriteFrame(
        Writer, 508L, 348L, KswordArkBugcheckLayoutFrameFullBottomRight);

    // The summary explains the stop without repeating the header identity.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 168L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "CRASH SUMMARY");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 194L, KswordArkBugcheckLayoutColorText, 50UL,
        "%s", KswordARKBugcheckLayoutHumanCauseText(
            Diagnostics->BugCheckCode));
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 226L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "CPU %lu / IRQL %lu", Diagnostics->Cpu, Diagnostics->Irql);

    // The evidence panel displays resolved facts and suppresses empty fields.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 168L, KswordArkBugcheckLayoutColorMuted, 52UL,
        "PRIMARY EVIDENCE");
    if (moduleText != NULL &&
        Diagnostics->CandidateClass != KSWORD_ARK_BUGCHECK_MODULE_UNKNOWN) {
        // A documented code address mapped to a module is primary attribution.
        if (moduleLength > 54UL) {
            // Split the rare long basename while retaining class and exact IP.
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 516L, 190L, KswordArkBugcheckLayoutColorAccent, 54UL,
                "%.*s", 54, moduleText);
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 516L, 214L, KswordArkBugcheckLayoutColorAccent, 54UL,
                "%s", moduleText + 54UL);
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 520L, 238L, KswordArkBugcheckLayoutColorText, 52UL,
                "%s CODE / CONFIDENCE %s",
                KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass),
                KswordARKBugcheckConfidenceText(
                    Diagnostics->CandidateConfidence));
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 520L, 262L, KswordArkBugcheckLayoutColorMuted, 52UL,
                "P%lu CODE IP  0x%p",
                Diagnostics->CandidateParameter,
                (PVOID)Diagnostics->FaultAddress);
        } else {
            // Short basenames leave room for offset and documented source.
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 516L, 190L, KswordArkBugcheckLayoutColorAccent, 54UL,
                "%s", moduleText);
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 520L, 214L, KswordArkBugcheckLayoutColorText, 52UL,
                "%s CODE / CONFIDENCE %s",
                KswordARKBugcheckModuleClassText(Diagnostics->CandidateClass),
                KswordARKBugcheckConfidenceText(
                    Diagnostics->CandidateConfidence));
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 520L, 238L, KswordArkBugcheckLayoutColorText, 52UL,
                "MODULE OFFSET  0x%p",
                (PVOID)Diagnostics->CandidateModuleOffset);
            KswordARKBugcheckLayoutWriteFormatted(
                Writer, 520L, 262L, KswordArkBugcheckLayoutColorMuted, 52UL,
                "DOCUMENTED CODE ADDRESS IN P%lu",
                Diagnostics->CandidateParameter);
        }
    } else if (Diagnostics->BugCheckCode == 0x000000EF &&
               KswordARKBugcheckLayoutHasProcess(Diagnostics)) {
        // A cached 0xEF process identifies the victim but not terminating code.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 190L, KswordArkBugcheckLayoutColorAccent, 52UL,
            "%s", Diagnostics->ProcessName);
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 214L, KswordArkBugcheckLayoutColorText, 52UL,
            "CRITICAL PROCESS / PID %Iu", Diagnostics->ProcessId);
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 238L, KswordArkBugcheckLayoutColorText, 52UL,
            "OBJECT TYPE  %s",
            KswordARKBugcheckLayoutCriticalObjectText(Diagnostics));
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 262L, KswordArkBugcheckLayoutColorMuted, 52UL,
            "ROOT CAUSE REQUIRES THE DUMP STACK");
    } else if (KswordARKBugcheckLayoutHasProcess(Diagnostics)) {
        // Other process cache hits are context only and never culprit claims.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 190L, KswordArkBugcheckLayoutColorAccent, 52UL,
            "%s", Diagnostics->ProcessName);
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 214L, KswordArkBugcheckLayoutColorText, 52UL,
            "CRASH CONTEXT / PID %Iu", Diagnostics->ProcessId);
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 238L, KswordArkBugcheckLayoutColorMuted, 52UL,
            "CONTEXT ONLY; ANALYZE THE DUMP STACK");
    } else {
        // A live miss is stated once instead of filling the panel with failures.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 190L, KswordArkBugcheckLayoutColorMuted, 52UL,
            "NO SAFE LIVE ATTRIBUTION");
        KswordARKBugcheckLayoutWriteFormatted(
            Writer, 520L, 216L, KswordArkBugcheckLayoutColorText, 52UL,
            "ANALYZE THE SAVED DUMP STACK");
    }

    // Technical evidence includes only semantic or nonzero stop parameters.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 28L, 360L, KswordArkBugcheckLayoutColorMuted, 50UL,
        "TECHNICAL EVIDENCE");
    parameterLines = KswordARKBugcheckLayoutWriteTechnicalParameters(
        Writer,
        28L,
        384L,
        50UL,
        Diagnostics,
        4UL);
    if (parameterLines < 4UL) {
        // CPU and IRQL use only genuinely unused space in the technical panel.
        KswordARKBugcheckLayoutWriteFormatted(
            Writer,
            28L,
            384L + (LONG)(parameterLines * 22UL),
            KswordArkBugcheckLayoutColorMuted,
            50UL,
            "CPU %lu / IRQL %lu",
            Diagnostics->Cpu,
            Diagnostics->Irql);
    }

    // Three short actions replace repeated warnings and generic advice.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 360L, KswordArkBugcheckLayoutColorMuted, 52UL,
        "NEXT ACTION");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 388L, KswordArkBugcheckLayoutColorText, 52UL,
        "1  KEEP THE NEWEST CRASH DUMP");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 418L, KswordArkBugcheckLayoutColorText, 52UL,
        "2  ANALYZE IN KSWORDARK OR WINDBG");
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 520L, 448L, KswordArkBugcheckLayoutColorText, 52UL,
        "3  ATTACH THE DUMP WHEN REPORTING");

    // The bottom band carries the single power-loss warning for the whole page.
    KswordARKBugcheckLayoutWriteFormatted(
        Writer, 16L, 724L, KswordArkBugcheckLayoutColorMuted, 80UL,
        "WAITING FOR WINDOWS TO COMPLETE THE CRASH DUMP. DO NOT POWER OFF.");
}

NTSTATUS
KswordARKBugcheckLayoutDraw(
    _In_ const KSWORD_ARK_BUGCHECK_LAYOUT_CANVAS* Canvas,
    _In_ const KSWORD_ARK_BUGCHECK_DIAGNOSTICS* Diagnostics,
    _In_ ULONG CallbackMask,
    _In_ ULONG ModuleCount
    )
{
    KSWORD_ARK_BUGCHECK_LAYOUT_WRITER writer;
    BOOLEAN compact;

    if (Canvas == NULL || Diagnostics == NULL ||
        Canvas->DrawText == NULL || Canvas->DrawFrame == NULL ||
        Canvas->Width < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_WIDTH ||
        Canvas->Height < KSWORD_ARK_BUGCHECK_LAYOUT_REQUIRED_HEIGHT) {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&writer, sizeof(writer));
    writer.Canvas = Canvas;
    writer.OriginX = KswordARKBugcheckLayoutOriginX(
        Canvas->Width,
        Canvas->Height);
    writer.Status = STATUS_SUCCESS;
    compact = KswordARKBugcheckLayoutIsCompact(Canvas->Width, Canvas->Height);
    KswordARKBugcheckLayoutWriteHeader(&writer, Diagnostics, compact);
    if (compact) {
        KswordARKBugcheckLayoutDrawCompact(
            &writer,
            Diagnostics,
            CallbackMask,
            ModuleCount);
    } else {
        KswordARKBugcheckLayoutDrawFull(
            &writer,
            Diagnostics,
            CallbackMask,
            ModuleCount);
    }
    return writer.Status;
}
