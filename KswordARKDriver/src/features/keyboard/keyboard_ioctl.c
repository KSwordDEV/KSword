/*++

Module Name:

    keyboard_ioctl.c

Abstract:

    IOCTL handlers for read-only win32k keyboard hotkey/hook inspection.

Environment:

    Kernel-mode Driver Framework

--*/

#include "ark/ark_driver.h"
#include "../../dispatch/ioctl_validation.h"

#include <ntstrsafe.h>
#include <stdarg.h>

#define KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY))

#define KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE \
    (sizeof(KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE) - sizeof(KSWORD_ARK_KEYBOARD_HOOK_ENTRY))

static VOID
KswordARKKeyboardIoctlLog(
    _In_ WDFDEVICE Device,
    _In_z_ PCSTR LevelText,
    _In_z_ PCSTR FormatText,
    ...
    )
{
    CHAR logMessage[KSWORD_ARK_LOG_ENTRY_MAX_BYTES] = { 0 };
    va_list arguments;

    va_start(arguments, FormatText);
    if (NT_SUCCESS(RtlStringCbVPrintfA(logMessage, sizeof(logMessage), FormatText, arguments))) {
        (VOID)KswordARKDriverEnqueueLogFrame(Device, LevelText, logMessage);
    }
    va_end(arguments);
}

static VOID
KswordARKKeyboardFillDefaultRequest(
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST* Request,
    _In_ ULONG DefaultFlags
    )
{
    RtlZeroMemory(Request, sizeof(*Request));
    Request->version = KSWORD_ARK_KEYBOARD_PROTOCOL_VERSION;
    Request->flags = DefaultFlags;
    Request->processId = 0UL;
    Request->maxEntries = 1024UL;
}

static NTSTATUS
KswordARKKeyboardRetrieveRequest(
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ ULONG DefaultFlags,
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST* RequestSnapshot,
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST** RequestOut,
    _Out_ KSWORD_ARK_ENUM_KEYBOARD_REQUEST* DefaultRequest
    )
{
    PVOID inputBuffer = NULL;
    size_t actualInputLength = 0;
    BOOLEAN hasInput = FALSE;
    NTSTATUS status = STATUS_SUCCESS;

    if (RequestSnapshot == NULL || RequestOut == NULL || DefaultRequest == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    *RequestOut = NULL;
    status = KswordARKRetrieveOptionalInputBuffer(
        Request,
        InputBufferLength,
        sizeof(KSWORD_ARK_ENUM_KEYBOARD_REQUEST),
        &inputBuffer,
        &actualInputLength,
        &hasInput);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (hasInput) {
        /* METHOD_BUFFERED shares input/output: preserve options before output is cleared. */
        RtlCopyMemory(RequestSnapshot, inputBuffer, sizeof(*RequestSnapshot));
        *RequestOut = RequestSnapshot;
    }
    else {
        KswordARKKeyboardFillDefaultRequest(DefaultRequest, DefaultFlags);
        *RequestOut = DefaultRequest;
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKeyboardIoctlEnumHotkeys(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST requestSnapshot;
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST defaultRequest;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKKeyboardRetrieveRequest(
        Request,
        InputBufferLength,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        &requestSnapshot,
        &enumRequest,
        &defaultRequest);
    if (!NT_SUCCESS(status)) {
        KswordARKKeyboardIoctlLog(Device, "Error", "R0 enum-keyboard-hotkeys ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKeyboardIoctlLog(Device, "Error", "R0 enum-keyboard-hotkeys ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateKeyboardHotkeys(outputBuffer, actualOutputLength, enumRequest, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKeyboardIoctlLog(Device, "Error", "R0 enum-keyboard-hotkeys failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_KEYBOARD_HOTKEY_RESPONSE_HEADER_SIZE) {
        const KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE* response =
            (const KSWORD_ARK_ENUM_KEYBOARD_HOTKEYS_RESPONSE*)outputBuffer;
        KswordARKKeyboardIoctlLog(
            Device,
            "Info",
            "R0 enum-keyboard-hotkeys success: status=%lu, total=%lu, returned=%lu.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKKeyboardIoctlEnumHooks(
    _In_ WDFDEVICE Device,
    _In_ WDFREQUEST Request,
    _In_ size_t InputBufferLength,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesReturned
    )
{
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST* enumRequest = NULL;
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST requestSnapshot;
    KSWORD_ARK_ENUM_KEYBOARD_REQUEST defaultRequest;
    PVOID outputBuffer = NULL;
    size_t actualOutputLength = 0;
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(OutputBufferLength);

    if (BytesReturned == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    *BytesReturned = 0;

    status = KswordARKKeyboardRetrieveRequest(
        Request,
        InputBufferLength,
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        &requestSnapshot,
        &enumRequest,
        &defaultRequest);
    if (!NT_SUCCESS(status)) {
        KswordARKKeyboardIoctlLog(Device, "Error", "R0 enum-keyboard-hooks ioctl: input invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKRetrieveRequiredOutputBuffer(
        Request,
        KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE,
        &outputBuffer,
        &actualOutputLength);
    if (!NT_SUCCESS(status)) {
        KswordARKKeyboardIoctlLog(Device, "Error", "R0 enum-keyboard-hooks ioctl: output invalid, status=0x%08X.", (unsigned int)status);
        return status;
    }

    status = KswordARKDriverEnumerateKeyboardHooks(outputBuffer, actualOutputLength, enumRequest, BytesReturned);
    if (!NT_SUCCESS(status)) {
        KswordARKKeyboardIoctlLog(Device, "Error", "R0 enum-keyboard-hooks failed: status=0x%08X, outBytes=%Iu.", (unsigned int)status, *BytesReturned);
        return status;
    }

    if (*BytesReturned >= KSWORD_ARK_KEYBOARD_HOOK_RESPONSE_HEADER_SIZE) {
        const KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE* response =
            (const KSWORD_ARK_ENUM_KEYBOARD_HOOKS_RESPONSE*)outputBuffer;
        KswordARKKeyboardIoctlLog(
            Device,
            "Info",
            "R0 enum-keyboard-hooks success: status=%lu, total=%lu, returned=%lu.",
            (unsigned long)response->status,
            (unsigned long)response->totalCount,
            (unsigned long)response->returnedCount);
    }

    return STATUS_SUCCESS;
}
