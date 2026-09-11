#pragma once
#include "KswordArkProcessIoctl.h"

// Native USER ordering. Deliberately separate from the read-only Win32k audit ABI.
#define KSWORD_ARK_WINDOW_BAND_VERSION 1UL
#define IOCTL_KSWORD_ARK_WINDOW_BAND CTL_CODE(KSWORD_ARK_IOCTL_DEVICE_TYPE, 0x898UL, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define KSW_BAND_PROBE 0UL
#define KSW_BAND_QUERY 1UL
#define KSW_BAND_SET 2UL
#define KSW_BAND_TOP 0UL
#define KSW_BAND_BOTTOM 1UL
#define KSW_BAND_CONFIRMED 0x42414E44UL
#define KSW_BAND_VERIFIED 0x1UL
#define KSW_BAND_CHANGED 0x2UL
#define KSW_BAND_ROLLED_BACK 0x4UL
#define KSW_BAND_POSITION_VERIFIED 0x8UL

typedef struct _KSWORD_ARK_WINDOW_BAND_REQUEST {
    ULONG size, version, operation, confirmation;
    ULONG64 hwnd, callerHwnd, processCreated, expectedObject;
    ULONG processId, threadId, expectedBand, newBand;
    ULONG position, reserved;
} KSWORD_ARK_WINDOW_BAND_REQUEST;

typedef struct _KSWORD_ARK_WINDOW_BAND_RESPONSE {
    ULONG size, version;
    LONG lastStatus;
    ULONG flags;
    ULONG64 windowObject;
    ULONG previousBand, currentBand;
    ULONG imageTimeDateStamp, imageSize;
} KSWORD_ARK_WINDOW_BAND_RESPONSE;
