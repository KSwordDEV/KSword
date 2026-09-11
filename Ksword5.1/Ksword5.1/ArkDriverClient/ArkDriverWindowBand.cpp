#include "ArkDriverClient.h"

namespace ksword::ark
{
    WindowBandResult DriverClient::controlWindowBand(KSWORD_ARK_WINDOW_BAND_REQUEST request) const
    {
        WindowBandResult result;
        request.size = sizeof(request);
        request.version = KSWORD_ARK_WINDOW_BAND_VERSION;
        // Give the caller-context handler a window on THIS GUI thread/desktop.
        // A message-only window is sufficient to prove ownership and desktop.
        HWND caller = nullptr;
        if (request.operation != KSW_BAND_PROBE)
        {
            caller = CreateWindowExW(0, L"STATIC", L"", 0, 0, 0, 0, 0,
                HWND_MESSAGE, nullptr, GetModuleHandleW(nullptr), nullptr);
            if (!caller) { result.io.win32Error = GetLastError(); return result; }
            request.callerHwnd = reinterpret_cast<ULONG64>(caller);
        }
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_WINDOW_BAND, &request, sizeof(request),
            &result.response, sizeof(result.response));
        if (caller) DestroyWindow(caller);
        if (!result.io.ok) return result;
        if (result.io.bytesReturned != sizeof(result.response) || result.response.size != sizeof(result.response) ||
            result.response.version != KSWORD_ARK_WINDOW_BAND_VERSION)
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            return result;
        }
        result.io.ntStatus = result.response.lastStatus;
        return result;
    }
}
