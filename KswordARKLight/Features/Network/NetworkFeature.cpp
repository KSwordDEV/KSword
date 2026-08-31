#include "NetworkFeature.h"

#include "NetworkView.h"

namespace Ksword::Features::Network {

HWND CreateNetworkFeaturePage(HWND parent, const RECT& bounds) {
    // Inputs are the host HWND and target child rectangle. Processing remains a
    // thin module boundary so the later registry/project integration thread only
    // needs to reference this stable entry point. The returned HWND owns the
    // NetworkView state, or nullptr indicates Win32 creation failure.
    return CreateNetworkFeatureView(parent, bounds);
}

void ResizeNetworkFeaturePage(HWND page, const RECT& bounds) {
    // Inputs are an already-created page HWND and the new host bounds. The view
    // performs its own child layout on WM_SIZE; this facade only moves the root
    // HWND and intentionally returns no value.
    if (page) {
        ::MoveWindow(
            page,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            TRUE);
    }
}

bool RequestNetworkFeatureProcess(HWND page, const DWORD processId) {
    return RequestNetworkFeatureViewProcess(page, processId);
}

} // namespace Ksword::Features::Network
