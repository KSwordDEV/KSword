#include "MonitorFeature.h"

#include "EtwMonitorView.h"

namespace Ksword::Features::Monitor {

HWND CreateMonitorFeaturePage(HWND parent, const RECT& bounds) {
    return CreateEtwMonitorPage(parent, bounds);
}

bool RequestMonitorFeatureProcess(HWND page, const DWORD processId) {
    return RequestEtwMonitorProcessFilter(page, processId);
}

} // namespace Ksword::Features::Monitor
