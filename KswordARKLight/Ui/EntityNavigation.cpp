#include "EntityNavigation.h"

namespace Ksword::Ui {

bool RequestEntityNavigation(HWND source, const Ksword::Core::NavigationRequest& request) {
    if (!source) {
        return false;
    }
    HWND root = ::GetAncestor(source, GA_ROOT);
    if (!root) {
        root = source;
    }
    return ::SendMessageW(
        root,
        kEntityNavigationMessage,
        0,
        reinterpret_cast<LPARAM>(&request)) != 0;
}

} // namespace Ksword::Ui
