#pragma once

#include "../Core/Win32Lean.h"

#include <functional>
#include <string>
#include <vector>

namespace Ksword::Ui {

using WorkspacePageFactory = std::function<HWND(HWND parent, const RECT& bounds)>;

struct WorkspaceTabDescriptor final {
    int id = 0;
    std::wstring title;
    std::wstring summary;
    WorkspacePageFactory createPage;
};

struct WorkspaceOptions final {
    int tabControlId = 0;
    int initialTabId = 0;
    int margin = 0;
    std::function<void(int tabId, HWND page)> pageActivated;
};

// CreateWorkspaceHost creates a retained Win32 tab workspace whose child pages
// are materialized only when selected. The module owns placeholders, failure
// retry, layout, state preservation and activation callbacks behind this small
// interface; callers only provide immutable descriptors and page factories.
HWND CreateWorkspaceHost(
    HWND parent,
    const RECT& bounds,
    std::vector<WorkspaceTabDescriptor> tabs,
    WorkspaceOptions options = {});

// WorkspaceHostPage returns a page by stable tab id. materialize=true performs
// synchronous creation when command routing needs the page immediately.
HWND WorkspaceHostPage(HWND workspace, int tabId, bool materialize = false);

int WorkspaceHostActiveTabId(HWND workspace);
bool ActivateWorkspaceHostTab(HWND workspace, int tabId, bool materialize = true);

} // namespace Ksword::Ui
