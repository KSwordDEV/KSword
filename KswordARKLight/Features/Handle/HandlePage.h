#pragma once

#include "../../Core/Win32Lean.h"

#include <string>

namespace Ksword::Features::Handle {

struct HandlePageState;

// HandlePage owns the lightweight read-only Handle audit surface. Inputs are a
// parent HWND and bounds at creation time; processing keeps all child controls
// alive until WM_NCDESTROY; output is the created root HWND.
class HandlePage final {
public:
    // Create registers the page class and creates one page instance. Inputs are
    // parent HWND and initial bounds; output is the root child HWND or nullptr.
    static HWND Create(HWND parent, const RECT& bounds);

    // SetProcessId selects a verified process identity supplied by the shell,
    // updates the PID field and starts the normal read-only handle refresh.
    static bool SetProcessId(HWND page, DWORD processId);

    // WindowProc routes Win32 messages to the instance stored on GWLP_USERDATA.
    // Inputs are standard Win32 procedure values; output is the message result.
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

private:
    HandlePage() = default;
    ~HandlePage() = default;

    HandlePage(const HandlePage&) = delete;
    HandlePage& operator=(const HandlePage&) = delete;

    // HandleMessage performs page message dispatch. Inputs are ordinary Win32
    // message parameters; processing updates controls/model; output is LRESULT.
    LRESULT HandleMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

    // Initialize creates toolbar controls, tab host and retained tab pages.
    // Input is the root HWND; processing builds child windows; output is true
    // when the page has enough controls to operate.
    bool Initialize(HWND hwnd);

    // Layout resizes toolbar, tab pages and current child controls. Input is the
    // current client rectangle read from hwnd_; no value is returned.
    void Layout();

    // Refresh reads the PID field and queries the R0 HandleTable adapter. Input
    // is implicit UI state; processing repopulates the table; no return value.
    void Refresh();

    // PopulateList renders the current handle snapshot. Input is snapshot_
    // stored on the object; processing rewrites list rows; no value is returned.
    void PopulateList();

    // PopulateDetail renders ObjectHeader/ObjectType/access details for one row.
    // Input is a row index from the list view; processing issues a read-only
    // object query and rewrites the detail table; no value is returned.
    void PopulateDetail(int rowIndex);

    // RequestFilter applies a debounced local search to the immutable handle
    // snapshot without issuing another driver query.
    void RequestFilter(const std::wstring& query, std::wstring selectedStableKey = {}, std::wstring topStableKey = {});

    // ShowHandleContextMenu exposes copy actions for the virtual handle table.
    void ShowHandleContextMenu(POINT screenPoint);

    // ShowDetailContextMenu exposes copy actions for Object detail rows.
    void ShowDetailContextMenu(POINT screenPoint);

    // SetStatus writes a compact status message. Input is UI text; processing
    // updates the status static control; no value is returned.
    void SetStatus(const std::wstring& text);

private:
    HWND hwnd_ = nullptr;
    HWND pidEdit_ = nullptr;
    HWND refreshButton_ = nullptr;
    HWND statusText_ = nullptr;
    HWND tab_ = nullptr;
    HWND filterBar_ = nullptr;
    HWND loadingOverlay_ = nullptr;
    HWND handleList_ = nullptr;
    HWND detailList_ = nullptr;
    int currentTab_ = 0;
    HandlePageState* state_ = nullptr;
};

} // namespace Ksword::Features::Handle
