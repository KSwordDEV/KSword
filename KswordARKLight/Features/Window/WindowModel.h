#pragma once
#include "../../../shared/usermode/backend/window/WindowTypes.h"

#include "../../Core/Win32Lean.h"

#include <string>
#include <vector>

namespace Ksword::Features::Window {
using ks::r3::window::WindowSortMode;
using ks::r3::window::WindowSnapshotRow;
using ks::r3::window::WindowProperty;
using ks::r3::window::WindowDetail;
using ks::r3::window::WindowEnumerationResult;
using ks::r3::window::WindowStateText;
using ks::r3::window::HwndToText;
using ks::r3::window::RectToText;


// WindowSortMode controls the retained window-list order. Inputs are selected
// from the WindowView combo box; processing happens inside WindowModel so the UI
// can rebuild without re-enumerating windows.


// WindowSnapshotRow is one top-level non-desktop window captured by EnumWindows.
// Inputs come from Win32 window APIs; consumers treat hwnd as a transient value
// that must be revalidated before any operation.


// WindowProperty is one detail-pane name/value pair. Inputs are raw Win32 fields
// formatted by WindowEnumerator or WindowModel; consumers display the value as a
// string and do not parse it back into window handles or style flags.


// WindowDetail is a live detail snapshot for one HWND. Input is an HWND selected
// from the list; processing revalidates the window before querying details; the
// found flag reports whether the handle still represents a window.


// WindowEnumerationResult contains one EnumWindows pass. success is false only
// when a fatal precondition fails; individual windows that disappear mid-query
// are skipped without failing the whole pass.


// WindowModel stores the latest top-level window snapshot and prepares display
// strings. Inputs are WindowSnapshotRow vectors; processing keeps sorting and
// formatting local to the Window module; outputs are stable until setRows.
class WindowModel final {
public:
    WindowModel();

    // setRows replaces the current window snapshot. Input rows are copied into
    // this model; processing preserves raw EnumWindows order and rebuilds the
    // display rows according to the active sort mode; no return.
    void setRows(std::vector<WindowSnapshotRow> rows);

    // setSortMode changes display ordering without re-enumerating windows.
    // Input is a mode from the view combo box; processing rebuilds rows_; no
    // value is returned.
    void setSortMode(WindowSortMode mode);

    // sortMode returns the current window-list ordering. There is no input;
    // output is used by WindowView when syncing combo-box state.
    WindowSortMode sortMode() const;

    // rows returns the current snapshot. There is no input; output is a const
    // reference valid until setRows is called again.
    const std::vector<WindowSnapshotRow>& rows() const;

    // rowAt validates a model index. Input is a zero-based row index; output is
    // nullptr when the index is invalid.
    const WindowSnapshotRow* rowAt(int index) const;

    // textForColumn returns list-view text. Inputs are row and column index;
    // output is empty for unsupported columns.
    std::wstring textForColumn(const WindowSnapshotRow& row, int column) const;

    // detailFromRow builds a fallback detail view from cached data. Input is a
    // snapshot row; output is a complete detail object without live Win32 calls.
    WindowDetail detailFromRow(const WindowSnapshotRow& row) const;

private:
    void rebuildRows();

private:
    std::vector<WindowSnapshotRow> originalRows_;
    std::vector<WindowSnapshotRow> rows_;
    WindowSortMode sortMode_ = WindowSortMode::StackingOrder;
};

// WindowStateText formats common visible/enabled/minimized state. Input is a
// row; output is a compact human-readable label.


// HwndToText formats an HWND as hexadecimal text. Input is an HWND; output is a
// stable display string that does not imply ownership of the handle.


// RectToText formats a RECT as left,top,width,height text. Input is a RECT;
// output is compact display text used by detail panes.


} // namespace Ksword::Features::Window
