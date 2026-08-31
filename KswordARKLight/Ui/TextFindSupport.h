#pragma once

#include "../Core/Win32Lean.h"

namespace Ksword::Ui {

// AttachTextFindSupport gives one multi-line EDIT the find bar it has been
// missing. Input is the control HWND; processing subclasses it and lazily
// creates a floating bar the first time the user asks for it; no value is
// returned and a control may be attached twice without harm.
//
// The detail and log panes in this project routinely hold thousands of lines --
// kernel feature detail, driver debug output, ETW rows, PEB dumps -- with no way
// to look for anything inside them, so reading one meant scrolling it by hand.
//
// Keys handled on the control: Ctrl+F opens the bar, Ctrl+H opens it with the
// replacement field focused (writable controls only), F3 and Shift+F3 step
// through matches without opening anything, and Esc closes the bar and hands
// focus back to the text.
//
// Read-only controls get find only: the replacement fields are not created at
// all rather than shown disabled, because a greyed control invites the user to
// hunt for the switch that would enable it.
void AttachTextFindSupport(HWND multilineEdit);

// OpenTextFindSupport exposes the attached find bar to page-local controls.
// If needed it attaches the support first, then opens the read-only or editable
// find UI exactly as Ctrl+F would.
void OpenTextFindSupport(HWND multilineEdit);

// AttachTextFindSupportRecursive attaches every multi-line EDIT under one root.
// Input is a page or dialog HWND; processing walks the child tree once and
// attaches each control whose style carries ES_MULTILINE; no value is returned.
// Controls created later are not covered and need their own attach call.
void AttachTextFindSupportRecursive(HWND root);

} // namespace Ksword::Ui
