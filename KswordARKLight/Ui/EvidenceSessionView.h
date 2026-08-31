#pragma once

#include "../Core/Win32Lean.h"

namespace Ksword::Ui {

// ShowEvidenceSessionInspector opens the modeless native inspector for the
// process-wide evidence session. The view reads immutable snapshots only; it
// never triggers a driver query, filesystem scan, or export operation.
bool ShowEvidenceSessionInspector(HWND owner);

} // namespace Ksword::Ui
