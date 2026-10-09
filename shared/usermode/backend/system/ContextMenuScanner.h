#pragma once

#include "../Win32.h"

#include <string>
#include <vector>

namespace ks::r3::system_tools {

// ContextMenuKind separates the two very different things Explorer calls a
// context-menu entry: an in-process COM handler that runs inside Explorer, and a
// declarative verb that only launches a command line.
enum class ContextMenuKind {
    ShellExHandler,
    ShellVerb
};

// ContextMenuEntry is one shell registration point. All strings are display
// ready; registrationPath is the only field the action functions need.
struct ContextMenuEntry {
    ContextMenuKind kind = ContextMenuKind::ShellExHandler;
    std::wstring scopeText;          // "*" / "Directory" / "Folder"
    std::wstring registrationPath;   // HKCR-relative path of the entry itself.
    std::wstring name;               // Leaf subkey name.
    std::wstring displayText;        // Friendly name, MUIVerb, or default value.
    std::wstring clsid;              // Empty for verb entries.
    std::wstring modulePath;         // InprocServer32 path or the verb command line.
    std::wstring moduleFile;         // The file whose existence was actually checked.
    bool moduleExists = false;
    bool enabled = true;             // False while the entry sits in the backup store.
    std::wstring backupKeyName;      // Backup store subkey name, set for disabled entries.
    std::wstring diagnosticText;
};

// ContextMenuScanResult carries one enumeration pass over the live registration
// points plus this tool's own backup store, so an entry that was disabled here
// stays visible and can be turned back on.
struct ContextMenuScanResult {
    bool success = false;
    bool elevated = false;
    std::wstring diagnosticText;
    std::vector<ContextMenuEntry> entries;
};

// ContextMenuActionResult is the value-only outcome of one registry mutation.
struct ContextMenuActionResult {
    bool success = false;
    std::wstring message;
};

// ScanContextMenuEntries reads the five registration points this page covers
// plus the backup store. There is no input; processing only reads the registry;
// output is one snapshot. It is safe to call from a worker thread.
ContextMenuScanResult ScanContextMenuEntries();

// DisableContextMenuEntry copies the whole subtree into this tool's backup store
// and then deletes it from HKCR. Input is a live entry; output reports what was
// written and removed.
//
// The traditional trick is to rename the entry with a "-" prefix so Explorer
// stops recognizing it. That is rejected here for three reasons: it is an
// undocumented convention that several shell versions have ignored, third-party
// "cleaners" strip the prefix back off and silently re-enable the handler, and a
// verb entry under HKCR\*\shell has no CLSID value to prefix at all. A verbatim
// backup followed by a delete is unambiguous -- Explorer cannot load a key that
// is not there -- and it is still reversible, because the backup keeps every
// value and subkey the "-" trick would have left in place.
//
// This deletes live registry state and must only be called after the caller has
// confirmed the operation with the user.
ContextMenuActionResult DisableContextMenuEntry(const ContextMenuEntry& entry);

// EnableContextMenuEntry restores one backed-up subtree to its original HKCR
// path and removes the backup. Input is a disabled entry; output reports the
// restore result.
ContextMenuActionResult EnableContextMenuEntry(const ContextMenuEntry& entry);

// ContextMenuBackupRootPath returns the backup store location, so the UI can
// tell the user where the removed keys actually went.
std::wstring ContextMenuBackupRootPath();

} // namespace ks::r3::system_tools
