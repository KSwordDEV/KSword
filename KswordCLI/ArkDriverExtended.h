#pragma once

// commandArkDriverExtended handles the r0 command family that reuses the
// production ArkDriverClient protocol wrappers for desktop-only R0 evidence.
int commandArkDriverExtended(int argc, wchar_t* argv[]);

// commandArkDriverCallbackMonitor handles callback monitor subcommands through
// the production ArkDriverClient protocol wrappers.
int commandArkDriverCallbackMonitor(int argc, wchar_t* argv[]);
