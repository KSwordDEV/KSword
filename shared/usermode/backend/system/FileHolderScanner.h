#pragma once

#include "../Win32.h"

#include <cstdint>
#include <string>
#include <vector>
#include <functional>

namespace ks::r3::system_tools {

// FileHolderEntry is one process/handle pair that currently keeps the target
// file open. Values are already formatted for display; the view never parses
// them back.
struct FileHolderEntry {
    std::uint64_t processCreationTime = 0;
    bool creationTimeKnown = false,processAlive = false,processAliveKnown = false,pathKnown = false,nameKnown = false;
    DWORD identityError = 0,pathError = 0;
    std::uint32_t processId = 0;
    std::wstring processName;
    std::wstring processPath;
    std::uint64_t handleValue = 0;
    std::uint32_t grantedAccess = 0;
    std::wstring accessText;      // Readable subset of the granted access mask.
    std::wstring objectName;      // NT object-manager path of the opened file.
    std::wstring win32Name;       // Same path mapped back to a drive letter.
};

// FileHolderScanResult carries one full system-wide handle sweep. The counters
// are part of the result rather than a log line because a sweep that inspected
// far fewer handles than it found is a permission problem, not an empty answer,
// and the operator has to be able to tell those two apart.
struct FileHolderScanResult {
    bool snapshotAttempted = false,ntStatusKnown = false,malformed = false,limited = false,cancelled = false,complete = false,apiUnavailable = false;
    LONG snapshotNtStatus = 0;
    DWORD snapshotBytes = 0,examinedHandles = 0,protectedSkipped = 0,openFailed = 0,duplicateFailed = 0,notDisk = 0,nameFailed = 0,identityMismatch = 0;
    DWORD waitFailed = 0,waitWin32Error = 0;
    bool success = false;
    std::wstring diagnosticText;
    std::wstring targetNtPath;             // What the sweep actually compared against.
    std::uint32_t totalHandles = 0;        // Every handle the system reported.
    std::uint32_t fileHandles = 0;         // Handles whose object type is File.
    std::uint32_t inspectedHandles = 0;    // File handles whose name was queried.
    std::uint32_t skippedHandles = 0;      // Pre-filtered or non-duplicable handles.
    std::uint32_t timedOutHandles = 0;     // Name queries abandoned on timeout.
    std::uint32_t elapsedMs = 0;
    std::vector<FileHolderEntry> entries;
};

// ScanFileHolders finds every process holding a handle to one file. Inputs are
// the target path (Win32 or NT form) and whether paths below a directory count
// as a match; processing enumerates all system handles and resolves the file
// ones; output is the match list plus sweep statistics.
//
// This blocks for seconds on a busy machine and must only be called from a
// worker thread.
struct FileHolderScanOptions {
    DWORD processId = 0,maxHandles = 1000000,maxDurationMs = 10000,maxTimeouts = 4;
    std::uint64_t processCreationTime = 0;
    std::function<bool()> cancelled;
};
FileHolderScanResult ScanFileHolders(const std::wstring& targetPath, bool includeSubPaths,const FileHolderScanOptions& options = {});

// ResolveWin32PathToNtPath maps a drive-letter path onto its object-manager
// form. Input is a Win32 path; processing consults QueryDosDeviceW; output is
// the NT path, or the input unchanged when it already looks like one.
std::wstring ResolveWin32PathToNtPath(const std::wstring& win32Path);

// ResolveNtPathToWin32Path is the reverse mapping used for display. Input is an
// NT device path; output is the drive-letter form, or the input unchanged when
// no mounted volume matches.
std::wstring ResolveNtPathToWin32Path(const std::wstring& ntPath);

} // namespace ks::r3::system_tools
