#pragma once

#include "../../Core/Win32Lean.h"

#include <string>
#include <vector>

namespace Ksword::Features::File {

// PathNavigator owns only lightweight path state for the file feature. Inputs
// are user-entered or UI-selected Windows paths; processing normalizes common
// directory forms and maintains back/forward history; return values describe
// the path that the FileView should enumerate next.
class PathNavigator final {
public:
    PathNavigator();

    // currentPath returns the directory currently selected by the navigator.
    // There is no input; output is empty when the virtual drive-root view should
    // be shown instead of a real directory.
    const std::wstring& currentPath() const;

    // navigateTo records a new target path. Input is a raw path from the UI or a
    // file entry; processing normalizes separators and trims redundant quotes;
    // output is the normalized path that should be enumerated.
    std::wstring navigateTo(const std::wstring& path);

    // navigateUp moves to the parent directory. There is no input; processing
    // keeps drive roots at the virtual drive list; output is the resulting path.
    std::wstring navigateUp();

    // navigateBack and navigateForward replay navigation history. There is no
    // input; output is true only when the current path changed.
    bool navigateBack();
    bool navigateForward();

    // canNavigateBack and canNavigateForward expose history availability. There
    // is no input; output controls toolbar button enabled state.
    bool canNavigateBack() const;
    bool canNavigateForward() const;

    // normalizeDirectoryPath accepts a user supplied path and returns a stable
    // directory string. It trims quotes, expands environment strings, converts
    // slashes, and preserves drive roots such as C:\.
    static std::wstring normalizeDirectoryPath(const std::wstring& path);

    // normalizeKnownDirectoryPath accepts a directory identity already supplied
    // by a Lite snapshot. It performs no filesystem I/O and accepts only an
    // explicit DOS or UNC path; device, extended, relative and command-line
    // text return empty so callers cannot claim a precise file-browser route.
    static std::wstring normalizeKnownDirectoryPath(const std::wstring& path);

    // parentDirectoryForKnownFilePath takes an already-known absolute DOS or
    // UNC file path and returns its syntactic parent directory without probing
    // the filesystem. It rejects the same ambiguous forms as
    // normalizeKnownDirectoryPath and returns empty when no file parent exists.
    static std::wstring parentDirectoryForKnownFilePath(const std::wstring& path);

    // parentPath returns the parent directory for a normalized path. Input is a
    // path string; processing handles drive roots and UNC roots; output is empty
    // when the virtual drive list should be displayed.
    static std::wstring parentPath(const std::wstring& path);

    // joinChildPath appends one child name to a directory. Inputs are the parent
    // path and leaf name; processing inserts one separator; output is full path.
    static std::wstring joinChildPath(const std::wstring& directory, const std::wstring& childName);

    // makeSearchPattern appends a wildcard suitable for FindFirstFileW. Input is
    // a directory; output is "<directory>\*" or "*" for the virtual root.
    static std::wstring makeSearchPattern(const std::wstring& directory);

    // isDriveRoot reports whether the path is a local drive root such as C:\.
    // Input is a path string; output is true for a normalized drive root.
    static bool isDriveRoot(const std::wstring& path);

private:
    void pushHistory(const std::wstring& path);

private:
    std::wstring currentPath_;
    std::vector<std::wstring> backStack_;
    std::vector<std::wstring> forwardStack_;
};

} // namespace Ksword::Features::File
