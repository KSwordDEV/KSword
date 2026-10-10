#pragma once
#include "../Win32.h"
#include <cfgmgr32.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <map>
namespace ks::r3::window {
struct WindowFieldEvidence {
    bool available = false,empty = false,truncated = false;
    DWORD error = ERROR_SUCCESS;
};
enum class WindowSortMode {
    StackingOrder,
    ProcessOrder
};
struct WindowSnapshotRow {
    HWND hwnd = nullptr;
    DWORD processId = 0;
    DWORD threadId = 0;
    DWORD style = 0;
    DWORD exStyle = 0;
    RECT windowRect{};
    RECT clientRect{};
    bool visible = false;
    bool enabled = false;
    bool minimized = false;
    bool maximized = false;
    bool unicode = false;
    std::wstring title;
    std::wstring className;
    std::wstring processImagePath;
    std::wstring processName;
    std::map<std::wstring,WindowFieldEvidence> evidence;
    std::uint64_t processCreationTime = 0,threadCreationTime = 0;
    bool clientRectInScreenCoordinates = true,stale = false;
};
struct WindowProperty {
    std::wstring name;
    std::wstring value;
};
struct WindowDetail {
    bool found = false;
    HWND hwnd = nullptr;
    std::wstring title;
    std::vector<WindowProperty> properties;
    WindowSnapshotRow row;
    DWORD win32Error = ERROR_SUCCESS;
};
struct WindowEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<WindowSnapshotRow> rows;
    bool complete = false,limited = false;
    DWORD win32Error = ERROR_SUCCESS,examinedCount = 0,skippedCount = 0,shellFilteredCount = 0;
};
std::wstring WindowStateText(const WindowSnapshotRow& row);
std::wstring HwndToText(HWND hwnd);
std::wstring RectToText(const RECT& rect);
}
