#include "WindowEnumerator.h"

#include "../Common.h"

#include <algorithm>
#include <cwchar>
#include <sstream>
#include <utility>
#include <vector>

namespace ks::r3::window {
namespace {

// AddProperty appends a non-empty detail row. Inputs are detail, label and value;
// processing keeps the details pane readable; no value is returned.
void AddProperty(WindowDetail& detail, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        detail.properties.push_back({ name, value });
    }
}

// DwordHex formats a DWORD as uppercase hexadecimal text. Input is a raw Win32
// value; output is a diagnostics-friendly string.
std::wstring DwordHex(DWORD value) {
    std::wstringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// QueryWindowTextSafe reads the title text for one HWND. Input is a live HWND;
// processing uses GetWindowTextLengthW/GetWindowTextW; output is empty for
// untitled, inaccessible, or disappearing windows.
std::wstring QueryWindowTextSafe(HWND hwnd) {
    const int length = ::GetWindowTextLengthW(hwnd);
    if (length <= 0) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(length) + 1, L'\0');
    const int copied = ::GetWindowTextW(hwnd, buffer.data(), static_cast<int>(buffer.size()));
    if (copied <= 0) {
        return {};
    }
    return std::wstring(buffer.data(), buffer.data() + copied);
}

// QueryClassNameSafe reads the Win32 class name for one HWND. Input is a live
// HWND; processing uses GetClassNameW; output is empty when the call fails.
std::wstring QueryClassNameSafe(HWND hwnd) {
    std::vector<wchar_t> buffer(512, L'\0');
    const int copied = ::GetClassNameW(hwnd, buffer.data(), static_cast<int>(buffer.size()));
    if (copied <= 0) {
        return {};
    }
    return std::wstring(buffer.data(), buffer.data() + copied);
}

// QueryProcessImagePath reads a process image path by PID. Input is a process ID
// obtained from GetWindowThreadProcessId; processing opens with query-only access;
// output is empty when access is denied or the process exits.
std::wstring QueryProcessImagePath(DWORD processId) {
    if (processId == 0) {
        return {};
    }
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return {};
    }
    std::wstring path;
    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(process, 0, buffer.data(), &size) && size > 0) {
        path.assign(buffer.data(), buffer.data() + size);
    }
    ::CloseHandle(process);
    return path;
}

// LeafName extracts a display process name from a full image path. Input may be
// empty, a native process name, or a full Win32 path; output is the last path
// component or a stable fallback for inaccessible processes.
std::wstring LeafName(const std::wstring& path, DWORD processId) {
    if (path.empty()) {
        return processId == 0 ? L"System Idle Process" : L"(unknown process)";
    }
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos || slash + 1 >= path.size()) {
        return path;
    }
    return path.substr(slash + 1);
}

// ReadWindowSnapshot converts one HWND into a WindowSnapshotRow. Input is a live
// top-level HWND; processing calls GetWindowInfo/GetClassName/GetWindowText and
// process lookup helpers; output has hwnd=nullptr when the window disappeared.
WindowSnapshotRow ReadWindowSnapshot(HWND hwnd) {
    WindowSnapshotRow row;
    if (!::IsWindow(hwnd)) {
        return row;
    }

    WINDOWINFO info{};
    info.cbSize = sizeof(info);
    if (::GetWindowInfo(hwnd, &info)) {
        row.style = info.dwStyle;
        row.exStyle = info.dwExStyle;
        row.windowRect = info.rcWindow;
        row.clientRect = info.rcClient;
    } else {
        ::GetWindowRect(hwnd, &row.windowRect);
        ::GetClientRect(hwnd, &row.clientRect);
        row.style = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_STYLE));
        row.exStyle = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
    }

    row.hwnd = hwnd;
    row.threadId = ::GetWindowThreadProcessId(hwnd, &row.processId);
    row.visible = ::IsWindowVisible(hwnd) != FALSE;
    row.enabled = ::IsWindowEnabled(hwnd) != FALSE;
    row.minimized = ::IsIconic(hwnd) != FALSE;
    row.maximized = ::IsZoomed(hwnd) != FALSE;
    row.unicode = ::IsWindowUnicode(hwnd) != FALSE;
    row.title = QueryWindowTextSafe(hwnd);
    row.className = QueryClassNameSafe(hwnd);
    row.processImagePath = QueryProcessImagePath(row.processId);
    row.processName = LeafName(row.processImagePath, row.processId);
    return row;
}

// IsDesktopManagementWindow filters shell desktop infrastructure windows from
// the retained window list. Input is a snapshot row; output is true only for
// desktop/shell classes that belong to desktop management rather than normal app
// windows. This intentionally does not enumerate or manipulate desktops.
bool IsDesktopManagementWindow(const WindowSnapshotRow& row) {
    return row.className == L"Progman" || row.className == L"WorkerW" || row.className == L"Shell_TrayWnd";
}

// EnumWindowsThunk receives HWND values from EnumWindows. Input is the callback
// pair; processing appends retained window rows to the vector; output TRUE keeps
// enumeration running.
BOOL CALLBACK EnumWindowsThunk(HWND hwnd, LPARAM lParam) {
    auto* rows = reinterpret_cast<std::vector<WindowSnapshotRow>*>(lParam);
    if (!rows) {
        return FALSE;
    }
    WindowSnapshotRow row = ReadWindowSnapshot(hwnd);
    if (row.hwnd && !IsDesktopManagementWindow(row)) {
        rows->push_back(std::move(row));
    }
    return TRUE;
}

} // namespace

WindowEnumerationResult EnumerateTopLevelWindows() {
    WindowEnumerationResult result;
    if (!::EnumWindows(EnumWindowsThunk, reinterpret_cast<LPARAM>(&result.rows))) {
        result.success = false;
        result.diagnosticText = L"EnumWindows failed: " + ks::r3::common::LastErrorMessage();
        return result;
    }
    result.success = true;
    result.diagnosticText = L"OK";
    return result;
}

WindowDetail QueryWindowDetails(HWND hwnd) {
    WindowDetail detail;
    detail.hwnd = hwnd;
    if (!::IsWindow(hwnd)) {
        return detail;
    }

    WindowSnapshotRow row = ReadWindowSnapshot(hwnd);
    if (!row.hwnd) {
        return detail;
    }

    detail.found = true;
    detail.title = row.title.empty() ? HwndToText(hwnd) : row.title;
    AddProperty(detail, L"HWND", HwndToText(row.hwnd));
    AddProperty(detail, L"Title", row.title.empty() ? L"(untitled)" : row.title);
    AddProperty(detail, L"Class", row.className);
    AddProperty(detail, L"Process ID", std::to_wstring(row.processId));
    AddProperty(detail, L"Process name", row.processName);
    AddProperty(detail, L"Thread ID", std::to_wstring(row.threadId));
    AddProperty(detail, L"State", WindowStateText(row));
    AddProperty(detail, L"Window rect", RectToText(row.windowRect));
    AddProperty(detail, L"Client rect", RectToText(row.clientRect));
    AddProperty(detail, L"Style", DwordHex(row.style));
    AddProperty(detail, L"Extended style", DwordHex(row.exStyle));
    AddProperty(detail, L"Unicode", row.unicode ? L"Yes" : L"No");
    AddProperty(detail, L"Process image", row.processImagePath);
    return detail;
}

} // namespace ks::r3::window
