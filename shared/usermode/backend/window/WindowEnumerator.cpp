#include "WindowEnumerator.h"

#include "../Common.h"

#include <algorithm>
#include <cwchar>
#include <sstream>
#include <utility>
#include <vector>
#include <chrono>
#include <new>

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
std::wstring QueryWindowTextSafe(HWND hwnd,WindowFieldEvidence* output = nullptr) {
    WindowFieldEvidence local;auto& e = output ? *output : local;e = {};::SetLastError(ERROR_SUCCESS);
    const int length = ::GetWindowTextLengthW(hwnd);e.error = ::GetLastError();
    if (length<=0) {e.available = length == 0 && e.error == ERROR_SUCCESS;e.empty = e.available;return {};}
    const int capacity = (std::min)(length,32767)+1;e.truncated = length>32767;
    std::vector<wchar_t> buffer(static_cast<std::size_t>(capacity),L'\0');::SetLastError(ERROR_SUCCESS);
    const int copied = ::GetWindowTextW(hwnd,buffer.data(),capacity);e.error = ::GetLastError();
    if (copied<=0) {
        if (!e.error) {::SetLastError(ERROR_SUCCESS);const auto currentLength = ::GetWindowTextLengthW(hwnd);e.error = ::GetLastError();e.available = currentLength == 0 && !e.error;e.empty = e.available;}
        return {};
    }
    e.available = true;e.error = ERROR_SUCCESS;
    if (::GetWindowTextLengthW(hwnd)>=capacity) e.truncated = true;
    return std::wstring(buffer.data(),buffer.data()+copied);
}
std::wstring QueryClassNameSafe(HWND hwnd,WindowFieldEvidence* output = nullptr) {
    WindowFieldEvidence local;auto& e = output ? *output : local;e = {};std::vector<wchar_t> buffer(512,L'\0');::SetLastError(ERROR_SUCCESS);
    const int copied = ::GetClassNameW(hwnd,buffer.data(),static_cast<int>(buffer.size()));
    if (copied<=0) {e.error = ::GetLastError();return {};}
    e.available = true;e.truncated = copied>=static_cast<int>(buffer.size())-1;return std::wstring(buffer.data(),buffer.data()+copied);
}
std::wstring QueryProcessImagePath(DWORD processId,WindowFieldEvidence* pathEvidence = nullptr,WindowFieldEvidence* identityEvidence = nullptr,std::uint64_t* creationTime = nullptr) {
    WindowFieldEvidence pathLocal,identityLocal;auto& pathState = pathEvidence ? *pathEvidence : pathLocal;auto& identity = identityEvidence ? *identityEvidence : identityLocal;
    pathState = {};identity = {};if (creationTime) *creationTime = 0;
    ks::r3::common::UniqueHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,processId));
    if (!process.valid()) {pathState.error = identity.error = ::GetLastError();return {};}
    FILETIME created{},exited{},kernel{},user{};
    if (::GetProcessTimes(process.get(),&created,&exited,&kernel,&user)) {
        identity.available = true;if (creationTime) *creationTime = static_cast<std::uint64_t>(created.dwHighDateTime)<<32 | created.dwLowDateTime;
    } else identity.error = ::GetLastError();
    std::vector<wchar_t> buffer(32768,L'\0');DWORD size = static_cast<DWORD>(buffer.size());
    if (!::QueryFullProcessImageNameW(process.get(),0,buffer.data(),&size)) {pathState.error = ::GetLastError();return {};}
    if (!size || size>buffer.size()) {pathState.error = ERROR_INVALID_DATA;return {};}
    pathState.available = true;return std::wstring(buffer.data(),buffer.data()+size);
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
    WindowSnapshotRow row;if (!::IsWindow(hwnd)) {row.stale = true;return row;}
    row.threadId = ::GetWindowThreadProcessId(hwnd,&row.processId);
    if (!row.threadId || !row.processId) {row.stale = true;return row;}
    row.hwnd = hwnd;row.evidence[L"owner"].available = true;
    WINDOWINFO info{};info.cbSize = sizeof(info);
    if (::GetWindowInfo(hwnd,&info)) {
        row.style = info.dwStyle;row.exStyle = info.dwExStyle;row.windowRect = info.rcWindow;row.clientRect = info.rcClient;
        for (const auto* name:{L"windowInfo",L"style",L"exStyle",L"windowRect",L"clientRect"}) row.evidence[name].available = true;
    } else {
        row.evidence[L"windowInfo"].error = ::GetLastError();row.clientRectInScreenCoordinates = false;
        auto& window = row.evidence[L"windowRect"];window.available = ::GetWindowRect(hwnd,&row.windowRect) != FALSE;if (!window.available) window.error = ::GetLastError();
        auto& client = row.evidence[L"clientRect"];client.available = ::GetClientRect(hwnd,&row.clientRect) != FALSE;if (!client.available) client.error = ::GetLastError();
        for (const auto& pair:{std::pair{GWL_STYLE,&row.style},std::pair{GWL_EXSTYLE,&row.exStyle}}) {
            ::SetLastError(ERROR_SUCCESS);const auto value = ::GetWindowLongPtrW(hwnd,pair.first);const auto error = ::GetLastError();
            auto& e = row.evidence[pair.first == GWL_STYLE ? L"style" : L"exStyle"];e.available = value != 0 || error == ERROR_SUCCESS;e.error = e.available ? ERROR_SUCCESS : error;*pair.second = static_cast<DWORD>(value);
        }
    }
    row.visible = ::IsWindowVisible(hwnd) != FALSE;row.enabled = ::IsWindowEnabled(hwnd) != FALSE;
    row.minimized = ::IsIconic(hwnd) != FALSE;row.maximized = ::IsZoomed(hwnd) != FALSE;row.unicode = ::IsWindowUnicode(hwnd) != FALSE;
    row.evidence[L"state"].available = true;
    row.title = QueryWindowTextSafe(hwnd,&row.evidence[L"title"]);row.className = QueryClassNameSafe(hwnd,&row.evidence[L"class"]);
    row.processImagePath = QueryProcessImagePath(row.processId,&row.evidence[L"processImagePath"],&row.evidence[L"processIdentity"],&row.processCreationTime);
    row.processName = LeafName(row.processImagePath,row.processId);
    auto& threadState = row.evidence[L"threadIdentity"];
    ks::r3::common::UniqueHandle thread(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION,FALSE,row.threadId));
    if (!thread.valid()) threadState.error = ::GetLastError();
    else {
        const auto owner = ::GetProcessIdOfThread(thread.get());FILETIME created{},exited{},kernel{},user{};
        if (owner != row.processId) threadState.error = owner ? ERROR_INVALID_PARAMETER : ::GetLastError();
        else if (!::GetThreadTimes(thread.get(),&created,&exited,&kernel,&user)) threadState.error = ::GetLastError();
        else {threadState.available = true;row.threadCreationTime = static_cast<std::uint64_t>(created.dwHighDateTime)<<32 | created.dwLowDateTime;}
    }
    DWORD currentPid = 0;const auto currentTid = ::GetWindowThreadProcessId(hwnd,&currentPid);
    if (!::IsWindow(hwnd) || currentPid != row.processId || currentTid != row.threadId) {row.stale = true;row.hwnd = nullptr;}
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
struct EnumContext {WindowEnumerationResult* result;std::chrono::steady_clock::time_point started;};
BOOL CALLBACK EnumWindowsThunk(HWND hwnd,LPARAM lParam) {
    auto* context = reinterpret_cast<EnumContext*>(lParam);if (!context || !context->result) return FALSE;
    auto& result = *context->result;
    if (result.examinedCount>=100000 || std::chrono::steady_clock::now()-context->started>std::chrono::seconds(8)) {result.limited = true;result.win32Error = ERROR_MORE_DATA;::SetLastError(ERROR_MORE_DATA);return FALSE;}
    ++result.examinedCount;
    try {
        WindowSnapshotRow row = ReadWindowSnapshot(hwnd);
        if (!row.hwnd) ++result.skippedCount;
        else if (IsDesktopManagementWindow(row)) ++result.shellFilteredCount;
        else result.rows.push_back(std::move(row));
    } catch (const std::bad_alloc&) {result.win32Error = ERROR_NOT_ENOUGH_MEMORY;::SetLastError(ERROR_NOT_ENOUGH_MEMORY);return FALSE;}
    return TRUE;
}

} // namespace

WindowEnumerationResult EnumerateTopLevelWindows() {
    WindowEnumerationResult result;
    EnumContext context{&result,std::chrono::steady_clock::now()};::SetLastError(ERROR_SUCCESS);
    if (!::EnumWindows(EnumWindowsThunk,reinterpret_cast<LPARAM>(&context))) {
        if (!result.win32Error) result.win32Error = ::GetLastError();
        result.success = false;
        result.diagnosticText = L"EnumWindows failed: " + ks::r3::common::LastErrorMessage();
        return result;
    }
    result.complete = true;result.success = true;
    result.diagnosticText = L"OK";
    return result;
}

WindowDetail QueryWindowDetails(HWND hwnd) {
    WindowDetail detail;
    detail.hwnd = hwnd;
    if (!::IsWindow(hwnd)) {
        detail.win32Error = ERROR_INVALID_WINDOW_HANDLE;return detail;
    }

    WindowSnapshotRow row = ReadWindowSnapshot(hwnd);
    if (!row.hwnd) {
        detail.win32Error = ERROR_INVALID_WINDOW_HANDLE;return detail;
    }

    detail.row = row;detail.found = true;
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
