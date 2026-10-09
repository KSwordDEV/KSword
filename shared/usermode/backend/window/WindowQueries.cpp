#include "WindowQueries.h"
#include <algorithm>
#include <cwchar>
#include <iomanip>
#include <sstream>
#include <unordered_map>
namespace ks::r3::window_tools {
std::wstring LeafName(const std::wstring& path, DWORD processId) {
    if (path.empty()) {
        return processId == 0 ? L"System Idle Process" : L"(无法读取)";
    }
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos || slash + 1 >= path.size()) {
        return path;
    }
    return path.substr(slash + 1);
}
TopLevelWindowInfo ReadWindowInfo(HWND hwnd) {
    TopLevelWindowInfo info;
    if (!::IsWindow(hwnd)) {
        return info;
    }

    info.hwnd = hwnd;
    info.threadId = ::GetWindowThreadProcessId(hwnd, &info.processId);
    info.style = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_STYLE));
    info.exStyle = static_cast<DWORD>(::GetWindowLongPtrW(hwnd, GWL_EXSTYLE));
    info.visible = ::IsWindowVisible(hwnd) != FALSE;
    info.title = WindowTitleText(hwnd);
    info.className = WindowClassText(hwnd);
    info.processName = ProcessNameFromId(info.processId);

    // GetWindowDisplayAffinity is a pure query and works across process
    // boundaries, so it belongs in the worker pass with the rest of the
    // read-only data. Its mutating counterpart does not; see the capture tab.
    DWORD affinity = 0;
    if (::GetWindowDisplayAffinity(hwnd, &affinity)) {
        info.displayAffinity = affinity;
        info.displayAffinityKnown = true;
    }
    return info;
}
BOOL CALLBACK EnumTopLevelThunk(HWND hwnd, LPARAM lParam) {
    auto* rows = reinterpret_cast<std::vector<TopLevelWindowInfo>*>(lParam);
    if (!rows) {
        return FALSE;
    }
    TopLevelWindowInfo info = ReadWindowInfo(hwnd);
    if (info.hwnd) {
        rows->push_back(std::move(info));
    }
    return TRUE;
}
std::vector<TopLevelWindowInfo> EnumerateTopLevelWindowInfo() {
    std::vector<TopLevelWindowInfo> rows;
    rows.reserve(256);
    ::EnumWindows(EnumTopLevelThunk, reinterpret_cast<LPARAM>(&rows));
    return rows;
}
std::wstring HwndText(HWND hwnd) {
    return HexText(reinterpret_cast<std::uint64_t>(hwnd), 8);
}
std::wstring HexText(const std::uint64_t value, const int digits) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(digits) << std::setfill(L'0') << value;
    return stream.str();
}
std::wstring WindowTitleText(HWND hwnd) {
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
std::wstring WindowClassText(HWND hwnd) {
    wchar_t buffer[256]{};
    const int copied = ::GetClassNameW(hwnd, buffer, static_cast<int>(sizeof(buffer) / sizeof(buffer[0])));
    if (copied <= 0) {
        return {};
    }
    return std::wstring(buffer, buffer + copied);
}
std::wstring ProcessNameFromId(const DWORD processId) {
    if (processId == 0) {
        return L"System Idle Process";
    }
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return L"(无法读取)";
    }
    std::wstring path;
    std::vector<wchar_t> buffer(1024, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(process, 0, buffer.data(), &size) && size > 0) {
        path.assign(buffer.data(), buffer.data() + size);
    }
    ::CloseHandle(process);
    return LeafName(path, processId);
}
std::wstring DisplayAffinityText(const DWORD affinity, const bool known) {
    if (!known) {
        return L"(查询失败)";
    }
    switch (affinity) {
    case WDA_NONE:
        return L"WDA_NONE（无保护，可被截屏与录制）";
    case WDA_MONITOR:
        return L"WDA_MONITOR（捕获结果为黑块）";
    case WDA_EXCLUDEFROMCAPTURE:
        return L"WDA_EXCLUDEFROMCAPTURE（完全排除出捕获）";
    default:
        return L"未知值 " + HexText(affinity, 8);
    }
}
}
