#include "ProcessEvidenceName.h"

namespace ks::r3::process {
std::wstring ProcessDisplayName(const std::uint32_t processId) {
    if (processId == 0) {
        return L"Idle/System";
    }
    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return L"PID " + std::to_wstring(processId);
    }
    std::wstring path(MAX_PATH * 4, L'\0');
    DWORD length = static_cast<DWORD>(path.size());
    std::wstring name = L"PID " + std::to_wstring(processId);
    if (::QueryFullProcessImageNameW(process, 0, path.data(), &length) && length > 0) {
        path.resize(length);
        const std::size_t slash = path.find_last_of(L"\\/");
        name = slash == std::wstring::npos ? path : path.substr(slash + 1);
    }
    ::CloseHandle(process);
    return name;
}
}
