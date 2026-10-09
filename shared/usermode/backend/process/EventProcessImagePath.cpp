#include "EventProcessImagePath.h"
#include <vector>
namespace ks::r3::process {
std::wstring QueryEventProcessImagePath(std::uint32_t processId) {
    if (processId == 0) {
        return {};
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(processId));
    if (process == nullptr) {
        return {};
    }

    std::wstring path;
    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD length = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(process, 0, buffer.data(), &length) && length > 0) {
        path.assign(buffer.data(), buffer.data() + length);
    }
    ::CloseHandle(process);
    return path;
}
}
