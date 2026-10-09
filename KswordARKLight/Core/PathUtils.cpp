#include "../../shared/usermode/backend/system/ModulePath.h"
#include "PathUtils.h"

#include "Win32Lean.h"
#include <vector>

namespace Ksword::Core {



std::wstring ModuleDirectory() {
    const std::wstring path = ModulePath();
    const std::size_t pos = path.find_last_of(L"\\/");
    return pos == std::wstring::npos ? std::wstring() : path.substr(0, pos);
}

std::wstring JoinPath(const std::wstring& base, const std::wstring& child) {
    if (base.empty()) {
        return child;
    }
    if (child.empty()) {
        return base;
    }
    const wchar_t last = base.back();
    if (last == L'\\' || last == L'/') {
        return base + child;
    }
    return base + L"\\" + child;
}

bool FileExists(const std::wstring& path) {
    const DWORD attrs = ::GetFileAttributesW(path.c_str());
    return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

} // namespace Ksword::Core
