#include "ModulePath.h"
#include <vector>
namespace ks::r3::common {
std::wstring ModulePath() {
    std::vector<wchar_t> buffer(1024, L'\0');
    while (buffer.size() < 32768) {
        const DWORD written = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
        if (written == 0) {
            return {};
        }
        if (written < buffer.size()) {
            return std::wstring(buffer.data(), written);
        }
        buffer.resize(buffer.size() * 2, L'\0');
    }
    return {};
}
}
