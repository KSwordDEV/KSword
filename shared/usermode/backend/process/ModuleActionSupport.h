#pragma once
#include "ThreadActionSupport.h"
#include <cstdint>
namespace ks::r3::process_detail::module_actions {
std::wstring BaseNameFromPath(const std::wstring& path);
std::wstring LastErrorText(const wchar_t* operation, DWORD error);
}
