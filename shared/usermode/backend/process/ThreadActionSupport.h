#pragma once
#include "../Common.h"
#include <string>
namespace ks::r3::process_detail::thread_actions {
std::wstring Win32ErrorText(const wchar_t* operation, DWORD error);
std::wstring DecimalText(std::uint64_t value);
std::wstring Utf8ToWide(const std::string& text);
}
