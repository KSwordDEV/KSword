#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::file {

bool EnablePrivilege(const wchar_t* privilegeName);
std::wstring TakeOwnershipPath(const std::wstring& path);
std::wstring QueryFileLockers(const std::wstring& path);
}
