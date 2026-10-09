#pragma once
#include "RegistryModel.h"
namespace ks::r3::registry {
RegistrySnapshot EnumerateRegistryKey(const std::wstring& path);
std::vector<std::wstring> EnumerateRegistrySubKeyNames(const std::wstring& path, std::wstring* statusTextOut);
RegistryOperationResult ReadRegistryValue(const std::wstring& path, const std::wstring& valueName);
}
