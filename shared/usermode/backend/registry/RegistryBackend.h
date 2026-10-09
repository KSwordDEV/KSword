#pragma once
#include "RegistryModel.h"
#include "RegistrySearchModel.h"
#include <atomic>
#include <memory>
namespace ks::r3::registry {
RegistrySnapshot EnumerateRegistryKey(const std::wstring& path);
std::vector<std::wstring> EnumerateRegistrySubKeyNames(const std::wstring& path, std::wstring* statusTextOut);
RegistryOperationResult ReadRegistryValue(const std::wstring& path, const std::wstring& valueName);
RegistrySearchSnapshot SearchRegistryWinApi(const RegistrySearchRequest& request, const std::shared_ptr<std::atomic_bool>& cancelToken);
}
