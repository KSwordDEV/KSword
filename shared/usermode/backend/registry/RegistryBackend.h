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
RegistryOperationResult WriteRegistryValue(const std::wstring& path, const std::wstring& valueName, const std::uint32_t type, const std::vector<std::uint8_t>& data);
RegistryOperationResult DeleteRegistryValue(const std::wstring& path, const std::wstring& valueName);
RegistryOperationResult CreateRegistryKey(const std::wstring& path);
RegistryOperationResult DeleteRegistryKey(const std::wstring& path);
RegistryOperationResult RenameRegistryValue(const std::wstring& path, const std::wstring& oldName, const std::wstring& newName);
RegistryOperationResult RenameRegistryKey(const std::wstring& path, const std::wstring& newName);
}
