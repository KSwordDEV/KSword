#pragma once
#include "RegistryDock/RegistryWorkbenchAccess.h"
#include "registry_workbench_mock.h"
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>
// Registry protocol constants are included by the builder from their real source.
namespace ksword::ark
{
    struct IoResult { bool ok=false; unsigned long win32Error=0; long ntStatus=0; std::string message; unsigned long bytesReturned=0; };
    struct RegistryReadResult { IoResult io; std::uint32_t version=0,status=0,valueType=0,dataBytes=0,requiredBytes=0; long lastStatus=0; std::vector<std::uint8_t> data; };
    struct RegistrySubKeyEntry { std::wstring name; };
    struct RegistryValueEntry { std::wstring name; std::uint32_t valueType=0,dataBytes=0,requiredBytes=0; std::vector<std::uint8_t> data; };
    struct RegistryEnumResult { IoResult io; std::uint32_t version=0,status=0,subKeyCount=0,returnedSubKeyCount=0,valueCount=0,returnedValueCount=0; long lastStatus=0; std::vector<RegistrySubKeyEntry> subKeys; std::vector<RegistryValueEntry> values; };
    struct RegistryOperationResult { IoResult io; std::uint32_t version=0,status=0; long lastStatus=0; };
    class DriverHandle { public: bool isValid() const noexcept { return registry_ui::driverEnabled.load(); } };
    class DriverClient {
    public:
        DriverHandle open(unsigned long = GENERIC_READ|GENERIC_WRITE) const { return {}; }
        RegistryEnumResult enumerateRegistryKey(const std::wstring& path, unsigned long flags) const;
        RegistryReadResult readRegistryValue(const std::wstring&,const std::wstring&,unsigned long) const { return {}; }
        RegistryOperationResult deleteRegistryValue(const std::wstring&,const std::wstring&) const { return {}; }
        RegistryOperationResult deleteRegistryKey(const std::wstring&) const { return {}; }
        RegistryOperationResult renameRegistryKey(const std::wstring&,const std::wstring&) const
        {
            ++registry_ui::r0KeyRenames;
            return {};
        }
    };
}
