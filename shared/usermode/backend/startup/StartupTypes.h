#pragma once
#include "../Win32.h"
#include <string>
#include <vector>
namespace ks::r3::startup {
enum class StartupEntryKind {
    RegistryRun,
    RegistryRunOnce,
    StartupFolder,
    Service,
    // DriverService represents a kernel or file-system driver reported by SCM.
    // These rows are investigation-only: StartupActions deliberately rejects all
    // mutation and Shell-open requests for this kind.
    DriverService,
    // RegistryOnlyService represents a Services-registry record that this SCM
    // enumeration did not return. It is an observation-only source mismatch,
    // not a hidden-service verdict, and all StartupActions reject it.
    RegistryOnlyService,
    ScheduledTaskFacade
};
enum class StartupEntryScope {
    CurrentUser,
    LocalMachine,
    AllUsers,
    Unknown
};
enum class StartupEntryState {
    Active,
    Disabled,
    Manual,
    Unknown
};
struct StartupProperty {
    std::wstring name;
    std::wstring value;
};
struct StartupEntry {
    StartupEntryKind kind = StartupEntryKind::RegistryRun;
    StartupEntryScope scope = StartupEntryScope::Unknown;
    StartupEntryState state = StartupEntryState::Unknown;
    std::wstring name;
    std::wstring command;
    std::wstring location;
    std::wstring description;
    std::wstring publisher;
    HKEY registryRoot = nullptr;
    DWORD registryView = 0;
    std::wstring registrySubKey;
    std::wstring registryValueName;
    std::wstring disabledRegistrySubKey;
    std::wstring filePath;
    std::wstring disabledFilePath;
    std::wstring serviceName;
    DWORD serviceStartType = 0;
    std::wstring taskPath;
    std::vector<StartupProperty> properties;
};
struct StartupEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<StartupEntry> entries;
};
}
