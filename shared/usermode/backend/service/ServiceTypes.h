#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::service {
struct ServiceProperty {
    std::wstring name;
    std::wstring value;
};
struct ServiceEntry {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring description;
    std::wstring binaryPath;
    std::wstring accountName;
    std::wstring loadOrderGroup;
    std::wstring dependencies;      // Multi-sz expanded into a readable list.
    std::uint32_t serviceType = 0;
    std::uint32_t currentState = 0;
    std::uint32_t startType = 0;
    std::uint32_t errorControl = 0;
    std::uint32_t processId = 0;
    std::uint32_t controlsAccepted = 0;
    std::uint32_t win32ExitCode = 0;
    std::uint32_t serviceSpecificExitCode = 0;
    std::uint32_t checkPoint = 0;
    std::uint32_t waitHint = 0;
    std::uint32_t serviceFlags = 0;
    std::uint32_t tagId = 0;
    bool delayedAutoStart = false;
    bool hasConfig = false;
    bool hasStatus = false;
    bool hasDescription = false;
    // Direct dependency names and +load-order-group entries stay separate so
    // a detail snapshot can expose the SCM's two dependency forms without
    // asking a view to reverse-parse display text.
    std::vector<std::wstring> dependencyServiceNames;
    std::vector<std::wstring> dependencyLoadOrderGroups;
    std::wstring riskText;          // Empty when nothing stood out.
    std::wstring diagnosticText;    // Why status or config could not be read.
};
struct ServiceEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<ServiceEntry> entries;
};
std::vector<ServiceProperty> ServicePropertiesForEntry(const ServiceEntry& entry);
std::wstring ServiceStateText(std::uint32_t currentState);
std::wstring ServiceStartTypeText(std::uint32_t startType, bool delayedAutoStart);
std::wstring ServiceTypeText(std::uint32_t serviceType);
bool ServiceIsTransitioning(const ServiceEntry& entry);
bool ServiceCanStart(const ServiceEntry& entry);
bool ServiceCanStop(const ServiceEntry& entry);
bool ServiceCanPause(const ServiceEntry& entry);
bool ServiceCanContinue(const ServiceEntry& entry);
}
