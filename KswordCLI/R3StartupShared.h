#pragma once
#include "CommandRegistry.h"
#include "../shared/usermode/backend/startup/StartupEnumerator.h"
namespace ks::cli::startup {
struct Identity {std::wstring sid;std::uint32_t win32Error = 0;};
Identity identity();
std::wstring id(const ks::r3::startup::StartupEntry& entry,const std::wstring& sid);
const wchar_t* kind(ks::r3::startup::StartupEntryKind value);
const wchar_t* state(ks::r3::startup::StartupEntryState value);
const wchar_t* scope(ks::r3::startup::StartupEntryScope value);
Json row(const ks::r3::startup::StartupEntry& entry,const std::wstring& sid);
Json errors(const ks::r3::startup::StartupEnumerationResult& snapshot);
}
