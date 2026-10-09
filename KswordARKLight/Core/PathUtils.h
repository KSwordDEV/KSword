#pragma once
#include "../../shared/usermode/backend/system/ModulePath.h"

#include <string>

namespace Ksword::Core {

// ModulePath returns the current executable path. There is no input; processing
// expands a Win32 path buffer; output is empty only when GetModuleFileNameW fails.
using ks::r3::common::ModulePath;

// ModuleDirectory returns the directory containing this executable. There is no
// input; processing trims ModulePath at the final separator; output is empty on
// failure.
std::wstring ModuleDirectory();

// JoinPath joins two Windows path fragments. Inputs are a base and child path;
// processing inserts one slash when needed; output is a combined path string.
std::wstring JoinPath(const std::wstring& base, const std::wstring& child);

// FileExists checks for a normal filesystem file. Input is a path; processing
// queries file attributes; output is true only for existing non-directory files.
bool FileExists(const std::wstring& path);

} // namespace Ksword::Core
