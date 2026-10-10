#pragma once
#include "CommandRegistry.h"
#include "../shared/usermode/backend/process/DetailActionTypes.h"
namespace ks::cli {
using ThreadAction = std::function<ks::r3::process_detail::ProcessDetailActionResult(DWORD,std::uint64_t,DWORD,std::uint64_t)>;
Result executeThreadAction(const Args& args,const std::wstring& verb,const ThreadAction& callback,DWORD terminateExitCode);
}
