#pragma once
#include "ThreadActions.h"
#include "ProcessDetailTypes.h"
#include "ModuleActionSupport.h"
#include <memory>
#include <vector>
namespace ks::r3::process_detail {
ProcessDetailActionResult UnloadDetailModule(std::uintptr_t moduleBase, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns, const std::shared_ptr<const std::vector<ProcessModuleInfo>>& moduleSnapshot);
ProcessDetailActionResult SuspendModuleThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns);
ProcessDetailActionResult ResumeModuleThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns);
ProcessDetailActionResult TerminateModuleThread(DWORD threadId, ULONGLONG expectedThreadCreationTime100ns, DWORD targetProcessId, ULONGLONG expectedProcessCreationTime100ns);
}
