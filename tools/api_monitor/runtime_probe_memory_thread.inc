#pragma once
#include "runtime_probe_support.h"
#include <enclaveapi.h>
#include <processtopologyapi.h>
#include <memoryapi.h>
#include <psapi.h>
#include <realtimeapiset.h>
#include <vector>
namespace apimon_probe {
inline void RunMemoryThreadCases() {
 constexpr auto kb=L"KernelBase.dll"; constexpr auto k32=L"Kernel32.dll";
 HANDLE process=GetCurrentProcess(), thread=GetCurrentThread();
 void* page=VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
 if(page) {
  Call<decltype(&::VirtualLock)>(700,kb,"VirtualLock",page,SIZE_T(4096));
  Call<decltype(&::VirtualUnlock)>(701,kb,"VirtualUnlock",page,SIZE_T(4096));
 } else { Skip(700,"owned_page_allocation_failed");Skip(701,"owned_page_allocation_failed"); }
 SIZE_T min=0,max=0; DWORD flags=0;
 auto got=Call<decltype(&::GetProcessWorkingSetSize)>(702,k32,"GetProcessWorkingSetSize",process,&min,&max);
 Call<decltype(&::GetProcessWorkingSetSizeEx)>(703,kb,"GetProcessWorkingSetSizeEx",process,&min,&max,&flags);
 if(got) Call<decltype(&::SetProcessWorkingSetSize)>(704,k32,"SetProcessWorkingSetSize",process,min,max); else Call<decltype(&::SetProcessWorkingSetSize)>(704,k32,"SetProcessWorkingSetSize",HANDLE(nullptr),SIZE_T(0),SIZE_T(0));
 if(got) Call<decltype(&::SetProcessWorkingSetSizeEx)>(705,kb,"SetProcessWorkingSetSizeEx",process,min,max,flags); else Call<decltype(&::SetProcessWorkingSetSizeEx)>(705,kb,"SetProcessWorkingSetSizeEx",HANDLE(nullptr),SIZE_T(0),SIZE_T(0),DWORD(0));
 HANDLE map=CreateFileMappingW(INVALID_HANDLE_VALUE,nullptr,PAGE_READWRITE,0,4096,nullptr);
 auto view=Call<decltype(&::MapViewOfFileFromApp)>(706,kb,"MapViewOfFileFromApp",map,ULONG(FILE_MAP_READ),ULONG64(0),SIZE_T(4096));
 if(view) { auto ok=Call<decltype(&::UnmapViewOfFileEx)>(707,kb,"UnmapViewOfFileEx",view,ULONG(0)); if(!ok) UnmapViewOfFile(view); }
 else Call<decltype(&::UnmapViewOfFileEx)>(707,kb,"UnmapViewOfFileEx",nullptr,ULONG(0));
 if(map) CloseHandle(map);
 auto app=Call<decltype(&::VirtualAllocFromApp)>(708,kb,"VirtualAllocFromApp",nullptr,SIZE_T(4096),ULONG(MEM_RESERVE|MEM_COMMIT),ULONG(PAGE_READWRITE));
 ULONG old=0; Call<decltype(&::VirtualProtectFromApp)>(709,kb,"VirtualProtectFromApp",app,SIZE_T(4096),ULONG(PAGE_READONLY),&old);
 if(app) VirtualFree(app,0,MEM_RELEASE);
 DWORD ee=0; SIZE_T written=0; unsigned char dummy=0;
 auto enclave=Call<decltype(&::CreateEnclave)>(710,kb,"CreateEnclave",HANDLE(nullptr),nullptr,SIZE_T(4096),SIZE_T(0),DWORD(0),&dummy,DWORD(0),&ee);
 Call<decltype(&::LoadEnclaveData)>(711,kb,"LoadEnclaveData",HANDLE(nullptr),nullptr,&dummy,SIZE_T(1),DWORD(PAGE_READWRITE),&dummy,DWORD(0),&written,&ee);
 Call<decltype(&::InitializeEnclave)>(712,kb,"InitializeEnclave",HANDLE(nullptr),nullptr,&dummy,DWORD(0),&ee);
 Call<decltype(&::DeleteEnclave)>(713,kb,"DeleteEnclave",enclave);
 int priority=GetThreadPriority(thread); if(priority==THREAD_PRIORITY_ERROR_RETURN) Call<decltype(&::SetThreadPriority)>(714,kb,"SetThreadPriority",HANDLE(nullptr),THREAD_PRIORITY_NORMAL); else Call<decltype(&::SetThreadPriority)>(714,kb,"SetThreadPriority",thread,priority);
 BOOL boost=FALSE; if(GetThreadPriorityBoost(thread,&boost)) Call<decltype(&::SetThreadPriorityBoost)>(715,kb,"SetThreadPriorityBoost",thread,boost); else Call<decltype(&::SetThreadPriorityBoost)>(715,kb,"SetThreadPriorityBoost",HANDLE(nullptr),FALSE);
 Call<decltype(&::GetThreadPriorityBoost)>(716,kb,"GetThreadPriorityBoost",thread,&boost);
 FILETIME a{},b{},c{},d{}; Call<decltype(&::GetThreadTimes)>(717,kb,"GetThreadTimes",thread,&a,&b,&c,&d);
 BOOL pending=FALSE; Call<decltype(&::GetThreadIOPendingFlag)>(718,kb,"GetThreadIOPendingFlag",thread,&pending);
 PROCESSOR_NUMBER ideal{},prev{}; BOOL idealOk=GetThreadIdealProcessorEx(thread,&ideal);
 Call<decltype(&::SetThreadIdealProcessorEx)>(719,kb,"SetThreadIdealProcessorEx",idealOk?thread:HANDLE(nullptr),&ideal,&prev);
 Call<decltype(&::GetThreadIdealProcessorEx)>(720,kb,"GetThreadIdealProcessorEx",thread,&ideal);
 GROUP_AFFINITY affinity{},previous{}; BOOL affinityOk=GetThreadGroupAffinity(thread,&affinity);
 Call<decltype(&::GetThreadGroupAffinity)>(721,kb,"GetThreadGroupAffinity",thread,&affinity);
 Call<decltype(&::SetThreadGroupAffinity)>(722,kb,"SetThreadGroupAffinity",affinityOk?thread:HANDLE(nullptr),&affinity,&previous);
 MEMORY_PRIORITY_INFORMATION info{};
 BOOL infoOk=Call<decltype(&::GetThreadInformation)>(723,kb,"GetThreadInformation",thread,ThreadMemoryPriority,&info,DWORD(sizeof(info)));
 Call<decltype(&::SetThreadInformation)>(724,kb,"SetThreadInformation",infoOk?thread:HANDLE(nullptr),ThreadMemoryPriority,&info,DWORD(sizeof(info)));
 ULONG ids[256]{},required=0;
 BOOL cpuOk=Call<decltype(&::GetThreadSelectedCpuSets)>(725,kb,"GetThreadSelectedCpuSets",thread,ids,ULONG(256),&required);
 Call<decltype(&::SetThreadSelectedCpuSets)>(726,kb,"SetThreadSelectedCpuSets",cpuOk?thread:HANDLE(nullptr),ids,cpuOk?required:ULONG(0));
 PWSTR description=nullptr; auto getDescription=reinterpret_cast<decltype(&::GetThreadDescription)>(GetProcAddress(GetModuleHandleW(kb),"GetThreadDescription")); auto hr=getDescription?getDescription(thread,&description):E_NOTIMPL;
 Call<decltype(&::SetThreadDescription)>(727,kb,"SetThreadDescription",SUCCEEDED(hr)?thread:HANDLE(nullptr),description?description:L"");
 PWSTR copy=nullptr; Call<decltype(&::GetThreadDescription)>(728,kb,"GetThreadDescription",thread,&copy); if(copy)LocalFree(copy);if(description)LocalFree(description);
 DWORD mode=GetThreadErrorMode(),oldMode=0; Call<decltype(&::SetThreadErrorMode)>(729,kb,"SetThreadErrorMode",mode,&oldMode);
 ULONG count=0,size=0; GetThreadPreferredUILanguages(MUI_LANGUAGE_NAME,&count,nullptr,&size); std::vector<wchar_t> langs(size?size:2);
 BOOL langOk=Call<decltype(&::GetThreadPreferredUILanguages)>(730,kb,"GetThreadPreferredUILanguages",DWORD(MUI_LANGUAGE_NAME),&count,langs.data(),&size);
 ULONG setCount=0; Call<decltype(&::SetThreadPreferredUILanguages)>(731,kb,"SetThreadPreferredUILanguages",langOk?DWORD(MUI_LANGUAGE_NAME):DWORD(0xffffffff),langOk?langs.data():L"",&setCount);

 // These calls only affect pages and handles owned by this fixture; changes to
 // process settings use the value just read, preserving the prior state.
 Call<decltype(&::OfferVirtualMemory)>(830,kb,"OfferVirtualMemory",page,SIZE_T(4096),VmOfferPriorityLow);
 Call<decltype(&::ReclaimVirtualMemory)>(831,kb,"ReclaimVirtualMemory",page,SIZE_T(4096));
 Call<decltype(&::DiscardVirtualMemory)>(832,kb,"DiscardVirtualMemory",page,SIZE_T(4096));
 WIN32_MEMORY_REGION_INFORMATION region{}; SIZE_T returned=0;
 Call<decltype(&::QueryVirtualMemoryInformation)>(833,kb,"QueryVirtualMemoryInformation",process,page,MemoryRegionInfo,&region,SIZE_T(sizeof(region)),&returned);
 PROCESS_MEMORY_COUNTERS counters{}; counters.cb=sizeof(counters);
 Call<decltype(&::K32GetProcessMemoryInfo)>(834,kb,"K32GetProcessMemoryInfo",process,&counters,DWORD(sizeof(counters)));
 PSAPI_WORKING_SET_INFORMATION ws{};
 Call<decltype(&::K32QueryWorkingSet)>(835,kb,"K32QueryWorkingSet",process,&ws,DWORD(sizeof(ws)));
 PSAPI_WORKING_SET_EX_INFORMATION wsEx{}; wsEx.VirtualAddress=page;
 Call<decltype(&::K32QueryWorkingSetEx)>(836,kb,"K32QueryWorkingSetEx",process,&wsEx,DWORD(sizeof(wsEx)));
 ULONG64 cycles=0;
 Call<decltype(&::QueryThreadCycleTime)>(837,kb,"QueryThreadCycleTime",thread,&cycles);
 Call<decltype(&::QueryProcessCycleTime)>(838,kb,"QueryProcessCycleTime",process,&cycles);
 DWORD countHandles=0; Call<decltype(&::GetProcessHandleCount)>(839,kb,"GetProcessHandleCount",process,&countHandles);
 IO_COUNTERS io{}; Call<decltype(&::GetProcessIoCounters)>(840,k32,"GetProcessIoCounters",process,&io);
 Call<decltype(&::GetProcessTimes)>(841,kb,"GetProcessTimes",process,&a,&b,&c,&d);
 BOOL processBoost=FALSE; auto processBoostOk=Call<decltype(&::GetProcessPriorityBoost)>(842,kb,"GetProcessPriorityBoost",process,&processBoost);
 Call<decltype(&::SetProcessPriorityBoost)>(843,kb,"SetProcessPriorityBoost",processBoostOk?process:HANDLE(nullptr),processBoost);
 DWORD_PTR processMask=0,systemMask=0; Call<decltype(&::GetProcessAffinityMask)>(844,k32,"GetProcessAffinityMask",process,&processMask,&systemMask);
 MEMORY_PRIORITY_INFORMATION processInfo{}; auto processInfoOk=Call<decltype(&::GetProcessInformation)>(845,kb,"GetProcessInformation",process,ProcessMemoryPriority,&processInfo,DWORD(sizeof(processInfo)));
 Call<decltype(&::SetProcessInformation)>(846,kb,"SetProcessInformation",processInfoOk?process:HANDLE(nullptr),ProcessMemoryPriority,&processInfo,DWORD(sizeof(processInfo)));
 PROCESS_MITIGATION_DEP_POLICY dep{}; Call<decltype(&::GetProcessMitigationPolicy)>(847,kb,"GetProcessMitigationPolicy",process,ProcessDEPPolicy,&dep,SIZE_T(sizeof(dep)));
 DWORD depFlags=0; BOOL permanent=FALSE; Call<decltype(&::GetProcessDEPPolicy)>(848,k32,"GetProcessDEPPolicy",process,&depFlags,&permanent);
 DWORD level=0,shutdownFlags=0; auto shutdownOk=Call<decltype(&::GetProcessShutdownParameters)>(849,kb,"GetProcessShutdownParameters",&level,&shutdownFlags);
 Call<decltype(&::SetProcessShutdownParameters)>(850,kb,"SetProcessShutdownParameters",shutdownOk?level:DWORD(0),shutdownOk?shutdownFlags:DWORD(0xffffffff));
 Call<decltype(&::GetProcessIdOfThread)>(851,kb,"GetProcessIdOfThread",thread);

 // Additional failure paths use invalid handles/flags only; they do not mutate state.
 Call<decltype(&::VirtualLock)>(700,kb,"VirtualLock",nullptr,SIZE_T(0));
 Call<decltype(&::VirtualUnlock)>(701,kb,"VirtualUnlock",nullptr,SIZE_T(0));
 Call<decltype(&::GetProcessWorkingSetSize)>(702,k32,"GetProcessWorkingSetSize",HANDLE(nullptr),&min,&max);
 Call<decltype(&::GetProcessWorkingSetSizeEx)>(703,kb,"GetProcessWorkingSetSizeEx",HANDLE(nullptr),&min,&max,&flags);
 Call<decltype(&::SetProcessWorkingSetSize)>(704,k32,"SetProcessWorkingSetSize",HANDLE(nullptr),SIZE_T(0),SIZE_T(0));
 Call<decltype(&::SetProcessWorkingSetSizeEx)>(705,kb,"SetProcessWorkingSetSizeEx",HANDLE(nullptr),SIZE_T(0),SIZE_T(0),DWORD(0));
 Call<decltype(&::MapViewOfFileFromApp)>(706,kb,"MapViewOfFileFromApp",nullptr,ULONG(FILE_MAP_READ),ULONG64(0),SIZE_T(4096));
 Call<decltype(&::UnmapViewOfFileEx)>(707,kb,"UnmapViewOfFileEx",nullptr,ULONG(0));
 Call<decltype(&::VirtualAllocFromApp)>(708,kb,"VirtualAllocFromApp",nullptr,SIZE_T(0),ULONG(MEM_COMMIT),ULONG(PAGE_READWRITE));
 Call<decltype(&::VirtualProtectFromApp)>(709,kb,"VirtualProtectFromApp",nullptr,SIZE_T(4096),ULONG(PAGE_READONLY),&old);
 Call<decltype(&::SetThreadPriority)>(714,kb,"SetThreadPriority",HANDLE(nullptr),THREAD_PRIORITY_NORMAL);
 Call<decltype(&::SetThreadPriorityBoost)>(715,kb,"SetThreadPriorityBoost",HANDLE(nullptr),FALSE);
 Call<decltype(&::GetThreadPriorityBoost)>(716,kb,"GetThreadPriorityBoost",HANDLE(nullptr),&boost);
 Call<decltype(&::GetThreadTimes)>(717,kb,"GetThreadTimes",HANDLE(nullptr),&a,&b,&c,&d);
 Call<decltype(&::GetThreadIOPendingFlag)>(718,kb,"GetThreadIOPendingFlag",HANDLE(nullptr),&pending);
 Call<decltype(&::SetThreadIdealProcessorEx)>(719,kb,"SetThreadIdealProcessorEx",HANDLE(nullptr),&ideal,&prev);
 Call<decltype(&::GetThreadIdealProcessorEx)>(720,kb,"GetThreadIdealProcessorEx",HANDLE(nullptr),&ideal);
 Call<decltype(&::GetThreadGroupAffinity)>(721,kb,"GetThreadGroupAffinity",HANDLE(nullptr),&affinity);
 Call<decltype(&::SetThreadGroupAffinity)>(722,kb,"SetThreadGroupAffinity",HANDLE(nullptr),&affinity,&previous);
 Call<decltype(&::GetThreadInformation)>(723,kb,"GetThreadInformation",HANDLE(nullptr),ThreadMemoryPriority,&info,DWORD(sizeof(info)));
 Call<decltype(&::SetThreadInformation)>(724,kb,"SetThreadInformation",HANDLE(nullptr),ThreadMemoryPriority,&info,DWORD(sizeof(info)));
 Call<decltype(&::GetThreadSelectedCpuSets)>(725,kb,"GetThreadSelectedCpuSets",HANDLE(nullptr),ids,ULONG(256),&required);
 Call<decltype(&::SetThreadSelectedCpuSets)>(726,kb,"SetThreadSelectedCpuSets",HANDLE(nullptr),ids,ULONG(0));
 Call<decltype(&::SetThreadDescription)>(727,kb,"SetThreadDescription",HANDLE(nullptr),L"");
 copy=nullptr; Call<decltype(&::GetThreadDescription)>(728,kb,"GetThreadDescription",HANDLE(nullptr),&copy); if(copy) LocalFree(copy);
 Call<decltype(&::SetThreadErrorMode)>(729,kb,"SetThreadErrorMode",DWORD(0xffffffff),&oldMode);
 Call<decltype(&::GetThreadPreferredUILanguages)>(730,kb,"GetThreadPreferredUILanguages",DWORD(0xffffffff),&count,langs.data(),&size);
 Call<decltype(&::SetThreadPreferredUILanguages)>(731,kb,"SetThreadPreferredUILanguages",DWORD(0xffffffff),L"",&setCount);
 Call<decltype(&::OfferVirtualMemory)>(830,kb,"OfferVirtualMemory",nullptr,SIZE_T(0),VmOfferPriorityLow);
 Call<decltype(&::ReclaimVirtualMemory)>(831,kb,"ReclaimVirtualMemory",nullptr,SIZE_T(0));
 Call<decltype(&::DiscardVirtualMemory)>(832,kb,"DiscardVirtualMemory",nullptr,SIZE_T(0));
 Call<decltype(&::QueryVirtualMemoryInformation)>(833,kb,"QueryVirtualMemoryInformation",HANDLE(nullptr),page,MemoryRegionInfo,&region,SIZE_T(sizeof(region)),&returned);
 Call<decltype(&::K32GetProcessMemoryInfo)>(834,kb,"K32GetProcessMemoryInfo",HANDLE(nullptr),&counters,DWORD(sizeof(counters)));
 Call<decltype(&::K32QueryWorkingSet)>(835,kb,"K32QueryWorkingSet",HANDLE(nullptr),&ws,DWORD(sizeof(ws)));
 Call<decltype(&::K32QueryWorkingSetEx)>(836,kb,"K32QueryWorkingSetEx",HANDLE(nullptr),&wsEx,DWORD(sizeof(wsEx)));
 Call<decltype(&::QueryThreadCycleTime)>(837,kb,"QueryThreadCycleTime",HANDLE(nullptr),&cycles);
 Call<decltype(&::QueryProcessCycleTime)>(838,kb,"QueryProcessCycleTime",HANDLE(nullptr),&cycles);
 Call<decltype(&::GetProcessHandleCount)>(839,kb,"GetProcessHandleCount",HANDLE(nullptr),&countHandles);
 Call<decltype(&::GetProcessIoCounters)>(840,k32,"GetProcessIoCounters",HANDLE(nullptr),&io);
 Call<decltype(&::GetProcessTimes)>(841,kb,"GetProcessTimes",HANDLE(nullptr),&a,&b,&c,&d);
 Call<decltype(&::GetProcessPriorityBoost)>(842,kb,"GetProcessPriorityBoost",HANDLE(nullptr),&processBoost);
 Call<decltype(&::SetProcessPriorityBoost)>(843,kb,"SetProcessPriorityBoost",HANDLE(nullptr),FALSE);
 Call<decltype(&::GetProcessAffinityMask)>(844,k32,"GetProcessAffinityMask",HANDLE(nullptr),&processMask,&systemMask);
 Call<decltype(&::GetProcessInformation)>(845,kb,"GetProcessInformation",HANDLE(nullptr),ProcessMemoryPriority,&processInfo,DWORD(sizeof(processInfo)));
 Call<decltype(&::SetProcessInformation)>(846,kb,"SetProcessInformation",HANDLE(nullptr),ProcessMemoryPriority,&processInfo,DWORD(sizeof(processInfo)));
 Call<decltype(&::GetProcessMitigationPolicy)>(847,kb,"GetProcessMitigationPolicy",HANDLE(nullptr),ProcessDEPPolicy,&dep,SIZE_T(sizeof(dep)));
 Call<decltype(&::GetProcessDEPPolicy)>(848,k32,"GetProcessDEPPolicy",HANDLE(nullptr),&depFlags,&permanent);
 Call<decltype(&::SetProcessShutdownParameters)>(850,kb,"SetProcessShutdownParameters",DWORD(0),DWORD(0xffffffff));
 Call<decltype(&::GetProcessIdOfThread)>(851,kb,"GetProcessIdOfThread",HANDLE(nullptr));
 if(page) VirtualFree(page,0,MEM_RELEASE);
}
}
