// Summaries contain only argument values; caller buffers are never read.

void CaptureOfferVirtualMemory(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID address, SIZE_T size, OFFER_PRIORITY priority, DWORD resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"priority="); AppendHexText(detailBuffer, ApiReturnBits(priority)); AppendWideText(detailBuffer, L" ");
}

void CaptureReclaimVirtualMemory(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const void* address, SIZE_T size, DWORD resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

// ReclaimVirtualMemory reports ERROR_BUSY when reclamation succeeded but the
// offered contents were discarded. Preserve that exact return to the caller.
DWORD WINAPI HookedReclaimVirtualMemory(const void* address, SIZE_T size)
{
    ScopedHookGuard guardValue;
    if (guardValue.bypass()) return g_reclaimVirtualMemoryOriginal(address, size);
    const auto entryArg1 = ApiReturnBits(address);
    const auto entryArg2 = ApiReturnBits(size);
    const auto callClock = BeginApiCallClock();
    const DWORD resultValue = g_reclaimVirtualMemoryOriginal(address, size);
    const DWORD savedError = ::GetLastError();
    const auto duration = EndApiCallClock(callClock);
    wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
    CaptureReclaimVirtualMemory(detailBuffer, address, size, resultValue);
    if (resultValue == ERROR_BUSY) AppendWideText(detailBuffer, L"reclaimed_discarded=1 ");
    AppendWideText(detailBuffer, L"arg1="); AppendHexText(detailBuffer, entryArg1);
    AppendWideText(detailBuffer, L" arg2="); AppendHexText(detailBuffer, entryArg2);
    const auto status = resultValue == ERROR_SUCCESS || resultValue == ERROR_BUSY
        ? 0 : static_cast<std::int32_t>(resultValue);
    SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Memory, L"KernelBase", L"ReclaimVirtualMemory",
        status, detailBuffer, true, ApiReturnBits(resultValue), duration);
    ::SetLastError(savedError);
    return resultValue;
}

void CaptureDiscardVirtualMemory(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID address, SIZE_T size, DWORD resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureQueryVirtualMemoryInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, const void* address, WIN32_MEMORY_INFORMATION_CLASS informationClass, PVOID information, SIZE_T size, PSIZE_T returnSize, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"informationClass="); AppendHexText(detailBuffer, ApiReturnBits(informationClass)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
}

void CaptureK32GetProcessMemoryInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PPROCESS_MEMORY_COUNTERS counters, DWORD size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"counters="); AppendHexText(detailBuffer, ApiReturnBits(counters)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureK32QueryWorkingSet(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PVOID information, DWORD size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureK32QueryWorkingSetEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PVOID information, DWORD size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureQueryThreadCycleTime(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PULONG64 cycles, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"cycles="); AppendHexText(detailBuffer, ApiReturnBits(cycles)); AppendWideText(detailBuffer, L" ");
}

void CaptureQueryProcessCycleTime(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PULONG64 cycles, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"cycles="); AppendHexText(detailBuffer, ApiReturnBits(cycles)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessHandleCount(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PDWORD count, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessIoCounters(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PIO_COUNTERS counters, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"counters="); AppendHexText(detailBuffer, ApiReturnBits(counters)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessTimes(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, LPFILETIME creation, LPFILETIME exit, LPFILETIME kernel, LPFILETIME user, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"creation="); AppendHexText(detailBuffer, ApiReturnBits(creation)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"exit="); AppendHexText(detailBuffer, ApiReturnBits(exit)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"kernel="); AppendHexText(detailBuffer, ApiReturnBits(kernel)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessPriorityBoost(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PBOOL disabled, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"disabled="); AppendHexText(detailBuffer, ApiReturnBits(disabled)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetProcessPriorityBoost(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, BOOL disabled, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"disabled="); AppendHexText(detailBuffer, ApiReturnBits(disabled)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessAffinityMask(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PDWORD_PTR processMask, PDWORD_PTR systemMask, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"processMask="); AppendHexText(detailBuffer, ApiReturnBits(processMask)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"systemMask="); AppendHexText(detailBuffer, ApiReturnBits(systemMask)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PROCESS_INFORMATION_CLASS informationClass, LPVOID information, DWORD size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"informationClass="); AppendHexText(detailBuffer, ApiReturnBits(informationClass)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetProcessInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PROCESS_INFORMATION_CLASS informationClass, LPVOID information, DWORD size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"informationClass="); AppendHexText(detailBuffer, ApiReturnBits(informationClass)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessMitigationPolicy(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PROCESS_MITIGATION_POLICY policy, PVOID information, SIZE_T size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"policy="); AppendHexText(detailBuffer, ApiReturnBits(policy)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessDEPPolicy(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, LPDWORD flags, PBOOL permanent, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"permanent="); AppendHexText(detailBuffer, ApiReturnBits(permanent)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessShutdownParameters(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPDWORD level, LPDWORD flags, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"level="); AppendHexText(detailBuffer, ApiReturnBits(level)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetProcessShutdownParameters(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD level, DWORD flags, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"level="); AppendHexText(detailBuffer, ApiReturnBits(level)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessIdOfThread(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, DWORD resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
}
