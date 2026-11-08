// Named summaries contain argument values only; never dereference caller buffers.
// Generated wrappers preserve the return value, call duration and LastError.

void CaptureVirtualLock(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID address, SIZE_T size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureVirtualUnlock(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID address, SIZE_T size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessWorkingSetSize(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PSIZE_T minimum, PSIZE_T maximum, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"minimum="); AppendHexText(detailBuffer, ApiReturnBits(minimum)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"maximum="); AppendHexText(detailBuffer, ApiReturnBits(maximum)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetProcessWorkingSetSizeEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PSIZE_T minimum, PSIZE_T maximum, PDWORD flags, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"minimum="); AppendHexText(detailBuffer, ApiReturnBits(minimum)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"maximum="); AppendHexText(detailBuffer, ApiReturnBits(maximum)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetProcessWorkingSetSize(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, SIZE_T minimum, SIZE_T maximum, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"minimum="); AppendHexText(detailBuffer, ApiReturnBits(minimum)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"maximum="); AppendHexText(detailBuffer, ApiReturnBits(maximum)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetProcessWorkingSetSizeEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, SIZE_T minimum, SIZE_T maximum, DWORD flags, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"minimum="); AppendHexText(detailBuffer, ApiReturnBits(minimum)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"maximum="); AppendHexText(detailBuffer, ApiReturnBits(maximum)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
}

void CaptureMapViewOfFileFromApp(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE mapping, ULONG access, ULONG64 offset, SIZE_T size, PVOID resultValue)
{
    AppendWideText(detailBuffer, L"mapping="); AppendHexText(detailBuffer, ApiReturnBits(mapping)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"access="); AppendHexText(detailBuffer, ApiReturnBits(access)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"offset="); AppendHexText(detailBuffer, ApiReturnBits(offset)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureUnmapViewOfFileEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID address, ULONG flags, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
}

void CaptureVirtualAllocFromApp(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID address, SIZE_T size, ULONG allocationType, ULONG protection, PVOID resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"allocationType="); AppendHexText(detailBuffer, ApiReturnBits(allocationType)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"protection="); AppendHexText(detailBuffer, ApiReturnBits(protection)); AppendWideText(detailBuffer, L" ");
}

void CaptureVirtualProtectFromApp(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID address, SIZE_T size, ULONG protection, PULONG oldProtection, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"protection="); AppendHexText(detailBuffer, ApiReturnBits(protection)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"oldProtection="); AppendHexText(detailBuffer, ApiReturnBits(oldProtection)); AppendWideText(detailBuffer, L" ");
}

void CaptureCreateEnclave(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, LPVOID address, SIZE_T size, SIZE_T initialCommitment, DWORD enclaveType, LPCVOID information, DWORD informationLength, LPDWORD enclaveError, LPVOID resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"initialCommitment="); AppendHexText(detailBuffer, ApiReturnBits(initialCommitment)); AppendWideText(detailBuffer, L" ");
}

void CaptureLoadEnclaveData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, LPVOID address, LPCVOID buffer, SIZE_T size, DWORD protection, LPCVOID information, DWORD informationLength, PSIZE_T bytesWritten, LPDWORD enclaveError, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"buffer="); AppendHexText(detailBuffer, ApiReturnBits(buffer)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"enclaveError="); AppendHexText(detailBuffer, ApiReturnBits(enclaveError)); AppendWideText(detailBuffer, L" ");
}

void CaptureInitializeEnclave(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, LPVOID address, LPCVOID information, DWORD informationLength, LPDWORD enclaveError, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, ApiReturnBits(process)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"informationLength="); AppendHexText(detailBuffer, ApiReturnBits(informationLength)); AppendWideText(detailBuffer, L" ");
}

void CaptureDeleteEnclave(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID address, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"address="); AppendHexText(detailBuffer, ApiReturnBits(address)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadPriority(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, int priority, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"priority="); AppendHexText(detailBuffer, ApiReturnBits(priority)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadPriorityBoost(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, BOOL disableBoost, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"disableBoost="); AppendHexText(detailBuffer, ApiReturnBits(disableBoost)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadPriorityBoost(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PBOOL disableBoost, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"disableBoost="); AppendHexText(detailBuffer, ApiReturnBits(disableBoost)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadTimes(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, LPFILETIME creation, LPFILETIME exit, LPFILETIME kernel, LPFILETIME user, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"creation="); AppendHexText(detailBuffer, ApiReturnBits(creation)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"exit="); AppendHexText(detailBuffer, ApiReturnBits(exit)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"kernel="); AppendHexText(detailBuffer, ApiReturnBits(kernel)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadIOPendingFlag(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PBOOL pending, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"pending="); AppendHexText(detailBuffer, ApiReturnBits(pending)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadIdealProcessorEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PPROCESSOR_NUMBER ideal, PPROCESSOR_NUMBER previous, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"ideal="); AppendHexText(detailBuffer, ApiReturnBits(ideal)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadIdealProcessorEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PPROCESSOR_NUMBER ideal, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"ideal="); AppendHexText(detailBuffer, ApiReturnBits(ideal)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadGroupAffinity(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PGROUP_AFFINITY affinity, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"affinity="); AppendHexText(detailBuffer, ApiReturnBits(affinity)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadGroupAffinity(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, const GROUP_AFFINITY* affinity, PGROUP_AFFINITY previous, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"affinity="); AppendHexText(detailBuffer, ApiReturnBits(affinity)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"previous="); AppendHexText(detailBuffer, ApiReturnBits(previous)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, THREAD_INFORMATION_CLASS informationClass, LPVOID information, DWORD size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"informationClass="); AppendHexText(detailBuffer, ApiReturnBits(informationClass)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, THREAD_INFORMATION_CLASS informationClass, LPVOID information, DWORD size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"informationClass="); AppendHexText(detailBuffer, ApiReturnBits(informationClass)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"information="); AppendHexText(detailBuffer, ApiReturnBits(information)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadSelectedCpuSets(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PULONG ids, ULONG count, PULONG required, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"ids="); AppendHexText(detailBuffer, ApiReturnBits(ids)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"required="); AppendHexText(detailBuffer, ApiReturnBits(required)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadSelectedCpuSets(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, const ULONG* ids, ULONG count, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"ids="); AppendHexText(detailBuffer, ApiReturnBits(ids)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadDescription(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PCWSTR description, HRESULT resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"description="); AppendHexText(detailBuffer, ApiReturnBits(description)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadDescription(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, PWSTR* description, HRESULT resultValue)
{
    AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, ApiReturnBits(thread)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"description="); AppendHexText(detailBuffer, ApiReturnBits(description)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadErrorMode(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD mode, LPDWORD oldMode, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"mode="); AppendHexText(detailBuffer, ApiReturnBits(mode)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"oldMode="); AppendHexText(detailBuffer, ApiReturnBits(oldMode)); AppendWideText(detailBuffer, L" ");
}

void CaptureGetThreadPreferredUILanguages(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD flags, PULONG count, PWSTR buffer, PULONG size, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"buffer="); AppendHexText(detailBuffer, ApiReturnBits(buffer)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"size="); AppendHexText(detailBuffer, ApiReturnBits(size)); AppendWideText(detailBuffer, L" ");
}

void CaptureSetThreadPreferredUILanguages(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD flags, PCWSTR languages, PULONG count, BOOL resultValue)
{
    AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, ApiReturnBits(flags)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"languages="); AppendHexText(detailBuffer, ApiReturnBits(languages)); AppendWideText(detailBuffer, L" ");
    AppendWideText(detailBuffer, L"count="); AppendHexText(detailBuffer, ApiReturnBits(count)); AppendWideText(detailBuffer, L" ");
}
