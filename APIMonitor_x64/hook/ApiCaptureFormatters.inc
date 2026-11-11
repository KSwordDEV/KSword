// Named C++ formatters retained from the typed wrappers. Included inside HookTargets.

void CaptureDeleteFileW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR pathPointer, BOOL resultValue)
{ BuildSinglePathDetailW(detailBuffer, pathPointer, 0); }

void CaptureDeleteFileA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR pathPointer, BOOL resultValue)
{ BuildSinglePathDetailA(detailBuffer, pathPointer, 0); }

void CaptureRemoveDirectoryW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR pathPointer, BOOL resultValue)
{ BuildSinglePathDetailW(detailBuffer, pathPointer, 0); }

void CaptureRemoveDirectoryA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR pathPointer, BOOL resultValue)
{ BuildSinglePathDetailA(detailBuffer, pathPointer, 0); }

void CaptureCreateFileMappingW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE fileHandle, LPSECURITY_ATTRIBUTES securityAttributes, DWORD protectValue, DWORD maximumSizeHigh, DWORD maximumSizeLow, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" protect="); AppendHexText(detailBuffer, protectValue); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, (static_cast<std::uint64_t>(maximumSizeHigh) << 32) | maximumSizeLow); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, namePointer); }

void CaptureCreateFileMappingA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE fileHandle, LPSECURITY_ATTRIBUTES securityAttributes, DWORD protectValue, DWORD maximumSizeHigh, DWORD maximumSizeLow, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" protect="); AppendHexText(detailBuffer, protectValue); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, (static_cast<std::uint64_t>(maximumSizeHigh) << 32) | maximumSizeLow); AppendWideText(detailBuffer, L" name="); AppendAnsiText(detailBuffer, namePointer); }

void CaptureOpenFileMappingW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" inherit="); AppendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, namePointer); }

void CaptureOpenFileMappingA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" inherit="); AppendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" name="); AppendAnsiText(detailBuffer, namePointer); }

void CaptureFlushViewOfFile(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCVOID baseAddress, SIZE_T bytesToFlush, BOOL resultValue)
{ AppendWideText(detailBuffer, L"base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesToFlush)); }

void CaptureCreateHardLinkW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR fileNamePointer, LPCWSTR existingFileNamePointer, LPSECURITY_ATTRIBUTES securityAttributes, BOOL resultValue)
{ BuildTwoPathDetailW(detailBuffer, existingFileNamePointer, fileNamePointer, 0); }

void CaptureCreateHardLinkA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR fileNamePointer, LPCSTR existingFileNamePointer, LPSECURITY_ATTRIBUTES securityAttributes, BOOL resultValue)
{ BuildTwoPathDetailA(detailBuffer, existingFileNamePointer, fileNamePointer, 0); }

void CaptureReplaceFileW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR replacedFilePointer, LPCWSTR replacementFilePointer, LPCWSTR backupFilePointer, DWORD flagsValue, LPVOID excludePointer, LPVOID reservedPointer, BOOL resultValue)
{ BuildTwoPathDetailW(detailBuffer, replacedFilePointer, replacementFilePointer, flagsValue); AppendWideText(detailBuffer, L" backup="); AppendWideText(detailBuffer, backupFilePointer); }

void CaptureReplaceFileA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR replacedFilePointer, LPCSTR replacementFilePointer, LPCSTR backupFilePointer, DWORD flagsValue, LPVOID excludePointer, LPVOID reservedPointer, BOOL resultValue)
{ BuildTwoPathDetailA(detailBuffer, replacedFilePointer, replacementFilePointer, flagsValue); AppendWideText(detailBuffer, L" backup="); AppendAnsiText(detailBuffer, backupFilePointer); }

void CaptureSetEndOfFile(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE fileHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"file", fileHandle); }

void CaptureLockFileEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE fileHandle, DWORD flagsValue, DWORD reservedValue, DWORD bytesLow, DWORD bytesHigh, LPOVERLAPPED overlappedPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" bytes="); AppendHexText(detailBuffer, (static_cast<std::uint64_t>(bytesHigh) << 32) | bytesLow); }

void CaptureUnlockFileEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE fileHandle, DWORD reservedValue, DWORD bytesLow, DWORD bytesHigh, LPOVERLAPPED overlappedPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" bytes="); AppendHexText(detailBuffer, (static_cast<std::uint64_t>(bytesHigh) << 32) | bytesLow); }

void CaptureGetFileSizeEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE fileHandle, PLARGE_INTEGER fileSizePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, fileSizePointer != nullptr ? static_cast<std::uint64_t>(fileSizePointer->QuadPart) : 0); }

void CaptureSetFilePointerEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE fileHandle, LARGE_INTEGER distanceValue, PLARGE_INTEGER newPointer, DWORD moveMethod, BOOL resultValue)
{ AppendWideText(detailBuffer, L"file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" distance="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(distanceValue.QuadPart)); AppendWideText(detailBuffer, L" method="); AppendUnsignedText(detailBuffer, moveMethod); AppendWideText(detailBuffer, L" new="); AppendHexText(detailBuffer, newPointer != nullptr ? static_cast<std::uint64_t>(newPointer->QuadPart) : 0); }

void CaptureCreateNamedPipeW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR namePointer, DWORD openMode, DWORD pipeMode, DWORD maxInstances, DWORD outBufferSize, DWORD inBufferSize, DWORD defaultTimeout, LPSECURITY_ATTRIBUTES securityAttributes, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" openMode="); AppendHexText(detailBuffer, openMode); AppendWideText(detailBuffer, L" pipeMode="); AppendHexText(detailBuffer, pipeMode); AppendWideText(detailBuffer, L" instances="); AppendUnsignedText(detailBuffer, maxInstances); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateNamedPipeA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR namePointer, DWORD openMode, DWORD pipeMode, DWORD maxInstances, DWORD outBufferSize, DWORD inBufferSize, DWORD defaultTimeout, LPSECURITY_ATTRIBUTES securityAttributes, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" openMode="); AppendHexText(detailBuffer, openMode); AppendWideText(detailBuffer, L" pipeMode="); AppendHexText(detailBuffer, pipeMode); AppendWideText(detailBuffer, L" instances="); AppendUnsignedText(detailBuffer, maxInstances); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureConnectNamedPipe(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE pipeHandle, LPOVERLAPPED overlappedPointer, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"pipe", pipeHandle); }

void CaptureDisconnectNamedPipe(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE pipeHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"pipe", pipeHandle); }

void CaptureWaitNamedPipeW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR namePointer, DWORD timeoutValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" timeout="); AppendUnsignedText(detailBuffer, timeoutValue); }

void CaptureWaitNamedPipeA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR namePointer, DWORD timeoutValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" timeout="); AppendUnsignedText(detailBuffer, timeoutValue); }

void CaptureTransactNamedPipe(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE pipeHandle, LPVOID inBufferPointer, DWORD inBufferSize, LPVOID outBufferPointer, DWORD outBufferSize, LPDWORD bytesReadPointer, LPOVERLAPPED overlappedPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"pipe="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(pipeHandle)); AppendWideText(detailBuffer, L" in="); AppendUnsignedText(detailBuffer, inBufferSize); AppendWideText(detailBuffer, L" out="); AppendUnsignedText(detailBuffer, outBufferSize); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); }

void CaptureCreateRemoteThreadEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, LPSECURITY_ATTRIBUTES threadAttributes, SIZE_T stackSize, LPTHREAD_START_ROUTINE startAddress, LPVOID parameterPointer, DWORD creationFlags, LPPROC_THREAD_ATTRIBUTE_LIST attributeListPointer, LPDWORD threadIdPointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" start="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startAddress)); AppendWideText(detailBuffer, L" param="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameterPointer)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, creationFlags); AppendWideText(detailBuffer, L" tid="); AppendUnsignedText(detailBuffer, threadIdPointer != nullptr ? *threadIdPointer : 0); AppendWideText(detailBuffer, L" thread="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureVirtualAlloc(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID baseAddress, SIZE_T sizeValue, DWORD allocationType, DWORD protectValue, LPVOID resultHandle)
{ AppendWideText(detailBuffer, L"baseHint="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(sizeValue)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, allocationType); AppendWideText(detailBuffer, L" protect="); AppendHexText(detailBuffer, protectValue); AppendWideText(detailBuffer, L" result="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureVirtualFree(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID baseAddress, SIZE_T sizeValue, DWORD freeType, BOOL resultValue)
{ AppendWideText(detailBuffer, L"base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(sizeValue)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, freeType); }

void CaptureVirtualProtect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID baseAddress, SIZE_T sizeValue, DWORD newProtect, PDWORD oldProtectPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(sizeValue)); AppendWideText(detailBuffer, L" newProtect="); AppendHexText(detailBuffer, newProtect); AppendWideText(detailBuffer, L" oldProtect="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureCloseHandle(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE handleValue, BOOL resultValue)
{ if (resultValue) RetireIoResource(reinterpret_cast<std::uintptr_t>(handleValue)); BuildSimpleHandleDetail(detailBuffer, L"handle", handleValue); }

void CaptureDuplicateHandle(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE sourceProcessHandle, HANDLE sourceHandle, HANDLE targetProcessHandle, LPHANDLE targetHandlePointer, DWORD desiredAccess, BOOL inheritHandle, DWORD optionsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"srcProc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceProcessHandle)); AppendWideText(detailBuffer, L" src="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceHandle)); AppendWideText(detailBuffer, L" dstProc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(targetProcessHandle)); AppendWideText(detailBuffer, L" dst="); AppendWideText(detailBuffer, L"<see-out_after>"); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" inherit="); AppendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" options="); AppendHexText(detailBuffer, optionsValue); }

void CaptureMapViewOfFile(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE mappingHandle, DWORD desiredAccess, DWORD offsetHigh, DWORD offsetLow, SIZE_T bytesToMap, LPVOID resultHandle)
{ AppendWideText(detailBuffer, L"mapping="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(mappingHandle)); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" offset="); AppendHexText(detailBuffer, (static_cast<std::uint64_t>(offsetHigh) << 32) | offsetLow); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesToMap)); AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureMapViewOfFileEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE mappingHandle, DWORD desiredAccess, DWORD offsetHigh, DWORD offsetLow, SIZE_T bytesToMap, LPVOID baseAddress, LPVOID resultHandle)
{ AppendWideText(detailBuffer, L"mapping="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(mappingHandle)); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" hint="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesToMap)); AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureUnmapViewOfFile(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCVOID baseAddress, BOOL resultValue)
{ AppendWideText(detailBuffer, L"base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); }

void CaptureCreateMutexW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributes, BOOL initialOwner, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" initialOwner="); AppendUnsignedText(detailBuffer, initialOwner != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateMutexA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributes, BOOL initialOwner, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" initialOwner="); AppendUnsignedText(detailBuffer, initialOwner != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenMutexW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenMutexA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateEventW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributes, BOOL manualReset, BOOL initialState, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" manual="); AppendUnsignedText(detailBuffer, manualReset != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" initial="); AppendUnsignedText(detailBuffer, initialState != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateEventA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributes, BOOL manualReset, BOOL initialState, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" manual="); AppendUnsignedText(detailBuffer, manualReset != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" initial="); AppendUnsignedText(detailBuffer, initialState != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenEventW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenEventA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateSemaphoreW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributes, LONG initialCount, LONG maximumCount, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" initial="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(initialCount < 0 ? 0 : initialCount)); AppendWideText(detailBuffer, L" max="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(maximumCount < 0 ? 0 : maximumCount)); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateSemaphoreA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributes, LONG initialCount, LONG maximumCount, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" initial="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(initialCount < 0 ? 0 : initialCount)); AppendWideText(detailBuffer, L" max="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(maximumCount < 0 ? 0 : maximumCount)); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenSemaphoreW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenSemaphoreA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureSetEvent(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"event", eventHandle); }

void CaptureResetEvent(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"event", eventHandle); }

void CaptureReleaseMutex(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE mutexHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"mutex", mutexHandle); }

void CaptureReleaseSemaphore(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE semaphoreHandle, LONG releaseCount, LPLONG previousCountPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"semaphore="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(semaphoreHandle)); AppendWideText(detailBuffer, L" release="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(releaseCount < 0 ? 0 : releaseCount)); AppendWideText(detailBuffer, L" previous="); AppendUnsignedText(detailBuffer, previousCountPointer != nullptr ? static_cast<unsigned long long>(*previousCountPointer) : 0ULL); }

void CaptureSetEnvironmentVariableW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR namePointer, LPCWSTR valuePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" valueLen="); AppendUnsignedText(detailBuffer, valuePointer != nullptr ? static_cast<unsigned long long>(::wcslen(valuePointer)) : 0ULL); }

void CaptureSetEnvironmentVariableA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR namePointer, LPCSTR valuePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" valueLen="); AppendUnsignedText(detailBuffer, valuePointer != nullptr ? static_cast<unsigned long long>(::strlen(valuePointer)) : 0ULL); }

void CaptureOpenProcessToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, DWORD desiredAccess, PHANDLE tokenHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" token="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureOpenThreadToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE threadHandle, DWORD desiredAccess, BOOL openAsSelf, PHANDLE tokenHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle)); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" openAsSelf="); AppendUnsignedText(detailBuffer, openAsSelf != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" token="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureAdjustTokenPrivileges(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, BOOL disableAllPrivileges, PTOKEN_PRIVILEGES newStatePointer, DWORD bufferLength, PTOKEN_PRIVILEGES previousStatePointer, PDWORD returnLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" disableAll="); AppendUnsignedText(detailBuffer, disableAllPrivileges != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" privilegeCount="); AppendUnsignedText(detailBuffer, newStatePointer != nullptr ? newStatePointer->PrivilegeCount : 0); AppendWideText(detailBuffer, L" returnLen="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureDuplicateToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE existingTokenHandle, SECURITY_IMPERSONATION_LEVEL impersonationLevel, PHANDLE newTokenHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(existingTokenHandle)); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(impersonationLevel)); AppendWideText(detailBuffer, L" newToken="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureDuplicateTokenEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE existingTokenHandle, DWORD desiredAccess, LPSECURITY_ATTRIBUTES tokenAttributes, SECURITY_IMPERSONATION_LEVEL impersonationLevel, TOKEN_TYPE tokenType, PHANDLE newTokenHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(existingTokenHandle)); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(impersonationLevel)); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(tokenType)); AppendWideText(detailBuffer, L" newToken="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureImpersonateLoggedOnUser(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"token", tokenHandle); }

void CaptureRevertToSelf(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BOOL resultValue)
{ detailBuffer[0] = L'\0'; }

void CaptureSetThreadToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE threadHandlePointer, HANDLE tokenHandle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0); AppendWideText(detailBuffer, L" token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); }

void CaptureLookupPrivilegeValueW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR systemNamePointer, LPCWSTR namePointer, PLUID luidPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"system="); AppendWideText(detailBuffer, systemNamePointer); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" luidLow="); AppendHexText(detailBuffer, luidPointer != nullptr ? luidPointer->LowPart : 0); }

void CaptureLookupPrivilegeValueA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR systemNamePointer, LPCSTR namePointer, PLUID luidPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"system="); AppendAnsiText(detailBuffer, systemNamePointer); AppendWideText(detailBuffer, L" name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" luidLow="); AppendHexText(detailBuffer, luidPointer != nullptr ? luidPointer->LowPart : 0); }

void CaptureOpenSCManagerW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR machineNamePointer, LPCWSTR databaseNamePointer, DWORD desiredAccess, SC_HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"machine="); AppendWideText(detailBuffer, machineNamePointer); AppendWideText(detailBuffer, L" database="); AppendWideText(detailBuffer, databaseNamePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenSCManagerA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR machineNamePointer, LPCSTR databaseNamePointer, DWORD desiredAccess, SC_HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"machine="); AppendAnsiText(detailBuffer, machineNamePointer); AppendWideText(detailBuffer, L" database="); AppendAnsiText(detailBuffer, databaseNamePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenServiceW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE managerHandle, LPCWSTR serviceNamePointer, DWORD desiredAccess, SC_HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"scm="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); AppendWideText(detailBuffer, L" service="); AppendWideText(detailBuffer, serviceNamePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenServiceA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE managerHandle, LPCSTR serviceNamePointer, DWORD desiredAccess, SC_HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"scm="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); AppendWideText(detailBuffer, L" service="); AppendAnsiText(detailBuffer, serviceNamePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateServiceW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE managerHandle, LPCWSTR serviceNamePointer, LPCWSTR displayNamePointer, DWORD desiredAccess, DWORD serviceType, DWORD startType, DWORD errorControl, LPCWSTR binaryPathPointer, LPCWSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCWSTR dependenciesPointer, LPCWSTR serviceStartNamePointer, LPCWSTR passwordPointer, SC_HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"service="); AppendWideText(detailBuffer, serviceNamePointer); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, serviceType); AppendWideText(detailBuffer, L" start="); AppendHexText(detailBuffer, startType); AppendWideText(detailBuffer, L" path="); AppendWideText(detailBuffer, binaryPathPointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateServiceA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE managerHandle, LPCSTR serviceNamePointer, LPCSTR displayNamePointer, DWORD desiredAccess, DWORD serviceType, DWORD startType, DWORD errorControl, LPCSTR binaryPathPointer, LPCSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCSTR dependenciesPointer, LPCSTR serviceStartNamePointer, LPCSTR passwordPointer, SC_HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"service="); AppendAnsiText(detailBuffer, serviceNamePointer); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, serviceType); AppendWideText(detailBuffer, L" start="); AppendHexText(detailBuffer, startType); AppendWideText(detailBuffer, L" path="); AppendAnsiText(detailBuffer, binaryPathPointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureChangeServiceConfigW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, DWORD serviceType, DWORD startType, DWORD errorControl, LPCWSTR binaryPathPointer, LPCWSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCWSTR dependenciesPointer, LPCWSTR serviceStartNamePointer, LPCWSTR passwordPointer, LPCWSTR displayNamePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, serviceType); AppendWideText(detailBuffer, L" start="); AppendHexText(detailBuffer, startType); AppendWideText(detailBuffer, L" path="); AppendWideText(detailBuffer, binaryPathPointer); }

void CaptureChangeServiceConfigA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, DWORD serviceType, DWORD startType, DWORD errorControl, LPCSTR binaryPathPointer, LPCSTR loadOrderGroupPointer, LPDWORD tagIdPointer, LPCSTR dependenciesPointer, LPCSTR serviceStartNamePointer, LPCSTR passwordPointer, LPCSTR displayNamePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, serviceType); AppendWideText(detailBuffer, L" start="); AppendHexText(detailBuffer, startType); AppendWideText(detailBuffer, L" path="); AppendAnsiText(detailBuffer, binaryPathPointer); }

void CaptureChangeServiceConfig2W(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, DWORD infoLevel, LPVOID infoPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, infoLevel); }

void CaptureChangeServiceConfig2A(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, DWORD infoLevel, LPVOID infoPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, infoLevel); }

void CaptureStartServiceW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, DWORD argumentCount, LPCWSTR* argumentVector, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" argc="); AppendUnsignedText(detailBuffer, argumentCount); }

void CaptureStartServiceA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, DWORD argumentCount, LPCSTR* argumentVector, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" argc="); AppendUnsignedText(detailBuffer, argumentCount); }

void CaptureControlService(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, DWORD controlCode, LPSERVICE_STATUS serviceStatusPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" control="); AppendHexText(detailBuffer, controlCode); }

void CaptureDeleteService(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"service", serviceHandle); }

void CaptureCloseServiceHandle(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"service", serviceHandle); }

void CaptureQueryServiceStatusEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, SC_STATUS_TYPE infoLevel, LPBYTE bufferPointer, DWORD bufferSize, LPDWORD bytesNeededPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, infoLevel); AppendWideText(detailBuffer, L" buffer="); AppendUnsignedText(detailBuffer, bufferSize); AppendWideText(detailBuffer, L" needed="); AppendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); }

void CaptureQueryServiceConfigW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, LPQUERY_SERVICE_CONFIGW configPointer, DWORD bufferSize, LPDWORD bytesNeededPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" buffer="); AppendUnsignedText(detailBuffer, bufferSize); AppendWideText(detailBuffer, L" needed="); AppendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); if (resultValue != FALSE && configPointer != nullptr) { AppendWideText(detailBuffer, L" path="); AppendWideText(detailBuffer, configPointer->lpBinaryPathName); } }

void CaptureQueryServiceConfigA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE serviceHandle, LPQUERY_SERVICE_CONFIGA configPointer, DWORD bufferSize, LPDWORD bytesNeededPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"service="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serviceHandle)); AppendWideText(detailBuffer, L" buffer="); AppendUnsignedText(detailBuffer, bufferSize); AppendWideText(detailBuffer, L" needed="); AppendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); if (resultValue != FALSE && configPointer != nullptr) { AppendWideText(detailBuffer, L" path="); AppendAnsiText(detailBuffer, configPointer->lpBinaryPathName); } }

void CaptureEnumServicesStatusExW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE managerHandle, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE servicesPointer, DWORD bufferSize, LPDWORD bytesNeededPointer, LPDWORD servicesReturnedPointer, LPDWORD resumeHandlePointer, LPCWSTR groupNamePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"scm="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, serviceType); AppendWideText(detailBuffer, L" state="); AppendHexText(detailBuffer, serviceState); AppendWideText(detailBuffer, L" returned="); AppendUnsignedText(detailBuffer, servicesReturnedPointer != nullptr ? *servicesReturnedPointer : 0); AppendWideText(detailBuffer, L" group="); AppendWideText(detailBuffer, groupNamePointer); }

void CaptureEnumServicesStatusExA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SC_HANDLE managerHandle, SC_ENUM_TYPE infoLevel, DWORD serviceType, DWORD serviceState, LPBYTE servicesPointer, DWORD bufferSize, LPDWORD bytesNeededPointer, LPDWORD servicesReturnedPointer, LPDWORD resumeHandlePointer, LPCSTR groupNamePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"scm="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(managerHandle)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, serviceType); AppendWideText(detailBuffer, L" state="); AppendHexText(detailBuffer, serviceState); AppendWideText(detailBuffer, L" returned="); AppendUnsignedText(detailBuffer, servicesReturnedPointer != nullptr ? *servicesReturnedPointer : 0); AppendWideText(detailBuffer, L" group="); AppendAnsiText(detailBuffer, groupNamePointer); }

void CaptureCryptAcquireContextW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTPROV* providerPointer, LPCWSTR containerPointer, LPCWSTR providerNamePointer, DWORD providerType, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"container="); AppendWideText(detailBuffer, containerPointer); AppendWideText(detailBuffer, L" provider="); AppendWideText(detailBuffer, providerNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, providerType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, providerPointer != nullptr ? static_cast<std::uint64_t>(*providerPointer) : 0); }

void CaptureCryptAcquireContextA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTPROV* providerPointer, LPCSTR containerPointer, LPCSTR providerNamePointer, DWORD providerType, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"container="); AppendAnsiText(detailBuffer, containerPointer); AppendWideText(detailBuffer, L" provider="); AppendAnsiText(detailBuffer, providerNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, providerType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, providerPointer != nullptr ? static_cast<std::uint64_t>(*providerPointer) : 0); }

void CaptureCryptCreateHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTPROV providerHandle, ALG_ID algorithmId, HCRYPTKEY keyHandle, DWORD flagsValue, HCRYPTHASH* hashHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" alg="); AppendHexText(detailBuffer, algorithmId); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" hash="); AppendHexText(detailBuffer, hashHandlePointer != nullptr ? static_cast<std::uint64_t>(*hashHandlePointer) : 0); }

void CaptureCryptHashData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTHASH hashHandle, const BYTE* dataPointer, DWORD dataLength, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"hash="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(hashHandle)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, dataLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureCryptDeriveKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTPROV providerHandle, ALG_ID algorithmId, HCRYPTHASH hashHandle, DWORD flagsValue, HCRYPTKEY* keyHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" alg="); AppendHexText(detailBuffer, algorithmId); AppendWideText(detailBuffer, L" hash="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(hashHandle)); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureCryptEncrypt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTKEY keyHandle, HCRYPTHASH hashHandle, BOOL finalValue, DWORD flagsValue, BYTE* dataPointer, DWORD* dataLengthPointer, DWORD bufferLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" final="); AppendUnsignedText(detailBuffer, finalValue != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" dataLen="); AppendUnsignedText(detailBuffer, dataLengthPointer != nullptr ? *dataLengthPointer : 0); AppendWideText(detailBuffer, L" bufferLen="); AppendUnsignedText(detailBuffer, bufferLength); }

void CaptureCryptDecrypt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTKEY keyHandle, HCRYPTHASH hashHandle, BOOL finalValue, DWORD flagsValue, BYTE* dataPointer, DWORD* dataLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" final="); AppendUnsignedText(detailBuffer, finalValue != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" dataLen="); AppendUnsignedText(detailBuffer, dataLengthPointer != nullptr ? *dataLengthPointer : 0); }

void CaptureCryptGenRandom(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTPROV providerHandle, DWORD bufferLength, BYTE* bufferPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bufferLength); }

void CaptureCryptReleaseContext(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTPROV providerHandle, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureCryptImportKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTPROV providerHandle, const BYTE* dataPointer, DWORD dataLength, HCRYPTKEY publicKeyHandle, DWORD flagsValue, HCRYPTKEY* keyHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, dataLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureCryptExportKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTKEY keyHandle, HCRYPTKEY exportKeyHandle, DWORD blobType, DWORD flagsValue, BYTE* dataPointer, DWORD* dataLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" exportKey="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(exportKeyHandle)); AppendWideText(detailBuffer, L" blobType="); AppendHexText(detailBuffer, blobType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, dataLengthPointer != nullptr ? *dataLengthPointer : 0); }

void CaptureCryptDestroyKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTKEY keyHandle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); }

void CaptureCryptDestroyHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCRYPTHASH hashHandle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"hash="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(hashHandle)); }

void CaptureFreeLibrary(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HMODULE moduleHandle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"module="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle)); }

void CaptureSetDllDirectoryW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR pathPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"path="); AppendWideText(detailBuffer, pathPointer); }

void CaptureSetDllDirectoryA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR pathPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"path="); AppendAnsiText(detailBuffer, pathPointer); }

void CaptureSetDefaultDllDirectories(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD directoryFlags, BOOL resultValue)
{ AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, directoryFlags); }

void CaptureAddDllDirectory(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PCWSTR pathPointer, DLL_DIRECTORY_COOKIE resultHandle)
{ AppendWideText(detailBuffer, L"path="); AppendWideText(detailBuffer, pathPointer); AppendWideText(detailBuffer, L" cookie="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureRemoveDllDirectory(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DLL_DIRECTORY_COOKIE cookieValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"cookie="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(cookieValue)); }

void CaptureModule32FirstW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, LPMODULEENTRY32W entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" module="); AppendWideText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? entryPointer->szModule : nullptr); AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); }

void CaptureModule32NextW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, LPMODULEENTRY32W entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" module="); AppendWideText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? entryPointer->szModule : nullptr); AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); }

void CaptureModule32First(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, tagMODULEENTRY32* entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" module="); if (resultValue != FALSE && entryPointer != nullptr) { AppendAnsiText(detailBuffer, entryPointer->szModule); } AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); }

void CaptureModule32Next(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, tagMODULEENTRY32* entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" module="); if (resultValue != FALSE && entryPointer != nullptr) { AppendAnsiText(detailBuffer, entryPointer->szModule); } AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, resultValue != FALSE && entryPointer != nullptr ? reinterpret_cast<std::uint64_t>(entryPointer->modBaseAddr) : 0); }

void CaptureGetModuleHandleW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR moduleNamePointer, HMODULE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, moduleNamePointer); AppendWideText(detailBuffer, L" module="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureGetModuleHandleA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR moduleNamePointer, HMODULE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, moduleNamePointer); AppendWideText(detailBuffer, L" module="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureGetModuleHandleExW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD flagsValue, LPCWSTR moduleNamePointer, HMODULE* moduleHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, moduleNamePointer); AppendWideText(detailBuffer, L" module="); AppendHexText(detailBuffer, moduleHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*moduleHandlePointer) : 0); }

void CaptureGetModuleHandleExA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD flagsValue, LPCSTR moduleNamePointer, HMODULE* moduleHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" name="); AppendAnsiText(detailBuffer, moduleNamePointer); AppendWideText(detailBuffer, L" module="); AppendHexText(detailBuffer, moduleHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*moduleHandlePointer) : 0); }

void CaptureRegCreateKeyTransactedW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCWSTR subKeyPointer, DWORD reservedValue, LPWSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer, HANDLE transactionHandle, PVOID extendedParameter, LSTATUS statusValue)
{ BuildRegCreateDetail(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); }

void CaptureRegCreateKeyTransactedA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCSTR subKeyPointer, DWORD reservedValue, LPSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer, HANDLE transactionHandle, PVOID extendedParameter, LSTATUS statusValue)
{ BuildRegCreateDetailA(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); }

void CaptureRegOpenKeyTransactedW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCWSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer, HANDLE transactionHandle, PVOID extendedParameter, LSTATUS statusValue)
{ BuildRegOpenDetail(detailBuffer, rootKey, subKeyPointer, samDesired); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); }

void CaptureRegOpenKeyTransactedA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer, HANDLE transactionHandle, PVOID extendedParameter, LSTATUS statusValue)
{ BuildRegOpenDetailA(detailBuffer, rootKey, subKeyPointer, samDesired); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); }

void CaptureRegDeleteKeyTransactedW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCWSTR subKeyPointer, REGSAM viewValue, DWORD reservedValue, HANDLE transactionHandle, PVOID extendedParameter, LSTATUS statusValue)
{ BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, viewValue); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); }

void CaptureRegDeleteKeyTransactedA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCSTR subKeyPointer, REGSAM viewValue, DWORD reservedValue, HANDLE transactionHandle, PVOID extendedParameter, LSTATUS statusValue)
{ BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, viewValue); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); }

void CaptureRegReplaceKeyW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCWSTR subKeyPointer, LPCWSTR newFilePointer, LPCWSTR oldFilePointer, LSTATUS statusValue)
{ BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0); AppendWideText(detailBuffer, L" newFile="); AppendWideText(detailBuffer, newFilePointer); AppendWideText(detailBuffer, L" oldFile="); AppendWideText(detailBuffer, oldFilePointer); }

void CaptureRegReplaceKeyA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCSTR subKeyPointer, LPCSTR newFilePointer, LPCSTR oldFilePointer, LSTATUS statusValue)
{ BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0); AppendWideText(detailBuffer, L" newFile="); AppendAnsiText(detailBuffer, newFilePointer); AppendWideText(detailBuffer, L" oldFile="); AppendAnsiText(detailBuffer, oldFilePointer); }

void CaptureRegRestoreKeyW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY keyHandle, LPCWSTR filePointer, DWORD flagsValue, LSTATUS statusValue)
{ AppendWideText(detailBuffer, L"hkey="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" file="); AppendWideText(detailBuffer, filePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureRegRestoreKeyA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY keyHandle, LPCSTR filePointer, DWORD flagsValue, LSTATUS statusValue)
{ AppendWideText(detailBuffer, L"hkey="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" file="); AppendAnsiText(detailBuffer, filePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureRegUnLoadKeyW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCWSTR subKeyPointer, LSTATUS statusValue)
{ BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0); }

void CaptureRegUnLoadKeyA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY rootKey, LPCSTR subKeyPointer, LSTATUS statusValue)
{ BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0); }

void CaptureRegLoadAppKeyW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR filePointer, PHKEY resultKeyPointer, REGSAM samDesired, DWORD optionsValue, DWORD reservedValue, LSTATUS statusValue)
{ AppendWideText(detailBuffer, L"file="); AppendWideText(detailBuffer, filePointer); AppendWideText(detailBuffer, L" sam="); AppendHexText(detailBuffer, samDesired); AppendWideText(detailBuffer, L" options="); AppendHexText(detailBuffer, optionsValue); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); }

void CaptureRegLoadAppKeyA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR filePointer, PHKEY resultKeyPointer, REGSAM samDesired, DWORD optionsValue, DWORD reservedValue, LSTATUS statusValue)
{ AppendWideText(detailBuffer, L"file="); AppendAnsiText(detailBuffer, filePointer); AppendWideText(detailBuffer, L" sam="); AppendHexText(detailBuffer, samDesired); AppendWideText(detailBuffer, L" options="); AppendHexText(detailBuffer, optionsValue); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0); }

void CaptureRegNotifyChangeKeyValue(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HKEY keyHandle, BOOL watchSubtree, DWORD notifyFilter, HANDLE eventHandle, BOOL asynchronous, LSTATUS statusValue)
{ AppendWideText(detailBuffer, L"hkey="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" subtree="); AppendUnsignedText(detailBuffer, watchSubtree != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" filter="); AppendHexText(detailBuffer, notifyFilter); AppendWideText(detailBuffer, L" event="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); AppendWideText(detailBuffer, L" async="); AppendUnsignedText(detailBuffer, asynchronous != FALSE ? 1ULL : 0ULL); }

void CaptureNtCreateKeyTransacted(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, ULONG titleIndex, PUNICODE_STRING classPointer, ULONG createOptions, HANDLE transactionHandle, PULONG dispositionPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendObjectNameText(detailBuffer, objectAttributes); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" options="); AppendHexText(detailBuffer, createOptions); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureNtOpenKeyTransacted(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, HANDLE transactionHandle, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendObjectNameText(detailBuffer, objectAttributes); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); AppendWideText(detailBuffer, L" hkeyOut="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureNtOpenKeyTransactedEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributes, ULONG openOptions, HANDLE transactionHandle, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendObjectNameText(detailBuffer, objectAttributes); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" options="); AppendHexText(detailBuffer, openOptions); AppendWideText(detailBuffer, L" transaction="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(transactionHandle)); }

void CaptureNtReplaceKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], POBJECT_ATTRIBUTES newFileObjectAttributes, HANDLE targetHandle, POBJECT_ATTRIBUTES oldFileObjectAttributes, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"target="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(targetHandle)); AppendWideText(detailBuffer, L" newFile="); AppendObjectNameText(detailBuffer, newFileObjectAttributes); AppendWideText(detailBuffer, L" oldFile="); AppendObjectNameText(detailBuffer, oldFileObjectAttributes); }

void CaptureNtRestoreKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE keyHandle, HANDLE fileHandle, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"hkey="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNtUnloadKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], POBJECT_ATTRIBUTES targetKey, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendObjectNameText(detailBuffer, targetKey); }

void CaptureNtUnloadKey2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], POBJECT_ATTRIBUTES targetKey, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendObjectNameText(detailBuffer, targetKey); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNtUnloadKeyEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], POBJECT_ATTRIBUTES targetKey, HANDLE eventHandle, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendObjectNameText(detailBuffer, targetKey); AppendWideText(detailBuffer, L" event="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); }

void CaptureNtClose(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE handleValue, NTSTATUS statusValue)
{ BuildSimpleHandleDetail(detailBuffer, L"handle", handleValue); }

void CaptureWSAIoctl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, DWORD ioControlCode, LPVOID inBufferPointer, DWORD inBufferSize, LPVOID outBufferPointer, DWORD outBufferSize, LPDWORD bytesReturnedPointer, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" code="); AppendHexText(detailBuffer, ioControlCode); AppendWideText(detailBuffer, L" in="); AppendUnsignedText(detailBuffer, inBufferSize); AppendWideText(detailBuffer, L" out="); AppendUnsignedText(detailBuffer, outBufferSize); AppendWideText(detailBuffer, L" returned="); AppendUnsignedText(detailBuffer, bytesReturnedPointer != nullptr ? *bytesReturnedPointer : 0); }

void CaptureWSASendTo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesSentPointer, DWORD flagsValue, const sockaddr* toPointer, int toLength, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer, int resultValue)
{ BuildSocketDetail(detailBuffer, L"sendto", socketValue, SumWsaBufferLength(buffersPointer, bufferCount), bytesSentPointer != nullptr ? static_cast<int>(*bytesSentPointer) : 0, flagsValue, toPointer, toLength); }

void CaptureWSARecvFrom(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesReceivedPointer, LPDWORD flagsPointer, sockaddr* fromPointer, LPINT fromLengthPointer, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer, int resultValue)
{ BuildSocketDetail(detailBuffer, L"recvfrom", socketValue, SumWsaBufferLength(buffersPointer, bufferCount), bytesReceivedPointer != nullptr ? static_cast<int>(*bytesReceivedPointer) : 0, flagsPointer != nullptr ? *flagsPointer : 0, fromPointer, fromLengthPointer != nullptr ? *fromLengthPointer : 0); }

void CaptureGetAddrInfoW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PCWSTR nodeNamePointer, PCWSTR serviceNamePointer, const ADDRINFOW* hintsPointer, PADDRINFOW* resultPointer, INT resultValue)
{ AppendWideText(detailBuffer, L"node="); AppendWideText(detailBuffer, nodeNamePointer); AppendWideText(detailBuffer, L" service="); AppendWideText(detailBuffer, serviceNamePointer); AppendWideText(detailBuffer, L" result="); AppendHexText(detailBuffer, resultPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultPointer) : 0); }

void Capturegetaddrinfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PCSTR nodeNamePointer, PCSTR serviceNamePointer, const ADDRINFOA* hintsPointer, PADDRINFOA* resultPointer, INT resultValue)
{ AppendWideText(detailBuffer, L"node="); AppendAnsiText(detailBuffer, nodeNamePointer); AppendWideText(detailBuffer, L" service="); AppendAnsiText(detailBuffer, serviceNamePointer); AppendWideText(detailBuffer, L" result="); AppendHexText(detailBuffer, resultPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultPointer) : 0); }

void CaptureWinHttpOpen(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR userAgentPointer, DWORD accessType, LPCWSTR proxyNamePointer, LPCWSTR proxyBypassPointer, DWORD flagsValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"agent="); AppendWideText(detailBuffer, userAgentPointer); AppendWideText(detailBuffer, L" accessType="); AppendUnsignedText(detailBuffer, accessType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureWinHttpConnect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET sessionHandle, LPCWSTR serverNamePointer, INTERNET_PORT serverPort, DWORD reservedValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"session="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sessionHandle)); AppendWideText(detailBuffer, L" host="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" port="); AppendUnsignedText(detailBuffer, serverPort); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureWinHttpOpenRequest(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET connectHandle, LPCWSTR verbPointer, LPCWSTR objectNamePointer, LPCWSTR versionPointer, LPCWSTR referrerPointer, LPCWSTR* acceptTypesPointer, DWORD flagsValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"connect="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(connectHandle)); AppendWideText(detailBuffer, L" verb="); AppendWideText(detailBuffer, verbPointer); AppendWideText(detailBuffer, L" object="); AppendWideText(detailBuffer, objectNamePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureWinHttpSendRequest(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPCWSTR headersPointer, DWORD headersLength, LPVOID optionalPointer, DWORD optionalLength, DWORD totalLength, DWORD_PTR contextValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" headersLen="); AppendUnsignedText(detailBuffer, headersLength); AppendWideText(detailBuffer, L" optionalLen="); AppendUnsignedText(detailBuffer, optionalLength); AppendWideText(detailBuffer, L" total="); AppendUnsignedText(detailBuffer, totalLength); }

void CaptureWinHttpReceiveResponse(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPVOID reservedPointer, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"request", requestHandle); }

void CaptureWinHttpReadData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPVOID bufferPointer, DWORD bytesToRead, LPDWORD bytesReadPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" requestBytes="); AppendUnsignedText(detailBuffer, bytesToRead); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); }

void CaptureWinHttpWriteData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPCVOID bufferPointer, DWORD bytesToWrite, LPDWORD bytesWrittenPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" requestBytes="); AppendUnsignedText(detailBuffer, bytesToWrite); AppendWideText(detailBuffer, L" written="); AppendUnsignedText(detailBuffer, bytesWrittenPointer != nullptr ? *bytesWrittenPointer : 0); }

void CaptureWinHttpQueryHeaders(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, DWORD infoLevel, LPCWSTR namePointer, LPVOID bufferPointer, LPDWORD bufferLengthPointer, LPDWORD indexPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" level="); AppendHexText(detailBuffer, infoLevel); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); }

void CaptureWinHttpQueryDataAvailable(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPDWORD bytesAvailablePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" available="); AppendUnsignedText(detailBuffer, bytesAvailablePointer != nullptr ? *bytesAvailablePointer : 0); }

void CaptureWinHttpSetOption(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, DWORD bufferLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" option="); AppendHexText(detailBuffer, optionValue); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLength); }

void CaptureWinHttpCloseHandle(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"handle", internetHandle); }

void CaptureInternetOpenW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR agentPointer, DWORD accessType, LPCWSTR proxyNamePointer, LPCWSTR proxyBypassPointer, DWORD flagsValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"agent="); AppendWideText(detailBuffer, agentPointer); AppendWideText(detailBuffer, L" accessType="); AppendUnsignedText(detailBuffer, accessType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureInternetOpenA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR agentPointer, DWORD accessType, LPCSTR proxyNamePointer, LPCSTR proxyBypassPointer, DWORD flagsValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"agent="); AppendAnsiText(detailBuffer, agentPointer); AppendWideText(detailBuffer, L" accessType="); AppendUnsignedText(detailBuffer, accessType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureInternetConnectW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, LPCWSTR serverNamePointer, INTERNET_PORT serverPort, LPCWSTR userNamePointer, LPCWSTR passwordPointer, DWORD serviceValue, DWORD flagsValue, DWORD_PTR contextValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"root="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" host="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" port="); AppendUnsignedText(detailBuffer, serverPort); AppendWideText(detailBuffer, L" service="); AppendUnsignedText(detailBuffer, serviceValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureInternetConnectA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, LPCSTR serverNamePointer, INTERNET_PORT serverPort, LPCSTR userNamePointer, LPCSTR passwordPointer, DWORD serviceValue, DWORD flagsValue, DWORD_PTR contextValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"root="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" host="); AppendAnsiText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" port="); AppendUnsignedText(detailBuffer, serverPort); AppendWideText(detailBuffer, L" service="); AppendUnsignedText(detailBuffer, serviceValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureHttpOpenRequestW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET connectHandle, LPCWSTR verbPointer, LPCWSTR objectNamePointer, LPCWSTR versionPointer, LPCWSTR referrerPointer, LPCWSTR* acceptTypesPointer, DWORD flagsValue, DWORD_PTR contextValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"connect="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(connectHandle)); AppendWideText(detailBuffer, L" verb="); AppendWideText(detailBuffer, verbPointer); AppendWideText(detailBuffer, L" object="); AppendWideText(detailBuffer, objectNamePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureHttpOpenRequestA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET connectHandle, LPCSTR verbPointer, LPCSTR objectNamePointer, LPCSTR versionPointer, LPCSTR referrerPointer, LPCSTR* acceptTypesPointer, DWORD flagsValue, DWORD_PTR contextValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"connect="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(connectHandle)); AppendWideText(detailBuffer, L" verb="); AppendAnsiText(detailBuffer, verbPointer); AppendWideText(detailBuffer, L" object="); AppendAnsiText(detailBuffer, objectNamePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureHttpSendRequestW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPCWSTR headersPointer, DWORD headersLength, LPVOID optionalPointer, DWORD optionalLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" headersLen="); AppendUnsignedText(detailBuffer, headersLength); AppendWideText(detailBuffer, L" optionalLen="); AppendUnsignedText(detailBuffer, optionalLength); }

void CaptureHttpSendRequestA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPCSTR headersPointer, DWORD headersLength, LPVOID optionalPointer, DWORD optionalLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" headersLen="); AppendUnsignedText(detailBuffer, headersLength); AppendWideText(detailBuffer, L" optionalLen="); AppendUnsignedText(detailBuffer, optionalLength); }

void CaptureInternetReadFile(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET fileHandle, LPVOID bufferPointer, DWORD bytesToRead, LPDWORD bytesReadPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" requestBytes="); AppendUnsignedText(detailBuffer, bytesToRead); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); }

void CaptureInternetWriteFile(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET fileHandle, LPCVOID bufferPointer, DWORD bytesToWrite, LPDWORD bytesWrittenPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" requestBytes="); AppendUnsignedText(detailBuffer, bytesToWrite); AppendWideText(detailBuffer, L" written="); AppendUnsignedText(detailBuffer, bytesWrittenPointer != nullptr ? *bytesWrittenPointer : 0); }

void CaptureInternetOpenUrlW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, LPCWSTR urlPointer, LPCWSTR headersPointer, DWORD headersLength, DWORD flagsValue, DWORD_PTR contextValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"root="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" url="); AppendWideText(detailBuffer, urlPointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureInternetOpenUrlA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, LPCSTR urlPointer, LPCSTR headersPointer, DWORD headersLength, DWORD flagsValue, DWORD_PTR contextValue, HINTERNET resultHandle)
{ AppendWideText(detailBuffer, L"root="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" url="); AppendAnsiText(detailBuffer, urlPointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureInternetQueryDataAvailable(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET fileHandle, LPDWORD bytesAvailablePointer, DWORD flagsValue, DWORD_PTR contextValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle)); AppendWideText(detailBuffer, L" available="); AppendUnsignedText(detailBuffer, bytesAvailablePointer != nullptr ? *bytesAvailablePointer : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureInternetSetOptionW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, DWORD bufferLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" option="); AppendHexText(detailBuffer, optionValue); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLength); }

void CaptureInternetSetOptionA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, DWORD bufferLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" option="); AppendHexText(detailBuffer, optionValue); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLength); }

void CaptureInternetCrackUrlW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR urlPointer, DWORD urlLength, DWORD flagsValue, LPURL_COMPONENTSW componentsPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"url="); AppendWideText(detailBuffer, urlPointer, urlLength != 0 ? urlLength : static_cast<std::size_t>(-1)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureInternetCrackUrlA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR urlPointer, DWORD urlLength, DWORD flagsValue, LPURL_COMPONENTSA componentsPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"url="); AppendAnsiText(detailBuffer, urlPointer, urlLength != 0 ? urlLength : static_cast<std::size_t>(-1)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureInternetCloseHandle(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"handle", internetHandle); }

void CaptureBCryptOpenAlgorithmProvider(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE* algorithmHandlePointer, LPCWSTR algorithmIdPointer, LPCWSTR implementationPointer, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"alg="); AppendWideText(detailBuffer, algorithmIdPointer); AppendWideText(detailBuffer, L" impl="); AppendWideText(detailBuffer, implementationPointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, algorithmHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*algorithmHandlePointer) : 0); }

void CaptureBCryptCreateHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_HASH_HANDLE* hashHandlePointer, PUCHAR hashObjectPointer, ULONG hashObjectLength, PUCHAR secretPointer, ULONG secretLength, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"algHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); AppendWideText(detailBuffer, L" objectLen="); AppendUnsignedText(detailBuffer, hashObjectLength); AppendWideText(detailBuffer, L" secretLen="); AppendUnsignedText(detailBuffer, secretLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" hash="); AppendHexText(detailBuffer, hashHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*hashHandlePointer) : 0); }

void CaptureBCryptHashData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_HASH_HANDLE hashHandle, PUCHAR inputPointer, ULONG inputLength, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"hash="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hashHandle)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureBCryptFinishHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_HASH_HANDLE hashHandle, PUCHAR outputPointer, ULONG outputLength, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"hash="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hashHandle)); AppendWideText(detailBuffer, L" outputLen="); AppendUnsignedText(detailBuffer, outputLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureBCryptEncrypt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE keyHandle, PUCHAR inputPointer, ULONG inputLength, VOID* paddingInfoPointer, PUCHAR ivPointer, ULONG ivLength, PUCHAR outputPointer, ULONG outputLength, ULONG* resultLengthPointer, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" inputLen="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" outputLen="); AppendUnsignedText(detailBuffer, outputLength); AppendWideText(detailBuffer, L" resultLen="); AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureBCryptDecrypt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE keyHandle, PUCHAR inputPointer, ULONG inputLength, VOID* paddingInfoPointer, PUCHAR ivPointer, ULONG ivLength, PUCHAR outputPointer, ULONG outputLength, ULONG* resultLengthPointer, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" inputLen="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" outputLen="); AppendUnsignedText(detailBuffer, outputLength); AppendWideText(detailBuffer, L" resultLen="); AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureBCryptGenRandom(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE algorithmHandle, PUCHAR bufferPointer, ULONG bufferLength, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"algHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bufferLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureBCryptCloseAlgorithmProvider(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE algorithmHandle, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"algHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureBCryptDestroyHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_HASH_HANDLE hashHandle, NTSTATUS statusValue)
{ BuildSimpleHandleDetail(detailBuffer, L"hash", hashHandle); }

void CaptureBCryptGenerateSymmetricKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_KEY_HANDLE* keyHandlePointer, PUCHAR keyObjectPointer, ULONG keyObjectLength, PUCHAR secretPointer, ULONG secretLength, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"algHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); AppendWideText(detailBuffer, L" objectLen="); AppendUnsignedText(detailBuffer, keyObjectLength); AppendWideText(detailBuffer, L" secretLen="); AppendUnsignedText(detailBuffer, secretLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureBCryptImportKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_KEY_HANDLE importKeyHandle, LPCWSTR blobTypePointer, BCRYPT_KEY_HANDLE* keyHandlePointer, PUCHAR keyObjectPointer, ULONG keyObjectLength, PUCHAR inputPointer, ULONG inputLength, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"algHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); AppendWideText(detailBuffer, L" blobType="); AppendWideText(detailBuffer, blobTypePointer); AppendWideText(detailBuffer, L" inputLen="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureBCryptImportKeyPair(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_ALG_HANDLE algorithmHandle, BCRYPT_KEY_HANDLE importKeyHandle, LPCWSTR blobTypePointer, BCRYPT_KEY_HANDLE* keyHandlePointer, PUCHAR inputPointer, ULONG inputLength, ULONG flagsValue, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"algHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(algorithmHandle)); AppendWideText(detailBuffer, L" blobType="); AppendWideText(detailBuffer, blobTypePointer); AppendWideText(detailBuffer, L" inputLen="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureBCryptDestroyKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], BCRYPT_KEY_HANDLE keyHandle, NTSTATUS statusValue)
{ BuildSimpleHandleDetail(detailBuffer, L"key", keyHandle); }

void CaptureCoInitializeEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID reservedPointer, DWORD coInitValue, HRESULT statusValue)
{ AppendWideText(detailBuffer, L"coinit="); AppendHexText(detailBuffer, coInitValue); }

void CaptureCoInitializeSecurity(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PSECURITY_DESCRIPTOR securityDescriptorPointer, LONG authServiceCount, SOLE_AUTHENTICATION_SERVICE* authServicesPointer, void* reserved1Pointer, DWORD authnLevel, DWORD impLevel, void* authListPointer, DWORD capabilitiesValue, void* reserved3Pointer, HRESULT statusValue)
{ AppendWideText(detailBuffer, L"authCount="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(authServiceCount < 0 ? 0 : authServiceCount)); AppendWideText(detailBuffer, L" authnLevel="); AppendHexText(detailBuffer, authnLevel); AppendWideText(detailBuffer, L" impLevel="); AppendHexText(detailBuffer, impLevel); AppendWideText(detailBuffer, L" caps="); AppendHexText(detailBuffer, capabilitiesValue); }

void CaptureCoCreateInstance(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFCLSID classId, LPUNKNOWN outerUnknownPointer, DWORD classContext, REFIID interfaceId, LPVOID* objectPointer, HRESULT statusValue)
{ AppendWideText(detailBuffer, L"clsctx="); AppendHexText(detailBuffer, classContext); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, objectPointer != nullptr ? reinterpret_cast<std::uint64_t>(*objectPointer) : 0); }

void CaptureCoCreateInstanceEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFCLSID classId, IUnknown* outerUnknownPointer, DWORD classContext, COSERVERINFO* serverInfoPointer, DWORD multiQiCount, MULTI_QI* resultsPointer, HRESULT statusValue)
{ AppendWideText(detailBuffer, L"clsctx="); AppendHexText(detailBuffer, classContext); AppendWideText(detailBuffer, L" qiCount="); AppendUnsignedText(detailBuffer, multiQiCount); AppendWideText(detailBuffer, L" server="); AppendWideText(detailBuffer, serverInfoPointer != nullptr ? serverInfoPointer->pwszName : nullptr); }

void CaptureCoGetClassObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REFCLSID classId, DWORD classContext, COSERVERINFO* serverInfoPointer, REFIID interfaceId, LPVOID* classObjectPointer, HRESULT statusValue)
{ AppendWideText(detailBuffer, L"clsctx="); AppendHexText(detailBuffer, classContext); AppendWideText(detailBuffer, L" factory="); AppendHexText(detailBuffer, classObjectPointer != nullptr ? reinterpret_cast<std::uint64_t>(*classObjectPointer) : 0); AppendWideText(detailBuffer, L" server="); AppendWideText(detailBuffer, serverInfoPointer != nullptr ? serverInfoPointer->pwszName : nullptr); }

void CaptureSetWindowsHookExW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int hookId, HOOKPROC hookProcPointer, HINSTANCE moduleHandle, DWORD threadId, HHOOK resultHandle)
{ AppendWideText(detailBuffer, L"id="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(hookId < 0 ? 0 : hookId)); AppendWideText(detailBuffer, L" proc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hookProcPointer)); AppendWideText(detailBuffer, L" module="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle)); AppendWideText(detailBuffer, L" tid="); AppendUnsignedText(detailBuffer, threadId); AppendWideText(detailBuffer, L" hook="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureSetWindowsHookExA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int hookId, HOOKPROC hookProcPointer, HINSTANCE moduleHandle, DWORD threadId, HHOOK resultHandle)
{ AppendWideText(detailBuffer, L"id="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(hookId < 0 ? 0 : hookId)); AppendWideText(detailBuffer, L" proc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(hookProcPointer)); AppendWideText(detailBuffer, L" module="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle)); AppendWideText(detailBuffer, L" tid="); AppendUnsignedText(detailBuffer, threadId); AppendWideText(detailBuffer, L" hook="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureUnhookWindowsHookEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HHOOK hookHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"hook", hookHandle); }

void CaptureEnumProcesses(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD* processIdsPointer, DWORD bytesValue, DWORD* bytesNeededPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"bytes="); AppendUnsignedText(detailBuffer, bytesValue); AppendWideText(detailBuffer, L" needed="); AppendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); }

void CaptureEnumProcessModules(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, HMODULE* modulePointer, DWORD bytesValue, LPDWORD bytesNeededPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bytesValue); AppendWideText(detailBuffer, L" needed="); AppendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); }

void CaptureEnumProcessModulesEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, HMODULE* modulePointer, DWORD bytesValue, LPDWORD bytesNeededPointer, DWORD filterFlag, BOOL resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bytesValue); AppendWideText(detailBuffer, L" needed="); AppendUnsignedText(detailBuffer, bytesNeededPointer != nullptr ? *bytesNeededPointer : 0); AppendWideText(detailBuffer, L" filter="); AppendHexText(detailBuffer, filterFlag); }

void CaptureGetMappedFileNameW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, LPVOID baseAddress, LPWSTR fileNamePointer, DWORD sizeValue, DWORD resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizeValue); AppendWideText(detailBuffer, L" path="); if (resultValue != 0) { AppendWideText(detailBuffer, fileNamePointer, resultValue); } }

void CaptureGetMappedFileNameA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, LPVOID baseAddress, LPSTR fileNamePointer, DWORD sizeValue, DWORD resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizeValue); AppendWideText(detailBuffer, L" path="); if (resultValue != 0) { AppendAnsiText(detailBuffer, fileNamePointer, resultValue); } }

void CaptureEnumWindows(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], WNDENUMPROC callbackPointer, LPARAM parameterValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"callback="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(callbackPointer)); AppendWideText(detailBuffer, L" param="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(parameterValue)); }

void CaptureEnumChildWindows(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND parentWindow, WNDENUMPROC callbackPointer, LPARAM parameterValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"parent="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentWindow)); AppendWideText(detailBuffer, L" callback="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(callbackPointer)); AppendWideText(detailBuffer, L" param="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(parameterValue)); }

void CaptureFindWindowW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR classNamePointer, LPCWSTR windowNamePointer, HWND resultHandle)
{ AppendWideText(detailBuffer, L"class="); AppendWideText(detailBuffer, classNamePointer); AppendWideText(detailBuffer, L" title="); AppendWideText(detailBuffer, windowNamePointer); AppendWideText(detailBuffer, L" hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureFindWindowA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR classNamePointer, LPCSTR windowNamePointer, HWND resultHandle)
{ AppendWideText(detailBuffer, L"class="); AppendAnsiText(detailBuffer, classNamePointer); AppendWideText(detailBuffer, L" title="); AppendAnsiText(detailBuffer, windowNamePointer); AppendWideText(detailBuffer, L" hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureFindWindowExW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND parentWindow, HWND childAfterWindow, LPCWSTR classNamePointer, LPCWSTR windowNamePointer, HWND resultHandle)
{ AppendWideText(detailBuffer, L"parent="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentWindow)); AppendWideText(detailBuffer, L" after="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(childAfterWindow)); AppendWideText(detailBuffer, L" class="); AppendWideText(detailBuffer, classNamePointer); AppendWideText(detailBuffer, L" title="); AppendWideText(detailBuffer, windowNamePointer); AppendWideText(detailBuffer, L" hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureFindWindowExA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND parentWindow, HWND childAfterWindow, LPCSTR classNamePointer, LPCSTR windowNamePointer, HWND resultHandle)
{ AppendWideText(detailBuffer, L"parent="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentWindow)); AppendWideText(detailBuffer, L" after="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(childAfterWindow)); AppendWideText(detailBuffer, L" class="); AppendAnsiText(detailBuffer, classNamePointer); AppendWideText(detailBuffer, L" title="); AppendAnsiText(detailBuffer, windowNamePointer); AppendWideText(detailBuffer, L" hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureGetWindowThreadProcessId(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND windowHandle, LPDWORD processIdPointer, DWORD resultValue)
{ AppendWideText(detailBuffer, L"hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, processIdPointer != nullptr ? *processIdPointer : 0); AppendWideText(detailBuffer, L" tid="); AppendUnsignedText(detailBuffer, resultValue); }

void CaptureGetForegroundWindow(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND resultHandle)
{ AppendWideText(detailBuffer, L"hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureGetDC(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND windowHandle, HDC resultHandle)
{ AppendWideText(detailBuffer, L"hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); AppendWideText(detailBuffer, L" dc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureReleaseDC(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND windowHandle, HDC deviceContext, int resultValue)
{ AppendWideText(detailBuffer, L"hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); AppendWideText(detailBuffer, L" dc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); AppendWideText(detailBuffer, L" result="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(resultValue < 0 ? 0 : resultValue)); }

void CaptureCreateCompatibleDC(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC deviceContext, HDC resultHandle)
{ AppendWideText(detailBuffer, L"sourceDc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); AppendWideText(detailBuffer, L" dc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureDeleteDC(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC deviceContext, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); }

void CaptureCreateCompatibleBitmap(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC deviceContext, int widthValue, int heightValue, HBITMAP resultHandle)
{ AppendWideText(detailBuffer, L"dc="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceContext)); AppendWideText(detailBuffer, L" width="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthValue < 0 ? 0 : widthValue)); AppendWideText(detailBuffer, L" height="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightValue < 0 ? 0 : heightValue)); AppendWideText(detailBuffer, L" bitmap="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureBitBlt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC destinationDc, int xDest, int yDest, int widthValue, int heightValue, HDC sourceDc, int xSource, int ySource, DWORD ropValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dst="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destinationDc)); AppendWideText(detailBuffer, L" src="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceDc)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthValue < 0 ? 0 : widthValue)); AppendWideText(detailBuffer, L"x"); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightValue < 0 ? 0 : heightValue)); AppendWideText(detailBuffer, L" rop="); AppendHexText(detailBuffer, ropValue); }

void CaptureStretchBlt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HDC destinationDc, int xDest, int yDest, int widthDest, int heightDest, HDC sourceDc, int xSource, int ySource, int widthSource, int heightSource, DWORD ropValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"dst="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destinationDc)); AppendWideText(detailBuffer, L" src="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceDc)); AppendWideText(detailBuffer, L" dstSize="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthDest < 0 ? 0 : widthDest)); AppendWideText(detailBuffer, L"x"); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightDest < 0 ? 0 : heightDest)); AppendWideText(detailBuffer, L" srcSize="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(widthSource < 0 ? 0 : widthSource)); AppendWideText(detailBuffer, L"x"); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(heightSource < 0 ? 0 : heightSource)); AppendWideText(detailBuffer, L" rop="); AppendHexText(detailBuffer, ropValue); }

void CaptureDeleteObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HGDIOBJ objectHandle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"object="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); }

void CaptureStartTraceW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PTRACEHANDLE traceHandlePointer, LPCWSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, instanceNamePointer); AppendWideText(detailBuffer, L" trace="); AppendHexText(detailBuffer, traceHandlePointer != nullptr ? *traceHandlePointer : 0); AppendWideText(detailBuffer, L" props="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(propertiesPointer)); }

void CaptureStartTraceA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PTRACEHANDLE traceHandlePointer, LPCSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, instanceNamePointer); AppendWideText(detailBuffer, L" trace="); AppendHexText(detailBuffer, traceHandlePointer != nullptr ? *traceHandlePointer : 0); AppendWideText(detailBuffer, L" props="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(propertiesPointer)); }

void CaptureControlTraceW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], TRACEHANDLE traceHandle, LPCWSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer, ULONG controlCode, ULONG statusValue)
{ AppendWideText(detailBuffer, L"trace="); AppendHexText(detailBuffer, traceHandle); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, instanceNamePointer); AppendWideText(detailBuffer, L" control="); AppendHexText(detailBuffer, controlCode); }

void CaptureControlTraceA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], TRACEHANDLE traceHandle, LPCSTR instanceNamePointer, PEVENT_TRACE_PROPERTIES propertiesPointer, ULONG controlCode, ULONG statusValue)
{ AppendWideText(detailBuffer, L"trace="); AppendHexText(detailBuffer, traceHandle); AppendWideText(detailBuffer, L" name="); AppendAnsiText(detailBuffer, instanceNamePointer); AppendWideText(detailBuffer, L" control="); AppendHexText(detailBuffer, controlCode); }

void CaptureEnableTraceEx2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], TRACEHANDLE traceHandle, LPCGUID providerIdPointer, ULONG controlCode, UCHAR levelValue, ULONGLONG matchAnyKeyword, ULONGLONG matchAllKeyword, ULONG timeoutValue, void* enableParametersPointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"trace="); AppendHexText(detailBuffer, traceHandle); AppendWideText(detailBuffer, L" provider="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(providerIdPointer)); AppendWideText(detailBuffer, L" control="); AppendHexText(detailBuffer, controlCode); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, levelValue); AppendWideText(detailBuffer, L" any="); AppendHexText(detailBuffer, matchAnyKeyword); AppendWideText(detailBuffer, L" all="); AppendHexText(detailBuffer, matchAllKeyword); }

void CaptureProcessTrace(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PTRACEHANDLE traceHandleArray, ULONG handleCount, LPFILETIME startTimePointer, LPFILETIME endTimePointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"count="); AppendUnsignedText(detailBuffer, handleCount); AppendWideText(detailBuffer, L" first="); AppendHexText(detailBuffer, traceHandleArray != nullptr && handleCount != 0 ? traceHandleArray[0] : 0); }

void CaptureCloseTrace(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], TRACEHANDLE traceHandle, ULONG statusValue)
{ AppendWideText(detailBuffer, L"trace="); AppendHexText(detailBuffer, traceHandle); }

void CaptureEventRegister(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCGUID providerIdPointer, PENABLECALLBACK callbackPointer, PVOID callbackContextPointer, PREGHANDLE registrationHandlePointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(providerIdPointer)); AppendWideText(detailBuffer, L" callback="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(callbackPointer)); AppendWideText(detailBuffer, L" reg="); AppendHexText(detailBuffer, registrationHandlePointer != nullptr ? *registrationHandlePointer : 0); }

void CaptureEventUnregister(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REGHANDLE registrationHandle, ULONG statusValue)
{ AppendWideText(detailBuffer, L"reg="); AppendHexText(detailBuffer, registrationHandle); }

void CaptureEventWrite(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REGHANDLE registrationHandle, PCEVENT_DESCRIPTOR eventDescriptorPointer, ULONG userDataCount, PEVENT_DATA_DESCRIPTOR userDataPointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"reg="); AppendHexText(detailBuffer, registrationHandle); AppendWideText(detailBuffer, L" event="); AppendUnsignedText(detailBuffer, eventDescriptorPointer != nullptr ? eventDescriptorPointer->Id : 0); AppendWideText(detailBuffer, L" fields="); AppendUnsignedText(detailBuffer, userDataCount); }

void CaptureEventWriteEx(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], REGHANDLE registrationHandle, PCEVENT_DESCRIPTOR eventDescriptorPointer, ULONG64 filterValue, ULONG flagsValue, LPCGUID activityIdPointer, LPCGUID relatedActivityIdPointer, ULONG userDataCount, PEVENT_DATA_DESCRIPTOR userDataPointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"reg="); AppendHexText(detailBuffer, registrationHandle); AppendWideText(detailBuffer, L" event="); AppendUnsignedText(detailBuffer, eventDescriptorPointer != nullptr ? eventDescriptorPointer->Id : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" fields="); AppendUnsignedText(detailBuffer, userDataCount); }

void CaptureWinVerifyTrust(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HWND windowHandle, GUID* actionIdPointer, LPVOID dataPointer, LONG statusValue)
{ AppendWideText(detailBuffer, L"hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); AppendWideText(detailBuffer, L" action="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(actionIdPointer)); AppendWideText(detailBuffer, L" data="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(dataPointer)); }

void CaptureCryptQueryObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD objectType, const void* objectPointer, DWORD expectedContentTypeFlags, DWORD expectedFormatTypeFlags, DWORD flagsValue, DWORD* encodingTypePointer, DWORD* contentTypePointer, DWORD* formatTypePointer, HCERTSTORE* certStorePointer, HCRYPTMSG* cryptMsgPointer, const void** contextPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"type="); AppendHexText(detailBuffer, objectType); AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectPointer)); AppendWideText(detailBuffer, L" content="); AppendHexText(detailBuffer, contentTypePointer != nullptr ? *contentTypePointer : 0); AppendWideText(detailBuffer, L" format="); AppendHexText(detailBuffer, formatTypePointer != nullptr ? *formatTypePointer : 0); }

void CaptureCertOpenStore(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR storeProviderPointer, DWORD encodingType, HCRYPTPROV_LEGACY cryptProvider, DWORD flagsValue, const void* parameterPointer, HCERTSTORE resultHandle)
{ AppendWideText(detailBuffer, L"provider="); AppendAnsiText(detailBuffer, storeProviderPointer); AppendWideText(detailBuffer, L" encoding="); AppendHexText(detailBuffer, encodingType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" store="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCertCloseStore(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCERTSTORE certStoreHandle, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"store="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(certStoreHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureCertFindCertificateInStore(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCERTSTORE certStoreHandle, DWORD encodingType, DWORD findFlags, DWORD findType, const void* findParaPointer, PCCERT_CONTEXT previousContextPointer, PCCERT_CONTEXT resultHandle)
{ AppendWideText(detailBuffer, L"store="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(certStoreHandle)); AppendWideText(detailBuffer, L" findType="); AppendHexText(detailBuffer, findType); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, findFlags); AppendWideText(detailBuffer, L" cert="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCertGetCertificateChain(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HCERTCHAINENGINE chainEngineHandle, PCCERT_CONTEXT certContextPointer, LPFILETIME timePointer, HCERTSTORE additionalStoreHandle, PCERT_CHAIN_PARA chainParaPointer, DWORD flagsValue, LPVOID reservedPointer, PCCERT_CHAIN_CONTEXT* chainContextPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"engine="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(chainEngineHandle)); AppendWideText(detailBuffer, L" cert="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(certContextPointer)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" chain="); AppendHexText(detailBuffer, chainContextPointer != nullptr ? reinterpret_cast<std::uint64_t>(*chainContextPointer) : 0); }

void CaptureCertVerifyCertificateChainPolicy(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR policyPointer, PCCERT_CHAIN_CONTEXT chainContextPointer, PCERT_CHAIN_POLICY_PARA policyParaPointer, PCERT_CHAIN_POLICY_STATUS policyStatusPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"policy="); AppendAnsiText(detailBuffer, policyPointer); AppendWideText(detailBuffer, L" chain="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(chainContextPointer)); AppendWideText(detailBuffer, L" error="); AppendHexText(detailBuffer, policyStatusPointer != nullptr ? policyStatusPointer->dwError : 0); }

void CaptureCryptProtectData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DATA_BLOB* dataInPointer, LPCWSTR descriptionPointer, DATA_BLOB* optionalEntropyPointer, PVOID reservedPointer, CRYPTPROTECT_PROMPTSTRUCT* promptPointer, DWORD flagsValue, DATA_BLOB* dataOutPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"inBytes="); AppendUnsignedText(detailBuffer, dataInPointer != nullptr ? dataInPointer->cbData : 0); AppendWideText(detailBuffer, L" entropyBytes="); AppendUnsignedText(detailBuffer, optionalEntropyPointer != nullptr ? optionalEntropyPointer->cbData : 0); AppendWideText(detailBuffer, L" outBytes="); AppendUnsignedText(detailBuffer, dataOutPointer != nullptr ? dataOutPointer->cbData : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" desc="); AppendWideText(detailBuffer, descriptionPointer); }

void CaptureCryptUnprotectData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DATA_BLOB* dataInPointer, LPWSTR* descriptionPointer, DATA_BLOB* optionalEntropyPointer, PVOID reservedPointer, CRYPTPROTECT_PROMPTSTRUCT* promptPointer, DWORD flagsValue, DATA_BLOB* dataOutPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"inBytes="); AppendUnsignedText(detailBuffer, dataInPointer != nullptr ? dataInPointer->cbData : 0); AppendWideText(detailBuffer, L" entropyBytes="); AppendUnsignedText(detailBuffer, optionalEntropyPointer != nullptr ? optionalEntropyPointer->cbData : 0); AppendWideText(detailBuffer, L" outBytes="); AppendUnsignedText(detailBuffer, dataOutPointer != nullptr ? dataOutPointer->cbData : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" desc="); AppendWideText(detailBuffer, descriptionPointer != nullptr ? *descriptionPointer : nullptr); }

void CaptureNCryptOpenStorageProvider(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_PROV_HANDLE* providerHandlePointer, LPCWSTR providerNamePointer, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, providerNamePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" provider="); AppendHexText(detailBuffer, providerHandlePointer != nullptr ? static_cast<std::uint64_t>(*providerHandlePointer) : 0); }

void CaptureNCryptOpenKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_PROV_HANDLE providerHandle, NCRYPT_KEY_HANDLE* keyHandlePointer, LPCWSTR keyNamePointer, DWORD legacyKeySpec, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, keyNamePointer); AppendWideText(detailBuffer, L" spec="); AppendHexText(detailBuffer, legacyKeySpec); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureNCryptCreatePersistedKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_PROV_HANDLE providerHandle, NCRYPT_KEY_HANDLE* keyHandlePointer, LPCWSTR algorithmIdPointer, LPCWSTR keyNamePointer, DWORD legacyKeySpec, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" alg="); AppendWideText(detailBuffer, algorithmIdPointer); AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, keyNamePointer); AppendWideText(detailBuffer, L" spec="); AppendHexText(detailBuffer, legacyKeySpec); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); }

void CaptureNCryptFinalizeKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_KEY_HANDLE keyHandle, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptEncrypt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_KEY_HANDLE keyHandle, PBYTE inputPointer, DWORD inputLength, VOID* paddingInfoPointer, PBYTE outputPointer, DWORD outputLength, DWORD* resultLengthPointer, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" in="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" out="); AppendUnsignedText(detailBuffer, outputLength); AppendWideText(detailBuffer, L" result="); AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptDecrypt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_KEY_HANDLE keyHandle, PBYTE inputPointer, DWORD inputLength, VOID* paddingInfoPointer, PBYTE outputPointer, DWORD outputLength, DWORD* resultLengthPointer, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" in="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" out="); AppendUnsignedText(detailBuffer, outputLength); AppendWideText(detailBuffer, L" result="); AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptSignHash(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_KEY_HANDLE keyHandle, VOID* paddingInfoPointer, PBYTE hashValuePointer, DWORD hashValueLength, PBYTE signaturePointer, DWORD signatureLength, DWORD* resultLengthPointer, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" hash="); AppendUnsignedText(detailBuffer, hashValueLength); AppendWideText(detailBuffer, L" sig="); AppendUnsignedText(detailBuffer, signatureLength); AppendWideText(detailBuffer, L" result="); AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptVerifySignature(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_KEY_HANDLE keyHandle, VOID* paddingInfoPointer, PBYTE hashValuePointer, DWORD hashValueLength, PBYTE signaturePointer, DWORD signatureLength, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" hash="); AppendUnsignedText(detailBuffer, hashValueLength); AppendWideText(detailBuffer, L" sig="); AppendUnsignedText(detailBuffer, signatureLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptExportKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_KEY_HANDLE keyHandle, NCRYPT_KEY_HANDLE exportKeyHandle, LPCWSTR blobTypePointer, VOID* parameterListPointer, PBYTE outputPointer, DWORD outputLength, DWORD* resultLengthPointer, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" blob="); AppendWideText(detailBuffer, blobTypePointer); AppendWideText(detailBuffer, L" out="); AppendUnsignedText(detailBuffer, outputLength); AppendWideText(detailBuffer, L" result="); AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptImportKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_PROV_HANDLE providerHandle, NCRYPT_KEY_HANDLE importKeyHandle, LPCWSTR blobTypePointer, VOID* parameterListPointer, NCRYPT_KEY_HANDLE* keyHandlePointer, PBYTE inputPointer, DWORD inputLength, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"provider="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(providerHandle)); AppendWideText(detailBuffer, L" blob="); AppendWideText(detailBuffer, blobTypePointer); AppendWideText(detailBuffer, L" in="); AppendUnsignedText(detailBuffer, inputLength); AppendWideText(detailBuffer, L" key="); AppendHexText(detailBuffer, keyHandlePointer != nullptr ? static_cast<std::uint64_t>(*keyHandlePointer) : 0); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptDeleteKey(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_KEY_HANDLE keyHandle, DWORD flagsValue, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"key="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(keyHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureNCryptFreeObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], NCRYPT_HANDLE objectHandle, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"object="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(objectHandle)); }

void CaptureRpcStringBindingComposeW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_WSTR objUuidPointer, RPC_WSTR protocolSequencePointer, RPC_WSTR networkAddressPointer, RPC_WSTR endpointPointer, RPC_WSTR optionsPointer, RPC_WSTR* stringBindingPointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"protseq="); AppendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(protocolSequencePointer)); AppendWideText(detailBuffer, L" addr="); AppendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(networkAddressPointer)); AppendWideText(detailBuffer, L" endpoint="); AppendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(endpointPointer)); AppendWideText(detailBuffer, L" binding="); AppendHexText(detailBuffer, stringBindingPointer != nullptr ? reinterpret_cast<std::uint64_t>(*stringBindingPointer) : 0); }

void CaptureRpcStringBindingComposeA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_CSTR objUuidPointer, RPC_CSTR protocolSequencePointer, RPC_CSTR networkAddressPointer, RPC_CSTR endpointPointer, RPC_CSTR optionsPointer, RPC_CSTR* stringBindingPointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"protseq="); AppendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(protocolSequencePointer)); AppendWideText(detailBuffer, L" addr="); AppendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(networkAddressPointer)); AppendWideText(detailBuffer, L" endpoint="); AppendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(endpointPointer)); AppendWideText(detailBuffer, L" binding="); AppendHexText(detailBuffer, stringBindingPointer != nullptr ? reinterpret_cast<std::uint64_t>(*stringBindingPointer) : 0); }

void CaptureRpcBindingFromStringBindingW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_WSTR stringBindingPointer, RPC_BINDING_HANDLE* bindingHandlePointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"bindingText="); AppendWideText(detailBuffer, reinterpret_cast<LPCWSTR>(stringBindingPointer)); AppendWideText(detailBuffer, L" binding="); AppendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); }

void CaptureRpcBindingFromStringBindingA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_CSTR stringBindingPointer, RPC_BINDING_HANDLE* bindingHandlePointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"bindingText="); AppendAnsiText(detailBuffer, reinterpret_cast<LPCSTR>(stringBindingPointer)); AppendWideText(detailBuffer, L" binding="); AppendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); }

void CaptureRpcBindingFree(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_BINDING_HANDLE* bindingHandlePointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"binding="); AppendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); }

void CaptureRpcMgmtEpEltInqBegin(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_BINDING_HANDLE endpointBindingHandle, unsigned long inquiryType, RPC_IF_ID* ifIdPointer, unsigned long versionOption, UUID* objectUuidPointer, RPC_EP_INQ_HANDLE* inquiryContextPointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"binding="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(endpointBindingHandle)); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, inquiryType); AppendWideText(detailBuffer, L" versionOpt="); AppendHexText(detailBuffer, versionOption); AppendWideText(detailBuffer, L" inquiry="); AppendHexText(detailBuffer, inquiryContextPointer != nullptr ? reinterpret_cast<std::uint64_t>(*inquiryContextPointer) : 0); }

void CaptureRpcMgmtEpEltInqNextW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_EP_INQ_HANDLE inquiryContext, RPC_IF_ID* ifIdPointer, RPC_BINDING_HANDLE* bindingHandlePointer, UUID* objectUuidPointer, RPC_WSTR* annotationPointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"inquiry="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(inquiryContext)); AppendWideText(detailBuffer, L" binding="); AppendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); AppendWideText(detailBuffer, L" annotation="); AppendWideText(detailBuffer, annotationPointer != nullptr ? reinterpret_cast<LPCWSTR>(*annotationPointer) : nullptr); }

void CaptureRpcMgmtEpEltInqNextA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_EP_INQ_HANDLE inquiryContext, RPC_IF_ID* ifIdPointer, RPC_BINDING_HANDLE* bindingHandlePointer, UUID* objectUuidPointer, RPC_CSTR* annotationPointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"inquiry="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(inquiryContext)); AppendWideText(detailBuffer, L" binding="); AppendHexText(detailBuffer, bindingHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*bindingHandlePointer) : 0); AppendWideText(detailBuffer, L" annotation="); AppendAnsiText(detailBuffer, annotationPointer != nullptr ? reinterpret_cast<LPCSTR>(*annotationPointer) : nullptr); }

void CaptureRpcMgmtEpEltInqDone(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], RPC_EP_INQ_HANDLE* inquiryContextPointer, RPC_STATUS statusValue)
{ AppendWideText(detailBuffer, L"inquiry="); AppendHexText(detailBuffer, inquiryContextPointer != nullptr ? reinterpret_cast<std::uint64_t>(*inquiryContextPointer) : 0); }

void CaptureNtQueryInformationToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, ULONG infoClass, PVOID tokenInformationPointer, ULONG tokenInformationLength, PULONG returnLengthPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, infoClass); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, tokenInformationLength); AppendWideText(detailBuffer, L" return="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureNtSetInformationToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, ULONG infoClass, PVOID tokenInformationPointer, ULONG tokenInformationLength, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, infoClass); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, tokenInformationLength); }

void CaptureNtAdjustPrivilegesToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, BOOLEAN disableAllPrivileges, PTOKEN_PRIVILEGES newStatePointer, ULONG bufferLength, PTOKEN_PRIVILEGES previousStatePointer, PULONG returnLengthPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" disableAll="); AppendUnsignedText(detailBuffer, disableAllPrivileges != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" privileges="); AppendUnsignedText(detailBuffer, newStatePointer != nullptr ? newStatePointer->PrivilegeCount : 0); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLength); }

void CaptureNtCreateMutant(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE mutantHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, BOOLEAN initialOwner, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" initialOwner="); AppendUnsignedText(detailBuffer, initialOwner != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, mutantHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*mutantHandlePointer) : 0); }

void CaptureNtOpenMutant(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE mutantHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, mutantHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*mutantHandlePointer) : 0); }

void CaptureNtReleaseMutant(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE mutantHandle, PLONG previousCountPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"mutant="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(mutantHandle)); AppendWideText(detailBuffer, L" previous="); AppendUnsignedText(detailBuffer, previousCountPointer != nullptr ? static_cast<unsigned long long>(*previousCountPointer < 0 ? 0 : *previousCountPointer) : 0ULL); }

void CaptureNtCreateEvent(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE eventHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, ULONG eventType, BOOLEAN initialState, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, eventType); AppendWideText(detailBuffer, L" initial="); AppendUnsignedText(detailBuffer, initialState != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, eventHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*eventHandlePointer) : 0); }

void CaptureNtOpenEvent(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE eventHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, eventHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*eventHandlePointer) : 0); }

void CaptureNtSetEvent(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventHandle, PLONG previousStatePointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"event="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); AppendWideText(detailBuffer, L" previous="); AppendUnsignedText(detailBuffer, previousStatePointer != nullptr ? static_cast<unsigned long long>(*previousStatePointer < 0 ? 0 : *previousStatePointer) : 0ULL); }

void CaptureNtResetEvent(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventHandle, PLONG previousStatePointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"event="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); AppendWideText(detailBuffer, L" previous="); AppendUnsignedText(detailBuffer, previousStatePointer != nullptr ? static_cast<unsigned long long>(*previousStatePointer < 0 ? 0 : *previousStatePointer) : 0ULL); }

void CaptureNtWaitForSingleObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE objectHandle, BOOLEAN alertableValue, PLARGE_INTEGER timeoutPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); AppendWideText(detailBuffer, L" alertable="); AppendUnsignedText(detailBuffer, alertableValue != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" timeout="); AppendHexText(detailBuffer, timeoutPointer != nullptr ? static_cast<std::uint64_t>(timeoutPointer->QuadPart) : 0); }

void CaptureNtWaitForMultipleObjects(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], ULONG countValue, HANDLE* handlesPointer, ULONG waitType, BOOLEAN alertableValue, PLARGE_INTEGER timeoutPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"count="); AppendUnsignedText(detailBuffer, countValue); AppendWideText(detailBuffer, L" first="); AppendHexText(detailBuffer, handlesPointer != nullptr && countValue != 0 ? reinterpret_cast<std::uint64_t>(handlesPointer[0]) : 0); AppendWideText(detailBuffer, L" waitType="); AppendUnsignedText(detailBuffer, waitType); AppendWideText(detailBuffer, L" alertable="); AppendUnsignedText(detailBuffer, alertableValue != FALSE ? 1ULL : 0ULL); }

void CaptureNtQuerySystemInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], ULONG infoClass, PVOID systemInformationPointer, ULONG systemInformationLength, PULONG returnLengthPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"class="); AppendUnsignedText(detailBuffer, infoClass); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, systemInformationLength); AppendWideText(detailBuffer, L" return="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureNtQueryObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE objectHandle, ULONG infoClass, PVOID objectInformationPointer, ULONG objectInformationLength, PULONG returnLengthPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"object="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, infoClass); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, objectInformationLength); AppendWideText(detailBuffer, L" return="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureLogonUserW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR userNamePointer, LPCWSTR domainPointer, LPCWSTR passwordPointer, DWORD logonType, DWORD logonProvider, PHANDLE tokenHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"user="); AppendWideText(detailBuffer, domainPointer); AppendWideText(detailBuffer, L"\\"); AppendWideText(detailBuffer, userNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, logonType); AppendWideText(detailBuffer, L" provider="); AppendUnsignedText(detailBuffer, logonProvider); AppendWideText(detailBuffer, L" token="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureLogonUserA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR userNamePointer, LPCSTR domainPointer, LPCSTR passwordPointer, DWORD logonType, DWORD logonProvider, PHANDLE tokenHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"user="); AppendAnsiText(detailBuffer, domainPointer); AppendWideText(detailBuffer, L"\\"); AppendAnsiText(detailBuffer, userNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, logonType); AppendWideText(detailBuffer, L" provider="); AppendUnsignedText(detailBuffer, logonProvider); AppendWideText(detailBuffer, L" token="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureGetTokenInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, LPVOID tokenInformationPointer, DWORD tokenInformationLength, PDWORD returnLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, tokenInformationLength); AppendWideText(detailBuffer, L" return="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureSetTokenInformation(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, TOKEN_INFORMATION_CLASS infoClass, LPVOID tokenInformationPointer, DWORD tokenInformationLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, tokenInformationLength); }

void CaptureCheckTokenMembership(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE tokenHandle, PSID sidPointer, PBOOL isMemberPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" sid="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sidPointer)); AppendWideText(detailBuffer, L" member="); AppendUnsignedText(detailBuffer, isMemberPointer != nullptr && *isMemberPointer != FALSE ? 1ULL : 0ULL); }

void CaptureCreateRestrictedToken(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE existingTokenHandle, DWORD flagsValue, DWORD disableSidCount, PSID_AND_ATTRIBUTES sidsToDisablePointer, DWORD deletePrivilegeCount, PLUID_AND_ATTRIBUTES privilegesToDeletePointer, DWORD restrictSidCount, PSID_AND_ATTRIBUTES sidsToRestrictPointer, PHANDLE newTokenHandlePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(existingTokenHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" disableSids="); AppendUnsignedText(detailBuffer, disableSidCount); AppendWideText(detailBuffer, L" deletePrivs="); AppendUnsignedText(detailBuffer, deletePrivilegeCount); AppendWideText(detailBuffer, L" restrictSids="); AppendUnsignedText(detailBuffer, restrictSidCount); AppendWideText(detailBuffer, L" newToken="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureImpersonateSelf(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SECURITY_IMPERSONATION_LEVEL impersonationLevel, BOOL resultValue)
{ AppendWideText(detailBuffer, L"level="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(impersonationLevel)); }

void CaptureImpersonateNamedPipeClient(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE pipeHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"pipe", pipeHandle); }

void CaptureCredReadW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR targetNamePointer, DWORD typeValue, DWORD flagsValue, PVOID* credentialPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"target="); AppendWideText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, typeValue); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" credential="); AppendHexText(detailBuffer, credentialPointer != nullptr ? reinterpret_cast<std::uint64_t>(*credentialPointer) : 0); }

void CaptureCredReadA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR targetNamePointer, DWORD typeValue, DWORD flagsValue, PVOID* credentialPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"target="); AppendAnsiText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, typeValue); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" credential="); AppendHexText(detailBuffer, credentialPointer != nullptr ? reinterpret_cast<std::uint64_t>(*credentialPointer) : 0); }

void CaptureCredEnumerateW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR filterPointer, DWORD flagsValue, DWORD* countPointer, PVOID* credentialArrayPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"filter="); AppendWideText(detailBuffer, filterPointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); }

void CaptureCredEnumerateA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR filterPointer, DWORD flagsValue, DWORD* countPointer, PVOID* credentialArrayPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"filter="); AppendAnsiText(detailBuffer, filterPointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); }

void CaptureCredWriteW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID credentialPointer, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"credential="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialPointer)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureCredWriteA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID credentialPointer, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"credential="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialPointer)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureCredDeleteW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR targetNamePointer, DWORD typeValue, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"target="); AppendWideText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, typeValue); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureCredDeleteA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR targetNamePointer, DWORD typeValue, DWORD flagsValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"target="); AppendAnsiText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, typeValue); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureCredFree(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID bufferPointer)
{ AppendWideText(detailBuffer, L"buffer="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bufferPointer)); }

void CaptureLsaOpenPolicy(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PUNICODE_STRING systemNamePointer, PVOID objectAttributesPointer, ACCESS_MASK desiredAccess, PVOID* policyHandlePointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"system="); AppendUnicodeStringText(detailBuffer, systemNamePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" policy="); AppendHexText(detailBuffer, policyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*policyHandlePointer) : 0); }

void CaptureLsaClose(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID objectHandle, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(objectHandle)); }

void CaptureLsaEnumerateLogonSessions(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PULONG logonSessionCountPointer, PVOID* logonSessionListPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"count="); AppendUnsignedText(detailBuffer, logonSessionCountPointer != nullptr ? *logonSessionCountPointer : 0); AppendWideText(detailBuffer, L" list="); AppendHexText(detailBuffer, logonSessionListPointer != nullptr ? reinterpret_cast<std::uint64_t>(*logonSessionListPointer) : 0); }

void CaptureLsaGetLogonSessionData(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID logonIdPointer, PVOID* sessionDataPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"logonId="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(logonIdPointer)); AppendWideText(detailBuffer, L" data="); AppendHexText(detailBuffer, sessionDataPointer != nullptr ? reinterpret_cast<std::uint64_t>(*sessionDataPointer) : 0); }

void CaptureLsaFreeReturnBuffer(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID bufferPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"buffer="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bufferPointer)); }

void CaptureLsaLookupNames2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID policyHandle, ULONG flagsValue, ULONG countValue, PUNICODE_STRING namesPointer, PVOID* referencedDomainsPointer, PVOID* sidsPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"policy="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(policyHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countValue); AppendWideText(detailBuffer, L" first="); if (namesPointer != nullptr && countValue != 0) { AppendUnicodeStringText(detailBuffer, &namesPointer[0]); } }

void CaptureLsaLookupSids2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID policyHandle, ULONG flagsValue, ULONG countValue, PVOID* sidsPointer, PVOID* referencedDomainsPointer, PVOID* namesPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"policy="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(policyHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countValue); AppendWideText(detailBuffer, L" firstSid="); AppendHexText(detailBuffer, sidsPointer != nullptr && countValue != 0 ? reinterpret_cast<std::uint64_t>(sidsPointer[0]) : 0); }

void CaptureOpenEventLogW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR serverNamePointer, LPCWSTR sourceNamePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" source="); AppendWideText(detailBuffer, sourceNamePointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenEventLogA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR serverNamePointer, LPCSTR sourceNamePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"server="); AppendAnsiText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" source="); AppendAnsiText(detailBuffer, sourceNamePointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureRegisterEventSourceW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR serverNamePointer, LPCWSTR sourceNamePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" source="); AppendWideText(detailBuffer, sourceNamePointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureRegisterEventSourceA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR serverNamePointer, LPCSTR sourceNamePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"server="); AppendAnsiText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" source="); AppendAnsiText(detailBuffer, sourceNamePointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureReadEventLogW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventLogHandle, DWORD readFlags, DWORD recordOffset, LPVOID bufferPointer, DWORD bytesToRead, DWORD* bytesReadPointer, DWORD* minBytesNeededPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"log="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, readFlags); AppendWideText(detailBuffer, L" offset="); AppendUnsignedText(detailBuffer, recordOffset); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bytesToRead); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); }

void CaptureReadEventLogA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventLogHandle, DWORD readFlags, DWORD recordOffset, LPVOID bufferPointer, DWORD bytesToRead, DWORD* bytesReadPointer, DWORD* minBytesNeededPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"log="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, readFlags); AppendWideText(detailBuffer, L" offset="); AppendUnsignedText(detailBuffer, recordOffset); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bytesToRead); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? *bytesReadPointer : 0); }

void CaptureClearEventLogW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventLogHandle, LPCWSTR backupFileNamePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"log="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); AppendWideText(detailBuffer, L" backup="); AppendWideText(detailBuffer, backupFileNamePointer); }

void CaptureClearEventLogA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventLogHandle, LPCSTR backupFileNamePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"log="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); AppendWideText(detailBuffer, L" backup="); AppendAnsiText(detailBuffer, backupFileNamePointer); }

void CaptureReportEventW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventLogHandle, WORD typeValue, WORD categoryValue, DWORD eventIdValue, PSID userSidPointer, WORD stringCount, DWORD dataSize, LPCWSTR* stringsPointer, LPVOID rawDataPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"log="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, typeValue); AppendWideText(detailBuffer, L" category="); AppendUnsignedText(detailBuffer, categoryValue); AppendWideText(detailBuffer, L" event="); AppendHexText(detailBuffer, eventIdValue); AppendWideText(detailBuffer, L" strings="); AppendUnsignedText(detailBuffer, stringCount); AppendWideText(detailBuffer, L" data="); AppendUnsignedText(detailBuffer, dataSize); }

void CaptureReportEventA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventLogHandle, WORD typeValue, WORD categoryValue, DWORD eventIdValue, PSID userSidPointer, WORD stringCount, DWORD dataSize, LPCSTR* stringsPointer, LPVOID rawDataPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"log="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventLogHandle)); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, typeValue); AppendWideText(detailBuffer, L" category="); AppendUnsignedText(detailBuffer, categoryValue); AppendWideText(detailBuffer, L" event="); AppendHexText(detailBuffer, eventIdValue); AppendWideText(detailBuffer, L" strings="); AppendUnsignedText(detailBuffer, stringCount); AppendWideText(detailBuffer, L" data="); AppendUnsignedText(detailBuffer, dataSize); }

void CaptureCloseEventLog(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE eventLogHandle, BOOL resultValue)
{ BuildSimpleHandleDetail(detailBuffer, L"log", eventLogHandle); }

void CaptureNetUserEnum(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR serverNamePointer, DWORD levelValue, DWORD filterValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, LPDWORD resumeHandlePointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, levelValue); AppendWideText(detailBuffer, L" filter="); AppendHexText(detailBuffer, filterValue); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); AppendWideText(detailBuffer, L" total="); AppendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); }

void CaptureNetLocalGroupEnum(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, PDWORD_PTR resumeHandlePointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, levelValue); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); AppendWideText(detailBuffer, L" total="); AppendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); }

void CaptureNetGroupEnum(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, PDWORD_PTR resumeHandlePointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, levelValue); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); AppendWideText(detailBuffer, L" total="); AppendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); }

void CaptureNetShareEnum(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, LPDWORD resumeHandlePointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, levelValue); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); AppendWideText(detailBuffer, L" total="); AppendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); }

void CaptureNetSessionEnum(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPWSTR serverNamePointer, LPWSTR uncClientNamePointer, LPWSTR userNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, LPDWORD resumeHandlePointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" client="); AppendWideText(detailBuffer, uncClientNamePointer); AppendWideText(detailBuffer, L" user="); AppendWideText(detailBuffer, userNamePointer); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, levelValue); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); AppendWideText(detailBuffer, L" total="); AppendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); }

void CaptureNetServerEnum(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD preferredMaxLength, LPDWORD entriesReadPointer, LPDWORD totalEntriesPointer, DWORD serverType, LPCWSTR domainPointer, LPDWORD resumeHandlePointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" domain="); AppendWideText(detailBuffer, domainPointer); AppendWideText(detailBuffer, L" type="); AppendHexText(detailBuffer, serverType); AppendWideText(detailBuffer, L" read="); AppendUnsignedText(detailBuffer, entriesReadPointer != nullptr ? *entriesReadPointer : 0); AppendWideText(detailBuffer, L" total="); AppendUnsignedText(detailBuffer, totalEntriesPointer != nullptr ? *totalEntriesPointer : 0); }

void CaptureNetWkstaGetInfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPWSTR serverNamePointer, DWORD levelValue, LPBYTE* bufferPointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, levelValue); AppendWideText(detailBuffer, L" buffer="); AppendHexText(detailBuffer, bufferPointer != nullptr ? reinterpret_cast<std::uint64_t>(*bufferPointer) : 0); }

void CaptureNetApiBufferFree(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPVOID bufferPointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"buffer="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bufferPointer)); }

void CaptureGetExtendedTcpTable(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID tcpTablePointer, PDWORD sizePointer, BOOL orderValue, ULONG familyValue, ULONG tableClassValue, ULONG reservedValue, ULONG statusValue)
{ AppendWideText(detailBuffer, L"family="); AppendUnsignedText(detailBuffer, familyValue); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, tableClassValue); AppendWideText(detailBuffer, L" ordered="); AppendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); }

void CaptureGetExtendedUdpTable(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID udpTablePointer, PDWORD sizePointer, BOOL orderValue, ULONG familyValue, ULONG tableClassValue, ULONG reservedValue, ULONG statusValue)
{ AppendWideText(detailBuffer, L"family="); AppendUnsignedText(detailBuffer, familyValue); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, tableClassValue); AppendWideText(detailBuffer, L" ordered="); AppendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); }

void CaptureGetTcpTable2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID tcpTablePointer, PULONG sizePointer, BOOL orderValue, ULONG statusValue)
{ AppendWideText(detailBuffer, L"ordered="); AppendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); }

void CaptureGetUdpTable(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID udpTablePointer, PDWORD sizePointer, BOOL orderValue, ULONG statusValue)
{ AppendWideText(detailBuffer, L"ordered="); AppendUnsignedText(detailBuffer, orderValue != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); }

void CaptureGetAdaptersAddresses(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], ULONG familyValue, ULONG flagsValue, PVOID reservedPointer, PVOID addressesPointer, PULONG sizePointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"family="); AppendUnsignedText(detailBuffer, familyValue); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); }

void CaptureGetNetworkParams(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID fixedInfoPointer, PULONG sizePointer, DWORD statusValue)
{ AppendWideText(detailBuffer, L"size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); }

void CaptureGetIpNetTable2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], USHORT familyValue, PVOID* tablePointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"family="); AppendUnsignedText(detailBuffer, familyValue); AppendWideText(detailBuffer, L" table="); AppendHexText(detailBuffer, tablePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tablePointer) : 0); }

void CaptureGetIfTable2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID* tablePointer, ULONG statusValue)
{ AppendWideText(detailBuffer, L"table="); AppendHexText(detailBuffer, tablePointer != nullptr ? reinterpret_cast<std::uint64_t>(*tablePointer) : 0); }

void CaptureFreeMibTable(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID memoryPointer)
{ AppendWideText(detailBuffer, L"memory="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(memoryPointer)); }

void CaptureWTSOpenServerW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPWSTR serverNamePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"server="); AppendWideText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureWTSOpenServerA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTR serverNamePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"server="); AppendAnsiText(detailBuffer, serverNamePointer); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureWTSCloseServer(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE serverHandle)
{ BuildSimpleHandleDetail(detailBuffer, L"server", serverHandle); }

void CaptureWTSEnumerateSessionsW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* sessionInfoPointer, DWORD* countPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"server="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); AppendWideText(detailBuffer, L" version="); AppendUnsignedText(detailBuffer, versionValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); }

void CaptureWTSEnumerateSessionsA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* sessionInfoPointer, DWORD* countPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"server="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); AppendWideText(detailBuffer, L" version="); AppendUnsignedText(detailBuffer, versionValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); }

void CaptureWTSEnumerateProcessesW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* processInfoPointer, DWORD* countPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"server="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); AppendWideText(detailBuffer, L" version="); AppendUnsignedText(detailBuffer, versionValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); }

void CaptureWTSEnumerateProcessesA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE serverHandle, DWORD reservedValue, DWORD versionValue, PVOID* processInfoPointer, DWORD* countPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"server="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); AppendWideText(detailBuffer, L" version="); AppendUnsignedText(detailBuffer, versionValue); AppendWideText(detailBuffer, L" count="); AppendUnsignedText(detailBuffer, countPointer != nullptr ? *countPointer : 0); }

void CaptureWTSQuerySessionInformationW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE serverHandle, DWORD sessionId, int infoClass, LPWSTR* bufferPointer, DWORD* bytesReturnedPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"server="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); AppendWideText(detailBuffer, L" session="); AppendUnsignedText(detailBuffer, sessionId); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass < 0 ? 0 : infoClass)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bytesReturnedPointer != nullptr ? *bytesReturnedPointer : 0); }

void CaptureWTSQuerySessionInformationA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE serverHandle, DWORD sessionId, int infoClass, LPSTR* bufferPointer, DWORD* bytesReturnedPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"server="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(serverHandle)); AppendWideText(detailBuffer, L" session="); AppendUnsignedText(detailBuffer, sessionId); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass < 0 ? 0 : infoClass)); AppendWideText(detailBuffer, L" bytes="); AppendUnsignedText(detailBuffer, bytesReturnedPointer != nullptr ? *bytesReturnedPointer : 0); }

void CaptureWTSFreeMemory(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID memoryPointer)
{ AppendWideText(detailBuffer, L"memory="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(memoryPointer)); }

void CaptureCreateJobObjectW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributesPointer, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateJobObjectA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSECURITY_ATTRIBUTES securityAttributesPointer, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenJobObjectW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCWSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" inherit="); AppendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureOpenJobObjectA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD desiredAccess, BOOL inheritHandle, LPCSTR namePointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" inherit="); AppendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureAssignProcessToJobObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE jobHandle, HANDLE processHandle, BOOL resultValue)
{ AppendWideText(detailBuffer, L"job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); AppendWideText(detailBuffer, L" process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); }

void CaptureTerminateJobObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE jobHandle, UINT exitCode, BOOL resultValue)
{ AppendWideText(detailBuffer, L"job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); AppendWideText(detailBuffer, L" exit="); AppendUnsignedText(detailBuffer, exitCode); }

void CaptureSetInformationJobObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE jobHandle, JOBOBJECTINFOCLASS infoClass, LPVOID jobObjectInformationPointer, DWORD jobObjectInformationLength, BOOL resultValue)
{ AppendWideText(detailBuffer, L"job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, jobObjectInformationLength); }

void CaptureQueryInformationJobObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE jobHandle, JOBOBJECTINFOCLASS infoClass, LPVOID jobObjectInformationPointer, DWORD jobObjectInformationLength, LPDWORD returnLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"job="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(jobHandle)); AppendWideText(detailBuffer, L" class="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoClass)); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, jobObjectInformationLength); AppendWideText(detailBuffer, L" return="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureAcquireCredentialsHandleW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPWSTR principalPointer, LPWSTR packagePointer, ULONG credentialUse, PVOID logonIdPointer, PVOID authDataPointer, PVOID getKeyFnPointer, PVOID getKeyArgumentPointer, PVOID credentialHandlePointer, PVOID expiryPointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"principal="); AppendWideText(detailBuffer, principalPointer); AppendWideText(detailBuffer, L" package="); AppendWideText(detailBuffer, packagePointer); AppendWideText(detailBuffer, L" use="); AppendHexText(detailBuffer, credentialUse); AppendWideText(detailBuffer, L" cred="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); }

void CaptureAcquireCredentialsHandleA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPSTR principalPointer, LPSTR packagePointer, ULONG credentialUse, PVOID logonIdPointer, PVOID authDataPointer, PVOID getKeyFnPointer, PVOID getKeyArgumentPointer, PVOID credentialHandlePointer, PVOID expiryPointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"principal="); AppendAnsiText(detailBuffer, principalPointer); AppendWideText(detailBuffer, L" package="); AppendAnsiText(detailBuffer, packagePointer); AppendWideText(detailBuffer, L" use="); AppendHexText(detailBuffer, credentialUse); AppendWideText(detailBuffer, L" cred="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); }

void CaptureInitializeSecurityContextW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID credentialHandlePointer, PVOID oldContextPointer, LPWSTR targetNamePointer, ULONG requestFlags, ULONG reserved1, ULONG targetDataRep, PVOID inputPointer, ULONG reserved2, PVOID newContextPointer, PVOID outputPointer, PULONG contextAttributesPointer, PVOID expiryPointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"target="); AppendWideText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, requestFlags); AppendWideText(detailBuffer, L" attrs="); AppendHexText(detailBuffer, contextAttributesPointer != nullptr ? *contextAttributesPointer : 0); }

void CaptureInitializeSecurityContextA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID credentialHandlePointer, PVOID oldContextPointer, LPSTR targetNamePointer, ULONG requestFlags, ULONG reserved1, ULONG targetDataRep, PVOID inputPointer, ULONG reserved2, PVOID newContextPointer, PVOID outputPointer, PULONG contextAttributesPointer, PVOID expiryPointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"target="); AppendAnsiText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, requestFlags); AppendWideText(detailBuffer, L" attrs="); AppendHexText(detailBuffer, contextAttributesPointer != nullptr ? *contextAttributesPointer : 0); }

void CaptureAcceptSecurityContext(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID credentialHandlePointer, PVOID contextHandlePointer, PVOID inputPointer, ULONG requestFlags, ULONG targetDataRep, PVOID newContextPointer, PVOID outputPointer, PULONG contextAttributesPointer, PVOID expiryPointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"cred="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); AppendWideText(detailBuffer, L" ctx="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, requestFlags); AppendWideText(detailBuffer, L" attrs="); AppendHexText(detailBuffer, contextAttributesPointer != nullptr ? *contextAttributesPointer : 0); }

void CaptureEncryptMessage(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID contextHandlePointer, ULONG qualityOfProtection, PVOID messagePointer, ULONG sequenceNumber, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"ctx="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); AppendWideText(detailBuffer, L" qop="); AppendHexText(detailBuffer, qualityOfProtection); AppendWideText(detailBuffer, L" seq="); AppendUnsignedText(detailBuffer, sequenceNumber); }

void CaptureDecryptMessage(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID contextHandlePointer, PVOID messagePointer, ULONG sequenceNumber, PULONG qualityOfProtectionPointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"ctx="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); AppendWideText(detailBuffer, L" seq="); AppendUnsignedText(detailBuffer, sequenceNumber); AppendWideText(detailBuffer, L" qop="); AppendHexText(detailBuffer, qualityOfProtectionPointer != nullptr ? *qualityOfProtectionPointer : 0); }

void CaptureDeleteSecurityContext(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID contextHandlePointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"ctx="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(contextHandlePointer)); }

void CaptureFreeCredentialsHandle(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID credentialHandlePointer, SECURITY_STATUS statusValue)
{ AppendWideText(detailBuffer, L"cred="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(credentialHandlePointer)); }

void CaptureProcess32FirstW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, PROCESSENTRY32W* entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); AppendWideText(detailBuffer, L" exe="); AppendWideText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); }

void CaptureProcess32First(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, tagPROCESSENTRY32* entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); AppendWideText(detailBuffer, L" exe="); AppendAnsiText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); }

void CaptureProcess32NextW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, PROCESSENTRY32W* entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); AppendWideText(detailBuffer, L" exe="); AppendWideText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); }

void CaptureProcess32Next(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, tagPROCESSENTRY32* entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ProcessID : 0); AppendWideText(detailBuffer, L" exe="); AppendAnsiText(detailBuffer, entryPointer != nullptr ? entryPointer->szExeFile : nullptr); }

void CaptureThread32First(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, LPTHREADENTRY32 entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" tid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ThreadID : 0); AppendWideText(detailBuffer, L" ownerPid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32OwnerProcessID : 0); }

void CaptureThread32Next(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, LPTHREADENTRY32 entryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" tid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32ThreadID : 0); AppendWideText(detailBuffer, L" ownerPid="); AppendUnsignedText(detailBuffer, entryPointer != nullptr ? entryPointer->th32OwnerProcessID : 0); }

void CaptureHeap32ListFirst(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, LPHEAPLIST32 heapListPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, heapListPointer != nullptr ? heapListPointer->th32ProcessID : 0); AppendWideText(detailBuffer, L" heap="); AppendHexText(detailBuffer, heapListPointer != nullptr ? static_cast<std::uint64_t>(heapListPointer->th32HeapID) : 0); }

void CaptureHeap32ListNext(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE snapshotHandle, LPHEAPLIST32 heapListPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"snapshot="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(snapshotHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, heapListPointer != nullptr ? heapListPointer->th32ProcessID : 0); AppendWideText(detailBuffer, L" heap="); AppendHexText(detailBuffer, heapListPointer != nullptr ? static_cast<std::uint64_t>(heapListPointer->th32HeapID) : 0); }

void CaptureHeap32First(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPHEAPENTRY32 heapEntryPointer, DWORD processId, ULONG_PTR heapId, BOOL resultValue)
{ AppendWideText(detailBuffer, L"pid="); AppendUnsignedText(detailBuffer, processId); AppendWideText(detailBuffer, L" heap="); AppendHexText(detailBuffer, heapId); AppendWideText(detailBuffer, L" block="); AppendHexText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->dwAddress : 0); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->dwBlockSize : 0); }

void CaptureHeap32Next(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPHEAPENTRY32 heapEntryPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"pid="); AppendUnsignedText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->th32ProcessID : 0); AppendWideText(detailBuffer, L" heap="); AppendHexText(detailBuffer, heapEntryPointer != nullptr ? static_cast<std::uint64_t>(heapEntryPointer->th32HeapID) : 0); AppendWideText(detailBuffer, L" block="); AppendHexText(detailBuffer, heapEntryPointer != nullptr ? heapEntryPointer->dwAddress : 0); }

void CaptureQueryFullProcessImageNameW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, DWORD flagsValue, LPWSTR imageNamePointer, PDWORD sizePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); AppendWideText(detailBuffer, L" image="); if (resultValue != FALSE) { AppendWideText(detailBuffer, imageNamePointer, sizePointer != nullptr ? *sizePointer : static_cast<std::size_t>(-1)); } }

void CaptureQueryFullProcessImageNameA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, DWORD flagsValue, LPSTR imageNamePointer, PDWORD sizePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizePointer != nullptr ? *sizePointer : 0); AppendWideText(detailBuffer, L" image="); if (resultValue != FALSE) { AppendAnsiText(detailBuffer, imageNamePointer, sizePointer != nullptr ? *sizePointer : static_cast<std::size_t>(-1)); } }

void CaptureGetProcessImageFileNameW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, LPWSTR imageNamePointer, DWORD sizeValue, DWORD resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizeValue); AppendWideText(detailBuffer, L" image="); if (resultValue != 0) { AppendWideText(detailBuffer, imageNamePointer, resultValue); } }

void CaptureGetProcessImageFileNameA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, LPSTR imageNamePointer, DWORD sizeValue, DWORD resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" size="); AppendUnsignedText(detailBuffer, sizeValue); AppendWideText(detailBuffer, L" image="); if (resultValue != 0) { AppendAnsiText(detailBuffer, imageNamePointer, resultValue); } }

void CaptureGetProcessId(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, DWORD resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" pid="); AppendUnsignedText(detailBuffer, resultValue); }

void CaptureGetThreadId(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE threadHandle, DWORD resultValue)
{ AppendWideText(detailBuffer, L"thread="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle)); AppendWideText(detailBuffer, L" tid="); AppendUnsignedText(detailBuffer, resultValue); }

void CaptureIsWow64Process(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, PBOOL wow64ProcessPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" wow64="); AppendUnsignedText(detailBuffer, wow64ProcessPointer != nullptr && *wow64ProcessPointer != FALSE ? 1ULL : 0ULL); }

void CaptureIsWow64Process2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE processHandle, USHORT* processMachinePointer, USHORT* nativeMachinePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle)); AppendWideText(detailBuffer, L" procMachine="); AppendHexText(detailBuffer, processMachinePointer != nullptr ? *processMachinePointer : 0); AppendWideText(detailBuffer, L" nativeMachine="); AppendHexText(detailBuffer, nativeMachinePointer != nullptr ? *nativeMachinePointer : 0); }

void CaptureWow64DisableWow64FsRedirection(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID* oldValuePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"old="); AppendHexText(detailBuffer, oldValuePointer != nullptr ? reinterpret_cast<std::uint64_t>(*oldValuePointer) : 0); }

void CaptureWow64RevertWow64FsRedirection(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PVOID oldValuePointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"old="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(oldValuePointer)); }

void CaptureGetTempPathW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD bufferLength, LPWSTR bufferPointer, DWORD resultValue)
{ AppendWideText(detailBuffer, L"buffer="); AppendUnsignedText(detailBuffer, bufferLength); AppendWideText(detailBuffer, L" path="); if (resultValue != 0) { AppendWideText(detailBuffer, bufferPointer, resultValue); } }

void CaptureGetTempPathA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], DWORD bufferLength, LPSTR bufferPointer, DWORD resultValue)
{ AppendWideText(detailBuffer, L"buffer="); AppendUnsignedText(detailBuffer, bufferLength); AppendWideText(detailBuffer, L" path="); if (resultValue != 0) { AppendAnsiText(detailBuffer, bufferPointer, resultValue); } }

void CaptureGetTempFileNameW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR pathNamePointer, LPCWSTR prefixStringPointer, UINT uniqueValue, LPWSTR tempFileNamePointer, UINT resultValue)
{ AppendWideText(detailBuffer, L"path="); AppendWideText(detailBuffer, pathNamePointer); AppendWideText(detailBuffer, L" prefix="); AppendWideText(detailBuffer, prefixStringPointer); AppendWideText(detailBuffer, L" unique="); AppendUnsignedText(detailBuffer, uniqueValue); AppendWideText(detailBuffer, L" file="); AppendWideText(detailBuffer, tempFileNamePointer); }

void CaptureGetTempFileNameA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR pathNamePointer, LPCSTR prefixStringPointer, UINT uniqueValue, LPSTR tempFileNamePointer, UINT resultValue)
{ AppendWideText(detailBuffer, L"path="); AppendAnsiText(detailBuffer, pathNamePointer); AppendWideText(detailBuffer, L" prefix="); AppendAnsiText(detailBuffer, prefixStringPointer); AppendWideText(detailBuffer, L" unique="); AppendUnsignedText(detailBuffer, uniqueValue); AppendWideText(detailBuffer, L" file="); AppendAnsiText(detailBuffer, tempFileNamePointer); }

void CaptureGetFullPathNameW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR fileNamePointer, DWORD bufferLength, LPWSTR bufferPointer, LPWSTR* filePartPointer, DWORD resultValue)
{ AppendWideText(detailBuffer, L"input="); AppendWideText(detailBuffer, fileNamePointer); AppendWideText(detailBuffer, L" buffer="); AppendUnsignedText(detailBuffer, bufferLength); AppendWideText(detailBuffer, L" full="); if (resultValue != 0 && resultValue < bufferLength) { AppendWideText(detailBuffer, bufferPointer, resultValue); } }

void CaptureGetFullPathNameA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR fileNamePointer, DWORD bufferLength, LPSTR bufferPointer, LPSTR* filePartPointer, DWORD resultValue)
{ AppendWideText(detailBuffer, L"input="); AppendAnsiText(detailBuffer, fileNamePointer); AppendWideText(detailBuffer, L" buffer="); AppendUnsignedText(detailBuffer, bufferLength); AppendWideText(detailBuffer, L" full="); if (resultValue != 0 && resultValue < bufferLength) { AppendAnsiText(detailBuffer, bufferPointer, resultValue); } }

void CaptureSearchPathW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR pathPointer, LPCWSTR fileNamePointer, LPCWSTR extensionPointer, DWORD bufferLength, LPWSTR bufferPointer, LPWSTR* filePartPointer, DWORD resultValue)
{ AppendWideText(detailBuffer, L"path="); AppendWideText(detailBuffer, pathPointer); AppendWideText(detailBuffer, L" file="); AppendWideText(detailBuffer, fileNamePointer); AppendWideText(detailBuffer, L" ext="); AppendWideText(detailBuffer, extensionPointer); AppendWideText(detailBuffer, L" result="); if (resultValue != 0 && resultValue < bufferLength) { AppendWideText(detailBuffer, bufferPointer, resultValue); } }

void CaptureSearchPathA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR pathPointer, LPCSTR fileNamePointer, LPCSTR extensionPointer, DWORD bufferLength, LPSTR bufferPointer, LPSTR* filePartPointer, DWORD resultValue)
{ AppendWideText(detailBuffer, L"path="); AppendAnsiText(detailBuffer, pathPointer); AppendWideText(detailBuffer, L" file="); AppendAnsiText(detailBuffer, fileNamePointer); AppendWideText(detailBuffer, L" ext="); AppendAnsiText(detailBuffer, extensionPointer); AppendWideText(detailBuffer, L" result="); if (resultValue != 0 && resultValue < bufferLength) { AppendAnsiText(detailBuffer, bufferPointer, resultValue); } }

void CaptureGetShortPathNameW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR longPathPointer, LPWSTR shortPathPointer, DWORD bufferLength, DWORD resultValue)
{ AppendWideText(detailBuffer, L"input="); AppendWideText(detailBuffer, longPathPointer); AppendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { AppendWideText(detailBuffer, shortPathPointer, resultValue); } }

void CaptureGetShortPathNameA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR longPathPointer, LPSTR shortPathPointer, DWORD bufferLength, DWORD resultValue)
{ AppendWideText(detailBuffer, L"input="); AppendAnsiText(detailBuffer, longPathPointer); AppendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { AppendAnsiText(detailBuffer, shortPathPointer, resultValue); } }

void CaptureGetLongPathNameW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR shortPathPointer, LPWSTR longPathPointer, DWORD bufferLength, DWORD resultValue)
{ AppendWideText(detailBuffer, L"input="); AppendWideText(detailBuffer, shortPathPointer); AppendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { AppendWideText(detailBuffer, longPathPointer, resultValue); } }

void CaptureGetLongPathNameA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR shortPathPointer, LPSTR longPathPointer, DWORD bufferLength, DWORD resultValue)
{ AppendWideText(detailBuffer, L"input="); AppendAnsiText(detailBuffer, shortPathPointer); AppendWideText(detailBuffer, L" output="); if (resultValue != 0 && resultValue < bufferLength) { AppendAnsiText(detailBuffer, longPathPointer, resultValue); } }

void CaptureCreatePipe(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE readPipePointer, PHANDLE writePipePointer, LPSECURITY_ATTRIBUTES securityAttributesPointer, DWORD sizeValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"size="); AppendUnsignedText(detailBuffer, sizeValue); AppendWideText(detailBuffer, L" read="); AppendWideText(detailBuffer, L"<see-out_after>"); AppendWideText(detailBuffer, L" write="); AppendWideText(detailBuffer, L"<see-out_after>"); }

void CaptureCreateMailslotW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR namePointer, DWORD maxMessageSize, DWORD readTimeout, LPSECURITY_ATTRIBUTES securityAttributesPointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendWideText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" maxMsg="); AppendUnsignedText(detailBuffer, maxMessageSize); AppendWideText(detailBuffer, L" timeout="); AppendUnsignedText(detailBuffer, readTimeout); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateMailslotA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR namePointer, DWORD maxMessageSize, DWORD readTimeout, LPSECURITY_ATTRIBUTES securityAttributesPointer, HANDLE resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" maxMsg="); AppendUnsignedText(detailBuffer, maxMessageSize); AppendWideText(detailBuffer, L" timeout="); AppendUnsignedText(detailBuffer, readTimeout); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureCreateDirectoryExW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR templateDirectoryPointer, LPCWSTR newDirectoryPointer, LPSECURITY_ATTRIBUTES securityAttributesPointer, BOOL resultValue)
{ BuildTwoPathDetailW(detailBuffer, templateDirectoryPointer, newDirectoryPointer, 0); }

void CaptureCreateDirectoryExA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCSTR templateDirectoryPointer, LPCSTR newDirectoryPointer, LPSECURITY_ATTRIBUTES securityAttributesPointer, BOOL resultValue)
{ BuildTwoPathDetailA(detailBuffer, templateDirectoryPointer, newDirectoryPointer, 0); }

void CaptureWSAStartup(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], WORD versionRequested, LPWSADATA dataPointer, int resultValue)
{ AppendWideText(detailBuffer, L"version="); AppendHexText(detailBuffer, versionRequested); AppendWideText(detailBuffer, L" highVersion="); AppendHexText(detailBuffer, dataPointer != nullptr ? dataPointer->wHighVersion : 0); }

void CaptureWSACleanup(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int resultValue)
{ detailBuffer[0] = L'\0'; }

void Captureselect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], int nfdsValue, fd_set* readSetPointer, fd_set* writeSetPointer, fd_set* exceptSetPointer, const timeval* timeoutPointer, int resultValue)
{ AppendWideText(detailBuffer, L"nfds="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(nfdsValue < 0 ? 0 : nfdsValue)); AppendWideText(detailBuffer, L" ready="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(resultValue < 0 ? 0 : resultValue)); AppendWideText(detailBuffer, L" timeout="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(timeoutPointer)); }

void Captureioctlsocket(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, long commandValue, u_long* argumentPointer, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" cmd="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(commandValue)); AppendWideText(detailBuffer, L" arg="); AppendHexText(detailBuffer, argumentPointer != nullptr ? *argumentPointer : 0); }

void Capturesetsockopt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, int levelValue, int optionName, const char* optionValuePointer, int optionLength, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(levelValue < 0 ? 0 : levelValue)); AppendWideText(detailBuffer, L" opt="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(optionName < 0 ? 0 : optionName)); AppendWideText(detailBuffer, L" len="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(optionLength < 0 ? 0 : optionLength)); }

void Capturegetsockopt(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, int levelValue, int optionName, char* optionValuePointer, int* optionLengthPointer, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" level="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(levelValue < 0 ? 0 : levelValue)); AppendWideText(detailBuffer, L" opt="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(optionName < 0 ? 0 : optionName)); AppendWideText(detailBuffer, L" len="); AppendUnsignedText(detailBuffer, optionLengthPointer != nullptr ? static_cast<unsigned long long>(*optionLengthPointer < 0 ? 0 : *optionLengthPointer) : 0ULL); }

void Capturegetsockname(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, sockaddr* namePointer, int* nameLengthPointer, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" addr="); AppendSocketAddress(detailBuffer, namePointer, nameLengthPointer != nullptr ? *nameLengthPointer : 0); }

void Capturegetpeername(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, sockaddr* namePointer, int* nameLengthPointer, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" addr="); AppendSocketAddress(detailBuffer, namePointer, nameLengthPointer != nullptr ? *nameLengthPointer : 0); }

void CaptureWSAEventSelect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, WSAEVENT eventHandle, long networkEvents, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" event="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(eventHandle)); AppendWideText(detailBuffer, L" netEvents="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(networkEvents)); }

void CaptureWSAAsyncSelect(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], SOCKET socketValue, HWND windowHandle, unsigned int messageValue, long networkEvents, int resultValue)
{ AppendWideText(detailBuffer, L"socket="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue)); AppendWideText(detailBuffer, L" hwnd="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(windowHandle)); AppendWideText(detailBuffer, L" msg="); AppendHexText(detailBuffer, messageValue); AppendWideText(detailBuffer, L" netEvents="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(networkEvents)); }

void Capturegethostbyname(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const char* namePointer, HostEntPtr resultHandle)
{ AppendWideText(detailBuffer, L"name="); AppendAnsiText(detailBuffer, namePointer); AppendWideText(detailBuffer, L" result="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void Capturegethostbyaddr(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const char* addressPointer, int lengthValue, int typeValue, HostEntPtr resultHandle)
{ AppendWideText(detailBuffer, L"len="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(lengthValue < 0 ? 0 : lengthValue)); AppendWideText(detailBuffer, L" type="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue < 0 ? 0 : typeValue)); AppendWideText(detailBuffer, L" result="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle)); }

void CaptureGetNameInfoW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const sockaddr* sockaddrPointer, int sockaddrLength, PWCHAR hostPointer, DWORD hostLength, PWCHAR servicePointer, DWORD serviceLength, INT flagsValue, INT resultValue)
{ AppendSocketAddress(detailBuffer, sockaddrPointer, sockaddrLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue)); AppendWideText(detailBuffer, L" host="); if (resultValue == 0) { AppendWideText(detailBuffer, hostPointer); } }

void Capturegetnameinfo(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], const sockaddr* sockaddrPointer, int sockaddrLength, PCHAR hostPointer, DWORD hostLength, PCHAR servicePointer, DWORD serviceLength, INT flagsValue, INT resultValue)
{ AppendSocketAddress(detailBuffer, sockaddrPointer, sockaddrLength); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue)); AppendWideText(detailBuffer, L" host="); if (resultValue == 0) { AppendAnsiText(detailBuffer, hostPointer); } }

void CaptureWinHttpAddRequestHeaders(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, LPCWSTR headersPointer, DWORD headersLength, DWORD modifiersValue, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, headersLength); AppendWideText(detailBuffer, L" modifiers="); AppendHexText(detailBuffer, modifiersValue); }

void CaptureWinHttpSetCredentials(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, DWORD authTargets, DWORD authScheme, LPCWSTR userNamePointer, LPCWSTR passwordPointer, LPVOID authParamsPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" targets="); AppendHexText(detailBuffer, authTargets); AppendWideText(detailBuffer, L" scheme="); AppendHexText(detailBuffer, authScheme); AppendWideText(detailBuffer, L" user="); AppendWideText(detailBuffer, userNamePointer); }

void CaptureWinHttpCrackUrl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR urlPointer, DWORD urlLength, DWORD flagsValue, LPURL_COMPONENTS componentsPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"url="); AppendWideText(detailBuffer, urlPointer, urlLength != 0 ? urlLength : static_cast<std::size_t>(-1)); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, flagsValue); }

void CaptureWinHttpCreateUrl(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPURL_COMPONENTS componentsPointer, DWORD flagsValue, LPWSTR urlPointer, LPDWORD urlLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"flags="); AppendHexText(detailBuffer, flagsValue); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, urlLengthPointer != nullptr ? *urlLengthPointer : 0); AppendWideText(detailBuffer, L" url="); if (resultValue != FALSE) { AppendWideText(detailBuffer, urlPointer); } }

void CaptureWinHttpSetTimeouts(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, int resolveTimeout, int connectTimeout, int sendTimeout, int receiveTimeout, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" resolve="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(resolveTimeout < 0 ? 0 : resolveTimeout)); AppendWideText(detailBuffer, L" connect="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(connectTimeout < 0 ? 0 : connectTimeout)); AppendWideText(detailBuffer, L" send="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(sendTimeout < 0 ? 0 : sendTimeout)); AppendWideText(detailBuffer, L" recv="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(receiveTimeout < 0 ? 0 : receiveTimeout)); }

void CaptureHttpQueryInfoW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, DWORD infoLevel, LPVOID bufferPointer, LPDWORD bufferLengthPointer, LPDWORD indexPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" level="); AppendHexText(detailBuffer, infoLevel); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); }

void CaptureHttpQueryInfoA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET requestHandle, DWORD infoLevel, LPVOID bufferPointer, LPDWORD bufferLengthPointer, LPDWORD indexPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"request="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(requestHandle)); AppendWideText(detailBuffer, L" level="); AppendHexText(detailBuffer, infoLevel); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); }

void CaptureInternetQueryOptionW(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, LPDWORD bufferLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" option="); AppendHexText(detailBuffer, optionValue); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); }

void CaptureInternetQueryOptionA(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HINTERNET internetHandle, DWORD optionValue, LPVOID bufferPointer, LPDWORD bufferLengthPointer, BOOL resultValue)
{ AppendWideText(detailBuffer, L"handle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(internetHandle)); AppendWideText(detailBuffer, L" option="); AppendHexText(detailBuffer, optionValue); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0); }

void CaptureNtOpenDirectoryObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE directoryHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, directoryHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*directoryHandlePointer) : 0); }

void CaptureNtQueryDirectoryObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE directoryHandle, PVOID bufferPointer, ULONG lengthValue, BOOLEAN returnSingleEntry, BOOLEAN restartScan, PULONG contextPointer, PULONG returnLengthPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"directory="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(directoryHandle)); AppendWideText(detailBuffer, L" length="); AppendUnsignedText(detailBuffer, lengthValue); AppendWideText(detailBuffer, L" single="); AppendUnsignedText(detailBuffer, returnSingleEntry != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" restart="); AppendUnsignedText(detailBuffer, restartScan != FALSE ? 1ULL : 0ULL); AppendWideText(detailBuffer, L" context="); AppendUnsignedText(detailBuffer, contextPointer != nullptr ? *contextPointer : 0); AppendWideText(detailBuffer, L" returned="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureNtCreateSymbolicLinkObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE linkHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PUNICODE_STRING targetNamePointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" target="); AppendUnicodeStringText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, linkHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*linkHandlePointer) : 0); }

void CaptureNtOpenSymbolicLinkObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE linkHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, linkHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*linkHandlePointer) : 0); }

void CaptureNtQuerySymbolicLinkObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE linkHandle, PUNICODE_STRING targetNamePointer, PULONG returnLengthPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"link="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(linkHandle)); AppendWideText(detailBuffer, L" target="); AppendUnicodeStringText(detailBuffer, targetNamePointer); AppendWideText(detailBuffer, L" returned="); AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : 0); }

void CaptureNtCreateSemaphore(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE semaphoreHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, LONG initialCount, LONG maximumCount, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" initial="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(initialCount < 0 ? 0 : initialCount)); AppendWideText(detailBuffer, L" max="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(maximumCount < 0 ? 0 : maximumCount)); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, semaphoreHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*semaphoreHandlePointer) : 0); }

void CaptureNtOpenSemaphore(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE semaphoreHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"object="); AppendObjectNameText(detailBuffer, objectAttributesPointer); AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, desiredAccess); AppendWideText(detailBuffer, L" handle="); AppendHexText(detailBuffer, semaphoreHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*semaphoreHandlePointer) : 0); }

void CaptureNtReleaseSemaphore(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE semaphoreHandle, LONG releaseCount, PLONG previousCountPointer, NTSTATUS statusValue)
{ AppendWideText(detailBuffer, L"semaphore="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(semaphoreHandle)); AppendWideText(detailBuffer, L" release="); AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(releaseCount < 0 ? 0 : releaseCount)); AppendWideText(detailBuffer, L" previous="); AppendUnsignedText(detailBuffer, previousCountPointer != nullptr ? static_cast<unsigned long long>(*previousCountPointer < 0 ? 0 : *previousCountPointer) : 0ULL); }

// Modern x64 APIs. Opaque ALPC structures are captured by address only.
void CaptureNtAlpcConnectPort(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PHANDLE port, const UNICODE_STRING* name, POBJECT_ATTRIBUTES object, KS_ALPC_PORT_ATTRIBUTES* attributes, ULONG flags, PSID sid, KS_PORT_MESSAGE* message, PSIZE_T length, KS_ALPC_MESSAGE_ATTRIBUTES* outAttributes, KS_ALPC_MESSAGE_ATTRIBUTES* inAttributes, PLARGE_INTEGER timeout, NTSTATUS statusValue)
{
    AppendWideText(detailBuffer, L" port="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(port));
    AppendWideText(detailBuffer, L" name="); AppendUnicodeStringText(detailBuffer, name);
    AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(object));
    AppendWideText(detailBuffer, L" attributes="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(attributes));
    AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(flags));
    AppendWideText(detailBuffer, L" sid="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sid));
    AppendWideText(detailBuffer, L" message="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(message));
    AppendWideText(detailBuffer, L" length="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(length));
    AppendWideText(detailBuffer, L" outAttributes="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(outAttributes));
    AppendWideText(detailBuffer, L" inAttributes="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(inAttributes));
    AppendWideText(detailBuffer, L" timeout="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(timeout));
    AppendWideText(detailBuffer, L" statusValue="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(statusValue));
}
void CaptureNtAlpcSendWaitReceivePort(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE port, ULONG flags, KS_PORT_MESSAGE* send, KS_ALPC_MESSAGE_ATTRIBUTES* sendAttributes, KS_PORT_MESSAGE* receive, PSIZE_T length, KS_ALPC_MESSAGE_ATTRIBUTES* receiveAttributes, PLARGE_INTEGER timeout, NTSTATUS statusValue)
{
    AppendWideText(detailBuffer, L" port="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(port));
    AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(flags));
    AppendWideText(detailBuffer, L" send="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(send));
    AppendWideText(detailBuffer, L" sendAttributes="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sendAttributes));
    AppendWideText(detailBuffer, L" receive="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(receive));
    AppendWideText(detailBuffer, L" length="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(length));
    AppendWideText(detailBuffer, L" receiveAttributes="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(receiveAttributes));
    AppendWideText(detailBuffer, L" timeout="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(timeout));
    AppendWideText(detailBuffer, L" statusValue="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(statusValue));
}
void CaptureNtQueryInformationThread(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE thread, THREADINFOCLASS infoClass, PVOID information, ULONG length, PULONG returned, NTSTATUS statusValue)
{
    AppendWideText(detailBuffer, L" thread="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(thread));
    AppendWideText(detailBuffer, L" infoClass="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(infoClass));
    AppendWideText(detailBuffer, L" information="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(information));
    AppendWideText(detailBuffer, L" length="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(length));
    AppendWideText(detailBuffer, L" returned="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(returned));
    AppendWideText(detailBuffer, L" statusValue="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(statusValue));
}
void CaptureVirtualAlloc2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PVOID base, SIZE_T size, ULONG allocation, ULONG protection, MEM_EXTENDED_PARAMETER* parameters, ULONG count, PVOID resultHandle)
{
    AppendWideText(detailBuffer, L" process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(process));
    AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(base));
    AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(size));
    AppendWideText(detailBuffer, L" allocation="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(allocation));
    AppendWideText(detailBuffer, L" protection="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(protection));
    AppendWideText(detailBuffer, L" parameters="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameters));
    AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(count));
    AppendWideText(detailBuffer, L" resultHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
}
void CaptureVirtualAlloc2FromApp(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE process, PVOID base, SIZE_T size, ULONG allocation, ULONG protection, MEM_EXTENDED_PARAMETER* parameters, ULONG count, PVOID resultHandle)
{
    AppendWideText(detailBuffer, L" process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(process));
    AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(base));
    AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(size));
    AppendWideText(detailBuffer, L" allocation="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(allocation));
    AppendWideText(detailBuffer, L" protection="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(protection));
    AppendWideText(detailBuffer, L" parameters="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameters));
    AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(count));
    AppendWideText(detailBuffer, L" resultHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
}
void CaptureMapViewOfFile3(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE mapping, HANDLE process, PVOID base, ULONG64 offset, SIZE_T size, ULONG allocation, ULONG protection, MEM_EXTENDED_PARAMETER* parameters, ULONG count, PVOID resultHandle)
{
    AppendWideText(detailBuffer, L" mapping="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(mapping));
    AppendWideText(detailBuffer, L" process="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(process));
    AppendWideText(detailBuffer, L" base="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(base));
    AppendWideText(detailBuffer, L" offset="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(offset));
    AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(size));
    AppendWideText(detailBuffer, L" allocation="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(allocation));
    AppendWideText(detailBuffer, L" protection="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(protection));
    AppendWideText(detailBuffer, L" parameters="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameters));
    AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(count));
    AppendWideText(detailBuffer, L" resultHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
}
void CaptureCreateFileMapping2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], HANDLE file, LPSECURITY_ATTRIBUTES security, ULONG access, ULONG protection, ULONG allocation, ULONG64 size, PCWSTR name, MEM_EXTENDED_PARAMETER* parameters, ULONG count, HANDLE resultHandle)
{
    AppendWideText(detailBuffer, L" file="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(file));
    AppendWideText(detailBuffer, L" security="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(security));
    AppendWideText(detailBuffer, L" access="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(access));
    AppendWideText(detailBuffer, L" protection="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(protection));
    AppendWideText(detailBuffer, L" allocation="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(allocation));
    AppendWideText(detailBuffer, L" size="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(size));
    AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, name);
    AppendWideText(detailBuffer, L" parameters="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameters));
    AppendWideText(detailBuffer, L" count="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(count));
    AppendWideText(detailBuffer, L" resultHandle="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
}
void CaptureQueueUserAPC2(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], PAPCFUNC callback, HANDLE thread, ULONG_PTR data, QUEUE_USER_APC_FLAGS flags, BOOL resultValue)
{
    AppendWideText(detailBuffer, L" callback="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(callback));
    AppendWideText(detailBuffer, L" thread="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(thread));
    AppendWideText(detailBuffer, L" data="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(data));
    AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(flags));
    AppendWideText(detailBuffer, L" resultValue="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(resultValue));
}
void CaptureCoGetObject(wchar_t (&detailBuffer)[ks::winapi_monitor::kMaxDetailChars], LPCWSTR name, BIND_OPTS* options, REFIID interfaceId, void** object, HRESULT statusValue)
{
    AppendWideText(detailBuffer, L" name="); AppendWideText(detailBuffer, name);
    AppendWideText(detailBuffer, L" options="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(options));
    AppendWideText(detailBuffer, L" interfaceId="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(&interfaceId));
    AppendWideText(detailBuffer, L" object="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(object));
    AppendWideText(detailBuffer, L" statusValue="); AppendHexText(detailBuffer, static_cast<std::uint64_t>(statusValue));
}
