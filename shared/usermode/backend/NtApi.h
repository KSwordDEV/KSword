#pragma once

#include "Win32.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace ks::r3::common {

// SystemInformationClass keeps this project independent from private SDK enum
// declarations. Values are passed to NtQuerySystemInformation by callers that
// know the selected information contract.
enum class SystemInformationClass : ULONG {
    SystemProcessInformation = 5
};

// NtProcessRow is a framework-level, UI-friendly process snapshot. Inputs come
// from SYSTEM_PROCESS_INFORMATION rows; processing is performed by the process
// feature; consumers render the values and never own kernel memory.
struct NtProcessRow {
    DWORD processId = 0;
    DWORD parentProcessId = 0;
    ULONG threadCount = 0;
    ULONGLONG kernelTime100ns = 0;
    ULONGLONG userTime100ns = 0;
    SIZE_T workingSetBytes = 0;
    std::wstring imageName;
};

using NtQuerySystemInformationFn = LONG (NTAPI*)(ULONG, PVOID, ULONG, PULONG);

// NtApi owns dynamic ntdll exports used by feature modules. Construction has no
// inputs; processing resolves exports lazily; querySystemInformation returns an
// NTSTATUS-compatible LONG.
class NtApi final {
public:
    NtApi();

    // available reports whether required exports were resolved. There is no
    // input; output is true only when NtQuerySystemInformation can be called.
    bool available() const;

    // querySystemInformation forwards to ntdll. Inputs are information class,
    // buffer pointer/size, and optional return length; output is the NTSTATUS
    // returned by ntdll, or a failure code when unavailable.
    LONG querySystemInformation(SystemInformationClass infoClass, void* buffer, ULONG bufferSize, ULONG* returnLength) const;

private:
    NtQuerySystemInformationFn querySystemInformation_;
};

// QueryRawSystemInformation grows a byte buffer until NtQuerySystemInformation
// succeeds. Input is the information class; processing retries size mismatch;
// output is the raw byte buffer, empty on failure.
std::vector<std::byte> QueryRawSystemInformation(SystemInformationClass infoClass);

} // namespace ks::r3::common
