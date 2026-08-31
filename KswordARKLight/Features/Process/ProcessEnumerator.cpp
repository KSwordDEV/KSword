#include "ProcessEnumerator.h"

#include "../../Core/NtApi.h"

#include <algorithm>
#include <cstddef>
#include <cwchar>
#include <vector>
#include <winternl.h>

namespace Ksword::Features::Process {
namespace {
constexpr LONG kStatusSuccess = 0x00000000L;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004UL);
constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023UL);
constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005UL);
constexpr LONG kStatusProcedureNotFound = static_cast<LONG>(0xC000007AUL);

// KSYSTEM_PROCESS_INFORMATION mirrors the leading fields of the documented / SDK
// SYSTEM_PROCESS_INFORMATION layout that are stable for process enumeration. The
// project defines it locally so the feature remains independent from SDK-private
// declarations and can parse the raw NtQuerySystemInformation buffer directly.
struct KSYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    LONG BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
};

std::wstring UnicodeStringToWString(const UNICODE_STRING& value) {
    if (value.Buffer == nullptr || value.Length == 0) {
        return {};
    }
    return std::wstring(value.Buffer, value.Buffer + (value.Length / sizeof(wchar_t)));
}

DWORD HandleToProcessId(HANDLE value) {
    return static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(value));
}

bool IsGrowStatus(LONG status) {
    return status == kStatusInfoLengthMismatch ||
           status == kStatusBufferTooSmall ||
           status == kStatusBufferOverflow;
}

std::wstring NtStatusText(LONG status) {
    wchar_t buffer[64]{};
    ::swprintf_s(buffer, L"NTSTATUS 0x%08lX", static_cast<unsigned long>(status));
    return buffer;
}

} // namespace

std::wstring QueryProcessImagePath(DWORD processId) {
    if (processId == 0) {
        return {};
    }

    HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!process) {
        return {};
    }

    std::wstring path;
    std::vector<wchar_t> buffer(32768, L'\0');
    DWORD size = static_cast<DWORD>(buffer.size());
    if (::QueryFullProcessImageNameW(process, 0, buffer.data(), &size) && size > 0) {
        path.assign(buffer.data(), buffer.data() + size);
    }
    ::CloseHandle(process);
    return path;
}

ProcessEnumerationResult EnumerateProcessesByNtQuerySystemInformation() {
    ProcessEnumerationResult result;
    Ksword::Core::NtApi api;
    if (!api.available()) {
        result.success = false;
        result.ntStatus = kStatusProcedureNotFound;
        result.diagnosticText = L"NtQuerySystemInformation is unavailable.";
        return result;
    }

    ULONG bufferSize = 1u << 20;
    std::vector<std::byte> buffer;
    LONG status = kStatusProcedureNotFound;
    for (int attempt = 0; attempt < 8; ++attempt) {
        buffer.assign(bufferSize, std::byte{});
        ULONG returnLength = 0;
        status = api.querySystemInformation(
            Ksword::Core::SystemInformationClass::SystemProcessInformation,
            buffer.data(),
            bufferSize,
            &returnLength);
        if (status == kStatusSuccess) {
            break;
        }
        if (!IsGrowStatus(status)) {
            result.success = false;
            result.ntStatus = status;
            result.diagnosticText = L"NtQuerySystemInformation failed: " + NtStatusText(status);
            return result;
        }
        bufferSize = std::max<ULONG>(bufferSize * 2u, returnLength + 0x10000u);
    }

    if (status != kStatusSuccess) {
        result.success = false;
        result.ntStatus = status;
        result.diagnosticText = L"NtQuerySystemInformation retry limit reached: " + NtStatusText(status);
        return result;
    }

    std::size_t offset = 0;
    for (;;) {
        if (offset + sizeof(KSYSTEM_PROCESS_INFORMATION) > buffer.size()) {
            break;
        }
        const auto* info = reinterpret_cast<const KSYSTEM_PROCESS_INFORMATION*>(buffer.data() + offset);

        ProcessSnapshotRow row;
        row.processId = HandleToProcessId(info->UniqueProcessId);
        row.parentProcessId = HandleToProcessId(info->InheritedFromUniqueProcessId);
        row.handleCount = info->HandleCount;
        row.sessionId = info->SessionId;
        row.threadCount = info->NumberOfThreads;
        row.basePriority = info->BasePriority;
        row.kernelTime100ns = static_cast<ULONGLONG>(info->KernelTime.QuadPart);
        row.userTime100ns = static_cast<ULONGLONG>(info->UserTime.QuadPart);
        row.cycleTime = info->CycleTime;
        row.creationTime100ns = info->CreateTime.QuadPart > 0
            ? static_cast<ULONGLONG>(info->CreateTime.QuadPart)
            : 0U;
        row.workingSetBytes = info->WorkingSetSize;
        row.peakWorkingSetBytes = info->PeakWorkingSetSize;
        row.privatePageBytes = info->PrivatePageCount;
        row.virtualSizeBytes = info->VirtualSize;
        row.commitBytes = info->PagefileUsage;
        row.pagedPoolBytes = info->QuotaPagedPoolUsage;
        row.nonPagedPoolBytes = info->QuotaNonPagedPoolUsage;
        row.pageFaultCount = info->PageFaultCount;
        row.ioReadOperations = static_cast<ULONGLONG>(info->ReadOperationCount.QuadPart);
        row.ioWriteOperations = static_cast<ULONGLONG>(info->WriteOperationCount.QuadPart);
        row.ioOtherOperations = static_cast<ULONGLONG>(info->OtherOperationCount.QuadPart);
        row.ioReadBytes = static_cast<ULONGLONG>(info->ReadTransferCount.QuadPart);
        row.ioWriteBytes = static_cast<ULONGLONG>(info->WriteTransferCount.QuadPart);
        row.ioOtherBytes = static_cast<ULONGLONG>(info->OtherTransferCount.QuadPart);
        row.imageName = UnicodeStringToWString(info->ImageName);
        if (row.imageName.empty()) {
            row.imageName = row.processId == 0 ? L"System Idle Process" : L"System";
        }
        row.imagePath = QueryProcessImagePath(row.processId);
        result.rows.push_back(std::move(row));

        if (info->NextEntryOffset == 0) {
            break;
        }
        offset += info->NextEntryOffset;
    }

    result.success = true;
    result.ntStatus = kStatusSuccess;
    result.diagnosticText = L"OK";
    return result;
}

} // namespace Ksword::Features::Process
