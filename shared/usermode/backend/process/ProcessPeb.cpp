#include "ProcessPeb.h"
#include <algorithm>
#include <chrono>
#include <array>
#include <cerrno>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iomanip>
#include <sstream>
namespace ks::r3::process_detail::peb {
std::wstring FormatHex(const std::uint64_t value) {
    std::wostringstream text;
    text << L"0x" << std::hex << std::uppercase << value;
    return text.str();
}
std::wstring TrimCopy(std::wstring text) {
    const auto isSpace = [](const wchar_t value) { return std::iswspace(value) != 0; };
    text.erase(text.begin(), std::find_if_not(text.begin(), text.end(), isSpace));
    text.erase(std::find_if_not(text.rbegin(), text.rend(), isSpace).base(), text.end());
    return text;
}
bool ReadRemoteExact(
    HANDLE process,
    const std::uint64_t address,
    void* buffer,
    const SIZE_T bufferSize) {
    if (!process || address == 0 || !buffer || bufferSize == 0) {
        return false;
    }
    SIZE_T bytesRead = 0;
    return ::ReadProcessMemory(
               process,
               reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
               buffer,
               bufferSize,
               &bytesRead) != FALSE &&
        bytesRead == bufferSize;
}
std::wstring ReadRemoteUnicode(
    HANDLE process,
    const std::uint64_t address,
    const USHORT byteLength) {
    if (!process || address == 0 || byteLength == 0 ||
        (byteLength % sizeof(wchar_t)) != 0 || byteLength > kMaxRemoteUnicodeBytes) {
        return {};
    }
    std::vector<wchar_t> buffer(static_cast<std::size_t>(byteLength / sizeof(wchar_t)) + 1U, L'\0');
    SIZE_T bytesRead = 0;
    if (::ReadProcessMemory(
            process,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
            buffer.data(),
            byteLength,
            &bytesRead) == FALSE ||
        bytesRead == 0) {
        return {};
    }
    buffer[std::min<std::size_t>(buffer.size() - 1U, bytesRead / sizeof(wchar_t))] = L'\0';
    return std::wstring(buffer.data(), bytesRead / sizeof(wchar_t));
}
PebReadResult ReadPeb64(HANDLE process, const std::uint64_t pebAddress) {
    PebReadResult result{};
    result.name = L"NativePEB";
    result.pebAddress = pebAddress;
    Peb64Lite peb{};
    if (!ReadRemoteStructure(process, pebAddress, peb)) {
        result.diagnostic = L"读取64位PEB头失败。";
        return result;
    }
    result.beingDebugged = peb.beingDebugged != 0;
    result.imageBaseAddress = peb.imageBaseAddress;
    result.processParametersAddress = peb.processParameters;
    if (peb.processParameters == 0) {
        result.diagnostic = L"NativePEB.ProcessParameters为空。";
        return result;
    }
    RtlUserProcessParameters64Lite parameters{};
    if (!ReadRemoteStructure(process, peb.processParameters, parameters)) {
        result.diagnostic = L"读取64位RTL_USER_PROCESS_PARAMETERS失败。";
        return result;
    }
    result.environmentAddress = parameters.environment;
    result.commandLine = ReadRemoteUnicode(process, parameters.commandLine.buffer, parameters.commandLine.length);
    result.imagePath = ReadRemoteUnicode(process, parameters.imagePathName.buffer, parameters.imagePathName.length);
    result.currentDirectory = ReadRemoteUnicode(
        process,
        parameters.currentDirectory.dosPath.buffer,
        parameters.currentDirectory.dosPath.length);
    result.ok = true;
    return result;
}
PebReadResult ReadPeb32(HANDLE process, const std::uint64_t pebAddress) {
    PebReadResult result{};
    result.name = L"Wow64PEB";
    result.wow64 = true;
    result.pebAddress = pebAddress;
    Peb32Lite peb{};
    if (!ReadRemoteStructure(process, pebAddress, peb)) {
        result.diagnostic = L"读取32位PEB头失败。";
        return result;
    }
    result.beingDebugged = peb.beingDebugged != 0;
    result.imageBaseAddress = peb.imageBaseAddress;
    result.processParametersAddress = peb.processParameters;
    if (peb.processParameters == 0) {
        result.diagnostic = L"Wow64PEB.ProcessParameters为空。";
        return result;
    }
    RtlUserProcessParameters32Lite parameters{};
    if (!ReadRemoteStructure(process, peb.processParameters, parameters)) {
        result.diagnostic = L"读取32位RTL_USER_PROCESS_PARAMETERS失败。";
        return result;
    }
    result.environmentAddress = parameters.environment;
    result.commandLine = ReadRemoteUnicode(process, parameters.commandLine.buffer, parameters.commandLine.length);
    result.imagePath = ReadRemoteUnicode(process, parameters.imagePathName.buffer, parameters.imagePathName.length);
    result.currentDirectory = ReadRemoteUnicode(
        process,
        parameters.currentDirectory.dosPath.buffer,
        parameters.currentDirectory.dosPath.length);
    result.ok = true;
    return result;
}
std::vector<std::wstring> ReadEnvironmentPreview(
    HANDLE process,
    const std::uint64_t address,
    std::wstring& diagnostic) {
    std::vector<std::wstring> lines;
    if (!process || address == 0) {
        return lines;
    }
    std::vector<wchar_t> allChars;
    bool doubleNullFound = false;
    std::size_t byteOffset = 0;
    while (byteOffset < kMaxEnvironmentBytes && !doubleNullFound) {
        const std::size_t requestBytes = std::min(kEnvironmentChunkBytes, kMaxEnvironmentBytes - byteOffset);
        std::vector<std::uint8_t> bytes(requestBytes, 0U);
        SIZE_T bytesRead = 0;
        if (::ReadProcessMemory(
                process,
                reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address + byteOffset)),
                bytes.data(),
                requestBytes,
                &bytesRead) == FALSE ||
            bytesRead < sizeof(wchar_t)) {
            diagnostic = L"环境块读取在 offset=" + std::to_wstring(byteOffset) + L" 处停止。";
            break;
        }
        const std::size_t charCount = bytesRead / sizeof(wchar_t);
        const auto* chars = reinterpret_cast<const wchar_t*>(bytes.data());
        const std::size_t previousSize = allChars.size();
        allChars.insert(allChars.end(), chars, chars + charCount);
        const std::size_t scanBegin = previousSize == 0 ? 1U : previousSize;
        for (std::size_t index = scanBegin; index < allChars.size(); ++index) {
            if (allChars[index - 1U] == L'\0' && allChars[index] == L'\0') {
                allChars.resize(index + 1U);
                doubleNullFound = true;
                break;
            }
        }
        byteOffset += charCount * sizeof(wchar_t);
    }
    if (!doubleNullFound && diagnostic.empty()) {
        diagnostic = L"环境块超过128KB或缺少双NUL终止。";
    }
    std::size_t cursor = 0;
    while (cursor < allChars.size() && lines.size() < kMaxEnvironmentLines) {
        std::size_t length = 0;
        while (cursor + length < allChars.size() && allChars[cursor + length] != L'\0') {
            ++length;
        }
        if (length == 0) {
            break;
        }
        lines.emplace_back(allChars.data() + cursor, length);
        cursor += length + 1U;
    }
    return lines;
}
std::wstring PriorityClassText(const DWORD priorityClass) {
    switch (priorityClass) {
    case IDLE_PRIORITY_CLASS: return L"IDLE";
    case BELOW_NORMAL_PRIORITY_CLASS: return L"BELOW_NORMAL";
    case NORMAL_PRIORITY_CLASS: return L"NORMAL";
    case ABOVE_NORMAL_PRIORITY_CLASS: return L"ABOVE_NORMAL";
    case HIGH_PRIORITY_CLASS: return L"HIGH";
    case REALTIME_PRIORITY_CLASS: return L"REALTIME";
    default: return L"UNKNOWN(" + std::to_wstring(priorityClass) + L")";
    }
}
DWORD PriorityClassByComboIndex(const int index) {
    constexpr std::array<DWORD, 7> values{
        0,
        IDLE_PRIORITY_CLASS,
        BELOW_NORMAL_PRIORITY_CLASS,
        NORMAL_PRIORITY_CLASS,
        ABOVE_NORMAL_PRIORITY_CLASS,
        HIGH_PRIORITY_CLASS,
        REALTIME_PRIORITY_CLASS
    };
    return index >= 0 && index < static_cast<int>(values.size()) ? values[static_cast<std::size_t>(index)] : 0;
}
int ComboIndexByPriorityClass(const DWORD priorityClass) {
    for (int index = 1; index <= 6; ++index) {
        if (PriorityClassByComboIndex(index) == priorityClass) {
            return index;
        }
    }
    return 0;
}
bool ParseUnsigned(const std::wstring& source, std::uint64_t& value) {
    std::wstring text = TrimCopy(source);
    if (text.empty()) {
        return false;
    }
    int base = 10;
    if (text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X')) {
        text.erase(0, 2);
        base = 16;
    }
    wchar_t* end = nullptr;
    errno = 0;
    const unsigned long long parsed = std::wcstoull(text.c_str(), &end, base);
    if (errno != 0 || !end || *end != L'\0') {
        return false;
    }
    value = parsed;
    return true;
}
std::wstring MemoryStateText(const DWORD state) {
    switch (state) {
    case MEM_COMMIT: return L"Commit";
    case MEM_RESERVE: return L"Reserve";
    case MEM_FREE: return L"Free";
    default: return FormatHex(state);
    }
}
std::wstring MemoryTypeText(const DWORD type) {
    switch (type) {
    case MEM_IMAGE: return L"Image";
    case MEM_MAPPED: return L"Mapped";
    case MEM_PRIVATE: return L"Private";
    default: return FormatHex(type);
    }
}
std::wstring MemoryProtectText(const DWORD protect) {
    if (protect == 0) {
        return L"-";
    }
    std::wstring text;
    switch (protect & 0xFFU) {
    case PAGE_NOACCESS: text = L"NOACCESS"; break;
    case PAGE_READONLY: text = L"R"; break;
    case PAGE_READWRITE: text = L"RW"; break;
    case PAGE_WRITECOPY: text = L"WC"; break;
    case PAGE_EXECUTE: text = L"X"; break;
    case PAGE_EXECUTE_READ: text = L"XR"; break;
    case PAGE_EXECUTE_READWRITE: text = L"XRW"; break;
    case PAGE_EXECUTE_WRITECOPY: text = L"XWC"; break;
    default: text = FormatHex(protect & 0xFFU); break;
    }
    if ((protect & PAGE_GUARD) != 0) { text += L"|GUARD"; }
    if ((protect & PAGE_NOCACHE) != 0) { text += L"|NOCACHE"; }
    if ((protect & PAGE_WRITECOMBINE) != 0) { text += L"|WRITECOMBINE"; }
    return text;
}
ProcessPebSnapshot CollectPebSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns,
    const int selectedTarget) {
    ProcessPebSnapshot snapshot{};
    const auto begin = std::chrono::steady_clock::now();
    std::wostringstream report;
    report << L"[PEB / Process Summary]\r\n";
    report << L"PID: " << processId << L"\r\n";
    std::vector<std::wstring> diagnostics;
    std::vector<PebReadResult> pebResults;

    if (processId == 0U || expectedProcessCreationTime100ns == 0U) {
        report << L"ProcessIdentity: <unavailable>\r\n";
        snapshot.completed = true;
        snapshot.reportText = report.str();
        snapshot.statusText = L"● PEB 刷新已取消 | 进程身份不可用";
        return snapshot;
    }

    HANDLE process = ::OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE,
        processId);
    if (!process) {
        process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    }
    if (process) {
        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (!::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
            const DWORD identityError = ::GetLastError();
            report << L"ProcessIdentity: <GetProcessTimes failed>\r\n";
            diagnostics.push_back(L"GetProcessTimes(identity)失败(" + std::to_wstring(identityError) + L")");
            ::CloseHandle(process);
            snapshot.completed = true;
            snapshot.reportText = report.str();
            snapshot.statusText = L"● PEB 刷新已取消 | 无法验证进程身份";
            return snapshot;
        }
        const ULONGLONG actualProcessCreationTime100ns =
            (static_cast<ULONGLONG>(creationTime.dwHighDateTime) << 32U) |
            static_cast<ULONGLONG>(creationTime.dwLowDateTime);
        if (actualProcessCreationTime100ns == 0U ||
            actualProcessCreationTime100ns != expectedProcessCreationTime100ns) {
            report << L"ProcessIdentity: <changed>\r\n";
            diagnostics.push_back(L"目标进程实例已变更（PID 已复用），PEB 刷新被取消。");
            ::CloseHandle(process);
            snapshot.completed = true;
            snapshot.reportText = report.str();
            snapshot.statusText = L"● PEB 刷新已取消 | 目标进程实例已变更";
            return snapshot;
        }
        snapshot.identityMatched = true;
    }
    if (!process) {
        diagnostics.push_back(L"OpenProcess失败(" + std::to_wstring(::GetLastError()) + L")");
        report << L"OpenProcess: <failed>\r\n";
    } else {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        const auto ntQuery = reinterpret_cast<NtQueryInformationProcessFn>(
            ntdll ? ::GetProcAddress(ntdll, "NtQueryInformationProcess") : nullptr);
        ProcessBasicInformationLite basic{};
        if (ntQuery) {
            const LONG status = ntQuery(process, kProcessBasicInformationClass, &basic, sizeof(basic), nullptr);
            if (status >= 0 && basic.pebBaseAddress) {
                report << L"PEB Address: " << FormatHex(reinterpret_cast<std::uint64_t>(basic.pebBaseAddress)) << L"\r\n";
                pebResults.push_back(ReadPeb64(process, reinterpret_cast<std::uint64_t>(basic.pebBaseAddress)));
            } else {
                diagnostics.push_back(L"ProcessBasicInformation未返回可用PEB地址。");
            }
            ULONG_PTR wow64Peb = 0;
            const LONG wowStatus = ntQuery(process, kProcessWow64InformationClass, &wow64Peb, sizeof(wow64Peb), nullptr);
            if (wowStatus >= 0 && wow64Peb != 0 && wow64Peb != reinterpret_cast<ULONG_PTR>(basic.pebBaseAddress)) {
                pebResults.push_back(ReadPeb32(process, static_cast<std::uint64_t>(wow64Peb)));
            }
        } else {
            diagnostics.push_back(L"NtQueryInformationProcess不可用。");
        }

        ULONG_PTR processAffinity = 0;
        ULONG_PTR systemAffinity = 0;
        if (::GetProcessAffinityMask(process, &processAffinity, &systemAffinity)) {
            report << L"ProcessAffinity: " << FormatHex(processAffinity) << L"\r\n";
            report << L"CpuCoreAffinity: ";
            bool first = true;
            for (unsigned int bit = 0; bit < sizeof(ULONG_PTR) * 8U; ++bit) {
                if ((processAffinity & (static_cast<ULONG_PTR>(1) << bit)) == 0) { continue; }
                if (!first) { report << L","; }
                report << bit;
                first = false;
            }
            report << L"\r\n";
            snapshot.affinityKnown = true;
            snapshot.affinityText = FormatHex(processAffinity);
        }

        const DWORD priorityClass = ::GetPriorityClass(process);
        report << L"PriorityClass: " << PriorityClassText(priorityClass) << L"\r\n";
        snapshot.priorityKnown = priorityClass != 0;
        snapshot.priorityComboIndex = ComboIndexByPriorityClass(priorityClass);

        USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (::IsWow64Process2(process, &processMachine, &nativeMachine)) {
            report << L"Wow64ProcessMachine: " << FormatHex(processMachine) << L"\r\n";
            report << L"Wow64NativeMachine: " << FormatHex(nativeMachine) << L"\r\n";
        }

        FILETIME creationTime{}, exitTime{}, kernelTime{}, userTime{};
        if (::GetProcessTimes(process, &creationTime, &exitTime, &kernelTime, &userTime)) {
            ULARGE_INTEGER kernel{};
            kernel.LowPart = kernelTime.dwLowDateTime;
            kernel.HighPart = kernelTime.dwHighDateTime;
            ULARGE_INTEGER user{};
            user.LowPart = userTime.dwLowDateTime;
            user.HighPart = userTime.dwHighDateTime;
            report << L"KernelCpuMs: " << static_cast<double>(kernel.QuadPart) / 10000.0 << L"\r\n";
            report << L"UserCpuMs: " << static_cast<double>(user.QuadPart) / 10000.0 << L"\r\n";
        }

        PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
        if (::GetProcessMemoryInfo(
                process,
                reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
                sizeof(memoryCounters))) {
            report << L"WorkingSet: " << memoryCounters.WorkingSetSize << L" bytes\r\n";
            report << L"PrivateUsage: " << memoryCounters.PrivateUsage << L" bytes\r\n";
            report << L"PeakWorkingSet: " << memoryCounters.PeakWorkingSetSize << L" bytes\r\n";
            report << L"QuotaPagedPool: " << memoryCounters.QuotaPagedPoolUsage << L" bytes\r\n";
            report << L"QuotaNonPagedPool: " << memoryCounters.QuotaNonPagedPoolUsage << L" bytes\r\n";
            report << L"PageFaultCount: " << memoryCounters.PageFaultCount << L"\r\n";
        }

        IO_COUNTERS io{};
        if (::GetProcessIoCounters(process, &io)) {
            report << L"ReadOps: " << io.ReadOperationCount << L"\r\n";
            report << L"WriteOps: " << io.WriteOperationCount << L"\r\n";
            report << L"ReadBytes: " << io.ReadTransferCount << L"\r\n";
            report << L"WriteBytes: " << io.WriteTransferCount << L"\r\n";
        }

        for (PebReadResult& peb : pebResults) {
            if (!peb.ok) {
                diagnostics.push_back(peb.name + L": " + peb.diagnostic);
                continue;
            }
            report << L"[" << peb.name << L"]\r\n";
            report << L"  PebAddress: " << FormatHex(peb.pebAddress) << L"\r\n";
            report << L"  ProcessParameters: " << FormatHex(peb.processParametersAddress) << L"\r\n";
            report << L"  ImageBaseAddress: " << FormatHex(peb.imageBaseAddress) << L"\r\n";
            report << L"  Environment: " << FormatHex(peb.environmentAddress) << L"\r\n";
            report << L"  BeingDebugged: " << (peb.beingDebugged ? L"true" : L"false") << L"\r\n";
            if (!peb.commandLine.empty()) { report << L"CommandLine(" << peb.name << L"): " << peb.commandLine << L"\r\n"; }
            if (!peb.imagePath.empty()) { report << L"ImagePath(" << peb.name << L"): " << peb.imagePath << L"\r\n"; }
            if (!peb.currentDirectory.empty()) { report << L"CurrentDirectory(" << peb.name << L"): " << peb.currentDirectory << L"\r\n"; }
        }

        const wchar_t* targetName = selectedTarget == 1 ? L"Wow64PEB" : L"NativePEB";
        const auto selectedPeb = std::find_if(pebResults.begin(), pebResults.end(), [targetName](const PebReadResult& peb) {
            return peb.ok && peb.name == targetName;
        });
        if (selectedPeb != pebResults.end()) {
            snapshot.selectedPebKnown = true;
            snapshot.commandLine = selectedPeb->commandLine;
            snapshot.imagePath = selectedPeb->imagePath;
            snapshot.currentDirectory = selectedPeb->currentDirectory;
            snapshot.imageBase = FormatHex(selectedPeb->imageBaseAddress);

            if (selectedPeb->imageBaseAddress != 0) {
                IMAGE_DOS_HEADER dos{};
                if (ReadRemoteStructure(process, selectedPeb->imageBaseAddress, dos) &&
                    dos.e_magic == IMAGE_DOS_SIGNATURE && dos.e_lfanew > 0 && dos.e_lfanew < 0x100000) {
                    IMAGE_NT_HEADERS64 nt{};
                    if (ReadRemoteStructure(process, selectedPeb->imageBaseAddress + dos.e_lfanew, nt) &&
                        nt.Signature == IMAGE_NT_SIGNATURE) {
                        report << L"ImageBaseAddress: " << FormatHex(selectedPeb->imageBaseAddress) << L"\r\n";
                        report << L"EntryPointRva: " << FormatHex(nt.OptionalHeader.AddressOfEntryPoint) << L"\r\n";
                        report << L"EntryPointAddress: "
                               << FormatHex(selectedPeb->imageBaseAddress + nt.OptionalHeader.AddressOfEntryPoint)
                               << L"\r\n";
                    }
                }
            }
        }

        const auto environmentPeb = std::find_if(pebResults.begin(), pebResults.end(), [](const PebReadResult& peb) {
            return peb.ok && peb.environmentAddress != 0;
        });
        report << L"[EnvironmentPreview";
        if (environmentPeb != pebResults.end()) { report << L":" << environmentPeb->name; }
        report << L"]\r\n";
        if (environmentPeb != pebResults.end()) {
            std::wstring environmentDiagnostic;
            const std::vector<std::wstring> environment = ReadEnvironmentPreview(
                process,
                environmentPeb->environmentAddress,
                environmentDiagnostic);
            for (const std::wstring& line : environment) {
                report << L"  " << line << L"\r\n";
            }
            if (environment.empty()) { report << L"  <unavailable>\r\n"; }
            if (!environmentDiagnostic.empty()) { diagnostics.push_back(environmentDiagnostic); }
        } else {
            report << L"  <unavailable>\r\n";
        }

        SYSTEM_INFO systemInfo{};
        ::GetSystemInfo(&systemInfo);
        std::uintptr_t cursor = reinterpret_cast<std::uintptr_t>(systemInfo.lpMinimumApplicationAddress);
        const std::uintptr_t maximum = reinterpret_cast<std::uintptr_t>(systemInfo.lpMaximumApplicationAddress);
        std::uint64_t regionCount = 0;
        std::uint64_t previewCount = 0;
        std::uint64_t commitBytes = 0;
        std::uint64_t mappedBytes = 0;
        std::uint64_t imageBytes = 0;
        std::uint64_t privateBytes = 0;
        const auto deadline = begin + std::chrono::seconds(8);
        report << L"[VirtualAddressRegionPreview]\r\n";
        while (cursor < maximum && regionCount < kMaxRegionCount && std::chrono::steady_clock::now() <= deadline) {
            MEMORY_BASIC_INFORMATION info{};
            if (::VirtualQueryEx(process, reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0 || info.RegionSize == 0) {
                break;
            }
            ++regionCount;
            if (info.State == MEM_COMMIT) { commitBytes += info.RegionSize; }
            if (info.Type == MEM_MAPPED) { mappedBytes += info.RegionSize; }
            if (info.Type == MEM_IMAGE) { imageBytes += info.RegionSize; }
            if (info.Type == MEM_PRIVATE) { privateBytes += info.RegionSize; }
            if (info.State == MEM_COMMIT && previewCount < kMaxPreviewRegions) {
                const std::uint64_t start = reinterpret_cast<std::uint64_t>(info.BaseAddress);
                report << L"  " << FormatHex(start) << L"-" << FormatHex(start + info.RegionSize)
                       << L" | " << MemoryStateText(info.State)
                       << L" | " << MemoryProtectText(info.Protect)
                       << L" | " << MemoryTypeText(info.Type);
                if (info.Type == MEM_MAPPED || info.Type == MEM_IMAGE) {
                    wchar_t mappedPath[1024]{};
                    if (::GetMappedFileNameW(process, info.BaseAddress, mappedPath, static_cast<DWORD>(std::size(mappedPath))) > 0) {
                        report << L" | " << mappedPath;
                    }
                }
                report << L"\r\n";
                ++previewCount;
            }
            const std::uintptr_t next = cursor + info.RegionSize;
            if (next <= cursor) { break; }
            cursor = next;
        }
        if (regionCount >= kMaxRegionCount) { diagnostics.push_back(L"虚拟内存枚举达到60000行上限。"); }
        if (std::chrono::steady_clock::now() > deadline) { diagnostics.push_back(L"虚拟内存枚举超过8秒，已返回部分结果。"); }
        report << L"RegionCount: " << regionCount << L"\r\n";
        report << L"CommitBytes: " << commitBytes << L"\r\n";
        report << L"MappedBytes: " << mappedBytes << L"\r\n";
        report << L"ImageBytes: " << imageBytes << L"\r\n";
        report << L"PrivateBytes: " << privateBytes << L"\r\n";
        report << L"HeapCount: <skipped>\r\n";
        report << L"HeapBlockCount: <skipped>\r\n";
        report << L"HeapBlockEnumeration: <skipped to keep PEB refresh bounded>\r\n";
        ::CloseHandle(process);
    }

    if (!diagnostics.empty()) {
        report << L"[Diagnostic]\r\n";
        for (const std::wstring& diagnostic : diagnostics) {
            report << L"  " << diagnostic << L"\r\n";
        }
    }
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - begin).count();
    snapshot.completed = true;
    snapshot.reportText = report.str();
    snapshot.statusText =
        L"● 后台刷新完成 " + std::to_wstring(elapsed) + L" ms" +
        (diagnostics.empty() ? L"" : L" | 存在降级/诊断信息");
    return snapshot;
}
ProcessDetailActionResult ApplyPebAttributes(DWORD processId, ULONGLONG expectedProcessCreationTime100ns, const std::wstring& commandLine, const std::wstring& imagePath, const std::wstring& currentDirectory, const std::wstring& environmentName, const std::wstring& imageBase, const std::wstring& affinityText, int priorityIndex) {

            ProcessDetailActionResult action{};
            ks::r3::common::UniqueHandle verifiedProcess;
            std::wstring identityError;
            if (!OpenVerifiedProcessActionTarget(
                    processId,
                    expectedProcessCreationTime100ns,
                    PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION,
                    verifiedProcess,
                    identityError)) {
                action.statusText = L"● PEB 修改失败：" + identityError;
                action.dialogTitle = L"PEB 修改失败";
                action.dialogText = identityError;
                action.dialogIcon = MB_ICONERROR;
                return action;
            }
            HANDLE process = verifiedProcess.get();

            std::vector<std::wstring> results;
            int successCount = 0;
            int failCount = 0;
            int skippedCount = 0;
            const auto skippedRemote = [&](const wchar_t* field, const std::wstring& value) {
                if (value.empty()) { return; }
                ++skippedCount;
                results.push_back(std::wstring(L"[跳过] ") + field + L"：Light 远程PEB写入未启用，未执行任何写操作。");
            };
            skippedRemote(L"CommandLine", commandLine);
            skippedRemote(L"ImagePathName", imagePath);
            skippedRemote(L"CurrentDirectory", currentDirectory);
            if (!TrimCopy(environmentName).empty()) {
                skippedRemote(L"Environment", environmentName);
            }
            skippedRemote(L"ImageBaseAddress", imageBase);

            if (affinityText.empty()) {
                ++skippedCount;
                results.push_back(L"[跳过] AffinityMask：输入为空。");
            } else {
                std::uint64_t requestedAffinity = 0;
                ULONG_PTR currentAffinity = 0;
                ULONG_PTR systemAffinity = 0;
                if (!ParseUnsigned(affinityText, requestedAffinity) || requestedAffinity == 0 ||
                    requestedAffinity > std::numeric_limits<ULONG_PTR>::max()) {
                    ++failCount;
                    results.push_back(L"[失败] AffinityMask：格式无效、为0或超过当前位宽。");
                } else if (::GetProcessAffinityMask(process, &currentAffinity, &systemAffinity) &&
                           requestedAffinity == static_cast<std::uint64_t>(currentAffinity)) {
                    ++skippedCount;
                    results.push_back(L"[跳过] AffinityMask：未变化。");
                } else if (::SetProcessAffinityMask(process, static_cast<ULONG_PTR>(requestedAffinity))) {
                    ++successCount;
                    results.push_back(L"[成功] AffinityMask：已设置为 " + FormatHex(requestedAffinity) + L"。");
                } else {
                    ++failCount;
                    results.push_back(L"[失败] AffinityMask：SetProcessAffinityMask失败(" +
                        std::to_wstring(::GetLastError()) + L")。");
                }
            }

            const DWORD requestedPriority = PriorityClassByComboIndex(priorityIndex);
            if (requestedPriority == 0) {
                ++skippedCount;
                results.push_back(L"[跳过] PriorityClass：选择为不修改。");
            } else {
                const DWORD currentPriority = ::GetPriorityClass(process);
                if (currentPriority == requestedPriority) {
                    ++skippedCount;
                    results.push_back(L"[跳过] PriorityClass：未变化。");
                } else if (::SetPriorityClass(process, requestedPriority)) {
                    ++successCount;
                    results.push_back(L"[成功] PriorityClass：已设置为 " + PriorityClassText(requestedPriority) + L"。");
                } else {
                    ++failCount;
                    results.push_back(L"[失败] PriorityClass：SetPriorityClass失败(" +
                        std::to_wstring(::GetLastError()) + L")。");
                }
            }
            std::wostringstream resultText;
            resultText << L"成功 " << successCount << L"，失败 " << failCount << L"，跳过 " << skippedCount << L"\r\n\r\n";
            for (const std::wstring& line : results) {
                resultText << line << L"\r\n";
            }
            action.statusText =
                L"● PEB修改完成：成功 " + std::to_wstring(successCount) +
                L"，失败 " + std::to_wstring(failCount) +
                L"，跳过 " + std::to_wstring(skippedCount);
            action.dialogTitle = L"PEB 修改结果";
            action.dialogText = resultText.str();
            action.dialogIcon = MB_ICONINFORMATION;
            action.refreshPebReport = true;
            return action;

}
}
