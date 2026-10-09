#include "FileHolderScanner.h"

#include "../NtApi.h"
#include "ModulePath.h"

#include <winternl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ks::r3::system_tools {
namespace {

constexpr LONG kStatusSuccess = 0x00000000L;

// SystemExtendedHandleInformation is not declared by the public SDK, so the
// value is passed through the existing Core::SystemInformationClass wrapper.
// The extended class is used rather than the classic SystemHandleInformation
// because the latter truncates the owning PID to 16 bits, which silently
// misattributes handles on machines that hand out PIDs above 65535.
constexpr ULONG kSystemExtendedHandleInformation = 64;

constexpr ULONG kObjectNameInformation = 1;
constexpr ULONG kObjectTypeInformation = 2;

// kNameQueryTimeoutMs bounds one NtQueryObject(ObjectNameInformation) call. A
// healthy local file answers in microseconds; anything that has not answered in
// a quarter second is a hang, not slow I/O.
constexpr DWORD kNameQueryTimeoutMs = 250;

using NtQueryObjectFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

// SysToolsObjectNameInformation mirrors the object-manager name reply. It is
// declared locally instead of relying on winternl.h so this file does not break
// when a future SDK changes which of these structures it chooses to publish.
struct SysToolsObjectNameInformation {
    UNICODE_STRING Name;
};

struct SysToolsObjectTypeInformation {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];
};

struct SysToolsHandleTableEntry {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct SysToolsHandleInformationEx {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SysToolsHandleTableEntry Handles[1];
};

NtQueryObjectFn ResolveNtQueryObject() {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    return ntdll ? reinterpret_cast<NtQueryObjectFn>(::GetProcAddress(ntdll, "NtQueryObject")) : nullptr;
}

std::wstring ToLowerCopy(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(::towlower(ch));
    });
    return text;
}

bool EqualsIgnoreCase(const std::wstring& left, const std::wstring& right) {
    return left.size() == right.size() && ::_wcsicmp(left.c_str(), right.c_str()) == 0;
}

bool StartsWithIgnoreCase(const std::wstring& text, const std::wstring& prefix) {
    return text.size() >= prefix.size() &&
        ::_wcsnicmp(text.c_str(), prefix.c_str(), prefix.size()) == 0;
}

// DriveDeviceMap is the drive-letter to \Device\... translation table. It is
// built once per sweep because QueryDosDeviceW is a per-call round trip into the
// object manager and the sweep would otherwise repeat it tens of thousands of
// times.
struct DriveDeviceMap final {
    std::vector<std::pair<std::wstring, std::wstring>> pairs;  // "C:" -> "\Device\HarddiskVolume3"
};

const DriveDeviceMap& DriveMap() {
    static const DriveDeviceMap map = [] {
        DriveDeviceMap built{};
        for (wchar_t letter = L'A'; letter <= L'Z'; ++letter) {
            const std::wstring drive = std::wstring(1, letter) + L":";
            wchar_t device[512] = {};
            if (::QueryDosDeviceW(drive.c_str(), device, static_cast<DWORD>(std::size(device))) == 0) {
                continue;
            }
            // QueryDosDeviceW can return a multi-sz for a drive with several
            // targets; only the first entry is the live mapping.
            built.pairs.emplace_back(drive, std::wstring(device));
        }
        return built;
    }();
    return map;
}

// ProbeOutcome distinguishes how a name query ended, because the sweep counts a
// deliberately skipped non-disk handle differently from one it actually
// inspected, and an abandoned query differently again.
enum class ProbeOutcome {
    Named,      // The object name was returned.
    NotDisk,    // Filtered out before naming; never reached NtQueryObject.
    Failed,     // The query ran and returned nothing usable.
    TimedOut    // The helper thread was abandoned.
};

// ObjectNameProbe runs the blocking part of the sweep on a helper thread so a
// hung call cannot take the sweep with it.
//
// Avoidance strategy, in the order it is applied:
//   1. Only handles whose object type index matches the File type are touched,
//      so no other object class is ever named.
//   2. Every survivor is duplicated and, on the helper thread, passed through
//      GetFileType(). Only FILE_TYPE_DISK continues. Pipes, consoles and
//      character devices -- the objects whose name query blocks waiting on a
//      peer that is under no obligation to answer -- are rejected here.
//      GetFileType runs on the helper rather than on the sweep thread so that
//      even it is covered by the timeout below.
//   3. Whatever gets through is named on the same helper, with a bounded wait.
//      On timeout the helper is abandoned rather than killed: TerminateThread on
//      a thread parked inside the object manager would leave process-wide locks
//      held and can deadlock the whole application, which is strictly worse than
//      leaking one thread and one handle. A replacement helper is created for the
//      next handle, so the sweep always finishes.
//
// Note on what is deliberately NOT done: the widely copied trick of dropping
// handles whose granted access is 0x0012019F / 0x00120189 / 0x00100000 is not
// used. Those masks are supposed to identify synchronous pipe ends, but
// 0x0012019F is simply FILE_GENERIC_READ | FILE_GENERIC_WRITE -- what every
// ordinary file opened for read/write carries -- so the heuristic silently
// discards the majority of the handles this page exists to find. The type-index
// and GetFileType gates above achieve the same protection without the false
// negatives.
class ObjectNameProbe final {
public:
    explicit ObjectNameProbe(NtQueryObjectFn queryObject) : queryObject_(queryObject) {}

    ~ObjectNameProbe() {
        shutdownChannel();
    }

    ObjectNameProbe(const ObjectNameProbe&) = delete;
    ObjectNameProbe& operator=(const ObjectNameProbe&) = delete;

    // queryName takes ownership of duplicatedHandle in every path, including
    // the timeout path where the abandoned helper closes it later. The caller
    // must never close the handle itself.
    ProbeOutcome queryName(HANDLE duplicatedHandle, std::wstring& nameOut) {
        nameOut.clear();
        if (!queryObject_ || !duplicatedHandle) {
            if (duplicatedHandle) {
                ::CloseHandle(duplicatedHandle);
            }
            return ProbeOutcome::Failed;
        }
        if (!ensureChannel()) {
            ::CloseHandle(duplicatedHandle);
            return ProbeOutcome::Failed;
        }

        channel_->target = duplicatedHandle;
        ::SetEvent(channel_->requestEvent);
        if (::WaitForSingleObject(channel_->replyEvent, kNameQueryTimeoutMs) != WAIT_OBJECT_0) {
            ++timeoutCount_;
            abandonChannel();
            return ProbeOutcome::TimedOut;
        }
        if (channel_->outcome != ProbeOutcome::Named) {
            return channel_->outcome;
        }
        nameOut = channel_->name;
        return ProbeOutcome::Named;
    }

    std::uint32_t timeoutCount() const noexcept {
        return timeoutCount_;
    }

private:
    struct Channel final {
        HANDLE requestEvent = nullptr;
        HANDLE replyEvent = nullptr;
        HANDLE target = nullptr;
        std::wstring name;
        ProbeOutcome outcome = ProbeOutcome::Failed;
        std::atomic_bool shutdown{ false };

        ~Channel() {
            if (requestEvent) {
                ::CloseHandle(requestEvent);
            }
            if (replyEvent) {
                ::CloseHandle(replyEvent);
            }
        }
    };

    static bool QueryNameDirect(NtQueryObjectFn queryObject, HANDLE handle, std::wstring& nameOut) {
        std::vector<std::byte> buffer(4096);
        for (int attempt = 0; attempt < 3; ++attempt) {
            ULONG needed = 0;
            const LONG status = queryObject(
                handle, kObjectNameInformation, buffer.data(), static_cast<ULONG>(buffer.size()), &needed);
            if (status == kStatusSuccess) {
                const auto* info = reinterpret_cast<const SysToolsObjectNameInformation*>(buffer.data());
                if (!info->Name.Buffer || info->Name.Length == 0) {
                    return false;
                }
                nameOut.assign(info->Name.Buffer, info->Name.Length / sizeof(wchar_t));
                return true;
            }
            if (needed <= buffer.size()) {
                return false;
            }
            buffer.resize(needed + 256);
        }
        return false;
    }

    bool ensureChannel() {
        if (channel_) {
            return true;
        }
        auto channel = std::make_shared<Channel>();
        channel->requestEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
        channel->replyEvent = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
        if (!channel->requestEvent || !channel->replyEvent) {
            return false;
        }

        const NtQueryObjectFn queryObject = queryObject_;
        std::thread([channel, queryObject]() {
            while (::WaitForSingleObject(channel->requestEvent, INFINITE) == WAIT_OBJECT_0) {
                if (channel->shutdown.load(std::memory_order_acquire)) {
                    break;
                }
                HANDLE target = channel->target;
                channel->target = nullptr;
                std::wstring name;
                ProbeOutcome outcome = ProbeOutcome::Failed;
                if (target) {
                    // GetFileType is answered by the I/O manager from the device
                    // object without dispatching an IRP, but it still runs here
                    // rather than on the sweep thread so that the timeout covers
                    // every kernel call made against a foreign handle.
                    if (::GetFileType(target) != FILE_TYPE_DISK) {
                        outcome = ProbeOutcome::NotDisk;
                    } else if (QueryNameDirect(queryObject, target, name)) {
                        outcome = ProbeOutcome::Named;
                    }
                    ::CloseHandle(target);
                }
                channel->name = std::move(name);
                channel->outcome = outcome;
                ::SetEvent(channel->replyEvent);
                // An abandoned helper reaches this point whenever the kernel
                // finally releases it. Exiting here is what keeps a timeout from
                // leaking the thread permanently.
                if (channel->shutdown.load(std::memory_order_acquire)) {
                    break;
                }
            }
        }).detach();

        channel_ = std::move(channel);
        return true;
    }

    // abandonChannel drops this probe's reference to a helper that is stuck
    // inside the kernel. The helper keeps the Channel alive through its own
    // shared_ptr, so nothing it touches afterwards has been freed.
    void abandonChannel() {
        if (channel_) {
            channel_->shutdown.store(true, std::memory_order_release);
        }
        channel_.reset();
    }

    void shutdownChannel() {
        if (!channel_) {
            return;
        }
        channel_->shutdown.store(true, std::memory_order_release);
        ::SetEvent(channel_->requestEvent);
        channel_.reset();
    }

private:
    NtQueryObjectFn queryObject_ = nullptr;
    std::shared_ptr<Channel> channel_;
    std::uint32_t timeoutCount_ = 0;
};

std::wstring FormatAccessMask(const ULONG mask) {
    struct Bit {
        ULONG value;
        const wchar_t* label;
    };
    static const Bit bits[] = {
        { FILE_READ_DATA, L"读数据" },
        { FILE_WRITE_DATA, L"写数据" },
        { FILE_APPEND_DATA, L"追加" },
        { FILE_READ_EA, L"读扩展属性" },
        { FILE_WRITE_EA, L"写扩展属性" },
        { FILE_EXECUTE, L"执行" },
        { FILE_READ_ATTRIBUTES, L"读属性" },
        { FILE_WRITE_ATTRIBUTES, L"写属性" },
        { DELETE, L"删除" },
        { READ_CONTROL, L"读安全描述符" },
        { WRITE_DAC, L"改DACL" },
        { WRITE_OWNER, L"改所有者" },
        { SYNCHRONIZE, L"同步" },
    };
    std::wstring text;
    for (const Bit& bit : bits) {
        if ((mask & bit.value) == bit.value) {
            if (!text.empty()) {
                text += L" | ";
            }
            text += bit.label;
        }
    }
    if (text.empty()) {
        text = L"无";
    }
    return text;
}

// ProcessNameMap resolves PID to image name once per sweep. Toolhelp is used
// rather than QueryFullProcessImageNameW on the duplicated process handle
// because it also names the processes this build cannot open, and an
// unattributed PID in the result table is not useful to anyone.
std::unordered_map<std::uint32_t, std::wstring> BuildProcessNameMap() {
    std::unordered_map<std::uint32_t, std::wstring> map;
    HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return map;
    }
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (::Process32FirstW(snapshot, &entry)) {
        do {
            map.emplace(static_cast<std::uint32_t>(entry.th32ProcessID), std::wstring(entry.szExeFile));
        } while (::Process32NextW(snapshot, &entry));
    }
    ::CloseHandle(snapshot);
    return map;
}

std::wstring QueryProcessImagePath(HANDLE process) {
    if (!process) {
        return {};
    }
    wchar_t buffer[MAX_PATH * 2] = {};
    DWORD size = static_cast<DWORD>(std::size(buffer));
    if (!::QueryFullProcessImageNameW(process, 0, buffer, &size)) {
        return {};
    }
    return std::wstring(buffer, size);
}

// ProcessHandleCache keeps one PROCESS_DUP_HANDLE handle per PID. Reopening a
// process for every one of its handles is the single most expensive mistake a
// sweep like this can make.
class ProcessHandleCache final {
public:
    ~ProcessHandleCache() {
        for (auto& item : handles_) {
            if (item.second) {
                ::CloseHandle(item.second);
            }
        }
    }

    HANDLE get(const std::uint32_t processId) {
        const auto found = handles_.find(processId);
        if (found != handles_.end()) {
            return found->second;
        }
        HANDLE process = ::OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
        if (!process) {
            process = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);
        }
        handles_.emplace(processId, process);
        return process;
    }

private:
    std::unordered_map<std::uint32_t, HANDLE> handles_;
};

// ResolveFileTypeIndex learns the object type index the running kernel uses for
// File. The index is not stable across Windows versions, so it is discovered by
// opening a file this process certainly owns and finding that handle in the same
// snapshot the sweep is about to walk.
USHORT ResolveFileTypeIndex(const SysToolsHandleInformationEx& info,
    const std::uint32_t ownProcessId,
    NtQueryObjectFn queryObject,
    HANDLE probeHandle) {
    if (probeHandle && probeHandle != INVALID_HANDLE_VALUE) {
        const auto probeValue = reinterpret_cast<ULONG_PTR>(probeHandle);
        for (ULONG_PTR index = 0; index < info.NumberOfHandles; ++index) {
            const SysToolsHandleTableEntry& entry = info.Handles[index];
            if (static_cast<std::uint32_t>(entry.UniqueProcessId) == ownProcessId &&
                entry.HandleValue == probeValue) {
                return entry.ObjectTypeIndex;
            }
        }
    }

    // Fallback: ask the object manager for the type name of the probe handle and
    // match it against the snapshot by name. This costs one extra call and only
    // runs when the handle could not be located above.
    if (queryObject && probeHandle && probeHandle != INVALID_HANDLE_VALUE) {
        std::vector<std::byte> buffer(2048);
        ULONG needed = 0;
        if (queryObject(probeHandle, kObjectTypeInformation, buffer.data(),
                static_cast<ULONG>(buffer.size()), &needed) == kStatusSuccess) {
            const auto* type = reinterpret_cast<const SysToolsObjectTypeInformation*>(buffer.data());
            if (type->TypeName.Buffer && type->TypeName.Length > 0) {
                const std::wstring name(type->TypeName.Buffer, type->TypeName.Length / sizeof(wchar_t));
                if (EqualsIgnoreCase(name, L"File")) {
                    // The name matched but the handle was absent from the
                    // snapshot, which only happens when the snapshot predates
                    // the probe handle. There is nothing better to return.
                    return 0;
                }
            }
        }
    }
    return 0;
}

} // namespace

std::wstring ResolveWin32PathToNtPath(const std::wstring& win32Path) {
    if (win32Path.empty()) {
        return {};
    }
    if (StartsWithIgnoreCase(win32Path, L"\\Device\\")) {
        return win32Path;
    }
    std::wstring path = win32Path;
    // Strip the Win32 long-path and device prefixes so the drive letter below is
    // found in both "C:\x" and "\\?\C:\x" spellings.
    if (StartsWithIgnoreCase(path, L"\\\\?\\") || StartsWithIgnoreCase(path, L"\\\\.\\")) {
        path.erase(0, 4);
    }
    if (StartsWithIgnoreCase(path, L"\\??\\")) {
        path.erase(0, 4);
    }
    if (path.size() >= 2 && path[1] == L':') {
        const std::wstring drive = path.substr(0, 2);
        for (const auto& pair : DriveMap().pairs) {
            if (EqualsIgnoreCase(pair.first, drive)) {
                return pair.second + path.substr(2);
            }
        }
        return path;
    }
    if (path.size() > 2 && path[0] == L'\\' && path[1] == L'\\') {
        // UNC shares surface as \Device\Mup\server\share under the object
        // manager. This is a best-effort mapping: a redirector that publishes a
        // different device prefix will simply not match.
        return L"\\Device\\Mup" + path.substr(1);
    }
    return path;
}

std::wstring ResolveNtPathToWin32Path(const std::wstring& ntPath) {
    if (ntPath.empty()) {
        return {};
    }
    for (const auto& pair : DriveMap().pairs) {
        if (StartsWithIgnoreCase(ntPath, pair.second) &&
            (ntPath.size() == pair.second.size() || ntPath[pair.second.size()] == L'\\')) {
            return pair.first + ntPath.substr(pair.second.size());
        }
    }
    if (StartsWithIgnoreCase(ntPath, L"\\Device\\Mup\\")) {
        return L"\\" + ntPath.substr(11);
    }
    return ntPath;
}

FileHolderScanResult ScanFileHolders(const std::wstring& targetPath, const bool includeSubPaths) {
    FileHolderScanResult result{};
    const ULONGLONG startTick = ::GetTickCount64();

    std::wstring trimmed = targetPath;
    while (!trimmed.empty() && (trimmed.front() == L' ' || trimmed.front() == L'"')) {
        trimmed.erase(trimmed.begin());
    }
    while (!trimmed.empty() && (trimmed.back() == L' ' || trimmed.back() == L'"')) {
        trimmed.pop_back();
    }
    if (trimmed.empty()) {
        result.diagnosticText = L"请输入要检查的文件或目录路径。";
        return result;
    }
    // A trailing separator would make the prefix comparison below reject the
    // directory itself, so it is normalized away up front.
    while (trimmed.size() > 3 && trimmed.back() == L'\\') {
        trimmed.pop_back();
    }

    result.targetNtPath = ResolveWin32PathToNtPath(trimmed);
    if (result.targetNtPath.empty()) {
        result.diagnosticText = L"无法把目标路径解析为对象管理器路径。";
        return result;
    }

    const NtQueryObjectFn queryObject = ResolveNtQueryObject();
    if (!queryObject) {
        result.diagnosticText = L"ntdll!NtQueryObject 不可用，无法解析句柄对象名。";
        return result;
    }

    // The probe handle is opened before the snapshot so it is guaranteed to be
    // inside it. FILE_READ_ATTRIBUTES with full sharing opens even a file that
    // is exclusively locked by someone else, which is exactly the case this page
    // exists to investigate.
    HANDLE probeHandle = ::CreateFileW(
        trimmed.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        nullptr);
    if (probeHandle == INVALID_HANDLE_VALUE) {
        // Falling back to this module's own image keeps the File type index
        // discoverable even when the target itself cannot be opened at all.
        probeHandle = ::CreateFileW(
            ks::r3::common::ModulePath().c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr);
    }

    const std::vector<std::byte> raw = ks::r3::common::QueryRawSystemInformation(
        static_cast<ks::r3::common::SystemInformationClass>(kSystemExtendedHandleInformation));
    if (raw.size() < sizeof(SysToolsHandleInformationEx)) {
        if (probeHandle != INVALID_HANDLE_VALUE) {
            ::CloseHandle(probeHandle);
        }
        result.diagnosticText = L"NtQuerySystemInformation(SystemExtendedHandleInformation) 失败，通常表示权限不足。";
        return result;
    }

    const auto& info = *reinterpret_cast<const SysToolsHandleInformationEx*>(raw.data());
    const ULONG_PTR maxEntries =
        (raw.size() - offsetof(SysToolsHandleInformationEx, Handles)) / sizeof(SysToolsHandleTableEntry);
    const ULONG_PTR handleCount = (std::min)(info.NumberOfHandles, maxEntries);
    result.totalHandles = static_cast<std::uint32_t>(handleCount);

    const std::uint32_t ownProcessId = static_cast<std::uint32_t>(::GetCurrentProcessId());
    const USHORT fileTypeIndex = ResolveFileTypeIndex(info, ownProcessId, queryObject, probeHandle);
    if (probeHandle != INVALID_HANDLE_VALUE) {
        ::CloseHandle(probeHandle);
        probeHandle = INVALID_HANDLE_VALUE;
    }
    if (fileTypeIndex == 0) {
        result.diagnosticText = L"无法确定 File 对象类型索引，扫描无法安全地跳过管道等易挂起句柄。";
        return result;
    }

    const std::unordered_map<std::uint32_t, std::wstring> processNames = BuildProcessNameMap();
    const std::wstring targetLower = ToLowerCopy(result.targetNtPath);
    const std::wstring targetPrefix = targetLower + L"\\";
    const HANDLE currentProcess = ::GetCurrentProcess();

    ProcessHandleCache processes;
    ObjectNameProbe probe(queryObject);
    std::unordered_map<std::uint32_t, std::wstring> processPaths;

    for (ULONG_PTR index = 0; index < handleCount; ++index) {
        const SysToolsHandleTableEntry& entry = info.Handles[index];
        if (entry.ObjectTypeIndex != fileTypeIndex) {
            continue;
        }
        ++result.fileHandles;

        const std::uint32_t processId = static_cast<std::uint32_t>(entry.UniqueProcessId);
        // PID 0 is the idle process and PID 4 is System; neither can be opened
        // for PROCESS_DUP_HANDLE from user mode, so they are counted as skipped
        // instead of producing a failed OpenProcess per handle.
        if (processId == 0 || processId == 4) {
            ++result.skippedHandles;
            continue;
        }

        HANDLE process = processes.get(processId);
        if (!process) {
            ++result.skippedHandles;
            continue;
        }

        HANDLE duplicated = nullptr;
        if (!::DuplicateHandle(process,
                reinterpret_cast<HANDLE>(entry.HandleValue),
                currentProcess,
                &duplicated,
                0,
                FALSE,
                DUPLICATE_SAME_ACCESS) ||
            !duplicated) {
            ++result.skippedHandles;
            continue;
        }

        std::wstring objectName;
        // queryName owns the handle from here on, timeout path included.
        const ProbeOutcome outcome = probe.queryName(duplicated, objectName);
        if (outcome == ProbeOutcome::NotDisk) {
            ++result.skippedHandles;
            continue;
        }
        ++result.inspectedHandles;
        if (outcome != ProbeOutcome::Named || objectName.empty()) {
            continue;
        }

        const std::wstring objectLower = ToLowerCopy(objectName);
        const bool matched = objectLower == targetLower ||
            (includeSubPaths && objectLower.size() > targetPrefix.size() &&
                objectLower.compare(0, targetPrefix.size(), targetPrefix) == 0);
        if (!matched) {
            continue;
        }

        FileHolderEntry match{};
        match.processId = processId;
        const auto namedProcess = processNames.find(processId);
        match.processName = namedProcess != processNames.end() ? namedProcess->second : L"(未知)";
        const auto cachedPath = processPaths.find(processId);
        if (cachedPath != processPaths.end()) {
            match.processPath = cachedPath->second;
        } else {
            match.processPath = QueryProcessImagePath(process);
            processPaths.emplace(processId, match.processPath);
        }
        match.handleValue = static_cast<std::uint64_t>(entry.HandleValue);
        match.grantedAccess = entry.GrantedAccess;
        match.accessText = FormatAccessMask(entry.GrantedAccess);
        match.objectName = objectName;
        match.win32Name = ResolveNtPathToWin32Path(objectName);
        result.entries.push_back(std::move(match));
    }

    result.timedOutHandles = probe.timeoutCount();
    result.elapsedMs = static_cast<std::uint32_t>(::GetTickCount64() - startTick);
    result.success = true;
    if (result.entries.empty()) {
        result.diagnosticText = L"未发现占用该路径的进程句柄。";
    }
    return result;
}

} // namespace ks::r3::system_tools
