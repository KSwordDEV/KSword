#include "ProcessActions.h"
#include "../../../shared/usermode/backend/process/ProcessControls.h"
#include "../../../shared/ProcessTerminateMethods.h"

#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/process/process.h"
#include "../../Core\Common.h"

#include <algorithm>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <functional>
#include <iomanip>
#include <shellapi.h>
#include <sstream>
#include <string>
#include <tlhelp32.h>
#include <utility>
#include <unordered_map>
#include <unordered_set>

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (0x00002100L)
#endif

namespace Ksword::Features::Process {
namespace {
using ks::r3::process::Utf8ToWide;
using ks::r3::process::PidListText;
using ks::r3::process::FindRowByPid;
using ks::r3::process::BuildProcessActionTargets;
using ks::r3::process::CollectR3ProcessTreePids;
using ks::r3::process::FailureResult;
using ks::r3::process::Win32ErrorText;
using ks::r3::process::Hex32;
using ks::r3::process::Hex64;
using ks::r3::process::AsciiLiteralToWide;
using ks::r3::process::NtProc;
using ks::r3::process::EnableCurrentProcessPrivilege;
using ks::r3::process::AppendIoLine;
using ks::r3::process::IsProtectedSystemPid;
using ks::r3::process::IsProcessPresentBySnapshot;
using ks::r3::process::OpenProcessForAction;
using ks::r3::process::ExecuteMultiMethodTerminate;
using ks::r3::process::NtSuspendOrResumeProcess;
using ks::r3::process::SetCriticalFlagForPid;
using ks::r3::process::SetEfficiencyModeForPid;
using ks::r3::process::SetPriorityForPid;
using ks::r3::process::ExecuteLocalProcessAction;
using ks::r3::process::PriorityClassForAction;












// ProcessPowerThrottlingStateNative mirrors PROCESS_POWER_THROTTLING_STATE
// without requiring a new SDK. Inputs are written by SetEfficiencyModeForPid;
// processing passes the structure to SetProcessInformation; it returns no value.


// Utf8ToWide converts ArkDriverClient diagnostic messages into the Win32 UI
// encoding. Input is a UTF-8/narrow diagnostic string; processing asks Windows
// for the exact UTF-16 size and falls back to byte widening when conversion is
// impossible; output is safe for status text and message boxes.




// WriteClipboardText copies Unicode operation handoff text to the clipboard.
// Input is owner HWND (optional) and text; processing transfers GMEM_MOVEABLE
// memory to the OS clipboard; output reports whether the copy succeeded.
bool WriteClipboardText(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return false;
    }
    ::EmptyClipboard();
    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (!memory) {
        ::CloseClipboard();
        return false;
    }
    void* target = ::GlobalLock(memory);
    if (!target) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    std::memcpy(target, text.c_str(), bytes);
    ::GlobalUnlock(memory);
    const bool ok = ::SetClipboardData(CF_UNICODETEXT, memory) != nullptr;
    if (!ok) {
        ::GlobalFree(memory);
    }
    ::CloseClipboard();
    return ok;
}



// BuildProcessActionTargets preserves the exact process instances selected by
// the user. Missing rows remain explicit zero-identity targets so mutations fail
// closed instead of falling back to whatever later owns the same PID.


// CollectR3ProcessTreePids expands the selected R3 processes into descendant-
// first termination targets. R0-only audit rows are deliberately excluded from
// both roots and descendants, so driver evidence never changes tree discovery.




// Win32ErrorText formats the current or supplied Win32 error. Input is the error
// code; processing delegates message formatting to Core; output is display text.


// Hex32 formats NTSTATUS-style signed LONG values without losing the raw bits.
// Input is an NTSTATUS-compatible value; output is uppercase 8-digit hex text.


// Hex64 formats pointer-sized diagnostics without truncating kernel/user
// addresses. Input is a 64-bit value from ArkDriverClient; output is a stable
// uppercase hexadecimal string used only for display.


// AsciiLiteralToWide widens short export names or fixed ASCII diagnostics.
// Input is a null-terminated ASCII string; processing widens byte-for-byte;
// output is empty when input is null.


// NtProc resolves one ntdll export by name. Input is an ANSI export name;
// processing uses the already-loaded ntdll module or loads it; output is null
// when the export cannot be found.


// EnableCurrentProcessPrivilege enables one privilege on the current token.
// Input is a privilege name such as SE_DEBUG_NAME; processing adjusts the
// process token; output reports whether Windows accepted and assigned it.


// AppendIoLine records one per-PID operation result. Inputs are a mutable
// details buffer, PID, operation label, success bit and driver/Win32 message;
// processing emits compact multiline diagnostics; no value is returned.


// AppendIoLine records a global non-PID operation such as clearing hidden marks.
// Inputs mirror the PID overload except there is no target process id.


// IsProtectedSystemPid blocks obviously invalid targets before sending mutating
// process IOCTLs. Input is a PID; output is true for PID 0..4, matching the
// original KswordARK R0 helpers.


// IsProcessPresentBySnapshot checks target liveness with the same Toolhelp
// snapshot semantics as the full ProcessDock aggregate termination action.
// A failed snapshot is conservatively treated as "still present" so a
// transient query failure cannot report a process as terminated.


// OpenProcessForAction retains a verified process handle for the duration of a
// mutation, so a PID cannot be silently rebound to a different snapshot row.

// ExecuteMultiMethodTerminate mirrors the full ProcessDock right-click action:
// each target is checked after every method and the chain stops immediately
// once its exit has been confirmed. The two-round cap prevents an unresponsive
// target from leaving the Light UI in an unbounded operation.


// OpenProcessForAction opens and identity-checks one local process action handle.
// Inputs are PID, expected snapshot creation time, and desired access; processing
// keeps the matching handle alive for the caller so PID-only fallback APIs cannot
// target a later process instance. Output is an owning handle or a diagnostic.


// HoldProcessIdentityForDriverAction keeps a verified process object alive
// while a driver operation still addresses that object by PID.
bool HoldProcessIdentityForDriverAction(
    const ProcessSnapshotRow& target,
    const wchar_t* operation,
    const bool rejectProtected,
    ProcessActionResult& result,
    Ksword::Core::UniqueHandle& identityHold) {
    std::wstring identityError;
    identityHold = OpenProcessForAction(
        target.processId,
        target.creationTime100ns,
        PROCESS_QUERY_LIMITED_INFORMATION,
        identityError,
        rejectProtected);
    if (identityHold.valid()) {
        return true;
    }
    AppendIoLine(result.detail, target.processId, operation, false, identityError);
    result.success = false;
    return false;
}

// NtSuspendOrResumeProcess invokes NtSuspendProcess or NtResumeProcess for one
// PID. Inputs are PID and desired direction; processing uses ntdll dynamically;
// output is true on NT_SUCCESS and a diagnostic otherwise.


// SetCriticalFlagForPid sets ProcessBreakOnTermination for one process. Inputs
// are PID and target state; processing enables SeDebugPrivilege best-effort then
// calls NtSetInformationProcess; output reports operation success.


// SetEfficiencyModeForPid toggles Windows process power throttling. Inputs are
// PID and target state; processing calls SetProcessInformation dynamically;
// output reports operation success and a concrete Win32 diagnostic.


// ProtectionLevelForAction maps the menu protection commands to the one-byte
// PS_PROTECTION level accepted by IOCTL_KSWORD_ARK_SET_PPL_LEVEL. Input is a
// menu id; output is false when the id is not a protection command.
// 低位是类型：0x?1 为 PPL（Light），0x?2 为完整 PP；高 4 位是 signer。
bool ProtectionLevelForAction(ProcessActionId actionId, std::uint8_t& levelOut) {
    switch (actionId) {
    case ProcessActionId::R0SetPplNone: levelOut = 0x00; return true;
    case ProcessActionId::R0SetPplAuthenticode: levelOut = 0x11; return true;
    case ProcessActionId::R0SetPplCodeGen: levelOut = 0x21; return true;
    case ProcessActionId::R0SetPplAntimalware: levelOut = 0x31; return true;
    case ProcessActionId::R0SetPplLsa: levelOut = 0x41; return true;
    case ProcessActionId::R0SetPplWindows: levelOut = 0x51; return true;
    case ProcessActionId::R0SetPplWinTcb: levelOut = 0x61; return true;
    case ProcessActionId::R0SetPpAuthenticode: levelOut = 0x12; return true;
    case ProcessActionId::R0SetPpCodeGen: levelOut = 0x22; return true;
    case ProcessActionId::R0SetPpAntimalware: levelOut = 0x32; return true;
    case ProcessActionId::R0SetPpLsa: levelOut = 0x42; return true;
    case ProcessActionId::R0SetPpWindows: levelOut = 0x52; return true;
    case ProcessActionId::R0SetPpWinTcb: levelOut = 0x62; return true;
    default: levelOut = 0; return false;
    }
}

// IntegrityRidForAction maps the new R0 mandatory-label menu entries to the
// standard S-1-16-* RID values. Input is a context menu id; output is false when
// another action family should handle the command.
bool IntegrityRidForAction(ProcessActionId actionId, unsigned long& ridOut) {
    switch (actionId) {
    case ProcessActionId::R0SetIntegrityUntrusted: ridOut = SECURITY_MANDATORY_UNTRUSTED_RID; return true;
    case ProcessActionId::R0SetIntegrityLow: ridOut = SECURITY_MANDATORY_LOW_RID; return true;
    case ProcessActionId::R0SetIntegrityMedium: ridOut = SECURITY_MANDATORY_MEDIUM_RID; return true;
    case ProcessActionId::R0SetIntegrityMediumPlus: ridOut = SECURITY_MANDATORY_MEDIUM_PLUS_RID; return true;
    case ProcessActionId::R0SetIntegrityHigh: ridOut = SECURITY_MANDATORY_HIGH_RID; return true;
    case ProcessActionId::R0SetIntegritySystem: ridOut = SECURITY_MANDATORY_SYSTEM_RID; return true;
    default: ridOut = 0; return false;
    }
}

// IntegrityResultDetail renders the fixed response fields returned by
// DriverClient::setProcessIntegrity. Inputs are the parsed wrapper result;
// output is a compact Chinese/hex diagnostic for the context-menu status area.
std::wstring IntegrityResultDetail(const ksword::ark::ProcessIntegrityResult& io) {
    std::wostringstream stream;
    stream << Utf8ToWide(io.io.message)
           << L"; status=" << io.status
           << L"; lastStatus=" << Hex32(io.lastStatus)
           << L"; rid=0x" << std::hex << std::uppercase << io.integrityRid;
    if (io.unsupported) {
        stream << L"; unsupported";
    }
    return stream.str();
}

// InjectResultDetail renders the R0 injection response without exposing any
// reusable primitive beyond what the driver already returned. Input is the
// ArkDriverClient parsed result; output is display-only status text.
std::wstring InjectResultDetail(const ksword::ark::ProcessInjectResult& io) {
    std::wostringstream stream;
    stream << Utf8ToWide(io.io.message)
           << L"; status=" << io.status
           << L"; lastStatus=" << Hex32(io.lastStatus)
           << L"; waitStatus=" << Hex32(io.waitStatus)
           << L"; bytesWritten=" << std::dec << io.bytesWritten
           << L"; remoteBase=" << Hex64(io.remoteBaseAddress)
           << L"; entry=" << Hex64(io.entryPointAddress);
    return stream.str();
}

// ReadBinaryFileForInjection loads a selected shellcode blob into memory. Input
// is a Win32 file path; processing enforces the shared R0 payload cap before
// returning bytes; output false includes a concrete diagnostic.
bool ReadBinaryFileForInjection(
    const std::wstring& path,
    std::vector<std::uint8_t>& bytes,
    std::wstring& errorText) {
    bytes.clear();
    if (path.empty()) {
        errorText = L"shellcode file path is empty";
        return false;
    }

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        errorText = L"无法打开 shellcode 文件。";
        return false;
    }
    const std::streamoff size = file.tellg();
    if (size <= 0) {
        errorText = L"shellcode 文件为空。";
        return false;
    }
    if (static_cast<unsigned long long>(size) > KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES) {
        errorText = L"shellcode 文件超过 R0 注入协议上限 " +
            std::to_wstring(KSWORD_ARK_PROCESS_INJECT_MAX_PAYLOAD_BYTES) + L" 字节。";
        return false;
    }

    bytes.resize(static_cast<std::size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(bytes.data()), size)) {
        errorText = L"读取 shellcode 文件失败。";
        bytes.clear();
        return false;
    }
    return true;
}

// VisibilityRequestForAction maps R0 process-hide menu ids onto the shared
// KswordArkProcessIoctl visibility action/flag contract. Input is a menu id;
// output is false when another action family should handle the command.
bool VisibilityRequestForAction(ProcessActionId actionId, unsigned long& actionOut, unsigned long& flagsOut) {
    switch (actionId) {
    case ProcessActionId::R0HideUnlinkOnly:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE;
        flagsOut = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST;
        return true;
    case ProcessActionId::R0HidePatchPidOnly:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE;
        flagsOut = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID;
        return true;
    case ProcessActionId::R0HideLegacyBoth:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE;
        flagsOut = KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH;
        return true;
    case ProcessActionId::R0UnhideProcess:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_UNHIDE;
        flagsOut = 0;
        return true;
    case ProcessActionId::R0ClearHiddenMarks:
        actionOut = KSWORD_ARK_PROCESS_VISIBILITY_ACTION_CLEAR_ALL;
        flagsOut = 0;
        return true;
    default:
        actionOut = 0;
        flagsOut = 0;
        return false;
    }
}

// SpecialProcessActionForMenu maps BreakOnTermination/APC menu entries onto
// IOCTL_KSWORD_ARK_SET_PROCESS_SPECIAL_FLAGS action values. Input is a menu id;
// output is false when the command belongs to another operation family.
bool SpecialProcessActionForMenu(ProcessActionId actionId, unsigned long& actionOut) {
    switch (actionId) {
    case ProcessActionId::R0EnableBreakOnTermination:
        actionOut = KSWORD_ARK_PROCESS_SPECIAL_ACTION_ENABLE_BREAK_ON_TERMINATION;
        return true;
    case ProcessActionId::R0DisableBreakOnTermination:
        actionOut = KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_BREAK_ON_TERMINATION;
        return true;
    case ProcessActionId::R0DisableApcInsertion:
        actionOut = KSWORD_ARK_PROCESS_SPECIAL_ACTION_DISABLE_APC_INSERTION;
        return true;
    default:
        actionOut = 0;
        return false;
    }
}



// KeyboardEnumOk checks shared keyboard enumeration status values. Input is the
// R0 aggregate status; output accepts OK and PARTIAL because partial still gives
// usable rows for the UI.
bool KeyboardEnumOk(std::uint32_t status) {
    return status == KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK ||
        status == KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL;
}

// ExecuteKeyboardHotkeyScan queries R0 win32k hotkey/hook evidence for one
// process. Inputs are one captured process row; processing uses ArkDriverClient only;
// output is a ProcessActionResult suitable for the context menu status dialog.
ProcessActionResult ExecuteKeyboardHotkeyScan(const ProcessSnapshotRow& target) {
    ProcessActionResult result;
    result.title = L"扫描进程热键";
    const DWORD pid = target.processId;
    Ksword::Core::UniqueHandle identityHold;
    if (!HoldProcessIdentityForDriverAction(target, L"scan hotkeys", false, result, identityHold)) {
        return result;
    }
    const ksword::ark::DriverClient driverClient;

    const ksword::ark::KeyboardHotkeyEnumResult hotkeys = driverClient.enumerateKeyboardHotkeys(
        static_cast<std::uint32_t>(pid),
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        2048UL);
    const ksword::ark::KeyboardHookEnumResult hooks = driverClient.enumerateKeyboardHooks(
        static_cast<std::uint32_t>(pid),
        KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS,
        2048UL);

    const bool hotkeyOk = hotkeys.io.ok && KeyboardEnumOk(hotkeys.status);
    const bool hookOk = hooks.io.ok && KeyboardEnumOk(hooks.status);
    result.success = hotkeyOk || hookOk;

    std::wostringstream detail;
    detail << L"PID " << pid << L"\r\n"
           << L"Hotkeys: IO=" << (hotkeys.io.ok ? L"OK" : L"FAIL")
           << L", status=" << hotkeys.status
           << L", total=" << hotkeys.totalCount
           << L", returned=" << hotkeys.returnedCount
           << L", parsed=" << hotkeys.entries.size()
           << L", message=" << Utf8ToWide(hotkeys.io.message) << L"\r\n"
           << L"Hooks: IO=" << (hooks.io.ok ? L"OK" : L"FAIL")
           << L", status=" << hooks.status
           << L", total=" << hooks.totalCount
           << L", returned=" << hooks.returnedCount
           << L", parsed=" << hooks.entries.size()
           << L", message=" << Utf8ToWide(hooks.io.message) << L"\r\n";

    const std::size_t hotkeyLimit = std::min<std::size_t>(hotkeys.entries.size(), 16U);
    for (std::size_t i = 0; i < hotkeyLimit; ++i) {
        const ksword::ark::KeyboardHotkeyEntry& row = hotkeys.entries[i];
        detail << L"Hotkey[" << i << L"] vk=0x" << std::hex << std::uppercase << row.virtualKey
               << L", modifiers=0x" << row.modifiers
               << L", tid=" << std::dec << row.threadId
               << L", object=" << Hex64(row.hotkeyObject)
               << L", detail=" << row.detail << L"\r\n";
    }

    const std::size_t hookLimit = std::min<std::size_t>(hooks.entries.size(), 16U);
    for (std::size_t i = 0; i < hookLimit; ++i) {
        const ksword::ark::KeyboardHookEntry& row = hooks.entries[i];
        detail << L"Hook[" << i << L"] type=" << row.hookType
               << L", scope=" << row.hookScope
               << L", tid=" << row.threadId
               << L", proc=" << Hex64(row.procedureAddress)
               << L", detail=" << row.detail << std::dec << L"\r\n";
    }

    result.detail = detail.str();
    return result;
}

// ExecuteLocalProcessAction applies one local Win32/NtAPI action to captured
// process instances. Each helper validates the snapshot creation time on the
// same handle used by its mutation, so a reused PID is rejected.

// ExecutePplRefresh queries the R0 process enumeration table and extracts the
// selected snapshot instances' protection bytes. Each verified handle remains
// live through the shared driver query so a recycled PID cannot supply results.
ProcessActionResult ExecutePplRefresh(const std::vector<ProcessSnapshotRow>& actionTargets) {
    ProcessActionResult result;
    result.title = L"手动刷新PPL保护级别";
    result.success = true;

    std::vector<ProcessSnapshotRow> verifiedTargets;
    std::vector<Ksword::Core::UniqueHandle> identityHolds;
    verifiedTargets.reserve(actionTargets.size());
    identityHolds.reserve(actionTargets.size());
    for (const ProcessSnapshotRow& target : actionTargets) {
        Ksword::Core::UniqueHandle identityHold;
        if (!HoldProcessIdentityForDriverAction(target, L"PPL refresh", false, result, identityHold)) {
            continue;
        }
        verifiedTargets.push_back(target);
        identityHolds.push_back(std::move(identityHold));
    }
    if (verifiedTargets.empty()) {
        return result;
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessEnumResult query = driverClient.enumerateProcesses(0);
    if (!query.io.ok) {
        result.success = false;
        result.detail = L"R0 process enumeration failed: " + Utf8ToWide(query.io.message);
        return result;
    }

    for (const ProcessSnapshotRow& target : verifiedTargets) {
        const DWORD pid = target.processId;
        const auto it = std::find_if(query.entries.begin(), query.entries.end(), [pid](const ksword::ark::ProcessEntry& row) {
            return row.processId == static_cast<std::uint32_t>(pid);
        });
        if (it == query.entries.end()) {
            AppendIoLine(result.detail, pid, L"PPL refresh", false, L"PID not returned by R0 enumeration");
            result.success = false;
            continue;
        }

        std::wostringstream line;
        line << L"protection=0x" << std::hex << std::uppercase << static_cast<unsigned int>(it->protection)
             << L", signature=0x" << static_cast<unsigned int>(it->signatureLevel)
             << L", sectionSignature=0x" << static_cast<unsigned int>(it->sectionSignatureLevel)
             << L", fieldFlags=0x" << it->fieldFlags
             << L", r0Status=" << std::dec << it->r0Status;
        const bool hasProtection = (it->fieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0;
        AppendIoLine(result.detail, pid, L"PPL refresh", hasProtection, line.str());
        result.success = result.success && hasProtection;
    }
    return result;
}
} // namespace

ProcessActionResult ExecuteProcessAction(
    ProcessActionId actionId,
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows) {
    if (selectedPids.empty() && actionId != ProcessActionId::R0ClearHiddenMarks) {
        return FailureResult(L"进程动作", selectedPids, L"没有选中进程。");
    }

    const auto buildActionTargets = [&snapshotRows](const std::vector<DWORD>& pids) {
        return BuildProcessActionTargets(pids, snapshotRows);
    };

    const DWORD priorityClass = PriorityClassForAction(actionId);
    if (priorityClass != 0) {
        ProcessActionResult result;
        result.title = L"设置进程优先级";
        result.success = true;
        for (const ProcessSnapshotRow& target : buildActionTargets(selectedPids)) {
            if (!SetPriorityForPid(
                    target.processId,
                    target.creationTime100ns,
                    priorityClass,
                    result.detail)) {
                result.success = false;
            }
        }
        return result;
    }

    if (actionId == ProcessActionId::OpenFolder) {
        const ProcessSnapshotRow* row = FindRowByPid(snapshotRows, selectedPids.front());
        if (!row || row->imagePath.empty()) {
            return FailureResult(L"打开所在目录", selectedPids, L"选中进程的映像路径不可用。");
        }
        const std::wstring args = L"/select,\"" + row->imagePath + L"\"";
        const HINSTANCE shellResult = ::ShellExecuteW(nullptr, L"open", L"explorer.exe", args.c_str(), nullptr, SW_SHOWNORMAL);
        ProcessActionResult result;
        result.title = L"打开所在目录";
        result.success = reinterpret_cast<INT_PTR>(shellResult) > 32;
        result.detail = result.success ? L"Explorer launch requested." : L"ShellExecuteW failed.";
        return result;
    }

    if (actionId == ProcessActionId::TerminateProcessMultiMethod) {
        return ExecuteMultiMethodTerminate(buildActionTargets(selectedPids));
    }

    if (actionId == ProcessActionId::TerminateProcessTree) {
        const std::vector<DWORD> treePids = CollectR3ProcessTreePids(selectedPids, snapshotRows);
        if (treePids.empty()) {
            return FailureResult(L"结束进程树", selectedPids, L"选中进程未包含在当前 R3 进程快照中，无法识别进程树。");
        }
        ProcessActionResult result = ExecuteMultiMethodTerminate(buildActionTargets(treePids));
        result.title = L"结束进程树";
        return result;
    }

    if (actionId == ProcessActionId::TerminateProcess) {
        return ks::r3::process::TerminateProcesses(buildActionTargets(selectedPids));
    }

    if (actionId == ProcessActionId::R0TerminateProcess || actionId == ProcessActionId::R0TerminateProcessTree) {
        const bool terminateTree = actionId == ProcessActionId::R0TerminateProcessTree;
        const std::vector<DWORD> targetPids = terminateTree
            ? CollectR3ProcessTreePids(selectedPids, snapshotRows)
            : selectedPids;
        if (targetPids.empty()) {
            return FailureResult(L"R0结束进程树", selectedPids, L"选中进程未包含在当前 R3 进程快照中，无法识别进程树。");
        }
        ProcessActionResult result;
        result.title = terminateTree ? L"R0结束进程树" : L"R0结束进程";
        result.success = true;
        const ksword::ark::DriverClient driverClient;
        for (const ProcessSnapshotRow& target : buildActionTargets(targetPids)) {
            const DWORD pid = target.processId;
            if (IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, L"R0 terminate", false, L"protected system PID");
                result.success = false;
                continue;
            }
            Ksword::Core::UniqueHandle identityHold;
            if (!HoldProcessIdentityForDriverAction(target, L"R0 terminate", true, result, identityHold)) {
                continue;
            }
            // 每个 PID 独立调用 ArkDriverClient，因此会单独提交现有结束进程 IOCTL。
            const ksword::ark::IoResult io = driverClient.terminateProcess(static_cast<std::uint32_t>(pid), static_cast<long>(0xC0000005u));
            AppendIoLine(result.detail, pid, L"R0 terminate", io.ok, Utf8ToWide(io.message));
            result.success = result.success && io.ok;
        }
        return result;
    }

    if (actionId == ProcessActionId::R0SuspendProcess ||
        actionId == ProcessActionId::R0ResumeProcess) {
        const bool suspend = actionId == ProcessActionId::R0SuspendProcess;
        ProcessActionResult result;
        result.title = suspend ? L"R0挂起进程" : L"R0恢复进程";
        result.success = true;
        const ksword::ark::DriverClient driverClient;
        for (const ProcessSnapshotRow& target : buildActionTargets(selectedPids)) {
            const DWORD pid = target.processId;
            if (IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, suspend ? L"R0 suspend" : L"R0 resume", false, L"protected system PID");
                result.success = false;
                continue;
            }
            Ksword::Core::UniqueHandle identityHold;
            if (!HoldProcessIdentityForDriverAction(target,
                    suspend ? L"R0 suspend" : L"R0 resume", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::IoResult io = suspend
                ? driverClient.suspendProcess(static_cast<std::uint32_t>(pid))
                : driverClient.resumeProcess(static_cast<std::uint32_t>(pid));
            AppendIoLine(result.detail, pid, suspend ? L"R0 suspend" : L"R0 resume",
                io.ok, Utf8ToWide(io.message));
            result.success = result.success && io.ok;
        }
        return result;
    }

    std::uint8_t protectionLevel = 0;
    if (ProtectionLevelForAction(actionId, protectionLevel)) {
        ProcessActionResult result;
        result.title = L"R0设置PPL层级";
        result.success = true;
        const ksword::ark::DriverClient driverClient;
        for (const ProcessSnapshotRow& target : buildActionTargets(selectedPids)) {
            const DWORD pid = target.processId;
            if (IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, L"set PPL", false, L"protected system PID");
                result.success = false;
                continue;
            }
            Ksword::Core::UniqueHandle identityHold;
            if (!HoldProcessIdentityForDriverAction(target, L"set PPL", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::IoResult io = driverClient.setProcessProtection(static_cast<std::uint32_t>(pid), protectionLevel);
            AppendIoLine(result.detail, pid, L"set PPL", io.ok, Utf8ToWide(io.message));
            result.success = result.success && io.ok;
        }
        return result;
    }

    unsigned long integrityRid = 0;
    if (IntegrityRidForAction(actionId, integrityRid)) {
        ProcessActionResult result;
        result.title = L"R0设置进程完整性";
        result.success = true;
        const ksword::ark::DriverClient driverClient;
        for (const ProcessSnapshotRow& target : buildActionTargets(selectedPids)) {
            const DWORD pid = target.processId;
            if (IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, L"set integrity", false, L"protected system PID");
                result.success = false;
                continue;
            }
            Ksword::Core::UniqueHandle identityHold;
            if (!HoldProcessIdentityForDriverAction(target, L"set integrity", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::ProcessIntegrityResult io =
                driverClient.setProcessIntegrity(static_cast<std::uint32_t>(pid), integrityRid);
            const bool ok = io.io.ok &&
                !io.unsupported &&
                io.lastStatus >= 0 &&
                io.status == KSWORD_ARK_PROCESS_INTEGRITY_STATUS_APPLIED;
            AppendIoLine(result.detail, pid, L"set integrity", ok, IntegrityResultDetail(io));
            result.success = result.success && ok;
        }
        return result;
    }

    unsigned long visibilityAction = 0;
    unsigned long visibilityFlags = 0;
    if (VisibilityRequestForAction(actionId, visibilityAction, visibilityFlags)) {
        ProcessActionResult result;
        result.title = L"R0进程可见性";
        result.success = true;
        const ksword::ark::DriverClient driverClient;
        if (actionId == ProcessActionId::R0ClearHiddenMarks) {
            const ksword::ark::ProcessVisibilityResult io = driverClient.setProcessVisibility(0, visibilityAction, visibilityFlags);
            const bool ok = io.io.ok && io.lastStatus >= 0 && io.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED;
            AppendIoLine(result.detail, L"R0 clear hidden marks", ok, Utf8ToWide(io.io.message));
            result.success = ok;
            return result;
        }
        for (const ProcessSnapshotRow& target : buildActionTargets(selectedPids)) {
            const DWORD pid = target.processId;
            if (visibilityAction == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE && IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, L"visibility", false, L"protected system PID");
                result.success = false;
                continue;
            }
            Ksword::Core::UniqueHandle identityHold;
            if (!HoldProcessIdentityForDriverAction(
                    target,
                    L"visibility",
                    visibilityAction == KSWORD_ARK_PROCESS_VISIBILITY_ACTION_HIDE,
                    result,
                    identityHold)) {
                continue;
            }
            const ksword::ark::ProcessVisibilityResult io = driverClient.setProcessVisibility(static_cast<std::uint32_t>(pid), visibilityAction, visibilityFlags);
            const bool ok = io.io.ok && io.lastStatus >= 0 &&
                (io.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_HIDDEN ||
                 io.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_VISIBLE ||
                 io.status == KSWORD_ARK_PROCESS_VISIBILITY_STATUS_CLEARED);
            AppendIoLine(result.detail, pid, L"visibility", ok, Utf8ToWide(io.io.message));
            result.success = result.success && ok;
        }
        return result;
    }

    unsigned long specialAction = 0;
    if (SpecialProcessActionForMenu(actionId, specialAction)) {
        ProcessActionResult result;
        result.title = L"R0进程特殊标志";
        result.success = true;
        const ksword::ark::DriverClient driverClient;
        for (const ProcessSnapshotRow& target : buildActionTargets(selectedPids)) {
            const DWORD pid = target.processId;
            if (IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, L"special flags", false, L"protected system PID");
                result.success = false;
                continue;
            }
            Ksword::Core::UniqueHandle identityHold;
            if (!HoldProcessIdentityForDriverAction(target, L"special flags", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::ProcessSpecialFlagsResult io = driverClient.setProcessSpecialFlags(static_cast<std::uint32_t>(pid), specialAction);
            const bool ok = io.io.ok && io.lastStatus >= 0 && io.status == KSWORD_ARK_PROCESS_SPECIAL_STATUS_APPLIED;
            AppendIoLine(result.detail, pid, L"special flags", ok, Utf8ToWide(io.io.message));
            result.success = result.success && ok;
        }
        return result;
    }

    if (actionId == ProcessActionId::R0DkomRemoveFromCidTable) {
        ProcessActionResult result;
        result.title = L"R0 DKOM从PspCidTable删除";
        result.success = true;
        const ksword::ark::DriverClient driverClient;
        for (const ProcessSnapshotRow& target : buildActionTargets(selectedPids)) {
            const DWORD pid = target.processId;
            if (IsProtectedSystemPid(pid)) {
                AppendIoLine(result.detail, pid, L"DKOM CID remove", false, L"protected system PID");
                result.success = false;
                continue;
            }
            Ksword::Core::UniqueHandle identityHold;
            if (!HoldProcessIdentityForDriverAction(target, L"DKOM CID remove", true, result, identityHold)) {
                continue;
            }
            const ksword::ark::ProcessDkomResult io = driverClient.dkomProcess(static_cast<std::uint32_t>(pid), KSWORD_ARK_PROCESS_DKOM_ACTION_REMOVE_FROM_PSP_CID_TABLE);
            const bool ok = io.io.ok && io.lastStatus >= 0 && io.status == KSWORD_ARK_PROCESS_DKOM_STATUS_REMOVED && io.removedEntries > 0;
            AppendIoLine(result.detail, pid, L"DKOM CID remove", ok, Utf8ToWide(io.io.message));
            result.success = result.success && ok;
        }
        return result;
    }

    switch (actionId) {
    case ProcessActionId::SuspendProcess:
    case ProcessActionId::ResumeProcess:
    case ProcessActionId::EnableEfficiencyMode:
    case ProcessActionId::DisableEfficiencyMode:
    case ProcessActionId::SetCriticalProcess:
    case ProcessActionId::ClearCriticalProcess:
        return ExecuteLocalProcessAction(actionId, buildActionTargets(selectedPids));
    case ProcessActionId::RefreshPplProtectionLevel:
        return ExecutePplRefresh(buildActionTargets(selectedPids));
    case ProcessActionId::OpenMemoryOperation: {
        ProcessActionResult result;
        result.title = L"复制到内存读写页输入";
        const std::wstring pidText = PidListText(selectedPids);
        result.success = WriteClipboardText(nullptr, pidText);
        result.detail = result.success
            ? L"已复制 PID 列表，可粘贴到驱动内存读写页的目标 PID 输入框: " + pidText
            : L"复制 PID 列表到剪贴板失败: " + Win32ErrorText(::GetLastError());
        return result;
    }
    case ProcessActionId::ScanHotkeys:
        if (selectedPids.size() != 1) {
            return FailureResult(L"扫描进程热键", selectedPids, L"扫描进程热键需要单选一个进程。");
        }
        {
            const std::vector<ProcessSnapshotRow> actionTargets = buildActionTargets(selectedPids);
            if (actionTargets.size() != 1U) {
                return FailureResult(L"扫描进程热键", selectedPids, L"扫描进程热键需要单选一个进程。");
            }
            return ExecuteKeyboardHotkeyScan(actionTargets.front());
        }
    case ProcessActionId::OpenDetails:
        return FailureResult(L"进程详细信息", selectedPids, L"该动作由进程列表窗口直接打开详细信息页。");
    default:
        return FailureResult(L"进程动作", selectedPids, L"未知进程动作。");
    }
}

ProcessActionResult ExecuteR0ProcessDllInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& dllPath) {
    if (selectedPids.size() != 1) {
        return FailureResult(L"R0 DLL注入", selectedPids, L"R0 DLL 注入需要单选一个进程。");
    }
    if (dllPath.empty()) {
        return FailureResult(L"R0 DLL注入", selectedPids, L"未选择 DLL 文件。");
    }

    const std::vector<ProcessSnapshotRow> actionTargets = BuildProcessActionTargets(selectedPids, snapshotRows);
    if (actionTargets.size() != 1U) {
        return FailureResult(L"R0 DLL注入", selectedPids, L"R0 DLL 注入需要单选一个进程。");
    }

    ProcessActionResult result;
    result.title = L"R0 DLL注入";
    const ProcessSnapshotRow& target = actionTargets.front();
    const DWORD pid = target.processId;
    if (IsProtectedSystemPid(pid)) {
        result.success = false;
        AppendIoLine(result.detail, pid, L"inject DLL", false, L"protected system PID");
        return result;
    }
    Ksword::Core::UniqueHandle identityHold;
    if (!HoldProcessIdentityForDriverAction(target, L"inject DLL", true, result, identityHold)) {
        return result;
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessInjectResult io = driverClient.injectProcessDll(
        static_cast<std::uint32_t>(pid),
        dllPath,
        KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED | KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD);
    result.success = io.io.ok &&
        io.lastStatus >= 0 &&
        io.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    AppendIoLine(result.detail, pid, L"inject DLL", result.success, InjectResultDetail(io));
    return result;
}

ProcessActionResult ExecuteR0ProcessShellcodeInjection(
    const std::vector<DWORD>& selectedPids,
    const std::vector<ProcessSnapshotRow>& snapshotRows,
    const std::wstring& shellcodePath) {
    if (selectedPids.size() != 1) {
        return FailureResult(L"R0 Shellcode注入", selectedPids, L"R0 Shellcode 注入需要单选一个进程。");
    }

    std::vector<std::uint8_t> shellcode;
    std::wstring readError;
    if (!ReadBinaryFileForInjection(shellcodePath, shellcode, readError)) {
        return FailureResult(L"R0 Shellcode注入", selectedPids, readError.c_str());
    }

    const std::vector<ProcessSnapshotRow> actionTargets = BuildProcessActionTargets(selectedPids, snapshotRows);
    if (actionTargets.size() != 1U) {
        return FailureResult(L"R0 Shellcode注入", selectedPids, L"R0 Shellcode 注入需要单选一个进程。");
    }

    ProcessActionResult result;
    result.title = L"R0 Shellcode注入";
    const ProcessSnapshotRow& target = actionTargets.front();
    const DWORD pid = target.processId;
    if (IsProtectedSystemPid(pid)) {
        result.success = false;
        AppendIoLine(result.detail, pid, L"inject shellcode", false, L"protected system PID");
        return result;
    }
    Ksword::Core::UniqueHandle identityHold;
    if (!HoldProcessIdentityForDriverAction(target, L"inject shellcode", true, result, identityHold)) {
        return result;
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::ProcessInjectResult io = driverClient.injectProcessShellcode(
        static_cast<std::uint32_t>(pid),
        shellcode,
        KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED);
    result.success = io.io.ok &&
        io.lastStatus >= 0 &&
        io.status == KSWORD_ARK_PROCESS_INJECT_STATUS_INJECTED;
    AppendIoLine(result.detail, pid, L"inject shellcode", result.success, InjectResultDetail(io));
    return result;
}



} // namespace Ksword::Features::Process
