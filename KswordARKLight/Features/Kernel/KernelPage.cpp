#include "KernelPage.h"

#include "KernelCatalog.h"
#include "KernelPageLayout.h"
#include "../../Ui/Controls.h"
#include "../../Ui/EntityNavigation.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/NumericSortKey.h"
#include "../../Ui/TextFindSupport.h"
#include "../../../shared/driver/KswordArkCallbackIoctl.h"
#include "../../../shared/driver/KswordArkCapabilityIoctl.h"
#include "../../../shared/driver/KswordArkDynDataIoctl.h"

#include <commctrl.h>
#include <commdlg.h>
#include <shellapi.h>
#include <windowsx.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <functional>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <set>
#include <sstream>
#include <unordered_map>

namespace Ksword::Features::Kernel {
namespace {
constexpr wchar_t kKernelPageClass[] = L"KswordARKLight.KernelPage";
constexpr int kIdPrimaryTab = 51001;
constexpr int kIdSecondaryTab = 51002;
constexpr int kIdRefresh = 51003;
constexpr int kIdResultList = 51005;
constexpr int kIdFilterEdit = 51006;
constexpr int kIdModuleFilterEdit = 51007;
constexpr int kIdLocate = 51008;
constexpr int kIdIncludeCombo = 51009;
constexpr int kIdCallbackRuleTab = 51010;
constexpr int kIdCallbackLogTab = 51011;
constexpr int kIdCallbackApply = 51012;
constexpr int kIdCallbackReload = 51013;
constexpr int kIdCallbackBypassApply = 51014;
constexpr int kIdCallbackBypassClear = 51015;
constexpr int kIdCallbackBypassRefresh = 51016;
constexpr int kIdCallbackStartFsctl = 51017;
constexpr int kIdCallbackDrainFileMonitor = 51018;
constexpr int kIdCallbackClearFileMonitor = 51019;
constexpr int kIdCallbackImport = 51020;
constexpr int kIdCallbackExport = 51021;
constexpr int kIdCallbackAddGroup = 51022;
constexpr int kIdCallbackRemoveGroup = 51023;
constexpr int kIdCallbackRenameGroup = 51024;
constexpr int kIdCallbackMoveGroupUp = 51025;
constexpr int kIdCallbackMoveGroupDown = 51026;
constexpr int kIdCallbackAddRule = 51027;
constexpr int kIdCallbackRemoveRule = 51028;
constexpr int kIdCallbackMoveRuleUp = 51029;
constexpr int kIdCallbackMoveRuleDown = 51030;
constexpr int kIdCallbackBypassAdd = 51031;
constexpr int kIdCallbackBypassRemove = 51032;
constexpr int kIdCallbackExportFileMonitor = 51033;
constexpr int kIdCopyDiagnosticReport = 51034;
constexpr int kIdRiskOnlyCheck = 51035;
constexpr int kIdEvidenceIncludeNonModuleCheck = 51036;
constexpr int kIdEvidenceStartEdit = 51037;
constexpr int kIdEvidenceEndEdit = 51038;
constexpr int kIdEvidenceMaxRowsEdit = 51039;
constexpr int kIdEvidenceMaxRowsSpin = 51040;
constexpr int kIdIntegrityModuleBaseEdit = 51041;
constexpr int kIdIntegrityFillFromSelection = 51042;
constexpr int kIdIntegrityCpuOnly = 51043;
constexpr int kIdIntegrityIdtVectorsEdit = 51044;
constexpr int kIdIntegrityIdtVectorsSpin = 51045;
constexpr UINT kMsgKernelQueryCompleted = WM_APP + 605;
constexpr UINT kMsgKernelActionCompleted = WM_APP + 606;
constexpr UINT kMsgCallbackEventReceived = WM_APP + 607;
constexpr UINT kMsgCallbackAnswerCompleted = WM_APP + 608;
constexpr UINT kMsgR0EvidenceFilterCompleted = WM_APP + 609;
constexpr UINT kMsgCallbackFileIoCompleted = WM_APP + 610;
constexpr UINT_PTR kTimerR0EvidenceFilter = 51057;
constexpr int kIdCallbackGlobalEnabled = 51047;
constexpr int kIdCallbackFileMonitorFsctlOnly = 51048;
constexpr int kIdDeviceDriverDirectoryCombo = 51049;
constexpr int kIdDeviceDriverTypeCombo = 51050;
constexpr int kIdBaseNamedScopeCombo = 51051;
constexpr int kIdBaseNamedTypeCombo = 51052;
constexpr int kIdCallbackStartReceiver = 51053;
constexpr int kIdCallbackStopReceiver = 51054;
constexpr int kIdCallbackAllowEvent = 51055;
constexpr int kIdCallbackDenyEvent = 51056;
constexpr UINT_PTR kFilterEditSubclassId = 51046;
constexpr UINT_PTR kMenuRefreshCurrentFeature = 51100;
constexpr UINT_PTR kMenuCopyCell = 51101;
constexpr UINT_PTR kMenuCopyRow = 51102;
constexpr UINT_PTR kMenuCopyAll = 51103;
constexpr UINT_PTR kMenuInlineNopPatch = 51104;
constexpr UINT_PTR kMenuCallbackSafeRemove = 51105;
constexpr UINT_PTR kMenuCallbackExperimentalUnlink = 51106;
constexpr UINT_PTR kMenuCallbackOpenModuleFolder = 51107;
constexpr UINT_PTR kMenuCallbackModuleFileDetail = 51108;
constexpr UINT_PTR kMenuMinifilterSetBypass = 51109;
constexpr UINT_PTR kMenuMinifilterClearBypass = 51110;
constexpr UINT_PTR kMenuNetworkCaptureStart = 51190;
constexpr UINT_PTR kMenuNetworkCaptureStop = 51191;
constexpr UINT_PTR kMenuPiDdbDeleteEntry = 51192;
constexpr UINT_PTR kMenuDriverDispatchRestore = 51193;
constexpr UINT_PTR kMenuDriverDispatchAbandon = 51194;
constexpr UINT_PTR kMenuDriverImageRestore = 51195;
constexpr UINT_PTR kMenuDriverImageAbandon = 51196;
constexpr UINT_PTR kMenuDriverCommunicationRestore = 51197;
constexpr UINT_PTR kMenuDriverObjectQueryDetail = 51111;
constexpr UINT_PTR kMenuDriverObjectForceUnload = 51112;
constexpr UINT_PTR kMenuNativeObjectQueryDetail = 51113;
constexpr UINT_PTR kMenuNativeSymbolicLinkResolve = 51114;
constexpr UINT_PTR kMenuNativeNamedPipeProbe = 51115;
constexpr UINT_PTR kMenuFilterByModule = 51116;
constexpr UINT_PTR kMenuFilterByTargetModule = 51117;
constexpr UINT_PTR kMenuFilterByAddress = 51118;
constexpr UINT_PTR kMenuShowRowDialog = 51119;
constexpr UINT_PTR kMenuFilterByPath = 51120;
constexpr UINT_PTR kMenuDynDataApplyMatchedProfile = 51121;
constexpr UINT_PTR kMenuMutationCommitDryRun = 51122;
constexpr UINT_PTR kMenuMutationRollbackDryRun = 51123;
constexpr UINT_PTR kMenuMutationRollbackConfirmed = 51124;
constexpr UINT_PTR kMenuCallbackCancelPendingDecisions = 51125;
constexpr UINT_PTR kMenuCallbackApplyDisabledEmptyRules = 51126;
constexpr UINT_PTR kMenuExportAllTsv = 51127;
constexpr UINT_PTR kMenuFilterByType = 51128;
constexpr UINT_PTR kMenuFilterByName = 51129;
constexpr UINT_PTR kMenuFilterByTarget = 51130;
constexpr UINT_PTR kMenuAtomVerify = 51131;
constexpr UINT_PTR kMenuAtomCopySnippet = 51132;
constexpr UINT_PTR kMenuCopySameDirectory = 51133;
constexpr UINT_PTR kMenuMapDosPath = 51134;
constexpr UINT_PTR kMenuCopyObjectName = 51135;
constexpr UINT_PTR kMenuCopyObjectType = 51136;
constexpr UINT_PTR kMenuCopyFullPath = 51137;
constexpr UINT_PTR kMenuCopySymbolicTarget = 51138;
constexpr UINT_PTR kMenuCopyAtomValue = 51139;
constexpr UINT_PTR kMenuCopyAtomHex = 51140;
constexpr UINT_PTR kMenuCopyAtomName = 51141;
constexpr UINT_PTR kMenuCopyAtomSource = 51142;
constexpr UINT_PTR kMenuCopyDiagnosticReport = 51143;
constexpr UINT_PTR kMenuCopySelectedRows = 51144;
constexpr UINT_PTR kMenuCopySelectedRowsWithHeader = 51145;
constexpr UINT_PTR kMenuCopySelectedDetails = 51146;
constexpr UINT_PTR kMenuCopyObjectEnumSource = 51147;
constexpr UINT_PTR kMenuCallbackGroupAdd = 51148;
constexpr UINT_PTR kMenuCallbackGroupRemove = 51149;
constexpr UINT_PTR kMenuCallbackGroupRename = 51150;
constexpr UINT_PTR kMenuCallbackGroupMoveUp = 51151;
constexpr UINT_PTR kMenuCallbackGroupMoveDown = 51152;
constexpr UINT_PTR kMenuCallbackRuleAdd = 51153;
constexpr UINT_PTR kMenuCallbackRuleRemove = 51154;
constexpr UINT_PTR kMenuCallbackRuleMoveUp = 51155;
constexpr UINT_PTR kMenuCallbackRuleMoveDown = 51156;
constexpr UINT_PTR kMenuCallbackBypassAdd = 51157;
constexpr UINT_PTR kMenuCallbackBypassRemove = 51158;
constexpr UINT_PTR kMenuCallbackBypassApply = 51159;
constexpr UINT_PTR kMenuCallbackBypassClear = 51160;
constexpr UINT_PTR kMenuCallbackBypassRefresh = 51161;
constexpr UINT_PTR kMenuCallbackFileMonitorStart = 51162;
constexpr UINT_PTR kMenuCallbackFileMonitorDrain = 51163;
constexpr UINT_PTR kMenuCallbackFileMonitorClear = 51164;
constexpr UINT_PTR kMenuCallbackFileMonitorExport = 51165;
constexpr UINT_PTR kMenuCallbackCopyPanelSelection = 51166;
constexpr UINT_PTR kMenuCallbackGroupToggleEnabled = 51167;
constexpr UINT_PTR kMenuCallbackRuleToggleEnabled = 51168;
constexpr UINT_PTR kMenuCallbackImportConfig = 51169;
constexpr UINT_PTR kMenuCallbackExportConfig = 51170;
constexpr UINT_PTR kMenuCallbackApplyLocalRules = 51171;
constexpr UINT_PTR kMenuCallbackReloadRuntime = 51172;
constexpr UINT_PTR kMenuCallbackRuleCopyText = 51176;
constexpr UINT_PTR kMenuCallbackRulePasteNew = 51177;
constexpr UINT_PTR kMenuCallbackFileMonitorOpenProcess = 51178;
constexpr UINT_PTR kMenuCallbackFileMonitorOpenPath = 51179;
constexpr UINT_PTR kMenuObjectFilterByRoot = 51173;
constexpr UINT_PTR kMenuObjectFilterByDirectory = 51174;
constexpr UINT_PTR kMenuCopyDosCandidate = 51175;
constexpr UINT_PTR kMenuCallbackCopyColumnBase = 51180;
constexpr UINT_PTR kMenuCallbackCopyColumnMax = 51188;
constexpr UINT_PTR kMenuFilterByOwner = 51189;
constexpr UINT_PTR kMenuFilterByRisk = 51190;
constexpr UINT_PTR kMenuFilterByPidTid = 51191;
constexpr UINT_PTR kMenuFilterByCapability = 51192;
constexpr UINT_PTR kMenuRefreshSelectedDetail = 51193;
constexpr UINT_PTR kMenuCopyColumnBase = 51200;
constexpr UINT_PTR kMenuCopyColumnMax = 51299;
constexpr int kCallbackFileMonitorPidColumn = 1;
constexpr int kCallbackFileMonitorPathColumn = 3;
constexpr int kCallbackFileMonitorPathStateColumn = 10;
constexpr wchar_t kInlineHookForceRequiredStatusText[] = L"6";
constexpr int kKernelSplitterThickness = 5;
constexpr const wchar_t* kDeviceDriverFixedDirectories[] = {
    L"\\Device",
    L"\\Driver",
    L"\\FileSystem",
    L"\\FileSystem\\Filters",
};

// IsR0EvidenceFeature identifies the large snapshot pages that share the
// generic R0 evidence projection. These pages use one debounced background
// filter path to keep edit notifications off the UI thread.
bool IsR0EvidenceFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::CpuHardwareSnapshot:
    case KernelFeatureId::PhysicalMemoryLayout:
    case KernelFeatureId::MutationAudit:
    case KernelFeatureId::KeyboardHotkeys:
    case KernelFeatureId::KeyboardHooks:
    case KernelFeatureId::DynDataCapabilities:
    case KernelFeatureId::MinifilterBypassPids:
    case KernelFeatureId::KernelTimerDpc:
    case KernelFeatureId::IoctlRegistry:
        return true;
    default:
        return false;
    }
}

// MinMaxValue keeps this file independent from std::min/std::max macro
// collisions when Windows headers are included before NOMINMAX is visible.
template <typename T>
constexpr const T& MinValue(const T& left, const T& right) {
    return (right < left) ? right : left;
}

// MaxValue keeps this file independent from std::min/std::max macro
// collisions when Windows headers are included before NOMINMAX is visible.
template <typename T>
constexpr const T& MaxValue(const T& left, const T& right) {
    return (left < right) ? right : left;
}

// ClampValue returns value clamped into [low, high] without depending on
// std::clamp. Inputs are the candidate value and inclusive bounds; output is
// always within the supplied range.
template <typename T>
constexpr T ClampValue(const T& value, const T& low, const T& high) {
    return value < low ? low : (high < value ? high : value);
}


// EnsureKernelPageClass registers the page window class once. Input is none;
// processing calls RegisterClassW idempotently; no value is returned.
void EnsureKernelPageClass() {
    static bool registered = false;
    if (registered) {
        return;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = KernelPage::WndProc;
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kKernelPageClass;
    ::RegisterClassW(&wc);
    registered = true;
}

// BoolText converts metadata or result booleans into compact Chinese labels.
// Input is a boolean value; output is "是" or "否".
const wchar_t* BoolText(const bool value) {
    return value ? L"是" : L"否";
}

// HexToUInt64 parses decimal or 0x-prefixed protocol numbers from cached rows.
// Input is display text emitted by KernelFacade; processing uses wcstoull and
// requires full-token consumption; output is false when the cell is missing or
// not numeric.
bool HexToUInt64(const std::wstring& text, std::uint64_t& valueOut) {
    if (text.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    const int base = text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X') ? 16 : 10;
    const unsigned long long value = std::wcstoull(text.c_str(), &end, base);
    if (end == text.c_str() || *end != L'\0') {
        return false;
    }
    valueOut = static_cast<std::uint64_t>(value);
    return true;
}

// CallbackGuidText formats the opaque callback event identifier for display and
// for the strongly validated facade action. It does not reinterpret the bytes
// as a Windows GUID, preserving the driver protocol's original byte order.
std::wstring CallbackGuidText(const KSWORD_ARK_GUID128& guid) {
    std::wostringstream stream;
    stream << std::hex << std::uppercase << std::setfill(L'0');
    for (const unsigned char value : guid.bytes) {
        stream << std::setw(2) << static_cast<unsigned int>(value);
    }
    return stream.str();
}

// FixedWideText converts a fixed shared-protocol wchar buffer to a bounded UI
// string. Input may have no terminator after a malformed driver response; the
// returned display text therefore never scans beyond the packet field.
template <std::size_t Size>
std::wstring FixedWideText(const wchar_t (&value)[Size]) {
    const std::size_t length = std::find(value, value + Size, L'\0') - value;
    return std::wstring(value, length);
}

std::wstring RowFieldByName(const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names);

// FirstRowValue returns the first non-empty field with one of the supplied
// aliases. Inputs are a row cache and column aliases; output is empty when no
// matching cell is present.
std::wstring FirstRowValue(
    const std::vector<std::vector<std::wstring>>& rows,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    for (const std::vector<std::wstring>& row : rows) {
        const std::wstring value = RowFieldByName(row, columns, names);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

// FirstRowUInt64 returns a numeric value from the first matching cached row.
// Inputs are row data, columns and aliases; processing accepts hexadecimal and
// decimal display forms; output uses fallback when no numeric value is found.
std::uint64_t FirstRowUInt64(
    const std::vector<std::vector<std::wstring>>& rows,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names,
    const std::uint64_t fallback = 0) {
    for (const std::vector<std::wstring>& row : rows) {
        std::uint64_t value = 0;
        if (HexToUInt64(RowFieldByName(row, columns, names), value)) {
            return value;
        }
    }
    return fallback;
}

// FirstNonZeroField reads one numeric field from a single cached row. Inputs are
// a raw row, its schema, and accepted column aliases; processing accepts decimal
// and hexadecimal text; output is zero when the field is absent or zero.
std::uint64_t FirstNonZeroField(
    const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    std::uint64_t value = 0;
    if (HexToUInt64(RowFieldByName(row, columns, names), value) && value != 0) {
        return value;
    }
    return 0;
}

// FlagEnabled checks whether a numeric bitmask contains a requested flag. Inputs
// are protocol flags and a flag value; output is true when all flag bits are set.
bool FlagEnabled(const std::uint64_t flags, const std::uint64_t flag) {
    return (flags & flag) == flag;
}

// IsZeroMaskText identifies empty dependency masks in their common display
// forms. Input is a cell string; output is true for blank, decimal zero, or
// hexadecimal zero variants.
bool IsZeroMaskText(const std::wstring& text) {
    std::uint64_t value = 0;
    return text.empty() || (HexToUInt64(text, value) && value == 0);
}

// NamedMask describes one protocol bit with its C macro name and original
// KernelDock Chinese title. Inputs are static constants; processing helpers use
// it to render bitsets; no runtime ownership is stored here.
struct NamedMask {
    std::uint64_t mask;
    const wchar_t* name;
    const wchar_t* title;
};

constexpr NamedMask kDynCapabilityMasks[] = {
    { KSW_CAP_DYN_NTOS_ACTIVE, L"KSW_CAP_DYN_NTOS_ACTIVE", L"ntoskrnl profile 已激活" },
    { KSW_CAP_DYN_LXCORE_ACTIVE, L"KSW_CAP_DYN_LXCORE_ACTIVE", L"lxcore profile 已激活" },
    { KSW_CAP_OBJECT_TYPE_FIELDS, L"KSW_CAP_OBJECT_TYPE_FIELDS", L"对象类型字段" },
    { KSW_CAP_HANDLE_TABLE_DECODE, L"KSW_CAP_HANDLE_TABLE_DECODE", L"句柄表解码" },
    { KSW_CAP_PROCESS_OBJECT_TABLE, L"KSW_CAP_PROCESS_OBJECT_TABLE", L"进程 ObjectTable" },
    { KSW_CAP_THREAD_STACK_FIELDS, L"KSW_CAP_THREAD_STACK_FIELDS", L"线程栈字段" },
    { KSW_CAP_THREAD_IO_COUNTERS, L"KSW_CAP_THREAD_IO_COUNTERS", L"线程 I/O 计数" },
    { KSW_CAP_ALPC_FIELDS, L"KSW_CAP_ALPC_FIELDS", L"ALPC 字段" },
    { KSW_CAP_SECTION_CONTROL_AREA, L"KSW_CAP_SECTION_CONTROL_AREA", L"Section/ControlArea" },
    { KSW_CAP_PROCESS_PROTECTION_PATCH, L"KSW_CAP_PROCESS_PROTECTION_PATCH", L"进程保护修改" },
    { KSW_CAP_WSL_LXCORE_FIELDS, L"KSW_CAP_WSL_LXCORE_FIELDS", L"WSL/lxcore 字段" },
    { KSW_CAP_ETW_GUID_FIELDS, L"KSW_CAP_ETW_GUID_FIELDS", L"ETW GUID/Registration 字段" },
    { KSW_CAP_CALLBACK_NOTIFY_GLOBALS, L"KSW_CAP_CALLBACK_NOTIFY_GLOBALS", L"Callback Notify 全局 RVA" },
    { KSW_CAP_CALLBACK_REGISTRY_GLOBALS, L"KSW_CAP_CALLBACK_REGISTRY_GLOBALS", L"Registry Callback 全局 RVA" },
    { KSW_CAP_CALLBACK_OBJECT_FIELDS, L"KSW_CAP_CALLBACK_OBJECT_FIELDS", L"Object Callback 结构偏移" },
    { KSW_CAP_PROCESS_LIST_FIELDS, L"KSW_CAP_PROCESS_LIST_FIELDS", L"进程链表字段" },
    { KSW_CAP_THREAD_LIST_FIELDS, L"KSW_CAP_THREAD_LIST_FIELDS", L"线程链表字段" },
    { KSW_CAP_CID_TABLE_WALK, L"KSW_CAP_CID_TABLE_WALK", L"CID 表遍历" },
    { KSW_CAP_KERNEL_MODULE_LIST_FIELDS, L"KSW_CAP_KERNEL_MODULE_LIST_FIELDS", L"内核模块链表字段" },
    { KSW_CAP_DRIVER_OBJECT_FIELDS, L"KSW_CAP_DRIVER_OBJECT_FIELDS", L"驱动对象字段" },
    { KSW_CAP_KERNEL_GLOBALS, L"KSW_CAP_KERNEL_GLOBALS", L"内核全局 RVA" },
};

constexpr NamedMask kSecurityPolicyMasks[] = {
    { KSWORD_ARK_SECURITY_POLICY_FLAG_ACTIVE, L"POLICY_ACTIVE", L"安全策略启用" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_MUTATING_ACTIONS, L"ALLOW_MUTATING_ACTIONS", L"允许进程修改动作" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_FILE_DELETE, L"ALLOW_FILE_DELETE", L"允许文件删除" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_CALLBACK_CONTROL, L"ALLOW_CALLBACK_CONTROL", L"允许回调控制" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_PROCESS_PROTECTION, L"ALLOW_PROCESS_PROTECTION", L"允许进程保护修改" },
    { KSWORD_ARK_SECURITY_POLICY_ALLOW_KERNEL_SNAPSHOTS, L"ALLOW_KERNEL_SNAPSHOTS", L"允许内核快照" },
    { KSWORD_ARK_SECURITY_POLICY_REQUIRE_CONFIRMATION, L"REQUIRE_CONFIRMATION", L"要求确认" },
    { KSWORD_ARK_SECURITY_POLICY_DENY_CRITICAL_PROCESS, L"DENY_CRITICAL_PROCESS", L"拒绝关键进程" },
    { KSWORD_ARK_SECURITY_POLICY_ADVANCED_MODE, L"ADVANCED_MODE", L"高级模式" },
};

constexpr NamedMask kFeatureFlagMasks[] = {
    { KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA, L"Requires DynData", L"需要 DynData" },
    { KSWORD_ARK_FEATURE_FLAG_MUTATING, L"Mutating", L"修改性操作" },
    { KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY, L"Kernel Only", L"仅内核" },
    { KSWORD_ARK_FEATURE_FLAG_READ_ONLY, L"Read Only", L"只读" },
    { KSWORD_ARK_FEATURE_FLAG_POLICY_GATED, L"Policy Gated", L"受策略控制" },
};

// HexTextPadded formats numeric protocol values the same way the full
// KernelDock helpers did. Inputs are value and hex digits; output is uppercase
// 0x-prefixed text used in details/reports without mutating cached row values.
std::wstring HexTextPadded(const std::uint64_t value, const int digits) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setw(digits) << std::setfill(L'0') << value;
    return stream.str();
}

// NamedMaskText renders a protocol bitset as "MACRO (中文)" entries. Inputs are
// a mask and table; processing preserves original KernelDock names; output is
// "None" when no known bit is enabled.
std::wstring NamedMaskText(const std::uint64_t mask, const NamedMask* items, const std::size_t count) {
    std::wstring text;
    for (std::size_t index = 0; index < count; ++index) {
        const NamedMask& item = items[index];
        if ((mask & item.mask) != item.mask) {
            continue;
        }
        if (!text.empty()) {
            text += L", ";
        }
        text += item.name;
        text += L" (";
        text += item.title;
        text += L")";
    }
    return text.empty() ? L"None" : text;
}

// DynCapabilityNames renders KSW_CAP_* bits. Input is a 64-bit mask; output is
// the original capability name list used by DynData and DriverStatus pages.
std::wstring DynCapabilityNames(const std::uint64_t mask) {
    return NamedMaskText(mask, kDynCapabilityMasks, std::size(kDynCapabilityMasks));
}

// SecurityPolicyNames renders KSWORD_ARK_SECURITY_POLICY_* bits. Input is a
// 32-bit policy mask; output matches the original DriverStatus detail text.
std::wstring SecurityPolicyNames(const std::uint32_t mask) {
    return NamedMaskText(mask, kSecurityPolicyMasks, std::size(kSecurityPolicyMasks));
}

// FeatureFlagNames renders KSWORD_ARK_FEATURE_FLAG_* bits. Input is a 32-bit
// feature mask; output mirrors the original capability detail panel.
std::wstring FeatureFlagNames(const std::uint32_t mask) {
    return NamedMaskText(mask, kFeatureFlagMasks, std::size(kFeatureFlagMasks));
}

// DisabledDynCapabilitySummary lists the Chinese names of capability bits that
// are not enabled. Input is the global DynData capability mask; output is "无"
// when all known bits are active.
std::wstring DisabledDynCapabilitySummary(const std::uint64_t mask) {
    std::wstring text;
    for (const NamedMask& item : kDynCapabilityMasks) {
        if ((mask & item.mask) == item.mask) {
            continue;
        }
        if (!text.empty()) {
            text += L"、";
        }
        text += item.title;
    }
    return text.empty() ? L"无" : text;
}

// DynDataStatusFlagsText renders KSW_DYN_STATUS_FLAG_* in the same English
// badge style as the full KernelDock. Input is status flags; output is "None" if empty.
std::wstring DynDataStatusFlagsText(const std::uint32_t flags) {
    std::vector<std::wstring> parts;
    if (FlagEnabled(flags, KSW_DYN_STATUS_FLAG_INITIALIZED)) { parts.push_back(L"Initialized"); }
    if (FlagEnabled(flags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE)) { parts.push_back(L"NtosActive"); }
    if (FlagEnabled(flags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE)) { parts.push_back(L"LxcoreActive"); }
    if (FlagEnabled(flags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE)) { parts.push_back(L"ExtraActive"); }
    if (FlagEnabled(flags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)) { parts.push_back(L"PdbProfileActive"); }
    if (FlagEnabled(flags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE)) { parts.push_back(L"CallbackProfileActive"); }
    std::wstring text;
    for (const std::wstring& part : parts) {
        if (!text.empty()) {
            text += L", ";
        }
        text += part;
    }
    return text.empty() ? L"None" : text;
}

// FeatureStateText normalizes numeric driver feature states. Inputs are state
// id and optional fallback text; output follows the original DriverStatus table.
std::wstring FeatureStateText(const std::uint32_t state, const std::wstring& fallbackText) {
    switch (state) {
    case KSWORD_ARK_FEATURE_STATE_AVAILABLE: return L"Available";
    case KSWORD_ARK_FEATURE_STATE_UNAVAILABLE: return L"Unavailable";
    case KSWORD_ARK_FEATURE_STATE_DEGRADED: return L"Degraded";
    case KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY: return L"Denied by policy";
    default: return fallbackText.empty() ? L"Unknown" : fallbackText;
    }
}

// SetTabText inserts one tab item. Inputs are target tab, index and caption;
// processing sends TCM_INSERTITEMW; no value is returned.
void SetTabText(HWND tab, int index, const std::wstring& text) {
    TCITEMW item{};
    item.mask = TCIF_TEXT;
    item.pszText = const_cast<LPWSTR>(text.c_str());
    ::SendMessageW(tab, TCM_INSERTITEMW, static_cast<WPARAM>(index), reinterpret_cast<LPARAM>(&item));
}

// Width returns a non-negative rectangle width. Input is a RECT; output is a
// pixel width safe for MoveWindow/ListView column sizing.
int Width(const RECT& rect) {
    return rect.right > rect.left ? rect.right - rect.left : 0;
}

// Height returns a non-negative rectangle height. Input is a RECT; output is a
// pixel height safe for MoveWindow.
int Height(const RECT& rect) {
    return rect.bottom > rect.top ? rect.bottom - rect.top : 0;
}

// ClampInt restricts a calculated splitter coordinate or size to a safe pixel
// range. Inputs are value/min/max; output is the nearest in-range value.
int ClampInt(const int value, const int minimum, const int maximum) {
    if (maximum < minimum) {
        return minimum;
    }
    return std::max(minimum, std::min(value, maximum));
}

// WindowText reads a Win32 edit/static text into std::wstring. Input is a child
// HWND; processing uses GetWindowTextLengthW/GetWindowTextW; return is empty for
// null handles or empty controls.
std::wstring WindowText(HWND hwnd) {
    if (!hwnd) {
        return {};
    }
    const int length = ::GetWindowTextLengthW(hwnd);
    if (length <= 0) {
        return {};
    }
    std::wstring text(static_cast<std::size_t>(length), L'\0');
    ::GetWindowTextW(hwnd, text.data(), length + 1);
    return text;
}

// SetEditCueBanner assigns the Win32 Edit cue-banner text used as a lightweight
// cue banner. Inputs are the edit HWND and cue text; processing sends
// EM_SETCUEBANNER and intentionally ignores failure on older controls; no value
// is returned because the edit remains usable without the banner.
void SetEditCueBanner(HWND edit, const wchar_t* text) {
    if (!edit) {
        return;
    }
    ::SendMessageW(edit, EM_SETCUEBANNER, TRUE, reinterpret_cast<LPARAM>(text != nullptr ? text : L""));
}

// HasColumn reports whether a dynamic result column has already been added.
// Inputs are the ordered column vector and a candidate name; output avoids
// duplicate ListView columns while preserving first-seen order.
bool HasColumn(const std::vector<std::wstring>& columns, const std::wstring& name) {
    return std::find(columns.begin(), columns.end(), name) != columns.end();
}

// EmptyDetailTextForFeature returns the original KernelDock empty-detail text.
// Input is the active feature; output is shown when the table has no visible
// rows after a refresh or filter pass.
const wchar_t* EmptyDetailTextForFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::AtomTable:
        return L"请选择一条原子记录查看详情。";
    case KernelFeatureId::NtQueryLegacy:
        return L"请选择一条 NtQuery 结果查看详情。";
    case KernelFeatureId::Ssdt:
        return L"当前环境未返回可见 SSDT 条目。";
    case KernelFeatureId::ShadowSsdt:
        return L"当前环境未返回 SSSDT stub 解析结果。";
    case KernelFeatureId::InlineHook:
        return L"当前过滤条件下未返回 Inline Hook 记录。";
    case KernelFeatureId::IatEatHook:
        return L"当前过滤条件下未返回 IAT/EAT 记录。";
    case KernelFeatureId::CallbackEnumeration:
        return L"当前环境未返回可见回调记录。";
    case KernelFeatureId::NamedPipe:
        return L"说明：命名管道属于 NPFS 文件系统目录枚举，本页使用 NtOpenFile + NtQueryDirectoryFile 读取 \\Device\\NamedPipe。\r\n这不是 NtQueryDirectoryObject 下钻，也不是系统句柄表枚举。";
    case KernelFeatureId::ObjectDirectoryRecursive:
        return L"输入根路径后点击刷新。";
    case KernelFeatureId::DynData:
        return L"请选择一条动态偏移字段查看详情。";
    case KernelFeatureId::DriverStatus:
        return L"当前筛选条件下没有驱动能力记录。";
    default:
        return L"";
    }
}

// ContainsCaseInsensitive checks whether text contains a fragment without case
// sensitivity. Inputs are display strings; output is true for empty fragments or
// any case-insensitive substring match.
bool ContainsCaseInsensitive(std::wstring text, std::wstring fragment) {
    if (fragment.empty()) {
        return true;
    }
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    std::transform(fragment.begin(), fragment.end(), fragment.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return text.find(fragment) != std::wstring::npos;
}

// ColumnWidth returns a practical default width for a kernel result column.
// Input is a column title; output is a compact but readable ListView width.
int ColumnWidth(const std::wstring& name) {
    if (name == L"#") {
        return 52;
    }
    if (name == L"字段" || name == L"功能") {
        return 260;
    }
    if (name == L"Path" || name == L"NtPath" || name == L"Target" || name == L"Detail" || name == L"Module" || name == L"TargetModule" ||
        name == L"路径/说明" || name == L"符号链接目标" || name == L"完整路径" || name == L"目标路径" ||
        name == L"targetPath" || name == L"fullPath" || name == L"dosCandidate" || name == L"Win32Path" ||
        name == L"模块" || name == L"目标模块" || name == L"原因" || name == L"导入模块") {
        if (name == L"完整路径" || name == L"目标路径") {
            return 320;
        }
        return 260;
    }
    if (name == L"服务名" || name == L"函数" || name == L"函数/序号") {
        return 240;
    }
    if (name == L"Function" || name == L"Name" || name == L"objectName" || name == L"linkName" ||
        name == L"Pipe" || name == L"Pipe Name" || name == L"Type" || name == L"objectType" || name == L"Status" ||
        name == L"函数" || name == L"名称" || name == L"对象名称" || name == L"类型" || name == L"对象类型" ||
        name == L"状态" || name == L"服务名") {
        return 180;
    }
    if (name == L"Parent" || name == L"Source" || name == L"Directory" || name == L"directoryPath" ||
        name == L"sourceDirectory" || name == L"目录路径" || name == L"来源目录") {
        return name == L"目录路径" ? 190 : 220;
    }
    if (name == L"Address" || name == L"Target" || name == L"Service" || name == L"Zw" || name == L"Callback" ||
        name == L"函数地址" || name == L"目标地址" || name == L"回调/对象地址" || name == L"表项地址" ||
        name == L"Stub地址" || name == L"Zw导出地址" || name == L"服务例程" || name == L"当前目标" ||
        name == L"期望目标" || name == L"Thunk/EAT项") {
        return 180;
    }
    if (name == L"索引") {
        return 90;
    }
    if (name == L"偏移" || name == L"类型" || name == L"类别" || name == L"状态" || name == L"策略" ||
        name == L"所需DynData" || name == L"已满足DynData") {
        return name == L"状态" ? 260 : 140;
    }
    if (name == L"能力提示") {
        return 320;
    }
    return 130;
}

// SetClipboardText copies Unicode text to the process clipboard. Input is the
// text to copy; processing owns the global memory after SetClipboardData; no
// value is returned.
void SetClipboardText(HWND owner, const std::wstring& text) {
    if (!::OpenClipboard(owner)) {
        return;
    }
    ::EmptyClipboard();
    const SIZE_T bytes = (text.size() + 1) * sizeof(wchar_t);
    HGLOBAL memory = ::GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (memory) {
        void* target = ::GlobalLock(memory);
        if (target) {
            std::memcpy(target, text.c_str(), bytes);
            ::GlobalUnlock(memory);
            ::SetClipboardData(CF_UNICODETEXT, memory);
            memory = nullptr;
        }
        if (memory) {
            ::GlobalFree(memory);
        }
    }
    ::CloseClipboard();
}

// GetClipboardText reads Unicode text from the process clipboard. Input is the
// owner HWND used for OpenClipboard; processing copies CF_UNICODETEXT into a
// std::wstring before releasing the global handle; output is empty on failure.
std::wstring GetClipboardText(HWND owner) {
    if (!::OpenClipboard(owner)) {
        return {};
    }
    std::wstring text;
    HANDLE data = ::GetClipboardData(CF_UNICODETEXT);
    if (data) {
        const wchar_t* raw = static_cast<const wchar_t*>(::GlobalLock(data));
        if (raw) {
            text = raw;
            ::GlobalUnlock(data);
        }
    }
    ::CloseClipboard();
    return text;
}

// ListViewText reads one cell from a report ListView. Inputs are list HWND, row
// and column indexes; output is the current display text.
std::wstring ListViewText(HWND list, const int row, const int column) {
    if (!list || row < 0 || column < 0) {
        return {};
    }
    std::wstring text(4096, L'\0');
    LVITEMW item{};
    item.iSubItem = column;
    item.cchTextMax = static_cast<int>(text.size());
    item.pszText = text.data();
    ::SendMessageW(list, LVM_GETITEMTEXTW, static_cast<WPARAM>(row), reinterpret_cast<LPARAM>(&item));
    text.resize(std::wcslen(text.c_str()));
    return text;
}

// HeaderColumnCount returns the number of visible ListView columns. Input is a
// ListView HWND; output is zero when no header exists.
int HeaderColumnCount(HWND list) {
    HWND header = ListView_GetHeader(list);
    return header ? Header_GetItemCount(header) : 0;
}

// BuildListViewSelectionTsv serializes selected rows from any report ListView.
// Inputs are the list and includeHeader flag; processing reads visible text
// exactly as displayed; output is a tab-separated string suitable for clipboard
// or file export.
std::wstring BuildListViewSelectionTsv(HWND list, const bool includeHeader) {
    if (!list) {
        return {};
    }
    const int columns = HeaderColumnCount(list);
    const int rows = ListView_GetItemCount(list);
    std::wstring text;
    if (includeHeader) {
        for (int column = 0; column < columns; ++column) {
            if (column > 0) {
                text += L'\t';
            }
            wchar_t headerText[256]{};
            LVCOLUMNW lvColumn{};
            lvColumn.mask = LVCF_TEXT;
            lvColumn.pszText = headerText;
            lvColumn.cchTextMax = static_cast<int>(std::size(headerText));
            ListView_GetColumn(list, column, &lvColumn);
            text += headerText;
        }
    }
    bool wroteRow = includeHeader;
    for (int row = 0; row < rows; ++row) {
        if (ListView_GetItemState(list, row, LVIS_SELECTED) == 0) {
            continue;
        }
        if (wroteRow) {
            text += L"\r\n";
        }
        for (int column = 0; column < columns; ++column) {
            if (column > 0) {
                text += L'\t';
            }
            text += ListViewText(list, row, column);
        }
        wroteRow = true;
    }
    return text;
}


// RowFieldByName reads a named value from a cached dynamic row. Inputs are a row,
// the current column names and one or more accepted column aliases; processing is
// case-insensitive and preserves the original display value; output is empty when
// no alias is present or the selected cell is blank.
std::wstring RowFieldByName(const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    for (const wchar_t* name : names) {
        for (std::size_t column = 0; column < columns.size() && column < row.size(); ++column) {
            if (_wcsicmp(columns[column].c_str(), name) == 0 && !row[column].empty()) {
                return row[column];
            }
        }
    }
    return {};
}

// IsObjectNamespaceFeature reports whether a feature belongs to the original
// KernelDock "对象命名空间" group. Inputs are stable feature ids; output drives
// the dedicated tree/table renderer instead of the generic result grid.
bool IsObjectNamespaceFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::ObjectNamespaceOverview:
    case KernelFeatureId::ObjectDirectoryRecursive:
    case KernelFeatureId::NamedPipe:
    case KernelFeatureId::BaseNamedObjects:
    case KernelFeatureId::SymbolicLink:
    case KernelFeatureId::DeviceDriverObjects:
    case KernelFeatureId::ObjectTypeMatrix:
    case KernelFeatureId::CommunicationEndpoint:
        return true;
    default:
        return false;
    }
}

// UsesObjectNamespaceTreeIndexColumn is retained for old call sites but now
// always reports false. The original KernelDock object namespace and directory
// recursive pages are QTreeWidget pages with visible tree columns only; they do
// not expose a synthetic "#" column.
bool UsesObjectNamespaceTreeIndexColumn(const KernelFeatureId featureId) {
    (void)featureId;
    return false;
}

// IsKernelHookFeature reports whether a feature uses the original KernelDock
// SSDT/SSSDT/Inline/IAT hook split layout. Input is a feature id; output drives
// the compact Win32 toolbar plus table/detail split.
bool IsKernelHookFeature(const KernelFeatureId featureId) {
    return featureId == KernelFeatureId::Ssdt ||
        featureId == KernelFeatureId::ShadowSsdt ||
        featureId == KernelFeatureId::InlineHook ||
        featureId == KernelFeatureId::IatEatHook;
}

// IsR0TableDetailFeature reports pages that use the same vertical table/detail
// splitter as their source dock pages. Input is a stable feature id; output is
// true when the user must be able to resize the result table and detail editor.
bool IsR0TableDetailFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::CallbackEnumeration:
    case KernelFeatureId::KernelExecutableMemory:
    case KernelFeatureId::KernelMemoryEvidence:
    case KernelFeatureId::ProcessCrossView:
    case KernelFeatureId::ThreadCrossView:
    case KernelFeatureId::DriverIntegrity:
    case KernelFeatureId::KernelCpuIntegrity:
    case KernelFeatureId::CpuHardwareSnapshot:
    case KernelFeatureId::PhysicalMemoryLayout:
    case KernelFeatureId::MutationAudit:
    case KernelFeatureId::KeyboardHotkeys:
    case KernelFeatureId::KeyboardHooks:
    case KernelFeatureId::DynDataCapabilities:
    case KernelFeatureId::MinifilterBypassPids:
    case KernelFeatureId::KernelTimerDpc:
    case KernelFeatureId::IoctlRegistry:
        return true;
    default:
        return false;
    }
}

// IsR0OriginalNoPopupFeature identifies source pages whose tables did not own a
// row context menu. Inputs are feature ids; output true means the Win32 port
// should swallow WM_CONTEXTMENU instead of appending generic kernel actions.
bool IsR0OriginalNoPopupFeature(const KernelFeatureId featureId) {
    switch (featureId) {
    case KernelFeatureId::KernelExecutableMemory:
    case KernelFeatureId::KernelMemoryEvidence:
    case KernelFeatureId::ProcessCrossView:
    case KernelFeatureId::ThreadCrossView:
    case KernelFeatureId::DriverIntegrity:
    case KernelFeatureId::KernelCpuIntegrity:
    case KernelFeatureId::CpuHardwareSnapshot:
    case KernelFeatureId::PhysicalMemoryLayout:
    case KernelFeatureId::KeyboardHotkeys:
    case KernelFeatureId::KeyboardHooks:
    case KernelFeatureId::DynDataCapabilities:
        return true;
    default:
        return false;
    }
}

// IsOriginalDetailPreferredFeature reports pages whose original KernelDock
// detail editor stored a complete detailText per source row. Input is a feature
// id; output controls copy/detail behavior so Win32 menus do not wrap those
// details with generic row labels.
bool IsOriginalDetailPreferredFeature(const KernelFeatureId featureId) {
    return IsKernelHookFeature(featureId) ||
        featureId == KernelFeatureId::CallbackEnumeration ||
        featureId == KernelFeatureId::AtomTable ||
        featureId == KernelFeatureId::NtQueryLegacy;
}

// KernelHookVisibleColumnIndices returns the ListView column indices that match
// the original KernelDock SSDT/SSSDT/Inline/IAT-EAT table headers. Inputs are
// the feature id and current dynamic column schema; processing skips synthetic
// "#" and hidden diagnostic columns; output is used by Win32 copy/menu code.
std::vector<int> KernelHookVisibleColumnIndices(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns) {
    std::vector<int> indices;
    if (!IsKernelHookFeature(featureId)) {
        return indices;
    }
    const std::vector<std::wstring> canonical = CanonicalColumnNames(featureId);
    indices.reserve(canonical.size());
    for (const std::wstring& name : canonical) {
        for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
            if (_wcsicmp(columns[static_cast<std::size_t>(index)].c_str(), name.c_str()) == 0) {
                indices.push_back(index);
                break;
            }
        }
    }
    return indices;
}

// CanonicalVisibleColumnIndices returns the original table columns for pages
// whose Win32 rows also carry hidden protocol fields. Inputs are the feature id
// and current dynamic schema; processing maps CanonicalColumnNames back to
// actual ListView indices; output is empty for pages that should copy every
// column.
std::vector<int> CanonicalVisibleColumnIndices(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns) {
    if (featureId != KernelFeatureId::CallbackEnumeration &&
        featureId != KernelFeatureId::DynData &&
        featureId != KernelFeatureId::DriverStatus) {
        return {};
    }

    std::vector<int> indices;
    const std::vector<std::wstring> canonical = CanonicalColumnNames(featureId);
    indices.reserve(canonical.size());
    for (const std::wstring& name : canonical) {
        for (int index = 0; index < static_cast<int>(columns.size()); ++index) {
            if (_wcsicmp(columns[static_cast<std::size_t>(index)].c_str(), name.c_str()) == 0) {
                indices.push_back(index);
                break;
            }
        }
    }
    return indices;
}

// PreferredCopyColumnIndices chooses the column set that should participate in
// row/header copy operations. Inputs are the active feature and current schema;
// output preserves the original KernelDock visible table contract while hidden
// Win32 protocol fields remain available for context menu actions.
std::vector<int> PreferredCopyColumnIndices(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns) {
    std::vector<int> indices = KernelHookVisibleColumnIndices(featureId, columns);
    if (!indices.empty()) {
        return indices;
    }
    return CanonicalVisibleColumnIndices(featureId, columns);
}

// IsKernelHookVisibleColumn reports whether a dynamic column should be shown in
// original hook tables. Inputs are the feature id and a display column name;
// output hides R0 capability, hidden address/detail, and synthetic columns while
// keeping the exact original KernelDock headers visible.
bool IsKernelHookVisibleColumn(const KernelFeatureId featureId, const std::wstring& name) {
    if (!IsKernelHookFeature(featureId)) {
        return true;
    }
    const std::vector<std::wstring> canonical = CanonicalColumnNames(featureId);
    return std::any_of(canonical.begin(), canonical.end(), [&name](const std::wstring& column) {
        return _wcsicmp(column.c_str(), name.c_str()) == 0;
    });
}

// HasKernelHookDisplayValues checks whether a row contains at least one value in
// the original visible hook columns. Inputs are a row, feature id, and current
// schema; output lets the UI hide injected R0 capability/status rows without
// dropping the hidden detail/action data on real rows.
bool HasKernelHookDisplayValues(
    const KernelFeatureId featureId,
    const std::vector<std::wstring>& columns,
    const std::vector<std::wstring>& row) {
    const std::vector<int> indices = KernelHookVisibleColumnIndices(featureId, columns);
    for (const int index : indices) {
        if (index >= 0 && index < static_cast<int>(row.size()) && !row[static_cast<std::size_t>(index)].empty()) {
            return true;
        }
    }
    return false;
}

// HasNonEmptyField checks whether a cached row carries at least one meaningful
// field. Inputs are the row, its column schema, and candidate field names; output
// lets the object namespace renderer hide generic diagnostic rows from the tree.
bool HasNonEmptyField(const std::vector<std::wstring>& row,
    const std::vector<std::wstring>& columns,
    std::initializer_list<const wchar_t*> names) {
    return !RowFieldByName(row, columns, names).empty();
}

// MergeRowText concatenates all non-empty fields of one cached result row.
// Inputs are row cells; processing joins values with a stable separator; output
// is used by local filter predicates without changing the backing result data.
std::wstring MergeRowText(const std::vector<std::wstring>& row) {
    std::wstring merged;
    for (const std::wstring& value : row) {
        if (value.empty()) {
            continue;
        }
        if (!merged.empty()) {
            merged += L" | ";
        }
        merged += value;
    }
    return merged;
}

// LowerInvariantKey normalizes object-manager paths for TreeView lookup. Inputs
// are display strings from query rows; processing lowercases only for map keys
// and leaves the original UI text untouched; output is empty when no key exists.
std::wstring LowerInvariantKey(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t ch) {
        return static_cast<wchar_t>(std::towlower(ch));
    });
    return text;
}

// ParentObjectPath derives a native parent path from a full object path when a
// row lacks an explicit Parent field. Input is a path like "\Device\Foo";
// output is "\Device", "\" for direct root children, or empty for invalid text.
std::wstring ParentObjectPath(const std::wstring& path) {
    if (path.empty() || path == L"\\") {
        return {};
    }
    const std::size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos) {
        return {};
    }
    if (slash == 0) {
        return L"\\";
    }
    return path.substr(0, slash);
}

// LeafObjectName returns the display leaf for synthetic TreeView directory
// nodes. Input is a native object path; output is "\" for the root, the last
// component for normal paths, or the original text when no separator exists.
std::wstring LeafObjectName(const std::wstring& path) {
    if (path.empty() || path == L"\\") {
        return L"\\";
    }
    const std::size_t slash = path.find_last_of(L'\\');
    if (slash == std::wstring::npos || slash + 1 >= path.size()) {
        return path;
    }
    return path.substr(slash + 1);
}

// ListViewInsertRow appends one row to a report ListView. Inputs are the target
// control and ordered cells; processing fills subitems after inserting column 0;
// there is no return value because the control stores the display state.
void ListViewInsertRow(HWND list, const std::vector<std::wstring>& cells) {
    if (!list || cells.empty()) {
        return;
    }
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(list);
    item.iSubItem = 0;
    item.pszText = const_cast<LPWSTR>(cells[0].c_str());
    const int inserted = ListView_InsertItem(list, &item);
    if (inserted < 0) {
        return;
    }
    for (int column = 1; column < static_cast<int>(cells.size()); ++column) {
        ListView_SetItemText(list, inserted, column, const_cast<LPWSTR>(cells[static_cast<std::size_t>(column)].c_str()));
    }
}

// AppendReportLine appends one diagnostic key/value pair. Inputs are a stream,
// a label and a value; processing skips empty values so copied reports stay
// compact like the original diagnostic reports; there is no return value.
void AppendReportLine(std::wostringstream& report, const wchar_t* label, const std::wstring& value) {
    if (!value.empty()) {
        report << label << L": " << value << L"\r\n";
    }
}

// AddListColumn inserts a report column into an auxiliary ListView. Inputs are a
// target ListView, index, title and width; processing is a direct Win32 column
// insert; no value is returned.
void AddListColumn(HWND list, const int index, const wchar_t* title, const int width) {
    if (!list) {
        return;
    }
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    column.cx = width;
    column.pszText = const_cast<LPWSTR>(title);
    ListView_InsertColumn(list, index, &column);
}

// AddListRow appends one row to an auxiliary ListView. Inputs are target list
// and ordered cell text; processing inserts the first cell then subitems; output
// is only visible UI state.
void AddListRow(HWND list, const std::vector<std::wstring>& cells) {
    if (!list || cells.empty()) {
        return;
    }
    LVITEMW item{};
    item.mask = LVIF_TEXT;
    item.iItem = ListView_GetItemCount(list);
    item.iSubItem = 0;
    item.pszText = const_cast<LPWSTR>(cells[0].c_str());
    const int row = ListView_InsertItem(list, &item);
    for (int column = 1; row >= 0 && column < static_cast<int>(cells.size()); ++column) {
        ListView_SetItemText(list, row, column, const_cast<LPWSTR>(cells[static_cast<std::size_t>(column)].c_str()));
    }
}

// ConfigureReportList applies compact ListView behavior used by all Win32
// kernel subpanels. Input is a ListView HWND; output is style state only.
void ConfigureReportList(HWND list) {
    if (!list) {
        return;
    }
    ListView_SetExtendedListViewStyleEx(list,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
        LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
}

// EscapeConfigField stores a local callback rule field in a tab-separated
// lightweight file. Input is arbitrary UI text; output escapes separators and
// line breaks without depending on JSON or third-party parsers.
std::wstring EscapeConfigField(const std::wstring& text) {
    std::wstring escaped;
    escaped.reserve(text.size());
    for (const wchar_t ch : text) {
        switch (ch) {
        case L'\\': escaped += L"\\\\"; break;
        case L'\t': escaped += L"\\t"; break;
        case L'\r': escaped += L"\\r"; break;
        case L'\n': escaped += L"\\n"; break;
        default: escaped.push_back(ch); break;
        }
    }
    return escaped;
}

// UnescapeConfigField reverses EscapeConfigField. Input is one serialized field;
// output is the UI text used by the local callback rule editor.
std::wstring UnescapeConfigField(const std::wstring& text) {
    std::wstring value;
    value.reserve(text.size());
    bool escaping = false;
    for (const wchar_t ch : text) {
        if (escaping) {
            switch (ch) {
            case L't': value.push_back(L'\t'); break;
            case L'r': value.push_back(L'\r'); break;
            case L'n': value.push_back(L'\n'); break;
            case L'\\': value.push_back(L'\\'); break;
            default:
                value.push_back(ch);
                break;
            }
            escaping = false;
            continue;
        }
        if (ch == L'\\') {
            escaping = true;
        } else {
            value.push_back(ch);
        }
    }
    if (escaping) {
        value.push_back(L'\\');
    }
    return value;
}

// SplitTabLine splits a callback config line while preserving empty fields.
// Input is a single CR/LF-free line; output is tab-separated fields.
std::vector<std::wstring> SplitTabLine(const std::wstring& line) {
    std::vector<std::wstring> fields;
    std::wstring current;
    for (const wchar_t ch : line) {
        if (ch == L'\t') {
            fields.push_back(current);
            current.clear();
        } else {
            current.push_back(ch);
        }
    }
    fields.push_back(current);
    return fields;
}

// ParseUnsigned converts a serialized unsigned field. Input is decimal text;
// output is fallback on invalid input so importing cannot crash the UI.
std::uint32_t ParseUnsigned(const std::wstring& text, const std::uint32_t fallback) {
    if (text.empty()) {
        return fallback;
    }
    wchar_t* end = nullptr;
    const unsigned long value = std::wcstoul(text.c_str(), &end, 10);
    return end != text.c_str() ? static_cast<std::uint32_t>(value) : fallback;
}

// ParseSigned converts a serialized signed field. Input is decimal text; output
// is fallback when parsing fails.
int ParseSigned(const std::wstring& text, const int fallback) {
    if (text.empty()) {
        return fallback;
    }
    wchar_t* end = nullptr;
    const long value = std::wcstol(text.c_str(), &end, 10);
    return end != text.c_str() ? static_cast<int>(value) : fallback;
}

// ParseUnsigned64Value converts decimal or 0x-prefixed text into a 64-bit value.
// Inputs are an edit-control string and an output reference; processing trims
// common whitespace and accepts the same address forms used by the original
// MemoryDock pages; output is true only when the whole token parsed.
bool ParseUnsigned64Value(const std::wstring& text, std::uint64_t& valueOut) {
    std::wstring trimmed = text;
    trimmed.erase(trimmed.begin(), std::find_if(trimmed.begin(), trimmed.end(), [](wchar_t ch) {
        return !std::iswspace(ch);
    }));
    trimmed.erase(std::find_if(trimmed.rbegin(), trimmed.rend(), [](wchar_t ch) {
        return !std::iswspace(ch);
    }).base(), trimmed.end());
    if (trimmed.empty()) {
        return false;
    }
    wchar_t* end = nullptr;
    const int base = trimmed.size() > 2 && trimmed[0] == L'0' && (trimmed[1] == L'x' || trimmed[1] == L'X') ? 16 : 10;
    const unsigned long long value = std::wcstoull(trimmed.c_str(), &end, base);
    if (end == trimmed.c_str() || *end != L'\0') {
        return false;
    }
    valueOut = static_cast<std::uint64_t>(value);
    return true;
}

// IsNavigableWin32OrUncPath accepts only unambiguous drive-rooted or UNC paths
// from callback file-monitor rows. Kernel device paths and extended/device
// namespaces deliberately stay display-only because this R3 browser must not
// guess a user-mode path for them.
bool IsNavigableWin32OrUncPath(const std::wstring& path) {
    const bool hasAsciiDriveLetter = path.size() >= 1U &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z'));
    if (path.size() >= 3U && hasAsciiDriveLetter && path[1] == L':' &&
        (path[2] == L'\\' || path[2] == L'/')) {
        return true;
    }
    if (path.size() < 5U || path[0] != L'\\' || path[1] != L'\\' ||
        path[2] == L'?' || path[2] == L'.') {
        return false;
    }
    const std::size_t serverEnd = path.find(L'\\', 2U);
    if (serverEnd == std::wstring::npos || serverEnd == 2U || serverEnd + 1U >= path.size()) {
        return false;
    }
    const std::size_t shareEnd = path.find(L'\\', serverEnd + 1U);
    return shareEnd != serverEnd + 1U;
}

// FileMonitorContainingDirectory derives the safe directory context of a
// complete event path without touching the filesystem. FileView enumerates
// directories, not individual files, so forwarding an observed file pathname
// itself would always produce an invalid "file\\*" search pattern.
std::wstring FileMonitorContainingDirectory(const std::wstring& path) {
    if (!IsNavigableWin32OrUncPath(path)) {
        return {};
    }
    std::wstring normalized = path;
    std::replace(normalized.begin(), normalized.end(), L'/', L'\\');
    if (normalized.back() == L'\\') {
        return normalized;
    }

    const std::size_t lastSeparator = normalized.find_last_of(L'\\');
    if (lastSeparator == std::wstring::npos) {
        return {};
    }
    const bool drivePath = normalized.size() >= 3U && normalized[1] == L':';
    if (drivePath && lastSeparator == 2U) {
        return normalized.substr(0U, 3U);
    }
    if (!drivePath) {
        const std::size_t serverSeparator = normalized.find(L'\\', 2U);
        if (serverSeparator == std::wstring::npos) {
            return {};
        }
        if (lastSeparator == serverSeparator) {
            return normalized;
        }
    }
    return lastSeparator > 0U ? normalized.substr(0U, lastSeparator) : std::wstring{};
}

// IsKernelMemoryHiddenColumn preserves R0/action fields while hiding them from
// the original MemoryDock-style list. Inputs are fixed display/raw column names;
// output is true when the ListView column width should be zero.
bool IsKernelMemoryHiddenColumn(const std::wstring& name) {
    return name == L"RegionSize" ||
        name == L"Perm" ||
        name == L"Risk" ||
        name == L"OwnerKind" ||
        name == L"OwnerKindText" ||
        name == L"OwnerAddress" ||
        name == L"ModuleBase" ||
        name == L"ModuleSize" ||
        name == L"ModuleSizeText" ||
        name == L"Status" ||
        name == L"LastStatus" ||
        name == L"Kind" ||
        name == L"PageSize" ||
        name == L"Confidence" ||
        name == L"BigPoolTag" ||
        name == L"BigPoolFlags" ||
        name == L"SectionRva" ||
        name == L"SectionSize" ||
        name == L"SectionSizeText" ||
        name == L"Section" ||
        name == L"HashAlgorithm" ||
        name == L"SampleSize" ||
        name == L"Hash" ||
        name == L"HashText" ||
        name == L"Sample";
}

// IsIntegrityHiddenColumn preserves raw R0 evidence fields while keeping the
// DriverIntegrity and CPU/IDT grids visually close to the original KernelDock
// tables. Input is a column name; output is true when the Win32 ListView column
// should be retained for detail/actions but hidden with width zero.
bool IsIntegrityHiddenColumn(const std::wstring& name) {
    return name == L"Class" ||
        name == L"ClassText" ||
        name == L"Risk" ||
        name == L"RiskText" ||
        name == L"Source" ||
        name == L"SourceMask" ||
        name == L"SourceText" ||
        name == L"Confidence" ||
        name == L"Group" ||
        name == L"CPU" ||
        name == L"Vector" ||
        name == L"CpuVector" ||
        name == L"Object" ||
        name == L"ObjectAddress" ||
        name == L"Target" ||
        name == L"TargetAddress" ||
        name == L"OwnerBase" ||
        name == L"OwnerModuleBase" ||
        name == L"OwnerSize" ||
        name == L"OwnerModuleSize" ||
        name == L"OwnerModuleSizeText" ||
        name == L"OwnerModule" ||
        name == L"LastStatus";
}

// CallbackRemoveClassForEnumClass maps one callback-enumeration row class to
// the R0 remove protocol class. Input is the hidden "Class" cell value; output
// is zero when no public remove path exists for that callback category.
std::uint32_t CallbackRemoveClassForEnumClass(const std::uint32_t callbackClass) {
    switch (callbackClass) {
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
    case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
        return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
    default:
        return 0;
    }
}

// CallbackEnumPrimaryRemoveValue selects the address/id that remove operations
// can send for one visible callback row. Inputs are selected-row text fields;
// output follows the original KernelDock priority for callback, registration,
// and raw storage values.
std::uint64_t CallbackEnumPrimaryRemoveValue(
    const std::uint64_t callbackAddress,
    const std::uint64_t registrationAddress,
    const std::uint64_t rawStorageValue,
    const std::uint32_t fieldFlags) {
    if (callbackAddress != 0 &&
        ((fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS) != 0 ||
            (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0 ||
            (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE) != 0 ||
            (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0)) {
        return callbackAddress;
    }
    if (registrationAddress != 0 &&
        (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0) {
        return registrationAddress;
    }
    return rawStorageValue != 0 ? rawStorageValue : registrationAddress;
}

// CallbackEnumFallbackSource reports whether a callback row came from private
// unsupported/pattern diagnostics. Input is the shared source id; output drives
// experimental-only menu enablement without calling the driver.
bool CallbackEnumFallbackSource(const std::uint32_t source) {
    return source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED;
}

// CallbackEnumSafeRemoveAllowed mirrors the original table menu policy for the
// public API path. Inputs are selected-row numeric/text fields; output is true
// only for a single verified/candidate row with a compatible request value.
bool CallbackEnumSafeRemoveAllowed(
    const std::uint32_t callbackClass,
    const std::uint32_t status,
    const std::uint32_t source,
    const std::uint32_t fieldFlags,
    const std::uint32_t removeBehavior,
    const std::uint64_t requestValue,
    const std::wstring& removePolicy) {
    if (CallbackRemoveClassForEnumClass(callbackClass) == 0 ||
        status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK ||
        requestValue == 0 ||
        ContainsCaseInsensitive(removePolicy, L"not removable") ||
        ContainsCaseInsensitive(removePolicy, L"不可移除") ||
        ContainsCaseInsensitive(removePolicy, L"experimental only")) {
        return false;
    }
    const bool verified = (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE) != 0 ||
        (removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0;
    const bool candidate = (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0 ||
        ContainsCaseInsensitive(removePolicy, L"candidate") ||
        ContainsCaseInsensitive(removePolicy, L"verified");
    const bool publicSource = source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API ||
        source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA;
    return verified || candidate || publicSource;
}

// CallbackEnumExperimentalUnlinkAllowed mirrors the original unlink menu policy.
// Inputs are selected-row numeric/text fields; output is false for diagnostics
// with no address-like storage or for explicitly non-removable rows.
bool CallbackEnumExperimentalUnlinkAllowed(
    const std::uint32_t callbackClass,
    const std::uint32_t status,
    const std::uint32_t source,
    const std::uint32_t fieldFlags,
    const std::uint32_t removeBehavior,
    const std::uint64_t requestValue,
    const std::uint64_t contextAddress,
    const std::wstring& removePolicy) {
    if (CallbackRemoveClassForEnumClass(callbackClass) == 0 ||
        status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK ||
        ContainsCaseInsensitive(removePolicy, L"not removable") ||
        ContainsCaseInsensitive(removePolicy, L"不可移除")) {
        return false;
    }
    const bool hasAnyStorage = requestValue != 0 || contextAddress != 0;
    if (!hasAnyStorage) {
        return false;
    }
    const bool experimental = (fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE) != 0 ||
        (removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK) != 0 ||
        ContainsCaseInsensitive(removePolicy, L"experimental") ||
        ContainsCaseInsensitive(removePolicy, L"candidate") ||
        ContainsCaseInsensitive(removePolicy, L"verified");
    return experimental || CallbackEnumFallbackSource(source);
}

// ReadWholeFileText reads a UTF-16LE-BOM or UTF-8 text file selected by the
// user. Inputs are path and error sink; output is decoded Unicode text.
std::wstring ReadWholeFileText(const std::wstring& path, std::wstring* errorText) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorText) {
            *errorText = L"无法打开文件，Win32=" + std::to_wstring(::GetLastError());
        }
        return {};
    }
    LARGE_INTEGER size{};
    if (!::GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > 16 * 1024 * 1024) {
        if (errorText) {
            *errorText = L"文件大小不可用或超过 16MB。";
        }
        ::CloseHandle(file);
        return {};
    }
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    const BOOL ok = bytes.empty() ? TRUE : ::ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr);
    ::CloseHandle(file);
    if (!ok || read != bytes.size()) {
        if (errorText) {
            *errorText = L"读取文件失败，Win32=" + std::to_wstring(::GetLastError());
        }
        return {};
    }
    if (bytes.size() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE) {
        const auto* wide = reinterpret_cast<const wchar_t*>(bytes.data() + 2);
        const std::size_t wcharCount = (bytes.size() - 2) / sizeof(wchar_t);
        return std::wstring(wide, wide + wcharCount);
    }
    const int needed = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), nullptr, 0);
    if (needed > 0) {
        std::wstring text(static_cast<std::size_t>(needed), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), text.data(), needed);
        return text;
    }
    const int ansiNeeded = ::MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), nullptr, 0);
    if (ansiNeeded <= 0) {
        if (errorText) {
            *errorText = L"无法按 UTF-8/ANSI 解码配置文件。";
        }
        return {};
    }
    std::wstring text(static_cast<std::size_t>(ansiNeeded), L'\0');
    ::MultiByteToWideChar(CP_ACP, 0, reinterpret_cast<const char*>(bytes.data()), static_cast<int>(bytes.size()), text.data(), ansiNeeded);
    return text;
}

// WriteWholeFileText writes UTF-16LE with BOM. Inputs are path and text; output
// is success/failure and optional Win32 error message.
bool WriteWholeFileText(const std::wstring& path, const std::wstring& text, std::wstring* errorText) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorText) {
            *errorText = L"无法创建文件，Win32=" + std::to_wstring(::GetLastError());
        }
        return false;
    }
    const std::uint8_t bom[] = { 0xFF, 0xFE };
    DWORD written = 0;
    BOOL ok = ::WriteFile(file, bom, sizeof(bom), &written, nullptr);
    if (ok) {
        ok = ::WriteFile(file, text.data(), static_cast<DWORD>(text.size() * sizeof(wchar_t)), &written, nullptr);
    }
    const DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
    ::CloseHandle(file);
    if (!ok && errorText) {
        *errorText = L"写入文件失败，Win32=" + std::to_wstring(error);
    }
    return ok != FALSE;
}

} // namespace

// KernelObjectNamespaceTreeNodeState is the per-TreeView node payload used by
// the Win32 object namespace port. Inputs are copied from the current table
// cache when the tree is rebuilt; processing stores this object behind
// TVITEM::lParam; return behavior is pointer-based selection with ownership kept
// by KernelPage::objectNamespaceTreeNodeStorage_.
struct KernelObjectNamespaceTreeNodeState {
    int rowIndex = -1;
    std::wstring nodeKind;
    std::wstring nodeName;
    std::wstring nodeType;
    std::wstring nodePath;
    std::wstring nodeDescription;
};

KernelPage::KernelPage() = default;
KernelPage::~KernelPage() = default;

void KernelPage::SetInitialFeature(const KernelFeatureId featureId) noexcept {
    // Store the requested feature until WM_CREATE constructs primary and
    // secondary tabs. Input is a stable catalog id; no value is returned.
    initialFeatureId_ = featureId;
    hasInitialFeatureId_ = true;
}

HWND KernelPage::Create(HWND parent, const int controlId, const RECT& bounds) {
    EnsureKernelPageClass();
    hwnd_ = ::CreateWindowExW(
        0,
        kKernelPageClass,
        L"Kernel",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        bounds.right - bounds.left,
        bounds.bottom - bounds.top,
        parent,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)),
        ::GetModuleHandleW(nullptr),
        this);
    return hwnd_;
}

LRESULT CALLBACK KernelPage::WndProc(HWND hwnd, const UINT msg, const WPARAM wParam, const LPARAM lParam) {
    KernelPage* page = reinterpret_cast<KernelPage*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
    if (msg == WM_NCCREATE) {
        auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
        page = static_cast<KernelPage*>(create->lpCreateParams);
        page->hwnd_ = hwnd;
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(page));
    }

    if (page) {
        return page->HandleMessage(hwnd, msg, wParam, lParam);
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK KernelPage::FilterEditSubclassProc(HWND hwnd, const UINT msg, const WPARAM wParam, const LPARAM lParam,
    const UINT_PTR subclassId, const DWORD_PTR refData) {
    // FilterEditSubclassProc gives the object-directory root edit the same
    // return-key refresh behavior as the original root-path edit. Inputs are the
    // edit HWND and normal subclass parameters; processing only intercepts Enter
    // while the active page is "目录递归"; output otherwise delegates to the
    // default subclass proc.
    auto* page = reinterpret_cast<KernelPage*>(refData);
    if (msg == WM_KEYDOWN && wParam == VK_RETURN && page != nullptr) {
        const KernelFeatureDescriptor* descriptor = page->CurrentDescriptor();
        if (descriptor != nullptr && descriptor->id == KernelFeatureId::ObjectDirectoryRecursive) {
            page->RefreshSelectedFeature();
            return 0;
        }
    }
    if (msg == WM_NCDESTROY) {
        ::RemoveWindowSubclass(hwnd, KernelPage::FilterEditSubclassProc, subclassId);
    }
    return ::DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT KernelPage::HandleMessage(HWND hwnd, const UINT msg, const WPARAM wParam, const LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        queryTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<KernelOperationResult>>(hwnd, kMsgKernelQueryCompleted);
        actionTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<KernelOperationResult>>(hwnd, kMsgKernelActionCompleted);
        callbackAnswerTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<KernelOperationResult>>(hwnd, kMsgCallbackAnswerCompleted);
        callbackFileIoTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<CallbackFileIoResult>>(hwnd, kMsgCallbackFileIoCompleted);
        r0EvidenceFilterTask_ = std::make_unique<Ksword::Ui::AsyncSnapshotTask<KernelR0EvidenceSnapshot>>(hwnd, kMsgR0EvidenceFilterCompleted);
        callbackEventReceiver_ = std::make_unique<CallbackEventReceiver>(hwnd, kMsgCallbackEventReceived);
        CreateChildControls();
        PopulateTabs();
        Layout();
        return 0;
    case WM_SIZE:
        Layout();
        return 0;
    case kMsgKernelQueryCompleted:
        if (queryTask_ && queryTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgKernelActionCompleted:
        if (actionTask_ && actionTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgCallbackEventReceived:
    {
        std::unique_ptr<CallbackEventSnapshot> snapshot(reinterpret_cast<CallbackEventSnapshot*>(lParam));
        if (snapshot && callbackEventReceiver_ && callbackEventReceiver_->accepts(snapshot->generation)) {
            AcceptCallbackEvent(std::move(*snapshot));
        }
        return 0;
    }
    case kMsgCallbackAnswerCompleted:
        if (callbackAnswerTask_ && callbackAnswerTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgCallbackFileIoCompleted:
        if (callbackFileIoTask_ && callbackFileIoTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case kMsgR0EvidenceFilterCompleted:
        if (r0EvidenceFilterTask_ && r0EvidenceFilterTask_->consume(hwnd, wParam, lParam)) {
            return 0;
        }
        break;
    case WM_TIMER:
        if (wParam == kTimerR0EvidenceFilter) {
            ::KillTimer(hwnd, kTimerR0EvidenceFilter);
            if (hasPendingR0EvidenceFilter_) {
                hasPendingR0EvidenceFilter_ = false;
                RequestR0EvidenceRebuild(pendingR0EvidenceFeatureId_);
            }
            return 0;
        }
        break;
    case WM_SETCURSOR:
        if (LOWORD(lParam) == HTCLIENT && CurrentFeatureUsesVerticalSplitter()) {
            POINT cursor{};
            ::GetCursorPos(&cursor);
            ::ScreenToClient(hwnd_, &cursor);
            if (::PtInRect(&verticalSplitterRect_, cursor)) {
                ::SetCursor(::LoadCursorW(nullptr, IDC_SIZENS));
                return TRUE;
            }
        }
        break;
    case WM_LBUTTONDOWN:
    {
        POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
        if (CurrentFeatureUsesVerticalSplitter() && ::PtInRect(&verticalSplitterRect_, point)) {
            verticalSplitterDragging_ = true;
            ::SetCapture(hwnd_);
            ::SetCursor(::LoadCursorW(nullptr, IDC_SIZENS));
            return 0;
        }
        break;
    }
    case WM_MOUSEMOVE:
        if (verticalSplitterDragging_) {
            MoveVerticalSplitterFromMouse(GET_Y_LPARAM(lParam));
            return 0;
        }
        break;
    case WM_LBUTTONUP:
        if (verticalSplitterDragging_) {
            verticalSplitterDragging_ = false;
            if (::GetCapture() == hwnd_) {
                ::ReleaseCapture();
            }
            MoveVerticalSplitterFromMouse(GET_Y_LPARAM(lParam));
            return 0;
        }
        break;
    case WM_CAPTURECHANGED:
        if (reinterpret_cast<HWND>(lParam) != hwnd_) {
            verticalSplitterDragging_ = false;
        }
        break;
    case WM_COMMAND:
        if (LOWORD(wParam) == kIdRefresh && HIWORD(wParam) == BN_CLICKED) {
            RefreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kIdLocate && HIWORD(wParam) == BN_CLICKED) {
            if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor(); descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id)) {
                ExecuteObjectNamespaceToolbarAction();
            } else {
                LocateNextResult();
            }
            return 0;
        }
        if (LOWORD(wParam) == kIdIntegrityFillFromSelection && HIWORD(wParam) == BN_CLICKED) {
            FillIntegrityInputsFromSelection();
            return 0;
        }
        if (LOWORD(wParam) == kIdIntegrityCpuOnly && HIWORD(wParam) == BN_CLICKED) {
            RefreshKernelCpuIntegrityFromDriverPage();
            return 0;
        }
        if ((LOWORD(wParam) == kIdFilterEdit || LOWORD(wParam) == kIdModuleFilterEdit) && HIWORD(wParam) == EN_CHANGE) {
            if (suppressFilterChange_) {
                return 0;
            }
            if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                descriptor != nullptr && IsR0EvidenceFeature(descriptor->id) && !currentRawColumns_.empty()) {
                ScheduleR0EvidenceFilter(descriptor->id);
                return 0;
            }
            if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                descriptor != nullptr &&
                (descriptor->id == KernelFeatureId::SymbolicLink ||
                    descriptor->id == KernelFeatureId::ObjectNamespaceOverview ||
                    descriptor->id == KernelFeatureId::ObjectDirectoryRecursive ||
                    descriptor->id == KernelFeatureId::BaseNamedObjects ||
                    descriptor->id == KernelFeatureId::DeviceDriverObjects ||
                    descriptor->id == KernelFeatureId::ObjectTypeMatrix ||
                    descriptor->id == KernelFeatureId::CommunicationEndpoint ||
                    descriptor->id == KernelFeatureId::AtomTable ||
                    descriptor->id == KernelFeatureId::DynData ||
                    descriptor->id == KernelFeatureId::DriverStatus ||
                    descriptor->id == KernelFeatureId::CallbackEnumeration ||
                    descriptor->id == KernelFeatureId::KernelExecutableMemory ||
                    descriptor->id == KernelFeatureId::KernelMemoryEvidence ||
                    descriptor->id == KernelFeatureId::ProcessCrossView ||
                    descriptor->id == KernelFeatureId::ThreadCrossView ||
                    descriptor->id == KernelFeatureId::DriverIntegrity ||
                    descriptor->id == KernelFeatureId::KernelCpuIntegrity ||
                    descriptor->id == KernelFeatureId::CpuHardwareSnapshot ||
                    descriptor->id == KernelFeatureId::PhysicalMemoryLayout ||
                    descriptor->id == KernelFeatureId::MutationAudit ||
                    descriptor->id == KernelFeatureId::KeyboardHotkeys ||
                    descriptor->id == KernelFeatureId::KeyboardHooks ||
                    descriptor->id == KernelFeatureId::DynDataCapabilities ||
                    descriptor->id == KernelFeatureId::MinifilterBypassPids ||
                    descriptor->id == KernelFeatureId::KernelTimerDpc ||
                    descriptor->id == KernelFeatureId::IoctlRegistry ||
                    IsKernelHookFeature(descriptor->id)) &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                if (IsObjectNamespaceFeature(descriptor->id)) {
                    RebuildObjectNamespaceListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::AtomTable) {
                    RebuildAtomTableFromCache();
                } else if (descriptor->id == KernelFeatureId::DynData ||
                    descriptor->id == KernelFeatureId::DriverStatus) {
                    RebuildDiagnosticDualTableFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::CallbackEnumeration) {
                    RebuildCallbackEnumerationListFromCache();
                } else if (IsKernelHookFeature(descriptor->id)) {
                    RebuildKernelHookListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::KernelExecutableMemory ||
                    descriptor->id == KernelFeatureId::KernelMemoryEvidence) {
                    RebuildKernelMemoryScanListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::ProcessCrossView ||
                    descriptor->id == KernelFeatureId::ThreadCrossView) {
                    RebuildCrossViewListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::DriverIntegrity ||
                    descriptor->id == KernelFeatureId::KernelCpuIntegrity) {
                    RebuildIntegrityEvidenceListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::CpuHardwareSnapshot ||
                    descriptor->id == KernelFeatureId::PhysicalMemoryLayout ||
                    descriptor->id == KernelFeatureId::MutationAudit ||
                    descriptor->id == KernelFeatureId::KeyboardHotkeys ||
                    descriptor->id == KernelFeatureId::KeyboardHooks ||
                    descriptor->id == KernelFeatureId::DynDataCapabilities ||
                    descriptor->id == KernelFeatureId::MinifilterBypassPids ||
                    descriptor->id == KernelFeatureId::KernelTimerDpc ||
                    descriptor->id == KernelFeatureId::IoctlRegistry) {
                    RebuildR0EvidenceListFromCache(descriptor->id);
                } else {
                    RebuildResultListFromCache();
                }
                ConfigureVisibleLayout();
                InvalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if ((LOWORD(wParam) == kIdDeviceDriverDirectoryCombo || LOWORD(wParam) == kIdDeviceDriverTypeCombo) &&
            HIWORD(wParam) == CBN_SELCHANGE) {
            if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                descriptor != nullptr &&
                descriptor->id == KernelFeatureId::DeviceDriverObjects &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                RebuildObjectNamespaceListFromCache(descriptor->id);
                ConfigureVisibleLayout();
                InvalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if ((LOWORD(wParam) == kIdBaseNamedScopeCombo || LOWORD(wParam) == kIdBaseNamedTypeCombo) &&
            HIWORD(wParam) == CBN_SELCHANGE) {
            if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                descriptor != nullptr &&
                descriptor->id == KernelFeatureId::BaseNamedObjects &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                RebuildObjectNamespaceListFromCache(descriptor->id);
                ConfigureVisibleLayout();
                InvalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if ((LOWORD(wParam) == kIdRiskOnlyCheck || LOWORD(wParam) == kIdEvidenceIncludeNonModuleCheck) &&
            HIWORD(wParam) == BN_CLICKED) {
            if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                descriptor != nullptr &&
                !currentRawColumns_.empty()) {
                currentColumns_ = currentRawColumns_;
                currentRows_ = currentRawRows_;
                if (descriptor->id == KernelFeatureId::KernelExecutableMemory ||
                    descriptor->id == KernelFeatureId::KernelMemoryEvidence) {
                    RebuildKernelMemoryScanListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::ProcessCrossView ||
                    descriptor->id == KernelFeatureId::ThreadCrossView) {
                    RebuildCrossViewListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::CallbackIntercept) {
                    PopulateCallbackInterceptPanel();
                } else if (descriptor->id == KernelFeatureId::DriverIntegrity ||
                    descriptor->id == KernelFeatureId::KernelCpuIntegrity) {
                    RebuildIntegrityEvidenceListFromCache(descriptor->id);
                } else if (descriptor->id == KernelFeatureId::CpuHardwareSnapshot ||
                    descriptor->id == KernelFeatureId::PhysicalMemoryLayout ||
                    descriptor->id == KernelFeatureId::MutationAudit ||
                    descriptor->id == KernelFeatureId::KeyboardHotkeys ||
                    descriptor->id == KernelFeatureId::KeyboardHooks ||
                    descriptor->id == KernelFeatureId::DynDataCapabilities ||
                    descriptor->id == KernelFeatureId::MinifilterBypassPids ||
                    descriptor->id == KernelFeatureId::KernelTimerDpc ||
                    descriptor->id == KernelFeatureId::IoctlRegistry) {
                    RebuildR0EvidenceListFromCache(descriptor->id);
                }
                ConfigureVisibleLayout();
                InvalidateCurrentFeatureViewCache();
            }
            return 0;
        }
        if (LOWORD(wParam) == kIdCopyDiagnosticReport && HIWORD(wParam) == BN_CLICKED) {
            if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                descriptor != nullptr && descriptor->id == KernelFeatureId::DeviceDriverObjects) {
                ExportAllRowsTsv();
            } else if (descriptor != nullptr && descriptor->id == KernelFeatureId::SymbolicLink) {
                CopyPreferredSelectedField({ L"targetPath", L"symbolicTarget", L"Target", L"目标路径", L"符号链接目标" }, L"状态：已复制符号链接目标。");
            } else if (descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id)) {
                ExecuteObjectNamespaceDetailAction();
            } else if (descriptor != nullptr && descriptor->id == KernelFeatureId::InlineHook) {
                ExecuteSelectedAction(KernelActionId::InlineHookNopPatch);
            } else {
                CopyDiagnosticReport();
            }
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackReload && HIWORD(wParam) == BN_CLICKED) {
            RefreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackApply && HIWORD(wParam) == BN_CLICKED) {
            ExecuteSelectedAction(KernelActionId::CallbackApplyLocalRules);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackImport && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackImportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackExport && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackExportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackStartReceiver && HIWORD(wParam) == BN_CLICKED) {
            StartCallbackEventReceiver();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackStopReceiver && HIWORD(wParam) == BN_CLICKED) {
            StopCallbackEventReceiver();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackAllowEvent && HIWORD(wParam) == BN_CLICKED) {
            AnswerCurrentCallbackEvent(true);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackDenyEvent && HIWORD(wParam) == BN_CLICKED) {
            AnswerCurrentCallbackEvent(false);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackAddGroup && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackAddGroup();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackRemoveGroup && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackRemoveGroup();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackRenameGroup && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackRenameGroup();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveGroupUp && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackMoveGroup(true);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveGroupDown && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackMoveGroup(false);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackAddRule && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackAddRule();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackRemoveRule && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackRemoveRule();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveRuleUp && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackMoveRule(true);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackMoveRuleDown && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackMoveRule(false);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassAdd && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackBypassAdd();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassRemove && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackBypassRemove();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassApply && HIWORD(wParam) == BN_CLICKED) {
            ::SetWindowTextW(filterEdit_, WindowText(callbackBypassPidEdit_).c_str());
            ExecuteSelectedAction(KernelActionId::MinifilterSetBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassClear && HIWORD(wParam) == BN_CLICKED) {
            ExecuteSelectedAction(KernelActionId::MinifilterClearBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackBypassRefresh && HIWORD(wParam) == BN_CLICKED) {
            RefreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackStartFsctl && HIWORD(wParam) == BN_CLICKED) {
            ExecuteSelectedAction(KernelActionId::FileMonitorStartFsctl);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackDrainFileMonitor && HIWORD(wParam) == BN_CLICKED) {
            ExecuteSelectedAction(KernelActionId::FileMonitorDrain);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackClearFileMonitor && HIWORD(wParam) == BN_CLICKED) {
            ExecuteSelectedAction(KernelActionId::FileMonitorClear);
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackExportFileMonitor && HIWORD(wParam) == BN_CLICKED) {
            OnCallbackExportFileMonitor();
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackGlobalEnabled && HIWORD(wParam) == BN_CLICKED) {
            AppendCallbackAppLog(CallbackRulesGlobalEnabled() ? L"全局启用已打开，下一次应用规则时生效。" : L"全局启用已关闭，下一次应用规则时生效。");
            return 0;
        }
        if (LOWORD(wParam) == kIdCallbackFileMonitorFsctlOnly && HIWORD(wParam) == BN_CLICKED) {
            AppendCallbackAppLog(Button_GetCheck(callbackFileMonitorFsctlOnlyCheck_) == BST_CHECKED
                ? L"文件监控过滤：仅显示 Oplock / FSCTL。"
                : L"文件监控过滤：显示全部当前事件。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuRefreshCurrentFeature) {
            RefreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyCell) {
            CopySelectedCell();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyRow) {
            CopySelectedRow();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySelectedRows) {
            CopySelectedRows(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySelectedRowsWithHeader) {
            CopySelectedRows(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySelectedDetails) {
            CopySelectedDetails();
            return 0;
        }
        if (LOWORD(wParam) >= kMenuCallbackCopyColumnBase && LOWORD(wParam) <= kMenuCallbackCopyColumnMax) {
            const std::vector<int> copyColumns = CurrentCopyColumnIndices();
            const int index = static_cast<int>(LOWORD(wParam) - kMenuCallbackCopyColumnBase);
            if (index >= 0 && index < static_cast<int>(copyColumns.size())) {
                CopySelectedColumn(copyColumns[static_cast<std::size_t>(index)]);
            }
            return 0;
        }
        if (LOWORD(wParam) >= kMenuCopyColumnBase && LOWORD(wParam) <= kMenuCopyColumnMax) {
            CopySelectedColumn(static_cast<int>(LOWORD(wParam) - kMenuCopyColumnBase));
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAll) {
            CopyAllRows();
            return 0;
        }
        if (LOWORD(wParam) == kMenuExportAllTsv) {
            ExportAllRowsTsv();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyDiagnosticReport) {
            CopyDiagnosticReport();
            return 0;
        }
        if (LOWORD(wParam) == kMenuRefreshSelectedDetail) {
            UpdateSelectedRowDetail();
            ::SetWindowTextW(statusText_, L"状态：已刷新详情面板。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuInlineNopPatch) {
            ExecuteSelectedAction(KernelActionId::InlineHookNopPatch);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackCancelPendingDecisions) {
            ExecuteSelectedAction(KernelActionId::CallbackCancelPendingDecisions);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackApplyDisabledEmptyRules) {
            ExecuteSelectedAction(KernelActionId::CallbackApplyDisabledEmptyRules);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackSafeRemove) {
            ExecuteSelectedAction(KernelActionId::CallbackSafeRemove);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackExperimentalUnlink) {
            ExecuteSelectedAction(KernelActionId::CallbackExperimentalUnlink);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackOpenModuleFolder) {
            OpenSelectedCallbackModuleFolder();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackModuleFileDetail) {
            ShowSelectedCallbackModuleFileDetail();
            return 0;
        }
        if (LOWORD(wParam) == kMenuNetworkCaptureStart) {
            ExecuteSelectedAction(KernelActionId::NetworkCaptureStart);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNetworkCaptureStop) {
            ExecuteSelectedAction(KernelActionId::NetworkCaptureStop);
            return 0;
        }
        if (LOWORD(wParam) == kMenuPiDdbDeleteEntry) {
            ExecuteSelectedAction(KernelActionId::PiDdbDeleteEntry);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverDispatchRestore) {
            ExecuteSelectedAction(KernelActionId::DriverDispatchRestore);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverDispatchAbandon) {
            ExecuteSelectedAction(KernelActionId::DriverDispatchAbandon);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverImageRestore) {
            ExecuteSelectedAction(KernelActionId::DriverImageRestore);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverImageAbandon) {
            ExecuteSelectedAction(KernelActionId::DriverImageAbandon);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverCommunicationRestore) {
            ExecuteSelectedAction(KernelActionId::DriverCommunicationRestore);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMinifilterSetBypass) {
            ExecuteSelectedAction(KernelActionId::MinifilterSetBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMinifilterClearBypass) {
            ExecuteSelectedAction(KernelActionId::MinifilterClearBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverObjectQueryDetail) {
            ExecuteSelectedAction(KernelActionId::DriverObjectQueryDetail);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDriverObjectForceUnload) {
            ExecuteSelectedAction(KernelActionId::DriverObjectForceUnload);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNativeObjectQueryDetail) {
            ExecuteSelectedAction(KernelActionId::NativeObjectQueryDetail);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNativeSymbolicLinkResolve) {
            ExecuteSelectedAction(KernelActionId::NativeSymbolicLinkResolve);
            return 0;
        }
        if (LOWORD(wParam) == kMenuNativeNamedPipeProbe) {
            ExecuteSelectedAction(KernelActionId::NativeNamedPipeProbe);
            return 0;
        }
        if (LOWORD(wParam) == kMenuDynDataApplyMatchedProfile) {
            ExecuteSelectedAction(KernelActionId::DynDataApplyMatchedProfile);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMutationCommitDryRun) {
            ExecuteSelectedAction(KernelActionId::MutationCommitDryRun);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMutationRollbackDryRun) {
            ExecuteSelectedAction(KernelActionId::MutationRollbackDryRun);
            return 0;
        }
        if (LOWORD(wParam) == kMenuMutationRollbackConfirmed) {
            ExecuteSelectedAction(KernelActionId::MutationRollbackConfirmed);
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByModule) {
            ApplySelectedModuleFilter(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByTargetModule) {
            ApplySelectedModuleFilter(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByAddress) {
            ApplySelectedAddressFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByPath) {
            ApplySelectedPathFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByOwner) {
            ApplySelectedOwnerFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByRisk) {
            ApplySelectedRiskFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByPidTid) {
            ApplySelectedPidTidFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByCapability) {
            ApplySelectedCapabilityFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuObjectFilterByRoot) {
            const std::wstring value = FirstSelectedRowField({
                L"RootPath", L"rootPath", L"Source", L"Parent", L"Directory",
                L"directoryPath", L"sourceDirectory", L"Path", L"fullPath", L"目录路径", L"来源目录", L"完整路径"
            });
            if (!value.empty()) {
                ::SetWindowTextW(filterEdit_, value.c_str());
                ::SetWindowTextW(statusText_, L"状态：已按目录路径过滤。");
                if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                    descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id)) {
                    RebuildObjectNamespaceListFromCache(descriptor->id);
                }
            }
            return 0;
        }
        if (LOWORD(wParam) == kMenuObjectFilterByDirectory) {
            const std::wstring value = FirstSelectedRowField({
                L"directoryPath", L"Parent", L"Directory", L"sourceDirectory", L"Source", L"目录路径", L"来源目录"
            });
            if (!value.empty()) {
                ::SetWindowTextW(filterEdit_, value.c_str());
                ::SetWindowTextW(statusText_, L"状态：已按当前目录过滤。");
                if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
                    descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id)) {
                    RebuildObjectNamespaceListFromCache(descriptor->id);
                }
            }
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByType) {
            ApplySelectedTypeFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByName) {
            ApplySelectedNameFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuFilterByTarget) {
            ApplySelectedTargetFilter();
            return 0;
        }
        if (LOWORD(wParam) == kMenuAtomVerify) {
            VerifySelectedAtom();
            return 0;
        }
        if (LOWORD(wParam) == kMenuAtomCopySnippet) {
            CopySelectedAtomSnippet();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySameDirectory) {
            CopyRowsWithSameDirectory();
            return 0;
        }
        if (LOWORD(wParam) == kMenuMapDosPath) {
            MapSelectedNtPathAsDosPaths();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyObjectName) {
            CopyPreferredSelectedField({ L"objectName", L"Name", L"名称", L"对象名称", L"linkName", L"Pipe", L"Pipe Name" }, L"状态：已复制对象名。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyObjectType) {
            CopyPreferredSelectedField({ L"objectType", L"Type", L"对象类型", L"类型" }, L"状态：已复制对象类型。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyFullPath) {
            CopyPreferredSelectedField({ L"fullPath", L"Path", L"完整路径", L"NtPath", L"NT Path" }, L"状态：已复制完整路径。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopySymbolicTarget) {
            CopyPreferredSelectedField({ L"symbolicTarget", L"targetPath", L"Target", L"目标路径", L"符号链接目标" }, L"状态：已复制符号链接目标。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyObjectEnumSource) {
            CopyPreferredSelectedField({ L"EnumApi", L"enumApi", L"枚举 API", L"EnumerationApi" }, L"状态：已复制枚举 API。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyDosCandidate) {
            CopyPreferredSelectedField({ L"dosCandidate", L"Win32Path", L"DosCandidates" }, L"状态：已复制 dosCandidate。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomValue) {
            CopyPreferredSelectedField({ L"Atom值", L"Id" }, L"状态：已复制 Atom 值。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomHex) {
            CopyPreferredSelectedField({ L"十六进制", L"Id" }, L"状态：已复制 Atom 十六进制。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomName) {
            CopyPreferredSelectedField({ L"名称", L"Name" }, L"状态：已复制 Atom 名称。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuCopyAtomSource) {
            CopyPreferredSelectedField({ L"来源", L"Source" }, L"状态：已复制 Atom 来源。");
            return 0;
        }
        if (LOWORD(wParam) == kMenuShowRowDialog) {
            ShowSelectedRowDialog();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupAdd) {
            OnCallbackAddGroup();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupRemove) {
            OnCallbackRemoveGroup();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupRename) {
            OnCallbackRenameGroup();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupMoveUp) {
            OnCallbackMoveGroup(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupMoveDown) {
            OnCallbackMoveGroup(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackGroupToggleEnabled) {
            OnCallbackToggleGroupEnabled();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleAdd) {
            OnCallbackAddRule();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleRemove) {
            OnCallbackRemoveRule();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleMoveUp) {
            OnCallbackMoveRule(true);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleMoveDown) {
            OnCallbackMoveRule(false);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleToggleEnabled) {
            OnCallbackToggleRuleEnabled();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRuleCopyText) {
            OnCallbackCopyRuleText();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackRulePasteNew) {
            OnCallbackPasteRuleText();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassAdd) {
            OnCallbackBypassAdd();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassRemove) {
            OnCallbackBypassRemove();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassApply) {
            ::SetWindowTextW(filterEdit_, WindowText(callbackBypassPidEdit_).c_str());
            ExecuteSelectedAction(KernelActionId::MinifilterSetBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassClear) {
            ExecuteSelectedAction(KernelActionId::MinifilterClearBypassPids);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackBypassRefresh) {
            RefreshSelectedFeature();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorStart) {
            ExecuteSelectedAction(KernelActionId::FileMonitorStartFsctl);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorDrain) {
            ExecuteSelectedAction(KernelActionId::FileMonitorDrain);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorClear) {
            ExecuteSelectedAction(KernelActionId::FileMonitorClear);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorExport) {
            OnCallbackExportFileMonitor();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorOpenProcess) {
            OpenCallbackFileMonitorProcess();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackFileMonitorOpenPath) {
            OpenCallbackFileMonitorPath();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackCopyPanelSelection) {
            const HWND focus = ::GetFocus();
            CopyCallbackPanelSelection(focus);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackImportConfig) {
            OnCallbackImportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackExportConfig) {
            OnCallbackExportConfig();
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackApplyLocalRules) {
            ExecuteSelectedAction(KernelActionId::CallbackApplyLocalRules);
            return 0;
        }
        if (LOWORD(wParam) == kMenuCallbackReloadRuntime) {
            RefreshSelectedFeature();
            return 0;
        }
        break;
    case WM_CONTEXTMENU:
        if (reinterpret_cast<HWND>(wParam) == callbackGroupList_ ||
            reinterpret_cast<HWND>(wParam) == callbackBypassList_ ||
            reinterpret_cast<HWND>(wParam) == callbackFileMonitorList_ ||
            std::find(callbackRuleLists_.begin(), callbackRuleLists_.end(), reinterpret_cast<HWND>(wParam)) != callbackRuleLists_.end()) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            ShowCallbackInterceptContextMenu(reinterpret_cast<HWND>(wParam), point);
            return 0;
        }
        if (reinterpret_cast<HWND>(wParam) == objectNamespaceTree_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            if (point.x == -1 && point.y == -1) {
                const HTREEITEM selectedItem = TreeView_GetSelection(objectNamespaceTree_);
                RECT itemRect{};
                if (selectedItem != nullptr && TreeView_GetItemRect(objectNamespaceTree_, selectedItem, &itemRect, TRUE)) {
                    point.x = itemRect.left;
                    point.y = itemRect.bottom;
                    ::ClientToScreen(objectNamespaceTree_, &point);
                }
            } else {
                POINT clientPoint = point;
                ::ScreenToClient(objectNamespaceTree_, &clientPoint);
                TVHITTESTINFO hit{};
                hit.pt = clientPoint;
                const HTREEITEM item = TreeView_HitTest(objectNamespaceTree_, &hit);
                if (item != nullptr) {
                    TreeView_SelectItem(objectNamespaceTree_, item);
                }
            }
            ShowResultContextMenu(point);
            return 0;
        }
        if (reinterpret_cast<HWND>(wParam) == resultList_) {
            POINT point{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
            contextColumn_ = -1;
            if (point.x != -1 || point.y != -1) {
                POINT clientPoint = point;
                ::ScreenToClient(resultList_, &clientPoint);
                LVHITTESTINFO hit{};
                hit.pt = clientPoint;
                const int row = ListView_HitTest(resultList_, &hit);
                contextColumn_ = hit.iSubItem >= 0 ? hit.iSubItem : 0;
                if (row >= 0) {
                    const UINT state = ListView_GetItemState(resultList_, row, LVIS_SELECTED);
                    if ((state & LVIS_SELECTED) == 0) {
                        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
                    }
                    ListView_SetItemState(resultList_, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    ListView_EnsureVisible(resultList_, row, FALSE);
                    UpdateSelectedRowDetail();
                }
            } else {
                const int selected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
                contextColumn_ = HeaderColumnCount(resultList_) > 1 ? 1 : 0;
                if (selected >= 0) {
                    ListView_SetItemState(resultList_, selected, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
                    ListView_EnsureVisible(resultList_, selected, FALSE);
                }
            }
            ShowResultContextMenu(point);
            return 0;
        }
        break;
    case WM_NOTIFY:
        if (const auto* header = reinterpret_cast<const NMHDR*>(lParam)) {
            if (header->hwndFrom == primaryTab_ && header->code == TCN_SELCHANGE) {
                Ksword::Ui::ScopedWindowRedrawLock pageRedrawLock(hwnd_);
                ParkCurrentFeatureViewCache();
                hasDirectFeatureId_ = false;
                RebuildSecondLevelTabs();
                SelectCurrentFeature();
                return 0;
            }
            if (header->hwndFrom == secondaryTab_ && header->code == TCN_SELCHANGE) {
                Ksword::Ui::ScopedWindowRedrawLock pageRedrawLock(hwnd_);
                ParkCurrentFeatureViewCache();
                hasDirectFeatureId_ = false;
                SelectCurrentFeature();
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == NM_CUSTOMDRAW) {
                return HandleResultListCustomDraw(lParam);
            }
            if (header->hwndFrom == resultList_ && header->code == LVN_GETDISPINFOW) {
                auto* info = reinterpret_cast<NMLVDISPINFOW*>(lParam);
                if (info && (info->item.mask & LVIF_TEXT) != 0 && info->item.pszText && info->item.cchTextMax > 0) {
                    const std::wstring text = ResultCellText(info->item.iItem, info->item.iSubItem);
                    ::wcsncpy_s(info->item.pszText, static_cast<std::size_t>(info->item.cchTextMax), text.c_str(), _TRUNCATE);
                }
                if (info && (info->item.mask & LVIF_INDENT) != 0) {
                    const int row = info->item.iItem;
                    info->item.iIndent = row >= 0 && row < static_cast<int>(currentRowIndents_.size())
                        ? std::max(0, std::min(currentRowIndents_[static_cast<std::size_t>(row)], 32))
                        : 0;
                }
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == LVN_COLUMNCLICK) {
                const auto* click = reinterpret_cast<const NMLISTVIEW*>(lParam);
                SortResultRowsByColumn(click->iSubItem);
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == NM_DBLCLK) {
                const auto* activate = reinterpret_cast<const NMITEMACTIVATE*>(lParam);
                ToggleObjectNamespaceListNode(activate->iItem);
                return 0;
            }
            if (header->hwndFrom == resultList_ && header->code == LVN_ITEMCHANGED) {
                const auto* item = reinterpret_cast<const NMLISTVIEW*>(lParam);
                if ((item->uChanged & LVIF_STATE) != 0 &&
                    ((item->uNewState ^ item->uOldState) & LVIS_SELECTED) != 0) {
                    UpdateSelectedRowDetail();
                }
                return 0;
            }
            if (header->hwndFrom == objectNamespaceTree_ && header->code == TVN_SELCHANGEDW) {
                const auto* changed = reinterpret_cast<const NMTREEVIEWW*>(lParam);
                SelectObjectNamespaceTreeItem(changed->itemNew.lParam);
                return 0;
            }
            if ((header->hwndFrom == callbackRuleTab_ || header->hwndFrom == callbackLogTab_) && header->code == TCN_SELCHANGE) {
                Layout();
                return 0;
            }
        }
        break;
    case WM_CTLCOLORSTATIC:
        ::SetBkMode(reinterpret_cast<HDC>(wParam), TRANSPARENT);
        return reinterpret_cast<LRESULT>(::GetSysColorBrush(COLOR_WINDOW));
    case WM_PAINT:
    {
        PAINTSTRUCT paint{};
        HDC dc = ::BeginPaint(hwnd, &paint);
        if (Width(verticalSplitterRect_) > 0 && Height(verticalSplitterRect_) > 0) {
            ::FillRect(dc, &verticalSplitterRect_, ::GetSysColorBrush(COLOR_BTNFACE));
            RECT line = verticalSplitterRect_;
            const int centerY = line.top + Height(line) / 2;
            line.top = centerY;
            line.bottom = centerY + 1;
            ::FillRect(dc, &line, ::GetSysColorBrush(COLOR_3DSHADOW));
        }
        ::EndPaint(hwnd, &paint);
        return 0;
    }
    case WM_NCDESTROY:
        ::KillTimer(hwnd, kTimerR0EvidenceFilter);
        if (callbackEventReceiver_) {
            callbackEventReceiver_->Shutdown();
        }
        if (queryTask_) {
            queryTask_->cancel();
        }
        if (actionTask_) {
            actionTask_->cancel();
        }
        if (callbackAnswerTask_) {
            callbackAnswerTask_->cancel();
        }
        if (callbackFileIoTask_) {
            callbackFileIoTask_->cancel();
        }
        if (r0EvidenceFilterTask_) {
            r0EvidenceFilterTask_->cancel();
        }
        ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
        hwnd_ = nullptr;
        delete this;
        return 0;
    default:
        break;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

void KernelPage::CreateChildControls() {
    // UI owns only Win32 controls. All kernel data requests continue through
    // KernelFacade, so driver/protocol access stays out of this view layer.
    primaryTab_ = ::CreateWindowExW(0,
        WC_TABCONTROLW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdPrimaryTab)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    secondaryTab_ = ::CreateWindowExW(0,
        WC_TABCONTROLW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdSecondaryTab)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    titleText_ = Ksword::Ui::CreateText(hwnd_, 0, L"内核", 0, 0, 0, 0);
    summaryText_ = Ksword::Ui::CreateText(hwnd_, 0, L"", 0, 0, 0, 0);
    backendText_ = Ksword::Ui::CreateText(hwnd_, 0, L"", 0, 0, 0, 0);
    statusText_ = Ksword::Ui::CreateText(hwnd_, 0, L"选择一个二级页后点击刷新/查询。", 0, 0, 0, 0);
    filterLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"过滤/起点", 0, 0, 0, 0);
    filterEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdFilterEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (filterEdit_) {
        ::SetWindowSubclass(filterEdit_, KernelPage::FilterEditSubclassProc, kFilterEditSubclassId, reinterpret_cast<DWORD_PTR>(this));
    }
    moduleFilterLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"模块过滤", 0, 0, 0, 0);
    moduleFilterEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdModuleFilterEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    symbolicLinkNoteText_ = Ksword::Ui::CreateText(hwnd_,
        0,
        L"说明：SymbolicLink 本身不是可递归容器，本页只解析目标；若目标指向 Directory，后续由目录递归 tab 处理。",
        0,
        0,
        0,
        0);
    deviceDriverDirectoryLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"目录：", 0, 0, 0, 0);
    deviceDriverDirectoryCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdDeviceDriverDirectoryCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    deviceDriverTypeLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"类型：", 0, 0, 0, 0);
    deviceDriverTypeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdDeviceDriverTypeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    baseNamedScopeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdBaseNamedScopeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    baseNamedTypeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdBaseNamedTypeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    integrityModuleBaseLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"模块基址", 0, 0, 0, 0);
    integrityModuleBaseEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIntegrityModuleBaseEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    integrityFillFromSelectionButton_ = Ksword::Ui::CreateButton(hwnd_, kIdIntegrityFillFromSelection, L"填充", 0, 0, 0, 0);
    integrityCpuOnlyButton_ = Ksword::Ui::CreateButton(hwnd_, kIdIntegrityCpuOnly, L"CPU", 0, 0, 0, 0);
    includeCombo_ = ::CreateWindowExW(0,
        WC_COMBOBOXW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | CBS_DROPDOWNLIST | CBS_HASSTRINGS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIncludeCombo)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    refreshButton_ = Ksword::Ui::CreateButton(hwnd_, kIdRefresh, L"刷新/查询", 0, 0, 0, 0);
    locateButton_ = Ksword::Ui::CreateButton(hwnd_, kIdLocate, L"定位", 0, 0, 0, 0);
    copyDiagnosticButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCopyDiagnosticReport, L"复制诊断", 0, 0, 0, 0);
    objectNamespaceTree_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_TREEVIEWW,
        L"",
        WS_CHILD | WS_TABSTOP | TVS_HASBUTTONS | TVS_HASLINES | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    resultList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdResultList)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (resultList_) {
        ListView_SetExtendedListViewStyleEx(resultList_,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
    }
    propertyList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (propertyList_) {
        ListView_SetExtendedListViewStyleEx(propertyList_,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
        LVCOLUMNW nameColumn{};
        nameColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        nameColumn.fmt = LVCFMT_LEFT;
        nameColumn.cx = 180;
        nameColumn.pszText = const_cast<LPWSTR>(L"属性项");
        ListView_InsertColumn(propertyList_, 0, &nameColumn);
        LVCOLUMNW valueColumn{};
        valueColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        valueColumn.fmt = LVCFMT_LEFT;
        valueColumn.cx = 320;
        valueColumn.pszText = const_cast<LPWSTR>(L"值");
        ListView_InsertColumn(propertyList_, 1, &valueColumn);
    }
    summaryList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_LISTVIEWW,
        L"",
        WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    if (summaryList_) {
        ListView_SetExtendedListViewStyleEx(summaryList_,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_LABELTIP | LVS_EX_GRIDLINES);
        LVCOLUMNW nameColumn{};
        nameColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        nameColumn.fmt = LVCFMT_LEFT;
        nameColumn.cx = 220;
        nameColumn.pszText = const_cast<LPWSTR>(L"项目");
        ListView_InsertColumn(summaryList_, 0, &nameColumn);
        LVCOLUMNW valueColumn{};
        valueColumn.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
        valueColumn.fmt = LVCFMT_LEFT;
        valueColumn.cx = 520;
        valueColumn.pszText = const_cast<LPWSTR>(L"值");
        ListView_InsertColumn(summaryList_, 1, &valueColumn);
    }
    detailEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        nullptr,
        ::GetModuleHandleW(nullptr),
        nullptr);
    // The selected-row detail pane is where a single kernel object expands into
    // dozens of lines, which is exactly where scanning by eye stops working.
    Ksword::Ui::AttachTextFindSupport(detailEdit_);
    riskOnlyCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"仅风险项",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdRiskOnlyCheck)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
    evidenceIncludeNonModuleCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"包含非模块执行范围",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceIncludeNonModuleCheck)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceStartEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceStartEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceEndEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceEndEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceMaxRowsLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"行数:", 0, 0, 0, 0);
    evidenceMaxRowsEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"256",
        WS_CHILD | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceMaxRowsEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    evidenceMaxRowsSpin_ = ::CreateWindowExW(0,
        UPDOWN_CLASSW,
        L"",
        WS_CHILD | UDS_SETBUDDYINT | UDS_ALIGNRIGHT | UDS_ARROWKEYS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdEvidenceMaxRowsSpin)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ::SendMessageW(evidenceMaxRowsSpin_, UDM_SETBUDDY, reinterpret_cast<WPARAM>(evidenceMaxRowsEdit_), 0);
    ::SendMessageW(evidenceMaxRowsSpin_, UDM_SETRANGE32, 16, 4096);
    integrityIdtVectorsLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"IDT/CPU:", 0, 0, 0, 0);
    integrityIdtVectorsEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE,
        WC_EDITW,
        L"64",
        WS_CHILD | WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIntegrityIdtVectorsEdit)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    integrityIdtVectorsSpin_ = ::CreateWindowExW(0,
        UPDOWN_CLASSW,
        L"",
        WS_CHILD | UDS_SETBUDDYINT | UDS_ALIGNRIGHT | UDS_ARROWKEYS,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdIntegrityIdtVectorsSpin)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    ::SendMessageW(integrityIdtVectorsSpin_, UDM_SETBUDDY, reinterpret_cast<WPARAM>(integrityIdtVectorsEdit_), 0);
    ::SendMessageW(integrityIdtVectorsSpin_, UDM_SETRANGE32, 0, 256);
    callbackGlobalEnabledCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"全局启用",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackGlobalEnabled)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    Button_SetCheck(callbackGlobalEnabledCheck_, BST_CHECKED);
    callbackApplyButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackApply, L"应用", 0, 0, 0, 0);
    callbackReloadButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackReload, L"重新加载驱动状态", 0, 0, 0, 0);
    callbackImportButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackImport, L"导入配置", 0, 0, 0, 0);
    callbackExportButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackExport, L"导出配置", 0, 0, 0, 0);
    callbackStartReceiverButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackStartReceiver, L"接收待决策", 0, 0, 0, 0);
    callbackStopReceiverButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackStopReceiver, L"停止接收", 0, 0, 0, 0);
    callbackAllowEventButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackAllowEvent, L"允许当前", 0, 0, 0, 0);
    callbackDenyEventButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackDenyEvent, L"拒绝当前", 0, 0, 0, 0);
    callbackStatusText_ = Ksword::Ui::CreateText(hwnd_, 0, L"状态：等待刷新", 0, 0, 0, 0);
    callbackGroupLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"规则组", 0, 0, 0, 0);
    callbackAddGroupButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackAddGroup, L"新增组", 0, 0, 0, 0);
    callbackRemoveGroupButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackRemoveGroup, L"删除组", 0, 0, 0, 0);
    callbackRenameGroupButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackRenameGroup, L"重命名", 0, 0, 0, 0);
    callbackMoveGroupUpButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackMoveGroupUp, L"上移", 0, 0, 0, 0);
    callbackMoveGroupDownButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackMoveGroupDown, L"下移", 0, 0, 0, 0);
    callbackGroupList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_TABSTOP | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    ConfigureReportList(callbackGroupList_);
    AddListColumn(callbackGroupList_, 0, L"groupId", 58);
    AddListColumn(callbackGroupList_, 1, L"组名称", 150);
    AddListColumn(callbackGroupList_, 2, L"启用", 60);
    AddListColumn(callbackGroupList_, 3, L"优先级", 70);
    AddListColumn(callbackGroupList_, 4, L"备注", 220);

    callbackRuleLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"规则", 0, 0, 0, 0);
    callbackAddRuleButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackAddRule, L"新增规则", 0, 0, 0, 0);
    callbackRemoveRuleButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackRemoveRule, L"删除规则", 0, 0, 0, 0);
    callbackMoveRuleUpButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackMoveRuleUp, L"规则上移", 0, 0, 0, 0);
    callbackMoveRuleDownButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackMoveRuleDown, L"规则下移", 0, 0, 0, 0);
    callbackRuleTab_ = ::CreateWindowExW(0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackRuleTab)), ::GetModuleHandleW(nullptr), nullptr);
    const wchar_t* ruleTabTitles[] = { L"注册表", L"进程创建", L"线程创建", L"镜像加载", L"对象管理器", L"文件系统微过滤器", L"Minifilter PID 放行" };
    constexpr int ruleTabCount = static_cast<int>(sizeof(ruleTabTitles) / sizeof(ruleTabTitles[0]));
    for (int index = 0; index < ruleTabCount; ++index) {
        SetTabText(callbackRuleTab_, index, ruleTabTitles[index]);
        HWND ruleList = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
        ConfigureReportList(ruleList);
        AddListColumn(ruleList, 0, L"启用", 42);
        AddListColumn(ruleList, 1, L"RuleID", 58);
        AddListColumn(ruleList, 2, L"GroupID", 96);
        AddListColumn(ruleList, 3, L"规则名称", 170);
        AddListColumn(ruleList, 4, L"操作类型", 480);
        AddListColumn(ruleList, 5, L"匹配模式", 104);
        AddListColumn(ruleList, 6, L"动作", 104);
        AddListColumn(ruleList, 7, L"超时毫秒", 72);
        AddListColumn(ruleList, 8, L"超时决策", 78);
        AddListColumn(ruleList, 9, L"优先级", 58);
        callbackRuleLists_.push_back(ruleList);
    }
    ::SendMessageW(callbackRuleTab_, TCM_SETCURSEL, 0, 0);

    callbackBypassLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"Minifilter PID 放行", 0, 0, 0, 0);
    callbackBypassPidEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
        WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    callbackBypassAddButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackBypassAdd, L"添加", 0, 0, 0, 0);
    callbackBypassRemoveButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackBypassRemove, L"移除选中", 0, 0, 0, 0);
    callbackBypassApplyButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackBypassApply, L"应用到驱动", 0, 0, 0, 0);
    callbackBypassClearButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackBypassClear, L"清空并应用", 0, 0, 0, 0);
    callbackBypassRefreshButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackBypassRefresh, L"从驱动刷新", 0, 0, 0, 0);
    callbackBypassList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    ConfigureReportList(callbackBypassList_);
    AddListColumn(callbackBypassList_, 0, L"PID", 80);
    AddListColumn(callbackBypassList_, 1, L"进程", 200);
    callbackBypassStatusText_ = Ksword::Ui::CreateText(hwnd_, 0, L"尚未从驱动刷新；编辑后点击“应用到驱动”生效。", 0, 0, 0, 0);

    callbackLogTab_ = ::CreateWindowExW(0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_CLIPSIBLINGS, 0, 0, 0, 0, hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackLogTab)), ::GetModuleHandleW(nullptr), nullptr);
    SetTabText(callbackLogTab_, 0, L"应用日志");
    SetTabText(callbackLogTab_, 1, L"事件日志");
    ::SendMessageW(callbackLogTab_, TCM_SETCURSEL, 0, 0);
    callbackAppLogEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
        WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    callbackEventLogEdit_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_EDITW, L"",
        WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    // Both callback logs grow without bound while the driver is running, so
    // finding one event in them is a search problem, not a scrolling one.
    Ksword::Ui::AttachTextFindSupport(callbackAppLogEdit_);
    Ksword::Ui::AttachTextFindSupport(callbackEventLogEdit_);

    callbackFileMonitorLabel_ = Ksword::Ui::CreateText(hwnd_, 0, L"文件系统事件", 0, 0, 0, 0);
    callbackStartFsctlButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackStartFsctl, L"启动 FSCTL 监控", 0, 0, 0, 0);
    callbackDrainFileMonitorButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackDrainFileMonitor, L"拉取事件", 0, 0, 0, 0);
    callbackClearFileMonitorButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackClearFileMonitor, L"清空", 0, 0, 0, 0);
    callbackExportFileMonitorButton_ = Ksword::Ui::CreateButton(hwnd_, kIdCallbackExportFileMonitor, L"导出", 0, 0, 0, 0);
    callbackFileMonitorFsctlOnlyCheck_ = ::CreateWindowExW(0,
        WC_BUTTONW,
        L"仅显示 Oplock / FSCTL",
        WS_CHILD | BS_AUTOCHECKBOX | WS_TABSTOP,
        0,
        0,
        0,
        0,
        hwnd_,
        reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdCallbackFileMonitorFsctlOnly)),
        ::GetModuleHandleW(nullptr),
        nullptr);
    Button_SetCheck(callbackFileMonitorFsctlOnlyCheck_, BST_CHECKED);
    callbackFileMonitorStatusText_ = Ksword::Ui::CreateText(hwnd_, 0, L"等待启动或读取事件", 0, 0, 0, 0);
    callbackFileMonitorList_ = ::CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, 0, 0, 0, 0, hwnd_, nullptr, ::GetModuleHandleW(nullptr), nullptr);
    ConfigureReportList(callbackFileMonitorList_);
    AddListColumn(callbackFileMonitorList_, 0, L"时间", 140);
    AddListColumn(callbackFileMonitorList_, 1, L"PID", 70);
    AddListColumn(callbackFileMonitorList_, 2, L"进程", 120);
    AddListColumn(callbackFileMonitorList_, 3, L"文件路径", 260);
    AddListColumn(callbackFileMonitorList_, 4, L"FSCTL 名称", 130);
    AddListColumn(callbackFileMonitorList_, 5, L"控制码", 100);
    AddListColumn(callbackFileMonitorList_, 6, L"状态码", 90);
    AddListColumn(callbackFileMonitorList_, 7, L"FileObject", 150);
    AddListColumn(callbackFileMonitorList_, 8, L"In", 90);
    AddListColumn(callbackFileMonitorList_, 9, L"Out", 95);
    AddListColumn(callbackFileMonitorList_, kCallbackFileMonitorPathStateColumn, L"路径状态", 90);
    Ksword::Ui::SetWindowFontRecursive(hwnd_);
}

void KernelPage::Layout() {
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int width = Width(rc);
    const int height = Height(rc);
    const RECT oldSplitterRect = verticalSplitterRect_;
    verticalSplitterRect_ = {};
    const int tabHeight = 28;
    const bool showPrimary = !hasDirectFeatureId_;
    const bool showSecondary = CurrentPrimaryUsesSecondaryTabs();
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    const bool showPropertyTable = descriptor != nullptr &&
        LayoutKindForFeature(descriptor->id) == KernelPageLayoutKind::TreeWithPropertyTable;
    const bool showSummaryTable = descriptor != nullptr &&
        LayoutKindForFeature(descriptor->id) == KernelPageLayoutKind::DualTable;
    const bool showRuntimePanel = descriptor != nullptr &&
        LayoutKindForFeature(descriptor->id) == KernelPageLayoutKind::RuntimePanel;
    const bool showCallbackPanel = descriptor != nullptr &&
        descriptor->id == KernelFeatureId::CallbackIntercept;
    const bool showTableDetail = descriptor != nullptr &&
        LayoutKindForFeature(descriptor->id) == KernelPageLayoutKind::TableWithDetail;
    const bool showObjectNamespacePanel = descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id);
    const bool showAtomPanel = descriptor != nullptr && descriptor->id == KernelFeatureId::AtomTable;
    const bool showNtQueryPanel = descriptor != nullptr && descriptor->id == KernelFeatureId::NtQueryLegacy;
    const bool showKernelHookPanel = descriptor != nullptr && IsKernelHookFeature(descriptor->id);
    const bool showIncludeCombo = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::InlineHook || descriptor->id == KernelFeatureId::IatEatHook);
    const int secondaryHeight = showSecondary ? tabHeight : 0;
    const bool showDiagnosticDualPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DynData || descriptor->id == KernelFeatureId::DriverStatus);
    const bool showCallbackEnumerationPanel = descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackEnumeration;
    const bool showKernelMemoryScanPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::KernelExecutableMemory ||
            descriptor->id == KernelFeatureId::KernelMemoryEvidence);
    const bool showCrossViewPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::ProcessCrossView ||
            descriptor->id == KernelFeatureId::ThreadCrossView);
    const bool showIntegrityPanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DriverIntegrity ||
            descriptor->id == KernelFeatureId::KernelCpuIntegrity);
    const bool showR0EvidencePanel = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::CpuHardwareSnapshot ||
            descriptor->id == KernelFeatureId::PhysicalMemoryLayout ||
            descriptor->id == KernelFeatureId::MutationAudit ||
            descriptor->id == KernelFeatureId::KeyboardHotkeys ||
             descriptor->id == KernelFeatureId::KeyboardHooks ||
             descriptor->id == KernelFeatureId::DynDataCapabilities ||
             descriptor->id == KernelFeatureId::MinifilterBypassPids ||
             descriptor->id == KernelFeatureId::KernelTimerDpc ||
             descriptor->id == KernelFeatureId::IoctlRegistry);
    const int infoHeight = (showObjectNamespacePanel || showAtomPanel || showNtQueryPanel || showKernelHookPanel || showDiagnosticDualPanel ||
        showCallbackEnumerationPanel || showKernelMemoryScanPanel || showCrossViewPanel || showIntegrityPanel || showR0EvidencePanel) ? 28 : 96;
    const int buttonWidth = 92;
    const int buttonHeight = 24;
    const int statusHeight = 20;
    const bool showCopyDiagnostic = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DynData || descriptor->id == KernelFeatureId::DriverStatus);
    const int copyWidth = showCopyDiagnostic ? 82 : 0;
    const int detailHeight = showKernelHookPanel
        ? std::max(130, (std::max(0, height - (tabHeight + secondaryHeight + infoHeight + statusHeight)) * 2) / 5)
        : showTableDetail
        ? std::max(96, (std::max(0, height - (tabHeight + secondaryHeight + infoHeight + statusHeight)) * 2) / 5)
        : std::min(150, std::max(72, height / 5));
    const int filterLabelWidth = 72;
    const int locateWidth = 52;
    const int includeWidth = showIncludeCombo ? 150 : 0;
    const int filterEditWidth = std::max(120, (width - buttonWidth - locateWidth - copyWidth - includeWidth - filterLabelWidth * 2) / 2);

    ::ShowWindow(primaryTab_, showPrimary ? SW_SHOW : SW_HIDE);
    ::MoveWindow(primaryTab_, 0, 0, width, tabHeight, TRUE);
    ::ShowWindow(secondaryTab_, showSecondary ? SW_SHOW : SW_HIDE);
    ::MoveWindow(secondaryTab_, 0, tabHeight, width, secondaryHeight, TRUE);
    const int contentTop = (showPrimary ? tabHeight : 0) + secondaryHeight;
    const int actionRight = width;
    const int refreshLeft = std::max(0, actionRight - buttonWidth);
    const int copyLeft = std::max(0, refreshLeft - copyWidth);
    const int locateLeft = std::max(0, copyLeft - locateWidth);
    ::MoveWindow(titleText_, 0, contentTop, std::max(0, locateLeft - 4), 22, TRUE);
    ::MoveWindow(locateButton_, locateLeft, contentTop, locateWidth, buttonHeight, TRUE);
    ::ShowWindow(copyDiagnosticButton_, showCopyDiagnostic ? SW_SHOW : SW_HIDE);
    ::MoveWindow(copyDiagnosticButton_, copyLeft, contentTop, copyWidth, buttonHeight, TRUE);
    ::MoveWindow(refreshButton_, refreshLeft, contentTop, buttonWidth, buttonHeight, TRUE);
    ::MoveWindow(summaryText_, 0, contentTop + 22, width, 28, TRUE);
    ::MoveWindow(backendText_, 0, contentTop + 50, width, 22, TRUE);
    const int filterTop = contentTop + 72;
    int cursorX = 0;
    ::MoveWindow(filterLabel_, cursorX, filterTop + 3, filterLabelWidth, 20, TRUE);
    cursorX += filterLabelWidth;
    ::MoveWindow(filterEdit_, cursorX, filterTop, filterEditWidth, 22, TRUE);
    cursorX += filterEditWidth;
    ::MoveWindow(moduleFilterLabel_, cursorX, filterTop + 3, filterLabelWidth, 20, TRUE);
    cursorX += filterLabelWidth;
    const int moduleWidth = std::max(0, width - cursorX - includeWidth);
    ::MoveWindow(moduleFilterEdit_, cursorX, filterTop, moduleWidth, 22, TRUE);
    cursorX += moduleWidth;
    ::ShowWindow(includeCombo_, showIncludeCombo ? SW_SHOW : SW_HIDE);
    ::MoveWindow(includeCombo_, cursorX, filterTop, includeWidth, 240, TRUE);
    ::MoveWindow(statusText_, 0, contentTop + infoHeight, width, statusHeight, TRUE);
    const int resultTop = contentTop + infoHeight + statusHeight;
    const int resultHeight = std::max(0, height - (resultTop + detailHeight));
    const auto moveResultDetailSplitter = [&](const int panelTop, const int minimumTableHeight, const int minimumDetailHeight) {
        // moveResultDetailSplitter mirrors the vertical splitters used by the
        // source dock pages. Inputs are the top edge and minimum pane heights;
        // processing clamps the saved table height, moves the table/detail HWNDs,
        // and redraws only the splitter strip; there is no return value.
        const int availableHeight = std::max(0, height - panelTop);
        const int maximumTableHeight = std::max(minimumTableHeight,
            availableHeight - minimumDetailHeight - kKernelSplitterThickness);
        if (verticalSplitterOffset_ < 0) {
            verticalSplitterOffset_ = std::max(minimumTableHeight, (availableHeight * 3) / 5);
        }
        const int tableHeight = ClampInt(verticalSplitterOffset_, minimumTableHeight, maximumTableHeight);
        const int splitterTop = panelTop + tableHeight;
        const int detailTop = splitterTop + kKernelSplitterThickness;
        verticalSplitterOffset_ = tableHeight;
        verticalSplitterRect_ = RECT{ 0, splitterTop, width, splitterTop + kKernelSplitterThickness };
        ::MoveWindow(resultList_, 0, panelTop, width, std::min(availableHeight, tableHeight), TRUE);
        ::MoveWindow(detailEdit_, 0, detailTop, width, std::max(0, height - detailTop), TRUE);
        ::InvalidateRect(hwnd_, &verticalSplitterRect_, FALSE);
        if (Width(oldSplitterRect) > 0 || Height(oldSplitterRect) > 0) {
            ::InvalidateRect(hwnd_, &oldSplitterRect, FALSE);
        }
    };
    std::vector<HWND> callbackControls = {
        callbackGlobalEnabledCheck_, callbackApplyButton_, callbackReloadButton_, callbackImportButton_, callbackExportButton_,
        callbackStartReceiverButton_, callbackStopReceiverButton_, callbackAllowEventButton_, callbackDenyEventButton_,
        callbackStatusText_, callbackGroupLabel_, callbackAddGroupButton_, callbackRemoveGroupButton_,
        callbackRenameGroupButton_, callbackMoveGroupUpButton_, callbackMoveGroupDownButton_, callbackGroupList_,
        callbackRuleLabel_, callbackAddRuleButton_, callbackRemoveRuleButton_, callbackMoveRuleUpButton_,
        callbackMoveRuleDownButton_, callbackRuleTab_, callbackBypassLabel_, callbackBypassPidEdit_,
        callbackBypassAddButton_, callbackBypassRemoveButton_, callbackBypassApplyButton_, callbackBypassClearButton_,
        callbackBypassRefreshButton_, callbackBypassList_, callbackBypassStatusText_, callbackLogTab_, callbackAppLogEdit_, callbackEventLogEdit_,
        callbackFileMonitorLabel_, callbackStartFsctlButton_, callbackDrainFileMonitorButton_, callbackClearFileMonitorButton_,
        callbackExportFileMonitorButton_, callbackFileMonitorFsctlOnlyCheck_, callbackFileMonitorStatusText_, callbackFileMonitorList_
    };
    for (HWND child : callbackRuleLists_) {
        callbackControls.push_back(child);
    }
    for (HWND child : callbackControls) {
        ::ShowWindow(child, showCallbackPanel ? SW_SHOW : SW_HIDE);
    }
    const std::vector<HWND> kernelMemoryControls = {
        riskOnlyCheck_, evidenceIncludeNonModuleCheck_, evidenceStartEdit_, evidenceEndEdit_,
        evidenceMaxRowsLabel_, evidenceMaxRowsEdit_, evidenceMaxRowsSpin_,
        integrityModuleBaseLabel_, integrityModuleBaseEdit_, integrityFillFromSelectionButton_, integrityCpuOnlyButton_,
        integrityIdtVectorsLabel_, integrityIdtVectorsEdit_, integrityIdtVectorsSpin_,
        deviceDriverDirectoryLabel_, deviceDriverDirectoryCombo_, deviceDriverTypeLabel_, deviceDriverTypeCombo_,
        baseNamedScopeCombo_, baseNamedTypeCombo_, symbolicLinkNoteText_
    };
    for (HWND child : kernelMemoryControls) {
        ::ShowWindow(child, SW_HIDE);
    }
    ::ShowWindow(objectNamespaceTree_, SW_HIDE);

    if (showAtomPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 34, buttonHeight, TRUE);
        toolbarX += 40;
        const int statusWidth = std::min(360, std::max(120, width / 3));
        const int filterWidth = std::max(120, width - toolbarX - statusWidth - 6);
        ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
        toolbarX += filterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        const int availableHeight = std::max(0, height - panelTop);
        const int tableHeight = std::max(120, (availableHeight * 3) / 5);
        ::MoveWindow(resultList_, 0, panelTop, width, std::min(availableHeight, tableHeight), TRUE);
        ::MoveWindow(detailEdit_, 0, panelTop + std::min(availableHeight, tableHeight), width,
            std::max(0, availableHeight - std::min(availableHeight, tableHeight)), TRUE);
        return;
    }

    if (showNtQueryPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        ::MoveWindow(refreshButton_, 0, toolbarTop + 2, 34, buttonHeight, TRUE);
        ::MoveWindow(statusText_, 40, toolbarTop + 4, std::max(0, width - 40), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        const int availableHeight = std::max(0, height - panelTop);
        const int tableHeight = std::max(120, (availableHeight * 3) / 5);
        const int visibleTableHeight = std::min(availableHeight, tableHeight);
        ::MoveWindow(resultList_, 0, panelTop, width, visibleTableHeight, TRUE);
        ::MoveWindow(detailEdit_, 0, panelTop + visibleTableHeight, width,
            std::max(0, availableHeight - visibleTableHeight), TRUE);
        return;
    }

    if (showObjectNamespacePanel) {
        if (descriptor->id == KernelFeatureId::ObjectNamespaceOverview) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_SHOW);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_SHOW);

            const int toolbarTop = contentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 34, buttonHeight, TRUE);
            toolbarX += 40;
            const int statusWidth = std::min(360, std::max(150, width / 3));
            const int filterWidth = std::max(160, std::max(0, width - toolbarX - statusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

            const int objectTop = contentTop + infoHeight;
            const int availableHeight = std::max(0, height - objectTop);
            const int objectDetailHeight = std::max(96, availableHeight / 3);
            const int objectResultHeight = std::max(0, availableHeight - objectDetailHeight);
            const int propertyWidth = std::max(260, (width * 2) / 5);
            ::MoveWindow(resultList_, 0, objectTop, std::max(0, width - propertyWidth), objectResultHeight, TRUE);
            ::MoveWindow(objectNamespaceTree_, 0, objectTop, 0, 0, TRUE);
            ::MoveWindow(propertyList_, std::max(0, width - propertyWidth), objectTop, propertyWidth, objectResultHeight, TRUE);
            ::MoveWindow(detailEdit_, 0, objectTop + objectResultHeight, width, objectDetailHeight, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::ObjectDirectoryRecursive) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_SHOW);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_SHOW);
            ::ShowWindow(moduleFilterEdit_, SW_SHOW);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_SHOW);

            const int toolbarTop = contentTop;
            int toolbarX = 0;
            ::MoveWindow(filterLabel_, toolbarX, toolbarTop + 5, 52, 20, TRUE);
            toolbarX += 52;
            const int depthLabelWidth = 64;
            const int depthEditWidth = 56;
            const int refreshWidth = 56;
            const int statusWidth = std::min(360, std::max(150, width / 3));
            const int rootEditWidth = std::max(120,
                std::max(0, width - toolbarX - depthLabelWidth - depthEditWidth - refreshWidth - statusWidth - 24));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, rootEditWidth, 22, TRUE);
            toolbarX += rootEditWidth + 6;
            ::MoveWindow(moduleFilterLabel_, toolbarX, toolbarTop + 5, depthLabelWidth, 20, TRUE);
            toolbarX += depthLabelWidth;
            ::MoveWindow(moduleFilterEdit_, toolbarX, toolbarTop + 3, depthEditWidth, 22, TRUE);
            toolbarX += depthEditWidth + 6;
            ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, refreshWidth, buttonHeight, TRUE);
            toolbarX += refreshWidth + 6;
            ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

            const int objectTop = contentTop + infoHeight;
            const int availableHeight = std::max(0, height - objectTop);
            const int objectDetailHeight = std::max(120, availableHeight / 3);
            const int objectResultHeight = std::max(0, availableHeight - objectDetailHeight);
            ::MoveWindow(resultList_, 0, objectTop, width, objectResultHeight, TRUE);
            ::MoveWindow(detailEdit_, 0, objectTop + objectResultHeight, width, objectDetailHeight, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::NamedPipe) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_SHOW);

            const int toolbarTop = contentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 34, buttonHeight, TRUE);
            toolbarX += 38;
            ::MoveWindow(copyDiagnosticButton_, toolbarX, toolbarTop + 2, 34, buttonHeight, TRUE);
            toolbarX += 38;
            const int statusWidth = std::min(360, std::max(180, width / 3));
            const int filterWidth = std::max(140, std::max(0, width - toolbarX - statusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

            const int objectTop = contentTop + 28;
            const int objectDetailHeight = std::min(150, std::max(96, height / 4));
            const int objectResultHeight = std::max(0, height - objectTop - objectDetailHeight);
            ::MoveWindow(resultList_, 0, objectTop, width, objectResultHeight, TRUE);
            ::MoveWindow(detailEdit_, 0, std::max(0, height - objectDetailHeight), width, objectDetailHeight, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::SymbolicLink) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_SHOW);
            ::ShowWindow(symbolicLinkNoteText_, SW_SHOW);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int toolbarTop = contentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 56, buttonHeight, TRUE);
            toolbarX += 60;
            ::MoveWindow(copyDiagnosticButton_, toolbarX, toolbarTop + 2, 76, buttonHeight, TRUE);
            toolbarX += 82;
            const int statusWidth = std::min(320, std::max(140, width / 4));
            const int filterWidth = std::max(140, std::max(0, (width - toolbarX - statusWidth - 12) / 2));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 6;
            ::MoveWindow(moduleFilterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

            const int noteTop = toolbarTop + 28;
            ::MoveWindow(symbolicLinkNoteText_, 0, noteTop + 2, width, 22, TRUE);
            const int objectTop = contentTop + 56;
            ::MoveWindow(resultList_, 0, objectTop, width, std::max(0, height - objectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, height, width, 0, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::BaseNamedObjects) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_SHOW);
            ::ShowWindow(baseNamedTypeCombo_, SW_SHOW);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int toolbarTop = contentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 56, buttonHeight, TRUE);
            toolbarX += 62;
            const int scopeWidth = std::max(130, std::min(190, width / 6));
            ::MoveWindow(baseNamedScopeCombo_, toolbarX, toolbarTop + 2, scopeWidth, 240, TRUE);
            toolbarX += scopeWidth + 6;
            const int typeWidth = std::max(130, std::min(190, width / 6));
            ::MoveWindow(baseNamedTypeCombo_, toolbarX, toolbarTop + 2, typeWidth, 240, TRUE);
            toolbarX += typeWidth + 6;
            const int statusWidth = std::min(360, std::max(150, width / 3));
            const int keywordWidth = std::max(120, std::max(0, width - toolbarX - statusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, keywordWidth, 22, TRUE);
            toolbarX += keywordWidth + 6;
            ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

            const int objectTop = contentTop + 28;
            ::MoveWindow(resultList_, 0, objectTop, width, std::max(0, height - objectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, height, width, 0, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::DeviceDriverObjects) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_SHOW);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_SHOW);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_SHOW);
            ::ShowWindow(deviceDriverTypeLabel_, SW_SHOW);
            ::ShowWindow(deviceDriverTypeCombo_, SW_SHOW);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int toolbarTop = contentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 56, buttonHeight, TRUE);
            toolbarX += 60;
            ::MoveWindow(copyDiagnosticButton_, toolbarX, toolbarTop + 2, 76, buttonHeight, TRUE);
            toolbarX += 82;
            ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

            const int filterTop = toolbarTop + 28;
            int filterX = 0;
            ::MoveWindow(deviceDriverDirectoryLabel_, filterX, filterTop + 5, 42, 20, TRUE);
            filterX += 42;
            const int directoryWidth = std::max(150, std::min(230, width / 5));
            ::MoveWindow(deviceDriverDirectoryCombo_, filterX, filterTop + 2, directoryWidth, 260, TRUE);
            filterX += directoryWidth + 6;
            ::MoveWindow(deviceDriverTypeLabel_, filterX, filterTop + 5, 42, 20, TRUE);
            filterX += 42;
            const int typeWidth = std::max(130, std::min(200, width / 6));
            ::MoveWindow(deviceDriverTypeCombo_, filterX, filterTop + 2, typeWidth, 260, TRUE);
            filterX += typeWidth + 6;
            ::SetWindowTextW(filterLabel_, L"关键字：");
            ::MoveWindow(filterLabel_, filterX, filterTop + 5, 58, 20, TRUE);
            filterX += 58;
            ::MoveWindow(filterEdit_, filterX, filterTop + 3, std::max(0, width - filterX), 22, TRUE);

            const int objectTop = contentTop + 56;
            ::MoveWindow(resultList_, 0, objectTop, width, std::max(0, height - objectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, height, width, 0, TRUE);
            return;
        }
        if (descriptor->id == KernelFeatureId::ObjectTypeMatrix) {
            ::ShowWindow(titleText_, SW_HIDE);
            ::ShowWindow(summaryText_, SW_HIDE);
            ::ShowWindow(backendText_, SW_HIDE);
            ::ShowWindow(filterLabel_, SW_HIDE);
            ::ShowWindow(filterEdit_, SW_SHOW);
            ::ShowWindow(moduleFilterLabel_, SW_HIDE);
            ::ShowWindow(moduleFilterEdit_, SW_HIDE);
            ::ShowWindow(symbolicLinkNoteText_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverDirectoryCombo_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeLabel_, SW_HIDE);
            ::ShowWindow(deviceDriverTypeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedScopeCombo_, SW_HIDE);
            ::ShowWindow(baseNamedTypeCombo_, SW_HIDE);
            ::ShowWindow(includeCombo_, SW_HIDE);
            ::ShowWindow(locateButton_, SW_HIDE);
            ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
            ::ShowWindow(refreshButton_, SW_SHOW);
            ::ShowWindow(statusText_, SW_SHOW);
            ::ShowWindow(summaryList_, SW_HIDE);
            ::ShowWindow(propertyList_, SW_HIDE);
            ::ShowWindow(resultList_, SW_SHOW);
            ::ShowWindow(objectNamespaceTree_, SW_HIDE);
            ::ShowWindow(detailEdit_, SW_HIDE);

            const int toolbarTop = contentTop;
            int toolbarX = 0;
            ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 34, buttonHeight, TRUE);
            toolbarX += 38;
            const int statusWidth = std::min(320, std::max(150, width / 3));
            const int filterWidth = std::max(120, std::max(0, width - toolbarX - statusWidth - 6));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 6;
            ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

            const int objectTop = contentTop + 28;
            ::MoveWindow(resultList_, 0, objectTop, width, std::max(0, height - objectTop), TRUE);
            ::MoveWindow(detailEdit_, 0, height, width, 0, TRUE);
            return;
        }
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_SHOW);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(locateButton_, SW_SHOW);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(statusText_, SW_SHOW);
        const bool showObjectAuxEdit = descriptor->id == KernelFeatureId::ObjectDirectoryRecursive ||
            descriptor->id == KernelFeatureId::BaseNamedObjects ||
            descriptor->id == KernelFeatureId::SymbolicLink ||
            descriptor->id == KernelFeatureId::DeviceDriverObjects;
        ::ShowWindow(moduleFilterLabel_, showObjectAuxEdit ? SW_SHOW : SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, showObjectAuxEdit ? SW_SHOW : SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        const bool showObjectExtraButton = descriptor->id == KernelFeatureId::NamedPipe ||
            descriptor->id == KernelFeatureId::DeviceDriverObjects ||
            descriptor->id == KernelFeatureId::SymbolicLink ||
            descriptor->id == KernelFeatureId::BaseNamedObjects;
        ::ShowWindow(copyDiagnosticButton_, showObjectExtraButton ? SW_SHOW : SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        // The original KswordARK object namespace and recursive-directory tabs
        // are tree widget pages, meaning a tree with visible report columns. A
        // plain Win32 TreeView loses those columns, so the Win32-light page keeps
        // the report ListView visible as the tree-table surface and uses hidden
        // row fields for actions/details.
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(objectNamespaceTree_, SW_HIDE);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 74, buttonHeight, TRUE);
        toolbarX += 76;
        const int filterLabelObjectWidth = descriptor->id == KernelFeatureId::ObjectDirectoryRecursive ? 52 : 40;
        ::MoveWindow(filterLabel_, toolbarX, toolbarTop + 5, filterLabelObjectWidth, 20, TRUE);
        toolbarX += filterLabelObjectWidth;
        const int actionWidthObject = showObjectExtraButton ? 76 : 0;
        const int locateWidthObject = descriptor->id == KernelFeatureId::NamedPipe ? 58 : 52;
        const int auxLabelWidth = showObjectAuxEdit ? 64 : 0;
        const int auxEditWidth = showObjectAuxEdit ? std::max(72, std::min(170, width / 5)) : 0;
        const int filterWidth = std::max(160, std::min(width / 3, std::max(0, width - toolbarX - locateWidthObject - actionWidthObject - auxLabelWidth - auxEditWidth - 220)));
        ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
        toolbarX += filterWidth + 2;
        if (showObjectAuxEdit) {
            ::MoveWindow(moduleFilterLabel_, toolbarX, toolbarTop + 5, auxLabelWidth, 20, TRUE);
            toolbarX += auxLabelWidth;
            ::MoveWindow(moduleFilterEdit_, toolbarX, toolbarTop + 3, auxEditWidth, 22, TRUE);
            toolbarX += auxEditWidth + 2;
        }
        ::MoveWindow(locateButton_, toolbarX, toolbarTop + 2, locateWidthObject, buttonHeight, TRUE);
        toolbarX += locateWidthObject + 4;
        if (showObjectExtraButton) {
            ::MoveWindow(copyDiagnosticButton_, toolbarX, toolbarTop + 2, actionWidthObject, buttonHeight, TRUE);
            toolbarX += actionWidthObject + 4;
        }
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int objectTop = contentTop + infoHeight;
        const int objectDetailHeight = std::min(160, std::max(96, height / 5));
        const int objectResultHeight = std::max(0, height - objectTop - objectDetailHeight);
        if (descriptor->id == KernelFeatureId::ObjectNamespaceOverview) {
            const int propertyWidth = std::max(260, width / 3);
            ::ShowWindow(propertyList_, SW_SHOW);
            ::MoveWindow(resultList_, 0, objectTop, std::max(0, width - propertyWidth), objectResultHeight, TRUE);
            ::MoveWindow(objectNamespaceTree_, 0, objectTop, 0, 0, TRUE);
            ::MoveWindow(propertyList_, std::max(0, width - propertyWidth), objectTop, propertyWidth, objectResultHeight, TRUE);
        } else if (descriptor->id == KernelFeatureId::ObjectDirectoryRecursive) {
            ::ShowWindow(propertyList_, SW_HIDE);
            ::MoveWindow(resultList_, 0, objectTop, width, objectResultHeight, TRUE);
            ::MoveWindow(objectNamespaceTree_, 0, objectTop, 0, 0, TRUE);
            ::MoveWindow(propertyList_, width, objectTop, 0, objectResultHeight, TRUE);
        } else {
            ::ShowWindow(propertyList_, SW_HIDE);
            ::MoveWindow(resultList_, 0, objectTop, width, objectResultHeight, TRUE);
            ::MoveWindow(propertyList_, width, objectTop, 0, objectResultHeight, TRUE);
        }
        ::MoveWindow(detailEdit_, 0, std::max(0, height - objectDetailHeight), width, objectDetailHeight, TRUE);
        return;
    }

    if (showKernelHookPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, descriptor->id == KernelFeatureId::InlineHook || descriptor->id == KernelFeatureId::IatEatHook ? SW_SHOW : SW_HIDE);
        ::ShowWindow(includeCombo_, showIncludeCombo ? SW_SHOW : SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, descriptor->id == KernelFeatureId::InlineHook ? SW_SHOW : SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(statusText_, SW_SHOW);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        const int refreshWidth = 34;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, refreshWidth, buttonHeight, TRUE);
        toolbarX += refreshWidth + 4;
        if (descriptor->id == KernelFeatureId::InlineHook) {
            ::MoveWindow(copyDiagnosticButton_, toolbarX, toolbarTop + 2, 96, buttonHeight, TRUE);
            toolbarX += 100;
        }
        if (descriptor->id == KernelFeatureId::InlineHook || descriptor->id == KernelFeatureId::IatEatHook) {
            const int reservedRight = (showIncludeCombo ? 174 : 0) + std::max(220, width / 4);
            const int editArea = std::max(260, width - toolbarX - reservedRight - 8);
            const int moduleEditWidth = std::max(160, editArea / 2);
            ::MoveWindow(moduleFilterEdit_, toolbarX, toolbarTop + 3, moduleEditWidth, 22, TRUE);
            toolbarX += moduleEditWidth + 4;
            const int filterWidth = std::max(180, editArea - moduleEditWidth);
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 4;
        } else {
            const int statusWidth = std::min(420, std::max(160, width / 3));
            const int filterWidth = std::max(180, std::max(0, width - toolbarX - statusWidth - 8));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 4;
        }
        if (showIncludeCombo) {
            ::MoveWindow(includeCombo_, toolbarX, toolbarTop + 2, 170, 240, TRUE);
            toolbarX += 174;
        }
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);
        const int hookTop = contentTop + infoHeight;
        moveResultDetailSplitter(hookTop, 88, 88);
        return;
    }

    if (showDiagnosticDualPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_SHOW);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_SHOW);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 34, buttonHeight, TRUE);
        toolbarX += 40;
        ::MoveWindow(copyDiagnosticButton_, toolbarX, toolbarTop + 2, 82, buttonHeight, TRUE);
        toolbarX += 88;
        ::MoveWindow(filterLabel_, toolbarX, toolbarTop + 5, 0, 20, TRUE);
        const int statusWidth = std::min(420, std::max(160, width / 3));
        const int diagnosticFilterWidth = std::max(180, std::max(0, width - toolbarX - statusWidth - 8));
        ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, diagnosticFilterWidth, 22, TRUE);
        toolbarX += diagnosticFilterWidth + 8;
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        const int availableHeight = std::max(0, height - panelTop);
        const int summaryHeight = std::min(availableHeight, std::max(96, (availableHeight * 2) / 7));
        const int lowerTop = panelTop + summaryHeight;
        const int lowerHeight = std::max(0, height - lowerTop);
        const int listWidth = std::min(width, std::max(320, (width * 3) / 5));
        ::MoveWindow(summaryList_, 0, panelTop, width, summaryHeight, TRUE);
        ::MoveWindow(resultList_, 0, lowerTop, listWidth, lowerHeight, TRUE);
        ::MoveWindow(propertyList_, width, panelTop, 0, 0, TRUE);
        ::MoveWindow(detailEdit_, listWidth, lowerTop, std::max(0, width - listWidth), lowerHeight, TRUE);
        return;
    }

    if (showCallbackEnumerationPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(statusText_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 34, buttonHeight, TRUE);
        toolbarX += 38;
        const int callbackFilterWidth = std::max(220, std::min(width / 2, std::max(0, width - toolbarX - 320)));
        ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, callbackFilterWidth, 22, TRUE);
        toolbarX += callbackFilterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        moveResultDetailSplitter(panelTop, 120, 96);
        return;
    }

    if (showKernelMemoryScanPanel) {
        const bool evidencePage = descriptor->id == KernelFeatureId::KernelMemoryEvidence;
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, evidencePage ? SW_HIDE : SW_HIDE);
        ::ShowWindow(filterEdit_, evidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, evidencePage ? SW_HIDE : SW_SHOW);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(riskOnlyCheck_, SW_SHOW);
        ::ShowWindow(evidenceIncludeNonModuleCheck_, evidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceStartEdit_, evidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceEndEdit_, evidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceMaxRowsLabel_, evidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceMaxRowsEdit_, evidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(evidenceMaxRowsSpin_, evidencePage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        const int refreshWidth = evidencePage ? 70 : 48;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, refreshWidth, buttonHeight, TRUE);
        toolbarX += refreshWidth + 4;
        ::MoveWindow(riskOnlyCheck_, toolbarX, toolbarTop + 3, 74, 22, TRUE);
        toolbarX += 78;
        if (evidencePage) {
            ::MoveWindow(evidenceIncludeNonModuleCheck_, toolbarX, toolbarTop + 3, 138, 22, TRUE);
            toolbarX += 142;
            ::MoveWindow(evidenceStartEdit_, toolbarX, toolbarTop + 3, 130, 22, TRUE);
            toolbarX += 134;
            ::MoveWindow(evidenceEndEdit_, toolbarX, toolbarTop + 3, 130, 22, TRUE);
            toolbarX += 134;
            ::MoveWindow(evidenceMaxRowsLabel_, toolbarX, toolbarTop + 5, 36, 20, TRUE);
            toolbarX += 36;
            ::MoveWindow(evidenceMaxRowsEdit_, toolbarX, toolbarTop + 3, 70, 22, TRUE);
            ::MoveWindow(evidenceMaxRowsSpin_, toolbarX + 50, toolbarTop + 3, 20, 22, TRUE);
            toolbarX += 74;
            const int filterWidth = std::max(160, std::min(300, std::max(0, width - toolbarX - 260)));
            ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
            toolbarX += filterWidth + 6;
        } else {
            const int moduleWidth = std::max(220, std::min(520, std::max(0, width - toolbarX - 300)));
            ::MoveWindow(moduleFilterEdit_, toolbarX, toolbarTop + 3, moduleWidth, 22, TRUE);
            toolbarX += moduleWidth + 6;
        }
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        moveResultDetailSplitter(panelTop, 120, 96);
        return;
    }

    if (showCrossViewPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(riskOnlyCheck_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 74, buttonHeight, TRUE);
        toolbarX += 78;
        ::MoveWindow(riskOnlyCheck_, toolbarX, toolbarTop + 3, 74, 22, TRUE);
        toolbarX += 78;
        const int filterWidth = std::max(220, std::min(width / 2, std::max(0, width - toolbarX - 300)));
        ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
        toolbarX += filterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        moveResultDetailSplitter(panelTop, 120, 96);
        return;
    }

    if (showR0EvidencePanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        const bool showR0RiskOnly = descriptor->id == KernelFeatureId::MutationAudit;
        ::ShowWindow(riskOnlyCheck_, showR0RiskOnly ? SW_SHOW : SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, 74, buttonHeight, TRUE);
        toolbarX += 78;
        if (showR0RiskOnly) {
            ::MoveWindow(riskOnlyCheck_, toolbarX, toolbarTop + 3, 74, 22, TRUE);
            toolbarX += 78;
        }
        const int filterWidth = std::max(220, std::min(width / 2, std::max(0, width - toolbarX - 320)));
        ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
        toolbarX += filterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        moveResultDetailSplitter(panelTop, 120, 96);
        return;
    }

    if (showIntegrityPanel) {
        const bool driverIntegrityPage = descriptor->id == KernelFeatureId::DriverIntegrity;
        const bool cpuIntegrityPage = descriptor->id == KernelFeatureId::KernelCpuIntegrity;
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_SHOW);
        ::ShowWindow(moduleFilterLabel_, driverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, driverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityModuleBaseLabel_, driverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityModuleBaseEdit_, driverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityFillFromSelectionButton_, driverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityCpuOnlyButton_, driverIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityIdtVectorsLabel_, cpuIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityIdtVectorsEdit_, cpuIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(integrityIdtVectorsSpin_, cpuIntegrityPage ? SW_SHOW : SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_SHOW);
        ::ShowWindow(riskOnlyCheck_, SW_SHOW);
        ::ShowWindow(evidenceMaxRowsLabel_, SW_SHOW);
        ::ShowWindow(evidenceMaxRowsEdit_, SW_SHOW);
        ::ShowWindow(evidenceMaxRowsSpin_, SW_SHOW);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);

        const int toolbarTop = contentTop;
        int toolbarX = 0;
        if (driverIntegrityPage) {
            ::MoveWindow(moduleFilterLabel_, toolbarX, toolbarTop + 5, 78, 20, TRUE);
            toolbarX += 78;
            const int driverNameWidth = std::max(120, std::min(260, width / 5));
            ::MoveWindow(moduleFilterEdit_, toolbarX, toolbarTop + 3, driverNameWidth, 22, TRUE);
            toolbarX += driverNameWidth + 4;
            ::MoveWindow(integrityModuleBaseLabel_, toolbarX, toolbarTop + 5, 58, 20, TRUE);
            toolbarX += 58;
            ::MoveWindow(integrityModuleBaseEdit_, toolbarX, toolbarTop + 3, 132, 22, TRUE);
            toolbarX += 136;
            ::MoveWindow(integrityFillFromSelectionButton_, toolbarX, toolbarTop + 2, 44, buttonHeight, TRUE);
            toolbarX += 48;
        }
        ::MoveWindow(refreshButton_, toolbarX, toolbarTop + 2, driverIntegrityPage ? 48 : 88, buttonHeight, TRUE);
        toolbarX += driverIntegrityPage ? 52 : 92;
        if (driverIntegrityPage) {
            ::MoveWindow(integrityCpuOnlyButton_, toolbarX, toolbarTop + 2, 42, buttonHeight, TRUE);
            toolbarX += 46;
        }
        ::MoveWindow(riskOnlyCheck_, toolbarX, toolbarTop + 3, 74, 22, TRUE);
        toolbarX += 78;
        ::MoveWindow(evidenceMaxRowsLabel_, toolbarX, toolbarTop + 5, 36, 20, TRUE);
        toolbarX += 36;
        ::MoveWindow(evidenceMaxRowsEdit_, toolbarX, toolbarTop + 3, 70, 22, TRUE);
        ::MoveWindow(evidenceMaxRowsSpin_, toolbarX + 50, toolbarTop + 3, 20, 22, TRUE);
        toolbarX += 74;
        if (cpuIntegrityPage) {
            ::MoveWindow(integrityIdtVectorsLabel_, toolbarX, toolbarTop + 5, 58, 20, TRUE);
            toolbarX += 58;
            ::MoveWindow(integrityIdtVectorsEdit_, toolbarX, toolbarTop + 3, 70, 22, TRUE);
            ::MoveWindow(integrityIdtVectorsSpin_, toolbarX + 50, toolbarTop + 3, 20, 22, TRUE);
            toolbarX += 74;
        }
        const int remainingAfterTools = std::max(0, width - toolbarX);
        const int targetStatusWidth = driverIntegrityPage ? 360 : 320;
        const int filterWidth = std::max(140,
            std::min(driverIntegrityPage ? 260 : std::max(180, width / 3),
                std::max(0, remainingAfterTools - targetStatusWidth)));
        ::MoveWindow(filterEdit_, toolbarX, toolbarTop + 3, filterWidth, 22, TRUE);
        toolbarX += filterWidth + 6;
        ::MoveWindow(statusText_, toolbarX, toolbarTop + 4, std::max(0, width - toolbarX), 22, TRUE);

        const int panelTop = contentTop + infoHeight;
        moveResultDetailSplitter(panelTop, 120, 96);
        return;
    }

    ::ShowWindow(titleText_, SW_SHOW);
    ::ShowWindow(summaryText_, SW_SHOW);
    ::ShowWindow(backendText_, SW_SHOW);
    ::ShowWindow(filterLabel_, SW_SHOW);
    ::ShowWindow(filterEdit_, SW_SHOW);
    ::ShowWindow(moduleFilterLabel_, SW_SHOW);
    ::ShowWindow(moduleFilterEdit_, SW_SHOW);
    ::ShowWindow(locateButton_, SW_SHOW);
    ::ShowWindow(refreshButton_, SW_SHOW);

    if (showCallbackPanel) {
        ::ShowWindow(titleText_, SW_HIDE);
        ::ShowWindow(summaryText_, SW_HIDE);
        ::ShowWindow(backendText_, SW_HIDE);
        ::ShowWindow(filterLabel_, SW_HIDE);
        ::ShowWindow(filterEdit_, SW_HIDE);
        ::ShowWindow(moduleFilterLabel_, SW_HIDE);
        ::ShowWindow(moduleFilterEdit_, SW_HIDE);
        ::ShowWindow(includeCombo_, SW_HIDE);
        ::ShowWindow(locateButton_, SW_HIDE);
        ::ShowWindow(copyDiagnosticButton_, SW_HIDE);
        ::ShowWindow(refreshButton_, SW_HIDE);
        ::ShowWindow(statusText_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_HIDE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(resultList_, SW_HIDE);
        ::ShowWindow(detailEdit_, SW_HIDE);
        ::MoveWindow(summaryList_, 0, resultTop, 0, 0, TRUE);
        ::MoveWindow(propertyList_, width, resultTop, 0, 0, TRUE);
        ::MoveWindow(resultList_, 0, resultTop, 0, 0, TRUE);
        ::MoveWindow(detailEdit_, 0, height, 0, 0, TRUE);

        const int panelTop = contentTop;
        const int compactGap = 4;
        const int toolbarHeight = buttonHeight;
        int toolbarX = 0;
        ::MoveWindow(callbackGlobalEnabledCheck_, toolbarX, panelTop + 3, 76, 20, TRUE); toolbarX += 80;
        ::MoveWindow(callbackApplyButton_, toolbarX, panelTop, 52, toolbarHeight, TRUE); toolbarX += 56;
        ::MoveWindow(callbackReloadButton_, toolbarX, panelTop, 126, toolbarHeight, TRUE); toolbarX += 130;
        ::MoveWindow(callbackImportButton_, toolbarX, panelTop, 72, toolbarHeight, TRUE); toolbarX += 76;
        ::MoveWindow(callbackExportButton_, toolbarX, panelTop, 72, toolbarHeight, TRUE); toolbarX += 76;
        ::MoveWindow(callbackStartReceiverButton_, toolbarX, panelTop, 82, toolbarHeight, TRUE); toolbarX += 86;
        ::MoveWindow(callbackStopReceiverButton_, toolbarX, panelTop, 68, toolbarHeight, TRUE); toolbarX += 72;
        ::MoveWindow(callbackAllowEventButton_, toolbarX, panelTop, 68, toolbarHeight, TRUE); toolbarX += 72;
        ::MoveWindow(callbackDenyEventButton_, toolbarX, panelTop, 68, toolbarHeight, TRUE); toolbarX += 72;
        ::MoveWindow(callbackStatusText_, toolbarX, panelTop + 3, std::max(0, width - toolbarX), 20, TRUE);

        const int statusTop = panelTop + toolbarHeight + compactGap;
        ::MoveWindow(callbackStatusText_, 0, statusTop, width, 20, TRUE);
        const int mainTop = statusTop + 22;
        const int fileMonitorMinHeight = std::min(210, std::max(120, height / 4));
        const int logHeight = std::min(150, std::max(74, height / 7));
        const int fileBlockHeight = std::min(std::max(0, height - mainTop - logHeight - compactGap), fileMonitorMinHeight);
        const int mainHeight = std::max(120, height - mainTop - logHeight - fileBlockHeight - compactGap * 2);
        const int leftWidth = std::max(250, (width * 3) / 10);
        const int rightX = leftWidth + compactGap;
        const int rightWidth = std::max(0, width - rightX);

        int gx = 0;
        ::MoveWindow(callbackAddGroupButton_, gx, mainTop, 30, buttonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackRemoveGroupButton_, gx, mainTop, 30, buttonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackRenameGroupButton_, gx, mainTop, 30, buttonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackMoveGroupUpButton_, gx, mainTop, 30, buttonHeight, TRUE); gx += 34;
        ::MoveWindow(callbackMoveGroupDownButton_, gx, mainTop, 30, buttonHeight, TRUE);
        ::MoveWindow(callbackGroupLabel_, gx + 36, mainTop + 4, std::max(0, leftWidth - gx - 36), 18, TRUE);
        ::MoveWindow(callbackGroupList_, 0, mainTop + buttonHeight + compactGap, leftWidth, std::max(0, mainHeight - buttonHeight - compactGap), TRUE);

        int rb = rightX;
        ::MoveWindow(callbackAddRuleButton_, rb, mainTop, 30, buttonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackRemoveRuleButton_, rb, mainTop, 30, buttonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackMoveRuleUpButton_, rb, mainTop, 30, buttonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackMoveRuleDownButton_, rb, mainTop, 30, buttonHeight, TRUE); rb += 34;
        ::MoveWindow(callbackRuleLabel_, rb + 2, mainTop + 4, std::max(0, rightX + rightWidth - rb - 2), 18, TRUE);
        const int ruleTabTop = mainTop + buttonHeight + compactGap;
        ::MoveWindow(callbackRuleTab_, rightX, ruleTabTop, rightWidth, std::max(0, mainHeight - buttonHeight - compactGap), TRUE);
        RECT tabClient{ rightX, ruleTabTop, rightX + rightWidth, ruleTabTop + std::max(0, mainHeight - buttonHeight - compactGap) };
        ::SendMessageW(callbackRuleTab_, TCM_ADJUSTRECT, FALSE, reinterpret_cast<LPARAM>(&tabClient));
        const int selectedRuleTab = static_cast<int>(::SendMessageW(callbackRuleTab_, TCM_GETCURSEL, 0, 0));
        for (int index = 0; index < static_cast<int>(callbackRuleLists_.size()); ++index) {
            const bool showRuleList = index == selectedRuleTab && index < 6;
            ::ShowWindow(callbackRuleLists_[static_cast<std::size_t>(index)], showRuleList ? SW_SHOW : SW_HIDE);
            ::MoveWindow(callbackRuleLists_[static_cast<std::size_t>(index)],
                tabClient.left,
                tabClient.top,
                Width(tabClient),
                Height(tabClient),
                TRUE);
        }

        const bool showBypass = selectedRuleTab == 6;
        ::ShowWindow(callbackBypassLabel_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassPidEdit_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassAddButton_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassRemoveButton_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassApplyButton_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassClearButton_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassRefreshButton_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassList_, showBypass ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackBypassStatusText_, showBypass ? SW_SHOW : SW_HIDE);
        ::MoveWindow(callbackBypassLabel_, tabClient.left, tabClient.top + 2, Width(tabClient), 18, TRUE);
        int bx = tabClient.left;
        const int bypassInputWidth = std::max(120, Width(tabClient) - 374);
        ::MoveWindow(callbackBypassPidEdit_, bx, tabClient.top + 24, bypassInputWidth, 22, TRUE); bx += bypassInputWidth + 4;
        ::MoveWindow(callbackBypassAddButton_, bx, tabClient.top + 23, 48, buttonHeight, TRUE); bx += 52;
        ::MoveWindow(callbackBypassRemoveButton_, bx, tabClient.top + 23, 76, buttonHeight, TRUE); bx += 80;
        ::MoveWindow(callbackBypassApplyButton_, bx, tabClient.top + 23, 78, buttonHeight, TRUE); bx += 82;
        ::MoveWindow(callbackBypassClearButton_, bx, tabClient.top + 23, 78, buttonHeight, TRUE); bx += 82;
        ::MoveWindow(callbackBypassRefreshButton_, bx, tabClient.top + 23, 78, buttonHeight, TRUE);
        const int bypassListTop = tabClient.top + 50;
        ::MoveWindow(callbackBypassList_, tabClient.left, bypassListTop, Width(tabClient), std::max(0, Height(tabClient) - 72), TRUE);
        ::MoveWindow(callbackBypassStatusText_, tabClient.left, tabClient.top + Height(tabClient) - 20, Width(tabClient), 18, TRUE);

        const int logTop = mainTop + mainHeight + compactGap;
        ::MoveWindow(callbackLogTab_, 0, logTop, width, logHeight, TRUE);
        RECT logClient{ 0, logTop, width, logTop + logHeight };
        ::SendMessageW(callbackLogTab_, TCM_ADJUSTRECT, FALSE, reinterpret_cast<LPARAM>(&logClient));
        const int selectedLog = static_cast<int>(::SendMessageW(callbackLogTab_, TCM_GETCURSEL, 0, 0));
        ::ShowWindow(callbackAppLogEdit_, selectedLog == 0 ? SW_SHOW : SW_HIDE);
        ::ShowWindow(callbackEventLogEdit_, selectedLog == 1 ? SW_SHOW : SW_HIDE);
        ::MoveWindow(callbackAppLogEdit_, logClient.left, logClient.top, Width(logClient), Height(logClient), TRUE);
        ::MoveWindow(callbackEventLogEdit_, logClient.left, logClient.top, Width(logClient), Height(logClient), TRUE);

        const int fileTop = logTop + logHeight + compactGap;
        int fx = 0;
        ::MoveWindow(callbackFileMonitorLabel_, fx, fileTop + 4, 132, 18, TRUE); fx += 136;
        ::MoveWindow(callbackStartFsctlButton_, fx, fileTop, 104, buttonHeight, TRUE); fx += 108;
        ::MoveWindow(callbackDrainFileMonitorButton_, fx, fileTop, 68, buttonHeight, TRUE); fx += 72;
        ::MoveWindow(callbackClearFileMonitorButton_, fx, fileTop, 48, buttonHeight, TRUE); fx += 52;
        ::MoveWindow(callbackExportFileMonitorButton_, fx, fileTop, 48, buttonHeight, TRUE); fx += 52;
        ::MoveWindow(callbackFileMonitorFsctlOnlyCheck_, fx, fileTop + 3, 142, 20, TRUE); fx += 146;
        ::MoveWindow(callbackFileMonitorStatusText_, fx, fileTop + 4, std::max(0, width - fx), 18, TRUE);
        ::MoveWindow(callbackFileMonitorList_, 0, fileTop + buttonHeight + compactGap, width, std::max(0, height - fileTop - buttonHeight - compactGap), TRUE);
        return;
    }

    if (showPropertyTable) {
        const int propertyWidth = std::max(260, width / 3);
        ::MoveWindow(summaryList_, 0, resultTop, 0, 0, TRUE);
        ::MoveWindow(resultList_, 0, resultTop, std::max(0, width - propertyWidth), resultHeight, TRUE);
        ::MoveWindow(propertyList_, std::max(0, width - propertyWidth), resultTop, propertyWidth, resultHeight, TRUE);
    } else if (showSummaryTable) {
        const int availableHeight = std::max(0, height - resultTop);
        const int summaryHeight = std::min(std::max(96, availableHeight / 4), std::max(96, availableHeight / 2));
        const int lowerTop = resultTop + summaryHeight;
        const int lowerHeight = std::max(0, height - lowerTop);
        const int listWidth = (width * 3) / 5;
        ::MoveWindow(summaryList_, 0, resultTop, width, summaryHeight, TRUE);
        ::MoveWindow(resultList_, 0, lowerTop, listWidth, lowerHeight, TRUE);
        ::MoveWindow(propertyList_, width, resultTop, 0, resultHeight, TRUE);
        ::MoveWindow(detailEdit_, listWidth, lowerTop, std::max(0, width - listWidth), lowerHeight, TRUE);
        ::ShowWindow(propertyList_, SW_HIDE);
        ::ShowWindow(summaryList_, SW_SHOW);
        ::ShowWindow(detailEdit_, SW_SHOW);
        return;
    } else if (showRuntimePanel) {
        const int summaryHeight = std::max(96, resultHeight / 3);
        ::MoveWindow(summaryList_, 0, resultTop, width, summaryHeight, TRUE);
        ::MoveWindow(resultList_, 0, resultTop + summaryHeight, width, std::max(0, resultHeight - summaryHeight), TRUE);
        ::MoveWindow(propertyList_, width, resultTop, 0, resultHeight, TRUE);
    } else {
        ::MoveWindow(summaryList_, 0, resultTop, 0, 0, TRUE);
        ::MoveWindow(resultList_, 0, resultTop, width, resultHeight, TRUE);
        ::MoveWindow(propertyList_, width, resultTop, 0, resultHeight, TRUE);
    }
    ::ShowWindow(propertyList_, showPropertyTable ? SW_SHOW : SW_HIDE);
    ::ShowWindow(summaryList_, (showSummaryTable || showRuntimePanel) ? SW_SHOW : SW_HIDE);
    ::MoveWindow(detailEdit_,
        0,
        std::max(0, height - detailHeight),
        width,
        detailHeight,
        TRUE);
    ::ShowWindow(detailEdit_, SW_SHOW);
}

void KernelPage::PopulateTabs() {
    features_ = GetKernelFeatureDescriptors();
    primaryTabs_.clear();
    primaryFeatureIds_.clear();

    ::SendMessageW(primaryTab_, TCM_DELETEALLITEMS, 0, 0);
    for (const TopLevelTabSpec& spec : OriginalTopLevelTabs()) {
        if (FeatureById(spec.featureId) == nullptr) {
            continue;
        }
        primaryTabs_.push_back(spec.title);
        primaryFeatureIds_.push_back(spec.featureId);
        SetTabText(primaryTab_, static_cast<int>(primaryTabs_.size() - 1), spec.title);
    }

    if (!primaryTabs_.empty()) {
        ::SendMessageW(primaryTab_, TCM_SETCURSEL, 0, 0);
        RebuildSecondLevelTabs();
        if (hasInitialFeatureId_) {
            // Embedded callers use CreateKernelSingleFeaturePage. Keep that
            // contract even when the requested feature also belongs to the
            // full Kernel dock's primary/secondary navigation tree; otherwise
            // the host dock ends up rendering a duplicate tab strip.
            hasInitialFeatureId_ = false;
            if (FeatureById(initialFeatureId_) != nullptr) {
                hasDirectFeatureId_ = true;
                directFeatureId_ = initialFeatureId_;
                SelectCurrentFeature();
                Layout();
            } else {
                SelectCurrentFeature();
            }
        } else {
            SelectCurrentFeature();
        }
    }
}

bool KernelPage::SelectFeatureById(const KernelFeatureId featureId) {
    // SelectFeatureById maps one retained feature id into the original
    // primary/secondary tab model. Inputs are immutable catalog ids; processing
    // changes tab selection when the feature is visible in the Kernel dock, or
    // enters a direct single-feature mode when an external dock embeds a hidden
    // retained page through SetInitialFeature. Output reports whether a feature
    // was selected.
    Ksword::Ui::ScopedWindowRedrawLock pageRedrawLock(hwnd_);
    if (FeatureById(featureId) == nullptr) {
        return false;
    }
    if (!hasActiveFeatureId_ || activeFeatureId_ != featureId) {
        ParkCurrentFeatureViewCache();
    }
    for (int primaryIndex = 0; primaryIndex < static_cast<int>(primaryFeatureIds_.size()); ++primaryIndex) {
        const KernelFeatureId primaryId = primaryFeatureIds_[static_cast<std::size_t>(primaryIndex)];
        if (primaryId == featureId) {
            hasDirectFeatureId_ = false;
            ::SendMessageW(primaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(primaryIndex), 0);
            RebuildSecondLevelTabs();
            SelectCurrentFeature();
            return true;
        }

        const std::vector<ObjectNamespaceTabSpec>& secondaryTabs = SecondaryTabsForPrimary(primaryId);
        for (const ObjectNamespaceTabSpec& secondary : secondaryTabs) {
            if (secondary.featureId != featureId || FeatureById(secondary.featureId) == nullptr) {
                continue;
            }
            hasDirectFeatureId_ = false;
            ::SendMessageW(primaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(primaryIndex), 0);
            RebuildSecondLevelTabs();
            for (int secondaryIndex = 0; secondaryIndex < static_cast<int>(secondaryFeatureIds_.size()); ++secondaryIndex) {
                if (secondaryFeatureIds_[static_cast<std::size_t>(secondaryIndex)] == featureId) {
                    ::SendMessageW(secondaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(secondaryIndex), 0);
                    SelectCurrentFeature();
                    return true;
                }
            }
            SelectCurrentFeature();
            return true;
        }
    }
    hasDirectFeatureId_ = true;
    directFeatureId_ = featureId;
    ::SendMessageW(primaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(-1), 0);
    ::SendMessageW(secondaryTab_, TCM_DELETEALLITEMS, 0, 0);
    secondaryFeatureIds_.clear();
    SelectCurrentFeature();
    Layout();
    return true;
}

void KernelPage::RebuildSecondLevelTabs() {
    ::SendMessageW(secondaryTab_, TCM_DELETEALLITEMS, 0, 0);
    secondaryFeatureIds_.clear();
    const int primary = CurrentPrimaryIndex();
    if (primary < 0 || primary >= static_cast<int>(primaryFeatureIds_.size())) {
        ClearResultTable();
        Layout();
        return;
    }
    const KernelFeatureId primaryFeatureId = primaryFeatureIds_[static_cast<std::size_t>(primary)];
    int tabIndex = 0;
    for (const ObjectNamespaceTabSpec& spec : SecondaryTabsForPrimary(primaryFeatureId)) {
        if (FeatureById(spec.featureId) != nullptr) {
            secondaryFeatureIds_.push_back(spec.featureId);
            SetTabText(secondaryTab_, tabIndex++, spec.title);
        }
    }
    if (tabIndex > 0) {
        int selectedSecondary = 0;
        const auto remembered = lastSecondaryFeatureByPrimary_.find(primaryFeatureId);
        if (remembered != lastSecondaryFeatureByPrimary_.end()) {
            for (int index = 0; index < static_cast<int>(secondaryFeatureIds_.size()); ++index) {
                if (secondaryFeatureIds_[static_cast<std::size_t>(index)] == remembered->second) {
                    selectedSecondary = index;
                    break;
                }
            }
        }
        ::SendMessageW(secondaryTab_, TCM_SETCURSEL, static_cast<WPARAM>(selectedSecondary), 0);
    }
    Layout();
}

void KernelPage::OnFeatureSelectionChanged() {
    SelectCurrentFeature();
}

void KernelPage::SelectCurrentFeature() {
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (!descriptor) {
        ClearResultTable();
        return;
    }
    if (hasActiveFeatureId_ && activeFeatureId_ == descriptor->id) {
        ConfigureVisibleLayout();
        return;
    }
    if (const int primary = CurrentPrimaryIndex(); primary >= 0 && primary < static_cast<int>(primaryFeatureIds_.size())) {
        lastSecondaryFeatureByPrimary_[primaryFeatureIds_[static_cast<std::size_t>(primary)]] = descriptor->id;
    }
    verticalSplitterOffset_ = -1;
    verticalSplitterRect_ = {};
    ConfigureToolbarForDescriptor(*descriptor);
    if (!RestoreFeatureViewCache(descriptor->id)) {
        RenderDescriptor(*descriptor);
    }
    activeFeatureId_ = descriptor->id;
    hasActiveFeatureId_ = true;
    ConfigureVisibleLayout();
}

void KernelPage::ParkCurrentFeatureViewCache() {
    // ParkCurrentFeatureViewCache moves the currently visible feature buffers
    // into the retained cache before tab selection points at another feature.
    // Input is the activeFeatureId_ state; processing is skipped when no page is
    // active or when the live buffers are already empty; no value is returned.
    if (!hasActiveFeatureId_ ||
        (currentColumns_.empty() && currentRows_.empty() && currentRawColumns_.empty() && currentRawRows_.empty())) {
        return;
    }
    SaveCurrentFeatureViewCache(true);
}

void KernelPage::RefreshSelectedFeature() {
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (!descriptor) {
        return;
    }
    activeFeatureId_ = descriptor->id;
    hasActiveFeatureId_ = true;
    KernelRequest request = BuildCurrentRequest(descriptor->id);
    if (!queryTask_) {
        const KernelOperationResult result = facade_.QueryFeature(request);
        RenderResult(result);
        InvalidateCurrentFeatureViewCache();
        return;
    }
    const KernelFeatureId featureId = descriptor->id;
    const std::uint64_t requestId = ++queryRequestId_;
    if (statusText_) {
        ::SetWindowTextW(statusText_, queryTask_->running()
            ? L"正在排队后台内核查询…"
            : L"正在后台查询内核快照…");
    }
    ::EnableWindow(refreshButton_, FALSE);
    queryTask_->request(
        [request] {
            KernelFacade facade;
            return facade.QueryFeature(request);
        },
        [this, featureId, requestId](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) {
            ::EnableWindow(refreshButton_, TRUE);
            const KernelFeatureDescriptor* current = CurrentDescriptor();
            if (error || !result.has_value()) {
                if (requestId == queryRequestId_ && current && current->id == featureId && statusText_) {
                    ::SetWindowTextW(statusText_, L"内核后台查询异常结束，已保留当前结果。");
                }
                return;
            }
            if (requestId != queryRequestId_ || !current || current->id != featureId) {
                return;
            }
            RenderResult(*result);
            InvalidateCurrentFeatureViewCache();
        });
}

void KernelPage::SaveCurrentFeatureViewCache(const bool transferDataToCache) {
    // SaveCurrentFeatureViewCache stores the currently rendered page under the
    // last active feature id rather than CurrentDescriptor(). Inputs select
    // whether the large row buffers should be transferred into the cache. Tab
    // switches pass true so rows are moved instead of copied; in-place refresh,
    // sort, and filter paths pass false and only update lightweight UI state.
    // There is no return value.
    if (!hasActiveFeatureId_) {
        return;
    }
    const KernelFeatureId cacheFeatureId = activeFeatureId_;
    KernelFeatureViewCache& cache = featureViewCache_[cacheFeatureId];
    if (transferDataToCache) {
        cache.columns = std::move(currentColumns_);
        cache.rows = std::move(currentRows_);
        cache.rowIndents = std::move(currentRowIndents_);
        cache.rawColumns = std::move(currentRawColumns_);
        cache.rawRows = std::move(currentRawRows_);
        cache.collapsedObjectPaths = std::move(collapsedObjectPaths_);
        cache.propertyRows = CaptureReportListRows(propertyList_);
        cache.summaryRows = CaptureReportListRows(summaryList_);
    }
    cache.filterText = WindowText(filterEdit_);
    cache.moduleFilterText = WindowText(moduleFilterEdit_);
    cache.objectNamespaceSelectedRow = objectNamespaceSelectedRow_;
    cache.objectNamespaceSelectedKind = objectNamespaceSelectedKind_;
    cache.objectNamespaceSelectedPath = objectNamespaceSelectedPath_;
    cache.objectNamespaceSelectedDescription = objectNamespaceSelectedDescription_;
    cache.sortColumn = sortColumn_;
    cache.sortAscending = sortAscending_;
    cache.selectedRow = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    cache.topRow = resultList_ ? ListView_GetTopIndex(resultList_) : 0;
    if (transferDataToCache) {
        cache.hasData = !cache.columns.empty() || !cache.rows.empty() || !cache.rawRows.empty();
    }
    if (detailEdit_) {
        cache.detailText = WindowText(detailEdit_);
    }
    if (statusText_) {
        cache.statusText = WindowText(statusText_);
    }
    if (transferDataToCache) {
        ClearResultGridOnly();
    }
}

void KernelPage::InvalidateCurrentFeatureViewCache() {
    // InvalidateCurrentFeatureViewCache drops any stale parked snapshot for the
    // currently active feature after refresh/filter/sort mutates the live
    // buffers. Inputs are the current activeFeatureId_ state; processing keeps
    // the live page untouched and only marks the cached parked copy unusable;
    // no value is returned.
    if (!hasActiveFeatureId_) {
        return;
    }
    auto found = featureViewCache_.find(activeFeatureId_);
    if (found == featureViewCache_.end()) {
        return;
    }
    found->second.hasData = false;
    found->second.columns.clear();
    found->second.rows.clear();
    found->second.rowIndents.clear();
    found->second.rawColumns.clear();
    found->second.rawRows.clear();
    found->second.collapsedObjectPaths.clear();
    found->second.propertyRows.clear();
    found->second.summaryRows.clear();
}

bool KernelPage::RestoreFeatureViewCache(const KernelFeatureId featureId) {
    // If the requested page is still resident in the current buffers, keep it
    // live instead of moving from the cache. This covers repeated selection or
    // control-notification noise and avoids a needless ListView reset.
    if (hasActiveFeatureId_ && activeFeatureId_ == featureId && (!currentColumns_.empty() || !currentRows_.empty() || !currentRawRows_.empty())) {
        return true;
    }

    auto found = featureViewCache_.find(featureId);
    if (found == featureViewCache_.end() || !found->second.hasData) {
        return false;
    }

    KernelFeatureViewCache& cache = found->second;
    currentColumns_ = std::move(cache.columns);
    currentRows_ = std::move(cache.rows);
    currentRowIndents_ = std::move(cache.rowIndents);
    currentRawColumns_ = std::move(cache.rawColumns);
    currentRawRows_ = std::move(cache.rawRows);
    collapsedObjectPaths_ = std::move(cache.collapsedObjectPaths);
    objectNamespaceSelectedRow_ = cache.objectNamespaceSelectedRow;
    objectNamespaceSelectedKind_ = cache.objectNamespaceSelectedKind;
    objectNamespaceSelectedPath_ = cache.objectNamespaceSelectedPath;
    objectNamespaceSelectedDescription_ = cache.objectNamespaceSelectedDescription;
    sortColumn_ = cache.sortColumn;
    sortAscending_ = cache.sortAscending;
    struct ScopedFilterChangeSuppressor {
        bool& flag;
        explicit ScopedFilterChangeSuppressor(bool& target) : flag(target) { flag = true; }
        ~ScopedFilterChangeSuppressor() { flag = false; }
    } suppressor(suppressFilterChange_);
    if (filterEdit_) {
        ::SetWindowTextW(filterEdit_, cache.filterText.c_str());
    }
    if (moduleFilterEdit_) {
        ::SetWindowTextW(moduleFilterEdit_, cache.moduleFilterText.c_str());
    }

    ClearResultGridOnly();
    EnsureResultColumnsForCurrentFeature();
    SyncResultListVirtualRows();
    RestoreReportListRows(propertyList_, cache.propertyRows);
    RestoreReportListRows(summaryList_, cache.summaryRows);
    if (featureId == KernelFeatureId::ObjectNamespaceOverview || featureId == KernelFeatureId::ObjectDirectoryRecursive) {
        const bool treeMatchesPage = hasObjectNamespaceTreeFeatureId_ && objectNamespaceTreeFeatureId_ == featureId;
        if (!objectNamespaceTree_ || TreeView_GetCount(objectNamespaceTree_) == 0 || !treeMatchesPage) {
            RebuildObjectNamespaceTreeFromCurrentRows();
        }
    }
    if (statusText_) {
        ::SetWindowTextW(statusText_, cache.statusText.empty() ? L"状态：已恢复缓存。": cache.statusText.c_str());
    }
    if (detailEdit_) {
        ::SetWindowTextW(detailEdit_, cache.detailText.c_str());
    }
    if (!currentRows_.empty()) {
        const int selected = cache.selectedRow >= 0 && cache.selectedRow < static_cast<int>(currentRows_.size())
            ? cache.selectedRow
            : 0;
        const int topRow = std::max(0, std::min(cache.topRow, static_cast<int>(currentRows_.size()) - 1));
        ListView_SetItemState(resultList_, selected, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        if (topRow > 0) {
            ListView_EnsureVisible(resultList_, topRow, FALSE);
        } else {
            ListView_EnsureVisible(resultList_, selected, FALSE);
        }
    }
    cache.hasData = false;
    return true;
}

void KernelPage::ResetVisibleResultRows() {
    currentRows_.clear();
    currentRowIndents_.clear();
    SyncResultListVirtualRows();
}

void KernelPage::SyncResultListVirtualRows() {
    if (!resultList_) {
        return;
    }
    const int rows = static_cast<int>(std::min<std::size_t>(currentRows_.size(), static_cast<std::size_t>(std::numeric_limits<int>::max())));
    ListView_SetItemCountEx(resultList_, rows, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    if (rows == 0) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ::InvalidateRect(resultList_, nullptr, FALSE);
}

std::vector<std::vector<std::wstring>> KernelPage::CaptureReportListRows(HWND list) const {
    // CaptureReportListRows snapshots small auxiliary report controls such as
    // propertyList_ and summaryList_. Input is a ListView HWND; processing reads
    // visible cell text only; output is a row-major text table. It deliberately
    // is not used for resultList_, which is owner-data and can be huge.
    std::vector<std::vector<std::wstring>> rows;
    if (!list) {
        return rows;
    }
    const int rowCount = ListView_GetItemCount(list);
    const int columnCount = HeaderColumnCount(list);
    rows.reserve(static_cast<std::size_t>(std::max(0, rowCount)));
    for (int row = 0; row < rowCount; ++row) {
        std::vector<std::wstring> cells;
        cells.reserve(static_cast<std::size_t>(std::max(0, columnCount)));
        for (int column = 0; column < columnCount; ++column) {
            cells.push_back(ListViewText(list, row, column));
        }
        rows.push_back(std::move(cells));
    }
    return rows;
}

void KernelPage::RestoreReportListRows(HWND list, const std::vector<std::vector<std::wstring>>& rows) {
    // RestoreReportListRows restores small auxiliary report controls after a
    // tab switch. Inputs are the target ListView and cached text rows;
    // processing bulk-inserts rows under a redraw lock; no value is returned.
    if (!list) {
        return;
    }
    Ksword::Ui::ScopedListViewRedrawLock redrawLock(list);
    ListView_DeleteAllItems(list);
    for (const std::vector<std::wstring>& row : rows) {
        ListViewInsertRow(list, row);
    }
}

void KernelPage::EnsureResultColumnsForCurrentFeature() {
    // EnsureResultColumnsForCurrentFeature syncs the owner-data ListView header
    // with currentColumns_. Inputs are the active feature and cached schema;
    // processing recreates only columns, never rows, so tab restore and sorting
    // stay lightweight. There is no return value.
    if (!resultList_) {
        return;
    }
    HWND header = ListView_GetHeader(resultList_);
    const int count = header ? Header_GetItemCount(header) : 0;
    for (int index = count - 1; index >= 0; --index) {
        ListView_DeleteColumn(resultList_, index);
    }

    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    const auto isObjectHiddenColumn = [](const std::wstring& name) {
        return name == L"Parent" ||
            name == L"Source" ||
            name == L"Directory" ||
            name == L"directoryPath" ||
            name == L"sourceDirectory" ||
            name == L"Depth" ||
            name == L"Path" ||
            name == L"NtPath" ||
            name == L"Target" ||
            name == L"Win32Path" ||
            name == L"dosCandidate" ||
            name == L"fullPath" ||
            name == L"targetPath" ||
            name == L"symbolicTarget" ||
            name == L"objectName" ||
            name == L"objectType" ||
            name == L"linkName" ||
            name == L"Handles" ||
            name == L"Pointers" ||
            name == L"EnumApi" ||
            name == L"enumApi" ||
            name == L"枚举 API" ||
            name == L"EnumerationApi" ||
            name == L"NodeKind" ||
            name == L"Detail";
    };
    const auto isDiagnosticHiddenColumn = [](const std::wstring& name) {
        return name == L"Id" ||
            name == L"StateId" ||
            name == L"SourceIndex" ||
            name == L"StatusFlags" ||
            name == L"CapabilityMask" ||
            name == L"Version" ||
            name == L"Protocol" ||
            name == L"ExpectedProtocol" ||
            name == L"SecurityPolicy" ||
            name == L"DynDataStatus" ||
            name == L"DynDataCapability" ||
            name == L"FeatureTotal" ||
            name == L"FeatureReturned" ||
            name == L"LastError" ||
            name == L"LastErrorSummary" ||
            name == L"LastErrorStatus" ||
            name == L"Class" ||
            name == L"Source" ||
            name == L"Callback" ||
            name == L"Context" ||
            name == L"Registration" ||
            name == L"ModulePath" ||
            name == L"Win32ModulePath" ||
            name == L"ModuleBase" ||
            name == L"ModuleSize" ||
            name == L"OperationMask" ||
            name == L"ObjectTypeMask" ||
            name == L"FieldFlags" ||
            name == L"Trust" ||
            name == L"Remove" ||
            name == L"RemoveFlags" ||
            name == L"Generation" ||
            name == L"IdentityHash" ||
            name == L"RawStorageValue" ||
            name == L"LastStatus" ||
            name == L"Detail";
    };

    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        bool hidden = false;
        if (descriptor != nullptr) {
            if (IsObjectNamespaceFeature(descriptor->id)) {
                hidden = isObjectHiddenColumn(name);
            } else if (IsKernelHookFeature(descriptor->id)) {
                hidden = !IsKernelHookVisibleColumn(descriptor->id, name);
            } else if (descriptor->id == KernelFeatureId::DynData ||
                descriptor->id == KernelFeatureId::DriverStatus ||
                descriptor->id == KernelFeatureId::CallbackEnumeration) {
                hidden = isDiagnosticHiddenColumn(name);
            } else if (descriptor->id == KernelFeatureId::KernelExecutableMemory ||
                descriptor->id == KernelFeatureId::KernelMemoryEvidence) {
                hidden = IsKernelMemoryHiddenColumn(name);
            } else if (descriptor->id == KernelFeatureId::DriverIntegrity ||
                descriptor->id == KernelFeatureId::KernelCpuIntegrity) {
                const bool canonicalColumn = HasColumn(CanonicalColumnNames(descriptor->id), name);
                hidden = !canonicalColumn && IsIntegrityHiddenColumn(name);
            }
        }
        AddResultTableColumn(static_cast<int>(index), name, hidden ? 0 : ColumnWidth(name));
    }
}

std::wstring KernelPage::ResultCellText(const int row, const int column) const {
    if (row < 0 || column < 0 ||
        row >= static_cast<int>(currentRows_.size()) ||
        column >= static_cast<int>(currentRows_[static_cast<std::size_t>(row)].size())) {
        return {};
    }
    return currentRows_[static_cast<std::size_t>(row)][static_cast<std::size_t>(column)];
}

std::wstring KernelPage::VisibleCellText(const int row, const int column) const {
    // VisibleCellText reads the current owner-data table cache. Inputs are
    // visible row and column indexes; output is the displayed string or empty
    // for invalid coordinates.
    return ResultCellText(row, column);
}

void KernelPage::LocateNextResult() {
    // LocateNextResult finds the next visible result row containing the generic
    // filter text. Inputs are current ListView rows and filter edit text;
    // processing wraps after the last row; output is ListView selection/focus.
    if (!resultList_) {
        return;
    }
    const std::wstring needle = WindowText(filterEdit_);
    if (needle.empty()) {
        return;
    }
    const int rowCount = ListView_GetItemCount(resultList_);
    const int columnCount = HeaderColumnCount(resultList_);
    if (rowCount <= 0 || columnCount <= 0) {
        return;
    }
    int start = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    start = start < 0 ? 0 : (start + 1) % rowCount;
    for (int step = 0; step < rowCount; ++step) {
        const int row = (start + step) % rowCount;
        bool matched = false;
        for (int column = 0; column < columnCount; ++column) {
            if (ContainsCaseInsensitive(VisibleCellText(row, column), needle)) {
                matched = true;
                break;
            }
        }
        if (matched) {
            ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_SetItemState(resultList_, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, row, FALSE);
            UpdateSelectedRowDetail();
            return;
        }
    }
}

KernelRequest KernelPage::BuildCurrentRequest(const KernelFeatureId featureId) const {
    // BuildCurrentRequest is the single UI-to-facade request mapper. Inputs are
    // the selected feature id plus current edit-control values; processing keeps
    // generic filters available to all R3 pages and module filters available to
    // R0 hook scans; return is a value object with no HWND lifetime dependency.
    KernelRequest request;
    request.featureId = featureId;
    request.filterText = WindowText(filterEdit_);
    request.moduleFilterText = WindowText(moduleFilterEdit_);
    if (featureId == KernelFeatureId::NtQueryLegacy) {
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::SymbolicLink) {
        // SymbolicLink mirrors the original full tab: R3 returns the complete
        // snapshot, then the main and target filter edits are applied locally.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::NamedPipe ||
        featureId == KernelFeatureId::BaseNamedObjects ||
        featureId == KernelFeatureId::CommunicationEndpoint) {
        // These R3 object pages keep their original behavior: enumerate the full
        // backing namespace first, then let the visible toolbar controls filter
        // the cached rows. Keeping request filters empty prevents a stale edit
        // value from hiding rows before combo options/details are rebuilt.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::DriverIntegrity) {
        request.filterText = WindowText(integrityModuleBaseEdit_);
        request.moduleFilterText = WindowText(moduleFilterEdit_);
    }
    if (featureId == KernelFeatureId::KernelExecutableMemory ||
        featureId == KernelFeatureId::KernelMemoryEvidence) {
        if (riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED) {
            request.flags |= KernelRequestFlagRiskOnly;
        }
        if (featureId == KernelFeatureId::KernelMemoryEvidence) {
            if (evidenceIncludeNonModuleCheck_ && Button_GetCheck(evidenceIncludeNonModuleCheck_) == BST_CHECKED) {
                request.flags |= KernelRequestFlagIncludeNonModuleExecutableRanges;
            }
            ParseUnsigned64Value(WindowText(evidenceStartEdit_), request.startAddress);
            ParseUnsigned64Value(WindowText(evidenceEndEdit_), request.endAddress);
            request.maxRows = ParseUnsigned(WindowText(evidenceMaxRowsEdit_), 256);
        }
    }
    if (featureId == KernelFeatureId::DriverIntegrity ||
        featureId == KernelFeatureId::KernelCpuIntegrity) {
        request.maxRows = ParseUnsigned(WindowText(evidenceMaxRowsEdit_), 1024);
        request.idtVectorLimit = ParseUnsigned(WindowText(integrityIdtVectorsEdit_), 64);
    }
    if (featureId == KernelFeatureId::DeviceDriverObjects) {
        // Device/Driver Objects intentionally requests a full snapshot. The
        // keyword edit plus directory/type comboboxes are local filters applied
        // after data arrives, matching the original full KernelDock tab behavior.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::ObjectTypeMatrix) {
        // Object Type Matrix also mirrors the original tab: NtQueryObject returns
        // the whole object-type table, and the edit box only filters the already
        // loaded rows locally. The request therefore carries no remote filter.
        request.filterText.clear();
        request.moduleFilterText.clear();
    }
    if (featureId == KernelFeatureId::ObjectDirectoryRecursive) {
        const std::uint32_t depth = ParseUnsigned(WindowText(moduleFilterEdit_), 4);
        request.moduleFilterText = std::to_wstring(std::min<std::uint32_t>(depth, 32));
    }
    request.flags |= CurrentIncludeFlags();
    return request;
}

void KernelPage::ExecuteObjectNamespaceToolbarAction() {
    // ExecuteObjectNamespaceToolbarAction mirrors the per-page small toolbar
    // action in the original R3 object-namespace tabs. Inputs are current
    // feature/selection; processing dispatches to copy/filter helpers; no value
    // is returned because the effect is UI state or clipboard text.
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr) {
        return;
    }
    switch (descriptor->id) {
    case KernelFeatureId::ObjectDirectoryRecursive:
        RefreshSelectedFeature();
        break;
    case KernelFeatureId::NamedPipe:
        CopyPreferredSelectedField({ L"Pipe", L"Pipe Name", L"Name", L"objectName" }, L"状态：已复制命名管道名称。");
        break;
    case KernelFeatureId::DeviceDriverObjects:
        ExportAllRowsTsv();
        break;
    case KernelFeatureId::ObjectTypeMatrix:
        CopyPreferredSelectedField({ L"类型名", L"Type", L"objectType" }, L"状态：已复制对象类型名。");
        break;
    case KernelFeatureId::CommunicationEndpoint:
        CopyPreferredSelectedField({ L"完整路径", L"fullPath", L"Path" }, L"状态：已复制通信端点完整路径。");
        break;
    case KernelFeatureId::BaseNamedObjects:
        CopyPreferredSelectedField({ L"fullPath", L"Path", L"完整路径" }, L"状态：已复制 BaseNamedObjects 完整路径。");
        break;
    case KernelFeatureId::SymbolicLink:
        CopyPreferredSelectedField({ L"targetPath", L"symbolicTarget", L"Target", L"目标路径", L"符号链接目标" }, L"状态：已复制符号链接目标。");
        break;
    default:
        LocateNextResult();
        break;
    }
}

void KernelPage::ExecuteObjectNamespaceDetailAction() {
    // ExecuteObjectNamespaceDetailAction mirrors the extra toolbar button on the
    // original object-namespace pages. Inputs are current page/selection; output
    // is either copied TSV/DOS text or refreshed detail text.
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr) {
        return;
    }
    switch (descriptor->id) {
    case KernelFeatureId::NamedPipe:
        ExecuteSelectedAction(KernelActionId::NativeNamedPipeProbe);
        break;
    case KernelFeatureId::SymbolicLink:
        ExecuteSelectedAction(KernelActionId::NativeSymbolicLinkResolve);
        break;
    case KernelFeatureId::DeviceDriverObjects:
        ExecuteSelectedAction(KernelActionId::NativeObjectQueryDetail);
        break;
    case KernelFeatureId::ObjectTypeMatrix:
        ApplySelectedTypeFilter();
        break;
    case KernelFeatureId::CommunicationEndpoint:
        ExecuteSelectedAction(KernelActionId::NativeObjectQueryDetail);
        break;
    case KernelFeatureId::BaseNamedObjects:
        ExecuteSelectedAction(KernelActionId::NativeObjectQueryDetail);
        break;
    default:
        CopyDiagnosticReport();
        break;
    }
}

void KernelPage::FillIntegrityInputsFromSelection() {
    // FillIntegrityInputsFromSelection mirrors the original DriverDock helper in
    // a page-local way. Inputs are the currently selected evidence row; processing
    // copies any driver-object path and module-base value into the query edits;
    // there is no return value because the visible controls are updated directly.
    const std::wstring driverObject = FirstSelectedRowField({
        L"DriverObject", L"DriverName", L"完整路径", L"fullPath", L"Path", L"Name"
    });
    const std::wstring moduleBase = FirstSelectedRowField({
        L"OwnerModuleBase", L"OwnerBase", L"ModuleBase"
    });

    bool updated = false;
    if (!driverObject.empty() && (ContainsCaseInsensitive(driverObject, L"\\Driver\\") || driverObject[0] == L'\\')) {
        ::SetWindowTextW(moduleFilterEdit_, driverObject.c_str());
        updated = true;
    }
    if (!moduleBase.empty() && moduleBase != L"0" && moduleBase != L"0x0") {
        ::SetWindowTextW(integrityModuleBaseEdit_, moduleBase.c_str());
        updated = true;
    }
    ::SetWindowTextW(statusText_, updated
        ? L"状态：已从当前选中行填充 DriverObject/模块基址。"
        : L"状态：当前选中行没有可填充的 DriverObject 或模块基址。");
}

void KernelPage::RefreshKernelCpuIntegrityFromDriverPage() {
    // RefreshKernelCpuIntegrityFromDriverPage implements the original
    // DriverDock CPU-only button. Inputs are the current max-row/risk controls;
    // processing queries KernelCpuIntegrity through KernelFacade and renders the
    // evidence rows in the same table; there is no direct driver access here.
    KernelRequest request = BuildCurrentRequest(KernelFeatureId::KernelCpuIntegrity);
    if (!queryTask_) {
        const KernelOperationResult result = facade_.QueryFeature(request);
        RenderResult(result);
        ::SetWindowTextW(statusText_, (L"状态：CPU-only 完整性查询完成 | " + result.message).c_str());
        return;
    }
    const KernelFeatureId activeFeatureId = activeFeatureId_;
    const std::uint64_t requestId = ++queryRequestId_;
    ::SetWindowTextW(statusText_, L"状态：正在后台查询 CPU-only 完整性快照…");
    ::EnableWindow(refreshButton_, FALSE);
    queryTask_->request(
        [request] {
            KernelFacade facade;
            return facade.QueryFeature(request);
        },
        [this, activeFeatureId, requestId](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) {
            ::EnableWindow(refreshButton_, TRUE);
            if (error || !result.has_value() || requestId != queryRequestId_ || activeFeatureId_ != activeFeatureId) {
                if (requestId == queryRequestId_ && activeFeatureId_ == activeFeatureId) {
                    ::SetWindowTextW(statusText_, L"状态：CPU-only 后台完整性查询异常结束。");
                }
                return;
            }
            RenderResult(*result);
            ::SetWindowTextW(statusText_, (L"状态：CPU-only 完整性查询完成 | " + result->message).c_str());
        });
}

KernelActionRequest KernelPage::BuildCurrentActionRequest(const KernelActionId actionId) const {
    // BuildCurrentActionRequest copies the selected result row into a value-only
    // packet. Inputs are the current feature, edit filters, selected row, and
    // action id; processing deliberately stores only text fields so this UI layer
    // never owns driver handles or protocol structs; output is consumed by facade.
    KernelActionRequest request;
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor != nullptr) {
        request.featureId = descriptor->id;
    }
    request.actionId = actionId;
    request.filterText = WindowText(filterEdit_);
    request.moduleFilterText = WindowText(moduleFilterEdit_);

    const int row = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    if (row >= 0) {
        const int columns = HeaderColumnCount(resultList_);
        for (int column = 0; column < columns; ++column) {
            const std::wstring name = column < static_cast<int>(currentColumns_.size())
                ? currentColumns_[static_cast<std::size_t>(column)]
                : std::wstring(L"Column ") + std::to_wstring(column);
            request.rowFields.push_back({ name, VisibleCellText(row, column) });
        }
        if (row < static_cast<int>(currentRows_.size())) {
            const std::vector<std::wstring>& cachedRow = currentRows_[static_cast<std::size_t>(row)];
            for (int column = 0; column < static_cast<int>(currentColumns_.size()) && column < static_cast<int>(cachedRow.size()); ++column) {
                const std::wstring& name = currentColumns_[static_cast<std::size_t>(column)];
                const bool alreadyPresent = std::any_of(request.rowFields.begin(), request.rowFields.end(), [&](const auto& field) {
                    return _wcsicmp(field.first.c_str(), name.c_str()) == 0;
                });
                if (!alreadyPresent || (!cachedRow[static_cast<std::size_t>(column)].empty() && SelectedRowField(name).empty())) {
                    request.rowFields.push_back({ name, cachedRow[static_cast<std::size_t>(column)] });
                }
            }
        }
    }
    return request;
}

void KernelPage::ExecuteSelectedAction(const KernelActionId actionId) {
    if (actionTask_ && actionTask_->running()) {
        ::SetWindowTextW(statusText_, L"状态：内核动作正在后台执行，请等待当前结果。");
        return;
    }
    // ExecuteSelectedAction is the only UI entry for mutable kernel operations.
    // Inputs are the menu action id and current selection/filter text; processing
    // asks for confirmation, calls KernelFacade, optionally asks for force
    // confirmation on inline patch refusal, and renders the action result.
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr) {
        return;
    }

    KernelActionRequest request = BuildCurrentActionRequest(actionId);
    std::wstring confirmTitle = L"内核动作确认";
    std::wstring confirmText = L"确认执行该内核动作？";
    bool requireSelectedRow = true;

    switch (actionId) {
    case KernelActionId::InlineHookNopPatch:
        confirmTitle = L"Inline Hook NOP 摘除";
        confirmText =
            L"将通过 ArkDriverClient 对当前 Inline Hook 行发起 NOP 摘除请求。\n\n"
            L"函数: " + FirstSelectedRowValue({ L"Function", L"函数" }) + L"\n"
            L"地址: " + FirstSelectedRowValue({ L"Address", L"函数地址", L"目标地址" }) + L"\n"
            L"模块: " + FirstSelectedRowValue({ L"Module", L"ModulePath", L"模块" }) + L"\n\n"
            L"该操作可能修改内核代码页。是否继续？";
        break;
    case KernelActionId::CallbackCancelPendingDecisions:
        requireSelectedRow = false;
        confirmTitle = L"取消全部 Callback 等待决策";
        confirmText =
            L"将通过 ArkDriverClient::cancelAllPendingCallbackDecisions 通知 R0 取消当前所有等待用户回答的回调事件。\n\n"
            L"该操作会影响正在等待 AskUser 决策的回调请求；完成后会刷新运行态。是否继续？";
        break;
    case KernelActionId::CallbackApplyDisabledEmptyRules:
        requireSelectedRow = false;
        confirmTitle = L"应用禁用空 Callback 规则";
        confirmText =
            L"将构造一个有效的空规则 blob，并通过 ArkDriverClient::setCallbackRules 应用到 R0。\n\n"
            L"规则组数和规则数均为 0，globalEnabled 为 false。该操作相当于禁用当前回调规则集，"
            L"并会改变 R0 callback runtime 的 ruleVersion。是否继续？";
        break;
    case KernelActionId::CallbackApplyLocalRules:
        requireSelectedRow = false;
        request.moduleFilterText = SerializeCallbackLocalConfig();
        confirmTitle = L"应用本地 Callback 规则";
        confirmText =
            L"将把当前 Win32 规则组/规则编辑器内容编译为 KSWORD_ARK_CALLBACK_RULE_BLOB，"
            L"并通过 ArkDriverClient::setCallbackRules 应用到 R0。\n\n"
            L"规则组数: " + std::to_wstring(callbackGroups_.size()) + L"\n"
            L"规则数: " + std::to_wstring(callbackRules_.size()) + L"\n\n"
            L"该操作会改变 R0 callback runtime 的 ruleVersion。是否继续？";
        break;
    case KernelActionId::CallbackSafeRemove:
        confirmTitle = L"Callback 安全移除";
        confirmText =
            L"将通过 ArkDriverClient::removeExternalCallbackEx 的公开 API 路径移除当前回调。\n\n"
            L"名称: " + FirstSelectedRowValue({ L"Name", L"名称" }) + L"\n"
            L"地址: " + SelectedRowField(L"Callback") + L"\n"
            L"模块: " + FirstSelectedRowValue({ L"ModulePath", L"Module", L"模块" }) + L"\n\n"
            L"不会使用 experimental unlink。是否继续？";
        break;
    case KernelActionId::MinifilterSetBypassPids:
        requireSelectedRow = false;
        confirmTitle = L"设置 Minifilter 放行 PID";
        confirmText =
            L"将把“过滤/起点”输入框中的 PID 列表写入 R0 minifilter bypass 白名单。\n\n"
            L"PID 列表: " + request.filterText + L"\n\n"
            L"示例格式: 1234,5678。是否继续？";
        break;
    case KernelActionId::MinifilterClearBypassPids:
        requireSelectedRow = false;
        confirmTitle = L"清空 Minifilter 放行 PID";
        confirmText = L"将清空 R0 minifilter bypass PID 白名单。是否继续？";
        break;
    case KernelActionId::NetworkCaptureStart:
        requireSelectedRow = false;
        confirmTitle = L"启动逐包捕获";
        confirmText =
            L"将通过 ArkDriverClient::controlNetworkTrafficCapture 启动 R0 WFP 逐包采集。\n\n"
            L"采集环是固定大小的非分页缓冲，不会无限增长；代价是 WFP callout 会对每个报文做一次拷贝，"
            L"高流量时有可测量的开销。是否继续？";
        break;
    case KernelActionId::NetworkCaptureStop:
        requireSelectedRow = false;
        confirmTitle = L"停止逐包捕获";
        confirmText =
            L"将停止 R0 WFP 逐包采集。已在环中的报文仍然保留、仍可读取，只是不再有新报文进入。\n\n"
            L"是否继续？";
        break;
    case KernelActionId::DriverDispatchRestore:
        confirmTitle = L"恢复驱动派遣槽";
        confirmText =
            L"将把选中 MajorFunction 槽位写回本驱动记录的原始地址。\n\n"
            L"槽位: " + FirstSelectedRowValue({ L"MajorFunction" }) + L"\n"
            L"当前值: " + FirstSelectedRowValue({ L"Current" }) + L"\n"
            L"原始值: " + FirstSelectedRowValue({ L"Original" }) + L"\n\n"
            L"R0 会先核对代次与 DriverObject 身份；期间若被他人改写过则直接拒绝，"
            L"不会覆盖。是否继续？";
        break;
    case KernelActionId::DriverDispatchAbandon:
        confirmTitle = L"放弃派遣恢复记录";
        confirmText =
            L"将永久丢弃该 MajorFunction 槽位的恢复记录，内核中的当前值保持不变。\n\n"
            L"槽位: " + FirstSelectedRowValue({ L"MajorFunction" }) + L"\n"
            L"当前值: " + FirstSelectedRowValue({ L"Current" }) + L"\n"
            L"原始值: " + FirstSelectedRowValue({ L"Original" }) + L"\n\n"
            L"此操作不改内核状态，但之后将再也无法把该槽位恢复回原值。是否继续？";
        break;
    case KernelActionId::DriverImageRestore:
        confirmTitle = L"恢复驱动镜像字段";
        confirmText =
            L"将按该行的 ManagedFields 掩码，把本驱动改过的镜像字段写回原值，并恢复加载器链。\n\n"
            L"受管字段: " + FirstSelectedRowValue({ L"ManagedFields" }) + L"\n"
            L"冲突字段: " + FirstSelectedRowValue({ L"ConflictFields" }) + L"\n\n"
            L"冲突字段是已被第三方改写的部分，记录中的原值不再是它当时的值；"
            L"恢复会覆盖对方的写入。是否继续？";
        break;
    case KernelActionId::DriverImageAbandon:
        confirmTitle = L"放弃镜像恢复记录";
        confirmText =
            L"将永久丢弃该驱动镜像字段的恢复记录，当前值与链状态全部保持不变。\n\n"
            L"受管字段: " + FirstSelectedRowValue({ L"ManagedFields" }) + L"\n\n"
            L"此操作不改内核状态，但之后将再也无法恢复这些字段。是否继续？";
        break;
    case KernelActionId::DriverCommunicationRestore:
        confirmTitle = L"恢复驱动通信";
        confirmText =
            L"将把该驱动被指向系统拒绝入口的派遣槽恢复为其自身处理例程。\n\n"
            L"当前生效掩码: " + FirstSelectedRowValue({ L"ActiveMask" }) + L"\n"
            L"可恢复掩码: " + FirstSelectedRowValue({ L"OwnedMask" }) + L"\n"
            L"冲突掩码: " + FirstSelectedRowValue({ L"ConflictMask" }) + L"\n\n"
            L"只恢复可恢复掩码内的槽位；冲突槽位由他人改写，会被有意跳过。是否继续？";
        break;
    case KernelActionId::PiDdbDeleteEntry:
        confirmTitle = L"删除 PiDDB 条目";
        confirmText =
            L"将通过 ArkDriverClient::deletePiDdbEntry 从 PiDDBCacheTable 中移除选中记录。\n\n"
            L"驱动: " + FirstSelectedRowValue({ L"Driver", L"驱动" }) + L"\n"
            L"条目地址: " + FirstSelectedRowValue({ L"Entry", L"条目地址" }) + L"\n"
            L"时间戳: " + FirstSelectedRowValue({ L"TimeDateStamp", L"时间戳" }) + L"\n\n"
            L"该记录是加载器留下的「这个驱动曾在本机通过校验」的证据，删除后无法恢复，"
            L"也会改变取证结论。R0 会先核对该槽位是否仍与此处显示的一致，不一致则拒绝。是否继续？";
        break;
    case KernelActionId::FileMonitorStartFsctl:
        requireSelectedRow = false;
        confirmTitle = L"启动 FSCTL 文件监控";
        confirmText = L"将通过 ArkDriverClient 启动/补充 R0 文件监控 FSCTL/Oplock 事件掩码。是否继续？";
        break;
    case KernelActionId::FileMonitorDrain:
        requireSelectedRow = false;
        confirmTitle = L"拉取文件监控事件";
        confirmText = L"将从 R0 file-monitor ring buffer 拉取当前排队事件。是否继续？";
        break;
    case KernelActionId::FileMonitorClear:
        requireSelectedRow = false;
        confirmTitle = L"清空文件监控表格";
        confirmText = L"将清空 R0 file-monitor 队列并刷新当前表格。是否继续？";
        break;
    case KernelActionId::DriverObjectQueryDetail:
        confirmTitle = L"DriverObject 详情查询";
        confirmText =
            L"将通过 ArkDriverClient 查询当前行对应的 R0 DriverObject 详情。\n\n"
            L"DriverName: " + FirstSelectedRowValue({ L"DriverName", L"对象名称", L"Name" }) + L"\n"
            L"Path: " + FirstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath" }) + L"\n"
            L"Name: " + FirstSelectedRowValue({ L"Name", L"objectName", L"对象名称", L"名称" }) + L"\n\n"
            L"该操作只读取 DriverObject/MajorFunction/DeviceObject 信息。是否继续？";
        break;
    case KernelActionId::DriverObjectForceUnload:
        confirmTitle = L"DriverObject 强制卸载";
        confirmText =
            L"将通过 ArkDriverClient 请求 R0 强制卸载当前行对应的 DriverObject。\n\n"
            L"DriverName: " + FirstSelectedRowValue({ L"DriverName", L"对象名称", L"Name" }) + L"\n"
            L"Path: " + FirstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath" }) + L"\n"
            L"Name: " + FirstSelectedRowValue({ L"Name", L"objectName", L"对象名称", L"名称" }) + L"\n\n"
            L"该操作可能调用 DriverUnload、删除 DeviceObject 并清理相关回调。是否继续？";
        break;
    case KernelActionId::NativeObjectQueryDetail:
        confirmTitle = L"R3 对象详情";
        confirmText =
            L"将使用 NtOpenDirectoryObject/NtOpenSymbolicLinkObject/NtQueryObject 对当前行执行只读详情查询。\n\n"
            L"Path: " + FirstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath", L"NT Path" }) + L"\n"
            L"NtPath: " + FirstSelectedRowValue({ L"NtPath", L"NT Path", L"Path", L"fullPath", L"完整路径" }) + L"\n"
            L"Type: " + FirstSelectedRowValue({ L"Type", L"objectType", L"对象类型", L"类型", L"类型名" }) + L"\n\n"
            L"该操作不访问 R0 驱动，也不修改对象。是否继续？";
        break;
    case KernelActionId::NativeSymbolicLinkResolve:
        confirmTitle = L"符号链接解析";
        confirmText =
            L"将使用 NtOpenSymbolicLinkObject/NtQuerySymbolicLinkObject 重新解析当前符号链接。\n\n"
            L"Path: " + FirstSelectedRowValue({ L"Path", L"fullPath", L"完整路径", L"NtPath" }) + L"\n"
            L"Target: " + FirstSelectedRowValue({ L"Target", L"targetPath", L"symbolicTarget", L"目标路径", L"符号链接目标" }) + L"\n\n"
            L"该操作只读。是否继续？";
        break;
    case KernelActionId::NativeNamedPipeProbe:
        confirmTitle = L"命名管道打开验证";
        confirmText =
            L"将使用 NtOpenFile 以只读属性访问验证当前命名管道是否可打开。\n\n"
            L"NtPath: " + FirstSelectedRowValue({ L"NtPath", L"NT Path", L"Path", L"fullPath" }) + L"\n"
            L"Pipe: " + FirstSelectedRowValue({ L"Pipe", L"Pipe Name", L"Name", L"objectName" }) + L"\n\n"
            L"不会读写管道数据。是否继续？";
        break;
    case KernelActionId::DynDataApplyMatchedProfile:
        requireSelectedRow = false;
        confirmTitle = L"DynData Profile 应用";
        confirmText =
            L"将查询当前 R0 ntoskrnl identity，在本地 profiles\\ark_dyndata_pack_v4.json 中寻找精确匹配，"
            L"然后通过 ArkDriverClient 调用 applyDynDataProfile/Ex 写入驱动 DynData 状态。\n\n"
            L"该操作会改变 R0 DynData 字段来源，影响后续内核枚举、CrossView、回调和 DriverObject 解析。是否继续？";
        break;
    case KernelActionId::MutationCommitDryRun:
        confirmTitle = L"Mutation Commit Dry-run";
        confirmText =
            L"将对当前 Audit 行的 TransactionId 执行 ArkDriverClient::commitMutation dry-run。\n\n"
            L"Tx: " + FirstSelectedRowField({ L"Tx", L"TransactionId" }) + L"\n"
            L"Status: " + SelectedRowField(L"Status") + L"\n"
            L"TargetKind: " + SelectedRowField(L"TargetKind") + L"\n\n"
            L"该动作不会提交写入，只验证事务状态和风险。是否继续？";
        break;
    case KernelActionId::MutationRollbackDryRun:
        confirmTitle = L"Mutation Rollback Dry-run";
        confirmText =
            L"将对当前 Audit 行的 TransactionId 执行 ArkDriverClient::rollbackMutation dry-run。\n\n"
            L"Tx: " + FirstSelectedRowField({ L"Tx", L"TransactionId" }) + L"\n"
            L"Status: " + SelectedRowField(L"Status") + L"\n"
            L"TargetKind: " + SelectedRowField(L"TargetKind") + L"\n\n"
            L"该动作不会写回 before 快照，只验证能否回滚。是否继续？";
        break;
    case KernelActionId::MutationRollbackConfirmed:
        confirmTitle = L"Mutation Rollback 确认执行";
        confirmText =
            L"将对当前 Audit 行的 TransactionId 执行非 dry-run rollback，并带 UI_CONFIRMED 标志。\n\n"
            L"Tx: " + FirstSelectedRowField({ L"Tx", L"TransactionId" }) + L"\n"
            L"Address: " + SelectedRowField(L"Address") + L"\n"
            L"Bytes: " + SelectedRowField(L"Bytes") + L"\n\n"
            L"该操作会尝试把 R0 事务目标恢复到 before 快照。是否继续？";
        break;
    case KernelActionId::None:
    default:
        return;
    }

    if (requireSelectedRow && (!resultList_ || ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) < 0)) {
        ::MessageBoxW(hwnd_, L"请先选择一条结果行。", confirmTitle.c_str(), MB_OK | MB_ICONWARNING);
        return;
    }

    if (::MessageBoxW(hwnd_, confirmText.c_str(), confirmTitle.c_str(), MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        ::SetWindowTextW(statusText_, L"状态：用户取消内核动作。");
        return;
    }

    ExecuteActionInBackground(std::move(request), actionId, true);
}

void KernelPage::ExecuteActionInBackground(KernelActionRequest request, const KernelActionId actionId, const bool offerForcedRetry) {
    if (!actionTask_) {
        RenderResult(facade_.ExecuteAction(request));
        return;
    }
    const KernelFeatureId featureId = request.featureId;
    const std::uint64_t requestId = ++actionRequestId_;
    const KernelActionRequest retryRequest = request;
    ::SetWindowTextW(statusText_, L"状态：正在后台执行内核动作…");
    ::EnableWindow(refreshButton_, FALSE);
    actionTask_->request(
        [request] {
            KernelFacade facade;
            return facade.ExecuteAction(request);
        },
        [this, request = retryRequest, actionId, featureId, requestId, offerForcedRetry](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) mutable {
            ::EnableWindow(refreshButton_, TRUE);
            const KernelFeatureDescriptor* current = CurrentDescriptor();
            if (error || !result.has_value()) {
                if (requestId == actionRequestId_ && current && current->id == featureId) {
                    ::SetWindowTextW(statusText_, L"状态：内核后台动作异常结束，未覆盖当前结果。");
                }
                return;
            }
            if (requestId != actionRequestId_ || !current || current->id != featureId) {
                return;
            }
            bool forceRequired = false;
            if (offerForcedRetry && actionId == KernelActionId::InlineHookNopPatch && !result->success) {
                for (const KernelResultRow& row : result->rows) {
                    for (const auto& column : row.columns) {
                        if (column.first == L"Status" && column.second == kInlineHookForceRequiredStatusText) {
                            forceRequired = true;
                            break;
                        }
                    }
                    if (forceRequired) {
                        break;
                    }
                }
            }
            if (forceRequired) {
                const std::wstring forceText =
                    L"R0 拒绝了普通 Inline Hook NOP 请求并要求强制确认。\n\n"
                    L"地址: " + FirstSelectedRowValue({ L"Address", L"函数地址", L"目标地址" }) + L"\n"
                    L"模块: " + FirstSelectedRowValue({ L"Module", L"ModulePath", L"模块" }) + L"\n\n"
                    L"强制继续会修改内核代码页，只应在确认目标和当前字节无误时使用。是否强制继续？";
                if (::MessageBoxW(hwnd_, forceText.c_str(), L"强制 Inline Hook 摘除", MB_YESNO | MB_DEFBUTTON2 | MB_ICONERROR) == IDYES) {
                    request.force = true;
                    ExecuteActionInBackground(std::move(request), actionId, false);
                    return;
                }
            }
            RenderResult(*result);
        });
}

void KernelPage::RenderDescriptor(const KernelFeatureDescriptor& descriptor) {
    ::SetWindowTextW(titleText_, descriptor.title.c_str());
    ::SetWindowTextW(summaryText_, L"");
    ::SetWindowTextW(backendText_, L"");
    ::SetWindowTextW(statusText_, L"状态：等待刷新。");

    currentColumns_.clear();
    currentRows_.clear();
    currentRawColumns_.clear();
    currentRawRows_.clear();
    sortColumn_ = -1;
    sortAscending_ = true;
    ClearResultTable();
    ::SetWindowTextW(detailEdit_, EmptyDetailTextForFeature(descriptor.id));
    if (IsObjectNamespaceFeature(descriptor.id)) {
        const std::vector<std::wstring> columns = CanonicalColumnNames(descriptor.id);
        if (UsesObjectNamespaceTreeIndexColumn(descriptor.id)) {
            currentColumns_.push_back(L"#");
        }
        for (const std::wstring& column : columns) {
            currentColumns_.push_back(column);
        }
        if (!HasColumn(currentColumns_, L"Parent")) {
            currentColumns_.push_back(L"Parent");
        }
        if (!HasColumn(currentColumns_, L"Source")) {
            currentColumns_.push_back(L"Source");
        }
        if (!HasColumn(currentColumns_, L"Detail")) {
            currentColumns_.push_back(L"Detail");
        }
        RebuildObjectNamespaceListFromCache(descriptor.id);
        ::SetWindowTextW(statusText_, L"状态：等待刷新。");
        return;
    }

    const std::vector<std::wstring> columns = CanonicalColumnNames(descriptor.id);
    if (columns.empty()) {
        AddResultTableColumn(0, L"字段", 180);
        AddResultTableColumn(1, L"值", 520);
        return;
    }
    currentColumns_ = columns;
    for (std::size_t index = 0; index < columns.size(); ++index) {
        AddResultTableColumn(static_cast<int>(index), columns[index], ColumnWidth(columns[index]));
    }

    switch (descriptor.id) {
    case KernelFeatureId::AtomTable:
        ::SetWindowTextW(detailEdit_, L"请选择一条原子记录查看详情。");
        break;
    case KernelFeatureId::NtQueryLegacy:
        ::SetWindowTextW(detailEdit_, L"请选择一条 NtQuery 结果查看详情。");
        break;
    case KernelFeatureId::Ssdt:
        ::SetWindowTextW(detailEdit_, L"请选择一条 SSDT 记录查看详情。");
        break;
    case KernelFeatureId::ShadowSsdt:
        ::SetWindowTextW(detailEdit_, L"请选择一条 SSSDT 记录查看详情。");
        break;
    case KernelFeatureId::InlineHook:
        ::SetWindowTextW(detailEdit_, L"请选择一条 Inline Hook 记录查看详情。");
        break;
    case KernelFeatureId::IatEatHook:
        ::SetWindowTextW(detailEdit_, L"请选择一条 IAT/EAT 记录查看详情。");
        break;
    case KernelFeatureId::CallbackEnumeration:
        ::SetWindowTextW(detailEdit_, L"请选择一条回调遍历记录查看详情。");
        break;
    default:
        ::SetWindowTextW(detailEdit_, L"");
        break;
    }
}

void KernelPage::RenderResult(const KernelOperationResult& result) {
    Ksword::Ui::ScopedListViewRedrawLock resultListLock(resultList_);
    Ksword::Ui::ScopedListViewRedrawLock propertyListLock(propertyList_);
    Ksword::Ui::ScopedListViewRedrawLock summaryListLock(summaryList_);
    Ksword::Ui::ScopedWindowRedrawLock objectTreeLock(objectNamespaceTree_);
    std::vector<std::wstring> orderedColumns;
    AddDynamicResultColumns(result, orderedColumns);
    bool statusHandledBySpecializedRenderer = false;
    currentColumns_ = orderedColumns;
    currentRows_.clear();
    currentRawColumns_.clear();
    currentRawRows_.clear();
    sortColumn_ = -1;
    sortAscending_ = true;

    for (std::size_t rowIndex = 0; rowIndex < result.rows.size(); ++rowIndex) {
        AddDynamicResultRow(static_cast<int>(rowIndex), result.rows[rowIndex], orderedColumns);
    }
    currentRawColumns_ = currentColumns_;
    currentRawRows_ = currentRows_;
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id)) {
        RebuildObjectNamespaceListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::AtomTable) {
        RebuildAtomTableFromCache();
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::NtQueryLegacy) {
        RebuildNtQueryLegacyListFromCache();
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DynData || descriptor->id == KernelFeatureId::DriverStatus)) {
        RebuildDiagnosticDualTableFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackEnumeration) {
        RebuildCallbackEnumerationListFromCache();
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && IsKernelHookFeature(descriptor->id)) {
        RebuildKernelHookListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::KernelExecutableMemory ||
            descriptor->id == KernelFeatureId::KernelMemoryEvidence)) {
        RebuildKernelMemoryScanListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::ProcessCrossView ||
            descriptor->id == KernelFeatureId::ThreadCrossView)) {
        RebuildCrossViewListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DriverIntegrity ||
            descriptor->id == KernelFeatureId::KernelCpuIntegrity)) {
        RebuildIntegrityEvidenceListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::CpuHardwareSnapshot ||
            descriptor->id == KernelFeatureId::PhysicalMemoryLayout ||
            descriptor->id == KernelFeatureId::MutationAudit ||
            descriptor->id == KernelFeatureId::KeyboardHotkeys ||
             descriptor->id == KernelFeatureId::KeyboardHooks ||
             descriptor->id == KernelFeatureId::DynDataCapabilities ||
             descriptor->id == KernelFeatureId::MinifilterBypassPids ||
             descriptor->id == KernelFeatureId::KernelTimerDpc ||
             descriptor->id == KernelFeatureId::IoctlRegistry)) {
        RebuildR0EvidenceListFromCache(descriptor->id);
        statusHandledBySpecializedRenderer = true;
    } else {
        RebuildResultListFromCache();
    }
    ConfigureVisibleLayout();
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackIntercept) {
        PopulateCallbackInterceptPanel();
        statusHandledBySpecializedRenderer = true;
    }

    if (statusHandledBySpecializedRenderer) {
        InvalidateCurrentFeatureViewCache();
        return;
    }

    std::wostringstream status;
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor(); descriptor != nullptr && IsKernelHookFeature(descriptor->id)) {
        const auto rowValue = [](const std::vector<std::wstring>& row, const std::vector<std::wstring>& columns, std::initializer_list<const wchar_t*> names) -> std::wstring {
            return RowFieldByName(row, columns, names);
        };
        std::size_t unresolved = 0;
        std::size_t suspicious = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring statusText = rowValue(row, currentColumns_, { L"状态", L"Status" });
            if (ContainsCaseInsensitive(statusText, L"未解析")) {
                ++unresolved;
            }
            if (ContainsCaseInsensitive(statusText, L"Hook") ||
                ContainsCaseInsensitive(statusText, L"可疑") ||
                ContainsCaseInsensitive(statusText, L"不同") ||
                ContainsCaseInsensitive(statusText, L"异常")) {
                ++suspicious;
            }
        }
        if (descriptor->id == KernelFeatureId::Ssdt) {
            status << L"状态：已刷新 " << result.rows.size() << L" 项，未解析索引 " << unresolved << L" 项";
        } else if (descriptor->id == KernelFeatureId::ShadowSsdt) {
            status << L"状态：SSSDT 已刷新 " << result.rows.size() << L" 项，未解析索引 " << unresolved << L" 项";
        } else if (descriptor->id == KernelFeatureId::InlineHook) {
            status << L"状态：Inline Hook 扫描完成，可疑/差异 " << suspicious << L" 项，可见 " << result.rows.size() << L" 项";
        } else {
            status << L"状态：IAT/EAT 扫描完成，可疑 " << suspicious << L" 项，可见 " << result.rows.size() << L" 项";
        }
        status << L" | " << result.message;
    } else {
        status << L"状态：" << (result.success ? L"刷新完成" : L"刷新未完成")
               << L" | 支持: " << (result.supported ? L"是" : L"否")
               << L" | 行数: " << result.rows.size()
               << L" | " << result.message;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
}

void KernelPage::AddDynamicResultColumns(const KernelOperationResult& result, std::vector<std::wstring>& orderedColumns) {
    // AddDynamicResultColumns creates a useful table for heterogeneous kernel
    // workers. Inputs are the complete operation result; processing preserves
    // each worker's first-seen column order and keeps the original KernelDock
    // table schemas. Object-namespace tree-table pages use a private "#" helper
    // column for expansion; all other pages avoid synthetic row-number columns.
    orderedColumns.clear();
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor()) {
        if (IsObjectNamespaceFeature(descriptor->id) && UsesObjectNamespaceTreeIndexColumn(descriptor->id)) {
            orderedColumns.push_back(L"#");
        }
        for (const std::wstring& columnName : CanonicalColumnNames(descriptor->id)) {
            if (!HasColumn(orderedColumns, columnName)) {
                orderedColumns.push_back(columnName);
            }
        }
    }
    for (const KernelResultRow& row : result.rows) {
        for (const auto& column : row.columns) {
            if (!HasColumn(orderedColumns, column.first)) {
                orderedColumns.push_back(column.first);
            }
        }
    }
    if (!HasColumn(orderedColumns, L"Detail")) {
        orderedColumns.push_back(L"Detail");
    }

}

void KernelPage::AddDynamicResultRow(const int rowIndex, const KernelResultRow& resultRow, const std::vector<std::wstring>& orderedColumns) {
    // AddDynamicResultRow maps a key/value result packet onto the current table
    // schema. Inputs are the model row and ordered columns; processing fills
    // missing values with empty cells and only writes rowIndex into the private
    // object-namespace "#" helper column; there is no return value.
    std::vector<std::wstring> cells;
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    cells.reserve(orderedColumns.size());
    for (const std::wstring& columnName : orderedColumns) {
        if (columnName == L"#") {
            cells.push_back(std::to_wstring(rowIndex));
            continue;
        }
        if (columnName == L"Detail") {
            cells.push_back(resultRow.detailText);
            continue;
        }
        std::wstring value;
        std::vector<std::wstring> aliases = descriptor != nullptr
            ? ColumnAliases(descriptor->id, columnName)
            : std::vector<std::wstring>{ columnName };
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            auto found = std::find_if(resultRow.columns.begin(), resultRow.columns.end(), [&alias](const auto& column) {
                return _wcsicmp(column.first.c_str(), alias.c_str()) == 0;
            });
            if (found != resultRow.columns.end() && !found->second.empty()) {
                value = found->second;
                break;
            }
        }
        cells.push_back(std::move(value));
    }
    currentRows_.push_back(std::move(cells));
}

void KernelPage::RebuildResultListFromCache() {
    // RebuildResultListFromCache projects cached row data into the owner-data
    // ListView. Inputs are currentColumns_/currentRows_; processing rebuilds
    // only the column headers plus an in-memory visible-row vector, then exposes
    // the final row count with one ListView_SetItemCountEx call. It does not
    // return a value.
    const std::vector<std::vector<std::wstring>>& sourceRows = currentRows_;
    const std::vector<int>& sourceIndents = currentRowIndents_;
    ClearResultTable();
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    const bool objectNamespaceLayout = descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id);
    const auto isHiddenObjectColumn = [](const std::wstring& name) {
        return name == L"Parent" ||
            name == L"Source" ||
            name == L"Directory" ||
            name == L"directoryPath" ||
            name == L"sourceDirectory" ||
            name == L"Depth" ||
            name == L"Path" ||
            name == L"NtPath" ||
            name == L"Target" ||
            name == L"Win32Path" ||
            name == L"dosCandidate" ||
            name == L"fullPath" ||
            name == L"targetPath" ||
            name == L"symbolicTarget" ||
            name == L"objectName" ||
            name == L"objectType" ||
            name == L"linkName" ||
            name == L"Handles" ||
            name == L"Pointers" ||
            name == L"Detail";
    };
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const bool hiddenColumn =
            (objectNamespaceLayout && isHiddenObjectColumn(currentColumns_[index])) ||
            (descriptor != nullptr && IsKernelHookFeature(descriptor->id) && !IsKernelHookVisibleColumn(descriptor->id, currentColumns_[index]));
        const int width = hiddenColumn ? 0 : ColumnWidth(currentColumns_[index]);
        AddResultTableColumn(static_cast<int>(index), currentColumns_[index], width);
    }
    const std::wstring hookFilter = WindowText(filterEdit_);
    const std::wstring hookModuleFilter = WindowText(moduleFilterEdit_);
    const auto hookRowMatches = [&](const std::vector<std::wstring>& row) {
        if (descriptor == nullptr || !IsKernelHookFeature(descriptor->id)) {
            return true;
        }
        std::wstring merged;
        for (const std::wstring& value : row) {
            if (!merged.empty()) {
                merged += L" | ";
            }
            merged += value;
        }
        if (!hookFilter.empty() && !ContainsCaseInsensitive(merged, hookFilter)) {
            return false;
        }
        if ((descriptor->id == KernelFeatureId::InlineHook || descriptor->id == KernelFeatureId::IatEatHook) && !hookModuleFilter.empty()) {
            const std::wstring module = RowFieldByName(row, currentColumns_, { L"模块", L"Module", L"目标模块", L"TargetModule", L"导入模块", L"Import" });
            if (!ContainsCaseInsensitive(module, hookModuleFilter)) {
                return false;
            }
        }
        return true;
    };

    std::vector<std::vector<std::wstring>> visibleRows;
    std::vector<int> visibleIndents;
    visibleRows.reserve(sourceRows.size());
    visibleIndents.reserve(sourceRows.size());
    for (std::size_t sourceIndex = 0; sourceIndex < sourceRows.size(); ++sourceIndex) {
        const std::vector<std::wstring>& row = sourceRows[sourceIndex];
        if (descriptor != nullptr && IsKernelHookFeature(descriptor->id) &&
            !HasKernelHookDisplayValues(descriptor->id, currentColumns_, row)) {
            continue;
        }
        if (!hookRowMatches(row)) {
            continue;
        }
        visibleRows.push_back(row);
        visibleIndents.push_back(sourceIndex < sourceIndents.size() ? sourceIndents[sourceIndex] : 0);
    }
    currentRows_ = std::move(visibleRows);
    currentRowIndents_ = std::move(visibleIndents);
    SyncResultListVirtualRows();

    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_,
            descriptor != nullptr ? EmptyDetailTextForFeature(descriptor->id) : L"");
    }
}

void KernelPage::RebuildKernelHookListFromCache(const KernelFeatureId featureId) {
    // RebuildKernelHookListFromCache mirrors the original SSDT/SSSDT/Inline
    // Hook/IAT-EAT tables. Inputs are cached raw rows from KernelFacade plus
    // local filter controls; processing projects only the original visible
    // columns while preserving hidden protocol/detail cells for actions; output
    // is the ListView, detail pane, and status text.
    if (!resultList_ || !IsKernelHookFeature(featureId)) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring filterText = WindowText(filterEdit_);
    const std::wstring moduleFilterText = WindowText(moduleFilterEdit_);
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto addColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!HasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };
    const auto isMeaningful = [&](const std::vector<std::wstring>& row) {
        switch (featureId) {
        case KernelFeatureId::Ssdt:
        case KernelFeatureId::ShadowSsdt:
            return HasNonEmptyField(row, rawColumns, { L"Index", L"Name", L"ServiceName", L"Zw", L"Stub", L"Service", L"ServiceAddress" });
        case KernelFeatureId::InlineHook:
            return HasNonEmptyField(row, rawColumns, { L"Module", L"Function", L"Address", L"Target", L"CurrentBytes", L"DiskBytes" });
        case KernelFeatureId::IatEatHook:
            return HasNonEmptyField(row, rawColumns, { L"ClassText", L"Class", L"Module", L"Import", L"Function", L"Thunk", L"Current", L"Expected" });
        default:
            return false;
        }
    };
    const auto hiddenColumn = [&](const std::wstring& name) {
        if (HasColumn(CanonicalColumnNames(featureId), name)) {
            return false;
        }
        return true;
    };

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : CanonicalColumnNames(featureId)) {
        addColumnIfMissing(displayColumns, column.c_str());
    }
    for (const std::wstring& column : rawColumns) {
        addColumnIfMissing(displayColumns, column.c_str());
    }
    addColumnIfMissing(displayColumns, L"Detail");

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    std::size_t unresolvedRows = 0;
    std::size_t suspiciousRows = 0;
    std::size_t cleanRows = 0;
    std::size_t diskDiffRows = 0;
    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t rawTotal = FirstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t rawReturned = FirstNonZeroField(rawRow, rawColumns, { L"Returned" });
        if (rawTotal != 0) {
            reportedTotalRows = static_cast<std::size_t>(rawTotal);
        }
        if (rawReturned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(rawReturned);
        }
        if (!isMeaningful(rawRow)) {
            continue;
        }
        ++totalRows;

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail", L"FlagsText", L"DiskDiff", L"Status" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }

        const std::wstring merged = MergeRowText(cells) + L" | " + rawValue(rawRow, { L"Detail" });
        if (!filterText.empty() && !ContainsCaseInsensitive(merged, filterText)) {
            continue;
        }
        if ((featureId == KernelFeatureId::InlineHook || featureId == KernelFeatureId::IatEatHook) && !moduleFilterText.empty()) {
            const std::wstring moduleText =
                RowFieldByName(cells, displayColumns, { L"模块", L"Module" }) + L" | " +
                RowFieldByName(cells, displayColumns, { L"目标模块", L"TargetModule" }) + L" | " +
                RowFieldByName(cells, displayColumns, { L"导入模块", L"Import", L"ImportModule" });
            if (!ContainsCaseInsensitive(moduleText, moduleFilterText)) {
                continue;
            }
        }

        const std::wstring status = RowFieldByName(cells, displayColumns, { L"状态", L"Status" });
        const std::wstring diff = RowFieldByName(cells, displayColumns, { L"差异状态", L"差异", L"DiskDiff" });
        if (ContainsCaseInsensitive(status, L"未解析") ||
            ContainsCaseInsensitive(status, L"unresolved") ||
            RowFieldByName(cells, displayColumns, { L"索引", L"Index" }) == L"<未知>") {
            ++unresolvedRows;
        }
        if (ContainsCaseInsensitive(status, L"Hook") ||
            ContainsCaseInsensitive(status, L"可疑") ||
            ContainsCaseInsensitive(status, L"异常") ||
            ContainsCaseInsensitive(status, L"outside") ||
            ContainsCaseInsensitive(diff, L"不同") ||
            ContainsCaseInsensitive(diff, L"diff")) {
            ++suspiciousRows;
        } else if (!status.empty()) {
            ++cleanRows;
        }
        if (ContainsCaseInsensitive(diff, L"不同") || ContainsCaseInsensitive(diff, L"diff")) {
            ++diskDiffRows;
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    ClearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        int width = hiddenColumn(currentColumns_[index]) ? 0 : ColumnWidth(currentColumns_[index]);
        if (currentColumns_[index] == L"索引") {
            width = 90;
        } else if (currentColumns_[index] == L"服务名" || currentColumns_[index] == L"函数") {
            width = 260;
        } else if (currentColumns_[index] == L"Zw导出地址" ||
            currentColumns_[index] == L"Stub地址" ||
            currentColumns_[index] == L"表项地址" ||
            currentColumns_[index] == L"服务例程" ||
            currentColumns_[index] == L"函数地址" ||
            currentColumns_[index] == L"目标地址" ||
            currentColumns_[index] == L"Thunk/EAT项" ||
            currentColumns_[index] == L"当前目标" ||
            currentColumns_[index] == L"期望目标") {
            width = 170;
        } else if (currentColumns_[index] == L"模块" ||
            currentColumns_[index] == L"导入模块" ||
            currentColumns_[index] == L"目标模块") {
            width = 190;
        } else if (currentColumns_[index] == L"内存字节" ||
            currentColumns_[index] == L"磁盘字节") {
            width = 240;
        } else if (currentColumns_[index] == L"差异状态" ||
            currentColumns_[index] == L"状态") {
            width = 180;
        }
        AddResultTableColumn(static_cast<int>(index), currentColumns_[index], width);
    }
    SyncResultListVirtualRows();

    std::wostringstream status;
    switch (featureId) {
    case KernelFeatureId::Ssdt:
        status << L"状态：已刷新 " << totalRows << L" 项，显示 " << currentRows_.size()
               << L" 项，未解析索引 " << unresolvedRows << L" 项";
        break;
    case KernelFeatureId::ShadowSsdt:
        status << L"状态：已解析 "
               << (reportedReturnedRows == 0 ? totalRows : reportedReturnedRows)
               << L"/"
               << (reportedTotalRows == 0 ? totalRows : reportedTotalRows)
               << L" 项，显示 " << currentRows_.size()
               << L" 项，未解析索引 " << unresolvedRows << L" 项";
        break;
    case KernelFeatureId::InlineHook:
        status << L"状态：Inline Hook 扫描完成，显示 " << currentRows_.size()
               << L" / " << totalRows << L" 项，可疑/差异 " << suspiciousRows
               << L" 项，磁盘差异 " << diskDiffRows << L" 项";
        break;
    case KernelFeatureId::IatEatHook:
        status << L"状态：IAT/EAT 扫描完成，显示 " << currentRows_.size()
               << L" / " << totalRows << L" 项，可疑 " << suspiciousRows
               << L" 项，干净 " << cleanRows << L" 项";
        break;
    default:
        break;
    }
    if (!filterText.empty()) {
        status << L"，过滤=" << filterText;
    }
    if (!moduleFilterText.empty() && (featureId == KernelFeatureId::InlineHook || featureId == KernelFeatureId::IatEatHook)) {
        status << L"，模块过滤=" << moduleFilterText;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());

    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, EmptyDetailTextForFeature(featureId));
    }
}

void KernelPage::RebuildObjectNamespaceListFromCache(const KernelFeatureId featureId) {
    // RebuildObjectNamespaceListFromCache reshapes generic KernelFacade rows
    // into the original KernelDock object-namespace tree/table schemas. Inputs
    // are currentColumns_/currentRows_ from AddDynamicResultRow; processing adds
    // root rows, tree indentation, original headers and hidden action fields;
    // there is no return value because the ListView owns the visible output.
    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : CanonicalColumnNames(featureId)) {
        if (!HasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const auto addHiddenColumn = [&](const wchar_t* name) {
        if (!HasColumn(displayColumns, name)) {
            displayColumns.push_back(name);
        }
    };
    addHiddenColumn(L"Parent");
    addHiddenColumn(L"Source");
    addHiddenColumn(L"Directory");
    addHiddenColumn(L"directoryPath");
    addHiddenColumn(L"sourceDirectory");
    addHiddenColumn(L"Depth");
    addHiddenColumn(L"Path");
    addHiddenColumn(L"NtPath");
    addHiddenColumn(L"Target");
    addHiddenColumn(L"Win32Path");
    addHiddenColumn(L"dosCandidate");
    addHiddenColumn(L"fullPath");
    addHiddenColumn(L"targetPath");
    addHiddenColumn(L"symbolicTarget");
    addHiddenColumn(L"objectName");
    addHiddenColumn(L"objectType");
    addHiddenColumn(L"linkName");
    addHiddenColumn(L"Handles");
    addHiddenColumn(L"Pointers");
    addHiddenColumn(L"Detail");
    addHiddenColumn(L"EnumApi");
    addHiddenColumn(L"enumApi");
    addHiddenColumn(L"枚举 API");
    addHiddenColumn(L"EnumerationApi");
    addHiddenColumn(L"NodeKind");

    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        if (columnName == L"Detail") {
            return rawValue(row, { L"Detail" });
        }
        std::vector<std::wstring> aliases = ColumnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = RowFieldByName(row, rawColumns, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };
    if (featureId == KernelFeatureId::DeviceDriverObjects && deviceDriverDirectoryCombo_ && deviceDriverTypeCombo_) {
        std::set<std::wstring> types;
        for (const std::vector<std::wstring>& rawRow : rawRows) {
            const std::wstring type = rawValue(rawRow, { L"Type", L"objectType", L"对象类型", L"类型" });
            if (!type.empty()) {
                types.insert(type);
            }
        }
        const std::wstring previousDirectory = [this]() -> std::wstring {
            const int selection = static_cast<int>(::SendMessageW(deviceDriverDirectoryCombo_, CB_GETCURSEL, 0, 0));
            if (selection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(deviceDriverDirectoryCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();
        const std::wstring previousType = [this]() -> std::wstring {
            const int selection = static_cast<int>(::SendMessageW(deviceDriverTypeCombo_, CB_GETCURSEL, 0, 0));
            if (selection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(deviceDriverTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();

        ::SendMessageW(deviceDriverDirectoryCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(deviceDriverDirectoryCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部目录"));
        int restoredDirectory = 0;
        for (const wchar_t* directory : kDeviceDriverFixedDirectories) {
            const int index = static_cast<int>(::SendMessageW(deviceDriverDirectoryCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(directory)));
            if (!previousDirectory.empty() && _wcsicmp(previousDirectory.c_str(), directory) == 0) {
                restoredDirectory = index;
            }
        }
        ::SendMessageW(deviceDriverDirectoryCombo_, CB_SETCURSEL, restoredDirectory, 0);

        ::SendMessageW(deviceDriverTypeCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(deviceDriverTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部类型"));
        int restoredType = 0;
        for (const std::wstring& type : types) {
            const int index = static_cast<int>(::SendMessageW(deviceDriverTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(type.c_str())));
            if (!previousType.empty() && _wcsicmp(previousType.c_str(), type.c_str()) == 0) {
                restoredType = index;
            }
        }
        ::SendMessageW(deviceDriverTypeCombo_, CB_SETCURSEL, restoredType, 0);
    }
    if (featureId == KernelFeatureId::BaseNamedObjects && baseNamedScopeCombo_ && baseNamedTypeCombo_) {
        std::set<std::wstring> scopes;
        std::set<std::wstring> types;
        for (const std::vector<std::wstring>& rawRow : rawRows) {
            const std::wstring scope = rawValue(rawRow, { L"Source", L"Scope", L"scope" });
            const std::wstring type = rawValue(rawRow, { L"Type", L"objectType", L"类型" });
            if (!scope.empty()) {
                scopes.insert(scope);
            }
            if (!type.empty()) {
                types.insert(type);
            }
        }
        const std::wstring previousScope = [this]() -> std::wstring {
            const int selection = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_GETCURSEL, 0, 0));
            if (selection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(baseNamedScopeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();
        const std::wstring previousType = [this]() -> std::wstring {
            const int selection = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_GETCURSEL, 0, 0));
            if (selection <= 0) {
                return {};
            }
            wchar_t buffer[512]{};
            ::SendMessageW(baseNamedTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
            return buffer;
        }();
        ::SendMessageW(baseNamedScopeCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(baseNamedScopeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部 Session"));
        int restoredScope = 0;
        for (const std::wstring& scope : scopes) {
            const int index = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(scope.c_str())));
            if (!previousScope.empty() && _wcsicmp(previousScope.c_str(), scope.c_str()) == 0) {
                restoredScope = index;
            }
        }
        ::SendMessageW(baseNamedScopeCombo_, CB_SETCURSEL, restoredScope, 0);
        ::SendMessageW(baseNamedTypeCombo_, CB_RESETCONTENT, 0, 0);
        ::SendMessageW(baseNamedTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"全部类型"));
        int restoredType = 0;
        for (const std::wstring& type : types) {
            const int index = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(type.c_str())));
            if (!previousType.empty() && _wcsicmp(previousType.c_str(), type.c_str()) == 0) {
                restoredType = index;
            }
        }
        ::SendMessageW(baseNamedTypeCombo_, CB_SETCURSEL, restoredType, 0);
    }
    const auto rowMatchesObjectFilters = [&](const std::vector<std::wstring>& row) -> bool {
        const std::wstring primaryFilter = WindowText(filterEdit_);
        const std::wstring secondaryFilter = WindowText(moduleFilterEdit_);
        if (featureId == KernelFeatureId::ObjectNamespaceOverview) {
            const std::wstring merged = rawValue(row, { L"Parent", L"Source" }) + L" | " +
                rawValue(row, { L"Name" }) + L" | " +
                rawValue(row, { L"Type" }) + L" | " +
                rawValue(row, { L"Path" }) + L" | " +
                rawValue(row, { L"Status" }) + L" | " +
                rawValue(row, { L"Target" });
            return primaryFilter.empty() || ContainsCaseInsensitive(merged, primaryFilter);
        }
        if (featureId == KernelFeatureId::ObjectDirectoryRecursive) {
            return true;
        }
        if (featureId == KernelFeatureId::BaseNamedObjects) {
            std::wstring scopeFilter;
            std::wstring typeFilter;
            if (baseNamedScopeCombo_) {
                const int selection = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_GETCURSEL, 0, 0));
                if (selection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(baseNamedScopeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
                    scopeFilter = buffer;
                }
            }
            if (baseNamedTypeCombo_) {
                const int selection = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_GETCURSEL, 0, 0));
                if (selection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(baseNamedTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
                    typeFilter = buffer;
                }
            }
            const std::wstring merged = rawValue(row, { L"Source", L"Scope" }) + L" | " +
                rawValue(row, { L"Parent", L"Directory" }) + L" | " +
                rawValue(row, { L"Name" }) + L" | " +
                rawValue(row, { L"Type" }) + L" | " +
                rawValue(row, { L"Path" }) + L" | " +
                rawValue(row, { L"Target" }) + L" | " +
                rawValue(row, { L"Status" });
            const bool keywordMatched = primaryFilter.empty() || ContainsCaseInsensitive(merged, primaryFilter);
            const bool scopeMatched = scopeFilter.empty() ||
                _wcsicmp(rawValue(row, { L"Source", L"Scope", L"scope" }).c_str(), scopeFilter.c_str()) == 0;
            const bool typeMatched = typeFilter.empty() ||
                _wcsicmp(rawValue(row, { L"Type", L"objectType" }).c_str(), typeFilter.c_str()) == 0;
            const bool legacyMatched = secondaryFilter.empty() ||
                ContainsCaseInsensitive(rawValue(row, { L"Source", L"Scope" }), secondaryFilter) ||
                ContainsCaseInsensitive(rawValue(row, { L"Type" }), secondaryFilter);
            const bool auxMatched = scopeMatched && typeMatched && legacyMatched;
            return keywordMatched && auxMatched;
        }
        if (featureId == KernelFeatureId::NamedPipe) {
            const std::wstring merged = rawValue(row, { L"Pipe", L"Name" }) + L" | " +
                rawValue(row, { L"NtPath", L"Path" }) + L" | " +
                rawValue(row, { L"Attributes" }) + L" | " +
                rawValue(row, { L"LastWrite" }) + L" | " +
                rawValue(row, { L"Status" }) + L" | " +
                rawValue(row, { L"Directory", L"Source" });
            return primaryFilter.empty() || ContainsCaseInsensitive(merged, primaryFilter);
        }
        if (featureId == KernelFeatureId::ObjectTypeMatrix) {
            const std::wstring merged = rawValue(row, { L"TypeIndex", L"Index" }) + L" | " +
                rawValue(row, { L"Type" }) + L" | " +
                rawValue(row, { L"Objects" }) + L" | " +
                rawValue(row, { L"Handles" }) + L" | " +
                rawValue(row, { L"ValidAccess" }) + L" | " +
                rawValue(row, { L"Detail", L"Status" });
            return primaryFilter.empty() || ContainsCaseInsensitive(merged, primaryFilter);
        }
        if (featureId == KernelFeatureId::CommunicationEndpoint) {
            const std::wstring merged = rawValue(row, { L"Source", L"Parent" }) + L" | " +
                rawValue(row, { L"Name" }) + L" | " +
                rawValue(row, { L"Type" }) + L" | " +
                rawValue(row, { L"Path" }) + L" | " +
                rawValue(row, { L"Status" });
            return primaryFilter.empty() || ContainsCaseInsensitive(merged, primaryFilter);
        }
        if (featureId != KernelFeatureId::SymbolicLink &&
            featureId != KernelFeatureId::DeviceDriverObjects) {
            return true;
        }
        if (featureId == KernelFeatureId::SymbolicLink) {
            const std::wstring merged = rawValue(row, { L"Source", L"Parent" }) + L" | " +
                rawValue(row, { L"Name" }) + L" | " +
                rawValue(row, { L"Path" }) + L" | " +
                rawValue(row, { L"Status" }) + L" | " +
                rawValue(row, { L"Target" }) + L" | " +
                rawValue(row, { L"Win32Path", L"DosCandidates" });
            const bool primaryMatched = primaryFilter.empty() || ContainsCaseInsensitive(merged, primaryFilter);
            const bool secondaryMatched = secondaryFilter.empty() ||
                ContainsCaseInsensitive(rawValue(row, { L"Target" }), secondaryFilter) ||
                ContainsCaseInsensitive(rawValue(row, { L"Win32Path", L"DosCandidates" }), secondaryFilter);
            return primaryMatched && secondaryMatched;
        }
        if (featureId == KernelFeatureId::DeviceDriverObjects) {
            std::wstring directoryFilter;
            std::wstring typeFilter;
            if (deviceDriverDirectoryCombo_) {
                const int selection = static_cast<int>(::SendMessageW(deviceDriverDirectoryCombo_, CB_GETCURSEL, 0, 0));
                if (selection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(deviceDriverDirectoryCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
                    directoryFilter = buffer;
                }
            }
            if (deviceDriverTypeCombo_) {
                const int selection = static_cast<int>(::SendMessageW(deviceDriverTypeCombo_, CB_GETCURSEL, 0, 0));
                if (selection > 0) {
                    wchar_t buffer[512]{};
                    ::SendMessageW(deviceDriverTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
                    typeFilter = buffer;
                }
            }
            const std::wstring directory = rawValue(row, { L"Parent", L"Directory", L"Source", L"directoryPath", L"目录路径" });
            const std::wstring type = rawValue(row, { L"Type", L"objectType", L"对象类型", L"类型" });
            const std::wstring keywordMerged = directory + L" | " +
                rawValue(row, { L"Name", L"DriverName", L"objectName", L"对象名称" }) + L" | " +
                type + L" | " +
                rawValue(row, { L"Path", L"NtPath", L"fullPath", L"完整路径" }) + L" | " +
                rawValue(row, { L"Target", L"targetPath", L"symbolicTarget", L"目标路径" }) + L" | " +
                rawValue(row, { L"Status", L"statusText", L"状态" }) + L" | " +
                rawValue(row, { L"Detail", L"Capability", L"capabilityHintText", L"能力提示" });
            const bool keywordMatched = primaryFilter.empty() || ContainsCaseInsensitive(keywordMerged, primaryFilter);
            const bool directoryMatched = directoryFilter.empty() || _wcsicmp(directory.c_str(), directoryFilter.c_str()) == 0;
            const bool typeMatched = typeFilter.empty() || _wcsicmp(type.c_str(), typeFilter.c_str()) == 0;
            return keywordMatched && directoryMatched && typeMatched;
        }
        return true;
    };
    const auto depthOf = [&](const std::vector<std::wstring>& row) -> int {
        const std::wstring text = rawValue(row, { L"Depth", L"深度" });
        if (text.empty()) {
            return 0;
        }
        wchar_t* end = nullptr;
        const long value = std::wcstol(text.c_str(), &end, 10);
        return end != text.c_str() && value > 0 ? static_cast<int>(std::min<long>(value, 16)) : 0;
    };
    std::vector<std::vector<std::wstring>> displayRows;
    std::vector<int> displayIndents;
    std::vector<std::wstring> insertedRoots;
    std::vector<std::wstring> insertedDirectories;
    std::size_t meaningfulRowCount = 0;
    const auto appendDisplayRow = [&](std::vector<std::wstring> cells, const int indent) {
        if (!cells.empty() && !displayColumns.empty() && displayColumns[0] == L"#") {
            cells[0] = std::to_wstring(displayRows.size());
        }
        displayRows.push_back(std::move(cells));
        displayIndents.push_back(std::max(0, indent));
    };
    const auto makeEmptyCells = [&]() {
        return std::vector<std::wstring>(displayColumns.size());
    };
    const auto appendOverviewRoot = [&](const std::wstring& root, const std::wstring& status) {
        if (root.empty()) {
            return;
        }
        const auto duplicate = std::find_if(insertedRoots.begin(), insertedRoots.end(), [&](const std::wstring& existing) {
            return _wcsicmp(existing.c_str(), root.c_str()) == 0;
        });
        if (duplicate != insertedRoots.end()) {
            return;
        }
        insertedRoots.push_back(root);
        std::vector<std::wstring> cells = makeEmptyCells();
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"名称") cells[column] = root;
            else if (name == L"类型") cells[column] = L"根目录";
            else if (name == L"路径/说明") cells[column] = status.empty() ? root : status;
            else if (name == L"状态") cells[column] = L"根节点";
            else if (name == L"Parent" || name == L"Source" || name == L"Path") cells[column] = root;
            else if (name == L"Depth") cells[column] = L"0";
            else if (name == L"NodeKind") cells[column] = L"Root";
            else if (name == L"Detail") cells[column] = L"Object Manager root: " + root;
        }
        appendDisplayRow(std::move(cells), 0);
    };
    const auto appendOverviewDirectory = [&](const std::wstring& root, const std::wstring& directory, const std::wstring& scope) {
        // appendOverviewDirectory reproduces the original middle tree level:
        // each root owns one row per enumerated directory, and object rows sit
        // under that directory. Inputs are root/scope/directory text from the
        // facade row; processing de-duplicates the pair; no value is returned.
        if (directory.empty()) {
            return;
        }
        const std::wstring key = root + L"\n" + directory;
        const auto duplicate = std::find_if(insertedDirectories.begin(), insertedDirectories.end(), [&](const std::wstring& existing) {
            return _wcsicmp(existing.c_str(), key.c_str()) == 0;
        });
        if (duplicate != insertedDirectories.end()) {
            return;
        }
        insertedDirectories.push_back(key);
        std::vector<std::wstring> cells = makeEmptyCells();
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"名称") cells[column] = LeafObjectName(directory);
            else if (name == L"类型") cells[column] = L"目录";
            else if (name == L"路径/说明") cells[column] = directory;
            else if (name == L"状态") cells[column] = L"已展开枚举";
            else if (name == L"Parent" || name == L"Source") cells[column] = root;
            else if (name == L"Directory" || name == L"directoryPath" || name == L"Path" || name == L"fullPath") cells[column] = directory;
            else if (name == L"Depth") cells[column] = L"1";
            else if (name == L"NodeKind") cells[column] = L"Directory";
            else if (name == L"Detail") cells[column] = scope.empty()
                ? (L"Object Manager directory: " + directory)
                : (L"Object Manager directory: " + directory + L"\r\n" + scope);
        }
        appendDisplayRow(std::move(cells), 1);
    };
    if (featureId == KernelFeatureId::ObjectDirectoryRecursive) {
        std::wstring rootPath = WindowText(filterEdit_);
        if (rootPath.empty()) {
            rootPath = L"\\";
        }
        std::vector<std::wstring> cells = makeEmptyCells();
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"名称") cells[column] = LeafObjectName(rootPath);
            else if (name == L"类型") cells[column] = L"Directory";
            else if (name == L"完整路径" || name == L"Path") cells[column] = rootPath;
            else if (name == L"深度" || name == L"Depth") cells[column] = L"0";
            else if (name == L"状态") cells[column] = L"根目录";
            else if (name == L"Parent" || name == L"Source") cells[column] = ParentObjectPath(rootPath).empty() ? rootPath : ParentObjectPath(rootPath);
            else if (name == L"Detail") cells[column] = L"Object Manager recursive root: " + rootPath;
        }
        appendDisplayRow(std::move(cells), 0);
    }

    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool meaningful =
            HasNonEmptyField(rawRow, rawColumns, { L"Name", L"Path", L"NtPath", L"Pipe", L"TypeIndex", L"Type" }) ||
            HasNonEmptyField(rawRow, rawColumns, { L"Parent", L"Source", L"Directory", L"Target" });
        if (!meaningful) {
            continue;
        }
        ++meaningfulRowCount;
        const std::wstring parent = rawValue(rawRow, { L"Parent", L"Directory", L"sourceDirectory", L"来源目录", L"目录路径" });
        const std::wstring source = rawValue(rawRow, { L"Source", L"scope" });
        const std::wstring path = rawValue(rawRow, { L"Path", L"NtPath", L"fullPath", L"完整路径" });
        const std::wstring objectName = rawValue(rawRow, { L"Name", L"Pipe", L"objectName", L"linkName", L"名称", L"对象名称", L"Type" });
        const std::wstring objectType = rawValue(rawRow, { L"Type", L"objectType", L"类型", L"对象类型" });
        const bool isQueryHeader = !HasNonEmptyField(rawRow, rawColumns, { L"Name", L"Pipe", L"objectName", L"linkName", L"TypeIndex" }) &&
            HasNonEmptyField(rawRow, rawColumns, { L"功能", L"数据源", L"Rows", L"Warnings" });
        if (isQueryHeader) {
            continue;
        }
        if (!rowMatchesObjectFilters(rawRow)) {
            continue;
        }

        if (featureId == KernelFeatureId::ObjectNamespaceOverview) {
            const std::wstring directory = !parent.empty() ? parent : (!rawValue(rawRow, { L"directoryPathText", L"directoryPath", L"Directory" }).empty()
                ? rawValue(rawRow, { L"directoryPathText", L"directoryPath", L"Directory" })
                : ParentObjectPath(path));
            const std::wstring root = !source.empty() ? source : (!rawValue(rawRow, { L"rootPathText", L"Root" }).empty()
                ? rawValue(rawRow, { L"rootPathText", L"Root" })
                : (!directory.empty() ? directory : path));
            const std::wstring scope = rawValue(rawRow, { L"scopeDescriptionText", L"Scope", L"scope", L"Detail" });
            if (WindowText(filterEdit_).empty() ||
                ContainsCaseInsensitive(root, WindowText(filterEdit_)) ||
                ContainsCaseInsensitive(directory, WindowText(filterEdit_)) ||
                ContainsCaseInsensitive(scope, WindowText(filterEdit_)) ||
                ContainsCaseInsensitive(path, WindowText(filterEdit_)) ||
                ContainsCaseInsensitive(objectName, WindowText(filterEdit_)) ||
                ContainsCaseInsensitive(objectType, WindowText(filterEdit_)) ||
                ContainsCaseInsensitive(rawValue(rawRow, { L"Status" }), WindowText(filterEdit_)) ||
                ContainsCaseInsensitive(rawValue(rawRow, { L"Target" }), WindowText(filterEdit_))) {
                appendOverviewRoot(root, scope);
                appendOverviewDirectory(root, directory, scope);
            }
            if (objectName.empty() && objectType.empty() && parent.empty()) {
                continue;
            }
        }

        std::vector<std::wstring> cells = makeEmptyCells();
        int rowIndent = 0;
        if (featureId == KernelFeatureId::ObjectNamespaceOverview) {
            rowIndent = 2;
        } else if (featureId == KernelFeatureId::ObjectDirectoryRecursive) {
            rowIndent = depthOf(rawRow) + 1;
        }
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                continue;
            }
            std::wstring value = displayValue(rawRow, name);
            if (featureId == KernelFeatureId::ObjectNamespaceOverview && name == L"名称") {
                value = objectName.empty() ? path : objectName;
            } else if (featureId == KernelFeatureId::ObjectNamespaceOverview && name == L"类型" && value.empty()) {
                value = objectType.empty() ? L"<未知>" : objectType;
            } else if (featureId == KernelFeatureId::ObjectNamespaceOverview && name == L"路径/说明" && value.empty()) {
                value = path;
            } else if (featureId == KernelFeatureId::ObjectNamespaceOverview && name == L"NodeKind") {
                value = L"ObjectEntry";
            } else if (featureId == KernelFeatureId::ObjectDirectoryRecursive && name == L"名称") {
                value = objectName.empty() ? path : objectName;
            } else if (featureId == KernelFeatureId::NamedPipe && name == L"Pipe Name" && value.empty()) {
                const std::wstring ntPath = rawValue(rawRow, { L"NtPath", L"Path" });
                const std::size_t slash = ntPath.find_last_of(L'\\');
                value = slash == std::wstring::npos ? ntPath : ntPath.substr(slash + 1);
            } else if (featureId == KernelFeatureId::DeviceDriverObjects && name == L"目标路径" && value.empty()) {
                value = L"<无>";
            } else if (name == L"Detail" && value.empty()) {
                value = rawValue(rawRow, { L"Status", L"statusText", L"Target", L"symbolicTarget", L"targetPath" });
            }
            cells[column] = std::move(value);
        }
        appendDisplayRow(std::move(cells), rowIndent);
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    ClearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& columnName = currentColumns_[index];
        const bool hidden = columnName == L"Parent" ||
            columnName == L"Source" ||
            columnName == L"Directory" ||
            columnName == L"directoryPath" ||
            columnName == L"sourceDirectory" ||
            columnName == L"Depth" ||
            columnName == L"Path" ||
            columnName == L"NtPath" ||
            columnName == L"Target" ||
            columnName == L"Win32Path" ||
            columnName == L"dosCandidate" ||
            columnName == L"fullPath" ||
            columnName == L"targetPath" ||
            columnName == L"symbolicTarget" ||
            columnName == L"objectName" ||
            columnName == L"objectType" ||
            columnName == L"linkName" ||
            columnName == L"Handles" ||
            columnName == L"Pointers" ||
            columnName == L"EnumApi" ||
            columnName == L"enumApi" ||
            columnName == L"枚举 API" ||
            columnName == L"EnumerationApi" ||
            columnName == L"NodeKind" ||
            columnName == L"Detail";
        int width = hidden ? 0 : ColumnWidth(columnName);
        if (featureId == KernelFeatureId::DeviceDriverObjects) {
            if (columnName == L"目录路径") width = 190;
            else if (columnName == L"对象名称") width = 180;
            else if (columnName == L"对象类型") width = 130;
            else if (columnName == L"完整路径") width = 320;
            else if (columnName == L"目标路径") width = 320;
            else if (columnName == L"状态") width = 260;
            else if (columnName == L"能力提示") width = 360;
        }
        AddResultTableColumn(static_cast<int>(index), columnName, width);
    }
    currentRowIndents_ = std::move(displayIndents);
    SyncResultListVirtualRows();
    if (featureId == KernelFeatureId::ObjectNamespaceOverview ||
        featureId == KernelFeatureId::ObjectDirectoryRecursive) {
        RebuildObjectNamespaceTreeFromCurrentRows();
    }
    std::wostringstream status;
    switch (featureId) {
    case KernelFeatureId::ObjectNamespaceOverview:
    {
        const std::wstring keyword = WindowText(filterEdit_);
        status << L"状态：对象命名空间已刷新，显示 " << currentRows_.size()
               << L" / " << meaningfulRowCount << L" 项";
        if (!keyword.empty()) {
            status << L"，过滤=" << keyword;
        }
        break;
    }
    case KernelFeatureId::ObjectDirectoryRecursive:
    {
        std::size_t directoryCount = 0;
        std::size_t failedDirectoryCount = 0;
        bool depthLimitReached = false;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring type = RowFieldByName(row, currentColumns_, { L"类型", L"Type", L"objectType" });
            const std::wstring rowStatus = RowFieldByName(row, currentColumns_, { L"状态", L"Status", L"statusText" });
            if (_wcsicmp(type.c_str(), L"Directory") == 0) {
                ++directoryCount;
                if (ContainsCaseInsensitive(rowStatus, L"失败") ||
                    ContainsCaseInsensitive(rowStatus, L"denied") ||
                    ContainsCaseInsensitive(rowStatus, L"error") ||
                    ContainsCaseInsensitive(rowStatus, L"0xC")) {
                    ++failedDirectoryCount;
                }
            }
            if (ContainsCaseInsensitive(rowStatus, L"深度") ||
                ContainsCaseInsensitive(rowStatus, L"depth")) {
                depthLimitReached = true;
            }
        }
        status << L"状态：已枚举 " << currentRows_.size()
               << L" 项，目录 " << directoryCount
               << L" 个，失败目录 " << failedDirectoryCount << L" 个";
        if (depthLimitReached) {
            status << L"，触达深度上限";
        }
        break;
    }
    case KernelFeatureId::NamedPipe:
    {
        const std::wstring keyword = WindowText(filterEdit_);
        status << L"状态：显示 " << currentRows_.size() << L" / " << meaningfulRowCount;
        if (!keyword.empty()) {
            status << L"，过滤=" << keyword;
        }
        break;
    }
    case KernelFeatureId::BaseNamedObjects:
    {
        std::wstring scopeText = L"全部 Session";
        std::wstring typeText = L"全部类型";
        if (baseNamedScopeCombo_) {
            const int selection = static_cast<int>(::SendMessageW(baseNamedScopeCombo_, CB_GETCURSEL, 0, 0));
            if (selection >= 0) {
                wchar_t buffer[512]{};
                ::SendMessageW(baseNamedScopeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
                if (buffer[0] != L'\0') {
                    scopeText = buffer;
                }
            }
        }
        if (baseNamedTypeCombo_) {
            const int selection = static_cast<int>(::SendMessageW(baseNamedTypeCombo_, CB_GETCURSEL, 0, 0));
            if (selection >= 0) {
                wchar_t buffer[512]{};
                ::SendMessageW(baseNamedTypeCombo_, CB_GETLBTEXT, static_cast<WPARAM>(selection), reinterpret_cast<LPARAM>(buffer));
                if (buffer[0] != L'\0') {
                    typeText = buffer;
                }
            }
        }
        const std::wstring keyword = WindowText(filterEdit_);
        status << L"状态：BaseNamedObjects 已刷新，总数 " << meaningfulRowCount
               << L"，可见 " << currentRows_.size()
               << L"，scope=" << scopeText
               << L"，类型=" << typeText;
        if (!keyword.empty()) {
            status << L"，关键字=" << keyword;
        }
        break;
    }
    case KernelFeatureId::SymbolicLink:
    {
        const std::wstring keyword = WindowText(filterEdit_);
        const std::wstring targetKeyword = WindowText(moduleFilterEdit_);
        status << L"状态：显示 " << currentRows_.size() << L" / " << meaningfulRowCount;
        if (!keyword.empty()) {
            status << L"，过滤=" << keyword;
        }
        if (!targetKeyword.empty()) {
            status << L"，目标过滤=" << targetKeyword;
        }
        break;
    }
    case KernelFeatureId::DeviceDriverObjects:
    {
        const std::size_t loadedRows = meaningfulRowCount;
        const std::size_t visibleRows = currentRows_.size();
        if (loadedRows == 0) {
            status << L"状态：暂无结果，点击刷新开始枚举对象目录。";
        } else if (visibleRows == 0) {
            status << L"状态：已加载 " << loadedRows << L" 条，当前过滤后无可见结果。";
        } else {
            status << L"状态：已加载 " << loadedRows << L" 条，当前显示 " << visibleRows << L" 条。";
        }
        break;
    }
    case KernelFeatureId::ObjectTypeMatrix:
    {
        const std::wstring keyword = WindowText(filterEdit_);
        status << L"状态：已加载 " << meaningfulRowCount << L" 类，显示 " << currentRows_.size() << L" 类";
        if (!keyword.empty()) {
            status << L"，过滤=" << keyword;
        }
        break;
    }
    case KernelFeatureId::CommunicationEndpoint:
    {
        const std::wstring keyword = WindowText(filterEdit_);
        status << L"状态：已加载 " << meaningfulRowCount << L" 项，显示 " << currentRows_.size() << L" 项";
        if (!keyword.empty()) {
            status << L"，过滤=" << keyword;
        }
        break;
    }
    default:
        status << L"状态：对象页已刷新，显示 " << currentRows_.size() << L" 项";
        break;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, EmptyDetailTextForFeature(featureId));
    }
}

void KernelPage::RebuildObjectNamespaceTreeFromCurrentRows() {
    // RebuildObjectNamespaceTreeFromCurrentRows renders the original object
    // namespace overview as a three-level Win32 TreeView. Inputs are
    // currentRows_ and currentColumns_ already projected to the original
    // root/directory/object schema; processing creates stable node payloads in
    // objectNamespaceTreeNodeStorage_ and binds them to TVITEM::lParam; no value
    // is returned.
    if (!objectNamespaceTree_) {
        return;
    }
    TreeView_DeleteAllItems(objectNamespaceTree_);
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor()) {
        objectNamespaceTreeFeatureId_ = descriptor->id;
        hasObjectNamespaceTreeFeatureId_ = true;
    }
    objectNamespaceTreeNodeStorage_.clear();

    std::unordered_map<std::wstring, HTREEITEM> rootItems;
    std::unordered_map<std::wstring, HTREEITEM> directoryItems;
    HTREEITEM firstItem = nullptr;
    HTREEITEM firstEntryItem = nullptr;
    const bool expandAll = !WindowText(filterEdit_).empty();
    const auto rowText = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) {
        return RowFieldByName(row, currentColumns_, names);
    };
    const auto safeText = [](const std::wstring& value, const wchar_t* fallback = L"<空>") -> std::wstring {
        return value.empty() ? std::wstring(fallback) : value;
    };
    const auto rootFromPath = [](const std::wstring& path) -> std::wstring {
        if (path.empty()) {
            return L"\\";
        }
        if (path == L"\\") {
            return path;
        }
        const std::size_t nextSlash = path.find(L'\\', 1);
        return nextSlash == std::wstring::npos ? path : path.substr(0, nextSlash);
    };
    const auto makeState = [&](const int rowIndex,
        std::wstring kind,
        std::wstring name,
        std::wstring type,
        std::wstring path,
        std::wstring description) -> KernelObjectNamespaceTreeNodeState* {
        auto state = std::make_unique<KernelObjectNamespaceTreeNodeState>();
        state->rowIndex = rowIndex;
        state->nodeKind = std::move(kind);
        state->nodeName = std::move(name);
        state->nodeType = std::move(type);
        state->nodePath = std::move(path);
        state->nodeDescription = std::move(description);
        KernelObjectNamespaceTreeNodeState* raw = state.get();
        objectNamespaceTreeNodeStorage_.push_back(std::move(state));
        return raw;
    };
    const auto insertTreeItem = [&](HTREEITEM parent,
        const std::wstring& text,
        KernelObjectNamespaceTreeNodeState* state) -> HTREEITEM {
        if (text.empty()) {
            return nullptr;
        }
        TVINSERTSTRUCTW insert{};
        insert.hParent = parent != nullptr ? parent : TVI_ROOT;
        insert.hInsertAfter = TVI_LAST;
        insert.item.mask = TVIF_TEXT | TVIF_PARAM;
        insert.item.pszText = const_cast<LPWSTR>(text.c_str());
        insert.item.lParam = reinterpret_cast<LPARAM>(state);
        return TreeView_InsertItem(objectNamespaceTree_, &insert);
    };

    const auto ensureRoot = [&](std::wstring rootPath, const std::wstring& description) -> HTREEITEM {
        if (rootPath.empty()) {
            rootPath = L"\\";
        }
        const std::wstring key = LowerInvariantKey(rootPath);
        if (const auto found = rootItems.find(key); found != rootItems.end()) {
            return found->second;
        }
        std::wstring text = rootPath + L"    [根目录]    " + safeText(description, L"<无>");
        KernelObjectNamespaceTreeNodeState* state = makeState(
            -1,
            L"Root",
            rootPath,
            L"根目录",
            rootPath,
            description);
        HTREEITEM item = insertTreeItem(nullptr, text, state);
        if (item != nullptr) {
            rootItems.emplace(key, item);
            if (firstItem == nullptr) {
                firstItem = item;
            }
            TreeView_Expand(objectNamespaceTree_, item, TVE_EXPAND);
        }
        return item;
    };
    const auto ensureDirectory = [&](std::wstring rootPath,
        std::wstring directoryPath,
        const std::wstring& description) -> HTREEITEM {
        if (directoryPath.empty()) {
            directoryPath = rootPath.empty() ? L"\\" : rootPath;
        }
        if (rootPath.empty() || rootPath[0] != L'\\') {
            rootPath = rootFromPath(directoryPath);
        }
        HTREEITEM rootItem = ensureRoot(rootPath, description);
        const std::wstring key = LowerInvariantKey(rootPath + L"\n" + directoryPath);
        if (const auto found = directoryItems.find(key); found != directoryItems.end()) {
            return found->second;
        }
        std::wstring text = LeafObjectName(directoryPath) + L"    [目录]    " + directoryPath;
        KernelObjectNamespaceTreeNodeState* state = makeState(
            -1,
            L"Directory",
            LeafObjectName(directoryPath),
            L"目录",
            directoryPath,
            description);
        HTREEITEM item = insertTreeItem(rootItem, text, state);
        if (item != nullptr) {
            directoryItems.emplace(key, item);
            if (firstItem == nullptr) {
                firstItem = item;
            }
            if (rootItem != nullptr) {
                TreeView_Expand(objectNamespaceTree_, rootItem, TVE_EXPAND);
            }
            if (expandAll) {
                TreeView_Expand(objectNamespaceTree_, item, TVE_EXPAND);
            }
        }
        return item;
    };

    for (std::size_t rowIndex = 0; rowIndex < currentRows_.size(); ++rowIndex) {
        const std::vector<std::wstring>& row = currentRows_[rowIndex];
        std::wstring nodeKind = rowText(row, { L"NodeKind" });
        const std::wstring name = rowText(row, { L"名称", L"Name", L"objectName" });
        const std::wstring type = rowText(row, { L"类型", L"Type", L"objectType" });
        const std::wstring path = rowText(row, { L"Path", L"完整路径", L"fullPath", L"路径/说明" });
        const std::wstring directory = rowText(row, { L"Directory", L"directoryPath", L"Parent", L"sourceDirectory", L"来源目录" });
        std::wstring root = rowText(row, { L"rootPathText", L"Root", L"Source" });
        const std::wstring description = rowText(row, { L"scopeDescriptionText", L"Scope", L"scope", L"Detail", L"路径/说明" });
        const std::wstring status = rowText(row, { L"状态", L"Status", L"statusText" });
        const std::wstring target = rowText(row, { L"符号链接目标", L"Target", L"symbolicTarget", L"targetPath" });
        if (name.empty() && path.empty()) {
            continue;
        }

        if (nodeKind.empty()) {
            if (_wcsicmp(type.c_str(), L"根目录") == 0 || _wcsicmp(status.c_str(), L"根节点") == 0) {
                nodeKind = L"Root";
            } else if (_wcsicmp(type.c_str(), L"目录") == 0 || _wcsicmp(status.c_str(), L"已展开枚举") == 0) {
                nodeKind = L"Directory";
            } else {
                nodeKind = L"ObjectEntry";
            }
        }

        if (_wcsicmp(nodeKind.c_str(), L"Root") == 0) {
            ensureRoot(path.empty() ? name : path, description);
            continue;
        }
        if (_wcsicmp(nodeKind.c_str(), L"Directory") == 0) {
            const std::wstring directoryPath = path.empty() ? directory : path;
            if (root.empty() || root[0] != L'\\') {
                root = rootFromPath(directoryPath);
            }
            ensureDirectory(root, directoryPath, description);
            continue;
        }

        std::wstring directoryPath = !directory.empty() ? directory : ParentObjectPath(path);
        if (root.empty() || root[0] != L'\\') {
            root = rootFromPath(!directoryPath.empty() ? directoryPath : path);
        }
        HTREEITEM directoryItem = ensureDirectory(root, directoryPath, description);
        std::wstring displayText = safeText(name, L"<未命名对象>");
        displayText += L"    [" + safeText(type) + L"]    " + safeText(path);
        if (!target.empty() && target != L"<无>") {
            displayText += L"    -> " + target;
        } else if (!status.empty()) {
            displayText += L"    " + status;
        }
        KernelObjectNamespaceTreeNodeState* state = makeState(
            static_cast<int>(rowIndex),
            L"ObjectEntry",
            name.empty() ? L"<未命名对象>" : name,
            type,
            path,
            description);
        const HTREEITEM item = insertTreeItem(directoryItem, displayText, state);
        if (item == nullptr) {
            continue;
        }
        if (firstItem == nullptr) {
            firstItem = item;
        }
        if (firstEntryItem == nullptr) {
            firstEntryItem = item;
        }
        if (expandAll && directoryItem != nullptr) {
            TreeView_Expand(objectNamespaceTree_, directoryItem, TVE_EXPAND);
        }
    }

    if (firstEntryItem != nullptr) {
        TreeView_SelectItem(objectNamespaceTree_, firstEntryItem);
    } else if (firstItem != nullptr) {
        TreeView_SelectItem(objectNamespaceTree_, firstItem);
    }
}

void KernelPage::ToggleObjectNamespaceListNode(const int rowIndex) {
    // ToggleObjectNamespaceListNode provides the Win32 report-list equivalent
    // of double-clicking a tree widget object node. Input is the activated
    // visible row; processing uses object type/path cells to perform the most
    // useful original action: directories become the recursive root and symbolic
    // links are resolved again; there is no return value.
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr || !IsObjectNamespaceFeature(descriptor->id) ||
        rowIndex < 0 || rowIndex >= static_cast<int>(currentRows_.size())) {
        return;
    }

    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemState(resultList_, rowIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    UpdateSelectedRowDetail();

    const std::vector<std::wstring>& row = currentRows_[static_cast<std::size_t>(rowIndex)];
    const std::wstring type = RowFieldByName(row, currentColumns_, { L"类型", L"Type", L"objectType", L"对象类型" });
    const std::wstring path = RowFieldByName(row, currentColumns_, { L"完整路径", L"Path", L"fullPath", L"路径/说明", L"NT Path", L"NtPath" });
    if (_wcsicmp(type.c_str(), L"Directory") == 0 && !path.empty()) {
        ::SetWindowTextW(filterEdit_, path.c_str());
        ::SetWindowTextW(moduleFilterEdit_, L"4");
        for (std::size_t index = 0; index < primaryFeatureIds_.size(); ++index) {
            if (primaryFeatureIds_[index] == KernelFeatureId::ObjectNamespaceOverview && secondaryTab_) {
                for (int tab = 0; tab < static_cast<int>(ObjectNamespaceTabs().size()); ++tab) {
                    if (ObjectNamespaceTabs()[static_cast<std::size_t>(tab)].featureId == KernelFeatureId::ObjectDirectoryRecursive) {
                        ::SendMessageW(secondaryTab_, TCM_SETCURSEL, tab, 0);
                        SelectCurrentFeature();
                        RefreshSelectedFeature();
                        return;
                    }
                }
            }
        }
        RefreshSelectedFeature();
        return;
    }
    if (_wcsicmp(type.c_str(), L"SymbolicLink") == 0) {
        ExecuteSelectedAction(KernelActionId::NativeSymbolicLinkResolve);
        return;
    }
    ExecuteSelectedAction(KernelActionId::NativeObjectQueryDetail);
}

void KernelPage::SelectObjectNamespaceTreeRow(const LPARAM rowIndex) {
    // SelectObjectNamespaceTreeRow maps a TreeView selection back to the hidden
    // ListView row model. Input is the row index stored in TVITEM::lParam;
    // processing updates selection/focus so all copy/filter/detail code remains
    // shared; there is no return value.
    if (!resultList_) {
        return;
    }
    if (rowIndex < 0 || rowIndex >= static_cast<LPARAM>(currentRows_.size())) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ::SetWindowTextW(detailEdit_, L"这是为保持目录层级自动补出的父目录节点，当前没有可执行的结果行。");
        UpdatePropertyTableFromSelection();
        return;
    }
    const int row = static_cast<int>(rowIndex);
    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemState(resultList_, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    UpdateSelectedRowDetail();
}

void KernelPage::SelectObjectNamespaceTreeItem(const LPARAM itemData) {
    // SelectObjectNamespaceTreeItem applies the original Qt tree-node selection
    // semantics. Input is a KernelObjectNamespaceTreeNodeState pointer stored in
    // TVITEM::lParam; processing either selects the backing result row or shows
    // synthetic root/directory node details; no value is returned.
    if (!resultList_ || !detailEdit_) {
        return;
    }
    const auto* state = reinterpret_cast<const KernelObjectNamespaceTreeNodeState*>(itemData);
    if (state == nullptr) {
        objectNamespaceSelectedRow_ = -1;
        objectNamespaceSelectedKind_ = L"";
        objectNamespaceSelectedPath_ = L"";
        objectNamespaceSelectedDescription_ = L"";
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ::SetWindowTextW(detailEdit_, L"请选择对象命名空间树节点查看详情。");
        UpdatePropertyTableFromSelection();
        return;
    }

    objectNamespaceSelectedRow_ = state->rowIndex;
    objectNamespaceSelectedKind_ = state->nodeKind;
    objectNamespaceSelectedPath_ = state->nodePath;
    objectNamespaceSelectedDescription_ = state->nodeDescription;
    if (state->rowIndex >= 0 && state->rowIndex < static_cast<int>(currentRows_.size())) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(resultList_, state->rowIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, state->rowIndex, FALSE);
        UpdateSelectedRowDetail();
        return;
    }

    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    std::wostringstream detail;
    detail << L"当前节点名称: " << (state->nodeName.empty() ? L"<空>" : state->nodeName) << L"\r\n"
           << L"当前节点类型: " << (state->nodeType.empty() ? L"<空>" : state->nodeType) << L"\r\n"
           << L"当前节点路径: " << (state->nodePath.empty() ? L"<无>" : state->nodePath) << L"\r\n"
           << L"节点说明: " << (state->nodeDescription.empty() ? L"<无>" : state->nodeDescription) << L"\r\n\r\n"
           << L"提示: 请选择目录下具体对象项以查看完整对象字段。";
    ::SetWindowTextW(detailEdit_, detail.str().c_str());
    UpdatePropertyTableFromSelection();
}

void KernelPage::RebuildAtomTableFromCache() {
    // RebuildAtomTableFromCache mirrors the original KernelDock atom page. The
    // input is the unfiltered R3 Win32 atom snapshot cached by RenderResult; the
    // processing projects the fixed Atom值/十六进制/名称/来源/状态 table and applies
    // the edit-box filter locally; the return behavior is direct ListView and
    // detail-pane updates with no extra driver/native calls.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring filterText = WindowText(filterEdit_);
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(KernelFeatureId::AtomTable, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns{ L"#" };
    for (const std::wstring& column : CanonicalColumnNames(KernelFeatureId::AtomTable)) {
        if (!HasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const wchar_t* hiddenColumns[] = {
        L"Id", L"Hex", L"Name", L"Source", L"Kind", L"GlobalName", L"ClipboardName", L"Length", L"Detail"
    };
    for (const wchar_t* column : hiddenColumns) {
        if (!HasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool atomRow = HasNonEmptyField(rawRow, rawColumns, { L"Id", L"Name", L"Source", L"Kind" });
        if (!atomRow) {
            continue;
        }
        ++totalRows;
        if (!filterText.empty() && !ContainsCaseInsensitive(MergeRowText(rawRow), filterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    currentRowIndents_.clear();
    ClearResultTable();
    const std::vector<std::wstring> canonical = CanonicalColumnNames(KernelFeatureId::AtomTable);
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool hidden = name == L"#" ? false : !HasColumn(canonical, name);
        int width = hidden ? 0 : ColumnWidth(name);
        if (name == L"Atom值" || name == L"十六进制") {
            width = 110;
        } else if (name == L"名称") {
            width = 360;
        } else if (name == L"来源") {
            width = 220;
        } else if (name == L"状态") {
            width = 160;
        }
        AddResultTableColumn(static_cast<int>(index), name, width);
    }
    SyncResultListVirtualRows();

    std::wostringstream status;
    status << L"状态：原子表已刷新，返回 " << currentRows_.size() << L"/" << totalRows;
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, totalRows == 0 ? L"尚未返回原子记录。" : L"当前过滤条件下没有原子记录。");
    }
}

void KernelPage::RebuildNtQueryLegacyListFromCache() {
    // RebuildNtQueryLegacyListFromCache mirrors the original "历史 NtQuery" page.
    // Inputs are the cached safe NtQuery probe rows; processing keeps the fixed
    // 类别/函数/查询项/状态/摘要 table with hidden diagnostics for details; the
    // output is the refreshed ListView and detail pane only.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(KernelFeatureId::NtQueryLegacy, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns{ L"#" };
    for (const std::wstring& column : CanonicalColumnNames(KernelFeatureId::NtQueryLegacy)) {
        if (!HasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const wchar_t* hiddenColumns[] = {
        L"Category", L"Function", L"Class", L"InfoClass", L"Status", L"Success", L"Bytes", L"Ordinal", L"RVA", L"Detail"
    };
    for (const wchar_t* column : hiddenColumns) {
        if (!HasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t successRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool ntQueryRow = HasNonEmptyField(rawRow, rawColumns, { L"Category", L"Function", L"Class", L"Ordinal", L"RVA" });
        if (!ntQueryRow) {
            continue;
        }
        if (rawValue(rawRow, { L"Success" }) == L"true" ||
            ContainsCaseInsensitive(rawValue(rawRow, { L"Status" }), L"Exported") ||
            rawValue(rawRow, { L"Status" }) == L"0x0") {
            ++successRows;
        }
        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    currentRowIndents_.clear();
    ClearResultTable();
    const std::vector<std::wstring> canonical = CanonicalColumnNames(KernelFeatureId::NtQueryLegacy);
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool hidden = name == L"#" ? false : !HasColumn(canonical, name);
        int width = hidden ? 0 : ColumnWidth(name);
        if (name == L"类别") {
            width = 110;
        } else if (name == L"函数") {
            width = 230;
        } else if (name == L"查询项") {
            width = 110;
        } else if (name == L"状态") {
            width = 130;
        } else if (name == L"摘要") {
            width = 360;
        }
        AddResultTableColumn(static_cast<int>(index), name, width);
    }
    SyncResultListVirtualRows();

    std::wostringstream status;
    status << L"状态：已刷新 " << currentRows_.size() << L" 项，成功 " << successRows << L" 项";
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, L"无可展示的 NtQuery 结果。");
    }
}

void KernelPage::RebuildDiagnosticDualTableFromCache(const KernelFeatureId featureId) {
    // RebuildDiagnosticDualTableFromCache reshapes DynData and DriverStatus
    // result packets into the original KernelDock dual-table layout. Inputs are
    // raw ArkDriverClient rows and the local filter text; processing builds the
    // original summary labels, visible matrix rows, and status sentence; output
    // updates the summary table, result table, detail editor, and status label.
    if (!resultList_ || !summaryList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring filterText = WindowText(filterEdit_);
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto firstValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        return FirstRowValue(rawRows, rawColumns, names);
    };
    const auto firstNumber = [&](std::initializer_list<const wchar_t*> names, const std::uint64_t fallback = 0) -> std::uint64_t {
        return FirstRowUInt64(rawRows, rawColumns, names, fallback);
    };
    const auto appendSummary = [&](const std::wstring& name, const std::wstring& value) {
        if (!name.empty() && !value.empty()) {
            ListViewInsertRow(summaryList_, { name, value });
        }
    };
    const auto appendSummaryBool = [&](const std::wstring& name, const bool value) {
        ListViewInsertRow(summaryList_, { name, BoolText(value) });
    };
    const auto addHiddenColumn = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!HasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        if (columnName == L"Capability") {
            return rawValue(row, { L"Mask", L"CapabilityMask" });
        }
        if (columnName == L"策略") {
            return rawValue(row, { L"Policy", L"RequiredPolicy", L"Flags", L"SecurityPolicy" });
        }
        if (columnName == L"依赖字段") {
            return rawValue(row, { L"Dependency", L"DependencyText" });
        }
        if (columnName == L"原因") {
            return rawValue(row, { L"Reason", L"Detail", L"LastError" });
        }
        return {};
    };

    ClearResultTable();
    ListView_DeleteAllItems(summaryList_);

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : CanonicalColumnNames(featureId)) {
        if (!HasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    addHiddenColumn(displayColumns, L"Id");
    addHiddenColumn(displayColumns, L"StateId");
    addHiddenColumn(displayColumns, L"StatusFlags");
    addHiddenColumn(displayColumns, L"CapabilityMask");
    addHiddenColumn(displayColumns, L"Version");
    addHiddenColumn(displayColumns, L"Protocol");
    addHiddenColumn(displayColumns, L"ExpectedProtocol");
    addHiddenColumn(displayColumns, L"SecurityPolicy");
    addHiddenColumn(displayColumns, L"DynDataStatus");
    addHiddenColumn(displayColumns, L"DynDataCapability");
    addHiddenColumn(displayColumns, L"FeatureTotal");
    addHiddenColumn(displayColumns, L"FeatureReturned");
    addHiddenColumn(displayColumns, L"LastError");
    addHiddenColumn(displayColumns, L"LastErrorSummary");
        addHiddenColumn(displayColumns, L"LastErrorStatus");
        addHiddenColumn(displayColumns, L"Flags");
        addHiddenColumn(displayColumns, L"StatusQueryOk");
        addHiddenColumn(displayColumns, L"FieldsQueryOk");
        addHiddenColumn(displayColumns, L"PdbProfileScanAttempted");
        addHiddenColumn(displayColumns, L"PdbProfileFound");
        addHiddenColumn(displayColumns, L"PdbProfileApplied");
        addHiddenColumn(displayColumns, L"PdbProfileSource");
        addHiddenColumn(displayColumns, L"PdbProfileName");
        addHiddenColumn(displayColumns, L"PdbProfilePath");
        addHiddenColumn(displayColumns, L"PdbProfileStatus");
        addHiddenColumn(displayColumns, L"PdbProfileAppliedFields");
        addHiddenColumn(displayColumns, L"PdbProfileRejectedFields");
        addHiddenColumn(displayColumns, L"PdbProfileUnknownFields");
        addHiddenColumn(displayColumns, L"PdbProfileIgnoredJsonFields");
        addHiddenColumn(displayColumns, L"PdbProfileMessage");
        addHiddenColumn(displayColumns, L"PdbProfileIo");
        addHiddenColumn(displayColumns, L"MatchedProfileOffset");
        addHiddenColumn(displayColumns, L"MatchedFieldsId");
        addHiddenColumn(displayColumns, L"RequiredPolicy");
        addHiddenColumn(displayColumns, L"DeniedPolicy");
        addHiddenColumn(displayColumns, L"StatusBadges");
        addHiddenColumn(displayColumns, L"DynDataStatusQueryOk");
        addHiddenColumn(displayColumns, L"DynDataFieldsQueryOk");
        addHiddenColumn(displayColumns, L"DynDataStatusIo");
        addHiddenColumn(displayColumns, L"DynDataFieldsIo");
        addHiddenColumn(displayColumns, L"FieldCoverage");
        addHiddenColumn(displayColumns, L"FieldSources");
        addHiddenColumn(displayColumns, L"RequiredMissing");
        addHiddenColumn(displayColumns, L"NtosIdentity");
        addHiddenColumn(displayColumns, L"LxcoreIdentity");
        addHiddenColumn(displayColumns, L"LocalPdbProfileMatched");
        addHiddenColumn(displayColumns, L"LocalPdbProfile");
        addHiddenColumn(displayColumns, L"LocalPdbProfileName");
        addHiddenColumn(displayColumns, L"LocalPdbProfilePath");
        addHiddenColumn(displayColumns, L"LocalPdbMessage");
        addHiddenColumn(displayColumns, L"LocalPdbVersion");
        addHiddenColumn(displayColumns, L"ActiveProcessLinksOffset");
        addHiddenColumn(displayColumns, L"CallbackProfileCoverage");
        addHiddenColumn(displayColumns, L"PdbProfileActive");
        addHiddenColumn(displayColumns, L"CallbackProfileActive");
        addHiddenColumn(displayColumns, L"TrustedPdbOffsetsActive");
        addHiddenColumn(displayColumns, L"TrustedOffset");
        addHiddenColumn(displayColumns, L"UnavailableReason");
        addHiddenColumn(displayColumns, L"Detail");

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t profileRows = 0;
    std::size_t failedRows = 0;
    std::size_t missingRequiredRows = 0;
    std::size_t unavailableRows = 0;
    std::size_t dynDataDependentRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool isDynField = featureId == KernelFeatureId::DynData &&
            HasNonEmptyField(rawRow, rawColumns, { L"Field", L"字段", L"Offset", L"Source", L"Feature", L"Mask" }) &&
            !rawValue(rawRow, { L"Field", L"字段" }).empty();
        const bool isDriverFeature = featureId == KernelFeatureId::DriverStatus &&
            HasNonEmptyField(rawRow, rawColumns, { L"Feature", L"功能", L"State", L"RequiredDyn", L"PresentDyn" }) &&
            !rawValue(rawRow, { L"Feature", L"功能" }).empty();
        const std::wstring merged = MergeRowText(rawRow);
        if (featureId == KernelFeatureId::DynData) {
            const std::wstring source = rawValue(rawRow, { L"Source", L"来源" });
            const std::wstring status = rawValue(rawRow, { L"Status", L"状态", L"DynData Fields IO" });
            if (ContainsCaseInsensitive(source, L"profile") || ContainsCaseInsensitive(source, L"pack") ||
                ContainsCaseInsensitive(source, L"pdb")) {
                ++profileRows;
            }
            if (ContainsCaseInsensitive(status, L"fail") || ContainsCaseInsensitive(status, L"失败") ||
                ContainsCaseInsensitive(status, L"missing") || ContainsCaseInsensitive(status, L"缺失")) {
                ++failedRows;
            }
            if (isDynField && ContainsCaseInsensitive(status, L"缺失(必需)")) {
                ++missingRequiredRows;
            }
        } else if (featureId == KernelFeatureId::DriverStatus) {
            const std::wstring state = rawValue(rawRow, { L"State", L"状态", L"Status" });
            const std::wstring requiredDyn = rawValue(rawRow, { L"RequiredDyn", L"所需DynData" });
            if (ContainsCaseInsensitive(state, L"unavailable") || ContainsCaseInsensitive(state, L"disabled") ||
                ContainsCaseInsensitive(state, L"denied") || ContainsCaseInsensitive(state, L"不可用") ||
                ContainsCaseInsensitive(state, L"禁用")) {
                ++unavailableRows;
            }
            if (!IsZeroMaskText(requiredDyn)) {
                ++dynDataDependentRows;
            }
        }
        if (!isDynField && !isDriverFeature) {
            continue;
        }
        if (!filterText.empty() && !ContainsCaseInsensitive(merged, filterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    if (featureId == KernelFeatureId::DynData) {
        const std::uint64_t statusFlags = firstNumber({ L"StatusFlags" });
        const bool initialized = FlagEnabled(statusFlags, KSW_DYN_STATUS_FLAG_INITIALIZED);
        const bool ntosActive = FlagEnabled(statusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE);
        const bool lxcoreActive = FlagEnabled(statusFlags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE);
        const bool extraActive = FlagEnabled(statusFlags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE);
        const bool pdbActive = FlagEnabled(statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
        const bool callbackActive = FlagEnabled(statusFlags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE);
        appendSummaryBool(L"DynData 初始化", initialized);
        appendSummaryBool(L"ntoskrnl profile", ntosActive);
        appendSummaryBool(L"lxcore profile", lxcoreActive);
        appendSummaryBool(L"Ksword runtime offset", extraActive);
        appendSummaryBool(L"PDB profile active", pdbActive);
        appendSummaryBool(L"PDB profile 扫描", firstValue({ L"PdbProfileScanAttempted" }) == L"是");
        appendSummaryBool(L"PDB profile 命中", firstValue({ L"PdbProfileFound" }) == L"是");
        appendSummaryBool(L"PDB profile 本次应用", firstValue({ L"PdbProfileApplied" }) == L"是");
        appendSummary(L"PDB profile 来源", firstValue({ L"PdbProfileSource" }));
        appendSummary(L"PDB profile 名称", firstValue({ L"PdbProfileName" }));
        appendSummary(L"PDB profile 路径", firstValue({ L"PdbProfilePath" }));
        appendSummary(L"PDB profile 状态", firstValue({ L"PdbProfileStatus" }));
        appendSummary(L"PDB profile 字段", L"applied=" + firstValue({ L"PdbProfileAppliedFields" }) +
            L" rejected=" + firstValue({ L"PdbProfileRejectedFields" }) +
            L" unknown=" + firstValue({ L"PdbProfileUnknownFields" }) +
            L" ignoredJson=" + firstValue({ L"PdbProfileIgnoredJsonFields" }));
        appendSummary(L"PDB profile 消息", firstValue({ L"PdbProfileMessage" }));
        appendSummary(L"PDB profile IO", firstValue({ L"PdbProfileIo" }));
        appendSummaryBool(L"Callback profile active", callbackActive);
        appendSummary(L"状态位", firstValue({ L"StatusFlags" }));
        appendSummary(L"System Informer 版本", firstValue({ L"SI Version" }));
        appendSummary(L"System Informer 数据长度", firstValue({ L"SI Length" }));
        appendSummary(L"MatchedProfileClass", firstValue({ L"MatchedClass", L"ProfileClass" }));
        appendSummary(L"MatchedProfileOffset", firstValue({ L"MatchedProfileOffset" }));
        appendSummary(L"MatchedFieldsId", firstValue({ L"MatchedFieldsId" }));
        appendSummary(L"CapabilityMask", firstValue({ L"CapabilityMask", L"Mask" }));
        appendSummary(L"字段总数/当前返回", firstValue({ L"FieldCount", L"FieldsTotal" }) + L" / " + std::to_wstring(displayRows.size()));
        appendSummary(L"Fields IO", firstValue({ L"DynData Fields IO" }));
        appendSummary(L"ntoskrnl", firstValue({ L"Ntos", L"NtosIdentity" }));
        appendSummary(L"lxcore", firstValue({ L"Lxcore", L"LxcoreIdentity" }));
        appendSummary(L"Profile/Pack 诊断行", std::to_wstring(profileRows));
        appendSummary(L"失败诊断行", std::to_wstring(failedRows));

        std::wstring statusLine = std::wstring(L"状态：") +
            (ntosActive ? L"ntos profile 已命中" : L"ntos profile 未命中") +
            (pdbActive ? L"，PDB profile 已启用" : L"") +
            L"，字段 " + std::to_wstring(displayRows.size()) +
            L" 项，缺失必需 " + std::to_wstring(missingRequiredRows) + L" 项";
        ::SetWindowTextW(statusText_, statusLine.c_str());
    } else {
        const std::uint64_t statusFlags = firstNumber({ L"StatusFlags" });
        const bool driverLoaded = FlagEnabled(statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_DRIVER_LOADED);
        const bool protocolOk = FlagEnabled(statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_PROTOCOL_OK);
        const bool dynDataMissing = FlagEnabled(statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_DYNDATA_MISSING);
        const bool limited = FlagEnabled(statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_LIMITED);
        const std::wstring badges = firstValue({ L"StatusBadges" }).empty()
            ? (std::wstring(L"Driver Loaded=") + BoolText(driverLoaded) +
                L"；Protocol OK=" + BoolText(protocolOk) +
                L"；DynData Missing=" + BoolText(dynDataMissing) +
                L"；Limited=" + BoolText(limited))
            : firstValue({ L"StatusBadges" });
        const std::wstring dynStatus = firstValue({ L"DynDataStatus" });
        const std::wstring dynCapability = firstValue({ L"DynDataCapability", L"CapabilityMask" });
        const std::wstring trustedOffset = !firstValue({ L"TrustedOffset" }).empty()
            ? firstValue({ L"TrustedOffset" })
            : (!dynCapability.empty() && dynCapability != L"0x0"
                ? std::wstring(L"已存在 DynData capability ") + dynCapability
                : std::wstring(L"暂无可用可信偏移。"));
        appendSummary(L"状态栏", badges);
        appendSummaryBool(L"Driver Loaded", driverLoaded);
        appendSummaryBool(L"Protocol OK", protocolOk);
        appendSummaryBool(L"DynData Missing", dynDataMissing);
        appendSummaryBool(L"Limited", limited);
        appendSummary(L"当前内核", firstValue({ L"NtosIdentity", L"Ntos" }));
        appendSummary(L"识别版本", firstValue({ L"LocalPdbVersion", L"KernelVersion" }));
        appendSummary(L"本地 PDB profile", firstValue({ L"LocalPdbProfile", L"LocalPdbMessage" }));
        appendSummary(L"ActiveProcessLinks 偏移", firstValue({ L"ActiveProcessLinksOffset" }));
        appendSummary(L"Callback profile 覆盖", firstValue({ L"CallbackProfileCoverage" }));
        appendSummary(L"可信偏移", trustedOffset);
        appendSummary(L"字段覆盖", firstValue({ L"FieldCoverage" }));
        appendSummary(L"字段来源", firstValue({ L"FieldSources" }));
        appendSummary(L"缺失必需字段", firstValue({ L"RequiredMissing" }));
        appendSummary(L"能力协议版本", firstValue({ L"Version" }));
        appendSummary(L"驱动协议版本", firstValue({ L"Protocol" }));
        appendSummary(L"期望协议版本", firstValue({ L"ExpectedProtocol" }));
        appendSummary(L"状态位", firstValue({ L"StatusFlags" }));
        appendSummary(L"安全策略位", firstValue({ L"SecurityPolicy", L"Policy", L"策略" }));
        appendSummary(L"DynData 状态位", dynStatus);
        appendSummary(L"DynData 能力位", dynCapability);
        appendSummary(L"System Informer 数据", L"version=" + firstValue({ L"SI Version" }) + L" length=" + firstValue({ L"SI Length" }));
        appendSummary(L"匹配内置 Profile", L"class=" + firstValue({ L"MatchedClass" }) +
            L" offset=" + firstValue({ L"MatchedProfileOffset" }) +
            L" fieldsId=" + firstValue({ L"MatchedFieldsId" }));
        appendSummary(L"DynData R3 IO", L"Status=" + firstValue({ L"DynDataStatusQueryOk" }) +
            L" (" + firstValue({ L"DynDataStatusIo" }) + L")；Fields=" +
            firstValue({ L"DynDataFieldsQueryOk" }) + L" (" + firstValue({ L"DynDataFieldsIo" }) + L")");
        appendSummary(L"DynData 不可用原因", firstValue({ L"UnavailableReason" }));
        appendSummary(L"功能数", L"显示 " + std::to_wstring(displayRows.size()) +
            L" / 返回 " + firstValue({ L"FeatureReturned" }) +
            L" / 总计 " + firstValue({ L"FeatureTotal" }));
        appendSummary(L"最近错误", firstValue({ L"LastErrorStatus" }) + L" / " +
            firstValue({ L"LastError" }) + L" / " + firstValue({ L"LastErrorSummary" }));
        appendSummary(L"R3 IO", firstValue({ L"IoMessage", L"Driver Capabilities" }));
        appendSummary(L"不可用/禁用行", std::to_wstring(unavailableRows));
        appendSummary(L"DynData 依赖行", std::to_wstring(dynDataDependentRows));

        const bool driverQueryFailed = rawRows.empty() || (!driverLoaded && !protocolOk && firstValue({ L"Version" }).empty());
        if (driverQueryFailed && dynStatus.empty()) {
            ::SetWindowTextW(statusText_, L"状态：驱动与 DynData 查询均失败");
        } else {
            const std::wstring kernelText = firstValue({ L"NtosIdentity", L"Ntos" }).empty() ? L"内核未识别" : firstValue({ L"NtosIdentity", L"Ntos" });
            const std::wstring statusLine = L"状态：" + badges + L"；" + kernelText + L"；功能 " +
                std::to_wstring(displayRows.size()) + L" 项；可信偏移 " + trustedOffset;
            ::SetWindowTextW(statusText_, statusLine.c_str());
        }
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    currentRowIndents_.clear();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const bool hidden = currentColumns_[index] == L"Id" ||
            currentColumns_[index] == L"StateId" ||
            currentColumns_[index] == L"StatusFlags" ||
            currentColumns_[index] == L"CapabilityMask" ||
            currentColumns_[index] == L"Version" ||
            currentColumns_[index] == L"Protocol" ||
            currentColumns_[index] == L"ExpectedProtocol" ||
            currentColumns_[index] == L"SecurityPolicy" ||
            currentColumns_[index] == L"DynDataStatus" ||
            currentColumns_[index] == L"DynDataCapability" ||
            currentColumns_[index] == L"FeatureTotal" ||
            currentColumns_[index] == L"FeatureReturned" ||
            currentColumns_[index] == L"LastError" ||
            currentColumns_[index] == L"LastErrorSummary" ||
            currentColumns_[index] == L"LastErrorStatus" ||
            currentColumns_[index] == L"Flags" ||
            currentColumns_[index] == L"StatusQueryOk" ||
            currentColumns_[index] == L"FieldsQueryOk" ||
            currentColumns_[index].find(L"PdbProfile") == 0 ||
            currentColumns_[index] == L"MatchedProfileOffset" ||
            currentColumns_[index] == L"MatchedFieldsId" ||
            currentColumns_[index] == L"RequiredPolicy" ||
            currentColumns_[index] == L"DeniedPolicy" ||
            currentColumns_[index] == L"StatusBadges" ||
            currentColumns_[index] == L"DynDataStatusQueryOk" ||
            currentColumns_[index] == L"DynDataFieldsQueryOk" ||
            currentColumns_[index] == L"DynDataStatusIo" ||
            currentColumns_[index] == L"DynDataFieldsIo" ||
            currentColumns_[index] == L"FieldCoverage" ||
            currentColumns_[index] == L"FieldSources" ||
            currentColumns_[index] == L"RequiredMissing" ||
            currentColumns_[index] == L"NtosIdentity" ||
            currentColumns_[index] == L"LxcoreIdentity" ||
            currentColumns_[index] == L"LocalPdbProfileMatched" ||
            currentColumns_[index] == L"LocalPdbProfile" ||
            currentColumns_[index] == L"LocalPdbProfileName" ||
            currentColumns_[index] == L"LocalPdbProfilePath" ||
            currentColumns_[index] == L"LocalPdbMessage" ||
            currentColumns_[index] == L"LocalPdbVersion" ||
            currentColumns_[index] == L"ActiveProcessLinksOffset" ||
            currentColumns_[index] == L"CallbackProfileCoverage" ||
            currentColumns_[index] == L"PdbProfileActive" ||
            currentColumns_[index] == L"CallbackProfileActive" ||
            currentColumns_[index] == L"TrustedPdbOffsetsActive" ||
            currentColumns_[index] == L"TrustedOffset" ||
            currentColumns_[index] == L"UnavailableReason" ||
            currentColumns_[index] == L"Detail";
        AddResultTableColumn(static_cast<int>(index), currentColumns_[index], hidden ? 0 : ColumnWidth(currentColumns_[index]));
    }
    SyncResultListVirtualRows();
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        const std::wstring report = BuildDiagnosticReportForCurrentFeature();
        ::SetWindowTextW(detailEdit_, report.empty() ? EmptyDetailTextForFeature(featureId) : report.c_str());
    }
}

void KernelPage::RebuildCallbackEnumerationListFromCache() {
    // RebuildCallbackEnumerationListFromCache mirrors the original
    // KernelDock.CallbackEnum table. Inputs are raw rows from
    // ArkDriverClient::enumerateCallbacks; processing keeps the exact visible
    // nine columns, preserves hidden protocol fields for remove actions, and
    // applies the local filter edit; output updates resultList_ and detailEdit_.
    if (!resultList_) {
        return;
    }
    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring filterText = WindowText(filterEdit_);
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto addColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!HasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(KernelFeatureId::CallbackEnumeration, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : CanonicalColumnNames(KernelFeatureId::CallbackEnumeration)) {
        addColumnIfMissing(displayColumns, column.c_str());
    }
    addColumnIfMissing(displayColumns, L"SourceIndex");
    addColumnIfMissing(displayColumns, L"Class");
    addColumnIfMissing(displayColumns, L"Source");
    addColumnIfMissing(displayColumns, L"Callback");
    addColumnIfMissing(displayColumns, L"Context");
    addColumnIfMissing(displayColumns, L"Registration");
    addColumnIfMissing(displayColumns, L"ModulePath");
    addColumnIfMissing(displayColumns, L"Win32ModulePath");
    addColumnIfMissing(displayColumns, L"ModuleBase");
    addColumnIfMissing(displayColumns, L"ModuleSize");
    addColumnIfMissing(displayColumns, L"OperationMask");
    addColumnIfMissing(displayColumns, L"ObjectTypeMask");
    addColumnIfMissing(displayColumns, L"FieldFlags");
    addColumnIfMissing(displayColumns, L"Trust");
    addColumnIfMissing(displayColumns, L"Remove");
    addColumnIfMissing(displayColumns, L"RemoveFlags");
    addColumnIfMissing(displayColumns, L"Generation");
    addColumnIfMissing(displayColumns, L"IdentityHash");
    addColumnIfMissing(displayColumns, L"RawStorageValue");
    addColumnIfMissing(displayColumns, L"LastStatus");
    addColumnIfMissing(displayColumns, L"Detail");

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t unsupportedCount = 0;
    std::size_t totalCallbackRows = 0;
    bool responseTruncated = false;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        std::uint64_t flagsValue = 0;
        if (ParseUnsigned64Value(rawValue(rawRow, { L"CallbackEnumResponseFlags", L"ResponseFlags", L"Flags" }), flagsValue) &&
            FlagEnabled(flagsValue, KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED)) {
            responseTruncated = true;
        }
        if (rawValue(rawRow, { L"CallbackEnumTruncated" }) == L"1") {
            responseTruncated = true;
        }
    }
    for (std::size_t sourceIndex = 0; sourceIndex < rawRows.size(); ++sourceIndex) {
        const std::vector<std::wstring>& rawRow = rawRows[sourceIndex];
        const bool meaningful = HasNonEmptyField(rawRow, rawColumns, {
            L"ClassText", L"Class", L"SourceText", L"Source", L"Callback", L"Object", L"Registration", L"RawStorageValue", L"Name", L"ModulePath"
        });
        if (!meaningful) {
            continue;
        }
        ++totalCallbackRows;
        const std::wstring status = rawValue(rawRow, { L"Status", L"状态" });
        if (ContainsCaseInsensitive(status, L"unsupported") || ContainsCaseInsensitive(status, L"未支持")) {
            ++unsupportedCount;
        }
        const std::wstring merged = MergeRowText(rawRow);
        if (!filterText.empty() && !ContainsCaseInsensitive(merged, filterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"SourceIndex") {
                cells[column] = std::to_wstring(sourceIndex);
            } else if (name == L"回调/对象地址") {
                std::wstring value = rawValue(rawRow, { L"Callback" });
                if (value.empty() || value == L"0" || value == L"0x0" || value == L"0x0000000000000000") {
                    value = rawValue(rawRow, { L"Object", L"Registration", L"RawStorageValue", L"Context" });
                }
                cells[column] = std::move(value);
            } else if (name == L"模块") {
                std::wstring module = rawValue(rawRow, { L"ModulePath", L"Module" });
                if (module.empty()) {
                    module = L"<未解析>";
                }
                cells[column] = std::move(module);
            } else if (name == L"名称") {
                std::wstring value = rawValue(rawRow, { L"Name", L"名称" });
                if (value.empty()) {
                    value = L"<无名称>";
                }
                cells[column] = std::move(value);
            } else if (name == L"Win32ModulePath") {
                cells[column] = NormalizeCallbackModulePath(rawValue(rawRow, { L"ModulePath", L"Module" }));
            } else if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail", L"FieldText", L"TrustText", L"RemoveText" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    ClearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const bool hidden = currentColumns_[index] == L"SourceIndex" ||
            currentColumns_[index] == L"Class" ||
            currentColumns_[index] == L"Source" ||
            currentColumns_[index] == L"Callback" ||
            currentColumns_[index] == L"Context" ||
            currentColumns_[index] == L"Registration" ||
            currentColumns_[index] == L"ModulePath" ||
            currentColumns_[index] == L"Win32ModulePath" ||
            currentColumns_[index] == L"ModuleBase" ||
            currentColumns_[index] == L"ModuleSize" ||
            currentColumns_[index] == L"OperationMask" ||
            currentColumns_[index] == L"ObjectTypeMask" ||
            currentColumns_[index] == L"FieldFlags" ||
            currentColumns_[index] == L"Trust" ||
            currentColumns_[index] == L"Remove" ||
            currentColumns_[index] == L"RemoveFlags" ||
            currentColumns_[index] == L"Generation" ||
            currentColumns_[index] == L"IdentityHash" ||
            currentColumns_[index] == L"RawStorageValue" ||
            currentColumns_[index] == L"LastStatus" ||
            currentColumns_[index] == L"Detail";
        int width = hidden ? 0 : ColumnWidth(currentColumns_[index]);
        if (currentColumns_[index] == L"可信状态") {
            width = 170;
        } else if (currentColumns_[index] == L"移除策略") {
            width = 200;
        } else if (currentColumns_[index] == L"回调/对象地址") {
            width = 180;
        } else if (currentColumns_[index] == L"模块") {
            width = 220;
        } else if (currentColumns_[index] == L"名称") {
            width = 260;
        }
        AddResultTableColumn(static_cast<int>(index), currentColumns_[index], width);
    }
    SyncResultListVirtualRows();
    std::wostringstream status;
    status << L"状态：已刷新 " << totalCallbackRows
           << L" 项，私有未支持 " << unsupportedCount << L" 项";
    if (responseTruncated) {
        status << L"，响应截断";
    }
    if (!filterText.empty()) {
        status << L"，显示 " << currentRows_.size() << L" 项";
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, L"当前环境未返回可见回调记录。");
    }
}

void KernelPage::RebuildKernelMemoryScanListFromCache(const KernelFeatureId featureId) {
    // RebuildKernelMemoryScanListFromCache mirrors the original MemoryDock
    // kernel executable/evidence grids. Inputs are raw ArkDriverClient rows
    // cached by RenderResult plus current Win32 filter controls; processing
    // projects only original visible columns while retaining hidden R0 fields for
    // details/actions; return behavior is UI state only.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const bool executablePage = featureId == KernelFeatureId::KernelExecutableMemory;
    const bool riskOnly = riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED;
    const std::wstring primaryFilter = executablePage ? WindowText(moduleFilterEdit_) : WindowText(filterEdit_);
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto addColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!HasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns;
    displayColumns.push_back(L"#");
    for (const std::wstring& column : CanonicalColumnNames(featureId)) {
        if (!HasColumn(displayColumns, column)) {
            displayColumns.push_back(column);
        }
    }
    const wchar_t* hiddenExecutable[] = {
        L"RegionSize", L"Perm", L"Risk", L"OwnerKind", L"OwnerKindText", L"OwnerAddress",
        L"ModuleBase", L"ModuleSize", L"Module", L"Status", L"LastStatus", L"Detail"
    };
    const wchar_t* hiddenEvidence[] = {
        L"Kind", L"RegionSize", L"PageSize", L"Perm", L"Risk", L"OwnerKind", L"OwnerKindText",
        L"OwnerAddress", L"ModuleBase", L"ModuleSize", L"ModuleSizeText", L"Confidence",
        L"BigPoolTag", L"BigPoolFlags", L"SectionRva", L"SectionSize", L"SectionSizeText",
        L"Section", L"HashAlgorithm", L"SampleSize", L"Hash", L"HashText", L"Sample",
        L"LastStatus", L"Detail"
    };
    if (executablePage) {
        for (const wchar_t* column : hiddenExecutable) {
            addColumnIfMissing(displayColumns, column);
        }
    } else {
        for (const wchar_t* column : hiddenEvidence) {
            addColumnIfMissing(displayColumns, column);
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    std::size_t returnedRows = 0;
    std::size_t reportedModuleRows = 0;
    std::size_t reportedBigPoolRows = 0;
    std::size_t moduleRows = 0;
    std::size_t bigPoolRows = 0;
    std::size_t riskRows = 0;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t total = FirstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t returned = FirstNonZeroField(rawRow, rawColumns, { L"Returned" });
        const std::uint64_t modules = FirstNonZeroField(rawRow, rawColumns, { L"Modules" });
        const std::uint64_t bigPool = FirstNonZeroField(rawRow, rawColumns, { L"BigPoolRows" });
        if (total != 0) {
            totalRows = static_cast<std::size_t>(total);
        }
        if (returned != 0) {
            returnedRows = static_cast<std::size_t>(returned);
        }
        if (modules != 0) {
            reportedModuleRows = static_cast<std::size_t>(modules);
        }
        if (bigPool != 0) {
            reportedBigPoolRows = static_cast<std::size_t>(bigPool);
        }
    }
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool isDataRow = executablePage
            ? HasNonEmptyField(rawRow, rawColumns, { L"VA", L"Pages", L"PermText", L"RiskText", L"OwnerDisplay", L"ModulePath" })
            : HasNonEmptyField(rawRow, rawColumns, { L"VA", L"KindText", L"RiskText", L"OwnerDisplay", L"HashText" });
        if (!isDataRow) {
            continue;
        }
        if (totalRows == 0) {
            ++returnedRows;
        }
        const std::wstring riskText = rawValue(rawRow, { L"RiskText", L"风险", L"风险标志" });
        const std::wstring riskValue = rawValue(rawRow, { L"Risk" });
        const bool risky = !riskText.empty() &&
            !ContainsCaseInsensitive(riskText, L"正常") &&
            !ContainsCaseInsensitive(riskValue, L"0x0");
        if (risky) {
            ++riskRows;
        }
        if (riskOnly && !risky) {
            continue;
        }

        std::wstring merged = MergeRowText(rawRow);
        if (executablePage) {
            merged += L" | " + rawValue(rawRow, { L"ModulePath", L"Module" });
            if (!primaryFilter.empty() && !ContainsCaseInsensitive(merged, primaryFilter)) {
                continue;
            }
            if (!rawValue(rawRow, { L"ModulePath", L"Module" }).empty()) {
                ++moduleRows;
            }
        } else {
            if (!primaryFilter.empty() && !ContainsCaseInsensitive(merged, primaryFilter)) {
                continue;
            }
            if (ContainsCaseInsensitive(rawValue(rawRow, { L"KindText", L"类型" }), L"BigPool")) {
                ++bigPoolRows;
            }
            if (!rawValue(rawRow, { L"ModuleBase" }).empty()) {
                ++moduleRows;
            }
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    ClearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        int width = IsKernelMemoryHiddenColumn(currentColumns_[index]) ? 0 : ColumnWidth(currentColumns_[index]);
        if (currentColumns_[index] == L"VA") {
            width = 170;
        } else if (currentColumns_[index] == L"页数" || currentColumns_[index] == L"页大小" || currentColumns_[index] == L"大小") {
            width = 82;
        } else if (currentColumns_[index] == L"权限" || currentColumns_[index] == L"PTE权限") {
            width = 160;
        } else if (currentColumns_[index] == L"Owner") {
            width = 190;
        } else if (currentColumns_[index] == L"模块路径") {
            width = 320;
        } else if (currentColumns_[index] == L"风险标志" || currentColumns_[index] == L"风险") {
            width = 210;
        } else if (currentColumns_[index] == L"text hash/diff") {
            width = 240;
        }
        AddResultTableColumn(static_cast<int>(index), currentColumns_[index], width);
    }
    SyncResultListVirtualRows();

    std::wostringstream status;
    if (executablePage) {
        const std::size_t effectiveTotal = totalRows == 0 ? returnedRows : totalRows;
        const std::size_t effectiveModules = reportedModuleRows == 0 ? moduleRows : reportedModuleRows;
        status << L"状态：总计 " << effectiveTotal
               << L"，显示 " << currentRows_.size()
               << L"，模块 " << effectiveModules
               << L"，风险项 " << riskRows;
    } else {
        const std::size_t effectiveTotal = totalRows == 0 ? returnedRows : totalRows;
        const std::size_t effectiveReturned = returnedRows == 0 ? effectiveTotal : returnedRows;
        const std::size_t effectiveModules = reportedModuleRows == 0 ? moduleRows : reportedModuleRows;
        const std::size_t effectiveBigPool = reportedBigPoolRows == 0 ? bigPoolRows : reportedBigPoolRows;
        status << L"状态：总计 " << effectiveTotal
               << L"，返回 " << effectiveReturned
               << L"，显示 " << currentRows_.size()
               << L"，模块 " << effectiveModules
               << L"，BigPool seen " << effectiveBigPool;
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, executablePage
            ? L"当前过滤条件下没有内核可执行页记录。"
            : L"当前过滤条件下没有内核内存证据记录。");
    }
}

void KernelPage::RebuildCrossViewListFromCache(const KernelFeatureId featureId) {
    // RebuildCrossViewListFromCache mirrors the original ProcessDock CrossView
    // matrix table. Inputs are raw R0 rows cached by RenderResult and the local
    // filter edit; processing keeps the visible matrix columns identical while
    // preserving offset/source fields for details; output is ListView/detail UI.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring filterText = WindowText(filterEdit_);
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };
    const auto addColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!HasColumn(columns, name)) {
            columns.push_back(name);
        }
    };

    std::vector<std::wstring> displayColumns;
    for (const std::wstring& column : CanonicalColumnNames(featureId)) {
        addColumnIfMissing(displayColumns, column.c_str());
    }
    const wchar_t* hiddenColumns[] = {
        L"PID", L"PPID", L"TID", L"Image", L"Object", L"ProcessObject", L"ThreadObject",
        L"Start", L"StartAddress", L"SourceMask", L"SourceText", L"Anomaly", L"AnomalyText",
        L"DynData", L"DynDataCapabilityMask", L"EP.UniqueProcessId", L"EP.ActiveProcessLinks",
        L"EP.ThreadListHead", L"EP.ImageFileName", L"ET.Cid", L"ET.ThreadListEntry",
        L"ET.StartAddress", L"ET.Win32StartAddress", L"KT.Process", L"HT.TableCode",
        L"HTE.LowValue", L"PspCidTableRva", L"PspCidTable", L"Confidence", L"LastStatus"
    };
    for (const wchar_t* column : hiddenColumns) {
        addColumnIfMissing(displayColumns, column);
    }

    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    std::wstring missingDynText;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t total = FirstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t returned = FirstNonZeroField(rawRow, rawColumns, { L"Returned" });
        if (total != 0) {
            reportedTotalRows = static_cast<std::size_t>(total);
        }
        if (returned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(returned);
        }
        if (missingDynText.empty()) {
            missingDynText = rawValue(rawRow, { L"MissingDyn", L"MissingDynData", L"MissingCapabilityMask" });
        }
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t totalRows = 0;
    std::size_t anomalyRows = 0;
    std::size_t cidOnlyRows = 0;
    const bool anomalyOnly = riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool rowLooksLikeProcess = featureId == KernelFeatureId::ProcessCrossView &&
            HasNonEmptyField(rawRow, rawColumns, { L"PID", L"ProcessObject", L"Object", L"Image" });
        const bool rowLooksLikeThread = featureId == KernelFeatureId::ThreadCrossView &&
            HasNonEmptyField(rawRow, rawColumns, { L"TID", L"ThreadObject", L"Object", L"ProcessObject" });
        if (!rowLooksLikeProcess && !rowLooksLikeThread) {
            continue;
        }
        ++totalRows;
        std::uint64_t anomalyMask = 0;
        const bool parsedAnomalyMask = HexToUInt64(rawValue(rawRow, { L"Anomaly" }), anomalyMask);
        const std::wstring anomaly = rawValue(rawRow, { L"异常", L"AnomalyText" });
        const bool anomalous = parsedAnomalyMask
            ? anomalyMask != 0
            : (!anomaly.empty() && !ContainsCaseInsensitive(anomaly, L"正常") && !ContainsCaseInsensitive(anomaly, L"0x0"));
        if (anomalous) {
            ++anomalyRows;
        }
        if (anomalyOnly && !anomalous) {
            continue;
        }
        const std::wstring merged = MergeRowText(rawRow);
        if (!filterText.empty() && !ContainsCaseInsensitive(merged, filterText)) {
            continue;
        }
        const std::wstring publicWalk = rawValue(rawRow, { L"PublicWalk" });
        const std::wstring active = rawValue(rawRow, { L"Active/ThreadList" });
        const std::wstring cid = rawValue(rawRow, { L"CID" });
        if (ContainsCaseInsensitive(cid, L"是") &&
            !ContainsCaseInsensitive(publicWalk, L"是") &&
            !ContainsCaseInsensitive(active, L"是")) {
            ++cidOnlyRows;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    ClearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool hidden = name == L"PID" ||
            name == L"PPID" ||
            name == L"TID" ||
            name == L"Image" ||
            name == L"Object" ||
            name == L"ProcessObject" ||
            name == L"ThreadObject" ||
            name == L"Start" ||
            name == L"StartAddress" ||
            name == L"SourceMask" ||
            name == L"SourceText" ||
            name == L"Anomaly" ||
            name == L"AnomalyText" ||
            name == L"DynData" ||
            name == L"DynDataCapabilityMask" ||
            name == L"EP.UniqueProcessId" ||
            name == L"EP.ActiveProcessLinks" ||
            name == L"EP.ThreadListHead" ||
            name == L"EP.ImageFileName" ||
            name == L"ET.Cid" ||
            name == L"ET.ThreadListEntry" ||
            name == L"ET.StartAddress" ||
            name == L"ET.Win32StartAddress" ||
            name == L"KT.Process" ||
            name == L"HT.TableCode" ||
            name == L"HTE.LowValue" ||
            name == L"PspCidTableRva" ||
            name == L"PspCidTable" ||
            name == L"Confidence" ||
            name == L"LastStatus";
        int width = hidden ? 0 : ColumnWidth(name);
        if (name == L"ID") {
            width = 84;
        } else if (name == L"对象") {
            width = 170;
        } else if (name == L"进程") {
            width = 180;
        } else if (name == L"PublicWalk" || name == L"Active/ThreadList" || name == L"CID") {
            width = 92;
        } else if (name == L"异常") {
            width = 210;
        } else if (name == L"置信度") {
            width = 72;
        } else if (name == L"Detail") {
            width = 300;
        }
        AddResultTableColumn(static_cast<int>(index), name, width);
    }
    SyncResultListVirtualRows();

    std::wostringstream status;
    const std::size_t effectiveTotal = reportedTotalRows == 0 ? totalRows : reportedTotalRows;
    const std::size_t effectiveReturned = reportedReturnedRows == 0 ? totalRows : reportedReturnedRows;
    status << L"状态：" << (featureId == KernelFeatureId::ProcessCrossView ? L"进程" : L"线程")
           << L" Cross-View 已刷新，显示 " << currentRows_.size()
           << L"，返回 " << effectiveReturned << L"/" << effectiveTotal
           << L"，异常 " << anomalyRows << L"，CID-only " << cidOnlyRows
           << L"，missingCaps=" << (missingDynText.empty() ? L"0x0" : missingDynText);
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, L"当前过滤条件下没有 Cross-View 记录。");
    }
}


void KernelPage::RebuildIntegrityEvidenceListFromCache(const KernelFeatureId featureId) {
    // RebuildIntegrityEvidenceListFromCache mirrors the original DriverDock and
    // HardwareDock integrity evidence tables. Inputs are raw R0 rows cached by
    // RenderResult and the local filter edit; processing projects the original
    // visible columns while retaining raw protocol fields for detail/actions;
    // output is the updated ListView, status text, and detail pane selection.
    if (!resultList_) {
        return;
    }

    const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring filterText = WindowText(filterEdit_);
    const bool cpuPage = featureId == KernelFeatureId::KernelCpuIntegrity;
    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto addColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!HasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };

    std::vector<std::wstring> displayColumns;
    displayColumns.push_back(L"#");
    for (const std::wstring& column : CanonicalColumnNames(featureId)) {
        addColumnIfMissing(displayColumns, column.c_str());
    }
    const wchar_t* hiddenColumns[] = {
        L"Class", L"ClassText", L"Risk", L"RiskText", L"Source", L"SourceMask", L"SourceText",
        L"Confidence", L"Group", L"CPU", L"Vector", L"CpuVector", L"Object", L"ObjectAddress",
        L"Target", L"TargetAddress", L"OwnerBase", L"OwnerModuleBase", L"OwnerSize",
        L"OwnerModuleSize", L"OwnerModuleSizeText", L"OwnerModule", L"LastStatus"
    };
    for (const wchar_t* column : hiddenColumns) {
        addColumnIfMissing(displayColumns, column);
    }

    std::vector<std::vector<std::wstring>> displayRows;
    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    std::size_t reportedCpuRows = 0;
    std::size_t reportedModuleRows = 0;
    std::size_t totalRows = 0;
    std::size_t riskRows = 0;
    std::wstring r0State;
    std::wstring r0Protocol;
    std::wstring dynDataState;
    std::wstring queryStatus;
    std::wstring sourceText;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t total = FirstNonZeroField(rawRow, rawColumns, { L"Total" });
        const std::uint64_t returned = FirstNonZeroField(rawRow, rawColumns, { L"Returned" });
        const std::uint64_t cpuCount = FirstNonZeroField(rawRow, rawColumns, { L"CpuCount" });
        const std::uint64_t moduleCount = FirstNonZeroField(rawRow, rawColumns, { L"ModuleCount" });
        if (total != 0) {
            reportedTotalRows = static_cast<std::size_t>(total);
        }
        if (returned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(returned);
        }
        if (cpuCount != 0) {
            reportedCpuRows = static_cast<std::size_t>(cpuCount);
        }
        if (moduleCount != 0) {
            reportedModuleRows = static_cast<std::size_t>(moduleCount);
        }
        if (r0State.empty()) {
            r0State = RowFieldByName(rawRow, rawColumns, { L"R0" });
        }
        if (r0Protocol.empty()) {
            r0Protocol = RowFieldByName(rawRow, rawColumns, { L"Protocol" });
        }
        if (dynDataState.empty()) {
            dynDataState = RowFieldByName(rawRow, rawColumns, { L"DynDataStatus" });
        }
        if (queryStatus.empty()) {
            queryStatus = RowFieldByName(rawRow, rawColumns, { L"Status" });
        }
        if (sourceText.empty()) {
            sourceText = RowFieldByName(rawRow, rawColumns, { L"SourceText", L"SourceMask" });
        }
    }
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const bool evidenceRow = HasNonEmptyField(rawRow, rawColumns, {
            L"类别", L"Class", L"ClassText", L"对象", L"ObjectAddress", L"目标", L"TargetAddress",
            L"Owner", L"OwnerModule", L"CPU/Vector", L"CpuVector", L"风险", L"RiskText"
        });
        if (!evidenceRow) {
            continue;
        }
        ++totalRows;
        const std::wstring riskText = rawValue(rawRow, { L"风险", L"RiskText", L"Risk" });
        const std::wstring riskMask = rawValue(rawRow, { L"Risk" });
        const bool risky = !riskText.empty() &&
            !ContainsCaseInsensitive(riskText, L"正常") &&
            !ContainsCaseInsensitive(riskMask, L"0x0") &&
            riskMask != L"0";
        if (risky) {
            ++riskRows;
        }
        const bool supportsRiskOnly = featureId == KernelFeatureId::MutationAudit;
        if (supportsRiskOnly && riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED && !risky) {
            continue;
        }
        const std::wstring merged = MergeRowText(rawRow);
        if (!filterText.empty() && !ContainsCaseInsensitive(merged, filterText)) {
            continue;
        }

        std::vector<std::wstring> cells(displayColumns.size());
        for (std::size_t column = 0; column < displayColumns.size(); ++column) {
            const std::wstring& name = displayColumns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(displayRows.size());
            } else if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        displayRows.push_back(std::move(cells));
    }

    currentColumns_ = std::move(displayColumns);
    currentRows_ = std::move(displayRows);
    ClearResultTable();
    for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
        const std::wstring& name = currentColumns_[index];
        const bool canonicalColumn = HasColumn(CanonicalColumnNames(featureId), name);
        int width = (!canonicalColumn && IsIntegrityHiddenColumn(name)) ? 0 : ColumnWidth(name);
        if (name == L"类别") {
            width = 150;
        } else if (name == L"对象" || name == L"目标" || name == L"对象/寄存器" || name == L"目标/入口") {
            width = 170;
        } else if (name == L"Owner" || name == L"Owner模块") {
            width = 240;
        } else if (name == L"CPU/Vector") {
            width = 110;
        } else if (name == L"风险") {
            width = 220;
        } else if (name == L"置信度") {
            width = 72;
        } else if (name == L"Detail") {
            width = 360;
        }
        AddResultTableColumn(static_cast<int>(index), name, width);
    }
    SyncResultListVirtualRows();

    std::wostringstream status;
    const std::size_t effectiveTotal = reportedTotalRows == 0 ? totalRows : reportedTotalRows;
    const std::size_t effectiveReturned = reportedReturnedRows == 0 ? totalRows : reportedReturnedRows;
    status << L"状态：" << (cpuPage ? L"CPU/IDT 完整性" : L"驱动完整性")
           << L"已刷新，显示 " << currentRows_.size()
           << L"，返回 " << effectiveReturned << L"/" << effectiveTotal
           << L"，风险 " << riskRows;
    if (!queryStatus.empty()) {
        status << L"，Query " << queryStatus;
    }
    if (!sourceText.empty()) {
        status << L"，Source " << sourceText;
    }
    if (reportedCpuRows != 0 || reportedModuleRows != 0) {
        status << L"，CPU " << reportedCpuRows << L"，模块 " << reportedModuleRows;
    }
    if (cpuPage && (!r0State.empty() || !r0Protocol.empty() || !dynDataState.empty())) {
        status << L"，R0 " << (r0State.empty() ? L"<unknown>" : r0State)
               << L"，Protocol " << (r0Protocol.empty() ? L"-" : r0Protocol)
               << L"，DynData " << (dynDataState.empty() ? L"-" : dynDataState);
    }
    ::SetWindowTextW(statusText_, status.str().c_str());
    if (!currentRows_.empty()) {
        ListView_SetItemState(resultList_, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_EnsureVisible(resultList_, 0, FALSE);
        UpdateSelectedRowDetail();
    } else {
        ::SetWindowTextW(detailEdit_, cpuPage
            ? L"当前过滤条件下没有 CPU/IDT 完整性证据。"
            : L"当前过滤条件下没有驱动完整性证据。");
    }
}

// BuildR0EvidenceSnapshot projects an immutable raw R0 table without touching
// Win32 controls. It runs on the filter worker, allowing large driver audits to
// remain responsive while the user edits the local search text.
KernelR0EvidenceSnapshot BuildR0EvidenceSnapshot(
    const KernelFeatureId featureId,
    std::wstring pageName,
    std::vector<std::wstring> rawColumns,
    std::vector<std::vector<std::wstring>> rawRows,
    std::wstring filterText,
    const bool riskOnly,
    std::wstring selectedRowSignature,
    const int topRow) {
    KernelR0EvidenceSnapshot snapshot{};
    snapshot.featureId = featureId;
    snapshot.selectedRowSignature = std::move(selectedRowSignature);
    snapshot.topRow = topRow;

    const auto rawValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, rawColumns, names);
    };
    const auto addColumnIfMissing = [](std::vector<std::wstring>& columns, const wchar_t* name) {
        if (!HasColumn(columns, name)) {
            columns.push_back(name);
        }
    };
    const auto displayValue = [&](const std::vector<std::wstring>& row, const std::wstring& columnName) -> std::wstring {
        std::vector<std::wstring> aliases = ColumnAliases(featureId, columnName);
        if (aliases.empty()) {
            aliases.push_back(columnName);
        }
        for (const std::wstring& alias : aliases) {
            const std::wstring value = rawValue(row, { alias.c_str() });
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };
    const auto isDataRow = [&](const std::vector<std::wstring>& row) {
        switch (featureId) {
        case KernelFeatureId::CpuHardwareSnapshot:
            return HasNonEmptyField(row, rawColumns, { L"Brand", L"Vendor", L"FeatureMask", L"Leaf1ECX", L"项目" });
        case KernelFeatureId::PhysicalMemoryLayout:
            return HasNonEmptyField(row, rawColumns, { L"Ranges", L"TotalBytes", L"HighestAddress", L"范围" });
        case KernelFeatureId::MutationAudit:
            return HasNonEmptyField(row, rawColumns, { L"Seq", L"Tx", L"Operation", L"TargetKind", L"Address" });
        case KernelFeatureId::KeyboardHotkeys:
            return HasNonEmptyField(row, rawColumns, { L"PID", L"TID", L"热键", L"Object", L"WindowObject" });
        case KernelFeatureId::KeyboardHooks:
            return HasNonEmptyField(row, rawColumns, { L"PID", L"TID", L"Hook类型", L"Procedure", L"Object" });
        case KernelFeatureId::DynDataCapabilities:
            return HasNonEmptyField(row, rawColumns, { L"Capability", L"CapabilityMask", L"StatusFlags", L"字段" });
        case KernelFeatureId::MinifilterBypassPids:
            return HasNonEmptyField(row, rawColumns, { L"PID", L"Process", L"Index" });
        case KernelFeatureId::KernelTimerDpc:
            return HasNonEmptyField(row, rawColumns, { L"Timer", L"TimerAddress", L"DPC", L"DpcAddress" });
        case KernelFeatureId::IoctlRegistry:
            return HasNonEmptyField(row, rawColumns, { L"IOCTL", L"IoControlCode", L"Name", L"FunctionNumber" });
        default:
            return false;
        }
    };

    snapshot.columns.push_back(L"#");
    for (const std::wstring& column : CanonicalColumnNames(featureId)) {
        addColumnIfMissing(snapshot.columns, column.c_str());
    }
    for (const std::wstring& column : rawColumns) {
        addColumnIfMissing(snapshot.columns, column.c_str());
    }
    addColumnIfMissing(snapshot.columns, L"Detail");

    std::size_t reportedTotalRows = 0;
    std::size_t reportedReturnedRows = 0;
    std::size_t totalRows = 0;
    std::size_t riskRows = 0;
    std::wstring queryStatus;
    std::wstring unsupportedText;
    std::wstring protocolVersion;
    std::wstring lastStatus;
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        const std::uint64_t total = FirstNonZeroField(rawRow, rawColumns, { L"Total", L"TotalCount" });
        const std::uint64_t returned = FirstNonZeroField(rawRow, rawColumns, { L"Returned", L"ReturnedCount" });
        if (total != 0) {
            reportedTotalRows = static_cast<std::size_t>(total);
        }
        if (returned != 0) {
            reportedReturnedRows = static_cast<std::size_t>(returned);
        }
        if (queryStatus.empty()) {
            queryStatus = rawValue(rawRow, { L"Status", L"状态" });
        }
        if (unsupportedText.empty()) {
            unsupportedText = rawValue(rawRow, { L"Unsupported" });
        }
        if (protocolVersion.empty()) {
            protocolVersion = rawValue(rawRow, { L"Version", L"Protocol" });
        }
        if (lastStatus.empty()) {
            lastStatus = rawValue(rawRow, { L"LastStatus" });
        }
    }
    snapshot.rows.reserve(rawRows.size());
    for (const std::vector<std::wstring>& rawRow : rawRows) {
        if (!isDataRow(rawRow)) {
            continue;
        }
        ++totalRows;
        const std::wstring risk = rawValue(rawRow, { L"RiskText", L"Risk", L"FlagsText", L"Flags", L"状态", L"Status" });
        const bool risky = ContainsCaseInsensitive(risk, L"风险") ||
            ContainsCaseInsensitive(risk, L"异常") ||
            ContainsCaseInsensitive(risk, L"failed") ||
            ContainsCaseInsensitive(risk, L"失败") ||
            ContainsCaseInsensitive(risk, L"rejected");
        if (risky) {
            ++riskRows;
        }
        if (riskOnly && !risky) {
            continue;
        }
        if (!filterText.empty() && !ContainsCaseInsensitive(MergeRowText(rawRow), filterText)) {
            continue;
        }
        std::vector<std::wstring> cells(snapshot.columns.size());
        for (std::size_t column = 0; column < snapshot.columns.size(); ++column) {
            const std::wstring& name = snapshot.columns[column];
            if (name == L"#") {
                cells[column] = std::to_wstring(snapshot.rows.size());
            } else if (name == L"Detail") {
                cells[column] = rawValue(rawRow, { L"Detail" });
            } else {
                cells[column] = displayValue(rawRow, name);
            }
        }
        snapshot.rows.push_back(std::move(cells));
    }

    const std::size_t effectiveTotal = reportedTotalRows == 0 ? totalRows : reportedTotalRows;
    const std::size_t effectiveReturned = reportedReturnedRows == 0 ? totalRows : reportedReturnedRows;
    std::wostringstream status;
    status << L"状态：" << pageName << L"已刷新，显示 " << snapshot.rows.size()
           << L"，返回 " << effectiveReturned << L"/" << effectiveTotal;
    if (riskRows != 0) {
        status << L"，风险/异常 " << riskRows;
    }
    if (!queryStatus.empty()) {
        status << L"，Query " << queryStatus;
    }
    if (!unsupportedText.empty()) {
        status << L"，Unsupported " << unsupportedText;
    }
    if (!protocolVersion.empty()) {
        status << L"，Ver " << protocolVersion;
    }
    if (!lastStatus.empty()) {
        status << L"，Last " << lastStatus;
    }
    snapshot.statusText = status.str();
    return snapshot;
}

void KernelPage::RebuildR0EvidenceListFromCache(const KernelFeatureId featureId) {
    // RebuildR0EvidenceListFromCache projects remaining R0-only KernelDock pages
    // into their original fixed-column tables. Inputs are raw facade rows and
    // the local filter edit; processing applies client-side filtering so edit-box
    // changes do not discard rows; output is the visible Win32 ListView and the
    // detail pane for the selected row.
    RequestR0EvidenceRebuild(featureId);
}

void KernelPage::ScheduleR0EvidenceFilter(const KernelFeatureId featureId) {
    if (!hwnd_ || !IsR0EvidenceFeature(featureId)) {
        return;
    }
    pendingR0EvidenceFeatureId_ = featureId;
    hasPendingR0EvidenceFilter_ = true;
    ::SetTimer(hwnd_, kTimerR0EvidenceFilter, 200, nullptr);
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor(); descriptor != nullptr) {
        ::SetWindowTextW(statusText_, (L"状态：正在等待筛选输入完成（200ms）… " + descriptor->title).c_str());
    }
}

void KernelPage::RequestR0EvidenceRebuild(const KernelFeatureId featureId) {
    if (!resultList_ || !IsR0EvidenceFeature(featureId)) {
        return;
    }
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr || descriptor->id != featureId) {
        return;
    }
    std::vector<std::wstring> rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
    std::vector<std::vector<std::wstring>> rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
    const std::wstring filterText = WindowText(filterEdit_);
    const bool riskOnly = riskOnlyCheck_ && Button_GetCheck(riskOnlyCheck_) == BST_CHECKED;
    const int selected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    std::wstring selectedSignature = selected >= 0 && selected < static_cast<int>(currentRows_.size())
        ? MergeRowText(currentRows_[static_cast<std::size_t>(selected)])
        : std::wstring{};
    const int topRow = std::max(0, ListView_GetTopIndex(resultList_));
    std::wstring pageName = descriptor->title;
    if (!r0EvidenceFilterTask_) {
        ApplyR0EvidenceSnapshot(BuildR0EvidenceSnapshot(featureId, pageName, rawColumns, rawRows, filterText,
            riskOnly, selectedSignature, topRow));
        return;
    }
    ::SetWindowTextW(statusText_, (L"状态：正在后台筛选 " + pageName + L"…").c_str());
    r0EvidenceFilterTask_->request(
        [featureId, pageName = std::move(pageName), rawColumns = std::move(rawColumns), rawRows = std::move(rawRows),
            filterText = std::move(filterText), riskOnly, selectedSignature = std::move(selectedSignature), topRow]() mutable {
            return BuildR0EvidenceSnapshot(featureId, std::move(pageName), std::move(rawColumns), std::move(rawRows),
                std::move(filterText), riskOnly, std::move(selectedSignature), topRow);
        },
        [this](std::uint64_t, std::optional<KernelR0EvidenceSnapshot>&& snapshot, std::exception_ptr error) {
            if (error || !snapshot.has_value()) {
                ::SetWindowTextW(statusText_, L"状态：R0 证据后台筛选异常结束，保留当前结果。");
                return;
            }
            const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
            if (descriptor == nullptr || descriptor->id != snapshot->featureId) {
                return;
            }
            ApplyR0EvidenceSnapshot(std::move(*snapshot));
        });
}

void KernelPage::ApplyR0EvidenceSnapshot(KernelR0EvidenceSnapshot snapshot) {
    if (!resultList_ || !IsR0EvidenceFeature(snapshot.featureId)) {
        return;
    }
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr || descriptor->id != snapshot.featureId) {
        return;
    }
    const bool schemaChanged = currentColumns_ != snapshot.columns;
    currentColumns_ = std::move(snapshot.columns);
    currentRows_ = std::move(snapshot.rows);
    currentRowIndents_.clear();
    if (schemaChanged) {
        ClearResultGridOnly();
        const std::vector<std::wstring> canonical = CanonicalColumnNames(snapshot.featureId);
        for (std::size_t index = 0; index < currentColumns_.size(); ++index) {
            const std::wstring& name = currentColumns_[index];
            int width = (name != L"#" && !HasColumn(canonical, name)) ? 0 : ColumnWidth(name);
            if (name == L"对象") width = 180;
            else if (name == L"热键ID" || name == L"进程ID" || name == L"线程ID" || name == L"Flags") width = 80;
            else if (name == L"热键" || name == L"类型" || name == L"范围" || name == L"VK/Mod") width = 130;
            else if (name == L"函数/偏移") width = 170;
            else if (name == L"详情") width = 300;
            else if (name == L"项目" || name == L"Capability") width = 170;
            else if (name == L"值" || name == L"摘要" || name == L"Features" || name == L"字段" || name == L"原因") width = 260;
            else if (name == L"Tx" || name == L"Address" || name == L"回调") width = 165;
            else if (name == L"PID" || name == L"TID" || name == L"Bytes") width = 72;
            else if (name == L"进程" || name == L"Process") width = 180;
            else if (name == L"Detail") width = 320;
            AddResultTableColumn(static_cast<int>(index), name, width);
        }
    }
    SyncResultListVirtualRows();
    ::SetWindowTextW(statusText_, snapshot.statusText.c_str());
    if (currentRows_.empty()) {
        ::SetWindowTextW(detailEdit_, L"当前过滤条件下没有 R0 证据记录。");
        InvalidateCurrentFeatureViewCache();
        return;
    }
    int selectedRow = 0;
    if (!snapshot.selectedRowSignature.empty()) {
        const auto found = std::find_if(currentRows_.begin(), currentRows_.end(), [&snapshot](const auto& row) {
            return MergeRowText(row) == snapshot.selectedRowSignature;
        });
        if (found != currentRows_.end()) {
            selectedRow = static_cast<int>(std::distance(currentRows_.begin(), found));
        }
    }
    const int topRow = std::max(0, std::min(snapshot.topRow, static_cast<int>(currentRows_.size()) - 1));
    ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_SetItemState(resultList_, selectedRow, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(resultList_, topRow > 0 ? topRow : selectedRow, FALSE);
    UpdateSelectedRowDetail();
    InvalidateCurrentFeatureViewCache();
}

void KernelPage::SortResultRowsByColumn(const int columnIndex) {
    // SortResultRowsByColumn sorts the current result cache by one visible
    // column. Input is the clicked column index; processing toggles direction
    // when clicking the same column; output is the rebuilt ListView.
    if (columnIndex < 0 || columnIndex >= static_cast<int>(currentColumns_.size()) || currentRows_.empty()) {
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::ObjectNamespaceOverview ||
            descriptor->id == KernelFeatureId::ObjectDirectoryRecursive)) {
        ::SetWindowTextW(statusText_, L"状态：对象命名空间树保持目录层级顺序，未执行排序。");
        return;
    }
    if (sortColumn_ == columnIndex) {
        sortAscending_ = !sortAscending_;
    } else {
        sortColumn_ = columnIndex;
        sortAscending_ = true;
    }
    Ksword::Ui::ScopedListViewRedrawLock resultListLock(resultList_);
    Ksword::Ui::ScopedListViewRedrawLock propertyListLock(propertyList_);
    Ksword::Ui::ScopedListViewRedrawLock summaryListLock(summaryList_);
    Ksword::Ui::ScopedWindowRedrawLock objectTreeLock(objectNamespaceTree_);

    // Nearly every kernel feature table puts addresses, sizes, counts and status
    // codes in these columns, and a plain string compare orders them by their
    // printed characters: 0x2 lands after 0x1FF and 9 lands after 10. The
    // comparison is numeric whenever both cells start with a number and falls
    // back to the case-insensitive string order otherwise.
    std::stable_sort(currentRows_.begin(), currentRows_.end(), [&](const auto& left, const auto& right) {
        const std::wstring leftValue = columnIndex < static_cast<int>(left.size()) ? left[static_cast<std::size_t>(columnIndex)] : std::wstring{};
        const std::wstring rightValue = columnIndex < static_cast<int>(right.size()) ? right[static_cast<std::size_t>(columnIndex)] : std::wstring{};
        const int compare = Ksword::Ui::CompareCellsNumericAware(leftValue, rightValue);
        return sortAscending_ ? compare < 0 : compare > 0;
    });
    SyncResultListVirtualRows();
    UpdateSelectedRowDetail();
    InvalidateCurrentFeatureViewCache();
}

void KernelPage::UpdateSelectedRowDetail() {
    // UpdateSelectedRowDetail expands the selected result row into key/value
    // text. Inputs are current selection and cached columns; processing reads
    // visible ListView text so sorted rows stay accurate; output is the read-only
    // detail edit content.
    if (!resultList_ || !detailEdit_) {
        return;
    }
    const int row = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (row < 0) {
        ::SetWindowTextW(detailEdit_, L"");
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor()) {
        const std::wstring originalStyleDetail = BuildOriginalStyleSelectedRowDetail(descriptor->id, row);
        if (!originalStyleDetail.empty()) {
            ::SetWindowTextW(detailEdit_, originalStyleDetail.c_str());
            UpdatePropertyTableFromSelection();
            return;
        }
    }
    const int columns = HeaderColumnCount(resultList_);
    std::wstring detail;
    for (int column = 0; column < columns; ++column) {
        const std::wstring name = column < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(column)]
            : std::wstring(L"Column ") + std::to_wstring(column);
        const std::wstring value = VisibleCellText(row, column);
        if (value.empty()) {
            continue;
        }
        if (!detail.empty()) {
            detail += L"\r\n";
        }
        detail += name;
        detail += L": ";
        detail += value;
    }
    ::SetWindowTextW(detailEdit_, detail.c_str());
    UpdatePropertyTableFromSelection();
}

LRESULT KernelPage::HandleResultListCustomDraw(const LPARAM lParam) {
    // HandleResultListCustomDraw colors Callback Enumeration evidence columns
    // like the original full Dock table. Input is the ListView custom-draw payload;
    // processing only changes text color for trust/status/remove-policy
    // subitems; output is the custom-draw stage directive expected by Win32.
    auto* draw = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
    if (draw == nullptr) {
        return CDRF_DODEFAULT;
    }

    switch (draw->nmcd.dwDrawStage) {
    case CDDS_PREPAINT:
        return CDRF_NOTIFYITEMDRAW;
    case CDDS_ITEMPREPAINT:
        return CDRF_NOTIFYSUBITEMDRAW;
    case CDDS_SUBITEM | CDDS_ITEMPREPAINT:
        break;
    default:
        return CDRF_DODEFAULT;
    }

    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr || descriptor->id != KernelFeatureId::CallbackEnumeration) {
        return CDRF_DODEFAULT;
    }

    const int row = static_cast<int>(draw->nmcd.dwItemSpec);
    const int column = draw->iSubItem;
    if (row < 0 || column < 0 || column >= static_cast<int>(currentColumns_.size())) {
        return CDRF_DODEFAULT;
    }

    const std::wstring& columnName = currentColumns_[static_cast<std::size_t>(column)];
    const std::wstring value = VisibleCellText(row, column);
    if (columnName == L"可信状态") {
        if (ContainsCaseInsensitive(value, L"可信") || ContainsCaseInsensitive(value, L"public") ||
            ContainsCaseInsensitive(value, L"pdb")) {
            draw->clrText = RGB(0x3A, 0x8F, 0x3A);
        } else if (ContainsCaseInsensitive(value, L"fallback") || ContainsCaseInsensitive(value, L"pattern") ||
            ContainsCaseInsensitive(value, L"私有")) {
            draw->clrText = RGB(0xD7, 0x7A, 0x00);
        } else if (ContainsCaseInsensitive(value, L"unsupported") || ContainsCaseInsensitive(value, L"未支持")) {
            draw->clrText = RGB(0x8A, 0x8A, 0x8A);
        }
        return CDRF_DODEFAULT;
    }

    if (columnName == L"状态") {
        if (ContainsCaseInsensitive(value, L"Query failed") || ContainsCaseInsensitive(value, L"失败")) {
            draw->clrText = RGB(0xB2, 0x3A, 0x3A);
        } else if (ContainsCaseInsensitive(value, L"Unsupported") || ContainsCaseInsensitive(value, L"未支持") ||
            ContainsCaseInsensitive(value, L"truncated")) {
            draw->clrText = RGB(0xD7, 0x7A, 0x00);
        }
        return CDRF_DODEFAULT;
    }

    if (columnName == L"移除策略") {
        if (ContainsCaseInsensitive(value, L"not removable") || ContainsCaseInsensitive(value, L"不可移除")) {
            draw->clrText = RGB(0x8A, 0x8A, 0x8A);
        } else if (ContainsCaseInsensitive(value, L"verified") || ContainsCaseInsensitive(value, L"公开") ||
            ContainsCaseInsensitive(value, L"可移除")) {
            draw->clrText = RGB(0x3A, 0x8F, 0x3A);
        } else if (ContainsCaseInsensitive(value, L"candidate") || ContainsCaseInsensitive(value, L"experimental") ||
            ContainsCaseInsensitive(value, L"候选") || ContainsCaseInsensitive(value, L"实验")) {
            draw->clrText = RGB(0xD7, 0x7A, 0x00);
        }
        return CDRF_DODEFAULT;
    }

    return CDRF_DODEFAULT;
}

std::wstring KernelPage::BuildOriginalStyleSelectedRowDetail(const KernelFeatureId featureId, const int row) const {
    // BuildOriginalStyleSelectedRowDetail mirrors the text bodies used by the
    // original KernelDock detail editors for SSDT/SSSDT/Inline/IAT-EAT. Input
    // is the active feature and ListView row; processing reads display columns
    // and hidden diagnostic columns; output is empty for pages that still use
    // generic key/value detail text.
    const auto cell = [&](std::initializer_list<std::wstring> names) -> std::wstring {
        for (const std::wstring& name : names) {
            for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
                if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), name.c_str()) == 0) {
                    const std::wstring value = VisibleCellText(row, column);
                    if (!value.empty()) {
                        return value;
                    }
                }
            }
        }
        return {};
    };
    const auto rawSummary = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
        const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
        for (const std::vector<std::wstring>& rawRow : rawRows) {
            const std::wstring value = RowFieldByName(rawRow, rawColumns, names);
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };

    switch (featureId) {
    case KernelFeatureId::AtomTable: {
        const std::wstring detailText = cell({ L"Detail" });
        if (!detailText.empty()) {
            return detailText;
        }
        std::wostringstream detail;
        detail << L"Atom值: " << cell({ L"Atom值", L"Id" }) << L" (" << cell({ L"十六进制", L"Hex" }) << L")\r\n"
               << L"名称: " << cell({ L"名称", L"Name" }) << L"\r\n"
               << L"来源: " << cell({ L"来源", L"Source", L"Kind" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::NtQueryLegacy: {
        std::wostringstream detail;
        detail << L"类别: " << cell({ L"类别", L"Category" }) << L"\r\n"
               << L"函数: " << cell({ L"函数", L"Function" }) << L"\r\n"
               << L"查询项: " << cell({ L"查询项", L"Class", L"InfoClass", L"Ordinal", L"RVA" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"摘要: " << cell({ L"摘要", L"Detail" }) << L"\r\n\r\n"
               << L"详细输出:\r\n" << cell({ L"Detail" });
        return detail.str();
    }
    case KernelFeatureId::ObjectDirectoryRecursive: {
        std::wostringstream detail;
        detail << L"[Object Manager Directory Recursive Entry]\r\n"
               << L"RootPath: " << WindowText(filterEdit_) << L"\r\n"
               << L"DirectoryPath: " << cell({ L"Parent", L"Directory", L"Source" }) << L"\r\n"
               << L"ObjectName: " << cell({ L"名称", L"Name", L"objectName" }) << L"\r\n"
               << L"ObjectType: " << cell({ L"类型", L"Type", L"objectType" }) << L"\r\n"
               << L"FullPath: " << cell({ L"Path", L"完整路径", L"fullPath" }) << L"\r\n"
               << L"Depth: " << cell({ L"深度", L"Depth" }) << L"\r\n"
               << L"IsDirectory: " << (_wcsicmp(cell({ L"类型", L"Type" }).c_str(), L"Directory") == 0 ? L"true" : L"false") << L"\r\n"
               << L"QuerySucceeded: " << (cell({ L"状态", L"Status" }).empty() ? L"false" : L"true") << L"\r\n"
               << L"Status: " << cell({ L"状态", L"Status", L"statusText" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::BaseNamedObjects: {
        std::wostringstream detail;
        detail << L"BaseNamedObjects Entry\r\n"
               << L"----------------------------------------\r\n"
               << L"scope: " << cell({ L"scope", L"Source" }) << L"\r\n"
               << L"directoryPath: " << cell({ L"directoryPath", L"Parent", L"Directory" }) << L"\r\n"
               << L"objectName: " << cell({ L"objectName", L"Name" }) << L"\r\n"
               << L"objectType: " << cell({ L"objectType", L"Type" }) << L"\r\n"
               << L"fullPath: " << cell({ L"fullPath", L"Path" }) << L"\r\n"
               << L"symbolicTarget: " << cell({ L"symbolicTarget", L"targetPath", L"Target", L"目标路径", L"符号链接目标" }) << L"\r\n"
               << L"statusText: " << cell({ L"statusText", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::CommunicationEndpoint: {
        std::wostringstream detail;
        detail << L"Communication Endpoint Entry\r\n"
               << L"----------------------------------------\r\n"
               << L"来源目录: " << cell({ L"来源目录", L"Source", L"Parent", L"Directory", L"directoryPath", L"sourceDirectory" }) << L"\r\n"
               << L"名称: " << cell({ L"名称", L"Name", L"objectName" }) << L"\r\n"
               << L"类型: " << cell({ L"类型", L"Type", L"objectType" }) << L"\r\n"
               << L"完整路径: " << cell({ L"完整路径", L"Path", L"fullPath" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::ObjectNamespaceOverview: {
    const std::wstring name = cell({ L"名称", L"Name", L"objectName" });
    const std::wstring type = cell({ L"类型", L"Type", L"objectType" });
    const std::wstring path = cell({ L"Path", L"完整路径", L"fullPath", L"路径/说明" });
    const std::wstring parent = cell({ L"Parent", L"directoryPath", L"来源目录", L"Source" });
    const std::wstring status = cell({ L"状态", L"Status", L"statusText" });
    const std::wstring target = cell({ L"Target", L"符号链接目标", L"symbolicTarget", L"targetPath" });
        const std::wstring nodeKind = cell({ L"NodeKind" });
        std::wostringstream detail;
        if (_wcsicmp(nodeKind.c_str(), L"Root") == 0) {
            detail << L"对象命名空间根节点\r\n"
                   << L"----------------------------------------\r\n"
                   << L"节点名称: " << name << L"\r\n"
                   << L"节点类型: " << type << L"\r\n"
                   << L"节点路径: " << path << L"\r\n"
                   << L"节点说明: " << cell({ L"Detail", L"路径/说明" }) << L"\r\n"
                   << L"提示: 当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。\r\n";
            return detail.str();
        }
        if (_wcsicmp(nodeKind.c_str(), L"Directory") == 0) {
            detail << L"对象命名空间目录节点\r\n"
                   << L"----------------------------------------\r\n"
                   << L"节点名称: " << name << L"\r\n"
                   << L"节点类型: " << type << L"\r\n"
                   << L"节点路径: " << path << L"\r\n"
                   << L"根目录: " << parent << L"\r\n"
                   << L"节点说明: " << cell({ L"Detail", L"路径/说明" }) << L"\r\n"
                   << L"提示: 当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。\r\n";
            return detail.str();
        }
        detail << L"对象命名空间详情\r\n"
               << L"----------------------------------------\r\n"
               << L"名称: " << name << L"\r\n"
               << L"类型: " << type << L"\r\n"
               << L"完整路径: " << path << L"\r\n"
               << L"父目录/来源: " << parent << L"\r\n"
               << L"符号链接目标: " << target << L"\r\n"
               << L"句柄数: " << cell({ L"Handles" }) << L"\r\n"
               << L"引用数: " << cell({ L"Pointers" }) << L"\r\n"
               << L"状态: " << status << L"\r\n\r\n"
               << L"操作: 右键可复制对象字段、复制同目录路径、按目录/对象名过滤或尝试映射 DOS 路径。";
        return detail.str();
    }
    case KernelFeatureId::NamedPipe: {
        std::wostringstream detail;
        detail << L"命名管道详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Pipe Name: " << cell({ L"Pipe Name", L"Pipe", L"Name" }) << L"\r\n"
               << L"NT Path: " << cell({ L"NT Path", L"NtPath", L"Path" }) << L"\r\n"
               << L"Win32 Path: " << cell({ L"Win32Path" }) << L"\r\n"
               << L"Attributes: " << cell({ L"Attributes" }) << L"\r\n"
               << L"LastWriteTime: " << cell({ L"LastWriteTime", L"LastWrite" }) << L"\r\n"
               << L"Status: " << cell({ L"Status" }) << L"\r\n"
               << L"Source: " << cell({ L"Source", L"Directory" }) << L"\r\n\r\n"
               << L"操作: 右键可用 NtOpenFile 只读属性打开验证，不读写管道数据。";
        return detail.str();
    }
    case KernelFeatureId::SymbolicLink: {
        std::wostringstream detail;
        detail << L"符号链接详情\r\n"
               << L"----------------------------------------\r\n"
               << L"来源目录: " << cell({ L"sourceDirectory", L"Source", L"Parent" }) << L"\r\n"
               << L"链接名: " << cell({ L"linkName", L"objectName", L"Name", L"名称" }) << L"\r\n"
               << L"完整路径: " << cell({ L"fullPath", L"Path", L"完整路径" }) << L"\r\n"
               << L"目标路径: " << cell({ L"targetPath", L"symbolicTarget", L"Target", L"目标路径", L"符号链接目标" }) << L"\r\n"
               << L"DOS 候选: " << cell({ L"dosCandidate", L"Win32Path" }) << L"\r\n"
               << L"状态: " << cell({ L"statusText", L"Status" }) << L"\r\n\r\n"
               << L"操作: 右键可复制单元格、targetPath、dosCandidate、整行，或按目标路径过滤。";
        return detail.str();
    }
    case KernelFeatureId::DeviceDriverObjects: {
        std::wostringstream detail;
        detail << L"设备/驱动对象详情\r\n"
               << L"----------------------------------------\r\n"
               << L"目录路径: " << cell({ L"目录路径", L"Parent", L"Directory", L"Source" }) << L"\r\n"
               << L"对象名称: " << cell({ L"对象名称", L"objectName", L"Name", L"DriverName" }) << L"\r\n"
               << L"对象类型: " << cell({ L"对象类型", L"objectType", L"Type" }) << L"\r\n"
               << L"完整路径: " << cell({ L"完整路径", L"fullPath", L"Path" }) << L"\r\n"
               << L"目标路径: " << cell({ L"目标路径", L"targetPath", L"symbolicTarget", L"Target" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"能力提示: " << cell({ L"能力提示", L"Capability", L"Detail" }) << L"\r\n\r\n"
               << L"操作: 右键可复制单元格、当前行、可见结果 TSV，或导出 TSV。";
        return detail.str();
    }
    case KernelFeatureId::ObjectTypeMatrix: {
        std::wostringstream detail;
        detail << L"对象类型矩阵详情\r\n"
               << L"----------------------------------------\r\n"
               << L"类型编号: " << cell({ L"类型编号", L"TypeIndex", L"Index" }) << L"\r\n"
               << L"类型名: " << cell({ L"类型名", L"Type" }) << L"\r\n"
               << L"对象数: " << cell({ L"对象数", L"Objects" }) << L"\r\n"
               << L"句柄数: " << cell({ L"句柄数", L"Handles" }) << L"\r\n"
               << L"访问掩码: " << cell({ L"访问掩码", L"ValidAccess" }) << L"\r\n"
               << L"枚举策略: " << cell({ L"枚举策略", L"Detail", L"Status" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::Ssdt: {
        const std::wstring originalDetailText = cell({ L"Detail" });
        if (!originalDetailText.empty() && originalDetailText.find(L"服务索引:") == 0) {
            return originalDetailText;
        }
        std::wostringstream detail;
        detail << L"服务索引: " << cell({ L"索引", L"Index" }) << L"\r\n"
               << L"服务名: " << cell({ L"服务名", L"Name", L"ServiceName" }) << L"\r\n"
               << L"模块: " << cell({ L"模块", L"Module" }) << L"\r\n"
               << L"Zw导出地址: " << cell({ L"Zw导出地址", L"Zw" }) << L"\r\n"
               << L"服务表基址: " << cell({ L"ServiceTable", L"ServiceTableBase" }) << L"\r\n"
               << L"表项服务地址: " << cell({ L"表项地址", L"Service", L"ServiceAddress" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"标志: " << cell({ L"Flags" }) << L"\r\n\r\n"
               << L"Worker详情:\r\n" << cell({ L"Detail", L"FlagsText" });
        return detail.str();
    }
    case KernelFeatureId::ShadowSsdt: {
        const std::wstring originalDetailText = cell({ L"Detail" });
        if (!originalDetailText.empty() && originalDetailText.find(L"SSSDT/Shadow SSDT 解析") == 0) {
            return originalDetailText;
        }
        std::wostringstream detail;
        detail << L"SSSDT/Shadow SSDT 解析\r\n"
               << L"协议版本: " << cell({ L"Version" }) << L"\r\n"
               << L"总条目: " << cell({ L"Total" }) << L"\r\n"
               << L"返回条目: " << cell({ L"Returned" }) << L"\r\n"
               << L"服务名: " << cell({ L"服务名", L"Name", L"ServiceName" }) << L"\r\n"
               << L"模块: " << cell({ L"模块", L"Module" }) << L"\r\n"
               << L"服务索引: " << cell({ L"索引", L"Index" }) << L"\r\n"
               << L"Stub地址: " << cell({ L"Stub地址", L"Zw", L"Stub" }) << L"\r\n"
               << L"Shadow服务表基址: " << cell({ L"ServiceTable", L"ServiceTableBase" }) << L"\r\n"
               << L"服务例程地址: " << cell({ L"服务地址", L"Service", L"ServiceAddress" }) << L"\r\n"
               << L"驱动标志: " << cell({ L"Flags" }) << L"\r\n\r\n"
               << L"说明: 当前 R0 参考 System Informer 的 ksyscall 思路，从 win32k.sys 的 __win32kstub_* 和 win32u.dll 的 Nt* stub 中解析 syscall index。"
               << L"若已应用包含 KeServiceDescriptorTableShadow 的 PDB/DynData profile，会继续解析 shadow service table 实际表项；服务例程地址为 0 表示 profile 缺失、身份不匹配或表项暂不可读。";
        return detail.str();
    }
    case KernelFeatureId::InlineHook: {
        const std::wstring originalDetailText = cell({ L"Detail" });
        if (!originalDetailText.empty() && originalDetailText.find(L"Inline Hook 检测详情") == 0) {
            return originalDetailText;
        }
        std::wostringstream detail;
        detail << L"Inline Hook 检测详情\r\n"
               << L"模块: " << cell({ L"模块", L"Module" }) << L"\r\n"
               << L"函数: " << cell({ L"函数", L"Function" }) << L"\r\n"
               << L"函数地址: " << cell({ L"函数地址", L"Address" }) << L"\r\n"
               << L"Hook类型: " << cell({ L"Hook类型", L"TypeText", L"Type" }) << L"\r\n"
               << L"目标地址: " << cell({ L"目标地址", L"Target" }) << L"\r\n"
               << L"目标模块: " << cell({ L"目标模块", L"TargetModule" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"模块基址: " << cell({ L"ModuleBase" }) << L"\r\n"
               << L"目标模块基址: " << cell({ L"TargetModuleBase" }) << L"\r\n"
               << L"当前内存字节(" << cell({ L"CurrentByteCount" }) << L"): " << cell({ L"当前字节", L"CurrentBytes" }) << L"\r\n"
               << L"R0 观察基线(" << cell({ L"OriginalByteCount" }) << L"): " << cell({ L"ExpectedBytes" }) << L"\r\n"
               << L"磁盘基线字节: " << cell({ L"磁盘字节", L"DiskBytes" }) << L"\r\n"
               << L"差异状态: " << cell({ L"差异", L"DiskDiff" }) << L"\r\n"
               << L"标志: " << cell({ L"Flags" }) << L"\r\n\r\n"
               << L"说明: 当前协议字段 expectedBytes 在 R0 中来自内存观察，通常是 currentBytes 的同源快照，不代表磁盘原始字节。"
               << L"摘除操作保持原有 NOP 流程，不新增自动修复能力。";
        return detail.str();
    }
    case KernelFeatureId::IatEatHook: {
        const std::wstring originalDetailText = cell({ L"Detail" });
        if (!originalDetailText.empty() && originalDetailText.find(L"IAT/EAT Hook 检测详情") == 0) {
            return originalDetailText;
        }
        std::wostringstream detail;
        detail << L"IAT/EAT Hook 检测详情\r\n"
               << L"类别: " << cell({ L"类别", L"ClassText", L"Class" }) << L"\r\n"
               << L"模块: " << cell({ L"模块", L"Module" }) << L"\r\n"
               << L"导入模块: " << cell({ L"导入模块", L"Import", L"ImportModule" }) << L"\r\n"
               << L"函数/序号: " << cell({ L"函数", L"Function" }) << L" / #" << cell({ L"Ordinal" }) << L"\r\n"
               << L"Thunk/EAT项: " << cell({ L"Thunk地址", L"Thunk", L"ThunkAddress" }) << L"\r\n"
               << L"当前目标: " << cell({ L"当前目标", L"Current", L"CurrentTarget" }) << L"\r\n"
               << L"期望目标: " << cell({ L"期望目标", L"Expected", L"ExpectedTarget" }) << L"\r\n"
               << L"目标模块: " << cell({ L"目标模块", L"TargetModule" }) << L"\r\n"
               << L"所属模块基址: " << cell({ L"ModuleBase" }) << L"\r\n"
               << L"目标模块基址: " << cell({ L"TargetModuleBase" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"标志: " << cell({ L"Flags" }) << L"\r\n\r\n"
               << L"说明: IAT 检测比较 thunk 当前目标是否仍落在声明导入模块内；EAT 检测导出 RVA 是否落在自身映像或转发导出区域内。";
        return detail.str();
    }
    case KernelFeatureId::CallbackEnumeration: {
        const auto yesNo = [](const std::wstring& value) -> const wchar_t* {
            return (!value.empty() && value != L"0" && _wcsicmp(value.c_str(), L"false") != 0) ? L"是" : L"否";
        };
        const std::wstring trustText = cell({ L"可信状态", L"SourceTrust", L"TrustText" });
        const bool fallbackOnly = trustText.find(L"fallback") != std::wstring::npos ||
            trustText.find(L"pattern") != std::wstring::npos ||
            trustText.find(L"Fallback") != std::wstring::npos;
        const bool secondConfirm = cell({ L"移除策略", L"RemovePolicy" }).find(L"experimental") != std::wstring::npos ||
            cell({ L"移除策略", L"RemovePolicy" }).find(L"候选") != std::wstring::npos;
        std::wostringstream detail;
        detail << L"类别: " << cell({ L"类别", L"ClassText", L"Class" }) << L"\r\n"
               << L"来源: " << cell({ L"来源", L"SourceText", L"Source" }) << L"\r\n"
               << L"可信状态: " << trustText << L"\r\n"
               << L"移除策略: " << cell({ L"移除策略", L"RemovePolicy" }) << L"\r\n"
               << L"是否需要二次确认: " << yesNo(secondConfirm ? L"1" : L"0") << L"\r\n"
               << L"当前来源是否只是 fallback/pattern: " << yesNo(fallbackOnly ? L"1" : L"0") << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"名称: " << cell({ L"名称", L"Name" }) << L"\r\n"
               << L"Altitude: " << cell({ L"Altitude" }) << L"\r\n"
               << L"主地址显示: " << cell({ L"回调/对象地址", L"Callback", L"Object", L"Registration", L"RawStorageValue" }) << L"\r\n"
               << L"真实回调地址: " << cell({ L"Callback" }) << L"\r\n"
               << L"上下文/诊断值: " << cell({ L"Context" }) << L"\r\n"
               << L"注册句柄/Cookie/全局节点: " << cell({ L"Registration" }) << L"\r\n"
               << L"模块路径: " << cell({ L"模块", L"ModulePath", L"Module" }) << L"\r\n"
               << L"Win32模块路径: " << cell({ L"Win32ModulePath" }) << L"\r\n"
               << L"模块基址: " << cell({ L"ModuleBase" }) << L"\r\n"
               << L"模块大小: " << cell({ L"ModuleSize" }) << L"\r\n"
               << L"操作掩码: " << cell({ L"OperationMask" }) << L"\r\n"
               << L"对象类型掩码: " << cell({ L"ObjectTypeMask" }) << L"\r\n"
               << L"字段标志: " << cell({ L"FieldFlags" }) << L"\r\n"
               << L"可信标志(预留): " << cell({ L"Trust" }) << L"\r\n"
               << L"移除行为(预留): " << cell({ L"Remove" }) << L"\r\n"
               << L"移除标志(预留): " << cell({ L"RemoveFlags" }) << L"\r\n"
               << L"Generation(预留): " << cell({ L"Generation" }) << L"\r\n"
               << L"IdentityHash(预留): " << cell({ L"IdentityHash" }) << L"\r\n"
               << L"RawStorageValue(预留): " << cell({ L"RawStorageValue" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n\r\n"
               << L"说明: 主地址显示会优先显示真实回调函数；定位/诊断行没有真实回调函数时显示全局数组、链表节点、标识符或诊断值。"
               << L"旧协议尚未返回 generation/identity hash/raw storage value 时保持 0 或空值；实验 unlink 仅为 UI 预留，不作为默认路径。\r\n\r\n"
               << L"详情:\r\n" << cell({ L"Detail", L"FieldText", L"TrustText", L"RemoveText" });
        return detail.str();
    }
    case KernelFeatureId::DynData: {
        std::uint64_t fieldMask = 0;
        std::uint64_t globalMask = 0;
        HexToUInt64(cell({ L"Capability", L"CapabilityMask", L"Mask" }), fieldMask);
        HexToUInt64(rawSummary({ L"CapabilityMask", L"DynDataCapability", L"Mask" }), globalMask);
        const std::wstring globalMaskText = globalMask != 0 ? HexTextPadded(globalMask, 16) : rawSummary({ L"CapabilityMask", L"DynDataCapability", L"Mask" });
        std::wostringstream detail;
        detail << L"字段名: " << cell({ L"字段", L"Field", L"Name" }) << L"\r\n"
               << L"字段ID: " << cell({ L"Id", L"FieldId" }) << L"\r\n"
               << L"偏移: " << cell({ L"偏移", L"Offset" }) << L"\r\n"
               << L"状态: " << cell({ L"状态", L"Status", L"DynData Fields IO" }) << L"\r\n"
               << L"来源: " << cell({ L"来源", L"Source" }) << L"\r\n"
               << L"功能: " << cell({ L"功能", L"Feature" }) << L"\r\n"
               << L"字段标志: " << cell({ L"Flags" }) << L"\r\n"
               << L"字段能力位: " << (fieldMask != 0 ? HexTextPadded(fieldMask, 16) : cell({ L"Capability", L"CapabilityMask", L"Mask" })) << L"\r\n"
               << L"字段能力名: " << DynCapabilityNames(fieldMask) << L"\r\n\r\n"
               << L"当前全局能力位: " << globalMaskText << L"\r\n"
               << L"当前未启用能力: " << DisabledDynCapabilitySummary(globalMask) << L"\r\n\r\n"
               << L"R0不可用原因: " << rawSummary({ L"UnavailableReason", L"Reason", L"Detail" }) << L"\r\n\r\n"
               << L"StatusFlags: " << rawSummary({ L"StatusFlags" }) << L" (" << DynDataStatusFlagsText(static_cast<std::uint32_t>(FirstRowUInt64(!currentRawRows_.empty() ? currentRawRows_ : currentRows_, !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_, { L"StatusFlags" }))) << L")\r\n"
               << L"SystemInformerDataVersion: " << rawSummary({ L"SI Version" }) << L"\r\n"
               << L"SystemInformerDataLength: " << rawSummary({ L"SI Length" }) << L"\r\n"
               << L"MatchedProfileClass: " << rawSummary({ L"MatchedClass", L"ProfileClass" }) << L"\r\n"
               << L"MatchedProfileOffset: " << rawSummary({ L"MatchedProfileOffset" }) << L"\r\n"
               << L"MatchedFieldsId: " << rawSummary({ L"MatchedFieldsId" }) << L"\r\n"
               << L"ntoskrnl: " << rawSummary({ L"Ntos", L"NtosIdentity" }) << L"\r\n"
               << L"lxcore: " << rawSummary({ L"Lxcore", L"LxcoreIdentity" });
        return detail.str();
    }
    case KernelFeatureId::DriverStatus: {
        std::uint64_t requiredDyn = 0;
        std::uint64_t presentDyn = 0;
        std::uint64_t globalDyn = 0;
        std::uint64_t featureFlags64 = 0;
        std::uint64_t requiredPolicy64 = 0;
        std::uint64_t deniedPolicy64 = 0;
        std::uint64_t stateId64 = 0;
        HexToUInt64(cell({ L"所需DynData", L"RequiredDyn" }), requiredDyn);
        HexToUInt64(cell({ L"已满足DynData", L"PresentDyn" }), presentDyn);
        HexToUInt64(rawSummary({ L"DynDataCapability", L"CapabilityMask" }), globalDyn);
        HexToUInt64(cell({ L"Flags" }), featureFlags64);
        HexToUInt64(cell({ L"策略", L"Policy", L"RequiredPolicy" }), requiredPolicy64);
        HexToUInt64(cell({ L"DeniedPolicy" }), deniedPolicy64);
        HexToUInt64(cell({ L"StateId" }), stateId64);
        const std::uint32_t featureFlags = static_cast<std::uint32_t>(featureFlags64);
        const std::uint32_t requiredPolicy = static_cast<std::uint32_t>(requiredPolicy64);
        const std::uint32_t deniedPolicy = static_cast<std::uint32_t>(deniedPolicy64);
        const std::uint32_t dynStatusFlags = static_cast<std::uint32_t>(FirstRowUInt64(!currentRawRows_.empty() ? currentRawRows_ : currentRows_, !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_, { L"DynDataStatus" }));
        std::wostringstream detail;
        detail << L"功能: " << cell({ L"功能", L"Feature", L"Name", L"项目" }) << L"\r\n"
               << L"FeatureId: " << cell({ L"Id" }) << L"\r\n"
               << L"状态: " << FeatureStateText(static_cast<std::uint32_t>(stateId64), cell({ L"状态", L"State", L"Status", L"值" })) << L"\r\n"
               << L"功能标志: " << (featureFlags64 != 0 ? HexTextPadded(featureFlags, 8) : cell({ L"Flags" })) << L" (" << FeatureFlagNames(featureFlags) << L")\r\n\r\n"
               << L"依赖字段: " << cell({ L"依赖字段", L"Fields", L"Dependency" }) << L"\r\n"
               << L"状态原因: " << cell({ L"原因", L"Reason", L"Detail" }) << L"\r\n\r\n"
               << L"所需安全策略: " << HexTextPadded(requiredPolicy, 8) << L" (" << SecurityPolicyNames(requiredPolicy) << L")\r\n"
               << L"被拒绝策略位: " << HexTextPadded(deniedPolicy, 8) << L" (" << SecurityPolicyNames(deniedPolicy) << L")\r\n"
               << L"所需 DynData capability: " << HexTextPadded(requiredDyn, 16) << L" (" << DynCapabilityNames(requiredDyn) << L")\r\n"
               << L"已满足 DynData capability: " << HexTextPadded(presentDyn, 16) << L" (" << DynCapabilityNames(presentDyn) << L")\r\n"
               << L"全局 DynData capability: " << HexTextPadded(globalDyn, 16) << L" (" << DynCapabilityNames(globalDyn) << L")\r\n\r\n"
               << L"当前内核: " << rawSummary({ L"NtosIdentity", L"Ntos" }) << L"\r\n"
               << L"识别版本: " << rawSummary({ L"LocalPdbVersion", L"KernelVersion" }) << L"\r\n"
               << L"本地 PDB profile: " << rawSummary({ L"LocalPdbProfile", L"LocalPdbMessage" }) << L"\r\n"
               << L"ActiveProcessLinks 偏移: " << rawSummary({ L"ActiveProcessLinksOffset" }) << L"\r\n"
               << L"可信偏移: " << rawSummary({ L"TrustedOffset" }) << L"\r\n"
               << L"字段覆盖: " << rawSummary({ L"FieldCoverage" }) << L"\r\n"
               << L"字段来源: " << rawSummary({ L"FieldSources" }) << L"\r\n\r\n"
               << L"驱动状态: " << rawSummary({ L"StatusBadges", L"StatusFlags" }) << L"\r\n"
               << L"DynDataStatus: " << rawSummary({ L"DynDataStatus" }) << L" (" << DynDataStatusFlagsText(dynStatusFlags) << L")\r\n"
               << L"最近 R0 错误: " << rawSummary({ L"LastErrorStatus" }) << L" / " << rawSummary({ L"LastError" }) << L" / " << rawSummary({ L"LastErrorSummary" });
        return detail.str();
    }
    case KernelFeatureId::KernelExecutableMemory: {
        std::wostringstream detail;
        detail << L"内核可执行页扫描详情\r\n"
               << L"VA: " << cell({ L"VA" }) << L"\r\n"
               << L"RegionSize: " << cell({ L"RegionSize" }) << L"\r\n"
               << L"PageCount: " << cell({ L"页数", L"Pages" }) << L"\r\n"
               << L"PageSize: " << cell({ L"页大小", L"PageSize" }) << L"\r\n"
               << L"Permissions: " << cell({ L"权限", L"PermText" }) << L" (" << cell({ L"Perm" }) << L")\r\n"
               << L"RiskFlags: " << cell({ L"风险标志", L"RiskText" }) << L" (" << cell({ L"Risk" }) << L")\r\n"
               << L"Status: " << cell({ L"Status" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n"
               << L"OwnerKind: " << cell({ L"OwnerKind" }) << L"\r\n"
               << L"Owner: " << cell({ L"Owner", L"OwnerKindText" }) << L"\r\n"
               << L"OwnerAddress: " << cell({ L"OwnerAddress" }) << L"\r\n"
               << L"ModuleBase: " << cell({ L"ModuleBase" }) << L"\r\n"
               << L"ModuleSize: " << cell({ L"ModuleSize" }) << L"\r\n"
               << L"ModulePath: " << cell({ L"模块路径", L"ModulePath", L"Module" }) << L"\r\n";
        const std::wstring r0Detail = cell({ L"Detail" });
        if (!r0Detail.empty()) {
            detail << L"\r\nR0 Detail:\r\n" << r0Detail << L"\r\n";
        }
        return detail.str();
    }
    case KernelFeatureId::KernelMemoryEvidence: {
        std::wostringstream detail;
        detail << L"内核内存证据详情\r\n"
               << L"Address: " << cell({ L"VA" }) << L"\r\n"
               << L"RegionSize: " << cell({ L"RegionSize" }) << L" (" << cell({ L"大小", L"SizeText" }) << L")\r\n"
               << L"EvidenceKind: " << cell({ L"类型", L"KindText" }) << L"\r\n"
               << L"OwnerKind: " << cell({ L"OwnerKindText" }) << L"\r\n"
               << L"OwnerName: " << cell({ L"Owner" }) << L"\r\n"
               << L"OwnerAddress: " << cell({ L"OwnerAddress" }) << L"\r\n"
               << L"ModuleBase: " << cell({ L"ModuleBase" }) << L"\r\n"
               << L"ModuleSize: " << cell({ L"ModuleSize" }) << L" (" << cell({ L"ModuleSizeText" }) << L")\r\n"
               << L"PermissionFlags: " << cell({ L"PTE权限", L"PermText" }) << L" (" << cell({ L"Perm" }) << L")\r\n"
               << L"RiskFlags: " << cell({ L"风险", L"RiskText" }) << L" (" << cell({ L"Risk" }) << L")\r\n"
               << L"BigPoolTag: " << cell({ L"BigPoolTag" }) << L"\r\n"
               << L"BigPoolFlags: " << cell({ L"BigPoolFlags" }) << L"\r\n"
               << L"Section: " << cell({ L"Section" }) << L" RVA=" << cell({ L"SectionRva" }) << L" Size=" << cell({ L"SectionSizeText", L"SectionSize" }) << L"\r\n"
               << L"Hash: " << cell({ L"text hash/diff", L"HashText", L"Hash" }) << L"\r\n"
               << L"SampleSize: " << cell({ L"SampleSize" }) << L"\r\n";
        const std::wstring sample = cell({ L"Sample" });
        if (!sample.empty()) {
            detail << L"Sample: " << sample << L"\r\n";
        }
        detail << L"Confidence: " << cell({ L"Confidence" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n"
               << L"Detail: " << cell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::ProcessCrossView:
    {
        std::wostringstream detail;
        detail << L"进程 Cross-View 详情\r\n"
               << L"PID: " << cell({ L"PID", L"ID" }) << L" PPID: " << cell({ L"PPID" }) << L" Image: " << cell({ L"Image", L"进程" }) << L"\r\n"
               << L"ProcessObject: " << cell({ L"ProcessObject", L"对象", L"Object" }) << L"\r\n"
               << L"StartAddress: " << cell({ L"StartAddress", L"Start" }) << L"\r\n"
               << L"SourceMask: " << cell({ L"SourceMask" }) << L"\r\n"
               << L"AnomalyFlags: " << cell({ L"异常", L"AnomalyText" }) << L" (" << cell({ L"Anomaly" }) << L")\r\n"
               << L"DynDataCapabilityMask: " << cell({ L"DynDataCapabilityMask", L"DynData" }) << L"\r\n"
               << L"EPROCESS.UniqueProcessId: " << cell({ L"EP.UniqueProcessId" }) << L"\r\n"
               << L"EPROCESS.ActiveProcessLinks: " << cell({ L"EP.ActiveProcessLinks" }) << L"\r\n"
               << L"EPROCESS.ThreadListHead: " << cell({ L"EP.ThreadListHead" }) << L"\r\n"
               << L"EPROCESS.ImageFileName: " << cell({ L"EP.ImageFileName" }) << L"\r\n"
               << L"ETHREAD.Cid: " << cell({ L"ET.Cid" }) << L"\r\n"
               << L"ETHREAD.ThreadListEntry: " << cell({ L"ET.ThreadListEntry" }) << L"\r\n"
               << L"ETHREAD.StartAddress: " << cell({ L"ET.StartAddress" }) << L"\r\n"
               << L"KTHREAD.Process: " << cell({ L"KT.Process" }) << L"\r\n"
               << L"PspCidTableRva: " << cell({ L"PspCidTableRva" }) << L"\r\n"
               << L"PspCidTableAddress: " << cell({ L"PspCidTable" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n"
               << L"Confidence: " << cell({ L"置信度", L"Confidence" }) << L"\r\n"
               << L"Detail: " << cell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::ThreadCrossView:
    {
        std::wostringstream detail;
        detail << L"线程 Cross-View 详情\r\n"
               << L"TID: " << cell({ L"TID", L"ID" }) << L" PID: " << cell({ L"PID" }) << L" Image: " << cell({ L"Image" }) << L"\r\n"
               << L"ThreadObject: " << cell({ L"ThreadObject", L"对象", L"Object" }) << L"\r\n"
               << L"ProcessObject: " << cell({ L"ProcessObject" }) << L"\r\n"
               << L"StartAddress: " << cell({ L"StartAddress", L"Start" }) << L"\r\n"
               << L"SourceMask: " << cell({ L"SourceMask" }) << L"\r\n"
               << L"AnomalyFlags: " << cell({ L"异常", L"AnomalyText" }) << L" (" << cell({ L"Anomaly" }) << L")\r\n"
               << L"DynDataCapabilityMask: " << cell({ L"DynDataCapabilityMask", L"DynData" }) << L"\r\n"
               << L"EPROCESS.UniqueProcessId: " << cell({ L"EP.UniqueProcessId" }) << L"\r\n"
               << L"EPROCESS.ActiveProcessLinks: " << cell({ L"EP.ActiveProcessLinks" }) << L"\r\n"
               << L"EPROCESS.ThreadListHead: " << cell({ L"EP.ThreadListHead" }) << L"\r\n"
               << L"EPROCESS.ImageFileName: " << cell({ L"EP.ImageFileName" }) << L"\r\n"
               << L"ETHREAD.Cid: " << cell({ L"ET.Cid" }) << L"\r\n"
               << L"ETHREAD.ThreadListEntry: " << cell({ L"ET.ThreadListEntry" }) << L"\r\n"
               << L"ETHREAD.StartAddress: " << cell({ L"ET.StartAddress" }) << L"\r\n"
               << L"KTHREAD.Process: " << cell({ L"KT.Process" }) << L"\r\n"
               << L"PspCidTableRva: " << cell({ L"PspCidTableRva" }) << L"\r\n"
               << L"PspCidTableAddress: " << cell({ L"PspCidTable" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n"
               << L"Confidence: " << cell({ L"置信度", L"Confidence" }) << L"\r\n"
               << L"Detail: " << cell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::DriverIntegrity:
    case KernelFeatureId::KernelCpuIntegrity:
    {
        std::wostringstream detail;
        if (featureId == KernelFeatureId::KernelCpuIntegrity) {
            detail << L"R0 查询摘要\r\n"
                   << L"R0: " << rawSummary({ L"R0" }) << L"\r\n"
                   << L"Protocol: " << rawSummary({ L"Protocol" }) << L"\r\n"
                   << L"DynDataStatus: " << rawSummary({ L"DynDataStatus" }) << L"\r\n"
                   << L"Win32: " << rawSummary({ L"Win32" }) << L"\r\n\r\n";
        }
        detail << L"驱动完整性证据详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Class: " << cell({ L"类别", L"ClassText" }) << L" (" << cell({ L"Class" }) << L")\r\n"
               << L"RiskFlags: " << cell({ L"风险", L"RiskText" }) << L" (" << cell({ L"Risk" }) << L")\r\n"
               << L"SourceMask: " << cell({ L"Source" }) << L" (" << cell({ L"SourceText" }) << L")\r\n"
               << L"Confidence: " << cell({ L"置信度", L"Confidence" }) << L"\r\n"
               << L"ObjectAddress: " << cell({ L"对象", L"对象/寄存器", L"ObjectAddress", L"Object" }) << L"\r\n"
               << L"TargetAddress: " << cell({ L"目标", L"目标/入口", L"TargetAddress", L"Target" }) << L"\r\n"
               << L"OwnerModule: " << cell({ L"Owner模块", L"OwnerModule" }) << L"\r\n"
               << L"OwnerModuleBase: " << cell({ L"OwnerModuleBase", L"OwnerBase" }) << L"\r\n"
               << L"OwnerModuleSize: " << cell({ L"OwnerModuleSizeText", L"OwnerModuleSize", L"OwnerSize" }) << L"\r\n"
               << L"CPU: group=" << cell({ L"Group" }) << L" cpu=" << cell({ L"CPU" }) << L" vector=" << cell({ L"Vector" }) << L"\r\n"
               << L"CPU/Vector: " << cell({ L"CPU/Vector", L"CpuVector" }) << L"\r\n"
               << L"Detail: " << cell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::CpuHardwareSnapshot:
    {
        std::wostringstream detail;
        detail << L"R0 CPUID 硬件快照详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Brand: " << cell({ L"Brand", L"值" }) << L"\r\n"
               << L"Vendor: " << cell({ L"Vendor" }) << L"\r\n"
               << L"Family/Model/Stepping: " << cell({ L"Family" }) << L"/" << cell({ L"Model" }) << L"/" << cell({ L"Stepping" }) << L"\r\n"
               << L"ProcessorType/BrandIndex: " << cell({ L"ProcessorType" }) << L"/" << cell({ L"BrandIndex" }) << L"\r\n"
               << L"Logical/Active/Package: " << cell({ L"Logical" }) << L"/" << cell({ L"Active" }) << L"/" << cell({ L"Package" }) << L"\r\n"
               << L"InitialApicId: " << cell({ L"InitialApicId" }) << L"\r\n"
               << L"CLFLUSH line: " << cell({ L"CLFlushLine" }) << L" bytes\r\n"
               << L"Leaves: " << cell({ L"Leaves" }) << L"\r\n"
               << L"FeatureMask: " << cell({ L"FeatureMask" }) << L"\r\n"
               << L"Features: " << cell({ L"Features" }) << L"\r\n"
               << L"Leaf1ECX: " << cell({ L"Leaf1ECX" }) << L"\r\n"
               << L"Leaf1EDX: " << cell({ L"Leaf1EDX" }) << L"\r\n"
               << L"Leaf7EBX: " << cell({ L"Leaf7EBX" }) << L"\r\n"
               << L"Leaf7ECX: " << cell({ L"Leaf7ECX" }) << L"\r\n"
               << L"Leaf7EDX: " << cell({ L"Leaf7EDX" }) << L"\r\n"
               << L"Leaf80000001ECX: " << cell({ L"Leaf80000001ECX" }) << L"\r\n"
               << L"Leaf80000001EDX: " << cell({ L"Leaf80000001EDX" }) << L"\r\n"
               << L"FieldFlags: " << cell({ L"FieldFlags" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::PhysicalMemoryLayout:
    {
        std::wostringstream detail;
        detail << L"R0 物理内存布局详情\r\n"
               << L"----------------------------------------\r\n"
               << L"总物理内存: " << cell({ L"总物理内存", L"TotalText" }) << L" (" << cell({ L"TotalBytes" }) << L")\r\n"
               << L"Range数量: " << cell({ L"范围", L"Ranges" }) << L"\r\n"
               << L"零长度Range: " << cell({ L"ZeroRanges" }) << L"\r\n"
               << L"Truncated: " << cell({ L"Truncated" }) << L"\r\n"
               << L"最大连续Range: " << cell({ L"最大连续Range", L"LargestRangeText" }) << L" (" << cell({ L"LargestRange" }) << L")\r\n"
               << L"最小Range: " << cell({ L"SmallestRangeText" }) << L" (" << cell({ L"SmallestRange" }) << L")\r\n"
               << L"最高物理地址: " << cell({ L"最高物理地址", L"HighestAddress" }) << L"\r\n"
               << L"首Range基址: " << cell({ L"FirstBase" }) << L"\r\n"
               << L"末Range结束: " << cell({ L"LastEnd" }) << L"\r\n"
               << L"估算地址空洞: " << cell({ L"GapText" }) << L" (" << cell({ L"GapBytes" }) << L")\r\n"
               << L"FieldFlags: " << cell({ L"FieldFlags" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::MutationAudit:
    {
        std::wostringstream detail;
        detail << L"R0 Mutation Audit 详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Seq: " << cell({ L"Seq" }) << L"\r\n"
               << L"TransactionId: " << cell({ L"Tx", L"TransactionIdHex", L"TransactionId" }) << L"\r\n"
               << L"Operation: " << cell({ L"Operation" }) << L"\r\n"
               << L"Status: " << cell({ L"Status" }) << L"\r\n"
               << L"TargetKind: " << cell({ L"TargetKind" }) << L"\r\n"
               << L"PID: " << cell({ L"PID" }) << L"\r\n"
               << L"Address: " << cell({ L"Address" }) << L"\r\n"
               << L"Context: " << cell({ L"Context" }) << L"\r\n"
               << L"Bytes: " << cell({ L"Bytes" }) << L"\r\n"
               << L"RiskFlags: " << cell({ L"RiskText", L"Risk" }) << L" (" << cell({ L"Risk" }) << L")\r\n"
               << L"Flags: " << cell({ L"FlagsText", L"Flags" }) << L" (" << cell({ L"Flags" }) << L")\r\n"
               << L"BeforeHash: " << cell({ L"BeforeHash" }) << L"\r\n"
               << L"AfterHash: " << cell({ L"AfterHash" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n"
               << L"Data: " << cell({ L"Data" }) << L"\r\n\r\n"
               << L"说明: 该页仅展示 R0 mutation transaction 审计和显式 dry-run/rollback 操作，不提供任意写入口。";
        return detail.str();
    }
    case KernelFeatureId::KeyboardHotkeys:
    {
        std::wostringstream detail;
        detail << L"win32k 热键枚举详情\r\n"
               << L"----------------------------------------\r\n"
               << L"PID/TID: " << cell({ L"PID" }) << L" / " << cell({ L"TID" }) << L"\r\n"
               << L"Process: " << cell({ L"进程", L"Process" }) << L"\r\n"
               << L"HotkeyObject: " << cell({ L"Object" }) << L"\r\n"
               << L"NextHotkeyObject: " << cell({ L"Next" }) << L"\r\n"
               << L"WindowObject: " << cell({ L"窗口", L"WindowObject" }) << L"\r\n"
               << L"ThreadInfo: " << cell({ L"ThreadInfo" }) << L"\r\n"
               << L"ThreadObject: " << cell({ L"ThreadObject" }) << L"\r\n"
               << L"Hotkey: " << cell({ L"热键" }) << L"\r\n"
               << L"VK: " << cell({ L"VK" }) << L"\r\n"
               << L"Modifiers: " << cell({ L"Modifiers" }) << L"\r\n"
               << L"ModifierFlags2: " << cell({ L"ModifierFlags2" }) << L"\r\n"
               << L"Id: " << cell({ L"Id" }) << L"\r\n"
               << L"Source: " << cell({ L"来源", L"SourceText" }) << L" (" << cell({ L"Source" }) << L")\r\n"
               << L"Status: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"Bucket/Depth: " << cell({ L"Bucket" }) << L" / " << cell({ L"Depth" }) << L"\r\n"
               << L"Flags: " << cell({ L"Flags" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n"
               << L"Detail: " << cell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::KeyboardHooks:
    {
        std::wostringstream detail;
        detail << L"win32k 键盘钩子枚举详情\r\n"
               << L"----------------------------------------\r\n"
               << L"PID/TID: " << cell({ L"PID" }) << L" / " << cell({ L"TID" }) << L"\r\n"
               << L"Process: " << cell({ L"进程", L"Process" }) << L"\r\n"
               << L"HookType: " << cell({ L"Hook类型", L"TypeText" }) << L" (" << cell({ L"Type" }) << L")\r\n"
               << L"Scope: " << cell({ L"ScopeText", L"Scope" }) << L" (" << cell({ L"Scope" }) << L")\r\n"
               << L"HookObject: " << cell({ L"Object" }) << L"\r\n"
               << L"ChainHead: " << cell({ L"ChainHead" }) << L"\r\n"
               << L"NextHookObject: " << cell({ L"Next" }) << L"\r\n"
               << L"ThreadInfo: " << cell({ L"ThreadInfo" }) << L"\r\n"
               << L"TargetThreadInfo: " << cell({ L"TargetThreadInfo" }) << L"\r\n"
               << L"DesktopInfo: " << cell({ L"DesktopInfo" }) << L"\r\n"
               << L"Procedure: " << cell({ L"回调", L"Procedure" }) << L"\r\n"
               << L"ProcedureOffset: " << cell({ L"ProcedureOffset" }) << L"\r\n"
               << L"Module: " << cell({ L"模块", L"ModuleBase" }) << L"\r\n"
               << L"ModuleId: " << cell({ L"ModuleId" }) << L"\r\n"
               << L"Source: " << cell({ L"来源", L"SourceText" }) << L" (" << cell({ L"Source" }) << L")\r\n"
               << L"Status: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"Flags: " << cell({ L"Flags" }) << L"\r\n"
               << L"LastStatus: " << cell({ L"LastStatus" }) << L"\r\n"
               << L"Detail: " << cell({ L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::DynDataCapabilities:
    {
        std::wostringstream detail;
        detail << L"DynData 能力详情\r\n"
               << L"----------------------------------------\r\n"
               << L"CapabilityMask: " << cell({ L"Capability", L"CapabilityMask" }) << L"\r\n"
               << L"StatusFlags: " << cell({ L"状态", L"StatusFlags" }) << L"\r\n"
               << L"字段: " << cell({ L"字段", L"Fields", L"Field" }) << L"\r\n"
               << L"原因/详情: " << cell({ L"原因", L"Reason", L"Detail" }) << L"\r\n";
        return detail.str();
    }
    case KernelFeatureId::MinifilterBypassPids: {
        std::wostringstream detail;
        detail << L"Minifilter PID 放行详情\r\n"
               << L"----------------------------------------\r\n"
               << L"Index: " << cell({ L"Index" }) << L"\r\n"
               << L"PID: " << cell({ L"PID" }) << L"\r\n"
               << L"Process: " << cell({ L"进程", L"Process" }) << L"\r\n"
               << L"Status: " << cell({ L"状态", L"Status" }) << L"\r\n"
               << L"Source: " << cell({ L"来源" }) << L"\r\n\r\n"
               << L"说明: 右键可用过滤框中的 PID 列表写入 R0 minifilter bypass whitelist，或清空 whitelist。";
        return detail.str();
    }
    case KernelFeatureId::KernelTimerDpc: {
        std::wostringstream detail;
        detail << L"KTIMER / KDPC 详情\r\n"
               << L"----------------------------------------\r\n"
               << L"CPU: " << cell({ L"CPU", L"Processor" }) << L"\r\n"
               << L"Bucket: " << cell({ L"Bucket", L"BucketIndex" }) << L"\r\n"
               << L"Timer: " << cell({ L"Timer", L"TimerAddress" }) << L"\r\n"
               << L"DueTime / Period: " << cell({ L"DueTime" }) << L" / " << cell({ L"Period" }) << L"\r\n"
               << L"TimerType: " << cell({ L"类型", L"TimerType" }) << L"\r\n"
               << L"DPC: " << cell({ L"DPC", L"DpcAddress" }) << L"\r\n"
               << L"DeferredRoutine: " << cell({ L"例程", L"DeferredRoutine" }) << L"\r\n"
               << L"DeferredContext: " << cell({ L"上下文", L"DeferredContext" }) << L"\r\n"
               << L"Flags: " << cell({ L"标志", L"Flags" }) << L"\r\n\r\n"
               << L"查询摘要：CPU=" << rawSummary({ L"ProcessorCount" })
               << L"，Bucket=" << rawSummary({ L"BucketsVisited" }) << L"/"
               << rawSummary({ L"BucketCount" }) << L"，损坏=" << rawSummary({ L"CorruptBuckets" })
               << L"，读取失败=" << rawSummary({ L"ReadFailures" })
               << L"，重复=" << rawSummary({ L"Duplicates" });
        return detail.str();
    }
    case KernelFeatureId::IoctlRegistry: {
        std::wostringstream detail;
        detail << L"KswordARK IOCTL 派遣注册表详情\r\n"
               << L"----------------------------------------\r\n"
               << L"IOCTL: " << cell({ L"IOCTL", L"IoControlCode" }) << L"\r\n"
               << L"Function: " << cell({ L"函数", L"Function", L"FunctionNumber" }) << L"\r\n"
               << L"Method/Access: " << cell({ L"Method/Access", L"MethodAccess" }) << L"\r\n"
               << L"RequiredCapability: " << cell({ L"Capability", L"RequiredCapability" }) << L"\r\n"
               << L"Handler: " << cell({ L"Handler", L"HandlerAddress" }) << L"\r\n"
               << L"Name: " << cell({ L"名称", L"Name" }) << L"\r\n"
               << L"Flags: " << cell({ L"Flags" }) << L"\r\n"
               << L"Status: " << cell({ L"状态", L"Status" }) << L"\r\n\r\n"
               << L"查询摘要：返回 " << rawSummary({ L"Returned" }) << L"/"
               << rawSummary({ L"Total" }) << L"，重复控制码=" << rawSummary({ L"Duplicates" })
               << L"，RegistryStatus=" << rawSummary({ L"RegistryStatus" });
        return detail.str();
    }
    default:
        return {};
    }
}

void KernelPage::ConfigureVisibleLayout() {
    // ConfigureVisibleLayout applies original KernelDock layout metadata to the
    // current Win32 controls. Inputs are the selected feature; processing hides
    // or shows the object-namespace property table and relayouts children; no
    // value is returned.
    Layout();
    UpdatePropertyTableFromSelection();
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DynData || descriptor->id == KernelFeatureId::DriverStatus)) {
        return;
    }
    UpdateSummaryTableFromRows();
}

void KernelPage::ConfigureToolbarForDescriptor(const KernelFeatureDescriptor& descriptor) {
    // ConfigureToolbarForDescriptor mirrors the original KernelDock toolbar for
    // the selected page. Input is the current feature descriptor; processing
    // changes static labels, combo items and default scan flags; there is no
    // return value because Win32 controls keep the state.
    ::SetWindowTextW(filterLabel_, L"过滤/起点");
    ::SetWindowTextW(moduleFilterLabel_, L"模块过滤");
    ::SetWindowTextW(locateButton_, L"定位");
    ::SetWindowTextW(refreshButton_, L"刷新/查询");
    ::SetWindowTextW(copyDiagnosticButton_, L"复制诊断");
    if (riskOnlyCheck_) {
        ::SetWindowTextW(riskOnlyCheck_, L"仅风险项");
    }
    SetEditCueBanner(filterEdit_, L"");
    SetEditCueBanner(moduleFilterEdit_, L"");
    if (includeCombo_) {
        ::SendMessageW(includeCombo_, CB_RESETCONTENT, 0, 0);
        ::ShowWindow(includeCombo_, SW_HIDE);
    }
    if (evidenceIncludeNonModuleCheck_) {
        Button_SetCheck(evidenceIncludeNonModuleCheck_, BST_UNCHECKED);
    }
    if (riskOnlyCheck_) {
        Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED);
    }
    if (integrityFillFromSelectionButton_) {
        ::SetWindowTextW(integrityFillFromSelectionButton_, L"填充");
    }
    if (integrityCpuOnlyButton_) {
        ::SetWindowTextW(integrityCpuOnlyButton_, L"CPU");
    }
    if (integrityIdtVectorsLabel_) {
        ::SetWindowTextW(integrityIdtVectorsLabel_, L"IDT");
    }

    switch (descriptor.id) {
    case KernelFeatureId::ObjectNamespaceOverview:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"定位");
        ::SetWindowTextW(refreshButton_, L"刷新");
        SetEditCueBanner(filterEdit_, L"过滤目录 / 名称 / 类型 / 完整路径 / 状态 / 目标");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::ObjectDirectoryRecursive:
        ::SetWindowTextW(filterLabel_, L"根路径:");
        ::SetWindowTextW(moduleFilterLabel_, L"最大深度:");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        SetEditCueBanner(filterEdit_, L"\\、\\Device、\\BaseNamedObjects、\\Sessions");
        SetEditCueBanner(moduleFilterEdit_, L"0-32");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        if (WindowText(filterEdit_).empty()) {
            ::SetWindowTextW(filterEdit_, L"\\");
        }
        if (WindowText(moduleFilterEdit_).empty()) {
            ::SetWindowTextW(moduleFilterEdit_, L"4");
        }
        break;
    case KernelFeatureId::NamedPipe:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"复制行");
        ::SetWindowTextW(copyDiagnosticButton_, L"刷新详情");
        ::SetWindowTextW(refreshButton_, L"刷新");
        SetEditCueBanner(filterEdit_, L"过滤管道名、NT路径、状态");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::SymbolicLink:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(copyDiagnosticButton_, L"复制目标");
        SetEditCueBanner(filterEdit_, L"过滤目录 / 名称 / 完整路径 / 状态");
        SetEditCueBanner(moduleFilterEdit_, L"按目标路径 / DOS 候选过滤");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::DeviceDriverObjects:
        ::SetWindowTextW(filterLabel_, L"关键字：");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(copyDiagnosticButton_, L"导出 TSV");
        ::SetWindowTextW(refreshButton_, L"刷新");
        SetEditCueBanner(filterEdit_, L"关键字过滤：名称 / 类型 / 路径 / 目标 / 提示");
        ::SetWindowTextW(statusText_, L"状态：首次打开后正在加载设备与驱动对象...");
        break;
    case KernelFeatureId::ObjectTypeMatrix:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"复制行");
        ::SetWindowTextW(copyDiagnosticButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        SetEditCueBanner(filterEdit_, L"按类型名、编号、策略筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::CommunicationEndpoint:
        ::SetWindowTextW(filterLabel_, L"过滤");
        ::SetWindowTextW(locateButton_, L"复制行");
        ::SetWindowTextW(copyDiagnosticButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        SetEditCueBanner(filterEdit_, L"按名称、类型、路径筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::BaseNamedObjects:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(locateButton_, L"");
        ::SetWindowTextW(refreshButton_, L"刷新");
        SetEditCueBanner(filterEdit_, L"过滤 scope / 目录 / 名称 / 类型 / 目标 / 状态");
        ::SetWindowTextW(statusText_, L"等待刷新");
        break;
    case KernelFeatureId::AtomTable:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::NtQueryLegacy:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(statusText_, L"状态：等待刷新");
        break;
    case KernelFeatureId::Ssdt:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        SetEditCueBanner(filterEdit_, L"按索引/服务名/地址/模块/状态筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 SSDT。");
        break;
    case KernelFeatureId::ShadowSsdt:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(refreshButton_, L"↻");
        SetEditCueBanner(filterEdit_, L"按索引/服务名/stub/服务例程/模块/状态筛选");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 SSSDT。");
        break;
    case KernelFeatureId::InlineHook:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"模块过滤");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(copyDiagnosticButton_, L"NOP摘除");
        SetEditCueBanner(filterEdit_, L"按模块/函数/地址/Hook类型/状态/字节筛选");
        SetEditCueBanner(moduleFilterEdit_, L"按模块或目标模块筛选");
        ::SetWindowTextW(statusText_, L"状态：等待重新扫描 Inline Hook。");
        if (includeCombo_) {
            const int suspicious = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"仅可疑外跳")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, suspicious, 0);
            const int internal = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"可疑 + 模块内跳转")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, internal, KernelRequestFlagIncludeInternal);
            const int clean = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"包含干净项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, clean, KernelRequestFlagIncludeInternal | KernelRequestFlagIncludeClean);
            ::SendMessageW(includeCombo_, CB_SETCURSEL, internal, 0);
            ::ShowWindow(includeCombo_, SW_SHOW);
        }
        break;
    case KernelFeatureId::IatEatHook:
        ::SetWindowTextW(filterLabel_, L"本地筛选");
        ::SetWindowTextW(moduleFilterLabel_, L"模块过滤");
        ::SetWindowTextW(refreshButton_, L"↻");
        SetEditCueBanner(filterEdit_, L"按类别/模块/导入模块/函数/目标/状态筛选");
        SetEditCueBanner(moduleFilterEdit_, L"按模块/导入模块/目标模块筛选");
        ::SetWindowTextW(statusText_, L"状态：等待重新扫描 IAT/EAT。");
        if (includeCombo_) {
            const int both = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"IAT + EAT 可疑项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, both, KernelRequestFlagIncludeIat | KernelRequestFlagIncludeEat);
            const int iat = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"仅 IAT 可疑项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, iat, KernelRequestFlagIncludeIat);
            const int eat = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"仅 EAT 可疑项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, eat, KernelRequestFlagIncludeEat);
            const int clean = static_cast<int>(::SendMessageW(includeCombo_, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"IAT + EAT + 干净项")));
            ::SendMessageW(includeCombo_, CB_SETITEMDATA, clean, KernelRequestFlagIncludeIat | KernelRequestFlagIncludeEat | KernelRequestFlagIncludeClean);
            ::SendMessageW(includeCombo_, CB_SETCURSEL, both, 0);
            ::ShowWindow(includeCombo_, SW_SHOW);
        }
        break;
    case KernelFeatureId::DynData:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"按字段名/偏移/状态/来源/功能/capability 筛选");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(copyDiagnosticButton_, L"复制诊断");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 DynData 状态、profile 命中和字段表。");
        break;
    case KernelFeatureId::DriverStatus:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"按功能/状态/策略/DynData capability/依赖字段筛选");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(copyDiagnosticButton_, L"复制诊断");
        ::SetWindowTextW(statusText_, L"状态：等待刷新驱动状态、协议、安全策略和能力矩阵。");
        break;
    case KernelFeatureId::CallbackEnumeration:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"按类别/来源/可信状态/移除策略/名称/地址/模块/Altitude筛选");
        ::SetWindowTextW(refreshButton_, L"↻");
        ::SetWindowTextW(statusText_, L"状态：等待刷新回调遍历。");
        break;
    case KernelFeatureId::KernelExecutableMemory:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        SetEditCueBanner(moduleFilterEdit_, L"按模块路径过滤，如 ntoskrnl.exe / drivers\\xxx.sys");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(statusText_, L"状态：等待刷新内核可执行页。");
        if (riskOnlyCheck_) {
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        break;
    case KernelFeatureId::KernelMemoryEvidence:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤 owner / detail / risk / hash");
        SetEditCueBanner(evidenceStartEdit_, L"起始VA(可选)");
        SetEditCueBanner(evidenceEndEdit_, L"结束VA(可选)");
        ::SetWindowTextW(refreshButton_, L"刷新证据");
        ::SetWindowTextW(statusText_, L"状态：等待刷新内核内存证据。");
        if (riskOnlyCheck_) {
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        if (evidenceIncludeNonModuleCheck_) {
            Button_SetCheck(evidenceIncludeNonModuleCheck_, BST_UNCHECKED);
        }
        if (WindowText(evidenceMaxRowsEdit_).empty() || WindowText(evidenceMaxRowsEdit_) == L"256") {
            ::SetWindowTextW(evidenceMaxRowsEdit_, L"512");
        }
        ::SetWindowTextW(detailEdit_,
            L"请选择一条内核内存证据记录查看详情。\r\n"
            L"说明：text diff 的磁盘对比由 R3 后续阶段完成，本页当前展示 R0 内存 hash/sample 状态。");
        break;
    case KernelFeatureId::ProcessCrossView:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤 PID/TID/进程名/异常/详情");
        ::SetWindowTextW(refreshButton_, L"刷新矩阵");
        ::SetWindowTextW(statusText_, L"状态：等待刷新进程 Cross-View 矩阵。");
        if (riskOnlyCheck_) {
            ::SetWindowTextW(riskOnlyCheck_, L"仅异常");
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        break;
    case KernelFeatureId::ThreadCrossView:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤 PID/TID/进程名/异常/详情");
        ::SetWindowTextW(refreshButton_, L"刷新矩阵");
        ::SetWindowTextW(statusText_, L"状态：等待刷新线程 Cross-View 矩阵。");
        if (riskOnlyCheck_) {
            ::SetWindowTextW(riskOnlyCheck_, L"仅异常");
            Button_SetCheck(riskOnlyCheck_, BST_CHECKED);
        }
        break;
    case KernelFeatureId::DriverIntegrity:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"DriverObject");
        ::SetWindowTextW(integrityModuleBaseLabel_, L"模块基址");
        ::SetWindowTextW(integrityFillFromSelectionButton_, L"填充");
        ::SetWindowTextW(integrityCpuOnlyButton_, L"CPU");
        SetEditCueBanner(moduleFilterEdit_, L"\\Driver\\Name（可选）");
        SetEditCueBanner(integrityModuleBaseEdit_, L"模块基址（可选）");
        SetEditCueBanner(filterEdit_, L"过滤类别/对象/目标/Owner/风险/详情");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(statusText_, L"状态：等待刷新驱动完整性证据。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        if (WindowText(evidenceMaxRowsEdit_).empty() || WindowText(evidenceMaxRowsEdit_) == L"256") {
            ::SetWindowTextW(evidenceMaxRowsEdit_, L"1024");
        }
        break;
    case KernelFeatureId::KernelCpuIntegrity:
        ::SetWindowTextW(filterLabel_, L"");
        ::SetWindowTextW(moduleFilterLabel_, L"");
        ::SetWindowTextW(integrityIdtVectorsLabel_, L"IDT/CPU:");
        SetEditCueBanner(filterEdit_, L"过滤CPU/Vector/Owner/风险/详情");
        SetEditCueBanner(integrityIdtVectorsEdit_, L"IDT向量数");
        ::SetWindowTextW(refreshButton_, L"刷新");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 CPU/IDT 完整性证据。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        if (WindowText(evidenceMaxRowsEdit_).empty() || WindowText(evidenceMaxRowsEdit_) == L"256") {
            ::SetWindowTextW(evidenceMaxRowsEdit_, L"1024");
        }
        if (WindowText(integrityIdtVectorsEdit_).empty()) {
            ::SetWindowTextW(integrityIdtVectorsEdit_, L"64");
        }
        break;
    case KernelFeatureId::CpuHardwareSnapshot:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤厂商/型号/Features/状态");
        ::SetWindowTextW(refreshButton_, L"刷新快照");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 CPU 硬件快照。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::PhysicalMemoryLayout:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤范围/地址/状态");
        ::SetWindowTextW(refreshButton_, L"刷新布局");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 R0 物理内存布局。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::MutationAudit:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤操作/目标/PID/地址/风险/Flags");
        ::SetWindowTextW(refreshButton_, L"刷新审计");
        ::SetWindowTextW(statusText_, L"状态：等待刷新内核修改审计。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::KeyboardHotkeys:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤PID/TID/进程/热键/来源");
        ::SetWindowTextW(refreshButton_, L"刷新热键");
        ::SetWindowTextW(statusText_, L"状态：等待刷新键盘热键。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::KeyboardHooks:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤PID/TID/类型/模块/来源/详情");
        ::SetWindowTextW(refreshButton_, L"刷新钩子");
        ::SetWindowTextW(statusText_, L"状态：等待刷新键盘钩子。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::DynDataCapabilities:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤Capability/状态/字段/原因");
        ::SetWindowTextW(refreshButton_, L"刷新能力");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 DynData 能力。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::MinifilterBypassPids:
        ::SetWindowTextW(filterLabel_, L"PID列表");
        SetEditCueBanner(filterEdit_, L"过滤PID/进程/状态/来源");
        ::SetWindowTextW(refreshButton_, L"刷新PID");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 Minifilter PID 放行表。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::KernelTimerDpc:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤CPU/Bucket/Timer/DPC/例程/标志/详情");
        ::SetWindowTextW(refreshButton_, L"刷新定时器");
        ::SetWindowTextW(statusText_, L"状态：等待刷新每 CPU KTIMER/DPC 快照。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    case KernelFeatureId::IoctlRegistry:
        ::SetWindowTextW(filterLabel_, L"");
        SetEditCueBanner(filterEdit_, L"过滤IOCTL/函数/名称/Capability/Handler/Flags");
        ::SetWindowTextW(refreshButton_, L"刷新派遣表");
        ::SetWindowTextW(statusText_, L"状态：等待刷新 KswordARK IOCTL 派遣注册表。");
        if (riskOnlyCheck_) { Button_SetCheck(riskOnlyCheck_, BST_UNCHECKED); }
        break;
    default:
        break;
    }
}

void KernelPage::PopulateCallbackInterceptPanel() {
    // PopulateCallbackInterceptPanel maps the callback-runtime result rows onto
    // the dedicated Win32 panel that mirrors the original CallbackIntercept
    // controller: rule-group table, per-callback rule tabs, minifilter bypass
    // table, app log, event log, and file-monitor grid. Inputs are the current
    // cached result rows; processing is display-only except explicit button
    // actions; no value is returned.
    if (!callbackGroupList_ || !callbackRuleTab_) {
        return;
    }
    EnsureCallbackLocalModel();
    ListView_DeleteAllItems(callbackGroupList_);
    for (HWND ruleList : callbackRuleLists_) {
        ListView_DeleteAllItems(ruleList);
    }
    if (callbackBypassList_) {
        ListView_DeleteAllItems(callbackBypassList_);
    }
    if (callbackFileMonitorList_) {
        ListView_DeleteAllItems(callbackFileMonitorList_);
    }
    RenderCallbackLocalModel();

    std::wstring runtimeStatus = L"状态：等待刷新";
    std::wstring appLog;
    std::wstring eventLog;
    std::wstring registeredText;
    std::wstring ruleVersion;
    std::wstring groupCount;
    std::wstring ruleCount;
    std::wstring pendingCount;
    std::wstring waitingCount;

    const auto rowValue = [](const std::vector<std::wstring>& row, const std::vector<std::wstring>& columns, std::initializer_list<const wchar_t*> names) -> std::wstring {
        for (const wchar_t* name : names) {
            for (std::size_t column = 0; column < columns.size() && column < row.size(); ++column) {
                if (_wcsicmp(columns[column].c_str(), name) == 0 && !row[column].empty()) {
                    return row[column];
                }
            }
        }
        return {};
    };

    for (const std::vector<std::wstring>& row : currentRows_) {
        const std::wstring section = rowValue(row, currentColumns_, { L"Section" });
        if (section == L"Runtime") {
            runtimeStatus = L"状态：驱动";
            runtimeStatus += rowValue(row, currentColumns_, { L"DriverOnline" }) == L"是" ? L"在线" : L"离线";
            runtimeStatus += L" | 全局启用=" + rowValue(row, currentColumns_, { L"GlobalEnabled" });
            runtimeStatus += L" | 规则已应用=" + rowValue(row, currentColumns_, { L"RulesApplied" });
            appLog += L"[Runtime] ";
            appLog += rowValue(row, currentColumns_, { L"Health" });
            appLog += L"\r\n";
        } else if (section == L"Callbacks") {
            registeredText = rowValue(row, currentColumns_, { L"RegisteredText" });
            appLog += L"[Callbacks] 已注册: " + registeredText + L"\r\n";
        } else if (section == L"CallbackType") {
            const std::wstring name = rowValue(row, currentColumns_, { L"Name", L"Type" });
            const std::wstring registered = rowValue(row, currentColumns_, { L"Registered" });
            if (callbackRuleLists_.empty() || ListView_GetItemCount(callbackRuleLists_.front()) == 0) {
                AddListRow(callbackRuleLists_.empty() ? nullptr : callbackRuleLists_.front(), {
                    registered, L"", L"", name, rowValue(row, currentColumns_, { L"Mask" }), L"", L"运行态注册", L"", L"", L""
                });
            }
        } else if (section == L"Rules") {
            groupCount = rowValue(row, currentColumns_, { L"Groups" });
            ruleCount = rowValue(row, currentColumns_, { L"Rules" });
            ruleVersion = rowValue(row, currentColumns_, { L"RuleVersion" });
            if (ListView_GetItemCount(callbackGroupList_) == 0) {
                AddListRow(callbackGroupList_, {
                    L"0",
                    L"当前驱动规则快照",
                    rowValue(row, currentColumns_, { L"RulesApplied" }).empty() ? L"是" : rowValue(row, currentColumns_, { L"RulesApplied" }),
                    L"0",
                    L"Groups=" + groupCount + L" Rules=" + ruleCount + L" Version=" + ruleVersion
                });
            }
            appLog += L"[Rules] groups=" + groupCount + L", rules=" + ruleCount + L", version=" + ruleVersion + L"\r\n";
        } else if (section == L"PendingDecision") {
            pendingCount = rowValue(row, currentColumns_, { L"Pending", L"PendingDecisions" });
            waitingCount = rowValue(row, currentColumns_, { L"WaitingReceivers" });
            eventLog += L"[PendingDecision] pending=" + pendingCount + L", waitingReceivers=" + waitingCount + L"\r\n";
            AddListRow(callbackRuleLists_.empty() ? nullptr : callbackRuleLists_.front(), {
                L"是", L"", L"", L"等待用户决策", L"", L"", rowValue(row, currentColumns_, { L"Attention" }), L"", L"", L""
            });
        } else if (section == L"Action") {
            appLog += L"[Action] " + rowValue(row, currentColumns_, { L"Action" }) + L" Win32=" + rowValue(row, currentColumns_, { L"Win32" }) + L"\r\n";
        } else if (section == L"MinifilterBypass" || section == L"BypassPid") {
            AddListRow(callbackBypassList_, {
                rowValue(row, currentColumns_, { L"PID", L"Pid" }),
                rowValue(row, currentColumns_, { L"Process", L"Name", L"Source" })
            });
        } else if (section == L"FileMonitor" || section == L"FileEvent") {
            const bool fsctlOnly = callbackFileMonitorFsctlOnlyCheck_ == nullptr ||
                Button_GetCheck(callbackFileMonitorFsctlOnlyCheck_) == BST_CHECKED;
            const std::wstring fsctlName = rowValue(row, currentColumns_, { L"FsctlName" });
            const std::wstring controlCode = rowValue(row, currentColumns_, { L"ControlCode" });
            if (section == L"FileEvent" && fsctlOnly &&
                (fsctlName.empty() || fsctlName == L"-") &&
                (controlCode.empty() || controlCode == L"-")) {
                continue;
            }
            AddListRow(callbackFileMonitorList_, {
                rowValue(row, currentColumns_, { L"Time" }),
                rowValue(row, currentColumns_, { L"PID", L"Pid" }),
                rowValue(row, currentColumns_, { L"Process" }),
                rowValue(row, currentColumns_, { L"Path" }),
                fsctlName,
                controlCode,
                rowValue(row, currentColumns_, { L"Status" }),
                rowValue(row, currentColumns_, { L"FileObject" }),
                rowValue(row, currentColumns_, { L"InputLength" }),
                rowValue(row, currentColumns_, { L"OutputLength" }),
                rowValue(row, currentColumns_, { L"PathState" }),
            });
        }
    }

    if (callbackGroupList_ && ListView_GetItemCount(callbackGroupList_) == 0) {
        AddListRow(callbackGroupList_, { L"1", L"默认规则组", L"是", L"10", L"本地规则编辑器默认组；点击应用后写入驱动。" });
    }
    for (std::size_t index = 1; index < callbackRuleLists_.size() && index < 6; ++index) {
        if (ListView_GetItemCount(callbackRuleLists_[index]) == 0) {
            AddListRow(callbackRuleLists_[index], { L"", L"", L"", L"暂无规则", L"", L"", L"", L"", L"", L"" });
        }
    }
    if (callbackBypassList_ && ListView_GetItemCount(callbackBypassList_) == 0) {
        AddListRow(callbackBypassList_, { L"", L"尚未从驱动刷新；编辑后点击“应用到驱动”生效。" });
    }
    if (callbackFileMonitorList_ && ListView_GetItemCount(callbackFileMonitorList_) == 0) {
        AddListRow(callbackFileMonitorList_, { L"", L"", L"", L"尚无文件系统事件；点击“启动 FSCTL 监控/拉取事件”后显示。", L"", L"", L"", L"", L"", L"", L"" });
    }

    runtimeStatus += L" | 规则版本=" + (ruleVersion.empty() ? L"<未知>" : ruleVersion);
    runtimeStatus += L" | 规则数=" + (ruleCount.empty() ? L"0" : ruleCount);
    runtimeStatus += L" | 等待接收者=" + (waitingCount.empty() ? L"0" : waitingCount);
    runtimeStatus += L" | 待决策=" + (pendingCount.empty() ? L"0" : pendingCount);
    ::SetWindowTextW(callbackStatusText_, runtimeStatus.c_str());
    if (callbackBypassStatusText_) {
        const int bypassRows = callbackBypassList_ ? ListView_GetItemCount(callbackBypassList_) : 0;
        std::wstring bypassStatus = L"尚未从驱动刷新；编辑后点击“应用到驱动”生效。";
        if (bypassRows > 0 && !ListViewText(callbackBypassList_, 0, 0).empty()) {
            bypassStatus = L"当前 PID 放行项: " + std::to_wstring(bypassRows) + L"；点击“应用到驱动”后生效。";
        }
        ::SetWindowTextW(callbackBypassStatusText_, bypassStatus.c_str());
    }
    if (callbackFileMonitorStatusText_) {
        const int fileRows = callbackFileMonitorList_ ? ListView_GetItemCount(callbackFileMonitorList_) : 0;
        std::wstring fileStatus = fileRows > 0 && !ListViewText(callbackFileMonitorList_, 0, 3).empty()
            ? L"当前文件监控事件: " + std::to_wstring(fileRows)
            : L"等待启动或读取事件";
        ::SetWindowTextW(callbackFileMonitorStatusText_, fileStatus.c_str());
    }
    if (appLog.empty()) {
        appLog = L"应用日志：刷新后显示驱动回调运行态、规则应用与控制动作。\r\n";
    }
    if (eventLog.empty()) {
        eventLog = L"事件日志：等待决策、文件系统事件和用户决策将显示在这里。\r\n";
    }
    ::SetWindowTextW(callbackAppLogEdit_, appLog.c_str());
    if (!callbackPendingEvents_.empty() || (callbackEventReceiver_ && callbackEventReceiver_->running())) {
        RefreshCallbackEventLog();
    } else {
        ::SetWindowTextW(callbackEventLogEdit_, eventLog.c_str());
    }
}

void KernelPage::EnsureCallbackLocalModel() {
    // EnsureCallbackLocalModel initializes the in-memory CallbackIntercept rule
    // editor. There is no input; processing creates one default group so the
    // original add/remove/move UI can operate immediately; no value is returned.
    if (!callbackGroups_.empty()) {
        return;
    }
    callbackGroups_.push_back({ 1, L"默认组", true, 10, L"默认规则组" });
    nextCallbackGroupId_ = 2;
    nextCallbackRuleId_ = 1;
}

void KernelPage::RenderCallbackLocalModel() {
    // RenderCallbackLocalModel maps local rule groups and rules into the Win32
    // grids. Inputs are callbackGroups_/callbackRules_; processing refreshes
    // group and per-type rule ListViews; output is visible UI state only.
    EnsureCallbackLocalModel();
    if (callbackGroupList_) {
        ListView_DeleteAllItems(callbackGroupList_);
    }
    for (HWND ruleList : callbackRuleLists_) {
        ListView_DeleteAllItems(ruleList);
    }
    for (const CallbackRuleGroup& group : callbackGroups_) {
        AddListRow(callbackGroupList_, {
            std::to_wstring(group.id),
            group.name,
            BoolText(group.enabled),
            std::to_wstring(group.priority),
            group.comment,
        });
    }
    for (const CallbackRule& rule : callbackRules_) {
        if (rule.typeIndex < 0 || rule.typeIndex >= static_cast<int>(callbackRuleLists_.size()) || rule.typeIndex >= 6) {
            continue;
        }
        HWND ruleList = callbackRuleLists_[static_cast<std::size_t>(rule.typeIndex)];
        AddListRow(ruleList, {
            BoolText(rule.enabled),
            std::to_wstring(rule.id),
            std::to_wstring(rule.groupId),
            rule.name,
            rule.operation,
            rule.matchMode,
            rule.action,
            std::to_wstring(rule.timeoutMs),
            rule.timeoutDefault,
            std::to_wstring(rule.priority),
        });
        AddListRow(ruleList, {
            L"",
            L"",
            L"发起程序匹配",
            rule.initiatorPattern.empty() ? L"*" : rule.initiatorPattern,
            L"目标程序匹配",
            rule.targetPattern.empty() ? L"*" : rule.targetPattern,
            L"备注",
            rule.comment,
            L"",
            L"",
        });
    }
}

void KernelPage::AppendCallbackAppLog(const std::wstring& message) {
    // AppendCallbackAppLog appends one operational line to the CallbackIntercept
    // app log. Input is already localized text; output updates the read-only
    // log edit and status label.
    std::wstring log = WindowText(callbackAppLogEdit_);
    if (!log.empty() && log.back() != L'\n') {
        log += L"\r\n";
    }
    log += message;
    log += L"\r\n";
    ::SetWindowTextW(callbackAppLogEdit_, log.c_str());
    ::SetWindowTextW(callbackStatusText_, message.c_str());
}

void KernelPage::StartCallbackEventReceiver() {
    if (!callbackEventReceiver_) {
        return;
    }
    if (callbackPendingEvents_.size() >= 64U) {
        AppendCallbackAppLog(L"待决策队列已达到 64 条，为避免丢失事件，未继续接收。请先处理当前事件。");
        RefreshCallbackEventLog();
        return;
    }
    if (callbackEventReceiver_->Start()) {
        AppendCallbackAppLog(L"已启动 Callback 待决策后台接收器。");
    } else if (callbackEventReceiver_->running()) {
        AppendCallbackAppLog(L"Callback 待决策后台接收器已在运行。");
    } else if (callbackEventReceiver_->stopping()) {
        AppendCallbackAppLog(L"Callback 待决策后台接收器正在停止，取消完成后可再次启动。");
    } else {
        AppendCallbackAppLog(L"无法启动 Callback 待决策后台接收器。");
    }
    RefreshCallbackEventLog();
}

void KernelPage::StopCallbackEventReceiver() {
    if (callbackEventReceiver_ && callbackEventReceiver_->running()) {
        callbackEventReceiver_->Stop();
        AppendCallbackAppLog(L"已请求停止 Callback 待决策后台接收器，当前待决策事件仍可应答。");
    }
    RefreshCallbackEventLog();
}

void KernelPage::AcceptCallbackEvent(CallbackEventSnapshot snapshot) {
    if (callbackPendingEvents_.size() >= 64U) {
        StopCallbackEventReceiver();
        AppendCallbackAppLog(L"待决策队列已满，已停止接收以保留现有事件。请处理当前事件后再继续接收。");
        return;
    }
    const std::wstring guid = CallbackGuidText(snapshot.event.eventGuid);
    callbackPendingEvents_.push_back(std::move(snapshot));
    AppendCallbackAppLog(L"收到待决策 Callback 事件 " + guid + L"，等待显式允许或拒绝。");
    if (callbackPendingEvents_.size() >= 64U) {
        StopCallbackEventReceiver();
    }
    RefreshCallbackEventLog();
}

void KernelPage::AnswerCurrentCallbackEvent(const bool allow) {
    if (callbackPendingEvents_.empty()) {
        AppendCallbackAppLog(L"没有等待用户决策的 Callback 事件。");
        return;
    }
    if (!callbackAnswerTask_ || callbackAnswerTask_->running()) {
        AppendCallbackAppLog(L"上一条 Callback 决策仍在后台提交，请等待结果。");
        return;
    }

    const CallbackEventSnapshot snapshot = callbackPendingEvents_.front();
    const std::wstring guid = CallbackGuidText(snapshot.event.eventGuid);
    const std::wstring target = FixedWideText(snapshot.event.targetPath);
    const std::wstring prompt = std::wstring(allow ? L"允许" : L"拒绝") + L" 当前 Callback 事件？\n\n"
        + L"事件: " + guid + L"\n"
        + L"发起 PID: " + std::to_wstring(snapshot.event.originatingPid) + L"\n"
        + L"目标: " + (target.empty() ? L"<不可用>" : target) + L"\n\n"
        + L"此决定会立即发送给驱动，超时前不会自动替代为默认动作。";
    if (::MessageBoxW(hwnd_, prompt.c_str(), allow ? L"确认允许 Callback 事件" : L"确认拒绝 Callback 事件",
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING) != IDYES) {
        AppendCallbackAppLog(L"用户取消了 Callback 待决策应答。");
        return;
    }

    KernelActionRequest request;
    request.featureId = KernelFeatureId::CallbackIntercept;
    request.actionId = KernelActionId::CallbackAnswerEvent;
    request.rowFields = {
        { L"EventGuid", guid },
        { L"SourceSessionId", std::to_wstring(snapshot.event.sessionId) },
        { L"Decision", allow ? L"Allow" : L"Deny" },
    };
    ::EnableWindow(callbackAllowEventButton_, FALSE);
    ::EnableWindow(callbackDenyEventButton_, FALSE);
    ::SetWindowTextW(callbackStatusText_, L"正在后台提交 Callback 待决策应答…");
    callbackAnswerTask_->request(
        [request] {
            KernelFacade facade;
            return facade.ExecuteAction(request);
        },
        [this, guid, allow](std::uint64_t, std::optional<KernelOperationResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value()) {
                AppendCallbackAppLog(L"Callback 待决策应答后台任务异常结束，事件仍保留在队列。" );
                RefreshCallbackEventLog();
                return;
            }
            if (result->success) {
                const auto found = std::find_if(callbackPendingEvents_.begin(), callbackPendingEvents_.end(),
                    [&guid](const CallbackEventSnapshot& item) { return CallbackGuidText(item.event.eventGuid) == guid; });
                if (found != callbackPendingEvents_.end()) {
                    callbackPendingEvents_.erase(found);
                }
                AppendCallbackAppLog(std::wstring(L"Callback 事件 ") + guid + (allow ? L" 已允许。" : L" 已拒绝。"));
            } else {
                AppendCallbackAppLog(L"Callback 待决策应答失败，事件保留在队列。 " + result->message);
            }
            RefreshCallbackEventLog();
        });
}

void KernelPage::RefreshCallbackEventLog() {
    const bool receiverRunning = callbackEventReceiver_ && callbackEventReceiver_->running();
    const bool answerRunning = callbackAnswerTask_ && callbackAnswerTask_->running();
    if (callbackStartReceiverButton_) {
        const bool receiverStopping = callbackEventReceiver_ && callbackEventReceiver_->stopping();
        ::EnableWindow(callbackStartReceiverButton_, !receiverRunning && !receiverStopping && callbackPendingEvents_.size() < 64U);
    }
    if (callbackStopReceiverButton_) {
        ::EnableWindow(callbackStopReceiverButton_, receiverRunning);
    }
    if (callbackAllowEventButton_) {
        ::EnableWindow(callbackAllowEventButton_, !callbackPendingEvents_.empty() && !answerRunning);
    }
    if (callbackDenyEventButton_) {
        ::EnableWindow(callbackDenyEventButton_, !callbackPendingEvents_.empty() && !answerRunning);
    }
    if (!callbackEventLogEdit_) {
        return;
    }

    std::wostringstream log;
    log << L"接收器: " << (receiverRunning ? L"运行中" : L"已停止")
        << L" | 待决策: " << callbackPendingEvents_.size() << L"/64\r\n";
    if (callbackPendingEvents_.empty()) {
        log << L"暂无待决策事件。启动接收器后，驱动的 Ask User 规则事件会在这里显示。\r\n";
    } else {
        const CallbackEventSnapshot& current = callbackPendingEvents_.front();
        log << L"当前事件（点击“允许当前”或“拒绝当前”后才会应答）\r\n"
            << L"GUID: " << CallbackGuidText(current.event.eventGuid) << L"\r\n"
            << L"类型/操作: " << current.event.callbackType << L" / " << current.event.operationType << L"\r\n"
            << L"发起: PID=" << current.event.originatingPid << L", TID=" << current.event.originatingTid
            << L", Session=" << current.event.sessionId << L"\r\n"
            << L"规则: [" << current.event.groupId << L"] " << FixedWideText(current.event.groupName)
            << L" / [" << current.event.ruleId << L"] " << FixedWideText(current.event.ruleName) << L"\r\n"
            << L"发起路径: " << FixedWideText(current.event.initiatorPath) << L"\r\n"
            << L"目标路径: " << FixedWideText(current.event.targetPath) << L"\r\n"
            << L"默认决策: " << current.event.defaultDecision << L", 超时毫秒: " << current.event.timeoutMs << L"\r\n";
        if (callbackPendingEvents_.size() > 1U) {
            log << L"\r\n后续待决策事件:\r\n";
            const std::size_t tail = std::min<std::size_t>(callbackPendingEvents_.size(), 16U);
            for (std::size_t index = 1; index < tail; ++index) {
                const CallbackEventSnapshot& item = callbackPendingEvents_[index];
                log << L"[" << index << L"] " << CallbackGuidText(item.event.eventGuid)
                    << L" PID=" << item.event.originatingPid
                    << L" " << FixedWideText(item.event.targetPath) << L"\r\n";
            }
            if (callbackPendingEvents_.size() > tail) {
                log << L"…其余 " << (callbackPendingEvents_.size() - tail) << L" 条保留在队列。\r\n";
            }
        }
    }
    ::SetWindowTextW(callbackEventLogEdit_, log.str().c_str());
}

int KernelPage::CallbackSelectedRuleTabIndex() const {
    // CallbackSelectedRuleTabIndex returns the selected rule tab index. There is
    // no input; output is clamped into the real rule-list range.
    const int index = callbackRuleTab_ ? static_cast<int>(::SendMessageW(callbackRuleTab_, TCM_GETCURSEL, 0, 0)) : 0;
    if (index < 0 || index >= static_cast<int>(callbackRuleLists_.size())) {
        return 0;
    }
    return index;
}

int KernelPage::CallbackSelectedGroupRow() const {
    // CallbackSelectedGroupRow returns the selected group ListView row. There is
    // no input; output is -1 when the user has not selected a group.
    return callbackGroupList_ ? ListView_GetNextItem(callbackGroupList_, -1, LVNI_SELECTED) : -1;
}

int KernelPage::CallbackSelectedRuleRow() const {
    // CallbackSelectedRuleRow returns the selected rule row on the active rule
    // tab. There is no input; output is the header row of the two-row original
    // rule presentation, or -1 when no row is selected.
    const int tab = CallbackSelectedRuleTabIndex();
    if (tab < 0 || tab >= static_cast<int>(callbackRuleLists_.size())) {
        return -1;
    }
    const int selected = ListView_GetNextItem(callbackRuleLists_[static_cast<std::size_t>(tab)], -1, LVNI_SELECTED);
    if (selected < 0) {
        return -1;
    }
    return selected % 2 == 0 ? selected : selected - 1;
}

std::uint32_t KernelPage::CallbackSelectedGroupId() const {
    // CallbackSelectedGroupId reads the selected group id from the visible grid.
    // There is no input; output falls back to the first local group id.
    const int row = CallbackSelectedGroupRow();
    if (row >= 0) {
        const std::uint32_t id = ParseUnsigned(ListViewText(callbackGroupList_, row, 0), 0);
        if (id != 0) {
            return id;
        }
    }
    return callbackGroups_.empty() ? 0 : callbackGroups_.front().id;
}

void KernelPage::OnCallbackAddGroup() {
    // OnCallbackAddGroup creates a local rule group. Input is optional name text
    // from the generic filter box; output updates the group grid and app log.
    EnsureCallbackLocalModel();
    CallbackRuleGroup group;
    group.id = nextCallbackGroupId_++;
    group.name = WindowText(filterEdit_);
    if (group.name.empty()) {
        group.name = L"规则组" + std::to_wstring(group.id);
    }
    group.enabled = true;
    group.priority = static_cast<int>(10 + callbackGroups_.size());
    group.comment = L"Win32 Light 本地规则组";
    callbackGroups_.push_back(group);
    RenderCallbackLocalModel();
    AppendCallbackAppLog(L"新增规则组: " + group.name);
}

void KernelPage::OnCallbackRemoveGroup() {
    // OnCallbackRemoveGroup deletes the selected local group and its rules.
    // Input is the group ListView selection; output refreshes local UI state.
    const std::uint32_t groupId = CallbackSelectedGroupId();
    if (groupId == 0 || callbackGroups_.size() <= 1) {
        AppendCallbackAppLog(L"至少保留一个规则组，删除已取消。");
        return;
    }
    callbackGroups_.erase(std::remove_if(callbackGroups_.begin(), callbackGroups_.end(), [groupId](const CallbackRuleGroup& group) {
        return group.id == groupId;
    }), callbackGroups_.end());
    callbackRules_.erase(std::remove_if(callbackRules_.begin(), callbackRules_.end(), [groupId](const CallbackRule& rule) {
        return rule.groupId == groupId;
    }), callbackRules_.end());
    RenderCallbackLocalModel();
    AppendCallbackAppLog(L"删除规则组: groupId=" + std::to_wstring(groupId));
}

void KernelPage::OnCallbackRenameGroup() {
    // OnCallbackRenameGroup renames the selected group. Input is the selected
    // group plus filter-box text as the new name; output refreshes the grid.
    const std::uint32_t groupId = CallbackSelectedGroupId();
    std::wstring newName = WindowText(filterEdit_);
    if (newName.empty()) {
        newName = L"规则组" + std::to_wstring(groupId) + L"-重命名";
    }
    for (CallbackRuleGroup& group : callbackGroups_) {
        if (group.id == groupId) {
            group.name = newName;
            RenderCallbackLocalModel();
            AppendCallbackAppLog(L"重命名规则组: " + newName);
            return;
        }
    }
}

void KernelPage::OnCallbackMoveGroup(const bool moveUp) {
    // OnCallbackMoveGroup moves the selected local group. Input is direction;
    // output is reordered local state and refreshed UI.
    const std::uint32_t groupId = CallbackSelectedGroupId();
    auto found = std::find_if(callbackGroups_.begin(), callbackGroups_.end(), [groupId](const CallbackRuleGroup& group) {
        return group.id == groupId;
    });
    if (found == callbackGroups_.end()) {
        return;
    }
    const std::size_t index = static_cast<std::size_t>(std::distance(callbackGroups_.begin(), found));
    if (moveUp) {
        if (index == 0) {
            return;
        }
        std::swap(callbackGroups_[index], callbackGroups_[index - 1]);
    } else {
        if (index + 1 >= callbackGroups_.size()) {
            return;
        }
        std::swap(callbackGroups_[index], callbackGroups_[index + 1]);
    }
    RenderCallbackLocalModel();
    AppendCallbackAppLog(moveUp ? L"规则组已上移。" : L"规则组已下移。");
}

void KernelPage::OnCallbackToggleGroupEnabled() {
    // OnCallbackToggleGroupEnabled flips the selected local group enabled flag.
    // Input is the current group row selection; output refreshes the group grid
    // and logs the new effective state used by later rule application.
    const std::uint32_t groupId = CallbackSelectedGroupId();
    for (CallbackRuleGroup& group : callbackGroups_) {
        if (group.id == groupId) {
            group.enabled = !group.enabled;
            RenderCallbackLocalModel();
            AppendCallbackAppLog(L"规则组 " + std::to_wstring(groupId) + L" 启用状态=" + BoolText(group.enabled));
            return;
        }
    }
    AppendCallbackAppLog(L"没有选中可切换的规则组。");
}

void KernelPage::OnCallbackAddRule() {
    // OnCallbackAddRule appends a rule to the active callback type tab. Inputs
    // are active tab and selected/default group; output is a new local rule row.
    EnsureCallbackLocalModel();
    const int typeIndex = CallbackSelectedRuleTabIndex();
    if (typeIndex >= 6) {
        AppendCallbackAppLog(L"PID 放行页不创建规则；请使用 PID 添加/移除按钮。");
        return;
    }
    CallbackRule rule;
    rule.id = nextCallbackRuleId_++;
    rule.groupId = CallbackSelectedGroupId();
    rule.typeIndex = typeIndex;
    rule.name = WindowText(filterEdit_);
    if (rule.name.empty()) {
        rule.name = L"规则" + std::to_wstring(rule.id);
    }
    rule.enabled = true;
    rule.operation = typeIndex == 0 ? L"全部注册表操作" :
        typeIndex == 1 ? L"进程创建" :
        typeIndex == 2 ? L"线程创建/退出" :
        typeIndex == 3 ? L"镜像加载" :
        typeIndex == 4 ? L"句柄创建/复制 + 进程/线程对象" :
        L"文件系统微过滤器全部操作";
    rule.matchMode = L"通配";
    rule.action = L"记录";
    rule.timeoutMs = 5000;
    rule.timeoutDefault = L"允许";
    rule.initiatorPattern = L"*";
    rule.targetPattern = L"*";
    rule.priority = (static_cast<int>(callbackRules_.size()) + 1) * 10;
    rule.comment = L"新建规则";
    callbackRules_.push_back(rule);
    RenderCallbackLocalModel();
    AppendCallbackAppLog(L"新增规则: " + rule.name);
}

void KernelPage::OnCallbackRemoveRule() {
    // OnCallbackRemoveRule deletes the selected rule from the active tab. Input
    // is ListView selection; output refreshes local rule tables.
    const int tab = CallbackSelectedRuleTabIndex();
    const int row = CallbackSelectedRuleRow();
    if (row < 0 || tab >= 6) {
        AppendCallbackAppLog(L"当前未选中可删除规则。");
        return;
    }
    const std::uint32_t ruleId = ParseUnsigned(ListViewText(callbackRuleLists_[static_cast<std::size_t>(tab)], row, 1), 0);
    callbackRules_.erase(std::remove_if(callbackRules_.begin(), callbackRules_.end(), [ruleId](const CallbackRule& rule) {
        return rule.id == ruleId;
    }), callbackRules_.end());
    RenderCallbackLocalModel();
    AppendCallbackAppLog(L"删除规则: ruleId=" + std::to_wstring(ruleId));
}

void KernelPage::OnCallbackMoveRule(const bool moveUp) {
    // OnCallbackMoveRule reorders the selected rule inside local storage. Input
    // is direction and active rule selection; output is refreshed rule grids.
    const int tab = CallbackSelectedRuleTabIndex();
    const int row = CallbackSelectedRuleRow();
    if (row < 0 || tab >= 6) {
        return;
    }
    const std::uint32_t ruleId = ParseUnsigned(ListViewText(callbackRuleLists_[static_cast<std::size_t>(tab)], row, 1), 0);
    auto found = std::find_if(callbackRules_.begin(), callbackRules_.end(), [ruleId](const CallbackRule& rule) {
        return rule.id == ruleId;
    });
    if (found == callbackRules_.end()) {
        return;
    }
    const std::size_t index = static_cast<std::size_t>(std::distance(callbackRules_.begin(), found));
    if (moveUp) {
        if (index == 0) {
            return;
        }
        std::swap(callbackRules_[index], callbackRules_[index - 1]);
    } else {
        if (index + 1 >= callbackRules_.size()) {
            return;
        }
        std::swap(callbackRules_[index], callbackRules_[index + 1]);
    }
    RenderCallbackLocalModel();
    AppendCallbackAppLog(moveUp ? L"规则已上移。" : L"规则已下移。");
}

void KernelPage::OnCallbackToggleRuleEnabled() {
    // OnCallbackToggleRuleEnabled flips the selected rule enabled flag. Input is
    // the active rule tab selection; output refreshes rule grids and logs state.
    const int tab = CallbackSelectedRuleTabIndex();
    const int row = CallbackSelectedRuleRow();
    if (row < 0 || tab >= 6) {
        AppendCallbackAppLog(L"当前未选中可切换规则。");
        return;
    }
    const std::uint32_t ruleId = ParseUnsigned(ListViewText(callbackRuleLists_[static_cast<std::size_t>(tab)], row, 1), 0);
    for (CallbackRule& rule : callbackRules_) {
        if (rule.id == ruleId) {
            rule.enabled = !rule.enabled;
            RenderCallbackLocalModel();
            AppendCallbackAppLog(L"规则 " + std::to_wstring(ruleId) + L" 启用状态=" + BoolText(rule.enabled));
            return;
        }
    }
    AppendCallbackAppLog(L"未找到选中的本地规则。");
}

void KernelPage::OnCallbackCopyRuleText() {
    // OnCallbackCopyRuleText mirrors the original rule-table context action.
    // Input is the selected two-row rule; processing serializes one rule as
    // key/value text; output writes CF_UNICODETEXT and an app-log line.
    const int tab = CallbackSelectedRuleTabIndex();
    const int row = CallbackSelectedRuleRow();
    if (row < 0 || tab >= 6) {
        AppendCallbackAppLog(L"复制规则失败：当前未选中有效规则。");
        return;
    }
    const std::uint32_t ruleId = ParseUnsigned(ListViewText(callbackRuleLists_[static_cast<std::size_t>(tab)], row, 1), 0);
    const auto found = std::find_if(callbackRules_.cbegin(), callbackRules_.cend(), [ruleId](const CallbackRule& rule) {
        return rule.id == ruleId;
    });
    if (found == callbackRules_.cend()) {
        AppendCallbackAppLog(L"复制规则失败：未找到本地规则模型。");
        return;
    }
    const CallbackRule& rule = *found;
    std::wostringstream out;
    out << L"KSWORD_CALLBACK_RULE_TEXT_V1\r\n"
        << L"ruleId=" << rule.id << L"\r\n"
        << L"groupId=" << rule.groupId << L"\r\n"
        << L"typeIndex=" << rule.typeIndex << L"\r\n"
        << L"enabled=" << (rule.enabled ? 1 : 0) << L"\r\n"
        << L"priority=" << rule.priority << L"\r\n"
        << L"timeoutMs=" << rule.timeoutMs << L"\r\n"
        << L"ruleName=" << EscapeConfigField(rule.name) << L"\r\n"
        << L"operation=" << EscapeConfigField(rule.operation) << L"\r\n"
        << L"matchMode=" << EscapeConfigField(rule.matchMode) << L"\r\n"
        << L"action=" << EscapeConfigField(rule.action) << L"\r\n"
        << L"timeoutDefault=" << EscapeConfigField(rule.timeoutDefault) << L"\r\n"
        << L"initiatorPattern=" << EscapeConfigField(rule.initiatorPattern) << L"\r\n"
        << L"targetPattern=" << EscapeConfigField(rule.targetPattern) << L"\r\n"
        << L"comment=" << EscapeConfigField(rule.comment) << L"\r\n";
    SetClipboardText(hwnd_, out.str());
    AppendCallbackAppLog(L"已复制规则到剪贴板：ruleId=" + std::to_wstring(rule.id));
}

void KernelPage::OnCallbackPasteRuleText() {
    // OnCallbackPasteRuleText mirrors the original paste-as-new-rule action.
    // Input is CF_UNICODETEXT containing key/value rule text; processing assigns
    // a fresh rule id and current group/type fallback; output appends a rule row.
    const std::wstring text = GetClipboardText(hwnd_);
    if (text.empty()) {
        AppendCallbackAppLog(L"粘贴失败：剪贴板为空。");
        return;
    }
    std::wistringstream input(text);
    std::wstring line;
    bool sawHeader = false;
    std::unordered_map<std::wstring, std::wstring> values;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if (!sawHeader) {
            sawHeader = line == L"KSWORD_CALLBACK_RULE_TEXT_V1";
            if (!sawHeader) {
                AppendCallbackAppLog(L"粘贴失败：不是支持的规则文本格式。");
                return;
            }
            continue;
        }
        const std::size_t equal = line.find(L'=');
        if (equal == std::wstring::npos) {
            continue;
        }
        values.emplace(line.substr(0, equal), line.substr(equal + 1));
    }
    if (!sawHeader) {
        AppendCallbackAppLog(L"粘贴失败：不是支持的规则文本格式。");
        return;
    }

    CallbackRule rule;
    rule.id = nextCallbackRuleId_++;
    rule.groupId = ParseUnsigned(values[L"groupId"], CallbackSelectedGroupId());
    if (rule.groupId == 0) {
        rule.groupId = CallbackSelectedGroupId();
    }
    rule.typeIndex = static_cast<int>(ParseUnsigned(values[L"typeIndex"], static_cast<std::uint32_t>(CallbackSelectedRuleTabIndex())));
    if (rule.typeIndex < 0 || rule.typeIndex > 5) {
        rule.typeIndex = std::min(CallbackSelectedRuleTabIndex(), 5);
    }
    rule.enabled = ParseUnsigned(values[L"enabled"], 1) != 0;
    rule.priority = ParseSigned(values[L"priority"], 10 + static_cast<int>(callbackRules_.size()));
    rule.timeoutMs = ParseUnsigned(values[L"timeoutMs"], 5000);
    rule.name = UnescapeConfigField(values[L"ruleName"]);
    if (rule.name.empty()) {
        rule.name = L"规则" + std::to_wstring(rule.id);
    }
    rule.operation = UnescapeConfigField(values[L"operation"]);
    rule.matchMode = UnescapeConfigField(values[L"matchMode"]);
    rule.action = UnescapeConfigField(values[L"action"]);
    rule.timeoutDefault = UnescapeConfigField(values[L"timeoutDefault"]);
    rule.initiatorPattern = UnescapeConfigField(values[L"initiatorPattern"]);
    rule.targetPattern = UnescapeConfigField(values[L"targetPattern"]);
    rule.comment = UnescapeConfigField(values[L"comment"]);
    if (rule.operation.empty()) { rule.operation = L"回调事件"; }
    if (rule.matchMode.empty()) { rule.matchMode = L"通配"; }
    if (rule.action.empty()) { rule.action = L"记录"; }
    if (rule.timeoutDefault.empty()) { rule.timeoutDefault = L"允许"; }
    if (rule.initiatorPattern.empty()) { rule.initiatorPattern = L"*"; }
    if (rule.targetPattern.empty()) { rule.targetPattern = L"*"; }
    if (rule.comment.empty()) { rule.comment = L"粘贴规则"; }

    callbackRules_.push_back(rule);
    RenderCallbackLocalModel();
    AppendCallbackAppLog(L"已从剪贴板粘贴规则：newRuleId=" + std::to_wstring(rule.id));
}

void KernelPage::OnCallbackBypassAdd() {
    // OnCallbackBypassAdd adds PID text from the edit into the bypass table.
    // Input is a comma/semicolon/space separated PID list; output updates table
    // and synchronizes the hidden filter field used by the R0 apply action.
    const std::wstring text = WindowText(callbackBypassPidEdit_);
    std::wstring token;
    std::vector<std::wstring> pids;
    for (const wchar_t ch : text) {
        if (ch == L',' || ch == L';' || ch == L' ' || ch == L'\r' || ch == L'\n' || ch == L'\t') {
            if (!token.empty()) {
                pids.push_back(token);
                token.clear();
            }
        } else {
            token.push_back(ch);
        }
    }
    if (!token.empty()) {
        pids.push_back(token);
    }
    for (const std::wstring& pid : pids) {
        bool exists = false;
        const int rows = callbackBypassList_ ? ListView_GetItemCount(callbackBypassList_) : 0;
        for (int row = 0; row < rows; ++row) {
            if (ListViewText(callbackBypassList_, row, 0) == pid) {
                exists = true;
                break;
            }
        }
        if (!exists) {
            AddListRow(callbackBypassList_, { pid, L"<本地编辑>" });
        }
    }
    std::wstring joined;
    const int rows = callbackBypassList_ ? ListView_GetItemCount(callbackBypassList_) : 0;
    for (int row = 0; row < rows; ++row) {
        const std::wstring pid = ListViewText(callbackBypassList_, row, 0);
        if (pid.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += L",";
        }
        joined += pid;
    }
    ::SetWindowTextW(callbackBypassPidEdit_, joined.c_str());
    ::SetWindowTextW(filterEdit_, joined.c_str());
    if (callbackBypassStatusText_) {
        const std::wstring status = joined.empty()
            ? L"尚未添加 PID；编辑后点击“应用到驱动”生效。"
            : L"已更新本地 PID 放行列表；点击“应用到驱动”后生效。";
        ::SetWindowTextW(callbackBypassStatusText_, status.c_str());
    }
    AppendCallbackAppLog(L"PID 放行列表已更新: " + joined);
}

void KernelPage::OnCallbackBypassRemove() {
    // OnCallbackBypassRemove removes selected PID rows from the bypass table.
    // Input is current ListView selection; output updates table and edit text.
    if (!callbackBypassList_) {
        return;
    }
    int row = -1;
    while ((row = ListView_GetNextItem(callbackBypassList_, -1, LVNI_SELECTED)) >= 0) {
        ListView_DeleteItem(callbackBypassList_, row);
    }
    std::wstring joined;
    const int rows = ListView_GetItemCount(callbackBypassList_);
    for (int index = 0; index < rows; ++index) {
        const std::wstring pid = ListViewText(callbackBypassList_, index, 0);
        if (pid.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined += L",";
        }
        joined += pid;
    }
    ::SetWindowTextW(callbackBypassPidEdit_, joined.c_str());
    ::SetWindowTextW(filterEdit_, joined.c_str());
    if (callbackBypassStatusText_) {
        const std::wstring status = joined.empty()
            ? L"已移除选中 PID；当前本地列表为空。"
            : L"已移除选中 PID；点击“应用到驱动”后生效。";
        ::SetWindowTextW(callbackBypassStatusText_, status.c_str());
    }
    AppendCallbackAppLog(L"已移除选中 PID，当前列表: " + joined);
}

// BuildCallbackModuleFileDetail performs all file metadata, version-resource
// and PE-header reads from an immutable path/row-summary pair. It is called by
// the file-I/O worker and never accesses HWNDs or page state.
std::wstring BuildCallbackModuleFileDetail(
    const std::wstring& modulePath,
    const std::wstring& callbackSummary,
    std::wstring* errorText) {
    WIN32_FILE_ATTRIBUTE_DATA fileData{};
    if (!::GetFileAttributesExW(modulePath.c_str(), GetFileExInfoStandard, &fileData)) {
        if (errorText) {
            *errorText = L"当前回调行没有可访问的模块文件，错误 " + std::to_wstring(::GetLastError());
        }
        return {};
    }

    const ULARGE_INTEGER fileSize{ { fileData.nFileSizeLow, fileData.nFileSizeHigh } };
    const auto fileTimeText = [](const FILETIME& ft) -> std::wstring {
        FILETIME localFt{};
        SYSTEMTIME st{};
        if (!::FileTimeToLocalFileTime(&ft, &localFt) || !::FileTimeToSystemTime(&localFt, &st)) {
            return L"<unknown>";
        }
        std::wostringstream out;
        out << std::setfill(L'0')
            << std::setw(4) << st.wYear << L'-'
            << std::setw(2) << st.wMonth << L'-'
            << std::setw(2) << st.wDay << L' '
            << std::setw(2) << st.wHour << L':'
            << std::setw(2) << st.wMinute << L':'
            << std::setw(2) << st.wSecond;
        return out.str();
    };

    std::wstring versionText;
    const DWORD versionSize = ::GetFileVersionInfoSizeW(modulePath.c_str(), nullptr);
    if (versionSize != 0) {
        std::vector<std::uint8_t> versionBytes(versionSize);
        if (::GetFileVersionInfoW(modulePath.c_str(), 0, versionSize, versionBytes.data())) {
            VS_FIXEDFILEINFO* info = nullptr;
            UINT infoSize = 0;
            if (::VerQueryValueW(versionBytes.data(), L"\\", reinterpret_cast<void**>(&info), &infoSize) && info != nullptr) {
                std::wostringstream version;
                version << HIWORD(info->dwFileVersionMS) << L'.' << LOWORD(info->dwFileVersionMS)
                    << L'.' << HIWORD(info->dwFileVersionLS) << L'.' << LOWORD(info->dwFileVersionLS);
                versionText = version.str();
            }
        }
    }

    std::wstring peText = L"PE: <unavailable>";
    HANDLE file = ::CreateFileW(modulePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file != INVALID_HANDLE_VALUE) {
        std::uint8_t header[4096]{};
        DWORD bytesRead = 0;
        if (::ReadFile(file, header, sizeof(header), &bytesRead, nullptr) && bytesRead >= sizeof(IMAGE_DOS_HEADER)) {
            const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(header);
            if (dos->e_magic == IMAGE_DOS_SIGNATURE && dos->e_lfanew > 0 &&
                static_cast<DWORD>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) <= bytesRead) {
                const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(header + dos->e_lfanew);
                if (nt->Signature == IMAGE_NT_SIGNATURE) {
                    std::wostringstream pe;
                    pe << L"PE Machine=0x" << std::hex << std::uppercase << nt->FileHeader.Machine
                       << L", Sections=" << std::dec << nt->FileHeader.NumberOfSections
                       << L", TimeDateStamp=0x" << std::hex << std::uppercase << nt->FileHeader.TimeDateStamp
                       << L", ImageBase=0x" << nt->OptionalHeader.ImageBase
                       << L", SizeOfImage=0x" << nt->OptionalHeader.SizeOfImage;
                    peText = pe.str();
                }
            }
        }
        ::CloseHandle(file);
    }

    std::wostringstream detail;
    detail << L"模块文件详细信息\r\n"
           << L"----------------------------------------\r\n"
           << L"文件路径: " << modulePath << L"\r\n"
           << L"文件大小: " << fileSize.QuadPart << L" bytes\r\n"
           << L"创建时间: " << fileTimeText(fileData.ftCreationTime) << L"\r\n"
           << L"修改时间: " << fileTimeText(fileData.ftLastWriteTime) << L"\r\n"
           << L"访问时间: " << fileTimeText(fileData.ftLastAccessTime) << L"\r\n"
           << L"版本: " << (versionText.empty() ? L"<unavailable>" : versionText) << L"\r\n"
           << peText << L"\r\n\r\n"
           << callbackSummary;
    return detail.str();
}

// BuildDosPathMapping performs the bounded drive-to-device lookup away from
// the UI thread. It returns display text and an optional plain mapping string
// for the UI thread to place on the clipboard.
std::wstring BuildDosPathMapping(const std::wstring& ntPath, std::wstring* clipboardText) {
    std::vector<wchar_t> drives(32768, L'\0');
    const DWORD chars = ::GetLogicalDriveStringsW(static_cast<DWORD>(drives.size()), drives.data());
    std::wstring mappings;
    for (wchar_t* cursor = drives.data(); chars != 0 && *cursor != L'\0'; cursor += std::wcslen(cursor) + 1) {
        const std::wstring driveRoot(cursor);
        if (driveRoot.size() < 2 || driveRoot[1] != L':') {
            continue;
        }
        const std::wstring driveName = driveRoot.substr(0, 2);
        std::vector<wchar_t> device(4096, L'\0');
        if (::QueryDosDeviceW(driveName.c_str(), device.data(), static_cast<DWORD>(device.size())) == 0) {
            continue;
        }
        const std::wstring devicePath(device.data());
        if (devicePath.empty() || _wcsnicmp(ntPath.c_str(), devicePath.c_str(), devicePath.size()) != 0) {
            continue;
        }
        if (!mappings.empty()) {
            mappings += L"\r\n";
        }
        mappings += driveName + ntPath.substr(devicePath.size());
    }

    if (mappings.empty()) {
        return L"路径: " + ntPath + L"\r\n未找到可用 DOS 路径映射。";
    }
    if (clipboardText) {
        *clipboardText = mappings;
    }
    return L"路径: " + ntPath + L"\r\n已找到 DOS 路径映射（并已复制）:\r\n" + mappings;
}

// SetCallbackFileIoControlsEnabled serializes the import/export surface while a
// filesystem task runs. Other callback views remain inspectable and the worker
// result is discarded automatically if this page closes.
void KernelPage::SetCallbackFileIoControlsEnabled(const bool enabled) {
    for (const HWND control : { callbackImportButton_, callbackExportButton_, callbackExportFileMonitorButton_ }) {
        if (control) {
            ::EnableWindow(control, enabled);
        }
    }
}

// StartCallbackFileIo is the sole callback-rule file I/O entry. Dialog paths
// and immutable text snapshots are captured on the UI thread, while decoding
// and writing execute on AsyncSnapshotTask's worker.
void KernelPage::StartCallbackFileIo(
    const CallbackFileIoOperation operation,
    std::wstring path,
    std::wstring text) {
    if (!callbackFileIoTask_) {
        ::MessageBoxW(hwnd_, L"回调配置文件任务不可用。", L"回调文件操作", MB_OK | MB_ICONWARNING);
        return;
    }
    if (callbackFileIoTask_->running()) {
        AppendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }

    const bool callbackOperation = operation != CallbackFileIoOperation::ExportResultTsv;
    const wchar_t* operationText = operation == CallbackFileIoOperation::ImportConfig
        ? L"正在后台导入回调配置…"
        : operation == CallbackFileIoOperation::ExportConfig
            ? L"正在后台导出回调配置…"
            : operation == CallbackFileIoOperation::ExportFileMonitor
                ? L"正在后台导出文件监控事件…"
                : operation == CallbackFileIoOperation::ExportResultTsv
                    ? L"正在后台导出内核结果 TSV…"
                : operation == CallbackFileIoOperation::CallbackModuleDetail
                    ? L"正在后台读取模块文件详细信息…"
                    : operation == CallbackFileIoOperation::MapNtPath
                        ? L"正在后台映射 DOS 路径…"
                        : L"正在后台打开模块所在目录…";
    ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + operationText).c_str());
    if (callbackOperation) {
        AppendCallbackAppLog(operationText);
        SetCallbackFileIoControlsEnabled(false);
    }
    callbackFileIoTask_->request(
        [operation, path = std::move(path), text = std::move(text)]() mutable {
            CallbackFileIoResult result{};
            result.operation = operation;
            result.path = std::move(path);
            if (operation == CallbackFileIoOperation::ImportConfig) {
                result.text = ReadWholeFileText(result.path, &result.errorText);
            } else if (operation == CallbackFileIoOperation::CallbackModuleDetail) {
                result.text = BuildCallbackModuleFileDetail(result.path, text, &result.errorText);
            } else if (operation == CallbackFileIoOperation::MapNtPath) {
                result.text = BuildDosPathMapping(result.path, &result.clipboardText);
            } else if (operation == CallbackFileIoOperation::OpenModuleFolder) {
                if (::GetFileAttributesW(result.path.c_str()) == INVALID_FILE_ATTRIBUTES) {
                    result.errorText = L"当前回调行没有可访问的模块文件，错误 " + std::to_wstring(::GetLastError());
                } else {
                    const std::wstring parameters = L"/select,\"" + result.path + L"\"";
                    const HINSTANCE launched = ::ShellExecuteW(nullptr, L"open", L"explorer.exe", parameters.c_str(), nullptr, SW_SHOWNORMAL);
                    if (reinterpret_cast<INT_PTR>(launched) <= 32) {
                        result.errorText = L"打开模块所在目录失败。";
                    } else {
                        result.text = L"状态：已打开模块所在目录。";
                    }
                }
            } else if (!WriteWholeFileText(result.path, text, &result.errorText)) {
                result.text.clear();
            }
            return result;
        },
        [this, operation](std::uint64_t, std::optional<CallbackFileIoResult>&& result, std::exception_ptr error) {
            const bool callbackOperation = operation != CallbackFileIoOperation::ExportResultTsv;
            if (callbackOperation) {
                SetCallbackFileIoControlsEnabled(true);
            }
            if (error || !result.has_value()) {
                const wchar_t* title = callbackOperation ? L"回调文件操作" : L"导出 TSV";
                const wchar_t* detail = callbackOperation ? L"回调配置文件后台任务异常结束。" : L"内核结果 TSV 后台导出异常结束。";
                if (callbackOperation) {
                    AppendCallbackAppLog(detail);
                }
                ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + detail).c_str());
                ::MessageBoxW(hwnd_, detail, title, MB_OK | MB_ICONWARNING);
                return;
            }
            ApplyCallbackFileIoResult(std::move(*result));
        });
}

// ApplyCallbackFileIoResult applies the completed immutable worker value. The
// file body has already been read or written, so this code only updates local
// callback models and UI diagnostics.
void KernelPage::ApplyCallbackFileIoResult(CallbackFileIoResult result) {
    const bool callbackOperation = result.operation != CallbackFileIoOperation::ExportResultTsv;
    const wchar_t* title = result.operation == CallbackFileIoOperation::ImportConfig
        ? L"导入配置"
        : result.operation == CallbackFileIoOperation::ExportConfig
            ? L"导出配置"
            : result.operation == CallbackFileIoOperation::ExportFileMonitor
                ? L"导出文件事件"
                : result.operation == CallbackFileIoOperation::ExportResultTsv
                    ? L"导出 TSV"
                : result.operation == CallbackFileIoOperation::CallbackModuleDetail
                    ? L"模块文件详细信息"
                    : result.operation == CallbackFileIoOperation::MapNtPath
                        ? L"DOS 路径映射"
                        : L"打开模块所在目录";
    if (!result.errorText.empty()) {
        if (callbackOperation) {
            AppendCallbackAppLog(std::wstring(title) + L"失败: " + result.errorText);
        }
        ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + title + L"失败: " + result.errorText).c_str());
        ::MessageBoxW(hwnd_, result.errorText.c_str(), title, MB_OK | MB_ICONWARNING);
        return;
    }

    if (result.operation == CallbackFileIoOperation::ImportConfig) {
        std::wstring parseError;
        if (!LoadCallbackLocalConfig(result.text, &parseError)) {
            AppendCallbackAppLog(L"导入配置解析失败: " + parseError);
            ::MessageBoxW(hwnd_, parseError.c_str(), title, MB_OK | MB_ICONWARNING);
            return;
        }
        RenderCallbackLocalModel();
        AppendCallbackAppLog(L"导入配置成功: " + result.path);
        ::SetWindowTextW(statusText_, (std::wstring(L"状态：已导入回调配置: ") + result.path).c_str());
        return;
    }

    if (result.operation == CallbackFileIoOperation::CallbackModuleDetail) {
        ::SetWindowTextW(detailEdit_, result.text.c_str());
        ::SetWindowTextW(statusText_, L"状态：已显示模块文件详细信息。");
        return;
    }

    if (result.operation == CallbackFileIoOperation::MapNtPath) {
        if (!result.clipboardText.empty()) {
            SetClipboardText(hwnd_, result.clipboardText);
        }
        ::SetWindowTextW(detailEdit_, result.text.c_str());
        ::SetWindowTextW(statusText_, L"状态：DOS 路径映射完成。");
        return;
    }

    if (result.operation == CallbackFileIoOperation::OpenModuleFolder) {
        ::SetWindowTextW(statusText_, result.text.c_str());
        return;
    }

    const std::wstring successText = result.operation == CallbackFileIoOperation::ExportConfig
        ? L"导出配置成功: " + result.path
        : result.operation == CallbackFileIoOperation::ExportFileMonitor
            ? L"文件系统事件导出成功: " + result.path
            : L"已导出 TSV: " + result.path;
    if (callbackOperation) {
        AppendCallbackAppLog(successText);
    }
    ::SetWindowTextW(statusText_, (std::wstring(L"状态：") + successText).c_str());
}

void KernelPage::OnCallbackImportConfig() {
    // OnCallbackImportConfig obtains the file path on the UI thread, then
    // delegates decoding and disk I/O to StartCallbackFileIo.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        AppendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"Ksword Rule File (*.kswrules)\0*.kswrules\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!::GetOpenFileNameW(&ofn)) {
        return;
    }
    StartCallbackFileIo(CallbackFileIoOperation::ImportConfig, path);
}

void KernelPage::OnCallbackExportConfig() {
    // OnCallbackExportConfig captures the current model snapshot before the
    // worker writes it, leaving the page responsive during disk activity.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        AppendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH] = L"callback_rules.kswrules";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"Ksword Rule File (*.kswrules)\0*.kswrules\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"kswrules";
    if (!::GetSaveFileNameW(&ofn)) {
        return;
    }
    StartCallbackFileIo(CallbackFileIoOperation::ExportConfig, path, SerializeCallbackLocalConfig());
}

void KernelPage::OnCallbackExportFileMonitor() {
    // OnCallbackExportFileMonitor snapshots the visible table before the worker
    // writes it. The UI read is bounded to the current list contents and disk
    // I/O does not run in this command handler.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        AppendCallbackAppLog(L"回调配置文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH] = L"callback_file_monitor.tsv";
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"TSV (*.tsv)\0*.tsv\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"tsv";
    if (!::GetSaveFileNameW(&ofn)) {
        return;
    }
    std::wstring text;
    const int rows = callbackFileMonitorList_ ? ListView_GetItemCount(callbackFileMonitorList_) : 0;
    const int columns = callbackFileMonitorList_ ? HeaderColumnCount(callbackFileMonitorList_) : 0;
    for (int row = 0; row < rows; ++row) {
        if (row > 0) {
            text += L"\r\n";
        }
        for (int column = 0; column < columns; ++column) {
            if (column > 0) {
                text += L'\t';
            }
            text += ListViewText(callbackFileMonitorList_, row, column);
        }
    }
    StartCallbackFileIo(CallbackFileIoOperation::ExportFileMonitor, path, std::move(text));
}

void KernelPage::OpenCallbackFileMonitorProcess() {
    // File-monitor rows carry an observed PID but not a creation-time identity.
    // Route it as the current PID so a terminated/reused process is never
    // presented as a guaranteed historical event owner.
    const int row = callbackFileMonitorList_
        ? ListView_GetNextItem(callbackFileMonitorList_, -1, LVNI_SELECTED)
        : -1;
    std::uint64_t processId = 0;
    if (row < 0 || !ParseUnsigned64Value(ListViewText(callbackFileMonitorList_, row, kCallbackFileMonitorPidColumn), processId) ||
        processId == 0U || processId > static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)())) {
        AppendCallbackAppLog(L"所选文件监控行没有可导航的当前 PID。");
        return;
    }

    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::ProcessDetails;
    request.entity.kind = Ksword::Core::EntityKind::Process;
    request.entity.id = processId;
    const bool routed = Ksword::Ui::RequestEntityNavigation(hwnd_, request);
    AppendCallbackAppLog(routed
        ? L"已请求打开文件监控事件的当前 PID " + std::to_wstring(processId) + L"；历史归属会重新校验。"
        : L"无法导航到文件监控事件的当前进程实例。");
}

void KernelPage::OpenCallbackFileMonitorPath() {
    // Only hand the File browser the containing directory of an event path it
    // can interpret without a lossy kernel-to-DOS conversion. The event stays
    // display-only when the driver did not confirm that the path is complete.
    const int row = callbackFileMonitorList_
        ? ListView_GetNextItem(callbackFileMonitorList_, -1, LVNI_SELECTED)
        : -1;
    const std::wstring path = row >= 0
        ? ListViewText(callbackFileMonitorList_, row, kCallbackFileMonitorPathColumn)
        : std::wstring{};
    const std::wstring directory = row >= 0 &&
        ListViewText(callbackFileMonitorList_, row, kCallbackFileMonitorPathStateColumn) == L"完整"
        ? FileMonitorContainingDirectory(path)
        : std::wstring{};
    if (directory.empty()) {
        AppendCallbackAppLog(L"所选文件监控路径未确认完整或不是可打开的 DOS/UNC 路径；已保留原始事件文本。");
        return;
    }

    Ksword::Core::NavigationRequest request{};
    request.target = Ksword::Core::NavigationTarget::FileBrowser;
    request.entity.kind = Ksword::Core::EntityKind::File;
    request.entity.text = directory;
    const bool routed = Ksword::Ui::RequestEntityNavigation(hwnd_, request);
    AppendCallbackAppLog(routed
        ? L"已在文件模块打开文件监控路径所在目录。"
        : L"文件模块当前无法接收该文件监控路径所在目录。");
}

void KernelPage::CopyCallbackPanelSelection(HWND source) {
    // CopyCallbackPanelSelection copies rows from the active CallbackIntercept
    // sub-table. Input is the focused/context ListView; processing falls back to
    // the last context source; output places selected rows with headers on the
    // clipboard and writes a short app-log line.
    HWND list = source;
    if (list != callbackGroupList_ &&
        list != callbackBypassList_ &&
        list != callbackFileMonitorList_ &&
        std::find(callbackRuleLists_.begin(), callbackRuleLists_.end(), list) == callbackRuleLists_.end()) {
        list = callbackContextList_;
    }
    if (!list) {
        AppendCallbackAppLog(L"没有可复制的 CallbackIntercept 表格。");
        return;
    }
    std::wstring text = BuildListViewSelectionTsv(list, true);
    if (text.empty()) {
        const int rows = ListView_GetItemCount(list);
        if (rows > 0) {
            ListView_SetItemState(list, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            text = BuildListViewSelectionTsv(list, true);
        }
    }
    if (text.empty()) {
        AppendCallbackAppLog(L"当前表格没有可复制的选中行。");
        return;
    }
    SetClipboardText(hwnd_, text);
    AppendCallbackAppLog(L"已复制 CallbackIntercept 表格选中行。");
}

void KernelPage::ShowCallbackInterceptContextMenu(HWND source, POINT screenPoint) {
    // ShowCallbackInterceptContextMenu mirrors the original CallbackIntercept
    // right-click workflow for groups, rules, PID bypass and file-monitor rows.
    // Inputs are the source ListView and screen coordinates; output is a modal
    // popup whose commands dispatch through WM_COMMAND.
    if (!source) {
        return;
    }
    callbackContextList_ = source;
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int selected = ListView_GetNextItem(source, -1, LVNI_SELECTED);
        if (selected >= 0 && ListView_GetItemRect(source, selected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(source, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(source, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int row = ListView_HitTest(source, &hit);
        if (row >= 0) {
            const UINT state = ListView_GetItemState(source, row, LVIS_SELECTED);
            if ((state & LVIS_SELECTED) == 0) {
                ListView_SetItemState(source, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(source, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(source, row, FALSE);
        }
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool hasSelection = ListView_GetNextItem(source, -1, LVNI_SELECTED) >= 0;
    bool appendCopySelection = false;
    if (source == callbackGroupList_) {
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackGroupAdd, L"新增规则组");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupToggleEnabled, L"切换规则组启用");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupRename, L"重命名规则组");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupRemove, L"删除规则组");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupMoveUp, L"规则组上移");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackGroupMoveDown, L"规则组下移");
        appendCopySelection = true;
    } else if (std::find(callbackRuleLists_.begin(), callbackRuleLists_.end(), source) != callbackRuleLists_.end()) {
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackRuleAdd, L"新增规则");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleToggleEnabled, L"切换规则启用");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleRemove, L"删除规则");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleMoveUp, L"规则上移");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleMoveDown, L"规则下移");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackRuleCopyText, L"复制规则文本");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackRulePasteNew, L"粘贴为新规则");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackGroupAdd, L"新增规则组");
        appendCopySelection = false;
    } else if (source == callbackBypassList_) {
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassAdd, L"添加 PID 到本地列表");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackBypassRemove, L"移除选中 PID");
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassApply, L"应用 PID 放行到驱动");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassClear, L"清空驱动 PID 放行");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackBypassRefresh, L"从驱动刷新 PID 放行");
        appendCopySelection = true;
    } else if (source == callbackFileMonitorList_) {
        const int selected = hasSelection ? ListView_GetNextItem(source, -1, LVNI_SELECTED) : -1;
        std::uint64_t processId = 0;
        const bool canOpenProcess = selected >= 0 &&
            ParseUnsigned64Value(ListViewText(source, selected, kCallbackFileMonitorPidColumn), processId) &&
            processId != 0U && processId <= static_cast<std::uint64_t>((std::numeric_limits<DWORD>::max)());
        const bool canOpenPath = selected >= 0 &&
            ListViewText(source, selected, kCallbackFileMonitorPathStateColumn) == L"完整" &&
            !FileMonitorContainingDirectory(ListViewText(source, selected, kCallbackFileMonitorPathColumn)).empty();
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorStart, L"启动/补充 FSCTL 文件监控");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorDrain, L"拉取文件监控事件");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorClear, L"清空当前文件事件");
        ::AppendMenuW(menu, MF_STRING, kMenuCallbackFileMonitorExport, L"导出当前文件事件");
        HMENU investigationMenu = ::CreatePopupMenu();
        if (investigationMenu) {
            ::AppendMenuW(investigationMenu, MF_STRING | (canOpenProcess ? MF_ENABLED : MF_GRAYED),
                kMenuCallbackFileMonitorOpenProcess, L"打开所属进程详细信息");
            ::AppendMenuW(investigationMenu, MF_STRING | (canOpenPath ? MF_ENABLED : MF_GRAYED),
                kMenuCallbackFileMonitorOpenPath, L"在文件模块查看所在目录");
            ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(investigationMenu), L"关联调查");
        }
        appendCopySelection = true;
    } else {
        ::DestroyMenu(menu);
        return;
    }
    if (appendCopySelection) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCallbackCopyPanelSelection, L"复制选中行（含表头）");
    }
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
}

std::wstring KernelPage::SerializeCallbackLocalConfig() const {
    // SerializeCallbackLocalConfig converts local callback groups/rules into a
    // stable tab-separated text format. There is no input; output can be saved
    // as .kswrules and later imported by this lightweight editor.
    std::wostringstream out;
    out << L"KSWORD_ARKLIGHT_CALLBACK_RULES_V1\r\n";
    out << L"GLOBAL\t" << (CallbackRulesGlobalEnabled() ? 1 : 0) << L"\r\n";
    for (const CallbackRuleGroup& group : callbackGroups_) {
        out << L"GROUP\t"
            << group.id << L'\t'
            << (group.enabled ? 1 : 0) << L'\t'
            << group.priority << L'\t'
            << EscapeConfigField(group.name) << L'\t'
            << EscapeConfigField(group.comment) << L"\r\n";
    }
    for (const CallbackRule& rule : callbackRules_) {
        out << L"RULE\t"
            << rule.id << L'\t'
            << rule.groupId << L'\t'
            << rule.typeIndex << L'\t'
            << (rule.enabled ? 1 : 0) << L'\t'
            << rule.priority << L'\t'
            << rule.timeoutMs << L'\t'
            << EscapeConfigField(rule.name) << L'\t'
            << EscapeConfigField(rule.operation) << L'\t'
            << EscapeConfigField(rule.matchMode) << L'\t'
            << EscapeConfigField(rule.action) << L'\t'
            << EscapeConfigField(rule.timeoutDefault) << L'\t'
            << EscapeConfigField(rule.initiatorPattern) << L'\t'
            << EscapeConfigField(rule.targetPattern) << L'\t'
            << EscapeConfigField(rule.comment) << L"\r\n";
    }
    return out.str();
}

bool KernelPage::CallbackRulesGlobalEnabled() const {
    // CallbackRulesGlobalEnabled reads the original CallbackIntercept global
    // enable checkbox. There is no input; output controls the globalFlags field
    // in the serialized local rule document consumed by KernelFacade.
    return callbackGlobalEnabledCheck_ == nullptr || Button_GetCheck(callbackGlobalEnabledCheck_) == BST_CHECKED;
}

bool KernelPage::LoadCallbackLocalConfig(const std::wstring& text, std::wstring* errorText) {
    // LoadCallbackLocalConfig parses the lightweight tab-separated rule format.
    // Input is a complete text file; output updates local vectors and reports
    // false with an error string on malformed mandatory fields.
    std::vector<CallbackRuleGroup> groups;
    std::vector<CallbackRule> rules;
    std::uint32_t maxGroupId = 0;
    std::uint32_t maxRuleId = 0;
    std::wistringstream input(text);
    std::wstring line;
    bool sawHeader = false;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == L'\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if (!sawHeader) {
            if (line != L"KSWORD_ARKLIGHT_CALLBACK_RULES_V1") {
                if (errorText) {
                    *errorText = L"配置头不匹配，无法导入。";
                }
                return false;
            }
            sawHeader = true;
            continue;
        }
        const std::vector<std::wstring> fields = SplitTabLine(line);
        if (fields.empty()) {
            continue;
        }
        if (fields[0] == L"GLOBAL") {
            if (fields.size() >= 2 && callbackGlobalEnabledCheck_ != nullptr) {
                Button_SetCheck(callbackGlobalEnabledCheck_, ParseUnsigned(fields[1], 1) != 0 ? BST_CHECKED : BST_UNCHECKED);
            }
        } else if (fields[0] == L"GROUP") {
            if (fields.size() < 6) {
                if (errorText) {
                    *errorText = L"GROUP 行字段不足。";
                }
                return false;
            }
            CallbackRuleGroup group;
            group.id = ParseUnsigned(fields[1], 0);
            group.enabled = ParseUnsigned(fields[2], 0) != 0;
            group.priority = ParseSigned(fields[3], 10);
            group.name = UnescapeConfigField(fields[4]);
            group.comment = UnescapeConfigField(fields[5]);
            if (group.id == 0) {
                if (errorText) {
                    *errorText = L"GROUP id 非法。";
                }
                return false;
            }
            maxGroupId = std::max(maxGroupId, group.id);
            groups.push_back(group);
        } else if (fields[0] == L"RULE") {
            if (fields.size() < 13) {
                if (errorText) {
                    *errorText = L"RULE 行字段不足。";
                }
                return false;
            }
            CallbackRule rule;
            rule.id = ParseUnsigned(fields[1], 0);
            rule.groupId = ParseUnsigned(fields[2], 0);
            rule.typeIndex = ParseSigned(fields[3], 0);
            rule.enabled = ParseUnsigned(fields[4], 0) != 0;
            rule.priority = ParseSigned(fields[5], 10);
            rule.timeoutMs = ParseUnsigned(fields[6], 0);
            rule.name = UnescapeConfigField(fields[7]);
            rule.operation = UnescapeConfigField(fields[8]);
            rule.matchMode = UnescapeConfigField(fields[9]);
            rule.action = UnescapeConfigField(fields[10]);
            rule.timeoutDefault = UnescapeConfigField(fields[11]);
            if (fields.size() >= 15) {
                rule.initiatorPattern = UnescapeConfigField(fields[12]);
                rule.targetPattern = UnescapeConfigField(fields[13]);
                rule.comment = UnescapeConfigField(fields[14]);
            } else {
                rule.initiatorPattern = L"*";
                rule.targetPattern = L"*";
                rule.comment = UnescapeConfigField(fields[12]);
            }
            if (rule.id == 0 || rule.groupId == 0 || rule.typeIndex < 0 || rule.typeIndex > 5) {
                if (errorText) {
                    *errorText = L"RULE id/group/type 非法。";
                }
                return false;
            }
            maxRuleId = std::max(maxRuleId, rule.id);
            rules.push_back(rule);
        }
    }
    if (!sawHeader) {
        if (errorText) {
            *errorText = L"空配置或缺少头。";
        }
        return false;
    }
    if (groups.empty()) {
        groups.push_back({ 1, L"默认组", true, 10, L"导入文件未包含组，自动创建。" });
        maxGroupId = 1;
    }
    callbackGroups_ = std::move(groups);
    callbackRules_ = std::move(rules);
    nextCallbackGroupId_ = maxGroupId + 1;
    nextCallbackRuleId_ = maxRuleId + 1;
    return true;
}

std::uint32_t KernelPage::CurrentIncludeFlags() const {
    // CurrentIncludeFlags reads the Hook include combo. Input is the selected
    // combo item; processing returns the item data only on pages that use it;
    // output is KernelRequest::flags consumed by KernelFacade.
    if (!includeCombo_) {
        return 0;
    }
    const int selection = static_cast<int>(::SendMessageW(includeCombo_, CB_GETCURSEL, 0, 0));
    if (selection < 0) {
        return 0;
    }
    const LRESULT data = ::SendMessageW(includeCombo_, CB_GETITEMDATA, static_cast<WPARAM>(selection), 0);
    if (data == CB_ERR) {
        return 0;
    }
    return static_cast<std::uint32_t>(data);
}

void KernelPage::UpdateSummaryTableFromRows() {
    // UpdateSummaryTableFromRows mirrors original DynData/DriverStatus summary
    // tables. Inputs are current cached rows and columns; processing extracts
    // the first few non-detail summary rows into a 项目/值 list; output updates
    // summaryList_ without changing the main result table.
    if (!summaryList_) {
        return;
    }
    ListView_DeleteAllItems(summaryList_);
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr) {
        return;
    }
    const KernelPageLayoutKind kind = LayoutKindForFeature(descriptor->id);
    if (kind != KernelPageLayoutKind::DualTable && kind != KernelPageLayoutKind::RuntimePanel) {
        return;
    }
    const auto valueFromRow = [](const std::vector<std::wstring>& row, const std::vector<std::wstring>& columns, std::initializer_list<const wchar_t*> names) -> std::wstring {
        for (const wchar_t* name : names) {
            for (std::size_t column = 0; column < columns.size() && column < row.size(); ++column) {
                if (_wcsicmp(columns[column].c_str(), name) == 0 && !row[column].empty()) {
                    return row[column];
                }
            }
        }
        return {};
    };
    const auto appendSummary = [&](int& rowIndex, const std::wstring& name, const std::wstring& value) {
        if (name.empty() || value.empty()) {
            return;
        }
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = rowIndex;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(name.c_str());
        const int inserted = ListView_InsertItem(summaryList_, &item);
        if (inserted >= 0) {
            ListView_SetItemText(summaryList_, inserted, 1, const_cast<LPWSTR>(value.c_str()));
            ++rowIndex;
        }
    };
    if (descriptor->id == KernelFeatureId::DynData) {
        int rowIndex = 0;
        int profileRows = 0;
        int fieldRows = 0;
        int failedRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring field = valueFromRow(row, currentColumns_, { L"Field", L"字段" });
            const std::wstring source = valueFromRow(row, currentColumns_, { L"Source", L"来源" });
            const std::wstring status = valueFromRow(row, currentColumns_, { L"Status", L"状态", L"DynData Fields IO" });
            if (!field.empty()) {
                ++fieldRows;
            }
            if (source.find(L"Profile") != std::wstring::npos || source.find(L"Pack") != std::wstring::npos) {
                ++profileRows;
            }
            if (status.find(L"FAIL") != std::wstring::npos || status.find(L"失败") != std::wstring::npos) {
                ++failedRows;
            }
        }
        for (const std::vector<std::wstring>& row : currentRows_) {
            appendSummary(rowIndex, L"状态标志", valueFromRow(row, currentColumns_, { L"StatusFlags" }));
            appendSummary(rowIndex, L"System Informer 版本", valueFromRow(row, currentColumns_, { L"SI Version" }));
            appendSummary(rowIndex, L"System Informer 长度", valueFromRow(row, currentColumns_, { L"SI Length" }));
            appendSummary(rowIndex, L"匹配 Profile Class", valueFromRow(row, currentColumns_, { L"MatchedClass" }));
            appendSummary(rowIndex, L"驱动字段数", valueFromRow(row, currentColumns_, { L"FieldCount" }));
            appendSummary(rowIndex, L"能力掩码", valueFromRow(row, currentColumns_, { L"CapabilityMask" }));
            appendSummary(rowIndex, L"ntoskrnl", valueFromRow(row, currentColumns_, { L"Ntos" }));
            appendSummary(rowIndex, L"lxcore", valueFromRow(row, currentColumns_, { L"Lxcore" }));
            appendSummary(rowIndex, L"字段 IO", valueFromRow(row, currentColumns_, { L"DynData Fields IO" }));
            appendSummary(rowIndex, L"字段总数", valueFromRow(row, currentColumns_, { L"FieldsTotal" }));
            appendSummary(rowIndex, L"字段返回数", valueFromRow(row, currentColumns_, { L"FieldsReturned" }));
            if (rowIndex >= 10) {
                break;
            }
        }
        appendSummary(rowIndex, L"可见字段行", std::to_wstring(fieldRows));
        appendSummary(rowIndex, L"Profile/Pack 诊断行", std::to_wstring(profileRows));
        appendSummary(rowIndex, L"失败诊断行", std::to_wstring(failedRows));
        return;
    }
    if (descriptor->id == KernelFeatureId::DriverStatus) {
        int rowIndex = 0;
        int featureRows = 0;
        int unavailableRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring feature = valueFromRow(row, currentColumns_, { L"Feature", L"功能" });
            const std::wstring state = valueFromRow(row, currentColumns_, { L"State", L"状态" });
            if (!feature.empty()) {
                ++featureRows;
            }
            if (state.find(L"Unavailable") != std::wstring::npos || state.find(L"Disabled") != std::wstring::npos || state.find(L"不可用") != std::wstring::npos) {
                ++unavailableRows;
            }
        }
        for (const std::vector<std::wstring>& row : currentRows_) {
            appendSummary(rowIndex, L"能力版本", valueFromRow(row, currentColumns_, { L"Version" }));
            appendSummary(rowIndex, L"协议版本", valueFromRow(row, currentColumns_, { L"Protocol" }));
            appendSummary(rowIndex, L"状态标志", valueFromRow(row, currentColumns_, { L"StatusFlags" }));
            appendSummary(rowIndex, L"安全策略", valueFromRow(row, currentColumns_, { L"SecurityPolicy" }));
            appendSummary(rowIndex, L"DynData 状态", valueFromRow(row, currentColumns_, { L"DynDataStatus" }));
            appendSummary(rowIndex, L"功能总数", valueFromRow(row, currentColumns_, { L"FeatureTotal" }));
            appendSummary(rowIndex, L"功能返回数", valueFromRow(row, currentColumns_, { L"FeatureReturned" }));
            appendSummary(rowIndex, L"最后错误来源", valueFromRow(row, currentColumns_, { L"LastError" }));
            if (rowIndex >= 8) {
                break;
            }
        }
        appendSummary(rowIndex, L"可见能力行", std::to_wstring(featureRows));
        appendSummary(rowIndex, L"不可用/禁用行", std::to_wstring(unavailableRows));
        return;
    }
    int outRow = 0;
    const std::size_t maxRows = std::min<std::size_t>(currentRows_.size(), 8);
    for (std::size_t rowIndex = 0; rowIndex < maxRows; ++rowIndex) {
        const std::vector<std::wstring>& row = currentRows_[rowIndex];
        for (std::size_t column = 1; column < currentColumns_.size() && column < row.size(); ++column) {
            if (row[column].empty()) {
                continue;
            }
            const std::wstring& name = currentColumns_[column];
            if (name == L"Detail" || name == L"功能" || name == L"原因" ||
                (name == L"状态" && kind != KernelPageLayoutKind::RuntimePanel)) {
                continue;
            }
            if (kind == KernelPageLayoutKind::RuntimePanel &&
                name != L"Section" &&
                name != L"RegisteredText" &&
                name != L"Pending" &&
                name != L"PendingDecisions" &&
                name != L"WaitingReceivers" &&
                name != L"RuleVersion" &&
                name != L"AppliedTime" &&
                name != L"Status" &&
                name != L"Type" &&
                name != L"Enabled") {
                continue;
            }
            LVITEMW item{};
            item.mask = LVIF_TEXT;
            item.iItem = outRow;
            item.iSubItem = 0;
            item.pszText = const_cast<LPWSTR>(name.c_str());
            const int inserted = ListView_InsertItem(summaryList_, &item);
            if (inserted >= 0) {
                ListView_SetItemText(summaryList_, inserted, 1, const_cast<LPWSTR>(row[column].c_str()));
                ++outRow;
            }
            if (outRow >= 64) {
                return;
            }
        }
    }
}

void KernelPage::UpdatePropertyTableFromSelection() {
    // UpdatePropertyTableFromSelection mirrors the original object namespace
    // property table. Inputs are either the selected object row or the selected
    // synthetic tree node; processing emits the same fixed fields as the Qt
    // KernelDock; output is propertyList_ content.
    if (!propertyList_) {
        return;
    }
    ListView_DeleteAllItems(propertyList_);
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr || LayoutKindForFeature(descriptor->id) != KernelPageLayoutKind::TreeWithPropertyTable) {
        return;
    }
    int propertyRow = 0;
    const auto appendProperty = [&](const std::wstring& name, const std::wstring& value) {
        if (name.empty()) {
            return;
        }
        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = propertyRow;
        item.iSubItem = 0;
        item.pszText = const_cast<LPWSTR>(name.c_str());
        const int inserted = ListView_InsertItem(propertyList_, &item);
        if (inserted >= 0) {
            ListView_SetItemText(propertyList_, inserted, 1, const_cast<LPWSTR>(value.c_str()));
            ++propertyRow;
        }
    };
    const auto safeText = [](const std::wstring& value, const wchar_t* fallback = L"<空>") -> std::wstring {
        return value.empty() ? std::wstring(fallback) : value;
    };
    const auto cellAt = [&](const int row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        if (!resultList_ || row < 0) {
            return {};
        }
        for (const wchar_t* name : names) {
            for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
                if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), name) == 0) {
                    const std::wstring value = VisibleCellText(row, column);
                    if (!value.empty()) {
                        return value;
                    }
                }
            }
        }
        return {};
    };
    const int row = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    const std::wstring selectedNodeKind = row >= 0 ? cellAt(row, { L"NodeKind" }) : objectNamespaceSelectedKind_;
    const bool syntheticNode = row < 0 ||
        _wcsicmp(selectedNodeKind.c_str(), L"Root") == 0 ||
        _wcsicmp(selectedNodeKind.c_str(), L"Directory") == 0;
    if (syntheticNode) {
        const std::wstring nodeName = row >= 0
            ? cellAt(row, { L"名称", L"Name" })
            : objectNamespaceSelectedPath_;
        const std::wstring nodeType = row >= 0
            ? cellAt(row, { L"类型", L"Type" })
            : objectNamespaceSelectedKind_;
        const std::wstring nodePath = row >= 0
            ? cellAt(row, { L"Path", L"完整路径", L"fullPath", L"路径/说明", L"Source", L"Parent" })
            : objectNamespaceSelectedPath_;
        const std::wstring nodeDescription = row >= 0
            ? cellAt(row, { L"Detail", L"scopeDescriptionText", L"Scope", L"scope", L"路径/说明" })
            : objectNamespaceSelectedDescription_;
        appendProperty(L"节点名称", safeText(nodeName));
        appendProperty(L"节点类型", safeText(nodeType));
        appendProperty(L"节点路径", safeText(nodePath, L"<无>"));
        appendProperty(L"节点说明", safeText(nodeDescription, L"<无>"));
        appendProperty(L"提示", L"当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。");
        return;
    }

    appendProperty(L"rootPathText（根目录）", safeText(cellAt(row, { L"rootPathText", L"Root", L"Source" })));
    appendProperty(L"scopeDescriptionText（作用说明）", safeText(cellAt(row, { L"scopeDescriptionText", L"Scope", L"scope", L"Detail", L"路径/说明" })));
    appendProperty(L"directoryPathText（当前目录）", safeText(cellAt(row, { L"directoryPathText", L"directoryPath", L"Directory", L"Parent", L"来源目录" })));
    appendProperty(L"objectNameText（对象名）", safeText(cellAt(row, { L"objectNameText", L"objectName", L"Name", L"名称" })));
    appendProperty(L"objectTypeText（对象类型）", safeText(cellAt(row, { L"objectTypeText", L"objectType", L"Type", L"类型" })));
    appendProperty(L"fullPathText（完整路径）", safeText(cellAt(row, { L"fullPathText", L"fullPath", L"Path", L"完整路径", L"路径/说明" })));
    appendProperty(L"enumApiText（枚举API）", safeText(cellAt(row, { L"enumApiText", L"enumApi", L"EnumApi", L"枚举 API", L"EnumerationApi" })));
    appendProperty(L"symbolicLinkTargetText（符号链接目标）", safeText(cellAt(row, { L"symbolicLinkTargetText", L"symbolicTarget", L"Target", L"targetPath", L"符号链接目标" }), L"<无>"));
    appendProperty(L"statusText（状态）", safeText(cellAt(row, { L"statusText", L"Status", L"状态" })));
    appendProperty(L"statusCode（NTSTATUS）", safeText(cellAt(row, { L"statusCode", L"StatusCode", L"NTSTATUS", L"LastStatus" }), L"0x00000000"));
    appendProperty(L"querySucceeded（查询成功）", safeText(cellAt(row, { L"querySucceeded", L"QuerySucceeded" }), L"<未知>"));
    appendProperty(L"isDirectory（是否目录）", safeText(cellAt(row, { L"isDirectory", L"IsDirectory" }), _wcsicmp(cellAt(row, { L"类型", L"Type", L"objectType" }).c_str(), L"Directory") == 0 ? L"true" : L"false"));
    appendProperty(L"isSymbolicLink（是否符号链接）", safeText(cellAt(row, { L"isSymbolicLink", L"IsSymbolicLink" }), _wcsicmp(cellAt(row, { L"类型", L"Type", L"objectType" }).c_str(), L"SymbolicLink") == 0 ? L"true" : L"false"));
    appendProperty(L"详情", safeText(cellAt(row, { L"Detail" }), L"<无>"));
    const int columns = HeaderColumnCount(resultList_);
    for (int column = 0; column < columns; ++column) {
        const std::wstring name = column < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(column)]
            : std::wstring(L"Column ") + std::to_wstring(column);
        const std::wstring value = VisibleCellText(row, column);
        if (name.empty() || value.empty()) {
            continue;
        }
        bool alreadyShown = false;
        for (int existing = 0; existing < propertyRow; ++existing) {
            if (_wcsicmp(ListViewText(propertyList_, existing, 0).c_str(), name.c_str()) == 0) {
                alreadyShown = true;
                break;
            }
        }
        if (!alreadyShown) {
            appendProperty(name, value);
        }
    }
}

void KernelPage::ShowResultContextMenu(POINT screenPoint) {
    // ShowResultContextMenu exposes copy operations for real kernel rows.
    // Inputs are screen coordinates from WM_CONTEXTMENU; processing creates a
    // short-lived Win32 popup; no value is returned.
    if (!resultList_) {
        return;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int selected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (selected >= 0 && ListView_GetItemRect(resultList_, selected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::NtQueryLegacy &&
        ShowNtQueryContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::AtomTable &&
        ShowAtomTableContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::DeviceDriverObjects &&
        ShowDeviceDriverObjectsContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::BaseNamedObjects &&
        ShowSimpleObjectTableContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::ObjectNamespaceOverview &&
        ShowObjectNamespaceOverviewContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::ObjectDirectoryRecursive &&
        ShowObjectDirectoryRecursiveContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::NamedPipe &&
        ShowNamedPipeContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::SymbolicLink &&
        ShowSymbolicLinkContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::ObjectTypeMatrix &&
        ShowObjectTypeMatrixContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::CommunicationEndpoint &&
        ShowCommunicationEndpointContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && IsObjectNamespaceFeature(descriptor->id) &&
        ShowObjectNamespaceContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && IsKernelHookFeature(descriptor->id)) {
        if (descriptor->id == KernelFeatureId::Ssdt) {
            // The original SSDT tab only refreshes/selects rows; unlike
            // SSSDT/Inline/IAT-EAT it does not attach a row popup. Swallow the
            // Win32 context message here so the generic kernel menu does not
            // create extra actions that never existed in KswordARK.
            ::DestroyMenu(menu);
            return;
        }
        if (ShowKernelHookContextMenu(screenPoint, *descriptor)) {
            ::DestroyMenu(menu);
            return;
        }
    }
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackEnumeration &&
        ShowCallbackEnumerationContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DynData ||
            descriptor->id == KernelFeatureId::DriverStatus)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr && IsR0OriginalNoPopupFeature(descriptor->id)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::MutationAudit ||
            descriptor->id == KernelFeatureId::MinifilterBypassPids) &&
        ShowR0EvidenceContextMenu(screenPoint, *descriptor)) {
        ::DestroyMenu(menu);
        return;
    }
    if (descriptor != nullptr) {
        std::wstring refreshText = L"刷新当前页";
        ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, refreshText.c_str());
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    }
    const bool canCopyDiagnostic = descriptor != nullptr &&
        (descriptor->id == KernelFeatureId::DynData || descriptor->id == KernelFeatureId::DriverStatus);
    const int visibleColumns = HeaderColumnCount(resultList_);
    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyCell, L"复制当前列（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyRow, L"复制当前行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopySelectedRows, L"复制选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopySelectedRowsWithHeader, L"复制表头+选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyAll, L"复制全部结果");
        ::AppendMenuW(copyMenu, MF_STRING, kMenuCopySelectedDetails, L"复制详情（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING | (canCopyDiagnostic ? MF_ENABLED : MF_GRAYED), kMenuCopyDiagnosticReport, L"复制诊断报告");
        HMENU columnMenu = ::CreatePopupMenu();
        if (columnMenu != nullptr) {
            for (int column = 0; column < visibleColumns && column < static_cast<int>(currentColumns_.size()) && column < static_cast<int>(kMenuCopyColumnMax - kMenuCopyColumnBase); ++column) {
                const std::wstring& columnName = currentColumns_[static_cast<std::size_t>(column)];
                ::AppendMenuW(columnMenu, MF_STRING, kMenuCopyColumnBase + static_cast<UINT_PTR>(column), columnName.c_str());
            }
            ::AppendMenuW(copyMenu, MF_POPUP | (visibleColumns > 0 ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(columnMenu), L"复制指定栏目（选中行）");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    ::AppendMenuW(menu, MF_STRING, kMenuExportAllTsv, L"导出全部 TSV");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING, kMenuShowRowDialog, L"查看当前行详情");
    const bool hasModule = !FirstSelectedRowField({ L"Module", L"ModulePath", L"OwnerModule", L"Owner", L"Import" }).empty();
    const bool hasTargetModule = !FirstSelectedRowField({ L"TargetModule", L"OwnerModule", L"Module", L"ModulePath", L"Owner", L"Import" }).empty();
    const bool hasAddress = !FirstSelectedRowField({
        L"Address",
        L"Target",
        L"Service",
        L"Zw",
        L"Current",
        L"Expected",
        L"VA",
        L"Object",
        L"ThreadObject",
        L"ProcessObject",
        L"DriverObject",
        L"DeviceObject",
        L"Callback",
        L"Registration",
    }).empty();
    ::AppendMenuW(menu, MF_STRING | (hasModule ? MF_ENABLED : MF_GRAYED), kMenuFilterByModule, L"按当前行模块重查");
    ::AppendMenuW(menu, MF_STRING | (hasTargetModule ? MF_ENABLED : MF_GRAYED), kMenuFilterByTargetModule, L"按目标模块重查");
    ::AppendMenuW(menu, MF_STRING | (hasAddress ? MF_ENABLED : MF_GRAYED), kMenuFilterByAddress, L"按地址/对象过滤");

    if (descriptor != nullptr) {
        if (descriptor->id == KernelFeatureId::CallbackIntercept) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuCallbackCancelPendingDecisions, L"取消全部等待决策");
            ::AppendMenuW(menu, MF_STRING, kMenuCallbackApplyDisabledEmptyRules, L"应用禁用空规则集");
        } else if (descriptor->id == KernelFeatureId::MinifilterBypassPids) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuMinifilterSetBypass, L"设置放行 PID（过滤/起点）");
            ::AppendMenuW(menu, MF_STRING, kMenuMinifilterClearBypass, L"清空放行 PID");
        } else if (descriptor->id == KernelFeatureId::NetworkTrafficPackets) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStart, L"启动逐包捕获");
            ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStop, L"停止逐包捕获");
        } else if (descriptor->id == KernelFeatureId::PiDdbCache) {
            const bool hasEntry = !FirstSelectedRowField({ L"Entry", L"条目地址" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (hasEntry ? MF_ENABLED : MF_GRAYED), kMenuPiDdbDeleteEntry, L"删除选中 PiDDB 条目");
        } else if (descriptor->id == KernelFeatureId::DriverDispatchTable) {
            const bool hasTarget = !FirstSelectedRowField({ L"ModuleBase" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchRestore, L"恢复派遣槽为原值");
            ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchAbandon, L"放弃派遣恢复记录");
        } else if (descriptor->id == KernelFeatureId::DriverImageFields) {
            const bool hasTarget = !FirstSelectedRowField({ L"ModuleBase" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageRestore, L"恢复镜像字段为原值");
            ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageAbandon, L"放弃镜像恢复记录");
        } else if (descriptor->id == KernelFeatureId::DriverCommunication) {
            const bool hasTarget = !FirstSelectedRowField({ L"DriverStart", L"ModuleBase" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverCommunicationRestore, L"恢复驱动通信");
        } else if (descriptor->id == KernelFeatureId::DynData) {
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING, kMenuDynDataApplyMatchedProfile, L"应用匹配 DynData Profile");
        } else if (descriptor->id == KernelFeatureId::MutationAudit) {
            const bool hasTransaction = !FirstSelectedRowField({ L"Tx", L"TransactionId" }).empty();
            ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
            ::AppendMenuW(menu, MF_STRING | (hasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationCommitDryRun, L"Commit dry-run 当前事务");
            ::AppendMenuW(menu, MF_STRING | (hasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackDryRun, L"Rollback dry-run 当前事务");
            ::AppendMenuW(menu, MF_STRING | (hasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackConfirmed, L"确认 Rollback 当前事务");
        }
    }
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
}

bool KernelPage::PrepareResultContextPoint(POINT& screenPoint, const bool updatePropertyTable) {
    // PrepareResultContextPoint normalizes keyboard and mouse context-menu
    // positions for the result ListView. Inputs are a mutable screen point and
    // whether property panes must refresh; processing selects the clicked row
    // while preserving existing multi-selection when Ctrl/Shift is held or the
    // clicked row is already selected. Return is false only when resultList_ is
    // unavailable.
    if (!resultList_) {
        return false;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int selected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (selected >= 0 && ListView_GetItemRect(resultList_, selected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
        return true;
    }

    POINT clientPoint = screenPoint;
    ::ScreenToClient(resultList_, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int row = ListView_HitTest(resultList_, &hit);
    if (row < 0) {
        return true;
    }

    const bool preserveMultiSelection = (::GetKeyState(VK_CONTROL) & 0x8000) != 0 ||
        (::GetKeyState(VK_SHIFT) & 0x8000) != 0 ||
        (ListView_GetItemState(resultList_, row, LVIS_SELECTED) & LVIS_SELECTED) != 0;
    if (!preserveMultiSelection) {
        ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
    }
    ListView_SetItemState(resultList_, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    ListView_EnsureVisible(resultList_, row, FALSE);
    UpdateSelectedRowDetail();
    if (updatePropertyTable) {
        UpdatePropertyTableFromSelection();
    }
    return true;
}

bool KernelPage::ShowNtQueryContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowNtQueryContextMenu keeps the legacy NtQuery history page close to the
    // original KernelDock surface. The source page only offered refresh and
    // detail-oriented inspection, so this popup intentionally avoids the
    // generic kernel filtering and mutation actions. Input is the screen point
    // from WM_CONTEXTMENU plus the active descriptor; return true means the
    // caller must not append the generic result menu.
    if (!resultList_ || descriptor.id != KernelFeatureId::NtQueryLegacy) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新历史 NtQuery");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情");

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowAtomTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowAtomTableContextMenu mirrors the original KernelDock atom popup: one
    // refresh command, a Copy submenu, and an Atom operation submenu. Inputs are
    // screen coordinates and the active descriptor; output true tells the
    // generic menu builder not to append unrelated kernel actions.
    if (!resultList_ || descriptor.id != KernelFeatureId::AtomTable) {
        return false;
    }
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool hasName = !FirstSelectedRowField({ L"名称", L"Name" }).empty();

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新原子表");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomValue, L"复制Atom值");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomHex, L"复制十六进制");
        ::AppendMenuW(copyMenu, MF_STRING | (hasName ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomName, L"复制名称");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyAtomSource, L"复制来源");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu != nullptr) {
        ::AppendMenuW(operationMenu, MF_STRING | (hasName ? MF_ENABLED : MF_GRAYED), kMenuFilterByName, L"用名称过滤");
        ::AppendMenuW(operationMenu, MF_STRING | (hasName ? MF_ENABLED : MF_GRAYED), kMenuAtomVerify, L"使用GlobalFindAtomW校验");
        ::AppendMenuW(operationMenu, MF_STRING | (hasName ? MF_ENABLED : MF_GRAYED), kMenuAtomCopySnippet, L"复制调用代码片段");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"原子操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowObjectNamespaceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowObjectNamespaceContextMenu mirrors the original object namespace tab
    // family: every page starts with refresh, then exposes a Copy submenu and a
    // small operation submenu when the source tab had row actions. Inputs are
    // screen coordinates plus the active descriptor; return true prevents the
    // generic kernel result menu from adding unrelated actions.
    if (!resultList_) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }

    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool hasPath = !FirstSelectedRowField({ L"Path", L"NtPath", L"fullPath", L"FullPath", L"完整路径", L"路径/说明" }).empty();
    const bool hasTarget = !FirstSelectedRowField({ L"Target", L"targetPath", L"symbolicTarget", L"符号链接目标", L"dosCandidate", L"Win32Path" }).empty();
    const bool hasType = !FirstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }).empty();
    const bool hasName = !FirstSelectedRowField({ L"Name", L"objectName", L"名称", L"linkName", L"Pipe", L"Pipe Name" }).empty();
    const bool hasDirectory = !FirstSelectedRowField({ L"directoryPath", L"Parent", L"Directory", L"Source", L"sourceDirectory", L"目录路径", L"来源目录" }).empty();
    const bool hasEnumApi = !FirstSelectedRowField({ L"EnumApi", L"enumApi", L"枚举 API", L"EnumerationApi" }).empty();
    const bool hasDosCandidate = !FirstSelectedRowField({ L"dosCandidate", L"Win32Path", L"DosCandidates" }).empty();
    const bool isSymbolicLink = ContainsCaseInsensitive(FirstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }), L"SymbolicLink") ||
        ContainsCaseInsensitive(FirstSelectedRowField({ L"类型" }), L"符号链接");

    const auto appendRefresh = [&](const wchar_t* refreshText) {
        ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, refreshText);
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    };
    const auto appendBasicCopyMenu = [&](const bool includeCell, const bool includeFields, const bool includeSameDirectory, const bool includeVisibleRows) {
        HMENU copyMenu = ::CreatePopupMenu();
        if (copyMenu == nullptr) {
            return;
        }
        if (includeCell) {
            ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前单元格");
        }
        if (includeFields) {
            ::AppendMenuW(copyMenu, MF_STRING | (hasName ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectName, L"复制对象名");
            ::AppendMenuW(copyMenu, MF_STRING | (hasType ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectType, L"复制对象类型");
            ::AppendMenuW(copyMenu, MF_STRING | (hasPath ? MF_ENABLED : MF_GRAYED), kMenuCopyFullPath, L"复制完整路径");
            ::AppendMenuW(copyMenu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制符号链接目标");
            ::AppendMenuW(copyMenu, MF_STRING | (hasEnumApi ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectEnumSource, L"复制枚举 API");
            ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        }
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        if (includeSameDirectory) {
            ::AppendMenuW(copyMenu, MF_STRING | (hasDirectory || hasPath ? MF_ENABLED : MF_GRAYED), kMenuCopySameDirectory, L"复制同目录路径全部行");
        }
        if (includeVisibleRows) {
            ::AppendMenuW(copyMenu, MF_STRING, kMenuCopyAll, L"复制可见结果 TSV");
            ::AppendMenuW(copyMenu, MF_STRING, kMenuExportAllTsv, L"导出 TSV");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    };
    const auto appendObjectOperationMenu = [&](const bool includeObjectDetail, const bool includeRootFilter, const bool includeNameFilter, const bool includeTargetFilter, const bool includeDosMap) {
        HMENU operationMenu = ::CreatePopupMenu();
        if (operationMenu == nullptr) {
            return;
        }
        if (includeObjectDetail) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        }
        if (includeRootFilter) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasDirectory || hasPath ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByRoot, L"用目录路径过滤");
            ::AppendMenuW(operationMenu, MF_STRING | (hasDirectory ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByDirectory, L"用当前目录过滤");
        }
        if (includeNameFilter) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasName ? MF_ENABLED : MF_GRAYED), kMenuFilterByName, L"用对象名过滤");
        }
        if (includeTargetFilter) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuFilterByTarget, L"按目标路径过滤");
        }
        if (isSymbolicLink || descriptor.id == KernelFeatureId::SymbolicLink) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeSymbolicLinkResolve, L"解析符号链接目标");
        }
        if (includeDosMap) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasPath || hasTarget ? MF_ENABLED : MF_GRAYED), kMenuMapDosPath, L"尝试映射为 DOS 路径");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"对象操作");
    };

    switch (descriptor.id) {
    case KernelFeatureId::ObjectNamespaceOverview:
        appendRefresh(L"刷新对象命名空间");
        appendBasicCopyMenu(true, true, true, false);
        appendObjectOperationMenu(false, true, true, false, true);
        break;
    case KernelFeatureId::BaseNamedObjects:
        ::DestroyMenu(menu);
        return true;
    case KernelFeatureId::NamedPipe:
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuShowRowDialog, L"刷新详情");
        break;
    case KernelFeatureId::SymbolicLink:
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
        ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制 targetPath");
        ::AppendMenuW(menu, MF_STRING | (hasDosCandidate ? MF_ENABLED : MF_GRAYED), kMenuCopyDosCandidate, L"复制 dosCandidate");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制整行");
        ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuFilterByTarget, L"按此目标路径过滤");
        break;
    case KernelFeatureId::DeviceDriverObjects:
        appendRefresh(L"刷新设备/驱动对象");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(menu, MF_STRING | (currentRows_.empty() ? MF_GRAYED : MF_ENABLED), kMenuCopyAll, L"复制可见结果 TSV");
        ::AppendMenuW(menu, MF_STRING | (currentRows_.empty() ? MF_GRAYED : MF_ENABLED), kMenuExportAllTsv, L"导出 TSV");
        break;
    case KernelFeatureId::ObjectTypeMatrix:
        appendRefresh(L"刷新对象类型统计");
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        break;
    case KernelFeatureId::CommunicationEndpoint:
        ::DestroyMenu(menu);
        return true;
    default:
        ::DestroyMenu(menu);
        return false;
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowObjectNamespaceOverviewContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowObjectNamespaceOverviewContextMenu mirrors the original object
    // namespace overview actions without leaking generic kernel mutation items.
    // Inputs are the popup screen point and descriptor; processing selects the
    // clicked row, then exposes copy, directory filtering and DOS mapping.
    // Return true means the popup is fully handled here.
    if (!resultList_ || descriptor.id != KernelFeatureId::ObjectNamespaceOverview) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, true)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool hasPath = !FirstSelectedRowField({ L"Path", L"NtPath", L"fullPath", L"FullPath", L"完整路径", L"路径/说明" }).empty();
    const bool hasTarget = !FirstSelectedRowField({ L"Target", L"targetPath", L"symbolicTarget", L"符号链接目标", L"dosCandidate", L"Win32Path" }).empty();
    const bool hasType = !FirstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }).empty();
    const bool hasName = !FirstSelectedRowField({ L"Name", L"objectName", L"名称", L"linkName" }).empty();
    const bool hasDirectory = !FirstSelectedRowField({ L"directoryPath", L"Parent", L"Directory", L"Source", L"sourceDirectory", L"目录路径", L"来源目录" }).empty();
    const bool hasEnumApi = !FirstSelectedRowField({ L"EnumApi", L"enumApi", L"枚举 API", L"EnumerationApi" }).empty();
    const bool hasEntry = _wcsicmp(FirstSelectedRowField({ L"NodeKind" }).c_str(), L"ObjectEntry") == 0 ||
        FirstSelectedRowField({ L"NodeKind" }).empty();
    const bool canMapDos = hasEntry && (hasPath || hasTarget);
    const bool isSymbolicLink = ContainsCaseInsensitive(FirstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }), L"SymbolicLink") ||
        ContainsCaseInsensitive(FirstSelectedRowField({ L"类型" }), L"符号链接");

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新对象命名空间");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (hasEntry && hasName ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectName, L"复制对象名");
        ::AppendMenuW(copyMenu, MF_STRING | (hasEntry && hasType ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectType, L"复制对象类型");
        ::AppendMenuW(copyMenu, MF_STRING | (hasEntry && hasPath ? MF_ENABLED : MF_GRAYED), kMenuCopyFullPath, L"复制完整路径");
        ::AppendMenuW(copyMenu, MF_STRING | (hasEntry && hasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制符号链接目标");
        ::AppendMenuW(copyMenu, MF_STRING | (hasEntry && hasEnumApi ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectEnumSource, L"复制枚举 API");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (hasEntry && (hasDirectory || hasPath) ? MF_ENABLED : MF_GRAYED), kMenuCopySameDirectory, L"复制同目录路径全部行");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu != nullptr) {
        ::AppendMenuW(operationMenu, MF_STRING | (hasEntry && hasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        ::AppendMenuW(operationMenu, MF_STRING | (hasEntry && (hasDirectory || hasPath) ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByRoot, L"用目录路径过滤");
        ::AppendMenuW(operationMenu, MF_STRING | (hasEntry && hasDirectory ? MF_ENABLED : MF_GRAYED), kMenuObjectFilterByDirectory, L"用当前目录过滤");
        ::AppendMenuW(operationMenu, MF_STRING | (hasEntry && hasName ? MF_ENABLED : MF_GRAYED), kMenuFilterByName, L"用对象名过滤");
        if (isSymbolicLink) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasEntry && hasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeSymbolicLinkResolve, L"解析符号链接目标");
        }
        ::AppendMenuW(operationMenu, MF_STRING | (canMapDos ? MF_ENABLED : MF_GRAYED), kMenuMapDosPath, L"尝试映射为 DOS 路径");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"对象操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowObjectDirectoryRecursiveContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowObjectDirectoryRecursiveContextMenu handles the recursive Object
    // Manager directory page. Inputs are the popup coordinates and descriptor;
    // processing selects the clicked row, exposes copy/export under one submenu,
    // and exposes read-only object helpers under another submenu. The recursive
    // page uses filterEdit_ as its next traversal root, so it intentionally does
    // not offer cached type/name filters; the only filter action resets the
    // traversal root to the selected full path and refreshes the query. The
    // return value is true when the menu is fully handled.
    if (!resultList_ || descriptor.id != KernelFeatureId::ObjectDirectoryRecursive) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool hasRows = ListView_GetItemCount(resultList_) > 0;
    const bool hasPath = !FirstSelectedRowField({ L"完整路径", L"fullPath", L"Path", L"NtPath" }).empty();
    const bool hasType = !FirstSelectedRowField({ L"类型", L"objectType", L"Type" }).empty();
    const bool hasName = !FirstSelectedRowField({ L"名称", L"objectName", L"Name" }).empty();
    const bool hasTarget = !FirstSelectedRowField({ L"Target", L"targetPath", L"symbolicTarget", L"符号链接目标", L"dosCandidate", L"Win32Path" }).empty();
    const bool isSymbolicLink = ContainsCaseInsensitive(FirstSelectedRowField({ L"Type", L"objectType", L"对象类型", L"类型" }), L"SymbolicLink") ||
        ContainsCaseInsensitive(FirstSelectedRowField({ L"类型" }), L"符号链接");

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新目录递归");

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
        ::AppendMenuW(copyMenu, MF_STRING | (hasName ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectName, L"复制对象名");
        ::AppendMenuW(copyMenu, MF_STRING | (hasType ? MF_ENABLED : MF_GRAYED), kMenuCopyObjectType, L"复制对象类型");
        ::AppendMenuW(copyMenu, MF_STRING | (hasPath ? MF_ENABLED : MF_GRAYED), kMenuCopyFullPath, L"复制完整路径");
        ::AppendMenuW(copyMenu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制符号链接目标");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
        ::AppendMenuW(copyMenu, MF_STRING | (hasRows ? MF_ENABLED : MF_GRAYED), kMenuCopyAll, L"复制可见结果 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (hasRows ? MF_ENABLED : MF_GRAYED), kMenuExportAllTsv, L"导出 TSV");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    HMENU operationMenu = ::CreatePopupMenu();
    if (operationMenu != nullptr) {
        ::AppendMenuW(operationMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        ::AppendMenuW(operationMenu, MF_STRING | (hasPath ? MF_ENABLED : MF_GRAYED), kMenuFilterByPath, L"以完整路径作为递归根");
        if (isSymbolicLink) {
            ::AppendMenuW(operationMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeSymbolicLinkResolve, L"解析符号链接目标");
        }
        ::AppendMenuW(operationMenu, MF_STRING | ((hasPath || hasTarget) ? MF_ENABLED : MF_GRAYED), kMenuMapDosPath, L"尝试映射为 DOS 路径");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(operationMenu), L"对象操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowDeviceDriverObjectsContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowDeviceDriverObjectsContextMenu mirrors the original full tab's base
    // menu exactly: copy cell, copy current row, copy visible TSV, and export
    // TSV. Inputs are the screen-space popup point and descriptor; processing
    // selects the clicked ListView row and optionally exposes R3/R0 helpers in
    // a separate submenu so original copy/export workflow stays first; output
    // is true when the popup was handled.
    if (!resultList_ || descriptor.id != KernelFeatureId::DeviceDriverObjects) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool hasRows = ListView_GetItemCount(resultList_) > 0;
    const std::wstring objectType = FirstSelectedRowField({ L"对象类型", L"objectType", L"Type", L"类型" });
    const std::wstring objectPath = FirstSelectedRowField({ L"完整路径", L"fullPath", L"Path", L"NtPath" });
    const bool isDriverObject = ContainsCaseInsensitive(objectType, L"Driver") ||
        ContainsCaseInsensitive(objectPath, L"\\Driver\\") ||
        !FirstSelectedRowField({ L"DriverName" }).empty();

    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (hasRows ? MF_ENABLED : MF_GRAYED), kMenuCopyAll, L"复制可见结果 TSV");
    ::AppendMenuW(menu, MF_STRING | (hasRows ? MF_ENABLED : MF_GRAYED), kMenuExportAllTsv, L"导出 TSV");

    HMENU objectMenu = ::CreatePopupMenu();
    if (objectMenu != nullptr) {
        ::AppendMenuW(objectMenu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新设备/驱动对象");
        ::AppendMenuW(objectMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(objectMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuNativeObjectQueryDetail, L"R3 对象详情");
        ::AppendMenuW(objectMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuFilterByPath, L"按完整路径过滤");
        ::AppendMenuW(objectMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuFilterByType, L"按对象类型过滤");
        ::AppendMenuW(objectMenu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(objectMenu, MF_STRING | (hasSelection && isDriverObject ? MF_ENABLED : MF_GRAYED), kMenuDriverObjectQueryDetail, L"R0 DriverObject 详情");
        ::AppendMenuW(objectMenu, MF_STRING | (hasSelection && isDriverObject ? MF_ENABLED : MF_GRAYED), kMenuDriverObjectForceUnload, L"R0 强制卸载 DriverObject");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(objectMenu), L"对象操作");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowSimpleObjectTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowSimpleObjectTableContextMenu handles BaseNamedObjects. Inputs are
    // screen coordinates and the active descriptor; processing keeps copy/export
    // in a submenu and exposes R3 detail/filter actions without mixing in R0
    // mutation entries. The return value is true when the popup was handled.
    if (!resultList_ || descriptor.id != KernelFeatureId::BaseNamedObjects) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowNamedPipeContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowNamedPipeContextMenu handles the NPFS named-pipe page. Inputs are the
    // popup point and active descriptor; processing selects the clicked row,
    // exposes copy/export commands under one submenu, and exposes read-only
    // probe/filter commands under another submenu. The return value is true
    // when no generic kernel menu should be appended.
    if (!resultList_ || descriptor.id != KernelFeatureId::NamedPipe) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuShowRowDialog, L"刷新详情");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowSymbolicLinkContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowSymbolicLinkContextMenu mirrors the original SymbolicLink tab popup.
    // Inputs are the context-menu screen point and active feature descriptor;
    // processing selects the row under the mouse and exposes only the original
    // five actions: copy cell, targetPath, dosCandidate, row, and target filter.
    // Return value is true when this flat table handled the popup.
    if (!resultList_ || descriptor.id != KernelFeatureId::SymbolicLink) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }

    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool hasTarget = !FirstSelectedRowField({
        L"targetPath",
        L"symbolicTarget",
        L"Target",
        L"目标路径",
        L"符号链接目标",
    }).empty();
    const bool hasDosCandidate = !FirstSelectedRowField({
        L"dosCandidate",
        L"Win32Path",
        L"DosCandidates",
    }).empty();
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuCopySymbolicTarget, L"复制 targetPath");
    ::AppendMenuW(menu, MF_STRING | (hasDosCandidate ? MF_ENABLED : MF_GRAYED), kMenuCopyDosCandidate, L"复制 dosCandidate");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制整行");
    ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuFilterByTarget, L"按此目标路径过滤");

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowObjectTypeMatrixContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowObjectTypeMatrixContextMenu keeps the object-type matrix popup as
    // small as the original source tab: the only row action is copying the
    // current type row. Inputs are the popup screen point and descriptor; return
    // true means the generic kernel/object menus must not add extra operations.
    if (!resultList_ || descriptor.id != KernelFeatureId::ObjectTypeMatrix) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowCommunicationEndpointContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowCommunicationEndpointContextMenu handles ALPC/Port endpoint rows.
    // Inputs are screen coordinates and the current descriptor; processing
    // selects the clicked row and exposes the same single "copy row" action as
    // the original endpoint tab. Return true prevents unrelated object or driver
    // operations from being appended.
    if (!resultList_ || descriptor.id != KernelFeatureId::CommunicationEndpoint) {
        return false;
    }
    if (!PrepareResultContextPoint(screenPoint, false)) {
        return false;
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowKernelHookContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowKernelHookContextMenu mirrors the original hook-related popup menus.
    // SSDT had no context menu in the original page. SSSDT, Inline, and IAT/EAT
    // keep their refresh/copy actions plus Inline's NOP entry. Inputs are screen
    // coordinates and the active descriptor; return true prevents generic kernel
    // actions.
    if (!resultList_ || descriptor.id == KernelFeatureId::Ssdt) {
        return false;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int selected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (selected >= 0 && ListView_GetItemRect(resultList_, selected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(resultList_, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int row = ListView_HitTest(resultList_, &hit);
        if (row >= 0) {
            const bool preserveMultiSelection = (::GetKeyState(VK_CONTROL) & 0x8000) != 0 ||
                (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (!preserveMultiSelection && ListView_GetItemState(resultList_, row, LVIS_SELECTED) == 0) {
                ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(resultList_, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, row, FALSE);
            UpdateSelectedRowDetail();
        }
    }
    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const wchar_t* refreshText = L"刷新当前页";
    if (descriptor.id == KernelFeatureId::Ssdt) {
        refreshText = L"刷新 SSDT";
    } else if (descriptor.id == KernelFeatureId::ShadowSsdt) {
        refreshText = L"刷新 SSSDT";
    } else if (descriptor.id == KernelFeatureId::InlineHook) {
        refreshText = L"重新扫描 Inline Hook";
    } else if (descriptor.id == KernelFeatureId::IatEatHook) {
        refreshText = L"重新扫描 IAT/EAT";
    }
    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, refreshText);
    if (descriptor.id == KernelFeatureId::InlineHook) {
        ::AppendMenuW(menu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuInlineNopPatch, L"NOP 摘除当前 Hook");
    }
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前列（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRows, L"复制选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRowsWithHeader, L"复制表头+选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情（选中行）");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        HMENU columnMenu = ::CreatePopupMenu();
        if (columnMenu != nullptr) {
            const std::vector<int> copyColumns = KernelHookVisibleColumnIndices(descriptor.id, currentColumns_);
            for (std::size_t position = 0; position < copyColumns.size() && position < static_cast<std::size_t>(kMenuCopyColumnMax - kMenuCopyColumnBase); ++position) {
                const int column = copyColumns[position];
                if (column < 0 || column >= static_cast<int>(currentColumns_.size())) {
                    continue;
                }
                ::AppendMenuW(columnMenu,
                    MF_STRING,
                    kMenuCopyColumnBase + static_cast<UINT_PTR>(column),
                    currentColumns_[static_cast<std::size_t>(column)].c_str());
            }
            ::AppendMenuW(copyMenu,
                MF_POPUP | (hasSelection && !copyColumns.empty() ? MF_ENABLED : MF_GRAYED),
                reinterpret_cast<UINT_PTR>(columnMenu),
                L"复制指定栏目（选中行）");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }
    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowCallbackEnumerationContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowCallbackEnumerationContextMenu mirrors KernelDock.CallbackEnum's menu:
    // refresh, module file actions, single-row remove entries, and copy submenu.
    // Inputs are screen coordinates and the active descriptor; output true means
    // the generic kernel menu must not add extra actions.
    if (!resultList_ || descriptor.id != KernelFeatureId::CallbackEnumeration) {
        return false;
    }

    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rowBounds{};
        const int selected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (selected >= 0 && ListView_GetItemRect(resultList_, selected, &rowBounds, LVIR_BOUNDS)) {
            screenPoint.x = rowBounds.left;
            screenPoint.y = rowBounds.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(resultList_, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int row = ListView_HitTest(resultList_, &hit);
        contextColumn_ = hit.iSubItem >= 0 ? hit.iSubItem : 0;
        if (row >= 0) {
            const bool preserveMultiSelection = (::GetKeyState(VK_CONTROL) & 0x8000) != 0 ||
                (::GetKeyState(VK_SHIFT) & 0x8000) != 0;
            if (!preserveMultiSelection && ListView_GetItemState(resultList_, row, LVIS_SELECTED) == 0) {
                ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(resultList_, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, row, FALSE);
            UpdateSelectedRowDetail();
        }
    }

    const int selectedCount = ListView_GetSelectedCount(resultList_);
    const bool hasSelection = selectedCount > 0;
    const bool singleSelection = selectedCount == 1;
    const std::wstring moduleFile = SelectedCallbackModulePath();
    const bool hasModuleFile = !moduleFile.empty() && ::GetFileAttributesW(moduleFile.c_str()) != INVALID_FILE_ATTRIBUTES;

    std::uint32_t callbackClass = 0;
    std::uint32_t status = 0;
    std::uint32_t source = 0;
    std::uint32_t fieldFlags = 0;
    std::uint32_t removeBehavior = 0;
    std::uint64_t callbackAddress = 0;
    std::uint64_t registrationAddress = 0;
    std::uint64_t rawStorageValue = 0;
    std::uint64_t contextAddress = 0;
    std::uint64_t parsed = 0;
    if (ParseUnsigned64Value(FirstSelectedRowField({ L"Class" }), parsed)) {
        callbackClass = static_cast<std::uint32_t>(parsed);
    }
    if (ParseUnsigned64Value(FirstSelectedRowField({ L"Source" }), parsed)) {
        source = static_cast<std::uint32_t>(parsed);
    }
    if (ParseUnsigned64Value(FirstSelectedRowField({ L"FieldFlags" }), parsed)) {
        fieldFlags = static_cast<std::uint32_t>(parsed);
    }
    if (ParseUnsigned64Value(FirstSelectedRowField({ L"Remove" }), parsed)) {
        removeBehavior = static_cast<std::uint32_t>(parsed);
    }
    ParseUnsigned64Value(FirstSelectedRowField({ L"Callback" }), callbackAddress);
    ParseUnsigned64Value(FirstSelectedRowField({ L"Registration" }), registrationAddress);
    ParseUnsigned64Value(FirstSelectedRowField({ L"RawStorageValue" }), rawStorageValue);
    ParseUnsigned64Value(FirstSelectedRowField({ L"Context" }), contextAddress);

    const std::wstring statusText = FirstSelectedRowField({ L"Status", L"状态" });
    if (ContainsCaseInsensitive(statusText, L"可见") || ContainsCaseInsensitive(statusText, L"OK") ||
        ContainsCaseInsensitive(statusText, L"success") || ContainsCaseInsensitive(statusText, L"(1)")) {
        status = KSWORD_ARK_CALLBACK_ENUM_STATUS_OK;
    }
    const std::wstring removePolicy = FirstSelectedRowField({ L"RemovePolicy", L"移除策略" });
    const std::uint64_t requestValue = CallbackEnumPrimaryRemoveValue(
        callbackAddress,
        registrationAddress,
        rawStorageValue,
        fieldFlags);
    const bool canSafeRemove = singleSelection && CallbackEnumSafeRemoveAllowed(
        callbackClass,
        status,
        source,
        fieldFlags,
        removeBehavior,
        requestValue,
        removePolicy);
    const bool canExperimentalUnlink = singleSelection && CallbackEnumExperimentalUnlinkAllowed(
        callbackClass,
        status,
        source,
        fieldFlags,
        removeBehavior,
        requestValue,
        contextAddress,
        removePolicy);

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新回调遍历");
    ::AppendMenuW(menu, MF_STRING | (hasModuleFile ? MF_ENABLED : MF_GRAYED), kMenuCallbackOpenModuleFolder, L"打开模块所在目录");
    ::AppendMenuW(menu, MF_STRING | (hasModuleFile ? MF_ENABLED : MF_GRAYED), kMenuCallbackModuleFileDetail, L"模块文件详细信息");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (canSafeRemove ? MF_ENABLED : MF_GRAYED), kMenuCallbackSafeRemove, L"安全移除（公开 API）");
    ::AppendMenuW(menu, MF_STRING | (canExperimentalUnlink ? MF_ENABLED : MF_GRAYED), kMenuCallbackExperimentalUnlink, L"实验性强制移除（unlink）");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu != nullptr) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前列（选中行）");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRows, L"复制选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRowsWithHeader, L"复制表头+选中行（TSV）");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情（选中行）");
        ::AppendMenuW(copyMenu, MF_SEPARATOR, 0, nullptr);
        HMENU columnMenu = ::CreatePopupMenu();
        if (columnMenu != nullptr) {
            const std::vector<int> copyColumns = CurrentCopyColumnIndices();
            for (int column = 0; column < static_cast<int>(copyColumns.size()) &&
                column < static_cast<int>(kMenuCallbackCopyColumnMax - kMenuCallbackCopyColumnBase + 1); ++column) {
                const int sourceColumn = copyColumns[static_cast<std::size_t>(column)];
                if (sourceColumn < 0 || sourceColumn >= static_cast<int>(currentColumns_.size())) {
                    continue;
                }
                ::AppendMenuW(columnMenu,
                    MF_STRING,
                    kMenuCallbackCopyColumnBase + static_cast<UINT_PTR>(column),
                    currentColumns_[static_cast<std::size_t>(sourceColumn)].c_str());
            }
            ::AppendMenuW(copyMenu, MF_POPUP | (hasSelection ? MF_ENABLED : MF_GRAYED), reinterpret_cast<UINT_PTR>(columnMenu), L"复制指定栏目（选中行）");
        }
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

bool KernelPage::ShowR0EvidenceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor) {
    // ShowR0EvidenceContextMenu provides original-style popups only for R0
    // pages that had row actions in the source UI. Inputs are screen position
    // plus the active descriptor; processing exposes copy and explicit mutation
    // actions only; output true means the menu was handled.
    if (!resultList_) {
        return false;
    }
    if (descriptor.id != KernelFeatureId::MutationAudit &&
        descriptor.id != KernelFeatureId::MinifilterBypassPids) {
        return false;
    }
    if (screenPoint.x == -1 && screenPoint.y == -1) {
        RECT rc{};
        const int selected = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
        if (selected >= 0 && ListView_GetItemRect(resultList_, selected, &rc, LVIR_BOUNDS)) {
            screenPoint.x = rc.left;
            screenPoint.y = rc.bottom;
            ::ClientToScreen(resultList_, &screenPoint);
        } else {
            ::GetCursorPos(&screenPoint);
        }
    } else {
        POINT clientPoint = screenPoint;
        ::ScreenToClient(resultList_, &clientPoint);
        LVHITTESTINFO hit{};
        hit.pt = clientPoint;
        const int row = ListView_HitTest(resultList_, &hit);
        if (row >= 0) {
            const UINT state = ListView_GetItemState(resultList_, row, LVIS_SELECTED);
            if ((state & LVIS_SELECTED) == 0) {
                ListView_SetItemState(resultList_, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
            }
            ListView_SetItemState(resultList_, row, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
            ListView_EnsureVisible(resultList_, row, FALSE);
            UpdateSelectedRowDetail();
        }
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return false;
    }
    const bool hasSelection = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) >= 0;
    const bool hasTransaction = descriptor.id == KernelFeatureId::MutationAudit &&
        !FirstSelectedRowField({ L"Tx", L"TransactionId" }).empty();

    ::AppendMenuW(menu, MF_STRING, kMenuRefreshCurrentFeature, L"刷新当前页");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);

    HMENU copyMenu = ::CreatePopupMenu();
    if (copyMenu) {
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyCell, L"复制当前列");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopyRow, L"复制当前行 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRows, L"复制选中行 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedRowsWithHeader, L"复制表头+选中行 TSV");
        ::AppendMenuW(copyMenu, MF_STRING | (hasSelection ? MF_ENABLED : MF_GRAYED), kMenuCopySelectedDetails, L"复制详情");
        ::AppendMenuW(menu, MF_POPUP, reinterpret_cast<UINT_PTR>(copyMenu), L"复制");
    }

    if (descriptor.id == KernelFeatureId::MutationAudit) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationCommitDryRun, L"Commit dry-run 当前事务");
        ::AppendMenuW(menu, MF_STRING | (hasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackDryRun, L"Rollback dry-run 当前事务");
        ::AppendMenuW(menu, MF_STRING | (hasTransaction ? MF_ENABLED : MF_GRAYED), kMenuMutationRollbackConfirmed, L"确认 Rollback 当前事务");
    } else if (descriptor.id == KernelFeatureId::MinifilterBypassPids) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuMinifilterSetBypass, L"设置放行 PID（过滤框）");
        ::AppendMenuW(menu, MF_STRING, kMenuMinifilterClearBypass, L"清空驱动 PID 放行");
    } else if (descriptor.id == KernelFeatureId::NetworkTrafficPackets) {
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStart, L"启动逐包捕获");
        ::AppendMenuW(menu, MF_STRING, kMenuNetworkCaptureStop, L"停止逐包捕获");
    } else if (descriptor.id == KernelFeatureId::PiDdbCache) {
        const bool hasEntry = !FirstSelectedRowField({ L"Entry", L"条目地址" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasEntry ? MF_ENABLED : MF_GRAYED), kMenuPiDdbDeleteEntry, L"删除选中 PiDDB 条目");
    } else if (descriptor.id == KernelFeatureId::DriverDispatchTable) {
        const bool hasTarget = !FirstSelectedRowField({ L"ModuleBase" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchRestore, L"恢复派遣槽为原值");
        ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverDispatchAbandon, L"放弃派遣恢复记录");
    } else if (descriptor.id == KernelFeatureId::DriverImageFields) {
        const bool hasTarget = !FirstSelectedRowField({ L"ModuleBase" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageRestore, L"恢复镜像字段为原值");
        ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverImageAbandon, L"放弃镜像恢复记录");
    } else if (descriptor.id == KernelFeatureId::DriverCommunication) {
        const bool hasTarget = !FirstSelectedRowField({ L"DriverStart", L"ModuleBase" }).empty();
        ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
        ::AppendMenuW(menu, MF_STRING | (hasTarget ? MF_ENABLED : MF_GRAYED), kMenuDriverCommunicationRestore, L"恢复驱动通信");
    }

    ::TrackPopupMenu(menu, TPM_RIGHTBUTTON | TPM_LEFTALIGN, screenPoint.x, screenPoint.y, 0, hwnd_, nullptr);
    ::DestroyMenu(menu);
    return true;
}

void KernelPage::ApplySelectedModuleFilter(const bool preferTargetModule) {
    // ApplySelectedModuleFilter turns a selected row into a module-filtered
    // refresh. Inputs are the active ListView selection and a target-module
    // preference; processing writes the module edit then reuses the normal
    // facade refresh path; return behavior is UI state update only.
    const std::wstring module = preferTargetModule
        ? FirstSelectedRowField({ L"TargetModule", L"OwnerModule", L"Module", L"ModulePath", L"Owner", L"Import" })
        : FirstSelectedRowField({ L"Module", L"ModulePath", L"OwnerModule", L"Owner", L"TargetModule", L"Import" });
    if (module.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Module/TargetModule/OwnerModule 字段，无法按模块重查。", L"模块过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackEnumeration) {
        ::SetWindowTextW(filterEdit_, module.c_str());
        ::SetWindowTextW(statusText_, L"状态：已设置回调模块过滤。");
        RebuildCallbackEnumerationListFromCache();
        return;
    }
    ::SetWindowTextW(moduleFilterEdit_, module.c_str());
    ::SetWindowTextW(statusText_, L"状态：已设置模块过滤并重新查询。");
    RefreshSelectedFeature();
}

void KernelPage::ApplySelectedAddressFilter() {
    // ApplySelectedAddressFilter uses the selected row's most meaningful address
    // or object field as the generic filter. Inputs are row text fields; output
    // is a filtered refresh through the same KernelFacade query contract.
    const std::wstring value = FirstSelectedRowField({
        L"Address",
        L"Target",
        L"Service",
        L"Zw",
        L"Current",
        L"Expected",
        L"VA",
        L"Object",
        L"ThreadObject",
        L"ProcessObject",
        L"DriverObject",
        L"DeviceObject",
        L"Callback",
        L"Registration",
        L"RawStorageValue",
        L"Context",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有可用于过滤的地址/对象字段。", L"地址过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackEnumeration) {
        ::SetWindowTextW(statusText_, L"状态：已设置回调地址/对象过滤。");
        RebuildCallbackEnumerationListFromCache();
    } else {
        ::SetWindowTextW(statusText_, L"状态：已设置地址/对象过滤并重新查询。");
        RefreshSelectedFeature();
    }
}

bool KernelPage::RebuildCurrentObjectNamespaceFilter(const wchar_t* statusText) {
    // RebuildCurrentObjectNamespaceFilter applies filter changes to cached R3
    // object pages instead of forcing a new Native/R0 query. Input is a status
    // message for the visible status bar; processing checks the active feature
    // and rebuilds object rows from currentRawRows_; return is true when the
    // caller should skip RefreshSelectedFeature().
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr || !IsObjectNamespaceFeature(descriptor->id)) {
        return false;
    }
    if (descriptor->id == KernelFeatureId::ObjectDirectoryRecursive) {
        return false;
    }
    ::SetWindowTextW(statusText_, statusText);
    RebuildObjectNamespaceListFromCache(descriptor->id);
    return true;
}

void KernelPage::ApplySelectedPathFilter() {
    // ApplySelectedPathFilter uses native paths, driver names, pipe names, or
    // owner/module text as the generic filter/start field. Inputs are selected
    // row cells; processing writes the filter edit and reuses the normal query
    // path; output is a refreshed page focused on the chosen object.
    const std::wstring value = FirstSelectedRowField({
        L"Path",
        L"NtPath",
        L"NT Path",
        L"fullPath",
        L"FullPath",
        L"完整路径",
        L"路径/说明",
        L"Target",
        L"targetPath",
        L"symbolicTarget",
        L"目标路径",
        L"符号链接目标",
        L"Win32Path",
        L"dosCandidate",
        L"DriverName",
        L"Name",
        L"objectName",
        L"linkName",
        L"对象名称",
        L"名称",
        L"Pipe",
        L"Pipe Name",
        L"Owner",
        L"OwnerModule",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Path/NtPath/Name/Owner 字段，无法作为起点重查。", L"路径/名称过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    if (RebuildCurrentObjectNamespaceFilter(L"状态：已设置路径/名称过滤。")) {
        return;
    }
    ::SetWindowTextW(statusText_, L"状态：已设置路径/名称过滤并重新查询。");
    RefreshSelectedFeature();
}

void KernelPage::ApplySelectedTypeFilter() {
    // ApplySelectedTypeFilter mirrors the original object/atom context menu
    // "filter by type/source" actions. Inputs are selected row cells; output is
    // a refreshed page with the generic filter text set.
    const std::wstring value = FirstSelectedRowField({
        L"Type",
        L"objectType",
        L"对象类型",
        L"类型",
        L"类型名",
        L"类别",
        L"ClassText",
        L"Class",
        L"Source",
        L"来源",
        L"来源目录",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Type/Source 字段，无法按类型过滤。", L"类型过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackEnumeration) {
        ::SetWindowTextW(statusText_, L"状态：已设置回调类别/来源过滤。");
        RebuildCallbackEnumerationListFromCache();
    } else {
        if (RebuildCurrentObjectNamespaceFilter(L"状态：已设置类型/来源过滤。")) {
            return;
        }
        ::SetWindowTextW(statusText_, L"状态：已设置类型/来源过滤并重新查询。");
        RefreshSelectedFeature();
    }
}

void KernelPage::ApplySelectedNameFilter() {
    // ApplySelectedNameFilter mirrors original "use object name / atom name as
    // filter" operations. Inputs are selected name-like cells; output refreshes
    // through the existing facade query path.
    const std::wstring value = FirstSelectedRowField({
        L"Name",
        L"objectName",
        L"名称",
        L"对象名称",
        L"linkName",
        L"Pipe",
        L"Pipe Name",
        L"Atom值",
        L"Id",
        L"函数",
        L"ServiceName",
        L"Name",
        L"Altitude",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有名称字段，无法按名称过滤。", L"名称过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::CallbackEnumeration) {
        ::SetWindowTextW(statusText_, L"状态：已设置回调名称过滤。");
        RebuildCallbackEnumerationListFromCache();
    } else {
        if (RebuildCurrentObjectNamespaceFilter(L"状态：已设置名称过滤。")) {
            return;
        }
        ::SetWindowTextW(statusText_, L"状态：已设置名称过滤并重新查询。");
        RefreshSelectedFeature();
    }
}

void KernelPage::ApplySelectedTargetFilter() {
    // ApplySelectedTargetFilter uses symbolic-link targets, DOS candidates, or
    // generic Target columns as the filter text. Input is selected-row text;
    // output refreshes generic pages, while SymbolicLink updates its secondary
    // target filter and rebuilds cached rows to match the original tab.
    const std::wstring value = FirstSelectedRowField({
        L"Target",
        L"targetPath",
        L"symbolicTarget",
        L"目标路径",
        L"符号链接目标",
        L"dosCandidate",
        L"Win32Path",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Target/符号链接目标字段，无法按目标过滤。", L"目标过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor != nullptr && descriptor->id == KernelFeatureId::SymbolicLink) {
        ::SetWindowTextW(moduleFilterEdit_, value.c_str());
        ::SetWindowTextW(statusText_, L"状态：已按目标路径过滤。");
        RebuildObjectNamespaceListFromCache(KernelFeatureId::SymbolicLink);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    if (RebuildCurrentObjectNamespaceFilter(L"状态：已设置目标过滤。")) {
        return;
    }
    ::SetWindowTextW(statusText_, L"状态：已设置目标过滤并重新查询。");
    RefreshSelectedFeature();
}

void KernelPage::ApplySelectedOwnerFilter() {
    // ApplySelectedOwnerFilter uses owner/module/process text from evidence
    // rows. Inputs are selected row fields; processing writes filterEdit_ and
    // triggers the normal query/rebuild path; no value is returned.
    const std::wstring value = FirstSelectedRowField({
        L"Owner",
        L"OwnerModule",
        L"Owner模块",
        L"模块",
        L"Module",
        L"ModulePath",
        L"进程",
        L"Process",
        L"Image",
        L"进程名",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Owner/Module/Process 字段，无法按归属过滤。", L"归属过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按 Owner/Module/Process 过滤。");
    RefreshSelectedFeature();
}

void KernelPage::ApplySelectedRiskFilter() {
    // ApplySelectedRiskFilter narrows evidence pages to the selected risk or
    // anomaly label. Inputs are current row risk fields; output refreshes the
    // visible table with the generic filter set.
    const std::wstring value = FirstSelectedRowField({
        L"风险",
        L"RiskText",
        L"Risk",
        L"异常",
        L"AnomalyText",
        L"Anomaly",
        L"FlagsText",
        L"Status",
        L"状态",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Risk/Anomaly/Status 字段，无法按风险过滤。", L"风险过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按风险/异常过滤。");
    RefreshSelectedFeature();
}

void KernelPage::ApplySelectedPidTidFilter() {
    // ApplySelectedPidTidFilter uses PID/TID/ID columns from CrossView,
    // keyboard, and Minifilter pages. Inputs are selected row identifiers; the
    // filter edit becomes the chosen id; no value is returned.
    const std::wstring value = FirstSelectedRowField({
        L"PID",
        L"进程ID",
        L"TID",
        L"线程ID",
        L"ID",
        L"热键ID",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 PID/TID/ID 字段，无法按标识过滤。", L"PID/TID 过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按 PID/TID/ID 过滤。");
    RefreshSelectedFeature();
}

void KernelPage::ApplySelectedCapabilityFilter() {
    // ApplySelectedCapabilityFilter targets DynData-capability pages. Inputs
    // are selected capability/status fields; output refreshes the current page
    // with a local text filter.
    const std::wstring value = FirstSelectedRowField({
        L"Capability",
        L"CapabilityMask",
        L"DynData",
        L"DynDataCapabilityMask",
        L"字段",
        L"Fields",
        L"状态",
        L"StatusFlags",
    });
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有 Capability/DynData 字段，无法按能力过滤。", L"Capability 过滤", MB_OK | MB_ICONINFORMATION);
        return;
    }
    ::SetWindowTextW(filterEdit_, value.c_str());
    ::SetWindowTextW(statusText_, L"状态：已按 Capability/DynData 过滤。");
    RefreshSelectedFeature();
}

void KernelPage::VerifySelectedAtom() {
    // VerifySelectedAtom mirrors KernelDock's GlobalFindAtomW check. Input is
    // the selected atom name; processing calls GlobalFindAtomW; output is shown
    // in the detail editor and also updates the status text.
    const std::wstring name = FirstSelectedRowField({ L"名称", L"Name" });
    if (name.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有原子名称，无法校验。", L"原子校验", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const ATOM atom = ::GlobalFindAtomW(name.c_str());
    std::wostringstream detail;
    detail << L"GlobalFindAtomW 校验\r\n"
           << L"名称: " << name << L"\r\n"
           << L"结果: " << (atom != 0 ? L"命中" : L"未命中") << L"\r\n"
           << L"Atom: " << static_cast<unsigned int>(atom) << L"\r\n"
           << L"十六进制: 0x" << std::uppercase << std::hex << static_cast<unsigned int>(atom);
    ::SetWindowTextW(detailEdit_, detail.str().c_str());
    ::SetWindowTextW(statusText_, atom != 0 ? L"状态：GlobalFindAtomW 校验命中。" : L"状态：GlobalFindAtomW 未命中。");
}

void KernelPage::CopySelectedAtomSnippet() {
    // CopySelectedAtomSnippet mirrors the original atom page snippet action.
    // Input is the selected atom name; output writes a Win32 call snippet to the
    // clipboard and displays it in the detail pane.
    std::wstring name = FirstSelectedRowField({ L"名称", L"Name" });
    if (name.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有原子名称，无法生成调用代码。", L"原子代码片段", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring escaped;
    escaped.reserve(name.size());
    for (const wchar_t ch : name) {
        if (ch == L'\\' || ch == L'"') {
            escaped.push_back(L'\\');
        }
        escaped.push_back(ch);
    }
    const std::wstring snippet = L"ATOM atomValue = GlobalFindAtomW(L\"" + escaped + L"\");";
    SetClipboardText(hwnd_, snippet);
    ::SetWindowTextW(detailEdit_, (L"已复制调用代码片段:\r\n" + snippet).c_str());
    ::SetWindowTextW(statusText_, L"状态：已复制 GlobalFindAtomW 调用代码片段。");
}

void KernelPage::CopyRowsWithSameDirectory() {
    // CopyRowsWithSameDirectory mirrors KernelDock's object namespace "copy same
    // directory rows" action. Input is the selected row's parent/directory; the
    // output is the original nine-field KernelObjectNamespaceEntry TSV copied
    // to the clipboard.
    const std::wstring directory = FirstSelectedRowField({
        L"directoryPath",
        L"Parent",
        L"Directory",
        L"目录路径",
        L"来源目录",
        L"sourceDirectory",
    });
    if (directory.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有目录字段，无法复制同目录行。", L"复制同目录", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wstring text;
    for (const std::vector<std::wstring>& row : currentRows_) {
        bool sameDirectory = false;
        for (int column = 0; column < static_cast<int>(currentColumns_.size()) && column < static_cast<int>(row.size()); ++column) {
            const std::wstring& columnName = currentColumns_[static_cast<std::size_t>(column)];
            if ((_wcsicmp(columnName.c_str(), L"directoryPath") == 0 ||
                 _wcsicmp(columnName.c_str(), L"Parent") == 0 ||
                 _wcsicmp(columnName.c_str(), L"Directory") == 0 ||
                 _wcsicmp(columnName.c_str(), L"目录路径") == 0 ||
                 _wcsicmp(columnName.c_str(), L"来源目录") == 0 ||
                 _wcsicmp(columnName.c_str(), L"sourceDirectory") == 0) &&
                _wcsicmp(row[static_cast<std::size_t>(column)].c_str(), directory.c_str()) == 0) {
                sameDirectory = true;
                break;
            }
        }
        if (!sameDirectory) {
            continue;
        }
        if (!text.empty()) {
            text += L"\r\n";
        }
        const wchar_t* fields[] = {
            L"rootPathText", L"scopeDescriptionText", L"directoryPathText",
            L"objectNameText", L"objectTypeText", L"fullPathText",
            L"enumApiText", L"symbolicLinkTargetText", L"statusText",
        };
        for (std::size_t fieldIndex = 0; fieldIndex < std::size(fields); ++fieldIndex) {
            if (fieldIndex > 0) {
                text += L'\t';
            }
            std::wstring value = RowFieldByName(row, currentColumns_, { fields[fieldIndex] });
            if (value.empty()) {
                switch (fieldIndex) {
                case 0: value = RowFieldByName(row, currentColumns_, { L"Root", L"Source" }); break;
                case 1: value = RowFieldByName(row, currentColumns_, { L"Scope", L"scope", L"Detail", L"路径/说明" }); break;
                case 2: value = RowFieldByName(row, currentColumns_, { L"directoryPath", L"Parent", L"Directory", L"来源目录" }); break;
                case 3: value = RowFieldByName(row, currentColumns_, { L"objectName", L"Name", L"名称" }); break;
                case 4: value = RowFieldByName(row, currentColumns_, { L"objectType", L"Type", L"类型" }); break;
                case 5: value = RowFieldByName(row, currentColumns_, { L"fullPath", L"Path", L"完整路径", L"路径/说明" }); break;
                case 6: value = RowFieldByName(row, currentColumns_, { L"enumApi", L"EnumApi", L"枚举 API", L"EnumerationApi" }); break;
                case 7: value = RowFieldByName(row, currentColumns_, { L"symbolicLinkTarget", L"symbolicTarget", L"Target", L"targetPath", L"符号链接目标" }); break;
                case 8: value = RowFieldByName(row, currentColumns_, { L"statusText", L"Status", L"状态" }); break;
                default: break;
                }
            }
            text += value.empty() ? L"<空>" : value;
        }
    }
    SetClipboardText(hwnd_, text);
    ::SetWindowTextW(statusText_, L"状态：已复制同目录全部行。");
}

void KernelPage::MapSelectedNtPathAsDosPaths() {
    // MapSelectedNtPathAsDosPaths captures the selected NT path and delegates
    // all drive/device queries to the background file-I/O task.
    const std::wstring ntPath = FirstSelectedRowField({
        L"Target",
        L"targetPath",
        L"symbolicTarget",
        L"符号链接目标",
        L"Path",
        L"fullPath",
        L"完整路径",
    });
    if (ntPath.empty() || ntPath.rfind(L"\\Device\\", 0) != 0) {
        ::MessageBoxW(hwnd_, L"当前行不是 \\Device\\... NT 路径，无法映射 DOS 路径。", L"DOS 路径映射", MB_OK | MB_ICONINFORMATION);
        return;
    }
    StartCallbackFileIo(CallbackFileIoOperation::MapNtPath, ntPath);
}

std::wstring KernelPage::NormalizeCallbackModulePath(const std::wstring& modulePath) const {
    // NormalizeCallbackModulePath mirrors the original CallbackEnum module path
    // normalization. Input is an R0 module path such as \SystemRoot\... or
    // \??\C:\...; processing converts it to a Win32 file path when possible;
    // output is empty when the selected row has no usable module file.
    std::wstring path = modulePath;
    while (!path.empty() && std::iswspace(path.front())) {
        path.erase(path.begin());
    }
    while (!path.empty() && std::iswspace(path.back())) {
        path.pop_back();
    }
    if (path.empty() || path == L"<未解析>" || path == L"<unknown>") {
        return {};
    }
    constexpr wchar_t ntPrefix[] = L"\\??\\";
    if (_wcsnicmp(path.c_str(), ntPrefix, 4) == 0) {
        path.erase(0, 4);
    }
    constexpr wchar_t systemRootPrefix[] = L"\\SystemRoot\\";
    if (_wcsnicmp(path.c_str(), systemRootPrefix, 12) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        const UINT chars = ::GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (chars > 0) {
            path = std::wstring(windowsDir) + path.substr(11);
        }
    }
    constexpr wchar_t sysrootPrefix[] = L"SystemRoot\\";
    if (_wcsnicmp(path.c_str(), sysrootPrefix, 11) == 0) {
        wchar_t windowsDir[MAX_PATH]{};
        const UINT chars = ::GetWindowsDirectoryW(windowsDir, MAX_PATH);
        if (chars > 0) {
            path = std::wstring(windowsDir) + L"\\" + path.substr(11);
        }
    }
    return path;
}

std::wstring KernelPage::SelectedCallbackModulePath() const {
    // SelectedCallbackModulePath returns the normalized module file for the
    // selected CallbackEnum row. Inputs are the current row fields; output is a
    // Win32 path suitable for ShellExecute/GetFileAttributes or empty.
    return NormalizeCallbackModulePath(FirstSelectedRowField({
        L"Win32ModulePath",
        L"ModulePath",
        L"Module",
        L"模块",
    }));
}

void KernelPage::OpenSelectedCallbackModuleFolder() {
    // OpenSelectedCallbackModuleFolder mirrors the original CallbackEnum Explorer
    // action. Input is the selected module path; processing asks explorer.exe to
    // select the module file; no value is returned beyond status text.
    const std::wstring modulePath = SelectedCallbackModulePath();
    if (modulePath.empty()) {
        ::MessageBoxW(hwnd_, L"当前回调行没有可访问的模块文件。", L"打开模块所在目录", MB_OK | MB_ICONINFORMATION);
        return;
    }
    StartCallbackFileIo(CallbackFileIoOperation::OpenModuleFolder, modulePath);
}

void KernelPage::ShowSelectedCallbackModuleFileDetail() {
    // ShowSelectedCallbackModuleFileDetail captures the selected row's immutable
    // text and delegates file metadata, version-resource and PE-header reads to
    // the callback file-I/O task.
    const std::wstring modulePath = SelectedCallbackModulePath();
    if (modulePath.empty()) {
        ::MessageBoxW(hwnd_, L"当前回调行没有可访问的模块文件。", L"模块文件详细信息", MB_OK | MB_ICONINFORMATION);
        return;
    }
    std::wostringstream summary;
    summary << L"回调行摘要\r\n"
            << L"原始模块路径: " << FirstSelectedRowField({ L"ModulePath", L"Module", L"模块" }) << L"\r\n"
            << L"类别: " << FirstSelectedRowField({ L"ClassText", L"Class", L"类别" }) << L"\r\n"
            << L"来源: " << FirstSelectedRowField({ L"SourceText", L"Source", L"来源" }) << L"\r\n"
            << L"名称: " << FirstSelectedRowField({ L"Name", L"名称" }) << L"\r\n"
            << L"Callback: " << SelectedRowField(L"Callback") << L"\r\n"
            << L"ModuleBase: " << SelectedRowField(L"ModuleBase") << L"\r\n"
            << L"ModuleSize: " << SelectedRowField(L"ModuleSize") << L"\r\n";
    StartCallbackFileIo(CallbackFileIoOperation::CallbackModuleDetail, modulePath, summary.str());
}


void KernelPage::CopyPreferredSelectedField(std::initializer_list<std::wstring> fieldNames, const wchar_t* statusText) {
    // CopyPreferredSelectedField mirrors original per-field copy actions. Input
    // is a priority list of display column names and a final status string;
    // output is clipboard text only.
    const std::wstring value = FirstSelectedRowField(fieldNames);
    if (value.empty()) {
        ::MessageBoxW(hwnd_, L"当前行没有对应字段可复制。", L"复制字段", MB_OK | MB_ICONINFORMATION);
        return;
    }
    SetClipboardText(hwnd_, value);
    ::SetWindowTextW(statusText_, statusText);
}

std::wstring KernelPage::BuildRowDetailText(const int row) const {
    // BuildRowDetailText builds the same expanded key/value text shown in the
    // detail editor. Input is a ListView row index; processing prefers original
    // KernelDock detail text for pages with hand-written detail builders and
    // falls back to visible columns; output is empty for invalid rows.
    if (!resultList_ || row < 0) {
        return {};
    }
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor(); descriptor != nullptr) {
        const std::wstring originalStyle = BuildOriginalStyleSelectedRowDetail(descriptor->id, row);
        if (!originalStyle.empty()) {
            return originalStyle;
        }
    }
    const int columns = HeaderColumnCount(resultList_);
    std::wstring detail;
    for (int column = 0; column < columns; ++column) {
        const std::wstring name = column < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(column)]
            : std::wstring(L"Column ") + std::to_wstring(column);
        const std::wstring value = VisibleCellText(row, column);
        if (!detail.empty()) {
            detail += L"\r\n";
        }
        detail += name;
        detail += L": ";
        detail += value;
    }
    return detail;
}

void KernelPage::ShowSelectedRowDialog() {
    // ShowSelectedRowDialog displays the same expanded key/value text as a modal
    // dialog. Inputs are the current row; processing reuses BuildRowDetailText;
    // output is a readable row detail dialog for rows with many columns.
    const int row = resultList_ ? ListView_GetNextItem(resultList_, -1, LVNI_SELECTED) : -1;
    if (row < 0) {
        ::MessageBoxW(hwnd_, L"请先选择一条结果行。", L"当前行详情", MB_OK | MB_ICONINFORMATION);
        return;
    }
    const std::wstring detail = BuildRowDetailText(row);
    ::MessageBoxW(hwnd_, detail.c_str(), L"当前行详情", MB_OK | MB_ICONINFORMATION);
}

std::wstring KernelPage::FirstSelectedRowField(std::initializer_list<std::wstring> fieldNames) const {
    // FirstSelectedRowField scans a preferred field-name list and returns the
    // first selected-row value that exists. Inputs are display column names;
    // output is empty only when none of those columns contain text.
    for (const std::wstring& name : fieldNames) {
        const std::wstring value = SelectedRowField(name);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

std::wstring KernelPage::FirstSelectedRowValue(std::initializer_list<const wchar_t*> fieldNames) const {
    // FirstSelectedRowValue is a literal-friendly wrapper for confirmation
    // dialogs and action builders. Inputs are candidate column names as string
    // literals; processing reuses FirstSelectedRowField; output is the first
    // non-empty selected cell value or empty when all aliases miss.
    for (const wchar_t* fieldName : fieldNames) {
        const std::wstring value = SelectedRowField(fieldName);
        if (!value.empty()) {
            return value;
        }
    }
    return {};
}

std::wstring KernelPage::SelectedRowField(const std::wstring& fieldName) const {
    // SelectedRowField reads one named cell from the current result list.
    // Inputs are a dynamic column name and the active selection; processing scans
    // currentColumns_ case-insensitively and reads the matching visible cell, so
    // sorted rows and current ListView state are respected; output is empty when
    // no selection or no matching field exists.
    if (!resultList_) {
        return {};
    }
    const int row = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (row < 0) {
        return {};
    }
    for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
        if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), fieldName.c_str()) == 0) {
            return VisibleCellText(row, column);
        }
    }
    return {};
}

void KernelPage::CopySelectedCell() {
    // CopySelectedCell copies the right-click/current column for every selected
    // row. Inputs are the current ListView selection and contextColumn_ from
    // WM_CONTEXTMENU; output is one value per line on the clipboard.
    const int row = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (row < 0) {
        return;
    }
    const int columns = HeaderColumnCount(resultList_);
    int column = contextColumn_;
    if (column < 0 || column >= columns) {
        column = 1;
    }
    if (column < 0 || column >= columns) {
        return;
    }
    CopySelectedColumn(column);
}

void KernelPage::CopySelectedRow() {
    // CopySelectedRow serializes the selected row as tab-separated text. Inputs
    // are current ListView selection; output is clipboard text only.
    const int row = ListView_GetNextItem(resultList_, -1, LVNI_SELECTED);
    if (row < 0) {
        return;
    }
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::ObjectNamespaceOverview) {
        const auto cell = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
            for (const wchar_t* name : names) {
                for (int column = 0; column < static_cast<int>(currentColumns_.size()); ++column) {
                    if (_wcsicmp(currentColumns_[static_cast<std::size_t>(column)].c_str(), name) == 0) {
                        const std::wstring value = VisibleCellText(row, column);
                        if (!value.empty()) {
                            return value;
                        }
                    }
                }
            }
            return {};
        };
        const auto safe = [](const std::wstring& value) -> std::wstring {
            return value.empty() ? std::wstring(L"<空>") : value;
        };
        const std::wstring nodeKind = cell({ L"NodeKind" });
        if (_wcsicmp(nodeKind.c_str(), L"ObjectEntry") == 0 || nodeKind.empty()) {
            const std::wstring fields[] = {
                safe(cell({ L"rootPathText", L"Root", L"Source" })),
                safe(cell({ L"scopeDescriptionText", L"Scope", L"scope", L"Detail", L"路径/说明" })),
                safe(cell({ L"directoryPathText", L"directoryPath", L"Parent", L"Directory", L"来源目录" })),
                safe(cell({ L"objectNameText", L"objectName", L"Name", L"名称" })),
                safe(cell({ L"objectTypeText", L"objectType", L"Type", L"类型" })),
                safe(cell({ L"fullPathText", L"fullPath", L"Path", L"完整路径", L"路径/说明" })),
                safe(cell({ L"enumApiText", L"enumApi", L"EnumApi", L"枚举 API", L"EnumerationApi" })),
                safe(cell({ L"symbolicLinkTargetText", L"symbolicLinkTarget", L"symbolicTarget", L"Target", L"targetPath", L"符号链接目标" })),
                safe(cell({ L"statusText", L"Status", L"状态" })),
            };
            std::wstring text;
            for (std::size_t index = 0; index < std::size(fields); ++index) {
                if (index > 0) {
                    text += L'\t';
                }
                text += fields[index];
            }
            SetClipboardText(hwnd_, text);
            return;
        }
        std::wstring text;
        const wchar_t* treeFields[] = { L"名称", L"类型", L"路径/说明", L"状态", L"符号链接目标" };
        for (std::size_t index = 0; index < std::size(treeFields); ++index) {
            if (index > 0) {
                text += L'\t';
            }
            text += safe(cell({ treeFields[index] }));
        }
        SetClipboardText(hwnd_, text);
        return;
    }
    const int columns = HeaderColumnCount(resultList_);
    std::vector<int> copyColumns;
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor(); descriptor != nullptr) {
        copyColumns = PreferredCopyColumnIndices(descriptor->id, currentColumns_);
    }
    if (copyColumns.empty()) {
        copyColumns.reserve(static_cast<std::size_t>(columns));
        for (int column = 0; column < columns; ++column) {
            copyColumns.push_back(column);
        }
    }
    std::wstring text;
    for (std::size_t position = 0; position < copyColumns.size(); ++position) {
        if (position > 0) {
            text += L'\t';
        }
        const int column = copyColumns[position];
        if (column < 0 || column >= columns) {
            continue;
        }
        text += VisibleCellText(row, column);
    }
    SetClipboardText(hwnd_, text);
}

std::wstring KernelPage::BuildSelectedRowsTsv(const bool includeHeader) const {
    // BuildSelectedRowsTsv serializes the current multi-selection. Input chooses
    // whether to prepend the visible header row; processing walks LVNI_SELECTED
    // so sorted/filtered ListView state is honored; output is empty when no row
    // is selected.
    if (!resultList_) {
        return {};
    }
    const int columns = HeaderColumnCount(resultList_);
    std::vector<int> copyColumns;
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor(); descriptor != nullptr) {
        copyColumns = PreferredCopyColumnIndices(descriptor->id, currentColumns_);
    }
    if (copyColumns.empty()) {
        copyColumns.reserve(static_cast<std::size_t>(columns));
        for (int column = 0; column < columns; ++column) {
            copyColumns.push_back(column);
        }
    }
    std::wstring text;
    if (includeHeader) {
        for (std::size_t position = 0; position < copyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int column = copyColumns[position];
            text += column < static_cast<int>(currentColumns_.size())
                ? currentColumns_[static_cast<std::size_t>(column)]
                : std::wstring(L"Column") + std::to_wstring(column);
        }
    }
    int row = -1;
    bool wroteRow = false;
    while ((row = ListView_GetNextItem(resultList_, row, LVNI_SELECTED)) >= 0) {
        if (!text.empty()) {
            text += L"\r\n";
        }
        for (std::size_t position = 0; position < copyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int column = copyColumns[position];
            if (column < 0 || column >= columns) {
                continue;
            }
            text += VisibleCellText(row, column);
        }
        wroteRow = true;
    }
    return wroteRow ? text : std::wstring{};
}

void KernelPage::CopySelectedRows(const bool includeHeader) {
    // CopySelectedRows mirrors the original KernelDock multi-row TSV copy.
    // Input is includeHeader; processing serializes selected rows only; output
    // is clipboard text and a compact status message.
    const std::wstring text = BuildSelectedRowsTsv(includeHeader);
    if (text.empty()) {
        ::MessageBoxW(hwnd_, L"请先选择至少一条结果行。", L"复制选中行", MB_OK | MB_ICONINFORMATION);
        return;
    }
    SetClipboardText(hwnd_, text);
    ::SetWindowTextW(statusText_, includeHeader ? L"状态：已复制表头和选中行。" : L"状态：已复制选中行。");
}

void KernelPage::CopySelectedDetails() {
    // CopySelectedDetails mirrors the original "copy detail" menu. Inputs are
    // all selected ListView rows; processing concatenates each row's detail text;
    // output is clipboard text and detailEdit_ preview.
    if (!resultList_) {
        return;
    }
    std::wstring text;
    int row = -1;
    int count = 0;
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    const bool originalDetailOnly = descriptor != nullptr && IsOriginalDetailPreferredFeature(descriptor->id);
    while ((row = ListView_GetNextItem(resultList_, row, LVNI_SELECTED)) >= 0) {
        if (!text.empty()) {
            text += originalDetailOnly ? L"\r\n\r\n---\r\n\r\n" : L"\r\n\r\n";
        }
        if (!originalDetailOnly) {
            text += L"[Row ";
            text += std::to_wstring(row + 1);
            text += L"]\r\n";
        }
        text += BuildRowDetailText(row);
        ++count;
    }
    if (count == 0) {
        ::MessageBoxW(hwnd_, L"请先选择至少一条结果行。", L"复制详情", MB_OK | MB_ICONINFORMATION);
        return;
    }
    SetClipboardText(hwnd_, text);
    ::SetWindowTextW(detailEdit_, text.c_str());
    ::SetWindowTextW(statusText_, L"状态：已复制选中行详情。");
}

void KernelPage::CopySelectedColumn(const int columnIndex) {
    // CopySelectedColumn mirrors the original per-column copy submenu. Input is
    // a visible column index chosen from the popup menu; processing copies that
    // column for all selected rows, one value per line; output is clipboard text.
    if (!resultList_ || columnIndex < 0 || columnIndex >= HeaderColumnCount(resultList_)) {
        return;
    }
    std::wstring text;
    int row = -1;
    int count = 0;
    while ((row = ListView_GetNextItem(resultList_, row, LVNI_SELECTED)) >= 0) {
        if (!text.empty()) {
            text += L"\r\n";
        }
        text += VisibleCellText(row, columnIndex);
        ++count;
    }
    if (count == 0) {
        ::MessageBoxW(hwnd_, L"请先选择至少一条结果行。", L"复制指定栏目", MB_OK | MB_ICONINFORMATION);
        return;
    }
    SetClipboardText(hwnd_, text);
    ::SetWindowTextW(statusText_, L"状态：已复制指定栏目。");
}

std::vector<int> KernelPage::CurrentCopyColumnIndices() const {
    // CurrentCopyColumnIndices returns the table columns that user-facing copy
    // and export actions should include. Inputs are the active feature and
    // current dynamic schema; processing keeps hidden protocol columns out of
    // clipboard/TSV output; output falls back to every ListView column.
    const int columns = resultList_ ? HeaderColumnCount(resultList_) : 0;
    std::vector<int> copyColumns;
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor(); descriptor != nullptr) {
        copyColumns = PreferredCopyColumnIndices(descriptor->id, currentColumns_);
    }
    if (copyColumns.empty()) {
        copyColumns.reserve(static_cast<std::size_t>(columns));
        for (int column = 0; column < columns; ++column) {
            copyColumns.push_back(column);
        }
    }
    return copyColumns;
}


void KernelPage::CopyAllRows() {
    // CopyAllRows serializes the whole result grid as tab-separated rows. There
    // is no input beyond the current ListView content; output is clipboard text.
    const int rows = ListView_GetItemCount(resultList_);
    const int columns = HeaderColumnCount(resultList_);
    const std::vector<int> copyColumns = CurrentCopyColumnIndices();
    std::wstring text;
    for (int row = 0; row < rows; ++row) {
        if (row > 0) {
            text += L"\r\n";
        }
        for (std::size_t position = 0; position < copyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int column = copyColumns[position];
            if (column < 0 || column >= columns) {
                continue;
            }
            text += VisibleCellText(row, column);
        }
    }
    SetClipboardText(hwnd_, text);
}


void KernelPage::CopyDiagnosticReport() {
    // CopyDiagnosticReport exposes the original KernelDock DynData/DriverStatus
    // "copy diagnostic" workflow. Inputs are the current feature selection and
    // cached table rows; processing builds a plain-text report and places it on
    // the clipboard; no value is returned, but statusText_ is updated.
    const std::wstring report = BuildDiagnosticReportForCurrentFeature();
    if (report.empty()) {
        ::MessageBoxW(hwnd_, L"当前页没有可复制的诊断报告。", L"复制诊断", MB_OK | MB_ICONINFORMATION);
        return;
    }
    SetClipboardText(hwnd_, report);
    ::SetWindowTextW(detailEdit_, report.c_str());
    ::SetWindowTextW(statusText_, L"状态：已复制诊断报告。");
}

std::wstring KernelPage::BuildDiagnosticReportForCurrentFeature() const {
    // BuildDiagnosticReportForCurrentFeature mirrors the original helper
    // buildDynDataReport/buildDriverStatusReport. Inputs are currentRows_ and
    // currentColumns_; processing emits summary key/value lines followed by the
    // visible field/capability matrix; output is empty for non-diagnostic pages.
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    if (descriptor == nullptr) {
        return {};
    }

    const auto rowValue = [&](const std::vector<std::wstring>& row, std::initializer_list<const wchar_t*> names) -> std::wstring {
        return RowFieldByName(row, currentColumns_, names);
    };
    const auto firstValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring value = rowValue(row, names);
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };
    const auto firstRawValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        const std::vector<std::wstring>& rawColumns = !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_;
        const std::vector<std::vector<std::wstring>>& rawRows = !currentRawRows_.empty() ? currentRawRows_ : currentRows_;
        for (const std::vector<std::wstring>& row : rawRows) {
            const std::wstring value = RowFieldByName(row, rawColumns, names);
            if (!value.empty()) {
                return value;
            }
        }
        return {};
    };
    const auto firstAnyValue = [&](std::initializer_list<const wchar_t*> names) -> std::wstring {
        const std::wstring visible = firstValue(names);
        return visible.empty() ? firstRawValue(names) : visible;
    };
    const auto appendTableHeader = [&](std::wostringstream& report) {
        const std::vector<int> copyColumns = CurrentCopyColumnIndices();
        for (std::size_t position = 0; position < copyColumns.size(); ++position) {
            if (position > 0) {
                report << L'\t';
            }
            const int column = copyColumns[position];
            if (column >= 0 && column < static_cast<int>(currentColumns_.size())) {
                report << currentColumns_[static_cast<std::size_t>(column)];
            }
        }
        report << L"\r\n";
    };
    const auto appendTableRows = [&](std::wostringstream& report) {
        const std::vector<int> copyColumns = CurrentCopyColumnIndices();
        for (const std::vector<std::wstring>& row : currentRows_) {
            for (std::size_t position = 0; position < copyColumns.size(); ++position) {
                if (position > 0) {
                    report << L'\t';
                }
                const int column = copyColumns[position];
                if (column < row.size()) {
                    report << row[static_cast<std::size_t>(column)];
                }
            }
            report << L"\r\n";
        }
    };

    if (descriptor->id == KernelFeatureId::DynData) {
        std::size_t fieldRows = 0;
        std::size_t profileRows = 0;
        std::size_t failedRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring field = rowValue(row, { L"Field", L"字段", L"Name" });
            const std::wstring source = rowValue(row, { L"Source", L"来源" });
            const std::wstring status = rowValue(row, { L"Status", L"状态", L"DynData Fields IO" });
            if (!field.empty()) {
                ++fieldRows;
            }
            if (ContainsCaseInsensitive(source, L"profile") || ContainsCaseInsensitive(source, L"pack") ||
                ContainsCaseInsensitive(source, L"pdb")) {
                ++profileRows;
            }
            if (ContainsCaseInsensitive(status, L"fail") || ContainsCaseInsensitive(status, L"失败") ||
                ContainsCaseInsensitive(status, L"missing")) {
                ++failedRows;
            }
        }

        std::wostringstream report;
        report << L"Ksword DynData Diagnostic Report\r\n";
        report << L"========================================\r\n";
        AppendReportLine(report, L"StatusQueryOk", firstAnyValue({ L"StatusQueryOk" }));
        AppendReportLine(report, L"FieldsQueryOk", firstAnyValue({ L"FieldsQueryOk" }));
        AppendReportLine(report, L"StatusFlags", firstAnyValue({ L"StatusFlags" }));
        AppendReportLine(report, L"CapabilityMask", firstAnyValue({ L"CapabilityMask", L"Capability" }));
        AppendReportLine(report, L"SystemInformerDataVersion", firstAnyValue({ L"SI Version" }));
        AppendReportLine(report, L"SystemInformerDataLength", firstAnyValue({ L"SI Length" }));
        AppendReportLine(report, L"LastStatus", firstAnyValue({ L"LastStatus" }));
        AppendReportLine(report, L"MatchedProfileClass", firstAnyValue({ L"MatchedClass", L"ProfileClass" }));
        AppendReportLine(report, L"MatchedProfileOffset", firstAnyValue({ L"MatchedProfileOffset" }));
        AppendReportLine(report, L"MatchedFieldsId", firstAnyValue({ L"MatchedFieldsId" }));
        AppendReportLine(report, L"UnavailableReason", firstAnyValue({ L"UnavailableReason" }));
        AppendReportLine(report, L"PdbProfileActive", FlagEnabled(FirstRowUInt64(!currentRawRows_.empty() ? currentRawRows_ : currentRows_,
            !currentRawColumns_.empty() ? currentRawColumns_ : currentColumns_, { L"StatusFlags" }), KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE) ? L"是" : L"否");
        AppendReportLine(report, L"PdbProfileScanAttempted", firstAnyValue({ L"PdbProfileScanAttempted" }));
        AppendReportLine(report, L"PdbProfileFound", firstAnyValue({ L"PdbProfileFound" }));
        AppendReportLine(report, L"PdbProfileAppliedThisRefresh", firstAnyValue({ L"PdbProfileApplied" }));
        AppendReportLine(report, L"PdbProfileSource", firstAnyValue({ L"PdbProfileSource" }));
        AppendReportLine(report, L"PdbProfileName", firstAnyValue({ L"PdbProfileName", L"Profile" }));
        AppendReportLine(report, L"PdbProfilePath", firstAnyValue({ L"PdbProfilePath", L"ProfilePath" }));
        AppendReportLine(report, L"PdbProfileStatus", firstAnyValue({ L"PdbProfileStatus" }));
        AppendReportLine(report, L"PdbProfileAppliedFields", firstAnyValue({ L"PdbProfileAppliedFields" }));
        AppendReportLine(report, L"PdbProfileRejectedFields", firstAnyValue({ L"PdbProfileRejectedFields" }));
        AppendReportLine(report, L"PdbProfileUnknownFields", firstAnyValue({ L"PdbProfileUnknownFields" }));
        AppendReportLine(report, L"PdbProfileIgnoredJsonFields", firstAnyValue({ L"PdbProfileIgnoredJsonFields" }));
        AppendReportLine(report, L"PdbProfileMessage", firstAnyValue({ L"PdbProfileMessage" }));
        AppendReportLine(report, L"PdbProfileIo", firstAnyValue({ L"PdbProfileIo" }));
        AppendReportLine(report, L"Ntos", firstAnyValue({ L"Ntos", L"NtosIdentity" }));
        AppendReportLine(report, L"Lxcore", firstAnyValue({ L"Lxcore", L"LxcoreIdentity" }));
        AppendReportLine(report, L"FieldCount", firstAnyValue({ L"FieldCount", L"FieldsTotal" }));
        AppendReportLine(report, L"FieldsReturned", firstAnyValue({ L"FieldsReturned" }));
        report << L"VisibleFieldRows: " << fieldRows << L"\r\n";
        report << L"ProfileDiagnosticRows: " << profileRows << L"\r\n";
        report << L"FailedDiagnosticRows: " << failedRows << L"\r\n\r\n";
        report << L"Capabilities:\r\n";
        std::uint64_t capabilityMask = 0;
        HexToUInt64(firstAnyValue({ L"CapabilityMask", L"Capability" }), capabilityMask);
        report << DynCapabilityNames(capabilityMask) << L"\r\n\r\n";
        report << L"Fields\r\n";
        report << L"----------------------------------------\r\n";
        appendTableHeader(report);
        appendTableRows(report);
        return report.str();
    }

    if (descriptor->id == KernelFeatureId::DriverStatus) {
        std::size_t capabilityRows = 0;
        std::size_t unavailableRows = 0;
        std::size_t dynDataDependentRows = 0;
        for (const std::vector<std::wstring>& row : currentRows_) {
            const std::wstring feature = rowValue(row, { L"Feature", L"功能", L"Name" });
            const std::wstring state = rowValue(row, { L"State", L"状态", L"Status" });
            const std::wstring requiredDyn = rowValue(row, { L"RequiredDyn", L"所需DynData" });
            if (!feature.empty()) {
                ++capabilityRows;
            }
            if (ContainsCaseInsensitive(state, L"unavailable") || ContainsCaseInsensitive(state, L"disabled") ||
                ContainsCaseInsensitive(state, L"不可用") || ContainsCaseInsensitive(state, L"禁用")) {
                ++unavailableRows;
            }
            if (!requiredDyn.empty() && requiredDyn != L"0" && requiredDyn != L"0x0" && requiredDyn != L"0x0000000000000000") {
                ++dynDataDependentRows;
            }
        }

        std::wostringstream report;
        report << L"Ksword Driver Capability Diagnostic Report\r\n";
        report << L"========================================\r\n";
        AppendReportLine(report, L"Status", firstAnyValue({ L"StatusBadges" }));
        AppendReportLine(report, L"QueryOk", firstAnyValue({ L"IO" }));
        AppendReportLine(report, L"IoMessage", firstAnyValue({ L"IoMessage", L"Driver Capabilities" }));
        AppendReportLine(report, L"CapabilityProtocolVersion", firstAnyValue({ L"Version" }));
        AppendReportLine(report, L"DriverProtocolVersion", firstAnyValue({ L"Protocol" }));
        AppendReportLine(report, L"ExpectedDriverProtocolVersion", firstAnyValue({ L"ExpectedProtocol" }));
        AppendReportLine(report, L"StatusFlags", firstAnyValue({ L"StatusFlags" }));
        std::uint64_t policyMask = 0;
        HexToUInt64(firstAnyValue({ L"SecurityPolicy", L"Policy", L"策略" }), policyMask);
        AppendReportLine(report, L"SecurityPolicyFlags", firstAnyValue({ L"SecurityPolicy", L"Policy", L"策略" }) +
            L" (" + SecurityPolicyNames(static_cast<std::uint32_t>(policyMask)) + L")");
        std::uint64_t dynStatusFlags = 0;
        HexToUInt64(firstAnyValue({ L"DynDataStatus" }), dynStatusFlags);
        AppendReportLine(report, L"DynDataStatusFlags", firstAnyValue({ L"DynDataStatus" }) +
            L" (" + DynDataStatusFlagsText(static_cast<std::uint32_t>(dynStatusFlags)) + L")");
        std::uint64_t dynCapability = 0;
        HexToUInt64(firstAnyValue({ L"DynDataCapability", L"CapabilityMask" }), dynCapability);
        AppendReportLine(report, L"DynDataCapabilityMask", firstAnyValue({ L"DynDataCapability", L"CapabilityMask" }) +
            L" (" + DynCapabilityNames(dynCapability) + L")");
        AppendReportLine(report, L"DynDataStatusQueryOk", firstAnyValue({ L"DynDataStatusQueryOk" }));
        AppendReportLine(report, L"DynDataFieldsQueryOk", firstAnyValue({ L"DynDataFieldsQueryOk" }));
        AppendReportLine(report, L"CurrentKernel", firstAnyValue({ L"NtosIdentity", L"Ntos" }));
        AppendReportLine(report, L"RecognizedVersion", firstAnyValue({ L"LocalPdbVersion", L"KernelVersion" }));
        AppendReportLine(report, L"LocalPdbProfileMatched", firstAnyValue({ L"LocalPdbProfileMatched" }));
        AppendReportLine(report, L"LocalPdbProfileName", firstAnyValue({ L"LocalPdbProfileName" }));
        AppendReportLine(report, L"LocalPdbProfilePath", firstAnyValue({ L"LocalPdbProfilePath" }));
        AppendReportLine(report, L"LocalPdbProfileMessage", firstAnyValue({ L"LocalPdbMessage", L"LocalPdbProfile" }));
        AppendReportLine(report, L"ActiveProcessLinksOffset", firstAnyValue({ L"ActiveProcessLinksOffset" }));
        AppendReportLine(report, L"CallbackProfileCoverage", firstAnyValue({ L"CallbackProfileCoverage" }));
        AppendReportLine(report, L"PdbProfileActive", firstAnyValue({ L"PdbProfileActive" }));
        AppendReportLine(report, L"CallbackProfileActive", firstAnyValue({ L"CallbackProfileActive" }));
        AppendReportLine(report, L"TrustedPdbOffsetsActive", firstAnyValue({ L"TrustedPdbOffsetsActive" }));
        AppendReportLine(report, L"TrustedOffsetSummary", firstAnyValue({ L"TrustedOffset" }));
        AppendReportLine(report, L"FieldCoverage", firstAnyValue({ L"FieldCoverage" }));
        AppendReportLine(report, L"FieldSources", firstAnyValue({ L"FieldSources" }));
        AppendReportLine(report, L"SystemInformerData", L"version=" + firstAnyValue({ L"SI Version" }) +
            L" length=" + firstAnyValue({ L"SI Length" }));
        AppendReportLine(report, L"MatchedProfile", L"class=" + firstAnyValue({ L"MatchedClass" }) +
            L" offset=" + firstAnyValue({ L"MatchedProfileOffset" }) +
            L" fieldsId=" + firstAnyValue({ L"MatchedFieldsId" }));
        AppendReportLine(report, L"DynDataUnavailableReason", firstAnyValue({ L"UnavailableReason" }));
        AppendReportLine(report, L"DynDataIo", L"Status=" + firstAnyValue({ L"DynDataStatusQueryOk" }) +
            L" (" + firstAnyValue({ L"DynDataStatusIo" }) + L")；Fields=" +
            firstAnyValue({ L"DynDataFieldsQueryOk" }) + L" (" + firstAnyValue({ L"DynDataFieldsIo" }) + L")");
        AppendReportLine(report, L"LastError", firstAnyValue({ L"LastErrorStatus" }) + L" / " +
            firstAnyValue({ L"LastError" }) + L" / " + firstAnyValue({ L"LastErrorSummary" }));
        AppendReportLine(report, L"FeatureCount", L"returned=" + firstAnyValue({ L"FeatureReturned" }) +
            L" total=" + firstAnyValue({ L"FeatureTotal" }));
        report << L"VisibleCapabilityRows: " << capabilityRows << L"\r\n";
        report << L"UnavailableRows: " << unavailableRows << L"\r\n";
        report << L"DynDataDependentRows: " << dynDataDependentRows << L"\r\n\r\n";
        report << L"Capabilities\r\n";
        report << L"----------------------------------------\r\n";
        appendTableHeader(report);
        appendTableRows(report);
        return report.str();
    }

    return {};
}

void KernelPage::ExportAllRowsTsv() {
    // ExportAllRowsTsv captures the visible table text and sends the disk write
    // through the shared file-I/O task so slow folders cannot freeze the dock.
    if (callbackFileIoTask_ && callbackFileIoTask_->running()) {
        ::SetWindowTextW(statusText_, L"状态：文件任务正在后台执行，请等待完成。");
        return;
    }
    wchar_t path[MAX_PATH] = L"kernel_rows.tsv";
    if (const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
        descriptor != nullptr && descriptor->id == KernelFeatureId::DeviceDriverObjects) {
        wcscpy_s(path, L"kernel_device_driver_objects.tsv");
    }
    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd_;
    ofn.lpstrFilter = L"TSV (*.tsv)\0*.tsv\0Text (*.txt)\0*.txt\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = path;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"tsv";
    if (!::GetSaveFileNameW(&ofn)) {
        return;
    }
    const int rows = resultList_ ? ListView_GetItemCount(resultList_) : 0;
    const int columns = resultList_ ? HeaderColumnCount(resultList_) : 0;
    const std::vector<int> copyColumns = CurrentCopyColumnIndices();
    std::wstring text;
    for (std::size_t position = 0; position < copyColumns.size(); ++position) {
        if (position > 0) {
            text += L'\t';
        }
        const int column = copyColumns[position];
        text += column < static_cast<int>(currentColumns_.size())
            ? currentColumns_[static_cast<std::size_t>(column)]
            : std::wstring(L"Column") + std::to_wstring(column);
    }
    for (int row = 0; row < rows; ++row) {
        text += L"\r\n";
        for (std::size_t position = 0; position < copyColumns.size(); ++position) {
            if (position > 0) {
                text += L'\t';
            }
            const int column = copyColumns[position];
            if (column < 0 || column >= columns) {
                continue;
            }
            text += VisibleCellText(row, column);
        }
    }
    StartCallbackFileIo(CallbackFileIoOperation::ExportResultTsv, path, std::move(text));
}

const KernelFeatureDescriptor* KernelPage::CurrentDescriptor() const {
    if (hasDirectFeatureId_) {
        return FeatureById(directFeatureId_);
    }
    const int primary = CurrentPrimaryIndex();
    if (primary < 0 || primary >= static_cast<int>(primaryFeatureIds_.size())) {
        return nullptr;
    }
    KernelFeatureId featureId = primaryFeatureIds_[static_cast<std::size_t>(primary)];
    if (!secondaryFeatureIds_.empty()) {
        const int secondary = CurrentSecondaryIndex();
        if (secondary >= 0 && secondary < static_cast<int>(secondaryFeatureIds_.size())) {
            featureId = secondaryFeatureIds_[static_cast<std::size_t>(secondary)];
        }
    }
    return FeatureById(featureId);
}

const KernelFeatureDescriptor* KernelPage::FeatureById(const KernelFeatureId featureId) const {
    // FeatureById resolves one stable feature id into catalog metadata. Input is
    // a KernelFeatureId from the original-tab mapping; output is null only when
    // a future catalog accidentally omits that page.
    const auto found = std::find_if(features_.begin(), features_.end(), [featureId](const KernelFeatureDescriptor& descriptor) {
        return descriptor.id == featureId;
    });
    return found == features_.end() ? nullptr : &(*found);
}

bool KernelPage::CurrentPrimaryUsesSecondaryTabs() const {
    // A page embedded as a single feature is already hosted by an outer dock;
    // exposing this page's own group tabs would duplicate that navigation.
    if (hasDirectFeatureId_) {
        return false;
    }
    const int primary = CurrentPrimaryIndex();
    return primary >= 0 &&
        primary < static_cast<int>(primaryFeatureIds_.size()) &&
        !secondaryFeatureIds_.empty();
}

void KernelPage::ClearResultGridOnly() {
    // ClearResultGridOnly clears only the owner-data result grid. Inputs are
    // the current resultList_ HWND; processing drops the visible row count and
    // column headers but deliberately leaves auxiliary tree/property/summary
    // controls intact for cached tab restoration. It has no return value.
    if (!resultList_) {
        return;
    }
    ListView_SetItemCountEx(resultList_, 0, LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
    HWND header = ListView_GetHeader(resultList_);
    const int count = header ? Header_GetItemCount(header) : 0;
    for (int index = count - 1; index >= 0; --index) {
        ListView_DeleteColumn(resultList_, index);
    }
}

void KernelPage::ClearResultTable() {
    // ClearResultTable clears the main result grid and all auxiliary views for
    // a real data rebuild. Inputs are owned child HWNDs; processing resets UI
    // state only and never mutates currentRows_; there is no return value.
    ClearResultGridOnly();
    if (objectNamespaceTree_) {
        TreeView_DeleteAllItems(objectNamespaceTree_);
    }
    if (propertyList_) {
        ListView_DeleteAllItems(propertyList_);
    }
    if (summaryList_) {
        ListView_DeleteAllItems(summaryList_);
    }
}

void KernelPage::AddResultTableColumn(int index, const std::wstring& title, int width) {
    if (!resultList_) {
        return;
    }
    LVCOLUMNW column{};
    column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
    column.fmt = LVCFMT_LEFT;
    column.cx = width;
    column.pszText = const_cast<LPWSTR>(title.c_str());
    ListView_InsertColumn(resultList_, index, &column);
}

void KernelPage::AddResultTableRow(const std::vector<std::wstring>& cells) {
    AddResultTableRow(cells, 0);
}

void KernelPage::AddResultTableRow(const std::vector<std::wstring>& cells, const int indent) {
    // AddResultTableRow appends one in-memory row for compatibility with small
    // legacy paths. Inputs are cell text plus optional tree indent; processing
    // never calls Win32 per row, so callers must invoke SyncResultListVirtualRows
    // once after batch population; there is no return value.
    if (cells.empty()) {
        return;
    }
    currentRows_.push_back(cells);
    currentRowIndents_.push_back(std::max(0, std::min(indent, 32)));
}

int KernelPage::CurrentPrimaryIndex() const {
    if (!primaryTab_) {
        return -1;
    }
    return static_cast<int>(::SendMessageW(primaryTab_, TCM_GETCURSEL, 0, 0));
}

int KernelPage::CurrentSecondaryIndex() const {
    if (!secondaryTab_) {
        return -1;
    }
    return static_cast<int>(::SendMessageW(secondaryTab_, TCM_GETCURSEL, 0, 0));
}

bool KernelPage::CurrentFeatureUsesVerticalSplitter() const {
    // CurrentFeatureUsesVerticalSplitter matches the pages that were QSplitter
    // based in the original KernelDock. Inputs are current tab state only;
    // output is true when the result table/detail editor divider is active.
    const KernelFeatureDescriptor* descriptor = CurrentDescriptor();
    return descriptor != nullptr &&
        (IsKernelHookFeature(descriptor->id) || IsR0TableDetailFeature(descriptor->id));
}

void KernelPage::MoveVerticalSplitterFromMouse(const int mouseY) {
    // MoveVerticalSplitterFromMouse updates the table/detail split while the
    // user drags the divider. Input is client-space mouse Y; processing clamps
    // the table height so both panes stay usable; there is no return value.
    if (!CurrentFeatureUsesVerticalSplitter()) {
        return;
    }
    RECT rc{};
    ::GetClientRect(hwnd_, &rc);
    const int tabHeight = 28;
    const bool showSecondary = CurrentPrimaryUsesSecondaryTabs();
    const int contentTop = tabHeight + (showSecondary ? tabHeight : 0);
    const int splitterPanelTop = contentTop + 28;
    const int availableHeight = std::max(0, Height(rc) - splitterPanelTop);
    const int minimumTableHeight = 88;
    const int minimumDetailHeight = 88;
    const int maximumTableHeight = std::max(minimumTableHeight,
        availableHeight - minimumDetailHeight - kKernelSplitterThickness);
    verticalSplitterOffset_ = ClampInt(mouseY - splitterPanelTop, minimumTableHeight, maximumTableHeight);
    Layout();
}

HWND CreateKernelPage(HWND parent, const int controlId, const RECT& bounds) {
    auto* page = new KernelPage();
    HWND hwnd = page->Create(parent, controlId, bounds);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

HWND CreateKernelPageForFeature(HWND parent, const int controlId, const RECT& bounds, const KernelFeatureId featureId) {
    // CreateKernelPageForFeature creates a normal kernel page and preselects one
    // feature for embedding under Memory/Driver/Hardware docks. Inputs are
    // parent/control/bounds plus the feature id; output is an owning HWND.
    auto* page = new KernelPage();
    page->SetInitialFeature(featureId);
    HWND hwnd = page->Create(parent, controlId, bounds);
    if (!hwnd) {
        delete page;
    }
    return hwnd;
}

} // namespace Ksword::Features::Kernel


