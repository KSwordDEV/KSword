#include "../../../shared/usermode/backend/security/AppLocker.h"
#include "../../../shared/usermode/backend/security/HyperV.h"
#include "../../../shared/usermode/backend/security/Vbs.h"
#include "../../../shared/usermode/backend/security/CodeIntegrity.h"
#include "MiscFeature.h"

#include "../../Ui/AsyncTask.h"
#include "../../Ui/Controls.h"
#include "../../Ui/FilterBar.h"
#include "../../Ui/ListViewUtil.h"
#include "../../Ui/LoadingOverlay.h"
#include "../../Ui/TabUtil.h"
#include "../../Ui/Theme.h"
#include "../../Ui/VirtualListView.h"
#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <commctrl.h>
#include <windowsx.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace Ksword::Features::Misc {
namespace {
using namespace ks::r3::security;
using namespace ks::r3::security;
using namespace ks::r3::security;
using namespace ks::r3::security;

constexpr wchar_t kMiscHostClass[] = L"KswordARKLight.MiscFeaturePage";
constexpr wchar_t kMiscAuditViewClass[] = L"KswordARKLight.MiscAuditView";
constexpr int kTabId = 69101;
constexpr int kListId = 69102;
constexpr int kRefreshButtonId = 69103;
constexpr int kCopyButtonId = 69104;
constexpr int kFilterBarId = 69105;
constexpr int kLoadingOverlayId = 69106;
constexpr int kBugcheckUploadButtonId = 69107;
constexpr int kCiTabIndex = 0;
constexpr int kVbsTabIndex = 1;
constexpr int kHyperVTabIndex = 2;
constexpr int kAppLockerTabIndex = 3;
constexpr int kAuxiliaryTabIndex = 4;
constexpr int kBugcheckTabIndex = 5;
constexpr int kHeaderHeight = 68;
constexpr int kGap = 6;
constexpr UINT kMenuRefresh = 69201;
constexpr UINT kMenuCopyRow = 69202;
constexpr UINT kMenuCopyAll = 69203;
constexpr UINT kMenuCopyCell = 69204;
constexpr UINT kMsgAuditRefreshCompleted = WM_APP + 603;
constexpr UINT kMsgAuditFilterCompleted = WM_APP + 604;
constexpr UINT kMsgBugcheckUploadCompleted = WM_APP + 605;

enum class MiscAuditPageId {
    CodeIntegrity,
    VbsHvciSkci,
    HyperV,
    AppLocker,
    BamAhcache,
    Bugcheck,
};

// MiscAuditRow is the value-only evidence record rendered into each ListView.
// Inputs come from read-only R3 commands, registry reads, service status queries
// and ArkDriverClient diagnostics. Processing stores only display strings;
// output is consumed by PopulateAuditList and clipboard export helpers.


struct MiscAuditRefreshResult {
    MiscAuditPageId pageId = MiscAuditPageId::CodeIntegrity;
    std::vector<MiscAuditRow> rows;
};

struct MiscAuditFilterResult {
    std::uint64_t generation = 0;
    std::wstring query;
    bool useRegex = false;
    std::vector<std::size_t> visibleIndexes;
};

// BugcheckUploadResult holds the value-only transport outcome of the explicit
// VMware diagnostic branding upload. It deliberately carries no bitmap bytes.
struct BugcheckUploadResult {
    ksword::ark::IoResult io;
};

// CommandResult captures bounded stdout/stderr from an external read-only query.
// Inputs are filled by RunCaptureCommand; processing later turns exit code and
// captured text into UI rows. No handles are retained after the command returns.


// MiscAuditViewState owns one tab page and its row snapshot. Inputs arrive from
// Win32 messages; processing refreshes only the local page and never performs
// patch/delete/bypass/remove/unlink operations. There is no shared global state.
struct MiscAuditViewState {
    HWND hwnd = nullptr;
    HWND refreshButton = nullptr;
    HWND copyButton = nullptr;
    HWND bugcheckUploadButton = nullptr;
    HWND filterBar = nullptr;
    HWND list = nullptr;
    HWND loadingOverlay = nullptr;
    MiscAuditPageId pageId = MiscAuditPageId::CodeIntegrity;
    std::wstring title;
    std::wstring statusText;
    std::vector<MiscAuditRow> rows;
    std::vector<MiscAuditRow> visibleRows;
    Ksword::Ui::VirtualListView virtualList;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> filterRows;
    std::wstring filterQuery;
    bool filterUseRegex = false;
    std::uint64_t snapshotGeneration = 0;
    int contextColumn = 0;
    bool hasLoaded = false;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<MiscAuditRefreshResult>> refreshTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<MiscAuditFilterResult>> filterTask;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<BugcheckUploadResult>> bugcheckUploadTask;
};

// MiscFeaturePageState owns the tab host and retained child pages. Inputs arrive
// through the host window procedure; processing switches visibility only, so each
// tab keeps its last snapshot and diagnostics until explicitly refreshed.
struct MiscFeaturePageState {
    HWND hwnd = nullptr;
    HWND tab = nullptr;
    HWND ciView = nullptr;
    HWND vbsView = nullptr;
    HWND hypervView = nullptr;
    HWND appLockerView = nullptr;
    HWND auxiliaryView = nullptr;
    HWND bugcheckView = nullptr;
    int currentTab = kCiTabIndex;
};

// Width returns a non-negative RECT width. Input is a Win32 RECT; output is the
// client width used by layout code.
int Width(const RECT& rc) {
    return rc.right > rc.left ? rc.right - rc.left : 0;
}

// Height returns a non-negative RECT height. Input is a Win32 RECT; output is
// the client height used by layout code.
int Height(const RECT& rc) {
    return rc.bottom > rc.top ? rc.bottom - rc.top : 0;
}

// StateFromAuditView reads the MiscAuditViewState pointer from a child HWND.
// Input is the page HWND; output is null before WM_NCCREATE or after destroy.
MiscAuditViewState* StateFromAuditView(HWND hwnd) {
    return reinterpret_cast<MiscAuditViewState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// StateFromHost reads the MiscFeaturePageState pointer from the host HWND. Input
// is the host HWND; output is null before creation or after destruction.
MiscFeaturePageState* StateFromHost(HWND hwnd) {
    return reinterpret_cast<MiscFeaturePageState*>(::GetWindowLongPtrW(hwnd, GWLP_USERDATA));
}

// TrimCopy removes leading and trailing whitespace from display command output.
// Input is any captured string; processing does not alter interior newlines;
// output is a new trimmed string.


// CollapseWhitespace converts multi-line command output into compact cell text.
// Input is a captured string; processing replaces CR/LF/TAB runs with spaces;
// output is bounded by the caller when inserted into the ListView.


// QuotePowerShellCommand wraps a script body in a PowerShell script block.
// Input is one read-only command body; processing keeps the body executable by
// powershell.exe while avoiding cmd.exe parsing; output is used only locally.


// GetLastErrorText formats a Win32 error. Input is a DWORD error code; output is
// a readable message with the numeric value retained for diagnostics.


// AppendRow appends one evidence row to a vector. Inputs are display fields and
// optional detail; processing copies them into the row list; no value is returned.


// RunCaptureCommand starts a bounded child process and captures stdout/stderr.
// Inputs are the full command line and timeout in milliseconds; processing uses
// anonymous pipes, waits without injecting input, and terminates only the helper
// process if it exceeds the local UI budget; output includes failure reason.


// PowerShellCommand builds a hidden, non-profile PowerShell invocation for local
// read-only posture queries. Input is a script body; output is a command line for
// RunCaptureCommand. The script is expected to avoid mutation cmdlets.


// RunPowerShellScalar executes one PowerShell query and returns compact output.
// Inputs are a script body and timeout; processing captures stdout/stderr and
// keeps the failure reason if PowerShell/WMI is unavailable; output is a command
// result suitable for AddCommandRow.


// AddCommandRow converts a command result into one evidence row. Inputs identify
// the evidence and command source; processing stores either output or an explicit
// failure reason; no value is returned.


// QueryRegistryValueString reads one HKLM value without writing registry state.
// Inputs are a subkey and value name; processing uses RegOpenKeyEx/RegQueryValueEx
// with KEY_READ only; output is true when a display value was extracted.


// AddRegistryRow appends one read-only registry evidence row. Inputs are HKLM
// path/value labels; processing never writes or creates keys; no value is returned.


// QueryServiceStatusText reads one service/driver status with the Service Control
// Manager using query access only. Inputs are a service name; output is true with
// status text or false with a failure reason.


// AddServiceRow appends one SCM status row. Inputs are a display category/item
// and SCM service name; processing uses query-only SCM handles; no return value.


// AddDriverCapabilityRow queries existing ArkDriverClient capability status as
// the only R0-facing check in this module. Inputs are a row list and scope label;
// processing calls the existing wrapper and never opens DeviceIoControl directly;
// no value is returned.
void AddDriverCapabilityRow(std::vector<MiscAuditRow>& rows, const std::wstring& scope) {
    const ksword::ark::DriverClient client;
    const ksword::ark::DriverCapabilitiesQueryResult capability = client.queryDriverCapabilities();
    if (capability.io.ok) {
        std::wostringstream detail;
        detail << L"Protocol=" << capability.driverProtocolVersion
               << L"; StatusFlags=0x" << std::hex << std::uppercase << capability.statusFlags
               << L"; DynData=0x" << capability.dynDataStatusFlags
               << L"; Returned=" << std::dec << capability.returnedFeatureCount << L"/" << capability.totalFeatureCount;
        AppendRow(rows, scope, L"KswordARK R0 capability", L"Online", L"ArkDriverClient::queryDriverCapabilities", L"Info", detail.str());
    } else {
        std::wstring detail = L"R0 能力查询失败：Win32=" + std::to_wstring(capability.io.win32Error) + L"; " +
            std::wstring(capability.io.message.begin(), capability.io.message.end());
        AppendRow(rows, scope, L"KswordARK R0 capability", L"Unavailable", L"ArkDriverClient::queryDriverCapabilities", L"Unknown", detail);
    }
}

// AddSecurityAuditRows 调用新增 ArkDriverClient 安全审计 wrapper。
// 输入：目标 rows 和页面 scope。
// 处理：按当前页面追加 Security/DriverTrust/HyperV/AppControl 的只读摘要。
// 返回：无返回值；所有失败原因保留在详情列，不裸 DeviceIoControl。
void AddSecurityAuditRows(std::vector<MiscAuditRow>& rows, const std::wstring& scope) {
    const ksword::ark::DriverClient client;
    const auto security = client.querySecurityStatus();
    {
        std::wostringstream detail;
        detail << L"Win32=" << security.io.win32Error
               << L"; QueryStatus=0x" << std::hex << std::uppercase << static_cast<unsigned long>(security.response.queryStatus)
               << L"; CIOptions=0x" << security.response.codeIntegrityOptions
               << L"; SecureBoot=" << std::dec << security.response.secureBootEnabled
               << L"; VBS=" << security.response.vbsPresent
               << L"; HVCI=" << security.response.hvciKmciEnabled
               << L"; TestSigning=" << security.response.testSigningEnabled;
        AppendRow(rows, scope, L"R0 SecurityStatus", security.io.ok ? L"OK" : (security.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::querySecurityStatus", security.io.ok ? L"Info" : L"Unknown", detail.str());
    }

    const auto trust = client.queryDriverTrustView();
    {
        std::wostringstream detail;
        detail << L"Win32=" << trust.io.win32Error
               << L"; total=" << trust.totalCount
               << L"; returned=" << trust.returnedCount
               << L"; truncated=" << trust.truncated
               << L"; moduleStatus=0x" << std::hex << std::uppercase << static_cast<unsigned long>(trust.moduleQueryStatus);
        AppendRow(rows, scope, L"R0 DriverTrustView", trust.io.ok ? L"OK" : (trust.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::queryDriverTrustView", trust.truncated ? L"Partial" : L"Info", detail.str());
    }

    const auto hyperv = client.queryHyperVSummary();
    {
        std::wostringstream detail;
        detail << L"Win32=" << hyperv.io.win32Error
               << L"; Hypervisor=" << hyperv.response.hypervisorPresent
               << L"; VMBus=" << hyperv.response.vmbusStatus
               << L"; vSwitch=" << hyperv.response.vSwitchStatus
               << L"; vPCI=" << hyperv.response.vPciStatus
               << L"; vendor=" << hyperv.response.hypervisorVendor;
        AppendRow(rows, scope, L"R0 HyperVSummary", hyperv.io.ok ? L"OK" : (hyperv.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::queryHyperVSummary", hyperv.io.ok ? L"Info" : L"Unknown", detail.str());
    }

    const auto appControl = client.queryAppControlStatus();
    {
        std::wostringstream detail;
        detail << L"Win32=" << appControl.io.win32Error
               << L"; AppID=" << appControl.response.appidStatus
               << L"; AppLockerFilter=" << appControl.response.appLockerFilterStatus
               << L"; mssecflt=" << appControl.response.mssecfltStatus
               << L"; BAM=" << appControl.response.bamStatus
               << L"; owner=" << appControl.response.appLockerOwnerModule;
        AppendRow(rows, scope, L"R0 AppControlStatus", appControl.io.ok ? L"OK" : (appControl.unsupported ? L"Unsupported" : L"Unavailable"), L"ArkDriverClient::queryAppControlStatus", appControl.io.ok ? L"Info" : L"Unknown", detail.str());
    }
}

// CollectCodeIntegrityRows gathers CI/WDAC posture evidence through documented
// R3 queries and registry reads. There is no input; output is a row vector for
// the Code Integrity / WDAC tab.
std::vector<MiscAuditRow> CollectCodeIntegrityRows() {
    std::vector<MiscAuditRow> rows;
    AddDriverCapabilityRow(rows, L"Code Integrity / WDAC");
    AddSecurityAuditRows(rows, L"Code Integrity / WDAC");
    ks::r3::security::AppendCodeIntegrityR3(rows);

    return rows;
}




// CollectVbsRows gathers VBS/HVCI/SKCI evidence from DeviceGuard CIM, systeminfo
// and service/module presence. There is no input; output is a row vector for the
// VBS/HVCI/SKCI tab.
std::vector<MiscAuditRow> CollectVbsRows() {
    std::vector<MiscAuditRow> rows;
    AddDriverCapabilityRow(rows, L"VBS / HVCI / SKCI");
    AddSecurityAuditRows(rows, L"VBS / HVCI / SKCI");
    ks::r3::security::AppendVbsR3(rows);

    return rows;
}




// CollectHyperVRows gathers Hyper-V, VMBus, vSwitch, vPCI and HvSocket posture
// with read-only service/module/CIM evidence. There is no input; output is a row
// vector for the Hyper-V tab.
std::vector<MiscAuditRow> CollectHyperVRows() {
    std::vector<MiscAuditRow> rows;
    AddDriverCapabilityRow(rows, L"Hyper-V / VMBus / HvSocket");
    AddSecurityAuditRows(rows, L"Hyper-V / VMBus / HvSocket");
    ks::r3::security::AppendHyperVR3(rows);

    return rows;
}




// CollectAppLockerRows gathers AppID/AppLocker/appid.sys/applockerfltr/mssecflt
// evidence without policy mutation or rule export. There is no input; output is
// a row vector for the AppLocker tab.
std::vector<MiscAuditRow> CollectAppLockerRows() {
    std::vector<MiscAuditRow> rows;
    AddDriverCapabilityRow(rows, L"AppLocker / AppID");
    AddSecurityAuditRows(rows, L"AppLocker / AppID");
    ks::r3::security::AppendAppLockerR3(rows);

    return rows;
}




// CollectAuxiliaryRows gathers BAM and ahcache availability in privacy-preserving
// summary mode. There is no input; output is a row vector for the BAM/ahcache tab.
std::vector<MiscAuditRow> CollectAuxiliaryRows() {
    std::vector<MiscAuditRow> rows;
    AddDriverCapabilityRow(rows, L"BAM / ahcache");
    AddSecurityAuditRows(rows, L"BAM / ahcache");
    AddCommandRow(rows, L"BAM / ahcache", L"BAM registry summary", L"PowerShell registry count", RunPowerShellScalar(
        L"$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings'; if(Test-Path $p){ $users=(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue | Measure-Object).Count; 'UserSettingsKeys=' + $users + '; privacyMode=SummaryOnly' } else { 'BAM UserSettings key missing' }"));
    AddCommandRow(rows, L"BAM / ahcache", L"Amcache availability", L"PowerShell file summary", RunPowerShellScalar(
        L"$p=Join-Path $env:windir 'AppCompat\\Programs\\Amcache.hve'; if(Test-Path $p){ $i=Get-Item -LiteralPath $p; 'AmcachePresent=true; Length=' + $i.Length + '; LastWriteUtc=' + $i.LastWriteTimeUtc.ToString('o') + '; privacyMode=SummaryOnly' } else { 'Amcache.hve missing' }"));
    AddCommandRow(rows, L"BAM / ahcache", L"AppCompat cache service keys", L"PowerShell registry summary", RunPowerShellScalar(
        L"$keys=@('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache','HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags'); foreach($k in $keys){ if(Test-Path $k){ Write-Output ($k + '=present') } else { Write-Output ($k + '=missing') } }"));
    AddServiceRow(rows, L"BAM / ahcache", L"BAM driver", L"bam");
    AddServiceRow(rows, L"BAM / ahcache", L"Application Compatibility Cache", L"ahcache");
    AppendRow(rows, L"BAM / ahcache", L"Privacy boundary", L"SummaryOnly", L"UI policy", L"Info", L"默认只显示状态、计数和可用性，不枚举用户执行历史明细、不导出路径时间线。");
    return rows;
}

// CollectBugcheckRows reports only feature applicability. The R0 feature is
// VMware-only and its valid upload path is intentionally quiet when inactive,
// so this page never claims that a successful transport activated a panel.
std::vector<MiscAuditRow> CollectBugcheckRows() {
    std::vector<MiscAuditRow> rows;
    AddDriverCapabilityRow(rows, L"Bugcheck / VMware branding");
    AddCommandRow(rows, L"Bugcheck / VMware branding", L"VMware environment", L"PowerShell Win32_ComputerSystem", RunPowerShellScalar(
        L"$c=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop; 'Manufacturer=' + $c.Manufacturer + '; Model=' + $c.Model"));
    AppendRow(rows, L"Bugcheck / VMware branding", L"R0 feature scope", L"VMware-only", L"KswordARK bugcheck runtime", L"Info",
        L"驱动仅在检测到受支持的 VMware 显示环境时启用该诊断面板；非 VMware 环境会安全忽略合法上传包。");
    AppendRow(rows, L"Bugcheck / VMware branding", L"内置测试位图", L"Explicit action required", L"ArkDriverClient::setBugcheckBitmap", L"Low",
        L"点击“上传内置位图”后才会在后台发送 16×16 BGRA 测试图；不会自动上传，也不会改变 Bugcheck 策略。传输成功不代表 VMware 面板已经激活。");
    return rows;
}

// CollectRowsForPage dispatches a tab id to its read-only collector. Input is a
// stable page id; processing performs local R3 queries; output is the fresh row
// snapshot used by RefreshAuditView.
std::vector<MiscAuditRow> CollectRowsForPage(const MiscAuditPageId pageId) {
    switch (pageId) {
    case MiscAuditPageId::CodeIntegrity:
        return CollectCodeIntegrityRows();
    case MiscAuditPageId::VbsHvciSkci:
        return CollectVbsRows();
    case MiscAuditPageId::HyperV:
        return CollectHyperVRows();
    case MiscAuditPageId::AppLocker:
        return CollectAppLockerRows();
    case MiscAuditPageId::BamAhcache:
        return CollectAuxiliaryRows();
    case MiscAuditPageId::Bugcheck:
        return CollectBugcheckRows();
    default:
        return {};
    }
}

// AuditColumns returns the fixed ListView schema shared by every Misc tab. There
// is no input; output is consumed by AddListViewColumns during page creation.
std::vector<Ksword::Ui::ListViewColumn> AuditColumns() {
    return {
        { 0, 190, LVCFMT_LEFT, L"类别" },
        { 1, 250, LVCFMT_LEFT, L"项目" },
        { 2, 130, LVCFMT_LEFT, L"状态" },
        { 3, 260, LVCFMT_LEFT, L"来源" },
        { 4, 100, LVCFMT_LEFT, L"风险" },
        { 5, 620, LVCFMT_LEFT, L"详情 / 失败原因" },
    };
}

std::vector<std::wstring> AuditCells(const MiscAuditRow& row) {
    return { row.category, row.item, row.state, row.source, row.risk, row.detail };
}

std::wstring AuditStableKey(const MiscAuditRow& row) {
    return row.category + L"\n" + row.item + L"\n" + row.source;
}

std::vector<Ksword::Ui::VirtualListRow> BuildAuditVirtualRows(const std::vector<MiscAuditRow>& rows) {
    std::vector<Ksword::Ui::VirtualListRow> displayRows;
    displayRows.reserve(rows.size());
    for (std::size_t index = 0; index < rows.size(); ++index) {
        Ksword::Ui::VirtualListRow display{};
        display.stableKey = AuditStableKey(rows[index]);
        display.cells = AuditCells(rows[index]);
        display.itemData = static_cast<LPARAM>(index);
        displayRows.push_back(std::move(display));
    }
    return displayRows;
}

std::wstring StableKeyAt(const MiscAuditViewState& state, const int visibleIndex) {
    if (visibleIndex < 0 || visibleIndex >= static_cast<int>(state.visibleRows.size())) {
        return {};
    }
    return AuditStableKey(state.visibleRows[static_cast<std::size_t>(visibleIndex)]);
}

void RestoreListPosition(MiscAuditViewState& state, const std::wstring& selectedKey, const std::wstring& topKey) {
    int selectedIndex = -1;
    int topIndex = -1;
    for (std::size_t index = 0; index < state.visibleRows.size(); ++index) {
        const std::wstring key = AuditStableKey(state.visibleRows[index]);
        if (!selectedKey.empty() && key == selectedKey) {
            selectedIndex = static_cast<int>(index);
        }
        if (!topKey.empty() && key == topKey) {
            topIndex = static_cast<int>(index);
        }
    }
    if (selectedIndex >= 0) {
        ListView_SetItemState(state.list, selectedIndex, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }
    if (topIndex >= 0) {
        ListView_EnsureVisible(state.list, topIndex, FALSE);
    }
}

// RequestAuditFilter runs local matching against the immutable text snapshot.
// Registry, service, WMI and R0 probes are never repeated while typing.
void RequestAuditFilter(MiscAuditViewState& state, std::wstring query) {
    if (!state.filterTask || !state.filterRows) {
        return;
    }
    state.filterQuery = std::move(query);
    state.filterUseRegex = Ksword::Ui::GetFilterBarRegexEnabled(state.filterBar);
    const std::uint64_t generation = state.snapshotGeneration;
    const auto rows = state.filterRows;
    const bool useRegex = state.filterUseRegex;
    state.filterTask->request(
        [rows, generation, useRegex, query = state.filterQuery]() mutable {
            MiscAuditFilterResult result{};
            result.generation = generation;
            result.query = std::move(query);
            result.useRegex = useRegex;
            result.visibleIndexes = Ksword::Ui::VirtualListView::FilterRowIndexes(*rows, result.query, useRegex);
            return result;
        },
        [&state](std::uint64_t, std::optional<MiscAuditFilterResult>&& result, std::exception_ptr error) {
            if (error || !result.has_value() || result->generation != state.snapshotGeneration ||
                result->query != state.filterQuery || result->useRegex != state.filterUseRegex) {
                return;
            }
            const std::wstring selectedKey = StableKeyAt(state, ListView_GetNextItem(state.list, -1, LVNI_SELECTED));
            const std::wstring topKey = StableKeyAt(state, ListView_GetTopIndex(state.list));
            state.visibleRows.clear();
            state.visibleRows.reserve(result->visibleIndexes.size());
            for (const std::size_t index : result->visibleIndexes) {
                if (index < state.rows.size()) {
                    state.visibleRows.push_back(state.rows[index]);
                }
            }
            state.virtualList.setVisibleIndexes(std::move(result->visibleIndexes));
            RestoreListPosition(state, selectedKey, topKey);
        });
}

// PopulateAuditList installs a new immutable owner-data snapshot after its
// collector finishes. The old result remains interactive until this point.
void PopulateAuditList(MiscAuditViewState& state) {
    if (!state.list) {
        return;
    }
    state.filterRows = std::make_shared<const std::vector<Ksword::Ui::VirtualListRow>>(BuildAuditVirtualRows(state.rows));
    ++state.snapshotGeneration;
    state.virtualList.setRows(*state.filterRows);
    RequestAuditFilter(state, state.filterBar ? Ksword::Ui::GetFilterBarText(state.filterBar) : state.filterQuery);
}

// BuildRowsTsv converts current rows to clipboard-friendly TSV. Input is a row
// vector; processing does not escape beyond replacing line breaks; output is text
// suitable for copy/paste into a spreadsheet.
std::wstring BuildRowsTsv(const std::vector<MiscAuditRow>& rows) {
    auto clean = [](std::wstring text) {
        std::replace(text.begin(), text.end(), L'\r', L' ');
        std::replace(text.begin(), text.end(), L'\n', L' ');
        std::replace(text.begin(), text.end(), L'\t', L' ');
        return text;
    };

    std::wostringstream stream;
    stream << L"类别\t项目\t状态\t来源\t风险\t详情\r\n";
    for (const MiscAuditRow& row : rows) {
        stream << clean(row.category) << L'\t'
               << clean(row.item) << L'\t'
               << clean(row.state) << L'\t'
               << clean(row.source) << L'\t'
               << clean(row.risk) << L'\t'
               << clean(row.detail) << L"\r\n";
    }
    return stream.str();
}

// WriteClipboardText copies Unicode text to the clipboard. Inputs are owner HWND
// and text; processing transfers a movable global allocation to Windows; output
// reports success for status messages.
bool WriteClipboardText(HWND owner, const std::wstring& text) {
    if (text.empty() || !::OpenClipboard(owner)) {
        return false;
    }
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
    ::EmptyClipboard();
    if (!::SetClipboardData(CF_UNICODETEXT, memory)) {
        ::GlobalFree(memory);
        ::CloseClipboard();
        return false;
    }
    ::CloseClipboard();
    return true;
}

// SelectedRowIndex returns the selected ListView row index. Input is a page state;
// output is -1 when no row is selected.
int SelectedRowIndex(const MiscAuditViewState& state) {
    return state.list ? ListView_GetNextItem(state.list, -1, LVNI_SELECTED) : -1;
}

// CopySelectedRow copies one evidence row as TSV. Input is a page state; process
// reads only the current in-memory row; no return value is produced.
void CopySelectedRow(MiscAuditViewState& state) {
    const int index = SelectedRowIndex(state);
    if (index < 0 || index >= static_cast<int>(state.visibleRows.size())) {
        state.statusText = L"没有选中可复制的行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const bool ok = WriteClipboardText(state.hwnd, BuildRowsTsv({ state.visibleRows[static_cast<std::size_t>(index)] }));
    state.statusText = ok ? L"已复制当前行。" : L"复制当前行失败。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// CopyAllRows copies the currently visible local result as TSV. It does not
// trigger an audit refresh and therefore remains instantaneous while typing.
void CopyAllRows(MiscAuditViewState& state) {
    const bool ok = WriteClipboardText(state.hwnd, BuildRowsTsv(state.visibleRows));
    state.statusText = ok ? L"已复制可见审计结果。" : L"复制可见审计结果失败。";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
}

// RefreshAuditView schedules all command, registry, service and R0 work in a
// snapshot worker. Repeated clicks coalesce and the old table stays available.
void RefreshAuditView(MiscAuditViewState& state) {
    if (!state.refreshTask) {
        return;
    }
    state.statusText = state.refreshTask->running()
        ? L"审计刷新已排队，等待当前快照完成…"
        : L"正在后台刷新只读审计证据…";
    ::EnableWindow(state.refreshButton, FALSE);
    if (state.rows.empty()) {
        Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, true, L"正在加载安全审计快照…");
    }
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    const MiscAuditPageId pageId = state.pageId;
    state.refreshTask->request(
        [pageId] {
            MiscAuditRefreshResult result{};
            result.pageId = pageId;
            result.rows = CollectRowsForPage(pageId);
            return result;
        },
        [&state](std::uint64_t, std::optional<MiscAuditRefreshResult>&& result, std::exception_ptr error) {
            ::EnableWindow(state.refreshButton, TRUE);
            Ksword::Ui::SetLoadingOverlay(state.loadingOverlay, false);
            if (error || !result.has_value() || result->pageId != state.pageId) {
                state.statusText = L"安全审计后台刷新异常结束，已保留旧结果。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            state.rows = std::move(result->rows);
            PopulateAuditList(state);
            std::size_t unavailable = 0;
            for (const MiscAuditRow& row : state.rows) {
                if (row.state == L"Unavailable" || row.state == L"Unsupported") {
                    ++unavailable;
                }
            }
            state.statusText = L"Rows=" + std::to_wstring(state.rows.size()) +
                L"; Unavailable=" + std::to_wstring(unavailable) +
                L"; 默认只读审计，失败原因保留在详情列。";
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

// UploadBuiltinBugcheckBitmap sends a fixed, bounded 16x16 BGRA diagnostic tile
// only after explicit UI confirmation. The work and IOCTL both run in the page's
// background task; the active audit snapshot remains usable while it runs.
void UploadBuiltinBugcheckBitmap(MiscAuditViewState& state) {
    if (state.pageId != MiscAuditPageId::Bugcheck || !state.bugcheckUploadTask) {
        return;
    }
    if (state.bugcheckUploadTask->running()) {
        state.statusText = L"Bugcheck 位图上传已在后台执行。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    const int answer = ::MessageBoxW(state.hwnd,
        L"将上传内置的 16×16 BGRA 诊断位图到 KswordARK。\n\n"
        L"该操作只影响受支持 VMware 环境中的驱动缓存。驱动会在非支持环境安全忽略合法数据包，"
        L"不会修改系统 Bugcheck 策略或主动触发蓝屏。是否继续？",
        L"确认上传 Bugcheck 诊断位图", MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING);
    if (answer != IDYES) {
        state.statusText = L"已取消 Bugcheck 位图上传。";
        ::InvalidateRect(state.hwnd, nullptr, TRUE);
        return;
    }
    ::EnableWindow(state.bugcheckUploadButton, FALSE);
    state.statusText = L"正在后台上传 Bugcheck 内置诊断位图…";
    ::InvalidateRect(state.hwnd, nullptr, TRUE);
    state.bugcheckUploadTask->request(
        [] {
            constexpr std::uint32_t width = 16;
            constexpr std::uint32_t height = 16;
            constexpr std::uint32_t stride = width * 4;
            std::vector<std::uint8_t> pixels(static_cast<std::size_t>(stride) * height, 0);
            for (std::uint32_t y = 0; y < height; ++y) {
                for (std::uint32_t x = 0; x < width; ++x) {
                    const std::size_t offset = (static_cast<std::size_t>(y) * stride) + (static_cast<std::size_t>(x) * 4U);
                    const bool accent = ((x / 4U) + (y / 4U)) % 2U == 0U;
                    pixels[offset] = accent ? 0xD7U : 0x9BU;
                    pixels[offset + 1U] = accent ? 0x83U : 0x56U;
                    pixels[offset + 2U] = accent ? 0x21U : 0x1BU;
                    pixels[offset + 3U] = 0xFFU;
                }
            }
            BugcheckUploadResult result{};
            result.io = ksword::ark::DriverClient().setBugcheckBitmap(width, height, stride, 0x2183D7U, pixels);
            return result;
        },
        [&state](std::uint64_t, std::optional<BugcheckUploadResult>&& result, std::exception_ptr error) {
            ::EnableWindow(state.bugcheckUploadButton, TRUE);
            if (error || !result.has_value()) {
                state.statusText = L"Bugcheck 位图后台上传异常结束。";
                ::InvalidateRect(state.hwnd, nullptr, TRUE);
                return;
            }
            const ksword::ark::IoResult& io = result->io;
            AppendRow(state.rows, L"Bugcheck / VMware branding", L"内置测试位图上传",
                io.ok ? L"Transport OK" : L"Transport failed",
                L"ArkDriverClient::setBugcheckBitmap", io.ok ? L"Info" : L"Unknown",
                L"16x16 BGRA; brandColor=#2183D7; Win32=" + std::to_wstring(io.win32Error) +
                L"; bytes=" + std::to_wstring(io.bytesReturned) + L"; " + std::wstring(io.message.begin(), io.message.end()));
            PopulateAuditList(state);
            state.statusText = io.ok
                ? L"Bugcheck 位图传输完成。请注意：非 VMware 环境会被驱动安全忽略。"
                : L"Bugcheck 位图传输失败，详细原因已加入结果列表。";
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        });
}

void EnsureAuditViewLoaded(HWND view) {
    MiscAuditViewState* state = StateFromAuditView(view);
    if (state && !state->hasLoaded) {
        state->hasLoaded = true;
        RefreshAuditView(*state);
    }
}

// LayoutAuditView places toolbar and ListView inside one Misc tab. Input is page
// state; processing uses current client size; no value is returned.
void LayoutAuditView(MiscAuditViewState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    const int width = Width(rc);
    const int height = Height(rc);
    ::MoveWindow(state.refreshButton, kGap, kGap, 86, 24, TRUE);
    ::MoveWindow(state.copyButton, kGap + 94, kGap, 106, 24, TRUE);
    const bool bugcheckPage = state.pageId == MiscAuditPageId::Bugcheck;
    ::ShowWindow(state.bugcheckUploadButton, bugcheckPage ? SW_SHOW : SW_HIDE);
    ::MoveWindow(state.bugcheckUploadButton, kGap + 208, kGap, 126, 24, TRUE);
    ::MoveWindow(state.filterBar, kGap, 34, std::max(100, width - (kGap * 2)), 28, TRUE);
    const int top = kHeaderHeight + kGap;
    ::MoveWindow(state.list, kGap, top, std::max(0, width - (kGap * 2)), std::max(0, height - top - kGap), TRUE);
    ::MoveWindow(state.loadingOverlay, kGap, top, std::max(0, width - (kGap * 2)), std::max(0, height - top - kGap), TRUE);
}

// ShowAuditContextMenu displays only read-only actions. Inputs are page state and
// a screen point; processing can refresh or copy rows; no mutation command exists.
void ShowAuditContextMenu(MiscAuditViewState& state, POINT screenPoint) {
    if (!state.list) {
        return;
    }
    POINT clientPoint = screenPoint;
    ::ScreenToClient(state.list, &clientPoint);
    LVHITTESTINFO hit{};
    hit.pt = clientPoint;
    const int item = ListView_HitTest(state.list, &hit);
    state.contextColumn = std::max(0, hit.iSubItem);
    if (item >= 0) {
        ListView_SetItemState(state.list, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
        ListView_SetItemState(state.list, item, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
    }

    HMENU menu = ::CreatePopupMenu();
    if (!menu) {
        return;
    }
    const bool hasSelection = SelectedRowIndex(state) >= 0;
    ::AppendMenuW(menu, MF_STRING, kMenuRefresh, L"刷新只读审计");
    ::AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kMenuCopyRow, L"复制当前行");
    ::AppendMenuW(menu, MF_STRING | (hasSelection ? 0U : MF_GRAYED), kMenuCopyCell, L"复制单元格");
    ::AppendMenuW(menu, MF_STRING, kMenuCopyAll, L"复制可见结果");

    const UINT command = ::TrackPopupMenu(menu, TPM_RETURNCMD | TPM_RIGHTBUTTON, screenPoint.x, screenPoint.y, 0, state.hwnd, nullptr);
    ::DestroyMenu(menu);
    switch (command) {
    case kMenuRefresh:
        RefreshAuditView(state);
        break;
    case kMenuCopyRow:
        CopySelectedRow(state);
        break;
    case kMenuCopyCell: {
        const int selected = SelectedRowIndex(state);
        if (selected >= 0 && selected < static_cast<int>(state.visibleRows.size())) {
            const std::vector<std::wstring> cells = AuditCells(state.visibleRows[static_cast<std::size_t>(selected)]);
            const std::size_t column = static_cast<std::size_t>(std::max(0, state.contextColumn));
            const bool ok = WriteClipboardText(state.hwnd, column < cells.size() ? cells[column] : std::wstring{});
            state.statusText = ok ? L"已复制单元格。" : L"复制单元格失败。";
            ::InvalidateRect(state.hwnd, nullptr, TRUE);
        }
        break;
    }
    case kMenuCopyAll:
        CopyAllRows(state);
        break;
    default:
        break;
    }
}

// CreateAuditChildControls creates one tab page's toolbar and report ListView.
// Input is the page state and HWND; processing adds fixed columns; output is true
// when all controls exist.
bool CreateAuditChildControls(MiscAuditViewState& state, HWND hwnd) {
    state.refreshButton = Ksword::Ui::CreateButton(hwnd, kRefreshButtonId, L"Refresh", 0, 0, 80, 24);
    state.copyButton = Ksword::Ui::CreateButton(hwnd, kCopyButtonId, L"Copy TSV", 0, 0, 100, 24);
    state.bugcheckUploadButton = Ksword::Ui::CreateButton(hwnd, kBugcheckUploadButtonId, L"上传内置位图", 0, 0, 120, 24);
    state.filterBar = Ksword::Ui::CreateFilterBar(hwnd, kFilterBarId,
        L"筛选类别、项目、状态、来源、风险和详情", 0, 0, 0, 0);
    if (!state.refreshButton || !state.copyButton || !state.bugcheckUploadButton || !state.filterBar ||
        !state.virtualList.create(hwnd, kListId, 0, 0, 0, 0, LVS_SHOWSELALWAYS | LVS_SINGLESEL)) {
        return false;
    }
    state.list = state.virtualList.hwnd();
    state.virtualList.addColumns(AuditColumns());
    state.loadingOverlay = Ksword::Ui::CreateLoadingOverlay(hwnd, kLoadingOverlayId, { 0, 0, 1, 1 });
    state.refreshTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<MiscAuditRefreshResult>>(hwnd, kMsgAuditRefreshCompleted);
    state.filterTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<MiscAuditFilterResult>>(hwnd, kMsgAuditFilterCompleted);
    state.bugcheckUploadTask = std::make_unique<Ksword::Ui::AsyncSnapshotTask<BugcheckUploadResult>>(hwnd, kMsgBugcheckUploadCompleted);
    if (!state.loadingOverlay || !state.refreshTask || !state.filterTask || !state.bugcheckUploadTask) {
        return false;
    }
    Ksword::Ui::SetWindowFontRecursive(hwnd);
    return true;
}

// RegisterAuditViewClass registers the retained child page class once. There is
// no input; output is true when CreateWindowExW can instantiate the class.
bool RegisterAuditViewClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        MiscAuditViewState* state = StateFromAuditView(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<MiscAuditViewState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!CreateAuditChildControls(*state, hwnd)) {
                    delete state;
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                LayoutAuditView(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                LayoutAuditView(*state);
            }
            return 0;
        case WM_COMMAND:
            if (state && LOWORD(wParam) == kRefreshButtonId) {
                RefreshAuditView(*state);
                return 0;
            }
            if (state && LOWORD(wParam) == kCopyButtonId) {
                CopyAllRows(*state);
                return 0;
            }
            if (state && LOWORD(wParam) == kBugcheckUploadButtonId) {
                UploadBuiltinBugcheckBitmap(*state);
                return 0;
            }
            if (state && LOWORD(wParam) == kFilterBarId && HIWORD(wParam) == EN_CHANGE) {
                RequestAuditFilter(*state, Ksword::Ui::GetFilterBarText(state->filterBar));
                return 0;
            }
            break;
        case kMsgAuditRefreshCompleted:
            if (state && state->refreshTask && state->refreshTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgAuditFilterCompleted:
            if (state && state->filterTask && state->filterTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case kMsgBugcheckUploadCompleted:
            if (state && state->bugcheckUploadTask && state->bugcheckUploadTask->consume(hwnd, wParam, lParam)) {
                return 0;
            }
            break;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                LRESULT virtualResult = 0;
                if (header && state->virtualList.handleNotify(*header, virtualResult)) {
                    return virtualResult;
                }
                if (header && header->hwndFrom == state->list && header->code == NM_RCLICK) {
                    POINT pt{};
                    ::GetCursorPos(&pt);
                    ShowAuditContextMenu(*state, pt);
                    return 0;
                }
            }
            break;
        case WM_CONTEXTMENU:
            if (state && reinterpret_cast<HWND>(wParam) == state->list) {
                POINT pt{ GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam) };
                if (pt.x == -1 && pt.y == -1) {
                    RECT rc{};
                    ::GetWindowRect(state->list, &rc);
                    pt = { rc.left + 24, rc.top + 24 };
                }
                ShowAuditContextMenu(*state, pt);
                return 0;
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
            return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().panelBrush());
        }
        case WM_PAINT: {
            PAINTSTRUCT ps{};
            HDC dc = ::BeginPaint(hwnd, &ps);
            RECT rc{};
            ::GetClientRect(hwnd, &rc);
            ::FillRect(dc, &rc, Ksword::Ui::AppTheme().panelBrush());
            const int textLeft = state && state->pageId == MiscAuditPageId::Bugcheck ? kGap + 344 : kGap + 210;
            RECT textRc{ textLeft, 7, rc.right - kGap, kHeaderHeight };
            const std::wstring text = state ? (state->title + L" - " + state->statusText) : L"Misc audit";
            Ksword::Ui::DrawTextLine(dc, text, textRc, Ksword::Ui::AppTheme().mutedTextColor, Ksword::Ui::SystemUIFont(), DT_SINGLELINE | DT_LEFT | DT_VCENTER);
            ::EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_NCDESTROY:
            if (state && state->refreshTask) {
                state->refreshTask->cancel();
            }
            if (state && state->filterTask) {
                state->filterTask->cancel();
            }
            if (state && state->bugcheckUploadTask) {
                state->bugcheckUploadTask->cancel();
            }
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().panelBrush();
    wc.lpszClassName = kMiscAuditViewClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

// CreateAuditView creates one retained Misc child page. Inputs are parent,
// bounds, page id and title; processing allocates state for the child window;
// output is the child HWND or nullptr on failure.
HWND CreateAuditView(HWND parent, const RECT& bounds, MiscAuditPageId pageId, std::wstring title) {
    if (!parent || !RegisterAuditViewClass()) {
        return nullptr;
    }
    auto* state = new MiscAuditViewState();
    state->pageId = pageId;
    state->title = std::move(title);
    HWND hwnd = ::CreateWindowExW(
        0,
        kMiscAuditViewClass,
        L"MiscAuditView",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        Width(bounds),
        Height(bounds),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

// ShowHostPages toggles retained tab pages without destroying their state. Input
// is host state; processing uses ShowWindow only; no value is returned.
void ShowHostPages(MiscFeaturePageState& state) {
    if (state.ciView) {
        ::ShowWindow(state.ciView, state.currentTab == kCiTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.vbsView) {
        ::ShowWindow(state.vbsView, state.currentTab == kVbsTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.hypervView) {
        ::ShowWindow(state.hypervView, state.currentTab == kHyperVTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.appLockerView) {
        ::ShowWindow(state.appLockerView, state.currentTab == kAppLockerTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.auxiliaryView) {
        ::ShowWindow(state.auxiliaryView, state.currentTab == kAuxiliaryTabIndex ? SW_SHOW : SW_HIDE);
    }
    if (state.bugcheckView) {
        ::ShowWindow(state.bugcheckView, state.currentTab == kBugcheckTabIndex ? SW_SHOW : SW_HIDE);
    }
    const HWND currentView = state.currentTab == kCiTabIndex ? state.ciView :
        state.currentTab == kVbsTabIndex ? state.vbsView :
        state.currentTab == kHyperVTabIndex ? state.hypervView :
        state.currentTab == kAppLockerTabIndex ? state.appLockerView : state.auxiliaryView;
    EnsureAuditViewLoaded(state.currentTab == kBugcheckTabIndex ? state.bugcheckView : currentView);
}

// LayoutHostChildren sizes the tab control and every retained child page. Input
// is host state; processing uses the tab display rect; no value is returned.
void LayoutHostChildren(MiscFeaturePageState& state) {
    if (!state.hwnd) {
        return;
    }
    RECT rc{};
    ::GetClientRect(state.hwnd, &rc);
    ::MoveWindow(state.tab, 0, 0, Width(rc), Height(rc), TRUE);
    RECT display = Ksword::Ui::GetTabDisplayRect(state.tab);
    const int pageWidth = Width(display);
    const int pageHeight = Height(display);
    const std::array<HWND, 6> pages{ state.ciView, state.vbsView, state.hypervView, state.appLockerView, state.auxiliaryView, state.bugcheckView };
    for (HWND page : pages) {
        if (page) {
            ::MoveWindow(page, display.left, display.top, pageWidth, pageHeight, TRUE);
        }
    }
    ShowHostPages(state);
}

// CreateHostChildControls creates the tab host and six security posture pages.
// Input is host state with hwnd already assigned; output is true when every page
// was created successfully.
bool CreateHostChildControls(MiscFeaturePageState& state) {
    state.tab = Ksword::Ui::CreateTabControl(state.hwnd, kTabId, 0, 0, 0, 0);
    if (!state.tab) {
        return false;
    }
    Ksword::Ui::AddTabPage(state.tab, kCiTabIndex, { L"Code Integrity / WDAC" });
    Ksword::Ui::AddTabPage(state.tab, kVbsTabIndex, { L"VBS / HVCI / SKCI" });
    Ksword::Ui::AddTabPage(state.tab, kHyperVTabIndex, { L"Hyper-V / VMBus" });
    Ksword::Ui::AddTabPage(state.tab, kAppLockerTabIndex, { L"AppLocker" });
    Ksword::Ui::AddTabPage(state.tab, kAuxiliaryTabIndex, { L"BAM / ahcache" });
    Ksword::Ui::AddTabPage(state.tab, kBugcheckTabIndex, { L"Bugcheck / VMware" });
    ::SendMessageW(state.tab, TCM_SETCURSEL, static_cast<WPARAM>(kCiTabIndex), 0);

    RECT display = Ksword::Ui::GetTabDisplayRect(state.tab);
    const RECT childBounds{ 0, 0, std::max(1, Width(display)), std::max(1, Height(display)) };
    state.ciView = CreateAuditView(state.tab, childBounds, MiscAuditPageId::CodeIntegrity, L"Code Integrity / WDAC");
    state.vbsView = CreateAuditView(state.tab, childBounds, MiscAuditPageId::VbsHvciSkci, L"VBS / HVCI / SKCI");
    state.hypervView = CreateAuditView(state.tab, childBounds, MiscAuditPageId::HyperV, L"Hyper-V / VMBus / HvSocket");
    state.appLockerView = CreateAuditView(state.tab, childBounds, MiscAuditPageId::AppLocker, L"AppLocker / AppID");
    state.auxiliaryView = CreateAuditView(state.tab, childBounds, MiscAuditPageId::BamAhcache, L"BAM / ahcache");
    state.bugcheckView = CreateAuditView(state.tab, childBounds, MiscAuditPageId::Bugcheck, L"Bugcheck / VMware branding");
    return state.ciView && state.vbsView && state.hypervView && state.appLockerView && state.auxiliaryView && state.bugcheckView;
}

// RegisterMiscFeatureClass registers the outer Misc tab host. There is no input;
// output is true when CreateMiscFeaturePage can create the class.
bool RegisterMiscFeatureClass() {
    static bool registered = false;
    if (registered) {
        return true;
    }

    WNDCLASSW wc{};
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) -> LRESULT {
        MiscFeaturePageState* state = StateFromHost(hwnd);
        if (msg == WM_NCCREATE) {
            auto* create = reinterpret_cast<CREATESTRUCTW*>(lParam);
            state = create ? static_cast<MiscFeaturePageState*>(create->lpCreateParams) : nullptr;
            if (state) {
                state->hwnd = hwnd;
                ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));
            }
        }

        switch (msg) {
        case WM_CREATE:
            if (state) {
                if (!CreateHostChildControls(*state)) {
                    delete state;
                    ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                    return -1;
                }
                LayoutHostChildren(*state);
            }
            return 0;
        case WM_SIZE:
            if (state) {
                LayoutHostChildren(*state);
            }
            return 0;
        case WM_NOTIFY:
            if (state) {
                const auto* header = reinterpret_cast<const NMHDR*>(lParam);
                if (header && header->hwndFrom == state->tab && header->code == TCN_SELCHANGE) {
                    const LRESULT selected = ::SendMessageW(state->tab, TCM_GETCURSEL, 0, 0);
                    if (selected >= 0) {
                        state->currentTab = static_cast<int>(selected);
                    }
                    ShowHostPages(*state);
                    return 0;
                }
            }
            break;
        case WM_CTLCOLORSTATIC: {
            HDC dc = reinterpret_cast<HDC>(wParam);
            ::SetBkMode(dc, TRANSPARENT);
            ::SetTextColor(dc, Ksword::Ui::AppTheme().textColor);
            return reinterpret_cast<LRESULT>(Ksword::Ui::AppTheme().windowBrush());
        }
        case WM_NCDESTROY:
            delete state;
            ::SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            return 0;
        default:
            break;
        }
        return ::DefWindowProcW(hwnd, msg, wParam, lParam);
    };
    wc.hInstance = ::GetModuleHandleW(nullptr);
    wc.hCursor = ::LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = Ksword::Ui::AppTheme().windowBrush();
    wc.lpszClassName = kMiscHostClass;
    if (::RegisterClassW(&wc) || ::GetLastError() == ERROR_CLASS_ALREADY_EXISTS) {
        registered = true;
    }
    return registered;
}

} // namespace

HWND CreateMiscFeaturePage(HWND parent, const RECT& bounds) {
    // Inputs are the shell parent HWND and initial child bounds. Processing only
    // creates the read-only Misc audit host and retained child tabs; registration
    // into FeatureRegistry/vcxproj is intentionally left to thread13 per the user
    // constraint. Return value is the host HWND or nullptr on failure.
    if (!parent || !RegisterMiscFeatureClass()) {
        return nullptr;
    }
    auto* state = new MiscFeaturePageState();
    HWND hwnd = ::CreateWindowExW(
        0,
        kMiscHostClass,
        L"Misc",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | WS_CLIPSIBLINGS,
        bounds.left,
        bounds.top,
        Width(bounds),
        Height(bounds),
        parent,
        nullptr,
        ::GetModuleHandleW(nullptr),
        state);
    if (!hwnd) {
        delete state;
    }
    return hwnd;
}

} // namespace Ksword::Features::Misc
