#pragma once

#include "ProcessDetailTypes.h"

#include "../../Core/Common.h"
#include "../../Core/Win32Lean.h"
#include "../../Ui/AsyncTask.h"
#include "../../Ui/VirtualListView.h"

#include <commctrl.h>

#include "../../../shared/driver/KswordArkKeyboardIoctl.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace Ksword::Features::ProcessDetail {

// ProcessDetailPage is the native Win32 conversion of the full process-detail
// layout. It owns native tab pages and does not load foreign UI sources,
// resources, or binaries.
class ProcessDetailPage final {
public:
    static HWND Create(
        HWND parent,
        DWORD processId,
        ULONGLONG expectedCreationTime100ns,
        const RECT& bounds);
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

private:
    enum class TabIndex : std::size_t {
        Detail = 0,
        Threads,
        Actions,
        Modules,
        Token,
        TokenSwitch,
        Evidence,
        Hotkey,
        Keyboard,
        Peb,
        Count
    };

    enum ControlId : int {
        TabControl = 1000,

        DetailTitle = 1100,
        DetailPath,
        DetailCopyPath,
        DetailOpenFolder,
        DetailCommandLine,
        DetailCopyCommand,
        DetailParentText,
        DetailOpenHandles,
        DetailGotoParent,
        DetailStartTime,
        DetailUser,
        DetailAdmin,
        DetailArchitecture,
        DetailPriority,
        DetailSession,
        DetailThreadCount,
        DetailHandleCount,
        DetailCpu,
        DetailRam,
        DetailDisk,
        DetailSignature,

        ThreadRefresh = 1200,
        ThreadSample,
        ThreadStack,
        ThreadStatus,
        ThreadList,
        ThreadRuntimeOutput,
        ThreadFilter,

        ActionTerminateMode = 1300,
        ActionTerminate,
        ActionSuspend,
        ActionResume,
        ActionSetCritical,
        ActionClearCritical,
        ActionPriority,
        ActionApplyPriority,
        ActionOpenFolder,
        ActionRefreshPpl,
        ActionEfficiencyOn,
        ActionEfficiencyOff,
        ActionR0Terminate,
        ActionR0Suspend,
        ActionR0Ppl,
        ActionR0Hide,
        ActionR0Danger,
        ActionInjectionMode,
        ActionDllPath,
        ActionBrowseDll,
        ActionInjectDll,
        ActionShellcodePath,
        ActionBrowseShellcode,
        ActionInjectShellcode,
        ActionStatus = 1330,

        ModuleRefresh = 1400,
        ModuleVerifySignature,
        ModuleStatus,
        ModuleList,
        ModuleFilter,

        TokenRefresh = 1500,
        TokenStatus,
        TokenEditorToolbar,
        TokenCopy,
        TokenFind,
        TokenGoto,
        TokenWrap,
        TokenOutput,
        TokenEditorStatus,

        TokenSwitchRefresh = 1600,
        TokenSwitchApply,
        TokenSwitchRefreshAll,
        TokenSwitchStatus,
        TokenSandboxInert,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenUiAccess,
        TokenMandatoryNoWriteUp,
        TokenMandatoryNewProcessMin,
        TokenHasRestrictions,
        TokenIsAppContainer,
        TokenIsRestricted,
        TokenIsLessPrivilegedAppContainer,
        TokenIsSandboxed,
        TokenIsAppSilo,
        TokenRawInfoClass,
        TokenRawInputMode,
        TokenRawPayload,
        TokenRawApply,

        EvidenceR0Status = 1700,
        EvidenceCapability,
        EvidenceImagePath,
        EvidenceHandleTable,
        EvidenceSectionObject,
        EvidenceProtection,
        EvidenceSignature,
        EvidenceSectionSignature,
        EvidenceSessionSource,
        EvidenceImagePathSource,
        EvidenceProtectionSource,
        EvidenceSignatureSource,
        EvidenceSectionSignatureSource,
        EvidenceObjectTableSource,
        EvidenceSectionObjectSource,
        EvidenceProtectionOffset,
        EvidenceSignatureOffset,
        EvidenceSectionSignatureOffset,
        EvidenceObjectTableOffset,
        EvidenceSectionObjectOffset,
        EvidenceRefreshSection,
        EvidenceSectionStatus,
        EvidenceSectionOutput,

        // 进程热键页控件：统一展示 R3 窗口/菜单/资源/快捷方式与 R0 热键证据。
        HotkeyRefresh = 1800,
        HotkeyStatus,
        HotkeyList,

        // 键盘页控件：通过内部分栏在热键表和 WH_KEYBOARD 钩子链之间切换。
        KeyboardRefresh = 1900,
        KeyboardStatus,
        KeyboardInnerTab,
        KeyboardList,

        PebRefresh = 2100,
        PebApply,
        PebStatus,
        PebTarget,
        PebCommandLine,
        PebImagePath,
        PebCurrentDirectory,
        PebEnvironmentName,
        PebEnvironmentValue,
        PebImageBase,
        PebAffinity,
        PebPriority,
        PebOutput,
        PebReadonlyReason
    };

    struct Placement {
        HWND hwnd = nullptr;
        int x = 0;
        int y = 0;
        int width = 0;  // Negative values mean right margin and stretch.
        int height = 0; // Negative values mean bottom margin and stretch.
    };

    struct PageState {
        HWND hwnd = nullptr;
        std::vector<Placement> placements;
    };

    struct DetailTableFilterResult {
        std::uint64_t sourceGeneration = 0;
        std::wstring query;
        bool useRegex = false;
        int sortColumn = 0;
        bool sortDescending = false;
        std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> rows;
        std::vector<std::size_t> visibleIndexes;
        HIMAGELIST imageList = nullptr;
    };

    struct ProcessDetailActionResult {
        bool refreshRequired = false;
        bool refreshTokenReport = false;
        bool refreshTokenSwitches = false;
        bool refreshPebReport = false;
        std::wstring statusText;
        std::wstring dialogTitle;
        std::wstring dialogText;
        UINT dialogIcon = 0;
    };

    // ProcessHotkeyEntry 保存一行进程热键审计结果。r0Snapshot 仅用于保留
    // R0 枚举证据，页面不会把内核地址作为未经确认的写入句柄使用。
    struct ProcessHotkeyEntry {
        std::wstring objectText;
        std::wstring hotkeyText;
        std::wstring processName;
        std::wstring sourceText;
        std::wstring detailText;
        DWORD processId = 0;
        DWORD threadId = 0;
        std::uint32_t hotkeyId = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
        bool hasR0Snapshot = false;
        KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY r0Snapshot{};
    };

    // ProcessHotkeySnapshot 是后台热键采集的不可变结果；UI 线程只渲染其中
    // 的字符串和值，避免后台任务持有窗口、菜单或 COM 对象。
    struct ProcessHotkeySnapshot {
        std::vector<ProcessHotkeyEntry> entries;
        std::wstring statusText;
        bool completed = false;
    };

    // KeyboardHookEntry 保存键盘钩子链的一行 R0 审计数据，不提供修改入口。
    struct KeyboardHookEntry {
        std::wstring objectText;
        std::wstring typeText;
        std::wstring scopeText;
        std::wstring procedureText;
        std::wstring moduleText;
        std::wstring sourceText;
        std::wstring flagsText;
        std::wstring detailText;
        DWORD processId = 0;
        DWORD threadId = 0;
    };

    // KeyboardSnapshot 将热键表和键盘钩子链一次性提交给键盘页，防止两个
    // 相关证据表在不同刷新代次之间混用。
    struct KeyboardSnapshot {
        std::vector<ProcessHotkeyEntry> hotkeys;
        std::vector<KeyboardHookEntry> hooks;
        std::wstring statusText;
        bool completed = false;
    };

    ProcessDetailPage(DWORD processId, ULONGLONG expectedCreationTime100ns);
    ~ProcessDetailPage();

    ProcessDetailPage(const ProcessDetailPage&) = delete;
    ProcessDetailPage& operator=(const ProcessDetailPage&) = delete;

    LRESULT HandleMessage(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK PageSubclassProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam,
        UINT_PTR subclassId,
        DWORD_PTR referenceData);
    LRESULT HandlePageMessage(TabIndex tab, HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);

    bool Initialize(HWND hwnd);
    void Layout();
    void LayoutPage(TabIndex tab);
    void UpdateVisiblePage();
    bool EnsurePage(TabIndex tab);
    bool CreatePageHost(TabIndex tab);
    void DestroyPageHost(TabIndex tab);
    bool CreateTabControls(TabIndex tab);
    void PopulateTab(TabIndex tab);
    void ResetTabRuntimeState(TabIndex tab);
    void RedrawTabClient();
    void OnTabActivated(TabIndex tab);
    void RefreshAll();
    void BeginSnapshotRefresh(const std::wstring& loadingMessage = L"正在后台加载进程详情…");
    void ApplySnapshot(ProcessDetailSnapshot snapshot);
    void SetSnapshotRefreshControlsEnabled(bool enabled);
    static bool OpenVerifiedProcessActionTarget(
        DWORD targetProcessId,
        ULONGLONG expectedProcessCreationTime100ns,
        DWORD requestedProcessAccess,
        Ksword::Core::UniqueHandle& processOut,
        std::wstring& errorText);
    static bool OpenVerifiedThreadActionTarget(
        DWORD targetProcessId,
        ULONGLONG expectedProcessCreationTime100ns,
        DWORD targetThreadId,
        ULONGLONG expectedThreadCreationTime100ns,
        DWORD requestedThreadAccess,
        Ksword::Core::UniqueHandle& processOut,
        Ksword::Core::UniqueHandle& threadOut,
        std::wstring& errorText);
    static bool TerminateAllThreadsIfProcessIdentityMatches(
        DWORD targetProcessId,
        ULONGLONG expectedProcessCreationTime100ns,
        std::wstring& detail);

    bool CreateDetailTab();
    bool CreateThreadTab();
    bool CreateActionTab();
    bool CreateModuleTab();
    bool CreateTokenTab();
    bool CreateTokenSwitchTab();
    bool CreateEvidenceTab();
    bool CreateHotkeyTab();
    bool CreateKeyboardTab();
    bool CreatePebTab();

    HWND AddControl(
        TabIndex tab,
        DWORD exStyle,
        const wchar_t* className,
        const wchar_t* text,
        DWORD style,
        int controlId,
        int x,
        int y,
        int width,
        int height);
    HWND AddLabel(TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height);
    HWND AddButton(TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height);
    HWND AddEdit(TabIndex tab, int controlId, const wchar_t* text, bool readOnly, bool multiline, int x, int y, int width, int height);
    HWND AddCombo(TabIndex tab, int controlId, int x, int y, int width, int height);
    HWND AddCheck(TabIndex tab, int controlId, const wchar_t* text, int x, int y, int width, int height);
    HWND AddGroup(TabIndex tab, const wchar_t* text, int x, int y, int width, int height);
    HWND AddList(TabIndex tab, int controlId, int x, int y, int width, int height);
    HWND AddVirtualList(
        TabIndex tab,
        int controlId,
        int x,
        int y,
        int width,
        int height,
        Ksword::Ui::VirtualListView& virtualList);
    HWND Control(TabIndex tab, int controlId) const;
    void SetControlText(TabIndex tab, int controlId, const std::wstring& text);
    std::wstring ControlText(TabIndex tab, int controlId) const;
    void SetPageStatus(TabIndex tab, int controlId, const std::wstring& text);

    static void AddListColumn(HWND list, int index, const wchar_t* title, int width);
    static void ClearList(HWND list);
    static void AddListRow(HWND list, int row, const std::vector<std::wstring>& values, LPARAM data = 0);
    static std::wstring ListCell(HWND list, int row, int column);
    static bool CopyText(HWND owner, const std::wstring& text);
    static std::wstring ReadWindowText(HWND hwnd);
    static void ApplyFont(HWND hwnd, HFONT font = nullptr);

    bool HandleGenericContextMenu(HWND source, POINT screenPoint);
    bool HandleThreadContextMenu(POINT screenPoint);
    bool HandleModuleContextMenu(POINT screenPoint);
    void ShowModuleDetailDialog();
    void CopyListCell(HWND list);
    void CopyListRow(HWND list);
    void CopyListAll(HWND list);
    int SelectedListRow(HWND list) const;

    void PopulateDetailTab();
    void PopulateThreadTab();
    void PopulateModuleTab();
    void PopulateTokenTab();
    void PopulateTokenSwitchTab();
    void PopulateEvidenceTab();
    void PopulateHotkeyTab();
    void PopulateKeyboardTab();
    void PopulatePebTab();
    void RequestThreadFilter(bool rebuildRows);
    void RequestModuleFilter(bool rebuildRows);
    void ExecuteBackgroundAction(
        TabIndex tab,
        int statusControlId,
        const std::wstring& workingText,
        std::function<ProcessDetailActionResult()> work);
    void SetBackgroundActionControlsEnabled(bool enabled);
    void OnModuleSortRequested(int column);
    static LRESULT CALLBACK ModuleHeaderSubclassProc(
        HWND hwnd,
        UINT message,
        WPARAM wParam,
        LPARAM lParam,
        UINT_PTR subclassId,
        DWORD_PTR referenceData);

    const std::vector<ProcessThreadInfo>& ThreadEntries() const noexcept;
    const std::vector<ProcessModuleInfo>& ModuleEntries() const noexcept;
    std::size_t LatestThreadCount() const noexcept;

    bool HandleDetailCommand(int controlId);
    bool HandleThreadCommand(int controlId);
    bool HandleActionCommand(int controlId);
    bool HandleModuleCommand(int controlId);
    bool HandleTokenCommand(int controlId);
    bool HandleTokenSwitchCommand(int controlId);
    bool HandleEvidenceCommand(int controlId);
    bool HandleHotkeyCommand(int controlId);
    bool HandleKeyboardCommand(int controlId);
    bool HandlePebCommand(int controlId);
    bool HandlePageNotify(TabIndex tab, NMHDR* header, LRESULT& result);

    void SuspendSelectedThread();
    void ResumeSelectedThread();
    void TerminateSelectedThread();
    void TerminateSelectedThreadByR0();
    void ShowSelectedThreadSummary();
    void OpenSelectedModuleFolder();
    void UnloadSelectedModule();
    void SuspendSelectedModuleThread();
    void ResumeSelectedModuleThread();
    void TerminateSelectedModuleThread();
    void ExecuteProcessAction(int actionId);
    void BrowseForPayload(bool dllMode);
    void ApplyTokenSwitches();
    void ApplyRawTokenValue();
    void RefreshTokenReport();
    void RefreshTokenSwitches();
    void RefreshSectionReport();
    void RenderSectionReport();
    void RefreshPebReport();
    void ApplyPebEdits();
    void RefreshHotkeys();
    void RefreshKeyboard();
    void RebuildHotkeyList();
    void RebuildKeyboardList();

private:
    DWORD processId_ = 0;
    ULONGLONG expectedCreationTime100ns_ = 0;
    HWND hwnd_ = nullptr;
    HWND tab_ = nullptr;
    HWND loadingOverlay_ = nullptr;
    HFONT titleFont_ = nullptr;
    TabIndex currentTab_ = TabIndex::Count;
    std::array<PageState, static_cast<std::size_t>(TabIndex::Count)> pages_{};
    std::unordered_map<HWND, int> listColumnCounts_;
    std::unordered_map<HWND, int> listContextColumns_;
    ProcessDetailSnapshot snapshot_{};
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessDetailSnapshot>> snapshotTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessDetailActionResult>> actionTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessTokenReportSnapshot>> tokenReportTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessTokenSwitchSnapshot>> tokenSwitchTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessDetailSnapshot>> evidenceTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessPebSnapshot>> pebTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<ProcessHotkeySnapshot>> hotkeyTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<KeyboardSnapshot>> keyboardTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<DetailTableFilterResult>> threadFilterTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<DetailTableFilterResult>> moduleFilterTask_;
    Ksword::Ui::VirtualListView threadVirtualList_;
    Ksword::Ui::VirtualListView moduleVirtualList_;
    std::shared_ptr<const std::vector<ProcessThreadInfo>> threadEntries_;
    std::shared_ptr<const std::vector<ProcessThreadInfo>> pendingThreadEntries_;
    std::shared_ptr<const std::vector<ProcessModuleInfo>> moduleEntries_;
    std::shared_ptr<const std::vector<ProcessModuleInfo>> pendingModuleEntries_;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> threadFilterRows_;
    std::shared_ptr<const std::vector<Ksword::Ui::VirtualListRow>> moduleFilterRows_;
    std::vector<std::size_t> threadVisibleIndexes_;
    std::vector<std::size_t> moduleVisibleIndexes_;
    std::uint64_t threadSourceGeneration_ = 0;
    std::uint64_t moduleSourceGeneration_ = 0;
    std::wstring threadFilterQuery_;
    bool threadFilterUseRegex_ = false;
    std::wstring moduleFilterQuery_;
    bool moduleFilterUseRegex_ = false;
    int moduleSortColumn_ = 0;
    bool moduleSortDescending_ = false;
    bool moduleVerifySignatures_ = true;
    bool tokenLoaded_ = false;
    bool tokenSwitchLoaded_ = false;
    bool sectionLoaded_ = false;
    bool hotkeyLoaded_ = false;
    bool keyboardLoaded_ = false;
    bool pebLoaded_ = false;
    std::vector<ProcessHotkeyEntry> hotkeyEntries_;
    std::vector<ProcessHotkeyEntry> keyboardHotkeyEntries_;
    std::vector<KeyboardHookEntry> keyboardHookEntries_;
};

} // namespace Ksword::Features::ProcessDetail
