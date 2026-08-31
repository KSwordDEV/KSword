#pragma once

#include "KernelFacade.h"
#include "KernelCallbackEventReceiver.h"
#include "KernelModel.h"
#include "../../Core/Win32Lean.h"
#include "../../Ui/AsyncTask.h"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace Ksword::Features::Kernel {

struct KernelObjectNamespaceTreeNodeState;

// KernelR0EvidenceSnapshot is the immutable result of a client-side R0
// evidence projection. Worker tasks own this value completely before the UI
// applies it to the owner-data ListView.
struct KernelR0EvidenceSnapshot {
    KernelFeatureId featureId = KernelFeatureId::CpuHardwareSnapshot;
    std::vector<std::wstring> columns;
    std::vector<std::vector<std::wstring>> rows;
    std::wstring statusText;
    std::wstring selectedRowSignature;
    int topRow = 0;
};

enum class CallbackFileIoOperation {
    ImportConfig,
    ExportConfig,
    ExportFileMonitor,
    ExportResultTsv,
    CallbackModuleDetail,
    MapNtPath,
    OpenModuleFolder
};

// CallbackFileIoResult is the immutable boundary for callback-rule files and
// file-monitor exports. Picker dialogs and model application remain on the UI
// thread; file reads and writes are performed by a dedicated worker task.
struct CallbackFileIoResult {
    CallbackFileIoOperation operation = CallbackFileIoOperation::ImportConfig;
    std::wstring path;
    std::wstring text;
    std::wstring clipboardText;
    std::wstring errorText;
};

// KernelPage is the lightweight Win32 UI for retained kernel entries. Inputs are
// parent HWND and bounds during Create; processing owns child controls and sends
// model requests to KernelFacade; return behavior is HWND-based like normal
// Win32 pages, with no direct driver or protocol access from this UI class.
class KernelPage final {
public:
    KernelPage();
    ~KernelPage();

    KernelPage(const KernelPage&) = delete;
    KernelPage& operator=(const KernelPage&) = delete;

    // Create registers and creates the child page window. Inputs are parent,
    // control id, and bounds; processing stores this object in GWLP_USERDATA;
    // output is the created HWND or nullptr on failure.
    HWND Create(HWND parent, int controlId, const RECT& bounds);

    // SetInitialFeature selects a retained kernel feature after Create builds
    // the controls. Input is a stable KernelFeatureId; processing stores it
    // until PopulateTabs runs, then either selects a visible dock tab or enters
    // direct single-feature mode for pages hidden from the Kernel dock. There
    // is no return value.
    void SetInitialFeature(KernelFeatureId featureId) noexcept;

    // Window returns the page HWND. There is no input; output can be null before
    // Create succeeds or after WM_NCDESTROY.
    HWND Window() const noexcept { return hwnd_; }

    // WndProc is public only so the local Win32 class-registration helper can
    // bind it to WNDCLASSW. Inputs are normal Win32 procedure parameters;
    // processing dispatches to the KernelPage stored in GWLP_USERDATA; output is
    // a normal Win32 LRESULT.
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK FilterEditSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
        UINT_PTR subclassId, DWORD_PTR refData);

private:
    LRESULT HandleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    void CreateChildControls();
    void Layout();
    void PopulateTabs();
    void OnFeatureSelectionChanged();
    void RefreshSelectedFeature();
    void ExecuteActionInBackground(KernelActionRequest request, KernelActionId actionId, bool offerForcedRetry);
    void LocateNextResult();
    void ExecuteObjectNamespaceToolbarAction();
    void ExecuteObjectNamespaceDetailAction();
    void FillIntegrityInputsFromSelection();
    void RefreshKernelCpuIntegrityFromDriverPage();
    void ExecuteSelectedAction(KernelActionId actionId);
    KernelRequest BuildCurrentRequest(KernelFeatureId featureId) const;
    KernelActionRequest BuildCurrentActionRequest(KernelActionId actionId) const;
    void RenderDescriptor(const KernelFeatureDescriptor& descriptor);
    void RenderResult(const KernelOperationResult& result);
    void RebuildObjectNamespaceListFromCache(KernelFeatureId featureId);
    void ToggleObjectNamespaceListNode(int rowIndex);
    void RebuildObjectNamespaceTreeFromCurrentRows();
    void SelectObjectNamespaceTreeItem(LPARAM itemData);
    void SelectObjectNamespaceTreeRow(LPARAM rowIndex);
    void RebuildAtomTableFromCache();
    void RebuildNtQueryLegacyListFromCache();
    void RebuildDiagnosticDualTableFromCache(KernelFeatureId featureId);
    void RebuildCallbackEnumerationListFromCache();
    void RebuildKernelHookListFromCache(KernelFeatureId featureId);
    void RebuildKernelMemoryScanListFromCache(KernelFeatureId featureId);
    void RebuildCrossViewListFromCache(KernelFeatureId featureId);
    void RebuildIntegrityEvidenceListFromCache(KernelFeatureId featureId);
    void RebuildR0EvidenceListFromCache(KernelFeatureId featureId);
    void ScheduleR0EvidenceFilter(KernelFeatureId featureId);
    void RequestR0EvidenceRebuild(KernelFeatureId featureId);
    void ApplyR0EvidenceSnapshot(KernelR0EvidenceSnapshot snapshot);
    const KernelFeatureDescriptor* CurrentDescriptor() const;
    const KernelFeatureDescriptor* FeatureById(KernelFeatureId featureId) const;
    void RebuildSecondLevelTabs();
    void SelectCurrentFeature();
    bool SelectFeatureById(KernelFeatureId featureId);
    void ParkCurrentFeatureViewCache();
    void SaveCurrentFeatureViewCache(bool transferDataToCache);
    void InvalidateCurrentFeatureViewCache();
    bool RestoreFeatureViewCache(KernelFeatureId featureId);
    void ResetVisibleResultRows();
    void SyncResultListVirtualRows();
    void EnsureResultColumnsForCurrentFeature();
    std::vector<std::vector<std::wstring>> CaptureReportListRows(HWND list) const;
    void RestoreReportListRows(HWND list, const std::vector<std::vector<std::wstring>>& rows);
    std::wstring ResultCellText(int row, int column) const;
    std::wstring VisibleCellText(int row, int column) const;
    bool CurrentPrimaryUsesSecondaryTabs() const;
    void AddDynamicResultColumns(const KernelOperationResult& result, std::vector<std::wstring>& orderedColumns);
    void AddDynamicResultRow(int rowIndex, const KernelResultRow& resultRow, const std::vector<std::wstring>& orderedColumns);
    void RebuildResultListFromCache();
    void SortResultRowsByColumn(int columnIndex);
    void UpdateSelectedRowDetail();
    LRESULT HandleResultListCustomDraw(LPARAM lParam);
    void UpdatePropertyTableFromSelection();
    void UpdateSummaryTableFromRows();
    void ConfigureVisibleLayout();
    void ConfigureToolbarForDescriptor(const KernelFeatureDescriptor& descriptor);
    void PopulateCallbackInterceptPanel();
    void StartCallbackEventReceiver();
    void StopCallbackEventReceiver();
    void AcceptCallbackEvent(CallbackEventSnapshot snapshot);
    void AnswerCurrentCallbackEvent(bool allow);
    void RefreshCallbackEventLog();
    void EnsureCallbackLocalModel();
    void RenderCallbackLocalModel();
    void AppendCallbackAppLog(const std::wstring& message);
    int CallbackSelectedRuleTabIndex() const;
    int CallbackSelectedGroupRow() const;
    int CallbackSelectedRuleRow() const;
    std::uint32_t CallbackSelectedGroupId() const;
    void OnCallbackAddGroup();
    void OnCallbackRemoveGroup();
    void OnCallbackRenameGroup();
    void OnCallbackMoveGroup(bool moveUp);
    void OnCallbackToggleGroupEnabled();
    void OnCallbackAddRule();
    void OnCallbackRemoveRule();
    void OnCallbackMoveRule(bool moveUp);
    void OnCallbackToggleRuleEnabled();
    void OnCallbackCopyRuleText();
    void OnCallbackPasteRuleText();
    void OnCallbackBypassAdd();
    void OnCallbackBypassRemove();
    void OnCallbackImportConfig();
    void OnCallbackExportConfig();
    void OnCallbackExportFileMonitor();
    void OpenCallbackFileMonitorProcess();
    void OpenCallbackFileMonitorPath();
    void StartCallbackFileIo(CallbackFileIoOperation operation, std::wstring path, std::wstring text = {});
    void ApplyCallbackFileIoResult(CallbackFileIoResult result);
    void SetCallbackFileIoControlsEnabled(bool enabled);
    void ShowCallbackInterceptContextMenu(HWND source, POINT screenPoint);
    void CopyCallbackPanelSelection(HWND source);
    std::wstring SerializeCallbackLocalConfig() const;
    bool LoadCallbackLocalConfig(const std::wstring& text, std::wstring* errorText);
    bool CallbackRulesGlobalEnabled() const;
    std::uint32_t CurrentIncludeFlags() const;
    std::wstring BuildOriginalStyleSelectedRowDetail(KernelFeatureId featureId, int row) const;
    bool PrepareResultContextPoint(POINT& screenPoint, bool updatePropertyTable);
    void ShowResultContextMenu(POINT screenPoint);
    bool ShowAtomTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowNtQueryContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowObjectNamespaceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowObjectNamespaceOverviewContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowObjectDirectoryRecursiveContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowNamedPipeContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowSymbolicLinkContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowObjectTypeMatrixContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowCommunicationEndpointContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowDeviceDriverObjectsContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowSimpleObjectTableContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowKernelHookContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowCallbackEnumerationContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    bool ShowR0EvidenceContextMenu(POINT screenPoint, const KernelFeatureDescriptor& descriptor);
    void ApplySelectedModuleFilter(bool preferTargetModule);
    void ApplySelectedAddressFilter();
    void ApplySelectedPathFilter();
    bool RebuildCurrentObjectNamespaceFilter(const wchar_t* statusText);
    void ApplySelectedOwnerFilter();
    void ApplySelectedRiskFilter();
    void ApplySelectedPidTidFilter();
    void ApplySelectedCapabilityFilter();
    void ShowSelectedRowDialog();
    void CopySelectedCell();
    void CopySelectedRow();
    void CopySelectedRows(bool includeHeader);
    void CopySelectedDetails();
    void CopySelectedColumn(int columnIndex);
    std::wstring BuildSelectedRowsTsv(bool includeHeader) const;
    std::wstring BuildRowDetailText(int row) const;
    std::vector<int> CurrentCopyColumnIndices() const;
    void CopyAllRows();
    void CopyDiagnosticReport();
    std::wstring BuildDiagnosticReportForCurrentFeature() const;
    void ExportAllRowsTsv();
    void ApplySelectedTypeFilter();
    void ApplySelectedNameFilter();
    void ApplySelectedTargetFilter();
    void VerifySelectedAtom();
    void CopySelectedAtomSnippet();
    void CopyRowsWithSameDirectory();
    void MapSelectedNtPathAsDosPaths();
    void OpenSelectedCallbackModuleFolder();
    void ShowSelectedCallbackModuleFileDetail();
    std::wstring SelectedCallbackModulePath() const;
    std::wstring NormalizeCallbackModulePath(const std::wstring& modulePath) const;
    void CopyPreferredSelectedField(std::initializer_list<std::wstring> fieldNames, const wchar_t* statusText);
    std::wstring FirstSelectedRowField(std::initializer_list<std::wstring> fieldNames) const;
    std::wstring FirstSelectedRowValue(std::initializer_list<const wchar_t*> fieldNames) const;
    std::wstring SelectedRowField(const std::wstring& fieldName) const;
    void ClearResultTable();
    void ClearResultGridOnly();
    void AddResultTableColumn(int index, const std::wstring& title, int width);
    void AddResultTableRow(const std::vector<std::wstring>& cells);
    void AddResultTableRow(const std::vector<std::wstring>& cells, int indent);
    int CurrentPrimaryIndex() const;
    int CurrentSecondaryIndex() const;
    bool CurrentFeatureUsesVerticalSplitter() const;
    void MoveVerticalSplitterFromMouse(int mouseY);

private:
    HWND hwnd_ = nullptr;
    HWND primaryTab_ = nullptr;
    HWND secondaryTab_ = nullptr;
    HWND titleText_ = nullptr;
    HWND summaryText_ = nullptr;
    HWND backendText_ = nullptr;
    HWND statusText_ = nullptr;
    HWND filterLabel_ = nullptr;
    HWND filterEdit_ = nullptr;
    HWND moduleFilterLabel_ = nullptr;
    HWND moduleFilterEdit_ = nullptr;
    HWND symbolicLinkNoteText_ = nullptr;
    HWND deviceDriverDirectoryLabel_ = nullptr;
    HWND deviceDriverDirectoryCombo_ = nullptr;
    HWND deviceDriverTypeLabel_ = nullptr;
    HWND deviceDriverTypeCombo_ = nullptr;
    HWND baseNamedScopeCombo_ = nullptr;
    HWND baseNamedTypeCombo_ = nullptr;
    HWND integrityModuleBaseLabel_ = nullptr;
    HWND integrityModuleBaseEdit_ = nullptr;
    HWND integrityFillFromSelectionButton_ = nullptr;
    HWND integrityCpuOnlyButton_ = nullptr;
    HWND includeCombo_ = nullptr;
    HWND refreshButton_ = nullptr;
    HWND locateButton_ = nullptr;
    HWND copyDiagnosticButton_ = nullptr;
    HWND objectNamespaceTree_ = nullptr;
    int objectNamespaceSelectedRow_ = -1;
    std::wstring objectNamespaceSelectedKind_;
    std::wstring objectNamespaceSelectedPath_;
    std::wstring objectNamespaceSelectedDescription_;
    std::vector<std::unique_ptr<KernelObjectNamespaceTreeNodeState>> objectNamespaceTreeNodeStorage_;
    HWND resultList_ = nullptr;
    HWND propertyList_ = nullptr;
    HWND summaryList_ = nullptr;
    HWND detailEdit_ = nullptr;
    RECT verticalSplitterRect_ = {};
    int verticalSplitterOffset_ = -1;
    bool verticalSplitterDragging_ = false;
    HWND riskOnlyCheck_ = nullptr;
    HWND evidenceIncludeNonModuleCheck_ = nullptr;
    HWND evidenceStartEdit_ = nullptr;
    HWND evidenceEndEdit_ = nullptr;
    HWND evidenceMaxRowsLabel_ = nullptr;
    HWND evidenceMaxRowsEdit_ = nullptr;
    HWND evidenceMaxRowsSpin_ = nullptr;
    HWND integrityIdtVectorsLabel_ = nullptr;
    HWND integrityIdtVectorsEdit_ = nullptr;
    HWND integrityIdtVectorsSpin_ = nullptr;
    HWND callbackGlobalEnabledCheck_ = nullptr;
    HWND callbackApplyButton_ = nullptr;
    HWND callbackReloadButton_ = nullptr;
    HWND callbackImportButton_ = nullptr;
    HWND callbackExportButton_ = nullptr;
    HWND callbackStartReceiverButton_ = nullptr;
    HWND callbackStopReceiverButton_ = nullptr;
    HWND callbackAllowEventButton_ = nullptr;
    HWND callbackDenyEventButton_ = nullptr;
    HWND callbackStatusText_ = nullptr;
    HWND callbackGroupLabel_ = nullptr;
    HWND callbackAddGroupButton_ = nullptr;
    HWND callbackRemoveGroupButton_ = nullptr;
    HWND callbackRenameGroupButton_ = nullptr;
    HWND callbackMoveGroupUpButton_ = nullptr;
    HWND callbackMoveGroupDownButton_ = nullptr;
    HWND callbackGroupList_ = nullptr;
    HWND callbackRuleLabel_ = nullptr;
    HWND callbackAddRuleButton_ = nullptr;
    HWND callbackRemoveRuleButton_ = nullptr;
    HWND callbackMoveRuleUpButton_ = nullptr;
    HWND callbackMoveRuleDownButton_ = nullptr;
    HWND callbackRuleTab_ = nullptr;
    std::vector<HWND> callbackRuleLists_;
    HWND callbackBypassLabel_ = nullptr;
    HWND callbackBypassPidEdit_ = nullptr;
    HWND callbackBypassAddButton_ = nullptr;
    HWND callbackBypassRemoveButton_ = nullptr;
    HWND callbackBypassApplyButton_ = nullptr;
    HWND callbackBypassClearButton_ = nullptr;
    HWND callbackBypassRefreshButton_ = nullptr;
    HWND callbackBypassList_ = nullptr;
    HWND callbackLogTab_ = nullptr;
    HWND callbackAppLogEdit_ = nullptr;
    HWND callbackEventLogEdit_ = nullptr;
    HWND callbackFileMonitorLabel_ = nullptr;
    HWND callbackStartFsctlButton_ = nullptr;
    HWND callbackDrainFileMonitorButton_ = nullptr;
    HWND callbackClearFileMonitorButton_ = nullptr;
    HWND callbackExportFileMonitorButton_ = nullptr;
    HWND callbackFileMonitorFsctlOnlyCheck_ = nullptr;
    HWND callbackFileMonitorStatusText_ = nullptr;
    HWND callbackFileMonitorList_ = nullptr;
    HWND callbackBypassStatusText_ = nullptr;
    std::vector<KernelFeatureDescriptor> features_;
    std::vector<std::wstring> primaryTabs_;
    std::vector<KernelFeatureId> primaryFeatureIds_;
    std::vector<KernelFeatureId> secondaryFeatureIds_;
    KernelFeatureId initialFeatureId_ = KernelFeatureId::ObjectNamespaceOverview;
    bool hasInitialFeatureId_ = false;
    KernelFeatureId directFeatureId_ = KernelFeatureId::ObjectNamespaceOverview;
    bool hasDirectFeatureId_ = false;
    std::vector<std::wstring> currentColumns_;
    std::vector<std::vector<std::wstring>> currentRows_;
    std::vector<int> currentRowIndents_;
    std::vector<std::wstring> collapsedObjectPaths_;
    std::vector<std::wstring> currentRawColumns_;
    std::vector<std::vector<std::wstring>> currentRawRows_;
    struct KernelFeatureViewCache {
        std::vector<std::wstring> columns;
        std::vector<std::vector<std::wstring>> rows;
        std::vector<int> rowIndents;
        std::vector<std::wstring> rawColumns;
        std::vector<std::vector<std::wstring>> rawRows;
        std::vector<std::wstring> collapsedObjectPaths;
        std::vector<std::vector<std::wstring>> propertyRows;
        std::vector<std::vector<std::wstring>> summaryRows;
        std::wstring detailText;
        std::wstring statusText;
        std::wstring filterText;
        std::wstring moduleFilterText;
        int objectNamespaceSelectedRow = -1;
        std::wstring objectNamespaceSelectedKind;
        std::wstring objectNamespaceSelectedPath;
        std::wstring objectNamespaceSelectedDescription;
        int sortColumn = -1;
        bool sortAscending = true;
        int selectedRow = -1;
        int topRow = 0;
        bool hasData = false;
    };
    std::unordered_map<KernelFeatureId, KernelFeatureViewCache> featureViewCache_;
    std::unordered_map<KernelFeatureId, KernelFeatureId> lastSecondaryFeatureByPrimary_;
    KernelFeatureId activeFeatureId_ = KernelFeatureId::ObjectNamespaceOverview;
    bool hasActiveFeatureId_ = false;
    bool suppressFilterChange_ = false;
    KernelFeatureId objectNamespaceTreeFeatureId_ = KernelFeatureId::ObjectNamespaceOverview;
    bool hasObjectNamespaceTreeFeatureId_ = false;
    struct CallbackRuleGroup {
        std::uint32_t id = 0;
        std::wstring name;
        bool enabled = true;
        int priority = 10;
        std::wstring comment;
    };
    struct CallbackRule {
        std::uint32_t id = 0;
        std::uint32_t groupId = 0;
        int typeIndex = 0;
        std::wstring name;
        bool enabled = true;
        std::wstring operation = L"监控";
        std::wstring matchMode = L"包含";
        std::wstring action = L"记录";
        std::uint32_t timeoutMs = 0;
        std::wstring timeoutDefault = L"允许";
        std::wstring initiatorPattern;
        std::wstring targetPattern;
        int priority = 10;
        std::wstring comment;
    };
    std::vector<CallbackRuleGroup> callbackGroups_;
    std::vector<CallbackRule> callbackRules_;
    std::unique_ptr<CallbackEventReceiver> callbackEventReceiver_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<KernelOperationResult>> callbackAnswerTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<CallbackFileIoResult>> callbackFileIoTask_;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<KernelR0EvidenceSnapshot>> r0EvidenceFilterTask_;
    std::vector<CallbackEventSnapshot> callbackPendingEvents_;
    std::uint32_t nextCallbackGroupId_ = 2;
    std::uint32_t nextCallbackRuleId_ = 1;
    HWND callbackContextList_ = nullptr;
    int contextColumn_ = -1;
    int sortColumn_ = -1;
    bool sortAscending_ = true;
    std::uint64_t queryRequestId_ = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<KernelOperationResult>> queryTask_;
    std::uint64_t actionRequestId_ = 0;
    std::unique_ptr<Ksword::Ui::AsyncSnapshotTask<KernelOperationResult>> actionTask_;
    KernelFeatureId pendingR0EvidenceFeatureId_ = KernelFeatureId::CpuHardwareSnapshot;
    bool hasPendingR0EvidenceFilter_ = false;
    KernelFacade facade_;
};

// CreateKernelPage creates the Win32-light kernel module page. Inputs are parent,
// command id and bounds; processing allocates a KernelPage owned by its HWND;
// output is the page HWND. The page deletes itself on WM_NCDESTROY.
HWND CreateKernelPage(HWND parent, int controlId, const RECT& bounds);

// CreateKernelPageForFeature creates the same Win32-light kernel page but
// preselects one retained kernel feature. Inputs are parent/control/bounds plus
// the stable feature id; output is the page HWND or nullptr on creation failure.
HWND CreateKernelPageForFeature(HWND parent, int controlId, const RECT& bounds, KernelFeatureId featureId);

} // namespace Ksword::Features::Kernel
