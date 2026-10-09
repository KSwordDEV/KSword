#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace ks::r3::kernel {

// KernelFeatureId is the stable Win32-light identifier for every kernel entry
// retained from the original KernelDock. Input values are selected by the UI
// or controller; processing uses the id to route to facade methods; return
// behavior is value-only with no side effects.
enum class KernelFeatureId : std::uint32_t {
    ObjectNamespaceOverview = 1,
    ObjectDirectoryRecursive,
    NamedPipe,
    BaseNamedObjects,
    SymbolicLink,
    DeviceDriverObjects,
    ObjectTypeMatrix,
    CommunicationEndpoint,
    AtomTable,
    NtQueryLegacy,
    Ssdt,
    ShadowSsdt,
    InlineHook,
    IatEatHook,
    DynData,
    DriverStatus,
    CallbackIntercept,
    CallbackEnumeration,
    KernelExecutableMemory,
    KernelMemoryEvidence,
    ProcessCrossView,
    ThreadCrossView,
    DriverIntegrity,
    KernelCpuIntegrity,
    CpuHardwareSnapshot,
    PhysicalMemoryLayout,
    MutationAudit,
    KeyboardHotkeys,
    KeyboardHooks,
    DynDataCapabilities,
    MinifilterBypassPids,
    KernelTimerDpc,
    IoctlRegistry,
    PdbProfileStatus,
    CidTableSummary,
    IpcSummary,
    HookAuditSummary,
    WorkQueueThreads,
    SlatIommuAudit,
    HvmStatus,
    HvmEvents,
    DriverDispatchTable,
    DriverImageFields,
    DriverCommunication,
    PlatformAudit,
    SystemTimeState,
    I8042Audit,
    PiDdbCache,
    RawDiskSectors,
    NetworkTrafficPackets,
    ObjectTypeProcedures
};

// KernelFeatureBackend describes where a feature obtains data. Input is fixed
// feature metadata; processing lets facade and UI decide whether the operation
// is user-mode-only, driver-backed, or mixed; return behavior is enum value use.
enum class KernelFeatureBackend : std::uint32_t {
    UserModeNative,
    ArkDriverClient,
    Hybrid
};

// KernelFeatureDescriptor is one UI/catalog row. Inputs are constants supplied
// by each feature file; processing copies them into the module catalog; output is
// the data rendered by the Win32 lightweight kernel page.
struct KernelFeatureDescriptor {
    KernelFeatureId id = KernelFeatureId::ObjectNamespaceOverview;
    std::wstring title;
    std::wstring category;
    std::wstring summary;
    KernelFeatureBackend backend = KernelFeatureBackend::UserModeNative;
    bool requiresAdministrator = false;
    bool mayModifyKernelState = false;
};

// KernelRequest carries one operation request from UI/controller to facade.
// Inputs are selected feature id, optional filter strings, and feature flags;
// processing is owned by KernelFacade; return behavior is via KernelOperationResult.
struct KernelRequest {
    KernelFeatureId featureId = KernelFeatureId::ObjectNamespaceOverview;
    std::wstring filterText;
    std::wstring moduleFilterText;
    std::uint32_t flags = 0;
    std::uint64_t startAddress = 0;
    std::uint64_t endAddress = 0;
    std::uint32_t maxRows = 0;
    std::uint32_t idtVectorLimit = 0;
};

// KernelRequestFlag is the UI/facade bridge for per-page scan options. Inputs
// are set by Win32 controls such as the Hook include combo; processing in
// KernelFacade translates these stable bits into shared driver protocol flags;
// return behavior is normal bitmask use inside KernelRequest::flags.
enum KernelRequestFlag : std::uint32_t {
    KernelRequestFlagIncludeInternal = 0x00000001U,
    KernelRequestFlagIncludeClean = 0x00000002U,
    KernelRequestFlagIncludeIat = 0x00000004U,
    KernelRequestFlagIncludeEat = 0x00000008U,
    KernelRequestFlagRiskOnly = 0x00000010U,
    KernelRequestFlagIncludeNonModuleExecutableRanges = 0x00000020U,
};

// KernelResultRow is a generic row used before final per-feature tables are
// wired. Inputs are key/value columns plus detail text from a worker or facade;
// processing is UI rendering only; output is copied into list/detail controls.
struct KernelResultRow {
    std::vector<std::pair<std::wstring, std::wstring>> columns;
    std::wstring detailText;
};

// KernelObjectNamespaceEntry stores one object-namespace snapshot row used by
// the Win32 kernel page. Inputs come from the native object-namespace worker;
// processing keeps the row immutable in the UI model; output is the same
// detail/copy payload that the original Qt object namespace tree rendered.
struct KernelObjectNamespaceEntry {
    std::wstring rootPathText;
    std::wstring scopeDescriptionText;
    std::wstring directoryPathText;
    std::wstring objectNameText;
    std::wstring objectTypeText;
    std::wstring fullPathText;
    std::wstring enumApiText;
    std::wstring symbolicLinkTargetText;
    std::wstring statusText;
    std::wstring detailText;
    long statusCode = 0;
    bool querySucceeded = false;
    bool isDirectory = false;
    bool isSymbolicLink = false;
};

// KernelOperationResult is the common facade return packet. Inputs come from a
// query/action method; processing reports support, success, diagnostics, and
// rows; return behavior is value-only and never throws by contract.
struct KernelOperationResult {
    bool supported = false;
    bool success = false;
    bool destructiveAction = false;
    std::wstring message;
    std::vector<KernelResultRow> rows;
};

// KernelActionId identifies explicit row/menu operations that may change R0
// state. Inputs are chosen only by the Win32 context menu; processing is routed
// through KernelFacade and ArkDriverClient; return behavior is a normal
// KernelOperationResult so actions render in the same table as queries.
enum class KernelActionId : std::uint32_t {
    None = 0,
    InlineHookNopPatch,
    CallbackCancelPendingDecisions,
    CallbackAnswerEvent,
    CallbackApplyDisabledEmptyRules,
    CallbackApplyLocalRules,
    CallbackSafeRemove,
    CallbackExperimentalUnlink,
    MinifilterSetBypassPids,
    MinifilterClearBypassPids,
    FileMonitorStartFsctl,
    FileMonitorDrain,
    FileMonitorClear,
    DriverObjectQueryDetail,
    DriverObjectForceUnload,
    NativeObjectQueryDetail,
    NativeSymbolicLinkResolve,
    NativeNamedPipeProbe,
    DynDataApplyMatchedProfile,
    MutationCommitDryRun,
    MutationRollbackDryRun,
    MutationRollbackConfirmed,
    NetworkCaptureStart,
    NetworkCaptureStop,
    PiDdbDeleteEntry,
    DriverDispatchRestore,
    DriverDispatchAbandon,
    DriverImageRestore,
    DriverImageAbandon,
    DriverCommunicationRestore
};

// KernelActionRequest carries one explicit action from the UI to the facade.
// Inputs are the selected feature/action, selected row field snapshot, generic
// filter text for PID-list entry, and a force flag for second-confirmation flows;
// processing is owned by KernelFacade; return is KernelOperationResult.
struct KernelActionRequest {
    KernelFeatureId featureId = KernelFeatureId::ObjectNamespaceOverview;
    KernelActionId actionId = KernelActionId::None;
    std::vector<std::pair<std::wstring, std::wstring>> rowFields;
    std::wstring filterText;
    std::wstring moduleFilterText;
    bool force = false;
};

// ToDisplayName converts a feature id into a human-readable Chinese title.
// Input is one KernelFeatureId; processing uses a switch over stable ids; output
// is a display string for logs, diagnostic messages, and fallback UI text.
std::wstring ToDisplayName(KernelFeatureId id);

// BackendToDisplayName converts backend metadata into a compact UI label. Input
// is one backend enum; processing uses a switch; output is a display string.
std::wstring BackendToDisplayName(KernelFeatureBackend backend);

} // namespace ks::r3::kernel
