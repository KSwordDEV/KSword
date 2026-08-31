#pragma once

// ============================================================
// ksword/startup/startup.h
// Namespace: ks::startup
// Purpose:
// - Provide a non-UI startup persistence enumeration backend.
// - Keep records in UTF-8 std::string fields so Qt and non-Qt callers can adapt them.
// - Avoid UI framework dependencies in this layer.
// ============================================================

#include <cstddef>    // std::size_t: enumeration stage coordinates.
#include <cstdint>    // std::uint32_t: Win32 result and status placeholders.
#include <functional> // std::function: optional enumeration progress callback.
#include <string>     // std::string: UTF-8 text fields exposed across layers.
#include <vector>     // std::vector: startup record and catalog containers.

namespace ks::startup
{
    // StartupCategory describes the logical startup source family.
    enum class StartupCategory : int
    {
        All = 0,
        Logon,
        Services,
        Drivers,
        Tasks,
        ImageHijack,
        Registry,
        Wmi,
        Hidden // Cross-view findings: objects one Windows view exposes and another one hides.
    };

    // StartupEnumerationStage identifies the active source family during a full enumeration pass.
    // It is intentionally UI-neutral; callers map the stable stage to their own localized text.
    enum class StartupEnumerationStage : int
    {
        Logon = 0,
        Services,
        Drivers,
        Tasks,
        ImageHijack,
        AdvancedRegistry,
        Winsock,
        Wmi,
        Hidden
    };

    // StartupEnumerationProgressCallback runs immediately before each source family is enumerated.
    // stageIndex is zero-based and stageCount is the total number of source families in the pass.
    using StartupEnumerationProgressCallback = std::function<void(
        StartupEnumerationStage stage,
        std::size_t stageIndex,
        std::size_t stageCount)>;

    // StartupActionKind identifies a backend operation without parsing display text.
    enum class StartupActionKind : int
    {
        None = 0,
        RegistryRunValue,
        RegistryTree,
        StartupFolderFile,
        ScheduledTask,
        ScmStartType,
        WmiEntryRemoval
    };

    // StartupRegistryRoot identifies the registry hives accepted by warning-gated value actions.
    enum class StartupRegistryRoot : int
    {
        None = 0,
        CurrentUser,
        LocalMachine
    };

    // StartupScmStartMode preserves the native SCM mode instead of collapsing Manual into Disabled.
    enum class StartupScmStartMode : int
    {
        None = 0,
        Boot,
        System,
        Automatic,
        Manual,
        Disabled
    };

    // StartupRiskLevel lets UI layers select warning treatment without parsing diagnostics.
    enum class StartupRiskLevel : int
    {
        Normal = 0,
        Elevated,
        Critical
    };

    // StartupActionLocator contains machine-readable action coordinates.
    // Only fields relevant to actionKind are populated.
    struct StartupActionLocator
    {
        StartupRegistryRoot registryRoot = StartupRegistryRoot::None;
        std::string registrySubKeyText;
        std::string registryValueNameText;
        bool registryValueSnapshotValid = false;
        std::uint32_t registryValueType = 0;
        std::vector<std::uint8_t> registryRawData;
        bool registryTreeSnapshotValid = false;
        std::uint32_t registryTreeSubKeyCount = 0;
        std::uint32_t registryTreeValueCount = 0;
        std::uint64_t registryTreeLastWriteTime = 0;
        std::string originalFilePathText;
        std::string parkedFilePathText;
        bool fileIdentitySnapshotValid = false;
        std::uint64_t fileVolumeSerial = 0;
        std::uint64_t fileIndex = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t fileLastWriteTime = 0;
        std::string taskPathText;
        std::string taskNameText;
        std::string taskDefinitionSha256Text;
        std::string serviceNameText;
        bool serviceIsDriver = false;
        StartupScmStartMode serviceStartMode = StartupScmStartMode::None;
        std::uint32_t serviceType = 0;
        std::uint32_t serviceStartType = 0;
        std::string serviceBinaryPathText;
        std::string wmiClassNameText;
        std::string wmiNameText;
        std::string wmiFilterText;
        std::string wmiConsumerText;
        std::string backupIdText;
    };

    // StartupEntry is the unified backend record used by every enumerator.
    // All text is UTF-8. UI layers may convert it to their own view model.
    struct StartupEntry
    {
        std::string uniqueIdText;          // Stable identity for cache, deletion, or diagnostics.
        StartupCategory category = StartupCategory::All; // Logical category of this entry.
        std::string categoryText;          // Display-ready category text.
        std::string itemNameText;          // Entry display name.
        std::string publisherText;         // Signature/company placeholder or resolved publisher.
        std::string imagePathText;         // Normalized image path when one can be inferred.
        std::string commandText;           // Raw command, registry data, or action text.
        std::string locationText;          // Source location: registry key, SCM name, task path, etc.
        std::string locationGroupText;     // Registry tree group location when applicable.
        std::string registryValueNameText; // Real registry value name for deletion.
        std::string userText;              // User/context text.
        std::string detailText;            // Additional diagnostics or source details.
        std::string sourceTypeText;        // Source subtype such as Run, ScheduledTask, WMI-EventFilter.
        StartupActionKind actionKind = StartupActionKind::None; // Structured backend operation.
        StartupActionLocator actionLocator; // Structured coordinates consumed by action APIs.
        bool enabled = true;               // Whether the source is enabled; for SCM, whether it is not Disabled.
        bool canEnable = false;             // Whether SetStartupEntryEnabled(entry, true) is supported.
        bool canDisable = false;            // Whether SetStartupEntryEnabled(entry, false) is supported.
        StartupRiskLevel riskLevel = StartupRiskLevel::Elevated; // Structured warning severity.
        // Stable i18n codes: registry_user, registry_machine, startup_folder,
        // scheduled_task, backup_record, service, driver, critical_registry,
        // policy, winsock, wmi, unsupported_source.
        std::string riskReasonCode;
        std::string riskReasonText;         // Stable backend warning or unavailability reason.
        bool canOpenFileLocation = false;  // Whether imagePathText can be opened in Explorer.
        bool canOpenRegistryLocation = false; // Whether locationText points to a registry location.
        bool canDelete = false;            // Whether the caller can delete this source entry.
        bool deleteRegistryTree = false;   // True when deletion should remove the whole subkey.
        bool imagePathExists = false;      // Existence placeholder for UI filtering/future checks.
        bool signatureTrusted = false;     // Signature trust placeholder; publisherText is display text.
        std::uint32_t lastErrorCode = 0;   // Optional Win32 error for synthetic/error records.
    };

    // StartupEnumerationStageResultCallback runs after one source family completes and before its
    // records are moved into the aggregate result. The referenced batch is valid only for the
    // duration of the callback; callers that dispatch asynchronously must copy or convert it.
    using StartupEnumerationStageResultCallback = std::function<void(
        StartupEnumerationStage stage,
        std::size_t stageIndex,
        std::size_t stageCount,
        const std::vector<StartupEntry>& stageEntries)>;

    // StartupActionStatus is a caller-facing classification for startup actions.
    enum class StartupActionStatus : int
    {
        Success = 0,
        NoChange,
        InvalidEntry,
        NotSupported,
        Conflict,
        NotFound,
        AccessDenied,
        WriteFailed,
        VerificationFailed,
        RollbackFailed,
        ProcessFailed
    };

    // ActionResult reports the primary outcome and whether a failed mutation was rolled back.
    struct ActionResult
    {
        StartupActionStatus status = StartupActionStatus::InvalidEntry;
        bool success = false;
        bool changed = false;
        bool rollbackAttempted = false;
        bool rollbackSucceeded = false;
        std::uint32_t errorCode = 0;
        std::string messageText;
    };

    // CategoryToText returns a stable Chinese display label for a category.
    std::string CategoryToText(StartupCategory category);

    // NormalizeFilePathText extracts an executable/library/driver path from a command line.
    std::string NormalizeFilePathText(const std::string& commandText);

    // QueryPublisherTextByPath returns a publisher/signature display string, or empty on failure.
    std::string QueryPublisherTextByPath(const std::string& filePathText);

    // NormalizeRegistryLocationLine fixes one raw Autoruns-style registry catalog line.
    std::string NormalizeRegistryLocationLine(const std::string& rawLineText);

    // BuildKnownStartupRegistryLocationList normalizes and de-duplicates raw catalog lines.
    std::vector<std::string> BuildKnownStartupRegistryLocationList(
        const std::vector<std::string>& rawLineList);

    // EnumerateLogonEntries returns Run/RunOnce/RunOnceEx and Startup Folder records.
    std::vector<StartupEntry> EnumerateLogonEntries();

    // EnumerateServiceEntries returns Win32 service records with mutable SCM start types.
    std::vector<StartupEntry> EnumerateServiceEntries();

    // EnumerateDriverEntries returns driver service records with mutable SCM start types.
    std::vector<StartupEntry> EnumerateDriverEntries();

    // EnumerateTaskEntries returns Scheduled Task records collected through PowerShell.
    std::vector<StartupEntry> EnumerateTaskEntries();

    // EnumerateImageHijackEntries returns executable redirection and image-load findings from
    // IFEO, filtered IFEO subkeys, Application Verifier DLL settings, and SilentProcessExit.
    std::vector<StartupEntry> EnumerateImageHijackEntries();

    // EnumerateAdvancedRegistryEntries returns Explorer/Winlogon/LSA/COM style registry persistence.
    std::vector<StartupEntry> EnumerateAdvancedRegistryEntries();

    // EnumerateWinsockEntries returns Winsock provider/catalog registry records.
    std::vector<StartupEntry> EnumerateWinsockEntries();

    // EnumerateWmiEntries returns WMI permanent event persistence records.
    std::vector<StartupEntry> EnumerateWmiEntries();

    // EnumerateHiddenEntries returns persistence that ordinary Win32/COM enumeration cannot see.
    // Findings come from comparing two views of the same object: the native NT registry view against
    // the Win32 view, the registry service database against the SCM, the Task Scheduler registry
    // cache against the Task Scheduler API, the configured Startup folder against the shell default,
    // and per-user class registrations against machine-wide ones.
    // Records are report-only: hidden objects are not addressable through the normal action locators.
    std::vector<StartupEntry> EnumerateHiddenEntries();

    // EnumerateAllStartupEntries runs every backend enumerator in the standard StartupDock order.
    std::vector<StartupEntry> EnumerateAllStartupEntries();

    // Callback overload keeps the backend UI-neutral while allowing a caller to expose each source
    // family as a distinct progress step. The no-argument overload preserves existing callers.
    std::vector<StartupEntry> EnumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback);

    // Two-callback overload additionally publishes each completed source family as an ordered batch.
    std::vector<StartupEntry> EnumerateAllStartupEntries(
        const StartupEnumerationProgressCallback& progressCallback,
        const StartupEnumerationStageResultCallback& stageResultCallback);

    // SetStartupEntryEnabled performs a warning-gated operation using actionKind/actionLocator only.
    ActionResult SetStartupEntryEnabled(const StartupEntry& entry, bool enabled);

    // DeleteStartupEntry permanently removes an entry after revalidating its structured locator.
    ActionResult DeleteStartupEntry(const StartupEntry& entry);
}
