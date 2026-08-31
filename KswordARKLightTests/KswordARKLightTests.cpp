#include "../KswordARKLight/Core/DriverLeasePolicy.h"
#include "../KswordARKLight/Core/EntityRef.h"
#include "../KswordARKLight/Core/WorkspaceConfig.h"
#include "../KswordARKLight/Features/File/PathNavigator.h"
#include "../KswordARKLight/Features/Monitor/EtwEventModel.h"
#include "../KswordARKLight/Features/Registry/RegistrySearchModel.h"
#include "../KswordARKLight/Features/SysTools/IoctlDecoder.h"
#include "../KswordARKLight/Features/Window/Win32kTimerEvidenceModel.h"
#include "../KswordARKLight/Features/Memory/MemorySnapshot.h"
#include "../KswordARKLight/Features/Memory/MemoryInspection.h"
#include "../KswordARKLight/Features/Memory/MemoryWritePlan.h"
#include "../KswordARKLight/Ui/EvidenceSession.h"
#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h"

#include <array>
#include <iostream>
#include <cwchar>
#include <limits>
#include <span>
#include <string>
#include <vector>

namespace {

int failures = 0;

void Expect(const bool condition, const wchar_t* label) {
    if (!condition) {
        ++failures;
        std::wcerr << L"FAIL: " << label << L'\n';
    }
}

} // namespace

int wmain() {
    using Ksword::Core::CommandInputKind;
    using Ksword::Core::DriverLeasePolicy;
    using Ksword::Core::EntityKind;
    using Ksword::Core::NavigationTarget;
    using Ksword::Core::ParseCommandInput;
    using Ksword::Core::WorkspaceCommandId;
    using Ksword::Core::WorkspaceConfig;
    using Ksword::Core::WorkspaceConfigDecodeStatus;
    using Ksword::Features::Memory::MemorySnapshotHistory;
    using Ksword::Features::Memory::MemoryReadSnapshot;

    Expect(DriverLeasePolicy::OwnsStartTransition(false, true), L"new driver start is owned");
    Expect(!DriverLeasePolicy::OwnsStartTransition(true, true), L"pre-existing driver is not owned");
    Expect(DriverLeasePolicy::ShouldStopOnLastRelease(true, 0), L"owned driver stops on last lease");
    Expect(!DriverLeasePolicy::ShouldStopOnLastRelease(true, 1), L"owned driver stays for peer lease");
    Expect(!DriverLeasePolicy::ShouldStopOnLastRelease(false, 0), L"pre-existing driver stays running");

    WorkspaceConfig workspaceConfig{};
    workspaceConfig.hasNormalRect = true;
    workspaceConfig.normalRect = { -1920, 40, 1200, 1080 };
    workspaceConfig.maximized = true;
    workspaceConfig.activeCommandId = 40010;
    const auto workspaceBinary = Ksword::Core::SerializeWorkspaceConfig(workspaceConfig);
    const auto workspaceRoundTrip = Ksword::Core::DeserializeWorkspaceConfig(workspaceBinary);
    Expect(workspaceBinary.size() == Ksword::Core::kWorkspaceConfigBinarySize &&
            workspaceBinary[0U] == static_cast<std::uint8_t>('K') &&
            workspaceBinary[1U] == static_cast<std::uint8_t>('S') &&
            workspaceBinary[2U] == static_cast<std::uint8_t>('L') &&
            workspaceBinary[3U] == static_cast<std::uint8_t>('W') &&
            workspaceBinary[4U] == 1U && workspaceBinary[5U] == 0U &&
            workspaceBinary[6U] == 36U && workspaceBinary[7U] == 0U &&
            workspaceBinary[8U] == 3U && workspaceBinary[9U] == 0U &&
            workspaceBinary[12U] == 0x80U && workspaceBinary[13U] == 0xF8U &&
            workspaceBinary[14U] == 0xFFU && workspaceBinary[15U] == 0xFFU,
        L"workspace config emits a fixed explicit little-endian binary layout");
    Expect(workspaceRoundTrip.valid() && !workspaceRoundTrip.discardedNormalRect &&
            workspaceRoundTrip.config.hasNormalRect &&
            workspaceRoundTrip.config.normalRect.left == -1920 &&
            workspaceRoundTrip.config.normalRect.top == 40 &&
            workspaceRoundTrip.config.normalRect.right == 1200 &&
            workspaceRoundTrip.config.normalRect.bottom == 1080 &&
            workspaceRoundTrip.config.maximized && workspaceRoundTrip.config.activeCommandId == 40010,
        L"workspace config round-trips rectangle maximized and command state");

    auto badMagicWorkspace = workspaceBinary;
    badMagicWorkspace[0U] = static_cast<std::uint8_t>('X');
    auto badVersionWorkspace = workspaceBinary;
    badVersionWorkspace[4U] = 2U;
    auto badDeclaredSizeWorkspace = workspaceBinary;
    badDeclaredSizeWorkspace[6U] = 35U;
    auto badFlagsWorkspace = workspaceBinary;
    badFlagsWorkspace[8U] |= 0x04U;
    auto badReservedWorkspace = workspaceBinary;
    badReservedWorkspace[32U] = 1U;
    const auto shortWorkspace = Ksword::Core::DeserializeWorkspaceConfig(
        std::span<const std::uint8_t>(workspaceBinary.data(), workspaceBinary.size() - 1U));
    Expect(!shortWorkspace.valid() && shortWorkspace.status == WorkspaceConfigDecodeStatus::InvalidLength &&
            Ksword::Core::DeserializeWorkspaceConfig(badMagicWorkspace).status == WorkspaceConfigDecodeStatus::InvalidMagic &&
            Ksword::Core::DeserializeWorkspaceConfig(badVersionWorkspace).status == WorkspaceConfigDecodeStatus::UnsupportedVersion &&
            Ksword::Core::DeserializeWorkspaceConfig(badDeclaredSizeWorkspace).status == WorkspaceConfigDecodeStatus::InvalidDeclaredSize &&
            Ksword::Core::DeserializeWorkspaceConfig(badFlagsWorkspace).status == WorkspaceConfigDecodeStatus::InvalidFlags &&
            Ksword::Core::DeserializeWorkspaceConfig(badReservedWorkspace).status == WorkspaceConfigDecodeStatus::InvalidReserved,
        L"workspace config rejects corrupt header flags and reserved bytes");

    auto invalidRectWorkspace = workspaceBinary;
    invalidRectWorkspace[20U] = invalidRectWorkspace[12U];
    invalidRectWorkspace[21U] = invalidRectWorkspace[13U];
    invalidRectWorkspace[22U] = invalidRectWorkspace[14U];
    invalidRectWorkspace[23U] = invalidRectWorkspace[15U];
    const auto invalidRectRestore = Ksword::Core::DeserializeWorkspaceConfig(invalidRectWorkspace);
    const std::array<WorkspaceCommandId, 2U> fallbackModules = { 40001, 40002 };
    Expect(invalidRectRestore.valid() && invalidRectRestore.discardedNormalRect &&
            !invalidRectRestore.config.hasNormalRect && invalidRectRestore.config.maximized &&
            invalidRectRestore.config.activeCommandId == 40010 &&
            Ksword::Core::ResolveWorkspaceCommandId(
                invalidRectRestore.config.activeCommandId, fallbackModules, 40002) == 40002,
        L"workspace restore drops only an invalid rectangle and independently falls back the command");

    const std::array<WorkspaceCommandId, 4U> originalModuleOrder = { 40001, 40010, 40011, 40018 };
    const std::array<WorkspaceCommandId, 4U> reorderedModules = { 40018, 40011, 40001, 40010 };
    Expect(Ksword::Core::ResolveWorkspaceCommandId(40011, originalModuleOrder, 40001) == 40011 &&
            Ksword::Core::ResolveWorkspaceCommandId(40011, reorderedModules, 40001) == 40011 &&
            Ksword::Core::ResolveWorkspaceCommandId(49999, originalModuleOrder) == 40001 &&
            Ksword::Core::ResolveWorkspaceCommandId(49999, reorderedModules) == 40001,
        L"workspace command restore uses stable ids rather than module indexes or order");

    const auto process = ParseCommandInput(L" pid 1234 ");
    Expect(process.kind == CommandInputKind::Navigation, L"pid command navigates");
    Expect(process.navigation.target == NavigationTarget::ProcessDetails, L"pid target");
    Expect(process.navigation.entity.kind == EntityKind::Process && process.navigation.entity.id == 1234,
        L"pid entity identity");

    const auto memory = ParseCommandInput(L"mem 4321");
    Expect(memory.kind == CommandInputKind::Navigation &&
            memory.navigation.target == NavigationTarget::MemoryOperations &&
            memory.navigation.entity.kind == EntityKind::Process && memory.navigation.entity.id == 4321U,
        L"memory command targets explicit process operations");
    const auto memoryModule = ParseCommandInput(L"内存");
    Expect(memoryModule.kind == CommandInputKind::Navigation && memoryModule.navigation.target == NavigationTarget::Default &&
            memoryModule.navigation.entity.kind == EntityKind::Module,
        L"plain memory title still opens the module without a target");

    const auto window = ParseCommandInput(L"hwnd 0xABC");
    Expect(window.navigation.target == NavigationTarget::WindowManager && window.navigation.entity.id == 0xABCU,
        L"hex HWND command");

    const auto file = ParseCommandInput(L"file C:\\Windows\\System32\\ntdll.dll");
    Expect(file.navigation.target == NavigationTarget::FileBrowser &&
        file.navigation.entity.text == L"C:\\Windows\\System32\\ntdll.dll", L"file command");

    const auto module = ParseCommandInput(L"网络");
    Expect(module.navigation.entity.kind == EntityKind::Module && module.navigation.entity.text == L"网络",
        L"plain module title");
    const auto englishModule = ParseCommandInput(L"process");
    Expect(englishModule.kind == CommandInputKind::Navigation &&
            englishModule.navigation.entity.kind == EntityKind::Module &&
            englishModule.navigation.entity.text == L"进程",
        L"bare English module alias resolves to a registry title");
    const auto fileModule = ParseCommandInput(L"file");
    Expect(fileModule.kind == CommandInputKind::Navigation &&
            fileModule.navigation.entity.kind == EntityKind::Module &&
            fileModule.navigation.entity.text == L"文件",
        L"bare file alias opens its module instead of requiring a path");

    const auto shell = ParseCommandInput(L"! whoami /all");
    Expect(shell.kind == CommandInputKind::Shell && shell.shellCommand == L"whoami /all", L"explicit shell escape");
    Expect(ParseCommandInput(L"pid zero").kind == CommandInputKind::Invalid, L"invalid pid rejected");
    Expect(ParseCommandInput(L"pid 4294967296").kind == CommandInputKind::Invalid &&
            ParseCommandInput(L"tid 0x100000000").kind == CommandInputKind::Invalid &&
            ParseCommandInput(L"net 4294967296").kind == CommandInputKind::Invalid,
        L"32-bit entity commands reject values that would truncate during routing");
    const auto largeHwnd = ParseCommandInput(L"hwnd 0x100000000");
    Expect(largeHwnd.kind == CommandInputKind::Navigation &&
            largeHwnd.navigation.entity.kind == EntityKind::Window &&
            largeHwnd.navigation.entity.id == 0x100000000ULL,
        L"HWND command preserves a 64-bit native handle value");

    using Ksword::Features::File::PathNavigator;
    Expect(PathNavigator::normalizeKnownDirectoryPath(L" C:/Program Files/KSword/ ") == L"C:\\Program Files\\KSword",
        L"known DOS directory normalizes without probing");
    Expect(PathNavigator::normalizeKnownDirectoryPath(L"\\\\server\\share\\folder\\") == L"\\\\server\\share\\folder",
        L"known UNC directory normalizes without probing");
    Expect(PathNavigator::normalizeKnownDirectoryPath(L"\\Device\\HarddiskVolume3\\Windows").empty() &&
            PathNavigator::normalizeKnownDirectoryPath(L"\\\\?\\C:\\Windows").empty() &&
            PathNavigator::normalizeKnownDirectoryPath(L"C:relative").empty(),
        L"known directory rejects device extended and relative syntax");
    Expect(PathNavigator::parentDirectoryForKnownFilePath(L"C:\\Windows\\System32\\notepad.exe") == L"C:\\Windows\\System32" &&
            PathNavigator::parentDirectoryForKnownFilePath(L"\\\\server\\share\\folder\\report.txt") == L"\\\\server\\share\\folder" &&
            PathNavigator::parentDirectoryForKnownFilePath(L"C:\\pagefile.sys") == L"C:\\",
        L"known file parent stays within explicit DOS and UNC routes");
    Expect(PathNavigator::parentDirectoryForKnownFilePath(L"svchost.exe -k netsvcs").empty() &&
            PathNavigator::parentDirectoryForKnownFilePath(L"\\\\?\\C:\\Windows\\notepad.exe").empty(),
        L"known file parent rejects command and extended syntax");

    Ksword::Features::Monitor::EtwEvent firstEtwEvent{};
    firstEtwEvent.timeText = L"2026-08-27 10:00:00.000";
    firstEtwEvent.providerText = L"Provider One";
    firstEtwEvent.eventId = 10U;
    firstEtwEvent.level = 4U;
    firstEtwEvent.processId = 100U;
    firstEtwEvent.threadId = 101U;
    firstEtwEvent.summary = L"first summary";
    Ksword::Features::Monitor::EtwEvent secondEtwEvent{};
    secondEtwEvent.timeText = L"2026-08-27 10:00:01.000";
    secondEtwEvent.providerText = L"Provider\tTwo";
    secondEtwEvent.eventId = 20U;
    secondEtwEvent.level = 5U;
    secondEtwEvent.processId = 200U;
    secondEtwEvent.threadId = 201U;
    secondEtwEvent.summary = L"second\r\nsummary";
    const std::wstring etwTsv = Ksword::Features::Monitor::BuildVisibleEtwEventsTsv(
        { firstEtwEvent, secondEtwEvent }, { 1U, 0U });
    Expect(etwTsv.find(L"PID\t时间\tProvider\tTID\tEventId\tLevel\t摘要\r\n200\t2026-08-27 10:00:01.000\tProvider Two\t201\t20\t5\tsecond  summary\r\n100") == 0U,
        L"ETW TSV follows visible order and sanitizes cell delimiters");
    Expect(Ksword::Features::Monitor::BuildVisibleEtwEventsTsv({ firstEtwEvent }, {}).empty() &&
            Ksword::Features::Monitor::BuildVisibleEtwEventsTsv({ firstEtwEvent }, { 3U }).empty(),
        L"ETW TSV rejects empty and invalid visible snapshots");

    Ksword::Features::Registry::RegistrySearchRequest registrySearchRequest{};
    registrySearchRequest.startPath = L"  HKLM\\Software\\KSword  ";
    registrySearchRequest.query = L"  Needle  ";
    registrySearchRequest.maxKeys = 999999U;
    registrySearchRequest.maxValues = 999999U;
    registrySearchRequest.maxResults = 999999U;
    registrySearchRequest.maxDepth = 999999U;
    registrySearchRequest.maxValuePreviewBytes = 999999U;
    const auto registrySearchValidation = Ksword::Features::Registry::ValidateRegistrySearchRequest(registrySearchRequest);
    Expect(registrySearchValidation.valid && registrySearchValidation.request.startPath == L"HKLM\\Software\\KSword" &&
            registrySearchValidation.normalizedQuery == L"Needle" &&
            registrySearchValidation.request.maxKeys == Ksword::Features::Registry::kRegistrySearchMaxKeys &&
            registrySearchValidation.request.maxValues == Ksword::Features::Registry::kRegistrySearchMaxValues &&
            registrySearchValidation.request.maxResults == Ksword::Features::Registry::kRegistrySearchMaxResults &&
            registrySearchValidation.request.maxDepth == Ksword::Features::Registry::kRegistrySearchMaxDepth &&
            registrySearchValidation.request.maxValuePreviewBytes == Ksword::Features::Registry::kRegistrySearchMaxValuePreviewBytes,
        L"registry search request trims text and clamps hard budgets");
    Expect(!Ksword::Features::Registry::ValidateRegistrySearchRequest({ L"HKLM", L"" }).valid &&
            !Ksword::Features::Registry::ValidateRegistrySearchRequest({ L"", L"needle" }).valid,
        L"registry search rejects empty path and keyword");
    Ksword::Features::Registry::RegistrySearchRequest zeroBudgetSearchRequest{};
    zeroBudgetSearchRequest.startPath = L"HKLM";
    zeroBudgetSearchRequest.query = L"needle";
    zeroBudgetSearchRequest.maxKeys = 0U;
    zeroBudgetSearchRequest.maxValues = 0U;
    zeroBudgetSearchRequest.maxResults = 0U;
    zeroBudgetSearchRequest.maxDepth = 0U;
    zeroBudgetSearchRequest.maxValuePreviewBytes = 0U;
    const auto zeroBudgetSearchValidation = Ksword::Features::Registry::ValidateRegistrySearchRequest(zeroBudgetSearchRequest);
    Expect(zeroBudgetSearchValidation.valid &&
            zeroBudgetSearchValidation.request.maxKeys == Ksword::Features::Registry::kRegistrySearchMaxKeys &&
            zeroBudgetSearchValidation.request.maxValues == Ksword::Features::Registry::kRegistrySearchMaxValues &&
            zeroBudgetSearchValidation.request.maxResults == Ksword::Features::Registry::kRegistrySearchMaxResults &&
            zeroBudgetSearchValidation.request.maxDepth == Ksword::Features::Registry::kRegistrySearchMaxDepth &&
            zeroBudgetSearchValidation.request.maxValuePreviewBytes == Ksword::Features::Registry::kRegistrySearchMaxValuePreviewBytes,
        L"registry search normalizes omitted zero budgets to fixed bounds");

    Ksword::Features::Registry::RegistrySearchCandidate registryCandidate{};
    registryCandidate.kind = Ksword::Features::Registry::RegistrySearchEntryKind::Value;
    registryCandidate.keyPath = L" HKLM\\Software\\Needle\\Branch ";
    registryCandidate.valueName = L"Name\tNeedle";
    registryCandidate.valueTypeText = L"REG_SZ";
    registryCandidate.dataPreview = L"line1\r\nneedle payload";
    registryCandidate.dataByteCount = 80U;
    registryCandidate.depth = 3U;
    const auto registryHit = Ksword::Features::Registry::ProjectRegistrySearchHit(registryCandidate, 24U);
    Expect(registryHit.valid && registryHit.keyPath == L"HKLM\\Software\\Needle\\Branch" &&
            registryHit.valueName == L"Name Needle" && registryHit.dataPreviewTruncated &&
            Ksword::Features::Registry::RegistrySearchHitMatches(registryHit, L"NEEDLE") &&
            Ksword::Features::Registry::RegistrySearchHitMatches(registryHit, L"reg_sz") &&
            !Ksword::Features::Registry::RegistrySearchHitMatches(registryHit, L"missing"),
        L"registry search projects safe candidates and matches fields case insensitively");
    Ksword::Features::Registry::RegistrySearchSnapshot registrySearchSnapshot{};
    registrySearchSnapshot.request = registrySearchValidation.request;
    registrySearchSnapshot.stopReason = Ksword::Features::Registry::RegistrySearchStopReason::DepthLimitReached;
    registrySearchSnapshot.counters.visitedKeyCount = 12U;
    registrySearchSnapshot.counters.visitedValueCount = 4U;
    registrySearchSnapshot.counters.skippedDepthCount = 2U;
    registrySearchSnapshot.hits = { registryHit };
    Expect(Ksword::Features::Registry::BuildRegistrySearchStatusText(registrySearchSnapshot).find(L"深度") != std::wstring::npos,
        L"registry search status names explicit traversal stop reasons");
    registrySearchSnapshot.stopReason = Ksword::Features::Registry::RegistrySearchStopReason::ValueLimitReached;
    Expect(Ksword::Features::Registry::BuildRegistrySearchStatusText(registrySearchSnapshot).find(L"个值的上限") != std::wstring::npos,
        L"registry search status names the value work bound");
    registrySearchSnapshot.stopReason = Ksword::Features::Registry::RegistrySearchStopReason::SubKeyEnumerationLimitReached;
    registrySearchSnapshot.counters.inspectedSubKeyCount = 12U;
    Expect(Ksword::Features::Registry::BuildRegistrySearchStatusText(registrySearchSnapshot).find(L"子键枚举工作上限") != std::wstring::npos,
        L"registry search status distinguishes child-enumeration work bounds");
    const std::wstring registrySearchTsv = Ksword::Features::Registry::BuildVisibleRegistrySearchTsv(
        { registryHit, {} }, { 0U, 1U, 9U });
    Expect(registrySearchTsv.find(L"类型\t键路径\t值名称") == 0U &&
            registrySearchTsv.find(L"Name Needle") != std::wstring::npos &&
            registrySearchTsv.find(L'\t') != std::wstring::npos &&
            registrySearchTsv.find(L"\r\nneedle") == std::wstring::npos,
        L"registry search TSV preserves valid visible order and sanitizes fields");

    const auto ioctl = Ksword::Features::SysTools::DecodeIoctlCode(L" 0x222004 ");
    Expect(ioctl.state == Ksword::Features::SysTools::IoctlDecodeState::Valid &&
            ioctl.code == 0x00222004U && ioctl.deviceType == 0x0022U && ioctl.function == 0x0801U &&
            ioctl.access == 0U && ioctl.method == 0U && !ioctl.common && ioctl.custom,
        L"IOCTL decoder extracts standard CTL_CODE fields");
    const auto ioctlBoundary = Ksword::Features::SysTools::DecodeIoctlCode(L"FFFFFFFF");
    Expect(ioctlBoundary.state == Ksword::Features::SysTools::IoctlDecodeState::Valid &&
            ioctlBoundary.deviceType == 0xFFFFU && ioctlBoundary.function == 0x0FFFU &&
            ioctlBoundary.access == 3U && ioctlBoundary.method == 3U && ioctlBoundary.common && ioctlBoundary.custom,
        L"IOCTL decoder preserves common custom and field boundaries");
    Expect(Ksword::Features::SysTools::DecodeIoctlCode(L"").state == Ksword::Features::SysTools::IoctlDecodeState::Empty &&
            Ksword::Features::SysTools::DecodeIoctlCode(L"0x").state == Ksword::Features::SysTools::IoctlDecodeState::Invalid &&
            Ksword::Features::SysTools::DecodeIoctlCode(L"123456789").state == Ksword::Features::SysTools::IoctlDecodeState::Invalid &&
            Ksword::Features::SysTools::DecodeIoctlCode(L"0x22G004").state == Ksword::Features::SysTools::IoctlDecodeState::Invalid,
        L"IOCTL decoder rejects malformed and overflow input");
    Expect(Ksword::Features::SysTools::BuildIoctlDecodedReport(ioctl).find(L"FILE_ANY_ACCESS") != std::wstring::npos &&
            Ksword::Features::SysTools::BuildIoctlDecodedReport(ioctlBoundary).find(L"METHOD_NEITHER") != std::wstring::npos,
        L"IOCTL decoder report includes standard access and method names");

    ksword::ark::Win32kTimersResult timerEvidence{};
    timerEvidence.io.ok = true;
    timerEvidence.io.message = "timer snapshot ok";
    timerEvidence.version = 2U;
    timerEvidence.status = KSWORD_ARK_WIN32K_STATUS_OK;
    timerEvidence.totalCount = 3U;
    timerEvidence.returnedCount = 1U;
    timerEvidence.entrySize = sizeof(KSWORD_ARK_WIN32K_TIMER_ENTRY);
    timerEvidence.flags = 0x17U;
    timerEvidence.lastStatus = -1073741823L;
    timerEvidence.capabilityMask = 0x1122334455667788ULL;
    timerEvidence.missingCapabilityMask = 0x10ULL;
    timerEvidence.timerHashTable = 0xFFFFF80012340000ULL;
    timerEvidence.visitedNodeCount = 8U;
    timerEvidence.readFailureCount = 1U;
    timerEvidence.corruptBucketCount = 2U;
    timerEvidence.duplicateCount = 3U;
    timerEvidence.win32kbaseTimeDateStamp = 0x11223344U;
    timerEvidence.win32kbaseImageSize = 0x55667788U;
    timerEvidence.win32kfullTimeDateStamp = 0x99AABBCCU;
    timerEvidence.win32kfullImageSize = 0xDDEEFF00U;
    timerEvidence.layout.source = KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY;
    timerEvidence.layout.objectSize = 0x88U;
    timerEvidence.layout.bucketCount = 64U;
    timerEvidence.layout.bucketStride = 16U;
    KSWORD_ARK_WIN32K_TIMER_ENTRY timerEntry{};
    timerEntry.fieldFlags = KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT |
        KSWORD_ARK_WIN32K_TIMER_FIELD_THREAD |
        KSWORD_ARK_WIN32K_TIMER_FIELD_CALLBACK |
        KSWORD_ARK_WIN32K_TIMER_FIELD_INTERVAL |
        KSWORD_ARK_WIN32K_TIMER_FIELD_FLAGS |
        KSWORD_ARK_WIN32K_TIMER_FIELD_WINDOW |
        KSWORD_ARK_WIN32K_TIMER_FIELD_ID |
        KSWORD_ARK_WIN32K_TIMER_FIELD_ALTERNATE_THREAD |
        KSWORD_ARK_WIN32K_TIMER_FIELD_HASH_LINK;
    timerEntry.status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    timerEntry.processId = 321U;
    timerEntry.threadId = 654U;
    timerEntry.sessionId = 2U;
    timerEntry.flags = 0xA5U;
    timerEntry.intervalMs = 1000U;
    timerEntry.countdownMs = 500U;
    timerEntry.toleranceMs = 25U;
    timerEntry.lastStatus = -1073741823L;
    timerEntry.timerObject = 0xFFFFF80000001000ULL;
    timerEntry.callbackAddress = 0xFFFFF80000002000ULL;
    timerEntry.primaryThreadInfo = 0xFFFFF80000003000ULL;
    timerEntry.alternateThreadInfo = 0xFFFFF80000004000ULL;
    timerEntry.windowObject = 0xFFFFF80000005000ULL;
    timerEntry.timerId = 0x1234ULL;
    timerEntry.hashLink = 0xFFFFF80000006000ULL;
    std::wmemcpy(timerEntry.detail, L"timer\tpartial", 13U);
    timerEvidence.entries.push_back(timerEntry);
    const auto timerRows = Ksword::Features::Window::BuildWin32kTimerEvidenceRows(timerEvidence);
    Expect(timerRows.size() == 3U && timerRows[0].status == L"OK" && timerRows[1].status == L"Exact" &&
            timerRows[2].status == L"Partial" && timerRows[2].relatedProcessId == 321U,
        L"Win32k timer evidence projects snapshot layout and owner identity");
    Expect(timerRows[0].detail.find(L"gTimerHashTable=0xFFFFF80012340000") != std::wstring::npos &&
            timerRows[1].detail.find(L"source=ValidatedDisassembly") != std::wstring::npos &&
            timerRows[2].detail.find(L"timerObject=0xFFFFF80000001000") != std::wstring::npos &&
            timerRows[2].detail.find(L"lastStatus=0xC0000001") != std::wstring::npos &&
            timerRows[2].detail.find(L"timer partial") != std::wstring::npos,
        L"Win32k timer evidence preserves raw addresses status and sanitized detail");

    ksword::ark::Win32kTimersResult incompleteTimerEvidence{};
    incompleteTimerEvidence.io.ok = true;
    incompleteTimerEvidence.status = KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED;
    incompleteTimerEvidence.layout.source = KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS;
    KSWORD_ARK_WIN32K_TIMER_ENTRY incompleteTimerEntry{};
    incompleteTimerEntry.fieldFlags = KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT;
    incompleteTimerEntry.status = KSWORD_ARK_WIN32K_STATUS_PARTIAL;
    incompleteTimerEntry.processId = 999U;
    incompleteTimerEntry.threadId = 888U;
    incompleteTimerEntry.timerObject = 0x12345678ULL;
    incompleteTimerEvidence.entries.push_back(incompleteTimerEntry);
    const auto incompleteTimerRows = Ksword::Features::Window::BuildWin32kTimerEvidenceRows(incompleteTimerEvidence);
    Expect(incompleteTimerRows.size() == 3U && incompleteTimerRows[1].status == L"NearestPrevious" &&
            incompleteTimerRows[2].relatedProcessId == 0U &&
            incompleteTimerRows[2].detail.find(L"processId=<absent; raw=999>") != std::wstring::npos &&
            incompleteTimerRows[2].detail.find(L"callbackAddress=<absent; raw=0x0000000000000000>") != std::wstring::npos,
        L"Win32k timer evidence keeps missing driver fields explicit and non-navigable");

    ksword::ark::Win32kTimersResult unsupportedTimerEvidence{};
    unsupportedTimerEvidence.io.ok = false;
    unsupportedTimerEvidence.unsupported = true;
    unsupportedTimerEvidence.io.message = "legacy driver";
    const auto unsupportedTimerRows = Ksword::Features::Window::BuildWin32kTimerEvidenceRows(unsupportedTimerEvidence);
    Expect(unsupportedTimerRows.size() == 1U && unsupportedTimerRows.front().status == L"Unsupported" &&
            unsupportedTimerRows.front().detail.find(L"legacy driver") != std::wstring::npos,
        L"Win32k timer evidence degrades old drivers to one explicit summary row");
    Expect(Ksword::Features::Window::Win32kTimerEvidenceStatusText(KSWORD_ARK_WIN32K_STATUS_READ_FAILED) == L"ReadFailed" &&
            Ksword::Features::Window::Win32kTimerEvidenceStatusText(0xA5A5A5A5U).find(L"0xA5A5A5A5") != std::wstring::npos,
        L"Win32k timer evidence preserves known and unknown protocol status codes");

    MemorySnapshotHistory snapshots(2U);
    Expect(!snapshots.record(0U, 0x1000U, 4U, { 1U }, L"bad"), L"snapshot rejects missing pid");
    Expect(snapshots.record(42U, 0x1000U, 4U, { 1U, 2U, 3U, 4U }, L"first"), L"first snapshot recorded");
    Expect(snapshots.record(42U, 0x2000U, 2U, { 5U, 6U }, L"second"), L"second snapshot recorded");
    Expect(snapshots.canMovePrevious() && !snapshots.canMoveNext(), L"snapshot back navigation available");
    Expect(snapshots.movePrevious() && snapshots.current() && snapshots.current()->address == 0x1000U,
        L"snapshot previous selects first bytes");
    Expect(snapshots.record(42U, 0x3000U, 1U, { 7U }, L"branch"), L"snapshot branch recorded");
    Expect(snapshots.size() == 2U && !snapshots.canMoveNext() && snapshots.current() && snapshots.current()->address == 0x3000U,
        L"snapshot branch truncates forward history");

    MemoryReadSnapshot inspect{};
    inspect.sequence = 7U;
    inspect.processId = 42U;
    inspect.address = 0x1000U;
    inspect.requestedBytes = 13U;
    inspect.bytes = { 'T', 'e', 's', 't', 0U, 'W', 0U, 'i', 0U, 'd', 0U, 'e', 0U };
    inspect.statusText = L"partial read";
    const std::wstring hexAscii = Ksword::Features::Memory::RenderMemorySnapshotHexAscii(inspect);
    const std::wstring textRuns = Ksword::Features::Memory::ExtractMemorySnapshotText(inspect);
    Expect(hexAscii.find(L"0x0000000000001000") != std::wstring::npos && hexAscii.find(L"Test") != std::wstring::npos,
        L"memory hex ascii view includes address and printable bytes");
    Expect(textRuns.find(L"ASCII") != std::wstring::npos && textRuns.find(L"UTF-16LE") != std::wstring::npos,
        L"memory inspection extracts ascii and utf16 text runs");
    Expect(Ksword::Features::Memory::BuildMemorySnapshotTextReport(inspect).find(L"ReturnedBytes") != std::wstring::npos,
        L"memory inspection report includes snapshot metadata");

    MemoryReadSnapshot writableSnapshot{};
    writableSnapshot.sequence = 8U;
    writableSnapshot.processId = 88U;
    writableSnapshot.address = 0x2000U;
    writableSnapshot.requestedBytes = 10U;
    writableSnapshot.bytes = { 0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U };
    Ksword::Features::Memory::MemoryWritePlan writePlan{};
    std::wstring planError;
    const std::vector<std::uint8_t> editedBytes = { 0U, 9U, 8U, 3U, 4U, 7U, 8U, 9U, 8U, 9U };
    Expect(Ksword::Features::Memory::BuildMemoryWritePlan(writableSnapshot, editedBytes, 2U, writePlan, planError),
        L"memory write plan accepts same-length edited snapshot");
    Expect(writePlan.changedByteCount == 5U && writePlan.blocks.size() == 3U,
        L"memory write plan merges and splits contiguous differences");
    Expect(writePlan.blocks[0].address == 0x2001U && writePlan.blocks[0].desiredAfter == std::vector<std::uint8_t>{ 9U, 8U } &&
            writePlan.blocks[1].address == 0x2005U && writePlan.blocks[1].desiredAfter == std::vector<std::uint8_t>{ 7U, 8U } &&
            writePlan.blocks[2].address == 0x2007U && writePlan.blocks[2].desiredAfter == std::vector<std::uint8_t>{ 9U },
        L"memory write plan preserves exact chunk addresses and payloads");
    Expect(Ksword::Features::Memory::ValidateMemoryWritePlan(writePlan, planError),
        L"memory write plan validates generated blocks");

    Ksword::Features::Memory::MemoryWritePlan noChangePlan{};
    Expect(Ksword::Features::Memory::BuildMemoryWritePlan(writableSnapshot, writableSnapshot.bytes, 2U, noChangePlan, planError) &&
            noChangePlan.changedByteCount == 0U && noChangePlan.blocks.empty(),
        L"memory write plan does not create no-op writes");
    Expect(!Ksword::Features::Memory::BuildMemoryWritePlan(writableSnapshot, { 1U }, 2U, noChangePlan, planError),
        L"memory write plan rejects length drift");
    MemoryReadSnapshot overflowSnapshot = writableSnapshot;
    overflowSnapshot.address = (std::numeric_limits<std::uint64_t>::max)();
    Expect(!Ksword::Features::Memory::BuildMemoryWritePlan(overflowSnapshot, editedBytes, 2U, noChangePlan, planError),
        L"memory write plan rejects address wraparound");
    Ksword::Features::Memory::MemoryWritePlan malformedPlan = writePlan;
    malformedPlan.blocks[0].desiredAfter[0] = 0U;
    Expect(!Ksword::Features::Memory::ValidateMemoryWritePlan(malformedPlan, planError),
        L"memory write plan rejects desired-byte drift");

    const std::wstring redacted = Ksword::Ui::RedactEvidenceText(
        L"C:\\Users\\Felix\\Desktop\\sample.txt", Ksword::Ui::EvidenceRedaction::Privacy);
    Expect(redacted == L"C:\\Users\\<redacted>\\Desktop\\sample.txt", L"privacy path redaction");

    const Ksword::Ui::EvidenceDiff diff = Ksword::Ui::BuildEvidenceDiff(L"one\r\ntwo\r\n", L"two\r\nthree\r\n");
    Expect(diff.added.size() == 1U && diff.added.front() == L"three", L"evidence added line");
    Expect(diff.removed.size() == 1U && diff.removed.front() == L"one", L"evidence removed line");
    Expect(diff.unchanged.size() == 1U && diff.unchanged.front() == L"two", L"evidence unchanged line");

    Ksword::Ui::EvidenceSession session;
    Expect(session.record(L"process", L"tsv", L"pid\tname") == 1U, L"first evidence sequence");
    session.record(L"process", L"tsv", L"pid\tname\r\n4\tSystem");
    Expect(session.size() == 2U, L"evidence session size");
    Expect(session.exportJson(Ksword::Ui::EvidenceRedaction::Privacy).find(L"ksword-arklight-evidence-v1") !=
        std::wstring::npos, L"evidence JSON schema");
    Expect(Ksword::Ui::RenderEvidenceDiff(session.latestDiff()).find(L"+ 4\tSystem") != std::wstring::npos,
        L"latest evidence diff");
    Expect(session.erase(1U) && session.size() == 1U && !session.erase(1U),
        L"evidence session erases one immutable item by sequence");

    if (failures == 0) {
        std::wcout << L"KswordARKLightTests: PASS\n";
    }
    return failures == 0 ? 0 : 1;
}
