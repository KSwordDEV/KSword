#include "OwnedDataWatchSession.h"
#include "NativeStopCondition.h"
#include "CooperativeBreakpointGate.h"
#include "NativeExecutionEvidence.h"

#include "../Project/ProjectStorage.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"

#include <algorithm>
#include <limits>
#include <optional>
#include <utility>

namespace ks::cli::action_analyze::control {
namespace {

namespace storage = Ksword::ActionAnalyze::ProjectStorage;
namespace rules = Ksword::ActionAnalyze::Rules;
constexpr std::string_view kOptInExport = "KSwordActionAnalyzeDataWatchV1";

// 写入变化与执行进入尝试均属观测；字段目录按键排序，未采集字段保持未知。
constexpr auto kConditionPhase = rules::Phase::Observation;
constexpr auto kConditionFields = NativeStopConditionFields(kConditionPhase);

// 将本端拒绝原因附在已有快照上，避免把先前的继续回执归给本次请求。
NativeControlResult Reject(NativeControlResult result, const char* stage, DWORD error, LedgerResult reason)
{
    result.status = NativeControlStatus::Rejected;
    result.stage = stage;
    result.win32Error = error;
    result.ledgerResult = reason;
    result.release.reset();
    result.releaseRequestId.reset();
    return result;
}

// 启动入口只接普通本机 EXE 路径、单一 ASCII 导出和支持的硬件范围。
bool ValidStart(const std::wstring& path, const std::string& name, std::uint32_t width, bool execute)
{
    return path.size() > 7 && path.size() < MAX_PATH &&
        ((path[0] >= L'A' && path[0] <= L'Z') || (path[0] >= L'a' && path[0] <= L'z')) &&
        path[1] == L':' && path[2] == L'\\' && path.find_last_of(L'\\') > 2 && path.find(L'\0') == path.npos &&
        path.find_first_of(L"\"\r\n:/", 2) == path.npos &&
        CompareStringOrdinal(path.data() + path.size() - 4, 4, L".exe", 4, TRUE) == CSTR_EQUAL &&
        !name.empty() && name.size() <= 255 && name != kOptInExport &&
        std::all_of(name.begin(), name.end(), [](char c) { return c >= 0x21 && c <= 0x7e; }) &&
        (execute ? width == 0 : (width == 1 || width == 2 || width == 4 || width == 8));
}

// 在已有 PE 解析结果中查找唯一的精确导出。拒绝序号别名重复及转发导出。
std::uint32_t ExportRva(const ks::file::PeExportSummary& exports, const std::wstring& name)
{
    std::uint32_t rva = 0;
    for (const auto& symbol : exports.symbols) {
        const auto matches = std::count(symbol.names.begin(), symbol.names.end(), name);
        if (!matches) {
            continue;
        }
        if (matches != 1 || rva || symbol.isForwarder || !symbol.rva) {
            return 0;
        }
        rva = symbol.rva;
    }
    return rva;
}

// 找到完整包含范围的单一映像段。偏移和长度均使用 PE 的 RVA 坐标。
const ks::file::PeSectionSummary* ImageSection(const ks::file::PeAnalysisResult& image,
    std::uint32_t rva, std::uint32_t width)
{
    if (!rva || rva >= image.sizeOfImage || width > image.sizeOfImage - rva) {
        return nullptr;
    }
    const ks::file::PeSectionSummary* found = nullptr;
    for (const auto& section : image.sections) {
        if (rva >= section.virtualAddress && width <= section.virtualSize &&
            rva - section.virtualAddress <= section.virtualSize - width) {
            if (found) {
                return nullptr;
            }
            found = &section;
        }
    }
    return found;
}

// 调用者持有目录和文件固定句柄。复用 Qt-free 文件读取和导出解析，返回盘上准入失败原因。
std::optional<NativeControlResult> CheckImage(const std::wstring& path, const std::string& exportName,
    std::uint32_t width, bool indirect, bool execute)
{
    DWORD binaryType = 0;
    if (!GetBinaryTypeW(path.c_str(), &binaryType) || binaryType != SCS_64BIT_BINARY) {
        return Reject({}, "data-watch-requires-executable", ERROR_BAD_EXE_FORMAT, LedgerResult::InvalidEvidence);
    }
    const auto image = ks::file::AnalyzePeFileShared(path, false);
    if (!image || !image->success || !image->isPe64 || image->machine != IMAGE_FILE_MACHINE_AMD64 ||
        !image->exports.complete || !image->exports.namesComplete ||
        (image->subsystem != IMAGE_SUBSYSTEM_WINDOWS_GUI && image->subsystem != IMAGE_SUBSYSTEM_WINDOWS_CUI)) {
        return Reject({}, "data-watch-requires-amd64-image", ERROR_BAD_EXE_FORMAT, LedgerResult::InvalidEvidence);
    }

    // 标记只用作合作声明。执行selector可在只读或可写映像数据段，写模式仍要求可写。
    const auto marker = ExportRva(image->exports, storage::WideAscii(kOptInExport));
    if (!ImageSection(*image, marker, 1)) {
        return Reject({}, "data-watch-opt-in-export-required", ERROR_PROC_NOT_FOUND, LedgerResult::InvalidEvidence);
    }
    const auto site = ExportRva(image->exports, storage::WideAscii(exportName));
    const auto exportBytes = indirect ? 8u : width; // 指针导出本身总是一个完整的 AMD64 指针。
    const auto* section = ImageSection(*image, site, exportBytes);
    if (!section || site % exportBytes ||
        !(section->characteristics & (execute ? IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE : IMAGE_SCN_MEM_WRITE)) ||
        (section->characteristics & IMAGE_SCN_MEM_EXECUTE)) {
        return Reject({}, "data-watch-aligned-data-export-required", ERROR_INVALID_ADDRESS, LedgerResult::InvalidEvidence);
    }
    return std::nullopt;
}

// 按返回的进程对象查询架构，宿主和子进程均要求原生 AMD64。
bool IsNativeAmd64(HANDLE process)
{
    USHORT machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native = IMAGE_FILE_MACHINE_UNKNOWN;
    return IsWow64Process2(process, &machine, &native) && machine == IMAGE_FILE_MACHINE_UNKNOWN &&
        native == IMAGE_FILE_MACHINE_AMD64;
}

} // namespace

DataWatchConditionPreparation PrepareDataWatchCondition(std::wstring_view source)
{
    if (source.empty()) {
        return {}; // 空输入表示不设条件，保留本模式的每次真实命中。
    }
    // 先限制 UTF-16 长度，再检查真实 UTF-8 字节数；非法编码不替换字符。
    if (source.size() > rules::MaxPredicateExpressionBytes) {
        return {{}, "expression-byte-limit", std::nullopt};
    }
    const auto length = static_cast<int>(source.size()); // 已限制到表达式上限，可安全转换。
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, source.data(), length, nullptr, 0, nullptr, nullptr);
    if (!bytes) {
        return {{}, "expression-invalid-unicode", std::nullopt};
    }
    if (static_cast<std::size_t>(bytes) > rules::MaxPredicateExpressionBytes) {
        return {{}, "expression-byte-limit", std::nullopt};
    }
    std::string text(static_cast<std::size_t>(bytes), '\0'); // 编译器使用的完整 UTF-8 原文。
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, source.data(), length, text.data(), bytes, nullptr, nullptr) != bytes) {
        return {{}, "expression-invalid-unicode", std::nullopt};
    }
    auto prepared = rules::PreparePredicateExpression(text, kConditionPhase, kConditionFields); // 复用 CLI 的类型、位置和预算校验。
    if (prepared.error == rules::ExpressionError::None) {
        return {std::move(prepared.predicate), nullptr, std::nullopt};
    }
    // 已识别的字段/类型错误保留更具体的诊断，位置始终来自共享编译器。
    const char* diagnostic = rules::ExpressionErrorId(prepared.error).data();
    switch (prepared.preparationError) {
    case rules::PrepareError::UnknownField: diagnostic = "unknown-field"; break;
    case rules::PrepareError::FieldNotInPhase: diagnostic = "field-not-in-phase"; break;
    case rules::PrepareError::TypeMismatch: diagnostic = "type-mismatch"; break;
    case rules::PrepareError::UnsupportedOperator: diagnostic = "unsupported-operator"; break;
    default: break;
    }
    return {{}, diagnostic, prepared.location};
}

struct OwnedDataWatchSession::AbortedLaunch {
    storage::Handle process; // 创建时取得的自有子进程句柄。
    NativeControlResult failure; // 原始启动拒绝原因，退出确认后回读。
    bool terminationRequested = false; // Win32 是否已接受撤销这次启动。
    DWORD terminationError = ERROR_SUCCESS;
};

OwnedDataWatchSession::OwnedDataWatchSession() = default;
OwnedDataWatchSession::~OwnedDataWatchSession() = default;

NativeControlResult OwnedDataWatchSession::Start(const std::wstring& requestedPath, const std::string& exportName,
    std::uint32_t width, rules::PreparedPredicate condition, bool indirect, std::string_view sampleId)
{
    // 旧API保持写入语义，零宽度仍由公共准入拒绝。
    return StartBound(requestedPath, exportName, width, std::move(condition), indirect, sampleId, false);
}

NativeControlResult OwnedDataWatchSession::StartPrivateExecution(const std::wstring& path, const std::string& exportName,
    rules::PreparedPredicate condition, std::string_view sampleId)
{
    // 明确的执行入口使用8字节selector，但不向原生层申请任何数据写入范围。
    return StartBound(path, exportName, 0, std::move(condition), true, sampleId, true);
}

NativeControlResult OwnedDataWatchSession::AttachPrivateAddress(std::uint32_t pid, std::uint64_t creationFileTime,
    std::uint64_t address, std::uint32_t width, rules::PreparedPredicate condition, std::string_view sampleId,
    std::uint64_t privateRangeBytes)
{
    if (owner_ || aborted_ || closing_)
        return Reject(Query(), "data-watch-session-already-used", ERROR_BUSY, LedgerResult::InvalidTransition);
    if (!pid || !creationFileTime || !address ||
        (width != 0 && width != 1 && width != 2 && width != 4 && width != 8) || (privateRangeBytes && width) ||
        (!sampleId.empty() && !storage::IsUuid(sampleId)))
        return Reject({}, "data-watch-private-address-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);

    NativeBreakpointRequest request;
    if (!sampleId.empty()) identity_.sampleId = sampleId;
    if ((sampleId.empty() && !storage::NewId(identity_.sampleId)) || !storage::NewId(identity_.sessionId) ||
        !storage::NewId(identity_.epoch) || !storage::NewId(identity_.backendInstanceId) ||
        !storage::NewId(request.target.requestId))
        return Reject({}, "data-watch-allocate-identities", ERROR_GEN_FAILURE, LedgerResult::InvalidEvidence);
    request.target.pid = pid;
    request.target.processCreationTime = creationFileTime;
    request.target.explicitlyAuthorized = true;
    request.target.disposition = NativeTargetDisposition::ResumeAndDetach;
    request.privateAddress = address;
    request.privateRangeBytes = privateRangeBytes; // 非零使用原owner的NX范围机制，单地址仍保持DR0。
    request.writeWatchBytes = width;
    condition_ = std::move(condition);
    // 同一owner处理真实附加、已有线程和后续CREATE_THREAD，不建立另一条暂停链。
    owner_ = std::make_unique<NativeDebugOwner>(identity_);
    auto state = owner_->ArmBreakpoint(request);
    if (!state.pid) {
        state.pid = pid;
        state.processCreationTime = creationFileTime;
    }
    return ApplyCondition(std::move(state));
}

NativeControlResult OwnedDataWatchSession::StartBound(const std::wstring& requestedPath, const std::string& exportName,
    std::uint32_t width, rules::PreparedPredicate condition, bool indirect, std::string_view sampleId, bool execute)
{
    if (owner_ || aborted_ || closing_) {
        return Reject(Query(), "data-watch-session-already-used", ERROR_BUSY, LedgerResult::InvalidTransition);
    }
    if (!sampleId.empty() && !storage::IsUuid(sampleId)) {
        return Reject({}, "data-watch-invalid-sample", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    }
    // 文件选择器可能返回正斜线。转换分隔符后按同一普通 DOS 路径规则核对。
    auto selectedPath = requestedPath;
    std::replace(selectedPath.begin(), selectedPath.end(), L'/', L'\\');
    if (!ValidStart(selectedPath, exportName, width, execute) || (execute && !indirect)) {
        return Reject({}, "data-watch-explicit-start-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    }
    if (!IsNativeAmd64(GetCurrentProcess())) {
        return Reject({}, "data-watch-native-amd64-host-required", ERROR_NOT_SUPPORTED, LedgerResult::InvalidEvidence);
    }

    // 固定本机目录链及实际文件。读权限共享，写入、替换及重解析均不可通过此路径发生。
    const auto separator = selectedPath.find_last_of(L'\\');
    const auto name = std::wstring_view(selectedPath).substr(separator + 1);
    storage::Directory directory;
    auto pinned = storage::OpenRoot(selectedPath.substr(0, separator), false, false, directory);
    storage::Handle executable;
    if (pinned) {
        pinned = storage::OpenFile(directory, name, GENERIC_READ, FILE_SHARE_READ, OPEN_EXISTING, executable);
    }
    if (!pinned) {
        return Reject({}, "data-watch-pin-image", pinned.nativeError ? pinned.nativeError : ERROR_BAD_PATHNAME,
            LedgerResult::InvalidEvidence);
    }
    const std::wstring folder = directory.path.substr(4); // 去掉固定目录的扩展 DOS 前缀，供实时映像解析。
    const std::wstring path = folder + L"\\" + std::wstring(name);
    if (path.size() >= MAX_PATH) {
        return Reject({}, "data-watch-image-path-too-long", ERROR_FILENAME_EXCED_RANGE, LedgerResult::InvalidEvidence);
    }
    if (auto failure = CheckImage(path, exportName, width, indirect, execute)) {
        return std::move(*failure);
    }

    // 复用 CLI 的 ID 生成入口。由 NativeDebugOwner 检查子进程的真实身份并武装关注点。
    NativeBreakpointRequest breakpoint;
    if (!sampleId.empty()) identity_.sampleId = sampleId;
    if ((sampleId.empty() && !storage::NewId(identity_.sampleId)) || !storage::NewId(identity_.sessionId) ||
        !storage::NewId(identity_.epoch) || !storage::NewId(identity_.backendInstanceId) ||
        !storage::NewId(breakpoint.target.requestId)) {
        return Reject({}, "data-watch-allocate-identities", ERROR_GEN_FAILURE, LedgerResult::InvalidEvidence);
    }
    breakpoint.target.explicitlyAuthorized = true;
    breakpoint.target.disposition = NativeTargetDisposition::ResumeAndDetach;
    breakpoint.modulePath = path;
    breakpoint.exportName = exportName;
    breakpoint.writeWatchBytes = width;
    breakpoint.writeWatchPointerExport = indirect && !execute;
    breakpoint.executePointerExport = execute; // 原生解析器验证MEM_PRIVATE及EXECUTE/RX/RWX和绑定变化。
    auto owner = std::make_unique<NativeDebugOwner>(identity_);
    auto launch = std::make_unique<AbortedLaunch>();

    // 固定句柄覆盖解析和进程创建。先挂起创建，再用返回的句柄核对实际映像与创建时间。
    STARTUPINFOEXW startup{}; // 两种路径共用创建身份核对，间接模式只继承私有合作句柄。
    startup.StartupInfo.cb = sizeof(STARTUPINFOW);
    PROCESS_INFORMATION created{};
    auto command = L"\"" + path + L"\"";
    if (indirect) {
        launchGate_ = std::make_unique<CooperativeBreakpointGate>();
        if (const auto error = launchGate_->Prepare(startup, command)) {
            launchGate_.reset();
            return Reject({}, "data-watch-prepare-private-gate", error, LedgerResult::InvalidEvidence);
        }
    }
    const DWORD flags = DETACHED_PROCESS | CREATE_SUSPENDED | (indirect ? EXTENDED_STARTUPINFO_PRESENT : 0);
    if (!CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, indirect, flags,
            nullptr, nullptr, &startup.StartupInfo, &created)) {
        const auto error = GetLastError(); // 关闭启动句柄前保留创建调用的原始错误。
        launchGate_.reset();
        return Reject({}, "data-watch-create-process", error, LedgerResult::InvalidEvidence);
    }
    launch->process = storage::Handle(created.hProcess);
    const storage::Handle initialThread(created.hThread);
    // 失败时保留创建所得句柄。清理只针对这个仍未恢复执行的子进程。
    const auto abort = [&](const char* stage, DWORD error) {
        if (launchGate_) launchGate_->Close(); // 未交付调试所有者时，只撤销本次自有启动。
        launch->failure = Reject({}, stage, error, LedgerResult::IdentityMismatch);
        launch->failure.pid = created.dwProcessId;
        aborted_ = std::move(launch);
        return ObserveAbortedLaunch(true);
    };
    const auto child = launch->process.get();
    wchar_t observedPath[MAX_PATH]{};
    DWORD length = MAX_PATH;
    if (!QueryFullProcessImageNameW(child, 0, observedPath, &length)) {
        return abort("data-watch-query-child-image", GetLastError());
    }
    if (CompareStringOrdinal(observedPath, static_cast<int>(length), path.data(),
            static_cast<int>(path.size()), TRUE) != CSTR_EQUAL || GetProcessId(child) != created.dwProcessId ||
        !IsNativeAmd64(child)) {
        return abort("data-watch-child-identity-mismatch", ERROR_INVALID_DATA);
    }

    // 用创建句柄读取 FILETIME。稍后原生所有者会独立核对 PID、时间、架构、用户与父进程。
    FILETIME createdAt{}, exitedAt{}, kernel{}, user{};
    if (!GetProcessTimes(child, &createdAt, &exitedAt, &kernel, &user)) {
        return abort("data-watch-query-child-times", GetLastError());
    }
    breakpoint.target.pid = created.dwProcessId;
    breakpoint.target.processCreationTime = (static_cast<std::uint64_t>(createdAt.dwHighDateTime) << 32) |
        createdAt.dwLowDateTime;
    if (!breakpoint.target.processCreationTime) {
        return abort("data-watch-child-creation-time-missing", ERROR_INVALID_DATA);
    }
    if (ResumeThread(initialThread.get()) == static_cast<DWORD>(-1)) {
        return abort("data-watch-resume-child", GetLastError());
    }
    if (launchGate_) {
        if (const auto error = launchGate_->AwaitReady(child)) {
            return abort("data-watch-private-target-not-ready", error);
        }
    }
    condition_ = std::move(condition); // 此后只求值这份启动时冻结的条件。
    owner_ = std::move(owner);
    auto state = owner_->ArmBreakpoint(breakpoint);
    // 原生准入可在建立账目之前拒绝。此时启动结果仍带实际创建的 PID 和时间。
    if (!state.pid) {
        state.pid = breakpoint.target.pid;
        state.processCreationTime = breakpoint.target.processCreationTime;
    }
    return ApplyCondition(std::move(state));
}

// 输入已有实例和模块内位置，提交原owner的执行DR0绑定；不启动目标，不创建合作Gate。
NativeControlResult OwnedDataWatchSession::AttachImageExecution(std::uint32_t pid, std::uint64_t creationFileTime,
    const std::wstring& modulePath, std::optional<std::uint32_t> rva, const std::string& exportName,
    rules::PreparedPredicate condition, std::string_view sampleId)
{
    if (owner_ || aborted_ || closing_)
    {
        return Reject(Query(), "data-watch-session-already-used", ERROR_BUSY, LedgerResult::InvalidTransition);
    }
    if (!pid || !creationFileTime || modulePath.empty() || rva.has_value() == !exportName.empty() ||
        (rva && !*rva) || (!sampleId.empty() && !storage::IsUuid(sampleId)))
    {
        return Reject({}, "image-execution-instance-and-site-required", ERROR_INVALID_PARAMETER, LedgerResult::InvalidEvidence);
    }

    NativeBreakpointRequest request; // 仅新入口设置显式已有映像准入，原合作启动规则保持原默认。
    if (!sampleId.empty())
    {
        identity_.sampleId = sampleId;
    }
    if ((sampleId.empty() && !storage::NewId(identity_.sampleId)) || !storage::NewId(identity_.sessionId) ||
        !storage::NewId(identity_.epoch) || !storage::NewId(identity_.backendInstanceId) ||
        !storage::NewId(request.target.requestId))
    {
        return Reject({}, "data-watch-allocate-identities", ERROR_GEN_FAILURE, LedgerResult::InvalidEvidence);
    }
    request.target.pid = pid;
    request.target.processCreationTime = creationFileTime;
    request.target.explicitlyAuthorized = true;
    request.target.disposition = NativeTargetDisposition::ResumeAndDetach;
    request.explicitImageAttachment = true;
    request.modulePath = modulePath;
    std::replace(request.modulePath.begin(), request.modulePath.end(), L'/', L'\\');
    request.rva = rva;
    request.exportName = exportName;
    condition_ = std::move(condition);

    // NativeDebugOwner完成真实模块/线程/映像执行区核验，回执不由表单或磁盘符号假定成功。
    owner_ = std::make_unique<NativeDebugOwner>(identity_);
    auto state = owner_->ArmBreakpoint(request); // 所有后续Continue/Step/Close仍使用这个唯一owner。
    if (!state.pid)
    {
        state.pid = pid;
        state.processCreationTime = creationFileTime;
    }
    return ApplyCondition(std::move(state));
}

NativeControlResult OwnedDataWatchSession::ObserveAbortedLaunch(bool requestTermination)
{
    auto& launch = *aborted_;
    if (!launch.process) {
        return launch.failure;
    }
    // TerminateProcess 的成功只确认请求已接受。以同一进程句柄被触发为退出证据。
    if (requestTermination && !launch.terminationRequested) {
        launch.terminationRequested = TerminateProcess(launch.process.get(), ERROR_PROCESS_ABORTED) != FALSE;
        launch.terminationError = launch.terminationRequested ? ERROR_SUCCESS : GetLastError();
    }
    const auto wait = WaitForSingleObject(launch.process.get(), 0);
    if (wait == WAIT_OBJECT_0) {
        launch.process.reset();
        return launch.failure;
    }
    auto state = launch.failure;
    state.clean = false;
    if (wait == WAIT_FAILED || !launch.terminationRequested) {
        state.status = NativeControlStatus::RecoveryRequired;
        state.stage = "data-watch-abort-launch-failed";
        state.win32Error = wait == WAIT_FAILED ? GetLastError() : launch.terminationError;
    } else {
        state.status = NativeControlStatus::ClosePending;
        state.stage = "data-watch-abort-launch-pending";
    }
    return state;
}

// 从活写入快照借用事件责任，供 Continue 核对两份快照及其修订。
static const EventResponsibility* LiveWrite(const NativeControlResult& control)
{
    const auto& group = control.group;
    const auto& pending = control.pending;
    const auto& responsibility = control.responsibility;
    if (control.attached && group && !group->historical && group->origin &&
        group->origin->phase == StopPhase::DataWriteObserved && control.breakpointHit && control.breakpointHit->dataChange &&
        pending && pending->ledgerOwned && !pending->continuationIndeterminate && responsibility &&
        (responsibility->state == EventState::Held || responsibility->state == EventState::Retryable) &&
        responsibility->event == pending->event && responsibility->groupId == group->groupId) {
        return &*responsibility;
    }
    return nullptr;
}

// 输入已返回的原生快照，识别私有执行进入尝试；输出责任指针，不伪造DataWrite变化。
static const EventResponsibility* LiveExecution(const NativeControlResult& control)
{
    const auto& binding = control.breakpoint; // 同owner当前执行绑定，不接受历史或写入绑定。
    const auto& hit = control.breakpointHit; // 执行事件没有字节变化字段。
    if (control.group && control.group->origin &&
        control.group->origin->phase == StopPhase::ExecutionEnterAttempt && binding &&
        !binding->writeWatchBytes && binding->address &&
        binding->state == NativeBreakpointState::Held && hit && !hit->dataChange &&
        NativeExecutionAddressInBinding(*binding, hit->address) && control.responsibility) {
        return &*control.responsibility;
    }
    return nullptr;
}

bool IsDataWatchStepStop(const NativeControlResult& state) noexcept
{
    // 原生步进停点必须由同一回执明确引用，不能把旧 Completed 回执套在后续事件上。
    return state.step && state.pending && state.group && state.step->observedEvent &&
        *state.step->observedEvent == state.pending->event && state.step->stopGroupId &&
        *state.step->stopGroupId == state.group->groupId && !state.breakpointHit;
}

const EventResponsibility* DataWatchHeldStop(const NativeControlResult& state) noexcept
{
    const auto& responsibility = state.responsibility; // 与原生待继续事件共同核对的责任记录。
    if (!state.attached || !state.group || state.group->historical ||
        !state.pending || !state.pending->ledgerOwned || state.pending->continuationIndeterminate || !responsibility ||
        (responsibility->state != EventState::Held && responsibility->state != EventState::Retryable) ||
        responsibility->event != state.pending->event || responsibility->groupId != state.group->groupId) {
        return nullptr;
    }
    const bool manual = state.stopReason == NativeStopReason::ManualPause && state.armedPause &&
        state.armedPause->state == NativeArmedPauseState::Held && state.armedPause->event &&
        *state.armedPause->event == state.pending->event && state.armedPause->groupId == state.group->groupId;
    return LiveWrite(state) || LiveExecution(state) || IsDataWatchStepStop(state) || manual ? &*responsibility : nullptr;
}

// 仅使用原owner发布状态，暂停请求不能抢占当前停点、步进或未决恢复。
bool CanPauseDataWatchSession(const NativeControlResult& state) noexcept
{
    return state.attached && !state.clean && state.pid && state.processCreationTime && state.breakpoint &&
        state.breakpoint->state == NativeBreakpointState::Armed && !state.pending &&
        state.status != NativeControlStatus::Held && state.status != NativeControlStatus::Rejected &&
        state.status != NativeControlStatus::RecoveryRequired && state.status != NativeControlStatus::ClosePending &&
        (!state.step || state.step->state != NativeStepState::Running) &&
        (!state.armedPause || state.armedPause->state != NativeArmedPauseState::Pending);
}

bool CanFollowDataWatchPrivateExecution(const NativeControlResult& state) noexcept
{
    const auto& binding = state.breakpoint; // 只判断已公布的冻结候选，不在UI线程查询目标。
    return state.status == NativeControlStatus::Held && DataWatchHeldStop(state) && state.group &&
        state.group->state == GroupState::HeldComplete && state.group->origin &&
        state.group->origin->phase == StopPhase::DataWriteObserved && state.breakpointHit &&
        state.breakpointHit->dataChange && binding && binding->writeWatchBytes &&
        binding->privateExecutionFollowAvailable && !binding->executePointerExport &&
        (binding->pointerExportAddress || binding->explicitPrivateAddress) && binding->address == binding->regionBase;
}

// 输入同owner的冻结命中快照和谓词，输出三值判断；执行事件的数据变化字段保持NotCollected。
static rules::Evaluation EvaluateWrite(const rules::PreparedPredicate& condition, const NativeControlResult& state)
{
    const auto samples = NativeStopConditionSamples(state);
    return rules::EvaluatePredicate(condition, kConditionPhase, samples);
}

NativeControlResult OwnedDataWatchSession::ApplyCondition(NativeControlResult state)
{
    if (!condition_.valid() || closing_) {
        return state;
    }
    auto& last = conditionReport_.last; // 继续失败后保持恢复状态，不重复提交或暴露手动继续。
    if (last && last->failureStage && !state.clean) {
        state = Reject(std::move(state), last->failureStage, last->releaseError, LedgerResult::InvalidTransition);
        state.status = NativeControlStatus::RecoveryRequired;
        return state;
    }
    if (state.status != NativeControlStatus::Held) {
        return state;
    }
    // 显式步进产生的新停点需要用户处置，不按数据变化条件自动放行或重复计数。
    if (IsDataWatchStepStop(state) || state.stopReason == NativeStopReason::ManualPause) {
        return state;
    }
    const auto* stop = DataWatchHeldStop(state); // 只对真实写入或私有执行进入事件求值，普通step已跳过。
    if (!stop) {
        state = Reject(std::move(state), "data-watch-condition-stop-unverified", ERROR_INVALID_DATA, LedgerResult::InvalidEvidence);
        state.status = NativeControlStatus::RecoveryRequired;
        return state;
    }
    if (last && last->event == stop->event) {
        return state; // 同一事件的回读不重复求值，也不重复计数。
    }

    const auto evaluation = EvaluateWrite(condition_, state); // 保留真假未知及求值故障。
    last = DataWatchConditionDecision{stop->event, stop->groupId, state.group->stateRevision, evaluation, std::nullopt};
    if (evaluation.truth == rules::Truth::True) {
        ++conditionReport_.trueCount;
        return state;
    }
    if (evaluation.truth == rules::Truth::False) {
        ++conditionReport_.falseCount;
    } else {
        ++conditionReport_.unknownCount;
    }

    // 提交前记录待核实状态。即使原生调用抛出异常，下次回读也不会重发同一事件。
    last->failureStage = "data-watch-condition-release-unconfirmed";
    last->releaseError = ERROR_INVALID_DATA;
    auto released = ReleaseWrite(state, *stop); // 本次自动继续的原生结果。
    // 拒绝或过期令牌可能带另一笔历史回执，只接受账本为本次请求登记的结果。
    if (released.ledgerResult == LedgerResult::Applied && released.release && released.release->receipt) {
        last->release = released.release->receipt->result;
    }
    if (last->release == ReleaseResult::Continued && released.status != NativeControlStatus::RecoveryRequired) {
        last->failureStage = nullptr;
        last->releaseError = ERROR_SUCCESS;
        return released;
    }
    if (released.win32Error) {
        last->failureStage = released.stage;
        last->releaseError = released.win32Error;
    }
    released.stage = last->failureStage;
    released.win32Error = last->releaseError;
    released.status = NativeControlStatus::RecoveryRequired;
    return released;
}

NativeControlResult OwnedDataWatchSession::Query()
{
    if (aborted_) {
        return ObserveAbortedLaunch(false);
    }
    if (!owner_) return {};
    auto state = owner_->Query(); // 原生武装状态来自原所有者，不由合作 Ready 自述代替。
    if (launchGate_) {
        if (const auto error = launchGate_->Observe(state)) {
            (void)owner_->Close(); // 业务许可写失败后清退原绑定，保留查询恢复入口。
            return Reject(std::move(state), "data-watch-private-gate-release", error, LedgerResult::InvalidTransition);
        }
    }
    return ApplyCondition(std::move(state));
}

NativeControlResult OwnedDataWatchSession::Continue(const NativeControlResult& displayedStop)
{
    auto current = Query();
    if (closing_) {
        return Reject(std::move(current), "data-watch-session-closing", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    }
    if (!MatchesDisplayedStop(displayedStop, current)) {
        if (current.status == NativeControlStatus::RecoveryRequired) {
            return current; // 假/未知未确认释放时保留原恢复诊断和 Close 入口。
        }
        return Reject(std::move(current), "data-watch-stale-stop", ERROR_INVALID_DATA, LedgerResult::StaleRevision);
    }
    const auto* live = DataWatchHeldStop(current); // MatchesDisplayedStop 已核对非空且属于同一事件。
    return ReleaseWrite(current, *live);
}

// 输入为当前会话；输出原生owner值快照，调用方不得借此绕过条件授予手动继续资格。
NativeControlResult OwnedDataWatchSession::QueryWithoutCondition()
{
    auto state = owner_ ? owner_->Query() : NativeControlResult{}; // 只回读原owner，不求值、不放行合作Gate。
    const auto& decision = conditionReport_.last; // 已发生的自动继续失败属于原会话，不能被原生Held快照抹掉。
    if (!state.clean && decision && decision->failureStage)
    {
        state.status = NativeControlStatus::RecoveryRequired;
        state.stage = decision->failureStage;
        state.win32Error = decision->releaseError;
    }
    return state;
}

// 点击时冻结原实例和绑定票据；工作线程只在同一个owner中请求下断，不创建暂停会话。
NativeControlResult OwnedDataWatchSession::Pause(const NativeControlResult& displayedSession)
{
    if (!owner_ || closing_)
    {
        return Reject({}, "data-watch-pause-owner-unavailable", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    }
    auto current = QueryWithoutCondition(); // 不触发条件自动Continue，也不打开合作Gate。
    if (current.status == NativeControlStatus::RecoveryRequired)
    {
        return current; // 条件恢复责任仍归原会话，只保留原Close恢复入口。
    }
    if (!CanPauseDataWatchSession(displayedSession) || !CanPauseDataWatchSession(current) ||
        displayedSession.pid != current.pid || displayedSession.processCreationTime != current.processCreationTime ||
        displayedSession.processInstanceId != current.processInstanceId ||
        displayedSession.breakpoint->requestId != current.breakpoint->requestId)
    {
        return Reject(std::move(current), "data-watch-pause-stale-session", ERROR_INVALID_DATA, LedgerResult::StaleRevision);
    }
    if (pauseSequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return Reject(std::move(current), "data-watch-pause-id-exhausted", ERROR_ARITHMETIC_OVERFLOW, LedgerResult::Capacity);
    }
    NativePauseRequest request; // 主动暂停不占继续、单步和新增范围的序号。
    request.requestId = "pause/" + std::to_string(++pauseSequence_);
    request.pid = current.pid;
    request.processCreationTime = current.processCreationTime;
    request.explicitlyAuthorized = true;
    request.disposition = NativeTargetDisposition::ResumeAndDetach;
    return owner_->PauseArmed(identity_, request);
}

NativeControlResult OwnedDataWatchSession::FollowPrivateExecution(const NativeControlResult& displayedStop)
{
    if (!owner_ || closing_)
    {
        return Reject({}, "data-watch-follow-owner-unavailable", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    }
    auto current = QueryWithoutCondition(); // 只回读原owner，不让该转换动作触发条件自动Continue。
    if (current.status == NativeControlStatus::RecoveryRequired)
    {
        return current;
    }
    if (!MatchesDisplayedStop(displayedStop, current) || !CanFollowDataWatchPrivateExecution(current))
    {
        return Reject(std::move(current), "data-watch-follow-stale-stop", ERROR_INVALID_DATA, LedgerResult::StaleRevision);
    }
    if (followSequence_ == std::numeric_limits<std::uint64_t>::max())
    {
        return Reject(std::move(current), "data-watch-follow-id-exhausted", ERROR_ARITHMETIC_OVERFLOW, LedgerResult::Capacity);
    }
    const auto& stop = *DataWatchHeldStop(current); // 本事件仍是写入，原真条件及停止资格保持不变。
    NativeExecutionFollowRequest request; // 独立票据只转换类型，不送入释放账本。
    request.stop = {identity_, stop.groupId, stop.stopId, stop.event,
        "follow/" + std::to_string(++followSequence_), current.group->stateRevision};
    request.address = current.breakpoint->address;
    return owner_->FollowPrivateExecution(request); // 后续真实执行命中由原Query应用本轮冻结条件。
}

bool OwnedDataWatchSession::MatchesDisplayedStop(const NativeControlResult& displayed, const NativeControlResult& current) const
{
    if (conditionReport_.last && conditionReport_.last->failureStage)
    {
        return false; // 手动暂停、步进或归档不能绕过同一会话尚未结算的自动继续失败。
    }
    const auto* selected = DataWatchHeldStop(displayed); // UI 点击时冻结的原生事件。
    const auto* live = DataWatchHeldStop(current); // 所有者刚回读的同一停止责任。
    if (!selected || !live || selected->event != live->event || selected->groupId != live->groupId ||
        selected->stopId != live->stopId || displayed.group->stateRevision != current.group->stateRevision) {
        return false;
    }
    const auto& decision = conditionReport_.last; // 写入和执行进入均须匹配本事件的真条件，普通step独立。
    return IsDataWatchStepStop(current) || current.stopReason == NativeStopReason::ManualPause || !condition_.valid() ||
        (decision && decision->event == live->event && decision->evaluation.truth == rules::Truth::True);
}

// 在原串行worker核验点击时停止身份，只有当前NX会话可以追加；失败保留原native恢复账。
NativeControlResult OwnedDataWatchSession::AddPrivateExecutionRange(const NativeControlResult& displayedStop,
    std::uint64_t address, std::uint64_t bytes)
{
    if (!owner_ || closing_)
    {
        return Reject({}, "data-watch-range-owner-unavailable", ERROR_INVALID_STATE, LedgerResult::InvalidTransition);
    }
    auto current = QueryWithoutCondition(); // 追加不是Query条件操作，不因条件为假或未知而释放原停点。
    if (current.status == NativeControlStatus::RecoveryRequired)
    {
        return current;
    }
    if (!MatchesDisplayedStop(displayedStop, current) || !current.breakpoint ||
        !current.breakpoint->rangeBytes || current.breakpoint->writeWatchBytes)
    {
        return Reject(std::move(current), "data-watch-range-stale-stop", ERROR_INVALID_DATA, LedgerResult::StaleRevision);
    }
    if (rangeSequence_ == (std::numeric_limits<std::uint64_t>::max)())
    {
        return Reject(std::move(current), "data-watch-range-id-exhausted", ERROR_ARITHMETIC_OVERFLOW, LedgerResult::Capacity);
    }
    const auto& stop = *DataWatchHeldStop(current); // 原事件身份不被新增范围替换。
    NativeExecutionRangeRequest request; // 控制范围事务独立于继续和步进票据。
    request.stop = {identity_, stop.groupId, stop.stopId, stop.event,
        "range/" + std::to_string(++rangeSequence_), current.group->stateRevision};
    request.address = address;
    request.bytes = bytes;
    return owner_->AddPrivateExecutionRange(request); // 页保护核验、回滚及责任保留只由原owner完成。
}

NativeControlResult OwnedDataWatchSession::Step(const NativeControlResult& displayedStop, NativeStepMode mode)
{
    auto current = Query(); // 与 Continue 相同，先处理条件，再核对显示快照是否仍有效。
    if (closing_ || !MatchesDisplayedStop(displayedStop, current) || current.stopReason == NativeStopReason::ManualPause) {
        return Reject(std::move(current), "data-watch-step-stale-stop", ERROR_INVALID_STATE, LedgerResult::StaleRevision);
    }
    const auto& stop = *DataWatchHeldStop(current); // 同一停止事件的精确来源线程。
    const auto thread = std::find_if(current.frozenThreads.begin(), current.frozenThreads.end(), [&](const auto& member) {
        return member.identity == stop.actualEventThread && member.tid == current.pending->tid && member.creationTime;
    });
    if (thread == current.frozenThreads.end()) {
        return Reject(std::move(current), "data-watch-step-thread-unverified", ERROR_INVALID_DATA, LedgerResult::IdentityMismatch);
    }
    if (releaseSequence_ == std::numeric_limits<std::uint64_t>::max()) {
        return Reject(std::move(current), "data-watch-continue-id-exhausted", ERROR_ARITHMETIC_OVERFLOW, LedgerResult::Capacity);
    }
    // 原生层再次校验释放序列及线程对象；请求不借用页面当前选区或裸 TID。
    const auto requestId = std::string(kSequencedReleasePrefix) + std::to_string(++releaseSequence_);
    NativeStepRequest request;
    request.release = {identity_, stop.groupId, stop.stopId, stop.event, requestId, current.group->stateRevision};
    request.thread = thread->identity;
    request.tid = thread->tid;
    request.threadCreationTime = thread->creationTime;
    request.mode = mode;
    return ApplyCondition(owner_->Step(request));
}

NativeControlResult OwnedDataWatchSession::CancelStep(const NativeControlResult& displayedStep)
{
    auto current = Query(); // 取消只指向用户看到的请求，完成后不取消下一笔请求。
    if (closing_ || !owner_ || !displayedStep.step || !current.step ||
        displayedStep.step->request != current.step->request ||
        displayedStep.step->request.release.owner != identity_) {
        return Reject(std::move(current), "data-watch-step-request-stale", ERROR_INVALID_DATA, LedgerResult::StaleRevision);
    }
    return ApplyCondition(owner_->CancelStep(current.step->request.release.requestId));
}

NativeControlResult OwnedDataWatchSession::ReleaseWrite(const NativeControlResult& state, const EventResponsibility& stop)
{
    if (releaseSequence_ == std::numeric_limits<std::uint64_t>::max()) {
        return Reject(state, "data-watch-continue-id-exhausted", ERROR_ARITHMETIC_OVERFLOW, LedgerResult::Capacity);
    }
    // 使用求值或点击时已核验的令牌。原生账本再次校验身份和修订后才允许继续。
    const auto requestId = std::string(kSequencedReleasePrefix) + std::to_string(++releaseSequence_);
    return owner_->Continue({identity_, stop.groupId, stop.stopId, stop.event, requestId, state.group->stateRevision});
}

NativeControlResult OwnedDataWatchSession::Close()
{
    closing_ = true;
    if (launchGate_) launchGate_->Close(); // EOF 取消未放行业务，不产生任何额外 Resume。
    if (aborted_) {
        return ObserveAbortedLaunch(true);
    }
    return owner_ ? owner_->Close() : NativeControlResult{};
}

} // namespace ks::cli::action_analyze::control
