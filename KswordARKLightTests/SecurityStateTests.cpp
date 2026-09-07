// S 模块（平台安全状态与原因解释）的离线自动测试。
//
// 覆盖编号与**各自的边界**。这一段按条写清楚，是因为只写一串"S-01…S-08"会读成
// 比这些断言实际支撑的更强的声明：
//   * S-01 完整覆盖：四维分离、五种失败语义、未知枚举保留，都在本文件里。
//   * S-02 只覆盖**新鲜度模型**（bootId / machineId 判定与历史值分列）。规范里
//     "存下状态、重开旧会话与当前并排看"那一半需要序列化，而 SecurityState.{h,cpp}
//     里没有任何序列化，所以不在本文件、也不在本模块范围内。
//   * S-03 只覆盖 SecureBoot / TPM 在不在 / TPM 就不就绪 / 测量日志四项。
//     "其它可获得的启动相关状态"里的 BitLocker、DMA 重映射没有解释函数；
//     KernelDmaProtection 只是能力枚举里的一个槽位，没有对应的 Interpret*。
//   * S-04 覆盖 WDAC 配置口径/有效口径分列、内核态与用户态分列、签名与策略分列。
//   * S-05 覆盖**结构化**的冲突输出（全部来源并排 + resolvedValue 恒 Unknown +
//     历史冲突单列）。规范里"解释可能的取值范围"那一句要的是文本输出，本层不产文本，
//     只给结构化事实，UI 侧据此渲染。
//   * S-06 覆盖约束陈述化词表闸与"不可用不启动"的判定。要说清楚的是：这道闸只在
//     本层生效，**还没有接到生产路径上**（除本测试工程外，仓库里没有别的地方引用
//     SecurityState）。MiscDock/DisableDse 那条"关掉内存完整性再重启"的文案不经过
//     本层，因此"仓库范围内不默认建议禁用保护"这条通过条件本文件管不了。
//   * S-07 覆盖**逐字段的权限降级模型**（可读性矩阵、Administrator/System/驱动
//     三档分离、能力级权限标注）。真机上"用普通账户跑一遍"属于目标环境层。
//   * S-08 只覆盖"支持声明"这个状态模型本身，真实两套环境的实测记录属于目标环境层。
//
// 断言标签一律用 ASCII：TestSupport.h 的 Suite 直接往 std::wcout/wcerr 写，默认
// "C" locale 下非 ASCII 宽字符会让流进入失败态，把后面的计数一起吞掉 —— 现有
// CrossViewTests 等套件也是同样的写法。
//
// 断言原则（Q-01/Q-02）：
//   * 期望值一律是手写字面量（"EnabledNotRunning"、TriState::No、计数 2 ……），
//     绝不把被测函数的输出再喂回去当参考；
//   * 生产的解释函数（InterpretVbsStatus / VbsStatusToDimensions ……）只在**自己的
//     单元用例**里被直接断言，不用来生成管线用例的输入 —— 否则一处坏掉两处一起坏，
//     断言会变成"参考对参考"；
//   * 管线用例（EvaluateSecurityState）的输入 TriState 全是手写的，不由解释函数产出；
//   * 每条负面判据都有独立用例：查询失败、无权限、未知枚举、跨启动周期、无支撑断言、
//     整轮缺席的能力、三源冲突、缺测量日志、有效策略查不到。

#include "TestSupport.h"

#include "../shared/evidence/SecurityState.h"

#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

constexpr const char* kMachine = "machine-S";
constexpr const char* kBootCurrent = "boot-S-current";
constexpr const char* kBootPrevious = "boot-S-previous";

CaptureWindow CurrentWindow() {
    CaptureWindow window;
    window.bootId = kBootCurrent;
    window.machineId = kMachine;
    window.mode = CaptureMode::Snapshot;
    return window;
}

RawObservation RawNumber(const char* text, std::uint64_t numeric) {
    RawObservation raw;
    raw.text = text;
    raw.numeric = OptionalU64::of(numeric);
    return raw;
}

RawObservation RawText(const char* text) {
    RawObservation raw;
    raw.text = text;
    return raw;
}

SecurityField MakeField(const char* fieldId, const char* sourceGroup, const char* bootId) {
    SecurityField field;
    field.fieldId = fieldId;
    field.queryEntry = std::string("query:") + fieldId;
    field.source.collectorId = std::string("collector.") + sourceGroup;
    field.source.sourceGroup = sourceGroup;
    field.source.collectorVersion = 1U;
    field.source.origin = SourceOrigin::LiveUserMode;
    field.window.bootId = bootId;
    field.window.machineId = kMachine;
    field.outcome = CollectionOutcome::success();
    field.access = AccessRequirement::None;
    return field;
}

CapabilityClaim MakeClaim(SecurityCapabilityId capability,
                          SecurityDimension dimension,
                          TriState value,
                          const char* fieldId) {
    CapabilityClaim claim;
    claim.capability = capability;
    claim.dimension = dimension;
    claim.value = value;
    claim.fieldId = fieldId;
    return claim;
}

bool Contains(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

bool HasKey(const std::vector<std::string>& keys, const char* key) {
    for (const std::string& entry : keys) {
        if (entry == key) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// S-01：三态与枚举解释
// ---------------------------------------------------------------------------
void TestTriStateAndEnums(KswordTests::Suite& s) {
    s.expect(std::string(TriStateName(TriState::Unknown)) == "Unknown",
             L"S-01 TriState Unknown has a name");
    s.expect(std::string(TriStateName(TriState::No)) == "No", L"S-01 TriState No has a name");
    s.expect(std::string(TriStateName(TriState::Yes)) == "Yes", L"S-01 TriState Yes has a name");
    s.expect(TriStateIsDefinite(TriState::Yes) && TriStateIsDefinite(TriState::No),
             L"S-01 Yes and No are definite values");
    s.expect(!TriStateIsDefinite(TriState::Unknown), L"S-01 Unknown is not a definite value");

    // 默认构造必须是 Unknown —— 忘记赋值不能变成"关闭"。
    const CapabilityState defaultState;
    s.expect(defaultState.hardwareSupport.value == TriState::Unknown &&
                 defaultState.configured.value == TriState::Unknown &&
                 defaultState.running.value == TriState::Unknown,
             L"S-01 a default-constructed capability has all three dimensions Unknown");
    s.expect(defaultState.queryOutcome.status == CollectionStatus::NotCollected,
             L"S-01 a default queryOutcome is NotCollected, not success");

    // --- Win32_DeviceGuard 服务编码（已知值） ---
    const DeviceGuardServiceValue none = InterpretDeviceGuardService(RawNumber("0", 0U));
    s.expect(none.service == DeviceGuardService::None && none.interpretation.recognized,
             L"S-01 DeviceGuard code 0 is None");
    const DeviceGuardServiceValue cg = InterpretDeviceGuardService(RawNumber("1", 1U));
    s.expect(cg.service == DeviceGuardService::CredentialGuard &&
                 cg.interpretation.normalizedName == "CredentialGuard",
             L"S-01 DeviceGuard code 1 is CredentialGuard");
    const DeviceGuardServiceValue hvci = InterpretDeviceGuardService(RawNumber("2", 2U));
    s.expect(hvci.service == DeviceGuardService::HypervisorEnforcedCodeIntegrity &&
                 hvci.interpretation.normalizedName == "HypervisorEnforcedCodeIntegrity",
             L"S-01 DeviceGuard code 2 is HVCI");
    const DeviceGuardServiceValue sbcg = InterpretDeviceGuardService(RawNumber("3", 3U));
    s.expect(sbcg.service == DeviceGuardService::SystemGuardSecureLaunch &&
                 sbcg.interpretation.normalizedName == "SystemGuardSecureLaunch",
             L"S-01 DeviceGuard code 3 is SystemGuardSecureLaunch");
    const DeviceGuardServiceValue smm = InterpretDeviceGuardService(RawNumber("4", 4U));
    s.expect(smm.service == DeviceGuardService::SmmFirmwareMeasurement &&
                 smm.interpretation.normalizedName == "SmmFirmwareMeasurement",
             L"S-01 DeviceGuard code 4 is SmmFirmwareMeasurement");

    // --- 未知枚举值：原值保留，解释留空，绝不猜 ---
    const DeviceGuardServiceValue future = InterpretDeviceGuardService(RawNumber("9", 9U));
    s.expect(future.service == DeviceGuardService::Unknown,
             L"S-01 an unknown service code does not collapse into a known one");
    s.expect(!future.interpretation.recognized, L"S-01 an unknown service code is flagged unrecognized");
    s.expect(future.interpretation.normalizedName.empty(),
             L"S-01 an unrecognized code gets no normalized name");
    s.expect(future.interpretation.rawCode == OptionalU64::of(9U),
             L"S-01 an unknown service code keeps its raw numeric value");
    s.expect(future.interpretation.rawText == "9", L"S-01 an unknown service code keeps its raw text");

    const DeviceGuardServiceValue textual = InterpretDeviceGuardService(RawText("HypervisorEnforced"));
    s.expect(!textual.interpretation.recognized, L"S-01 a non numeric source is not guessed at");
    s.expect(!textual.interpretation.rawCode.present,
             L"S-01 a non numeric source leaves rawCode unset instead of 0");
    s.expect(textual.interpretation.rawText == "HypervisorEnforced",
             L"S-01 a non numeric source keeps its raw text");

    // --- VBS 状态码 ---
    const VbsStatusValue off = InterpretVbsStatus(RawNumber("0", 0U));
    s.expect(off.status == VbsStatus::Disabled && off.interpretation.normalizedName == "Disabled",
             L"S-01 VBS code 0 is Disabled");
    const VbsStatusValue configuredOnly = InterpretVbsStatus(RawNumber("1", 1U));
    s.expect(configuredOnly.status == VbsStatus::EnabledNotRunning &&
                 configuredOnly.interpretation.normalizedName == "EnabledNotRunning",
             L"S-01 VBS code 1 is EnabledNotRunning");
    const VbsStatusValue runningNow = InterpretVbsStatus(RawNumber("2", 2U));
    s.expect(runningNow.status == VbsStatus::EnabledAndRunning &&
                 runningNow.interpretation.normalizedName == "EnabledAndRunning",
             L"S-01 VBS code 2 is EnabledAndRunning");
    const VbsStatusValue vbsFuture = InterpretVbsStatus(RawNumber("7", 7U));
    s.expect(vbsFuture.status == VbsStatus::Unknown && !vbsFuture.interpretation.recognized &&
                 vbsFuture.interpretation.rawCode == OptionalU64::of(7U),
             L"S-01 an unknown VBS status code keeps its value and is not interpreted");

    // --- Configured 与 Running 不可混用 ---
    TriState configured = TriState::Yes;
    TriState running = TriState::Yes;
    VbsStatusToDimensions(VbsStatus::Disabled, configured, running);
    s.expect(configured == TriState::No && running == TriState::No,
             L"S-01 Disabled maps to configured=No and running=No");
    VbsStatusToDimensions(VbsStatus::EnabledNotRunning, configured, running);
    s.expect(configured == TriState::Yes, L"S-01 EnabledNotRunning maps to configured=Yes");
    s.expect(running == TriState::No,
             L"S-01 EnabledNotRunning maps to running=No so Configured is never reused as Running");
    VbsStatusToDimensions(VbsStatus::EnabledAndRunning, configured, running);
    s.expect(configured == TriState::Yes && running == TriState::Yes,
             L"S-01 EnabledAndRunning maps to configured=Yes and running=Yes");
    configured = TriState::Yes;
    running = TriState::Yes;
    VbsStatusToDimensions(VbsStatus::Unknown, configured, running);
    s.expect(configured == TriState::Unknown && running == TriState::Unknown,
             L"S-01 an unknown status code resets both dimensions to Unknown, not to off");

    // --- 安全属性编码。0..8 逐个钉死：这张表挪一位，四个已文档化的取值会静默错位。 ---
    s.expect(InterpretSecurityProperty(RawNumber("0", 0U)).property == SecurityProperty::None,
             L"S-01 security property 0 is None");
    s.expect(InterpretSecurityProperty(RawNumber("1", 1U)).property ==
                 SecurityProperty::BaseVirtualizationSupport,
             L"S-01 security property 1 is BaseVirtualizationSupport");
    s.expect(InterpretSecurityProperty(RawNumber("2", 2U)).property == SecurityProperty::SecureBoot,
             L"S-01 security property 2 is SecureBoot");
    s.expect(InterpretSecurityProperty(RawNumber("3", 3U)).property == SecurityProperty::DmaProtection,
             L"S-01 security property 3 is DmaProtection");
    s.expect(InterpretSecurityProperty(RawNumber("4", 4U)).property ==
                 SecurityProperty::SecureMemoryOverwrite,
             L"S-01 security property 4 is SecureMemoryOverwrite");
    s.expect(InterpretSecurityProperty(RawNumber("5", 5U)).property == SecurityProperty::NxProtections,
             L"S-01 security property 5 is NxProtections");
    s.expect(InterpretSecurityProperty(RawNumber("6", 6U)).property ==
                 SecurityProperty::SmmMitigations,
             L"S-01 security property 6 is SmmMitigations");
    s.expect(InterpretSecurityProperty(RawNumber("7", 7U)).property ==
                 SecurityProperty::ModeBasedExecutionControl,
             L"S-01 security property 7 is ModeBasedExecutionControl");
    s.expect(InterpretSecurityProperty(RawNumber("8", 8U)).property ==
                 SecurityProperty::ApicVirtualization,
             L"S-01 security property 8 is ApicVirtualization");
    const SecurityPropertyValue propertyFuture = InterpretSecurityProperty(RawNumber("15", 15U));
    s.expect(propertyFuture.property == SecurityProperty::Unknown &&
                 !propertyFuture.interpretation.recognized &&
                 propertyFuture.interpretation.rawCode == OptionalU64::of(15U),
             L"S-01 an unknown security property code keeps its raw value");

    // --- 代码完整性执行状态编码 ---
    s.expect(InterpretCodeIntegrityEnforcement(RawNumber("0", 0U)).enforcement ==
                 CodeIntegrityEnforcement::Off,
             L"S-04 code integrity code 0 is Off");
    s.expect(InterpretCodeIntegrityEnforcement(RawNumber("1", 1U)).enforcement ==
                 CodeIntegrityEnforcement::Audit,
             L"S-04 code integrity code 1 is Audit");
    s.expect(InterpretCodeIntegrityEnforcement(RawNumber("2", 2U)).enforcement ==
                 CodeIntegrityEnforcement::Enforced,
             L"S-04 code integrity code 2 is Enforced");
    const CodeIntegrityEnforcementValue ciFuture = InterpretCodeIntegrityEnforcement(RawNumber("5", 5U));
    s.expect(ciFuture.enforcement == CodeIntegrityEnforcement::Unknown &&
                 !ciFuture.interpretation.recognized && ciFuture.interpretation.rawText == "5",
             L"S-04 an unknown code integrity code is not read as Off");

    // --- 词汇表本身。规范点名的能力/权限档/约束类都必须有各自的名字，不许两档共名。 ---
    s.expect(std::string(SecurityCapabilityName(SecurityCapabilityId::CredentialGuard)) ==
                 "CredentialGuard",
             L"S-01 CredentialGuard is named in the capability vocabulary");
    s.expect(std::string(SecurityCapabilityName(SecurityCapabilityId::SystemGuardSecureLaunch)) ==
                 "SystemGuardSecureLaunch",
             L"S-01 SystemGuardSecureLaunch is named in the capability vocabulary");
    s.expect(std::string(SecurityCapabilityName(SecurityCapabilityId::KernelDmaProtection)) ==
                 "KernelDmaProtection",
             L"S-03 KernelDmaProtection is named in the capability vocabulary");
    s.expect(std::string(SecurityCapabilityName(SecurityCapabilityId::KernelModeCodeIntegrityPolicy)) ==
                     "KernelModeCodeIntegrityPolicy" &&
                 std::string(SecurityCapabilityName(
                     SecurityCapabilityId::UserModeCodeIntegrityPolicy)) ==
                     "UserModeCodeIntegrityPolicy",
             L"S-04 kernel mode and user mode policy are two separately named capabilities");
    s.expect(std::string(SecurityCapabilityName(SecurityCapabilityId::TpmPresence)) !=
                 std::string(SecurityCapabilityName(SecurityCapabilityId::TpmReadiness)),
             L"S-03 TPM presence and TPM readiness do not share one name");

    s.expect(std::string(AccessRequirementName(AccessRequirement::Unknown)) == "Unknown",
             L"S-07 an undeclared access requirement is named Unknown, not None");
    s.expect(std::string(AccessRequirementName(AccessRequirement::None)) == "None",
             L"S-07 the None access requirement has its own name");
    s.expect(std::string(AccessRequirementName(AccessRequirement::Administrator)) == "Administrator",
             L"S-07 the Administrator access requirement has its own name");
    s.expect(std::string(AccessRequirementName(AccessRequirement::System)) == "System",
             L"S-07 the System access requirement is named System and not folded into Administrator");
    s.expect(std::string(AccessRequirementName(AccessRequirement::KswordDriver)) == "KswordDriver",
             L"S-07 the driver access requirement has its own name");

    s.expect(std::string(CapabilityConstraintKindName(
                 CapabilityConstraintKind::PrivilegeInsufficient)) == "PrivilegeInsufficient",
             L"S-06 PrivilegeInsufficient is a separately named constraint kind");
    s.expect(std::string(CapabilityConstraintKindName(CapabilityConstraintKind::QueryUnavailable)) ==
                 "QueryUnavailable",
             L"S-06 QueryUnavailable is a separately named constraint kind");
    s.expect(std::string(CapabilityConstraintKindName(
                 CapabilityConstraintKind::SecurityConfiguration)) == "SecurityConfiguration",
             L"S-06 SecurityConfiguration is a separately named constraint kind");
}

// ---------------------------------------------------------------------------
// S-02：新鲜度判定
// ---------------------------------------------------------------------------
void TestFreshness(KswordTests::Suite& s) {
    const CaptureWindow current = CurrentWindow();

    CaptureWindow same;
    same.bootId = kBootCurrent;
    same.machineId = kMachine;
    s.expect(ClassifyFieldFreshness(same, current) == FieldFreshness::Current,
             L"S-02 the same bootId is classified Current");

    CaptureWindow older;
    older.bootId = kBootPrevious;
    older.machineId = kMachine;
    s.expect(ClassifyFieldFreshness(older, current) == FieldFreshness::Historical,
             L"S-02 a different bootId is classified Historical");

    CaptureWindow noBoot;
    noBoot.machineId = kMachine;
    s.expect(ClassifyFieldFreshness(noBoot, current) == FieldFreshness::Unknown,
             L"S-02 a field without bootId is Unknown rather than Current");

    CaptureWindow currentNoBoot;
    currentNoBoot.machineId = kMachine;
    s.expect(ClassifyFieldFreshness(same, currentNoBoot) == FieldFreshness::Unknown,
             L"S-02 a baseline without bootId makes freshness Unknown");

    CaptureWindow foreign;
    foreign.bootId = kBootCurrent;
    foreign.machineId = "machine-other";
    s.expect(ClassifyFieldFreshness(foreign, current) == FieldFreshness::DifferentMachine,
             L"S-02 a different machineId wins over a matching bootId");

    s.expect(FreshnessUsableAsCurrent(FieldFreshness::Current),
             L"S-02 only Current may be used as the present value");
    s.expect(!FreshnessUsableAsCurrent(FieldFreshness::Unknown),
             L"S-02 Unknown freshness may not be used as the present value");
    s.expect(!FreshnessUsableAsCurrent(FieldFreshness::Historical),
             L"S-02 Historical may not be used as the present value");
    s.expect(!FreshnessUsableAsCurrent(FieldFreshness::DifferentMachine),
             L"S-02 DifferentMachine may not be used as the present value");
}

// ---------------------------------------------------------------------------
// S-01/S-07：字段可读性矩阵。五种失败语义必须彼此可区分且原始错误码保留。
// ---------------------------------------------------------------------------
void TestFieldAvailabilityMatrix(KswordTests::Suite& s) {
    SecurityStateInput input;
    input.currentWindow = CurrentWindow();
    input.privilege.administrator = TriState::No;
    input.privilege.kswordDriverLoaded = TriState::No;

    SecurityField ok = MakeField("f.ok", "wmi", kBootCurrent);
    ok.raw = RawNumber("2", 2U);

    SecurityField denied = MakeField("f.denied", "wmi", kBootCurrent);
    denied.outcome =
        CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5U, "Access is denied.");

    SecurityField unsupported = MakeField("f.unsupported", "wmi", kBootCurrent);
    unsupported.outcome = CollectionOutcome::failure(CollectionStatus::Unsupported, "HRESULT",
                                                     0x80041010ULL, "Invalid class");

    SecurityField timeout = MakeField("f.timeout", "wmi", kBootCurrent);
    timeout.outcome =
        CollectionOutcome::failure(CollectionStatus::Timeout, "WIN32", 1460U, "The operation timed out.");

    SecurityField failed = MakeField("f.error", "wmi", kBootCurrent);
    failed.outcome = CollectionOutcome::failure(CollectionStatus::Error, "NTSTATUS", 0xC0000001ULL,
                                                "STATUS_UNSUCCESSFUL");

    SecurityField needAdmin = MakeField("f.admin", "reg", kBootCurrent);
    needAdmin.outcome = CollectionOutcome::notCollected();
    needAdmin.access = AccessRequirement::Administrator;

    SecurityField needDriver = MakeField("f.driver", "r0", kBootCurrent);
    needDriver.outcome = CollectionOutcome::notCollected();
    needDriver.access = AccessRequirement::KswordDriver;

    SecurityField plainMissing = MakeField("f.missing", "reg", kBootCurrent);
    plainMissing.outcome = CollectionOutcome::notCollected();

    // 正确的空集合：跑了，成功，只是没有内容 —— 与上面任何一种失败都不是一回事。
    SecurityField emptyButOk = MakeField("f.empty", "reg", kBootCurrent);
    emptyButOk.raw = RawText("");

    input.fields = {ok,     denied,    unsupported, timeout,   failed,
                    needAdmin, needDriver, plainMissing, emptyButOk};

    const SecurityStateReport report = EvaluateSecurityState(input);
    s.expect(report.fields.size() == 9U, L"S-07 all nine fields survive into the report");

    const FieldAssessment* okView = report.findField("f.ok");
    s.expect(okView != nullptr && okView->availability == FieldAvailability::Readable,
             L"S-07 a successful field is Readable");
    s.expect(okView != nullptr && okView->raw.text == "2" && okView->raw.numeric == OptionalU64::of(2U),
             L"S-02 the raw value is preserved verbatim");

    const FieldAssessment* deniedView = report.findField("f.denied");
    s.expect(deniedView != nullptr && deniedView->availability == FieldAvailability::BlockedByPrivilege,
             L"S-07 access denied becomes BlockedByPrivilege");
    s.expect(deniedView != nullptr && deniedView->outcome.status == CollectionStatus::AccessDenied,
             L"S-01 the AccessDenied status itself is preserved");
    s.expect(deniedView != nullptr && deniedView->outcome.nativeCode == OptionalU64::of(5U) &&
                 deniedView->outcome.nativeCodeDomain == "WIN32",
             L"S-01 the native error code and its domain are preserved");
    s.expect(deniedView != nullptr && deniedView->outcome.message == "Access is denied.",
             L"S-01 the message from the source is preserved");

    const FieldAssessment* unsupportedView = report.findField("f.unsupported");
    s.expect(unsupportedView != nullptr &&
                 unsupportedView->availability == FieldAvailability::NotSupported,
             L"S-07 unsupported is its own availability value");
    const FieldAssessment* timeoutView = report.findField("f.timeout");
    s.expect(timeoutView != nullptr && timeoutView->outcome.status == CollectionStatus::Timeout,
             L"S-01 a timeout is not collapsed into a generic error");
    const FieldAssessment* errorView = report.findField("f.error");
    s.expect(errorView != nullptr && errorView->outcome.status == CollectionStatus::Error &&
                 errorView->outcome.nativeCode == OptionalU64::of(0xC0000001ULL),
             L"S-01 an NTSTATUS value is preserved");
    s.expect(timeoutView != nullptr && errorView != nullptr &&
                 timeoutView->outcome.status != errorView->outcome.status,
             L"S-01 timeout and error stay two distinguishable values");

    const FieldAssessment* adminView = report.findField("f.admin");
    s.expect(adminView != nullptr && adminView->availability == FieldAvailability::BlockedByPrivilege,
             L"S-07 not collected plus an admin requirement is explained as a privilege block");
    s.expect(adminView != nullptr && adminView->access == AccessRequirement::Administrator,
             L"S-07 the privilege requirement is recorded per field");
    const FieldAssessment* driverView = report.findField("f.driver");
    s.expect(driverView != nullptr && driverView->availability == FieldAvailability::BlockedByDriver,
             L"S-07 a driver requirement is separate from a privilege requirement");
    const FieldAssessment* missingView = report.findField("f.missing");
    s.expect(missingView != nullptr && missingView->availability == FieldAvailability::NotCollected,
             L"S-07 not collected with no privilege reason stays NotCollected");
    const FieldAssessment* emptyView = report.findField("f.empty");
    s.expect(emptyView != nullptr && emptyView->availability == FieldAvailability::Readable,
             L"S-01 a correct empty result is still a readable observation");
    s.expect(emptyView != nullptr && emptyView->carriesObservation,
             L"S-01 empty but successful is not a failure");

    s.expect(report.readableFieldCount == 2U, L"S-07 the readable field count is exact");
    s.expect(report.blockedFieldCount == 3U, L"S-07 the blocked field count is exact");
    s.expect(report.hasLimitation(SecurityLimitationKeys::kPrivilegeDegraded),
             L"S-07 privilege degradation is accounted for explicitly");
    s.expect(report.hasLimitation(SecurityLimitationKeys::kDriverDegraded),
             L"S-07 driver degradation is accounted for explicitly");

    // describe()：原始值与规范化解释并列输出。
    SecurityStateInput described;
    described.currentWindow = CurrentWindow();
    SecurityField withInterp = MakeField("f.vbs", "wmi", kBootCurrent);
    withInterp.raw = RawNumber("2", 2U);
    withInterp.interpretation = InterpretVbsStatus(withInterp.raw).interpretation;
    described.fields = {withInterp};
    const SecurityStateReport describedReport = EvaluateSecurityState(described);
    const FieldAssessment* describedView = describedReport.findField("f.vbs");
    s.expect(describedView != nullptr, L"S-02 the described field exists");
    const std::string text = describedView == nullptr ? std::string() : describedView->describe();
    s.expect(Contains(text, "raw=2"), L"S-02 describe emits the raw value");
    s.expect(Contains(text, "normalized=EnabledAndRunning"),
             L"S-02 describe emits the normalized interpretation");
    s.expect(Contains(text, "query=query:f.vbs"), L"S-02 describe emits the concrete query entry");
    s.expect(Contains(text, "boot=boot-S-current"), L"S-02 describe emits the boot the value came from");
    s.expect(describedView != nullptr && describedView->raw.text == "2",
             L"S-02 normalization does not overwrite the raw value");
}

// ---------------------------------------------------------------------------
// S-01：四维分离 + 五种输入样本
// ---------------------------------------------------------------------------
void TestFourDimensions(KswordTests::Suite& s) {
    // 样本一：未配置。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField field = MakeField("vbs.status", "wmi", kBootCurrent);
        field.raw = RawNumber("0", 0U);
        input.fields = {field};
        input.claims = {
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Configured,
                      TriState::No, "vbs.status"),
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Running,
                      TriState::No, "vbs.status"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* vbs =
            report.findCapability(SecurityCapabilityId::VirtualizationBasedSecurity);
        s.expect(vbs != nullptr, L"S-01 the not-configured sample yields a capability state");
        s.expect(vbs != nullptr && vbs->configured.value == TriState::No,
                 L"S-01 not configured gives configured=No");
        s.expect(vbs != nullptr && vbs->running.value == TriState::No,
                 L"S-01 not configured gives running=No");
        s.expect(vbs != nullptr && vbs->hardwareSupport.value == TriState::Unknown,
                 L"S-01 hardware support stays Unknown and is not inferred from configuration");
        s.expect(vbs != nullptr && vbs->queryOutcome.status == CollectionStatus::Success,
                 L"S-01 the fourth dimension records that the query succeeded");
    }

    // 样本二：已配置未运行 —— 这是 Configured/Running 混用的经典事故点。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField field = MakeField("vbs.status", "wmi", kBootCurrent);
        field.raw = RawNumber("1", 1U);
        input.fields = {field};
        input.claims = {
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Configured,
                      TriState::Yes, "vbs.status"),
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Running,
                      TriState::No, "vbs.status"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* vbs =
            report.findCapability(SecurityCapabilityId::VirtualizationBasedSecurity);
        s.expect(vbs != nullptr && vbs->configured.value == TriState::Yes,
                 L"S-01 configured but not running gives configured=Yes");
        s.expect(vbs != nullptr && vbs->running.value == TriState::No,
                 L"S-01 configured but not running gives running=No");
        s.expect(vbs != nullptr && vbs->running.value != TriState::Yes,
                 L"S-01 configured is never displayed as running");
    }

    // 样本三：正在运行。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField field = MakeField("vbs.status", "wmi", kBootCurrent);
        field.raw = RawNumber("2", 2U);
        SecurityField hardware = MakeField("vbs.available", "wmi", kBootCurrent);
        hardware.raw = RawNumber("1", 1U);
        input.fields = {field, hardware};
        input.claims = {
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity,
                      SecurityDimension::HardwareSupport, TriState::Yes, "vbs.available"),
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Configured,
                      TriState::Yes, "vbs.status"),
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Running,
                      TriState::Yes, "vbs.status"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* vbs =
            report.findCapability(SecurityCapabilityId::VirtualizationBasedSecurity);
        s.expect(vbs != nullptr && vbs->hardwareSupport.value == TriState::Yes,
                 L"S-01 hardware support comes from its own field");
        s.expect(vbs != nullptr && vbs->running.value == TriState::Yes,
                 L"S-01 the running sample gives running=Yes");
        s.expect(vbs != nullptr && vbs->hardwareSupport.claims.size() == 1U &&
                     vbs->hardwareSupport.claims[0].fieldId == "vbs.available",
                 L"S-01 the hardware dimension points back at its own field");
        s.expect(report.conclusion == AnalysisConclusion::NoDifferenceObserved,
                 L"S-05 a fully covered run with no conflict concludes NoDifferenceObserved");
    }

    // 样本四：无权限 —— 查询失败绝不等于关闭。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        input.privilege.administrator = TriState::No;
        SecurityField field = MakeField("vbs.status", "wmi", kBootCurrent);
        field.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5U,
                                                   "Access is denied.");
        field.access = AccessRequirement::Administrator;
        input.fields = {field};
        // 来源"顺手"给了一个 No —— 本层必须拒绝采纳。
        input.claims = {
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Running,
                      TriState::No, "vbs.status"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* vbs =
            report.findCapability(SecurityCapabilityId::VirtualizationBasedSecurity);
        s.expect(vbs != nullptr && vbs->running.value == TriState::Unknown,
                 L"S-01 a failed query leaves running Unknown instead of No");
        s.expect(vbs != nullptr && vbs->running.claims.size() == 1U &&
                     vbs->running.claims[0].value == TriState::No,
                 L"S-01 the source claim is still shown verbatim");
        s.expect(vbs != nullptr && !vbs->running.claims[0].usableAsCurrent,
                 L"S-01 a claim without observation cannot set a value");
        s.expect(vbs != nullptr && vbs->queryOutcome.status == CollectionStatus::AccessDenied,
                 L"S-01 the fourth dimension keeps AccessDenied");
        s.expect(vbs != nullptr && vbs->queryOutcome.nativeCode == OptionalU64::of(5U),
                 L"S-01 the capability level outcome also keeps the native code");
        s.expect(vbs != nullptr && vbs->requiresAdministrator,
                 L"S-07 the capability is marked as needing administrator");
        s.expect(vbs != nullptr && vbs->blockedFieldCount == 1U,
                 L"S-07 the capability counts its blocked fields");
        s.expect(report.hasLimitation(SecurityLimitationKeys::kClaimNotObserved),
                 L"S-01 a definite claim over a failed query is accounted for");
        s.expect(report.conclusion == AnalysisConclusion::NoEvidence,
                 L"S-01 with no observation at all the conclusion is NoEvidence, not normal");
    }

    // 样本五：未知枚举值。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField field = MakeField("vbs.status", "wmi", kBootCurrent);
        field.raw = RawNumber("7", 7U);
        field.interpretation = InterpretVbsStatus(field.raw).interpretation;
        input.fields = {field};
        input.claims = {
            MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Running,
                      TriState::Unknown, "vbs.status"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const FieldAssessment* view = report.findField("vbs.status");
        s.expect(view != nullptr && view->raw.numeric == OptionalU64::of(7U),
                 L"S-01 the unknown enum value survives into the report");
        s.expect(view != nullptr && !view->interpretation.recognized,
                 L"S-01 the unknown enum value is flagged unrecognized");
        s.expect(view != nullptr && view->interpretation.normalizedName.empty(),
                 L"S-01 an unknown enum value gets no normalized name");
        s.expect(report.hasLimitation(SecurityLimitationKeys::kUnknownEnumPreserved),
                 L"S-01 the report states that an unknown enum value was seen");
        const CapabilityState* vbs =
            report.findCapability(SecurityCapabilityId::VirtualizationBasedSecurity);
        s.expect(vbs != nullptr && vbs->running.value == TriState::Unknown,
                 L"S-01 an unknown enum value is not mis-explained as a concrete state");
    }
}

// ---------------------------------------------------------------------------
// S-02：历史状态不得当成当前值（OfflineSample 与 LiveKernel 混合）
// ---------------------------------------------------------------------------
void TestHistoricalSeparation(KswordTests::Suite& s) {
    SecurityStateInput input;
    input.currentWindow = CurrentWindow();

    SecurityField live = MakeField("hvci.running.live", "wmi", kBootCurrent);
    live.source.origin = SourceOrigin::LiveKernel;
    live.raw = RawNumber("2", 2U);

    SecurityField saved = MakeField("hvci.running.saved", "session", kBootPrevious);
    saved.source.origin = SourceOrigin::OfflineSample;
    saved.raw = RawNumber("0", 0U);

    input.fields = {live, saved};
    input.claims = {
        MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Running,
                  TriState::Yes, "hvci.running.live"),
        MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Running,
                  TriState::No, "hvci.running.saved"),
    };

    const SecurityStateReport report = EvaluateSecurityState(input);
    const CapabilityState* hvci =
        report.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
    s.expect(hvci != nullptr, L"S-02 the capability state exists");
    s.expect(hvci != nullptr && hvci->running.value == TriState::Yes,
             L"S-02 the present value only takes evidence from the current boot");
    s.expect(hvci != nullptr && hvci->running.historicalValue == TriState::No,
             L"S-02 the pre-reboot value is listed separately as historical");
    s.expect(hvci != nullptr && !hvci->running.conflicted,
             L"S-02 a historical value differing from the current one is not a conflict");
    s.expect(hvci != nullptr && hvci->running.claims.size() == 2U,
             L"S-02 both sources stay in the report");
    s.expect(hvci != nullptr && hvci->running.claims[1].freshness == FieldFreshness::Historical,
             L"S-02 the offline source is marked historical");
    s.expect(hvci != nullptr && hvci->running.definiteClaimCount == 1U,
             L"S-02 only one claim participates in the present value");
    s.expect(report.historicalFieldCount == 1U, L"S-02 historical fields are counted");
    s.expect(report.hasLimitation(SecurityLimitationKeys::kFieldHistorical),
             L"S-02 the report states that it carries historical state");
    s.expect(report.trust.offlineSampleViewCount == 1U,
             L"S-02 offline sample sources are counted per origin");
    s.expect(report.trust.liveKernelViewCount == 1U,
             L"S-02 live kernel sources are counted per origin");
    s.expect(HasKey(report.trust.limitationKeys, "trust.limitation.offlineSample"),
             L"S-02 mixing in an offline sample is declared in the trust statement");
    s.expect(report.envelope.source.origin == SourceOrigin::Unknown,
             L"S-02 a mixed origin report does not pick one origin to stand for all");
    // 账目口径：采集成功但属于上一次启动的观测回答不了"现在是什么状态"。
    s.expect(report.envelope.coverage.succeeded == 1U,
             L"S-02 only the current boot observation counts as covered");
    s.expect(report.envelope.coverage.skipped == 1U,
             L"S-02 a pre-reboot observation is accounted as skipped, not as covered");
    s.expect(report.envelope.coverage.failed == 0U,
             L"S-02 a pre-reboot observation is not miscounted as a failure");
    s.expect(!report.envelope.coverage.fullyCovered(),
             L"S-02 mixing in pre-reboot data means the current state is not fully covered");

    // 只有历史证据时，当前值必须是未知 —— 这是"重启前的状态不得当成当前值"的正例。
    {
        SecurityStateInput onlyOld;
        onlyOld.currentWindow = CurrentWindow();
        onlyOld.fields = {saved};
        onlyOld.claims = {MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                                    SecurityDimension::Running, TriState::Yes, "hvci.running.saved")};
        const SecurityStateReport oldReport = EvaluateSecurityState(onlyOld);
        const CapabilityState* oldHvci =
            oldReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(oldHvci != nullptr && oldHvci->running.value == TriState::Unknown,
                 L"S-02 with only historical evidence the present value is Unknown");
        s.expect(oldHvci != nullptr && oldHvci->running.historicalValue == TriState::Yes,
                 L"S-02 the historical value is still visible");
        s.expect(oldReport.conclusion != AnalysisConclusion::NoDifferenceObserved,
                 L"S-02 historical evidence alone cannot conclude NoDifferenceObserved");
        s.expect(oldReport.conclusion == AnalysisConclusion::Indeterminate,
                 L"S-02 historical evidence alone concludes Indeterminate");
        s.expect(oldReport.envelope.coverage.succeeded == 0U &&
                     oldReport.envelope.coverage.skipped == 1U,
                 L"S-02 a run made only of pre-reboot data covers nothing about the present");
        s.expect(!oldReport.envelope.coverage.fullyCovered(),
                 L"S-02 a run made only of pre-reboot data is never fully covered");
        s.expect(oldReport.trust.anyIncompleteCoverage,
                 L"S-02 the trust statement also flags the incomplete coverage");
    }

    // 另一台机器的样本：既不进当前值，也不进历史值。
    {
        SecurityStateInput foreign;
        foreign.currentWindow = CurrentWindow();
        SecurityField other = MakeField("hvci.running.other", "session", kBootCurrent);
        other.window.machineId = "machine-other";
        other.source.origin = SourceOrigin::OfflineSample;
        foreign.fields = {other};
        foreign.claims = {MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                                    SecurityDimension::Running, TriState::Yes, "hvci.running.other")};
        const SecurityStateReport foreignReport = EvaluateSecurityState(foreign);
        const CapabilityState* foreignHvci =
            foreignReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(foreignHvci != nullptr && foreignHvci->running.value == TriState::Unknown,
                 L"S-02 a sample from another machine is not the present value");
        s.expect(foreignHvci != nullptr && foreignHvci->running.historicalValue == TriState::Unknown,
                 L"S-02 a sample from another machine is not this machine's history either");
        s.expect(foreignReport.hasLimitation(SecurityLimitationKeys::kFieldForeignMachine),
                 L"S-02 a cross machine sample is accounted for explicitly");
    }
}

// ---------------------------------------------------------------------------
// S-05：三源冲突 + 待生效
// ---------------------------------------------------------------------------
void TestConflictAndPending(KswordTests::Suite& s) {
    SecurityStateInput input;
    input.currentWindow = CurrentWindow();

    SecurityField wmi = MakeField("dg.wmi.configured", "wmi", kBootCurrent);
    wmi.raw = RawNumber("2", 2U);
    SecurityField registry = MakeField("dg.registry.enabled", "registry", kBootCurrent);
    registry.raw = RawNumber("0", 0U);
    SecurityField runtime = MakeField("dg.runtime.probe", "runtime", kBootCurrent);
    runtime.raw = RawText("present");

    input.fields = {wmi, registry, runtime};
    input.claims = {
        MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Configured,
                  TriState::Yes, "dg.wmi.configured"),
        MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Configured,
                  TriState::No, "dg.registry.enabled"),
        MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Configured,
                  TriState::Yes, "dg.runtime.probe"),
    };

    const SecurityStateReport report = EvaluateSecurityState(input);
    const CapabilityState* hvci =
        report.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
    s.expect(hvci != nullptr && hvci->configured.conflicted,
             L"S-05 three disagreeing sources are reported as a conflict");
    s.expect(hvci != nullptr && hvci->configured.value == TriState::Unknown,
             L"S-05 a conflict never reports enabled, the value stays Unknown");
    s.expect(hvci != nullptr && hvci->configured.claims.size() == 3U,
             L"S-05 all three source values are kept");
    s.expect(hvci != nullptr && hvci->configured.claims[0].value == TriState::Yes &&
                 hvci->configured.claims[1].value == TriState::No &&
                 hvci->configured.claims[2].value == TriState::Yes,
             L"S-05 each source value is shown verbatim side by side");
    s.expect(hvci != nullptr && hvci->configured.claims[0].sourceGroup == "wmi" &&
                 hvci->configured.claims[1].sourceGroup == "registry" &&
                 hvci->configured.claims[2].sourceGroup == "runtime",
             L"S-05 every value points back at its own source group");
    s.expect(hvci != nullptr && hvci->configured.distinctSourceGroupCount == 3U,
             L"S-05 three independent source groups are counted");
    s.expect(hvci != nullptr && hvci->configured.definiteClaimCount == 3U,
             L"S-05 all three claims took part in the comparison");

    const DimensionConflict* conflict = report.findConflict(
        SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Configured);
    s.expect(conflict != nullptr, L"S-05 the conflict is listed in its own table");
    s.expect(conflict != nullptr && conflict->resolvedValue == TriState::Unknown,
             L"S-05 the conflict table does not pick a value for the caller");
    s.expect(conflict != nullptr && conflict->claims.size() == 3U,
             L"S-05 the conflict table keeps every source");
    s.expect(conflict != nullptr && !conflict->pendingActivation,
             L"S-05 without pending evidence a conflict is never guessed to need a reboot");
    s.expect(report.hasLimitation(SecurityLimitationKeys::kDimensionConflict),
             L"S-05 the conflict is accounted for explicitly");
    s.expect(report.conclusion == AnalysisConclusion::DifferenceObserved,
             L"S-05 a conflict makes the conclusion DifferenceObserved");
    s.expect(report.conclusion != AnalysisConclusion::NoDifferenceObserved,
             L"S-05 a conflict is never benign-ised");

    // 两个来源一致时不算冲突（避免"只要多来源就报冲突"的另一种作弊）。
    {
        SecurityStateInput agree = input;
        agree.claims[1].value = TriState::Yes;
        const SecurityStateReport agreeReport = EvaluateSecurityState(agree);
        const CapabilityState* agreeHvci =
            agreeReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(agreeHvci != nullptr && !agreeHvci->configured.conflicted,
                 L"S-05 three agreeing sources are not a conflict");
        s.expect(agreeHvci != nullptr && agreeHvci->configured.value == TriState::Yes,
                 L"S-05 three agreeing sources yield that definite value");
        s.expect(agreeReport.conflicts.empty(), L"S-05 the conflict table is empty when sources agree");
    }

    // Unknown 不构成冲突，但也不会让 Unknown 那一侧"被投票淹没"。
    {
        SecurityStateInput partial = input;
        partial.claims[1].value = TriState::Unknown;
        partial.claims[2].value = TriState::Yes;
        const SecurityStateReport partialReport = EvaluateSecurityState(partial);
        const CapabilityState* partialHvci =
            partialReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(partialHvci != nullptr && !partialHvci->configured.conflicted,
                 L"S-05 Unknown does not conflict with a definite value");
        s.expect(partialHvci != nullptr && partialHvci->configured.definiteClaimCount == 2U,
                 L"S-05 Unknown is not counted as a definite claim");
        s.expect(partialHvci != nullptr && partialHvci->configured.claims.size() == 3U,
                 L"S-05 the Unknown source is still displayed");
    }

    // 待生效：来源明确给出证据时才标。
    {
        SecurityStateInput pending = input;
        SecurityField reboot = MakeField("dg.pending.reboot", "registry", kBootCurrent);
        reboot.raw = RawText("PendingReboot=1");
        pending.fields.push_back(reboot);
        PendingActivationEvidence evidence;
        evidence.capability = SecurityCapabilityId::HypervisorEnforcedCodeIntegrity;
        evidence.dimension = SecurityDimension::Configured;
        evidence.fieldId = "dg.pending.reboot";
        evidence.rawText = "PendingReboot=1";
        pending.pendingEvidence = {evidence};
        const SecurityStateReport pendingReport = EvaluateSecurityState(pending);
        const CapabilityState* pendingHvci =
            pendingReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(pendingHvci != nullptr && pendingHvci->configured.pendingActivation,
                 L"S-05 explicit pending evidence marks the dimension pending");
        s.expect(pendingHvci != nullptr &&
                     pendingHvci->configured.pendingEvidenceFieldId == "dg.pending.reboot",
                 L"S-05 pending points back at the concrete evidence field");
        s.expect(pendingHvci != nullptr && pendingHvci->configured.value == TriState::Unknown,
                 L"S-05 marking pending does not change the Unknown of a conflict");
    }

    // 待生效证据本身没采到 -> 不算数。
    {
        SecurityStateInput pending = input;
        SecurityField reboot = MakeField("dg.pending.reboot", "registry", kBootCurrent);
        reboot.outcome = CollectionOutcome::notCollected();
        pending.fields.push_back(reboot);
        PendingActivationEvidence evidence;
        evidence.capability = SecurityCapabilityId::HypervisorEnforcedCodeIntegrity;
        evidence.dimension = SecurityDimension::Configured;
        evidence.fieldId = "dg.pending.reboot";
        pending.pendingEvidence = {evidence};
        const SecurityStateReport pendingReport = EvaluateSecurityState(pending);
        const CapabilityState* pendingHvci =
            pendingReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(pendingHvci != nullptr && !pendingHvci->configured.pendingActivation,
                 L"S-05 pending evidence that was never collected does not count");
    }

    // 待生效证据来自上一次启动 -> 不算当前的待生效。
    {
        SecurityStateInput pending = input;
        SecurityField reboot = MakeField("dg.pending.reboot", "registry", kBootPrevious);
        reboot.raw = RawText("PendingReboot=1");
        pending.fields.push_back(reboot);
        PendingActivationEvidence evidence;
        evidence.capability = SecurityCapabilityId::HypervisorEnforcedCodeIntegrity;
        evidence.dimension = SecurityDimension::Configured;
        evidence.fieldId = "dg.pending.reboot";
        pending.pendingEvidence = {evidence};
        const SecurityStateReport pendingReport = EvaluateSecurityState(pending);
        const CapabilityState* pendingHvci =
            pendingReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(pendingHvci != nullptr && !pendingHvci->configured.pendingActivation,
                 L"S-05 pre-reboot pending evidence is not treated as pending now");
    }

    // 待生效证据指向不存在的字段 -> 不算数。
    {
        SecurityStateInput pending = input;
        PendingActivationEvidence evidence;
        evidence.capability = SecurityCapabilityId::HypervisorEnforcedCodeIntegrity;
        evidence.dimension = SecurityDimension::Configured;
        evidence.fieldId = "dg.pending.nonexistent";
        pending.pendingEvidence = {evidence};
        const SecurityStateReport pendingReport = EvaluateSecurityState(pending);
        const CapabilityState* pendingHvci =
            pendingReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(pendingHvci != nullptr && !pendingHvci->configured.pendingActivation,
                 L"S-05 pending evidence with no backing field does not count");
    }
}

// ---------------------------------------------------------------------------
// 反作弊：整轮缺席的能力必须显式记账
// ---------------------------------------------------------------------------
void TestMissingCapabilityAccounting(KswordTests::Suite& s) {
    SecurityStateInput input;
    input.currentWindow = CurrentWindow();
    SecurityField field = MakeField("sb.enabled", "uefi", kBootCurrent);
    field.raw = RawText("True");
    input.fields = {field};
    input.claims = {MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running,
                              TriState::Yes, "sb.enabled")};
    input.requestedCapabilities = {SecurityCapabilityId::SecureBoot,
                                   SecurityCapabilityId::TpmPresence,
                                   SecurityCapabilityId::KernelDmaProtection};

    const SecurityStateReport report = EvaluateSecurityState(input);
    s.expect(report.capabilities.size() == 3U,
             L"S-01 every requested capability appears in the report");

    const CapabilityState* tpm = report.findCapability(SecurityCapabilityId::TpmPresence);
    s.expect(tpm != nullptr, L"a capability absent for the whole run still produces a record");
    s.expect(tpm != nullptr && !tpm->anyClaim, L"an absent capability is marked as having no claim");
    s.expect(tpm != nullptr && tpm->queryOutcome.status == CollectionStatus::NotCollected,
             L"an absent capability gets NotCollected, not success");
    s.expect(tpm != nullptr && tpm->hardwareSupport.value == TriState::Unknown &&
                 tpm->configured.value == TriState::Unknown && tpm->running.value == TriState::Unknown,
             L"an absent capability has all three dimensions Unknown");
    s.expect(report.missingCapabilityCount == 2U, L"absent capabilities are counted exactly");
    s.expect(report.hasLimitation(SecurityLimitationKeys::kCapabilityNotCollected),
             L"absent capabilities are accounted for explicitly");
    s.expect(report.envelope.coverage.skipped == 2U,
             L"absent capabilities land in the coverage account as skipped");
    s.expect(report.envelope.coverage.totalKnown == OptionalU64::of(3U),
             L"the coverage total is fields plus absent capabilities");
    s.expect(!report.envelope.coverage.fullyCovered(),
             L"anything absent means the coverage is not complete");
    s.expect(report.conclusion == AnalysisConclusion::Indeterminate,
             L"incomplete coverage concludes Indeterminate, not NoDifferenceObserved");

    // 正面对照：账目填满且无缺席时才允许 NoDifferenceObserved。
    {
        SecurityStateInput complete;
        complete.currentWindow = CurrentWindow();
        complete.fields = {field};
        complete.claims = input.claims;
        complete.requestedCapabilities = {SecurityCapabilityId::SecureBoot};
        const SecurityStateReport completeReport = EvaluateSecurityState(complete);
        s.expect(completeReport.missingCapabilityCount == 0U,
                 L"nothing absent means a zero absence count");
        s.expect(completeReport.envelope.coverage.fullyCovered(),
                 L"a self consistent account is judged fully covered");
        s.expect(completeReport.conclusion == AnalysisConclusion::NoDifferenceObserved,
                 L"only full coverage with no conflict yields NoDifferenceObserved");
    }

    // 空输入：什么都没有就是无证据。
    {
        SecurityStateInput empty;
        empty.currentWindow = CurrentWindow();
        const SecurityStateReport emptyReport = EvaluateSecurityState(empty);
        s.expect(emptyReport.fields.empty() && emptyReport.capabilities.empty(),
                 L"an empty input invents no records");
        s.expect(emptyReport.envelope.outcome.status == CollectionStatus::NotCollected,
                 L"an empty input has collection status NotCollected");
        s.expect(emptyReport.conclusion == AnalysisConclusion::NoEvidence,
                 L"an empty input concludes NoEvidence rather than normal");
        s.expect(emptyReport.readableFieldCount == 0U && emptyReport.blockedFieldCount == 0U,
                 L"an empty input has zero counts");
    }

    // 无支撑断言：值原样留着，但不参与定值。
    {
        SecurityStateInput unbacked;
        unbacked.currentWindow = CurrentWindow();
        unbacked.claims = {MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running,
                                     TriState::Yes, "nowhere")};
        const SecurityStateReport unbackedReport = EvaluateSecurityState(unbacked);
        const CapabilityState* sb = unbackedReport.findCapability(SecurityCapabilityId::SecureBoot);
        s.expect(sb != nullptr && sb->running.value == TriState::Unknown,
                 L"a claim with no backing field produces no value");
        s.expect(sb != nullptr && sb->running.claims.size() == 1U && !sb->running.claims[0].backed,
                 L"an unbacked claim is flagged and kept");
        s.expect(sb != nullptr && sb->running.claims[0].value == TriState::Yes,
                 L"an unbacked claim still shows the value it asserted");
        s.expect(unbackedReport.hasLimitation(SecurityLimitationKeys::kClaimUnbacked),
                 L"an unbacked claim is accounted for explicitly");
        s.expect(sb != nullptr && sb->queryOutcome.status == CollectionStatus::NotCollected,
                 L"an unbacked claim cannot support the fourth dimension");
    }

    // 重复 fieldId：引用歧义必须报出来。
    {
        SecurityStateInput duplicate;
        duplicate.currentWindow = CurrentWindow();
        const SecurityField a = MakeField("dup", "wmi", kBootCurrent);
        const SecurityField b = MakeField("dup", "registry", kBootCurrent);
        duplicate.fields = {a, b};
        const SecurityStateReport duplicateReport = EvaluateSecurityState(duplicate);
        s.expect(duplicateReport.fields.size() == 2U, L"both fields with a duplicate id are kept");
        s.expect(duplicateReport.hasLimitation(SecurityLimitationKeys::kFieldDuplicateId),
                 L"a duplicate field id is accounted for explicitly");
    }
}

// ---------------------------------------------------------------------------
// S-03：启动安全
// ---------------------------------------------------------------------------
void TestBootSecurity(KswordTests::Suite& s) {
    // 缺 TPM：存在=No，但"就绪"不得被自动推成 No —— 那是另一个维度的另一次查询。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField present = MakeField("tpm.present", "tbs", kBootCurrent);
        present.raw = RawText("False");
        input.fields = {present};
        input.claims = {MakeClaim(SecurityCapabilityId::TpmPresence,
                                  SecurityDimension::HardwareSupport, TriState::No, "tpm.present")};
        input.requestedCapabilities = {SecurityCapabilityId::TpmPresence,
                                       SecurityCapabilityId::TpmReadiness};
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* presence = report.findCapability(SecurityCapabilityId::TpmPresence);
        const CapabilityState* readiness = report.findCapability(SecurityCapabilityId::TpmReadiness);
        s.expect(presence != nullptr && presence->hardwareSupport.value == TriState::No,
                 L"S-03 a missing TPM gives presence=No");
        s.expect(readiness != nullptr && readiness->running.value == TriState::Unknown,
                 L"S-03 a missing TPM does not auto-derive a readiness state");
        s.expect(readiness != nullptr && readiness->queryOutcome.status == CollectionStatus::NotCollected,
                 L"S-03 readiness that was never queried says so");
    }

    // TPM 在但未就绪。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField present = MakeField("tpm.present", "tbs", kBootCurrent);
        present.raw = RawText("True");
        SecurityField ready = MakeField("tpm.ready", "tbs", kBootCurrent);
        ready.raw = RawText("False");
        input.fields = {present, ready};
        input.claims = {
            MakeClaim(SecurityCapabilityId::TpmPresence, SecurityDimension::HardwareSupport,
                      TriState::Yes, "tpm.present"),
            MakeClaim(SecurityCapabilityId::TpmReadiness, SecurityDimension::Running, TriState::No,
                      "tpm.ready"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* presence = report.findCapability(SecurityCapabilityId::TpmPresence);
        const CapabilityState* readiness = report.findCapability(SecurityCapabilityId::TpmReadiness);
        s.expect(presence != nullptr && presence->hardwareSupport.value == TriState::Yes,
                 L"S-03 TPM presence is Yes");
        s.expect(readiness != nullptr && readiness->running.value == TriState::No,
                 L"S-03 TPM not ready is expressed on its own");
        s.expect(presence != nullptr && readiness != nullptr &&
                     presence->hardwareSupport.value != readiness->running.value,
                 L"S-03 presence and readiness are two independent conclusions");
    }

    // BIOS 不支持 Secure Boot / 查询不可用。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField capable = MakeField("sb.capable", "uefi", kBootCurrent);
        capable.raw = RawText("False");
        SecurityField enabled = MakeField("sb.enabled", "uefi", kBootCurrent);
        enabled.outcome = CollectionOutcome::failure(CollectionStatus::Unsupported, "WIN32", 50U,
                                                     "The request is not supported.");
        input.fields = {capable, enabled};
        input.claims = {
            MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::HardwareSupport,
                      TriState::No, "sb.capable"),
            MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running, TriState::No,
                      "sb.enabled"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* sb = report.findCapability(SecurityCapabilityId::SecureBoot);
        s.expect(sb != nullptr && sb->hardwareSupport.value == TriState::No,
                 L"S-03 firmware that cannot do Secure Boot is expressed on its own");
        s.expect(sb != nullptr && sb->running.value == TriState::Unknown,
                 L"S-03 an unavailable query leaves the running state Unknown");
        const FieldAssessment* enabledView = report.findField("sb.enabled");
        s.expect(enabledView != nullptr && enabledView->availability == FieldAvailability::NotSupported,
                 L"S-03 an unavailable query is marked NotSupported");
        s.expect(enabledView != nullptr && enabledView->outcome.nativeCode == OptionalU64::of(50U),
                 L"S-03 an unsupported query still keeps its native code");
        s.expect(sb != nullptr && sb->queryOutcome.status == CollectionStatus::Partial,
                 L"S-03 one success plus one failure makes the capability outcome Partial");
    }

    // 测量日志缺失：绝不能输出"Measured Boot 正常"。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField log = MakeField("measuredboot.log", "tbs", kBootCurrent);
        log.outcome = CollectionOutcome::notCollected();
        input.fields = {log};
        input.claims = {MakeClaim(SecurityCapabilityId::MeasuredBootLog, SecurityDimension::Running,
                                  TriState::Yes, "measuredboot.log")};
        input.requestedCapabilities = {SecurityCapabilityId::MeasuredBootLog};
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* mb = report.findCapability(SecurityCapabilityId::MeasuredBootLog);
        s.expect(mb != nullptr && mb->running.value == TriState::Unknown,
                 L"S-03 without a measured boot log the running state is Unknown");
        s.expect(mb != nullptr && mb->running.value != TriState::Yes,
                 L"S-03 Measured Boot is never reported as fine when the log is missing");
        s.expect(report.hasLimitation(SecurityLimitationKeys::kMeasuredBootLogUnknown),
                 L"S-03 a missing measured boot log is accounted for explicitly");
        s.expect(report.conclusion != AnalysisConclusion::NoDifferenceObserved,
                 L"S-03 a missing log cannot yield NoDifferenceObserved");

        // API 里没有远程证明结论 —— 能力清单里也没有这种名字。
        bool sawAttestation = false;
        for (const CapabilityState& state : report.capabilities) {
            const std::string name = SecurityCapabilityName(state.capability);
            if (Contains(name, "Attestation") || Contains(name, "Score")) {
                sawAttestation = true;
            }
        }
        s.expect(!sawAttestation,
                 L"S-03 the capability vocabulary has no remote attestation or security score");
    }
}

// ---------------------------------------------------------------------------
// S-04：WDAC 与代码完整性
// ---------------------------------------------------------------------------
void TestCodeIntegrity(KswordTests::Suite& s) {
    // audit
    {
        CodeIntegrityInput input;
        input.kernelModeRaw = RawNumber("1", 1U);
        input.kernelModeOutcome = CollectionOutcome::success();
        input.userModeRaw = RawNumber("1", 1U);
        input.userModeOutcome = CollectionOutcome::success();
        const CodeIntegrityAssessment assessment = EvaluateCodeIntegrity(input);
        s.expect(assessment.kernelModeEnforcement == CodeIntegrityEnforcement::Audit,
                 L"S-04 kernel mode audit is recognised");
        s.expect(assessment.userModeEnforcement == CodeIntegrityEnforcement::Audit,
                 L"S-04 user mode audit is recognised");
        s.expect(assessment.kernelModeInterpretation.normalizedName == "Audit",
                 L"S-04 audit carries a normalized name");
    }

    // enforced
    {
        CodeIntegrityInput input;
        input.kernelModeRaw = RawNumber("2", 2U);
        input.kernelModeOutcome = CollectionOutcome::success();
        input.userModeRaw = RawNumber("0", 0U);
        input.userModeOutcome = CollectionOutcome::success();
        const CodeIntegrityAssessment assessment = EvaluateCodeIntegrity(input);
        s.expect(assessment.kernelModeEnforcement == CodeIntegrityEnforcement::Enforced,
                 L"S-04 kernel mode enforced is recognised");
        s.expect(assessment.userModeEnforcement == CodeIntegrityEnforcement::Off,
                 L"S-04 user mode off is independent of kernel mode");
    }

    // 查询失败：不得落成 Off，原始值仍保留。
    {
        CodeIntegrityInput input;
        input.kernelModeRaw = RawNumber("2", 2U);
        input.kernelModeOutcome =
            CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5U, "Access is denied.");
        const CodeIntegrityAssessment assessment = EvaluateCodeIntegrity(input);
        s.expect(assessment.kernelModeEnforcement == CodeIntegrityEnforcement::Unknown,
                 L"S-04 a failed query leaves the enforcement state Unknown");
        s.expect(assessment.kernelModeEnforcement != CodeIntegrityEnforcement::Off,
                 L"S-04 a failed query never becomes Off");
        s.expect(assessment.kernelModeInterpretation.rawCode == OptionalU64::of(2U),
                 L"S-04 a failed query still keeps the raw value");
        s.expect(!assessment.kernelModeInterpretation.recognized,
                 L"S-04 a failed query gets no normalized interpretation");
    }

    // 未知执行状态编码。
    {
        CodeIntegrityInput input;
        input.kernelModeRaw = RawNumber("9", 9U);
        input.kernelModeOutcome = CollectionOutcome::success();
        const CodeIntegrityAssessment assessment = EvaluateCodeIntegrity(input);
        s.expect(assessment.kernelModeEnforcement == CodeIntegrityEnforcement::Unknown,
                 L"S-04 an unknown enforcement code is not interpreted");
        s.expect(assessment.kernelModeInterpretation.rawCode == OptionalU64::of(9U),
                 L"S-04 an unknown enforcement code keeps its raw value");
        s.expect(HasKey(assessment.limitationKeys, SecurityLimitationKeys::kUnknownEnumPreserved),
                 L"S-04 an unknown enum is accounted for explicitly");
    }

    // 多策略：audit 与 enforced 同时存在。
    {
        CodeIntegrityInput input;
        input.effectiveOutcome = CollectionOutcome::success();
        CodeIntegrityPolicyRecord audit;
        audit.policyId = "{11111111-1111-1111-1111-111111111111}";
        audit.friendlyName = "AuditPolicy";
        audit.enforcementRaw = RawNumber("1", 1U);
        audit.basePolicy = TriState::Yes;
        audit.sourceFieldId = "ci.effective";
        CodeIntegrityPolicyRecord enforcedA;
        enforcedA.policyId = "{22222222-2222-2222-2222-222222222222}";
        enforcedA.friendlyName = "EnforcedPolicyA";
        enforcedA.enforcementRaw = RawNumber("2", 2U);
        enforcedA.basePolicy = TriState::No;
        enforcedA.sourceFieldId = "ci.effective";
        CodeIntegrityPolicyRecord enforcedB = enforcedA;
        enforcedB.policyId = "{33333333-3333-3333-3333-333333333333}";
        enforcedB.friendlyName = "EnforcedPolicyB";
        input.effectivePolicies = {audit, enforcedA, enforcedB};
        const CodeIntegrityAssessment assessment = EvaluateCodeIntegrity(input);
        s.expect(assessment.effectivePolicyKnown,
                 L"S-04 a successful effective policy query marks the list known");
        s.expect(assessment.effectivePolicies.size() == 3U,
                 L"S-04 all three effective policies are kept");
        s.expect(assessment.auditPolicyCount() == 1U, L"S-04 the audit policy count is one");
        s.expect(assessment.enforcedPolicyCount() == 2U, L"S-04 the enforced policy count is two");
        s.expect(assessment.effectivePolicies[0].policyId == "{11111111-1111-1111-1111-111111111111}",
                 L"S-04 the policy GUID text is not rewritten");
        s.expect(assessment.effectivePolicies[0].basePolicy == TriState::Yes &&
                     assessment.effectivePolicies[1].basePolicy == TriState::No,
                 L"S-04 the base policy flag is kept per policy");
    }

    // 查不到有效策略：保持未知，且绝不拿配置策略顶替。
    {
        CodeIntegrityInput input;
        input.configuredOutcome = CollectionOutcome::success();
        CodeIntegrityPolicyRecord onDisk;
        onDisk.policyId = "{44444444-4444-4444-4444-444444444444}";
        onDisk.enforcementRaw = RawNumber("2", 2U);
        onDisk.sourceFieldId = "ci.configured";
        CodeIntegrityPolicyRecord onDiskTwo = onDisk;
        onDiskTwo.policyId = "{55555555-5555-5555-5555-555555555555}";
        input.configuredPolicies = {onDisk, onDiskTwo};
        input.effectiveOutcome = CollectionOutcome::notCollected();
        const CodeIntegrityAssessment assessment = EvaluateCodeIntegrity(input);
        s.expect(assessment.configuredPolicyKnown, L"S-04 the configured policy list is known");
        s.expect(assessment.configuredPolicies.size() == 2U,
                 L"S-04 both configured policies are kept");
        s.expect(!assessment.effectivePolicyKnown,
                 L"S-04 an unqueried effective policy list stays unknown");
        s.expect(assessment.effectivePolicies.empty(),
                 L"S-04 an unknown effective list is empty and never filled from the configured one");
        s.expect(assessment.auditPolicyCount() == 0U && assessment.enforcedPolicyCount() == 0U,
                 L"S-04 an unknown effective list yields no enforcement counts");
        s.expect(HasKey(assessment.limitationKeys, SecurityLimitationKeys::kEffectivePolicyUnknown),
                 L"S-04 an unknown effective policy list is accounted for explicitly");
    }

    // 配置策略查询失败时同样保持未知。
    {
        CodeIntegrityInput input;
        input.configuredOutcome =
            CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5U, "Access is denied.");
        CodeIntegrityPolicyRecord ghost;
        ghost.policyId = "{66666666-6666-6666-6666-666666666666}";
        input.configuredPolicies = {ghost};
        const CodeIntegrityAssessment assessment = EvaluateCodeIntegrity(input);
        s.expect(!assessment.configuredPolicyKnown,
                 L"S-04 a failed configured policy query stays unknown");
        s.expect(assessment.configuredPolicies.empty(),
                 L"S-04 a policy list from a failed query is not treated as an observation");
        s.expect(HasKey(assessment.limitationKeys, SecurityLimitationKeys::kConfiguredPolicyUnknown),
                 L"S-04 an unknown configured policy list is accounted for explicitly");
    }

    // 签名有效 != 当前策略允许加载。
    {
        ImageLoadInput input;
        input.imagePath = "C:\\Windows\\System32\\drivers\\sample.sys";
        input.signatureValid = TriState::Yes;
        input.signatureOutcome = CollectionOutcome::success();
        input.policyAllowsLoad = TriState::Yes;  // 来源"顺手"给的，但没有查询支撑
        input.policyDecisionOutcome = CollectionOutcome::notCollected();
        const ImageLoadAssessment assessment = EvaluateImageLoad(input);
        s.expect(assessment.signatureValid == TriState::Yes, L"S-04 a valid signature is adopted");
        s.expect(assessment.allowedByCurrentPolicy == TriState::Unknown,
                 L"S-04 a valid signature does not imply the current policy allows loading");
        s.expect(HasKey(assessment.limitationKeys, SecurityLimitationKeys::kPolicyDecisionUnknown),
                 L"S-04 an unknown policy decision is accounted for explicitly");
        s.expect(assessment.imagePath == "C:\\Windows\\System32\\drivers\\sample.sys",
                 L"S-04 the image path is kept verbatim");
    }

    // 签名有效但策略明确禁止：两个字段互不影响。
    {
        ImageLoadInput input;
        input.signatureValid = TriState::Yes;
        input.signatureOutcome = CollectionOutcome::success();
        input.policyAllowsLoad = TriState::No;
        input.policyDecisionOutcome = CollectionOutcome::success();
        const ImageLoadAssessment assessment = EvaluateImageLoad(input);
        s.expect(assessment.signatureValid == TriState::Yes &&
                     assessment.allowedByCurrentPolicy == TriState::No,
                 L"S-04 a valid signature and a policy denial can hold at the same time");
    }

    // 签名查询失败：签名结论回落未知，不影响策略结论。
    {
        ImageLoadInput input;
        input.signatureValid = TriState::Yes;
        input.signatureOutcome = CollectionOutcome::failure(CollectionStatus::Error, "WIN32", 87U,
                                                            "The parameter is incorrect.");
        input.policyAllowsLoad = TriState::Yes;
        input.policyDecisionOutcome = CollectionOutcome::success();
        const ImageLoadAssessment assessment = EvaluateImageLoad(input);
        s.expect(assessment.signatureValid == TriState::Unknown,
                 L"S-04 a failed signature query falls back to Unknown");
        s.expect(assessment.allowedByCurrentPolicy == TriState::Yes,
                 L"S-04 a failed signature query does not drag down the policy decision");
        s.expect(assessment.signatureOutcome.nativeCode == OptionalU64::of(87U),
                 L"S-04 the signature query native code is kept");
    }
}

// ---------------------------------------------------------------------------
// S-06：约束键词表闸。SecurityState.h 把这张表宣传成"防止修复建议被塞回本层"的
// 防回归装置，那就得逐词钉死 —— 表里少一个词，闸就悄悄窄一格。
// 下面每条都手写成字面量而不是循环遍历同一张表：循环会让"表被改小"这件事
// 自动跟着变小，等于没测。
// ---------------------------------------------------------------------------
void TestConstraintKeyWordGate(KswordTests::Suite& s) {
    // --- 13 个动作词逐个都要拦住 ---
    s.expect(!IsStatementOnlyConstraintKey("kvm.action.disable.hvci"),
             L"S-06 word gate rejects disable");
    s.expect(!IsStatementOnlyConstraintKey("kvm.action.turnOff.vbs"),
             L"S-06 word gate rejects turnoff");
    s.expect(!IsStatementOnlyConstraintKey("kvm.action.switch-off.hvci"),
             L"S-06 word gate rejects switchoff");
    s.expect(!IsStatementOnlyConstraintKey("kvm.action.shutdown.smm"),
             L"S-06 word gate rejects shutdown");
    s.expect(!IsStatementOnlyConstraintKey("kvm.action.uninstall.driver"),
             L"S-06 word gate rejects uninstall");
    s.expect(!IsStatementOnlyConstraintKey("kvm.action.bypass.hvci"),
             L"S-06 word gate rejects bypass");
    s.expect(!IsStatementOnlyConstraintKey("kvm.remediation.hvci"),
             L"S-06 word gate rejects the remediat stem");
    s.expect(!IsStatementOnlyConstraintKey("kvm.recommend.reboot"),
             L"S-06 word gate rejects recommend");
    s.expect(!IsStatementOnlyConstraintKey("kvm.suggestion.hvci"),
             L"S-06 word gate rejects suggest");
    s.expect(!IsStatementOnlyConstraintKey("kvm.workaround.forHvci"),
             L"S-06 word gate rejects workaround");
    s.expect(!IsStatementOnlyConstraintKey("kvm.how-to-fix.hvci"),
             L"S-06 word gate rejects howtofix");
    s.expect(!IsStatementOnlyConstraintKey("kvm.please-turn.off.hvci"),
             L"S-06 word gate rejects pleaseturn");
    s.expect(!IsStatementOnlyConstraintKey("kvm.you-should.rebootFirst"),
             L"S-06 word gate rejects youshould");

    // 大小写与分隔符变体照样拦住。
    s.expect(!IsStatementOnlyConstraintKey("kvm.fix.disableHvci"),
             L"S-06 word gate rejects an imperative glued to its object");
    s.expect(!IsStatementOnlyConstraintKey("kvm.turn-off.memoryIntegrity"),
             L"S-06 word gate rejects a hyphen split action phrase");
    s.expect(!IsStatementOnlyConstraintKey("kvm.Turn_Off.protection"),
             L"S-06 word gate rejects case and underscore variants");
    s.expect(!IsStatementOnlyConstraintKey("dse.fix.disableMemoryIntegrityAndReboot"),
             L"S-06 word gate rejects the full disable-and-reboot advice key");
    s.expect(!IsStatementOnlyConstraintKey(""), L"S-06 an empty key is not a statement");

    // 时态豁免只给动作动词的 -ed 过去分词。动名词还在描述动作，劝说词变成任何形态
    // 都还是建议 —— 这三条是"豁免不能宽到把建议放回来"的门闩。
    s.expect(!IsStatementOnlyConstraintKey("kvm.fix.byDisablingHvci"),
             L"S-06 a gerund of an action verb is still an action, not a state");
    s.expect(!IsStatementOnlyConstraintKey("kvm.fix.byTurningOffMemoryIntegrity"),
             L"S-06 an inflected two word action phrase is still an action");
    s.expect(!IsStatementOnlyConstraintKey("kvm.hint.suggestedFix"),
             L"S-06 the past participle of an advice verb is still advice");
    s.expect(!IsStatementOnlyConstraintKey("kvm.hint.recommendedReboot"),
             L"S-06 a recommended action is advice regardless of its tense");

    // --- 近似的**陈述**键必须放行。这些是子串匹配下的假阳性：键里出现动作词的
    // 字母序列，但整句在陈述现状。被误拦时它们一条也进不了 accepted，
    // 于是 ExplainKswordCapability 会顺着 fall-through 把能力放行 —— 闸变成洞。 ---
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.hvci.running"),
             L"S-06 a statement style constraint key is accepted");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.vendor.amd"),
             L"S-06 a vendor constraint key is accepted");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.dse.isDisabledByPolicy"),
             L"S-06 isDisabledByPolicy is a statement, not an instruction to disable");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.hvci.notDisabled"),
             L"S-06 notDisabled is a statement, not an instruction to disable");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.hvci.disabled"),
             L"S-06 the past participle disabled states a current state");
    s.expect(IsStatementOnlyConstraintKey("vt.constraint.bypassDetected"),
             L"S-06 bypassDetected states an observation, it does not ask for a bypass");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.driver.uninstalled"),
             L"S-06 uninstalled states a driver state, it does not ask for an uninstall");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.smm.shutdownPending"),
             L"S-06 shutdownPending states a pending state, it does not ask for a shutdown");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.vbs.turnedOff"),
             L"S-06 turnedOff states a configuration, it is not the turn-off action phrase");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.profile.absent"),
             L"S-06 a profile absence statement is accepted");
}

// ---------------------------------------------------------------------------
// S-06：KSword 能力解释
// ---------------------------------------------------------------------------
void TestCapabilityExplanation(KswordTests::Suite& s) {
    // 词表闸单测。
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.hvci.running"),
             L"S-06 a statement style constraint key is accepted");
    s.expect(IsStatementOnlyConstraintKey("kvm.constraint.vendor.amd"),
             L"S-06 a vendor constraint key is accepted");
    s.expect(!IsStatementOnlyConstraintKey("kvm.fix.disableHvci"),
             L"S-06 a key containing disable is rejected");
    s.expect(!IsStatementOnlyConstraintKey("kvm.turn-off.memoryIntegrity"),
             L"S-06 a key containing turn-off is rejected");
    s.expect(!IsStatementOnlyConstraintKey("kvm.Turn_Off.protection"),
             L"S-06 case and separator variants are rejected too");
    s.expect(!IsStatementOnlyConstraintKey("kvm.recommend.reboot"),
             L"S-06 a key containing recommend is rejected");
    s.expect(!IsStatementOnlyConstraintKey("kvm.suggestion.hvci"),
             L"S-06 a key containing suggest is rejected");
    s.expect(!IsStatementOnlyConstraintKey(""), L"S-06 an empty key is not a statement");

    SecurityStateInput stateInput;
    stateInput.currentWindow = CurrentWindow();
    SecurityField vendor = MakeField("cpu.vendor", "cpuid", kBootCurrent);
    vendor.raw = RawText("AuthenticAMD");
    SecurityField driver = MakeField("driver.loaded", "scm", kBootCurrent);
    driver.raw = RawText("False");
    SecurityField profile = MakeField("dyndata.profile", "local", kBootCurrent);
    profile.raw = RawText("missing:26300.9022");
    SecurityField hvci = MakeField("hvci.running", "wmi", kBootCurrent);
    hvci.raw = RawNumber("2", 2U);
    SecurityField broken = MakeField("query.broken", "wmi", kBootCurrent);
    broken.outcome = CollectionOutcome::failure(CollectionStatus::Timeout, "WIN32", 1460U, "timeout");
    stateInput.fields = {vendor, driver, profile, hvci, broken};
    const SecurityStateReport report = EvaluateSecurityState(stateInput);

    // 四类约束分别表示。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        KswordCapabilityConstraint vendorConstraint;
        vendorConstraint.kind = CapabilityConstraintKind::VendorUnsupported;
        vendorConstraint.constraintKey = "kvm.constraint.vendor.amdBackendAbsent";
        vendorConstraint.sourceFieldId = "cpu.vendor";
        vendorConstraint.observed = RawText("AuthenticAMD");
        KswordCapabilityConstraint driverConstraint;
        driverConstraint.kind = CapabilityConstraintKind::DriverMissing;
        driverConstraint.constraintKey = "kvm.constraint.driver.notLoaded";
        driverConstraint.sourceFieldId = "driver.loaded";
        driverConstraint.observed = RawText("False");
        KswordCapabilityConstraint profileConstraint;
        profileConstraint.kind = CapabilityConstraintKind::ProfileMissing;
        profileConstraint.constraintKey = "kvm.constraint.profile.absent";
        profileConstraint.sourceFieldId = "dyndata.profile";
        profileConstraint.observed = RawText("missing:26300.9022");
        KswordCapabilityConstraint securityConstraint;
        securityConstraint.kind = CapabilityConstraintKind::SecurityConfiguration;
        securityConstraint.constraintKey = "kvm.constraint.hvci.running";
        securityConstraint.sourceFieldId = "hvci.running";
        securityConstraint.observed = RawNumber("2", 2U);
        input.constraints = {vendorConstraint, driverConstraint, profileConstraint,
                             securityConstraint};

        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.constraints.size() == 4U, L"S-06 all four constraints are kept");
        s.expect(explanation.constraints[0].kind == CapabilityConstraintKind::VendorUnsupported &&
                     explanation.constraints[1].kind == CapabilityConstraintKind::DriverMissing &&
                     explanation.constraints[2].kind == CapabilityConstraintKind::ProfileMissing &&
                     explanation.constraints[3].kind == CapabilityConstraintKind::SecurityConfiguration,
                 L"S-06 vendor, driver, profile and security config are separate kinds");
        s.expect(explanation.constraints[0].accepted && explanation.constraints[1].accepted &&
                     explanation.constraints[2].accepted && explanation.constraints[3].accepted,
                 L"S-06 statement style constraints with a backing field are accepted");
        s.expect(explanation.constraints[3].sourceFieldId == "hvci.running" &&
                     explanation.constraints[3].observed.numeric == OptionalU64::of(2U),
                 L"S-06 each constraint points at its source field and observed value");
        s.expect(explanation.available == TriState::No,
                 L"S-06 a capability with constraints is unavailable");
        s.expect(!explanation.mayStart(), L"S-06 an unavailable capability is not started");
        s.expect(explanation.rejectedConstraintKeys.empty(),
                 L"S-06 statement style keys are not rejected");
    }

    // 建议型键被拒收，并且不因此产生"不可用"结论。
    {
        KswordCapabilityInput input;
        input.capabilityId = "dse.disable";
        KswordCapabilityConstraint advice;
        advice.kind = CapabilityConstraintKind::SecurityConfiguration;
        advice.constraintKey = "dse.fix.disableMemoryIntegrityAndReboot";
        advice.sourceFieldId = "hvci.running";
        advice.observed = RawNumber("2", 2U);
        input.constraints = {advice};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.constraints.size() == 1U && !explanation.constraints[0].accepted,
                 L"S-06 an advice style constraint key is not accepted");
        s.expect(explanation.rejectedConstraintKeys.size() == 1U &&
                     explanation.rejectedConstraintKeys[0] == "dse.fix.disableMemoryIntegrityAndReboot",
                 L"S-06 the rejected key is listed verbatim so it can be fixed");
        s.expect(HasKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintNonStatement),
                 L"S-06 an advice style key is accounted for explicitly");
        s.expect(explanation.available == TriState::Unknown,
                 L"S-06 a rejected constraint alone leaves availability Unknown");
        s.expect(!explanation.mayStart(), L"S-06 Unknown availability is not started either");
    }

    // 约束指向没采到的字段：不算数。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.msr.policy";
        KswordCapabilityConstraint constraint;
        constraint.kind = CapabilityConstraintKind::QueryUnavailable;
        constraint.constraintKey = "kvm.constraint.query.timeout";
        constraint.sourceFieldId = "query.broken";
        input.constraints = {constraint};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(!explanation.constraints[0].backed,
                 L"S-06 a constraint over an uncollected field is marked unbacked");
        s.expect(explanation.available == TriState::Unknown,
                 L"S-06 an unbacked constraint does not declare unavailability");
        s.expect(HasKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintUnbacked),
                 L"S-06 an unbacked constraint is accounted for explicitly");
    }

    // 约束指向不存在的字段。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        KswordCapabilityConstraint constraint;
        constraint.kind = CapabilityConstraintKind::HardwareUnsupported;
        constraint.constraintKey = "kvm.constraint.hardware.absent";
        constraint.sourceFieldId = "does.not.exist";
        input.constraints = {constraint};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(!explanation.constraints[0].accepted,
                 L"S-06 a constraint naming a nonexistent field is not accepted");
        s.expect(explanation.available == TriState::Unknown,
                 L"S-06 availability stays Unknown for a nonexistent field");
    }

    // 明确观测到可用：允许启动。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        input.observedAvailable = TriState::Yes;
        input.availabilityOutcome = CollectionOutcome::success();
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.available == TriState::Yes,
                 L"S-06 an observed available capability with no constraint is available");
        s.expect(explanation.mayStart(), L"S-06 only an available capability may start");
    }

    // 没约束也没观测：未知，不放行。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.available == TriState::Unknown,
                 L"S-06 with no evidence the availability is Unknown");
        s.expect(!explanation.mayStart(), L"S-06 Unknown does not mean available");
    }

    // 约束与"可用"观测矛盾：取受限的一侧并记账。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        input.observedAvailable = TriState::Yes;
        input.availabilityOutcome = CollectionOutcome::success();
        KswordCapabilityConstraint constraint;
        constraint.kind = CapabilityConstraintKind::SecurityConfiguration;
        constraint.constraintKey = "kvm.constraint.hvci.running";
        constraint.sourceFieldId = "hvci.running";
        input.constraints = {constraint};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.available == TriState::No,
                 L"S-06 a constraint contradicting an available observation takes the restrictive side");
        s.expect(HasKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintConflict),
                 L"S-06 a contradictory availability is accounted for explicitly");
    }

    // --- 约束在场却一条都判不了 + 来源自称"可用"。这是"从没采到推出正常"在 S-06 的
    //     落点：拦路的证据自己没采到，就不能让 observedAvailable 顺着 fall-through
    //     把能力放行。三种判不了的成因各测一次。 ---

    // (a) 约束指向一个超时没采到的字段。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        input.observedAvailable = TriState::Yes;
        input.availabilityOutcome = CollectionOutcome::success();
        KswordCapabilityConstraint constraint;
        constraint.kind = CapabilityConstraintKind::SecurityConfiguration;
        constraint.constraintKey = "kvm.constraint.hvci.running";
        constraint.sourceFieldId = "query.broken";
        input.constraints = {constraint};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(!explanation.constraints[0].accepted,
                 L"S-06 a constraint over a timed out field is not accepted");
        s.expect(explanation.available == TriState::Unknown,
                 L"S-06 an unbacked constraint withholds availability instead of letting the source say Yes");
        s.expect(!explanation.mayStart(),
                 L"S-06 a capability whose blocking evidence was never collected is not started");
        s.expect(HasKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintIndeterminate),
                 L"S-06 withholding availability over an unjudgeable constraint is accounted for");
        s.expect(HasKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintUnbacked),
                 L"S-06 the unbacked constraint itself is still accounted for");
    }

    // (b) 约束键被词表闸拒收。拒收的是键，不是约束存在这件事。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        input.observedAvailable = TriState::Yes;
        input.availabilityOutcome = CollectionOutcome::success();
        KswordCapabilityConstraint advice;
        advice.kind = CapabilityConstraintKind::SecurityConfiguration;
        advice.constraintKey = "dse.fix.disableMemoryIntegrityAndReboot";
        advice.sourceFieldId = "hvci.running";
        advice.observed = RawNumber("2", 2U);
        input.constraints = {advice};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.rejectedConstraintKeys.size() == 1U,
                 L"S-06 the advice key is still rejected");
        s.expect(explanation.available == TriState::Unknown,
                 L"S-06 a rejected key does not let the source declare the capability available");
        s.expect(!explanation.mayStart(),
                 L"S-06 a capability whose only constraint key was rejected is not started");
        s.expect(HasKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintIndeterminate),
                 L"S-06 the withheld availability is accounted for on the rejected key path too");
    }

    // (c) 约束指向根本不存在的字段。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        input.observedAvailable = TriState::Yes;
        input.availabilityOutcome = CollectionOutcome::success();
        KswordCapabilityConstraint constraint;
        constraint.kind = CapabilityConstraintKind::HardwareUnsupported;
        constraint.constraintKey = "kvm.constraint.hardware.absent";
        constraint.sourceFieldId = "does.not.exist";
        input.constraints = {constraint};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.available == TriState::Unknown,
                 L"S-06 a constraint naming a nonexistent field withholds availability");
        s.expect(!explanation.mayStart(),
                 L"S-06 a constraint naming a nonexistent field does not permit a start");
    }

    // (d) 反向：来源明确说"不可用"时，判不了的约束不把这条负面证据抹成 Unknown。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.ept.view";
        input.observedAvailable = TriState::No;
        input.availabilityOutcome = CollectionOutcome::success();
        KswordCapabilityConstraint constraint;
        constraint.kind = CapabilityConstraintKind::QueryUnavailable;
        constraint.constraintKey = "kvm.constraint.query.timeout";
        constraint.sourceFieldId = "query.broken";
        input.constraints = {constraint};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.available == TriState::No,
                 L"S-06 an observed unavailability survives an unjudgeable constraint");
        s.expect(!explanation.mayStart(), L"S-06 an observed unavailability never starts");
    }

    // --- 词表闸的假阳性会变成放行洞：下面三个键都是陈述，必须能被采纳，
    //     从而把自称"可用"的能力拦住。子串匹配下它们全部被拒收，
    //     available 会落成 Yes 且 mayStart()=1。 ---
    {
        const char* const statementKeys[] = {
            "kvm.constraint.dse.isDisabledByPolicy",
            "kvm.constraint.hvci.notDisabled",
            "kvm.constraint.smm.shutdownPending",
        };
        const wchar_t* const labels[] = {
            L"S-06 isDisabledByPolicy is accepted and blocks a capability claiming to be available",
            L"S-06 notDisabled is accepted and blocks a capability claiming to be available",
            L"S-06 shutdownPending is accepted and blocks a capability claiming to be available",
        };
        for (std::size_t i = 0; i < 3U; ++i) {
            KswordCapabilityInput input;
            input.capabilityId = "kvm.ept.view";
            input.observedAvailable = TriState::Yes;
            input.availabilityOutcome = CollectionOutcome::success();
            KswordCapabilityConstraint constraint;
            constraint.kind = CapabilityConstraintKind::SecurityConfiguration;
            constraint.constraintKey = statementKeys[i];
            constraint.sourceFieldId = "hvci.running";
            constraint.observed = RawNumber("2", 2U);
            input.constraints = {constraint};
            const KswordCapabilityExplanation explanation =
                ExplainKswordCapability(input, report.fields);
            s.expect(explanation.constraints.size() == 1U && explanation.constraints[0].accepted &&
                         explanation.rejectedConstraintKeys.empty() &&
                         explanation.available == TriState::No && !explanation.mayStart(),
                     labels[i]);
        }
    }

    // S-06 要求"权限不足"能单独表达出来，而不是混进 QueryUnavailable。
    {
        KswordCapabilityInput input;
        input.capabilityId = "kvm.msr.policy";
        KswordCapabilityConstraint constraint;
        constraint.kind = CapabilityConstraintKind::PrivilegeInsufficient;
        constraint.constraintKey = "kvm.constraint.privilege.notElevated";
        constraint.sourceFieldId = "driver.loaded";
        constraint.observed = RawText("False");
        input.constraints = {constraint};
        const KswordCapabilityExplanation explanation = ExplainKswordCapability(input, report.fields);
        s.expect(explanation.constraints.size() == 1U &&
                     explanation.constraints[0].kind ==
                         CapabilityConstraintKind::PrivilegeInsufficient,
                 L"S-06 PrivilegeInsufficient survives as its own constraint kind");
        s.expect(explanation.constraints[0].accepted && explanation.available == TriState::No,
                 L"S-06 a backed privilege constraint makes the capability unavailable");
        s.expect(!explanation.mayStart(),
                 L"S-06 a capability blocked by insufficient privilege is not started");
    }
}

// ---------------------------------------------------------------------------
// S-07：按字段的权限降级（可读字段仍可读）
// ---------------------------------------------------------------------------
void TestPrivilegeDegradation(KswordTests::Suite& s) {
    SecurityStateInput input;
    input.currentWindow = CurrentWindow();
    input.privilege.administrator = TriState::No;
    input.privilege.kswordDriverLoaded = TriState::No;

    SecurityField publicField = MakeField("vbs.status", "wmi", kBootCurrent);
    publicField.raw = RawNumber("2", 2U);
    publicField.access = AccessRequirement::None;

    SecurityField adminField = MakeField("ci.policy", "reg", kBootCurrent);
    adminField.outcome = CollectionOutcome::notCollected();
    adminField.access = AccessRequirement::Administrator;

    SecurityField driverField = MakeField("r0.dyndata", "r0", kBootCurrent);
    driverField.outcome = CollectionOutcome::notCollected();
    driverField.access = AccessRequirement::KswordDriver;

    input.fields = {publicField, adminField, driverField};
    input.claims = {
        MakeClaim(SecurityCapabilityId::VirtualizationBasedSecurity, SecurityDimension::Running,
                  TriState::Yes, "vbs.status"),
        MakeClaim(SecurityCapabilityId::KernelModeCodeIntegrityPolicy, SecurityDimension::Configured,
                  TriState::Yes, "ci.policy"),
        MakeClaim(SecurityCapabilityId::TestSigning, SecurityDimension::Running, TriState::No,
                  "r0.dyndata"),
    };

    const SecurityStateReport report = EvaluateSecurityState(input);
    s.expect(report.fields.size() == 3U, L"S-07 without administrator the page is not blanked out");
    s.expect(report.readableFieldCount == 1U, L"S-07 the readable field is still readable");
    s.expect(report.blockedFieldCount == 2U, L"S-07 the blocked field count is exact");

    const CapabilityState* vbs =
        report.findCapability(SecurityCapabilityId::VirtualizationBasedSecurity);
    s.expect(vbs != nullptr && vbs->running.value == TriState::Yes,
             L"S-07 a capability readable without administrator still reports its state");
    s.expect(vbs != nullptr && !vbs->requiresAdministrator,
             L"S-07 a capability that needs no administrator is not mislabelled");

    const CapabilityState* ci =
        report.findCapability(SecurityCapabilityId::KernelModeCodeIntegrityPolicy);
    s.expect(ci != nullptr && ci->requiresAdministrator,
             L"S-07 a capability needing administrator is labelled");
    s.expect(ci != nullptr && ci->configured.value == TriState::Unknown,
             L"S-07 a field that could not be read produces no definite value");
    s.expect(ci != nullptr && ci->blockedFieldCount == 1U,
             L"S-07 the capability counts its blocked fields");

    const CapabilityState* testSigning = report.findCapability(SecurityCapabilityId::TestSigning);
    s.expect(testSigning != nullptr && testSigning->requiresKswordDriver,
             L"S-07 a capability needing the driver is labelled separately");
    s.expect(testSigning != nullptr && !testSigning->requiresAdministrator,
             L"S-07 a driver requirement is not folded into an administrator requirement");

    // 管理员在场时同样的输入不再报权限降级。
    {
        SecurityStateInput elevated = input;
        elevated.privilege.administrator = TriState::Yes;
        elevated.fields[1].outcome = CollectionOutcome::success();
        elevated.fields[1].raw = RawNumber("1", 1U);
        const SecurityStateReport elevatedReport = EvaluateSecurityState(elevated);
        s.expect(!elevatedReport.hasLimitation(SecurityLimitationKeys::kPrivilegeDegraded),
                 L"S-07 with administrator and a successful read no privilege degradation is reported");
        s.expect(elevatedReport.readableFieldCount == 2U,
                 L"S-07 elevation makes one more field readable");
        const CapabilityState* elevatedCi =
            elevatedReport.findCapability(SecurityCapabilityId::KernelModeCodeIntegrityPolicy);
        s.expect(elevatedCi != nullptr && elevatedCi->configured.value == TriState::Yes,
                 L"S-07 after elevation that field yields a definite value");
        s.expect(elevatedReport.hasLimitation(SecurityLimitationKeys::kDriverDegraded),
                 L"S-07 the driver degradation is still reported while the driver is absent");
    }
}

// ---------------------------------------------------------------------------
// S-08：实测配置清单
// ---------------------------------------------------------------------------
void TestSupportClaim(KswordTests::Suite& s) {
    // 空清单 = BLOCKED。
    {
        const SupportClaim claim = EvaluateSupportClaim({});
        s.expect(claim.status == SupportClaimStatus::Blocked,
                 L"S-08 with no verified configuration the claim stays BLOCKED");
        s.expect(!claim.baselineConfigurationVerified && !claim.vbsConfigurationVerified,
                 L"S-08 an empty inventory verifies nothing");
        s.expect(HasKey(claim.limitationKeys, SecurityLimitationKeys::kSupportClaimBlocked),
                 L"S-08 BLOCKED is accounted for explicitly");
    }

    VerifiedConfiguration baseline;
    baseline.configurationId = "baseline";
    baseline.osBuildRaw = "10.0.26300.9022";
    baseline.vbsRunning = TriState::No;
    baseline.hvciRunning = TriState::No;
    baseline.kswordDriverLoaded = TriState::Yes;
    baseline.evidenceFieldId = "env.baseline";

    VerifiedConfiguration hardened;
    hardened.configurationId = "vbs-hvci";
    hardened.osBuildRaw = "10.0.26100.1742";
    hardened.vbsRunning = TriState::Yes;
    hardened.hvciRunning = TriState::Yes;
    hardened.kswordDriverLoaded = TriState::No;
    hardened.evidenceFieldId = "env.hardened";

    // 只有一套：PartiallyVerified。
    {
        const SupportClaim claim = EvaluateSupportClaim({baseline});
        s.expect(claim.status == SupportClaimStatus::PartiallyVerified,
                 L"S-08 one configuration only is partially verified");
        s.expect(claim.baselineConfigurationVerified && !claim.vbsConfigurationVerified,
                 L"S-08 only the configuration actually checked counts");
        s.expect(HasKey(claim.limitationKeys, SecurityLimitationKeys::kSupportClaimIncomplete),
                 L"S-08 partial verification is accounted for explicitly");
    }

    // 两套齐全：Verified。
    {
        const SupportClaim claim = EvaluateSupportClaim({baseline, hardened});
        s.expect(claim.status == SupportClaimStatus::Verified,
                 L"S-08 both configurations present makes the claim verified");
        s.expect(claim.acceptedConfigurationIds.size() == 2U, L"S-08 both configurations are accepted");
        s.expect(claim.rejectedConfigurationIds.empty(), L"S-08 no configuration is rejected");
    }

    // 缺 build：不算数。
    {
        VerifiedConfiguration noBuild = baseline;
        noBuild.osBuildRaw.clear();
        const SupportClaim claim = EvaluateSupportClaim({noBuild, hardened});
        s.expect(claim.status == SupportClaimStatus::PartiallyVerified,
                 L"S-08 a configuration without a recorded build does not count");
        s.expect(claim.rejectedConfigurationIds.size() == 1U,
                 L"S-08 the configuration missing a build is rejected");
        s.expect(!claim.baselineConfigurationVerified,
                 L"S-08 without a build the baseline is not verified");
    }

    // 缺驱动加载状态：不算数。
    {
        VerifiedConfiguration noDriver = baseline;
        noDriver.kswordDriverLoaded = TriState::Unknown;
        const SupportClaim claim = EvaluateSupportClaim({noDriver, hardened});
        s.expect(!claim.baselineConfigurationVerified,
                 L"S-08 a configuration without a recorded driver state does not count");
    }

    // VBS 套但 HVCI 状态未知：不算数。
    {
        VerifiedConfiguration vague = hardened;
        vague.hvciRunning = TriState::Unknown;
        const SupportClaim claim = EvaluateSupportClaim({baseline, vague});
        s.expect(!claim.vbsConfigurationVerified,
                 L"S-08 an unknown HVCI state disqualifies the VBS configuration");
        s.expect(claim.status == SupportClaimStatus::PartiallyVerified,
                 L"S-08 only the baseline left means partially verified");
        s.expect(claim.acceptedConfigurationIds.size() == 1U,
                 L"S-08 the vague configuration is not listed as accepted");
    }
}

// ---------------------------------------------------------------------------
// S-01：能力级第四维的汇总口径。摘要**只能**由真实返回过的状态构成 ——
// 合成一个谁都没返回过的 Error 会把"要管理员"抹平成"坏了"。
// ---------------------------------------------------------------------------
void TestCapabilityOutcomeSummary(KswordTests::Suite& s) {
    // 期望值全部手算：两条支撑都失败，AccessDenied 是其中严重度最高的一条，
    // 它的 WIN32 5 / "Access is denied." 原样上浮。
    const auto buildTwoFieldCapability = [](const SecurityField& a, const SecurityField& b) {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        input.fields = {a, b};
        input.claims = {
            MakeClaim(SecurityCapabilityId::CredentialGuard, SecurityDimension::Configured,
                      TriState::No, a.fieldId.c_str()),
            MakeClaim(SecurityCapabilityId::CredentialGuard, SecurityDimension::Running,
                      TriState::No, b.fieldId.c_str()),
        };
        return EvaluateSecurityState(input);
    };

    SecurityField denied = MakeField("cg.wmi", "wmi", kBootCurrent);
    denied.outcome =
        CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5U, "Access is denied.");
    SecurityField unsupported = MakeField("cg.reg", "registry", kBootCurrent);
    unsupported.outcome = CollectionOutcome::failure(CollectionStatus::Unsupported, "HRESULT",
                                                     0x80041010ULL, "Invalid class");

    // (a) AccessDenied + Unsupported。
    {
        const SecurityStateReport report = buildTwoFieldCapability(denied, unsupported);
        const CapabilityState* cg = report.findCapability(SecurityCapabilityId::CredentialGuard);
        s.expect(cg != nullptr && cg->queryOutcome.status != CollectionStatus::Success,
                 L"S-01 a capability whose every query was denied never summarises as Success");
        s.expect(cg != nullptr && cg->queryOutcome.status != CollectionStatus::Partial,
                 L"S-01 a capability with no observation at all never summarises as Partial");
        s.expect(cg != nullptr && cg->queryOutcome.status != CollectionStatus::Error,
                 L"S-01 the summary never invents an Error status no source returned");
        s.expect(cg != nullptr && cg->queryOutcome.status == CollectionStatus::AccessDenied,
                 L"S-01 a privilege failure stays recognisable at the capability level");
        s.expect(cg != nullptr && cg->queryOutcome.nativeCode == OptionalU64::of(5U) &&
                     cg->queryOutcome.nativeCodeDomain == "WIN32",
                 L"S-01 the summarised failure keeps its own native code and domain");
        s.expect(cg != nullptr && cg->queryOutcome.message == "Access is denied.",
                 L"S-01 the summarised failure keeps the source message");
        s.expect(report.hasLimitation(SecurityLimitationKeys::kOutcomeMixedFailures),
                 L"S-01 summarising away the other failure statuses is accounted for explicitly");
        s.expect(cg != nullptr && cg->configured.value == TriState::Unknown &&
                     cg->running.value == TriState::Unknown,
                 L"S-01 CredentialGuard stays Unknown when every supporting query failed");
        s.expect(cg != nullptr && !cg->anyBackedObservation,
                 L"S-01 a capability whose fields all failed carries no backed observation");
    }

    // (a') 换个顺序结论必须一样 —— 摘要不是"第一条说了算"。
    {
        const SecurityStateReport report = buildTwoFieldCapability(unsupported, denied);
        const CapabilityState* cg = report.findCapability(SecurityCapabilityId::CredentialGuard);
        s.expect(cg != nullptr && cg->queryOutcome.status == CollectionStatus::AccessDenied,
                 L"S-01 the summarised failure does not depend on which field came first");
        s.expect(cg != nullptr && cg->queryOutcome.nativeCode == OptionalU64::of(5U),
                 L"S-01 the summarised native code does not depend on field order either");
    }

    // (b) AccessDenied + Timeout。
    {
        SecurityField timeout = MakeField("cg.reg", "registry", kBootCurrent);
        timeout.outcome = CollectionOutcome::failure(CollectionStatus::Timeout, "WIN32", 1460U,
                                                     "The operation timed out.");
        const SecurityStateReport report = buildTwoFieldCapability(denied, timeout);
        const CapabilityState* cg = report.findCapability(SecurityCapabilityId::CredentialGuard);
        s.expect(cg != nullptr && cg->queryOutcome.status == CollectionStatus::AccessDenied,
                 L"S-01 a timeout alongside a denial does not hide the denial");
        s.expect(cg != nullptr && cg->queryOutcome.nativeCode == OptionalU64::of(5U),
                 L"S-01 the denial native code survives the timeout");
    }

    // (c) 两条同为 AccessDenied 但错误码不同：状态保留，代表码留空 ——
    //     从两个真实错误码里挑一个当"代表"同样是骗人。
    {
        SecurityField deniedOther = MakeField("cg.reg", "registry", kBootCurrent);
        deniedOther.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32",
                                                         1314U, "A required privilege is not held.");
        const SecurityStateReport report = buildTwoFieldCapability(denied, deniedOther);
        const CapabilityState* cg = report.findCapability(SecurityCapabilityId::CredentialGuard);
        s.expect(cg != nullptr && cg->queryOutcome.status == CollectionStatus::AccessDenied,
                 L"S-01 two denials with different codes still summarise as AccessDenied");
        s.expect(cg != nullptr && !cg->queryOutcome.nativeCode.present,
                 L"S-01 two different native codes do not get a made up representative code");
        s.expect(!report.hasLimitation(SecurityLimitationKeys::kOutcomeMixedFailures),
                 L"S-01 same-status failures are not reported as mixed failure statuses");
    }

    // (d) Partial 不得被 Success 吞掉：一条覆盖不全的采集会让整个能力覆盖不全。
    {
        SecurityField full = MakeField("cg.wmi", "wmi", kBootCurrent);
        full.raw = RawNumber("1", 1U);
        SecurityField partial = MakeField("cg.reg", "registry", kBootCurrent);
        partial.outcome.status = CollectionStatus::Partial;
        const SecurityStateReport report = buildTwoFieldCapability(full, partial);
        const CapabilityState* cg = report.findCapability(SecurityCapabilityId::CredentialGuard);
        s.expect(cg != nullptr && cg->queryOutcome.status == CollectionStatus::Partial,
                 L"S-01 one partial query makes the whole capability outcome Partial");
        s.expect(cg != nullptr && cg->queryOutcome.status != CollectionStatus::Success,
                 L"S-01 a partial query is never rounded up to Success");
    }

    // (e) NotCollected 是"没跑"，不是"跑失败了"。两者在账目里必须分开。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField never = MakeField("cg.never", "wmi", kBootCurrent);
        never.outcome = CollectionOutcome::notCollected();
        input.fields = {never};
        input.claims = {MakeClaim(SecurityCapabilityId::CredentialGuard, SecurityDimension::Running,
                                  TriState::Yes, "cg.never")};
        const SecurityStateReport report = EvaluateSecurityState(input);
        s.expect(report.envelope.coverage.succeeded == 0U,
                 L"S-01 a field that never ran covers nothing");
        s.expect(report.envelope.coverage.failed == 0U,
                 L"S-01 a field that never ran is not counted as a failed query");
        s.expect(report.envelope.coverage.skipped == 1U,
                 L"S-01 a field that never ran is accounted as skipped");

        SecurityStateInput failedInput = input;
        failedInput.fields[0].outcome = CollectionOutcome::failure(CollectionStatus::Error,
                                                                   "NTSTATUS", 0xC0000001ULL,
                                                                   "STATUS_UNSUCCESSFUL");
        const SecurityStateReport failedReport = EvaluateSecurityState(failedInput);
        s.expect(failedReport.envelope.coverage.failed == 1U &&
                     failedReport.envelope.coverage.skipped == 0U,
                 L"S-01 a query that ran and failed is accounted as failed, not as skipped");
    }
}

// ---------------------------------------------------------------------------
// S-02：重复 fieldId 的引用歧义。同一份输入换个顺序不能得出不同结论。
// ---------------------------------------------------------------------------
void TestDuplicateFieldResolution(KswordTests::Suite& s) {
    SecurityField bad = MakeField("dg.state", "wmi", kBootCurrent);
    bad.outcome =
        CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5U, "Access is denied.");
    SecurityField good = MakeField("dg.state", "registry", kBootCurrent);
    good.raw = RawNumber("2", 2U);

    const auto evaluate = [&bad, &good](bool badFirst) {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        if (badFirst) {
            input.fields = {bad, good};
        } else {
            input.fields = {good, bad};
        }
        input.claims = {MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                                  SecurityDimension::Running, TriState::Yes, "dg.state")};
        return EvaluateSecurityState(input);
    };

    const SecurityStateReport badFirst = evaluate(true);
    const SecurityStateReport goodFirst = evaluate(false);
    const CapabilityState* a =
        badFirst.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
    const CapabilityState* b =
        goodFirst.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);

    s.expect(a != nullptr && b != nullptr && a->running.value == b->running.value,
             L"S-02 a duplicate field id yields the same verdict whichever copy comes first");
    s.expect(a != nullptr && a->running.value == TriState::Unknown,
             L"S-02 a claim over an ambiguous field id produces no value");
    s.expect(b != nullptr && b->running.value == TriState::Unknown,
             L"S-02 the reversed order does not resolve the ambiguity into a definite value");
    s.expect(a != nullptr && a->running.claims.size() == 1U && !a->running.claims[0].backed,
             L"S-02 a claim over an ambiguous field id is treated as unbacked");
    s.expect(a != nullptr && a->running.claims[0].sourceGroup.empty(),
             L"S-02 an ambiguous claim is not attributed to a collector that may not have supplied it");
    s.expect(badFirst.hasLimitation(SecurityLimitationKeys::kFieldDuplicateId) &&
                 goodFirst.hasLimitation(SecurityLimitationKeys::kFieldDuplicateId),
             L"S-02 the duplicate id is reported in both orderings");
    s.expect(badFirst.hasLimitation(SecurityLimitationKeys::kClaimUnbacked),
             L"S-02 a claim left unbacked by an ambiguous id is accounted for explicitly");
    s.expect(badFirst.fields.size() == 2U && goodFirst.fields.size() == 2U,
             L"S-02 both copies of the duplicated field are still listed");
}

// ---------------------------------------------------------------------------
// S-05 / F-11：独立来源计数。"N 个独立来源一致"里的 N 不能虚报。
// ---------------------------------------------------------------------------
void TestSourceGroupCounting(KswordTests::Suite& s) {
    // 同一个来源分组下的两次查询是一个来源，不是两个。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField classA = MakeField("dg.wmi.a", "wmi", kBootCurrent);
        classA.raw = RawNumber("2", 2U);
        SecurityField classB = MakeField("dg.wmi.b", "wmi", kBootCurrent);
        classB.raw = RawNumber("2", 2U);
        input.fields = {classA, classB};
        input.claims = {
            MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                      SecurityDimension::Configured, TriState::Yes, "dg.wmi.a"),
            MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                      SecurityDimension::Configured, TriState::Yes, "dg.wmi.b"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* hvci =
            report.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(hvci != nullptr && hvci->configured.definiteClaimCount == 2U,
                 L"S-05 two queries from one source group are still two claims");
        s.expect(hvci != nullptr && hvci->configured.distinctSourceGroupCount == 1U,
                 L"S-05 two queries from one source group count as one independent source");
        s.expect(hvci != nullptr && hvci->configured.value == TriState::Yes,
                 L"S-05 two agreeing claims from one group still yield that value");
    }

    // 三个不同分组就是三个。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField wmi = MakeField("dg.wmi", "wmi", kBootCurrent);
        wmi.raw = RawNumber("2", 2U);
        SecurityField registry = MakeField("dg.registry", "registry", kBootCurrent);
        registry.raw = RawNumber("1", 1U);
        SecurityField runtime = MakeField("dg.runtime", "runtime", kBootCurrent);
        runtime.raw = RawText("present");
        input.fields = {wmi, registry, runtime};
        input.claims = {
            MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                      SecurityDimension::Configured, TriState::Yes, "dg.wmi"),
            MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                      SecurityDimension::Configured, TriState::Yes, "dg.registry"),
            MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity,
                      SecurityDimension::Configured, TriState::Yes, "dg.runtime"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* hvci =
            report.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(hvci != nullptr && hvci->configured.distinctSourceGroupCount == 3U,
                 L"S-05 three distinct source groups count as three independent sources");
        s.expect(hvci != nullptr && hvci->configured.definiteClaimCount == 3U,
                 L"S-05 all three agreeing claims took part");
    }

    // 两条都没署名的证据是两条，不是一条 —— 否则空分组键会把它们并成一个幽灵来源。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField first;
        first.fieldId = "anon.one";
        first.window.bootId = kBootCurrent;
        first.window.machineId = kMachine;
        first.outcome = CollectionOutcome::success();
        first.raw = RawText("yes");
        SecurityField second = first;
        second.fieldId = "anon.two";
        second.raw = RawText("no");
        input.fields = {first, second};
        input.claims = {
            MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running, TriState::Yes,
                      "anon.one"),
            MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running, TriState::No,
                      "anon.two"),
        };
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* sb = report.findCapability(SecurityCapabilityId::SecureBoot);
        s.expect(sb != nullptr && sb->running.conflicted,
                 L"S-05 two unattributed sources disagreeing is still a conflict");
        s.expect(sb != nullptr && sb->running.definiteClaimCount == 2U,
                 L"S-05 both unattributed claims took part");
        s.expect(sb != nullptr && sb->running.distinctSourceGroupCount == 2U,
                 L"S-05 two unattributed sources are two sources, not one merged phantom group");
        s.expect(report.hasLimitation(SecurityLimitationKeys::kSourceGroupUnattributed),
                 L"S-05 an unattributed source is accounted for explicitly");
    }
}

// ---------------------------------------------------------------------------
// S-05：重启前的来源之间也会打架，这件事必须看得见。
// ---------------------------------------------------------------------------
void TestHistoricalConflict(KswordTests::Suite& s) {
    SecurityField wmi = MakeField("hvci.old.wmi", "wmi", kBootPrevious);
    wmi.raw = RawNumber("2", 2U);
    SecurityField registry = MakeField("hvci.old.registry", "registry", kBootPrevious);
    registry.raw = RawNumber("0", 0U);

    SecurityStateInput input;
    input.currentWindow = CurrentWindow();
    input.fields = {wmi, registry};
    input.claims = {
        MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Running,
                  TriState::Yes, "hvci.old.wmi"),
        MakeClaim(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Running,
                  TriState::No, "hvci.old.registry"),
    };

    const SecurityStateReport report = EvaluateSecurityState(input);
    const CapabilityState* hvci =
        report.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
    s.expect(hvci != nullptr && hvci->running.value == TriState::Unknown,
             L"S-02 pre-reboot sources never set the present value");
    s.expect(hvci != nullptr && hvci->running.definiteClaimCount == 0U,
             L"S-02 pre-reboot claims do not take part in the present value");
    s.expect(hvci != nullptr && hvci->running.historicalValue == TriState::Unknown,
             L"S-05 two disagreeing pre-reboot sources do not arbitrate into one historical value");
    s.expect(hvci != nullptr && hvci->running.historicalConflicted,
             L"S-05 the pre-reboot disagreement is flagged instead of vanishing into Unknown");
    s.expect(report.hasLimitation(SecurityLimitationKeys::kHistoricalConflict),
             L"S-05 a pre-reboot disagreement is accounted for explicitly");
    const DimensionConflict* conflict = report.findConflict(
        SecurityCapabilityId::HypervisorEnforcedCodeIntegrity, SecurityDimension::Running);
    s.expect(conflict != nullptr, L"S-05 a pre-reboot disagreement reaches the conflict table");
    s.expect(conflict != nullptr && conflict->historicalConflict && !conflict->currentConflict,
             L"S-05 the conflict table says the disagreement is pre-reboot, not current");
    s.expect(conflict != nullptr && conflict->claims.size() == 2U &&
                 conflict->claims[0].value == TriState::Yes &&
                 conflict->claims[1].value == TriState::No,
             L"S-05 both pre-reboot source values are shown side by side");
    s.expect(conflict != nullptr && conflict->resolvedValue == TriState::Unknown,
             L"S-05 a pre-reboot conflict picks no value for the caller either");
    s.expect(report.conclusion == AnalysisConclusion::DifferenceObserved,
             L"S-05 disagreeing pre-reboot sources are a difference, not a clean run");

    // 对照：两条历史来源一致时既不是冲突，也照样只进 historicalValue。
    {
        SecurityStateInput agree = input;
        agree.claims[1].value = TriState::Yes;
        const SecurityStateReport agreeReport = EvaluateSecurityState(agree);
        const CapabilityState* agreeHvci =
            agreeReport.findCapability(SecurityCapabilityId::HypervisorEnforcedCodeIntegrity);
        s.expect(agreeHvci != nullptr && !agreeHvci->running.historicalConflicted,
                 L"S-05 two agreeing pre-reboot sources are not a conflict");
        s.expect(agreeHvci != nullptr && agreeHvci->running.historicalValue == TriState::Yes,
                 L"S-05 two agreeing pre-reboot sources yield that historical value");
        s.expect(agreeHvci != nullptr && agreeHvci->running.value == TriState::Unknown,
                 L"S-02 agreeing pre-reboot sources still do not set the present value");
        s.expect(agreeReport.conflicts.empty(),
                 L"S-05 agreeing pre-reboot sources leave the conflict table empty");
    }
}

// ---------------------------------------------------------------------------
// S-07：Administrator 与 System 是两档。
// ---------------------------------------------------------------------------
void TestPrivilegeTiers(KswordTests::Suite& s) {
    SecurityStateInput input;
    input.currentWindow = CurrentWindow();
    input.privilege.administrator = TriState::Yes;   // 已经是管理员
    input.privilege.system = TriState::Unknown;      // 但没有 SYSTEM/TCB
    input.privilege.kswordDriverLoaded = TriState::No;

    SecurityField systemField = MakeField("f.system", "r0", kBootCurrent);
    systemField.outcome = CollectionOutcome::notCollected();
    systemField.access = AccessRequirement::System;

    SecurityField adminField = MakeField("f.admin", "reg", kBootCurrent);
    adminField.outcome = CollectionOutcome::notCollected();
    adminField.access = AccessRequirement::Administrator;

    SecurityField driverField = MakeField("f.driver", "r0", kBootCurrent);
    driverField.outcome = CollectionOutcome::notCollected();
    driverField.access = AccessRequirement::KswordDriver;

    SecurityField plainField = MakeField("f.plain", "reg", kBootCurrent);
    plainField.outcome = CollectionOutcome::notCollected();
    plainField.access = AccessRequirement::None;

    input.fields = {systemField, adminField, driverField, plainField};
    input.claims = {MakeClaim(SecurityCapabilityId::TestSigning, SecurityDimension::Running,
                              TriState::No, "f.system")};

    const SecurityStateReport report = EvaluateSecurityState(input);
    const FieldAssessment* systemView = report.findField("f.system");
    const FieldAssessment* adminView = report.findField("f.admin");
    s.expect(systemView != nullptr &&
                 systemView->availability == FieldAvailability::BlockedByPrivilege,
             L"S-07 a SYSTEM level field with only administrator present is a privilege block");
    s.expect(adminView != nullptr && adminView->availability == FieldAvailability::NotCollected,
             L"S-07 an administrator level field with administrator present is merely not collected");
    s.expect(systemView != nullptr && adminView != nullptr &&
                 systemView->availability != adminView->availability,
             L"S-07 the System tier and the Administrator tier do not resolve identically");
    const FieldAssessment* driverView = report.findField("f.driver");
    const FieldAssessment* plainView = report.findField("f.plain");
    s.expect(driverView != nullptr && driverView->availability == FieldAvailability::BlockedByDriver,
             L"S-07 the driver tier stays its own availability value");
    s.expect(plainView != nullptr && plainView->availability == FieldAvailability::NotCollected,
             L"S-07 a field needing no privilege is merely not collected");
    s.expect(report.blockedFieldCount == 2U,
             L"S-07 exactly the SYSTEM field and the driver field count as blocked");
    s.expect(report.hasLimitation(SecurityLimitationKeys::kSystemPrivilegeDegraded),
             L"S-07 a missing SYSTEM tier is reported on its own limitation key");
    s.expect(!report.hasLimitation(SecurityLimitationKeys::kPrivilegeDegraded),
             L"S-07 with administrator present no administrator degradation is reported");

    const CapabilityState* testSigning = report.findCapability(SecurityCapabilityId::TestSigning);
    s.expect(testSigning != nullptr && testSigning->requiresSystem,
             L"S-07 a capability backed by a SYSTEM level field is labelled as needing SYSTEM");
    s.expect(testSigning != nullptr && !testSigning->requiresAdministrator,
             L"S-07 a SYSTEM requirement is not folded into an administrator requirement");

    // 拿到 SYSTEM 之后同一个字段就只是"没跑"。
    {
        SecurityStateInput elevated = input;
        elevated.privilege.system = TriState::Yes;
        const SecurityStateReport elevatedReport = EvaluateSecurityState(elevated);
        const FieldAssessment* elevatedSystem = elevatedReport.findField("f.system");
        s.expect(elevatedSystem != nullptr &&
                     elevatedSystem->availability == FieldAvailability::NotCollected,
                 L"S-07 with SYSTEM present the SYSTEM field is no longer a privilege block");
        s.expect(!elevatedReport.hasLimitation(SecurityLimitationKeys::kSystemPrivilegeDegraded),
                 L"S-07 with SYSTEM present no SYSTEM degradation is reported");
        s.expect(elevatedReport.blockedFieldCount == 1U,
                 L"S-07 only the driver field stays blocked once SYSTEM is present");
    }

    // 反向：没有管理员时管理员档才报降级，且不冒充 SYSTEM 档。
    {
        SecurityStateInput unprivileged = input;
        unprivileged.privilege.administrator = TriState::No;
        const SecurityStateReport unprivilegedReport = EvaluateSecurityState(unprivileged);
        const FieldAssessment* view = unprivilegedReport.findField("f.admin");
        s.expect(view != nullptr && view->availability == FieldAvailability::BlockedByPrivilege,
                 L"S-07 without administrator the administrator field is a privilege block");
        s.expect(unprivilegedReport.hasLimitation(SecurityLimitationKeys::kPrivilegeDegraded) &&
                     unprivilegedReport.hasLimitation(
                         SecurityLimitationKeys::kSystemPrivilegeDegraded),
                 L"S-07 the two missing tiers are reported on two separate keys");
    }
}

// ---------------------------------------------------------------------------
// S-01：anyBackedObservation 是公开输出，四种情形都要钉死。
// ---------------------------------------------------------------------------
void TestBackedObservationFlag(KswordTests::Suite& s) {
    // 真的有观测。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField field = MakeField("sb.enabled", "uefi", kBootCurrent);
        field.raw = RawText("True");
        input.fields = {field};
        input.claims = {MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running,
                                  TriState::Yes, "sb.enabled")};
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* sb = report.findCapability(SecurityCapabilityId::SecureBoot);
        s.expect(sb != nullptr && sb->anyBackedObservation,
                 L"S-01 a capability with an observed backing field reports a backed observation");
    }

    // 断言指不到任何字段。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        input.claims = {MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running,
                                  TriState::Yes, "nowhere")};
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* sb = report.findCapability(SecurityCapabilityId::SecureBoot);
        s.expect(sb != nullptr && !sb->anyBackedObservation,
                 L"S-01 an unbacked claim does not count as a backed observation");
    }

    // 字段在，但查询失败。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField field = MakeField("sb.enabled", "uefi", kBootCurrent);
        field.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5U,
                                                   "Access is denied.");
        input.fields = {field};
        input.claims = {MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running,
                                  TriState::Yes, "sb.enabled")};
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* sb = report.findCapability(SecurityCapabilityId::SecureBoot);
        s.expect(sb != nullptr && sb->anyClaim && !sb->anyBackedObservation,
                 L"S-01 a claim over a failed field is a claim but not a backed observation");
    }

    // 整轮缺席的能力。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        input.requestedCapabilities = {SecurityCapabilityId::TpmReadiness};
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* tpm = report.findCapability(SecurityCapabilityId::TpmReadiness);
        s.expect(tpm != nullptr && !tpm->anyBackedObservation,
                 L"S-01 a capability absent for the whole run has no backed observation");
    }

    // 历史观测也算"真的有观测"，但仍然不是当前值。
    {
        SecurityStateInput input;
        input.currentWindow = CurrentWindow();
        SecurityField field = MakeField("sb.enabled", "uefi", kBootPrevious);
        field.raw = RawText("True");
        input.fields = {field};
        input.claims = {MakeClaim(SecurityCapabilityId::SecureBoot, SecurityDimension::Running,
                                  TriState::Yes, "sb.enabled")};
        const SecurityStateReport report = EvaluateSecurityState(input);
        const CapabilityState* sb = report.findCapability(SecurityCapabilityId::SecureBoot);
        s.expect(sb != nullptr && sb->anyBackedObservation && sb->running.value == TriState::Unknown,
                 L"S-01 a pre-reboot observation is a backed observation without being the present value");
    }
}

// ---------------------------------------------------------------------------
// S-01 / S-04：规范点名的几个能力走一遍完整管线，不只是枚举里的一个槽位。
// ---------------------------------------------------------------------------
void TestNamedCapabilitiesEndToEnd(KswordTests::Suite& s) {
    SecurityStateInput input;
    input.currentWindow = CurrentWindow();

    SecurityField configured = MakeField("dg.servicesConfigured", "wmi", kBootCurrent);
    configured.raw = RawNumber("1", 1U);
    SecurityField running = MakeField("dg.servicesRunning", "wmi", kBootCurrent);
    running.raw = RawNumber("0", 0U);
    SecurityField userMode = MakeField("ci.userMode", "wmi", kBootCurrent);
    userMode.raw = RawNumber("2", 2U);
    SecurityField secureLaunch = MakeField("sgsl.capable", "wmi", kBootCurrent);
    secureLaunch.raw = RawText("False");

    input.fields = {configured, running, userMode, secureLaunch};
    // 断言值全是手写字面量，不由 Interpret* 产出。
    input.claims = {
        MakeClaim(SecurityCapabilityId::CredentialGuard, SecurityDimension::Configured,
                  TriState::Yes, "dg.servicesConfigured"),
        MakeClaim(SecurityCapabilityId::CredentialGuard, SecurityDimension::Running, TriState::No,
                  "dg.servicesRunning"),
        MakeClaim(SecurityCapabilityId::UserModeCodeIntegrityPolicy, SecurityDimension::Running,
                  TriState::Yes, "ci.userMode"),
        MakeClaim(SecurityCapabilityId::SystemGuardSecureLaunch,
                  SecurityDimension::HardwareSupport, TriState::No, "sgsl.capable"),
    };
    input.requestedCapabilities = {SecurityCapabilityId::CredentialGuard,
                                   SecurityCapabilityId::UserModeCodeIntegrityPolicy,
                                   SecurityCapabilityId::SystemGuardSecureLaunch,
                                   SecurityCapabilityId::KernelDmaProtection};

    const SecurityStateReport report = EvaluateSecurityState(input);

    const CapabilityState* cg = report.findCapability(SecurityCapabilityId::CredentialGuard);
    s.expect(cg != nullptr && cg->configured.value == TriState::Yes,
             L"S-01 Credential Guard configured comes from the configured property");
    s.expect(cg != nullptr && cg->running.value == TriState::No,
             L"S-01 Credential Guard configured is never reused as running");
    s.expect(cg != nullptr && cg->hardwareSupport.value == TriState::Unknown,
             L"S-01 Credential Guard hardware support is not inferred from its configuration");
    s.expect(cg != nullptr && cg->anyBackedObservation && cg->queryOutcome.status ==
                                                              CollectionStatus::Success,
             L"S-01 Credential Guard records that both of its queries succeeded");

    const CapabilityState* umci =
        report.findCapability(SecurityCapabilityId::UserModeCodeIntegrityPolicy);
    s.expect(umci != nullptr && umci->running.value == TriState::Yes,
             L"S-04 the user mode code integrity policy has its own capability state");
    s.expect(umci != nullptr && umci->configured.value == TriState::Unknown,
             L"S-04 a running user mode policy does not imply a configured one");

    const CapabilityState* sgsl =
        report.findCapability(SecurityCapabilityId::SystemGuardSecureLaunch);
    s.expect(sgsl != nullptr && sgsl->hardwareSupport.value == TriState::No,
             L"S-01 System Guard Secure Launch expresses its hardware support on its own");
    s.expect(sgsl != nullptr && sgsl->running.value == TriState::Unknown,
             L"S-01 an unsupported Secure Launch does not auto-derive a running state");

    const CapabilityState* dma = report.findCapability(SecurityCapabilityId::KernelDmaProtection);
    s.expect(dma != nullptr && !dma->anyClaim &&
                 dma->queryOutcome.status == CollectionStatus::NotCollected,
             L"S-03 Kernel DMA protection was requested and reports that nothing was collected");
    s.expect(report.missingCapabilityCount == 1U,
             L"S-03 exactly the uncollected Kernel DMA protection counts as absent");
}

} // namespace

int RunSecurityStateTests() {
    KswordTests::Suite suite(L"S security state");
    TestTriStateAndEnums(suite);
    TestFreshness(suite);
    TestFieldAvailabilityMatrix(suite);
    TestFourDimensions(suite);
    TestHistoricalSeparation(suite);
    TestConflictAndPending(suite);
    TestMissingCapabilityAccounting(suite);
    TestBootSecurity(suite);
    TestCodeIntegrity(suite);
    TestConstraintKeyWordGate(suite);
    TestCapabilityExplanation(suite);
    TestPrivilegeDegradation(suite);
    TestSupportClaim(suite);
    TestCapabilityOutcomeSummary(suite);
    TestDuplicateFieldResolution(suite);
    TestSourceGroupCounting(suite);
    TestHistoricalConflict(suite);
    TestPrivilegeTiers(suite);
    TestBackedObservationFlag(suite);
    TestNamedCapabilitiesEndToEnd(suite);
    suite.report();
    return suite.failures();
}
