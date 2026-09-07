#include "SecurityState.h"

#include <algorithm>
#include <cstddef>
#include <unordered_map>
#include <unordered_set>

namespace Ksword::Evidence {
namespace {

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

std::string Fact(const char* key, const std::string& value) {
    return std::string(key) + "=" + value;
}

// 未知一律写 "unknown"，绝不用空串或 0 冒充 —— 空串在拼接结果里看不出来。
std::string TextOrUnknown(const std::string& value) {
    return value.empty() ? std::string("unknown") : value;
}

std::string CodeOrUnknown(const OptionalU64& value) {
    return value.present ? FormatU64(value.value, U64Format::Decimal) : std::string("unknown");
}

void AddKey(std::vector<std::string>& keys, const char* key) {
    keys.emplace_back(key);
}

void SortUniqueKeys(std::vector<std::string>& keys) {
    std::sort(keys.begin(), keys.end());
    keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
}

// 规范化解释的通用构造：无论认不认识，rawCode / rawText 都原样带走（S-01/S-02）。
EnumInterpretation MakeInterpretation(const RawObservation& raw, bool recognized, const char* name) {
    EnumInterpretation interpretation;
    interpretation.recognized = recognized;
    if (recognized) {
        interpretation.normalizedName = name;
    }
    interpretation.rawCode = raw.numeric;
    interpretation.rawText = raw.text;
    return interpretation;
}

// 动作/建议词表。命中任意一条就说明这个键在"教用户做什么"，而不是在"陈述现状"。
// S-06 通过条件禁止把禁用保护作为默认修复，这里从词汇层面把门关死。
//
// 分两类，是因为时态豁免只对其中一类成立：
//   * Verb —— 动作动词。它们的 -ed 过去分词是**状态**（uninstalled、disabled），
//     真陈述键要用得上，所以给豁免。
//   * Advice —— 劝说用的言语行为动词。recommend / suggest / howToFix 无论变成哪种
//     形态（suggested、recommendation）都还是在给建议，一律不豁免。
enum class ActionWordClass { Verb, Advice };

struct ActionWordEntry final {
    std::string_view word;
    ActionWordClass kind;
};

const ActionWordEntry kActionWords[] = {
    // "disabl" 而不是 "disable"：英语构词会吃掉哑音 e（disable -> disabling），
    // 写全拼时 "disabling" 根本不以 "disable" 开头，前缀匹配会漏掉动名词。
    {"disabl", ActionWordClass::Verb},
    {"turnoff", ActionWordClass::Verb},
    {"switchoff", ActionWordClass::Verb},
    {"shutdown", ActionWordClass::Verb},
    {"uninstall", ActionWordClass::Verb},
    {"bypass", ActionWordClass::Verb},
    {"remediat", ActionWordClass::Verb},
    {"recommend", ActionWordClass::Advice},
    {"suggest", ActionWordClass::Advice},
    {"workaround", ActionWordClass::Advice},
    {"howtofix", ActionWordClass::Advice},
    {"pleaseturn", ActionWordClass::Advice},
    {"youshould", ActionWordClass::Advice},
};

// --- S-06 词表闸的分词 -----------------------------------------------------
// 旧实现把整个键折成一个小写串再做**子串**查找。那样匹配的是字母序列而不是词，
// 于是 "hvci.notDisabled" / "dse.isDisabledByPolicy" / "driver.uninstalled" /
// "smm.shutdownPending" / "bypassDetected" 这些**陈述**键统统被自己的闸拒收，
// 一条都进不了 accepted —— 能力反而被来源自称的 observedAvailable 放行。
// 现在按词匹配：先按分隔符切段，段内再按 camelCase 切词。段号要留着，
// 因为时态豁免只在同一段内成立（"kvm.disable.running" 不能靠隔壁段的 running 脱罪）。
struct KeyToken final {
    std::string text;
    // 去掉 -ing / -ed 之后的词干。用来接住被变形拆开的动作短语："turningOff"
    // 拼起来是 "turningoff"，只有词干拼接才等于词表里的 "turnoff"。
    std::string stem;
    std::size_t segment = 0;
};

bool IsKeySeparator(char c) noexcept {
    return c == '.' || c == '-' || c == '_' || c == ' ' || c == '/' || c == ':';
}

bool IsUpperAscii(char c) noexcept { return c >= 'A' && c <= 'Z'; }
bool IsLowerAscii(char c) noexcept { return c >= 'a' && c <= 'z'; }
bool IsDigitAscii(char c) noexcept { return c >= '0' && c <= '9'; }

char LowerAscii(char c) noexcept {
    return IsUpperAscii(c) ? static_cast<char>(c + ('a' - 'A')) : c;
}

std::string StemWord(const std::string& token) {
    if (token.size() > 5U && token.compare(token.size() - 3U, 3U, "ing") == 0) {
        return token.substr(0, token.size() - 3U);
    }
    if (token.size() > 4U && token.compare(token.size() - 2U, 2U, "ed") == 0) {
        return token.substr(0, token.size() - 2U);
    }
    return token;
}

std::vector<KeyToken> SplitKeyTokens(std::string_view key) {
    std::vector<KeyToken> tokens;
    std::string current;
    std::size_t segment = 0;
    bool segmentHasContent = false;
    const auto flush = [&tokens, &current, &segment]() {
        if (!current.empty()) {
            tokens.push_back(KeyToken{current, StemWord(current), segment});
            current.clear();
        }
    };
    for (std::size_t i = 0; i < key.size(); ++i) {
        const char c = key[i];
        if (IsKeySeparator(c)) {
            flush();
            if (segmentHasContent) {
                ++segment;
                segmentHasContent = false;
            }
            continue;
        }
        if (!current.empty()) {
            const char previous = key[i - 1];
            // "turnOff" -> turn|off；"HVCIRunning" -> hvci|running。
            const bool lowerToUpper = (IsLowerAscii(previous) || IsDigitAscii(previous)) &&
                                      IsUpperAscii(c);
            const bool acronymTail = IsUpperAscii(previous) && IsUpperAscii(c) &&
                                     (i + 1U) < key.size() && IsLowerAscii(key[i + 1U]);
            if (lowerToUpper || acronymTail) {
                flush();
            }
        }
        current.push_back(LowerAscii(c));
        segmentHasContent = true;
    }
    flush();
    return tokens;
}

// 过去分词。长度门槛挡掉 red 这种碰巧结尾相同的短词。
bool IsPastParticiple(const std::string& token) noexcept {
    return token.size() > 3U && token.compare(token.size() - 2U, 2U, "ed") == 0;
}

// -ed / -ing 变形是"陈述状态"的形态标记：detected / pending / running。
bool IsStateFormWord(const std::string& token) noexcept {
    return IsPastParticiple(token) ||
           (token.size() > 4U && token.compare(token.size() - 3U, 3U, "ing") == 0);
}

// 命中动作动词之后的时态豁免，两种成立方式：
//   * 命中片段里出现过 -ed 过去分词（uninstalled、disabled、turnedOff）；
//   * 命中片段在**同一段**里紧跟着一个 -ed/-ing 状态词
//     （bypassDetected、shutdownPending）——此时动作词是被修饰的名词。
// 第一种只认 -ed 不认 -ing：动名词（byDisablingHvci 里的 disabling、
// turningOff 里的 turning）仍然在描述动作，给它豁免等于把建议键放回来。
bool ActionHitIsStatement(const std::vector<KeyToken>& tokens,
                          std::size_t first,
                          std::size_t last) noexcept {
    for (std::size_t i = first; i <= last; ++i) {
        if (IsPastParticiple(tokens[i].text)) {
            return true;
        }
    }
    const std::size_t next = last + 1U;
    return next < tokens.size() && tokens[next].segment == tokens[last].segment &&
           IsStateFormWord(tokens[next].text);
}

// 一个能力/维度下的所有断言视图 —— 建维度结果时用。
struct DimensionBuildResult final {
    DimensionResult result;
    std::vector<std::string> backingFieldIds;
};

// 失败语义的严重度序。用来在"每条支撑都失败但失败原因不一样"时挑一条**真实存在**
// 的结果当摘要。AccessDenied 排最前：它是唯一能解释"为什么整块没有数据"的那一类，
// 一旦被合成的 Error 盖掉，能力级就再也分不出"要管理员"和"坏了"。
int FailureSeverityRank(CollectionStatus status) noexcept {
    switch (status) {
    case CollectionStatus::AccessDenied: return 5;
    case CollectionStatus::Unsupported:  return 4;
    case CollectionStatus::Timeout:      return 3;
    case CollectionStatus::Error:        return 2;
    case CollectionStatus::NotCollected: return 1;
    case CollectionStatus::Success:
    case CollectionStatus::Partial:      return 0;
    }
    return 0;
}

// 把若干采集结果汇总成能力级的第四维。
// 注意：这是**摘要**，逐字段的原始 status / nativeCode / message 仍然完整保留在
// FieldAssessment.outcome 里，五种失败语义没有在那一层被塌掉。
// mixedFailureStatuses 为出参：全部失败但失败**状态**不一致时置真，供调用方记账 ——
// 摘要必然丢掉了另外几种失败，这件事本身要在报告里看得见。
CollectionOutcome AggregateOutcomes(const std::vector<const CollectionOutcome*>& outcomes,
                                    bool* mixedFailureStatuses = nullptr) {
    if (mixedFailureStatuses != nullptr) {
        *mixedFailureStatuses = false;
    }
    if (outcomes.empty()) {
        // 一条支撑都没有 —— 是"没采集"，不是"没问题"。
        return CollectionOutcome::notCollected();
    }

    std::size_t observed = 0;
    bool anyPartial = false;
    for (const CollectionOutcome* outcome : outcomes) {
        if (StatusCarriesObservation(outcome->status)) {
            ++observed;
        }
        if (outcome->status == CollectionStatus::Partial) {
            anyPartial = true;
        }
    }

    if (observed == outcomes.size()) {
        CollectionOutcome result;
        result.status = anyPartial ? CollectionStatus::Partial : CollectionStatus::Success;
        return result;
    }
    if (observed != 0U) {
        CollectionOutcome result;
        result.status = CollectionStatus::Partial;
        return result;
    }

    // 一条观测都没有。若所有失败完全一致，原样保留（含 nativeCode 与来源原文）。
    const CollectionOutcome& first = *outcomes.front();
    bool identical = true;
    bool sameStatus = true;
    for (const CollectionOutcome* outcome : outcomes) {
        if (outcome->status != first.status) {
            sameStatus = false;
            identical = false;
            continue;
        }
        if (outcome->nativeCode != first.nativeCode ||
            outcome->nativeCodeDomain != first.nativeCodeDomain ||
            outcome->message != first.message) {
            identical = false;
        }
    }
    if (identical) {
        return first;
    }
    if (sameStatus) {
        // 状态相同但错误码不同：状态可以保留，编造一个"代表码"会骗人，所以留空。
        CollectionOutcome result;
        result.status = first.status;
        return result;
    }

    // 状态各不相同。这里**不**合成 CollectionStatus::Error —— 那个状态没有任何来源
    // 返回过，等于凭空发明一种失败，还会把 AccessDenied 这类可解释的失败抹平成
    // "一般错误"（S-01 的"五种失败语义不得混用"）。挑严重度最高的那一条真实结果。
    if (mixedFailureStatuses != nullptr) {
        *mixedFailureStatuses = true;
    }
    const CollectionOutcome* chosen = outcomes.front();
    for (const CollectionOutcome* outcome : outcomes) {
        if (FailureSeverityRank(outcome->status) > FailureSeverityRank(chosen->status)) {
            chosen = outcome;
        }
    }
    // 被选中的状态如果在多条支撑上出现且细节不一致，同样不挑"代表码"。
    bool sameDetail = true;
    for (const CollectionOutcome* outcome : outcomes) {
        if (outcome->status != chosen->status) {
            continue;
        }
        if (outcome->nativeCode != chosen->nativeCode ||
            outcome->nativeCodeDomain != chosen->nativeCodeDomain ||
            outcome->message != chosen->message) {
            sameDetail = false;
        }
    }
    if (sameDetail) {
        return *chosen;
    }
    CollectionOutcome result;
    result.status = chosen->status;
    return result;
}

// S-07：字段在当前上下文里能不能读到。
FieldAvailability ComputeAvailability(const CollectionOutcome& outcome,
                                      AccessRequirement access,
                                      const PrivilegeContext& privilege) noexcept {
    if (StatusCarriesObservation(outcome.status)) {
        // 已经拿到观测了，无论声明需要什么权限，事实是读到了。
        return FieldAvailability::Readable;
    }
    switch (outcome.status) {
    case CollectionStatus::AccessDenied:
        return FieldAvailability::BlockedByPrivilege;
    case CollectionStatus::Unsupported:
        return FieldAvailability::NotSupported;
    case CollectionStatus::Timeout:
    case CollectionStatus::Error:
        return FieldAvailability::QueryFailed;
    case CollectionStatus::NotCollected:
        break;
    case CollectionStatus::Success:
    case CollectionStatus::Partial:
        // 上面已经返回过，这两支只为让 switch 覆盖全部枚举值。
        return FieldAvailability::Readable;
    }

    // NotCollected：能用声明的权限要求解释为什么没跑，就说清楚，而不是含糊地"没数据"。
    // S-07：System 走自己的门。拿 administrator 顶替 SYSTEM/TCB 会让这一档彻底消失 ——
    // 有管理员时一个真正需要 SYSTEM 的字段会被说成"只是没跑"，而不是"权限不够"。
    switch (access) {
    case AccessRequirement::System:
        if (privilege.system != TriState::Yes) {
            return FieldAvailability::BlockedByPrivilege;
        }
        break;
    case AccessRequirement::Administrator:
        if (privilege.administrator != TriState::Yes) {
            return FieldAvailability::BlockedByPrivilege;
        }
        break;
    case AccessRequirement::KswordDriver:
        if (privilege.kswordDriverLoaded != TriState::Yes) {
            return FieldAvailability::BlockedByDriver;
        }
        break;
    case AccessRequirement::Unknown:
    case AccessRequirement::None:
        break;
    }
    return FieldAvailability::NotCollected;
}

} // namespace

// ---------------------------------------------------------------------------
// 枚举名字
// ---------------------------------------------------------------------------

const char* TriStateName(TriState value) noexcept {
    switch (value) {
    case TriState::Unknown: return "Unknown";
    case TriState::No:      return "No";
    case TriState::Yes:     return "Yes";
    }
    return "Unknown";
}

bool TriStateIsDefinite(TriState value) noexcept {
    return value == TriState::Yes || value == TriState::No;
}

const char* SecurityCapabilityName(SecurityCapabilityId capability) noexcept {
    switch (capability) {
    case SecurityCapabilityId::Unknown:                        return "Unknown";
    case SecurityCapabilityId::VirtualizationBasedSecurity:     return "VirtualizationBasedSecurity";
    case SecurityCapabilityId::HypervisorEnforcedCodeIntegrity: return "HypervisorEnforcedCodeIntegrity";
    case SecurityCapabilityId::CredentialGuard:                 return "CredentialGuard";
    case SecurityCapabilityId::SystemGuardSecureLaunch:         return "SystemGuardSecureLaunch";
    case SecurityCapabilityId::KernelDmaProtection:             return "KernelDmaProtection";
    case SecurityCapabilityId::SecureBoot:                      return "SecureBoot";
    case SecurityCapabilityId::TpmPresence:                     return "TpmPresence";
    case SecurityCapabilityId::TpmReadiness:                    return "TpmReadiness";
    case SecurityCapabilityId::MeasuredBootLog:                 return "MeasuredBootLog";
    case SecurityCapabilityId::KernelModeCodeIntegrityPolicy:   return "KernelModeCodeIntegrityPolicy";
    case SecurityCapabilityId::UserModeCodeIntegrityPolicy:     return "UserModeCodeIntegrityPolicy";
    case SecurityCapabilityId::TestSigning:                     return "TestSigning";
    }
    return "Unknown";
}

const char* SecurityDimensionName(SecurityDimension dimension) noexcept {
    switch (dimension) {
    case SecurityDimension::HardwareSupport: return "HardwareSupport";
    case SecurityDimension::Configured:      return "Configured";
    case SecurityDimension::Running:         return "Running";
    }
    return "HardwareSupport";
}

const char* DeviceGuardServiceName(DeviceGuardService service) noexcept {
    switch (service) {
    case DeviceGuardService::Unknown:                         return "Unknown";
    case DeviceGuardService::None:                            return "None";
    case DeviceGuardService::CredentialGuard:                 return "CredentialGuard";
    case DeviceGuardService::HypervisorEnforcedCodeIntegrity: return "HypervisorEnforcedCodeIntegrity";
    case DeviceGuardService::SystemGuardSecureLaunch:         return "SystemGuardSecureLaunch";
    case DeviceGuardService::SmmFirmwareMeasurement:          return "SmmFirmwareMeasurement";
    }
    return "Unknown";
}

const char* VbsStatusName(VbsStatus status) noexcept {
    switch (status) {
    case VbsStatus::Unknown:           return "Unknown";
    case VbsStatus::Disabled:          return "Disabled";
    case VbsStatus::EnabledNotRunning: return "EnabledNotRunning";
    case VbsStatus::EnabledAndRunning: return "EnabledAndRunning";
    }
    return "Unknown";
}

const char* SecurityPropertyName(SecurityProperty property) noexcept {
    switch (property) {
    case SecurityProperty::Unknown:                   return "Unknown";
    case SecurityProperty::None:                      return "None";
    case SecurityProperty::BaseVirtualizationSupport: return "BaseVirtualizationSupport";
    case SecurityProperty::SecureBoot:                return "SecureBoot";
    case SecurityProperty::DmaProtection:             return "DmaProtection";
    case SecurityProperty::SecureMemoryOverwrite:     return "SecureMemoryOverwrite";
    case SecurityProperty::NxProtections:             return "NxProtections";
    case SecurityProperty::SmmMitigations:            return "SmmMitigations";
    case SecurityProperty::ModeBasedExecutionControl: return "ModeBasedExecutionControl";
    case SecurityProperty::ApicVirtualization:        return "ApicVirtualization";
    }
    return "Unknown";
}

const char* CodeIntegrityEnforcementName(CodeIntegrityEnforcement enforcement) noexcept {
    switch (enforcement) {
    case CodeIntegrityEnforcement::Unknown:  return "Unknown";
    case CodeIntegrityEnforcement::Off:      return "Off";
    case CodeIntegrityEnforcement::Audit:    return "Audit";
    case CodeIntegrityEnforcement::Enforced: return "Enforced";
    }
    return "Unknown";
}

const char* FieldFreshnessName(FieldFreshness freshness) noexcept {
    switch (freshness) {
    case FieldFreshness::Unknown:          return "Unknown";
    case FieldFreshness::Current:          return "Current";
    case FieldFreshness::Historical:       return "Historical";
    case FieldFreshness::DifferentMachine: return "DifferentMachine";
    }
    return "Unknown";
}

const char* AccessRequirementName(AccessRequirement requirement) noexcept {
    switch (requirement) {
    case AccessRequirement::Unknown:       return "Unknown";
    case AccessRequirement::None:          return "None";
    case AccessRequirement::Administrator: return "Administrator";
    case AccessRequirement::System:        return "System";
    case AccessRequirement::KswordDriver:  return "KswordDriver";
    }
    return "Unknown";
}

const char* FieldAvailabilityName(FieldAvailability availability) noexcept {
    switch (availability) {
    case FieldAvailability::Unknown:            return "Unknown";
    case FieldAvailability::Readable:           return "Readable";
    case FieldAvailability::BlockedByPrivilege: return "BlockedByPrivilege";
    case FieldAvailability::BlockedByDriver:    return "BlockedByDriver";
    case FieldAvailability::NotSupported:       return "NotSupported";
    case FieldAvailability::QueryFailed:        return "QueryFailed";
    case FieldAvailability::NotCollected:       return "NotCollected";
    }
    return "Unknown";
}

const char* CapabilityConstraintKindName(CapabilityConstraintKind kind) noexcept {
    switch (kind) {
    case CapabilityConstraintKind::Unknown:              return "Unknown";
    case CapabilityConstraintKind::VendorUnsupported:    return "VendorUnsupported";
    case CapabilityConstraintKind::HardwareUnsupported:  return "HardwareUnsupported";
    case CapabilityConstraintKind::DriverMissing:        return "DriverMissing";
    case CapabilityConstraintKind::ProfileMissing:       return "ProfileMissing";
    case CapabilityConstraintKind::SecurityConfiguration: return "SecurityConfiguration";
    case CapabilityConstraintKind::PrivilegeInsufficient: return "PrivilegeInsufficient";
    case CapabilityConstraintKind::QueryUnavailable:     return "QueryUnavailable";
    }
    return "Unknown";
}

const char* SupportClaimStatusName(SupportClaimStatus status) noexcept {
    switch (status) {
    case SupportClaimStatus::Blocked:           return "Blocked";
    case SupportClaimStatus::PartiallyVerified: return "PartiallyVerified";
    case SupportClaimStatus::Verified:          return "Verified";
    }
    return "Blocked";
}

// ---------------------------------------------------------------------------
// S-01：枚举解释。不认识就是不认识 —— rawCode 一律保留，normalizedName 一律留空。
// ---------------------------------------------------------------------------

DeviceGuardServiceValue InterpretDeviceGuardService(const RawObservation& raw) {
    DeviceGuardServiceValue value;
    if (!raw.numeric.present) {
        // 来源给的不是数值编码，我们不去猜文本 —— 猜错比不猜更糟。
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.service = DeviceGuardService::None; break;
    case 1U: value.service = DeviceGuardService::CredentialGuard; break;
    case 2U: value.service = DeviceGuardService::HypervisorEnforcedCodeIntegrity; break;
    case 3U: value.service = DeviceGuardService::SystemGuardSecureLaunch; break;
    case 4U: value.service = DeviceGuardService::SmmFirmwareMeasurement; break;
    default:
        // 新版本 Windows 加的新服务编码：原值留着，解释留空，UI 显示"未知枚举 N"。
        value.service = DeviceGuardService::Unknown;
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = MakeInterpretation(raw, true, DeviceGuardServiceName(value.service));
    return value;
}

VbsStatusValue InterpretVbsStatus(const RawObservation& raw) {
    VbsStatusValue value;
    if (!raw.numeric.present) {
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.status = VbsStatus::Disabled; break;
    case 1U: value.status = VbsStatus::EnabledNotRunning; break;
    case 2U: value.status = VbsStatus::EnabledAndRunning; break;
    default:
        value.status = VbsStatus::Unknown;
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = MakeInterpretation(raw, true, VbsStatusName(value.status));
    return value;
}

void VbsStatusToDimensions(VbsStatus status, TriState& configured, TriState& running) noexcept {
    switch (status) {
    case VbsStatus::Disabled:
        configured = TriState::No;
        running = TriState::No;
        return;
    case VbsStatus::EnabledNotRunning:
        // S-01 的关键分离：配置上开了，实际没跑。这里绝不把 running 也写成 Yes。
        configured = TriState::Yes;
        running = TriState::No;
        return;
    case VbsStatus::EnabledAndRunning:
        configured = TriState::Yes;
        running = TriState::Yes;
        return;
    case VbsStatus::Unknown:
        break;
    }
    // 不认识的状态码：两维都保持未知，绝不落成"关闭"。
    configured = TriState::Unknown;
    running = TriState::Unknown;
}

SecurityPropertyValue InterpretSecurityProperty(const RawObservation& raw) {
    SecurityPropertyValue value;
    if (!raw.numeric.present) {
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.property = SecurityProperty::None; break;
    case 1U: value.property = SecurityProperty::BaseVirtualizationSupport; break;
    case 2U: value.property = SecurityProperty::SecureBoot; break;
    case 3U: value.property = SecurityProperty::DmaProtection; break;
    case 4U: value.property = SecurityProperty::SecureMemoryOverwrite; break;
    case 5U: value.property = SecurityProperty::NxProtections; break;
    case 6U: value.property = SecurityProperty::SmmMitigations; break;
    case 7U: value.property = SecurityProperty::ModeBasedExecutionControl; break;
    case 8U: value.property = SecurityProperty::ApicVirtualization; break;
    default:
        value.property = SecurityProperty::Unknown;
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = MakeInterpretation(raw, true, SecurityPropertyName(value.property));
    return value;
}

CodeIntegrityEnforcementValue InterpretCodeIntegrityEnforcement(const RawObservation& raw) {
    CodeIntegrityEnforcementValue value;
    if (!raw.numeric.present) {
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    switch (raw.numeric.value) {
    case 0U: value.enforcement = CodeIntegrityEnforcement::Off; break;
    case 1U: value.enforcement = CodeIntegrityEnforcement::Audit; break;
    case 2U: value.enforcement = CodeIntegrityEnforcement::Enforced; break;
    default:
        value.enforcement = CodeIntegrityEnforcement::Unknown;
        value.interpretation = MakeInterpretation(raw, false, "");
        return value;
    }
    value.interpretation = MakeInterpretation(raw, true, CodeIntegrityEnforcementName(value.enforcement));
    return value;
}

// ---------------------------------------------------------------------------
// S-02：新鲜度
// ---------------------------------------------------------------------------

FieldFreshness ClassifyFieldFreshness(const CaptureWindow& field,
                                      const CaptureWindow& current) noexcept {
    // 先看机器：不是同一台机器时，启动周期比不比都没意义。
    if (!field.machineId.empty() && !current.machineId.empty() && field.machineId != current.machineId) {
        return FieldFreshness::DifferentMachine;
    }
    // 缺 bootId 就是说不清 —— 不能乐观地当成"就是这次启动"。
    if (field.bootId.empty() || current.bootId.empty()) {
        return FieldFreshness::Unknown;
    }
    return (field.bootId == current.bootId) ? FieldFreshness::Current : FieldFreshness::Historical;
}

bool FreshnessUsableAsCurrent(FieldFreshness freshness) noexcept {
    return freshness == FieldFreshness::Current;
}

// ---------------------------------------------------------------------------
// FieldAssessment
// ---------------------------------------------------------------------------

std::string FieldAssessment::describe() const {
    std::string text;
    const auto append = [&text](const std::string& piece) {
        if (!text.empty()) {
            text += ";";
        }
        text += piece;
    };
    append(Fact("field", TextOrUnknown(fieldId)));
    append(Fact("query", TextOrUnknown(queryEntry)));
    append(Fact("collector", TextOrUnknown(source.collectorId)));
    append(Fact("origin", SourceOriginName(source.origin)));
    append(Fact("boot", TextOrUnknown(window.bootId)));
    append(Fact("status", CollectionStatusName(outcome.status)));
    append(Fact("nativeDomain", TextOrUnknown(outcome.nativeCodeDomain)));
    append(Fact("nativeCode", CodeOrUnknown(outcome.nativeCode)));
    // S-02：原始值与规范化解释并列输出，规范化不覆盖原值。
    append(Fact("raw", TextOrUnknown(raw.text)));
    append(Fact("rawNumeric", CodeOrUnknown(raw.numeric)));
    append(Fact("normalized",
                interpretation.recognized ? TextOrUnknown(interpretation.normalizedName)
                                          : std::string("unrecognized")));
    append(Fact("interpretedRawCode", CodeOrUnknown(interpretation.rawCode)));
    append(Fact("access", AccessRequirementName(access)));
    append(Fact("availability", FieldAvailabilityName(availability)));
    append(Fact("freshness", FieldFreshnessName(freshness)));
    return text;
}

const DimensionResult& CapabilityState::dimension(SecurityDimension which) const noexcept {
    switch (which) {
    case SecurityDimension::HardwareSupport: return hardwareSupport;
    case SecurityDimension::Configured:      return configured;
    case SecurityDimension::Running:         return running;
    }
    return hardwareSupport;
}

// ---------------------------------------------------------------------------
// S-04：WDAC / 代码完整性
// ---------------------------------------------------------------------------

std::size_t CodeIntegrityAssessment::auditPolicyCount() const noexcept {
    std::size_t count = 0;
    for (const CodeIntegrityPolicyView& policy : effectivePolicies) {
        if (policy.enforcement == CodeIntegrityEnforcement::Audit) {
            ++count;
        }
    }
    return count;
}

std::size_t CodeIntegrityAssessment::enforcedPolicyCount() const noexcept {
    std::size_t count = 0;
    for (const CodeIntegrityPolicyView& policy : effectivePolicies) {
        if (policy.enforcement == CodeIntegrityEnforcement::Enforced) {
            ++count;
        }
    }
    return count;
}

namespace {

CodeIntegrityPolicyView MakePolicyView(const CodeIntegrityPolicyRecord& record,
                                       std::vector<std::string>& limitations) {
    CodeIntegrityPolicyView view;
    view.policyId = record.policyId;
    view.friendlyName = record.friendlyName;
    view.basePolicy = record.basePolicy;
    view.sourceFieldId = record.sourceFieldId;
    const CodeIntegrityEnforcementValue value = InterpretCodeIntegrityEnforcement(record.enforcementRaw);
    view.enforcement = value.enforcement;
    view.enforcementInterpretation = value.interpretation;
    if (!value.interpretation.recognized &&
        (record.enforcementRaw.numeric.present || !record.enforcementRaw.text.empty())) {
        AddKey(limitations, SecurityLimitationKeys::kUnknownEnumPreserved);
    }
    return view;
}

} // namespace

CodeIntegrityAssessment EvaluateCodeIntegrity(const CodeIntegrityInput& input) {
    CodeIntegrityAssessment assessment;
    assessment.configuredOutcome = input.configuredOutcome;
    assessment.effectiveOutcome = input.effectiveOutcome;
    assessment.configuredPolicyKnown = StatusCarriesObservation(input.configuredOutcome.status);
    assessment.effectivePolicyKnown = StatusCarriesObservation(input.effectiveOutcome.status);

    // 配置口径与有效口径各自成列。查询没有携带观测时列表保持空 ——
    // 一次失败查询返回的策略列表不是观测，更不能拿另一口径的列表顶替（S-04）。
    if (assessment.configuredPolicyKnown) {
        assessment.configuredPolicies.reserve(input.configuredPolicies.size());
        for (const CodeIntegrityPolicyRecord& record : input.configuredPolicies) {
            assessment.configuredPolicies.push_back(MakePolicyView(record, assessment.limitationKeys));
        }
    } else {
        AddKey(assessment.limitationKeys, SecurityLimitationKeys::kConfiguredPolicyUnknown);
    }

    if (assessment.effectivePolicyKnown) {
        assessment.effectivePolicies.reserve(input.effectivePolicies.size());
        for (const CodeIntegrityPolicyRecord& record : input.effectivePolicies) {
            assessment.effectivePolicies.push_back(MakePolicyView(record, assessment.limitationKeys));
        }
    } else {
        AddKey(assessment.limitationKeys, SecurityLimitationKeys::kEffectivePolicyUnknown);
    }

    // 内核态与用户态执行状态是两个独立属性，各看各的 outcome。
    if (StatusCarriesObservation(input.kernelModeOutcome.status)) {
        const CodeIntegrityEnforcementValue value = InterpretCodeIntegrityEnforcement(input.kernelModeRaw);
        assessment.kernelModeEnforcement = value.enforcement;
        assessment.kernelModeInterpretation = value.interpretation;
        if (!value.interpretation.recognized) {
            AddKey(assessment.limitationKeys, SecurityLimitationKeys::kUnknownEnumPreserved);
        }
    } else {
        // 查询失败：状态保持 Unknown，但原始值仍然原样留着（S-02）。
        assessment.kernelModeInterpretation = MakeInterpretation(input.kernelModeRaw, false, "");
    }

    if (StatusCarriesObservation(input.userModeOutcome.status)) {
        const CodeIntegrityEnforcementValue value = InterpretCodeIntegrityEnforcement(input.userModeRaw);
        assessment.userModeEnforcement = value.enforcement;
        assessment.userModeInterpretation = value.interpretation;
        if (!value.interpretation.recognized) {
            AddKey(assessment.limitationKeys, SecurityLimitationKeys::kUnknownEnumPreserved);
        }
    } else {
        assessment.userModeInterpretation = MakeInterpretation(input.userModeRaw, false, "");
    }

    SortUniqueKeys(assessment.limitationKeys);
    return assessment;
}

ImageLoadAssessment EvaluateImageLoad(const ImageLoadInput& input) {
    ImageLoadAssessment assessment;
    assessment.imagePath = input.imagePath;
    assessment.signatureOutcome = input.signatureOutcome;
    assessment.policyDecisionOutcome = input.policyDecisionOutcome;

    // S-04："签名有效 ≠ 当前策略允许加载"。两个字段各自只认自己的 outcome，
    // 本函数没有任何一行会把 signatureValid 写进 allowedByCurrentPolicy。
    assessment.signatureValid = StatusCarriesObservation(input.signatureOutcome.status)
                                    ? input.signatureValid
                                    : TriState::Unknown;
    assessment.allowedByCurrentPolicy = StatusCarriesObservation(input.policyDecisionOutcome.status)
                                            ? input.policyAllowsLoad
                                            : TriState::Unknown;
    if (assessment.allowedByCurrentPolicy == TriState::Unknown) {
        AddKey(assessment.limitationKeys, SecurityLimitationKeys::kPolicyDecisionUnknown);
    }
    SortUniqueKeys(assessment.limitationKeys);
    return assessment;
}

// ---------------------------------------------------------------------------
// S-06：能力约束
// ---------------------------------------------------------------------------

bool IsStatementOnlyConstraintKey(std::string_view key) noexcept {
    if (key.empty()) {
        return false;
    }
    const std::vector<KeyToken> tokens = SplitKeyTokens(key);
    if (tokens.empty()) {
        return false;
    }
    // 单个词允许派生形（suggestion / remediation 都以动作词开头）；拼接出来的
    // 多词短语必须整体相等，否则 "turnedoff" 这种字母串会被当成 "turnoff"。
    const auto hits = [](const std::string& candidate, std::string_view word, std::size_t n) {
        if (candidate.size() < word.size() || candidate.compare(0, word.size(), word) != 0) {
            return false;
        }
        return n == 0U || candidate.size() == word.size();
    };

    for (std::size_t i = 0; i < tokens.size(); ++i) {
        std::string joined;
        std::string stemmed;
        // 至多三个相邻词拼一次，覆盖 turn-off / please-turn / how-to-fix 这类
        // 被分隔符或驼峰拆开的动作短语。原形与词干各拼一份：原形接住
        // "turn-off"，词干接住 "turningOff"。
        for (std::size_t n = 0; n < 3U && (i + n) < tokens.size(); ++n) {
            joined += tokens[i + n].text;
            stemmed += tokens[i + n].stem;
            for (const ActionWordEntry& entry : kActionWords) {
                if (!hits(joined, entry.word, n) && !hits(stemmed, entry.word, n)) {
                    continue;
                }
                // 劝说词没有时态豁免：它变成什么形态都还是在给建议。
                if (entry.kind == ActionWordClass::Verb && ActionHitIsStatement(tokens, i, i + n)) {
                    continue;
                }
                return false;
            }
        }
    }
    return true;
}

bool KswordCapabilityExplanation::mayStart() const noexcept {
    // S-06 通过条件："不能运行的能力不会启动"。Unknown 也不放行。
    return available == TriState::Yes;
}

KswordCapabilityExplanation ExplainKswordCapability(const KswordCapabilityInput& input,
                                                    const std::vector<FieldAssessment>& fields) {
    KswordCapabilityExplanation explanation;
    explanation.capabilityId = input.capabilityId;

    bool anyAccepted = false;
    bool anyUnaccepted = false;
    explanation.constraints.reserve(input.constraints.size());
    for (const KswordCapabilityConstraint& constraint : input.constraints) {
        KswordCapabilityConstraintView view;
        view.kind = constraint.kind;
        view.constraintKey = constraint.constraintKey;
        view.sourceFieldId = constraint.sourceFieldId;
        view.observed = constraint.observed;

        const auto found = std::find_if(fields.begin(), fields.end(),
                                        [&constraint](const FieldAssessment& field) {
                                            return field.fieldId == constraint.sourceFieldId;
                                        });
        view.backed = (found != fields.end()) && found->carriesObservation;

        const bool statementOnly = IsStatementOnlyConstraintKey(constraint.constraintKey);
        if (!statementOnly) {
            // 这个键在教用户做什么。拒收并留痕，不让它进结果。
            explanation.rejectedConstraintKeys.push_back(constraint.constraintKey);
            AddKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintNonStatement);
        } else if (!view.backed) {
            AddKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintUnbacked);
        }

        view.accepted = statementOnly && view.backed;
        if (view.accepted) {
            anyAccepted = true;
        } else {
            anyUnaccepted = true;
        }
        explanation.constraints.push_back(std::move(view));
    }

    const bool availabilityObserved = StatusCarriesObservation(input.availabilityOutcome.status);
    if (anyAccepted) {
        // 有有据可查的约束就是不可用。若来源同时声称"可用"，那是矛盾 ——
        // 取受限的一侧，因为通过条件要求不能运行的能力不会启动。
        explanation.available = TriState::No;
        if (availabilityObserved && input.observedAvailable == TriState::Yes) {
            AddKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintConflict);
        }
    } else if (anyUnaccepted && availabilityObserved && input.observedAvailable == TriState::Yes) {
        // 约束在场，却一条都判不了（键被拒 / 来源字段没采到 / 指不到字段）。
        // 这些约束正是"拦住能力"的那一侧：它们的证据没采到，就说明**说不清**，
        // 不能让来源自称的"可用"顺着 fall-through 把能力放行 ——
        // 那就是"从没采到推出正常"，也是 S-06 通过条件"不能运行的能力不会启动"
        // 最容易被绕过的那条缝。回落 Unknown，mayStart() 保持 false。
        explanation.available = TriState::Unknown;
        AddKey(explanation.limitationKeys, SecurityLimitationKeys::kConstraintIndeterminate);
    } else if (availabilityObserved) {
        // 来源声称 No 时照样采纳：那是正面的不可用证据，抹成 Unknown 反而丢信息。
        explanation.available = input.observedAvailable;
    } else {
        // 没约束也没观测 = 不知道。不知道不等于可用。
        explanation.available = TriState::Unknown;
    }

    SortUniqueKeys(explanation.limitationKeys);
    return explanation;
}

// ---------------------------------------------------------------------------
// S-08：实测配置清单
// ---------------------------------------------------------------------------

SupportClaim EvaluateSupportClaim(const std::vector<VerifiedConfiguration>& configurations) {
    SupportClaim claim;
    for (const VerifiedConfiguration& configuration : configurations) {
        // 一套配置要算数，必须记全：build 原文、证据字段、VBS 运行状态、驱动加载状态。
        const bool complete = !configuration.configurationId.empty() &&
                              !configuration.osBuildRaw.empty() &&
                              !configuration.evidenceFieldId.empty() &&
                              TriStateIsDefinite(configuration.vbsRunning) &&
                              TriStateIsDefinite(configuration.kswordDriverLoaded);
        if (!complete) {
            claim.rejectedConfigurationIds.push_back(configuration.configurationId);
            continue;
        }
        claim.acceptedConfigurationIds.push_back(configuration.configurationId);
        if (configuration.vbsRunning == TriState::No) {
            claim.baselineConfigurationVerified = true;
        } else if (TriStateIsDefinite(configuration.hvciRunning)) {
            // VBS 在跑的那一套还要求 HVCI 状态是定值，否则说不清核对的是哪种配置。
            claim.vbsConfigurationVerified = true;
        } else {
            claim.rejectedConfigurationIds.push_back(configuration.configurationId);
            claim.acceptedConfigurationIds.pop_back();
        }
    }

    if (claim.baselineConfigurationVerified && claim.vbsConfigurationVerified) {
        claim.status = SupportClaimStatus::Verified;
    } else if (claim.baselineConfigurationVerified || claim.vbsConfigurationVerified) {
        claim.status = SupportClaimStatus::PartiallyVerified;
        AddKey(claim.limitationKeys, SecurityLimitationKeys::kSupportClaimIncomplete);
    } else {
        // 空清单也走这里：没记录 = 没核对 = BLOCKED。
        claim.status = SupportClaimStatus::Blocked;
        AddKey(claim.limitationKeys, SecurityLimitationKeys::kSupportClaimBlocked);
    }
    SortUniqueKeys(claim.limitationKeys);
    return claim;
}

// ---------------------------------------------------------------------------
// 顶层评估
// ---------------------------------------------------------------------------

namespace {

using FieldIndex = std::unordered_map<std::string, std::size_t>;

// 同一个 fieldId 出现两次时索引里存这个哨兵值。
constexpr std::size_t kAmbiguousFieldIndex = static_cast<std::size_t>(-1);

const FieldAssessment* LookupField(const std::vector<FieldAssessment>& fields,
                                   const FieldIndex& index,
                                   const std::string& fieldId) {
    if (fieldId.empty()) {
        return nullptr;
    }
    const auto found = index.find(fieldId);
    if (found == index.end()) {
        return nullptr;
    }
    if (found->second == kAmbiguousFieldIndex) {
        // S-02：重复 fieldId 意味着"引用它的断言到底指哪一条"说不清。挑第一条或
        // 最后一条都会让同一份输入换个顺序就得出不同结论，SourceClaimView.sourceGroup
        // 还会把值记在一个根本没提供它的采集器名下。歧义 id 一律当作指不到，
        // 引用它的断言退化为无支撑（值保持 Unknown 并记 kClaimUnbacked）。
        return nullptr;
    }
    return &fields[found->second];
}

DimensionBuildResult BuildDimension(SecurityCapabilityId capability,
                                    SecurityDimension dimension,
                                    const SecurityStateInput& input,
                                    const std::vector<FieldAssessment>& fields,
                                    const FieldIndex& index,
                                    std::vector<std::string>& limitations) {
    DimensionBuildResult build;
    build.result.dimension = dimension;

    for (const CapabilityClaim& claim : input.claims) {
        if (claim.capability != capability || claim.dimension != dimension) {
            continue;
        }
        SourceClaimView view;
        view.fieldId = claim.fieldId;
        view.value = claim.value;  // 来源断言原样保留，冲突时一个都不丢

        const FieldAssessment* field = LookupField(fields, index, claim.fieldId);
        if (field != nullptr) {
            view.backed = true;
            view.sourceGroup = field->source.sourceGroup.empty() ? field->source.collectorId
                                                                 : field->source.sourceGroup;
            view.origin = field->source.origin;
            view.freshness = field->freshness;
            view.carriesObservation = field->carriesObservation;
            view.usableAsCurrent = field->usableAsCurrent;
            build.backingFieldIds.push_back(field->fieldId);
        } else {
            // 断言指不到任何字段 —— 结论不能建立在没有来源的话上。
            AddKey(limitations, SecurityLimitationKeys::kClaimUnbacked);
        }

        if (view.backed && !view.carriesObservation && TriStateIsDefinite(claim.value)) {
            // S-01："查询失败不是关闭"。这里只记账并拒绝采纳，不改写来源给的值。
            AddKey(limitations, SecurityLimitationKeys::kClaimNotObserved);
        }
        build.result.claims.push_back(std::move(view));
    }

    // 当前值：只由"携带观测且属于当前启动周期"的定值断言产生。
    bool first = true;
    TriState current = TriState::Unknown;
    std::unordered_set<std::string> groups;
    for (const SourceClaimView& view : build.result.claims) {
        if (!view.usableAsCurrent || !TriStateIsDefinite(view.value)) {
            continue;
        }
        ++build.result.definiteClaimCount;
        if (view.sourceGroup.empty()) {
            // sourceGroup 与 collectorId 都为空 = 这条证据没有署名。把所有没署名的
            // 来源折成同一个空串分组会让"N 个独立来源一致"虚报成 1 个来源
            // （F-11 的独立性判据直接失真）。没署名的各算各的，并显式记账。
            groups.insert("\x01unattributed:" + view.fieldId);
            AddKey(limitations, SecurityLimitationKeys::kSourceGroupUnattributed);
        } else {
            groups.insert(view.sourceGroup);
        }
        if (first) {
            current = view.value;
            first = false;
        } else if (current != view.value) {
            build.result.conflicted = true;
        }
    }
    build.result.distinctSourceGroupCount = groups.size();
    // S-05：不一致就是不一致，不替调用方选。
    build.result.value = build.result.conflicted ? TriState::Unknown : current;

    // S-02：跨启动周期的定值单独收进 historicalValue，永远不会被当成当前值。
    bool historyFirst = true;
    TriState history = TriState::Unknown;
    bool historyConflict = false;
    for (const SourceClaimView& view : build.result.claims) {
        if (!view.backed || !view.carriesObservation) {
            continue;
        }
        if (view.freshness != FieldFreshness::Historical || !TriStateIsDefinite(view.value)) {
            continue;
        }
        if (historyFirst) {
            history = view.value;
            historyFirst = false;
        } else if (history != view.value) {
            historyConflict = true;
        }
    }
    // S-05：重启前的两个来源互相矛盾时，只把 historicalValue 塌成 Unknown 是不够的 ——
    // 那与"根本没有历史证据"在报告里长得一模一样，"来源不一致"这件事就消失了。
    build.result.historicalConflicted = historyConflict;
    build.result.historicalValue = historyConflict ? TriState::Unknown : history;
    if (historyConflict) {
        AddKey(limitations, SecurityLimitationKeys::kHistoricalConflict);
    }

    // S-05：pending 必须由来源明确给出，且那条证据本身得是当前的、采到的。
    for (const PendingActivationEvidence& evidence : input.pendingEvidence) {
        if (evidence.capability != capability || evidence.dimension != dimension) {
            continue;
        }
        const FieldAssessment* field = LookupField(fields, index, evidence.fieldId);
        if (field != nullptr && field->carriesObservation &&
            FreshnessUsableAsCurrent(field->freshness)) {
            build.result.pendingActivation = true;
            build.result.pendingEvidenceFieldId = evidence.fieldId;
            break;
        }
    }

    return build;
}

} // namespace

const FieldAssessment* SecurityStateReport::findField(std::string_view fieldId) const noexcept {
    for (const FieldAssessment& field : fields) {
        if (field.fieldId == fieldId) {
            return &field;
        }
    }
    return nullptr;
}

const CapabilityState* SecurityStateReport::findCapability(
    SecurityCapabilityId capability) const noexcept {
    for (const CapabilityState& state : capabilities) {
        if (state.capability == capability) {
            return &state;
        }
    }
    return nullptr;
}

const DimensionConflict* SecurityStateReport::findConflict(
    SecurityCapabilityId capability, SecurityDimension dimension) const noexcept {
    for (const DimensionConflict& conflict : conflicts) {
        if (conflict.capability == capability && conflict.dimension == dimension) {
            return &conflict;
        }
    }
    return nullptr;
}

bool SecurityStateReport::hasLimitation(std::string_view key) const noexcept {
    for (const std::string& limitation : limitationKeys) {
        if (limitation == key) {
            return true;
        }
    }
    return false;
}

SecurityStateReport EvaluateSecurityState(const SecurityStateInput& input) {
    SecurityStateReport report;
    std::vector<std::string> limitations;

    // --- 1. 逐字段评估 ------------------------------------------------------
    FieldIndex index;
    report.fields.reserve(input.fields.size());
    std::size_t currentObservedFields = 0;
    std::size_t staleObservedFields = 0;
    std::size_t failedFields = 0;
    std::size_t notCollectedFields = 0;
    bool needsAdministrator = false;
    bool needsSystem = false;
    bool needsDriver = false;

    for (const SecurityField& field : input.fields) {
        FieldAssessment assessment;
        assessment.fieldId = field.fieldId;
        assessment.queryEntry = field.queryEntry;
        assessment.source = field.source;
        assessment.window = field.window;
        assessment.outcome = field.outcome;
        assessment.raw = field.raw;                    // S-02：原样透传
        assessment.interpretation = field.interpretation;  // 规范化并列存放，不覆盖 raw
        assessment.access = field.access;
        assessment.freshness = ClassifyFieldFreshness(field.window, input.currentWindow);
        assessment.carriesObservation = StatusCarriesObservation(field.outcome.status);
        assessment.availability = ComputeAvailability(field.outcome, field.access, input.privilege);
        assessment.usableAsCurrent =
            assessment.carriesObservation && FreshnessUsableAsCurrent(assessment.freshness);

        if (assessment.carriesObservation) {
            // S-02：采集成功 ≠ 说明了当前状态。跨启动周期/跨机器/说不清是哪次启动的
            // 观测，对"现在是什么状态"这个问题没有贡献，账目里必须与当前观测分开，
            // 否则一份全是重启前数据的报告会算出"完整覆盖"，进而得出"未发现差异"。
            if (assessment.usableAsCurrent) {
                ++currentObservedFields;
            } else {
                ++staleObservedFields;
            }
        } else if (field.outcome.status == CollectionStatus::NotCollected) {
            ++notCollectedFields;
        } else {
            ++failedFields;
        }

        switch (assessment.availability) {
        case FieldAvailability::Readable:
            ++report.readableFieldCount;
            break;
        case FieldAvailability::BlockedByPrivilege:
        case FieldAvailability::BlockedByDriver:
            ++report.blockedFieldCount;
            break;
        case FieldAvailability::Unknown:
        case FieldAvailability::NotSupported:
        case FieldAvailability::QueryFailed:
        case FieldAvailability::NotCollected:
            break;
        }

        switch (assessment.freshness) {
        case FieldFreshness::Historical:
            ++report.historicalFieldCount;
            AddKey(limitations, SecurityLimitationKeys::kFieldHistorical);
            break;
        case FieldFreshness::DifferentMachine:
            AddKey(limitations, SecurityLimitationKeys::kFieldForeignMachine);
            break;
        case FieldFreshness::Unknown:
            AddKey(limitations, SecurityLimitationKeys::kFieldFreshnessUnknown);
            break;
        case FieldFreshness::Current:
            break;
        }

        // S-01：调用方已经尝试解释但没认出来 —— 报告里必须看得见"有未知枚举"。
        if (!assessment.interpretation.recognized &&
            (assessment.interpretation.rawCode.present || !assessment.interpretation.rawText.empty())) {
            AddKey(limitations, SecurityLimitationKeys::kUnknownEnumPreserved);
        }

        // S-07：Administrator 与 System 分开记。折在一起的话，"缺 SYSTEM"会被
        // 报成"缺管理员"，而在已经是管理员的会话里干脆什么都不报。
        if (field.access == AccessRequirement::Administrator) {
            needsAdministrator = true;
        }
        if (field.access == AccessRequirement::System) {
            needsSystem = true;
        }
        if (field.access == AccessRequirement::KswordDriver) {
            needsDriver = true;
        }

        const auto inserted = index.emplace(assessment.fieldId, report.fields.size());
        if (!inserted.second) {
            // 同一个 fieldId 出现两次：引用它的断言到底指哪一条说不清，必须报出来，
            // 并且把这个 id 标成歧义 —— 谁都指不到，好过按输入顺序随机指一条。
            AddKey(limitations, SecurityLimitationKeys::kFieldDuplicateId);
            inserted.first->second = kAmbiguousFieldIndex;
        }
        report.fields.push_back(std::move(assessment));
    }

    // S-07：降级要显式说明，而不是让页面看起来"就这么多字段"。
    if (needsAdministrator && input.privilege.administrator != TriState::Yes) {
        AddKey(limitations, SecurityLimitationKeys::kPrivilegeDegraded);
    }
    if (needsSystem && input.privilege.system != TriState::Yes) {
        AddKey(limitations, SecurityLimitationKeys::kSystemPrivilegeDegraded);
    }
    if (needsDriver && input.privilege.kswordDriverLoaded != TriState::Yes) {
        AddKey(limitations, SecurityLimitationKeys::kDriverDegraded);
    }

    // --- 2. 能力集合：期望的 + 断言里出现过的 -------------------------------
    std::vector<SecurityCapabilityId> order;
    const auto pushCapability = [&order](SecurityCapabilityId capability) {
        if (std::find(order.begin(), order.end(), capability) == order.end()) {
            order.push_back(capability);
        }
    };
    for (const SecurityCapabilityId capability : input.requestedCapabilities) {
        pushCapability(capability);
    }
    for (const CapabilityClaim& claim : input.claims) {
        pushCapability(claim.capability);
    }

    // --- 3. 逐能力四维 ------------------------------------------------------
    report.capabilities.reserve(order.size());
    for (const SecurityCapabilityId capability : order) {
        CapabilityState state;
        state.capability = capability;

        std::vector<std::string> backingFieldIds;
        // 去重用哈希集合而不是在向量上线性查找：同一能力下的断言条数由调用方决定，
        // 逐策略 / 逐设备枚举时 std::find 的 O(n^2) 会直接变成秒级卡顿。
        std::unordered_set<std::string> backingFieldSeen;
        const SecurityDimension dimensions[] = {SecurityDimension::HardwareSupport,
                                                SecurityDimension::Configured,
                                                SecurityDimension::Running};
        DimensionResult* slots[] = {&state.hardwareSupport, &state.configured, &state.running};
        for (std::size_t i = 0; i < 3U; ++i) {
            DimensionBuildResult build =
                BuildDimension(capability, dimensions[i], input, report.fields, index, limitations);
            for (const std::string& fieldId : build.backingFieldIds) {
                if (backingFieldSeen.insert(fieldId).second) {
                    backingFieldIds.push_back(fieldId);
                }
            }
            state.anyClaim = state.anyClaim || !build.result.claims.empty();
            for (const SourceClaimView& view : build.result.claims) {
                if (view.backed && view.carriesObservation) {
                    state.anyBackedObservation = true;
                }
            }
            *slots[i] = std::move(build.result);
        }

        // S-07：能力级权限说明来自它的支撑字段，不是拍脑袋。
        std::vector<const CollectionOutcome*> outcomes;
        outcomes.reserve(backingFieldIds.size());
        for (const std::string& fieldId : backingFieldIds) {
            const FieldAssessment* field = LookupField(report.fields, index, fieldId);
            if (field == nullptr) {
                continue;
            }
            outcomes.push_back(&field->outcome);
            if (field->access == AccessRequirement::Administrator) {
                state.requiresAdministrator = true;
            }
            if (field->access == AccessRequirement::System) {
                state.requiresSystem = true;
            }
            if (field->access == AccessRequirement::KswordDriver) {
                state.requiresKswordDriver = true;
            }
            if (field->availability == FieldAvailability::BlockedByPrivilege ||
                field->availability == FieldAvailability::BlockedByDriver) {
                ++state.blockedFieldCount;
            }
        }
        bool mixedFailures = false;
        state.queryOutcome = AggregateOutcomes(outcomes, &mixedFailures);
        if (mixedFailures) {
            // 摘要必然只留下了其中一种失败，这件事要在报告里看得见。
            AddKey(limitations, SecurityLimitationKeys::kOutcomeMixedFailures);
        }

        if (!state.anyClaim) {
            // 被期望覆盖却整轮缺席：显式落成 NotCollected 并计进账目，
            // 绝不静默跳过 —— 否则这一轮会看着"干干净净全都可用"。
            ++report.missingCapabilityCount;
            AddKey(limitations, SecurityLimitationKeys::kCapabilityNotCollected);
        }

        // S-03：测量日志拿不到就是 Unknown，绝不输出"Measured Boot 正常"。
        if (capability == SecurityCapabilityId::MeasuredBootLog &&
            state.running.value == TriState::Unknown) {
            AddKey(limitations, SecurityLimitationKeys::kMeasuredBootLogUnknown);
        }

        // --- 冲突单独成表 ---
        // 当前来源打架和重启前来源打架都要进表：后者如果只塌成 historicalValue=Unknown，
        // UI 上与"没有历史证据"完全一样，S-05"不一致时同时展示全部来源"就落空了。
        for (std::size_t i = 0; i < 3U; ++i) {
            const DimensionResult& result = state.dimension(dimensions[i]);
            if (!result.conflicted && !result.historicalConflicted) {
                continue;
            }
            DimensionConflict conflict;
            conflict.capability = capability;
            conflict.dimension = dimensions[i];
            conflict.claims = result.claims;  // 全部来源并排，不筛选
            conflict.resolvedValue = TriState::Unknown;
            conflict.currentConflict = result.conflicted;
            conflict.historicalConflict = result.historicalConflicted;
            conflict.pendingActivation = result.pendingActivation;
            conflict.pendingEvidenceFieldId = result.pendingEvidenceFieldId;
            report.conflicts.push_back(std::move(conflict));
            if (result.conflicted) {
                AddKey(limitations, SecurityLimitationKeys::kDimensionConflict);
            }
        }

        report.capabilities.push_back(std::move(state));
    }

    // --- 4. 账目与结论 ------------------------------------------------------
    // 账目单位是"对当前平台安全状态的预期证据项"：每个字段一项，外加每个整轮缺席
    // 的能力一项。succeeded 只数**当前启动周期的成功观测**；采集成功但属于别的启动
    // 周期/别的机器的观测计入 skipped，它们回答不了"现在是什么状态"。
    CoverageAccount coverage;
    coverage.totalKnown = OptionalU64::of(
        static_cast<std::uint64_t>(input.fields.size() + report.missingCapabilityCount));
    coverage.succeeded = static_cast<std::uint64_t>(currentObservedFields);
    coverage.failed = static_cast<std::uint64_t>(failedFields);
    coverage.skipped = static_cast<std::uint64_t>(notCollectedFields + staleObservedFields +
                                                  report.missingCapabilityCount);

    std::vector<const CollectionOutcome*> allOutcomes;
    allOutcomes.reserve(report.fields.size());
    std::vector<EvidenceEnvelope> fieldEnvelopes;
    fieldEnvelopes.reserve(report.fields.size());
    bool originUniform = !report.fields.empty();
    SourceOrigin commonOrigin = SourceOrigin::Unknown;
    for (const FieldAssessment& field : report.fields) {
        allOutcomes.push_back(&field.outcome);
        if (&field == &report.fields.front()) {
            commonOrigin = field.source.origin;
        } else if (field.source.origin != commonOrigin) {
            originUniform = false;
        }
        EvidenceEnvelope envelope;
        envelope.source = field.source;
        envelope.window = field.window;
        envelope.outcome = field.outcome;
        envelope.coverage.totalKnown = OptionalU64::of(1U);
        // 与上面同样的口径：只有当前启动周期的观测才算这条字段"覆盖到了"。
        envelope.coverage.succeeded = field.usableAsCurrent ? 1U : 0U;
        envelope.coverage.failed = field.carriesObservation ? 0U : 1U;
        envelope.coverage.skipped =
            (field.carriesObservation && !field.usableAsCurrent) ? 1U : 0U;
        envelope.evidenceId = field.fieldId;
        fieldEnvelopes.push_back(std::move(envelope));
    }

    report.envelope.source.collectorId = "s.security.state";
    report.envelope.source.sourceGroup = "s.security.state";
    report.envelope.source.collectorVersion = 1U;
    // 混源时报告级 origin 保持 Unknown —— 由 trust 逐类计数说明各来自哪里，
    // 挑一个"主要来源"填上去会让离线样本混进来的那部分看不见（F-11）。
    report.envelope.source.origin = originUniform ? commonOrigin : SourceOrigin::Unknown;
    report.envelope.window = input.currentWindow;
    report.envelope.outcome = AggregateOutcomes(allOutcomes);
    report.envelope.coverage = coverage;
    report.conclusion = report.envelope.deriveConclusion(!report.conflicts.empty());
    report.trust = BuildTrustStatement(fieldEnvelopes);

    SortUniqueKeys(limitations);
    report.limitationKeys = std::move(limitations);
    return report;
}

} // namespace Ksword::Evidence
