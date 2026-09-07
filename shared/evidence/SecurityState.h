#pragma once

// S 模块：平台安全状态与原因解释。
//
// 这一层只做**状态模型**，不查 WMI、不读注册表、不碰 Win32。查询在既有 Qt 页面里，
// 它们把查到的原始值塞进 SecurityField，本层负责回答四个问题：
//   1. 这个能力硬件/系统支持吗？（hardwareSupport）
//   2. 配置成开了吗？（configured）
//   3. 现在真的在跑吗？（running）
//   4. 上面三条各自的证据是怎么来的、查成功了没有？（queryOutcome + 逐字段 outcome）
//
// 贯穿全模块的硬规则（照 S-01…S-08 逐条落）：
//   * S-01 四维互不推导。Win32_DeviceGuard 的 SecurityServicesConfigured 与
//     SecurityServicesRunning 是两个属性，本层没有任何一行代码把其中一个抄给另一个；
//     hardwareSupport 也不从 configured/running 反推。
//   * S-01 查询失败 ≠ 关闭。一条断言（CapabilityClaim）只有在它指向的字段
//     **真的携带观测**时才会被采纳；否则该维保持 Unknown，断言本身仍然原样列出来
//     供人看，但不参与定值。所以 AccessDenied / Timeout / Unsupported 永远不会
//     变成 TriState::No。
//   * S-01 未知枚举原样保留。Interpret* 系列对不认识的编码返回
//     recognized=false，同时把 rawCode / rawText 原封不动带上，绝不猜一个最近的
//     已知值，也绝不落成 0。
//   * S-02 规范化不覆盖原始值。FieldAssessment 同时持有 RawObservation 与
//     EnumInterpretation，两者是并列字段而不是"解析后替换"。
//   * S-02 重启前的状态不是当前值。用 CaptureWindow.bootId 判定新鲜度：跨 bootId
//     的定值只进 historicalValue，绝不进 value。
//   * S-05 多来源不一致时同时展示全部来源的值，resolved 恒为 Unknown。本层没有
//     任何"取有利值 / 取最新值 / 取内核值优先"的仲裁分支。
//   * S-05 pending 必须有正面证据。只有来源明确给出待重启/待生效字段，且该字段
//     携带观测且属于当前启动周期，才会标 pendingActivation。
//   * S-06 只陈述约束，不给修复建议。KswordCapabilityExplanation 里**没有**
//     remediation / suggestion / fixAction 之类字段；约束键还要过
//     IsStatementOnlyConstraintKey 这道词表闸，带 disable/turnoff 之类动作词的键
//     会被拒收并记进 limitationKeys。词表闸按**词**匹配而不是按子串匹配，
//     否则 "hvci.notDisabled"、"driver.uninstalled" 这类陈述键会被自己的闸拦掉，
//     而真正的建议键反而借着 fall-through 把能力放行（见 ExplainKswordCapability）。
//   * S-06 约束在场却一条都判不了时，可用性回落 Unknown。约束是"拦住能力"的那一侧，
//     采不到约束证据只能说明"说不清"，绝不能让来源自称的 observedAvailable=Yes
//     直接放行 —— 那正是"从没采到推出正常"。
//   * S-07 权限精确到字段。无管理员时 AccessRequirement::None 的字段照样是
//     Readable，报告不会整体清空。Administrator 与 System 是两档，各由
//     PrivilegeContext 里各自的三态门控，不共用一个 administrator 判据。
//
// 本层不产出"系统安全""已加固""有威胁"这类结论，也不做远程证明推导。

#include "EvidenceEnvelope.h"
#include "LosslessValue.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// S-01：三态。bool 表达不了"没查到"，所以这一层一律不用 bool 表达状态。
// Unknown 放在 0 位，是为了让任何默认构造的状态都是"未知"而不是"关闭"。
// ---------------------------------------------------------------------------
enum class TriState {
    Unknown,  // 没有可用证据
    No,       // 有证据表明否
    Yes,      // 有证据表明是
};

const char* TriStateName(TriState value) noexcept;

// 只有 Yes/No 是"定值"。Unknown 不参与一致性比较，也不会与任何值构成冲突。
bool TriStateIsDefinite(TriState value) noexcept;

// ---------------------------------------------------------------------------
// S-01 / S-03 / S-04：能力清单。启动安全那几项被拆成独立能力，就是为了满足
// S-03"Secure Boot / TPM 存在 / TPM 就绪 / 测量日志分开表达"。
// ---------------------------------------------------------------------------
enum class SecurityCapabilityId {
    Unknown,
    VirtualizationBasedSecurity,
    HypervisorEnforcedCodeIntegrity,
    CredentialGuard,
    SystemGuardSecureLaunch,
    KernelDmaProtection,
    SecureBoot,
    TpmPresence,          // TPM 在不在
    TpmReadiness,         // TPM 就不就绪 —— 与"在不在"是两回事
    MeasuredBootLog,      // 测量日志能不能拿到 —— 拿不到就是 Unknown，不是"正常"
    KernelModeCodeIntegrityPolicy,
    UserModeCodeIntegrityPolicy,
    TestSigning,
};

const char* SecurityCapabilityName(SecurityCapabilityId capability) noexcept;

// S-01：四维中的前三维。第四维 queryOutcome 是 CollectionOutcome，不在这个枚举里，
// 因为它描述的是"采集这件事"，不是"能力的状态"。
enum class SecurityDimension {
    HardwareSupport,  // 硬件/系统是否具备该能力
    Configured,       // 是否被配置为启用
    Running,          // 是否正在运行
};

const char* SecurityDimensionName(SecurityDimension dimension) noexcept;

// ---------------------------------------------------------------------------
// S-02：原始值与规范化解释并列存放。
// ---------------------------------------------------------------------------

// 来源原文。numeric 只在来源本身给的就是数值时才填；文本型字段保持 unset，
// 不做"看着像数字就转一下"的隐式转换 —— 那会把 "0x2" 和 "2" 混成一个值。
struct RawObservation final {
    std::string text;
    OptionalU64 numeric;

    bool empty() const noexcept { return text.empty() && !numeric.present; }
};

// 枚举规范化结果。recognized=false 表示"这个编码我不认识"，此时 normalizedName
// 必须为空 —— 不许拿一个"最接近的"已知名字冒充。rawCode/rawText 无论认不认识
// 都原样保留（S-01 通过条件："新枚举值保留原值且不错误解释"）。
struct EnumInterpretation final {
    bool recognized = false;
    std::string normalizedName;
    OptionalU64 rawCode;
    std::string rawText;
};

// --- Win32_DeviceGuard.SecurityServicesConfigured / SecurityServicesRunning ---
// 依据 Microsoft VBS/Device Guard 文档中公开的编码。注意：这两个属性共用同一张
// 编码表，但**取值来自两个不同的属性**，本层的解释函数不关心它来自哪一个，
// 调用方必须把它们分别填进 Configured / Running 两个维度。
enum class DeviceGuardService {
    Unknown,
    None,
    CredentialGuard,
    HypervisorEnforcedCodeIntegrity,
    SystemGuardSecureLaunch,
    SmmFirmwareMeasurement,
};

const char* DeviceGuardServiceName(DeviceGuardService service) noexcept;

struct DeviceGuardServiceValue final {
    DeviceGuardService service = DeviceGuardService::Unknown;
    EnumInterpretation interpretation;
};

DeviceGuardServiceValue InterpretDeviceGuardService(const RawObservation& raw);

// --- Win32_DeviceGuard.VirtualizationBasedSecurityStatus ---
enum class VbsStatus {
    Unknown,
    Disabled,
    EnabledNotRunning,
    EnabledAndRunning,
};

const char* VbsStatusName(VbsStatus status) noexcept;

struct VbsStatusValue final {
    VbsStatus status = VbsStatus::Unknown;
    EnumInterpretation interpretation;
};

VbsStatusValue InterpretVbsStatus(const RawObservation& raw);

// S-01 的核心分离点：一个 VBS 状态码同时说明了"配置"和"运行"两件事，本函数把它
// 拆成两个**独立输出**。EnabledNotRunning 给出 configured=Yes / running=No，
// 绝不会因为"配置了"就把 running 也写成 Yes。未知/无法识别时两个输出都是 Unknown，
// 不会把"查不出来"落成 No。
void VbsStatusToDimensions(VbsStatus status, TriState& configured, TriState& running) noexcept;

// --- Win32_DeviceGuard.AvailableSecurityProperties / RequiredSecurityProperties ---
enum class SecurityProperty {
    Unknown,
    None,
    BaseVirtualizationSupport,
    SecureBoot,
    DmaProtection,
    SecureMemoryOverwrite,
    NxProtections,
    SmmMitigations,
    ModeBasedExecutionControl,
    ApicVirtualization,
};

const char* SecurityPropertyName(SecurityProperty property) noexcept;

struct SecurityPropertyValue final {
    SecurityProperty property = SecurityProperty::Unknown;
    EnumInterpretation interpretation;
};

SecurityPropertyValue InterpretSecurityProperty(const RawObservation& raw);

// --- S-04：CodeIntegrityPolicyEnforcementStatus / Usermode... ---
enum class CodeIntegrityEnforcement {
    Unknown,
    Off,
    Audit,
    Enforced,
};

const char* CodeIntegrityEnforcementName(CodeIntegrityEnforcement enforcement) noexcept;

struct CodeIntegrityEnforcementValue final {
    CodeIntegrityEnforcement enforcement = CodeIntegrityEnforcement::Unknown;
    EnumInterpretation interpretation;
};

CodeIntegrityEnforcementValue InterpretCodeIntegrityEnforcement(const RawObservation& raw);

// ---------------------------------------------------------------------------
// S-02：新鲜度。跨启动周期的状态是历史，不是当前值。
// ---------------------------------------------------------------------------
enum class FieldFreshness {
    Unknown,          // 缺 bootId，说不清是哪一次启动的数据
    Current,          // 与当前启动周期一致
    Historical,       // 明确来自另一个启动周期（重启前的状态）
    DifferentMachine, // machineId 都在场且不同 —— 根本不是这台机器
};

const char* FieldFreshnessName(FieldFreshness freshness) noexcept;

// 判定顺序：先看机器，再看启动周期。任一 bootId 缺失就是 Unknown —— 缺失不能
// 乐观地当成"就是当前这次启动"。
FieldFreshness ClassifyFieldFreshness(const CaptureWindow& field,
                                      const CaptureWindow& current) noexcept;

// 只有 Current 才允许当作"现在的状态"。Unknown 也不行：说不清就是说不清。
bool FreshnessUsableAsCurrent(FieldFreshness freshness) noexcept;

// ---------------------------------------------------------------------------
// S-07：权限降级。要求精确到字段。
// ---------------------------------------------------------------------------
enum class AccessRequirement {
    Unknown,        // 没声明 —— 报告里照实说"未声明"，不假定是 None
    None,           // 普通用户可读
    Administrator,  // 需要管理员
    System,         // 需要 SYSTEM/TCB 级
    KswordDriver,   // 需要本工具驱动已加载
};

const char* AccessRequirementName(AccessRequirement requirement) noexcept;

struct PrivilegeContext final {
    TriState administrator = TriState::Unknown;
    // S-07：SYSTEM/TCB 与 Administrator 是两档权限。没有这一项时
    // AccessRequirement::System 的字段就只能靠 administrator 冒充判断，
    // "需要 SYSTEM 却没跑"会被说成"只是没跑"。默认 Unknown = 没声明 = 不当作具备。
    TriState system = TriState::Unknown;
    TriState kswordDriverLoaded = TriState::Unknown;
};

// 字段在当前上下文里的可读性。它是路由用的粗粒度值，**不替代** outcome.status ——
// Timeout 与 Error 都落到 QueryFailed，但 FieldAssessment.outcome 仍然分别保留了
// 原始 status、nativeCode 和 message（防止五种失败语义被塌成一个）。
enum class FieldAvailability {
    Unknown,
    Readable,            // 拿到了观测
    BlockedByPrivilege,  // 权限不足（被拒，或声明需要更高权限且当前没有）
    BlockedByDriver,     // 需要本工具驱动而驱动不在
    NotSupported,        // 当前 OS/硬件不提供
    QueryFailed,         // 权限够但查询失败（超时/错误）
    NotCollected,        // 没跑，且没有权限原因可解释
};

const char* FieldAvailabilityName(FieldAvailability availability) noexcept;

// ---------------------------------------------------------------------------
// 输入：字段
// ---------------------------------------------------------------------------

// 一个安全状态字段的一次采集。fieldId 是稳定标识，claim 与 pending 证据都靠它引用。
struct SecurityField final {
    std::string fieldId;
    // S-02：具体查询入口原文。例如
    // "WMI root\\Microsoft\\Windows\\DeviceGuard:Win32_DeviceGuard.SecurityServicesRunning"
    // 或 "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard:EnableVirtualizationBasedSecurity"。
    std::string queryEntry;
    SourceRef source;
    CaptureWindow window;
    CollectionOutcome outcome;
    RawObservation raw;
    EnumInterpretation interpretation;  // 调用方用上面的 Interpret* 填；不填即"未解释"
    AccessRequirement access = AccessRequirement::Unknown;
};

// 输出：字段评估。raw / interpretation 原样透传，评估只**追加**判断，不改写来源数据。
struct FieldAssessment final {
    std::string fieldId;
    std::string queryEntry;
    SourceRef source;
    CaptureWindow window;
    CollectionOutcome outcome;
    RawObservation raw;
    EnumInterpretation interpretation;
    AccessRequirement access = AccessRequirement::Unknown;
    FieldAvailability availability = FieldAvailability::Unknown;
    FieldFreshness freshness = FieldFreshness::Unknown;
    bool carriesObservation = false;
    bool usableAsCurrent = false;  // carriesObservation && freshness == Current

    // 供导出/UI 使用的事实串，只陈述观测，不含任何结论词。
    std::string describe() const;
};

// ---------------------------------------------------------------------------
// 输入：断言与待生效证据
// ---------------------------------------------------------------------------

// 某来源对"某能力的某一维"给出的一次断言。fieldId 必须指向一个 SecurityField ——
// 指不到就是无支撑断言，会被原样列出但不参与定值（防止"结论没有来源"）。
struct CapabilityClaim final {
    SecurityCapabilityId capability = SecurityCapabilityId::Unknown;
    SecurityDimension dimension = SecurityDimension::HardwareSupport;
    TriState value = TriState::Unknown;
    std::string fieldId;
};

// S-05：待重启/待生效证据。必须由来源明确给出，本层不从"不一致"倒推重启需求。
struct PendingActivationEvidence final {
    SecurityCapabilityId capability = SecurityCapabilityId::Unknown;
    SecurityDimension dimension = SecurityDimension::HardwareSupport;
    std::string fieldId;  // 明确给出待生效证据的字段
    std::string rawText;  // 来源原文，例如 "PendingReboot=1"
};

// 输出：一条断言在报告里的样子。冲突时所有来源的值都留在这里，一个都不丢。
struct SourceClaimView final {
    std::string fieldId;
    std::string sourceGroup;  // 独立来源分组键（取 SourceRef.sourceGroup，空则退回 collectorId）
    SourceOrigin origin = SourceOrigin::Unknown;
    TriState value = TriState::Unknown;  // 该来源断言的值，原样保留
    FieldFreshness freshness = FieldFreshness::Unknown;
    bool backed = false;          // fieldId 解析到了字段
    bool carriesObservation = false;
    bool usableAsCurrent = false; // 只有它为真，value 才参与定值
};

// 一个维度的结论。
struct DimensionResult final {
    SecurityDimension dimension = SecurityDimension::HardwareSupport;

    // 当前值。只由 usableAsCurrent 的定值断言产生；有冲突时恒为 Unknown。
    TriState value = TriState::Unknown;
    // 跨启动周期的历史定值，单独展示，永远不会被当成 value（S-02）。
    TriState historicalValue = TriState::Unknown;

    std::vector<SourceClaimView> claims;  // 全部来源，含无支撑与历史的
    bool conflicted = false;              // 可用来源之间定值不一致
    // S-05：重启前的多个来源之间也可能互相打架。没有这一位时两条互相矛盾的历史定值
    // 会一起塌成 historicalValue=Unknown，与"根本没有历史证据"在报告里长得一模一样。
    bool historicalConflicted = false;
    std::size_t definiteClaimCount = 0;   // 参与定值的断言条数
    // 独立来源分组数。sourceGroup 与 collectorId 都为空的来源不与别人合并 ——
    // 两个都没署名的来源是两个来源，不是一个（否则 F-11 的"N 个独立来源"会虚报）。
    std::size_t distinctSourceGroupCount = 0;

    bool pendingActivation = false;       // 只有拿到明确的待生效证据才为真
    std::string pendingEvidenceFieldId;
};

// S-01：一个能力的四维状态。三个 DimensionResult 是三份独立数据，
// 本类型没有任何成员函数会用其中一个去填另一个。
struct CapabilityState final {
    SecurityCapabilityId capability = SecurityCapabilityId::Unknown;
    DimensionResult hardwareSupport;
    DimensionResult configured;
    DimensionResult running;

    // 第四维：这一能力相关字段的采集结果汇总。没有任何断言时是 NotCollected，
    // 而不是"没问题"。
    CollectionOutcome queryOutcome;

    bool anyClaim = false;             // 是否收到过任何断言（哪怕是无支撑的）
    bool anyBackedObservation = false; // 是否有任何支撑字段真的携带观测

    // S-07：能力级权限说明，来自其支撑字段声明的要求。Administrator 与 System
    // 分开标：把 System 折进 requiresAdministrator 会让"需要 TCB"这一档消失。
    bool requiresAdministrator = false;
    bool requiresSystem = false;
    bool requiresKswordDriver = false;
    std::size_t blockedFieldCount = 0;

    const DimensionResult& dimension(SecurityDimension which) const noexcept;
};

// S-05：一次维度级冲突。claims 里是**全部**来源的值，调用方原样并排展示。
// resolvedValue 恒为 TriState::Unknown —— 这个字段存在的意义就是把"我不替你选"
// 写进类型里，而不是留给调用方去猜。
struct DimensionConflict final {
    SecurityCapabilityId capability = SecurityCapabilityId::Unknown;
    SecurityDimension dimension = SecurityDimension::HardwareSupport;
    std::vector<SourceClaimView> claims;
    TriState resolvedValue = TriState::Unknown;
    // 当前启动周期的来源互相矛盾 / 重启前的来源互相矛盾。两者都可能单独成立，
    // 所以是两位而不是一个枚举 —— 调用方要能说清"打架的是现在还是重启前"。
    bool currentConflict = false;
    bool historicalConflict = false;
    bool pendingActivation = false;
    std::string pendingEvidenceFieldId;
};

// ---------------------------------------------------------------------------
// S-04：WDAC / 代码完整性
// ---------------------------------------------------------------------------

// 一条策略。策略"配置在磁盘上"与"当前实际生效"是两个列表，不共用。
struct CodeIntegrityPolicyRecord final {
    std::string policyId;      // GUID 原文，不做大小写归一（避免覆盖原始值）
    std::string friendlyName;
    RawObservation enforcementRaw;  // 该策略自己的 audit/enforced 原始编码
    TriState basePolicy = TriState::Unknown;
    std::string sourceFieldId;
};

// 评估后的策略：解释与原始值并列。
struct CodeIntegrityPolicyView final {
    std::string policyId;
    std::string friendlyName;
    CodeIntegrityEnforcement enforcement = CodeIntegrityEnforcement::Unknown;
    EnumInterpretation enforcementInterpretation;
    TriState basePolicy = TriState::Unknown;
    std::string sourceFieldId;
};

struct CodeIntegrityInput final {
    // 配置口径：磁盘上摆着的策略文件。
    CollectionOutcome configuredOutcome;
    std::vector<CodeIntegrityPolicyRecord> configuredPolicies;
    // 有效口径：运行时列举出来的、真正生效的策略。
    CollectionOutcome effectiveOutcome;
    std::vector<CodeIntegrityPolicyRecord> effectivePolicies;
    // 全局执行状态（内核态 / 用户态各一个属性）。
    RawObservation kernelModeRaw;
    CollectionOutcome kernelModeOutcome;
    RawObservation userModeRaw;
    CollectionOutcome userModeOutcome;
};

struct CodeIntegrityAssessment final {
    std::vector<CodeIntegrityPolicyView> configuredPolicies;
    CollectionOutcome configuredOutcome;
    bool configuredPolicyKnown = false;

    std::vector<CodeIntegrityPolicyView> effectivePolicies;
    CollectionOutcome effectiveOutcome;
    // S-04 通过条件："查不到实际策略状态时保留未知"。查不到时这里是 false，
    // effectivePolicies 保持空 —— 绝不拿 configuredPolicies 顶替。
    bool effectivePolicyKnown = false;

    CodeIntegrityEnforcement kernelModeEnforcement = CodeIntegrityEnforcement::Unknown;
    EnumInterpretation kernelModeInterpretation;
    CodeIntegrityEnforcement userModeEnforcement = CodeIntegrityEnforcement::Unknown;
    EnumInterpretation userModeInterpretation;

    std::vector<std::string> limitationKeys;

    std::size_t auditPolicyCount() const noexcept;
    std::size_t enforcedPolicyCount() const noexcept;
};

CodeIntegrityAssessment EvaluateCodeIntegrity(const CodeIntegrityInput& input);

// S-04："签名有效 ≠ 当前策略允许加载"。这两件事在类型上就是两个字段，各自由
// 各自的 outcome 支撑；EvaluateImageLoad 不会用其中一个推另一个。
struct ImageLoadInput final {
    std::string imagePath;
    TriState signatureValid = TriState::Unknown;
    CollectionOutcome signatureOutcome;
    TriState policyAllowsLoad = TriState::Unknown;
    CollectionOutcome policyDecisionOutcome;
};

struct ImageLoadAssessment final {
    std::string imagePath;
    TriState signatureValid = TriState::Unknown;
    TriState allowedByCurrentPolicy = TriState::Unknown;
    CollectionOutcome signatureOutcome;
    CollectionOutcome policyDecisionOutcome;
    std::vector<std::string> limitationKeys;
};

ImageLoadAssessment EvaluateImageLoad(const ImageLoadInput& input);

// ---------------------------------------------------------------------------
// S-06：KSword 能力为什么不可用
// ---------------------------------------------------------------------------
enum class CapabilityConstraintKind {
    Unknown,
    VendorUnsupported,      // CPU 厂商侧后端缺失（AMD/Intel 分别表示）
    HardwareUnsupported,    // 硬件本身不具备
    DriverMissing,          // 本工具驱动未加载
    ProfileMissing,         // 偏移表 / profile 缺失
    SecurityConfiguration,  // 平台安全配置不允许（例如 HVCI 在跑）
    PrivilegeInsufficient,  // 权限不足
    QueryUnavailable,       // 相关状态查不到，无法判断
};

const char* CapabilityConstraintKindName(CapabilityConstraintKind kind) noexcept;

// S-06：约束键必须是**陈述**（"当前 HVCI 正在运行"），不能是**动作建议**
// （"去关闭内存完整性"）。这道词表闸是防回归用的：以后有人想把修复建议塞进
// 这一层，键会被拒收并留下 limitation，而不是悄悄通过。
//
// 匹配按**词**做，不按子串做。键先在 '.'/'-'/'_'/' '/'/'/':' 上切成段，段内再按
// camelCase 切成词；命中判据是"某个词恰好等于动作词"，或"相邻至多三个词拼起来
// 等于动作词"（覆盖 turn-off / please-turn / how-to-fix 这类被分隔符拆开的写法），
// 或"某个词以动作词开头"（覆盖 suggestion / remediation 这类派生名词）。
// 命中后还有一道时态豁免，且**只对动作动词生效**：命中词本身是 -ed 过去分词
// （uninstalled、disabled），或命中词在同一段里紧跟着一个 -ed/-ing 词
// （bypassDetected、shutdownPending），都判为**陈述**而不是祈使句。
// recommend / suggest / howToFix 这类劝说词不享受豁免（suggested 还是建议）；
// 动名词也不享受第一种豁免，否则 "fix.byDisablingHvci" 会溜进来。
// 子串匹配做不到这一点：它会把
// "hvci.notDisabled"、"dse.isDisabledByPolicy"、"driver.uninstalled"、
// "smm.shutdownPending"、"bypassDetected" 全部当成动作键拒收，
// 于是这些真正的约束一条都进不了 accepted，能力反而被 observedAvailable 放行。
bool IsStatementOnlyConstraintKey(std::string_view key) noexcept;

struct KswordCapabilityConstraint final {
    CapabilityConstraintKind kind = CapabilityConstraintKind::Unknown;
    std::string constraintKey;  // i18n 键
    std::string sourceFieldId;  // 这个约束是从哪个字段看出来的
    RawObservation observed;    // 该字段的原始值
};

struct KswordCapabilityConstraintView final {
    CapabilityConstraintKind kind = CapabilityConstraintKind::Unknown;
    std::string constraintKey;
    std::string sourceFieldId;
    RawObservation observed;
    bool backed = false;    // sourceFieldId 解析到了字段且该字段携带观测
    bool accepted = false;  // 键通过词表闸且有来源字段
};

struct KswordCapabilityInput final {
    std::string capabilityId;  // 例如 "kvm.ept.view"
    // 来源直接观测到的"能不能用"。只有 availabilityOutcome 携带观测时才被采纳。
    TriState observedAvailable = TriState::Unknown;
    CollectionOutcome availabilityOutcome;
    std::vector<KswordCapabilityConstraint> constraints;
};

// 注意：本结构故意**没有** remediation / suggestedAction / howToFix 字段。
// S-06 通过条件明确禁止把"禁用保护"作为默认修复给出去。
//
// available 的判定顺序（越靠前越优先）：
//   1. 有任一约束被采纳 -> No。来源同时声称可用是矛盾，记 kConstraintConflict。
//   2. 有约束但一条都没被采纳（键被拒 / 来源字段没采到 / 指不到字段），
//      且来源声称 observedAvailable=Yes -> Unknown，记 kConstraintIndeterminate。
//      拦路的证据自己没采到就不能放行 —— 这是"查询失败 ≠ 正常"在 S-06 的落点。
//      来源声称 No 时保留 No：那是正面的不可用证据，不必抹成 Unknown。
//   3. 没有任何约束且可用性查询携带观测 -> 采纳 observedAvailable。
//   4. 其余 -> Unknown。
struct KswordCapabilityExplanation final {
    std::string capabilityId;
    TriState available = TriState::Unknown;
    std::vector<KswordCapabilityConstraintView> constraints;
    std::vector<std::string> rejectedConstraintKeys;
    std::vector<std::string> limitationKeys;

    // S-06 通过条件："不能运行的能力不会启动"。Unknown 同样不允许启动 ——
    // 只有明确 Yes 才放行。
    bool mayStart() const noexcept;
};

KswordCapabilityExplanation ExplainKswordCapability(const KswordCapabilityInput& input,
                                                    const std::vector<FieldAssessment>& fields);

// ---------------------------------------------------------------------------
// S-08：实测配置清单
// ---------------------------------------------------------------------------
struct VerifiedConfiguration final {
    std::string configurationId;
    std::string osBuildRaw;  // 原始 build 串，不解析成数字（避免丢掉 "26100.1234" 这种形态）
    TriState vbsRunning = TriState::Unknown;
    TriState hvciRunning = TriState::Unknown;
    TriState kswordDriverLoaded = TriState::Unknown;
    std::string evidenceFieldId;
};

enum class SupportClaimStatus {
    Blocked,            // 还不够两套配置 —— 规范要求保留 BLOCKED
    PartiallyVerified,  // 只核对了其中一套
    Verified,           // 普通配置与 VBS/HVCI 运行配置各一套都核对过
};

const char* SupportClaimStatusName(SupportClaimStatus status) noexcept;

struct SupportClaim final {
    SupportClaimStatus status = SupportClaimStatus::Blocked;
    bool baselineConfigurationVerified = false;  // VBS 未运行的一套
    bool vbsConfigurationVerified = false;       // VBS/HVCI 在运行的一套
    std::vector<std::string> acceptedConfigurationIds;
    std::vector<std::string> rejectedConfigurationIds;  // 缺 build / 缺证据 / 状态未知
    std::vector<std::string> limitationKeys;
};

// 默认（空清单）是 Blocked：没记录 = 没核对，不是"都支持"。
SupportClaim EvaluateSupportClaim(const std::vector<VerifiedConfiguration>& configurations);

// ---------------------------------------------------------------------------
// 顶层评估
// ---------------------------------------------------------------------------
struct SecurityStateInput final {
    // 当前启动周期基准。bootId 为空时所有字段的新鲜度都判 Unknown（说不清）。
    CaptureWindow currentWindow;
    PrivilegeContext privilege;
    std::vector<SecurityField> fields;
    std::vector<CapabilityClaim> claims;
    std::vector<PendingActivationEvidence> pendingEvidence;

    // 本轮**期望**覆盖的能力。一个被期望却一条断言都没有的能力，会显式产出一份
    // 全 Unknown / queryOutcome=NotCollected 的状态并计进账目 —— 绝不静默跳过，
    // 否则"整轮缺席"会让报告看着干干净净。
    std::vector<SecurityCapabilityId> requestedCapabilities;
};

struct SecurityStateReport final {
    std::vector<FieldAssessment> fields;
    std::vector<CapabilityState> capabilities;
    std::vector<DimensionConflict> conflicts;

    // envelope.coverage 的单位是"对当前平台安全状态的预期证据项"：每个字段一项，
    // 外加每个整轮缺席的能力一项。succeeded 只数**当前启动周期的成功观测**；
    // 采集成功但来自另一个启动周期或另一台机器的观测计进 skipped —— 它们回答不了
    // "现在是什么状态"，据此判完整覆盖会让一份全是重启前数据的报告得出"未发现差异"。
    EvidenceEnvelope envelope;
    AnalysisConclusion conclusion = AnalysisConclusion::NoEvidence;
    TrustStatement trust;
    std::vector<std::string> limitationKeys;  // 已排序去重

    std::size_t readableFieldCount = 0;
    std::size_t blockedFieldCount = 0;      // 权限/驱动导致读不到
    std::size_t historicalFieldCount = 0;
    std::size_t missingCapabilityCount = 0; // 期望覆盖却一条断言都没有的能力数

    const FieldAssessment* findField(std::string_view fieldId) const noexcept;
    const CapabilityState* findCapability(SecurityCapabilityId capability) const noexcept;
    const DimensionConflict* findConflict(SecurityCapabilityId capability,
                                          SecurityDimension dimension) const noexcept;
    bool hasLimitation(std::string_view key) const noexcept;
};

SecurityStateReport EvaluateSecurityState(const SecurityStateInput& input);

// 报告里用到的 limitation 键。集中列出来，UI 侧照这张表翻译。
namespace SecurityLimitationKeys {
inline constexpr const char* kClaimUnbacked = "security.claim.unbacked";
inline constexpr const char* kClaimNotObserved = "security.claim.notObserved";
inline constexpr const char* kFieldHistorical = "security.field.historical";
inline constexpr const char* kFieldForeignMachine = "security.field.foreignMachine";
inline constexpr const char* kFieldFreshnessUnknown = "security.field.freshnessUnknown";
inline constexpr const char* kFieldDuplicateId = "security.field.duplicateId";
inline constexpr const char* kCapabilityNotCollected = "security.capability.notCollected";
inline constexpr const char* kDimensionConflict = "security.dimension.conflict";
inline constexpr const char* kHistoricalConflict = "security.dimension.historicalConflict";
inline constexpr const char* kSourceGroupUnattributed = "security.source.unattributed";
inline constexpr const char* kOutcomeMixedFailures = "security.outcome.mixedFailures";
inline constexpr const char* kPrivilegeDegraded = "security.privilege.degraded";
inline constexpr const char* kSystemPrivilegeDegraded = "security.privilege.systemDegraded";
inline constexpr const char* kDriverDegraded = "security.driver.degraded";
inline constexpr const char* kUnknownEnumPreserved = "security.enum.unknownPreserved";
inline constexpr const char* kMeasuredBootLogUnknown = "security.measuredBoot.logUnknown";
inline constexpr const char* kConfiguredPolicyUnknown = "security.codeIntegrity.configuredUnknown";
inline constexpr const char* kEffectivePolicyUnknown = "security.codeIntegrity.effectiveUnknown";
inline constexpr const char* kPolicyDecisionUnknown = "security.codeIntegrity.policyDecisionUnknown";
inline constexpr const char* kConstraintNonStatement = "security.constraint.nonStatement";
inline constexpr const char* kConstraintUnbacked = "security.constraint.unbacked";
inline constexpr const char* kConstraintConflict = "security.capability.constraintConflict";
// 有约束但一条都判不了，因此不采纳来源自称的"可用"。
inline constexpr const char* kConstraintIndeterminate = "security.constraint.indeterminate";
inline constexpr const char* kSupportClaimBlocked = "security.supportClaim.blocked";
inline constexpr const char* kSupportClaimIncomplete = "security.supportClaim.incomplete";
} // namespace SecurityLimitationKeys

} // namespace Ksword::Evidence
