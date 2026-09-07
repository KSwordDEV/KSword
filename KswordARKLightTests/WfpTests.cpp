// N 模块（WFP 与网络规则解释）的离线自动测试。
//
// 覆盖编号：N-01 N-02 N-03 N-04 N-05 N-06 N-08。
// N-07（自有规则端到端）需要隔离环境实测，本文件不声称覆盖它。
//
// 断言原则（Q-01 / Q-02）：
//   * 期望值一律独立手算写死：地址字节、掩码前缀、仲裁结论、限制键字符串都直接写字面量，
//     不从被测函数反算，也不把生产函数的输出再喂回同一个生产函数做"参考对参考"。
//   * FWP 常量（FWP_MATCH_*、FWP_ACTION_*、FWPM_CONDITION_* 的 GUID）在测试里独立抄自
//     Windows SDK，与 WfpAnalysis.cpp 里的表分开写 —— 表抄错时这里会红。
//   * 每个枚举分支都要有断言；"未知"与"不匹配"绝不共用一个期望值。

#include "TestSupport.h"

#include "../shared/evidence/WfpAnalysis.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace {

using namespace Ksword::Evidence;

// FWP_MATCH_TYPE（独立抄自 SDK fwptypes.h）
constexpr std::uint32_t kMatchEqual = 0U;
constexpr std::uint32_t kMatchGreater = 1U;
constexpr std::uint32_t kMatchLessOrEqual = 4U;
constexpr std::uint32_t kMatchRange = 5U;
constexpr std::uint32_t kMatchFlagsAllSet = 6U;
constexpr std::uint32_t kMatchNotEqual = 10U;
constexpr std::uint32_t kMatchPrefix = 11U;
constexpr std::uint32_t kMatchBogus = 99U;  // 不在 0..12 内 —— 必须解成 Unknown

// FWP_DATA_TYPE（独立抄自 SDK fwptypes.h）
constexpr std::uint32_t kTypeUint8 = 1U;
constexpr std::uint32_t kTypeUint16 = 2U;
constexpr std::uint32_t kTypeUint32 = 3U;
constexpr std::uint32_t kTypeByteArray16 = 11U;
constexpr std::uint32_t kTypeByteBlob = 12U;
constexpr std::uint32_t kTypeSid = 13U;
constexpr std::uint32_t kTypeV4AddrMask = 0x100U;
constexpr std::uint32_t kTypeV6AddrMask = 0x101U;
constexpr std::uint32_t kTypeRange = 0x102U;
constexpr std::uint32_t kTypeBogus = 0x777U;

// FWP_ACTION_*（独立抄自 SDK fwptypes.h：低位序号 | 标志位）
constexpr std::uint32_t kActionBlock = 0x00000001U | 0x00001000U;
constexpr std::uint32_t kActionPermit = 0x00000002U | 0x00001000U;
constexpr std::uint32_t kActionCalloutTerminating = 0x00000003U | 0x00004000U | 0x00001000U;
constexpr std::uint32_t kActionCalloutInspection = 0x00000004U | 0x00004000U | 0x00002000U;
constexpr std::uint32_t kActionCalloutUnknown = 0x00000005U | 0x00004000U;
constexpr std::uint32_t kActionContinue = 0x00000006U | 0x00002000U;
constexpr std::uint32_t kActionNone = 0x00000007U;
constexpr std::uint32_t kActionNoneNoMatch = 0x00000008U;

// FWPM_CONDITION_*（独立抄自 SDK fwpmu.h 的注释行）
constexpr const char* kGuidRemotePort = "{c35a604d-d22b-4e1a-91b4-68f674ee674b}";
constexpr const char* kGuidLocalPort = "{0c1ba1af-5765-453f-af22-a8f791ac775b}";
constexpr const char* kGuidRemoteAddress = "{b235ae9a-1d64-49b8-a44c-5ff3d9095045}";
constexpr const char* kGuidLocalAddress = "{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}";
constexpr const char* kGuidProtocol = "{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}";
constexpr const char* kGuidDirection = "{8784c146-ca97-44d6-9fd1-19fb1840cbf7}";
constexpr const char* kGuidAppId = "{d78e1e87-8644-4ea5-9437-d809ecefc971}";
constexpr const char* kGuidUserId = "{af043a0a-b34d-4f86-979c-c90371af6e66}";
constexpr const char* kGuidFlags = "{632ce23b-5167-435c-86d7-e903684aa80c}";
// 内置表里没有的条件 GUID（FWPM_CONDITION_INTERFACE_TYPE），用来验证"未知条件"路径。
constexpr const char* kGuidUnmodeled = "{daf8cd14-e09e-4c93-a5ae-c5c13b73ffca}";

// 测试样本用的对象 GUID。刻意让两个 provider 的显示名相同、GUID 不同。
constexpr const char* kProviderA = "{11111111-1111-4111-8111-111111111111}";
constexpr const char* kProviderB = "{22222222-2222-4222-8222-222222222222}";
constexpr const char* kLayerAle = "{33333333-3333-4333-8333-333333333333}";
constexpr const char* kSubLayerHigh = "{44444444-4444-4444-8444-444444444444}";
constexpr const char* kSubLayerLow = "{55555555-5555-4555-8555-555555555555}";
constexpr const char* kCalloutX = "{66666666-6666-4666-8666-666666666666}";
constexpr const char* kFilter1 = "{aaaaaaaa-0000-4000-8000-000000000001}";
constexpr const char* kFilter2 = "{aaaaaaaa-0000-4000-8000-000000000002}";
constexpr const char* kFilter3 = "{aaaaaaaa-0000-4000-8000-000000000003}";
constexpr const char* kFilter4 = "{aaaaaaaa-0000-4000-8000-000000000004}";

// 越界安全的取值器：断言失败时不再顺手越界访问（注入式复核会把分组数改小）。
const LayerCandidateGroup& LayerAt(const StaticCandidateReport& report, std::size_t index) {
    static const LayerCandidateGroup kEmptyLayer;
    return index < report.layers.size() ? report.layers[index] : kEmptyLayer;
}

const SubLayerCandidateGroup& SubAt(const LayerCandidateGroup& group, std::size_t index) {
    static const SubLayerCandidateGroup kEmptySubLayer;
    return index < group.subLayers.size() ? group.subLayers[index] : kEmptySubLayer;
}

const FilterCandidate& FilterAt(const SubLayerCandidateGroup& group, std::size_t index) {
    static const FilterCandidate kEmptyFilter;
    return index < group.filters.size() ? group.filters[index] : kEmptyFilter;
}

OptionalText Text(const char* value) { return OptionalText::of(std::string(value)); }

WfpGuid G(const char* text) { return GuidFromText(text); }

WfpAddress Ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
    WfpAddress address;
    address.family = WfpAddressFamily::IPv4;
    address.bytes.fill(0U);
    address.bytes[0] = a;
    address.bytes[1] = b;
    address.bytes[2] = c;
    address.bytes[3] = d;
    return address;
}

WfpConditionValue NumericValue(WfpDataType type, std::uint32_t rawTypeCode, std::uint64_t value) {
    WfpConditionValue result;
    result.type = type;
    result.rawTypeCode = rawTypeCode;
    result.numeric = OptionalU64::of(value);
    return result;
}

WfpConditionValue V4MaskValue(const WfpAddress& network, std::uint32_t mask) {
    WfpConditionValue result;
    result.type = WfpDataType::V4AddrMask;
    result.rawTypeCode = kTypeV4AddrMask;
    result.v4Present = true;
    result.v4.address = network;
    result.v4.mask = mask;
    return result;
}

WfpConditionValue V6PrefixValue(const WfpAddress& network, std::uint32_t prefixLength, bool valid) {
    WfpConditionValue result;
    result.type = WfpDataType::V6AddrMask;
    result.rawTypeCode = kTypeV6AddrMask;
    result.v6Present = true;
    result.v6.address = network;
    result.v6.prefixLength = prefixLength;
    result.v6.prefixLengthValid = valid;
    return result;
}

WfpConditionValue RangeValue(std::uint64_t low, std::uint64_t high) {
    WfpConditionValue result;
    result.type = WfpDataType::Range;
    result.rawTypeCode = kTypeRange;
    result.range.elementType = WfpDataType::Uint16;
    result.range.numeric = true;
    result.range.low = OptionalU64::of(low);
    result.range.high = OptionalU64::of(high);
    return result;
}

WfpConditionValue AppIdValue(const char* path) {
    WfpConditionValue result;
    result.type = WfpDataType::ByteBlob;
    result.rawTypeCode = kTypeByteBlob;
    result.blobText = Text(path);
    result.blobBytes = { 0x01U, 0x02U };
    return result;
}

WfpConditionValue SidValue(const char* sid) {
    WfpConditionValue result;
    result.type = WfpDataType::Sid;
    result.rawTypeCode = kTypeSid;
    result.sidText = Text(sid);
    return result;
}

ConnectionDescription MakeConnection() {
    ConnectionDescription connection;
    connection.localAddress = Ipv4(192U, 168U, 1U, 50U);
    connection.remoteAddress = Ipv4(93U, 184U, 216U, 34U);
    connection.localPort = OptionalU64::of(52344U);
    connection.remotePort = OptionalU64::of(443U);
    connection.protocol = OptionalU64::of(6U);  // IPPROTO_TCP
    connection.direction = WfpDirection::Outbound;
    connection.appId = Text("\\device\\harddiskvolume3\\windows\\system32\\curl.exe");
    connection.userSid = Text("S-1-5-21-100-200-300-1001");
    return connection;
}

void MarkPartitionComplete(WfpCatalog& catalog, WfpPartition partition, std::uint64_t count) {
    CoverageAccount coverage;
    coverage.totalKnown = OptionalU64::of(count);
    coverage.succeeded = count;
    catalog.setPartitionState(partition, CollectionOutcome::success(), coverage);
}

WfpFilter MakeFilter(const char* key,
                     std::uint64_t filterId,
                     const char* subLayer,
                     std::uint32_t rawAction,
                     WfpActionType action) {
    WfpFilter filter;
    filter.filterKey = G(key);
    filter.filterId = OptionalU64::of(filterId);
    filter.displayName = Text(key);
    filter.providerKey = G(kProviderA);
    filter.layerKey = G(kLayerAle);
    filter.subLayerKey = G(subLayer);
    filter.rawActionCode = rawAction;
    filter.action = action;
    return filter;
}

void SetEffectiveWeight(WfpFilter& filter, std::uint64_t weight) {
    filter.weightKind = WfpWeightKind::Explicit;
    filter.weight = OptionalU64::of(weight);
    filter.effectiveWeight = OptionalU64::of(weight);
}

// 远端端口 == value 的条件（本测试最常用的"可判定"条件）。
WfpCondition RemotePortEquals(std::uint64_t port) {
    return MakeCondition(G(kGuidRemotePort), kMatchEqual,
                         NumericValue(WfpDataType::Uint16, kTypeUint16, port));
}

// ---------------------------------------------------------------------------
// N-01：对象关系与唯一键
// ---------------------------------------------------------------------------
void TestObjectIdentityAndJoins(KswordTests::Suite& s) {
    WfpGuid parsed;
    s.expect(ParseGuid("{11111111-1111-4111-8111-111111111111}", parsed),
             L"N-01 规范形式的 GUID 可解析");
    s.expect(parsed.text == "{11111111-1111-4111-8111-111111111111}",
             L"N-01 解析结果保持规范文本");

    WfpGuid upper;
    s.expect(ParseGuid("A1B2C3D4-E5F6-4788-9AAB-CCDDEEFF0011", upper),
             L"N-01 不带花括号的大写 GUID 也可解析");
    s.expect(upper.text == "{a1b2c3d4-e5f6-4788-9aab-ccddeeff0011}",
             L"N-01 GUID 归一化成小写带花括号");

    WfpGuid untouched;
    untouched.text = "sentinel";
    s.expect(!ParseGuid("", untouched), L"N-01 空串不是合法 GUID");
    s.expect(!ParseGuid("11111111-1111-4111-8111-11111111111", untouched), L"N-01 少一位的 GUID 被拒绝");
    s.expect(!ParseGuid("11111111-1111-4111-8111-11111111111Z", untouched), L"N-01 非十六进制字符被拒绝");
    s.expect(!ParseGuid("111111111-111-4111-8111-111111111111", untouched), L"N-01 连字符位置错误被拒绝");
    s.expect(untouched.text == "sentinel", L"N-01 解析失败不修改输出参数");
    s.expect(!GuidFromText("not-a-guid").known(), L"N-01 非法文本得到未知 GUID 而不是半成品键");

    WfpCatalog catalog;
    WfpProvider providerA;
    providerA.providerKey = G(kProviderA);
    providerA.displayName = Text("Microsoft Corporation");
    WfpProvider providerB;
    providerB.providerKey = G(kProviderB);
    providerB.displayName = Text("Microsoft Corporation");  // 同名异 GUID
    s.expect(catalog.addProvider(providerA), L"N-01 首个 provider 入库成功");
    s.expect(catalog.addProvider(providerB), L"N-01 同名异 GUID 的 provider 也能独立入库");
    MarkPartitionComplete(catalog, WfpPartition::Providers, 2U);

    s.expect(catalog.providers().size() == 2U, L"N-01 同名不合并：目录里仍是两个 provider");
    const ObjectReference refA = catalog.resolveProvider(G(kProviderA));
    const ObjectReference refB = catalog.resolveProvider(G(kProviderB));
    s.expect(refA.state == ReferenceState::Resolved, L"N-01 provider A 按 GUID 关联成功");
    s.expect(refB.state == ReferenceState::Resolved, L"N-01 provider B 按 GUID 关联成功");
    s.expect(refA.key.text == std::string(kProviderA), L"N-01 关联结果保留自己的 GUID");
    s.expect(refB.key.text == std::string(kProviderB), L"N-01 两个同名对象没有互相顶替");
    s.expect(catalog.findProvidersByDisplayName("Microsoft Corporation").size() == 2U,
             L"N-01 名称查询返回全部同名对象，说明名称不是唯一键");

    // 目录里没有的 GUID：分区已完整采集 -> 未知对象（不猜、不留裸 GUID 冒充已解析）。
    const ObjectReference missing = catalog.resolveProvider(G("{99999999-9999-4999-8999-999999999999}"));
    s.expect(missing.state == ReferenceState::UnknownObject, L"N-01 缺失关联显示未知对象");
    s.expect(!missing.resolvedName.present, L"N-01 未知对象不带解析名称");
    s.expect(missing.key.known(), L"N-01 未知对象仍保留原始 GUID 供追查");

    // 引用字段本身为空 —— 与"未知对象"是两种状态。
    const ObjectReference unspecified = catalog.resolveProvider(WfpGuid{});
    s.expect(unspecified.state == ReferenceState::NotSpecified, L"N-01 空引用是 NotSpecified 而不是未知对象");

    // 同一 GUID 出现两次：快照不自洽，必须显式报歧义而不是静默取第一条。
    WfpCatalog duplicated;
    WfpProvider dup1;
    dup1.providerKey = G(kProviderA);
    dup1.displayName = Text("first");
    WfpProvider dup2;
    dup2.providerKey = G(kProviderA);
    dup2.displayName = Text("second");
    s.expect(duplicated.addProvider(dup1), L"N-01 重复 GUID 的第一条正常入库");
    s.expect(!duplicated.addProvider(dup2), L"N-01 重复 GUID 的第二条被标记为重复");
    MarkPartitionComplete(duplicated, WfpPartition::Providers, 2U);
    s.expect(duplicated.resolveProvider(G(kProviderA)).state == ReferenceState::Ambiguous,
             L"N-01 同 GUID 重复时关联结果是 Ambiguous");
    s.expect(duplicated.providers().size() == 2U, L"N-01 重复行仍然保留，不静默丢弃");
}

// ---------------------------------------------------------------------------
// N-01：动作与权重字段
// ---------------------------------------------------------------------------
void TestActionAndWeightDecoding(KswordTests::Suite& s) {
    s.expect(DecodeActionType(kActionBlock) == WfpActionType::Block, L"N-01 FWP_ACTION_BLOCK 解成 Block");
    s.expect(DecodeActionType(kActionPermit) == WfpActionType::Permit, L"N-01 FWP_ACTION_PERMIT 解成 Permit");
    s.expect(DecodeActionType(kActionCalloutTerminating) == WfpActionType::CalloutTerminating,
             L"N-01 CALLOUT_TERMINATING 正确解码");
    s.expect(DecodeActionType(kActionCalloutInspection) == WfpActionType::CalloutInspection,
             L"N-01 CALLOUT_INSPECTION 正确解码");
    s.expect(DecodeActionType(kActionCalloutUnknown) == WfpActionType::CalloutUnknown,
             L"N-01 CALLOUT_UNKNOWN 正确解码");
    s.expect(DecodeActionType(kActionContinue) == WfpActionType::Continue, L"N-01 CONTINUE 正确解码");
    s.expect(DecodeActionType(kActionNone) == WfpActionType::None, L"N-01 NONE 正确解码");
    s.expect(DecodeActionType(kActionNoneNoMatch) == WfpActionType::NoneNoMatch,
             L"N-01 NONE_NO_MATCH 正确解码");
    s.expect(DecodeActionType(0x00000001U) == WfpActionType::Unknown,
             L"N-01 缺少 TERMINATING 标志的 0x1 不是 Block 而是 Unknown");
    s.expect(DecodeActionType(0xDEADU) == WfpActionType::Unknown, L"N-01 未知动作码解成 Unknown 而不是放行");

    s.expect(ActionIsCallout(WfpActionType::CalloutTerminating), L"N-01 终结型 callout 属于动态动作");
    s.expect(ActionIsCallout(WfpActionType::CalloutInspection), L"N-01 检查型 callout 属于动态动作");
    s.expect(ActionIsCallout(WfpActionType::CalloutUnknown), L"N-01 未知型 callout 属于动态动作");
    s.expect(!ActionIsCallout(WfpActionType::Block), L"N-01 Block 不是动态动作");
    s.expect(!ActionIsCallout(WfpActionType::Unknown), L"N-01 未知动作不被当成动态 callout");

    s.expect(DecodeDataType(kTypeUint16) == WfpDataType::Uint16, L"N-02 FWP_UINT16 正确解码");
    s.expect(DecodeDataType(kTypeV4AddrMask) == WfpDataType::V4AddrMask, L"N-02 FWP_V4_ADDR_MASK 正确解码");
    s.expect(DecodeDataType(kTypeV6AddrMask) == WfpDataType::V6AddrMask, L"N-02 FWP_V6_ADDR_MASK 正确解码");
    s.expect(DecodeDataType(kTypeRange) == WfpDataType::Range, L"N-02 FWP_RANGE_TYPE 正确解码");
    s.expect(DecodeDataType(kTypeBogus) == WfpDataType::Unknown, L"N-02 未建模数据类型解成 Unknown");
    s.expect(DecodeMatchType(kMatchRange) == WfpMatchType::Range, L"N-02 FWP_MATCH_RANGE 正确解码");
    s.expect(DecodeMatchType(kMatchPrefix) == WfpMatchType::Prefix, L"N-02 FWP_MATCH_PREFIX 正确解码");
    s.expect(DecodeMatchType(kMatchBogus) == WfpMatchType::Unknown, L"N-02 越界比较运算解成 Unknown");

    // weight / effectiveWeight 是两个字段，且都不等于 FWP_VALUE0 的类型号。
    WfpCatalog catalog;
    WfpFilter automatic = MakeFilter(kFilter1, 11U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
    automatic.weightKind = WfpWeightKind::Auto;  // FWP_EMPTY：调用方没给权重
    automatic.effectiveWeight = OptionalU64::of(4200U);
    WfpFilter explicitWeight = MakeFilter(kFilter2, 12U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    explicitWeight.weightKind = WfpWeightKind::Explicit;
    explicitWeight.weight = OptionalU64::of(7U);  // 没有 effectiveWeight
    catalog.addFilter(automatic);
    catalog.addFilter(explicitWeight);
    MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

    const ConnectionDescription connection = MakeConnection();
    const FilterCandidate autoCandidate = EvaluateFilter(catalog, automatic, connection);
    const FilterCandidate explicitCandidate = EvaluateFilter(catalog, explicitWeight, connection);
    s.expect(autoCandidate.weightConfidence == WeightOrderConfidence::EffectiveWeight,
             L"N-01 自动权重的 filter 用 effectiveWeight 排序");
    s.expect(autoCandidate.orderingWeight == OptionalU64::of(4200U), L"N-01 排序权重取 effectiveWeight 的值");
    s.expect(explicitCandidate.weightConfidence == WeightOrderConfidence::ExplicitWeight,
             L"N-01 没有 effectiveWeight 时退回显式 weight");
    s.expect(explicitCandidate.orderingWeight == OptionalU64::of(7U), L"N-01 显式权重值被原样保留");

    WfpFilter noWeight = MakeFilter(kFilter3, 13U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    noWeight.weightKind = WfpWeightKind::Auto;  // 既没 effectiveWeight 也没显式 weight
    const FilterCandidate noWeightCandidate = EvaluateFilter(catalog, noWeight, connection);
    s.expect(noWeightCandidate.weightConfidence == WeightOrderConfidence::Unknown,
             L"N-01 缺权重元数据时排序依据是 Unknown");
    s.expect(!noWeightCandidate.orderingWeight.present, L"N-01 缺权重时不拿 0 冒充权重");
    s.expect(HasLimitation(noWeightCandidate.limitationKeys, "wfp.filter.weight-unknown"),
             L"N-01 缺权重会记入限制说明");
}

// ---------------------------------------------------------------------------
// N-02：地址、掩码与前缀
// ---------------------------------------------------------------------------
void TestAddressParsing(KswordTests::Suite& s) {
    WfpAddress v4;
    s.expect(ParseIpAddress("192.168.1.50", v4), L"N-02 IPv4 文本可解析");
    s.expect(v4.family == WfpAddressFamily::IPv4, L"N-02 IPv4 地址族标记正确");
    s.expect(v4.bytes[0] == 192U && v4.bytes[1] == 168U && v4.bytes[2] == 1U && v4.bytes[3] == 50U,
             L"N-02 IPv4 字节按网络序存放");
    s.expect(FormatIpAddress(v4) == "192.168.1.50", L"N-02 IPv4 文本往返一致");

    WfpAddress reject;
    s.expect(!ParseIpAddress("256.1.1.1", reject), L"N-02 越界八位组被拒绝");
    s.expect(!ParseIpAddress("1.2.3", reject), L"N-02 少一段的 IPv4 被拒绝");
    s.expect(!ParseIpAddress("1.2.3.4.5", reject), L"N-02 多一段的 IPv4 被拒绝");
    s.expect(!ParseIpAddress("1.2.3.a", reject), L"N-02 非数字八位组被拒绝");
    s.expect(!ParseIpAddress("", reject), L"N-02 空串不是地址");

    WfpAddress v6;
    s.expect(ParseIpAddress("2001:db8::1", v6), L"N-02 压缩形式 IPv6 可解析");
    s.expect(v6.family == WfpAddressFamily::IPv6, L"N-02 IPv6 地址族标记正确");
    s.expect(v6.bytes[0] == 0x20U && v6.bytes[1] == 0x01U && v6.bytes[2] == 0x0dU && v6.bytes[3] == 0xb8U,
             L"N-02 IPv6 前四字节正确");
    s.expect(v6.bytes[14] == 0x00U && v6.bytes[15] == 0x01U, L"N-02 IPv6 末尾字节正确");
    s.expect(FormatIpAddress(v6) == "2001:db8::1", L"N-02 IPv6 按 RFC 5952 压缩输出");

    WfpAddress loopback;
    s.expect(ParseIpAddress("::1", loopback), L"N-02 前导 :: 可解析");
    s.expect(loopback.bytes[15] == 1U && loopback.bytes[0] == 0U, L"N-02 ::1 字节正确");
    s.expect(FormatIpAddress(loopback) == "::1", L"N-02 ::1 往返一致");

    WfpAddress anyAddress;
    s.expect(ParseIpAddress("::", anyAddress), L"N-02 全零 IPv6 可解析");
    s.expect(FormatIpAddress(anyAddress) == "::", L"N-02 全零 IPv6 输出 ::");

    WfpAddress mapped;
    s.expect(ParseIpAddress("::ffff:192.168.0.1", mapped), L"N-02 内嵌 IPv4 的 IPv6 可解析");
    s.expect(mapped.bytes[10] == 0xffU && mapped.bytes[11] == 0xffU, L"N-02 v4 映射前缀字节正确");
    s.expect(mapped.bytes[12] == 192U && mapped.bytes[15] == 1U, L"N-02 内嵌 IPv4 字节正确");

    WfpAddress full;
    s.expect(ParseIpAddress("1:2:3:4:5:6:7:8", full), L"N-02 完整八段 IPv6 可解析");
    s.expect(full.bytes[1] == 1U && full.bytes[15] == 8U, L"N-02 完整八段的首尾正确");
    s.expect(FormatIpAddress(full) == "1:2:3:4:5:6:7:8", L"N-02 无零段时不压缩");

    // 最长零段压缩，并列取最左：2001:0:0:1:0:0:0:1 -> 2001:0:0:1::1
    std::array<std::uint8_t, 16> raw{};
    raw[0] = 0x20U;
    raw[1] = 0x01U;
    raw[7] = 0x01U;
    raw[15] = 0x01U;
    const WfpAddress twoRuns = WfpAddress::ipv6FromBytes(raw);
    s.expect(FormatIpAddress(twoRuns) == "2001:0:0:1::1", L"N-02 压缩最长零段而不是第一个零段");

    s.expect(!ParseIpAddress(":::", reject), L"N-02 三个冒号被拒绝");
    s.expect(!ParseIpAddress("1::2::3", reject), L"N-02 两个 :: 被拒绝");
    s.expect(!ParseIpAddress("12345::", reject), L"N-02 超长分组被拒绝");
    s.expect(!ParseIpAddress("1:2:3:4:5:6:7", reject), L"N-02 段数不足且无 :: 被拒绝");
    s.expect(!ParseIpAddress("1:2:3:4:5:6:7:8:9", reject), L"N-02 段数超出被拒绝");
    s.expect(!ParseIpAddress("1:2:3:4:5:6:7:", reject), L"N-02 结尾单冒号被拒绝");

    std::uint32_t prefix = 0xFFFFFFFFU;
    s.expect(MaskToPrefixLength(0xFFFFFF00U, prefix) && prefix == 24U, L"N-02 255.255.255.0 前缀长度是 24");
    s.expect(MaskToPrefixLength(0xFFFFFFFFU, prefix) && prefix == 32U, L"N-02 全 1 掩码前缀长度是 32");
    s.expect(MaskToPrefixLength(0U, prefix) && prefix == 0U, L"N-02 全 0 掩码前缀长度是 0");
    s.expect(!MaskToPrefixLength(0xFF00FF00U, prefix), L"N-02 非连续掩码不能折成前缀长度");

    const WfpV4AddrMask subnet{ Ipv4(10U, 0U, 0U, 0U), 0xFF000000U };
    s.expect(AddressInV4Subnet(Ipv4(10U, 1U, 2U, 3U), subnet), L"N-02 10.1.2.3 落在 10/8 内");
    s.expect(!AddressInV4Subnet(Ipv4(11U, 1U, 2U, 3U), subnet), L"N-02 11.1.2.3 不在 10/8 内");

    WfpAddress prefixBase;
    (void)ParseIpAddress("2001:db8::", prefixBase);
    WfpV6AddrPrefix v6Prefix;
    v6Prefix.address = prefixBase;
    v6Prefix.prefixLength = 32U;
    v6Prefix.prefixLengthValid = true;
    WfpAddress inside;
    (void)ParseIpAddress("2001:db8:1234::9", inside);
    WfpAddress outside;
    (void)ParseIpAddress("2001:db9::1", outside);
    s.expect(AddressInV6Prefix(inside, v6Prefix), L"N-02 2001:db8:1234::9 落在 2001:db8::/32 内");
    s.expect(!AddressInV6Prefix(outside, v6Prefix), L"N-02 2001:db9::1 不在 2001:db8::/32 内");
    WfpV6AddrPrefix invalidPrefix = v6Prefix;
    invalidPrefix.prefixLengthValid = false;
    s.expect(!AddressInV6Prefix(inside, invalidPrefix), L"N-02 前缀长度无效时不做包含判定");
}

// ---------------------------------------------------------------------------
// N-02：条件解释与三态求值
// ---------------------------------------------------------------------------
void TestConditionInterpretation(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();

    // 字段表：GUID -> FWPM_CONDITION_* 名称
    const WfpCondition remotePort = RemotePortEquals(443U);
    s.expect(remotePort.field == WfpFieldKind::IpRemotePort, L"N-02 远端端口条件 GUID 解出正确字段");
    s.expect(remotePort.fieldName == "FWPM_CONDITION_IP_REMOTE_PORT", L"N-02 字段名与 SDK 符号一致");
    s.expect(FieldGuidFor(WfpFieldKind::IpRemotePort).text == std::string(kGuidRemotePort),
             L"N-02 字段反查 GUID 与 SDK 一致");
    s.expect(FieldGuidFor(WfpFieldKind::IpLocalPort).text == std::string(kGuidLocalPort),
             L"N-02 本地端口 GUID 与 SDK 一致");
    s.expect(FieldGuidFor(WfpFieldKind::IpLocalPort) != FieldGuidFor(WfpFieldKind::IpRemotePort),
             L"N-02 本地/远端端口是两个不同的条件 GUID");
    s.expect(remotePort.interpreted(), L"N-02 端口等值条件被完整解释");
    s.expect(remotePort.evaluable(), L"N-02 端口条件可用于判定连接");

    s.expect(EvaluateCondition(remotePort, connection).result == ConditionMatch::Match,
             L"N-02 远端端口 443 == 443 判定为匹配");
    s.expect(EvaluateCondition(RemotePortEquals(8080U), connection).result == ConditionMatch::NoMatch,
             L"N-02 远端端口 443 != 8080 判定为不匹配");

    // 端口范围
    const WfpCondition portRange = MakeCondition(G(kGuidRemotePort), kMatchRange, RangeValue(400U, 500U));
    s.expect(portRange.match == WfpMatchType::Range, L"N-02 范围比较运算解码正确");
    s.expect(EvaluateCondition(portRange, connection).result == ConditionMatch::Match,
             L"N-02 443 落在 [400,500] 内");
    const WfpCondition portRangeMiss = MakeCondition(G(kGuidRemotePort), kMatchRange, RangeValue(1U, 100U));
    s.expect(EvaluateCondition(portRangeMiss, connection).result == ConditionMatch::NoMatch,
             L"N-02 443 不在 [1,100] 内");

    // 其它数值比较
    const WfpCondition portGreater = MakeCondition(G(kGuidRemotePort), kMatchGreater,
                                                   NumericValue(WfpDataType::Uint16, kTypeUint16, 1024U));
    s.expect(EvaluateCondition(portGreater, connection).result == ConditionMatch::NoMatch,
             L"N-02 443 > 1024 为不匹配");
    const WfpCondition portLessEqual = MakeCondition(G(kGuidRemotePort), kMatchLessOrEqual,
                                                     NumericValue(WfpDataType::Uint16, kTypeUint16, 443U));
    s.expect(EvaluateCondition(portLessEqual, connection).result == ConditionMatch::Match,
             L"N-02 443 <= 443 为匹配");
    const WfpCondition portNotEqual = MakeCondition(G(kGuidRemotePort), kMatchNotEqual,
                                                    NumericValue(WfpDataType::Uint16, kTypeUint16, 80U));
    s.expect(EvaluateCondition(portNotEqual, connection).result == ConditionMatch::Match,
             L"N-02 443 != 80 为匹配");

    // 协议
    const WfpCondition protocolTcp = MakeCondition(G(kGuidProtocol), kMatchEqual,
                                                   NumericValue(WfpDataType::Uint8, kTypeUint8, 6U));
    s.expect(protocolTcp.field == WfpFieldKind::IpProtocol, L"N-02 协议条件 GUID 解出正确字段");
    s.expect(EvaluateCondition(protocolTcp, connection).result == ConditionMatch::Match,
             L"N-02 TCP(6) 协议条件匹配");
    const WfpCondition protocolUdp = MakeCondition(G(kGuidProtocol), kMatchEqual,
                                                   NumericValue(WfpDataType::Uint8, kTypeUint8, 17U));
    s.expect(EvaluateCondition(protocolUdp, connection).result == ConditionMatch::NoMatch,
             L"N-02 UDP(17) 协议条件不匹配");

    // IPv4 子网
    const WfpCondition remoteSubnet = MakeCondition(G(kGuidRemoteAddress), kMatchEqual,
                                                    V4MaskValue(Ipv4(93U, 184U, 0U, 0U), 0xFFFF0000U));
    s.expect(remoteSubnet.field == WfpFieldKind::IpRemoteAddress, L"N-02 远端地址条件 GUID 解出正确字段");
    s.expect(EvaluateCondition(remoteSubnet, connection).result == ConditionMatch::Match,
             L"N-02 93.184.216.34 落在 93.184.0.0/16 内");
    const WfpCondition otherSubnet = MakeCondition(G(kGuidRemoteAddress), kMatchEqual,
                                                   V4MaskValue(Ipv4(10U, 0U, 0U, 0U), 0xFF000000U));
    s.expect(EvaluateCondition(otherSubnet, connection).result == ConditionMatch::NoMatch,
             L"N-02 93.184.216.34 不在 10/8 内");

    // 单个 IPv4 地址以 FWP_UINT32 主机序表达
    const WfpCondition localExact = MakeCondition(
        G(kGuidLocalAddress), kMatchEqual,
        NumericValue(WfpDataType::Uint32, kTypeUint32, 0xC0A80132ULL));  // 192.168.1.50
    s.expect(EvaluateCondition(localExact, connection).result == ConditionMatch::Match,
             L"N-02 主机序 UINT32 形式的本地地址匹配");

    // IPv6 前缀：连接换成 v6
    ConnectionDescription v6Connection = MakeConnection();
    (void)ParseIpAddress("2001:db8:1::5", v6Connection.remoteAddress);
    WfpAddress v6Base;
    (void)ParseIpAddress("2001:db8::", v6Base);
    const WfpCondition v6Prefix = MakeCondition(G(kGuidRemoteAddress), kMatchEqual,
                                                V6PrefixValue(v6Base, 32U, true));
    s.expect(EvaluateCondition(v6Prefix, v6Connection).result == ConditionMatch::Match,
             L"N-02 IPv6 /32 前缀条件匹配");
    const WfpCondition v6PrefixMiss = MakeCondition(G(kGuidRemoteAddress), kMatchEqual,
                                                    V6PrefixValue(v6Base, 64U, true));
    s.expect(EvaluateCondition(v6PrefixMiss, v6Connection).result == ConditionMatch::NoMatch,
             L"N-02 IPv6 /64 前缀条件不匹配");
    const WfpCondition v6BadPrefix = MakeCondition(G(kGuidRemoteAddress), kMatchEqual,
                                                   V6PrefixValue(v6Base, 200U, false));
    const ConditionEvaluation badPrefixEval = EvaluateCondition(v6BadPrefix, v6Connection);
    s.expect(badPrefixEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 非法前缀长度不做真值断言");
    s.expect(HasLimitation(badPrefixEval.limitationKeys, "wfp.condition.invalid-prefix-length"),
             L"N-02 非法前缀长度写进限制说明");

    // 单个 IPv6 地址（FWP_BYTE_ARRAY16）
    WfpConditionValue exactV6;
    exactV6.type = WfpDataType::ByteArray16;
    exactV6.rawTypeCode = kTypeByteArray16;
    (void)ParseIpAddress("2001:db8:1::5", exactV6.singleAddress);
    const WfpCondition v6Exact = MakeCondition(G(kGuidRemoteAddress), kMatchEqual, exactV6);
    s.expect(EvaluateCondition(v6Exact, v6Connection).result == ConditionMatch::Match,
             L"N-02 单个 IPv6 地址等值匹配");

    // 地址族错配：正向比较可判不匹配，否定比较保持未知
    const ConditionEvaluation familyPositive = EvaluateCondition(remoteSubnet, v6Connection);
    s.expect(familyPositive.result == ConditionMatch::NoMatch, L"N-02 IPv4 子网条件对 IPv6 连接判不匹配");
    s.expect(HasLimitation(familyPositive.limitationKeys, "wfp.condition.address-family-mismatch"),
             L"N-02 地址族错配写进限制说明");
    const WfpCondition remoteNotSubnet = MakeCondition(G(kGuidRemoteAddress), kMatchNotEqual,
                                                       V4MaskValue(Ipv4(10U, 0U, 0U, 0U), 0xFF000000U));
    s.expect(EvaluateCondition(remoteNotSubnet, v6Connection).result == ConditionMatch::InsufficientInfo,
             L"N-02 跨地址族的否定条件保持信息不足");

    // 地址上的范围比较本层不建模
    const WfpCondition addressRange = MakeCondition(G(kGuidRemoteAddress), kMatchRange, RangeValue(1U, 2U));
    const ConditionEvaluation addressRangeEval = EvaluateCondition(addressRange, connection);
    s.expect(addressRangeEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 地址范围条件不猜结果");
    s.expect(HasLimitation(addressRangeEval.limitationKeys, "wfp.condition.address-range-not-modeled"),
             L"N-02 地址范围未建模写进限制说明");

    // 方向
    const WfpCondition outbound = MakeCondition(G(kGuidDirection), kMatchEqual,
                                                NumericValue(WfpDataType::Uint32, kTypeUint32, 0U));
    s.expect(outbound.field == WfpFieldKind::Direction, L"N-02 方向条件 GUID 解出正确字段");
    s.expect(EvaluateCondition(outbound, connection).result == ConditionMatch::Match,
             L"N-02 FWP_DIRECTION_OUTBOUND(0) 对出站连接匹配");
    const WfpCondition inbound = MakeCondition(G(kGuidDirection), kMatchEqual,
                                               NumericValue(WfpDataType::Uint32, kTypeUint32, 1U));
    s.expect(EvaluateCondition(inbound, connection).result == ConditionMatch::NoMatch,
             L"N-02 FWP_DIRECTION_INBOUND(1) 对出站连接不匹配");
    const WfpCondition bogusDirection = MakeCondition(G(kGuidDirection), kMatchEqual,
                                                      NumericValue(WfpDataType::Uint32, kTypeUint32, 2U));
    const ConditionEvaluation bogusDirEval = EvaluateCondition(bogusDirection, connection);
    s.expect(bogusDirEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 方向值 2 不在 FWP_DIRECTION_ 定义内，不猜成 FORWARD");
    s.expect(HasLimitation(bogusDirEval.limitationKeys, "wfp.condition.unknown-direction-value"),
             L"N-02 未知方向值写进限制说明");
    s.expect(bogusDirEval.condition.value.numeric == OptionalU64::of(2U),
             L"N-02 未知方向值的原始数值被保留");
    ConnectionDescription forwardConnection = MakeConnection();
    forwardConnection.direction = WfpDirection::Forward;
    s.expect(EvaluateCondition(outbound, forwardConnection).result == ConditionMatch::InsufficientInfo,
             L"N-02 转发流量与 in/out 二分不可比，保持信息不足");

    // AppId
    const WfpCondition appId = MakeCondition(
        G(kGuidAppId), kMatchEqual,
        AppIdValue("\\Device\\HarddiskVolume3\\Windows\\System32\\curl.exe"));
    s.expect(appId.field == WfpFieldKind::AleAppId, L"N-02 AppId 条件 GUID 解出正确字段");
    s.expect(EvaluateCondition(appId, connection).result == ConditionMatch::Match,
             L"N-02 AppId 大小写不敏感匹配");
    const WfpCondition appIdOther = MakeCondition(G(kGuidAppId), kMatchEqual,
                                                  AppIdValue("\\device\\harddiskvolume3\\windows\\system32\\ping.exe"));
    s.expect(EvaluateCondition(appIdOther, connection).result == ConditionMatch::NoMatch,
             L"N-02 不同 AppId 判不匹配");
    const WfpCondition appIdPrefix = MakeCondition(G(kGuidAppId), kMatchPrefix,
                                                   AppIdValue("\\Device\\HarddiskVolume3\\Windows\\"));
    s.expect(EvaluateCondition(appIdPrefix, connection).result == ConditionMatch::Match,
             L"N-02 AppId 前缀比较匹配");
    WfpConditionValue undecodedBlob;
    undecodedBlob.type = WfpDataType::ByteBlob;
    undecodedBlob.rawTypeCode = kTypeByteBlob;
    undecodedBlob.blobBytes = { 0xFFU, 0xFEU, 0x00U };  // 解不成路径文本
    const WfpCondition appIdRaw = MakeCondition(G(kGuidAppId), kMatchEqual, undecodedBlob);
    const ConditionEvaluation appIdRawEval = EvaluateCondition(appIdRaw, connection);
    s.expect(appIdRawEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 解不出文本的 AppId 不能当成匹配任何程序");
    s.expect(HasLimitation(appIdRawEval.limitationKeys, "wfp.condition.blob-not-decoded"),
             L"N-02 未解码 blob 写进限制说明");
    s.expect(appIdRawEval.condition.value.blobBytes.size() == 3U, L"N-02 未解码 blob 的原始字节被保留");

    // 用户 SID
    const WfpCondition userSid = MakeCondition(G(kGuidUserId), kMatchEqual,
                                               SidValue("S-1-5-21-100-200-300-1001"));
    s.expect(userSid.field == WfpFieldKind::AleUserId, L"N-02 用户条件 GUID 解出正确字段");
    s.expect(EvaluateCondition(userSid, connection).result == ConditionMatch::Match, L"N-02 SID 等值匹配");
    const WfpCondition otherSid = MakeCondition(G(kGuidUserId), kMatchEqual, SidValue("S-1-5-18"));
    s.expect(EvaluateCondition(otherSid, connection).result == ConditionMatch::NoMatch,
             L"N-02 不同 SID 判不匹配");

    // ---- 未知/未建模路径：绝不塌成"无条件匹配" ----
    const WfpCondition unknownField = MakeCondition(G(kGuidUnmodeled), kMatchEqual,
                                                    NumericValue(WfpDataType::Uint32, kTypeUint32, 1U));
    const ConditionEvaluation unknownFieldEval = EvaluateCondition(unknownField, connection);
    s.expect(unknownField.field == WfpFieldKind::Unknown, L"N-02 表外条件 GUID 解成未知字段");
    s.expect(unknownField.fieldName.empty(), L"N-02 未知字段不编造名称");
    s.expect(!unknownField.interpreted(), L"N-02 未知字段的条件不算已解释");
    s.expect(unknownFieldEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 未知条件是信息不足，不是无条件匹配");
    s.expect(unknownFieldEval.result != ConditionMatch::Match, L"N-02 未知条件绝不判匹配");
    s.expect(HasLimitation(unknownFieldEval.limitationKeys, "wfp.condition.unknown-field"),
             L"N-02 未知字段写进限制说明");
    s.expect(unknownFieldEval.condition.fieldKey.text == std::string(kGuidUnmodeled),
             L"N-02 未知条件保留原始 GUID");

    WfpConditionValue unknownValue;
    unknownValue.type = WfpDataType::Unknown;
    unknownValue.rawTypeCode = kTypeBogus;
    unknownValue.rawText = "0x0102030405";
    const WfpCondition unknownType = MakeCondition(G(kGuidRemotePort), kMatchEqual, unknownValue);
    const ConditionEvaluation unknownTypeEval = EvaluateCondition(unknownType, connection);
    s.expect(unknownTypeEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 未知数据类型是信息不足");
    s.expect(HasLimitation(unknownTypeEval.limitationKeys, "wfp.condition.unknown-value-type"),
             L"N-02 未知数据类型写进限制说明");
    s.expect(unknownTypeEval.condition.value.rawText == "0x0102030405",
             L"N-02 未知数据类型的原始值被保留");
    s.expect(unknownTypeEval.condition.value.rawTypeCode == kTypeBogus,
             L"N-02 未知数据类型的原始类型号被保留");

    const WfpCondition unknownMatch = MakeCondition(G(kGuidRemotePort), kMatchBogus,
                                                    NumericValue(WfpDataType::Uint16, kTypeUint16, 443U));
    const ConditionEvaluation unknownMatchEval = EvaluateCondition(unknownMatch, connection);
    s.expect(unknownMatch.match == WfpMatchType::Unknown, L"N-02 越界比较运算解成 Unknown");
    s.expect(unknownMatchEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 未知比较运算不按等值处理");
    s.expect(unknownMatchEval.condition.rawMatchCode == kMatchBogus, L"N-02 未知比较运算的原始码被保留");

    const WfpCondition flagsCondition = MakeCondition(G(kGuidFlags), kMatchFlagsAllSet,
                                                      NumericValue(WfpDataType::Uint32, kTypeUint32, 4U));
    const ConditionEvaluation flagsEval = EvaluateCondition(flagsCondition, connection);
    s.expect(flagsCondition.field == WfpFieldKind::Flags, L"N-02 FLAGS 字段名可解析");
    s.expect(flagsCondition.interpreted(), L"N-02 FLAGS 条件的字段与类型都读懂了");
    s.expect(!flagsCondition.evaluable(), L"N-02 读懂名字不等于能判定连接");
    s.expect(flagsEval.result == ConditionMatch::InsufficientInfo, L"N-02 未建模字段保持信息不足");
    s.expect(HasLimitation(flagsEval.limitationKeys, "wfp.condition.field-not-modeled"),
             L"N-02 未建模字段写进限制说明");

    // 连接描述本身缺属性
    ConnectionDescription partial = MakeConnection();
    partial.remotePort = OptionalU64::unset();
    const ConditionEvaluation missingAttr = EvaluateCondition(remotePort, partial);
    s.expect(missingAttr.result == ConditionMatch::InsufficientInfo,
             L"N-02 连接缺少端口时不判匹配也不判不匹配");
    s.expect(HasLimitation(missingAttr.limitationKeys, "wfp.condition.attribute-unknown"),
             L"N-02 连接属性缺失写进限制说明");
    ConnectionDescription noApp = MakeConnection();
    noApp.appId = OptionalText::unset();
    s.expect(EvaluateCondition(appId, noApp).result == ConditionMatch::InsufficientInfo,
             L"N-02 连接缺少 AppId 时保持信息不足");

    // 值类型与字段语义错配
    const WfpCondition portWithBlob = MakeCondition(G(kGuidRemotePort), kMatchEqual, AppIdValue("x"));
    const ConditionEvaluation mismatchEval = EvaluateCondition(portWithBlob, connection);
    s.expect(mismatchEval.result == ConditionMatch::InsufficientInfo, L"N-02 端口字段配 blob 值不做判定");
    s.expect(HasLimitation(mismatchEval.limitationKeys, "wfp.condition.value-type-mismatch"),
             L"N-02 值类型错配写进限制说明");
}

// ---------------------------------------------------------------------------
// N-02 / N-03：条件合并
// ---------------------------------------------------------------------------
void TestConditionCombination(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();

    std::vector<ConditionEvaluation> none;
    s.expect(CombineConditionResults(none, false) == ConditionMatch::Match,
             L"N-03 真正的空条件集才是无条件匹配");
    s.expect(CombineConditionResults(none, true) == ConditionMatch::InsufficientInfo,
             L"N-02 条件被截断时不能当成无条件匹配");

    // 同字段 OR：一条命中即整组命中
    std::vector<ConditionEvaluation> sameField;
    sameField.push_back(EvaluateCondition(RemotePortEquals(443U), connection));
    sameField.push_back(EvaluateCondition(RemotePortEquals(80U), connection));
    s.expect(sameField[0].result == ConditionMatch::Match, L"N-02 同字段第一条命中");
    s.expect(sameField[1].result == ConditionMatch::NoMatch, L"N-02 同字段第二条不命中");
    s.expect(CombineConditionResults(sameField, false) == ConditionMatch::Match,
             L"N-03 同一字段的多条条件按 OR 合并");

    // 跨字段 AND：一条不命中即整体不命中
    std::vector<ConditionEvaluation> crossField;
    crossField.push_back(EvaluateCondition(RemotePortEquals(443U), connection));
    crossField.push_back(EvaluateCondition(
        MakeCondition(G(kGuidProtocol), kMatchEqual, NumericValue(WfpDataType::Uint8, kTypeUint8, 17U)),
        connection));
    s.expect(CombineConditionResults(crossField, false) == ConditionMatch::NoMatch,
             L"N-03 不同字段的条件按 AND 合并");

    // 匹配 AND 未知 = 未知（这是"未知条件不等于无条件匹配"的核心）
    std::vector<ConditionEvaluation> withUnknown;
    withUnknown.push_back(EvaluateCondition(RemotePortEquals(443U), connection));
    withUnknown.push_back(EvaluateCondition(
        MakeCondition(G("{daf8cd14-e09e-4c93-a5ae-c5c13b73ffca}"), kMatchEqual,
                      NumericValue(WfpDataType::Uint32, kTypeUint32, 1U)),
        connection));
    s.expect(CombineConditionResults(withUnknown, false) == ConditionMatch::InsufficientInfo,
             L"N-02 命中条件 AND 未知条件的结果是未知");

    // 不匹配 AND 未知 = 不匹配（未知不会把确定的否定拉回来）
    std::vector<ConditionEvaluation> noMatchWithUnknown;
    noMatchWithUnknown.push_back(EvaluateCondition(RemotePortEquals(8080U), connection));
    noMatchWithUnknown.push_back(withUnknown[1]);
    s.expect(CombineConditionResults(noMatchWithUnknown, false) == ConditionMatch::NoMatch,
             L"N-03 确定的不匹配不会被未知条件抬回未知");

    // 截断 + 已有条件不匹配 = 仍然不匹配
    s.expect(CombineConditionResults(noMatchWithUnknown, true) == ConditionMatch::NoMatch,
             L"N-02 截断不会把确定的不匹配变成未知");
}

// ---------------------------------------------------------------------------
// N-03：按 layer / sublayer 的候选仲裁
// ---------------------------------------------------------------------------
WfpCatalog MakeArbitrationCatalog(std::uint64_t highWeight, std::uint64_t lowWeight) {
    WfpCatalog catalog;
    catalog.setGeneration(7U);

    // N-06：采集时间与启动周期跟着目录走，跨启动的运行时 id 才有得核对。
    CaptureWindow window;
    window.bootId = "boot-N";
    window.machineId = "machine-N";
    window.sessionId = "session-N";
    window.mode = CaptureMode::Snapshot;
    window.startUtc100ns = OptionalU64::of(133700000000000000ULL);
    window.endUtc100ns = OptionalU64::of(133700000500000000ULL);
    catalog.setCaptureWindow(window);

    WfpProvider provider;
    provider.providerKey = G(kProviderA);
    provider.displayName = Text("KSword Test Provider");
    catalog.addProvider(provider);

    WfpLayer layer;
    layer.layerKey = G(kLayerAle);
    layer.displayName = Text("ALE_AUTH_CONNECT_V4");
    layer.layerId = OptionalU64::of(48U);
    catalog.addLayer(layer);

    WfpSubLayer high;
    high.subLayerKey = G(kSubLayerHigh);
    high.displayName = Text("SubLayerHigh");
    high.weight = OptionalU64::of(highWeight);
    catalog.addSubLayer(high);

    WfpSubLayer low;
    low.subLayerKey = G(kSubLayerLow);
    low.displayName = Text("SubLayerLow");
    low.weight = OptionalU64::of(lowWeight);
    catalog.addSubLayer(low);

    WfpCallout callout;
    callout.calloutKey = G(kCalloutX);
    callout.displayName = Text("InspectionCallout");
    callout.calloutId = OptionalU64::of(90U);
    callout.registered = true;
    catalog.addCallout(callout);

    MarkPartitionComplete(catalog, WfpPartition::Providers, 1U);
    MarkPartitionComplete(catalog, WfpPartition::Layers, 1U);
    MarkPartitionComplete(catalog, WfpPartition::SubLayers, 2U);
    MarkPartitionComplete(catalog, WfpPartition::Callouts, 1U);
    return catalog;
}

void TestStaticArbitration(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();

    // --- 场景 A：单个 sublayer 内按权重降序，最高权重的匹配规则胜出 ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter lowPriority = MakeFilter(kFilter1, 101U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        SetEffectiveWeight(lowPriority, 100U);
        lowPriority.conditions.push_back(RemotePortEquals(443U));
        WfpFilter highPriority = MakeFilter(kFilter2, 102U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(highPriority, 9000U);
        highPriority.conditions.push_back(RemotePortEquals(443U));
        catalog.addFilter(lowPriority);
        catalog.addFilter(highPriority);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(report.evaluatedFilterCount == 2U, L"N-03 两条规则都参与了候选评估");
        s.expect(report.layers.size() == 1U, L"N-03 两条规则归入同一个 layer 分组");
        s.expect(LayerAt(report, 0U).subLayers.size() == 1U, L"N-03 同 sublayer 的规则归入同一组");
        s.expect(SubAt(LayerAt(report, 0U), 0U).filters.size() == 2U, L"N-03 分组内保留全部两条规则");
        s.expect(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).filterKey.text == std::string(kFilter2),
                 L"N-03 分组内按权重降序：9000 的规则排在前面");
        s.expect(SubAt(LayerAt(report, 0U), 0U).orderingReliable, L"N-03 同量纲且不重复的权重可作为排序依据");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::BlockCandidate,
                 L"N-03 sublayer 内最高权重的匹配规则决定候选结论");
        s.expect(LayerAt(report, 0U).decision == CandidateDecision::BlockCandidate, L"N-03 层结论与其唯一 sublayer 一致");
        s.expect(report.overallDecision == CandidateDecision::BlockCandidate, L"N-03 整体候选结论为阻断候选");
        s.expect(LayerAt(report, 0U).layer.state == ReferenceState::Resolved, L"N-03 layer 关联成功");
        s.expect(SubAt(LayerAt(report, 0U), 0U).subLayerWeight == OptionalU64::of(60000U),
                 L"N-03 sublayer 权重取自 sublayer 对象而不是 filter");
        s.expect(HasLimitation(report.limitationKeys, "wfp.candidate.layer-default-action-not-modeled"),
                 L"N-03 明确声明层默认动作未建模");
        s.expect(HasLimitation(report.limitationKeys, "wfp.candidate.filter-flags-not-modeled"),
                 L"N-03 明确声明 filter 标志位未建模");
    }

    // --- 场景 B：不同 sublayer 各自仲裁，绝不按一个全局 weight 排序 ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        // 高权重 sublayer 里放一条**低** filter 权重的放行规则
        WfpFilter permitInHighSubLayer =
            MakeFilter(kFilter1, 201U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        SetEffectiveWeight(permitInHighSubLayer, 10U);
        permitInHighSubLayer.conditions.push_back(RemotePortEquals(443U));
        // 低权重 sublayer 里放一条**高** filter 权重的阻断规则
        WfpFilter blockInLowSubLayer =
            MakeFilter(kFilter2, 202U, kSubLayerLow, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(blockInLowSubLayer, 5000U);
        blockInLowSubLayer.conditions.push_back(RemotePortEquals(443U));
        catalog.addFilter(permitInHighSubLayer);
        catalog.addFilter(blockInLowSubLayer);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(report.layers.size() == 1U, L"N-03 两条规则同层");
        s.expect(LayerAt(report, 0U).subLayers.size() == 2U, L"N-03 不同 sublayer 分成两组");
        s.expect(SubAt(LayerAt(report, 0U), 0U).subLayerWeight == OptionalU64::of(60000U),
                 L"N-03 sublayer 按自己的权重降序排列");
        s.expect(SubAt(LayerAt(report, 0U), 0U).filters.size() == 1U,
                 L"N-03 高权重 sublayer 里只有属于它的那条规则");
        s.expect(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).filterKey.text == std::string(kFilter1),
                 L"N-03 全局权重更高的规则没有被挪进别的 sublayer");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::PermitCandidate,
                 L"N-03 低 filter 权重的规则在自己的 sublayer 里照样胜出");
        s.expect(SubAt(LayerAt(report, 0U), 1U).decision == CandidateDecision::BlockCandidate,
                 L"N-03 另一个 sublayer 独立得出阻断候选");
        s.expect(LayerAt(report, 0U).decision == CandidateDecision::BlockCandidate,
                 L"N-03 全部 sublayer 判明时阻断压过放行");
        s.expect(LayerAt(report, 0U).subLayerOrderingReliable, L"N-03 sublayer 权重齐备且不重复时顺序可信");
    }

    // --- 场景 C：不同 sublayer + 不同权重 + 缺元数据 + callout 动态判断 -> Unknown ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter permitHigh = MakeFilter(kFilter1, 301U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        SetEffectiveWeight(permitHigh, 900U);
        permitHigh.conditions.push_back(RemotePortEquals(443U));

        WfpFilter blockNoWeight = MakeFilter(kFilter2, 302U, kSubLayerLow, kActionBlock, WfpActionType::Block);
        blockNoWeight.weightKind = WfpWeightKind::Auto;  // 缺权重元数据
        blockNoWeight.conditions.push_back(RemotePortEquals(443U));

        WfpFilter dynamicCallout =
            MakeFilter(kFilter3, 303U, kSubLayerLow, kActionCalloutTerminating, WfpActionType::CalloutTerminating);
        dynamicCallout.actionCalloutKey = G(kCalloutX);
        SetEffectiveWeight(dynamicCallout, 800U);
        dynamicCallout.conditions.push_back(RemotePortEquals(443U));

        catalog.addFilter(permitHigh);
        catalog.addFilter(blockNoWeight);
        catalog.addFilter(dynamicCallout);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 3U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(report.layers.size() == 1U, L"N-03 混合规则组仍在同一层");
        s.expect(LayerAt(report, 0U).subLayers.size() == 2U, L"N-03 混合规则组按 sublayer 分成两组");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::PermitCandidate,
                 L"N-03 元数据齐备的 sublayer 仍然给出可知结论");
        s.expect(SubAt(LayerAt(report, 0U), 1U).filters.size() == 2U, L"N-03 低权重 sublayer 有两条规则");
        s.expect(!SubAt(LayerAt(report, 0U), 1U).orderingReliable,
                 L"N-03 有规则缺权重时该 sublayer 顺序不可信");
        s.expect(HasLimitation(SubAt(LayerAt(report, 0U), 1U).limitationKeys, "wfp.sublayer.order-unreliable"),
                 L"N-03 顺序不可信写进限制说明");
        s.expect(SubAt(LayerAt(report, 0U), 1U).decision == CandidateDecision::Unknown,
                 L"N-03 缺元数据 + 动态 callout 的 sublayer 结论保持未知");
        s.expect(LayerAt(report, 0U).decision == CandidateDecision::Unknown,
                 L"N-03 有 sublayer 不确定时整层保持未知");
        s.expect(report.overallDecision == CandidateDecision::Unknown,
                 L"N-03 存在动态判断时最终决策必须保留未知");
        s.expect(report.overallDecision != CandidateDecision::BlockCandidate,
                 L"N-03 不确定时不许升级成阻断结论");

        bool sawDynamicKey = false;
        bool calloutResolved = false;
        for (const FilterCandidate& candidate : SubAt(LayerAt(report, 0U), 1U).filters) {
            if (candidate.filterKey.text == std::string(kFilter3)) {
                sawDynamicKey = HasLimitation(candidate.limitationKeys, "wfp.filter.dynamic-callout");
                calloutResolved = candidate.actionCallout.state == ReferenceState::Resolved;
                s.expect(candidate.dynamicByCallout, L"N-03 callout 动作被标为动态判定");
            }
        }
        s.expect(sawDynamicKey, L"N-03 动态 callout 写进该规则的限制说明");
        s.expect(calloutResolved, L"N-01 filter 的 action callout 关联到目录里的 callout 对象");
    }

    // --- 场景 D：没有任何规则匹配 -> NoMatchingFilter，而不是"放行" ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter unrelated = MakeFilter(kFilter1, 401U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(unrelated, 500U);
        unrelated.conditions.push_back(RemotePortEquals(8080U));
        catalog.addFilter(unrelated);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 1U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::NoMatchingFilter,
                 L"N-03 无规则匹配时结论是「无匹配规则」");
        s.expect(report.overallDecision == CandidateDecision::NoMatchingFilter,
                 L"N-03 无匹配规则不等于放行候选");
        s.expect(report.overallDecision != CandidateDecision::PermitCandidate,
                 L"N-03 不把「没匹配上」翻译成放行");
    }

    // --- 场景 E：更高权重的规则条件读不懂 -> 整个 sublayer 保持未知 ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter unreadable = MakeFilter(kFilter1, 501U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        SetEffectiveWeight(unreadable, 9000U);
        unreadable.conditions.push_back(MakeCondition(G(kGuidUnmodeled), kMatchEqual,
                                                      NumericValue(WfpDataType::Uint32, kTypeUint32, 1U)));
        WfpFilter definite = MakeFilter(kFilter2, 502U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(definite, 10U);
        definite.conditions.push_back(RemotePortEquals(443U));
        catalog.addFilter(unreadable);
        catalog.addFilter(definite);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).match == ConditionMatch::InsufficientInfo,
                 L"N-02 读不懂条件的规则匹配结论是信息不足");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::Unknown,
                 L"N-03 更高权重的规则不确定时不能拿下面的确定规则当结论");
        s.expect(report.overallDecision != CandidateDecision::BlockCandidate,
                 L"N-03 上方存在未知规则时不得给出阻断结论");
    }

    // --- 场景 F：顺序不可信但候选唯一 -> 结论与顺序无关，可以给出 ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter noWeightMatch = MakeFilter(kFilter1, 601U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        noWeightMatch.weightKind = WfpWeightKind::Auto;
        noWeightMatch.conditions.push_back(RemotePortEquals(443U));
        WfpFilter noWeightMiss = MakeFilter(kFilter2, 602U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        noWeightMiss.weightKind = WfpWeightKind::Auto;
        noWeightMiss.conditions.push_back(RemotePortEquals(8080U));
        catalog.addFilter(noWeightMatch);
        catalog.addFilter(noWeightMiss);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(!SubAt(LayerAt(report, 0U), 0U).orderingReliable, L"N-03 两条规则都缺权重时顺序不可信");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::BlockCandidate,
                 L"N-03 唯一候选时结论与顺序无关");
    }

    // --- 场景 G：权重量纲混用 -> 不敢排序 ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter effective = MakeFilter(kFilter1, 701U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(effective, 900U);
        effective.conditions.push_back(RemotePortEquals(443U));
        WfpFilter explicitOnly = MakeFilter(kFilter2, 702U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        explicitOnly.weightKind = WfpWeightKind::Explicit;
        explicitOnly.weight = OptionalU64::of(15U);  // 没有 effectiveWeight
        explicitOnly.conditions.push_back(RemotePortEquals(443U));
        catalog.addFilter(effective);
        catalog.addFilter(explicitOnly);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(!SubAt(LayerAt(report, 0U), 0U).orderingReliable,
                 L"N-03 effectiveWeight 与显式 weight 混用时顺序不可信");
        s.expect(HasLimitation(SubAt(LayerAt(report, 0U), 0U).limitationKeys, "wfp.sublayer.weight-scale-mixed"),
                 L"N-03 权重量纲混用写进限制说明");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::Unknown,
                 L"N-03 两个候选且顺序不可信时结论保持未知");
    }

    // --- 场景 H：条件被截断的规则不能当成无条件匹配 ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter truncated = MakeFilter(kFilter1, 801U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(truncated, 900U);
        truncated.conditions.push_back(RemotePortEquals(443U));
        truncated.conditionsTruncated = true;
        catalog.addFilter(truncated);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 1U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).match == ConditionMatch::InsufficientInfo,
                 L"N-02 条件被截断的规则匹配结论是信息不足");
        s.expect(HasLimitation(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).limitationKeys,
                               "wfp.filter.conditions-truncated"),
                 L"N-02 条件截断写进限制说明");
        s.expect(report.overallDecision == CandidateDecision::Unknown, L"N-03 条件截断时结论保持未知");
    }

    // --- 场景 I：缺 layer / sublayer 元数据的规则单独成组并标注 ---
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter orphan = MakeFilter(kFilter1, 901U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        orphan.layerKey = WfpGuid{};      // 没采到 layer 引用
        orphan.subLayerKey = WfpGuid{};   // 没采到 sublayer 引用
        SetEffectiveWeight(orphan, 900U);
        orphan.conditions.push_back(RemotePortEquals(443U));
        WfpFilter normal = MakeFilter(kFilter2, 902U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        SetEffectiveWeight(normal, 800U);
        normal.conditions.push_back(RemotePortEquals(443U));
        catalog.addFilter(orphan);
        catalog.addFilter(normal);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(report.layers.size() == 2U, L"N-01 缺 layer 引用的规则不并进已知层");
        bool foundUnspecifiedLayer = false;
        for (const LayerCandidateGroup& group : report.layers) {
            if (group.layer.state == ReferenceState::NotSpecified) {
                foundUnspecifiedLayer = true;
                s.expect(HasLimitation(group.limitationKeys, "wfp.filter.layer-missing"),
                         L"N-01 缺 layer 引用写进限制说明");
                s.expect(group.subLayers.size() == 1U, L"N-01 缺引用的规则自成一组");
                s.expect(SubAt(group, 0U).subLayer.state == ReferenceState::NotSpecified,
                         L"N-01 缺 sublayer 引用也是 NotSpecified");
                s.expect(!SubAt(group, 0U).subLayerWeight.present,
                         L"N-03 无法确定 sublayer 时不拿 0 当权重");
            }
        }
        s.expect(foundUnspecifiedLayer, L"N-01 存在一个未指定 layer 的分组");
        for (const LayerCandidateGroup& group : report.layers) {
            if (group.layer.state == ReferenceState::NotSpecified) {
                s.expect(group.unlinkedReference, L"N-01 缺引用的分组被标为「所属范围未知」");
                s.expect(!SubAt(group, 0U).orderingReliable,
                         L"N-03 所属范围未知时顺序一律不可信（连和谁竞争都不知道）");
                s.expect(SubAt(group, 0U).decision == CandidateDecision::Unknown,
                         L"N-03 所属范围未知的分组不得给出阻断/放行候选，只能是未知");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// N-01 / N-03：缺 layer / sublayer 引用的规则每条独占一个仲裁范围
//
// 「未知引用不并进已知分组」与「未知引用之间也不许互相并组」是同一条规则。两条不知道
// 属于哪个 layer 的规则很可能一条在 ALE_AUTH_CONNECT_V4、一条在 OUTBOUND_TRANSPORT_V4，
// 把它们放进同一个桶按权重仲裁，等于凭空发明了一个仲裁范围。
// ---------------------------------------------------------------------------
void TestUnlinkedFiltersNeverArbitrateTogether(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();

    // 两条 layer/sublayer 都未采集的规则：Block(900) 与 Permit(100)，条件都命中 443。
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter orphanBlock = MakeFilter(kFilter1, 901U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        orphanBlock.layerKey = WfpGuid{};
        orphanBlock.subLayerKey = WfpGuid{};
        SetEffectiveWeight(orphanBlock, 900U);
        orphanBlock.conditions.push_back(RemotePortEquals(443U));
        WfpFilter orphanPermit = MakeFilter(kFilter2, 902U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        orphanPermit.layerKey = WfpGuid{};
        orphanPermit.subLayerKey = WfpGuid{};
        SetEffectiveWeight(orphanPermit, 100U);
        orphanPermit.conditions.push_back(RemotePortEquals(443U));
        catalog.addFilter(orphanBlock);
        catalog.addFilter(orphanPermit);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(report.evaluatedFilterCount == 2U, L"N-03 两条无引用规则都参与了评估");
        s.expect(report.layers.size() == 2U,
                 L"N-01 两条引用未采集的规则各自独占一个分组，不互相并组");
        s.expect(LayerAt(report, 0U).subLayers.size() == 1U, L"N-01 第一个未知引用分组里只有一条规则");
        s.expect(SubAt(LayerAt(report, 0U), 0U).filters.size() == 1U,
                 L"N-01 未知引用分组不收第二条规则");
        s.expect(SubAt(LayerAt(report, 1U), 0U).filters.size() == 1U,
                 L"N-01 第二条未知引用规则也自成一组");
        s.expect(!SubAt(LayerAt(report, 0U), 0U).orderingReliable,
                 L"N-03 引用未采集的分组顺序不可信");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::Unknown,
                 L"N-03 权重 900 的 Block 不因为独占分组就变成阻断候选");
        s.expect(SubAt(LayerAt(report, 1U), 0U).decision == CandidateDecision::Unknown,
                 L"N-03 权重 100 的 Permit 同样只能是未知");
        s.expect(report.overallDecision == CandidateDecision::Unknown,
                 L"N-03 900 压过 100 这种结论在范围未知时不成立，整体保持未知");
        s.expect(report.overallDecision != CandidateDecision::BlockCandidate,
                 L"N-03 绝不从未知仲裁范围推出阻断候选");
        s.expect(HasLimitation(SubAt(LayerAt(report, 0U), 0U).limitationKeys, "wfp.filter.layer-missing"),
                 L"N-01 缺 layer 引用写进分组自己的限制说明");
        s.expect(HasLimitation(SubAt(LayerAt(report, 0U), 0U).limitationKeys, "wfp.filter.sublayer-missing"),
                 L"N-01 缺 sublayer 引用写进分组自己的限制说明");
    }

    // layer 采到了、sublayer 没采到的两条规则：同层，但仍然各自独占一个 sublayer 分组。
    {
        WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter a = MakeFilter(kFilter1, 911U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        a.subLayerKey = WfpGuid{};
        SetEffectiveWeight(a, 900U);
        a.conditions.push_back(RemotePortEquals(443U));
        WfpFilter b = MakeFilter(kFilter2, 912U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        b.subLayerKey = WfpGuid{};
        SetEffectiveWeight(b, 100U);
        b.conditions.push_back(RemotePortEquals(443U));
        catalog.addFilter(a);
        catalog.addFilter(b);
        MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
        s.expect(report.layers.size() == 1U, L"N-01 layer 引用还在，两条规则仍归入同一层");
        s.expect(LayerAt(report, 0U).subLayers.size() == 2U,
                 L"N-01 sublayer 引用未采集时两条规则不共用一个 sublayer 分组");
        s.expect(SubAt(LayerAt(report, 0U), 0U).filters.size() == 1U, L"N-01 每个未知 sublayer 分组只有一条规则");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::Unknown,
                 L"N-03 sublayer 未知时该分组结论保持未知");
        s.expect(LayerAt(report, 0U).decision == CandidateDecision::Unknown,
                 L"N-03 层内有范围未知的分组时整层保持未知");
        s.expect(LayerAt(report, 0U).unlinkedReference,
                 L"N-01 层分组标出「含有所属范围未知的规则」");
    }
}

// ---------------------------------------------------------------------------
// N-03 / N-06：目录不足以证明缺席时，「无匹配规则」一律降级为未知
//
// 这是一条缺席断言：只有 filter 分区能正面证明枚举完整，才允许说"该范围内没有任何
// 规则匹配"。BFE 打不开、分区没采、只枚举到 1/9 —— 这些情况下给出的"无匹配规则"
// 与"完整枚举 2000 条后确实没有规则匹配"在 UI 上是同一句话。
// ---------------------------------------------------------------------------
void TestAbsenceRequiresCompleteCatalog(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();

    // (a) 全新目录：所有分区 NotCollected
    {
        WfpCatalog empty;
        const StaticCandidateReport report = AnalyzeStaticCandidates(empty, connection);
        s.expect(report.layers.empty(), L"N-06 空目录没有任何分组");
        s.expect(report.evaluatedFilterCount == 0U, L"N-06 空目录评估了 0 条规则");
        s.expect(!report.catalogUsableForAbsence, L"N-06 未采集的分区不能用来推断缺席");
        s.expect(report.overallDecision == CandidateDecision::Unknown,
                 L"N-06 一条规则都没采到时结论是未知，不是「无匹配规则」");
        s.expect(report.overallDecision != CandidateDecision::NoMatchingFilter,
                 L"N-06 没采到绝不等于确实没有规则");
        s.expect(HasLimitation(report.limitationKeys, "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 目录不完整写进报告级限制说明");
    }

    // (b) BFE 打不开：分区落成 Error + 原始错误码
    {
        WfpCatalog broken = MakeArbitrationCatalog(60000U, 100U);
        broken.setPartitionState(WfpPartition::Filters,
                                 CollectionOutcome::failure(CollectionStatus::Error, "WIN32", 1753ULL,
                                                            "FwpmEngineOpen0 failed"),
                                 CoverageAccount{});
        const StaticCandidateReport report = AnalyzeStaticCandidates(broken, connection);
        s.expect(!report.catalogUsableForAbsence, L"N-06 BFE 打不开时目录不可用于缺席推断");
        s.expect(report.overallDecision == CandidateDecision::Unknown,
                 L"N-06 BFE 打不开时结论是未知而不是「无匹配规则」");
        s.expect(broken.partitionState(WfpPartition::Filters).outcome.nativeCode == OptionalU64::of(1753ULL),
                 L"N-06 原始 Win32 错误码 1753 仍然保留");
    }

    // (c) Partial：声明 9 条只枚举到 1 条，那一条还不匹配
    {
        WfpCatalog partial = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter onlyOne = MakeFilter(kFilter1, 1001U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(onlyOne, 500U);
        onlyOne.conditions.push_back(RemotePortEquals(8080U));  // 与 443 不匹配
        partial.addFilter(onlyOne);
        CoverageAccount account;
        account.totalKnown = OptionalU64::of(9U);
        account.succeeded = 1U;
        account.limitHit = true;
        partial.setPartitionState(WfpPartition::Filters,
                                  CollectionOutcome::failure(CollectionStatus::Partial, "WIN32", 0ULL,
                                                             "enumeration limit"),
                                  account);

        const StaticCandidateReport report = AnalyzeStaticCandidates(partial, connection);
        s.expect(!report.catalogUsableForAbsence, L"N-06 只枚举到 1/9 的分区不能推断缺席");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::Unknown,
                 L"N-06 枚举不全时 sublayer 结论降级为未知");
        s.expect(LayerAt(report, 0U).decision == CandidateDecision::Unknown,
                 L"N-06 枚举不全时 layer 结论降级为未知");
        s.expect(report.overallDecision == CandidateDecision::Unknown,
                 L"N-06 枚举不全时整体结论降级为未知");
        s.expect(HasLimitation(SubAt(LayerAt(report, 0U), 0U).limitationKeys,
                               "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 目录不完整写进 sublayer 分组的限制说明（不能只写在报告级）");
        s.expect(HasLimitation(LayerAt(report, 0U).limitationKeys,
                               "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 目录不完整写进 layer 分组的限制说明");
    }

    // (d) 反向守卫：账目能正面证明完整时，「无匹配规则」照常给出
    {
        WfpCatalog complete = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter unrelated = MakeFilter(kFilter1, 1002U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(unrelated, 500U);
        unrelated.conditions.push_back(RemotePortEquals(8080U));
        complete.addFilter(unrelated);
        MarkPartitionComplete(complete, WfpPartition::Filters, 1U);

        const StaticCandidateReport report = AnalyzeStaticCandidates(complete, connection);
        s.expect(report.catalogUsableForAbsence, L"N-06 账目正面证明完整时目录可用于缺席推断");
        s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::NoMatchingFilter,
                 L"N-06 完整枚举后确实没有规则匹配才允许说「无匹配规则」");
        s.expect(report.overallDecision == CandidateDecision::NoMatchingFilter,
                 L"N-06 完整枚举的「无匹配规则」结论没有被过度降级");
        s.expect(!HasLimitation(report.limitationKeys, "wfp.candidate.filter-catalog-incomplete"),
                 L"N-06 完整枚举时不误报目录不完整");
    }

    // (e) 关联判据：目录采到了但没采全时，「目录里没有」不是「未知对象」也不是「NoMatch」
    {
        WfpCatalog partial = MakeArbitrationCatalog(60000U, 100U);
        partial.setGeneration(7U);
        WfpFilter present = MakeFilter(kFilter1, 77U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(present, 900U);
        partial.addFilter(present);
        CoverageAccount account;
        account.totalKnown = OptionalU64::of(9U);
        account.succeeded = 1U;
        account.limitHit = true;
        partial.setPartitionState(WfpPartition::Filters,
                                  CollectionOutcome::failure(CollectionStatus::Partial, "WIN32", 0ULL,
                                                             "enumeration limit"),
                                  account);

        s.expect(partial.resolveFilter(G(kFilter4)).state == ReferenceState::CatalogIncomplete,
                 L"N-06 枚举不全时缺失关联是「目录不完整」而不是「未知对象」");
        s.expect(partial.resolveFilter(G(kFilter1)).state == ReferenceState::Resolved,
                 L"N-06 枚举不全不影响已经采到的那条的关联");

        RuntimeFilterReference byGuid;
        byGuid.filterKey = G(kFilter4);
        const FilterReferenceResolution guidResult = ResolveFilterReference(partial, byGuid);
        s.expect(guidResult.state == FilterLinkState::CatalogIncomplete,
                 L"N-06 枚举不全时按 GUID 找不到不等于「没有这条」");
        s.expect(guidResult.state != FilterLinkState::NoMatch, L"N-06 找不到不等于确实不存在");
        s.expect(HasLimitation(guidResult.limitationKeys, "wfp.link.catalog-incomplete"),
                 L"N-06 目录不完整写进关联的限制说明");

        RuntimeFilterReference byId;
        byId.filterId = OptionalU64::of(4242U);
        byId.capturedGeneration = OptionalU64::of(7U);
        byId.bootId = "boot-N";
        const FilterReferenceResolution idResult = ResolveFilterReference(partial, byId);
        s.expect(idResult.state == FilterLinkState::CatalogIncomplete,
                 L"N-06 枚举不全时运行时 id 找不到同样不下缺席结论");
        s.expect(HasLimitation(idResult.limitationKeys, "wfp.link.catalog-incomplete"),
                 L"N-06 运行时 id 关联也写进目录不完整");

        // 反向守卫：完整目录里找不到才是 NoMatch / UnknownObject
        WfpCatalog complete = MakeArbitrationCatalog(60000U, 100U);
        complete.setGeneration(7U);
        complete.addFilter(present);
        MarkPartitionComplete(complete, WfpPartition::Filters, 1U);
        s.expect(complete.resolveFilter(G(kFilter4)).state == ReferenceState::UnknownObject,
                 L"N-06 完整目录里找不到才是「未知对象」");
        s.expect(ResolveFilterReference(complete, byGuid).state == FilterLinkState::NoMatch,
                 L"N-06 完整目录里找不到才是「没有这条」");
    }
}

// ---------------------------------------------------------------------------
// N-02：没读出来的地址不是"不在子网内"
//
// WfpConditionValue.v4/v6 里的 address 默认 family==Unknown，而 ParseIpAddress 失败时
// 按设计不修改 out —— 于是离线样本里一条地址文本解析失败就会留下 v4Present=true 加一个
// 未知族的地址。包含判定若把它当成"确定的 false"，FWP_MATCH_NOT_EQUAL 的取反会把它翻成
// "匹配"，等于从根本没读出来的地址推出了阻断候选。
// ---------------------------------------------------------------------------
void TestUndecodedAddressNeverMatches(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();

    // 前提：解析失败不修改 out，未知地址的 family 就是 Unknown、文本是空串。
    WfpAddress undecoded;
    s.expect(!undecoded.known(), L"N-02 未解析的地址默认是未知地址");
    s.expect(undecoded.family == WfpAddressFamily::Unknown, L"N-02 未知地址的族是 Unknown");
    s.expect(FormatIpAddress(undecoded).empty(), L"N-02 未知地址的展示文本是空串而不是 0.0.0.0");
    s.expect(!ParseIpAddress("10.0.0.999", undecoded), L"N-02 越界文本解析失败");
    s.expect(!undecoded.known(), L"N-02 解析失败后地址仍然是未知，不是半成品");

    // 三态包含判定：Undecidable 与 Outside 是两回事
    const WfpV4AddrMask subnet{ Ipv4(10U, 0U, 0U, 0U), 0xFF000000U };
    s.expect(ClassifyV4Containment(Ipv4(10U, 1U, 2U, 3U), subnet) == AddressContainment::Inside,
             L"N-02 10.1.2.3 在 10/8 内");
    s.expect(ClassifyV4Containment(Ipv4(11U, 1U, 2U, 3U), subnet) == AddressContainment::Outside,
             L"N-02 11.1.2.3 确实不在 10/8 内");
    const WfpV4AddrMask undecodedSubnet{ WfpAddress{}, 0xFFFFFF00U };
    s.expect(ClassifyV4Containment(Ipv4(10U, 1U, 2U, 3U), undecodedSubnet) == AddressContainment::Undecidable,
             L"N-02 网络地址没解出来时包含判定是「无法判定」而不是「不在里面」");
    s.expect(!AddressInV4Subnet(Ipv4(10U, 1U, 2U, 3U), undecodedSubnet),
             L"N-02 布尔便捷形式对无法判定同样返回 false（调用方不得对它取反）");
    WfpV6AddrPrefix undecodedPrefix;
    undecodedPrefix.prefixLength = 32U;
    undecodedPrefix.prefixLengthValid = true;
    WfpAddress v6Actual;
    (void)ParseIpAddress("2001:db8:1::5", v6Actual);
    s.expect(ClassifyV6Containment(v6Actual, undecodedPrefix) == AddressContainment::Undecidable,
             L"N-02 v6 网络地址没解出来时同样是「无法判定」");

    // 条件求值：EQUAL 与 NOT_EQUAL 都必须是信息不足
    WfpConditionValue badV4;
    badV4.type = WfpDataType::V4AddrMask;
    badV4.rawTypeCode = kTypeV4AddrMask;
    badV4.v4Present = true;         // 样本声称带了地址+掩码
    badV4.v4.mask = 0xFFFFFF00U;    // 掩码解出来了
    // badV4.v4.address 保持未知 —— 地址文本解析失败
    const WfpCondition v4Equal = MakeCondition(G(kGuidRemoteAddress), kMatchEqual, badV4);
    const ConditionEvaluation v4EqualEval = EvaluateCondition(v4Equal, connection);
    s.expect(v4EqualEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 网络地址没解码时等值比较是信息不足，不是不匹配");
    s.expect(HasLimitation(v4EqualEval.limitationKeys, "wfp.condition.address-not-decoded"),
             L"N-02 地址未解码写进限制说明");
    const WfpCondition v4NotEqual = MakeCondition(G(kGuidRemoteAddress), kMatchNotEqual, badV4);
    const ConditionEvaluation v4NotEqualEval = EvaluateCondition(v4NotEqual, connection);
    s.expect(v4NotEqualEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 地址没解码时否定比较仍是信息不足");
    s.expect(v4NotEqualEval.result != ConditionMatch::Match,
             L"N-02 绝不允许把「读不出来」取反成「匹配」");

    WfpConditionValue badV6;
    badV6.type = WfpDataType::V6AddrMask;
    badV6.rawTypeCode = kTypeV6AddrMask;
    badV6.v6Present = true;
    badV6.v6.prefixLength = 64U;
    badV6.v6.prefixLengthValid = true;
    ConnectionDescription v6Connection = MakeConnection();
    (void)ParseIpAddress("2001:db8:1::5", v6Connection.remoteAddress);
    const ConditionEvaluation v6EqualEval =
        EvaluateCondition(MakeCondition(G(kGuidRemoteAddress), kMatchEqual, badV6), v6Connection);
    s.expect(v6EqualEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 v6 前缀地址没解码时等值比较是信息不足");
    s.expect(HasLimitation(v6EqualEval.limitationKeys, "wfp.condition.address-not-decoded"),
             L"N-02 v6 地址未解码写进限制说明");
    s.expect(EvaluateCondition(MakeCondition(G(kGuidRemoteAddress), kMatchNotEqual, badV6), v6Connection)
                     .result == ConditionMatch::InsufficientInfo,
             L"N-02 v6 地址没解码时否定比较不得翻成匹配");

    WfpConditionValue badSingle;
    badSingle.type = WfpDataType::ByteArray16;
    badSingle.rawTypeCode = kTypeByteArray16;
    // singleAddress 保持未知
    const ConditionEvaluation singleEval =
        EvaluateCondition(MakeCondition(G(kGuidRemoteAddress), kMatchNotEqual, badSingle), v6Connection);
    s.expect(singleEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 单个 IPv6 地址没解码时否定比较是信息不足");
    s.expect(HasLimitation(singleEval.limitationKeys, "wfp.condition.address-not-decoded"),
             L"N-02 未解码的单地址写进限制说明");

    // 端到端：一条只带该条件的 Block 规则不得变成阻断候选
    WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
    WfpFilter blockOnUndecoded = MakeFilter(kFilter1, 1101U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    SetEffectiveWeight(blockOnUndecoded, 900U);
    blockOnUndecoded.conditions.push_back(v4NotEqual);
    catalog.addFilter(blockOnUndecoded);
    MarkPartitionComplete(catalog, WfpPartition::Filters, 1U);
    const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
    s.expect(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).match == ConditionMatch::InsufficientInfo,
             L"N-02 条件地址没解码的规则匹配结论是信息不足");
    s.expect(HasLimitation(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).limitationKeys,
                           "wfp.condition.address-not-decoded"),
             L"N-02 地址未解码写进该规则的限制说明");
    s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::Unknown,
             L"N-02 从没读出来的地址不得推出阻断候选");
    s.expect(report.overallDecision != CandidateDecision::BlockCandidate,
             L"N-02 未解码地址绝不产生阻断候选");
}

// ---------------------------------------------------------------------------
// N-02：读坏的 FWP_RANGE0 不是"确定的不匹配"
//
// low > high 对任何 actual 都恒为 false。把它当成确定的 NoMatch，会让该 filter 在
// DecideWithinSubLayer 里被直接跳过，把仲裁结论让给权重更低的规则。
// ---------------------------------------------------------------------------
void TestMalformedRangeStaysUnknown(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();  // remotePort = 443

    const WfpCondition inverted = MakeCondition(G(kGuidRemotePort), kMatchRange, RangeValue(500U, 400U));
    const ConditionEvaluation invertedEval = EvaluateCondition(inverted, connection);
    s.expect(invertedEval.result == ConditionMatch::InsufficientInfo,
             L"N-02 low>high 的范围读不出合法区间，判定为信息不足");
    s.expect(invertedEval.result != ConditionMatch::NoMatch,
             L"N-02 非法范围不得变成确定的不匹配");
    s.expect(HasLimitation(invertedEval.limitationKeys, "wfp.condition.invalid-range"),
             L"N-02 非法范围写进限制说明");
    s.expect(invertedEval.condition.value.range.low == OptionalU64::of(500U) &&
                 invertedEval.condition.value.range.high == OptionalU64::of(400U),
             L"N-02 非法范围的原始端点被原样保留");

    // 边界：low == high 是合法的单点区间
    s.expect(EvaluateCondition(MakeCondition(G(kGuidRemotePort), kMatchRange, RangeValue(443U, 443U)),
                               connection)
                     .result == ConditionMatch::Match,
             L"N-02 [443,443] 单点区间命中 443");
    s.expect(EvaluateCondition(MakeCondition(G(kGuidRemotePort), kMatchRange, RangeValue(400U, 500U)),
                               connection)
                     .result == ConditionMatch::Match,
             L"N-02 合法区间 [400,500] 仍然照常命中");

    // 缺端点与类型错配是两个不同的原因，不再共用一个键
    WfpConditionValue missingHigh = RangeValue(400U, 500U);
    missingHigh.range.high = OptionalU64::unset();
    const ConditionEvaluation missingEval =
        EvaluateCondition(MakeCondition(G(kGuidRemotePort), kMatchRange, missingHigh), connection);
    s.expect(missingEval.result == ConditionMatch::InsufficientInfo, L"N-02 缺端点的范围不做判定");
    s.expect(HasLimitation(missingEval.limitationKeys, "wfp.condition.range-endpoint-missing"),
             L"N-02 缺端点有自己的限制键");
    s.expect(!HasLimitation(missingEval.limitationKeys, "wfp.condition.value-type-mismatch"),
             L"N-02 缺端点不再被塞进「值类型错配」");

    WfpConditionValue textRange = RangeValue(400U, 500U);
    textRange.range.numeric = false;
    textRange.range.rawLow = "aa";
    textRange.range.rawHigh = "bb";
    const ConditionEvaluation textEval =
        EvaluateCondition(MakeCondition(G(kGuidRemotePort), kMatchRange, textRange), connection);
    s.expect(textEval.result == ConditionMatch::InsufficientInfo, L"N-02 非数值端点的范围不做判定");
    s.expect(HasLimitation(textEval.limitationKeys, "wfp.condition.range-not-numeric"),
             L"N-02 非数值端点有自己的限制键");

    WfpConditionValue notRange = NumericValue(WfpDataType::Uint16, kTypeUint16, 443U);
    const ConditionEvaluation typeEval =
        EvaluateCondition(MakeCondition(G(kGuidRemotePort), kMatchRange, notRange), connection);
    s.expect(HasLimitation(typeEval.limitationKeys, "wfp.condition.value-type-mismatch"),
             L"N-02 比较运算是范围而值不是范围类型，仍报值类型错配");

    // 仲裁：读坏范围的高权重规则不得把结论让给低权重规则
    WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
    WfpFilter broken = MakeFilter(kFilter1, 1201U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    SetEffectiveWeight(broken, 9000U);
    broken.conditions.push_back(inverted);
    WfpFilter lower = MakeFilter(kFilter2, 1202U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
    SetEffectiveWeight(lower, 10U);
    lower.conditions.push_back(RemotePortEquals(443U));
    catalog.addFilter(broken);
    catalog.addFilter(lower);
    MarkPartitionComplete(catalog, WfpPartition::Filters, 2U);
    const StaticCandidateReport report = AnalyzeStaticCandidates(catalog, connection);
    s.expect(FilterAt(SubAt(LayerAt(report, 0U), 0U), 0U).match == ConditionMatch::InsufficientInfo,
             L"N-02 读坏范围的规则匹配结论是信息不足");
    s.expect(SubAt(LayerAt(report, 0U), 0U).decision == CandidateDecision::Unknown,
             L"N-03 高权重规则的范围读不懂时不得把结论让给低权重规则");
    s.expect(report.overallDecision != CandidateDecision::PermitCandidate,
             L"N-03 读坏的范围不得间接抬出放行候选");
}

// ---------------------------------------------------------------------------
// N-02：前导零的八位组一律拒绝（与 inet_pton 对齐）
// ---------------------------------------------------------------------------
void TestLeadingZeroOctetsRejected(KswordTests::Suite& s) {
    WfpAddress out;
    out.family = WfpAddressFamily::IPv6;  // 哨兵：解析失败不得修改 out
    s.expect(!ParseIpAddress("010.001.001.001", out),
             L"N-02 带前导零的 IPv4 被拒绝（inet_addr 会按八进制解成 8.1.1.1）");
    s.expect(out.family == WfpAddressFamily::IPv6, L"N-02 前导零解析失败不修改输出参数");
    s.expect(!ParseIpAddress("192.168.01.1", out), L"N-02 单段前导零同样被拒绝");
    s.expect(!ParseIpAddress("00.1.1.1", out), L"N-02 00 被拒绝");
    s.expect(!ParseIpAddress("::ffff:010.1.1.1", out), L"N-02 内嵌 IPv4 的前导零同样被拒绝");

    WfpAddress zero;
    s.expect(ParseIpAddress("0.0.0.0", zero), L"N-02 单个 0 不是前导零，仍然合法");
    s.expect(zero.bytes[0] == 0U && zero.bytes[3] == 0U, L"N-02 0.0.0.0 字节全零");
    s.expect(FormatIpAddress(zero) == "0.0.0.0", L"N-02 0.0.0.0 往返一致");
    WfpAddress normal;
    s.expect(ParseIpAddress("10.1.1.1", normal), L"N-02 无前导零的地址照常解析");
    s.expect(normal.bytes[0] == 10U && normal.bytes[1] == 1U, L"N-02 10.1.1.1 字节正确");
    WfpAddress mapped;
    s.expect(ParseIpAddress("::ffff:192.168.0.1", mapped), L"N-02 无前导零的内嵌 IPv4 照常解析");
    s.expect(mapped.bytes[12] == 192U && mapped.bytes[13] == 168U, L"N-02 内嵌 IPv4 字节仍然正确");
}

// ---------------------------------------------------------------------------
// N-04：实际事件与静态候选分开
// ---------------------------------------------------------------------------
ObservedFilterHit MakeHit(ObservationSource source, bool supported, bool enabled) {
    ObservedFilterHit hit;
    hit.source = source;
    hit.sourceSupported = supported;
    hit.sourceEnabled = enabled;
    hit.filterId = OptionalU64::of(102U);
    hit.filterKey = G(kFilter2);
    hit.layerId = OptionalU64::of(48U);
    hit.eventUtc100ns = OptionalU64::of(133700000000000000ULL);
    hit.verdict = WfpEventVerdict::Blocked;
    hit.rawRecordId = "netevent#17";
    hit.capturedGeneration = OptionalU64::of(7U);
    hit.evidenceId = "ev-wfp-1";
    hit.connection.bootId = "boot-N";
    hit.connection.protocol = 6U;
    hit.connection.localAddress = "192.168.1.50";
    hit.connection.localPort = 52344U;
    hit.connection.remoteAddress = "93.184.216.34";
    hit.connection.remotePort = 443U;
    hit.connection.observedFirstUtc100ns = OptionalU64::of(133700000000000000ULL);
    hit.connection.observedLastUtc100ns = OptionalU64::of(133700000010000000ULL);
    return hit;
}

void TestObservedEvents(KswordTests::Suite& s) {
    const ConnectionDescription connection = MakeConnection();
    WfpCatalog catalog = MakeArbitrationCatalog(60000U, 100U);
    WfpFilter blocking = MakeFilter(kFilter2, 102U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    SetEffectiveWeight(blocking, 900U);
    blocking.conditions.push_back(RemotePortEquals(443U));
    catalog.addFilter(blocking);
    MarkPartitionComplete(catalog, WfpPartition::Filters, 1U);

    // 只有静态候选，没有运行记录
    RuleExplanation staticOnly;
    staticOnly.candidates = AnalyzeStaticCandidates(catalog, connection);
    s.expect(staticOnly.candidates.overallDecision == CandidateDecision::BlockCandidate,
             L"N-03 仅静态候选时也能给出阻断候选");
    s.expect(staticOnly.observations.empty(), L"N-04 仅静态候选时事件集合为空");
    s.expect(staticOnly.actualHitCount() == 0U, L"N-04 没有运行记录就没有实际命中");
    s.expect(!staticOnly.hasActualPath(), L"N-04 静态候选再确定也不生成实际经过路径");

    // 一条来自已启用且受支持来源的运行记录
    RuleExplanation withEvent = staticOnly;
    withEvent.observations.push_back(MakeHit(ObservationSource::WfpNetEventEnum, true, true));
    s.expect(ClassifyObservation(withEvent.observations[0]) == ObservationTrust::ActualObservation,
             L"N-04 已启用且受支持的来源才算实际观测");
    s.expect(withEvent.actualHitCount() == 1U, L"N-04 实际命中计数为 1");
    s.expect(withEvent.untrustedObservationCount() == 0U, L"N-04 没有不可信记录");
    s.expect(withEvent.hasActualPath(), L"N-04 有受支持来源的记录才存在实际经过路径");
    s.expect(DescribesActualVerdict(withEvent.observations[0]), L"N-04 该记录可以称实际阻断");
    s.expect(withEvent.observations[0].source == ObservationSource::WfpNetEventEnum,
             L"N-04 事件保留自己的来源标识");
    s.expect(withEvent.candidates.overallDecision == CandidateDecision::BlockCandidate,
             L"N-04 静态候选结论不因为来了运行记录而改变");

    // 来源不受支持 / 未启用 / 未知：记录保留，但都不算实际命中
    const ObservedFilterHit unsupported = MakeHit(ObservationSource::EtwProvider, false, true);
    s.expect(ClassifyObservation(unsupported) == ObservationTrust::SourceUnsupported,
             L"N-04 不受支持的来源被单独标记");
    s.expect(!DescribesActualVerdict(unsupported), L"N-04 不受支持来源的记录不能称实际阻断");

    const ObservedFilterHit disabled = MakeHit(ObservationSource::SecurityAuditLog, true, false);
    s.expect(ClassifyObservation(disabled) == ObservationTrust::SourceNotEnabled,
             L"N-04 未启用的来源被单独标记");
    s.expect(!DescribesActualVerdict(disabled), L"N-04 未启用来源的记录不能称实际阻断");

    ObservedFilterHit unknownSource = MakeHit(ObservationSource::Unknown, true, true);
    s.expect(ClassifyObservation(unknownSource) == ObservationTrust::SourceUnknown,
             L"N-04 来源未知时自称受支持也不算数");

    ObservedFilterHit noVerdict = MakeHit(ObservationSource::KernelAleCallout, true, true);
    noVerdict.verdict = WfpEventVerdict::Unknown;
    s.expect(ClassifyObservation(noVerdict) == ObservationTrust::ActualObservation,
             L"N-04 来源可信但判定未知，来源分级仍是实际观测");
    s.expect(!DescribesActualVerdict(noVerdict), L"N-04 判定未知时不渲染成实际阻断/放行");

    RuleExplanation mixed;
    mixed.observations.push_back(unsupported);
    mixed.observations.push_back(disabled);
    mixed.observations.push_back(unknownSource);
    s.expect(mixed.observations.size() == 3U, L"N-04 不可信记录仍然保留而不是丢弃");
    s.expect(mixed.actualHitCount() == 0U, L"N-04 三条不可信记录都不算实际命中");
    s.expect(mixed.untrustedObservationCount() == 3U, L"N-04 不可信记录被单独计数");
    s.expect(!mixed.hasActualPath(), L"N-04 全是不可信来源时不存在实际经过路径");

    // 事件与目录里的规则关联（N-04 要求显示过滤器引用）
    const FilterReferenceResolution link = LinkObservationToCatalog(catalog, withEvent.observations[0]);
    s.expect(link.state == FilterLinkState::LinkedByGuid, L"N-04 事件按 filter GUID 关联到规则");
    s.expect(link.hasIndex && catalog.filters()[link.filterIndex].filterKey.text == std::string(kFilter2),
             L"N-04 关联到的是同一条规则");
}

// ---------------------------------------------------------------------------
// N-04 / F-05：「事件来源没采到」与「采集正常、确实零事件」必须分得开
//
// ObservedFilterHit 上的 sourceSupported/sourceEnabled 只在"至少有一条记录"时存在，
// 恰好在采集失败（零条记录）这个最需要说明的情形下失效。没有独立的采集账目，导出只能
// 写"实际命中 0"，读者会读成"没有任何东西被阻断"。
// ---------------------------------------------------------------------------
void TestObservationCollectionOutcomes(KswordTests::Suite& s) {
    // (a) 从没订阅过：一条记录都没有，也没有任何来源账目
    RuleExplanation neverCollected;
    s.expect(neverCollected.observations.empty(), L"N-04 未采集时事件集合为空");
    s.expect(neverCollected.actualHitCount() == 0U, L"N-04 未采集时实际命中为 0");
    s.expect(!neverCollected.observationsCollected(),
             L"N-04 没有任何来源账目时不得声称「事件已采集」");
    s.expect(!neverCollected.hasActualPath(), L"N-04 未采集时没有实际经过路径");

    // (b) 订阅失败：来源受支持且启用，但 FwpmNetEventSubscribe 返回错误
    RuleExplanation subscribeFailed;
    {
        ObservationSourceOutcome entry;
        entry.source = ObservationSource::WfpNetEventSubscribe;
        entry.sourceSupported = true;
        entry.sourceEnabled = true;
        entry.outcome = CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5ULL,
                                                   "FwpmNetEventSubscribe0 access denied");
        subscribeFailed.sourceOutcomes.push_back(entry);
    }
    s.expect(subscribeFailed.actualHitCount() == 0U, L"N-04 订阅失败时实际命中为 0");
    s.expect(!subscribeFailed.observationsCollected(),
             L"N-04 订阅失败不算「事件已采集」，零命中是采集问题");
    s.expect(subscribeFailed.anyObservationSourceFailed(), L"N-04 订阅失败被单独标出");
    s.expect(subscribeFailed.sourceOutcomes[0].outcome.nativeCode == OptionalU64::of(5ULL),
             L"N-04 采集失败保留原始 Win32 错误码 5");
    s.expect(subscribeFailed.sourceOutcomes[0].outcome.nativeCodeDomain == "WIN32",
             L"N-04 采集失败保留错误码域");
    s.expect(!subscribeFailed.sourceOutcomes[0].carriesObservation(),
             L"N-04 AccessDenied 的来源不携带观测");

    // (c) 采集正常、确实零事件
    RuleExplanation collectedEmpty;
    {
        ObservationSourceOutcome entry;
        entry.source = ObservationSource::WfpNetEventEnum;
        entry.sourceSupported = true;
        entry.sourceEnabled = true;
        entry.outcome = CollectionOutcome::success();
        entry.coverage.totalKnown = OptionalU64::of(0U);
        entry.coverage.succeeded = 0U;
        collectedEmpty.sourceOutcomes.push_back(entry);
    }
    s.expect(collectedEmpty.actualHitCount() == 0U, L"N-04 正确的空集合实际命中也是 0");
    s.expect(collectedEmpty.observationsCollected(),
             L"N-04 受支持且启用的来源跑完了，「零事件」才是真的零事件");
    s.expect(!collectedEmpty.anyObservationSourceFailed(), L"N-04 正常跑完的来源不算失败");
    s.expect(collectedEmpty.sourceOutcomes[0].carriesObservation(), L"N-04 Success 的来源携带观测");

    // 三者的 actualHitCount 相同 —— 必须靠采集账目才分得开
    s.expect(neverCollected.actualHitCount() == collectedEmpty.actualHitCount() &&
                 subscribeFailed.actualHitCount() == collectedEmpty.actualHitCount(),
             L"N-04 三种情形的实际命中数都是 0，说明单看命中数分不出来");
    s.expect(neverCollected.observationsCollected() != collectedEmpty.observationsCollected(),
             L"N-04 「未采集」与「采集正常且零事件」在结构上可区分");
    s.expect(subscribeFailed.observationsCollected() != collectedEmpty.observationsCollected(),
             L"N-04 「采集失败」与「采集正常且零事件」在结构上可区分");
    s.expect(neverCollected.anyObservationSourceFailed() != subscribeFailed.anyObservationSourceFailed(),
             L"N-04 「从没订阅」与「订阅失败」在结构上可区分");

    // (d) 来源受支持但未启用：跑完了也不算"能观测到"
    RuleExplanation notEnabled;
    {
        ObservationSourceOutcome entry;
        entry.source = ObservationSource::SecurityAuditLog;
        entry.sourceSupported = true;
        entry.sourceEnabled = false;  // 审计策略没开
        entry.outcome = CollectionOutcome::success();
        notEnabled.sourceOutcomes.push_back(entry);
    }
    s.expect(!notEnabled.observationsCollected(),
             L"N-04 来源没启用时「零事件」说明不了问题");
}

// ---------------------------------------------------------------------------
// N-04：离线导入必须另记真实来源
//
// OfflineImport 只说明"这条记录是从样本读进来的"。原始来源不明时，样本里自己填的
// supported/enabled 两个布尔不能把它抬成"实际阻断"。
// ---------------------------------------------------------------------------
void TestOfflineImportProvenance(KswordTests::Suite& s) {
    ObservedFilterHit anonymous = MakeHit(ObservationSource::OfflineImport, true, true);
    s.expect(anonymous.originalSource == ObservationSource::Unknown,
             L"N-04 离线记录默认没有原始来源");
    s.expect(ClassifyObservation(anonymous) == ObservationTrust::SourceUnknown,
             L"N-04 原始来源不明的离线记录是「来源未知」，不是实际观测");
    s.expect(ClassifyObservation(anonymous) != ObservationTrust::ActualObservation,
             L"N-04 离线样本不能靠自填两个布尔把记录抬成实际观测");
    s.expect(!DescribesActualVerdict(anonymous), L"N-04 原始来源不明时不得渲染成实际阻断");

    ObservedFilterHit audited = MakeHit(ObservationSource::OfflineImport, true, true);
    audited.originalSource = ObservationSource::SecurityAuditLog;
    audited.originalSourceDetail = Text("Security 5157");
    s.expect(ClassifyObservation(audited) == ObservationTrust::ActualObservation,
             L"N-04 原始来源填了 5157 安全审计的离线记录才算实际观测");
    s.expect(DescribesActualVerdict(audited), L"N-04 有原始来源的离线记录可以称实际阻断");
    s.expect(audited.originalSource == ObservationSource::SecurityAuditLog,
             L"N-04 原始来源被原样保留供来源栏显示");
    s.expect(audited.originalSourceDetail.present && audited.originalSourceDetail.value == "Security 5157",
             L"N-04 原始来源明细被原样保留");
    s.expect(std::string(ObservationSourceName(audited.originalSource)) == "SecurityAuditLog",
             L"N-04 原始来源有独立可显示的名称");

    // 自指的离线来源同样不算数
    ObservedFilterHit selfReferential = MakeHit(ObservationSource::OfflineImport, true, true);
    selfReferential.originalSource = ObservationSource::OfflineImport;
    s.expect(ClassifyObservation(selfReferential) == ObservationTrust::SourceUnknown,
             L"N-04 原始来源写成「离线导入」等于没写");

    // 非离线来源不受这条判据影响
    s.expect(ClassifyObservation(MakeHit(ObservationSource::WfpNetEventEnum, true, true)) ==
                 ObservationTrust::ActualObservation,
             L"N-04 现场来源不需要填原始来源");

    // 导航：原始来源不明的离线记录不能当"实际经过路径"
    const WfpNavigationResult blocked = NavigateObservationToTimeline(anonymous, true, true);
    s.expect(blocked.blockedByUntrustedSource, L"N-04 原始来源不明的离线记录被拦下");
    s.expect(blocked.rejection == WfpNavigationRejection::SourceNotTrusted,
             L"N-04 拦下原因是「来源不可信」");
    s.expect(blocked.outcome != NavigationOutcome::Delivered, L"N-04 拦下的记录不进时间线");
}

// ---------------------------------------------------------------------------
// N-05：所有者归因
// ---------------------------------------------------------------------------
void TestOwnerAttribution(KswordTests::Suite& s) {
    // 有直接地址证据
    OwnerEvidence direct;
    direct.displayName = Text("Windows Firewall");
    direct.moduleAddress = OptionalU64::of(0xFFFFF80512340000ULL);
    direct.moduleResolved = true;
    direct.resolvedModulePath = Text("\\SystemRoot\\System32\\drivers\\mpsdrv.sys");
    const OwnerAttributionResult directResult = DeriveOwnerAttribution(direct);
    s.expect(directResult.attribution == WfpOwnerAttribution::DirectEvidence, L"N-05 模块地址落位是直接证据");
    s.expect(directResult.ownerModulePath.present, L"N-05 直接证据才给出所有者模块路径");
    s.expect(directResult.ownerModulePath.value == "\\SystemRoot\\System32\\drivers\\mpsdrv.sys",
             L"N-05 所有者模块路径与解析结果一致");
    s.expect(!directResult.candidateModulePath.present, L"N-05 直接证据不需要候选路径");
    s.expect(!directResult.signerCertificateAvailable, L"N-05 没读签名就不声称有签名");
    s.expect(!directResult.signerSubject.present, L"N-05 没读签名就不给证书主体");

    // 模块卸载：地址在，但没有映像覆盖它
    OwnerEvidence unloaded;
    unloaded.displayName = Text("Some Callout");
    unloaded.moduleAddress = OptionalU64::of(0xFFFFF80599990000ULL);
    unloaded.moduleResolved = false;
    const OwnerAttributionResult unloadedResult = DeriveOwnerAttribution(unloaded);
    s.expect(unloadedResult.attribution == WfpOwnerAttribution::Unknown, L"N-05 模块卸载时归因是未知");
    s.expect(!unloadedResult.ownerModulePath.present, L"N-05 模块卸载时不指名文件");
    s.expect(HasLimitation(unloadedResult.limitationKeys, "wfp.owner.module-unresolved"),
             L"N-05 模块未解析写进限制说明");

    // 服务配置：只是候选
    OwnerEvidence service;
    service.displayName = Text("Base Filtering Engine");
    service.serviceName = Text("BFE");
    service.serviceRecordFound = true;
    service.serviceImagePath = Text("%SystemRoot%\\System32\\svchost.exe -k LocalServiceNoNetwork");
    const OwnerAttributionResult serviceResult = DeriveOwnerAttribution(service);
    s.expect(serviceResult.attribution == WfpOwnerAttribution::Candidate, L"N-05 服务配置只能给候选归因");
    s.expect(serviceResult.candidateModulePath.present, L"N-05 候选归因给出候选路径");
    s.expect(!serviceResult.ownerModulePath.present, L"N-05 候选归因不占用直接证据字段");
    s.expect(serviceResult.serviceName.present && serviceResult.serviceName.value == "BFE",
             L"N-05 服务名被保留");

    // 找不到服务
    OwnerEvidence missingService;
    missingService.displayName = Text("Ghost Provider");
    missingService.serviceName = Text("GhostSvc");
    missingService.serviceRecordFound = false;
    const OwnerAttributionResult missingServiceResult = DeriveOwnerAttribution(missingService);
    s.expect(missingServiceResult.attribution == WfpOwnerAttribution::Unknown, L"N-05 找不到服务时归因未知");
    s.expect(!missingServiceResult.candidateModulePath.present, L"N-05 找不到服务时不编造候选路径");
    s.expect(HasLimitation(missingServiceResult.limitationKeys, "wfp.owner.service-not-found"),
             L"N-05 服务未找到写进限制说明");

    // 只有显示名
    OwnerEvidence nameOnly;
    nameOnly.displayName = Text("Microsoft Corporation");
    const OwnerAttributionResult nameOnlyResult = DeriveOwnerAttribution(nameOnly);
    s.expect(nameOnlyResult.attribution == WfpOwnerAttribution::Unknown, L"N-05 只有名称时归因未知");
    s.expect(!nameOnlyResult.ownerModulePath.present, L"N-05 不凭名称猜驱动文件");
    s.expect(!nameOnlyResult.candidateModulePath.present, L"N-05 不凭名称造候选文件");
    s.expect(HasLimitation(nameOnlyResult.limitationKeys, "wfp.owner.name-only"),
             L"N-05 只有名称写进限制说明");

    // 什么都没有
    const OwnerAttributionResult emptyResult = DeriveOwnerAttribution(OwnerEvidence{});
    s.expect(emptyResult.attribution == WfpOwnerAttribution::Unknown, L"N-05 无证据时归因未知");
    s.expect(HasLimitation(emptyResult.limitationKeys, "wfp.owner.no-evidence"),
             L"N-05 无证据写进限制说明");

    // 签名信息只有真的读到才出现
    OwnerEvidence fabricated = direct;
    fabricated.signerCertificateRead = false;
    fabricated.signerSubject = Text("Microsoft Windows");
    const OwnerAttributionResult fabricatedResult = DeriveOwnerAttribution(fabricated);
    s.expect(!fabricatedResult.signerCertificateAvailable, L"N-05 未读取签名时不声称有证书");
    s.expect(!fabricatedResult.signerSubject.present, L"N-05 未读取签名时证书主体保持未知");
    OwnerEvidence signed_ = direct;
    signed_.signerCertificateRead = true;
    signed_.signerSubject = Text("CN=Microsoft Windows");
    const OwnerAttributionResult signedResult = DeriveOwnerAttribution(signed_);
    s.expect(signedResult.signerCertificateAvailable, L"N-05 真读到签名时才标记可用");
    s.expect(signedResult.signerSubject.value == "CN=Microsoft Windows", L"N-05 证书主体原样保留");

    // 同名组件：目录侧把"名称有歧义"写进证据
    WfpCatalog catalog;
    WfpCallout first;
    first.calloutKey = G(kCalloutX);
    first.displayName = Text("Inspect");
    first.owner.displayName = Text("Inspect");
    WfpCallout second;
    second.calloutKey = G("{77777777-7777-4777-8777-777777777777}");
    second.displayName = Text("Inspect");
    second.owner.displayName = Text("Inspect");
    catalog.addCallout(first);
    catalog.addCallout(second);
    MarkPartitionComplete(catalog, WfpPartition::Callouts, 2U);
    s.expect(catalog.callouts().size() == 2U, L"N-01 同名 callout 不因名称相同而合并");
    const OwnerEvidence ambiguousEvidence = catalog.calloutOwnerEvidence(0U);
    s.expect(ambiguousEvidence.displayNameAmbiguous, L"N-05 同名组件被标记为名称歧义");
    const OwnerAttributionResult ambiguousResult = DeriveOwnerAttribution(ambiguousEvidence);
    s.expect(ambiguousResult.attribution == WfpOwnerAttribution::Unknown, L"N-05 同名组件不因名称获得归因");
    s.expect(HasLimitation(ambiguousResult.limitationKeys, "wfp.owner.ambiguous-display-name"),
             L"N-05 名称歧义写进限制说明");

    WfpCatalog unique;
    WfpCallout only;
    only.calloutKey = G(kCalloutX);
    only.displayName = Text("Inspect");
    only.owner.displayName = Text("Inspect");
    unique.addCallout(only);
    MarkPartitionComplete(unique, WfpPartition::Callouts, 1U);
    s.expect(!unique.calloutOwnerEvidence(0U).displayNameAmbiguous, L"N-05 唯一名称不误报歧义");
}

// ---------------------------------------------------------------------------
// N-06：动态变化、BFE 不可用与旧 id 复用
// ---------------------------------------------------------------------------
void TestDynamicStateAndIdReuse(KswordTests::Suite& s) {
    // BFE 不可用：不生成任何假对象行，分区状态显式失败
    WfpCatalog broken;
    broken.setGeneration(3U);
    CollectionOutcome bfeDown = CollectionOutcome::failure(CollectionStatus::Error, "WIN32", 1753ULL,
                                                           "FwpmEngineOpen0 failed");
    broken.setPartitionState(WfpPartition::Providers, bfeDown, CoverageAccount{});
    s.expect(broken.providers().empty(), L"N-06 BFE 打不开时不伪造 provider 行");
    s.expect(broken.partitionState(WfpPartition::Providers).outcome.status == CollectionStatus::Error,
             L"N-06 BFE 失败落成分区状态");
    s.expect(broken.partitionState(WfpPartition::Providers).outcome.nativeCode == OptionalU64::of(1753ULL),
             L"N-06 原始错误码被保留");
    s.expect(broken.partitionState(WfpPartition::Providers).outcome.nativeCodeDomain == "WIN32",
             L"N-06 错误码域被保留");
    s.expect(!broken.partitionUsableForAbsence(WfpPartition::Providers),
             L"N-06 失败的分区不能用来推断「这个对象不存在」");
    s.expect(broken.resolveProvider(G(kProviderA)).state == ReferenceState::CatalogNotCollected,
             L"N-06 没采到时关联结果是「未采集」而不是「未知对象」");

    // 拒绝访问与未采集是两种状态，都不许被当成"0 个对象"
    WfpCatalog denied;
    denied.setPartitionState(WfpPartition::Callouts,
                             CollectionOutcome::failure(CollectionStatus::AccessDenied, "WIN32", 5ULL,
                                                        "FwpmCalloutEnum0 access denied"),
                             CoverageAccount{});
    s.expect(denied.partitionState(WfpPartition::Callouts).outcome.status == CollectionStatus::AccessDenied,
             L"N-06 拒绝访问是独立状态");
    s.expect(!denied.partitionUsableForAbsence(WfpPartition::Callouts), L"N-06 拒绝访问不能推断缺席");
    s.expect(denied.partitionState(WfpPartition::Filters).outcome.status == CollectionStatus::NotCollected,
             L"N-06 没设置过的分区默认是未采集");
    s.expect(!denied.partitionUsableForAbsence(WfpPartition::Filters), L"N-06 未采集不能推断缺席");

    // Success 但账目一字未填 —— 不算完整覆盖
    WfpCatalog blankAccount;
    blankAccount.setPartitionState(WfpPartition::Filters, CollectionOutcome::success(), CoverageAccount{});
    s.expect(!blankAccount.partitionUsableForAbsence(WfpPartition::Filters),
             L"N-06 账目空白时不算完整枚举（默认不等于完整）");
    WfpCatalog counted;
    CoverageAccount full;
    full.totalKnown = OptionalU64::of(2U);
    full.succeeded = 2U;
    counted.setPartitionState(WfpPartition::Filters, CollectionOutcome::success(), full);
    s.expect(counted.partitionUsableForAbsence(WfpPartition::Filters),
             L"N-06 有正面账目证据时才算完整枚举");
    CoverageAccount truncatedAccount = full;
    truncatedAccount.truncated = 1U;
    WfpCatalog truncatedCatalog;
    truncatedCatalog.setPartitionState(WfpPartition::Filters, CollectionOutcome::success(), truncatedAccount);
    s.expect(!truncatedCatalog.partitionUsableForAbsence(WfpPartition::Filters),
             L"N-06 有截断记录时不算完整枚举");

    // 运行时 id 关联
    WfpCatalog current = MakeArbitrationCatalog(60000U, 100U);
    current.setGeneration(7U);
    WfpFilter alive = MakeFilter(kFilter1, 77U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    SetEffectiveWeight(alive, 900U);
    current.addFilter(alive);
    MarkPartitionComplete(current, WfpPartition::Filters, 1U);

    s.expect(current.captureWindow().bootId == "boot-N", L"N-06 目录保留采集时的启动周期");
    s.expect(current.captureWindow().startUtc100ns == OptionalU64::of(133700000000000000ULL),
             L"N-06 目录保留采集时间");
    s.expect(current.captureWindow().mode == CaptureMode::Snapshot, L"N-06 目录保留采集方式");

    RuntimeFilterReference sameGen;
    sameGen.filterId = OptionalU64::of(77U);
    sameGen.capturedGeneration = OptionalU64::of(7U);
    sameGen.bootId = "boot-N";
    const FilterReferenceResolution sameGenResult = ResolveFilterReference(current, sameGen);
    s.expect(sameGenResult.state == FilterLinkState::LinkedByRuntimeIdSameGeneration,
             L"N-06 同一采集代次内可按运行时 id 关联");
    s.expect(sameGenResult.hasIndex, L"N-06 同代次关联给出命中位置");

    // 代次号跨启动会从头再来：代次相同但 bootId 不同一律拒绝
    RuntimeFilterReference otherBoot = sameGen;
    otherBoot.bootId = "boot-OTHER";
    const FilterReferenceResolution otherBootResult = ResolveFilterReference(current, otherBoot);
    s.expect(otherBootResult.state == FilterLinkState::RejectedStaleGeneration,
             L"N-06 代次相同但跨启动周期时拒绝关联");
    s.expect(!otherBootResult.hasIndex, L"N-06 跨启动时不给命中位置");
    s.expect(HasLimitation(otherBootResult.limitationKeys, "wfp.link.boot-mismatch"),
             L"N-06 跨启动写进限制说明");

    RuntimeFilterReference noBoot = sameGen;
    noBoot.bootId.clear();
    s.expect(ResolveFilterReference(current, noBoot).state ==
                 FilterLinkState::LinkedByRuntimeIdSameGeneration,
             L"N-06 拿不到 bootId 时只能靠代次判据，不额外收紧也不额外放宽");

    RuntimeFilterReference staleGen;
    staleGen.filterId = OptionalU64::of(77U);
    staleGen.capturedGeneration = OptionalU64::of(6U);
    const FilterReferenceResolution staleResult = ResolveFilterReference(current, staleGen);
    s.expect(staleResult.state == FilterLinkState::RejectedStaleGeneration,
             L"N-06 旧代次的运行时 id 不敢关联");
    s.expect(!staleResult.hasIndex, L"N-06 拒绝关联时不给命中位置");
    s.expect(HasLimitation(staleResult.limitationKeys, "wfp.link.stale-generation"),
             L"N-06 旧代次写进限制说明");

    RuntimeFilterReference unknownGen;
    unknownGen.filterId = OptionalU64::of(77U);
    const FilterReferenceResolution unknownGenResult = ResolveFilterReference(current, unknownGen);
    s.expect(unknownGenResult.state == FilterLinkState::RejectedStaleGeneration,
             L"N-06 代次未知的运行时 id 同样不敢关联");
    s.expect(HasLimitation(unknownGenResult.limitationKeys, "wfp.link.generation-unknown"),
             L"N-06 代次未知写进限制说明");

    // 旧 id 已被复用：引用带着旧 GUID，目录里同 id 是别的规则
    RuntimeFilterReference reused;
    reused.filterId = OptionalU64::of(77U);
    reused.filterKey = G(kFilter4);  // 目录里没有这个 GUID
    reused.capturedGeneration = OptionalU64::of(6U);
    const FilterReferenceResolution reusedResult = ResolveFilterReference(current, reused);
    s.expect(reusedResult.state == FilterLinkState::RejectedIdReused, L"N-06 旧 id 被复用时明确拒绝关联");
    s.expect(!reusedResult.hasIndex, L"N-06 id 复用时绝不误连到新规则");
    s.expect(HasLimitation(reusedResult.limitationKeys, "wfp.link.id-reused"),
             L"N-06 id 复用写进限制说明");

    // GUID 命中但运行时 id 变了：照连，但要说出来
    RuntimeFilterReference movedId;
    movedId.filterKey = G(kFilter1);
    movedId.filterId = OptionalU64::of(999U);
    movedId.capturedGeneration = OptionalU64::of(6U);
    const FilterReferenceResolution movedResult = ResolveFilterReference(current, movedId);
    s.expect(movedResult.state == FilterLinkState::LinkedByGuid, L"N-06 GUID 是稳定键，跨代次仍可关联");
    s.expect(HasLimitation(movedResult.limitationKeys, "wfp.link.runtime-id-changed"),
             L"N-06 运行时 id 变化写进限制说明");

    // 目录里同一个 filterId 出现两次
    WfpCatalog ambiguousIds = MakeArbitrationCatalog(60000U, 100U);
    ambiguousIds.setGeneration(7U);
    WfpFilter twinA = MakeFilter(kFilter1, 55U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    WfpFilter twinB = MakeFilter(kFilter2, 55U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
    ambiguousIds.addFilter(twinA);
    ambiguousIds.addFilter(twinB);
    MarkPartitionComplete(ambiguousIds, WfpPartition::Filters, 2U);
    RuntimeFilterReference twinRef;
    twinRef.filterId = OptionalU64::of(55U);
    twinRef.capturedGeneration = OptionalU64::of(7U);
    s.expect(ResolveFilterReference(ambiguousIds, twinRef).state == FilterLinkState::RejectedAmbiguous,
             L"N-06 同一运行时 id 有多条时拒绝关联");

    // 什么都没带 / 目录没采到
    s.expect(ResolveFilterReference(current, RuntimeFilterReference{}).state == FilterLinkState::NotSpecified,
             L"N-06 引用什么都没带时状态是 NotSpecified");
    WfpCatalog uncollected;
    RuntimeFilterReference idOnly;
    idOnly.filterId = OptionalU64::of(77U);
    idOnly.capturedGeneration = OptionalU64::of(0U);
    s.expect(ResolveFilterReference(uncollected, idOnly).state == FilterLinkState::CatalogNotCollected,
             L"N-06 filter 分区未采集时无法关联");
    RuntimeFilterReference unknownGuid;
    unknownGuid.filterKey = G(kFilter4);
    s.expect(ResolveFilterReference(current, unknownGuid).state == FilterLinkState::NoMatch,
             L"N-06 GUID 不在完整目录里时是「没有这条」而不是「未采集」");

    // --- 两代之间的增删改 ---
    WfpCatalog before = MakeArbitrationCatalog(60000U, 100U);
    before.setGeneration(1U);
    WfpFilter keptBefore = MakeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    SetEffectiveWeight(keptBefore, 100U);
    keptBefore.conditions.push_back(RemotePortEquals(443U));
    WfpFilter removed = MakeFilter(kFilter2, 11U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
    SetEffectiveWeight(removed, 200U);
    before.addFilter(keptBefore);
    before.addFilter(removed);
    MarkPartitionComplete(before, WfpPartition::Filters, 2U);

    WfpCatalog after = MakeArbitrationCatalog(60000U, 100U);
    after.setGeneration(2U);
    WfpFilter keptAfter = MakeFilter(kFilter1, 10U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
    SetEffectiveWeight(keptAfter, 300U);
    keptAfter.conditions.push_back(RemotePortEquals(8080U));
    WfpFilter added = MakeFilter(kFilter3, 12U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    SetEffectiveWeight(added, 400U);
    WfpFilter reuser = MakeFilter(kFilter4, 11U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    SetEffectiveWeight(reuser, 500U);
    after.addFilter(keptAfter);
    after.addFilter(added);
    after.addFilter(reuser);
    MarkPartitionComplete(after, WfpPartition::Filters, 3U);

    const CatalogDelta delta = DiffCatalogs(before, after);
    s.expect(delta.comparable, L"N-06 两侧都完整枚举时才敢做增删对比");
    std::size_t addedCount = 0;
    std::size_t removedCount = 0;
    std::size_t actionChanged = 0;
    std::size_t weightChanged = 0;
    std::size_t conditionsChanged = 0;
    std::size_t idReused = 0;
    std::size_t presenceUnknown = 0;
    for (const CatalogChange& change : delta.changes) {
        switch (change.kind) {
        case CatalogChangeKind::Added: ++addedCount; break;
        case CatalogChangeKind::Removed: ++removedCount; break;
        case CatalogChangeKind::ActionChanged: ++actionChanged; break;
        case CatalogChangeKind::WeightChanged: ++weightChanged; break;
        case CatalogChangeKind::ConditionsChanged: ++conditionsChanged; break;
        case CatalogChangeKind::RuntimeIdReused: ++idReused; break;
        case CatalogChangeKind::PresenceUnknown: ++presenceUnknown; break;
        }
    }
    s.expect(addedCount == 2U, L"N-06 新增两条规则被识别");
    s.expect(removedCount == 1U, L"N-06 删除一条规则被识别");
    s.expect(actionChanged == 1U, L"N-06 动作变化被识别");
    s.expect(weightChanged == 1U, L"N-06 权重变化被识别");
    s.expect(conditionsChanged == 1U, L"N-06 条件变化被识别");
    s.expect(idReused == 1U, L"N-06 运行时 id 复用被单独识别");
    s.expect(presenceUnknown == 0U, L"N-06 两侧完整时不产生「在场未知」");
    s.expect(!HasLimitation(delta.limitationKeys, "wfp.delta.boot-changed"),
             L"N-06 同一启动周期内不误报跨启动");

    // 跨启动重采：id 重排是必然现象，不能被当成同一次会话里的 id 回收
    WfpCatalog rebooted = after;
    CaptureWindow newBoot = after.captureWindow();
    newBoot.bootId = "boot-N2";
    rebooted.setCaptureWindow(newBoot);
    const CatalogDelta rebootDelta = DiffCatalogs(before, rebooted);
    s.expect(HasLimitation(rebootDelta.limitationKeys, "wfp.delta.boot-changed"),
             L"N-06 跨启动重采写进限制说明");
    bool rebootIdReuseFlagged = false;
    for (const CatalogChange& change : rebootDelta.changes) {
        if (change.kind == CatalogChangeKind::RuntimeIdReused) {
            rebootIdReuseFlagged = HasLimitation(change.limitationKeys, "wfp.delta.boot-changed");
        }
    }
    s.expect(rebootIdReuseFlagged, L"N-06 跨启动的 id 重排在该条变更上单独标注");

    // 新一侧枚举不完整：不许把"没看见"说成"被删了"
    WfpCatalog partialAfter = MakeArbitrationCatalog(60000U, 100U);
    partialAfter.setGeneration(2U);
    CoverageAccount partialAccount;
    partialAccount.totalKnown = OptionalU64::of(9U);
    partialAccount.succeeded = 1U;
    partialAccount.limitHit = true;
    partialAfter.setPartitionState(WfpPartition::Filters,
                                   CollectionOutcome::failure(CollectionStatus::Partial, "WIN32", 0ULL,
                                                              "enumeration limit"),
                                   partialAccount);
    const CatalogDelta partialDelta = DiffCatalogs(before, partialAfter);
    s.expect(!partialDelta.comparable, L"N-06 一侧不完整时对比结论不可比");
    s.expect(HasLimitation(partialDelta.limitationKeys, "wfp.delta.after-incomplete"),
             L"N-06 不完整侧写进限制说明");
    bool anyRemoved = false;
    bool anyUnknown = false;
    for (const CatalogChange& change : partialDelta.changes) {
        if (change.kind == CatalogChangeKind::Removed) {
            anyRemoved = true;
        }
        if (change.kind == CatalogChangeKind::PresenceUnknown) {
            anyUnknown = true;
        }
    }
    s.expect(!anyRemoved, L"N-06 枚举不完整时不产出「已删除」结论");
    s.expect(anyUnknown, L"N-06 枚举不完整时产出「在场未知」");
}

// ---------------------------------------------------------------------------
// N-01 / N-06：两代对比里让 GUID 索引失真的两类行
//
// std::map::emplace 会静默丢掉重复 GUID 的第二行；没有 GUID 的行根本进不了索引。
// 两者都会让"两代之间毫无变化"这种结论盖住一条凭空消失的规则。
// ---------------------------------------------------------------------------
void TestDeltaRejectsDistortedSnapshots(KswordTests::Suite& s) {
    // (a) before 一侧同一 GUID 出现两次（Block/10 与 Permit/20），after 只有 Block/10
    {
        WfpCatalog before = MakeArbitrationCatalog(60000U, 100U);
        before.setGeneration(1U);
        WfpFilter first = MakeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(first, 10U);
        WfpFilter second = MakeFilter(kFilter1, 20U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        SetEffectiveWeight(second, 20U);
        s.expect(before.addFilter(first), L"N-01 重复 GUID 的第一条 filter 正常入库");
        s.expect(!before.addFilter(second), L"N-01 重复 GUID 的第二条 filter 被标记为重复");
        MarkPartitionComplete(before, WfpPartition::Filters, 2U);
        s.expect(before.resolveFilter(G(kFilter1)).state == ReferenceState::Ambiguous,
                 L"N-01 目录自己已经认得这是歧义");

        WfpCatalog after = MakeArbitrationCatalog(60000U, 100U);
        after.setGeneration(2U);
        WfpFilter survivor = MakeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        SetEffectiveWeight(survivor, 10U);
        after.addFilter(survivor);
        MarkPartitionComplete(after, WfpPartition::Filters, 1U);

        const CatalogDelta delta = DiffCatalogs(before, after);
        s.expect(!delta.comparable,
                 L"N-06 一侧快照自相矛盾时不敢宣称两代可比");
        s.expect(HasLimitation(delta.limitationKeys, "wfp.delta.duplicate-guid"),
                 L"N-06 重复 GUID 写进对比的限制说明");
        std::size_t presenceUnknown = 0;
        std::size_t others = 0;
        for (const CatalogChange& change : delta.changes) {
            if (change.kind == CatalogChangeKind::PresenceUnknown) {
                ++presenceUnknown;
                s.expect(change.filterKey.text == std::string(kFilter1),
                         L"N-06 歧义条目的变更行带着出问题的那个 GUID");
                s.expect(HasLimitation(change.limitationKeys, "wfp.delta.duplicate-guid"),
                         L"N-06 歧义写进该条变更自己的限制说明");
            } else {
                ++others;
            }
        }
        s.expect(presenceUnknown == 1U, L"N-06 歧义 GUID 产出一条「在场未知」");
        s.expect(others == 0U,
                 L"N-06 对歧义 GUID 不产出任何增删改结论（那条 Permit/20 不许凭空消失）");
    }

    // (b) before 有一条只有可复用运行时 id、没有 GUID 的规则，after 没有
    {
        WfpCatalog before = MakeArbitrationCatalog(60000U, 100U);
        before.setGeneration(1U);
        WfpFilter anonymous = MakeFilter(kFilter1, 42U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
        anonymous.filterKey = WfpGuid{};  // 没采到 GUID
        SetEffectiveWeight(anonymous, 900U);
        before.addFilter(anonymous);
        MarkPartitionComplete(before, WfpPartition::Filters, 1U);

        WfpCatalog after = MakeArbitrationCatalog(60000U, 100U);
        after.setGeneration(2U);
        MarkPartitionComplete(after, WfpPartition::Filters, 0U);

        const CatalogDelta delta = DiffCatalogs(before, after);
        s.expect(!delta.comparable, L"N-06 有无 GUID 的行时两代对比不可比");
        s.expect(HasLimitation(delta.limitationKeys, "wfp.delta.filter-without-guid"),
                 L"N-06 无 GUID 的行写进对比的限制说明");
        s.expect(delta.changes.size() == 1U, L"N-06 无 GUID 的行逐条产出变更行，不是只记一个全局键");
        if (!delta.changes.empty()) {
            s.expect(delta.changes[0].kind == CatalogChangeKind::PresenceUnknown,
                     L"N-06 无 GUID 的行是「在场未知」");
            s.expect(delta.changes[0].beforeFilterId == OptionalU64::of(42U),
                     L"N-06 无 GUID 的行带上旧一侧的运行时 id 供追查");
            s.expect(!delta.changes[0].afterFilterId.present,
                     L"N-06 无 GUID 的行不编造新一侧的运行时 id");
            s.expect(!delta.changes[0].filterKey.known(), L"N-06 无 GUID 的行不编造 GUID");
            s.expect(HasLimitation(delta.changes[0].limitationKeys, "wfp.delta.filter-without-guid"),
                     L"N-06 无 GUID 写进该条变更自己的限制说明");
        }
    }

    // (c) after 一侧的无 GUID 行同样逐条产出
    {
        WfpCatalog before = MakeArbitrationCatalog(60000U, 100U);
        MarkPartitionComplete(before, WfpPartition::Filters, 0U);
        WfpCatalog after = MakeArbitrationCatalog(60000U, 100U);
        WfpFilter anonymous = MakeFilter(kFilter1, 77U, kSubLayerHigh, kActionPermit, WfpActionType::Permit);
        anonymous.filterKey = WfpGuid{};
        after.addFilter(anonymous);
        MarkPartitionComplete(after, WfpPartition::Filters, 1U);

        const CatalogDelta delta = DiffCatalogs(before, after);
        s.expect(delta.changes.size() == 1U, L"N-06 新一侧的无 GUID 行也产出一条变更");
        if (!delta.changes.empty()) {
            s.expect(delta.changes[0].afterFilterId == OptionalU64::of(77U),
                     L"N-06 新一侧无 GUID 行带上新一侧的运行时 id");
            s.expect(!delta.changes[0].beforeFilterId.present,
                     L"N-06 新一侧无 GUID 行不编造旧一侧的运行时 id");
        }
    }
}

// ---------------------------------------------------------------------------
// N-08：导航
// ---------------------------------------------------------------------------
void TestNavigation(KswordTests::Suite& s) {
    WfpFilter withGuid = MakeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    const ObjectRef filterRef = MakeFilterRef(withGuid, "ev-1");
    s.expect(filterRef.navigable(), L"N-08 带 GUID 的规则可以导航");
    s.expect(filterRef.key == std::string("wfp-filter|") + kFilter1, L"N-08 规则键带前缀且基于 GUID");
    s.expect(filterRef.strength == IdentityStrength::Strong, L"N-08 GUID 是稳定的跨会话键");

    WfpFilter idOnly = withGuid;
    idOnly.filterKey = WfpGuid{};
    const ObjectRef idOnlyRef = MakeFilterRef(idOnly, "ev-1");
    s.expect(!idOnlyRef.navigable(), L"N-08 只有可复用运行时 id 的规则不可导航");
    s.expect(idOnlyRef.key.empty(), L"N-08 身份不足时不发主键");
    s.expect(idOnlyRef.strength == IdentityStrength::Unusable, L"N-08 只有运行时 id 时身份不可用");

    const WfpNavigationResult delivered = NavigateFilterToEvidence(withGuid, true, true, true, "ev-1");
    s.expect(delivered.outcome == NavigationOutcome::Delivered, L"N-08 规则回看关联证据可以送达");
    s.expect(!delivered.refetchAttempted, L"N-08 导航层永远不重新发起查询");
    s.expect(delivered.request.page == NavigationPage::Network, L"N-08 规则证据落在网络页");
    s.expect(delivered.request.evidenceId == "ev-1", L"N-08 导航请求带上证据 id");

    const WfpNavigationResult unusable = NavigateFilterToEvidence(idOnly, true, true, true, "ev-1");
    s.expect(unusable.outcome == NavigationOutcome::IdentityUnusable, L"N-08 身份不足时拒绝跳转");

    const WfpNavigationResult notSaved = NavigateFilterToEvidence(withGuid, true, true, false, "ev-1");
    s.expect(notSaved.outcome == NavigationOutcome::EvidenceNotSaved,
             L"N-08 离线会话没保存这段数据时明确显示未保存");
    s.expect(!notSaved.refetchAttempted, L"N-08 缺数据时不偷偷重新发起查询");

    const WfpNavigationResult noEvidenceId = NavigateFilterToEvidence(withGuid, true, true, true, "");
    s.expect(noEvidenceId.outcome == NavigationOutcome::EvidenceIdMissing, L"N-08 没带证据 id 的导航被拒绝");

    const WfpNavigationResult pageGone = NavigateFilterToEvidence(withGuid, false, true, true, "ev-1");
    s.expect(pageGone.outcome == NavigationOutcome::TargetPageMissing, L"N-08 目标页不在时说明原因");

    // 连接 -> 进程实例
    ConnectionDescription connection = MakeConnection();
    connection.identity.bootId = "boot-N";
    connection.identity.protocol = 6U;
    connection.identity.localAddress = "192.168.1.50";
    connection.identity.localPort = 52344U;
    connection.identity.remoteAddress = "93.184.216.34";
    connection.identity.remotePort = 443U;
    connection.identity.observedFirstUtc100ns = OptionalU64::of(133700000000000000ULL);
    connection.identity.owner.bootId = "boot-N";
    connection.identity.owner.pid = OptionalU64::of(4321U);
    connection.identity.owner.createTime100ns = OptionalU64::of(133699000000000000ULL);
    connection.identity.owner.imageName = "curl.exe";

    LiveResolution match;
    match.found = true;
    match.liveProcess = connection.identity.owner;
    const WfpNavigationResult toProcess =
        NavigateConnectionToProcess(connection, match, true, true, "ev-2");
    s.expect(toProcess.identityRevalidated, L"N-08 跳现场前做过身份复核");
    s.expect(toProcess.liveDecision == LiveNavigationDecision::Allow, L"N-08 身份一致时允许跳转");
    s.expect(toProcess.outcome == NavigationOutcome::Delivered, L"N-08 身份一致的连接可以跳到进程实例");
    s.expect(toProcess.request.page == NavigationPage::Process, L"N-08 跳转目标是进程页");

    LiveResolution reused;
    reused.found = true;
    reused.liveProcess = connection.identity.owner;
    reused.liveProcess.createTime100ns = OptionalU64::of(133799000000000000ULL);  // PID 被复用
    const WfpNavigationResult reusedNav = NavigateConnectionToProcess(connection, reused, true, true, "ev-2");
    s.expect(reusedNav.liveDecision == LiveNavigationDecision::RejectIdentityMismatch,
             L"N-08 PID 复用被识别为身份不匹配");
    s.expect(reusedNav.outcome == NavigationOutcome::ObjectNotPresent, L"N-08 PID 复用时不把操作交给新进程");

    LiveResolution gone;
    gone.found = false;
    const WfpNavigationResult goneNav = NavigateConnectionToProcess(connection, gone, true, true, "ev-2");
    s.expect(goneNav.liveDecision == LiveNavigationDecision::RejectObjectExited, L"N-08 对象已退出被单独识别");
    s.expect(goneNav.outcome == NavigationOutcome::ObjectNotPresent, L"N-08 对象已退出时不跳转");

    ConnectionDescription weak = connection;
    weak.identity.owner.createTime100ns = OptionalU64::unset();
    LiveResolution weakLive;
    weakLive.found = true;
    weakLive.liveProcess = weak.identity.owner;
    const WfpNavigationResult weakNav = NavigateConnectionToProcess(weak, weakLive, true, true, "ev-2");
    s.expect(weakNav.liveDecision == LiveNavigationDecision::RejectIdentityUnverifiable,
             L"N-08 缺创建时间时身份无法确认");
    s.expect(weakNav.outcome == NavigationOutcome::IdentityUnusable, L"N-08 身份无法确认时拒绝跳转");

    // 运行事件 -> 时间线
    const ObservedFilterHit trusted = MakeHit(ObservationSource::KernelAleCallout, true, true);
    const WfpNavigationResult timeline = NavigateObservationToTimeline(trusted, true, true);
    s.expect(timeline.request.page == NavigationPage::Timeline, L"N-08 事件跳转目标是时间线");
    s.expect(!timeline.blockedByUntrustedSource, L"N-08 受支持来源的事件不被拦下");
    s.expect(timeline.outcome == NavigationOutcome::Delivered, L"N-08 受支持来源的事件可以进时间线");

    const ObservedFilterHit untrusted = MakeHit(ObservationSource::EtwProvider, false, true);
    const WfpNavigationResult blocked = NavigateObservationToTimeline(untrusted, true, true);
    s.expect(blocked.blockedByUntrustedSource, L"N-04 来源不受支持的事件被标记拦下");
    s.expect(blocked.outcome != NavigationOutcome::Delivered, L"N-04 不受支持来源不生成实际经过路径");
    s.expect(!blocked.refetchAttempted, L"N-08 被拦下时也不重新发起查询");

    const WfpNavigationResult timelineNotSaved = NavigateObservationToTimeline(trusted, true, false);
    s.expect(timelineNotSaved.outcome == NavigationOutcome::EvidenceNotSaved,
             L"N-08 离线缺事件数据时明确显示未保存");
}

// ---------------------------------------------------------------------------
// N-08：三种拒绝原因不许塌成一个值
//
// NavigationOutcome::ObjectNotPresent 的语义是"页面在，但对象不在当前数据里"。把
// "来源不可信"也塞进这个值，并且排在常规判据前面，会让"请求根本没带证据 id"整个查不出来。
// ---------------------------------------------------------------------------
void TestNavigationRejectionReasonsStayDistinct(KswordTests::Suite& s) {
    const ObservedFilterHit trusted = MakeHit(ObservationSource::KernelAleCallout, true, true);
    ObservedFilterHit untrusted = MakeHit(ObservationSource::EtwProvider, false, true);

    // (a) 来源可信 + 一切正常
    const WfpNavigationResult ok = NavigateObservationToTimeline(trusted, true, true);
    s.expect(ok.outcome == NavigationOutcome::Delivered, L"N-08 正常情况下事件送达时间线");
    s.expect(ok.rejection == WfpNavigationRejection::None, L"N-08 送达时没有拒绝原因");
    s.expect(!ok.blockedByUntrustedSource, L"N-08 可信来源不被拦下");

    // (b) 来源不可信，其余一切正常 -> 拒绝原因是「来源不可信」
    const WfpNavigationResult untrustedOnly = NavigateObservationToTimeline(untrusted, true, true);
    s.expect(untrustedOnly.blockedByUntrustedSource, L"N-04 不受支持来源被拦下");
    s.expect(untrustedOnly.rejection == WfpNavigationRejection::SourceNotTrusted,
             L"N-08 拒绝原因明确是「来源不可信」而不是「对象不在数据里」");
    s.expect(untrustedOnly.outcome != NavigationOutcome::Delivered,
             L"N-04 不可信来源不生成实际经过路径");

    // (c) 来源可信但请求没带证据 id -> EvidenceIdMissing
    ObservedFilterHit trustedNoEvidence = trusted;
    trustedNoEvidence.evidenceId.clear();
    const WfpNavigationResult noEvidence = NavigateObservationToTimeline(trustedNoEvidence, true, true);
    s.expect(noEvidence.outcome == NavigationOutcome::EvidenceIdMissing,
             L"N-08 没带证据 id 的事件导航报 EvidenceIdMissing");
    s.expect(noEvidence.rejection == WfpNavigationRejection::EvidenceIdMissing,
             L"N-08 拒绝原因是「没带证据 id」");
    s.expect(!noEvidence.blockedByUntrustedSource, L"N-08 可信来源不因为缺证据 id 被标成来源问题");

    // (d) 既不可信、又没带证据 id -> 两个原因都查得出来
    ObservedFilterHit untrustedNoEvidence = untrusted;
    untrustedNoEvidence.evidenceId.clear();
    const WfpNavigationResult both = NavigateObservationToTimeline(untrustedNoEvidence, true, true);
    s.expect(both.outcome == NavigationOutcome::EvidenceIdMissing,
             L"N-08 来源不可信不得把「没带证据 id」盖成「对象不在数据里」");
    s.expect(both.rejection == WfpNavigationRejection::SourceNotTrusted,
             L"N-08 来源不可信仍然作为拒绝原因单列");
    s.expect(both.blockedByUntrustedSource, L"N-08 来源不可信仍然被标记");
    s.expect(both.outcome != untrustedOnly.outcome,
             L"N-08 「不可信且没证据 id」与「只是不可信」在 outcome 上可区分");

    // (e) 来源不可信 + 离线没保存这段数据
    const WfpNavigationResult notSaved = NavigateObservationToTimeline(untrusted, true, false);
    s.expect(notSaved.outcome == NavigationOutcome::EvidenceNotSaved,
             L"N-08 来源不可信不得把「离线未保存」盖掉");
    s.expect(notSaved.rejection == WfpNavigationRejection::SourceNotTrusted,
             L"N-08 离线未保存时来源不可信仍然作为拒绝原因单列");
    s.expect(!notSaved.refetchAttempted, L"N-08 被拦下时也不重新发起查询");

    // (f) 目标页不在 -> TargetPageMissing 不被来源问题覆盖
    const WfpNavigationResult pageGone = NavigateObservationToTimeline(untrusted, false, true);
    s.expect(pageGone.outcome == NavigationOutcome::TargetPageMissing,
             L"N-08 来源不可信不得把「目标页不在」盖掉");

    // (g) 另外两条导航路径也带拒绝原因
    WfpFilter withGuid = MakeFilter(kFilter1, 10U, kSubLayerHigh, kActionBlock, WfpActionType::Block);
    s.expect(NavigateFilterToEvidence(withGuid, true, true, true, "ev-1").rejection ==
                 WfpNavigationRejection::None,
             L"N-08 规则回看送达时没有拒绝原因");
    WfpFilter idOnly = withGuid;
    idOnly.filterKey = WfpGuid{};
    s.expect(NavigateFilterToEvidence(idOnly, true, true, true, "ev-1").rejection ==
                 WfpNavigationRejection::IdentityUnusable,
             L"N-08 只有运行时 id 时拒绝原因是身份不可用");
    s.expect(NavigateFilterToEvidence(withGuid, false, true, true, "ev-1").rejection ==
                 WfpNavigationRejection::TargetPageMissing,
             L"N-08 目标页不在时拒绝原因是目标页缺失");
    s.expect(NavigateFilterToEvidence(withGuid, true, true, false, "ev-1").rejection ==
                 WfpNavigationRejection::EvidenceNotSaved,
             L"N-08 离线未保存时拒绝原因是证据未保存");
}

} // namespace

int RunWfpTests() {
    KswordTests::Suite suite(L"N wfp analysis");
    TestObjectIdentityAndJoins(suite);
    TestActionAndWeightDecoding(suite);
    TestAddressParsing(suite);
    TestConditionInterpretation(suite);
    TestConditionCombination(suite);
    TestUndecodedAddressNeverMatches(suite);
    TestMalformedRangeStaysUnknown(suite);
    TestLeadingZeroOctetsRejected(suite);
    TestStaticArbitration(suite);
    TestUnlinkedFiltersNeverArbitrateTogether(suite);
    TestAbsenceRequiresCompleteCatalog(suite);
    TestObservedEvents(suite);
    TestObservationCollectionOutcomes(suite);
    TestOfflineImportProvenance(suite);
    TestOwnerAttribution(suite);
    TestDynamicStateAndIdReuse(suite);
    TestDeltaRejectsDistortedSnapshots(suite);
    TestNavigation(suite);
    TestNavigationRejectionReasonsStayDistinct(suite);
    suite.report();
    return suite.failures();
}
