#pragma once

// N 模块：WFP 与网络规则解释。
//
// 这一层是**纯解释层**：不调用 Fwpm* API，不含 Qt / Win32，只吃适配层（或离线样本）
// 递进来的对象与条件，产出可复核的解释。枚举本身在既有 NetworkDock 里做。
//
// 贯穿全模块的硬规则：
//   * N-01：本地化显示名不是键。唯一键只有 GUID；同名异 GUID 是两个对象，永远不合并。
//     关联不上时给"未知对象"状态，不猜、不留裸 GUID 冒充已解析。
//   * N-02：不认识的条件保留原始值，并且**绝不等于"无条件匹配"**。任何一条没读懂的
//     条件都会把该 filter 的匹配结论压到 InsufficientInfo。
//   * N-03：仲裁是 per-layer、per-sublayer 的（依据 Microsoft Filter Arbitration，与
//     zh-CN 知识库 [M4] 词条一致）。绝不允许把所有 filter 塞进一个全局 weight 排序。
//     有 callout 动态判定、缺权重元数据、条件读不懂时，最终决策保留 Unknown。
//   * N-04：静态候选与实际运行事件是两套数据结构。只有来自"已启用且受支持"来源的
//     记录才能称实际命中/阻断；没有这类记录时不生成任何"实际经过路径"。
//   * N-05：显示名 / 服务配置 / 模块地址是三种不同证据。没有直接映射就不猜驱动文件，
//     更不编造签名证书。
//   * N-06：BFE 不可用 / 拒绝访问 / 未采集必须落成分区状态，绝不伪装成一条对象行；
//     filterId、calloutId 是可复用的运行时 id，跨采集代次不敢连就说不敢连。
//   * N-08：导航复用 LiveNavigation 的 NavigationRequest/DecideNavigation。本层永远
//     不发起任何查询 —— 离线缺数据只报 EvidenceNotSaved。
//
// 本层不产出 malicious / suspicious / riskScore 之类的判定字段。

#include "EvidenceEnvelope.h"
#include "LiveNavigation.h"
#include "LosslessValue.h"
#include "ObjectIdentity.h"

#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace Ksword::Evidence {

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

// 文本版的"未知 / 已知但可能为空"。空串与未知是两回事（AppId 未采集 ≠ AppId 为空）。
struct OptionalText final {
    bool present = false;
    std::string value;

    static OptionalText unset() { return OptionalText{}; }
    static OptionalText of(std::string v) {
        OptionalText t;
        t.present = true;
        t.value = std::move(v);
        return t;
    }
};

// 限制说明键（i18n 键，UI 负责翻译）。查询用，避免调用方自己写循环。
bool HasLimitation(const std::vector<std::string>& keys, std::string_view key) noexcept;

// ---------------------------------------------------------------------------
// N-01：GUID 是唯一键
// ---------------------------------------------------------------------------

// 规范化 GUID 文本：小写、带花括号、8-4-4-4-12。text 为空表示"未知/未采集"。
struct WfpGuid final {
    std::string text;

    bool known() const noexcept { return !text.empty(); }

    friend bool operator==(const WfpGuid& a, const WfpGuid& b) noexcept { return a.text == b.text; }
    friend bool operator!=(const WfpGuid& a, const WfpGuid& b) noexcept { return !(a == b); }
};

// 解析并规范化。接受带/不带花括号、任意大小写；长度、分隔位置、非十六进制字符一律失败。
// 失败时返回 false 且**不修改** out —— 半解析结果绝不允许流出去当键用。
bool ParseGuid(std::string_view text, WfpGuid& out);

// 测试与离线样本用的便捷构造：解析失败返回 known()==false 的未知 GUID。
// 调用点如果关心"输入是不是合法 GUID"，必须用 ParseGuid，而不是看这里的返回值非空。
WfpGuid GuidFromText(std::string_view text);

// ---------------------------------------------------------------------------
// N-02：地址、掩码与前缀
// ---------------------------------------------------------------------------
enum class WfpAddressFamily {
    Unknown,
    IPv4,
    IPv6,
};

const char* WfpAddressFamilyName(WfpAddressFamily family) noexcept;

struct WfpAddress final {
    WfpAddressFamily family = WfpAddressFamily::Unknown;
    std::array<std::uint8_t, 16> bytes{};  // 网络字节序；IPv4 只用 bytes[0..3]

    bool known() const noexcept { return family != WfpAddressFamily::Unknown; }

    // WFP 的 IPv4 地址在 FWP_VALUE0 里是**主机序 UINT32**，这里显式转成网络序字节。
    static WfpAddress ipv4FromHostOrder(std::uint32_t hostOrder) noexcept;
    static WfpAddress ipv6FromBytes(const std::array<std::uint8_t, 16>& raw) noexcept;

    friend bool operator==(const WfpAddress& a, const WfpAddress& b) noexcept;
    friend bool operator!=(const WfpAddress& a, const WfpAddress& b) noexcept { return !(a == b); }
};

// 文本解析（离线样本入口）。支持点分十进制 IPv4 与 RFC 4291 IPv6（含 :: 与内嵌 IPv4）。
// 失败返回 false 且不修改 out。
//
// N-02"显示与输入一致"：八位组的前导零一律拒绝，与 inet_pton 对齐。历史 inet_addr 把
// "010" 当八进制解成 8，本层若宽松接受就会把 010.001.001.001 静默改写成 10.1.1.1 ——
// 同一串文本在本层、系统接口和别的工具里含义不同，那是无声的语义改写，不是"容错"。
bool ParseIpAddress(std::string_view text, WfpAddress& out);

// 展示用文本。IPv6 按 RFC 5952 压缩（小写、最长零段压成 ::，并列时取最左）。
// 未知地址返回空串 —— 调用方不得把空串当成 "0.0.0.0"。
std::string FormatIpAddress(const WfpAddress& address);

bool Ipv4HostOrder(const WfpAddress& address, std::uint32_t& out) noexcept;

// FWP_V4_ADDR_AND_MASK：mask 是**完整 32 位掩码**而不是前缀长度。非连续掩码是合法输入，
// 必须原样保留，不能偷偷折成前缀长度（N-02 "掩码/前缀"）。
struct WfpV4AddrMask final {
    WfpAddress address;
    std::uint32_t mask = 0;
};

// 连续掩码才能转前缀长度；非连续返回 false，调用方据此保持"掩码"表述。
bool MaskToPrefixLength(std::uint32_t mask, std::uint32_t& outPrefixLength) noexcept;

// FWP_V6_ADDR_AND_MASK：v6 侧是 prefixLength（0..128）。>128 视为非法。
struct WfpV6AddrPrefix final {
    WfpAddress address;
    std::uint32_t prefixLength = 0;
    bool prefixLengthValid = false;
};

// N-02：包含判定必须区分"确实不在里面"和"输入根本不可用"。一个 bool 把两者都表示成
// false，再被 FWP_MATCH_NOT_EQUAL 的取反翻成"匹配"，等于从读不出来的地址推出了结论。
// 判定"不可用"的依据：任一侧地址族未知（ParseIpAddress 失败时按设计不修改 out，所以
// v4Present/v6Present 为真并不代表 address 解出来了）、两侧族不同、v6 前缀长度非法。
enum class AddressContainment {
    Inside,
    Outside,
    Undecidable,
};

const char* AddressContainmentName(AddressContainment containment) noexcept;

AddressContainment ClassifyV4Containment(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept;
AddressContainment ClassifyV6Containment(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept;

// 便捷布尔形式：**只有** Inside 才是 true。调用方若需要区分 Outside 与 Undecidable，
// 必须用上面的三态版本，绝不允许对这里的 false 取反当成"匹配"。
bool AddressInV4Subnet(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept;
bool AddressInV6Prefix(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept;

// ---------------------------------------------------------------------------
// N-02：FWP 数据类型 / 比较运算 / 方向
// ---------------------------------------------------------------------------

// FWP_DATA_TYPE 的子集。Unknown 表示"采到了一个我们没建模的类型"，原始值必须保留。
enum class WfpDataType {
    Empty,
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    ByteArray16,  // 单个 IPv6 地址
    ByteBlob,     // AppId 等
    Sid,
    V4AddrMask,
    V6AddrMask,
    Range,
    Unknown,
};

const char* WfpDataTypeName(WfpDataType type) noexcept;

// FWP_DATA_TYPE 数值 -> 枚举。未建模的数值返回 Unknown（原值由调用方保留在 rawTypeCode）。
WfpDataType DecodeDataType(std::uint32_t rawTypeCode) noexcept;

// FWP_MATCH_TYPE。Unknown 表示没读懂的比较运算 —— 它绝不等于 Equal。
enum class WfpMatchType {
    Equal,
    Greater,
    Less,
    GreaterOrEqual,
    LessOrEqual,
    Range,
    FlagsAllSet,
    FlagsAnySet,
    FlagsNoneSet,
    EqualCaseInsensitive,
    NotEqual,
    Prefix,
    NotPrefix,
    Unknown,
};

const char* WfpMatchTypeName(WfpMatchType match) noexcept;
WfpMatchType DecodeMatchType(std::uint32_t rawMatchCode) noexcept;

// FWP_DIRECTION_ 只定义了 OUTBOUND=0 / INBOUND=1。别的数值一律 Unknown，
// 不许自作主张把 2 解释成 FORWARD（那是转发层的语义，不在 FWP_DIRECTION_ 里）。
enum class WfpDirection {
    Unknown,
    Outbound,
    Inbound,
    Forward,  // 仅供连接描述侧标注转发流量；条件解析不会产出这个值
};

const char* WfpDirectionName(WfpDirection direction) noexcept;
WfpDirection DecodeDirectionValue(std::uint64_t rawValue) noexcept;

// FWP_ACTION_TYPE。Unknown 不是"放行"。
enum class WfpActionType {
    Unknown,
    Block,
    Permit,
    CalloutTerminating,
    CalloutInspection,
    CalloutUnknown,
    Continue,
    None,
    NoneNoMatch,
};

const char* WfpActionTypeName(WfpActionType action) noexcept;
WfpActionType DecodeActionType(std::uint32_t rawActionCode) noexcept;

// callout 类动作意味着最终判定由驱动在运行时给出 —— 静态分析必须保留 Unknown。
bool ActionIsCallout(WfpActionType action) noexcept;

// ---------------------------------------------------------------------------
// N-02：条件字段
// ---------------------------------------------------------------------------
enum class WfpFieldKind {
    Unknown,
    IpLocalAddress,
    IpRemoteAddress,
    IpLocalPort,
    IpRemotePort,
    IpProtocol,
    Direction,
    AleAppId,
    AleUserId,
    IpLocalAddressType,
    Flags,
};

const char* WfpFieldKindName(WfpFieldKind kind) noexcept;

// 内置字段表。GUID 取自 Windows SDK fwpmu.h 的 FWPM_CONDITION_*。
// 注意：SDK 里有若干 FWPM_CONDITION_* 共用同一个 GUID（例如 RESERVED* 系列、
// ALE_PACKAGE_ID 与 MAC_REMOTE_ADDRESS_TYPE），所以 GUID→名称并非全局一对一。
// 这张表只收录**互不冲突**的常用键；其余一律走 Unknown 分支保留原始 GUID。
struct WfpFieldDescriptor final {
    WfpFieldKind kind = WfpFieldKind::Unknown;
    const char* name = "";  // FWPM_CONDITION_* 符号名
};

// 未收录的 GUID 返回 kind==Unknown 且 name 为空串。
WfpFieldDescriptor LookupFieldByGuid(const WfpGuid& fieldKey) noexcept;

// 反查：给定字段语义拿它的条件 GUID（离线样本构造用）。未收录返回未知 GUID。
WfpGuid FieldGuidFor(WfpFieldKind kind);

// ---------------------------------------------------------------------------
// N-02：条件值与条件
// ---------------------------------------------------------------------------
struct WfpRangeValue final {
    WfpDataType elementType = WfpDataType::Unknown;
    bool numeric = false;  // 只有数值端点才可比较
    OptionalU64 low;
    OptionalU64 high;
    std::string rawLow;   // 非数值端点原样保留
    std::string rawHigh;
};

struct WfpConditionValue final {
    WfpDataType type = WfpDataType::Empty;
    std::uint32_t rawTypeCode = 0;  // FWP_DATA_TYPE 原值，永远保留

    OptionalU64 numeric;  // Uint8/16/32/64
    WfpV4AddrMask v4;
    bool v4Present = false;
    WfpV6AddrPrefix v6;
    bool v6Present = false;
    WfpAddress singleAddress;  // ByteArray16
    WfpRangeValue range;
    OptionalText blobText;                 // AppId 的 NT 设备路径（解得出时）
    std::vector<std::uint8_t> blobBytes;   // 原始字节，永远保留
    OptionalText sidText;                  // S-1-5-... 文本
    std::string rawText;                   // 任何没建模类型的原始表示，绝不丢
};

struct WfpCondition final {
    WfpGuid fieldKey;                // 原始条件 GUID
    WfpFieldKind field = WfpFieldKind::Unknown;
    std::string fieldName;           // 解出的 FWPM_CONDITION_* 名；未知则空
    WfpMatchType match = WfpMatchType::Unknown;
    std::uint32_t rawMatchCode = 0;  // FWP_MATCH_TYPE 原值，永远保留
    WfpConditionValue value;

    // 本层是否读懂了这条条件的字段名、比较运算与值类型。
    bool interpreted() const noexcept;

    // 是否能拿它去判定一条连接描述。interpreted() 为真但本层不建模该字段语义
    // （例如 FLAGS / IP_LOCAL_ADDRESS_TYPE）时，evaluable() 为假。
    bool evaluable() const noexcept;
};

// 从原始数值构造条件：字段名与比较运算按内置表解析，解不出就保留原值并标 Unknown。
WfpCondition MakeCondition(const WfpGuid& fieldKey, std::uint32_t rawMatchCode, WfpConditionValue value);

// ---------------------------------------------------------------------------
// N-05：所有者归因
// ---------------------------------------------------------------------------
enum class WfpOwnerAttribution {
    Unknown,        // 没有可用于定位二进制的证据
    Candidate,      // 只有服务配置这类"应该加载谁"的间接证据
    DirectEvidence, // 模块地址落在已加载映像范围内，能直接指名文件
};

const char* WfpOwnerAttributionName(WfpOwnerAttribution attribution) noexcept;

// 三种互不替代的证据。名称永远只是名称。
struct OwnerEvidence final {
    OptionalText displayName;
    bool displayNameAmbiguous = false;  // 目录里同名异 GUID 的对象不止一个

    OptionalText serviceName;      // 对象自报的服务名
    bool serviceRecordFound = false;
    OptionalText serviceImagePath;  // 仅在 serviceRecordFound 时有意义

    OptionalU64 moduleAddress;   // classifyFn/notifyFn/ownerImageBase 之类的真实地址
    bool moduleResolved = false; // 该地址落在某个已加载映像范围内
    OptionalText resolvedModulePath;

    bool signerCertificateRead = false;  // 真的读到了签名信息才允许置位
    OptionalText signerSubject;
};

struct OwnerAttributionResult final {
    WfpOwnerAttribution attribution = WfpOwnerAttribution::Unknown;
    OptionalText ownerModulePath;      // 不变式：只有 DirectEvidence 才允许 present
    OptionalText candidateModulePath;  // 服务配置给出的"应该是谁"，与直接证据分开放
    OptionalText serviceName;
    bool signerCertificateAvailable = false;
    OptionalText signerSubject;        // 不变式：available 为假时必须 unset
    std::vector<std::string> limitationKeys;
};

OwnerAttributionResult DeriveOwnerAttribution(const OwnerEvidence& evidence);

// ---------------------------------------------------------------------------
// N-01：对象模型
// ---------------------------------------------------------------------------

// filter->weight 是 FWP_VALUE0：FWP_EMPTY 表示"自动权重"，FWP_UINT64 才是显式权重。
// 把 weight.type 当权重展示是错的（既有 NetworkAuditPage 的老写法就是这个 bug）。
enum class WfpWeightKind {
    Unknown,   // 未采集
    Auto,      // FWP_EMPTY：由 BFE 自动分配
    Explicit,  // FWP_UINT64：调用方显式指定
};

const char* WfpWeightKindName(WfpWeightKind kind) noexcept;

struct WfpProvider final {
    WfpGuid providerKey;
    OptionalText displayName;
    OptionalText description;
    bool persistent = false;
    OwnerEvidence owner;
};

struct WfpSubLayer final {
    WfpGuid subLayerKey;
    OptionalText displayName;
    WfpGuid providerKey;
    OptionalU64 weight;  // FWPM_SUBLAYER0::weight 是 UINT16
};

struct WfpLayer final {
    WfpGuid layerKey;
    OptionalText displayName;
    OptionalU64 layerId;  // 运行时 id，可复用
    WfpGuid defaultSubLayerKey;
};

struct WfpCallout final {
    WfpGuid calloutKey;
    OptionalText displayName;
    WfpGuid providerKey;
    WfpGuid applicableLayerKey;
    OptionalU64 calloutId;  // 运行时 id，可复用
    bool registered = false;  // 目录里有条目 ≠ 驱动已注册回调
    OwnerEvidence owner;
};

struct WfpFilter final {
    WfpGuid filterKey;
    OptionalU64 filterId;  // 运行时 id，可复用
    OptionalText displayName;
    WfpGuid providerKey;
    WfpGuid layerKey;
    WfpGuid subLayerKey;

    WfpWeightKind weightKind = WfpWeightKind::Unknown;
    OptionalU64 weight;           // 仅 Explicit 时有值
    OptionalU64 effectiveWeight;  // BFE 算出的有效权重

    WfpActionType action = WfpActionType::Unknown;
    std::uint32_t rawActionCode = 0;
    WfpGuid actionCalloutKey;  // action 是 callout 类时指向 callout

    std::vector<WfpCondition> conditions;
    // N-02/N-06：条件被截断时剩下的条件未知，绝不能按"没有更多条件"处理。
    bool conditionsTruncated = false;
};

// ---------------------------------------------------------------------------
// N-01 / N-06：目录、分区状态与关联
// ---------------------------------------------------------------------------
enum class WfpPartition {
    Providers,
    SubLayers,
    Layers,
    Filters,
    Callouts,
};

const char* WfpPartitionName(WfpPartition partition) noexcept;
inline constexpr std::size_t kWfpPartitionCount = 5;

struct WfpPartitionState final {
    CollectionOutcome outcome;  // 默认 NotCollected —— "没采" 是初始状态
    CoverageAccount coverage;
};

enum class ReferenceState {
    Resolved,            // 目录里唯一命中
    UnknownObject,       // GUID 有值、目录可用、但里面没有 —— 显示"未知对象"，不猜
    Ambiguous,           // 目录里同一 GUID 出现多次（快照不自洽）
    NotSpecified,        // 引用字段本身未采集/为空
    CatalogNotCollected, // 该类对象根本没采到，无法判断关联（N-06）
    // N-06：采到了但没采全（Partial / 账目证明不了完整）。"目录里没有"在这种情况下
    // 既不是"未知对象"（那要求目录能正面证明缺席）也不是"完全没采"，必须自成一档，
    // 否则一次 1/9 的枚举会和一次 2000/2000 的完整枚举给出同样的字样。
    CatalogIncomplete,
};

const char* ReferenceStateName(ReferenceState state) noexcept;

struct ObjectReference final {
    ReferenceState state = ReferenceState::NotSpecified;
    WfpGuid key;
    OptionalText resolvedName;  // 不变式：只有 Resolved 才允许 present

    bool resolved() const noexcept { return state == ReferenceState::Resolved; }
};

// 目录。唯一键只有 GUID：同名异 GUID 必然是两个条目。
class WfpCatalog final {
public:
    void setGeneration(std::uint64_t generation) noexcept { generation_ = generation; }
    std::uint64_t generation() const noexcept { return generation_; }

    void setCaptureWindow(CaptureWindow window) { window_ = std::move(window); }
    const CaptureWindow& captureWindow() const noexcept { return window_; }

    void setPartitionState(WfpPartition partition, CollectionOutcome outcome, CoverageAccount coverage);
    const WfpPartitionState& partitionState(WfpPartition partition) const noexcept;

    // N-06：只有"成功 + 账目正面证明完整"才允许把"目录里没有"当成"确实不存在"。
    bool partitionUsableForAbsence(WfpPartition partition) const noexcept;

    // 返回 false 表示该 GUID 已存在（重复行）。对象仍会被登记，并让后续 resolve 报
    // Ambiguous —— 静默丢弃重复行会让"快照不自洽"这一事实消失。
    bool addProvider(WfpProvider provider);
    bool addSubLayer(WfpSubLayer subLayer);
    bool addLayer(WfpLayer layer);
    bool addCallout(WfpCallout callout);
    bool addFilter(WfpFilter filter);

    const std::vector<WfpProvider>& providers() const noexcept { return providers_; }
    const std::vector<WfpSubLayer>& subLayers() const noexcept { return subLayers_; }
    const std::vector<WfpLayer>& layers() const noexcept { return layers_; }
    const std::vector<WfpCallout>& callouts() const noexcept { return callouts_; }
    const std::vector<WfpFilter>& filters() const noexcept { return filters_; }

    ObjectReference resolveProvider(const WfpGuid& key) const;
    ObjectReference resolveSubLayer(const WfpGuid& key) const;
    ObjectReference resolveLayer(const WfpGuid& key) const;
    ObjectReference resolveCallout(const WfpGuid& key) const;
    ObjectReference resolveFilter(const WfpGuid& key) const;

    // N-01：名称查询返回**全部**同名对象。调用方据此判断"这个名字有歧义"，
    // 而不是拿名字当键去 join。
    std::vector<WfpGuid> findProvidersByDisplayName(std::string_view name) const;
    std::vector<WfpGuid> findCalloutsByDisplayName(std::string_view name) const;

    // 运行时 id 反查（可复用 id，跨代次必须另行校验）。
    std::vector<std::size_t> findFilterIndexesByRuntimeId(const OptionalU64& filterId) const;

    // 供 N-05 使用：把"目录里同名对象数 > 1"写进证据。
    OwnerEvidence providerOwnerEvidence(std::size_t providerIndex) const;
    OwnerEvidence calloutOwnerEvidence(std::size_t calloutIndex) const;

private:
    struct Index final {
        std::map<std::string, std::size_t> byGuid;
        std::map<std::string, bool> duplicated;
    };

    // 查表结果：状态 + 命中位置。名字由各 resolveXxx 从自己的容器里取，
    // 避免在这里对不同类型做指针步长运算。
    struct IndexHit final {
        ReferenceState state = ReferenceState::NotSpecified;
        bool hasPosition = false;
        std::size_t position = 0;
    };

    static bool registerKey(Index& index, const WfpGuid& key, std::size_t position);
    // 未命中时的判据统一走 partitionUsableForAbsence()：只有"能正面证明枚举完整"的
    // 分区才允许把"目录里没有"渲染成 UnknownObject。
    IndexHit lookup(const Index& index, const WfpGuid& key, WfpPartition partition) const;

    std::uint64_t generation_ = 0;
    CaptureWindow window_;
    std::array<WfpPartitionState, kWfpPartitionCount> partitions_{};

    std::vector<WfpProvider> providers_;
    std::vector<WfpSubLayer> subLayers_;
    std::vector<WfpLayer> layers_;
    std::vector<WfpCallout> callouts_;
    std::vector<WfpFilter> filters_;

    Index providerIndex_;
    Index subLayerIndex_;
    Index layerIndex_;
    Index calloutIndex_;
    Index filterIndex_;
};

// ---------------------------------------------------------------------------
// N-03：连接描述与三态匹配
// ---------------------------------------------------------------------------
struct ConnectionDescription final {
    WfpAddress localAddress;
    WfpAddress remoteAddress;
    OptionalU64 localPort;
    OptionalU64 remotePort;
    OptionalU64 protocol;  // IPPROTO_*
    WfpDirection direction = WfpDirection::Unknown;
    OptionalText appId;   // 归一化 NT 设备路径
    OptionalText userSid;
    ConnectionIdentity identity;  // 复用 F-03 身份，供 N-08 导航
};

enum class ConditionMatch {
    Match,
    NoMatch,
    InsufficientInfo,
};

const char* ConditionMatchName(ConditionMatch match) noexcept;

struct ConditionEvaluation final {
    WfpCondition condition;
    ConditionMatch result = ConditionMatch::InsufficientInfo;
    std::vector<std::string> limitationKeys;
};

ConditionEvaluation EvaluateCondition(const WfpCondition& condition, const ConnectionDescription& connection);

// 一条 filter 的全部条件：同字段 OR、跨字段 AND（这是 FWP 的真实语义），
// 三值逻辑按 Kleene 规则合并。条件为空 = 真正的"无条件"；条件被截断 = InsufficientInfo。
ConditionMatch CombineConditionResults(const std::vector<ConditionEvaluation>& evaluations,
                                       bool conditionsTruncated);

// ---------------------------------------------------------------------------
// N-03：仲裁与候选
// ---------------------------------------------------------------------------

// 排序依据。effectiveWeight 与 explicit weight 是两个量纲，混着排没有意义。
enum class WeightOrderConfidence {
    Unknown,          // 没有可比权重
    ExplicitWeight,   // 只有调用方指定的 weight
    EffectiveWeight,  // BFE 计算出的有效权重
};

const char* WeightOrderConfidenceName(WeightOrderConfidence confidence) noexcept;

enum class CandidateDecision {
    Unknown,           // 信息不足 / 有动态判定 / 顺序不可信 / 目录不足以证明缺席 —— 不猜
    // 该范围内没有任何 filter 匹配（层默认动作不在本模型内）。
    // N-03 硬约束：这是一条**缺席断言**，只有 filter 分区能正面证明枚举完整时才允许
    // 产出。BFE 打不开、分区未采集、只枚举到 1/9 —— 这些情况一律是 Unknown，
    // 否则一次彻底失败的枚举会和"完整枚举 2000 条后确实没有规则匹配"显示成同一句话。
    NoMatchingFilter,
    BlockCandidate,
    PermitCandidate,
};

const char* CandidateDecisionName(CandidateDecision decision) noexcept;

struct FilterCandidate final {
    WfpGuid filterKey;
    OptionalU64 filterId;
    OptionalText displayName;
    ObjectReference provider;
    ObjectReference layer;
    ObjectReference subLayer;
    ObjectReference actionCallout;

    WfpActionType action = WfpActionType::Unknown;
    bool dynamicByCallout = false;

    WeightOrderConfidence weightConfidence = WeightOrderConfidence::Unknown;
    OptionalU64 orderingWeight;

    ConditionMatch match = ConditionMatch::InsufficientInfo;
    std::vector<ConditionEvaluation> conditions;
    std::vector<std::string> limitationKeys;
};

struct SubLayerCandidateGroup final {
    ObjectReference subLayer;
    OptionalU64 subLayerWeight;
    std::vector<FilterCandidate> filters;  // 可排时按仲裁顺序（权重降序）
    bool orderingReliable = false;         // 全部 filter 同量纲、有值且互不相等
    CandidateDecision decision = CandidateDecision::Unknown;
    // N-01：layer/sublayer 引用未采集的 filter 每条独占一个分组，不与任何别的 filter
    // （包括别的同样缺引用的 filter）互相仲裁。真实所属范围未知时，两条规则很可能
    // 根本不在同一个仲裁范围里，"900 压过 100"这种结论没有依据。
    bool unlinkedReference = false;
    std::vector<std::string> limitationKeys;
};

struct LayerCandidateGroup final {
    ObjectReference layer;
    std::vector<SubLayerCandidateGroup> subLayers;  // 按 sublayer 权重降序
    bool subLayerOrderingReliable = false;
    CandidateDecision decision = CandidateDecision::Unknown;
    bool unlinkedReference = false;  // 见 SubLayerCandidateGroup::unlinkedReference
    std::vector<std::string> limitationKeys;
};

struct StaticCandidateReport final {
    std::vector<LayerCandidateGroup> layers;
    // 跨层的保守汇总：任一层 Unknown 即 Unknown。它**不是**数据包的实际路径判定。
    CandidateDecision overallDecision = CandidateDecision::Unknown;
    std::size_t evaluatedFilterCount = 0;
    // N-06：filter 分区是否能正面证明枚举完整。为假时本报告里所有"无匹配规则"
    // 都已降级为 Unknown，且每个分组自己也带上了 wfp.candidate.filter-catalog-incomplete。
    bool catalogUsableForAbsence = false;
    std::vector<std::string> limitationKeys;
};

FilterCandidate EvaluateFilter(const WfpCatalog& catalog,
                               const WfpFilter& filter,
                               const ConnectionDescription& connection);

StaticCandidateReport AnalyzeStaticCandidates(const WfpCatalog& catalog,
                                              const ConnectionDescription& connection);

// ---------------------------------------------------------------------------
// N-04：实际运行事件
// ---------------------------------------------------------------------------
enum class ObservationSource {
    Unknown,
    WfpNetEventEnum,       // FwpmNetEventEnum*
    WfpNetEventSubscribe,  // FwpmNetEventSubscribe*
    KernelAleCallout,      // 本工具驱动的 ALE 流授权事件环
    EtwProvider,
    SecurityAuditLog,      // 5152/5157 之类
    // 从离线样本导入。它只说明"这条记录是从样本读进来的"，不说明原始证据来自哪里 ——
    // 真实来源必须填在 ObservedFilterHit::originalSource 里。没有原始来源的离线记录
    // 一律不可信（N-04：来源栏必须能显示"5157 安全审计 / FwpmNetEventEnum / 本工具驱动"
    // 到底是哪一个，不能只显示"离线导入"）。
    OfflineImport,
};

const char* ObservationSourceName(ObservationSource source) noexcept;

enum class WfpEventVerdict {
    Unknown,
    Permitted,
    Blocked,
};

const char* WfpEventVerdictName(WfpEventVerdict verdict) noexcept;

struct ObservedFilterHit final {
    ObservationSource source = ObservationSource::Unknown;
    // source == OfflineImport 时，样本里另记的真实来源。必须填；留 Unknown 意味着
    // 这条记录的证据来源不明，ClassifyObservation 会判 SourceUnknown 而不是实际观测。
    // 对非 OfflineImport 的记录这两个字段无意义，保持默认即可。
    ObservationSource originalSource = ObservationSource::Unknown;
    OptionalText originalSourceDetail;  // 例如 "Security 5157" / "FwpmNetEventEnum0"
    bool sourceSupported = false;  // 该来源在当前系统上受支持
    bool sourceEnabled = false;    // 采集时该来源确实处于启用状态
    OptionalU64 filterId;          // 运行时 id
    WfpGuid filterKey;
    OptionalU64 layerId;
    OptionalU64 eventUtc100ns;
    WfpEventVerdict verdict = WfpEventVerdict::Unknown;
    ConnectionIdentity connection;
    std::string rawRecordId;
    OptionalU64 capturedGeneration;  // 记录所属的目录采集代次
    std::string evidenceId;
};

enum class ObservationTrust {
    ActualObservation,  // 已启用且受支持 —— 只有这一档能称"实际命中/阻断"
    SourceUnknown,
    SourceUnsupported,
    SourceNotEnabled,
};

const char* ObservationTrustName(ObservationTrust trust) noexcept;

ObservationTrust ClassifyObservation(const ObservedFilterHit& hit) noexcept;

// N-04：只有 ActualObservation 的记录才允许把 verdict 渲染成"实际阻断/放行"。
bool DescribesActualVerdict(const ObservedFilterHit& hit) noexcept;

// N-04 / F-05：事件通道的采集状态。"ETW 订阅失败 / FwpmNetEventEnum 返回错误 /
// 根本没订阅" 与 "来源受支持且已启用、正常跑完、确实零事件" 必须在结构上分得开 ——
// 没有这一段，导出只能写"实际命中 0"，读者会读成"没有任何东西被阻断"。
struct ObservationSourceOutcome final {
    ObservationSource source = ObservationSource::Unknown;
    bool sourceSupported = false;
    bool sourceEnabled = false;
    CollectionOutcome outcome;   // 默认 NotCollected —— "没订阅"是初始状态
    CoverageAccount coverage;

    // 这一路来源是否真的跑起来并带回了观测（哪怕是正确的空集合）。
    bool carriesObservation() const noexcept;
};

// 静态候选与实际事件在结构上分开，导出也按两段走。
struct RuleExplanation final {
    StaticCandidateReport candidates;
    std::vector<ObservedFilterHit> observations;
    // 事件来源的采集账目。渲染 actualHitCount()==0 之前必须先看它：
    // observationsCollected() 为假时只能报"事件来源未采集/采集失败 + 原始错误码"，
    // 绝不能报"实际命中 0"。
    std::vector<ObservationSourceOutcome> sourceOutcomes;

    std::size_t actualHitCount() const noexcept;
    std::size_t untrustedObservationCount() const noexcept;

    // 至少有一路"受支持 + 已启用 + 带回观测"的来源。为假时"零命中"是采集问题，
    // 不是"确实没有命中"。
    bool observationsCollected() const noexcept;

    // 存在采集失败/未采集的来源（有账目但状态不携带观测）。UI 据此提示原始错误码。
    bool anyObservationSourceFailed() const noexcept;

    // 没有任何受支持且启用来源的记录时，不允许生成"实际经过路径"。
    bool hasActualPath() const noexcept;
};

// ---------------------------------------------------------------------------
// N-06：运行时 id 引用与失效
// ---------------------------------------------------------------------------
struct RuntimeFilterReference final {
    OptionalU64 filterId;
    WfpGuid filterKey;
    OptionalU64 capturedGeneration;  // 未知即 unset
    // 采集时所处的启动周期。代次号只在同一次启动内单调，跨启动会从头再来，
    // 所以"代次相同"跨启动不成立 —— 两侧都拿得到 bootId 时必须先对上（N-06）。
    std::string bootId;
};

enum class FilterLinkState {
    LinkedByGuid,                     // GUID 命中 —— 跨代次仍然可信
    LinkedByRuntimeIdSameGeneration,  // 同代次内按 filterId 关联
    RejectedIdReused,                 // 引用自带 GUID，与目录里同 id 的对象不是一个
    RejectedStaleGeneration,          // 代次不同/代次未知且没有 GUID 可核对 —— 不敢连
    RejectedAmbiguous,                // 目录里同一 GUID 或同一 filterId 有多条
    // 目录**能正面证明枚举完整**，且里面确实没有。这是一条缺席断言。
    NoMatch,
    CatalogNotCollected,              // filter 分区没采到，无法判断
    // 采到了但没采全 —— 找不到不等于不存在（N-06）。与 NoMatch 是两回事。
    CatalogIncomplete,
    NotSpecified,                     // 引用什么都没带
};

const char* FilterLinkStateName(FilterLinkState state) noexcept;

struct FilterReferenceResolution final {
    FilterLinkState state = FilterLinkState::NotSpecified;
    bool hasIndex = false;
    std::size_t filterIndex = 0;
    std::vector<std::string> limitationKeys;
};

FilterReferenceResolution ResolveFilterReference(const WfpCatalog& catalog,
                                                 const RuntimeFilterReference& reference);

FilterReferenceResolution LinkObservationToCatalog(const WfpCatalog& catalog,
                                                   const ObservedFilterHit& hit);

// 两次采集之间的变化。只有在**两侧账目都能正面证明完整**时才敢说"新增/删除"。
enum class CatalogChangeKind {
    Added,
    Removed,
    ActionChanged,
    WeightChanged,
    ConditionsChanged,
    RuntimeIdReused,   // 同一 filterId 在两代里指向不同 GUID
    PresenceUnknown,   // 有一侧不足以判断在场与否
};

const char* CatalogChangeKindName(CatalogChangeKind kind) noexcept;

struct CatalogChange final {
    CatalogChangeKind kind = CatalogChangeKind::PresenceUnknown;
    WfpGuid filterKey;
    OptionalU64 beforeFilterId;
    OptionalU64 afterFilterId;
    std::vector<std::string> limitationKeys;
};

struct CatalogDelta final {
    std::vector<CatalogChange> changes;
    // 两侧 filter 分区都能做缺席推断，**并且**两侧都没有让 GUID 索引失真的行
    // （同 GUID 重复 / 根本没有 GUID）时才为真。任何一条这样的行都会让"增删改"
    // 这套结论失去依据：重复行会被静默丢掉一条，无 GUID 行根本进不了比较。
    bool comparable = false;
    std::vector<std::string> limitationKeys;
};

CatalogDelta DiffCatalogs(const WfpCatalog& before, const WfpCatalog& after);

// ---------------------------------------------------------------------------
// N-08：导航
// ---------------------------------------------------------------------------

// filter 的对象引用。ObjectIdentity 的 ObjectKind 没有 WFP filter 这一类，
// 这里用 Unknown 类别 + 带前缀的键，避免与进程/驱动键互撞。
// 只有 GUID 已知才发键；只有运行时 id 的引用一律 Unusable（id 可复用）。
ObjectRef MakeFilterRef(const WfpFilter& filter, std::string evidenceId);
ObjectRef MakeCalloutRef(const WfpCallout& callout, std::string evidenceId);

// N-08：拒绝原因。NavigationOutcome 里"对象不在当前数据里"这一个值同时被用来表示
// "来源不可信"和"请求没带证据 id"，三种完全不同的原因在 outcome 这一维塌成一个值，
// 导出只写 outcome 就丢了原因。本枚举与 outcome 并列输出，专门保住这个区分度。
enum class WfpNavigationRejection {
    None,               // outcome == Delivered
    TargetPageMissing,
    ObjectNotPresent,   // 页面在，但对象不在当前数据里
    IdentityUnusable,   // 引用身份不足（例如只有可复用的 filterId）
    EvidenceIdMissing,  // 请求根本没带证据 id
    EvidenceNotSaved,   // 离线会话里这段数据没保存
    SourceNotTrusted,   // N-04：来源不受支持/未启用/来源不明，不能当"实际经过路径"
};

const char* WfpNavigationRejectionName(WfpNavigationRejection rejection) noexcept;

struct WfpNavigationResult final {
    NavigationRequest request;
    NavigationOutcome outcome = NavigationOutcome::ObjectNotPresent;
    // 与 outcome 并列的拒绝原因。outcome 复用 LiveNavigation 的取值域（不新增），
    // 具体是哪一种拒绝看这里。
    WfpNavigationRejection rejection = WfpNavigationRejection::ObjectNotPresent;
    // 恒为 false：本层永远不重新发起查询。离线缺数据只报 EvidenceNotSaved。
    bool refetchAttempted = false;

    // 从离线连接跳现场时的身份复核结果（F-09 / N-08）。
    bool identityRevalidated = false;
    LiveNavigationDecision liveDecision = LiveNavigationDecision::RejectIdentityUnverifiable;

    // N-04：来源不受支持/未启用的记录不能当"实际经过路径"送去时间线。
    bool blockedByUntrustedSource = false;
};

// 从一条连接跳到进程实例。saved/live 身份不一致时按 F-09 拒绝。
WfpNavigationResult NavigateConnectionToProcess(const ConnectionDescription& connection,
                                                const LiveResolution& live,
                                                bool targetPageAvailable,
                                                bool evidencePresentInSession,
                                                std::string evidenceId);

// 从一条 filter 回看关联证据（规则 → 证据）。
WfpNavigationResult NavigateFilterToEvidence(const WfpFilter& filter,
                                             bool targetPageAvailable,
                                             bool objectPresentInPage,
                                             bool evidencePresentInSession,
                                             std::string evidenceId);

// 从一条运行事件跳到时间线。事件没有受支持来源时不允许把它当"实际路径"送去时间线。
// 判定顺序：先按常规导航判据（身份 / 证据 id / 目标页 / 离线是否保存）拿到结论，
// 再用来源可信度覆盖 —— 否则"来源不可信"会把"根本没带证据 id"整个盖掉。
WfpNavigationResult NavigateObservationToTimeline(const ObservedFilterHit& hit,
                                                  bool targetPageAvailable,
                                                  bool evidencePresentInSession);

} // namespace Ksword::Evidence
