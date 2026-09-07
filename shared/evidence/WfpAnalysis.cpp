#include "WfpAnalysis.h"

#include <algorithm>
#include <utility>

namespace Ksword::Evidence {

namespace {

// ---------------------------------------------------------------------------
// 基础工具
// ---------------------------------------------------------------------------
char LowerAscii(char c) noexcept {
    return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
}

bool EqualsIgnoreCase(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (LowerAscii(a[i]) != LowerAscii(b[i])) {
            return false;
        }
    }
    return true;
}

bool StartsWithIgnoreCase(std::string_view text, std::string_view prefix) noexcept {
    if (prefix.size() > text.size()) {
        return false;
    }
    return EqualsIgnoreCase(text.substr(0, prefix.size()), prefix);
}

int HexDigit(char c) noexcept {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

void AddKey(std::vector<std::string>& keys, std::string_view key) {
    for (const std::string& existing : keys) {
        if (std::string_view(existing) == key) {
            return;
        }
    }
    keys.emplace_back(key);
}

void MergeKeys(std::vector<std::string>& target, const std::vector<std::string>& source) {
    for (const std::string& key : source) {
        AddKey(target, key);
    }
}

// ---------------------------------------------------------------------------
// 三值逻辑（Kleene）。这是 N-02/N-03 的核心：未知的否定仍然是未知，
// 未知绝不塌成"匹配"，也绝不塌成"不匹配"。
// ---------------------------------------------------------------------------
ConditionMatch NegateMatch(ConditionMatch value) noexcept {
    switch (value) {
    case ConditionMatch::Match:
        return ConditionMatch::NoMatch;
    case ConditionMatch::NoMatch:
        return ConditionMatch::Match;
    case ConditionMatch::InsufficientInfo:
        return ConditionMatch::InsufficientInfo;
    }
    return ConditionMatch::InsufficientInfo;
}

ConditionMatch AndMatch(ConditionMatch a, ConditionMatch b) noexcept {
    if (a == ConditionMatch::NoMatch || b == ConditionMatch::NoMatch) {
        return ConditionMatch::NoMatch;
    }
    if (a == ConditionMatch::InsufficientInfo || b == ConditionMatch::InsufficientInfo) {
        return ConditionMatch::InsufficientInfo;
    }
    return ConditionMatch::Match;
}

ConditionMatch OrMatch(ConditionMatch a, ConditionMatch b) noexcept {
    if (a == ConditionMatch::Match || b == ConditionMatch::Match) {
        return ConditionMatch::Match;
    }
    if (a == ConditionMatch::InsufficientInfo || b == ConditionMatch::InsufficientInfo) {
        return ConditionMatch::InsufficientInfo;
    }
    return ConditionMatch::NoMatch;
}

ConditionMatch FromBool(bool value) noexcept {
    return value ? ConditionMatch::Match : ConditionMatch::NoMatch;
}

// ---------------------------------------------------------------------------
// 内置条件字段表。GUID 抄自 Windows SDK fwpmu.h 的 FWPM_CONDITION_*。
// ---------------------------------------------------------------------------
struct FieldTableEntry final {
    WfpFieldKind kind;
    const char* guid;  // 已经是规范化形式（小写带花括号）
    const char* name;
};

constexpr FieldTableEntry kFieldTable[] = {
    { WfpFieldKind::IpLocalAddress,     "{d9ee00de-c1ef-4617-bfe3-ffd8f5a08957}", "FWPM_CONDITION_IP_LOCAL_ADDRESS" },
    { WfpFieldKind::IpRemoteAddress,    "{b235ae9a-1d64-49b8-a44c-5ff3d9095045}", "FWPM_CONDITION_IP_REMOTE_ADDRESS" },
    // 注意：FWPM_CONDITION_ICMP_TYPE 在 SDK 里就是 IP_LOCAL_PORT 的别名，
    // FWPM_CONDITION_ICMP_CODE 是 IP_REMOTE_PORT 的别名。GUID 解不出"到底是哪个语义"，
    // 只能按端口解释；真要区分得看所在 layer。这一点必须在 UI 上说明，不能装作端口。
    { WfpFieldKind::IpLocalPort,        "{0c1ba1af-5765-453f-af22-a8f791ac775b}", "FWPM_CONDITION_IP_LOCAL_PORT" },
    { WfpFieldKind::IpRemotePort,       "{c35a604d-d22b-4e1a-91b4-68f674ee674b}", "FWPM_CONDITION_IP_REMOTE_PORT" },
    { WfpFieldKind::IpProtocol,         "{3971ef2b-623e-4f9a-8cb1-6e79b806b9a7}", "FWPM_CONDITION_IP_PROTOCOL" },
    { WfpFieldKind::Direction,          "{8784c146-ca97-44d6-9fd1-19fb1840cbf7}", "FWPM_CONDITION_DIRECTION" },
    { WfpFieldKind::AleAppId,           "{d78e1e87-8644-4ea5-9437-d809ecefc971}", "FWPM_CONDITION_ALE_APP_ID" },
    { WfpFieldKind::AleUserId,          "{af043a0a-b34d-4f86-979c-c90371af6e66}", "FWPM_CONDITION_ALE_USER_ID" },
    { WfpFieldKind::IpLocalAddressType, "{6ec7f6c4-376b-45d7-9e9c-d337cedcd237}", "FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE" },
    { WfpFieldKind::Flags,              "{632ce23b-5167-435c-86d7-e903684aa80c}", "FWPM_CONDITION_FLAGS" },
};

// 本层真正能拿去判定一条连接的字段。IP_LOCAL_ADDRESS_TYPE / FLAGS 认得出名字，
// 但连接描述里没有对应维度 —— 认得名字不等于能判定，必须退回 InsufficientInfo。
bool FieldIsModeled(WfpFieldKind kind) noexcept {
    switch (kind) {
    case WfpFieldKind::IpLocalAddress:
    case WfpFieldKind::IpRemoteAddress:
    case WfpFieldKind::IpLocalPort:
    case WfpFieldKind::IpRemotePort:
    case WfpFieldKind::IpProtocol:
    case WfpFieldKind::Direction:
    case WfpFieldKind::AleAppId:
    case WfpFieldKind::AleUserId:
        return true;
    case WfpFieldKind::IpLocalAddressType:
    case WfpFieldKind::Flags:
    case WfpFieldKind::Unknown:
        return false;
    }
    return false;
}

bool DataTypeIsNumeric(WfpDataType type) noexcept {
    switch (type) {
    case WfpDataType::Uint8:
    case WfpDataType::Uint16:
    case WfpDataType::Uint32:
    case WfpDataType::Uint64:
        return true;
    case WfpDataType::Empty:
    case WfpDataType::ByteArray16:
    case WfpDataType::ByteBlob:
    case WfpDataType::Sid:
    case WfpDataType::V4AddrMask:
    case WfpDataType::V6AddrMask:
    case WfpDataType::Range:
    case WfpDataType::Unknown:
        return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 条件签名：只用于 N-06 的两代对比，不参与任何匹配判定。
// ---------------------------------------------------------------------------
std::string ConditionSignature(const WfpCondition& condition) {
    std::string sig = condition.fieldKey.text;
    sig.push_back('|');
    sig += FormatU64(condition.rawMatchCode, U64Format::Decimal);
    sig.push_back('|');
    sig += FormatU64(condition.value.rawTypeCode, U64Format::Decimal);
    sig.push_back('|');
    sig += FormatOptionalU64(condition.value.numeric, U64Format::Decimal);
    sig.push_back('|');
    if (condition.value.v4Present) {
        sig += FormatIpAddress(condition.value.v4.address);
        sig.push_back('/');
        sig += FormatU64(condition.value.v4.mask, U64Format::Decimal);
    }
    sig.push_back('|');
    if (condition.value.v6Present) {
        sig += FormatIpAddress(condition.value.v6.address);
        sig.push_back('/');
        sig += FormatU64(condition.value.v6.prefixLength, U64Format::Decimal);
    }
    sig.push_back('|');
    if (condition.value.blobText.present) {
        sig += condition.value.blobText.value;
    }
    sig.push_back('|');
    if (condition.value.sidText.present) {
        sig += condition.value.sidText.value;
    }
    sig.push_back('|');
    sig += condition.value.rawText;
    sig.push_back('|');
    sig += FormatOptionalU64(condition.value.range.low, U64Format::Decimal);
    sig.push_back('-');
    sig += FormatOptionalU64(condition.value.range.high, U64Format::Decimal);
    return sig;
}

std::string FilterConditionsSignature(const WfpFilter& filter) {
    std::string sig = filter.conditionsTruncated ? "truncated;" : "complete;";
    for (const WfpCondition& condition : filter.conditions) {
        sig += ConditionSignature(condition);
        sig.push_back(';');
    }
    return sig;
}

} // namespace

// ---------------------------------------------------------------------------
// 限制键
// ---------------------------------------------------------------------------
bool HasLimitation(const std::vector<std::string>& keys, std::string_view key) noexcept {
    for (const std::string& existing : keys) {
        if (std::string_view(existing) == key) {
            return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// GUID
// ---------------------------------------------------------------------------
bool ParseGuid(std::string_view text, WfpGuid& out) {
    std::string_view body = text;
    if (body.size() >= 2 && body.front() == '{' && body.back() == '}') {
        body = body.substr(1, body.size() - 2);
    }
    if (body.size() != 36U) {
        return false;
    }
    static constexpr std::size_t kHyphen[4] = { 8U, 13U, 18U, 23U };
    for (std::size_t position : kHyphen) {
        if (body[position] != '-') {
            return false;
        }
    }
    std::string normalized;
    normalized.reserve(38U);
    normalized.push_back('{');
    for (std::size_t i = 0; i < body.size(); ++i) {
        const char c = body[i];
        if (c == '-') {
            if (i != kHyphen[0] && i != kHyphen[1] && i != kHyphen[2] && i != kHyphen[3]) {
                return false;
            }
            normalized.push_back('-');
            continue;
        }
        if (HexDigit(c) < 0) {
            return false;
        }
        normalized.push_back(LowerAscii(c));
    }
    normalized.push_back('}');
    out.text = std::move(normalized);
    return true;
}

WfpGuid GuidFromText(std::string_view text) {
    WfpGuid guid;
    if (!ParseGuid(text, guid)) {
        return WfpGuid{};
    }
    return guid;
}

// ---------------------------------------------------------------------------
// 地址
// ---------------------------------------------------------------------------
const char* WfpAddressFamilyName(WfpAddressFamily family) noexcept {
    switch (family) {
    case WfpAddressFamily::Unknown: return "Unknown";
    case WfpAddressFamily::IPv4:    return "IPv4";
    case WfpAddressFamily::IPv6:    return "IPv6";
    }
    return "Unknown";
}

WfpAddress WfpAddress::ipv4FromHostOrder(std::uint32_t hostOrder) noexcept {
    WfpAddress address;
    address.family = WfpAddressFamily::IPv4;
    address.bytes[0] = static_cast<std::uint8_t>((hostOrder >> 24) & 0xFFU);
    address.bytes[1] = static_cast<std::uint8_t>((hostOrder >> 16) & 0xFFU);
    address.bytes[2] = static_cast<std::uint8_t>((hostOrder >> 8) & 0xFFU);
    address.bytes[3] = static_cast<std::uint8_t>(hostOrder & 0xFFU);
    return address;
}

WfpAddress WfpAddress::ipv6FromBytes(const std::array<std::uint8_t, 16>& raw) noexcept {
    WfpAddress address;
    address.family = WfpAddressFamily::IPv6;
    address.bytes = raw;
    return address;
}

bool operator==(const WfpAddress& a, const WfpAddress& b) noexcept {
    if (a.family != b.family) {
        return false;
    }
    const std::size_t length = (a.family == WfpAddressFamily::IPv4) ? 4U : 16U;
    if (a.family == WfpAddressFamily::Unknown) {
        return true;  // 两个"未知"在结构上相等；调用方必须先看 known()
    }
    for (std::size_t i = 0; i < length; ++i) {
        if (a.bytes[i] != b.bytes[i]) {
            return false;
        }
    }
    return true;
}

namespace {

bool ParseIpv4Bytes(std::string_view text, std::array<std::uint8_t, 4>& out) {
    std::size_t pos = 0;
    for (std::size_t part = 0; part < 4U; ++part) {
        if (part > 0) {
            if (pos >= text.size() || text[pos] != '.') {
                return false;
            }
            ++pos;
        }
        const std::size_t start = pos;
        std::uint32_t value = 0;
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
            value = value * 10U + static_cast<std::uint32_t>(text[pos] - '0');
            if (value > 255U) {
                return false;
            }
            ++pos;
        }
        const std::size_t digits = pos - start;
        if (digits == 0U || digits > 3U) {
            return false;
        }
        // N-02"显示与输入一致"：前导零一律拒绝，与 inet_pton 对齐。历史 inet_addr 会把
        // "010" 按八进制解成 8，宽松接受就意味着 010.001.001.001 在本层显示成 10.1.1.1、
        // 在系统接口里是 8.1.1.1 —— 同一串文本三种含义，还没有任何提示。
        if (digits > 1U && text[start] == '0') {
            return false;
        }
        out[part] = static_cast<std::uint8_t>(value);
    }
    return pos == text.size();
}

bool ParseIpv6Bytes(std::string_view text, std::array<std::uint8_t, 16>& out) {
    std::vector<std::uint8_t> head;
    std::vector<std::uint8_t> tail;
    bool sawDoubleColon = false;
    bool inTail = false;
    std::size_t pos = 0;

    if (!text.empty() && text[0] == ':') {
        if (text.size() < 2U || text[1] != ':') {
            return false;
        }
        sawDoubleColon = true;
        inTail = true;
        pos = 2U;
        if (pos == text.size()) {
            out.fill(0U);
            return true;  // "::"
        }
    }

    while (pos < text.size()) {
        const std::size_t start = pos;
        while (pos < text.size() && text[pos] != ':') {
            ++pos;
        }
        const std::string_view token = text.substr(start, pos - start);
        if (token.empty()) {
            return false;
        }
        std::vector<std::uint8_t>& target = inTail ? tail : head;
        if (token.find('.') != std::string_view::npos) {
            if (pos != text.size()) {
                return false;  // 内嵌 IPv4 只能出现在末尾
            }
            std::array<std::uint8_t, 4> v4{};
            if (!ParseIpv4Bytes(token, v4)) {
                return false;
            }
            for (std::uint8_t byte : v4) {
                target.push_back(byte);
            }
            break;
        }
        if (token.size() > 4U) {
            return false;
        }
        std::uint32_t group = 0;
        for (char c : token) {
            const int digit = HexDigit(c);
            if (digit < 0) {
                return false;
            }
            group = group * 16U + static_cast<std::uint32_t>(digit);
        }
        target.push_back(static_cast<std::uint8_t>((group >> 8) & 0xFFU));
        target.push_back(static_cast<std::uint8_t>(group & 0xFFU));

        if (pos == text.size()) {
            break;
        }
        ++pos;  // 跳过 ':'
        if (pos < text.size() && text[pos] == ':') {
            if (sawDoubleColon) {
                return false;
            }
            sawDoubleColon = true;
            inTail = true;
            ++pos;
            if (pos == text.size()) {
                break;  // 结尾 "::"
            }
        } else if (pos == text.size()) {
            return false;  // 结尾单个 ':'
        }
    }

    const std::size_t filled = head.size() + tail.size();
    if (sawDoubleColon) {
        if (filled >= 16U) {
            return false;  // "::" 至少要压掉一组
        }
    } else if (filled != 16U) {
        return false;
    }
    out.fill(0U);
    for (std::size_t i = 0; i < head.size(); ++i) {
        out[i] = head[i];
    }
    for (std::size_t i = 0; i < tail.size(); ++i) {
        out[16U - tail.size() + i] = tail[i];
    }
    return true;
}

std::string FormatHexGroup(std::uint32_t group) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    bool started = false;
    for (int shift = 12; shift >= 0; shift -= 4) {
        const std::uint32_t nibble = (group >> shift) & 0xFU;
        if (nibble != 0U || started || shift == 0) {
            text.push_back(kDigits[nibble]);
            started = true;
        }
    }
    return text;
}

} // namespace

bool ParseIpAddress(std::string_view text, WfpAddress& out) {
    if (text.empty()) {
        return false;
    }
    if (text.find(':') != std::string_view::npos) {
        std::array<std::uint8_t, 16> bytes{};
        if (!ParseIpv6Bytes(text, bytes)) {
            return false;
        }
        out = WfpAddress::ipv6FromBytes(bytes);
        return true;
    }
    std::array<std::uint8_t, 4> v4{};
    if (!ParseIpv4Bytes(text, v4)) {
        return false;
    }
    WfpAddress address;
    address.family = WfpAddressFamily::IPv4;
    address.bytes.fill(0U);
    for (std::size_t i = 0; i < 4U; ++i) {
        address.bytes[i] = v4[i];
    }
    out = address;
    return true;
}

std::string FormatIpAddress(const WfpAddress& address) {
    if (address.family == WfpAddressFamily::IPv4) {
        std::string text;
        for (std::size_t i = 0; i < 4U; ++i) {
            if (i > 0) {
                text.push_back('.');
            }
            text += FormatU64(address.bytes[i], U64Format::Decimal);
        }
        return text;
    }
    if (address.family != WfpAddressFamily::IPv6) {
        return std::string();
    }

    std::array<std::uint32_t, 8> groups{};
    for (std::size_t i = 0; i < 8U; ++i) {
        groups[i] = (static_cast<std::uint32_t>(address.bytes[i * 2U]) << 8) |
                    static_cast<std::uint32_t>(address.bytes[i * 2U + 1U]);
    }
    // RFC 5952：压缩最长的零段（长度 >= 2），并列时取最左。
    std::size_t bestStart = 8U;
    std::size_t bestLength = 0;
    std::size_t runStart = 8U;
    std::size_t runLength = 0;
    for (std::size_t i = 0; i < 8U; ++i) {
        if (groups[i] == 0U) {
            if (runLength == 0U) {
                runStart = i;
            }
            ++runLength;
            if (runLength > bestLength) {
                bestLength = runLength;
                bestStart = runStart;
            }
        } else {
            runLength = 0;
        }
    }
    if (bestLength < 2U) {
        bestStart = 8U;
        bestLength = 0;
    }

    std::string text;
    for (std::size_t i = 0; i < 8U;) {
        if (bestLength > 0U && i == bestStart) {
            text += "::";
            i += bestLength;
            continue;
        }
        if (!text.empty() && text.back() != ':') {
            text.push_back(':');
        }
        text += FormatHexGroup(groups[i]);
        ++i;
    }
    if (text.empty()) {
        text = "::";
    }
    return text;
}

bool Ipv4HostOrder(const WfpAddress& address, std::uint32_t& out) noexcept {
    if (address.family != WfpAddressFamily::IPv4) {
        return false;
    }
    out = (static_cast<std::uint32_t>(address.bytes[0]) << 24) |
          (static_cast<std::uint32_t>(address.bytes[1]) << 16) |
          (static_cast<std::uint32_t>(address.bytes[2]) << 8) |
          static_cast<std::uint32_t>(address.bytes[3]);
    return true;
}

bool MaskToPrefixLength(std::uint32_t mask, std::uint32_t& outPrefixLength) noexcept {
    const std::uint32_t inverted = ~mask;
    // 连续掩码的取反必然是 2^n - 1 形式；非连续掩码（例如 255.0.255.0）在这里被拒绝，
    // 调用方必须继续按"掩码"展示，不能改说成前缀长度（N-02）。
    if ((inverted & (inverted + 1U)) != 0U) {
        return false;
    }
    std::uint32_t bits = 0;
    std::uint32_t value = mask;
    while (value != 0U) {
        bits += (value & 1U);
        value >>= 1;
    }
    outPrefixLength = bits;
    return true;
}

const char* AddressContainmentName(AddressContainment containment) noexcept {
    switch (containment) {
    case AddressContainment::Inside:      return "Inside";
    case AddressContainment::Outside:     return "Outside";
    case AddressContainment::Undecidable: return "Undecidable";
    }
    return "Undecidable";
}

AddressContainment ClassifyV4Containment(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept {
    std::uint32_t addressValue = 0;
    std::uint32_t networkValue = 0;
    // 任一侧不是解出来的 IPv4 —— 包括"条件里带着 v4Present 但地址根本没解码"这种
    // 离线样本 —— 都不构成"不在子网内"的证据。
    if (!Ipv4HostOrder(address, addressValue) || !Ipv4HostOrder(subnet.address, networkValue)) {
        return AddressContainment::Undecidable;
    }
    return ((addressValue & subnet.mask) == (networkValue & subnet.mask)) ? AddressContainment::Inside
                                                                         : AddressContainment::Outside;
}

AddressContainment ClassifyV6Containment(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept {
    if (address.family != WfpAddressFamily::IPv6 || prefix.address.family != WfpAddressFamily::IPv6) {
        return AddressContainment::Undecidable;
    }
    if (!prefix.prefixLengthValid || prefix.prefixLength > 128U) {
        return AddressContainment::Undecidable;
    }
    const std::size_t fullBytes = prefix.prefixLength / 8U;
    const std::size_t remainingBits = prefix.prefixLength % 8U;
    for (std::size_t i = 0; i < fullBytes; ++i) {
        if (address.bytes[i] != prefix.address.bytes[i]) {
            return AddressContainment::Outside;
        }
    }
    if (remainingBits == 0U) {
        return AddressContainment::Inside;
    }
    const std::uint32_t mask = (0xFFU << (8U - remainingBits)) & 0xFFU;
    return ((static_cast<std::uint32_t>(address.bytes[fullBytes]) & mask) ==
            (static_cast<std::uint32_t>(prefix.address.bytes[fullBytes]) & mask))
               ? AddressContainment::Inside
               : AddressContainment::Outside;
}

bool AddressInV4Subnet(const WfpAddress& address, const WfpV4AddrMask& subnet) noexcept {
    return ClassifyV4Containment(address, subnet) == AddressContainment::Inside;
}

bool AddressInV6Prefix(const WfpAddress& address, const WfpV6AddrPrefix& prefix) noexcept {
    return ClassifyV6Containment(address, prefix) == AddressContainment::Inside;
}

// ---------------------------------------------------------------------------
// 枚举名与解码
// ---------------------------------------------------------------------------
const char* WfpDataTypeName(WfpDataType type) noexcept {
    switch (type) {
    case WfpDataType::Empty:       return "Empty";
    case WfpDataType::Uint8:       return "Uint8";
    case WfpDataType::Uint16:      return "Uint16";
    case WfpDataType::Uint32:      return "Uint32";
    case WfpDataType::Uint64:      return "Uint64";
    case WfpDataType::ByteArray16: return "ByteArray16";
    case WfpDataType::ByteBlob:    return "ByteBlob";
    case WfpDataType::Sid:         return "Sid";
    case WfpDataType::V4AddrMask:  return "V4AddrMask";
    case WfpDataType::V6AddrMask:  return "V6AddrMask";
    case WfpDataType::Range:       return "Range";
    case WfpDataType::Unknown:     return "Unknown";
    }
    return "Unknown";
}

WfpDataType DecodeDataType(std::uint32_t rawTypeCode) noexcept {
    // 数值来自 Windows SDK fwptypes.h 的 FWP_DATA_TYPE。
    switch (rawTypeCode) {
    case 0U:     return WfpDataType::Empty;
    case 1U:     return WfpDataType::Uint8;
    case 2U:     return WfpDataType::Uint16;
    case 3U:     return WfpDataType::Uint32;
    case 4U:     return WfpDataType::Uint64;
    case 11U:    return WfpDataType::ByteArray16;
    case 12U:    return WfpDataType::ByteBlob;
    case 13U:    return WfpDataType::Sid;
    case 0x100U: return WfpDataType::V4AddrMask;
    case 0x101U: return WfpDataType::V6AddrMask;
    case 0x102U: return WfpDataType::Range;
    default:     break;
    }
    return WfpDataType::Unknown;
}

const char* WfpMatchTypeName(WfpMatchType match) noexcept {
    switch (match) {
    case WfpMatchType::Equal:                return "Equal";
    case WfpMatchType::Greater:              return "Greater";
    case WfpMatchType::Less:                 return "Less";
    case WfpMatchType::GreaterOrEqual:       return "GreaterOrEqual";
    case WfpMatchType::LessOrEqual:          return "LessOrEqual";
    case WfpMatchType::Range:                return "Range";
    case WfpMatchType::FlagsAllSet:          return "FlagsAllSet";
    case WfpMatchType::FlagsAnySet:          return "FlagsAnySet";
    case WfpMatchType::FlagsNoneSet:         return "FlagsNoneSet";
    case WfpMatchType::EqualCaseInsensitive: return "EqualCaseInsensitive";
    case WfpMatchType::NotEqual:             return "NotEqual";
    case WfpMatchType::Prefix:               return "Prefix";
    case WfpMatchType::NotPrefix:            return "NotPrefix";
    case WfpMatchType::Unknown:              return "Unknown";
    }
    return "Unknown";
}

WfpMatchType DecodeMatchType(std::uint32_t rawMatchCode) noexcept {
    // 数值来自 FWP_MATCH_TYPE（0..12）。
    switch (rawMatchCode) {
    case 0U:  return WfpMatchType::Equal;
    case 1U:  return WfpMatchType::Greater;
    case 2U:  return WfpMatchType::Less;
    case 3U:  return WfpMatchType::GreaterOrEqual;
    case 4U:  return WfpMatchType::LessOrEqual;
    case 5U:  return WfpMatchType::Range;
    case 6U:  return WfpMatchType::FlagsAllSet;
    case 7U:  return WfpMatchType::FlagsAnySet;
    case 8U:  return WfpMatchType::FlagsNoneSet;
    case 9U:  return WfpMatchType::EqualCaseInsensitive;
    case 10U: return WfpMatchType::NotEqual;
    case 11U: return WfpMatchType::Prefix;
    case 12U: return WfpMatchType::NotPrefix;
    default:  break;
    }
    return WfpMatchType::Unknown;
}

const char* WfpDirectionName(WfpDirection direction) noexcept {
    switch (direction) {
    case WfpDirection::Unknown:  return "Unknown";
    case WfpDirection::Outbound: return "Outbound";
    case WfpDirection::Inbound:  return "Inbound";
    case WfpDirection::Forward:  return "Forward";
    }
    return "Unknown";
}

WfpDirection DecodeDirectionValue(std::uint64_t rawValue) noexcept {
    // FWP_DIRECTION_ 只定义 OUTBOUND=0 / INBOUND=1。2 是 FWP_DIRECTION_MAX，不是 FORWARD。
    switch (rawValue) {
    case 0U: return WfpDirection::Outbound;
    case 1U: return WfpDirection::Inbound;
    default: break;
    }
    return WfpDirection::Unknown;
}

const char* WfpActionTypeName(WfpActionType action) noexcept {
    switch (action) {
    case WfpActionType::Unknown:            return "Unknown";
    case WfpActionType::Block:              return "Block";
    case WfpActionType::Permit:             return "Permit";
    case WfpActionType::CalloutTerminating: return "CalloutTerminating";
    case WfpActionType::CalloutInspection:  return "CalloutInspection";
    case WfpActionType::CalloutUnknown:     return "CalloutUnknown";
    case WfpActionType::Continue:           return "Continue";
    case WfpActionType::None:               return "None";
    case WfpActionType::NoneNoMatch:        return "NoneNoMatch";
    }
    return "Unknown";
}

WfpActionType DecodeActionType(std::uint32_t rawActionCode) noexcept {
    // FWP_ACTION_* = 低位序号 | 标志位。标志位不同的同序号不是同一个动作，
    // 因此这里按完整常量比对，而不是只看低 8 位。
    constexpr std::uint32_t kFlagTerminating = 0x00001000U;
    constexpr std::uint32_t kFlagNonTerminating = 0x00002000U;
    constexpr std::uint32_t kFlagCallout = 0x00004000U;
    switch (rawActionCode) {
    case 0x00000001U | kFlagTerminating:                  return WfpActionType::Block;
    case 0x00000002U | kFlagTerminating:                  return WfpActionType::Permit;
    case 0x00000003U | kFlagCallout | kFlagTerminating:   return WfpActionType::CalloutTerminating;
    case 0x00000004U | kFlagCallout | kFlagNonTerminating: return WfpActionType::CalloutInspection;
    case 0x00000005U | kFlagCallout:                      return WfpActionType::CalloutUnknown;
    case 0x00000006U | kFlagNonTerminating:               return WfpActionType::Continue;
    case 0x00000007U:                                     return WfpActionType::None;
    case 0x00000008U:                                     return WfpActionType::NoneNoMatch;
    default: break;
    }
    return WfpActionType::Unknown;
}

bool ActionIsCallout(WfpActionType action) noexcept {
    switch (action) {
    case WfpActionType::CalloutTerminating:
    case WfpActionType::CalloutInspection:
    case WfpActionType::CalloutUnknown:
        return true;
    case WfpActionType::Unknown:
    case WfpActionType::Block:
    case WfpActionType::Permit:
    case WfpActionType::Continue:
    case WfpActionType::None:
    case WfpActionType::NoneNoMatch:
        return false;
    }
    return false;
}

const char* WfpFieldKindName(WfpFieldKind kind) noexcept {
    switch (kind) {
    case WfpFieldKind::Unknown:            return "Unknown";
    case WfpFieldKind::IpLocalAddress:     return "IpLocalAddress";
    case WfpFieldKind::IpRemoteAddress:    return "IpRemoteAddress";
    case WfpFieldKind::IpLocalPort:        return "IpLocalPort";
    case WfpFieldKind::IpRemotePort:       return "IpRemotePort";
    case WfpFieldKind::IpProtocol:         return "IpProtocol";
    case WfpFieldKind::Direction:          return "Direction";
    case WfpFieldKind::AleAppId:           return "AleAppId";
    case WfpFieldKind::AleUserId:          return "AleUserId";
    case WfpFieldKind::IpLocalAddressType: return "IpLocalAddressType";
    case WfpFieldKind::Flags:              return "Flags";
    }
    return "Unknown";
}

WfpFieldDescriptor LookupFieldByGuid(const WfpGuid& fieldKey) noexcept {
    WfpFieldDescriptor descriptor;
    if (!fieldKey.known()) {
        return descriptor;
    }
    for (const FieldTableEntry& entry : kFieldTable) {
        if (fieldKey.text == entry.guid) {
            descriptor.kind = entry.kind;
            descriptor.name = entry.name;
            return descriptor;
        }
    }
    return descriptor;
}

WfpGuid FieldGuidFor(WfpFieldKind kind) {
    for (const FieldTableEntry& entry : kFieldTable) {
        if (entry.kind == kind) {
            return GuidFromText(entry.guid);
        }
    }
    return WfpGuid{};
}

const char* WfpWeightKindName(WfpWeightKind kind) noexcept {
    switch (kind) {
    case WfpWeightKind::Unknown:  return "Unknown";
    case WfpWeightKind::Auto:     return "Auto";
    case WfpWeightKind::Explicit: return "Explicit";
    }
    return "Unknown";
}

const char* WfpPartitionName(WfpPartition partition) noexcept {
    switch (partition) {
    case WfpPartition::Providers: return "Providers";
    case WfpPartition::SubLayers: return "SubLayers";
    case WfpPartition::Layers:    return "Layers";
    case WfpPartition::Filters:   return "Filters";
    case WfpPartition::Callouts:  return "Callouts";
    }
    return "Providers";
}

const char* ReferenceStateName(ReferenceState state) noexcept {
    switch (state) {
    case ReferenceState::Resolved:            return "Resolved";
    case ReferenceState::UnknownObject:       return "UnknownObject";
    case ReferenceState::Ambiguous:           return "Ambiguous";
    case ReferenceState::NotSpecified:        return "NotSpecified";
    case ReferenceState::CatalogNotCollected: return "CatalogNotCollected";
    case ReferenceState::CatalogIncomplete:   return "CatalogIncomplete";
    }
    return "NotSpecified";
}

const char* ConditionMatchName(ConditionMatch match) noexcept {
    switch (match) {
    case ConditionMatch::Match:            return "Match";
    case ConditionMatch::NoMatch:          return "NoMatch";
    case ConditionMatch::InsufficientInfo: return "InsufficientInfo";
    }
    return "InsufficientInfo";
}

const char* WeightOrderConfidenceName(WeightOrderConfidence confidence) noexcept {
    switch (confidence) {
    case WeightOrderConfidence::Unknown:         return "Unknown";
    case WeightOrderConfidence::ExplicitWeight:  return "ExplicitWeight";
    case WeightOrderConfidence::EffectiveWeight: return "EffectiveWeight";
    }
    return "Unknown";
}

const char* CandidateDecisionName(CandidateDecision decision) noexcept {
    switch (decision) {
    case CandidateDecision::Unknown:          return "Unknown";
    case CandidateDecision::NoMatchingFilter: return "NoMatchingFilter";
    case CandidateDecision::BlockCandidate:   return "BlockCandidate";
    case CandidateDecision::PermitCandidate:  return "PermitCandidate";
    }
    return "Unknown";
}

const char* ObservationSourceName(ObservationSource source) noexcept {
    switch (source) {
    case ObservationSource::Unknown:              return "Unknown";
    case ObservationSource::WfpNetEventEnum:      return "WfpNetEventEnum";
    case ObservationSource::WfpNetEventSubscribe: return "WfpNetEventSubscribe";
    case ObservationSource::KernelAleCallout:     return "KernelAleCallout";
    case ObservationSource::EtwProvider:          return "EtwProvider";
    case ObservationSource::SecurityAuditLog:     return "SecurityAuditLog";
    case ObservationSource::OfflineImport:        return "OfflineImport";
    }
    return "Unknown";
}

const char* WfpEventVerdictName(WfpEventVerdict verdict) noexcept {
    switch (verdict) {
    case WfpEventVerdict::Unknown:   return "Unknown";
    case WfpEventVerdict::Permitted: return "Permitted";
    case WfpEventVerdict::Blocked:   return "Blocked";
    }
    return "Unknown";
}

const char* ObservationTrustName(ObservationTrust trust) noexcept {
    switch (trust) {
    case ObservationTrust::ActualObservation: return "ActualObservation";
    case ObservationTrust::SourceUnknown:     return "SourceUnknown";
    case ObservationTrust::SourceUnsupported: return "SourceUnsupported";
    case ObservationTrust::SourceNotEnabled:  return "SourceNotEnabled";
    }
    return "SourceUnknown";
}

const char* FilterLinkStateName(FilterLinkState state) noexcept {
    switch (state) {
    case FilterLinkState::LinkedByGuid:                    return "LinkedByGuid";
    case FilterLinkState::LinkedByRuntimeIdSameGeneration: return "LinkedByRuntimeIdSameGeneration";
    case FilterLinkState::RejectedIdReused:                return "RejectedIdReused";
    case FilterLinkState::RejectedStaleGeneration:         return "RejectedStaleGeneration";
    case FilterLinkState::RejectedAmbiguous:               return "RejectedAmbiguous";
    case FilterLinkState::NoMatch:                         return "NoMatch";
    case FilterLinkState::CatalogNotCollected:             return "CatalogNotCollected";
    case FilterLinkState::CatalogIncomplete:               return "CatalogIncomplete";
    case FilterLinkState::NotSpecified:                    return "NotSpecified";
    }
    return "NotSpecified";
}

const char* WfpNavigationRejectionName(WfpNavigationRejection rejection) noexcept {
    switch (rejection) {
    case WfpNavigationRejection::None:              return "None";
    case WfpNavigationRejection::TargetPageMissing: return "TargetPageMissing";
    case WfpNavigationRejection::ObjectNotPresent:  return "ObjectNotPresent";
    case WfpNavigationRejection::IdentityUnusable:  return "IdentityUnusable";
    case WfpNavigationRejection::EvidenceIdMissing: return "EvidenceIdMissing";
    case WfpNavigationRejection::EvidenceNotSaved:  return "EvidenceNotSaved";
    case WfpNavigationRejection::SourceNotTrusted:  return "SourceNotTrusted";
    }
    return "ObjectNotPresent";
}

const char* CatalogChangeKindName(CatalogChangeKind kind) noexcept {
    switch (kind) {
    case CatalogChangeKind::Added:             return "Added";
    case CatalogChangeKind::Removed:           return "Removed";
    case CatalogChangeKind::ActionChanged:     return "ActionChanged";
    case CatalogChangeKind::WeightChanged:     return "WeightChanged";
    case CatalogChangeKind::ConditionsChanged: return "ConditionsChanged";
    case CatalogChangeKind::RuntimeIdReused:   return "RuntimeIdReused";
    case CatalogChangeKind::PresenceUnknown:   return "PresenceUnknown";
    }
    return "PresenceUnknown";
}

const char* WfpOwnerAttributionName(WfpOwnerAttribution attribution) noexcept {
    switch (attribution) {
    case WfpOwnerAttribution::Unknown:        return "Unknown";
    case WfpOwnerAttribution::Candidate:      return "Candidate";
    case WfpOwnerAttribution::DirectEvidence: return "DirectEvidence";
    }
    return "Unknown";
}

// ---------------------------------------------------------------------------
// 条件
// ---------------------------------------------------------------------------
bool WfpCondition::interpreted() const noexcept {
    return field != WfpFieldKind::Unknown && match != WfpMatchType::Unknown &&
           value.type != WfpDataType::Unknown;
}

bool WfpCondition::evaluable() const noexcept {
    return interpreted() && FieldIsModeled(field);
}

WfpCondition MakeCondition(const WfpGuid& fieldKey, std::uint32_t rawMatchCode, WfpConditionValue value) {
    WfpCondition condition;
    condition.fieldKey = fieldKey;
    const WfpFieldDescriptor descriptor = LookupFieldByGuid(fieldKey);
    condition.field = descriptor.kind;
    condition.fieldName = descriptor.name;
    condition.rawMatchCode = rawMatchCode;
    condition.match = DecodeMatchType(rawMatchCode);
    condition.value = std::move(value);
    return condition;
}

// ---------------------------------------------------------------------------
// N-05 归因
// ---------------------------------------------------------------------------
OwnerAttributionResult DeriveOwnerAttribution(const OwnerEvidence& evidence) {
    OwnerAttributionResult result;

    // 签名信息只有真的读到才出现。没读到就是没读到，不因为"名字像微软"而补一个证书。
    result.signerCertificateAvailable = evidence.signerCertificateRead && evidence.signerSubject.present;
    if (result.signerCertificateAvailable) {
        result.signerSubject = evidence.signerSubject;
    }

    if (evidence.serviceName.present) {
        result.serviceName = evidence.serviceName;
    }
    if (evidence.displayNameAmbiguous) {
        AddKey(result.limitationKeys, "wfp.owner.ambiguous-display-name");
    }

    const bool hasModuleAddress = evidence.moduleAddress.present;
    const bool hasDirectModule =
        hasModuleAddress && evidence.moduleResolved && evidence.resolvedModulePath.present;

    if (hasDirectModule) {
        // 直接证据：地址落在某个已加载映像范围内，能指名文件。
        result.attribution = WfpOwnerAttribution::DirectEvidence;
        result.ownerModulePath = evidence.resolvedModulePath;
        return result;
    }

    if (hasModuleAddress) {
        // 有地址但没有映像覆盖它 —— 典型是模块已卸载。地址本身留着，但不敢指名文件。
        AddKey(result.limitationKeys, "wfp.owner.module-unresolved");
    }

    if (evidence.serviceRecordFound && evidence.serviceImagePath.present) {
        // 服务配置说的是"这个服务应该加载谁"，不是"这段代码就是它"。只能是候选。
        result.attribution = WfpOwnerAttribution::Candidate;
        result.candidateModulePath = evidence.serviceImagePath;
        return result;
    }

    if (evidence.serviceName.present && !evidence.serviceRecordFound) {
        AddKey(result.limitationKeys, "wfp.owner.service-not-found");
        result.attribution = WfpOwnerAttribution::Unknown;
        return result;
    }

    if (evidence.displayName.present) {
        // 只有显示名。N-05 明确禁止凭名称猜驱动文件。
        AddKey(result.limitationKeys, "wfp.owner.name-only");
        result.attribution = WfpOwnerAttribution::Unknown;
        return result;
    }

    if (!hasModuleAddress) {
        AddKey(result.limitationKeys, "wfp.owner.no-evidence");
    }
    result.attribution = WfpOwnerAttribution::Unknown;
    return result;
}

// ---------------------------------------------------------------------------
// 目录
// ---------------------------------------------------------------------------
void WfpCatalog::setPartitionState(WfpPartition partition, CollectionOutcome outcome, CoverageAccount coverage) {
    WfpPartitionState& state = partitions_[static_cast<std::size_t>(partition)];
    state.outcome = std::move(outcome);
    state.coverage = std::move(coverage);
}

const WfpPartitionState& WfpCatalog::partitionState(WfpPartition partition) const noexcept {
    return partitions_[static_cast<std::size_t>(partition)];
}

bool WfpCatalog::partitionUsableForAbsence(WfpPartition partition) const noexcept {
    const WfpPartitionState& state = partitionState(partition);
    if (state.outcome.status != CollectionStatus::Success) {
        return false;
    }
    // F-06：完整覆盖需要正面证据。账目一字未填 = 未知覆盖 ≠ 完整枚举。
    return state.coverage.fullyCovered();
}

bool WfpCatalog::registerKey(Index& index, const WfpGuid& key, std::size_t position) {
    if (!key.known()) {
        return true;  // 没有 GUID 的行进不了索引；它只能靠运行时 id 或根本不可关联。
    }
    const auto inserted = index.byGuid.emplace(key.text, position);
    if (!inserted.second) {
        index.duplicated[key.text] = true;
        return false;
    }
    return true;
}

WfpCatalog::IndexHit WfpCatalog::lookup(const Index& index,
                                        const WfpGuid& key,
                                        WfpPartition partition) const {
    IndexHit hit;
    if (!key.known()) {
        hit.state = ReferenceState::NotSpecified;
        return hit;
    }
    if (index.duplicated.find(key.text) != index.duplicated.end()) {
        hit.state = ReferenceState::Ambiguous;
        return hit;
    }
    const auto it = index.byGuid.find(key.text);
    if (it != index.byGuid.end()) {
        hit.state = ReferenceState::Resolved;
        hit.hasPosition = true;
        hit.position = it->second;
        return hit;
    }
    // N-06：只有能**正面证明枚举完整**的分区，"目录里没有"才等于"这个对象不存在"。
    // 判据必须与 AnalyzeStaticCandidates / DiffCatalogs 一致地走 partitionUsableForAbsence：
    // StatusCarriesObservation 对 Partial 返回 true，用它会把只枚举到 1/9 的分区
    // 当成"目录可用"，从而对一个 GUID 宣称"未知对象"（语义是目录里确实没有）。
    if (partitionUsableForAbsence(partition)) {
        hit.state = ReferenceState::UnknownObject;
        return hit;
    }
    hit.state = StatusCarriesObservation(partitionState(partition).outcome.status)
                    ? ReferenceState::CatalogIncomplete
                    : ReferenceState::CatalogNotCollected;
    return hit;
}

bool WfpCatalog::addProvider(WfpProvider provider) {
    const std::size_t position = providers_.size();
    const bool unique = registerKey(providerIndex_, provider.providerKey, position);
    providers_.push_back(std::move(provider));
    return unique;
}

bool WfpCatalog::addSubLayer(WfpSubLayer subLayer) {
    const std::size_t position = subLayers_.size();
    const bool unique = registerKey(subLayerIndex_, subLayer.subLayerKey, position);
    subLayers_.push_back(std::move(subLayer));
    return unique;
}

bool WfpCatalog::addLayer(WfpLayer layer) {
    const std::size_t position = layers_.size();
    const bool unique = registerKey(layerIndex_, layer.layerKey, position);
    layers_.push_back(std::move(layer));
    return unique;
}

bool WfpCatalog::addCallout(WfpCallout callout) {
    const std::size_t position = callouts_.size();
    const bool unique = registerKey(calloutIndex_, callout.calloutKey, position);
    callouts_.push_back(std::move(callout));
    return unique;
}

bool WfpCatalog::addFilter(WfpFilter filter) {
    const std::size_t position = filters_.size();
    const bool unique = registerKey(filterIndex_, filter.filterKey, position);
    filters_.push_back(std::move(filter));
    return unique;
}

ObjectReference WfpCatalog::resolveProvider(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit hit = lookup(providerIndex_, key, WfpPartition::Providers);
    reference.state = hit.state;
    if (hit.hasPosition) {
        reference.resolvedName = providers_[hit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveSubLayer(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit hit = lookup(subLayerIndex_, key, WfpPartition::SubLayers);
    reference.state = hit.state;
    if (hit.hasPosition) {
        reference.resolvedName = subLayers_[hit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveLayer(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit hit = lookup(layerIndex_, key, WfpPartition::Layers);
    reference.state = hit.state;
    if (hit.hasPosition) {
        reference.resolvedName = layers_[hit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveCallout(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit hit = lookup(calloutIndex_, key, WfpPartition::Callouts);
    reference.state = hit.state;
    if (hit.hasPosition) {
        reference.resolvedName = callouts_[hit.position].displayName;
    }
    return reference;
}

ObjectReference WfpCatalog::resolveFilter(const WfpGuid& key) const {
    ObjectReference reference;
    reference.key = key;
    const IndexHit hit = lookup(filterIndex_, key, WfpPartition::Filters);
    reference.state = hit.state;
    if (hit.hasPosition) {
        reference.resolvedName = filters_[hit.position].displayName;
    }
    return reference;
}

std::vector<WfpGuid> WfpCatalog::findProvidersByDisplayName(std::string_view name) const {
    std::vector<WfpGuid> matches;
    for (const WfpProvider& provider : providers_) {
        if (provider.displayName.present && EqualsIgnoreCase(provider.displayName.value, name)) {
            matches.push_back(provider.providerKey);
        }
    }
    return matches;
}

std::vector<WfpGuid> WfpCatalog::findCalloutsByDisplayName(std::string_view name) const {
    std::vector<WfpGuid> matches;
    for (const WfpCallout& callout : callouts_) {
        if (callout.displayName.present && EqualsIgnoreCase(callout.displayName.value, name)) {
            matches.push_back(callout.calloutKey);
        }
    }
    return matches;
}

std::vector<std::size_t> WfpCatalog::findFilterIndexesByRuntimeId(const OptionalU64& filterId) const {
    std::vector<std::size_t> matches;
    if (!filterId.present) {
        return matches;
    }
    for (std::size_t i = 0; i < filters_.size(); ++i) {
        if (filters_[i].filterId.present && filters_[i].filterId.value == filterId.value) {
            matches.push_back(i);
        }
    }
    return matches;
}

OwnerEvidence WfpCatalog::providerOwnerEvidence(std::size_t providerIndex) const {
    if (providerIndex >= providers_.size()) {
        return OwnerEvidence{};
    }
    OwnerEvidence evidence = providers_[providerIndex].owner;
    if (evidence.displayName.present) {
        evidence.displayNameAmbiguous = findProvidersByDisplayName(evidence.displayName.value).size() > 1U;
    }
    return evidence;
}

OwnerEvidence WfpCatalog::calloutOwnerEvidence(std::size_t calloutIndex) const {
    if (calloutIndex >= callouts_.size()) {
        return OwnerEvidence{};
    }
    OwnerEvidence evidence = callouts_[calloutIndex].owner;
    if (evidence.displayName.present) {
        evidence.displayNameAmbiguous = findCalloutsByDisplayName(evidence.displayName.value).size() > 1U;
    }
    return evidence;
}

// ---------------------------------------------------------------------------
// N-02 / N-03：单条条件求值
// ---------------------------------------------------------------------------
namespace {

ConditionMatch CompareNumeric(WfpMatchType match,
                              std::uint64_t actual,
                              const WfpConditionValue& value,
                              std::vector<std::string>& keys) {
    if (match == WfpMatchType::Range) {
        if (value.type != WfpDataType::Range) {
            AddKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::InsufficientInfo;
        }
        if (!value.range.numeric) {
            // 端点不是数值（原文保留在 rawLow/rawHigh）—— 无从比较，不猜。
            AddKey(keys, "wfp.condition.range-not-numeric");
            return ConditionMatch::InsufficientInfo;
        }
        if (!value.range.low.present || !value.range.high.present) {
            // "缺端点"与"类型错配"是两回事，混用一个键会让 UI 说不清到底缺了什么。
            AddKey(keys, "wfp.condition.range-endpoint-missing");
            return ConditionMatch::InsufficientInfo;
        }
        if (value.range.low.value > value.range.high.value) {
            // low > high 是非法/读坏的 FWP_RANGE0。`actual >= low && actual <= high`
            // 对任何 actual 都恒为 false，会变成一条"确定的不匹配"，让该 filter 在
            // DecideWithinSubLayer 里被直接跳过，把仲裁结论让给权重更低的规则。
            AddKey(keys, "wfp.condition.invalid-range");
            return ConditionMatch::InsufficientInfo;
        }
        return FromBool(actual >= value.range.low.value && actual <= value.range.high.value);
    }
    if (!DataTypeIsNumeric(value.type) || !value.numeric.present) {
        AddKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::InsufficientInfo;
    }
    const std::uint64_t expected = value.numeric.value;
    switch (match) {
    case WfpMatchType::Equal:
        return FromBool(actual == expected);
    case WfpMatchType::NotEqual:
        return FromBool(actual != expected);
    case WfpMatchType::Greater:
        return FromBool(actual > expected);
    case WfpMatchType::Less:
        return FromBool(actual < expected);
    case WfpMatchType::GreaterOrEqual:
        return FromBool(actual >= expected);
    case WfpMatchType::LessOrEqual:
        return FromBool(actual <= expected);
    case WfpMatchType::EqualCaseInsensitive:
    case WfpMatchType::FlagsAllSet:
    case WfpMatchType::FlagsAnySet:
    case WfpMatchType::FlagsNoneSet:
    case WfpMatchType::Prefix:
    case WfpMatchType::NotPrefix:
        // 端口/协议这类标量上的位标志与前缀比较本层不建模，绝不猜。
        AddKey(keys, "wfp.condition.match-not-modeled");
        return ConditionMatch::InsufficientInfo;
    case WfpMatchType::Range:
    case WfpMatchType::Unknown:
        break;
    }
    AddKey(keys, "wfp.condition.unknown-match");
    return ConditionMatch::InsufficientInfo;
}

bool MatchIsNegated(WfpMatchType match) noexcept {
    return match == WfpMatchType::NotEqual || match == WfpMatchType::NotPrefix;
}

ConditionMatch CompareAddress(WfpMatchType match,
                              const WfpAddress& actual,
                              const WfpConditionValue& value,
                              std::vector<std::string>& keys) {
    const bool negated = MatchIsNegated(match);
    if (match != WfpMatchType::Equal && !negated) {
        if (match == WfpMatchType::Range) {
            AddKey(keys, "wfp.condition.address-range-not-modeled");
        } else {
            AddKey(keys, "wfp.condition.match-not-modeled");
        }
        return ConditionMatch::InsufficientInfo;
    }

    WfpAddressFamily conditionFamily = WfpAddressFamily::Unknown;
    switch (value.type) {
    case WfpDataType::V4AddrMask:
    case WfpDataType::Uint32:
        conditionFamily = WfpAddressFamily::IPv4;
        break;
    case WfpDataType::V6AddrMask:
    case WfpDataType::ByteArray16:
        conditionFamily = WfpAddressFamily::IPv6;
        break;
    case WfpDataType::Empty:
    case WfpDataType::Uint8:
    case WfpDataType::Uint16:
    case WfpDataType::Uint64:
    case WfpDataType::ByteBlob:
    case WfpDataType::Sid:
    case WfpDataType::Range:
    case WfpDataType::Unknown:
        AddKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::InsufficientInfo;
    }

    // N-02：先确认条件值里的网络地址**真的解出来了**，再谈比较。
    // WfpConditionValue.v4/v6 的 address 默认 family==Unknown，而 ParseIpAddress 失败时
    // 按设计不修改 out —— 离线样本里一条地址文本解析失败就会留下 v4Present=true 加一个
    // 未知族的地址。放过去的话包含判定会返回一个"确定的 false"，再被 NOT_EQUAL 取反成
    // Match：等于从一个根本没读出来的地址推出了"阻断候选"。
    switch (value.type) {
    case WfpDataType::V4AddrMask:
        if (!value.v4Present) {
            AddKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::InsufficientInfo;
        }
        if (!value.v4.address.known()) {
            AddKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::InsufficientInfo;
        }
        break;
    case WfpDataType::V6AddrMask:
        if (!value.v6Present) {
            AddKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::InsufficientInfo;
        }
        if (!value.v6.address.known()) {
            AddKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::InsufficientInfo;
        }
        if (!value.v6.prefixLengthValid) {
            AddKey(keys, "wfp.condition.invalid-prefix-length");
            return ConditionMatch::InsufficientInfo;
        }
        break;
    case WfpDataType::ByteArray16:
        if (!value.singleAddress.known()) {
            AddKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::InsufficientInfo;
        }
        break;
    case WfpDataType::Uint32:
        if (!value.numeric.present) {
            AddKey(keys, "wfp.condition.value-type-mismatch");
            return ConditionMatch::InsufficientInfo;
        }
        break;
    case WfpDataType::Empty:
    case WfpDataType::Uint8:
    case WfpDataType::Uint16:
    case WfpDataType::Uint64:
    case WfpDataType::ByteBlob:
    case WfpDataType::Sid:
    case WfpDataType::Range:
    case WfpDataType::Unknown:
        AddKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::InsufficientInfo;
    }

    if (conditionFamily != actual.family) {
        // 正向比较：v4 子网装不下一个 v6 地址，判 NoMatch 是有依据的。
        // 否定比较：跨地址族的"不等于"本层不做真值断言，保持未知。
        if (negated) {
            AddKey(keys, "wfp.condition.address-family-mismatch");
            return ConditionMatch::InsufficientInfo;
        }
        AddKey(keys, "wfp.condition.address-family-mismatch");
        return ConditionMatch::NoMatch;
    }

    ConditionMatch positive = ConditionMatch::InsufficientInfo;
    switch (value.type) {
    case WfpDataType::V4AddrMask: {
        // 三态：Undecidable 绝不能塌成 NoMatch —— NegateMatch 会把它翻成 Match。
        const AddressContainment containment = ClassifyV4Containment(actual, value.v4);
        if (containment == AddressContainment::Undecidable) {
            AddKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::InsufficientInfo;
        }
        positive = FromBool(containment == AddressContainment::Inside);
        break;
    }
    case WfpDataType::Uint32: {
        const WfpAddress expected =
            WfpAddress::ipv4FromHostOrder(static_cast<std::uint32_t>(value.numeric.value & 0xFFFFFFFFULL));
        positive = FromBool(actual == expected);
        break;
    }
    case WfpDataType::V6AddrMask: {
        const AddressContainment containment = ClassifyV6Containment(actual, value.v6);
        if (containment == AddressContainment::Undecidable) {
            AddKey(keys, "wfp.condition.address-not-decoded");
            return ConditionMatch::InsufficientInfo;
        }
        positive = FromBool(containment == AddressContainment::Inside);
        break;
    }
    case WfpDataType::ByteArray16:
        positive = FromBool(actual == value.singleAddress);
        break;
    case WfpDataType::Empty:
    case WfpDataType::Uint8:
    case WfpDataType::Uint16:
    case WfpDataType::Uint64:
    case WfpDataType::ByteBlob:
    case WfpDataType::Sid:
    case WfpDataType::Range:
    case WfpDataType::Unknown:
        AddKey(keys, "wfp.condition.value-type-mismatch");
        return ConditionMatch::InsufficientInfo;
    }
    return negated ? NegateMatch(positive) : positive;
}

ConditionMatch CompareText(WfpMatchType match,
                           std::string_view actual,
                           std::string_view expected,
                           std::vector<std::string>& keys) {
    switch (match) {
    case WfpMatchType::Equal:
    case WfpMatchType::EqualCaseInsensitive:
        // AppId / SID 在 WFP 里就是大小写不敏感比较。
        return FromBool(EqualsIgnoreCase(actual, expected));
    case WfpMatchType::NotEqual:
        return FromBool(!EqualsIgnoreCase(actual, expected));
    case WfpMatchType::Prefix:
        return FromBool(StartsWithIgnoreCase(actual, expected));
    case WfpMatchType::NotPrefix:
        return FromBool(!StartsWithIgnoreCase(actual, expected));
    case WfpMatchType::Greater:
    case WfpMatchType::Less:
    case WfpMatchType::GreaterOrEqual:
    case WfpMatchType::LessOrEqual:
    case WfpMatchType::Range:
    case WfpMatchType::FlagsAllSet:
    case WfpMatchType::FlagsAnySet:
    case WfpMatchType::FlagsNoneSet:
        AddKey(keys, "wfp.condition.match-not-modeled");
        return ConditionMatch::InsufficientInfo;
    case WfpMatchType::Unknown:
        break;
    }
    AddKey(keys, "wfp.condition.unknown-match");
    return ConditionMatch::InsufficientInfo;
}

} // namespace

ConditionEvaluation EvaluateCondition(const WfpCondition& condition, const ConnectionDescription& connection) {
    ConditionEvaluation evaluation;
    evaluation.condition = condition;
    evaluation.result = ConditionMatch::InsufficientInfo;

    // N-02 核心陷阱：没读懂的条件不是"无条件匹配"，而是"信息不足"。
    if (condition.field == WfpFieldKind::Unknown) {
        AddKey(evaluation.limitationKeys, "wfp.condition.unknown-field");
    }
    if (condition.match == WfpMatchType::Unknown) {
        AddKey(evaluation.limitationKeys, "wfp.condition.unknown-match");
    }
    if (condition.value.type == WfpDataType::Unknown) {
        AddKey(evaluation.limitationKeys, "wfp.condition.unknown-value-type");
    }
    if (!condition.interpreted()) {
        return evaluation;
    }
    if (!FieldIsModeled(condition.field)) {
        AddKey(evaluation.limitationKeys, "wfp.condition.field-not-modeled");
        return evaluation;
    }

    switch (condition.field) {
    case WfpFieldKind::IpLocalPort:
    case WfpFieldKind::IpRemotePort:
    case WfpFieldKind::IpProtocol: {
        const OptionalU64& actual = (condition.field == WfpFieldKind::IpLocalPort)
                                        ? connection.localPort
                                        : (condition.field == WfpFieldKind::IpRemotePort
                                               ? connection.remotePort
                                               : connection.protocol);
        if (!actual.present) {
            AddKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        evaluation.result = CompareNumeric(condition.match, actual.value, condition.value,
                                           evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::IpLocalAddress:
    case WfpFieldKind::IpRemoteAddress: {
        const WfpAddress& actual = (condition.field == WfpFieldKind::IpLocalAddress)
                                       ? connection.localAddress
                                       : connection.remoteAddress;
        if (!actual.known()) {
            AddKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        evaluation.result = CompareAddress(condition.match, actual, condition.value,
                                           evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::Direction: {
        if (connection.direction == WfpDirection::Unknown) {
            AddKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        if (!DataTypeIsNumeric(condition.value.type) || !condition.value.numeric.present) {
            AddKey(evaluation.limitationKeys, "wfp.condition.value-type-mismatch");
            return evaluation;
        }
        const WfpDirection expected = DecodeDirectionValue(condition.value.numeric.value);
        if (expected == WfpDirection::Unknown) {
            // 数值不在 FWP_DIRECTION_ 定义里 —— 原值已保留在 value.numeric，不猜语义。
            AddKey(evaluation.limitationKeys, "wfp.condition.unknown-direction-value");
            return evaluation;
        }
        if (connection.direction == WfpDirection::Forward) {
            // 转发流量不在 FWP_DIRECTION_ 的 in/out 二分里，不做真值断言。
            AddKey(evaluation.limitationKeys, "wfp.condition.direction-not-comparable");
            return evaluation;
        }
        if (condition.match == WfpMatchType::Equal) {
            evaluation.result = FromBool(connection.direction == expected);
        } else if (condition.match == WfpMatchType::NotEqual) {
            evaluation.result = FromBool(connection.direction != expected);
        } else {
            AddKey(evaluation.limitationKeys, "wfp.condition.match-not-modeled");
        }
        return evaluation;
    }
    case WfpFieldKind::AleAppId: {
        if (!connection.appId.present) {
            AddKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        if (condition.value.type != WfpDataType::ByteBlob) {
            AddKey(evaluation.limitationKeys, "wfp.condition.value-type-mismatch");
            return evaluation;
        }
        if (!condition.value.blobText.present) {
            // 字节还在（blobBytes），只是解不成路径文本 —— 不能当成"匹配任何程序"。
            AddKey(evaluation.limitationKeys, "wfp.condition.blob-not-decoded");
            return evaluation;
        }
        evaluation.result = CompareText(condition.match, connection.appId.value,
                                        condition.value.blobText.value, evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::AleUserId: {
        if (!connection.userSid.present) {
            AddKey(evaluation.limitationKeys, "wfp.condition.attribute-unknown");
            return evaluation;
        }
        if (condition.value.type != WfpDataType::Sid || !condition.value.sidText.present) {
            AddKey(evaluation.limitationKeys, "wfp.condition.value-type-mismatch");
            return evaluation;
        }
        evaluation.result = CompareText(condition.match, connection.userSid.value,
                                        condition.value.sidText.value, evaluation.limitationKeys);
        return evaluation;
    }
    case WfpFieldKind::IpLocalAddressType:
    case WfpFieldKind::Flags:
    case WfpFieldKind::Unknown:
        break;
    }
    AddKey(evaluation.limitationKeys, "wfp.condition.field-not-modeled");
    return evaluation;
}

ConditionMatch CombineConditionResults(const std::vector<ConditionEvaluation>& evaluations,
                                       bool conditionsTruncated) {
    // FWP 真实语义：同一字段的多条条件是 OR，不同字段之间是 AND。
    std::map<std::string, ConditionMatch> groups;
    for (std::size_t i = 0; i < evaluations.size(); ++i) {
        const ConditionEvaluation& evaluation = evaluations[i];
        std::string key;
        if (evaluation.condition.fieldKey.known()) {
            key = evaluation.condition.fieldKey.text;
        } else {
            // 没有字段 GUID 的条件不知道属于哪个字段，绝不能和别的未知条件 OR 到一起
            // （OR 会让一条"匹配"掩盖另一条"不匹配"）。这里给它一个独占分组，走 AND。
            key = "#unkeyed-" + FormatU64(i, U64Format::Decimal);
        }
        const auto existing = groups.find(key);
        if (existing == groups.end()) {
            groups.emplace(std::move(key), evaluation.result);
        } else {
            existing->second = OrMatch(existing->second, evaluation.result);
        }
    }

    ConditionMatch combined = ConditionMatch::Match;  // 空条件集 = 真正的"无条件匹配"
    for (const auto& entry : groups) {
        combined = AndMatch(combined, entry.second);
    }
    if (conditionsTruncated) {
        // 被截断掉的条件内容未知，等价于再 AND 一条未知条件。
        combined = AndMatch(combined, ConditionMatch::InsufficientInfo);
    }
    return combined;
}

// ---------------------------------------------------------------------------
// N-03：候选分析
// ---------------------------------------------------------------------------
FilterCandidate EvaluateFilter(const WfpCatalog& catalog,
                               const WfpFilter& filter,
                               const ConnectionDescription& connection) {
    FilterCandidate candidate;
    candidate.filterKey = filter.filterKey;
    candidate.filterId = filter.filterId;
    candidate.displayName = filter.displayName;
    candidate.provider = catalog.resolveProvider(filter.providerKey);
    candidate.layer = catalog.resolveLayer(filter.layerKey);
    candidate.subLayer = catalog.resolveSubLayer(filter.subLayerKey);
    candidate.action = filter.action;
    candidate.dynamicByCallout = ActionIsCallout(filter.action);
    if (candidate.dynamicByCallout) {
        candidate.actionCallout = catalog.resolveCallout(filter.actionCalloutKey);
    }

    // effectiveWeight 与调用方指定的 weight 是两个量纲，优先用 BFE 算出来的那个。
    if (filter.effectiveWeight.present) {
        candidate.weightConfidence = WeightOrderConfidence::EffectiveWeight;
        candidate.orderingWeight = filter.effectiveWeight;
    } else if (filter.weightKind == WfpWeightKind::Explicit && filter.weight.present) {
        candidate.weightConfidence = WeightOrderConfidence::ExplicitWeight;
        candidate.orderingWeight = filter.weight;
    } else {
        candidate.weightConfidence = WeightOrderConfidence::Unknown;
        AddKey(candidate.limitationKeys, "wfp.filter.weight-unknown");
    }

    candidate.conditions.reserve(filter.conditions.size());
    for (const WfpCondition& condition : filter.conditions) {
        ConditionEvaluation evaluation = EvaluateCondition(condition, connection);
        MergeKeys(candidate.limitationKeys, evaluation.limitationKeys);
        candidate.conditions.push_back(std::move(evaluation));
    }
    candidate.match = CombineConditionResults(candidate.conditions, filter.conditionsTruncated);

    if (filter.conditionsTruncated) {
        AddKey(candidate.limitationKeys, "wfp.filter.conditions-truncated");
    }
    if (filter.action == WfpActionType::Unknown) {
        AddKey(candidate.limitationKeys, "wfp.filter.action-unknown");
    }
    if (candidate.dynamicByCallout) {
        AddKey(candidate.limitationKeys, "wfp.filter.dynamic-callout");
    }
    if (candidate.layer.state == ReferenceState::NotSpecified) {
        AddKey(candidate.limitationKeys, "wfp.filter.layer-missing");
    }
    if (candidate.subLayer.state == ReferenceState::NotSpecified) {
        AddKey(candidate.limitationKeys, "wfp.filter.sublayer-missing");
    }
    return candidate;
}

namespace {

// 单个 sublayer 内的仲裁。返回值一律保守：只要顺序不可信或有读不懂的条件就是 Unknown。
CandidateDecision DecideWithinSubLayer(const std::vector<FilterCandidate>& ordered,
                                       bool orderingReliable) {
    if (orderingReliable) {
        for (const FilterCandidate& candidate : ordered) {
            if (candidate.match == ConditionMatch::InsufficientInfo) {
                // 它可能就是赢家，也可能不是 —— 不猜。
                return CandidateDecision::Unknown;
            }
            if (candidate.match == ConditionMatch::NoMatch) {
                continue;
            }
            if (candidate.dynamicByCallout) {
                return CandidateDecision::Unknown;
            }
            switch (candidate.action) {
            case WfpActionType::Block:
                return CandidateDecision::BlockCandidate;
            case WfpActionType::Permit:
                return CandidateDecision::PermitCandidate;
            case WfpActionType::Continue:
                continue;  // FWP_ACTION_CONTINUE 的语义就是继续往下走
            case WfpActionType::Unknown:
            case WfpActionType::None:
            case WfpActionType::NoneNoMatch:
            case WfpActionType::CalloutTerminating:
            case WfpActionType::CalloutInspection:
            case WfpActionType::CalloutUnknown:
                return CandidateDecision::Unknown;
            }
            return CandidateDecision::Unknown;
        }
        return CandidateDecision::NoMatchingFilter;
    }

    // 顺序不可信：只有"候选唯一"时结论才与顺序无关。
    std::size_t candidateCount = 0;
    const FilterCandidate* single = nullptr;
    for (const FilterCandidate& candidate : ordered) {
        if (candidate.match == ConditionMatch::NoMatch) {
            continue;
        }
        ++candidateCount;
        single = &candidate;
    }
    if (candidateCount == 0U) {
        return CandidateDecision::NoMatchingFilter;
    }
    if (candidateCount > 1U || single == nullptr) {
        return CandidateDecision::Unknown;
    }
    if (single->match == ConditionMatch::InsufficientInfo || single->dynamicByCallout) {
        return CandidateDecision::Unknown;
    }
    switch (single->action) {
    case WfpActionType::Block:
        return CandidateDecision::BlockCandidate;
    case WfpActionType::Permit:
        return CandidateDecision::PermitCandidate;
    case WfpActionType::Continue:
        return CandidateDecision::NoMatchingFilter;  // 唯一候选让路，后面没有别的了
    case WfpActionType::Unknown:
    case WfpActionType::None:
    case WfpActionType::NoneNoMatch:
    case WfpActionType::CalloutTerminating:
    case WfpActionType::CalloutInspection:
    case WfpActionType::CalloutUnknown:
        break;
    }
    return CandidateDecision::Unknown;
}

// 跨 sublayer / 跨 layer 的保守汇总。
// 真实 WFP 里 block 会盖过 permit，但那要求每个 sublayer 都已判明；再加上本层没有建模
// FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT 这种否决权和层默认动作，所以只要有一个不确定，
// 整体就保持 Unknown（N-03 明确要求存在动态行为时保留未知）。
CandidateDecision CombineDecisions(const std::vector<CandidateDecision>& decisions) {
    bool sawBlock = false;
    bool sawPermit = false;
    for (CandidateDecision decision : decisions) {
        switch (decision) {
        case CandidateDecision::Unknown:
            return CandidateDecision::Unknown;
        case CandidateDecision::BlockCandidate:
            sawBlock = true;
            break;
        case CandidateDecision::PermitCandidate:
            sawPermit = true;
            break;
        case CandidateDecision::NoMatchingFilter:
            break;
        }
    }
    if (sawBlock) {
        return CandidateDecision::BlockCandidate;
    }
    if (sawPermit) {
        return CandidateDecision::PermitCandidate;
    }
    return CandidateDecision::NoMatchingFilter;
}

// N-01：layer / sublayer 引用未采集的 filter 用这些前缀单独开桶。真实 GUID 一律是
// "{...}" 形式，'#' 开头的键不可能与之相撞（与 CombineConditionResults 对无 GUID 条件
// 的 "#unkeyed-" 处理同一套做法）。
constexpr const char* kUnlinkedLayerPrefix = "#unlinked-layer-";
constexpr const char* kUnlinkedSubLayerPrefix = "#unlinked-sublayer-";

bool IsUnlinkedBucketKey(const std::string& key) noexcept {
    return key.rfind("#unlinked-", 0U) == 0U;
}

bool OrderingIsReliable(const std::vector<FilterCandidate>& filters, bool& mixedScale) {
    mixedScale = false;
    if (filters.empty()) {
        return false;
    }
    const WeightOrderConfidence first = filters.front().weightConfidence;
    std::vector<std::uint64_t> seen;
    for (const FilterCandidate& candidate : filters) {
        if (candidate.weightConfidence == WeightOrderConfidence::Unknown ||
            !candidate.orderingWeight.present) {
            return false;
        }
        if (candidate.weightConfidence != first) {
            mixedScale = true;
            return false;
        }
        for (std::uint64_t value : seen) {
            if (value == candidate.orderingWeight.value) {
                return false;  // 同权重无法确定先后
            }
        }
        seen.push_back(candidate.orderingWeight.value);
    }
    return true;
}

} // namespace

StaticCandidateReport AnalyzeStaticCandidates(const WfpCatalog& catalog,
                                              const ConnectionDescription& connection) {
    StaticCandidateReport report;
    // 这两条永远成立：本层不模拟层默认动作，也不解释 filter flags（含否决权）。
    AddKey(report.limitationKeys, "wfp.candidate.layer-default-action-not-modeled");
    AddKey(report.limitationKeys, "wfp.candidate.filter-flags-not-modeled");
    // N-06：只有"能正面证明枚举完整"的 filter 分区才允许产出"无匹配规则"这条缺席断言。
    const bool usableForAbsence = catalog.partitionUsableForAbsence(WfpPartition::Filters);
    report.catalogUsableForAbsence = usableForAbsence;
    if (!usableForAbsence) {
        // 目录本身可能没枚举全 —— "没有匹配的规则"不等于"确实没有规则"。
        AddKey(report.limitationKeys, "wfp.candidate.filter-catalog-incomplete");
    }

    // layerKey -> subLayerKey -> filters。
    // N-01：引用未采集的 filter **每条独占一个桶**，既不并进任何已知分组，也不和别的
    // 同样缺引用的 filter 并到一起 —— 后者是同一个谬误：两条不知道属于哪个 layer 的规则
    // 很可能根本不在同一个仲裁范围里（一条在 ALE_AUTH_CONNECT_V4、一条在
    // OUTBOUND_TRANSPORT_V4），却会被判成"900 压过 100 → 阻断候选"。
    std::map<std::string, std::map<std::string, std::vector<FilterCandidate>>> buckets;
    std::size_t bucketIndex = 0;
    for (const WfpFilter& filter : catalog.filters()) {
        FilterCandidate candidate = EvaluateFilter(catalog, filter, connection);
        const std::string suffix = FormatU64(bucketIndex, U64Format::Decimal);
        const std::string layerBucket =
            filter.layerKey.known() ? filter.layerKey.text : (std::string(kUnlinkedLayerPrefix) + suffix);
        const std::string subBucket = filter.subLayerKey.known()
                                          ? filter.subLayerKey.text
                                          : (std::string(kUnlinkedSubLayerPrefix) + suffix);
        buckets[layerBucket][subBucket].push_back(std::move(candidate));
        ++bucketIndex;
        ++report.evaluatedFilterCount;
    }

    std::vector<CandidateDecision> layerDecisions;
    for (auto& layerEntry : buckets) {
        LayerCandidateGroup layerGroup;
        const bool layerUnlinked = IsUnlinkedBucketKey(layerEntry.first);
        layerGroup.layer =
            catalog.resolveLayer(layerUnlinked ? WfpGuid{} : GuidFromText(layerEntry.first));
        if (layerGroup.layer.state == ReferenceState::NotSpecified) {
            AddKey(layerGroup.limitationKeys, "wfp.filter.layer-missing");
        }
        layerGroup.unlinkedReference = layerUnlinked;

        std::vector<CandidateDecision> subLayerDecisions;
        for (auto& subEntry : layerEntry.second) {
            SubLayerCandidateGroup subGroup;
            const bool subUnlinked = IsUnlinkedBucketKey(subEntry.first);
            subGroup.unlinkedReference = layerUnlinked || subUnlinked;
            subGroup.subLayer =
                catalog.resolveSubLayer(subUnlinked ? WfpGuid{} : GuidFromText(subEntry.first));
            if (subGroup.subLayer.resolved()) {
                for (const WfpSubLayer& subLayer : catalog.subLayers()) {
                    if (subLayer.subLayerKey == subGroup.subLayer.key) {
                        subGroup.subLayerWeight = subLayer.weight;
                        break;
                    }
                }
            }
            if (!subGroup.subLayerWeight.present) {
                AddKey(subGroup.limitationKeys, "wfp.layer.sublayer-weight-unknown");
            }
            subGroup.filters = std::move(subEntry.second);

            // 展示顺序：权重降序（未知权重排最后）。判定是否敢依赖这个顺序另算。
            std::stable_sort(subGroup.filters.begin(), subGroup.filters.end(),
                             [](const FilterCandidate& a, const FilterCandidate& b) {
                                 if (a.orderingWeight.present != b.orderingWeight.present) {
                                     return a.orderingWeight.present;
                                 }
                                 if (!a.orderingWeight.present) {
                                     return false;
                                 }
                                 return a.orderingWeight.value > b.orderingWeight.value;
                             });

            bool mixedScale = false;
            subGroup.orderingReliable = OrderingIsReliable(subGroup.filters, mixedScale);
            if (mixedScale) {
                AddKey(subGroup.limitationKeys, "wfp.sublayer.weight-scale-mixed");
            }
            if (subGroup.unlinkedReference) {
                // 连"这条规则和谁在同一个仲裁范围里"都不知道，遑论范围内的先后顺序。
                subGroup.orderingReliable = false;
                if (layerUnlinked) {
                    AddKey(subGroup.limitationKeys, "wfp.filter.layer-missing");
                }
                if (subUnlinked) {
                    AddKey(subGroup.limitationKeys, "wfp.filter.sublayer-missing");
                }
            }
            if (!subGroup.orderingReliable) {
                AddKey(subGroup.limitationKeys, "wfp.sublayer.order-unreliable");
            }
            subGroup.decision = DecideWithinSubLayer(subGroup.filters, subGroup.orderingReliable);
            if (subGroup.unlinkedReference && subGroup.decision != CandidateDecision::NoMatchingFilter) {
                // 范围未知的分组只允许"这条规则不匹配"或"不知道"，绝不允许给出
                // 阻断/放行候选 —— 那需要先确定它到底在哪个 sublayer 里跟谁竞争。
                subGroup.decision = CandidateDecision::Unknown;
            }
            if (!usableForAbsence) {
                // N-03/N-06：目录不足以证明缺席时，"该范围内没有任何 filter 匹配"这条
                // 缺席断言在分组这一级也不成立。限制键必须落到分组上，只写在 report
                // 级别的话 UI 渲染 SubLayerCandidateGroup::decision 时看不到任何异常。
                AddKey(subGroup.limitationKeys, "wfp.candidate.filter-catalog-incomplete");
                if (subGroup.decision == CandidateDecision::NoMatchingFilter) {
                    subGroup.decision = CandidateDecision::Unknown;
                }
            }
            subLayerDecisions.push_back(subGroup.decision);
            layerGroup.subLayers.push_back(std::move(subGroup));
        }

        // sublayer 之间按 UINT16 权重降序展示。
        std::stable_sort(layerGroup.subLayers.begin(), layerGroup.subLayers.end(),
                         [](const SubLayerCandidateGroup& a, const SubLayerCandidateGroup& b) {
                             if (a.subLayerWeight.present != b.subLayerWeight.present) {
                                 return a.subLayerWeight.present;
                             }
                             if (!a.subLayerWeight.present) {
                                 return false;
                             }
                             return a.subLayerWeight.value > b.subLayerWeight.value;
                         });
        layerGroup.subLayerOrderingReliable = true;
        std::vector<std::uint64_t> seenWeights;
        for (const SubLayerCandidateGroup& subGroup : layerGroup.subLayers) {
            if (!subGroup.subLayerWeight.present) {
                layerGroup.subLayerOrderingReliable = false;
                break;
            }
            bool duplicate = false;
            for (std::uint64_t value : seenWeights) {
                if (value == subGroup.subLayerWeight.value) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) {
                layerGroup.subLayerOrderingReliable = false;
                break;
            }
            seenWeights.push_back(subGroup.subLayerWeight.value);
        }

        for (const SubLayerCandidateGroup& subGroup : layerGroup.subLayers) {
            if (subGroup.unlinkedReference) {
                layerGroup.unlinkedReference = true;
                break;
            }
        }

        layerGroup.decision = CombineDecisions(subLayerDecisions);
        if (!usableForAbsence) {
            AddKey(layerGroup.limitationKeys, "wfp.candidate.filter-catalog-incomplete");
            if (layerGroup.decision == CandidateDecision::NoMatchingFilter) {
                layerGroup.decision = CandidateDecision::Unknown;
            }
        }
        layerDecisions.push_back(layerGroup.decision);
        report.layers.push_back(std::move(layerGroup));
    }

    if (layerDecisions.empty()) {
        // 一条 filter 都没有：目录能证明完整时这才是"确实没有规则"，否则是"没采到"。
        report.overallDecision =
            usableForAbsence ? CandidateDecision::NoMatchingFilter : CandidateDecision::Unknown;
    } else {
        report.overallDecision = CombineDecisions(layerDecisions);
        if (!usableForAbsence && report.overallDecision == CandidateDecision::NoMatchingFilter) {
            report.overallDecision = CandidateDecision::Unknown;
        }
    }
    return report;
}

// ---------------------------------------------------------------------------
// N-04：运行事件
// ---------------------------------------------------------------------------
ObservationTrust ClassifyObservation(const ObservedFilterHit& hit) noexcept {
    // 来源未知时，记录自己声称的"已启用/受支持"没有意义 —— 先看来源。
    if (hit.source == ObservationSource::Unknown) {
        return ObservationTrust::SourceUnknown;
    }
    if (hit.source == ObservationSource::OfflineImport &&
        (hit.originalSource == ObservationSource::Unknown ||
         hit.originalSource == ObservationSource::OfflineImport)) {
        // N-04：离线导入只说明"这条记录是从样本读进来的"。原始来源不明时，样本里
        // 自己填的 supported/enabled 两个布尔不能把它抬成"实际阻断" —— 那样来源栏
        // 只能显示"离线导入"，分不清原始是 5157 安全审计、FwpmNetEventEnum 还是
        // 本工具驱动的 ALE 流授权环。
        return ObservationTrust::SourceUnknown;
    }
    if (!hit.sourceSupported) {
        return ObservationTrust::SourceUnsupported;
    }
    if (!hit.sourceEnabled) {
        return ObservationTrust::SourceNotEnabled;
    }
    return ObservationTrust::ActualObservation;
}

bool DescribesActualVerdict(const ObservedFilterHit& hit) noexcept {
    return ClassifyObservation(hit) == ObservationTrust::ActualObservation &&
           hit.verdict != WfpEventVerdict::Unknown;
}

bool ObservationSourceOutcome::carriesObservation() const noexcept {
    return StatusCarriesObservation(outcome.status);
}

std::size_t RuleExplanation::actualHitCount() const noexcept {
    std::size_t count = 0;
    for (const ObservedFilterHit& hit : observations) {
        if (ClassifyObservation(hit) == ObservationTrust::ActualObservation) {
            ++count;
        }
    }
    return count;
}

std::size_t RuleExplanation::untrustedObservationCount() const noexcept {
    return observations.size() - actualHitCount();
}

bool RuleExplanation::observationsCollected() const noexcept {
    // N-04 / F-05：只有"受支持 + 已启用 + 状态携带观测"的来源，才让"零命中"这句话
    // 具备"确实没有命中"的含义。一条都没登记（从没订阅过）时返回 false。
    for (const ObservationSourceOutcome& entry : sourceOutcomes) {
        if (entry.sourceSupported && entry.sourceEnabled && entry.carriesObservation()) {
            return true;
        }
    }
    return false;
}

bool RuleExplanation::anyObservationSourceFailed() const noexcept {
    for (const ObservationSourceOutcome& entry : sourceOutcomes) {
        if (!entry.carriesObservation()) {
            return true;  // 未采集 / 订阅失败 / 拒绝访问 —— 原始错误码在 outcome 里
        }
    }
    return false;
}

bool RuleExplanation::hasActualPath() const noexcept {
    // N-04：没有受支持且启用来源的记录时，不允许生成"实际经过路径"。
    // 静态候选再多也不能顶。
    return actualHitCount() > 0U;
}

// ---------------------------------------------------------------------------
// N-06：运行时 id 引用
// ---------------------------------------------------------------------------
FilterReferenceResolution ResolveFilterReference(const WfpCatalog& catalog,
                                                 const RuntimeFilterReference& reference) {
    FilterReferenceResolution resolution;
    if (!reference.filterKey.known() && !reference.filterId.present) {
        resolution.state = FilterLinkState::NotSpecified;
        return resolution;
    }

    if (reference.filterKey.known()) {
        const ObjectReference object = catalog.resolveFilter(reference.filterKey);
        switch (object.state) {
        case ReferenceState::Resolved: {
            resolution.state = FilterLinkState::LinkedByGuid;
            const std::vector<WfpFilter>& filters = catalog.filters();
            for (std::size_t i = 0; i < filters.size(); ++i) {
                if (filters[i].filterKey == reference.filterKey) {
                    resolution.hasIndex = true;
                    resolution.filterIndex = i;
                    break;
                }
            }
            if (resolution.hasIndex && reference.filterId.present) {
                const OptionalU64& current = catalog.filters()[resolution.filterIndex].filterId;
                if (!current.present || current.value != reference.filterId.value) {
                    // GUID 是稳定键，照连；但运行时 id 变了必须说出来。
                    AddKey(resolution.limitationKeys, "wfp.link.runtime-id-changed");
                }
            }
            return resolution;
        }
        case ReferenceState::Ambiguous:
            resolution.state = FilterLinkState::RejectedAmbiguous;
            return resolution;
        case ReferenceState::CatalogNotCollected:
            resolution.state = FilterLinkState::CatalogNotCollected;
            return resolution;
        case ReferenceState::CatalogIncomplete:
            // 采到了但没采全：找不到不等于不存在。
            resolution.state = FilterLinkState::CatalogIncomplete;
            AddKey(resolution.limitationKeys, "wfp.link.catalog-incomplete");
            return resolution;
        case ReferenceState::UnknownObject:
        case ReferenceState::NotSpecified:
            break;
        }
        // GUID 不在目录里。如果同一个运行时 id 已经被别的 filter 占用，那就是 id 复用。
        const std::vector<std::size_t> byId = catalog.findFilterIndexesByRuntimeId(reference.filterId);
        if (!byId.empty()) {
            resolution.state = FilterLinkState::RejectedIdReused;
            AddKey(resolution.limitationKeys, "wfp.link.id-reused");
            return resolution;
        }
        // 走到这里 resolveFilter 已经判过 UnknownObject（目录能正面证明缺席），
        // NoMatch 这条缺席断言才成立。
        resolution.state = FilterLinkState::NoMatch;
        return resolution;
    }

    // 只有运行时 id：id 可复用，必须先确认代次。
    const CollectionStatus filterStatus = catalog.partitionState(WfpPartition::Filters).outcome.status;
    if (!StatusCarriesObservation(filterStatus)) {
        resolution.state = FilterLinkState::CatalogNotCollected;
        return resolution;
    }
    if (!reference.capturedGeneration.present) {
        resolution.state = FilterLinkState::RejectedStaleGeneration;
        AddKey(resolution.limitationKeys, "wfp.link.generation-unknown");
        return resolution;
    }
    if (reference.capturedGeneration.value != catalog.generation()) {
        resolution.state = FilterLinkState::RejectedStaleGeneration;
        AddKey(resolution.limitationKeys, "wfp.link.stale-generation");
        return resolution;
    }
    // 代次号跨启动会从 0 重来，"代次相同"在跨启动时不构成证据。两侧都有 bootId
    // 且不相等就直接拒绝；有一侧拿不到 bootId 时只能保持"代次相同"这一层判据。
    const std::string& catalogBoot = catalog.captureWindow().bootId;
    if (!reference.bootId.empty() && !catalogBoot.empty() && reference.bootId != catalogBoot) {
        resolution.state = FilterLinkState::RejectedStaleGeneration;
        AddKey(resolution.limitationKeys, "wfp.link.boot-mismatch");
        return resolution;
    }
    const std::vector<std::size_t> matches = catalog.findFilterIndexesByRuntimeId(reference.filterId);
    if (matches.empty()) {
        // N-06：目录没枚举全时"这个 id 不在里面"证明不了这条规则不存在。
        if (!catalog.partitionUsableForAbsence(WfpPartition::Filters)) {
            resolution.state = FilterLinkState::CatalogIncomplete;
            AddKey(resolution.limitationKeys, "wfp.link.catalog-incomplete");
            return resolution;
        }
        resolution.state = FilterLinkState::NoMatch;
        return resolution;
    }
    if (matches.size() > 1U) {
        resolution.state = FilterLinkState::RejectedAmbiguous;
        return resolution;
    }
    resolution.state = FilterLinkState::LinkedByRuntimeIdSameGeneration;
    resolution.hasIndex = true;
    resolution.filterIndex = matches.front();
    return resolution;
}

FilterReferenceResolution LinkObservationToCatalog(const WfpCatalog& catalog,
                                                   const ObservedFilterHit& hit) {
    RuntimeFilterReference reference;
    reference.filterId = hit.filterId;
    reference.filterKey = hit.filterKey;
    reference.capturedGeneration = hit.capturedGeneration;
    reference.bootId = hit.connection.bootId;  // 事件自带的启动周期，用于跨启动保护
    return ResolveFilterReference(catalog, reference);
}

namespace {

// GUID 索引 + 让这套索引失真的两类行。std::map::emplace 会静默丢掉重复 GUID 的第二行，
// 没有 GUID 的行则根本进不了索引 —— 两者都会让"增删改"结论悄悄漏掉规则。
struct FilterGuidIndex final {
    std::map<std::string, std::size_t> byGuid;
    std::vector<std::string> duplicatedGuids;
    std::vector<std::size_t> rowsWithoutGuid;

    bool distorted() const noexcept {
        return !duplicatedGuids.empty() || !rowsWithoutGuid.empty();
    }
};

FilterGuidIndex BuildFilterGuidIndex(const std::vector<WfpFilter>& filters) {
    FilterGuidIndex index;
    for (std::size_t i = 0; i < filters.size(); ++i) {
        const WfpFilter& filter = filters[i];
        if (!filter.filterKey.known()) {
            index.rowsWithoutGuid.push_back(i);
            continue;
        }
        const auto inserted = index.byGuid.emplace(filter.filterKey.text, i);
        if (!inserted.second) {
            AddKey(index.duplicatedGuids, filter.filterKey.text);
        }
    }
    return index;
}

} // namespace

CatalogDelta DiffCatalogs(const WfpCatalog& before, const WfpCatalog& after) {
    CatalogDelta delta;
    const bool beforeUsable = before.partitionUsableForAbsence(WfpPartition::Filters);
    const bool afterUsable = after.partitionUsableForAbsence(WfpPartition::Filters);
    if (!beforeUsable) {
        AddKey(delta.limitationKeys, "wfp.delta.before-incomplete");
    }
    if (!afterUsable) {
        AddKey(delta.limitationKeys, "wfp.delta.after-incomplete");
    }

    const FilterGuidIndex beforeIndex = BuildFilterGuidIndex(before.filters());
    const FilterGuidIndex afterIndex = BuildFilterGuidIndex(after.filters());
    const std::map<std::string, std::size_t>& beforeByGuid = beforeIndex.byGuid;
    const std::map<std::string, std::size_t>& afterByGuid = afterIndex.byGuid;

    // 索引失真时"两代之间毫无变化"这句话没有依据 —— 被丢掉的那一行既可能一直在，
    // 也可能刚被删掉，本层不知道。
    delta.comparable =
        beforeUsable && afterUsable && !beforeIndex.distorted() && !afterIndex.distorted();

    // N-01：同一 GUID 在一侧出现多次 = 快照不自洽。目录自己已经会把它报成 Ambiguous，
    // 这里绝不能取第一条了事，而要对这条 GUID 拒绝做任何增删改结论。
    std::vector<std::string> ambiguousGuids;
    MergeKeys(ambiguousGuids, beforeIndex.duplicatedGuids);
    MergeKeys(ambiguousGuids, afterIndex.duplicatedGuids);
    if (!ambiguousGuids.empty()) {
        AddKey(delta.limitationKeys, "wfp.delta.duplicate-guid");
    }
    for (const std::string& text : ambiguousGuids) {
        CatalogChange change;
        change.kind = CatalogChangeKind::PresenceUnknown;
        change.filterKey = GuidFromText(text);
        // 歧义行的运行时 id 本来就不唯一，留 unset 而不是随手取一条。
        AddKey(change.limitationKeys, "wfp.delta.duplicate-guid");
        delta.changes.push_back(std::move(change));
    }

    // N-06：只有可复用运行时 id、没有 GUID 的行进不了比较循环。必须逐行产出可解释的
    // "在场未知"，而不是只在 delta 级别记一个"有过这类行"的全局键 —— 那样看不出有几条、
    // 是哪条、是新增还是删除。
    if (!beforeIndex.rowsWithoutGuid.empty() || !afterIndex.rowsWithoutGuid.empty()) {
        AddKey(delta.limitationKeys, "wfp.delta.filter-without-guid");
    }
    for (std::size_t row : beforeIndex.rowsWithoutGuid) {
        CatalogChange change;
        change.kind = CatalogChangeKind::PresenceUnknown;
        change.beforeFilterId = before.filters()[row].filterId;
        AddKey(change.limitationKeys, "wfp.delta.filter-without-guid");
        delta.changes.push_back(std::move(change));
    }
    for (std::size_t row : afterIndex.rowsWithoutGuid) {
        CatalogChange change;
        change.kind = CatalogChangeKind::PresenceUnknown;
        change.afterFilterId = after.filters()[row].filterId;
        AddKey(change.limitationKeys, "wfp.delta.filter-without-guid");
        delta.changes.push_back(std::move(change));
    }

    for (const auto& entry : beforeByGuid) {
        if (HasLimitation(ambiguousGuids, entry.first)) {
            continue;  // 已经产出过 PresenceUnknown
        }
        const WfpFilter& oldFilter = before.filters()[entry.second];
        const auto found = afterByGuid.find(entry.first);
        if (found == afterByGuid.end()) {
            CatalogChange change;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            if (afterUsable) {
                change.kind = CatalogChangeKind::Removed;
            } else {
                // 新一侧没枚举全 —— "不在里面"不等于"被删了"（禁止从没采到推出结论）。
                change.kind = CatalogChangeKind::PresenceUnknown;
                AddKey(change.limitationKeys, "wfp.delta.after-incomplete");
            }
            delta.changes.push_back(std::move(change));
            continue;
        }
        const WfpFilter& newFilter = after.filters()[found->second];
        if (oldFilter.action != newFilter.action || oldFilter.rawActionCode != newFilter.rawActionCode) {
            CatalogChange change;
            change.kind = CatalogChangeKind::ActionChanged;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            change.afterFilterId = newFilter.filterId;
            delta.changes.push_back(std::move(change));
        }
        if (oldFilter.weightKind != newFilter.weightKind || oldFilter.weight != newFilter.weight ||
            oldFilter.effectiveWeight != newFilter.effectiveWeight) {
            CatalogChange change;
            change.kind = CatalogChangeKind::WeightChanged;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            change.afterFilterId = newFilter.filterId;
            delta.changes.push_back(std::move(change));
        }
        if (FilterConditionsSignature(oldFilter) != FilterConditionsSignature(newFilter)) {
            CatalogChange change;
            change.kind = CatalogChangeKind::ConditionsChanged;
            change.filterKey = oldFilter.filterKey;
            change.beforeFilterId = oldFilter.filterId;
            change.afterFilterId = newFilter.filterId;
            delta.changes.push_back(std::move(change));
        }
    }

    for (const auto& entry : afterByGuid) {
        if (beforeByGuid.find(entry.first) != beforeByGuid.end()) {
            continue;
        }
        if (HasLimitation(ambiguousGuids, entry.first)) {
            continue;
        }
        const WfpFilter& newFilter = after.filters()[entry.second];
        CatalogChange change;
        change.filterKey = newFilter.filterKey;
        change.afterFilterId = newFilter.filterId;
        if (beforeUsable) {
            change.kind = CatalogChangeKind::Added;
        } else {
            change.kind = CatalogChangeKind::PresenceUnknown;
            AddKey(change.limitationKeys, "wfp.delta.before-incomplete");
        }
        delta.changes.push_back(std::move(change));
    }

    // 运行时 id 复用：同一个 filterId 在两代里指向不同 GUID。
    const std::string& beforeBoot = before.captureWindow().bootId;
    const std::string& afterBoot = after.captureWindow().bootId;
    const bool bootChanged = !beforeBoot.empty() && !afterBoot.empty() && beforeBoot != afterBoot;
    if (bootChanged) {
        AddKey(delta.limitationKeys, "wfp.delta.boot-changed");
    }
    std::map<std::uint64_t, std::string> beforeById;
    for (const WfpFilter& filter : before.filters()) {
        if (filter.filterId.present && filter.filterKey.known()) {
            beforeById.emplace(filter.filterId.value, filter.filterKey.text);
        }
    }
    for (const WfpFilter& filter : after.filters()) {
        if (!filter.filterId.present || !filter.filterKey.known()) {
            continue;
        }
        const auto found = beforeById.find(filter.filterId.value);
        if (found == beforeById.end() || found->second == filter.filterKey.text) {
            continue;
        }
        CatalogChange change;
        change.kind = CatalogChangeKind::RuntimeIdReused;
        change.filterKey = filter.filterKey;
        change.beforeFilterId = filter.filterId;
        change.afterFilterId = filter.filterId;
        AddKey(change.limitationKeys, "wfp.link.id-reused");
        if (bootChanged) {
            // 跨启动的 id 重排是必然现象，不是"同一次会话里 id 被回收再分配"的证据。
            AddKey(change.limitationKeys, "wfp.delta.boot-changed");
        }
        delta.changes.push_back(std::move(change));
    }
    return delta;
}

// ---------------------------------------------------------------------------
// N-08：导航
// ---------------------------------------------------------------------------
namespace {

// outcome 复用 LiveNavigation 的取值域（本层不新增导航结果），拒绝原因单列一维。
WfpNavigationRejection RejectionFromOutcome(NavigationOutcome outcome) noexcept {
    switch (outcome) {
    case NavigationOutcome::Delivered:         return WfpNavigationRejection::None;
    case NavigationOutcome::TargetPageMissing: return WfpNavigationRejection::TargetPageMissing;
    case NavigationOutcome::ObjectNotPresent:  return WfpNavigationRejection::ObjectNotPresent;
    case NavigationOutcome::IdentityUnusable:  return WfpNavigationRejection::IdentityUnusable;
    case NavigationOutcome::EvidenceIdMissing: return WfpNavigationRejection::EvidenceIdMissing;
    case NavigationOutcome::EvidenceNotSaved:  return WfpNavigationRejection::EvidenceNotSaved;
    }
    return WfpNavigationRejection::ObjectNotPresent;
}

} // namespace

ObjectRef MakeFilterRef(const WfpFilter& filter, std::string evidenceId) {
    ObjectRef ref;
    ref.kind = ObjectKind::Unknown;  // ObjectIdentity 没有 WFP filter 这一类
    ref.evidenceId = std::move(evidenceId);
    ref.displayText = filter.displayName.present ? filter.displayName.value : filter.filterKey.text;
    if (filter.filterKey.known()) {
        ref.key = "wfp-filter|" + filter.filterKey.text;
        ref.strength = IdentityStrength::Strong;  // GUID 是稳定的跨会话键
    } else {
        // 只有运行时 id 的引用不发键：filterId 会被复用，跨会话跳过去可能是别的规则。
        ref.strength = IdentityStrength::Unusable;
    }
    return ref;
}

ObjectRef MakeCalloutRef(const WfpCallout& callout, std::string evidenceId) {
    ObjectRef ref;
    ref.kind = ObjectKind::Unknown;
    ref.evidenceId = std::move(evidenceId);
    ref.displayText = callout.displayName.present ? callout.displayName.value : callout.calloutKey.text;
    if (callout.calloutKey.known()) {
        ref.key = "wfp-callout|" + callout.calloutKey.text;
        ref.strength = IdentityStrength::Strong;
    } else {
        ref.strength = IdentityStrength::Unusable;
    }
    return ref;
}

WfpNavigationResult NavigateConnectionToProcess(const ConnectionDescription& connection,
                                                const LiveResolution& live,
                                                bool targetPageAvailable,
                                                bool evidencePresentInSession,
                                                std::string evidenceId) {
    WfpNavigationResult result;
    result.identityRevalidated = true;
    result.liveDecision = ResolveProcessNavigation(connection.identity.owner, live);
    result.request.page = NavigationPage::Process;
    result.request.evidenceId = evidenceId;

    switch (result.liveDecision) {
    case LiveNavigationDecision::Allow:
        break;
    case LiveNavigationDecision::RejectObjectExited:
    case LiveNavigationDecision::RejectIdentityMismatch:
        // PID 复用 / 对象已退出：现场没有这个对象，绝不把操作交给"看起来像"的新进程。
        result.request.object = MakeProcessRef(connection.identity.owner, std::move(evidenceId));
        result.outcome = NavigationOutcome::ObjectNotPresent;
        result.rejection = WfpNavigationRejection::ObjectNotPresent;
        return result;
    case LiveNavigationDecision::RejectIdentityUnverifiable:
        result.request.object = MakeProcessRef(connection.identity.owner, std::move(evidenceId));
        result.outcome = NavigationOutcome::IdentityUnusable;
        result.rejection = WfpNavigationRejection::IdentityUnusable;
        return result;
    }

    result.request.object = MakeProcessRef(live.liveProcess, std::move(evidenceId));
    result.outcome = DecideNavigation(result.request, targetPageAvailable, true, evidencePresentInSession);
    result.rejection = RejectionFromOutcome(result.outcome);
    return result;
}

WfpNavigationResult NavigateFilterToEvidence(const WfpFilter& filter,
                                             bool targetPageAvailable,
                                             bool objectPresentInPage,
                                             bool evidencePresentInSession,
                                             std::string evidenceId) {
    WfpNavigationResult result;
    result.request.page = NavigationPage::Network;
    result.request.evidenceId = evidenceId;
    result.request.object = MakeFilterRef(filter, std::move(evidenceId));
    result.outcome = DecideNavigation(result.request, targetPageAvailable, objectPresentInPage,
                                      evidencePresentInSession);
    result.rejection = RejectionFromOutcome(result.outcome);
    return result;
}

WfpNavigationResult NavigateObservationToTimeline(const ObservedFilterHit& hit,
                                                  bool targetPageAvailable,
                                                  bool evidencePresentInSession) {
    WfpNavigationResult result;
    result.request.page = NavigationPage::Timeline;
    result.request.evidenceId = hit.evidenceId;
    result.request.object = MakeConnectionRef(hit.connection, hit.evidenceId);
    // 先按常规导航判据判：身份不足 / 没带证据 id / 离线没保存 / 目标页不在，这四种
    // 原因各不相同。把来源可信度排在前面会让它们全被"对象不在当前数据里"盖掉 ——
    // 连"请求根本没带证据 id"都查不出来。
    result.outcome = DecideNavigation(result.request, targetPageAvailable, true, evidencePresentInSession);
    result.rejection = RejectionFromOutcome(result.outcome);
    if (ClassifyObservation(hit) != ObservationTrust::ActualObservation) {
        // N-04：来源不受支持/未启用/来源不明的记录不能当"实际经过路径"放到时间线上。
        // outcome 保留上面那条常规判据的结论，拒绝原因单独标成 SourceNotTrusted：
        // 两个字段合起来才说得清"既不可信、而且还没带证据 id"。
        result.blockedByUntrustedSource = true;
        if (result.outcome == NavigationOutcome::Delivered) {
            result.outcome = NavigationOutcome::ObjectNotPresent;
        }
        result.rejection = WfpNavigationRejection::SourceNotTrusted;
    }
    return result;
}

} // namespace Ksword::Evidence
