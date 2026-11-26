#pragma once
#include "../WinApiMonitorProtocol.h"
#include <algorithm>
#include <array>
#include <optional>
#include <string_view>

namespace Ksword::Evidence {
// AASM1 仅描述节映射请求/返回，不证明写入、别名传播、归因或执行。
// kApiSectionMapFieldsMarker：本独立协议在业务包中的显式标记。
inline constexpr std::uint32_t kApiSectionMapFieldsMarker = 0x534d5631u;
// kApiSectionMapFieldsPrefix：固定文本布局的版本前缀。
inline constexpr std::wstring_view kApiSectionMapFieldsPrefix = L"AASM1|";
// ApiSectionMapFieldFlag：身份、请求输入和成功输出的独立有效位。
enum ApiSectionMapFieldFlag : std::uint64_t {
    ApiSectionMapActorIdentity = 1ull << 0, // 源进程创建代次有效。
    ApiSectionMapTargetIdentity = 1ull << 1, // 目标进程 PID 和创建代次有效。
    ApiSectionMapTargetStable = 1ull << 2, // 原调用前后目标身份一致。
    ApiSectionMapRequestedBase = 1ull << 3, // 已安全读到原请求地址。
    ApiSectionMapRequestedBytes = 1ull << 4, // 已安全读到原请求长度。
    ApiSectionMapSectionOffset = 1ull << 5, // 已安全读到输入节内偏移。
    ApiSectionMapMappedBase = 1ull << 6, // 成功后已安全读回实际地址。
    ApiSectionMapMappedBytes = 1ull << 7, // 成功后已安全读回实际长度。
};
// ApiSectionMapOperation：本版本只表示节映射调用。
enum class ApiSectionMapOperation : std::uint64_t {
    Map = 1, // 调用节映射接口。
};
// ApiSectionMapFieldsV1：以下字段按固定顺序编码，缺少有效位的值保持零。
struct ApiSectionMapFieldsV1 {
    ApiSectionMapOperation operation = ApiSectionMapOperation::Map; // 当前操作类型。
    std::uint64_t flags = 0; // ApiSectionMapFieldFlag 有效位集合。
    std::uint64_t actorCreationFileTime = 0; // 包头源 PID 的创建 FILETIME。
    std::uint64_t targetPid = 0; // 原进程句柄解析出的目标 PID。
    std::uint64_t targetCreationFileTime = 0; // 目标进程创建 FILETIME。
    std::uint64_t requestedBase = 0; // 调用前读取的请求基址。
    std::uint64_t requestedBytes = 0; // 调用前读取的请求长度。
    std::uint64_t mappedBase = 0; // 成功后安全读回的实际映射基址。
    std::uint64_t mappedBytes = 0; // 成功后安全读回的实际映射长度。
    std::uint64_t sectionOffset = 0; // 输入偏移位模式，不是系统调整后的输出。
    std::uint64_t inputSectionHandle = 0; // 原节句柄位模式，不能作为节对象身份。
    std::uint64_t requestedProtection = 0; // 原保护参数位模式。
    std::uint64_t enterQpc = 0; // 原调用进入前的时点。
    std::uint64_t returnQpc = 0; // 原调用返回后的时点。
    std::uint64_t inputProcessHandle = 0; // 原进程句柄位模式，不独立作为身份。
};
// kApiSectionMapValueCount：固定编码的数值个数。
inline constexpr std::size_t kApiSectionMapValueCount = 15;
// kApiSectionMapTextLength：前缀、字段及分隔符的字符数，不含终止符。
inline constexpr std::size_t kApiSectionMapTextLength = kApiSectionMapFieldsPrefix.size() + kApiSectionMapValueCount * 17 - 1;
static_assert(kApiSectionMapTextLength < ks::winapi_monitor::kMaxDetailChars);
// StoreApiSectionMapFields：把 f 写入 p 的独立文本槽，保留原返回、耗时和定义摘要。
inline void StoreApiSectionMapFields(ks::winapi_monitor::ApiMonitorEventPacket& p,
    const ApiSectionMapFieldsV1& f) noexcept
{
    // values：与公开字段顺序一致的待编码值。
    const std::array<std::uint64_t, kApiSectionMapValueCount> values{
        static_cast<std::uint64_t>(f.operation),
        f.flags,
        f.actorCreationFileTime,
        f.targetPid,
        f.targetCreationFileTime,
        f.requestedBase,
        f.requestedBytes,
        f.mappedBase,
        f.mappedBytes,
        f.sectionOffset,
        f.inputSectionHandle,
        f.requestedProtection,
        f.enterQpc,
        f.returnQpc,
        f.inputProcessHandle,
    };
    std::fill(std::begin(p.detailText), std::end(p.detailText), L'\0');
    std::copy(kApiSectionMapFieldsPrefix.begin(), kApiSectionMapFieldsPrefix.end(), p.detailText);
    std::size_t cursor = kApiSectionMapFieldsPrefix.size(); // 下一处文本写入位置。
    constexpr wchar_t digits[] = L"0123456789abcdef"; // 规范小写十六进制字符表。
    for (std::size_t i = 0; i < values.size(); ++i) { // 当前编码字段序号。
        if (i) {
            p.detailText[cursor++] = L'|';
        }
        for (unsigned d = 0; d < 16; ++d) { // 当前字段的十六进制位序。
            p.detailText[cursor++] = digits[(values[i] >> ((15 - d) * 4)) & 15];
        }
    }
    p.coverageState = kApiSectionMapFieldsMarker;
}
// ReadApiSectionMapFields：严格解码 p 的显式 AASM1；消费者还须核对精确 API/模块及返回。
inline std::optional<ApiSectionMapFieldsV1> ReadApiSectionMapFields(
    const ks::winapi_monitor::ApiMonitorEventPacket& p) noexcept
{
    namespace m = ks::winapi_monitor;
    if (p.size != sizeof(p) || p.version != m::kProtocolVersion ||
        p.eventKind != static_cast<std::uint32_t>(m::EventKind::ApiCall) ||
        p.category != static_cast<std::uint32_t>(m::EventCategory::Memory) ||
        p.hookKind != static_cast<std::uint32_t>(m::HookKind::Strong) ||
        p.snapshotIndex != m::kApiCallReturnValueMarker || p.coverageState != kApiSectionMapFieldsMarker ||
        !std::equal(kApiSectionMapFieldsPrefix.begin(), kApiSectionMapFieldsPrefix.end(), p.detailText) ||
        p.detailText[kApiSectionMapTextLength] != L'\0') {
        return std::nullopt;
    }
    std::array<std::uint64_t, kApiSectionMapValueCount> v{}; // 验证完成前的局部解码值。
    std::size_t cursor = kApiSectionMapFieldsPrefix.size(); // 下一处文本读取位置。
    for (std::size_t i = 0; i < v.size(); ++i) { // 当前解码字段序号。
        if (i && p.detailText[cursor++] != L'|') {
            return std::nullopt;
        }
        for (unsigned d = 0; d < 16; ++d) { // 当前字段的十六进制位序。
            const wchar_t c = p.detailText[cursor++]; // 本次读取的编码字符。
            if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
                return std::nullopt;
            }
            v[i] = (v[i] << 4) | static_cast<std::uint64_t>(c <= L'9' ? c - L'0' : c - L'a' + 10);
        }
    }
    if (v[0] != 1 || (v[1] & ~255ull) || v[3] > UINT32_MAX || !v[12] || v[13] < v[12]) {
        return std::nullopt;
    }
    const auto flags = v[1]; // 核对字段值与声明的有效位是否一致。
    if (((flags & ApiSectionMapActorIdentity) ? v[2] == 0 : v[2] != 0) ||
        ((flags & ApiSectionMapTargetIdentity) ? (!v[3] || !v[4]) : (v[3] || v[4])) ||
        ((flags & ApiSectionMapTargetStable) && !(flags & ApiSectionMapTargetIdentity)) ||
        (!(flags & ApiSectionMapRequestedBase) && v[5]) ||
        (!(flags & ApiSectionMapRequestedBytes) && v[6]) ||
        (!(flags & ApiSectionMapMappedBase) && v[7]) ||
        (!(flags & ApiSectionMapMappedBytes) && v[8]) ||
        (!(flags & ApiSectionMapSectionOffset) && v[9])) {
        return std::nullopt;
    }
    return ApiSectionMapFieldsV1{
        ApiSectionMapOperation::Map,
        v[1],
        v[2],
        v[3],
        v[4],
        v[5],
        v[6],
        v[7],
        v[8],
        v[9],
        v[10],
        v[11],
        v[12],
        v[13],
        v[14],
    };
}

// ApiSectionMapOutcome：只说明节映射 API 的原返回，不表达写入、别名传播或执行。
enum class ApiSectionMapOutcome {
    Unknown, // 结构无效、API/模块不符、状态类型错误或原返回互相矛盾。
    Failed, // 原节映射调用明确返回失败。
    Accepted, // 原调用接受节映射请求，不证明内容写入或任何执行。
};

// ApiSectionMapCallOutcome：输入 packet 为原始固定事件包，先解码 AASM1 再核对精确来源和返回。
// 输出 Unknown/Failed/Accepted；仅接受 ntdll 的 NtMapViewOfSection，不扩大到其它映射 API。
// 本函数不修改 packet，不补造输出范围；来源、目标代次和有效输出仍由消费者独立核对。
inline ApiSectionMapOutcome ApiSectionMapCallOutcome(
    const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
{
    namespace monitor = ks::winapi_monitor;
    if (!ReadApiSectionMapFields(packet)) {
        return ApiSectionMapOutcome::Unknown;
    }
    if (packet.resultKind != static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode)) {
        return ApiSectionMapOutcome::Unknown;
    }

    // text：从 value 定长包字段读取有界字符串，缺少终止符时返回空视图。
    const auto text = [](const auto& value) -> std::wstring_view {
        const auto* end = std::find(std::begin(value), std::end(value), L'\0'); // 包内字符串终止位置。
        if (end == std::end(value)) {
            return {};
        }
        return std::wstring_view(value, end - value);
    };
    const auto api = text(packet.apiName); // 原精确导出名，大小写必须一致。
    const auto module = text(packet.moduleName); // 原模块名，仅允许 ASCII 大小写差异。
    // moduleIs：与 expected 小写完整模块名比较，不接受路径、前后缀或子串匹配。
    const auto moduleIs = [&](std::wstring_view expected) {
        return module.size() == expected.size() &&
            std::equal(module.begin(), module.end(), expected.begin(),
                [](wchar_t value, wchar_t lower) {
                    // value 是包内字符，lower 是预期小写字符，仅折叠 ASCII 大写字母。
                    return (value >= L'A' && value <= L'Z' ? value + (L'a' - L'A') : value) == lower;
                });
    };
    if (api != L"NtMapViewOfSection" || (!moduleIs(L"ntdll") && !moduleIs(L"ntdll.dll"))) {
        return ApiSectionMapOutcome::Unknown;
    }

    // returnStatusBits：原返回低 32 位，保留原 NTSTATUS 的逐位编码。
    const auto returnStatusBits = static_cast<std::uint32_t>(packet.hookAddress);
    // resultStatusBits：独立状态码的同宽位模式，不能用 Win32 BOOL/HANDLE 方式解释。
    const auto resultStatusBits = static_cast<std::uint32_t>(packet.resultCode);
    if (returnStatusBits != resultStatusBits) {
        return ApiSectionMapOutcome::Unknown;
    }
    if (packet.resultCode >= 0) {
        return ApiSectionMapOutcome::Accepted;
    }
    return ApiSectionMapOutcome::Failed;
}
}
