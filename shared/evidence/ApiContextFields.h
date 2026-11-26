#pragma once
#include "../WinApiMonitorProtocol.h"
#include <algorithm>
#include <array>
#include <optional>
#include <string_view>

namespace Ksword::Evidence {
// AACT1 只描述调用方请求的上下文，不能解释为之后实际取指。
// kApiContextFieldsMarker：本独立协议在业务包中的识别标记。
inline constexpr std::uint32_t kApiContextFieldsMarker = 0x43545631u;
// kApiContextFieldsPrefix：固定文本版本前缀。
inline constexpr std::wstring_view kApiContextFieldsPrefix = L"AACT1|";
// ApiContextFieldFlag：各身份、请求寄存器及复核结果的有效位。
enum ApiContextFieldFlag : std::uint64_t {
    ApiContextActorIdentity = 1ull << 0, // 源进程创建代次有效。
    ApiContextTargetIdentity = 1ull << 1, // 目标进程 PID 和创建代次有效。
    ApiContextThreadIdentity = 1ull << 2, // 目标线程 TID 和创建代次有效。
    ApiContextFlags = 1ull << 3, // 已安全读到请求 ContextFlags。
    ApiContextControlRegisters = 1ull << 4, // 已安全读到本 ABI 的 CONTROL 请求值。
    ApiContextTargetStable = 1ull << 5, // 原调用前后目标进程和线程代次一致。
};
// ApiContextOperation：本版本只表示设置上下文请求。
enum class ApiContextOperation : std::uint64_t {
    Set = 1, // 调用上下文设置接口。
};
// ApiContextFieldsV1：按下列固定顺序编码；请求值与实际执行状态分开。
struct ApiContextFieldsV1 {
    ApiContextOperation operation = ApiContextOperation::Set; // 本条操作类型。
    std::uint64_t flags = 0; // ApiContextFieldFlag 有效位集合。
    std::uint64_t actorCreationFileTime = 0; // 包头源 PID 的创建 FILETIME。
    std::uint64_t targetPid = 0; // 原线程句柄所属进程 PID。
    std::uint64_t targetCreationFileTime = 0; // 目标进程创建 FILETIME。
    std::uint64_t targetTid = 0; // 原线程句柄的 TID。
    std::uint64_t targetThreadCreationFileTime = 0; // 目标线程创建 FILETIME。
    std::uint64_t contextFlags = 0; // 安全读取的原请求寄存器分组和 ABI。
    std::uint64_t requestedIp = 0; // 原请求 IP，不表示已执行。
    std::uint64_t requestedSp = 0; // 原请求 SP，不表示已生效。
    std::uint64_t contextArchitecture = 0; // 当前 Agent 原生 CONTEXT ABI：32 或 64。
    std::uint64_t enterQpc = 0; // 原 API 调用前的时点。
    std::uint64_t returnQpc = 0; // 原 API 刚返回时的时点。
    std::uint64_t inputThreadHandle = 0; // 原句柄位模式，不独立作为身份。
    std::uint64_t inputContextAddress = 0; // 原 CONTEXT 输入地址，不供消费者解引用。
};
// kApiContextValueCount：固定编码的数值个数。
inline constexpr std::size_t kApiContextValueCount = 15;
// kApiContextTextLength：编码文本字符数，不含终止符。
inline constexpr std::size_t kApiContextTextLength = kApiContextFieldsPrefix.size() + kApiContextValueCount * 17 - 1;
static_assert(kApiContextTextLength < ks::winapi_monitor::kMaxDetailChars);
// StoreApiContextFields：把 f 写入 packet 的独立文本槽，保留原返回、耗时和定义摘要。
inline void StoreApiContextFields(ks::winapi_monitor::ApiMonitorEventPacket& packet,
    const ApiContextFieldsV1& f) noexcept
{
    // values：按协议字段顺序展开的编码值。
    const std::array<std::uint64_t, kApiContextValueCount> values{
        static_cast<std::uint64_t>(f.operation),
        f.flags,
        f.actorCreationFileTime,
        f.targetPid,
        f.targetCreationFileTime,
        f.targetTid,
        f.targetThreadCreationFileTime,
        f.contextFlags,
        f.requestedIp,
        f.requestedSp,
        f.contextArchitecture,
        f.enterQpc,
        f.returnQpc,
        f.inputThreadHandle,
        f.inputContextAddress,
    };
    std::fill(std::begin(packet.detailText), std::end(packet.detailText), L'\0');
    std::copy(kApiContextFieldsPrefix.begin(), kApiContextFieldsPrefix.end(), packet.detailText);
    std::size_t cursor = kApiContextFieldsPrefix.size(); // 下一处写入位置。
    constexpr wchar_t digits[] = L"0123456789abcdef"; // 规范小写十六进制字符表。
    for (std::size_t i = 0; i < values.size(); ++i) { // 当前编码字段序号。
        if (i) {
            packet.detailText[cursor++] = L'|';
        }
        for (unsigned d = 0; d < 16; ++d) { // 当前字段的十六进制位序。
            packet.detailText[cursor++] = digits[(values[i] >> ((15 - d) * 4)) & 15];
        }
    }
    packet.coverageState = kApiContextFieldsMarker;
}
// ReadApiContextFields：严格解码 p 中的显式 AACT1；模块/API 和原返回由消费者另行核对。
inline std::optional<ApiContextFieldsV1> ReadApiContextFields(
    const ks::winapi_monitor::ApiMonitorEventPacket& p) noexcept
{
    namespace m = ks::winapi_monitor;
    if (p.size != sizeof(p) || p.version != m::kProtocolVersion ||
        p.eventKind != static_cast<std::uint32_t>(m::EventKind::ApiCall) ||
        p.category != static_cast<std::uint32_t>(m::EventCategory::Thread) ||
        p.hookKind != static_cast<std::uint32_t>(m::HookKind::Strong) ||
        p.snapshotIndex != m::kApiCallReturnValueMarker || p.coverageState != kApiContextFieldsMarker ||
        !std::equal(kApiContextFieldsPrefix.begin(), kApiContextFieldsPrefix.end(), p.detailText) ||
        p.detailText[kApiContextTextLength] != L'\0') {
        return std::nullopt;
    }
    std::array<std::uint64_t, kApiContextValueCount> v{}; // 验证完成前的局部解码值。
    std::size_t cursor = kApiContextFieldsPrefix.size(); // 下一处读取位置。
    for (std::size_t i = 0; i < v.size(); ++i) { // 当前解码字段序号。
        if (i && p.detailText[cursor++] != L'|') {
            return std::nullopt;
        }
        for (unsigned d = 0; d < 16; ++d) { // 当前字段的十六进制位序。
            const wchar_t c = p.detailText[cursor++]; // 当前编码字符。
            if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
                return std::nullopt;
            }
            v[i] = (v[i] << 4) | static_cast<std::uint64_t>(c <= L'9' ? c - L'0' : c - L'a' + 10);
        }
    }
    if (v[0] != 1 || (v[1] & ~63ull) || v[3] > UINT32_MAX || v[5] > UINT32_MAX ||
        (v[10] != 32 && v[10] != 64) || !v[11] || v[12] < v[11]) {
        return std::nullopt;
    }
    const auto flags = v[1]; // 核对身份、请求字段与声明的有效位是否一致。
    if (((flags & ApiContextActorIdentity) ? v[2] == 0 : v[2] != 0) ||
        ((flags & ApiContextTargetIdentity) ? (!v[3] || !v[4]) : (v[3] || v[4])) ||
        ((flags & ApiContextThreadIdentity) ? (!v[5] || !v[6]) : (v[5] || v[6])) ||
        (!(flags & ApiContextFlags) && v[7]) ||
        (!(flags & ApiContextControlRegisters) && (v[8] || v[9])) ||
        ((flags & ApiContextControlRegisters) && !(flags & ApiContextFlags)) ||
        ((flags & ApiContextTargetStable) && (flags & (ApiContextTargetIdentity | ApiContextThreadIdentity)) !=
            (ApiContextTargetIdentity | ApiContextThreadIdentity))) {
        return std::nullopt;
    }
    return ApiContextFieldsV1{
        ApiContextOperation::Set,
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

// ApiContextOutcome：只说明上下文设置 API 的原返回，不表达后续取指或执行状态。
enum class ApiContextOutcome {
    Unknown, // 结构无效、API/模块不符、状态类型错误或原返回互相矛盾。
    Failed, // 原上下文设置调用明确返回失败。
    Accepted, // 原调用接受上下文设置请求，不证明请求 IP 已执行。
};

// ApiContextCallOutcome：输入 packet 为原始固定事件包，先解码 AACT1 再核对精确来源和返回。
// 输出 Unknown/Failed/Accepted；只接受 SetThreadContext 和 NtSetContextThread 的约定。
// 本函数不修改 packet，不补造缺失字段；消费者仍须另行核对采样来源、目标代次和关联条件。
inline ApiContextOutcome ApiContextCallOutcome(
    const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
{
    namespace monitor = ks::winapi_monitor;
    if (!ReadApiContextFields(packet)) {
        return ApiContextOutcome::Unknown;
    }
    if (packet.resultKind != static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode)) {
        return ApiContextOutcome::Unknown;
    }

    // text：从 value 定长包字段读取有界字符串，缺少终止符时返回空视图。
    const auto text = [](const auto& value) -> std::wstring_view {
        const auto* end = std::find(std::begin(value), std::end(value), L'\0'); // 包内字符串终止位置。
        if (end == std::end(value)) {
            return {};
        }
        return std::wstring_view(value, end - value);
    };
    const auto api = text(packet.apiName); // 保持大小写精确匹配的原导出名。
    const auto module = text(packet.moduleName); // 包中模块身份，允许 ASCII 大小写差异。
    // moduleIs：将原模块名与 expected 小写完整名称比较，不允许路径、前后缀或子串匹配。
    const auto moduleIs = [&](std::wstring_view expected) {
        return module.size() == expected.size() &&
            std::equal(module.begin(), module.end(), expected.begin(),
                [](wchar_t value, wchar_t lower) {
                    // value 是包内字符，lower 是预期小写字符，仅折叠 ASCII 大写字母。
                    return (value >= L'A' && value <= L'Z' ? value + (L'a' - L'A') : value) == lower;
                });
    };

    if (api == L"NtSetContextThread") {
        if (!moduleIs(L"ntdll") && !moduleIs(L"ntdll.dll")) {
            return ApiContextOutcome::Unknown;
        }
        // returnStatusBits：原返回低 32 位，按位比较以保留 NTSTATUS 的负值编码。
        const auto returnStatusBits = static_cast<std::uint32_t>(packet.hookAddress);
        // resultStatusBits：独立 resultCode 的同宽位模式，高 32 位不参与原 NTSTATUS 判定。
        const auto resultStatusBits = static_cast<std::uint32_t>(packet.resultCode);
        if (returnStatusBits != resultStatusBits) {
            return ApiContextOutcome::Unknown;
        }
        if (packet.resultCode >= 0) {
            return ApiContextOutcome::Accepted;
        }
        return ApiContextOutcome::Failed;
    }

    if (api != L"SetThreadContext" ||
        (!moduleIs(L"kernel32") && !moduleIs(L"kernel32.dll") &&
         !moduleIs(L"kernelbase") && !moduleIs(L"kernelbase.dll"))) {
        return ApiContextOutcome::Unknown;
    }
    // Win32 源端保存原 BOOL 位和成功零状态/失败 LastError；拒绝非规范 BOOL 和矛盾成功码。
    if (packet.hookAddress > 1 || (packet.hookAddress != 0 && packet.resultCode != 0)) {
        return ApiContextOutcome::Unknown;
    }
    if (packet.hookAddress == 1) {
        return ApiContextOutcome::Accepted;
    }
    // 失败时原 LastError 即使为零仍保持原 BOOL 失败，不从残留错误码反推成功。
    return ApiContextOutcome::Failed;
}
}
