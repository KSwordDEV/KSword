#pragma once

#include "../WinApiMonitorProtocol.h"
#include <algorithm>
#include <array>
#include <optional>
#include <string_view>

namespace Ksword::Evidence {

// 独立于 AAIP1 的 APC 入队协议；接受入队不表示投递，也不表示执行。
// kApiApcFieldsMarker：普通业务包中用于识别本协议的显式标记。
inline constexpr std::uint32_t kApiApcFieldsMarker = 0x41505631u;
// kApiApcFieldsPrefix：固定文本布局的版本前缀。
inline constexpr std::wstring_view kApiApcFieldsPrefix = L"AAAP1|";

// ApiApcFieldFlag：逐项说明真实采到的身份、参数及复核结果。
enum ApiApcFieldFlag : std::uint64_t {
    ApiApcActorIdentity = 1ull << 0, // 已采到包头源 PID 对应的创建时间。
    ApiApcTargetIdentity = 1ull << 1, // 已采到目标 PID 和创建时间。
    ApiApcThreadIdentity = 1ull << 2, // 已从输入句柄采到目标 TID 和创建时间。
    ApiApcRoutineAddress = 1ull << 3, // 已记录原请求例程地址，允许请求值为零。
    ApiApcTargetStable = 1ull << 4, // 调用前后的目标进程和线程身份复核一致。
};

// ApiApcOperation：本版本只表达一次入队请求，不能解释为其它协议的 operation。
enum class ApiApcOperation : std::uint64_t {
    Queue = 1, // 调用 APC 入队接口。
};

// ApiApcFieldsV1：固定字段顺序；缺少有效位的身份字段保持零。
struct ApiApcFieldsV1 {
    ApiApcOperation operation = ApiApcOperation::Queue; // 本条记录的操作类型。
    std::uint64_t flags = 0; // ApiApcFieldFlag 有效位集合。
    std::uint64_t actorCreationFileTime = 0; // 包头源 PID 对应的创建 FILETIME。
    std::uint64_t targetPid = 0; // 原线程句柄解析出的所属进程 PID。
    std::uint64_t targetCreationFileTime = 0; // 所属进程的创建 FILETIME。
    std::uint64_t targetTid = 0; // 原线程句柄解析出的线程 TID。
    std::uint64_t targetThreadCreationFileTime = 0; // 目标线程的创建 FILETIME。
    std::uint64_t routineAddress = 0; // 请求例程地址，不能视为已执行地址。
    std::uint64_t enterQpc = 0; // 原 API 调用前的 QPC。
    std::uint64_t returnQpc = 0; // 原 API 返回后、额外查询前的 QPC。
    std::uint64_t inputThreadHandle = 0; // 原输入句柄位模式，不独立提供身份。
    std::uint64_t argument1 = 0; // 原始第一个 APC 参数；Win32 接口对应 data。
    std::uint64_t argument2 = 0; // NT 原始第二个参数；Win32 接口不存在此参数。
    std::uint64_t argument3 = 0; // NT 原始第三个参数；Win32 接口不存在此参数。
    std::uint64_t reserveHandle = 0; // NtQueueApcThreadEx 的 Reserve 句柄位模式，其它接口保持零。
};

// kApiApcValueCount：当前 AAAP1 文本编码的数值个数；旧档案仍按14个字段读取。
inline constexpr std::size_t kApiApcValueCount = 15;
inline constexpr std::size_t kApiApcLegacyValueCount = 14;
// 文本长度由前缀、十六进制字段和分隔符共同决定，不含终止符。
inline constexpr std::size_t kApiApcTextLength = kApiApcFieldsPrefix.size() + kApiApcValueCount * 17 - 1;
inline constexpr std::size_t kApiApcLegacyTextLength =
    kApiApcFieldsPrefix.size() + kApiApcLegacyValueCount * 17 - 1;
static_assert(kApiApcTextLength < ks::winapi_monitor::kMaxDetailChars);
static_assert(kApiApcLegacyTextLength < ks::winapi_monitor::kMaxDetailChars);

// StoreApiApcFields：把 fields 按固定顺序写入 packet，保留包中原返回、耗时和定义摘要。
inline void StoreApiApcFields(ks::winapi_monitor::ApiMonitorEventPacket& packet,
    const ApiApcFieldsV1& fields) noexcept
{
    // values：与公开字段顺序严格一致的待编码值。
    const std::array<std::uint64_t, kApiApcValueCount> values{
        static_cast<std::uint64_t>(fields.operation),
        fields.flags,
        fields.actorCreationFileTime,
        fields.targetPid,
        fields.targetCreationFileTime,
        fields.targetTid,
        fields.targetThreadCreationFileTime,
        fields.routineAddress,
        fields.enterQpc,
        fields.returnQpc,
        fields.inputThreadHandle,
        fields.argument1,
        fields.argument2,
        fields.argument3,
        fields.reserveHandle,
    };
    std::fill(std::begin(packet.detailText), std::end(packet.detailText), L'\0');
    std::copy(kApiApcFieldsPrefix.begin(), kApiApcFieldsPrefix.end(), packet.detailText);
    std::size_t cursor = kApiApcFieldsPrefix.size(); // 下一处文本写入位置。
    constexpr wchar_t digits[] = L"0123456789abcdef"; // 规范小写十六进制字符表。
    for (std::size_t index = 0; index < values.size(); ++index) { // 当前字段序号。
        if (index) {
            packet.detailText[cursor++] = L'|';
        }
        for (unsigned digit = 0; digit < 16; ++digit) { // 当前字段的十六进制位序。
            packet.detailText[cursor++] = digits[(values[index] >> ((15 - digit) * 4)) & 15];
        }
    }
    packet.coverageState = kApiApcFieldsMarker;
}

// ReadApiApcFields：只解码 packet 中显式标记的完整 AAAP1，任何布局/有效位矛盾均拒绝。
inline std::optional<ApiApcFieldsV1> ReadApiApcFields(
    const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
{
    namespace monitor = ks::winapi_monitor;
    if (packet.size != sizeof(packet) || packet.version != monitor::kProtocolVersion ||
        packet.eventKind != static_cast<std::uint32_t>(monitor::EventKind::ApiCall) ||
        packet.category != static_cast<std::uint32_t>(monitor::EventCategory::Thread) ||
        packet.hookKind != static_cast<std::uint32_t>(monitor::HookKind::Strong) ||
        packet.snapshotIndex != monitor::kApiCallReturnValueMarker ||
        packet.coverageState != kApiApcFieldsMarker ||
        !std::equal(kApiApcFieldsPrefix.begin(), kApiApcFieldsPrefix.end(), packet.detailText) ||
        packet.detailText[kApiApcTextLength] != L'\0') {
        return std::nullopt;
    }
    // 先按终止位置识别新旧布局；旧包的扩展字段保持零，保证历史档案可回读。
    const std::size_t valueCount = packet.detailText[kApiApcLegacyTextLength] == L'\0'
        ? kApiApcLegacyValueCount : kApiApcValueCount;
    std::array<std::uint64_t, kApiApcValueCount> values{}; // 验证成功前的局部解码值。
    std::size_t cursor = kApiApcFieldsPrefix.size(); // 下一处文本读取位置。
    for (std::size_t index = 0; index < valueCount; ++index) { // 当前字段序号。
        if (index && packet.detailText[cursor++] != L'|') {
            return std::nullopt;
        }
        for (unsigned digit = 0; digit < 16; ++digit) { // 当前字段的十六进制位序。
            const wchar_t c = packet.detailText[cursor++]; // 本次读取的编码字符。
            if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
                return std::nullopt;
            }
            values[index] = (values[index] << 4) | static_cast<std::uint64_t>(
                c <= L'9' ? c - L'0' : c - L'a' + 10);
        }
    }
    if (values[0] != 1 || (values[1] & ~31ull) || values[3] > UINT32_MAX ||
        values[5] > UINT32_MAX || !values[8] || values[9] < values[8]) {
        return std::nullopt;
    }
    const auto flags = values[1]; // 单独命名有效位，核对字段是否与声明一致。
    if (((flags & ApiApcActorIdentity) ? values[2] == 0 : values[2] != 0) ||
        ((flags & ApiApcTargetIdentity) ? (!values[3] || !values[4]) : (values[3] || values[4])) ||
        ((flags & ApiApcThreadIdentity) ? (!values[5] || !values[6]) : (values[5] || values[6])) ||
        (!(flags & ApiApcRoutineAddress) && values[7]) ||
        ((flags & ApiApcTargetStable) && (flags & (ApiApcTargetIdentity | ApiApcThreadIdentity)) !=
            (ApiApcTargetIdentity | ApiApcThreadIdentity))) {
        return std::nullopt;
    }
    return ApiApcFieldsV1{
        ApiApcOperation::Queue,
        values[1],
        values[2],
        values[3],
        values[4],
        values[5],
        values[6],
        values[7],
        values[8],
        values[9],
        values[10],
        values[11],
        values[12],
        values[13],
        values[14],
    };
}

// ApiApcQueueOutcome：仅说明入队接口的返回语义，不包含投递或执行状态。
enum class ApiApcQueueOutcome {
    Unknown, // 缺字段、来源不符或原返回和状态互相矛盾。
    Failed, // 原 API 明确返回失败。
    Accepted, // 原 API 接受入队请求，不证明投递或执行。
};

// ApiApcCallOutcome：核对 packet 的精确 API/模块族及原始返回，消费者仍须核对来源身份。
inline ApiApcQueueOutcome ApiApcCallOutcome(const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
{
    namespace monitor = ks::winapi_monitor;
    if (!ReadApiApcFields(packet) ||
        packet.resultKind != static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode)) {
        return ApiApcQueueOutcome::Unknown;
    }
    // text：从 value 定长数组取得有界字符串，缺失终止符时返回空视图。
    const auto text = [](const auto& value) -> std::wstring_view {
        const auto* end = std::find(std::begin(value), std::end(value), L'\0'); // 字符串终止位置。
        return end == std::end(value) ? std::wstring_view{} : std::wstring_view(value, end - value);
    };
    const auto api = text(packet.apiName); // 包报告的精确导出名。
    const auto module = text(packet.moduleName); // 包报告的模块名。
    // moduleIs：以 expected 小写模块名进行 ASCII 大小写无关匹配。
    const auto moduleIs = [&](std::wstring_view expected) {
        return module.size() == expected.size() && std::equal(module.begin(), module.end(), expected.begin(),
            [](wchar_t value, wchar_t lower) {
                // value 是包中字符，lower 是预期小写字符；仅折叠 ASCII 大写字母。
                return (value >= L'A' && value <= L'Z' ? value + (L'a' - L'A') : value) == lower;
            });
    };
    if (api == L"NtQueueApcThread" || api == L"NtQueueApcThreadEx") {
        if (!moduleIs(L"ntdll") && !moduleIs(L"ntdll.dll")) {
            return ApiApcQueueOutcome::Unknown;
        }
        if (static_cast<std::int32_t>(packet.hookAddress) != packet.resultCode) {
            return ApiApcQueueOutcome::Unknown;
        }
        return packet.resultCode >= 0 ? ApiApcQueueOutcome::Accepted : ApiApcQueueOutcome::Failed;
    }
    // 两个Win32入口均以非零返回表示入队已接受；特殊APC标志不改变执行证据边界。
    if ((api != L"QueueUserAPC" && api != L"QueueUserAPC2") ||
        (!moduleIs(L"kernelbase") && !moduleIs(L"kernelbase.dll") &&
         !moduleIs(L"kernel32") && !moduleIs(L"kernel32.dll")) || packet.hookAddress > UINT32_MAX ||
        (packet.hookAddress && packet.resultCode)) {
        return ApiApcQueueOutcome::Unknown;
    }
    return packet.hookAddress ? ApiApcQueueOutcome::Accepted : ApiApcQueueOutcome::Failed;
}
} // namespace Ksword::Evidence
