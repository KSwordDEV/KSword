#pragma once

#include "../WinApiMonitorProtocol.h"
#include "ApiMonitorClue.h"

#include <array>
#include <optional>
#include <string_view>

namespace Ksword::Evidence {

// 普通强类型 API 包的显式扩展标记；固定 1000 字节 ABI 和覆盖包语义保持不变。
inline constexpr std::uint32_t kApiInjectionFieldsMarker = 0x49505631u;
inline constexpr std::wstring_view kApiInjectionFieldsPrefix = L"AAIP1|";

enum class ApiInjectionOperation : std::uint64_t { MemoryWrite = 1, ThreadCreate = 2 };

// 每个有效位只对应实际采到的字段；没有位的字段保持零，不从摘要补值。
enum ApiInjectionFieldFlag : std::uint64_t {
    ApiInjectionActorIdentity = 1ull << 0,
    ApiInjectionTargetIdentity = 1ull << 1,
    ApiInjectionThreadIdentity = 1ull << 2,
    ApiInjectionCompletedLength = 1ull << 3,
    ApiInjectionAddress = 1ull << 4,
    ApiInjectionStartAddress = 1ull << 5,
    ApiInjectionTargetStable = 1ull << 6,
};

// 源端在同次调用窗口取值。目标身份是句柄解析结果，单独保存前后复核标志，不保证实际执行。
struct ApiInjectionFieldsV1 {
    ApiInjectionOperation operation = ApiInjectionOperation::MemoryWrite; // 精确操作种类。
    std::uint64_t flags = 0; // 上方字段有效位。
    std::uint64_t actorCreationFileTime = 0; // 包头 PID 对应的源进程创建时间。
    std::uint64_t targetPid = 0; // 本次句柄解析得到的目标 PID。
    std::uint64_t targetCreationFileTime = 0; // 同一目标对象的创建时间。
    std::uint64_t targetTid = 0; // 创建成功后的真实线程 ID。
    std::uint64_t targetThreadCreationFileTime = 0; // 从返回线程句柄查询的创建时间。
    std::uint64_t address = 0; // 写入区间起点，是否有效由单独标志决定。
    std::uint64_t requestedBytes = 0; // 原调用要求的写入长度。
    std::uint64_t completedBytes = 0; // 安全读取到的完成长度，不用请求值代替。
    std::uint64_t startAddress = 0; // 请求的线程入口，不代表线程已经执行。
    std::uint64_t enterQpc = 0; // 调用前的本机 QPC。
    std::uint64_t returnQpc = 0; // 返回后、遥测查询前的本机 QPC。
    std::uint64_t inputHandle = 0; // 原调用输入句柄，只作原始参数，不独立提供身份。
};

inline constexpr std::size_t kApiInjectionValueCount = 14;
inline constexpr std::size_t kApiInjectionTextLength = kApiInjectionFieldsPrefix.size() +
    kApiInjectionValueCount * 16 + kApiInjectionValueCount - 1;
static_assert(kApiInjectionTextLength < ks::winapi_monitor::kMaxDetailChars);

// 将源端已采集的值编码进普通包的专用详情槽。返回/耗时标志和声明摘要由原发送路径管理。
inline void StoreApiInjectionFields(ks::winapi_monitor::ApiMonitorEventPacket& packet,
    const ApiInjectionFieldsV1& fields) noexcept
{
    const std::array<std::uint64_t, kApiInjectionValueCount> values{
        static_cast<std::uint64_t>(fields.operation), fields.flags, fields.actorCreationFileTime,
        fields.targetPid, fields.targetCreationFileTime, fields.targetTid, fields.targetThreadCreationFileTime,
        fields.address, fields.requestedBytes, fields.completedBytes, fields.startAddress,
        fields.enterQpc, fields.returnQpc, fields.inputHandle};
    std::fill(std::begin(packet.detailText), std::end(packet.detailText), L'\0');
    std::copy(kApiInjectionFieldsPrefix.begin(), kApiInjectionFieldsPrefix.end(), packet.detailText);
    std::size_t cursor = kApiInjectionFieldsPrefix.size(); // 固定格式只写入界内的十六进制字符。
    constexpr wchar_t digits[] = L"0123456789abcdef";
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index) packet.detailText[cursor++] = L'|';
        for (unsigned digit = 0; digit < 16; ++digit) {
            packet.detailText[cursor++] = digits[(values[index] >> ((15 - digit) * 4)) & 15];
        }
    }
    packet.coverageState = kApiInjectionFieldsMarker;
}

// 只解码显式标记的固定格式；旧摘要、原始入口槽位和截断文本均不能变成结构化证据。
inline std::optional<ApiInjectionFieldsV1> ReadApiInjectionFields(
    const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
{
    namespace monitor = ks::winapi_monitor;
    if (packet.size != sizeof(packet) || packet.version != monitor::kProtocolVersion ||
        packet.eventKind != static_cast<std::uint32_t>(monitor::EventKind::ApiCall) ||
        packet.hookKind != static_cast<std::uint32_t>(monitor::HookKind::Strong) ||
        packet.coverageState != kApiInjectionFieldsMarker ||
        packet.snapshotIndex != monitor::kApiCallReturnValueMarker ||
        !std::equal(kApiInjectionFieldsPrefix.begin(), kApiInjectionFieldsPrefix.end(), packet.detailText) ||
        packet.detailText[kApiInjectionTextLength] != L'\0') {
        return std::nullopt;
    }
    std::array<std::uint64_t, kApiInjectionValueCount> values{}; // 无分配解码，同一包一次性成功或失败。
    std::size_t cursor = kApiInjectionFieldsPrefix.size();
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index && packet.detailText[cursor++] != L'|') return std::nullopt;
        for (unsigned digit = 0; digit < 16; ++digit) {
            const auto character = packet.detailText[cursor++]; // 只接受规范小写十六进制。
            if (!((character >= L'0' && character <= L'9') || (character >= L'a' && character <= L'f'))) {
                return std::nullopt;
            }
            values[index] = (values[index] << 4) | static_cast<std::uint64_t>(
                character <= L'9' ? character - L'0' : character - L'a' + 10);
        }
    }
    if ((values[0] != 1 && values[0] != 2) || (values[1] & ~127ull) ||
        values[3] > UINT32_MAX || values[5] > UINT32_MAX ||
        !values[11] || values[12] < values[11]) {
        return std::nullopt;
    }
    return ApiInjectionFieldsV1{static_cast<ApiInjectionOperation>(values[0]), values[1], values[2],
        values[3], values[4], values[5], values[6], values[7], values[8], values[9], values[10],
        values[11], values[12], values[13]};
}

enum class ApiInjectionOutcome { Unknown, Failed, Succeeded, Partial };

// 对已接入AAIP1的写入和线程创建API核对返回语义；NTSTATUS不与Win32 BOOL/HANDLE混用。
inline ApiInjectionOutcome ApiInjectionCallOutcome(const ks::winapi_monitor::ApiMonitorEventPacket& packet,
    const ApiInjectionFieldsV1& fields) noexcept
{
    namespace monitor = ks::winapi_monitor;
    const auto* clue = ClassifyApiMonitorClue(packet); // 已核对模块族、导出名及类别。
    if (!clue || packet.resultKind != static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode)) {
        return ApiInjectionOutcome::Unknown;
    }
    const bool write = fields.operation == ApiInjectionOperation::MemoryWrite;
    const bool native = clue->api == L"NtWriteVirtualMemory" || clue->api == L"NtCreateThreadEx";
    if ((write && clue->api != L"WriteProcessMemory" && clue->api != L"NtWriteVirtualMemory") ||
        (!write && clue->api != L"CreateRemoteThread" && clue->api != L"CreateRemoteThreadEx" &&
            clue->api != L"NtCreateThreadEx")) {
        return ApiInjectionOutcome::Unknown;
    }
    // 返回字段和独立状态码不一致时保留未知，不根据 API 名称修补原包。
    if ((native && static_cast<std::int32_t>(packet.hookAddress) != packet.resultCode) ||
        (!native && packet.hookAddress != 0 && packet.resultCode != 0) ||
        (!native && write && packet.hookAddress > UINT32_MAX)) {
        return ApiInjectionOutcome::Unknown;
    }
    const bool succeeded = native ? packet.resultCode >= 0 : packet.hookAddress != 0;
    if (write && (fields.flags & ApiInjectionCompletedLength)) {
        // AAIP1源端只在成功且安全读回时发布完成长度；失败携带完成位是矛盾原包，不生成写入候选。
        if (!succeeded || fields.completedBytes > fields.requestedBytes) return ApiInjectionOutcome::Unknown;
        if (fields.completedBytes && fields.completedBytes < fields.requestedBytes) {
            return ApiInjectionOutcome::Partial;
        }
    }
    return succeeded ? ApiInjectionOutcome::Succeeded : ApiInjectionOutcome::Failed;
}

} // namespace Ksword::Evidence
