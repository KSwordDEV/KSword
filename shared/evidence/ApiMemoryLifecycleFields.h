#pragma once

#include "../WinApiMonitorProtocol.h"
#include "../ApiMonitorCallStack.h"
#include <algorithm>
#include <array>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>

namespace Ksword::Evidence {
// AAIM1 使用原详情槽；不修改1000B包、AAIP1或其它独立扩展的ABI。
inline constexpr std::uint32_t kApiMemoryLifecycleMarker = 0x4d4c5631u; // 生命周期独立标记。
inline constexpr std::wstring_view kApiMemoryLifecyclePrefix = L"AAIM1|"; // 文本编码版本。
enum class ApiMemoryOperation : std::uint64_t {
    Allocate = 1, // NtAllocateVirtualMemory请求和成功输出。
    Protect = 2, // NtProtectVirtualMemory请求和成功输出。
    Free = 3, // NtFreeVirtualMemory请求及返回，不推断释放范围。
    Unmap = 4, // NtUnmapViewOfSection直接基址请求；没有长度、输出范围或新保护。
};
enum ApiMemoryFlag : std::uint64_t {
    ApiMemoryActorIdentity = 1ull << 0, // 源创建时间查询成功。
    ApiMemoryTargetIdentity = 1ull << 1, // 原进程句柄的PID和创建时间均有效。
    ApiMemoryTargetStable = 1ull << 2, // 原调用前后目标强身份一致。
    ApiMemoryRequestedBase = 1ull << 3, // 输入base安全读取成功，可为零。
    ApiMemoryRequestedBytes = 1ull << 4, // 输入size安全读取成功，可为零。
    ApiMemoryOutputBase = 1ull << 5, // Allocate/Protect成功后安全读取base。
    ApiMemoryOutputBytes = 1ull << 6, // Allocate/Protect成功后安全读取size。
    ApiMemoryOldProtection = 1ull << 7, // Protect成功后安全读取原保护。
};
struct ApiMemoryLifecycleFieldsV1 {
    ApiMemoryOperation operation = ApiMemoryOperation::Allocate; // 明确的操作kind。
    std::uint64_t flags = 0; // 独立有效位，不由返回成功补齐。
    std::uint64_t pointerBits = 0; // 源调用ABI位数，不能拿读端位数代替。
    std::uint64_t actorCreationFileTime = 0; // 包头源PID的创建FILETIME。
    std::uint64_t targetPid = 0; // 查询失败保持零，不用报头PID回填。
    std::uint64_t targetCreationFileTime = 0; // 目标实例创建FILETIME。
    std::uint64_t requestedBase = 0; // 原调用前请求基址。
    std::uint64_t requestedBytes = 0; // 原调用前请求长度。
    std::uint64_t outputBase = 0; // 成功分配/改保护后的实际输出。
    std::uint64_t outputBytes = 0; // 成功分配/改保护后的实际输出长度。
    std::uint64_t allocationType = 0; // Allocate原AllocationType。
    std::uint64_t newProtection = 0; // Allocate初始保护或Protect新保护。
    std::uint64_t freeType = 0; // Free原FreeType。
    std::uint64_t oldProtection = 0; // 仅有效位成立时代表Protect旧保护。
    std::uint64_t inputProcessHandle = 0; // 输入句柄位模式，不是对象身份。
    std::uint64_t enterQpc = 0; // 原调用进入计数，查询失败为零。
    std::uint64_t returnQpc = 0; // 原调用返回计数，查询失败为零。
    std::int32_t status = 0; // 解析时从原packet状态读取，不重复编码。
    bool returnValid = false; // 解析时核验原返回marker和位模式后置true。
};
inline constexpr std::size_t kApiMemoryValueCount = 16; // kind已区分alloc/free，共用一个原type槽。
inline constexpr std::size_t kApiMemoryTextLength = kApiMemoryLifecyclePrefix.size() + kApiMemoryValueCount * 17 - 1;
static_assert(kApiMemoryTextLength < ks::winapi_monitor::kStackTrailerStart); // 保留原可选调用栈尾槽。

// StoreApiMemoryLifecycleFields：发送端将f写到p的独立详情槽，不修改返回/耗时/会话字段。
inline void StoreApiMemoryLifecycleFields(ks::winapi_monitor::ApiMonitorEventPacket& p,
    const ApiMemoryLifecycleFieldsV1& f) noexcept
{
    const std::array<std::uint64_t, kApiMemoryValueCount> values{ // 顺序属于AAIM1版本契约。
        static_cast<std::uint64_t>(f.operation), f.flags, f.pointerBits, f.actorCreationFileTime,
        f.targetPid, f.targetCreationFileTime, f.requestedBase, f.requestedBytes,
        f.outputBase, f.outputBytes, f.operation == ApiMemoryOperation::Free ? f.freeType : f.allocationType, f.newProtection,
        f.oldProtection, f.inputProcessHandle, f.enterQpc, f.returnQpc};
    std::fill(std::begin(p.detailText), std::end(p.detailText), L'\0');
    std::copy(kApiMemoryLifecyclePrefix.begin(), kApiMemoryLifecyclePrefix.end(), p.detailText);
    std::size_t cursor = kApiMemoryLifecyclePrefix.size(); // 下一字符位置。
    constexpr wchar_t digits[] = L"0123456789abcdef"; // 规范编码字符。
    for (std::size_t i = 0; i < values.size(); ++i) { // 当前字段下标。
        if (i) {
            p.detailText[cursor++] = L'|';
        }
        for (unsigned d = 0; d < 16; ++d) { // 当前十六进制位。
            p.detailText[cursor++] = digits[(values[i] >> ((15 - d) * 4)) & 15];
        }
    }
    p.coverageState = kApiMemoryLifecycleMarker;
}

// ReadApiMemoryLifecycleFields：核对完整原包和AAIM1，不从摘要或读端架构补造字段。
inline std::optional<ApiMemoryLifecycleFieldsV1> ReadApiMemoryLifecycleFields(
    const ks::winapi_monitor::ApiMonitorEventPacket& p) noexcept
{
    namespace m = ks::winapi_monitor;
    if (p.size != sizeof(p) || p.version != m::kProtocolVersion || !p.pid || !p.sessionIdentity ||
        p.eventKind != static_cast<std::uint32_t>(m::EventKind::ApiCall) ||
        p.category != static_cast<std::uint32_t>(m::EventCategory::Memory) ||
        p.hookKind != static_cast<std::uint32_t>(m::HookKind::Strong) ||
        p.resultKind != static_cast<std::uint32_t>(m::EventResultKind::StatusCode) ||
        p.snapshotIndex != m::kApiCallReturnValueMarker || p.coverageState != kApiMemoryLifecycleMarker ||
        !std::equal(kApiMemoryLifecyclePrefix.begin(), kApiMemoryLifecyclePrefix.end(), p.detailText) ||
        p.detailText[kApiMemoryTextLength] != L'\0') { // NUL之后仍允许原调用栈trailer。
        return std::nullopt;
    }
    std::array<std::uint64_t, kApiMemoryValueCount> v{}; // 未完成校验的局部值。
    std::size_t cursor = kApiMemoryLifecyclePrefix.size(); // 下一字符位置。
    for (std::size_t i = 0; i < v.size(); ++i) { // 当前解码字段。
        if (i && p.detailText[cursor++] != L'|') {
            return std::nullopt;
        }
        for (unsigned d = 0; d < 16; ++d) { // 当前十六进制位。
            const wchar_t c = p.detailText[cursor++]; // 当前包内字符。
            if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) {
                return std::nullopt;
            }
            v[i] = (v[i] << 4) | static_cast<std::uint64_t>(c <= L'9' ? c - L'0' : c - L'a' + 10);
        }
    }
    // 接受已定义四类操作，旧三类编码不变；NTSTATUS必须与原返回一致。
    if (v[0] < 1 || v[0] > 4 || (v[1] & ~255ull) || (v[2] != 32 && v[2] != 64) ||
        v[4] > UINT32_MAX || v[10] > UINT32_MAX || v[11] > UINT32_MAX ||
        v[12] > UINT32_MAX ||
        p.hookAddress != static_cast<std::uint32_t>(p.resultCode) ||
        (v[14] && v[15] && v[15] < v[14])) {
        return std::nullopt;
    }
    const auto flags = v[1]; // 字段有效位集合。
    const bool success = p.resultCode >= 0; // 原NT_SUCCESS语义，不解释为执行。
    if (((flags & ApiMemoryActorIdentity) ? !v[3] : v[3] != 0) ||
        ((flags & ApiMemoryTargetIdentity) ? (!v[4] || !v[5]) : (v[4] || v[5])) ||
        ((flags & ApiMemoryTargetStable) && !(flags & ApiMemoryTargetIdentity)) ||
        (!(flags & ApiMemoryRequestedBase) && v[6]) || (!(flags & ApiMemoryRequestedBytes) && v[7]) ||
        (!(flags & ApiMemoryOutputBase) && v[8]) || (!(flags & ApiMemoryOutputBytes) && v[9]) ||
        (!(flags & ApiMemoryOldProtection) && v[12]) ||
        ((!success || v[0] >= 3) && (flags & (ApiMemoryOutputBase | ApiMemoryOutputBytes | ApiMemoryOldProtection))) ||
        (v[0] != 2 && (flags & ApiMemoryOldProtection)) ||
        (v[0] == 2 && v[10]) || (v[0] >= 3 && v[11]) ||
        (v[0] == 4 && ((flags & ApiMemoryRequestedBytes) || v[7] || v[10]))) {
        return std::nullopt;
    }
    // 对原指针/size_t/句柄按源位宽核对，不能在x64读端接受伪造x86高位。
    if (v[2] == 32 && (v[6] > UINT32_MAX || v[7] > UINT32_MAX || v[8] > UINT32_MAX ||
        v[9] > UINT32_MAX || v[13] > UINT32_MAX)) {
        return std::nullopt;
    }
    const auto text = [](const auto& value) -> std::wstring_view { // value为定长字符数组，返回有界模块/导出名。
        const auto* end = std::find(std::begin(value), std::end(value), L'\0'); // 字段内终止位置。
        return end == std::end(value) ? std::wstring_view{} :
            std::wstring_view(value, static_cast<std::size_t>(end - value));
    };
    const auto module = text(p.moduleName); // 声明模块。
    const auto moduleIs = [&](std::wstring_view expected) { // 仅折叠ASCII大小写，不接受路径。
        return module.size() == expected.size() && std::equal(module.begin(), module.end(), expected.begin(),
            [](wchar_t c, wchar_t lower) { return (c >= L'A' && c <= L'Z' ? c + 32 : c) == lower; });
    };
    const std::wstring_view expectedApi = v[0] == 1 ? L"NtAllocateVirtualMemory" :
        v[0] == 2 ? L"NtProtectVirtualMemory" : v[0] == 3 ? L"NtFreeVirtualMemory" :
        L"NtUnmapViewOfSection"; // kind必须与原Hook精确匹配，不能让Free伪装为Unmap。
    if ((!moduleIs(L"ntdll") && !moduleIs(L"ntdll.dll")) || text(p.apiName) != expectedApi) {
        return std::nullopt;
    }
    return ApiMemoryLifecycleFieldsV1{static_cast<ApiMemoryOperation>(v[0]), v[1], v[2], v[3], v[4],
        v[5], v[6], v[7], v[8], v[9], v[0] == 1 ? v[10] : 0, v[11], v[0] == 3 ? v[10] : 0,
        v[12], v[13], v[14], v[15], p.resultCode, true};
}

// 字节入口先核对真实载荷长度，再复制解码；不访问短包或未对齐的存档内存。
inline std::optional<ApiMemoryLifecycleFieldsV1> ReadApiMemoryLifecycleFields(std::span<const std::byte> bytes) noexcept
{
    ks::winapi_monitor::ApiMonitorEventPacket packet{}; // 对齐且大小固定的本地值。
    if (bytes.size() != sizeof(packet)) {
        return std::nullopt;
    }
    std::memcpy(&packet, bytes.data(), sizeof(packet));
    return ReadApiMemoryLifecycleFields(packet);
}

// ApiMemoryLifecycleEventType：公开稳定语义，不把释放请求解释为已知释放全区。
inline std::string_view ApiMemoryLifecycleEventType(const ApiMemoryLifecycleFieldsV1& f) noexcept
{
    if (!f.returnValid) {
        return "memory-outcome-unknown";
    }
    if (f.operation == ApiMemoryOperation::Allocate) {
        return f.status >= 0 ? "memory-allocation-succeeded" : "memory-allocation-failed";
    }
    if (f.operation == ApiMemoryOperation::Free) {
        return f.status >= 0 ? "memory-release-request-succeeded" : "memory-release-request-failed";
    }
    if (f.operation == ApiMemoryOperation::Unmap)
    {
        return f.status >= 0 ? "memory-unmap-request-succeeded" : "memory-unmap-request-failed";
    }
    if (f.status < 0) {
        return "memory-protection-failed";
    }
    const auto protection = f.newProtection & 0xff; // 保留修饰位，仅按基础保护判断请求的X属性。
    return protection == PAGE_EXECUTE || protection == PAGE_EXECUTE_READ ||
        protection == PAGE_EXECUTE_READWRITE || protection == PAGE_EXECUTE_WRITECOPY
        ? "memory-executable-protection-succeeded" : "memory-protection-succeeded";
}
} // namespace Ksword::Evidence
