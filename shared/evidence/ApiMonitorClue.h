#pragma once

#include "EvidenceJson.h"
#include "../WinApiMonitorProtocol.h"

#include <algorithm>
#include <cstring>
#include <string_view>

namespace Ksword::Evidence {

// 精确导出及分类表。命中只表示观察到相关 API，身份核对和执行确认由独立来源提供。
struct ApiMonitorClue {
    std::wstring_view api; // 事件包中的规范导出名。
    std::string_view family; // 归档、筛选和回放共用的线索类别。
    ks::winapi_monitor::EventCategory category; // 声明中的业务分类。
    bool native; // 模块来自 ntdll，或来自 KernelBase/kernel32 转发族。
};

// 从定长包字段读取字符串。缺失终止符时返回空视图，避免越界解释原始归档。
template<std::size_t N>
std::wstring_view ApiMonitorPacketText(const wchar_t (&text)[N]) noexcept
{
    const auto* end = std::find(text, text + N, L'\0'); // 包内第一处终止符。
    if (end == text + N) {
        return {};
    }
    return {text, static_cast<std::size_t>(end - text)};
}

// 验证包封装、模块、导出名和业务分类，返回静态类别或空指针。支持既有强类型和入口摘要。
inline const ApiMonitorClue* ClassifyApiMonitorClue(const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
{
    using namespace ks::winapi_monitor;
    using C = EventCategory;
    static constexpr ApiMonitorClue catalog[] = {
        {L"WriteProcessMemory", "memory-write", C::Memory, false},
        {L"NtWriteVirtualMemory", "memory-write", C::Memory, true},
        {L"CreateRemoteThread", "thread-create", C::Thread, false},
        {L"CreateRemoteThreadEx", "thread-create", C::Thread, false},
        {L"NtCreateThreadEx", "thread-create", C::Thread, true},
        {L"QueueUserAPC", "apc-queue", C::Thread, false},
        {L"QueueUserAPC2", "apc-queue", C::Thread, false},
        {L"NtQueueApcThread", "apc-queue", C::Thread, true},
        {L"NtQueueApcThreadEx", "apc-queue", C::Thread, true},
        {L"SetThreadContext", "thread-context", C::Thread, false},
        {L"Wow64SetThreadContext", "thread-context", C::Thread, false},
        {L"NtSetContextThread", "thread-context", C::Thread, true},
        {L"NtMapViewOfSection", "section-map", C::Memory, true},
    }; // 已有专用处理器或声明表中的导出。
    if (packet.size != sizeof(packet) || packet.version != kProtocolVersion ||
        packet.eventKind != static_cast<std::uint32_t>(EventKind::ApiCall) ||
        (packet.category != static_cast<std::uint32_t>(C::Memory) &&
         packet.category != static_cast<std::uint32_t>(C::Thread))) {
        return nullptr;
    }

    // 比较限于已读到终止符的模块名和值，ASCII 模块名不受区域设置影响。
    const auto module = ApiMonitorPacketText(packet.moduleName); // 包报告的模块名。
    const auto api = ApiMonitorPacketText(packet.apiName); // 包报告的精确导出名。
    const auto matchesModule = [&](std::wstring_view expected) {
        return std::ranges::equal(module, expected, [](wchar_t value, wchar_t lower) {
            return (value >= L'A' && value <= L'Z' ? value + (L'a' - L'A') : value) == lower;
        });
    };
    const bool native = matchesModule(L"ntdll") || matchesModule(L"ntdll.dll"); // 原生模块族。
    const bool win32 = matchesModule(L"kernelbase") || matchesModule(L"kernelbase.dll") ||
        matchesModule(L"kernel32") || matchesModule(L"kernel32.dll"); // Win32 包装器模块族。
    for (const auto& item : catalog) { // 仅匹配表内同模块族、同分类的精确导出。
        if ((item.native ? native : win32) && api == item.api && packet.category == static_cast<std::uint32_t>(item.category)) {
            return &item;
        }
    }
    return nullptr;
}

struct ApiMonitorMemoryWriteReturn {
    bool returned; // WriteProcessMemory 的 BOOL 返回值。
    std::uint32_t statusCode; // 同一包中报告的 Win32 状态；失败时来自 GetLastError。
};

// 仅投影已校验来源的结构字段。不能用摘要文字、原始入口槽位或单独的状态码补造返回值。
inline std::optional<ApiMonitorMemoryWriteReturn> ReadApiMonitorMemoryWriteReturn(
    const ks::winapi_monitor::ApiMonitorEventPacket& packet) noexcept
{
    using namespace ks::winapi_monitor;
    if (packet.hookKind != static_cast<std::uint32_t>(HookKind::Strong) ||
        packet.resultKind != static_cast<std::uint32_t>(EventResultKind::StatusCode) ||
        packet.snapshotIndex != kApiCallReturnValueMarker || (packet.hookAddress >> 32) != 0) {
        return std::nullopt;
    }
    const auto* clue = ClassifyApiMonitorClue(packet);
    if (!clue || clue->api != L"WriteProcessMemory") {
        return std::nullopt;
    }
    return ApiMonitorMemoryWriteReturn{packet.hookAddress != 0, static_cast<std::uint32_t>(packet.resultCode)};
}

// 从 Stored raw 读取线索及源归档坐标。readerCreation 是文件声明，不能充当已认证的现场身份。
struct ArchivedApiMonitorClue {
    ks::winapi_monitor::ApiMonitorEventPacket packet; // 已核对大小及分类的原始协议包。
    const ApiMonitorClue* clue = nullptr; // 重新从包计算的静态类别。
    std::uint64_t sourceSequence = 0; // 源序号的语义由整段尾记说明。
    std::uint64_t readerCreation = 0; // 源归档声明的调用方创建时间，缺失为零。
};

inline constexpr std::string_view kApiMonitorClueRecord = "api-monitor-clue-v1"; // RawRecord 内的来源类型。
inline constexpr std::string_view kApiMonitorClueEnd = "api-monitor-clue-import-end-v1"; // 导入尾部回执。

// 尾记声明输入方式，不代表已重新认证历史生产者。
enum class ApiMonitorArchiveSource { LegacyUnspecified, ClosedJsonl, CooperativePipe };

// 返回写端及三个读端共用的稳定来源标识。
constexpr std::string_view ApiMonitorArchiveSourceName(ApiMonitorArchiveSource source) noexcept
{
    switch (source) {
    case ApiMonitorArchiveSource::ClosedJsonl:
        return "closed-jsonl";
    case ApiMonitorArchiveSource::CooperativePipe:
        return "cooperative-pipe";
    case ApiMonitorArchiveSource::LegacyUnspecified:
        return "legacy-unspecified";
    }
    return "legacy-unspecified";
}

// 只读已解封的尾记；省略字段兼容旧档，显式无效值产生空返回。
inline std::optional<ApiMonitorArchiveSource> ReadApiMonitorArchiveSource(const JsonValue& terminal)
{
    const auto* field = terminal.find("archiveSource"); // 来源方式只由尾记声明。
    if (!field) {
        return ApiMonitorArchiveSource::LegacyUnspecified;
    }
    std::string name; // 字符串以外的 JSON 类型不兼容。
    if (field->tryGetString(name)) {
        if (name == ApiMonitorArchiveSourceName(ApiMonitorArchiveSource::ClosedJsonl)) {
            return ApiMonitorArchiveSource::ClosedJsonl;
        }
        if (name == ApiMonitorArchiveSourceName(ApiMonitorArchiveSource::CooperativePipe)) {
            return ApiMonitorArchiveSource::CooperativePipe;
        }
    }
    return std::nullopt;
}

// 用明确的版本类型识别导入段，即使首条线索的数据已损坏也进入严格校验。
inline bool IsApiMonitorClueImport(const JsonValue& metadata)
{
    const auto* kind = metadata.find("kind"); // 本记录声明的类型。
    std::string type; // 从有效 JSON 提取的名称。
    return kind && kind->tryGetString(type) && (type == kApiMonitorClueRecord || type == kApiMonitorClueEnd);
}

// 输入为解封后的 RawRecord 元数据与原包字节。返回可回放线索或不匹配的空值。
inline std::optional<ArchivedApiMonitorClue> ReadArchivedApiMonitorClue(const JsonValue& metadata,
    std::string_view bytes)
{
    const auto* kind = metadata.find("kind"); // 来源元数据中的版本化类型。
    const auto* sequence = metadata.find("sourceSequence"); // 借用原行号字段。
    const auto* creation = metadata.find("readerCreation100ns"); // 调用方身份声明可缺失。
    ArchivedApiMonitorClue result; // 回放持有的独立值。
    std::string type; // 解码后的类型名。
    if (!kind || !kind->tryGetString(type) || type != kApiMonitorClueRecord ||
        bytes.size() != sizeof(result.packet) || !sequence ||
        !sequence->tryGetU64(result.sourceSequence) || !result.sourceSequence ||
        (creation && (!creation->tryGetU64(result.readerCreation) || !result.readerCreation))) {
        return std::nullopt;
    }

    // 原包决定线索及身份提示。导入者不写回或覆盖任何原包字段。
    std::memcpy(&result.packet, bytes.data(), bytes.size());
    result.clue = ClassifyApiMonitorClue(result.packet);
    if (!result.clue || !result.packet.pid || !result.packet.sessionIdentity) {
        return std::nullopt;
    }
    return result;
}

// 对单个导入段验证原始行顺序和尾记。调用方仍需独立验证 Stored 封装及实际扫描边界。
struct ApiMonitorClueReadback {
    std::uint64_t sourceSequence = 0; // 最后见到的源序号。
    std::uint64_t sourceRows = 0; // 尾记声明的篇幅，包括未保留的源项。
    std::uint64_t clues = 0; // 已核对的线索数。
    bool ended = false; // 最后一条必须是计数匹配的导入尾记。
    ApiMonitorArchiveSource source = ApiMonitorArchiveSource::LegacyUnspecified; // 只有合法尾记才更新。

    // 从已解码的 RawRecord 读取一条记录。合法尾记返回 true 且 row 为空。
    bool Accept(const JsonValue& metadata, std::string_view bytes, std::optional<ArchivedApiMonitorClue>& row)
    {
        if (ended) {
            return false;
        }
        row = ReadArchivedApiMonitorClue(metadata, bytes);
        if (row) {
            if (row->sourceSequence <= sourceSequence) {
                return false;
            }
            sourceSequence = row->sourceSequence;
            ++clues;
            return true;
        }

        // 尾记验证导入的结构和计数。源端覆盖与运行效果仍保持未知。
        const auto* kind = metadata.find("kind"); // 版本化导入尾记类型。
        const auto* scanned = metadata.find("sourceRows"); // 原归档行数包含已略过的记录。
        const auto* retained = metadata.find("clueRows"); // 导入者计数声明。
        std::string type; // 解码后的尾记类型名。
        std::uint64_t count = 0; // 与本次核对的线索数比较。
        const auto declaredSource = ReadApiMonitorArchiveSource(metadata); // 可选的原始输入方式。
        ended = declaredSource && clues > 0 && bytes.empty() && kind && kind->tryGetString(type) && type == kApiMonitorClueEnd &&
            scanned && scanned->tryGetU64(sourceRows) && sourceRows >= sourceSequence && retained &&
            retained->tryGetU64(count) && count == clues;
        if (ended) {
            source = *declaredSource;
        }
        return ended;
    }
};

} // namespace Ksword::Evidence
