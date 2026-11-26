#pragma once

#include "ApiTransferCandidateWindow.h"
#include "../../KswordCLI/ActionAnalyze/Detection/NativeTransferAssociation.h"
#include "../../KswordCLI/ActionAnalyze/Detection/NativeSectionMapAssociation.h"

#include <functional>
#include <deque>
#include <optional>
#include <vector>

namespace Ksword::Evidence {

enum class NativeHistoryState { NotRequested, Complete, Failed, Limited, Canceled };

// 状态独立于 API 主读回执；完整空链、坏链和窗口限额不会互相冒充。
struct NativeExecutionHistory {
    NativeHistoryState state = NativeHistoryState::NotRequested; // 本次原生链读取状态。
    ActionAnalyze::ProjectResult problem; // 失败的精确项目错误与阶段。
    std::uint64_t failedOrdinal = 0; // 坏段或首个超预算段。
    std::vector<ActionAnalyze::ArchivedNativeExecution> records; // 从第一段连续核验的历史文档。
};

// 在已有后台项目任务中调用；只读同采样 raw-native，逐段传递前一序号。
NativeExecutionHistory ReadNativeExecutionHistory(const ActionAnalyze::ProjectDocument& project,
    std::string_view sample, const std::function<bool()>& canceled = {});

// 两端共用同一份规范来源文档，native 包含未经推断改写的完整原生文档。
JsonValue NativeExecutionSourceDocument(int kind, const ActionAnalyze::Detection::EvidenceRef* write,
    const ActionAnalyze::Detection::EvidenceRef& request,
    const ActionAnalyze::ArchivedNativeExecution& execution, std::uint64_t ordinal,
    const ActionAnalyze::Detection::ArchivedGraphRecord& requestRecord, std::optional<std::uint64_t> writeOffset,
    std::string_view mappingSha256 = {});

// 单独的历史观察没有API请求；两端按这些物理坐标恢复选择，完整文档只供读取。
struct NativeExecutionHistoryEntry {
    std::uint64_t nativeOrdinal = 0; // raw-native的真实段号。
    std::uint64_t nativeSequence = 0; // 该段原记录序号。
    std::uint64_t nativeRecordOffset = 0; // 核验得到的记录头偏移。
    std::string nativeSha256; // 原段摘要，防止同坐标内容变化后沿用选择。
    JsonValue sourceDocument; // 同一归档文档用于详情、复制与导出。
};

// 输入已核验的段及真实段号，输出独立历史来源；不创建API关联或活控制令牌。
NativeExecutionHistoryEntry NativeExecutionHistorySource(
    const ActionAnalyze::ArchivedNativeExecution& execution, std::uint64_t ordinal);

// 输入两次发布的历史叶项，返回物理来源是否相同；不按PID或树下标认领旧选择。
inline bool SameNativeExecutionHistory(const NativeExecutionHistoryEntry& left,
    const NativeExecutionHistoryEntry& right)
{
    return left.nativeOrdinal == right.nativeOrdinal && left.nativeSequence == right.nativeSequence &&
        left.nativeRecordOffset == right.nativeRecordOffset && left.nativeSha256 == right.nativeSha256;
}

template<typename Row>
struct ApiNativeExecutionCandidate {
    int kind = 0; // 0 创建，1 APC，2 上下文，3 内存范围（映射/分配/保护）。
    std::optional<Row> write; // 映射没有写入前置条件，其余保留真实写入原行。
    Row request; // 实际 API 请求原行，支持主表窗口之外定位。
    std::uint64_t nativeOrdinal = 0; // 独立 raw-native 的真实段号。
    std::uint64_t nativeSequence = 0; // 原生记录的真实序号。
    std::uint64_t nativeRecordOffset = 0; // 原生记录头在已核验段中的真实偏移。
    std::string nativeSha256; // 同坐标文件替换后不能静默继承旧选择。
    JsonValue sourceDocument; // 两端选择详情唯一规范源，保留原始声明和所有边界。
};

template<typename Row>
struct ApiNativeExecutionProjection {
    NativeHistoryState state = NativeHistoryState::NotRequested; // 原生读取结果，独立于候选数量。
    ActionAnalyze::ProjectResult problem; // 本次失败原因，不掩盖 API 已成功读取的前缀。
    std::uint64_t failedOrdinal = 0; // 坏段或限额位置。
    std::uint64_t verifiedNativeCount = 0; // 实际通过核验的原生记录总数。
    std::uint64_t candidateCount = 0; // 当前 API 窗口内全部匹配数，包含结果裁剪。
    std::uint64_t evictedMaps = 0; // API 映射输入窗口淘汰数。
    std::deque<ApiNativeExecutionCandidate<Row>> candidates; // 最近 512 个一致性候选，常数开销淘汰旧项。
    std::deque<NativeExecutionHistoryEntry> observations; // 最近512条独立观察，匹配不到API也保留。
};

// 后台项目任务传入同采样的已核验API窗口、原生历史和取消回调，返回有界只读候选与独立状态。
// 匹配只调用CLI核心；本层保存来源和限额，不比较跨来源QPC或生成新推断。
template<typename Row>
ApiNativeExecutionProjection<Row> ProjectApiNativeExecution(
    const ActionAnalyze::Detection::SampleScope& scope, const NativeExecutionHistory& history,
    const std::vector<ApiTransferCandidateRows<Row>>& threads,
    const std::vector<ApiApcCandidateRows<Row>>& apcs,
    const std::vector<ApiContextCandidateRows<Row>>& contexts,
    const std::vector<ApiSectionMapCandidateRow<Row>>& maps, std::uint64_t evictedMaps,
    const std::function<bool()>& canceled = {})
{
    namespace detection = ActionAnalyze::Detection;
    ApiNativeExecutionProjection<Row> result; // 失败状态也发布，API 树仍使用原有候选。
    result.state = history.state;
    result.problem = history.problem;
    result.failedOrdinal = history.failedOrdinal;
    result.verifiedNativeCount = history.records.size();
    result.evictedMaps = evictedMaps;
    if (history.state == NativeHistoryState::Failed || history.state == NativeHistoryState::Canceled)
    {
        return result;
    }
    // 每个候选保存类型、双方原坐标和独立原生坐标；绝不建立跨来源 QPC 排序。
    const auto append = [&](int kind, const Row* write, const Row& request,
        const detection::EvidenceRef* writeRef, const detection::EvidenceRef& requestRef,
        const detection::ArchivedGraphRecord& requestRecord,
        const ActionAnalyze::ArchivedNativeExecution& execution, std::uint64_t ordinal, std::string_view mappingSha256 = {}) {
        ++result.candidateCount;
        if (result.candidates.size() == 512)
        {
            result.candidates.pop_front();
        }
        result.candidates.push_back({kind, write ? std::optional<Row>(*write) : std::nullopt,
            request, ordinal, execution.end.lastSequence, execution.recordOffset, execution.sha256,
            NativeExecutionSourceDocument(kind, writeRef, requestRef, execution, ordinal, requestRecord,
                write ? std::optional<std::uint64_t>(write->offset) : std::nullopt, mappingSha256)});
    };
    for (std::size_t index = 0; index < history.records.size(); ++index)
    {
        if (canceled && canceled())
        {
            result.state = NativeHistoryState::Canceled;
            result.candidates.clear();
            result.observations.clear();
            result.candidateCount = 0;
            return result; // 取消只影响原生投影，API已核验窗口仍由原读任务保留。
        }
        const auto& native = history.records[index]; // 已从首段连续核验的原生文档。
        const auto ordinal = static_cast<std::uint64_t>(index + 1); // 不采用 UI 行号作为段号。
        if (result.observations.size() == 512)
        {
            result.observations.pop_front();
        }
        result.observations.push_back(NativeExecutionHistorySource(native, ordinal));
        for (const auto& pair : threads)
        {
            if (detection::AssociateNativeTransfer(scope, pair.link, pair.requestRecord, native, ordinal))
            {
                append(0, &pair.write, pair.threadCreate, &pair.link.write, pair.link.threadCreate,
                    pair.requestRecord, native, ordinal);
            }
        }
        // APC 与上下文分别按原线程代次、实际指令地址及共享核心的精确约束匹配。
        for (const auto& pair : apcs)
        {
            if (detection::AssociateNativeApcTransfer(scope, pair.link, pair.requestRecord, native, ordinal))
            {
                append(1, &pair.write, pair.queue, &pair.link.write, pair.link.queue, pair.requestRecord, native, ordinal);
            }
        }
        for (const auto& pair : contexts)
        {
            if (detection::AssociateNativeContextTransfer(scope, pair.link, pair.requestRecord, native, ordinal))
            {
                append(2, &pair.write, pair.context, &pair.link.write, pair.link.context, pair.requestRecord, native, ordinal);
            }
        }
        // 三种范围请求共用独立输入窗口；核心各自核对成功实际输出，不凭句柄或请求地址补造写入。
        for (const auto& mapping : maps)
        {
            if (detection::AssociateNativeSectionMap(scope, mapping.evidence, mapping.record,
                mapping.sha256, native, ordinal) || detection::AssociateNativeMemoryRange(scope, mapping.evidence,
                    mapping.record, mapping.sha256, native, ordinal))
            {
                append(3, nullptr, mapping.row, nullptr, mapping.evidence, mapping.record, native, ordinal, mapping.sha256);
            }
        }
    }
    return result;
}

} // namespace Ksword::Evidence
