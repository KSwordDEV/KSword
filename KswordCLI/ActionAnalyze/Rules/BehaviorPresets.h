#pragma once

#include "RuleExpression.h"

#include <array>
#include <filesystem>
#include <optional>

#include "../../../shared/evidence/ApiMonitorClue.h"

namespace Ksword::ActionAnalyze::Rules {

inline constexpr std::size_t MaxApiPresetRows = 4096; // 与归档读侧的最近线索窗口相同。
inline constexpr wchar_t ApiPresetProfilePath[] = L"profiles/action_analyze_api_rules.json";

struct ArchivedApiMemoryWriteReturn {
    bool returned;
    std::uint32_t statusCode;
};

// 调用方须先验证 Stored 封装、原包分类和导入尾记。此投影不读文件或调用目标。
struct ArchivedApiObservation {
    std::uint64_t rawSequence; // Stored 行标识，与样本 UUID 一起引用。
    std::uint64_t sourceSequence; // API Monitor 原始归档行号。
    std::string_view api; // 经校验的精确导出名。
    std::string_view family; // 经校验的 API 线索类别。
    // 仅授权输入且有明确返回标记时，从同一原包投影。缺失时保留分类，不补造返回结论。
    std::optional<ArchivedApiMemoryWriteReturn> memoryWriteReturn = std::nullopt;
};

struct ApiPresetBehavior {
    std::string ruleId; // 行为规则版本；独立于原分类规则。
    std::string evidence; // 证据强度，而非目标身份、效果、意图或覆盖结论。
    std::string summary; // 规则文件中的默认释义。
    std::string summaryZh; // 可选的中文释义。
};

struct ApiPresetMatch {
    std::string ruleId; // 本轮冻结的规则 ID，结果拥有该文本。
    std::uint64_t rawSequence;
    std::uint64_t sourceSequence;
    std::string api; // 结果拥有数据，不引用下一次扫描的输入。
    std::optional<ApiPresetBehavior> behavior = std::nullopt; // 释义引用同一原包坐标。
};

enum class ApiPresetError { None, InvalidInput, InvalidPreset, EvaluationFailed };
enum class ApiPresetProfile { Grouped, ByCategory }; // 兼容汇总或细分到五类单事件线索。

struct ApiPresetDefinition {
    ApiPresetBehavior description; // 目录和命中共用的规则说明。
    std::string predicate; // 规则文件中的 UTF-8 谓词。
    PreparedPredicate prepared; // 装载时校验，分段时复用。
};

struct ApiPresetDatabase {
    std::string presetSet; // 本次加载的规则版本。
    std::string error; // 加载失败的诊断；成功时为空。
    std::array<std::vector<ApiPresetDefinition>, 2> profiles; // 汇总、细分两个回放配置。
    std::vector<ApiPresetDefinition> behaviorRules; // 同一观测按文件顺序选首条命中释义。
};

// 读取应用目录下的规则文件，输出可在一次采样或回放期间冻结的已准备数据库。
ApiPresetDatabase LoadApiPresetDatabase();
ApiPresetDatabase LoadApiPresetDatabase(const std::filesystem::path& path);
// 用运行时实际字段或已准备规则枚举目录，无须复制规则定义。
std::span<const FieldBinding> ApiPresetFields(bool behavior);
std::span<const ApiPresetDefinition> ApiClassificationPresets(const ApiPresetDatabase& database, ApiPresetProfile profile);

struct ApiPresetReport {
    ApiPresetError error = ApiPresetError::None;
    std::uint64_t importedRows = 0; // 归档读端核对的线索总数，不代表采集覆盖。
    std::size_t analyzedRows = 0; // 此次实际分析的窗口。
    std::vector<ApiPresetMatch> matches;
};

// 按单条已归档观测分类，有经验证返回证据时可附加行为释义。
// 默认按内存操作和线程控制汇总，也可按线索类别细分。
// 每条线索保留原始输入顺序及两套序号，坏输入不会发布部分命中。
ApiPresetReport AnalyzeArchivedApiPresets(const ApiPresetDatabase& database, std::span<const ArchivedApiObservation> rows,
    std::uint64_t importedRows, ApiPresetProfile profile = ApiPresetProfile::Grouped);

// 已获严格读回的一页。采样内两套序号均须递增，但计划、非线索原包或分页可能造成跳号。
// 页为空时仍可返回成功。verifiedClueRows 仅表示此次归档扫描确认的线索总数。
ApiPresetReport AnalyzeVerifiedApiPresetPage(const ApiPresetDatabase& database, std::span<const ArchivedApiObservation> rows,
    std::uint64_t verifiedClueRows, ApiPresetProfile profile = ApiPresetProfile::Grouped);

// 仅在检查点发布成功后传入原样回读的一批连续原包，含非线索包，不含计划和尾记。
// 两套序号从检查点的 planRawSequence 和 previousSourceSequence 各加 1 开始；段号由调用方保留。
// 使用实时跟随的五类预置；无命中是成功，失败不发布部分匹配，也不改变已提交原包。
ApiPresetReport AnalyzeCommittedApiPresetBatch(const ApiPresetDatabase& database,
    std::span<const ks::winapi_monitor::ApiMonitorEventPacket> packets,
    std::uint64_t planRawSequence, std::uint64_t previousSourceSequence) noexcept;
ApiPresetReport AnalyzeCommittedApiPresetBatch(const ApiPresetDatabase& database,
    std::span<const Evidence::ArchivedApiMonitorClue> rows,
    std::uint64_t planRawSequence, std::uint64_t previousSourceSequence) noexcept;

} // namespace Ksword::ActionAnalyze::Rules
