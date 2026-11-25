#include "BehaviorPresets.h"

#include <utility>

namespace Ksword::ActionAnalyze::Rules {
namespace {

struct PresetDefinition {
    std::string_view id; // 固定语义及版本，供证据回执核对。
    std::string_view predicate; // 单事件纯表达式，由生产解析器类型检查。
};

// 预置只采用现有原包归档已经校验的字段。没有进程实例、线程顺序或执行结论。
constexpr PresetDefinition GroupedPresets[] = {
    {"ksword.api.memory-operation-observed.v1", R"(api.family == "memory-write" || api.family == "section-map")"},
    {"ksword.api.thread-control-observed.v1", R"(api.family == "thread-create" || api.family == "thread-context" || api.family == "apc-queue")"}
};
// 精细回查保留实际的类别。每条规则只报告观察到相关 API。
constexpr PresetDefinition CategoryPresets[] = {
    {"ksword.api.memory-write-observed.v1", R"(api.family == "memory-write")"},
    {"ksword.api.section-map-observed.v1", R"(api.family == "section-map")"},
    {"ksword.api.thread-create-observed.v1", R"(api.family == "thread-create")"},
    {"ksword.api.thread-context-observed.v1", R"(api.family == "thread-context")"},
    {"ksword.api.apc-queue-observed.v1", R"(api.family == "apc-queue")"},
};
constexpr FieldBinding Catalog[] = {{"api.family", FieldType::Text, Phase::Observation}};

// 按显式选择返回固定预置表，未经登记的模式返回空视图。
std::span<const PresetDefinition> SelectPresets(ApiPresetProfile profile)
{
    switch (profile) {
    case ApiPresetProfile::Grouped: return GroupedPresets;
    case ApiPresetProfile::ByCategory: return CategoryPresets;
    }
    return {};
}

} // namespace

ApiPresetReport AnalyzeArchivedApiPresets(std::span<const ArchivedApiObservation> rows,
    std::uint64_t importedRows, ApiPresetProfile profile)
{
    if (rows.size() > MaxApiPresetRows || rows.size() > importedRows || (rows.empty() && importedRows != 0)) {
        return {ApiPresetError::InvalidInput, importedRows, 0, {}};
    }
    const auto presets = SelectPresets(profile); // 本次分析显式选定的预置表。
    if (presets.empty()) {
        return {ApiPresetError::InvalidPreset, importedRows, 0, {}};
    }
    std::vector<PreparedPredicate> compiled; // 回放期间冻结已校验的预置。
    compiled.reserve(presets.size());
    for (const auto& preset : presets) {
        auto prepared = PreparePredicateExpression(preset.predicate, Phase::Observation, Catalog); // 静态阶段和类型检查。
        if (prepared.error != ExpressionError::None) {
            return {ApiPresetError::InvalidPreset, importedRows, 0, {}};
        }
        compiled.push_back(std::move(prepared.predicate));
    }

    ApiPresetReport report{ApiPresetError::None, importedRows, rows.size(), {}}; // 只在确定时返回窗口结果。
    report.matches.reserve(rows.size());
    std::uint64_t lastRaw = importedRows - rows.size(); // 最近窗口之前的 Stored 线索条数。
    std::uint64_t lastSource = 0; // 原始归档按行的严格递增位置，可以跳号。
    for (const auto& row : rows) {
        if (row.rawSequence <= lastRaw || row.rawSequence - lastRaw != 1 || row.sourceSequence <= lastSource ||
            row.api.empty() || row.api.size() > MaxKeyBytes || row.family.empty() || row.family.size() > MaxKeyBytes) {
            return {ApiPresetError::InvalidInput, importedRows, 0, {}};
        }
        lastRaw = row.rawSequence;
        lastSource = row.sourceSequence;
        const FieldSample field{"api.family", Quality::Known, row.family}; // 单条线索的已确认分类。
        std::string_view ruleId; // 每条线索在当前预置表内应有且仅有一个归属。
        for (std::size_t index = 0; index < compiled.size(); ++index) {
            const auto evaluation = EvaluatePredicate(compiled[index], Phase::Observation, std::span(&field, 1));
            if (evaluation.fault != EvaluationFault::None || evaluation.truth == Truth::Unknown) {
                return {ApiPresetError::InvalidInput, importedRows, 0, {}};
            }
            if (evaluation.truth == Truth::True) {
                if (!ruleId.empty()) {
                    return {ApiPresetError::InvalidPreset, importedRows, 0, {}};
                }
                ruleId = presets[index].id;
            }
        }
        if (ruleId.empty()) { // 新分类需显式登记后才能进入预置包。
            return {ApiPresetError::InvalidInput, importedRows, 0, {}};
        }
        report.matches.push_back({ruleId, row.rawSequence, row.sourceSequence, std::string(row.api)});
    }
    return report;
}

} // namespace Ksword::ActionAnalyze::Rules
