#include "BehaviorPresets.h"

#include <array>
#include <utility>

namespace Ksword::ActionAnalyze::Rules {
namespace {

struct PresetDefinition {
    std::string_view id; // 固定语义及版本，供证据回执核对。
    std::string_view predicate; // 单事件纯表达式，由生产解析器类型检查。
};

// 预置只采用现有原包归档已经校验的字段。没有进程实例、线程顺序或执行结论。
constexpr PresetDefinition Presets[] = {
    {"ksword.api.memory-operation-observed.v1", R"(api.family == "memory-write" || api.family == "section-map")"},
    {"ksword.api.thread-control-observed.v1", R"(api.family == "thread-create" || api.family == "thread-context" || api.family == "apc-queue")"}
};
constexpr FieldBinding Catalog[] = {{"api.family", FieldType::Text, Phase::Observation}};

} // namespace

ApiPresetReport AnalyzeArchivedApiPresets(std::span<const ArchivedApiObservation> rows, std::uint64_t importedRows)
{
    if (rows.size() > MaxApiPresetRows || rows.size() > importedRows || (rows.empty() && importedRows != 0)) {
        return {ApiPresetError::InvalidInput, importedRows, 0, {}};
    }
    std::array<PreparedPredicate, std::size(Presets)> compiled; // 单次回放冻结的已校验预置。
    for (std::size_t index = 0; index < compiled.size(); ++index) {
        auto prepared = PreparePredicateExpression(Presets[index].predicate, Phase::Observation, Catalog);
        if (prepared.error != ExpressionError::None) {
            return {ApiPresetError::InvalidPreset, importedRows, 0, {}};
        }
        compiled[index] = std::move(prepared.predicate);
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
        bool matched = false; // 每条已知源线索属于两个互斥类别之一。
        for (std::size_t index = 0; index < compiled.size(); ++index) {
            const auto evaluation = EvaluatePredicate(compiled[index], Phase::Observation, std::span(&field, 1));
            if (evaluation.fault != EvaluationFault::None) {
                return {ApiPresetError::InvalidInput, importedRows, 0, {}};
            }
            if (evaluation.truth == Truth::True) {
                report.matches.push_back({Presets[index].id, row.rawSequence, row.sourceSequence, std::string(row.api)});
                matched = true;
            }
        }
        if (!matched) { // 其它版本新增的未知分类需要显式适配才能进入该预置包。
            return {ApiPresetError::InvalidInput, importedRows, 0, {}};
        }
    }
    return report;
}

} // namespace Ksword::ActionAnalyze::Rules
