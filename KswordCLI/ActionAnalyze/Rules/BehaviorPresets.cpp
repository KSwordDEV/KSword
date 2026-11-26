#include "BehaviorPresets.h"

#include <ranges>
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

// BOOL 为 FALSE 且同包 Win32 状态为 ERROR_ACCESS_DENIED (5)。不读取 detailText，也不据此判断写入量或目标。
constexpr PresetDefinition MemoryWriteAccessDenied{
    "ksword.behavior.memory-write-access-denied-return.v1",
    R"(api.family == "memory-write" && api.name == "WriteProcessMemory" && !result.returned && result.win32Status == 5u64)"
};
constexpr FieldBinding BehaviorCatalog[] = {
    {"api.family", FieldType::Text, Phase::Observation},
    {"api.name", FieldType::Text, Phase::Observation},
    {"result.returned", FieldType::Bool, Phase::Observation},
    {"result.win32Status", FieldType::U64, Phase::Observation},
};

// 按显式选择返回固定预置表，未经登记的模式返回空视图。
std::span<const PresetDefinition> SelectPresets(ApiPresetProfile profile)
{
    switch (profile) {
    case ApiPresetProfile::Grouped: return GroupedPresets;
    case ApiPresetProfile::ByCategory: return CategoryPresets;
    }
    return {};
}

ApiPresetReport AnalyzePresetRows(std::span<const ArchivedApiObservation> rows,
    std::uint64_t verifiedClueRows, ApiPresetProfile profile, std::optional<std::uint64_t> contiguousAfter)
{
    if (rows.size() > MaxApiPresetRows || rows.size() > verifiedClueRows) {
        return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
    }
    const auto presets = SelectPresets(profile); // 本次分析显式选定的预置表。
    if (presets.empty()) {
        return {ApiPresetError::InvalidPreset, verifiedClueRows, 0, {}};
    }
    std::vector<PreparedPredicate> compiled; // 回放期间冻结已校验的预置。
    compiled.reserve(presets.size());
    for (const auto& preset : presets) {
        auto prepared = PreparePredicateExpression(preset.predicate, Phase::Observation, Catalog); // 静态阶段和类型检查。
        if (prepared.error != ExpressionError::None) {
            return {ApiPresetError::InvalidPreset, verifiedClueRows, 0, {}};
        }
        compiled.push_back(std::move(prepared.predicate));
    }
    const auto behaviorPredicate = PreparePredicateExpression(MemoryWriteAccessDenied.predicate, Phase::Observation, BehaviorCatalog);
    if (behaviorPredicate.error != ExpressionError::None) {
        return {ApiPresetError::InvalidPreset, verifiedClueRows, 0, {}};
    }

    ApiPresetReport report{ApiPresetError::None, verifiedClueRows, rows.size(), {}}; // 只在确定时返回窗口结果。
    report.matches.reserve(rows.size());
    std::uint64_t lastRaw = contiguousAfter.value_or(0); // 旧归档按线索连续编号，检查点页允许有空隙。
    std::uint64_t lastSource = 0; // 原始归档按行的严格递增位置，可以跳号。
    for (const auto& row : rows) {
        if (row.rawSequence <= lastRaw || (contiguousAfter && row.rawSequence - lastRaw != 1) || row.sourceSequence <= lastSource ||
            row.api.empty() || row.api.size() > MaxKeyBytes || row.family.empty() || row.family.size() > MaxKeyBytes) {
            return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
        }
        lastRaw = row.rawSequence;
        lastSource = row.sourceSequence;
        const FieldSample field{"api.family", Quality::Known, row.family}; // 单条线索的已确认分类。
        std::string_view ruleId; // 每条线索在当前预置表内应有且仅有一个归属。
        for (std::size_t index = 0; index < compiled.size(); ++index) {
            const auto evaluation = EvaluatePredicate(compiled[index], Phase::Observation, std::span(&field, 1));
            if (evaluation.fault != EvaluationFault::None || evaluation.truth == Truth::Unknown) {
                return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
            }
            if (evaluation.truth == Truth::True) {
                if (!ruleId.empty()) {
                    return {ApiPresetError::InvalidPreset, verifiedClueRows, 0, {}};
                }
                ruleId = presets[index].id;
            }
        }
        if (ruleId.empty()) { // 新分类需显式登记后才能进入预置包。
            return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
        }
        std::optional<ApiPresetBehavior> behavior;
        if (const auto& returned = row.memoryWriteReturn) {
            const FieldSample fields[] = {
                field, {"api.name", Quality::Known, row.api},
                {"result.returned", Quality::Known, returned->returned},
                {"result.win32Status", Quality::Known, static_cast<std::uint64_t>(returned->statusCode)},
            };
            const auto evaluation = EvaluatePredicate(behaviorPredicate.predicate, Phase::Observation, fields);
            if (evaluation.fault != EvaluationFault::None) {
                return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
            }
            if (evaluation.truth == Truth::True) {
                behavior = ApiPresetBehavior{MemoryWriteAccessDenied.id, "reported-api-return"};
            }
        }
        report.matches.push_back({ruleId, row.rawSequence, row.sourceSequence, std::string(row.api), behavior});
    }
    return report;
}

template<class PacketRange>
ApiPresetReport AnalyzeCommittedPackets(const PacketRange& packets, std::uint64_t planRawSequence,
    std::uint64_t previousSourceSequence) noexcept
{
    if (!planRawSequence || packets.size() > MaxApiPresetRows ||
        packets.size() > UINT64_MAX - planRawSequence || packets.size() > UINT64_MAX - previousSourceSequence) {
        return {ApiPresetError::InvalidInput, 0, 0, {}};
    }

    try {
        std::vector<std::string> names;
        std::vector<ArchivedApiObservation> observations;
        names.reserve(packets.size());
        observations.reserve(packets.size());
        auto rawSequence = planRawSequence;
        auto sourceSequence = previousSourceSequence;
        for (const auto& packet : packets) {
            ++rawSequence;
            ++sourceSequence;
            const auto* clue = Evidence::ClassifyApiMonitorClue(packet);
            if (!clue) {
                continue;
            }
            auto& name = names.emplace_back(); // 目录名均为 ASCII；保留存储供观测视图借用。
            for (const auto character : clue->api) {
                name.push_back(static_cast<char>(character));
            }
            const auto outcome = Evidence::ReadApiMonitorMemoryWriteReturn(packet);
            observations.push_back({rawSequence, sourceSequence, name, clue->family,
                outcome ? std::optional{ArchivedApiMemoryWriteReturn{outcome->returned, outcome->statusCode}} : std::nullopt});
        }
        if (observations.empty()) {
            return {};
        }
        return AnalyzeVerifiedApiPresetPage(observations, observations.size(), ApiPresetProfile::ByCategory);
    } catch (...) {
        return {ApiPresetError::EvaluationFailed, 0, 0, {}};
    }
}

} // namespace

ApiPresetReport AnalyzeArchivedApiPresets(std::span<const ArchivedApiObservation> rows,
    std::uint64_t importedRows, ApiPresetProfile profile)
{
    if (rows.size() > importedRows || (rows.empty() && importedRows != 0)) {
        return {ApiPresetError::InvalidInput, importedRows, 0, {}};
    }
    return AnalyzePresetRows(rows, importedRows, profile, importedRows - rows.size());
}

ApiPresetReport AnalyzeVerifiedApiPresetPage(std::span<const ArchivedApiObservation> rows,
    std::uint64_t verifiedClueRows, ApiPresetProfile profile)
{
    return AnalyzePresetRows(rows, verifiedClueRows, profile, std::nullopt);
}

ApiPresetReport AnalyzeCommittedApiPresetBatch(std::span<const ks::winapi_monitor::ApiMonitorEventPacket> packets,
    std::uint64_t planRawSequence, std::uint64_t previousSourceSequence) noexcept
{
    return AnalyzeCommittedPackets(packets, planRawSequence, previousSourceSequence);
}

ApiPresetReport AnalyzeCommittedApiPresetBatch(std::span<const Evidence::ArchivedApiMonitorClue> rows,
    std::uint64_t planRawSequence, std::uint64_t previousSourceSequence) noexcept
{
    const auto packets = rows | std::views::transform(&Evidence::ArchivedApiMonitorClue::packet);
    return AnalyzeCommittedPackets(packets, planRawSequence, previousSourceSequence);
}

} // namespace Ksword::ActionAnalyze::Rules
