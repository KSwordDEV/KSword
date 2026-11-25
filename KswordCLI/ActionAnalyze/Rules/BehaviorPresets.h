#pragma once

#include "RuleExpression.h"

namespace Ksword::ActionAnalyze::Rules {

inline constexpr std::size_t MaxApiPresetRows = 4096; // 与归档读侧的最近线索窗口相同。

// 调用方须先验证 Stored 封装、原包分类和导入尾记。此投影不读文件或调用目标。
struct ArchivedApiObservation {
    std::uint64_t rawSequence; // Stored 行标识，与样本 UUID 一起引用。
    std::uint64_t sourceSequence; // API Monitor 原始归档行号。
    std::string_view api; // 经校验的精确导出名。
    std::string_view family; // 经校验的 API 线索类别。
};

struct ApiPresetMatch {
    std::string_view ruleId; // 静态带版本的预置 ID。
    std::uint64_t rawSequence;
    std::uint64_t sourceSequence;
    std::string api; // 结果拥有数据，不引用下一次扫描的输入。
};

enum class ApiPresetError { None, InvalidInput, InvalidPreset };

struct ApiPresetReport {
    ApiPresetError error = ApiPresetError::None;
    std::uint64_t importedRows = 0; // 尾记及扫描确认的总数，不代表采集覆盖。
    std::size_t analyzedRows = 0; // 此次实际分析的最近窗口。
    std::vector<ApiPresetMatch> matches;
};

// 仅归类单条已归档观测。两组预置分别对应内存操作 API 与线程控制 API。
// 按原始输入顺序返回证据，保留明确的窗口计数，坏输入不会发布部分命中。
ApiPresetReport AnalyzeArchivedApiPresets(std::span<const ArchivedApiObservation> rows,
    std::uint64_t importedRows);

} // namespace Ksword::ActionAnalyze::Rules
