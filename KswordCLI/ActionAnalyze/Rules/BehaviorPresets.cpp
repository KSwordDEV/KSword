#include "BehaviorPresets.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <bcrypt.h>

#include <filesystem>
#include <fstream>
#include <ranges>
#include <set>
#include <utility>

#pragma comment(lib, "bcrypt.lib")

namespace Ksword::ActionAnalyze::Rules {
namespace {

constexpr FieldBinding Catalog[] = {{"api.family", FieldType::Text, Phase::Observation}};
// 字段来自已核验原包。返回字段缺失时保留 NotCollected。
constexpr FieldBinding BehaviorCatalog[] = {
    {"api.family", FieldType::Text, Phase::Observation},
    {"api.name", FieldType::Text, Phase::Observation},
    {"result.returned", FieldType::Bool, Phase::Observation},
    {"result.win32Status", FieldType::U64, Phase::Observation},
};

constexpr std::size_t kMaxProfileBytes = 1024 * 1024; // 限制本地规则数据读入量。

// 对实际交给 JSON 解析器的有界缓冲求摘要，不重新打开可能已被替换的文件。
std::string SourceSha256(std::string_view bytes)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        return {};
    }
    std::array<UCHAR, 32> digest{};
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        return {};
    }
    constexpr std::string_view hex = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (const auto byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 15]);
    }
    return result;
}

// 从 JSON 对象读取必填且非空的文本。
bool ReadText(const Evidence::JsonValue& object, std::string_view field, std::string& output)
{
    const auto* value = object.find(field); // 当前规则对象中指定的键。
    return value && value->tryGetString(output) && !output.empty() && output.find('\0') == output.npos;
}

// 样本计划、目录和回放共用同一版本及规则 ID 字符集。
bool ValidId(std::string_view value)
{
    return !value.empty() && value.size() <= 128 && value.find_first_not_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._") == value.npos;
}

// 校验数组及表达式，任一错误均由调用方丢弃整份数据库。
std::string ReadPresets(const Evidence::JsonValue* value, bool behavior,
    std::set<std::string>& ids, std::vector<ApiPresetDefinition>& definitions)
{
    const auto* rows = value ? value->asArray() : nullptr; // 文件顺序用于选择行为释义。
    if (!rows || rows->size() > 128 || (!behavior && rows->empty())) {
        return "rules-profile-invalid-list";
    }
    for (const auto& row : *rows) {
        ApiPresetDefinition rule; // 完整解析和类型校验后才进入数据库。
        auto& text = rule.description;
        if (!ReadText(row, "ruleId", text.ruleId) || !ValidId(text.ruleId) || !ids.insert(text.ruleId).second ||
            !ReadText(row, "predicate", rule.predicate) || !ReadText(row, "summary", text.summary)) {
            return "rules-profile-invalid-entry";
        }
        if (row.find("summaryZh") && !ReadText(row, "summaryZh", text.summaryZh)) {
            return "rules-profile-invalid-entry";
        }
        text.evidence = behavior ? "reported-api-return" : "classified-api-observation";
        auto result = PreparePredicateExpression(rule.predicate, Phase::Observation, behavior ?
            std::span<const FieldBinding>(BehaviorCatalog) : std::span<const FieldBinding>(Catalog));
        if (result.error != ExpressionError::None) {
            return std::string("rules-profile-invalid-predicate/") + text.ruleId + "/" + std::string(ExpressionErrorId(result.error));
        }
        rule.prepared = std::move(result.predicate);
        definitions.push_back(std::move(rule));
    }
    return {};
}

// 丢弃任何部分解析的规则，同时返回可定位失败原因的诊断。
ApiPresetDatabase ProfileError(std::string detail)
{
    ApiPresetDatabase database;
    database.error = std::move(detail);
    return database;
}

// 对已经加载的同一版本求值。单条线索必须匹配一个分类。
ApiPresetReport AnalyzePresetRows(const ApiPresetDatabase& database, std::span<const ArchivedApiObservation> rows,
    std::uint64_t verifiedClueRows, ApiPresetProfile profile, std::optional<std::uint64_t> contiguousAfter)
{
    if (rows.size() > MaxApiPresetRows || rows.size() > verifiedClueRows) {
        return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
    }
    const auto presets = ApiClassificationPresets(database, profile);
    if (!database.error.empty() || presets.empty()) {
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
        for (const auto& preset : presets) {
            const auto evaluation = EvaluatePredicate(preset.prepared, Phase::Observation, std::span(&field, 1));
            if (evaluation.fault != EvaluationFault::None || evaluation.truth == Truth::Unknown) {
                return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
            }
            if (evaluation.truth == Truth::True) {
                if (!ruleId.empty()) {
                    return {ApiPresetError::InvalidPreset, verifiedClueRows, 0, {}};
                }
                ruleId = preset.description.ruleId;
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
            for (const auto& preset : database.behaviorRules) {
                const auto evaluation = EvaluatePredicate(preset.prepared, Phase::Observation, fields);
                if (evaluation.fault != EvaluationFault::None) {
                    return {ApiPresetError::InvalidInput, verifiedClueRows, 0, {}};
                }
                if (evaluation.truth == Truth::True) {
                    behavior = preset.description;
                    break;
                }
            }
        }
        report.matches.push_back({std::string(ruleId), row.rawSequence, row.sourceSequence, std::string(row.api), std::move(behavior)});
    }
    return report;
}

// 从连续的已提交原包投影规则输入，分类输入缺失时仍推进两套原始编号。
template<class PacketRange>
ApiPresetReport AnalyzeCommittedPackets(const ApiPresetDatabase& database, const PacketRange& packets, std::uint64_t planRawSequence,
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
        return AnalyzeVerifiedApiPresetPage(database, observations, observations.size(), ApiPresetProfile::ByCategory);
    } catch (...) {
        return {ApiPresetError::EvaluationFailed, 0, 0, {}};
    }
}

} // namespace

ApiPresetDatabase LoadApiPresetDatabase()
{
    try {
        std::wstring image(32768, L'\0'); // 当前进程映像绝对路径。
        const auto length = GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
        if (!length || length >= image.size()) {
            return ProfileError("rules-profile-path-unavailable");
        }
        image.resize(length);
        return LoadApiPresetDatabase(std::filesystem::path(image).parent_path() / ApiPresetProfilePath);
    } catch (...) {
        return ProfileError("rules-profile-load-failed");
    }
}

ApiPresetDatabase LoadApiPresetDatabase(const std::filesystem::path& path)
{
    try {
        std::ifstream input(path, std::ios::binary);
        if (!input) {
            return ProfileError("rules-profile-unavailable");
        }
        std::string bytes(kMaxProfileBytes + 1, '\0'); // 多读一个字节以识别超限。
        input.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (input.bad() || !input.eof()) {
            return ProfileError(input.bad() ? "rules-profile-read-failed" : "rules-profile-too-large");
        }
        bytes.resize(static_cast<std::size_t>(input.gcount()));
        const auto json = Evidence::ParseJson(bytes, {8, MaxPredicateExpressionBytes, 128, 4096, kMaxProfileBytes});
        if (!json.ok()) {
            return ProfileError(std::string("rules-profile-json/") + Evidence::JsonParseStatusName(json.status));
        }
        ApiPresetDatabase database;
        std::uint64_t schema = 0; // 仅接受当前模式的规则数据。
        const auto* version = json.value.find("schemaVersion");
        const auto* profiles = json.value.find("profiles");
        if (!version || version->type() != Evidence::JsonType::UInt || !version->tryGetU64(schema) || schema != 1 ||
            !ReadText(json.value, "presetSet", database.presetSet) || !ValidId(database.presetSet) || !profiles) {
            return ProfileError("rules-profile-invalid-header");
        }
        std::set<std::string> ids; // 分类及释义共用规则 ID 空间。
        for (const auto& [profile, target] : {std::pair{"grouped", &database.profiles[0]},
                 std::pair{"by-category", &database.profiles[1]}}) {
            if (auto error = ReadPresets(profiles->find(profile), false, ids, *target); !error.empty()) {
                return ProfileError(std::move(error));
            }
        }
        if (auto error = ReadPresets(json.value.find("behaviorRules"), true, ids, database.behaviorRules); !error.empty()) {
            return ProfileError(std::move(error));
        }
        database.sourceSha256 = SourceSha256(bytes); // 解析与摘要使用同一份原字节，只在完整成功后发布身份。
        if (database.sourceSha256.empty()) {
            return ProfileError("rules-profile-sha256-failed");
        }
        return database;
    } catch (...) {
        return ProfileError("rules-profile-load-failed");
    }
}

std::span<const FieldBinding> ApiPresetFields(bool behavior)
{
    return behavior ? std::span<const FieldBinding>(BehaviorCatalog) : std::span<const FieldBinding>(Catalog);
}

std::span<const ApiPresetDefinition> ApiClassificationPresets(const ApiPresetDatabase& database, ApiPresetProfile profile)
{
    switch (profile) {
    case ApiPresetProfile::Grouped: return database.profiles[0];
    case ApiPresetProfile::ByCategory: return database.profiles[1];
    }
    return {};
}

ApiPresetReport AnalyzeArchivedApiPresets(const ApiPresetDatabase& database, std::span<const ArchivedApiObservation> rows,
    std::uint64_t importedRows, ApiPresetProfile profile)
{
    if (rows.size() > importedRows || (rows.empty() && importedRows != 0)) {
        return {ApiPresetError::InvalidInput, importedRows, 0, {}};
    }
    return AnalyzePresetRows(database, rows, importedRows, profile, importedRows - rows.size());
}

ApiPresetReport AnalyzeVerifiedApiPresetPage(const ApiPresetDatabase& database, std::span<const ArchivedApiObservation> rows,
    std::uint64_t verifiedClueRows, ApiPresetProfile profile)
{
    return AnalyzePresetRows(database, rows, verifiedClueRows, profile, std::nullopt);
}

ApiPresetReport AnalyzeCommittedApiPresetBatch(const ApiPresetDatabase& database,
    std::span<const ks::winapi_monitor::ApiMonitorEventPacket> packets,
    std::uint64_t planRawSequence, std::uint64_t previousSourceSequence) noexcept
{
    return AnalyzeCommittedPackets(database, packets, planRawSequence, previousSourceSequence);
}

ApiPresetReport AnalyzeCommittedApiPresetBatch(const ApiPresetDatabase& database,
    std::span<const Evidence::ArchivedApiMonitorClue> rows,
    std::uint64_t planRawSequence, std::uint64_t previousSourceSequence) noexcept
{
    const auto packets = rows | std::views::transform(&Evidence::ArchivedApiMonitorClue::packet);
    return AnalyzeCommittedPackets(database, packets, planRawSequence, previousSourceSequence);
}

} // namespace Ksword::ActionAnalyze::Rules
