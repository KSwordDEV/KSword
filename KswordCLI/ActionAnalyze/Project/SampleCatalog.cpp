#include "SampleCatalog.h"

#include <algorithm>
#include <optional>
#include <unordered_set>

namespace Ksword::ActionAnalyze {
using namespace ProjectStorage;

namespace {

JsonObject SummaryFields(const SampleInfo& sample) {
    return {{"sampleId", Text(sample.sampleId)}, {"title", Text(sample.title)},
            {"createdUtc", Number(sample.createdUtc)}, {"revisionId", Text(sample.revisionId)},
            {"snapshotId", Text(sample.snapshotId)}};
}

bool CheckSummaryFields(const JsonValue& doc, SampleInfo& out) {
    return GetUuid(doc, "sampleId", out.sampleId) && GetString(doc, "title", out.title) &&
        IsText(out.title, kMaxTitleBytes) && GetNumber(doc, "createdUtc", out.createdUtc) &&
        out.createdUtc != 0 && GetUuid(doc, "revisionId", out.revisionId) &&
        GetUuid(doc, "snapshotId", out.snapshotId);
}

ProjectResult ReadError(const char* detail) { return Failure(ProjectError::Corrupt, detail); }

} // namespace

ProjectResult SampleCatalog::Load(const Directory& root, std::string_view projectId) {
    JsonValue doc;
    if (auto result = Read(root, {L"catalog", std::to_wstring(generation)}, L"manifest.json", hash, doc);
        !result) return result;
    std::uint64_t actualGeneration = 0;
    std::uint64_t actualCount = 0;
    if (!Fields(doc, {"kind", "projectId", "generation", "sampleCount", "pageHashes"}) ||
        !IsString(doc, "kind", "sample-catalog") || !IsString(doc, "projectId", projectId) ||
        !GetNumber(doc, "generation", actualGeneration) || actualGeneration != generation ||
        !GetNumber(doc, "sampleCount", actualCount)) return ReadError("sampleCatalog");
    if (actualCount > kProjectSampleLimit) return Failure(ProjectError::LimitExceeded, "sampleLimit");

    const auto* pages = doc.find("pageHashes")->asArray();
    if (!pages || pages->size() != (actualCount + kProjectCatalogPageSize - 1) / kProjectCatalogPageSize) {
        return ReadError("catalogPageCount");
    }
    std::vector<std::string> hashes;
    for (const auto& page : *pages) {
        std::string pageHash;
        if (!page.tryGetString(pageHash) || !IsHash(pageHash)) return ReadError("catalogPageHash");
        hashes.push_back(std::move(pageHash));
    }
    pages_ = std::move(hashes);
    count = actualCount;
    return {};
}

ProjectResult SampleCatalog::Publish(const Directory& root, std::string_view projectId,
                                     const std::vector<SampleInfo>& entries) {
    const auto folder = std::to_wstring(generation);
    JsonArray hashes;
    std::vector<std::string> pageHashes;
    for (std::size_t first = 0; first < entries.size(); first += kProjectCatalogPageSize) {
        JsonArray records;
        const std::size_t end = std::min(first + kProjectCatalogPageSize, entries.size());
        for (auto i = first; i < end; ++i) {
            auto fields = SummaryFields(entries[i]);
            fields.emplace_back("descriptionHash", Text(entries[i].descriptionHash));
            records.push_back(Object(std::move(fields)));
        }
        const std::uint64_t page = pageHashes.size() + 1;
        const auto pageDoc = Object({{"kind", Text("sample-catalog-page")}, {"projectId", Text(projectId)},
                                     {"generation", Number(generation)}, {"pageId", Number(page)},
                                     {"samples", JsonValue::makeArray(std::move(records))}});
        std::string pageHash;
        if (auto result = ProjectStorage::Publish(root, {L"catalog", folder}, NumberFile(page), pageDoc,
                                                 false, &pageHash); !result) return result;
        hashes.push_back(Text(pageHash));
        pageHashes.push_back(std::move(pageHash));
    }
    const auto manifest = Object({{"kind", Text("sample-catalog")}, {"projectId", Text(projectId)},
                                  {"generation", Number(generation)}, {"sampleCount", Number(entries.size())},
                                  {"pageHashes", JsonValue::makeArray(std::move(hashes))}});
    if (auto result = ProjectStorage::Publish(root, {L"catalog", folder}, L"manifest.json", manifest,
                                             false, &hash); !result) return result;
    pages_ = std::move(pageHashes);
    count = entries.size();
    return {};
}

ProjectResult SampleCatalog::ReadPage(const Directory& root, std::string_view projectId,
                                      std::size_t page, std::vector<SampleInfo>& out) const {
    if (page >= pages_.size()) return ReadError("catalogPageIndex");
    JsonValue doc;
    if (auto result = Read(root, {L"catalog", std::to_wstring(generation)}, NumberFile(page + 1),
                           pages_[page], doc); !result) return result;
    std::uint64_t actualPage = 0;
    std::uint64_t actualGeneration = 0;
    if (!Fields(doc, {"kind", "projectId", "generation", "pageId", "samples"}) ||
        !IsString(doc, "kind", "sample-catalog-page") || !IsString(doc, "projectId", projectId) ||
        !GetNumber(doc, "generation", actualGeneration) || generation != actualGeneration ||
        !GetNumber(doc, "pageId", actualPage) || page + 1 != actualPage) return ReadError("catalogPage");
    const auto* samples = doc.find("samples")->asArray();
    const std::uint64_t remaining = count - page * kProjectCatalogPageSize;
    if (!samples || samples->size() != std::min(remaining, kProjectCatalogPageSize)) {
        return ReadError("catalogPageSize");
    }
    std::unordered_set<std::string> ids;
    for (const auto& entry : *samples) {
        SampleInfo sample;
        if (!Fields(entry, {"sampleId", "title", "createdUtc", "revisionId", "snapshotId", "descriptionHash"}) ||
            !CheckSummaryFields(entry, sample) || !GetHash(entry, "descriptionHash", sample.descriptionHash) ||
            !ids.insert(sample.sampleId).second) return ReadError("catalogSample");
        out.push_back(std::move(sample));
    }
    return {};
}

ProjectResult SampleCatalog::List(const Directory& root, std::string_view projectId, std::uint64_t start,
                                  std::uint64_t limit, std::vector<SampleInfo>& out) const {
    if (!limit || limit > kProjectCatalogPageSize || start > count) {
        return Failure(ProjectError::InvalidArgument, "catalogPageRange");
    }
    std::vector<SampleInfo> rows;
    const auto stop = start + std::min(count - start, limit);
    while (start < stop) {
        std::vector<SampleInfo> page;
        const auto index = static_cast<std::size_t>(start / kProjectCatalogPageSize);
        if (auto result = ReadPage(root, projectId, index, page); !result) return result;
        const auto within = static_cast<std::size_t>(start % kProjectCatalogPageSize);
        const auto take = std::min<std::size_t>(page.size() - within, stop - start);
        for (std::size_t i = within; i < within + take; ++i) rows.push_back(std::move(page[i]));
        start += take;
    }
    out = std::move(rows);
    return {};
}

ProjectResult SampleCatalog::ReadAll(const Directory& root, std::string_view projectId,
                                     std::vector<SampleInfo>& out) const {
    std::vector<SampleInfo> rows;
    rows.reserve(static_cast<std::size_t>(count));
    for (std::size_t p = 0; p < pages_.size(); ++p) {
        if (auto result = ReadPage(root, projectId, p, rows); !result) return result;
    }
    std::unordered_set<std::string> ids;
    for (const auto& row : rows) {
        if (!ids.insert(row.sampleId).second) return ReadError("catalogDuplicateSample");
    }
    out = std::move(rows);
    return {};
}

ProjectResult SampleCatalog::Find(const Directory& root, std::string_view projectId,
                                  std::string_view sampleId, SampleInfo& out) const {
    std::optional<SampleInfo> found;
    for (std::size_t p = 0; p < pages_.size(); ++p) {
        std::vector<SampleInfo> page;
        if (auto result = ReadPage(root, projectId, p, page); !result) return result;
        for (auto& row : page) {
            if (row.sampleId != sampleId) continue;
            if (found) return ReadError("catalogDuplicateSample");
            found = std::move(row);
        }
    }
    if (!found) return Failure(ProjectError::NotFound, "sampleId");
    out = std::move(*found);
    return {};
}

ProjectResult PublishSample(const Directory& root, const ProjectInfo& project, const SampleInfo& sample,
                            std::string& sampleHash) {
    const auto id = WideAscii(sample.sampleId);
    const auto snapshotName = WideAscii(sample.snapshotId) + L".json";
    Directory sampleDir;
    if (auto result = OpenDirectory(root, {L"samples", id}, sampleDir, true); !result) return result;
    Directory snapshotDir;
    if (auto result = OpenDirectory(sampleDir, {L"snapshots"}, snapshotDir, true); !result) return result;

    // 快照内嵌所选已提交修订的全部定义与标识，历史读取不借用当前配置。
    const auto snapshot = Object({{"kind", Text("offline-config-snapshot")}, {"projectId", Text(project.projectId)},
        {"sampleId", Text(sample.sampleId)}, {"snapshotId", Text(sample.snapshotId)},
        {"revisionId", Text(project.revisionId)}, {"revisionHash", Text(project.revisionHash)},
        {"configSemanticHash", Text(project.configSemanticHash)}, {"config", Settings(project.settings)}});
    std::string snapshotHash;
    if (auto result = Publish(root, {L"samples", id, L"snapshots"}, snapshotName, snapshot, false, &snapshotHash);
        !result) return result;

    auto fields = SummaryFields(sample);
    fields.emplace_back("kind", Text("offline-sample"));
    fields.emplace_back("projectId", Text(project.projectId));
    fields.emplace_back("snapshotHash", Text(snapshotHash));
    fields.emplace_back("producer", Text("KswordCLI"));
    fields.emplace_back("status", Text(kOfflineSampleStatus));
    fields.emplace_back("requestedBackend", JsonValue::makeNull());
    fields.emplace_back("actualBackend", JsonValue::makeNull());
    fields.emplace_back("initialTarget", JsonValue::makeNull());
    return Publish(root, {L"samples", id}, L"sample.json", Object(std::move(fields)), false, &sampleHash);
}

ProjectResult ReadSampleRecord(const Directory& root, std::string_view projectId,
                               const SampleInfo& expected, bool allowBreakpointDefinitions, SampleRecord& out) {
    SampleRecord record;
    const auto id = WideAscii(expected.sampleId);
    JsonValue doc;
    if (auto result = Read(root, {L"samples", id}, L"sample.json", expected.descriptionHash, doc);
        !result) return result;
    std::string snapshotHash;
    const auto& summary = record.info;
    if (!Fields(doc, {"kind", "projectId", "sampleId", "title", "createdUtc", "revisionId", "snapshotId",
                      "snapshotHash", "producer", "status", "requestedBackend", "actualBackend", "initialTarget"}) ||
        !IsString(doc, "kind", "offline-sample") || !IsString(doc, "projectId", projectId) ||
        !IsString(doc, "producer", "KswordCLI") || !IsString(doc, "status", kOfflineSampleStatus) ||
        !IsNull(doc, "requestedBackend") || !IsNull(doc, "actualBackend") || !IsNull(doc, "initialTarget") ||
        !GetHash(doc, "snapshotHash", snapshotHash) || !CheckSummaryFields(doc, record.info) ||
        summary.sampleId != expected.sampleId || summary.title != expected.title ||
        summary.createdUtc != expected.createdUtc || summary.revisionId != expected.revisionId ||
        summary.snapshotId != expected.snapshotId) return ReadError("sampleDescription");
    record.info.descriptionHash = expected.descriptionHash;

    const auto fileName = WideAscii(expected.snapshotId) + L".json";
    JsonValue snapshot;
    if (auto result = Read(root, {L"samples", id, L"snapshots"}, fileName, snapshotHash, snapshot); !result) return result;
    if (!Fields(snapshot, {"kind", "projectId", "sampleId", "snapshotId", "revisionId", "revisionHash",
                           "configSemanticHash", "config"}) || !IsString(snapshot, "kind", "offline-config-snapshot") ||
        !IsString(snapshot, "projectId", projectId) || !IsString(snapshot, "sampleId", expected.sampleId) ||
        !IsString(snapshot, "snapshotId", expected.snapshotId) || !IsString(snapshot, "revisionId", expected.revisionId) ||
        !GetHash(snapshot, "revisionHash", record.revisionHash) ||
        !GetHash(snapshot, "configSemanticHash", record.configSemanticHash) ||
        !ReadStoredSettings(*snapshot.find("config"), record.frozenSettings) ||
        (record.frozenSettings.breakpointDefinitions.has_value() && !allowBreakpointDefinitions)) {
        return ReadError("sampleSnapshot");
    }
    std::string actual;
    if (auto result = ConfigHash(record.frozenSettings, actual); !result) return result;
    if (actual != record.configSemanticHash) return ReadError("snapshotConfigHash");
    out = std::move(record);
    return {};
}

} // namespace Ksword::ActionAnalyze
