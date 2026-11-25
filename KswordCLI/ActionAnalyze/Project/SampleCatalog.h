#pragma once

#include "ProjectStorage.h"

namespace Ksword::ActionAnalyze {

class SampleCatalog final {
public:
    std::uint64_t generation = 0;
    std::string hash;
    std::uint64_t count = 0;

    ProjectResult Load(const ProjectStorage::Directory& root, std::string_view projectId);
    ProjectResult Publish(const ProjectStorage::Directory& root, std::string_view projectId,
                          const std::vector<SampleInfo>& entries);
    ProjectResult List(const ProjectStorage::Directory& root, std::string_view projectId,
                       std::uint64_t start, std::uint64_t limit, std::vector<SampleInfo>& out) const;
    ProjectResult ReadAll(const ProjectStorage::Directory& root, std::string_view projectId,
                          std::vector<SampleInfo>& out) const;
    ProjectResult Find(const ProjectStorage::Directory& root, std::string_view projectId,
                       std::string_view sampleId, SampleInfo& out) const;

private:
    ProjectResult ReadPage(const ProjectStorage::Directory& root, std::string_view projectId,
                           std::size_t page, std::vector<SampleInfo>& out) const;
    std::vector<std::string> pages_;
};

ProjectResult PublishSample(const ProjectStorage::Directory& root, const ProjectInfo& project,
                            const SampleInfo& sample, std::string& sampleHash);
// 已升级项目可同时读取旧快照与含定义的快照，旧清单只接受旧快照。
ProjectResult ReadSampleRecord(const ProjectStorage::Directory& root, std::string_view projectId,
                               const SampleInfo& expected, bool allowBreakpointDefinitions, SampleRecord& out);

} // namespace Ksword::ActionAnalyze
