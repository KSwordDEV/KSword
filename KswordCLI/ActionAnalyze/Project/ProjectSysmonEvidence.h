#pragma once

#include "ProjectRawEvidence.h"
#include "../Detection/SysmonThreadSource.h"

namespace Ksword::ActionAnalyze {

struct ProjectSysmonEvidenceRecord {
    Detection::SysmonThreadObservation observation;
    // Stored coordinates, not the Windows EventRecordID.
    std::uint64_t sequence = 0;
    std::uint64_t offset = 0;
};

struct ProjectSysmonEvidenceReceipt {
    std::string projectId, sampleId;
    Detection::SysmonThreadQuery query; // 规范目标 GUID、匹配上限及可选原生日志记录号。
    Detection::SysmonReadState sourceState = Detection::SysmonReadState::InvalidRequest;
    Detection::SysmonLimit sourceLimit = Detection::SysmonLimit::None;
    std::wstring nativeStage;
    std::uint32_t nativeError = 0;
    std::uint32_t examined = 0, unsupportedVersions = 0, malformed = 0, renderFailed = 0;
    bool reachedEnd = false; // Native query cursor only; source coverage remains unknown.
    std::uint64_t segmentOrdinal = 1;
    ks::cli::action_analyze::archive::RawEvidenceBoundary boundary;
    std::string prefixSha256;
    std::vector<ProjectSysmonEvidenceRecord> records;
};

// 在单独的已登记采样上，将本次已授权的本机只读 retained 查询结果写入 raw/1。
// 调用方直接提供 ReadLocalSysmonThreadEvents(query) 的返回值。成功返回完整段的回读结果。
ProjectResult WriteInitialSysmonEvidence(ProjectDocument& project, std::string_view sampleId,
    const Detection::SysmonThreadQuery& query, const Detection::SysmonThreadReadResult& source,
    ProjectSysmonEvidenceReceipt& out);

// 仅返回与本项目采样匹配且完整提交的 raw/1。有效空档的 records 为空，boundary 仍然有效。
// The checkpoint verifies project membership and stored bytes, not independent log authenticity.
ProjectResult ReadInitialSysmonEvidence(const ProjectDocument& project, std::string_view sampleId,
    ProjectSysmonEvidenceReceipt& out);

} // namespace Ksword::ActionAnalyze
