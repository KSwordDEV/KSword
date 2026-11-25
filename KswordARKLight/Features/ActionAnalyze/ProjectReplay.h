#pragma once

#include "StoredEvidence.h"

namespace Ksword::Features::ActionAnalyze {

// 从已登记目录行冻结的回放请求。重读沿用相同身份和描述散列。
struct ProjectReplayRequest {
    std::wstring manifestPath; // 用户明确选中的 project.ksaproj。
    std::string projectId; // 清单项目 UUID。
    std::string sampleId; // 目录行采样 UUID。
    std::string descriptionHash; // 目录记录的采样描述 SHA-256。
    bool operator==(const ProjectReplayRequest&) const = default;
};

struct ProjectReplayChoice {
    std::string title; // 目录记录的 UTF-8 采样名称。
    ProjectReplayRequest request; // 确认选择时提交的完整请求值。
};

struct ProjectReplayCatalog {
    std::string diagnostic; // 空值表示已读到目录，包括成功的空目录。
    std::uint32_t systemError = 0; // 原生错误码（若有）。
    bool recoveredPrevious = false; // 目录来自恢复的上一次项目提交。
    std::vector<ProjectReplayChoice> choices; // 仅含已提交的目录记录。
};

enum class CheckpointState { NotChecked, NotPublished, Verified };

struct ProjectReplayEvidence {
    SegmentEvidence raw; // 声明范围内的 raw 投影，失败时不携带可发布行。
    CheckpointState checkpoint = CheckpointState::NotChecked; // 归档提交状态。
    std::uint64_t recordsEnd = 0; // 仅在终态检查点通过时提供 records/1 端点。
};

// 供现有打开入口识别固定清单文件名，不从孤立段自动推断它所属的项目。
bool IsProjectReplayManifest(const std::wstring& path);
// 在后台读取已提交目录，返回供选择的值快照。
ProjectReplayCatalog ReadProjectReplayCatalog(const std::wstring& manifestPath);
// 在后台复核冻结请求和提交，再投影同一只读句柄中的 raw 字节。
ProjectReplayEvidence ReadProjectReplay(const ProjectReplayRequest& request);

} // namespace Ksword::Features::ActionAnalyze
