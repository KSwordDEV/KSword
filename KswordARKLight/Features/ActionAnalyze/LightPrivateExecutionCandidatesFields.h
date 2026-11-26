#pragma once

#include "../../Core/Win32Lean.h"
#include "../../../KswordCLI/ActionAnalyze/Detection/PrivateExecutionCandidates.h"
#include "../../../KswordCLI/ActionAnalyze/Project/NativeBoundApiCapture.h"
#include <memory>

namespace Ksword::Features::ActionAnalyze {
namespace private_execution = Ksword::ActionAnalyze::Detection;

// 入原worker的拥有型请求；不跨线程借用string_view，也不携带项目document或writer。
struct LightPrivateExecutionCandidatesRequest {
    std::string projectId, sampleId; // 原document及本轮新sample的稳定身份。
    std::uint64_t throughOrdinal = 0; // 用户显式选择1..128，续页固定原值。
    std::optional<private_execution::RawLocator> after; // 原成功页最后一行raw坐标。
    std::string expectedSnapshot; // 与after配对的完整前缀token。
};

// 最近请求和最近成功目录独立；失败保留page及其原目录身份。
struct LightPrivateExecutionCandidatesView {
    LightPrivateExecutionCandidatesRequest request; // 最近一次读取请求，包括失败请求。
    Ksword::ActionAnalyze::ProjectResult result; // 最近读取的真实错误/成功回执。
    std::wstring projectDirectory; // 最近请求的原archive路径。
    std::shared_ptr<const private_execution::PrivateExecutionCandidatesPage> page; // 最近完整成功页。
    std::wstring pageProjectDirectory; // 该成功页的原目录，不随失败请求改写。
};

// UI仅消费原页本地快照，不查询目标或读取项目文件。
struct LightPrivateExecutionCandidatesContext {
    std::shared_ptr<const std::uint8_t> sessionIdentity; // 原Start本地代次，只作身份比较。
    bool active = false, busy = false, retiring = false, nxBinding = false; // 原会话实际准入状态。
    Ksword::ActionAnalyze::NativeBoundApiTarget target; // 原worker发布的native强目标。
    std::string projectId, sampleId; // 当前原document/sample，不从编辑框取值。
    std::wstring projectDirectory; // 当前原archive路径。
    std::shared_ptr<const LightPrivateExecutionCandidatesView> view; // 最近请求及成功页共享值。
    std::wstring diagnostic; // 在途或异常诊断，不覆盖旧成功页。
};

struct LightPrivateExecutionCandidateSelection {
    std::shared_ptr<const std::uint8_t> sessionIdentity; // 用户点击时看到的原会话。
    std::shared_ptr<const private_execution::PrivateExecutionCandidatesPage> page; // 明确冻结所选页。
    std::size_t row = 0; // 所选原调用在该页的索引，不是全局序号。
    std::uint64_t address = 0, bytes = 0; // 用户明确选择，不自动取整。
};

// 纯值正文源同时供列表、详情、原AddRange草稿与回执使用。
std::wstring PrivateCandidateHex(std::uint64_t value);
std::wstring PrivateCandidateCoordinate(const private_execution::PrivateMemoryCall& call);
std::wstring FormatLightPrivateExecutionCandidate(const private_execution::PrivateExecutionCandidate& candidate);
std::wstring FormatLightPrivateExecutionOrigin(const private_execution::PrivateExecutionRangeDraft& draft);
std::vector<std::wstring> LightPrivateExecutionCandidateCells(const private_execution::PrivateExecutionCandidate& candidate, bool provenance);
} // namespace Ksword::Features::ActionAnalyze
