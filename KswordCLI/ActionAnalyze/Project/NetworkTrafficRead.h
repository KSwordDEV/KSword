#pragma once

#include "NetworkTrafficCapture.h"

namespace Ksword::ActionAnalyze {

// 端侧在点击时冻结的纯值请求；不含窗口、writer或第二个采集运行时。
struct NetworkTrafficRequest {
    std::wstring projectPath; // 已有项目目录或正式manifest路径。
    NetworkTrafficCapturePlan plan; // 原sample、精确目标、时长及显式来源。
    bool capture = false; // true采集并归档，false只读已发布网络段。
    std::uint64_t ordinal = 0; // 读取段号；0选择最后一个已发布段。
    std::uint64_t recordSequence = 0; // 0读取前256条预览，否则读取精确记录全部保留字节。
};

struct NetworkTrafficReadResult {
    ProjectResult status; // 整段校验失败时不发布任何预览。
    ProjectNetworkCheckpoint checkpoint; // 真实段、水位及冻结目标。
    std::vector<ks::cli::action_analyze::archive::NetworkStoredFlowPreview> records; // 拥有字节的读侧值。
    std::uint64_t totalRecords = 0; // 段内记录总数，与展示条数分别报告。
};

struct NetworkTrafficResult {
    NetworkTrafficRequest request; // 实际执行来源，不受之后修改草稿影响。
    std::string projectId; // 成功打开的项目身份。
    NetworkTrafficCaptureReceipt receipt; // 原同步采集器的完整回执。
    NetworkTrafficReadResult read; // 显式读取结果或采集末段回读结果。
    ProjectResult opened; // 正式项目租约打开结果。
};

// 从系统读取实际启动UUID；失败返回空，不以随机值冒充启动身份。
std::string ReadNetworkTrafficBootId();

// 只借用已打开项目，核验已发布网络段后返回有界预览/指定记录的全部保留字节。
// 段号0读取最新提交；不存在、损坏和成功空段通过status/checkpoint分别表达。
NetworkTrafficReadResult ReadNetworkTraffic(const ProjectDocument& project,
    std::string_view sampleId, std::uint64_t ordinal, std::uint64_t recordSequence = 0);

} // namespace Ksword::ActionAnalyze
