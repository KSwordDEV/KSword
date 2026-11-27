#pragma once

#include "Transport.h"
#include "../Project/CooperativeApiCapture.h"
#include "../Project/ProjectApiCheckpoint.h"

#include <optional>
#include <string>

namespace ks::cli::action_analyze {

// CLI采集进度只旁听原writer；stderr堵塞不能阻止原owner恢复或成为第二个归档写者。
class ApiCaptureProgress final {
public:
    // requested来自显式命令选项；projectId为本轮已打开的项目身份，不查询当前草稿。
    ApiCaptureProgress(bool requested, std::string projectId);
    // 传入原启动阶段文档，沿同一输出队列发送，避免与运行进度交错成半行JSON。
    void Publish(const Ksword::Evidence::JsonValue& value);
    // 传入已发布检查点与规则累计值；只报告已核验坐标，不把收包数当成归档水位。
    void Committed(const Ksword::ActionAnalyze::SampleInfo& sample,
        const Ksword::ActionAnalyze::ProjectApiCheckpoint& checkpoint,
        const Ksword::ActionAnalyze::CooperativeApiRuleReceipt& rules);
    // 传入原控制器的活动快照；该通知不是终态，也不签发继续或停止权限。
    void Transfers(const Ksword::ActionAnalyze::CooperativeApiTransferReceipt& transfers);
    // 采集和恢复结束后有限等待stderr排空，返回独立交付摘要；失败不改采集退出码。
    Ksword::Evidence::JsonValue Finish();

private:
    // 输入通知类别、实际采样及纯值正文，输出含连续尝试序号的JSONL进度帧。
    void Emit(std::string_view kind, const Ksword::ActionAnalyze::SampleInfo& sample,
        Ksword::Evidence::JsonValue payload);
    Transport output_; // 复用CLI现有有界输出worker，不读取stdin、不安装第二个控制处理器。
    std::string projectId_; // 打开文档时冻结的项目UUID。
    std::optional<Ksword::ActionAnalyze::SampleInfo> committedSample_; // 无自动接管时仍从已发布检查点取得真实采样身份。
    bool requested_ = false; // 是否请求进度，不等于stderr实际可用。
    bool started_ = false; // 输出worker是否真正启动。
    std::uint64_t sequence_ = 0; // 已尝试发出的运行进度序号，丢帧后不回收。
    std::uint64_t enqueued_ = 0; // 真正进入输出队列的帧数，不冒充已交付。
    std::uint64_t dropped_ = 0; // 队列满、通道故障或单帧过大而未接纳的通知数。
    std::uint64_t candidateCount_ = 0; // 原writer先发布候选回调，检查点通知随后使用同一批累计值。
    std::uint64_t apcCandidateCount_ = 0; // APC候选计数独立于线程创建，不复制完整候选窗口。
    std::uint64_t contextCandidateCount_ = 0; // 上下文候选计数只来自已提交原包，不等于执行次数。
};

} // namespace ks::cli::action_analyze
