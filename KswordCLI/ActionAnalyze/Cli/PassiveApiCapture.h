#pragma once

#include "../Project/ProjectApiCheckpoint.h"
#include "../../../shared/evidence/PassiveApiArchiveTail.h"
#include "../../../shared/evidence/PassiveApiSourceDiagnosis.h"

#include <chrono>
#include <memory>

namespace ks::cli::action_analyze {

// CLI 本端的归档队列和项目回执。所有方法由活会话请求线程串行调用。
class PassiveApiCapture final {
public:
    // 打开调用方明确授权的本地文件，校验后固定句柄和文件身份。返回首次错误的阶段和系统码。
    Ksword::ActionAnalyze::ProjectResult Open(std::string_view path, Ksword::Evidence::PassiveApiSource source);
    // 冻结样本计划，写入与对外状态查询共用此描述。
    void SetPlan(Ksword::Evidence::JsonValue plan);
    // 处理一轮读取及必要的分段提交。返回 false 时会话进入停止流程。
    bool Tick(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sampleId);
    // 冻结可见边界、限额排空、提交终态并释放本端句柄。
    void Finish(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sampleId, std::string_view reason);
    // 返回已冻结的文件身份，以及观察与归档各自的实际前缀。
    Ksword::Evidence::JsonValue FileIdentity() const;
    Ksword::Evidence::JsonValue SourceReport() const;
    Ksword::Evidence::JsonValue ArchiveReport() const;
    // 本端是否在一个完整边界结束且已经读回所选前缀。用于退出码。
    bool Incomplete() const noexcept;
    // 为来源故障或项目失败选择稳定终止原因。
    std::string_view FailureReason() const noexcept;

private:
    // 返回终段可持久化的原有字段。实时查询在这份字段上追加诊断和线索预览。
    Ksword::Evidence::JsonObject SourceReportFields() const;
    // 接纳一个有界读取批次。调用方先确认队列空间足以容纳整批。
    void ReadBatch();
    // 写独立 raw 段，只有刷盘、回读并发布检查点才推进水位。
    bool Commit(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sampleId,
        std::optional<std::string_view> reason = std::nullopt);

    std::unique_ptr<Ksword::Evidence::PassiveApiArchiveTail> reader_; // 本端只读游标。
    Ksword::Evidence::PassiveApiTailStatus status_; // 保留句柄释放后的来源回执。
    Ksword::Evidence::PassiveApiSourceDiagnosis diagnosis_; // 在同一串行队列内保存已核验的生产方声明。
    Ksword::Evidence::JsonValue plan_; // 写入每个 raw 段的冻结采样计划。
    std::vector<Ksword::Evidence::ArchivedApiMonitorClue> pending_; // 按原行号保留的有界待写包。
    Ksword::ActionAnalyze::ProjectResult writeResult_; // 第一个归档失败的阶段和原生错误。
    std::optional<Ksword::ActionAnalyze::ProjectApiCheckpoint> checkpoint_; // 本端最后一次成功发布的项目水位。
    std::chrono::steady_clock::time_point nextPoll_; // 查询洪峰下仍按间隔安排文件 I/O。
    std::chrono::steady_clock::time_point nextCommit_; // 本批非空数据的常规提交时限。
    std::string fileId_; // 卷内 128 位文件 ID 的原始字节十六进制。
    std::uint64_t volumeSerial_ = 0; // 文件身份所属卷版本。
    std::uint64_t initialBytes_ = 0; // 打开时可见的积压字节数。
    std::uint64_t recordedRows_ = 0; // 通过本端项目回读的累计原始包数。
    std::uint64_t clueRows_ = 0; // 通过输入校验且命中线索目录的累计包数。
    std::uint64_t latestClueSequence_ = 0; // 最近一条线索的原文件位置。
    const Ksword::Evidence::ApiMonitorClue* latestClue_ = nullptr; // 静态目录条目。
    bool ended_ = false; // 本端已完成跟随并清退只读句柄。
};

} // namespace ks::cli::action_analyze
