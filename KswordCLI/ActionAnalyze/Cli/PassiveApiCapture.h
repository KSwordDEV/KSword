#pragma once

#include "../Project/ProjectApiCheckpoint.h"
#include "../Rules/BehaviorPresets.h"
#include "../../../shared/evidence/PassiveApiArchiveTail.h"
#include "../../../shared/evidence/PassiveApiSourceDiagnosis.h"

#include <chrono>
#include <memory>

namespace ks::cli::action_analyze {

enum class PassiveApiStartStage { Project, Source, Session, Sample };

struct PassiveApiStartRequest {
    std::string_view path; // 用户明确授权的本地 JSONL 绝对路径，调用期间借用。
    std::string_view projectId, revisionId, title; // 本轮冻结的项目目录行与标题。
    Ksword::Evidence::PassiveApiSource source; // 归档声明中的 PID、创建时间和来源会话 ID。
    std::uint32_t durationMs = 0; // 0 表示由本端显式停止。
    bool mixedEtw = false;
};

// 各端独立持有的归档队列和项目回执。所有方法由同一采集工作线程串行调用。
class PassiveApiCapture final {
public:
    // 调用方已确认授权并打开项目写租约。成功设置采样和代次；失败阶段区分源与存储。
    Ksword::ActionAnalyze::ProjectResult BeginProject(Ksword::ActionAnalyze::ProjectDocument& project,
        const PassiveApiStartRequest& request, Ksword::ActionAnalyze::SampleInfo& sample,
        std::string& epoch, PassiveApiStartStage& failedStage);
    // 所有水位写入同一计划；引用仅在本对象存活期间有效。
    const Ksword::Evidence::JsonValue& Plan() const noexcept { return plan_; }
    // 处理一轮读取及必要的分段提交。返回 false 时会话进入停止流程。
    bool Tick(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sampleId);
    // 冻结可见边界、限额排空、提交终态并释放本端句柄。
    void Finish(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sampleId, std::string_view reason);
    // 返回已冻结的文件身份，以及观察与归档各自的实际前缀。
    Ksword::Evidence::JsonValue FileIdentity() const;
    Ksword::Evidence::JsonValue SourceReport() const;
    Ksword::Evidence::JsonValue ArchiveReport() const;
    // 独立报告本次 API 入口的声明、已提交原包坐标和停止状态。
    Ksword::Evidence::JsonValue ReadinessReport() const;
    // 返回已提交线索的即时规则回执。查询不执行规则或推进归档。
    Ksword::Evidence::JsonValue RulesReport() const;
    // 本端是否在一个完整边界结束且已经读回所选前缀。用于退出码。
    bool Incomplete() const noexcept;
    // 为来源故障或项目失败选择稳定终止原因。
    std::string_view FailureReason() const noexcept;

private:
    // 校验并固定来源文件句柄，不提交项目采样。
    Ksword::ActionAnalyze::ProjectResult Open(std::string_view path, Ksword::Evidence::PassiveApiSource source);
    struct RawPosition {
        std::uint64_t segmentOrdinal; // 当前采样的 raw 段号。
        std::uint64_t rawSequence; // Stored 内实际记录序号。
        std::uint64_t sourceSequence; // 原始 JSONL 行号。
    };

    // 返回终段可持久化的原有字段。实时查询在这份字段上追加诊断和线索预览。
    Ksword::Evidence::JsonObject SourceReportFields() const;
    // 将读取健康、停止结果及已提交证据转换为入口状态。
    std::string_view ReadinessState() const noexcept;
    // 接纳一个有界读取批次。调用方先确认队列空间足以容纳整批。
    void ReadBatch();
    // 写独立 raw 段，只有刷盘、回读并发布检查点才推进水位。
    bool Commit(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view sampleId,
        std::optional<std::string_view> reason = std::nullopt);
    // 检查点发布后求值本段的分类线索。规则求值失败不会撤销已提交档案。
    void ObserveCommittedRules(const Ksword::ActionAnalyze::ProjectApiCheckpoint& committed) noexcept;

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
    std::uint64_t hooksInstalledSequence_ = 0; // 第一次核对通过的生产方安装声明行。
    std::uint64_t firstApiSequence_ = 0; // 第一条普通 API 原包候选的源行号。
    std::optional<RawPosition> firstRaw_; // 候选所在段发布检查点后才记录的原包坐标。
    std::uint64_t ruleMatches_ = 0; // 成功求值的已提交分类线索数。
    std::optional<RawPosition> latestRuleRaw_; // 最近一次规则匹配的已提交原始位置。
    Ksword::ActionAnalyze::Rules::ApiPresetDatabase ruleDatabase_; // 从开始到收尾冻结同一份外置规则。
    std::optional<Ksword::ActionAnalyze::Rules::ApiPresetMatch> latestRule_; // 自持有的末次匹配与可选释义。
    bool ruleFailed_ = false; // 保留首次规则失败前的有效计数和匹配。
    bool ended_ = false; // 本端已完成跟随并清退只读句柄。
};

} // namespace ks::cli::action_analyze
