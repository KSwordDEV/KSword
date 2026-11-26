#pragma once

#include "Protocol.h"
#include "../Control/ProcessGroupMemorySnapshot.h"
#include "../Project/ProjectMemorySnapshot.h"

namespace ks::cli::action_analyze {

// 集合会话的单写项目绑定和当前已显示内存结果；本类从不读取活目标或继续停点。
class ProcessGroupMemoryArchive final {
public:
    // 在创建控制所有者前固定项目写租约及采样；空项目保持原有无项目控制模式。
    Ksword::ActionAnalyze::ProjectResult Bind(const std::wstring& path, std::string_view sampleId);
    // 返回绑定采样，供原生控制组及内存读取共用同一个真实样本身份。
    const std::string& SampleId() const noexcept;
    // 当前绑定、保存通道和已显示 capture 的只读说明，不产生磁盘或进程操作。
    JsonValue Describe() const;
    // 仅在读取响应成功进入输出队列后冻结该次实际结果；拒绝读取不替换旧结果。
    void Remember(control::ProcessMemorySnapshotResult capture);
    // 仅写调用者明确指认的已显示结果；参数改变不能触发重新读取或保存另一结果。
    JsonValue Save(std::string_view captureId, std::string_view sampleId);

private:
    // 连续核验既有 raw-memory 段，确定唯一可追加位置；坏尾不跳过。
    Ksword::ActionAnalyze::ProjectResult FindAppendPosition();
    // 将项目错误和冻结身份投影为保存响应，保留首次通道错误。
    JsonValue Failure(Ksword::ActionAnalyze::ProjectResult issue) const;

    Ksword::ActionAnalyze::ProjectDocument project_; // 从启动到清退结束独占项目写租约。
    Ksword::ActionAnalyze::SampleInfo sample_; // 启动前固定的采样及配置修订。
    std::uint64_t nextOrdinal_ = 1; // 独立 raw-memory 通道的下一个完整段号。
    std::optional<std::uint64_t> previousSequence_ = 0; // 最近已核验段的末序号。
    std::optional<control::ProcessMemorySnapshotResult> displayed_; // 唯一可保存的当前显示快照及其原字节。
    std::optional<JsonValue> saved_; // 同一显示 capture 的首次保存回执，重复保存不追加。
    std::optional<Ksword::ActionAnalyze::ProjectMemorySnapshotReceipt> lastWrite_; // 保存失败时仍保留实际写入与刷盘端点。
    bool laneBlocked_ = false; // 写入或回读失败后禁止继续追加，绝不覆盖坏尾。
    Ksword::ActionAnalyze::ProjectResult laneFailure_; // 首次通道故障，不被后续参数错误覆盖。
};

} // namespace ks::cli::action_analyze
