#pragma once

#include "ProjectNativeExecution.h"
#include "NativeBoundApiCapture.h"
#include "../Control/OwnedExecutionGroup.h"

#include <map>
#include <memory>

namespace Ksword::ActionAnalyze {

// 一次显式保存的原执行事件与独立存储结果；未知执行或失败不会填入旧成功事件。
struct ExecutionGroupExecutionSave {
    ProjectResult status; // 本次核对或写入结果，不代表集合控制状态。
    ks::cli::action_analyze::control::OwnerIdentity owner; // 实际被保存成员的原owner。
    std::optional<ks::cli::action_analyze::control::NativeExecutionEvidence> observation; // 当前原事件。
    std::optional<ProjectNativeExecutionReceipt> receipt; // 实际尝试的段号及刷盘/核验状态。
};

// 三端共享的纯值投影；写租约、原集合和项目句柄不离开本端串行worker。
struct ExecutionGroupArchiveView {
    std::wstring directory; // Start前明确选择的项目目录，失败时也保留。
    std::string projectId; // 实际创建或打开的项目身份。
    std::string sampleId; // 本轮独立新采样，全部成员沿用同一sample。
    ProjectResult setup; // 项目和采样准备结果，未配置目录时不创建项目。
    std::shared_ptr<const ExecutionGroupExecutionSave> saved; // 最近一次显式保存回执。
    std::shared_ptr<const ExecutionGroupExecutionSave> firstFailure; // 首次追加失败，旧成功重放不覆盖。
    std::shared_ptr<const NativeBoundApiResult> api; // 本轮原writer的另一明确来源实例采集，不自动保存执行事件。
    ks::cli::action_analyze::control::OwnerIdentity apiOwner; // 此次API关联的原集合成员owner，选择变化不改写。
    ks::cli::action_analyze::control::NativeControlResult apiBefore, apiAfter; // 采集前后无条件回读，不能授予旧停点控制权。
    bool configured = false; // 用户明确要求写项目，不从其它页面借用writer。
    bool writerHeld = false; // 原租约仍被本worker持有，只有clean后调用Close才能归还。
    bool duplicate = false; // 同一backend/serial返回原段坐标，没有重新写入。
    bool appendBlocked = false; // 一次真实写入失败后不跳段或覆盖坏尾。
};

// 输入原worker纯值投影，输出同一规范JSON；三端正文、复制、导出与CLI响应共用字段。
Evidence::JsonValue DescribeExecutionGroupArchive(const ExecutionGroupArchiveView& view);

// 每个集合的原worker持有一份；CLI、Qt、Light复用相同新采样和执行保存语义。
class ExecutionGroupArchive final {
public:
    // 输入显式目录及新建/打开方式，输出准备结果；已有项目也只创建本轮新sample。
    bool Prepare(const std::wstring& directory, bool openExisting);
    // 在任何成员附加前核对全部可选冻结定义；成功继承约束，失败保留原草稿并归还未使用writer。
    bool ResolveSites(std::vector<ks::cli::action_analyze::control::ExecutionGroupSite>& sites);
    // 在原worker借唯一writer采集另一明确来源，拒绝来源属于集合；前后回读不求条件或Continue。
    void CaptureApi(ks::cli::action_analyze::control::OwnedExecutionGroup& group,
        const ks::cli::action_analyze::control::ExecutionGroupSessionEntry& displayed,
        const NativeBoundApiRequest& request, const std::atomic_bool& cancel,
        const NativeBoundApiStartup& onStartup = {});
    // 输入完整原成员owner/control；先无条件回读，匹配精确事件后写raw-native，不Continue。
    void Save(ks::cli::action_analyze::control::OwnedExecutionGroup& group,
        const ks::cli::action_analyze::control::ExecutionGroupSessionEntry& displayed);
    // 返回不可变值投影供原详情与JSON响应使用；不访问目标，也不读取项目文件。
    const ExecutionGroupArchiveView& View() const noexcept { return view_; }
    // 仅在原集合确认clean后调用；归还项目租约，保留全部历史结果投影。
    void Close();

private:
    std::optional<ProjectDocument> project_; // 原worker独占的项目写租约。
    ExecutionGroupArchiveView view_; // 本轮项目身份及最新保存回执。
    std::uint64_t ordinal_ = 1; // 新采样raw-native从第1段开始，不扫描或覆盖其它采样。
    std::optional<std::uint64_t> previousSequence_ = 0; // 本流上次成功刷盘的真实末序号。
    // 不同成员原backend与serial成对去重，不能只凭事件流水号或PID。
    std::map<std::pair<std::string, std::uint64_t>, std::shared_ptr<const ExecutionGroupExecutionSave>> journal_;
};

} // namespace Ksword::ActionAnalyze
