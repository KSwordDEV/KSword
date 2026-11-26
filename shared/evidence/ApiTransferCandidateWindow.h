#pragma once

#include "../../KswordCLI/ActionAnalyze/Detection/ApiTransferChain.h"
#include "ApiMonitorClue.h"

#include <algorithm>
#include <deque>
#include <limits>
#include <utility>

namespace Ksword::Evidence {

// 桌面读侧只保存最近候选及双方原始行；匹配判据始终由 CLI 的链分析器拥有。
inline constexpr std::size_t kApiTransferCandidateRows = 256;
inline constexpr std::size_t kApiTransferWriteRows = 1024;
inline constexpr std::size_t kApiApcCandidateRows = 128; // APC 与线程创建分别限额，共享写入窗口。
inline constexpr std::size_t kApiContextCandidateRows = 128; // 上下文候选独立限额，不另建写入状态。

template<typename Row>
struct ApiTransferCandidateRows {
    ActionAnalyze::Detection::ApiTransferLink link; // 共享匹配器返回的来源声明候选。
    Row write; // 写入包真实坐标及当时读取的只读详情。
    Row threadCreate; // 创建包真实坐标及当时读取的只读详情。
};

template<typename Row>
struct ApiApcCandidateRows {
    ActionAnalyze::Detection::ApiApcTransferLink link; // 只表示写入与队列接受的一致性候选。
    Row write; // 同一候选的真实写入原行，独立于主表窗口。
    Row queue; // 同一候选的 APC 入队返回原行，不表示投递或执行。
};

// 上下文来源候选保留真实双方原行，不记录上下文已生效或执行事实。
template<typename Row>
struct ApiContextCandidateRows {
    ActionAnalyze::Detection::ApiContextTransferLink link; // 共享判据返回的请求 IP 区间候选。
    Row write; // 当前候选的原始实际写入行。
    Row context; // 当前候选的上下文请求返回行，不是实际执行记录。
};

// 从已核验包生成与 ArchivedEvidenceGraph 相同的来源身份，不生成任何强对象或控制资格。
inline ActionAnalyze::Detection::EvidenceRef ApiTransferEvidence(
    const ActionAnalyze::Detection::SampleScope& scope, const ArchivedApiMonitorClue& clue,
    std::uint64_t segment, std::uint64_t sequence, const std::string& followEpoch)
{
    ActionAnalyze::Detection::EvidenceRef evidence; // 坐标与源流水号分别保存。
    const bool imported = followEpoch.empty(); // 独立导入只使用本采样派生的代次。
    evidence.projectId = scope.projectId;
    evidence.sampleId = scope.sampleId;
    evidence.sourceId = (imported ? "api-monitor-import:" : "api-monitor-follow:") +
        std::to_string(clue.packet.sessionIdentity);
    evidence.sourceEpoch = imported ? "api-import:" + scope.sampleId : followEpoch;
    evidence.raw = ActionAnalyze::Detection::RawLocator{segment, sequence};
    evidence.sourceSequence = clue.sourceSequence;
    evidence.sourceGroup = "api-monitor";
    return evidence;
}

// 工作线程逐包调用。每段先复制本对象暂存，整段检查点核验成功后才移动提交。
template<typename Row>
class ApiTransferCandidateWindow final {
public:
    explicit ApiTransferCandidateWindow(ActionAnalyze::Detection::SampleScope scope)
        : scope_(std::move(scope)), chain_(scope_)
    {
    }

    // 输入原包和同一次读取生成的行；输出只读有界候选，不触碰目标现场或文件系统。
    void Accept(const ArchivedApiMonitorClue& clue, const Row& row,
        std::uint64_t segment, std::uint64_t sequence, const std::string& followEpoch = {})
    {
        const auto evidence = ApiTransferEvidence(scope_, clue, segment, sequence, followEpoch); // 实际原包锚点。
        const auto links = chain_.Accept(evidence, clue.packet); // 唯一匹配器决定区间、实例和时序。
        for (const auto& link : links)
        {
            ++candidateCount_; // 总数不因候选或事件表窗口淘汰而回退。
            const auto prior = std::find_if(writes_.begin(), writes_.end(), [&](const WriteRow& item) {
                return item.evidence == link.write;
            }); // 找到链分析器引用的同一真实写入行。
            if (prior == writes_.end())
            {
                continue;
            }
            if (candidates_.size() == kApiTransferCandidateRows)
            {
                candidates_.pop_front();
            }
            candidates_.push_back({link, prior->row, row});
        }

        // Accept 已登记本包写入；APC 查询复用同一匹配器，不另存一份 1024 写入状态。
        const auto apcLinks = chain_.AcceptApc(evidence, clue.packet); // 共享判据返回本包全部 APC 候选。
        for (const auto& link : apcLinks)
        {
            ++apcCandidateCount_;
            const auto prior = std::find_if(writes_.begin(), writes_.end(), [&](const WriteRow& item) {
                return item.evidence == link.write;
            }); // 从已有详情缓存提取同一写入原包。
            if (prior == writes_.end())
            {
                continue;
            }
            if (apcCandidates_.size() == kApiApcCandidateRows)
            {
                apcCandidates_.pop_front();
            }
            apcCandidates_.push_back({link, prior->row, row});
        }

        // 同一 Accept 已登记写入；上下文匹配复用该链及已有详情，不创建第二套写状态。
        const auto contextLinks = chain_.AcceptContext(evidence, clue.packet); // 本包形成的全部请求 IP 候选。
        for (const auto& link : contextLinks) // 每条 link 均由共享匹配器给出真实双方坐标。
        {
            ++contextCandidateCount_;
            const auto prior = std::find_if(writes_.begin(), writes_.end(), [&](const WriteRow& item) {
                return item.evidence == link.write;
            }); // prior 指向原有 1024 详情窗口内同一写入，item 是被比较的缓存项。
            if (prior == writes_.end())
            {
                continue;
            }
            // 只裁剪上下文自己的 128 对窗口，不挤占创建或 APC 候选。
            if (contextCandidates_.size() == kApiContextCandidateRows)
            {
                contextCandidates_.pop_front();
            }
            contextCandidates_.push_back({link, prior->row, row});
        }

        // 此筛选仅控制详情缓存；候选成立与否仍完全取决于上面的共享链分析器。
        if (!CacheableWrite(clue.packet))
        {
            return;
        }
        const auto duplicate = std::find_if(writes_.begin(), writes_.end(), [&](const WriteRow& item) {
            return item.evidence.raw == evidence.raw && item.evidence.sourceId == evidence.sourceId &&
                item.evidence.sourceEpoch == evidence.sourceEpoch;
        }); // 与共享写入窗口相同的原包去重身份。
        if (duplicate != writes_.end())
        {
            return;
        }
        if (writes_.size() == kApiTransferWriteRows)
        {
            writes_.pop_front();
        }
        writes_.push_back({evidence, row});
    }

    // 后台任务发布时复制最多 256 对原始行，不在 UI 线程扫描归档。
    const std::deque<ApiTransferCandidateRows<Row>>& Candidates() const noexcept { return candidates_; }
    std::uint64_t CandidateCount() const noexcept { return candidateCount_; }
    std::uint64_t EvictedWrites() const noexcept { return chain_.EvictedWrites(); }
    // 发布 APC 的独立有界窗口与累计数；复制草稿随整段事务一同提交。
    const std::deque<ApiApcCandidateRows<Row>>& ApcCandidates() const noexcept { return apcCandidates_; }
    std::uint64_t ApcCandidateCount() const noexcept { return apcCandidateCount_; }
    // 无输入，返回独立上下文窗口的只读引用；由原后台段事务发布，不执行查询。
    const std::deque<ApiContextCandidateRows<Row>>& ContextCandidates() const noexcept
    {
        return contextCandidates_;
    }
    // 无输入，返回已接受前缀中的累计上下文候选数，裁剪不回退。
    std::uint64_t ContextCandidateCount() const noexcept
    {
        return contextCandidateCount_;
    }

private:
    // 仅缓存共享链路有资格保留的实际写入，避免失败包挤出有效写入详情。
    static bool CacheableWrite(const ks::winapi_monitor::ApiMonitorEventPacket& packet)
    {
        const auto fields = ReadApiInjectionFields(packet); // 显式版本字段，绝不解析摘要字符串。
        constexpr auto required = ApiInjectionActorIdentity | ApiInjectionTargetIdentity |
            ApiInjectionTargetStable | ApiInjectionAddress | ApiInjectionCompletedLength;
        if (!fields || fields->operation != ApiInjectionOperation::MemoryWrite || !packet.sessionIdentity ||
            (fields->flags & required) != required || !packet.pid || !fields->actorCreationFileTime ||
            !fields->targetPid || !fields->targetCreationFileTime || fields->targetPid == packet.pid ||
            !fields->address || !fields->completedBytes ||
            fields->completedBytes > std::numeric_limits<std::uint64_t>::max() - fields->address)
        {
            return false;
        }
        const auto outcome = ApiInjectionCallOutcome(packet, *fields); // 部分完成只保留实际完成区间。
        return outcome == ApiInjectionOutcome::Succeeded || outcome == ApiInjectionOutcome::Partial;
    }

    struct WriteRow {
        ActionAnalyze::Detection::EvidenceRef evidence; // 精确的项目、采样、来源和原包坐标。
        Row row; // 写入详情的有界值副本。
    };
    ActionAnalyze::Detection::SampleScope scope_; // 本次只读采样作用域。
    ActionAnalyze::Detection::ApiTransferChain chain_; // 与正式 CLI 共用 1024 写入窗口。
    std::deque<WriteRow> writes_; // 与链状态同容量的真实写入行。
    std::deque<ApiTransferCandidateRows<Row>> candidates_; // 最近候选双方详情，与主表窗口独立。
    std::uint64_t candidateCount_ = 0; // 连续已核验前缀的候选总数。
    std::deque<ApiApcCandidateRows<Row>> apcCandidates_; // 最近 128 对写入与入队双方详情。
    std::uint64_t apcCandidateCount_ = 0; // 不随 APC 候选窗口裁剪回退。
    std::deque<ApiContextCandidateRows<Row>> contextCandidates_; // 最近 128 对 write/context 原行值。
    std::uint64_t contextCandidateCount_ = 0; // 已核验前缀累计上下文候选数。
};

} // namespace Ksword::Evidence
