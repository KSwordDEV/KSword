#pragma once

#include "ArchivedEvidenceGraph.h"

namespace Ksword::ActionAnalyze::Detection {

inline constexpr std::size_t kPrivateCandidateMaxPage = 8; // 单页含完整原调用及Free关联，控制CLI正文体积。
inline constexpr std::size_t kPrivateCandidateMaxEvents = 2048; // 超限返回错误，不截断成完整目录。
inline constexpr std::size_t kPrivateCandidateMaxObservations = 32768; // 包含非AAIM1的扫描预算。
inline constexpr std::size_t kPrivateCandidateMaxFreeLinks = 4; // 每条保留四个原请求，完整关联总数另列。

// 原AAIM1调用、强实例声明和文件坐标的值快照，不包含任何现场控制权。
struct PrivateMemoryCall {
    EvidenceRef evidence; // 原sample、来源代次、源序号和raw坐标。
    ArchivedGraphRecord record; // 原字节/块坐标、请求/实际输出、NTSTATUS和有效位。
    std::string sha256; // 本条所在已核验段的真实前缀摘要。
};

// 只说明后续Free请求在同源时间/强实例/请求地址上相关，不证明同allocation或已释放。
struct PrivateFreeRequestLink {
    PrivateMemoryCall call; // Free原调用及实际返回；其输出范围始终未知。
    bool requestedRangeOverlaps = false; // 非零请求范围与候选实际范围有交集。
    bool requestedBaseInside = false; // 输入base落入候选实际范围，size=0也只报告此事实。
};

// 供原held工作流显式选取的草稿；owner仍须核对当前强实例、MEM_PRIVATE和allocation。
struct PrivateExecutionRangeDraft {
    std::string projectId; // 草稿绑定的历史项目，不改写owner当前身份。
    std::string sampleId; // 原调用所属的冻结采样。
    std::uint32_t targetPid = 0; // 原调用查询到的目标PID，不能用裸pid候选补值。
    std::uint64_t targetCreationFileTime = 0; // 原目标创建代次，现场仍需复核。
    std::uint64_t address = 0; // 显式选择的4KiB整页子范围起点。
    std::uint64_t bytes = 0; // 显式选择的整页子范围字节数，无固定页数上限。
    PrivateMemoryCall origin; // 产生范围的唯一原调用，选择不剥离来源依据。
};

struct PrivateExecutionCandidate {
    PrivateMemoryCall origin; // 每次原调用独立成行，不合并不同来源或allocation。
    bool rangeCandidate = false; // 仅成功Allocate实际范围或成功Protect的实际可执行范围。
    bool executableProtection = false; // 原调用新保护的基础位包含execute。
    bool strongTarget = false; // 目标身份有效且原调用前后稳定，不等于当前live。
    // generation、实际释放范围与当前存活均保持未知，本目录不维护allocation状态机。
    const char* reason = "not-a-range-candidate"; // 不能形成范围或草稿的稳定原因。
    std::optional<PrivateExecutionRangeDraft> wholeRangeDraft; // 整个实际范围恰满足约束才提供。
    std::vector<PrivateFreeRequestLink> freeRequests; // 同源严格时间顺序下的有界后续请求。
    std::uint64_t freeRequestCount = 0; // 完整扫描前缀内的相关请求数，未保留条数仍计数。
};

struct PrivateExecutionCandidatesRequest {
    std::string_view sampleId; // 原项目中登记的采样UUID。
    std::uint64_t throughOrdinal = 0; // 从1连续核验到此raw段，不搜索未知未来尾部。
    std::optional<RawLocator> after; // 上页末生命周期原坐标，不能用源流水号代替。
    std::size_t limit = kPrivateCandidateMaxPage; // 每页1..8条，Free/失败线索也占一行。
    std::string_view expectedSnapshot; // 续页必须绑定上页完整前缀快照token。
};

struct PrivateExecutionCandidatesPage {
    SampleScope scope; // 仅原项目/采样，不凭空填写machine/boot。
    std::string snapshot; // 绑定项目、采样、描述散列和逐段摘要的完整比较token。
    std::uint64_t throughOrdinal = 0; // 本次目录的明确扫描截止点。
    std::uint64_t observationCount = 0; // 已核验的分类API观察数，含非生命周期观察。
    std::uint64_t lifecycleCount = 0; // 合法AAIM1数量，失败及Free请求也计数。
    std::uint64_t malformedLifecycleCount = 0; // 带AAIM1标记但格式非法的调用数。
    std::uint64_t legacyLifecycleCount = 0; // 对应API中无AAIM1结构字段的旧摘要数量。
    std::uint64_t rangeCandidateCount = 0; // 整个扫描前缀内满足实际范围的候选数。
    std::uint64_t freeRequestCount = 0; // 整个扫描前缀内合法Free请求数，不代表实际释放。
    bool finalSegment = false; // 原API检查点声明的终段，不推断目标仍活着。
    std::vector<PrivateExecutionCandidate> rows; // 本页纯值条目，含失败及Free请求线索。
    std::optional<RawLocator> nextAfter; // 存在下一页时，精确指向本页末行原坐标。
};

// 输入已核验候选和用户明确选定的子范围；不查询、不控制目标。
// 成功才替换out；仅整页包含在实际输出内部时通过，不向外自动对齐。
ProjectResult PreparePrivateExecutionRangeDraft(const PrivateExecutionCandidate& candidate,
    std::uint64_t address, std::uint64_t bytes, PrivateExecutionRangeDraft& out);

// 原归档worker只读调用：复用transfer/correlate的归档读取器，完整核验后才替换out。
// 缺段、坏尾、来源不支持、预算超限或snapshot变化均返回错误，不冒充成功空目录。
ProjectResult ReadPrivateExecutionCandidates(const ProjectDocument& project,
    const PrivateExecutionCandidatesRequest& request, PrivateExecutionCandidatesPage& out);

} // namespace Ksword::ActionAnalyze::Detection
