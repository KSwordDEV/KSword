#include "CrossViewDiff.h"

#include <algorithm>
#include <unordered_map>
#include <utility>

namespace Ksword::Evidence {
namespace {

// 主键分隔符不会出现在路径、GUID 或数字里，避免 "a|b" 与 "a" + "|b" 撞键。
constexpr char kSep = '\x1F';

const std::string& GroupOf(const SourceRef& source) {
    return source.sourceGroup.empty() ? source.collectorId : source.sourceGroup;
}

std::uint32_t CategoryBit(ViewEntityCategory category) noexcept {
    return static_cast<std::uint32_t>(1U) << static_cast<unsigned>(category);
}

// X-04：只有"该对象曾被这一类别的视图列出过"，这一类别的视图才有资格对它做缺项推断。
// 一个 boot-start 驱动出现在加载模块列表、合法地不出现在设备对象树里 —— 那是结构，
// 不是差异。反过来，进程列表之间（同类别）的缺项才是 cross-view 要解释的东西。
bool CategoryComparable(std::uint32_t homeMask, ViewEntityCategory category) noexcept {
    return (homeMask & CategoryBit(category)) != 0U;
}

// X-06：账目的**正面证据**。字段全默认的 CoverageAccount 只说明"没记录到失败"，
// 并不说明"确实枚举完了"；把它当成完整覆盖，等于白送"确认缺失"资格。
bool CoverageProvesCompleteness(const CoverageAccount& coverage) noexcept {
    if (coverage.limitHit || coverage.cancelled) {
        return false;  // 提前停止：剩下的没看过
    }
    // (a) 数量口径：声明了总数，且已经全部拿到。
    if (coverage.totalKnown.present && coverage.succeeded >= coverage.totalKnown.value) {
        return true;
    }
    // (b) 范围口径：四个端点同时在场，且处理范围完全盖住请求范围。少一个端点就无从
    //     校验边界，不算数。
    if (coverage.requestedBegin.present && coverage.requestedEnd.present &&
        coverage.processedBegin.present && coverage.processedEnd.present) {
        return coverage.processedBegin.value <= coverage.requestedBegin.value &&
               coverage.processedEnd.value >= coverage.requestedEnd.value;
    }
    return false;  // 账目一字未填 = 未知覆盖 ≠ 完整覆盖
}

// X-06：账目与实际返回的记录条数对不上，说明这个 collector 静默损坏了
// （典型症状：status=Success、succeeded=500、records 一条没有）。这种视图的"没列出"
// 不是"不存在"，必须降级成未知，否则它会连续几轮把正常对象顶成持续差异。
bool ViewAccountMatchesRecords(const ViewSnapshot& view) noexcept {
    const CoverageAccount& coverage = view.envelope.coverage;
    const std::uint64_t records = static_cast<std::uint64_t>(view.records.size());
    if (coverage.succeeded > records) {
        return false;
    }
    if (coverage.totalKnown.present && coverage.totalKnown.value > records) {
        return false;
    }
    return true;
}

// 一个视图本轮是否有资格对"没列出"作出"确认不存在"的推断。
bool ViewUsableForAbsenceInRound(const ViewSnapshot& view) noexcept {
    return ViewUsableForAbsence(view.envelope, view.coversTargetScope) &&
           ViewAccountMatchesRecords(view);
}

// 每个对象在一轮里的聚合状态。
// 不变式：presentViews + usableAbsentViews + unusableViews + crossCategoryViews == hits.size()
struct RoundState final {
    std::size_t presentViews = 0;
    std::size_t usableAbsentViews = 0;
    std::size_t unusableViews = 0;
    std::size_t crossCategoryViews = 0;
    std::vector<ViewHit> hits;
};

struct ObjectEntry final {
    bool initialized = false;
    bool weak = false;                 // X-02：身份不足，只能作候选关系
    // 第一条落到这个对象上的源记录。保留它才能在建候选边时调用 ObjectIdentity 的
    // Match*（那些函数吃的是带类型的身份，不是字符串键）。记录活在调用方的 rounds
    // 里，生命周期覆盖整个 AnalyzeCrossView。
    const ViewRecord* representative = nullptr;
    ObjectKind kind = ObjectKind::Unknown;
    IdentityStrength strength = IdentityStrength::Unusable;
    std::string identityKey;
    std::string candidateKey;
    std::string displayText;
    std::uint32_t homeMask = 0;        // X-04：曾列出该对象的视图类别集合
    std::string firstSeenViewId;
    std::string firstSeenRawRecordId;
    std::size_t firstSeenRoundIndex = 0;
    // X-06 / BLOCKER：曾经 Present 报告过该对象的视图。判"对象已结束"必须由这些
    // 见证视图本轮全部可用且都不再列出它来支撑，超时的见证视图不算数。
    std::vector<std::string> everPresentViews;
    std::vector<RoundState> perRound;
};

// 一个 (round, view) 的记录索引：identityKey/candidateKey 每条记录只算一次。
// X-09：没有这张表，第 3 步就是 O(rounds × objects × views × records) 且每次比较都要
// 重新构造一个 std::string，4000 个对象要 13 秒，10 分钟采样窗口根本跑不完。
struct ViewIndex final {
    const ViewSnapshot* view = nullptr;
    std::unordered_map<std::string, const ViewRecord*> byKey;
};

void AppendKeyField(std::string& key, const std::string& value) {
    key.push_back(kSep);
    key.append(value);
}

void AppendKeyField(std::string& key, const OptionalU64& value) {
    key.push_back(kSep);
    if (value.present) {
        key.append(FormatU64(value.value, U64Format::Decimal));
    }
}

// 分析键：强身份走 "S"+跨会话主键，弱身份走 "W"+候选键。两个键空间必须分开，
// 否则弱候选会和强对象撞在一起，正好是 X-02 禁止的误合并。
std::string MakeAnalysisKey(const std::string& identity, const std::string& candidate) {
    std::string key;
    const bool weak = identity.empty();
    const std::string& body = weak ? candidate : identity;
    key.reserve(body.size() + 2U);
    key.push_back(weak ? 'W' : 'S');
    key.push_back(kSep);
    key.append(body);
    return key;
}

bool ContainsView(const std::vector<std::string>& list, const std::string& value) {
    return std::find(list.begin(), list.end(), value) != list.end();
}

// X-04：把一轮的逐视图命中折叠成"每个类别里有几个视图列出/没列出"的基数事实。
std::vector<CategoryObservation> BuildCategoryObservations(const RoundState& state,
                                                           std::uint32_t homeMask) {
    std::vector<CategoryObservation> result;
    for (const ViewHit& hit : state.hits) {
        auto found = std::find_if(result.begin(), result.end(),
                                  [&hit](const CategoryObservation& observation) {
                                      return observation.category == hit.category;
                                  });
        if (found == result.end()) {
            CategoryObservation observation;
            observation.category = hit.category;
            observation.comparable = CategoryComparable(homeMask, hit.category);
            result.push_back(observation);
            found = result.end() - 1;
        }
        ++found->viewsInCategory;
        if (hit.presence == ObjectPresence::Present) {
            ++found->viewsListing;
        } else if (hit.presence == ObjectPresence::AbsentInUsableView) {
            ++found->usableViewsNotListing;
        }
    }
    return result;
}

// X-02：候选边的分桶键。弱记录与强对象只有落在同一个桶里才值得两两比对 ——
// 否则就是 O(weak × strong)。桶键只用"两侧都必然拥有、且不同对象几乎不会相同"
// 的字段：进程/句柄用 PID、线程用 TID、驱动用镜像路径。桶键相同**不代表**是同
// 一个对象，真正的判定仍然交给 ObjectIdentity 的 Match*。
std::string LinkBucketKey(const ViewRecord& record) {
    std::string key(1, static_cast<char>(record.kind));
    switch (record.kind) {
    case ObjectKind::Process:
        AppendKeyField(key, record.process.pid);
        return key;
    case ObjectKind::Thread:
        AppendKeyField(key, record.thread.tid);
        return key;
    case ObjectKind::Driver:
        AppendKeyField(key, record.driver.imagePath);
        return key;
    default:
        return std::string();  // 其它类别本层还没有身份模型，不建候选边
    }
}

// X-02：按类型分派到对应的 Match*。这是 AnalyzeCrossView 里**唯一**真正调用
// ObjectIdentity 匹配器的地方 —— 强对象之间仍然按 crossSessionKey 精确相等合并
// （那是主键语义，本来就该严格），Match* 只用来给弱记录找候选。
MatchResult MatchRecords(const ViewRecord& a, const ViewRecord& b) noexcept {
    if (a.kind != b.kind) {
        return MatchResult::NoMatch;
    }
    switch (a.kind) {
    case ObjectKind::Process: return MatchProcessInstance(a.process, b.process);
    case ObjectKind::Thread:  return MatchThreadInstance(a.thread, b.thread);
    case ObjectKind::Driver:  return MatchDriverInstance(a.driver, b.driver);
    default:                  return MatchResult::NoMatch;
    }
}

// 候选边的依据说明：说清"凭什么认为可能是同一个"和"缺了什么所以不能确认"。
std::string DescribeLinkBasis(const ViewRecord& weak, const ViewRecord& strong) {
    std::string basis;
    switch (weak.kind) {
    case ObjectKind::Process:
        basis = "pid=" + FormatOptionalU64(weak.process.pid, U64Format::Decimal);
        if (!weak.process.createTime100ns.present) {
            basis += "；弱侧缺创建时间";
        }
        if (weak.process.bootId.empty() || strong.process.bootId.empty()) {
            basis += "；缺启动标识";
        }
        break;
    case ObjectKind::Thread:
        basis = "tid=" + FormatOptionalU64(weak.thread.tid, U64Format::Decimal);
        if (!weak.thread.createTime100ns.present) {
            basis += "；弱侧缺线程创建时间";
        }
        if (weak.thread.process.strength() != IdentityStrength::Strong) {
            basis += "；所属进程实例不完整";
        }
        break;
    case ObjectKind::Driver:
        basis = "path=" + weak.driver.imagePath;
        if (weak.driver.pdbSignature.empty()) {
            basis += "；弱侧缺 PDB 身份";
        }
        if (!weak.driver.timeDateStamp.present || !weak.driver.imageSize.present) {
            basis += "；弱侧缺 PE 头身份";
        }
        break;
    default:
        break;
    }
    return basis;
}

// X-06：见证视图（曾报告过该对象的视图）本轮是否全部可用且都不再列出它。
bool WitnessesAllUsablyAbsent(const RoundState& state, const std::vector<std::string>& witnesses) {
    for (const std::string& viewId : witnesses) {
        const auto found = std::find_if(state.hits.begin(), state.hits.end(),
                                        [&viewId](const ViewHit& hit) { return hit.viewId == viewId; });
        if (found == state.hits.end() || found->presence != ObjectPresence::AbsentInUsableView) {
            return false;
        }
    }
    return !witnesses.empty();
}

} // namespace

const char* ObjectPresenceName(ObjectPresence presence) noexcept {
    switch (presence) {
    case ObjectPresence::Present:               return "Present";
    case ObjectPresence::AbsentInUsableView:    return "AbsentInUsableView";
    case ObjectPresence::UnknownViewFailed:     return "UnknownViewFailed";
    case ObjectPresence::UnknownOutOfCoverage:  return "UnknownOutOfCoverage";
    case ObjectPresence::NotComparableCategory: return "NotComparableCategory";
    }
    return "UnknownViewFailed";
}

const char* ViewEntityCategoryName(ViewEntityCategory category) noexcept {
    switch (category) {
    case ViewEntityCategory::Unspecified:       return "Unspecified";
    case ViewEntityCategory::ProcessList:       return "ProcessList";
    case ViewEntityCategory::ThreadList:        return "ThreadList";
    case ViewEntityCategory::LoadedModuleList:  return "LoadedModuleList";
    case ViewEntityCategory::DriverObjectTable: return "DriverObjectTable";
    case ViewEntityCategory::DeviceObjectTree:  return "DeviceObjectTree";
    case ViewEntityCategory::ServiceConfig:     return "ServiceConfig";
    }
    return "Unspecified";
}

bool ViewUsableForAbsence(const EvidenceEnvelope& envelope, bool coversTargetScope) noexcept {
    // 超时、拒绝访问、不支持、未采集：一律不能当成"该视图确认不存在"。
    if (envelope.outcome.status != CollectionStatus::Success) {
        return false;
    }
    if (!coversTargetScope) {
        return false;
    }
    // 截断、命中上限、单项失败都会让"没列出"变成"可能没扫到"。
    if (!envelope.coverage.fullyCovered()) {
        return false;
    }
    // X-06：再要求账目给出正面证据。fullyCovered() 的否定项能挡住"记录到的失败"，
    // 挡不住"什么都没记录"——后者同样不能当成确认缺失。
    return CoverageProvesCompleteness(envelope.coverage);
}

const char* DiscrepancyStateName(DiscrepancyState state) noexcept {
    switch (state) {
    case DiscrepancyState::NoDiscrepancy:  return "NoDiscrepancy";
    case DiscrepancyState::PendingRecheck: return "PendingRecheck";
    case DiscrepancyState::Transient:      return "Transient";
    case DiscrepancyState::Persistent:     return "Persistent";
    case DiscrepancyState::ObjectEnded:    return "ObjectEnded";
    case DiscrepancyState::Unverifiable:   return "Unverifiable";
    case DiscrepancyState::CandidateOnly:  return "CandidateOnly";
    }
    return "Unverifiable";
}

bool StateConclusionConsistent(DiscrepancyState state, AnalysisConclusion conclusion) noexcept {
    switch (state) {
    case DiscrepancyState::Persistent:
        // 既然"达到复查轮数且始终缺失"，就不可能同时"没有可用观测"。
        return conclusion == AnalysisConclusion::DifferenceObserved;
    case DiscrepancyState::NoDiscrepancy:
        return conclusion != AnalysisConclusion::DifferenceObserved;
    case DiscrepancyState::Transient:
        return conclusion == AnalysisConclusion::NoDifferenceObserved ||
               conclusion == AnalysisConclusion::Indeterminate;
    case DiscrepancyState::ObjectEnded:
        // "对象已结束"解释了缺项，但它不是"覆盖足够且未发现矛盾"。
        return conclusion == AnalysisConclusion::Indeterminate ||
               conclusion == AnalysisConclusion::NoEvidence;
    case DiscrepancyState::PendingRecheck:
    case DiscrepancyState::Unverifiable:
    case DiscrepancyState::CandidateOnly:
        return conclusion == AnalysisConclusion::Indeterminate ||
               conclusion == AnalysisConclusion::NoEvidence;
    }
    return false;
}

std::string ViewRecord::identityKey() const {
    switch (kind) {
    case ObjectKind::Process: return process.crossSessionKey();
    case ObjectKind::Thread:  return thread.crossSessionKey();
    case ObjectKind::Driver:  return driver.crossSessionKey();
    default:                  return std::string();
    }
}

std::string ViewRecord::candidateKey() const {
    // X-02：这里用的全是"可复用"的标识，所以它只能用来在**本次分析内**把同一条弱记录
    // 的多个副本收成一个候选对象，绝不能拿去跨会话认定同一个对象。
    std::string key;
    switch (kind) {
    case ObjectKind::Process:
        key = "cand-proc";
        AppendKeyField(key, process.bootId);
        AppendKeyField(key, process.pid);
        AppendKeyField(key, process.imageName);
        break;
    case ObjectKind::Thread:
        key = "cand-thread";
        AppendKeyField(key, thread.process.bootId);
        AppendKeyField(key, thread.process.pid);
        AppendKeyField(key, thread.tid);
        AppendKeyField(key, thread.process.imageName);
        break;
    case ObjectKind::Driver:
        key = "cand-driver";
        AppendKeyField(key, driver.bootId);
        AppendKeyField(key, driver.imagePath);
        AppendKeyField(key, driver.pdbSignature);
        break;
    default:
        // 连 kind 都没有：只能按原始记录 id 保留，至少让报告能回到那一行（X-07）。
        key = "cand-raw";
        AppendKeyField(key, rawRecordId);
        break;
    }
    return key;
}

IdentityStrength ViewRecord::strength() const noexcept {
    switch (kind) {
    case ObjectKind::Process: return process.strength();
    case ObjectKind::Thread:  return thread.strength();
    case ObjectKind::Driver:  return driver.strength();
    default:                  return IdentityStrength::Unusable;
    }
}

std::string ViewRecord::displayText() const {
    switch (kind) {
    case ObjectKind::Process:
        return process.imageName + " (" + FormatOptionalU64(process.pid, U64Format::Decimal) + ")";
    case ObjectKind::Thread:
        return "TID " + FormatOptionalU64(thread.tid, U64Format::Decimal) + " @ " +
               thread.process.imageName;
    case ObjectKind::Driver:
        return driver.imagePath;
    default:
        // X-07：没有身份也要说得出跳过了什么，不能只留一个整数。
        return rawRecordId.empty() ? std::string() : ("raw:" + rawRecordId);
    }
}

CrossViewReport AnalyzeCrossView(const std::vector<SampleRound>& rounds,
                                 const CrossViewOptions& options) {
    CrossViewReport report;
    report.roundCount = rounds.size();
    if (rounds.empty()) {
        return report;
    }

    // -----------------------------------------------------------------------
    // 1) 跨**全部轮次**普查：视图并集、每轮实际视图数、每轮独立来源组数。
    //    X-01：只在第 1 轮到场、后面就崩掉的来源不能撑可信度，所以来源组数取
    //    每轮独立组数的最小值，视图集合取并集（缺席的轮次会在第 3 步显式产出
    //    NotCollected，而不是当作"这轮干干净净"）。
    // -----------------------------------------------------------------------
    std::vector<EvidenceEnvelope> allEnvelopes;
    std::vector<std::string> unionViewIds;
    std::vector<ViewEntityCategory> unionViewCategories;  // 与 unionViewIds 同序
    std::size_t minGroupCount = 0;
    std::size_t minRoundViewCount = 0;
    bool firstRound = true;

    for (const SampleRound& round : rounds) {
        std::vector<std::string> roundViewIds;
        std::vector<std::string> roundGroups;
        for (const ViewSnapshot& view : round.views) {
            if (ContainsView(roundViewIds, view.viewId)) {
                continue;  // 同一轮里重复的 viewId 只认第一份，不算两个视图
            }
            roundViewIds.push_back(view.viewId);
            allEnvelopes.push_back(view.envelope);
            const std::string& group = GroupOf(view.envelope.source);
            if (!ContainsView(roundGroups, group)) {
                roundGroups.push_back(group);
            }
            const auto found = std::find(unionViewIds.begin(), unionViewIds.end(), view.viewId);
            if (found == unionViewIds.end()) {
                unionViewIds.push_back(view.viewId);
                unionViewCategories.push_back(view.category);
            } else {
                unionViewCategories[static_cast<std::size_t>(found - unionViewIds.begin())] =
                    view.category;
            }
        }
        if (firstRound) {
            minGroupCount = roundGroups.size();
            minRoundViewCount = roundViewIds.size();
            firstRound = false;
        } else {
            minGroupCount = (std::min)(minGroupCount, roundGroups.size());
            minRoundViewCount = (std::min)(minRoundViewCount, roundViewIds.size());
        }
        report.latestRoundViewCount = roundViewIds.size();  // 循环结束后即最后一轮
    }

    report.viewCount = unionViewIds.size();
    report.minRoundViewCount = minRoundViewCount;
    report.independentSourceGroupCount = minGroupCount;

    // 信任说明取**全部轮次**的 envelope：最后一轮的 AccessDenied 与命中上限不能因为
    // "第 1 轮很干净"就从限制说明里消失（X-01/F-11）。
    report.trust = BuildTrustStatement(allEnvelopes);
    // BuildTrustStatement 按 envelope 条数计数（这里是 轮数 × 视图数），对 X 模块而言
    // 正确口径是"不同视图"与"每轮都在的独立来源"，所以覆盖掉这两项并重算对应限制项。
    report.trust.viewCount = report.viewCount;
    report.trust.independentSourceGroupCount = report.independentSourceGroupCount;
    report.trust.limitationKeys.erase(
        std::remove(report.trust.limitationKeys.begin(), report.trust.limitationKeys.end(),
                    std::string("trust.limitation.singleSourceGroup")),
        report.trust.limitationKeys.end());
    if (report.trust.independentSourceGroupCount <= 1U && report.trust.viewCount > 1U) {
        report.trust.limitationKeys.insert(report.trust.limitationKeys.begin(),
                                           "trust.limitation.singleSourceGroup");
    }

    // -----------------------------------------------------------------------
    // 2) 建对象集合 + 逐 (round, view) 的记录索引（X-09：identityKey 每条只算一次）。
    //    身份不足的记录不再被丢弃：它进入独立的候选键空间，报告里保留 kind /
    //    displayText / rawRecordId / 逐视图命中（X-02/X-07）。
    // -----------------------------------------------------------------------
    std::unordered_map<std::string, ObjectEntry> objects;
    std::vector<std::unordered_map<std::string, ViewIndex>> roundIndex(rounds.size());

    for (std::size_t roundIndexNo = 0; roundIndexNo < rounds.size(); ++roundIndexNo) {
        const SampleRound& round = rounds[roundIndexNo];
        std::unordered_map<std::string, ViewIndex>& index = roundIndex[roundIndexNo];
        for (const ViewSnapshot& view : round.views) {
            const auto inserted = index.try_emplace(view.viewId);
            if (!inserted.second) {
                continue;  // 与第 1 步一致：同轮重复 viewId 只认第一份
            }
            ViewIndex& viewIndex = inserted.first->second;
            viewIndex.view = &view;
            viewIndex.byKey.reserve(view.records.size());
            for (const ViewRecord& record : view.records) {
                const std::string identity = record.identityKey();
                const bool weak = identity.empty();
                std::string analysisKey =
                    MakeAnalysisKey(identity, weak ? record.candidateKey() : std::string());
                viewIndex.byKey.emplace(analysisKey, &record);
                if (weak) {
                    ++report.weakIdentityRecords;
                }
                ObjectEntry& entry = objects[analysisKey];
                if (!entry.initialized) {
                    entry.initialized = true;
                    entry.weak = weak;
                    entry.representative = &record;
                    entry.kind = record.kind;
                    entry.strength = record.strength();
                    entry.identityKey = identity;
                    entry.candidateKey = weak ? record.candidateKey() : std::string();
                    entry.displayText = record.displayText();
                    entry.firstSeenViewId = view.viewId;
                    entry.firstSeenRawRecordId = record.rawRecordId;
                    entry.firstSeenRoundIndex = roundIndexNo;
                    entry.perRound.resize(rounds.size());
                    if (weak) {
                        ++report.weakIdentityObjects;
                    }
                }
                entry.homeMask |= CategoryBit(view.category);
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3) 逐轮逐视图求存在性 —— 按**视图并集**遍历。
    //    X-06 / F-05：并集里存在但本轮整个缺席的视图（collector 崩了、驱动卸载了，
    //    连一个 NotCollected 的 envelope 都没送上来）必须产出 NotCollected 的命中并
    //    计入 unusableViews。一个从未被采集的视图不能推出"未发现差异"。
    // -----------------------------------------------------------------------
    for (std::size_t roundNo = 0; roundNo < rounds.size(); ++roundNo) {
        const std::unordered_map<std::string, ViewIndex>& index = roundIndex[roundNo];
        for (auto& item : objects) {
            const std::string& analysisKey = item.first;
            ObjectEntry& entry = item.second;
            RoundState& state = entry.perRound[roundNo];
            state.hits.reserve(unionViewIds.size());
            for (std::size_t viewNo = 0; viewNo < unionViewIds.size(); ++viewNo) {
                ViewHit hit;
                hit.viewId = unionViewIds[viewNo];
                const auto viewIt = index.find(unionViewIds[viewNo]);
                if (viewIt == index.end()) {
                    // 整轮缺席：sourceGroup 本轮未知，留空；状态是"根本没采集"。
                    hit.presence = ObjectPresence::UnknownViewFailed;
                    hit.viewStatus = CollectionStatus::NotCollected;
                    hit.category = unionViewCategories[viewNo];
                    ++state.unusableViews;
                    state.hits.push_back(std::move(hit));
                    continue;
                }
                const ViewSnapshot& view = *viewIt->second.view;
                hit.sourceGroup = GroupOf(view.envelope.source);
                hit.viewStatus = view.envelope.outcome.status;
                hit.category = view.category;

                const auto recordIt = viewIt->second.byKey.find(analysisKey);
                if (recordIt != viewIt->second.byKey.end()) {
                    hit.presence = ObjectPresence::Present;
                    hit.rawRecordId = recordIt->second->rawRecordId;
                    ++state.presentViews;
                    if (!ContainsView(entry.everPresentViews, hit.viewId)) {
                        entry.everPresentViews.push_back(hit.viewId);
                    }
                } else if (!CategoryComparable(entry.homeMask, view.category)) {
                    // X-04：另一类实体的视图没列出它，是结构现象，不是缺项。
                    hit.presence = ObjectPresence::NotComparableCategory;
                    ++state.crossCategoryViews;
                } else if (ViewUsableForAbsenceInRound(view)) {
                    hit.presence = ObjectPresence::AbsentInUsableView;
                    ++state.usableAbsentViews;
                } else if (view.envelope.outcome.status == CollectionStatus::Success ||
                           view.envelope.outcome.status == CollectionStatus::Partial) {
                    hit.presence = ObjectPresence::UnknownOutOfCoverage;
                    ++state.unusableViews;
                } else {
                    hit.presence = ObjectPresence::UnknownViewFailed;
                    ++state.unusableViews;
                }
                state.hits.push_back(std::move(hit));
            }
        }
    }

    // -----------------------------------------------------------------------
    // 3.5) X-02：给弱身份记录建"候选对应哪个强对象"的边。
    //
    // 规范要求身份不足时"保留候选关系"。此前弱记录只落成一条孤立的 CandidateOnly
    // finding，报告里看不出它可能就是哪个已确认对象；但反向合并进去又正是 X-02
    // 禁止的误合并。所以这里建**显式的候选边**：判定走 ObjectIdentity 的 Match*，
    // 由统一身份门槛保证结果最强只到 Candidate，NoMatch 的对不记录。
    //
    // 复杂度：先按 PID/TID/镜像路径分桶，只在同桶内两两比对。桶通常只有一两个成员，
    // 所以是 O(strong + weak) 而不是 O(weak × strong)。
    // -----------------------------------------------------------------------
    std::unordered_map<std::string, std::vector<CandidateLink>> linksByAnalysisKey;
    {
        std::unordered_map<std::string, std::vector<const std::pair<const std::string, ObjectEntry>*>> strongBuckets;
        for (const auto& item : objects) {
            const ObjectEntry& entry = item.second;
            if (entry.weak || entry.representative == nullptr) {
                continue;
            }
            const std::string bucket = LinkBucketKey(*entry.representative);
            if (bucket.empty()) {
                continue;
            }
            strongBuckets[bucket].push_back(&item);
        }

        for (const auto& item : objects) {
            const ObjectEntry& weakEntry = item.second;
            if (!weakEntry.weak || weakEntry.representative == nullptr) {
                continue;
            }
            const std::string bucket = LinkBucketKey(*weakEntry.representative);
            if (bucket.empty()) {
                continue;
            }
            const auto found = strongBuckets.find(bucket);
            if (found == strongBuckets.end()) {
                continue;
            }
            for (const auto* strongItem : found->second) {
                const ObjectEntry& strongEntry = strongItem->second;
                if (strongEntry.representative == nullptr) {
                    continue;
                }
                const MatchResult verdict =
                    MatchRecords(*weakEntry.representative, *strongEntry.representative);
                if (verdict == MatchResult::NoMatch) {
                    continue;
                }
                CandidateLink link;
                link.strongIdentityKey = strongEntry.identityKey;
                // 统一身份门槛保证弱侧参与的匹配不可能是 Confirmed；这里再钉一道，
                // 免得将来有人放宽了门槛而这里悄悄升级成确定关系。
                link.match = MatchResult::Candidate;
                link.basis = DescribeLinkBasis(*weakEntry.representative, *strongEntry.representative);
                linksByAnalysisKey[item.first].push_back(link);

                CandidateLink back;
                back.strongIdentityKey = weakEntry.candidateKey;
                back.match = MatchResult::Candidate;
                back.basis = link.basis;
                linksByAnalysisKey[strongItem->first].push_back(back);
                ++report.candidateLinkCount;
            }
        }
    }

    // -----------------------------------------------------------------------
    // 4) 状态机：首次缺项 -> 复采样 -> 分类 -> 结论（与状态同一证据窗口）。
    // -----------------------------------------------------------------------
    const std::size_t lastRound = rounds.size() - 1U;
    for (auto& item : objects) {
        ObjectEntry& entry = item.second;
        CrossViewFinding finding;
        finding.kind = entry.kind;
        finding.identityKey = entry.identityKey;
        finding.candidateKey = entry.candidateKey;
        finding.strength = entry.strength;
        finding.displayText = entry.displayText;
        finding.viewCount = unionViewIds.size();
        finding.independentSourceGroupCount = report.independentSourceGroupCount;
        finding.latestRoundViewCount = report.latestRoundViewCount;
        finding.latestHits = entry.perRound[lastRound].hits;
        finding.latestCategories = BuildCategoryObservations(entry.perRound[lastRound], entry.homeMask);
        finding.firstSeenViewId = entry.firstSeenViewId;
        finding.firstSeenRawRecordId = entry.firstSeenRawRecordId;
        finding.firstSeenRoundIndex = entry.firstSeenRoundIndex;
        {
            const auto links = linksByAnalysisKey.find(item.first);
            if (links != linksByAnalysisKey.end()) {
                finding.candidateLinks = links->second;
            }
        }

        // 首次出现差异的轮次：有视图看到、同时有可用视图没看到。
        std::size_t firstDiscrepancy = rounds.size();
        for (std::size_t i = 0; i < rounds.size(); ++i) {
            const RoundState& state = entry.perRound[i];
            if (state.presentViews > 0U && state.usableAbsentViews > 0U) {
                firstDiscrepancy = i;
                break;
            }
        }

        OptionalU64 firstUtc;
        if (firstDiscrepancy < rounds.size()) {
            firstUtc = rounds[firstDiscrepancy].sampleUtc100ns;
            for (std::size_t i = firstDiscrepancy; i < rounds.size(); ++i) {
                const RoundState& state = entry.perRound[i];
                RecheckEntry recheck;
                recheck.sampleId = rounds[i].sampleId;
                recheck.sampleUtc100ns = rounds[i].sampleUtc100ns;
                if (firstUtc.present && rounds[i].sampleUtc100ns.present) {
                    // X-05：无符号裸相减遇到 NTP 回拨会回绕成天文数字（≈5.8e13 年），
                    // 且看上去是个有效间隔。先比大小，回拨就明确标出来并保持 unset。
                    if (rounds[i].sampleUtc100ns.value >= firstUtc.value) {
                        recheck.intervalFromFirst100ns =
                            OptionalU64::of(rounds[i].sampleUtc100ns.value - firstUtc.value);
                    } else {
                        recheck.clockWentBackwards = true;
                    }
                }
                recheck.presentViews = state.presentViews;
                recheck.usableAbsentViews = state.usableAbsentViews;
                recheck.unusableViews = state.unusableViews;
                recheck.crossCategoryViews = state.crossCategoryViews;
                recheck.hits = state.hits;  // X-07：每轮都能展开逐视图命中与源记录 id
                finding.recheckHistory.push_back(std::move(recheck));
            }
        }

        std::size_t classificationRound = lastRound;
        if (entry.weak) {
            // X-02：身份不足的对象只保留候选关系，禁止参与任何差异升级。
            finding.state = DiscrepancyState::CandidateOnly;
            classificationRound = lastRound;
        } else if (firstDiscrepancy == rounds.size()) {
            finding.state = DiscrepancyState::NoDiscrepancy;
        } else {
            const std::size_t availableRecheckRounds = rounds.size() - firstDiscrepancy - 1U;
            bool reappeared = false;
            bool objectEnded = false;
            std::size_t usableRecheckRounds = 0;
            std::size_t persistentRounds = 0;

            for (std::size_t i = firstDiscrepancy + 1U; i < rounds.size(); ++i) {
                const RoundState& state = entry.perRound[i];
                if (state.presentViews == 0U && state.usableAbsentViews == 0U) {
                    // 该轮没有一个视图有资格判断（含"这一轮一个视图都没有"）。
                    // 这里不能要求 unusableViews > 0：视图数为 0 的空轮次三个计数全 0，
                    // 那样它会被算成一次有效复查，让阈值检查退化成冗余分支（X-05）。
                    continue;
                }
                ++usableRecheckRounds;
                if (state.presentViews > 0U && state.usableAbsentViews == 0U) {
                    reappeared = true;
                    classificationRound = i;
                    break;
                }
                if (objectEnded) {
                    continue;  // 已判定结束，后面只继续看会不会重新出现
                }
                if (state.presentViews == 0U && state.usableAbsentViews > 0U) {
                    // X-06 / BLOCKER：原本看到它的视图"这轮超时了"不等于"它不在了"。
                    // 只有本轮没有任何无法判断的视图、且所有见证视图都可用并且都不再
                    // 列出它，才允许判"对象已结束"；否则本轮按"无法复查"处理。
                    if (state.unusableViews == 0U &&
                        WitnessesAllUsablyAbsent(state, entry.everPresentViews)) {
                        objectEnded = true;
                        classificationRound = i;
                    }
                    continue;
                }
                ++persistentRounds;  // presentViews > 0 且 usableAbsentViews > 0
            }

            if (reappeared) {
                finding.state = DiscrepancyState::Transient;
            } else if (objectEnded) {
                finding.state = DiscrepancyState::ObjectEnded;
            } else if (availableRecheckRounds < options.requiredRecheckRounds) {
                finding.state = DiscrepancyState::PendingRecheck;
            } else if (usableRecheckRounds < options.requiredRecheckRounds) {
                // X-05/X-06：复查轮里没有足够的可用视图，不能升级为持续差异。
                finding.state = DiscrepancyState::Unverifiable;
            } else if (persistentRounds >= options.requiredRecheckRounds) {
                finding.state = DiscrepancyState::Persistent;
            } else {
                finding.state = DiscrepancyState::Unverifiable;
            }
        }

        // F-05：结论必须取与状态**同一个证据窗口**，不能拿最后一轮伪造的 envelope
        // 另算一遍 —— 那正是"state=Persistent 而 conclusion=NoEvidence"的来源。
        const std::size_t windowBegin =
            (firstDiscrepancy < rounds.size()) ? firstDiscrepancy : 0U;
        const std::size_t windowEnd =
            (firstDiscrepancy < rounds.size()) ? classificationRound : lastRound;
        bool windowHasUsable = false;
        bool windowFullyUsable = true;
        for (std::size_t i = windowBegin; i <= windowEnd; ++i) {
            const RoundState& state = entry.perRound[i];
            if (state.presentViews > 0U || state.usableAbsentViews > 0U) {
                windowHasUsable = true;
            }
            if (state.unusableViews > 0U) {
                windowFullyUsable = false;
            }
        }

        switch (finding.state) {
        case DiscrepancyState::Persistent:
            finding.conclusion = AnalysisConclusion::DifferenceObserved;
            break;
        case DiscrepancyState::Transient:
            // 缺项被复采样解释掉了；只有整个窗口都可用才谈得上"未发现差异"。
            finding.conclusion = (windowHasUsable && windowFullyUsable)
                                     ? AnalysisConclusion::NoDifferenceObserved
                                     : AnalysisConclusion::Indeterminate;
            break;
        case DiscrepancyState::NoDiscrepancy:
            finding.conclusion = !windowHasUsable ? AnalysisConclusion::NoEvidence
                                 : (windowFullyUsable ? AnalysisConclusion::NoDifferenceObserved
                                                      : AnalysisConclusion::Indeterminate);
            break;
        case DiscrepancyState::ObjectEnded:
            // X-05/F-05：对象已结束解释了缺项，但它不是"覆盖足够且未发现矛盾"。
            finding.conclusion = AnalysisConclusion::Indeterminate;
            break;
        case DiscrepancyState::PendingRecheck:
        case DiscrepancyState::Unverifiable:
        case DiscrepancyState::CandidateOnly:
            finding.conclusion = windowHasUsable ? AnalysisConclusion::Indeterminate
                                                 : AnalysisConclusion::NoEvidence;
            break;
        }

        // 不变式兜底：禁止 Persistent+NoEvidence、ObjectEnded+NoDifferenceObserved
        // 这类自相矛盾的组合流出去。命中说明上面的映射漏了分支，整份报告降级。
        if (!StateConclusionConsistent(finding.state, finding.conclusion)) {
            finding.conclusion = AnalysisConclusion::Indeterminate;
            report.selfCheckPassed = false;
        }

        report.findings.push_back(std::move(finding));
    }

    std::sort(report.findings.begin(), report.findings.end(),
              [](const CrossViewFinding& a, const CrossViewFinding& b) {
                  // 强身份在前、候选态在后；组内按键排序，保证输出稳定可比对。
                  const bool aWeak = a.identityKey.empty();
                  const bool bWeak = b.identityKey.empty();
                  if (aWeak != bWeak) {
                      return !aWeak;
                  }
                  const std::string& ka = aWeak ? a.candidateKey : a.identityKey;
                  const std::string& kb = bWeak ? b.candidateKey : b.identityKey;
                  if (ka != kb) {
                      return ka < kb;
                  }
                  return a.displayText < b.displayText;
              });

    // 内部一致性自检（X-01/X-07）：
    //   * 每条 finding 的 latestHits 必须逐视图铺满整个视图并集 —— 缺一条就说明
    //     有视图被静默跳过了；
    //   * 声称的独立来源组数不得超过最后一轮实际出现的来源组数 —— 否则就是拿一个
    //     已经不在场的来源、或者拿同一组的重复视图在撑可信度。
    for (const CrossViewFinding& finding : report.findings) {
        if (finding.latestHits.size() != report.viewCount ||
            finding.viewCount != report.viewCount) {
            report.selfCheckPassed = false;
            break;
        }
        std::vector<std::string> latestGroups;
        for (const ViewHit& hit : finding.latestHits) {
            if (!hit.sourceGroup.empty() && !ContainsView(latestGroups, hit.sourceGroup)) {
                latestGroups.push_back(hit.sourceGroup);
            }
        }
        if (finding.independentSourceGroupCount > latestGroups.size()) {
            report.selfCheckPassed = false;
            break;
        }
    }

    return report;
}

} // namespace Ksword::Evidence
