#include "ImageDiff.h"

#include <algorithm>
#include <utility>

namespace Ksword::Evidence {
namespace {

constexpr std::size_t kNoRule = static_cast<std::size_t>(-1);

// 已通过准入的规则集合。索引指回调用方原始的 rules 数组，条目里的 ruleId /
// ruleVersion 才对得上。
std::size_t RuleIndexForRva(const std::vector<ExplanationRule>& rules,
                            const std::vector<std::size_t>& admitted,
                            std::uint32_t rva) noexcept {
    for (const std::size_t index : admitted) {
        if (rules[index].range.contains(rva)) {
            return index;
        }
    }
    return kNoRule;
}

// 折叠前的原始片段。key 由 (kind, readStatus, sectionIndex, ruleIndex) 组成，
// 任一项变化都必须断开 —— 否则折叠后的 readStatus 或 ruleId 会代表不了里面的字节。
struct Piece final {
    std::uint32_t rva = 0;
    std::uint32_t length = 0;
    DiffKind kind = DiffKind::ByteDifference;
    ByteReadStatus readStatus = ByteReadStatus::Read;
    std::size_t sectionIndex = kInvalidSectionIndex;
    std::size_t ruleIndex = kNoRule;

    std::uint64_t endExclusive() const noexcept {
        return static_cast<std::uint64_t>(rva) + static_cast<std::uint64_t>(length);
    }

    bool sameKey(const Piece& other) const noexcept {
        return kind == other.kind && readStatus == other.readStatus &&
               sectionIndex == other.sectionIndex && ruleIndex == other.ruleIndex;
    }
};

void AppendBytes(std::vector<std::uint8_t>& target,
                 const std::vector<std::uint8_t>& source,
                 std::size_t offset,
                 std::size_t count) {
    if (offset >= source.size()) {
        return;
    }
    const std::size_t available = std::min(count, source.size() - offset);
    target.insert(target.end(),
                  source.begin() + static_cast<std::ptrdiff_t>(offset),
                  source.begin() + static_cast<std::ptrdiff_t>(offset + available));
}

} // namespace

// ---------------------------------------------------------------------------
// 枚举名字
// ---------------------------------------------------------------------------

const char* ByteReadStatusName(ByteReadStatus status) noexcept {
    switch (status) {
    case ByteReadStatus::Read:         return "Read";
    case ByteReadStatus::Unreadable:   return "Unreadable";
    case ByteReadStatus::NotCollected: return "NotCollected";
    }
    return "NotCollected";
}

const char* DiffExplanationName(DiffExplanation explanation) noexcept {
    switch (explanation) {
    case DiffExplanation::Unexplained: return "Unexplained";
    case DiffExplanation::Explained:   return "Explained";
    }
    return "Unexplained";
}

const char* DiffKindName(DiffKind kind) noexcept {
    switch (kind) {
    case DiffKind::ByteDifference:   return "ByteDifference";
    case DiffKind::MissingLiveBytes: return "MissingLiveBytes";
    }
    return "ByteDifference";
}

const char* ModuleStalenessVerdictName(ModuleStalenessVerdict verdict) noexcept {
    switch (verdict) {
    case ModuleStalenessVerdict::Same:         return "Same";
    case ModuleStalenessVerdict::Stale:        return "Stale";
    case ModuleStalenessVerdict::Unverifiable: return "Unverifiable";
    }
    return "Unverifiable";
}

const char* ReferenceSourceKindName(ReferenceSourceKind kind) noexcept {
    switch (kind) {
    case ReferenceSourceKind::LocalDisk:         return "LocalDisk";
    case ReferenceSourceKind::UserSelectedImage: return "UserSelectedImage";
    case ReferenceSourceKind::SavedSnapshot:     return "SavedSnapshot";
    }
    return "LocalDisk";
}

const char* TargetOwnerKindName(TargetOwnerKind kind) noexcept {
    switch (kind) {
    case TargetOwnerKind::InsideModule:        return "InsideModule";
    case TargetOwnerKind::OutsideKnownModules: return "OutsideKnownModules";
    }
    return "OutsideKnownModules";
}

const char* FollowStepKindName(FollowStepKind kind) noexcept {
    switch (kind) {
    case FollowStepKind::ResolvedCode:       return "ResolvedCode";
    case FollowStepKind::DirectBranch:       return "DirectBranch";
    case FollowStepKind::IndirectUnresolved: return "IndirectUnresolved";
    case FollowStepKind::ExportForwarder:    return "ExportForwarder";
    case FollowStepKind::TargetUnreadable:   return "TargetUnreadable";
    }
    return "TargetUnreadable";
}

const char* FollowTerminationName(FollowTermination termination) noexcept {
    switch (termination) {
    case FollowTermination::Resolved:            return "Resolved";
    case FollowTermination::DepthExhausted:      return "DepthExhausted";
    case FollowTermination::ByteBudgetExhausted: return "ByteBudgetExhausted";
    case FollowTermination::CycleDetected:       return "CycleDetected";
    case FollowTermination::TargetUnreadable:    return "TargetUnreadable";
    case FollowTermination::OutsideKnownModules: return "OutsideKnownModules";
    case FollowTermination::IndirectUnresolved:  return "IndirectUnresolved";
    case FollowTermination::ExportForwarder:     return "ExportForwarder";
    }
    return "TargetUnreadable";
}

// ---------------------------------------------------------------------------
// LiveImageBytes
// ---------------------------------------------------------------------------

RvaRange LiveImageBytes::window() const noexcept {
    RvaRange range;
    range.rva = baseRva;
    const std::uint64_t count = static_cast<std::uint64_t>(bytes.size());
    const std::uint64_t end = std::min<std::uint64_t>(
        static_cast<std::uint64_t>(baseRva) + count, 0xFFFFFFFFULL);
    range.length = static_cast<std::uint32_t>(end - static_cast<std::uint64_t>(baseRva));
    return range;
}

ByteReadStatus LiveImageBytes::statusAt(std::uint32_t rva) const noexcept {
    if (!wellFormed() || rva < baseRva) {
        return ByteReadStatus::NotCollected;
    }
    const std::uint64_t offset = static_cast<std::uint64_t>(rva) - static_cast<std::uint64_t>(baseRva);
    if (offset >= static_cast<std::uint64_t>(status.size())) {
        return ByteReadStatus::NotCollected;
    }
    return status[static_cast<std::size_t>(offset)];
}

bool LiveImageBytes::byteAt(std::uint32_t rva, std::uint8_t& out) const noexcept {
    if (statusAt(rva) != ByteReadStatus::Read) {
        return false;
    }
    const std::size_t offset = static_cast<std::size_t>(rva - baseRva);
    out = bytes[offset];
    return true;
}

LiveImageBytes LiveImageBytes::fromBytes(std::uint32_t baseRvaIn, std::vector<std::uint8_t> data) {
    LiveImageBytes live;
    live.baseRva = baseRvaIn;
    live.status.assign(data.size(), ByteReadStatus::Read);
    live.bytes = std::move(data);
    return live;
}

void LiveImageBytes::markRange(const RvaRange& range, ByteReadStatus newStatus) noexcept {
    if (!wellFormed() || range.empty()) {
        return;
    }
    const std::uint64_t windowBegin = baseRva;
    const std::uint64_t windowEnd = windowBegin + static_cast<std::uint64_t>(status.size());
    const std::uint64_t begin = std::max<std::uint64_t>(range.rva, windowBegin);
    const std::uint64_t end = std::min<std::uint64_t>(range.endExclusive(), windowEnd);
    for (std::uint64_t at = begin; at < end; ++at) {
        status[static_cast<std::size_t>(at - windowBegin)] = newStatus;
    }
}

// ---------------------------------------------------------------------------
// I-04 规则
// ---------------------------------------------------------------------------

const char* RuleAdmissionName(RuleAdmission admission) noexcept {
    switch (admission) {
    case RuleAdmission::Accepted:              return "Accepted";
    case RuleAdmission::Unusable:              return "Unusable";
    case RuleAdmission::CoversWholeImage:      return "CoversWholeImage";
    case RuleAdmission::NotScopedToOneSection: return "NotScopedToOneSection";
    }
    return "Unusable";
}

RuleAdmission AdmitExplanationRule(const PeImageMap& reference,
                                   const ExplanationRule& rule) noexcept {
    if (!rule.usable()) {
        return RuleAdmission::Unusable;
    }
    if (!reference.valid()) {
        // 参考映像都解析不了就没有"范围"可言，谈不上豁免。
        return RuleAdmission::NotScopedToOneSection;
    }
    RvaRange imageRange;
    imageRange.rva = 0U;
    imageRange.length = reference.header.sizeOfImage;
    if (rule.range.containsRange(imageRange)) {
        // 覆盖整份映像 = 给整份驱动永久放行。I-04 通过条件里被点名禁止的那条路。
        return RuleAdmission::CoversWholeImage;
    }
    // 豁免必须精确到范围：整段落在某一个已映射节里，或整段落在 PE 头里。
    // 跨节的"依据"没有可核对的对象 —— 一条规则说不清它同时在解释两个节里的什么。
    if (reference.headerRange.containsRange(rule.range)) {
        return RuleAdmission::Accepted;
    }
    for (const SectionMap& section : reference.sections) {
        if (section.status != SectionMapStatus::Mapped) {
            continue;
        }
        if (section.virtualRange().containsRange(rule.range)) {
            return RuleAdmission::Accepted;
        }
    }
    return RuleAdmission::NotScopedToOneSection;
}

const ExplanationRule* FindExplanationRule(const PeImageMap& reference,
                                           const std::vector<ExplanationRule>& rules,
                                           const RvaRange& span) noexcept {
    for (const ExplanationRule& rule : rules) {
        if (AdmitExplanationRule(reference, rule) == RuleAdmission::Accepted &&
            rule.range.containsRange(span)) {
            return &rule;
        }
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// I-09 统计与身份复核
// ---------------------------------------------------------------------------

void AccumulateStats(ScanCoverageStats& accumulator, const ScanCoverageStats& one) noexcept {
    accumulator.modules.attempted += one.modules.attempted;
    accumulator.modules.succeeded += one.modules.succeeded;
    accumulator.modules.failed += one.modules.failed;
    accumulator.modules.excluded += one.modules.excluded;
    accumulator.modules.notAttempted += one.modules.notAttempted;
    accumulator.bytes.attempted += one.bytes.attempted;
    accumulator.bytes.succeeded += one.bytes.succeeded;
    accumulator.bytes.failed += one.bytes.failed;
    accumulator.bytes.excluded += one.bytes.excluded;
    accumulator.bytes.notAttempted += one.bytes.notAttempted;
    accumulator.pages.attempted += one.pages.attempted;
    accumulator.pages.succeeded += one.pages.succeeded;
    accumulator.pages.failed += one.pages.failed;
    accumulator.pages.excluded += one.pages.excluded;
    accumulator.pages.notAttempted += one.pages.notAttempted;
    if (accumulator.pageSize == 0U) {
        accumulator.pageSize = one.pageSize;
    }
}

ModuleStalenessVerdict CheckModuleStillSame(const DriverInstanceId& before,
                                            const DriverInstanceId& after) noexcept {
    if (before.strength() == IdentityStrength::Unusable) {
        // 读前就没有可用身份，读后再怎么比也确认不了 —— 不能假装"还是同一个"。
        return ModuleStalenessVerdict::Unverifiable;
    }
    if (after.strength() == IdentityStrength::Unusable) {
        // 读后拿不到任何身份：模块已卸载，或复核本身失败。两种情况都不允许继续
        // 用旧地址解释差异，因此保守判过期。
        return ModuleStalenessVerdict::Stale;
    }
    if (!before.bootId.empty() && !after.bootId.empty() && before.bootId != after.bootId) {
        // 跨启动周期的地址没有可比性。
        return ModuleStalenessVerdict::Stale;
    }
    if (before.imageBase.present && after.imageBase.present &&
        before.imageBase.value != after.imageBase.value) {
        // 同一启动周期内基址变了：模块被重载过，之前算出的 RVA→VA 映射全部失效。
        return ModuleStalenessVerdict::Stale;
    }

    switch (MatchDriverInstance(before, after)) {
    case MatchResult::Confirmed:
        return ModuleStalenessVerdict::Same;
    case MatchResult::NoMatch:
        return ModuleStalenessVerdict::Stale;
    case MatchResult::Candidate:
        return ModuleStalenessVerdict::Unverifiable;
    }
    return ModuleStalenessVerdict::Unverifiable;
}

// ---------------------------------------------------------------------------
// I-10 比较依据
// ---------------------------------------------------------------------------

std::vector<std::string> BuildTrustNotes(const ReferenceSource& source) {
    std::vector<std::string> notes;
    switch (source.kind) {
    case ReferenceSourceKind::LocalDisk:
        notes.emplace_back("integrity.reference.localDisk");
        // 本机磁盘不是不可篡改的信任根：能改内核的攻击者一般也能改盘上的文件。
        notes.emplace_back("integrity.reference.localDisk.notATrustRoot");
        notes.emplace_back("integrity.reference.localDisk.sameNameMayBeOtherVersion");
        break;
    case ReferenceSourceKind::UserSelectedImage:
        notes.emplace_back("integrity.reference.userSelected");
        notes.emplace_back("integrity.reference.userSelected.versionMustBeConfirmed");
        notes.emplace_back("integrity.reference.userSelected.providedByOperator");
        break;
    case ReferenceSourceKind::SavedSnapshot:
        notes.emplace_back("integrity.reference.savedSnapshot");
        notes.emplace_back("integrity.reference.savedSnapshot.mayPredateChange");
        notes.emplace_back("integrity.reference.savedSnapshot.capturedOnThisMachine");
        break;
    }
    // 签名状态与"字节一致"是两回事，任何来源下都要说清楚。
    notes.emplace_back("integrity.reference.signatureIsNotByteEquality");
    if (source.identity.strength() == IdentityStrength::Unusable) {
        notes.emplace_back("integrity.reference.identityUnusable");
    }
    return notes;
}

// ---------------------------------------------------------------------------
// I-05 差异引擎
// ---------------------------------------------------------------------------

ImageDiffReport CompareImage(const PeImageMap& reference,
                             const LiveImageBytes& live,
                             const ImageDiffOptions& options) {
    ImageDiffReport report;
    report.reference = options.reference;
    report.trustNotes = BuildTrustNotes(options.reference);
    report.staleness = options.staleness;
    report.stats.pageSize = (options.pageSize != 0U) ? options.pageSize : 4096U;
    report.stats.modules.attempted = 1U;

    if (!reference.valid()) {
        // 参考映像本身无法解析：不产出任何差异，也绝不产出"未发现差异"。
        report.outcome = CollectionOutcome::failure(CollectionStatus::Error, "PE",
                                                    static_cast<std::uint64_t>(reference.status),
                                                    reference.errorDetail);
        report.limitationKeys.emplace_back("integrity.limitation.referenceUnparsable");
        report.stats.modules.failed = 1U;
        report.conclusion = AnalysisConclusion::NoEvidence;
        return report;
    }

    // 1) 计算有效比较集合。
    RvaRange imageRange;
    imageRange.rva = 0U;
    imageRange.length = reference.header.sizeOfImage;
    // 默认请求集合用 rawBackedRanges（减 notComparable 之前的口径）：不可比较的字节
    // 必须以"已排除"的身份进账，而不是从请求里凭空消失。
    std::vector<RvaRange> base = options.compareRanges.empty() ? reference.rawBackedRanges
                                                               : options.compareRanges;
    base = IntersectRvaRanges(base, std::vector<RvaRange>{imageRange});

    std::vector<RvaRange> excluded = reference.notComparableRanges;
    excluded.insert(excluded.end(), options.excludedRanges.begin(), options.excludedRanges.end());
    excluded = NormalizeRvaRanges(std::move(excluded));

    const std::vector<RvaRange> effective = SubtractRvaRanges(base, excluded);
    report.excludedRanges = IntersectRvaRanges(base, excluded);
    report.excludedBytes = RvaRangesTotalBytes(report.excludedRanges);
    const std::uint64_t effectiveBytes = RvaRangesTotalBytes(effective);

    // 1b) I-04 规则准入。过宽或跨节的规则一律丢弃并留下限制键 —— 静默忽略会让
    //     调用方以为豁免生效了，静默接受则等于整模块放行。
    std::vector<std::size_t> admittedRules;
    admittedRules.reserve(options.rules.size());
    bool sawWholeImageRule = false;
    bool sawUnscopedRule = false;
    bool sawUnusableRule = false;
    for (std::size_t index = 0; index < options.rules.size(); ++index) {
        switch (AdmitExplanationRule(reference, options.rules[index])) {
        case RuleAdmission::Accepted:
            admittedRules.push_back(index);
            break;
        case RuleAdmission::CoversWholeImage:
            sawWholeImageRule = true;
            ++report.rejectedRuleCount;
            break;
        case RuleAdmission::NotScopedToOneSection:
            sawUnscopedRule = true;
            ++report.rejectedRuleCount;
            break;
        case RuleAdmission::Unusable:
            sawUnusableRule = true;
            ++report.rejectedRuleCount;
            break;
        }
    }

    // 2) 页级位图。SizeOfImage 有 512MB 上限，位图规模可控。
    const std::uint32_t pageSize = report.stats.pageSize;
    const std::size_t pageCount =
        static_cast<std::size_t>((static_cast<std::uint64_t>(reference.header.sizeOfImage) +
                                  pageSize - 1U) / pageSize);
    std::vector<bool> pageCompared(pageCount, false);
    std::vector<bool> pageFailed(pageCount, false);
    std::vector<bool> pageExcluded(pageCount, false);
    // 落在有效比较集合里的页。命中上限提前停止时，靠它把"从未扫描"的页记进
    // notAttempted，而不是让它们从账目里消失。
    std::vector<bool> pageInEffective(pageCount, false);
    for (const RvaRange& range : effective) {
        for (std::uint64_t at = range.rva; at < range.endExclusive(); at += pageSize) {
            const std::size_t page = static_cast<std::size_t>(at / pageSize);
            if (page < pageCount) {
                pageInEffective[page] = true;
            }
        }
        const std::uint64_t lastPage = (range.endExclusive() - 1U) / pageSize;
        if (lastPage < static_cast<std::uint64_t>(pageCount)) {
            pageInEffective[static_cast<std::size_t>(lastPage)] = true;
        }
    }
    for (const RvaRange& range : report.excludedRanges) {
        for (std::uint64_t at = range.rva; at < range.endExclusive(); at += pageSize) {
            const std::size_t page = static_cast<std::size_t>(at / pageSize);
            if (page < pageCount) {
                pageExcluded[page] = true;
            }
        }
        const std::uint64_t lastPage = (range.endExclusive() - 1U) / pageSize;
        if (lastPage < static_cast<std::uint64_t>(pageCount)) {
            pageExcluded[static_cast<std::size_t>(lastPage)] = true;
        }
    }

    // 3) 逐字节扫描，产出未折叠片段。
    // pieceCap 是真正会停住扫描的那条上限：折叠发生在扫描之后，所以 maxEntries
    // 管不住片段数。它必须被当成一条公开的约束记账（F-06），不能只留在这里。
    const std::size_t pieceCap = options.maxEntries * 4U + 16U;
    report.entryLimit = static_cast<std::uint64_t>(options.maxEntries);
    report.pieceLimit = static_cast<std::uint64_t>(pieceCap);
    std::vector<Piece> pieces;
    Piece current;
    bool haveCurrent = false;
    std::size_t cachedSection = kInvalidSectionIndex;
    bool stopped = false;
    OptionalU64 processedBegin;
    std::uint64_t processedEnd = 0U;

    auto flush = [&]() {
        if (haveCurrent) {
            pieces.push_back(current);
            haveCurrent = false;
        }
    };

    for (const RvaRange& range : effective) {
        if (stopped) {
            break;
        }
        if (!processedBegin.present) {
            processedBegin = OptionalU64::of(range.rva);
        }
        for (std::uint64_t at = range.rva; at < range.endExclusive(); ++at) {
            const std::uint32_t rva = static_cast<std::uint32_t>(at);
            const std::size_t page = static_cast<std::size_t>(at / pageSize);
            if (page < pageCount) {
                pageCompared[page] = true;
            }
            report.stats.bytes.attempted += 1U;

            const ByteReadStatus liveStatus = live.statusAt(rva);
            if (liveStatus == ByteReadStatus::Read) {
                std::uint8_t liveByte = 0U;
                const bool got = live.byteAt(rva, liveByte);
                const std::uint8_t referenceByte = reference.image[static_cast<std::size_t>(rva)];
                report.comparedBytes += 1U;
                if (got && liveByte == referenceByte) {
                    // 相同：断开当前片段，但不产生任何条目。
                    flush();
                    processedEnd = at + 1U;
                    continue;
                }
                report.differingBytes += 1U;
            } else {
                // I-05：读不到的字节是缺失标记，不参与字节比较，也不计入差异。
                if (liveStatus == ByteReadStatus::Unreadable) {
                    report.unreadableBytes += 1U;
                } else {
                    report.notCollectedBytes += 1U;
                }
                report.stats.bytes.failed += 1U;
                if (page < pageCount) {
                    pageFailed[page] = true;
                }
            }

            // 到这里说明该字节要进条目：要么是真差异，要么是缺失标记。
            if (cachedSection == kInvalidSectionIndex ||
                !reference.sections[cachedSection].virtualRange().contains(rva) ||
                reference.sections[cachedSection].status != SectionMapStatus::Mapped) {
                cachedSection = SectionIndexForRva(reference, rva);
            }
            const DiffKind kind = (liveStatus == ByteReadStatus::Read) ? DiffKind::ByteDifference
                                                                       : DiffKind::MissingLiveBytes;
            // 缺失标记从不带解释：没读到就没有可核对的依据。
            const std::size_t ruleIndex = (kind == DiffKind::ByteDifference)
                                              ? RuleIndexForRva(options.rules, admittedRules, rva)
                                              : kNoRule;

            Piece candidate;
            candidate.rva = rva;
            candidate.length = 1U;
            candidate.kind = kind;
            candidate.readStatus = liveStatus;
            candidate.sectionIndex = cachedSection;
            candidate.ruleIndex = ruleIndex;

            if (haveCurrent && current.sameKey(candidate) && current.endExclusive() == at) {
                current.length += 1U;
            } else {
                flush();
                current = candidate;
                haveCurrent = true;
                if (pieces.size() >= pieceCap) {
                    // 片段数命中上限：保留已产出的部分，并明确记账为不完整。
                    stopped = true;
                    report.limitHit = true;
                    break;
                }
            }
            processedEnd = at + 1U;
        }
    }
    flush();

    report.stats.bytes.succeeded = report.comparedBytes;
    report.stats.bytes.excluded = report.excludedBytes;
    // F-06：命中片段上限时，有效比较集合里还没走到的尾部一个字节都没进任何桶。
    // 它既不是失败也不是排除，单独立一个桶，账目才闭合：
    //   attempted + notAttempted + excluded == 请求集合字节数。
    report.notAttemptedBytes =
        (effectiveBytes > report.stats.bytes.attempted)
            ? (effectiveBytes - report.stats.bytes.attempted)
            : 0U;
    report.stats.bytes.notAttempted = report.notAttemptedBytes;

    for (std::size_t page = 0; page < pageCount; ++page) {
        // 排除与比较是两个独立事实：一个页可以既有被比较的字节，又有被排除的
        // 字节。只在"整页从未被比较"时才计入 excluded，会让含排除窗口的页报出
        // 100% 成功（I-09）。因此两个桶分别判，同一页可以同时进 attempted 与
        // excluded。
        if (pageCompared[page]) {
            report.stats.pages.attempted += 1U;
            if (pageFailed[page]) {
                report.stats.pages.failed += 1U;
            } else {
                report.stats.pages.succeeded += 1U;
            }
        }
        if (pageExcluded[page]) {
            report.stats.pages.excluded += 1U;
        }
        if (!pageCompared[page] && pageInEffective[page]) {
            report.stats.pages.notAttempted += 1U;
        }
    }
    report.scanStoppedAtPieceLimit = stopped;

    // 4) 折叠成条目。折叠只在同 key 且间隔不超过 collapseGapBytes 时发生，
    //    原始片段全部保留在 subRanges 里。
    std::vector<std::vector<Piece>> groups;
    for (const Piece& piece : pieces) {
        bool merged = false;
        if (!groups.empty()) {
            std::vector<Piece>& back = groups.back();
            const Piece& last = back.back();
            if (last.sameKey(piece) && piece.rva >= last.endExclusive()) {
                const std::uint64_t gap = static_cast<std::uint64_t>(piece.rva) - last.endExclusive();
                if (gap <= static_cast<std::uint64_t>(options.collapseGapBytes)) {
                    bool ruleStillCovers = true;
                    if (piece.ruleIndex != kNoRule) {
                        RvaRange span;
                        span.rva = back.front().rva;
                        span.length = static_cast<std::uint32_t>(piece.endExclusive() - span.rva);
                        // 折叠后的整段必须仍落在同一条规则范围内，否则被折进来的
                        // 间隔字节会跟着一起"被解释"。
                        ruleStillCovers = options.rules[piece.ruleIndex].range.containsRange(span);
                    }
                    if (ruleStillCovers) {
                        back.push_back(piece);
                        merged = true;
                    }
                }
            }
        }
        if (!merged) {
            groups.push_back(std::vector<Piece>{piece});
        }
    }

    std::size_t dropped = 0U;
    for (const std::vector<Piece>& group : groups) {
        if (report.entries.size() >= options.maxEntries) {
            ++dropped;
            continue;
        }
        const Piece& first = group.front();
        const Piece& last = group.back();

        ImageDiffEntry entry;
        entry.kind = first.kind;
        entry.module = options.module;   // I-05：差异必须能指回具体模块实例
        entry.rva = first.rva;
        entry.length = static_cast<std::uint32_t>(last.endExclusive() - first.rva);
        entry.va = reference.loadedBase + entry.rva;
        entry.readStatus = first.readStatus;
        entry.sectionIndex = first.sectionIndex;
        entry.sectionName = SectionNameForRva(reference, first.rva);
        entry.evidenceSource = options.evidenceSource;
        entry.collapsed = group.size() > 1U;

        // I-05：反汇编上下文。本层没有解码器，所以请求解码只能得到"尝试过但解不
        // 出来"+ 一个明确的原因键；没请求就是"没尝试"。两者必须能区分，而且都
        // 不影响上面已经填好的原始字节证据。
        if (options.attemptDisassembly) {
            entry.disassembly.attempted = true;
            entry.disassembly.decoded = false;
            entry.disassembly.unavailableReasonKey = kDisassemblyUnavailableNoDecoder;
        }

        if (first.ruleIndex != kNoRule) {
            const ExplanationRule& rule = options.rules[first.ruleIndex];
            entry.explanation = DiffExplanation::Explained;
            entry.ruleId = rule.ruleId;
            entry.ruleVersion = rule.ruleVersion;
            entry.ruleEvidence = rule.evidenceText;
        }

        for (const Piece& piece : group) {
            DiffSubRange sub;
            sub.rva = piece.rva;
            sub.length = piece.length;
            AppendBytes(sub.referenceBytes, reference.image, static_cast<std::size_t>(piece.rva),
                        static_cast<std::size_t>(piece.length));
            if (piece.readStatus == ByteReadStatus::Read) {
                for (std::uint32_t offset = 0U; offset < piece.length; ++offset) {
                    std::uint8_t value = 0U;
                    if (live.byteAt(piece.rva + offset, value)) {
                        sub.liveBytes.push_back(value);
                    }
                }
            }
            // readStatus != Read 时 liveBytes 保持为空：绝不补 00。
            entry.subRanges.push_back(std::move(sub));
        }

        // 条目上的字节证据有上限，超出部分只在 subRanges 里保留完整原始范围描述。
        // 截断必须显式标出来，不能让调用方以为拿到的是全部字节。
        const std::size_t byteCap = static_cast<std::size_t>(options.maxBytesPerEntry);
        for (const DiffSubRange& sub : entry.subRanges) {
            const std::size_t referenceRoom =
                (entry.referenceBytes.size() < byteCap) ? (byteCap - entry.referenceBytes.size()) : 0U;
            if (referenceRoom < sub.referenceBytes.size()) {
                entry.byteEvidenceTruncated = true;
            }
            AppendBytes(entry.referenceBytes, sub.referenceBytes, 0U, referenceRoom);
            if (entry.kind == DiffKind::ByteDifference) {
                const std::size_t liveRoom =
                    (entry.liveBytes.size() < byteCap) ? (byteCap - entry.liveBytes.size()) : 0U;
                if (liveRoom < sub.liveBytes.size()) {
                    entry.byteEvidenceTruncated = true;
                }
                AppendBytes(entry.liveBytes, sub.liveBytes, 0U, liveRoom);
            }
        }

        if (entry.kind == DiffKind::ByteDifference) {
            ++report.byteDifferenceEntries;
            if (entry.explanation == DiffExplanation::Explained) {
                ++report.explainedEntries;
            } else {
                ++report.unexplainedEntries;
            }
        } else {
            ++report.missingEntries;
        }
        report.entries.push_back(std::move(entry));
    }

    if (dropped != 0U) {
        report.limitHit = true;
    }

    // 5) 账目与结论。
    report.coverage.requestedBegin =
        base.empty() ? OptionalU64::unset() : OptionalU64::of(base.front().rva);
    report.coverage.requestedEnd =
        base.empty() ? OptionalU64::unset() : OptionalU64::of(base.back().endExclusive());
    report.coverage.processedBegin = processedBegin;
    report.coverage.processedEnd =
        processedBegin.present ? OptionalU64::of(processedEnd) : OptionalU64::unset();
    report.coverage.succeeded = report.comparedBytes;
    report.coverage.failed = report.unreadableBytes + report.notCollectedBytes;
    report.coverage.skipped = report.excludedBytes + report.notAttemptedBytes;
    report.coverage.truncated = dropped;
    report.coverage.limitHit = report.limitHit;
    if (report.limitHit) {
        // F-06：报告真正生效的那条上限。停住扫描的是片段数，只写 maxEntries 会
        // 让调用方以为约束是条目数（单位都不一样）。两者都在 report 里暴露。
        report.coverage.limit = OptionalU64::of(report.scanStoppedAtPieceLimit
                                                    ? report.pieceLimit
                                                    : report.entryLimit);
    }

    // I-09 + I-01：Unverifiable 与 Stale 同等对待。"读前读后无法确认是同一个模块"
    // 不是"确认了是同一个"——把它走正常路径会把"分析无法判断"塌成"正确的空集合"，
    // 那正是 F 第 4 节要求必须区分的两件事。观测到的条目照常保留，但结论封顶在
    // Indeterminate、采集状态降为 Partial。
    const bool identityUncertain = (options.staleness == ModuleStalenessVerdict::Stale) ||
                                   (options.staleness == ModuleStalenessVerdict::Unverifiable);

    CollectionOutcome outcome;
    if (base.empty()) {
        // 比较集合为空：什么都没比，绝不能因为"没看到差异"而升级成 NoDifferenceObserved。
        outcome.status = CollectionStatus::NotCollected;
        outcome.message = "integrity.diff.nothingToCompare";
        report.limitationKeys.emplace_back("integrity.limitation.emptyCompareSet");
    } else if (options.staleness == ModuleStalenessVerdict::Stale) {
        outcome.status = CollectionStatus::Partial;
        outcome.message = "integrity.diff.moduleStale";
    } else if (options.staleness == ModuleStalenessVerdict::Unverifiable) {
        outcome.status = CollectionStatus::Partial;
        outcome.message = "integrity.diff.moduleIdentityUnverifiable";
    } else if (report.coverage.fullyCovered()) {
        outcome.status = CollectionStatus::Success;
    } else {
        outcome.status = CollectionStatus::Partial;
        outcome.message = "integrity.diff.partialCoverage";
    }
    report.outcome = outcome;

    EvidenceEnvelope envelope;
    envelope.outcome = report.outcome;
    envelope.coverage = report.coverage;
    report.conclusion = envelope.deriveConclusion(report.byteDifferenceEntries != 0U);
    if (identityUncertain) {
        // 身份不一致或无法确认时，地址可能已经指向别的东西，不允许把观测升级成
        // 任何确定结论 —— 包括"未发现差异"。
        report.conclusion = AnalysisConclusion::Indeterminate;
    }

    if (options.staleness == ModuleStalenessVerdict::Stale) {
        report.stats.modules.failed = 1U;
    } else if (options.staleness == ModuleStalenessVerdict::Unverifiable) {
        // 既不记成功也不记失败：字节确实读到了，但"读的是不是这个模块"没确认。
        // 记成 succeeded 会在多模块汇总里把不确定性洗掉，记成 failed 又谎报了一次
        // 采集失败。attempted 与 succeeded + failed 的差额就是这一类。
    } else {
        report.stats.modules.succeeded = 1U;
    }

    if (options.staleness == ModuleStalenessVerdict::Stale) {
        report.limitationKeys.emplace_back("integrity.limitation.moduleStale");
    } else if (options.staleness == ModuleStalenessVerdict::Unverifiable) {
        report.limitationKeys.emplace_back("integrity.limitation.moduleIdentityUnverifiable");
    }
    if (sawWholeImageRule) {
        report.limitationKeys.emplace_back("integrity.limitation.explanationRuleCoversWholeImage");
    }
    if (sawUnscopedRule) {
        report.limitationKeys.emplace_back("integrity.limitation.explanationRuleNotScopedToSection");
    }
    if (sawUnusableRule) {
        report.limitationKeys.emplace_back("integrity.limitation.explanationRuleUnusable");
    }
    if (report.notAttemptedBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.bytesNotAttempted");
    }
    if (report.unreadableBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.unreadableBytes");
    }
    if (report.notCollectedBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.notCollectedBytes");
    }
    if (report.excludedBytes != 0U) {
        report.limitationKeys.emplace_back("integrity.limitation.excludedNotComparable");
    }
    if (report.limitHit) {
        report.limitationKeys.emplace_back("integrity.limitation.entryLimitHit");
    }
    switch (reference.relocation.status) {
    case RelocationStatus::NotNeeded:
    case RelocationStatus::Applied:
        break;
    case RelocationStatus::AppliedWithUnsupported:
        report.limitationKeys.emplace_back("integrity.limitation.relocationUnsupportedTypes");
        break;
    case RelocationStatus::DirectoryMissing:
        report.limitationKeys.emplace_back("integrity.limitation.relocationDirectoryMissing");
        break;
    case RelocationStatus::DirectoryUnbacked:
        report.limitationKeys.emplace_back("integrity.limitation.relocationDirectoryUnbacked");
        break;
    case RelocationStatus::DirectoryMalformed:
        report.limitationKeys.emplace_back("integrity.limitation.relocationDirectoryMalformed");
        break;
    case RelocationStatus::Stripped:
        report.limitationKeys.emplace_back("integrity.limitation.relocationsStripped");
        break;
    }
    return report;
}

// ---------------------------------------------------------------------------
// I-06 跳转目标与所有者
// ---------------------------------------------------------------------------

TargetOwner ResolveTargetOwner(std::uint64_t address, const std::vector<ModuleRange>& modules) {
    TargetOwner owner;
    for (const ModuleRange& module : modules) {
        if (module.contains(address)) {
            owner.kind = TargetOwnerKind::InsideModule;
            owner.moduleName = module.name;
            owner.moduleBase = OptionalU64::of(module.base);
            owner.offset = OptionalU64::of(address - module.base);
            return owner;
        }
    }
    // 落在已知模块之外只是"我们不知道它属于谁"，不是判定。
    owner.kind = TargetOwnerKind::OutsideKnownModules;
    return owner;
}

FollowResult FollowBranchTarget(std::uint64_t startAddress,
                                const std::vector<ModuleRange>& modules,
                                const BranchResolver& resolver,
                                const FollowOptions& options) {
    FollowResult result;
    if (!resolver) {
        result.termination = FollowTermination::TargetUnreadable;
        return result;
    }

    std::vector<std::uint64_t> visited;
    std::uint64_t address = startAddress;
    std::string previousOwnerName;
    bool havePreviousOwner = false;

    for (;;) {
        const TargetOwner owner = ResolveTargetOwner(address, modules);

        if (havePreviousOwner && owner.moduleName != previousOwnerName) {
            result.crossedModuleBoundary = true;
        }
        previousOwnerName = owner.moduleName;
        havePreviousOwner = true;

        if (owner.kind == TargetOwnerKind::OutsideKnownModules) {
            // 不往未知内存里继续跟随：没有模块归属就没有可核对的边界。
            FollowNode node;
            node.address = address;
            node.owner = owner;
            node.step = FollowStepKind::TargetUnreadable;
            result.path.push_back(std::move(node));
            result.termination = FollowTermination::OutsideKnownModules;
            return result;
        }

        if (std::find(visited.begin(), visited.end(), address) != visited.end()) {
            FollowNode node;
            node.address = address;
            node.owner = owner;
            node.step = FollowStepKind::DirectBranch;
            result.path.push_back(std::move(node));
            result.termination = FollowTermination::CycleDetected;
            return result;
        }
        visited.push_back(address);

        const BranchStep step = resolver(address);
        result.bytesUsed += step.bytesConsumed;

        FollowNode node;
        node.address = address;
        node.owner = owner;
        node.step = step.kind;
        node.forwarderText = step.forwarderText;
        result.path.push_back(std::move(node));

        if (result.bytesUsed > options.maxBytes) {
            result.termination = FollowTermination::ByteBudgetExhausted;
            return result;
        }

        switch (step.kind) {
        case FollowStepKind::ResolvedCode:
            result.termination = FollowTermination::Resolved;
            return result;
        case FollowStepKind::IndirectUnresolved:
            result.termination = FollowTermination::IndirectUnresolved;
            return result;
        case FollowStepKind::ExportForwarder:
            result.termination = FollowTermination::ExportForwarder;
            return result;
        case FollowStepKind::TargetUnreadable:
            result.termination = FollowTermination::TargetUnreadable;
            return result;
        case FollowStepKind::DirectBranch:
            break;
        }

        if (result.depthUsed >= options.maxDepth) {
            result.termination = FollowTermination::DepthExhausted;
            return result;
        }
        result.depthUsed += 1U;
        address = step.target;
    }
}

} // namespace Ksword::Evidence
