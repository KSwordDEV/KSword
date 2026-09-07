#include "ScanBudget.h"

#include <limits>

namespace Ksword::Evidence {

const char* TaskStateName(TaskState state) noexcept {
    switch (state) {
    case TaskState::Pending:    return "Pending";
    case TaskState::Running:    return "Running";
    case TaskState::Cancelling: return "Cancelling";
    case TaskState::Cancelled:  return "Cancelled";
    case TaskState::Completed:  return "Completed";
    case TaskState::Failed:     return "Failed";
    }
    return "Pending";
}

bool TaskStateIsTerminal(TaskState state) noexcept {
    return state == TaskState::Cancelled || state == TaskState::Completed || state == TaskState::Failed;
}

const char* RangeValidationName(RangeValidation validation) noexcept {
    switch (validation) {
    case RangeValidation::Ok:              return "Ok";
    case RangeValidation::EmptyRange:      return "EmptyRange";
    case RangeValidation::Reversed:        return "Reversed";
    case RangeValidation::Overflow:        return "Overflow";
    case RangeValidation::ExceedsApproved: return "ExceedsApproved";
    }
    return "Ok";
}

bool AddressRange::endAddress(std::uint64_t& out) const noexcept {
    if (reversed) {
        return false;  // 逆序范围没有有意义的末地址
    }
    constexpr std::uint64_t kMax = (std::numeric_limits<std::uint64_t>::max)();
    if (length > kMax - begin) {
        return false;
    }
    out = begin + length;
    return true;
}

AddressRange AddressRange::fromBeginEnd(std::uint64_t begin, std::uint64_t end) noexcept {
    AddressRange range;
    range.begin = begin;
    if (end < begin) {
        // M-10：不把 (end - begin) 的回绕结果当长度用，那会把"给反了"伪装成
        // 一个合法的巨大范围或 Overflow。原样记下逆序，由 ValidateRange 报 Reversed。
        range.reversed = true;
        range.length = 0U;
        return range;
    }
    range.length = end - begin;
    return range;
}

RangeValidation ValidateRange(const AddressRange& request, const AddressRange& approved) noexcept {
    // 逆序先于空范围判定：逆序范围的 length 是 0，否则会被误报成 EmptyRange。
    if (request.reversed) {
        return RangeValidation::Reversed;
    }
    if (request.length == 0U) {
        return RangeValidation::EmptyRange;
    }
    std::uint64_t requestEnd = 0U;
    if (!request.endAddress(requestEnd)) {
        return RangeValidation::Overflow;
    }
    if (approved.reversed) {
        return RangeValidation::Reversed;  // 批准窗口本身给反了
    }
    if (approved.length == 0U) {
        // M-10：未限定批准范围 ≠ 允许扫全 RAM。没有窗口时仍卡单次请求的天花板，
        // 否则 {begin=0, length=MAX} 这种"扫全 64 位地址空间"会被判成 Ok。
        if (request.length > kUnapprovedScanCeilingBytes) {
            return RangeValidation::ExceedsApproved;
        }
        return RangeValidation::Ok;
    }
    std::uint64_t approvedEnd = 0U;
    if (!approved.endAddress(approvedEnd)) {
        return RangeValidation::Overflow;
    }
    if (request.begin < approved.begin || requestEnd > approvedEnd) {
        return RangeValidation::ExceedsApproved;
    }
    return RangeValidation::Ok;
}

bool ScanBudget::bounded() const noexcept {
    return maxBytes.present || maxPages.present || maxItems.present || maxDurationNanos.present;
}

const char* BudgetStopName(BudgetStop stop) noexcept {
    switch (stop) {
    case BudgetStop::Continue:        return "Continue";
    case BudgetStop::BytesExhausted:  return "BytesExhausted";
    case BudgetStop::PagesExhausted:  return "PagesExhausted";
    case BudgetStop::ItemsExhausted:  return "ItemsExhausted";
    case BudgetStop::TimeExhausted:   return "TimeExhausted";
    case BudgetStop::Cancelled:       return "Cancelled";
    }
    return "Continue";
}

BudgetStop EvaluateBudget(const ScanBudget& budget, const ScanProgress& progress) noexcept {
    // 取消优先于预算：用户点了取消就立即停，不等预算跑满。
    if (progress.cancelRequested) {
        return BudgetStop::Cancelled;
    }
    if (budget.maxBytes.present && progress.bytesDone >= budget.maxBytes.value) {
        return BudgetStop::BytesExhausted;
    }
    if (budget.maxPages.present && progress.pagesDone >= budget.maxPages.value) {
        return BudgetStop::PagesExhausted;
    }
    if (budget.maxItems.present && progress.itemsDone >= budget.maxItems.value) {
        return BudgetStop::ItemsExhausted;
    }
    if (budget.maxDurationNanos.present && progress.elapsedNanos >= budget.maxDurationNanos.value) {
        return BudgetStop::TimeExhausted;
    }
    return BudgetStop::Continue;
}

CollectionOutcome OutcomeForStop(BudgetStop stop) noexcept {
    CollectionOutcome outcome;
    switch (stop) {
    case BudgetStop::Continue:
        outcome.status = CollectionStatus::Success;
        break;
    case BudgetStop::Cancelled:
        // 取消不是错误，但结果确实不完整。
        outcome.status = CollectionStatus::Partial;
        outcome.message = "cancelled";
        break;
    case BudgetStop::TimeExhausted:
        outcome.status = CollectionStatus::Partial;
        outcome.message = "budget:time";
        break;
    case BudgetStop::BytesExhausted:
        outcome.status = CollectionStatus::Partial;
        outcome.message = "budget:bytes";
        break;
    case BudgetStop::PagesExhausted:
        outcome.status = CollectionStatus::Partial;
        outcome.message = "budget:pages";
        break;
    case BudgetStop::ItemsExhausted:
        outcome.status = CollectionStatus::Partial;
        outcome.message = "budget:items";
        break;
    }
    return outcome;
}

void ApplyStopToCoverage(BudgetStop stop, const ScanBudget& budget, CoverageAccount& coverage) {
    if (stop == BudgetStop::Continue) {
        return;
    }
    if (stop == BudgetStop::Cancelled) {
        // F-06：用户点了取消，账目里就该写"取消"。写成 limitHit + limit=unset 会让
        // describeRemaining() 输出 "limit-hit:unknown" —— 把一次主动取消说成
        // "命中了一个不知道是多少的上限"，停止原因这一维就丢了。
        coverage.cancelled = true;
        return;
    }
    coverage.limitHit = true;
    switch (stop) {
    case BudgetStop::BytesExhausted: coverage.limit = budget.maxBytes; break;
    case BudgetStop::PagesExhausted: coverage.limit = budget.maxPages; break;
    case BudgetStop::ItemsExhausted: coverage.limit = budget.maxItems; break;
    case BudgetStop::TimeExhausted:  coverage.limit = budget.maxDurationNanos; break;
    case BudgetStop::Cancelled:      break;  // 上面已提前返回
    case BudgetStop::Continue:       break;
    }
}

const char* RefreshDecisionName(RefreshDecision decision) noexcept {
    switch (decision) {
    case RefreshDecision::Apply:                     return "Apply";
    case RefreshDecision::RejectSessionIsImmutable:  return "RejectSessionIsImmutable";
    case RefreshDecision::RejectStaleSnapshot:       return "RejectStaleSnapshot";
    case RefreshDecision::RejectNotLatestRequest:    return "RejectNotLatestRequest";
    }
    return "Apply";
}

RefreshDecision DecideRefresh(DataOrigin origin,
                              std::uint64_t currentSnapshotId,
                              std::uint64_t incomingSnapshotId,
                              bool isLatestRequest) noexcept {
    if (origin == DataOrigin::Session) {
        // F-09：已保存结果不可被后台刷新悄悄覆盖。
        return RefreshDecision::RejectSessionIsImmutable;
    }
    if (!isLatestRequest) {
        return RefreshDecision::RejectNotLatestRequest;
    }
    if (incomingSnapshotId <= currentSnapshotId) {
        return RefreshDecision::RejectStaleSnapshot;
    }
    return RefreshDecision::Apply;
}

const char* LiveNavigationDecisionName(LiveNavigationDecision decision) noexcept {
    switch (decision) {
    case LiveNavigationDecision::Allow:                      return "Allow";
    case LiveNavigationDecision::RejectObjectExited:         return "RejectObjectExited";
    case LiveNavigationDecision::RejectIdentityMismatch:     return "RejectIdentityMismatch";
    case LiveNavigationDecision::RejectIdentityUnverifiable: return "RejectIdentityUnverifiable";
    }
    return "RejectIdentityUnverifiable";
}

} // namespace Ksword::Evidence
