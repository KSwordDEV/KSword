// HexViewport.Cache.cpp
// 作用：HexViewport 的页缓存——预取规划、在途登记、结果写入、代次守卫、LRU 淘汰、字节查询。
//
// 为什么这一层要被穷举测试：它属于"算错了不会报错"的一类。
// 陈旧的异步结果被当成新数据收下，界面照样画、字节照样显示，只是显示的是上一个目标的内容；
// 不可读被当成 0，则会让用户把"读不到"看成"这里就是全零"。
// 所以状态必须分四种，代次不符必须拒绝，两者都有单独的断言。

#include "HexViewport.h"

#include <algorithm>
#include <utility>

namespace ksword::memwb {

namespace {

// PageWindow：PlanFetch 决定要保证驻留的页号窗口（页号 = 地址 / kPageBytes）。
struct PageWindow {
    std::uint64_t low = 0;          // 窗口最低页号（含）
    std::uint64_t high = 0;         // 窗口最高页号（含）
    std::uint64_t visibleLow = 0;   // 可见页最低页号（含）
    std::uint64_t visibleHigh = 0;  // 可见页最高页号（含）
};

// PlanItem：排序前的一条候选范围。
struct PlanItem {
    HexViewport::FetchRange range;  // 候选范围
    int zoneRank = 0;               // 所属区域：0=可见页，1=可见页之后，2=可见页之前（平局时按此排序，向后在前）
};

// ComputeWindow：在缓存容量内决定要保证驻留的页窗口。
// 传入：可见页范围、空间页范围、预取页数、缓存容量；传出：窗口。
// 规则：可见页优先；可见页本身就占满容量时只取前 capacity 页且不预取；
//       否则把剩余名额分给前后预取，向后优先（滚动多半向下）。
PageWindow ComputeWindow(
    std::uint64_t visibleLow,
    std::uint64_t visibleHigh,
    std::uint64_t spaceLow,
    std::uint64_t spaceHigh,
    std::uint64_t prefetchPages,
    std::uint64_t capacity) {
    // window：返回值，先记下可见页范围。
    PageWindow window;
    window.visibleLow = visibleLow;
    window.visibleHigh = visibleHigh;

    // 可见页自己就把容量占满：截断到前 capacity 页，不做预取，否则预取会把可见页挤出缓存。
    // visibleCount：可见页数（至少为 1）。
    const std::uint64_t visibleCount = visibleHigh - visibleLow + 1ULL;
    if (visibleCount >= capacity) {
        window.visibleHigh = visibleLow + capacity - 1ULL;
        window.low = window.visibleLow;
        window.high = window.visibleHigh;
        return window;
    }

    // budget：留给预取的页数。
    // beforeRoom/afterRoom：可见页前/后方在地址空间内还剩多少页。
    // beforeAvail/afterAvail：前/后各自实际能预取多少页（受空间边界与预取页数限制）。
    const std::uint64_t budget = capacity - visibleCount;
    const std::uint64_t beforeRoom = visibleLow - spaceLow;
    const std::uint64_t afterRoom = spaceHigh - visibleHigh;
    const std::uint64_t beforeAvail = (prefetchPages < beforeRoom) ? prefetchPages : beforeRoom;
    const std::uint64_t afterAvail = (prefetchPages < afterRoom) ? prefetchPages : afterRoom;

    // before/after：最终前后各取多少页。
    std::uint64_t before = 0;
    std::uint64_t after = 0;
    if (beforeAvail + afterAvail <= budget) {
        // 名额够用：想取多少取多少。
        before = beforeAvail;
        after = afterAvail;
    } else {
        // 名额不够：向后多分一页（奇数名额时），某一侧不够分的由另一侧补足。
        // afterTarget/beforeTarget：平均分配时后/前各自应得的页数。
        const std::uint64_t afterTarget = (budget + 1ULL) / 2ULL;
        const std::uint64_t beforeTarget = budget / 2ULL;
        if (afterAvail < afterTarget) {
            after = afterAvail;
            before = budget - after;
        } else if (beforeAvail < beforeTarget) {
            before = beforeAvail;
            after = budget - before;
        } else {
            after = afterTarget;
            before = beforeTarget;
        }
    }

    window.low = visibleLow - before;
    window.high = visibleHigh + after;
    return window;
}

// AppendGaps：在一个区域内找出"未被占用"的页段，追加到候选列表。
// 传入：升序的占用页号、区域上下界、区域编号、窗口（用来算距离）；传出：追加到 items。
void AppendGaps(
    const std::vector<std::uint64_t>& occupied,
    std::uint64_t zoneLow,
    std::uint64_t zoneHigh,
    int zoneRank,
    const PageWindow& window,
    std::vector<PlanItem>& items) {
    // emit：把 [gapLow, gapHigh] 页段记成一条候选，并按区域算出它与可见页的距离。
    const auto emit = [&](std::uint64_t gapLow, std::uint64_t gapHigh) {
        // item：这一条候选。
        PlanItem item;
        item.zoneRank = zoneRank;
        item.range.firstPageStart = gapLow * HexViewport::kPageBytes;
        item.range.pageCount = gapHigh - gapLow + 1ULL;
        if (zoneRank == 1) {
            item.range.distancePages = gapLow - window.visibleHigh;
        } else if (zoneRank == 2) {
            item.range.distancePages = window.visibleLow - gapHigh;
        } else {
            item.range.distancePages = 0;
        }
        items.push_back(item);
    };

    // cursor：下一个还没判定的页号。顺着升序的占用页走，占用页之间的空隙就是要读的页段。
    std::uint64_t cursor = zoneLow;
    for (const std::uint64_t index : occupied) {
        if (index < zoneLow) {
            continue;
        }
        if (index > zoneHigh) {
            break;
        }
        if (index > cursor) {
            emit(cursor, index - 1ULL);
        }
        cursor = index + 1ULL;
    }
    if (cursor <= zoneHigh) {
        emit(cursor, zoneHigh);
    }
}

}  // namespace

// 地址所在页的起始地址。
// 传入：地址；传出：向下对齐到 kPageBytes 的地址（不会溢出）。
std::uint64_t HexViewport::PageStartOf(std::uint64_t address) {
    return address - (address % kPageBytes);
}

// 规划需要读取的页范围。
// 用法：for (const auto& r : view.PlanFetch(top, rows, 2)) { view.MarkInFlight(r); 派发异步读取(r); }
// 传入：首个可见行、可见行数、前后各预取的页数；传出：按距离由近到远的页范围列表。
std::vector<HexViewport::FetchRange> HexViewport::PlanFetch(
    std::uint64_t first, std::uint64_t count, std::uint64_t prefetch, bool ignoreCache) const {
    if (hiddenRows_.empty()) return PlanFetchRaw(first, count, prefetch, ignoreCache, foldUnknown_);
    if (first >= RowCount() || count == 0) return {};
    count = std::min(count, RowCount() - first);
    std::map<std::uint64_t, std::uint64_t> pages;
    std::uint64_t offset = 0;
    while (offset < count && pages.size() < maxCachedPages_) {
        const auto raw = VisualToRaw(first + offset);
        std::uint64_t run = 1;
        while (offset + run < count && VisualToRaw(first + offset + run) == raw + run) ++run;
        for (const auto& range : PlanFetchRaw(raw, run, prefetch, ignoreCache, true)) {
            for (std::uint64_t n = 0; n < range.pageCount && pages.size() < maxCachedPages_; ++n) {
                const auto page = range.firstPageStart + n * kPageBytes;
                const auto found = pages.find(page);
                if (found == pages.end()) pages.emplace(page, range.distancePages);
                else found->second = std::min(found->second, range.distancePages);
            }
        }
        offset += run;
    }
    std::vector<FetchRange> result;
    for (const auto& [page, distance] : pages) result.push_back({page, 1, distance});
    std::stable_sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.distancePages < right.distancePages;
    });
    return result;
}

std::vector<HexViewport::FetchRange> HexViewport::PlanAddressFetch(
    std::uint64_t first, std::uint64_t last, std::uint64_t prefetch, bool ignoreCache) const {
    if (!IsValid() || first > last || last < firstAddress_ || first > lastAddress_) return {};
    first = std::max(first, firstAddress_); last = std::min(last, lastAddress_);
    const auto low = (first - rowBase_) / bytesPerRow_;
    const auto high = (last - rowBase_) / bytesPerRow_;
    return PlanFetchRaw(low, high - low + 1, prefetch, ignoreCache, false);
}

std::vector<HexViewport::FetchRange> HexViewport::PlanFetchRaw(
    std::uint64_t firstVisibleRow,
    std::uint64_t visibleRowCount,
    std::uint64_t prefetchPages, bool ignoreCache, bool skipKnownUnknown) const {
    // plan：返回值，按距离排好序的页范围。
    std::vector<FetchRange> plan;

    // 无效视图、零行高、起始行越界：没有可见内容就没有需要读的页。
    // rowCount：总行数。
    const std::uint64_t rowCount = RawRowCount();
    if (!IsValid() || visibleRowCount == 0 || firstVisibleRow >= rowCount) {
        return plan;
    }

    // 可见行的末行夹取到最后一行。rowsAvailable >= 1，所以下面的加法在条件成立时不会溢出。
    // rowsAvailable：从首个可见行起到最后一行还剩多少行；lastVisibleRow：夹取后的末个可见行。
    const std::uint64_t rowsAvailable = rowCount - firstVisibleRow;
    const std::uint64_t lastVisibleRow = (visibleRowCount >= rowsAvailable)
        ? (rowCount - 1ULL)
        : (firstVisibleRow + visibleRowCount - 1ULL);

    // 可见字节范围：首行取有效首地址、末行取有效末地址（已排除补空位），再换算成页号。
    // topSpan/bottomSpan：首个/末个可见行的有效区间；visibleLow/visibleHigh：可见页号范围；
    // spaceLow/spaceHigh：整个地址空间的页号范围。
    const HexViewport geometry(firstAddress_, lastAddress_, bytesPerRow_, maxCachedPages_);
    const std::optional<AddressRange> topSpan = geometry.RowValidSpan(firstVisibleRow);
    const std::optional<AddressRange> bottomSpan = geometry.RowValidSpan(lastVisibleRow);
    if (!topSpan.has_value() || !bottomSpan.has_value()) {
        return plan;
    }
    const std::uint64_t visibleLow = topSpan->first / kPageBytes;
    const std::uint64_t visibleHigh = bottomSpan->last / kPageBytes;
    const std::uint64_t spaceLow = firstAddress_ / kPageBytes;
    const std::uint64_t spaceHigh = lastAddress_ / kPageBytes;

    // 在缓存容量内决定窗口（可见页 + 预取页）。
    // window：要保证驻留的页号窗口。
    const PageWindow window = ComputeWindow(
        visibleLow,
        visibleHigh,
        spaceLow,
        spaceHigh,
        prefetchPages,
        static_cast<std::uint64_t>(maxCachedPages_));

    // 收集窗口内"已被占用"的页号：已缓存（含已知不可读）与已在途的都不再请求。
    // 只遍历占用页而不是窗口内每一页，窗口再大也是 O(占用页数)。
    // occupied：占用页号（升序、去重）；lowStart/highStart：窗口两端的页起始地址。
    std::vector<std::uint64_t> occupied;
    const std::uint64_t lowStart = window.low * kPageBytes;
    const std::uint64_t highStart = window.high * kPageBytes;
    for (auto it = ignoreCache ? pages_.end() : pages_.lower_bound(lowStart); it != pages_.end() && it->first <= highStart; ++it) {
        occupied.push_back(it->first / kPageBytes);
    }
    for (auto it = ignoreCache ? inFlight_.end() : inFlight_.lower_bound(lowStart); it != inFlight_.end() && *it <= highStart; ++it) {
        occupied.push_back(*it / kPageBytes);
    }
    if (skipKnownUnknown && !unknownRanges_.empty()) {
        for (auto page = window.low; page <= window.high; ++page) {
            const auto first = std::max(page * kPageBytes, firstAddress_);
            const auto last = std::min(page * kPageBytes + kPageBytes - 1, lastAddress_);
            const auto upper = unknownRanges_.upper_bound(first);
            if (upper != unknownRanges_.begin() && std::prev(upper)->second >= last)
                occupied.push_back(page);
        }
    }
    std::sort(occupied.begin(), occupied.end());
    occupied.erase(std::unique(occupied.begin(), occupied.end()), occupied.end());

    // 三个区域各自找空隙：可见页、可见页之后、可见页之前。
    // 范围从不跨越可见页边界，这样可见页的读取可以最先单独完成。
    // items：排序前的候选范围。
    std::vector<PlanItem> items;
    AppendGaps(occupied, window.visibleLow, window.visibleHigh, 0, window, items);
    if (window.high > window.visibleHigh) {
        AppendGaps(occupied, window.visibleHigh + 1ULL, window.high, 1, window, items);
    }
    if (window.visibleLow > window.low) {
        AppendGaps(occupied, window.low, window.visibleLow - 1ULL, 2, window, items);
    }

    // 排序：距离近的在前；距离相等时向后的在前；同区域内按地址升序。
    std::sort(items.begin(), items.end(), [](const PlanItem& left, const PlanItem& right) {
        if (left.range.distancePages != right.range.distancePages) {
            return left.range.distancePages < right.range.distancePages;
        }
        if (left.zoneRank != right.zoneRank) {
            return left.zoneRank < right.zoneRank;
        }
        return left.range.firstPageStart < right.range.firstPageStart;
    });

    plan.reserve(items.size());
    for (const PlanItem& item : items) {
        plan.push_back(item.range);
    }
    return plan;
}

// 校验页范围。
// 传入：页范围；传出：Accepted 表示对齐、页数在 [1, 缓存容量]、且整段落在地址空间的页之内。
// 页数上限取缓存容量：登记得再多也缓存不下，也避免调用方传入巨大范围拖垮循环。
HexViewport::PageResult HexViewport::ValidateRange(const FetchRange& range) const {
    if (!IsValid()) {
        return PageResult::RejectedOutsideSpace;
    }
    if (range.firstPageStart % kPageBytes != 0) {
        return PageResult::RejectedMisaligned;
    }
    if (range.pageCount == 0 || range.pageCount > static_cast<std::uint64_t>(maxCachedPages_)) {
        return PageResult::RejectedBadSize;
    }

    // 起始页必须在空间的页范围内，且整段不能越过空间最后一页（先比较后加减，防溢出）。
    // spaceLow/spaceHigh：地址空间的页号范围；firstIndex：范围起始页的页号。
    const std::uint64_t spaceLow = firstAddress_ / kPageBytes;
    const std::uint64_t spaceHigh = lastAddress_ / kPageBytes;
    const std::uint64_t firstIndex = range.firstPageStart / kPageBytes;
    if (firstIndex < spaceLow || firstIndex > spaceHigh) {
        return PageResult::RejectedOutsideSpace;
    }
    if (range.pageCount > spaceHigh - firstIndex + 1ULL) {
        return PageResult::RejectedOutsideSpace;
    }
    return PageResult::Accepted;
}

// 登记在途。
// 传入：页范围；传出：结果，拒绝时不登记任何页。已缓存的页不降级成 Pending。
HexViewport::PageResult HexViewport::MarkInFlight(const FetchRange& range) {
    // verdict：范围校验结果。
    const PageResult verdict = ValidateRange(range);
    if (verdict != PageResult::Accepted) {
        return verdict;
    }

    // 逐页登记。范围页数已被限制在缓存容量以内，循环有界。
    // index：范围内第几页；pageStart：该页起始地址。
    for (std::uint64_t index = 0; index < range.pageCount; ++index) {
        const std::uint64_t pageStart = range.firstPageStart + index * kPageBytes;
        if (pages_.find(pageStart) == pages_.end()) {
            inFlight_.insert(pageStart);
        }
    }
    return PageResult::Accepted;
}

// 撤销在途登记。
// 传入：页范围；传出：结果。只清在途标记，不动已缓存的页。
HexViewport::PageResult HexViewport::CancelInFlight(const FetchRange& range) {
    // verdict：范围校验结果。
    const PageResult verdict = ValidateRange(range);
    if (verdict != PageResult::Accepted) {
        return verdict;
    }
    for (std::uint64_t index = 0; index < range.pageCount; ++index) {
        inFlight_.erase(range.firstPageStart + index * kPageBytes);
    }
    return PageResult::Accepted;
}

// 淘汰最久未用的一页（lastUsedTick 最小者）。
// 调用前提：缓存非空。缓存页数有上限（默认 256），线性找最小值足够便宜。
void HexViewport::EvictOldestPage() {
    if (pages_.empty()) {
        return;
    }
    // oldest：目前已知最久未用的页；逐个比较使用序号，小者更久未用。
    auto oldest = pages_.begin();
    for (auto it = pages_.begin(); it != pages_.end(); ++it) {
        if (it->second.lastUsedTick < oldest->second.lastUsedTick) {
            oldest = it;
        }
    }
    pages_.erase(oldest);
    ++stats_.evictions;
}

// 取得（或新建）某页的缓存槽，容量满且是新页时先淘汰最久未用的页。
// 传入：页起始地址；传出：槽引用，使用序号已刷新为最新，内容由调用方填写。
HexViewport::CachedPage& HexViewport::AcquirePageSlot(std::uint64_t pageStart) {
    // 已存在的页是原地替换，不占新名额，所以不触发淘汰。
    if (pages_.find(pageStart) == pages_.end() && pages_.size() >= maxCachedPages_) {
        EvictOldestPage();
    }
    // slot：该页的缓存槽（不存在则新建一个空槽）。
    CachedPage& slot = pages_[pageStart];
    slot.lastUsedTick = ++useTick_;
    return slot;
}

// 插入一页读取结果。
// 用法：view.InsertPage(pageStart, bytes, mask, revisionCapturedWhenRequested);
// 传入：页起始地址、4096 字节数据、4096 字节有效掩码、发起读取时的来源代次；传出：结果。
// 校验顺序：代次 -> 页位置 -> 缓冲长度。任何拒绝都不改动缓存与在途登记。
HexViewport::PageResult HexViewport::InsertPage(
    std::uint64_t pageStart,
    const std::vector<std::uint8_t>& bytes,
    const std::vector<std::uint8_t>& validMask,
    std::uint64_t sourceRevision) {
    if (!IsValid()) {
        return PageResult::RejectedOutsideSpace;
    }

    // 代次不符一律丢弃：旧的（目标已换）或超前的（调用方登记错了）都不能进缓存。
    if (sourceRevision != sourceRevision_) {
        ++stats_.staleRejections;
        return PageResult::RejectedStaleRevision;
    }

    // 页位置：借用范围校验（单页）判断对齐与是否在空间内。
    // single：只含这一页的范围；placement：位置校验结果。
    FetchRange single;
    single.firstPageStart = pageStart;
    single.pageCount = 1;
    const PageResult placement = ValidateRange(single);
    if (placement != PageResult::Accepted) {
        return placement;
    }

    // 缓冲长度必须正好是一页，数据与掩码一一对应。
    if (bytes.size() != kPageBytes || validMask.size() != kPageBytes) {
        return PageResult::RejectedBadSize;
    }

    // 校验全部通过后才动缓存：取槽、填内容、清除在途登记。
    // slot：该页的缓存槽。
    CachedPage& slot = AcquirePageSlot(pageStart);
    slot.bytes = bytes;
    slot.validMask = validMask;
    slot.sourceRevision = sourceRevision;
    slot.unreadable = false;
    inFlight_.erase(pageStart);
    if (foldUnknown_) { RebuildReadableRanges(pageStart, slot); TrackUnknownPage(pageStart, validMask); RebuildFolds(); }
    return PageResult::Accepted;
}

// 把范围内整页标成不可读。
// 传入：页范围、发起读取时的来源代次；传出：结果，拒绝时整体不生效。
HexViewport::PageResult HexViewport::MarkUnreadable(const FetchRange& range, std::uint64_t sourceRevision) {
    if (!IsValid()) {
        return PageResult::RejectedOutsideSpace;
    }

    // 陈旧的失败结果同样要丢：它不能把新读到的页标成不可读。
    if (sourceRevision != sourceRevision_) {
        ++stats_.staleRejections;
        return PageResult::RejectedStaleRevision;
    }
    // verdict：范围校验结果。
    const PageResult verdict = ValidateRange(range);
    if (verdict != PageResult::Accepted) {
        return verdict;
    }

    // 逐页覆盖成不可读页：清掉旧字节，避免旧内容在"读不到"的页上继续显示。
    // index：范围内第几页；pageStart：该页起始地址；slot：该页的缓存槽。
    for (std::uint64_t index = 0; index < range.pageCount; ++index) {
        const std::uint64_t pageStart = range.firstPageStart + index * kPageBytes;
        CachedPage& slot = AcquirePageSlot(pageStart);
        slot.bytes.clear();
        slot.validMask.clear();
        slot.readableRanges.clear();
        slot.sourceRevision = sourceRevision;
        slot.unreadable = true;
        inFlight_.erase(pageStart);
    }
    if (foldUnknown_) {
        const auto first = range.firstPageStart;
        AddUnknownRange(first, first + (range.pageCount - 1) * kPageBytes + kPageBytes - 1);
        RebuildFolds();
    }
    return PageResult::Accepted;
}

// 清空缓存与在途登记并更新来源代次。选区、行宽不受影响。
// 传入：新的来源代次；换目标/重读时必须传一个与旧值不同的新值，旧代次的在途结果才会被拒绝。
void HexViewport::InvalidateAll(std::uint64_t newSourceRevision) {
    pages_.clear();
    inFlight_.clear();
    unknownRanges_.clear();
    foldRevealedAddress_.reset();
    RebuildFolds();
    sourceRevision_ = newSourceRevision;
}

// 当前来源代次。
std::uint64_t HexViewport::SourceRevision() const {
    return sourceRevision_;
}

// 判定一个地址的缓存状态。
// 传入：地址；pageOut 非空时命中已缓存页会写入该页指针，否则写入空。
// 传出：状态与字节值（仅 Valid 时有意义）。
HexViewport::ByteLookup HexViewport::Classify(std::uint64_t address, const CachedPage** pageOut) const {
    // result：返回值，初值为 NotLoaded + 0。
    ByteLookup result;
    if (pageOut != nullptr) {
        *pageOut = nullptr;
    }

    // 地址不属于空间（含补空位）：没有数据可言，按未加载返回。
    if (!ContainsAddress(address)) {
        return result;
    }

    // 页未缓存：在途则 Pending，否则 NotLoaded。
    // pageStart：地址所在页的起始地址；found：缓存里该页的位置。
    const std::uint64_t pageStart = PageStartOf(address);
    const auto found = pages_.find(pageStart);
    if (found == pages_.end()) {
        if (inFlight_.find(pageStart) != inFlight_.end()) {
            result.state = ByteState::Pending;
        } else if (IsKnownUnreadable(address)) {
            result.state = ByteState::Unreadable;
        }
        return result;
    }

    // 页已缓存：整页不可读，或掩码为 0 的字节，一律 Unreadable，值保持 0 且不得当数据用。
    // page：缓存页；offset：字节在页内的偏移；inBuffer：偏移是否落在缓冲与掩码范围内（防御性检查）。
    const CachedPage& page = found->second;
    if (pageOut != nullptr) {
        *pageOut = &page;
    }
    const std::size_t offset = static_cast<std::size_t>(address - pageStart);
    const bool inBuffer = offset < page.bytes.size() && offset < page.validMask.size();
    if (page.unreadable || !inBuffer || page.validMask[offset] == 0) {
        result.state = ByteState::Unreadable;
        return result;
    }
    result.state = ByteState::Valid;
    result.value = page.bytes[offset];
    return result;
}

// 读一个字节并刷新 LRU、累计命中计数。
// 传入：地址；传出：状态与字节值。空间之外的地址不计数。
HexViewport::ByteLookup HexViewport::LookupByte(std::uint64_t address) {
    // page：命中的缓存页（未命中为空）；result：判定结果。
    const CachedPage* page = nullptr;
    const ByteLookup result = Classify(address, &page);
    if (!ContainsAddress(address)) {
        return result;
    }

    // 命中已缓存页（含已知不可读页）才算命中并刷新 LRU；未命中的查询不能改变淘汰次序。
    if (page != nullptr) {
        page->lastUsedTick = ++useTick_;
        ++stats_.hits;
    } else {
        ++stats_.misses;
    }
    return result;
}

// 只读版本：不刷新 LRU、不计数。
// 传入：地址；传出：状态与字节值。
HexViewport::ByteLookup HexViewport::PeekByte(std::uint64_t address) const {
    return Classify(address, nullptr);
}

// 已缓存页数（含已知不可读页，不含在途）。
std::size_t HexViewport::CachedPageCount() const {
    return pages_.size();
}

// 已缓存页的起始地址，从最久未用到最近使用。
// 传出：即将被淘汰的页排在最前。
std::vector<std::uint64_t> HexViewport::CachedPageStartsLeastRecentFirst() const {
    // 先把（使用序号，页起始地址）配对收集起来，再按使用序号升序排。
    // ordered：配对列表；starts：返回值。
    std::vector<std::pair<std::uint64_t, std::uint64_t>> ordered;
    ordered.reserve(pages_.size());
    for (const auto& entry : pages_) {
        ordered.emplace_back(entry.second.lastUsedTick, entry.first);
    }
    std::sort(ordered.begin(), ordered.end());

    std::vector<std::uint64_t> starts;
    starts.reserve(ordered.size());
    for (const auto& item : ordered) {
        starts.push_back(item.second);
    }
    return starts;
}

// 某页是否已缓存（含已知不可读）。
bool HexViewport::IsPageCached(std::uint64_t pageStart) const {
    return pages_.find(pageStart) != pages_.end();
}

// 某页是否在途。
bool HexViewport::IsPageInFlight(std::uint64_t pageStart) const {
    return inFlight_.find(pageStart) != inFlight_.end();
}

// 在途页数。
std::size_t HexViewport::InFlightPageCount() const {
    return inFlight_.size();
}

// 缓存计数。
const HexViewport::CacheStats& HexViewport::Stats() const {
    return stats_;
}

// 清零缓存计数，不影响缓存内容。
void HexViewport::ResetStats() {
    stats_ = CacheStats{};
}

}  // namespace ksword::memwb
