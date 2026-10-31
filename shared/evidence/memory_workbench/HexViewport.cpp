// HexViewport.cpp
// 作用：HexViewport 的构造、基本信息、行列几何与滚动目标计算。
// 页缓存在 HexViewport.Cache.cpp，选区在 HexViewport.Selection.cpp。
//
// 本文件所有地址算术都遵守同一条纪律：先比较、再加减。任何一次
// "起点 + 偏移" 都先确认不会超过 UINT64_MAX，绝不允许回绕成小地址。

#include "HexViewport.h"

#include <limits>
#include <algorithm>

namespace ksword::memwb {

namespace {

// kMaxAddress：uint64 能表示的最大地址，用于溢出判定。
constexpr std::uint64_t kMaxAddress = std::numeric_limits<std::uint64_t>::max();

}  // namespace

// 构造。
// 用法：HexViewport view(0x1000, 0x1FFF, 16);
// 传入：闭区间两端、每行字节数、缓存页数上限。
// 传出：对象本身；参数非法时 Status() 不是 Ok，且视图为空（所有查询返回空/0）。
HexViewport::HexViewport(
    std::uint64_t firstAddress,
    std::uint64_t lastAddress,
    std::uint32_t bytesPerRow,
    std::size_t maxCachedPages)
    : status_(InitStatus::Ok),
      firstAddress_(firstAddress),
      lastAddress_(lastAddress),
      bytesPerRow_(bytesPerRow),
      maxCachedPages_(maxCachedPages),
      rowBase_(0),
      sourceRevision_(0),
      useTick_(0) {
    // 按固定顺序校验参数：先区间，再行宽，最后缓存容量。
    if (firstAddress > lastAddress) {
        status_ = InitStatus::InvalidRange;
    } else if (!IsSupportedBytesPerRow(bytesPerRow)) {
        status_ = InitStatus::InvalidBytesPerRow;
    } else if (maxCachedPages == 0) {
        status_ = InitStatus::InvalidCacheCapacity;
    }

    // 非法参数：把可能被除的成员归一到安全值，视图保持为空。
    // 这样即使某条路径忘了检查 IsValid()，也不会出现除零。
    if (status_ != InitStatus::Ok) {
        bytesPerRow_ = kDefaultBytesPerRow;
        maxCachedPages_ = kMaxCachedPages;
        selection_ = Selection{};
        return;
    }

    // 第 0 行起始地址 = firstAddress 向下对齐到行宽的倍数。
    // 取模得到的余数一定不大于 firstAddress，所以减法不会下溢。
    rowBase_ = firstAddress_ - (firstAddress_ % bytesPerRow_);

    // 初始插入点放在第一个有效字节上，有效视图任何时刻都有插入点。
    selection_.anchor = firstAddress_;
    selection_.caret = firstAddress_;
    selection_.pane = ActivePane::Hex;
}

// 构造结果。
HexViewport::InitStatus HexViewport::Status() const {
    return status_;
}

// 视图是否有效。
bool HexViewport::IsValid() const {
    return status_ == InitStatus::Ok;
}

// 地址空间起点。
std::uint64_t HexViewport::FirstAddress() const {
    return firstAddress_;
}

// 地址空间终点。
std::uint64_t HexViewport::LastAddress() const {
    return lastAddress_;
}

// 当前每行字节数。
std::uint32_t HexViewport::BytesPerRow() const {
    return bytesPerRow_;
}

// 缓存页数上限。
std::size_t HexViewport::MaxCachedPages() const {
    return maxCachedPages_;
}

// 是否是受支持的行宽。
// 传入：行宽；传出：8/16/32/48/64 之一为 true。
bool HexViewport::IsSupportedBytesPerRow(std::uint32_t bytesPerRow) {
    return bytesPerRow == 8U
        || bytesPerRow == 16U
        || bytesPerRow == 32U
        || bytesPerRow == 48U
        || bytesPerRow == 64U;
}

// 改行宽。
// 传入：新行宽；传出：是否接受。拒绝时视图保持原样。
bool HexViewport::SetBytesPerRow(std::uint32_t bytesPerRow) {
    // 无效视图或不受支持的行宽一律拒绝，不做任何改动。
    if (!IsValid() || !IsSupportedBytesPerRow(bytesPerRow)) {
        return false;
    }

    // 行宽变了，第 0 行起始地址要按新行宽重新对齐。
    bytesPerRow_ = bytesPerRow;
    rowBase_ = firstAddress_ - (firstAddress_ % bytesPerRow_);
    if (foldUnknown_) for (auto& [address, page] : pages_) RebuildReadableRanges(address, page);
    RebuildFolds();
    return true;
}

// 地址是否属于空间。
bool HexViewport::ContainsAddress(std::uint64_t address) const {
    return IsValid() && address >= firstAddress_ && address <= lastAddress_;
}

// 总行数。
// 最后一个有效地址所在行号 + 1。(last - rowBase) 不会下溢也不会超过 uint64，
// 除以至少为 8 的行宽后 +1 也不会溢出。
std::uint64_t HexViewport::RawRowCount() const {
    if (!IsValid()) {
        return 0;
    }
    return (lastAddress_ - rowBase_) / bytesPerRow_ + 1ULL;
}

std::uint64_t HexViewport::RowCount() const {
    return RawRowCount() - hiddenRowCount_;
}

// 某行的起始地址。
// 传入：行号；传出：已对齐的行起始地址，越界为空。
std::optional<std::uint64_t> HexViewport::RowStartAddress(std::uint64_t row) const {
    // 行号必须在 [0, RowCount) 内；在范围内时 row*bytesPerRow 不会超过 last-rowBase。
    if (row >= RowCount()) {
        return std::nullopt;
    }
    return rowBase_ + VisualToRaw(row) * static_cast<std::uint64_t>(bytesPerRow_);
}

// 某行内属于地址空间的闭区间。
// 传入：行号；传出：去掉补空位后的 [first, last]，越界为空。
std::optional<HexViewport::AddressRange> HexViewport::RowValidSpan(std::uint64_t row) const {
    // start：该行的起始地址（已对齐，首行可能早于 firstAddress）。
    const std::optional<std::uint64_t> start = RowStartAddress(row);
    if (!start.has_value()) {
        return std::nullopt;
    }

    // 行尾地址 = 行首 + (行宽 - 1)；最高一行可能超过 2^64，此时饱和到最大地址，
    // 随后再被 lastAddress_ 夹住。
    // span：行首到行尾的距离；rowEnd：该行最后一格对应的地址（饱和后）。
    const std::uint64_t span = static_cast<std::uint64_t>(bytesPerRow_) - 1ULL;
    std::uint64_t rowEnd = kMaxAddress;
    if (span <= kMaxAddress - *start) {
        rowEnd = *start + span;
    }

    // 行首早于 firstAddress 的部分是首行开头的补空位，行尾晚于 lastAddress 的部分是末行结尾的补空位。
    // valid：去掉补空位后的有效区间。
    AddressRange valid;
    valid.first = (*start < firstAddress_) ? firstAddress_ : *start;
    valid.last = (rowEnd > lastAddress_) ? lastAddress_ : rowEnd;
    return valid;
}

// 地址所在行。
// 传入：地址；传出：行号，地址不属于空间（含补空位）为空。
std::optional<std::uint64_t> HexViewport::RowOfAddress(std::uint64_t address) const {
    if (!ContainsAddress(address)) {
        return std::nullopt;
    }
    return RawToVisual((address - rowBase_) / static_cast<std::uint64_t>(bytesPerRow_));
}

// 地址所在列。
// 传入：地址；传出：列号 0..bytesPerRow-1，地址不属于空间为空。
std::optional<std::uint32_t> HexViewport::ColumnOfAddress(std::uint64_t address) const {
    if (!ContainsAddress(address)) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>((address - rowBase_) % static_cast<std::uint64_t>(bytesPerRow_));
}

// 行列对应的地址。
// 传入：行号、列号；传出：地址，补空位/越界/超出 2^64 为空。
std::optional<std::uint64_t> HexViewport::AddressAt(std::uint64_t row, std::uint32_t column) const {
    // 列号必须小于行宽。
    if (column >= bytesPerRow_) {
        return std::nullopt;
    }

    // 行号越界（含无效视图，此时 RowCount 为 0）。
    // start：该行起始地址。
    const std::optional<std::uint64_t> start = RowStartAddress(row);
    if (!start.has_value()) {
        return std::nullopt;
    }

    // 先判会不会超过 2^64：行宽 48 时最高一行的后几列就在这里被挡住，
    // 绝不能让它回绕成接近 0 的地址再碰巧落进空间。
    // offset：列号（行内偏移）。
    const std::uint64_t offset = static_cast<std::uint64_t>(column);
    if (offset > kMaxAddress - *start) {
        return std::nullopt;
    }

    // 再判是否是补空位（首行开头在 firstAddress 之前，末行结尾在 lastAddress 之后）。
    // address：该格对应的地址。
    const std::uint64_t address = *start + offset;
    if (address < firstAddress_ || address > lastAddress_) {
        return std::nullopt;
    }
    return address;
}

// 可滚动的最大首行。
// 传入：可见行数；传出：RowCount - visibleRowCount，不足一屏为 0。
std::uint64_t HexViewport::MaxFirstVisibleRow(std::uint64_t visibleRowCount) const {
    // rowCount：总行数。
    const std::uint64_t rowCount = RowCount();
    if (rowCount > visibleRowCount) {
        return rowCount - visibleRowCount;
    }
    return 0;
}

// 计算让 address 可见所需的目标首行。
// 用法：auto top = view.ScrollToAddress(addr, ScrollAlign::Center, scrollBar.value(), visibleRows);
// 传入：目标地址、对齐方式、当前首行、可见行数；传出：目标首行，无法计算为空。
std::optional<std::uint64_t> HexViewport::ScrollToAddress(
    std::uint64_t address,
    ScrollAlign align,
    std::uint64_t currentFirstRow,
    std::uint64_t visibleRowCount) const {
    // 零行高的视口没有"滚到哪"可言；目标地址不属于空间同理。
    if (!IsValid() || visibleRowCount == 0) {
        return std::nullopt;
    }
    // targetRow：目标地址所在行。
    const std::optional<std::uint64_t> targetRow = RowOfAddress(address);
    if (!targetRow.has_value()) {
        return std::nullopt;
    }

    // 最大首行：目标首行不能让视口下方出现空白。
    const std::uint64_t maxFirstRow = MaxFirstVisibleRow(visibleRowCount);

    // result：按对齐方式先算出的目标首行（尚未夹取）。
    std::uint64_t result = *targetRow;
    if (align == ScrollAlign::Top) {
        // 顶部对齐：目标行就是首行。
        result = *targetRow;
    } else if (align == ScrollAlign::Center) {
        // 居中：首行 = 目标行 - 可见行数/2，不足则取 0（不能下溢）。
        // half：视口高度的一半（向下取整）。
        const std::uint64_t half = visibleRowCount / 2ULL;
        result = (*targetRow > half) ? (*targetRow - half) : 0ULL;
    } else {
        // 就近：先把当前首行夹进合法范围，再判断目标行在视口的上方、之内还是下方。
        // current：夹取后的当前首行。
        const std::uint64_t current = (currentFirstRow > maxFirstRow) ? maxFirstRow : currentFirstRow;
        if (*targetRow < current) {
            // 在上方：滚到顶部对齐。
            result = *targetRow;
        } else if (*targetRow - current >= visibleRowCount) {
            // 在下方（已经越过最后一个可见行）：滚到底部对齐。
            result = *targetRow - (visibleRowCount - 1ULL);
        } else {
            // 已经可见：不动。
            result = current;
        }
    }

    // 最后统一夹取，防止滚出末尾空白。
    return (result > maxFirstRow) ? maxFirstRow : result;
}

void HexViewport::EraseUnknownRange(std::uint64_t first, std::uint64_t last) {
    if (unknownRanges_.empty() || first > last) return;
    auto it = unknownRanges_.upper_bound(first);
    if (it != unknownRanges_.begin()) --it;
    while (it != unknownRanges_.end() && it->first <= last) {
        if (it->second < first) { ++it; continue; }
        const auto low = it->first, high = it->second;
        it = unknownRanges_.erase(it);
        if (low < first) unknownRanges_.emplace(low, first - 1);
        if (high > last) { unknownRanges_.emplace(last + 1, high); break; }
    }
}

void HexViewport::AddUnknownRange(std::uint64_t first, std::uint64_t last) {
    if (first > last || last < firstAddress_ || first > lastAddress_) return;
    first = std::max(first, firstAddress_); last = std::min(last, lastAddress_);
    auto it = unknownRanges_.lower_bound(first);
    if (it != unknownRanges_.begin()) {
        const auto previous = std::prev(it);
        if (previous->second >= first || first - previous->second == 1) it = previous;
    }
    while (it != unknownRanges_.end() && (it->first <= last || it->first - last == 1)) {
        first = std::min(first, it->first); last = std::max(last, it->second);
        it = unknownRanges_.erase(it);
    }
    if (unknownRanges_.size() < 4096) unknownRanges_.emplace(first, last);
}

bool HexViewport::IsKnownUnreadable(std::uint64_t address) const {
    if (!foldUnknown_ || unknownRanges_.empty()) return false;
    auto it = unknownRanges_.upper_bound(address);
    return it != unknownRanges_.begin() && std::prev(it)->second >= address;
}

void HexViewport::TrackUnknownPage(std::uint64_t pageStart, const std::vector<std::uint8_t>& mask) {
    if (!foldUnknown_) return;
    EraseUnknownRange(pageStart, pageStart + kPageBytes - 1);
    std::size_t index = 0;
    while (index < mask.size()) {
        if (mask[index] != 0) { ++index; continue; }
        const auto begin = index;
        while (index < mask.size() && mask[index] == 0) ++index;
        if (index - begin >= 8 || begin == 0 || index == mask.size())
            AddUnknownRange(pageStart + begin, pageStart + index - 1);
    }
}

void HexViewport::RebuildReadableRanges(std::uint64_t pageStart, CachedPage& page) {
    page.readableRanges.clear();
    if (page.unreadable || page.validMask.empty()) return;
    const auto first = std::max(pageStart, firstAddress_);
    const auto last = std::min(pageStart + kPageBytes - 1, lastAddress_);
    auto offset = static_cast<std::size_t>(first - pageStart);
    const auto limit = static_cast<std::size_t>(last - pageStart + 1);
    while (offset < limit) {
        if (!page.validMask[offset]) { ++offset; continue; }
        const auto begin = offset;
        while (offset < limit && page.validMask[offset]) ++offset;
        const auto low = pageStart + begin, high = pageStart + offset - 1;
        // Several valid bytes on adjacent rows keep the same rows visible. Merge
        // them in the summary, so checkerboard byte masks do not inflate the index.
        if (!page.readableRanges.empty()
            && (low - rowBase_) / bytesPerRow_ <= (page.readableRanges.back().last - rowBase_) / bytesPerRow_ + 1)
            page.readableRanges.back().last = high;
        else page.readableRanges.push_back({low, high});
    }
}

void HexViewport::RebuildFolds() {
    if (!foldUnknown_ && hiddenRows_.empty()) return;
    std::vector<HiddenRows> next;
    std::uint64_t hidden = 0;
    if (foldUnknown_ && IsValid()) {
        const auto caretRow = (selection_.caret - rowBase_) / bytesPerRow_;
        const auto append = [&](std::uint64_t first, std::uint64_t last) {
            if (first > last) return;
            if (!next.empty() && first == next.back().last + 1) next.back().last = last;
            else next.push_back({first, last, hidden, first - hidden});
            hidden += last - first + 1;
        };
        const auto appendProtected = [&](std::uint64_t first, std::uint64_t last) {
            // Walk staged BLOCKS rather than staged rows/bytes. A 64MiB patch
            // remains one range query even when most of the address space is unknown.
            while (first <= last) {
                const auto lowAddress = rowBase_ + first * bytesPerRow_;
                const auto lastRowAddress = rowBase_ + last * bytesPerRow_;
                const auto highAddress = lastRowAddress + std::min<std::uint64_t>(bytesPerRow_ - 1, lastAddress_ - lastRowAddress);
                const auto range = foldProtection_ ? foldProtection_(lowAddress, highAddress) : std::nullopt;
                if (!range) { append(first, last); return; }
                if (range->first > highAddress || range->last < lowAddress || range->first > range->last) return;
                const auto lowRow = (std::max(lowAddress, range->first) - rowBase_) / bytesPerRow_;
                const auto highRow = (std::min(highAddress, range->last) - rowBase_) / bytesPerRow_;
                if (first < lowRow) append(first, lowRow - 1);
                if (highRow == last) return;
                first = highRow + 1;
            }
        };
        const auto unknown = [&](std::uint64_t first, std::uint64_t last) {
            if (first > last) return;
            const auto low = (first - rowBase_) / bytesPerRow_;
            const auto high = (last - rowBase_) / bytesPerRow_;
            if (high - low < 2) return;
            const auto begin = low + 1, end = high - 1;
            std::uint64_t protectedRows[2] = {caretRow, foldRevealedAddress_
                ? (*foldRevealedAddress_ - rowBase_) / bytesPerRow_ : kMaxAddress};
            if (protectedRows[1] < protectedRows[0]) std::swap(protectedRows[0], protectedRows[1]);
            auto cursor = begin;
            for (const auto row : protectedRows) if (row >= cursor && row <= end) {
                if (cursor < row) appendProtected(cursor, row - 1);
                cursor = row + 1;
            }
            if (cursor <= end) appendProtected(cursor, end);
        };
        // Unloaded and pending bytes are unknown too. Build their complement from
        // the bounded readable-page summaries, without visiting absent pages.
        std::vector<AddressRange> readable;
        for (const auto& [address, page] : pages_) {
            (void)address;
            for (const auto& range : page.readableRanges) {
                if (!readable.empty()
                    && (range.first - rowBase_) / bytesPerRow_ <= (readable.back().last - rowBase_) / bytesPerRow_ + 1)
                    readable.back().last = range.last;
                else readable.push_back(range);
            }
        }
        auto cursor = firstAddress_;
        bool finished = false;
        for (const auto& range : readable) {
            if (cursor < range.first) unknown(cursor, range.first - 1);
            if (range.last == lastAddress_) { finished = true; break; }
            cursor = range.last + 1;
        }
        if (!finished) unknown(cursor, lastAddress_);
    }
    if (next != hiddenRows_) ++foldRevision_;
    hiddenRows_ = std::move(next);
    hiddenRowCount_ = hidden;
}

void HexViewport::SetFoldUnknown(bool enabled) {
    if (foldUnknown_ == enabled) return;
    foldUnknown_ = enabled;
    foldRevealedAddress_.reset();
    unknownRanges_.clear();
    if (enabled) for (auto& [address, page] : pages_) {
        RebuildReadableRanges(address, page);
        if (page.unreadable) AddUnknownRange(address, address + kPageBytes - 1);
        else TrackUnknownPage(address, page.validMask);
    }
    RebuildFolds();
}

void HexViewport::NoteUnreadableRange(std::uint64_t first, std::uint64_t last) {
    if (!foldUnknown_ || !IsValid()) return;
    AddUnknownRange(first, last);
    // Mapping evidence may arrive after data: never hide retained values or pending reads.
    const auto firstPage = PageStartOf(first), lastPage = PageStartOf(last);
    for (auto it = pages_.lower_bound(firstPage); it != pages_.end() && it->first <= lastPage; ++it)
        if (!it->second.unreadable && std::any_of(it->second.validMask.begin(), it->second.validMask.end(),
            [](auto value) { return value != 0; })) EraseUnknownRange(it->first, it->first + kPageBytes - 1);
    for (auto it = inFlight_.lower_bound(firstPage); it != inFlight_.end() && *it <= lastPage; ++it)
        EraseUnknownRange(*it, *it + kPageBytes - 1);
    RebuildFolds();
}

void HexViewport::RevealAddress(std::uint64_t address) {
    if (!foldUnknown_ || !ContainsAddress(address)) return;
    if (foldRevealedAddress_ && *foldRevealedAddress_ == address) return;
    // Keep explicit navigation pinned even if the row is already visible: a
    // later width change or cache eviction must not fold the target away.
    foldRevealedAddress_ = address;
    RebuildFolds();
}

std::uint64_t HexViewport::RawToVisual(std::uint64_t row) const {
    if (hiddenRows_.empty()) return row;
    auto it = std::upper_bound(hiddenRows_.begin(), hiddenRows_.end(), row,
        [](auto value, const HiddenRows& span) { return value < span.first; });
    if (it == hiddenRows_.begin()) return row;
    --it;
    return row <= it->last ? it->visual : row - it->before - (it->last - it->first + 1);
}

std::uint64_t HexViewport::VisualToRaw(std::uint64_t row) const {
    if (hiddenRows_.empty()) return row;
    auto it = std::upper_bound(hiddenRows_.begin(), hiddenRows_.end(), row,
        [](auto value, const HiddenRows& span) { return value < span.visual; });
    if (it == hiddenRows_.begin()) return row;
    --it;
    return row + it->before + (it->last - it->first + 1);
}

}  // namespace ksword::memwb
