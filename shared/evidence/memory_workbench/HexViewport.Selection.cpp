// HexViewport.Selection.cpp
// 作用：HexViewport 的选区——插入点设置、按字节/行/页移动、Home/End、全选、面板切换。
//
// 选区模型是"线性文本式"：锚点 anchor 与插入点 caret 之间的所有字节（含两端）、
// 跨行连续，不是矩形。所有移动都先夹取到 [firstAddress, lastAddress]，绝不回绕。
//
// 移动函数统一用"方向 + 无符号幅度"实现：有符号增量转成幅度时用 0 - x 的补码写法，
// INT64_MIN 也能得到正确的 2^63，不会出现 -INT64_MIN 的溢出。

#include "HexViewport.h"

#include <limits>
#include <algorithm>

namespace ksword::memwb {

namespace {

// kMaxAddress：uint64 最大值，用于饱和与溢出判定。
constexpr std::uint64_t kMaxAddress = std::numeric_limits<std::uint64_t>::max();

// MagnitudeOf：有符号增量的绝对值（无符号表示）。
// 传入：增量；传出：|delta|。对 INT64_MIN 同样正确（结果为 2^63）。
std::uint64_t MagnitudeOf(std::int64_t delta) {
    if (delta >= 0) {
        return static_cast<std::uint64_t>(delta);
    }
    // 对负数取补码：0 - x（无符号回绕）恰好等于 |x|。
    return 0ULL - static_cast<std::uint64_t>(delta);
}

}  // namespace

// 当前选区。
HexViewport::Selection HexViewport::GetSelection() const {
    return selection_;
}

// 选区的闭区间。
// 传出：[min(anchor,caret), max(anchor,caret)]；视图无效返回空。
std::optional<HexViewport::AddressRange> HexViewport::SelectedRange() const {
    if (!IsValid()) {
        return std::nullopt;
    }
    // range：返回值，端点按先后排好。
    AddressRange range;
    if (selection_.anchor <= selection_.caret) {
        range.first = selection_.anchor;
        range.last = selection_.caret;
    } else {
        range.first = selection_.caret;
        range.last = selection_.anchor;
    }
    return range;
}

// 把地址夹取到地址空间。
// 因为补空位只出现在首行开头与末行结尾，"吸附到该行第一个有效地址"与"夹取"是同一个动作。
std::uint64_t HexViewport::ClampToSpace(std::uint64_t address) const {
    if (address < firstAddress_) {
        return firstAddress_;
    }
    if (address > lastAddress_) {
        return lastAddress_;
    }
    return address;
}

// 应用新的插入点。
// 传入：目标地址（必须已在空间内）、是否扩选；传出：选区是否变化。
bool HexViewport::ApplyCaret(std::uint64_t target, bool extend) {
    // before：改动前的选区，用来判断是否有变化。
    const Selection before = selection_;

    // 插入点总是跟随；锚点只在不扩选时跟随（扩选时保持不动）。
    selection_.caret = target;
    if (!extend) {
        selection_.anchor = target;
    }
    if (foldUnknown_ && before.caret / bytesPerRow_ != target / bytesPerRow_
        && (PeekByte(before.caret).state != ByteState::Valid || PeekByte(target).state != ByteState::Valid)) RebuildFolds();
    return selection_.anchor != before.anchor || selection_.caret != before.caret;
}

// 设置插入点。
// 用法：鼠标点击命中格 (row, col) 时 view.SetCaret(rowStart + col, shiftDown)。
// 传入：地址、是否扩选；传出：true=正好落在该地址，false=被吸附/夹取或视图无效。
bool HexViewport::SetCaret(std::uint64_t address, bool extend) {
    if (!IsValid()) {
        return false;
    }
    // snapped：夹取（吸附）后的地址。
    const std::uint64_t snapped = ClampToSpace(address);
    ApplyCaret(snapped, extend);
    return snapped == address;
}

// 按字节数量级移动。
// 传入：方向、幅度、是否扩选；传出：选区是否变化。
bool HexViewport::MoveBytesByMagnitude(bool forward, std::uint64_t magnitude, bool extend) {
    if (!IsValid()) {
        return false;
    }

    // 先比较剩余空间再加减：幅度超过剩余就直接落在边界上，不会回绕。
    // caret：当前插入点；target：移动后的插入点。
    const std::uint64_t caret = selection_.caret;
    std::uint64_t target = caret;
    if (forward) {
        target = (magnitude > lastAddress_ - caret) ? lastAddress_ : (caret + magnitude);
    } else {
        target = (magnitude > caret - firstAddress_) ? firstAddress_ : (caret - magnitude);
    }
    if (foldUnknown_ && magnitude == 1 && !hiddenRows_.empty()) {
        const auto raw = (target - rowBase_) / bytesPerRow_;
        auto it = std::upper_bound(hiddenRows_.begin(), hiddenRows_.end(), raw,
            [](auto value, const HiddenRows& span) { return value < span.first; });
        if (it != hiddenRows_.begin()) {
            --it;
            if (raw <= it->last) {
                const auto row = forward ? it->last + 1 : it->first - 1;
                const auto column = (target - rowBase_) % bytesPerRow_;
                const auto start = rowBase_ + row * bytesPerRow_;
                target = ClampToSpace(start + std::min<std::uint64_t>(column, lastAddress_ - start));
            }
        }
    }
    return ApplyCaret(target, extend);
}

// 按字节移动。
// 传入：增量（正数向高地址）、是否扩选；传出：选区是否变化。
bool HexViewport::MoveCaretByBytes(std::int64_t deltaBytes, bool extend) {
    return MoveBytesByMagnitude(deltaBytes >= 0, MagnitudeOf(deltaBytes), extend);
}

// 按行数量级移动，保持列。
// 传入：方向、行数、是否扩选；传出：选区是否变化。
bool HexViewport::MoveRowsByMagnitude(bool forward, std::uint64_t magnitude, bool extend) {
    if (!IsValid()) {
        return false;
    }

    // 插入点始终在空间内，所以行列必然存在；防御性地处理不存在的情况。
    // row/column：当前插入点的行与列。
    const std::optional<std::uint64_t> row = RowOfAddress(selection_.caret);
    const std::optional<std::uint32_t> column = ColumnOfAddress(selection_.caret);
    if (!row.has_value() || !column.has_value()) {
        return false;
    }

    // 目标行：先比较剩余行数再加减，夹取在 [0, RowCount-1]，不回绕。
    // lastRow：最后一行的行号；targetRow：移动后的行号。
    const std::uint64_t lastRow = RowCount() - 1ULL;
    std::uint64_t targetRow = *row;
    if (forward) {
        targetRow = (magnitude > lastRow - *row) ? lastRow : (*row + magnitude);
    } else {
        targetRow = (magnitude > *row) ? 0ULL : (*row - magnitude);
    }

    // 目标行首 + 列：超过 2^64（行宽 48 的最高一行）或晚于末地址一律落在末地址，
    // 早于首地址（首行补空位）则吸附到首地址，统一由 ClampToSpace 处理。
    // start：目标行起始地址；offset：列号；target：移动后的插入点。
    const std::optional<std::uint64_t> start = RowStartAddress(targetRow);
    if (!start.has_value()) {
        return false;
    }
    const std::uint64_t offset = static_cast<std::uint64_t>(*column);
    std::uint64_t target = lastAddress_;
    if (offset <= kMaxAddress - *start) {
        target = ClampToSpace(*start + offset);
    }
    return ApplyCaret(target, extend);
}

// 按行移动。
// 传入：增量行数（正数向下）、是否扩选；传出：选区是否变化。
bool HexViewport::MoveCaretByRows(std::int64_t deltaRows, bool extend) {
    return MoveRowsByMagnitude(deltaRows >= 0, MagnitudeOf(deltaRows), extend);
}

// 按页移动：一页 = visibleRows 行。
// 传入：页数（正数向下）、每页行数（视口可见行数）、是否扩选；传出：选区是否变化。
// visibleRows 为 0 视为无效返回 false；页数 * 行数溢出时饱和为最大值，随后被夹取。
bool HexViewport::MoveCaretByPages(std::int64_t deltaPages, std::uint64_t visibleRows, bool extend) {
    if (!IsValid() || visibleRows == 0) {
        return false;
    }

    // 行数 = 页数幅度 * 每页行数；乘法前先用除法判断是否会溢出，溢出就饱和。
    // pages：页数幅度；rows：折算成行数（饱和后）。
    const std::uint64_t pages = MagnitudeOf(deltaPages);
    const std::uint64_t rows = (pages > kMaxAddress / visibleRows) ? kMaxAddress : (pages * visibleRows);
    return MoveRowsByMagnitude(deltaPages >= 0, rows, extend);
}

// Home：移到插入点所在行的第一个有效地址。
// 传入：是否扩选；传出：选区是否变化。首行取 firstAddress（补空位不可选）。
bool HexViewport::MoveCaretHome(bool extend) {
    if (!IsValid()) {
        return false;
    }
    // row：插入点所在行；span：该行的有效区间。
    const std::optional<std::uint64_t> row = RowOfAddress(selection_.caret);
    if (!row.has_value()) {
        return false;
    }
    const std::optional<AddressRange> span = RowValidSpan(*row);
    if (!span.has_value()) {
        return false;
    }
    return ApplyCaret(span->first, extend);
}

// End：移到插入点所在行的最后一个有效地址。
// 传入：是否扩选；传出：选区是否变化。末行取 lastAddress（末尾补空位不可选）。
bool HexViewport::MoveCaretEnd(bool extend) {
    if (!IsValid()) {
        return false;
    }
    // row：插入点所在行；span：该行的有效区间。
    const std::optional<std::uint64_t> row = RowOfAddress(selection_.caret);
    if (!row.has_value()) {
        return false;
    }
    const std::optional<AddressRange> span = RowValidSpan(*row);
    if (!span.has_value()) {
        return false;
    }
    return ApplyCaret(span->last, extend);
}

// 全选：锚点放在 firstAddress、插入点放在 lastAddress。
// 传出：选区是否变化。
bool HexViewport::SelectAll() {
    if (!IsValid()) {
        return false;
    }
    // before：改动前的选区，用来判断是否有变化。
    const Selection before = selection_;
    selection_.anchor = firstAddress_;
    selection_.caret = lastAddress_;
    return selection_.anchor != before.anchor || selection_.caret != before.caret;
}

// 当前面板。
HexViewport::ActivePane HexViewport::Pane() const {
    return selection_.pane;
}

// 设置面板，不改变选区地址。
void HexViewport::SetPane(ActivePane pane) {
    selection_.pane = pane;
}

// 切换 Hex/Ascii。
// 传出：切换后的面板。
HexViewport::ActivePane HexViewport::TogglePane() {
    if (selection_.pane == ActivePane::Hex) {
        selection_.pane = ActivePane::Ascii;
    } else {
        selection_.pane = ActivePane::Hex;
    }
    return selection_.pane;
}

}  // namespace ksword::memwb
