// HexCanvas.Scroll.cpp
// 作用：HexCanvas 的滚动模型——首行权威值、竖向滚动条的精确/比例映射、横向滚动、
// 让插入点可见、页请求规划（PlanFetch + MarkInFlight + 提供者）与可见范围通知。
//
// 竖向滚动条映射"首行行号"：最大首行不超过 2^31-1 时滑块值 == 首行；超过时量程固定为 INT_MAX，
// 滑块值按"首行 / 最大首行"的比例换算，拖滑块按比例跳转，滚轮与键盘仍按精确行数移动。

#include "HexCanvas.h"

#include <QScrollBar>
#include <QPointer>
#include <QSignalBlocker>

#include <algorithm>
#include <limits>

namespace ks::ui
{
    // ======================== 滚动 ========================

    // 能完整显示的行数，至少为 1。
    std::uint64_t HexCanvas::fullVisibleRows() const
    {
        const int usable = viewport()->height() - m_layout.headerHeight;
        if (usable < m_layout.rowHeight)
        {
            return 1ULL;
        }
        return static_cast<std::uint64_t>(usable / m_layout.rowHeight);
    }

    // 需要绘制的行数（含被截断的最后一行），至少为 1。
    std::uint64_t HexCanvas::paintRowCount() const
    {
        const int usable = viewport()->height() - m_layout.headerHeight;
        if (usable <= 0)
        {
            return 1ULL;
        }
        return static_cast<std::uint64_t>((usable + m_layout.rowHeight - 1) / m_layout.rowHeight);
    }

    // 当前能完整显示的行数（公开版本）。
    std::uint64_t HexCanvas::visibleRowCount() const
    {
        return fullVisibleRows();
    }

    // 首行行号。
    std::uint64_t HexCanvas::firstVisibleRow() const
    {
        return m_firstRow;
    }

    // 最大首行。
    std::uint64_t HexCanvas::maxFirstRow() const
    {
        return m_hasSpace ? m_viewport.MaxFirstVisibleRow(fullVisibleRows()) : 0ULL;
    }

    // 设置首行（公开版本，会同步滚动条）。
    void HexCanvas::setFirstVisibleRow(std::uint64_t row)
    {
        setFirstRowInternal(row, true);
    }

    // 设置首行的内部实现。
    // 传入：行号（夹取到最大首行）、是否同步滚动条（用户拖滑块时为假，避免取整抖动）。
    void HexCanvas::setFirstRowInternal(std::uint64_t row, bool syncBar)
    {
        const QPointer<HexCanvas> alive(this);
        const std::uint64_t scrollingRevision = sourceRevision();
        const std::uint64_t clamped = std::min(row, maxFirstRow());
        if (clamped == m_firstRow)
        {
            return;
        }
        m_firstRow = clamped;
        if (syncBar)
        {
            syncScrollBars();
            if (!alive || sourceRevision() != scrollingRevision || m_firstRow != clamped) return;
        }
        viewport()->update();
        requestVisiblePages();
        if (!alive || sourceRevision() != scrollingRevision || m_firstRow != clamped) return;
        notifyVisibleRange();
    }

    // 滚动到地址。
    bool HexCanvas::scrollToAddress(std::uint64_t address, ScrollAlign align)
    {
        if (!m_hasSpace)
        {
            return false;
        }
        const std::optional<std::uint64_t> top =
            m_viewport.ScrollToAddress(address, align, m_firstRow, fullVisibleRows());
        if (!top.has_value())
        {
            return false;
        }
        setFirstVisibleRow(*top);
        return true;
    }

    // 按精确行数滚动。
    // 传入：行数（正数向下）；先比较后加减，绝不回绕。
    void HexCanvas::scrollRowsBy(std::int64_t deltaRows)
    {
        if (!m_hasSpace || deltaRows == 0)
        {
            return;
        }
        // magnitude：|delta|，用补码写法对 INT64_MIN 同样正确。
        const std::uint64_t magnitude = deltaRows >= 0
            ? static_cast<std::uint64_t>(deltaRows)
            : (0ULL - static_cast<std::uint64_t>(deltaRows));
        const std::uint64_t limit = maxFirstRow();
        std::uint64_t target = m_firstRow;
        if (deltaRows > 0)
        {
            target = (magnitude > limit - m_firstRow) ? limit : (m_firstRow + magnitude);
        }
        else
        {
            target = (magnitude > m_firstRow) ? 0ULL : (m_firstRow - magnitude);
        }
        setFirstVisibleRow(target);
    }

    // 滑块值 -> 行号（比例映射）。
    // 传入：滑块值、最大首行；用商+余数分解避免 128 位乘法：余数 < 2^31、滑块值 < 2^31，乘积 < 2^62。
    std::uint64_t HexCanvas::rowFromSlider(int value, std::uint64_t maxRow)
    {
        const std::uint64_t range = static_cast<std::uint64_t>(kProportionalRange);
        if (value <= 0)
        {
            return 0ULL;
        }
        const std::uint64_t slider = static_cast<std::uint64_t>(value);
        if (slider >= range)
        {
            return maxRow;
        }
        return (maxRow / range) * slider + ((maxRow % range) * slider) / range;
    }

    // 行号 -> 滑块值（比例映射）。末行精确对应量程上限，便于"拖到底就是最后一屏"。
    int HexCanvas::sliderFromRow(std::uint64_t row, std::uint64_t maxRow)
    {
        if (maxRow == 0)
        {
            return 0;
        }
        if (row >= maxRow)
        {
            return kProportionalRange;
        }
        const long double ratio = static_cast<long double>(row) / static_cast<long double>(maxRow);
        const long double scaled = ratio * static_cast<long double>(kProportionalRange);
        return static_cast<int>(std::min<long double>(scaled, static_cast<long double>(kProportionalRange)));
    }

    // 把滚动条量程、页长与当前值同步到模型。
    // 精确模式：滑块值 == 首行行号；比例模式：量程固定，滑块值 = 首行/最大首行 的比例。
    void HexCanvas::syncScrollBars()
    {
        const QPointer<HexCanvas> alive(this);
        const QPointer<QScrollBar> vertical(verticalScrollBar());
        const QPointer<QScrollBar> horizontal(horizontalScrollBar());
        // 冻结 setter 前的实际属性，只在原生栈返回后通知真实范围和值变化。
        struct BarState
        {
            int minimum;
            int maximum;
            int value;
        };
        const BarState oldVertical {vertical->minimum(), vertical->maximum(), vertical->value()};
        const BarState oldHorizontal {horizontal->minimum(), horizontal->maximum(), horizontal->value()};
        // 同步期间屏蔽 valueChanged 回调，避免把程序设置当成用户拖动。
        const bool previousGuard = m_updatingBars;
        m_updatingBars = true;
        {
            const QSignalBlocker blockedVertical(vertical.data());
            const QSignalBlocker blockedHorizontal(horizontal.data());

            // 竖向滚动条。
            const std::uint64_t limit = maxFirstRow();
            QScrollBar* vBar = verticalScrollBar();
            if (limit <= static_cast<std::uint64_t>(std::numeric_limits<int>::max()))
            {
                m_proportionalScroll = false;
                vBar->setRange(0, static_cast<int>(limit));
                vBar->setPageStep(static_cast<int>(std::min<std::uint64_t>(fullVisibleRows(), 0x7FFFFFFFULL)));
                vBar->setSingleStep(1);
                vBar->setValue(static_cast<int>(std::min(m_firstRow, limit)));
            }
            else
            {
                m_proportionalScroll = true;
                vBar->setRange(0, kProportionalRange);
                vBar->setPageStep(1);
                vBar->setSingleStep(1);
                vBar->setValue(sliderFromRow(m_firstRow, limit));
            }

            // 横向滚动条：像素滚动，量程 = 内容宽度 - 视口宽度。
            const int viewWidth = viewport()->width();
            const int maxHorizontal = std::max(0, m_layout.contentWidth - viewWidth);
            QScrollBar* hBar = horizontalScrollBar();
            hBar->setRange(0, maxHorizontal);
            hBar->setPageStep(std::max(1, viewWidth));
            hBar->setSingleStep(std::max(1, m_layout.charWidth * 3));
            m_hOffset = std::clamp(m_hOffset, 0, maxHorizontal);
            hBar->setValue(m_hOffset);
        }

        // 观察者可关闭页面或换源。换源后只通知控件当前属性，不重放旧数值；
        // 来源/行宽调用者在本方法返回后再核对自己的票据，停止旧目标后续操作。
        const auto publish = [&alive](const QPointer<QScrollBar>& bar, const BarState& before) {
            if (!alive || !bar) return false;
            if (before.minimum != bar->minimum() || before.maximum != bar->maximum())
                emit bar->rangeChanged(bar->minimum(), bar->maximum());
            if (!alive || !bar) return false;
            if (before.value != bar->value()) emit bar->valueChanged(bar->value());
            return alive && bar;
        };
        if (!publish(vertical, oldVertical) || !publish(horizontal, oldHorizontal))
        {
            if (alive) m_updatingBars = previousGuard;
            return;
        }
        if (alive) m_updatingBars = previousGuard;
    }

    // 用户拖动或点击竖向滚动条。
    void HexCanvas::onVerticalBarChanged(int value)
    {
        if (m_updatingBars || !m_hasSpace)
        {
            return;
        }
        const std::uint64_t limit = maxFirstRow();
        const std::uint64_t row = m_proportionalScroll
            ? rowFromSlider(value, limit)
            : static_cast<std::uint64_t>(std::max(0, value));
        // 用户拖动时不回写滑块：回写会因取整把滑块拉得抖动。
        setFirstRowInternal(row, false);
    }

    // 横向滚动条变化。
    void HexCanvas::onHorizontalBarChanged(int value)
    {
        if (m_updatingBars)
        {
            return;
        }
        m_hOffset = value;
        viewport()->update();
    }

    // 让插入点所在行列可见。
    // 作用：纵向按"最近"对齐，横向在插入点单元格越出视口时补偿滚动量。
    void HexCanvas::ensureCaretVisible()
    {
        // 既有键盘路径保持 Nearest；正式打开入口显式调用 revealCaret(Top)。
        (void)revealCaret(ScrollAlign::Nearest);
    }

    // 双轴揭示当前插入点：纵向只执行调用方指定的对齐，横向使用真实单元格几何。
    bool HexCanvas::revealCaret(ScrollAlign align)
    {
        if (!m_hasSpace)
        {
            return false;
        }
        const QPointer<HexCanvas> alive(this);
        const std::uint64_t scrollingRevision = sourceRevision();
        const auto selected = m_viewport.GetSelection();
        const std::uint64_t caret = m_viewport.GetSelection().caret;
        const std::optional<std::uint64_t> top =
            m_viewport.ScrollToAddress(caret, align, m_firstRow, fullVisibleRows());
        if (top.has_value())
        {
            setFirstVisibleRow(*top);
            if (!alive || sourceRevision() != scrollingRevision || !selectionStillMatches(selected)) return false;
        }

        // 横向：取活动面板里插入点单元格的矩形，越出左右边界就挪动横向滚动条。
        const QRect cell = cellRect(caret, m_viewport.Pane());
        if (cell.isNull())
        {
            return true;
        }
        const int viewWidth = viewport()->width();
        const int margin = m_layout.charWidth;
        if (cell.left() < 0)
        {
            horizontalScrollBar()->setValue(m_hOffset + cell.left() - margin);
        }
        else if (cell.right() > viewWidth)
        {
            horizontalScrollBar()->setValue(m_hOffset + cell.right() - viewWidth + margin);
        }
        return alive && sourceRevision() == scrollingRevision && selectionStillMatches(selected);
    }

    // 规划并发出页请求。
    // 作用：PlanFetch（预取前后各 2 页）-> 先 MarkInFlight -> 交给提供者。
    void HexCanvas::requestVisiblePages()
    {
        if (!m_hasSpace || m_provider == nullptr || !m_viewportReadEnabled)
        {
            return;
        }

        // plan：还需要读取的页范围；accepted：成功登记在途的范围，只有它们才交给提供者。
        const std::vector<HexFetchRange> plan =
            m_viewport.PlanFetch(m_firstRow, paintRowCount(), kPrefetchPages);
        std::vector<HexFetchRange> accepted;
        accepted.reserve(plan.size());
        for (const HexFetchRange& range : plan)
        {
            if (m_viewport.MarkInFlight(range) == PageResult::Accepted)
            {
                accepted.push_back(range);
            }
        }
        if (!accepted.empty())
        {
            m_provider->RequestPages(accepted, m_viewport.SourceRevision());
        }
    }

    std::optional<HexCanvas::AddressRange> HexCanvas::addressSpaceRange() const
    {
        if (!m_hasSpace) return std::nullopt;
        return AddressRange{m_viewport.FirstAddress(), m_viewport.LastAddress()};
    }

    void HexCanvas::setViewportReadEnabled(bool enabled)
    {
        if (m_viewportReadEnabled == enabled) return;
        m_viewportReadEnabled = enabled;
        if (enabled) requestVisiblePages();
    }

    void HexCanvas::requestAddressRange(std::uint64_t first, std::uint64_t last)
    {
        if (!m_hasSpace || !m_provider || first > last) return;
        first = std::max(first, m_viewport.FirstAddress());
        last = std::min(last, m_viewport.LastAddress());
        if (first > last) return;
        // A view requests a bounded decode window, never an entire target address space.
        last = first + std::min<std::uint64_t>(last - first, 65535);
        const auto firstRow = m_viewport.RowOfAddress(first);
        const auto lastRow = m_viewport.RowOfAddress(last);
        if (!firstRow || !lastRow) return;
        const auto plan = m_viewport.PlanFetch(*firstRow, *lastRow - *firstRow + 1, kPrefetchPages);
        std::vector<HexFetchRange> accepted;
        for (const auto& range : plan)
            if (m_viewport.MarkInFlight(range) == PageResult::Accepted) accepted.push_back(range);
        if (!accepted.empty()) m_provider->RequestPages(accepted, m_viewport.SourceRevision());
    }

    // 返回当前绘制区间；首尾行均按真实地址空间去掉补空位。
    std::optional<HexCanvas::AddressRange> HexCanvas::visibleAddressRange() const
    {
        if (!m_hasSpace)
        {
            return std::nullopt;
        }
        // lastRow：最后一个被绘制的行（夹取到末行）。
        const std::uint64_t rowCount = m_viewport.RowCount();
        const std::uint64_t lastRow = std::min(m_firstRow + (paintRowCount() - 1ULL), rowCount - 1ULL);
        const std::optional<AddressRange> topSpan = m_viewport.RowValidSpan(m_firstRow);
        const std::optional<AddressRange> bottomSpan = m_viewport.RowValidSpan(lastRow);
        if (!topSpan.has_value() || !bottomSpan.has_value())
        {
            return std::nullopt;
        }
        return AddressRange{topSpan->first, bottomSpan->last};
    }

    // 可见范围变化时发 visibleRangeChanged（去重）；返回 HEX 也读取同一几何来源。
    void HexCanvas::notifyVisibleRange()
    {
        const auto visible = visibleAddressRange();
        if (!visible) return;
        if (m_notifiedOnce && visible->first == m_lastNotifiedFirst && visible->last == m_lastNotifiedLast)
        {
            return;
        }
        m_notifiedOnce = true;
        m_lastNotifiedFirst = visible->first;
        m_lastNotifiedLast = visible->last;
        emit visibleRangeChanged(visible->first, visible->last);
    }

}
