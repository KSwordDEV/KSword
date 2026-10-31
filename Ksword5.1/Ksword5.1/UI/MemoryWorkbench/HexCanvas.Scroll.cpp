// HexCanvas.Scroll.cpp
// 作用：HexCanvas 的滚动模型——首行权威值、竖向滚动条的精确/比例映射、横向滚动、
// 让插入点可见、页请求规划（PlanFetch + MarkInFlight + 提供者）与可见范围通知。
//
// 竖向滚动条映射"首行行号"：最大首行不超过 2^31-1 时滑块值 == 首行；超过时量程固定为 INT_MAX，
// 滑块值按"首行 / 最大首行"的比例换算，拖滑块按比例跳转，滚轮与键盘仍按精确行数移动。

#include "HexCanvas.h"
#include "HexCanvasOverviewBar.h"

#include <QScrollBar>
#include <QPointer>
#include <QSignalBlocker>
#include <QToolButton>
#include <QApplication>
#include <QShowEvent>
#include <QStyleOptionSlider>
#include "../../theme.h"
#include "../../Internationalization/LanguageManager.h"

#include <algorithm>
#include <limits>

namespace ks::ui
{
    void HexCanvas::setFixedAddressScale(bool enabled)
    {
        if (m_fixedAddressScale == enabled) return;
        m_fixedAddressScale = enabled;
        m_keepScrollEnd = false;
        syncScrollBars();
    }
    std::uint64_t HexCanvas::scrollScaleRows() const
    {
        if (!m_hasSpace) return 0;
        if (knownScrollScale()) return m_viewport.KnownRowCount();
        return m_fixedAddressScale ? m_viewport.UnfoldedRowCount() : m_viewport.RowCount();
    }
    std::uint64_t HexCanvas::scrollScaleLimit() const
    {
        const auto rows = scrollScaleRows();
        if (knownScrollScale()) {
            const auto top = m_viewport.RowValidSpan(scrollEndFirstRow());
            return top && rows ? std::min(m_viewport.KnownRowAtOrAfter(top->first), rows - 1) : 0;
        }
        return rows > fullVisibleRows() ? rows - fullVisibleRows() : 0;
    }
    std::uint64_t HexCanvas::scrollEndFirstRow() const
    {
        if (!knownScrollScale()) return maxFirstRow();
        const auto rows = m_viewport.KnownRowCount();
        if (!rows) return m_firstRow;
        const auto first = m_viewport.RowOfAddress(m_viewport.KnownRowSpan(0)->first).value();
        const auto last = m_viewport.RowOfAddress(m_viewport.KnownRowSpan(rows - 1)->last).value();
        return std::min(maxFirstRow(), std::max(first, last - std::min(last - first, fullVisibleRows() - 1)));
    }
    std::uint64_t HexCanvas::scrollScaleFirstRow() const
    {
        if (knownScrollScale()) {
            if (m_keepScrollEnd) return scrollScaleLimit();
            const auto top = m_viewport.RowValidSpan(m_firstRow);
            return top ? std::min(m_viewport.KnownRowAtOrAfter(top->first), scrollScaleLimit()) : 0;
        }
        if (!m_fixedAddressScale || !m_hasSpace) return m_firstRow;
        if (m_keepScrollEnd || (maxFirstRow() && m_firstRow == maxFirstRow())) return scrollScaleLimit();
        if (!maxFirstRow() && m_foldNavigationAddress)
            return std::min(m_viewport.UnfoldedRowOfAddress(*m_foldNavigationAddress).value_or(0), scrollScaleLimit());
        const auto span = m_viewport.RowValidSpan(m_firstRow);
        return span ? m_viewport.UnfoldedRowOfAddress(span->first).value_or(0) : 0;
    }
    std::uint64_t HexCanvas::scrollScaleAddress(std::uint64_t row) const
    {
        if (knownScrollScale()) return m_viewport.KnownRowSpan(row).value().first;
        const auto first = m_viewport.FirstAddress();
        const auto base = first - first % m_viewport.BytesPerRow();
        return std::max(first, base + std::min(row, m_viewport.UnfoldedRowCount() - 1) * m_viewport.BytesPerRow());
    }
    void HexCanvas::scrollKnownToRow(std::uint64_t row, bool syncBar)
    {
        if (!m_viewport.KnownRowCount()) return;
        const auto limit = scrollScaleLimit();
        row = std::min(row, limit);
        const auto projected = row == limit ? scrollEndFirstRow()
            : m_viewport.RowOfAddress(scrollScaleAddress(row)).value();
        // No revealing/reading arbitrary unknown addresses from the overview.
        // Normal viewport fetch planning remains owned by setFirstRowInternal.
        setFirstRowInternal(projected, syncBar, row == limit);
    }
    void HexCanvas::setOverviewEnabled(bool enabled)
    {
        if (m_overviewEnabled == enabled) return;
        m_overviewEnabled = enabled;
        if (enabled) ensureOverviewBar();
        else {
            const QPointer<HexCanvas> alive(this);
            if (m_overviewBar) m_overviewBar->hide();
            if (!alive) return;
            m_viewport.SetOverviewEnabled(false);
            setViewportMargins(0, 0, 0, 0);
        }
    }

    void HexCanvas::ensureOverviewBar()
    {
        if (!m_overviewEnabled || !isVisible()) return;
        const QPointer<HexCanvas> alive(this);
        if (!m_overviewBar) {
            auto* rail = new HexCanvasOverviewBar(this);
            m_overviewBar = rail;
            connect(this, &HexCanvas::contentChanged, rail, qOverload<>(&QWidget::update));
            connect(this, &HexCanvas::caretMoved, rail, qOverload<>(&QWidget::update));
            connect(this, &HexCanvas::rowWidthModeChanged, rail, qOverload<>(&QWidget::update));
        }
        m_viewport.SetOverviewEnabled(true);
        setViewportMargins(0, 0, HexCanvasOverviewBar::kWidth, 0);
        if (alive) syncOverviewBar();
    }

    void HexCanvas::syncOverviewBar()
    {
        if (!m_overviewEnabled || !m_overviewBar) return;
        const QPointer<HexCanvas> alive(this);
        const auto view = viewport()->geometry();
        auto* bar = verticalScrollBar();
        QStyleOptionSlider option;
        option.initFrom(bar); option.orientation = Qt::Vertical;
        option.minimum = bar->minimum(); option.maximum = bar->maximum();
        option.pageStep = bar->pageStep(); option.singleStep = bar->singleStep();
        option.sliderPosition = bar->sliderPosition(); option.sliderValue = bar->value();
        const auto groove = bar->style()->subControlRect(QStyle::CC_ScrollBar, &option, QStyle::SC_ScrollBarGroove, bar);
        const auto top = groove.isEmpty() ? view.top() : bar->mapTo(this, groove.topLeft()).y();
        const auto height = groove.isEmpty() ? view.height() : groove.height();
        m_overviewBar->setGeometry(view.right() + 1, top, HexCanvasOverviewBar::kWidth, height);
        if (!alive) return;
        m_overviewBar->show();
        if (alive) m_overviewBar->update();
    }

    void HexCanvas::updateOverviewBar()
    {
        if (m_overviewEnabled && m_overviewBar && m_overviewBar->isVisible()) m_overviewBar->update();
    }

    void HexCanvas::showEvent(QShowEvent* event)
    {
        const QPointer<HexCanvas> alive(this);
        QAbstractScrollArea::showEvent(event);
        if (alive) ensureOverviewBar();
    }

    void HexCanvas::scrollOverviewToRow(std::uint64_t row)
    {
        if (!m_hasSpace) return;
        const auto limit = scrollScaleLimit();
        row = std::min(row, limit);
        const int value = m_proportionalScroll ? sliderFromRow(row, limit) : static_cast<int>(row);
        // Use the existing scrollbar path, including its proportional rounding,
        // cancellation and viewport read planning.
        verticalScrollBar()->setSliderPosition(value);
    }
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
    void HexCanvas::setFirstRowInternal(std::uint64_t row, bool syncBar, bool keepEnd)
    {
        m_keepScrollEnd = m_fixedAddressScale && keepEnd;
        cancelUniformBoundarySearch();
        m_foldFetchBudget = 16;
        const QPointer<HexCanvas> alive(this);
        const std::uint64_t scrollingRevision = sourceRevision();
        const std::uint64_t clamped = std::min(row, maxFirstRow());
        if (clamped == m_firstRow)
        {
            return;
        }
        m_foldScrollUp = clamped < m_firstRow;
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
        if (!m_hasSpace || !m_viewport.ContainsAddress(address))
        {
            return false;
        }
        const QPointer<HexCanvas> alive(this);
        m_keepScrollEnd = false;
        const auto revision = sourceRevision();
        m_foldNavigationAddress = address;
        const auto foldRevision = m_viewport.FoldRevision();
        m_viewport.RevealAddress(address);
        const bool revealed = foldRevision != m_viewport.FoldRevision();
        syncFoldGeometry();
        if (!alive || sourceRevision() != revision) return false;
        const std::optional<std::uint64_t> top =
            m_viewport.ScrollToAddress(address, align, m_firstRow, fullVisibleRows());
        if (!top.has_value())
        {
            return false;
        }
        const bool unchanged = *top == m_firstRow;
        setFirstVisibleRow(*top);
        if (!alive || sourceRevision() != revision) return false;
        // Revealing a row can leave the same visual first row (a fully folded
        // address space may fit on one screen). It still needs a page request.
        if (unchanged && (revealed || m_viewport.PeekByte(address).state == ByteState::NotLoaded))
        {
            viewport()->update();
            requestVisiblePages();
        }
        if (!alive || sourceRevision() != revision) return false;
        const auto state = m_viewport.PeekByte(address).state;
        if (m_foldUnknownRegions && (state == ByteState::NotLoaded || state == ByteState::Pending))
            requestAddressRange(address, address, RangeReadPurpose::ExplicitRead);
        return alive && sourceRevision() == revision;
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
        if (knownScrollScale()) {
            const auto first = scrollScaleFirstRow(), end = scrollScaleLimit();
            scrollKnownToRow(deltaRows > 0 ? first + std::min(magnitude, end - first)
                : first - std::min(magnitude, first), true);
            return;
        }
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
        setFirstRowInternal(target, true, deltaRows > 0 && target == limit);
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
        // Floating-point ratios can round a near-end row to 1.0 in enormous
        // spaces. Reserve the actual endpoint for the actual last screen.
        return static_cast<int>(std::min<long double>(scaled, static_cast<long double>(kProportionalRange - 1)));
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
            if (m_keepScrollEnd) m_firstRow = scrollEndFirstRow();
            const std::uint64_t limit = scrollScaleLimit();
            const auto position = std::min(scrollScaleFirstRow(), limit);
            QScrollBar* vBar = verticalScrollBar();
            if (limit <= static_cast<std::uint64_t>(std::numeric_limits<int>::max()))
            {
                m_proportionalScroll = false;
                vBar->setRange(0, static_cast<int>(limit));
                const auto pageRows = knownScrollScale() ? scrollScaleRows() - limit : fullVisibleRows();
                vBar->setPageStep(static_cast<int>(std::clamp<std::uint64_t>(pageRows, 1, 0x7FFFFFFFULL)));
                vBar->setSingleStep(1);
                vBar->setValue(static_cast<int>(position));
            }
            else
            {
                m_proportionalScroll = true;
                vBar->setRange(0, kProportionalRange);
                vBar->setPageStep(1);
                vBar->setSingleStep(1);
                vBar->setValue(sliderFromRow(position, limit));
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
        if (alive) updateOverviewBar();
    }

    // 用户拖动或点击竖向滚动条。
    void HexCanvas::onVerticalBarChanged(int value)
    {
        if (m_updatingBars || !m_hasSpace)
        {
            return;
        }
        const std::uint64_t limit = scrollScaleLimit();
        const std::uint64_t row = m_proportionalScroll
            ? rowFromSlider(value, limit)
            : static_cast<std::uint64_t>(std::max(0, value));
        if (knownScrollScale()) { scrollKnownToRow(row, false); return; }
        // 用户拖动时不回写滑块：回写会因取整把滑块拉得抖动。
        if (!m_fixedAddressScale) { setFirstRowInternal(row, false); return; }
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        if (limit && row >= limit)
        {
            setFirstRowInternal(maxFirstRow(), false, true);
            if (!alive || sourceRevision() != revision) return;
            const auto last = m_viewport.LastAddress();
            const auto state = m_viewport.PeekByte(last).state;
            if (state == ByteState::NotLoaded || state == ByteState::Pending)
                requestAddressRange(last, last, RangeReadPurpose::ExplicitRead);
            return;
        }
        const auto address = scrollScaleAddress(row);
        m_keepScrollEnd = false;
        m_foldNavigationAddress = address;
        m_viewport.RevealAddress(address);
        syncFoldGeometry();
        if (!alive || sourceRevision() != revision) return;
        const auto projected = m_viewport.RowOfAddress(address).value_or(0);
        setFirstRowInternal(projected, false);
        if (!alive || sourceRevision() != revision) return;
        const auto state = m_viewport.PeekByte(address).state;
        if (state == ByteState::NotLoaded || state == ByteState::Pending)
            requestAddressRange(address, address, RangeReadPurpose::ExplicitRead);
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
        // Module/region/address navigation enters through this path. A folded
        // space can fit on one screen, so a focus change need not move its first
        // row. Use the common reveal/read intent even in that case.
        if (!scrollToAddress(caret, align)) return false;
        if (!alive || sourceRevision() != scrollingRevision || !selectionStillMatches(selected)) return false;

        // 横向：取活动面板里插入点单元格的矩形，越出左右边界就挪动横向滚动条。
        const QRect cell = cellRect(caret, m_viewport.Pane());
        if (cell.isNull())
        {
            return true;
        }
        const int viewWidth = viewport()->width();
        const int margin = m_layout.charWidth;
        const int gutter = addressGutterWidth();
        if (cell.left() < gutter)
        {
            horizontalScrollBar()->setValue(m_hOffset + cell.left() - gutter - margin);
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
        // Record the NEW navigation position before a provider can synchronously
        // deliver pages/cancel reads; visibleRangeChanged has not fired yet.
        rememberFoldScrollAnchor();
        if (!m_hasSpace || m_provider == nullptr || !m_viewportReadEnabled)
        {
            return;
        }

        const QPointer<HexCanvas> alive(this);
        const auto revision = m_viewport.SourceRevision();
        auto* const provider = m_provider;
        // Interest follows visual rows, including folds, without copying cached bytes.
        provider->UpdateViewportInterest(
            m_viewport.PlanFetch(m_firstRow, paintRowCount(), kPrefetchPages, true), revision);
        if (!alive || revision != sourceRevision() || provider != m_provider) return;

        // plan：还需要读取的页范围；accepted：成功登记在途的范围，只有它们才交给提供者。
        const std::vector<HexFetchRange> plan =
            m_viewport.PlanFetch(m_firstRow, paintRowCount(), kPrefetchPages);
        std::vector<HexFetchRange> accepted;
        accepted.reserve(plan.size());
        for (HexFetchRange range : plan)
        {
            if (m_foldUnknownRegions)
            {
                range.pageCount = std::min(range.pageCount, m_foldFetchBudget);
                if (range.pageCount == 0) break;
            }
            if (m_viewport.MarkInFlight(range) == PageResult::Accepted)
            {
                accepted.push_back(range);
                if (m_foldUnknownRegions) m_foldFetchBudget -= range.pageCount;
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

    void HexCanvas::requestAddressRange(std::uint64_t first, std::uint64_t last, RangeReadPurpose purpose)
    {
        if (!m_hasSpace || !m_provider || first > last) return;
        first = std::max(first, m_viewport.FirstAddress());
        last = std::min(last, m_viewport.LastAddress());
        if (first > last) return;
        // A view requests a bounded decode window, never an entire target address space.
        last = first + std::min<std::uint64_t>(last - first, 65535);
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        auto* const provider = m_provider;
        const auto intent = m_viewport.PlanAddressFetch(first, last, kPrefetchPages, true);
        // Preserve the complete explicit intent BEFORE PlanFetch removes cached and
        // in-flight pages. A fully pending range still has protected ownership.
        if (purpose == RangeReadPurpose::Browse) provider->UpdateViewportInterest(intent, revision);
        else provider->ProtectPages(intent, revision);
        if (!alive || revision != sourceRevision() || provider != m_provider) return;
        const auto plan = m_viewport.PlanAddressFetch(first, last, kPrefetchPages);
        std::vector<HexFetchRange> accepted;
        for (const auto& range : plan)
            if (m_viewport.MarkInFlight(range) == PageResult::Accepted) accepted.push_back(range);
        if (!accepted.empty())
        {
            if (purpose == RangeReadPurpose::Browse) m_provider->RequestPages(accepted, revision);
            else m_provider->RequestExplicitPages(accepted, revision);
        }
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
        rememberFoldScrollAnchor();
        updateOverviewBar();
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

    std::optional<std::uint64_t> HexCanvas::visibleCenterAddress() const
    {
        if (!m_hasSpace) return std::nullopt;
        const auto lastRow = std::min(m_firstRow + paintRowCount() - 1ULL, m_viewport.RowCount() - 1ULL);
        const auto span = m_viewport.RowValidSpan(m_firstRow + (lastRow - m_firstRow) / 2);
        return span ? std::optional<std::uint64_t>(span->first + (span->last - span->first) / 2) : std::nullopt;
    }

    std::vector<HexCanvas::AddressRange> HexCanvas::visibleAddressSpans() const
    {
        std::vector<AddressRange> spans;
        if (!m_hasSpace) return spans;
        const auto count = std::min(paintRowCount(), m_viewport.RowCount() - m_firstRow);
        for (std::uint64_t row = 0; row < count; ++row)
        {
            const auto span = m_viewport.RowValidSpan(m_firstRow + row);
            if (!span) continue;
            if (!spans.empty() && span->first > spans.back().last && span->first - spans.back().last == 1)
                spans.back().last = span->last;
            else spans.push_back(*span);
        }
        return spans;
    }

    void HexCanvas::rememberFoldScrollAnchor(bool preferReadable)
    {
        m_foldScrollAnchor.reset();
        if (!m_hasSpace || !m_foldUnknownRegions) return;
        const auto top = m_viewport.RowValidSpan(m_firstRow);
        if (!top) return;
        m_foldScrollAnchor = FoldScrollAnchor{top->first, 0, preferReadable};
        const auto rows = std::min(fullVisibleRows(), m_viewport.RowCount() - m_firstRow);
        if (preferReadable)
        {
            // A folding toggle preserves the content being viewed. In a sparse
            // view the old caret can also be visible at a remote unknown endpoint;
            // following it while unfolding would leave the real fragment behind.
            // This bounded scan runs only for an explicit toggle, never per paint.
            for (std::uint64_t row = 0; row < rows; ++row)
            {
                const auto span = m_viewport.RowValidSpan(m_firstRow + row);
                if (!span) continue;
                for (auto address = span->first;; ++address)
                {
                    if (m_viewport.PeekByte(address).state == ByteState::Valid
                        || (m_overlay && m_overlay->HasPendingInRange(address, address)))
                    {
                        m_foldScrollAnchor = FoldScrollAnchor{address, row, true};
                        return;
                    }
                    if (address == span->last) break;
                }
            }
        }
        if (m_foldNavigationAddress)
        {
            const auto row = m_viewport.RowOfAddress(*m_foldNavigationAddress);
            const auto span = row ? m_viewport.RowValidSpan(*row) : std::nullopt;
            if (row && span && *row >= m_firstRow && *row - m_firstRow < rows
                && *m_foldNavigationAddress >= span->first && *m_foldNavigationAddress <= span->last)
            {
                m_foldScrollAnchor = FoldScrollAnchor{*m_foldNavigationAddress, *row - m_firstRow, true};
                return;
            }
        }
        // A visible caret is already protected by the fold model. Otherwise pin
        // a readable row, so newly folded leading placeholders cannot move it.
        const auto caret = m_viewport.GetSelection().caret;
        const auto caretRow = m_viewport.RowOfAddress(caret);
        if (!preferReadable && caretRow && *caretRow >= m_firstRow && *caretRow - m_firstRow < rows)
        {
            m_foldScrollAnchor = FoldScrollAnchor{caret, *caretRow - m_firstRow, true};
            return;
        }
        for (std::uint64_t row = 0; row < rows; ++row)
        {
            const auto span = m_viewport.RowValidSpan(m_firstRow + row);
            if (!span) continue;
            if (m_viewport.PeekByte(span->first).state == ByteState::Valid
                || (m_overlay && m_overlay->HasPendingInRange(span->first, span->last)))
            {
                m_foldScrollAnchor = FoldScrollAnchor{span->first, row, true};
                return;
            }
        }
    }

    void HexCanvas::syncFoldGeometry()
    {
        if (!m_hasSpace) return;
        if (m_foldGeometryRevision == m_viewport.FoldRevision())
        {
            if (knownScrollScale()) {
                // A boundary row can become readable without changing any
                // folds. Its accepted bytes must still update the known axis.
                const QPointer<HexCanvas> alive(this);
                const auto revision = sourceRevision();
                syncScrollBars();
                if (alive && sourceRevision() == revision) notifyVisibleRange();
                return;
            }
            // A readable page may have just arrived without changing the fold
            // index. Pin it before the next unreadable-page completion folds above it.
            rememberFoldScrollAnchor();
            return;
        }
        const auto first = m_notifiedOnce ? m_lastNotifiedFirst : m_viewport.FirstAddress();
        const auto anchor = m_foldScrollAnchor.value_or(FoldScrollAnchor{first, 0});
        auto row = m_viewport.RowOfAddress(anchor.address).value_or(0);
        auto span = m_viewport.RowValidSpan(row);
        if (anchor.keepVisible && m_foldUnknownRegions && span
            && (anchor.address < span->first || anchor.address > span->last))
        {
            // Refresh/toggle/eviction may turn the viewed data into dots. Keep
            // that address present so the normal visible-page planner reloads it.
            m_viewport.RevealAddress(anchor.address);
            row = m_viewport.RowOfAddress(anchor.address).value_or(0);
            span = m_viewport.RowValidSpan(row);
        }
        m_foldGeometryRevision = m_viewport.FoldRevision();
        if (span && (anchor.address < span->first || anchor.address > span->last) && m_foldScrollUp && row > 0)
            --row; // All-unknown view: keep moving toward the preceding boundary.
        m_firstRow = m_keepScrollEnd ? scrollEndFirstRow()
            : std::min(row - std::min(row, anchor.screenRow), maxFirstRow());
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        syncScrollBars();
        if (alive && sourceRevision() == revision) notifyVisibleRange();
    }

    void HexCanvas::setFoldUnknownRegions(bool enabled)
    {
        if (m_foldUnknownRegions == enabled) return;
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        if (!enabled) rememberFoldScrollAnchor(true);
        m_foldUnknownRegions = enabled;
        m_keepScrollEnd = false;
        if (enabled) rememberFoldScrollAnchor(true);
        const auto anchor = m_foldScrollAnchor;
        if (anchor && anchor->keepVisible) m_foldNavigationAddress = anchor->address;
        m_foldFetchBudget = 16;
        cancelUniformBoundarySearch();
        m_viewport.SetFoldUnknown(enabled);
        if (m_provider) m_provider->SetUnknownFoldingEnabled(enabled);
        if (!alive || sourceRevision() != revision) return;
        syncFoldGeometry();
        if (!alive || sourceRevision() != revision) return;
        // An all-readable source may not change FoldRevision, but the selected
        // scrollbar/overview scale still changed with the checkbox.
        syncScrollBars();
        if (!alive || sourceRevision() != revision) return;
        viewport()->update();
        requestVisiblePages();
        if (!alive || sourceRevision() != revision) return;
        if (anchor && anchor->keepVisible)
        {
            const auto state = m_viewport.PeekByte(anchor->address).state;
            if (state == ByteState::NotLoaded || state == ByteState::Pending)
                requestAddressRange(anchor->address, anchor->address, RangeReadPurpose::ExplicitRead);
        }
    }

    void HexCanvas::deliverUnreadableExtent(std::uint64_t first, std::uint64_t last, std::uint64_t revision)
    {
        if (!m_hasSpace || !m_foldUnknownRegions || revision != sourceRevision() || first > last) return;
        const QPointer<HexCanvas> alive(this);
        m_viewport.NoteUnreadableRange(first, last);
        syncFoldGeometry();
        if (!alive || revision != sourceRevision()) return;
        viewport()->update();
        scheduleContentChanged();
        requestVisiblePages();
    }

    void HexCanvas::setUniformBoundaryNavigationEnabled(bool enabled)
    {
        if (m_uniformNavigationEnabled == enabled) return;
        m_uniformNavigationEnabled = enabled;
        if (enabled && !m_uniformUpperButton)
        {
            const auto make = [this](bool upper) {
                auto* button = new QToolButton(viewport());
                button->setFont(QApplication::font());
                button->setObjectName(upper ? QStringLiteral("memwb_upper_bound") : QStringLiteral("memwb_lower_bound"));
                button->setIcon(QIcon(upper ? QStringLiteral(":/Icon/memwb_upper_bound.svg") : QStringLiteral(":/Icon/memwb_lower_bound.svg")));
                button->setToolButtonStyle(Qt::ToolButtonIconOnly);
                button->setText(ks::i18n::sourceText(upper ? QStringLiteral("上界") : QStringLiteral("下界")));
                button->setAccessibleName(button->text());
                button->setToolTip(ks::i18n::sourceText(upper
                    ? QStringLiteral("查找当前可读纯色区块的上界并居中；仅点击时读取，再次点击可停止")
                    : QStringLiteral("查找当前可读纯色区块的下界并居中；仅点击时读取，再次点击可停止")));
                KswordTheme::ApplyCompactIconButtonMetrics(button);
                button->hide();
                connect(button, &QToolButton::clicked, this, [this, upper]() { startUniformBoundarySearch(upper); });
                return button;
            };
            m_uniformUpperButton = make(true);
            m_uniformLowerButton = make(false);
        }
        if (!enabled) { cancelUniformBoundarySearch(); updateUniformButtons(false, 0); }
        viewport()->update();
    }

    void HexCanvas::updateUniformButtons(bool uniform, std::uint8_t value)
    {
        if (!m_uniformUpperButton) return;
        uniform = uniform && m_uniformNavigationEnabled;
        const bool wanted = uniform || m_uniformSearch.has_value();
        const bool unchanged = m_uniformScreen == uniform && (!uniform || m_uniformValue == value)
            && m_uniformButtonsWanted == wanted
            && m_uniformButtonViewport == viewport()->size();
        m_uniformScreen = uniform;
        m_uniformButtonsWanted = wanted;
        m_uniformValue = value;
        if (unchanged || m_uniformUpdateQueued) return;
        m_uniformUpdateQueued = true;
        const QPointer<HexCanvas> alive(this);
        QTimer::singleShot(0, this, [alive]() {
            if (!alive) return;
            alive->m_uniformUpdateQueued = false;
            alive->m_uniformButtonViewport = alive->viewport()->size();
            const bool visible = alive->m_uniformNavigationEnabled && (alive->m_uniformScreen || alive->m_uniformSearch.has_value());
            // Icon-only controls have shared fixed metrics. Resolved inherited
            // fonts must not enqueue setFont/resize work on every painted frame.
            const int x = std::max(0, alive->viewport()->width() - alive->m_uniformUpperButton->width() - 8);
            const int top = alive->m_layout.headerHeight + 6;
            const int bottom = alive->viewport()->height() - alive->m_uniformLowerButton->height() - 6;
            const bool fits = bottom >= top + alive->m_uniformUpperButton->height() + 4;
            alive->m_uniformUpperButton->move(x, top);
            if (!alive) return;
            alive->m_uniformLowerButton->move(x, std::max(top, bottom));
            if (!alive) return;
            alive->m_uniformUpperButton->setVisible(visible && fits);
            if (!alive) return;
            alive->m_uniformLowerButton->setVisible(visible && fits);
        });
    }

    void HexCanvas::cancelUniformBoundarySearch()
    {
        if (!m_uniformSearch) return;
        m_uniformSearch.reset();
        if (m_uniformUpperButton)
        {
            m_uniformUpperButton->setText(ks::i18n::sourceText(QStringLiteral("上界")));
            m_uniformLowerButton->setText(ks::i18n::sourceText(QStringLiteral("下界")));
            m_uniformUpperButton->setAccessibleName(m_uniformUpperButton->text());
            m_uniformLowerButton->setAccessibleName(m_uniformLowerButton->text());
            m_uniformUpperButton->setIcon(QIcon(QStringLiteral(":/Icon/memwb_upper_bound.svg")));
            m_uniformLowerButton->setIcon(QIcon(QStringLiteral(":/Icon/memwb_lower_bound.svg")));
        }
        updateUniformButtons(m_uniformScreen, m_uniformValue);
    }

    void HexCanvas::boundaryReadFailed(const QString& reason)
    {
        if (!m_uniformSearch) return;
        cancelUniformBoundarySearch();
        if (!reason.isEmpty()) emit boundaryNavigationMessage(reason, true);
    }

    void HexCanvas::startUniformBoundarySearch(bool upper)
    {
        if (m_uniformSearch && m_uniformSearch->upper == upper)
        {
            cancelUniformBoundarySearch();
            emit boundaryNavigationMessage(ks::i18n::sourceText(QStringLiteral("已停止纯色边界查找")), false);
            return;
        }
        if (!m_uniformScreen || !m_hasSpace) return;
        cancelUniformBoundarySearch();
        const auto visible = visibleAddressRange();
        if (!visible) return;
        const auto origin = upper ? visible->first : visible->last;
        m_uniformSearch = UniformSearch{upper, m_uniformValue, sourceRevision(), origin, origin, 0};
        const QPointer<HexCanvas> alive(this);
        auto* activeButton = upper ? m_uniformUpperButton : m_uniformLowerButton;
        activeButton->setText(ks::i18n::sourceText(QStringLiteral("停止")));
        activeButton->setAccessibleName(activeButton->text());
        activeButton->setIcon(QIcon(QStringLiteral(":/Icon/process_stop.svg")));
        emit boundaryNavigationMessage(ks::i18n::sourceText(upper
            ? QStringLiteral("正在查找纯色区域上界…") : QStringLiteral("正在查找纯色区域下界…")), false);
        if (alive) advanceUniformBoundarySearch();
    }

    void HexCanvas::advanceUniformBoundarySearch()
    {
        if (!m_uniformSearch || m_uniformAdvanceQueued) return;
        m_uniformAdvanceQueued = true;
        const QPointer<HexCanvas> alive(this);
        QTimer::singleShot(0, this, [alive]() {
            if (!alive) return;
            alive->m_uniformAdvanceQueued = false;
            alive->scanUniformBoundaryStep();
        });
    }

    void HexCanvas::scanUniformBoundaryStep()
    {
        if (!m_uniformSearch) return;
        if (m_uniformSearch->revision != sourceRevision()) { cancelUniformBoundarySearch(); return; }
        constexpr std::uint64_t stepBudget = 16384; // Bounded CPU work; no whole-buffer scan in paint/scroll.
        const QPointer<HexCanvas> alive(this);
        const auto finish = [this](std::uint64_t address) {
            const QPointer<HexCanvas> alive(this);
            const bool upper = m_uniformSearch->upper;
            const auto revision = m_uniformSearch->revision;
            const auto width = m_viewport.BytesPerRow();
            if (upper && address % width != 0 && width - address % width <= m_viewport.LastAddress() - address)
                address += width - address % width;
            else if (!upper && address % width != width - 1 && address / width > m_viewport.FirstAddress() / width)
                address = address - address % width - width;
            cancelUniformBoundarySearch();
            scrollToAddress(address, ScrollAlign::Center);
            if (alive && sourceRevision() == revision) emit boundaryNavigationMessage(ks::i18n::sourceText(upper
                ? QStringLiteral("已定位当前可读纯色区块的上界") : QStringLiteral("已定位当前可读纯色区块的下界")), false);
        };
        for (std::uint64_t count = 0; count < stepBudget; ++count)
        {
            auto& search = *m_uniformSearch;
            const auto core = resolveCore(search.cursor);
            if (core.state == ByteState::NotLoaded || core.state == ByteState::Pending)
            {
                const auto first = search.upper ? search.cursor - std::min<std::uint64_t>(search.cursor - m_viewport.FirstAddress(), 65535) : search.cursor;
                const auto last = search.upper ? search.cursor : search.cursor + std::min<std::uint64_t>(m_viewport.LastAddress() - search.cursor, 65535);
                requestAddressRange(first, last, RangeReadPurpose::ExplicitRead);
                return; // Page completion resumes this exact cursor; no polling timer while IO is pending.
            }
            if (core.state == ByteState::Unreadable || !core.hasValue || core.value != search.value)
            {
                if (search.cursor == search.origin)
                {
                    boundaryReadFailed(ks::i18n::sourceText(QStringLiteral("当前数据已变化，请重新查找纯色边界")));
                    return;
                }
                finish(search.upper ? search.cursor + 1 : search.cursor - 1);
                return;
            }
            ++search.scanned;
            if (search.upper ? search.cursor == m_viewport.FirstAddress() : search.cursor == m_viewport.LastAddress())
            {
                finish(search.cursor);
                return;
            }
            if (search.upper) --search.cursor; else ++search.cursor;
        }
        if (alive && m_uniformSearch) advanceUniformBoundarySearch();
    }

}
