// HexCanvas.Paint.cpp
// 作用：HexCanvas 的绘制——调色板、表头、行、插入点外框，以及"所见即所绘"的单元格状态与悬停提示。
//
// 主题纪律：
// - 绘制路径只用 theme.h 的静态 QColor 访问器，并且在每次 paintEvent 里现取，不缓存颜色，
//   不用 palette(...) 样式串（那是 QSS 专有扩展，QPainter 路径会静默丢弃）。
// - 变化着色用主题强调色按固定比例混入表面色，深浅两套主题都经 EnsureTextContrast 校准文字色。

#include "HexCanvas.h"
#include "HexCanvasFormat.h"

#include "../../theme.h"

#include <QPainter>
#include <QPen>
#include <QPointer>
#include <QStringList>
#include <QTimer>

#include <algorithm>

namespace ks::ui
{
    // PaintPalette：一次绘制用到的全部颜色。每次 paintEvent 开头重新构造。
    struct HexCanvas::PaintPalette
    {
        QColor surface;             // 视口底色
        QColor surfaceAlt;          // 表头底色
        QColor border;              // 分隔线
        QColor borderStrong;        // 非活动面板的插入点外框
        QColor text;                // 正文
        QColor textSecondary;       // 次要文字（地址、列偏移、00 字节）
        QColor textDisabled;        // 禁用文字（未加载、不可读、不可见字符）
        QColor accent;              // 主题强调色
        QColor headerCaret;         // 表头里插入点所在列的文字色
        QColor selActiveBg;         // 活动面板选区底色
        QColor selActiveFg;         // 活动面板选区文字色
        QColor selInactiveBg;       // 非活动面板选区（镜像）底色
        QColor selInactiveFg;       // 非活动面板选区文字色
        QColor pendingBg;           // 暂存补丁底色（暖色）
        QColor pendingFg;           // 暂存补丁文字色
        QColor externalBg;          // 外部变化底色（冷色）
        QColor externalFg;          // 外部变化文字色
        QColor selfBg;              // 自己写入底色（淡色）
        QColor selfFg;              // 自己写入文字色
        std::vector<QColor> layerBg;    // 各高亮层底色，与 m_layerSnapshot 同序
        std::vector<QColor> layerFg;    // 各高亮层文字色，与 m_layerSnapshot 同序
    };

    // 构造本次绘制的调色板。
    // 传出：调色板。所有颜色此刻现取，主题切换后下一次绘制自然生效。
    HexCanvas::PaintPalette HexCanvas::makePalette() const
    {
        PaintPalette palette;

        // 中性色：表面、边框、文字三族。
        palette.surface = KswordTheme::SurfaceColor();
        palette.surfaceAlt = KswordTheme::SurfaceAltColor();
        palette.border = KswordTheme::BorderColor();
        palette.borderStrong = KswordTheme::BorderStrongColor();
        palette.text = KswordTheme::TextPrimaryColor();
        palette.textSecondary = KswordTheme::TextSecondaryColor();
        palette.textDisabled = KswordTheme::TextDisabledColor();
        palette.accent = KswordTheme::PrimaryAccentColor();
        palette.headerCaret = KswordTheme::EnsureTextContrast(palette.accent, palette.surfaceAlt);

        // 选区：活动面板用编辑器选区色（最醒目），非活动面板把它按固定比例淡化后混入表面色。
        const QColor selection = KswordTheme::EditorSelectionColor();
        palette.selActiveBg = selection;
        palette.selActiveFg = KswordTheme::OnAccentColor(selection);
        palette.selInactiveBg = KswordTheme::BlendColors(palette.surface, selection, 120);
        palette.selInactiveFg = KswordTheme::EnsureTextContrast(palette.text, palette.selInactiveBg);

        // 变化种类：橙（暖）= 暂存，青（冷）= 外部变化，绿（淡）= 自己写入；
        // 混入权重固定，保证深浅主题下都能和 Unchanged 区分开。
        palette.pendingBg = KswordTheme::BlendColors(
            palette.surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Orange), 120);
        palette.pendingFg = KswordTheme::EnsureTextContrast(palette.text, palette.pendingBg);
        palette.externalBg = KswordTheme::BlendColors(
            palette.surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Cyan), 105);
        palette.externalFg = KswordTheme::EnsureTextContrast(palette.text, palette.externalBg);
        palette.selfBg = KswordTheme::BlendColors(
            palette.surface, KswordTheme::AccentColor(KswordTheme::AccentRole::Green), 70);
        palette.selfFg = KswordTheme::EnsureTextContrast(palette.text, palette.selfBg);

        // 通用高亮层：调用方给的颜色按其 alpha 缩放权重后混入表面色。
        palette.layerBg.reserve(m_layerSnapshot.size());
        palette.layerFg.reserve(m_layerSnapshot.size());
        for (const auto& entry : m_layerSnapshot)
        {
            const QColor layerColor = entry.second->color;
            const int weight = std::clamp(static_cast<int>(150.0 * layerColor.alphaF()), 0, 255);
            const QColor background = KswordTheme::BlendColors(palette.surface, layerColor.toRgb(), weight);
            palette.layerBg.push_back(background);
            palette.layerFg.push_back(KswordTheme::EnsureTextContrast(palette.text, background));
        }
        return palette;
    }

    // 判定一个地址落在哪个高亮层。
    // 传入：地址；传出：层在快照里的下标（高层优先），没有命中返回 -1。
    int HexCanvas::findLayerIndex(std::uint64_t address) const
    {
        for (std::size_t index = 0; index < m_layerSnapshot.size(); ++index)
        {
            // ranges：已排序合并的区间；upper_bound 找到第一个起点大于地址的区间，前一个才是候选。
            const std::vector<AddressRange>& ranges = m_layerSnapshot[index].second->ranges;
            auto it = std::upper_bound(
                ranges.begin(),
                ranges.end(),
                address,
                [](std::uint64_t value, const AddressRange& range) { return value < range.first; });
            if (it == ranges.begin())
            {
                continue;
            }
            --it;
            if (address <= it->last)
            {
                return static_cast<int>(index);
            }
        }
        return -1;
    }

    // 解析一个地址的轻量显示状态（无字符串分配，不改动缓存 LRU）。
    // 传入：地址；传出：CellCore。有暂存补丁的字节显示补丁值，且视为已读到。
    HexCanvas::CellCore HexCanvas::resolveCore(std::uint64_t address) const
    {
        CellCore core;
        core.inSpace = m_hasSpace && m_viewport.ContainsAddress(address);
        if (!core.inSpace)
        {
            return core;
        }

        // 先看页缓存：Valid 才有值，其余三种状态值恒为 0 且不得当数据显示。
        const ksword::memwb::HexViewport::ByteLookup lookup = m_viewport.PeekByte(address);
        core.state = lookup.state;
        if (lookup.state == ByteState::Valid)
        {
            core.hasValue = true;
            core.value = lookup.value;
        }

        // 再看暂存叠加层：补丁值覆盖缓存值；其余变化种类只在"有值可显示"时才着色。
        if (m_overlay != nullptr)
        {
            const ChangeKind kind = m_overlay->ChangeKind(address);
            if (kind == ChangeKind::Pending)
            {
                const std::optional<std::uint8_t> effective = m_overlay->EffectiveByte(address);
                if (effective.has_value())
                {
                    core.hasValue = true;
                    core.value = *effective;
                    core.state = ByteState::Valid;
                }
            }
            if (core.hasValue && kind != ChangeKind::Unreadable)
            {
                core.change = kind;
            }
        }
        core.layerIndex = findLayerIndex(address);
        return core;
    }

    // 刷新可见页在 LRU 里的新旧：绘制本身用只读查询，所以每帧对可见页各点一次名，
    // 防止刚预取进来的页把仍在屏幕上的老页挤出缓存。
    // 传入：可见范围首尾地址（都在空间内）。
    void HexCanvas::touchVisiblePages(std::uint64_t firstAddress, std::uint64_t lastAddress)
    {
        const std::uint64_t lastPage = ksword::memwb::HexViewport::PageStartOf(lastAddress);
        std::uint64_t page = ksword::memwb::HexViewport::PageStartOf(firstAddress);
        while (true)
        {
            // probe：该页内一个确定在空间内的地址（首页的页起点可能早于空间起点）。
            const std::uint64_t probe = std::max(page, firstAddress);
            m_viewport.LookupByte(probe);
            if (page >= lastPage)
            {
                break;
            }
            page += ksword::memwb::HexViewport::kPageBytes;
        }
    }

    // 绘制入口。
    void HexCanvas::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);

        // 每次绘制现取调色板并整面铺底，WA_OpaquePaintEvent 保证不会残留旧内容。
        QPainter painter(viewport());
        const PaintPalette palette = makePalette();
        painter.fillRect(viewport()->rect(), palette.surface);
        painter.setFont(font());
        m_lastPaintedRows = 0;
        if (!m_hasSpace)
        {
            updateUniformButtons(false, 0);
            return;
        }

        // 可见行范围：从首行起最多 paintRowCount 行，夹取到末行。
        const std::uint64_t rowCount = m_viewport.RowCount();
        const std::uint64_t rowsToPaint = std::min(paintRowCount(), rowCount - m_firstRow);
        const std::optional<AddressRange> topSpan = m_viewport.RowValidSpan(m_firstRow);
        const std::optional<AddressRange> bottomSpan = m_viewport.RowValidSpan(m_firstRow + (rowsToPaint - 1ULL));
        if (topSpan.has_value() && bottomSpan.has_value())
        {
            if (!m_viewport.HasFoldedRows()) touchVisiblePages(topSpan->first, bottomSpan->last);
            else
            {
                // Never walk the physical span across a folded multi-terabyte hole.
                std::optional<std::uint64_t> lastTouched;
                for (std::uint64_t row = 0; row < rowsToPaint; ++row)
                {
                    const auto span = m_viewport.RowValidSpan(m_firstRow + row);
                    if (!span) continue;
                    const auto firstPage = ksword::memwb::HexViewport::PageStartOf(span->first);
                    const auto lastPage = ksword::memwb::HexViewport::PageStartOf(span->last);
                    if (!lastTouched || *lastTouched != firstPage) touchVisiblePages(span->first, span->first);
                    if (lastPage != firstPage) touchVisiblePages(span->last, span->last);
                    lastTouched = lastPage;
                }
            }
        }
        UniformPaintProbe uniform;
        uniform.uniform = rowsToPaint >= fullVisibleRows();

        // 行区域：裁剪到表头之下，并按横向滚动量平移；整个内容坐标系从这里开始。
        const int viewWidth = viewport()->width();
        const int viewHeight = viewport()->height();
        const std::optional<AddressRange> selection = m_viewport.SelectedRange();
        painter.save();
        painter.setClipRect(0, m_layout.headerHeight, viewWidth, std::max(0, viewHeight - m_layout.headerHeight));
        painter.translate(-m_hOffset, 0);
        for (std::uint64_t index = 0; index < rowsToPaint; ++index)
        {
            const int rowTop = m_layout.headerHeight + static_cast<int>(index) * m_layout.rowHeight;
            paintRow(painter, palette, m_firstRow + index, rowTop, selection,
                m_uniformNavigationEnabled ? &uniform : nullptr);
            ++m_lastPaintedRows;
        }
        paintCaretFrames(painter, palette);
        painter.restore();

        // 表头最后画，盖住行区域顶部的任何溢出。
        const std::optional<std::uint32_t> caretColumn = m_viewport.ColumnOfAddress(m_viewport.GetSelection().caret);
        paintHeader(painter, palette, viewWidth, caretColumn.has_value() ? *caretColumn : 0U);
        updateUniformButtons(m_uniformNavigationEnabled && uniform.uniform && uniform.seen, uniform.value);

        // 可见页被 LRU 淘汰后（单元格回到"未加载"且没有在途），排队一次补读。
        if (m_provider != nullptr && !m_refetchQueued && topSpan.has_value() && bottomSpan.has_value())
        {
            const ksword::memwb::HexViewport::ByteLookup topProbe = m_viewport.PeekByte(topSpan->first);
            const ksword::memwb::HexViewport::ByteLookup bottomProbe = m_viewport.PeekByte(bottomSpan->last);
            if (topProbe.state == ByteState::NotLoaded || bottomProbe.state == ByteState::NotLoaded)
            {
                m_refetchQueued = true;
                QPointer<HexCanvas> guard(this);
                QTimer::singleShot(0, this, [guard]() {
                    if (guard != nullptr)
                    {
                        guard->m_refetchQueued = false;
                        guard->requestVisiblePages();
                    }
                });
            }
        }
    }

    // 绘制表头：列偏移（00 01 …）与 ASCII 列的十六进制位序，以及两条竖向分隔线。
    // 传入：画笔、调色板、视口宽度、插入点所在列（该列的表头文字用强调色）。
    void HexCanvas::paintHeader(QPainter& painter, const PaintPalette& palette, int viewWidth, std::uint64_t caretColumn) const
    {
        // 表头底色与下边框。
        painter.fillRect(0, 0, viewWidth, m_layout.headerHeight, palette.surfaceAlt);
        painter.setPen(palette.border);
        painter.drawLine(0, m_layout.headerHeight - 1, viewWidth, m_layout.headerHeight - 1);

        painter.save();
        painter.translate(-m_hOffset, 0);

        // 两条竖向分隔线：地址列|十六进制区，十六进制区|ASCII 区，贯穿表头与行区域。
        const int viewHeight = viewport()->height();
        const int addrDivider = m_layout.addrX + m_layout.addrWidth + m_layout.charWidth;
        const int asciiDivider = m_layout.asciiX - m_layout.charWidth;
        painter.setPen(palette.border);
        painter.drawLine(addrDivider, 0, addrDivider, viewHeight);
        painter.drawLine(asciiDivider, 0, asciiDivider, viewHeight);

        // 十六进制列偏移：直接复用 256 个字节值的缓存文字（列号 < 64）。
        const int columns = static_cast<int>(m_viewport.BytesPerRow());
        const int textTop = 3;
        for (int column = 0; column < columns; ++column)
        {
            const bool isCaretColumn = static_cast<std::uint64_t>(column) == caretColumn;
            painter.setPen(isCaretColumn ? palette.headerCaret : palette.textSecondary);
            painter.drawStaticText(
                QPointF(m_layout.hexX + m_layout.cellX[column], textTop),
                m_hexTexts[column]);
        }

        // ASCII 列的列号：只画低 4 位的一位十六进制数字。
        const int baseline = textTop + m_layout.ascent;
        for (int column = 0; column < columns; ++column)
        {
            const bool isCaretColumn = static_cast<std::uint64_t>(column) == caretColumn;
            painter.setPen(isCaretColumn ? palette.headerCaret : palette.textSecondary);
            const QString digit = QString::number(column % 16, 16).toUpper();
            painter.drawText(QPointF(m_layout.asciiX + column * m_layout.charWidth, baseline), digit);
        }
        painter.restore();
    }

    // 绘制一行：地址、十六进制单元格、ASCII 单元格。
    // 传入：画笔（已平移到内容坐标）、调色板、行号、行顶 y、选区。补空位处不画任何字节。
    void HexCanvas::paintRow(
        QPainter& painter,
        const PaintPalette& palette,
        std::uint64_t row,
        int rowTop,
        const std::optional<AddressRange>& selection, UniformPaintProbe* probe) const
    {
        const std::optional<std::uint64_t> start = m_viewport.RowStartAddress(row);
        const std::optional<AddressRange> span = m_viewport.RowValidSpan(row);
        if (!start.has_value() || !span.has_value())
        {
            return;
        }

        // 地址列：行首地址（首行含补空位时仍显示对齐后的行首，与列头一致）。
        const std::uint64_t caret = m_viewport.GetSelection().caret;
        const bool caretInRow = caret >= span->first && caret <= span->last;
        const QString addressText = QString::number(static_cast<qulonglong>(*start), 16)
            .toUpper()
            .rightJustified(m_layout.addrDigits, QLatin1Char('0'));
        const int textTop = rowTop + 1;
        painter.setPen(caretInRow ? palette.text : palette.textSecondary);
        painter.drawText(QPointF(m_layout.addrX, textTop + m_layout.ascent), addressText);

        // 有效列范围：补空位列不参与任何绘制。
        const int firstColumn = static_cast<int>(span->first - *start);
        const int lastColumn = static_cast<int>(span->last - *start);
        if (probe && (firstColumn != 0 || lastColumn + 1 != static_cast<int>(m_viewport.BytesPerRow())))
            probe->uniform = false;

        // cores/selected：本行每一列的轻量状态与是否在选区内。
        CellCore cores[64];
        bool selected[64] = {};
        for (int column = firstColumn; column <= lastColumn; ++column)
        {
            const std::uint64_t address = *start + static_cast<std::uint64_t>(column);
            cores[column] = resolveCore(address);
            if (probe && probe->uniform)
            {
                const auto& core = cores[column];
                if (core.state != ByteState::Valid || !core.hasValue) probe->uniform = false;
                else if (!probe->seen) { probe->value = core.value; probe->seen = true; }
                else if (probe->value != core.value) probe->uniform = false;
            }
            selected[column] = selection.has_value() && address >= selection->first && address <= selection->last;
        }

        // 两个面板各自算底色与文字色：活动面板的选区更醒目。
        const bool hexActive = m_viewport.Pane() == ActivePane::Hex;
        QColor hexBg[64];
        QColor hexFg[64];
        QColor asciiBg[64];
        QColor asciiFg[64];
        for (int column = firstColumn; column <= lastColumn; ++column)
        {
            const CellCore& core = cores[column];

            // 底色优先级：选区 > 高亮层 > 变化种类。三者都没有则无底色。
            const auto pickBackground = [&](bool paneActive, QColor& bgOut, QColor& fgOut) -> bool {
                if (selected[column])
                {
                    bgOut = paneActive ? palette.selActiveBg : palette.selInactiveBg;
                    fgOut = paneActive ? palette.selActiveFg : palette.selInactiveFg;
                    return true;
                }
                if (core.layerIndex >= 0)
                {
                    bgOut = palette.layerBg[static_cast<std::size_t>(core.layerIndex)];
                    fgOut = palette.layerFg[static_cast<std::size_t>(core.layerIndex)];
                    return true;
                }
                switch (core.change)
                {
                case ChangeKind::Pending:
                    bgOut = palette.pendingBg;
                    fgOut = palette.pendingFg;
                    return true;
                case ChangeKind::ExternalChange:
                    bgOut = palette.externalBg;
                    fgOut = palette.externalFg;
                    return true;
                case ChangeKind::SelfWritten:
                    bgOut = palette.selfBg;
                    fgOut = palette.selfFg;
                    return true;
                default:
                    return false;
                }
            };

            // 十六进制面板：无底色时，没值用禁用色，00 用次要色，其余正文色。
            if (!pickBackground(hexActive, hexBg[column], hexFg[column]))
            {
                if (!core.hasValue)
                {
                    hexFg[column] = palette.textDisabled;
                }
                else if (core.value == 0)
                {
                    hexFg[column] = palette.textSecondary;
                }
                else
                {
                    hexFg[column] = palette.text;
                }
            }

            // ASCII 面板：无底色时，没值与不可见字符用禁用色，可见字符正文色。
            if (!pickBackground(!hexActive, asciiBg[column], asciiFg[column]))
            {
                const bool printable = core.hasValue && hexcanvas_format::IsPrintableAscii(core.value);
                asciiFg[column] = printable ? palette.text : palette.textDisabled;
            }

            // 半字节预览：插入点字节显示"高半字节 + _"，用暂存色提示"尚未提交"。
            if (m_nibbleActive && *start + static_cast<std::uint64_t>(column) == m_nibbleAddress)
            {
                hexBg[column] = palette.pendingBg;
                hexFg[column] = palette.pendingFg;
            }
        }

        // ---- 十六进制面板：先铺底色，再写文字 ----
        const int padding = m_layout.charWidth / 2;
        for (int column = firstColumn; column <= lastColumn; ++column)
        {
            if (!hexBg[column].isValid())
            {
                continue;
            }
            // 单元格底色向左右各外扩半个字符；与左邻同色时直接接到左邻右缘，让选区在分组缝处也连成一条带。
            const int cellLeft = m_layout.hexX + m_layout.cellX[column];
            int left = cellLeft - padding;
            const int right = cellLeft + 2 * m_layout.charWidth + padding;
            if (column > firstColumn && hexBg[column - 1].isValid() && hexBg[column - 1] == hexBg[column])
            {
                left = m_layout.hexX + m_layout.cellX[column - 1] + 2 * m_layout.charWidth + padding;
            }
            painter.fillRect(left, rowTop, right - left, m_layout.rowHeight, hexBg[column]);
        }
        const QFontMetrics metrics(painter.font());
        for (int column = firstColumn; column <= lastColumn; ++column)
        {
            const CellCore& core = cores[column];
            const int cellLeft = m_layout.hexX + m_layout.cellX[column];
            painter.setPen(hexFg[column]);

            // 半字节预览用临时字符串直接绘制，其余走缓存文字。
            if (m_nibbleActive && *start + static_cast<std::uint64_t>(column) == m_nibbleAddress)
            {
                const QString preview = QString::number(m_nibbleHigh, 16).toUpper() + QLatin1Char('_');
                painter.drawText(QPointF(cellLeft, textTop + metrics.ascent()), preview);
            }
            else if (core.hasValue)
            {
                painter.drawStaticText(QPointF(cellLeft, textTop), m_hexTexts[core.value]);
            }
            else if (core.state == ByteState::Unreadable)
            {
                painter.drawStaticText(QPointF(cellLeft, textTop), m_unreadableHexText);
            }
            else
            {
                painter.drawStaticText(QPointF(cellLeft, textTop), m_loadingHexText);
            }
        }

        // ---- ASCII 面板：相邻同色单元格天然相连 ----
        for (int column = firstColumn; column <= lastColumn; ++column)
        {
            if (asciiBg[column].isValid())
            {
                painter.fillRect(
                    m_layout.asciiX + column * m_layout.charWidth,
                    rowTop,
                    m_layout.charWidth,
                    m_layout.rowHeight,
                    asciiBg[column]);
            }
        }
        for (int column = firstColumn; column <= lastColumn; ++column)
        {
            const CellCore& core = cores[column];
            const QPointF origin(m_layout.asciiX + column * m_layout.charWidth, textTop);
            painter.setPen(asciiFg[column]);
            if (core.hasValue)
            {
                painter.drawStaticText(origin, m_asciiTexts[core.value]);
            }
            else if (core.state == ByteState::Unreadable)
            {
                painter.drawStaticText(origin, m_unreadableAsciiText);
            }
            else
            {
                painter.drawStaticText(origin, m_loadingAsciiText);
            }
        }
    }

    // 绘制插入点外框：两个面板各画一个，活动面板用强调色双线，另一个用弱色单线。
    // 传入：画笔（已平移到内容坐标）、调色板。插入点不在可见行时什么也不画。
    void HexCanvas::paintCaretFrames(QPainter& painter, const PaintPalette& palette) const
    {
        const std::uint64_t caret = m_viewport.GetSelection().caret;
        const bool hexActive = m_viewport.Pane() == ActivePane::Hex;
        const int padding = m_layout.charWidth / 2;

        painter.setBrush(Qt::NoBrush);
        for (int paneIndex = 0; paneIndex < 2; ++paneIndex)
        {
            const ActivePane pane = paneIndex == 0 ? ActivePane::Hex : ActivePane::Ascii;
            // cell：视口坐标的单元格矩形；加回横向滚动量得到内容坐标。
            QRect cell = cellRect(caret, pane);
            if (cell.isNull())
            {
                continue;
            }
            cell.translate(m_hOffset, 0);
            if (pane == ActivePane::Hex)
            {
                cell.adjust(-padding, 0, padding, 0);
            }

            const bool paneActive = (pane == ActivePane::Hex) == hexActive;
            if (paneActive)
            {
                // 活动面板：失去焦点时降为次要色，仍然保留位置提示。
                const QColor frameColor = hasFocus() ? palette.accent : palette.textSecondary;
                painter.setPen(QPen(frameColor, 1));
                painter.drawRect(cell.adjusted(0, 0, -1, -1));
                painter.drawRect(cell.adjusted(1, 1, -2, -2));
            }
            else
            {
                painter.setPen(QPen(palette.borderStrong, 1));
                painter.drawRect(cell.adjusted(0, 0, -1, -1));
            }
        }
    }

    // 查询地址的显示状态（诊断用，所见即所绘）。
    // 传入：地址；传出：CellState，不在空间内时 inSpace 为假且文字为空。
    HexCanvas::CellState HexCanvas::cellStateAt(std::uint64_t address) const
    {
        CellState state;
        const CellCore core = resolveCore(address);
        state.inSpace = core.inSpace;
        if (!core.inSpace)
        {
            return state;
        }

        state.byteState = core.state;
        state.hasValue = core.hasValue;
        state.value = core.value;
        state.change = core.change;
        const std::optional<AddressRange> selection = selectedRange();
        state.selected = selection.has_value() && address >= selection->first && address <= selection->last;
        state.isCaret = address == m_viewport.GetSelection().caret;
        if (core.layerIndex >= 0)
        {
            state.highlighted = true;
            state.highlightLayerId = m_layerSnapshot[static_cast<std::size_t>(core.layerIndex)].first;
        }
        state.nibblePreview = m_nibbleActive && address == m_nibbleAddress;

        // 文字：与 paintRow 的取字规则一一对应。
        if (state.nibblePreview)
        {
            state.hexText = QString::number(m_nibbleHigh, 16).toUpper() + QLatin1Char('_');
        }
        else if (core.hasValue)
        {
            state.hexText = QStringLiteral("%1").arg(static_cast<int>(core.value), 2, 16, QLatin1Char('0')).toUpper();
        }
        else if (core.state == ByteState::Unreadable)
        {
            state.hexText = QStringLiteral("??");
        }
        else
        {
            state.hexText = QString(2, QChar(hexcanvas_format::kLoadingGlyph));
        }

        // ASCII 面板：可见字符照画，不可见字节画点号；没有值时用不会与可见 ASCII 冲突的占位符
        // （未加载 = 中点，不可读 = 乘号），所以问号永远只表示真实的 0x3F 字节。
        if (core.hasValue)
        {
            state.asciiChar = hexcanvas_format::IsPrintableAscii(core.value)
                ? QChar(static_cast<char16_t>(core.value))
                : QLatin1Char('.');
        }
        else if (core.state == ByteState::Unreadable)
        {
            state.asciiChar = QChar(hexcanvas_format::kUnreadableAsciiGlyph);
        }
        else
        {
            state.asciiChar = QChar(hexcanvas_format::kLoadingGlyph);
        }
        return state;
    }

    // 悬停提示文本。
    // 传入：地址；传出：多行文本（地址、十进制、二进制、变化状态与暂存前后值、高亮层提示）。
    QString HexCanvas::cellToolTip(std::uint64_t address) const
    {
        if (!m_hasSpace || !m_viewport.ContainsAddress(address))
        {
            return QString();
        }
        const CellCore core = resolveCore(address);

        // hexPair：把字节格式化为两位大写十六进制（用于"原值/新值"）。
        const auto hexPair = [](std::uint8_t value) {
            return QStringLiteral("%1").arg(static_cast<int>(value), 2, 16, QLatin1Char('0')).toUpper();
        };

        QStringList lines;
        lines << QStringLiteral("地址：%1").arg(hexcanvas_format::FormatAddress(address, addressDigits()));
        if (core.hasValue)
        {
            lines << QStringLiteral("十进制：%1").arg(static_cast<int>(core.value));
            lines << QStringLiteral("二进制：%1")
                .arg(QString::number(static_cast<int>(core.value), 2).rightJustified(8, QLatin1Char('0')));
        }

        // 状态行：暂存要列出"原值 -> 新值"，外部变化列出"上次 -> 当前"。
        if (core.change == ChangeKind::Pending && m_overlay != nullptr)
        {
            const std::optional<std::uint8_t> before = m_overlay->BaselineByte(address);
            lines << QStringLiteral("状态：已暂存，原值 0x%1，新值 0x%2")
                .arg(before.has_value() ? hexPair(*before) : QStringLiteral("??"))
                .arg(hexPair(core.value));
        }
        else if (core.change == ChangeKind::ExternalChange && m_overlay != nullptr)
        {
            const std::optional<std::uint8_t> previous = m_overlay->PreviousByte(address);
            lines << QStringLiteral("状态：外部变化，上次 0x%1，当前 0x%2")
                .arg(previous.has_value() ? hexPair(*previous) : QStringLiteral("??"))
                .arg(hexPair(core.value));
        }
        else if (core.change == ChangeKind::SelfWritten)
        {
            lines << QStringLiteral("状态：本程序刚写入");
        }
        else if (core.hasValue)
        {
            lines << QStringLiteral("状态：未修改");
        }
        else if (core.state == ByteState::Unreadable)
        {
            lines << QStringLiteral("状态：不可读（读取失败）");
        }
        else
        {
            lines << QStringLiteral("状态：尚未加载");
        }

        // 命中高亮层时附上调用方给的提示（搜索命中/书签说明）。
        if (core.layerIndex >= 0)
        {
            const QString& tip = m_layerSnapshot[static_cast<std::size_t>(core.layerIndex)].second->tip;
            if (!tip.isEmpty())
            {
                lines << tip;
            }
        }
        return lines.join(QLatin1Char('\n'));
    }
}
