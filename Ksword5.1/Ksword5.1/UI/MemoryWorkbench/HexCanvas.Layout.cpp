// HexCanvas.Layout.cpp
// 作用：HexCanvas 的度量与横向布局（字体、等宽字符宽度、各区域边界）、单元格几何查询、
// 尺寸/字体/调色板变化事件，以及通用高亮层的存取。

#include "HexCanvas.h"
#include "HexCanvasFormat.h"

#include <QEvent>
#include <QFontMetrics>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollBar>
#include <QTextOption>
#include <QTimer>
#include <QTransform>

#include <algorithm>
#include <limits>

namespace ks::ui
{

    // 重新量字体：字符宽度、行高，并重建缓存文字与横向几何。
    void HexCanvas::rebuildMetrics()
    {
        // fm：当前控件字体的度量。
        const QFontMetrics fm(font());
        m_layout.charWidth = std::max(1, fm.horizontalAdvance(QLatin1Char('0')));
        m_layout.rowHeight = fm.height() + 2;
        m_layout.ascent = fm.ascent();
        m_layout.headerHeight = m_layout.rowHeight + 4;
        rebuildStaticTexts();
        recomputeLayout();
    }

    // 重建 256 个字节值的缓存文字。
    // 之所以用 QStaticText：文字布局只做一次，之后每格绘制只是一次 drawStaticText。
    void HexCanvas::rebuildStaticTexts()
    {
        // makeText：构造一个无换行、纯文本、积极缓存的静态文字。
        const auto makeText = [this](const QString& text) {
            QStaticText staticText(text);
            QTextOption option;
            option.setWrapMode(QTextOption::NoWrap);
            staticText.setTextOption(option);
            staticText.setTextFormat(Qt::PlainText);
            staticText.setPerformanceHint(QStaticText::AggressiveCaching);
            staticText.prepare(QTransform(), font());
            return staticText;
        };

        for (int value = 0; value < 256; ++value)
        {
            // hexText：两位大写十六进制；asciiText：可见字符或点号。
            const QString hexText = QStringLiteral("%1").arg(value, 2, 16, QLatin1Char('0')).toUpper();
            const bool printable = value >= 0x20 && value <= 0x7E;
            const QString asciiText = printable ? QString(QChar(static_cast<char16_t>(value))) : QStringLiteral(".");
            m_hexTexts[value] = makeText(hexText);
            m_asciiTexts[value] = makeText(asciiText);
        }

        // 特殊状态：
        // - 未加载：十六进制画两个中点，ASCII 画一个中点；
        // - 不可读：十六进制画 "??"（只会出现十六进制数字，没有歧义），
        //   ASCII 画乘号（问号会与真实的 0x3F 字节混淆，乘号不在可见 ASCII 范围内）。
        const QChar loadingGlyph(hexcanvas_format::kLoadingGlyph);
        const QChar unreadableGlyph(hexcanvas_format::kUnreadableAsciiGlyph);
        m_loadingHexText = makeText(QString(2, loadingGlyph));
        m_unreadableHexText = makeText(QStringLiteral("??"));
        m_loadingAsciiText = makeText(QString(1, loadingGlyph));
        m_unreadableAsciiText = makeText(QString(1, unreadableGlyph));
    }

    // 地址列位数：地址空间上界不超过 0xFFFFFFFF 时 8 位，否则 16 位。
    int HexCanvas::addressDigits() const
    {
        if (m_hasSpace && m_viewport.LastAddress() <= 0xFFFFFFFFULL)
        {
            return 8;
        }
        return 16;
    }

    // 重算横向几何。
    // 每列十六进制单元格占 2 个字符 + 1 个空格；分组边界多留 1 个字符，
    // 每 8 字节的中缝多留 2 个字符（组边界与中缝重合时取中缝）。
    void HexCanvas::recomputeLayout()
    {
        const int charWidth = m_layout.charWidth;
        const int columns = static_cast<int>(m_viewport.BytesPerRow());

        // 逐列累计"额外单位数"：每进入一个新的分组/中缝先加上对应的额外宽度。
        int extraUnits = 0;
        for (int column = 0; column < columns && column < 64; ++column)
        {
            if (column > 0)
            {
                if (column % 8 == 0)
                {
                    extraUnits += 2;
                }
                else if (m_groupSize > 1 && column % m_groupSize == 0)
                {
                    extraUnits += 1;
                }
            }
            m_layout.cellX[column] = (column * 3 + extraUnits) * charWidth;
        }

        // 区域划分：左边距一个字符 | 地址 | 间隔 | 十六进制 | 间隔 | ASCII | 右边距。
        m_layout.addrDigits = addressDigits();
        m_layout.addrX = charWidth;
        m_layout.addrWidth = m_layout.addrDigits * charWidth;
        m_layout.hexX = m_layout.addrX + m_layout.addrWidth + 2 * charWidth;
        m_layout.hexWidth = m_layout.cellX[columns - 1] + 2 * charWidth;
        m_layout.asciiX = m_layout.hexX + m_layout.hexWidth + 2 * charWidth;
        m_layout.asciiWidth = columns * charWidth;
        m_layout.contentWidth = m_layout.asciiX + m_layout.asciiWidth + charWidth;
    }

    // 单元格矩形（视口坐标）。
    QRect HexCanvas::cellRect(std::uint64_t address, ActivePane pane) const
    {
        if (!m_hasSpace || !m_viewport.ContainsAddress(address))
        {
            return QRect();
        }
        const std::optional<std::uint64_t> row = m_viewport.RowOfAddress(address);
        const std::optional<std::uint32_t> column = m_viewport.ColumnOfAddress(address);
        if (!row.has_value() || !column.has_value() || *row < m_firstRow)
        {
            return QRect();
        }
        const std::uint64_t relative = *row - m_firstRow;
        if (relative >= paintRowCount())
        {
            return QRect();
        }

        // 纵向：表头之下第 relative 行；横向：Hex 取 cellX 表，ASCII 每列一个字符。
        const int top = m_layout.headerHeight + static_cast<int>(relative) * m_layout.rowHeight;
        if (pane == ActivePane::Hex)
        {
            return QRect(
                m_layout.hexX + m_layout.cellX[*column] - m_hOffset,
                top,
                2 * m_layout.charWidth,
                m_layout.rowHeight);
        }
        return QRect(
            m_layout.asciiX + static_cast<int>(*column) * m_layout.charWidth - m_hOffset,
            top,
            m_layout.charWidth,
            m_layout.rowHeight);
    }

    // 建议尺寸（首选尺寸，不是最小尺寸）。
    QSize HexCanvas::sizeHint() const
    {
        return QSize(
            m_layout.contentWidth + verticalScrollBar()->sizeHint().width() + 2,
            m_layout.headerHeight + 16 * m_layout.rowHeight + 2);
    }

    // 最小尺寸：宽度沿用基类（两个滚动条的宽度），高度至少"表头 + 4 行 + 横向滚动条 + 边框"。
    // 宽度绝不抬高：画布自己支持横向滚动，宿主窗口理应能被拖得比"半行"还窄，
    // 抬宽会把宿主钉在一个拖不动的宽度上（见 MemoryWorkbenchView.Ui.cpp 的窄宽度硬下限说明）。
    // 4 行是"压扁时仍能看到几行数据"的下限；基类的默认最小高度只有两个滚动条那么高（约 70 px），与字体无关。
    QSize HexCanvas::minimumSizeHint() const
    {
        const QSize base = QAbstractScrollArea::minimumSizeHint();
        const int minimumHeight = m_layout.headerHeight
            + 4 * m_layout.rowHeight
            + horizontalScrollBar()->sizeHint().height()
            + 2;
        return QSize(base.width(), std::max(base.height(), minimumHeight));
    }

    // 自适应行宽：按视口宽度在候选档里选"放得下的最大一档"，变了就重排。
    // 调用时机：视口 Resize（viewportEvent）、字体变化、分组变化、地址空间安装（地址位数可能变）、
    //          setAutoBytesPerRow(true)。
    // 判据只用 viewport()->width()：竖向滚动条常驻，它的出现与否不会影响视口宽度，所以没有反馈环；
    // m_inAutoFit 防的是 applyBytesPerRow -> 横向滚动条显隐 -> 视口 Resize -> 再进本函数 这条理论上的重入路径。
    // 传出：true 表示行宽真的变了（已发 rowWidthModeChanged(n, true)）。
    bool HexCanvas::applyAutoBytesPerRow()
    {
        if (!m_autoBytesPerRow || m_inAutoFit || !m_hasSpace)
        {
            return false;
        }

        // 视口宽度还是 0 或负数：窗口尚未布局，什么都不做，等 show 之后的 Resize 再选。
        const int viewportWidth = viewport()->width();
        if (viewportWidth <= 0)
        {
            return false;
        }

        // wanted：此刻放得下的最大一档；与当前相同就不重排（也就不会发多余的信号）。
        const int wanted = hexcanvas_format::ChooseAutoBytesPerRow(
            viewportWidth,
            m_layout.charWidth,
            m_groupSize,
            addressDigits());
        if (wanted == bytesPerRow())
        {
            return false;
        }

        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        m_inAutoFit = true;
        const bool changed = applyBytesPerRow(wanted);
        if (!alive) return false;
        // 活对象换源也必须解除重排锁；旧来源的模式通知则不再发送。
        m_inAutoFit = false;
        const int currentWanted = hexcanvas_format::ChooseAutoBytesPerRow(
            viewport()->width(), m_layout.charWidth, m_groupSize, addressDigits());
        if (sourceRevision() != revision || (m_autoBytesPerRow && bytesPerRow() != currentWanted))
        {
            // 重入期间新来源/字体的自动选档被忙锁挡住；仅为仍有效的新来源补一次。
            const auto currentRevision = sourceRevision();
            if (m_autoBytesPerRow && m_hasSpace)
                QTimer::singleShot(0, this, [this, currentRevision]() {
                    if (sourceRevision() == currentRevision) applyAutoBytesPerRow();
                });
            return false;
        }
        if (!m_autoBytesPerRow || bytesPerRow() != wanted) return false;
        if (changed)
        {
            emit rowWidthModeChanged(bytesPerRow(), true);
        }
        return alive && sourceRevision() == revision && changed;
    }

    // 当前缩放级别。
    int HexCanvas::zoomLevel() const
    {
        return m_zoomLevel;
    }

    // 设置缩放级别：夹取到 [kMinZoomLevel, kMaxZoomLevel]，真的变了才重建字体并发信号。
    void HexCanvas::setZoomLevel(int level)
    {
        const int clamped = std::clamp(level, kMinZoomLevel, kMaxZoomLevel);
        if (clamped == m_zoomLevel)
        {
            return;
        }
        m_zoomLevel = clamped;

        // setFont 会触发 FontChange -> changeEvent：那里重量度、夹取首行、重选自适应行宽。
        const QPointer<HexCanvas> alive(this);
        applyZoomFont();
        if (!alive || m_zoomLevel != clamped) return;
        emit zoomLevelChanged(m_zoomLevel);
    }

    // 在当前级别上加 delta 档。
    void HexCanvas::zoomBy(int delta)
    {
        setZoomLevel(m_zoomLevel + delta);
    }

    // 恢复默认字号。
    void HexCanvas::zoomReset()
    {
        setZoomLevel(0);
    }

    // 按基准字体与缩放级别算出字体并设置给控件。
    // 每档 1pt（基准字体以像素为单位给尺寸时每档 1 px）；点数下限 4pt，防止极小字号退化成度量为 0。
    void HexCanvas::applyZoomFont()
    {
        QFont zoomed = m_baseFont;
        if (m_baseFont.pointSizeF() > 0.0)
        {
            zoomed.setPointSizeF(std::max(4.0, m_baseFont.pointSizeF() + static_cast<qreal>(m_zoomLevel)));
        }
        else if (m_baseFont.pixelSize() > 0)
        {
            zoomed.setPixelSize(std::max(5, m_baseFont.pixelSize() + m_zoomLevel));
        }
        setFont(zoomed);
    }

    // 输入法提示：禁用预测、偏好拉丁字符。
    QVariant HexCanvas::inputMethodQuery(Qt::InputMethodQuery query) const
    {
        if (query == Qt::ImHints)
        {
            const Qt::InputMethodHints hints =
                Qt::ImhNoPredictiveText | Qt::ImhPreferLatin | Qt::ImhLatinOnly;
            return QVariant(static_cast<int>(hints));
        }
        return QAbstractScrollArea::inputMethodQuery(query);
    }

    // 最近一次绘制的行数。
    std::uint64_t HexCanvas::lastPaintedRowCount() const
    {
        return m_lastPaintedRows;
    }

    // 尺寸变化：夹取首行（可见行数变了最大首行也变）、重算滚动条并请求新露出的页。
    void HexCanvas::resizeEvent(QResizeEvent* event)
    {
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        QAbstractScrollArea::resizeEvent(event);
        if (!alive || sourceRevision() != revision) return;
        m_firstRow = std::min(m_firstRow, maxFirstRow());
        syncScrollBars();
        if (!alive || sourceRevision() != revision) return;
        requestVisiblePages();
        if (!alive || sourceRevision() != revision) return;
        notifyVisibleRange();
    }

    // 字体/调色板变化：字体变化重算度量，其余只需要重绘（颜色在绘制时现取）。
    void HexCanvas::changeEvent(QEvent* event)
    {
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        QAbstractScrollArea::changeEvent(event);
        if (!alive || sourceRevision() != revision) return;
        switch (event->type())
        {
        case QEvent::FontChange:
            // 行高变了可见行数也变了，最大首行随之变化：必须夹取首行，否则 syncScrollBars 里的 setValue
            // 被 m_updatingBars 屏蔽，m_firstRow 可能大于新的最大首行，末尾出现空白带（缩放功能前的潜伏缺陷）。
            // 字符宽度变了每行内容宽度也变了，自适应模式要重选行宽（内部会同步滚动条）。
            rebuildMetrics();
            m_firstRow = std::min(m_firstRow, maxFirstRow());
            applyAutoBytesPerRow();
            if (!alive || sourceRevision() != revision) return;
            syncScrollBars();
            if (!alive || sourceRevision() != revision) return;
            requestVisiblePages();
            if (!alive || sourceRevision() != revision) return;
            notifyVisibleRange();
            if (!alive || sourceRevision() != revision) return;
            viewport()->update();
            break;
        case QEvent::PaletteChange:
        case QEvent::ApplicationPaletteChange:
        case QEvent::StyleChange:
            viewport()->update();
            break;
        default:
            break;
        }
    }

    // ======================== 高亮层 ========================

    // 设置/替换一个高亮层。
    void HexCanvas::setHighlightRanges(
        int layerId,
        const std::vector<AddressRange>& ranges,
        const QColor& color,
        const QString& tip)
    {
        // normalized：丢弃非法区间，按起点排序。
        std::vector<AddressRange> normalized;
        normalized.reserve(ranges.size());
        for (const AddressRange& range : ranges)
        {
            if (range.first <= range.last)
            {
                normalized.push_back(range);
            }
        }
        std::sort(normalized.begin(), normalized.end(), [](const AddressRange& left, const AddressRange& right) {
            return left.first < right.first;
        });

        // merged：把重叠或相邻的区间合并，保证二分查找只需看一个候选。
        std::vector<AddressRange> merged;
        for (const AddressRange& range : normalized)
        {
            const bool touches = !merged.empty()
                && (range.first <= merged.back().last
                    || (merged.back().last != std::numeric_limits<std::uint64_t>::max()
                        && range.first == merged.back().last + 1ULL));
            if (touches)
            {
                merged.back().last = std::max(merged.back().last, range.last);
            }
            else
            {
                merged.push_back(range);
            }
        }

        HighlightLayer layer;
        layer.ranges = std::move(merged);
        layer.color = color;
        layer.tip = tip;
        m_layers[layerId] = std::move(layer);
        rebuildLayerSnapshot();
        viewport()->update();
    }

    // 清除一个高亮层。
    void HexCanvas::clearHighlightRanges(int layerId)
    {
        if (m_layers.erase(layerId) != 0)
        {
            rebuildLayerSnapshot();
            viewport()->update();
        }
    }

    // 清除全部高亮层。
    void HexCanvas::clearAllHighlightRanges()
    {
        if (!m_layers.empty())
        {
            m_layers.clear();
            rebuildLayerSnapshot();
            viewport()->update();
        }
    }

    // 重建层快照：层号降序，使高层优先匹配。map 的节点地址稳定，指针在增删其它层时仍有效。
    void HexCanvas::rebuildLayerSnapshot()
    {
        m_layerSnapshot.clear();
        m_layerSnapshot.reserve(m_layers.size());
        for (auto it = m_layers.rbegin(); it != m_layers.rend(); ++it)
        {
            m_layerSnapshot.emplace_back(it->first, &it->second);
        }
    }
}
