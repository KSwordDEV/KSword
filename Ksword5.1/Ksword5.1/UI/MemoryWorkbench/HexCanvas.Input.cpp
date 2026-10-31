// HexCanvas.Input.cpp
// 作用：HexCanvas 的鼠标、滚轮、键盘、输入法与悬停提示。
// 所有选区变化都经 HexViewport 的移动/扩选接口完成，再统一走 applySelectionChange 收尾，
// 因此不会出现"原生选区 / 成员变量 / 画刷三头不同步"的旧问题。

#include "HexCanvas.h"
#include "HexCanvasFormat.h"

#include <QContextMenuEvent>
#include <QHelpEvent>
#include <QInputMethodEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QMouseEvent>
#include <QScrollBar>
#include <QToolTip>
#include <QWheelEvent>

#include <algorithm>
#include <limits>

namespace ks::ui
{
    // 鼠标命中测试。
    // 传入：视口坐标；传出：Hit。表头及其上方不是数据行，valid 为假；
    // 落在补空位上的位置会吸附到该行最近的有效地址，exact 为假。
    HexCanvas::Hit HexCanvas::hitTest(const QPoint& viewportPos) const
    {
        Hit hit;
        if (!m_hasSpace || viewportPos.y() < m_layout.headerHeight)
        {
            return hit;
        }

        // 行：表头之下按行高取整，夹取到末行。
        const std::uint64_t rowCount = m_viewport.RowCount();
        const std::uint64_t relative = static_cast<std::uint64_t>(
            (viewportPos.y() - m_layout.headerHeight) / m_layout.rowHeight);
        const std::uint64_t row = std::min(m_firstRow + relative, rowCount - 1ULL);
        hit.pastLastRow = (m_firstRow + relative) > (rowCount - 1ULL);

        // 列与面板：先看落在哪个区域，再换算列号。
        // contentX：加上横向滚动量后的内容坐标。
        const int contentX = viewportPos.x() + m_hOffset;
        const int columns = static_cast<int>(m_viewport.BytesPerRow());
        int column = 0;
        if (viewportPos.x() < addressGutterWidth())
        {
            // 地址列：点击表示选整行，面板保持当前面板。
            hit.inGutter = true;
            hit.pane = m_viewport.Pane();
        }
        else if (contentX >= m_layout.asciiX - m_layout.charWidth)
        {
            // ASCII 区：每列一个字符；越过末列右缘的空白吸附到末列，但记为"越过行尾"。
            hit.pane = ActivePane::Ascii;
            const int rawColumn = (contentX - m_layout.asciiX) / m_layout.charWidth;
            hit.pastRowEnd = rawColumn >= columns;
            column = std::clamp(rawColumn, 0, columns - 1);
        }
        else
        {
            // 十六进制区：取左边界（向左外扩半个字符）不超过点击位置的最后一列，
            // 这样点击单元格之间的空隙也归属到左边那一格，不会出现"点不中"的死区。
            hit.pane = ActivePane::Hex;
            for (int index = 0; index < columns; ++index)
            {
                if (m_layout.hexX + m_layout.cellX[index] - m_layout.charWidth / 2 <= contentX)
                {
                    column = index;
                }
            }

            // 末列单元格（宽 2 个字符，向右外扩半个字符）之后到 ASCII 区之前的空隙不属于任何字节。
            const int hexEnd = m_layout.hexX + m_layout.cellX[columns - 1] + 2 * m_layout.charWidth + m_layout.charWidth / 2;
            hit.pastRowEnd = contentX >= hexEnd;
        }

        // 行内地址：先比较后加减，再夹取到该行有效区间（首尾行的补空位由此吸附）。
        const std::optional<std::uint64_t> start = m_viewport.RowStartAddress(row);
        const std::optional<AddressRange> span = m_viewport.RowValidSpan(row);
        if (!start.has_value() || !span.has_value())
        {
            return hit;
        }
        const std::uint64_t offset = static_cast<std::uint64_t>(column);
        std::uint64_t address = span->last;
        if (offset <= std::numeric_limits<std::uint64_t>::max() - *start)
        {
            address = *start + offset;
        }
        hit.exact = address >= span->first && address <= span->last;
        hit.address = std::clamp(address, span->first, span->last);
        hit.row = row;
        hit.valid = true;
        return hit;
    }

    // 视口坐标命中的真实字节地址（公开版本，供宿主做悬停/拖放定位）。
    // 传入：视口坐标；传出：命中十六进制或 ASCII 面板里的真实字节时返回其地址，
    // 其余（表头、地址列、首尾行补空位、末行之下的空白、越过末列的右侧空白、无数据）返回 nullopt——
    // 不吸附到最近字节，否则拖放落在空白处会被误当成落在某个字节上。
    // 与鼠标点击、悬停提示用同一个 hitTest（十六进制单元格之间的空隙归属左边那一格）。
    std::optional<std::uint64_t> HexCanvas::addressForViewportPos(const QPoint& viewportPos) const
    {
        const Hit hit = hitTest(viewportPos);
        if (!hit.valid || hit.inGutter || hit.pastLastRow || hit.pastRowEnd || !hit.exact)
        {
            return std::nullopt;
        }
        return hit.address;
    }

    // 视口坐标落在哪个面板（公开版本）。
    // 传入：视口坐标；传出：数据行的十六进制区 -> Hex，ASCII 区 -> Ascii（补空位与行尾空白处面板仍明确，
    // 此时 addressForViewportPos 为空）；表头、地址列、末行之下的空白、无数据返回 nullopt。
    std::optional<HexCanvas::ActivePane> HexCanvas::paneAtViewportPos(const QPoint& viewportPos) const
    {
        const Hit hit = hitTest(viewportPos);
        if (!hit.valid || hit.inGutter || hit.pastLastRow)
        {
            return std::nullopt;
        }
        return hit.pane;
    }

    // 鼠标按下：左键设置插入点（Shift 扩选）并开始拖选；点地址列选中整行。
    void HexCanvas::mousePressEvent(QMouseEvent* event)
    {
        if (event->button() != Qt::LeftButton || !m_hasSpace)
        {
            QAbstractScrollArea::mousePressEvent(event);
            return;
        }
        setFocus(Qt::MouseFocusReason);

        const QPoint position = event->position().toPoint();
        const Hit hit = hitTest(position);
        if (!hit.valid)
        {
            event->accept();
            return;
        }

        m_lastMousePos = position;
        const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();
        if (hit.inGutter)
        {
            // 地址列：选中该行全部有效字节。
            const std::optional<AddressRange> span = m_viewport.RowValidSpan(hit.row);
            if (span.has_value())
            {
                m_viewport.SetCaret(span->first, false);
                m_viewport.SetCaret(span->last, true);
            }
        }
        else
        {
            // 数据区：先切面板，再设插入点；按住 Shift 时锚点不动。
            const bool extend = (event->modifiers() & Qt::ShiftModifier) != 0;
            m_viewport.SetPane(hit.pane);
            m_viewport.SetCaret(hit.address, extend);
            m_dragging = true;
        }
        applySelectionChange(before);
        event->accept();
    }

    // 把插入点扩选到命中位置（拖选时每次鼠标移动调用）。
    void HexCanvas::extendSelectionTo(const Hit& hit)
    {
        if (!hit.valid)
        {
            return;
        }
        const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();
        m_viewport.SetCaret(hit.address, true);
        applySelectionChange(before);
    }

    // 鼠标移动：拖选时扩选；拖出视口上下边界时启动自动滚动定时器。
    void HexCanvas::mouseMoveEvent(QMouseEvent* event)
    {
        if (!m_dragging || (event->buttons() & Qt::LeftButton) == 0)
        {
            QAbstractScrollArea::mouseMoveEvent(event);
            return;
        }
        m_lastMousePos = event->position().toPoint();

        // 越出上下边界：交给定时器按距离持续滚动；回到边界内则停掉定时器。
        const bool outside = m_lastMousePos.y() < m_layout.headerHeight
            || m_lastMousePos.y() >= viewport()->height();
        if (outside && !m_autoScrollTimer.isActive())
        {
            m_autoScrollTimer.start();
        }
        else if (!outside && m_autoScrollTimer.isActive())
        {
            m_autoScrollTimer.stop();
        }

        // 扩选用夹取到数据区内的位置，这样拖到表头或视口外时仍然选到首/末可见行。
        QPoint clamped = m_lastMousePos;
        clamped.setY(std::clamp(clamped.y(), m_layout.headerHeight, std::max(m_layout.headerHeight, viewport()->height() - 1)));
        extendSelectionTo(hitTest(clamped));
        event->accept();
    }

    // 鼠标释放：结束拖选并停掉自动滚动。
    void HexCanvas::mouseReleaseEvent(QMouseEvent* event)
    {
        if (event->button() == Qt::LeftButton)
        {
            m_dragging = false;
            m_autoScrollTimer.stop();
            event->accept();
            return;
        }
        QAbstractScrollArea::mouseReleaseEvent(event);
    }

    // 拖选自动滚动的一拍。
    // 作用：鼠标在视口上方/下方时，按距离每拍滚动 1 行起、距离越远越快，并把选区扩到新露出的行。
    void HexCanvas::autoScrollTick()
    {
        if (!m_dragging || !m_hasSpace)
        {
            m_autoScrollTimer.stop();
            return;
        }

        // deltaRows：本拍要滚动的行数（负数向上）。
        std::int64_t deltaRows = 0;
        if (m_lastMousePos.y() < m_layout.headerHeight)
        {
            deltaRows = -(1 + (m_layout.headerHeight - m_lastMousePos.y()) / m_layout.rowHeight);
        }
        else if (m_lastMousePos.y() >= viewport()->height())
        {
            deltaRows = 1 + (m_lastMousePos.y() - viewport()->height()) / m_layout.rowHeight;
        }
        if (deltaRows == 0)
        {
            m_autoScrollTimer.stop();
            return;
        }

        scrollRowsBy(deltaRows);
        QPoint clamped = m_lastMousePos;
        clamped.setY(std::clamp(clamped.y(), m_layout.headerHeight, std::max(m_layout.headerHeight, viewport()->height() - 1)));
        extendSelectionTo(hitTest(clamped));
    }

    // 滚轮：每一档（120）滚 3 行，高精度触摸板的小增量累积到整档再滚；Shift 或横向滚轮滚动横向滚动条；
    // Ctrl+滚轮缩放字号（向上放大、向下缩小，按 120 累计成整档），此时不滚动内容。
    void HexCanvas::wheelEvent(QWheelEvent* event)
    {
        const QPoint angle = event->angleDelta();

        // Ctrl+滚轮：字号缩放。重建缓存文字有成本（512 个以上 QStaticText），所以用累加器把触摸板的
        // 小增量凑成整档再缩放，不是每个事件都重建；accept 之后事件不再往上冒泡成外层滚动区的滚动。
        if ((event->modifiers() & Qt::ControlModifier) != 0)
        {
            m_zoomWheelRemainder += angle.y();
            const int zoomSteps = m_zoomWheelRemainder / 120;
            if (zoomSteps != 0)
            {
                m_zoomWheelRemainder -= zoomSteps * 120;
                zoomBy(zoomSteps);
            }
            event->accept();
            return;
        }
        m_zoomWheelRemainder = 0;

        const bool horizontal = (event->modifiers() & Qt::ShiftModifier) != 0 || (angle.y() == 0 && angle.x() != 0);
        if (horizontal)
        {
            const int delta = angle.x() != 0 ? angle.x() : angle.y();
            QScrollBar* bar = horizontalScrollBar();
            bar->setValue(bar->value() - (delta * bar->singleStep()) / 40);
            event->accept();
            return;
        }
        if (angle.y() == 0)
        {
            event->ignore();
            return;
        }

        m_wheelRemainder += angle.y();
        const int steps = m_wheelRemainder / 120;
        if (steps != 0)
        {
            m_wheelRemainder -= steps * 120;
            scrollRowsBy(static_cast<std::int64_t>(-steps) * 3);
        }
        event->accept();
    }

    // 处理插入点移动类按键（方向键/Home/End/PgUp/PgDn，Shift 扩选）。
    // 传入：按键事件；传出：是否已处理。选区不回绕不越界由 HexViewport 保证。
    bool HexCanvas::handleCaretKey(QKeyEvent* event)
    {
        const bool extend = (event->modifiers() & Qt::ShiftModifier) != 0;
        const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();

        switch (event->key())
        {
        case Qt::Key_Left:
            m_viewport.MoveCaretByBytes(-1, extend);
            break;
        case Qt::Key_Right:
            m_viewport.MoveCaretByBytes(1, extend);
            break;
        case Qt::Key_Up:
            m_viewport.MoveCaretByRows(-1, extend);
            break;
        case Qt::Key_Down:
            m_viewport.MoveCaretByRows(1, extend);
            break;
        case Qt::Key_Home:
            m_viewport.MoveCaretHome(extend);
            break;
        case Qt::Key_End:
            m_viewport.MoveCaretEnd(extend);
            break;
        case Qt::Key_PageUp:
        case Qt::Key_PageDown:
        {
            // 翻页：视图与插入点一起移动一屏，插入点在屏幕上的相对位置保持不变。
            const std::int64_t direction = event->key() == Qt::Key_PageUp ? -1 : 1;
            const std::uint64_t rows = fullVisibleRows();
            scrollRowsBy(direction * static_cast<std::int64_t>(rows));
            m_viewport.MoveCaretByPages(direction, rows, extend);
            break;
        }
        default:
            return false;
        }

        applySelectionChange(before);
        ensureCaretVisible();
        event->accept();
        return true;
    }

    // 字号缩放键：Ctrl+= 与 Ctrl++（美式键盘上加号要按 Shift，Qt 报 Key_Plus）放大，Ctrl+- 缩小，Ctrl+0 恢复默认。
    // 传入：按键事件。传出：true 表示已处理并 accept。
    // Ctrl+Alt 同时按下是 AltGr（文字输入），不当缩放键；这些键目前没有被 WorkbenchActions 的快捷键占用
    // （Ctrl+1..4 是子页切换，Ctrl+0/=/- 空闲）。
    bool HexCanvas::handleZoomKey(QKeyEvent* event)
    {
        const Qt::KeyboardModifiers modifiers = event->modifiers();
        if ((modifiers & Qt::ControlModifier) == 0 || (modifiers & Qt::AltModifier) != 0)
        {
            return false;
        }

        switch (event->key())
        {
        case Qt::Key_Equal:
        case Qt::Key_Plus:
            zoomBy(1);
            break;
        case Qt::Key_Minus:
            zoomBy(-1);
            break;
        case Qt::Key_0:
            zoomReset();
            break;
        default:
            return false;
        }
        event->accept();
        return true;
    }

    // 键盘入口。
    // 优先级：字号缩放键 -> Ctrl 组合键 -> 插入点移动 -> Tab/Esc/Backspace -> 文字输入（编辑）。
    void HexCanvas::keyPressEvent(QKeyEvent* event)
    {
        // 字号缩放键（Ctrl+= / Ctrl++ / Ctrl+- / Ctrl+0）与有没有数据无关，放在"无数据直接交给基类"之前。
        if (handleZoomKey(event))
        {
            return;
        }

        if (!m_hasSpace)
        {
            QAbstractScrollArea::keyPressEvent(event);
            return;
        }

        const Qt::KeyboardModifiers modifiers = event->modifiers();
        const bool ctrl = (modifiers & Qt::ControlModifier) != 0;
        const bool shift = (modifiers & Qt::ShiftModifier) != 0;
        const bool alt = (modifiers & Qt::AltModifier) != 0;
        const int key = event->key();

        // Ctrl 组合键：全选、复制（Shift 复制另一个面板）、粘贴、地址空间首尾。
        if (ctrl)
        {
            switch (key)
            {
            case Qt::Key_A:
                selectAll();
                event->accept();
                return;
            case Qt::Key_C:
                if (shift)
                {
                    copyOtherPane();
                }
                else
                {
                    copyCurrentPane();
                }
                event->accept();
                return;
            case Qt::Key_V:
                pasteFromClipboard();
                event->accept();
                return;
            case Qt::Key_Home:
                setCaretAddress(m_viewport.FirstAddress(), shift, true);
                event->accept();
                return;
            case Qt::Key_End:
                setCaretAddress(m_viewport.LastAddress(), shift, true);
                event->accept();
                return;
            case Qt::Key_Tab:
            case Qt::Key_Backtab:
                // Ctrl+Tab / Ctrl+Shift+Tab：把焦点交给下一个/上一个控件。
                // 普通 Tab 已被面板切换占用，必须留一条键盘路径让焦点离开画布，否则就是键盘陷阱。
                QWidget::focusNextPrevChild(key == Qt::Key_Tab);
                event->accept();
                return;
            default:
                break;
            }
        }

        if (handleCaretKey(event))
        {
            return;
        }

        // Tab / Shift+Tab：切换 Hex 与 ASCII 面板。
        if (key == Qt::Key_Tab || key == Qt::Key_Backtab)
        {
            setActivePane(m_viewport.Pane() == ActivePane::Hex ? ActivePane::Ascii : ActivePane::Hex);
            event->accept();
            return;
        }

        // Esc：先取消未完成的半字节，否则把选区折叠到插入点。
        if (key == Qt::Key_Escape)
        {
            if (m_nibbleActive)
            {
                cancelNibble();
            }
            else
            {
                const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();
                m_viewport.SetCaret(before.caret, false);
                applySelectionChange(before);
            }
            event->accept();
            return;
        }

        if (key == Qt::Key_Backspace)
        {
            backspaceStep();
            event->accept();
            return;
        }

        // 文字输入：Ctrl/Alt 组合键不当文字；Ctrl+Alt 同时按下是 AltGr，视为文字。
        if ((!ctrl && !alt) || (ctrl && alt))
        {
            bool consumed = false;
            const QString text = event->text();
            for (const QChar ch : text)
            {
                consumed = handleTextInput(ch) || consumed;
            }
            if (consumed)
            {
                event->accept();
                return;
            }
        }
        QAbstractScrollArea::keyPressEvent(event);
    }

    // 输入法事件：预编辑内容一律丢弃，只把提交的字符当作按键处理（非拉丁字符会被 handleTextInput 忽略）。
    void HexCanvas::inputMethodEvent(QInputMethodEvent* event)
    {
        const QString committed = event->commitString();
        for (const QChar ch : committed)
        {
            handleTextInput(ch);
        }
        event->accept();
    }

    // 视口事件：处理悬停提示；视口尺寸变化后重选自适应行宽；其余交给基类。
    // 自适应放在这里而不是 resizeEvent：此刻视口已经是新尺寸，也覆盖滚动条显隐造成的视口变化；
    // 先让基类走完（含 resizeEvent 里的夹取首行/同步滚动条/请求页），再按新宽度重选行宽。
    bool HexCanvas::viewportEvent(QEvent* event)
    {
        if (event->type() == QEvent::ToolTip)
        {
            const QHelpEvent* helpEvent = static_cast<QHelpEvent*>(event);
            const Hit hit = hitTest(helpEvent->pos());
            if (m_addressColumnCollapsed && helpEvent->pos().y() < m_layout.headerHeight
                && helpEvent->pos().x() < addressGutterWidth() && !m_addressColumnPrefix.isEmpty())
            {
                QToolTip::showText(helpEvent->globalPos(), m_addressColumnPrefix, viewport());
            }
            else if (m_addressColumnCollapsed && hit.valid && hit.inGutter)
            {
                QToolTip::showText(helpEvent->globalPos(),
                    hexcanvas_format::FormatAddress(m_viewport.RowStartAddress(hit.row).value(), addressDigits()), viewport());
            }
            else if (hit.valid && !hit.inGutter && hit.exact)
            {
                QToolTip::showText(
                    helpEvent->globalPos(),
                    cellToolTip(hit.address),
                    viewport(),
                    cellRect(hit.address, hit.pane));
            }
            else
            {
                QToolTip::hideText();
            }
            event->accept();
            return true;
        }

        const bool handled = QAbstractScrollArea::viewportEvent(event);
        if (event->type() == QEvent::Resize)
        {
            applyAutoBytesPerRow();
        }
        return handled;
    }

    // 让 Tab/Shift+Tab 作为按键到达 keyPressEvent（用来切换面板），而不是移动焦点。
    bool HexCanvas::focusNextPrevChild(bool next)
    {
        Q_UNUSED(next);
        return false;
    }

    // 获得焦点：重绘以恢复插入点外框的强调色。
    void HexCanvas::focusInEvent(QFocusEvent* event)
    {
        QAbstractScrollArea::focusInEvent(event);
        viewport()->update();
    }

    // 失去焦点：停止拖选，重绘以把外框降为次要色。
    void HexCanvas::focusOutEvent(QFocusEvent* event)
    {
        QAbstractScrollArea::focusOutEvent(event);
        m_dragging = false;
        m_autoScrollTimer.stop();
        viewport()->update();
    }

    // 右键菜单。
    // 流程：命中字节且不在选区内先把选区设为该字节 -> 构造菜单（内置项 + 发信号让宿主追加）-> 弹出。
    void HexCanvas::contextMenuEvent(QContextMenuEvent* event)
    {
        if (!m_hasSpace)
        {
            event->ignore();
            return;
        }

        // address/hasByte：菜单针对的地址以及该处是否真有字节；popupPos：弹出位置（全局坐标）。
        std::uint64_t address = m_viewport.GetSelection().caret;
        bool hasByte = true;
        QPoint popupPos = event->globalPos();
        if (event->reason() == QContextMenuEvent::Keyboard)
        {
            // 键盘触发（菜单键）：针对插入点，弹在插入点单元格旁。
            const QRect cell = cellRect(address, m_viewport.Pane());
            if (!cell.isNull())
            {
                popupPos = viewport()->mapToGlobal(cell.bottomLeft());
            }
        }
        else
        {
            const Hit hit = hitTest(event->pos());
            hasByte = hit.valid && !hit.inGutter && hit.exact;
            if (hasByte)
            {
                address = hit.address;
                const std::optional<AddressRange> range = selectedRange();
                const bool insideSelection = range.has_value() && address >= range->first && address <= range->last;
                if (!insideSelection)
                {
                    // 右键落在未选中字节上：先把选区设为该字节，菜单作用的就是它。
                    const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();
                    m_viewport.SetPane(hit.pane);
                    m_viewport.SetCaret(address, false);
                    applySelectionChange(before);
                }
            }
        }

        // 构造并弹出菜单；exec 返回后立即释放，宿主追加的动作随菜单一起销毁。
        std::unique_ptr<QMenu> menu(buildContextMenu(address, hasByte));
        menu->exec(popupPos);
        event->accept();
    }
}
