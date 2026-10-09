// HexInspectorRowView.cpp
// 作用：HexInspectorRowView 的状态、布局、输入处理与行内编辑器；绘制在 HexInspectorRowView.Paint.cpp。

#include "HexInspectorRowView.h"
#include "HexInspectorWidgets.h"

#include "../../theme.h"
#include "../FloatingScrollbars.h"

#include <QAbstractScrollArea>
#include <QContextMenuEvent>
#include <QEvent>
#include <QFocusEvent>
#include <QFontMetrics>
#include <QFrame>
#include <QHelpEvent>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollBar>
#include <QToolTip>

#include <algorithm>

namespace ks::ui
{
    // 构造：等宽字体、无边框、可获得焦点，开启鼠标跟踪以便悬停行显示复制图标。
    HexInspectorRowView::HexInspectorRowView(QWidget* parent)
        : QAbstractScrollArea(parent)
    {
        setFont(HexInspectorFixedFont());
        setFrameShape(QFrame::NoFrame);
        setFocusPolicy(Qt::StrongFocus);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        // 右缘复制动作必须保持完整点击区，细线滑块放在动作列左侧。
        ks::ui::SetFloatingScrollbarInsets(this, QMargins(0, 0, kActionWidth + 2, 0));
        viewport()->setMouseTracking(true);
        viewport()->setAutoFillBackground(false);
        rebuildMetrics();
        updateScrollBars();
    }

    // 整体替换行内容。
    void HexInspectorRowView::setRows(std::vector<HexInspectorRowData> rows)
    {
        m_rows = std::move(rows);

        // 当前行与悬停行夹取到新的行数范围。
        const int count = static_cast<int>(m_rows.size());
        if (count == 0)
        {
            m_currentRow = -1;
            m_hoverRow = -1;
        }
        else
        {
            m_currentRow = (m_currentRow < 0) ? 0 : std::min(m_currentRow, count - 1);
            if (m_hoverRow >= count)
            {
                m_hoverRow = -1;
            }
        }

        // 类型名可能变化（ptr32 与 ptr64），重算度量；行数可能变化，重算滚动范围；编辑器跟着新几何走。
        rebuildMetrics();
        updateScrollBars();
        repositionEditor();
        viewport()->update();
    }

    // 行数。
    int HexInspectorRowView::rowCount() const
    {
        return static_cast<int>(m_rows.size());
    }

    // 取一行；越界时返回静态空行，避免调用方判空。
    const HexInspectorRowData& HexInspectorRowView::rowAt(int index) const
    {
        static const HexInspectorRowData emptyRow;
        if (index < 0 || index >= rowCount())
        {
            return emptyRow;
        }
        return m_rows[static_cast<std::size_t>(index)];
    }

    // 当前行。
    int HexInspectorRowView::currentRow() const
    {
        return m_currentRow;
    }

    // 设置当前行。
    void HexInspectorRowView::setCurrentRow(int row)
    {
        const int count = rowCount();
        const int target = (count == 0) ? -1 : std::clamp(row, 0, count - 1);
        if (target == m_currentRow)
        {
            return;
        }
        m_currentRow = target;
        if (target >= 0)
        {
            ensureRowVisible(target);
        }
        viewport()->update();
        emit currentRowChanged(target);
    }

    // 行高。
    int HexInspectorRowView::rowHeight() const
    {
        return m_rowHeight;
    }

    // 标题高度。
    int HexInspectorRowView::headerHeight() const
    {
        return m_headerHeight;
    }

    // 整行矩形。
    QRect HexInspectorRowView::rowRect(int row) const
    {
        if (row < 0 || row >= rowCount())
        {
            return QRect();
        }
        const int top = m_headerHeight + row * m_rowHeight - verticalScrollBar()->value();
        return QRect(0, top, viewport()->width(), m_rowHeight);
    }

    // 值列矩形。
    QRect HexInspectorRowView::valueCellRect(int row) const
    {
        const QRect full = rowRect(row);
        if (full.isNull())
        {
            return QRect();
        }
        const Columns columns = computeColumns();
        return QRect(columns.valueX, full.top(), columns.valueW, full.height());
    }

    // 十六进制列矩形。
    QRect HexInspectorRowView::hexCellRect(int row) const
    {
        const QRect full = rowRect(row);
        if (full.isNull())
        {
            return QRect();
        }
        const Columns columns = computeColumns();
        return QRect(columns.hexX, full.top(), columns.hexW, full.height());
    }

    // 复制图标矩形：行尾复制图标列里居中的 16x16 方块。
    QRect HexInspectorRowView::copyGlyphRect(int row) const
    {
        const QRect full = rowRect(row);
        if (full.isNull())
        {
            return QRect();
        }
        const Columns columns = computeColumns();
        const int size = std::min(16, std::min(columns.actionW, full.height()));
        return QRect(
            columns.actionX + (columns.actionW - size) / 2,
            full.top() + (full.height() - size) / 2,
            size,
            size);
    }

    // 视口坐标落在哪一行。
    int HexInspectorRowView::rowAtPosition(const QPoint& viewportPos) const
    {
        if (viewportPos.y() < m_headerHeight || viewportPos.x() < 0 || viewportPos.x() >= viewport()->width())
        {
            return -1;
        }
        const int offset = viewportPos.y() - m_headerHeight + verticalScrollBar()->value();
        const int row = offset / std::max(1, m_rowHeight);
        return (row >= 0 && row < rowCount()) ? row : -1;
    }

    // 悬停提示：标题区按列给说明，行内复制图标给"复制值"，其余给整行提示。
    QString HexInspectorRowView::toolTipAt(const QPoint& viewportPos) const
    {
        // 标题区：三列各自说明含义，尤其是"十六进制"列容易被误解成"原始字节"。
        if (viewportPos.y() >= 0 && viewportPos.y() < m_headerHeight)
        {
            const Columns columns = computeColumns();
            if (viewportPos.x() < columns.valueX)
            {
                return QStringLiteral("数据类型；整数、浮点、指针与时间按右上角选择的字节序解释");
            }
            if (viewportPos.x() < columns.hexX)
            {
                return QStringLiteral("从插入点起按该类型解释出的值；双击整数、浮点、指针行可以直接编辑");
            }
            return QStringLiteral("该值的十六进制位模式；字符串与 GUID 行显示起点处的原始字节（内存顺序）");
        }

        // 行内：先判复制图标，再回到整行提示。
        const int row = rowAtPosition(viewportPos);
        if (row < 0)
        {
            return QString();
        }
        if (overCopyGlyph(viewportPos, row))
        {
            return QStringLiteral("复制该行的值");
        }
        return rowAt(row).toolTip;
    }

    // 打开行内编辑器。
    bool HexInspectorRowView::beginEdit(int row, const QString& initialText)
    {
        if (row < 0 || row >= rowCount())
        {
            return false;
        }

        // 先结束旧编辑器（不发信号），再滚动到目标行并建新的。
        endEdit();
        ensureRowVisible(row);
        m_editRow = row;
        m_editHasError = false;
        m_editor = new QLineEdit(viewport());
        m_editor->setFont(font());
        m_editor->setStyleSheet(editorStyleSheet(false));
        m_editor->setText(initialText);
        m_editor->setToolTip(QStringLiteral("输入新值后按 Enter 暂存，按 Esc 取消"));
        m_editor->installEventFilter(this);
        m_editor->setGeometry(editorRect(row));

        // 用户继续键入说明在改正输入：边框从错误红色恢复为强调色（状态条里的原因保留到下一次提交）。
        connect(m_editor, &QLineEdit::textEdited, this, [this]() {
            setEditError(false);
        });

        m_editor->show();
        m_editor->setFocus(Qt::OtherFocusReason);
        m_editor->selectAll();
        viewport()->update();
        return true;
    }

    // 结束编辑器，不发信号，焦点回到列表本身。
    void HexInspectorRowView::endEdit()
    {
        endEditInternal(true);
    }

    // 结束编辑器的共用实现。
    // 传入：restoreFocus 为真时把焦点还给列表；因"点到别处"而失焦时必须为假，否则会把用户刚点的控件抢回来。
    void HexInspectorRowView::endEditInternal(bool restoreFocus)
    {
        if (m_editor == nullptr)
        {
            return;
        }

        // 先把成员置空再销毁：销毁过程中可能再触发失焦事件，此时不能再认它是"当前编辑器"。
        QLineEdit* editor = m_editor;
        m_editor = nullptr;
        m_editRow = -1;
        editor->removeEventFilter(this);
        editor->hide();
        editor->deleteLater();

        // 焦点回到列表本身，键盘上下键与 Enter 可以继续用。
        if (restoreFocus)
        {
            setFocus(Qt::OtherFocusReason);
        }
        viewport()->update();
    }

    // 是否正在编辑。
    bool HexInspectorRowView::isEditing() const
    {
        return m_editor != nullptr;
    }

    // 被编辑的行。
    int HexInspectorRowView::editingRow() const
    {
        return m_editRow;
    }

    // 编辑器指针。
    QLineEdit* HexInspectorRowView::editor() const
    {
        return m_editor;
    }

    // 切换编辑器边框的错误态。
    void HexInspectorRowView::setEditError(bool hasError)
    {
        if (m_editor == nullptr || m_editHasError == hasError)
        {
            return;
        }
        m_editHasError = hasError;
        m_editor->setStyleSheet(editorStyleSheet(hasError));
    }

    // 建议尺寸：理想列宽 + 全部行高。
    QSize HexInspectorRowView::sizeHint() const
    {
        const int width = m_nameWidth
            + (kValueIdealChars + kHexIdealChars) * m_charWidth
            + 4 * kCellPadding
            + kActionWidth;
        const int height = m_headerHeight + rowCount() * m_rowHeight + 2 * frameWidth();
        return QSize(width, std::max(height, m_headerHeight + 6 * m_rowHeight));
    }

    // 最小尺寸：类型名 + 十几个字符的值，三行可见。
    QSize HexInspectorRowView::minimumSizeHint() const
    {
        const int width = m_nameWidth + 14 * m_charWidth + 2 * kCellPadding + kActionWidth;
        return QSize(width, m_headerHeight + 3 * m_rowHeight);
    }

    // 重绘事件的实现在 Paint.cpp。

    // 尺寸变化：重算滚动范围，编辑器跟着新列宽走。
    void HexInspectorRowView::resizeEvent(QResizeEvent* event)
    {
        QAbstractScrollArea::resizeEvent(event);
        updateScrollBars();
        repositionEditor();
    }

    // 字体变化：度量全部重算。
    void HexInspectorRowView::changeEvent(QEvent* event)
    {
        QAbstractScrollArea::changeEvent(event);
        if (event->type() == QEvent::FontChange)
        {
            rebuildMetrics();
            updateScrollBars();
            repositionEditor();
            viewport()->update();
        }
    }

    // 滚动：重绘并让编辑器跟随。
    void HexInspectorRowView::scrollContentsBy(int dx, int dy)
    {
        Q_UNUSED(dx);
        Q_UNUSED(dy);
        viewport()->update();
        repositionEditor();
    }

    // 左键：点复制图标就复制，否则选中该行并取得焦点。
    void HexInspectorRowView::mousePressEvent(QMouseEvent* event)
    {
        if (event->button() != Qt::LeftButton)
        {
            QAbstractScrollArea::mousePressEvent(event);
            return;
        }
        const QPoint position = event->position().toPoint();
        const int row = rowAtPosition(position);
        setFocus(Qt::MouseFocusReason);
        if (row >= 0)
        {
            setCurrentRow(row);
            if (overCopyGlyph(position, row))
            {
                emit copyRequested(row, static_cast<int>(CopyKind::Value));
            }
        }
        event->accept();
    }

    // 鼠标移动：更新悬停行。
    void HexInspectorRowView::mouseMoveEvent(QMouseEvent* event)
    {
        setHoverRow(rowAtPosition(event->position().toPoint()));
        QAbstractScrollArea::mouseMoveEvent(event);
    }

    // 双击：激活该行（复制图标上的双击不当作激活，避免复制后又弹出编辑器）。
    void HexInspectorRowView::mouseDoubleClickEvent(QMouseEvent* event)
    {
        if (event->button() != Qt::LeftButton)
        {
            QAbstractScrollArea::mouseDoubleClickEvent(event);
            return;
        }
        const QPoint position = event->position().toPoint();
        const int row = rowAtPosition(position);
        if (row >= 0 && !overCopyGlyph(position, row))
        {
            setCurrentRow(row);
            emit rowActivated(row);
        }
        event->accept();
    }

    // 键盘：上下移动当前行，Enter/F2 激活，Ctrl+C 复制值，菜单键弹菜单。
    void HexInspectorRowView::keyPressEvent(QKeyEvent* event)
    {
        if (event->matches(QKeySequence::Copy))
        {
            if (m_currentRow >= 0)
            {
                emit copyRequested(m_currentRow, static_cast<int>(CopyKind::Value));
            }
            event->accept();
            return;
        }
        switch (event->key())
        {
        case Qt::Key_Up:
            moveCurrentRow(-1);
            event->accept();
            return;
        case Qt::Key_Down:
            moveCurrentRow(1);
            event->accept();
            return;
        case Qt::Key_PageUp:
            moveCurrentRow(-std::max(1, (viewport()->height() - m_headerHeight) / std::max(1, m_rowHeight)));
            event->accept();
            return;
        case Qt::Key_PageDown:
            moveCurrentRow(std::max(1, (viewport()->height() - m_headerHeight) / std::max(1, m_rowHeight)));
            event->accept();
            return;
        case Qt::Key_Home:
            setCurrentRow(0);
            event->accept();
            return;
        case Qt::Key_End:
            setCurrentRow(rowCount() - 1);
            event->accept();
            return;
        case Qt::Key_Return:
        case Qt::Key_Enter:
        case Qt::Key_F2:
            if (m_currentRow >= 0)
            {
                emit rowActivated(m_currentRow);
            }
            event->accept();
            return;
        case Qt::Key_Menu:
            if (m_currentRow >= 0)
            {
                emit contextMenuRequested(m_currentRow, viewport()->mapToGlobal(rowRect(m_currentRow).center()));
            }
            event->accept();
            return;
        default:
            break;
        }
        QAbstractScrollArea::keyPressEvent(event);
    }

    // 右键菜单：选中被点的行并把请求交给面板。
    void HexInspectorRowView::contextMenuEvent(QContextMenuEvent* event)
    {
        int row = rowAtPosition(event->pos());
        QPoint globalPos = event->globalPos();

        // 键盘触发的菜单没有可靠的鼠标位置，改用当前行的中心。
        if (event->reason() == QContextMenuEvent::Keyboard)
        {
            row = m_currentRow;
            if (row >= 0)
            {
                globalPos = viewport()->mapToGlobal(rowRect(row).center());
            }
        }
        if (row >= 0)
        {
            setCurrentRow(row);
        }
        emit contextMenuRequested(row, globalPos);
        event->accept();
    }

    // 获得焦点：当前行底色从"非活动"变"活动"。
    void HexInspectorRowView::focusInEvent(QFocusEvent* event)
    {
        QAbstractScrollArea::focusInEvent(event);
        viewport()->update();
    }

    // 失去焦点：反过来。
    void HexInspectorRowView::focusOutEvent(QFocusEvent* event)
    {
        QAbstractScrollArea::focusOutEvent(event);
        viewport()->update();
    }

    // 视口事件：处理悬停提示与鼠标离开。
    bool HexInspectorRowView::viewportEvent(QEvent* event)
    {
        if (event->type() == QEvent::ToolTip)
        {
            // 悬停提示：按鼠标所在行/列取文字，没有就隐藏旧提示。
            const QHelpEvent* help = static_cast<QHelpEvent*>(event);
            const QString tip = toolTipAt(help->pos());
            if (tip.isEmpty())
            {
                QToolTip::hideText();
                event->ignore();
            }
            else
            {
                QToolTip::showText(help->globalPos(), HexInspectorRichToolTip(tip), viewport());
            }
            return true;
        }
        if (event->type() == QEvent::Leave)
        {
            setHoverRow(-1);
        }
        return QAbstractScrollArea::viewportEvent(event);
    }

    // 编辑器的事件过滤：Esc 取消；点到别处（真正的失焦）取消。
    bool HexInspectorRowView::eventFilter(QObject* watched, QEvent* event)
    {
        if (m_editor == nullptr || watched != m_editor)
        {
            return QAbstractScrollArea::eventFilter(watched, event);
        }

        if (event->type() == QEvent::KeyPress)
        {
            const QKeyEvent* keyEvent = static_cast<QKeyEvent*>(event);
            if (keyEvent->key() == Qt::Key_Escape)
            {
                const int row = m_editRow;
                endEdit();
                emit editCancelled(row);
                return true;
            }

            // Enter：把当前输入交给面板校验；面板决定是否结束编辑（失败时编辑器保持打开）。
            // 必须在这里消费掉按键：QLineEdit 对 Enter 会 ignore 事件，事件随后沿父控件传到本列表的
            // keyPressEvent，被当成"激活当前行"，刚提交完的编辑器会立刻又被打开一次。
            if (keyEvent->key() == Qt::Key_Return || keyEvent->key() == Qt::Key_Enter)
            {
                emit editCommitted(m_editRow, m_editor->text());
                return true;
            }
        }
        else if (event->type() == QEvent::FocusOut)
        {
            // 窗口失活、弹出右键菜单造成的失焦不算"点到别处"，编辑器保持打开，用户回来可以继续输入。
            const QFocusEvent* focusEvent = static_cast<QFocusEvent*>(event);
            const Qt::FocusReason reason = focusEvent->reason();
            if (reason != Qt::ActiveWindowFocusReason && reason != Qt::PopupFocusReason)
            {
                const int row = m_editRow;
                endEditInternal(false);
                emit editCancelled(row);
            }
        }
        return QAbstractScrollArea::eventFilter(watched, event);
    }

    // 重算字体相关的度量：字符宽度、行高、标题高度、类型列宽度。
    void HexInspectorRowView::rebuildMetrics()
    {
        const QFontMetrics metrics(font());
        m_charWidth = std::max(1, metrics.horizontalAdvance(QLatin1Char('0')));
        m_rowHeight = std::max(22, metrics.height() + 7);
        m_headerHeight = std::max(22, metrics.height() + 6);

        // 类型列宽度：取"当前所有类型名"与一个保底样例（最长的常见名）中较宽者，再加两侧内边距。
        int widest = metrics.horizontalAdvance(QStringLiteral("time_t64"));
        for (const HexInspectorRowData& row : m_rows)
        {
            widest = std::max(widest, metrics.horizontalAdvance(row.typeName));
        }
        m_nameWidth = widest + 2 * kCellPadding;
    }

    // 重算滚动条范围：内容高度减去视口里除标题之外的可用高度。
    void HexInspectorRowView::updateScrollBars()
    {
        const int contentHeight = rowCount() * m_rowHeight;
        const int viewHeight = std::max(1, viewport()->height() - m_headerHeight);
        const int maximum = std::max(0, contentHeight - viewHeight);
        verticalScrollBar()->setRange(0, maximum);
        verticalScrollBar()->setPageStep(viewHeight);
        verticalScrollBar()->setSingleStep(m_rowHeight);
    }

    // 计算各列位置。
    HexInspectorRowView::Columns HexInspectorRowView::computeColumns() const
    {
        Columns columns;
        const int totalWidth = viewport()->width();
        columns.nameX = 0;
        columns.nameW = std::min(m_nameWidth, totalWidth);
        columns.actionW = std::min(kActionWidth, std::max(0, totalWidth - columns.nameW));
        columns.actionX = totalWidth - columns.actionW;

        // 中间两列：理想宽度之和放得下时，十六进制列取理想宽度、值列拿走全部余量；放不下按理想宽度比例分。
        const int rest = std::max(0, columns.actionX - columns.nameW);
        const int valueIdeal = kValueIdealChars * m_charWidth + 2 * kCellPadding;
        const int hexIdeal = kHexIdealChars * m_charWidth + 2 * kCellPadding;
        if (rest >= valueIdeal + hexIdeal)
        {
            columns.hexW = hexIdeal;
            columns.valueW = rest - hexIdeal;
        }
        else
        {
            columns.valueW = rest * valueIdeal / (valueIdeal + hexIdeal);
            columns.hexW = rest - columns.valueW;
        }
        columns.valueX = columns.nameX + columns.nameW;
        columns.hexX = columns.valueX + columns.valueW;
        return columns;
    }

    // 编辑器矩形：覆盖值列与十六进制列，上下各留 1 像素。
    QRect HexInspectorRowView::editorRect(int row) const
    {
        const QRect full = rowRect(row);
        const Columns columns = computeColumns();
        return QRect(
            columns.valueX + 2,
            full.top() + 1,
            std::max(20, columns.valueW + columns.hexW - 4),
            std::max(10, full.height() - 2));
    }

    // 让编辑器跟随当前几何（滚动、缩放、行数变化后调用）。
    void HexInspectorRowView::repositionEditor()
    {
        if (m_editor == nullptr || m_editRow < 0)
        {
            return;
        }
        m_editor->setGeometry(editorRect(m_editRow));
    }

    // 编辑器样式：每次 beginEdit 用当时的静态主题色生成；错误态只换边框色。
    QString HexInspectorRowView::editorStyleSheet(bool hasError) const
    {
        const QColor surface = KswordTheme::SurfaceAltColor();
        const QColor selection = KswordTheme::EditorSelectionColor();
        const QColor frame = hasError
            ? KswordTheme::EnsureTextContrast(KswordTheme::ErrorColor(), surface)
            : KswordTheme::PrimaryAccentColor();
        return QStringLiteral(
            "QLineEdit{background-color:%1;color:%2;border:1px solid %3;border-radius:3px;padding:0px 4px;"
            "selection-background-color:%4;selection-color:%5;}")
            .arg(KswordTheme::ThemeColorName(surface))
            .arg(KswordTheme::TextPrimaryColorHex())
            .arg(KswordTheme::ThemeColorName(frame))
            .arg(KswordTheme::ThemeColorName(selection))
            .arg(KswordTheme::ThemeColorName(KswordTheme::OnAccentColor(selection)));
    }

    // 移动当前行 delta 行。
    void HexInspectorRowView::moveCurrentRow(int delta)
    {
        if (rowCount() == 0)
        {
            return;
        }
        const int base = (m_currentRow < 0) ? 0 : m_currentRow;
        setCurrentRow(base + delta);
    }

    // 滚动让某行完整可见。
    void HexInspectorRowView::ensureRowVisible(int row)
    {
        if (row < 0 || row >= rowCount())
        {
            return;
        }
        const int top = row * m_rowHeight;
        const int bottom = top + m_rowHeight;
        const int viewHeight = std::max(1, viewport()->height() - m_headerHeight);
        QScrollBar* bar = verticalScrollBar();
        if (top < bar->value())
        {
            bar->setValue(top);
        }
        else if (bottom > bar->value() + viewHeight)
        {
            bar->setValue(bottom - viewHeight);
        }
    }

    // 坐标是否落在某行的复制图标上；只有字节可用的行才有复制图标。
    bool HexInspectorRowView::overCopyGlyph(const QPoint& viewportPos, int row) const
    {
        if (row < 0 || row >= rowCount() || !rowAt(row).available)
        {
            return false;
        }
        return copyGlyphRect(row).adjusted(-3, -3, 3, 3).contains(viewportPos);
    }

    // 设置悬停行并按需重绘。
    void HexInspectorRowView::setHoverRow(int row)
    {
        if (row == m_hoverRow)
        {
            return;
        }
        m_hoverRow = row;
        viewport()->update();
    }
}
