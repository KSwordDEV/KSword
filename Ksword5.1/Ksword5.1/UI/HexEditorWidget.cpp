#include "HexEditorWidget.Internal.h"

namespace ksword::ui::hex_editor_internal
{
    // kMinBytesPerRow：
    // - 每行最小字节数限制；
    // - 防止出现 0 或过小导致布局异常。
    constexpr int kMinBytesPerRow = 4;

    // kMaxBytesPerRow：
    // - 每行最大字节数限制；
    // - 限制过大列数导致表格性能恶化。
    constexpr int kMaxBytesPerRow = 64;

    // buildToolbarButtonStyle：
    // - 统一工具按钮样式；
    // - 常态无边框/透明背景，只在 hover/pressed 时才显示边框，减少视觉噪声。
    QString buildToolbarButtonStyle()
    {
        // 占位符编号必须与 arg() 调用一一对应：QString::arg 替换的是字符串里
        // 编号最小的 %n，而不是固定的 %1，删掉占位符却留着 arg 会让颜色整体错位。
        return QStringLiteral(
            "QToolButton {"
            "  border:1px solid transparent;"
            "  border-radius:3px;"
            "  padding:2px 6px;"
            "  background:transparent;"
            "  color:%1;"
            "}"
            "QToolButton:hover {"
            "  border:1px solid %2;"
            "  background:%3;"
            "  color:%5;"
            "}"
            "QToolButton:pressed {"
            "  border:1px solid %2;"
            "  background:%4;"
            "  color:%5;"
            "}")
            .arg(KswordTheme::TextPrimaryHex())      // %1
            .arg(KswordTheme::PrimaryBlueHex)        // %2
            .arg(KswordTheme::PrimaryBlueHoverHex)   // %3
            .arg(KswordTheme::PrimaryBluePressedHex) // %4
            .arg(QStringLiteral("palette(highlighted-text)")); // %5
    }

    // buildInputStyle：
    // - 查找/跳转输入框与下拉框统一样式。
    QString buildInputStyle()
    {
        return QStringLiteral(
            "QLineEdit {"
            "  border:1px solid %1;"
            "  border-radius:3px;"
            "  padding:2px 6px;"
            "  background:%2;"
            "  color:%3;"
            "}"
            "QLineEdit:focus {"
            "  border:1px solid %4;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::PrimaryBlueHex)
            + KswordTheme::ThemedComboBoxStyle();
    }

    // buildHeaderStyle：
    // - 表头统一主题样式，保证深浅模式下视觉一致；
    // - padding 压缩为 2px 上下 / 4px 左右，减少表头占高。
    QString buildHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section {"
            "  color:%1;"
            "  background:transparent; /* %2 */"
            "  border:none;"
            "  padding:2px 4px;"
            "  font-weight:600;"
            "}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex());
    }

    // buildMenuStyle：
    // - 为 HexEditor 内部右键菜单和导出菜单生成独立主题样式；
    // - 修复深色模式下菜单仍然白底的问题。
    QString buildMenuStyle()
    {
        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QMenu::item{"
            "  padding:6px 18px;"
            "  background:transparent;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:%5;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:4px 8px;"
            "}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    // buildMatchColor：
    // - 返回普通命中字节背景色；
    // - 深色模式使用偏墨绿，浅色模式使用淡黄。
    QColor buildMatchColor()
    {
        if (KswordTheme::IsDarkModeEnabled())
        {
            return KswordTheme::EditorMatchColor();
        }
        return KswordTheme::EditorMatchColor();
    }

    // buildCurrentMatchColor：
    // - 返回当前命中字节背景色；
    // - 颜色稍强，方便快速定位。
    QColor buildCurrentMatchColor()
    {
        if (KswordTheme::IsDarkModeEnabled())
        {
            return KswordTheme::EditorCurrentMatchColor();
        }
        return KswordTheme::EditorCurrentMatchColor();
    }

    // buildSelectionColor：
    // - 返回当前用户选区的高亮色；
    // - 优先保证拖拽选区比查找高亮更显眼。
    QColor buildSelectionColor()
    {
        if (KswordTheme::IsDarkModeEnabled())
        {
            return KswordTheme::EditorSelectionColor();
        }
        return KswordTheme::EditorSelectionColor();
    }

    // byteToHexText：
    // - 把单字节转为两位大写 HEX 文本。
    QString byteToHexText(const std::uint8_t byteValue)
    {
        return QStringLiteral("%1").arg(byteValue, 2, 16, QChar('0')).toUpper();
    }

    // normalizeBytesPerRow：
    // - 对每行字节数进行安全夹取；
    // - 防止非法值影响布局。
    int normalizeBytesPerRow(const int requestedBytesPerRow)
    {
        return std::clamp(requestedBytesPerRow, kMinBytesPerRow, kMaxBytesPerRow);
    }
}


using namespace ksword::ui::hex_editor_internal;

HexEditorWidget::HexEditorWidget(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    // 初始化为空数据视图。
    clearData();
}

HexEditorWidget::~HexEditorWidget() = default;

void HexEditorWidget::setRegionData(
    const void* regionPointer,
    const std::size_t regionSize,
    const std::uint64_t baseAddress)
{
    // 传入空指针或长度为 0 时，统一视为清空操作。
    if (regionPointer == nullptr || regionSize == 0)
    {
        m_baseAddress = baseAddress;
        m_buffer.clear();
        ++m_bufferRevision;
        clearSearchState();
        m_selectionRangeValid = false;
        m_selectionRangeStartOffset = 0;
        m_selectionRangeEndOffset = 0;
        m_selectionVisualAsciiColumn = false;
        rebuildTable();
        updateSummaryLabel();
        updateSelectionInspector();
        updateStatusLabel(QStringLiteral("当前区域为空。"));
        return;
    }

    // 复制输入内存区域，避免外部缓冲区生命周期影响控件。
    const QByteArray incomingBytes(
        static_cast<const char*>(regionPointer),
        static_cast<int>(regionSize));
    setByteArray(incomingBytes, baseAddress);
}

void HexEditorWidget::setByteArray(const QByteArray& bytes, const std::uint64_t baseAddress)
{
    // 覆盖当前缓冲区，更新基址和版本号。
    m_buffer = bytes;
    m_baseAddress = baseAddress;
    ++m_bufferRevision;

    // 新数据进入后清空旧查找结果，避免高亮错位。
    clearSearchState();
    m_selectionRangeValid = false;
    m_selectionRangeStartOffset = 0;
    m_selectionRangeEndOffset = 0;
    m_selectionVisualAsciiColumn = false;
    rebuildTable();
    updateSummaryLabel();
    updateSelectionInspector();

    updateStatusLabel(
        QStringLiteral("加载完成：%1 字节。")
        .arg(static_cast<qulonglong>(m_buffer.size())));
}

void HexEditorWidget::clearData()
{
    // clearData 直接复用 setByteArray，保持行为一致。
    setByteArray(QByteArray(), m_baseAddress);
}

void HexEditorWidget::setEditable(const bool editable)
{
    if (m_editable == editable)
    {
        return;
    }

    m_editable = editable;
    rebuildTable();
    updateSummaryLabel();
    updateSelectionInspector();
}

bool HexEditorWidget::isEditable() const
{
    return m_editable;
}

void HexEditorWidget::setBytesPerRow(const int bytesPerRow)
{
    const int normalizedBytesPerRow = normalizeBytesPerRow(bytesPerRow);
    if (normalizedBytesPerRow == m_bytesPerRow)
    {
        return;
    }

    m_bytesPerRow = normalizedBytesPerRow;
    if (m_bytesPerRowCombo != nullptr)
    {
        const int comboIndex = m_bytesPerRowCombo->findData(m_bytesPerRow);
        if (comboIndex >= 0)
        {
            m_bytesPerRowCombo->setCurrentIndex(comboIndex);
        }
    }

    rebuildTable();
    updateSummaryLabel();
    updateSelectionInspector();
}

int HexEditorWidget::bytesPerRow() const
{
    return m_bytesPerRow;
}

bool HexEditorWidget::jumpToAbsoluteAddress(const std::uint64_t absoluteAddress)
{
    if (absoluteAddress < m_baseAddress)
    {
        updateStatusLabel(QStringLiteral("跳转失败：地址小于基址。"));
        return false;
    }

    const std::uint64_t offset = absoluteAddress - m_baseAddress;
    return jumpToOffset(offset);
}

bool HexEditorWidget::jumpToOffset(const std::uint64_t offset)
{
    if (m_buffer.isEmpty())
    {
        updateStatusLabel(QStringLiteral("跳转失败：当前无可显示数据。"));
        return false;
    }

    if (offset >= static_cast<std::uint64_t>(m_buffer.size()))
    {
        updateStatusLabel(QStringLiteral("跳转失败：偏移超出范围。"));
        return false;
    }

    int row = -1;
    int column = -1;
    if (!offsetToRowColumn(offset, row, column))
    {
        updateStatusLabel(QStringLiteral("跳转失败：目标单元格不可用。"));
        return false;
    }

    m_hexTable->setCurrentCell(row, column);
    m_hexTable->scrollToItem(m_hexTable->item(row, column), QAbstractItemView::PositionAtCenter);

    updateStatusLabel(
        QStringLiteral("已跳转到地址 %1。")
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(m_baseAddress + offset), 16, 16, QChar('0')).toUpper()));
    return true;
}

bool HexEditorWidget::jumpToRow(const std::uint64_t rowIndex)
{
    if (m_buffer.isEmpty())
    {
        updateStatusLabel(QStringLiteral("跳转失败：当前无可显示数据。"));
        return false;
    }

    const std::uint64_t offset = rowIndex * static_cast<std::uint64_t>(m_bytesPerRow);
    if (offset >= static_cast<std::uint64_t>(m_buffer.size()))
    {
        updateStatusLabel(QStringLiteral("跳转失败：行号超出范围。"));
        return false;
    }

    return jumpToOffset(offset);
}

void HexEditorWidget::openFindPanel()
{
    if (m_findPanel == nullptr)
    {
        return;
    }

    m_findPanel->setVisible(true);
    if (m_findEdit != nullptr)
    {
        m_findEdit->setFocus(Qt::ShortcutFocusReason);
        m_findEdit->selectAll();
    }
}

void HexEditorWidget::openJumpPanel()
{
    if (m_jumpPanel == nullptr)
    {
        return;
    }

    m_jumpPanel->setVisible(true);
    if (m_jumpEdit != nullptr)
    {
        m_jumpEdit->setFocus(Qt::ShortcutFocusReason);
        m_jumpEdit->selectAll();
    }
}

bool HexEditorWidget::setByteAtAbsoluteAddress(
    const std::uint64_t absoluteAddress,
    const std::uint8_t byteValue,
    const bool keepSelection)
{
    if (absoluteAddress < m_baseAddress)
    {
        return false;
    }

    const std::uint64_t offset = absoluteAddress - m_baseAddress;
    if (offset >= static_cast<std::uint64_t>(m_buffer.size()))
    {
        return false;
    }

    m_buffer[static_cast<int>(offset)] = static_cast<char>(byteValue);
    ++m_bufferRevision;

    int row = -1;
    int column = -1;
    if (!offsetToRowColumn(offset, row, column))
    {
        return false;
    }

    // 回填时屏蔽 itemChanged，避免触发编辑信号。
    m_ignoreItemChanged = true;
    QTableWidgetItem* byteItem = m_hexTable->item(row, column);
    if (byteItem != nullptr)
    {
        byteItem->setText(byteToHexText(byteValue));
    }
    updateAsciiCellByRow(row);
    refreshAsciiTabText();
    updateRowHighlightByRow(row);
    m_ignoreItemChanged = false;
    updateSelectionInspector();

    if (keepSelection)
    {
        m_hexTable->setCurrentCell(row, column);
    }
    return true;
}

QByteArray HexEditorWidget::data() const
{
    return m_buffer;
}

std::size_t HexEditorWidget::regionSize() const
{
    return static_cast<std::size_t>(m_buffer.size());
}

std::uint64_t HexEditorWidget::baseAddress() const
{
    return m_baseAddress;
}

std::uint64_t HexEditorWidget::selectedAbsoluteAddress() const
{
    return m_baseAddress + selectedOffset();
}

std::uint64_t HexEditorWidget::selectedOffset() const
{
    if (m_hexTable == nullptr || m_hexTable->currentItem() == nullptr)
    {
        return 0;
    }

    const int currentRow = m_hexTable->currentItem()->row();
    const int currentColumn = m_hexTable->currentItem()->column();

    std::uint64_t offset = 0;
    if (!rowColumnToOffset(currentRow, currentColumn, offset))
    {
        return 0;
    }
    return offset;
}

bool HexEditorWidget::eventFilter(QObject* watched, QEvent* event)
{
    if (m_hexTable == nullptr || event == nullptr)
    {
        return QWidget::eventFilter(watched, event);
    }

    // 仅拦截十六进制表格视口，其他对象交给基类处理。
    if (watched != m_hexTable->viewport())
    {
        return QWidget::eventFilter(watched, event);
    }

    if (m_buffer.isEmpty())
    {
        return QWidget::eventFilter(watched, event);
    }

    // 鼠标按下：记录锚点并进入线性拖拽模式。
    if (event->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() != Qt::LeftButton)
        {
            return QWidget::eventFilter(watched, event);
        }

        std::uint64_t clickedOffset = 0;
        if (!viewportPosToOffset(mouseEvent->pos(), clickedOffset))
        {
            return true;
        }

        if (!(mouseEvent->modifiers() & Qt::ShiftModifier) || !m_linearSelectAnchorValid)
        {
            m_linearSelectAnchorOffset = clickedOffset;
            m_linearSelectAnchorValid = true;
        }

        // 记录本次拖拽起点是否在 ASCII 列：
        // - true：视觉高亮保留在 ASCII 列；
        // - false：视觉高亮保留在十六进制字节列。
        const int pressedColumnIndex = m_hexTable->columnAt(mouseEvent->pos().x());
        m_selectionVisualAsciiColumn = (pressedColumnIndex == (m_bytesPerRow + 1));

        m_linearSelectDragging = true;
        selectLinearRange(m_linearSelectAnchorOffset, clickedOffset, false);
        m_hexTable->setFocus(Qt::MouseFocusReason);
        return true;
    }

    // 鼠标拖动：按“文本式连续字节区间”更新选区。
    if (event->type() == QEvent::MouseMove)
    {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (!m_linearSelectDragging || !(mouseEvent->buttons() & Qt::LeftButton))
        {
            return QWidget::eventFilter(watched, event);
        }

        std::uint64_t hoverOffset = 0;
        if (!viewportPosToOffset(mouseEvent->pos(), hoverOffset))
        {
            return true;
        }

        selectLinearRange(m_linearSelectAnchorOffset, hoverOffset, true);
        return true;
    }

    // 鼠标释放：结束拖拽状态。
    if (event->type() == QEvent::MouseButtonRelease)
    {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton)
        {
            m_linearSelectDragging = false;
            return true;
        }
    }

    return QWidget::eventFilter(watched, event);
}
