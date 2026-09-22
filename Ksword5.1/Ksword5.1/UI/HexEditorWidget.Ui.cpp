#include "HexEditorWidget.Internal.h"
#include "VisibleTableWidget.h"

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::ui::hex_editor_internal;

// ============================================================
// HexEditorWidget.Ui.cpp
// 作用：承载 UI 创建、信号连接、表格重建与高亮刷新逻辑。
// ============================================================

void HexEditorWidget::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(4);

    // 顶部工具条：摘要 + 行宽 + 查找/跳转/导出。
    QWidget* toolbarWidget = new QWidget(this);
    m_toolbarLayout = new QHBoxLayout(toolbarWidget);
    m_toolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolbarLayout->setSpacing(6);

    m_summaryLabel = new QLabel(toolbarWidget);
    m_summaryLabel->setText(QStringLiteral("长度: 0 字节 | 基址: 0x0000000000000000"));

    m_bytesPerRowCombo = new QComboBox(toolbarWidget);
    m_bytesPerRowCombo->addItem(QStringLiteral("8/行"), 8);
    m_bytesPerRowCombo->addItem(QStringLiteral("16/行"), 16);
    m_bytesPerRowCombo->addItem(QStringLiteral("32/行"), 32);
    m_bytesPerRowCombo->addItem(QStringLiteral("48/行"), 48);
    m_bytesPerRowCombo->addItem(QStringLiteral("64/行"), 64);
    m_bytesPerRowCombo->setToolTip(QStringLiteral("设置每行显示字节数"));

    m_findButton = new QToolButton(toolbarWidget);
    m_findButton->setText(QStringLiteral("查找"));
    m_findButton->setToolTip(QStringLiteral("打开查找面板（Ctrl+F）"));

    m_jumpButton = new QToolButton(toolbarWidget);
    m_jumpButton->setText(QStringLiteral("跳转"));
    m_jumpButton->setToolTip(QStringLiteral("打开跳转面板（Ctrl+G）"));

    m_exportButton = new QToolButton(toolbarWidget);
    m_exportButton->setText(QStringLiteral("导出"));
    m_exportButton->setToolTip(QStringLiteral("导出当前缓冲区"));

    const QString toolbarButtonStyle = buildToolbarButtonStyle();
    m_findButton->setStyleSheet(toolbarButtonStyle);
    m_jumpButton->setStyleSheet(toolbarButtonStyle);
    m_exportButton->setStyleSheet(toolbarButtonStyle);
    m_bytesPerRowCombo->setStyleSheet(buildInputStyle());

    m_toolbarLayout->addWidget(m_summaryLabel, 1);
    m_toolbarLayout->addWidget(new QLabel(QStringLiteral("行宽"), toolbarWidget));
    m_toolbarLayout->addWidget(m_bytesPerRowCombo);
    m_toolbarLayout->addWidget(m_findButton);
    m_toolbarLayout->addWidget(m_jumpButton);
    m_toolbarLayout->addWidget(m_exportButton);

    m_rootLayout->addWidget(toolbarWidget);

    // 查找面板：默认隐藏，按需显示。
    m_findPanel = new QWidget(this);
    m_findLayout = new QHBoxLayout(m_findPanel);
    m_findLayout->setContentsMargins(0, 0, 0, 0);
    m_findLayout->setSpacing(6);

    m_findModeCombo = new QComboBox(m_findPanel);
    m_findModeCombo->addItem(QStringLiteral("HEX字节"), static_cast<int>(SearchMode::HexBytes));
    m_findModeCombo->addItem(QStringLiteral("ASCII文本"), static_cast<int>(SearchMode::AsciiText));
    m_findModeCombo->addItem(QStringLiteral("UTF-16文本"), static_cast<int>(SearchMode::Utf16Text));
    m_findModeCombo->setToolTip(QStringLiteral("查找模式"));

    m_findEdit = new QLineEdit(m_findPanel);
    m_findEdit->setPlaceholderText(QStringLiteral("HEX模式示例：4D 5A ?? 90；ASCII模式示例：HTTP"));
    m_findEdit->setToolTip(QStringLiteral("输入查找内容，回车查找下一个"));

    m_findPrevButton = new QToolButton(m_findPanel);
    m_findPrevButton->setText(QStringLiteral("上一个"));
    m_findPrevButton->setToolTip(QStringLiteral("跳转到上一个命中（Shift+F3）"));

    m_findNextButton = new QToolButton(m_findPanel);
    m_findNextButton->setText(QStringLiteral("下一个"));
    m_findNextButton->setToolTip(QStringLiteral("跳转到下一个命中（F3）"));

    m_findCloseButton = new QToolButton(m_findPanel);
    m_findCloseButton->setText(QStringLiteral("关闭"));
    m_findCloseButton->setToolTip(QStringLiteral("关闭查找面板"));

    m_findResultLabel = new QLabel(QStringLiteral("命中: -"), m_findPanel);

    m_findModeCombo->setStyleSheet(buildInputStyle());
    m_findEdit->setStyleSheet(buildInputStyle());
    m_findPrevButton->setStyleSheet(toolbarButtonStyle);
    m_findNextButton->setStyleSheet(toolbarButtonStyle);
    m_findCloseButton->setStyleSheet(toolbarButtonStyle);

    m_findLayout->addWidget(new QLabel(QStringLiteral("查找"), m_findPanel));
    m_findLayout->addWidget(m_findModeCombo);
    m_findLayout->addWidget(m_findEdit, 1);
    m_findLayout->addWidget(m_findPrevButton);
    m_findLayout->addWidget(m_findNextButton);
    m_findLayout->addWidget(m_findResultLabel);
    m_findLayout->addWidget(m_findCloseButton);

    m_findPanel->setVisible(false);
    m_rootLayout->addWidget(m_findPanel);

    // 跳转面板：默认隐藏，支持地址/偏移/行号。
    m_jumpPanel = new QWidget(this);
    m_jumpLayout = new QHBoxLayout(m_jumpPanel);
    m_jumpLayout->setContentsMargins(0, 0, 0, 0);
    m_jumpLayout->setSpacing(6);

    m_jumpModeCombo = new QComboBox(m_jumpPanel);
    m_jumpModeCombo->addItem(QStringLiteral("绝对地址"), 0);
    m_jumpModeCombo->addItem(QStringLiteral("相对偏移"), 1);
    m_jumpModeCombo->addItem(QStringLiteral("行号"), 2);
    m_jumpModeCombo->setToolTip(QStringLiteral("跳转模式"));

    m_jumpEdit = new QLineEdit(m_jumpPanel);
    m_jumpEdit->setPlaceholderText(QStringLiteral("输入十进制或 0x 十六进制数值"));
    m_jumpEdit->setToolTip(QStringLiteral("例如：0x401000 / 256 / 0x20"));

    m_jumpApplyButton = new QToolButton(m_jumpPanel);
    m_jumpApplyButton->setText(QStringLiteral("执行"));
    m_jumpApplyButton->setToolTip(QStringLiteral("执行跳转"));

    m_jumpCloseButton = new QToolButton(m_jumpPanel);
    m_jumpCloseButton->setText(QStringLiteral("关闭"));
    m_jumpCloseButton->setToolTip(QStringLiteral("关闭跳转面板"));

    m_jumpModeCombo->setStyleSheet(buildInputStyle());
    m_jumpEdit->setStyleSheet(buildInputStyle());
    m_jumpApplyButton->setStyleSheet(toolbarButtonStyle);
    m_jumpCloseButton->setStyleSheet(toolbarButtonStyle);

    m_jumpLayout->addWidget(new QLabel(QStringLiteral("跳转"), m_jumpPanel));
    m_jumpLayout->addWidget(m_jumpModeCombo);
    m_jumpLayout->addWidget(m_jumpEdit, 1);
    m_jumpLayout->addWidget(m_jumpApplyButton);
    m_jumpLayout->addWidget(m_jumpCloseButton);

    m_jumpPanel->setVisible(false);
    m_rootLayout->addWidget(m_jumpPanel);

    // 主视图区：HEX 与 ASCII 两个页面。
    m_viewTabWidget = new QTabWidget(this);
    m_viewTabWidget->setDocumentMode(true);
    m_hexViewPage = new QWidget(m_viewTabWidget);
    QVBoxLayout* hexPageLayout = new QVBoxLayout(m_hexViewPage);
    hexPageLayout->setContentsMargins(0, 0, 0, 0);
    hexPageLayout->setSpacing(0);

    // HEX 页面主表：地址列 + 字节列 + ASCII 列。
    m_hexTable = new ks::ui::VisibleTableWidget(m_hexViewPage);
    ks::ui::SetPreserveCustomTableHeaderStyle(m_hexTable, true);
    m_hexTable->setColumnCount(m_bytesPerRow + 2);
    m_hexTable->setRowCount(1);
    // 使用 ExtendedSelection：
    // - 线性跨行选区在二维表格中并非严格矩形；
    // - ContiguousSelection 会主动约束并吞掉部分选中状态，导致视觉高亮异常。
    m_hexTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_hexTable->setSelectionBehavior(QAbstractItemView::SelectItems);
    m_hexTable->setEditTriggers(
        QAbstractItemView::AnyKeyPressed
        | QAbstractItemView::EditKeyPressed
        | QAbstractItemView::SelectedClicked
        | QAbstractItemView::DoubleClicked);
    m_hexTable->setAlternatingRowColors(true);
    m_hexTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_hexTable->verticalHeader()->setVisible(false);
    m_hexTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_hexTable->horizontalHeader()->setStretchLastSection(true);
    m_hexTable->horizontalHeader()->setStyleSheet(buildHeaderStyle());
    m_hexTable->setShowGrid(false);
    m_hexTable->setFrameShape(QFrame::NoFrame);
    m_hexTable->setStyleSheet(
        QStringLiteral(
            "QTableView{"
            "  border:none;"
            "  gridline-color:transparent;"
            "  outline:none;"
            "  background:%1;"
            "  alternate-background-color:%2;"
            "  color:%3;"
            "}"
            "QTableView::item{"
            "  border:none;"
            "  padding:0 3px;"
            "  color:%3;"
            "}"
        "QTableCornerButton::section{"
            "  background:transparent; /* %1 */"
            "  border:none;"
            "}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::SurfaceAltHex())
        .arg(KswordTheme::TextPrimaryHex()));

    // 表格字体加大并固定等宽，便于编辑十六进制内容。
    QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    // 系统等宽字体缺少中文字形时 Windows 会回退到宋体，显式指定雅黑承接中文。
    fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });
    fixedFont.setPointSize(std::max(fixedFont.pointSize(), 13));
    // ksword_preserve_custom_font 作用：阻止全局表格字体刷新覆盖 HEX 对齐所需的等宽字体。
    m_hexTable->setProperty("ksword_preserve_custom_font", true);
    m_hexTable->horizontalHeader()->setProperty("ksword_preserve_custom_font", true);
    m_hexTable->verticalHeader()->setProperty("ksword_preserve_custom_font", true);
    m_hexTable->setFont(fixedFont);
    m_hexTable->horizontalHeader()->setFont(fixedFont);
    m_hexTable->verticalHeader()->setFont(fixedFont);

    // 紧凑行高：以字体行高为基准只加 4px 上下余白，避免 Qt 默认 margin 吃掉大量空间。
    // QFontMetrics::height() = ascent + descent，是文字实际占用的像素高度。
    const int compactRowHeight = QFontMetrics(fixedFont).height() + 4;
    m_hexTable->verticalHeader()->setDefaultSectionSize(compactRowHeight);
    m_hexTable->verticalHeader()->setMinimumSectionSize(compactRowHeight);

    // 鼠标悬浮显示 I-beam，强调“可直接输入”编辑体验。
    m_hexTable->viewport()->setCursor(Qt::IBeamCursor);
    m_hexTable->setCursor(Qt::IBeamCursor);
    m_hexTable->viewport()->installEventFilter(this);
    hexPageLayout->addWidget(m_hexTable, 1);
    m_viewTabWidget->addTab(m_hexViewPage, QStringLiteral("HEX"));

    m_asciiViewPage = new QWidget(m_viewTabWidget);
    QVBoxLayout* asciiPageLayout = new QVBoxLayout(m_asciiViewPage);
    asciiPageLayout->setContentsMargins(0, 0, 0, 0);
    asciiPageLayout->setSpacing(0);
    m_asciiEditor = new CodeEditorWidget(m_asciiViewPage);
    m_asciiEditor->setReadOnly(true);
    m_asciiEditor->setLocalizedText(QStringLiteral("当前无数据。"));
    asciiPageLayout->addWidget(m_asciiEditor, 1);
    m_viewTabWidget->addTab(m_asciiViewPage, QStringLiteral("ASCII"));

    m_rootLayout->addWidget(m_viewTabWidget, 1);

    // 选区检查器：展示当前选中字节的多种解释结果。
    initializeSelectionInspector();
    m_rootLayout->addWidget(m_selectionInspectorPanel);

    // 底部状态文本：反馈操作成功/失败。
    m_statusLabel = new QLabel(QStringLiteral("就绪。"), this);
    m_rootLayout->addWidget(m_statusLabel);

    // 快捷键：查找、跳转、命中导航、复制。
    m_findShortcut = new QShortcut(QKeySequence::Find, this);
    m_jumpShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+G")), this);
    m_findNextShortcut = new QShortcut(QKeySequence::FindNext, this);
    m_findPrevShortcut = new QShortcut(QKeySequence::FindPrevious, this);
    m_copyHexShortcut = new QShortcut(QKeySequence::Copy, this);
    m_copyAsciiShortcut = new QShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+C")), this);

    updateHeaderText();
    updateSummaryLabel();
    updateSelectionInspector();
    refreshAsciiTabText();
}

void HexEditorWidget::initializeConnections()
{
    connect(m_bytesPerRowCombo, &QComboBox::currentIndexChanged, this, [this](const int indexValue)
        {
            if (indexValue < 0)
            {
                return;
            }
            const int bytesPerRowValue = m_bytesPerRowCombo->itemData(indexValue).toInt();
            setBytesPerRow(bytesPerRowValue);
        });

    connect(m_findButton, &QToolButton::clicked, this, [this]()
        {
            openFindPanel();
        });
    connect(m_jumpButton, &QToolButton::clicked, this, [this]()
        {
            openJumpPanel();
        });
    connect(m_exportButton, &QToolButton::clicked, this, [this]()
        {
            QMenu exportMenu(this);
            exportMenu.setStyleSheet(buildMenuStyle());
            QAction* binaryAction = exportMenu.addAction(QStringLiteral("导出二进制"));
            QAction* textAction = exportMenu.addAction(QStringLiteral("导出HEX文本"));
            QAction* selectedHexAction = exportMenu.addAction(QStringLiteral("导出选中HEX数据"));
            selectedHexAction->setEnabled(!collectSelectedOffsets().empty());
            QAction* selectedAction = exportMenu.exec(m_exportButton->mapToGlobal(QPoint(0, m_exportButton->height())));
            if (selectedAction == binaryAction)
            {
                exportBinaryFile();
                return;
            }
            if (selectedAction == textAction)
            {
                exportHexTextFile();
                return;
            }
            if (selectedAction == selectedHexAction)
            {
                exportSelectedHexDataFile();
            }
        });

    connect(m_findCloseButton, &QToolButton::clicked, this, [this]()
        {
            m_findPanel->setVisible(false);
        });
    connect(m_jumpCloseButton, &QToolButton::clicked, this, [this]()
        {
            m_jumpPanel->setVisible(false);
        });

    connect(m_findEdit, &QLineEdit::returnPressed, this, [this]()
        {
            const std::uint64_t currentOffset = selectedOffset();
            const std::uint64_t startOffset =
                (m_buffer.isEmpty() || currentOffset + 1 >= static_cast<std::uint64_t>(m_buffer.size()))
                ? 0
                : (currentOffset + 1);
            if (!ensureSearchResultReady(NavigateDirection::Next, startOffset))
            {
                return;
            }
            gotoMatchByDirection(NavigateDirection::Next, startOffset);
        });

    connect(m_findNextButton, &QToolButton::clicked, this, [this]()
        {
            const std::uint64_t currentOffset = selectedOffset();
            const std::uint64_t startOffset =
                (m_buffer.isEmpty() || currentOffset + 1 >= static_cast<std::uint64_t>(m_buffer.size()))
                ? 0
                : (currentOffset + 1);
            if (!ensureSearchResultReady(NavigateDirection::Next, startOffset))
            {
                return;
            }
            gotoMatchByDirection(NavigateDirection::Next, startOffset);
        });

    connect(m_findPrevButton, &QToolButton::clicked, this, [this]()
        {
            const std::uint64_t currentOffset = selectedOffset();
            const std::uint64_t startOffset =
                (m_buffer.isEmpty())
                ? 0
                : ((currentOffset == 0) ? static_cast<std::uint64_t>(m_buffer.size() - 1) : (currentOffset - 1));
            if (!ensureSearchResultReady(NavigateDirection::Previous, startOffset))
            {
                return;
            }
            gotoMatchByDirection(NavigateDirection::Previous, startOffset);
        });

    connect(m_jumpApplyButton, &QToolButton::clicked, this, [this]()
        {
            if (m_jumpEdit == nullptr || m_jumpModeCombo == nullptr)
            {
                return;
            }

            std::uint64_t targetValue = 0;
            if (!parseAddressNumber(m_jumpEdit->text(), targetValue))
            {
                updateStatusLabel(QStringLiteral("跳转失败：输入格式无效。"));
                return;
            }

            const int jumpMode = m_jumpModeCombo->currentData().toInt();
            bool jumpOk = false;
            if (jumpMode == 0)
            {
                jumpOk = jumpToAbsoluteAddress(targetValue);
            }
            else if (jumpMode == 1)
            {
                jumpOk = jumpToOffset(targetValue);
            }
            else
            {
                jumpOk = jumpToRow(targetValue);
            }

            if (jumpOk)
            {
                m_jumpPanel->setVisible(false);
            }
        });

    connect(m_jumpEdit, &QLineEdit::returnPressed, this, [this]()
        {
            m_jumpApplyButton->click();
        });

    connect(m_hexTable, &QTableWidget::itemChanged, this, [this](QTableWidgetItem* changedItem)
        {
            if (m_ignoreItemChanged || changedItem == nullptr)
            {
                return;
            }

            const int rowIndex = changedItem->row();
            const int columnIndex = changedItem->column();

            std::uint64_t offset = 0;
            if (!rowColumnToOffset(rowIndex, columnIndex, offset))
            {
                return;
            }

            bool parseOk = false;
            const int parsedValue = changedItem->text().trimmed().toInt(&parseOk, 16);
            if (!parseOk || parsedValue < 0 || parsedValue > 0xFF)
            {
                updateStatusLabel(QStringLiteral("编辑失败：请输入两位十六进制字节。"));
                m_ignoreItemChanged = true;
                const std::uint8_t oldByte = static_cast<std::uint8_t>(m_buffer.at(static_cast<int>(offset)));
                changedItem->setText(byteToHexText(oldByte));
                m_ignoreItemChanged = false;
                return;
            }

            const std::uint8_t oldValue = static_cast<std::uint8_t>(m_buffer.at(static_cast<int>(offset)));
            const std::uint8_t newValue = static_cast<std::uint8_t>(parsedValue);
            if (oldValue == newValue)
            {
                changedItem->setText(byteToHexText(newValue));
                return;
            }

            // 更新本地缓冲区后通知外部。
            m_buffer[static_cast<int>(offset)] = static_cast<char>(newValue);
            ++m_bufferRevision;

            // 统一把输入格式回写为两位大写 HEX。
            m_ignoreItemChanged = true;
            changedItem->setText(byteToHexText(newValue));
            updateAsciiCellByRow(rowIndex);
            refreshAsciiTabText();
            updateRowHighlightByRow(rowIndex);
            m_ignoreItemChanged = false;

            emit byteEdited(m_baseAddress + offset, oldValue, newValue);

            // 编辑成功后自动移动到下一个字节单元格，提升连续编辑效率。
            const std::uint64_t nextOffset = offset + 1;
            if (nextOffset < static_cast<std::uint64_t>(m_buffer.size()))
            {
                int nextRow = 0;
                int nextColumn = 0;
                if (offsetToRowColumn(nextOffset, nextRow, nextColumn))
                {
                    m_hexTable->setCurrentCell(nextRow, nextColumn);
                    m_hexTable->setFocus(Qt::OtherFocusReason);
                }
            }
        });

    connect(m_hexTable, &QTableWidget::currentCellChanged, this,
        [this](int currentRow, int currentColumn, int previousRow, int previousColumn)
        {
            Q_UNUSED(previousRow);
            Q_UNUSED(previousColumn);

            std::uint64_t offset = 0;
            if (!rowColumnToOffset(currentRow, currentColumn, offset))
            {
                updateSelectionInspector();
                return;
            }
            emit currentAddressChanged(m_baseAddress + offset);
            updateSelectionInspector();
        });

    connect(m_hexTable, &QTableWidget::itemSelectionChanged, this, [this]()
        {
            updateSelectionInspector();
        });

    connect(m_hexTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition)
        {
            QTableWidgetItem* clickedItem = m_hexTable->itemAt(localPosition);

            std::uint64_t clickedOffset = 0;
            bool hasByte = false;
            if (clickedItem != nullptr)
            {
                hasByte = rowColumnToOffset(clickedItem->row(), clickedItem->column(), clickedOffset);
                // 右键点击未选中单元格时，先把该字节设为当前选区，保证复制严格针对当前目标。
                if (hasByte && !clickedItem->isSelected())
                {
                    m_selectionVisualAsciiColumn = (clickedItem->column() == (m_bytesPerRow + 1));
                    selectRangeByOffset(clickedOffset, 1, false);
                }
            }

            const std::uint64_t absoluteAddress = m_baseAddress + clickedOffset;
            const bool hasSelection = !collectSelectedOffsets().empty();

            QMenu menu(this);
            menu.setStyleSheet(buildMenuStyle());
            QAction* copyHexAction = menu.addAction(QStringLiteral("复制 HEX"));
            QAction* copyAsciiAction = menu.addAction(QStringLiteral("复制 ASCII"));
            QAction* copyAddressAction = menu.addAction(QStringLiteral("复制地址"));
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
            menu.addSeparator();
            QAction* findAction = menu.addAction(QStringLiteral("查找（Ctrl+F）"));
            QAction* jumpAction = menu.addAction(QStringLiteral("跳转（Ctrl+G）"));
            menu.addSeparator();
            QAction* exportBinaryAction = menu.addAction(QStringLiteral("导出二进制"));
            QAction* exportTextAction = menu.addAction(QStringLiteral("导出 HEX 文本"));
            QAction* exportSelectedHexAction = menu.addAction(QStringLiteral("导出选中 HEX 数据"));

            if (!hasSelection)
            {
                copyHexAction->setEnabled(false);
                copyAsciiAction->setEnabled(false);
                exportSelectedHexAction->setEnabled(false);
            }

            if (!hasByte)
            {
                copyAddressAction->setEnabled(false);
                copyRowAction->setEnabled(false);
            }

            emit aboutToShowContextMenu(&menu, absoluteAddress, hasByte);

            QAction* selectedAction = menu.exec(m_hexTable->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            if (selectedAction == copyHexAction)
            {
                copySelectedAsHex();
                return;
            }
            if (selectedAction == copyAsciiAction)
            {
                copySelectedAsAscii();
                return;
            }
            if (selectedAction == copyAddressAction)
            {
                copyCurrentAddress();
                return;
            }
            if (selectedAction == copyRowAction)
            {
                copyCurrentRowDump();
                return;
            }
            if (selectedAction == findAction)
            {
                openFindPanel();
                return;
            }
            if (selectedAction == jumpAction)
            {
                openJumpPanel();
                return;
            }
            if (selectedAction == exportBinaryAction)
            {
                exportBinaryFile();
                return;
            }
            if (selectedAction == exportTextAction)
            {
                exportHexTextFile();
                return;
            }
            if (selectedAction == exportSelectedHexAction)
            {
                exportSelectedHexDataFile();
            }
        });

    connect(m_findShortcut, &QShortcut::activated, this, [this]()
        {
            openFindPanel();
        });
    connect(m_jumpShortcut, &QShortcut::activated, this, [this]()
        {
            openJumpPanel();
        });
    connect(m_findNextShortcut, &QShortcut::activated, this, [this]()
        {
            m_findNextButton->click();
        });
    connect(m_findPrevShortcut, &QShortcut::activated, this, [this]()
        {
            m_findPrevButton->click();
        });
    connect(m_copyHexShortcut, &QShortcut::activated, this, [this]()
        {
            copySelectedAsHex();
        });
    connect(m_copyAsciiShortcut, &QShortcut::activated, this, [this]()
        {
            copySelectedAsAscii();
        });

    connect(m_viewTabWidget, &QTabWidget::currentChanged, this, [this](const int indexValue)
        {
            const bool hexPageActive = (indexValue == 0);
            if (m_selectionInspectorPanel != nullptr)
            {
                m_selectionInspectorPanel->setVisible(hexPageActive);
            }
            if (!hexPageActive)
            {
                refreshAsciiTabText();
            }
        });
}

void HexEditorWidget::rebuildTable()
{
    if (m_hexTable == nullptr)
    {
        return;
    }

    // 重建前先更新表头，确保列数和 m_bytesPerRow 同步。
    updateHeaderText();

    const int rowCount = m_buffer.isEmpty()
        ? 1
        : ((m_buffer.size() + m_bytesPerRow - 1) / m_bytesPerRow);

    m_ignoreItemChanged = true;
    m_hexTable->clearContents();
    m_hexTable->setRowCount(rowCount);

    const QColor matchColor = buildMatchColor();
    const QColor currentMatchColor = buildCurrentMatchColor();

    for (int rowIndex = 0; rowIndex < rowCount; ++rowIndex)
    {
        const std::uint64_t rowOffset = static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(m_bytesPerRow);

        QTableWidgetItem* addressItem = new QTableWidgetItem(
            QStringLiteral("0x%1").arg(
                static_cast<qulonglong>(m_baseAddress + rowOffset),
                16,
                16,
                QChar('0')).toUpper());
        addressItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        m_hexTable->setItem(rowIndex, 0, addressItem);

        QString asciiText;
        asciiText.reserve(m_bytesPerRow);

        for (int byteColumn = 0; byteColumn < m_bytesPerRow; ++byteColumn)
        {
            const std::uint64_t byteOffset = rowOffset + static_cast<std::uint64_t>(byteColumn);
            QTableWidgetItem* byteItem = nullptr;

            if (byteOffset < static_cast<std::uint64_t>(m_buffer.size()))
            {
                const std::uint8_t byteValue = static_cast<std::uint8_t>(m_buffer.at(static_cast<int>(byteOffset)));
                byteItem = new QTableWidgetItem(byteToHexText(byteValue));

                Qt::ItemFlags flags = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
                if (m_editable)
                {
                    flags |= Qt::ItemIsEditable;
                }
                byteItem->setFlags(flags);

                const bool printable = (byteValue >= 32 && byteValue <= 126);
                asciiText.push_back(printable ? QChar(byteValue) : QChar('.'));

                // 普通命中高亮。
                if (byteOffset < static_cast<std::uint64_t>(m_matchMask.size()) && m_matchMask.at(static_cast<int>(byteOffset)) != 0)
                {
                    byteItem->setBackground(matchColor);
                }

                // 当前命中高亮优先级更高。
                if (m_currentMatchIndex >= 0 &&
                    m_currentMatchIndex < static_cast<int>(m_matchOffsets.size()) &&
                    byteOffset >= m_matchOffsets[static_cast<std::size_t>(m_currentMatchIndex)] &&
                    byteOffset < m_matchOffsets[static_cast<std::size_t>(m_currentMatchIndex)] +
                    static_cast<std::uint64_t>(std::max(1, m_currentMatchLength)))
                {
                    byteItem->setBackground(currentMatchColor);
                }
            }
            else
            {
                byteItem = new QTableWidgetItem(QStringLiteral("--"));
                byteItem->setFlags(Qt::ItemIsEnabled);
                asciiText.push_back(' ');
            }

            m_hexTable->setItem(rowIndex, byteColumn + 1, byteItem);
        }

        QTableWidgetItem* asciiItem = new QTableWidgetItem(asciiText);
        // ASCII 列允许被选中，满足“在 ASCII 列跨行高亮”的交互需求。
        asciiItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        m_hexTable->setItem(rowIndex, m_bytesPerRow + 1, asciiItem);
    }

    m_ignoreItemChanged = false;

    if (m_buffer.isEmpty())
    {
        m_linearSelectDragging = false;
        m_linearSelectAnchorValid = false;
        m_linearSelectAnchorOffset = 0;
        m_selectionVisualAsciiColumn = false;
    }

    refreshAsciiTabText();
}

void HexEditorWidget::updateHeaderText()
{
    if (m_hexTable == nullptr)
    {
        return;
    }

    m_hexTable->setColumnCount(m_bytesPerRow + 2);

    QStringList headerList;
    headerList.reserve(m_bytesPerRow + 2);
    headerList.push_back(QStringLiteral("地址"));

    for (int columnIndex = 0; columnIndex < m_bytesPerRow; ++columnIndex)
    {
        headerList.push_back(QStringLiteral("%1").arg(columnIndex, 2, 16, QChar('0')).toUpper());
    }
    headerList.push_back(QStringLiteral("ASCII"));
    m_hexTable->setHorizontalHeaderLabels(headerList);
}

void HexEditorWidget::updateSummaryLabel()
{
    if (m_summaryLabel == nullptr)
    {
        return;
    }

    m_summaryLabel->setText(
        QStringLiteral("长度: %1 字节 | 基址: %2 | 行宽: %3 | 模式: %4")
        .arg(static_cast<qulonglong>(m_buffer.size()))
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(m_baseAddress), 16, 16, QChar('0')).toUpper())
        .arg(m_bytesPerRow)
        .arg(m_editable ? QStringLiteral("可编辑") : QStringLiteral("只读")));
}

void HexEditorWidget::updateStatusLabel(const QString& statusText)
{
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(statusText);
    }
}

void HexEditorWidget::refreshAsciiTabText()
{
    if (m_asciiEditor == nullptr)
    {
        return;
    }

    if (m_buffer.isEmpty())
    {
        m_asciiEditor->setLocalizedText(QStringLiteral("当前无数据。"));
        return;
    }

    const int safeBytesPerRow = std::max(1, m_bytesPerRow);
    QString asciiText;
    asciiText.reserve(m_buffer.size() + (m_buffer.size() / safeBytesPerRow) + 8);

    for (int index = 0; index < m_buffer.size(); ++index)
    {
        const std::uint8_t byteValue = static_cast<std::uint8_t>(m_buffer.at(index));
        const bool printable = (byteValue >= 32 && byteValue <= 126);
        asciiText.push_back(printable ? QChar(byteValue) : QChar('.'));

        if (((index + 1) % safeBytesPerRow) == 0 && (index + 1) < m_buffer.size())
        {
            asciiText.push_back(QChar('\n'));
        }
    }

    m_asciiEditor->setRawText(asciiText);
}

void HexEditorWidget::updateAsciiCellByRow(const int rowIndex)
{
    if (rowIndex < 0 || rowIndex >= m_hexTable->rowCount())
    {
        return;
    }

    const std::uint64_t rowOffset = static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(m_bytesPerRow);
    QString asciiText;
    asciiText.reserve(m_bytesPerRow);

    for (int byteColumn = 0; byteColumn < m_bytesPerRow; ++byteColumn)
    {
        const std::uint64_t byteOffset = rowOffset + static_cast<std::uint64_t>(byteColumn);
        if (byteOffset < static_cast<std::uint64_t>(m_buffer.size()))
        {
            const std::uint8_t byteValue = static_cast<std::uint8_t>(m_buffer.at(static_cast<int>(byteOffset)));
            const bool printable = (byteValue >= 32 && byteValue <= 126);
            asciiText.push_back(printable ? QChar(byteValue) : QChar('.'));
        }
        else
        {
            asciiText.push_back(' ');
        }
    }

    QTableWidgetItem* asciiItem = m_hexTable->item(rowIndex, m_bytesPerRow + 1);
    if (asciiItem == nullptr)
    {
        asciiItem = new QTableWidgetItem();
        // 维持 ASCII 列可选中属性，避免重建后丢失跨行选区视觉反馈。
        asciiItem->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        m_hexTable->setItem(rowIndex, m_bytesPerRow + 1, asciiItem);
    }
    asciiItem->setText(asciiText);
}

void HexEditorWidget::updateRowHighlightByRow(const int rowIndex)
{
    if (rowIndex < 0 || rowIndex >= m_hexTable->rowCount())
    {
        return;
    }

    const std::uint64_t rowOffset = static_cast<std::uint64_t>(rowIndex) * static_cast<std::uint64_t>(m_bytesPerRow);
    const QColor matchColor = buildMatchColor();
    const QColor currentMatchColor = buildCurrentMatchColor();
    const QColor selectionColor = buildSelectionColor();

    for (int byteColumn = 0; byteColumn < m_bytesPerRow; ++byteColumn)
    {
        const std::uint64_t byteOffset = rowOffset + static_cast<std::uint64_t>(byteColumn);
        QTableWidgetItem* byteItem = m_hexTable->item(rowIndex, byteColumn + 1);
        if (byteItem == nullptr)
        {
            continue;
        }

        byteItem->setBackground(QBrush());
        if (byteOffset >= static_cast<std::uint64_t>(m_buffer.size()))
        {
            continue;
        }

        if (!m_selectionVisualAsciiColumn &&
            m_selectionRangeValid &&
            byteOffset >= std::min(m_selectionRangeStartOffset, m_selectionRangeEndOffset) &&
            byteOffset <= std::max(m_selectionRangeStartOffset, m_selectionRangeEndOffset))
        {
            byteItem->setBackground(selectionColor);
            continue;
        }

        if (byteOffset < static_cast<std::uint64_t>(m_matchMask.size()) && m_matchMask.at(static_cast<int>(byteOffset)) != 0)
        {
            byteItem->setBackground(matchColor);
        }

        if (m_currentMatchIndex >= 0 &&
            m_currentMatchIndex < static_cast<int>(m_matchOffsets.size()) &&
            byteOffset >= m_matchOffsets[static_cast<std::size_t>(m_currentMatchIndex)] &&
            byteOffset < m_matchOffsets[static_cast<std::size_t>(m_currentMatchIndex)] +
            static_cast<std::uint64_t>(std::max(1, m_currentMatchLength)))
        {
            byteItem->setBackground(currentMatchColor);
        }
    }
}

