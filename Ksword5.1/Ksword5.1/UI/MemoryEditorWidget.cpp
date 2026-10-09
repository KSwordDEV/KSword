#include "MemoryEditorWidget.h"
#include "CodeTextEdit.h"
#include "MemoryAssembly.h"
#include "HexEditorWidget.h"
#include "MemoryWorkbench/WorkbenchDisasmView.h"
#include "MemoryWorkbench/WorkbenchTextView.h"
#include "MemoryWorkbench/MemoryRowCanvas.h"
#include "X64DbgNavigation.h"
#include "Decompiler/GhidraDecompiler.h"
#include "TableHeaderSortingSupport.h"
#include "VisibleTableWidget.h"
#include "UI_All.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QEvent>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QShortcut>
#include <QSpinBox>
#include <QTabWidget>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

namespace ks::ui
{
    namespace
    {
        constexpr int kRowOffsetRole = Qt::UserRole + 41;
        constexpr qsizetype kComparisonPageRows = 256;

        QString trText(const QString& source)
        {
            return ks::i18n::sourceText(source);
        }

        QString addressText(std::uint64_t address)
        {
            return QStringLiteral("0x%1").arg(address, 16, 16, QLatin1Char('0')).toUpper();
        }

        QString byteText(const QByteArray& bytes)
        {
            return QString::fromLatin1(bytes.toHex(' ').toUpper());
        }

        QString asciiText(const QByteArray& bytes)
        {
            QString text;
            text.reserve(bytes.size());
            for (unsigned char byte : bytes)
                text += byte >= 32 && byte < 127 ? QChar(static_cast<char>(byte)) : QChar('.');
            return text;
        }

        QColor changeColor(const QPalette& palette, bool pending)
        {
            return KswordTheme::BlendColors(palette.color(QPalette::Base),
                KswordTheme::AccentColor(pending ? KswordTheme::AccentRole::Orange : KswordTheme::AccentRole::Cyan), 95);
        }
    }

    MemoryEditorWidget::MemoryEditorWidget(QWidget* parent) : QWidget(parent)
    {
        setObjectName(QStringLiteral("memory_snapshot_editor"));
        auto* layout = new QVBoxLayout(this);
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSpacing(4);
        auto* tools = new QHBoxLayout;
        m_architecture = new QComboBox(this);
        m_architecture->addItems({QStringLiteral("x86"), QStringLiteral("x64")});
        m_architecture->setCurrentIndex(1);
        m_architecture->setToolTip(trText(QStringLiteral("指令架构；可手动切换，物理地址和 CR3 无法自动判断目标位数。")));
        m_assemble = new QPushButton(trText(QStringLiteral("汇编编辑")), this);
        m_assemble->setToolTip(trText(QStringLiteral("双击指令或按 F2 可编辑汇编；Enter 填入缓存，Esc 取消。右键汇编编辑可预览并调整覆盖长度。")));
        tools->addWidget(new QLabel(trText(QStringLiteral("指令架构")), this));
        tools->addWidget(m_architecture);
        tools->addWidget(m_assemble);
        m_undo = new QPushButton(trText(QStringLiteral("撤销")), this);
        m_redo = new QPushButton(trText(QStringLiteral("重做")), this);
        m_undo->setToolTip(trText(QStringLiteral("撤销上一次缓存编辑（Ctrl+Z）；已应用到真实内存的写入不能在此撤销。")));
        m_redo->setToolTip(trText(QStringLiteral("重做缓存编辑（Ctrl+Y 或 Ctrl+Shift+Z）。")));
        tools->addWidget(m_undo);
        tools->addWidget(m_redo);
        m_highlightChanges = new QCheckBox(trText(QStringLiteral("变化高亮")), this);
        m_highlightChanges->setChecked(true);
        m_highlightChanges->setToolTip(trText(QStringLiteral("橙色为待应用修改，青色为同一目标和范围两次读取之间的变化；选区和搜索高亮优先显示。")));
        m_status = new QLabel(this);
        m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_status->setWordWrap(true);
        tools->addStretch();
        layout->addLayout(tools);
        auto* stateRow = new QHBoxLayout;
        stateRow->addWidget(m_highlightChanges);
        stateRow->addWidget(m_status, 1);
        layout->addLayout(stateRow);

        m_tabs = new QTabWidget(this);
        m_hex = new HexEditorWidget(m_tabs);
        m_hex->setBytesPerRow(16);
        m_hex->setHexOnlyView(true);
        m_tabs->addTab(m_hex, trText(QStringLiteral("十六进制")));
        auto* codePage = new QWidget(m_tabs);
        auto* codeLayout = new QVBoxLayout(codePage);
        codeLayout->setContentsMargins(0, 0, 0, 0);
        auto* navigation = new QHBoxLayout;
        m_decodeLabel = new QLabel(trText(QStringLiteral("反汇编起点")), codePage);
        navigation->addWidget(m_decodeLabel);
        m_decodeAddress = new QLineEdit(codePage);
        m_decodeAddress->setToolTip(trText(QStringLiteral("从此地址开始解码，避免从指令中间或无关数据处解码；地址必须在快照内。")));
        auto* decode = new QPushButton(trText(QStringLiteral("定位并解码")), codePage);
        navigation->addWidget(m_decodeAddress, 1);
        navigation->addWidget(decode);
        codeLayout->addLayout(navigation);
        m_decodeStatus = new QLabel(codePage);
        m_decodeStatus->setWordWrap(true);
        codeLayout->addWidget(m_decodeStatus);
        m_disassembly = new WorkbenchDisasmView(codePage);
        m_disassembly->setObjectName(QStringLiteral("memory_instruction_canvas"));
        codeLayout->addWidget(m_disassembly, 1);
        m_tabs->addTab(codePage, trText(QStringLiteral("反汇编")));
        m_text = new WorkbenchTextView(m_tabs);
        m_text->setObjectName(QStringLiteral("memory_text_canvas"));
        m_text->setBytesProvider(&m_bytesProvider);
        m_tabs->addTab(m_text, trText(QStringLiteral("文本")));
        auto* comparisonPage = new QWidget(m_tabs);
        auto* comparisonLayout = new QVBoxLayout(comparisonPage);
        comparisonLayout->setContentsMargins(0, 0, 0, 0);
        auto* comparisonTools = new QHBoxLayout;
        comparisonTools->addWidget(new QLabel(trText(QStringLiteral("对比基线")), comparisonPage));
        m_comparisonBaseline = new QComboBox(comparisonPage);
        m_comparisonBaseline->addItems({trText(QStringLiteral("读取基线")), trText(QStringLiteral("上次读取"))});
        m_onlyDifferences = new QCheckBox(trText(QStringLiteral("仅显示差异")), comparisonPage);
        m_onlyDifferences->setChecked(true);
        m_previousComparison = new QPushButton(trText(QStringLiteral("上一页")), comparisonPage);
        m_nextComparison = new QPushButton(trText(QStringLiteral("下一页")), comparisonPage);
        comparisonTools->addWidget(m_comparisonBaseline);
        comparisonTools->addWidget(m_onlyDifferences);
        comparisonTools->addStretch();
        comparisonTools->addWidget(m_previousComparison);
        comparisonTools->addWidget(m_nextComparison);
        comparisonLayout->addLayout(comparisonTools);
        m_comparisonStatus = new QLabel(comparisonPage);
        m_comparisonStatus->setWordWrap(true);
        comparisonLayout->addWidget(m_comparisonStatus);
        m_comparison = new VisibleTableWidget(comparisonPage);
        m_comparison->setObjectName(QStringLiteral("memory_comparison_table"));
        m_comparison->setColumnCount(6);
        m_comparison->setHorizontalHeaderLabels({trText(QStringLiteral("地址")), trText(QStringLiteral("基线字节")),
            trText(QStringLiteral("当前字节")), trText(QStringLiteral("基线文本")),
            trText(QStringLiteral("当前文本")), trText(QStringLiteral("变化字节数"))});
        m_comparison->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
        m_comparison->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_comparison->setSelectionMode(QAbstractItemView::SingleSelection);
        m_comparison->setEditTriggers(QAbstractItemView::NoEditTriggers);
        m_comparison->setAlternatingRowColors(true);
        m_comparison->verticalHeader()->hide();
        m_comparison->horizontalHeader()->setStretchLastSection(true);
        m_comparison->setSortingEnabled(false);
        SetTableHeaderClickSortingEnabled(m_comparison, false);
        m_comparison->setContextMenuPolicy(Qt::CustomContextMenu);
        comparisonLayout->addWidget(m_comparison, 1);
        m_tabs->addTab(comparisonPage, trText(QStringLiteral("对比")));
        layout->addWidget(m_tabs, 1);
        initializePseudocodeView();

        connect(m_undo, &QPushButton::clicked, this, &MemoryEditorWidget::undo);
        connect(m_redo, &QPushButton::clicked, this, &MemoryEditorWidget::redo);
        auto* undoShortcut = new QShortcut(QKeySequence::Undo, this);
        undoShortcut->setContext(Qt::WidgetWithChildrenShortcut);
        connect(undoShortcut, &QShortcut::activated, this, &MemoryEditorWidget::undo);
        for (const auto& key : {QKeySequence(Qt::CTRL | Qt::Key_Y), QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_Z)})
        {
            auto* shortcut = new QShortcut(key, this);
            shortcut->setContext(Qt::WidgetWithChildrenShortcut);
            connect(shortcut, &QShortcut::activated, this, &MemoryEditorWidget::redo);
        }
        connect(m_highlightChanges, &QCheckBox::toggled, this, [this]() {
            updateHighlights();
            if (m_tabs->currentIndex() == 1) rebuildDisassembly();
            if (m_tabs->currentIndex() == 2) rebuildText();
            if (m_tabs->currentIndex() == 3) renderComparisonPage();
        });
        connect(m_comparisonBaseline, &QComboBox::currentIndexChanged, this, [this]() {
            m_comparisonPage = 0;
            rebuildComparison();
        });
        connect(m_onlyDifferences, &QCheckBox::toggled, this, [this]() {
            m_comparisonPage = 0;
            rebuildComparison();
        });
        connect(m_previousComparison, &QPushButton::clicked, this, [this]() {
            if (m_comparisonPage > 0) --m_comparisonPage;
            renderComparisonPage();
        });
        connect(m_nextComparison, &QPushButton::clicked, this, [this]() {
            if ((m_comparisonPage + 1) * kComparisonPageRows < m_comparisonRows.size()) ++m_comparisonPage;
            renderComparisonPage();
        });
        connect(m_comparison, &QTableWidget::cellDoubleClicked, this, [this](int row) {
            const auto* cell = m_comparison->item(row, 0);
            if (!cell) return;
            const auto offset = cell->data(kRowOffsetRole).toULongLong();
            m_tabs->setCurrentIndex(0);
            jumpToAddress(m_base + offset);
        });
        connect(m_comparison, &QTableWidget::currentCellChanged, this, [this](int row) {
            const auto* cell = m_comparison->item(row, 0);
            if (m_syncing || !cell) return;
            const auto address = m_base + cell->data(kRowOffsetRole).toULongLong();
            m_syncing = true;
            m_hex->jumpToAbsoluteAddress(address);
            m_syncing = false;
            emit currentAddressChanged(address);
        });
        connect(m_comparison, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position) {
            const auto index = m_comparison->indexAt(position);
            if (!index.isValid()) return;
            m_comparison->setCurrentCell(index.row(), 0);
            const auto* addressItem = m_comparison->item(index.row(), 0);
            const auto* beforeItem = m_comparison->item(index.row(), 1);
            const auto* afterItem = m_comparison->item(index.row(), 2);
            if (!addressItem || !beforeItem || !afterItem) return;
            const auto address = m_base + addressItem->data(kRowOffsetRole).toULongLong();
            const auto before = beforeItem->text();
            const auto after = afterItem->text();
            const auto revision = m_snapshotRevision;
            // 菜单进入嵌套事件循环，父编辑器可能先被销毁；堆对象与双守卫避免释放栈对象。
            const QPointer<MemoryEditorWidget> self(this);
            QPointer<QMenu> menu = new QMenu(this);
            menu->setStyleSheet(KswordTheme::ContextMenuStyle());
            auto* copyAddress = menu->addAction(trText(QStringLiteral("复制地址")));
            auto* copyBefore = menu->addAction(trText(QStringLiteral("复制基线字节")));
            auto* copyAfter = menu->addAction(trText(QStringLiteral("复制当前字节")));
            auto* locate = menu->addAction(trText(QStringLiteral("在十六进制视图中定位")));
            auto* selected = menu->exec(m_comparison->viewport()->mapToGlobal(position));
            if (!self || !menu)
            {
                return;
            }
            // 动作指针随菜单销毁；先冻结选择，再立即释放菜单，后续不引用动作或菜单。
            const bool copyAddressSelected = selected == copyAddress;
            const bool copyBeforeSelected = selected == copyBefore;
            const bool copyAfterSelected = selected == copyAfter;
            const bool locateSelected = selected == locate;
            delete menu.data();
            if (copyAddressSelected) QApplication::clipboard()->setText(addressText(address));
            if (copyBeforeSelected) QApplication::clipboard()->setText(before);
            if (copyAfterSelected) QApplication::clipboard()->setText(after);
            if (self && locateSelected && revision == m_snapshotRevision && contains(address))
            {
                m_tabs->setCurrentIndex(0);
                jumpToAddress(address);
            }
        });

        connect(m_hex, &HexEditorWidget::byteEdited, this, [this]() { refreshFromHexEditor(); });
        connect(m_hex, &HexEditorWidget::currentAddressChanged, this, [this](std::uint64_t address) {
            if (!m_syncing)
                emit currentAddressChanged(address);
        });
        connect(m_hex, &HexEditorWidget::aboutToShowContextMenu, this,
            [this](QMenu* menu, std::uint64_t address, bool valid) {
                if (!valid) return;
                if (m_processPid != 0)
                    x64dbg_navigation::AddAction(menu, this, {m_processPid, m_processCreateTime100ns,
                        address, x64dbg_navigation::View::Dump});
                const auto revision = m_snapshotRevision;
                const auto menuArchitecture = architecture();
                menu->addSeparator();
                auto* show = menu->addAction(trText(QStringLiteral("从此处反汇编")));
                connect(show, &QAction::triggered, this, [this, address, revision]() {
                    if (revision != m_snapshotRevision || !contains(address)) return;
                    showDisassemblyAt(address);
                });
                auto* edit = menu->addAction(trText(QStringLiteral("汇编编辑")));
                edit->setEnabled(m_editable);
                connect(edit, &QAction::triggered, this, [this, address, revision, menuArchitecture]() {
                    if (!m_editable || revision != m_snapshotRevision || architecture() != menuArchitecture
                        || !contains(address)) return;
                    jumpToAddress(address);
                    showAssemblyEditor();
                });
                auto* pseudocode = menu->addAction(trText(QStringLiteral("反编译为 C 伪代码")));
                connect(pseudocode, &QAction::triggered, this, [this, address, revision]() {
                    if (revision != m_snapshotRevision || !contains(address)) return;
                    showPseudocodeAt(address);
                });
            });
        connect(m_tabs, &QTabWidget::currentChanged, this, [this](int index) {
            if (index == 1)
            {
                const auto address = m_hex->selectedAbsoluteAddress();
                if (contains(address)) m_anchor = address;
                m_decodeAddress->setText(addressText(m_anchor));
                rebuildDisassembly();
                selectInstruction(m_anchor);
            }
            if (index == 2) rebuildText();
            if (index == 3) rebuildComparison();
        });
        connect(m_architecture, &QComboBox::currentIndexChanged, this, [this]() {
            // 即使之后切回原架构，也不复活切换前已经排队或打开预览的汇编请求。
            ++m_snapshotRevision;
            const QPointer<MemoryEditorWidget> alive(this);
            invalidatePseudocode();
            if (!alive) return;
            synchronizeSnapshotProvider();
            m_disassembly->setArchitectureOverride(architecture() == DisassemblyArchitecture::X64);
            if (m_tabs->currentIndex() == 1) rebuildDisassembly();
        });
        const auto navigate = [this]() {
            QString value = m_decodeAddress->text().trimmed();
            if (value.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) value.remove(0, 2);
            bool ok = false;
            const auto address = value.toULongLong(&ok, 16);
            if (!ok || !contains(address))
            {
                m_decodeStatus->setText(m_addressKind == SnapshotAddressKind::FileOffset
                    ? trText(QStringLiteral("反汇编起点必须是当前范围内的十六进制文件偏移。"))
                    : trText(QStringLiteral("反汇编起点必须是当前快照内的十六进制地址。")));
                return;
            }
            m_anchor = address;
            rebuildDisassembly();
            selectInstruction(address);
        };
        connect(decode, &QPushButton::clicked, this, navigate);
        connect(m_decodeAddress, &QLineEdit::returnPressed, this, navigate);
        const auto synchronizeSelection = [this](quint64 first, quint64 last) {
            if (m_syncing || !contains(first)) return;
            m_syncing = true;
            m_hex->selectAbsoluteRange(first, last);
            m_syncing = false;
            emit currentAddressChanged(first);
        };
        connect(m_disassembly, &WorkbenchDisasmView::selectionChanged, this,
            [this, synchronizeSelection](quint64 first, quint64 last) {
                if (!m_syncing) m_anchor = m_disassembly->anchorAddress();
                synchronizeSelection(first, last);
            });
        connect(m_text, &WorkbenchTextView::selectionChanged, this, synchronizeSelection);
        connect(m_text, &WorkbenchTextView::windowRequested, this, [this](quint64 address, quint64 length) {
            if (requestCapturedWindow(address, length)) return;
            if (!contains(address)) return;
            m_text->setWindow(address, std::min<std::uint64_t>(length,
                static_cast<std::uint64_t>(data().size()) - (address - m_base)));
        });
        connect(m_disassembly, &WorkbenchDisasmView::windowRequested, this,
            [this](quint64 address, quint64 length) { requestCapturedWindow(address, length); });
        connect(m_disassembly, &WorkbenchDisasmView::architectureChanged, this, [this](bool x64) {
            if (m_syncing) return;
            m_architecture->setCurrentIndex(x64 ? 1 : 0);
        });
        connect(m_disassembly, &WorkbenchDisasmView::contextMenuAboutToShow, this,
            [this](QMenu* menu, quint64 address, bool valid) {
                if (valid && m_processPid != 0)
                    x64dbg_navigation::AddAction(menu, this, {m_processPid, m_processCreateTime100ns,
                        address, x64dbg_navigation::View::Disassembly});
                if (valid)
                {
                    const auto revision = m_snapshotRevision;
                    auto* pseudocode = menu->addAction(trText(QStringLiteral("反编译为 C 伪代码")));
                    connect(pseudocode, &QAction::triggered, this, [this, address, revision]() {
                        if (revision != m_snapshotRevision || !contains(address)) return;
                        showPseudocodeAt(address);
                    });
                }
                emit instructionContextMenuAboutToShow(menu, address, valid);
            });
        connect(m_text, &WorkbenchTextView::contextMenuAboutToShow, this,
            [this](QMenu* menu, quint64 address, bool valid) {
                if (valid && m_processPid != 0)
                    x64dbg_navigation::AddAction(menu, this, {m_processPid, m_processCreateTime100ns,
                        address, x64dbg_navigation::View::Dump});
            });
        connect(m_text, &WorkbenchTextView::requestHexLocate, this, [this](quint64 address) {
            if (!contains(address)) return;
            m_tabs->setCurrentIndex(0);
            jumpToAddress(address);
        });
        connect(m_disassembly, &WorkbenchDisasmView::requestHexLocate, this, [this](quint64 address) {
            if (!contains(address)) return;
            m_tabs->setCurrentIndex(0);
            jumpToAddress(address);
        });
        initializeInlineAssemblyEditing();
        connect(m_assemble, &QPushButton::clicked, this, [this]() {
            showDisassemblyAt(selectedAddress());
            beginInlineAssemblyEdit();
        });
        updateState();
    }

    HexEditorWidget* MemoryEditorWidget::hexEditor() const { return m_hex; }
    void MemoryEditorWidget::setAddressKind(SnapshotAddressKind kind)
    {
        if (m_addressKind == kind) return;
        m_addressKind = kind;
        // Do not carry process navigation, read comparisons or staged edits
        // across coordinate domains, even when numeric offsets happen to match.
        const QPointer<MemoryEditorWidget> self(this);
        clear();
        if (!self || m_addressKind != kind) return;
        const bool file = kind == SnapshotAddressKind::FileOffset;
        m_decodeLabel->setText(file ? trText(QStringLiteral("反汇编起点（文件偏移）"))
            : trText(QStringLiteral("反汇编起点")));
        m_decodeAddress->setToolTip(file
            ? trText(QStringLiteral("从此文件偏移开始解码；偏移必须在当前已加载范围内。"))
            : trText(QStringLiteral("从此地址开始解码，避免从指令中间或无关数据处解码；地址必须在快照内。")));
        m_architecture->setToolTip(file
            ? trText(QStringLiteral("按所选 x86/x64 指令集解码原始文件字节；文件偏移不等于 PE 虚拟地址。"))
            : trText(QStringLiteral("指令架构；可手动切换，物理地址和 CR3 无法自动判断目标位数。")));
        m_comparison->horizontalHeaderItem(0)->setText(file
            ? trText(QStringLiteral("文件偏移")) : trText(QStringLiteral("地址")));
    }
    QByteArray MemoryEditorWidget::data() const { return m_hex->data(); }
    QByteArray MemoryEditorWidget::originalBytes() const { return m_original; }
    std::uint64_t MemoryEditorWidget::baseAddress() const { return m_base; }
    DisassemblyArchitecture MemoryEditorWidget::currentArchitecture() const { return architecture(); }
    bool MemoryEditorWidget::hasChanges() const { return data() != m_original; }
    bool MemoryEditorWidget::contains(std::uint64_t address) const
    {
        return address >= m_base && address - m_base < static_cast<std::uint64_t>(m_hex->regionSize());
    }
    DisassemblyArchitecture MemoryEditorWidget::architecture() const
    {
        return m_architecture->currentIndex() == 0 ? DisassemblyArchitecture::X86 : DisassemblyArchitecture::X64;
    }

    void MemoryEditorWidget::setSnapshot(const QByteArray& bytes, std::uint64_t base,
        DisassemblyArchitecture arch, std::uint64_t anchor, const QString& sourceIdentity)
    {
        const QPointer<MemoryEditorWidget> alive(this);
        const auto previousRevision = m_snapshotRevision;
        invalidatePseudocode(true);
        if (!alive || previousRevision != m_snapshotRevision) return;
        // Invalid wrapping ranges are never exposed as writable snapshots.
        if (!bytes.isEmpty() && static_cast<std::uint64_t>(bytes.size() - 1)
            > std::numeric_limits<std::uint64_t>::max() - base)
        {
            clear();
            return;
        }
        m_previousRead = !sourceIdentity.isEmpty() && m_base == base
            && m_original.size() == bytes.size() && m_sourceIdentity == sourceIdentity
            ? m_original : QByteArray();
        m_recentChanges.clear();
        if (!m_previousRead.isEmpty())
        {
            m_recentChanges.resize(bytes.size());
            for (qsizetype i = 0; i < bytes.size(); ++i)
                m_recentChanges[i] = bytes.at(i) != m_previousRead.at(i) ? 1 : 0;
        }
        if (m_sourceIdentity != sourceIdentity)
        {
            m_processPid = 0;
            m_processCreateTime100ns = 0;
        }
        m_sourceIdentity = sourceIdentity;
        m_history.reset();
        m_observed = bytes;
        m_comparisonPage = 0;
        m_base = base;
        ++m_snapshotRevision;
        m_original = bytes;
        m_disassembly->reset();
        m_text->reset();
        const QPointer<MemoryEditorWidget> self(this);
        m_hex->setByteArray(bytes, base);
        if (!self) return;
        m_anchor = contains(anchor) ? anchor : base;
        {
            // 后续 bytesChanged 可同步销毁编辑器；信号屏蔽器不能跨越该通知存活。
            const QSignalBlocker blocker(m_architecture);
            m_architecture->setCurrentIndex(arch == DisassemblyArchitecture::X86 ? 0 : 1);
        }
        synchronizeSnapshotProvider();
        m_decodeAddress->setText(addressText(m_anchor));
        jumpToAddress(m_anchor);
        if (!self) return;
        refreshFromHexEditor();
    }

    void MemoryEditorWidget::setEditable(bool editable)
    {
        // 权限暂停/恢复使之前的编辑上下文失效；重复下发相同状态不干扰正常操作。
        if (m_editable != editable)
        {
            ++m_snapshotRevision;
            const QPointer<MemoryEditorWidget> alive(this);
            invalidatePseudocode();
            if (!alive) return;
        }
        m_editable = editable;
        updateState();
    }

    QVector<MemoryEditBlock> MemoryEditorWidget::diffBlocks() const
    {
        QVector<MemoryEditBlock> blocks;
        const auto bytes = data();
        if (bytes.size() != m_original.size()) return blocks;
        for (qsizetype i = 0; i < bytes.size();)
        {
            if (bytes.at(i) == m_original.at(i)) { ++i; continue; }
            const qsizetype start = i++;
            while (i < bytes.size() && bytes.at(i) != m_original.at(i)) ++i;
            blocks.push_back({m_base + static_cast<std::uint64_t>(start),
                m_original.mid(start, i - start), bytes.mid(start, i - start)});
        }
        return blocks;
    }

    void MemoryEditorWidget::acceptChanges()
    {
        const QPointer<MemoryEditorWidget> alive(this);
        const auto revision = m_snapshotRevision;
        invalidatePseudocode();
        if (!alive || revision != m_snapshotRevision) return;
        m_disassembly->invalidateEditContext();
        ++m_snapshotRevision;
        m_original = m_observed = data();
        m_history.reset();
        if (m_previousRead.size() == m_original.size())
        {
            m_recentChanges.resize(m_original.size());
            for (qsizetype i = 0; i < m_original.size(); ++i)
                m_recentChanges[i] = m_original.at(i) != m_previousRead.at(i) ? 1 : 0;
        }
        else m_recentChanges.clear();
        refreshFromHexEditor();
    }
    void MemoryEditorWidget::discardChanges()
    {
        const QPointer<MemoryEditorWidget> alive(this);
        const auto revision = m_snapshotRevision;
        invalidatePseudocode();
        if (!alive || revision != m_snapshotRevision) return;
        const auto address = selectedAddress();
        m_disassembly->invalidateEditContext();
        ++m_snapshotRevision;
        m_history.reset();
        m_observed = m_original;
        m_hex->setByteArray(m_original, m_base);
        jumpToAddress(address);
        refreshFromHexEditor();
    }
    void MemoryEditorWidget::clear()
    {
        const QPointer<MemoryEditorWidget> alive(this);
        const auto revision = m_snapshotRevision;
        invalidatePseudocode(true);
        if (!alive || revision != m_snapshotRevision) return;
        ++m_snapshotRevision;
        m_original.clear();
        m_observed.clear();
        m_previousRead.clear();
        m_recentChanges.clear();
        m_sourceIdentity.clear();
        m_history.reset();
        m_comparisonRows.clear();
        m_comparisonPage = 0;
        m_base = m_anchor = 0;
        m_hex->clearData();
        m_disassembly->reset();
        m_text->reset();
        m_processPid = 0;
        m_processCreateTime100ns = 0;
        refreshFromHexEditor();
    }
    void MemoryEditorWidget::refreshFromHexEditor()
    {
        const auto bytes = data();
        if (bytes != m_observed)
        {
            // Snapshot sizes are invariant for staged editing. External owners
            // must use setSnapshot to load a different range.
            if (bytes.size() == m_observed.size())
                m_history.record(reinterpret_cast<const std::uint8_t*>(m_observed.constData()),
                    reinterpret_cast<const std::uint8_t*>(bytes.constData()), static_cast<std::size_t>(bytes.size()));
            else m_history.reset();
            m_observed = bytes;
            ++m_snapshotRevision;
            const QPointer<MemoryEditorWidget> alive(this);
            invalidatePseudocode();
            if (!alive) return;
        }
        synchronizeSnapshotProvider();
        updateHighlights();
        updateState();
        if (m_tabs->currentIndex() == 1) rebuildDisassembly();
        if (m_tabs->currentIndex() == 2) rebuildText();
        if (m_tabs->currentIndex() == 3) rebuildComparison();
        emit bytesChanged();
    }

    void MemoryEditorWidget::updateHighlights()
    {
        synchronizeSnapshotProvider();
        if (m_highlightChanges->isChecked())
            m_hex->setChangeReferences(m_original, m_previousRead);
        else m_hex->clearChangeHighlights();
    }

    void MemoryEditorWidget::undo() { applyHistory(false); }
    void MemoryEditorWidget::redo() { applyHistory(true); }
    void MemoryEditorWidget::applyHistory(bool forward)
    {
        if (!m_editable || data().isEmpty() || (forward ? !m_history.canRedo() : !m_history.canUndo())) return;
        const auto bytes = data();
        const auto result = forward
            ? m_history.redo(reinterpret_cast<const std::uint8_t*>(bytes.constData()), static_cast<std::size_t>(bytes.size()))
            : m_history.undo(reinterpret_cast<const std::uint8_t*>(bytes.constData()), static_cast<std::size_t>(bytes.size()));
        if (!result)
        {
            m_history.reset();
            updateState();
            return;
        }
        const auto address = selectedAddress();
        m_disassembly->invalidateEditContext();
        const QByteArray restored(reinterpret_cast<const char*>(result->data()), static_cast<qsizetype>(result->size()));
        m_observed = restored;
        ++m_snapshotRevision;
        const QPointer<MemoryEditorWidget> alive(this);
        invalidatePseudocode();
        if (!alive) return;
        m_hex->setByteArray(restored, m_base);
        jumpToAddress(address);
        refreshFromHexEditor();
    }
    void MemoryEditorWidget::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (m_tabs != nullptr && (event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange))
        {
            if (m_tabs->currentIndex() == 1) rebuildDisassembly();
            if (m_tabs->currentIndex() == 2) rebuildText();
            if (m_tabs->currentIndex() == 3) renderComparisonPage();
        }
    }
    void MemoryEditorWidget::updateState()
    {
        const bool loaded = m_hex->regionSize() != 0;
        m_hex->setEditable(m_editable && loaded);
        m_disassembly->setEditable(m_editable && loaded);
        m_assemble->setEnabled(m_editable && loaded);
        m_undo->setEnabled(m_editable && loaded && m_history.canUndo());
        m_redo->setEnabled(m_editable && loaded && m_history.canRedo());
        updatePseudocodeState();
        const bool fileReadOnly = m_addressKind == SnapshotAddressKind::FileOffset && !m_editable;
        for (auto* button : {m_assemble, m_undo, m_redo}) button->setVisible(!fileReadOnly);
        m_status->setText(fileReadOnly
            ? (loaded ? trText(QStringLiteral("已加载 %1 字节（只读）。")).arg(m_hex->regionSize())
                : trText(QStringLiteral("加载文件范围后可查看十六进制、反汇编和文本。")))
            : loaded
            ? trText(QStringLiteral("%1 字节 | %2 处差异待应用")).arg(m_hex->regionSize()).arg(diffBlocks().size())
            : trText(QStringLiteral("读取内存后可查看指令和编辑缓存。")));
    }
    std::uint64_t MemoryEditorWidget::selectedAddress() const
    {
        if (m_tabs->currentIndex() == 1)
        {
            const auto row = m_disassembly->selectedInstruction();
            if (row) return row->address;
        }
        if (m_tabs->currentIndex() == 2)
        {
            const auto range = m_text->canvas()->selectedRange();
            if (range) return range->first;
        }
        return m_hex->selectedAbsoluteAddress();
    }
    void MemoryEditorWidget::jumpToAddress(std::uint64_t address)
    {
        if (!contains(address)) { requestCapturedWindow(address, 65536); return; }
        m_syncing = true;
        m_hex->jumpToAbsoluteAddress(address);
        m_syncing = false;
        if (m_tabs->currentIndex() == 2) rebuildText();
        if (m_tabs->currentIndex() == 1)
        {
            m_anchor = address;
            m_decodeAddress->setText(addressText(address));
            rebuildDisassembly();
            selectInstruction(address);
        }
        emit currentAddressChanged(address);
    }
    void MemoryEditorWidget::showDisassemblyAt(std::uint64_t address)
    {
        const QPointer<MemoryEditorWidget> alive(this);
        const auto revision = m_snapshotRevision;
        if (!contains(address))
        {
            m_tabs->setCurrentIndex(1);
            if (alive && revision == m_snapshotRevision) requestCapturedWindow(address, 4096 + 15);
            return;
        }
        m_tabs->setCurrentIndex(1);
        if (alive && revision == m_snapshotRevision) jumpToAddress(address);
    }
    void MemoryEditorWidget::openFindPanel()
    {
        if (m_tabs->currentIndex() == 1) m_disassembly->openFind();
        else if (m_tabs->currentIndex() == 2) m_text->openFind();
        else
        {
            const QPointer<MemoryEditorWidget> self(this);
            m_tabs->setCurrentIndex(0);
            if (self) m_hex->openFindPanel();
        }
    }
    WorkbenchDisasmView* MemoryEditorWidget::disassemblyView() const { return m_disassembly; }
    WorkbenchTextView* MemoryEditorWidget::textView() const { return m_text; }
    std::optional<DisassemblySelection> MemoryEditorWidget::selectedInstruction() const
    {
        const auto row = m_disassembly->selectedInstruction();
        if (!row || row->bytes.isEmpty() || !contains(row->address)) return std::nullopt;
        const auto offset = row->address - m_base;
        if (offset > std::numeric_limits<std::uint32_t>::max()
            || data().mid(static_cast<qsizetype>(offset), row->bytes.size()) != row->bytes)
            return std::nullopt;
        return DisassemblySelection{row->address, static_cast<std::uint32_t>(offset), row->bytes};
    }
    void MemoryEditorWidget::selectInstruction(std::uint64_t address)
    {
        const auto& rows = m_disassembly->canvas()->rows();
        for (int row = 0; row < rows.size(); ++row)
        {
            const auto& candidate = rows.at(row);
            if (address >= candidate.address
                && address - candidate.address < static_cast<std::uint64_t>(candidate.bytes.size()))
            {
                m_disassembly->canvas()->setSelectedRow(row);
                break;
            }
        }
    }
    void MemoryEditorWidget::rebuildDisassembly()
    {
        const auto selection = selectedAddress();
        if (!contains(m_anchor)) m_anchor = m_base;
        synchronizeSnapshotProvider();
        m_syncing = true;
        m_disassembly->setArchitectureOverride(architecture() == DisassemblyArchitecture::X64);
        // Zero is a valid file offset/address, distinct from an unpositioned view.
        if (!m_disassembly->hasAnchor() || m_disassembly->anchorAddress() != m_anchor)
            m_disassembly->jumpTo(m_anchor);
        else
            m_disassembly->refreshView();
        selectInstruction(contains(selection) ? selection : m_anchor);
        m_syncing = false;
    }
    void MemoryEditorWidget::rebuildText()
    {
        synchronizeSnapshotProvider();
        const auto address = m_hex->selectedAbsoluteAddress();
        m_text->setBytesPerRow(m_hex->bytesPerRow());
        const auto start = contains(address) ? address : m_base;
        const auto offset = start - m_base;
        const auto length = std::min<std::uint64_t>(64ULL * 1024ULL,
            static_cast<std::uint64_t>(data().size()) - offset);
        const auto windowStart = m_text->windowAddress();
        const auto windowLength = m_text->windowLength();
        if (windowLength != 0 && start >= windowStart && start - windowStart < windowLength)
            m_text->refreshView();
        else
            m_text->setWindow(start, length);
        if (contains(address)) m_text->canvas()->scrollToAddress(address);
    }

    void MemoryEditorWidget::rebuildComparison()
    {
        m_comparisonRows.clear();
        const auto bytes = data();
        const auto& baseline = m_comparisonBaseline->currentIndex() == 1 ? m_previousRead : m_original;
        if (baseline.size() == bytes.size())
        {
            for (qsizetype offset = 0; offset < bytes.size(); offset += 16)
                if (!m_onlyDifferences->isChecked() || bytes.mid(offset, 16) != baseline.mid(offset, 16))
                    m_comparisonRows.append(offset);
        }
        m_comparisonPage = std::min(m_comparisonPage, std::max<qsizetype>(0, (m_comparisonRows.size() - 1) / kComparisonPageRows));
        renderComparisonPage();
    }

    void MemoryEditorWidget::renderComparisonPage()
    {
        const auto bytes = data();
        const auto& baseline = m_comparisonBaseline->currentIndex() == 1 ? m_previousRead : m_original;
        const auto first = m_comparisonPage * kComparisonPageRows;
        const auto last = std::min(first + kComparisonPageRows, m_comparisonRows.size());
        const QSignalBlocker blocker(m_comparison);
        m_comparison->setRowCount(static_cast<int>(std::max<qsizetype>(0, last - first)));
        qsizetype changedBytes = 0;
        if (baseline.size() == bytes.size())
            for (qsizetype i = 0; i < bytes.size(); ++i) changedBytes += bytes.at(i) != baseline.at(i);
        m_comparisonStatus->setText(baseline.size() != bytes.size()
            ? trText(QStringLiteral("没有上次相同目标和范围的读取可供对比。"))
            : trText(QStringLiteral("%1 字节变化；显示第 %2–%3 / %4 行。双击可定位字节。"))
                .arg(changedBytes).arg(last > first ? first + 1 : 0).arg(last).arg(m_comparisonRows.size()));
        m_previousComparison->setEnabled(first > 0);
        m_nextComparison->setEnabled(last < m_comparisonRows.size());
        for (qsizetype index = first; index < last; ++index)
        {
            const auto offset = m_comparisonRows.at(index);
            const auto oldLine = baseline.mid(offset, 16);
            const auto newLine = bytes.mid(offset, 16);
            int count = 0;
            QString detail;
            for (qsizetype i = 0; i < newLine.size(); ++i)
            {
                if (oldLine.at(i) == newLine.at(i)) continue;
                ++count;
                detail += addressText(m_base + static_cast<std::uint64_t>(offset + i))
                    + QStringLiteral("  ") + byteText(oldLine.mid(i, 1)) + QStringLiteral(" → ")
                    + byteText(newLine.mid(i, 1)) + QLatin1Char('\n');
            }
            const QStringList fields{addressText(m_base + static_cast<std::uint64_t>(offset)), byteText(oldLine),
                byteText(newLine), asciiText(oldLine), asciiText(newLine), QString::number(count)};
            for (int column = 0; column < fields.size(); ++column)
            {
                auto* item = new QTableWidgetItem(fields.at(column));
                item->setData(kRowOffsetRole, QVariant::fromValue<qulonglong>(offset));
                item->setToolTip(detail);
                if (count != 0 && m_highlightChanges->isChecked())
                {
                    QFont font = item->font(); font.setBold(true); item->setFont(font);
                    item->setBackground(changeColor(palette(), m_comparisonBaseline->currentIndex() == 0));
                }
                m_comparison->setItem(static_cast<int>(index - first), column, item);
            }
        }
        m_comparison->resizeColumnsToContents();
    }
    void MemoryEditorWidget::showAssemblyEditor()
    {
        const auto address = selectedAddress();
        if (!m_editable || !contains(address)) return;
        const auto snapshot = data();
        const auto snapshotBase = m_base;
        const auto snapshotRevision = m_snapshotRevision;
        const auto assemblyArchitecture = architecture();
        const auto offset = static_cast<qsizetype>(address - m_base);
        const auto decoded = InstructionDecoder::decode(snapshot.mid(offset, 15), address, assemblyArchitecture, 1);
        if (decoded.rows.isEmpty()) return;
        const auto first = decoded.rows.first();
        // 父窗口在 exec 期间销毁时，Qt 会删除所有子对象，不能让它 delete 一个栈上对话框。
        const QPointer<MemoryEditorWidget> self(this);
        QPointer<QDialog> dialog = new QDialog(this);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setObjectName(QStringLiteral("memory_assembly_dialog"));
        dialog->setStyleSheet(KswordTheme::OpaqueDialogStyle(dialog->objectName()));
        dialog->setWindowTitle(trText(QStringLiteral("汇编编辑")));
        auto* layout = new QVBoxLayout(dialog);
        auto* form = new QFormLayout;
        form->addRow(trText(QStringLiteral("起始地址")), new QLabel(addressText(address), dialog));
        form->addRow(trText(QStringLiteral("指令架构")), new QLabel(
            assemblyArchitecture == DisassemblyArchitecture::X64 ? QStringLiteral("x64") : QStringLiteral("x86"), dialog));
        auto* span = new QSpinBox(dialog);
        span->setRange(1, static_cast<int>(std::min<qsizetype>(snapshot.size() - offset, 65536)));
        span->setValue(static_cast<int>(first.bytes.size()));
        form->addRow(trText(QStringLiteral("覆盖长度（字节）")), span);
        auto* pad = new QCheckBox(trText(QStringLiteral("用 NOP 填充剩余覆盖空间")), dialog);
        pad->setChecked(true);
        form->addRow(pad);
        layout->addLayout(form);
        auto* hint = new QLabel(trText(QStringLiteral("每行一条 Intel 指令。数字默认十六进制，十进制用 0d 前缀；支持局部标签。覆盖长度须包含完整指令；编译不会写入真实内存。")), dialog);
        hint->setWordWrap(true);
        layout->addWidget(hint);
        auto* source = new CodeTextEdit(dialog);
        source->setObjectName(QStringLiteral("memory_assembly_source"));
        source->setPlainText(first.decoded ? first.mnemonic + QLatin1Char(' ') + first.operands
            : QStringLiteral("db ") + byteText(first.bytes));
        layout->addWidget(source, 1);
        auto* preview = new CodeTextEdit(dialog);
        static_cast<CodeTextEdit*>(preview)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        preview->setObjectName(QStringLiteral("memory_assembly_preview"));
        preview->setReadOnly(true);
        layout->addWidget(preview, 1);
        auto* status = new QLabel(dialog);
        status->setWordWrap(true);
        layout->addWidget(status);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, dialog);
        auto* compile = buttons->addButton(trText(QStringLiteral("编译并预览")), QDialogButtonBox::ActionRole);
        auto* stage = buttons->addButton(trText(QStringLiteral("填入缓存")), QDialogButtonBox::AcceptRole);
        stage->setEnabled(false);
        layout->addWidget(buttons);
        QByteArray payload;
        const auto invalidate = [&]() { payload.clear(); stage->setEnabled(false); preview->clear(); status->clear(); };
        connect(source, &QPlainTextEdit::textChanged, dialog.data(), invalidate);
        connect(span, &QSpinBox::valueChanged, dialog.data(), invalidate);
        connect(pad, &QCheckBox::toggled, dialog.data(), invalidate);
        connect(compile, &QPushButton::clicked, dialog.data(), [&]() {
            invalidate();
            const auto result = InstructionAssembler::assemble(source->toPlainText(), address, assemblyArchitecture);
            if (!result.success)
            {
                status->setText(trText(QStringLiteral("第 %1 行：%2")).arg(result.errorLine).arg(result.error));
                return;
            }
            if (result.bytes.isEmpty() || result.bytes.size() > span->value())
            {
                status->setText(trText(QStringLiteral("机器码为 %1 字节，超出覆盖长度 %2；请明确扩大覆盖范围后重新预览。"))
                    .arg(result.bytes.size()).arg(span->value()));
                return;
            }
            // Boundaries are measured in the same architecture, at the actual VA.
            // No tail of an old instruction is silently left executable.
            const auto oldRows = InstructionDecoder::decode(snapshot.mid(offset, span->value() + 15), address, assemblyArchitecture, 65536);
            qsizetype boundary = 0;
            for (const auto& row : oldRows.rows)
            {
                if (!row.decoded)
                {
                    status->setText(trText(QStringLiteral("覆盖范围包含无法解码的字节；请调整范围或使用十六进制编辑。")));
                    return;
                }
                boundary += row.bytes.size();
                if (boundary >= span->value()) break;
            }
            if (boundary != span->value())
            {
                status->setText(trText(QStringLiteral("覆盖长度截断了原指令，请选择完整指令边界（下一边界为 %1 字节）。")).arg(boundary));
                return;
            }
            if (!pad->isChecked() && result.bytes.size() != span->value())
            {
                status->setText(trText(QStringLiteral("关闭 NOP 填充时，机器码长度必须等于覆盖长度。")));
                return;
            }
            payload = result.bytes;
            payload.append(QByteArray(span->value() - payload.size(), static_cast<char>(0x90)));
            QString text = trText(QStringLiteral("原始：%1\n替换：%2\n"))
                .arg(byteText(snapshot.mid(offset, span->value()))).arg(byteText(payload));
            const auto newRows = InstructionDecoder::decode(payload, address, assemblyArchitecture);
            for (const auto& row : newRows.rows)
                text += addressText(row.address) + QStringLiteral("  ") + byteText(row.bytes)
                    + QStringLiteral("  ") + row.mnemonic + QLatin1Char(' ') + row.operands + QLatin1Char('\n');
            preview->setPlainText(text);
            status->setText(trText(QStringLiteral("预览完成：%1 字节；填入缓存后，使用页面的应用差异按钮写回。" )).arg(payload.size()));
            stage->setEnabled(true);
        });
        connect(buttons, &QDialogButtonBox::accepted, dialog.data(), &QDialog::accept);
        connect(buttons, &QDialogButtonBox::rejected, dialog.data(), &QDialog::reject);
        applyResponsiveWindowGeometry(dialog, this, QSize(760, 620), QSize(480, 360));
        const int result = dialog->exec();
        // 先销毁尚存的弹窗，断开捕获 payload 等局部变量的回调，再允许本函数返回。
        // WA_DeleteOnClose 已销毁或父对象同步删除时，QPointer 为 null，无需再次释放。
        if (dialog)
        {
            delete dialog.data();
        }
        if (!self || result != QDialog::Accepted || payload.isEmpty()) return;
        // 嵌套事件循环可能更换目标/架构、暂停权限或刷新字节；旧快照的预览必须整体失效。
        if (!m_editable || m_base != snapshotBase || m_snapshotRevision != snapshotRevision
            || architecture() != assemblyArchitecture || data() != snapshot) return;
        QByteArray changed = snapshot;
        changed.replace(offset, payload.size(), payload);
        m_hex->setByteArray(changed, m_base);
        if (!self) return;
        jumpToAddress(address);
        if (!self) return;
        refreshFromHexEditor();
    }
}
