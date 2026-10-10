#include "SnapshotWorkbenchWidget.h"
#include "../PageControlStyle.h"
#include "../ToolbarMetrics.h"
#include "../CodeTextEdit.h"
#include "../MemoryAssembly.h"
#include "HexView.h"
#include "WorkbenchDisasmView.h"
#include "WorkbenchTextView.h"
#include "WorkbenchCompareView.h"
#include "AssemblyPreviewDialog.h"
#include "HexCanvas.h"
#include "MemoryRowCanvas.h"
#include "../X64DbgNavigation.h"
#include "../Decompiler/GhidraDecompiler.h"
#include "../UI_All.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"

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


    }

    SnapshotWorkbenchWidget::SnapshotWorkbenchWidget(QWidget* parent) : QWidget(parent)
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
        NormalizeToolbarRow(tools);
        layout->addLayout(tools);
        auto* stateRow = new QHBoxLayout;
        stateRow->addWidget(m_highlightChanges);
        stateRow->addWidget(m_status, 1);
        NormalizeToolbarRow(stateRow);
        layout->addLayout(stateRow);

        m_tabs = new QTabWidget(this);
        StylePageTabs(m_tabs);
        m_hex = new HexView(m_tabs);
        m_hex->setBytesPerRow(16);
        m_hex->setStatusBarVisible(false);
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
        NormalizeToolbarRow(navigation);
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
        // 比较页复用正式虚拟模型，不再维护旧的分页 QTableWidget 副本。
        m_comparison = new WorkbenchCompareView(m_tabs);
        m_comparison->setBytesProvider(&m_bytesProvider);
        m_tabs->addTab(m_comparison, trText(QStringLiteral("对比")));
        layout->addWidget(m_tabs, 1);
        initializePseudocodeView();

        connect(m_undo, &QPushButton::clicked, this, &SnapshotWorkbenchWidget::undo);
        connect(m_redo, &QPushButton::clicked, this, &SnapshotWorkbenchWidget::redo);
        auto* undoShortcut = new QShortcut(QKeySequence::Undo, this);
        undoShortcut->setContext(Qt::WidgetWithChildrenShortcut);
        connect(undoShortcut, &QShortcut::activated, this, &SnapshotWorkbenchWidget::undo);
        for (const auto& key : {QKeySequence(Qt::CTRL | Qt::Key_Y), QKeySequence(Qt::CTRL | Qt::SHIFT | Qt::Key_Z)})
        {
            auto* shortcut = new QShortcut(key, this);
            shortcut->setContext(Qt::WidgetWithChildrenShortcut);
            connect(shortcut, &QShortcut::activated, this, &SnapshotWorkbenchWidget::redo);
        }
        connect(m_highlightChanges, &QCheckBox::toggled, this, [this]() {
            updateHighlights();
            if (m_tabs->currentIndex() == 1) rebuildDisassembly();
            if (m_tabs->currentIndex() == 2) rebuildText();
            if (m_tabs->currentIndex() == 3) rebuildComparison();
        });
        connect(m_comparison, &WorkbenchCompareView::requestHexLocate, this, [this](quint64 address) {
            if (!contains(address)) return;
            m_tabs->setCurrentIndex(0);
            jumpToAddress(address);
        });
        connect(m_hex, &HexView::byteEdited, this, [this]() { refreshFromHexEditor(); });
        connect(m_hex, &HexView::caretMoved, this, [this](std::uint64_t address) {
            if (!m_syncing)
            {
                // 光标变化也是分析位置变化；同一窗口缓存命中不依赖 contentChanged 补同步。
                const QPointer<SnapshotWorkbenchWidget> alive(this);
                synchronizePseudocodeContext();
                if (!alive) return;
                emit currentAddressChanged(address);
            }
        });
        connect(m_hex, &HexView::aboutToShowContextMenu, this,
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
                const auto address = m_hex->bufferSize() ? m_hex->caretAddress() : m_base;
                if (contains(address)) m_anchor = address;
                m_decodeAddress->setText(addressText(m_anchor));
                rebuildDisassembly();
                selectInstruction(m_anchor);
            }
            if (index == 2) rebuildText();
            if (index == 3) rebuildComparison();
            if (index == 4) synchronizePseudocodeContext();
        });
        connect(m_architecture, &QComboBox::currentIndexChanged, this, [this]() {
            // 即使之后切回原架构，也不复活切换前已经排队或打开预览的汇编请求。
            ++m_snapshotRevision;
            const QPointer<SnapshotWorkbenchWidget> alive(this);
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
            selectByteRange(first, last);
            m_syncing = false;
            // 反汇编/文本选区移动后冻结新的位置，隐藏的 C 页也不能保留旧按钮上下文。
            const QPointer<SnapshotWorkbenchWidget> alive(this);
            synchronizePseudocodeContext();
            if (!alive) return;
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

    HexView* SnapshotWorkbenchWidget::hexEditor() const { return m_hex; }
    void SnapshotWorkbenchWidget::setAddressKind(SnapshotAddressKind kind)
    {
        if (m_addressKind == kind) return;
        m_addressKind = kind;
        // Do not carry process navigation, read comparisons or staged edits
        // across coordinate domains, even when numeric offsets happen to match.
        const QPointer<SnapshotWorkbenchWidget> self(this);
        clear();
        if (!self || m_addressKind != kind) return;
        const bool file = kind == SnapshotAddressKind::FileOffset;
        m_comparison->setFileOffsetCoordinates(file);
        m_decodeLabel->setText(file ? trText(QStringLiteral("反汇编起点（文件偏移）"))
            : trText(QStringLiteral("反汇编起点")));
        m_decodeAddress->setToolTip(file
            ? trText(QStringLiteral("从此文件偏移开始解码；偏移必须在当前已加载范围内。"))
            : trText(QStringLiteral("从此地址开始解码，避免从指令中间或无关数据处解码；地址必须在快照内。")));
        m_architecture->setToolTip(file
            ? trText(QStringLiteral("按所选 x86/x64 指令集解码原始文件字节；文件偏移不等于 PE 虚拟地址。"))
            : trText(QStringLiteral("指令架构；可手动切换，物理地址和 CR3 无法自动判断目标位数。")));

    }
    QByteArray SnapshotWorkbenchWidget::data() const { return m_hex->buffer(); }
    QByteArray SnapshotWorkbenchWidget::originalBytes() const { return m_original; }
    std::uint64_t SnapshotWorkbenchWidget::baseAddress() const { return m_base; }
    DisassemblyArchitecture SnapshotWorkbenchWidget::currentArchitecture() const { return architecture(); }
    bool SnapshotWorkbenchWidget::hasChanges() const { return data() != m_original; }
    bool SnapshotWorkbenchWidget::contains(std::uint64_t address) const
    {
        return address >= m_base && address - m_base < static_cast<std::uint64_t>(m_hex->bufferSize());
    }
    DisassemblyArchitecture SnapshotWorkbenchWidget::architecture() const
    {
        return m_architecture->currentIndex() == 0 ? DisassemblyArchitecture::X86 : DisassemblyArchitecture::X64;
    }

    void SnapshotWorkbenchWidget::setSnapshot(const QByteArray& bytes, std::uint64_t base,
        DisassemblyArchitecture arch, std::uint64_t anchor, const QString& sourceIdentity)
    {
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        // 换源意图先领代次，再使所有比较索引失效；reset 的观察者可重入换源或销毁宿主。
        const auto previousRevision = ++m_snapshotRevision;
        m_comparison->reset();
        if (!alive || previousRevision != m_snapshotRevision) return;
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
        m_base = base;
        m_original = bytes;
        m_disassembly->reset();
        if (!alive || previousRevision != m_snapshotRevision) return;
        m_text->reset();
        if (!alive || previousRevision != m_snapshotRevision) return;
        const QPointer<SnapshotWorkbenchWidget> self(this);
        m_hex->setBuffer(base, bytes);
        if (!self || previousRevision != m_snapshotRevision) return;
        m_anchor = contains(anchor) ? anchor : base;
        {
            // 后续 bytesChanged 可同步销毁编辑器；信号屏蔽器不能跨越该通知存活。
            const QSignalBlocker blocker(m_architecture);
            m_architecture->setCurrentIndex(arch == DisassemblyArchitecture::X86 ? 0 : 1);
        }
        synchronizeSnapshotProvider();
        m_decodeAddress->setText(addressText(m_anchor));
        jumpToAddress(m_anchor);
        if (!self || previousRevision != m_snapshotRevision) return;
        refreshFromHexEditor();
    }

    void SnapshotWorkbenchWidget::setEditable(bool editable)
    {
        // 权限暂停/恢复使之前的编辑上下文失效；重复下发相同状态不干扰正常操作。
        if (m_editable != editable)
        {
            ++m_snapshotRevision;
            const QPointer<SnapshotWorkbenchWidget> alive(this);
            invalidatePseudocode();
            if (!alive) return;
        }
        m_editable = editable;
        updateState();
    }

    QVector<MemoryEditBlock> SnapshotWorkbenchWidget::diffBlocks() const
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

    void SnapshotWorkbenchWidget::acceptChanges()
    {
        const QPointer<SnapshotWorkbenchWidget> alive(this);
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
    void SnapshotWorkbenchWidget::discardChanges()
    {
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        const auto revision = m_snapshotRevision;
        invalidatePseudocode();
        if (!alive || revision != m_snapshotRevision) return;
        const auto address = selectedAddress();
        m_disassembly->invalidateEditContext();
        ++m_snapshotRevision;
        m_history.reset();
        m_observed = m_original;
        m_hex->setBuffer(m_base, m_original);
        jumpToAddress(address);
        refreshFromHexEditor();
    }
    void SnapshotWorkbenchWidget::clear()
    {
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        const auto revision = ++m_snapshotRevision; // 清空意图也要取消所有旧行和在途来源动作。
        m_comparison->reset();
        if (!alive || revision != m_snapshotRevision) return;
        invalidatePseudocode(true);
        if (!alive || revision != m_snapshotRevision) return;
        m_original.clear();
        m_observed.clear();
        m_previousRead.clear();
        m_recentChanges.clear();
        m_sourceIdentity.clear();
        m_history.reset();
        m_base = m_anchor = 0;
        m_hex->clearBuffer();
        if (!alive || revision != m_snapshotRevision) return;
        m_disassembly->reset();
        if (!alive || revision != m_snapshotRevision) return;
        m_text->reset();
        if (!alive || revision != m_snapshotRevision) return;
        m_processPid = 0;
        m_processCreateTime100ns = 0;
        refreshFromHexEditor();
    }
    void SnapshotWorkbenchWidget::refreshFromHexEditor()
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
            const QPointer<SnapshotWorkbenchWidget> alive(this);
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

    void SnapshotWorkbenchWidget::updateHighlights()
    {
        synchronizeSnapshotProvider();
        if (m_highlightChanges->isChecked())
        {
            // 原生画布已维护编辑叠加层，重复同一参照不能每字节重装整个快照。
            if (!m_hex->hasReference() || m_lastReferenceOriginal != m_original || m_lastReferencePrevious != m_previousRead)
            {
                m_hex->setReference(m_original, m_previousRead);
                m_lastReferenceOriginal = m_original;
                m_lastReferencePrevious = m_previousRead;
            }
        }
        else if (m_hex->hasReference())
        {
            m_hex->clearReference();
            m_lastReferenceOriginal.clear();
            m_lastReferencePrevious.clear();
        }
    }

    void SnapshotWorkbenchWidget::undo() { applyHistory(false); }
    void SnapshotWorkbenchWidget::redo() { applyHistory(true); }
    void SnapshotWorkbenchWidget::applyHistory(bool forward)
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
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        invalidatePseudocode();
        if (!alive) return;
        m_hex->setBuffer(m_base, restored);
        jumpToAddress(address);
        refreshFromHexEditor();
    }
    void SnapshotWorkbenchWidget::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (m_tabs != nullptr && (event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange))
        {
            if (m_tabs->currentIndex() == 1) rebuildDisassembly();
            if (m_tabs->currentIndex() == 2) rebuildText();
            if (m_tabs->currentIndex() == 3) rebuildComparison();
        }
    }
    void SnapshotWorkbenchWidget::updateState()
    {
        const bool loaded = m_hex->bufferSize() != 0;
        m_hex->setEditable(m_editable && loaded);
        m_disassembly->setEditable(m_editable && loaded);
        m_assemble->setEnabled(m_editable && loaded);
        m_undo->setEnabled(m_editable && loaded && m_history.canUndo());
        m_redo->setEnabled(m_editable && loaded && m_history.canRedo());
        updatePseudocodeState();
        const bool fileReadOnly = m_addressKind == SnapshotAddressKind::FileOffset && !m_editable;
        for (auto* button : {m_assemble, m_undo, m_redo}) button->setVisible(!fileReadOnly);
        m_status->setText(fileReadOnly
            ? (loaded ? trText(QStringLiteral("已加载 %1 字节（只读）。")).arg(m_hex->bufferSize())
                : trText(QStringLiteral("加载文件范围后可查看十六进制、反汇编和文本。")))
            : loaded
            ? trText(QStringLiteral("%1 字节 | %2 处差异待应用")).arg(m_hex->bufferSize()).arg(diffBlocks().size())
            : trText(QStringLiteral("读取内存后可查看指令和编辑缓存。")));
    }
    std::uint64_t SnapshotWorkbenchWidget::selectedAddress() const
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
        return m_hex->bufferSize() ? m_hex->caretAddress() : m_base;
    }
    void SnapshotWorkbenchWidget::jumpToAddress(std::uint64_t address)
    {
        if (!contains(address)) { requestCapturedWindow(address, 65536); return; }
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        m_syncing = true;
        m_hex->jumpToAddress(address);
        if (!alive) return;
        m_syncing = false;
        if (m_tabs->currentIndex() == 2) rebuildText();
        if (m_tabs->currentIndex() == 1)
        {
            m_anchor = address;
            m_decodeAddress->setText(addressText(address));
            rebuildDisassembly();
            selectInstruction(address);
        }
        // 外层 Scanner 地址条在同窗内只调用此入口；必须同步实际按钮将消费的位置。
        synchronizePseudocodeContext();
        if (!alive) return;
        emit currentAddressChanged(address);
    }
    void SnapshotWorkbenchWidget::showDisassemblyAt(std::uint64_t address)
    {
        const QPointer<SnapshotWorkbenchWidget> alive(this);
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
    void SnapshotWorkbenchWidget::openFindPanel()
    {
        if (m_tabs->currentIndex() == 4) m_pseudocodePage->openFindPanel();
        else if (m_tabs->currentIndex() == 1) m_disassembly->openFind();
        else if (m_tabs->currentIndex() == 2) m_text->openFind();
        else
        {
            const QPointer<SnapshotWorkbenchWidget> self(this);
            m_tabs->setCurrentIndex(0);
            if (self) m_hex->openFind();
        }
    }
    WorkbenchDisasmView* SnapshotWorkbenchWidget::disassemblyView() const { return m_disassembly; }
    WorkbenchTextView* SnapshotWorkbenchWidget::textView() const { return m_text; }
    std::optional<DisassemblySelection> SnapshotWorkbenchWidget::selectedInstruction() const
    {
        const auto row = m_disassembly->selectedInstruction();
        if (!row || row->bytes.isEmpty() || !contains(row->address)) return std::nullopt;
        const auto offset = row->address - m_base;
        if (offset > std::numeric_limits<std::uint32_t>::max()
            || data().mid(static_cast<qsizetype>(offset), row->bytes.size()) != row->bytes)
            return std::nullopt;
        return DisassemblySelection{row->address, static_cast<std::uint32_t>(offset), row->bytes};
    }
    void SnapshotWorkbenchWidget::selectInstruction(std::uint64_t address)
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
    void SnapshotWorkbenchWidget::rebuildDisassembly()
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
    void SnapshotWorkbenchWidget::rebuildText()
    {
        synchronizeSnapshotProvider();
        const auto address = m_hex->bufferSize() ? m_hex->caretAddress() : m_base;
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

    void SnapshotWorkbenchWidget::rebuildComparison()
    {
        // 比较完整捕获范围，公共页按小块读取再建虚拟摘要，不能把 1 MiB 读上限当总范围。
        synchronizeSnapshotProvider();
        const auto size = static_cast<std::uint64_t>(data().size());
        if (!size) { m_comparison->reset(); return; }
        m_comparison->setWindow(m_base, size);
    }

    // 共享预览只生成冻结载荷；此宿主仍只改缓存，真实写回由外层页面确认并提交。
    void SnapshotWorkbenchWidget::showAssemblyEditor()
    {
        const auto address = selectedAddress();
        if (!m_editable || !contains(address)) return;
        const auto snapshot = data(); // 完整原缓存用于模态返回后的整体复核。
        const auto snapshotBase = m_base;
        const auto snapshotRevision = m_snapshotRevision;
        const auto assemblyArchitecture = architecture();
        const auto offset = static_cast<qsizetype>(address - m_base);
        const auto decode = [](const std::uint8_t* bytes, std::size_t length,
            std::uint64_t at, bool x64) -> std::optional<DecodedRow> {
            const QByteArray input(reinterpret_cast<const char*>(bytes),
                static_cast<qsizetype>(std::min<std::size_t>(length, 15)));
            const auto decoded = InstructionDecoder::decode(input, at,
                x64 ? DisassemblyArchitecture::X64 : DisassemblyArchitecture::X86, 1);
            if (decoded.rows.isEmpty()) return std::nullopt;
            const auto& row = decoded.rows.first();
            return DecodedRow{row.address, row.bytes, row.mnemonic, row.operands, row.decoded};
        };
        const auto* beginning = reinterpret_cast<const std::uint8_t*>(snapshot.constData()) + offset;
        const auto first = decode(beginning, static_cast<std::size_t>(snapshot.size() - offset),
            address, assemblyArchitecture == DisassemblyArchitecture::X64);
        if (!first || first->bytes.isEmpty()) return;

        // 只冻结最大覆盖范围和一条指令余量；两套宿主明确保留自己的 65536/256 限额。
        AssemblyPreviewInput input;
        input.address = address;
        input.x64 = assemblyArchitecture == DisassemblyArchitecture::X64;
        input.snapshot = snapshot.mid(offset, 65536 + 15);
        input.initialSource = first->decoded ? (first->mnemonic + QLatin1Char(' ') + first->operands).trimmed()
            : QStringLiteral("db ") + byteText(first->bytes);
        input.initialSpan = static_cast<int>(first->bytes.size());
        input.maximumSpan = 65536;
        input.dialogName = QStringLiteral("memory_assembly_dialog");
        input.sourceName = QStringLiteral("memory_assembly_source");
        input.previewName = QStringLiteral("memory_assembly_preview");
        input.stageCaption = QStringLiteral("填入缓存");
        input.hint = QStringLiteral("每行一条 Intel 指令。数字默认十六进制，十进制用 0d 前缀；支持局部标签。覆盖长度须包含完整指令；编译不会写入真实内存。");
        input.completion = QStringLiteral("预览完成：%1 字节；填入缓存后，使用页面的应用差异按钮写回。");
        const QPointer<SnapshotWorkbenchWidget> self(this);
        const auto payload = RunAssemblyPreviewDialog(this, input,
            [](const QString& source, std::uint64_t at, bool x64) {
                const auto result = InstructionAssembler::assemble(source, at,
                    x64 ? DisassemblyArchitecture::X64 : DisassemblyArchitecture::X86);
                return WorkbenchAssembleResult{result.success, result.bytes, result.error, result.errorLine};
            }, decode);
        if (!self || payload.isEmpty()) return;
        // 嵌套事件循环允许换源/架构/权限和刷新；共享外壳不能代替宿主的身份复核。
        if (!m_editable || m_base != snapshotBase || m_snapshotRevision != snapshotRevision
            || architecture() != assemblyArchitecture || data() != snapshot) return;
        QByteArray changed = snapshot;
        changed.replace(offset, payload.size(), payload);
        m_hex->setBuffer(m_base, changed);
        if (!self) return;
        jumpToAddress(address);
        if (self) refreshFromHexEditor();
    }
}
