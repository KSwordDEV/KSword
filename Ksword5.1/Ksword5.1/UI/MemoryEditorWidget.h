#pragma once

#include "KernelDisassemblyDialog.h"
#include "MemoryEditHistory.Core.h"
#include "MemorySnapshotBytesProvider.h"
#include <QWidget>
#include <memory>
#include <vector>

class HexEditorWidget;
class QComboBox;
class QCheckBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QMenu;
class QPushButton;
class QTabWidget;
class QTableWidget;

namespace ks::ui
{
    class WorkbenchDisasmView;
    class WorkbenchTextView;
    class GhidraDecompiler;
    struct FileAnalysisRegion
    {
        std::uint64_t fileOffset = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t rva = 0;
        std::uint64_t virtualSize = 0;
        QString name;
        bool executable = false;
    };
    enum class SnapshotAddressKind { MemoryAddress, FileOffset };
    struct MemoryEditBlock
    {
        std::uint64_t address = 0;
        QByteArray originalBytes;
        QByteArray bytes;
    };

    // Shared byte snapshot viewer/editor for memory and files. All edits are
    // staged; only the owner reads/writes the source. File offsets stay 64-bit
    // independently of the selected instruction architecture.
    class MemoryEditorWidget final : public QWidget
    {
        Q_OBJECT
    public:
        explicit MemoryEditorWidget(QWidget* parent = nullptr);
        ~MemoryEditorWidget() override;
        HexEditorWidget* hexEditor() const;
        void setAddressKind(SnapshotAddressKind kind);
        SnapshotAddressKind addressKind() const { return m_addressKind; }
        // A stable nonempty source identity enables comparison across actual
        // reads. Without one, only the current snapshot's edit baseline is used.
        void setSnapshot(const QByteArray& bytes, std::uint64_t base,
            DisassemblyArchitecture architecture = DisassemblyArchitecture::X64,
            std::uint64_t anchor = 0, const QString& sourceIdentity = QString());
        QByteArray data() const;
        QByteArray originalBytes() const;
        std::uint64_t baseAddress() const;
        DisassemblyArchitecture currentArchitecture() const;
        void setEditable(bool editable);
        bool hasChanges() const;
        QVector<MemoryEditBlock> diffBlocks() const;
        void acceptChanges();
        void discardChanges();
        void clear();
        void refreshFromHexEditor();
        void jumpToAddress(std::uint64_t address);
        // Search the visible byte/code/text view; comparison redirects to HEX.
        void openFindPanel();
        void showDisassemblyAt(std::uint64_t address);
        WorkbenchDisasmView* disassemblyView() const;
        WorkbenchTextView* textView() const;
        // Hosts supply the same captured file used for structural analysis.
        // Unmapped gaps/overlay and virtual-only bytes have no PE address.
        void setFileAnalysisContext(std::shared_ptr<const std::vector<std::uint8_t>> snapshot,
            std::uint64_t imageBase, const QVector<FileAnalysisRegion>& regions,
            bool x86Compatible = true);
        std::optional<std::uint64_t> fileOffsetToVirtualAddress(std::uint64_t offset) const;
        void setCapturedAddressRange(std::uint64_t base, std::uint64_t length);
        void showPseudocodeAt(std::uint64_t address);
        QPlainTextEdit* pseudocodeView() const;
        GhidraDecompiler* decompiler() const;
        std::optional<DisassemblySelection> selectedInstruction() const;
        // 只接受宿主读取时冻结的进程 VA 身份；缺创建时间时禁用导航，不按当前 PID 补授。
        // 文件偏移、物理和内核证据不能继承进程导航目标，字节缓存和编辑通路不受影响。
        void setProcessContext(std::uint32_t pid, std::uint64_t createTime100ns = 0);
        void undo();
        void redo();

    signals:
        void bytesChanged();
        void currentAddressChanged(std::uint64_t address);
        void instructionContextMenuAboutToShow(QMenu* menu, std::uint64_t address, bool valid);
        void windowRequested(quint64 address, quint64 length);

    protected:
        void changeEvent(QEvent* event) override;

    private:
        void rebuildDisassembly();
        void rebuildText();
        void rebuildComparison();
        void renderComparisonPage();
        void updateHighlights();
        void applyHistory(bool forward);
        void updateState();
        void showAssemblyEditor();
        // 配置行内汇编编辑；单击/工具按钮只暂存单条完整指令，不写入真实内存。
        void initializeInlineAssemblyEditing();
        void beginInlineAssemblyEdit();
        void synchronizeSnapshotProvider();
        void stageSnapshotBytes(std::uint64_t address, const QByteArray& bytes);
        void selectInstruction(std::uint64_t address);
        std::uint64_t selectedAddress() const;
        bool contains(std::uint64_t address) const;
        DisassemblyArchitecture architecture() const;
        void initializePseudocodeView();
        bool setPseudocodeText(const QString& text);
        void startDecompilation();
        void invalidatePseudocode(bool clearContext = false);
        void updatePseudocodeState();
        void refreshDecompilerRuntime();
        void locatePseudocodeLine(bool disassembly);
        bool requestCapturedWindow(std::uint64_t address, std::uint64_t length);
        std::optional<std::uint64_t> virtualAddressToFileOffset(std::uint64_t address) const;

        HexEditorWidget* m_hex = nullptr;
        QTabWidget* m_tabs = nullptr;
        WorkbenchDisasmView* m_disassembly = nullptr;
        QTableWidget* m_comparison = nullptr;
        QComboBox* m_comparisonBaseline = nullptr;
        QCheckBox* m_onlyDifferences = nullptr;
        QCheckBox* m_highlightChanges = nullptr;
        QPushButton* m_previousComparison = nullptr;
        QPushButton* m_nextComparison = nullptr;
        QLabel* m_comparisonStatus = nullptr;
        WorkbenchTextView* m_text = nullptr;
        QComboBox* m_architecture = nullptr;
        QLineEdit* m_decodeAddress = nullptr;
        QLabel* m_decodeLabel = nullptr;
        QPushButton* m_assemble = nullptr;
        QPushButton* m_undo = nullptr;
        QPushButton* m_redo = nullptr;
        QLabel* m_status = nullptr;
        QLabel* m_decodeStatus = nullptr;
        QByteArray m_original;
        QByteArray m_observed;
        QByteArray m_previousRead;
        QByteArray m_recentChanges;
        MemorySnapshotBytesProvider m_bytesProvider;
        QString m_sourceIdentity;
        detail::MemoryEditHistory m_history;
        QVector<qsizetype> m_comparisonRows;
        qsizetype m_comparisonPage = 0;
        std::uint64_t m_base = 0;
        std::uint64_t m_anchor = 0;
        std::uint64_t m_snapshotRevision = 0;
        SnapshotAddressKind m_addressKind = SnapshotAddressKind::MemoryAddress;
        bool m_editable = false;
        bool m_syncing = false;
        std::uint32_t m_processPid = 0;
        std::uint64_t m_processCreateTime100ns = 0;
        GhidraDecompiler* m_decompiler = nullptr;
        QPlainTextEdit* m_pseudocode = nullptr;
        QLineEdit* m_ghidraDirectory = nullptr;
        QPushButton* m_decompile = nullptr;
        QPushButton* m_cancelDecompile = nullptr;
        QPushButton* m_pseudocodeHex = nullptr;
        QPushButton* m_pseudocodeDisassembly = nullptr;
        QLabel* m_pseudocodeStatus = nullptr;
        QLabel* m_decompilerRuntimeStatus = nullptr;
        QPushButton* m_installGhidra = nullptr;
        QPushButton* m_refreshGhidra = nullptr;
        QVector<quint64> m_pseudocodeLineAddresses;
        QVector<bool> m_pseudocodeLineValid;
        std::shared_ptr<const std::vector<std::uint8_t>> m_fileAnalysisSnapshot;
        QVector<FileAnalysisRegion> m_fileAnalysisRegions;
        std::optional<std::pair<std::uint64_t, std::uint64_t>> m_capturedAddressRange;
        std::uint64_t m_fileImageBase = 0;
        std::uint64_t m_pseudocodeRequestRevision = 0;
        std::uint64_t m_pseudocodeRequestAddress = 0;
        std::uint64_t m_pseudocodeContextRevision = 0;
        std::uint64_t m_pseudocodeEpoch = 0;
        bool m_fileX86Compatible = true;
        bool m_pseudocodeResultIsPe = false;
    };
}
