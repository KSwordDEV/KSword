#include "SnapshotWorkbenchWidget.h"
#include "WorkbenchCompareView.h"
#include "../MemoryAssembly.h"
#include "HexView.h"
#include "../X64DbgNavigation.h"
#include "../Decompiler/GhidraDecompiler.h"
#include "WorkbenchTextView.h"
#include "MemoryRowCanvas.h"

#include <QCheckBox>
#include <QComboBox>
#include <QPointer>
#include <algorithm>

namespace ks::ui
{
    SnapshotWorkbenchWidget::~SnapshotWorkbenchWidget()
    {
        // 外部进程和各页先放开非拥有的数据源，随后才销毁快照成员。
        m_pseudocodePage->setBytesProvider(nullptr);
        m_comparison->setBytesProvider(nullptr);
        // QObject deletes the child views after C++ members. Release their
        // non-owning provider reference while that member still exists.
        m_disassembly->setBytesProvider(nullptr);
        m_text->setBytesProvider(nullptr);
    }

    void SnapshotWorkbenchWidget::initializeInlineAssemblyEditing()
    {
        m_disassembly->setBytesProvider(&m_bytesProvider);
        m_disassembly->setDecodeBackend([this](const std::uint8_t* bytes, std::size_t available,
            std::uint64_t address, bool x64) -> std::optional<DecodedRow> {
            auto decodeAddress = address;
            auto decodeAvailable = std::min<std::size_t>(available, 15);
            if (m_fileAnalysisSnapshot)
            {
                if (!m_fileX86Compatible) return std::nullopt;
                const auto va = fileOffsetToVirtualAddress(address);
                if (!va) return std::nullopt;
                decodeAddress = *va;
                // An instruction may not consume raw alignment padding or
                // cross a section whose virtual and file layouts diverge.
                for (const auto& region : m_fileAnalysisRegions)
                {
                    if (address < region.fileOffset) continue;
                    const auto delta = address - region.fileOffset;
                    const auto mappedSize = std::min(region.fileSize,
                        region.virtualSize ? region.virtualSize : region.fileSize);
                    if (delta < mappedSize)
                        decodeAvailable = static_cast<std::size_t>(std::min<std::uint64_t>(
                            decodeAvailable, mappedSize - delta));
                }
            }
            const QByteArray input(reinterpret_cast<const char*>(bytes),
                static_cast<qsizetype>(decodeAvailable));
            const auto result = InstructionDecoder::decode(input, decodeAddress,
                x64 ? DisassemblyArchitecture::X64 : DisassemblyArchitecture::X86, 1);
            if (result.rows.isEmpty() || !result.rows.first().decoded) return std::nullopt;
            const auto& row = result.rows.first();
            if (m_fileAnalysisSnapshot)
            {
                // Start/end checks alone miss a short overlapping mapping in
                // the middle of an instruction. Every consumed byte must have
                // the same unique, contiguous VA mapping (at most 15 bytes).
                for (qsizetype index = 1; index < row.bytes.size(); ++index)
                {
                    const auto delta = static_cast<std::uint64_t>(index);
                    if (delta > UINT64_MAX - address || delta > UINT64_MAX - decodeAddress)
                        return std::nullopt;
                    const auto va = fileOffsetToVirtualAddress(address + delta);
                    if (!va || *va != decodeAddress + delta) return std::nullopt;
                }
            }
            // Display/selection stays in file coordinates; Zydis operands use
            // the real virtual address for relative branches and RIP accesses.
            return DecodedRow{address, row.bytes, row.mnemonic, row.operands, true};
        });
        m_disassembly->setOperandTargetResolver([this](std::uint64_t address) {
            return m_fileAnalysisSnapshot ? virtualAddressToFileOffset(address)
                : std::optional<std::uint64_t>(address);
        });
        m_disassembly->setAssembleBackend([](const QString& source, std::uint64_t address, bool x64) {
            const auto result = InstructionAssembler::assemble(source, address,
                x64 ? DisassemblyArchitecture::X64 : DisassemblyArchitecture::X86);
            return WorkbenchAssembleResult{result.success, result.bytes, result.error, result.errorLine};
        });
        connect(m_disassembly, &WorkbenchDisasmView::stageRequested, this,
            [this](quint64 address, const QByteArray& bytes) { stageSnapshotBytes(address, bytes); });
    }

    void SnapshotWorkbenchWidget::synchronizeSnapshotProvider()
    {
        const int addressBits = m_addressKind == SnapshotAddressKind::FileOffset
            || architecture() == DisassemblyArchitecture::X64 ? 64 : 32;
        m_bytesProvider.setSnapshot(m_base, data(), m_original, m_previousRead,
            addressBits, m_highlightChanges->isChecked());
        m_disassembly->setAddressRange(m_base, static_cast<std::uint64_t>(data().size()));
        m_text->setAddressBits(addressBits);
        m_text->setAddressRange(m_base, static_cast<std::uint64_t>(data().size()));
        if (m_capturedAddressRange)
        {
            m_disassembly->setAddressBounds(m_capturedAddressRange->first, m_capturedAddressRange->second);
            m_text->setAddressBounds(m_capturedAddressRange->first, m_capturedAddressRange->second);
        }
    }

    void SnapshotWorkbenchWidget::stageSnapshotBytes(std::uint64_t address, const QByteArray& bytes)
    {
        if (!m_editable || bytes.isEmpty() || !contains(address)) return;
        auto changed = data();
        const auto offset = static_cast<qsizetype>(address - m_base);
        if (bytes.size() > changed.size() - offset) return;
        // The view has already checked the frozen instruction bytes and context.
        // This transaction touches only the shared cache; the host's apply action
        // retains its existing write-before-compare and final-readback gate.
        changed.replace(offset, bytes.size(), bytes);
        const QPointer<SnapshotWorkbenchWidget> self(this);
        m_hex->setBuffer(m_base, changed);
        if (!self) return;
        refreshFromHexEditor();
        if (!self) return;
        m_syncing = true;
        selectByteRange(address, address + static_cast<std::uint64_t>(bytes.size() - 1));
        m_syncing = false;
    }

    void SnapshotWorkbenchWidget::beginInlineAssemblyEdit()
    {
        if (m_editable) m_disassembly->beginSelectedInstructionEdit();
    }

    void SnapshotWorkbenchWidget::setProcessContext(std::uint32_t pid, std::uint64_t createTime100ns)
    {
        if (m_addressKind == SnapshotAddressKind::FileOffset)
        {
            m_processPid = 0;
            m_processCreateTime100ns = 0;
            return;
        }
        // 只接受宿主在读取阶段保留的原身份，不能把当前同号进程授权给旧字节。
        // 文件偏移的早退保持不变；物理/内核/缺身份快照仍不拥有进程导航目标。
        const bool identified = x64dbg_navigation::HasCapturedIdentity(pid, createTime100ns);
        m_processPid = identified ? pid : 0;
        m_processCreateTime100ns = identified ? createTime100ns : 0;
    }
}
