#include "SnapshotWorkbenchWidget.h"
#include "HexView.h"
#include "HexCanvas.h"
#include "../CodeTextEdit.h"
#include "../../Internationalization/LanguageManager.h"
#include <QPointer>
#include <QTabWidget>
#include <algorithm>

namespace ks::ui
{
    // 创建与实时工作台同一个 C 子页；只把快照数据源与宿主导航接进去。
    void SnapshotWorkbenchWidget::initializePseudocodeView()
    {
        m_pseudocodePage = new WorkbenchPseudocodeView(m_tabs);
        m_pseudocodePage->setBytesProvider(&m_bytesProvider);
        m_tabs->addTab(m_pseudocodePage, ks::i18n::sourceText(QStringLiteral("C 伪代码")));
        connect(m_pseudocodePage, &WorkbenchPseudocodeView::windowRequested, this,
            [this](quint64 address, quint64 length) { requestCapturedWindow(address, length); });
        connect(m_pseudocodePage, &WorkbenchPseudocodeView::requestHexLocate, this,
            [this](quint64 address) {
                // C 地址可以属于同一文件的其它捕获窗口，由宿主按范围取回。
                const QPointer<SnapshotWorkbenchWidget> alive(this);
                m_tabs->setCurrentIndex(0);
                if (alive) jumpToAddress(address);
            });
        connect(m_pseudocodePage, &WorkbenchPseudocodeView::requestDisasmLocate, this,
            [this](quint64 address) { showDisassemblyAt(address); });
        synchronizePseudocodeContext();
    }

    // 本页允许的范围严格是当前缓存；完整 PE 分析由同一冻结文件证据单独提供。
    void SnapshotWorkbenchWidget::synchronizePseudocodeContext()
    {
        if (!m_pseudocodePage) return;
        WorkbenchPseudocodeContext context;
        context.sourceIdentity = m_sourceIdentity.isEmpty()
            ? QStringLiteral("snapshot_%1").arg(reinterpret_cast<quintptr>(this), 0, 16) : m_sourceIdentity;
        context.revision = m_snapshotRevision;
        context.baseAddress = m_base;
        context.length = static_cast<std::uint64_t>(data().size());
        context.selectedAddress = selectedAddress();
        context.addressBits = architecture() == DisassemblyArchitecture::X64 ? 64 : 32;
        context.addressKind = m_addressKind;
        context.x86Compatible = m_fileX86Compatible;
        m_pseudocodePage->setContext(context);
    }

    // 快照/架构/坐标域变化会使结果失效；返回旧坐标域也不复活已经取消的请求。
    void SnapshotWorkbenchWidget::invalidatePseudocode(bool clearContext)
    {
        if (!m_pseudocodePage) return;
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        m_pseudocodePage->invalidate();
        if (!alive) return;
        if (clearContext)
        {
            // 捕获范围与文件解释同属当前来源，清空或换源不能沿用旧范围。
            m_capturedAddressRange.reset();
            m_fileAnalysisSnapshot.reset();
            m_fileAnalysisRegions.clear();
            m_fileImageBase = 0;
            m_fileX86Compatible = true;
            m_pseudocodePage->setFileAnalysisContext({}, 0, {}, true);
        }
        if (alive) synchronizePseudocodeContext();
    }

    // 字节变化后由共用页面逐字复核请求，不以“相同地址”冒充相同证据。
    void SnapshotWorkbenchWidget::updatePseudocodeState()
    {
        if (!m_pseudocodePage) return;
        synchronizePseudocodeContext();
        m_pseudocodePage->refreshView();
    }

    void SnapshotWorkbenchWidget::setFileAnalysisContext(
        std::shared_ptr<const std::vector<std::uint8_t>> snapshot, std::uint64_t imageBase,
        const QVector<FileAnalysisRegion>& regions, bool x86Compatible)
    {
        // 映像证据只属于文件偏移域；内存/物理快照不能继承它的 VA 解释。
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        ++m_snapshotRevision;
        invalidatePseudocode();
        if (!alive) return;
        m_fileAnalysisSnapshot = m_addressKind == SnapshotAddressKind::FileOffset ? std::move(snapshot) : nullptr;
        m_fileImageBase = imageBase;
        m_fileAnalysisRegions = m_fileAnalysisSnapshot ? regions : QVector<FileAnalysisRegion>();
        m_fileX86Compatible = x86Compatible;
        m_pseudocodePage->setFileAnalysisContext(m_fileAnalysisSnapshot, imageBase, m_fileAnalysisRegions, x86Compatible);
        if (!alive) return;
        updatePseudocodeState();
        if (alive && m_tabs->currentIndex() == 1) rebuildDisassembly();
    }

    std::optional<std::uint64_t> SnapshotWorkbenchWidget::fileOffsetToVirtualAddress(std::uint64_t offset) const
    {
        return m_pseudocodePage->fileOffsetToVirtualAddress(offset);
    }

    std::optional<std::uint64_t> SnapshotWorkbenchWidget::virtualAddressToFileOffset(std::uint64_t address) const
    {
        return m_pseudocodePage->virtualAddressToFileOffset(address);
    }

    void SnapshotWorkbenchWidget::setCapturedAddressRange(std::uint64_t base, std::uint64_t length)
    {
        // 存储可请求的捕获上下界；不会因此把尚未读到的内容补成零字节。
        m_capturedAddressRange = length && length - 1 <= UINT64_MAX - base
            ? std::optional<std::pair<std::uint64_t, std::uint64_t>>({base, base + length - 1}) : std::nullopt;
        synchronizeSnapshotProvider();
    }

    bool SnapshotWorkbenchWidget::requestCapturedWindow(std::uint64_t address, std::uint64_t length)
    {
        if (!m_capturedAddressRange || address < m_capturedAddressRange->first || address > m_capturedAddressRange->second)
            return false;
        const auto available = m_capturedAddressRange->second - address;
        const auto requested = length ? std::min(length - 1, available) + 1 : std::uint64_t{1};
        const auto loaded = contains(address) ? static_cast<std::uint64_t>(data().size()) - (address - m_base) : 0;
        if (loaded >= requested) return false;
        emit windowRequested(address, requested);
        return true;
    }

    // 范围选择直接走新画布；旧 HexEditorWidget 门面不再参与任何路径。
    bool SnapshotWorkbenchWidget::selectByteRange(std::uint64_t first, std::uint64_t last)
    {
        if (first > last || !contains(first) || !contains(last)) return false;
        if (!m_hex->canvas()->setCaretAddress(first, false, true)) return false;
        return m_hex->canvas()->setCaretAddress(last, true, true);
    }

    void SnapshotWorkbenchWidget::showPseudocodeAt(std::uint64_t address)
    {
        const QPointer<SnapshotWorkbenchWidget> alive(this);
        if (!contains(address))
        {
            // 尚未载入的捕获字节先请求窗口；读取完成前不启动反编译。
            const auto revision = m_snapshotRevision;
            m_tabs->setCurrentIndex(4);
            if (alive && revision == m_snapshotRevision) requestCapturedWindow(address, 65536);
            return;
        }
        jumpToAddress(address);
        if (!alive) return;
        synchronizeSnapshotProvider();
        synchronizePseudocodeContext();
        m_tabs->setCurrentIndex(4);
        if (alive) m_pseudocodePage->startDecompilation();
    }

    CodeTextEdit* SnapshotWorkbenchWidget::pseudocodeView() const { return m_pseudocodePage->editor(); }
    GhidraDecompiler* SnapshotWorkbenchWidget::decompiler() const { return m_pseudocodePage->decompiler(); }
}
