#include "MemoryEditorWidget.h"
#include "CodeTextEdit.h"
#include "HexEditorWidget.h"
#include "Decompiler/GhidraDecompiler.h"
#include "../PluginHost.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QCheckBox>
#include <QFileDialog>
#include <QFontDatabase>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSettings>
#include <QSignalBlocker>
#include <QTabWidget>
#include <QTextBlock>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

namespace ks::ui
{
    namespace
    {
        QString pseudoText(const QString& source) { return ks::i18n::sourceText(source); }
        QString pseudoAddress(std::uint64_t address)
        {
            return QStringLiteral("0x%1").arg(address, 0, 16).toUpper();
        }
        QString decompilerErrorText(const QString& code)
        {
            if (code == QStringLiteral("ghidra_not_configured"))
                return pseudoText(QStringLiteral("请通过插件管理安装 Ghidra 反编译后端。"));
            if (code == QStringLiteral("java_not_found"))
                return pseudoText(QStringLiteral("未找到兼容的 JDK；请设置 JAVA_HOME 或 KSWORD_GHIDRA_JAVA。"));
            if (code == QStringLiteral("snapshot_too_large"))
                return pseudoText(QStringLiteral("快照超过反编译后端的大小上限；请缩小分析范围。"));
            if (code == QStringLiteral("timeout")) return pseudoText(QStringLiteral("反编译超时；可以缩小范围后重试。"));
            if (code == QStringLiteral("cancelled")) return pseudoText(QStringLiteral("反编译已取消。"));
            if (code == QStringLiteral("no_function_at_address"))
                return pseudoText(QStringLiteral("当前位置没有可恢复的函数；请在代码节选择函数起点后重试。"));
            if (code == QStringLiteral("unsupported_architecture"))
                return pseudoText(QStringLiteral("当前伪代码后端仅支持 x86/x64 指令集。"));
            if (code == QStringLiteral("unmapped_pe_address") || code == QStringLiteral("invalid_address"))
                return pseudoText(QStringLiteral("当前位置没有有效的 PE 地址映射；请选择有文件内容的代码节。"));
            if (code == QStringLiteral("process_isolation_failed"))
                return pseudoText(QStringLiteral("无法创建隔离的反编译进程；请检查系统进程限制。"));
            return pseudoText(QStringLiteral("反编译失败（%1）；请检查后端目录和运行日志。")).arg(code);
        }
    }

    void MemoryEditorWidget::initializePseudocodeView()
    {
        m_decompiler = new GhidraDecompiler(this);
        auto* page = new QWidget(m_tabs);
        page->setObjectName(QStringLiteral("memory_pseudocode_page"));
        auto* layout = new QVBoxLayout(page);
        layout->setContentsMargins(0, 0, 0, 0);
        auto* configuration = new QHBoxLayout;
        m_decompilerRuntimeStatus = new QLabel(page);
        m_decompilerRuntimeStatus->setObjectName(QStringLiteral("memory_decompiler_runtime_status"));
        m_decompilerRuntimeStatus->setTextFormat(Qt::PlainText);
        configuration->addWidget(m_decompilerRuntimeStatus, 1);
        m_installGhidra = new QPushButton(pseudoText(QStringLiteral("安装 / 管理 Ghidra 插件")), page);
        m_installGhidra->setObjectName(QStringLiteral("memory_install_ghidra_plugin"));
        m_refreshGhidra = new QPushButton(pseudoText(QStringLiteral("刷新后端")), page);
        auto* advanced = new QCheckBox(pseudoText(QStringLiteral("高级路径")), page);
        configuration->addWidget(m_installGhidra);
        configuration->addWidget(m_refreshGhidra);
        configuration->addWidget(advanced);
        layout->addLayout(configuration);
        auto* advancedPage = new QWidget(page);
        auto* paths = new QHBoxLayout(advancedPage);
        paths->setContentsMargins(0, 0, 0, 0);
        paths->addWidget(new QLabel(pseudoText(QStringLiteral("Ghidra 目录")), advancedPage));
        m_ghidraDirectory = new QLineEdit(page);
        m_ghidraDirectory->setObjectName(QStringLiteral("memory_decompiler_directory"));
        QSettings settings;
        const auto directory = settings.value(QStringLiteral("analysis/ghidra_directory")).toString();
        m_ghidraDirectory->setText(directory);
        m_ghidraDirectory->setPlaceholderText(pseudoText(QStringLiteral("选择解压后的 Ghidra 安装目录")));
        m_decompiler->setGhidraDirectory(directory);
        paths->addWidget(m_ghidraDirectory, 1);
        auto* browse = new QPushButton(pseudoText(QStringLiteral("浏览…")), page);
        paths->addWidget(browse);
        layout->addWidget(advancedPage);
        advanced->setChecked(!directory.isEmpty());
        advancedPage->setVisible(advanced->isChecked());
        connect(advanced, &QCheckBox::toggled, advancedPage, &QWidget::setVisible);
        connect(m_installGhidra, &QPushButton::clicked, this, [this]() {
            ks::plugin_host::showPluginManager(this, QStringLiteral("ghidra"));
        });
        connect(m_refreshGhidra, &QPushButton::clicked, this, &MemoryEditorWidget::refreshDecompilerRuntime);
        auto* tools = new QHBoxLayout;
        m_decompile = new QPushButton(pseudoText(QStringLiteral("反编译当前函数")), page);
        m_decompile->setObjectName(QStringLiteral("memory_decompile_function"));
        m_cancelDecompile = new QPushButton(pseudoText(QStringLiteral("取消")), page);
        m_cancelDecompile->setObjectName(QStringLiteral("memory_decompile_cancel"));
        m_pseudocodeHex = new QPushButton(pseudoText(QStringLiteral("定位十六进制")), page);
        m_pseudocodeDisassembly = new QPushButton(pseudoText(QStringLiteral("定位反汇编")), page);
        m_pseudocodeHex->setObjectName(QStringLiteral("memory_pseudocode_locate_hex"));
        m_pseudocodeDisassembly->setObjectName(QStringLiteral("memory_pseudocode_locate_disassembly"));
        tools->addWidget(m_decompile);
        tools->addWidget(m_cancelDecompile);
        tools->addStretch();
        tools->addWidget(m_pseudocodeHex);
        tools->addWidget(m_pseudocodeDisassembly);
        layout->addLayout(tools);
        m_pseudocodeStatus = new QLabel(page);
        m_pseudocodeStatus->setObjectName(QStringLiteral("memory_pseudocode_status"));
        m_pseudocodeStatus->setTextFormat(Qt::PlainText);
        m_pseudocodeStatus->setWordWrap(true);
        m_pseudocodeStatus->setTextInteractionFlags(Qt::TextSelectableByMouse);
        m_pseudocodeStatus->setText(pseudoText(QStringLiteral("选择代码地址后反编译；伪代码基于当前快照，类型和函数边界由后端推断。")));
        layout->addWidget(m_pseudocodeStatus);
        m_pseudocode = new CodeTextEdit(page);
        connect(m_pseudocode, &QObject::destroyed, this, [this]() { m_pseudocode = nullptr; });
        static_cast<CodeTextEdit*>(m_pseudocode)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Cpp);
        m_pseudocode->setObjectName(QStringLiteral("memory_pseudocode_view"));
        m_pseudocode->setReadOnly(true);
        m_pseudocode->setLineWrapMode(QPlainTextEdit::NoWrap);
        layout->addWidget(m_pseudocode, 1);
        m_tabs->addTab(page, pseudoText(QStringLiteral("C 伪代码")));
        connect(browse, &QPushButton::clicked, this, [this]() {
            const QPointer<MemoryEditorWidget> self(this);
            const auto chosen = QFileDialog::getExistingDirectory(this,
                pseudoText(QStringLiteral("选择 Ghidra 安装目录")), m_ghidraDirectory->text());
            if (!self || chosen.isEmpty()) return;
            m_ghidraDirectory->setText(chosen);
            m_decompiler->setGhidraDirectory(chosen);
            QSettings().setValue(QStringLiteral("analysis/ghidra_directory"), chosen);
            refreshDecompilerRuntime();
        });
        connect(m_ghidraDirectory, &QLineEdit::editingFinished, this, [this]() {
            const auto chosen = m_ghidraDirectory->text().trimmed();
            m_decompiler->setGhidraDirectory(chosen);
            QSettings().setValue(QStringLiteral("analysis/ghidra_directory"), chosen);
            refreshDecompilerRuntime();
        });
        connect(m_decompile, &QPushButton::clicked, this, &MemoryEditorWidget::startDecompilation);
        connect(m_cancelDecompile, &QPushButton::clicked, this, [this]() { m_decompiler->cancel(); });
        connect(m_pseudocodeHex, &QPushButton::clicked, this, [this]() { locatePseudocodeLine(false); });
        connect(m_pseudocodeDisassembly, &QPushButton::clicked, this, [this]() { locatePseudocodeLine(true); });
        connect(m_pseudocode, &QPlainTextEdit::cursorPositionChanged, this, &MemoryEditorWidget::updatePseudocodeState);
        connect(m_decompiler, &GhidraDecompiler::runningChanged, this, [this](bool) { updatePseudocodeState(); });
        connect(m_decompiler, &GhidraDecompiler::finished, this, [this](const DecompilerResult& result) {
            if (m_pseudocodeRequestRevision != m_snapshotRevision
                || m_pseudocodeContextRevision == 0) return;
            const QPointer<MemoryEditorWidget> self(this);
            const auto revision = m_pseudocodeRequestRevision;
            const auto context = m_pseudocodeContextRevision;
            m_pseudocodeLineAddresses = result.lineAddresses;
            m_pseudocodeLineValid = result.lineAddressValid;
            if (result.success)
            {
                if (!setPseudocodeText(result.code)) return;
                if (!self || revision != m_snapshotRevision || context != m_pseudocodeContextRevision) return;
                auto status = pseudoText(QStringLiteral("%1 | 函数地址 %2 | 分析位置 %3；伪代码由当前字节快照推断。"))
                    .arg(result.functionName, pseudoAddress(result.functionAddress), pseudoAddress(m_pseudocodeRequestAddress));
                if (result.boundaryInferred)
                    status += QLatin1Char('\n') + pseudoText(QStringLiteral("RAW 候选函数：起点按选中地址推断；请从已知函数起点分析。"));
                m_pseudocodeStatus->setText(status);
            }
            else
            {
                if (!setPseudocodeText(QString())) return;
                if (!self || revision != m_snapshotRevision || context != m_pseudocodeContextRevision) return;
                m_pseudocodeLineAddresses.clear();
                m_pseudocodeLineValid.clear();
                m_pseudocodeStatus->setText(decompilerErrorText(result.error));
            }
            m_pseudocodeStatus->setToolTip(result.diagnostics.toHtmlEscaped());
            updatePseudocodeState();
        });
        updatePseudocodeState();
        refreshDecompilerRuntime();
    }

    bool MemoryEditorWidget::setPseudocodeText(const QString& text)
    {
        const QPointer<MemoryEditorWidget> self(this);
        const QPointer<QPlainTextEdit> view(m_pseudocode);
        if (!view) return false;
        const auto epoch = m_pseudocodeEpoch;
        const auto oldText = view->toPlainText();
        const auto oldBlocks = view->blockCount();
        const auto oldPosition = view->textCursor().position();
        {
            // A host may close the owner from textChanged. Deliver public
            // notifications only after Qt's native document mutation returns.
            // Document signals stay live for its layout and syntax highlighter.
            const QSignalBlocker mutationSignals(view.data());
            view->setPlainText(text);
        }
        const auto valid = [&]() { return self && view && epoch == m_pseudocodeEpoch; };
        if (!valid()) return false;
        if (oldBlocks != view->blockCount()) emit view->blockCountChanged(view->blockCount());
        if (!valid()) return false;
        if (oldText != text) emit view->textChanged();
        if (!valid()) return false;
        if (oldPosition != view->textCursor().position()) emit view->cursorPositionChanged();
        if (!valid()) return false;
        emit view->updateRequest(view->viewport()->rect(), 0);
        return valid();
    }

    void MemoryEditorWidget::invalidatePseudocode(bool clearContext)
    {
        const QPointer<MemoryEditorWidget> self(this);
        const auto epoch = ++m_pseudocodeEpoch;
        m_pseudocodeContextRevision = 0;
        m_pseudocodeRequestRevision = 0;
        if (m_decompiler) m_decompiler->cancel();
        if (!self || epoch != m_pseudocodeEpoch) return;
        m_pseudocodeLineAddresses.clear();
        m_pseudocodeLineValid.clear();
        if (m_pseudocode && !setPseudocodeText(QString())) return;
        if (!self || epoch != m_pseudocodeEpoch) return;
        if (clearContext)
        {
            m_fileAnalysisSnapshot.reset();
            m_fileAnalysisRegions.clear();
            m_fileImageBase = 0;
            m_fileX86Compatible = true;
            m_capturedAddressRange.reset();
        }
        if (m_pseudocodeStatus)
        {
            m_pseudocodeStatus->setToolTip(QString());
            m_pseudocodeStatus->setText(pseudoText(QStringLiteral("快照或分析上下文已变化；请重新反编译当前函数。")));
        }
        updatePseudocodeState();
    }

    void MemoryEditorWidget::setFileAnalysisContext(
        std::shared_ptr<const std::vector<std::uint8_t>> snapshot, std::uint64_t imageBase,
        const QVector<FileAnalysisRegion>& regions, bool x86Compatible)
    {
        const QPointer<MemoryEditorWidget> alive(this);
        const auto revision = m_snapshotRevision;
        const auto expectedEpoch = m_pseudocodeEpoch + 1;
        invalidatePseudocode();
        if (!alive || revision != m_snapshotRevision || expectedEpoch != m_pseudocodeEpoch) return;
        m_fileAnalysisSnapshot = m_addressKind == SnapshotAddressKind::FileOffset ? std::move(snapshot) : nullptr;
        m_fileImageBase = imageBase;
        m_fileAnalysisRegions = m_fileAnalysisSnapshot ? regions : QVector<FileAnalysisRegion>();
        m_fileX86Compatible = x86Compatible;
        updatePseudocodeState();
        if (m_tabs->currentIndex() == 1) rebuildDisassembly();
    }

    std::optional<std::uint64_t> MemoryEditorWidget::fileOffsetToVirtualAddress(std::uint64_t offset) const
    {
        if (!m_fileAnalysisSnapshot || offset >= m_fileAnalysisSnapshot->size()) return std::nullopt;
        std::optional<std::uint64_t> candidate;
        for (const auto& region : m_fileAnalysisRegions)
        {
            if (offset < region.fileOffset) continue;
            const auto delta = offset - region.fileOffset;
            const auto mappedSize = std::min(region.fileSize, region.virtualSize ? region.virtualSize : region.fileSize);
            if (delta >= mappedSize) continue;
            if (candidate || region.rva > UINT32_MAX || delta > UINT32_MAX - region.rva
                || region.rva > UINT64_MAX - m_fileImageBase
                || delta > UINT64_MAX - (m_fileImageBase + region.rva)) return std::nullopt;
            candidate = m_fileImageBase + region.rva + delta;
        }
        return candidate;
    }

    std::optional<std::uint64_t> MemoryEditorWidget::virtualAddressToFileOffset(std::uint64_t address) const
    {
        if (!m_fileAnalysisSnapshot || address < m_fileImageBase || address - m_fileImageBase > UINT32_MAX)
            return std::nullopt;
        const auto rva = address - m_fileImageBase;
        std::optional<std::uint64_t> candidate;
        for (const auto& region : m_fileAnalysisRegions)
        {
            if (rva < region.rva) continue;
            const auto delta = rva - region.rva;
            const auto mappedSize = std::min(region.fileSize, region.virtualSize ? region.virtualSize : region.fileSize);
            if (delta >= mappedSize) continue;
            if (candidate || delta > UINT64_MAX - region.fileOffset) return std::nullopt;
            const auto offset = region.fileOffset + delta;
            if (offset >= m_fileAnalysisSnapshot->size()) return std::nullopt;
            candidate = offset;
        }
        return candidate;
    }

    void MemoryEditorWidget::setCapturedAddressRange(std::uint64_t base, std::uint64_t length)
    {
        m_capturedAddressRange = length && length - 1 <= UINT64_MAX - base
            ? std::optional<std::pair<std::uint64_t, std::uint64_t>>(std::make_pair(base, base + length - 1)) : std::nullopt;
        synchronizeSnapshotProvider();
    }

    bool MemoryEditorWidget::requestCapturedWindow(std::uint64_t address, std::uint64_t length)
    {
        if (!m_capturedAddressRange || address < m_capturedAddressRange->first
            || address > m_capturedAddressRange->second) return false;
        const auto available = m_capturedAddressRange->second - address;
        const auto requested = length ? std::min(length - 1, available) + 1 : std::uint64_t{1};
        const auto loaded = contains(address) ? static_cast<std::uint64_t>(data().size()) - (address - m_base) : 0;
        if (loaded >= requested) return false;
        emit windowRequested(address, requested);
        return true;
    }

    void MemoryEditorWidget::startDecompilation()
    {
        if (!m_pseudocode || m_decompiler->isRunning() || data().isEmpty()) return;
        const auto address = selectedAddress();
        if (!contains(address)) return;
        const QPointer<MemoryEditorWidget> self(this);
        const auto revision = m_snapshotRevision;
        const auto expectedEpoch = m_pseudocodeEpoch + 1;
        invalidatePseudocode();
        if (!self || revision != m_snapshotRevision || expectedEpoch != m_pseudocodeEpoch
            || m_decompiler->isRunning()) return;
        DecompilerRequest request;
        request.selectedAddress = address;
        request.baseAddress = m_base;
        request.x64 = architecture() == DisassemblyArchitecture::X64;
        m_pseudocodeResultIsPe = false;
        if (m_fileAnalysisSnapshot)
        {
            if (m_fileAnalysisSnapshot->size() > static_cast<std::size_t>(GhidraDecompiler::MaximumPeBytes))
            {
                m_pseudocodeStatus->setText(decompilerErrorText(QStringLiteral("snapshot_too_large")));
                return;
            }
            const auto va = fileOffsetToVirtualAddress(address);
            if (!m_fileX86Compatible)
            {
                m_pseudocodeStatus->setText(decompilerErrorText(QStringLiteral("unsupported_architecture")));
                return;
            }
            if (!va)
            {
                m_pseudocodeStatus->setText(decompilerErrorText(QStringLiteral("unmapped_pe_address")));
                return;
            }
            request.bytes = QByteArray(reinterpret_cast<const char*>(m_fileAnalysisSnapshot->data()),
                static_cast<qsizetype>(m_fileAnalysisSnapshot->size()));
            // Overlay this viewer's staged window onto the SAME captured image.
            const auto current = data();
            if (m_base > static_cast<std::uint64_t>(request.bytes.size())
                || static_cast<std::uint64_t>(current.size()) > static_cast<std::uint64_t>(request.bytes.size()) - m_base)
            {
                m_pseudocodeStatus->setText(decompilerErrorText(QStringLiteral("invalid_address")));
                return;
            }
            request.bytes.replace(static_cast<qsizetype>(m_base), current.size(), current);
            request.baseAddress = m_fileImageBase;
            request.selectedAddress = *va;
            request.inputKind = DecompilerInputKind::PortableExecutable;
            m_pseudocodeResultIsPe = true;
        }
        else request.bytes = data();
        m_pseudocodeRequestRevision = m_snapshotRevision;
        m_pseudocodeContextRevision = ++m_pseudocodeEpoch;
        m_pseudocodeRequestAddress = address;
        m_decompiler->setGhidraDirectory(m_ghidraDirectory->text().trimmed());
        refreshDecompilerRuntime();
        m_pseudocodeStatus->setText(m_pseudocodeResultIsPe
            ? pseudoText(QStringLiteral("正在反编译 PE 函数：文件偏移 %1 → VA %2…")).arg(pseudoAddress(address), pseudoAddress(request.selectedAddress))
            : pseudoText(QStringLiteral("正在按原始 x86/x64 快照反编译 %1；缺失范围不会补零。")).arg(pseudoAddress(address)));
        m_decompiler->start(request);
        if (self) updatePseudocodeState();
    }

    void MemoryEditorWidget::updatePseudocodeState()
    {
        if (!m_decompiler || !m_pseudocode) return;
        const bool running = m_decompiler->isRunning();
        m_decompile->setEnabled(!running && !data().isEmpty());
        m_cancelDecompile->setEnabled(running);
        m_ghidraDirectory->setEnabled(!running);
        m_installGhidra->setEnabled(!running);
        m_refreshGhidra->setEnabled(!running);
        const auto line = m_pseudocode->textCursor().blockNumber();
        const bool mapped = line >= 0 && line < m_pseudocodeLineAddresses.size()
            && line < m_pseudocodeLineValid.size() && m_pseudocodeLineValid.at(line);
        m_pseudocodeHex->setEnabled(!running && mapped);
        m_pseudocodeDisassembly->setEnabled(!running && mapped);
    }

    void MemoryEditorWidget::locatePseudocodeLine(bool disassembly)
    {
        const auto line = m_pseudocode->textCursor().blockNumber();
        if (line < 0 || line >= m_pseudocodeLineAddresses.size()
            || line >= m_pseudocodeLineValid.size() || !m_pseudocodeLineValid.at(line)) return;
        const auto source = m_pseudocodeLineAddresses.at(line);
        const auto address = m_pseudocodeResultIsPe ? virtualAddressToFileOffset(source)
            : std::optional<std::uint64_t>(source);
        if (!address) return;
        if (disassembly) showDisassemblyAt(*address);
        else
        {
            const QPointer<MemoryEditorWidget> self(this);
            m_tabs->setCurrentIndex(0);
            if (self) jumpToAddress(*address);
        }
    }

    void MemoryEditorWidget::showPseudocodeAt(std::uint64_t address)
    {
        const QPointer<MemoryEditorWidget> self(this);
        if (!contains(address))
        {
            m_tabs->setCurrentIndex(4);
            if (self) requestCapturedWindow(address, 65536);
            return;
        }
        jumpToAddress(address);
        if (!self) return;
        m_tabs->setCurrentIndex(4);
        if (self) startDecompilation();
    }
    QPlainTextEdit* MemoryEditorWidget::pseudocodeView() const { return m_pseudocode; }
    GhidraDecompiler* MemoryEditorWidget::decompiler() const { return m_decompiler; }

    void MemoryEditorWidget::refreshDecompilerRuntime()
    {
        if (!m_decompiler || !m_decompilerRuntimeStatus || m_decompiler->isRunning()) return;
        m_decompiler->setGhidraDirectory(m_ghidraDirectory->text().trimmed());
        const bool managed = m_ghidraDirectory->text().trimmed().isEmpty()
            && qEnvironmentVariable("KSWORD_GHIDRA_DIR").trimmed().isEmpty()
            && !GhidraDecompiler::installedPluginDirectory().isEmpty();
        m_decompilerRuntimeStatus->setText(managed
            ? pseudoText(QStringLiteral("已就绪：Ghidra 插件"))
            : !m_decompiler->ghidraDirectory().isEmpty()
                ? pseudoText(QStringLiteral("已就绪：自定义 Ghidra 后端"))
                : pseudoText(QStringLiteral("未安装 Ghidra 插件")));
    }
}
