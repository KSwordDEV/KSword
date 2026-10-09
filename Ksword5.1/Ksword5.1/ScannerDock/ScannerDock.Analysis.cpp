#include "ScannerDock.h"
#include "../UI/BinaryOverviewBar.h"
#include "../UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "../ksword/scanner/binary_layout.h"
#include "../theme.h"
#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStyle>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>

namespace
{
    constexpr std::uint64_t kAnalysisWindowBytes = 256U * 1024U;
    constexpr std::uint64_t kAnalysisAlignment = 64U * 1024U;
    QString hexOffset(const std::uint64_t offset)
    {
        return QStringLiteral("0x%1").arg(offset, 0, 16).toUpper();
    }
    QString regionLabel(const ks::scanner::BinaryMappedRegion& region)
    {
        return QString::fromUtf8(region.name.data(), static_cast<qsizetype>(region.name.size()));
    }
}

void ScannerDock::buildAnalysisUi()
{
    m_analysisPage = new QWidget(m_mainTabs);
    auto* layout = new QVBoxLayout(m_analysisPage);
    layout->setContentsMargins(6, 6, 6, 6);
    layout->setSpacing(5);
    m_overviewBar = new ks::ui::BinaryOverviewBar(m_analysisPage);
    layout->addWidget(m_overviewBar);
    m_analysisLegend = new QLabel(m_analysisPage);
    m_analysisLegend->setWordWrap(true);
    m_analysisLegend->setTextFormat(Qt::RichText);
    layout->addWidget(m_analysisLegend);

    auto* sectionRow = new QHBoxLayout();
    sectionRow->setSpacing(5);
    m_analysisSectionLabel = new QLabel(m_analysisPage);
    m_analysisSectionCombo = new QComboBox(m_analysisPage);
    m_analysisSectionCombo->setObjectName(QStringLiteral("scanner_analysis_sections"));
    m_analysisSectionCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_analysisSectionCombo->setMinimumContentsLength(8);
    m_analysisSectionCombo->setMinimumWidth(0);
    m_analysisEntryButton = new QPushButton(m_analysisPage);
    m_analysisEntryButton->setObjectName(QStringLiteral("scanner_analysis_entry"));
    m_analysisPreviousButton = new QPushButton(m_analysisPage);
    m_analysisNextButton = new QPushButton(m_analysisPage);
    m_analysisPreviousButton->setIcon(style()->standardIcon(QStyle::SP_ArrowLeft));
    m_analysisNextButton->setIcon(style()->standardIcon(QStyle::SP_ArrowRight));
    KswordTheme::ApplyCompactIconButtonMetrics(m_analysisPreviousButton);
    KswordTheme::ApplyCompactIconButtonMetrics(m_analysisNextButton);
    m_analysisFindButton = new QPushButton(m_analysisPage);
    sectionRow->addWidget(m_analysisSectionLabel);
    sectionRow->addWidget(m_analysisSectionCombo, 1);
    sectionRow->addWidget(m_analysisEntryButton);
    sectionRow->addWidget(m_analysisPreviousButton);
    sectionRow->addWidget(m_analysisNextButton);
    sectionRow->addWidget(m_analysisFindButton);
    layout->addLayout(sectionRow);

    auto* addressRow = new QHBoxLayout();
    addressRow->setSpacing(5);
    m_analysisAddressKind = new QComboBox(m_analysisPage);
    m_analysisAddressKind->setObjectName(QStringLiteral("scanner_analysis_address_kind"));
    m_analysisAddressKind->addItems({QString(), QStringLiteral("RVA"), QStringLiteral("VA")});
    m_analysisAddressEdit = new QLineEdit(m_analysisPage);
    m_analysisAddressEdit->setObjectName(QStringLiteral("scanner_analysis_address"));
    m_analysisAddressEdit->setMinimumWidth(0);
    m_analysisAddressEdit->setPlaceholderText(QStringLiteral("0x00000000"));
    m_analysisJumpButton = new QPushButton(m_analysisPage);
    addressRow->addWidget(m_analysisAddressKind);
    addressRow->addWidget(m_analysisAddressEdit, 1);
    addressRow->addWidget(m_analysisJumpButton);
    layout->addLayout(addressRow);
    m_analysisPosition = new QLabel(m_analysisPage);
    m_analysisPosition->setObjectName(QStringLiteral("scanner_analysis_position"));
    m_analysisPosition->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_analysisPosition->setWordWrap(true);
    layout->addWidget(m_analysisPosition);

    m_analysisEditor = new ks::ui::SnapshotWorkbenchWidget(m_analysisPage);
    m_analysisEditor->setAddressKind(ks::ui::SnapshotAddressKind::FileOffset);
    m_analysisEditor->setEditable(false);
    layout->addWidget(m_analysisEditor, 1);
    m_mainTabs->addTab(m_analysisPage, QString());
    m_analysisPage->setEnabled(false);

    m_overviewBar->offsetActivated = [this](const std::uint64_t offset) { navigateAnalysisOffset(offset); };
    connect(m_analysisEntryButton, &QPushButton::clicked, this, [this]() {
        if (m_lastResult && m_lastResult->entryPointFileOffsetValid)
            navigateAnalysisOffset(m_lastResult->entryPointFileOffset, m_lastResult->x86Compatible);
    });
    connect(m_analysisJumpButton, &QPushButton::clicked, this, [this]() { jumpAnalysisAddress(); });
    connect(m_analysisAddressEdit, &QLineEdit::returnPressed, this, [this]() { jumpAnalysisAddress(); });
    connect(m_analysisAddressKind, &QComboBox::currentIndexChanged, this, [this](int) {
        m_analysisAddressEdit->clearFocus();
        updateAnalysisAddress(m_currentFileOffset);
    });
    connect(m_analysisSectionCombo, &QComboBox::currentIndexChanged, this, [this](int index) {
        if (m_analysisLoading || !m_lastResult || index < 0) return;
        const auto regionIndex = m_analysisSectionCombo->itemData(index).toULongLong();
        if (regionIndex >= m_lastResult->mappedRegions.size()) return;
        const auto& region = m_lastResult->mappedRegions[static_cast<std::size_t>(regionIndex)];
        if (region.fileSize == 0)
        {
            m_analysisPosition->setText(translated("scanner.analysis.virtual_only",
                "该区段只有虚拟空间，没有可查看的文件字节。"));
            return;
        }
        navigateAnalysisOffset(region.fileOffset);
    });
    connect(m_analysisPreviousButton, &QPushButton::clicked, this, [this]() {
        const auto base = m_analysisEditor->baseAddress();
        navigateAnalysisOffset(base - std::min(base, kAnalysisWindowBytes));
    });
    connect(m_analysisNextButton, &QPushButton::clicked, this, [this]() {
        navigateAnalysisOffset(m_analysisEditor->baseAddress() +
            static_cast<std::uint64_t>(m_analysisEditor->data().size()));
    });
    connect(m_analysisFindButton, &QPushButton::clicked, m_analysisEditor, &ks::ui::SnapshotWorkbenchWidget::openFindPanel);
    connect(m_analysisEditor, &ks::ui::SnapshotWorkbenchWidget::currentAddressChanged, this,
        [this](const std::uint64_t address) {
            if (!m_analysisLoading) updateAnalysisAddress(address);
        });
    connect(m_analysisEditor, &ks::ui::SnapshotWorkbenchWidget::windowRequested, this,
        [this](quint64 address, quint64) {
            if (m_analysisLoading || !m_analysisSnapshot || address >= m_analysisSnapshot->size()) return;
            // The view finishes its current paint/fetch before its bounded
            // snapshot is replaced. A new scan invalidates this queued request.
            const auto snapshot = m_analysisSnapshot;
            const auto generation = ++m_analysisNavigationGeneration;
            QTimer::singleShot(0, this, [this, address, snapshot, generation]() {
                if (snapshot == m_analysisSnapshot && generation == m_analysisNavigationGeneration &&
                    !m_analysisLoading && !m_scanBusy)
                    loadAnalysisWindow(address);
            });
        });
}

void ScannerDock::retranslateAnalysisUi()
{
    if (!m_analysisPage) return;
    m_mainTabs->setTabText(m_mainTabs->indexOf(m_analysisPage), translated("scanner.tab.analysis", "可视化分析"));
    m_overviewBar->setAccessibleName(translated("scanner.analysis.overview", "文件区段总览"));
    m_analysisSectionLabel->setText(translated("scanner.analysis.section", "区段"));
    m_analysisEntryButton->setText(translated("scanner.analysis.entry", "入口点"));
    m_analysisFindButton->setText(translated("scanner.analysis.find", "查找"));
    m_analysisJumpButton->setText(translated("scanner.analysis.jump", "跳转"));
    m_analysisAddressKind->setItemText(0, translated("scanner.editor.offset", "文件偏移"));
    m_analysisAddressEdit->setToolTip(translated("scanner.analysis.address_hint",
        "输入十进制或 0x 十六进制地址；RVA/VA 只定位有文件字节的 PE 映射。"));
    m_analysisPreviousButton->setToolTip(translated("scanner.analysis.previous_window", "上一页文件字节"));
    m_analysisNextButton->setToolTip(translated("scanner.analysis.next_window", "下一页文件字节"));
    m_analysisEntryButton->setToolTip(translated("scanner.analysis.entry_hint", "定位 PE 入口点对应的文件字节"));
    using Accent = KswordTheme::AccentRole;
    const auto item = [this](const QColor& color, const char* key, const char* fallback) {
        return QStringLiteral("<span style=\"color:%1\">●</span> %2")
            .arg(color.name(), translated(key, fallback).toHtmlEscaped());
    };
    m_analysisLegend->setText(QStringList{
        item(KswordTheme::AccentColor(Accent::Slate), "scanner.analysis.headers", "文件头"),
        item(KswordTheme::AccentColor(Accent::Blue), "scanner.analysis.code", "代码"),
        item(KswordTheme::AccentColor(Accent::Green), "scanner.analysis.data", "数据"),
        item(KswordTheme::AccentColor(Accent::Purple), "scanner.analysis.resources", "资源"),
        item(KswordTheme::AccentColor(Accent::Orange), "scanner.analysis.overlay", "尾部附加数据"),
        item(KswordTheme::TextDisabledColor(), "scanner.analysis.unmapped", "未映射数据")
    }.join(QStringLiteral(" &nbsp; ")));
    if (!m_lastResult) m_analysisPosition->setText(translated("scanner.analysis.empty", "扫描文件后查看区段、字节、反汇编与文本。"));
}

void ScannerDock::renderAnalysisResult()
{
    if (!m_analysisEditor || !m_lastResult) return;
    const auto previousSnapshot = m_analysisSnapshot;
    ++m_analysisNavigationGeneration;
    m_analysisSnapshot = m_lastResult->inputSnapshot;
    if (previousSnapshot != m_analysisSnapshot) m_analysisArchitectureInitialized = false;
    m_overviewBar->setLayout(m_lastResult);
    const bool available = m_analysisSnapshot && !m_analysisSnapshot->empty();
    m_analysisPage->setEnabled(available);
    const QSignalBlocker blocker(m_analysisSectionCombo);
    m_analysisSectionCombo->clear();
    for (std::size_t index = 0; index < m_lastResult->mappedRegions.size(); ++index)
    {
        const auto& region = m_lastResult->mappedRegions[index];
        QString name = region.kind == ks::scanner::BinaryRegionKind::Headers
            ? translated("scanner.analysis.headers", "文件头")
            : region.kind == ks::scanner::BinaryRegionKind::Overlay
                ? translated("scanner.analysis.overlay", "尾部附加数据") : regionLabel(region);
        name += QStringLiteral(" · %1 · %2 B").arg(hexOffset(region.fileOffset)).arg(region.fileSize);
        m_analysisSectionCombo->addItem(name, QVariant::fromValue(static_cast<qulonglong>(index)));
        if (region.fileSize == 0) m_analysisSectionCombo->setItemData(static_cast<int>(index),
            translated("scanner.analysis.virtual_only", "该区段只有虚拟空间，没有可查看的文件字节。"), Qt::ToolTipRole);
    }
    m_analysisSectionCombo->setEnabled(!m_lastResult->mappedRegions.empty());
    m_analysisEntryButton->setEnabled(available && m_lastResult->entryPointFileOffsetValid &&
        m_lastResult->entryPointFileOffset < m_analysisSnapshot->size());
    const bool pe = m_lastResult->format == ks::scanner::BinaryFormat::Pe32 ||
        m_lastResult->format == ks::scanner::BinaryFormat::Pe32Plus;
    m_analysisAddressKind->setEnabled(pe);
    if (!pe) m_analysisAddressKind->setCurrentIndex(0);
    if (!available)
    {
        m_analysisEditor->clear();
        m_currentFileOffset = 0;
        m_analysisPosition->setText(translated("scanner.analysis.no_snapshot", "当前文件没有可查看的字节快照。"));
        return;
    }
    auto offset = previousSnapshot == m_analysisSnapshot ? m_currentFileOffset : 0;
    if (offset >= m_analysisSnapshot->size()) offset = 0;
    loadAnalysisWindow(offset);
}

void ScannerDock::loadAnalysisWindow(const std::uint64_t offset)
{
    if (m_analysisLoading || !m_analysisSnapshot || offset >= m_analysisSnapshot->size() || !m_lastResult) return;
    m_analysisLoading = true;
    const auto base = (offset / kAnalysisAlignment) * kAnalysisAlignment;
    const auto length = std::min<std::uint64_t>(kAnalysisWindowBytes, m_analysisSnapshot->size() - base);
    const QByteArray bytes(reinterpret_cast<const char*>(m_analysisSnapshot->data() + base),
        static_cast<qsizetype>(length));
    const auto architecture = m_analysisArchitectureInitialized
        ? m_analysisEditor->currentArchitecture()
        : m_lastResult->is64Bit ? ks::ui::DisassemblyArchitecture::X64 : ks::ui::DisassemblyArchitecture::X86;
    m_analysisEditor->setSnapshot(bytes, base, architecture,
        offset, QStringLiteral("scanner:%1").arg(m_scanGeneration.load()));
    QVector<ks::ui::FileAnalysisRegion> regions;
    for (const auto& region : m_lastResult->mappedRegions)
    {
        if (!region.mapped) continue;
        regions.push_back(ks::ui::FileAnalysisRegion{region.fileOffset, region.fileSize,
            region.rva, region.virtualSize, regionLabel(region), (region.characteristics & 0x20000000U) != 0});
    }
    if (m_lastResult->format == ks::scanner::BinaryFormat::Pe32 ||
        m_lastResult->format == ks::scanner::BinaryFormat::Pe32Plus)
        m_analysisEditor->setFileAnalysisContext(m_analysisSnapshot, m_lastResult->imageBase, regions,
            m_lastResult->x86Compatible);
    m_analysisEditor->setCapturedAddressRange(0, m_analysisSnapshot->size());
    m_analysisArchitectureInitialized = true;
    m_analysisLoading = false;
    updateAnalysisAddress(offset);
}

void ScannerDock::navigateAnalysisOffset(const std::uint64_t offset, const bool showDisassembly)
{
    if (!m_analysisSnapshot || offset >= m_analysisSnapshot->size()) return;
    ++m_analysisNavigationGeneration;
    m_mainTabs->setCurrentWidget(m_analysisPage);
    const auto base = m_analysisEditor->baseAddress();
    const auto length = static_cast<std::uint64_t>(m_analysisEditor->data().size());
    if (offset < base || offset - base >= length) loadAnalysisWindow(offset);
    if (showDisassembly) m_analysisEditor->showDisassemblyAt(offset);
    else m_analysisEditor->jumpToAddress(offset);
    updateAnalysisAddress(offset);
}

void ScannerDock::updateAnalysisAddress(const std::uint64_t offset)
{
    if (!m_lastResult || !m_analysisSnapshot || offset >= m_analysisSnapshot->size()) return;
    m_currentFileOffset = offset;
    m_overviewBar->setCurrentOffset(offset);
    const auto rva = ks::scanner::FileOffsetToRva(*m_lastResult, offset);
    const auto va = ks::scanner::FileOffsetToVa(*m_lastResult, offset);
    QString position = translated("scanner.analysis.offset", "文件偏移：%1").arg(hexOffset(offset));
    if (rva && va) position += QStringLiteral(" · RVA: %1 · VA: %2").arg(hexOffset(*rva), hexOffset(*va));
    const auto base = m_analysisEditor->baseAddress();
    const auto length = static_cast<std::uint64_t>(m_analysisEditor->data().size());
    position += QStringLiteral(" · ") + translated("scanner.analysis.loaded_window", "已加载：%1 – %2")
        .arg(hexOffset(base), hexOffset(base + length - 1));
    m_analysisPosition->setText(position);
    if (!m_analysisAddressEdit->hasFocus())
    {
        const auto mode = m_analysisAddressKind->currentIndex();
        const auto value = mode == 1 ? rva : mode == 2 ? va : std::optional<std::uint64_t>(offset);
        m_analysisAddressEdit->setText(value ? hexOffset(*value) : QString());
    }
    m_analysisPreviousButton->setEnabled(base != 0);
    m_analysisNextButton->setEnabled(length < m_analysisSnapshot->size() - base);
    for (std::size_t index = 0; index < m_lastResult->mappedRegions.size(); ++index)
    {
        const auto& region = m_lastResult->mappedRegions[index];
        if (offset < region.fileOffset || offset - region.fileOffset >= region.fileSize) continue;
        const QSignalBlocker blocker(m_analysisSectionCombo);
        m_analysisSectionCombo->setCurrentIndex(static_cast<int>(index));
        break;
    }
}

void ScannerDock::jumpAnalysisAddress()
{
    if (!m_lastResult || !m_analysisSnapshot) return;
    const QString input = m_analysisAddressEdit->text().trimmed();
    bool ok = false;
    const auto value = input.toULongLong(&ok, input.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
    std::optional<std::uint64_t> offset;
    if (ok && !input.isEmpty())
    {
        switch (m_analysisAddressKind->currentIndex())
        {
        case 1: offset = ks::scanner::RvaToFileOffset(*m_lastResult, value); break;
        case 2: offset = ks::scanner::VaToFileOffset(*m_lastResult, value); break;
        default: if (value < m_analysisSnapshot->size()) offset = value; break;
        }
    }
    if (!offset)
    {
        m_analysisPosition->setText(translated("scanner.analysis.invalid_address",
            "地址越界或没有对应的文件字节（例如虚拟零填充区段）。"));
        return;
    }
    m_analysisAddressEdit->clearFocus();
    navigateAnalysisOffset(*offset);
}
