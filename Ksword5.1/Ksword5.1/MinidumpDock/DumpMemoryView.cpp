// ============================================================
// DumpMemoryView.cpp
// 作用：实现转储虚拟内存查看器的安全地址解析、重开文件读取与分页。
// ============================================================

#include "DumpMemoryView.h"
#include "../UI/StructuredFieldView.h"

#include "Internationalization/LanguageManager.h"
#include "MinidumpFormat.h"
#include "UI/MemoryWorkbench/HexView.h"
#include "UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "theme.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPushButton>
#include <QRegularExpression>
#include <QTextBrowser>
#include <QVBoxLayout>

#include <algorithm>
#include <limits>

namespace
{
    // kMaximumReadBytes：单次读取硬上限，避免用户输入或畸形目录触发大分配。
    constexpr std::uint64_t kMaximumReadBytes = 64ull * 1024ull;
    // kInitialContentProbeBytes：首次打开时每个范围的只读抽样窗口。它只用于避免
    // 默认页恰好是全零块，不改变用户按地址查看任何已捕获范围的能力。
    constexpr std::uint64_t kInitialContentProbeBytes = 512;

    QString inputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QComboBox{"
            "  border:1px solid %2;"
            "  border-radius:4px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QComboBox:focus{ border:1px solid %1; }")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    QString buttonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    bool parseUnsignedAddress(const QString& text, std::uint64_t* const valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }
        QString normalized = text.trimmed();
        if (normalized.isEmpty())
        {
            return false;
        }
        int base = 10;
        if (normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2);
            base = 16;
        }
        else if (normalized.contains(QRegularExpression(QStringLiteral("[A-Fa-f]"))))
        {
            // 裸十六进制地址在调试场景很常见，如 FFFFF8058282A8E0。
            base = 16;
        }
        bool ok = false;
        const qulonglong value = normalized.toULongLong(&ok, base);
        if (!ok)
        {
            return false;
        }
        *valueOut = static_cast<std::uint64_t>(value);
        return true;
    }
}

DumpMemoryView::DumpMemoryView(QWidget* parent)
    : QWidget(parent)
{
    auto* const rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(8, 8, 8, 8);
    rootLayout->setSpacing(8);

    auto* const toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);
    m_addressLabel = new QLabel(this);
    m_addressEdit = new QLineEdit(this);
    m_addressEdit->setClearButtonEnabled(true);
    m_readSizeLabel = new QLabel(this);
    m_readSizeCombo = new QComboBox(this);
    m_readSizeCombo->addItem(QStringLiteral("256 B"), 256);
    m_readSizeCombo->addItem(QStringLiteral("1 KiB"), 1024);
    m_readSizeCombo->addItem(QStringLiteral("4 KiB"), 4 * 1024);
    m_readSizeCombo->addItem(QStringLiteral("16 KiB"), 16 * 1024);
    m_readSizeCombo->addItem(QStringLiteral("64 KiB"), 64 * 1024);
    m_readSizeCombo->setCurrentIndex(2);
    m_readButton = new QPushButton(this);
    m_previousButton = new QPushButton(this);
    m_nextButton = new QPushButton(this);
    m_addressEdit->setStyleSheet(inputStyle());
    m_readSizeCombo->setStyleSheet(inputStyle());
    for (QPushButton* const button : { m_readButton, m_previousButton, m_nextButton })
    {
        button->setStyleSheet(buttonStyle());
    }

    toolbarLayout->addWidget(m_addressLabel);
    toolbarLayout->addWidget(m_addressEdit, 1);
    toolbarLayout->addWidget(m_readSizeLabel);
    toolbarLayout->addWidget(m_readSizeCombo);
    toolbarLayout->addWidget(m_readButton);
    toolbarLayout->addWidget(m_previousButton);
    toolbarLayout->addWidget(m_nextButton);
    rootLayout->addLayout(toolbarLayout);

    // 映射说明直接使用原生字段模型；复制与导出由模型按需生成。
    m_messageView = new ks::ui::StructuredFieldView(this);
    m_messageView->setMaximumHeight(145);
    rootLayout->addWidget(m_messageView);

    m_memoryEditor = new ks::ui::SnapshotWorkbenchWidget(this);
    m_memoryEditor->setEditable(false);
    m_hexEditor = m_memoryEditor->hexEditor();
    rootLayout->addWidget(m_memoryEditor, 1);

    connect(m_readButton, &QPushButton::clicked, this, [this]() { loadCurrentInput(); });
    connect(m_addressEdit, &QLineEdit::returnPressed, this, [this]() { loadCurrentInput(); });
    connect(m_previousButton, &QPushButton::clicked, this, [this]() { goPreviousPage(); });
    connect(m_nextButton, &QPushButton::clicked, this, [this]() { goNextPage(); });
    connect(m_readSizeCombo, &QComboBox::currentIndexChanged, this, [this](const int)
        {
            if (m_currentRangeIndex >= 0)
            {
                loadAddress(m_currentAddress);
            }
        });
    retranslateUi();
    clearData();
}

void DumpMemoryView::setDumpData(const ks::minidump::DumpParseResult& result)
{
    m_pointerSize = result.pointerSize;
    m_architectureInitialized = false;
    m_memoryEditor->clear();
    m_filePath = result.filePath;
    m_expectedFileSize = result.fileSize;
    m_expectedFileLastModifiedUtcMs = result.fileLastModifiedUtcMs;
    m_ranges = result.capturedMemoryRanges;
    m_modules = result.modules;
    m_memoryRegions = result.memoryRegions;
    m_currentAddress = 0;
    m_currentReadBytes = 0;
    m_currentRangeIndex = -1;
    retranslateUi();

    if (m_ranges.empty())
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.no_ranges"),
            QStringLiteral("转储中没有可直接读取的虚拟内存范围。")));
        return;
    }

    const int faultingRange = result.faultingAddress != 0
        ? findRangeIndex(result.faultingAddress)
        : -1;
    const std::uint64_t initialAddress = faultingRange >= 0
        ? result.faultingAddress
        : findPreferredInitialAddress();
    m_addressEdit->setText(formatHex(initialAddress));
    loadAddress(initialAddress);
}

void DumpMemoryView::clearData()
{
    m_pointerSize = 8;
    m_architectureInitialized = false;
    m_filePath.clear();
    m_expectedFileSize = 0;
    m_expectedFileLastModifiedUtcMs = -1;
    m_ranges.clear();
    m_modules.clear();
    m_memoryRegions.clear();
    m_currentAddress = 0;
    m_currentReadBytes = 0;
    m_currentRangeIndex = -1;
    if (m_memoryEditor != nullptr)
    {
        m_memoryEditor->clear();
    }
    if (m_addressEdit != nullptr)
    {
        m_addressEdit->clear();
    }
    setDiagnostic(ks::i18n::text(
        QStringLiteral("minidump.memory_view.status.idle"),
        QStringLiteral("请选择一个已捕获的虚拟地址。")));
}

void DumpMemoryView::retranslateUi()
{
    if (m_addressLabel == nullptr)
    {
        return;
    }
    m_addressLabel->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.address_label"), QStringLiteral("虚拟地址")));
    m_addressEdit->setPlaceholderText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.address_placeholder"),
        QStringLiteral("输入虚拟地址，或 模块名+偏移")));
    m_addressEdit->setToolTip(ks::i18n::text(
        QStringLiteral("minidump.memory_view.address_tooltip"),
        QStringLiteral("支持 0x 地址、裸十六进制地址，以及 模块名+偏移。")));
    m_readSizeLabel->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.read_size_label"), QStringLiteral("读取大小")));
    const QVariant previousSize = m_readSizeCombo->currentData();
    m_readSizeCombo->setItemText(0, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.256b"), QStringLiteral("256 字节")));
    m_readSizeCombo->setItemText(1, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.1k"), QStringLiteral("1 KiB")));
    m_readSizeCombo->setItemText(2, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.4k"), QStringLiteral("4 KiB")));
    m_readSizeCombo->setItemText(3, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.16k"), QStringLiteral("16 KiB")));
    m_readSizeCombo->setItemText(4, ks::i18n::text(
        QStringLiteral("minidump.memory_view.size.64k"), QStringLiteral("64 KiB")));
    const int previousSizeIndex = m_readSizeCombo->findData(previousSize);
    if (previousSizeIndex >= 0)
    {
        m_readSizeCombo->setCurrentIndex(previousSizeIndex);
    }
    m_readButton->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.action.read"), QStringLiteral("读取")));
    m_previousButton->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.action.previous"), QStringLiteral("上一页")));
    m_nextButton->setText(ks::i18n::text(
        QStringLiteral("minidump.memory_view.action.next"), QStringLiteral("下一页")));
}

bool DumpMemoryView::readAddressText(const QString& text, std::uint64_t* const addressOut) const
{
    if (parseUnsignedAddress(text, addressOut))
    {
        return true;
    }
    const int plusIndex = text.lastIndexOf(QLatin1Char('+'));
    if (plusIndex <= 0 || plusIndex == text.size() - 1)
    {
        return false;
    }
    std::uint64_t offset = 0;
    if (!parseUnsignedAddress(text.mid(plusIndex + 1), &offset))
    {
        return false;
    }
    const QString moduleText = text.left(plusIndex).trimmed();
    for (const ks::minidump::ModuleEntry& module : m_modules)
    {
        const QString fileName = QFileInfo(module.name).fileName();
        const QString nativeModulePath = QDir::toNativeSeparators(module.name);
        const QString nativeModuleText = QDir::toNativeSeparators(moduleText);
        if (module.name.compare(moduleText, Qt::CaseInsensitive) != 0 &&
            nativeModulePath.compare(nativeModuleText, Qt::CaseInsensitive) != 0 &&
            fileName.compare(moduleText, Qt::CaseInsensitive) != 0)
        {
            continue;
        }
        if (module.base > std::numeric_limits<std::uint64_t>::max() - offset)
        {
            return false;
        }
        *addressOut = module.base + offset;
        return true;
    }
    return false;
}

int DumpMemoryView::findRangeIndex(const std::uint64_t address) const
{
    const auto upper = std::upper_bound(
        m_ranges.begin(),
        m_ranges.end(),
        address,
        [](const std::uint64_t value, const ks::minidump::DumpMemoryRange& range)
        {
            return value < range.virtualAddress;
        });
    const int upperIndex = static_cast<int>(upper - m_ranges.begin());
    constexpr int kOverlapProbeDepth = 8;
    for (int index = upperIndex - 1, probes = 0;
         index >= 0 && probes < kOverlapProbeDepth;
         --index, ++probes)
    {
        const ks::minidump::DumpMemoryRange& range =
            m_ranges[static_cast<std::size_t>(index)];
        if (address < range.virtualAddress)
        {
            continue;
        }
        const std::uint64_t offset = address - range.virtualAddress;
        if (offset < range.bytes)
        {
            return index;
        }
    }
    return -1;
}

std::uint64_t DumpMemoryView::findPreferredInitialAddress() const
{
    if (m_ranges.empty() || m_filePath.isEmpty())
    {
        return m_ranges.empty() ? 0 : m_ranges.front().virtualAddress;
    }

    QFile dumpFile(m_filePath);
    if (!dumpFile.open(QIODevice::ReadOnly))
    {
        return m_ranges.front().virtualAddress;
    }

    for (const ks::minidump::DumpMemoryRange& range : m_ranges)
    {
        const std::uint64_t probeBytes = std::min(range.bytes, kInitialContentProbeBytes);
        if (probeBytes == 0 ||
            range.fileOffset > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
            probeBytes > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
            !dumpFile.seek(static_cast<qint64>(range.fileOffset)))
        {
            continue;
        }
        const QByteArray bytes = dumpFile.read(static_cast<qint64>(probeBytes));
        if (bytes.size() != static_cast<qsizetype>(probeBytes))
        {
            continue;
        }
        const bool hasNonZeroByte = std::any_of(
            bytes.cbegin(),
            bytes.cend(),
            [](const char byte) { return static_cast<unsigned char>(byte) != 0; });
        if (hasNonZeroByte)
        {
            return range.virtualAddress;
        }
    }
    return m_ranges.front().virtualAddress;
}

void DumpMemoryView::loadCurrentInput()
{
    std::uint64_t address = 0;
    if (!readAddressText(m_addressEdit->text(), &address))
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.invalid_address"),
            QStringLiteral("请输入有效的虚拟地址，或“模块名+偏移”。")));
        return;
    }
    loadAddress(address);
}

bool DumpMemoryView::loadAddress(const std::uint64_t address)
{
    const int rangeIndex = findRangeIndex(address);
    if (rangeIndex < 0)
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.not_captured"),
            QStringLiteral("地址 %1 不在当前转储捕获的虚拟内存范围内。"))
            .arg(formatHex(address)));
        return false;
    }
    if (m_filePath.isEmpty())
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.no_file"),
            QStringLiteral("没有与当前内存范围关联的转储文件。")));
        return false;
    }

    const QFileInfo fileInfo(m_filePath);
    const bool changed = !fileInfo.exists() || !fileInfo.isFile() ||
        static_cast<std::uint64_t>(fileInfo.size()) != m_expectedFileSize ||
        (m_expectedFileLastModifiedUtcMs >= 0 &&
            fileInfo.lastModified().toUTC().toMSecsSinceEpoch() !=
                m_expectedFileLastModifiedUtcMs);
    if (changed)
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.file_changed"),
            QStringLiteral("转储文件已变更，请重新解析后再读取内存。")));
        return false;
    }

    const ks::minidump::DumpMemoryRange& range =
        m_ranges[static_cast<std::size_t>(rangeIndex)];
    const std::uint64_t offsetInRange = address - range.virtualAddress;
    const std::uint64_t remaining = range.bytes - offsetInRange;
    const std::uint64_t requestedBytes = std::min(remaining, selectedReadBytes());
    if (requestedBytes == 0 || range.fileOffset > std::numeric_limits<std::uint64_t>::max() - offsetInRange)
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.offset_invalid"),
            QStringLiteral("文件偏移超出可读取范围。")));
        return false;
    }
    const std::uint64_t fileOffset = range.fileOffset + offsetInRange;
    if (fileOffset > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
        requestedBytes > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) ||
        fileOffset > m_expectedFileSize || requestedBytes > m_expectedFileSize - fileOffset)
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.offset_invalid"),
            QStringLiteral("文件偏移超出可读取范围。")));
        return false;
    }

    QFile dumpFile(m_filePath);
    if (!dumpFile.open(QIODevice::ReadOnly))
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.open_failed"),
            QStringLiteral("无法打开转储文件：%1"))
            .arg(dumpFile.errorString()));
        return false;
    }
    if (!dumpFile.seek(static_cast<qint64>(fileOffset)))
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.read_failed"),
            QStringLiteral("读取失败或文件内容不足。")));
        return false;
    }
    const QByteArray bytes = dumpFile.read(static_cast<qint64>(requestedBytes));
    if (bytes.size() != static_cast<qsizetype>(requestedBytes))
    {
        m_memoryEditor->clear();
        setDiagnostic(ks::i18n::text(
            QStringLiteral("minidump.memory_view.status.read_failed"),
            QStringLiteral("读取失败或文件内容不足。")));
        return false;
    }

    m_currentAddress = address;
    m_currentReadBytes = requestedBytes;
    m_currentRangeIndex = rangeIndex;
    m_addressEdit->setText(formatHex(address));
    const auto architecture = m_architectureInitialized
        ? m_memoryEditor->currentArchitecture()
        : (m_pointerSize == 4 ? ks::ui::DisassemblyArchitecture::X86
                              : ks::ui::DisassemblyArchitecture::X64);
    const QString sourceIdentity = QStringLiteral("dump:%1:%2:%3")
        .arg(m_filePath).arg(m_expectedFileSize).arg(m_expectedFileLastModifiedUtcMs);
    m_memoryEditor->setSnapshot(bytes, address, architecture, address, sourceIdentity);
    m_memoryEditor->setEditable(false);
    m_architectureInitialized = true;

    ks::ui::FieldDocument details;
    details.section(QStringLiteral("转储映射"));
    details.field(QStringLiteral("虚拟地址"), formatHex(address));
    const std::uint64_t rangeEnd = range.bytes <= std::numeric_limits<std::uint64_t>::max() - range.virtualAddress
        ? range.virtualAddress + range.bytes - 1 : std::numeric_limits<std::uint64_t>::max();
    details.field(QStringLiteral("捕获范围起点"), formatHex(range.virtualAddress));
    details.field(QStringLiteral("捕获范围终点"), formatHex(rangeEnd));
    details.field(QStringLiteral("捕获大小（字节）"), QString::number(range.bytes));
    details.field(QStringLiteral("文件偏移"), formatHex(fileOffset));
    details.field(QStringLiteral("来源"), range.source, true);
    for (const ks::minidump::ModuleEntry& module : m_modules)
    {
        if (module.size == 0 || address < module.base || address - module.base >= module.size) continue;
        details.field(QStringLiteral("所属模块"), module.name);
        details.field(QStringLiteral("模块偏移"), formatHex(address - module.base));
        break;
    }
    for (const ks::minidump::MemoryRegionEntry& region : m_memoryRegions)
    {
        if (region.size == 0 || address < region.base || address - region.base >= region.size) continue;
        details.section(QStringLiteral("内存区域"));
        details.field(QStringLiteral("基址"), formatHex(region.base));
        details.field(QStringLiteral("状态"), region.state, true);
        details.field(QStringLiteral("保护"), region.protect, true);
        details.field(QStringLiteral("类型"), region.type, true);
        break;
    }
    details.field(QStringLiteral("本次读取（字节）"), QString::number(requestedBytes));
    m_messageView->setDocument(details);
    return true;
}

void DumpMemoryView::goPreviousPage()
{
    if (m_currentRangeIndex < 0)
    {
        loadCurrentInput();
        return;
    }
    const ks::minidump::DumpMemoryRange& current =
        m_ranges[static_cast<std::size_t>(m_currentRangeIndex)];
    if (m_currentAddress > current.virtualAddress)
    {
        const std::uint64_t previous = m_currentAddress - current.virtualAddress >= selectedReadBytes()
            ? m_currentAddress - selectedReadBytes()
            : current.virtualAddress;
        loadAddress(previous);
        return;
    }
    for (int index = m_currentRangeIndex - 1; index >= 0; --index)
    {
        const ks::minidump::DumpMemoryRange& previous =
            m_ranges[static_cast<std::size_t>(index)];
        if (previous.bytes == 0)
        {
            continue;
        }
        const std::uint64_t pageBytes = std::min(previous.bytes, selectedReadBytes());
        loadAddress(previous.virtualAddress + previous.bytes - pageBytes);
        return;
    }
}

void DumpMemoryView::goNextPage()
{
    if (m_currentRangeIndex < 0)
    {
        loadCurrentInput();
        return;
    }
    const ks::minidump::DumpMemoryRange& current =
        m_ranges[static_cast<std::size_t>(m_currentRangeIndex)];
    const std::uint64_t consumed = m_currentAddress - current.virtualAddress;
    if (m_currentReadBytes != 0 && consumed <= current.bytes - m_currentReadBytes)
    {
        const std::uint64_t next = m_currentAddress + m_currentReadBytes;
        if (next > m_currentAddress && next - current.virtualAddress < current.bytes)
        {
            loadAddress(next);
            return;
        }
    }
    for (std::size_t index = static_cast<std::size_t>(m_currentRangeIndex) + 1;
         index < m_ranges.size(); ++index)
    {
        if (m_ranges[index].bytes != 0)
        {
            loadAddress(m_ranges[index].virtualAddress);
            return;
        }
    }
}

std::uint64_t DumpMemoryView::selectedReadBytes() const
{
    const QVariant data = m_readSizeCombo->currentData();
    bool ok = false;
    const qulonglong selected = data.toULongLong(&ok);
    return ok ? std::clamp<std::uint64_t>(selected, 1, kMaximumReadBytes) : 4ull * 1024ull;
}

void DumpMemoryView::setDiagnostic(const QString& text)
{
    if (m_messageView != nullptr)
    {
        m_messageView->setDocument(ks::ui::FieldDocument{}.note(text));
    }
}

QString DumpMemoryView::formatHex(const std::uint64_t value)
{
    return QStringLiteral("0x%1").arg(QString::number(value, 16).toUpper());
}
