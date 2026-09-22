#include "HexEditorWidget.h"

// ============================================================
// HexEditorWidget.Selection.cpp
// 作用：
// - 承载“选区检查器”面板创建与选区解释逻辑；
// - 与主 UI/工具逻辑分离，降低维护成本；
// - 只处理展示，不碰查找和编辑核心流程。
// ============================================================

#include "../theme.h"

#include <QFontDatabase>
#include <QGridLayout>
#include <QLabel>

#include <algorithm>
#include <cstring>
#include <string>

namespace
{
    // byteToHexTextLocal：
    // - 把单字节转为两位大写 HEX 文本；
    // - 选区检查器独立编译单元复用，避免依赖主 cpp 的匿名函数。
    QString byteToHexTextLocal(const std::uint8_t byteValue)
    {
        return QStringLiteral("%1").arg(byteValue, 2, 16, QChar('0')).toUpper();
    }

    // buildSelectionInspectorPanelStyle：
    // - 选区检查器面板只保留顶部分隔线，去掉四周边框，减少视觉噪声；
    // - 与上方主体区域之间用一条细线隔开即可。
    QString buildSelectionInspectorPanelStyle()
    {
        return QStringLiteral(
            "#ksHexSelectionInspectorPanel{"
            "  border:none;"
            "  border-top:1px solid %1;"
            "  background:transparent;"
            "  background-color:transparent;"
            "}"
            "#ksHexSelectionInspectorPanel QLabel{"
            "  border:none;"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%3;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // buildFixedPreviewFont：
    // - 为 HEX/ASCII/UTF-16/数值解释提供统一等宽字体；
    // - 便于用户对齐阅读字节预览。
    QFont buildFixedPreviewFont()
    {
        QFont fixedFont = QFontDatabase::systemFont(QFontDatabase::FixedFont);
        // 系统等宽字体缺少中文字形时 Windows 会回退到宋体，显式指定雅黑承接中文（UTF-16 预览会出现中文）。
        fixedFont.setFamilies(QStringList{ fixedFont.family(), QStringLiteral("Microsoft YaHei UI") });
        fixedFont.setPointSize(std::max(fixedFont.pointSize(), 10));
        return fixedFont;
    }
}

void HexEditorWidget::initializeSelectionInspector()
{
    m_selectionInspectorPanel = new QWidget(this);
    m_selectionInspectorPanel->setObjectName(QStringLiteral("ksHexSelectionInspectorPanel"));
    m_selectionInspectorPanel->setAutoFillBackground(false);
    m_selectionInspectorPanel->setAttribute(Qt::WA_StyledBackground, true);
    m_selectionInspectorLayout = new QGridLayout(m_selectionInspectorPanel);
    m_selectionInspectorLayout->setContentsMargins(6, 4, 6, 4);
    m_selectionInspectorLayout->setHorizontalSpacing(6);
    m_selectionInspectorLayout->setVerticalSpacing(2);
    m_selectionInspectorPanel->setStyleSheet(buildSelectionInspectorPanelStyle());

    auto buildValueLabel = [this]() -> QLabel*
        {
            QLabel* valueLabel = new QLabel(m_selectionInspectorPanel);
            valueLabel->setWordWrap(true);
            valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            valueLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            return valueLabel;
        };

    const QFont fixedFont = buildFixedPreviewFont();
    m_selectionSummaryLabel = buildValueLabel();
    m_selectionHexPreviewLabel = buildValueLabel();
    m_selectionAsciiPreviewLabel = buildValueLabel();
    m_selectionUtf16PreviewLabel = buildValueLabel();
    m_selectionIntegerPreviewLabel = buildValueLabel();

    m_selectionHexPreviewLabel->setFont(fixedFont);
    m_selectionAsciiPreviewLabel->setFont(fixedFont);
    m_selectionUtf16PreviewLabel->setFont(fixedFont);
    m_selectionIntegerPreviewLabel->setFont(fixedFont);

    m_selectionInspectorLayout->addWidget(new QLabel(QStringLiteral("选区"), m_selectionInspectorPanel), 0, 0);
    m_selectionInspectorLayout->addWidget(m_selectionSummaryLabel, 0, 1);
    m_selectionInspectorLayout->addWidget(new QLabel(QStringLiteral("HEX"), m_selectionInspectorPanel), 1, 0);
    m_selectionInspectorLayout->addWidget(m_selectionHexPreviewLabel, 1, 1);
    m_selectionInspectorLayout->addWidget(new QLabel(QStringLiteral("ASCII"), m_selectionInspectorPanel), 2, 0);
    m_selectionInspectorLayout->addWidget(m_selectionAsciiPreviewLabel, 2, 1);
    m_selectionInspectorLayout->addWidget(new QLabel(QStringLiteral("UTF-16"), m_selectionInspectorPanel), 3, 0);
    m_selectionInspectorLayout->addWidget(m_selectionUtf16PreviewLabel, 3, 1);
    m_selectionInspectorLayout->addWidget(new QLabel(QStringLiteral("数值"), m_selectionInspectorPanel), 4, 0);
    m_selectionInspectorLayout->addWidget(m_selectionIntegerPreviewLabel, 4, 1);
    m_selectionInspectorLayout->setColumnStretch(1, 1);
}

void HexEditorWidget::updateSelectionInspector()
{
    // 选区检查器是所有选区变更的统一汇聚点，因此对外广播也放在这里，
    // 保证外部拿到通知时 selectedBytes()/selectionRange() 已经是最新状态。
    std::uint64_t notifyStartOffset = 0;
    std::uint64_t notifyEndOffset = 0;
    const bool notifyHasSelection = selectionRange(notifyStartOffset, notifyEndOffset);
    emit selectionChanged(notifyStartOffset, notifyEndOffset, notifyHasSelection);

    if (m_selectionSummaryLabel == nullptr ||
        m_selectionHexPreviewLabel == nullptr ||
        m_selectionAsciiPreviewLabel == nullptr ||
        m_selectionUtf16PreviewLabel == nullptr ||
        m_selectionIntegerPreviewLabel == nullptr)
    {
        return;
    }

    if (m_buffer.isEmpty())
    {
        m_selectionSummaryLabel->setText(QStringLiteral("当前无数据。"));
        m_selectionHexPreviewLabel->setText(QStringLiteral("-"));
        m_selectionAsciiPreviewLabel->setText(QStringLiteral("-"));
        m_selectionUtf16PreviewLabel->setText(QStringLiteral("-"));
        m_selectionIntegerPreviewLabel->setText(QStringLiteral("-"));
        return;
    }

    const std::vector<std::uint64_t> offsetList = collectSelectedOffsets();
    if (offsetList.empty())
    {
        m_selectionSummaryLabel->setText(QStringLiteral("当前未选中有效字节。"));
        m_selectionHexPreviewLabel->setText(QStringLiteral("-"));
        m_selectionAsciiPreviewLabel->setText(QStringLiteral("-"));
        m_selectionUtf16PreviewLabel->setText(QStringLiteral("-"));
        m_selectionIntegerPreviewLabel->setText(QStringLiteral("-"));
        return;
    }

    const QByteArray selectedBytes = buildSelectedByteArray();
    const std::uint64_t firstOffset = offsetList.front();
    const std::uint64_t lastOffset = offsetList.back();
    const bool contiguous = (lastOffset - firstOffset + 1) == static_cast<std::uint64_t>(offsetList.size());

    m_selectionSummaryLabel->setText(
        QStringLiteral("起始=%1 | 结束=%2 | 长度=%3 字节 | 模式=%4")
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(m_baseAddress + firstOffset), 16, 16, QChar('0')).toUpper())
        .arg(QStringLiteral("0x%1").arg(static_cast<qulonglong>(m_baseAddress + lastOffset), 16, 16, QChar('0')).toUpper())
        .arg(static_cast<qulonglong>(selectedBytes.size()))
        .arg(contiguous ? QStringLiteral("连续") : QStringLiteral("非连续")));
    m_selectionHexPreviewLabel->setText(formatSelectionHexPreview(selectedBytes));
    m_selectionAsciiPreviewLabel->setText(formatSelectionAsciiPreview(selectedBytes));
    m_selectionUtf16PreviewLabel->setText(formatSelectionUtf16Preview(selectedBytes));
    m_selectionIntegerPreviewLabel->setText(formatSelectionIntegerPreview(selectedBytes));
}

QByteArray HexEditorWidget::buildSelectedByteArray() const
{
    QByteArray selectedBytes;
    const std::vector<std::uint64_t> offsetList = collectSelectedOffsets();
    selectedBytes.reserve(static_cast<int>(offsetList.size()));

    for (const std::uint64_t offset : offsetList)
    {
        if (offset >= static_cast<std::uint64_t>(m_buffer.size()))
        {
            continue;
        }
        selectedBytes.push_back(m_buffer.at(static_cast<int>(offset)));
    }
    return selectedBytes;
}

QByteArray HexEditorWidget::selectedBytes() const
{
    // 直接转调既有内部实现，避免选区语义出现第二份定义。
    return buildSelectedByteArray();
}

bool HexEditorWidget::selectionRange(
    std::uint64_t& startOffsetOut,
    std::uint64_t& endOffsetOut) const
{
    // collectSelectedOffsets 已保证升序去重，取首尾即可还原区间。
    const std::vector<std::uint64_t> offsetList = collectSelectedOffsets();
    if (offsetList.empty())
    {
        return false;
    }

    startOffsetOut = offsetList.front();
    endOffsetOut = offsetList.back() + 1U;
    return true;
}

QString HexEditorWidget::formatSelectionHexPreview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.isEmpty())
    {
        return QStringLiteral("-");
    }

    constexpr int kPreviewBytes = 64;
    QStringList hexTextList;
    const int displayCount = std::min<int>(selectedBytes.size(), kPreviewBytes);
    hexTextList.reserve(displayCount);
    for (int index = 0; index < displayCount; ++index)
    {
        hexTextList.push_back(byteToHexTextLocal(static_cast<std::uint8_t>(selectedBytes.at(index))));
    }

    QString previewText = hexTextList.join(' ');
    if (selectedBytes.size() > kPreviewBytes)
    {
        previewText += QStringLiteral(" ...（共 %1 字节）").arg(selectedBytes.size());
    }
    return previewText;
}

QString HexEditorWidget::formatSelectionAsciiPreview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.isEmpty())
    {
        return QStringLiteral("-");
    }

    QString asciiText;
    asciiText.reserve(selectedBytes.size());
    for (int index = 0; index < selectedBytes.size(); ++index)
    {
        const std::uint8_t byteValue = static_cast<std::uint8_t>(selectedBytes.at(index));
        asciiText.push_back((byteValue >= 32 && byteValue <= 126) ? QChar(byteValue) : QChar('.'));
    }
    return asciiText;
}

QString HexEditorWidget::formatSelectionUtf16Preview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.size() < static_cast<int>(sizeof(char16_t)))
    {
        return QStringLiteral("-");
    }

    constexpr int kPreviewCodeUnits = 32;
    const int codeUnitCount = std::min<int>(
        selectedBytes.size() / static_cast<int>(sizeof(char16_t)),
        kPreviewCodeUnits);
    std::u16string utf16Buffer(static_cast<std::size_t>(codeUnitCount), u'\0');
    std::memcpy(
        utf16Buffer.data(),
        selectedBytes.constData(),
        static_cast<std::size_t>(codeUnitCount) * sizeof(char16_t));

    QString utf16Text = QString::fromUtf16(
        reinterpret_cast<const char16_t*>(utf16Buffer.data()),
        codeUnitCount);
    utf16Text.replace(QChar(u'\0'), QChar('.'));
    if ((selectedBytes.size() / static_cast<int>(sizeof(char16_t))) > kPreviewCodeUnits)
    {
        utf16Text += QStringLiteral(" ...");
    }
    return utf16Text;
}

QString HexEditorWidget::formatSelectionIntegerPreview(const QByteArray& selectedBytes) const
{
    if (selectedBytes.isEmpty())
    {
        return QStringLiteral("-");
    }

    const auto byteAt = [&selectedBytes](const int index) -> std::uint8_t
        {
            return static_cast<std::uint8_t>(selectedBytes.at(index));
        };
    const auto readLe = [&byteAt](const int count) -> std::uint64_t
        {
            std::uint64_t value = 0;
            for (int index = 0; index < count; ++index)
            {
                value |= (static_cast<std::uint64_t>(byteAt(index)) << (index * 8));
            }
            return value;
        };
    const auto readBe = [&byteAt](const int count) -> std::uint64_t
        {
            std::uint64_t value = 0;
            for (int index = 0; index < count; ++index)
            {
                value = (value << 8) | static_cast<std::uint64_t>(byteAt(index));
            }
            return value;
        };

    QStringList valueTextList;
    valueTextList.push_back(QStringLiteral("u8=%1").arg(byteAt(0)));
    valueTextList.push_back(QStringLiteral("s8=%1").arg(static_cast<qint8>(byteAt(0))));

    if (selectedBytes.size() >= 2)
    {
        valueTextList.push_back(QStringLiteral("u16le=%1").arg(readLe(2)));
        valueTextList.push_back(QStringLiteral("u16be=%1").arg(readBe(2)));
    }
    if (selectedBytes.size() >= 4)
    {
        const std::uint32_t u32le = static_cast<std::uint32_t>(readLe(4));
        const std::uint32_t u32be = static_cast<std::uint32_t>(readBe(4));
        float f32le = 0.0f;
        std::memcpy(&f32le, &u32le, sizeof(f32le));
        valueTextList.push_back(QStringLiteral("u32le=%1").arg(u32le));
        valueTextList.push_back(QStringLiteral("u32be=%1").arg(u32be));
        valueTextList.push_back(QStringLiteral("f32le=%1").arg(QString::number(f32le, 'g', 8)));
    }
    if (selectedBytes.size() >= 8)
    {
        const std::uint64_t u64le = readLe(8);
        const std::uint64_t u64be = readBe(8);
        double f64le = 0.0;
        std::memcpy(&f64le, &u64le, sizeof(f64le));
        valueTextList.push_back(QStringLiteral("u64le=%1").arg(QString::number(static_cast<qulonglong>(u64le))));
        valueTextList.push_back(QStringLiteral("u64be=%1").arg(QString::number(static_cast<qulonglong>(u64be))));
        valueTextList.push_back(QStringLiteral("f64le=%1").arg(QString::number(f64le, 'g', 12)));
    }

    return valueTextList.join(QStringLiteral(" | "));
}
