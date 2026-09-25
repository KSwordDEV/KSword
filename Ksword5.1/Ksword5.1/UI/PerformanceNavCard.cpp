#include "PerformanceNavCard.h"
#include "../Internationalization/LanguageManager.h"

// ============================================================
// PerformanceNavCard.cpp
// 作用：
// 1) 按任务管理器样式绘制左侧性能导航卡片；
// 2) 深浅色主题下统一处理背景和文字可读性；
// 3) 维护缩略折线历史并在每次采样后重绘。
// ============================================================

#include "../theme.h"

#include <QEasingCurve>
#include <QFontMetrics>
#include <QPaintEvent>
#include <QPainter>
#include <QPainterPath>
#include <QSizePolicy>
#include <QVariantAnimation>

#include <algorithm>

namespace
{
    // 缩略图不能随左侧栏无限变宽，否则拖动分割器后会吞掉设备名称区域。
    constexpr int kSparkChartMaxWidth = 88;
    constexpr int kSparkChartTextReserveWidth = 96;
    constexpr int kSparkChartMinWidth = 36;
}

PerformanceNavCard::PerformanceNavCard(QWidget* parent)
    : QWidget(parent)
    , m_accentColor(KswordTheme::PrimaryBlueColor)
    , m_primarySeriesColor(KswordTheme::PrimaryBlueColor)
{
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(false);
    // 左侧设备列表会按 Dock 可用高度动态压缩卡片，因此这里不能设置固定最小高度。
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    setMinimumSize(0, 0);

    m_sampleAnimation = new QVariantAnimation(this);
    m_sampleAnimation->setDuration(260);
    m_sampleAnimation->setEasingCurve(QEasingCurve::OutCubic);
    m_sampleAnimation->setStartValue(0.0);
    m_sampleAnimation->setEndValue(1.0);
    connect(m_sampleAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
        m_animationProgress = value.toDouble();
        update();
    });
}

void PerformanceNavCard::setTitleText(const QString& titleText)
{
    m_titleText = titleText;
    update();
}

void PerformanceNavCard::setSubtitleText(const QString& subtitleText)
{
    m_subtitleText = subtitleText;
    update();
}

void PerformanceNavCard::setAccentColor(const QColor& accentColor)
{
    m_accentColor = accentColor;
    if (m_primarySeriesFollowsAccentColor)
    {
        m_primarySeriesColor = accentColor;
    }
    if (!m_secondarySeriesVisible)
    {
        m_secondarySeriesColor = QColor();
    }
    update();
}

void PerformanceNavCard::setSeriesColors(
    const QColor& primarySeriesColor,
    const QColor& secondarySeriesColor)
{
    m_primarySeriesFollowsAccentColor = !primarySeriesColor.isValid();
    m_primarySeriesColor = primarySeriesColor.isValid() ? primarySeriesColor : m_accentColor;
    m_secondarySeriesColor = secondarySeriesColor;
    m_secondarySeriesVisible = secondarySeriesColor.isValid();
    if (!m_secondarySeriesVisible)
    {
        m_secondarySamples.clear();
    }
    update();
}

void PerformanceNavCard::setSelectedState(const bool selected)
{
    m_selected = selected;
    update();
}

void PerformanceNavCard::appendSample(const double usagePercent)
{
    // clampedPercent 用途：把外部传入采样限制在 0~100，避免越界绘制。
    const double clampedPercent = std::clamp(usagePercent, 0.0, 100.0);
    const double previousPrimarySample = m_primarySamples.isEmpty()
        ? clampedPercent
        : m_primarySamples.back();
    m_previousSampleCount = static_cast<int>(m_primarySamples.size());
    m_historyWindowShifted = m_previousSampleCount >= m_maxSampleCount;
    m_primarySamples.push_back(clampedPercent);
    while (m_primarySamples.size() > m_maxSampleCount)
    {
        m_primarySamples.pop_front();
    }
    startLatestSampleAnimation(previousPrimarySample, m_previousSecondarySample);
}

void PerformanceNavCard::appendDualSample(
    const double primaryUsagePercent,
    const double secondaryUsagePercent)
{
    // primaryClampedPercent 用途：主序列采样值，限制在 0~100。
    const double primaryClampedPercent = std::clamp(primaryUsagePercent, 0.0, 100.0);
    // secondaryClampedPercent 用途：次序列采样值，限制在 0~100。
    const double secondaryClampedPercent = std::clamp(secondaryUsagePercent, 0.0, 100.0);
    const double previousPrimarySample = m_primarySamples.isEmpty()
        ? primaryClampedPercent
        : m_primarySamples.back();
    const double previousSecondarySample = m_secondarySamples.isEmpty()
        ? secondaryClampedPercent
        : m_secondarySamples.back();
    m_previousSampleCount = static_cast<int>(m_primarySamples.size());
    m_historyWindowShifted = m_previousSampleCount >= m_maxSampleCount;
    m_primarySamples.push_back(primaryClampedPercent);
    m_secondarySamples.push_back(secondaryClampedPercent);
    while (m_primarySamples.size() > m_maxSampleCount)
    {
        m_primarySamples.pop_front();
    }
    while (m_secondarySamples.size() > m_maxSampleCount)
    {
        m_secondarySamples.pop_front();
    }
    startLatestSampleAnimation(previousPrimarySample, previousSecondarySample);
}

void PerformanceNavCard::setSampleSeries(
    const QVector<double>& primarySampleList,
    const QVector<double>& secondarySampleList)
{
    const double previousPrimarySample = m_primarySamples.isEmpty()
        ? (primarySampleList.isEmpty() ? 0.0 : primarySampleList.back())
        : m_primarySamples.back();
    const double previousSecondarySample = m_secondarySamples.isEmpty()
        ? (secondarySampleList.isEmpty() ? 0.0 : secondarySampleList.back())
        : m_secondarySamples.back();
    m_previousSampleCount = static_cast<int>(m_primarySamples.size());
    const int nextSampleCount = std::min(static_cast<int>(primarySampleList.size()), m_maxSampleCount);
    m_historyWindowShifted =
        m_previousSampleCount >= m_maxSampleCount && nextSampleCount == m_previousSampleCount;
    m_primarySamples = primarySampleList;
    while (m_primarySamples.size() > m_maxSampleCount)
    {
        m_primarySamples.pop_front();
    }

    if (m_secondarySeriesVisible)
    {
        m_secondarySamples = secondarySampleList;
        while (m_secondarySamples.size() > m_maxSampleCount)
        {
            m_secondarySamples.pop_front();
        }
    }
    else
    {
        m_secondarySamples.clear();
    }
    startLatestSampleAnimation(previousPrimarySample, previousSecondarySample);
}

void PerformanceNavCard::clearSamples()
{
    m_sampleAnimation->stop();
    m_animationProgress = 1.0;
    m_primarySamples.clear();
    m_previousSampleCount = 0;
    m_historyWindowShifted = false;
    m_secondarySamples.clear();
    update();
}

void PerformanceNavCard::startLatestSampleAnimation(
    const double previousPrimarySample,
    const double previousSecondarySample)
{
    m_previousPrimarySample = previousPrimarySample;
    m_previousSecondarySample = previousSecondarySample;
    m_animationProgress = 0.0;
    m_sampleAnimation->stop();
    m_sampleAnimation->start();
}

double PerformanceNavCard::animatedXRatio(const int sampleIndex, const int sampleCount) const
{
    if (sampleCount <= 1)
    {
        return 0.0;
    }

    const double targetRatio =
        static_cast<double>(sampleIndex) / static_cast<double>(sampleCount - 1);
    double startRatio = targetRatio;
    if (m_historyWindowShifted && m_previousSampleCount == sampleCount)
    {
        startRatio = sampleIndex + 1 < sampleCount
            ? static_cast<double>(sampleIndex + 1) / static_cast<double>(sampleCount - 1)
            : 1.0;
    }
    else if (m_previousSampleCount + 1 == sampleCount && m_previousSampleCount > 1)
    {
        startRatio = sampleIndex < m_previousSampleCount
            ? static_cast<double>(sampleIndex) / static_cast<double>(m_previousSampleCount - 1)
            : 1.0;
    }

    return startRatio + (targetRatio - startRatio) * m_animationProgress;
}

QSize PerformanceNavCard::sizeHint() const
{
    // 默认高度压到 52px，实际高度由 HardwareDock 按列表可见高度继续动态下调。
    return QSize(208, 52);
}


int PerformanceNavCard::sampleCapacity() const
{
    return m_maxSampleCount;
}

void PerformanceNavCard::paintEvent(QPaintEvent* paintEventPointer)
{
    Q_UNUSED(paintEventPointer);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    // 卡片区域：改成透明底，仅保留边框高亮，避免计数器页左侧卡片遮住背景。
    const QRect cardRect = rect().adjusted(1, 1, -1, -1);
    // cardBorderColor 用途：当前卡片边框颜色；选中时更亮，不选中时仅保留弱轮廓。
    const QColor cardBorderColor = KswordTheme::WithAlpha(
        m_accentColor,
        m_selected ? 210 : 86);
    QPen cardBorderPen(cardBorderColor);
    cardBorderPen.setWidthF(m_selected ? 1.2 : 0.8);
    painter.setPen(cardBorderPen);
    painter.setBrush(Qt::NoBrush);
    painter.drawRoundedRect(cardRect, 4.0, 4.0);

    // 缩略图区域：保留边框与曲线，内部背景保持透明。
    // compactMode 用途：窄宽度/低高度下收缩文字字号，避免左侧列表触发滚动条。
    const bool compactMode = cardRect.width() < 176 || cardRect.height() < 48;
    const int sparkInset = compactMode ? 4 : 5;
    // showSparkChart 用途：只有在能为文字保留可读空间时才绘制缩略图。
    // 折线宽度设有绝对上限，避免分割器拖宽左栏后再次占据卡片的一半。
    const int availableSparkWidth = std::max(
        0,
        cardRect.width() - (sparkInset * 2) - kSparkChartTextReserveWidth - 7);
    const int sparkWidth = std::min(kSparkChartMaxWidth, availableSparkWidth);
    const bool showSparkChart = sparkWidth >= kSparkChartMinWidth;
    const QRect sparkRect(
        cardRect.left() + sparkInset,
        cardRect.top() + sparkInset,
        sparkWidth,
        std::max(1, cardRect.height() - sparkInset * 2));
    // sparkBorderColor 用途：缩略图边框颜色；选中时使用实色，未选中时降低透明度。
    const QColor sparkBorderColor = KswordTheme::WithAlpha(
        m_accentColor,
        m_selected ? 220 : 150);
    if (showSparkChart)
    {
        painter.setBrush(Qt::NoBrush);
        QPen sparkBorderPen(sparkBorderColor);
        sparkBorderPen.setWidthF(1.2);
        painter.setPen(sparkBorderPen);
        painter.drawRect(sparkRect);

        // 网格线：浅色辅助线，提升趋势可读性但不喧宾夺主。
        QPen gridPen(m_accentColor);
        gridPen.setWidthF(0.8);
        gridPen.setColor(KswordTheme::WithAlpha(m_accentColor, 45));
        painter.setPen(gridPen);
        for (int rowIndex = 1; rowIndex < 4; ++rowIndex)
        {
            const int yValue = sparkRect.top() + (sparkRect.height() * rowIndex / 4);
            painter.drawLine(sparkRect.left(), yValue, sparkRect.right(), yValue);
        }
    }

    // drawSeriesPath 作用：
    // - 把采样列表映射为缩略图曲线；
    // - 先绘制折线与 X 轴围成的透明填充，再绘制趋势线本体。
    const auto drawSeriesPath =
        [this, &painter, &sparkRect](
            const QVector<double>& sampleList,
            const QColor& seriesColor,
            const double previousLastValue)
        {
            if (sampleList.isEmpty())
            {
                return;
            }
            const auto animatedValueAt = [this, &sampleList, previousLastValue](const int indexValue) {
                const double targetValue = sampleList.at(indexValue);
                if (indexValue != sampleList.size() - 1 || m_animationProgress >= 1.0)
                {
                    return targetValue;
                }
                return previousLastValue
                    + (targetValue - previousLastValue) * m_animationProgress;
            };


            QPen trendPen(seriesColor);
            trendPen.setWidthF(1.6);

            if (sampleList.size() == 1)
            {
                const double yRatio = animatedValueAt(0) / 100.0;
                const double yValue = sparkRect.bottom() - yRatio * static_cast<double>(sparkRect.height());
                const QColor fillColor = KswordTheme::WithAlpha(seriesColor, 34);
                painter.fillRect(
                    QRectF(
                        QPointF(sparkRect.left(), yValue),
                        QPointF(sparkRect.right(), sparkRect.bottom())),
                    fillColor);
                painter.setPen(trendPen);
                painter.setBrush(Qt::NoBrush);
                painter.drawLine(
                    QPointF(sparkRect.left(), yValue),
                    QPointF(sparkRect.right(), yValue));
                return;
            }

            QPainterPath path;
            QPainterPath fillPath;
            const int pointCount = sampleList.size();
            for (int indexValue = 0; indexValue < pointCount; ++indexValue)
            {
                const double xRatio = animatedXRatio(indexValue, pointCount);
                const double yRatio = animatedValueAt(indexValue) / 100.0;
                const double xValue = sparkRect.left() + xRatio * static_cast<double>(sparkRect.width());
                const double yValue = sparkRect.bottom() - yRatio * static_cast<double>(sparkRect.height());
                if (indexValue == 0)
                {
                    path.moveTo(xValue, yValue);
                    fillPath.moveTo(xValue, sparkRect.bottom());
                    fillPath.lineTo(xValue, yValue);
                }
                else
                {
                    path.lineTo(xValue, yValue);
                    fillPath.lineTo(xValue, yValue);
                }
            }

            fillPath.lineTo(sparkRect.right(), sparkRect.bottom());
            fillPath.closeSubpath();
            painter.fillPath(
                fillPath,
                KswordTheme::WithAlpha(seriesColor, 34));
            painter.setPen(trendPen);
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(path);
        };

    // 双线卡片先画次序列再画主序列，确保主线不会被遮住。
    if (showSparkChart && m_secondarySeriesVisible)
    {
        drawSeriesPath(m_secondarySamples, m_secondarySeriesColor, m_previousSecondarySample);
    }
    if (showSparkChart)
    {
        drawSeriesPath(m_primarySamples, m_primarySeriesColor, m_previousPrimarySample);
    }

    // 文本区域：主标题加粗，副标题使用次级颜色。
    const int textLeft = showSparkChart
        ? sparkRect.right() + (compactMode ? 5 : 7)
        : cardRect.left() + (compactMode ? 5 : 8);
    const int textWidth = std::max(0, cardRect.right() - textLeft - 4);
    const int titleHeight = std::max(1, cardRect.height() / 2);
    const QRect titleRect(textLeft, cardRect.top() + 2, textWidth, titleHeight);
    const QRect subtitleRect(
        textLeft,
        titleRect.bottom() - 1,
        textWidth,
        std::max(1, cardRect.bottom() - titleRect.bottom()));

    QFont titleFont = painter.font();
    // 设备名主标题按需求改小，并在紧凑模式下继续压缩。
    titleFont.setPointSizeF(compactMode ? 11.0 : 12.5);
    titleFont.setBold(true);
    painter.setFont(titleFont);
    painter.setPen(KswordTheme::TextPrimaryColor());
    const QString elidedTitleText = QFontMetrics(titleFont).elidedText(
        ks::i18n::displayText(m_titleText),
        Qt::ElideRight,
        titleRect.width());
    painter.drawText(titleRect, Qt::AlignLeft | Qt::AlignVCenter, elidedTitleText);

    QFont subtitleFont = painter.font();
    subtitleFont.setPointSizeF(compactMode ? 8.5 : 9.5);
    subtitleFont.setBold(false);
    painter.setFont(subtitleFont);
    painter.setPen(KswordTheme::TextSecondaryColor());
    const QString elidedSubtitleText = QFontMetrics(subtitleFont).elidedText(
        ks::i18n::displayText(m_subtitleText),
        Qt::ElideRight,
        subtitleRect.width());
    painter.drawText(subtitleRect, Qt::AlignLeft | Qt::AlignVCenter, elidedSubtitleText);
}
