#include "MemoryCompositionHistoryWidget.h"
#include "../Internationalization/LanguageManager.h"

#include "../theme.h"

#include <QFont>
#include <QPainter>
#include <QPainterPath>
#include <QEasingCurve>
#include <QVariantAnimation>
#include <QPaintEvent>
#include <QPen>
#include <QSizePolicy>

#include <algorithm>
#include <array>
#include <cmath>

namespace
{
    // CompositionColor 作用：保存图例名称与对应填充色。
    struct CompositionColor
    {
        const char* labelText = ""; // labelText：图例显示文本。
        QColor color;               // color：该内存构成层的填充颜色。
    };

    // buildCompositionColorList 作用：按绘制顺序返回内存构成配色。
    std::array<CompositionColor, 4> buildCompositionColorList()
    {
        return {
            CompositionColor{ "活跃", KswordTheme::WithAlpha(KswordTheme::AccentColor(KswordTheme::AccentRole::Purple), 145) },
            CompositionColor{ "缓存", KswordTheme::WithAlpha(KswordTheme::AccentColor(KswordTheme::AccentRole::Cyan, 24, -2), 120) },
            CompositionColor{ "分页池", KswordTheme::WithAlpha(KswordTheme::AccentColor(KswordTheme::AccentRole::Yellow), 120) },
            CompositionColor{ "非分页池", KswordTheme::WithAlpha(KswordTheme::AccentColor(KswordTheme::AccentRole::Orange, 36, 10), 130) },
        };
    }
}

MemoryCompositionHistoryWidget::MemoryCompositionHistoryWidget(QWidget* parent)
    : QWidget(parent)
{
    // 利用率页要求宽高不足时图表自动压缩，不能用固定最小高度撑出外层滚动条。
    setMinimumSize(0, 0);
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMouseTracking(true);
    setAttribute(Qt::WA_StyledBackground, false);
    setAutoFillBackground(false);
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

void MemoryCompositionHistoryWidget::setHistoryLength(const int historyLength)
{
    m_historyLength = std::max(2, historyLength);
    while (static_cast<int>(m_sampleList.size()) > m_historyLength)
    {
        m_sampleList.erase(m_sampleList.begin());
    }
    update();
}

void MemoryCompositionHistoryWidget::appendSample(const CompositionSample& sample)
{
    CompositionSample safeSample;
    safeSample.usedPercent = boundedPercent(sample.usedPercent);
    safeSample.cachedPercent = boundedPercent(sample.cachedPercent);
    safeSample.pagedPoolPercent = boundedPercent(sample.pagedPoolPercent);
    safeSample.nonPagedPoolPercent = boundedPercent(sample.nonPagedPoolPercent);

    const double poolPercentSum = safeSample.pagedPoolPercent + safeSample.nonPagedPoolPercent;
    safeSample.cachedPercent = std::min(safeSample.cachedPercent, safeSample.usedPercent);
    if (safeSample.cachedPercent + poolPercentSum > safeSample.usedPercent)
    {
        const double scaleValue = safeSample.usedPercent / std::max(1.0, safeSample.cachedPercent + poolPercentSum);
        safeSample.cachedPercent *= scaleValue;
        safeSample.pagedPoolPercent *= scaleValue;
        safeSample.nonPagedPoolPercent *= scaleValue;
    }
    safeSample.activePercent = std::max(
        0.0,
        safeSample.usedPercent
            - safeSample.cachedPercent
            - safeSample.pagedPoolPercent
            - safeSample.nonPagedPoolPercent);

    const CompositionSample previousSample = m_sampleList.empty()
        ? safeSample
        : m_sampleList.back();
    m_previousSampleCount = static_cast<int>(m_sampleList.size());
    m_historyWindowShifted = m_previousSampleCount >= m_historyLength;
    m_sampleList.push_back(safeSample);
    while (static_cast<int>(m_sampleList.size()) > m_historyLength)
    {
        m_sampleList.erase(m_sampleList.begin());
    }
    m_previousSample = previousSample;
    m_hasPreviousSample = true;
    m_animationProgress = 0.0;
    m_sampleAnimation->stop();
    m_sampleAnimation->start();
}

void MemoryCompositionHistoryWidget::clearSamples()
{
    m_sampleAnimation->stop();
    m_animationProgress = 1.0;
    m_hasPreviousSample = false;
    m_previousSampleCount = 0;
    m_historyWindowShifted = false;
    m_sampleList.clear();
    update();
}

void MemoryCompositionHistoryWidget::paintEvent(QPaintEvent* paintEventPointer)
{
    Q_UNUSED(paintEventPointer);

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QColor textColor = KswordTheme::TextPrimaryColor();
    const QColor borderColor = KswordTheme::WithAlpha(KswordTheme::BorderColor(), 138);
    const QColor gridColor = KswordTheme::WithAlpha(
        KswordTheme::AccentColor(KswordTheme::AccentRole::Purple),
        42);

    painter.fillRect(rect(), Qt::transparent);
    // 图例空间随高度缩放；低高度时舍弃下方图例，优先保留折线和构成填充。
    const bool compactHeight = height() < 70;
    const QRectF plotRect = compactHeight
        ? rect().adjusted(4.0, 4.0, -4.0, -4.0)
        : rect().adjusted(8.0, 10.0, -8.0, -24.0);
    if (plotRect.width() <= 4.0 || plotRect.height() <= 4.0)
    {
        return;
    }

    painter.setPen(QPen(borderColor, 1.0));
    painter.drawRect(plotRect);
    painter.setPen(QPen(gridColor, 1.0));
    for (int gridIndex = 1; gridIndex < 4; ++gridIndex)
    {
        const double yValue = plotRect.top() + plotRect.height() * static_cast<double>(gridIndex) / 4.0;
        painter.drawLine(QPointF(plotRect.left(), yValue), QPointF(plotRect.right(), yValue));
    }

    drawStackedComposition(painter, plotRect);
    drawUsageLine(painter, plotRect);

    if (!compactHeight)
    {
        painter.setPen(textColor);
        // 硬编码 9pt 在高 DPI 下几乎不可读；跟随当前字体并给一个 10pt 下限。
        painter.setFont(QFont(painter.font().family(), std::max(painter.font().pointSize(), 10)));
        painter.drawText(
            plotRect.adjusted(6.0, 4.0, -6.0, -4.0),
            Qt::AlignTop | Qt::AlignLeft,
            ks::i18n::contextText(
                QStringLiteral("hardware.memory.history.title"),
                QStringLiteral("内存占用历史 / 构成填充")));
        drawLegend(painter, plotRect);
    }
}

double MemoryCompositionHistoryWidget::boundedPercent(const double percentValue)
{
    if (!std::isfinite(percentValue))
    {
        return 0.0;
    }
    return std::clamp(percentValue, 0.0, 100.0);
}

MemoryCompositionHistoryWidget::CompositionSample MemoryCompositionHistoryWidget::animatedSampleAt(
    const std::size_t sampleIndex) const
{
    const CompositionSample targetSample = m_sampleList[sampleIndex];
    if (!m_hasPreviousSample || sampleIndex + 1U != m_sampleList.size() || m_animationProgress >= 1.0)
    {
        return targetSample;
    }
    const auto interpolate = [this](const double startValue, const double targetValue) {
        return startValue + (targetValue - startValue) * m_animationProgress;
    };
    CompositionSample result = targetSample;
    result.usedPercent = interpolate(m_previousSample.usedPercent, targetSample.usedPercent);
    result.activePercent = interpolate(m_previousSample.activePercent, targetSample.activePercent);
    result.cachedPercent = interpolate(m_previousSample.cachedPercent, targetSample.cachedPercent);
    result.pagedPoolPercent = interpolate(m_previousSample.pagedPoolPercent, targetSample.pagedPoolPercent);
    result.nonPagedPoolPercent = interpolate(m_previousSample.nonPagedPoolPercent, targetSample.nonPagedPoolPercent);
    return result;
}

double MemoryCompositionHistoryWidget::sampleX(const int sampleIndex, const QRectF& plotRect) const
{
    if (m_sampleList.size() <= 1)
    {
        return plotRect.left();
    }
    const int sampleCount = static_cast<int>(m_sampleList.size());
    const double targetRatio =
        static_cast<double>(sampleIndex) / static_cast<double>(sampleCount - 1);
    double startRatio = targetRatio;
    if (m_animationProgress < 1.0)
    {
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
    }
    const double animatedRatio =
        startRatio + (targetRatio - startRatio) * m_animationProgress;
    return plotRect.left() + plotRect.width() * animatedRatio;
}

double MemoryCompositionHistoryWidget::percentY(const double percentValue, const QRectF& plotRect)
{
    return plotRect.bottom() - plotRect.height() * boundedPercent(percentValue) / 100.0;
}

void MemoryCompositionHistoryWidget::drawStackedComposition(QPainter& painter, const QRectF& plotRect) const
{
    if (m_sampleList.empty())
    {
        return;
    }

    const std::array<CompositionColor, 4> colorList = buildCompositionColorList();
    for (int componentIndex = 0; componentIndex < static_cast<int>(colorList.size()); ++componentIndex)
    {
        QPainterPath componentPath;
        componentPath.moveTo(sampleX(0, plotRect), plotRect.bottom());

        for (int sampleIndex = 0; sampleIndex < static_cast<int>(m_sampleList.size()); ++sampleIndex)
        {
            const CompositionSample sample = animatedSampleAt(static_cast<std::size_t>(sampleIndex));
            const double componentValues[4] = {
                sample.activePercent,
                sample.cachedPercent,
                sample.pagedPoolPercent,
                sample.nonPagedPoolPercent,
            };

            double stackedPercent = 0.0;
            for (int stackedIndex = 0; stackedIndex <= componentIndex; ++stackedIndex)
            {
                stackedPercent += componentValues[stackedIndex];
            }
            componentPath.lineTo(sampleX(sampleIndex, plotRect), percentY(stackedPercent, plotRect));
        }

        for (int sampleIndex = static_cast<int>(m_sampleList.size()) - 1; sampleIndex >= 0; --sampleIndex)
        {
            const CompositionSample sample = animatedSampleAt(static_cast<std::size_t>(sampleIndex));
            const double componentValues[4] = {
                sample.activePercent,
                sample.cachedPercent,
                sample.pagedPoolPercent,
                sample.nonPagedPoolPercent,
            };

            double lowerStackedPercent = 0.0;
            for (int stackedIndex = 0; stackedIndex < componentIndex; ++stackedIndex)
            {
                lowerStackedPercent += componentValues[stackedIndex];
            }
            componentPath.lineTo(sampleX(sampleIndex, plotRect), percentY(lowerStackedPercent, plotRect));
        }
        componentPath.closeSubpath();

        painter.fillPath(componentPath, colorList[static_cast<std::size_t>(componentIndex)].color);
    }
}

void MemoryCompositionHistoryWidget::drawUsageLine(QPainter& painter, const QRectF& plotRect) const
{
    if (m_sampleList.empty())
    {
        return;
    }

    QPainterPath linePath;
    for (int sampleIndex = 0; sampleIndex < static_cast<int>(m_sampleList.size()); ++sampleIndex)
    {
        const QPointF pointValue(
            sampleX(sampleIndex, plotRect),
            percentY(animatedSampleAt(static_cast<std::size_t>(sampleIndex)).usedPercent, plotRect));
        if (sampleIndex == 0)
        {
            linePath.moveTo(pointValue);
        }
        else
        {
            linePath.lineTo(pointValue);
        }
    }

    painter.setPen(QPen(KswordTheme::AccentColor(KswordTheme::AccentRole::Purple), 2.0));
    painter.drawPath(linePath);
}

void MemoryCompositionHistoryWidget::drawLegend(QPainter& painter, const QRectF& plotRect) const
{
    const std::array<CompositionColor, 4> colorList = buildCompositionColorList();
    const QColor textColor = KswordTheme::TextPrimaryColor();

    // 图例原本 8pt，小到辨不出色块对应哪一项；下限提到 9pt——
    // 再大会撑破下面 58px 的标签宽度和 68px 的条目间距。
    painter.setFont(QFont(painter.font().family(), std::max(painter.font().pointSize() - 1, 9)));
    painter.setPen(textColor);

    double xValue = plotRect.left();
    const double yValue = plotRect.bottom() + 9.0;
    for (const CompositionColor& colorEntry : colorList)
    {
        const QRectF colorRect(xValue, yValue, 10.0, 7.0);
        painter.fillRect(colorRect, colorEntry.color);
        const QString sourceLabel = QString::fromUtf8(colorEntry.labelText);
        const QString labelKey = sourceLabel == QStringLiteral("活跃")
            ? QStringLiteral("hardware.memory.legend.active")
            : sourceLabel == QStringLiteral("缓存")
                ? QStringLiteral("hardware.memory.legend.cached")
                : sourceLabel == QStringLiteral("分页池")
                    ? QStringLiteral("hardware.memory.legend.paged_pool")
                    : QStringLiteral("hardware.memory.legend.non_paged_pool");
        painter.drawText(
            QRectF(xValue + 13.0, yValue - 4.0, 58.0, 16.0),
            Qt::AlignLeft | Qt::AlignVCenter,
            ks::i18n::contextText(labelKey, sourceLabel));
        xValue += 68.0;
    }
}
