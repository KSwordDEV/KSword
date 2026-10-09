#include "ProcessTraceTimelineWidget.h"
#include "../theme.h"
#include "../Internationalization/LanguageManager.h"

// 渲染与速率动画投影从交互/选区模块拆出，仍绘制同一生产模型，不维护另一份事件。
#include <QPainter>
#include <QPen>
#include <QPolygonF>
#include <QPaintEvent>
#include <algorithm>
#include <cmath>

namespace
{
    // themeColorFromText：
    // - 将主题返回的调色板字符串安全转换为 QColor；
    // - 当主题文本不是具体 #RRGGBB 时，使用 fallbackColor 保持绘制稳定。
    QColor themeColorFromText(const QString& colorText, const QColor& fallbackColor)
    {
        QColor colorValue(colorText);
        return colorValue.isValid() ? colorValue : fallbackColor;
    }

}

ProcessTraceTimelineRatePoint ProcessTraceTimelineWidget::animatedRatePointAt(
    const std::size_t pointIndex) const
{
    const ProcessTraceTimelineRatePoint targetPoint = m_ratePointList[pointIndex];
    if (!m_hasPreviousRatePoint || pointIndex + 1U != m_ratePointList.size() || m_rateAnimationProgress >= 1.0)
    {
        return targetPoint;
    }
    ProcessTraceTimelineRatePoint result = targetPoint;
    if (targetPoint.time100ns >= m_previousRatePoint.time100ns)
    {
        result.time100ns = m_previousRatePoint.time100ns + static_cast<std::uint64_t>(
            static_cast<long double>(targetPoint.time100ns - m_previousRatePoint.time100ns)
            * m_rateAnimationProgress);
    }
    else
    {
        result.time100ns = targetPoint.time100ns;
    }
    result.uploadBytesPerSecond = m_previousRatePoint.uploadBytesPerSecond
        + (targetPoint.uploadBytesPerSecond - m_previousRatePoint.uploadBytesPerSecond) * m_rateAnimationProgress;
    result.downloadBytesPerSecond = m_previousRatePoint.downloadBytesPerSecond
        + (targetPoint.downloadBytesPerSecond - m_previousRatePoint.downloadBytesPerSecond) * m_rateAnimationProgress;
    return result;
}

double ProcessTraceTimelineWidget::animatedRateTimeToX(const std::uint64_t time100ns) const
{
    long double rangeStart = static_cast<long double>(m_rangeStart100ns);
    long double rangeEnd = static_cast<long double>(m_rangeEnd100ns);
    if (m_hasPreviousRateRange && m_rateAnimationProgress < 1.0)
    {
        const long double progress = m_rateAnimationProgress;
        rangeStart = static_cast<long double>(m_previousRateRangeStart100ns)
            + (rangeStart - static_cast<long double>(m_previousRateRangeStart100ns)) * progress;
        rangeEnd = static_cast<long double>(m_previousRateRangeEnd100ns)
            + (rangeEnd - static_cast<long double>(m_previousRateRangeEnd100ns)) * progress;
    }

    const QRectF axisRect = timelineRect();
    if (rangeEnd <= rangeStart)
    {
        return axisRect.left();
    }
    const long double ratio = std::clamp(
        (static_cast<long double>(time100ns) - rangeStart) / (rangeEnd - rangeStart),
        0.0L,
        1.0L);
    return axisRect.left() + axisRect.width() * static_cast<double>(ratio);
}

void ProcessTraceTimelineWidget::paintEvent(QPaintEvent* eventPointer)
{
    (void)eventPointer;

    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing, true);

    const QRectF axisRect = timelineRect();
    // themeColorFromText 用途：KswordTheme 可能返回 palette(mid) 这类样式表文本，
    // 绘图 API 需要真实 QColor，因此这里统一提供深浅色兜底。
    const QColor borderColor = themeColorFromText(
        KswordTheme::BorderColorHex(),
        KswordTheme::BorderColor());
    const QColor surfaceColor = themeColorFromText(
        KswordTheme::SurfaceColorHex(),
        KswordTheme::SurfaceColor());
    const QColor textColor = themeColorFromText(
        KswordTheme::TextSecondaryColorHex(),
        KswordTheme::TextSecondaryColor());

    // 背景与边框：
    // - 这个矩形本身代表完整时间范围；
    // - 即使没有事件，也要保留清晰边界。
    painter.setPen(QPen(borderColor, 1.0));
    painter.setBrush(surfaceColor);
    painter.drawRect(axisRect);

    // 行分隔线只做弱提示，主要类别信息由事件点颜色表达。
    painter.setPen(QPen(borderColor, 0.5));
    const int laneCount = static_cast<int>(m_tracks.size());
    for (int laneIndex = 1; laneIndex < laneCount; ++laneIndex)
    {
        const double yValue = axisRect.top()
            + axisRect.height() * static_cast<double>(laneIndex)
            / static_cast<double>(laneCount);
        painter.drawLine(QPointF(axisRect.left(), yValue), QPointF(axisRect.right(), yValue));
    }

    // 绘制按 viewport 像素聚合的桶；透明度从真实 count 推导，宽度保留桶内 min/max。
    // 事件原文和筛选时间始终留在原始列表，不能从这些绘制坐标反推业务记录。
    for (const ks::ui::EventTimelineBucket& bucket : eventBuckets())
    {
        const double laneHeight = axisRect.height() / static_cast<double>(laneCount);
        const double yValue = axisRect.top() + laneHeight * (static_cast<double>(bucket.laneIndex) + 0.5);
        const auto& track = m_tracks[static_cast<std::size_t>(bucket.laneIndex)];
        QColor color = KswordTheme::TimelineColor(track.colorRole);
        // 合成 alpha 等价于 count 个 20% 点叠加，聚合不会把高密度桶误画成单个事件。
        color.setAlphaF(1.0 - std::pow(0.8, static_cast<double>(bucket.count)));
        const double leftX = timeToX(bucket.minTime100ns);
        const double rightX = timeToX(bucket.maxTime100ns);

        painter.setPen(Qt::NoPen);
        painter.setBrush(color);
        painter.drawRoundedRect(QRectF(leftX - 1.7, yValue - 1.7,
            std::max(3.4, rightX - leftX + 3.4), 3.4), 1.7, 1.7);
    }

    // 速率折线叠加：
    // - 折线使用同一条 X 轴，Y 轴按当前可见范围内的峰值自适应；
    // - 绿色表示上传/出站，蓝色表示下载/入站；
    // - 折线绘制在选区框之前，保证框选区域仍然位于最上层。
    if (!m_ratePointList.empty() && m_rangeEnd100ns > m_rangeStart100ns)
    {
        double maxVisibleRate = 0.0;
        for (const ProcessTraceTimelineRatePoint& ratePoint : m_ratePointList)
        {
            if (ratePoint.time100ns < m_rangeStart100ns || ratePoint.time100ns > m_rangeEnd100ns)
            {
                continue;
            }
            maxVisibleRate = std::max(maxVisibleRate, ratePoint.uploadBytesPerSecond);
            maxVisibleRate = std::max(maxVisibleRate, ratePoint.downloadBytesPerSecond);
        }

        if (maxVisibleRate > 0.0)
        {
            QPolygonF uploadPolygon;
            QPolygonF downloadPolygon;
            const QRectF rateRect = axisRect.adjusted(0.0, 3.0, 0.0, -4.0);

            // appendRatePoint 用途：把“某秒 B/s”映射成折线坐标点。
            const auto appendRatePoint = [this, &rateRect, maxVisibleRate](
                QPolygonF& polygon,
                const std::uint64_t time100ns,
                const double bytesPerSecond)
                {
                    const double clampedRate = std::clamp(bytesPerSecond, 0.0, maxVisibleRate);
                    const double ratio = maxVisibleRate <= 0.0 ? 0.0 : clampedRate / maxVisibleRate;
                    const double xValue = animatedRateTimeToX(time100ns);
                    const double yValue = rateRect.bottom() - rateRect.height() * ratio;
                    polygon << QPointF(xValue, yValue);
                };

            for (std::size_t rateIndex = 0; rateIndex < m_ratePointList.size(); ++rateIndex)
            {
                const ProcessTraceTimelineRatePoint ratePoint = animatedRatePointAt(rateIndex);
                if (ratePoint.time100ns < m_rangeStart100ns || ratePoint.time100ns > m_rangeEnd100ns)
                {
                    continue;
                }
                appendRatePoint(uploadPolygon, ratePoint.time100ns, ratePoint.uploadBytesPerSecond);
                appendRatePoint(downloadPolygon, ratePoint.time100ns, ratePoint.downloadBytesPerSecond);
            }

            // 上行/下行沿用绿蓝语义色，但改由 KswordTheme 取值，保证跟随主题与自定义强调色。
            const QColor uploadLineColor = KswordTheme::WithAlpha(KswordTheme::SuccessColor(), 220);
            const QColor downloadLineColor = KswordTheme::WithAlpha(KswordTheme::InfoColor(), 220);
            painter.setBrush(Qt::NoBrush);

            // drawPolyline 需要至少两个点；单秒只有一个采样时退化成圆点，避免折线不可见。
            painter.setPen(QPen(downloadLineColor, 1.5));
            if (downloadPolygon.size() > 1)
            {
                painter.drawPolyline(downloadPolygon);
            }
            else if (downloadPolygon.size() == 1)
            {
                painter.setBrush(downloadLineColor);
                painter.drawEllipse(downloadPolygon.first(), 2.0, 2.0);
                painter.setBrush(Qt::NoBrush);
            }

            painter.setPen(QPen(uploadLineColor, 1.5));
            if (uploadPolygon.size() > 1)
            {
                painter.drawPolyline(uploadPolygon);
            }
            else if (uploadPolygon.size() == 1)
            {
                painter.setBrush(uploadLineColor);
                painter.drawEllipse(uploadPolygon.first(), 2.0, 2.0);
                painter.setBrush(Qt::NoBrush);
            }

            // 简短图例直接绘制在轴内，避免新增控件占用网络 Dock 垂直空间。
            const QFont originalFont = painter.font();
            QFont legendFont = originalFont;
            legendFont.setPointSizeF(std::max(7.0, originalFont.pointSizeF() - 1.0));
            painter.setFont(legendFont);
            painter.setPen(uploadLineColor);
            painter.drawText(
                axisRect.adjusted(54.0, 1.0, -54.0, 0.0),
                Qt::AlignTop | Qt::AlignHCenter,
                ks::i18n::contextText(QStringLiteral("network.timeline.upload"), QStringLiteral("上行")));
            painter.setPen(downloadLineColor);
            painter.drawText(
                axisRect.adjusted(96.0, 1.0, -12.0, 0.0),
                Qt::AlignTop | Qt::AlignLeft,
                ks::i18n::contextText(QStringLiteral("network.timeline.download"), QStringLiteral("下行")));
            painter.setFont(originalFont);
        }
    }

    // 选区框放在事件点之后绘制，保证拖拽框始终可见。
    const QRectF selectedRect = selectionRect();
    if (!selectedRect.isEmpty())
    {
        QColor fillColor(KswordTheme::PrimaryBlueColor);
        fillColor.setAlpha(36);
        QColor edgeColor(KswordTheme::PrimaryBlueColor);
        edgeColor.setAlpha(220);

        painter.setBrush(fillColor);
        painter.setPen(QPen(edgeColor, 1.5));
        painter.drawRect(selectedRect);

        // 左右把手是两条竖线，不额外创建子控件。
        painter.setPen(QPen(edgeColor, 2.0));
        painter.drawLine(selectedRect.topLeft(), selectedRect.bottomLeft());
        painter.drawLine(selectedRect.topRight(), selectedRect.bottomRight());
    }

    // 标签最后绘制：
    // - 左侧固定相对时间 00:00；
    // - 右侧显示当前或停止后的总耗时。
    painter.setPen(textColor);
    const QString leftText = QStringLiteral("00:00");
    const QString rightText = formatDurationText(m_rangeEnd100ns > m_rangeStart100ns
        ? (m_rangeEnd100ns - m_rangeStart100ns)
        : 0);
    painter.drawText(axisRect.adjusted(5, 0, -5, 0), Qt::AlignLeft | Qt::AlignVCenter, leftText);
    painter.drawText(axisRect.adjusted(5, 0, -5, 0), Qt::AlignRight | Qt::AlignVCenter, rightText);
}
