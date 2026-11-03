#include "MetricAreaRenderer.h"
#include "../theme.h"

#include <QImage>
#include <QPainter>
#include <QWidget>
#include <QMouseEvent>
#include <QTimer>
#include <QScreen>
#include <QStyle>
#include <QLineF>
#include <algorithm>
#include <cmath>

namespace ks::ui {
namespace {
quint32 colorIdentity(const QString& key)
{
    quint32 hash = 2166136261U;
    for (const QChar character : key) hash = (hash ^ character.unicode()) * 16777619U;
    return hash;
}

QPixmap cushionLightMap(double lx = -0.32, double ly = -0.38, double lz = 0.86)
{
    constexpr int size = 48;
    const double halfLength = std::sqrt(lx * lx + ly * ly + (lz + 1.0) * (lz + 1.0));
    const double hx = lx / halfLength, hy = ly / halfLength, hz = (lz + 1.0) / halfLength;
    QImage image(size, size, QImage::Format_ARGB32_Premultiplied);
    for (int y = 0; y < size; ++y) {
        auto* pixels = reinterpret_cast<QRgb*>(image.scanLine(y));
        const double ny = 1.8 * (2.0 * y / (size - 1) - 1.0);
        for (int x = 0; x < size; ++x) {
            const double nx = 1.8 * (2.0 * x / (size - 1) - 1.0);
            const double length = std::sqrt(nx * nx + ny * ny + 1.0);
            const double diffuse = std::max(0.0, (lx * nx + ly * ny + lz) / length);
            const double specular = std::max(0.0, (hx * nx + hy * ny + hz) / length);
            const double square = specular * specular;
            const double fourth = square * square;
            const double eighth = fourth * fourth;
            const double shine = eighth * eighth * eighth;
            const double light = std::clamp(0.32 + 0.74 * diffuse + 0.16 * shine, 0.32, 1.22);
            const int channel = light > 1.0 ? 255 : 0;
            const int alpha = qRound(std::abs(light - 1.0) * 255.0);
            pixels[x] = qPremultiply(qRgba(channel, channel, channel, alpha));
        }
    }
    return QPixmap::fromImage(image);
}
}

MetricAreaRenderer::MetricAreaRenderer() : m_cushion(cushionLightMap()) {}

void MetricAreaRenderer::attach(QWidget* host)
{
    if (m_host || !host) return;
    m_host = host;
    host->installEventFilter(this);
    m_timer = new QTimer(this);
    m_timer->setTimerType(Qt::PreciseTimer);
    connect(m_timer, &QTimer::timeout, this, [this] { advanceLight(); });
}

void MetricAreaRenderer::scheduleLight()
{
    if (!m_host || !m_host->isVisible()) return;
    if (!m_host->style()->styleHint(QStyle::SH_Widget_Animate, nullptr, m_host)) {
        m_position = m_target; m_tracking = m_targetTracking;
        m_timer->stop(); m_host->update(); return;
    }
    if (!m_timer->isActive()) {
        const qreal hz = m_host->screen() ? m_host->screen()->refreshRate() : 60.0;
        m_timer->setInterval(qMax(7, qRound(1000.0 / qBound(30.0, hz, 144.0))));
        m_clock.restart(); m_timer->start();
    }
}

void MetricAreaRenderer::advanceLight()
{
    if (!m_host || !m_host->isVisible()) { m_timer->stop(); return; }
    const double elapsed = std::min(0.25, m_clock.restart() / 1000.0);
    const double fraction = 1.0 - std::exp(-elapsed / 0.055);
    m_position += (m_target - m_position) * fraction;
    m_tracking += (m_targetTracking - m_tracking) * fraction;
    if (std::abs(m_tracking - m_targetTracking) < 0.002
        && QLineF(m_position, m_target).length() < 0.5) {
        m_position = m_target; m_tracking = m_targetTracking; m_timer->stop();
    }
    m_host->update();
}

bool MetricAreaRenderer::eventFilter(QObject* watched, QEvent* event)
{
    if (watched != m_host) return false;
    if (event->type() == QEvent::MouseMove) {
        m_target = static_cast<QMouseEvent*>(event)->position();
        if (m_tracking == 0) m_position = m_target;
        m_targetTracking = 1; scheduleLight();
    } else if (event->type() == QEvent::Leave) {
        m_targetTracking = 0; scheduleLight();
    } else if (event->type() == QEvent::Hide) {
        m_timer->stop(); m_tracking = m_targetTracking = 0;
    }
    return false;
}

const QPixmap& MetricAreaRenderer::directionalMap(int ix, int iy) const
{
    auto& map = m_directions[static_cast<std::size_t>(iy * 17 + ix)];
    if (map.isNull()) {
        const double dx = (ix - 8) / 8.0, dy = (iy - 8) / 8.0;
        const double length = std::sqrt(dx * dx + dy * dy + 1.0);
        map = cushionLightMap(dx / length, dy / length, 1.0 / length);
    }
    return map;
}

void MetricAreaRenderer::paintLight(QPainter& painter, const QRectF& rectangle) const
{
    if (rectangle.isEmpty()) return;
    const QRectF pixels = painter.deviceTransform().mapRect(rectangle);
    if (pixels.width() < 0.75 || pixels.height() < 0.75) return;
    painter.save(); painter.setClipRect(rectangle, Qt::IntersectClip);
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    if (m_host && m_tracking > 0) {
        const double height = std::max(100.0, std::max(m_lightViewport.width(), m_lightViewport.height()) * 0.65);
        const QPointF offset = (m_position - rectangle.center()) / height;
        // Blend the direction back to the original light; all tiles share one world-space source.
        const double gx = std::clamp((-0.32 / 0.86 * (1 - m_tracking) + offset.x() * m_tracking) * 8 + 8, 0.0, 16.0);
        const double gy = std::clamp((-0.38 / 0.86 * (1 - m_tracking) + offset.y() * m_tracking) * 8 + 8, 0.0, 16.0);
        if (pixels.width() < 8 || pixels.height() < 8) {
            const auto& map = directionalMap(qRound(gx), qRound(gy));
            painter.drawPixmap(rectangle, map, QRectF(map.rect()));
        } else {
            const int x = static_cast<int>(gx), y = static_cast<int>(gy);
            const double fx = gx - x, fy = gy - y;
            const double opacity = painter.opacity();
            for (int dy = 0; dy < 2; ++dy) for (int dx = 0; dx < 2; ++dx) {
                const double weight = (dx ? fx : 1 - fx) * (dy ? fy : 1 - fy);
                if (weight <= 0) continue;
                const auto& map = directionalMap(std::min(16, x + dx), std::min(16, y + dy));
                painter.setOpacity(opacity * weight);
                painter.drawPixmap(rectangle, map, QRectF(map.rect()));
            }
        }
    } else {
        painter.drawPixmap(rectangle, m_cushion, QRectF(m_cushion.rect()));
    }
    painter.restore();
}

void MetricAreaRenderer::setLightGeometry(QSize viewport, const std::vector<QRectF>& rectangles)
{
    if (m_lightViewport == viewport && m_lightRects == rectangles) return;
    m_lightViewport = viewport;
    m_lightRects = rectangles;
    const double area = static_cast<double>(viewport.width()) * viewport.height();
    const double scale = area > 0 ? std::min(1.0, std::sqrt(196608.0 / area)) : 1.0;
    m_lightPixels = QSize(std::max(1, qRound(viewport.width() * scale)),
        std::max(1, qRound(viewport.height() * scale)));
    m_lightDirty = true;
}

void MetricAreaRenderer::paintLights(QPainter& painter) const
{
    if (m_lightViewport.isEmpty() || m_lightRects.empty()) return;
    if (m_lightDirty || m_lastLightPosition != m_position || m_lastTracking != m_tracking) {
        if (m_lightLayer.size() != m_lightPixels) m_lightLayer = QPixmap(m_lightPixels);
        m_lightLayer.fill(Qt::transparent);
        QPainter layer(&m_lightLayer);
        layer.scale(static_cast<double>(m_lightPixels.width()) / m_lightViewport.width(),
            static_cast<double>(m_lightPixels.height()) / m_lightViewport.height());
        for (const auto& rectangle : m_lightRects) paintLight(layer, rectangle);
        m_lastLightPosition = m_position; m_lastTracking = m_tracking; m_lightDirty = false;
    }
    // Only the soft light is reduced; object edges, colors and text stay at native resolution.
    painter.save();
    painter.setRenderHint(QPainter::SmoothPixmapTransform);
    painter.drawPixmap(QRectF(QPointF(), QSizeF(m_lightViewport)), m_lightLayer, QRectF(m_lightLayer.rect()));
    painter.restore();
}

QColor MetricAreaRenderer::identityColor(const QString& identity, const QPalette& palette,
    const QString& variant)
{
    const quint32 hash = colorIdentity(identity);
    const quint32 childHash = colorIdentity(variant);
    const int variation = variant.isEmpty() ? 0 : static_cast<int>(childHash % 37) - 18;
    const int hue = (static_cast<int>(hash % 360) + variation + 360) % 360;
    // Color grouping is independent of lighting: retain saturated bodies at the lower brightness.
    const int saturation = 194 + (variant.isEmpty() ? 0 : static_cast<int>((childHash >> 8) % 25) - 12);
    const int value = (palette.color(QPalette::Base).lightnessF() < 0.5 ? 180 : 210)
        - (variant.isEmpty() ? 0 : static_cast<int>((childHash >> 16) % 11));
    return QColor::fromHsv(hue, saturation, value);
}

QColor MetricAreaRenderer::captionColor(const QColor& color, const QPalette& palette)
{
    return palette.color(QPalette::Base).lightnessF() < 0.5 ? color.darker(135) : color.lighter(112);
}

QColor MetricAreaRenderer::paintTile(QPainter& painter, const QRectF& rectangle,
    const QColor& color, const MetricAreaTileState& state) const
{
    const QColor fill = color.lighter(state.selected ? 132 : state.hovered ? 118 : 100);
    if (rectangle.isEmpty()) return fill;
    painter.save();
    painter.setClipRect(rectangle, Qt::IntersectClip);
    if (!state.outlineOnly) {
        // Groups and leaves both carry their color across the entire block.
        painter.fillRect(rectangle, fill);
        // Attached views composite lighting separately, above cached colors and below cached labels.
        if (!m_host) paintLight(painter, rectangle);
    }
    if (state.group && rectangle.width() > 3.0 && rectangle.height() > 3.0) {
        const QColor border = KswordTheme::EnsureTextContrast(color.darker(150), fill, 3.0);
        painter.setPen(QPen(border, state.selected ? 3.0 : state.hovered ? 2.0 : 1.0));
        painter.setBrush(Qt::NoBrush);
        painter.drawRect(rectangle.adjusted(1.5, 1.5, -1.5, -1.5));
    }
    painter.restore();
    return fill;
}

}
