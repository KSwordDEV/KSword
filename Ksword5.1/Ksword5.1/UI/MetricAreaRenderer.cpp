#include "MetricAreaRenderer.h"
#include "../theme.h"

#include <QImage>
#include <QPainter>
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

QPixmap cushionLightMap()
{
    constexpr int size = 96;
    QImage image(size, size, QImage::Format_ARGB32_Premultiplied);
    for (int y = 0; y < size; ++y) {
        auto* pixels = reinterpret_cast<QRgb*>(image.scanLine(y));
        const double ny = 1.8 * (2.0 * y / (size - 1) - 1.0);
        for (int x = 0; x < size; ++x) {
            const double nx = 1.8 * (2.0 * x / (size - 1) - 1.0);
            const double length = std::sqrt(nx * nx + ny * ny + 1.0);
            const double diffuse = std::max(0.0, (-0.32 * nx - 0.38 * ny + 0.86) / length);
            const double shine = std::pow(std::max(0.0, (-0.16 * nx - 0.19 * ny + 0.97) / length), 24.0);
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

QColor MetricAreaRenderer::identityColor(const QString& identity, const QPalette& palette,
    const QString& variant)
{
    const quint32 hash = colorIdentity(identity);
    const int variation = variant.isEmpty() ? 0 : static_cast<int>(colorIdentity(variant) % 33) - 16;
    const int hue = (static_cast<int>(hash % 360) + variation + 360) % 360;
    return QColor::fromHsv(hue, 156, palette.color(QPalette::Base).lightnessF() < 0.5 ? 180 : 210);
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
        painter.setRenderHint(QPainter::SmoothPixmapTransform);
        painter.drawPixmap(rectangle, m_cushion, QRectF(m_cushion.rect()));
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
