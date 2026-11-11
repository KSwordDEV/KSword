#pragma once

#include <QColor>
#include <QPalette>
#include <QPixmap>
#include <QRectF>
#include <QString>
#include <QObject>
#include <QPointer>
#include <QElapsedTimer>
#include <array>
#include <vector>

class QPainter;
class QWidget;
class QTimer;

namespace ks::ui {

struct MetricAreaTileState {
    bool group = false;
    bool hovered = false;
    bool selected = false;
    // A container's children are already in the scene cache; only emphasize its outline.
    bool outlineOnly = false;
};

// Shared drawing for metric trees and bounded file-space projections.
// Layout, object identity, selection and navigation stay with their owning view.
class MetricAreaRenderer final : public QObject {
public:
    MetricAreaRenderer();
    void attach(QWidget* host);
    void setLightEnabled(bool enabled);
    void paintLight(QPainter& painter, const QRectF& rectangle) const;
    void setLightGeometry(QSize viewport, const std::vector<QRectF>& rectangles);
    void paintLights(QPainter& painter) const;
    static QColor identityColor(const QString& identity, const QPalette& palette,
        const QString& variant = {});
    static QColor captionColor(const QColor& color, const QPalette& palette);
    QColor paintTile(QPainter& painter, const QRectF& rectangle, const QColor& color,
        const MetricAreaTileState& state = {}) const;
private:
    bool eventFilter(QObject* watched, QEvent* event) override;
    void advanceLight();
    void scheduleLight();
    const QPixmap& directionalMap(int x, int y) const;
    QPixmap m_cushion;
    mutable std::array<QPixmap, 289> m_directions;
    QPointer<QWidget> m_host;
    QTimer* m_timer = nullptr;
    bool m_lightEnabled = true;
    QElapsedTimer m_clock;
    QPointF m_position, m_target;
    double m_tracking = 0, m_targetTracking = 0;
    QSize m_lightViewport, m_lightPixels;
    std::vector<QRectF> m_lightRects;
    mutable QPixmap m_lightLayer;
    mutable QPointF m_lastLightPosition;
    mutable double m_lastTracking = -1;
    mutable bool m_lightDirty = true;
};

}
