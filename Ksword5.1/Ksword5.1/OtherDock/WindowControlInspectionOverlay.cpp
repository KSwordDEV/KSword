#include "WindowControlInspectionOverlay.h"
#include "WindowListInteraction.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include <QPainter>
#include <QPainterPath>
#include <QRegion>
#include <QTimer>
#include <QWidget>
#include <dwmapi.h>
#include <algorithm>
#include <set>
#include <tuple>

#pragma comment(lib, "dwmapi.lib")

namespace ks::control_inspection
{
    namespace
    {
        QString T(const char* source)
        { return ks::i18n::sourceText(QString::fromUtf8(source)); }
        HWND native(QWidget* widget) { return reinterpret_cast<HWND>(widget->winId()); }
        bool visibleWindow(HWND window)
        {
            if (!::IsWindowVisible(window) || ::IsIconic(window)) return false;
            DWORD cloaked = 0;
            return FAILED(::DwmGetWindowAttribute(window, DWMWA_CLOAKED, &cloaked, sizeof(cloaked))) || cloaked == 0;
        }
        class Overlay final : public QWidget
        {
        public:
            explicit Overlay(QWidget* owner) : QWidget(owner, Qt::Tool | Qt::FramelessWindowHint
                | Qt::WindowStaysOnTopHint | Qt::WindowDoesNotAcceptFocus | Qt::WindowTransparentForInput)
            {
                setObjectName(QStringLiteral("ks_control_overlay"));
                setPalette(owner->palette()); setFont(owner->font());
                setAttribute(Qt::WA_TranslucentBackground); setAttribute(Qt::WA_ShowWithoutActivating);
                createWinId(); fit();
                ::SetWindowLongPtrW(native(this), GWL_EXSTYLE, ::GetWindowLongPtrW(native(this), GWL_EXSTYLE)
                    | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE);
            }
            QVector<Node> nodes;
            Node hovered, selected;
            bool all = true, tips = true;
            QPoint cursor;
            QMap<quintptr, QRegion> visible;
            QMap<quintptr, QRect> hostBounds;
            void fit()
            {
                const auto desktop = ks::window::physicalVirtualDesktop();
                const ks::window::PhysicalCoordinateScope dpi;
                ::SetWindowPos(native(this), HWND_TOPMOST, desktop.x(), desktop.y(), desktop.width(), desktop.height(),
                    SWP_NOACTIVATE | SWP_NOOWNERZORDER);
            }
            bool clipToWindows(HWND root, HWND excluded)
            {
                const auto oldRoots = visible.keys();
                visible.clear();
                hostBounds.clear();
                const auto roots = relatedRoots(root, excluded);
                const ks::window::PhysicalCoordinateScope dpi;
                QRegion obstruction;
                for (HWND window = ::GetTopWindow(nullptr); window; window = ::GetWindow(window, GW_HWNDNEXT))
                {
                    if (window == native(this) || !visibleWindow(window)) continue;
                    const QRect bounds = physicalBounds(window);
                    if (bounds.isEmpty()) continue;
                    if (roots.contains(window))
                    {
                        visible.insert(reinterpret_cast<quintptr>(window), QRegion(bounds).subtracted(obstruction));
                        hostBounds.insert(reinterpret_cast<quintptr>(window), bounds);
                    }
                    obstruction += bounds;
                }
                // A selected child HWND is not itself in the top-level Z list.
                if (!visible.contains(reinterpret_cast<quintptr>(root)))
                {
                    HWND top = ::GetAncestor(root, GA_ROOT);
                    QRegion above;
                    for (HWND window = ::GetTopWindow(nullptr); window && window != top;
                        window = ::GetWindow(window, GW_HWNDNEXT))
                        if (window != native(this) && visibleWindow(window)) above += physicalBounds(window);
                    visible.insert(reinterpret_cast<quintptr>(root), QRegion(physicalBounds(root)).subtracted(above));
                    hostBounds.insert(reinterpret_cast<quintptr>(root), physicalBounds(root));
                }
                return oldRoots != visible.keys();
            }
        protected:
            bool event(QEvent* event) override
            {
                const bool handled = QWidget::event(event);
                if (event->type() == QEvent::DevicePixelRatioChange || event->type() == QEvent::ScreenChangeInternal)
                    QTimer::singleShot(0, this, [this] { fit(); update(); });
                return handled;
            }
            bool nativeEvent(const QByteArray& type, void* message, qintptr* result) override
            {
                const auto* msg = static_cast<MSG*>(message);
                if (msg->message == WM_DISPLAYCHANGE) QTimer::singleShot(0, this, [this] { fit(); update(); });
                if (msg->message == WM_NCHITTEST) { *result = HTTRANSPARENT; return true; }
                return QWidget::nativeEvent(type, message, result);
            }
            void paintEvent(QPaintEvent*) override
            {
                QPainter painter(this);
                painter.setCompositionMode(QPainter::CompositionMode_Source); painter.fillRect(rect(), Qt::transparent);
                painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
                const QRect bounds = physicalBounds(native(this));
                const QPoint origin = bounds.topLeft(); const qreal scale = devicePixelRatioF();
                const auto local = [&](const QRect& physical) { return ks::window::physicalRectToOverlay(physical, origin, scale); };
                QColor accent = palette().color(QPalette::Active, QPalette::Highlight);
                const auto draw = [&](const Node& node, int alpha, int width, Qt::PenStyle style, bool fill) {
                    if (node.id.isEmpty() || node.offscreen || node.bounds.isEmpty()) return;
                    const auto region = visible.value(reinterpret_cast<quintptr>(node.host));
                    if (region.isEmpty()) return;
                    QPainterPath clip;
                    for (const QRect& part : region) clip.addRect(local(part));
                    painter.save(); painter.setClipPath(clip);
                    QColor color = accent; color.setAlpha(alpha);
                    QPen pen(color, width, style); pen.setCosmetic(true); painter.setPen(pen);
                    QColor filling = accent; filling.setAlpha(20);
                    painter.setBrush(fill ? QBrush(filling) : Qt::NoBrush);
                    const QRect live = hostBounds.value(reinterpret_cast<quintptr>(node.host));
                    const QPoint delta = node.hostBounds.isEmpty() ? QPoint() : live.topLeft() - node.hostBounds.topLeft();
                    painter.drawRect(local(node.bounds.translated(delta)).adjusted(0, 0, -1 / scale, -1 / scale)); painter.restore();
                };
                if (all)
                {
                    std::set<std::tuple<quintptr, int, int, int, int>> painted;
                    for (const auto& node : nodes)
                        if (painted.emplace(reinterpret_cast<quintptr>(node.host), node.bounds.x(), node.bounds.y(),
                            node.bounds.width(), node.bounds.height()).second) draw(node, 180, 3, Qt::SolidLine, false);
                }
                draw(selected, 235, 4, Qt::DashLine, false);
                draw(hovered, 255, 4, Qt::SolidLine, true);
                if (!tips || hovered.id.isEmpty() || hovered.offscreen) return;
                const QStringList lines{hovered.name.isEmpty() ? T("<无名称>") : hovered.name,
                    hovered.type, T("位置：%1, %2　大小：%3 × %4").arg(hovered.bounds.x()).arg(hovered.bounds.y())
                        .arg(hovered.bounds.width()).arg(hovered.bounds.height()),
                    hovered.enabled ? T("可用") : T("不可用")};
                const QFontMetrics metrics(font());
                qreal width = 0;
                for (const auto& line : lines) width = std::max(width, static_cast<qreal>(metrics.horizontalAdvance(line)));
                QRect work = ks::window::physicalVirtualDesktop();
                MONITORINFO monitor{}; monitor.cbSize = sizeof(monitor);
                if (::GetMonitorInfoW(::MonitorFromPoint(POINT{cursor.x(), cursor.y()}, MONITOR_DEFAULTTONEAREST), &monitor))
                    work = QRect(monitor.rcWork.left, monitor.rcWork.top, monitor.rcWork.right - monitor.rcWork.left,
                        monitor.rcWork.bottom - monitor.rcWork.top);
                const QRectF canvas = local(work).adjusted(6, 6, -6, -6);
                width = std::min(width + 24, canvas.width());
                const qreal height = metrics.height() * lines.size() + 20;
                QPointF position((cursor.x() - origin.x()) / scale + 18, (cursor.y() - origin.y()) / scale + 22);
                if (position.x() + width > canvas.right()) position.setX((cursor.x() - origin.x()) / scale - width - 18);
                if (position.y() + height > canvas.bottom()) position.setY((cursor.y() - origin.y()) / scale - height - 18);
                position.setX(std::max(canvas.left(), std::min(position.x(), canvas.right() - width)));
                position.setY(std::max(canvas.top(), std::min(position.y(), canvas.bottom() - height)));
                const QRectF card(position, QSizeF(width, height));
                // Transparent application palettes are valid for the main
                // window, but must never make this information card transparent.
                QColor background = KswordTheme::SurfaceColor(); background.setAlpha(255);
                QColor text = KswordTheme::EnsureTextContrast(KswordTheme::TextPrimaryColor(), background);
                text.setAlpha(255);
                painter.setPen(QPen(accent, 2)); painter.setBrush(background);
                painter.drawRoundedRect(card, 4, 4); painter.setPen(text);
                qreal y = card.top() + 10;
                for (const auto& line : lines) {
                    painter.drawText(QRectF(card.left() + 12, y, card.width() - 24, metrics.height()),
                        Qt::AlignLeft | Qt::AlignVCenter, metrics.elidedText(line, Qt::ElideRight, static_cast<int>(card.width() - 24)));
                    y += metrics.height();
                }
            }
        };

    }
    QWidget* CreateOverlay(QWidget* owner) { return new Overlay(owner); }
    void FitOverlay(QWidget* overlay) { static_cast<Overlay*>(overlay)->fit(); }
    bool ClipOverlay(QWidget* overlay, HWND root, HWND excluded)
    { return static_cast<Overlay*>(overlay)->clipToWindows(root, excluded); }
    void UpdateOverlay(QWidget* widget, const QVector<Node>& nodes,
        const Node& hovered, const Node& selected, bool all, bool tips, QPoint cursor)
    {
        auto* overlay = static_cast<Overlay*>(widget);
        overlay->nodes = nodes; overlay->hovered = hovered; overlay->selected = selected;
        overlay->all = all; overlay->tips = tips; overlay->cursor = cursor;
        overlay->update();
    }
}
