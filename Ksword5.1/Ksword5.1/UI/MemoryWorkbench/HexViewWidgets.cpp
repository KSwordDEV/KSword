// HexViewWidgets.cpp
// 作用：HexViewWidgets.h 里条带底板（HexViewBarFrame）与图标按钮（HexViewGlyphButton）的实现。
// 分段按钮、消息标签、状态条在 HexViewWidgets.Text.cpp。
// 约定：所有颜色在每次 paintEvent 里现取 KswordTheme 的静态颜色访问器，不缓存、不用样式表。

#include "HexViewWidgets.h"

#include "../../theme.h"

#include <QFont>
#include <QFontMetrics>
#include <QMenu>
#include <QPaintEvent>
#include <QPainter>
#include <QPen>
#include <QPolygonF>

#include <algorithm>

namespace ks::ui
{
    namespace
    {
        // kGlyphBox：图标逻辑方块的边长（像素），图形坐标都按 16x16 书写。
        constexpr qreal kGlyphBox = 16.0;

        // DrawGlyph：在 box 内画一个图标。
        // 传入：画笔对象、图形种类、16x16 逻辑方块、墨色、徽标字体（仅 CaseSensitive 用来画 A 与 a）。
        // 约定：图形全部用线条与小方块，墨色统一，线宽 1.4，圆端点圆拐角。
        void DrawGlyph(
            QPainter& painter,
            HexViewGlyphButton::Glyph glyph,
            const QRectF& box,
            const QColor& ink,
            const QFont& baseFont)
        {
            // point：把 16x16 坐标换算成控件坐标。
            const auto point = [&box](qreal x, qreal y) {
                return QPointF(box.left() + x, box.top() + y);
            };

            // 线条画笔：圆端点、圆拐角，所有"描线型"图形共用。
            QPen linePen(ink, 1.4);
            linePen.setCapStyle(Qt::RoundCap);
            linePen.setJoinStyle(Qt::RoundJoin);
            painter.setPen(linePen);
            painter.setBrush(Qt::NoBrush);

            switch (glyph)
            {
            case HexViewGlyphButton::Glyph::Find:
            {
                // 放大镜：圆圈 + 右下手柄。
                painter.drawEllipse(QRectF(point(2.0, 2.0), QSizeF(8.5, 8.5)));
                painter.drawLine(point(9.0, 9.0), point(13.5, 13.5));
                break;
            }
            case HexViewGlyphButton::Glyph::Goto:
            {
                // 向右箭头指向一条竖线：跳到某处。
                painter.drawLine(point(2.0, 8.0), point(10.5, 8.0));
                painter.drawLine(point(7.5, 5.0), point(10.5, 8.0));
                painter.drawLine(point(7.5, 11.0), point(10.5, 8.0));
                painter.drawLine(point(13.0, 3.5), point(13.0, 12.5));
                break;
            }
            case HexViewGlyphButton::Glyph::Export:
            {
                // 托盘（U 形）+ 向下箭头：把数据送出去。
                painter.drawLine(point(8.0, 2.0), point(8.0, 9.5));
                painter.drawLine(point(5.0, 6.5), point(8.0, 9.5));
                painter.drawLine(point(11.0, 6.5), point(8.0, 9.5));
                painter.drawPolyline(QPolygonF({
                    point(2.5, 10.0), point(2.5, 13.5), point(13.5, 13.5), point(13.5, 10.0) }));
                break;
            }
            case HexViewGlyphButton::Glyph::Inspector:
            {
                // 窗口外框 + 右侧窗格分隔线 + 窗格里的两道短横线：数据解释器面板。
                painter.drawRoundedRect(QRectF(point(1.5, 2.5), QSizeF(13.0, 11.0)), 1.5, 1.5);
                painter.drawLine(point(9.5, 2.5), point(9.5, 13.5));
                painter.drawLine(point(11.2, 6.0), point(12.8, 6.0));
                painter.drawLine(point(11.2, 9.0), point(12.8, 9.0));
                break;
            }
            case HexViewGlyphButton::Glyph::RowWidth:
            {
                // 两行各四个小方格（一行里的字节），下方一条双向箭头（行宽）。
                painter.setPen(Qt::NoPen);
                painter.setBrush(ink);
                for (int row = 0; row < 2; ++row)
                {
                    for (int column = 0; column < 4; ++column)
                    {
                        const qreal left = 2.0 + column * 3.6;
                        const qreal top = 2.5 + row * 3.7;
                        painter.drawRect(QRectF(point(left, top), QSizeF(2.6, 2.6)));
                    }
                }
                painter.setPen(linePen);
                painter.setBrush(Qt::NoBrush);
                painter.drawLine(point(2.0, 12.5), point(14.0, 12.5));
                painter.drawLine(point(2.0, 12.5), point(4.2, 10.8));
                painter.drawLine(point(2.0, 12.5), point(4.2, 14.2));
                painter.drawLine(point(14.0, 12.5), point(11.8, 10.8));
                painter.drawLine(point(14.0, 12.5), point(11.8, 14.2));
                break;
            }
            case HexViewGlyphButton::Glyph::GroupSize:
            {
                // 四个方格分成两组（中间留缝），每组下方一道括线：分组。
                painter.setPen(Qt::NoPen);
                painter.setBrush(ink);
                const qreal lefts[4] = { 2.0, 4.6, 9.0, 11.6 };
                for (const qreal left : lefts)
                {
                    painter.drawRect(QRectF(point(left, 3.0), QSizeF(2.4, 4.2)));
                }
                painter.setPen(linePen);
                painter.setBrush(Qt::NoBrush);
                painter.drawPolyline(QPolygonF({
                    point(2.0, 9.5), point(2.0, 12.0), point(7.0, 12.0), point(7.0, 9.5) }));
                painter.drawPolyline(QPolygonF({
                    point(9.0, 9.5), point(9.0, 12.0), point(14.0, 12.0), point(14.0, 9.5) }));
                break;
            }
            case HexViewGlyphButton::Glyph::CaseSensitive:
            {
                // 大写 A 与小写 a 并排：区分大小写。字符分开绘制，避免整串字面量被当成待翻译文本。
                QFont glyphFont = baseFont;
                glyphFont.setBold(true);
                glyphFont.setPixelSize(11);
                painter.setFont(glyphFont);
                painter.setPen(ink);
                painter.drawText(QRectF(point(0.5, 0.0), QSizeF(8.0, 16.0)), Qt::AlignCenter, QString(QChar(u'A')));
                painter.drawText(QRectF(point(8.0, 0.5), QSizeF(8.0, 16.0)), Qt::AlignCenter, QString(QChar(u'a')));
                break;
            }
            case HexViewGlyphButton::Glyph::Previous:
            {
                // 向上的尖角。
                painter.drawPolyline(QPolygonF({ point(3.5, 10.0), point(8.0, 5.5), point(12.5, 10.0) }));
                break;
            }
            case HexViewGlyphButton::Glyph::Next:
            {
                // 向下的尖角。
                painter.drawPolyline(QPolygonF({ point(3.5, 6.0), point(8.0, 10.5), point(12.5, 6.0) }));
                break;
            }
            case HexViewGlyphButton::Glyph::Close:
            {
                // 叉。
                painter.drawLine(point(4.0, 4.0), point(12.0, 12.0));
                painter.drawLine(point(12.0, 4.0), point(4.0, 12.0));
                break;
            }
            case HexViewGlyphButton::Glyph::Go:
            {
                // 向右箭头：执行。
                painter.drawLine(point(2.5, 8.0), point(13.0, 8.0));
                painter.drawLine(point(9.5, 4.5), point(13.0, 8.0));
                painter.drawLine(point(9.5, 11.5), point(13.0, 8.0));
                break;
            }
            case HexViewGlyphButton::Glyph::History:
            {
                // 时钟：圆 + 时针分针。
                painter.drawEllipse(QRectF(point(2.0, 2.0), QSizeF(12.0, 12.0)));
                painter.drawPolyline(QPolygonF({ point(8.0, 4.8), point(8.0, 8.2), point(10.4, 9.6) }));
                break;
            }
            }
        }
    }

    // ========================= HexViewBarFrame =========================

    // 构造：条带高度由内容决定，宽度铺满。
    HexViewBarFrame::HexViewBarFrame(Edge edge, QWidget* parent)
        : QWidget(parent)
        , m_edge(edge)
    {
        setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    }

    // 边线位置。
    HexViewBarFrame::Edge HexViewBarFrame::edge() const
    {
        return m_edge;
    }

    // 绘制底色与边线。
    void HexViewBarFrame::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);
        QPainter painter(this);

        // 底色：次级表面色；整条不透明填充，不依赖父控件的背景。
        painter.fillRect(rect(), KswordTheme::SurfaceAltColor());

        // 边线：一像素边框色。
        painter.setPen(KswordTheme::BorderColor());
        if (m_edge == Edge::Bottom)
        {
            painter.drawLine(0, height() - 1, width(), height() - 1);
        }
        else if (m_edge == Edge::Top)
        {
            painter.drawLine(0, 0, width(), 0);
        }
    }

    // ========================= HexViewGlyphButton =========================

    // 构造：开启悬停重绘；Tab 可达但点击不抢焦点；手形光标；自动提升（无凸起边框）。
    HexViewGlyphButton::HexViewGlyphButton(Glyph glyph, QWidget* parent)
        : QToolButton(parent)
        , m_glyph(glyph)
    {
        setAttribute(Qt::WA_Hover, true);
        setFocusPolicy(Qt::TabFocus);
        setCursor(Qt::PointingHandCursor);
        setAutoRaise(true);
    }

    // 图形种类。
    HexViewGlyphButton::Glyph HexViewGlyphButton::glyph() const
    {
        return m_glyph;
    }

    // 设置徽标文字；变化后重新计算尺寸并重绘。
    void HexViewGlyphButton::setBadgeText(const QString& text)
    {
        if (m_badge == text)
        {
            return;
        }
        m_badge = text;
        updateGeometry();
        update();
    }

    // 徽标文字。
    QString HexViewGlyphButton::badgeText() const
    {
        return m_badge;
    }

    // 建议尺寸：内边距 + 图形 + 徽标 + 下拉箭头。
    QSize HexViewGlyphButton::sizeHint() const
    {
        // badgeFont：徽标用的小号字体；宽度 = 文字宽度 + 与图形的间距。
        QFont badgeFont = font();
        badgeFont.setPixelSize(std::max(9, QFontMetrics(font()).height() - 4));
        const QFontMetrics badgeMetrics(badgeFont);
        int width = 6 + static_cast<int>(kGlyphBox) + 6;
        if (!m_badge.isEmpty())
        {
            width += 2 + badgeMetrics.horizontalAdvance(m_badge);
        }
        if (menu() != nullptr)
        {
            width += 7;
        }
        const int height = std::max(26, QFontMetrics(font()).height() + 8);
        return QSize(width, height);
    }

    // 绘制按钮。
    void HexViewGlyphButton::paintEvent(QPaintEvent* event)
    {
        Q_UNUSED(event);
        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);

        // 自绘按钮与普通工具按钮采用同样的实心状态底色，尺寸/菜单仍由原控件管理。
        const QPalette colors = parentWidget() != nullptr ? parentWidget()->palette() : palette();
        QColor surface = colors.color(QPalette::Active, QPalette::Button);
        surface.setAlpha(255);
        const QColor accent = colors.color(QPalette::Active, QPalette::Highlight);
        const QColor text = colors.color(QPalette::Active, QPalette::ButtonText);
        const QColor disabledText = colors.color(QPalette::Disabled, QPalette::ButtonText);
        const bool darkSurface = KswordTheme::RelativeLuminance(surface) < 0.25;

        const QRectF plate = QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5);
        QColor plateColor = surface;
        if (!isEnabled())
        {
            plateColor = colors.color(QPalette::Disabled, QPalette::Button);
        }
        else if (isChecked())
        {
            plateColor = accent;
        }
        else if (isDown())
        {
            plateColor = darkSurface ? surface.lighter(145) : surface.darker(120);
        }
        else if (underMouse() || hasFocus())
        {
            // 与公共按钮一致，焦点通过悬停实色底反馈而不追加轮廓。
            plateColor = darkSurface ? surface.lighter(125) : surface.darker(108);
        }
        plateColor.setAlpha(255);
        painter.setPen(Qt::NoPen);
        painter.setBrush(plateColor);
        painter.drawRoundedRect(plate, 4.0, 4.0);

        // 每一种实际底色都校准图形前景，禁用时仍保持可辨认而不冒充可操作状态。
        const QColor normalInk = KswordTheme::EnsureTextContrast(text, surface, 4.5);
        const QColor preferredInk = !isEnabled() ? disabledText
            : (isChecked() ? colors.color(QPalette::Active, QPalette::HighlightedText) : normalInk);
        const QColor ink = KswordTheme::EnsureTextContrast(
            preferredInk, plateColor, isEnabled() ? 4.5 : 3.0);
        const QColor secondaryInk = ink;

        // 图形位置：左内边距 6，垂直居中；有徽标或菜单时图形靠左，其余居中。
        const bool hasBadge = !m_badge.isEmpty();
        const bool hasMenu = (menu() != nullptr);
        const qreal glyphLeft = (hasBadge || hasMenu)
            ? 6.0
            : (static_cast<qreal>(width()) - kGlyphBox) / 2.0;
        const QRectF box(glyphLeft, (static_cast<qreal>(height()) - kGlyphBox) / 2.0, kGlyphBox, kGlyphBox);
        DrawGlyph(painter, m_glyph, box, ink, font());

        // 徽标：图形右侧的小字，次要文字色（禁用时灰）。
        if (hasBadge)
        {
            QFont badgeFont = font();
            badgeFont.setPixelSize(std::max(9, QFontMetrics(font()).height() - 4));
            badgeFont.setBold(true);
            painter.setFont(badgeFont);
            painter.setPen(secondaryInk);
            const QRectF badgeRect(
                box.right() + 2.0,
                0.0,
                static_cast<qreal>(width()) - box.right() - 2.0 - (hasMenu ? 7.0 : 2.0),
                static_cast<qreal>(height()));
            painter.drawText(badgeRect, Qt::AlignVCenter | Qt::AlignLeft, m_badge);
        }

        // 下拉箭头：菜单按钮右缘的小三角。
        if (hasMenu)
        {
            const qreal arrowX = static_cast<qreal>(width()) - 8.0;
            const qreal arrowY = static_cast<qreal>(height()) / 2.0;
            painter.setPen(Qt::NoPen);
            painter.setBrush(secondaryInk);
            painter.drawPolygon(QPolygonF({
                QPointF(arrowX - 2.5, arrowY - 1.2),
                QPointF(arrowX + 2.5, arrowY - 1.2),
                QPointF(arrowX, arrowY + 2.0) }));
        }
    }
}
