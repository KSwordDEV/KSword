#pragma once

#include "./UiAnimationGate.h"
#include "../theme.h"
#include <QElapsedTimer>
#include <QPainter>
#include <QPointer>
#include <QScreen>
#include <QTimer>
#include <QWidget>
#include <algorithm>
#include <cmath>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace ks::ui
{
    enum class NavigationHighlightKind { Region, SearchResult };

    // One transparent overlay on the requested target. It never takes focus, touches a
    // model, screenshots a page, or scans other windows. Repeated navigation replaces it.
    inline QWidget* FlashNavigationTarget(QWidget* target, NavigationHighlightKind kind = NavigationHighlightKind::Region)
    {
        if (!target || !target->isVisible()) return nullptr;
        class Highlight final : public QWidget
        {
        public:
            Highlight(QWidget* host, NavigationHighlightKind mode)
                : QWidget(host), m_target(host), m_kind(mode), m_timer(new QTimer(this))
            {
                setProperty("ksword_keyboard_overlay", true);
                setProperty("ksword_navigation_highlight", true);
                setAttribute(Qt::WA_TransparentForMouseEvents);
                setAttribute(Qt::WA_NoSystemBackground);
                setFocusPolicy(Qt::NoFocus);
                setGeometry(host->rect());
                host->installEventFilter(this);
                ObserveUiAnimations(this);
                m_elapsed.start();
                const qreal refresh = screen() ? screen()->refreshRate() : 60.0;
                m_timer->setInterval(qMax(4, qRound(1000.0 / std::clamp(refresh, 30.0, 240.0))));
                m_timer->setTimerType(Qt::PreciseTimer);
                connect(m_timer, &QTimer::timeout, this, [this]() { advance(); });
                if (animationsEnabled()) m_timer->start();
                else QTimer::singleShot(750, this, &QObject::deleteLater);
            }
        protected:
            void paintEvent(QPaintEvent*) override
            {
                QPainter painter(this);
                painter.setRenderHint(QPainter::Antialiasing);
                QColor accent = KswordTheme::EnsureTextContrast(KswordTheme::PrimaryAccentColor(), KswordTheme::SurfaceColor(), 3.0);
                QColor border = accent, fill = accent;
                border.setAlpha(qRound(245.0 * m_strength));
                fill.setAlpha(qRound((m_kind == NavigationHighlightKind::Region ? 48.0 : 36.0) * m_strength));
                painter.setPen(QPen(border, 3));
                painter.setBrush(fill);
                painter.drawRoundedRect(QRectF(rect()).adjusted(2, 2, -2, -2), 8, 8);
            }
            bool eventFilter(QObject* watched, QEvent* event) override
            {
                if (watched == m_target)
                {
                    if (event->type() == QEvent::Resize) setGeometry(m_target->rect());
                    else if (event->type() == QEvent::Hide) { m_timer->stop(); hide(); deleteLater(); }
                }
                return false;
            }
            bool event(QEvent* event) override
            {
                if (event->type() == UiAnimationsChangedEventType() && !animationsEnabled())
                {
                    m_timer->stop(); m_strength = 1.0; update();
                    QTimer::singleShot(750, this, &QObject::deleteLater);
                }
                return QWidget::event(event);
            }
        private:
            bool animationsEnabled() const
            {
                if (!AreUiAnimationsEnabled()) return false;
#ifdef Q_OS_WIN
                BOOL enabled = TRUE;
                return !SystemParametersInfoW(SPI_GETCLIENTAREAANIMATION, 0, &enabled, 0) || enabled;
#else
                return true;
#endif
            }
            void advance()
            {
                if (!isVisible() || !m_target) { m_timer->stop(); deleteLater(); return; }
                const qreal duration = m_kind == NavigationHighlightKind::Region ? 900.0 : 1800.0;
                const qreal progress = std::clamp(m_elapsed.elapsed() / duration, 0.0, 1.0);
                if (progress >= 1.0) { m_timer->stop(); hide(); deleteLater(); return; }
                if (!animationsEnabled())
                {
                    m_timer->stop(); m_strength = 1.0; update();
                    QTimer::singleShot(750, this, &QObject::deleteLater);
                    return;
                }
                if (m_kind == NavigationHighlightKind::Region)
                    m_strength = 1.0 - std::pow(qMax(0.0, (progress - 0.2) / 0.8), 2.0);
                else
                    m_strength = (0.35 + 0.65 * std::abs(std::cos(progress * 3.0 * 3.14159265358979323846))) * (1.0 - progress);
                update();
            }
            QPointer<QWidget> m_target;
            NavigationHighlightKind m_kind;
            QTimer* m_timer;
            QElapsedTimer m_elapsed;
            qreal m_strength = 1.0;
        };
        for (QWidget* child : target->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly))
            if (child->property("ksword_navigation_highlight").toBool()) { child->hide(); child->deleteLater(); }
        auto* highlight = new Highlight(target, kind);
        highlight->show();
        highlight->raise();
        return highlight;
    }
}
