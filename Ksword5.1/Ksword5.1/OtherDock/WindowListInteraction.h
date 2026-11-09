#pragma once

#include "../UI/TableColumnAutoFit.h"
#include <QHeaderView>
#include <QPainter>
#include <QSet>
#include <QMouseEvent>
#include <QContextMenuEvent>
#include <QFontMetrics>
#include <QPointer>
#include <QVector>
#include <QTimer>
#include <algorithm>
#include <utility>
#include <QTreeWidget>
#include <QTreeWidgetItemIterator>
#include <QWidget>
#include <Windows.h>

namespace ks::window
{
    inline void configureWindowListColumnSizing(QTreeView* tree)
    {
        // The shared fitter samples and compresses fields. Keep HWNDs and
        // process names at their native delegate widths, including icons/fonts.
        ks::ui::SetTableColumnAutoFitEnabled(tree, false);
        tree->header()->setStretchLastSection(false);
        tree->header()->setResizeContentsPrecision(100);
        tree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
        tree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    }

    inline QString windowIdentityKey(quint64 hwnd, quint64 pid, quint64 tid, quint64 created)
    {
        return QStringLiteral("%1/%2/%3/%4")
            .arg(hwnd).arg(pid).arg(tid).arg(created);
    }

    inline QString windowItemIdentity(const QTreeWidgetItem* item)
    {
        return windowIdentityKey(item->data(0, Qt::UserRole).toULongLong(),
            item->data(0, Qt::UserRole + 2).toULongLong(),
            item->data(0, Qt::UserRole + 3).toULongLong(),
            item->data(0, Qt::UserRole + 4).toULongLong());
    }

    struct WindowTreeSelection
    {
        QSet<QString> identities;
        QString current;
    };

    inline WindowTreeSelection captureWindowSelection(const QTreeWidget* tree)
    {
        WindowTreeSelection selection;
        for (const auto* item : tree->selectedItems())
            if (!item->data(0, Qt::UserRole + 1).toBool())
                selection.identities.insert(windowItemIdentity(item));
        const auto* current = tree->currentItem();
        if (current && !current->data(0, Qt::UserRole + 1).toBool())
            selection.current = windowItemIdentity(current);
        return selection;
    }

    inline void restoreWindowSelection(QTreeWidget* tree, const WindowTreeSelection& selection)
    {
        QTreeWidgetItemIterator iterator(tree);
        while (*iterator)
        {
            auto* item = *iterator++;
            if (item->data(0, Qt::UserRole + 1).toBool()) continue;
            const QString identity = windowItemIdentity(item);
            item->setSelected(selection.identities.contains(identity));
            if (identity == selection.current)
                tree->setCurrentItem(item, 0, QItemSelectionModel::NoUpdate);
        }
    }

    inline void selectContextWindow(QTreeWidget* tree, QTreeWidgetItem* item)
    {
        tree->setCurrentItem(item, 0, item->isSelected() ? QItemSelectionModel::NoUpdate
            : QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }

    inline QList<quint64> selectedWindowHandles(const QTreeWidget* tree)
    {
        QList<quint64> handles;
        QSet<quint64> seen;
        for (const auto* item : tree->selectedItems())
        {
            const quint64 hwnd = item->data(0, Qt::UserRole).toULongLong();
            if (item->data(0, Qt::UserRole + 1).toBool() || item->isHidden()
                || hwnd == 0 || seen.contains(hwnd)) continue;
            seen.insert(hwnd);
            handles.push_back(hwnd);
        }
        return handles;
    }

    inline QString windowItemIdentity(const QModelIndex& index)
    {
        const QString stableKey = index.data(Qt::UserRole + 5).toString();
        if (!stableKey.isEmpty()) return stableKey;
        return windowIdentityKey(index.data(Qt::UserRole).toULongLong(),
            index.data(Qt::UserRole + 2).toULongLong(), index.data(Qt::UserRole + 3).toULongLong(),
            index.data(Qt::UserRole + 4).toULongLong());
    }
    inline WindowTreeSelection captureWindowSelection(const QTreeView* tree)
    {
        WindowTreeSelection selection;
        if (!tree->selectionModel()) return selection;
        for (const auto& index : tree->selectionModel()->selectedRows())
            selection.identities.insert(windowItemIdentity(index));
        const auto current = tree->currentIndex();
        if (current.isValid()) selection.current = windowItemIdentity(current);
        return selection;
    }
    inline void selectContextWindow(QTreeView* tree, const QModelIndex& index)
    {
        const bool selected = tree->selectionModel()->isRowSelected(index.row(), index.parent());
        tree->selectionModel()->setCurrentIndex(index, selected ? QItemSelectionModel::NoUpdate
            : QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    }
    inline QList<quint64> selectedWindowHandles(const QTreeView* tree)
    {
        QList<quint64> handles;
        QSet<quint64> seen;
        for (const auto& index : tree->selectionModel()->selectedRows())
        {
            const quint64 hwnd = index.data(Qt::UserRole).toULongLong();
            if (index.data(Qt::UserRole + 1).toBool() || tree->isRowHidden(index.row(), index.parent()) || !hwnd || seen.contains(hwnd)) continue;
            seen.insert(hwnd); handles.push_back(hwnd);
        }
        return handles;
    }

    inline bool windowIdentityMatches(quint64 hwnd, DWORD pid, DWORD tid, quint64 created = 0)
    {
        DWORD livePid = 0;
        const DWORD liveTid = ::GetWindowThreadProcessId(
            reinterpret_cast<HWND>(static_cast<quintptr>(hwnd)), &livePid);
        if (liveTid == 0 || liveTid != tid || livePid != pid) return false;
        if (created == 0) return true;
        HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, livePid);
        if (!process) return false;
        FILETIME creation{}, exit{}, kernel{}, user{};
        const bool queried = ::GetProcessTimes(process, &creation, &exit, &kernel, &user) != FALSE;
        ::CloseHandle(process);
        const quint64 liveCreated = (static_cast<quint64>(creation.dwHighDateTime) << 32)
            | creation.dwLowDateTime;
        return queried && created == liveCreated;
    }

    inline bool setWindowTopMost(HWND hwnd, bool target)
    {
        return ::SetWindowPos(hwnd, target ? HWND_TOPMOST : HWND_NOTOPMOST,
            0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE) != FALSE
            && ((::GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOPMOST) != 0) == target;
    }

    inline bool requestWindowVisible(HWND hwnd, bool target)
    {
        return ::ShowWindowAsync(hwnd, target ? SW_SHOWNA : SW_HIDE) != FALSE;
    }

    inline bool setWindowEnabled(HWND hwnd, bool target)
    {
        ::EnableWindow(hwnd, target);
        return ::IsWindow(hwnd) != FALSE && (::IsWindowEnabled(hwnd) != FALSE) == target;
    }

    struct WindowPositionMark
    {
        QRect physicalRect;
        QStringList information;
    };

    class PhysicalCoordinateScope
    {
    public:
        PhysicalCoordinateScope()
            : m_previous(::SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) {}
        ~PhysicalCoordinateScope() { if (m_previous) ::SetThreadDpiAwarenessContext(m_previous); }
        PhysicalCoordinateScope(const PhysicalCoordinateScope&) = delete;
        PhysicalCoordinateScope& operator=(const PhysicalCoordinateScope&) = delete;
    private:
        DPI_AWARENESS_CONTEXT m_previous;
    };

    inline QRect physicalVirtualDesktop()
    {
        const PhysicalCoordinateScope coordinates;
        return QRect(::GetSystemMetrics(SM_XVIRTUALSCREEN), ::GetSystemMetrics(SM_YVIRTUALSCREEN),
            ::GetSystemMetrics(SM_CXVIRTUALSCREEN), ::GetSystemMetrics(SM_CYVIRTUALSCREEN));
    }

    inline QRectF physicalRectToOverlay(const QRect& physical, const QPoint& overlayOrigin, qreal backingScale)
    {
        return QRectF((physical.x() - overlayOrigin.x()) / backingScale,
            (physical.y() - overlayOrigin.y()) / backingScale,
            physical.width() / backingScale, physical.height() / backingScale);
    }

    inline bool queryWindowMarkRect(HWND hwnd, QRect& rect)
    {
        const PhysicalCoordinateScope coordinates;
        RECT bounds{};
        if (!::GetWindowRect(hwnd, &bounds)) return false;
        if (::IsIconic(hwnd))
        {
            WINDOWPLACEMENT placement{};
            placement.length = sizeof(placement);
            if (::GetWindowPlacement(hwnd, &placement))
            {
                bounds = placement.rcNormalPosition;
                if ((::GetWindowLongPtrW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) == 0)
                {
                    MONITORINFO monitor{};
                    monitor.cbSize = sizeof(monitor);
                    if (::GetMonitorInfoW(::MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &monitor))
                        ::OffsetRect(&bounds, monitor.rcWork.left - monitor.rcMonitor.left,
                            monitor.rcWork.top - monitor.rcMonitor.top);
                }
            }
        }
        rect = QRect(bounds.left, bounds.top, bounds.right - bounds.left, bounds.bottom - bounds.top);
        return !rect.isEmpty();
    }

    // One native window spans the virtual desktop. All shadows and outlines are
    // painted first; opaque information cards and text are painted above them.
    class WindowPositionOverlay final : public QWidget
    {
    public:
        WindowPositionOverlay(QVector<WindowPositionMark> marks, const QString& hint, QWidget* owner)
            : QWidget(owner, Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint
                | Qt::WindowDoesNotAcceptFocus), m_marks(std::move(marks)), m_hint(hint)
        {
            const PhysicalCoordinateScope coordinates;
            if (s_active) s_active->close();
            s_active = this;
            if (owner)
            {
                setPalette(owner->palette());
                setFont(owner->font());
            }
            setAttribute(Qt::WA_TranslucentBackground);
            setAttribute(Qt::WA_ShowWithoutActivating);
            setAttribute(Qt::WA_DeleteOnClose);
            setAttribute(Qt::WA_NoMousePropagation);
            setCursor(Qt::CrossCursor);
            show();
            m_ready = true;
            fitPhysicalDesktop();
        }

    protected:
        bool event(QEvent* event) override
        {
            const bool handled = QWidget::event(event);
            if (m_ready && (event->type() == QEvent::DevicePixelRatioChange
                || event->type() == QEvent::ScreenChangeInternal))
                QTimer::singleShot(0, this, [this] { fitPhysicalDesktop(); update(); });
            return handled;
        }

        bool nativeEvent(const QByteArray& type, void* message, qintptr* result) override
        {
            const auto* native = static_cast<MSG*>(message);
            if (native->message == WM_DISPLAYCHANGE)
                QTimer::singleShot(0, this, [this] { fitPhysicalDesktop(); update(); });
            return QWidget::nativeEvent(type, message, result);
        }

        void mousePressEvent(QMouseEvent* event) override
        {
            event->accept();
            if (event->button() == Qt::LeftButton || event->button() == Qt::RightButton) close();
        }

        void contextMenuEvent(QContextMenuEvent* event) override { event->accept(); }

        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            // 1/255 alpha keeps blank pixels hit-testable on Windows, so a click
            // anywhere dismisses the overlay and never clicks an underlying app.
            painter.setCompositionMode(QPainter::CompositionMode_Source);
            painter.fillRect(rect(), QColor(0, 0, 0, 1));
            painter.setCompositionMode(QPainter::CompositionMode_SourceOver);

            RECT nativeBounds{};
            {
                const PhysicalCoordinateScope coordinates;
                ::GetWindowRect(reinterpret_cast<HWND>(winId()), &nativeBounds);
            }
            const qreal scale = devicePixelRatioF();
            const auto localRect = [&](const QRect& physical) {
                return physicalRectToOverlay(physical, QPoint(nativeBounds.left, nativeBounds.top), scale);
            };
            QColor theme = palette().color(QPalette::Active, QPalette::Highlight);
            QColor shadow = theme;
            shadow.setAlpha(36);
            for (const auto& mark : m_marks) painter.fillRect(localRect(mark.physicalRect), shadow);
            QPen outline(theme, 3);
            outline.setCosmetic(true);
            painter.setPen(outline);
            painter.setBrush(Qt::NoBrush);
            for (const auto& mark : m_marks) painter.drawRect(localRect(mark.physicalRect));

            const QFontMetrics metrics(font());
            const QRectF canvas = QRectF(rect()).adjusted(8, 8, -8, -8);
            const qreal hintWidth = std::min(canvas.width(), static_cast<qreal>(metrics.horizontalAdvance(m_hint) + 24));
            const QRectF hintRect(canvas.center().x() - hintWidth / 2, canvas.top(), hintWidth, metrics.height() + 16);
            QVector<QRectF> occupied{hintRect};
            QVector<QRectF> cards;
            cards.reserve(m_marks.size());
            const auto clampedCard = [&](QPointF origin, QSizeF size) {
                return QRectF(QPointF(std::clamp(origin.x(), canvas.left(), canvas.right() - size.width()),
                    std::clamp(origin.y(), canvas.top(), canvas.bottom() - size.height())), size);
            };
            const auto available = [&](const QRectF& candidate) {
                return std::none_of(occupied.begin(), occupied.end(), [&](const QRectF& other) {
                    return candidate.intersects(other.adjusted(-4, -4, 4, 4));
                });
            };
            for (const auto& mark : m_marks)
            {
                qreal width = 280;
                for (const auto& line : mark.information)
                    width = std::max(width, static_cast<qreal>(metrics.horizontalAdvance(line) + 24));
                const QSizeF size(std::min({width, qreal(420), canvas.width()}),
                    std::min(canvas.height(), static_cast<qreal>(metrics.lineSpacing() * mark.information.size() + 20)));
                const QRectF target = localRect(mark.physicalRect);
                const QList<QPointF> anchors{
                    target.topLeft() + QPointF(6, 6),
                    QPointF(target.right() - size.width() - 6, target.top() + 6),
                    QPointF(target.right() + 8, target.top()),
                    QPointF(target.left(), target.bottom() + 8),
                    QPointF(target.left() - size.width() - 8, target.top())};
                QRectF card = clampedCard(anchors.front(), size);
                bool found = false;
                for (const auto& anchor : anchors)
                {
                    const QRectF candidate = clampedCard(anchor, size);
                    if (available(candidate)) { card = candidate; found = true; break; }
                }
                // Stack dense/overlapping selections in free screen space.
                for (qreal y = canvas.top(); !found && y + size.height() <= canvas.bottom(); y += size.height() + 6)
                    for (qreal x = canvas.left(); !found && x + size.width() <= canvas.right(); x += size.width() + 6)
                    {
                        const QRectF candidate(QPointF(x, y), size);
                        if (available(candidate)) { card = candidate; found = true; }
                    }
                occupied.push_back(card);
                cards.push_back(card);
            }

            QColor background = palette().color(QPalette::Active, QPalette::Base);
            background.setAlpha(255);
            painter.setPen(QPen(theme, 1));
            painter.setBrush(background);
            painter.drawRect(hintRect);
            for (const auto& card : cards) painter.drawRect(card);
            // Text is the final pass, even when a later target overlaps a card.
            painter.setPen(palette().color(QPalette::Active, QPalette::Text));
            painter.drawText(hintRect.adjusted(12, 0, -12, 0), Qt::AlignCenter,
                metrics.elidedText(m_hint, Qt::ElideRight, qRound(hintRect.width() - 24)));
            for (qsizetype i = 0; i < m_marks.size(); ++i)
            {
                const QRectF textRect = cards[i].adjusted(12, 10, -12, -10);
                painter.save();
                painter.setClipRect(textRect);
                for (qsizetype row = 0; row < m_marks[i].information.size(); ++row)
                {
                    QString line = m_marks[i].information[row];
                    if (row == 0) line = QStringLiteral("%1. %2").arg(i + 1).arg(line);
                    painter.drawText(QPointF(textRect.left(), textRect.top() + metrics.ascent() + row * metrics.lineSpacing()),
                        metrics.elidedText(line, Qt::ElideRight, qRound(textRect.width())));
                }
                painter.restore();
            }
        }

    private:
        void fitPhysicalDesktop()
        {
            const PhysicalCoordinateScope coordinates;
            const QRect desktop = physicalVirtualDesktop();
            ::SetWindowPos(reinterpret_cast<HWND>(winId()), HWND_TOPMOST,
                desktop.x(), desktop.y(), desktop.width(), desktop.height(), SWP_NOACTIVATE | SWP_SHOWWINDOW);
        }

        QVector<WindowPositionMark> m_marks;
        QString m_hint;
        bool m_ready = false;
        inline static QPointer<WindowPositionOverlay> s_active;
    };
}
