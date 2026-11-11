#include "MouselessNavigation.h"
// Navigation/layout map: main title and active Dock branch -> shared region controller;
// Settings > Startup -> existing SecondaryPageLayout form; Welcome -> existing page root;
// first activation / F1 / Welcome guide -> SecondaryPageLayout dialog with fixed footer.
// Navigation changes focus only; editing and business execution keep their own validation.
#include "./FlatButtonTheme.h"
#include "./SecondaryPageLayout.h"
#include "./ThemeBinding.h"
#include "./UI_All.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include "../include/ads/DockAreaTabBar.h"
#include "../include/ads/DockAreaWidget.h"
#include "../include/ads/DockWidget.h"
#include "../include/ads/DockWidgetTab.h"

#include <QAbstractButton>
#include <QAbstractItemView>
#include <QAbstractSpinBox>
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QContextMenuEvent>
#include <QDialog>
#include <QFocusFrame>
#include <QGroupBox>
#include <QHash>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMouseEvent>
#include <QPainter>
#include <QPersistentModelIndex>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QShortcut>
#include <QSplitter>
#include <QTabBar>
#include <QTabWidget>
#include <QTextEdit>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <algorithm>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace
{
    constexpr auto modeProperty = "ksword_mouseless_mode";
    constexpr auto regionProperty = "ksword_keyboard_region";
    constexpr auto overlayProperty = "ksword_keyboard_overlay";

    QString text(const char* source)
    {
        return ks::i18n::sourceText(QString::fromUtf8(source));
    }

    class KeyboardFocusFrame final : public QFocusFrame
    {
    public:
        explicit KeyboardFocusFrame(QWidget* parent) : QFocusFrame(parent)
        {
            setProperty(overlayProperty, true);
            setAttribute(Qt::WA_TransparentForMouseEvents);
            setFocusPolicy(Qt::NoFocus);
            ks::ui::BindWidgetTheme(this, [this]() { update(); });
        }
    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing);
            const QRectF frame = QRectF(rect()).adjusted(2, 2, -2, -2);
            // Two contrasting strokes remain readable on tables, pictures and transparent surfaces.
            painter.setPen(QPen(KswordTheme::SurfaceColor(), 4));
            painter.drawRoundedRect(frame, 5, 5);
            painter.setPen(QPen(KswordTheme::TextPrimaryColor(), 2, Qt::DashLine));
            painter.drawRoundedRect(frame, 5, 5);
        }
    };

    class KeyTipsOverlay final : public QWidget
    {
    public:
        struct Tip { QPointer<QWidget> target; QString code; QString title; };
        QVector<Tip> tips;
        QString prefix;
        explicit KeyTipsOverlay(QWidget* parent) : QWidget(parent)
        {
            setProperty(overlayProperty, true);
            setAttribute(Qt::WA_TransparentForMouseEvents);
            setAttribute(Qt::WA_NoSystemBackground);
            setFocusPolicy(Qt::NoFocus);
            QFont readable = font();
            if (readable.pixelSize() > 0) readable.setPixelSize(qMax(14, readable.pixelSize()));
            else readable.setPointSizeF(qMax(10.0, readable.pointSizeF()));
            setFont(readable);
        }
    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing);
            painter.setFont(font());
            QVector<QRect> placed;
            for (const auto& tip : tips)
            {
                if (!tip.target || !tip.target->isVisible() || tip.target->window() != parentWidget()->window()
                    || !tip.code.startsWith(prefix)) continue;
                const QString caption = tip.code + QStringLiteral("  ")
                    + fontMetrics().elidedText(tip.title, Qt::ElideRight, 150);
                const QSize size(qMin(width(), fontMetrics().horizontalAdvance(caption) + 16),
                    fontMetrics().height() + 10);
                const QPoint point = tip.target->mapTo(parentWidget(), QPoint());
                QRect box(QPoint(qBound(0, point.x(), qMax(0, width() - size.width())),
                    qBound(0, point.y(), qMax(0, height() - size.height()))), size);
                // Colliding nested regions get separate labels; no target is silently discarded.
                for (int attempt = 0; attempt < placed.size() + 1; ++attempt)
                {
                    bool collision = false;
                    for (const auto& previous : placed)
                    {
                        if (!previous.intersects(box)) continue;
                        box.moveTop(previous.bottom() + 3);
                        if (box.bottom() >= height())
                        {
                            box.moveTop(0);
                            box.moveLeft(qBound(0, previous.right() + 3, qMax(0, width() - size.width())));
                        }
                        collision = true;
                        break;
                    }
                    if (!collision) break;
                }
                placed.append(box);
                painter.setPen(QPen(KswordTheme::TextPrimaryColor(), 1));
                painter.setBrush(KswordTheme::SurfaceColor());
                painter.drawRoundedRect(box, 5, 5);
                painter.drawText(box.adjusted(8, 0, -8, 0), Qt::AlignVCenter | Qt::AlignLeft, caption);
            }
        }
    };

    bool isControl(QWidget* widget)
    {
        if (qobject_cast<QScrollBar*>(widget) || qobject_cast<QFocusFrame*>(widget)) return false;
        if (qobject_cast<QAbstractButton*>(widget) || qobject_cast<QTabBar*>(widget)
            || qobject_cast<ads::CDockAreaTabBar*>(widget)) return true;
        return widget->focusPolicy() != Qt::NoFocus && !widget->focusProxy();
    }

    QWidget* regionFor(QWidget* control, QWidget* window)
    {
        for (QWidget* item = control; item && item != window; item = item->parentWidget())
        {
            if (item->property(regionProperty).toBool() || item->property("ksword_secondary_footer").toBool()
                || qobject_cast<QGroupBox*>(item)
                || qobject_cast<QTabBar*>(item) || qobject_cast<ads::CDockAreaTabBar*>(item)
                || qobject_cast<QAbstractItemView*>(item) || qobject_cast<QPlainTextEdit*>(item)
                || qobject_cast<QTextEdit*>(item)) return item;
            QWidget* parent = item->parentWidget();
            if (qobject_cast<QSplitter*>(parent) || qobject_cast<ads::CDockWidget*>(parent)) return item;
        }
        return window;
    }

    QString regionTitle(QWidget* anchor)
    {
        const QString declared = anchor->property("ksword_keyboard_region_name").toString();
        if (!declared.isEmpty()) return ks::i18n::sourceText(declared);
        if (!anchor->accessibleName().isEmpty()) return anchor->accessibleName();
        if (auto* group = qobject_cast<QGroupBox*>(anchor)) return group->title();
        if (qobject_cast<QTabBar*>(anchor)) return text("页面导航");
        if (qobject_cast<ads::CDockAreaTabBar*>(anchor)) return text("主功能导航");
        if (qobject_cast<QAbstractItemView*>(anchor)) return text("列表 / 树");
        if (qobject_cast<QPlainTextEdit*>(anchor) || qobject_cast<QTextEdit*>(anchor)) return text("文本 / 编辑器");
        return text("操作区");
    }

    class TutorialDialog final : public QDialog
    {
    public:
        using QDialog::QDialog;
        std::function<void()> refresh;
    protected:
        void changeEvent(QEvent* event) override
        {
            QDialog::changeEvent(event);
            if (event->type() == QEvent::LanguageChange && refresh) refresh();
        }
    };
}

ks::ui::MouselessNavigation::MouselessNavigation(QWidget* mainWindow,
    std::function<void(bool)> modeChanged, std::function<void()> dismissTransientPanels)
    : QObject(mainWindow), m_mainWindow(mainWindow), m_modeChanged(std::move(modeChanged)),
      m_dismissTransientPanels(std::move(dismissTransientPanels))
{
    m_clock.start();
    qApp->installEventFilter(this);
    qApp->installNativeEventFilter(this);
    connect(qApp, &QApplication::focusChanged, this, [this](QWidget*, QWidget*) {
        if (m_enabled) updateFocusFrame();
    });
}

ks::ui::MouselessNavigation::~MouselessNavigation()
{
    qApp->removeNativeEventFilter(this);
    qApp->removeEventFilter(this);
    qApp->setProperty(modeProperty, false);
    delete m_tipOverlay.data();
    delete m_focusFrame.data();
}

void ks::ui::MouselessNavigation::setEnabled(bool enabled)
{
    if (m_enabled == enabled) return;
    m_enabled = enabled;
    qApp->setProperty(modeProperty, enabled);
    hideKeyTips();
    if (m_modeChanged) m_modeChanged(enabled);
    if (!enabled && m_tutorial) m_tutorial->close();
    if (auto* focus = QApplication::focusWidget()) focus->update();
    updateFocusFrame();
    if (enabled)
    {
        if (!QApplication::focusWidget()) recoverFocus();
        offerFirstTutorial();
    }
}

QWidget* ks::ui::MouselessNavigation::navigationWindow() const
{
    if (auto* modal = QApplication::activeModalWidget()) return modal;
    if (auto* active = QApplication::activeWindow()) return active;
    return m_mainWindow;
}

QVector<ks::ui::MouselessNavigation::Region> ks::ui::MouselessNavigation::regions(QWidget* window) const
{
    QVector<Region> result;
    if (!window) return result;
    QVector<QWidget*> pending{window};
    while (!pending.isEmpty())
    {
        QWidget* widget = pending.takeLast();
        if (!widget->isVisible() || !widget->isEnabled() || widget->property(overlayProperty).toBool()
            || (widget != window && widget->isWindow())) continue;
        if (isControl(widget))
        {
            QWidget* anchor = regionFor(widget, window);
            auto found = std::find_if(result.begin(), result.end(), [anchor](const Region& region) {
                return region.anchor == anchor;
            });
            if (found == result.end())
            {
                result.append({anchor, {}, regionTitle(anchor)});
                found = result.end() - 1;
            }
            found->controls.append(widget);
            // Composite editors keep their own internal caret/selection and viewport identity.
            if (qobject_cast<QAbstractItemView*>(widget) || qobject_cast<QAbstractSpinBox*>(widget)
                || qobject_cast<QComboBox*>(widget) || qobject_cast<QPlainTextEdit*>(widget)
                || qobject_cast<QTextEdit*>(widget) || qobject_cast<QTabBar*>(widget)
                || qobject_cast<ads::CDockAreaTabBar*>(widget)) continue;
        }
        const auto children = widget->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
        for (auto child = children.crbegin(); child != children.crend(); ++child) pending.append(*child);
    }
    // Regions follow their displayed top-to-bottom/left-to-right positions, not allocation order.
    std::stable_sort(result.begin(), result.end(), [window](const Region& left, const Region& right) {
        const QPoint a = left.anchor->mapTo(window, QPoint());
        const QPoint b = right.anchor->mapTo(window, QPoint());
        if (a.y() != b.y()) return a.y() < b.y();
        return window->layoutDirection() == Qt::RightToLeft ? a.x() > b.x() : a.x() < b.x();
    });
    // Read the chain once, even on pages with many regions; preserve explicit setTabOrder.
    QHash<QWidget*, int> order;
    QWidget* cursor = window;
    do
    {
        order.insert(cursor, static_cast<int>(order.size()));
        cursor = cursor->nextInFocusChain();
    } while (cursor && cursor != window);
    for (auto& region : result)
    {
        std::stable_sort(region.controls.begin(), region.controls.end(), [&order](const auto& left, const auto& right) {
            return order.value(left, static_cast<int>(order.size())) < order.value(right, static_cast<int>(order.size()));
        });
    }
    return result;
}

int ks::ui::MouselessNavigation::currentRegion(const QVector<Region>& items, QWidget* focus) const
{
    if (!focus) return -1;
    for (int index = 0; index < items.size(); ++index)
        for (const auto& control : items[index].controls)
            if (control && (control == focus || control->isAncestorOf(focus))) return index;
    return -1;
}

void ks::ui::MouselessNavigation::focusControl(QWidget* control)
{
    if (!control || !control->isVisible() || !control->isEnabled()
        || control->window() != navigationWindow()) return;
    const QPointer<QWidget> alive(control);
    const QPointer<MouselessNavigation> owner(this);
    QVector<QPointer<QScrollArea>> scrolls;
    for (QWidget* parent = control->parentWidget(); parent && !parent->isWindow(); parent = parent->parentWidget())
        if (auto* scroll = qobject_cast<QScrollArea*>(parent)) scrolls.append(scroll);
    control->setFocus(Qt::TabFocusReason); // Works for mouse-only buttons without rewriting focus policies.
    if (!alive || !owner) return;
    for (const auto& scroll : scrolls)
    {
        if (scroll) scroll->ensureWidgetVisible(alive, 8, 8);
        if (!alive || !owner) return;
    }
    if (auto* view = qobject_cast<QAbstractItemView*>(control); view && view->model())
    {
        if (!view->currentIndex().isValid() && view->model()->rowCount(view->rootIndex()) > 0)
            view->setCurrentIndex(view->model()->index(0, 0, view->rootIndex()));
        if (!alive || !owner) return;
        if (view->currentIndex().isValid()) view->scrollTo(view->currentIndex());
    }
    if (owner) updateFocusFrame();
}

void ks::ui::MouselessNavigation::moveFocus(bool backwards, bool withinRegion)
{
    hideKeyTips();
    if (auto* popup = QApplication::activePopupWidget()) popup->close();
    const auto items = regions(navigationWindow());
    if (items.isEmpty()) return;
    QWidget* focus = QApplication::focusWidget();
    const int current = currentRegion(items, focus);
    if (withinRegion && current >= 0)
    {
        const auto& controls = items[current].controls;
        int index = -1;
        for (int i = 0; i < controls.size(); ++i)
            if (controls[i] && (controls[i] == focus || controls[i]->isAncestorOf(focus))) { index = i; break; }
        focusControl(controls[MouselessNextIndex(index, static_cast<int>(controls.size()), backwards)]);
    }
    else
    {
        const auto& next = items[MouselessNextIndex(current, static_cast<int>(items.size()), backwards)];
        focusControl(backwards ? next.controls.last().data() : next.controls.first().data());
    }
}

void ks::ui::MouselessNavigation::recoverFocus()
{
    hideKeyTips();
    if (auto* popup = QApplication::activePopupWidget()) popup->close();
    if (navigationWindow() == m_mainWindow && m_dismissTransientPanels) m_dismissTransientPanels();
    const auto items = regions(navigationWindow());
    if (!items.isEmpty()) focusControl(items.first().controls.first());
}

void ks::ui::MouselessNavigation::updateFocusFrame()
{
    if (!m_enabled || QGuiApplication::applicationState() != Qt::ApplicationActive)
    {
        if (m_focusFrame) m_focusFrame->hide();
        return;
    }
    QWidget* focus = QApplication::focusWidget();
    if (!focus || !focus->isVisible())
    {
        if (m_focusFrame) m_focusFrame->hide();
        return;
    }
    if (!m_focusFrame) m_focusFrame = new KeyboardFocusFrame(m_mainWindow);
    m_focusFrame->setWidget(focus);
    m_focusFrame->show();
    m_focusFrame->raise();
}

void ks::ui::MouselessNavigation::showKeyTips()
{
    hideKeyTips();
    QWidget* window = navigationWindow();
    m_tipRegions = regions(window);
    if (m_tipRegions.isEmpty()) return;
    m_tipDigits = static_cast<int>(QString::number(m_tipRegions.size()).size());
    auto* overlay = new KeyTipsOverlay(window);
    for (int i = 0; i < m_tipRegions.size(); ++i)
        overlay->tips.append({m_tipRegions[i].anchor,
            QString::number(i + 1).rightJustified(m_tipDigits, QLatin1Char('0')), m_tipRegions[i].title});
    m_tipOverlay = overlay;
    overlay->setGeometry(window->rect());
    overlay->show();
    overlay->raise();
}

void ks::ui::MouselessNavigation::hideKeyTips()
{
    if (m_tipOverlay) { m_tipOverlay->hide(); m_tipOverlay->deleteLater(); }
    m_tipOverlay.clear();
    m_tipRegions.clear();
    m_tipPrefix.clear();
}

bool ks::ui::MouselessNavigation::contextMenu(QWidget* focus)
{
    if (!focus) return false;
    QWidget* target = focus;
    QPoint position = focus->rect().center();
    if (auto* view = qobject_cast<QAbstractItemView*>(focus))
    {
        const QPointer<QAbstractItemView> alive(view);
        target = view->viewport();
        if (view->currentIndex().isValid())
        {
            view->scrollTo(view->currentIndex());
            if (!alive) return true;
            target = view->viewport();
            position = view->visualRect(view->currentIndex()).center();
        }
        else position = target->rect().center();
    }
    QContextMenuEvent menu(QContextMenuEvent::Keyboard, position, target->mapToGlobal(position));
    QApplication::sendEvent(target, &menu);
    return true;
}

bool ks::ui::MouselessNavigation::activateControl(QWidget* focus, QKeyEvent* key)
{
    if (!focus) return false;
    const bool enter = key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter;
    if (auto* view = qobject_cast<QAbstractItemView*>(focus); view && enter)
    {
        if (key->isAutoRepeat()) return true;
        const QPointer<QAbstractItemView> alive(view);
        const QPersistentModelIndex index(view->currentIndex());
        if (!index.isValid()) return true;
        view->scrollTo(index);
        if (!alive || !index.isValid()) return true;
        const QPoint position = view->visualRect(index).intersected(view->viewport()->rect()).center();
        if (view->indexAt(position) != index) return true;
        const QPointer<QWidget> viewport(view->viewport());
        const QPoint global = viewport->mapToGlobal(position);
        QMouseEvent press(QEvent::MouseButtonPress, QPointF(position), QPointF(global),
            Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
        QApplication::sendEvent(viewport, &press);
        if (!alive || !viewport) return true;
        // Never release onto a different row after a synchronous model reset/reorder.
        const bool sameTarget = index.isValid() && alive->indexAt(position) == index;
        const QPoint releasePosition = sameTarget ? position : QPoint(-1, -1);
        QMouseEvent release(QEvent::MouseButtonRelease, QPointF(releasePosition),
            QPointF(viewport->mapToGlobal(releasePosition)), Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
        QApplication::sendEvent(viewport, &release);
        if (key->modifiers().testFlag(Qt::ControlModifier) && sameTarget && alive && viewport
            && index.isValid() && alive->indexAt(position) == index)
        {
            QMouseEvent doubleClick(QEvent::MouseButtonDblClick, QPointF(position), QPointF(global),
                Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
            QApplication::sendEvent(viewport, &doubleClick);
            if (alive && viewport)
            {
                const QPoint end = index.isValid() && alive->indexAt(position) == index ? position : QPoint(-1, -1);
                QMouseEvent finish(QEvent::MouseButtonRelease, QPointF(end), QPointF(viewport->mapToGlobal(end)),
                    Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
                QApplication::sendEvent(viewport, &finish);
            }
        }
        return true;
    }
    if (key->modifiers().testFlag(Qt::ControlModifier)) return false;
    if (auto* bar = qobject_cast<ads::CDockAreaTabBar*>(focus))
    {
        if (key->key() != Qt::Key_Left && key->key() != Qt::Key_Right
            && key->key() != Qt::Key_Home && key->key() != Qt::Key_End) return false;
        const bool previous = key->key() == Qt::Key_Left || key->key() == Qt::Key_End;
        int current = (key->key() == Qt::Key_Home || key->key() == Qt::Key_End) ? -1 : bar->currentIndex();
        for (int tried = 0; tried < bar->count(); ++tried)
        {
            current = MouselessNextIndex(current, bar->count(), previous);
            auto* tab = bar->tab(current);
            if (!bar->isTabOpen(current) || !tab || !tab->isEnabled() || !tab->dockWidget()) continue;
            const QPointer<ads::CDockAreaTabBar> alive(bar);
            if (auto* area = tab->dockWidget()->dockAreaWidget()) area->setCurrentIndex(current);
            if (alive) alive->setFocus(Qt::TabFocusReason);
            return true;
        }
        return true;
    }
    if (!enter) return false;
    if (auto* button = qobject_cast<QAbstractButton*>(focus))
    {
        if (!key->isAutoRepeat())
        {
            if (auto* tool = qobject_cast<QToolButton*>(button); tool && tool->menu()) tool->showMenu();
            else if (auto* push = qobject_cast<QPushButton*>(button); push && push->menu()) push->showMenu();
            else button->click();
        }
        return true;
    }
    if (auto* combo = qobject_cast<QComboBox*>(focus))
    {
        combo->showPopup();
        return true;
    }
    // Text editors, active cell editors and professional canvases retain native Enter semantics.
    return false;
}

bool ks::ui::MouselessNavigation::nativeEventFilter(const QByteArray&, void* message, qintptr* result)
{
#ifdef Q_OS_WIN
    if (QGuiApplication::applicationState() != Qt::ApplicationActive) return false;
    const auto* msg = static_cast<const MSG*>(message);
    const bool down = msg->message == WM_KEYDOWN || msg->message == WM_SYSKEYDOWN;
    const bool up = msg->message == WM_KEYUP || msg->message == WM_SYSKEYUP;
    if (!down && !up) return false;
    const auto vk = msg->wParam;
    const bool alt = vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU;
    const bool control = vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL;
    const auto key = alt ? ((msg->lParam & (1LL << 24)) ? MouselessGesture::Key::RightAlt
        : MouselessGesture::Key::LeftAlt) : control ? MouselessGesture::Key::Control : MouselessGesture::Key::Other;
    if (m_gesture.update(key, down, (GetKeyState(VK_CONTROL) & 0x8000) != 0,
        down && (msg->lParam & (1LL << 30)) != 0, m_clock.elapsed()))
    {
        setEnabled(!m_enabled);
        if (result) *result = 0;
        return true;
    }
#else
    Q_UNUSED(message);
    Q_UNUSED(result);
#endif
    return false;
}

bool ks::ui::MouselessNavigation::eventFilter(QObject* object, QEvent* event)
{
    const auto type = event->type();
    if (type == QEvent::ApplicationDeactivate)
    {
        m_gesture.reset();
        m_altHeld = false;
        hideKeyTips();
        updateFocusFrame();
        return false;
    }
    if (object == m_mainWindow && type == QEvent::Show) offerFirstTutorial();
    if (!m_enabled) return false;
    if (type == QEvent::ApplicationActivate) updateFocusFrame();
    if (type == QEvent::MouseButtonPress || type == QEvent::WindowDeactivate) hideKeyTips();
    if (m_tipOverlay && object == m_tipOverlay->parentWidget() && type == QEvent::Resize) hideKeyTips();
    if (type != QEvent::KeyPress && type != QEvent::KeyRelease && type != QEvent::ShortcutOverride) return false;
    auto* key = static_cast<QKeyEvent*>(event);
    const auto modifiers = key->modifiers();
    const bool control = modifiers.testFlag(Qt::ControlModifier);
    const bool alt = modifiers.testFlag(Qt::AltModifier);
    const bool shift = modifiers.testFlag(Qt::ShiftModifier);
    const bool meta = modifiers.testFlag(Qt::MetaModifier);
    if (modifiers.testFlag(Qt::GroupSwitchModifier)) return false; // AltGr text input is not a navigation command.
    const bool plain = !control && !alt && !meta;
    const bool tab = (key->key() == Qt::Key_Tab || key->key() == Qt::Key_Backtab) && !alt && !meta;
    const bool recovery = key->key() == Qt::Key_Home && control && alt && !meta;
    const bool tipsDigit = m_tipOverlay && key->key() >= Qt::Key_0 && key->key() <= Qt::Key_9 && !control && !meta;
    const bool altKey = key->key() == Qt::Key_Alt && !control && !shift && !meta;
    QWidget* focus = QApplication::focusWidget();
    const bool nativePopup = QApplication::activePopupWidget() != nullptr;
    const bool activation = plain && !shift && !nativePopup && focus
        && (qobject_cast<QAbstractButton*>(focus) || qobject_cast<QComboBox*>(focus)
            || qobject_cast<ads::CDockAreaTabBar*>(focus))
        && (key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter
            || key->key() == Qt::Key_Left || key->key() == Qt::Key_Right
            || key->key() == Qt::Key_Home || key->key() == Qt::Key_End);
    const bool viewActivation = !alt && !meta && !shift && !nativePopup && qobject_cast<QAbstractItemView*>(focus)
        && (key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter);
    const bool menuKey = key->key() == Qt::Key_Menu
        || (key->key() == Qt::Key_F10 && shift && !control && !alt && !meta);
    const bool help = key->key() == Qt::Key_F1 && plain;
    const bool f6 = key->key() == Qt::Key_F6 && plain;
    const bool searchScope = control && alt && !meta && key->key() == Qt::Key_S && focus
        && focus->property("ksword_mouseless_search_input").toBool();
    if (type == QEvent::ShortcutOverride)
    {
        if (tab || recovery || tipsDigit || altKey || activation || viewActivation || menuKey || help || f6 || searchScope
            || (m_tipOverlay && key->key() == Qt::Key_Escape))
        { key->accept(); return true; }
        return false;
    }
    if (type == QEvent::KeyRelease)
    {
        if (key->key() == Qt::Key_Alt && m_altHeld)
        {
            m_altHeld = false;
            if (m_tipUsed) hideKeyTips();
            return true;
        }
        return false;
    }
    if (recovery) { recoverFocus(); return true; }
    if (help) { if (!key->isAutoRepeat()) showTutorial(); return true; }
    if (altKey)
    {
        if (nativePopup) return false;
        if (!key->isAutoRepeat())
        {
            m_altHeld = true;
            m_tipUsed = false;
            if (m_tipOverlay) hideKeyTips(); else showKeyTips();
        }
        return true;
    }
    if (tipsDigit)
    {
        if (key->isAutoRepeat()) return true;
        m_tipPrefix += QChar(QLatin1Char('0').unicode() + key->key() - Qt::Key_0);
        if (m_tipPrefix.size() == m_tipDigits)
        {
            const int selected = m_tipPrefix.toInt() - 1;
            QPointer<QWidget> target;
            if (selected >= 0 && selected < m_tipRegions.size()) target = m_tipRegions[selected].controls.first();
            hideKeyTips();
            m_tipUsed = true;
            if (target) focusControl(target);
        }
        else
        {
            static_cast<KeyTipsOverlay*>(m_tipOverlay.data())->prefix = m_tipPrefix;
            m_tipOverlay->update();
        }
        return true;
    }
    if (m_tipOverlay && key->key() == Qt::Key_Escape) { hideKeyTips(); return true; }
    if (tab || f6) { moveFocus(shift || key->key() == Qt::Key_Backtab, control); return true; }
    if (m_tipOverlay) hideKeyTips();
    if (menuKey && !nativePopup) return contextMenu(focus);
    if (((plain && !shift) || viewActivation) && !nativePopup) return activateControl(focus, key);
    return false;
}

void ks::ui::MouselessNavigation::offerFirstTutorial()
{
    if (!m_enabled || m_tutorialOffered || m_firstTutorialQueued || !m_mainWindow || !m_mainWindow->isVisible()) return;
    QSettings preferences(QStringLiteral("KSword"), QStringLiteral("KeyboardNavigation"));
    if (preferences.value(QStringLiteral("tutorialVersion"), 0).toInt() >= 1) return;
    m_firstTutorialQueued = true;
    QTimer::singleShot(0, this, [this]() {
        m_firstTutorialQueued = false;
        if (!m_enabled || !m_mainWindow || !m_mainWindow->isVisible()) return;
        m_tutorialOffered = true;
        showTutorial();
    });
}

void ks::ui::MouselessNavigation::showTutorial()
{
    if (!navigationWindow() || !navigationWindow()->isEnabled()) return;
    m_tutorialOffered = true;
    setEnabled(true);
    hideKeyTips();
    if (m_tutorial) { m_tutorial->show(); m_tutorial->raise(); m_tutorial->activateWindow(); return; }
    if (auto* popup = QApplication::activePopupWidget()) popup->close();
    auto* dialog = new TutorialDialog(navigationWindow());
    m_tutorial = dialog;
    dialog->setWindowModality(Qt::WindowModal);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setProperty("ksword_detail_keep_layout", true);
    StyleSecondaryWindow(dialog);
    applyResponsiveWindowGeometry(dialog, navigationWindow(), QSize(780, 620), QSize(480, 360));
    auto* root = new QVBoxLayout(dialog);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);
    auto* body = new QWidget(dialog);
    auto* content = new QVBoxLayout(body);
    StyleSecondaryContentLayout(content);
    auto* heading = new QLabel(body);
    auto* explanation = new QLabel(body);
    heading->setWordWrap(true);
    explanation->setWordWrap(true);
    explanation->setTextFormat(Qt::PlainText);
    content->addWidget(heading);
    content->addWidget(explanation);
    auto* practice = new QGroupBox(body);
    StyleSecondarySection(practice);
    auto* fields = new QVBoxLayout(practice);
    auto* input = new QLineEdit(practice);
    auto* check = new QCheckBox(practice);
    auto* action = new QPushButton(practice);
    auto* feedback = new QLabel(practice);
    feedback->setWordWrap(true);
    fields->addWidget(input);
    fields->addWidget(check);
    fields->addWidget(action);
    fields->addWidget(feedback);
    content->addWidget(practice);
    content->addStretch(1);
    auto* scroll = new QScrollArea(dialog);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setWidget(body);
    root->addWidget(scroll, 1);
    auto* footer = new QWidget(dialog);
    footer->setProperty(regionProperty, true);
    auto* actions = new QHBoxLayout(footer);
    auto* previous = new QPushButton(footer);
    auto* next = new QPushButton(footer);
    auto* close = new QPushButton(footer);
    actions->addWidget(previous);
    actions->addWidget(next);
    actions->addStretch(1);
    actions->addWidget(close);
    StyleSecondaryFooter(footer);
    ApplyFlatButtonTheme(next, FlatButtonTone::Accent, FlatButtonAppearance::Solid);
    root->addWidget(footer);
    dialog->setProperty("tutorial_step", 0);
    dialog->refresh = [dialog, heading, explanation, practice, input, check, action, previous, next, close]() {
        const int step = dialog->property("tutorial_step").toInt();
        const QStringList lessons{
            text("1. 进入与退出\n按住 Ctrl 连按两次 Alt（两次间隔不超过 0.7 秒），或同时按住 Ctrl、左 Alt 和右 Alt。标题末尾显示“（无鼠标模式）”。重复任一手势即可退出。设置 → 启动可选择下次自动进入。"),
            text("2. 先选分区，再选控件\nTab / Shift+Tab 切换下一个 / 上一个分区；F6 / Shift+F6 也可以。Ctrl+Tab / Ctrl+Shift+Tab 在当前分区内逐个选择控件。虚线框标出当前焦点。试着在下面的输入框、复选框和按钮间移动。"),
            text("3. 从输入框直接跳转\n按 Alt 显示每个分区的编号；按完整编号直接跳转。可以按住 Alt 输入，也可以松开 Alt 再输入。多位编号需要输入前导零。Esc 取消编号。输入框、代码编辑器和表格不会拦截这些分区键。"),
            text("4. 激活与右键菜单\nEnter 激活当前按钮或打开下拉框，Space 勾选复选框。Shift+F10 或菜单键打开当前控件的右键菜单；方向键选菜单项，Enter 确认，Esc 关闭。试着对下面的练习按钮打开右键菜单。文本框中的 Enter 保留提交 / 换行语义。"),
            text("5. 切页、列表与编辑\n聚焦主功能导航或页签栏后，用左右方向键切页。列表和树用方向键、Home/End、PageUp/PageDown 选择，Enter 单击当前项，Ctrl+Enter 双击。Ctrl/Shift 多选、F2 编辑沿用原有行为。编辑器保留光标与选区操作；需要字面 Tab 时可暂时退出无鼠标模式。"),
            text("6. 搜索与脱困\n顶部搜索框内用 Ctrl+Alt+S 切换全局、当前页、当前表格和 CMD；加 Shift 反向切换。Esc 关闭当前菜单或弹窗。Ctrl+Alt+Home 回到当前窗口第一个分区，不清空草稿。模态对话框内不会跳到被阻挡的主窗口。F1 随时重开本教程。"),
            text("7. 开始使用\n建议先练习：Tab 找分区 → Ctrl+Tab 找控件 → 方向键选择 → Enter 或 Space 执行 → Shift+F10 查看更多动作。F8 下一步，Shift+F8 上一步，Esc 关闭教程；只有点击“完成教程”才记为已完成。系统原生选择器和外部程序使用其原生键盘规则；Alt+F4 仍是关闭当前窗口。")
        };
        dialog->setWindowTitle(text("无鼠标模式教程"));
        heading->setText(text("无鼠标模式 · 第 %1 / 7 步").arg(step + 1));
        explanation->setText(lessons[step]);
        practice->setTitle(text("安全练习区（只练习键盘，不执行系统操作）"));
        input->setPlaceholderText(text("在这里输入文字，再用 Tab 或 Alt 编号跳出去"));
        check->setText(text("练习：用 Space 勾选"));
        action->setText(text("练习：Enter 激活 / Shift+F10 右键菜单"));
        previous->setText(text("上一步"));
        previous->setEnabled(step > 0);
        next->setText(step == 6 ? text("完成教程") : text("下一步"));
        close->setText(text("稍后再学"));
    };
    connect(action, &QPushButton::clicked, dialog, [feedback]() { feedback->setText(text("已成功激活按钮。")); });
    action->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(action, &QWidget::customContextMenuRequested, dialog, [action, feedback](const QPoint& position) {
        auto* menu = new QMenu(action);
        menu->setAttribute(Qt::WA_DeleteOnClose);
        menu->setStyleSheet(KswordTheme::ContextMenuStyle());
        menu->addAction(text("练习：选择此菜单项"), feedback, [feedback]() {
            feedback->setText(text("已成功使用右键菜单。"));
        });
        menu->popup(action->mapToGlobal(position));
    });
    connect(previous, &QPushButton::clicked, dialog, [dialog]() {
        dialog->setProperty("tutorial_step", qMax(0, dialog->property("tutorial_step").toInt() - 1));
        dialog->refresh();
    });
    connect(next, &QPushButton::clicked, dialog, [dialog, feedback]() {
        const int step = dialog->property("tutorial_step").toInt();
        if (step < 6) { dialog->setProperty("tutorial_step", step + 1); dialog->refresh(); return; }
        QSettings preferences(QStringLiteral("KSword"), QStringLiteral("KeyboardNavigation"));
        preferences.setValue(QStringLiteral("tutorialVersion"), 1);
        preferences.sync();
        if (preferences.status() != QSettings::NoError)
        { feedback->setText(text("无法保存教程完成状态；下次可能再次显示。可按 Esc 关闭。")); return; }
        dialog->accept();
    });
    connect(close, &QPushButton::clicked, dialog, &QDialog::reject);
    auto* forward = new QShortcut(QKeySequence(Qt::Key_F8), dialog);
    auto* backward = new QShortcut(QKeySequence(Qt::SHIFT | Qt::Key_F8), dialog);
    connect(forward, &QShortcut::activated, next, &QPushButton::click);
    connect(backward, &QShortcut::activated, previous, &QPushButton::click);
    connect(dialog, &QDialog::finished, this, [this]() {
        m_tutorial.clear();
        QTimer::singleShot(0, this, [this]() { if (m_enabled) recoverFocus(); });
    });
    dialog->refresh();
    dialog->show();
    dialog->activateWindow();
    next->setFocus(Qt::TabFocusReason);
}
