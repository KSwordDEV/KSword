#include "MouselessNavigation.h"
// Navigation/layout map: main title and active Dock branch -> shared region controller;
// Settings > Startup -> existing SecondaryPageLayout form; Welcome -> existing page root;
// first activation / F1 / Welcome guide -> inline toolbar on the main workspace.
// Navigation changes focus only; editing and business execution keep their own validation.
#include "./FlatButtonTheme.h"
#include "./NavigationHighlight.h"
#include "./FlowLayout.h"
#include "./PrimaryPageStyle.h"
#include "./ThemeBinding.h"
#include "./ToolbarMetrics.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include "../include/ads/DockAreaTabBar.h"
#include "../include/ads/DockAreaWidget.h"
#include "../include/ads/DockWidget.h"
#include "../include/ads/DockWidgetTab.h"

#include <QAbstractButton>
#include <QAbstractItemView>
#include <QAbstractSpinBox>
#include <QAbstractSlider>
#include <QApplication>
#include <QButtonGroup>
#include <QComboBox>
#include <QContextMenuEvent>
#include <QFocusFrame>
#include <QGroupBox>
#include <QHash>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPainter>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSettings>
#include <QSplitter>
#include <QTabBar>
#include <QTabWidget>
#include <QTextEdit>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>

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
        if (qobject_cast<QScrollBar*>(widget) || qobject_cast<QFocusFrame*>(widget)
            || qobject_cast<QSplitterHandle*>(widget)) return false;
        if (auto* radio = qobject_cast<QRadioButton*>(widget); radio && !radio->isChecked())
        {
            // An exclusive radio group is one Tab stop; arrows retain Qt's group navigation.
            const auto buttons = radio->group() ? radio->group()->buttons()
                : radio->parentWidget() ? radio->parentWidget()->findChildren<QAbstractButton*>(QString(), Qt::FindDirectChildrenOnly)
                : QList<QAbstractButton*>{};
            const bool exclusive = radio->group() ? radio->group()->exclusive() : radio->autoExclusive();
            if (exclusive)
                for (auto* other : buttons)
                    if (other != radio && qobject_cast<QRadioButton*>(other) && other->isChecked()
                        && other->isVisible() && other->isEnabled()) return false;
        }
        if (qobject_cast<QAbstractButton*>(widget) || qobject_cast<QTabBar*>(widget)
            || qobject_cast<ads::CDockAreaTabBar*>(widget) || qobject_cast<QAbstractItemView*>(widget)
            || qobject_cast<QAbstractSpinBox*>(widget) || qobject_cast<QComboBox*>(widget)
            || qobject_cast<QLineEdit*>(widget) || qobject_cast<QPlainTextEdit*>(widget)
            || qobject_cast<QTextEdit*>(widget) || qobject_cast<QAbstractSlider*>(widget)) return true;
        if (auto* group = qobject_cast<QGroupBox*>(widget)) return group->isCheckable();
        // Scroll hosts and form canvases are containers, even when they have StrongFocus.
        // Including them makes their children appear to belong to the same earlier stop.
        if (qobject_cast<QScrollArea*>(widget) || widget->layout() || widget->focusProxy()) return false;
        return (widget->focusPolicy() & Qt::TabFocus) != 0;
    }

    QWidget* regionFor(QWidget* control, QWidget* window)
    {
        // Explicit workspace panels take precedence over their internal groups and viewports.
        for (QWidget* item = control; item && item != window; item = item->parentWidget())
            if (item->property(regionProperty).toBool() || item->property("ksword_secondary_footer").toBool())
                return item;
        for (QWidget* item = control; item && item != window; item = item->parentWidget())
        {
            if (qobject_cast<QGroupBox*>(item) || qobject_cast<QTabBar*>(item) || qobject_cast<ads::CDockAreaTabBar*>(item)
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
        return text("页面操作");
    }

    int focusDistance(QWidget* control, QWidget* focus)
    {
        int distance = 0;
        for (QWidget* item = focus; item; item = item->parentWidget(), ++distance)
        {
            if (item == control || (control && item == control->focusProxy())) return distance;
            if (item->isWindow()) break;
        }
        return -1;
    }

    QWidget* keyboardActionTarget(QWidget* focus)
    {
        for (QWidget* item = focus; item && !item->isWindow(); item = item->parentWidget())
        {
            if (qobject_cast<ads::CDockAreaTabBar*>(item) || qobject_cast<QTabBar*>(item)) return item;
            if (auto* view = qobject_cast<QAbstractItemView*>(item))
                return focus == view->viewport() ? view : focus; // A live cell editor keeps its own keys.
        }
        return focus;
    }

    int regionOrder(QWidget* anchor)
    {
        const QVariant declared = anchor->property("ksword_keyboard_region_order");
        if (declared.isValid()) return declared.toInt();
        if (qobject_cast<ads::CDockAreaTabBar*>(anchor)) return 40;
        if (qobject_cast<QTabBar*>(anchor)) return 60;
        return 100;
    }

}

ks::ui::MouselessNavigation::MouselessNavigation(QWidget* mainWindow, QWidget* tutorialHost,
    QVBoxLayout* tutorialLayout, QWidget* workspace,
    std::function<void(bool)> modeChanged, std::function<void()> dismissTransientPanels)
    : QObject(mainWindow), m_mainWindow(mainWindow), m_tutorialHost(tutorialHost),
      m_tutorialLayout(tutorialLayout), m_workspace(workspace), m_modeChanged(std::move(modeChanged)),
      m_dismissTransientPanels(std::move(dismissTransientPanels))
{
    m_clock.start();
    qApp->installEventFilter(this);
    qApp->installNativeEventFilter(this);
    connect(qApp, &QApplication::focusChanged, this, [this](QWidget*, QWidget* focus) {
        if (m_tutorial && focus && focus->window() == m_mainWindow
            && focus != m_tutorial && !m_tutorial->isAncestorOf(focus)) m_tutorialReturnFocus = focus;
        if (m_enabled) updateFocusFrame();
        if (m_enabled && m_navigationFocusAnchor && focusDistance(m_navigationFocusAnchor, focus) < 0)
            queueNavigationFocusRestore();
    });
}

ks::ui::MouselessNavigation::~MouselessNavigation()
{
    qApp->removeNativeEventFilter(this);
    qApp->removeEventFilter(this);
    disconnect(qApp, nullptr, this, nullptr);
    qApp->setProperty(modeProperty, false);
    restoreFocusPolicies();
    delete m_tutorial.data();
    delete m_regionHighlight.data();
    delete m_tipOverlay.data();
    delete m_focusFrame.data();
}

void ks::ui::MouselessNavigation::setEnabled(bool enabled)
{
    if (m_enabled == enabled) return;
    m_enabled = enabled;
    ++m_inputRevision;
    m_navigationFocusAnchor.clear();
    if (!enabled) { delete m_regionHighlight.data(); m_regionHighlight.clear(); }
    qApp->setProperty(modeProperty, enabled);
    hideKeyTips();
    if (m_modeChanged) m_modeChanged(enabled);
    if (!enabled && m_tutorial) closeTutorial();
    if (!enabled) restoreFocusPolicies();
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
    // Shared landmarks define the main reading order. Bucket nearby tops into the
    // same text row so a 1px alignment difference cannot put window controls first.
    std::stable_sort(result.begin(), result.end(), [window](const Region& left, const Region& right) {
        if (regionOrder(left.anchor) != regionOrder(right.anchor))
            return regionOrder(left.anchor) < regionOrder(right.anchor);
        const QPoint a = left.anchor->mapTo(window, QPoint());
        const QPoint b = right.anchor->mapTo(window, QPoint());
        const int rowHeight = qMax(1, window->fontMetrics().height() * 2);
        if (a.y() / rowHeight != b.y() / rowHeight) return a.y() / rowHeight < b.y() / rowHeight;
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
    int best = -1;
    int nearest = std::numeric_limits<int>::max();
    for (int index = 0; index < items.size(); ++index)
        for (const auto& control : items[index].controls)
        {
            const int distance = control ? focusDistance(control, focus) : -1;
            if (distance >= 0 && distance < nearest) { best = index; nearest = distance; }
        }
    return best;
}

bool ks::ui::MouselessNavigation::focusControl(QWidget* control)
{
    if (!control || !control->isVisible() || !control->isEnabled()
        || control->window() != navigationWindow()) return false;
    const QPointer<QWidget> alive(control);
    const QPointer<MouselessNavigation> owner(this);
    QPointer<QWidget> focusTarget(control);
    for (int hop = 0; hop < 32 && focusTarget->focusProxy(); ++hop)
    {
        if (focusTarget->focusProxy() == focusTarget) break;
        focusTarget = focusTarget->focusProxy();
    }
    if (focusTarget->focusPolicy() == Qt::NoFocus)
    {
        m_focusPolicyChanges.append({focusTarget, Qt::NoFocus});
        focusTarget->setFocusPolicy(Qt::StrongFocus);
        if (!alive || !owner || !focusTarget) return false;
    }
    QVector<QPointer<QScrollArea>> scrolls;
    for (QWidget* parent = control->parentWidget(); parent && !parent->isWindow(); parent = parent->parentWidget())
        if (auto* scroll = qobject_cast<QScrollArea*>(parent)) scrolls.append(scroll);
    focusTarget->setFocus(Qt::TabFocusReason);
    if (!alive || !owner || !focusTarget) return false;
    if (focusDistance(alive, QApplication::focusWidget()) < 0
        && focusDistance(focusTarget, QApplication::focusWidget()) < 0) return false;
    for (const auto& scroll : scrolls)
    {
        if (scroll) scroll->ensureWidgetVisible(alive, 8, 8);
        if (!alive || !owner) return false;
    }
    if (auto* view = qobject_cast<QAbstractItemView*>(control); view && view->model())
    {
        // Focus navigation does not create or replace the user's selection.
        if (view->currentIndex().isValid()) view->scrollTo(view->currentIndex());
    }
    if (owner) updateFocusFrame();
    return owner && alive && (focusDistance(alive, QApplication::focusWidget()) >= 0
        || (focusTarget && focusDistance(focusTarget, QApplication::focusWidget()) >= 0));
}

void ks::ui::MouselessNavigation::restoreFocusPolicies()
{
    for (const auto& change : m_focusPolicyChanges)
        if (change.widget && change.widget->focusPolicy() == Qt::StrongFocus)
            change.widget->setFocusPolicy(change.original);
    m_focusPolicyChanges.clear();
    m_regionFocus.clear();
}

bool ks::ui::MouselessNavigation::focusRegion(const Region& region, bool backwards)
{
    for (const auto& remembered : m_regionFocus)
        if (remembered.anchor == region.anchor && remembered.control
            && (remembered.control == region.anchor || region.anchor->isAncestorOf(remembered.control))
            && focusControl(remembered.control)) return true;
    for (int offset = 0; offset < region.controls.size(); ++offset)
    {
        const int index = backwards ? static_cast<int>(region.controls.size()) - 1 - offset : offset;
        if (focusControl(region.controls[index])) return true;
    }
    return false;
}

void ks::ui::MouselessNavigation::moveFocus(bool backwards, bool byRegion)
{
    const QPointer<MouselessNavigation> owner(this);
    hideKeyTips();
    if (auto* popup = QApplication::activePopupWidget()) popup->close();
    if (!owner) return;
    const auto items = regions(navigationWindow());
    if (items.isEmpty()) return;
    const QPointer<QWidget> focus(QApplication::focusWidget());
    const int current = currentRegion(items, focus);
    m_regionFocus.erase(std::remove_if(m_regionFocus.begin(), m_regionFocus.end(),
        [](const RegionFocus& item) { return !item.anchor || !item.control; }), m_regionFocus.end());
    if (current >= 0)
    {
        auto found = std::find_if(m_regionFocus.begin(), m_regionFocus.end(),
            [&items, current](const RegionFocus& item) { return item.anchor == items[current].anchor; });
        if (found == m_regionFocus.end()) m_regionFocus.append({items[current].anchor, focus});
        else found->control = focus;
    }
    if (byRegion)
    {
        int index = current;
        for (int tried = 0; tried < items.size(); ++tried)
        {
            index = MouselessNextIndex(index, static_cast<int>(items.size()), backwards);
            const bool received = focusRegion(items[index], backwards);
            if (!owner) return;
            if (received && QApplication::focusWidget() != focus)
            {
                highlightRegion(items[index].anchor);
                return;
            }
        }
        return;
    }
    // Tab visits real controls continuously, including across region boundaries.
    QVector<QPointer<QWidget>> controls;
    for (const auto& item : items) controls += item.controls;
    int index = -1;
    int nearest = std::numeric_limits<int>::max();
    for (int i = 0; i < controls.size(); ++i)
    {
        const int distance = controls[i] ? focusDistance(controls[i], focus) : -1;
        if (distance >= 0 && distance < nearest) { index = i; nearest = distance; }
    }
    for (int tried = 0; tried < controls.size(); ++tried)
    {
        index = MouselessNextIndex(index, static_cast<int>(controls.size()), backwards);
        const bool received = focusControl(controls[index]);
        if (!owner) return;
        if (received && QApplication::focusWidget() != focus) return;
    }
}

void ks::ui::MouselessNavigation::recoverFocus()
{
    hideKeyTips();
    if (auto* popup = QApplication::activePopupWidget()) popup->close();
    if (navigationWindow() == m_mainWindow && m_dismissTransientPanels) m_dismissTransientPanels();
    const auto items = regions(navigationWindow());
    for (const auto& item : items)
        if (focusRegion(item)) { highlightRegion(item.anchor); break; }
}

void ks::ui::MouselessNavigation::highlightRegion(QWidget* anchor)
{
    delete m_regionHighlight.data();
    m_regionHighlight = FlashNavigationTarget(anchor);
}

void ks::ui::MouselessNavigation::rememberNavigationFocus(QWidget* anchor, int tabIndex)
{
    m_navigationFocusAnchor = anchor;
    m_navigationTabIndex = tabIndex;
    m_navigationInputRevision = m_inputRevision;
    queueNavigationFocusRestore();
}

void ks::ui::MouselessNavigation::queueNavigationFocusRestore()
{
    if (!m_navigationFocusAnchor || m_navigationRestoreQueued) return;
    m_navigationRestoreQueued = true;
    QTimer::singleShot(0, this, [this]() {
        m_navigationRestoreQueued = false;
        const QPointer<QWidget> anchor = m_navigationFocusAnchor;
        if (!anchor || !m_enabled || m_navigationInputRevision != m_inputRevision
            || anchor->window() != navigationWindow() || QApplication::activePopupWidget()) return;
        const auto* tabs = qobject_cast<QTabBar*>(anchor.data());
        const auto* docks = qobject_cast<ads::CDockAreaTabBar*>(anchor.data());
        const int current = tabs ? tabs->currentIndex() : docks ? docks->currentIndex() : -1;
        if (current != m_navigationTabIndex) { m_navigationFocusAnchor.clear(); return; }
        if (focusDistance(anchor, QApplication::focusWidget()) < 0) focusControl(anchor);
    });
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
    QWidget* actionTarget = keyboardActionTarget(focus);
    if (qobject_cast<QTabBar*>(actionTarget))
    {
        // QTabBar already paints the focused tab. Do not outline its whole empty strip.
        if (m_focusFrame) m_focusFrame->hide();
        actionTarget->update();
        return;
    }
    if (auto* bar = qobject_cast<ads::CDockAreaTabBar*>(actionTarget);
        bar && bar->currentIndex() >= 0 && bar->currentIndex() < bar->count())
        if (auto* current = bar->tab(bar->currentIndex())) focus = current;
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
        else position = QPoint(-1, -1); // No current row means a background menu, never an arbitrary row.
    }
    QContextMenuEvent menu(QContextMenuEvent::Keyboard, position, target->mapToGlobal(position));
    QApplication::sendEvent(target, &menu);
    return true;
}

bool ks::ui::MouselessNavigation::activateControl(QWidget* focus, QKeyEvent* key)
{
    if (!focus) return false;
    const bool enter = key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter;
    if (key->modifiers().testFlag(Qt::ControlModifier)) return false;
    if (auto* bar = qobject_cast<QTabBar*>(focus))
    {
        const auto shape = bar->shape();
        const bool vertical = shape == QTabBar::RoundedWest || shape == QTabBar::RoundedEast
            || shape == QTabBar::TriangularWest || shape == QTabBar::TriangularEast;
        const bool nextKey = key->key() == Qt::Key_Right || (vertical && key->key() == Qt::Key_Down);
        const bool previousKey = key->key() == Qt::Key_Left || (vertical && key->key() == Qt::Key_Up);
        if (!nextKey && !previousKey && key->key() != Qt::Key_Home && key->key() != Qt::Key_End) return false;
        const bool edge = key->key() == Qt::Key_Home || key->key() == Qt::Key_End;
        const bool backwards = edge ? key->key() == Qt::Key_End
            : previousKey != (!vertical && bar->layoutDirection() == Qt::RightToLeft);
        int index = edge ? -1 : bar->currentIndex();
        for (int tried = 0; tried < bar->count(); ++tried)
        {
            index = MouselessNextIndex(index, bar->count(), backwards);
            if (!bar->isTabVisible(index) || !bar->isTabEnabled(index)) continue;
            const QPointer<QTabBar> alive(bar);
            const QPointer<MouselessNavigation> owner(this);
            bar->setCurrentIndex(index);
            if (alive && owner)
            {
                rememberNavigationFocus(alive, index);
                focusControl(alive);
            }
            return true;
        }
        return true;
    }
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
            const QPointer<MouselessNavigation> owner(this);
            if (auto* area = tab->dockWidget()->dockAreaWidget()) area->setCurrentIndex(current);
            if (alive && owner)
            {
                rememberNavigationFocus(alive, current);
                focusControl(alive);
            }
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
    if (type == QEvent::KeyPress || type == QEvent::MouseButtonPress
        || type == QEvent::MouseButtonDblClick || type == QEvent::Wheel
        || type == QEvent::WindowDeactivate || type == QEvent::ApplicationDeactivate)
    {
        ++m_inputRevision;
        m_navigationFocusAnchor.clear(); // Never pull focus back after a new user action or modal/window switch.
    }
    if (type == QEvent::ApplicationDeactivate)
    {
        m_gesture.reset();
        m_altHeld = false;
        delete m_regionHighlight.data();
        m_regionHighlight.clear();
        hideKeyTips();
        updateFocusFrame();
        return false;
    }
    if (object == m_mainWindow && (type == QEvent::Show || type == QEvent::WindowActivate)) offerFirstTutorial();
    if (!m_enabled) return false;
    if (type == QEvent::ApplicationActivate) updateFocusFrame();
    if (type == QEvent::LanguageChange && m_tutorial && object == m_tutorial && m_renderTutorial)
        m_renderTutorial();
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
    const bool tab = (key->key() == Qt::Key_Tab || key->key() == Qt::Key_Backtab) && !control && !alt && !meta;
    const bool recovery = key->key() == Qt::Key_Home && control && alt && !meta;
    const bool tipsDigit = m_tipOverlay && key->key() >= Qt::Key_0 && key->key() <= Qt::Key_9 && !control && !meta;
    const bool altKey = key->key() == Qt::Key_Alt && !control && !shift && !meta;
    QWidget* focus = QApplication::focusWidget();
    const bool nativePopup = QApplication::activePopupWidget() != nullptr;
    QWidget* actionTarget = keyboardActionTarget(focus);
    const bool enter = key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter;
    const bool navigationKey = key->key() == Qt::Key_Left || key->key() == Qt::Key_Right
        || key->key() == Qt::Key_Up || key->key() == Qt::Key_Down
        || key->key() == Qt::Key_Home || key->key() == Qt::Key_End;
    const bool activation = plain && !shift && !nativePopup && actionTarget
        && ((enter && (qobject_cast<QAbstractButton*>(actionTarget) || qobject_cast<QComboBox*>(actionTarget)))
            || (navigationKey && (qobject_cast<QTabBar*>(actionTarget) || qobject_cast<ads::CDockAreaTabBar*>(actionTarget))));
    const bool menuKey = key->key() == Qt::Key_Menu
        || (key->key() == Qt::Key_F10 && shift && !control && !alt && !meta);
    const bool onMainWindow = navigationWindow() == m_mainWindow && !nativePopup;
    const bool help = key->key() == Qt::Key_F1 && plain && onMainWindow;
    const bool tutorialStep = key->key() == Qt::Key_F8 && plain && onMainWindow && m_tutorial;
    const bool f6 = key->key() == Qt::Key_F6 && plain;
    const bool searchScope = control && alt && !meta && key->key() == Qt::Key_S && focus
        && focus->property("ksword_mouseless_search_input").toBool();
    if (type == QEvent::ShortcutOverride)
    {
        if ((tab && !nativePopup) || recovery || tipsDigit || altKey || activation || menuKey || help || tutorialStep || f6 || searchScope
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
    if (tutorialStep) { if (!key->isAutoRepeat()) advanceTutorial(shift ? -1 : 1); return true; }
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
            const Region target = selected >= 0 && selected < m_tipRegions.size() ? m_tipRegions[selected] : Region{};
            hideKeyTips();
            m_tipUsed = true;
            if (target.anchor && focusRegion(target)) highlightRegion(target.anchor);
        }
        else
        {
            static_cast<KeyTipsOverlay*>(m_tipOverlay.data())->prefix = m_tipPrefix;
            m_tipOverlay->update();
        }
        return true;
    }
    if (m_tipOverlay && key->key() == Qt::Key_Escape) { hideKeyTips(); return true; }
    if ((tab && !nativePopup) || f6)
    {
        moveFocus(shift || key->key() == Qt::Key_Backtab, f6);
        return true;
    }
    if (m_tipOverlay) hideKeyTips();
    if (menuKey && !nativePopup) return contextMenu(actionTarget);
    if (plain && !shift && !nativePopup) return activateControl(actionTarget, key);
    return false;
}

void ks::ui::MouselessNavigation::offerFirstTutorial()
{
    if (!m_enabled || m_tutorialOffered || m_firstTutorialQueued || !m_mainWindow || !m_mainWindow->isVisible()) return;
    QSettings preferences(QStringLiteral("KSword"), QStringLiteral("KeyboardNavigation"));
    if (preferences.value(QStringLiteral("tutorialVersion"), 0).toInt() >= 2) return;
    m_firstTutorialQueued = true;
    QTimer::singleShot(0, this, [this]() {
        m_firstTutorialQueued = false;
        if (!m_enabled || !m_mainWindow || !m_mainWindow->isVisible()) return;
        showTutorial();
    });
}

void ks::ui::MouselessNavigation::showTutorial()
{
    if (!m_mainWindow || !m_tutorialHost || !m_tutorialLayout || !m_workspace
        || !m_mainWindow->isVisible() || QApplication::activeModalWidget()) return;
    m_tutorialOffered = true;
    setEnabled(true);
    hideKeyTips();
    if (m_tutorial) return;

    m_tutorialReturnFocus = QApplication::focusWidget();
    m_tutorialStep = 0;
    // A normal child in the existing root layout: no new HWND, modal loop or fake practice UI.
    auto* host = new QWidget(m_tutorialHost);
    m_tutorial = host;
    host->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);
    auto* envelope = new QVBoxLayout(host);
    envelope->setContentsMargins(6, 6, 6, 6);
    envelope->setSpacing(0);
    auto* panel = new QWidget(host);
    panel->setProperty(regionProperty, true);
    panel->setProperty("ksword_keyboard_region_name", QStringLiteral("键盘引导"));
    panel->setProperty("ksword_keyboard_region_order", 35);
    StylePrimaryToolbar(panel);
    QFont readable = panel->font();
    if (readable.pixelSize() > 0) readable.setPixelSize(qMax(14, readable.pixelSize()));
    else readable.setPointSizeF(qMax(10.0, readable.pointSizeF()));
    panel->setFont(readable);
    envelope->addWidget(panel);
    auto* content = new QVBoxLayout(panel);
    content->setContentsMargins(16, 10, 16, 10);
    content->setSpacing(8);
    auto* heading = new QLabel(panel);
    auto* explanation = new QLabel(panel);
    auto* hint = new QLabel(panel);
    auto* status = new QLabel(panel);
    m_tutorialStatus = status;
    for (QLabel* label : {heading, explanation, hint, status})
    {
        label->setWordWrap(true);
        label->setTextFormat(Qt::PlainText);
        label->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    }
    StylePrimarySectionTitle(heading);
    content->addWidget(heading);
    content->addWidget(explanation);
    auto* actions = new FlowLayout(nullptr, 0, 8, 8);
    auto* previous = new QPushButton(panel);
    auto* next = new QPushButton(panel);
    auto* locate = new QPushButton(panel);
    auto* close = new QPushButton(panel);
    actions->addWidget(previous);
    actions->addWidget(next);
    actions->addWidget(locate);
    actions->addWidget(close);
    NormalizeToolbarLayout(actions);
    ApplyFlatButtonTheme(next, FlatButtonTone::Accent, FlatButtonAppearance::Solid);
    content->addLayout(actions);
    content->addWidget(hint);
    content->addWidget(status);
    status->hide();

    const QPointer<QWidget> alive(host);
    m_renderTutorial = [this, alive, panel, heading, explanation, hint, previous, next, locate, close]() {
        if (!alive) return;
        const QStringList lessons{
            text("1. 在当前页面开始\n引导就在主窗口中，下方是真实页面。焦点框标出现在接收按键的控件；阅读本步后可直接练习。按住 Ctrl 连按两次 Alt，或同时按 Ctrl、左 Alt 和右 Alt，均可进入或退出无鼠标模式。"),
            text("2. Tab 逐个移动\nTab 访问下一个控件，Shift+Tab 返回上一个；走到分区末尾会自然进入下一区域，不会停在标签栏里循环。试着从输入框移动到按钮，再按 Shift+Tab 返回。导航只改变焦点，不会替你按下按钮。"),
            text("3. F6 快速跨区\nF6 跳到下一个分区，Shift+F6 反向跳转；到达的整个分区会短暂高亮，控件焦点框继续保留。返回分区时尽量保留上次焦点。Alt 显示直达编号，输入完整编号即可跳转（包含前导零）；Esc 关闭编号。输入框里也能直接跳出去。"),
            text("4. 切换主功能与页面\n先用 F6 或 Alt 编号到主功能导航、页面标签栏，再用左右方向键切换标签；竖排标签也支持上下方向键。选好页面后按 Tab 进入下一个控件。Ctrl+Tab / Ctrl+Shift+Tab 保留页面本来的页签切换行为。"),
            text("5. 输入与按钮\n普通输入框直接打字；Enter 使用当前控件的默认动作，Space 勾选复选框，Alt+下方向键展开下拉框。可定位顶部“选项”，按 Enter 打开菜单，再按 Esc 返回。顶部搜索用 Ctrl+Alt+S 切范围 / CMD，加 Shift 反向；Tab 不切换搜索类型。"),
            text("6. 选择、双击与右键菜单\n方向键只移动选择；Enter 执行当前项的默认动作，相当于该项的鼠标双击。例如进程列表中，Enter 展开 / 收起应用分组，选中真实进程则打开详情。Ctrl/Shift 多选保持不变，不需要另外按“双击键”。Shift+F10 或菜单键打开右键菜单，Esc 返回；练习时只打开和关闭菜单，不执行修改或删除。"),
            text("7. 返回与完成\n迷失焦点时按 Ctrl+Alt+Home 回到当前窗口起点；菜单或对话框内先用 Esc 返回。主窗口按 F1 可再次查看引导。无鼠标模式下 Tab 用于焦点导航；需要 Tab 缩进时可临时退出模式。系统原生选择器及外部程序沿用自身键盘规则。完成后可收起引导继续使用。")
        };
        panel->setAccessibleName(text("键盘引导"));
        heading->setText(text("无鼠标模式 · 第 %1 / 7 步").arg(m_tutorialStep + 1));
        explanation->setText(lessons[m_tutorialStep]);
        previous->setText(text("上一步"));
        previous->setEnabled(m_tutorialStep > 0);
        next->setText(m_tutorialStep == 6 ? text("完成教程") : text("下一步"));
        locate->setText(text("定位练习位置"));
        close->setText(text("稍后再学"));
        hint->setText(text("F8 下一步 · Shift+F8 上一步 · 定位练习位置只移动焦点；当前页面和输入内容保留。"));
    };
    connect(previous, &QPushButton::clicked, this, [this]() { advanceTutorial(-1); });
    connect(next, &QPushButton::clicked, this, [this]() { advanceTutorial(1); });
    connect(locate, &QPushButton::clicked, this, &MouselessNavigation::locateTutorialTarget);
    connect(close, &QPushButton::clicked, this, &MouselessNavigation::closeTutorial);
    m_renderTutorial();
    const int beforeWorkspace = m_tutorialLayout->indexOf(m_workspace);
    m_tutorialLayout->insertWidget(beforeWorkspace >= 0 ? beforeWorkspace : 1, host, 0);
    PrepareWidgetThemeBindingsForShow(host);
    host->show();
    // Keep the user's real page, caret, selection and focus; the tutorial does not activate a window.
}

void ks::ui::MouselessNavigation::advanceTutorial(int direction)
{
    if (!m_tutorial) return;
    if (direction < 0 || m_tutorialStep < 6)
    {
        m_tutorialStep = std::clamp(m_tutorialStep + direction, 0, 6);
        if (m_tutorialStatus) m_tutorialStatus->hide();
        if (m_renderTutorial) m_renderTutorial();
        return;
    }
    QSettings preferences(QStringLiteral("KSword"), QStringLiteral("KeyboardNavigation"));
    preferences.setValue(QStringLiteral("tutorialVersion"), 2);
    preferences.sync();
    if (preferences.status() != QSettings::NoError)
    {
        if (m_tutorialStatus)
        {
            m_tutorialStatus->setText(text("无法保存教程完成状态；下次可能再次显示。可选择“稍后再学”收起引导。"));
            m_tutorialStatus->show();
        }
        return;
    }
    closeTutorial();
}

void ks::ui::MouselessNavigation::closeTutorial()
{
    if (!m_tutorial) return;
    hideKeyTips();
    QWidget* focus = QApplication::focusWidget();
    const bool returnToPage = focus && (focus == m_tutorial || m_tutorial->isAncestorOf(focus));
    const QPointer<QWidget> previous = m_tutorialReturnFocus;
    auto* host = m_tutorial.data();
    m_tutorial.clear();
    m_tutorialStatus.clear();
    m_tutorialReturnFocus.clear();
    m_renderTutorial = {};
    host->hide();
    host->deleteLater();
    if (returnToPage)
    {
        if (!previous || !focusControl(previous)) recoverFocus();
    }
}

void ks::ui::MouselessNavigation::locateTutorialTarget()
{
    if (!m_tutorial || !m_workspace || navigationWindow() != m_mainWindow) return;
    const auto items = regions(m_mainWindow);
    QPointer<QWidget> target;
    for (const auto& region : items)
    {
        if (!region.anchor || m_tutorial->isAncestorOf(region.anchor)) continue;
        for (const auto& control : region.controls)
        {
            if (!control) continue;
            if ((m_tutorialStep == 0 || m_tutorialStep == 3 || m_tutorialStep == 6)
                && qobject_cast<ads::CDockAreaTabBar*>(control)) target = control;
            else if (m_tutorialStep == 1 && m_workspace->isAncestorOf(control)
                && (qobject_cast<QLineEdit*>(control) || qobject_cast<QComboBox*>(control))) target = control;
            else if (m_tutorialStep == 2 && control->property("ksword_mouseless_search_input").toBool()) target = control;
            else if (m_tutorialStep == 4 && control->objectName() == QStringLiteral("ksOptionsMenuButton")) target = control;
            else if (m_tutorialStep == 5 && qobject_cast<QAbstractItemView*>(control)) target = control;
            if (target) break;
        }
        if (target) break;
    }
    if (!target && m_tutorialReturnFocus && m_tutorialReturnFocus->isVisible()) target = m_tutorialReturnFocus;
    if (target && focusControl(target))
    {
        const int region = currentRegion(items, target);
        if (region >= 0) highlightRegion(items[region].anchor);
        if (m_tutorialStatus)
        {
            m_tutorialStatus->setText(text("焦点已移到真实页面。按本步提示操作，完成后按 F8 继续。"));
            m_tutorialStatus->show();
        }
    }
}
