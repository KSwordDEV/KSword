#include <QApplication>
#include <QElapsedTimer>
#include <QMainWindow>
#include <QScrollBar>
#include <QTest>
#include <QToolButton>
#include <QWheelEvent>
#include <iostream>
#include "../Ksword5.1/Ksword5.1/include/ads/DockAreaTabBar.h"
#include "../Ksword5.1/Ksword5.1/include/ads/DockAreaTitleBar.h"
#include "../Ksword5.1/Ksword5.1/include/ads/DockAreaWidget.h"
#include "../Ksword5.1/Ksword5.1/include/ads/DockManager.h"
#include "../Ksword5.1/Ksword5.1/include/ads/DockWidget.h"
#include "../Ksword5.1/Ksword5.1/include/ads/DockWidgetTab.h"
#include "../Ksword5.1/Ksword5.1/UI/DockTabInteraction.h"
#include "../Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.h"
namespace {
int checks = 0, failures = 0;
void check(bool ok, const char* text) {
    ++checks; if (!ok) { ++failures; std::cerr << "FAIL " << text << '\n'; }
}
void waitForValue(QScrollBar* bar, int value) {
    QElapsedTimer timer; timer.start();
    while (bar->value() != value && timer.elapsed() < 1000)
        QTest::qWait(10);
}
void wheel(QWidget* widget, QPoint angle = {0, -120}, QPoint pixels = {}) {
    const QPoint local = widget->rect().center();
    QWheelEvent event(local, widget->mapToGlobal(local), pixels, angle,
        Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
    QApplication::sendEvent(widget, &event);
    check(event.isAccepted(), "ADS wheel is consumed");
}
void exercise(ads::CDockAreaWidget* area, bool smooth) {
    ks::ui::SetGlobalSmoothScrollingEnabled(smooth);
    qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
    auto* tabs = area->titleBar()->tabBar(); auto* bar = tabs->horizontalScrollBar();
    tabs->setCurrentIndex(0); QTest::qWait(30); bar->setValue(bar->minimum());
    check(bar->maximum() > 0, "real ADS tab strip overflows");
    int changed = 0;
    const auto connection = QObject::connect(tabs, &ads::CDockAreaTabBar::currentChanged,
        tabs, [&](int) { ++changed; });
    wheel(tabs->tab(0));
    if (smooth) {
        check(bar->value() == 0, "real ADS does not jump immediately"); QTest::qWait(45);
        check(bar->value() > 0 && bar->value() < 48, "real ADS has an intermediate animation position");
    }
    QTest::qWait(210);
    waitForValue(bar, 48);
    check(bar->value() == 48, "real ADS scrolls a single event exactly once");
    check(changed == 0 && tabs->currentIndex() == 0, "ADS scrolling never activates lazy pages");
    wheel(tabs->viewport(), {}, {-13, 0}); QTest::qWait(130);
    waitForValue(bar, 61);
    check(bar->value() == 61, "real ADS accepts touchpad pixel deltas");
    for (int i = 0; i < 10; ++i)
        wheel(tabs->tab(0), {0, -1});
    QTest::qWait(210);
    waitForValue(bar, 65);
    check(bar->value() == 65, "real ADS retains small angle increments");
    auto* right = area->titleBar()->findChild<QToolButton*>("ks_dock_scroll_right");
    check(right && right->isVisible(), "overflow arrows exist on the actual title bar");
    if (right) { right->click(); QTest::qWait(210); check(bar->value() > 65, "ADS arrow scrolls without selecting"); }
    bar->setValue(bar->maximum()); wheel(tabs->viewport()); QTest::qWait(210);
    check(bar->value() == bar->maximum() && changed == 0, "ADS edge never changes tab");
    qApp->setProperty("ksword_slider_wheel_adjust_enabled", true);
    wheel(tabs->viewport()); check(tabs->currentIndex() == 1, "ADS switching requires explicit enabled setting");
    qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
    wheel(tabs->viewport()); QTest::qWait(210);
    check(tabs->currentIndex() == 1, "ADS setting can be disabled immediately");
    QObject::disconnect(connection);
}
ads::CDockAreaWidget* addTabs(ads::CDockManager* manager, ads::CDockAreaWidget* area = nullptr) {
    static int serial = 0;
    for (int i = 0; i < 12; ++i) {
        auto* dock = new ads::CDockWidget(manager, QString("Dock %1 long name").arg(serial++));
        dock->setWidget(new QWidget);
        area = manager->addDockWidget(ads::CenterDockWidgetArea, dock, area);
    }
    return area;
}
}
int main(int argc, char** argv) {
    QApplication app(argc, argv); app.setStyle("Fusion");
    ks::ui::InstallGlobalSmoothScrollSupport(&app);
    ads::CDockManager::setConfigFlag(ads::CDockManager::DisableStylesheet, true);
    QMainWindow window; auto* manager = new ads::CDockManager(&window);
    auto* existing = addTabs(manager);
    ks::ui::installDockTabWheelScrolling(manager);
    ks::ui::installDockTabWheelScrolling(manager);
    window.resize(500, 250); window.show(); QTest::qWait(100);
    exercise(existing, true); exercise(existing, false);
    const QByteArray layout = manager->saveState();
    check(manager->restoreState(layout), "ADS saved layout restores"); QTest::qWait(100);
    exercise(manager->dockArea(0), true);
    auto* floatingDock = new ads::CDockWidget(manager, "Floating tab"); floatingDock->setWidget(new QWidget);
    manager->addDockWidgetFloating(floatingDock); QTest::qWait(50);
    auto* later = addTabs(manager, floatingDock->dockAreaWidget()); QTest::qWait(100);
    exercise(later, true);
    std::cout << "ADS_TAB_WHEEL_CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
