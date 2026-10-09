// Exercise the production filter on real Qt widgets without starting KSword or its driver.
#include <QApplication>
#include <QScrollArea>
#include <QScrollBar>
#include <QTabBar>
#include <QTabWidget>
#include <QTest>
#include <QToolButton>
#include <QWheelEvent>
#include <iostream>
#include "../Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.h"

namespace {
int checks = 0, failures = 0;
void check(bool ok, const char* message) {
    ++checks;
    if (!ok) { ++failures; std::cerr << "FAIL " << message << '\n'; }
}
void wheel(QWidget* target, QPoint angle = {0, -120}, QPoint pixels = {},
    Qt::KeyboardModifiers modifiers = Qt::NoModifier, bool inverted = false) {
    const QPoint local = target->rect().center();
    QWheelEvent event(local, target->mapToGlobal(local), pixels, angle, Qt::NoButton,
        modifiers, Qt::NoScrollPhase, inverted);
    QApplication::sendEvent(target, &event);
    check(event.isAccepted(), "tab wheel remains consumed");
}
int start(QTabBar* bar) { return bar->tabRect(0).x(); }
void fill(QTabBar* bar) {
    for (int i = 0; i < 20; ++i) bar->addTab(QString("Tab %1 long title").arg(i));
}
void ordinaryTabs(bool smooth) {
    ks::ui::SetGlobalSmoothScrollingEnabled(smooth);
    qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
    QTabWidget widget;
    for (int i = 0; i < 20; ++i) widget.addTab(new QWidget, QString("Lazy page %1").arg(i));
    widget.resize(300, 120); widget.show(); QTest::qWait(30);
    QTabBar* bar = widget.tabBar();
    int changes = 0;
    QObject::connect(&widget, &QTabWidget::currentChanged, &widget, [&] { ++changes; });
    const int initial = start(bar);
    wheel(bar);
    if (smooth) {
        check(start(bar) == initial, "smooth wheel does not jump immediately");
        QTest::qWait(45);
        check(start(bar) < initial && start(bar) > initial - 48, "smooth wheel has an intermediate position");
    }
    QTest::qWait(200);
    check(start(bar) == initial - 48, "one notch moves 48 pixels");
    check(changes == 0 && widget.currentIndex() == 0, "scroll never loads another lazy tab");
    const int prior = start(bar);
    wheel(bar, {0, 120}); QTest::qWait(210);
    check(start(bar) > prior, "reverse wheel moves toward start");
    for (int i = 0; i < 10; ++i) wheel(bar, {0, -1});
    QTest::qWait(210);
    check(start(bar) == initial - 4, "high resolution angle deltas retain their fraction");
    wheel(bar, {}, {-17, 0}); QTest::qWait(130);
    check(start(bar) == initial - 21, "touchpad pixel delta remains exact");
    wheel(bar, {-120, 0}, {}, Qt::ShiftModifier); QTest::qWait(210);
    check(start(bar) == initial - 69, "horizontal shift wheel scrolls tabs");
    wheel(bar, {0, -120}, {}, Qt::ControlModifier); QTest::qWait(210);
    check(changes == 0, "Ctrl wheel cannot bypass the default tab guard");
    // Scroll events over close buttons must have the same behavior as the tab surface.
    bar->setTabsClosable(true); QTest::qWait(20);
    QWidget* close = bar->tabButton(0, QTabBar::RightSide);
    check(close != nullptr, "close button exists");
    if (close) {
        const int gap = close->x() - bar->tabRect(0).x();
        wheel(close); QTest::qWait(210);
        check(close->x() - bar->tabRect(0).x() == gap, "close buttons stay aligned while scrolling");
    }
    check(changes == 0, "wheel over child button does not switch pages");
    // Bound pending movement even under a burst, then stop on resize and explicit selection.
    const int burstStart = start(bar);
    for (int i = 0; i < 30; ++i) wheel(bar);
    QTest::qWait(210);
    if (smooth) check(burstStart - start(bar) <= bar->width(), "pending smooth movement is bounded to one viewport");
    wheel(bar); widget.resize(220, 120); QTest::qWait(20);
    const int resized = start(bar); QTest::qWait(210);
    check(start(bar) == resized, "resize stops the old animation");
    wheel(bar); bar->setCurrentIndex(3); QTest::qWait(20);
    const int selected = start(bar); QTest::qWait(210);
    check(start(bar) == selected, "selection stops pending animation");
    qApp->setProperty("ksword_slider_wheel_adjust_enabled", true);
    bar->setTabEnabled(4, false); bar->setTabVisible(5, false);
    wheel(bar); check(bar->currentIndex() == 6, "enabled setting switches and skips disabled/hidden tabs");
    qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
    wheel(bar); QTest::qWait(210);
    check(bar->currentIndex() == 6, "turning setting off restores scroll immediately");
    // No overflow still consumes the wheel, so the surrounding page cannot scroll.
    QTabBar shortBar; shortBar.addTab("One"); shortBar.addTab("Two");
    shortBar.resize(500, 35); shortBar.show(); QTest::qWait(20);
    wheel(&shortBar); QTest::qWait(210);
    check(shortBar.currentIndex() == 0, "no overflow does not switch tabs");
}
void scrollAreaTabs(bool smooth) {
    ks::ui::SetGlobalSmoothScrollingEnabled(smooth);
    QScrollArea area; area.setProperty("ksword_disable_smooth_scroll", true);
    area.setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    area.setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    auto* content = new QWidget; content->resize(1600, 35); area.setWidget(content);
    area.resize(300, 40); area.show(); QTest::qWait(25);
    const QPoint local = area.viewport()->rect().center();
    QWheelEvent event(local, area.viewport()->mapToGlobal(local), {}, {0, -120},
        Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
    ks::ui::ScrollTabStripWithWheel(&area, &event);
    if (smooth) {
        check(area.horizontalScrollBar()->value() == 0, "ADS path starts without a jump");
        QTest::qWait(45);
        check(area.horizontalScrollBar()->value() > 0 && area.horizontalScrollBar()->value() < 48,
            "ADS path moves through intermediate offsets");
    }
    QTest::qWait(210);
    check(area.horizontalScrollBar()->value() == 48, "ADS wheel uses the shared 48 pixel step");
    ks::ui::ScrollTabStripByPixels(&area, 100);
    if (smooth) check(area.horizontalScrollBar()->value() == 48, "ADS arrow restart does not jump or rewind");
    QTest::qWait(250);
    check(area.horizontalScrollBar()->value() == 148, "ADS navigation arrows also scroll");
    ks::ui::ScrollTabStripByPixels(&area, 100); ks::ui::StopTabStripScrolling(&area);
    const int stopped = area.horizontalScrollBar()->value(); QTest::qWait(210);
    check(area.horizontalScrollBar()->value() == stopped, "ADS selection cancels pending motion");
}
void lifecycleAndDirections() {
    ks::ui::SetGlobalSmoothScrollingEnabled(true);
    auto* bar = new QTabBar; fill(bar); bar->resize(240, 35); bar->show(); QTest::qWait(20);
    wheel(bar); delete bar; QTest::qWait(210);
    check(true, "destroying a scrolling tab bar is safe");
    QTabBar rtl; fill(&rtl); rtl.setLayoutDirection(Qt::RightToLeft); rtl.resize(240, 35);
    rtl.show(); QTest::qWait(20); const int first = start(&rtl);
    wheel(&rtl); QTest::qWait(210);
    check(start(&rtl) != first && rtl.currentIndex() == 0, "RTL tabs scroll without selecting");
    QTabBar vertical; vertical.setShape(QTabBar::RoundedWest); fill(&vertical);
    vertical.resize(35, 240); vertical.show(); QTest::qWait(20);
    const int before = vertical.tabRect(0).y(); wheel(&vertical); QTest::qWait(210);
    check(vertical.tabRect(0).y() == before - 48, "vertical tab strips retain their orientation");
    QTabBar toggle; fill(&toggle); toggle.resize(240, 35); toggle.show(); QTest::qWait(20);
    wheel(&toggle); QTest::qWait(40); ks::ui::SetGlobalSmoothScrollingEnabled(false);
    const int position = start(&toggle); QTest::qWait(210);
    check(start(&toggle) == position, "disabling smooth scrolling stops active motion");
    wheel(&toggle); check(start(&toggle) == position - 48, "disabled smooth still scrolls without switching");
    // Internal pixel frames must not bubble out of a strip that fits or reaches its edge.
    QScrollArea outer; auto* content = new QWidget; content->resize(400, 1500);
    auto* inner = new QTabBar(content); inner->addTab("One"); inner->addTab("Two"); inner->resize(300, 35);
    outer.setWidget(content); outer.resize(320, 200); outer.show(); QTest::qWait(30);
    ks::ui::SetGlobalSmoothScrollingEnabled(true);
    wheel(inner); QTest::qWait(210);
    check(outer.verticalScrollBar()->value() == 0, "internal animation frames do not scroll an enclosing page");
}
void styledTabs() {
    for (const char* style : {"Windows", "Fusion"}) {
        qApp->setStyle(style);
        QTabBar bar; fill(&bar); bar.resize(240, 35);
        bar.setStyleSheet("QTabBar::tab { padding: 4px 12px; color: white; background: #202020; }");
        bar.show(); QTest::qWait(30); const int before = start(&bar);
        wheel(&bar); QTest::qWait(210);
        check(start(&bar) == before - 48 && bar.currentIndex() == 0, "styled native tab bars scroll without switching");
    }
}
}
int main(int argc, char** argv) {
    QApplication app(argc, argv); app.setStyle("Fusion");
    ks::ui::InstallGlobalSmoothScrollSupport(&app);
    ordinaryTabs(true); ordinaryTabs(false);
    scrollAreaTabs(true); scrollAreaTabs(false); lifecycleAndDirections(); styledTabs();
    std::cout << "TAB_WHEEL_CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
