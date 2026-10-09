#pragma once
#include <QString>
#include <qstring.h>

// QSS_MainWindow_TabWidget 作用：
// - 统一项目内所有 QTabWidget / QTabBar 的基础样式；
// - 避免使用白底默认样式，保证深浅色都由调色板接管；
// - 不设置 font-size，让 Tab 栏继承 Qt 默认应用字号。
const QString QSS_MainWindow_TabWidget = R"(
    QTabWidget::pane {
        border: none;
        background-color: transparent;
        top: 0px;
    }

    QTabBar {
        background-color: palette(window);
        border: none;
    }

    QTabBar::tab {
        background-color: palette(alternate-base);
        color: palette(text);
        padding: 3px 12px;
        margin: 0px;
        min-height: 24px;
        border: none;
        border-radius: 0px;
    }

    QTabBar::tab:left,
    QTabBar::tab:right {
        padding: 5px 6px;
    }

    QTabBar::tab:selected {
        background-color: palette(highlight);
        color: palette(highlighted-text);
        font-weight: 700;
    }

    QTabBar::tab:selected:hover,
    QTabBar::tab:selected:pressed {
        background-color: palette(highlight) !important;
        background: palette(highlight) !important;
        color: palette(highlighted-text);
    }

    QTabBar::tab:hover:!selected,
    QTabBar::tab:pressed:!selected {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
    }
)";

// QSS_MainWindow_dockStyle 作用：
// - 统一主窗口 Dock 区域、ADS 停靠系统、滚动条的样式；
// - 强制当前选中 Tab 使用主题色背景 + 白字，解决白底黑字残留问题；
// - 不设置 font-size，让 Dock 栏和内部 Tab 栏继承 Qt 默认应用字号。
const QString QSS_MainWindow_dockStyle = R"(
    QDockWidget {
        border: none;
        margin: 1px;
        background-color: palette(window);
        color: palette(text);
    }

    QDockWidget::title {
        background-color: palette(window);
        color: palette(text);
        padding: 6px 10px;
        border-bottom: none;
    }

    QDockWidget > QWidget {
        background-color: palette(base);
        color: palette(text);
        border: none;
    }

    QMainWindow QTabBar {
        background-color: palette(window);
        border: none;
    }

    QMainWindow QTabBar::tab {
        background-color: palette(alternate-base);
        color: palette(text);
        border: none;
        border-radius: 0px;
        padding: 3px 12px;
        margin: 0px;
        min-height: 22px;
    }

    QMainWindow QTabBar::tab:left,
    QMainWindow QTabBar::tab:right {
        padding: 5px 6px;
    }

    QMainWindow QTabBar::tab:selected {
        background-color: palette(highlight);
        color: palette(highlighted-text);
        font-weight: 700;
    }

    QMainWindow QTabBar::tab:selected:hover,
    QMainWindow QTabBar::tab:selected:pressed {
        background-color: palette(highlight) !important;
        background: palette(highlight) !important;
        color: palette(highlighted-text);
    }

    QMainWindow QTabBar::tab:hover:!selected,
    QMainWindow QTabBar::tab:pressed:!selected {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
    }

    ads--CDockManager,
    ads--CDockContainerWidget,
    ads--CDockAreaWidget,
    ads--CDockAreaTitleBar,
    ads--CFloatingDockContainer {
        background-color: palette(window);
        color: palette(text);
    }

    ads--CDockAreaTabBar {
        background-color: palette(window);
        border: none;
        padding: 0px;
    }

    ads--CDockWidgetTab,
    ads--CAutoHideTab {
        background-color: palette(alternate-base);
        color: palette(text);
        border: none;
        border-radius: 0px;
        padding: 3px 12px;
        min-height: 24px;
    }

    ads--CDockWidgetTab QLabel,
    ads--CAutoHideTab QLabel {
        color: palette(text);
    }

    ads--CDockWidgetTab[activeTab="true"],
    ads--CAutoHideTab[activeTab="true"] {
        background-color: palette(highlight);
        background: palette(highlight);
        color: palette(highlighted-text);
    }

    ads--CDockWidgetTab[activeTab="true"] QLabel,
    ads--CAutoHideTab[activeTab="true"] QLabel {
        color: palette(highlighted-text);
        font-weight: 600;
    }

    ads--CDockWidgetTab:hover,
    ads--CDockWidgetTab[activeTab="true"]:hover,
    ads--CDockWidgetTab[kswordDockTab="true"]:hover,
    ads--CAutoHideTab:hover {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
        border: none !important;
    }

    ads--CDockWidgetTab:hover QLabel,
    ads--CDockWidgetTab:hover QWidget,
    ads--CDockWidgetTab[kswordDockTab="true"]:hover QLabel,
    ads--CDockWidgetTab[kswordDockTab="true"]:hover QWidget,
    ads--CAutoHideTab:hover QLabel,
    ads--CAutoHideTab:hover QWidget {
        background-color: palette(alternate-base) !important;
        background: palette(alternate-base) !important;
        color: palette(text);
    }

    ads--CDockAreaTitleBar QToolButton,
    ads--CDockAreaTitleBar QPushButton {
        background-color: transparent;
        color: palette(text);
        border: none;
        border-radius: 1px;
    }

    ads--CDockAreaTitleBar QToolButton:hover,
    ads--CDockAreaTitleBar QPushButton:hover {
        background-color: palette(highlight);
        color: palette(highlighted-text);
        border-color: palette(highlight);
    }

    QTableCornerButton::section {
        background-color: transparent;
        border: none;
    }
)";

// QSS_Buttons_Light 作用：
// - 欢迎页等浅色场景统一按钮风格；
// - 默认和悬停都不使用白色背景，避免高亮发白。
const QString QSS_Buttons_Light = R"(
    QPushButton {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border: 1px solid palette(highlight) !important;
        padding: 6px 16px;
        border-radius: 1px;
        font-weight: 500;
        outline: none;
    }

    QPushButton:hover {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:pressed {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:disabled {
        background-color: palette(button) !important;
        color: palette(disabled, text) !important;
        border: 1px solid palette(mid) !important;
        font-weight: normal;
    }
)";

// QSS_Buttons_Dark 作用：
// - 深色场景按钮样式保持主题蓝，悬停继续加深；
// - 避免出现白色 hover 背景。
const QString QSS_Buttons_Dark = R"(
    QPushButton {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border: 1px solid palette(highlight) !important;
        padding: 6px 16px;
        border-radius: 1px;
        font-weight: 500;
        outline: none;
    }

    QPushButton:hover {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:pressed {
        background-color: palette(highlight) !important;
        color: palette(highlighted-text) !important;
        border-color: palette(highlight) !important;
    }

    QPushButton:disabled {
        background-color: palette(button) !important;
        color: palette(disabled, text) !important;
        border: 1px solid palette(mid) !important;
        font-weight: normal;
    }
)";
