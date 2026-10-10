#pragma once

#include "./ThemeBinding.h"
#include "../theme.h"
#include "../Internationalization/LanguageManager.h"
#include <QFontMetrics>
#include <QLineEdit>
#include <QPointer>
#include <QTabBar>
#include <QTabWidget>
#include <algorithm>

namespace ks::ui
{
    // 输入页面已确认的搜索字段；只统一搜索外观与单行高度，保留过滤连接和限定宽度。
    // 不扫描页面，不识别字段名，路径、地址、命令输入框必须由调用方明确排除。
    inline void StyleSearchField(QLineEdit* field, int compactHeight = 0)
    {
        if (field == nullptr || field->property("ksword_page_search_style").toBool())
        {
            return;
        }
        field->setProperty("ksword_page_search_style", true);
        // 标题栏双模式字段可明确传入原有紧凑高度；普通页面按字体统一高度。
        field->setFixedHeight(compactHeight > 0 ? compactHeight
            : std::max(28, QFontMetrics(field->font()).height() + 12));
        field->setClearButtonEnabled(true);
        if (field->placeholderText().isEmpty())
        {
            field->setPlaceholderText(ks::i18n::sourceText(QStringLiteral("搜索")));
        }
        // 几何在控件自身设置，颜色交给现有热主题绑定，避免再次引入白色描边。
        field->setStyleSheet(field->styleSheet() + QStringLiteral(
            "\nQLineEdit[ksword_page_search_style=\"true\"]{padding:0px 10px;border-radius:5px;}"));
        BindSearchFieldTheme(field);
    }

    // 普通内容页签采用低对比选中底面和细主题下划线；不接管 ADS 或详情侧栏导航。
    // bar 是页面明确传入的 QTabBar；规则只命中此栏，主题变化时完整重建颜色。
    inline void StylePageTabBar(QTabBar* bar)
    {
        if (bar == nullptr || bar->property("ksword_page_tabs_style").toBool())
        {
            return;
        }
        bar->setProperty("ksword_page_tabs_style", true);
        bar->setExpanding(false);
        bar->setUsesScrollButtons(true);
        const QPointer<QTabBar> safeBar(bar); // 控件销毁后排队主题刷新不再访问旧栏。
        BindWidgetTheme(bar, [safeBar]()
        {
            if (safeBar.isNull())
            {
                return;
            }
            const QColor base = KswordTheme::SurfaceColor();
            const QColor accent = KswordTheme::ControlAccentColor();
            const QColor selected = KswordTheme::BlendColors(base, accent, 38);
            const QColor hover = KswordTheme::BlendColors(base, accent, 18);
            const QColor selectedText = KswordTheme::EnsureTextContrast(
                KswordTheme::TextPrimaryColor(), selected, 4.5);
            // 所有状态使用相同的边缘和留白，切换时不改变页签几何；侧向栏单独下发细边。
            const QString style = QStringLiteral(
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab{"
                "background:%1;color:%2;border:0;border-bottom:2px solid transparent;"
                "padding:5px 12px;min-height:18px;margin:0px 2px 0px 0px;"
                "border-top-left-radius:5px;border-top-right-radius:5px;}"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:hover:!selected{background:%3;}"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:selected{"
                "background:%4;color:%5;border-bottom-color:%6;}"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:selected:hover{background:%4;}"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:disabled{color:%7;}"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:left,"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:right{"
                "margin:0px 0px 2px 0px;border-bottom:0;border-left:2px solid transparent;}"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:left:selected,"
                "QTabBar[ksword_page_tabs_style=\"true\"]::tab:right:selected{border-left-color:%6;}")
                .arg(base.name(), KswordTheme::TextSecondaryColor().name(), hover.name(),
                    selected.name(), selectedText.name(), accent.name(), KswordTheme::TextDisabledColor().name());
            if (safeBar->styleSheet() != style)
            {
                safeBar->setStyleSheet(style);
            }
        });
    }

    // 输入已审核的普通 QTabWidget，保留原页索引、惰性加载及 pane 边界；只调整其页签栏。
    inline void StylePageTabs(QTabWidget* tabs)
    {
        if (tabs != nullptr)
        {
            StylePageTabBar(tabs->tabBar());
        }
    }
}
