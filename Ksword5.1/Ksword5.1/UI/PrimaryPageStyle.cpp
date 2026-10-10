#include "../Framework.h"
#include "./PrimaryPageStyle.h"
#include "./ThemeBinding.h"
#include "./ToolbarMetrics.h"
#include "../theme.h"

#include <QComboBox>
#include <QGroupBox>
#include <QLabel>
#include <QPointer>

namespace
{
    // 各控件只替换自己拥有的样式片段，避免丢掉页面既有几何规则。
    void ReplacePrimaryStyle(QWidget* widget, const QString& rules)
    {
        const QString begin = QStringLiteral("/* ks_primary_begin */");
        const QString end = QStringLiteral("/* ks_primary_end */");
        QString style = widget->styleSheet(); // 当前页面专用样式保留在拥有块之外。
        const qsizetype first = style.indexOf(begin);
        const qsizetype last = first < 0 ? -1 : style.indexOf(end, first);
        if (first >= 0 && last >= first)
        {
            style.remove(first, last + end.size() - first);
        }
        style = style.trimmed() + QLatin1Char('\n') + begin + rules + end;
        if (style != widget->styleSheet())
        {
            widget->setStyleSheet(style);
        }
    }
}

namespace ks::ui
{
    void StylePrimaryCombo(QComboBox* combo)
    {
        if (combo == nullptr || combo->property("ksword_primary_combo").toBool())
        {
            return;
        }
        combo->setProperty("ksword_primary_combo", true);
        NormalizeToolbarControl(combo);
        const QPointer<QComboBox> target(combo); // 页面销毁后取消延迟主题刷新。
        BindWidgetTheme(combo, [target]()
        {
            if (target)
            {
                // 控件自身的完整状态规则优先于 Dock 透明祖先，热切换不留下旧色快照。
                ReplacePrimaryStyle(target, KswordTheme::ThemedComboBoxStyle());
            }
        });
    }

    void StylePrimaryGroup(QGroupBox* group)
    {
        if (group == nullptr || group->property("ksword_primary_group").toBool())
        {
            return;
        }
        group->setProperty("ksword_primary_group", true);
        const QPointer<QGroupBox> target(group);
        BindWidgetTheme(group, [target]()
        {
            if (!target)
            {
                return;
            }
            const QColor surface = KswordTheme::SurfaceColor(); // 功能区相对页面保留一层中性底。
            const QColor title = KswordTheme::EnsureTextContrast(
                KswordTheme::TextSecondaryColor(), surface, 4.5);
            const QColor disabled = KswordTheme::EnsureTextContrast(
                KswordTheme::TextDisabledColor(), surface, 3.0);
            // 仅命中此分组自身，嵌套业务控件、表格语义底色及选中态保持原所有权。
            ReplacePrimaryStyle(target, QStringLiteral(
                "QGroupBox[ksword_primary_group=\"true\"]{background:%1;"
                "border:1px solid %2;border-radius:6px;margin-top:10px;padding-top:6px;}"
                "QGroupBox[ksword_primary_group=\"true\"]::title{"
                "subcontrol-origin:margin;subcontrol-position:top left;left:10px;"
                "padding:0 5px;background:%1;color:%3;font-weight:600;}"
                "QGroupBox[ksword_primary_group=\"true\"]::title:disabled{color:%4;}")
                .arg(surface.name(), KswordTheme::BorderColor().name(), title.name(), disabled.name()));
        });
    }

    void StylePrimaryToolbar(QWidget* toolbar)
    {
        if (toolbar == nullptr || toolbar->property("ksword_primary_toolbar").toBool())
        {
            return;
        }
        toolbar->setProperty("ksword_primary_toolbar", true);
        toolbar->setAttribute(Qt::WA_StyledBackground, true);
        const QPointer<QWidget> target(toolbar);
        BindWidgetTheme(toolbar, [target]()
        {
            if (target)
            {
                // 工具带只画底面和一条下边界，不把所有按钮包成重复卡片。
                ReplacePrimaryStyle(target, QStringLiteral(
                    "QWidget[ksword_primary_toolbar=\"true\"]{"
                    "background:%1;border:0;border-bottom:1px solid %2;}")
                    .arg(KswordTheme::SurfaceColor().name(), KswordTheme::BorderColor().name()));
            }
        });
    }

    void StylePrimarySectionTitle(QLabel* title)
    {
        if (title == nullptr || title->property("ksword_primary_title").toBool())
        {
            return;
        }
        title->setProperty("ksword_primary_title", true);
        const QPointer<QLabel> target(title);
        BindWidgetTheme(title, [target]()
        {
            if (target)
            {
                // 标题既可能位于工具带，也可能直接位于页面，两个背景都保持可读。
                const QColor backgrounds[] = {KswordTheme::WindowColor(), KswordTheme::SurfaceColor()};
                const QColor text = KswordTheme::EnsureTextContrastForBackgrounds(
                    KswordTheme::TextSecondaryColor(), backgrounds, 2, 4.5);
                ReplacePrimaryStyle(target, QStringLiteral(
                    "QLabel[ksword_primary_title=\"true\"]{"
                    "background:transparent;color:%1;font-weight:600;}").arg(text.name()));
            }
        });
    }
}
