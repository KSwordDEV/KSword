#include "../Framework.h"
#include "./PrimaryPageStyle.h"
#include "./ThemeBinding.h"
#include "./ToolbarMetrics.h"
#include "./MainSurfaceStyle.h"
#include "./GroupBoxStyle.h"
#include "../theme.h"

#include <QComboBox>
#include <QAbstractSpinBox>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QVariant>
#include <QBoxLayout>
#include <QFont>
#include <utility>

namespace
{
    // 独立表单没有工具行观察器；字号变化时按同一规则更新高度，不重复登记。
    class StandaloneInputMetrics final : public QObject
    {
    public:
        explicit StandaloneInputMetrics(QWidget* input) : QObject(input), m_input(input)
        {
            input->installEventFilter(this);
        }
    protected:
        bool eventFilter(QObject* source, QEvent* event) override
        {
            if (event->type() == QEvent::FontChange || event->type() == QEvent::ApplicationFontChange)
            {
                ks::ui::NormalizeToolbarControl(m_input);
            }
            return QObject::eventFilter(source, event);
        }
    private:
        QWidget* m_input = nullptr; // 父控件拥有观察器，二者同时销毁。
    };

    // 各控件只替换自己拥有的样式片段，避免丢掉页面既有几何规则。
    void ReplacePrimaryStyle(QWidget* widget, const QString& rules)
    {
        const QString begin = QStringLiteral("/* ks_primary_begin */");
        const QString end = QStringLiteral("/* ks_primary_end */");
        QString style = ks::ui::InitialStandaloneInputThemeStyle(widget); // 页面专用样式保留在拥有块之外。
        const qsizetype first = style.indexOf(begin);
        const qsizetype last = first < 0 ? -1 : style.indexOf(end, first);
        if (first >= 0 && last >= first)
        {
            style.remove(first, last + end.size() - first);
        }
        const QString ownedBlock = begin + rules + end; // 仅本模块的容器/输入规则，不拥有按钮颜色。
        widget->setProperty("ksword_primary_style_block", ownedBlock);
        style = style.trimmed() + QLatin1Char('\n') + ownedBlock;
        // The combo callback formerly appended standalone geometry after this
        // write (trimmed() can remove its leading newline). Compose that exact
        // final order here, including any required legacy duplicate rule.
        if (widget->property("ksword_primary_combo").toBool()
            && widget->property("ksword_standalone_input").toBool())
            style = ks::ui::WithStandaloneInputGeometry(std::move(style));
        if (style != widget->styleSheet())
        {
            widget->setStyleSheet(style);
        }
    }
}

namespace ks::ui
{
    QString WithParameterInputGeometry(QString style)
    {
        const QString geometry = QStringLiteral(
            "QLineEdit[ksword_standalone_input=\"true\"]{padding:0 8px;}");
        if (!style.contains(geometry)) style += geometry;
        return style;
    }

    QString WithStandaloneInputGeometry(QString style)
    {
        const QString geometry = QStringLiteral(
            "\nQComboBox[ksword_standalone_input=\"true\"],"
            "QAbstractSpinBox[ksword_standalone_input=\"true\"],"
            "QLineEdit[ksword_standalone_input=\"true\"]{border-radius:5px;}"
            "QAbstractSpinBox[ksword_standalone_input=\"true\"]::up-button{border-top-right-radius:4px;}"
            "QAbstractSpinBox[ksword_standalone_input=\"true\"]::down-button{border-bottom-right-radius:4px;}");
        if (!style.contains(geometry)) style += geometry;
        return style;
    }

    void StyleStandaloneInput(QWidget* input)
    {
        if (!input || (!qobject_cast<QComboBox*>(input)
            && !qobject_cast<QAbstractSpinBox*>(input) && !qobject_cast<QLineEdit*>(input)))
        {
            return;
        }
        // 内部编辑器属于外层输入面，单独加圆角会产生重复底块和接缝。
        if (qobject_cast<QLineEdit*>(input)
            && (qobject_cast<QComboBox*>(input->parentWidget())
                || qobject_cast<QAbstractSpinBox*>(input->parentWidget())))
        {
            return;
        }
        // 独立单行输入与按钮共用字体测量高度；组合控件内部编辑器已在上方排除。
        NormalizeToolbarControl(input);
        if (!input->property("ksword_standalone_metrics").toBool())
        {
            input->setProperty("ksword_standalone_metrics", true);
            new StandaloneInputMetrics(input);
        }
        input->setProperty("ksword_standalone_input", true);
        // 明确独立输入才接管完整底色；已有业务主题绑定保留所有权，不覆盖状态语义。
        const QPointer<QWidget> target(input);
        if (!HasWidgetThemeBinding(input))
        {
            if (auto* combo = qobject_cast<QComboBox*>(input)) StylePrimaryCombo(combo);
            else if (auto* spin = qobject_cast<QAbstractSpinBox*>(input)) BindSpinBoxTheme(spin);
            else if (auto* edit = qobject_cast<QLineEdit*>(input)) BindLineEditTheme(edit);
        }
        if (!target) return;
        const QString current = target->styleSheet();
        const QString finalStyle = WithStandaloneInputGeometry(current);
        if (finalStyle != current && !RequestStandaloneInputThemeGeometry(target))
        {
            // A custom owner (including the automatic combo policy) already
            // has its own rules. Preserve its original single geometry write.
            target->setStyleSheet(finalStyle);
        }
    }

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
                const QColor surface = UsesMainSurfaceHierarchy(target)
                    ? MainWindowSurfaceColors().input : KswordTheme::ControlInputSurfaceColor();
                ReplacePrimaryStyle(target, KswordTheme::ThemedComboBoxStyle(surface,
                    UsesTransparentMainSurface(target) ? MainDataSurfaceAlpha() : 255));
                if (target->property("ksword_standalone_input").toBool())
                {
                    StyleStandaloneInput(target);
                }
            }
        }, ThemePalettePolicy::FollowApplication, true);
    }

    void StylePrimaryGroup(QGroupBox* group)
    {
        if (group == nullptr)
        {
            return;
        }
        // 先普通卡片、后参数分区的构造顺序会改变角色；只在已登记同一角色时跳过。
        const bool embedded = group->property("ksword_parameter_section").toBool();
        const bool parameterCard = group->property("ksword_parameter_card").toBool();
        const QVariant registeredRole = group->property("ksword_primary_group_embedded_role");
        if (group->property("ksword_primary_group").toBool() && registeredRole.isValid()
            && registeredRole.toBool() == embedded
            && group->property("ksword_primary_group_card_role").toBool() == parameterCard
            && HasWidgetThemeBinding(group))
        {
            return;
        }
        group->setProperty("ksword_primary_group", true);
        group->setProperty("ksword_primary_group_embedded_role", embedded);
        group->setProperty("ksword_primary_group_card_role", parameterCard);
        const QPointer<QGroupBox> target(group);
        BindWidgetTheme(group, [target]()
        {
            if (!target)
            {
                return;
            }
            const bool parameterCard = target->property("ksword_parameter_card").toBool();
            const QColor surface = parameterCard ? MainWindowSurfaceColors().toolbar
                : UsesMainSurfaceHierarchy(target) ? MainWindowSurfaceColors().content : KswordTheme::SurfaceColor();
            const QColor title = KswordTheme::EnsureTextContrast(
                KswordTheme::TextSecondaryColor(), surface, 4.5);
            const QColor disabled = KswordTheme::EnsureTextContrast(
                KswordTheme::TextDisabledColor(), surface, 3.0);
            // 标题与正文内距由唯一共享配方管理；参数分区借外部卡片的16px，不叠第二层。
            const bool embedded = target->property("ksword_parameter_section").toBool();
            const QString selector = embedded
                ? QStringLiteral("QGroupBox[ksword_parameter_section=\"true\"]")
                : QStringLiteral("QGroupBox[ksword_primary_group=\"true\"]");
            const QString background = parameterCard
                ? MainControlSurfaceColor(surface, target).name(QColor::HexArgb)
                : UsesTransparentMainSurface(target) ? QStringLiteral("transparent") : surface.name();
            ConfigureGroupBoxLayout(target);
            ReplacePrimaryStyle(target, GroupBoxStyle(selector, background,
                title.name(), disabled.name(), target->fontMetrics().height(),
                embedded, !target->title().isEmpty()));
        });
    }

    void StylePrimaryToolbar(QWidget* toolbar)
    {
        if (toolbar == nullptr)
        {
            return;
        }
        const bool joined = toolbar->property("ksword_primary_toolbar_joined_tabs").toBool();
        if (toolbar->property("ksword_primary_toolbar").toBool()
            && toolbar->property("ksword_primary_toolbar_joined_applied").toBool() == joined)
        {
            return; // 只在明确改变拼接形状时重新登记本工具带，普通重复调用保持幂等。
        }
        toolbar->setProperty("ksword_primary_toolbar_joined_applied", joined);
        toolbar->setProperty("ksword_primary_toolbar", true);
        toolbar->setAttribute(Qt::WA_StyledBackground, true);
        const QPointer<QWidget> target(toolbar);
        BindWidgetTheme(toolbar, [target]()
        {
            if (target)
            {
                const bool transparentSurface = UsesTransparentMainSurface(target);
                const bool mainSurface = UsesMainSurfaceHierarchy(target) || transparentSurface;
                const MainSurfaceColors surfaces = MainWindowSurfaceColors();
                // 独立工具带与内容板统一圆角，以底色差表达层级，不再拼接一块方形底面。
                const int bottomRadius = target->property("ksword_primary_toolbar_joined_tabs").toBool() ? 0 : 8;
                ReplacePrimaryStyle(target, QStringLiteral(
                    "QWidget[ksword_primary_toolbar=\"true\"]{"
                    "background:%1;border:0;border-radius:8px;"
                    "border-bottom-left-radius:%2px;border-bottom-right-radius:%2px;}")
                    .arg(mainSurface ? MainDataSurfaceStyleColor(surfaces.toolbar, transparentSurface)
                        : KswordTheme::SurfaceColor().name()).arg(bottomRadius));
            }
        });
    }

    void StylePrimaryContentPanel(QWidget* panel, bool outline)
    {
        if (!panel)
        {
            return;
        }
        const bool changed = panel->property("ksword_primary_content_panel_outlined").isValid()
            && panel->property("ksword_primary_content_panel_outlined").toBool() != outline;
        panel->setProperty("ksword_primary_content_panel_outlined", outline);
        if (panel->property("ksword_primary_content_panel").toBool() && !changed)
        {
            return;
        }
        // 单面板边界模式改变只替换并排队自己的绑定，不广播全应用主题刷新。
        panel->setProperty("ksword_primary_content_panel", true);
        panel->setAttribute(Qt::WA_StyledBackground, true);
        const QPointer<QWidget> target(panel); // 沿用原面板对象，图表采样和绘图逻辑不变。
        BindWidgetTheme(panel, [target]()
        {
            if (!target)
            {
                return;
            }
            const bool transparentSurface = UsesTransparentMainSurface(target);
            const bool mainSurface = UsesMainSurfaceHierarchy(target) || transparentSurface;
            const MainSurfaceColors surfaces = MainWindowSurfaceColors();
            const bool outlined = target->property("ksword_primary_content_panel_outlined").toBool();
            const QString background = transparentSurface ? QStringLiteral("transparent")
                : mainSurface ? MainDataSurfaceStyleColor(surfaces.content, transparentSurface)
                : outlined ? QStringLiteral("transparent") : KswordTheme::SurfaceColor().name();
            const QString rules = outlined ? QStringLiteral(
                "QWidget[ksword_primary_content_panel=\"true\"]{background:%1;border:1px solid %2;border-radius:8px;}")
                    .arg(background, mainSurface ? surfaces.border.name() : KswordTheme::BorderColor().name())
                : QStringLiteral(
                    "QWidget[ksword_primary_content_panel=\"true\"]{background:%1;border:0;border-radius:8px;}").arg(background);
            ReplacePrimaryStyle(target, rules);
        });
    }

    void StyleWorkspacePage(QWidget* page, int margin)
    {
        if (!page) return;
        page->setProperty("ksword_workspace_page", true);
        page->setAttribute(Qt::WA_StyledBackground);
        QFont body = page->font();
        if (body.pixelSize() > 0) body.setPixelSize(qMax(14, body.pixelSize()));
        else body.setPointSizeF(qMax(10.0, body.pointSizeF()));
        page->setFont(body);
        if (page->layout())
        {
            page->layout()->setContentsMargins(margin, margin, margin, margin);
            if (auto* box = qobject_cast<QBoxLayout*>(page->layout())) box->setSpacing(12);
        }
        const QPointer<QWidget> target(page);
        BindWidgetTheme(page, [target]()
        {
            if (!target) return;
            const QColor canvas = UsesMainSurfaceHierarchy(target)
                ? MainWindowSurfaceColors().canvas : KswordTheme::WindowColor();
            ReplacePrimaryStyle(target, QStringLiteral(
                "QWidget[ksword_workspace_page=\"true\"]{background:%1;border:0;border-radius:8px;}")
                    .arg(UsesTransparentMainSurface(target) ? QStringLiteral("transparent") : canvas.name()));
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
                const bool mainSurface = UsesMainSurfaceHierarchy(target);
                const MainSurfaceColors surfaces = MainWindowSurfaceColors();
                const QColor backgrounds[] = {
                    mainSurface ? surfaces.canvas : KswordTheme::WindowColor(),
                    mainSurface ? surfaces.toolbar : KswordTheme::SurfaceColor()};
                const QColor text = KswordTheme::EnsureTextContrastForBackgrounds(
                    KswordTheme::TextSecondaryColor(), backgrounds, 2, 4.5);
                ReplacePrimaryStyle(target, QStringLiteral(
                    "QLabel[ksword_primary_title=\"true\"]{"
                    "background:transparent;color:%1;font-weight:600;}").arg(text.name()));
            }
        });
    }
}
