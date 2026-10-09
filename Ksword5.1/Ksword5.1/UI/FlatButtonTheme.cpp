#include "./FlatButtonTheme.h"
#include "ThemeBinding.h"
#include "../theme.h"

#include <QAbstractButton>
#include <QApplication>
#include <QEvent>
#include <QPalette>
#include <QPointer>
#include <QPushButton>
#include <QToolButton>
#include <memory>

namespace
{
    // 标记只描述本模块拥有的颜色规则，页面原有几何和其它控件样式原样保留。
    constexpr char beginMarker[] = "/*KSWORD_FLAT_BUTTON_BEGIN*/";
    constexpr char endMarker[] = "/*KSWORD_FLAT_BUTTON_END*/";

    QString replaceOwnedBlock(QString style, const QString& replacement)
    {
        const qsizetype begin = style.indexOf(QLatin1String(beginMarker));
        const qsizetype end = style.indexOf(QLatin1String(endMarker), begin);
        if (begin >= 0 && end >= begin)
        {
            style.replace(begin, end + qstrlen(endMarker) - begin, replacement);
        }
        else
        {
            style += replacement;
        }
        return style;
    }

    // 按钮只接管自身状态色；色调来自页面选择，所有前景按实际底色校准对比度。
    QString buildStyle(ks::ui::FlatButtonTone tone, const QPalette& palette)
    {
        QColor background = palette.color(QPalette::Active, QPalette::Button);
        QColor text = palette.color(QPalette::Active, QPalette::ButtonText);
        QColor accent = palette.color(QPalette::Active, QPalette::Highlight);
        accent.setAlpha(255);
        if (tone == ks::ui::FlatButtonTone::Accent)
        {
            background = accent;
        }
        else if (tone == ks::ui::FlatButtonTone::Danger)
        {
            background = KswordTheme::ErrorColor();
        }
        else if (tone == ks::ui::FlatButtonTone::Success)
        {
            background = KswordTheme::SuccessColor();
        }
        background.setAlpha(255);
        text = KswordTheme::EnsureTextContrast(text, background, 4.5);
        const bool dark = KswordTheme::RelativeLuminance(background) < 0.25;
        const QColor hover = dark ? background.lighter(125) : background.darker(108);
        const QColor pressed = dark ? background.lighter(145) : background.darker(120);
        const QColor hoverText = KswordTheme::EnsureTextContrast(text, hover, 4.5);
        const QColor pressedText = KswordTheme::EnsureTextContrast(text, pressed, 4.5);
        const QColor selectedText = KswordTheme::EnsureTextContrast(
            palette.color(QPalette::Active, QPalette::HighlightedText), accent, 4.5);
        QColor disabledBackground = palette.color(QPalette::Disabled, QPalette::Button);
        disabledBackground.setAlpha(255);
        const QColor disabledText = KswordTheme::EnsureTextContrast(
            palette.color(QPalette::Disabled, QPalette::ButtonText), disabledBackground, 3.0);

        // 只匹配 push/tool 按钮，不碰 checkbox、表格 item、输入框、菜单和页面面板。
        // 不声明 padding、字号、最小尺寸或图标，保留各页面已经审核的几何与动作。
        return QStringLiteral(
            "/*KSWORD_FLAT_BUTTON_TONE_%1*/"
            "QPushButton,QToolButton,QPushButton:flat{background-color:%2;color:%3;border:none;}"
            "QPushButton:hover,QToolButton:hover{background-color:%4;color:%5;border:none;}"
            "QPushButton:focus,QToolButton:focus{background-color:%4;color:%5;border:none;}"
            "QPushButton:pressed,QToolButton:pressed{background-color:%6;color:%7;border:none;}"
            "QPushButton:checked,QToolButton:checked{background-color:%8;color:%9;border:none;}"
            "QPushButton:checked:hover,QToolButton:checked:hover{background-color:%8;color:%9;border:none;}"
            "QPushButton:disabled,QToolButton:disabled,QPushButton:checked:disabled,QToolButton:checked:disabled{"
            "background-color:%10;color:%11;border:none;}"
            "QToolButton::menu-button{background:transparent;border:none;}")
            .arg(static_cast<int>(tone))
            .arg(background.name()).arg(text.name()).arg(hover.name()).arg(hoverText.name())
            .arg(pressed.name()).arg(pressedText.name()).arg(accent.name()).arg(selectedText.name())
            .arg(disabledBackground.name()).arg(disabledText.name());
    }

    // 只对明确使用本组件标记的本地/父级样式登记绑定，不猜测未审核业务的动作色。
    class FlatButtonFilter final : public QObject
    {
    public:
        explicit FlatButtonFilter(QApplication* app) : QObject(app) {}

        bool eventFilter(QObject* object, QEvent* event) override
        {
            if (event == nullptr || (event->type() != QEvent::Polish
                && event->type() != QEvent::Show && event->type() != QEvent::StyleChange))
            {
                return false;
            }
            auto* button = qobject_cast<QAbstractButton*>(object);
            if (button == nullptr || (!qobject_cast<QPushButton*>(button)
                && !qobject_cast<QToolButton*>(button)) || (ks::ui::HasWidgetThemeBinding(button)
                && !button->property("ksword_flat_button_managed").toBool()))
            {
                return false;
            }
            // 显式 API 尚未刷新时，旧的本地/父级 marker 不得把 Danger 降回 Neutral。
            // 页面真的重写自身样式则继续重新发现，保留 A/B 切换的最新声明。
            if (button->property("ksword_flat_button_pending").toBool()
                && button->styleSheet() == button->property("ksword_flat_button_initial_style").toString())
            {
                return false;
            }
            for (QWidget* owner = button; owner != nullptr; owner = owner->parentWidget())
            {
                const QString style = owner->styleSheet();
                int latestTone = -1; // 后声明的页面状态优先，不把首次 Neutral 锁成永久色调。
                qsizetype latestPosition = -1;
                for (int tone = 0; tone <= 3; ++tone)
                {
                    const qsizetype position = style.lastIndexOf(
                        QStringLiteral("/*KSWORD_FLAT_BUTTON_TONE_%1*/").arg(tone));
                    if (position > latestPosition)
                    {
                        latestPosition = position;
                        latestTone = tone;
                    }
                }
                // 未标记的本地或祖先覆盖属于页面，不跨过它猜更远父级/全局按钮归一。
                // 例如数据颜色面板可在父 QWidget 给按钮定义底色，而按钮自身 QSS 为空。
                if (!style.isEmpty() && latestTone < 0)
                {
                    return false;
                }
                if (latestTone >= 0)
                {
                    if (!button->property("ksword_flat_button_managed").toBool()
                        || button->property("ksword_flat_button_tone").toInt() != latestTone)
                    {
                        ks::ui::ApplyFlatButtonTheme(button,
                            static_cast<ks::ui::FlatButtonTone>(latestTone));
                    }
                    return false;
                }
            }
            return false;
        }
    };
}

QString ks::ui::BuildFlatButtonStyle(FlatButtonTone tone)
{
    return QLatin1String(beginMarker) + buildStyle(tone, QApplication::palette())
        + QLatin1String(endMarker);
}

void ks::ui::ApplyFlatButtonTheme(QAbstractButton* button, FlatButtonTone tone)
{
    if (button == nullptr || (!qobject_cast<QPushButton*>(button)
        && !qobject_cast<QToolButton*>(button)))
    {
        return;
    }
    button->setProperty("ksword_flat_button_managed", true);
    button->setProperty("ksword_flat_button_tone", static_cast<int>(tone));
    const QPointer<QAbstractButton> guardedButton(button);
    const QString initialStyle = button->styleSheet(); // 显式调用允许接管调用时的样式。
    button->setProperty("ksword_flat_button_pending", true);
    button->setProperty("ksword_flat_button_initial_style", initialStyle);
    // ThemeBinding 探活时复制回调；首次许可必须跨闭包副本共享，不能只用 mutable bool。
    const auto applied = std::make_shared<bool>(false);
    BindWidgetTheme(button, [guardedButton, tone, initialStyle, applied]()
    {
        if (guardedButton.isNull())
        {
            return;
        }
        const QString currentStyle = guardedButton->styleSheet();
        // 页面后来改成未标记的数据色时，旧绑定不得重新追加共享规则夺回所有权。
        // 首次显式接管也要核对等待队列期间页面是否已经换过样式。
        if (!currentStyle.isEmpty() && !currentStyle.contains(QLatin1String(beginMarker))
            && (*applied || currentStyle != initialStyle))
        {
            guardedButton->setProperty("ksword_flat_button_pending", false);
            return;
        }
        const QPalette colors = guardedButton->parentWidget() != nullptr
            ? guardedButton->parentWidget()->palette() : QApplication::palette();
        const QString block = QLatin1String(beginMarker) + buildStyle(tone, colors)
            + QLatin1String(endMarker);
        const QString style = replaceOwnedBlock(currentStyle, block);
        *applied = true;
        if (style != guardedButton->styleSheet())
        {
            guardedButton->setStyleSheet(style);
        }
        if (!guardedButton.isNull())
        {
            guardedButton->setProperty("ksword_flat_button_pending", false);
            guardedButton->setProperty("ksword_flat_button_initial_style", QVariant());
        }
    }, ThemePalettePolicy::PreserveLocal);
}

void ks::ui::InstallGlobalFlatButtonTheme(QApplication* app)
{
    if (app == nullptr || app->property("ksword_flat_button_filter").toBool())
    {
        return;
    }
    app->setProperty("ksword_flat_button_filter", true);
    app->installEventFilter(new FlatButtonFilter(app));
}

bool ks::ui::TryGetFlatButtonBackground(const QAbstractButton* button,
    QIcon::Mode mode, QIcon::State state, QColor* background)
{
    if (button == nullptr || background == nullptr
        || (!qobject_cast<const QPushButton*>(button) && !qobject_cast<const QToolButton*>(button)))
    {
        return false;
    }
    int tone = -1; // 只从仍实际存在的拥有标记读取，避免旧 managed 属性覆盖页面数据色。
    for (const QWidget* owner = button; owner != nullptr; owner = owner->parentWidget())
    {
        const QString style = owner->styleSheet();
        qsizetype latestPosition = -1;
        for (int candidate = 0; candidate <= 3; ++candidate)
        {
            const qsizetype position = style.lastIndexOf(
                QStringLiteral("/*KSWORD_FLAT_BUTTON_TONE_%1*/").arg(candidate));
            if (position > latestPosition)
            {
                latestPosition = position;
                tone = candidate;
            }
        }
        // 祖先未知 QSS 可能比应用基线更优先；必须和自动绑定使用相同所有权边界。
        if (!style.isEmpty() && tone < 0)
        {
            return false;
        }
        if (tone >= 0)
        {
            break;
        }
    }
    if (tone < 0)
    {
        // 没有本地覆盖的应用默认按钮使用全局同一 Neutral 块。
        if (!button->styleSheet().isEmpty() || QApplication::instance() == nullptr
            || !qApp->styleSheet().contains(QLatin1String(beginMarker)))
        {
            return false;
        }
        tone = static_cast<int>(FlatButtonTone::Neutral);
    }
    const QPalette colors = button->parentWidget() != nullptr
        ? button->parentWidget()->palette() : QApplication::palette();
    QColor result = colors.color(QPalette::Active, QPalette::Button);
    if (tone == static_cast<int>(FlatButtonTone::Accent))
    {
        result = colors.color(QPalette::Active, QPalette::Highlight);
    }
    else if (tone == static_cast<int>(FlatButtonTone::Danger))
    {
        result = KswordTheme::ErrorColor();
    }
    else if (tone == static_cast<int>(FlatButtonTone::Success))
    {
        result = KswordTheme::SuccessColor();
    }
    result.setAlpha(255);
    const bool dark = KswordTheme::RelativeLuminance(result) < 0.25;
    if (button->isDown())
    {
        result = dark ? result.lighter(145) : result.darker(120);
    }
    else if (mode == QIcon::Active || button->underMouse() || button->hasFocus())
    {
        result = dark ? result.lighter(125) : result.darker(108);
    }
    // 与 QSS 的声明优先级一致：checked 覆盖 pressed，disabled 最后覆盖全部状态。
    if (button->isChecked() || state == QIcon::On || mode == QIcon::Selected)
    {
        result = colors.color(QPalette::Active, QPalette::Highlight);
    }
    if (!button->isEnabled() || mode == QIcon::Disabled)
    {
        result = colors.color(QPalette::Disabled, QPalette::Button);
    }
    result.setAlpha(255);
    *background = result;
    return true;
}
