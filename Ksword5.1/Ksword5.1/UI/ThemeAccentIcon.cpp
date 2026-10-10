#include "../Framework.h"
#include "ThemeAccentIcon.h"
#include "./FlatButtonTheme.h"
#include "../theme.h"

#include <QIconEngine>
#include <QApplication>
#include <QAbstractButton>
#include <QPainter>
#include <QPalette>
#include <QPixmap>
#include <QPointer>
#include <QStyle>
#include <QStyleOption>
#include <cmath>

namespace ks::ui
{
    namespace
    {
        // ThemeAccentIconEngine 保留未着色轮廓，每次绘制独立读取当前主题颜色。
        // 不保存主题色缓存，也不遍历模型项，因此懒加载和恢复默认使用同一源图。
        class ThemeAccentIconEngine final : public QIconEngine
        {
        public:
            // sourceIcon 用途：复制固定默认色源图；模式、状态和缩放仍由源引擎决定。
            // fixedAccent 为主题色快照，button 可为空；非空时只保存寿命受控的绘制上下文。
            explicit ThemeAccentIconEngine(const QIcon& sourceIcon,
                const QColor& fixedAccent = QColor(), QAbstractButton* button = nullptr,
                bool neutralTab = false)
                : m_sourceIcon(sourceIcon)
                , m_fixedAccent(fixedAccent)
                , m_button(button)
                , m_neutralTab(neutralTab)
            {
            }

            // clone：Qt 图标分离时仅复制原始源图，不捕获当时的主题色或派生位图。
            QIconEngine* clone() const override
            {
                return new ThemeAccentIconEngine(m_sourceIcon, m_fixedAccent, m_button.data(), m_neutralTab);
            }

            // isNull/actualSize/availableSizes：转发源图能力，不把空源或小轮廓伪装成新资源。
            bool isNull() override
            {
                return m_sourceIcon.isNull();
            }

            QSize actualSize(const QSize& size, QIcon::Mode mode, QIcon::State state) override
            {
                return m_sourceIcon.actualSize(size, mode, state);
            }

            QList<QSize> availableSizes(QIcon::Mode mode, QIcon::State state) override
            {
                return m_sourceIcon.availableSizes(mode, state);
            }

            // pixmap：普通像素请求沿用相同绘制流程，返回当前主题色与源图 alpha。
            QPixmap pixmap(const QSize& size, QIcon::Mode mode, QIcon::State state) override
            {
                return renderPixmap(size, mode, state, 1.0);
            }

            // scaledPixmap：Qt 6.9 的 size 为逻辑尺寸；scale 为请求的设备像素比。
            // 直接交给源图的 DPR 重载，避免再次乘尺寸导致高 DPI 放大两次。
            QPixmap scaledPixmap(const QSize& size, QIcon::Mode mode, QIcon::State state, qreal scale) override
            {
                return renderPixmap(size, mode, state, scale);
            }

            // paint：只在请求的矩形绘制当前颜色，不修改外部 painter 的模式或状态。
            void paint(QPainter* painter, const QRect& rect, QIcon::Mode mode, QIcon::State state) override
            {
                if (painter == nullptr || painter->device() == nullptr || rect.isEmpty())
                {
                    return;
                }

                // deviceScale 用途：匹配实际绘制设备；themedPixmap 用途：本次临时着色结果。
                const qreal deviceScale = painter->device()->devicePixelRatioF();
                const QPixmap themedPixmap = renderPixmap(rect.size(), mode, state, deviceScale);
                if (!themedPixmap.isNull())
                {
                    painter->drawPixmap(rect, themedPixmap);
                }
            }

        private:
            // foregroundColor 按Qt请求的模式/状态校准，不能把黑/白主体色原样画在同色底上。
            // sourceAccent无效时动态读取全局种子；多种中性底共用Normal，强调底使用独立状态。
            // flatButtonBackgroundKnown 回传是否已按共享按钮底色校准，用于禁止二次禁用灰化。
            QColor foregroundColor(const QIcon::Mode mode, const QIcon::State state,
                bool* flatButtonBackgroundKnown) const
            {
                if (flatButtonBackgroundKnown != nullptr)
                {
                    *flatButtonBackgroundKnown = false;
                }
                const QColor accent = m_fixedAccent.isValid()
                    ? m_fixedAccent : KswordTheme::PrimaryAccentColor(); // 本次图形的主题种子。

                // 弱底色 Tab 的 Active/Selected 仍在中性表面上，不能校准到强调色底。
                if (m_neutralTab)
                {
                    const QColor base = KswordTheme::SurfaceColor();
                    const QColor parentBase = KswordTheme::SurfaceAltColor();
                    const QColor backgrounds[] = {KswordTheme::WindowColor(), base, parentBase,
                        KswordTheme::BlendColors(base, KswordTheme::ControlAccentColor(), 38),
                        KswordTheme::BlendColors(parentBase, KswordTheme::ControlAccentColor(), 38)};
                    const QColor preferred = mode == QIcon::Disabled
                        ? KswordTheme::TextDisabledColor() : accent;
                    if (flatButtonBackgroundKnown != nullptr)
                    {
                        *flatButtonBackgroundKnown = true;
                    }
                    return KswordTheme::EnsureTextContrastForBackgrounds(preferred, backgrounds, 5, 3.0);
                }

                // buttonBackground 用途：仅由共享按钮组件确认拥有的实际状态底色。
                // 透明 Neutral 常态取父级真实合成底；hover/focus/down/checked 取实际强调底。
                // 不自行填图标背景，也不再从旧 Neutral 实底配方猜测当前模式对应的颜色。
                QColor buttonBackground;
                if (!m_button.isNull() && TryGetFlatButtonBackground(
                    m_button.data(), mode, state, &buttonBackground))
                {
                    if (flatButtonBackgroundKnown != nullptr)
                    {
                        *flatButtonBackgroundKnown = true;
                    }
                    const QPalette colors = m_button->parentWidget() != nullptr // 按钮 QSS 配方所用父级色板。
                        ? m_button->parentWidget()->palette() : QApplication::palette();
                    QColor buttonAccent = colors.color(QPalette::Active, QPalette::Highlight); // 当前按钮强调种子。
                    if (!buttonAccent.isValid() || buttonAccent.alpha() == 0)
                    {
                        buttonAccent = KswordTheme::PrimaryAccentColor(); // 透明继承色不能被强制变成黑色种子。
                    }
                    buttonAccent.setAlpha(255); // 图标轮廓只继承源 alpha，主题色自身保持不透明。
                    const bool disabled = mode == QIcon::Disabled || !m_button->isEnabled(); // 实际禁用态优先。
                    QColor preferred = disabled
                        ? colors.color(QPalette::Disabled, QPalette::ButtonText) : buttonAccent;
                    preferred.setAlpha(255); // 禁用色也保留原轮廓 alpha，不能把父级透明色当作图标透明度。
                    return KswordTheme::EnsureTextContrast(preferred, buttonBackground, 3.0);
                }

                // 非共享样式、菜单和模型没有已知按钮底色，保留原有通用图标角色。
                // 不凭旧 managed 属性猜测数据原色，不把全局 Active 改成 Neutral。
                if (mode == QIcon::Selected || state == QIcon::On)
                {
                    return KswordTheme::EnsureTextContrast(accent, KswordTheme::PrimaryAccentColor(), 3.0);
                }
                if (mode == QIcon::Active)
                {
                    return KswordTheme::EnsureTextContrast(accent, KswordTheme::ControlAccentColor(), 3.0);
                }
                const QColor surfaces[] = {KswordTheme::SurfaceColor(),
                    KswordTheme::SurfaceAltColor(), KswordTheme::SurfaceMutedColor()}; // 普通图标明确覆盖三种中性表面。
                const QColor preferred = mode == QIcon::Disabled
                    ? KswordTheme::BlendColors(surfaces[0], accent, 96) : accent;
                return KswordTheme::EnsureTextContrastForBackgrounds(preferred, surfaces, 3, 3.0);
            }

            // renderPixmap：按源引擎提供的 mode/state/DPR 取得透明轮廓，替换可见像素色。
            // size 为逻辑尺寸，scale 为设备像素比；无效请求返回空位图，结果不持久缓存。
            QPixmap renderPixmap(const QSize& size, QIcon::Mode mode, QIcon::State state, qreal scale) const
            {
                if (size.isEmpty() || !std::isfinite(scale) || scale <= 0.0)
                {
                    return {};
                }

                // sourceMode 用途：禁用效果应在新主题着色后生成一次，避免覆盖旧灰度。
                // 本接口的自制源图只有单色 Normal 轮廓；其它模式继续请求源状态。
                const QIcon::Mode sourceMode = mode == QIcon::Disabled ? QIcon::Normal : mode;
                QPixmap themedPixmap = m_sourceIcon.pixmap(size, scale, sourceMode, state);
                if (themedPixmap.isNull())
                {
                    return themedPixmap;
                }

                // painter 用途：仅在临时副本上使用 SourceIn，不修改共享源图缓存。
                QPainter painter(&themedPixmap);
                painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
                bool flatButtonBackgroundKnown = false; // 是否已按共享按钮真实底色完成校准。
                painter.fillRect(themedPixmap.rect(), foregroundColor(
                    mode, state, &flatButtonBackgroundKnown));
                painter.end();

                // applicationStyle/styleOption 用途：让 Qt 按当前 palette 生成真实禁用态。
                QStyle* applicationStyle = QApplication::style();
                // 共享按钮禁用态已经用 disabled palette 和实际底色求得前景。
                // 二次 generatedIconPixmap 灰化会破坏刚保证的对比度，只保留未知控件旧行为。
                if (mode == QIcon::Disabled && !flatButtonBackgroundKnown && applicationStyle != nullptr)
                {
                    QStyleOption styleOption;
                    styleOption.palette = QApplication::palette();
                    // sourceScale 用途：防止样式实现生成新位图时丢失原来的设备像素比。
                    const qreal sourceScale = themedPixmap.devicePixelRatioF();
                    themedPixmap = applicationStyle->generatedIconPixmap(mode, themedPixmap, &styleOption);
                    themedPixmap.setDevicePixelRatio(sourceScale);
                }
                return themedPixmap;
            }

            QIcon m_sourceIcon; // m_sourceIcon：固定默认蓝源图，包含源引擎的模式与状态。
            QColor m_fixedAccent; // 无效表示随全局种子变化；有效表示管理器本轮主体色。
            QPointer<QAbstractButton> m_button; // 仅按钮包装持有的弱上下文，销毁后自动失效。
            bool m_neutralTab = false; // 普通 Tab 已明确采用中性选中底，不借用按钮配色。
        };
    }

    // MakeThemeAccentIcon：QIcon 接管新引擎生命周期；调用方无需保存或释放引擎指针。
    QIcon MakeThemeAccentIcon(const QIcon& sourceIcon)
    {
        return MakeThemeAccentIcon(sourceIcon, QColor());
    }

    QIcon MakeThemeAccentIcon(const QIcon& sourceIcon, const QColor& fixedAccent)
    {
        if (sourceIcon.isNull())
        {
            return sourceIcon;
        }
        return QIcon(new ThemeAccentIconEngine(sourceIcon, fixedAccent));
    }

    // 普通 Tab 使用独立的中性底色策略，强调色快照和源图随图标副本保留。
    QIcon MakeThemeTabAccentIcon(const QIcon& sourceIcon, const QColor& fixedAccent)
    {
        if (sourceIcon.isNull())
        {
            return sourceIcon;
        }
        return QIcon(new ThemeAccentIconEngine(sourceIcon, fixedAccent, nullptr, true));
    }

    // 每个按钮创建自己的引擎，Qt 分离副本仍跟随同一弱上下文。
    // 不进入全局着色缓存；按钮销毁后安全回退通用主题语义。
    QIcon MakeThemeButtonAccentIcon(const QIcon& sourceIcon,
        const QColor& fixedAccent, QAbstractButton* button)
    {
        if (sourceIcon.isNull())
        {
            return sourceIcon;
        }
        return QIcon(new ThemeAccentIconEngine(sourceIcon, fixedAccent, button));
    }
}
