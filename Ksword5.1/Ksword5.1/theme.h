#pragma once
#include "UI/FlatButtonTheme.h"

// Central theme helpers for all Qt UI code.
//
// A color used by a widget must be derived from a named theme role and an
// offset.  Keeping the RGB seed and the light/dark offsets here prevents a
// local literal from silently becoming unreadable when the application theme
// changes.

#include <QApplication>
#include <QColor>
#include <QSize>
#include <QString>

#include "UI/ThemeControlGlyphs.h"

#include <cmath>

namespace KswordTheme
{
    inline bool IsDarkModeEnabled();

    // 纯图标按钮只允许两档几何：紧凑工具栏使用 28/16，独立或强调动作使用 32/18。
    // 调用方不再自行组合按钮边长与图标边长，避免同类动作漂移到 30/34/36px。
    inline QSize CompactIconButtonSize()
    {
        return QSize(28, 28);
    }

    inline QSize CompactIconSize()
    {
        return QSize(16, 16);
    }

    inline QSize StandardIconButtonSize()
    {
        return QSize(32, 32);
    }

    inline QSize StandardIconSize()
    {
        return QSize(18, 18);
    }

    template <typename ButtonType>
    inline void ApplyCompactIconButtonMetrics(ButtonType* button)
    {
        if (button != nullptr)
        {
            button->setFixedSize(CompactIconButtonSize());
            button->setIconSize(CompactIconSize());
        }
    }

    template <typename ButtonType>
    inline void ApplyStandardIconButtonMetrics(ButtonType* button)
    {
        if (button != nullptr)
        {
            button->setFixedSize(StandardIconButtonSize());
            button->setIconSize(StandardIconSize());
        }
    }

    struct RgbOffset
    {
        int red = 0;
        int green = 0;
        int blue = 0;
    };

    // ThemeRgbOffset 作用：把同一颜色角色的深色、浅色偏移量绑定为一组。
    // 两组数值必须相对于同一个基础色计算，调用方不能只传一套数值复用到两个主题。
    struct ThemeRgbOffset
    {
        RgbOffset dark;
        RgbOffset light;
    };

    inline constexpr RgbOffset UniformOffset(const int value)
    {
        return { value, value, value };
    }

    // UniformThemeOffset 作用：生成深浅主题各自独立的等量 RGB 偏移。
    // 入参分别是深色与浅色模式数值，返回可交给 ThemeOffsetColor 的成对配置。
    inline constexpr ThemeRgbOffset UniformThemeOffset(
        const int darkValue,
        const int lightValue)
    {
        return { UniformOffset(darkValue), UniformOffset(lightValue) };
    }

    inline int ClampChannel(const int channelValue)
    {
        return qBound(0, channelValue, 255);
    }

    // OffsetColor is the only place where RGB channel arithmetic is allowed.
    // Callers pass a named seed and a named/semantic offset instead of a
    // second hard-coded color for the other theme.
    inline QColor OffsetColor(
        const QColor& baseColor,
        const RgbOffset offset,
        const int alphaOverride = -1)
    {
        QColor adjustedColor(
            ClampChannel(baseColor.red() + offset.red),
            ClampChannel(baseColor.green() + offset.green),
            ClampChannel(baseColor.blue() + offset.blue),
            alphaOverride >= 0 ? ClampChannel(alphaOverride) : baseColor.alpha());
        return adjustedColor;
    }

    // ActiveThemeOffset 作用：根据当前主题只选择对应的一套 RGB 偏移量。
    // 入参为成对配置，返回深色或浅色分支，不执行任何颜色运算。
    inline RgbOffset ActiveThemeOffset(const ThemeRgbOffset& themeOffset)
    {
        return IsDarkModeEnabled() ? themeOffset.dark : themeOffset.light;
    }

    // ThemeOffsetColor 作用：使用同一基础色和两套独立偏移量生成当前主题颜色。
    // alphaOverride 为负数时保留基础色透明度，非负时覆盖透明度。
    inline QColor ThemeOffsetColor(
        const QColor& baseColor,
        const ThemeRgbOffset& themeOffset,
        const int alphaOverride = -1)
    {
        return OffsetColor(baseColor, ActiveThemeOffset(themeOffset), alphaOverride);
    }

    inline QColor OffsetColor(const QColor& baseColor, const int uniformOffset)
    {
        return OffsetColor(baseColor, UniformOffset(uniformOffset));
    }

    inline QColor WithAlpha(const QColor& baseColor, const int alphaValue)
    {
        return OffsetColor(baseColor, {}, alphaValue);
    }

    // BlendColors 作用：按 overlayWeight/255 把覆盖色混入基础色。
    // 用于“中性背景 + 强调色”的交互状态，避免再用固定蓝色 RGB 偏移破坏自定义主题色。
    inline QColor BlendColors(
        const QColor& baseColor,
        const QColor& overlayColor,
        const int overlayWeight)
    {
        const int safeWeight = ClampChannel(overlayWeight);
        const int baseWeight = 255 - safeWeight;
        const auto blendChannel = [baseWeight, safeWeight](
            const int baseChannel,
            const int overlayChannel) {
            return (baseChannel * baseWeight + overlayChannel * safeWeight + 127) / 255;
        };

        return QColor(
            blendChannel(baseColor.red(), overlayColor.red()),
            blendChannel(baseColor.green(), overlayColor.green()),
            blendChannel(baseColor.blue(), overlayColor.blue()),
            baseColor.alpha());
    }

    inline QColor ThemeLighterColor(const QColor& baseColor)
    {
        return ThemeOffsetColor(baseColor, UniformThemeOffset(10, 18));
    }

    inline QColor ThemeDarkerColor(const QColor& baseColor)
    {
        return ThemeOffsetColor(baseColor, UniformThemeOffset(-22, -28));
    }

    inline QColor WhiteColor(const int alphaValue = 255)
    {
        return QColor(255, 255, 255, ClampChannel(alphaValue));
    }

    inline QColor BlackColor(const int alphaValue = 255)
    {
        return QColor(0, 0, 0, ClampChannel(alphaValue));
    }

    inline QString ThemeColorName(const QColor& colorValue)
    {
        return colorValue.name(QColor::HexRgb).toUpper();
    }

    // HslLightness 作用：只取 HSL 明度分量。
    // 中性族的层次全部由明暗表达，把明度单独取出来，色相与饱和度才能交给主题去决定。
    inline int HslLightness(const QColor& colorValue)
    {
        int hue = 0;
        int saturation = 0;
        int lightness = 0;
        colorValue.getHsl(&hue, &saturation, &lightness);
        return lightness;
    }

    // ShiftLightness 作用：只移动 HSL 明度，色相与饱和度原样保留。
    // 灰阶颜色的色相是 -1，getHsl/setHsl 之间原样往返即可，不需要额外处理。
    inline QColor ShiftLightness(const QColor& baseColor, const int lightnessDelta)
    {
        int hue = 0;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        baseColor.getHsl(&hue, &saturation, &lightness, &alpha);

        QColor shiftedColor;
        shiftedColor.setHsl(hue, saturation, ClampChannel(lightness + lightnessDelta), alpha);
        return shiftedColor;
    }

    inline QString RgbaColorName(const QColor& colorValue, const int alphaValue)
    {
        return QStringLiteral("rgba(%1,%2,%3,%4)")
            .arg(colorValue.red())
            .arg(colorValue.green())
            .arg(colorValue.blue())
            .arg(ClampChannel(alphaValue));
    }

    inline double RelativeLuminance(const QColor& colorValue)
    {
        const auto linearize = [](const int channelValue) {
            const double channel = static_cast<double>(channelValue) / 255.0;
            return channel <= 0.03928
                ? channel / 12.92
                : std::pow((channel + 0.055) / 1.055, 2.4);
        };

        return 0.2126 * linearize(colorValue.red())
            + 0.7152 * linearize(colorValue.green())
            + 0.0722 * linearize(colorValue.blue());
    }

    inline double ContrastRatio(const QColor& firstColor, const QColor& secondColor)
    {
        const double firstLuminance = RelativeLuminance(firstColor);
        const double secondLuminance = RelativeLuminance(secondColor);
        const double brighter = qMax(firstLuminance, secondLuminance);
        const double darker = qMin(firstLuminance, secondLuminance);
        return (brighter + 0.05) / (darker + 0.05);
    }

    // EnsureTextContrast keeps the hue where possible, then moves only the
    // HSL lightness until the requested WCAG-style ratio is reached.
    inline QColor EnsureTextContrast(
        const QColor& preferredColor,
        const QColor& backgroundColor,
        const double minimumRatio = 4.5)
    {
        QColor candidate = preferredColor;
        candidate.setAlpha(255);
        if (ContrastRatio(candidate, backgroundColor) >= minimumRatio)
        {
            return candidate;
        }

        int hue = -1;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        candidate.getHsl(&hue, &saturation, &lightness, &alpha);

        const bool shouldLighten = RelativeLuminance(backgroundColor) < 0.5;
        const auto findAdjustedColor = [&](const bool lighten) -> QColor {
            for (int lightnessOffset = 4; lightnessOffset <= 255; lightnessOffset += 4)
            {
                QColor adjustedColor = candidate;
                const int adjustedLightness = lighten
                    ? qMin(255, lightness + lightnessOffset)
                    : qMax(0, lightness - lightnessOffset);
                adjustedColor.setHsl(hue, saturation, adjustedLightness, 255);
                if (ContrastRatio(adjustedColor, backgroundColor) >= minimumRatio)
                {
                    return adjustedColor;
                }
            }
            return QColor();
        };

        const QColor preferredDirectionColor = findAdjustedColor(shouldLighten);
        if (preferredDirectionColor.isValid())
        {
            return preferredDirectionColor;
        }

        const QColor oppositeDirectionColor = findAdjustedColor(!shouldLighten);
        if (oppositeDirectionColor.isValid())
        {
            return oppositeDirectionColor;
        }

        const QColor whiteColor = WhiteColor();
        const QColor blackColor = BlackColor();
        return ContrastRatio(whiteColor, backgroundColor) >= ContrastRatio(blackColor, backgroundColor)
            ? whiteColor
            : blackColor;
    }

    // EnsureTextContrastForBackgrounds 作用：让同一个前景色对多个候选背景同时可读。
    // 只对一种表面校准是不够的：同一个文字角色会落在窗口底、面板底、交替行底和
    // 静音底上，这些表面亮度并不相同，只满足其中一个时，在别的表面上就会糊成一片。
    // 处理：先看原色是否已经满足全部背景；不满足时保持色相，沿 HSL 亮度逐档搜索，
    //       取第一个对所有背景都达标的值；两个方向都失败时退回黑白里更稳的一个。
    inline QColor EnsureTextContrastForBackgrounds(
        const QColor& preferredColor,
        const QColor* backgroundColors,
        const int backgroundCount,
        const double minimumRatio = 4.5)
    {
        if (backgroundColors == nullptr || backgroundCount <= 0)
        {
            return preferredColor;
        }

        const auto satisfiesAll = [&](const QColor& candidateColor) {
            for (int index = 0; index < backgroundCount; ++index)
            {
                if (ContrastRatio(candidateColor, backgroundColors[index]) < minimumRatio)
                {
                    return false;
                }
            }
            return true;
        };

        QColor candidate = preferredColor;
        candidate.setAlpha(255);
        if (satisfiesAll(candidate))
        {
            return candidate;
        }

        int hue = -1;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        candidate.getHsl(&hue, &saturation, &lightness, &alpha);

        // 背景族整体偏暗就往亮处找，偏亮就往暗处找；取平均亮度判断方向。
        double luminanceSum = 0.0;
        for (int index = 0; index < backgroundCount; ++index)
        {
            luminanceSum += RelativeLuminance(backgroundColors[index]);
        }
        const bool shouldLighten = (luminanceSum / backgroundCount) < 0.5;

        const auto findAdjustedColor = [&](const bool lighten) -> QColor {
            for (int lightnessOffset = 4; lightnessOffset <= 255; lightnessOffset += 4)
            {
                QColor adjustedColor = candidate;
                const int adjustedLightness = lighten
                    ? qMin(255, lightness + lightnessOffset)
                    : qMax(0, lightness - lightnessOffset);
                adjustedColor.setHsl(hue, saturation, adjustedLightness, 255);
                if (satisfiesAll(adjustedColor))
                {
                    return adjustedColor;
                }
            }
            return QColor();
        };

        const QColor preferredDirectionColor = findAdjustedColor(shouldLighten);
        if (preferredDirectionColor.isValid())
        {
            return preferredDirectionColor;
        }
        const QColor oppositeDirectionColor = findAdjustedColor(!shouldLighten);
        if (oppositeDirectionColor.isValid())
        {
            return oppositeDirectionColor;
        }

        // 没有任何同色相亮度能同时满足全部背景（背景族本身跨度过大时会这样），
        // 退回黑白里“最差那一档更好”的一个，保证不出现完全糊掉的组合。
        const auto worstRatio = [&](const QColor& candidateColor) {
            double worst = 1000.0;
            for (int index = 0; index < backgroundCount; ++index)
            {
                worst = qMin(worst, ContrastRatio(candidateColor, backgroundColors[index]));
            }
            return worst;
        };
        return worstRatio(WhiteColor()) >= worstRatio(BlackColor()) ? WhiteColor() : BlackColor();
    }

    // ==============================
    // Theme state and neutral surfaces
    // ==============================

    // ==============================
    // Theme seed generation and per-role cache
    // ==============================

    // ThemeSeedGeneration 作用：深浅模式、强调色、主背景三个种子每变一次就自增。
    // 自定义主题下的角色求值要在多个背景之间做亮度搜索，单次可达十几微秒；而这些
    // 角色会在 paintEvent 和 item delegate 里被逐帧逐行调用。缓存以此计数器失效，
    // 换主题后立刻重算，平时直接命中。
    inline quint64 ThemeSeedGeneration = 1;

    // ThemePreviewSeeds 保存未应用的深浅模式、主体色和背景色，只供预览求值使用。
    // 无效颜色表示使用内置默认值；不改 QApplication、已应用种子或缓存代次。
    struct ThemePreviewSeeds
    {
        bool darkModeEnabled = false; // 预览当前选择的深浅模式。
        QColor primaryAccentColor; // 无效值表示默认主体色。
        QColor mainBackgroundColor; // 无效值表示当前模式的默认背景。
    };

    // ActiveThemePreviewSeeds 仅在当前线程的同步颜色计算范围内有效。
    inline thread_local const ThemePreviewSeeds* ActiveThemePreviewSeeds = nullptr;

    // ScopedThemePreview 在局部栈范围内借用种子，退出时恢复外层上下文。
    // 调用者须保证 seeds 在 scope 内存活，且不在范围内处理事件或应用设置。
    class ScopedThemePreview final
    {
    public:
        explicit ScopedThemePreview(const ThemePreviewSeeds& seeds)
            : m_previousSeeds(ActiveThemePreviewSeeds)
        {
            ActiveThemePreviewSeeds = &seeds;
        }

        ~ScopedThemePreview()
        {
            ActiveThemePreviewSeeds = m_previousSeeds;
        }

        ScopedThemePreview(const ScopedThemePreview&) = delete;
        ScopedThemePreview& operator=(const ScopedThemePreview&) = delete;

    private:
        const ThemePreviewSeeds* m_previousSeeds = nullptr; // 支持嵌套后恢复原计算环境。
    };

    inline void InvalidateThemeColorCache()
    {
        ++ThemeSeedGeneration;
    }

    // CachedThemeColor 作用：把一个角色的求值结果存进调用方给的槽位。
    // 槽位是该角色专属的 static thread_local 变量：thread_local 让后台线程
    // （日志、导出）各持一份，不必加锁，也不会读到别的线程算到一半的值。
    template <typename ComputeFunction>
    inline QColor CachedThemeColor(
        QColor& cachedColor,
        quint64& cachedGeneration,
        ComputeFunction computeFunction)
    {
        // 预览复用同一生产算法，但不读写已应用配色的角色缓存。
        if (ActiveThemePreviewSeeds != nullptr)
        {
            return computeFunction();
        }
        if (cachedGeneration != ThemeSeedGeneration || !cachedColor.isValid())
        {
            cachedColor = computeFunction();
            cachedGeneration = ThemeSeedGeneration;
        }
        return cachedColor;
    }

    inline const char* DarkModePropertyKey = "ksword_dark_mode_enabled";

    inline void SetDarkModeEnabled(const bool enabled)
    {
        if (qApp != nullptr)
        {
            qApp->setProperty(DarkModePropertyKey, enabled);
        }
        InvalidateThemeColorCache();
    }

    inline bool IsDarkModeEnabled()
    {
        if (ActiveThemePreviewSeeds != nullptr)
        {
            return ActiveThemePreviewSeeds->darkModeEnabled;
        }
        return qApp != nullptr && qApp->property(DarkModePropertyKey).toBool();
    }

    // 以下配置的 dark/light 分别是深色与浅色模式的独立数字。
    // 每个配置必须与其颜色函数使用的基础色保持一致，避免通道截断后变成纯黑或纯白。
    inline constexpr ThemeRgbOffset WindowOffset{
        { -245, -240, -233 },
        { -7, -4, 0 }
    };
    inline constexpr ThemeRgbOffset SurfaceOffset{
        { -238, -230, -219 },
        { 0, 0, 0 }
    };
    inline constexpr ThemeRgbOffset SurfaceAltOffset{
        { 7, 10, 14 },
        { -12, -7, 0 }
    };
    inline constexpr ThemeRgbOffset SurfaceMutedOffset{
        { 13, 18, 24 },
        { -29, -14, 0 }
    };
    inline constexpr ThemeRgbOffset BorderOffset{
        { 38, 55, 70 },
        { -65, -44, -22 }
    };
    inline constexpr ThemeRgbOffset BorderStrongOffset{
        { 55, 80, 102 },
        { -104, -65, -24 }
    };
    inline constexpr ThemeRgbOffset TextPrimaryOffset{
        { -18, -9, 0 },
        { -239, -220, -201 }
    };
    inline constexpr ThemeRgbOffset TextSecondaryOffset{
        { -76, -52, -11 },
        { -176, -156, -135 }
    };
    inline constexpr ThemeRgbOffset TextDisabledOffset{
        { -130, -109, -84 },
        { -129, -113, -95 }
    };
    inline constexpr ThemeRgbOffset PaletteDarkOffset{
        { 3, 5, 6 },
        { -111, -90, -67 }
    };

    inline QColor DefaultMainBackgroundColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            WhiteColor(),
            darkModeEnabled ? WindowOffset.dark : WindowOffset.light);
    }

    inline QColor DefaultSurfaceColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            WhiteColor(),
            darkModeEnabled ? SurfaceOffset.dark : SurfaceOffset.light);
    }

    inline QColor DefaultSurfaceAltColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            DefaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? SurfaceAltOffset.dark : SurfaceAltOffset.light);
    }

    inline QColor DefaultSurfaceMutedColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            DefaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? SurfaceMutedOffset.dark : SurfaceMutedOffset.light);
    }

    inline QColor DefaultBorderColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            DefaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? BorderOffset.dark : BorderOffset.light);
    }

    inline QColor DefaultBorderStrongColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            DefaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? BorderStrongOffset.dark : BorderStrongOffset.light);
    }

    inline QColor DefaultPaletteDarkColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            DefaultSurfaceColor(darkModeEnabled),
            darkModeEnabled ? PaletteDarkOffset.dark : PaletteDarkOffset.light);
    }

    inline QColor DefaultTextPrimaryColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            WhiteColor(),
            darkModeEnabled ? TextPrimaryOffset.dark : TextPrimaryOffset.light);
    }

    inline QColor DefaultTextSecondaryColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            WhiteColor(),
            darkModeEnabled ? TextSecondaryOffset.dark : TextSecondaryOffset.light);
    }

    inline QColor DefaultTextDisabledColor(const bool darkModeEnabled)
    {
        return OffsetColor(
            WhiteColor(),
            darkModeEnabled ? TextDisabledOffset.dark : TextDisabledOffset.light);
    }

    // CustomMainBackgroundColor 是整套中性背景调色板的独立种子：窗口、面板、
    // 表格、树、编辑器、对话框和边框都从它派生；强调色仍由 PrimaryBlueColor 单独控制。
    // 无效值表示继续使用当前深浅模式的内置中性调色板。
    inline QColor CustomMainBackgroundColor;

    // MainBackgroundSeed 返回当前计算上下文的背景种子，保存接口仍只修改全局配置。
    inline const QColor& MainBackgroundSeed()
    {
        return ActiveThemePreviewSeeds != nullptr
            ? ActiveThemePreviewSeeds->mainBackgroundColor
            : CustomMainBackgroundColor;
    }

    inline void SetMainBackgroundColor(const QString& customColorText)
    {
        const QColor requestedColor(customColorText.trimmed());
        CustomMainBackgroundColor = requestedColor.isValid()
            ? requestedColor.toRgb()
            : QColor();
        InvalidateThemeColorCache();
    }

    inline QColor ComputeMainBackgroundColor()
    {
        return MainBackgroundSeed().isValid()
            ? MainBackgroundSeed()
            : DefaultMainBackgroundColor(IsDarkModeEnabled());
    }

    inline QColor MainBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeMainBackgroundColor);
    }

    inline QColor WindowColor()
    {
        return MainBackgroundColor();
    }

    // NeutralRoleTone 作用：把一个内置中性角色搬到用户主背景的色调上，明度由调用方给定。
    //
    // 背景：内置深色中性族并不是中性灰，而是一整套深蓝灰 —— 窗口 (10,15,22)、
    // 边框 (55,80,106)、强边框 (72,105,138)，蓝通道比红通道高 12 到 66。
    // 原先按 RGB 通道差值整体平移到用户主背景，这个蓝调会被一并搬过去：主背景设成纯黑
    // 之后边框照样算出 (45,65,84)，于是黑灰主题的界面上到处是蓝色的边框和分隔线。
    //
    // 处理：色相取用户主背景的；饱和度按「用户主背景相对内置主背景」的比例缩放角色
    // 自身的饱和度。这里不能直接套用主背景的饱和度 —— HSL 在低明度端会把饱和度放得很大
    // （纯黑附近的 (10,15,22) 饱和度是 96，而边框自己只有 37），边框那种高明度角色套进去
    // 反而比内置更蓝。按比例缩放则是恒等的：用户主背景正好等于内置主背景时取值不变。
    inline QColor NeutralRoleTone(const QColor& defaultRoleColor, const int targetLightness)
    {
        int roleHue = 0;
        int roleSaturation = 0;
        int roleLightness = 0;
        defaultRoleColor.getHsl(&roleHue, &roleSaturation, &roleLightness);

        int backgroundHue = 0;
        int backgroundSaturation = 0;
        int backgroundLightness = 0;
        MainBackgroundColor().getHsl(&backgroundHue, &backgroundSaturation, &backgroundLightness);

        int defaultHue = 0;
        int defaultSaturation = 0;
        int defaultLightness = 0;
        DefaultMainBackgroundColor(IsDarkModeEnabled())
            .getHsl(&defaultHue, &defaultSaturation, &defaultLightness);

        const int scaledSaturation = defaultSaturation > 0
            ? ClampChannel(roleSaturation * backgroundSaturation / defaultSaturation)
            : 0;
        // 灰阶颜色的 HSL 色相是 -1（未定义），Qt 用它表示消色差。饱和度被缩到 0 时
        // 色相取什么都不影响取值，统一归到 -1，避免把一个假角度写进颜色。
        const int tonedHue = (backgroundHue < 0 || scaledSaturation == 0) ? -1 : backgroundHue;

        QColor tonedColor;
        tonedColor.setHsl(tonedHue, scaledSaturation, ClampChannel(targetLightness), 255);
        return tonedColor;
    }

    // RetintedNeutralColor 作用：保留角色自身明度，只把色调搬到用户主背景上。
    // 供文字角色使用：文字的明暗是绝对的（深色主题下就该亮），不跟着主背景平移。
    inline QColor RetintedNeutralColor(const QColor& defaultRoleColor)
    {
        return NeutralRoleTone(defaultRoleColor, HslLightness(defaultRoleColor));
    }

    // NeutralLayerMinimumSeparation 作用：去色之后中性族相邻层级的最小明度间距。
    //
    // 内置中性族的层次是「极小的明度差 + 递增的蓝调」两个维度撑起来的：深色主题下
    // Surface→PaletteDark 的明度只差 4（亮度对比度 1.031），PaletteDark→SurfaceAlt 差 6，
    // 人眼分辨不出 3% 的亮度差，真正在区分它们的是色差 19→22→26→30→51→66 的递增蓝调。
    // 主背景被设成灰阶时色相维度整个消失，这几档就会糊在一起 —— 这不是错觉，是把二维
    // 调色板投影到一维的必然结果。把相邻间距顶到这个值，最弱相邻对比度从 1.027 回到 1.067
    //（内置带色相时是 1.051），而最亮一档的明度不变，不会更刺眼。
    //
    // 它还顺带拆开了一类静默故障：去色会让不同语义的角色塌到同一个灰阶值，
    // ThemeColorRemap 按旧值查表就再也分不开它们，撞色的角色会被映射到别人的新值
    //（实测 ControlAccentColor 撞上 ControlOutlineColor，切回默认主题后交互控件整片失去强调色）。
    inline constexpr int NeutralLayerMinimumSeparation = 10;

    // NeutralLayerRank 作用：角色在中性族明暗阶梯上的位置，从主背景往外数，最近的是 1。
    // 不能写死序号：深浅主题的排序完全不同 —— 深色下 PaletteDark 紧贴 Surface（第 2 档），
    // 浅色下它是离背景最远的一档。这里按当前主题的内置取值现算。
    inline int NeutralLayerRank(const QColor& defaultRoleColor)
    {
        const bool darkModeEnabled = IsDarkModeEnabled();
        const int backgroundLightness = HslLightness(DefaultMainBackgroundColor(darkModeEnabled));
        const int roleDistance = qAbs(HslLightness(defaultRoleColor) - backgroundLightness);

        const QColor familyColors[] = {
            DefaultSurfaceColor(darkModeEnabled),
            DefaultPaletteDarkColor(darkModeEnabled),
            DefaultSurfaceAltColor(darkModeEnabled),
            DefaultSurfaceMutedColor(darkModeEnabled),
            DefaultBorderColor(darkModeEnabled),
            DefaultBorderStrongColor(darkModeEnabled)
        };

        int rank = 1;
        for (const QColor& familyColor : familyColors)
        {
            if (qAbs(HslLightness(familyColor) - backgroundLightness) < roleDistance)
            {
                ++rank;
            }
        }
        return rank;
    }

    // RebasedNeutralRoleColor 作用：把内置中性角色相对默认窗口的明度差，
    // 平移到用户的主背景种子。未自定义时直接返回原角色，保证默认主题像素不变。
    inline QColor RebasedNeutralRoleColor(const QColor& defaultRoleColor)
    {
        if (!MainBackgroundSeed().isValid())
        {
            return defaultRoleColor;
        }

        // 只搬明度差。搬 RGB 差值会把内置中性族的蓝调一起搬到用户主背景上，见 NeutralRoleTone。
        const int lightnessDelta =
            HslLightness(defaultRoleColor)
            - HslLightness(DefaultMainBackgroundColor(IsDarkModeEnabled()));

        // 补偿量随主背景的饱和度线性退场：主背景还带着色相时，色相仍在帮忙分辨层级，
        // 补了反而会偏离内置调校好的明度设计；饱和度等于内置主背景时补偿量正好归零。
        int backgroundHue = 0;
        int backgroundSaturation = 0;
        int backgroundLightness = 0;
        MainBackgroundColor().getHsl(&backgroundHue, &backgroundSaturation, &backgroundLightness);
        int defaultHue = 0;
        int defaultSaturation = 0;
        int defaultLightness = 0;
        DefaultMainBackgroundColor(IsDarkModeEnabled())
            .getHsl(&defaultHue, &defaultSaturation, &defaultLightness);
        const int compensationPermille = defaultSaturation > 0
            ? qBound(0, 1000 - backgroundSaturation * 1000 / defaultSaturation, 1000)
            : 1000;

        const int separation =
            NeutralLayerRank(defaultRoleColor)
            * NeutralLayerMinimumSeparation
            * compensationPermille / 1000;
        // 只放大距离，不改方向：浅色主题下 Surface 在主背景的亮侧、其余角色在暗侧，
        // 用符号跟随原始明度差才不会把某一档推到背景的另一边去。
        const int boostedDistance = qMax(qAbs(lightnessDelta), separation);
        const int targetLightness = lightnessDelta >= 0
            ? backgroundLightness + boostedDistance
            : backgroundLightness - boostedDistance;

        return NeutralRoleTone(defaultRoleColor, targetLightness);
    }

    inline QColor ComputeSurfaceColor()
    {
        return RebasedNeutralRoleColor(DefaultSurfaceColor(IsDarkModeEnabled()));
    }

    inline QColor SurfaceColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeSurfaceColor);
    }

    inline QColor ComputeSurfaceAltColor()
    {
        return RebasedNeutralRoleColor(DefaultSurfaceAltColor(IsDarkModeEnabled()));
    }

    inline QColor SurfaceAltColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeSurfaceAltColor);
    }

    inline QColor ComputeSurfaceMutedColor()
    {
        return RebasedNeutralRoleColor(DefaultSurfaceMutedColor(IsDarkModeEnabled()));
    }

    inline QColor SurfaceMutedColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeSurfaceMutedColor);
    }

    inline QColor ComputeBorderColor()
    {
        return RebasedNeutralRoleColor(DefaultBorderColor(IsDarkModeEnabled()));
    }

    inline QColor BorderColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeBorderColor);
    }

    inline QColor ComputeBorderStrongColor()
    {
        return RebasedNeutralRoleColor(DefaultBorderStrongColor(IsDarkModeEnabled()));
    }

    inline QColor BorderStrongColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeBorderStrongColor);
    }

    inline QColor ComputePaletteDarkColor()
    {
        return RebasedNeutralRoleColor(DefaultPaletteDarkColor(IsDarkModeEnabled()));
    }

    inline QColor PaletteDarkColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputePaletteDarkColor);
    }

    // NeutralSurfaceFamily 作用：列出通用文字角色真实会落到的四种中性表面。
    // 文字只对 SurfaceColor 校准时，自定义主背景一旦把 SurfaceAlt / SurfaceMuted
    // 推到别的亮度档，同一段文字在按钮、交替行和静音底上就会贴到背景里。
    // 出参写入调用方数组，返回有效元素个数，避免在 header 里引入容器依赖。
    inline int NeutralSurfaceFamily(QColor* surfaceBuffer)
    {
        surfaceBuffer[0] = MainBackgroundColor();
        surfaceBuffer[1] = SurfaceColor();
        surfaceBuffer[2] = SurfaceAltColor();
        surfaceBuffer[3] = SurfaceMutedColor();
        return 4;
    }

    // 以下三个角色只在用户自定义主背景时才做对比度校准：内置调色板的取值经过
    // 人工调校，默认主题必须保持原像素，不能被自动校准改动。
    inline QColor ComputeTextPrimaryColor()
    {
        const QColor defaultTextColor = DefaultTextPrimaryColor(IsDarkModeEnabled());
        if (!MainBackgroundSeed().isValid())
        {
            return defaultTextColor;
        }
        QColor surfaceBuffer[4];
        const int surfaceCount = NeutralSurfaceFamily(surfaceBuffer);
        // 内置深色文字色是蓝白的 (237,246,255)，对比度校准只动明度、保留色相，
        // 不先把色调搬到主背景上的话，纯黑灰主题的正文会一直泛蓝。
        return EnsureTextContrastForBackgrounds(
            RetintedNeutralColor(defaultTextColor), surfaceBuffer, surfaceCount);
    }

    inline QColor TextPrimaryColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeTextPrimaryColor);
    }

    inline QColor ComputeTextSecondaryColor()
    {
        const QColor defaultTextColor = DefaultTextSecondaryColor(IsDarkModeEnabled());
        if (!MainBackgroundSeed().isValid())
        {
            return defaultTextColor;
        }
        QColor surfaceBuffer[4];
        const int surfaceCount = NeutralSurfaceFamily(surfaceBuffer);
        // 次级文字是全项目蓝调最重的中性角色：内置取值 (179,203,244)，蓝通道比红通道高 65。
        return EnsureTextContrastForBackgrounds(
            RetintedNeutralColor(defaultTextColor), surfaceBuffer, surfaceCount);
    }

    inline QColor TextSecondaryColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeTextSecondaryColor);
    }

    inline QColor ComputeTextDisabledColor()
    {
        const QColor defaultTextColor = DefaultTextDisabledColor(IsDarkModeEnabled());
        if (!MainBackgroundSeed().isValid())
        {
            return defaultTextColor;
        }
        QColor surfaceBuffer[4];
        const int surfaceCount = NeutralSurfaceFamily(surfaceBuffer);
        // 禁用文字属于非关键信息，按 WCAG 图形/大字档 3.0 判定。
        return EnsureTextContrastForBackgrounds(
            RetintedNeutralColor(defaultTextColor), surfaceBuffer, surfaceCount, 3.0);
    }

    inline QColor TextDisabledColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeTextDisabledColor);
    }

    inline QColor ComputeMainBackgroundTextColor()
    {
        return EnsureTextContrast(TextPrimaryColor(), MainBackgroundColor());
    }

    inline QColor MainBackgroundTextColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeMainBackgroundTextColor);
    }

    inline QString WindowColorHex() { return ThemeColorName(WindowColor()); }
    inline QString MainBackgroundColorHex() { return ThemeColorName(MainBackgroundColor()); }
    inline QString MainBackgroundTextColorHex() { return ThemeColorName(MainBackgroundTextColor()); }
    inline QString SurfaceColorHex() { return ThemeColorName(SurfaceColor()); }
    inline QString SurfaceAltColorHex() { return ThemeColorName(SurfaceAltColor()); }
    inline QString SurfaceMutedColorHex() { return ThemeColorName(SurfaceMutedColor()); }
    inline QString BorderColorHex() { return ThemeColorName(BorderColor()); }
    inline QString BorderStrongColorHex() { return ThemeColorName(BorderStrongColor()); }
    inline QString TextPrimaryColorHex() { return ThemeColorName(TextPrimaryColor()); }
    inline QString TextSecondaryColorHex() { return ThemeColorName(TextSecondaryColor()); }
    inline QString TextDisabledColorHex() { return ThemeColorName(TextDisabledColor()); }

    // ==============================
    // Named accent seeds and offsets
    // ==============================

    enum class AccentRole
    {
        Blue,
        Purple,
        Green,
        Orange,
        Cyan,
        Yellow,
        Red,
        Teal,
        Indigo,
        Brown,
        Lime,
        Slate,
        Violet
    };

    inline QColor DefaultPrimaryAccentColor()
    {
        return QColor(67, 160, 255);
    }

    // PrimaryBlueColor 是强调色族的运行期种子。各角色先应用相对 RGB 偏移，
    // 再应用独立深浅偏移；自定义颜色因此覆盖图表、时间线和语义角色的全部来源。
    inline QColor PrimaryBlueColor = DefaultPrimaryAccentColor();

    inline QColor PrimaryAccentColor()
    {
        if (ActiveThemePreviewSeeds != nullptr)
        {
            const QColor& previewAccent = ActiveThemePreviewSeeds->primaryAccentColor;
            return previewAccent.isValid() ? previewAccent : DefaultPrimaryAccentColor();
        }
        return PrimaryBlueColor;
    }

    inline void SetPrimaryAccentColor(const QString& customColorText)
    {
        const QColor requestedColor(customColorText.trimmed());
        PrimaryBlueColor = requestedColor.isValid()
            ? requestedColor.toRgb()
            : DefaultPrimaryAccentColor();
        InvalidateThemeColorCache();
    }

    // AccentSeedOffset 作用：量化各角色相对于默认主题种子的 RGB 差值。
    // 默认种子 (67,160,255) 时逐通道精确还原原配色；修改主题色时角色跟随同一偏移链。
    inline constexpr RgbOffset AccentSeedOffset(const AccentRole role)
    {
        switch (role)
        {
        case AccentRole::Blue: return { 0, 0, 0 };
        case AccentRole::Purple: return { 117, -61, 0 };
        case AccentRole::Green: return { -20, -35, -205 };
        case AccentRole::Orange: return { 150, -41, -249 };
        case AccentRole::Cyan: return { -67, 28, -43 };
        case AccentRole::Yellow: return { 178, -2, -244 };
        case AccentRole::Red: return { 153, -110, -208 };
        case AccentRole::Teal: return { -67, -10, -119 };
        case AccentRole::Indigo: return { -4, -79, -74 };
        case AccentRole::Brown: return { 54, -75, -183 };
        case AccentRole::Lime: return { 72, 35, -181 };
        case AccentRole::Slate: return { 29, -35, -116 };
        case AccentRole::Violet: return { 54, -84, -45 };
        }
        return {};
    }

    // AccentSeed 作用：从运行期主题种子和命名角色偏移生成颜色，不保留固定双色分支。
    inline QColor AccentSeed(const AccentRole role)
    {
        return OffsetColor(PrimaryAccentColor(), AccentSeedOffset(role));
    }

    // AccentColor 作用：按深色、浅色两套独立亮度偏移生成强调色。
    // 调用方需要自定义亮度时必须同时传入 darkOffset 与 lightOffset，禁止复用单一数字。
    inline QColor AccentColor(
        const AccentRole role,
        const int darkOffset,
        const int lightOffset)
    {
        const QColor adjustedColor = ThemeOffsetColor(
            AccentSeed(role),
            UniformThemeOffset(darkOffset, lightOffset));
        // 默认角色保持既有像素；自定义种子通道截断后仍须让图表线/图形对表面可辨。
        return PrimaryAccentColor() == DefaultPrimaryAccentColor()
            ? adjustedColor
            : EnsureTextContrast(adjustedColor, SurfaceColor(), 3.0);
    }

    // 默认强调色也明确保留两套数字：深色背景提高亮度，浅色背景略微压低亮度。
    inline QColor AccentColor(const AccentRole role)
    {
        return AccentColor(role, 18, -8);
    }

    inline QColor AccentTextColor(
        const AccentRole role,
        const QColor& backgroundColor = QColor())
    {
        const QColor effectiveBackground = backgroundColor.isValid()
            ? backgroundColor
            : SurfaceColor();
        return EnsureTextContrast(AccentColor(role), effectiveBackground);
    }

    inline QString AccentHex(
        const AccentRole role,
        const int darkOffset,
        const int lightOffset)
    {
        return ThemeColorName(AccentColor(role, darkOffset, lightOffset));
    }

    inline QString AccentHex(const AccentRole role)
    {
        return ThemeColorName(AccentColor(role));
    }

    inline QColor ComputeSuccessBackgroundColor();
    inline QColor ComputeWarningBackgroundColor();
    inline QColor ComputeErrorBackgroundColor();

    // SemanticTextColor 作用：语义文字色必须同时在中性表面和自己的语义底色上可读。
    // 只对 SurfaceColor 校准时，同一个「成功绿」放到交替行底或成功底色上就会发灰。
    // semanticBackground 无效表示该语义没有专用底色，只校准中性表面族。
    // 默认调色板经过人工调校，不做自动校准，避免改动内置主题的既有像素。
    inline QColor SemanticTextColor(const AccentRole role, const QColor& semanticBackground)
    {
        const QColor preferredColor = AccentColor(role);
        if (!MainBackgroundSeed().isValid()
            && PrimaryAccentColor() == DefaultPrimaryAccentColor())
        {
            return EnsureTextContrast(preferredColor, SurfaceColor());
        }

        QColor backgroundBuffer[5];
        int backgroundCount = NeutralSurfaceFamily(backgroundBuffer);
        if (semanticBackground.isValid())
        {
            backgroundBuffer[backgroundCount] = semanticBackground;
            ++backgroundCount;
        }
        return EnsureTextContrastForBackgrounds(preferredColor, backgroundBuffer, backgroundCount);
    }

    inline QColor ErrorBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeErrorBackgroundColor);
    }

    inline QColor WarningBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeWarningBackgroundColor);
    }

    inline QColor SuccessBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeSuccessBackgroundColor);
    }

    inline QColor ComputeSuccessColor() { return SemanticTextColor(AccentRole::Green, SuccessBackgroundColor()); }

    inline QColor SuccessColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeSuccessColor);
    }
    inline QColor ComputeWarningColor() { return SemanticTextColor(AccentRole::Orange, WarningBackgroundColor()); }

    inline QColor WarningColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeWarningColor);
    }
    inline QColor ComputeErrorColor() { return SemanticTextColor(AccentRole::Red, ErrorBackgroundColor()); }

    inline QColor ErrorColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeErrorColor);
    }
    inline QColor ComputeInfoColor() { return SemanticTextColor(AccentRole::Blue, QColor()); }

    inline QColor InfoColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeInfoColor);
    }
    inline QString SuccessHex() { return ThemeColorName(SuccessColor()); }
    inline QString WarningHex() { return ThemeColorName(WarningColor()); }
    inline QString ErrorHex() { return ThemeColorName(ErrorColor()); }
    inline QString InfoHex() { return ThemeColorName(InfoColor()); }

    // 语义背景与编辑器状态色都使用独立的深浅 RGB 偏移，基础色统一为 SurfaceColor。
    inline constexpr ThemeRgbOffset SuccessBackgroundOffset{
        { 8, 32, 14 },
        { -32, 0, -28 }
    };
    inline constexpr ThemeRgbOffset WarningBackgroundOffset{
        { 38, 24, 4 },
        { 0, -24, -62 }
    };
    inline constexpr ThemeRgbOffset ErrorBackgroundOffset{
        { 36, 4, 4 },
        { 0, -31, -31 }
    };
    inline constexpr ThemeRgbOffset EditorMatchOffset{
        { 10, 28, 6 },
        { -8, -10, -42 }
    };
    inline constexpr ThemeRgbOffset EditorCurrentMatchOffset{
        { 20, 62, 10 },
        { -8, -42, -1 }
    };

    // ReadableStateBackgroundColor 作用：给行/块状态底色兜一道对正文色的对比度。
    // 这类底色是「SurfaceColor + 固定 RGB 偏移」，自定义主背景把 SurfaceColor 推到
    // 中等亮度时，加上偏移就会顶到正文色附近。此时必须调底色：正文色可能已经被
    // 推到接近纯白，再往上调也拉不开距离。默认调色板保持原像素，不做自动校准。
    // ReadableSurfaceColor 作用：把一个底色推离正文色与禁用文字色，直到两者都可读。
    //
    // 这里不能串联两次 EnsureTextContrast：那个函数按「参照色的绝对亮度」决定推向，
    // 深色主题下禁用文字亮度低于 0.5，它会判定要把底色调亮，正好把上一步调暗的结果
    // 顶回正文色附近。方向必须由底色与文字的相对亮度决定：底色本来在文字的暗侧，
    // 就继续往暗侧推，反之亦然。
    inline QColor ReadableSurfaceColor(const QColor& surfaceColor)
    {
        const QColor primaryTextColor = TextPrimaryColor();
        const QColor disabledTextColor = TextDisabledColor();
        const auto isReadable = [&](const QColor& candidateColor) {
            return ContrastRatio(candidateColor, primaryTextColor) >= 4.5
                && ContrastRatio(candidateColor, disabledTextColor) >= 3.0;
        };

        QColor candidate = surfaceColor;
        candidate.setAlpha(255);
        if (isReadable(candidate))
        {
            return candidate;
        }

        int hue = -1;
        int saturation = 0;
        int lightness = 0;
        int alpha = 255;
        candidate.getHsl(&hue, &saturation, &lightness, &alpha);
        const bool shouldDarken =
            RelativeLuminance(candidate) < RelativeLuminance(primaryTextColor);

        const auto findAdjustedColor = [&](const bool darken) -> QColor {
            for (int lightnessOffset = 4; lightnessOffset <= 255; lightnessOffset += 4)
            {
                QColor adjustedColor = candidate;
                const int adjustedLightness = darken
                    ? qMax(0, lightness - lightnessOffset)
                    : qMin(255, lightness + lightnessOffset);
                adjustedColor.setHsl(hue, saturation, adjustedLightness, 255);
                if (isReadable(adjustedColor))
                {
                    return adjustedColor;
                }
            }
            return QColor();
        };

        const QColor preferredDirectionColor = findAdjustedColor(shouldDarken);
        if (preferredDirectionColor.isValid())
        {
            return preferredDirectionColor;
        }
        const QColor oppositeDirectionColor = findAdjustedColor(!shouldDarken);
        if (oppositeDirectionColor.isValid())
        {
            return oppositeDirectionColor;
        }

        // 同色相的任何亮度都无法同时满足两个前景时，退到黑白里更稳的一个。
        const auto worstRatio = [&](const QColor& candidateColor) {
            return qMin(
                ContrastRatio(candidateColor, primaryTextColor),
                ContrastRatio(candidateColor, disabledTextColor));
        };
        return worstRatio(WhiteColor()) >= worstRatio(BlackColor()) ? WhiteColor() : BlackColor();
    }

    // ReadableStateBackgroundColor 作用：给行/块状态底色兜一道可读性。
    // 默认调色板保持原像素，只有自定义主背景时才校准。
    inline QColor ReadableStateBackgroundColor(const QColor& stateBackgroundColor)
    {
        if (!MainBackgroundSeed().isValid())
        {
            return stateBackgroundColor;
        }
        return ReadableSurfaceColor(stateBackgroundColor);
    }

    inline QColor ComputeSuccessBackgroundColor()
    {
        return ReadableStateBackgroundColor(
            ThemeOffsetColor(SurfaceColor(), SuccessBackgroundOffset));
    }

    inline QColor ComputeWarningBackgroundColor()
    {
        return ReadableStateBackgroundColor(
            ThemeOffsetColor(SurfaceColor(), WarningBackgroundOffset));
    }

    inline QColor ComputeErrorBackgroundColor()
    {
        return ReadableStateBackgroundColor(
            ThemeOffsetColor(SurfaceColor(), ErrorBackgroundOffset));
    }

    inline QColor ComputeEditorMatchColor()
    {
        return ReadableStateBackgroundColor(
            ThemeOffsetColor(SurfaceColor(), EditorMatchOffset));
    }

    inline QColor EditorMatchColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeEditorMatchColor);
    }

    inline QColor ComputeEditorCurrentMatchColor()
    {
        return ReadableStateBackgroundColor(
            ThemeOffsetColor(SurfaceColor(), EditorCurrentMatchOffset));
    }

    inline QColor EditorCurrentMatchColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeEditorCurrentMatchColor);
    }

    inline QColor ComputeEditorSelectionColor()
    {
        return AccentColor(AccentRole::Blue, -2, -28);
    }

    inline QColor EditorSelectionColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeEditorSelectionColor);
    }

    // 强调色可能被用户设置成高亮度颜色；选中文字必须根据实际强调色自适应，
    // 不能固定白字，否则亮绿色、黄色等背景上的可读性会明显下降。
    //
    // 带参版本用于「底色不是 PrimaryAccentColor 本身」的场合：编辑器选中块、
    // 括号匹配的错误红底、按钮按下态底色都不等于强调色，套用无参版本会把
    // 对强调色校准好的前景放到另一种底色上，重新贴成一团。
    inline QColor OnAccentColor(const QColor& accentBackgroundColor)
    {
        return EnsureTextContrast(TextPrimaryColor(), accentBackgroundColor);
    }

    inline QColor OnAccentColor()
    {
        return OnAccentColor(PrimaryAccentColor());
    }
    // 有独立交互底色时必须传实际颜色，不能沿用原始主体色的前景。
    inline QString OnAccentHex(const QColor& backgroundColor)
    {
        return ThemeColorName(OnAccentColor(backgroundColor));
    }
    inline QString OnAccentHex() { return OnAccentHex(PrimaryAccentColor()); }

    inline bool UsesBuiltInColorSeeds()
    {
        return !MainBackgroundSeed().isValid()
            && PrimaryAccentColor() == DefaultPrimaryAccentColor();
    }

    inline constexpr ThemeRgbOffset DefaultActiveTabBackgroundOffset{
        { 38, 55, 70 },
        { -65, -44, -22 }
    };

    // 默认主题保留原活动标签像素；自定义任一颜色后以强调色为主，
    // 避免互补色背景与主题色低比例混合成棕灰色。
    inline QColor ComputeActiveTabBackgroundColor()
    {
        if (UsesBuiltInColorSeeds())
        {
            return ThemeOffsetColor(SurfaceColor(), DefaultActiveTabBackgroundOffset);
        }
        return AccentColor(AccentRole::Blue, -18, -26);
    }

    inline QColor ActiveTabBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeActiveTabBackgroundColor);
    }

    inline QColor ComputeActiveTabTextColor()
    {
        return EnsureTextContrast(TextPrimaryColor(), ActiveTabBackgroundColor());
    }

    inline QColor ActiveTabTextColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeActiveTabTextColor);
    }

    inline QString ActiveTabBackgroundHex() { return ThemeColorName(ActiveTabBackgroundColor()); }
    inline QString ActiveTabTextHex() { return ThemeColorName(ActiveTabTextColor()); }

    // ==============================
    // Reusable chart roles
    // ==============================

    enum class PerformanceRole
    {
        Cpu,
        Memory,
        Disk,
        Network,
        Gpu,
        Read,
        Write,
        DedicatedMemory,
        SharedMemory,
        VideoEncode,
        VideoDecode,
        Copy
    };

    inline QColor PerformanceColor(const PerformanceRole role)
    {
        // 每个性能角色显式写出深色/浅色两套总偏移，避免共享亮度参数导致主题失真。
        switch (role)
        {
        case PerformanceRole::Cpu: return AccentColor(AccentRole::Blue, 40, 14);
        case PerformanceRole::Memory: return AccentColor(AccentRole::Purple);
        case PerformanceRole::Disk: return AccentColor(AccentRole::Green, 40, 14);
        case PerformanceRole::Network: return AccentColor(AccentRole::Orange, 26, 0);
        case PerformanceRole::Gpu: return AccentColor(AccentRole::Blue, 26, 0);
        case PerformanceRole::Read: return AccentColor(AccentRole::Blue, 30, 4);
        case PerformanceRole::Write: return AccentColor(AccentRole::Orange, 40, 14);
        case PerformanceRole::DedicatedMemory: return AccentColor(AccentRole::Blue, 30, 4);
        case PerformanceRole::SharedMemory: return AccentColor(AccentRole::Cyan, 22, -4);
        case PerformanceRole::VideoEncode: return AccentColor(AccentRole::Blue, 36, 10);
        case PerformanceRole::VideoDecode: return AccentColor(AccentRole::Blue, 48, 22);
        case PerformanceRole::Copy: return AccentColor(AccentRole::Cyan, 36, 10);
        }
        return AccentColor(AccentRole::Blue);
    }

    enum class TimelineRole
    {
        Process,
        Thread,
        Image,
        File,
        Registry,
        Network,
        Dns,
        PowerShell,
        Wmi,
        Security,
        Storage,
        Kernel
    };

    inline QColor TimelineColor(const TimelineRole role)
    {
        // 时间线角色同样独立配置两种主题，所有数值都是相对于 AccentSeed 的总偏移。
        switch (role)
        {
        case TimelineRole::Process: return AccentColor(AccentRole::Green, 40, 14);
        case TimelineRole::Thread: return AccentColor(AccentRole::Lime, 26, 0);
        case TimelineRole::Image: return AccentColor(AccentRole::Cyan, 28, 2);
        case TimelineRole::File: return AccentColor(AccentRole::Blue, 36, 10);
        case TimelineRole::Registry: return AccentColor(AccentRole::Purple, 8, -18);
        case TimelineRole::Network: return AccentColor(AccentRole::Orange, 36, 10);
        case TimelineRole::Dns: return AccentColor(AccentRole::Yellow, 26, 0);
        case TimelineRole::PowerShell: return AccentColor(AccentRole::Indigo, 36, 10);
        case TimelineRole::Wmi: return AccentColor(AccentRole::Teal, 28, 2);
        case TimelineRole::Security: return AccentColor(AccentRole::Red);
        case TimelineRole::Storage: return AccentColor(AccentRole::Brown, 26, 0);
        case TimelineRole::Kernel: return AccentColor(AccentRole::Slate, 26, 0);
        }
        return AccentColor(AccentRole::Blue);
    }

    // ==============================
    // Compatibility helpers used by existing style builders
    // ==============================

    // These compatibility values are intentionally palette roles: existing QSS
    // builders therefore follow the active light/dark palette at render time.
    inline const QString PrimaryBlueHex = QStringLiteral("palette(highlight)");
    inline const QString PrimaryBlueHoverHex = QStringLiteral("palette(highlight)");
    inline const QString PrimaryBluePressedHex = QStringLiteral("palette(highlight)");
    inline const QString PrimaryBlueBorderHex = QStringLiteral("palette(highlight)");
    inline const QString PrimaryBlueActiveHex = QStringLiteral("palette(highlight)");

    inline constexpr ThemeRgbOffset ExitedRowBackgroundOffset{
        { 26, 28, 28 },
        { -19, -13, -7 }
    };
    inline constexpr ThemeRgbOffset DefaultPrimaryBlueSubtleOffset{
        { 6, 28, 47 },
        { -21, -11, 0 }
    };
    inline constexpr ThemeRgbOffset DefaultPrimaryBlueSurfacePressedOffset{
        { -1, -1, 26 },
        { -41, -19, 0 }
    };

    inline QColor ComputePrimaryBlueSubtleColor()
    {
        if (UsesBuiltInColorSeeds())
        {
            return ThemeOffsetColor(SurfaceColor(), DefaultPrimaryBlueSubtleOffset);
        }
        // 混合权重必须低：subtle 的语义是「带一点强调色的表面」，不是强调色本身。
        // 原来的 160/128（63%/50%）会把它推到接近强调色的亮度，正文放上去就糊了；
        // 46/38（18%/15%）与内置分支 SurfaceColor+(6,28,47) 的观感一致。
        const QColor blendedColor = BlendColors(
            SurfaceColor(),
            PrimaryAccentColor(),
            IsDarkModeEnabled() ? 46 : 38);
        // 再兜一道：高饱和强调色混出的底色仍可能贴近正文色。这里调底色而不是调文字，
        // 免得为了一个局部背景把全局文字角色拉到极端。
        return ReadableSurfaceColor(blendedColor);
    }

    inline QColor PrimaryBlueSubtleColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputePrimaryBlueSubtleColor);
    }

    inline QString PrimaryBlueSubtleHex()
    {
        return ThemeColorName(PrimaryBlueSubtleColor());
    }

    inline QColor PrimaryBlueSolidHoverColor()
    {
        return AccentColor(AccentRole::Blue, 6, -20);
    }
    inline QString PrimaryBlueSolidHoverHex() { return ThemeColorName(PrimaryBlueSolidHoverColor()); }

    inline QColor ComputePrimaryBlueSurfacePressedColor()
    {
        if (UsesBuiltInColorSeeds())
        {
            return ThemeOffsetColor(SurfaceColor(), DefaultPrimaryBlueSurfacePressedOffset);
        }
        // 按下态要比 subtle 更明显，但同样是「表面」而不是强调色实心块：
        // 原来的 196/170（77%/67%）已经等同强调色，按钮上的文字会和底色贴到一起。
        const QColor blendedColor = BlendColors(
            SurfaceColor(),
            PrimaryAccentColor(),
            IsDarkModeEnabled() ? 72 : 60);
        return ReadableSurfaceColor(blendedColor);
    }

    inline QColor PrimaryBlueSurfacePressedColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputePrimaryBlueSurfacePressedColor);
    }

    // AccentButtonTextColor 作用：中性底按钮上那种「不填色、只用强调色写字」的按钮文字。
    // 这类按钮（权限徽章、R0 徽章、测试模式按钮）hover 时底色换成 PrimaryBlueSubtle、
    // pressed 时换成 PrimaryBlueSurfacePressed，而文字色全程不变，
    // 只对 SurfaceColor 校准的话，一按下去字就贴到底色里了。
    inline QColor ComputeAccentButtonTextColor()
    {
        QColor backgroundBuffer[3] = {
            SurfaceColor(),
            PrimaryBlueSubtleColor(),
            PrimaryBlueSurfacePressedColor()
        };
        return EnsureTextContrastForBackgrounds(AccentColor(AccentRole::Blue), backgroundBuffer, 3);
    }

    inline QColor AccentButtonTextColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeAccentButtonTextColor);
    }

    inline QString AccentButtonTextHex() { return ThemeColorName(AccentButtonTextColor()); }

    // 交互控件的边界和状态标记属于非文本信息，至少需要 3:1 对比度。
    // 这些角色专供复选框、单选框、滑块和滚动条使用，不能直接复用普通面板边框。
    inline QColor ComputeControlOutlineColor()
    {
        return EnsureTextContrast(BorderStrongColor(), SurfaceColor(), 3.0);
    }

    inline QColor ControlOutlineColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeControlOutlineColor);
    }

    // ControlAccentOutlineSeparation 作用：控件强调色必须比中性轮廓色亮/暗出来的明度距离。
    // 灰阶主题色下强调色和轮廓色会被同一道 3.0 校准推到同一个取值：复选框、单选框、
    // 滑块的选中填充色因此等于未选中的轮廓色，选中态整个看不出来。
    // 这个距离同时也让 ThemeColorRemap 能继续分开这两个角色 —— 它是按颜色值查表的，
    // 两个角色撞成同一个值之后，其中一个会被静默映射到另一个的新值。
    inline constexpr int ControlAccentOutlineSeparation = 26;

    inline QColor ComputeControlAccentColor()
    {
        const QColor accentColor = EnsureTextContrast(PrimaryAccentColor(), SurfaceColor(), 3.0);
        const QColor outlineColor = ControlOutlineColor();

        // 强调色要比轮廓更突出：深色主题往亮推，浅色主题往暗推。
        const int direction = IsDarkModeEnabled() ? 1 : -1;
        const int currentDistance = direction * (HslLightness(accentColor) - HslLightness(outlineColor));
        if (currentDistance >= ControlAccentOutlineSeparation)
        {
            // 彩色主题色下两者本来就分得开，取值保持不变。
            return accentColor;
        }

        const QColor separatedColor = ShiftLightness(
            accentColor,
            direction * ControlAccentOutlineSeparation - (HslLightness(accentColor) - HslLightness(outlineColor)));
        // 推开之后仍要守住对表面的 3.0 对比度，否则浅色主题往暗推可能反而贴上表面。
        return EnsureTextContrast(separatedColor, SurfaceColor(), 3.0);
    }

    inline QColor ControlAccentColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeControlAccentColor);
    }

    inline QColor ComputeControlAccentHoverColor()
    {
        return EnsureTextContrast(
            AccentColor(AccentRole::Blue, 6, -20),
            SurfaceColor(),
            3.0);
    }

    inline QColor ControlAccentHoverColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeControlAccentHoverColor);
    }

    inline QColor ComputeControlAccentPressedColor()
    {
        return EnsureTextContrast(
            PrimaryBlueSurfacePressedColor(),
            SurfaceColor(),
            3.0);
    }

    inline QColor ControlAccentPressedColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeControlAccentPressedColor);
    }

    inline QColor ComputeControlDisabledOutlineColor()
    {
        return EnsureTextContrast(TextDisabledColor(), SurfaceColor(), 3.0);
    }

    inline QColor ControlDisabledOutlineColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeControlDisabledOutlineColor);
    }

    inline QColor ComputeControlDisabledFillColor()
    {
        const QColor mutedAccentColor = BlendColors(
            SurfaceMutedColor(),
            ControlAccentColor(),
            IsDarkModeEnabled() ? 72 : 56);
        return EnsureTextContrast(mutedAccentColor, SurfaceColor(), 3.0);
    }

    inline QColor ControlDisabledFillColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeControlDisabledFillColor);
    }

    inline QColor MaximumContrastMonochromeColor(const QColor& backgroundColor)
    {
        return ContrastRatio(WhiteColor(), backgroundColor)
                >= ContrastRatio(BlackColor(), backgroundColor)
            ? WhiteColor()
            : BlackColor();
    }

    enum class DockTabState
    {
        Inactive,
        Hover,
        Active
    };

    // 主导航三态底面只使用背景种子的表面偏移，主题色仅用于强调前景与选中标记。
    // state 为普通/悬停/选中态；返回真实绘制底色，预览与ADS样式共用此入口。
    inline QColor DockTabBackgroundColor(const DockTabState state)
    {
        switch (state)
        {
        case DockTabState::Inactive:
            return SurfaceColor();
        case DockTabState::Hover:
            return SurfaceMutedColor();
        case DockTabState::Active:
            return SurfaceAltColor();
        }
        return SurfaceColor();
    }

    // 普通文字保持正文角色，悬停/选中文字从主题色派生，并对实际背景保持4.5:1。
    inline QColor DockTabTextColor(const DockTabState state)
    {
        const QColor preferred = state == DockTabState::Inactive
            ? TextPrimaryColor() : PrimaryAccentColor(); // 普通正文或强调前景的首选色。
        return EnsureTextContrast(preferred, DockTabBackgroundColor(state));
    }

    // 选中标记使用主题色；按背景偏移后的选中底面保证3:1，不反过来染色背景。
    inline QColor DockTabHighlightColor()
    {
        return EnsureTextContrast(PrimaryAccentColor(), DockTabBackgroundColor(DockTabState::Active), 3.0);
    }

    // Qt按钮有时在活动标签上仍请求Normal图标，故每个图形同时对三态保持3:1。
    // 禁用态混入当前导航底色，背景变化后重新校准，不能强求图标RGB保持不变。
    inline QColor DockTabGlyphColor(const DockTabState state, const bool disabled = false)
    {
        const QColor background = DockTabBackgroundColor(state);
        const QColor preferred = disabled
            ? BlendColors(background, PrimaryAccentColor(), 96)
            : PrimaryAccentColor();
        const QColor backgrounds[]{
            DockTabBackgroundColor(DockTabState::Inactive),
            DockTabBackgroundColor(DockTabState::Hover),
            DockTabBackgroundColor(DockTabState::Active) };
        return EnsureTextContrastForBackgrounds(preferred, backgrounds, 3, 3.0);
    }

    // 此块最后追加，覆盖背景图透明兜底；只影响ADS导航，不覆盖业务页面的QTabBar。
    // 父子控件与自绘hover必须共用上面的颜色，避免标签文字层露出背景色。
    inline QString DockNavigationStyleSheet()
    {
        return QStringLiteral(R"(
ads--CDockAreaTitleBar,ads--CDockAreaTabBar{ background:%1 !important;background-color:%1 !important;color:%2 !important;}
ads--CDockAreaTitleBar QToolButton,ads--CDockAreaTitleBar QPushButton{ background:%1 !important;background-color:%1 !important;color:%2 !important;border:none !important;}
ads--CDockAreaTitleBar QToolButton:hover,ads--CDockAreaTitleBar QPushButton:hover{ background:%3 !important;background-color:%3 !important;color:%4 !important;}
ads--CDockAreaTitleBar QToolButton:pressed,ads--CDockAreaTitleBar QPushButton:pressed{ background:%5 !important;background-color:%5 !important;color:%6 !important;}
ads--CDockAreaTitleBar QToolButton:disabled,ads--CDockAreaTitleBar QPushButton:disabled{ background:%1 !important;background-color:%1 !important;color:%2 !important;border:none !important;}
ads--CDockAreaTabBar{border:none !important;padding:0px;}
ads--CDockWidgetTab,ads--CAutoHideTab{ background:%1 !important;background-color:%1 !important;color:%2 !important; border:none !important;border-radius:0px !important; padding:3px 12px;margin:0px;min-height:22px;}
ads--CDockWidgetTab QLabel,ads--CDockWidgetTab QWidget,ads--CAutoHideTab QLabel,ads--CAutoHideTab QWidget{ background:transparent !important;background-color:transparent !important; color:%2 !important;}
ads--CDockWidgetTab:hover,ads--CAutoHideTab:hover,ads--CDockWidgetTab[kswordDockTab="true"]:hover,ads--CAutoHideTab[kswordAutoHideTab="true"]:hover,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover{ background:%3 !important;background-color:%3 !important;color:%4 !important;}
ads--CDockWidgetTab:hover QLabel,ads--CDockWidgetTab:hover QWidget,ads--CAutoHideTab:hover QLabel,ads--CAutoHideTab:hover QWidget,ads--CDockWidgetTab[kswordDockTab="true"]:hover QLabel,ads--CDockWidgetTab[kswordDockTab="true"]:hover QWidget,ads--CAutoHideTab[kswordAutoHideTab="true"]:hover QLabel,ads--CAutoHideTab[kswordAutoHideTab="true"]:hover QWidget,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover QLabel,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover QWidget,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover QLabel,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover QWidget{ background:transparent !important;background-color:transparent !important; color:%4 !important;}
ads--CDockWidgetTab[activeTab="true"],ads--CAutoHideTab[activeTab="true"],ads--CDockWidgetTab[activeTab="true"]:hover,ads--CAutoHideTab[activeTab="true"]:hover,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab[activeTab="true"]:hover,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab[activeTab="true"]:hover{ background:%5 !important;background-color:%5 !important;color:%6 !important; font-weight:700;}
ads--CDockWidgetTab[activeTab="true"],ads--CAutoHideTab[activeTab="true"],ads--CDockWidgetTab[activeTab="true"]:hover,ads--CAutoHideTab[activeTab="true"]:hover,ads--CDockWidgetTab[kswordDockTab="true"][activeTab="true"]:hover,ads--CAutoHideTab[kswordAutoHideTab="true"][activeTab="true"]:hover,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab[activeTab="true"]:hover,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab[activeTab="true"]:hover{border-bottom:2px solid %7 !important;padding-bottom:1px;}
ads--CDockWidgetTab[activeTab="true"] QLabel,ads--CDockWidgetTab[activeTab="true"] QWidget,ads--CAutoHideTab[activeTab="true"] QLabel,ads--CAutoHideTab[activeTab="true"] QWidget,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab[activeTab="true"]:hover QLabel,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab[activeTab="true"]:hover QWidget,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab[activeTab="true"]:hover QLabel,ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab[activeTab="true"]:hover QWidget{ background:transparent !important;background-color:transparent !important; color:%6 !important;}
)")
            .arg(ThemeColorName(DockTabBackgroundColor(DockTabState::Inactive)))
            .arg(ThemeColorName(DockTabTextColor(DockTabState::Inactive)))
            .arg(ThemeColorName(DockTabBackgroundColor(DockTabState::Hover)))
            .arg(ThemeColorName(DockTabTextColor(DockTabState::Hover)))
            .arg(ThemeColorName(DockTabBackgroundColor(DockTabState::Active)))
            .arg(ThemeColorName(DockTabTextColor(DockTabState::Active)))
            .arg(ThemeColorName(DockTabHighlightColor()));
    }

    // ControlGlyphColor 作用：让箭头/勾号等控件图形从主题色派生，并对实际底色保持 3:1。
    // disabled 为 true 时先混入中性底色降低强调程度；最后校准避免极端主题下图形消失。
    inline QColor ControlGlyphColor(const QColor& backgroundColor, const bool disabled = false)
    {
        const QColor preferredColor = disabled
            ? BlendColors(SurfaceMutedColor(), PrimaryAccentColor(), 96)
            : PrimaryAccentColor();
        return EnsureTextContrast(preferredColor, backgroundColor, 3.0);
    }

    inline QString ControlOutlineHex() { return ThemeColorName(ControlOutlineColor()); }
    inline QString ControlAccentHex() { return ThemeColorName(ControlAccentColor()); }
    inline QString ControlAccentHoverHex() { return ThemeColorName(ControlAccentHoverColor()); }
    inline QString ControlAccentPressedHex() { return ThemeColorName(ControlAccentPressedColor()); }
    inline QString ControlDisabledOutlineHex() { return ThemeColorName(ControlDisabledOutlineColor()); }
    inline QString ControlDisabledFillHex() { return ThemeColorName(ControlDisabledFillColor()); }

    // 以下这组返回的是 QSS 动态调色板角色，不是颜色值。它们只能写进样式表：
    // QLabel/QTextEdit 的富文本走 QTextDocument，其 CSS 解析器不认 palette(...)
    // （那是 QSS 专有扩展），整条声明会被忽略、文字退回继承色，而且不报任何错。
    // 富文本、QPainter 绘制、以及要传给别的进程的颜色，一律改用 *ColorHex()。
    inline QString SurfaceHex() { return QStringLiteral("palette(base)"); }
    inline QString SurfaceAltHex() { return QStringLiteral("palette(alternate-base)"); }
    inline QString BorderHex() { return QStringLiteral("palette(mid)"); }
    inline QString TextPrimaryHex() { return QStringLiteral("palette(text)"); }
    // 次级文字必须使用专用动态文字角色；palette(mid) 是边框色，在深色背景上对比度不足。
    inline QString TextSecondaryHex() { return QStringLiteral("palette(placeholder-text)"); }
    // OnAccentDynamicHex 作用：强调色之上的文字色，取 palette 角色而不是当场求值。
    // applyAppearanceSettings 把 QPalette::HighlightedText 设成了 OnAccentColor()，两者取值一致；
    // 区别是这个版本跟着主题切换走，适合写进构造期就一次性下发、之后不再重建的 QSS。
    inline QString OnAccentDynamicHex() { return QStringLiteral("palette(highlighted-text)"); }

    // 下面三个角色在 MainWindow::applyAppearanceSettings 里被写进 QApplication 调色板：
    //   QPalette::Window   = MainBackgroundColor()
    //   QPalette::WindowText = MainBackgroundTextColor()
    //   QPalette::Midlight = BorderStrongColor()
    // 因此这三种颜色本来就能用动态角色表达，取值与对应的 *ColorHex() 完全一致，
    // 区别只是跟着主题切换走。构造期一次性下发、之后不再重建的 QSS 应当优先用这一组。
    inline QString MainBackgroundHex() { return QStringLiteral("palette(window)"); }
    inline QString MainBackgroundTextHex() { return QStringLiteral("palette(window-text)"); }
    inline QString BorderStrongHex() { return QStringLiteral("palette(midlight)"); }

    // SurfaceMuted 与 TextDisabled 没有对应的动态角色：QSS 的 palette(...) 只能选当前
    // group 的角色，选不到 disabled group，而剩余空闲角色（light/bright-text/shadow）
    // 都会被 QStyle 用于原生控件的立体边框绘制，挪作他用会改变非 QSS 控件的外观。
    // 这两种颜色只能继续用 *ColorHex()，因此使用它们的页面必须自己具备重建入口
    // （changeEvent 处理 ApplicationPaletteChange，或每次显示时重新生成样式）。

    // ControlCornerRadius 作用：统一按钮、组合框本体及组合框 Popup 的外轮廓圆角。
    inline constexpr int ControlCornerRadius = 3;

    inline QString ThemedButtonStyle()
    {
        // 对话框和普通页面共用实心无线框状态色，几何仍保持原来的紧凑按钮尺寸。
        return ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
            + QStringLiteral(
                "QPushButton,QToolButton{border-radius:%1px;padding:4px 10px;font-weight:600;}")
                .arg(ControlCornerRadius);
    }
    // 单行输入、搜索与组合框共用中性表面；调用方可传独立页面的实际底色。
    // 正常态先从 SurfaceAlt/Muted 派生，底面对比不足时仅提高中性明暗差。
    inline QColor ControlInputSurfaceColor(
        const QColor& pageSurface = SurfaceColor(),
        const QColor& alternateSurface = SurfaceAltColor())
    {
        QColor surface = BlendColors(alternateSurface, SurfaceMutedColor(), 64);
        surface.setAlpha(255);
        if (ContrastRatio(surface, pageSurface) < 1.15)
        {
            const QColor contrastSeed = RelativeLuminance(pageSurface) < 0.25
                ? QColor(Qt::white) : QColor(Qt::black);
            surface = BlendColors(pageSurface, contrastSeed, 24);
        }
        return surface;
    }

    // 交互态用少量主题色形成反馈，保持与正常编辑面相同的视觉重量。
    inline QColor ControlInputHoverColor(const QColor& surface = ControlInputSurfaceColor())
    {
        return BlendColors(surface, ControlAccentColor(), 12);
    }

    inline QColor ControlInputFocusColor(const QColor& surface = ControlInputSurfaceColor())
    {
        return BlendColors(surface, ControlAccentColor(), 28);
    }

    // Popup 是独立窗口，保留柔和边界与不透明表面；输入框本身不用强调描边。
    inline QString ThemedComboBoxPopupViewStyle()
    {
        const QColor accentColor = ControlAccentColor(); // 选中项保持明确主题强调。
        const QColor surfaceColor = SurfaceAltColor(); // 菜单与输入面分别表达内容与编辑角色。
        const QColor hoverColor = ControlInputHoverColor(surfaceColor);
        const QColor backgrounds[] = {surfaceColor, hoverColor}; // 同一文字覆盖普通与悬停项。
        const QColor textColor = EnsureTextContrastForBackgrounds(TextPrimaryColor(), backgrounds, 2);
        return QStringLiteral(
            "QAbstractItemView{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  alternate-background-color:%1 !important;"
            "  color:%2 !important;"
            "  border:1px solid %3 !important;"
            "  border-radius:%7px;"
            "  selection-background-color:%5 !important;"
            "  selection-color:%6 !important;"
            "  outline:0;"
            "}"
            "QAbstractScrollArea::viewport{background:%1 !important;background-color:%1 !important;}"
            "QAbstractItemView::item{"
            "  background:%1 !important;background-color:%1 !important;color:%2 !important;"
            "  min-height:22px;padding:2px 6px;"
            "}"
            "QAbstractItemView::item:hover{background:%4 !important;background-color:%4 !important;color:%2 !important;}"
            "QAbstractItemView::item:selected{background:%5 !important;background-color:%5 !important;color:%6 !important;}")
            .arg(surfaceColor.name(), textColor.name(), BorderColorHex(), hoverColor.name(),
                accentColor.name(), OnAccentColor(accentColor).name())
            .arg(ControlCornerRadius);
    }

    inline QString ThemedComboBoxStyle()
    {
        const QColor surfaceColor = ControlInputSurfaceColor(); // 普通输入面与搜索/数值框一致。
        const QColor hoverColor = ControlInputHoverColor(surfaceColor);
        const QColor focusColor = ControlInputFocusColor(surfaceColor);
        const QColor mutedColor = SurfaceMutedColor(); // 禁用态保留可辨认的中性轮廓。
        const QColor backgrounds[] = {surfaceColor, hoverColor, focusColor};
        const QColor textColor = EnsureTextContrastForBackgrounds(TextPrimaryColor(), backgrounds, 3);
        const QColor disabledTextColor = EnsureTextContrast(TextDisabledColor(), mutedColor, 3.0);
        const QColor accentColor = ControlAccentColor(); // 选择区使用高对比强调，避免状态消失。
        const QString arrowResource = QStringLiteral(":/Icon/ks_control_down_white.svg");
        const QColor arrowColor = EnsureTextContrastForBackgrounds(
            ControlGlyphColor(surfaceColor), backgrounds, 3, 3.0);
        const QString arrowPath = ks::ui::ThemedControlGlyphPath(arrowResource, arrowColor);
        const QString disabledArrowPath = ks::ui::ThemedControlGlyphPath(
            arrowResource, ControlGlyphColor(mutedColor, true));

        // 外围与箭头区共用一个表面，取消第二层竖线和空心框；已有布局尺寸保持不变。
        return QStringLiteral(
            "QComboBox{"
            "  background:%1 !important;background-color:%1 !important;color:%4 !important;"
            "  border:none !important;border-radius:%12px;"
            "  padding:2px 24px 2px 6px;min-height:22px;"
            "  selection-background-color:%7 !important;selection-color:%8 !important;"
            "}"
            "QComboBox:hover{background:%2 !important;background-color:%2 !important;border:none !important;}"
            "QComboBox:focus,QComboBox:on{background:%3 !important;background-color:%3 !important;border:none !important;}"
            "QComboBox:disabled{background:%5 !important;background-color:%5 !important;color:%6 !important;border:none !important;}"
            "QComboBox::drop-down{background:transparent !important;border:none !important;width:20px;}"
            "QComboBox::drop-down:disabled{background:transparent !important;border:none !important;}"
            "QComboBox::down-arrow{"
            "  image:url(\"%9\");width:12px;height:12px;margin-right:4px;"
            "  subcontrol-origin:padding;subcontrol-position:center right;"
            "}"
            "QComboBox::down-arrow:disabled{image:url(\"%10\");}"
            // 可编辑 Combo 内部编辑器不能重新画出系统白框，也不能遮挡外围焦点底色。
            "QComboBox QLineEdit,QComboBox QLineEdit:hover,QComboBox QLineEdit:focus{"
            "  background:transparent !important;color:%4 !important;border:none !important;"
            "  selection-background-color:%7 !important;selection-color:%8 !important;"
            "}"
            "QComboBox QLineEdit:disabled{background:transparent !important;color:%6 !important;border:none !important;}"
            "QComboBox QAbstractItemView{"
            "  background:%1 !important;background-color:%1 !important;alternate-background-color:%1 !important;"
            "  color:%4 !important;border:1px solid %11 !important;border-radius:%12px;"
            "  selection-background-color:%7 !important;selection-color:%8 !important;outline:0;"
            "}"
            "QComboBox QAbstractItemView::viewport{background:%1 !important;background-color:%1 !important;}"
            "QComboBox QAbstractItemView::item{background:%1 !important;background-color:%1 !important;color:%4 !important;min-height:22px;padding:2px 6px;}"
            "QComboBox QAbstractItemView::item:hover{background:%2 !important;background-color:%2 !important;color:%4 !important;}"
            "QComboBox QAbstractItemView::item:selected{background:%7 !important;background-color:%7 !important;color:%8 !important;}")
            .arg(surfaceColor.name(), hoverColor.name(), focusColor.name(), textColor.name(), mutedColor.name(),
                disabledTextColor.name(), accentColor.name(), OnAccentColor(accentColor).name(), arrowPath)
            .arg(disabledArrowPath, BorderColorHex())
            .arg(ControlCornerRadius);
    }

    inline QString ContextMenuStyle()
    {
        return QStringLiteral(
            "QMenu{background-color:%1 !important;color:%2 !important;border:1px solid %3 !important;padding:3px;}"
            "QMenu::item{color:%2 !important;padding:5px 18px 5px 14px;background-color:transparent !important;}"
            "QMenu::item:selected{background-color:%4 !important;color:%5 !important;}"
            "QMenu::item:disabled{color:%6 !important;background-color:transparent !important;}"
            "QMenu::separator{height:1px;background-color:%3;margin:2px 6px;}")
            .arg(SurfaceColorHex())
            .arg(TextPrimaryColorHex())
            .arg(BorderColorHex())
            .arg(PrimaryBlueHex)
            .arg(OnAccentHex())
            .arg(TextDisabledColorHex());
    }

    inline QString OpaqueDialogStyle(const QString& dialogObjectName)
    {
        if (dialogObjectName.trimmed().isEmpty())
        {
            return QString();
        }

        return QStringLiteral(
            "QDialog#%1{background-color:palette(window) !important;color:palette(text) !important;}"
            "QDialog#%1 QPlainTextEdit,QDialog#%1 QTextEdit,QDialog#%1 QTreeWidget,"
            "QDialog#%1 QTableWidget,QDialog#%1 QAbstractScrollArea,QDialog#%1 QAbstractScrollArea::viewport{"
            "background-color:palette(base) !important;color:palette(text) !important;}"
            "QDialog#%1 QHeaderView::section{background:transparent !important;background-color:transparent !important;color:palette(text) !important;}"
            "QDialog#%1 QMenu{background-color:palette(base) !important;color:palette(text) !important;border:1px solid palette(mid) !important;}"
            "QDialog#%1 QMenu::item:selected{background-color:%2 !important;color:%3 !important;}"
            "QDialog#%1 QMenu::separator{height:1px;background-color:palette(mid) !important;}")
            .arg(dialogObjectName)
            .arg(PrimaryBlueHex)
            .arg(OnAccentHex());
    }

    inline QColor NewRowBackgroundColor() { return SuccessBackgroundColor(); }
    inline QColor ComputeExitedRowBackgroundColor()
    {
        return ReadableStateBackgroundColor(
            ThemeOffsetColor(SurfaceColor(), ExitedRowBackgroundOffset));
    }

    inline QColor ExitedRowBackgroundColor()
    {
        static thread_local QColor cachedColor;
        static thread_local quint64 cachedGeneration = 0;
        return CachedThemeColor(cachedColor, cachedGeneration, &ComputeExitedRowBackgroundColor);
    }
    inline QColor ExitedRowForegroundColor() { return TextSecondaryColor(); }
    inline QColor WarningAccentColor() { return WarningColor(); }
} // namespace KswordTheme
