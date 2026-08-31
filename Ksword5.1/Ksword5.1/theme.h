#pragma once

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

    // ==============================
    // Theme state and neutral surfaces
    // ==============================

    inline const char* DarkModePropertyKey = "ksword_dark_mode_enabled";

    inline void SetDarkModeEnabled(const bool enabled)
    {
        if (qApp != nullptr)
        {
            qApp->setProperty(DarkModePropertyKey, enabled);
        }
    }

    inline bool IsDarkModeEnabled()
    {
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

    inline void SetMainBackgroundColor(const QString& customColorText)
    {
        const QColor requestedColor(customColorText.trimmed());
        CustomMainBackgroundColor = requestedColor.isValid()
            ? requestedColor.toRgb()
            : QColor();
    }

    inline QColor MainBackgroundColor()
    {
        return CustomMainBackgroundColor.isValid()
            ? CustomMainBackgroundColor
            : DefaultMainBackgroundColor(IsDarkModeEnabled());
    }

    inline QColor WindowColor()
    {
        return MainBackgroundColor();
    }

    // RebasedNeutralRoleColor 作用：把内置中性角色相对默认窗口的 RGB 差值，
    // 平移到用户的主背景种子。未自定义时直接返回原角色，保证默认主题像素不变。
    inline QColor RebasedNeutralRoleColor(const QColor& defaultRoleColor)
    {
        if (!CustomMainBackgroundColor.isValid())
        {
            return defaultRoleColor;
        }

        const QColor defaultBackgroundColor = DefaultMainBackgroundColor(IsDarkModeEnabled());
        return OffsetColor(
            MainBackgroundColor(),
            {
                defaultRoleColor.red() - defaultBackgroundColor.red(),
                defaultRoleColor.green() - defaultBackgroundColor.green(),
                defaultRoleColor.blue() - defaultBackgroundColor.blue()
            });
    }

    inline QColor SurfaceColor()
    {
        return RebasedNeutralRoleColor(DefaultSurfaceColor(IsDarkModeEnabled()));
    }

    inline QColor SurfaceAltColor()
    {
        return RebasedNeutralRoleColor(DefaultSurfaceAltColor(IsDarkModeEnabled()));
    }

    inline QColor SurfaceMutedColor()
    {
        return RebasedNeutralRoleColor(DefaultSurfaceMutedColor(IsDarkModeEnabled()));
    }

    inline QColor BorderColor()
    {
        return RebasedNeutralRoleColor(DefaultBorderColor(IsDarkModeEnabled()));
    }

    inline QColor BorderStrongColor()
    {
        return RebasedNeutralRoleColor(DefaultBorderStrongColor(IsDarkModeEnabled()));
    }

    inline QColor PaletteDarkColor()
    {
        return RebasedNeutralRoleColor(DefaultPaletteDarkColor(IsDarkModeEnabled()));
    }

    inline QColor TextPrimaryColor()
    {
        const QColor defaultTextColor = DefaultTextPrimaryColor(IsDarkModeEnabled());
        return CustomMainBackgroundColor.isValid()
            ? EnsureTextContrast(defaultTextColor, SurfaceColor())
            : defaultTextColor;
    }

    inline QColor TextSecondaryColor()
    {
        const QColor defaultTextColor = DefaultTextSecondaryColor(IsDarkModeEnabled());
        return CustomMainBackgroundColor.isValid()
            ? EnsureTextContrast(defaultTextColor, SurfaceColor())
            : defaultTextColor;
    }

    inline QColor TextDisabledColor()
    {
        const QColor defaultTextColor = DefaultTextDisabledColor(IsDarkModeEnabled());
        return CustomMainBackgroundColor.isValid()
            ? EnsureTextContrast(defaultTextColor, SurfaceColor(), 3.0)
            : defaultTextColor;
    }

    inline QColor MainBackgroundTextColor()
    {
        return EnsureTextContrast(TextPrimaryColor(), MainBackgroundColor());
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

    // PrimaryBlueColor 是所有蓝色强调控件的运行期种子。用户自定义时只替换该种子，
    // 原有深浅主题偏移仍会继续作用，其他语义色不受影响。
    inline QColor PrimaryBlueColor = DefaultPrimaryAccentColor();

    inline QColor PrimaryAccentColor()
    {
        return PrimaryBlueColor;
    }

    inline void SetPrimaryAccentColor(const QString& customColorText)
    {
        const QColor requestedColor(customColorText.trimmed());
        PrimaryBlueColor = requestedColor.isValid()
            ? requestedColor.toRgb()
            : DefaultPrimaryAccentColor();
    }

    inline QColor AccentSeed(const AccentRole role)
    {
        switch (role)
        {
        case AccentRole::Blue: return PrimaryAccentColor();
        case AccentRole::Purple: return QColor(184, 99, 255);
        case AccentRole::Green: return QColor(47, 125, 50);
        case AccentRole::Orange: return QColor(217, 119, 6);
        case AccentRole::Cyan: return QColor(0, 188, 212);
        case AccentRole::Yellow: return QColor(245, 158, 11);
        case AccentRole::Red: return QColor(220, 50, 47);
        case AccentRole::Teal: return QColor(0, 150, 136);
        case AccentRole::Indigo: return QColor(63, 81, 181);
        case AccentRole::Brown: return QColor(121, 85, 72);
        case AccentRole::Lime: return QColor(139, 195, 74);
        case AccentRole::Slate: return QColor(96, 125, 139);
        case AccentRole::Violet: return QColor(121, 76, 210);
        }
        return PrimaryAccentColor();
    }

    // AccentColor 作用：按深色、浅色两套独立亮度偏移生成强调色。
    // 调用方需要自定义亮度时必须同时传入 darkOffset 与 lightOffset，禁止复用单一数字。
    inline QColor AccentColor(
        const AccentRole role,
        const int darkOffset,
        const int lightOffset)
    {
        return ThemeOffsetColor(
            AccentSeed(role),
            UniformThemeOffset(darkOffset, lightOffset));
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

    inline QColor SuccessColor() { return AccentTextColor(AccentRole::Green); }
    inline QColor WarningColor() { return AccentTextColor(AccentRole::Orange); }
    inline QColor ErrorColor() { return AccentTextColor(AccentRole::Red); }
    inline QColor InfoColor() { return AccentTextColor(AccentRole::Blue); }
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

    inline QColor SuccessBackgroundColor()
    {
        return ThemeOffsetColor(SurfaceColor(), SuccessBackgroundOffset);
    }

    inline QColor WarningBackgroundColor()
    {
        return ThemeOffsetColor(SurfaceColor(), WarningBackgroundOffset);
    }

    inline QColor ErrorBackgroundColor()
    {
        return ThemeOffsetColor(SurfaceColor(), ErrorBackgroundOffset);
    }

    inline QColor EditorMatchColor()
    {
        return ThemeOffsetColor(SurfaceColor(), EditorMatchOffset);
    }

    inline QColor EditorCurrentMatchColor()
    {
        return ThemeOffsetColor(SurfaceColor(), EditorCurrentMatchOffset);
    }

    inline QColor EditorSelectionColor()
    {
        return AccentColor(AccentRole::Blue, -2, -28);
    }

    // 强调色可能被用户设置成高亮度颜色；选中文字必须根据实际强调色自适应，
    // 不能固定白字，否则亮绿色、黄色等背景上的可读性会明显下降。
    inline QColor OnAccentColor()
    {
        return EnsureTextContrast(TextPrimaryColor(), PrimaryAccentColor());
    }
    inline QString OnAccentHex() { return ThemeColorName(OnAccentColor()); }

    inline bool UsesBuiltInColorSeeds()
    {
        return !CustomMainBackgroundColor.isValid()
            && PrimaryAccentColor() == DefaultPrimaryAccentColor();
    }

    inline constexpr ThemeRgbOffset DefaultActiveTabBackgroundOffset{
        { 38, 55, 70 },
        { -65, -44, -22 }
    };

    // 默认主题保留原活动标签像素；自定义任一颜色后以强调色为主，
    // 避免互补色背景与主题色低比例混合成棕灰色。
    inline QColor ActiveTabBackgroundColor()
    {
        if (UsesBuiltInColorSeeds())
        {
            return ThemeOffsetColor(SurfaceColor(), DefaultActiveTabBackgroundOffset);
        }
        return AccentColor(AccentRole::Blue, -18, -26);
    }

    inline QColor ActiveTabTextColor()
    {
        return EnsureTextContrast(TextPrimaryColor(), ActiveTabBackgroundColor());
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

    inline QColor PrimaryBlueSubtleColor()
    {
        if (UsesBuiltInColorSeeds())
        {
            return ThemeOffsetColor(SurfaceColor(), DefaultPrimaryBlueSubtleOffset);
        }
        return BlendColors(
            SurfaceColor(),
            PrimaryAccentColor(),
            IsDarkModeEnabled() ? 160 : 128);
    }

    inline QString PrimaryBlueSubtleHex()
    {
        return ThemeColorName(PrimaryBlueSubtleColor());
    }

    inline QString PrimaryBlueSolidHoverHex()
    {
        return AccentHex(AccentRole::Blue, 6, -20);
    }

    inline QColor PrimaryBlueSurfacePressedColor()
    {
        if (UsesBuiltInColorSeeds())
        {
            return ThemeOffsetColor(SurfaceColor(), DefaultPrimaryBlueSurfacePressedOffset);
        }
        return BlendColors(
            SurfaceColor(),
            PrimaryAccentColor(),
            IsDarkModeEnabled() ? 196 : 170);
    }

    // 交互控件的边界和状态标记属于非文本信息，至少需要 3:1 对比度。
    // 这些角色专供复选框、单选框、滑块和滚动条使用，不能直接复用普通面板边框。
    inline QColor ControlOutlineColor()
    {
        return EnsureTextContrast(BorderStrongColor(), SurfaceColor(), 3.0);
    }

    inline QColor ControlAccentColor()
    {
        return EnsureTextContrast(PrimaryAccentColor(), SurfaceColor(), 3.0);
    }

    inline QColor ControlAccentHoverColor()
    {
        return EnsureTextContrast(
            AccentColor(AccentRole::Blue, 6, -20),
            SurfaceColor(),
            3.0);
    }

    inline QColor ControlAccentPressedColor()
    {
        return EnsureTextContrast(
            PrimaryBlueSurfacePressedColor(),
            SurfaceColor(),
            3.0);
    }

    inline QColor ControlDisabledOutlineColor()
    {
        return EnsureTextContrast(TextDisabledColor(), SurfaceColor(), 3.0);
    }

    inline QColor ControlDisabledFillColor()
    {
        const QColor mutedAccentColor = BlendColors(
            SurfaceMutedColor(),
            ControlAccentColor(),
            IsDarkModeEnabled() ? 72 : 56);
        return EnsureTextContrast(mutedAccentColor, SurfaceColor(), 3.0);
    }

    inline QColor MaximumContrastMonochromeColor(const QColor& backgroundColor)
    {
        return ContrastRatio(WhiteColor(), backgroundColor)
                >= ContrastRatio(BlackColor(), backgroundColor)
            ? WhiteColor()
            : BlackColor();
    }

    inline QString ControlOutlineHex() { return ThemeColorName(ControlOutlineColor()); }
    inline QString ControlAccentHex() { return ThemeColorName(ControlAccentColor()); }
    inline QString ControlAccentHoverHex() { return ThemeColorName(ControlAccentHoverColor()); }
    inline QString ControlAccentPressedHex() { return ThemeColorName(ControlAccentPressedColor()); }
    inline QString ControlDisabledOutlineHex() { return ThemeColorName(ControlDisabledOutlineColor()); }
    inline QString ControlDisabledFillHex() { return ThemeColorName(ControlDisabledFillColor()); }

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

    // ControlCornerRadius 作用：统一按钮、组合框本体及组合框 Popup 的外轮廓圆角。
    inline constexpr int ControlCornerRadius = 3;

    inline QString ThemedButtonStyle()
    {
        return QStringLiteral(
            "QPushButton,QToolButton{"
            "background-color:%1 !important;color:%2 !important;border:1px solid %3 !important;"
            "border-radius:%8px;padding:4px 10px;font-weight:600;}"
            "QPushButton:hover,QToolButton:hover{background-color:%4 !important;color:%5 !important;border-color:%4 !important;}"
            "QPushButton:pressed,QToolButton:pressed{background-color:%6 !important;color:%5 !important;border-color:%6 !important;}"
            "QPushButton:disabled,QToolButton:disabled{background-color:%1 !important;color:%7 !important;border-color:%3 !important;}")
            .arg(SurfaceAltHex())
            .arg(TextPrimaryHex())
            .arg(BorderHex())
            .arg(PrimaryBlueSolidHoverHex())
            .arg(OnAccentHex())
            .arg(PrimaryBluePressedHex)
            .arg(TextSecondaryHex())
            .arg(ControlCornerRadius);
    }

    // ThemedComboBoxPopupViewStyle / ThemedComboBoxStyle 作用：
    // - 为普通、可编辑及嵌入表格的组合框提供同一套不透明表面、箭头区和 Popup 列表规则；
    // - Popup 使用显式 base 表面，避免独立顶层窗口回退到平台默认的透明/黑色背景；
    // - 所有交互边框和选中态使用 Control* 角色，随自定义主题色和主背景色同步更新。
    inline QString ThemedComboBoxPopupViewStyle()
    {
        const QColor accentColor = ControlAccentColor();
        const QString surfaceColor = SurfaceColorHex();
        const QString textColor = TextPrimaryColorHex();
        const QString outlineColor = ControlOutlineHex();
        const QString hoverColor = SurfaceAltColorHex();
        const QString accentColorText = ThemeColorName(accentColor);
        const QString accentTextColor = ThemeColorName(MaximumContrastMonochromeColor(accentColor));

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
            "QAbstractScrollArea::viewport{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "}"
            "QAbstractItemView::item{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "  min-height:22px;"
            "  padding:2px 6px;"
            "}"
            "QAbstractItemView::item:hover{"
            "  background:%4 !important;"
            "  background-color:%4 !important;"
            "  color:%2 !important;"
            "}"
            "QAbstractItemView::item:selected{"
            "  background:%5 !important;"
            "  background-color:%5 !important;"
            "  color:%6 !important;"
            "}")
            .arg(surfaceColor)
            .arg(textColor)
            .arg(outlineColor)
            .arg(hoverColor)
            .arg(accentColorText)
            .arg(accentTextColor)
            .arg(ControlCornerRadius);
    }

    inline QString ThemedComboBoxStyle()
    {
        const QColor accentColor = ControlAccentColor();
        const QString surfaceColor = SurfaceColorHex();
        const QString surfaceAltColor = SurfaceAltColorHex();
        const QString surfaceMutedColor = SurfaceMutedColorHex();
        const QString textColor = TextPrimaryColorHex();
        const QString disabledTextColor = TextDisabledColorHex();
        const QString outlineColor = ControlOutlineHex();
        const QString accentColorText = ThemeColorName(accentColor);
        const QString accentHoverColor = ControlAccentHoverHex();
        const QString accentPressedColor = ControlAccentPressedHex();
        const QString disabledOutlineColor = ControlDisabledOutlineHex();
        const QString accentTextColor = ThemeColorName(MaximumContrastMonochromeColor(accentColor));
        const auto arrowPathForBackground = [](const QColor& backgroundColor) {
            return MaximumContrastMonochromeColor(backgroundColor) == WhiteColor()
                ? QStringLiteral(":/Icon/ks_control_down_white.svg")
                : QStringLiteral(":/Icon/ks_control_down_black.svg");
        };
        const QString arrowPath = arrowPathForBackground(SurfaceAltColor());
        const QString disabledArrowPath = arrowPathForBackground(SurfaceMutedColor());

        return QStringLiteral(
            "QComboBox{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%4 !important;"
            "  border:1px solid %6 !important;"
            "  border-radius:%14px;"
            "  padding:2px 24px 2px 6px;"
            "  min-height:22px;"
            "  selection-background-color:%7 !important;"
            "  selection-color:%11 !important;"
            "}"
            "QComboBox:hover{"
            "  background:%2 !important;"
            "  background-color:%2 !important;"
            "  color:%4 !important;"
            "  border-color:%8 !important;"
            "}"
            "QComboBox:focus,QComboBox:on{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%4 !important;"
            "  border-color:%9 !important;"
            "}"
            "QComboBox:disabled{"
            "  background:%3 !important;"
            "  background-color:%3 !important;"
            "  color:%5 !important;"
            "  border-color:%10 !important;"
            "}"
            "QComboBox::drop-down{"
            "  background:%2 !important;"
            "  background-color:%2 !important;"
            "  border:none !important;"
            "  border-left:1px solid %6 !important;"
            "  width:20px;"
            "}"
            "QComboBox::drop-down:disabled{"
            "  background:%3 !important;"
            "  background-color:%3 !important;"
            "  border-left-color:%10 !important;"
            "}"
            "QComboBox::down-arrow{"
            "  image:url(%12);"
            "  width:12px;"
            "  height:12px;"
            "  margin-right:4px;"
            "  subcontrol-origin:padding;"
            "  subcontrol-position:center right;"
            "}"
            "QComboBox::down-arrow:disabled{image:url(%13);}"
            "QComboBox QAbstractItemView{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  alternate-background-color:%1 !important;"
            "  color:%4 !important;"
            "  border:1px solid %6 !important;"
            "  border-radius:%14px;"
            "  selection-background-color:%7 !important;"
            "  selection-color:%11 !important;"
            "  outline:0;"
            "}"
            "QComboBox QAbstractItemView::viewport{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "}"
            "QComboBox QAbstractItemView::item{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%4 !important;"
            "  min-height:22px;"
            "  padding:2px 6px;"
            "}"
            "QComboBox QAbstractItemView::item:hover{"
            "  background:%2 !important;"
            "  background-color:%2 !important;"
            "  color:%4 !important;"
            "}"
            "QComboBox QAbstractItemView::item:selected{"
            "  background:%7 !important;"
            "  background-color:%7 !important;"
            "  color:%11 !important;"
            "}")
            .arg(surfaceColor)
            .arg(surfaceAltColor)
            .arg(surfaceMutedColor)
            .arg(textColor)
            .arg(disabledTextColor)
            .arg(outlineColor)
            .arg(accentColorText)
            .arg(accentHoverColor)
            .arg(accentPressedColor)
            .arg(disabledOutlineColor)
            .arg(accentTextColor)
            .arg(arrowPath)
            .arg(disabledArrowPath)
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
    inline QColor ExitedRowBackgroundColor()
    {
        return ThemeOffsetColor(SurfaceColor(), ExitedRowBackgroundOffset);
    }
    inline QColor ExitedRowForegroundColor() { return TextSecondaryColor(); }
    inline QColor WarningAccentColor() { return WarningColor(); }
} // namespace KswordTheme
