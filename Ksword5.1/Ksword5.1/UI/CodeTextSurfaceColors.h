#pragma once

#include "../theme.h"
#include <QPalette>

namespace ks::ui
{
    // Shared surface roles for the editable and virtual read-only code views.
    // The application palette owns theme/background changes; these are values.
    struct CodeTextSurfaceColors
    {
        QColor base, gutter, gutterText, currentNumber, divider, currentLine;
    };
    inline CodeTextSurfaceColors CodeTextSurfaceColorsFor(const QPalette& palette)
    {
        CodeTextSurfaceColors colors;
        colors.base = palette.color(QPalette::Base);
        // QSS background:transparent can expose a transparent black Base.
        // Contrast calculations need the visible theme surface, not that RGB.
        if (colors.base.alpha() < 255)
            colors.base = KswordTheme::BlendColors(KswordTheme::SurfaceColor(), colors.base, colors.base.alpha());
        const QColor text = palette.color(QPalette::Text);
        const QColor accent = palette.color(QPalette::Highlight);
        colors.gutter = KswordTheme::IsDarkModeEnabled() ? colors.base : KswordTheme::WhiteColor();
        colors.gutterText = KswordTheme::EnsureTextContrast(KswordTheme::BlendColors(text, colors.gutter, 110), colors.gutter);
        colors.currentNumber = KswordTheme::EnsureTextContrast(accent, colors.gutter);
        colors.divider = KswordTheme::BlendColors(text, colors.gutter, 218);
        colors.currentLine = KswordTheme::WithAlpha(accent, 36);
        return colors;
    }
}
