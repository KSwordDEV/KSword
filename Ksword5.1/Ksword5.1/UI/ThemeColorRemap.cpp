#include "ThemeColorRemap.h"
#include "ThemeBinding.h"

#include "../theme.h"

#include <QApplication>
#include <QBrush>
#include <QHash>
#include <QPalette>
#include <QPointer>
#include <QSet>
#include <QWidget>
#include <QWidgetList>

namespace ks::ui
{
    namespace
    {
        // AppendThemeColorSeries 作用：把带枚举的成组角色按固定顺序追加进 token 表。
        // 两次采集必须走同一段代码，下标才能一一对应。
        void AppendThemeColorSeries(QList<QColor>& colors)
        {
            using KswordTheme::AccentRole;
            using KswordTheme::PerformanceRole;
            using KswordTheme::TimelineRole;

            const AccentRole accentRoles[] = {
                AccentRole::Blue, AccentRole::Purple, AccentRole::Green, AccentRole::Orange,
                AccentRole::Cyan, AccentRole::Yellow, AccentRole::Red, AccentRole::Teal,
                AccentRole::Indigo, AccentRole::Brown, AccentRole::Lime, AccentRole::Slate,
                AccentRole::Violet
            };
            for (const AccentRole role : accentRoles)
            {
                colors.append(KswordTheme::AccentColor(role));
                colors.append(KswordTheme::AccentTextColor(role));
            }

            const PerformanceRole performanceRoles[] = {
                PerformanceRole::Cpu, PerformanceRole::Memory, PerformanceRole::Disk,
                PerformanceRole::Network, PerformanceRole::Gpu, PerformanceRole::Read,
                PerformanceRole::Write, PerformanceRole::DedicatedMemory,
                PerformanceRole::SharedMemory, PerformanceRole::VideoEncode,
                PerformanceRole::VideoDecode, PerformanceRole::Copy
            };
            for (const PerformanceRole role : performanceRoles)
            {
                colors.append(KswordTheme::PerformanceColor(role));
            }

            const TimelineRole timelineRoles[] = {
                TimelineRole::Process, TimelineRole::Thread, TimelineRole::Image,
                TimelineRole::File, TimelineRole::Registry, TimelineRole::Network,
                TimelineRole::Dns, TimelineRole::PowerShell, TimelineRole::Wmi,
                TimelineRole::Security, TimelineRole::Storage, TimelineRole::Kernel
            };
            for (const TimelineRole role : timelineRoles)
            {
                colors.append(KswordTheme::TimelineColor(role));
            }
        }

        // CollectThemeColors 作用：求值全部“调用即固化”的主题角色。
        // 只收录静态 token；palette(...) 形式的动态 token 由 Qt 自行跟随，不需要重写。
        // 登记顺序即撞色时的优先级，从大面积到小面积：中性表面 -> 文字 -> 交互控件
        // -> 强调色 -> 语义色 -> 编辑器与行状态 -> 图表配色。新增角色请按这个梯度插入。
        QList<QColor> CollectThemeColors()
        {
            QList<QColor> colors;
            colors.reserve(96);

            colors.append(KswordTheme::MainBackgroundColor());
            colors.append(KswordTheme::MainBackgroundTextColor());
            colors.append(KswordTheme::SurfaceColor());
            colors.append(KswordTheme::SurfaceAltColor());
            colors.append(KswordTheme::SurfaceMutedColor());
            colors.append(KswordTheme::BorderColor());
            colors.append(KswordTheme::BorderStrongColor());
            colors.append(KswordTheme::PaletteDarkColor());
            colors.append(KswordTheme::TextPrimaryColor());
            colors.append(KswordTheme::TextSecondaryColor());
            colors.append(KswordTheme::TextDisabledColor());
            colors.append(KswordTheme::OnAccentColor());

            colors.append(KswordTheme::ControlOutlineColor());
            colors.append(KswordTheme::ControlAccentColor());
            colors.append(KswordTheme::ControlAccentHoverColor());
            colors.append(KswordTheme::ControlAccentPressedColor());
            colors.append(KswordTheme::ControlDisabledOutlineColor());
            colors.append(KswordTheme::ControlDisabledFillColor());

            colors.append(KswordTheme::PrimaryAccentColor());
            // AccentColor(Blue) 是全项目用量最大的强调色写法（AccentHex(AccentRole::Blue)）。
            // 它在深色主题里与 InfoColor 取值相同，却在换主题时走向不同的新值，
            // 必须排在语义色之前，否则这批调用会被判给只有个位数用量的 InfoColor。
            colors.append(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue));
            colors.append(KswordTheme::AccentButtonTextColor());
            colors.append(KswordTheme::PrimaryBlueSubtleColor());
            colors.append(KswordTheme::PrimaryBlueSurfacePressedColor());
            colors.append(KswordTheme::ActiveTabBackgroundColor());
            colors.append(KswordTheme::ActiveTabTextColor());

            colors.append(KswordTheme::SuccessColor());
            colors.append(KswordTheme::WarningColor());
            colors.append(KswordTheme::ErrorColor());
            colors.append(KswordTheme::InfoColor());
            colors.append(KswordTheme::SuccessBackgroundColor());
            colors.append(KswordTheme::WarningBackgroundColor());
            colors.append(KswordTheme::ErrorBackgroundColor());

            colors.append(KswordTheme::EditorMatchColor());
            colors.append(KswordTheme::EditorCurrentMatchColor());
            colors.append(KswordTheme::EditorSelectionColor());
            colors.append(KswordTheme::NewRowBackgroundColor());
            colors.append(KswordTheme::ExitedRowBackgroundColor());
            colors.append(KswordTheme::ExitedRowForegroundColor());

            // 项目里实际用到的强调色亮度变体：它们不是默认偏移，必须显式登记。
            colors.append(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, 6, -20));
            colors.append(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -12, -38));
            colors.append(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -18, -26));
            colors.append(KswordTheme::AccentTextColor(
                KswordTheme::AccentRole::Red,
                KswordTheme::BlackColor()));

            AppendThemeColorSeries(colors);
            return colors;
        }

        // BuildColorMapping 作用：由“旧值 -> 新值”建立重写表。
        // 不同角色在某个主题下取到同一个旧值是常态，例如内置深色主题里
        // BorderColor 与 ActiveTabBackgroundColor 的偏移完全相同；换主题后两者却走向
        // 不同的新值。此时按 CollectThemeColors 的登记顺序取第一个新值：该顺序是
        // 刻意排的优先级，中性表面、边框和文字排在强调色与图表色之前，
        // 因为它们决定了界面绝大部分面积。整条跳过会让这些主色一起失去跟随，
        // 代价远大于让个别小面积特例跟着主色走。
        QHash<QRgb, QRgb> BuildColorMapping(
            const QList<QString>& previousColorTexts,
            const QList<QColor>& currentColors,
            int* ambiguousColorCount)
        {
            QHash<QRgb, QRgb> preferredMapping;
            QSet<QRgb> ambiguousColors;
            const int pairCount = qMin(previousColorTexts.size(), currentColors.size());
            for (int index = 0; index < pairCount; ++index)
            {
                const QColor previousColor(previousColorTexts.at(index));
                const QColor currentColor = currentColors.at(index);
                if (!previousColor.isValid() || !currentColor.isValid())
                {
                    continue;
                }
                const QRgb previousValue =
                    qRgb(previousColor.red(), previousColor.green(), previousColor.blue());
                const QRgb currentValue =
                    qRgb(currentColor.red(), currentColor.green(), currentColor.blue());

                const auto existingIterator = preferredMapping.constFind(previousValue);
                if (existingIterator == preferredMapping.constEnd())
                {
                    preferredMapping.insert(previousValue, currentValue);
                    continue;
                }
                if (existingIterator.value() != currentValue)
                {
                    ambiguousColors.insert(previousValue);
                }
            }

            QHash<QRgb, QRgb> colorMapping;
            for (auto iterator = preferredMapping.constBegin();
                iterator != preferredMapping.constEnd();
                ++iterator)
            {
                // 取值没变的角色不需要重写，留在表里只会拖慢扫描。
                if (iterator.value() != iterator.key())
                {
                    colorMapping.insert(iterator.key(), iterator.value());
                }
            }

            if (ambiguousColorCount != nullptr)
            {
                *ambiguousColorCount = static_cast<int>(ambiguousColors.size());
            }
            return colorMapping;
        }

        bool IsHexDigit(const QChar character)
        {
            return (character >= QLatin1Char('0') && character <= QLatin1Char('9'))
                || (character >= QLatin1Char('a') && character <= QLatin1Char('f'))
                || (character >= QLatin1Char('A') && character <= QLatin1Char('F'));
        }

        // FormatHexChannels 作用：按原写法的大小写和位宽回写颜色，避免样式文本无谓抖动。
        QString FormatHexChannels(const QRgb colorValue, const bool upperCase)
        {
            const QString hexText = QStringLiteral("%1%2%3")
                .arg(qRed(colorValue), 2, 16, QLatin1Char('0'))
                .arg(qGreen(colorValue), 2, 16, QLatin1Char('0'))
                .arg(qBlue(colorValue), 2, 16, QLatin1Char('0'));
            return upperCase ? hexText.toUpper() : hexText;
        }

        // TryRewriteHexColor 作用：处理 #RRGGBB 与 #AARRGGBB 两种写法。
        // 只在整段十六进制恰好是 6 位或 8 位时改写，位数不符的写法原样保留。
        bool TryRewriteHexColor(
            const QHash<QRgb, QRgb>& colorMapping,
            const QString& styleText,
            const int hashIndex,
            QString* rewrittenText,
            int* nextIndex)
        {
            int scanIndex = hashIndex + 1;
            while (scanIndex < styleText.size() && IsHexDigit(styleText.at(scanIndex)))
            {
                ++scanIndex;
            }
            const int digitCount = scanIndex - hashIndex - 1;
            if (digitCount != 6 && digitCount != 8)
            {
                return false;
            }

            // 8 位写法的前两位是 alpha 通道，颜色匹配只看后面的 RGB。
            const int rgbOffset = hashIndex + 1 + (digitCount == 8 ? 2 : 0);
            const QString rgbText = styleText.mid(rgbOffset, 6);
            bool parsedOk = false;
            const uint parsedValue = rgbText.toUInt(&parsedOk, 16);
            if (!parsedOk)
            {
                return false;
            }

            const auto mappedIterator = colorMapping.constFind(
                qRgb((parsedValue >> 16) & 0xFF, (parsedValue >> 8) & 0xFF, parsedValue & 0xFF));
            if (mappedIterator == colorMapping.constEnd())
            {
                return false;
            }

            const bool upperCase = (rgbText == rgbText.toUpper());
            rewrittenText->append(styleText.mid(hashIndex, rgbOffset - hashIndex));
            rewrittenText->append(FormatHexChannels(mappedIterator.value(), upperCase));
            *nextIndex = scanIndex;
            return true;
        }

        // TryRewriteFunctionalColor 作用：处理 rgb(r,g,b) 与 rgba(r,g,b,a) 两种写法。
        // 只改写前三个通道，alpha 参数按原文保留，透明度设计不会被主题切换改掉。
        bool TryRewriteFunctionalColor(
            const QHash<QRgb, QRgb>& colorMapping,
            const QString& styleText,
            const int startIndex,
            QString* rewrittenText,
            int* nextIndex)
        {
            int scanIndex = startIndex;
            if (styleText.mid(scanIndex, 4).compare(QStringLiteral("rgba"), Qt::CaseInsensitive) == 0)
            {
                scanIndex += 4;
            }
            else if (styleText.mid(scanIndex, 3).compare(QStringLiteral("rgb"), Qt::CaseInsensitive) == 0)
            {
                scanIndex += 3;
            }
            else
            {
                return false;
            }
            while (scanIndex < styleText.size() && styleText.at(scanIndex).isSpace())
            {
                ++scanIndex;
            }
            if (scanIndex >= styleText.size() || styleText.at(scanIndex) != QLatin1Char('('))
            {
                return false;
            }
            const int openParenIndex = scanIndex;
            const int closeParenIndex = styleText.indexOf(QLatin1Char(')'), openParenIndex + 1);
            if (closeParenIndex < 0)
            {
                return false;
            }

            const QString argumentText =
                styleText.mid(openParenIndex + 1, closeParenIndex - openParenIndex - 1);
            const QList<QStringView> argumentParts = QStringView(argumentText).split(QLatin1Char(','));
            if (argumentParts.size() < 3 || argumentParts.size() > 4)
            {
                return false;
            }

            int channelValues[3] = { 0, 0, 0 };
            for (int channelIndex = 0; channelIndex < 3; ++channelIndex)
            {
                bool parsedOk = false;
                channelValues[channelIndex] = argumentParts.at(channelIndex).trimmed().toInt(&parsedOk);
                if (!parsedOk || channelValues[channelIndex] < 0 || channelValues[channelIndex] > 255)
                {
                    return false;
                }
            }

            const auto mappedIterator = colorMapping.constFind(
                qRgb(channelValues[0], channelValues[1], channelValues[2]));
            if (mappedIterator == colorMapping.constEnd())
            {
                return false;
            }

            const QRgb mappedColor = mappedIterator.value();
            rewrittenText->append(styleText.mid(startIndex, openParenIndex + 1 - startIndex));
            rewrittenText->append(QStringLiteral("%1,%2,%3")
                .arg(qRed(mappedColor))
                .arg(qGreen(mappedColor))
                .arg(qBlue(mappedColor)));
            if (argumentParts.size() == 4)
            {
                rewrittenText->append(QLatin1Char(','));
                rewrittenText->append(argumentParts.at(3).trimmed().toString());
            }
            rewrittenText->append(QLatin1Char(')'));
            *nextIndex = closeParenIndex + 1;
            return true;
        }

        // RewriteColorsInText 作用：单趟扫描完成全部改写。
        // 单趟是必要的：逐条 QString::replace 会让 A->B、B->C 两条规则串成 A->C。
        QString RewriteColorsInText(const QHash<QRgb, QRgb>& colorMapping, const QString& styleText)
        {
            if (colorMapping.isEmpty() || styleText.isEmpty())
            {
                return styleText;
            }

            QString rewrittenText;
            rewrittenText.reserve(styleText.size());
            int scanIndex = 0;
            while (scanIndex < styleText.size())
            {
                const QChar currentCharacter = styleText.at(scanIndex);
                int nextIndex = scanIndex;
                if (currentCharacter == QLatin1Char('#')
                    && TryRewriteHexColor(colorMapping, styleText, scanIndex, &rewrittenText, &nextIndex))
                {
                    scanIndex = nextIndex;
                    continue;
                }
                if ((currentCharacter == QLatin1Char('r') || currentCharacter == QLatin1Char('R'))
                    && TryRewriteFunctionalColor(
                        colorMapping, styleText, scanIndex, &rewrittenText, &nextIndex))
                {
                    scanIndex = nextIndex;
                    continue;
                }
                rewrittenText.append(currentCharacter);
                ++scanIndex;
            }
            return rewrittenText;
        }

        // RewritePaletteColors 作用：改写一个控件自己设过的 QPalette。
        // 只遍历 isBrushSet 为真的 group/role：未显式设置的角色仍然继承 QApplication
        // 调色板，本来就会跟随主题，重写反而会把继承关系固化下来。
        bool RewritePaletteColors(const QHash<QRgb, QRgb>& colorMapping, QPalette& widgetPalette)
        {
            bool paletteChanged = false;
            for (int groupIndex = 0; groupIndex < QPalette::NColorGroups; ++groupIndex)
            {
                const auto colorGroup = static_cast<QPalette::ColorGroup>(groupIndex);
                for (int roleIndex = 0; roleIndex < QPalette::NColorRoles; ++roleIndex)
                {
                    const auto colorRole = static_cast<QPalette::ColorRole>(roleIndex);
                    if (!widgetPalette.isBrushSet(colorGroup, colorRole))
                    {
                        continue;
                    }
                    const QBrush roleBrush = widgetPalette.brush(colorGroup, colorRole);
                    // 渐变或纹理画刷不是单一颜色，按颜色查表会误改，整体跳过。
                    if (roleBrush.style() != Qt::SolidPattern)
                    {
                        continue;
                    }
                    const QColor roleColor = roleBrush.color();
                    const auto mappedIterator = colorMapping.constFind(
                        qRgb(roleColor.red(), roleColor.green(), roleColor.blue()));
                    if (mappedIterator == colorMapping.constEnd())
                    {
                        continue;
                    }
                    const QRgb mappedColor = mappedIterator.value();
                    widgetPalette.setColor(
                        colorGroup,
                        colorRole,
                        QColor(
                            qRed(mappedColor),
                            qGreen(mappedColor),
                            qBlue(mappedColor),
                            roleColor.alpha()));
                    paletteChanged = true;
                }
            }
            return paletteChanged;
        }
    }

    ThemeColorSnapshot CaptureThemeColorSnapshot()
    {
        ThemeColorSnapshot snapshot;
        const QList<QColor> colors = CollectThemeColors();
        snapshot.colorTexts.reserve(colors.size());
        for (const QColor& color : colors)
        {
            snapshot.colorTexts.append(KswordTheme::ThemeColorName(color));
        }
        return snapshot;
    }

    QString RemapStaleThemeColorsInText(
        const ThemeColorSnapshot& previousSnapshot,
        const QString& styleText)
    {
        if (previousSnapshot.colorTexts.isEmpty() || styleText.isEmpty())
        {
            return styleText;
        }
        const QHash<QRgb, QRgb> colorMapping =
            BuildColorMapping(previousSnapshot.colorTexts, CollectThemeColors(), nullptr);
        return RewriteColorsInText(colorMapping, styleText);
    }

    QColor RemapStaleThemeColor(const ThemeColorSnapshot& previousSnapshot, const QColor& color)
    {
        if (previousSnapshot.colorTexts.isEmpty() || !color.isValid())
        {
            return color;
        }
        const QHash<QRgb, QRgb> colorMapping =
            BuildColorMapping(previousSnapshot.colorTexts, CollectThemeColors(), nullptr);
        const auto iterator = colorMapping.constFind(qRgb(color.red(), color.green(), color.blue()));
        return iterator == colorMapping.constEnd()
            ? color
            : QColor(qRed(iterator.value()), qGreen(iterator.value()), qBlue(iterator.value()), color.alpha());
    }

    QPalette RemapStaleThemeColorsInPalette(
        const ThemeColorSnapshot& previousSnapshot,
        const QPalette& palette)
    {
        QPalette updatedPalette = palette;
        if (!previousSnapshot.colorTexts.isEmpty())
        {
            const QHash<QRgb, QRgb> colorMapping =
                BuildColorMapping(previousSnapshot.colorTexts, CollectThemeColors(), nullptr);
            RewritePaletteColors(colorMapping, updatedPalette);
        }
        return updatedPalette;
    }

    ThemeColorRemapResult RemapStaleThemeColors(const ThemeColorSnapshot& previousSnapshot)
    {
        ThemeColorRemapResult result;
        if (previousSnapshot.colorTexts.isEmpty())
        {
            return result;
        }

        const QHash<QRgb, QRgb> colorMapping = BuildColorMapping(
            previousSnapshot.colorTexts,
            CollectThemeColors(),
            &result.ambiguousColorCount);
        result.mappedColorCount = static_cast<int>(colorMapping.size());
        if (colorMapping.isEmpty())
        {
            return result;
        }

        // allWidgets() 返回裸指针快照，而 setStyleSheet / setPalette 会触发 polish 与
        // 样式重算，途中可能有控件被延迟销毁。先整体包成 QPointer，遍历时再校验，
        // 避免后半程解引用到已析构的 QWidget。
        const QWidgetList widgetSnapshot = QApplication::allWidgets();
        QList<QPointer<QWidget>> guardedWidgets;
        guardedWidgets.reserve(widgetSnapshot.size());
        for (QWidget* const widget : widgetSnapshot)
        {
            guardedWidgets.append(QPointer<QWidget>(widget));
        }

        for (const QPointer<QWidget>& guardedWidget : guardedWidgets)
        {
            QWidget* const widget = guardedWidget.data();
            if (widget == nullptr || HasWidgetThemeBinding(widget))
            {
                continue;
            }
            // 显式 setPalette 过的控件不再接受 QApplication 调色板更新，必须单独改写。
            QPalette widgetPalette = widget->palette();
            if (widget->testAttribute(Qt::WA_SetPalette)
                && RewritePaletteColors(colorMapping, widgetPalette))
            {
                widget->setPalette(widgetPalette);
                ++result.rewrittenPaletteWidgetCount;
            }

            const QString currentStyleSheet = widget->styleSheet();
            if (currentStyleSheet.isEmpty())
            {
                continue;
            }
            ++result.inspectedWidgetCount;
            const QString rewrittenStyleSheet =
                RewriteColorsInText(colorMapping, currentStyleSheet);
            if (rewrittenStyleSheet != currentStyleSheet)
            {
                widget->setStyleSheet(rewrittenStyleSheet);
                ++result.rewrittenWidgetCount;
            }
        }
        return result;
    }
}
