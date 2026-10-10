#include "GlobalDialogTheme.h"
#include "./DetailDialogChrome.h"

#include "../theme.h"

#include <QApplication>
#include <QDialog>
#include <QEvent>
#include <QMessageBox>
#include <QPalette>
#include <QPointer>
#include <QPushButton>
#include <QStyle>
#include <QWidget>

namespace
{
    // kGlobalDialogThemePropertyName 作用：
    // - 标记某个 QDialog 已纳入全局普通弹窗主题；
    // - QSS 使用该动态属性作为选择器，避免污染非弹窗控件。
    constexpr const char* kGlobalDialogThemePropertyName = "ksword_global_dialog_theme";

    // kGlobalDialogPolishingPropertyName 作用：
    // - 标记当前弹窗正在应用主题；
    // - 避免 setStyleSheet 触发 StyleChange 后递归进入主题刷新。
    constexpr const char* kGlobalDialogPolishingPropertyName = "ksword_global_dialog_polishing";

    // kGlobalDialogDarkModePropertyName 作用：
    // - 缓存上次应用到弹窗的深浅色模式；
    // - 减少同一主题下重复刷新样式表的次数。
    constexpr const char* kGlobalDialogDarkModePropertyName = "ksword_global_dialog_dark_mode";

    // kOriginalDialogStyleSheetPropertyName 作用：
    // - 保存业务弹窗原有样式表；
    // - 全局主题只追加兜底规则，不直接丢弃业务自己的局部样式。
    constexpr const char* kOriginalDialogStyleSheetPropertyName = "ksword_global_dialog_original_style_sheet";

    // kGlobalDialogStyleMarker 作用：
    // - 写入合成样式表中的分隔标记；
    // - 后续刷新时据此区分“业务原样式”和“全局主题追加块”。
    constexpr const char* kGlobalDialogStyleMarker = "/* KSWORD_GLOBAL_DIALOG_THEME_BEGIN */";

    // dialogWindowColor 作用：让普通弹窗使用全局窗口背景角色。
    QColor dialogWindowColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return KswordTheme::WindowColor();
    }

    // dialogSurfaceColor 作用：让输入区、列表和内容面板使用派生表面角色。
    QColor dialogSurfaceColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return KswordTheme::SurfaceColor();
    }

    // dialogAlternateSurfaceColor 作用：返回弹窗按钮和普通标签的次级表面色。
    QColor dialogAlternateSurfaceColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return KswordTheme::SurfaceAltColor();
    }

    // dialogWindowTextColor 作用：返回窗口背景上的自适应文字色。
    QColor dialogWindowTextColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return KswordTheme::MainBackgroundTextColor();
    }

    // dialogTextColor 作用：返回内容表面上的主文字色。
    QColor dialogTextColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return KswordTheme::TextPrimaryColor();
    }

    // dialogBorderColor 作用：返回随主背景种子派生的边框色。
    QColor dialogBorderColor(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return KswordTheme::BorderColor();
    }

    // buildDialogPalette 作用：
    // - 构建普通弹窗 palette；
    // - 与 QSS 配合处理未被样式表覆盖的原生绘制分支。
    QPalette buildDialogPalette(const QPalette& basePalette, const bool darkModeEnabled)
    {
        QPalette dialogPalette = basePalette;
        const QColor windowColor = dialogWindowColor(darkModeEnabled);
        const QColor surfaceColor = dialogSurfaceColor(darkModeEnabled);
        const QColor alternateSurfaceColor = dialogAlternateSurfaceColor(darkModeEnabled);
        const QColor windowTextColor = dialogWindowTextColor(darkModeEnabled);
        const QColor textColor = dialogTextColor(darkModeEnabled);
        const QColor borderColor = dialogBorderColor(darkModeEnabled);

        dialogPalette.setColor(QPalette::Window, windowColor);
        dialogPalette.setColor(QPalette::Base, surfaceColor);
        dialogPalette.setColor(QPalette::AlternateBase, alternateSurfaceColor);
        dialogPalette.setColor(QPalette::Text, textColor);
        dialogPalette.setColor(QPalette::WindowText, windowTextColor);
        dialogPalette.setColor(QPalette::Button, alternateSurfaceColor);
        dialogPalette.setColor(QPalette::ButtonText, textColor);
        dialogPalette.setColor(QPalette::Mid, borderColor);
        dialogPalette.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
        dialogPalette.setColor(
            QPalette::HighlightedText,
            KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()));
        return dialogPalette;
    }

    // buildGlobalDialogStyleSheetBlock 作用：
    // - 生成普通弹窗全局追加样式；
    // - 窗口、输入控件、列表和标签分别使用全局中性角色，完整跟随自定义主背景色。
    QString buildGlobalDialogStyleSheetBlock(const bool darkModeEnabled)
    {
        const QString windowBackgroundText = KswordTheme::ThemeColorName(dialogWindowColor(darkModeEnabled));
        const QString surfaceBackgroundText = KswordTheme::ThemeColorName(dialogSurfaceColor(darkModeEnabled));
        const QString alternateSurfaceText = KswordTheme::ThemeColorName(dialogAlternateSurfaceColor(darkModeEnabled));
        const QString windowTextColorText = KswordTheme::ThemeColorName(dialogWindowTextColor(darkModeEnabled));
        const QString textColorText = KswordTheme::ThemeColorName(dialogTextColor(darkModeEnabled));
        const QString borderColorText = KswordTheme::ThemeColorName(dialogBorderColor(darkModeEnabled));

        QString styleSheetText = QString::fromLatin1(
            "\n__MARKER__\n"
            // Do not paint every descendant QWidget with the dialog Window layer here.
            // Group boxes and other nested content panes deliberately use the Surface layer.
            "QDialog[%2=\"true\"]{"
            "  background-color:__WINDOW_BACKGROUND__ !important;"
            "  color:__WINDOW_TEXT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QLineEdit,"
            "QDialog[%2=\"true\"] QTextEdit,"
            "QDialog[%2=\"true\"] QPlainTextEdit,"
            "QDialog[%2=\"true\"] QSpinBox,"
            "QDialog[%2=\"true\"] QDoubleSpinBox{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  border-radius:3px;"
            "  padding:3px 6px;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QDialog[%2=\"true\"] QAbstractScrollArea,"
            "QDialog[%2=\"true\"] QAbstractScrollArea::viewport{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QDialog[%2=\"true\"] QGroupBox{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  border-radius:4px;"
            "  margin-top:8px;"
            "}"
            "QDialog[%2=\"true\"] QGroupBox QLabel{"
            "  background-color:transparent !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QCheckBox,"
            "QDialog[%2=\"true\"] QRadioButton{"
            "  background-color:transparent !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QTabWidget::pane{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  border:1px solid __BORDER__;"
            "}"
            "QDialog[%2=\"true\"] QTabBar::tab{"
            "  background-color:__SURFACE_ALT__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "  padding:4px 10px;"
            "}"
            "QDialog[%2=\"true\"] QTabBar::tab:selected{"
            "  background-color:__ACCENT__ !important;"
            "  color:__ON_ACCENT__ !important;"
            "}"
            "QDialog[%2=\"true\"] QMenu{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:1px solid __BORDER__;"
            "}"
            "QDialog[%2=\"true\"] QMenu::item:selected{"
            "  background-color:__ACCENT__ !important;"
            "  color:__ON_ACCENT__ !important;"
            "}"
            "__COMBO_BOX_STYLE__"
            "__BUTTON_STYLE__");
        styleSheetText = styleSheetText.arg(QString::fromLatin1(kGlobalDialogThemePropertyName));
        styleSheetText.replace(QStringLiteral("__MARKER__"), QString::fromLatin1(kGlobalDialogStyleMarker));
        styleSheetText.replace(QStringLiteral("__WINDOW_BACKGROUND__"), windowBackgroundText);
        styleSheetText.replace(QStringLiteral("__SURFACE_BACKGROUND__"), surfaceBackgroundText);
        styleSheetText.replace(QStringLiteral("__SURFACE_ALT__"), alternateSurfaceText);
        styleSheetText.replace(QStringLiteral("__WINDOW_TEXT__"), windowTextColorText);
        styleSheetText.replace(QStringLiteral("__SURFACE_TEXT__"), textColorText);
        styleSheetText.replace(QStringLiteral("__BORDER__"), borderColorText);
        styleSheetText.replace(QStringLiteral("__ACCENT__"), KswordTheme::PrimaryBlueHex);
        styleSheetText.replace(QStringLiteral("__ON_ACCENT__"), KswordTheme::OnAccentHex());
        QString dialogComboBoxStyle = KswordTheme::ThemedComboBoxStyle();
        dialogComboBoxStyle.replace(
            QStringLiteral("QComboBox"),
            QStringLiteral("QDialog[%1=\"true\"] QComboBox")
                .arg(QString::fromLatin1(kGlobalDialogThemePropertyName)));
        styleSheetText.replace(QStringLiteral("__COMBO_BOX_STYLE__"), dialogComboBoxStyle);
        styleSheetText.replace(QStringLiteral("__BUTTON_STYLE__"), KswordTheme::ThemedButtonStyle());
        return styleSheetText;
    }

    // originalStyleSheetForDialog 作用：
    // - 获取并缓存业务弹窗原始样式；
    // - 如果当前样式已经含有全局标记，则沿用已缓存的原始样式。
    QString originalStyleSheetForDialog(QDialog* dialog)
    {
        if (dialog == nullptr)
        {
            return QString();
        }

        const QString currentStyleSheet = dialog->styleSheet();
        const bool currentStyleHasThemeBlock = currentStyleSheet.contains(QString::fromLatin1(kGlobalDialogStyleMarker));
        if (!currentStyleHasThemeBlock)
        {
            dialog->setProperty(kOriginalDialogStyleSheetPropertyName, currentStyleSheet);
            return currentStyleSheet;
        }

        return dialog->property(kOriginalDialogStyleSheetPropertyName).toString();
    }

    // shouldThemeDialog 作用：
    // - 判断某个 QDialog 是否应由普通弹窗主题器处理；
    // - QMessageBox 由 UI/ThemedMessageBox 专用逻辑处理，必须排除。
    bool shouldThemeDialog(QDialog* dialog)
    {
        if (dialog == nullptr)
        {
            return false;
        }
        if (qobject_cast<QMessageBox*>(dialog) != nullptr)
        {
            return false;
        }
        // 配置与操作窗口由其明确登记的主题拥有，避免兜底重新铺上卡片和高亮 Tab。
        if (dialog->property("ksword_secondary_window").toBool())
        {
            return false;
        }
        return true;
    }

    // GlobalDialogStyler 作用：
    // - QApplication 级事件过滤器；
    // - 在普通弹窗显示、换肤、样式变化时统一补齐背景和控件颜色。
    class GlobalDialogStyler final : public QObject
    {
    public:
        // 构造函数：
        // - 参数 parentObject：通常为 QApplication；
        // - 返回值：无，QObject 生命周期由父对象管理。
        explicit GlobalDialogStyler(QObject* parentObject)
            : QObject(parentObject)
        {
        }

        // eventFilter 作用：
        // - 监听普通弹窗的显示与样式相关事件；
        // - 触发时调用 polishDialog 统一补齐主题。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            QDialog* dialog = qobject_cast<QDialog*>(watchedObject);
            if (!shouldThemeDialog(dialog) || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type eventType = eventObject->type();
            if (eventType == QEvent::Polish ||
                eventType == QEvent::Show ||
                eventType == QEvent::PaletteChange ||
                eventType == QEvent::ApplicationPaletteChange ||
                eventType == QEvent::StyleChange)
            {
                if (!dialog->property(kGlobalDialogPolishingPropertyName).toBool())
                {
                    polishDialog(dialog);
                }
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }

        // polishDialog 作用：
        // - 对单个普通弹窗应用当前主题；
        // - 不返回值，只修改控件 palette、属性和样式表。
        void polishDialog(QDialog* dialog) const
        {
            if (!shouldThemeDialog(dialog))
            {
                return;
            }
            if (dialog->property(kGlobalDialogPolishingPropertyName).toBool())
            {
                return;
            }

            struct PolishingResetter
            {
                QDialog* targetDialog = nullptr; // targetDialog：需要恢复重入标记的弹窗。
                ~PolishingResetter()
                {
                    if (targetDialog != nullptr)
                    {
                        targetDialog->setProperty(kGlobalDialogPolishingPropertyName, false);
                    }
                }
            };

            dialog->setProperty(kGlobalDialogPolishingPropertyName, true);
            PolishingResetter resetter{ dialog };

            const bool darkModeEnabled = KswordTheme::IsDarkModeEnabled();
            const QPalette sourcePalette = (qApp != nullptr) ? qApp->palette() : dialog->palette();
            const QString originalStyleSheet = originalStyleSheetForDialog(dialog);
            const QString targetStyleSheet = originalStyleSheet + buildGlobalDialogStyleSheetBlock(darkModeEnabled)
                + (dialog->property("ksword_detail_shell").toBool()
                    ? ks::ui::BuildDetailDialogChromeStyle(dialog->objectName()) : QString());

            dialog->setProperty(kGlobalDialogThemePropertyName, QStringLiteral("true"));
            dialog->setProperty(kGlobalDialogDarkModePropertyName, darkModeEnabled);
            dialog->setAttribute(Qt::WA_StyledBackground, true);
            dialog->setAutoFillBackground(true);
            dialog->setPalette(buildDialogPalette(sourcePalette, darkModeEnabled));

            if (dialog->styleSheet() != targetStyleSheet)
            {
                dialog->setStyleSheet(targetStyleSheet);
            }

            const QList<QPushButton*> buttonList = dialog->findChildren<QPushButton*>();
            for (QPushButton* button : buttonList)
            {
                if (button == nullptr)
                {
                    continue;
                }
                button->setCursor(Qt::PointingHandCursor);
                if (QStyle* buttonStyle = button->style())
                {
                    buttonStyle->unpolish(button);
                    buttonStyle->polish(button);
                }
            }
        }
    };

    // globalDialogStylerInstance 作用：
    // - 返回普通弹窗全局主题器单例；
    // - 单例父对象绑定 QApplication，避免手动释放。
    GlobalDialogStyler* globalDialogStylerInstance()
    {
        static QPointer<GlobalDialogStyler> stylerInstance;
        if (stylerInstance == nullptr && qApp != nullptr)
        {
            stylerInstance = new GlobalDialogStyler(qApp);
        }
        return stylerInstance.data();
    }
}

namespace ks::ui
{
    void InstallGlobalDialogTheme(QApplication* appInstance)
    {
        if (appInstance == nullptr)
        {
            return;
        }

        GlobalDialogStyler* stylerInstance = globalDialogStylerInstance();
        if (stylerInstance == nullptr)
        {
            return;
        }

        appInstance->installEventFilter(stylerInstance);
        RefreshGlobalDialogTheme();
    }

    void RefreshGlobalDialogTheme()
    {
        GlobalDialogStyler* stylerInstance = globalDialogStylerInstance();
        if (stylerInstance == nullptr || qApp == nullptr)
        {
            return;
        }

        const QWidgetList topLevelWidgetList = qApp->topLevelWidgets();
        for (QWidget* topLevelWidget : topLevelWidgetList)
        {
            QDialog* dialog = qobject_cast<QDialog*>(topLevelWidget);
            if (!shouldThemeDialog(dialog))
            {
                continue;
            }

            stylerInstance->polishDialog(dialog);
        }
    }
}
