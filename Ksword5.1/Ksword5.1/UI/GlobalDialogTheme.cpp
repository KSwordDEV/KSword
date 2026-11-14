#include "GlobalDialogTheme.h"
#include "./DetailDialogChrome.h"
#include "./ThemeBinding.h"
#include "./GroupBoxStyle.h"

#include "../theme.h"

#include <QApplication>
#include <QDialog>
#include <QEvent>
#include <QMessageBox>
#include <QPalette>
#include <QPointer>
#include <QPushButton>
#include <QWidget>
#include <QVariant>
#include <QTimer>
#include <QFileDialog>
#include <QColorDialog>
#include <QFontDialog>
#include <QInputDialog>
#include <QLayout>
#include <QFontMetrics>

namespace
{
    // 系统专用选择器和共享设置页保留自己的结构，业务弹窗统一由详情框架安装布局。
    bool shouldInstallDetailFramework(QDialog* dialog)
    {
        return dialog && !qobject_cast<QMessageBox*>(dialog)
            && !qobject_cast<QFileDialog*>(dialog) && !qobject_cast<QColorDialog*>(dialog)
            && !qobject_cast<QFontDialog*>(dialog) && !qobject_cast<QInputDialog*>(dialog)
            && !dialog->property("ksword_detail_keep_layout").toBool()
            && !dialog->property("ksword_secondary_keep_layout").toBool();
    }

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
    constexpr const char* kGlobalDialogStyleEndMarker = "/* KSWORD_GLOBAL_DIALOG_THEME_END */"; // 完整主题块结束标记。
    constexpr const char* kAppliedDialogStyleSheetPropertyName = "ksword_global_dialog_applied_style_sheet"; // 最近实际写入的根QSS。
    constexpr const char* kAppliedDialogPalettePropertyName = "ksword_global_dialog_applied_palette"; // 最近实际生效的根调色板。
    constexpr const char* kDialogThemePendingPropertyName = "ksword_dialog_theme_pending"; // 尚未消费的合并主题请求。

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
            "  background-color:__INPUT_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:0;"
            "  border-radius:5px;"
            "  padding:3px 6px;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "QDialog[%2=\"true\"] QAbstractScrollArea,"
            "QDialog[%2=\"true\"] QAbstractScrollArea::viewport{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:0;"
            "  selection-background-color:__ACCENT__;"
            "  selection-color:__ON_ACCENT__;"
            "}"
            "__GROUP_BOX_STYLE__"
            "QDialog[%2=\"true\"] QGroupBox{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
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
            "  border:0;"
            "}"
            "QDialog[%2=\"true\"] QTabBar::tab{"
            "  background-color:__SURFACE_ALT__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border:0;"
            "  padding:4px 10px;"
            "}"
            "QDialog[%2=\"true\"] QTabBar::tab:selected{"
            "  background-color:__SURFACE_BACKGROUND__ !important;"
            "  color:__SURFACE_TEXT__ !important;"
            "  border-bottom:2px solid __ACCENT__;"
            "}"
            // 滚动容器只是视口，不再叠加一整块更亮的底色和边框。
            "QDialog[%2=\"true\"] QScrollArea{background:transparent;border:0;}"
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
        // 普通弹窗继续拥有原表面与文字角色，只从共享配方取得标题和正文几何。
        styleSheetText.replace(QStringLiteral("__GROUP_BOX_STYLE__"), ks::ui::GroupBoxStyle(
            QStringLiteral("QDialog[%1=\"true\"] QGroupBox")
                .arg(QString::fromLatin1(kGlobalDialogThemePropertyName)),
            surfaceBackgroundText, textColorText,
            KswordTheme::TextDisabledColorHex(), QFontMetrics(QApplication::font()).height()));
        styleSheetText.replace(QStringLiteral("__MARKER__"), QString::fromLatin1(kGlobalDialogStyleMarker));
        styleSheetText.replace(QStringLiteral("__WINDOW_BACKGROUND__"), windowBackgroundText);
        styleSheetText.replace(QStringLiteral("__SURFACE_BACKGROUND__"), surfaceBackgroundText);
        styleSheetText.replace(QStringLiteral("__INPUT_BACKGROUND__"),
            KswordTheme::ThemeColorName(KswordTheme::ControlInputSurfaceColor()));
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

    // 移除明确拥有的完整块，保留业务在主题块前后新增的规则和顺序。
    void removeOwnedStyleBlocks(QString& style, const QString& begin, const QString& end)
    {
        qsizetype first = style.indexOf(begin);
        while (first >= 0)
        {
            const qsizetype last = style.indexOf(end, first + begin.size());
            if (last < 0)
            {
                break;
            }
            style.remove(first, last + end.size() - first);
            first = style.indexOf(begin);
        }
    }

    // 每次从现有QSS提取业务规则，不能因为含主题标记就回退到旧缓存并丢掉新规则。
    QString originalStyleSheetForDialog(QDialog* dialog)
    {
        if (dialog == nullptr)
        {
            return QString();
        }

        QString businessStyle = dialog->styleSheet();
        const QString begin = QString::fromLatin1(kGlobalDialogStyleMarker);
        const QString end = QString::fromLatin1(kGlobalDialogStyleEndMarker);
        // 旧运行状态只有BEGIN时沿用既有原始缓存；新块均有END，更新不会再吞掉业务后缀。
        if (businessStyle.contains(begin) && !businessStyle.contains(end))
        {
            businessStyle = dialog->property(kOriginalDialogStyleSheetPropertyName).isValid()
                ? dialog->property(kOriginalDialogStyleSheetPropertyName).toString()
                : businessStyle.left(businessStyle.indexOf(begin));
        }
        removeOwnedStyleBlocks(businessStyle, begin, end);
        // 普通弹窗由本主题器独占根QSS；接管前可能已有共享框架的同一外观块。
        removeOwnedStyleBlocks(businessStyle, QStringLiteral("/* KSWORD_DETAIL_FRAMEWORK_BEGIN */"),
            QStringLiteral("/* KSWORD_DETAIL_FRAMEWORK_END */"));
        businessStyle = businessStyle.trimmed();
        dialog->setProperty(kOriginalDialogStyleSheetPropertyName, businessStyle);
        return businessStyle;
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
        if (dialog->property("ksword_secondary_window").toBool()
            || dialog->property("ksword_detail_theme_owner").toBool())
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
            // 普通按钮只在自身首次Polish设置光标，保持原交互提示而不扫描整个详情子树。
            if (eventObject && eventObject->type() == QEvent::Polish)
            {
                auto* button = qobject_cast<QPushButton*>(watchedObject);
                auto* owner = button ? qobject_cast<QDialog*>(button->window()) : nullptr;
                if (button && shouldThemeDialog(owner))
                {
                    button->setCursor(Qt::PointingHandCursor);
                }
            }
            QDialog* dialog = qobject_cast<QDialog*>(watchedObject);
            if (dialog == nullptr || eventObject == nullptr
                || dialog->property(kGlobalDialogPolishingPropertyName).toBool())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type eventType = eventObject->type();
            const bool ownsTheme = shouldThemeDialog(dialog);
            const QPointer<QDialog> eventDialog(dialog); // 首显结构迁移和主题事件可使业务窗口关闭。
            if (eventType == QEvent::Polish || eventType == QEvent::Show)
            {
                // 首帧前声明根主题所有权；Polish只登记，Show时才迁移已构建完成的布局。
                if (ownsTheme)
                {
                    dialog->setProperty(kGlobalDialogThemePropertyName, QStringLiteral("true"));
                }
                if (shouldInstallDetailFramework(dialog))
                {
                    ks::ui::InstallDetailWindowFramework(dialog);
                    if (eventType == QEvent::Show)
                    {
                        ks::ui::PrepareDetailWindowForShow(dialog);
                    }
                }
                if (!eventDialog)
                {
                    return true;
                }
                if (ownsTheme)
                {
                    // Polish/Show在Qt真正绘制前完成；取消旧排队项，不再先画旧颜色再闪到新主题。
                    dialog->setProperty(kDialogThemePendingPropertyName, false);
                    polishDialog(dialog);
                }
                if (!eventDialog)
                {
                    return true;
                }
                if (eventType == QEvent::Show)
                {
                    // 详情结构与根色完成后，只消费当前分支初次颜色，不让子卡片下一帧换底。
                    ks::ui::PrepareWidgetThemeBindingsForShow(eventDialog.data());
                    if (!eventDialog)
                    {
                        return true;
                    }
                    if (eventDialog->layout() != nullptr)
                    {
                        eventDialog->layout()->activate();
                    }
                    if (!eventDialog)
                    {
                        return true;
                    }
                }
                return QObject::eventFilter(watchedObject, eventObject);
            }
            if (!ownsTheme)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // 自身已应用的根样式/调色板重新发事件时直接退出，不遍历子按钮或重建主题块。
            if (eventType == QEvent::StyleChange
                && dialog->property(kAppliedDialogStyleSheetPropertyName).isValid()
                && dialog->styleSheet() == dialog->property(kAppliedDialogStyleSheetPropertyName).toString())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }
            if (eventType == QEvent::PaletteChange
                && dialog->property(kAppliedDialogPalettePropertyName).isValid()
                && dialog->palette() == dialog->property(kAppliedDialogPalettePropertyName).value<QPalette>())
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }
            if (eventType == QEvent::PaletteChange || eventType == QEvent::ApplicationPaletteChange
                || eventType == QEvent::StyleChange)
            {
                scheduleTheme(dialog);
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }

        // 真实主题或业务QSS变化合并到一次更新；弹窗销毁和首显同步应用会取消旧任务。
        void scheduleTheme(QDialog* dialog)
        {
            // 隐藏窗口的整树根QSS不参与每次换肤，真实Show入口会同步应用最新主题。
            if (!dialog->isVisible() || dialog->property(kDialogThemePendingPropertyName).toBool())
            {
                return;
            }
            dialog->setProperty(kDialogThemePendingPropertyName, true);
            const QPointer<GlobalDialogStyler> safeStyler(this);
            const QPointer<QDialog> safeDialog(dialog);
            QTimer::singleShot(0, dialog, [safeStyler, safeDialog]()
            {
                if (!safeStyler || !safeDialog || !safeDialog->property(kDialogThemePendingPropertyName).toBool())
                {
                    return;
                }
                safeDialog->setProperty(kDialogThemePendingPropertyName, false);
                if (safeDialog->isVisible())
                {
                    safeStyler->polishDialog(safeDialog);
                }
            });
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
                QPointer<QDialog> targetDialog; // 根样式处理可引发业务关闭，恢复标记前必须探活。
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
            const QPointer<QDialog> safeDialog(dialog); // 事件接收者可能在业务主题回调中关闭。

            const bool darkModeEnabled = KswordTheme::IsDarkModeEnabled();
            const QPalette sourcePalette = (qApp != nullptr) ? qApp->palette() : dialog->palette();
            const QString originalStyleSheet = originalStyleSheetForDialog(dialog);
            const QString targetStyleSheet = originalStyleSheet + buildGlobalDialogStyleSheetBlock(darkModeEnabled)
                + (dialog->property("ksword_detail_shell").toBool()
                    ? ks::ui::BuildDetailDialogChromeStyle(dialog->objectName()) : QString())
                + QLatin1Char('\n') + QString::fromLatin1(kGlobalDialogStyleEndMarker);

            dialog->setProperty(kGlobalDialogThemePropertyName, QStringLiteral("true"));
            dialog->setProperty(kGlobalDialogDarkModePropertyName, darkModeEnabled);
            dialog->setAttribute(Qt::WA_StyledBackground, true);
            dialog->setAutoFillBackground(true);
            const QPalette targetPalette = buildDialogPalette(sourcePalette, darkModeEnabled);
            if (dialog->palette() != targetPalette)
            {
                dialog->setPalette(targetPalette);
            }
            if (!safeDialog)
            {
                return;
            }

            if (dialog->styleSheet() != targetStyleSheet)
            {
                dialog->setStyleSheet(targetStyleSheet);
            }
            if (!safeDialog)
            {
                return;
            }

            // Qt在根QSS实际变化时自行刷新子控件；手工逐按钮重polish会重复触发整个主题链。
            dialog->setProperty(kAppliedDialogStyleSheetPropertyName, targetStyleSheet);
            dialog->setProperty(kAppliedDialogPalettePropertyName, QVariant::fromValue(dialog->palette()));
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
            if (dialog == nullptr || !dialog->isVisible())
            {
                continue; // 首次/再次Show同步安装并换肤，不预加载隐藏业务窗口。
            }
            // 手动刷新与首显遵循同一根QSS所有权顺序，不能先让框架写一份重复主题。
            if (shouldThemeDialog(dialog))
            {
                dialog->setProperty(kGlobalDialogThemePropertyName, QStringLiteral("true"));
            }
            if (shouldInstallDetailFramework(dialog))
            {
                ks::ui::InstallDetailWindowFramework(dialog);
            }
            if (!shouldThemeDialog(dialog))
            {
                continue;
            }

            stylerInstance->polishDialog(dialog);
        }
    }
}
