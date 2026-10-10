#include "page_theme_regression_fixtures.h"

#include "../Ksword5.1/Ksword5.1/UI/DetailDialogChrome.h"
#include "../Ksword5.1/Ksword5.1/UI/FlatButtonTheme.h"
#include "../Ksword5.1/Ksword5.1/UI/FloatingScrollbars.h"
#include "../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include "../Ksword5.1/Ksword5.1/UI/SvgThemeIconManager.h"
#include "../Ksword5.1/Ksword5.1/UI/ThemeBinding.h"
#include "../Ksword5.1/Ksword5.1/UI/TablePresentation.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QAbstractButton>
#include <QAction>
#include <QApplication>
#include <QButtonGroup>
#include <QDialog>
#include <QDir>
#include <QFrame>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QImage>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPalette>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QSet>
#include <QStackedWidget>
#include <QStandardItemModel>
#include <QStyle>
#include <QTableView>
#include <QThread>
#include <QToolButton>
#include <QVBoxLayout>

#include <iostream>
#include <vector>

namespace
{
    using ks::ui::FlatButtonAppearance;
    using ks::ui::FlatButtonTone;

    // 每轮独立统计，允许同一进程重复调用而不累加前一轮结果。
    struct FixtureChecks
    {
        int checks = 0; // 已执行的断言总数。
        int failures = 0; // 本轮失败总数。

        void require(bool passed, const char* name)
        {
            ++checks;
            failures += passed ? 0 : 1;
            std::cout << (passed ? "PASS " : "FAIL ") << name << std::endl;
        }
    };

    // 只推进 GUI 队列；没有固定时间戳任务，也不访问主程序的采样后端。
    void drainEvents()
    {
        for (int iteration = 0; iteration < 30; ++iteration)
        {
            QApplication::processEvents();
            QThread::msleep(2);
        }
    }

    // 来源为 MainWindow::applyAppearanceSettings 的完整角色集合，而非手工修补父 Button。
    QPalette mainWindowPalette(const QPalette& original)
    {
        QPalette palette = original;
        palette.setColor(QPalette::Window, KswordTheme::MainBackgroundColor());
        palette.setColor(QPalette::WindowText, KswordTheme::MainBackgroundTextColor());
        palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::Mid, KswordTheme::BorderColor());
        palette.setColor(QPalette::Midlight, KswordTheme::BorderStrongColor());
        palette.setColor(QPalette::Dark, KswordTheme::PaletteDarkColor());
        palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
        palette.setColor(QPalette::Button, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::ToolTipBase, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::ToolTipText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Highlight, KswordTheme::PrimaryBlueColor);
        palette.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor());
        return palette;
    }

    // 从完整顶层合成图取色；透明 child 单独 grab 不保证带入真实宿主底面。
    // localSample 避开中央文字/图标与圆角，并逐层验证未被祖先视口裁切。
    QColor compositedColor(QWidget& widget, const QPoint& localSample)
    {
        QWidget* host = widget.window(); // 实际顶层宿主，可因布局重挂而改变。
        if (host == nullptr || !widget.rect().contains(localSample))
        {
            return QColor();
        }
        for (QWidget* owner = &widget; owner != nullptr; owner = owner->parentWidget())
        {
            if (!owner->rect().contains(widget.mapTo(owner, localSample)))
            {
                std::cout << "PAGE_REGRESSION_SAMPLE_CLIPPED CLASS="
                    << widget.metaObject()->className() << std::endl;
                return QColor();
            }
            if (owner == host)
            {
                break;
            }
        }
        const QPoint hostSample = widget.mapTo(host, localSample);
        const QImage frame = host->grab().toImage();
        const QPoint pixelSample = hostSample * frame.devicePixelRatio();
        if (!host->rect().contains(hostSample) || !frame.rect().contains(pixelSample))
        {
            std::cout << "PAGE_REGRESSION_SAMPLE_OUTSIDE_HOST CLASS="
                << widget.metaObject()->className() << std::endl;
            return QColor();
        }
        return frame.pixelColor(pixelSample);
    }

    // 普通按钮使用既有左侧取样；导航另选内容矩形内点，避开圆角与悬浮条。
    QColor bodyColor(QWidget& widget)
    {
        return compositedColor(widget, QPoint(4, widget.height() / 2));
    }

    // QWidget 实际绘制状态决定 QSS hover；不以 TryGetFlatButtonBackground 自证渲染正确。
    void setMouseOver(QAbstractButton& button, bool mouseOver)
    {
        button.setAttribute(Qt::WA_UnderMouse, mouseOver);
        // QPushButton 还维护 hitButton 驱动的 hovering，WA_UnderMouse 单独写入不够。
        const QPoint local = mouseOver ? button.rect().center() : QPoint(-1, -1);
        QMouseEvent move(QEvent::MouseMove, QPointF(local),
            QPointF(button.mapTo(button.window(), local)), QPointF(button.mapToGlobal(local)),
            Qt::NoButton, Qt::NoButton, Qt::NoModifier);
        QApplication::sendEvent(&button, &move);
        button.update();
        drainEvents();
    }

    // 独立从页面已声明角色求悬停期望；不调用被测试的按钮颜色查询或状态配方。
    QColor expectedSurface(const QAbstractButton& button)
    {
        for (const QWidget* owner = button.parentWidget(); owner != nullptr; owner = owner->parentWidget())
        {
            const QColor base = owner->palette().color(QPalette::Active, QPalette::Base);
            if (base.isValid() && base.alpha() == 255)
            {
                return base;
            }
        }
        return QApplication::palette().color(QPalette::Active, QPalette::Base);
    }

    QColor expectedAccent(const QAbstractButton& button)
    {
        QColor highlight = button.parentWidget() != nullptr
            ? button.parentWidget()->palette().color(QPalette::Active, QPalette::Highlight)
            : QApplication::palette().color(QPalette::Active, QPalette::Highlight);
        if (!highlight.isValid() || highlight.alpha() == 0)
        {
            highlight = KswordTheme::PrimaryAccentColor();
        }
        return KswordTheme::EnsureTextContrast(highlight, expectedSurface(button), 3.0);
    }

    // 保留原渲染断言，失败时展示实际状态、拥有标记和父角色，便于区分配方与采样故障。
    void requireColor(FixtureChecks& result, bool passed, const char* name,
        const QAbstractButton& button, const QColor& actual, const QColor& expected,
        const char* relation = "equal")
    {
        result.require(passed, name);
        if (passed)
        {
            return;
        }
        const QPalette parent = button.parentWidget() != nullptr
            ? button.parentWidget()->palette() : QApplication::palette();
        const QString style = button.styleSheet();
        std::cout << "PAGE_REGRESSION_COLOR_DIAGNOSTIC NAME=" << name
            << " CLASS=" << button.metaObject()->className()
            << " OBJECT=" << button.objectName().toStdString()
            << " APPEARANCE=" << button.property("ksword_flat_button_appearance").toInt()
            << " TONE=" << button.property("ksword_flat_button_tone").toInt()
            << " MARKER=" << style.contains(QStringLiteral("KSWORD_FLAT_BUTTON_BEGIN"))
            << " ACTUAL=" << actual.name(QColor::HexArgb).toStdString()
            << " EXPECTED=" << expected.name(QColor::HexArgb).toStdString()
            << " RELATION=" << relation
            << " FOCUS=" << button.hasFocus() << " MOUSE=" << button.underMouse()
            << " TRACKING=" << button.hasMouseTracking()
            << " DOWN=" << button.isDown() << " CHECKED=" << button.isChecked()
            << " ENABLED=" << button.isEnabled()
            << " PARENT_BASE=" << parent.color(QPalette::Active, QPalette::Base).name(QColor::HexArgb).toStdString()
            << " PARENT_BUTTON=" << parent.color(QPalette::Active, QPalette::Button).name(QColor::HexArgb).toStdString()
            << " PARENT_HIGHLIGHT=" << parent.color(QPalette::Active, QPalette::Highlight).name(QColor::HexArgb).toStdString()
            << " SURFACE=" << expectedSurface(button).name(QColor::HexArgb).toStdString()
            << " LOCAL_QSS=" << style.toStdString() << std::endl;
    }

    // 预览保存到调用方既有 output，不创建目录，也不更改用户文件或系统窗口。
    void savePreview(FixtureChecks& result, QWidget& host, const char* relativePath)
    {
        const QString path = QDir::current().filePath(QString::fromLatin1(relativePath));
        const bool saved = host.grab().save(path);
        result.require(saved, "actual_top_level_preview_saved_to_existing_output");
        std::cout << "PAGE_REGRESSION_PREVIEW PATH=" << path.toStdString()
            << " SAVED=" << saved << std::endl;
    }

    // 日志保留真实父角色的 alpha，证明夹具确实进入过去漏测的透明黑路径。
    void reportPalette(const char* name, const QWidget& widget)
    {
        const QColor button = widget.palette().color(QPalette::Active, QPalette::Button);
        const QColor base = widget.palette().color(QPalette::Active, QPalette::Base);
        std::cout << "PAGE_REGRESSION_PALETTE " << name
            << " BUTTON=" << button.name(QColor::HexArgb).toStdString()
            << " BASE=" << base.name(QColor::HexArgb).toStdString() << std::endl;
    }

    struct ButtonCase
    {
        QAbstractButton* button; // 由页面 QObject 树持有的真实 push/tool 控件。
        bool transparent; // 用户期望的普通态是否露出父表面。
    };

    // 工具条使用真实布局重挂：按钮先在旧父级/图表面板创建，再加入当前页面控制行。
    void transparentToolbarFixture(QApplication& app, FixtureChecks& result)
    {
        for (int dark = 0; dark < 2; ++dark)
        {
            KswordTheme::SetDarkModeEnabled(dark != 0);
            KswordTheme::SetPrimaryAccentColor(QStringLiteral("#2586c9"));
            app.setPalette(mainWindowPalette(app.palette()));
            app.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());

            QWidget host;
            host.setAttribute(Qt::WA_DontShowOnScreen);
            host.setAutoFillBackground(true);
            host.resize(700, 160);
            auto* hostLayout = new QVBoxLayout(&host);
            auto* stack = new QStackedWidget(&host);
            auto* page = new QWidget;
            auto* row = new QHBoxLayout(page);
            row->setContentsMargins(12, 12, 12, 12);
            auto* originalParent = new QWidget(&host);
            originalParent->hide();
            auto* activityPanel = new QWidget(&host);
            activityPanel->hide();

            // 等价于 MainWindow 的 QStackedWidget 后代透明兜底，并保留进程图表面板原样式。
            host.setStyleSheet(QStringLiteral(
                "QStackedWidget,QStackedWidget > QWidget{background:transparent;background-color:transparent;}"));
            activityPanel->setStyleSheet(QStringLiteral(
                "background:transparent;background-color:transparent;"));
            stack->addWidget(page);
            hostLayout->addWidget(stack);

            std::vector<ButtonCase> cases;
            for (const FlatButtonAppearance appearance : {FlatButtonAppearance::Auto,
                FlatButtonAppearance::Solid, FlatButtonAppearance::Flat})
            {
                auto* push = new QPushButton(QStringLiteral("Run"), originalParent);
                auto* tool = new QToolButton(activityPanel);
                tool->setText(QStringLiteral("Window"));
                for (QAbstractButton* button : {static_cast<QAbstractButton*>(push),
                    static_cast<QAbstractButton*>(tool)})
                {
                    button->setFixedSize(90, 32);
                    button->setFocusPolicy(Qt::NoFocus);
                    button->setCheckable(true);
                    ks::ui::ApplyFlatButtonTheme(button, FlatButtonTone::Neutral, appearance);
                    row->addWidget(button);
                    result.require(button->parentWidget() == page, "toolbar_layout_reparents_real_buttons");
                }
                cases.push_back({push, appearance == FlatButtonAppearance::Flat});
                cases.push_back({tool, appearance != FlatButtonAppearance::Solid});
            }
            host.show();
            drainEvents();
            reportPalette("transparent_toolbar_page", *page);
            const QColor parentButton = page->palette().color(QPalette::Active, QPalette::Button);
            result.require(parentButton.alpha() == 0 && parentButton.red() == 0
                && parentButton.green() == 0 && parentButton.blue() == 0,
                "production_transparent_parent_button_really_is_transparent_black");

            const QColor exposed = host.palette().color(QPalette::Window);
            const QColor accent = expectedAccent(*cases.front().button);
            for (const ButtonCase& current : cases)
            {
                QAbstractButton& button = *current.button;
                setMouseOver(button, false);
                const QColor normal = bodyColor(button);
                requireColor(result, current.transparent ? normal == exposed
                    : normal != exposed && normal != QColor(Qt::black),
                    "auto_solid_flat_actual_normal_fill_matches_product_contract",
                    button, normal, exposed, current.transparent ? "equal" : "different_nonblack");
                setMouseOver(button, true);
                const QColor hover = bodyColor(button);
                const QColor buttonAccent = expectedAccent(button);
                requireColor(result, hover == buttonAccent && hover != normal,
                    "transparent_parent_actual_hover_restores_theme_accent", button, hover, buttonAccent);
                button.setDown(true);
                drainEvents();
                const QColor pressed = bodyColor(button);
                requireColor(result, pressed != normal && pressed != QColor(Qt::black)
                    && KswordTheme::ContrastRatio(pressed, expectedSurface(button)) >= 2.99,
                    "transparent_parent_actual_pressed_remains_visible", button, pressed, normal,
                    "different_nonblack_contrast_3");
                button.setDown(false);
                button.setChecked(true);
                drainEvents();
                const QColor checked = bodyColor(button);
                requireColor(result, checked == buttonAccent, "actual_checked_fill_overrides_hover",
                    button, checked, buttonAccent);
                button.setEnabled(false);
                drainEvents();
                const QColor disabled = bodyColor(button);
                setMouseOver(button, false);
                const QColor disabledWithoutHover = bodyColor(button);
                requireColor(result, disabledWithoutHover == disabled && disabled != buttonAccent,
                    "disabled_checked_button_does_not_paint_hover_accent", button, disabledWithoutHover, disabled);
                button.setEnabled(true);
                button.setChecked(false);
            }

            // 标题栏最小化一类图标工具使用真 QPushButton + 平台图标，正常态仍必须透明。
            auto* titleIcon = new QPushButton(originalParent);
            titleIcon->setObjectName(QStringLiteral("ksTitleMinButton"));
            titleIcon->setFixedSize(32, 28);
            titleIcon->setFocusPolicy(Qt::NoFocus);
            titleIcon->setIcon(app.style()->standardIcon(QStyle::SP_TitleBarMinButton));
            ks::ui::ApplyFlatButtonTheme(titleIcon, FlatButtonTone::Neutral, FlatButtonAppearance::Flat);
            row->addWidget(titleIcon);
            ks::ui::SvgThemeIconManager::instance().applyToApplication(
                &app, KswordTheme::PrimaryAccentColor(), false);
            drainEvents();
            const QColor titleNormal = bodyColor(*titleIcon);
            requireColor(result, titleNormal == exposed,
                "title_icon_button_actual_normal_is_transparent_against_parent", *titleIcon, titleNormal, exposed);
            setMouseOver(*titleIcon, true);
            const QColor titleHover = bodyColor(*titleIcon);
            requireColor(result, titleHover == expectedAccent(*titleIcon) && titleHover != titleNormal,
                "title_icon_button_actual_hover_restores_theme_accent", *titleIcon, titleHover,
                expectedAccent(*titleIcon));
            setMouseOver(*titleIcon, false);
            if (dark == 0)
            {
                savePreview(result, host, "output/page_theme_transparent_parent.png");
            }

            // Palette 热切换保留真实透明父角色，不能通过补色绕开受测路径。
            KswordTheme::SetPrimaryAccentColor(QStringLiteral("#a44371"));
            app.setPalette(mainWindowPalette(app.palette()));
            app.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
            ks::ui::RefreshWidgetThemeBindings();
            drainEvents();
            const QColor nextAccent = expectedAccent(*cases.front().button);
            setMouseOver(*cases.front().button, true);
            const QColor hotHover = bodyColor(*cases.front().button);
            requireColor(result, hotHover == nextAccent && nextAccent != accent,
                "actual_hover_updates_after_hot_palette_change", *cases.front().button, hotHover, nextAccent);
            setMouseOver(*cases.front().button, false);

            // 再次重挂到不透明表面，普通态/悬停态必须跟随真实新父级刷新。
            QWidget opaqueHost;
            opaqueHost.setAttribute(Qt::WA_DontShowOnScreen);
            opaqueHost.setAutoFillBackground(true);
            opaqueHost.resize(170, 70);
            auto* opaqueLayout = new QHBoxLayout(&opaqueHost);
            QAbstractButton* moved = cases.back().button;
            row->removeWidget(moved);
            opaqueLayout->addWidget(moved);
            opaqueHost.show();
            ks::ui::RefreshWidgetThemeBindings();
            drainEvents();
            const QColor movedNormal = bodyColor(*moved);
            requireColor(result, moved->parentWidget() == &opaqueHost
                && movedNormal == opaqueHost.palette().color(QPalette::Window),
                "flat_button_reparent_keeps_actual_normal_transparency", *moved, movedNormal,
                opaqueHost.palette().color(QPalette::Window));
            setMouseOver(*moved, true);
            const QColor movedHover = bodyColor(*moved);
            requireColor(result, movedHover == expectedAccent(*moved),
                "reparented_button_actual_hover_uses_new_theme", *moved, movedHover, expectedAccent(*moved));
        }
    }

    // 文件属性窗口的 palette 来自生产 buildFileDetailDialogPalette，保留 disabled 角色。
    QPalette fileDetailPalette(const QPalette& source)
    {
        QPalette palette = source;
        palette.setColor(QPalette::Window, KswordTheme::WindowColor());
        palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Button, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
        palette.setColor(QPalette::HighlightedText,
            KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()));
        palette.setColor(QPalette::Disabled, QPalette::WindowText, KswordTheme::TextDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::Text, KswordTheme::TextDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::ButtonText, KswordTheme::TextDisabledColor());
        return palette;
    }

    // 外框直接使用生产详情外壳；本地仅保留保存栏和按钮的业务几何。
    // 输入、导航底色及边缘由实际公共组件决定，不维护旧主题选择器副本。
    QString fileDetailStyle()
    {
        return ks::ui::BuildDetailDialogChromeStyle(QStringLiteral("FileDetailDialogRoot"))
            + QStringLiteral(
            "QFrame#FileMetadataSaveBar{background:%1;border-top:1px solid %2;}"
            "QDialog#FileDetailDialogRoot QPushButton{border-radius:3px;padding:4px 10px;}")
            .arg(KswordTheme::SurfaceHex(), KswordTheme::BorderHex())
            + ks::ui::BuildFlatButtonStyle();
    }

    // 保留原生图标的完整像素，避免测试把“同色实心圆”误判为仍可用的清除图标。
    QImage iconImage(const QIcon& icon)
    {
        return icon.pixmap(QSize(24, 24), QIcon::Normal, QIcon::Off).toImage()
            .convertToFormat(QImage::Format_ARGB32);
    }

    int visibleColorCount(const QImage& image)
    {
        QSet<QRgb> colors; // 忽略透明度而保留所有可见 RGB 差异。
        for (int y = 0; y < image.height(); ++y)
        {
            for (int x = 0; x < image.width(); ++x)
            {
                const QRgb pixel = image.pixel(x, y);
                if (qAlpha(pixel) != 0)
                {
                    colors.insert(qRgb(qRed(pixel), qGreen(pixel), qBlue(pixel)));
                }
            }
        }
        return static_cast<int>(colors.size());
    }

    // 真 QDialog、QScrollArea、原生 QLineEdit clear 子控件，无磁盘目标或驱动依赖。
    void fileHexShellFixture(QApplication& app, FixtureChecks& result)
    {
        QDialog dialog;
        dialog.setAttribute(Qt::WA_DontShowOnScreen);
        dialog.setObjectName(QStringLiteral("FileDetailDialogRoot"));
        dialog.resize(760, 520);
        dialog.setPalette(fileDetailPalette(app.palette()));
        ks::ui::ConfigureDetailDialogRoot(&dialog);
        dialog.setStyleSheet(fileDetailStyle());
        auto* root = new QVBoxLayout(&dialog);
        root->setContentsMargins(0, 0, 0, 0);
        root->setSpacing(0);
        auto* content = new QHBoxLayout;
        content->setContentsMargins(0, 0, 0, 0);
        auto* navigation = new QWidget;
        navigation->setObjectName(QStringLiteral("FileDetailTabNavigation"));
        auto* navLayout = new QVBoxLayout(navigation);
        auto* scroll = new QScrollArea(&dialog);
        scroll->setObjectName(QStringLiteral("FileDetailNavigationScroll"));
        scroll->setWidget(navigation);
        ks::ui::ConfigureDetailNavigation(scroll, navigation, 240);
        auto* group = new QButtonGroup(&dialog);
        group->setExclusive(true);
        QToolButton* selected = nullptr; // 第14条模拟十六进制导航，后面确保露出它。
        for (int index = 0; index < 14; ++index)
        {
            auto* button = new QToolButton(navigation);
            button->setText(QStringLiteral("Page %1").arg(index + 1));
            button->setCheckable(true);
            button->setFocusPolicy(Qt::NoFocus);
            button->setMinimumHeight(38);
            button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            ks::ui::ApplyFlatButtonTheme(button);
            navLayout->addWidget(button);
            group->addButton(button, index);
            selected = button;
        }
        navLayout->addStretch(1);
        selected->setChecked(true);
        content->addWidget(scroll);

        // 输入有原始内容后再创建 clear 子按钮，可避免160ms淡入动画干扰像素比较。
        auto* hexPage = new QWidget(&dialog);
        auto* hexLayout = new QVBoxLayout(hexPage);
        auto* offset = new QLineEdit(hexPage);
        offset->setText(QStringLiteral("0x0"));
        offset->setClearButtonEnabled(true);
        hexLayout->addWidget(offset);
        hexLayout->addStretch(1);
        content->addWidget(hexPage, 1);
        root->addLayout(content, 1);
        auto* footer = new QFrame(&dialog);
        footer->setObjectName(QStringLiteral("FileMetadataSaveBar"));
        auto* footerLayout = new QHBoxLayout(footer);
        footerLayout->setContentsMargins(8, 6, 8, 6);
        footerLayout->addStretch(1);
        auto* discard = new QPushButton(QStringLiteral("Discard"), footer);
        auto* save = new QPushButton(QStringLiteral("Save"), footer);
        auto* close = new QPushButton(QStringLiteral("Close"), footer);
        for (QPushButton* button : {discard, save, close})
        {
            button->setFocusPolicy(Qt::NoFocus);
            button->setMinimumSize(90, 30);
            footerLayout->addWidget(button);
        }
        discard->setEnabled(false);
        save->setDefault(true);
        save->setEnabled(false);
        root->addWidget(footer);
        dialog.show();
        drainEvents();

        QToolButton* clear = offset->findChild<QToolButton*>();
        QAction* clearAction = offset->findChild<QAction*>(QStringLiteral("_q_qlineeditclearaction"));
        result.require(clear != nullptr && clear->inherits("QLineEditIconButton")
            && clearAction != nullptr, "hex_has_actual_native_clear_child_and_private_action");
        if (clear != nullptr && clearAction != nullptr)
        {
            const QIcon originalButtonIcon = clear->icon();
            const QIcon originalActionIcon = clearAction->icon();
            const QImage originalPixels = iconImage(originalButtonIcon);
            int textEdited = 0; // 只统计真实 clear 点击产生的业务输入通知。
            const QMetaObject::Connection editedConnection = QObject::connect(offset, &QLineEdit::textEdited, offset,
                [&textEdited](const QString&) { ++textEdited; });
            for (const bool defaultTheme : {false, true})
            {
                ks::ui::SvgThemeIconManager::instance().applyToApplication(
                    &app, defaultTheme ? KswordTheme::DefaultPrimaryAccentColor() : QColor(163, 67, 113),
                    defaultTheme);
                drainEvents();
                const QImage currentPixels = iconImage(clear->icon());
                result.require(clear->icon().cacheKey() == originalButtonIcon.cacheKey()
                    && clearAction->icon().cacheKey() == originalActionIcon.cacheKey(),
                    "native_clear_button_and_action_icon_identity_preserved");
                result.require(!originalPixels.isNull() && currentPixels == originalPixels,
                    "native_clear_x_contour_and_rgb_pixels_preserved");
                std::cout << "PAGE_REGRESSION_CLEAR_COLORS ORIGINAL=" << visibleColorCount(originalPixels)
                    << " CURRENT=" << visibleColorCount(currentPixels) << std::endl;
            }
            clear->click();
            result.require(offset->text().isEmpty() && textEdited == 1,
                "native_clear_click_clears_offset_and_notifies_exactly_once");
            QObject::disconnect(editedConnection); // 后续主题事件不得再引用已离开作用域的计数器。
            offset->setText(QStringLiteral("0x0"));
            for (int iteration = 0; iteration < 3; ++iteration)
            {
                drainEvents(); // 预览等待原生160ms clear淡入完整结束，不改其私有opacity。
            }
        }

        // 侧栏边缘必须由实际溢出与 overlay几何解释，不能凭蓝色像素猜选中残影。
        ks::ui::InstallFloatingScrollbars(scroll);
        scroll->ensureWidgetVisible(selected, 0, 0);
        ks::ui::RefreshFloatingScrollbars(scroll);
        drainEvents();
        // 悬浮条收回原生布局空隙后再定位最后一项，确认采样的是完整内容而非视口裁切边缘。
        scroll->ensureWidgetVisible(selected, 0, 0);
        drainEvents();
        QScrollBar* overlay = scroll->findChild<QScrollBar*>(
            QStringLiteral("ksword_floating_vertical_scrollbar"));
        result.require(scroll->width() == 240 && scroll->verticalScrollBar()->maximum() > 0,
            "file_navigation_real_fourteen_rows_overflow_fixed_sidebar");
        result.require(overlay != nullptr && overlay->isVisible()
            && overlay->geometry().right() == scroll->viewport()->geometry().right(),
            "navigation_blue_edge_is_bounded_scroll_overlay");
        if (overlay != nullptr)
        {
            std::cout << "PAGE_REGRESSION_NAV_RANGE MIN=" << scroll->verticalScrollBar()->minimum()
                << " MAX=" << scroll->verticalScrollBar()->maximum()
                << " OVERLAY=" << overlay->x() << ',' << overlay->y() << ','
                << overlay->width() << ',' << overlay->height() << std::endl;
        }
        const QColor navigationAccent = expectedAccent(*selected);
        const QRect selectedContent = selected->rect().adjusted(12, 8, -12, -8);
        const QPoint selectedSample(selectedContent.right() - 4, selectedContent.center().y());
        const QColor selectedFill = compositedColor(*selected, selectedSample);
        const QRect contentInViewport(selected->mapTo(scroll->viewport(), selectedContent.topLeft()),
            selectedContent.size());
        result.require(selectedContent.isValid() && scroll->viewport()->rect().contains(contentInViewport),
            "hex_navigation_selected_content_is_fully_visible");
        requireColor(result, selected->isChecked() && selectedFill == navigationAccent,
            "hex_navigation_actual_selected_fill_is_theme_accent", *selected, selectedFill, navigationAccent);

        // 同时检查整块内容覆盖，不能只挑一个恰好为强调色的像素掩盖残留底色。
        const QImage navigationFrame = dialog.grab().toImage();
        int accentPixels = 0;
        int contentPixels = 0;
        for (int y = selectedContent.top(); y <= selectedContent.bottom(); ++y)
        {
            for (int x = selectedContent.left(); x <= selectedContent.right(); ++x)
            {
                const QPoint point = selected->mapTo(&dialog, QPoint(x, y)) * navigationFrame.devicePixelRatio();
                if (navigationFrame.rect().contains(point))
                {
                    ++contentPixels;
                    accentPixels += navigationFrame.pixelColor(point) == navigationAccent ? 1 : 0;
                }
            }
        }
        result.require(contentPixels == selectedContent.width() * selectedContent.height()
            && accentPixels * 100 >= contentPixels * 85,
            "hex_navigation_theme_accent_covers_selected_content_area");

        // Footer真实父palette与disabled按钮独立验收；disabled不响应hover是正确行为。
        reportPalette("file_detail_footer", *footer);
        const QColor closeNormal = bodyColor(*close);
        requireColor(result, closeNormal != QColor(Qt::black) && closeNormal != bodyColor(*footer),
            "file_footer_enabled_normal_has_visible_solid_fill", *close, closeNormal, bodyColor(*footer),
            "different_nonblack");
        if (!KswordTheme::IsDarkModeEnabled())
        {
            savePreview(result, dialog, "output/page_theme_file_dialog.png");
        }
        setMouseOver(*close, true);
        const QColor closeHover = bodyColor(*close);
        requireColor(result, closeHover == expectedAccent(*close) && closeHover != closeNormal,
            "file_footer_enabled_hover_has_theme_accent", *close, closeHover, expectedAccent(*close));
        const QColor disabledNormal = bodyColor(*save);
        setMouseOver(*save, true);
        const QColor saveHover = bodyColor(*save);
        requireColor(result, saveHover == disabledNormal && !discard->isEnabled() && !save->isEnabled(),
            "file_footer_disabled_buttons_preserve_disabled_semantics", *save, saveHover, disabledNormal);
    }

    // 使用生产表格呈现入口验证表头底面、底部分隔与模型语义染色，不复制其 QSS。
    void tableHeaderFixture(FixtureChecks& result)
    {
        QWidget host;
        host.setAttribute(Qt::WA_DontShowOnScreen);
        host.setAutoFillBackground(true);
        host.resize(720, 270);
        auto* layout = new QVBoxLayout(&host);
        auto* table = new QTableView(&host);
        auto* model = new QStandardItemModel(3, 3, table);
        model->setHorizontalHeaderLabels({QStringLiteral("进程名"), QStringLiteral("内存使用"), QStringLiteral("CPU 占用")});
        model->setData(model->index(0, 0), QStringLiteral("KSword.exe"));
        model->setData(model->index(1, 0), QStringLiteral("APSDaemon.exe"));
        model->setData(model->index(1, 1), QStringLiteral("38.5 MiB"));
        model->setData(model->index(2, 0), QStringLiteral("System"));
        const QColor semanticFill(72, 103, 148); // 模型拥有的数据染色，不能被 chrome 接管。
        model->setData(model->index(1, 1), semanticFill, Qt::BackgroundRole);
        table->setModel(model);
        table->setAlternatingRowColors(true);
        table->setFocusPolicy(Qt::NoFocus);
        table->verticalHeader()->hide();
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        layout->addWidget(table);
        ks::ui::ApplyTablePresentation(table);
        host.show();
        table->clearSelection();
        drainEvents();

        // 靠近第一列表头右侧采样可避开标题字形；底线严格取最后一像素行。
        QHeaderView* header = table->horizontalHeader();
        const int headerX = header->sectionViewportPosition(0) + header->sectionSize(0) - 12;
        const QColor headerFill = compositedColor(*header->viewport(), QPoint(headerX, header->viewport()->height() / 2));
        const QColor headerLine = compositedColor(*header->viewport(), QPoint(headerX, header->viewport()->height() - 1));
        const QRect normalCell = table->visualRect(model->index(0, 0));
        const QColor normalFill = compositedColor(*table->viewport(), QPoint(normalCell.right() - 12, normalCell.center().y()));
        result.require(headerFill == KswordTheme::SurfaceMutedColor() && headerFill != normalFill,
            "production_table_header_has_distinct_surface");
        result.require(headerLine == KswordTheme::BorderColor() && headerLine != headerFill,
            "production_table_header_bottom_separator_is_visible");

        // 同时读回模型角色和真实单元格像素，防止角色仍在但被 item 样式遮住的旧回归。
        const QRect semanticCell = table->visualRect(model->index(1, 1));
        const QColor actualSemanticFill = compositedColor(*table->viewport(),
            QPoint(semanticCell.right() - 12, semanticCell.center().y()));
        result.require(model->data(model->index(1, 1), Qt::BackgroundRole).value<QColor>() == semanticFill
            && actualSemanticFill == semanticFill,
            "production_table_presentation_preserves_visible_model_background_role");
        std::cout << "PAGE_REGRESSION_HEADER FILL=" << headerFill.name().toStdString()
            << " LINE=" << headerLine.name().toStdString() << " BODY=" << normalFill.name().toStdString()
            << " SEMANTIC=" << actualSemanticFill.name().toStdString() << std::endl;
        savePreview(result, host, KswordTheme::IsDarkModeEnabled()
            ? "output/page_theme_table_header_dark.png" : "output/page_theme_table_header_light.png");
    }
}

int RunPageThemeRegressionFixtures(QApplication& application)
{
    // 恢复调用方状态，夹具只改变本进程主题，不保存设置或操纵外部窗口。
    const QPalette oldPalette = application.palette();
    const QString oldStyle = application.styleSheet();
    const bool oldDark = KswordTheme::IsDarkModeEnabled();
    const QColor oldAccent = KswordTheme::PrimaryAccentColor();
    FixtureChecks result;
    ks::ui::InstallGlobalFlatButtonTheme(&application);
    transparentToolbarFixture(application, result);
    for (int dark = 0; dark < 2; ++dark)
    {
        KswordTheme::SetDarkModeEnabled(dark != 0);
        application.setPalette(mainWindowPalette(application.palette()));
        application.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
        fileHexShellFixture(application, result);
        tableHeaderFixture(result);
    }
    KswordTheme::SetDarkModeEnabled(oldDark);
    KswordTheme::SetPrimaryAccentColor(oldAccent.name());
    application.setPalette(oldPalette);
    application.setStyleSheet(oldStyle);
    ks::ui::RefreshWidgetThemeBindings();
    ks::ui::SvgThemeIconManager::instance().applyToApplication(&application, oldAccent,
        oldAccent == KswordTheme::DefaultPrimaryAccentColor());
    drainEvents();
    std::cout << "PAGE_REGRESSION_CHECKS=" << result.checks
        << " PAGE_REGRESSION_FAILURES=" << result.failures << std::endl;
    return result.failures;
}
