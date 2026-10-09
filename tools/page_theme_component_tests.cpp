#include "../Ksword5.1/Ksword5.1/UI/FlatButtonTheme.h"
#include "../Ksword5.1/Ksword5.1/UI/FloatingScrollbars.h"
#include "../Ksword5.1/Ksword5.1/UI/ThemeBinding.h"
#include "../Ksword5.1/Ksword5.1/UI/ThemeAccentIcon.h"
#include "../Ksword5.1/Ksword5.1/UI/SvgThemeIconManager.h"
#include "../Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.h"
#include "../Ksword5.1/Ksword5.1/UI/VisibleTableWidget.h"
#include "../Ksword5.1/Ksword5.1/theme.h"
#include "page_theme_regression_fixtures.h"

#include <QAbstractScrollArea>
#include <QApplication>
#include <QFrame>
#include <QEnterEvent>
#include <QDoubleSpinBox>
#include <QComboBox>
#include "../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include <QElapsedTimer>
#include <QLineEdit>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QToolButton>
#include <QPainter>
#include <QFontDatabase>
#include <QFont>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QThread>
#include <QWheelEvent>
#include <iostream>
#include <limits>

namespace
{
    int failures = 0; // 独立组件验收失败数，不启动生产程序或访问驱动。
    int checks = 0;
    void drain(); // 各状态夹具共用 GUI 事件排空函数，定义在下面。
    QColor bodyColor(QWidget& widget); // 从真实控件帧读取避开字形的底色。

    void check(bool passed, const char* name)
    {
        ++checks;
        failures += passed ? 0 : 1;
        std::cout << (passed ? "PASS " : "FAIL ") << name << std::endl;
    }

    // 真实 QIconEngine 在不同按钮/状态/主题下必须对实际填充保持3:1，不改源图轮廓。
    void buttonIconThemeTest(QApplication& app)
    {
        QPixmap sourcePixmap(24, 24);
        sourcePixmap.fill(Qt::transparent);
        QPainter sourcePainter(&sourcePixmap);
        sourcePainter.fillRect(QRect(4, 4, 16, 16), QColor(58, 156, 255));
        sourcePainter.end();
        const QIcon sourceIcon(sourcePixmap);
        for (int dark = 0; dark < 2; ++dark)
        {
            KswordTheme::SetDarkModeEnabled(dark != 0);
            QWidget root;
            root.setAttribute(Qt::WA_DontShowOnScreen);
            root.resize(300, 80);
            QPalette palette = app.palette();
            palette.setColor(QPalette::Active, QPalette::Button,
                dark ? QColor(34, 43, 56) : QColor(240, 242, 245));
            palette.setColor(QPalette::Active, QPalette::ButtonText, dark ? Qt::white : Qt::black);
            palette.setColor(QPalette::Disabled, QPalette::Button,
                dark ? QColor(30, 36, 46) : QColor(229, 232, 238));
            palette.setColor(QPalette::Disabled, QPalette::ButtonText,
                dark ? QColor(100, 110, 120) : QColor(150, 154, 162));
            root.setStyleSheet(ks::ui::BuildFlatButtonStyle());
            for (const QColor accent : {QColor(Qt::white), QColor(Qt::black), QColor(58, 156, 255)})
            {
                palette.setColor(QPalette::Active, QPalette::Highlight, accent);
                root.setPalette(palette);
                for (int tone = 0; tone <= 3; ++tone)
                {
                    QToolButton button(&root);
                    button.setGeometry(0, 0, 40, 32);
                    button.setFocusPolicy(Qt::NoFocus);
                    button.setCheckable(true);
                    button.setStyleSheet(ks::ui::BuildFlatButtonStyle(
                        static_cast<ks::ui::FlatButtonTone>(tone)));
                    button.setIcon(ks::ui::MakeThemeButtonAccentIcon(sourceIcon, accent, &button));
                    root.show();
                    drain();
                    for (int state = 0; state < 5; ++state)
                    {
                        button.setChecked(state == 3);
                        button.setDown(state == 2);
                        button.setEnabled(state != 4);
                        const QIcon::Mode mode = state == 1 ? QIcon::Active
                            : state == 4 ? QIcon::Disabled : QIcon::Normal;
                        const QIcon::State iconState = state == 3 ? QIcon::On : QIcon::Off;
                        QColor background;
                        const bool known = ks::ui::TryGetFlatButtonBackground(
                            &button, mode, iconState, &background);
                        const QImage icon = button.icon().pixmap(QSize(24, 24), mode, iconState).toImage();
                        check(known && KswordTheme::ContrastRatio(icon.pixelColor(12, 12), background) >= 2.99,
                            "button_icon_real_state_contrast");
                    }
                }
            }

            // 默认主题也必须适配共享强调按钮；未知页面数据色保留原默认图标。
            QToolButton managed(&root);
            managed.setStyleSheet(ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Accent));
            managed.setIcon(sourceIcon);
            QToolButton unowned(&root);
            unowned.setStyleSheet(QStringLiteral("QToolButton{background:#136dcb;border:none;}"));
            unowned.setIcon(sourceIcon);
            ks::ui::SvgThemeIconManager::instance().applyToApplication(
                &app, QColor(58, 156, 255), true);
            drain();
            check(managed.icon().cacheKey() != sourceIcon.cacheKey(),
                "default_theme_shared_button_gets_context_icon");
            check(unowned.icon().cacheKey() == sourceIcon.cacheKey(),
                "default_theme_unknown_button_keeps_source_icon");
            QWidget dataParent(&root);
            dataParent.setGeometry(100, 0, 90, 40);
            dataParent.setStyleSheet(QStringLiteral(
                "QToolButton{background:#111111;color:white;border:none;}"));
            QToolButton inheritedData(&dataParent);
            inheritedData.setGeometry(0, 0, 70, 32);
            inheritedData.setFocusPolicy(Qt::NoFocus);
            inheritedData.setIcon(sourceIcon);
            dataParent.show();
            drain();
            QColor unknownBackground;
            check(bodyColor(inheritedData) == QColor(17, 17, 17),
                "unknown_ancestor_actual_fill_rendered");
            check(!ks::ui::TryGetFlatButtonBackground(
                &inheritedData, QIcon::Normal, QIcon::Off, &unknownBackground)
                && !inheritedData.property("ksword_flat_button_managed").toBool(),
                "unknown_ancestor_not_inferred_as_shared_theme");
            ks::ui::SvgThemeIconManager::instance().applyToApplication(
                &app, QColor(58, 156, 255), true);
            drain();
            check(inheritedData.icon().cacheKey() == sourceIcon.cacheKey(),
                "unknown_ancestor_default_icon_preserved");
            auto* transient = new QToolButton(&root); // 强调图标副本可以比原按钮存活更久。
            transient->setStyleSheet(ks::ui::BuildFlatButtonStyle());
            const QIcon retained = ks::ui::MakeThemeButtonAccentIcon(sourceIcon, Qt::white, transient);
            delete transient;
            check(!retained.pixmap(QSize(24, 24), QIcon::Active).isNull(),
                "button_icon_weak_context_safe_after_destroy");
        }
        KswordTheme::SetDarkModeEnabled(false);
    }

    // 等待事件队列真正推进，繁忙构建期间不依赖固定毫秒触发绘制。
    void drain()
    {
        for (int iteration = 0; iteration < 30; ++iteration)
        {
            QApplication::processEvents();
            QThread::msleep(2);
        }
    }

    QColor bodyColor(QWidget& widget)
    {
        const QImage frame = widget.grab().toImage();
        return frame.pixelColor(QPoint(7, widget.height() / 2) * frame.devicePixelRatio());
    }

    // 同色文字故障使用真实父 QSS 重现；绑定后测字形，不仅检查 palette 或模型值。
    void numericThemeTest(QApplication& app)
    {
        for (int dark = 0; dark < 2; ++dark)
        {
            KswordTheme::SetDarkModeEnabled(dark != 0);
            QWidget root;
            root.setAttribute(Qt::WA_DontShowOnScreen);
            const QString same = dark ? QStringLiteral("#121a24") : QStringLiteral("#fafafa");
            root.setStyleSheet(QStringLiteral(
                "QSpinBox,QLineEdit{color:%1;background-color:%1;border:1px solid %1;}")
                .arg(same));
            QSpinBox spin(&root);
            spin.setRange(1, std::numeric_limits<int>::max());
            spin.setValue(50);
            spin.setSuffix(QStringLiteral(" 次"));
            spin.setGeometry(0, 0, 120, 24);
            root.resize(140, 40);
            root.show();
            drain();
            QLineEdit* editor = spin.findChild<QLineEdit*>();
            check(editor != nullptr && editor->text() == QStringLiteral("50 次"),
                "numeric_value_exists_under_colliding_parent_color");
            check(ks::ui::BindSpinBoxTheme(&spin), "numeric_theme_bound");
            drain();
            const QImage frame = editor->grab().toImage();
            int readablePixels = 0;
            const QColor background = KswordTheme::SurfaceColor();
            for (int y = 2; y < frame.height() - 2; ++y)
            {
                for (int x = 2; x < frame.width() - 2; ++x)
                {
                    if (KswordTheme::ContrastRatio(frame.pixelColor(x, y), background) >= 3.0)
                    {
                        ++readablePixels;
                    }
                }
            }
            check(readablePixels > 6, "numeric_digits_visible_on_light_and_dark");
            check(spin.value() == 50 && spin.suffix() == QStringLiteral(" 次"),
                "numeric_theme_preserves_value_suffix");
            spin.setEnabled(false);
            drain();
            check(spin.value() == 50, "numeric_disabled_preserves_data");
        }
        KswordTheme::SetDarkModeEnabled(false);
        Q_UNUSED(app);
    }

    // 使用真实全局样式与局部 Combo 样式验证同排输入面，不启动主程序或访问业务状态。
    void unifiedInputSurfaceTest(QApplication& app)
    {
        const QString oldStyle = app.styleSheet(); // 夹具结束后归还调用方应用样式与调色板。
        const QPalette oldPalette = app.palette();
        for (int dark = 0; dark < 2; ++dark)
        {
            KswordTheme::SetDarkModeEnabled(dark != 0);
            const QColor pageSurface = KswordTheme::SurfaceColor();
            QPalette palette = oldPalette;
            for (const QPalette::ColorGroup group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled})
            {
                palette.setColor(group, QPalette::Window, pageSurface);
                palette.setColor(group, QPalette::Base, pageSurface);
                palette.setColor(group, QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
                palette.setColor(group, QPalette::Text, KswordTheme::TextPrimaryColor());
                palette.setColor(group, QPalette::WindowText, KswordTheme::TextPrimaryColor());
                palette.setColor(group, QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
            }
            app.setPalette(palette);
            app.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
            QWidget host;
            host.setAttribute(Qt::WA_DontShowOnScreen);
            host.setAutoFillBackground(true);
            host.setFocusPolicy(Qt::StrongFocus);
            host.resize(420, 210);

            // 数值框使用真实内部编辑器；普通输入与搜索分别保留原生及显式绑定路径。
            QSpinBox spin(&host);
            spin.setObjectName(QStringLiteral("integer"));
            spin.setGeometry(18, 20, 170, 30);
            spin.setValue(50);
            spin.setSuffix(QStringLiteral(" 次"));
            ks::ui::BindSpinBoxTheme(&spin);
            QDoubleSpinBox decimal(&host);
            decimal.setObjectName(QStringLiteral("decimal"));
            decimal.setGeometry(18, 60, 170, 30);
            decimal.setValue(12.50);
            ks::ui::BindSpinBoxTheme(&decimal);
            QComboBox combo(&host);
            combo.setObjectName(QStringLiteral("combo"));
            combo.setGeometry(18, 100, 170, 30);
            combo.addItem(QStringLiteral("Inspect"));
            combo.setStyleSheet(KswordTheme::ThemedComboBoxStyle());
            QLineEdit ordinary(&host);
            ordinary.setObjectName(QStringLiteral("ordinary"));
            ordinary.setGeometry(210, 20, 170, 30);
            ordinary.setPlaceholderText(QStringLiteral("Search address"));
            QLineEdit search(&host);
            search.setObjectName(QStringLiteral("search"));
            search.setGeometry(210, 60, 170, 30);
            search.setPlaceholderText(QStringLiteral("Search process"));
            ks::ui::BindSearchFieldTheme(&search);
            const QList<QWidget*> fields{&spin, &decimal, &combo, &ordinary, &search};

            // 真实 QFrame 结构线必须有可见像素，同时不为全部面板追加一圈线框。
            QFrame horizontal(&host);
            horizontal.setFrameShape(QFrame::HLine);
            horizontal.setGeometry(18, 170, 365, 2);
            QFrame vertical(&host);
            vertical.setFrameShape(QFrame::VLine);
            vertical.setGeometry(395, 20, 2, 110);
            host.show();
            // DontShowOnScreen 不会由窗口系统自动激活；显式设置测试应用的活动窗口。
            // 这只改变离屏夹具内部焦点归属，不触碰用户桌面上的任何窗口。
            // 隐藏夹具无平台激活事件，使用仍公开的应用内焦点入口；警告抑制只覆盖此测试调用。
            QT_WARNING_PUSH
            QT_WARNING_DISABLE_DEPRECATED
            QApplication::setActiveWindow(&host);
            QT_WARNING_POP
            drain();
            host.setFocus();
            const QColor surfaces[] = {KswordTheme::ControlInputSurfaceColor(),
                KswordTheme::ControlInputHoverColor(), KswordTheme::ControlInputFocusColor()};
            for (int state = 0; state < 3; ++state)
            {
                for (QWidget* field : fields)
                {
                    // 清理上个控件的真实 hover/focus，防止离屏平台遗留鼠标状态混淆样本。
                    for (QWidget* previous : fields)
                    {
                        previous->clearFocus();
                        previous->setAttribute(Qt::WA_UnderMouse, false);
                        QEvent leave(QEvent::Leave);
                        QApplication::sendEvent(previous, &leave);
                    }
                    host.setFocus();
                    const QPoint local(field->width() / 2, field->height() / 2);
                    if (state == 1)
                    {
                        QEnterEvent enter(QPointF(local), QPointF(field->mapTo(&host, local)),
                            QPointF(field->mapToGlobal(local)));
                        field->setAttribute(Qt::WA_UnderMouse, true);
                        QApplication::sendEvent(field, &enter);
                        QMouseEvent move(QEvent::MouseMove, QPointF(local),
                            QPointF(field->mapToGlobal(local)), Qt::NoButton, Qt::NoButton, Qt::NoModifier);
                        QApplication::sendEvent(field, &move);
                    }
                    else if (state == 2)
                    {
                        field->setFocus(Qt::TabFocusReason);
                    }
                    drain();
                    const QImage frame = field->grab().toImage();
                    const qreal ratio = frame.devicePixelRatio();
                    const auto sample = [&](int x, int y)
                    {
                        return frame.pixelColor(qRound(x * ratio), qRound(y * ratio));
                    };
                    const QColor body = sample(field->width() - 30, field->height() - 7);
                    const QColor topEdge = sample(field->width() / 2, 0);
                    const QColor leftEdge = sample(0, field->height() / 2);
                    const bool surfaceMatches = body == surfaces[state];
                    const bool borderless = topEdge == body && leftEdge == body;
                    check(surfaceMatches, "input_classes_share_normal_hover_focus_surface");
                    check(borderless, "input_normal_hover_focus_have_no_white_wire_frame");
                    if (state == 2)
                    {
                        check(field->hasFocus(), "input_focus_sample_is_actually_focused");
                    }
                    int readablePixels = 0; // 只取文字区域，排除右侧步进或下拉箭头的亮像素。
                    for (int y = 5; y < field->height() - 5; ++y)
                    {
                        for (int x = 4; x < 95; ++x)
                        {
                            if (KswordTheme::ContrastRatio(sample(x, y), body) >= 3.0)
                            {
                                ++readablePixels;
                            }
                        }
                    }
                    check(readablePixels > 6, "input_digits_text_and_placeholders_render_readably");
                    if (!surfaceMatches || !borderless || readablePixels <= 6
                        || (state == 2 && !field->hasFocus()))
                    {
                        // 失败信息包含真实像素、调色板 alpha 和活动窗口，避免把无焦点误判为样式错误。
                        const QColor placeholder = field->palette().color(QPalette::PlaceholderText);
                        std::cout << "INPUT_RENDER_DIAGNOSTIC MODE=" << (dark ? "dark" : "light")
                            << " NAME=" << field->objectName().toStdString()
                            << " CLASS=" << field->metaObject()->className()
                            << " STATE=" << state << " FOCUS=" << field->hasFocus()
                            << " ACTIVE=" << host.isActiveWindow() << " HOVER=" << field->underMouse()
                            << " ACTUAL=" << body.name(QColor::HexArgb).toStdString()
                            << " EXPECTED=" << surfaces[state].name(QColor::HexArgb).toStdString()
                            << " EDGE_TOP=" << topEdge.name(QColor::HexArgb).toStdString()
                            << " EDGE_LEFT=" << leftEdge.name(QColor::HexArgb).toStdString()
                            << " PLACEHOLDER=" << placeholder.name(QColor::HexArgb).toStdString()
                            << " TEXT_PIXELS=" << readablePixels << std::endl;
                    }
                }
            }
            const QImage frame = host.grab().toImage();
            const qreal ratio = frame.devicePixelRatio();
            const QColor horizontalPixel = frame.pixelColor(qRound(180 * ratio), qRound(170 * ratio));
            const QColor verticalPixel = frame.pixelColor(qRound(395 * ratio), qRound(80 * ratio));
            check(horizontalPixel == KswordTheme::BorderColor()
                && KswordTheme::ContrastRatio(horizontalPixel, pageSurface) > 1.2,
                "horizontal_structure_separator_is_visible");
            check(verticalPixel == KswordTheme::BorderColor()
                && KswordTheme::ContrastRatio(verticalPixel, pageSurface) > 1.2,
                "vertical_structure_separator_is_visible");
            check(spin.value() == 50 && spin.suffix() == QStringLiteral(" 次") && decimal.value() == 12.50,
                "unified_input_surface_preserves_numeric_values_and_suffix");
        }
        app.setPalette(oldPalette);
        app.setStyleSheet(oldStyle);
        KswordTheme::SetDarkModeEnabled(false);
        drain();
    }

    // 按钮状态与数据原色按页面语义处理，不能将任意本地 QSS 粗暴抹成默认样式。
    void buttonThemeTest(QApplication& app)
    {
        QWidget root;
        root.setAttribute(Qt::WA_DontShowOnScreen);
        QPalette colors = app.palette();
        colors.setColor(QPalette::Active, QPalette::Button, QColor(34, 43, 56));
        colors.setColor(QPalette::Active, QPalette::ButtonText, Qt::white);
        colors.setColor(QPalette::Active, QPalette::Highlight, QColor(250, 215, 60));
        colors.setColor(QPalette::Active, QPalette::HighlightedText, Qt::black);
        colors.setColor(QPalette::Disabled, QPalette::Button, QColor(30, 36, 46));
        colors.setColor(QPalette::Disabled, QPalette::ButtonText, QColor(100, 110, 120));
        root.setPalette(colors);
        root.setStyleSheet(ks::ui::BuildFlatButtonStyle());
        root.resize(500, 220);

        QPushButton button(QStringLiteral("8888"), &root);
        button.setGeometry(0, 0, 110, 32);
        button.setStyleSheet(ks::ui::BuildFlatButtonStyle()
            + QStringLiteral("QPushButton{padding:3px 6px;border-radius:3px;}"));
        QPushButton data(QStringLiteral("RGB"), &root);
        data.setGeometry(120, 0, 100, 32);
        data.setStyleSheet(QStringLiteral(
            "QPushButton{background:#136dcb;color:white;border:none;}"));
        root.show();
        drain();
        // 模拟 IRP 页先声明 Neutral、再显式指定 Danger、首次 Show 抢在主题队列前。
        QPushButton dangerous(QStringLiteral("IRP"), &root);
        dangerous.setGeometry(230, 0, 100, 32);
        dangerous.setFocusPolicy(Qt::NoFocus);
        dangerous.setStyleSheet(ks::ui::BuildFlatButtonStyle());
        ks::ui::ApplyFlatButtonTheme(&dangerous, ks::ui::FlatButtonTone::Danger);
        dangerous.show();
        drain();
        check(dangerous.property("ksword_flat_button_tone").toInt() == 2,
            "explicit_danger_tone_survives_first_show");
        check(bodyColor(dangerous) == KswordTheme::ErrorColor(),
            "explicit_danger_fill_rendered");
        const QColor normal = bodyColor(button);
        check(button.property("ksword_flat_button_managed").toBool(), "audited_button_live_bound");
        check(!data.property("ksword_flat_button_managed").toBool(), "data_color_not_auto_overwritten");
        check(bodyColor(data) == QColor(19, 109, 203), "data_rgb_preserved");

        button.setStyleSheet(ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Accent)
            + QStringLiteral("QPushButton{padding:3px 6px;border-radius:3px;}"));
        drain();
        check(button.property("ksword_flat_button_tone").toInt() == 1,
            "dynamic_column_preset_tone_changes");
        check(bodyColor(button) != normal, "dynamic_column_preset_color_changes");
        check(button.styleSheet().contains(QStringLiteral("padding:3px 6px")),
            "page_geometry_preserved");

        button.setCheckable(true);
        button.setChecked(true);
        button.setEnabled(false);
        drain();
        check(!button.isEnabled() && button.isChecked(), "disabled_checked_state_preserved");
        const QImage frame = button.grab().toImage();
        check(frame.pixelColor(QPoint(1, 16) * frame.devicePixelRatio())
            == frame.pixelColor(QPoint(7, 16) * frame.devicePixelRatio()), "button_no_wire_border");
        button.setEnabled(true);
        button.setChecked(false);
        const QColor before = bodyColor(button);
        colors.setColor(QPalette::Active, QPalette::Highlight, QColor(75, 140, 250));
        root.setPalette(colors);
        ks::ui::RefreshWidgetThemeBindings();
        drain();
        check(bodyColor(button) != before, "button_hot_palette_refresh");
        int clicks = 0;
        QObject::connect(&button, &QPushButton::clicked, [&clicks]() { ++clicks; });
        button.click();
        check(clicks == 1, "button_action_connection_preserved");
        // 页面运行中从共享按钮切换为真实数据色，旧主题绑定不得再次夺回样式。
        button.setStyleSheet(QStringLiteral(
            "QPushButton{background:#136dcb;color:white;border:none;}"));
        ks::ui::RefreshWidgetThemeBindings();
        drain();
        check(bodyColor(button) == QColor(19, 109, 203)
            && !button.styleSheet().contains(QStringLiteral("KSWORD_FLAT_BUTTON_BEGIN")),
            "managed_button_to_data_color_survives_theme_refresh");
        button.setStyleSheet(ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Accent));
        ks::ui::RefreshWidgetThemeBindings();
        drain();
        check(bodyColor(button) != QColor(19, 109, 203),
            "data_button_can_explicitly_return_to_shared_theme");
        const QString originalDataStyle = QStringLiteral(
            "QPushButton{background:#136dcb;color:white;border:none;}");
        data.setStyleSheet(originalDataStyle);
        ks::ui::ApplyFlatButtonTheme(&data, ks::ui::FlatButtonTone::Accent);
        drain();
        check(bodyColor(data) != QColor(19, 109, 203), "explicit_api_can_adopt_unknown_initial_style");
        data.setStyleSheet(originalDataStyle);
        ks::ui::RefreshWidgetThemeBindings();
        drain();
        check(data.styleSheet() == originalDataStyle && bodyColor(data) == QColor(19, 109, 203),
            "restored_initial_data_style_survives_copied_callback");
    }

    // 专用搜索框验证真实 placeholder 与无框表面，保留输入数据、选区及过滤信号。
    void searchFieldThemeTest(QApplication& app)
    {
        for (int dark = 0; dark < 2; ++dark)
        {
            KswordTheme::SetDarkModeEnabled(dark != 0);
            QWidget host;
            host.setAttribute(Qt::WA_DontShowOnScreen);
            host.resize(340, 100);
            host.setStyleSheet(QStringLiteral("QWidget#searchRoot{background:%1;}")
                .arg(KswordTheme::SurfaceColor().name()));
            host.setObjectName(QStringLiteral("searchRoot"));
            QWidget page(&host);
            page.setGeometry(0, 0, 340, 100);
            page.setStyleSheet(QStringLiteral("background:transparent;"));
            QLineEdit process(&page);
            QLineEdit module(&page);
            process.setGeometry(10, 10, 300, 24);
            module.setGeometry(10, 45, 300, 24);
            const QString oldStyle = QStringLiteral(
                "QLineEdit{border:1px solid white;padding:1px 3px;}"
                "QLineEdit:focus{border:1px solid white;}");
            process.setStyleSheet(oldStyle);
            module.setStyleSheet(oldStyle);
            process.setPlaceholderText(QStringLiteral("搜索进程"));
            module.setPlaceholderText(QStringLiteral("搜索模块"));
            process.setText(QStringLiteral("PID123"));
            process.setSelection(0, 3);
            int changed = 0;
            QObject::connect(&process, &QLineEdit::textChanged, [&changed]() { ++changed; });
            host.show();
            check(ks::ui::BindSearchFieldTheme(&process)
                && ks::ui::BindSearchFieldTheme(&module), "two_dedicated_search_fields_bound");
            drain();
            check(process.text() == QStringLiteral("PID123") && process.selectedText() == QStringLiteral("PID")
                && changed == 0, "search_binding_preserves_data_selection_filter_signals");
            check(process.styleSheet().contains(QStringLiteral("padding:1px 3px"))
                && process.geometry() == QRect(10, 10, 300, 24), "search_geometry_preserved");
            check(process.placeholderText() == QStringLiteral("搜索进程")
                && module.placeholderText() == QStringLiteral("搜索模块"), "specific_search_placeholders_preserved");
            const QImage frame = host.grab().toImage();
            const QColor surface = frame.pixelColor(QPoint(4, 57));
            const QColor inside = frame.pixelColor(QPoint(304, 57));
            const QColor edge = frame.pixelColor(QPoint(10, 57));
            check(KswordTheme::ContrastRatio(inside, surface) >= 1.14, "search_surface_distinct_from_page");
            check(edge == inside, "search_white_wire_border_removed");
            const QColor placeholder = module.palette().color(QPalette::Active, QPalette::PlaceholderText);
            check(placeholder.alpha() == 255 && KswordTheme::ContrastRatio(placeholder, inside) >= 4.49,
                "search_placeholder_opaque_and_readable");
            module.setEnabled(false);
            drain();
            check(module.placeholderText() == QStringLiteral("搜索模块")
                && module.palette().color(QPalette::Disabled, QPalette::PlaceholderText).alpha() == 255,
                "disabled_search_keeps_opaque_placeholder");
        }
        KswordTheme::SetDarkModeEnabled(false);
        Q_UNUSED(app);
    }

    // 真实原条维持策略和数值；视觉层不能占用 viewport，也不能另造滚动单位。
    void scrollbarThemeTest()
    {
        // 真实事件循环覆盖 1.1 秒空闲期与 180 毫秒淡出；刷新模式模拟持续采样页面。
        const auto waitForIdle = [](QAbstractScrollArea* area, bool refresh)
        {
            QElapsedTimer elapsed;
            elapsed.start();
            while (elapsed.elapsed() < 1500)
            {
                if (refresh)
                {
                    ks::ui::RefreshFloatingScrollbars(area);
                    area->viewport()->update();
                }
                QApplication::processEvents();
                QThread::msleep(5);
            }
            QApplication::processEvents();
        };
        QStandardItemModel model(1000, 20);
        ks::ui::TableActionTableView table;
        table.setAttribute(Qt::WA_DontShowOnScreen);
        table.setModel(&model);
        table.setTopActionBarHeight(28);
        table.setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
        table.setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        table.setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        table.setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        table.resize(480, 280);
        table.show();
        drain();
        const QSize noBars = table.viewport()->size();
        QScrollBar* originalV = table.verticalScrollBar();
        QScrollBar* originalH = table.horizontalScrollBar();
        table.setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        table.setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        ks::ui::InstallFloatingScrollbars(&table);
        drain();
        check(ks::ui::HasFloatingScrollbars(&table), "floating_installed");
        check(table.verticalScrollBar() == originalV && table.horizontalScrollBar() == originalH,
            "native_bar_objects_preserved");
        check(table.viewport()->size() == noBars, "floating_has_zero_layout_occupancy");
        check(table.topActionBarHeight() == 28, "table_action_bar_margins_preserved");
        check(originalV->sizeHint().width() == 0 && originalH->sizeHint().height() == 0,
            "native_extent_zero_for_hex_and_snapshot_layout");

        QScrollBar* overlayV = table.findChild<QScrollBar*>(
            QStringLiteral("ksword_floating_vertical_scrollbar"));
        QScrollBar* overlayH = table.findChild<QScrollBar*>(
            QStringLiteral("ksword_floating_horizontal_scrollbar"));
        check(overlayV != nullptr && overlayH != nullptr, "both_overlay_axes_exist");
        check(overlayV->isVisible() && overlayH->isVisible(), "both_overflow_axes_visible");

        // 连续布局与内容刷新不能算作用户滚动，否则进程列表永远无法自动隐藏。
        const int idleRange = originalV->maximum();
        waitForIdle(&table, true);
        check(!overlayV->isVisible() && !overlayH->isVisible(),
            "idle_fades_and_hides_despite_continuous_refresh");
        check(overlayV->testAttribute(Qt::WA_TransparentForMouseEvents)
            && overlayH->testAttribute(Qt::WA_TransparentForMouseEvents)
            && table.childAt(overlayV->geometry().center()) != overlayV,
            "hidden_overlay_leaves_no_mouse_capture_band");
        check(originalV->maximum() == idleRange && table.viewport()->size() == noBars,
            "idle_hide_keeps_native_range_and_viewport");

        // 以视口局部坐标派发悬停：先从隐藏态靠近实际几何边缘，再返回内容中央。
        const QPoint edgePoint = table.viewport()->mapFrom(&table, overlayV->geometry().center());
        const QPoint centerPoint = table.viewport()->rect().center();
        QHoverEvent edgeHover(QEvent::HoverMove, QPointF(edgePoint),
            QPointF(table.viewport()->mapToGlobal(edgePoint)), QPointF(centerPoint));
        QApplication::sendEvent(table.viewport(), &edgeHover);
        drain();
        check(overlayV->isVisible() && !overlayV->testAttribute(Qt::WA_TransparentForMouseEvents),
            "viewport_edge_hover_restores_hidden_overlay");
        QHoverEvent centerHover(QEvent::HoverMove, QPointF(centerPoint),
            QPointF(table.viewport()->mapToGlobal(centerPoint)), QPointF(edgePoint));
        QApplication::sendEvent(table.viewport(), &centerHover);
        waitForIdle(&table, false);
        check(!overlayV->isVisible(), "leaving_edge_restarts_idle_hide");
        originalV->setValue(originalV->value() + 1);
        drain();
        check(overlayV->isVisible(), "native_value_change_restores_hidden_overlay");

        const int originalPageStep = originalV->pageStep(); // 测试后还原原生业务步长。
        const int originalSingleStep = originalV->singleStep();
        const bool originalTracking = originalV->hasTracking();
        const bool originalInvertedControls = originalV->invertedControls();
        // 页步长可以单独更新而不改变量程；下一次真实视口绘制必须带入新值。
        originalV->setPageStep(73);
        originalV->setSingleStep(9);
        originalV->setTracking(false);
        originalV->setInvertedControls(true);
        table.viewport()->update();
        drain();
        check(overlayV->pageStep() == 73 && overlayV->singleStep() == 9,
            "step_only_change_synchronized_on_paint");
        check(!overlayV->hasTracking() && overlayV->invertedControls(),
            "control_flags_without_value_signal_synchronized");
        originalV->setPageStep(originalPageStep);
        originalV->setSingleStep(originalSingleStep);
        originalV->setTracking(originalTracking);
        originalV->setInvertedControls(originalInvertedControls);
        int changes = 0;
        QObject::connect(originalV, &QScrollBar::valueChanged, [&changes]() { ++changes; });
        originalV->setValue(100);
        drain();
        check(overlayV->value() == 100 && changes > 0, "original_business_signal_preserved");
        overlayV->setValue(120);
        drain();
        check(originalV->value() == 120, "overlay_updates_original_value");

        table.setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        ks::ui::RefreshFloatingScrollbars(&table);
        originalH->setValue(originalH->value() + 1); // 横条按用户滚动唤醒，不要求闲置常显。
        drain();
        check(!overlayV->isVisible() && overlayH->isVisible(), "business_always_off_respected");
        table.setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        table.setProperty("KSWORD_TABLE_INTERACTION_COMPARISON_SOURCE_ACTIVE", true);
        ks::ui::RefreshFloatingScrollbars(&table);
        drain();
        check(!overlayV->isVisible() && !overlayH->isVisible(), "comparison_source_hidden");
        table.setProperty("KSWORD_TABLE_INTERACTION_COMPARISON_SOURCE_ACTIVE", false);
        ks::ui::RefreshFloatingScrollbars(&table);
        drain();
        check(overlayV->isVisible(), "comparison_restore");
        table.setLayoutDirection(Qt::RightToLeft);
        ks::ui::RefreshFloatingScrollbars(&table);
        drain();
        check(overlayV->geometry().left() <= table.viewport()->geometry().left() + 2,
            "rtl_overlay_on_content_edge");
        const int normalWidth = overlayV->width();
        ks::ui::SetFloatingScrollbarScale(&table, 2.0);
        drain();
        check(overlayV->width() > normalWidth, "floating_window_scale_applied");
        ks::ui::SetFloatingScrollbarScale(&table, 1.0);
        table.setLayoutDirection(Qt::LeftToRight);
        ks::ui::SetFloatingScrollbarInsets(&table, QMargins(0, 0, 26, 0));
        drain();
        check(overlayV->geometry().right() <= table.viewport()->geometry().right() - 26,
            "hex_copy_column_protected");
        table.setViewport(new QWidget(&table));
        ks::ui::RefreshFloatingScrollbars(&table);
        originalV->setValue(originalV->value() + 1); // 替换后的源条仍能唤醒同一视觉条。
        drain();
        check(overlayV->isVisible(), "viewport_replacement_keeps_overlay");

        // 同一用户 wheel 仍通过现有 GlobalSmoothScrollSupport 更新原始 bar。
        ks::ui::SetGlobalSmoothScrollingEnabled(false);
        originalV->setValue(0);
        QWheelEvent wheel(QPointF(2, 20), QPointF(overlayV->mapToGlobal(QPoint(2, 20))),
            QPoint(), QPoint(0, -120), Qt::NoButton, Qt::NoModifier, Qt::NoScrollPhase, false);
        QApplication::sendEvent(overlayV, &wheel);
        drain();
        check(originalV->value() > 0, "overlay_wheel_uses_existing_native_path");

        table.setProperty("ksword_preserve_native_scrollbars", true);
        ks::ui::RefreshFloatingScrollbars(&table);
        drain();
        check(!ks::ui::HasFloatingScrollbars(&table) && !overlayV->isVisible(),
            "explicit_page_native_optout");
        check(originalV->sizeHint().width() > 0, "native_extent_restored_on_optout");

        // 文本纵轴保留视觉行步长；大地址画布仍使用原生 INT_MAX 比例量程。
        QPlainTextEdit editor;
        editor.setAttribute(Qt::WA_DontShowOnScreen);
        editor.setPlainText(QString(600, QChar('x')).replace(QStringLiteral("xx"), QStringLiteral("x\n")));
        editor.resize(320, 120);
        editor.show();
        drain();
        QScrollBar* textBar = editor.verticalScrollBar();
        const int textStep = textBar->singleStep();
        ks::ui::InstallFloatingScrollbars(&editor);
        drain();
        check(textBar == editor.verticalScrollBar() && textBar->singleStep() == textStep,
            "text_visual_line_units_preserved");

        QAbstractScrollArea canvas;
        canvas.setAttribute(Qt::WA_DontShowOnScreen);
        canvas.resize(200, 220);
        canvas.verticalScrollBar()->setRange(0, std::numeric_limits<int>::max());
        canvas.verticalScrollBar()->setPageStep(80);
        canvas.show();
        ks::ui::InstallFloatingScrollbars(&canvas);
        drain();
        QScrollBar* huge = canvas.findChild<QScrollBar*>(
            QStringLiteral("ksword_floating_vertical_scrollbar"));
        check(huge != nullptr && huge->maximum() == std::numeric_limits<int>::max(),
            "hex_int_max_range_preserved");
        int pressed = 0;
        QObject::connect(canvas.verticalScrollBar(), &QScrollBar::sliderPressed, [&pressed]() { ++pressed; });
        QMouseEvent press(QEvent::MouseButtonPress, QPointF(5, 5), QPointF(huge->mapToGlobal(QPoint(5, 5))),
            Qt::LeftButton, Qt::LeftButton, Qt::NoModifier);
        QApplication::sendEvent(huge, &press);
        QMouseEvent move(QEvent::MouseMove, QPointF(5, huge->height() - 2),
            QPointF(huge->mapToGlobal(QPoint(5, huge->height() - 2))),
            Qt::NoButton, Qt::LeftButton, Qt::NoModifier);
        QApplication::sendEvent(huge, &move);
        check(pressed == 1 && canvas.verticalScrollBar()->isSliderDown(),
            "overlay_drag_bridges_native_slider_pressed");
        check(canvas.verticalScrollBar()->value() > std::numeric_limits<int>::max() / 2,
            "hex_large_range_drag_no_overflow");
        waitForIdle(&canvas, true);
        check(huge->isVisible() && !huge->testAttribute(Qt::WA_TransparentForMouseEvents)
            && canvas.verticalScrollBar()->isSliderDown(),
            "drag_remains_visible_beyond_idle_delay");
        QMouseEvent release(QEvent::MouseButtonRelease, QPointF(5, huge->height() - 2),
            QPointF(huge->mapToGlobal(QPoint(5, huge->height() - 2))),
            Qt::LeftButton, Qt::NoButton, Qt::NoModifier);
        QApplication::sendEvent(huge, &release);
        check(!canvas.verticalScrollBar()->isSliderDown(), "native_slider_release_preserved");
    }
}

// 只运行实际 UI 组件与合成模型；不启动主程序、不加载驱动、不创建临时编译目录。
int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    // offscreen 平台不自动枚举 Windows 字体；显式加载系统字体，确保实际文字而非方框被采样。
    const int fixtureFont = QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    if (fixtureFont >= 0 && !QFontDatabase::applicationFontFamilies(fixtureFont).isEmpty())
    {
        app.setFont(QFont(QFontDatabase::applicationFontFamilies(fixtureFont).first(), 9));
    }
    ks::ui::InstallGlobalFlatButtonTheme(&app);
    ks::ui::InstallGlobalSmoothScrollSupport(&app);
    // 仅隔离本轮输入渲染时可快速结束，正常无参数执行仍跑完整组件集合。
    if (app.arguments().contains(QStringLiteral("--input-only")))
    {
        unifiedInputSurfaceTest(app);
        std::cout << "INPUT_THEME_CHECKS=" << checks << " FAILURES=" << failures << std::endl;
        return failures == 0 ? 0 : 1;
    }
    numericThemeTest(app);
    unifiedInputSurfaceTest(app);
    buttonThemeTest(app);
    buttonIconThemeTest(app);
    searchFieldThemeTest(app);
    scrollbarThemeTest();
    failures += RunPageThemeRegressionFixtures(app);
    std::cout << "PAGE_THEME_CHECKS=" << checks << " FAILURES=" << failures << std::endl;
    return failures == 0 ? 0 : 1;
}
