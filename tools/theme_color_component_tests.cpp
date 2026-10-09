// 离屏验证实际生产组件的配色与主题切换；仅使用合成文本/日志/进度，不访问驱动。
#include "../Ksword5.1/Ksword5.1/theme.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeTextEdit.h"
#include "../Ksword5.1/Ksword5.1/UI/SvgThemeIconManager.h"
#include "../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include "../Ksword5.1/Ksword5.1/UI/ThemedMessageBox.h"
#include "../Ksword5.1/Ksword5.1/UI/CommandExecutionPopup.h"
#include "../Ksword5.1/Ksword5.1/Framework/NotificationCardManager.h"
#include "../Ksword5.1/Ksword5.1/Framework/LogDockWidget.h"
#include "../Ksword5.1/Ksword5.1/Framework/CustomTitleBar.h"

#include <QApplication>
#include <QBrush>
#include <QEvent>
#include <QEnterEvent>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QRegularExpression>
#include <QResource>
#include <QScrollBar>
#include <QStyleOptionButton>
#include <QTableView>
#include <QTest>
#include <QTextBlock>
#include <QTextLayout>
#include <QToolButton>
#include <array>
#include <cstdlib>
#include <iostream>

namespace
{
    class HoverProbeButton final : public QPushButton
    {
    public:
        using QPushButton::QPushButton;
        QStyle::State actualStyleState() const
        {
            QStyleOptionButton option;
            initStyleOption(&option);
            return option.state;
        }
    };
    unsigned checks = 0;
    void require(const bool value, const char* message)
    {
        ++checks;
        if (!value)
        {
            std::cerr << "FAIL [" << checks << "]: " << message << '\n';
            std::exit(1);
        }
    }

    void drainEvents()
    {
        QTest::qWait(25);
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QApplication::processEvents();
    }

    void applyTheme(const bool dark, const QString& seed)
    {
        KswordTheme::SetDarkModeEnabled(dark);
        KswordTheme::SetMainBackgroundColor(QString());
        KswordTheme::SetPrimaryAccentColor(seed);
        QPalette palette = qApp->palette();
        palette.setColor(QPalette::Window, KswordTheme::MainBackgroundColor());
        palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::Button, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::WindowText, KswordTheme::MainBackgroundTextColor());
        palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Highlight, KswordTheme::PrimaryAccentColor());
        palette.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor());
        palette.setColor(QPalette::Disabled, QPalette::Text, KswordTheme::TextDisabledColor());
        QApplication::setPalette(palette);
        qApp->setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
        drainEvents();
    }

    QColor iconColor(const QIcon& icon, const QIcon::Mode mode, const QIcon::State state = QIcon::Off)
    {
        const QImage image = icon.pixmap(QSize(22, 22), mode, state).toImage();
        require(!image.isNull(), "real editor toolbar contains a rendered SVG");
        int alpha = -1;
        QColor result;
        for (int y = 0; y < image.height(); ++y)
        {
            for (int x = 0; x < image.width(); ++x)
            {
                const QColor pixel = image.pixelColor(x, y);
                if (pixel.alpha() > alpha) { alpha = pixel.alpha(); result = pixel; }
            }
        }
        require(alpha > 100, "toolbar glyph retains visible alpha and its SVG silhouette");
        result.setAlpha(255);
        return result;
    }

    QColor syntaxForeground(QPlainTextEdit* editor)
    {
        const auto formats = editor->document()->firstBlock().layout()->formats();
        for (const auto& range : formats)
        {
            if (range.start == 0 && range.length > 0) return range.format.foreground().color();
        }
        return QColor();
    }

    void verifyEditorState(QPlainTextEdit* editor, const QString& text, const int cursor,
        const int vertical, const int horizontal, const bool modified, const bool undo)
    {
        require(editor->toPlainText() == text, "theme change retains exact editor text");
        require(editor->textCursor().position() == cursor, "theme change retains cursor position");
        require(editor->verticalScrollBar()->value() == vertical
            && editor->horizontalScrollBar()->value() == horizontal, "theme change retains scrolling");
        require(editor->document()->isModified() == modified
            && editor->document()->isUndoAvailable() == undo, "theme change retains modified/undo session");
        const QColor base = editor->palette().color(QPalette::Base);
        const QColor accent = editor->palette().color(QPalette::Highlight);
        const QColor currentLine = KswordTheme::BlendColors(base, accent, 18);
        const std::array<QColor, 2> backgrounds{ base, currentLine };
        const QColor keyword = KswordTheme::EnsureTextContrastForBackgrounds(
            KswordTheme::AccentColor(KswordTheme::AccentRole::Purple), backgrounds.data(),
            static_cast<int>(backgrounds.size()));
        require(syntaxForeground(editor) == keyword,
            "existing C++ keyword QTextLayout uses the current theme without editing");
        require(KswordTheme::ContrastRatio(keyword, base) >= 4.499
            && KswordTheme::ContrastRatio(keyword, currentLine) >= 4.499,
            "syntax remains readable on the document and current-line backgrounds");
        const auto selections = editor->extraSelections();
        require(!selections.isEmpty()
            && selections.front().format.background().color() == currentLine,
            "existing current-line ExtraSelection uses the current palette");
        bool foundPair = false;
        for (const auto& selection : selections)
        {
            if (selection.cursor.hasSelection())
            {
                foundPair = true;
                const QColor background = selection.format.background().color();
                require(background == KswordTheme::BlendColors(base, accent, 65),
                    "matched bracket background follows the current palette role");
                require(KswordTheme::ContrastRatio(selection.format.foreground().color(), background) >= 4.499,
                    "matched bracket foreground remains readable on its own background");
            }
        }
        require(foundPair, "theme refresh retains bracket matching selections");
    }

    void testEditors(QApplication& application)
    {
        applyTheme(false, QStringLiteral("#808080"));
        CodeTextEdit standalone;
        CodeEditorWidget composite;
        composite.resize(1000, 500);
        composite.setRawText(QStringLiteral("int main() { return 1; }\nunchanged"));
        standalone.setPlainText(QStringLiteral("int main() { return 1; }\nunchanged"));
        standalone.setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Cpp);
        composite.show(); standalone.show();
        auto* embedded = composite.findChild<QPlainTextEdit*>();
        require(embedded != nullptr, "real CodeEditorWidget contains its private text editor");
        auto* embeddedCode = dynamic_cast<CodeTextEdit*>(embedded);
        require(embeddedCode != nullptr, "composite editor uses the shared lexical editor");
        embeddedCode->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Cpp);
        std::array<QPlainTextEdit*, 2> editors{ &standalone, embedded };
        for (auto* editor : editors)
        {
            QTextCursor edit = editor->textCursor();
            edit.movePosition(QTextCursor::End); edit.insertText(QStringLiteral("!"));
            edit.setPosition(9); editor->setTextCursor(edit);
        }
        drainEvents();
        const auto buttons = composite.findChildren<QToolButton*>();
        QToolButton* probe = nullptr;
        for (auto* button : buttons)
        {
            if (button->property("ksword_editor_icon_path").toString().endsWith(QStringLiteral("codeeditor_new.svg")))
                probe = button;
        }
        require(probe != nullptr, "real editor exposes its new-file toolbar glyph");
        int textChanges = 0;
        for (auto* editor : editors)
            QObject::connect(editor, &QPlainTextEdit::textChanged, &application, [&]() { ++textChanges; });
        std::array<QString, 2> texts{ standalone.toPlainText(), embedded->toPlainText() };
        std::array<int, 2> cursors{ standalone.textCursor().position(), embedded->textCursor().position() };
        for (const bool dark : { false, true })
        {
            // 主题往返比较使用相同的非悬停状态，不能把新底色与鼠标状态混为一项。
            QTest::mouseMove(&composite, QPoint(composite.width() - 5, composite.height() - 5));
            drainEvents();
            applyTheme(dark, QString());
            const QImage defaultNormal = probe->icon().pixmap(QSize(22, 22), QIcon::Normal).toImage();
            for (const QString& seed : { QStringLiteral("#ffffff"), QStringLiteral("#000000"),
                QStringLiteral("#808080"), QStringLiteral("#20cc80"), QStringLiteral("#c08040"), QString() })
            {
                std::array<int, 2> vertical{}, horizontal{};
                std::array<bool, 2> modified{}, undo{};
                for (std::size_t i = 0; i < editors.size(); ++i)
                {
                    vertical[i] = editors[i]->verticalScrollBar()->value();
                    horizontal[i] = editors[i]->horizontalScrollBar()->value();
                    modified[i] = editors[i]->document()->isModified();
                    undo[i] = editors[i]->document()->isUndoAvailable();
                }
                applyTheme(dark, seed);
                for (std::size_t i = 0; i < editors.size(); ++i)
                    verifyEditorState(editors[i], texts[i], cursors[i], vertical[i], horizontal[i], modified[i], undo[i]);
                require(probe->property("ksword_theme_icon_managed").toBool(), "editor glyph is owned by its state renderer");
                require(KswordTheme::ContrastRatio(iconColor(probe->icon(), QIcon::Normal), probe->parentWidget()->palette().color(QPalette::Base)) >= 2.999,
                    "Normal editor glyph is readable even with white/black/gray accent");
                require(KswordTheme::ContrastRatio(iconColor(probe->icon(), QIcon::Active), probe->palette().color(QPalette::AlternateBase)) >= 2.999,
                    "hover glyph contrasts its actual palette alternate-base surface");
                require(KswordTheme::ContrastRatio(iconColor(probe->icon(), QIcon::Normal, QIcon::On), KswordTheme::PrimaryAccentColor()) >= 2.999,
                    "checked glyph contrasts its actual checked surface");
                const auto stable = probe->icon().pixmap(QSize(22, 22), QIcon::Disabled).toImage();
                ks::ui::SvgThemeIconManager::instance().applyToApplication(&application,
                    KswordTheme::PrimaryAccentColor(), seed.isEmpty());
                drainEvents();
                require(probe->icon().pixmap(QSize(22, 22), QIcon::Disabled).toImage() == stable,
                    "global SVG tint leaves editor Disabled state pixels intact");
                QTest::mousePress(probe, Qt::LeftButton);
                drainEvents();
                const QColor pressed = KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -14, -40);
                require(KswordTheme::ContrastRatio(iconColor(probe->icon(), QIcon::Normal), pressed) >= 2.999,
                    "pressed Normal glyph also contrasts its actual darker surface");
                // 释放前取消down，避免测试触发新建业务动作。
                probe->setDown(false);
                QTest::mouseRelease(probe, Qt::LeftButton);
                QTest::mouseMove(&composite, QPoint(composite.width() - 5, composite.height() - 5));
                drainEvents();
                require(KswordTheme::ContrastRatio(iconColor(probe->icon(), QIcon::Normal), probe->parentWidget()->palette().color(QPalette::Base)) >= 2.999,
                    "cancelled press returns Normal glyph to the actual editor surface");
                if (seed.isEmpty())
                    require(probe->icon().pixmap(QSize(22, 22), QIcon::Normal).toImage() == defaultNormal,
                        "returning to the default seed restores the same editor glyph pixels");
                require(textChanges == 0, "palette/highlighter changes do not emit text edits");
            }
        }
        // 仅父工具栏改变调色板也必须补刷新；不依赖按钮自身 Base 发生变化。
        QWidget* toolbar = probe->parentWidget();
        const QPalette originalToolbarPalette = toolbar->palette();
        const QImage originalToolbarGlyph = probe->icon().pixmap(QSize(22, 22), QIcon::Normal).toImage();
        QImage previousToolbarGlyph;
        for (const QColor& background : { QColor(Qt::white), QColor(Qt::black) })
        {
            QPalette localPalette = originalToolbarPalette;
            localPalette.setColor(QPalette::Base, background);
            toolbar->setPalette(localPalette);
            drainEvents();
            require(KswordTheme::ContrastRatio(iconColor(probe->icon(), QIcon::Normal), background) >= 2.999,
                "toolbar-only palette changes recalibrate the transparent normal glyph");
            const QImage currentGlyph = probe->icon().pixmap(QSize(22, 22), QIcon::Normal).toImage();
            if (!previousToolbarGlyph.isNull())
                require(currentGlyph != previousToolbarGlyph,
                    "opposite parent surfaces produce freshly calibrated glyph pixels");
            previousToolbarGlyph = currentGlyph;
        }
        toolbar->setPalette(originalToolbarPalette);
        drainEvents();
        require(probe->icon().pixmap(QSize(22, 22), QIcon::Normal).toImage() == originalToolbarGlyph,
            "restoring only the toolbar palette restores its glyph pixels");
        for (auto* editor : editors)
        {
            const QString oldText = editor->toPlainText();
            const int beforeInsert = textChanges;
            QTextCursor edit = editor->textCursor();
            edit.insertText(QStringLiteral("Z"));
            drainEvents();
            require(textChanges > beforeInsert && editor->toPlainText() != oldText,
                "real edits still emit textChanged after theme refresh");
            const int beforeUndo = textChanges;
            editor->undo(); drainEvents();
            require(textChanges > beforeUndo && editor->toPlainText() == oldText,
                "real undo still emits textChanged and restores pre-edit content");
        }
        const int afterEdits = textChanges;
        applyTheme(false, QStringLiteral("#c08040"));
        require(textChanges == afterEdits, "later palette refresh still leaves genuine edit signals isolated");
        // 排队后立即删除；Qt上下文必须取消所有主题任务。
        auto* disposable = new CodeEditorWidget;
        auto* plainDisposable = new CodeTextEdit;
        QEvent event(QEvent::PaletteChange);
        QApplication::sendEvent(disposable, &event); QApplication::sendEvent(plainDisposable, &event);
        delete disposable; delete plainDisposable;
        drainEvents();
        require(true, "queued editor theme refresh survives immediate component destruction");
        QObject::disconnect(&standalone, nullptr, &application, nullptr);
        QObject::disconnect(embedded, nullptr, &application, nullptr);
    }

    QColor styleColor(const QString& style, const QString& selector)
    {
        const QRegularExpression expression(QRegularExpression::escape(selector) + QStringLiteral("\\{color:([^;]+)"));
        return QColor(expression.match(style).captured(1));
    }

    void testNotificationsAndLog()
    {
        applyTheme(false, QStringLiteral("#c08040"));
        QWidget host;
        host.resize(1100, 750); host.show();
        QObject taskOwner;
        ks::ui::NotificationCardManager manager(&host, &host);
        ks::settings::AppearanceSettings settings;
        settings.notificationMinimumLevel = 0;
        settings.notificationLogDisplaySeconds = 60;
        settings.notificationDisplayPlacement = ks::settings::NotificationDisplayPlacement::MainWindow;
        manager.applySettings(settings);
        kEvent event{};
        event.level = kLogLevel::Debug; event.content = "theme-fixture-debug";
        KswordARKEventEntry.add(event);
        event.level = kLogLevel::Error; event.content = "theme-fixture-error";
        KswordARKEventEntry.add(event);
        const int taskId = kPro.add(&taskOwner, "theme-fixture-task", "theme-fixture-progress");
        require(taskId > 0, "fixture creates only an in-memory task record");
        QTest::qWait(120);
        const auto logRevision = KswordARKEventEntry.Revision();
        const auto progressRevision = kPro.Revision();
        LogDockWidget log;
        log.refreshNow();
        auto* table = log.findChild<QTableView*>();
        require(table != nullptr, "real LogDockWidget uses a table model");
        for (const bool dark : { false, true })
        {
            for (const QString& seed : { QStringLiteral("#20cc80"), QStringLiteral("#ffffff"),
                QStringLiteral("#808080"), QStringLiteral("#000000"), QString() })
            {
                applyTheme(dark, seed); manager.refreshVisuals(); drainEvents();
                unsigned cards = 0;
                for (QWidget* widget : QApplication::allWidgets())
                {
                    if (widget->objectName() != QStringLiteral("ksNotificationCardFrame")) continue;
                    ++cards;
                    auto* body = widget->findChild<QLabel*>(QStringLiteral("ksNotificationCardBody"));
                    require(body != nullptr, "notification retains its existing synthetic data");
                    const QColor accent = body->text() == QStringLiteral("theme-fixture-debug")
                        ? KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, -12, -38)
                        : body->text() == QStringLiteral("theme-fixture-error")
                        ? KswordTheme::ErrorColor() : KswordTheme::PrimaryAccentColor();
                    require(widget->styleSheet().contains(QStringLiteral("border-left:4px solid %1;").arg(accent.name())),
                        "stored notifications follow the current semantic accent after multiple switches");
                    const QColor foreground = styleColor(widget->styleSheet(), QStringLiteral("#ksNotificationCardCopy"));
                    require(foreground.isValid() && KswordTheme::ContrastRatio(foreground, KswordTheme::SurfaceColor()) >= 4.499,
                        "copy text contrasts its actual notification surface");
                    const QColor hover = styleColor(widget->styleSheet(), QStringLiteral("#ksNotificationCardCopy:hover"));
                    // hover规则的color在末尾，单独提取实际声明。
                    const QRegularExpression hoverExpression(QStringLiteral("#ksNotificationCardCopy:hover\\{[^}]*color:(#[0-9a-fA-F]+);\\}"));
                    const QColor hoverForeground(hoverExpression.match(widget->styleSheet()).captured(1));
                    (void)hover;
                    require(hoverForeground.isValid() && KswordTheme::ContrastRatio(hoverForeground,
                        KswordTheme::BlendColors(KswordTheme::SurfaceColor(), accent, 36)) >= 4.499,
                        "copy hover text contrasts its own composited background");
                }
                require(cards == 3, "continuous theme updates retain all three existing notification cards");
                require(KswordARKEventEntry.Revision() == logRevision && kPro.Revision() == progressRevision,
                    "notification recoloring does not refresh or mutate source data");
                bool checkedError = false;
                for (int row = 0; row < table->model()->rowCount(); ++row)
                {
                    const auto index = table->model()->index(row, 2);
                    if (index.data().toString() != QStringLiteral("theme-fixture-error")) continue;
                    const QColor background = index.data(Qt::BackgroundRole).value<QBrush>().color();
                    const QColor foreground = index.data(Qt::ForegroundRole).value<QBrush>().color();
                    require(foreground == KswordTheme::OnAccentColor(background)
                        && KswordTheme::ContrastRatio(foreground, background) >= 4.499,
                        "existing Error log model row calibrates foreground against its real background");
                    checkedError = true;
                }
                require(checkedError, "real log model retained the synthetic Error row");
            }
        }
        manager.clearCards();
    }

    void testButtons()
    {
        // 复用同一组组件，验证同一明暗模式内的连续种子变化，不只验证新建窗口。
        ks::ui::CustomTitleBar title;
        QMessageBox message(QMessageBox::Information, QStringLiteral("fixture"), QStringLiteral("fixture"), QMessageBox::Ok);
        message.setWindowModality(Qt::NonModal);
        message.show();
        QWidget popupHost;
        popupHost.resize(1000, 700);
        QWidget anchor(&popupHost);
        anchor.setGeometry(20, 20, 500, 40);
        QLineEdit command(&anchor);
        command.setText(QStringLiteral("fixture-command-never-executed"));
        ks::ui::CommandExecutionPopup popup(&popupHost, &anchor, &command);
        popupHost.show();
        popup.setCommandModeActive(true);
        for (const bool dark : { false, true })
        {
            for (const QString& seed : { QStringLiteral("#808080"), QStringLiteral("#ffffff"),
                QStringLiteral("#000000"), QStringLiteral("#20cc80"), QString() })
            {
                applyTheme(dark, seed);
                HoverProbeButton button(QStringLiteral("MMMMMMMM"));
                QFont buttonFont = button.font();
                buttonFont.setPointSize(20);
                button.setFont(buttonFont);
                button.setStyleSheet(KswordTheme::ThemedButtonStyle());
                button.resize(200, 50); button.show(); drainEvents();
                for (const bool pressed : { false, true })
                {
                    button.setAttribute(Qt::WA_UnderMouse, true);
                    QTest::mouseMove(&button, button.rect().center());
                    QEnterEvent enter(button.rect().center(), button.rect().center(), button.mapToGlobal(button.rect().center()));
                    QApplication::sendEvent(&button, &enter);
                    // 离屏平台的QTest移动可能只移动系统光标；真实MouseMove更新QPushButton私有hovering。
                    QMouseEvent move(QEvent::MouseMove, button.rect().center(),
                        button.mapToGlobal(button.rect().center()), Qt::NoButton, Qt::NoButton, Qt::NoModifier);
                    QApplication::sendEvent(&button, &move);
                    button.setDown(pressed); drainEvents();
                    require(button.actualStyleState().testFlag(QStyle::State_MouseOver),
                        "real QPushButton initStyleOption entered hover through mouseMoveEvent");
                    const QColor background = pressed ? KswordTheme::PrimaryAccentColor()
                        : KswordTheme::PrimaryBlueSolidHoverColor();
                    const QColor foreground = KswordTheme::OnAccentColor(background);
                    const QImage pixels = button.grab().toImage();
                    if (pixels.pixelColor(8, pixels.height() / 2).rgba() != background.rgba())
                    {
                        std::cerr << "BUTTON_STATE dark=" << dark << " seed=" << seed.toStdString()
                            << " pressed=" << pressed << " enabled=" << button.isEnabled()
                            << " underMouse=" << button.underMouse() << " actual="
                            << pixels.pixelColor(8, pixels.height() / 2).name().toStdString()
                            << " expected=" << background.name().toStdString()
                            << " mouseOverState=" << button.actualStyleState().testFlag(QStyle::State_MouseOver)
                            << " hoverAttribute=" << button.testAttribute(Qt::WA_Hover) << '\n';
                    }
                    require(pixels.pixelColor(8, pixels.height() / 2).rgba() == background.rgba(),
                        "actual shared button paints the requested hover/pressed surface");
                    bool textFound = false;
                    int closestDistance = 1000;
                    QColor closestPixel;
                    for (int y = 8; y < pixels.height() - 8; ++y)
                        for (int x = 20; x < pixels.width() - 20; ++x)
                        {
                            const QColor pixel = pixels.pixelColor(x, y);
                            // QSS输出8位RGB，QColor的HSL内部通道可能保留16位；按真实像素编码精确比较。
                            if (pixel.rgba() == foreground.rgba()) textFound = true;
                            const int distance = std::abs(pixel.red() - foreground.red())
                                + std::abs(pixel.green() - foreground.green()) + std::abs(pixel.blue() - foreground.blue());
                            if (distance < closestDistance) { closestDistance = distance; closestPixel = pixel; }
                        }
                    if (!textFound)
                        std::cerr << "BUTTON_TEXT expected=" << foreground.name().toStdString()
                            << " closest=" << closestPixel.name().toStdString() << " rgbDistance=" << closestDistance
                            << " style=" << button.styleSheet().toStdString() << '\n';
                    require(textFound && KswordTheme::ContrastRatio(QColor(foreground.name()),
                        pixels.pixelColor(8, pixels.height() / 2)) >= 4.499,
                        "actual shared button glyph text uses its matching state foreground");
                }
                title.setDarkModeEnabled(dark);
                auto* mode = title.findChild<QToolButton*>(QStringLiteral("ksTitleInputModeButton"));
                require(mode != nullptr && title.styleSheet().contains(QStringLiteral("color:%1;")
                    .arg(KswordTheme::OnAccentHex(KswordTheme::PrimaryBlueSolidHoverColor()))),
                    "real title input-mode hover has the matching state foreground");
                drainEvents();
                require(message.styleSheet().contains(QStringLiteral("color:%1;")
                    .arg(KswordTheme::OnAccentHex(KswordTheme::PrimaryBlueSolidHoverColor()))),
                    "real themed message primary hover has the matching foreground");
                require(popup.styleSheet().contains(QStringLiteral("color:%1;")
                    .arg(KswordTheme::OnAccentHex(KswordTheme::PrimaryBlueSolidHoverColor()))),
                    "existing command popup regenerates its actual hover foreground on palette changes");
                QPushButton globalButton(QStringLiteral("MMMMMMMM"));
                globalButton.setFont(buttonFont);
                globalButton.resize(200, 50); globalButton.show();
                globalButton.setAttribute(Qt::WA_UnderMouse, true);
                globalButton.setDown(true); drainEvents();
                const QColor globalPressed = KswordTheme::ControlAccentPressedColor();
                const QImage globalPixels = globalButton.grab().toImage();
                require(globalPixels.pixelColor(8, globalPixels.height() / 2).rgba() == globalPressed.rgba(),
                    "actual global base button paints its own pressed surface");
                const QColor globalText = KswordTheme::OnAccentColor(globalPressed);
                bool globalTextFound = false;
                for (int y = 8; y < globalPixels.height() - 8; ++y)
                    for (int x = 20; x < globalPixels.width() - 20; ++x)
                        if (globalPixels.pixelColor(x, y).rgba() == globalText.rgba()) globalTextFound = true;
                require(globalTextFound && KswordTheme::ContrastRatio(QColor(globalText.name()),
                    globalPixels.pixelColor(8, globalPixels.height() / 2)) >= 4.499,
                    "global pressed text matches its actual pressed background");
            }
        }
    }
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    require(argc == 2 && QResource::registerResource(QString::fromLocal8Bit(argv[1])),
        "fixture receives its explicit editor SVG resource bundle");
    ks::ui::InstallGlobalMessageBoxTheme(&application);
    testEditors(application);
    testNotificationsAndLog();
    testButtons();
    std::cout << "THEME_COMPONENT_ASSERTIONS=" << checks << '\n' << "THEME_COMPONENT_FAILURES=0\n";
    return 0;
}
