// Real Qt editor regression. All disk writes stay in the owned fixture directory;
// no clipboard action, native dialog, process memory or driver is used.
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeTextEdit.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorFileSession.h"
#include "../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include "../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"
#include "../Ksword5.1/Ksword5.1/theme.h"
#include <QApplication>
#include <QAction>
#include <QComboBox>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFontDatabase>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPalette>
#include <QPlainTextEdit>
#include <QPointer>
#include <QStackedWidget>
#include <QTemporaryDir>
#include <QTest>
#include <QTextBlock>
#include <QTextCursor>
#include <QTextDocument>
#include <QTextLayout>
#include <QTextOption>
#include <QToolButton>
#include <cstdlib>
#include <iostream>
#include <utility>

namespace
{
    unsigned checks = 0;
    QString outputDirectory;

    void require(bool value, const char* description)
    {
        ++checks;
        if (!value) { std::cerr << "FAIL [" << checks << "]: " << description << '\n'; std::exit(1); }
    }
    void flushEvents()
    {
        QCoreApplication::processEvents();
        QTest::qWait(25);
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents();
    }
    void applyTheme(bool dark)
    {
        KswordTheme::SetDarkModeEnabled(dark);
        QPalette palette;
        for (auto group : {QPalette::Active, QPalette::Inactive, QPalette::Disabled})
        {
            palette.setColor(group, QPalette::Window, KswordTheme::WindowColor());
            palette.setColor(group, QPalette::Base, KswordTheme::SurfaceColor());
            palette.setColor(group, QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
            palette.setColor(group, QPalette::Button, KswordTheme::SurfaceColor());
            const auto text = group == QPalette::Disabled ? KswordTheme::TextDisabledColor() : KswordTheme::TextPrimaryColor();
            palette.setColor(group, QPalette::WindowText, text);
            palette.setColor(group, QPalette::Text, text);
            palette.setColor(group, QPalette::ButtonText, text);
            palette.setColor(group, QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
            palette.setColor(group, QPalette::Highlight, KswordTheme::PrimaryAccentColor());
            palette.setColor(group, QPalette::HighlightedText, QColor(KswordTheme::OnAccentHex()));
            palette.setColor(group, QPalette::Mid, KswordTheme::BorderColor());
        }
        qApp->setPalette(palette);
        qApp->setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
        flushEvents();
    }
    CodeTextEdit* textCore(CodeEditorWidget& owner)
    {
        auto* core = dynamic_cast<CodeTextEdit*>(owner.findChild<QPlainTextEdit*>(QStringLiteral("code_editor_text")));
        require(core != nullptr, "wrapper uses the actual shared CodeTextEdit core");
        return core;
    }
    QToolButton* tool(CodeEditorWidget& owner, const QString& role)
    {
        for (auto* button : owner.findChildren<QToolButton*>())
            if (button->property("ksword_editor_icon_path").toString() == QStringLiteral(":/Icon/codeeditor_") + role + QStringLiteral(".svg"))
                return button;
        require(false, "the requested real toolbar tool exists");
        return nullptr;
    }
    template<class T> T* named(CodeEditorWidget& owner, const char* name)
    {
        auto* child = owner.findChild<T*>(QString::fromLatin1(name));
        require(child != nullptr, "the requested editor control has its stable object name");
        return child;
    }
    QColor foregroundAt(const CodeTextEdit& core, int position)
    {
        const auto block = core.document()->findBlock(position);
        if (block.isValid() && block.layout())
            for (const auto& format : block.layout()->formats())
                if (position - block.position() >= format.start && position - block.position() < format.start + format.length
                    && format.format.foreground().style() != Qt::NoBrush)
                    return format.format.foreground().color();
        return core.palette().color(QPalette::Text);
    }
    void show(CodeEditorWidget& owner, const QSize& size = QSize(1100, 650))
    {
        owner.resize(size);
        owner.show();
        owner.activateWindow();
        flushEvents();
    }
    void savePreview(CodeEditorWidget& owner, const QString& name, const QSize& size)
    {
        show(owner, size);
        require(owner.grab().save(QDir(outputDirectory).filePath(name + QStringLiteral(".png"))),
            "actual editor preview is saved");
    }
    QByteArray readBytes(const QString& path)
    {
        QFile file(path);
        require(file.open(QIODevice::ReadOnly), "owned file fixture can be read");
        return file.readAll();
    }
    void writeBytes(const QString& path, const QByteArray& bytes)
    {
        QFile file(path);
        require(file.open(QIODevice::WriteOnly), "owned file fixture can be written");
        require(file.write(bytes) == bytes.size(), "owned file fixture contains every expected byte");
    }
    QByteArray encodeUtf16(const QString& text, bool littleEndian)
    {
        QByteArray bytes = littleEndian ? QByteArray::fromHex("fffe") : QByteArray::fromHex("feff");
        for (const auto character : text)
        {
            const auto value = character.unicode();
            bytes.append(static_cast<char>(littleEndian ? value & 0xFF : value >> 8));
            bytes.append(static_cast<char>(littleEndian ? value >> 8 : value & 0xFF));
        }
        return bytes;
    }

    void checkRawText()
    {
        CodeEditorWidget owner;
        auto* core = textCore(owner);
        const QString json = QStringLiteral("{\"path\":\"C:\\\\fixture\",\"n\":[1,2],\"ok\":true}");
        const QString xml = QStringLiteral("<?xml version=\"1.0\"?><root attr=\"1\"><item>世界</item></root>");
        QString notifiedText;
        unsigned notifications = 0;
        QObject::connect(&owner, &CodeEditorWidget::contentChanged, &owner,
            [&](const QString& text) { notifiedText = text; ++notifications; });
        owner.setRawText(json);
        flushEvents();
        require(owner.text() == json && core->toPlainText() == json && notifiedText == json,
            "raw minified JSON and its content notification retain literal spacing");
        const auto previousNotifications = notifications;
        owner.setRawText(json + QLatin1Char(' '));
        owner.setRawText(xml);
        require(notifications == previousNotifications, "buffer replacements do not notify an observer inside native Qt mutation");
        flushEvents();
        require(notifications == previousNotifications + 1 && notifiedText == xml,
            "one deferred notification publishes the latest buffer after multiple replacements");
        require(owner.text() == xml && core->blockCount() == 1, "raw minified XML is not reformatted");
        owner.setReadOnly(true);
        owner.setRawText(json);
        QEvent languageChange(QEvent::LanguageChange);
        QCoreApplication::sendEvent(&owner, &languageChange);
        require(owner.text() == json, "readonly raw JSON stays literal during language events");

        auto& languages = ks::i18n::LanguageManager::instance();
        QString error;
        require(languages.initialize(QStringLiteral("zh-CN"), &error), "real language packs initialize for report tests");
        const auto suffix = QStringLiteral("{\"成功\":\"成功\",\"literal\":[1,2]}");
        owner.setText(QStringLiteral("成功\n") + suffix);
        require(owner.text() == QStringLiteral("成功\n") + suffix, "plain alias preserves all raw text");
        require(languages.setLanguage(QStringLiteral("en-US"), &error), "real English pack loads");
        flushEvents();
        require(owner.text() == QStringLiteral("成功\n") + suffix,
            "language changes never regenerate or translate raw editor content");
        owner.setRawText(xml);
        require(languages.setLanguage(QStringLiteral("zh-CN"), &error), "raw tests restore Chinese");
        flushEvents();
        require(owner.text() == xml, "raw setter retains the literal XML");

        const QString original = QStringLiteral("first\r\nsecond\rthird\nlast");
        owner.setRawText(original);
        core->selectAll();
        require(owner.text() == original && owner.copyTextForCurrentView() == original,
            "untouched raw text and whole selection retain mixed original line endings");
        QTextCursor rawSelection(core->document());
        rawSelection.setPosition(3);
        rawSelection.setPosition(9, QTextCursor::KeepAnchor);
        core->setTextCursor(rawSelection);
        require(owner.copyTextForCurrentView() == QStringLiteral("st\r\nsec"),
            "partial raw selection maps Qt paragraph positions back to original CRLF source");

        owner.setReadOnly(false);
        owner.setRawText(json);
        QAction* format = nullptr;
        for (auto* action : named<QToolButton>(owner, "code_editor_more")->menu()->actions())
            if (action->text().contains(QStringLiteral("JSON")) && action->text().contains(QStringLiteral("XML"))) format = action;
        require(format != nullptr, "explicit JSON XML formatting action is available");
        format->trigger();
        require(owner.text() != json && owner.text().contains(QLatin1Char('\n')), "explicit formatting changes the minified document only on request");
        core->undo();
        require(owner.text() == json, "one undo restores the literal pre-format document");
    }

    void checkEditingAndReadOnly()
    {
        CodeEditorWidget owner;
        show(owner);
        auto* core = textCore(owner);
        owner.setRawText(QStringLiteral("a cat cat\ncat!"));
        core->setFocus();
        tool(owner, QStringLiteral("replace"))->click();
        flushEvents();
        auto* find = named<QLineEdit>(owner, "code_editor_find");
        auto* replacement = named<QLineEdit>(owner, "code_editor_replace");
        find->setText(QStringLiteral("cat"));
        replacement->setText(QStringLiteral("dog"));
        named<QToolButton>(owner, "code_editor_replace_all")->click();
        require(owner.text() == QStringLiteral("a dog dog\ndog!"), "replace all changes every literal match");
        core->undo();
        require(owner.text() == QStringLiteral("a cat cat\ncat!"), "one undo reverses the complete replace-all transaction");
        core->redo();
        require(owner.text() == QStringLiteral("a dog dog\ndog!"), "one redo replays the complete replace-all transaction");
        require(tool(owner, QStringLiteral("undo"))->isEnabled(), "undo toolbar state reflects real document history");

        owner.setRawText(QStringLiteral("Cat cat catalog\ncat."));
        find->setText(QStringLiteral("cat"));
        named<QToolButton>(owner, "code_editor_whole_word")->setChecked(true);
        named<QToolButton>(owner, "code_editor_match_case")->setChecked(false);
        core->moveCursor(QTextCursor::Start);
        QTest::keyClick(find, Qt::Key_Return);
        require(core->textCursor().selectedText() == QStringLiteral("Cat"), "whole-word find can match a differently cased complete word");
        named<QToolButton>(owner, "code_editor_match_case")->setChecked(true);
        core->moveCursor(QTextCursor::Start);
        QTest::keyClick(find, Qt::Key_Return);
        require(core->textCursor().selectedText() == QStringLiteral("cat") && core->textCursor().selectionStart() == 4,
            "case-sensitive whole-word search selects the real lowercase match");

        core->moveCursor(QTextCursor::End);
        QTest::keyClicks(core, "x");
        require(core->document()->isUndoAvailable(), "readonly shortcut check starts with an actual user undo transaction");

        owner.setReadOnly(true);
        const auto frozen = owner.text();
        core->selectAll();
        QTest::keyClicks(core, "overwrite");
        QTest::keyClick(core, Qt::Key_Tab);
        QTest::keyClick(core, Qt::Key_Backtab);
        QTest::keyClick(core, Qt::Key_Z, Qt::ControlModifier);
        flushEvents();
        require(owner.isReadOnly() && core->isReadOnly() && owner.text() == frozen,
            "readonly report rejects typing indentation and undo shortcuts");
        for (const auto& role : {QStringLiteral("new"), QStringLiteral("save"), QStringLiteral("save_as"),
            QStringLiteral("cut"), QStringLiteral("replace")})
        {
            auto* button = tool(owner, role);
            require(!button->isVisible() || !button->isEnabled(), "readonly view does not expose an available write action");
        }
        require(tool(owner, QStringLiteral("find"))->isVisible() && tool(owner, QStringLiteral("find"))->isEnabled(),
            "readonly logs retain a usable find command");
        owner.setReadOnly(false);
        require(!core->isReadOnly(), "restoring edit mode restores the actual text core permission");

        core->setPlainText(QStringLiteral("alpha\nbeta\ngamma"));
        QTextCursor selected(core->document());
        selected.setPosition(0);
        selected.setPosition(11, QTextCursor::KeepAnchor);
        core->setTextCursor(selected);
        QTest::keyClick(core, Qt::Key_Tab);
        require(core->toPlainText() == QStringLiteral("    alpha\n    beta\ngamma"),
            "multiline Tab indents selected blocks and excludes a trailing block selected only at its start");
        core->undo();
        require(core->toPlainText() == QStringLiteral("alpha\nbeta\ngamma"), "one undo reverses multiline indentation");
        core->redo();
        selected = QTextCursor(core->document());
        selected.setPosition(0);
        selected.setPosition(19, QTextCursor::KeepAnchor);
        core->setTextCursor(selected);
        QTest::keyClick(core, Qt::Key_Backtab);
        require(core->toPlainText() == QStringLiteral("alpha\nbeta\ngamma"), "multiline Backtab removes exactly the selected indentation");
        core->undo();
        require(core->toPlainText() == QStringLiteral("    alpha\n    beta\ngamma"), "one undo reverses multiline outdent");
        core->setPlainText(QStringLiteral("ab"));
        core->moveCursor(QTextCursor::End);
        QTest::keyClick(core, Qt::Key_Tab);
        require(core->toPlainText() == QStringLiteral("ab  "), "single-cursor Tab advances to the next four-column stop");
    }

    void checkInitialAndStructureDisabledActions()
    {
        CodeEditorWidget owner;
        auto* core = textCore(owner);
        if (tool(owner, QStringLiteral("undo"))->isEnabled() || tool(owner, QStringLiteral("redo"))->isEnabled()
            || tool(owner, QStringLiteral("copy"))->isEnabled() || tool(owner, QStringLiteral("cut"))->isEnabled())
            std::cerr << "Initial actions undo=" << tool(owner, QStringLiteral("undo"))->isEnabled()
                << " redo=" << tool(owner, QStringLiteral("redo"))->isEnabled()
                << " copy=" << tool(owner, QStringLiteral("copy"))->isEnabled()
                << " cut=" << tool(owner, QStringLiteral("cut"))->isEnabled()
                << " availableUndo=" << core->document()->isUndoAvailable()
                << " availableRedo=" << core->document()->isRedoAvailable()
                << " selection=" << core->textCursor().hasSelection()
                << " modified=" << core->document()->isModified()
                << " chars=" << core->toPlainText().size() << '\n';
        require(!tool(owner, QStringLiteral("undo"))->isEnabled() && !tool(owner, QStringLiteral("redo"))->isEnabled()
            && !tool(owner, QStringLiteral("copy"))->isEnabled() && !tool(owner, QStringLiteral("cut"))->isEnabled(),
            "a fresh empty editor starts with accurate history and selection action states");
        require(tool(owner, QStringLiteral("wrap"))->isChecked() && core->lineWrapMode() == QPlainTextEdit::WidgetWidth,
            "the initial wrap tool matches the real text core wrap mode");
        owner.setRawText(QStringLiteral("state fixture"));
        core->selectAll();
        owner.setReadOnly(true);
        require(core->isReadOnly() && tool(owner, QStringLiteral("copy"))->isEnabled()
            && !tool(owner, QStringLiteral("undo"))->isEnabled() && !tool(owner, QStringLiteral("cut"))->isEnabled(),
            "disabling structured reports still refreshes readonly history and copy-selection actions");
        const auto before = owner.text();
        tool(owner, QStringLiteral("wrap"))->click();
        require(owner.text() == before && !tool(owner, QStringLiteral("wrap"))->isChecked()
            && core->lineWrapMode() == QPlainTextEdit::NoWrap,
            "structure-disabled readonly text can toggle wrapping without editing its bytes");
    }

    void checkSyntaxThemeAndStreaming()
    {
        using Language = CodeTextEdit::SyntaxLanguage;
        CodeEditorWidget owner;
        auto* core = textCore(owner);
        core->setSyntaxLanguage(Language::Auto);
        for (const auto& sample : {std::pair{QStringLiteral("{\"a\":1}"), Language::Json},
            std::pair{QStringLiteral("<root attr=\"value\"/>"), Language::Xml},
            std::pair{QStringLiteral("#include <vector>\nint main() {}"), Language::Cpp},
            std::pair{QStringLiteral("[settings]\nenabled=true"), Language::Ini},
            std::pair{QStringLiteral("#!/bin/sh\necho ready"), Language::Shell},
            std::pair{QStringLiteral("ordinary plain words"), Language::PlainText}})
        {
            owner.setRawText(sample.first);
            core->setSyntaxLanguage(Language::Auto);
            flushEvents();
            require(core->effectiveSyntaxLanguage() == sample.second && owner.text() == sample.first,
                "automatic syntax detection chooses a language without changing source bytes");
        }
        const auto cpp = QStringLiteral("int value = 42;\n// a comment\nconst char* text = \"hello\";\n/* multi\n comment */ int end = 1;");
        owner.setRawText(cpp);
        core->setSyntaxLanguage(Language::Cpp);
        show(owner);
        applyTheme(false);
        core->refreshThemeColors();
        flushEvents();
        const auto lightKeyword = foregroundAt(*core, 0);
        require(lightKeyword != core->palette().color(QPalette::Text), "C++ keyword has real syntax foreground formatting");
        const auto firstComment = cpp.indexOf(QStringLiteral("/* multi"));
        const auto continuedComment = cpp.indexOf(QStringLiteral(" comment */"));
        require(foregroundAt(*core, firstComment) == foregroundAt(*core, continuedComment)
            && foregroundAt(*core, continuedComment + 12) == lightKeyword,
            "multiline comments carry state across blocks and return to code after their terminator");
        core->moveCursor(QTextCursor::End);
        QTest::keyClicks(core, " ");
        QTextCursor selection = core->textCursor();
        selection.setPosition(cpp.indexOf(QStringLiteral("hello")));
        selection.setPosition(selection.position() + 5, QTextCursor::KeepAnchor);
        core->setTextCursor(selection);
        const auto beforeText = owner.text();
        const auto beforePosition = core->textCursor().position();
        const auto beforeAnchor = core->textCursor().anchor();
        const auto beforeModified = core->document()->isModified();
        flushEvents();
        unsigned contentNotifications = 0;
        unsigned modifiedNotifications = 0;
        const auto contentConnection = QObject::connect(&owner, &CodeEditorWidget::contentChanged, &owner,
            [&](const QString&) { ++contentNotifications; });
        const auto modifiedConnection = QObject::connect(core->document(), &QTextDocument::modificationChanged, &owner,
            [&](bool) { ++modifiedNotifications; });
        applyTheme(true);
        core->refreshThemeColors();
        flushEvents();
        require(owner.text() == beforeText && core->textCursor().position() == beforePosition
            && core->textCursor().anchor() == beforeAnchor && core->document()->isModified() == beforeModified,
            "live theme refresh preserves text selection cursor and modified state");
        require(contentNotifications == 0 && modifiedNotifications == 0,
            "theme-only refresh emits no fake content or dirty-state notifications");
        QObject::disconnect(contentConnection);
        QObject::disconnect(modifiedConnection);
        require(foregroundAt(*core, 0) != lightKeyword, "live theme refresh rebuilds existing syntax foregrounds");
        core->undo();
        require(owner.text() == cpp, "theme refresh preserves the user undo transaction");
        core->setSyntaxLanguage(Language::PlainText);
        flushEvents();
        require(foregroundAt(*core, 0) == core->palette().color(QPalette::Text), "explicit plain text clears code syntax colors");

        core->setLineNumbersVisible(false);
        flushEvents();
        auto* gutter = core->findChild<QWidget*>(QStringLiteral("code_editor_gutter"));
        require(gutter != nullptr && !core->lineNumbersVisible() && !gutter->isVisible(), "line-number toggle hides the real gutter");
        core->setLineNumbersVisible(true);
        core->setWhitespaceVisible(true);
        require(core->lineNumbersVisible() && (core->document()->defaultTextOption().flags() & QTextOption::ShowTabsAndSpaces),
            "line-number and whitespace controls change the actual text view options");
        core->setWhitespaceVisible(false);

        CodeTextEdit log;
        require(!log.document()->isUndoAvailable() && !log.document()->isModified() && log.toPlainText().isEmpty(),
            "a fresh standalone text core has no decoration-only undo or dirty baseline");
        require(log.lineWrapMode() == QPlainTextEdit::WidgetWidth,
            "a standalone logger retains the implicit QPlainTextEdit wrap contract");
        log.setSyntaxLanguage(Language::PlainText);
        log.setReadOnly(true);
        log.setMaximumBlockCount(3);
        for (int line = 1; line <= 10; ++line) log.appendPlainText(QStringLiteral("line %1").arg(line));
        require(log.blockCount() == 3 && log.toPlainText() == QStringLiteral("line 8\nline 9\nline 10"),
            "readonly streaming logs preserve append order and bounded-document semantics");
    }

    void checkOwnedFileSessions()
    {
        QTemporaryDir fixtures(QDir(outputDirectory).filePath(QStringLiteral("owned-files-XXXXXX")));
        require(fixtures.isValid(), "owned file fixture directory is available");
        struct Case { const char* name; QByteArray bytes; QString text; QString encoding; };
        const auto lf = QStringLiteral("hello 世界\nsecond\n");
        const auto crlf = QStringLiteral("hello 世界\r\nsecond\r\n");
        const auto cr = QStringLiteral("hello 世界\rsecond\r");
        const auto literalReplacement = QStringLiteral("literal \uFFFD value\n");
        code_editor_file_session::FileSessionMetadata replacementMetadata;
        const auto replacementDecoded = code_editor_file_session::decodeTextFileBytes(literalReplacement.toUtf8(), &replacementMetadata);
        require(replacementDecoded == literalReplacement && replacementMetadata.encoding == QStringConverter::Utf8
            && !replacementMetadata.hasBom, "a literal UTF8 replacement scalar does not imply an invalid byte sequence");
        const Case cases[] = {
            {"minified.json", QByteArray("{\"ok\":true,\"n\":1}"), QStringLiteral("{\"ok\":true,\"n\":1}"), QStringLiteral("UTF-8")},
            {"utf8-bom.txt", QByteArray::fromHex("efbbbf") + crlf.toUtf8(), lf, QStringLiteral("UTF-8 BOM")},
            {"utf16-le.txt", encodeUtf16(cr, true), lf, QStringLiteral("UTF-16 LE BOM")},
            {"utf16-be.txt", encodeUtf16(lf, false), lf, QStringLiteral("UTF-16 BE BOM")},
            {"literal-replacement.txt", literalReplacement.toUtf8(), literalReplacement, QStringLiteral("UTF-8")}
        };
        for (const auto& sample : cases)
        {
            const auto path = QDir(fixtures.path()).filePath(QString::fromLatin1(sample.name));
            writeBytes(path, sample.bytes);
            CodeEditorWidget owner;
            show(owner, QSize(800, 450));
            owner.setReadOnly(true);
            owner.setRawText(QStringLiteral("成功\n"));
            owner.setReadOnly(false);
            require(owner.openLocalFile(path) && owner.text() == sample.text,
                "opening an owned file preserves raw content and clears earlier report text");
            require(owner.currentFilePath() == path && owner.currentEncodingDisplayText() == sample.encoding,
                "file session exposes its original path encoding and BOM");
            auto* core = textCore(owner);
            core->setFocus();
            QTest::keyClick(core, Qt::Key_S, Qt::ControlModifier);
            flushEvents();
            require(QApplication::activeModalWidget() == nullptr && readBytes(path) == sample.bytes,
                "saving the current owned file preserves BOM encoding and original newline style without a dialog");
            QEvent languageChange(QEvent::LanguageChange);
            QCoreApplication::sendEvent(&owner, &languageChange);
            require(owner.text() == sample.text, "opened files cannot resurrect a generated report on language changes");
        }
    }

    void checkCompactSingleLine()
    {
        CodeTextEdit core;
        core.setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        core.setPlainText(QStringLiteral("first line"));
        core.moveCursor(QTextCursor::End);
        QTest::keyClicks(&core, "x");
        QTextCursor selected(core.document());
        selected.setPosition(0);
        selected.setPosition(5, QTextCursor::KeepAnchor);
        core.setTextCursor(selected);
        const auto before = core.toPlainText();
        const auto position = core.textCursor().position();
        const auto anchor = core.textCursor().anchor();
        const bool modified = core.document()->isModified();
        require(core.document()->isUndoAvailable(), "compact toggle starts with actual edit history");
        unsigned contentNotifications = 0;
        unsigned modifiedNotifications = 0;
        const auto contentConnection = QObject::connect(&core, &QPlainTextEdit::textChanged, &core,
            [&]() { ++contentNotifications; });
        const auto modifiedConnection = QObject::connect(core.document(), &QTextDocument::modificationChanged, &core,
            [&](bool) { ++modifiedNotifications; });
        core.setCompactMode(true);
        core.setLineNumbersVisible(false);
        core.resize(340, 24);
        core.show();
        flushEvents();
        require(core.compactMode() && core.toPlainText() == before && core.textCursor().position() == position
            && core.textCursor().anchor() == anchor && core.document()->isModified() == modified,
            "compact mode preserves buffer cursor selection and modified state");
        require(contentNotifications == 0 && modifiedNotifications == 0,
            "compact and gutter-only changes emit no false content or dirty notifications");
        const auto cursor = core.cursorRect();
        require(core.height() == 24 && cursor.top() >= 0 && cursor.bottom() < core.viewport()->height(),
            "the first compact text line fits entirely inside a 24-pixel editor");
        require(core.grab().save(QDir(outputDirectory).filePath(QStringLiteral("compact-24px.png"))),
            "actual compact editor paint preview is saved");
        QObject::disconnect(contentConnection);
        QObject::disconnect(modifiedConnection);
        core.undo();
        require(core.toPlainText() == QStringLiteral("first line"), "compact layout preserves the original undo transaction");
        core.setCompactMode(false);
        require(!core.compactMode() && core.toPlainText() == QStringLiteral("first line")
            && !core.document()->isModified() && core.document()->isRedoAvailable(),
            "restoring regular layout preserves the undone document state and redo history");
        core.redo();
        require(core.toPlainText() == before && core.document()->isModified(),
            "the original redo transaction survives both compact layout directions");
    }

    void checkReentrantParentLifetime()
    {
        for (int setter = 0; setter < 3; ++setter)
        {
            std::cerr << "Lifetime setter " << setter << '\n';
            QPointer<CodeEditorWidget> owner = new CodeEditorWidget;
            QObject::connect(owner, &CodeEditorWidget::contentChanged, owner,
                [owner](const QString&) { delete owner.data(); });
            if (setter == 0) owner->setRawText(QStringLiteral("literal"));
            if (setter == 1) owner->setText(QStringLiteral("成功\n"));
            if (setter == 2) owner->replaceRawText(QStringLiteral("成功\n{\"literal\":1}"));
            require(owner != nullptr, "text setter returns before the external content observer retires its owner");
            flushEvents();
            require(owner.isNull(), "deferred content notification safely permits the observer to retire its owner");
        }
        QTemporaryDir fixtures(QDir(outputDirectory).filePath(QStringLiteral("lifetime-files-XXXXXX")));
        require(fixtures.isValid(), "owned lifetime fixture directory is available");
        const auto path = QDir(fixtures.path()).filePath(QStringLiteral("source.txt"));
        const auto bytes = QByteArray("literal loaded text\n");
        writeBytes(path, bytes);
        QPointer<CodeEditorWidget> owner = new CodeEditorWidget;
        QObject::connect(owner, &CodeEditorWidget::contentChanged, owner,
            [owner](const QString&) { delete owner.data(); });
        const bool opened = owner->openLocalFile(path);
        require(owner != nullptr && opened && owner->text() == QString::fromUtf8(bytes),
            "file loading completes before its deferred content observer retires the owner");
        flushEvents();
        require(owner.isNull() && readBytes(path) == bytes,
            "file-load content notification permits safe retirement and leaves the owned input file intact");
    }

    void checkResponsiveAndPreviews()
    {
        const auto source = QStringLiteral("#include <vector>\n\n// 统一编辑器：用户文本保持原样\nint main()\n{\n    std::vector<int> values = {1, 2, 3};\n    const char* status = \"ready\";\n    if (!values.empty()) {\n        return values.front();\n    }\n    return 0;\n}\n");
        CodeEditorWidget owner;
        owner.setRawText(source);
        auto* core = textCore(owner);
        core->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Cpp);
        applyTheme(false);
        savePreview(owner, QStringLiteral("code-light-wide"), QSize(1100, 650));
        applyTheme(true);
        savePreview(owner, QStringLiteral("code-dark-wide"), QSize(1100, 650));
        show(owner, QSize(360, 460));
        tool(owner, QStringLiteral("replace"))->click();
        flushEvents();
        auto* toolbar = named<QWidget>(owner, "code_editor_toolbar");
        require(owner.width() == 360, "editor does not expand a narrow host to its toolbar minimum width");
        for (auto* button : toolbar->findChildren<QToolButton*>())
            if (button->isVisibleTo(toolbar))
            {
                const QRect bounds(button->mapTo(toolbar, QPoint()), button->size());
                require(toolbar->rect().contains(bounds), "every visible narrow toolbar control fits inside its toolbar");
            }
        for (auto* field : owner.findChildren<QLineEdit*>())
            if (field->isVisibleTo(&owner))
                require(field->width() >= 50 && owner.rect().contains(QRect(field->mapTo(&owner, QPoint()), field->size())),
                    "narrow find and replacement inputs remain usable inside the host");
        savePreview(owner, QStringLiteral("code-dark-narrow-find"), QSize(360, 460));

        owner.setReadOnly(true);
        owner.setRawText(QStringLiteral("进程信息\n状态: 成功\n路径: C:\\fixture\\program.exe\nPID: 1234\n\n模块\n名称: example.dll\n地址: 0x0000000012345000\n"));
        show(owner, QSize(800, 540));
        require(owner.findChild<QComboBox*>(QStringLiteral("code_editor_structure")) == nullptr
            && owner.findChild<QStackedWidget*>() == nullptr, "plain editor has no report or structure frontend");
        require(core->isVisible(), "readonly text core remains visible");
        savePreview(owner, QStringLiteral("raw-text-dark-wide"), QSize(800, 540));
        tool(owner, QStringLiteral("find"))->click();
        named<QLineEdit>(owner, "code_editor_find")->setText(QStringLiteral("fixture"));
        savePreview(owner, QStringLiteral("raw-text-dark-narrow-find"), QSize(360, 460));
        owner.setRawText(QStringLiteral("2026-10-08 09:12:00 [INFO] 用户原始日志\n2026-10-08 09:12:01 [WARN] retry=1 path=C:\\fixture\\data.json\n2026-10-08 09:12:02 [INFO] ready\n"));
        core->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        applyTheme(false);
        savePreview(owner, QStringLiteral("log-light-narrow"), QSize(360, 460));
    }
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    if (QFontDatabase::families().contains(QStringLiteral("Microsoft YaHei")))
        application.setFont(QFont(QStringLiteral("Microsoft YaHei"), 9));
    outputDirectory = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QStringLiteral(".codex-tmp/code-editor-ui-tests/shots");
    require(QDir().mkpath(outputDirectory), "editor preview output directory is available");
    applyTheme(false);
    std::cerr << "Raw/localized text checks\n";
    checkRawText();
    std::cerr << "Editing/readonly checks\n";
    checkEditingAndReadOnly();
    checkInitialAndStructureDisabledActions();
    std::cerr << "Syntax/theme/streaming checks\n";
    checkSyntaxThemeAndStreaming();
    std::cerr << "File session checks\n";
    checkOwnedFileSessions();
    std::cerr << "Compact single-line checks\n";
    checkCompactSingleLine();
    std::cerr << "Lifetime checks\n";
    checkReentrantParentLifetime();
    std::cerr << "Responsive/visual checks\n";
    checkResponsiveAndPreviews();
    std::cout << "PASS: " << checks << " code editor Qt checks\n";
}
