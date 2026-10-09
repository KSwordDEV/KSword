// Real production Qt views. No clipboard writes, native dialogs, target I/O,
// settings persistence or temporary directories are used by this regression.
#include "../../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include "../../Ksword5.1/Ksword5.1/UI/CodeTextEdit.h"
#include "../../Ksword5.1/Ksword5.1/UI/TypedSyntaxDocument.h"
#include "../../Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"
#include "../../Ksword5.1/Ksword5.1/theme.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchTextView.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/MemoryRowCanvas.h"
#include <QApplication>
#include <QComboBox>
#include <QDialog>
#include <QEvent>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPointer>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTest>
#include <QTextDocument>
#include <QTimer>
#include <QScrollBar>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iostream>

namespace
{
    int checks = 0;
    void expect(const bool value, const char* description)
    {
        ++checks;
        if (!value) { std::cerr << "FAIL " << checks << ": " << description << '\n'; std::exit(1); }
    }
    void drain()
    {
        QCoreApplication::processEvents();
        QTest::qWait(5);
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QCoreApplication::processEvents();
    }
    template<class Widget> Widget* named(QWidget& owner, const char* name)
    {
        Widget* widget = nullptr;
        for (QWidget* child : owner.findChildren<QWidget*>(QString::fromLatin1(name)))
            if ((widget = dynamic_cast<Widget*>(child)) != nullptr) break;
        if (widget == nullptr)
        {
            std::cerr << "Missing widget " << name << '\n';
            for (QWidget* child : owner.findChildren<QWidget*>())
                std::cerr << child->metaObject()->className() << ' ' << child->objectName().toStdString() << '\n';
        }
        expect(widget != nullptr, "production view exposes its expected control");
        return widget;
    }
    struct Provider final : ks::ui::IWorkbenchBytesProvider
    {
        std::uint64_t base = 0x1000;
        std::vector<std::uint8_t> bytes;
        std::vector<std::uint8_t> states;
        mutable int calls = 0;
        void set(const QByteArray& data)
        {
            bytes.assign(data.begin(), data.end());
            states.assign(bytes.size(), 1);
        }
        ks::ui::WorkbenchByteWindow FetchWindow(const std::uint64_t address, const std::uint64_t length) const override
        {
            ++calls;
            ks::ui::WorkbenchByteWindow result;
            result.address = address;
            if (address < base || address - base >= bytes.size()) return result;
            const auto offset = static_cast<std::size_t>(address - base);
            const auto count = std::min<std::size_t>(static_cast<std::size_t>(length), bytes.size() - offset);
            result.ok = true;
            result.bytes.assign(bytes.begin() + static_cast<std::ptrdiff_t>(offset), bytes.begin() + static_cast<std::ptrdiff_t>(offset + count));
            result.validMask.assign(states.begin() + static_cast<std::ptrdiff_t>(offset), states.begin() + static_cast<std::ptrdiff_t>(offset + count));
            return result;
        }
        int AddressBits() const override { return 64; }
        bool HasPreviousRead() const override { return false; }
    };

    void parserTests()
    {
        using ks::ui::ParseTypedSyntaxDocument;
        expect(!ParseTypedSyntaxDocument(QStringLiteral("[Identity]\nPID: 42\nPath: C:\\Windows\\sample.exe\n")),
            "generated colon/bracket reports never enter the syntax adapter");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("name: value\nstate: ready")), "colon fields are never guessed");
        const QString json = QStringLiteral("{\r\n\"z\":9007199254740993,\"a\":\"literal\",\"成功\":false\r\n}\r\n");
        const auto parsed = ParseTypedSyntaxDocument(json);
        expect(parsed.has_value() && parsed->kind == ks::ui::TypedSyntaxDocument::Kind::Json, "valid JSON produces a typed document");
        const auto& fields = parsed->fields.nodes.front().children;
        expect(fields.size() == 3 && fields[0].name == QStringLiteral("z") && fields[1].name == QStringLiteral("a"), "JSON keys retain exact source order");
        expect(fields[0].value == QStringLiteral("9007199254740993"), "JSON 64 bit integer avoids double rounding");
        expect(fields[2].name == QStringLiteral("成功") && !fields[2].translateName && !fields[2].translateValue,
            "external syntax names and values have no localization semantics");
        ks::ui::StructuredFieldView view;
        view.setPresentation(ks::ui::StructuredFieldView::Presentation::Tree);
        view.setDocument(parsed->fields); view.resize(600, 360); view.show(); drain();
        auto* tree = view.tree();
        expect(tree->topLevelItemCount() == 1 && tree->topLevelItem(0)->childCount() == 3, "typed JSON renders in the native shared field view");
        expect(tree->editTriggers() == QAbstractItemView::NoEditTriggers, "syntax fields are read only");
        tree->setCurrentItem(tree->topLevelItem(0)->child(0));
        expect(view.selectedText() == QStringLiteral("z: 9007199254740993"), "selected typed numeric field copies exact lexical evidence");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("{\"x\":[1,}")), "malformed JSON has no partial field document");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("{\"duplicate\":1,\"duplicate\":2}")), "duplicate JSON keys never silently drop evidence");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("{\"a\":1,\"\\u0061\":2}")), "escaped duplicate keys are compared after decoding");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("<root><child></root>")), "malformed XML has no partial field document");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("<!DOCTYPE r [<!ENTITY x \"data\">]><r>&x;</r>")), "XML DTD and entity expansion have no field path");
        const auto xml = ParseTypedSyntaxDocument(QStringLiteral("<?xml version=\"1.0\"?><r xmlns=\"urn:test\" a=\"1\"><v>text</v><!--kept--></r>"));
        expect(xml.has_value() && xml->kind == ks::ui::TypedSyntaxDocument::Kind::Xml, "valid XML attributes namespaces and content are supported");
        expect(xml->fields.nodes.front().children.size() == 4, "XML namespace attribute child text and comment nodes retained");
        const auto spaces = ParseTypedSyntaxDocument(QStringLiteral("<r xml:space=\"preserve\">   </r>"));
        expect(spaces && spaces->fields.nodes.front().children.back().value == QStringLiteral("   "), "XML significant whitespace is preserved");
        QString nodes = QStringLiteral("[") + QStringLiteral("0,").repeated(4094) + QStringLiteral("0]");
        expect(ParseTypedSyntaxDocument(nodes).has_value(), "node budget accepts 4096 complete JSON nodes");
        nodes.insert(nodes.size() - 1, QStringLiteral(",0"));
        expect(!ParseTypedSyntaxDocument(nodes), "node budget rejects 4097 nodes without partial results");
        expect(!ParseTypedSyntaxDocument(QString(65, QLatin1Char('[')) + QStringLiteral("0") + QString(65, QLatin1Char(']'))), "JSON excessive depth returns original source");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("<r>").repeated(65) + QStringLiteral("</r>").repeated(65)), "XML excessive depth returns original source");
        expect(!ParseTypedSyntaxDocument(QStringLiteral("{\"v\":\"") + QString(2 * 1024 * 1024, QLatin1Char('x')) + QStringLiteral("\"}")), "oversized syntax cannot allocate an unbounded field tree");
        expect(ParseTypedSyntaxDocument(QChar(0xFEFF) + QLatin1Char('\n') + json).has_value(), "syntax BOM and leading whitespace are accepted");
        for (const QString& token : {QStringLiteral("18446744073709551615"), QStringLiteral("123456789012345678901234567890"),
            QStringLiteral("0.12345678901234567890123456789"), QStringLiteral("1.234567890123456789e+25"), QStringLiteral("-0"), QStringLiteral("1.00e-20")})
        {
            const auto exact = ParseTypedSyntaxDocument(QStringLiteral("{\"number\":%1}").arg(token));
            expect(exact && exact->fields.nodes.front().children.front().value == token, "every numeric source lexeme remains exact");
        }
        const auto escaped = ParseTypedSyntaxDocument(QStringLiteral("{\"escaped\\\"key\":\"prefix\\\"18446744073709551615\",\"array\":[true,null,{\"x\":-1.001E+03}]}"));
        expect(escaped && escaped->fields.nodes.front().children[0].name == QStringLiteral("escaped\"key")
            && escaped->fields.nodes.front().children[0].value == QStringLiteral("prefix\"18446744073709551615")
            && escaped->fields.nodes.front().children[1].children[2].children[0].value == QStringLiteral("-1.001E+03"),
            "JSON string escape decoding is independent of exact numeric lexical values");
    }

    void shellTests()
    {
        CodeEditorWidget editor;
        editor.resize(680, 420); editor.show(); editor.setReadOnly(true);
        const QString raw = QStringLiteral("{\r\n\"id\":42,\"path\":\"literal\"\r\n}\r\n");
        auto* core = named<QPlainTextEdit>(editor, "code_editor_text");
        editor.setText(raw); drain();
        expect(editor.text() == raw && editor.findChild<QStackedWidget*>() == nullptr
            && editor.findChild<QComboBox*>(QStringLiteral("code_editor_structure")) == nullptr,
            "readonly text alias has no report interpretation or hidden field frontend");
        core->selectAll();
        expect(editor.copyTextForCurrentView() == raw, "raw whole selection preserves exact original CRLF");
        QEvent language(QEvent::LanguageChange); QApplication::sendEvent(&editor, &language);
        expect(editor.text() == raw && editor.copyTextForCurrentView() == raw, "language events preserve raw source and selection");
        editor.setReadOnly(false); core->moveCursor(QTextCursor::End); core->insertPlainText(QStringLiteral("edited"));
        const QString edited = editor.text();
        expect(edited.endsWith(QStringLiteral("edited")), "editing invalidates only the untouched raw cache");
        editor.setWordWrapEnabled(true); expect(editor.wordWrapEnabled(), "word wrap remains available");
        editor.setWordWrapEnabled(false); expect(!editor.wordWrapEnabled() && editor.text() == edited, "word wrap preserves source text");
        core->undo(); expect(editor.text() == core->toPlainText(), "undo continues to use the actual editable document");
    }

    void byteTests()
    {
        Provider provider;
        const QByteArray json("{\r\n\"name\":\"value\",\"items\":[1,2]\r\n}");
        provider.set(json);
        ks::ui::WorkbenchTextView view;
        view.resize(720, 420); view.show();
        view.setEncoding(ks::ui::WorkbenchTextView::Encoding::Utf8);
        view.setBytesProvider(&provider); view.setAddressRange(provider.base, provider.bytes.size());
        view.setWindow(provider.base, provider.bytes.size()); drain();
        auto* choice = named<QComboBox>(view, "ksMemwbTextStructureCombo");
        auto* treeView = named<ks::ui::StructuredFieldView>(view, "ksMemwbTextStructuredView");
        auto* stack = view.findChild<QStackedWidget*>();
        expect(choice->isEnabled() && choice->currentIndex() == 0 && stack->currentWidget() == view.canvas(), "complete byte JSON offers an explicit structure action and starts in original view");
        const auto originalBytes = provider.bytes;
        view.canvas()->selectRange(provider.base, provider.base + 3); const auto selection = view.selectedByteRange();
        const QString selected = view.selectedDecodedText(); const QString rendered = view.renderedText();
        const int calls = provider.calls;
        choice->setCurrentIndex(1); drain(); view.setFocus(); drain();
        expect(stack->currentWidget() == treeView && !treeView->document().isEmpty(), "byte text uses the native typed field component");
        expect(view.copyTextForCurrentView() == QString::fromUtf8(json), "byte structured full-copy preserves CRLF rather than canvas control glyphs");
        expect(provider.calls == calls && provider.bytes == originalBytes, "view conversion performs no provider fetch or byte mutation");
        expect(view.renderedText() == rendered && view.selectedByteRange() == selection && view.selectedDecodedText() == selected, "switching presentation preserves byte selection and row text");
        auto* dataTree = treeView->tree();
        dataTree->setFocus(); view.activateWindow(); drain();
        QTest::keyClick(dataTree, Qt::Key_F, Qt::ControlModifier); drain();
        expect(stack->currentWidget() == view.canvas(), "search always returns to the address-backed original canvas");
        auto* find = named<QLineEdit>(view, "ksMemwbTextFind");
        find->setText(QStringLiteral("value")); QTest::keyClick(find, Qt::Key_Return); drain();
        const auto valueOffset = static_cast<std::uint64_t>(json.indexOf("value"));
        expect(view.selectedByteRange() == std::make_optional(std::make_pair(provider.base + valueOffset, provider.base + valueOffset + 4)), "search selects original bytes even after structured view");
        expect(view.copyTextForCurrentView() == QStringLiteral("value"), "canvas copy stays mapped to selected decoded bytes");
        for (const std::uint8_t invalidState : {std::uint8_t{0}, std::uint8_t{2}})
        {
            choice->setCurrentIndex(1); provider.states[5] = invalidState; view.refreshView(); drain();
            expect(!choice->isEnabled() && choice->currentIndex() == 0 && treeView->document().isEmpty(), "unreadable or loading bytes clear the previous structured interpretation");
            provider.states[5] = 1;
        }
        provider.set(QByteArray("{\"v\":\"") + QByteArray(1, static_cast<char>(0xFF)) + QByteArray("\"}"));
        view.setAddressRange(provider.base, provider.bytes.size()); view.setWindow(provider.base, provider.bytes.size()); drain();
        expect(!choice->isEnabled(), "invalid UTF-8 cannot enter a structured evidence view");
        provider.set(QByteArray("{\"v\":\"") + QByteArray(1, static_cast<char>(0xE2)));
        view.setAddressRange(provider.base, provider.bytes.size()); view.setWindow(provider.base, provider.bytes.size()); drain();
        expect(!choice->isEnabled(), "incomplete UTF-8 tail cannot enter a structured evidence view");
        provider.set(json); view.clearAddressBounds(); view.setWindow(provider.base, provider.bytes.size() + 1); drain();
        expect(!choice->isEnabled(), "short provider prefix cannot masquerade as a complete requested window");
        provider.set(QByteArray("<r a=\"1\"><v>value</v></r>"));
        view.setAddressRange(provider.base, provider.bytes.size()); view.setWindow(provider.base, provider.bytes.size()); drain();
        expect(choice->isEnabled(), "byte XML uses the same explicit conversion path");
        provider.base = 0; provider.set(json); view.reset(); view.setAddressBounds(0, UINT64_MAX);
        view.setWindow(0, provider.bytes.size()); drain();
        expect(choice->isEnabled(), "zero file offset and full 64 bit upper bounds preserve complete-window detection");
        view.setBytesProvider(nullptr); drain();
        expect(!choice->isEnabled() && treeView->document().isEmpty(), "provider removal drops cached structured evidence");
    }

    void textFontTests()
    {
        const QFont previous = QApplication::font();
        QFont initial = previous;
        initial.setPointSizeF(10.0);
        QApplication::setFont(initial);
        drain();

        CodeEditorWidget shell;
        shell.resize(440, 260);
        shell.show();
        auto* core = named<CodeTextEdit>(shell, "code_editor_text");
        shell.setWordWrapEnabled(false);
        QStringList lines;
        for (int index = 0; index < 120; ++index)
            lines.append(QStringLiteral("line %1 ").arg(index) + QString(160, QLatin1Char('x')));
        shell.setRawText(lines.join(QLatin1Char('\n')));
        core->moveCursor(QTextCursor::Start);
        core->insertPlainText(QStringLiteral("edited "));
        QTextCursor cursor(core->document());
        cursor.setPosition(180);
        cursor.setPosition(186, QTextCursor::KeepAnchor);
        core->setTextCursor(cursor);
        drain();
        core->verticalScrollBar()->setValue(4);
        core->horizontalScrollBar()->setValue(12);
        const int vertical = core->verticalScrollBar()->value();
        const int horizontal = core->horizontalScrollBar()->value();
        const QString exact = shell.text();
        const bool modified = core->document()->isModified();
        const bool undo = core->document()->isUndoAvailable();
        const auto families = core->font().families();
        int changes = 0;
        QObject::connect(core, &QPlainTextEdit::textChanged, &shell, [&]() { ++changes; });

        CodeTextEdit scaled;
        scaled.setPlainText(QStringLiteral("literal raw license <tag>"));
        scaled.setReadOnly(true);
        QFont host = scaled.font();
        host.setFamilies({QStringLiteral("Courier New")});
        host.setPointSizeF(16.0);
        host.setBold(true);
        host.setItalic(true);
        scaled.setFont(host);

        QFont changed = initial;
        changed.setPointSizeF(14.0);
        QApplication::setFont(changed);
        drain();
        expect(std::abs(core->font().pointSizeF() - 14.0) < 0.01,
            "existing raw shell core follows the hot application size");
        expect(std::abs(scaled.font().pointSizeF() - 22.4) < 0.01,
            "explicit host size preserves its 1.6 application multiplier");
        expect(core->font().families() == families && scaled.font().families() == host.families()
            && scaled.font().bold() && scaled.font().italic(), "hot font size preserves code family and host formatting");
        expect(shell.text() == exact && scaled.toPlainText() == QStringLiteral("literal raw license <tag>") && changes == 0,
            "hot font refresh changes no raw source and emits no content edits");
        expect(core->textCursor().position() == cursor.position() && core->textCursor().anchor() == cursor.anchor()
            && core->document()->isModified() == modified && core->document()->isUndoAvailable() == undo,
            "hot font refresh preserves selection, modified flag and undo history");
        expect(core->verticalScrollBar()->value() == vertical && core->horizontalScrollBar()->value() == horizontal,
            "hot font refresh preserves the raw reader viewport");

        changed.setPointSizeF(18.0);
        QApplication::setFont(changed);
        QFont hostOverride = scaled.font();
        hostOverride.setPointSizeF(27.0);
        scaled.setFont(hostOverride);
        drain();
        expect(std::abs(scaled.font().pointSizeF() - 27.0) < 0.01,
            "host font override during queued application refresh remains authoritative");
        changed.setPointSizeF(20.0);
        QApplication::setFont(changed);
        drain();
        expect(std::abs(scaled.font().pointSizeF() - 30.0) < 0.01 && std::abs(core->font().pointSizeF() - 20.0) < 0.01,
            "repeated hot updates preserve the new host multiplier without compounding");
        expect(shell.text() == exact && changes == 0, "repeated font changes preserve edited source");
        core->undo();
        expect(!shell.text().startsWith(QStringLiteral("edited ")), "font updates leave the original edit undoable");

        changed.setPixelSize(24);
        QApplication::setFont(changed);
        drain();
        expect(core->font().pixelSize() == 24 && scaled.font().pixelSize() == 36,
            "point to pixel application font changes retain each host scale");
        QApplication::setFont(previous);
        drain();
    }

    void streamingTests()
    {
        CodeEditorWidget log;
        log.resize(400, 240);
        log.show();
        auto* core = named<QPlainTextEdit>(log, "code_editor_text");
        int notifications = 0;
        QString notified;
        QObject::connect(&log, &CodeEditorWidget::contentChanged, &log, [&](const QString& text) { ++notifications; notified = text; });
        log.setReadOnly(true);
        log.setMaximumBlockCount(3);
        log.appendRawText(QStringLiteral("first"));
        log.appendRawText(QStringLiteral("second"));
        log.appendRawText(QStringLiteral("third"));
        log.appendRawText(QStringLiteral("fourth"));
        drain();
        expect(log.maximumBlockCount() == 3 && log.text() == QStringLiteral("second\nthird\nfourth"), "streaming retains only the configured latest blocks");
        expect(!core->document()->isUndoRedoEnabled(), "bounded raw streams follow Qt capacity and undo semantics");
        expect(notifications == 1 && notified == log.text(), "burst streaming emits one deferred notification with the latest retained text");
        const QString raw = log.text();
        QEvent language(QEvent::LanguageChange);
        QApplication::sendEvent(&log, &language);
        expect(log.text() == raw, "raw streams remain unchanged on language refresh");
        log.clear();
        expect(log.text().isEmpty() && log.maximumBlockCount() == 3, "clearing a stream preserves its capacity");
        log.setMaximumBlockCount(0);
        log.setReadOnly(false);
        core->document()->setUndoRedoEnabled(true);
        log.appendRawText(QStringLiteral("editable"));
        expect(core->document()->isUndoAvailable(), "unbounded editable append preserves normal document undo");
        core->undo();
        expect(log.text().isEmpty(), "stream append can be undone through the text core");
        log.setReadOnly(true);
        QStringList lines;
        for (int index = 0; index < 100; ++index) lines.append(QStringLiteral("line %1").arg(index));
        log.setRawText(lines.join(QLatin1Char('\n')));
        drain();
        core->verticalScrollBar()->setValue(0);
        log.appendRawText(QStringLiteral("new tail"), false);
        expect(core->verticalScrollBar()->value() == 0, "stream autoScroll false keeps the user's reading position");
        log.appendRawText(QStringLiteral("new tail during reading"));
        expect(core->verticalScrollBar()->value() == 0, "default stream append does not steal a reader's non-tail viewport");
        core->verticalScrollBar()->setValue(core->verticalScrollBar()->maximum());
        log.appendRawText(QStringLiteral("latest tail"), true);
        expect(core->verticalScrollBar()->value() == core->verticalScrollBar()->maximum(), "stream autoScroll true follows the latest text");
        log.replaceRawText(log.text() + QStringLiteral("\nrebuilt tail"));
        expect(core->verticalScrollBar()->value() == core->verticalScrollBar()->maximum(), "raw log rebuild follows tail only when previously at the end");
        core->verticalScrollBar()->setValue(0);
        log.replaceRawText(log.text() + QStringLiteral("\nmore rebuilt text"));
        expect(core->verticalScrollBar()->value() == 0, "raw log rebuild preserves a reader's non-tail viewport");
        log.setMaximumBlockCount(3);
        log.replaceRawText(QStringLiteral("a\nb\nc\nd"), false);
        expect(log.maximumBlockCount() == 3 && log.text() == QStringLiteral("b\nc\nd"), "raw log rebuild preserves the established capacity");
        drain();
    }
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    parserTests(); shellTests(); byteTests(); textFontTests(); streamingTests();
    std::cout << "UNIFIED_TEXT_VIEWS_TESTS checks=" << checks << " failures=0\n";
    return 0;
}
