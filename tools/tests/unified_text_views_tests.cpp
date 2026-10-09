// Real production Qt views. No clipboard writes, native dialogs, target I/O,
// settings persistence or temporary directories are used by this regression.
#include "../../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include "../../Ksword5.1/Ksword5.1/UI/CodeTextEdit.h"
#include "../../Ksword5.1/Ksword5.1/UI/ReportStructuredView.h"
#include "../../Ksword5.1/Ksword5.1/UI/FieldTreePresenter.h"
#include "../../Ksword5.1/Ksword5.1/theme.h"
#include "../../Ksword5.1/Ksword5.1/UI/DetailLayoutHost.h"
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
        using ks::ui::ReportStructuredView;
        const QString report = QStringLiteral("[Identity]\nPID: 42\nPath: C:\\Windows\\sample.exe\nState: Ready\n");
        expect(ReportStructuredView::canStructure(report), "bracketed reports remain compatible with JSON detection");
        const QString json = QStringLiteral("{\r\n  \"text\": \"<literal>\", \"list\": [true, null, 42]\r\n}\r\n");
        ReportStructuredView view;
        view.resize(600, 400); view.show();
        expect(view.setReportText(json), "valid JSON gets the common structured view"); drain();
        auto* tree = named<QTreeWidget>(view, "report_structured_data");
        expect(tree->topLevelItemCount() == 1 && tree->topLevelItem(0)->childCount() == 2, "JSON object fields render as tree nodes");
        expect(tree->editTriggers() == QAbstractItemView::NoEditTriggers, "JSON tree is presentation only");
        view.setFocus(); drain();
        expect(view.selectionOrReportText() == json, "whole-report copy retains exact original CRLF and spacing");
        expect(!ReportStructuredView::canStructure(QStringLiteral("{\"x\": [1,}")), "invalid JSON never masquerades as a report");
        expect(view.setReportText(QStringLiteral("{\"address\":9007199254740993}")), "JSON preserves native 64 bit integers"); drain();
        tree = named<QTreeWidget>(view, "report_structured_data");
        expect(tree->topLevelItem(0)->child(0)->text(1) == QStringLiteral("9007199254740993"), "integer rendering does not round through double");
        expect(!ReportStructuredView::canStructure(QStringLiteral("<root><child></root>")), "invalid XML falls back to source");
        expect(ReportStructuredView::canStructure(QStringLiteral("<?xml version=\"1.0\"?><r xmlns=\"urn:test\" a=\"1\"><v>text</v><!--kept--></r>")), "valid XML attributes and content are supported");
        expect(!ReportStructuredView::canStructure(QStringLiteral("<!DOCTYPE r [<!ENTITY x \"data\">]><r>&x;</r>")), "XML entity expansion has no presentation path");
        QString nodes = QStringLiteral("[");
        for (int n = 0; n < 4095; ++n) nodes += n ? QStringLiteral(",0") : QStringLiteral("0");
        nodes += QLatin1Char(']');
        expect(ReportStructuredView::canStructure(nodes), "node budget accepts 4096 total JSON nodes");
        nodes.insert(nodes.size() - 1, QStringLiteral(",0"));
        expect(!ReportStructuredView::canStructure(nodes), "node budget rejects 4097 total JSON nodes without truncating evidence");
        const QString deep = QString(65, QLatin1Char('[')) + QStringLiteral("0") + QString(65, QLatin1Char(']'));
        expect(!ReportStructuredView::canStructure(deep), "excessive JSON nesting returns to original text");
        QString deepXml;
        for (int n = 0; n < 65; ++n) deepXml += QStringLiteral("<r>");
        for (int n = 0; n < 65; ++n) deepXml += QStringLiteral("</r>");
        expect(!ReportStructuredView::canStructure(deepXml), "XML depth has the same bounded presentation rule");
        const QString tooLong = QStringLiteral("{\"v\":\"") + QString(2 * 1024 * 1024, QLatin1Char('x')) + QStringLiteral("\"}");
        expect(!ReportStructuredView::canStructure(tooLong), "oversized data cannot allocate an unbounded tree");
        expect(ReportStructuredView::canStructure(QChar(0xFEFF) + QLatin1Char('\n') + json), "BOM detection permits whitespace before valid JSON without altering source");
        const QString manyReportLines = QStringLiteral("[Fields]\n") + QStringLiteral("Field: value\n").repeated(4096);
        expect(!ReportStructuredView::canStructure(manyReportLines), "plain generated reports also obey a bounded row budget");
    }

    void shellTests()
    {
        CodeEditorWidget editor;
        editor.resize(680, 420); editor.show(); editor.activateWindow(); editor.setReadOnly(true);
        const QString json = QStringLiteral("{\r\n\"id\":42, \"path\":\"literal\"\r\n}\r\n");
        auto* choice = named<QComboBox>(editor, "code_editor_structure");
        auto* core = named<QPlainTextEdit>(editor, "code_editor_text");
        editor.setRawText(json); drain();
        expect(!editor.isReportText() && !choice->isVisible(), "read-only raw JSON has no implicit report conversion");
        editor.setReportText(json); drain();
        expect(editor.isReportText() && choice->isVisible(), "already localized report opts into the shared structure view");
        expect(editor.text() == json, "report API retains every original line-ending character");
        expect(!core->document()->isModified(), "structure conversion does not dirty the text document");
        choice->setCurrentIndex(0); editor.setFocus(); drain();
        expect(editor.copyTextForCurrentView() == json, "structured copy defaults to full exact report rather than a hidden source selection");
        auto* typed = new QTreeWidget;
        ks::ui::ConfigureFieldTree(typed, false);
        auto* row = ks::ui::AppendFieldRow(typed, nullptr, QStringLiteral("Address"), QStringLiteral("0x1234"));
        editor.setStructuredContentWidget(typed); choice->setCurrentIndex(0); drain();
        auto* stack = editor.findChild<QStackedWidget*>();
        expect(stack != nullptr && stack->currentWidget() == typed, "typed evidence uses the same structure selector");
        typed->setCurrentItem(row); row->setSelected(true);
        expect(editor.copyTextForCurrentView() == QStringLiteral("Address: 0x1234"), "custom field copy uses the same colon row format as parsed fields");
        typed->setFocus(); editor.activateWindow(); drain();
        QTest::keyClick(typed, Qt::Key_F, Qt::ControlModifier); drain();
        expect(stack->currentWidget() == core, "find from the typed view returns to visible searchable source");
        auto* find = named<QLineEdit>(editor, "code_editor_find");
        find->setText(QStringLiteral("literal")); QTest::keyClick(find, Qt::Key_Return); drain();
        expect(editor.copyTextForCurrentView() == QStringLiteral("literal"), "source copy follows the source search selection");
        editor.setRawText(json); drain();
        expect(!choice->isVisible() && stack->currentWidget() == core, "same text in raw mode clears the previous structured page");
        choice->setCurrentIndex(0); drain();
        expect(stack->currentWidget() == core, "a hidden selector cannot expose a stale interpretation in raw mode");
        editor.setReportText(json); editor.setReadOnly(false); drain();
        expect(!choice->isVisible() && !editor.isReportText(), "editable mode drops report interpretation");
        core->insertPlainText(QStringLiteral("edited"));
        expect(editor.text().contains(QStringLiteral("edited")), "editing uses the actual source document");
        const QString edited = editor.text();
        editor.setWordWrapEnabled(true); expect(editor.wordWrapEnabled(), "shared wrap API enables actual text wrapping");
        editor.setWordWrapEnabled(false); expect(!editor.wordWrapEnabled() && editor.text() == edited, "wrap policy changes preserve edited source text");
        editor.setReadOnly(true); editor.setStructuredContentWidget(nullptr); editor.setReportText(json); drain();
        expect(choice->isVisible(), "removing custom evidence restores shared JSON parsing");
        editor.appendReportText(QStringLiteral("suffix"));
        expect(editor.text() == json + QLatin1Char('\n') + QStringLiteral("suffix"), "append retains the report source instead of reformatting its JSON");
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
        auto* treeView = named<ks::ui::ReportStructuredView>(view, "ksMemwbTextStructuredView");
        auto* stack = view.findChild<QStackedWidget*>();
        expect(choice->isEnabled() && choice->currentIndex() == 0 && stack->currentWidget() == view.canvas(), "complete byte JSON offers an explicit structure action and starts in original view");
        const auto originalBytes = provider.bytes;
        view.canvas()->selectRange(provider.base, provider.base + 3); const auto selection = view.selectedByteRange();
        const QString selected = view.selectedDecodedText(); const QString rendered = view.renderedText();
        const int calls = provider.calls;
        choice->setCurrentIndex(1); drain(); view.setFocus(); drain();
        expect(stack->currentWidget() == treeView && treeView->hasStructure(), "byte text uses the same report structure component");
        expect(view.copyTextForCurrentView() == QString::fromUtf8(json), "byte structured full-copy preserves CRLF rather than canvas control glyphs");
        expect(provider.calls == calls && provider.bytes == originalBytes, "view conversion performs no provider fetch or byte mutation");
        expect(view.renderedText() == rendered && view.selectedByteRange() == selection && view.selectedDecodedText() == selected, "switching presentation preserves byte selection and row text");
        auto* dataTree = named<QTreeWidget>(*treeView, "report_structured_data");
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
            expect(!choice->isEnabled() && choice->currentIndex() == 0 && !treeView->hasStructure(), "unreadable or loading bytes clear the previous structured interpretation");
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
        expect(!choice->isEnabled() && !treeView->hasStructure(), "provider removal drops cached structured evidence");
    }

    // 比较实际 typed 与解析树，覆盖复制、字体、主题和嵌套菜单生命周期。
    void fieldPresenterTests()
    {
        using namespace ks::ui;
        const QString address = QStringLiteral("0xFEDCBA9876543210");
        const QString exact = QStringLiteral("[R0]\n  Address: %1\n  FileId: 18446744073709551615\n  State: failed\n\n").arg(address);
        CodeEditorWidget typedShell;
        typedShell.resize(650, 400);
        typedShell.setReadOnly(true);
        auto* typed = new QTreeWidget;
        ConfigureFieldTree(typed, true);
        auto* group = AppendFieldGroup(typed, QStringLiteral("R0"));
        auto* addressRow = AppendFieldRow(typed, group, QStringLiteral("Address"), address);
        AppendFieldRow(typed, group, QStringLiteral("FileId"), QStringLiteral("18446744073709551615"));
        auto* state = AppendFieldRow(typed, group, QStringLiteral("State"), QStringLiteral("failed"));
        RefreshFieldTree(typed);
        typedShell.setStructuredContentWidget(typed);
        typedShell.setReportText(FieldTreeToPlainText(typed));
        typedShell.show();
        named<QComboBox>(typedShell, "code_editor_structure")->setCurrentIndex(0);
        drain();
        expect(typedShell.text() == exact, "typed R0 field identity, order, group and 64 bit values remain exact");
        typed->setCurrentItem(addressRow);
        const auto typedCopy = CaptureStructuredCopy(typed, typed->indexFromItem(addressRow));
        expect(typedCopy.value == address && typedCopy.row == QStringLiteral("Address: %1").arg(address), "typed menu freezes value and colon formatted row");
        expect(typedCopy.all == exact, "typed full copy retains groups and field order");
        expect(typedShell.copyTextForCurrentView() == typedCopy.row, "typed toolbar and context menu serialize the same selected row");
        expect(StructuredCopyText(typed) == typedCopy.row, "typed keyboard policy copies the same selected row");
        typed->clearSelection();
        expect(StructuredCopyText(typed) == exact && typedShell.copyTextForCurrentView() == exact,
            "typed keyboard and toolbar use authoritative full source when no row is selected");
        typed->setCurrentItem(addressRow);
        addressRow->setSelected(true);

        ReportStructuredView parsed;
        parsed.resize(650, 400);
        parsed.show();
        expect(parsed.setReportText(exact), "the same generated report remains parseable");
        drain();
        auto* parsedTree = parsed.findChild<QTreeWidget*>();
        expect(parsedTree != nullptr, "parsed report uses a field tree");
        auto* parsedAddress = parsedTree->topLevelItem(0)->child(0);
        parsedTree->setCurrentItem(parsedAddress);
        parsedTree->setFocus();
        parsed.activateWindow();
        drain();
        const auto parsedCopy = CaptureStructuredCopy(parsedTree, parsedTree->indexFromItem(parsedAddress));
        expect(parsedCopy.value == typedCopy.value && parsedCopy.row == typedCopy.row && parsedCopy.all == typedCopy.all, "typed and parsed fields share value, row and complete copy formatting");
        expect(parsed.selectionOrReportText() == typedCopy.row, "parsed toolbar selection uses the same presenter payload");
        expect(StructuredCopyText(parsedTree) == typedCopy.row, "parsed keyboard policy copies the same selected row");
        parsedTree->clearSelection();
        expect(StructuredCopyText(parsedTree) == exact && parsed.selectionOrReportText() == exact,
            "parsed and typed keyboard policies share exact source fallback");
        parsedTree->setCurrentItem(parsedAddress);
        parsedAddress->setSelected(true);
        expect(typed->font() == parsedTree->font() && typed->columnWidth(0) == parsedTree->columnWidth(0), "typed and parsed trees share font and name width");
        expect(typed->styleSheet() == parsedTree->styleSheet() && !typed->styleSheet().isEmpty(), "shared field geometry overrides old per-dialog tree styling");

        // 应用字体热更新不重新采集数据，也不把已有字符串再次翻译。
        const QFont previousFont = QApplication::font();
        QFont changedFont = previousFont;
        changedFont.setFamily(QStringLiteral("Arial"));
        changedFont.setPointSizeF(13.0);
        QApplication::setFont(changedFont);
        drain();
        parsedTree = parsed.findChild<QTreeWidget*>();
        expect(typed->font() == ScaledReportFont(QApplication::font(typed)), "typed fields recompute the scaled application font after hot update");
        expect(parsedTree->font() == typed->font() && group->font(0).pointSizeF() == typed->font().pointSizeF(), "parsed fields and typed groups follow the same updated font");
        expect(typedShell.text() == exact && FieldTreeToPlainText(typed) == exact, "font refresh does not alter typed source evidence");
        const bool previousDark = KswordTheme::IsDarkModeEnabled();
        const QPalette previousPalette = QApplication::palette();
        KswordTheme::SetDarkModeEnabled(!previousDark);
        QPalette changedPalette = previousPalette;
        changedPalette.setColor(QPalette::Window, previousDark ? QColor("#ffffff") : QColor("#151515"));
        QApplication::setPalette(changedPalette);
        drain();
        expect(state->foreground(1).color() == KswordTheme::ErrorColor(), "typed semantic foreground refreshes to the current theme");
        expect(FieldTreeToPlainText(typed) == exact, "theme refresh preserves every typed field");
        KswordTheme::SetDarkModeEnabled(previousDark);
        QApplication::setPalette(previousPalette);
        QApplication::setFont(previousFont);
        drain();

        // 菜单循环内销毁旧节点并建新字段，选择动作只能返回打开前冻结的数据。
        const QPoint position = typed->visualItemRect(addressRow).center();
        QTimer::singleShot(0, &typedShell, [typed]()
        {
            auto* menu = qobject_cast<QMenu*>(QApplication::activePopupWidget());
            expect(menu != nullptr && !menu->styleSheet().isEmpty(), "shared copy menu has explicit opaque theme styling");
            typed->clear();
            AppendFieldRow(typed, nullptr, QStringLiteral("New"), QStringLiteral("replacement"));
            menu->setActiveAction(menu->actions().at(1));
            QTest::keyClick(menu, Qt::Key_Return);
        });
        expect(ExecStructuredCopyMenu(typed, position) == typedCopy.row, "menu refresh never dereferences deleted field nodes and returns frozen row");
        drain();

        // 完整宿主在菜单期间销毁时，无复制结果；不触碰真实剪贴板。
        auto* doomed = new QTreeWidget;
        ConfigureFieldTree(doomed, false);
        auto* doomedRow = AppendFieldRow(doomed, nullptr, QStringLiteral("Old"), QStringLiteral("value"));
        doomed->resize(400, 240);
        doomed->show();
        drain();
        const QPoint doomedPosition = doomed->visualItemRect(doomedRow).center();
        QPointer<QTreeWidget> doomedGuard(doomed);
        QTimer::singleShot(0, qApp, [doomed]() { delete doomed; });
        expect(ExecStructuredCopyMenu(doomed, doomedPosition).isEmpty() && !doomedGuard, "owner destruction safely exits the nested copy menu");
        drain();
    }

    // 实际正文热字体保留宿主倍率、字体族及编辑状态，不触发剪贴板或真实业务后端。
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

    // JSON/XML 的复制全部使用完整原文，不经过字段排序或字符串/整数再序列化。
    void authoritativeCopyTests()
    {
        using namespace ks::ui;
        const QString json = QStringLiteral("{\r\n  \"z\":9007199254740993,\r\n  \"a\":\"literal\"\r\n}\r\n");
        ReportStructuredView report;
        report.resize(600, 360);
        report.show();
        expect(report.setReportText(json), "copy authority fixture has real JSON structure");
        drain();
        auto* tree = named<QTreeWidget>(report, "report_structured_data");
        expect(StructuredCopyText(tree) == json && CaptureStructuredCopy(tree, {}).all == json,
            "parsed keyboard and menu all-copy retain unsorted JSON CRLF source");
        expect(tree->topLevelItem(0)->child(0)->text(0) == QStringLiteral("z"),
            "JSON presentation preserves source field order instead of Qt object sorting");
        tree->setCurrentItem(tree->topLevelItem(0)->child(1));
        expect(StructuredCopyText(tree) == QStringLiteral("a: literal"),
            "selected JSON field uses common exact row copy instead of whole-report fallback");
        const auto frozen = CaptureStructuredCopy(tree, tree->indexFromItem(tree->currentItem()));
        tree->clearSelection();
        const QString replacement = QStringLiteral("{\"new\":true}");
        report.setReportText(replacement);
        drain();
        tree = named<QTreeWidget>(report, "report_structured_data");
        expect(StructuredCopyText(tree) == replacement && frozen.all == json,
            "report update refreshes copy authority while previously frozen menu payload remains old evidence");
        QTreeWidget standalone;
        ConfigureFieldTree(&standalone, false);
        AppendFieldRow(&standalone, nullptr, QStringLiteral("Actual"), QStringLiteral("typed value"));
        expect(StructuredCopyText(&standalone) == FieldTreeToPlainText(&standalone),
            "standalone typed fields share whole-copy policy without fabricated report source");
    }

    // 字段值本身亦须保真，完整原文复制不能掩盖 JSON 数字被 double 舍入的问题。
    void exactJsonNumberTests()
    {
        using ks::ui::ReportStructuredView;
        ReportStructuredView report;
        report.resize(600, 360);
        report.show();
        for (const QString& token : {QStringLiteral("18446744073709551615"),
            QStringLiteral("123456789012345678901234567890"),
            QStringLiteral("0.12345678901234567890123456789"),
            QStringLiteral("1.234567890123456789e+25"), QStringLiteral("-0"), QStringLiteral("1.00e-20")})
        {
            const QString source = QStringLiteral("{\"number\":%1}").arg(token);
            const bool structured = report.setReportText(source);
            drain();
            auto* tree = report.findChild<QTreeWidget*>();
            const QString displayed = structured && tree != nullptr
                ? tree->topLevelItem(0)->child(0)->text(1) : QString();
            if (structured && displayed != token)
                std::cerr << "Lossy JSON numeric source=" << token.toStdString()
                    << " display=" << displayed.toStdString() << '\n';
            expect(structured && displayed == token, "bounded valid JSON displays its exact numeric source token");
            if (structured)
            {
                auto* row = tree->topLevelItem(0)->child(0);
                tree->setCurrentItem(row);
                expect(ks::ui::StructuredCopyText(tree) == QStringLiteral("number: %1").arg(token),
                    "selected JSON numeric field retains its exact source token");
            }
            report.setFocus();
            drain();
            expect(report.selectionOrReportText() == source, "numeric structure or rejection keeps original JSON copy authority");
        }
        const QString digits = QStringLiteral("18446744073709551615 1.234567890123456789e+25");
        expect(report.setReportText(QStringLiteral("{\"string\":\"%1\"}").arg(digits)),
            "numeric text inside JSON strings remains valid string data");
        drain();
        auto* tree = report.findChild<QTreeWidget*>();
        expect(tree != nullptr && tree->topLevelItem(0)->child(0)->text(1) == digits,
            "numeric-looking strings are not parsed as numbers");
        const QString escaped = QStringLiteral("{\"escaped\\\"key\":\"prefix\\\"18446744073709551615\",\"array\":[true,null,{\"x\":-1.001E+03}]}");
        expect(report.setReportText(escaped), "escaped strings and nested numeric nodes remain parseable");
        drain();
        tree = report.findChild<QTreeWidget*>();
        expect(tree != nullptr && tree->topLevelItem(0)->child(0)->text(0) == QStringLiteral("escaped\"key")
            && tree->topLevelItem(0)->child(0)->text(1) == QStringLiteral("prefix\"18446744073709551615")
            && tree->topLevelItem(0)->child(1)->child(2)->child(0)->text(1) == QStringLiteral("-1.001E+03"),
            "string escape decoding stays separate from exact nested numeric lexemes");
        expect(!ReportStructuredView::canStructure(QStringLiteral("{\"duplicate\":1,\"duplicate\":2}")),
            "ambiguous duplicate JSON keys return to original source instead of dropping evidence");
        expect(!ReportStructuredView::canStructure(QStringLiteral("{\"a\":1,\"\\u0061\":2}")),
            "duplicate detection compares decoded key names rather than raw escaped tokens");
    }

    // 原文日志流使用真实文档验证容量、通知、撤销与滚动，不启动目标或写剪贴板。
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
        expect(!log.isReportText() && !core->document()->isUndoRedoEnabled(), "bounded raw streams follow Qt capacity and undo semantics");
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

    void mirrorTests()
    {
        QWidget page; auto* layout = new QVBoxLayout(&page);
        auto* table = new QTableWidget(1, 1, &page); table->setItem(0, 0, new QTableWidgetItem(QStringLiteral("row")));
        auto* source = new CodeEditorWidget(&page); source->setReadOnly(true);
        layout->addWidget(table); layout->addWidget(source);
        ks::ui::DetailLayoutHost host(table, source, &page);
        page.resize(700, 600); page.show(); drain();
        const QString report = QStringLiteral("PID: 42\nAddress: 0x1000\nState: Ready\n");
        source->setReportText(report); drain();
        host.applyScheme(ks::settings::DetailDisplayScheme::Floating); drain();
        QTest::mouseClick(table->viewport(), Qt::LeftButton, Qt::NoModifier, table->visualRect(table->model()->index(0, 0)).center()); drain();
        CodeEditorWidget* mirror = nullptr;
        for (QWidget* window : QApplication::topLevelWidgets())
            if (auto* dialog = qobject_cast<QDialog*>(window))
                if (auto* editor = dialog->findChild<CodeEditorWidget*>()) mirror = editor;
        expect(mirror != nullptr && mirror->isReportText() && mirror->text() == report, "floating details preserve the same exact report and interpretation");
        source->setRawText(report); drain();
        expect(!mirror->isReportText() && !named<QComboBox>(*mirror, "code_editor_structure")->isVisible(), "floating raw source does not become a parsed report");
        source->setReportText(report); drain();
        host.applyScheme(ks::settings::DetailDisplayScheme::Embedded); drain();
        QTest::mouseClick(table->viewport(), Qt::LeftButton, Qt::NoModifier, table->visualRect(table->model()->index(0, 0)).center()); drain();
        auto* inlineEditor = table->viewport()->findChild<CodeEditorWidget*>();
        expect(inlineEditor != nullptr && inlineEditor->isReportText() && inlineEditor->text() == report, "inline details use the same report shell and original content");
        expect(!named<QComboBox>(*inlineEditor, "code_editor_structure")->isHidden(), "inline details retain the shared structure selector");
        source->setRawText(report); drain();
        expect(!inlineEditor->isReportText(), "inline updates keep raw sources raw");
        host.applyScheme(ks::settings::DetailDisplayScheme::BottomCollapsed); drain();
    }
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    parserTests(); shellTests(); byteTests(); fieldPresenterTests(); textFontTests(); authoritativeCopyTests(); exactJsonNumberTests(); streamingTests(); mirrorTests();
    std::cout << "UNIFIED_TEXT_VIEWS_TESTS checks=" << checks << " failures=0\n";
    return 0;
}
