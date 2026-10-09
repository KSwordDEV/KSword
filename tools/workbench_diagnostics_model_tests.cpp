#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchDiagnosticsHost.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchStatusBar.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchMessages.h"
#include "../Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeEditorWidget.h"
#include <QApplication>
#include <QClipboard>
#include <QCheckBox>
#include <QElapsedTimer>
#include <QMimeData>
#include <QStackedWidget>
#include <QScrollBar>
#include <QToolButton>
#include <QTreeWidget>
#include <cstdio>
#include <memory>
#include <stdexcept>

namespace {
int checks = 0;
void expect(bool value, const char* description) {
    ++checks;
    if (!value) throw std::runtime_error(description);
}
void settleLayout() {
    QElapsedTimer elapsed;
    elapsed.start();
    do { QCoreApplication::processEvents(QEventLoop::AllEvents, 20); } while (elapsed.elapsed() < 80);
}
QTreeWidgetItem* findValue(QTreeWidgetItem* parent, const QString& value) {
    for (int index = 0; index < parent->childCount(); ++index) {
        QTreeWidgetItem* child = parent->child(index);
        if (child->text(1) == value) return child;
        if (auto* nested = findValue(child, value)) return nested;
    }
    return nullptr;
}
struct RestoreClipboard {
    std::unique_ptr<QMimeData> original = std::make_unique<QMimeData>();
    RestoreClipboard() {
        if (const QMimeData* data = QApplication::clipboard()->mimeData())
            for (const QString& format : data->formats()) original->setData(format, data->data(format));
    }
    ~RestoreClipboard() { QApplication::clipboard()->setMimeData(original.release()); }
};
}
int main(int argc, char** argv) {
    QApplication app(argc, argv);
    try {
        RestoreClipboard restore;
        auto host = std::make_unique<ks::ui::WorkbenchDiagnosticsHost>();
        auto* actual = host.get();
        ks::ui::WorkbenchStatusBar status(std::move(host));
        status.resize(800, 220);
        status.show();
        const QString log = QStringLiteral("actual raw log: %2 := <payload>\nsecond line\n");
        status.setDiagnosticsText(log, true);
        auto* raw = actual->editorForTest();
        auto* fields = actual->fieldsForTest();
        auto* panes = actual->findChild<QStackedWidget*>();
        auto* copy = status.findChild<QToolButton*>(QStringLiteral("workbench_copy_diagnostics"));
        expect(raw && fields && panes && copy, "production drawer exposes raw/native panes and actual copy action");
        expect(panes->currentWidget() == raw && status.diagnosticsText() == log, "raw log mode preserves exact original bytes");
        expect(raw->isReadOnly(), "genuine raw log stays read only");
        expect(fields->findChildren<CodeEditorWidget*>().isEmpty(), "native report has no hidden text editor mirror");

        ks::ui::FieldDocument source;
        source.section(QStringLiteral("Pointer chain"));
        const QStringList values = {QStringLiteral("0xFFFFFFFFC0000001"), QStringLiteral("path_%1:[x]=<raw>&\nnext"),
            QStringLiteral("SID_%2_中文"), QString(5000, QChar(u'Z')), QStringLiteral("old_record_exact")};
        for (qsizetype index = 0; index < values.size(); ++index)
            source.field(QStringLiteral("Field %1").arg(index), values[index]);
        const QString expected = source.toPlainText(true);
        status.setDiagnosticsDocument(source, true);
        QCoreApplication::processEvents();
        expect(status.isDrawerExpanded(), "typed update retains automatic expansion behavior");
        expect(panes->currentWidget() == fields, "typed setter displays production native fields");
        expect(fields->document().toPlainText(true) == expected, "typed setter stores the complete source model");
        expect(raw->text() == log, "model updates do not overwrite or mirror into raw log editor");
        expect(fields->tree()->editTriggers() == QAbstractItemView::NoEditTriggers, "native diagnostics are read only");
        copy->click();
        expect(QApplication::clipboard()->text() == expected, "actual copy button exports current model on demand");
        for (const QString& value : values)
            expect(QApplication::clipboard()->text().contains(value), "actual clipboard conserves full scalar and special characters");
        status.resize(360, 220);
        settleLayout();
        auto* tree = fields->tree();
        auto* longItem = findValue(tree->invisibleRootItem(), values[3]);
        expect(longItem != nullptr, "actual native tree retains the complete 5000-character value");
        tree->scrollToItem(longItem, QAbstractItemView::PositionAtTop);
        settleLayout();
        const int wrappedHeight = tree->visualItemRect(longItem).height();
        const int wrappedWidth = tree->columnWidth(1);
        expect(wrappedHeight > 0 && tree->visualItemRect(longItem).intersects(tree->viewport()->rect()),
            "long wrapped row is actually laid out and visible in the narrow drawer");
        QCheckBox* wrap = nullptr;
        for (QCheckBox* checkbox : status.findChildren<QCheckBox*>())
            if (checkbox->text() == ks::ui::workbench_messages::DiagnosticsWrapCheckboxText()) wrap = checkbox;
        expect(wrap && wrap->isEnabled() && wrap->isChecked(), "original wrap checkbox remains available in typed mode");
        wrap->setChecked(false);
        settleLayout();
        const int unwrappedHeight = tree->visualItemRect(longItem).height();
        const int unwrappedWidth = tree->columnWidth(1);
        expect(unwrappedHeight < wrappedHeight, "turning off wrap actually reduces the rendered row height");
        expect(tree->horizontalScrollBar()->maximum() > 0 && unwrappedWidth > wrappedWidth,
            "unwrapped long value widens its column and exposes real horizontal scrolling");
        copy->click();
        expect(QApplication::clipboard()->text() == expected, "nowrap rendering leaves full model copy unchanged");
        wrap->setChecked(true);
        settleLayout();
        tree->scrollToItem(longItem, QAbstractItemView::PositionAtTop);
        settleLayout();
        if (tree->visualItemRect(longItem).height() <= unwrappedHeight)
            std::fprintf(stderr, "wrap geometry: wrapped=%d nowrap=%d restored=%d valueWidths=%d/%d/%d wordWrap=%d horizontalMax=%d\n",
                wrappedHeight, unwrappedHeight, tree->visualItemRect(longItem).height(), wrappedWidth, unwrappedWidth,
                tree->columnWidth(1), tree->wordWrap() ? 1 : 0, tree->horizontalScrollBar()->maximum());
        expect(tree->visualItemRect(longItem).height() > unwrappedHeight, "restoring wrap restores actual multiline row geometry");
        expect(tree->columnWidth(1) < unwrappedWidth && tree->horizontalScrollBar()->maximum() == 0,
            "restoring wrap shrinks the value column and removes horizontal overflow");
        copy->click();
        expect(QApplication::clipboard()->text() == expected, "restored wrapped rendering conserves full model copy");
        source.nodes.front().children.front().value = QStringLiteral("mutated caller after publish");
        expect(status.diagnosticsText() == expected, "published native model owns its snapshot independently of caller mutation");

        ks::ui::FieldDocument next;
        next.field(QStringLiteral("Next"), QStringLiteral("new_value_%2\nfull"));
        status.setDiagnosticsDocument(next, true);
        copy->click();
        expect(QApplication::clipboard()->text() == next.toPlainText(true), "copy action observes the latest typed snapshot");
        expect(!QApplication::clipboard()->text().contains(QStringLiteral("old_record_exact")), "new typed copy contains no stale prior fields");
        expect(raw->text() == log, "multiple typed publications leave raw data independent");
        actual->SetWrapEnabled(false);
        expect(!actual->lastWrapRequestForTest() && !fields->tree()->wordWrap(), "wrap policy updates native pane without rewriting model");
        expect(status.diagnosticsText() == next.toPlainText(true), "native wrap changes preserve exported evidence");
        actual->SetWrapEnabled(true);
        expect(actual->lastWrapRequestForTest() && fields->tree()->wordWrap(), "wrap policy can be restored on native pane");

        const QString failed = QStringLiteral("transport failed raw_%7\r\n<unaltered>");
        status.setDiagnosticsText(failed, false);
        expect(panes->currentWidget() == raw, "raw diagnostic switches back through explicit text setter");
        copy->click();
        expect(QApplication::clipboard()->text() == failed, "actual copy action preserves raw failure text");
        expect(fields->document().toPlainText(true) == next.toPlainText(true), "raw log updates leave typed model independent");
        status.setDiagnosticsDocument({}, false);
        copy->click();
        expect(QApplication::clipboard()->text().isEmpty(), "empty typed snapshot clears copied content instead of leaking old raw text");
        expect(raw->text() == failed, "empty model is never synthesized as a raw editor report");
        std::printf("PASS actual typed diagnostics drawer: %d checks\n", checks);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAIL typed diagnostics drawer: %s\n", error.what());
        return 1;
    }
}
