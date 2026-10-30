// Actual hardware factory + StructuredFieldView/FieldTreeModel. No native queries.
#include "Ksword5.1/Ksword5.1/UI/StructuredFieldView.h"
#include "Ksword5.1/Ksword5.1/UI/FieldTreeModel.h"
#include "Ksword5.1/Ksword5.1/UI/PrimaryPageStyle.h"
#include "Ksword5.1/Ksword5.1/HardwareDock/HardwareFieldDocuments.h"

#include <QApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QLabel>
#include <QThread>
#include <QThreadPool>
#include <QTimer>
#include <QTreeView>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <cstdio>
#include <cstdlib>
#include <memory>

namespace
{
    int checks = 0;
    void expect(bool condition, const char* label)
    {
        ++checks;
        if (!condition) { std::fprintf(stderr, "HARDWARE_PAGE_FAILURE=%s\n", label); std::exit(1); }
    }
    // Only the external process is replaced; production parsing/status code is extracted verbatim.
    QString queryPowerShellTextSync(const QString& payload, int) { return payload; }
#include "hardware_field_page_actual.inc"

    template<class Predicate> void until(Predicate ready)
    {
        QElapsedTimer timeout;
        timeout.start();
        while (!ready() && timeout.elapsed() < 15000)
        {
            QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
            QThread::msleep(1);
        }
        expect(ready(), "value projection completes without a blocking wait on GUI");
    }
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    ks::ui::StructuredFieldView* editor = nullptr;
    std::unique_ptr<QWidget> page(createReadOnlyFieldPage(nullptr,
        QStringLiteral("USB 设备关系"), QStringLiteral("USB fixture"), &editor));
    expect(editor && !editor->tree() && editor->findChildren<QTreeWidget*>().isEmpty(),
        "ordinary hardware page opts into paged values instead of synchronous native items");
    auto* tree = editor->findChild<QTreeView*>();
    auto* model = tree ? dynamic_cast<ks::ui::FieldTreeModel*>(tree->model()) : nullptr;
    expect(model != nullptr, "hardware factory uses the existing canonical value model");

    const QString diagnostic = QStringLiteral("PowerShell执行超时（10000 ms）。");
    const auto failure = queryPowerShellFieldsSync(diagnostic, 10000);
    expect(failure.nodes.size() == 1 && !failure.nodes.front().initiallyExpanded,
        "collection status starts collapsed");
    expect(failure.toPlainText().contains(diagnostic)
        && failure.toPlainText().contains(QStringLiteral("状态: 失败")),
        "collapsed collection status retains complete failure and diagnostic data");
    const auto empty = queryPowerShellFieldsSync(QStringLiteral("{\"USB连接\":[]}"), 10000);
    expect(empty.nodes.size() == 1 && empty.nodes.front().name == QStringLiteral("USB连接")
        && empty.toPlainText().contains(QStringLiteral("<未检测到>")),
        "successful empty inventory remains distinct from collection failure");

    editor->setDocument(failure);
    page->resize(800, 600);
    page->show();
    until([&] { return model->snapshot() && model->snapshot()->document == failure && tree->isVisible(); });
    expect(!tree->isExpanded(model->index(0, 0)), "first visible collection status is collapsed");
    tree->expand(model->index(0, 0));
    auto changedFailure = failure;
    changedFailure.nodes.front().children.last().value += QStringLiteral(" retry");
    editor->setDocument(changedFailure);
    until([&] { return model->snapshot()->document == changedFailure; });
    expect(tree->isExpanded(model->index(0, 0)), "refresh preserves explicit user expansion");

    ks::ui::FieldDocument large;
    for (int row = 0; row < 1024; ++row)
    {
        large.section(QStringLiteral("USB-risk-%1").arg(row));
        for (int field = 0; field < 13; ++field)
            large.field(QStringLiteral("field-%1").arg(field),
                QStringLiteral("USB-device-%1-field-%2").arg(row).arg(field));
    }
    // Same maximum R0 row count as production, including risk rows retained in the summary.
    int heartbeats = 0;
    QTimer heartbeat;
    heartbeat.setInterval(1);
    QObject::connect(&heartbeat, &QTimer::timeout, &app, [&] { ++heartbeats; });
    heartbeat.start();
    QElapsedTimer synchronous;
    synchronous.start();
    editor->setDocument(large);
    const qint64 submitMs = synchronous.elapsed();
    expect(submitMs < 1000, "large snapshot handoff returns without full GUI tree construction");
    until([&] { return model->snapshot() && model->snapshot()->document == large; });
    expect(heartbeats > 0, "GUI timer runs while preparing the large snapshot");
    expect(model->snapshot()->entries.size() == 1024 * 14,
        "all 1024 rows and 13312 fields survive background preparation");
    const int viewRoots = model->rowCount(); // Qt may request additional pages during layout.
    ks::ui::FieldTreeModel paging;
    paging.applySnapshot(model->snapshot());
    expect(paging.rowCount() == 128 && paging.canFetchMore({}),
        "the canonical model exposes the first bounded page without a view");
    paging.fetchMore({});
    expect(paging.rowCount() == 256 && paging.canFetchMore({}),
        "explicit page requests expose the next bounded batch");
    expect(editor->plainText() == large.toPlainText(true), "complete export source remains canonical");

    editor->setSearchText(QStringLiteral("USB-device-1023-field-12"));
    until([&] { return model->snapshot()->query == QStringLiteral("USB-device-1023-field-12"); });
    expect(model->rowCount() == 1 && model->data(model->index(0, 0), Qt::DisplayRole).toString() == QStringLiteral("USB-risk-1023"),
        "search reaches a record beyond all initially exposed pages");
    editor->setSearchText({});
    until([&] { return model->snapshot()->query.isEmpty(); });
    page->resize(360, 480);
    QCoreApplication::processEvents();
    expect(page->width() == 360, "field toolbar and values permit narrow hardware content");

    page->hide();
    const auto displayed = model->snapshot();
    auto hiddenUpdate = large;
    hiddenUpdate.nodes.last().children.last().value = QStringLiteral("hidden-latest");
    editor->setDocument(hiddenUpdate);
    QCoreApplication::processEvents();
    expect(editor->document() == hiddenUpdate && model->snapshot() == displayed,
        "hidden hardware page retains latest source without rebuilding its projection");
    page->show();
    until([&] { return model->snapshot()->document == hiddenUpdate; });
    expect(editor->plainText().contains(QStringLiteral("hidden-latest")), "reshow publishes latest complete values");

    // Close during pending preparation; the actual weak callback must discard the stale result.
    auto pending = large;
    pending.nodes.front().children.front().value = QStringLiteral("closing");
    editor->setDocument(pending);
    page.reset();
    QThreadPool::globalInstance()->waitForDone();
    QCoreApplication::processEvents();
    std::printf("HARDWARE_PAGE_CHECKS=%d\nHARDWARE_PAGE_FAILURES=0\nHANDOFF_MS=%lld\nHEARTBEATS=%d\nVIEW_ROOTS=%d\n",
        checks, static_cast<long long>(submitMs), heartbeats, viewRoots);
    return 0;
}
