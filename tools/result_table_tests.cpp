// 编译真实生产组件的 Qt 离屏回归，不访问网络、驱动或用户剪贴板。
#include "../Ksword5.1/Ksword5.1/UI/ResultTableHost.h"
#include "../Ksword5.1/Ksword5.1/UI/TableInteractionSupport.h"
#include "../Ksword5.1/Ksword5.1/UI/TableSearchSupport.h"
#include "../Ksword5.1/Ksword5.1/UI/TableHeaderSortingSupport.h"
#include "../Ksword5.1/Ksword5.1/UI/TableFreezeSupport.h"
#include "../Ksword5.1/Ksword5.1/UI/TableSnapshotCompare.h"
#include "../Ksword5.1/Ksword5.1/UI/GlobalUiBaseStyle.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QComboBox>
#include <QContextMenuEvent>
#include <QDir>
#include <QFont>
#include <QHeaderView>
#include <QKeyEvent>
#include <QMenu>
#include <QPushButton>
#include <QSpinBox>
#include <QStandardItemModel>
#include <QTableWidget>
#include <QToolButton>

#include <cstdio>
#include <memory>

namespace
{
    int checks = 0;   // 已执行断言数。
    int failures = 0; // 失败断言数。

    void expect(const bool condition, const char* label)
    {
        ++checks;
        if (!condition)
        {
            ++failures;
            std::printf("RESULT_TABLE_FAILURE=%s\n", label);
        }
    }

    // 排空 queued 释放和回投；固定轮数不依赖机器墙钟延迟。
    void drain()
    {
        for (int iteration = 0; iteration < 8; ++iteration)
        {
            QCoreApplication::sendPostedEvents();
            QCoreApplication::processEvents();
        }
    }

    QToolButton* buttonWithText(QWidget* parent, const QString& text)
    {
        for (QToolButton* const button : parent->findChildren<QToolButton*>())
        {
            if (button->text() == text)
            {
                return button;
            }
        }
        return nullptr;
    }

    QAction* actionWithText(QMenu* menu, const QString& text)
    {
        for (QAction* action : menu->actions()) if (action->text() == text) return action;
        return nullptr;
    }

    // 物理左 Ctrl 探针可控，其余使用真实 Qt 视图和生产提交协调器。
    void checkCoordinator(QApplication& application)
    {
        bool leftCtrl = false;
        ks::ui::UiCommitInteractionProbes probes;
        probes.leftCtrlHeld = [&leftCtrl]() { return leftCtrl; };
        ks::ui::UiCommitCoordinator coordinator(&application, probes);
        QObject owner;
        QTableWidget tcp;
        QTableWidget udp;
        int value = 0;
        const QList<QAbstractItemView*> views = {&tcp, &udp};
        expect(coordinator.submit(&owner, QStringLiteral("immediate"), views,
            [&value]() { value = 1; }) == ks::ui::UiCommitSubmission::Executed,
            "ordinary commit executes immediately");
        expect(value == 1 && coordinator.pendingCount() == 0, "immediate queue is empty");
        expect(coordinator.submit(nullptr, QStringLiteral("invalid"), views, []() {})
            == ks::ui::UiCommitSubmission::Rejected, "missing owner rejected");

        coordinator.beginContextMenu(&udp);
        expect(coordinator.isBlocked(views), "second table blocks whole group");
        coordinator.submit(&owner, QStringLiteral("snapshot"), views, [&value]() { value = 2; });
        coordinator.submit(&owner, QStringLiteral("snapshot"), views, [&value]() { value = 3; });
        expect(coordinator.pendingCount() == 1 && value == 1, "same key keeps latest only");
        coordinator.endContextMenu(&udp);
        expect(value == 1, "menu end waits for outer event loop");
        drain();
        expect(value == 3 && coordinator.pendingCount() == 0, "latest atomic snapshot released");

        coordinator.beginContextMenu(&tcp);
        coordinator.beginContextMenu(&tcp);
        coordinator.submit(&owner, QStringLiteral("nested"), views, [&value]() { value = 4; });
        coordinator.endContextMenu(&tcp);
        drain();
        expect(value == 3 && coordinator.pendingCount() == 1, "nested menu retains barrier");
        coordinator.endContextMenu(&tcp);
        drain();
        expect(value == 4, "last menu release flushes once");

        // owner 销毁不仅阻止执行，还立即释放被 std::function 捕获的快照。
        leftCtrl = true;
        auto* doomedOwner = new QObject;
        auto payload = std::make_shared<int>(9);
        std::weak_ptr<int> weakPayload = payload;
        coordinator.submit(doomedOwner, QStringLiteral("owner"), views,
            [payload, &value]() { value = *payload; });
        payload.reset();
        delete doomedOwner;
        expect(weakPayload.expired() && coordinator.pendingCount() == 0,
            "owner destruction releases pending payload");

        auto* doomedView = new QTableWidget;
        coordinator.submit(&owner, QStringLiteral("target"), {&tcp, doomedView},
            [&value]() { value = 10; });
        delete doomedView;
        leftCtrl = false;
        coordinator.flush();
        expect(value == 4 && coordinator.pendingCount() == 0,
            "partial target destruction cancels atomic commit");

        leftCtrl = true;
        coordinator.submit(&owner, QStringLiteral("ctrl"), views, [&value]() { value = 5; });
        QKeyEvent release(QEvent::KeyRelease, Qt::Key_Control, Qt::NoModifier);
        QApplication::sendEvent(&tcp, &release);
        drain();
        expect(value == 4, "release hint rechecks physical left Ctrl");
        leftCtrl = false;
        QApplication::sendEvent(&tcp, &release);
        drain();
        expect(value == 5, "left Ctrl release flushes pending result");

        // 丢失释放事件时，新立即结果先淘汰同键旧结果，之后 flush 不可倒退。
        leftCtrl = true;
        coordinator.submit(&owner, QStringLiteral("fresh"), views, [&value]() { value = 6; });
        leftCtrl = false;
        coordinator.submit(&owner, QStringLiteral("fresh"), views, [&value]() { value = 7; });
        coordinator.flush();
        expect(value == 7 && coordinator.pendingCount() == 0,
            "fresh immediate result supersedes older queued result");

        QComboBox combo;
        combo.addItems({QStringLiteral("a"), QStringLiteral("b")});
        combo.show();
        combo.showPopup();
        drain();
        expect(coordinator.isBlocked(views), "actual combo popup blocks commit");
        coordinator.submit(&owner, QStringLiteral("popup"), views, [&value]() { value = 8; });
        combo.hidePopup();
        drain();
        expect(value == 8 && coordinator.pendingCount() == 0,
            "actual combo popup hide flushes commit");
        combo.hide();

        // 用户回调可再次打开菜单，后续记录必须重新检查屏障。
        leftCtrl = true;
        coordinator.submit(&owner, QStringLiteral("first"), views, [&coordinator, &tcp]()
        {
            coordinator.beginContextMenu(&tcp);
        });
        coordinator.submit(&owner, QStringLiteral("second"), views, [&value]() { value = 11; });
        leftCtrl = false;
        coordinator.flush();
        expect(value == 8 && coordinator.pendingCount() == 1, "reentrant callback rechecks barrier");
        coordinator.endContextMenu(&tcp);
        drain();
        expect(value == 11, "reentrant menu finally releases second commit");

        // 在同一次 submit 中输入状态只查询一次，防止查询间松键造成回调被移动后丢失。
        int probeReads = 0;
        ks::ui::UiCommitInteractionProbes changingProbes;
        changingProbes.leftCtrlHeld = [&probeReads]() { return ++probeReads == 1; };
        ks::ui::UiCommitCoordinator changingCoordinator(&application, changingProbes);
        expect(changingCoordinator.submit(&owner, QStringLiteral("changing"), views,
            [&value]() { value = 12; }) == ks::ui::UiCommitSubmission::Deferred,
            "changing physical state still retains callback");
        expect(probeReads == 1 && changingCoordinator.pendingCount() == 1,
            "submission reads physical barrier exactly once");
        changingCoordinator.flush();
        expect(value == 12, "retained callback executes after state changes");

        // 回调主动关闭协调器时，flush 不可继续访问被释放的队列。
        leftCtrl = true;
        auto* disposable = new ks::ui::UiCommitCoordinator(&application, probes);
        const QPointer<ks::ui::UiCommitCoordinator> disposableGuard(disposable);
        disposable->submit(&owner, QStringLiteral("self"), views, [disposable]() { delete disposable; });
        leftCtrl = false;
        disposable->flush();
        expect(disposableGuard.isNull(), "callback may destroy coordinator without use after free");
    }

    // 生产全局安装仍发现动态表，并复用同一个宿主、操作条和搜索控制器。
    void checkHosts(QApplication& application)
    {
        ks::ui::InstallGlobalTableInteractionSupport(&application);
        ks::ui::VisibleTableWidget table;
        table.setColumnCount(2);
        table.setRowCount(2);
        table.setItem(0, 0, new QTableWidgetItem(QStringLiteral("z")));
        table.setItem(1, 0, new QTableWidgetItem(QStringLiteral("a")));
        table.show();
        drain();
        auto* const host = ks::ui::ResultTableHost::ensure(&table);
        expect(host == ks::ui::ResultTableHost::ensure(&table), "host installation is idempotent");
        expect(host->model() == table.model(), "dynamic legacy model is bound");
        expect(table.contextMenuPolicy() == Qt::DefaultContextMenu,
            "global discovery does not steal business context menu");
        expect(!table.isSortingEnabled(), "one shot sorting does not enable live sorting");
        expect(table.findChildren<QObject*>(QStringLiteral("KSWORD_TABLE_INTERACTION_ACTION_BAR")).size() == 1,
            "dynamic table has one action bar");
        expect(host->bindModel(table.model(), {{0, QStringLiteral("name")}, {1, QStringLiteral("pid")}}),
            "explicit column schema accepted");
        table.horizontalHeader()->setSectionsMovable(true);
        table.horizontalHeader()->moveSection(0, 1);
        expect(host->stableColumnId(0) == QStringLiteral("name"), "header move retains stable column identity");
        expect(!host->bindModel(table.model(), {{0, QStringLiteral("same")}, {1, QStringLiteral("same")}}),
            "duplicate stable column identity rejected");
        expect(host->stableColumnId(0) == QStringLiteral("name"), "failed schema leaves old binding intact");
        QObject groupOwner;
        bool partialApplied = false;
        expect(ks::ui::ResultTableHost::submitGroup(&groupOwner, QStringLiteral("missing"), {host, nullptr},
            [&partialApplied]() { partialApplied = true; }) == ks::ui::UiCommitSubmission::Rejected
            && !partialApplied, "missing grouped target rejects atomic submission");

        QStandardItemModel foreignModel(1, 2);
        expect(!host->bindModel(&foreignModel, {{0, QStringLiteral("foreign")}}),
            "QTableWidget internal model cannot be replaced");
        QMetaObject::invokeMethod(table.horizontalHeader(), "sectionClicked", Q_ARG(int, 0));
        expect(table.item(0, 0)->text() == QStringLiteral("a") && !table.isSortingEnabled(),
            "actual header click performs one shot sorting");
        table.setItem(0, 1, new QTableWidgetItem(QStringLiteral("refresh")));
        expect(!table.horizontalHeader()->isSortIndicatorShown(), "refill invalidates manual sorting arrow");

        // 保留既有表头样式例外与窄表动作条降级，不让新宿主强行升级。
        ks::ui::VisibleTableWidget compact;
        compact.setColumnCount(1);
        ks::ui::SetTableActionBarMode(&compact, ks::ui::TableActionBarMode::Compact);
        ks::ui::SetPreserveCustomTableHeaderStyle(&compact, true);
        compact.horizontalHeader()->setStyleSheet(QStringLiteral("QHeaderView{padding:9px;}"));
        compact.show();
        drain();
        expect(ks::ui::EffectiveTableActionBarMode(&compact) == ks::ui::TableActionBarMode::Compact,
            "legacy compact action bar preserved");
        expect(compact.horizontalHeader()->styleSheet() == QStringLiteral("QHeaderView{padding:9px;}"),
            "professional custom header style preserved");

        ks::ui::VisibleTableWidget displayOnly;
        displayOnly.setColumnCount(1);
        ks::ui::SetTableActionBarMode(&displayOnly, ks::ui::TableActionBarMode::None);
        displayOnly.show();
        drain();
        expect(displayOnly.topActionBarHeight() == 0, "legacy no action bar preserved");

        QToolButton* const pause = buttonWithText(&table, QStringLiteral("冻结视图"));
        QToolButton* const snapshot = buttonWithText(&table, QStringLiteral("增加快照"));
        expect(pause != nullptr && snapshot != nullptr, "real pause and snapshot controls retained");
        if (pause != nullptr)
        {
            pause->click();
            drain();
            expect(pause->isChecked(), "production paused view opens");
            pause->click();
            drain();
            expect(!pause->isChecked(), "production paused view resumes");
        }
        if (snapshot != nullptr)
        {
            snapshot->click();
            drain();
            snapshot->click();
            drain();
            expect(buttonWithText(&table, QStringLiteral("清理")) != nullptr,
                "production snapshot controls retained");
        }
    }

    void checkFreezeMenu(QApplication& application, const QString& output)
    {
        ks::ui::VisibleTableWidget table;
        table.setColumnCount(4);
        table.setRowCount(12);
        table.setHorizontalHeaderLabels({QStringLiteral("Name"), QStringLiteral("PID"),
            QStringLiteral("State"), QStringLiteral("Location")});
        table.setSelectionBehavior(QAbstractItemView::SelectRows);
        table.setSelectionMode(QAbstractItemView::ExtendedSelection);
        for (int row = 0; row < table.rowCount(); ++row)
            for (int column = 0; column < table.columnCount(); ++column)
                table.setItem(row, column, new QTableWidgetItem(QStringLiteral("row%1 value%2").arg(row).arg(column)));
        for (int column = 0; column < table.columnCount(); ++column) table.setColumnWidth(column, 140);
        table.resize(1200, 620);
        table.show();
        drain();
        auto* freeze = table.findChild<QToolButton*>(QStringLiteral("ksword_table_freeze_button"));
        expect(freeze != nullptr && freeze->text() == QStringLiteral("冻结")
            && freeze->toolButtonStyle() == Qt::ToolButtonTextOnly && freeze->height() >= 28,
            "one normal-sized labelled freeze entry is visible");
        if (freeze == nullptr || freeze->menu() == nullptr) return;
        QMenu* menu = freeze->menu();
        auto* rows = menu->findChild<QSpinBox*>(QStringLiteral("ksword_table_freeze_row_count"));
        auto* columns = menu->findChild<QSpinBox*>(QStringLiteral("ksword_table_freeze_column_count"));
        auto* apply = menu->findChild<QPushButton*>(QStringLiteral("ksword_table_apply_freeze_counts"));
        expect(rows != nullptr && columns != nullptr && apply != nullptr && !rows->isVisible() && !columns->isVisible(),
            "row-column settings live in the freeze menu instead of the table bar");
        if (rows == nullptr || columns == nullptr || apply == nullptr) return;
        auto* clearRows = actionWithText(menu, QStringLiteral("取消冻结行"));
        auto* clearColumns = actionWithText(menu, QStringLiteral("取消冻结列"));
        auto* clearAll = actionWithText(menu, QStringLiteral("取消全部冻结"));
        auto* selectedRows = actionWithText(menu, QStringLiteral("冻结选中行"));
        expect(clearRows && clearColumns && clearAll && selectedRows
            && actionWithText(menu, QStringLiteral("冻结选中列"))
            && actionWithText(menu, QStringLiteral("冻结选中行列")),
            "every existing selected-row-column and unfreeze action remains available");
        if (!clearRows || !clearColumns || !clearAll || !selectedRows) return;

        table.setRowHidden(0, true);
        table.setColumnHidden(1, true);
        table.horizontalHeader()->setSectionsMovable(true);
        table.horizontalHeader()->moveSection(3, 0);
        menu->popup(freeze->mapToGlobal(QPoint(0, freeze->height())));
        drain();
        expect(menu->isVisible() && rows->maximum() == 12 && columns->maximum() == 4,
            "menu exposes complete row and column count ranges");
        QObject owner;
        int committed = 0;
        auto* coordinator = ks::ui::UiCommitCoordinator::forApplication(&application);
        expect(coordinator->submit(&owner, QStringLiteral("freeze-menu"), {&table}, [&committed]() { ++committed; })
            == ks::ui::UiCommitSubmission::Deferred && committed == 0,
            "freeze settings menu protects the source model with the existing commit barrier");
        rows->setValue(2);
        columns->setValue(1);
        apply->click();
        expect(committed == 0, "freeze apply retains commit barrier until its callback returns");
        drain();
        expect(committed == 1 && !menu->isVisible(), "menu close releases the deferred commit once");
        expect(ks::ui::isRowHiddenByFreeze(&table, 1) && ks::ui::isRowHiddenByFreeze(&table, 2)
            && ks::ui::isColumnHiddenByFreeze(&table, 3),
            "counts freeze the first visible sections in current visual order");
        expect(table.isRowHidden(0) && table.isColumnHidden(1)
            && !ks::ui::isRowHiddenByFreeze(&table, 0) && !ks::ui::isColumnHiddenByFreeze(&table, 1),
            "count operations preserve business-hidden rows and columns");
        expect(freeze->property("ksword_frozen_rows").toInt() == 2
            && freeze->property("ksword_frozen_columns").toInt() == 1
            && freeze->text() == QStringLiteral("冻结（2 行 / 1 列）"),
            "freeze entry reports the actual row and column state");
        const auto snapshot = ks::ui::TableSnapshotCompareEngine::capture(&table, QStringLiteral("frozen"), 1);
        expect(snapshot.rows.size() == 11 && snapshot.visibleColumns.size() == 3
            && snapshot.visibleColumns.front().sourceColumn == 3,
            "snapshot capture retains frozen sections and current visual order");

        if (!output.isEmpty())
        {
            expect(table.grab().save(QDir(output).filePath(QStringLiteral("table-freeze-light.png"))),
                "actual freeze toolbar light screenshot saved");
            menu->popup(freeze->mapToGlobal(QPoint(0, freeze->height())));
            drain();
            expect(menu->grab().save(QDir(output).filePath(QStringLiteral("table-freeze-menu-light.png"))),
                "actual freeze count menu screenshot saved");
            menu->hide(); drain();
            const QPalette oldPalette = application.palette();
            KswordTheme::SetDarkModeEnabled(true);
            QPalette dark = oldPalette;
            dark.setColor(QPalette::Window, KswordTheme::MainBackgroundColor());
            dark.setColor(QPalette::Base, KswordTheme::SurfaceColor());
            dark.setColor(QPalette::Button, KswordTheme::SurfaceAltColor());
            dark.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
            for (const auto role : {QPalette::Text, QPalette::WindowText, QPalette::ButtonText}) dark.setColor(role, KswordTheme::TextPrimaryColor());
            dark.setColor(QPalette::Mid, KswordTheme::BorderColor());
            dark.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
            dark.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
            dark.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor(KswordTheme::ControlAccentColor()));
            application.setPalette(dark);
            application.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
            drain();
            expect(table.palette().color(QPalette::Text).rgba() == dark.color(QPalette::Text).rgba(),
                "actual global theme refresh updates the source table text palette");
            for (QTableView* pane : table.findChildren<QTableView*>())
                if (pane->property("KSWORD_TABLE_INTERACTION_FROZEN_PANE_AUXILIARY").toBool())
                    expect(pane->palette().color(QPalette::Text).rgba() == table.palette().color(QPalette::Text).rgba()
                        && pane->viewport()->palette().color(QPalette::Base).rgba() == table.viewport()->palette().color(QPalette::Base).rgba(),
                        "frozen pane mirrors the current source theme palette");
            expect(table.grab().save(QDir(output).filePath(QStringLiteral("table-freeze-dark.png"))),
                "actual freeze toolbar follows a hot dark palette");
            menu->popup(freeze->mapToGlobal(QPoint(0, freeze->height()))); drain();
            expect(menu->grab().toImage().pixelColor(3, menu->height() - 3).rgba() == KswordTheme::SurfaceColor().rgba(),
                "freeze popup refreshes its sampled surface color when reopened after hot theme change");
            expect(menu->grab().save(QDir(output).filePath(QStringLiteral("table-freeze-menu-dark.png"))),
                "actual freeze count menu follows a hot dark palette");
            menu->hide(); drain();
            KswordTheme::SetDarkModeEnabled(false);
            application.setPalette(oldPalette);
            application.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
            drain();
        }

        menu->popup(freeze->mapToGlobal(QPoint(0, freeze->height()))); drain();
        expect(rows->value() == 2 && columns->value() == 1, "menu count defaults follow actual frozen state");
        clearRows->trigger(); menu->hide(); drain();
        expect(!ks::ui::isRowHiddenByFreeze(&table, 1) && !ks::ui::isRowHiddenByFreeze(&table, 2)
            && freeze->property("ksword_frozen_rows").toInt() == 0
            && freeze->property("ksword_frozen_columns").toInt() == 1,
            "unfreeze rows keeps the frozen column and updates the entry immediately");
        clearAll->trigger(); drain();
        expect(freeze->text() == QStringLiteral("冻结") && table.isRowHidden(0) && table.isColumnHidden(1),
            "unfreeze all restores the idle label without exposing business-hidden sections");
        table.setCurrentCell(2, 0);
        table.selectRow(2);
        table.selectionModel()->select(table.model()->index(4, 0), QItemSelectionModel::Select | QItemSelectionModel::Rows);
        menu->popup(freeze->mapToGlobal(QPoint(0, freeze->height()))); drain();
        selectedRows->trigger(); menu->hide(); drain();
        expect(ks::ui::isRowHiddenByFreeze(&table, 2) && ks::ui::isRowHiddenByFreeze(&table, 4),
            "existing multi-selection freeze behavior is preserved");
        table.removeRow(2); drain();
        expect(freeze->property("ksword_frozen_rows").toInt() == 1,
            "model row deletion updates the visible freeze count without reopening the menu");
        clearAll->trigger(); drain();
        menu->popup(freeze->mapToGlobal(QPoint(0, freeze->height()))); drain();
        rows->setValue(rows->maximum()); columns->setValue(0); apply->click(); drain();
        expect(freeze->property("ksword_frozen_rows").toInt() > 0
            && freeze->property("ksword_frozen_rows").toInt() < table.rowCount() - 1 && table.viewport()->height() > 0,
            "the original half-viewport freeze budget remains effective");
        clearAll->trigger(); drain();
        auto* pause = buttonWithText(&table, QStringLiteral("冻结视图"));
        expect(pause != nullptr && pause->isEnabled(), "view pause remains a separate labelled capability");
        if (pause != nullptr)
        {
            pause->click(); drain();
            menu->popup(freeze->mapToGlobal(QPoint(0, freeze->height()))); drain();
            rows->setValue(1); columns->setValue(1); apply->click(); drain();
            expect(pause->isChecked() && freeze->property("ksword_frozen_rows").toInt() == 1
                && freeze->property("ksword_frozen_columns").toInt() == 1,
                "row-column count settings also operate on the actual paused view");
            pause->click(); drain();
            expect(!pause->isChecked() && freeze->text() == QStringLiteral("冻结"),
                "resuming the live view clears the paused pane count coherently");
        }
    }

    void checkFreezeMenuLifetime(QApplication& application)
    {
        QObject owner;
        int unexpectedCommits = 0;
        auto* coordinator = ks::ui::UiCommitCoordinator::forApplication(&application);
        for (int iteration = 0; iteration < 8; ++iteration)
        {
            auto* table = new ks::ui::VisibleTableWidget;
            table->setRowCount(4); table->setColumnCount(2);
            table->resize(1100, 380); table->show(); drain();
            auto* freeze = table->findChild<QToolButton*>(QStringLiteral("ksword_table_freeze_button"));
            expect(freeze != nullptr && freeze->menu() != nullptr, "lifetime fixture has the actual freeze menu");
            if (freeze == nullptr || freeze->menu() == nullptr) { delete table; continue; }
            freeze->menu()->popup(freeze->mapToGlobal(QPoint(0, freeze->height()))); drain();
            coordinator->submit(&owner, QStringLiteral("destroy-open-freeze"), {table},
                [&unexpectedCommits]() { ++unexpectedCommits; });
            const QPointer<ks::ui::VisibleTableWidget> guard(table);
            delete table; drain();
            expect(guard.isNull() && coordinator->pendingCount() == 0 && unexpectedCommits == 0,
                "destroying an open freeze menu cancels its deferred source commit safely");
        }
    }

    void checkModelRebinding()
    {
        ks::ui::TableActionTableView table;
        QStandardItemModel oldModel(3, 1);
        oldModel.setItem(0, new QStandardItem(QStringLiteral("keep")));
        oldModel.setItem(1, new QStandardItem(QStringLiteral("drop")));
        oldModel.setItem(2, new QStandardItem(QStringLiteral("keep")));
        QStandardItemModel newModel(2, 1);
        newModel.setItem(0, new QStandardItem(QStringLiteral("drop")));
        newModel.setItem(1, new QStandardItem(QStringLiteral("keep")));
        auto* const host = ks::ui::ResultTableHost::ensure(&table);
        expect(host->bindModel(&oldModel, {{0, QStringLiteral("name")}}), "first view model bound");
        table.setRowHidden(2, true);
        expect(ks::ui::ApplyTableSearchResultFilter(&table, QStringLiteral("keep")), "production search filter active");
        expect(!table.isRowHidden(0) && table.isRowHidden(1) && table.isRowHidden(2),
            "search respects existing hidden row baseline");
        expect(host->bindModel(&newModel, {{0, QStringLiteral("name")}}), "replacement model bound");
        drain();
        expect(host->model() == &newModel && table.isRowHidden(0) && !table.isRowHidden(1),
            "original query reapplied to replacement model");
        oldModel.setData(oldModel.index(0, 0), QStringLiteral("drop"));
        oldModel.removeRow(0);
        drain();
        expect(table.isRowHidden(0) && !table.isRowHidden(1), "old model signals cannot alter new view");
        newModel.setData(newModel.index(0, 0), QStringLiteral("keep"));
        drain();
        expect(!table.isRowHidden(0), "new model data change rechecks search query");
        newModel.clear();
        newModel.setColumnCount(1);
        newModel.setRowCount(2);
        newModel.setItem(0, new QStandardItem(QStringLiteral("keep")));
        newModel.setItem(1, new QStandardItem(QStringLiteral("drop")));
        drain();
        expect(!table.isRowHidden(0) && table.isRowHidden(1), "new model reset retains query");
        ks::ui::ClearTableSearchResultFilter(&table);
        expect(!table.isRowHidden(0) && !table.isRowHidden(1), "clear restores replacement baseline");

        // 精确覆盖旧结构变化已排队但尚未回投，随后换绑并清空新模型过滤。
        QStandardItemModel queuedOld(2, 1);
        queuedOld.setItem(0, new QStandardItem(QStringLiteral("keep")));
        queuedOld.setItem(1, new QStandardItem(QStringLiteral("drop")));
        host->bindModel(&queuedOld, {{0, QStringLiteral("name")}});
        ks::ui::ApplyTableSearchResultFilter(&table, QStringLiteral("keep"));
        queuedOld.insertRow(0, new QStandardItem(QStringLiteral("drop")));
        host->bindModel(&newModel, {{0, QStringLiteral("name")}});
        drain();
        ks::ui::ClearTableSearchResultFilter(&table);
        expect(!table.isRowHidden(0) && !table.isRowHidden(1),
            "queued old mutation cannot poison replacement hidden baseline");
    }

    // 真实 QMenu Show/Hide 由旧全局来源过滤器识别，再交给新协调器计数释放。
    void checkNativeMenus()
    {
        ks::ui::VisibleTableWidget tcp;
        ks::ui::VisibleTableWidget udp;
        tcp.setColumnCount(1);
        udp.setColumnCount(1);
        tcp.setRowCount(1);
        udp.setRowCount(1);
        tcp.setContextMenuPolicy(Qt::CustomContextMenu);
        QMenu menu(&tcp);
        menu.addAction(QStringLiteral("fixture"));
        QObject::connect(&tcp, &QWidget::customContextMenuRequested, &tcp, [&menu](const QPoint& point)
        {
            menu.popup(point);
        });
        tcp.show();
        udp.show();
        drain();
        QContextMenuEvent context(QContextMenuEvent::Mouse, QPoint(3, 3), tcp.mapToGlobal(QPoint(3, 3)));
        QApplication::sendEvent(tcp.viewport(), &context);
        drain();
        auto* const tcpHost = ks::ui::ResultTableHost::ensure(&tcp);
        auto* const udpHost = ks::ui::ResultTableHost::ensure(&udp);
        const QList<ks::ui::ResultTableHost*> hosts = {tcpHost, udpHost};
        expect(menu.isVisible() && ks::ui::ResultTableHost::isGroupCommitBlocked(hosts),
            "actual business menu activates new coordinator");
        QObject owner;
        int value = 0;
        ks::ui::DeferTableUiCommitIfContextMenuOpen(&owner, QStringLiteral("pair"), {&tcp, &udp},
            [&value]() { value = 1; });
        ks::ui::ResultTableHost::submitGroup(&owner, QStringLiteral("pair"), hosts,
            [&tcp, &udp, &value]()
            {
                tcp.setItem(0, 0, new QTableWidgetItem(QStringLiteral("tcp")));
                udp.setItem(0, 0, new QTableWidgetItem(QStringLiteral("udp")));
                value = 2;
            });
        expect(value == 0, "legacy and new API share same menu barrier");
        menu.hide();
        expect(value == 0, "native menu hide retains barrier until callback returns");
        drain();
        expect(value == 2 && tcp.item(0, 0) != nullptr && udp.item(0, 0) != nullptr,
            "actual paired tables atomically receive latest snapshot");
    }
}

// 标题栏搜索路由不属于本组件范围；只替换这个外部入口，搜索控制器本身是生产代码。
namespace ks::ui
{
    void ActivateGlobalUiSearchForTable(QTableView*, const QString&, bool)
    {
    }
}

int main(int argc, char* argv[])
{
    QApplication application(argc, argv);
    application.setStyle(QStringLiteral("Fusion"));
    application.setFont(QFont(QStringLiteral("Microsoft YaHei UI"), 10));
    application.setStyleSheet(ks::ui::BuildGlobalBaseControlStyleBlock());
    const QString output = argc > 1 ? QString::fromLocal8Bit(argv[1]) : QString();
    if (!output.isEmpty()) QDir().mkpath(output);
    checkCoordinator(application);
    checkHosts(application);
    checkModelRebinding();
    checkNativeMenus();
    checkFreezeMenu(application, output);
    checkFreezeMenuLifetime(application);
    drain();
    std::printf("RESULT_TABLE_CHECKS=%d\nRESULT_TABLE_FAILURES=%d\n", checks, failures);
    return failures == 0 ? 0 : 1;
}
