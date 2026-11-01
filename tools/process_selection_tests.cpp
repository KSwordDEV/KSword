// Production selection methods/restore block are inserted unchanged by the runner.
// Real Qt view, selection model, sort proxy and FlatTableModel; no process APIs.
#include "FlatTableModel.h"
#include <QApplication>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QTableView>
#include <QtTest/QTest>
#include <algorithm>
#include <cstdio>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

struct ProcessDock
{
    enum class ProcessTableRowKind { Process, GroupHeader, ApplicationAggregate };
    enum class TableColumn { Name, Cpu, Memory, Count };
    struct ProcessTableRow {
        std::string identityKey;
        ProcessTableRowKind rowKind = ProcessTableRowKind::Process;
        QString expansionKey;
        std::vector<std::string> actionIdentityKeys;
        int value = 0;
    };
    using ProcessTableModel = ks::ui::FlatTableModel<ProcessTableRow>;
    QTableView view;
    QSortFilterProxyModel proxy;
    ProcessTableModel model;
    QTableView* m_processTable = &view;
    QSortFilterProxyModel* m_processSortProxy = &proxy;
    ProcessTableModel* m_processTableModel = &model;
    std::string m_trackedSelectedIdentityKey, m_contextActionIdentityKey;
    std::vector<std::string> m_trackedSelectedIdentityKeys;
    int m_trackedSelectedColumn = 0;
    std::unordered_map<std::string, int> m_cacheByIdentity;
    bool historical = false, m_contextMenuVisible = false;
    bool isProcessActivityTableSnapshotActive() const { return historical; }
    QString currentProcessSearchText() const { return {}; }
    __METHODS__
    explicit ProcessDock(bool reset)
        : model({{QStringLiteral("name")}, {QStringLiteral("cpu")}, {QStringLiteral("memory")}},
            [](const ProcessTableRow& row, int column, int role) -> QVariant {
                if (role != Qt::DisplayRole) return {};
                return column == 0 ? QVariant(QString::fromStdString(row.identityKey) + row.expansionKey)
                    : QVariant(row.value);
            }, nullptr, [](const ProcessTableRow& row, int) {
                return row.rowKind == ProcessTableRowKind::GroupHeader ? Qt::ItemIsEnabled
                    : Qt::ItemIsEnabled | Qt::ItemIsSelectable;
            }, reset ? ProcessTableModel::KeyResolver{} : ProcessTableModel::KeyResolver{
                [](const ProcessTableRow& row) {
                    return std::to_string(static_cast<int>(row.rowKind)) + ":" + row.identityKey
                        + row.expansionKey.toStdString();
                }}, [](const ProcessTableRow& before, const ProcessTableRow& after) {
                return before.value == after.value ? std::vector<ProcessTableModel::ColumnChange>{}
                    : std::vector<ProcessTableModel::ColumnChange>{{1, 2, {Qt::DisplayRole}}};
            })
    {
        proxy.setDynamicSortFilter(false);
        proxy.setSourceModel(&model);
        view.setModel(&proxy);
        view.setSelectionBehavior(QAbstractItemView::SelectRows);
        view.setSelectionMode(QAbstractItemView::ExtendedSelection);
        view.setAttribute(Qt::WA_DontShowOnScreen);
        view.resize(650, 400);
        QObject::connect(view.selectionModel(), &QItemSelectionModel::selectionChanged, &view,
            [this] { syncTrackedSelectionFromTable(); });
        QObject::connect(view.selectionModel(), &QItemSelectionModel::currentChanged, &view,
            [this](const QModelIndex& current) {
                if (current.isValid()) m_trackedSelectedColumn = current.column();
                syncTrackedSelectionFromTable();
            });
        view.show();
    }
    void update(std::vector<ProcessTableRow> rows, int sortColumn = -1)
    {
        __CAPTURE__
        QSignalBlocker blocker(view.selectionModel());
        const auto modelUpdateStats = model.setRows(std::move(rows));
        proxy.sort(sortColumn, Qt::DescendingOrder);
        __RESTORE__
        QApplication::processEvents();
    }
    void click(int sourceRow, Qt::KeyboardModifiers modifiers = Qt::NoModifier)
    {
        const auto index = proxy.mapFromSource(model.index(sourceRow, 1));
        QTest::mouseClick(view.viewport(), Qt::LeftButton, modifiers, view.visualRect(index).center());
        QApplication::processEvents();
    }
};

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    using Row = ProcessDock::ProcessTableRow;
    using Kind = ProcessDock::ProcessTableRowKind;
    int checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* label) {
        ++checks;
        if (!ok) { ++failures; std::printf("PROCESS_SELECTION_FAIL=%s\n", label); }
    };
    const Row aggregate{"", Kind::ApplicationAggregate, QStringLiteral("application:browser"), {"10:100", "20:200"}, 20};
    const Row process{"30:300", Kind::Process, {}, {}, 10};
    const Row group{"", Kind::GroupHeader, QStringLiteral("group:apps"), {}, 0};
    for (bool reset : {false, true})
    for (bool history : {false, true})
    {
        ProcessDock dock(reset);
        dock.historical = history;
        std::vector<Row> rows{group, aggregate, process};
        dock.update(rows);
        dock.click(1);
        check(dock.view.selectionModel()->selectedRows().size() == 1, "left click selects application parent");
        check(dock.currentProcessActivitySelectionKeys().size() == 2, "activity chart follows selected parent members");
        for (int round = 0; round < 8; ++round)
        {
            rows[1].value = round % 2 ? 3 : 50;
            rows[2].value = 60 - round;
            dock.update(rows, round % 2 ? 1 : -1);
            auto selected = dock.view.selectionModel()->selectedRows();
            check(selected.size() == 1 && dock.processTableRowForViewIndex(selected.first())->rowKind == Kind::ApplicationAggregate,
                "numeric refresh/resort retains application parent");
            check(dock.currentProcessActivitySelectionKeys() == aggregate.actionIdentityKeys,
                "numeric refresh keeps activity chart target");
            check(dock.view.currentIndex().column() == 1, "refresh retains clicked column");
        }
        dock.click(2, Qt::ControlModifier);
        check(dock.view.selectionModel()->selectedRows().size() == 2, "Ctrl adds concrete process to parent selection");
        rows[2].value = 80;
        dock.update(rows, 1);
        check(dock.view.selectionModel()->selectedRows().size() == 2, "mixed multi-selection survives numeric refresh");
        check(dock.currentProcessActivitySelectionKeys().size() == 3, "mixed chart selection retains all process identities");
        dock.click(2);
        rows[2].value = 90;
        dock.update(rows, 1);
        check(dock.currentProcessActivitySelectionKeys() == std::vector<std::string>{process.identityKey},
            "single concrete process survives numeric refresh");
        rows[2].identityKey = "30:999";
        dock.update(rows, 1);
        check(dock.view.selectionModel()->selectedRows().empty(), "reused PID never inherits selection");
        check(!dock.view.currentIndex().isValid(), "removed identity clears fallback current target");
        dock.click(1);
        rows.erase(rows.begin() + 1);
        dock.update(rows);
        check(dock.view.selectionModel()->selectedRows().empty(), "removed parent clears selection");
    }
    std::printf("PROCESS_SELECTION_CHECKS=%d\nPROCESS_SELECTION_FAILURES=%d\n", checks, failures);
    return failures ? 1 : 0;
}
