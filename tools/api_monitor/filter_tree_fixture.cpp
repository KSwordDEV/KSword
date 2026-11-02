#include "MonitorDock/WinAPIFilterCatalog.h"
#include <QApplication>
#include <QElapsedTimer>
#include <QLabel>
#include <QLineEdit>
#include <QSignalBlocker>
#include <QTemporaryDir>
#include <QTimer>
#include <QTreeWidget>
#include <deque>
#include <iostream>

class WinAPIEventTableModel { public: void setEventRules(std::shared_ptr<const ks::monitor::WinAPIFilterSnapshot>) {} };
class WinAPIDock : public QWidget {
public:
    QTreeWidget* m_eventRulesTree = nullptr;
    QLineEdit* m_ruleSearchEdit = nullptr;
    QLabel* m_eventRulesStatus = nullptr;
    std::shared_ptr<ks::monitor::WinAPIFilterRules> m_eventRules;
    WinAPIEventTableModel* m_eventModel = nullptr;
    bool m_eventRulesValid = true, m_eventRulesPreStage = true, m_ruleCatalogPumpScheduled = false, m_ruleDefinitionsUnavailable = false;
    bool m_ruleSearchScheduled = false, m_ruleSearchActive = false, m_ruleStateScheduled = false;
    QHash<QString, QTreeWidgetItem*> m_ruleModules, m_ruleFunctions, m_ruleCategories;
    QList<QTreeWidgetItem*> m_ruleSearchItems, m_ruleStateItems;
    QSet<QString> m_ruleExpandedBeforeSearch;
    QString m_ruleSearchText;
    qsizetype m_ruleSearchCursor = 0, m_ruleStateCursor = 0;
    std::deque<std::pair<std::shared_ptr<const ks::monitor::WinAPIFilterCatalog>, std::size_t>> m_ruleCatalogBatches;
    void refreshEventRulesPanel();
    void eventRulesChanged();
    void applyVisibleEventRules(bool, bool);
    void refreshEventRuleItem(const QString&, const QString&, const QString& = {});
    void queueEventRuleCatalog(std::shared_ptr<const ks::monitor::WinAPIFilterCatalog>);
    void pumpEventRuleCatalog();
    void pumpEventRuleStates();
    void scheduleEventRuleSearch();
    void pumpEventRuleSearch();
};

// PRODUCTION_METHODS

#define CHECK(x) do { if (!(x)) { std::cerr << "FAIL " << __LINE__ << ": " #x "\n"; return 1; } } while (false)
static bool drain(const std::function<bool()>& done) {
    QElapsedTimer clock; clock.start();
    while (!done() && clock.elapsed() < 30000) QCoreApplication::processEvents(QEventLoop::AllEvents, 10);
    return done();
}
int main(int argc, char** argv) {
    QApplication app(argc, argv); QTemporaryDir dir; CHECK(dir.isValid());
    WinAPIDock dock; QTreeWidget tree(&dock); QLineEdit search(&dock); QLabel status(&dock);
    dock.m_eventRulesTree = &tree; dock.m_ruleSearchEdit = &search; dock.m_eventRulesStatus = &status;
    dock.m_eventRules = std::make_shared<ks::monitor::WinAPIFilterRules>(dir.filePath(QStringLiteral("config/filter.cfg")));
    tree.setColumnCount(2); tree.setUniformRowHeights(true); tree.setSortingEnabled(true);
    auto catalog = std::make_shared<ks::monitor::WinAPIFilterCatalog>();
    catalog->push_back({QStringLiteral("user32.dll"), QStringLiteral("GetMessageW"), QStringLiteral("Process")});
    catalog->push_back({QStringLiteral("user32.dll"), QStringLiteral("PeekMessageW"), QStringLiteral("Process")});
    catalog->push_back({QStringLiteral("kernel32.dll"), QStringLiteral("CreateFileW"), QStringLiteral("File")});
    for (int i = 0; i < 5000; ++i) catalog->push_back({QStringLiteral("ntdll.dll"), QStringLiteral("RawFunction%1").arg(i), {}});
    int pulses = 0; QTimer timer; timer.setInterval(1); QObject::connect(&timer, &QTimer::timeout, [&]() { ++pulses; }); timer.start();
    dock.queueEventRuleCatalog(catalog); CHECK(drain([&]() { return !dock.m_ruleCatalogPumpScheduled; }));
    CHECK(dock.m_ruleModules.size() == 3 && dock.m_ruleFunctions.size() == 5003 && pulses > 1);
    const auto key = ks::monitor::WinAPIFilterSnapshot::functionKey(QStringLiteral("user32.dll"), QStringLiteral("GetMessageW"));
    auto* function = dock.m_ruleFunctions.value(key); CHECK(function && function->parent()->parent() == dock.m_ruleModules.value(QStringLiteral("user32.dll")));
    CHECK(function->parent()->text(0) == QStringLiteral("进程"));
    CHECK(function->checkState(0) == Qt::Checked && function->checkState(1) == Qt::Checked);
    auto rules = *dock.m_eventRules->snapshot(); rules.preFunctions.insert(key); CHECK(dock.m_eventRules->save(rules));
    dock.refreshEventRulesPanel(); CHECK(drain([&]() { return !dock.m_ruleStateScheduled && !dock.m_ruleCatalogPumpScheduled; }));
    CHECK(function->checkState(0) == Qt::Unchecked && function->checkState(1) == Qt::Checked);
    dock.m_eventRulesPreStage = false; dock.refreshEventRulesPanel(); CHECK(drain([&]() { return !dock.m_ruleStateScheduled; }));
    CHECK(function->checkState(0) == Qt::Unchecked && function->checkState(1) == Qt::Checked);
    dock.m_eventRulesPreStage = true; rules.preModules.insert(QStringLiteral("user32.dll")); CHECK(dock.m_eventRules->save(rules));
    dock.refreshEventRulesPanel(); CHECK(drain([&]() { return !dock.m_ruleStateScheduled; }));
    CHECK(dock.m_ruleModules.value(QStringLiteral("user32.dll"))->checkState(0) == Qt::Unchecked && !function->isDisabled());
    rules.preModules.clear(); CHECK(dock.m_eventRules->save(rules)); dock.refreshEventRulesPanel();
    CHECK(drain([&]() { return !dock.m_ruleStateScheduled; })); CHECK(!function->isDisabled() && function->checkState(0) == Qt::Unchecked);
    auto* user = dock.m_ruleModules.value(QStringLiteral("user32.dll")); user->setExpanded(true); function->parent()->setExpanded(false);
    search.setText(QStringLiteral("GetMessage")); dock.scheduleEventRuleSearch(); CHECK(drain([&]() { return !dock.m_ruleSearchScheduled; }));
    CHECK(!function->isHidden() && function->parent()->isExpanded());
    CHECK(dock.m_ruleFunctions.value(ks::monitor::WinAPIFilterSnapshot::functionKey(QStringLiteral("user32.dll"), QStringLiteral("PeekMessageW")))->isHidden());
    CHECK(dock.m_ruleModules.value(QStringLiteral("ntdll.dll"))->isHidden());
    dock.m_eventRulesPreStage = false; dock.refreshEventRulesPanel(); CHECK(drain([&]() { return !dock.m_ruleStateScheduled; }));
    CHECK(search.text() == QStringLiteral("GetMessage") && !function->isHidden() && function->checkState(0) == Qt::Unchecked);
    dock.m_eventRulesPreStage = true; dock.refreshEventRulesPanel(); CHECK(drain([&]() { return !dock.m_ruleStateScheduled; }));
    CHECK(function->checkState(0) == Qt::Unchecked);
    CHECK(drain([&]() { return !dock.m_ruleCatalogPumpScheduled; }));
    dock.applyVisibleEventRules(true, false); CHECK(drain([&]() { return !dock.m_ruleStateScheduled && !dock.m_ruleCatalogPumpScheduled; }));
    CHECK(function->checkState(0) == Qt::Checked && !dock.m_eventRules->snapshot()->rejects(QStringLiteral("user32.dll"), QStringLiteral("GetMessageW"), true));
    dock.applyVisibleEventRules(true, true); CHECK(drain([&]() { return !dock.m_ruleStateScheduled && !dock.m_ruleCatalogPumpScheduled; }));
    CHECK(function->checkState(0) == Qt::Unchecked && dock.m_eventRules->snapshot()->rejects(QStringLiteral("user32.dll"), QStringLiteral("GetMessageW"), true));
    CHECK(!dock.m_eventRules->snapshot()->rejects(QStringLiteral("user32.dll"), QStringLiteral("PeekMessageW"), true));
    rules = *dock.m_eventRules->snapshot(); rules.preModules.insert(QStringLiteral("user32.dll")); CHECK(dock.m_eventRules->save(rules));
    dock.refreshEventRulesPanel(); CHECK(drain([&]() { return !dock.m_ruleStateScheduled && !dock.m_ruleCatalogPumpScheduled; }));
    dock.applyVisibleEventRules(true, false); CHECK(drain([&]() { return !dock.m_ruleStateScheduled && !dock.m_ruleCatalogPumpScheduled; }));
    CHECK(!dock.m_eventRules->snapshot()->rejects(QStringLiteral("user32.dll"), QStringLiteral("GetMessageW"), true));
    CHECK(dock.m_eventRules->snapshot()->rejects(QStringLiteral("user32.dll"), QStringLiteral("PeekMessageW"), true));
    search.clear(); dock.scheduleEventRuleSearch(); CHECK(drain([&]() { return !dock.m_ruleSearchScheduled; }));
    CHECK(user->isExpanded() && !function->parent()->isExpanded() && !function->isHidden());
    auto late = std::make_shared<ks::monitor::WinAPIFilterCatalog>();
    late->push_back({QStringLiteral("late.dll"), QStringLiteral("Unknown"), {}}); dock.queueEventRuleCatalog(late);
    CHECK(drain([&]() { return !dock.m_ruleCatalogPumpScheduled; }));
    CHECK(dock.m_ruleFunctions.value(ks::monitor::WinAPIFilterSnapshot::functionKey(QStringLiteral("late.dll"), QStringLiteral("Unknown"))));
    CHECK(dock.m_ruleModules.value(QStringLiteral("late.dll"))->child(0)->text(0) == QStringLiteral("Raw / U"));
    late = std::make_shared<ks::monitor::WinAPIFilterCatalog>();
    late->push_back({QStringLiteral("late.dll"), QStringLiteral("Unknown"), QStringLiteral("File")}); dock.queueEventRuleCatalog(late);
    CHECK(drain([&]() { return !dock.m_ruleCatalogPumpScheduled; }));
    CHECK(dock.m_ruleModules.value(QStringLiteral("late.dll"))->childCount() == 1);
    CHECK(dock.m_ruleFunctions.value(ks::monitor::WinAPIFilterSnapshot::functionKey(QStringLiteral("late.dll"), QStringLiteral("Unknown")))->parent()->text(0) == QStringLiteral("文件"));
    std::cout << "PASS: catalog, module/function checkboxes, stage rules, 5000-row search and expansion restoration\n";
}
