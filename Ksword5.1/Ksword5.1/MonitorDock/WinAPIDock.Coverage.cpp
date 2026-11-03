#include "WinAPIDock.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/FlowLayout.h"
#include "../UI/SegmentedControl.h"
#include "../UI/PageControlStyle.h"
#include "WinAPIEventTableModel.h"
#include "WinAPIParameterEditor.h"
#include "../Internationalization/LanguageManager.h"
#include <QAbstractTableModel>
#include <QFileSystemWatcher>
#include <QDir>
#include <QRunnable>
#include <QThreadPool>
#include <QTimer>
#include <QApplication>
#include <algorithm>
#include <functional>
#include <QComboBox>
#include <QCollator>
#include <QHeaderView>
#include <QElapsedTimer>
#include <QHBoxLayout>
#include <QCryptographicHash>
#include <QFile>
#include <QLabel>
#include <QLineEdit>
#include <QSignalBlocker>
#include <QTableView>
#include <QTabWidget>
#include <QCheckBox>
#include <QFileDialog>
#include <QPushButton>
#include <QStyle>
#include <QToolButton>
#include <QTreeWidget>
#include <QVBoxLayout>

namespace {
QString filterCategoryLabel(const QString& category)
{
    if (category == QStringLiteral("File")) return QStringLiteral("文件");
    if (category == QStringLiteral("Registry")) return QStringLiteral("注册表");
    if (category == QStringLiteral("Network")) return QStringLiteral("网络");
    if (category == QStringLiteral("Process")) return QStringLiteral("进程");
    if (category == QStringLiteral("Loader")) return QStringLiteral("加载器");
    if (category == QStringLiteral("Clipboard")) return QStringLiteral("剪贴板");
    if (category.startsWith(QStringLiteral("Raw/"))) return QStringLiteral("Raw / %1").arg(category.mid(4));
    return QStringLiteral("其他 / Raw");
}
}

QWidget* WinAPIDock::createEventRulesPanel(QWidget* parent)
{
    auto* panel = new QWidget(parent);
    auto* layout = new QVBoxLayout(panel); layout->setContentsMargins(0, 0, 0, 0); layout->setSpacing(6);
    auto* row = new ks::ui::FlowLayout(nullptr, 0, 8, 8);
    const auto help = [panel, row](const QString& tip) {
        auto* button = new QToolButton(panel); button->setIcon(panel->style()->standardIcon(QStyle::SP_MessageBoxQuestion));
        button->setIconSize(QSize(16, 16)); button->setToolTip(tip); button->setAccessibleName(tip); row->addWidget(button);
    };
    row->addWidget(new QLabel(QStringLiteral("前置"), panel)); help(QStringLiteral("前置筛选：主程序收到事件后丢弃，不写入采集档案，不能恢复；不会阻止目标进程中的 Hook。"));
    auto* preAll = new QPushButton(QStringLiteral("全选显示"), panel); auto* preInvert = new QPushButton(QStringLiteral("反选显示"), panel);
    row->addWidget(preAll); row->addWidget(preInvert);
    row->addWidget(new QLabel(QStringLiteral("后置"), panel)); help(QStringLiteral("后置筛选：事件仍会采集和存档，只从列表隐藏；移除规则后可恢复内存中保留的事件。"));
    auto* postAll = new QPushButton(QStringLiteral("全选显示"), panel); auto* postInvert = new QPushButton(QStringLiteral("反选显示"), panel);
    row->addWidget(postAll); row->addWidget(postInvert);
    auto* importButton = new QPushButton(QStringLiteral("导入配置"), panel);
    auto* exportButton = new QPushButton(QStringLiteral("导出配置"), panel);
    m_ruleSearchEdit = new QLineEdit(panel); m_ruleSearchEdit->setPlaceholderText(QStringLiteral("搜索模块或函数"));
    ks::ui::StyleSearchField(m_ruleSearchEdit); row->addWidget(m_ruleSearchEdit);
    for (auto* button : {importButton, exportButton}) row->addWidget(button);
    ks::ui::NormalizeToolbarLayout(row); layout->addLayout(row);
    m_eventRulesTree = new QTreeWidget(panel); m_eventRulesTree->setColumnCount(2);
    m_eventRulesTree->setHeaderLabels({QStringLiteral("前置"), QStringLiteral("后置")});
    m_eventRulesTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_eventRulesTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_eventRulesTree->setUniformRowHeights(true); m_eventRulesTree->setSortingEnabled(true);
    layout->addWidget(m_eventRulesTree, 1);
    m_eventRulesStatus = new QLabel(panel); m_eventRulesStatus->setWordWrap(true); layout->addWidget(m_eventRulesStatus);
    connect(preAll, &QPushButton::clicked, panel, [this]() { applyVisibleEventRules(true, false); });
    connect(preInvert, &QPushButton::clicked, panel, [this]() { applyVisibleEventRules(true, true); });
    connect(postAll, &QPushButton::clicked, panel, [this]() { applyVisibleEventRules(false, false); });
    connect(postInvert, &QPushButton::clicked, panel, [this]() { applyVisibleEventRules(false, true); });
    connect(m_ruleSearchEdit, &QLineEdit::textChanged, panel, [this]() {
        const auto ticket = ++m_ruleSearchTicket;
        QTimer::singleShot(120, this, [this, ticket]() { if (ticket == m_ruleSearchTicket) scheduleEventRuleSearch(); });
    });
    connect(m_eventRulesTree, &QTreeWidget::itemChanged, panel, [this](QTreeWidgetItem* item, int column) {
        if (column < 0 || column > 1 || item->data(0, Qt::UserRole + 2).isValid()) return;
        const auto module = item->data(0, Qt::UserRole).toString(); const auto function = item->data(0, Qt::UserRole + 1).toString();
        const bool pre = column == 0, enabled = item->checkState(column) != Qt::Checked;
        QTimer::singleShot(0, this, [this, module, function, pre, enabled]() { applyEventRule(module, function, pre, enabled); });
    });
    connect(importButton, &QPushButton::clicked, panel, [this]() {
        const auto path = QFileDialog::getOpenFileName(this, QStringLiteral("导入筛选配置"), {}, QStringLiteral("Config (*.cfg *.json)"));
        if (path.isEmpty()) return;
        ks::monitor::WinAPIFilterRules imported(path);
        if (!QFileInfo::exists(path) || !imported.load() || !m_eventRules->save(*imported.snapshot())) {
            m_eventRulesStatus->setText(QStringLiteral("导入失败：配置无效或无法保存。")); return;
        }
        m_eventRulesValid = true; eventRulesChanged();
    });
    connect(exportButton, &QPushButton::clicked, panel, [this]() {
        const auto path = QFileDialog::getSaveFileName(this, QStringLiteral("导出筛选配置"), QStringLiteral("winapi-filter.cfg"), QStringLiteral("Config (*.cfg *.json)"));
        if (!path.isEmpty() && (!m_eventRulesValid || !m_eventRules->exportFile(path))) m_eventRulesStatus->setText(QStringLiteral("导出失败：配置无效或无法写入。"));
    });
    refreshEventRulesPanel(); loadEventRuleDefinitions(); return panel;
}

void WinAPIDock::applyEventRule(const QString& rawModule, const QString& rawFunction, bool pre, bool enabled)
{
    const auto module = rawModule.trimmed(); const auto function = rawFunction.trimmed();
    if (!m_eventRulesValid || module.isEmpty() || module.size() > 260 || function.size() > 1024
        || module.contains(QChar(0x1f)) || function.contains(QChar(0x1f))) { refreshEventRulesPanel(); return; }
    auto next = *m_eventRules->snapshot();
    const auto key = function.isEmpty() ? ks::monitor::WinAPIFilterSnapshot::moduleKey(module) : ks::monitor::WinAPIFilterSnapshot::functionKey(module, function);
    auto& set = function.isEmpty() ? (pre ? next.preModules : next.postModules) : (pre ? next.preFunctions : next.postFunctions);
    if (enabled) set.insert(key); else set.remove(key);
    if (!function.isEmpty()) {
        auto& allowed = pre ? next.preAllowed : next.postAllowed;
        const auto& modules = pre ? next.preModules : next.postModules;
        if (!enabled && modules.contains(ks::monitor::WinAPIFilterSnapshot::moduleKey(module))) allowed.insert(key); else allowed.remove(key);
    } else {
        const QString prefix = key + QChar(0x1f);
        auto& denied = pre ? next.preFunctions : next.postFunctions;
        auto& allowed = pre ? next.preAllowed : next.postAllowed;
        for (auto it = denied.begin(); it != denied.end();) { if (it->startsWith(prefix)) it = denied.erase(it); else ++it; }
        for (auto it = allowed.begin(); it != allowed.end();) { if (it->startsWith(prefix)) it = allowed.erase(it); else ++it; }
    }
    if (!m_eventRules->save(next)) { refreshEventRulesPanel(); m_eventRulesStatus->setText(QStringLiteral("筛选规则保存失败，请检查 config 目录权限。")); return; }
    refreshEventRuleItem(module, function);
    if (function.isEmpty()) refreshEventRulesPanel();
    if (m_eventModel) m_eventModel->setEventRules(m_eventRules->snapshot());
}

void WinAPIDock::applyVisibleEventRules(bool pre, bool invert)
{
    if (!m_eventRulesValid || !m_eventRulesTree) return;
    if (m_ruleSearchScheduled || m_ruleCatalogPumpScheduled || (m_ruleSearchEdit && m_ruleSearchText != m_ruleSearchEdit->text().trimmed())) {
        m_eventRulesStatus->setText(QStringLiteral("筛选结果正在更新，请稍后重试。")); return;
    }
    auto next = *m_eventRules->snapshot();
    auto& denied = pre ? next.preFunctions : next.postFunctions;
    auto& allowed = pre ? next.preAllowed : next.postAllowed;
    const auto& modules = pre ? next.preModules : next.postModules;
    if (!invert && m_ruleSearchText.isEmpty()) {
        (pre ? next.preModules : next.postModules).clear(); denied.clear(); allowed.clear();
        if (!m_eventRules->save(next)) { m_eventRulesStatus->setText(QStringLiteral("筛选规则保存失败，请检查 config 目录权限。")); return; }
        eventRulesChanged(); return;
    }
    for (auto it = m_ruleFunctions.cbegin(); it != m_ruleFunctions.cend(); ++it) {
        auto* item = it.value(); auto* category = item->parent(); auto* moduleItem = category->parent();
        if (item->isHidden() || category->isHidden() || moduleItem->isHidden()) continue;
        const auto module = item->data(0, Qt::UserRole).toString();
        const auto function = item->data(0, Qt::UserRole + 1).toString();
        const bool blocked = next.rejects(module, function, pre);
        const bool newBlocked = invert ? !blocked : false;
        if (newBlocked) { denied.insert(it.key()); allowed.remove(it.key()); }
        else { denied.remove(it.key()); if (modules.contains(ks::monitor::WinAPIFilterSnapshot::moduleKey(module))) allowed.insert(it.key()); else allowed.remove(it.key()); }
    }
    if (!m_eventRules->save(next)) { m_eventRulesStatus->setText(QStringLiteral("筛选规则保存失败，请检查 config 目录权限。")); return; }
    eventRulesChanged();
}

void WinAPIDock::eventRulesChanged()
{
    refreshEventRulesPanel();
    if (m_eventModel) m_eventModel->setEventRules(m_eventRules->snapshot());
}

void WinAPIDock::refreshEventRulesPanel()
{
    if (!m_eventRulesTree) return;
    const QSignalBlocker blocker(m_eventRulesTree);
    const auto rules = m_eventRules->snapshot();
    QSet<QString> keys = rules->preModules; keys.unite(rules->postModules); keys.unite(rules->preFunctions); keys.unite(rules->postFunctions);
    keys.unite(rules->preAllowed); keys.unite(rules->postAllowed);
    auto entries = std::make_shared<ks::monitor::WinAPIFilterCatalog>(); entries->reserve(static_cast<std::size_t>(keys.size()));
    for (const auto& key : keys) { const int split = key.indexOf(QChar(0x1f));
        entries->push_back({split < 0 ? key : key.left(split), split < 0 ? QString() : key.mid(split + 1), {}}); }
    queueEventRuleCatalog(entries);
    for (auto it = m_ruleModules.cbegin(); it != m_ruleModules.cend(); ++it) {
        const auto* item = it.value(); refreshEventRuleItem(item->data(0, Qt::UserRole).toString(), {});
    }
    m_ruleStateItems = m_ruleFunctions.values(); m_ruleStateCursor = 0;
    if (!m_ruleStateScheduled) { m_ruleStateScheduled = true; QTimer::singleShot(0, this, [this]() { pumpEventRuleStates(); }); }
    m_eventRulesTree->setEnabled(m_eventRulesValid);
    m_eventRulesStatus->setText(!m_eventRulesValid ? QStringLiteral("筛选配置无法读取，已停用编辑；可导入有效配置恢复。")
        : m_ruleDefinitionsUnavailable ? QStringLiteral("API 定义文件不可用；仅显示已发现和已保存的函数。")
        : QStringLiteral("勾选表示接收或显示；批量操作只影响当前搜索结果。规则自动保存。"));
}

void WinAPIDock::refreshEventRuleItem(const QString& module, const QString& function, const QString& category)
{
    if (!m_eventRulesTree || module.isEmpty()) return;
    const QSignalBlocker blocker(m_eventRulesTree);
    const auto moduleKey = ks::monitor::WinAPIFilterSnapshot::moduleKey(module);
    auto* group = m_ruleModules.value(moduleKey, nullptr);
    if (!group) {
        group = new QTreeWidgetItem(m_eventRulesTree, {module});
        group->setText(1, module);
        group->setData(0, Qt::UserRole, module); group->setData(0, Qt::UserRole + 1, QString());
        m_ruleModules.insert(moduleKey, group);
    }
    const auto rules = m_eventRules->snapshot();
    const auto stateFor = [&](bool pre) {
        const bool blocked = (pre ? rules->preModules : rules->postModules).contains(moduleKey);
        const auto& exceptions = blocked ? (pre ? rules->preAllowed : rules->postAllowed) : (pre ? rules->preFunctions : rules->postFunctions);
        const QString prefix = moduleKey + QChar(0x1f);
        for (const auto& key : exceptions) if (key.startsWith(prefix)) return Qt::PartiallyChecked;
        return blocked ? Qt::Unchecked : Qt::Checked;
    };
    group->setCheckState(0, stateFor(true)); group->setCheckState(1, stateFor(false));
    const auto updateChild = [&](QTreeWidgetItem* child) {
        const auto name = child->data(0, Qt::UserRole + 1).toString();
        child->setCheckState(0, rules->rejects(module, name, true) ? Qt::Unchecked : Qt::Checked);
        child->setCheckState(1, rules->rejects(module, name, false) ? Qt::Unchecked : Qt::Checked);
    };
    if (function.isEmpty()) {
        return;
    }
    const auto key = ks::monitor::WinAPIFilterSnapshot::functionKey(module, function);
    auto* child = m_ruleFunctions.value(key, nullptr);
    if (!child || !category.isEmpty()) {
        const QChar initial = function.isEmpty() ? QChar('#') : function.front().toUpper();
        const QString categoryKey = category.isEmpty()
            ? QStringLiteral("Raw/") + (initial.isLetterOrNumber() ? QString(initial) : QStringLiteral("#")) : category;
        const QString groupKey = moduleKey + QChar(0x1f) + categoryKey;
        auto* section = m_ruleCategories.value(groupKey, nullptr);
        if (!section) {
            section = new QTreeWidgetItem(group, {filterCategoryLabel(categoryKey)});
            section->setText(1, filterCategoryLabel(categoryKey));
            section->setData(0, Qt::UserRole, module); section->setData(0, Qt::UserRole + 2, categoryKey);
            m_ruleCategories.insert(groupKey, section);
        }
        if (child && child->parent() != section) {
            auto* previous = child->parent(); previous->removeChild(child); section->addChild(child);
            if (previous->childCount() == 0) {
                m_ruleCategories.remove(moduleKey + QChar(0x1f) + previous->data(0, Qt::UserRole + 2).toString());
                delete previous;
            }
        }
        if (!child) child = new QTreeWidgetItem(section, {function});
        child->setText(1, function);
        child->setData(0, Qt::UserRole, module); child->setData(0, Qt::UserRole + 1, function);
        m_ruleFunctions.insert(key, child);
    }
    updateChild(child);
}

void WinAPIDock::pumpEventRuleStates()
{
    m_ruleStateScheduled = false;
    if (!m_eventRulesTree) return;
    const QSignalBlocker blocker(m_eventRulesTree); const auto rules = m_eventRules->snapshot();
    QElapsedTimer budget; budget.start(); int count = 0;
    while (m_ruleStateCursor < m_ruleStateItems.size() && count++ < 300 && budget.elapsed() < 4) {
        auto* item = m_ruleStateItems[m_ruleStateCursor++];
        const auto module = item->data(0, Qt::UserRole).toString(); const auto function = item->data(0, Qt::UserRole + 1).toString();
        item->setCheckState(0, rules->rejects(module, function, true) ? Qt::Unchecked : Qt::Checked);
        item->setCheckState(1, rules->rejects(module, function, false) ? Qt::Unchecked : Qt::Checked);
    }
    if (m_ruleStateCursor < m_ruleStateItems.size()) {
        m_ruleStateScheduled = true; QTimer::singleShot(0, this, [this]() { pumpEventRuleStates(); });
    } else m_ruleStateItems.clear();
}

void WinAPIDock::queueEventRuleCatalog(std::shared_ptr<const ks::monitor::WinAPIFilterCatalog> entries)
{
    if (!entries || entries->empty()) return;
    m_ruleCatalogBatches.emplace_back(std::move(entries), 0);
    if (!m_ruleCatalogPumpScheduled) {
        m_ruleCatalogPumpScheduled = true;
        QTimer::singleShot(0, this, [this]() { pumpEventRuleCatalog(); });
    }
}

void WinAPIDock::pumpEventRuleCatalog()
{
    m_ruleCatalogPumpScheduled = false;
    if (!m_eventRulesTree) { m_ruleCatalogBatches.clear(); return; }
    QElapsedTimer budget; budget.start(); int count = 0;
    while (!m_ruleCatalogBatches.empty() && count++ < 200 && budget.elapsed() < 4) {
        auto& batch = m_ruleCatalogBatches.front();
        const auto& [module, function, category] = (*batch.first)[batch.second++];
        const auto key = ks::monitor::WinAPIFilterSnapshot::functionKey(module, function);
        if ((function.isEmpty() && !m_ruleModules.contains(ks::monitor::WinAPIFilterSnapshot::moduleKey(module)))
            || (!function.isEmpty() && (!m_ruleFunctions.contains(key) || !category.isEmpty()))) refreshEventRuleItem(module, function, category);
        if (batch.second == batch.first->size()) m_ruleCatalogBatches.pop_front();
    }
    if (!m_ruleCatalogBatches.empty()) {
        m_ruleCatalogPumpScheduled = true; QTimer::singleShot(0, this, [this]() { pumpEventRuleCatalog(); });
    }
    else if (m_ruleSearchEdit && !m_ruleSearchEdit->text().trimmed().isEmpty()) scheduleEventRuleSearch();
}

void WinAPIDock::loadEventRuleDefinitions()
{
    if (!m_coverageDispatcher) return;
    const auto ticket = ++m_ruleDefinitionsTicket;
    const auto dispatcher = m_coverageDispatcher;
    const QString path = QApplication::applicationDirPath() + QStringLiteral("/profiles/api_monitor_definitions.json");
    QThreadPool::globalInstance()->start(QRunnable::create([this, dispatcher, path, ticket]() {
        auto entries = std::make_shared<ks::monitor::WinAPIFilterCatalog>();
        auto signatures = std::make_shared<ks::monitor::WinAPISignatureCatalog>(); QFile file(path);
        const bool opened = file.open(QIODevice::ReadOnly) && file.size() <= 16 * 1024 * 1024;
        const QByteArray contents = opened ? file.readAll() : QByteArray();
        const bool ok = opened && ks::monitor::ParseWinAPIFilterCatalog(contents, entries.get());
        const bool signatureOk = opened && signatures->load(contents);
        dispatcher->post([this, entries, signatures, signatureOk, ok, ticket]() {
            if (ticket != m_ruleDefinitionsTicket) return;
            m_ruleDefinitionsUnavailable = !ok;
            if (ok) queueEventRuleCatalog(entries);
            if (signatureOk && m_parameterEditor) m_parameterEditor->setSignatureCatalog(signatures);
            refreshEventRulesPanel();
        });
    }));
}

void WinAPIDock::scheduleEventRuleSearch()
{
    if (!m_eventRulesTree || !m_ruleSearchEdit) return;
    const QString next = m_ruleSearchEdit->text().trimmed();
    if (!m_ruleSearchActive && !next.isEmpty()) {
        m_ruleExpandedBeforeSearch.clear();
        for (auto it = m_ruleModules.cbegin(); it != m_ruleModules.cend(); ++it)
            if (it.value()->isExpanded()) m_ruleExpandedBeforeSearch.insert(QStringLiteral("M") + it.key());
        for (auto it = m_ruleCategories.cbegin(); it != m_ruleCategories.cend(); ++it)
            if (it.value()->isExpanded()) m_ruleExpandedBeforeSearch.insert(QStringLiteral("C") + it.key());
    }
    m_ruleSearchActive = !next.isEmpty(); m_ruleSearchText = next;
    for (auto it = m_ruleModules.cbegin(); it != m_ruleModules.cend(); ++it)
        it.value()->setHidden(!next.isEmpty() && !it.value()->text(0).contains(next, Qt::CaseInsensitive));
    for (auto it = m_ruleCategories.cbegin(); it != m_ruleCategories.cend(); ++it)
        it.value()->setHidden(!next.isEmpty() && !it.value()->text(0).contains(next, Qt::CaseInsensitive)
            && !it.value()->parent()->text(0).contains(next, Qt::CaseInsensitive));
    m_ruleSearchItems = m_ruleFunctions.values(); m_ruleSearchCursor = 0;
    if (!m_ruleSearchScheduled) {
        m_ruleSearchScheduled = true; QTimer::singleShot(0, this, [this]() { pumpEventRuleSearch(); });
    }
}

void WinAPIDock::pumpEventRuleSearch()
{
    m_ruleSearchScheduled = false;
    if (!m_eventRulesTree) return;
    QElapsedTimer budget; budget.start(); int count = 0;
    while (m_ruleSearchCursor < m_ruleSearchItems.size() && count++ < 300 && budget.elapsed() < 4) {
        auto* function = m_ruleSearchItems[m_ruleSearchCursor++];
        auto* section = function->parent(); auto* module = section->parent();
        const bool match = m_ruleSearchText.isEmpty() || function->text(0).contains(m_ruleSearchText, Qt::CaseInsensitive)
            || section->text(0).contains(m_ruleSearchText, Qt::CaseInsensitive)
            || module->text(0).contains(m_ruleSearchText, Qt::CaseInsensitive);
        function->setHidden(!match);
        if (match) {
            section->setHidden(false); module->setHidden(false);
            if (m_ruleSearchActive) { module->setExpanded(true); section->setExpanded(true); }
        }
    }
    if (m_ruleSearchCursor < m_ruleSearchItems.size()) {
        m_ruleSearchScheduled = true; QTimer::singleShot(0, this, [this]() { pumpEventRuleSearch(); });
    } else {
        m_ruleSearchItems.clear();
        if (!m_ruleSearchActive) {
            for (auto it = m_ruleModules.cbegin(); it != m_ruleModules.cend(); ++it)
                it.value()->setExpanded(m_ruleExpandedBeforeSearch.contains(QStringLiteral("M") + it.key()));
            for (auto it = m_ruleCategories.cbegin(); it != m_ruleCategories.cend(); ++it)
                it.value()->setExpanded(m_ruleExpandedBeforeSearch.contains(QStringLiteral("C") + it.key()));
            m_ruleExpandedBeforeSearch.clear();
        }
    }
}

namespace
{
    // The source packet snapshot remains canonical; search only replaces these row identities.
    std::vector<std::size_t> coverageMatchingRows(
        const std::vector<WinAPIDock::CoverageDisplayRow>& rows, const QString& filter,
        int sortColumn, Qt::SortOrder sortOrder, const ks::i18n::SourceTextSnapshot& language)
    {
        std::vector<std::size_t> matching;
        matching.reserve(rows.size());
        for (std::size_t i = 0; i < rows.size(); ++i)
            if (filter.isEmpty() || rows[i].searchText.contains(filter, Qt::CaseInsensitive)) matching.push_back(i);
        if (sortColumn >= 0 && sortColumn < 7)
        {
            std::vector<std::pair<std::size_t, QString>> keys;
            keys.reserve(matching.size());
            for (const auto row : matching) keys.emplace_back(row, language.displayText(rows[row].columns.value(sortColumn)));
            const QCollator collator;
            std::stable_sort(keys.begin(), keys.end(), [&](const auto& left, const auto& right) {
                const int order = collator.compare(left.second, right.second);
                return sortOrder == Qt::AscendingOrder ? order < 0 : order > 0;
            });
            matching.clear();
            for (const auto& key : keys) matching.push_back(key.first);
        }
        return matching;
    }

    class CoverageTableModel final : public QAbstractTableModel
    {
    public:
        explicit CoverageTableModel(QObject* parent, std::function<void()> request)
            : QAbstractTableModel(parent), m_request(std::move(request)) {}
        void sort(int column, Qt::SortOrder order) override
        { m_requestedSortColumn = column; m_requestedSortOrder = order; m_request(); }
        int requestedSortColumn() const { return m_requestedSortColumn; }
        Qt::SortOrder requestedSortOrder() const { return m_requestedSortOrder; }
        int rowCount(const QModelIndex& parent = {}) const override
        { return parent.isValid() || !m_indexes ? 0 : static_cast<int>(m_indexes->size()); }
        int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 7; }
        QVariant data(const QModelIndex& index, const int role) const override
        {
            if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()
                || index.column() < 0 || index.column() >= columnCount() || !m_rows) return {};
            const auto source = (*m_indexes)[static_cast<std::size_t>(index.row())];
            if (source >= m_rows->size()) return {};
            if (role == Qt::DisplayRole || role == Qt::ToolTipRole)
                return ks::i18n::sourceText((*m_rows)[source].columns[index.column()]);
            if (role == Qt::TextAlignmentRole) return int(Qt::AlignLeft | Qt::AlignVCenter);
            return {};
        }
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override
        {
            if (role != Qt::DisplayRole) return {};
            if (orientation == Qt::Vertical) return section + 1;
            static const QStringList headers{QStringLiteral("PID"), QStringLiteral("API ID"), QStringLiteral("Hook 类型"),
                QStringLiteral("API"), QStringLiteral("覆盖状态"), QStringLiteral("入口地址"), QStringLiteral("原因")};
            return section >= 0 && section < headers.size() ? QVariant(ks::i18n::sourceText(headers[section])) : QVariant();
        }
        bool matches(const std::shared_ptr<const std::vector<WinAPIDock::CoverageDisplayRow>>& rows, const QString& filter, int column, Qt::SortOrder order) const
        { return m_rows == rows && m_filter == filter && m_appliedSortColumn == column && m_appliedSortOrder == order; }
        void replace(std::shared_ptr<const std::vector<WinAPIDock::CoverageDisplayRow>> rows,
            std::shared_ptr<const std::vector<std::size_t>> indexes, QString filter = {},
            int sortColumn = -1, Qt::SortOrder sortOrder = Qt::AscendingOrder)
        {
            const bool sameRows = m_rows == rows && m_filter == filter && m_indexes && indexes;
            if (sameRows) emit layoutAboutToBeChanged({}, QAbstractItemModel::VerticalSortHint);
            else beginResetModel();
            // Selection models create their persistent indexes in the signal.
            const auto previousPersistent = sameRows ? persistentIndexList() : QModelIndexList{};
            auto previousRows = std::move(m_rows);
            auto previousIndexes = std::move(m_indexes);
            m_rows = std::move(rows); m_indexes = std::move(indexes); m_filter = std::move(filter);
            m_appliedSortColumn = sortColumn; m_appliedSortOrder = sortOrder;
            if (sameRows) {
                std::vector<int> destination(m_rows->size(), -1);
                for (std::size_t row = 0; row < m_indexes->size(); ++row) destination[(*m_indexes)[row]] = static_cast<int>(row);
                QModelIndexList nextPersistent; nextPersistent.reserve(previousPersistent.size());
                for (const auto& index : previousPersistent) {
                    const auto source = (*previousIndexes)[static_cast<std::size_t>(index.row())];
                    nextPersistent.push_back(source < destination.size() && destination[source] >= 0 ? this->index(destination[source], index.column()) : QModelIndex{});
                }
                changePersistentIndexList(previousPersistent, nextPersistent);
                emit layoutChanged({}, QAbstractItemModel::VerticalSortHint);
            } else endResetModel();
            // Large immutable snapshots can become last-owned here; release their strings off GUI.
            QThreadPool::globalInstance()->start(QRunnable::create(
                [previousRows = std::move(previousRows), previousIndexes = std::move(previousIndexes)]() {}));
        }
    private:
        QString m_filter;
        std::function<void()> m_request;
        int m_requestedSortColumn = -1, m_appliedSortColumn = -1;
        Qt::SortOrder m_requestedSortOrder = Qt::AscendingOrder, m_appliedSortOrder = Qt::AscendingOrder;
        std::shared_ptr<const std::vector<WinAPIDock::CoverageDisplayRow>> m_rows;
        std::shared_ptr<const std::vector<std::size_t>> m_indexes;
    };

    QString coverageText(const wchar_t* text, std::size_t capacity)
    { return QString::fromWCharArray(text, static_cast<int>(wcsnlen_s(text, capacity))); }
    QString coverageStateText(std::uint32_t state)
    {
        using ks::winapi_monitor::CoverageState;
        switch (static_cast<CoverageState>(state))
        {
        case CoverageState::Installed: return QStringLiteral("已安装");
        case CoverageState::SharedEntry: return QStringLiteral("共享入口");
        case CoverageState::CategoryDisabled: return QStringLiteral("分类关闭");
        case CoverageState::WaitingModule: return QStringLiteral("等待模块");
        case CoverageState::ExportMissing: return QStringLiteral("导出缺失");
        case CoverageState::RuleExcluded: return QStringLiteral("规则排除");
        case CoverageState::RetryableFailure: return QStringLiteral("可重试失败");
        case CoverageState::Unsupported: return QStringLiteral("不支持");
        case CoverageState::Removed: return QStringLiteral("已移除");
        }
        return QStringLiteral("未知");
    }
    QString coverageKindText(std::uint32_t kind)
    {
        using ks::winapi_monitor::HookKind;
        switch (static_cast<HookKind>(kind))
        {
        case HookKind::Strong: return QStringLiteral("强类型");
        case HookKind::Raw: return QString::fromLatin1("Raw");
        case HookKind::Fake: return QString::fromLatin1("Fake");
        case HookKind::DynamicExtension: return QStringLiteral("动态扩展");
        }
        return QStringLiteral("未知");
    }
}

void WinAPISessionBackend::queueCoverageSnapshot(std::uint32_t pid, std::uint64_t session, std::uint64_t revision,
    std::vector<ks::winapi_monitor::ApiMonitorEventPacket> rows, bool stale, std::uint64_t generation)
{
    std::shared_ptr<const std::vector<CoverageDisplayRow>> displayRows;
    if (!stale)
    {
        auto prepared = std::make_shared<std::vector<CoverageDisplayRow>>();
        prepared->reserve(rows.size());
        for (const auto& packet : rows)
        {
            const QString api = coverageText(packet.moduleName, std::size(packet.moduleName)) + QString::fromLatin1("!")
                + coverageText(packet.apiName, std::size(packet.apiName));
            const QString state = coverageStateText(packet.coverageState);
            const QString kind = coverageKindText(packet.hookKind);
            const QString detail = coverageText(packet.detailText, std::size(packet.detailText));
            prepared->push_back({{QString::number(pid), QString::number(packet.apiId), kind, api, state,
                QString::fromLatin1("0x%1").arg(static_cast<qulonglong>(packet.hookAddress), 0, 16), detail}, api + state + kind + detail});
        }
        displayRows = std::move(prepared);
    }
    const std::lock_guard<std::mutex> lock(pendingMutex);
    if (generation != config.generation) return;
    auto& pending = pendingCoverage[pid];
    if (pending.session && (pending.session != session || pending.revision > revision)) return;
    pending.session = session;
    pending.revision = revision;
    pending.stale = stale;
    if (!stale) { pending.rows = std::move(rows); pending.displayRows = std::move(displayRows); pending.complete = true; }
}

void WinAPIDock::flushCoverageUpdates()
{
    // A canceled GUI delivery only publishes a value flag. This existing tick
    // reconciles it and recomputes the latest replaceable projection/hash.
    if (m_coverageHashDeliveryDropped && m_coverageHashDeliveryDropped->exchange(false)) {
        m_coverageHashPending = false; refreshCoverageDefinitionHash();
    }
    if (m_coverageFilterDeliveryDropped && m_coverageFilterDeliveryDropped->exchange(false)) {
        m_coverageFilterRunning = false; m_coverageDirty = true; updateCoverageView();
    }
    std::unordered_map<std::uint32_t, CoverageViewState> updates;
    {
        const std::lock_guard<std::mutex> lock(m_pendingMutex);
        updates.swap(m_pendingCoverage);
    }
    bool changed = false;
    for (auto& [pid, update] : updates)
    {
        auto& visible = m_coverageViews[pid];
        if (visible.session && (visible.session != update.session || visible.revision > update.revision)) continue;
        visible.session = update.session;
        if (update.complete) {
            visible.revision = update.revision; visible.rows = std::move(update.rows); visible.displayRows = std::move(update.displayRows); visible.complete = true;
            const auto rows = visible.displayRows; const auto dispatcher = m_coverageDispatcher;
            if (rows && dispatcher) QThreadPool::globalInstance()->start(QRunnable::create([this, rows, dispatcher]() {
                auto entries = std::make_shared<ks::monitor::WinAPIFilterCatalog>(); entries->reserve(rows->size());
                for (const auto& row : *rows) {
                    const auto api = row.columns.value(3); const int split = api.indexOf(QChar('!'));
                    if (split > 0 && split + 1 < api.size()) entries->push_back({api.left(split), api.mid(split + 1), {}});
                }
                dispatcher->post([this, entries]() { queueEventRuleCatalog(entries); });
            }));
        }
        visible.stale = update.stale;
        if (pid == m_currentSessionPid && !visible.rows.empty())
        {
            m_definitionMismatch = m_coverageDefinitionHash.isEmpty()
                || m_coverageDefinitionHash != QByteArray(visible.rows.front().definitionSha256, 64);
        }
        changed = true;
    }
    if (!changed) return;
    m_coverageDirty = true;
    const QSignalBlocker blocker(m_coveragePidCombo);
    const auto previousPid = m_coveragePidCombo->currentData().toUInt();
    m_coveragePidCombo->clear();
    std::vector<std::uint32_t> pids;
    for (const auto& [pid, view] : m_coverageViews) pids.push_back(pid);
    std::sort(pids.begin(), pids.end());
    for (const auto pid : pids) m_coveragePidCombo->addItem(QString::number(pid), pid);
    const int selected = m_coveragePidCombo->findData(previousPid);
    if (selected >= 0) m_coveragePidCombo->setCurrentIndex(selected);
    if (m_resultTabs->currentIndex() == 1) updateCoverageView();
}

void WinAPIDock::initializeCoverageTable()
{
    m_coverageDispatcher = std::make_shared<ks::ui::AsyncUiDispatcher>(this);
    m_coverageModel = new CoverageTableModel(m_coverageTable, [this]() { updateCoverageView(); });
    m_coverageTable->setModel(m_coverageModel);
    auto* watcher = new QFileSystemWatcher(this);
    const QString directory = QApplication::applicationDirPath() + QStringLiteral("/profiles");
    watcher->addPath(directory);
    watcher->addPath(directory + QStringLiteral("/api_monitor_definitions.json"));
    connect(watcher, &QFileSystemWatcher::directoryChanged, this, [this, watcher, directory]() {
        // Atomic replacement invalidates a file watch. The directory watch reconnects it.
        if (watcher->files().isEmpty()) watcher->addPath(directory + QStringLiteral("/api_monitor_definitions.json"));
        refreshCoverageDefinitionHash(); loadEventRuleDefinitions();
    });
    connect(watcher, &QFileSystemWatcher::fileChanged, this, [this]() { refreshCoverageDefinitionHash(); loadEventRuleDefinitions(); });
    refreshCoverageDefinitionHash();
}

void WinAPIDock::refreshCoverageDefinitionHash()
{
    m_coverageHashDirty = true;
    if (m_coverageHashPending || !m_coverageDispatcher) return;
    m_coverageHashPending = true;
    const auto deliveryDropped = m_coverageHashDeliveryDropped = std::make_shared<std::atomic_bool>(false);
    m_coverageHashDirty = false;
    const QString path = QApplication::applicationDirPath() + QStringLiteral("/profiles/api_monitor_definitions.json");
    const auto dispatcher = m_coverageDispatcher;
    QThreadPool::globalInstance()->start(QRunnable::create([this, dispatcher, path, deliveryDropped]() {
        QFile file(path);
        QCryptographicHash hasher(QCryptographicHash::Sha256);
        const QByteArray hash = file.open(QIODevice::ReadOnly) && hasher.addData(&file)
            && file.error() == QFileDevice::NoError ? hasher.result().toHex() : QByteArray();
        dispatcher->post([this, hash]() {
            m_coverageHashPending = false;
            const bool changed = m_coverageDefinitionHash != hash;
            m_coverageDefinitionHash = hash;
            if (changed)
            {
                const auto root = m_coverageViews.find(m_currentSessionPid);
                if (root != m_coverageViews.end() && !root->second.rows.empty())
                    m_definitionMismatch = hash.isEmpty() || hash != QByteArray(root->second.rows.front().definitionSha256, 64);
                m_coverageDirty = true;
                updateCoverageView();
                updateStatusLabel();
            }
            if (m_coverageHashDirty) refreshCoverageDefinitionHash();
        }, [deliveryDropped]() { deliveryDropped->store(true); });
    }));
}

void WinAPIDock::updateCoverageView()
{
    if (!m_coverageTable || !m_coveragePidCombo || !m_coverageStatusLabel || !m_coverageDispatcher) return;
    m_coverageDirty = true;
    const auto ticket = ++m_coverageFilterTicket;
    // Hidden coverage keeps its accepted canonical snapshot; only its display projection waits.
    if (!m_coverageTable->isVisible()) return;
    if (!m_coverageDebounceDue)
    {
        if (!m_coverageDebouncePending)
        {
            m_coverageDebouncePending = true;
            QTimer::singleShot(180, this, [this]() {
                m_coverageDebouncePending = false;
                m_coverageDebounceDue = true;
                updateCoverageView();
            });
        }
        return;
    }
    m_coverageDebounceDue = false;
    const auto pid = m_coveragePidCombo->currentData().toUInt();
    const auto iterator = m_coverageViews.find(pid);
    if (iterator == m_coverageViews.end())
    {
        static_cast<CoverageTableModel*>(m_coverageModel)->replace({}, {});
        m_coverageStatusLabel->setText(QStringLiteral("覆盖快照：等待 Agent 完整快照"));
        m_coverageDirty = false;
        return;
    }
    const auto& view = iterator->second;
    const auto remoteHash = view.rows.empty() ? QByteArray() : QByteArray(view.rows.front().definitionSha256, 64);
    const bool mismatch = m_coverageDefinitionHash.isEmpty() || remoteHash != m_coverageDefinitionHash;
    if (pid == m_currentSessionPid) m_definitionMismatch = mismatch;
    QString status = view.stale ? QStringLiteral("覆盖快照：已过期或不完整") : QStringLiteral("覆盖快照：完整");
    status += QStringLiteral(" | PID=%1，修订=%2，API=%3").arg(pid).arg(static_cast<qulonglong>(view.revision)).arg(view.rows.size());
    if (mismatch) status += QStringLiteral(" | API 定义不匹配或缺失");
    m_coverageStatusLabel->setText(status);
    ks::ui::ApplyStatusRole(m_coverageStatusLabel, view.stale || mismatch ? ks::ui::StatusRole::Warning : ks::ui::StatusRole::Info);
    const auto rows = view.displayRows;
    const QString filter = m_coverageFilterEdit->text().trimmed();
    const auto model = static_cast<CoverageTableModel*>(m_coverageModel);
    const int sortColumn = model->requestedSortColumn();
    const auto sortOrder = model->requestedSortOrder();
    const auto language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    if (model->matches(rows, filter, sortColumn, sortOrder))
    { m_coverageDirty = false; return; }
    const auto dispatcher = m_coverageDispatcher;
    // One timer samples the latest request; one worker scans it without touching the model.
    if (m_coverageFilterRunning) return;
    m_coverageFilterRunning = true;
    const auto deliveryDropped = m_coverageFilterDeliveryDropped = std::make_shared<std::atomic_bool>(false);
        QThreadPool::globalInstance()->start(QRunnable::create([this, ticket, rows, filter, sortColumn, sortOrder, language, dispatcher, deliveryDropped]() {
            const auto matching = std::make_shared<const std::vector<std::size_t>>(
                rows ? coverageMatchingRows(*rows, filter, sortColumn, sortOrder, language) : std::vector<std::size_t>());
            dispatcher->post([this, ticket, rows, matching, filter, sortColumn, sortOrder]() {
                m_coverageFilterRunning = false;
                if (ticket != m_coverageFilterTicket) { updateCoverageView(); return; }
                if (!m_coverageTable->isVisible()) return;
                auto commit = [this, ticket, rows, matching, filter, sortColumn, sortOrder]() {
                    if (ticket != m_coverageFilterTicket || !m_coverageTable->isVisible()) return;
                    static_cast<CoverageTableModel*>(m_coverageModel)->replace(rows, matching, filter, sortColumn, sortOrder);
                    m_coverageDirty = false;
                };
                if (!ks::ui::DeferTableUiCommitIfContextMenuOpen(this,
                    QStringLiteral("winapi-coverage-projection-apply"), {m_coverageTable}, commit)) commit();
            }, [deliveryDropped]() { deliveryDropped->store(true); });
        }));
}

void WinAPIDock::resetCoverageView()
{
    {
        const std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingCoverage.clear();
    }
    m_coverageViews.clear();
    refreshCoverageDefinitionHash();
    m_coveragePidCombo->clear();
    m_coverageDirty = true;
    updateCoverageView();
}

void WinAPIDock::markCoverageStale()
{
    flushCoverageUpdates();
    for (auto& [pid, view] : m_coverageViews) view.stale = true;
    m_coverageDirty = true;
    if (m_resultTabs->currentIndex() == 1) updateCoverageView();
}
