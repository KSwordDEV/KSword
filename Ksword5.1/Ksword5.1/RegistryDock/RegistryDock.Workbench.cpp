#include "../Internationalization/LanguageManager.h"
#include "../UI/AdaptivePageScroll.h"
#include "../UI/ThemeBinding.h"
#include <QResizeEvent>
#include <QStyle>
#include "RegistryDock.h"
#include "RegistryValueEditorWidget.h"
#include "RegistryWorkbenchAccess.h"
#include "RegistryDocument.h"
#include "RegistryDocumentApply.h"
#include "RegistryValueTransactions.h"
#include "../UI/FlowLayout.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/UI_All.h"
#include "../theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QCompleter>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
#include <QShortcut>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStringListModel>
#include <QTabBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QThreadPool>
#include <QToolButton>
#include <QTreeWidget>
#include <QTimer>
#include <QVBoxLayout>

namespace
{
    QString locationLabel(const QString& path)
    {
        const qsizetype slash = path.lastIndexOf(QLatin1Char('\\'));
        return slash < 0 ? path : path.mid(slash + 1);
    }

    QString sourceLabel(const int viewBits, const bool useR0)
    {
        return useR0 ? ks::i18n::sourceText(QStringLiteral("R0 / 本机视图"))
            : viewBits == 32 ? ks::i18n::sourceText(QStringLiteral("Win32 / 32 位视图"))
            : viewBits == 64 ? ks::i18n::sourceText(QStringLiteral("Win32 / 64 位视图"))
            : ks::i18n::sourceText(QStringLiteral("Win32 / 本机视图"));
    }

    // 输入待显示的菜单，设置当前主题的背景、文字、选中态与禁用态。
    // 子菜单在创建后同样调用，避免依赖父容器或应用的默认菜单样式。
    void applyWorkbenchMenuTheme(QMenu& menu)
    {
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        menu.setToolTipsVisible(true);
    }
}

RegistryAccessContext RegistryDock::accessContext() const
{
    return accessContextForPath(m_currentPath);
}

RegistryAccessContext RegistryDock::accessContextForPath(const QString& path) const
{
    const bool merged = path.compare(QStringLiteral("HKEY_CLASSES_ROOT"), Qt::CaseInsensitive) == 0
        || path.startsWith(QStringLiteral("HKEY_CLASSES_ROOT\\"), Qt::CaseInsensitive);
    return RegistryAccessContext{m_viewBits, !merged && shouldUseRegistryR0()};
}

void RegistryDock::initializeWorkbenchControls()
{
    const auto fallbackIcon = [](QPushButton* button, QStyle::StandardPixmap icon) {
        if (button->icon().pixmap(button->iconSize()).isNull()) button->setIcon(button->style()->standardIcon(icon));
    };
    fallbackIcon(m_backButton, QStyle::SP_ArrowBack);
    fallbackIcon(m_forwardButton, QStyle::SP_ArrowForward);
    fallbackIcon(m_refreshButton, QStyle::SP_BrowserReload);
    for (auto* button : {m_searchButton, m_stopSearchButton})
    {
        button->setMinimumWidth(0);
        button->setMaximumWidth(QWIDGETSIZE_MAX);
        button->setText(button->toolTip());
    }
    // 位置标签与新建入口共用一行；加号独立于可滚动标签，窄窗口也不会被挤出。
    QWidget* locationTabRow = new QWidget(m_registryEditorPage); // 标签栏行的宿主。
    auto* locationTabLayout = new QHBoxLayout(locationTabRow);   // 保留加号固定宽度的横向布局。
    locationTabLayout->setContentsMargins(0, 0, 0, 0);
    locationTabLayout->setSpacing(4);
    m_locationTabs = new QTabBar(locationTabRow);
    m_locationTabs->setExpanding(false);
    m_locationTabs->setUsesScrollButtons(true);
    m_locationTabs->setTabsClosable(true);
    m_locationTabs->setMovable(true);
    m_locationTabs->setProperty("ks_i18n_preserve_data_text", true);
    m_locationTabs->addTab(QStringLiteral("HKEY_CURRENT_USER"));
    m_locationTabs->setTabData(0, QStringLiteral("HKEY_CURRENT_USER"));
    locationTabLayout->addWidget(m_locationTabs, 1);
    // 点击沿用原有新标签流程，保留当前路径与尚未提交的编辑草稿。
    auto* addTabButton = new QToolButton(locationTabRow); // 始终可见的 Tab 新建按钮。
    addTabButton->setObjectName(QStringLiteral("registry_workbench_add_tab"));
    addTabButton->setText(QStringLiteral("+"));
    addTabButton->setAutoRaise(true);
    KswordTheme::ApplyCompactIconButtonMetrics(addTabButton);
    ks::i18n::LanguageManager::instance().bindToolTip(addTabButton,
        QStringLiteral("registry.workbench.new_tab"), QStringLiteral("新标签"));
    addTabButton->setAccessibleName(ks::i18n::sourceText(QStringLiteral("新标签")));
    connect(addTabButton, &QToolButton::clicked, this, [this]()
    {
        addLocationTab(m_currentPath);
    });
    locationTabLayout->addWidget(addTabButton);
    m_registryEditorLayout->insertWidget(0, locationTabRow);
    m_favoritePaths = QSettings().value(QStringLiteral("RegistryWorkbench/Favorites")).toStringList();

    QWidget* commands = new QWidget(m_registryEditorPage);
    auto* commandLayout = new ks::ui::FlowLayout(commands, 0, 6, 4);
    for (auto* button : {m_newKeyButton, m_newValueButton, m_renameButton,
        m_deleteButton, m_importButton, m_exportButton})
    {
        m_toolBarLayout->removeWidget(button);
        button->setMinimumWidth(0);
        button->setMaximumWidth(QWIDGETSIZE_MAX);
        button->setText(button->toolTip());
        commandLayout->addWidget(button);
    }
    auto* navigation = new QPushButton(QStringLiteral("收藏 / 历史"), commands);
    commandLayout->addWidget(navigation);
    connect(navigation, &QPushButton::clicked, this, &RegistryDock::showNavigationMenu);
    auto* details = new QPushButton(QStringLiteral("详情"), commands);
    m_detailToggle = details;
    details->setCheckable(true);
    details->setChecked(true);
    commandLayout->addWidget(details);
    auto* more = new QPushButton(QStringLiteral("更多"), commands);
    commandLayout->addWidget(more);
    connect(more, &QPushButton::clicked, this, [this, more]() {
        QMenu menu(this);
        applyWorkbenchMenuTheme(menu);
        menu.setObjectName(QStringLiteral("registry_workbench_more_menu"));
        auto* backup = menu.addAction(QStringLiteral("备份完整子树"));
        auto* restore = menu.addAction(QStringLiteral("恢复原始备份"));
        menu.addSeparator();
        auto* permissions = menu.addAction(QStringLiteral("键权限"));
        auto* hive = menu.addAction(QStringLiteral("打开离线 Hive 工作副本"));
        auto* related = menu.addAction(QStringLiteral("打开值中的文件 / 定位关联键"));
        QAction* selected = menu.exec(more->mapToGlobal(QPoint(0, more->height())));
        if (selected == backup) backupCurrentKey();
        else if (selected == restore) restoreBackup();
        else if (selected == permissions) showKeyPermissions();
        else if (selected == hive) openOfflineHive();
        else if (selected == related) openRelatedItem();
    });
    m_viewCombo = new QComboBox(m_toolBarWidget);
    m_viewCombo->addItem(QStringLiteral("本机视图"), 0);
    m_viewCombo->addItem(QStringLiteral("32 位视图"), 32);
    m_viewCombo->addItem(QStringLiteral("64 位视图"), 64);
    m_toolBarLayout->removeWidget(m_driverRegistryModeLabel);
    commandLayout->addWidget(m_viewCombo);
    commandLayout->addWidget(m_driverRegistryModeLabel);
    m_pathEdit->setMinimumWidth(0);
    m_pathEdit->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    ks::ui::IsolateMinimumSize(m_registryTabWidget);
    m_registryEditorLayout->insertWidget(2, commands);

    QWidget* searchPanel = new QWidget(m_registryEditorPage);
    auto* searchLayout = new ks::ui::FlowLayout(searchPanel, 0, 6, 4);
    m_filterEdit = new QLineEdit(searchPanel);
    // 当前注册表值列表的本地过滤独立于完整注册表查询，二者均保留各自信号。
    ks::ui::BindSearchFieldTheme(m_filterEdit);
    m_filterEdit->setPlaceholderText(QStringLiteral("过滤当前值列表"));
    m_filterEdit->setClearButtonEnabled(true);
    m_filterEdit->setMinimumWidth(160);
    searchLayout->addWidget(m_filterEdit);
    m_toolBarLayout->removeWidget(m_searchEdit);
    m_toolBarLayout->removeWidget(m_searchButton);
    m_toolBarLayout->removeWidget(m_stopSearchButton);
    m_searchEdit->setPlaceholderText(QStringLiteral("注册表搜索 / hex:字节"));
    m_searchEdit->setClearButtonEnabled(true);
    m_searchEdit->setMinimumWidth(160);
    searchLayout->addWidget(m_searchEdit);
    m_searchScopeCombo = new QComboBox(searchPanel);
    m_searchScopeCombo->addItem(QStringLiteral("当前子树"), 1);
    m_searchScopeCombo->addItem(QStringLiteral("当前键"), 0);
    m_searchScopeCombo->addItem(QStringLiteral("全部根键"), 2);
    searchLayout->addWidget(m_searchScopeCombo);
    m_searchTypeCombo = new QComboBox(searchPanel);
    m_searchTypeCombo->addItem(QStringLiteral("全部类型"), -1);
    for (const DWORD type : {REG_SZ, REG_EXPAND_SZ, REG_MULTI_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_NONE})
        m_searchTypeCombo->addItem(valueTypeToText(type), static_cast<int>(type));
    searchLayout->addWidget(m_searchTypeCombo);
    m_matchKeysCheck = new QCheckBox(QStringLiteral("键名"), searchPanel);
    m_matchNamesCheck = new QCheckBox(QStringLiteral("值名"), searchPanel);
    m_matchDataCheck = new QCheckBox(QStringLiteral("数据"), searchPanel);
    m_matchCaseCheck = new QCheckBox(QStringLiteral("区分大小写"), searchPanel);
    m_matchExactCheck = new QCheckBox(QStringLiteral("完全匹配"), searchPanel);
    for (auto* check : {m_matchKeysCheck, m_matchNamesCheck, m_matchDataCheck}) check->setChecked(true);
    for (auto* check : {m_matchKeysCheck, m_matchNamesCheck, m_matchDataCheck, m_matchCaseCheck, m_matchExactCheck})
        searchLayout->addWidget(check);
    searchLayout->addWidget(m_searchButton);
    searchLayout->addWidget(m_stopSearchButton);
    m_registryEditorLayout->insertWidget(3, searchPanel);

    m_detailScroll = new QScrollArea(m_mainSplitter);
    m_detailScroll->setWidgetResizable(true);
    m_detailScroll->setMinimumWidth(0);
    QWidget* detail = new QWidget;
    auto* detailLayout = new QVBoxLayout(detail);
    detailLayout->setContentsMargins(8, 8, 8, 8);
    m_editorContextLabel = new QLabel(QStringLiteral("选择一个值查看完整数据。"), detail);
    m_editorContextLabel->setProperty("ks_i18n_preserve_data_text", true);
    m_editorContextLabel->setWordWrap(true);
    m_editorContextLabel->setTextFormat(Qt::PlainText);
    detailLayout->addWidget(m_editorContextLabel);
    m_editorSourceLabel = new QLabel(detail);
    m_editorSourceLabel->setTextFormat(Qt::PlainText);
    detailLayout->addWidget(m_editorSourceLabel);
    m_valueEditor = new RegistryValueEditorWidget(detail);
    m_valueEditor->hide();
    detailLayout->addWidget(m_valueEditor, 1);
    m_editorStatusLabel = new QLabel(detail);
    m_editorStatusLabel->setWordWrap(true);
    m_editorStatusLabel->setTextFormat(Qt::PlainText);
    detailLayout->addWidget(m_editorStatusLabel);
    auto* detailActions = new ks::ui::FlowLayout(nullptr, 0, 6, 4);
    m_stageButton = new QPushButton(QStringLiteral("暂存修改"), detail);
    m_discardButton = new QPushButton(QStringLiteral("放弃修改"), detail);
    auto* fullEditor = new QPushButton(QStringLiteral("完整编辑窗"), detail);
    detailActions->addWidget(m_stageButton);
    detailActions->addWidget(m_discardButton);
    detailActions->addWidget(fullEditor);
    detailLayout->addLayout(detailActions);
    auto* draftHint = new QLabel(QStringLiteral("离开已修改值时自动暂存；应用暂存后才写入。"), detail);
    draftHint->setWordWrap(true);
    draftHint->setTextFormat(Qt::PlainText);
    detailLayout->addWidget(draftHint);
    m_detailScroll->setWidget(detail);
    m_mainSplitter->addWidget(m_detailScroll);
    m_mainSplitter->setStretchFactor(0, 0);
    m_mainSplitter->setStretchFactor(1, 1);
    m_mainSplitter->setStretchFactor(2, 0);
    m_keyTree->setMinimumWidth(120);
    m_mainSplitter->setSizes({240, 760, 340});
    m_keyTree->installEventFilter(this);
    m_valueTable->installEventFilter(this);
    m_keyTree->setProperty("ks_i18n_preserve_model_data", true);
    connect(details, &QPushButton::toggled, m_detailScroll, &QWidget::setVisible);
    connect(m_valueTable, &QTableWidget::currentItemChanged, this,
        [this](QTableWidgetItem*, QTableWidgetItem*) { loadSelectedValue(); });
    connect(m_stageButton, &QPushButton::clicked, this, &RegistryDock::stageEditorValue);
    connect(m_discardButton, &QPushButton::clicked, this, &RegistryDock::discardEditorValue);
    connect(fullEditor, &QPushButton::clicked, this, &RegistryDock::editSelectedValue);
    connect(m_valueEditor, &RegistryValueEditorWidget::draftChanged, this, [this]() {
        RegistryValueDraft draft;
        QString error;
        const bool valid = m_editorReady && m_valueEditor->value(&draft, &error);
        m_stageButton->setEnabled(valid && m_valueEditor->isModified() && !m_applyingChanges);
        m_discardButton->setEnabled(m_editorReady && m_valueEditor->isModified() && !m_applyingChanges);
        m_editorStatusLabel->setText(valid ? (m_valueEditor->isModified()
            ? QStringLiteral("有未暂存修改") : QStringLiteral("与读取基线一致")) : ks::i18n::packedSourceText(error));
    });
    m_stageButton->setEnabled(false);
    m_discardButton->setEnabled(false);

    QWidget* changes = new QWidget(m_rightTabWidget);
    auto* changesLayout = new QVBoxLayout(changes);
    changesLayout->setContentsMargins(0, 0, 0, 0);
    auto* changesActions = new ks::ui::FlowLayout(nullptr, 0, 6, 4);
    m_applyChangesButton = new QPushButton(QStringLiteral("应用暂存"), changes);
    auto* clearChanges = new QPushButton(QStringLiteral("清空草稿"), changes);
    auto* restoreChanges = new QPushButton(QStringLiteral("恢复上次提交"), changes);
    changesActions->addWidget(m_applyChangesButton);
    changesActions->addWidget(clearChanges);
    changesActions->addWidget(restoreChanges);
    changesLayout->addLayout(changesActions);
    m_changesTable = new ks::ui::VisibleTableWidget(changes);
    m_changesTable->setColumnCount(6);
    m_changesTable->setHorizontalHeaderLabels({QStringLiteral("路径"), QStringLiteral("名称"),
        QStringLiteral("原值"), QStringLiteral("新值"), QStringLiteral("来源 / 视图"), QStringLiteral("结果")});
    m_changesTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_changesTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_changesTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_changesTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    changesLayout->addWidget(m_changesTable, 1);
    m_rightTabWidget->addTab(changes, ks::i18n::sourceText(QStringLiteral("待应用")));
    for (auto* table : {m_valueTable, m_searchResultTable, m_changesTable})
    {
        table->setProperty("ks_i18n_preserve_model_data", true);
        table->setShowGrid(false);
        table->verticalHeader()->setDefaultSectionSize(28);
        ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
    }
    connect(m_applyChangesButton, &QPushButton::clicked, this, &RegistryDock::applyPendingChanges);
    connect(clearChanges, &QPushButton::clicked, this, [this]() {
        if (m_applyingChanges) return;
        m_pendingChanges.clear();
        discardEditorValue();
        updatePendingChanges();
    });
    connect(restoreChanges, &QPushButton::clicked, this, &RegistryDock::restoreLastChanges);
    connect(m_filterEdit, &QLineEdit::textChanged, this, &RegistryDock::filterCurrentValues);
    connect(m_viewCombo, &QComboBox::currentIndexChanged, this, [this]() {
        if (!preserveEditorDraft())
        {
            QSignalBlocker blocked(m_viewCombo);
            m_viewCombo->setCurrentIndex(m_viewCombo->findData(m_viewBits));
            return;
        }
        stopSearch(true);
        m_viewBits = m_viewCombo->currentData().toInt();
        ++m_editorGeneration;
        m_editorReady = false;
        m_valueEditor->hide();
        m_keyTree->clear();
        m_searchResultTable->setRowCount(0);
        initializeRootItems();
        navigateToPath(m_currentPath, false);
    });
    connect(m_locationTabs, &QTabBar::currentChanged, this, [this](int index) {
        if (index >= 0) navigateToPath(m_locationTabs->tabData(index).toString(), true);
    });
    connect(m_locationTabs, &QTabBar::tabCloseRequested, this, [this](int index) {
        if (m_locationTabs->count() > 1 && preserveEditorDraft()) m_locationTabs->removeTab(index);
    });
    auto addShortcut = [this](const QKeySequence& keys, const std::function<void()>& callback) {
        auto* shortcut = new QShortcut(keys, m_registryEditorPage);
        shortcut->setContext(Qt::WidgetWithChildrenShortcut);
        connect(shortcut, &QShortcut::activated, this, callback);
    };
    addShortcut(QKeySequence(QStringLiteral("Ctrl+L")), [this]() { m_pathEdit->setFocus(); m_pathEdit->selectAll(); });
    addShortcut(QKeySequence(QStringLiteral("F2")), [this]() { renameSelectedObject(); });
    addShortcut(QKeySequence(QStringLiteral("F5")), [this]() { refreshCurrentKey(true); });
    addShortcut(QKeySequence(QStringLiteral("Ctrl+T")), [this]() { addLocationTab(m_currentPath); });
    addShortcut(QKeySequence(QStringLiteral("Ctrl+S")), [this]() { applyPendingChanges(); });
    updatePendingChanges();
}

bool RegistryDock::eventFilter(QObject* watched, QEvent* event)
{
    if (event->type() == QEvent::FocusIn)
    {
        if (watched == m_keyTree) m_valuesActive = false;
        else if (watched == m_valueTable) m_valuesActive = true;
    }
    return QWidget::eventFilter(watched, event);
}

void RegistryDock::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    if (!m_detailToggle) return;
    m_detailScroll->setVisible(width() >= 900 && m_detailToggle->isChecked());
    m_keyTree->setVisible(width() >= 520);
}

bool RegistryDock::preserveEditorDraft()
{
    if (!m_editorReady || !m_valueEditor->isModified()) return true;
    RegistryValueDraft draft;
    QString error;
    if (!m_valueEditor->value(&draft, &error))
    {
        m_editorStatusLabel->setText(error);
        updateStatusBar(QStringLiteral("请修正或放弃当前输入后再切换。"));
        return false;
    }
    return stageEditorValue();
}

void RegistryDock::loadSelectedValue()
{
    if (!preserveEditorDraft())
    {
        QSignalBlocker blocked(m_valueTable);
        for (int row = 0; row < m_valueTable->rowCount(); ++row)
            if (m_valueTable->item(row, 0)->data(Qt::UserRole).toString() == m_editorName)
            { m_valueTable->selectRow(row); break; }
        return;
    }
    const int row = m_valueTable->currentRow();
    auto* nameItem = row < 0 ? nullptr : m_valueTable->item(row, 0);
    if (!nameItem) return;
    const QString path = m_currentPath;
    const QString name = nameItem->data(Qt::UserRole).toString();
    const RegistryAccessContext context = accessContext();
    const quint64 generation = ++m_editorGeneration;
    m_editorReady = false;
    m_valueEditor->hide();
    m_stageButton->setEnabled(false);
    m_discardButton->setEnabled(false);
    m_editorContextLabel->setText(path);
    m_editorSourceLabel->setText(sourceLabel(context.viewBits, context.useR0));
    m_editorStatusLabel->setText(QStringLiteral("正在读取完整值…"));
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    QThreadPool::globalInstance()->start([guarded, dispatcher, path, name, context, generation]() {
        RegistryValueState value;
        QString error;
        const bool ok = RegistryWorkbenchAccess::read(path, name, context, &value, &error);
        dispatcher->post([guarded, path, name, context, generation, value, error, ok]() {
            if (!guarded || guarded->m_editorGeneration != generation || guarded->m_currentPath != path
                || guarded->m_viewBits != context.viewBits) return;
            if (!ok || !value.exists || !value.complete)
            {
                guarded->m_editorStatusLabel->setText(error.isEmpty() ? QStringLiteral("值不存在或数据不完整，无法编辑。") : ks::i18n::packedSourceText(error));
                return;
            }
            guarded->m_editorPath = path;
            guarded->m_editorName = name;
            guarded->m_editorOriginalType = value.type;
            guarded->m_editorOriginalData = value.data;
            guarded->m_editorViewBits = context.viewBits;
            guarded->m_editorUseR0 = context.useR0;
            RegistryValueState displayed = value;
            for (const auto& change : guarded->m_pendingChanges)
                if (change.keyPath.compare(path, Qt::CaseInsensitive) == 0
                    && change.name.compare(name, Qt::CaseInsensitive) == 0
                    && change.viewBits == context.viewBits && change.useR0 == context.useR0 && !change.deleteValue)
                { displayed.type = change.afterType; displayed.data = change.afterData; break; }
            guarded->m_valueEditor->setValue(path, name, displayed.type, displayed.data);
            guarded->m_valueEditor->show();
            guarded->m_editorReady = true;
            guarded->m_editorStatusLabel->setText(displayed.data == value.data
                ? QStringLiteral("已读取完整原值") : QStringLiteral("显示已暂存草稿，尚未应用"));
        });
    });
}

bool RegistryDock::stageEditorValue()
{
    if (!m_editorReady || m_applyingChanges) return false;
    RegistryValueDraft draft;
    QString error;
    if (!m_valueEditor->value(&draft, &error)) { m_editorStatusLabel->setText(error); return false; }
    PendingValueChange change;
    change.keyPath = m_editorPath;
    change.name = m_editorName;
    change.beforeExists = true;
    change.beforeType = m_editorOriginalType;
    change.beforeData = m_editorOriginalData;
    change.afterType = draft.type;
    change.afterData = draft.data;
    change.viewBits = m_editorViewBits;
    change.useR0 = m_editorUseR0;
    qsizetype existingIndex = -1;
    for (qsizetype index = 0; index < m_pendingChanges.size(); ++index)
    {
        const auto& existing = m_pendingChanges.at(index);
        if (existing.keyPath.compare(change.keyPath, Qt::CaseInsensitive) == 0
            && existing.name.compare(change.name, Qt::CaseInsensitive) == 0
            && existing.viewBits == change.viewBits && existing.useR0 == change.useR0)
        {
            change.beforeExists = existing.beforeExists;
            change.beforeType = existing.beforeType;
            change.beforeData = existing.beforeData;
            existingIndex = index;
            break;
        }
    }
    if (!change.beforeExists || change.afterType != change.beforeType || change.afterData != change.beforeData)
    {
        qsizetype bytes = change.beforeData.size() + change.afterData.size();
        for (qsizetype i = 0; i < m_pendingChanges.size(); ++i)
            if (i != existingIndex) bytes += m_pendingChanges.at(i).beforeData.size() + m_pendingChanges.at(i).afterData.size();
        if ((existingIndex < 0 && m_pendingChanges.size() >= 1024) || bytes > 64 * 1024 * 1024)
        { m_editorStatusLabel->setText(QStringLiteral("暂存达到容量上限，请先应用或清空。")); return false; }
        if (existingIndex >= 0) m_pendingChanges[existingIndex] = change;
        else m_pendingChanges.push_back(change);
    }
    else if (existingIndex >= 0) m_pendingChanges.removeAt(existingIndex);
    m_valueEditor->setValue(m_editorPath, m_editorName, draft.type, draft.data);
    m_editorStatusLabel->setText(QStringLiteral("已暂存，尚未写入注册表"));
    updatePendingChanges();
    return true;
}

void RegistryDock::discardEditorValue()
{
    if (!m_editorReady || m_applyingChanges) return;
    for (qsizetype i = m_pendingChanges.size(); i > 0; --i)
    {
        const auto& change = m_pendingChanges.at(i - 1);
        if (change.keyPath.compare(m_editorPath, Qt::CaseInsensitive) == 0
            && change.name.compare(m_editorName, Qt::CaseInsensitive) == 0
            && change.viewBits == m_editorViewBits && change.useR0 == m_editorUseR0)
            m_pendingChanges.removeAt(i - 1);
    }
    m_valueEditor->setValue(m_editorPath, m_editorName, m_editorOriginalType, m_editorOriginalData);
    m_editorStatusLabel->setText(QStringLiteral("已放弃当前值修改"));
    updatePendingChanges();
}

void RegistryDock::updatePendingChanges()
{
    if (!m_changesTable) return;
    m_changesTable->setRowCount(static_cast<int>(m_pendingChanges.size()));
    for (qsizetype i = 0; i < m_pendingChanges.size(); ++i)
    {
        const auto& change = m_pendingChanges.at(i);
        const QStringList cells{change.keyPath, change.name.isEmpty() ? ks::i18n::sourceText(QStringLiteral("(默认)")) : change.name,
            change.beforeExists ? formatValueData(change.beforeType, change.beforeData) : ks::i18n::sourceText(QStringLiteral("不存在")),
            change.deleteValue ? ks::i18n::sourceText(QStringLiteral("删除值")) : formatValueData(change.afterType, change.afterData),
            sourceLabel(change.viewBits, change.useR0), change.result.isEmpty() ? ks::i18n::sourceText(QStringLiteral("待应用")) : ks::i18n::packedSourceText(change.result)};
        for (int column = 0; column < cells.size(); ++column)
            m_changesTable->setItem(static_cast<int>(i), column, new QTableWidgetItem(cells.at(column)));
    }
    m_rightTabWidget->setTabText(2, ks::i18n::sourceText(QStringLiteral("待应用 (%1)")).arg(m_pendingChanges.size()));
    m_applyChangesButton->setEnabled(!m_pendingChanges.isEmpty() && !m_applyingChanges);
}

void RegistryDock::applyPendingChanges()
{
    if (m_applyingChanges || !preserveEditorDraft() || m_pendingChanges.isEmpty()) return;
    const auto changes = m_pendingChanges;
    m_applyingChanges = true;
    m_valueEditor->setEnabled(false);
    m_viewCombo->setEnabled(false);
    m_applyChangesButton->setEnabled(false);
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    const auto closed = m_operationsClosed;
    QThreadPool::globalInstance()->start([guarded, dispatcher, closed, changes]() mutable {
        QVector<PendingValueChange> applied;
        QVector<PendingValueChange> recoverable;
        QVector<PendingValueChange> remaining;
        for (qsizetype index = 0; index < changes.size(); ++index)
        {
            auto change = changes.at(index); // 每项草稿保留各自的原始目标、视图和通道。
            if (closed->load())
            {
                for (; index < changes.size(); ++index) remaining.push_back(changes.at(index));
                break; // 取消不丢弃还没执行的草稿。
            }
            const RegistryAccessContext context{change.viewBits, change.useR0};
            const RegistryApplyValueState before{change.beforeExists, change.beforeType, change.beforeData};
            const RegistryApplyValueState after{!change.deleteValue, change.afterType, change.afterData};
            RegistryApplyResult result; // 共用状态机检查原值、处理取消并记录真实回读。
            const bool ok = RegistryValueTransactions::apply(change.keyPath, change.name,
                before, after, context, result, closed.get());
            if (ok)
            {
                change.result = QStringLiteral("已应用并回读验证");
                applied.push_back(change);
                recoverable.push_back(change);
            }
            else
            {
                change.result = result.error.isEmpty()
                    ? QStringLiteral("回读不一致，请重新读取后核对") : result.error;
                // 只有成功且实际回读过的回执才能用于自动恢复，失败的未知写入保留诊断。
                remaining.push_back(change);
            }
        }
        dispatcher->post([guarded, applied, remaining, recoverable]() {
            if (!guarded) return;
            guarded->m_applyingChanges = false;
            guarded->m_valueEditor->setEnabled(true);
            guarded->m_viewCombo->setEnabled(true);
            guarded->m_pendingChanges = remaining;
            guarded->m_lastChanges = recoverable;
            guarded->m_lastDocumentResult.reset();
            guarded->m_editorReady = false;
            guarded->m_valueEditor->hide();
            guarded->updatePendingChanges();
            guarded->refreshValueTable();
            guarded->updateStatusBar(QStringLiteral("提交完成：成功 %1 项，未完成 %2 项。")
                .arg(applied.size()).arg(remaining.size()));
        });
    });
}

void RegistryDock::restoreLastChanges()
{
    if (m_applyingChanges || !preserveEditorDraft()) return;
    if (!m_pendingChanges.isEmpty())
    { QMessageBox::information(this, QStringLiteral("恢复"), QStringLiteral("请先处理当前暂存修改。")); return; }
    if (m_lastDocumentResult)
    {
        if (!m_lastDocumentResult->canUndo)
        { QMessageBox::information(this, QStringLiteral("恢复"), QStringLiteral("本次操作不支持自动撤销，请使用修改前的原始备份进行合并恢复。")); return; }
        m_applyingChanges = true;
        m_viewCombo->setEnabled(false);
        m_valueEditor->setEnabled(false);
        m_applyChangesButton->setEnabled(false);
        m_documentCancel = std::make_shared<std::atomic_bool>(false);
        const auto cancel = m_documentCancel;
        const auto previous = m_lastDocumentResult;
        const QPointer<RegistryDock> guarded(this);
        const auto dispatcher = m_uiDispatcher;
        QThreadPool::globalInstance()->start([guarded, dispatcher, cancel, previous]() {
            auto result = std::make_shared<RegistryApplyResult>();
            RegistryDocumentApplyService::undoAccess(*previous, *result, cancel.get());
            dispatcher->post([guarded, result]() {
                if (!guarded) return;
                guarded->m_applyingChanges = false;
                guarded->m_viewCombo->setEnabled(true);
                guarded->m_valueEditor->setEnabled(true);
                guarded->m_editorReady = false;
                guarded->m_valueEditor->hide();
                guarded->m_lastChanges.clear();
                guarded->m_lastDocumentResult = result->completed ? nullptr : result;
                guarded->updatePendingChanges();
                guarded->refreshCurrentKey(true);
                guarded->updateStatusBar(result->completed ? QStringLiteral("上次提交已恢复并回读验证。")
                    : QStringLiteral("恢复未全部完成：%1").arg(result->error));
            });
        });
        return;
    }
    if (m_lastChanges.isEmpty()) return;
    for (auto it = m_lastChanges.crbegin(); it != m_lastChanges.crend(); ++it)
    {
        PendingValueChange restore = *it;
        restore.beforeExists = !it->deleteValue;
        restore.beforeType = it->afterType;
        restore.beforeData = it->afterData;
        restore.deleteValue = !it->beforeExists;
        restore.afterType = it->beforeType;
        restore.afterData = it->beforeData;
        restore.result.clear();
        m_pendingChanges.push_back(restore);
    }
    updatePendingChanges();
    m_rightTabWidget->setCurrentIndex(2);
}

void RegistryDock::filterCurrentValues()
{
    const QString query = m_filterEdit->text();
    for (int row = 0; row < m_valueTable->rowCount(); ++row)
    {
        bool match = query.isEmpty();
        for (int column = 0; !match && column < m_valueTable->columnCount(); ++column)
            if (auto* item = m_valueTable->item(row, column)) match = item->text().contains(query, Qt::CaseInsensitive);
        m_valueTable->setRowHidden(row, !match);
    }
}

void RegistryDock::appendValueRows(const std::shared_ptr<const RegistryKeyListing>& listing,
    int offset, quint64 generation, const QString& selectedName)
{
    if (generation != m_valueLoadGeneration) return;
    const QPointer<RegistryDock> guarded(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(this, QStringLiteral("registry-value-batch"),
        {m_valueTable}, [guarded, listing, offset, generation, selectedName]() {
            if (guarded) guarded->appendValueRows(listing, offset, generation, selectedName);
        })) return;
    const int count = static_cast<int>(listing->values.size());
    const int end = qMin(offset + 300, count);
    {
        QSignalBlocker blocked(m_valueTable);
        m_valueTable->setUpdatesEnabled(false);
        m_valueTable->setRowCount(end);
        for (int row = offset; row < end; ++row)
        {
            const auto& value = listing->values.at(row);
            auto* name = new QTableWidgetItem(value.name.isEmpty() ? ks::i18n::sourceText(QStringLiteral("(默认)")) : value.name);
            name->setData(Qt::UserRole, value.name);
            name->setData(Qt::UserRole + 1, value.type);
            name->setData(Qt::UserRole + 2, value.requiredBytes);
            name->setData(Qt::UserRole + 3, value.complete);
            m_valueTable->setItem(row, 0, name);
            m_valueTable->setItem(row, 1, new QTableWidgetItem(valueTypeToText(value.type)));
            QString preview = formatValueData(value.type, value.data);
            if (!value.complete) preview += ks::i18n::sourceText(QStringLiteral(" <摘要 %1/%2 字节>")).arg(value.data.size()).arg(value.requiredBytes);
            auto* dataItem = new QTableWidgetItem(preview); // 值预览单元格，不与 QWidget::data 混名。
            dataItem->setToolTip(ks::i18n::sourceText(QStringLiteral("完整长度：%1 字节；选择后按实际通道读取完整数据。"))
                .arg(value.requiredBytes));
            m_valueTable->setItem(row, 2, dataItem);
        }
        m_valueTable->setUpdatesEnabled(true);
    }
    filterCurrentValues();
    if (end < count)
    {
        QTimer::singleShot(0, this, [guarded, listing, end, generation, selectedName]() {
            if (guarded) guarded->appendValueRows(listing, end, generation, selectedName);
        });
        return;
    }
    updateStatusBar(listing->complete ? QStringLiteral("已加载 %1 个值。选择后读取完整数据。").arg(count)
        : QStringLiteral("已加载 %1 个值，结果不完整：%2").arg(count).arg(listing->warning));
    int selectedRow = -1;
    for (int row = 0; row < count; ++row)
        if (m_valueTable->item(row, 0)->data(Qt::UserRole).toString() == selectedName)
        { selectedRow = row; break; }
    if (selectedRow < 0)
        for (int row = 0; row < count; ++row) if (!m_valueTable->isRowHidden(row)) { selectedRow = row; break; }
    if (selectedRow >= 0)
    {
        QSignalBlocker blocked(m_valueTable);
        m_valueTable->selectRow(selectedRow);
    }
    if (selectedRow >= 0) loadSelectedValue();
    else m_editorContextLabel->setText(ks::i18n::sourceText(QStringLiteral("当前键没有可见值。")));
}

void RegistryDock::addLocationTab(const QString& path)
{
    if (!preserveEditorDraft()) return;
    const int index = m_locationTabs->addTab(locationLabel(path));
    m_locationTabs->setTabData(index, path);
    m_locationTabs->setTabToolTip(index, path);
    m_locationTabs->setCurrentIndex(index);
}

void RegistryDock::showNavigationMenu()
{
    QMenu menu(this);
    applyWorkbenchMenuTheme(menu);
    menu.setObjectName(QStringLiteral("registry_workbench_navigation_menu"));
    QAction* toggle = menu.addAction(m_favoritePaths.contains(m_currentPath)
        ? QStringLiteral("移除当前收藏") : QStringLiteral("收藏当前键"));
    menu.addSeparator();
    for (const QString& path : m_favoritePaths)
    { auto* action = menu.addAction(path); action->setData(path); }
    menu.addSeparator();
    auto* history = menu.addMenu(QStringLiteral("最近访问"));
    applyWorkbenchMenuTheme(*history);
    history->setObjectName(QStringLiteral("registry_workbench_history_menu"));
    const qsizetype count = static_cast<qsizetype>(m_navigationHistory.size());
    for (qsizetype i = count; i > qMax<qsizetype>(0, count - 20); --i)
    { const QString path = m_navigationHistory.at(static_cast<size_t>(i - 1)); auto* action = history->addAction(path); action->setData(path); }
    QAction* selected = menu.exec(QCursor::pos());
    if (selected == toggle)
    {
        if (!m_favoritePaths.removeAll(m_currentPath)) m_favoritePaths.push_back(m_currentPath);
        QSettings().setValue(QStringLiteral("RegistryWorkbench/Favorites"), m_favoritePaths);
    }
    else if (selected && !selected->data().toString().isEmpty()) navigateToPath(selected->data().toString(), true);
}
