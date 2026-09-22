#include "ContextMenuCleanerTab.h"
#include "../../Framework/PrivilegeElevationPrompt.h"
#include "../../UI/VisibleTableWidget.h"
#include "../../UI/CodeEditorWidget.h"
#include "../../UI/DetailLayoutRegistry.h"

#include "ContextMenuCleanerTab.Internal.h"
#include "../../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QStringList>

#include <array>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

ContextMenuCleanerTab::ContextMenuCleanerTab(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    refreshArea(MenuArea::InternetExplorer);

    kLogEvent event;
    info << event << "[ContextMenuCleanerTab] 右键菜单清理页初始化完成。" << eol;
}

void ContextMenuCleanerTab::initializeUi()
{
    // 根布局：上方风险说明，下方七类 Shell 关联子页。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    m_areaTabWidget = new QTabWidget(this);
    m_areaTabWidget->setObjectName(QStringLiteral("ksContextMenuCleanerAreaTabs"));
    m_rootLayout->addWidget(m_areaTabWidget, 1);

    createAreaPage(MenuArea::InternetExplorer);
    createAreaPage(MenuArea::Desktop);
    createAreaPage(MenuArea::File);
    createAreaPage(MenuArea::UrlBinding);
    createAreaPage(MenuArea::OpenWith);
    createAreaPage(MenuArea::FormatMenu);
    createAreaPage(MenuArea::ExplorerHome);

    // 页签按需加载：
    // - URL/格式菜单会扫描大量 Classes 子键，不在杂项页构造时一次性阻塞 UI；
    // - 用户首次切换到分类时枚举一次，之后仅由刷新按钮主动重扫。
    const std::array<MenuArea, 7> orderedAreas{
        MenuArea::InternetExplorer,
        MenuArea::Desktop,
        MenuArea::File,
        MenuArea::UrlBinding,
        MenuArea::OpenWith,
        MenuArea::FormatMenu,
        MenuArea::ExplorerHome
    };
    connect(
        m_areaTabWidget,
        &QTabWidget::currentChanged,
        this,
        [this, orderedAreas](const int tabIndex) {
            if (tabIndex < 0
                || tabIndex >= static_cast<int>(orderedAreas.size()))
            {
                return;
            }
            const MenuArea area = orderedAreas[static_cast<std::size_t>(tabIndex)];
            AreaWidgets* areaWidgets = widgetsForArea(area);
            if (areaWidgets != nullptr && !areaWidgets->hasLoaded)
            {
                refreshArea(area);
            }
        });
}

void ContextMenuCleanerTab::createAreaPage(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    areaWidgets->page = new QWidget(m_areaTabWidget);
    areaWidgets->layout = new QVBoxLayout(areaWidgets->page);
    areaWidgets->layout->setContentsMargins(0, 0, 0, 0);
    areaWidgets->layout->setSpacing(6);

    areaWidgets->toolbarWidget = new QWidget(areaWidgets->page);
    QHBoxLayout* toolbarLayout = new QHBoxLayout(areaWidgets->toolbarWidget);
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(6);
    areaWidgets->layout->addWidget(areaWidgets->toolbarWidget);

    areaWidgets->refreshButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("刷新"), areaWidgets->toolbarWidget);
    areaWidgets->refreshButton->setToolTip(QStringLiteral("重新枚举当前分类的 Shell 关联注册表项目"));
    areaWidgets->deleteButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("删除选中"), areaWidgets->toolbarWidget);
    // 备份口径按分类不同，挂在删除按钮上比页首一段通用说明更贴近实际动作。
    areaWidgets->deleteButton->setToolTip(
        area == MenuArea::UrlBinding
            ? QStringLiteral("删除表格选中项对应的注册表子树或值。本分类删除前会自动备份，可用「恢复上次删除」还原；更改后通常需要重启 Explorer 或相关程序才会完全刷新。")
            : QStringLiteral("删除表格选中项对应的注册表子树或值。本分类不会自动备份；更改后通常需要重启 Explorer 或相关程序才会完全刷新。"));
    if (area == MenuArea::UrlBinding)
    {
        areaWidgets->restoreButton = new QPushButton(
            QIcon(QStringLiteral(":/Icon/codeeditor_undo.svg")),
            QStringLiteral("恢复上次删除"),
            areaWidgets->toolbarWidget);
        areaWidgets->restoreButton->setToolTip(QStringLiteral("恢复上一次 URL 绑定删除前自动保存的注册表树"));
    }
    areaWidgets->copyButton = new QPushButton(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制路径"), areaWidgets->toolbarWidget);
    areaWidgets->copyButton->setToolTip(QStringLiteral("复制选中项的注册表路径"));
    areaWidgets->filterEdit = new QLineEdit(areaWidgets->toolbarWidget);
    areaWidgets->filterEdit->setClearButtonEnabled(true);
    areaWidgets->filterEdit->setPlaceholderText(QStringLiteral("筛选：名称/显示名/命令/注册表路径/CLSID"));
    areaWidgets->filterEdit->setStyleSheet(buildInputStyle());

    areaWidgets->refreshButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    areaWidgets->deleteButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    if (areaWidgets->restoreButton != nullptr)
    {
        areaWidgets->restoreButton->setStyleSheet(KswordTheme::ThemedButtonStyle());
    }
    areaWidgets->copyButton->setStyleSheet(KswordTheme::ThemedButtonStyle());

    toolbarLayout->addWidget(areaWidgets->refreshButton);
    toolbarLayout->addWidget(areaWidgets->deleteButton);
    if (areaWidgets->restoreButton != nullptr)
    {
        toolbarLayout->addWidget(areaWidgets->restoreButton);
    }
    toolbarLayout->addWidget(areaWidgets->copyButton);
    toolbarLayout->addWidget(areaWidgets->filterEdit, 1);

    // 表格与详情编辑器必须放进同一个竖直分隔器：
    // DetailLayoutHost 靠它识别“表格 + 详情”这一对控件，并接管四种详情布局。
    QSplitter* splitter = new QSplitter(Qt::Vertical, areaWidgets->page);
    areaWidgets->table = new ks::ui::VisibleTableWidget(splitter);
    areaWidgets->table->setColumnCount(kColumnCount);
    areaWidgets->table->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("名称"),
        QStringLiteral("显示名"),
        QStringLiteral("类型"),
        QStringLiteral("来源"),
        QStringLiteral("命令/处理器"),
        QStringLiteral("注册表位置"),
        QStringLiteral("状态"),
        QStringLiteral("详情") });
    areaWidgets->table->setSelectionBehavior(QAbstractItemView::SelectRows);
    areaWidgets->table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    areaWidgets->table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    areaWidgets->table->setAlternatingRowColors(true);
    areaWidgets->table->setContextMenuPolicy(Qt::CustomContextMenu);
    areaWidgets->table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    areaWidgets->table->setSortingEnabled(true);
    areaWidgets->table->verticalHeader()->setVisible(false);
    areaWidgets->table->horizontalHeader()->setStyleSheet(buildHeaderStyle());
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnName, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnDisplayName, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnKind, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnSource, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnCommandOrHandler, QHeaderView::Stretch);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnRegistryPath, QHeaderView::Stretch);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnStatus, QHeaderView::ResizeToContents);
    areaWidgets->table->horizontalHeader()->setSectionResizeMode(kColumnDetail, QHeaderView::Stretch);

    // 详情编辑器：只读，承载当前选中行的完整信息。
    // 这里只用既有字段拼文本，不新增表格列，也不改枚举逻辑。
    areaWidgets->detailEditor = new CodeEditorWidget(splitter);
    areaWidgets->detailEditor->setReadOnly(true);
    splitter->setStretchFactor(0, 4);
    splitter->setStretchFactor(1, 2);
    areaWidgets->layout->addWidget(splitter, 1);

    // 注册进详情布局系统：四种布局（下方折叠 / 行内展开 / 独立窗口 / 右侧）由全局设置决定，
    // 本页只负责把选中行的文本写进 detailEditor，其余布局与展开状态全部由宿主维护。
    ks::ui::DetailLayoutRegistry::registerHost(
        areaWidgets->table,
        areaWidgets->detailEditor,
        areaWidgets->page);

    areaWidgets->statusLabel = new QLabel(QStringLiteral("尚未刷新。"), areaWidgets->page);
    areaWidgets->statusLabel->setWordWrap(true);
    areaWidgets->layout->addWidget(areaWidgets->statusLabel);

    connect(areaWidgets->refreshButton, &QPushButton::clicked, this, [this, area]() {
        refreshArea(area);
    });
    connect(areaWidgets->deleteButton, &QPushButton::clicked, this, [this, area]() {
        deleteSelectedEntries(area);
    });
    if (areaWidgets->restoreButton != nullptr)
    {
        connect(areaWidgets->restoreButton, &QPushButton::clicked, this, [this]() {
            restoreLastUrlBindingBackup();
        });
    }
    connect(areaWidgets->copyButton, &QPushButton::clicked, this, [this, area]() {
        copySelectedEntries(area);
    });
    connect(areaWidgets->filterEdit, &QLineEdit::textChanged, this, [this, area](const QString&) {
        rebuildAreaTable(area);
    });
    connect(areaWidgets->table, &QTableWidget::customContextMenuRequested, this, [this, area](const QPoint& localPosition) {
        showAreaContextMenu(area, localPosition);
    });
    // 选中行变化 → 重写详情文本；详情宿主随后按当前布局方案把它镜像出去
    // （下方折叠展开该区、行内插入合成行、独立窗口刷新、右侧面板刷新）。
    connect(areaWidgets->table, &QTableWidget::itemSelectionChanged, this, [this, area]() {
        updateAreaDetail(area);
    });

    m_areaTabWidget->addTab(areaWidgets->page, QIcon(areaIconPath(area)), areaTitle(area));
}

void ContextMenuCleanerTab::refreshArea(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<ContextMenuEntry> newEntries = enumerateEntriesForArea(area);
    areaWidgets->entries = newEntries;
    areaWidgets->hasLoaded = true;
    rebuildAreaTable(area);

    kLogEvent event;
    info << event
        << "[ContextMenuCleanerTab] 刷新分类完成, area="
        << areaTitle(area).toStdString()
        << ", count="
        << newEntries.size()
        << eol;
}

void ContextMenuCleanerTab::rebuildAreaTable(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr)
    {
        return;
    }

    const QString filterText = areaWidgets->filterEdit != nullptr
        ? areaWidgets->filterEdit->text().trimmed().toLower()
        : QString();

    // 重建数据前先让详情宿主收起行内详情：合成的行内控件引用的是即将失效的源行。
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(areaWidgets->detailEditor);

    areaWidgets->table->setSortingEnabled(false);
    areaWidgets->table->setRowCount(0);

    int visibleCount = 0;
    for (int entryIndex = 0; entryIndex < areaWidgets->entries.size(); ++entryIndex)
    {
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        const QString searchableText = QStringList{
            entry.itemName,
            entry.displayName,
            entry.entryKind,
            entry.sourceGroup,
            entry.commandOrHandler,
            registryTargetPathText(
                entry.rootLabel,
                entry.subKeyPath,
                entry.deleteKind == DeleteKind::RegistryValue,
                entry.valueName),
            entry.statusText,
            entry.detailText,
            entry.clsidText }.join('\n').toLower();
        if (!filterText.isEmpty() && !searchableText.contains(filterText))
        {
            continue;
        }

        const int row = visibleCount++;
        areaWidgets->table->insertRow(row);

        const auto makeItem = [entryIndex](const QString& text) -> QTableWidgetItem*
        {
            QTableWidgetItem* item = new QTableWidgetItem(text);
            item->setData(Qt::UserRole, entryIndex);
            item->setToolTip(text);
            return item;
        };

        areaWidgets->table->setItem(row, kColumnName, makeItem(entry.itemName));
        areaWidgets->table->setItem(row, kColumnDisplayName, makeItem(entry.displayName));
        areaWidgets->table->setItem(row, kColumnKind, makeItem(entry.entryKind));
        areaWidgets->table->setItem(row, kColumnSource, makeItem(entry.sourceGroup));
        areaWidgets->table->setItem(row, kColumnCommandOrHandler, makeItem(entry.commandOrHandler));
        areaWidgets->table->setItem(
            row,
            kColumnRegistryPath,
            makeItem(registryTargetPathText(
                entry.rootLabel,
                entry.subKeyPath,
                entry.deleteKind == DeleteKind::RegistryValue,
                entry.valueName)));
        areaWidgets->table->setItem(row, kColumnStatus, makeItem(entry.statusText));
        areaWidgets->table->setItem(row, kColumnDetail, makeItem(entry.detailText));
    }

    areaWidgets->table->setSortingEnabled(true);
    if (areaWidgets->statusLabel != nullptr)
    {
        areaWidgets->statusLabel->setText(QStringLiteral("%1：共枚举 %2 项，当前显示 %3 项。")
            .arg(areaTitle(area))
            .arg(areaWidgets->entries.size())
            .arg(visibleCount));
    }

    // 重建后选中行已失效：重新同步一次详情文本（无选中行则回到引导占位）。
    updateAreaDetail(area);
}

void ContextMenuCleanerTab::showAreaContextMenu(const MenuArea area, const QPoint& localPosition)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr)
    {
        return;
    }

    QMenu menu(areaWidgets->table);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyAction = menu.addAction(QIcon(QStringLiteral(":/Icon/log_copy.svg")), QStringLiteral("复制注册表路径"));
    QAction* deleteAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_terminate.svg")), QStringLiteral("删除选中项"));

    const QVector<int> selectedIndexes = selectedEntryIndexes(area);
    bool hasDeleteableEntry = false;
    for (const int entryIndex : selectedIndexes)
    {
        if (entryIndex >= 0
            && entryIndex < areaWidgets->entries.size()
            && areaWidgets->entries.at(entryIndex).canDelete)
        {
            hasDeleteableEntry = true;
            break;
        }
    }
    copyAction->setEnabled(!selectedIndexes.isEmpty());
    deleteAction->setEnabled(hasDeleteableEntry);

    QAction* selectedAction = menu.exec(areaWidgets->table->viewport()->mapToGlobal(localPosition));
    if (selectedAction == copyAction)
    {
        copySelectedEntries(area);
    }
    else if (selectedAction == deleteAction)
    {
        deleteSelectedEntries(area);
    }
}

void ContextMenuCleanerTab::deleteSelectedEntries(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<int> selectedIndexes = selectedEntryIndexes(area);
    if (selectedIndexes.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("Shell 关联管理"), QStringLiteral("请先选择需要删除的注册表项目。"));
        return;
    }

    QStringList targetPaths;
    QVector<int> deleteableIndexes;
    int machineScopeTargetCount = 0;
    for (const int entryIndex : selectedIndexes)
    {
        if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        if (!entry.canDelete
            || (area == MenuArea::UrlBinding && !isUrlBindingDeletionAllowed(entry)))
        {
            continue;
        }
        deleteableIndexes.push_back(entryIndex);
        if (entry.rootKey == HKEY_LOCAL_MACHINE)
        {
            ++machineScopeTargetCount;
        }
        targetPaths.push_back(registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::RegistryValue,
            entry.valueName));
    }
    if (deleteableIndexes.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("Shell 关联管理"),
            QStringLiteral("选中项属于受保护的系统注册，当前页面不允许删除。"));
        return;
    }

    const QString previewText = targetPaths.mid(0, 8).join('\n');
    const QString moreText = targetPaths.size() > 8
        ? QStringLiteral("\n... 另有 %1 项").arg(targetPaths.size() - 8)
        : QString();
    const QString machineScopeWarning = machineScopeTargetCount > 0
        ? QStringLiteral("\n\n高风险警告：其中 %1 项位于 HKLM，修改会影响所有用户，错误删除可能使协议、应用入口或系统功能失效。KSword 不限制此操作，但只应在确认目标属于第三方软件时继续；恢复 HKLM 备份需要管理员权限。")
            .arg(machineScopeTargetCount)
        : QString();
    const QString confirmationText = area == MenuArea::UrlBinding
        ? QStringLiteral("将删除 %1 个 URL 绑定注册表子树。删除前会自动备份，可通过“恢复上次删除”还原。%2\n\n%3%4")
            .arg(targetPaths.size())
            .arg(machineScopeWarning)
            .arg(previewText)
            .arg(moreText)
        : QStringLiteral("将删除 %1 个注册表子树或值。此操作不会自动备份，删除后通常需要重启 Explorer 或相关程序才会完全生效。\n\n%2%3")
            .arg(targetPaths.size())
            .arg(previewText)
            .arg(moreText);
    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        QStringLiteral("确认删除注册表项目"),
        confirmationText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirmButton != QMessageBox::Yes)
    {
        return;
    }

    if (area == MenuArea::UrlBinding)
    {
        QString backupError;
        if (!createUrlBindingBackup(deleteableIndexes, &backupError))
        {
            QMessageBox::critical(
                this,
                QStringLiteral("URL 绑定备份失败"),
                QStringLiteral("删除已取消，因为无法建立可恢复备份：\n\n%1").arg(backupError));
            return;
        }
    }

    QStringList failedMessages;
    int successCount = 0;
    // privilegePromptHandled：批量删除中最多显示一次权限恢复提示，并抑制最终重复失败框。
    bool privilegePromptHandled = false;
    for (const int entryIndex : deleteableIndexes)
    {
        if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        if (area == MenuArea::UrlBinding && !isUrlBindingDeletionAllowed(entry))
        {
            failedMessages.push_back(QStringLiteral("%1：执行时安全校验拒绝删除")
                .arg(registryTargetPathText(
                    entry.rootLabel,
                    entry.subKeyPath,
                    entry.deleteKind == DeleteKind::RegistryValue,
                    entry.valueName)));
            continue;
        }
        QString errorText;
        const bool deleteOk = entry.deleteKind == DeleteKind::RegistryValue
            ? deleteRegistryValueWithView(
                entry.rootKey,
                entry.subKeyPath,
                entry.valueName,
                entry.viewFlag,
                entry.cleanupOpenWithMru,
                &errorText)
            : deleteRegistryTreeWithView(
                entry.rootKey,
                entry.subKeyPath,
                entry.viewFlag,
                &errorText);
        const QString targetPath = registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::RegistryValue,
            entry.valueName);
        if (deleteOk)
        {
            ++successCount;
            kLogEvent event;
            warn << event
                << "[ContextMenuCleanerTab] 删除 Shell 关联注册表项目成功, path="
                << targetPath.toStdString()
                << eol;
        }
        else
        {
            if (!privilegePromptHandled)
            {
                privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("清理 Shell 关联注册表项目"),
                    errorText);
            }
            failedMessages.push_back(QStringLiteral("%1：%2")
                .arg(targetPath, errorText));
            kLogEvent event;
            err << event
                << "[ContextMenuCleanerTab] 删除 Shell 关联注册表项目失败, path="
                << targetPath.toStdString()
                << ", error="
                << errorText.toStdString()
                << eol;
        }
    }

    refreshArea(area);

    if (failedMessages.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("Shell 关联管理"),
            QStringLiteral("已删除 %1 项。建议重启 Explorer 或相关程序后确认变化。").arg(successCount));
    }
    else
    {
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("Shell 关联管理"),
                QStringLiteral("成功删除 %1 项，失败 %2 项：\n\n%3")
                    .arg(successCount)
                    .arg(failedMessages.size())
                    .arg(failedMessages.join('\n')));
        }
    }
}

void ContextMenuCleanerTab::copySelectedEntries(const MenuArea area) const
{
    const AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr)
    {
        return;
    }

    const QVector<int> selectedIndexes = selectedEntryIndexes(area);
    if (selectedIndexes.isEmpty())
    {
        QMessageBox::information(const_cast<ContextMenuCleanerTab*>(this), QStringLiteral("复制注册表路径"), QStringLiteral("请先选择需要复制的行。"));
        return;
    }

    QStringList lines;
    for (const int entryIndex : selectedIndexes)
    {
        if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
        {
            continue;
        }
        const ContextMenuEntry& entry = areaWidgets->entries.at(entryIndex);
        lines.push_back(registryTargetPathText(
            entry.rootLabel,
            entry.subKeyPath,
            entry.deleteKind == DeleteKind::RegistryValue,
            entry.valueName));
    }

    if (QClipboard* clipboard = QApplication::clipboard())
    {
        clipboard->setText(lines.join('\n'));
    }
}


QVector<int> ContextMenuCleanerTab::selectedEntryIndexes(const MenuArea area) const
{
    const AreaWidgets* areaWidgets = widgetsForArea(area);
    QVector<int> indexes;
    if (areaWidgets == nullptr || areaWidgets->table == nullptr || areaWidgets->table->selectionModel() == nullptr)
    {
        return indexes;
    }

    const QModelIndexList selectedRows = areaWidgets->table->selectionModel()->selectedRows();
    for (const QModelIndex& modelIndex : selectedRows)
    {
        const QTableWidgetItem* item = areaWidgets->table->item(modelIndex.row(), kColumnName);
        if (item == nullptr)
        {
            continue;
        }
        const int entryIndex = item->data(Qt::UserRole).toInt();
        if (!indexes.contains(entryIndex))
        {
            indexes.push_back(entryIndex);
        }
    }
    return indexes;
}

ContextMenuCleanerTab::AreaWidgets* ContextMenuCleanerTab::widgetsForArea(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return &m_ieWidgets;
    case MenuArea::Desktop:
        return &m_desktopWidgets;
    case MenuArea::File:
        return &m_fileWidgets;
    case MenuArea::UrlBinding:
        return &m_urlBindingWidgets;
    case MenuArea::OpenWith:
        return &m_openWithWidgets;
    case MenuArea::FormatMenu:
        return &m_formatMenuWidgets;
    case MenuArea::ExplorerHome:
        return &m_explorerHomeWidgets;
    }
    return &m_fileWidgets;
}

const ContextMenuCleanerTab::AreaWidgets* ContextMenuCleanerTab::widgetsForArea(const MenuArea area) const
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return &m_ieWidgets;
    case MenuArea::Desktop:
        return &m_desktopWidgets;
    case MenuArea::File:
        return &m_fileWidgets;
    case MenuArea::UrlBinding:
        return &m_urlBindingWidgets;
    case MenuArea::OpenWith:
        return &m_openWithWidgets;
    case MenuArea::FormatMenu:
        return &m_formatMenuWidgets;
    case MenuArea::ExplorerHome:
        return &m_explorerHomeWidgets;
    }
    return &m_fileWidgets;
}

QString ContextMenuCleanerTab::areaTitle(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return QStringLiteral("IE右键菜单");
    case MenuArea::Desktop:
        return QStringLiteral("桌面右键菜单");
    case MenuArea::File:
        return QStringLiteral("文件右键菜单");
    case MenuArea::UrlBinding:
        return QStringLiteral("URL 绑定");
    case MenuArea::OpenWith:
        return QStringLiteral("文件打开方式");
    case MenuArea::FormatMenu:
        return QStringLiteral("格式右键菜单");
    case MenuArea::ExplorerHome:
        return QStringLiteral("资源管理器主页第三方程序");
    }
    return QStringLiteral("文件右键菜单");
}

QString ContextMenuCleanerTab::areaIconPath(const MenuArea area)
{
    switch (area)
    {
    case MenuArea::InternetExplorer:
        return QStringLiteral(":/Icon/process_list.svg");
    case MenuArea::Desktop:
        return QStringLiteral(":/Icon/desktop_switch.svg");
    case MenuArea::File:
        return QStringLiteral(":/Icon/process_open_folder.svg");
    case MenuArea::UrlBinding:
        return QStringLiteral(":/Icon/log_track.svg");
    case MenuArea::OpenWith:
        return QStringLiteral(":/Icon/process_open_folder.svg");
    case MenuArea::FormatMenu:
        return QStringLiteral(":/Icon/process_list.svg");
    case MenuArea::ExplorerHome:
        return QStringLiteral(":/Icon/desktop_switch.svg");
    }
    return QStringLiteral(":/Icon/process_open_folder.svg");
}

void ContextMenuCleanerTab::updateAreaDetail(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr ||
        areaWidgets->table == nullptr ||
        areaWidgets->detailEditor == nullptr)
    {
        return;
    }

    // 行 → 条目的映射沿用表格项 Qt::UserRole 里保存的 entries 下标：
    // 排序或筛选后 visual row 会变，但 UserRole 始终指向原始快照，因此这里不需要额外的对应表。
    const int currentRow = areaWidgets->table->currentRow();
    if (currentRow < 0)
    {
        applyAreaDetailPlaceholder(area);
        return;
    }

    const QTableWidgetItem* anchorItem = areaWidgets->table->item(currentRow, kColumnName);
    const int entryIndex = anchorItem != nullptr ? anchorItem->data(Qt::UserRole).toInt() : -1;
    if (entryIndex < 0 || entryIndex >= areaWidgets->entries.size())
    {
        applyAreaDetailPlaceholder(area);
        return;
    }

    // setText 在只读模式下按“程序生成的报告”处理：随语言切换重绘，也不会被误当成用户文件原文。
    // 详情文本一变，DetailLayoutHost 就会按当前布局方案把它镜像到下方折叠区 / 行内 / 独立窗口。
    areaWidgets->detailEditor->setText(buildEntryDetailText(areaWidgets->entries.at(entryIndex)));
}

void ContextMenuCleanerTab::applyAreaDetailPlaceholder(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->detailEditor == nullptr)
    {
        return;
    }

    // 未刷新或未选中任何行时的引导文本：说明这一页能给出哪些信息，避免详情区一片空白。
    // 整段写成一个字面量（不跨行拼接），这样 i18n 审计只需要登记一条源串。
    areaWidgets->detailEditor->setText(QStringLiteral("【%1 详情】\n\n在上方表格中选择一行，这里显示该条 Shell 关联的完整信息：注册表根键与精确位置、命令或 CLSID 处理器、状态标记与删除粒度。\n\n详情显示方式可在设置中切换：下方折叠（默认）、行内展开、独立窗口、右侧面板。").arg(areaTitle(area)));
}

QString ContextMenuCleanerTab::buildEntryDetailText(const ContextMenuEntry& entry) const
{
    // 只用枚举阶段已经采集到的字段拼装文本，不新增数据来源，也不改表格列；
    // CLSID 友好名与服务器路径复用 Internal.h 里既有的 HKCR 查询 helper。
    QStringList lines;
    lines.push_back(QStringLiteral("【%1】").arg(
        entry.displayName.isEmpty() ? entry.itemName : entry.displayName));
    lines.push_back(QString());
    lines.push_back(QStringLiteral("分类        ：%1").arg(areaTitle(entry.area)));
    lines.push_back(QStringLiteral("名称        ：%1").arg(entry.itemName));
    lines.push_back(QStringLiteral("显示名      ：%1").arg(entry.displayName));
    lines.push_back(QStringLiteral("类型        ：%1").arg(entry.entryKind));
    lines.push_back(QStringLiteral("来源        ：%1").arg(entry.sourceGroup));
    lines.push_back(QStringLiteral("根键        ：%1").arg(entry.rootLabel));
    lines.push_back(QStringLiteral("注册表位置  ：%1").arg(registryTargetPathText(
        entry.rootLabel,
        entry.subKeyPath,
        entry.deleteKind == DeleteKind::RegistryValue,
        entry.valueName)));
    lines.push_back(QStringLiteral("命令/处理器 ：%1").arg(entry.commandOrHandler));
    lines.push_back(QStringLiteral("状态        ：%1").arg(entry.statusText));

    if (!entry.clsidText.isEmpty())
    {
        lines.push_back(QString());
        lines.push_back(QStringLiteral("CLSID       ：%1").arg(entry.clsidText));
        const QString friendlyName = queryClsidFriendlyName(entry.clsidText);
        if (!friendlyName.isEmpty())
        {
            lines.push_back(QStringLiteral("CLSID 名称  ：%1").arg(friendlyName));
        }
        const QString serverPath = queryClsidServerPath(entry.clsidText);
        if (!serverPath.isEmpty())
        {
            lines.push_back(QStringLiteral("服务器      ：%1").arg(serverPath));
        }
    }

    if (!entry.detailText.isEmpty())
    {
        lines.push_back(QString());
        lines.push_back(QStringLiteral("补充详情："));
        lines.push_back(entry.detailText);
    }

    lines.push_back(QString());
    lines.push_back(QStringLiteral("删除粒度    ：%1").arg(
        entry.deleteKind == DeleteKind::RegistryValue
            ? QStringLiteral("仅删除注册表值 %1").arg(entry.valueName)
            : QStringLiteral("删除整棵子键树")));
    lines.push_back(QStringLiteral("本页可删除  ：%1").arg(
        entry.canDelete
            ? QStringLiteral("是")
            : QStringLiteral("否（系统保护项或受策略限制）")));

    return lines.join('\n');
}

} // namespace ks::misc
