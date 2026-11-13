#include "StartupDock.Internal.h"
#include "../UI/TableContextMenu.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../Framework/PrivilegeElevationPrompt.h"

#include <QMetaObject>
#include <QSaveFile>
#include "../UI/AsyncOperation.h"
#include "../UI/TableRowFilterSupport.h"

using namespace startup_dock_detail;

namespace
{
    QString startupToggleActionText(const bool enabled)
    {
        return enabled
            ? startupText("startup.menu.enable", QStringLiteral("启用"))
            : startupText("startup.menu.disable", QStringLiteral("禁用"));
    }

    QString startupToggleImpactText(
        const ks::startup::StartupActionKind actionKind,
        const bool enabled)
    {
        switch (actionKind)
        {
        case ks::startup::StartupActionKind::RegistryRunValue:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.registry.enable",
                    QStringLiteral("将已停放的 Run 注册表值恢复到原位置；若原位置已被占用，不会覆盖现有值。"))
                : startupText(
                    "startup.dialog.toggle.impact.registry.disable",
                    QStringLiteral("将 Run 注册表值移入 KSword 的可恢复备份；原值数据会保留，便于重新启用。"));
        case ks::startup::StartupActionKind::RegistryTree:
            return startupText(
                "startup.dialog.toggle.impact.registry_tree",
                QStringLiteral("永久删除精确定位的注册表子树；此操作不会创建可恢复备份。"));
        case ks::startup::StartupActionKind::StartupFolderFile:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.startup_folder.enable",
                    QStringLiteral("将启动文件从 KSword 专用停放位置移回“启动”文件夹；若目标路径已存在，不会覆盖现有文件。"))
                : startupText(
                    "startup.dialog.toggle.impact.startup_folder.disable",
                    QStringLiteral("将启动文件移到 KSword 专用停放位置；文件内容会保留，之后可以重新启用。"));
        case ks::startup::StartupActionKind::ScheduledTask:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.task.enable",
                    QStringLiteral("重新启用计划任务，并保留其现有触发器与操作配置。"))
                : startupText(
                    "startup.dialog.toggle.impact.task.disable",
                    QStringLiteral("禁用计划任务，但保留任务定义、触发器与操作配置，之后可以重新启用。"));
        case ks::startup::StartupActionKind::ScmStartType:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.scm.enable",
                    QStringLiteral("把服务设置为自动启动，或把驱动设置为系统启动；不会立即启动当前服务或驱动。"))
                : startupText(
                    "startup.dialog.toggle.impact.scm.disable",
                    QStringLiteral("把服务控制管理器启动类型设为“已禁用”；当前正在运行的实例不会被停止。"));
        case ks::startup::StartupActionKind::WmiEntryRemoval:
            return startupText(
                "startup.dialog.toggle.impact.wmi.disable",
                QStringLiteral("永久删除精确匹配的 WMI 永久事件对象；此操作不会创建可恢复备份。"));
        case ks::startup::StartupActionKind::None:
        default:
            return enabled
                ? startupText(
                    "startup.dialog.toggle.impact.generic.enable",
                    QStringLiteral("后端将使用已保存的结构化定位信息恢复该启动项。"))
                : startupText(
                    "startup.dialog.toggle.impact.generic.disable",
                    QStringLiteral("后端将保留恢复信息并以可逆方式禁用该启动项。"));
        }
    }

    QString startupToggleRecoveryText(const ks::startup::StartupActionKind actionKind)
    {
        switch (actionKind)
        {
        case ks::startup::StartupActionKind::RegistryRunValue:
        case ks::startup::StartupActionKind::StartupFolderFile:
        case ks::startup::StartupActionKind::ScheduledTask:
            return startupText(
                "startup.dialog.toggle.recovery.reversible",
                QStringLiteral("此操作保留恢复信息或原始对象，可通过右键菜单尝试改回原状态。"));
        case ks::startup::StartupActionKind::ScmStartType:
            return startupText(
                "startup.dialog.toggle.recovery.scm",
                QStringLiteral("重新启用会使用默认的自动/系统启动类型，不保证恢复修改前的精确启动类型。"));
        case ks::startup::StartupActionKind::RegistryTree:
        case ks::startup::StartupActionKind::WmiEntryRemoval:
            return startupText(
                "startup.dialog.toggle.recovery.irreversible",
                QStringLiteral("此操作不可由 KSword 恢复；继续前请自行确认已有可用备份。"));
        case ks::startup::StartupActionKind::None:
        default:
            return startupText(
                "startup.dialog.toggle.recovery.generic",
                QStringLiteral("该修改可能不可恢复，请在继续前确认影响和备份。"));
        }
    }

    QString startupRiskLevelText(const ks::startup::StartupRiskLevel riskLevel)
    {
        switch (riskLevel)
        {
        case ks::startup::StartupRiskLevel::Normal:
            return startupText("startup.risk_level.normal", QStringLiteral("普通"));
        case ks::startup::StartupRiskLevel::Critical:
            return startupText("startup.risk_level.critical", QStringLiteral("严重"));
        case ks::startup::StartupRiskLevel::Elevated:
        default:
            return startupText("startup.risk_level.elevated", QStringLiteral("较高"));
        }
    }

    QString startupActionStatusText(const ks::startup::StartupActionStatus status)
    {
        switch (status)
        {
        case ks::startup::StartupActionStatus::Success:
            return startupText("startup.dialog.toggle.status.success", QStringLiteral("成功"));
        case ks::startup::StartupActionStatus::NoChange:
            return startupText("startup.dialog.toggle.status.no_change", QStringLiteral("状态未变化"));
        case ks::startup::StartupActionStatus::InvalidEntry:
            return startupText("startup.dialog.toggle.status.invalid_entry", QStringLiteral("条目无效"));
        case ks::startup::StartupActionStatus::NotSupported:
            return startupText("startup.dialog.toggle.status.not_supported", QStringLiteral("来源类型不受支持"));
        case ks::startup::StartupActionStatus::Conflict:
            return startupText("startup.dialog.toggle.status.conflict", QStringLiteral("目标位置存在冲突"));
        case ks::startup::StartupActionStatus::NotFound:
            return startupText("startup.dialog.toggle.status.not_found", QStringLiteral("来源或备份不存在"));
        case ks::startup::StartupActionStatus::AccessDenied:
            return startupText("startup.dialog.toggle.status.access_denied", QStringLiteral("权限不足"));
        case ks::startup::StartupActionStatus::WriteFailed:
            return startupText("startup.dialog.toggle.status.write_failed", QStringLiteral("写入失败"));
        case ks::startup::StartupActionStatus::VerificationFailed:
            return startupText("startup.dialog.toggle.status.verification_failed", QStringLiteral("操作后验证失败"));
        case ks::startup::StartupActionStatus::RollbackFailed:
            return startupText("startup.dialog.toggle.status.rollback_failed", QStringLiteral("回滚失败"));
        case ks::startup::StartupActionStatus::ProcessFailed:
            return startupText("startup.dialog.toggle.status.process_failed", QStringLiteral("系统命令执行失败"));
        default:
            return startupText("startup.dialog.toggle.status.unknown", QStringLiteral("未知错误"));
        }
    }

    QString startupActionFailureText(const ks::startup::ActionResult& actionResult)
    {
        const QString backendMessageText = QString::fromUtf8(
            actionResult.messageText.c_str(),
            static_cast<qsizetype>(actionResult.messageText.size())).trimmed();
        // 权限回退失败保留固定可翻译前缀，API 阶段/原始错误作为诊断后缀原样显示。
        const QString permissionPrefix = QStringLiteral("服务删除权限不足，申请额外权限后仍无法继续。");
        const QString messageText = backendMessageText.startsWith(permissionPrefix)
            ? ks::i18n::sourceText(permissionPrefix) + backendMessageText.mid(permissionPrefix.size())
            : backendMessageText.isEmpty()
            ? backendMessageText
            : ks::i18n::sourceText(backendMessageText);
        QString detailText = startupText(
            "startup.dialog.toggle.failed.details",
            QStringLiteral("状态：%1\n详细信息：%2"))
            .arg(startupActionStatusText(actionResult.status))
            .arg(messageText.isEmpty()
                ? startupText(
                    "startup.dialog.toggle.failed.no_details",
                    QStringLiteral("后端未提供附加错误信息。"))
                : messageText);

        if (actionResult.errorCode != ERROR_SUCCESS)
        {
            detailText += QStringLiteral("\n");
            detailText += startupText(
                "startup.dialog.toggle.failed.win32",
                QStringLiteral("Win32 错误：%1"))
                .arg(winErrorText(actionResult.errorCode));
        }

        if (actionResult.rollbackAttempted)
        {
            detailText += QStringLiteral("\n");
            detailText += actionResult.rollbackSucceeded
                ? startupText(
                    "startup.dialog.toggle.rollback.succeeded",
                    QStringLiteral("安全回滚：已成功恢复操作前状态。"))
                : startupText(
                    "startup.dialog.toggle.rollback.failed",
                    QStringLiteral("安全回滚：失败，请在刷新后核对启动项和备份状态。"));
        }
        return detailText;
    }

    bool isStartupPrivilegeFailure(const ks::startup::ActionResult& actionResult)
    {
        return actionResult.status == ks::startup::StartupActionStatus::AccessDenied
            || actionResult.errorCode == ERROR_ACCESS_DENIED
            || actionResult.errorCode == ERROR_PRIVILEGE_NOT_HELD
            || actionResult.errorCode == ERROR_ELEVATION_REQUIRED;
    }

    QString startupTsvField(QString fieldText)
    {
        // 用可见控制字符替代 TSV 的行/列分隔符，确保一条启动项恒定占一行。
        fieldText.replace(QChar('\t'), QStringLiteral("␉"));
        fieldText.replace(QChar('\r'), QStringLiteral("␍"));
        fieldText.replace(QChar('\n'), QStringLiteral("␊"));
        return fieldText;
    }

    QString startupEntryTsvRow(const StartupDock::StartupEntry& entry)
    {
        QStringList fieldList{
            entry.itemNameText,
            entry.publisherText,
            entry.imagePathText,
            entry.commandText,
            entry.locationText,
            ks::i18n::sourceText(entry.userText),
            buildStatusText(entry.backendEntry),
            ks::i18n::sourceText(entry.sourceTypeText),
            startupLocalizedDetailText(entry.detailText)
        };
        for (QString& fieldText : fieldList)
        {
            fieldText = startupTsvField(fieldText);
        }
        return fieldList.join(QChar('\t'));
    }

}

void StartupDock::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestAsyncRefresh(true);
        });
    connect(m_exportButton, &QPushButton::clicked, this, [this]()
        {
            exportCurrentView();
        });
    connect(m_copyButton, &QPushButton::clicked, this, [this]()
        {
            copySelectedRow(currentCategory(), currentCategoryTable());
        });
    connect(m_filterEdit, &QLineEdit::textChanged, this, [this](const QString&)
        {
            scheduleFilterRefresh();
        });
    connect(m_hideMicrosoftCheck, &QCheckBox::toggled, this, [this](const bool)
        {
            applyFilterAndRefresh();
        });
    connect(m_hideEmptyPathCheck, &QCheckBox::toggled, this, [this](const bool)
        {
            applyFilterAndRefresh();
        });

    const auto bindTableContextMenu =
        [this](const StartupCategory category, QTableWidget* tableWidget)
        {
            if (tableWidget == nullptr)
            {
                return;
            }
            connect(tableWidget, &QWidget::customContextMenuRequested, this, [this, category, tableWidget](const QPoint& localPos)
                {
                    showEntryContextMenu(category, tableWidget, localPos);
                });
            connect(tableWidget, &QTableWidget::cellDoubleClicked, this, [this, category, tableWidget](const int row, const int /*column*/)
                {
                    if (row < 0)
                    {
                        return;
                    }
                    openSelectedFileLocation(category, tableWidget);
                });
        };

    bindTableContextMenu(StartupCategory::All, m_allTable);
    bindTableContextMenu(StartupCategory::Logon, m_logonTable);
    bindTableContextMenu(StartupCategory::Services, m_servicesTable);
    bindTableContextMenu(StartupCategory::Drivers, m_driversTable);
    bindTableContextMenu(StartupCategory::Tasks, m_tasksTable);
    bindTableContextMenu(StartupCategory::ImageHijack, m_imageHijackTable);
    bindTableContextMenu(StartupCategory::Wmi, m_wmiTable);
    bindTableContextMenu(StartupCategory::Hidden, m_hiddenTable);

    if (m_registryTree != nullptr)
    {
        connect(m_registryTree, &QWidget::customContextMenuRequested, this, [this](const QPoint& localPos)
            {
                showRegistryContextMenu(localPos);
            });
        connect(m_registryTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* treeItem, int)
            {
                if (treeItem == nullptr)
                {
                    return;
                }

                const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
                    treeItem->data(0, kStartupTreeNodeKindRole).toInt());
                if (nodeKind == StartupTreeNodeKind::Entry)
                {
                    openSelectedFileLocation(StartupCategory::Registry, nullptr);
                }
                else if (nodeKind == StartupTreeNodeKind::Group
                    || nodeKind == StartupTreeNodeKind::Placeholder)
                {
                    openSelectedRegistryLocation(StartupCategory::Registry, nullptr);
                }
            });
    }
}

void StartupDock::refreshAllStartupEntries()
{
    requestAsyncRefresh(true);
}

void StartupDock::showEntryContextMenu(
    const StartupCategory category,
    QTableWidget* tableWidget,
    const QPoint& localPos)
{
    if (tableWidget == nullptr || !isCategoryProjectionReady(category))
    {
        return;
    }

    QTableWidgetItem* clickedItem = tableWidget->itemAt(localPos);
    if (clickedItem == nullptr)
    {
        return;
    }
    QItemSelectionModel* const selectionModel = tableWidget->selectionModel();
    const QModelIndex clickedIndex = tableWidget->indexFromItem(clickedItem);
    if (selectionModel != nullptr && clickedIndex.isValid())
    {
        if (!selectionModel->isRowSelected(clickedIndex.row(), QModelIndex()))
        {
            selectionModel->select(
                clickedIndex,
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        }
        selectionModel->setCurrentIndex(clickedIndex, QItemSelectionModel::NoUpdate);
    }

    const int entryIndex = findEntryIndexByTableRow(category, clickedItem->row());
    if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
    {
        return;
    }

    const StartupEntry entry = m_entryList.at(static_cast<std::size_t>(entryIndex));
    std::vector<StartupEntry> selectedEntryList;
    if (selectionModel != nullptr)
    {
        const QModelIndexList selectedRowIndexList = selectionModel->selectedRows();
        selectedEntryList.reserve(static_cast<std::size_t>(selectedRowIndexList.size()));
        for (const QModelIndex& selectedRowIndex : selectedRowIndexList)
        {
            const int selectedEntryIndex = findEntryIndexByTableRow(
                category,
                selectedRowIndex.row());
            if (selectedEntryIndex >= 0
                && selectedEntryIndex < static_cast<int>(m_entryList.size()))
            {
                selectedEntryList.push_back(
                    m_entryList.at(static_cast<std::size_t>(selectedEntryIndex)));
            }
        }
    }
    if (selectedEntryList.empty())
    {
        selectedEntryList.push_back(entry);
    }

    QMenu contextMenu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.entry_details", QStringLiteral("查看启动项详细信息")));
    QAction* copyAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_copy.svg"),
        startupText("startup.menu.copy_row", QStringLiteral("复制整行")));
    // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
    ks::ui::SetTableContextActionRole(copyAction, ks::ui::TableContextActionRole::CopyRows);
    QAction* openFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_open_folder.svg"),
        startupText("startup.menu.open_file", QStringLiteral("打开文件位置")));
    QAction* filePropertiesAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.file_properties", QStringLiteral("转到文件属性")));
    QAction* openRegistryAction = contextMenu.addAction(
        createBlueIcon(":/Icon/file_find.svg"),
        startupText("startup.menu.open_registry", QStringLiteral("打开注册表位置")));
    QAction* gotoServiceAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_list.svg"),
        startupText("startup.menu.goto_service", QStringLiteral("转到服务管理")));
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [entry]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：启动项缓存行。
            // 处理：把镜像路径或命令行交给统一路径提取器。
            // 返回：待上传路径和来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            uploadTarget.filePath = entry.imagePathText;
            uploadTarget.sourceText = startupText(
                "startup.source.autostart",
                QStringLiteral("自启动项 %1"))
                .arg(entry.itemNameText);
            return uploadTarget;
        });
    contextMenu.addSeparator();
    const bool targetEnabled = !entry.enabled;
    const bool canApplyTargetStateToSelection = std::all_of(
        selectedEntryList.cbegin(),
        selectedEntryList.cend(),
        [targetEnabled](const StartupEntry& selectedEntry)
        {
            return selectedEntry.enabled == targetEnabled
                || (targetEnabled
                    ? selectedEntry.backendEntry.canEnable
                    : selectedEntry.backendEntry.canDisable);
        });
    const bool canDeleteSelection = std::all_of(
        selectedEntryList.cbegin(),
        selectedEntryList.cend(),
        [](const StartupEntry& selectedEntry)
        {
            return selectedEntry.canDelete && selectedEntry.backendEntry.canDelete;
        });
    QAction* toggleAction = contextMenu.addAction(
        createBlueIcon(targetEnabled ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"),
        startupToggleActionText(targetEnabled));
    QAction* deleteAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        startupText("startup.menu.delete", QStringLiteral("删除项")));
    openFileAction->setEnabled(entry.canOpenFileLocation);
    filePropertiesAction->setEnabled(entry.canOpenFileLocation);
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(entry.canOpenFileLocation && !entry.imagePathText.trimmed().isEmpty());
    }
    openRegistryAction->setEnabled(entry.canOpenRegistryLocation);
    gotoServiceAction->setEnabled(
        entry.category == StartupCategory::Services);
    toggleAction->setEnabled(
        canApplyTargetStateToSelection
        && !m_startupActionInProgress.load());
    deleteAction->setEnabled(
        canDeleteSelection
        && !m_startupActionInProgress.load());

    QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPos));
    if (selectedAction == detailAction)
    {
        showSelectedEntryDetails(category, tableWidget);
    }
    else if (selectedAction == copyAction)
    {
        copySelectedRow(category, tableWidget);
    }
    else if (selectedAction == openFileAction)
    {
        openSelectedFileLocation(category, tableWidget);
    }
    else if (selectedAction == filePropertiesAction)
    {
        openSelectedFileProperties(category, tableWidget);
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedRegistryLocation(category, tableWidget);
    }
    else if (selectedAction == gotoServiceAction)
    {
        QString serviceNameText;
        if (entry.uniqueIdText.startsWith(QStringLiteral("SERVICE|"), Qt::CaseInsensitive))
        {
            serviceNameText = entry.uniqueIdText.mid(QStringLiteral("SERVICE|").size()).trimmed();
        }
        if (serviceNameText.isEmpty())
        {
            const int lastSlashIndex = entry.locationText.lastIndexOf('\\');
            serviceNameText = (lastSlashIndex >= 0)
                ? entry.locationText.mid(lastSlashIndex + 1).trimmed()
                : entry.itemNameText.trimmed();
        }

        QWidget* mainWindowWidget = window();
        if (mainWindowWidget != nullptr && !serviceNameText.isEmpty())
        {
            QMetaObject::invokeMethod(
                mainWindowWidget,
                "focusServiceDockByName",
                Qt::QueuedConnection,
                Q_ARG(QString, serviceNameText));
        }
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == toggleAction)
    {
        setStartupEntriesEnabled(std::move(selectedEntryList), targetEnabled);
    }
    else if (selectedAction == deleteAction)
    {
        deleteStartupEntries(std::move(selectedEntryList));
    }
}

void StartupDock::showRegistryContextMenu(const QPoint& localPos)
{
    if (!isCategoryProjectionReady(StartupCategory::Registry)) return;
    if (m_registryTree == nullptr)
    {
        return;
    }

    QTreeWidgetItem* treeItem = m_registryTree->itemAt(localPos);
    if (treeItem == nullptr)
    {
        return;
    }

    m_registryTree->setCurrentItem(treeItem);

    const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
        treeItem->data(0, kStartupTreeNodeKindRole).toInt());
    const int entryIndex = findEntryIndexByRegistryTreeItem(treeItem);
    const QString locationText = treeItem->data(0, kStartupTreeLocationRole).toString().trimmed();

    QMenu contextMenu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* detailAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.entry_details", QStringLiteral("查看启动项详细信息")));
    QAction* copyAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_copy.svg"),
        startupText("startup.menu.copy", QStringLiteral("复制")));
    QAction* openFileAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_open_folder.svg"),
        startupText("startup.menu.open_file", QStringLiteral("打开文件位置")));
    QAction* filePropertiesAction = contextMenu.addAction(
        createBlueIcon(":/Icon/process_details.svg"),
        startupText("startup.menu.file_properties", QStringLiteral("转到文件属性")));
    QAction* openRegistryAction = contextMenu.addAction(
        createBlueIcon(":/Icon/file_find.svg"),
        startupText("startup.menu.open_registry", QStringLiteral("打开注册表位置")));
    const bool hasRegistryEntry =
        entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size());
    const StartupEntry registryEntry = hasRegistryEntry
        ? m_entryList.at(static_cast<std::size_t>(entryIndex))
        : StartupEntry{};
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [hasRegistryEntry, registryEntry]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：高级注册表树当前叶子条目。
            // 处理：只有叶子条目才从 imagePathText 提取上传文件。
            // 返回：待上传路径和来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            if (!hasRegistryEntry)
            {
                uploadTarget.errorText = startupText(
                    "startup.upload.error.invalid_node",
                    QStringLiteral("当前注册表节点不是可上传的启动项。"));
                return uploadTarget;
            }
            uploadTarget.filePath = registryEntry.imagePathText;
            uploadTarget.sourceText = startupText(
                "startup.source.autostart_registry",
                QStringLiteral("自启动注册表项 %1"))
                .arg(registryEntry.itemNameText);
            return uploadTarget;
        });
    contextMenu.addSeparator();
    const bool targetEnabled = !hasRegistryEntry || !registryEntry.enabled;
    QAction* toggleAction = contextMenu.addAction(
        createBlueIcon(targetEnabled ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"),
        startupToggleActionText(targetEnabled));
    QAction* deleteAction = contextMenu.addAction(
        createBlueIcon(":/Icon/log_clear.svg"),
        startupText("startup.menu.delete", QStringLiteral("删除项")));

    if (nodeKind == StartupTreeNodeKind::Group
        || nodeKind == StartupTreeNodeKind::Placeholder)
    {
        openFileAction->setEnabled(false);
        filePropertiesAction->setEnabled(false);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(false);
        }
        openRegistryAction->setEnabled(!locationText.isEmpty());
        toggleAction->setEnabled(false);
        deleteAction->setEnabled(false);
    }
    else if (entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size()))
    {
        const StartupEntry& entry = registryEntry;
        openFileAction->setEnabled(entry.canOpenFileLocation);
        filePropertiesAction->setEnabled(entry.canOpenFileLocation);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(entry.canOpenFileLocation && !entry.imagePathText.trimmed().isEmpty());
        }
        openRegistryAction->setEnabled(entry.canOpenRegistryLocation);
        const bool toggleSupported = targetEnabled
            ? entry.backendEntry.canEnable
            : entry.backendEntry.canDisable;
        toggleAction->setEnabled(
            toggleSupported
            && !m_startupActionInProgress.load());
        deleteAction->setEnabled(
            entry.canDelete
            && !m_startupActionInProgress.load());
    }
    else
    {
        openFileAction->setEnabled(false);
        filePropertiesAction->setEnabled(false);
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(false);
        }
        openRegistryAction->setEnabled(false);
        toggleAction->setEnabled(false);
        deleteAction->setEnabled(false);
    }

    QAction* selectedAction = contextMenu.exec(m_registryTree->viewport()->mapToGlobal(localPos));
    if (selectedAction == detailAction)
    {
        showSelectedEntryDetails(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == copyAction)
    {
        copySelectedRow(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == openFileAction)
    {
        openSelectedFileLocation(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == filePropertiesAction)
    {
        openSelectedFileProperties(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == openRegistryAction)
    {
        openSelectedRegistryLocation(StartupCategory::Registry, nullptr);
    }
    else if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }
    else if (selectedAction == toggleAction && hasRegistryEntry)
    {
        setStartupEntryEnabled(registryEntry, targetEnabled);
    }
    else if (selectedAction == deleteAction && hasRegistryEntry)
    {
        deleteStartupEntry(registryEntry);
    }
}

void StartupDock::openSelectedFileLocation(const StartupCategory category, QTableWidget* tableWidget)
{
    int entryIndex = -1;
    if (category == StartupCategory::Registry)
    {
        entryIndex = findEntryIndexByRegistryTreeItem(
            m_registryTree != nullptr ? m_registryTree->currentItem() : nullptr);
    }
    else if (tableWidget != nullptr && tableWidget->currentRow() >= 0)
    {
        entryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
    }
    if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
    {
        return;
    }

    const StartupEntry& entry = m_entryList.at(static_cast<std::size_t>(entryIndex));
    if (!entry.canOpenFileLocation || entry.imagePathText.trimmed().isEmpty())
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.open_file.no_path",
                QStringLiteral("该条目没有可打开的文件路径。")));
        return;
    }

    QProcess::startDetached(
        QStringLiteral("explorer.exe"),
        { QStringLiteral("/select,%1").arg(QDir::toNativeSeparators(entry.imagePathText)) });
}

void StartupDock::openSelectedRegistryLocation(const StartupCategory category, QTableWidget* tableWidget)
{
    QString locationText;
    if (category == StartupCategory::Registry)
    {
        QTreeWidgetItem* currentItem = (m_registryTree != nullptr) ? m_registryTree->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
            currentItem->data(0, kStartupTreeNodeKindRole).toInt());
        if (nodeKind == StartupTreeNodeKind::Group || nodeKind == StartupTreeNodeKind::Placeholder)
        {
            locationText = currentItem->data(0, kStartupTreeLocationRole).toString().trimmed();
        }
        else
        {
            const int entryIndex = findEntryIndexByRegistryTreeItem(currentItem);
            if (entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size()))
            {
                locationText = m_entryList.at(static_cast<std::size_t>(entryIndex)).locationText;
            }
        }
    }
    else if (tableWidget != nullptr && tableWidget->currentRow() >= 0)
    {
        const int entryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
        if (entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size()))
        {
            locationText = m_entryList.at(static_cast<std::size_t>(entryIndex)).locationText;
        }
    }
    if (locationText.trimmed().isEmpty())
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.open_registry.no_path",
                QStringLiteral("该条目没有可打开的注册表位置。")));
        return;
    }

    QApplication::clipboard()->setText(locationText);
    QProcess::startDetached(QStringLiteral("regedit.exe"), {});
    QMessageBox::information(
        this,
        startupText("startup.dialog.title", QStringLiteral("启动项")),
        startupText(
            "startup.dialog.open_registry.success",
            QStringLiteral("已复制注册表路径到剪贴板，并尝试打开 regedit。")));
}

void StartupDock::copySelectedRow(const StartupCategory category, QTableWidget* tableWidget)
{
    if (category == StartupCategory::Registry)
    {
        QTreeWidgetItem* currentItem = (m_registryTree != nullptr) ? m_registryTree->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
            currentItem->data(0, kStartupTreeNodeKindRole).toInt());
        if (nodeKind == StartupTreeNodeKind::Group || nodeKind == StartupTreeNodeKind::Placeholder)
        {
            QApplication::clipboard()->setText(currentItem->data(0, kStartupTreeLocationRole).toString());
            return;
        }

        const int entryIndex = findEntryIndexByRegistryTreeItem(currentItem);
        if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
        {
            return;
        }

        const StartupEntry& entry = m_entryList.at(static_cast<std::size_t>(entryIndex));
        QApplication::clipboard()->setText(startupEntryTsvRow(entry));
        return;
    }

    if (tableWidget == nullptr || tableWidget->currentRow() < 0)
    {
        return;
    }

    const int entryIndex = findEntryIndexByTableRow(category, tableWidget->currentRow());
    if (entryIndex < 0 || entryIndex >= static_cast<int>(m_entryList.size()))
    {
        return;
    }

    const StartupEntry& entry = m_entryList.at(static_cast<std::size_t>(entryIndex));
    QApplication::clipboard()->setText(startupEntryTsvRow(entry));
}

void StartupDock::settleExportReceipt(const QString& errorText)
{
    m_exportPendingReceipt = false;
    m_exportReceiptPath.clear();
    if (m_exportButton) m_exportButton->setEnabled(isCategoryProjectionReady(currentCategory()) && !m_exportOperation->isInFlight());
    if (!errorText.isEmpty())
        QMessageBox::warning(this, startupText("startup.dialog.title", QStringLiteral("启动项")), errorText);
}

void StartupDock::reconcileExportReceipt()
{
    if (m_exportButton) m_exportButton->setEnabled(isCategoryProjectionReady(currentCategory()) && !m_exportOperation->isInFlight());
    if (m_exportPendingReceipt && !m_exportOperation->isInFlight())
        settleExportReceipt(ks::i18n::sourceText(QStringLiteral("导出未返回有效回执，请检查目标文件后再重试。"))
            + QLatin1Char('\n') + m_exportReceiptPath);
}

void StartupDock::exportCurrentView()
{
    const QPointer<StartupDock> guarded(this);
    reconcileExportReceipt();
    if (!guarded || !isCategoryProjectionReady(currentCategory()) || m_exportOperation->isInFlight()) return;
    const QString outputPath = QFileDialog::getSaveFileName(this,
        startupText("startup.dialog.export.title", QStringLiteral("导出启动项")), QStringLiteral("StartupEntries.txt"),
        QStringLiteral("Text Files (*.txt);;All Files (*.*)"));
    if (!guarded || outputPath.trimmed().isEmpty()) return;
    reconcileExportReceipt();
    if (!guarded) return;
    if (!isCategoryProjectionReady(currentCategory()) || m_exportOperation->isInFlight())
    {
        QMessageBox::warning(this, startupText("startup.dialog.title", QStringLiteral("启动项")),
            ks::i18n::sourceText(QStringLiteral("本次导出请求未提交，请稍后重试。")));
        return;
    }
    struct Request {
        QString path; QStringList headers; QVector<StartupEntry> sourceRows; QVector<int> rowIndices;
        QHash<QString, QString> texts; ks::i18n::SourceTextSnapshot language;
    } request;
    request.path = outputPath;
    request.sourceRows = m_entryList; // Frozen shared complete source, no per-entry GUI copy.
    request.headers = startupTableHeaders();
    request.language = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    const auto captureText = [&request](const char* key, const QString& source) {
        request.texts.insert(QString::fromLatin1(key), startupText(key, source));
    };
    captureText("startup.value.enabled", QStringLiteral("启用"));
    captureText("startup.value.disabled", QStringLiteral("禁用"));
    captureText("startup.value.scm.boot", QStringLiteral("引导启动"));
    captureText("startup.value.scm.system", QStringLiteral("系统启动"));
    captureText("startup.value.scm.automatic", QStringLiteral("自动启动"));
    captureText("startup.value.scm.manual", QStringLiteral("手动启动"));
    captureText("startup.value.scm.disabled", QStringLiteral("已禁用"));
    captureText("startup.detail.scheduled_task", QStringLiteral("状态：%1；触发器：%2；描述：%3"));
    captureText("startup.detail.backup_record", QStringLiteral("KSword 备份记录：%1"));
    captureText("startup.detail.parking_path", QStringLiteral("KSword 暂存路径：%1"));
    const auto appendEntry = [&request](const int index) {
        if (index >= 0 && index < request.sourceRows.size()) request.rowIndices.push_back(index);
    };
    const auto category = currentCategory();
    if (category == StartupCategory::Registry)
    {
        if (!m_registryTree) return;
        for (int root = 0; root < m_registryTree->topLevelItemCount(); ++root)
        {
            const auto* group = m_registryTree->topLevelItem(root);
            if (!group) continue;
            for (int child = 0; child < group->childCount(); ++child)
                appendEntry(findEntryIndexByRegistryTreeItem(group->child(child)));
        }
    }
    else
    {
        const auto* table = currentCategoryTable();
        if (!table) return;
        request.rowIndices.reserve(table->rowCount());
        for (int row = 0; row < table->rowCount(); ++row)
            if (!ks::ui::IsTableRowExcludedByFilter(table, row))
                appendEntry(findEntryIndexByTableRow(category, row));
    }
    struct Result { bool committed = false; QString error; };
    m_exportPendingReceipt = true;
    m_exportReceiptPath = outputPath;
    const auto ticket = m_exportOperation->submitTransaction<Request, Result>(std::move(request),
        [](const Request& input) {
            Result result;
            QSaveFile file(input.path);
            if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) { result.error = file.errorString(); return result; }
            QTextStream stream(&file);
            stream.setEncoding(QStringConverter::Utf8);
            stream << input.headers.join(QChar('\t')) << '\n';
            const StartupContextResolver context = [&input](const char* key, const QString& source) {
                return input.texts.value(QString::fromLatin1(key), source);
            };
            const StartupSourceResolver source = [&input](const QString& value) { return input.language.sourceText(value); };
            for (const int index : input.rowIndices)
            {
                const auto& row = input.sourceRows.at(index);
                QStringList fields{row.itemNameText, row.publisherText, row.imagePathText, row.commandText, row.locationText,
                    source(row.userText), formatStartupStatusText(row.backendEntry.actionKind, row.backendEntry.actionLocator.serviceStartMode, row.backendEntry.enabled, context),
                    source(row.sourceTypeText), formatStartupDetailText(row.detailText, context, source)};
                for (QString& field : fields) field = startupTsvField(field);
                stream << fields.join(QChar('\t')) << '\n';
            }
            stream.flush();
            if (stream.status() != QTextStream::Ok) { result.error = file.errorString(); file.cancelWriting(); return result; }
            result.committed = file.commit();
            if (!result.committed) result.error = file.errorString();
            return result;
        },
        [this](const Result& result, std::uint64_t) {
            settleExportReceipt(result.committed ? QString() : startupText("startup.dialog.export.failed", QStringLiteral("导出失败：%1")).arg(result.error));
            return true;
        },
        [this, outputPath](std::exception_ptr) {
            settleExportReceipt(ks::i18n::sourceText(QStringLiteral("导出未返回有效回执，请检查目标文件后再重试。")) + QLatin1Char('\n') + outputPath);
        });
    if (!ticket && guarded && m_exportPendingReceipt)
        settleExportReceipt(ks::i18n::sourceText(QStringLiteral("本次导出请求未提交，请稍后重试。")));
}

void StartupDock::scheduleFilterRefresh()
{
    m_filterRefreshPending = true;
    m_filterRefreshTimer->start();
    if (m_exportButton) m_exportButton->setEnabled(false);
    if (m_copyButton) m_copyButton->setEnabled(false);
    if (auto* table = currentCategoryTable()) table->setEnabled(false);
    else if (m_registryTree) m_registryTree->setEnabled(false);
}

void StartupDock::applyFilterAndRefresh()
{
    rebuildAllTables();
}

void StartupDock::reportUnknownStartupAction()
{
    const QString title = m_actionReceiptTitle;
    const QStringList targets = m_actionReceiptTargets;
    m_actionPendingReceipt = false;
    m_startupActionInProgress.store(false);
    m_actionReceiptTitle.clear();
    m_actionReceiptTargets.clear();
    const QPointer<StartupDock> guarded(this);
    refreshAllStartupEntries();
    if (!guarded) return;
    QMessageBox::warning(this, title,
        ks::i18n::sourceText(QStringLiteral("启动项操作未返回有效回执，最终状态待核实。请刷新核对后再决定是否重试。"))
            + QStringLiteral("\n\n") + targets.join(QLatin1Char('\n')));
}

void StartupDock::reconcileStartupActionReceipt()
{
    if (m_actionPendingReceipt && !m_actionOperation->isInFlight()) reportUnknownStartupAction();
}

void StartupDock::submitStartupAction(std::vector<ks::startup::StartupEntry> entries,
    const bool remove, const bool enabled, const QString& title, const QStringList& targets,
    std::function<void(const StartupKnownActionResults&)> completion)
{
    if (m_actionOperation->isInFlight())
    {
        m_startupActionInProgress.store(false);
        QMessageBox::warning(this, title, ks::i18n::sourceText(QStringLiteral("本次启动项操作未提交，请稍后重试。")));
        return;
    }
    struct Request { std::vector<ks::startup::StartupEntry> entries; bool remove; bool enabled; QStringList targets; } request{std::move(entries), remove, enabled, targets};
    struct Result { StartupKnownActionResults known; std::vector<std::size_t> unknown; };
    const QPointer<StartupDock> guarded(this);
    const auto ticket = m_actionOperation->submitTransaction<Request, Result>(std::move(request),
        [](const Request& input) {
            Result result;
            result.known.reserve(input.entries.size());
            result.unknown.reserve(input.entries.size());
            for (std::size_t index = 0; index < input.entries.size(); ++index)
            {
                ks::startup::ActionResult action;
                kLogEvent actionEvent; // 同一条目的权限告警与最终回执共用事件，便于追踪。
                try
                {
                    // 后台同步告警不弹阻塞窗口；实际额外权限申请由后端完成并回报结果。
                    const auto permissionWarning = [&input, index, &actionEvent]() {
                        warn << actionEvent
                            << ks::i18n::sourceText(QStringLiteral("服务删除权限不足，已请求额外权限，正在尝试临时接管服务对象并重试。"))
                                   .toStdString()
                            << " target=" << input.targets.value(static_cast<qsizetype>(index)).toStdString()
                            << eol;
                    };
                    action = input.remove ? ks::startup::DeleteStartupEntry(input.entries[index], permissionWarning)
                        : ks::startup::SetStartupEntryEnabled(input.entries[index], input.enabled);
                }
                catch (...)
                {
                    result.unknown.push_back(index);
                    err << actionEvent << "[StartupDock] accepted mutation outcome unknown, target="
                        << input.targets.value(static_cast<qsizetype>(index)).toStdString() << eol;
                    continue;
                }
                result.known.emplace_back(index, std::move(action));
                const auto& receipt = result.known.back().second;
                // SCM 删除是提交标记，不保证条目已消失；把后端真实回执显示在告警日志中。
                if (input.remove && receipt.success
                    && input.entries[index].actionKind == ks::startup::StartupActionKind::ScmStartType)
                {
                    warn << actionEvent
                        << ks::i18n::sourceText(QStringLiteral("服务删除请求已处理；若仍能枚举到条目，请等待服务停止及相关句柄关闭。"))
                               .toStdString()
                        << " target=" << input.targets.value(static_cast<qsizetype>(index)).toStdString()
                        << eol;
                }
                info << actionEvent << "[StartupDock] accepted mutation receipt, target="
                    << input.targets.value(static_cast<qsizetype>(index)).toStdString()
                    << ", remove=" << input.remove << ", enabled=" << input.enabled
                    << ", success=" << receipt.success << ", changed=" << receipt.changed
                    << ", status=" << static_cast<int>(receipt.status) << ", error=" << receipt.errorCode
                    << ", rollbackAttempted=" << receipt.rollbackAttempted << ", rollbackSucceeded=" << receipt.rollbackSucceeded << eol;
            }
            return result;
        },
        [this, title, targets, completion = std::move(completion)](const Result& result, std::uint64_t) {
            const QPointer<StartupDock> guarded(this);
            m_actionPendingReceipt = false;
            m_startupActionInProgress.store(false);
            m_actionReceiptTitle.clear();
            m_actionReceiptTargets.clear();
            refreshAllStartupEntries();
            if (!guarded) return true;
            completion(result.known);
            if (!guarded) return true;
            if (!result.unknown.empty())
            {
                QStringList unknownTargets;
                for (const auto index : result.unknown) unknownTargets.append(targets.value(static_cast<qsizetype>(index)));
                QMessageBox::warning(this, title,
                    ks::i18n::sourceText(QStringLiteral("启动项操作未返回有效回执，最终状态待核实。请刷新核对后再决定是否重试。"))
                        + QStringLiteral("\n\n") + unknownTargets.join(QLatin1Char('\n')));
            }
            return true;
        },
        [this](std::exception_ptr) { reportUnknownStartupAction(); });
    if (!guarded) return;
    if (ticket)
    {
        m_actionPendingReceipt = true;
        m_actionReceiptTitle = title;
        m_actionReceiptTargets = targets;
    }
    else
    {
        m_startupActionInProgress.store(false);
        QMessageBox::warning(this, title, ks::i18n::sourceText(QStringLiteral("本次启动项操作未提交，请稍后重试。")));
    }
}

void StartupDock::setStartupEntryEnabled(StartupEntry entry, const bool enabled)
{
    const QPointer<StartupDock> guarded(this);
    reconcileStartupActionReceipt();
    if (!guarded) return;
    const QString actionText = startupToggleActionText(enabled);
    const QString operationTitle = startupText(
        "startup.dialog.toggle.operation.title",
        QStringLiteral("%1启动项"))
        .arg(actionText);

    const bool actionSupported = enabled
        ? entry.backendEntry.canEnable
        : entry.backendEntry.canDisable;
    if (!actionSupported)
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.toggle.unsupported",
                QStringLiteral("后端未允许对该条目执行“%1”。请刷新后查看最新状态。"))
                .arg(actionText));
        return;
    }

    if (enabled)
    {
        const QString locationText = entry.locationText.trimmed().isEmpty()
            ? startupText("startup.value.empty", QStringLiteral("<空>"))
            : entry.locationText;
        const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
            this,
            startupText(
                "startup.dialog.toggle.confirm.title",
                QStringLiteral("确认%1"))
                .arg(operationTitle),
            startupText(
                "startup.dialog.toggle.confirm.message",
                QStringLiteral("%1\n\n条目：%2\n来源：%3\n目标状态：%4\n风险等级：%5\n风险提示：%6\n\n%7\n是否继续？"))
                .arg(startupToggleImpactText(entry.backendEntry.actionKind, enabled))
                .arg(entry.itemNameText)
                .arg(locationText)
                .arg(buildStatusText(enabled))
                .arg(startupRiskLevelText(entry.backendEntry.riskLevel))
                .arg(startupRiskReasonText(entry.backendEntry))
                .arg(startupToggleRecoveryText(entry.backendEntry.actionKind)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (!guarded || confirmButton != QMessageBox::Yes)
        {
            return;
        }
    }

    bool expectedIdle = false;
    if (!m_startupActionInProgress.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.toggle.busy",
                QStringLiteral("已有一个启动项启停操作正在执行，请等待其完成后重试。")));
        return;
    }

    const ks::startup::StartupEntry backendEntry = entry.backendEntry;
    const QString itemNameText = entry.itemNameText;
    const QString sourceTypeText = entry.sourceTypeText;
    const QString entryLocationText = entry.locationText;
    submitStartupAction({backendEntry}, false, enabled, operationTitle, {itemNameText + QStringLiteral(" | ") + entryLocationText},
        [this, operationTitle, itemNameText, sourceTypeText, entryLocationText, enabled, actionText](const StartupKnownActionResults& known) {
            const QPointer<StartupDock> guarded(this);
            if (known.empty()) return;
            const auto& actionResult = known.front().second;

                if (!actionResult.success)
                {
                    const QString failureText = startupActionFailureText(actionResult);
                    bool privilegePromptHandled = false;
                    if (isStartupPrivilegeFailure(actionResult))
                    {
                        if (actionResult.errorCode != ERROR_SUCCESS)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                operationTitle,
                                static_cast<unsigned long>(actionResult.errorCode));
                            if (!guarded) return;
                        }
                        if (!privilegePromptHandled)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                operationTitle,
                                failureText);
                            if (!guarded) return;
                        }
                    }
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(
                            this,
                            startupText(
                                "startup.dialog.toggle.failed.title",
                                QStringLiteral("%1失败"))
                                .arg(operationTitle),
                            failureText);
                    }
                    return;
                }

                kLogEvent actionEvent;
                info << actionEvent
                    << startupText(
                        "startup.log.toggle.succeeded",
                        QStringLiteral("[StartupDock] 启动项修改成功, action=%1, changed=%2, targetEnabled=%3, type=%4, name=%5, location=%6"))
                           .arg(actionText)
                           .arg(actionResult.changed ? QStringLiteral("true") : QStringLiteral("false"))
                           .arg(enabled ? QStringLiteral("true") : QStringLiteral("false"))
                           .arg(sourceTypeText)
                           .arg(itemNameText)
                           .arg(entryLocationText)
                           .toStdString()
                    << eol;

        });
}

void StartupDock::deleteStartupEntry(StartupEntry entry)
{
    const QPointer<StartupDock> guarded(this);
    reconcileStartupActionReceipt();
    if (!guarded) return;
    const QString operationTitle = startupText(
        "startup.dialog.delete.operation.title",
        QStringLiteral("删除启动项"));
    if (!entry.canDelete || !entry.backendEntry.canDelete)
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText("startup.dialog.delete.unsupported", QStringLiteral("该条目当前不支持删除。")));
        return;
    }

    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        startupText(
            "startup.dialog.delete.confirm.irreversible.title",
            QStringLiteral("永久删除启动项")),
        startupText(
            "startup.dialog.delete.confirm.irreversible.message",
            QStringLiteral("即将永久删除以下启动项及其来源记录：\n\n%1\n来源：%2\n风险等级：%3\n风险提示：%4\n\n此操作不可通过 KSword 恢复。若只是暂时停止启动，请取消并使用“禁用”。\n\n确定仍要永久删除吗？"))
            .arg(entry.itemNameText)
            .arg(entry.locationText)
            .arg(startupRiskLevelText(entry.backendEntry.riskLevel))
            .arg(startupRiskReasonText(entry.backendEntry)),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (!guarded || confirmButton != QMessageBox::Yes)
    {
        return;
    }

    bool expectedIdle = false;
    if (!m_startupActionInProgress.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.operation.busy",
                QStringLiteral("已有一个启动项修改操作正在执行，请等待其完成后重试。")));
        return;
    }

    const ks::startup::StartupEntry backendEntry = entry.backendEntry;
    const QString itemNameText = entry.itemNameText;
    const QString sourceTypeText = entry.sourceTypeText;
    const QString entryLocationText = entry.locationText;
    submitStartupAction({backendEntry}, true, false, operationTitle, {itemNameText + QStringLiteral(" | ") + entryLocationText},
        [this, operationTitle, itemNameText, sourceTypeText, entryLocationText](const StartupKnownActionResults& known) {
            const QPointer<StartupDock> guarded(this);
            if (known.empty()) return;
            const auto& actionResult = known.front().second;

                if (!actionResult.success)
                {
                    const QString failureText = startupActionFailureText(actionResult);
                    bool privilegePromptHandled = false;
                    if (isStartupPrivilegeFailure(actionResult))
                    {
                        if (actionResult.errorCode != ERROR_SUCCESS)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                operationTitle,
                                static_cast<unsigned long>(actionResult.errorCode));
                            if (!guarded) return;
                        }
                        if (!privilegePromptHandled)
                        {
                            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                                this,
                                operationTitle,
                                failureText);
                            if (!guarded) return;
                        }
                    }
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(
                            this,
                            operationTitle,
                            startupText(
                                "startup.dialog.delete.failed",
                                QStringLiteral("删除失败：%1"))
                                .arg(failureText));
                    }
                    return;
                }

                kLogEvent deleteEvent;
                info << deleteEvent
                    << startupText(
                        "startup.log.delete.succeeded",
                        QStringLiteral("[StartupDock] 删除启动项成功, type="))
                           .toStdString()
                    << sourceTypeText.toStdString()
                    << ", name="
                    << itemNameText.toStdString()
                    << ", location="
                    << entryLocationText.toStdString()
                    << ", changed="
                    << (actionResult.changed ? "true" : "false")
                    << eol;

        });
}

void StartupDock::setStartupEntriesEnabled(
    std::vector<StartupEntry> entryList,
    const bool enabled)
{
    const QPointer<StartupDock> guarded(this);
    reconcileStartupActionReceipt();
    if (!guarded) return;
    if (entryList.size() <= 1)
    {
        if (!entryList.empty())
        {
            setStartupEntryEnabled(std::move(entryList.front()), enabled);
        }
        return;
    }

    const QString actionText = startupToggleActionText(enabled);
    const QString operationTitle = startupText(
        "startup.dialog.toggle.operation.title",
        QStringLiteral("%1启动项"))
        .arg(actionText);
    std::vector<StartupEntry> actionableEntryList;
    actionableEntryList.reserve(entryList.size());
    for (const StartupEntry& entry : entryList)
    {
        if (entry.enabled == enabled)
        {
            continue;
        }

        const bool actionSupported = enabled
            ? entry.backendEntry.canEnable
            : entry.backendEntry.canDisable;
        if (!actionSupported)
        {
            QMessageBox::information(
                this,
                operationTitle,
                startupText(
                    "startup.dialog.toggle.unsupported",
                    QStringLiteral("后端未允许对该条目执行“%1”。请刷新后查看最新状态。"))
                    .arg(actionText));
            return;
        }
        actionableEntryList.push_back(entry);
    }
    if (actionableEntryList.empty())
    {
        return;
    }

    if (enabled)
    {
        const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
            this,
            startupText(
                "startup.dialog.toggle.confirm.title",
                QStringLiteral("确认%1"))
                .arg(operationTitle),
            startupText(
                "startup.dialog.toggle.confirm.batch.message",
                QStringLiteral("即将%1 %2 个启动项。操作会逐项执行；失败项不会中断其余项目。\n\n是否继续？"))
                .arg(actionText)
                .arg(actionableEntryList.size()),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (!guarded || confirmButton != QMessageBox::Yes)
        {
            return;
        }
    }

    bool expectedIdle = false;
    if (!m_startupActionInProgress.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.toggle.busy",
                QStringLiteral("已有一个启动项启停操作正在执行，请等待其完成后重试。")));
        return;
    }

    std::vector<ks::startup::StartupEntry> acceptedEntries;
    QStringList targets;
    for (const auto& item : actionableEntryList) { acceptedEntries.push_back(item.backendEntry); targets.append(item.itemNameText + QStringLiteral(" | ") + item.locationText); }
    submitStartupAction(std::move(acceptedEntries), false, enabled, operationTitle, targets,
        [this, entries = std::move(actionableEntryList), operationTitle, enabled, actionText](const StartupKnownActionResults& known) {
            const QPointer<StartupDock> guarded(this);
            std::vector<std::pair<StartupEntry, ks::startup::ActionResult>> actionResultList;
            for (const auto& value : known) if (value.first < entries.size()) actionResultList.emplace_back(entries[value.first], value.second);

                QStringList failureTextList;
                bool privilegePromptHandled = false;
                for (const auto& actionResultEntry : actionResultList)
                {
                    const StartupEntry& entry = actionResultEntry.first;
                    const ks::startup::ActionResult& actionResult = actionResultEntry.second;
                    if (!actionResult.success)
                    {
                        const QString failureText = startupActionFailureText(actionResult);
                        if (!privilegePromptHandled && isStartupPrivilegeFailure(actionResult))
                        {
                            privilegePromptHandled = actionResult.errorCode != ERROR_SUCCESS
                                ? ks::ui::promptForPrivilegeFailure(
                                    this,
                                    operationTitle,
                                    static_cast<unsigned long>(actionResult.errorCode))
                                : ks::ui::promptForPrivilegeFailure(
                                    this,
                                    operationTitle,
                                    failureText);
                            if (!guarded) return;
                        }
                        failureTextList.push_back(
                            QStringLiteral("%1：%2").arg(entry.itemNameText, failureText));
                        continue;
                    }

                    kLogEvent actionEvent;
                    info << actionEvent
                        << startupText(
                            "startup.log.toggle.succeeded",
                            QStringLiteral("[StartupDock] 启动项修改成功, action=%1, changed=%2, targetEnabled=%3, type=%4, name=%5, location=%6"))
                               .arg(actionText)
                               .arg(actionResult.changed ? QStringLiteral("true") : QStringLiteral("false"))
                               .arg(enabled ? QStringLiteral("true") : QStringLiteral("false"))
                               .arg(entry.sourceTypeText)
                               .arg(entry.itemNameText)
                               .arg(entry.locationText)
                               .toStdString()
                        << eol;
                }

                if (!failureTextList.isEmpty() && !privilegePromptHandled)
                {
                    QMessageBox::warning(
                        this,
                        startupText(
                            "startup.dialog.toggle.failed.title",
                            QStringLiteral("%1失败"))
                            .arg(operationTitle),
                        startupText(
                            "startup.dialog.batch.failed",
                            QStringLiteral("%1 个条目未能执行%2：\n\n%3"))
                            .arg(failureTextList.size())
                            .arg(actionText)
                            .arg(failureTextList.join(QStringLiteral("\n\n"))));
                }

        });
}

void StartupDock::deleteStartupEntries(std::vector<StartupEntry> entryList)
{
    const QPointer<StartupDock> guarded(this);
    reconcileStartupActionReceipt();
    if (!guarded) return;
    if (entryList.size() <= 1)
    {
        if (!entryList.empty())
        {
            deleteStartupEntry(std::move(entryList.front()));
        }
        return;
    }

    const QString operationTitle = startupText(
        "startup.dialog.delete.operation.title",
        QStringLiteral("删除启动项"));
    for (const StartupEntry& entry : entryList)
    {
        if (!entry.canDelete || !entry.backendEntry.canDelete)
        {
            QMessageBox::information(
                this,
                operationTitle,
                startupText("startup.dialog.delete.unsupported", QStringLiteral("该条目当前不支持删除。")));
            return;
        }
    }

    const QMessageBox::StandardButton confirmButton = QMessageBox::warning(
        this,
        startupText(
            "startup.dialog.delete.confirm.irreversible.title",
            QStringLiteral("永久删除启动项")),
        startupText(
            "startup.dialog.delete.confirm.batch.message",
            QStringLiteral("即将永久删除 %1 个启动项及其来源记录。此操作不可通过 KSword 恢复。\n\n确定仍要永久删除吗？"))
            .arg(entryList.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (!guarded || confirmButton != QMessageBox::Yes)
    {
        return;
    }

    bool expectedIdle = false;
    if (!m_startupActionInProgress.compare_exchange_strong(expectedIdle, true))
    {
        QMessageBox::information(
            this,
            operationTitle,
            startupText(
                "startup.dialog.operation.busy",
                QStringLiteral("已有一个启动项修改操作正在执行，请等待其完成后重试。")));
        return;
    }

    std::vector<ks::startup::StartupEntry> acceptedEntries;
    QStringList targets;
    for (const auto& item : entryList) { acceptedEntries.push_back(item.backendEntry); targets.append(item.itemNameText + QStringLiteral(" | ") + item.locationText); }
    submitStartupAction(std::move(acceptedEntries), true, false, operationTitle, targets,
        [this, entries = std::move(entryList), operationTitle](const StartupKnownActionResults& known) {
            const QPointer<StartupDock> guarded(this);
            std::vector<std::pair<StartupEntry, ks::startup::ActionResult>> actionResultList;
            for (const auto& value : known) if (value.first < entries.size()) actionResultList.emplace_back(entries[value.first], value.second);

                QStringList failureTextList;
                bool privilegePromptHandled = false;
                for (const auto& actionResultEntry : actionResultList)
                {
                    const StartupEntry& entry = actionResultEntry.first;
                    const ks::startup::ActionResult& actionResult = actionResultEntry.second;
                    if (!actionResult.success)
                    {
                        const QString failureText = startupActionFailureText(actionResult);
                        if (!privilegePromptHandled && isStartupPrivilegeFailure(actionResult))
                        {
                            privilegePromptHandled = actionResult.errorCode != ERROR_SUCCESS
                                ? ks::ui::promptForPrivilegeFailure(
                                    this,
                                    operationTitle,
                                    static_cast<unsigned long>(actionResult.errorCode))
                                : ks::ui::promptForPrivilegeFailure(
                                    this,
                                    operationTitle,
                                    failureText);
                            if (!guarded) return;
                        }
                        failureTextList.push_back(
                            QStringLiteral("%1：%2").arg(entry.itemNameText, failureText));
                        continue;
                    }

                    kLogEvent deleteEvent;
                    info << deleteEvent
                        << startupText(
                            "startup.log.delete.succeeded",
                            QStringLiteral("[StartupDock] 删除启动项成功, type="))
                               .toStdString()
                        << entry.sourceTypeText.toStdString()
                        << ", name="
                        << entry.itemNameText.toStdString()
                        << ", location="
                        << entry.locationText.toStdString()
                        << ", changed="
                        << (actionResult.changed ? "true" : "false")
                        << eol;
                }

                if (!failureTextList.isEmpty() && !privilegePromptHandled)
                {
                    QMessageBox::warning(
                        this,
                        operationTitle,
                        startupText(
                            "startup.dialog.batch.failed",
                            QStringLiteral("%1 个条目未能执行%2：\n\n%3"))
                            .arg(failureTextList.size())
                            .arg(operationTitle)
                            .arg(failureTextList.join(QStringLiteral("\n\n"))));
                }

        });
}

int StartupDock::findEntryIndexByTableRow(const StartupCategory category, const int row) const
{
    if (!isCategoryProjectionReady(category)) return -1;
    QTableWidget* tableWidget = nullptr;
    switch (category)
    {
    case StartupCategory::All:
        tableWidget = m_allTable;
        break;
    case StartupCategory::Logon:
        tableWidget = m_logonTable;
        break;
    case StartupCategory::Services:
        tableWidget = m_servicesTable;
        break;
    case StartupCategory::Drivers:
        tableWidget = m_driversTable;
        break;
    case StartupCategory::Tasks:
        tableWidget = m_tasksTable;
        break;
    case StartupCategory::ImageHijack:
        tableWidget = m_imageHijackTable;
        break;
    case StartupCategory::Registry:
        return -1;
    case StartupCategory::Wmi:
        tableWidget = m_wmiTable;
        break;
    case StartupCategory::Hidden:
        tableWidget = m_hiddenTable;
        break;
    default:
        break;
    }

    if (tableWidget == nullptr || row < 0)
    {
        return -1;
    }

    QTableWidgetItem* nameItem = tableWidget->item(row, toStartupColumn(StartupColumn::Name));
    if (nameItem == nullptr)
    {
        return -1;
    }
    return nameItem->data(Qt::UserRole).toInt();
}

bool StartupDock::entryMatchesCurrentFilter(const StartupEntry& entry) const
{
    const QString keywordText = (m_filterEdit != nullptr) ? m_filterEdit->text().trimmed() : QString();
    const bool hideMicrosoft = (m_hideMicrosoftCheck != nullptr) && m_hideMicrosoftCheck->isChecked();

    if (hideMicrosoft)
    {
        const QString publisherLowerText = entry.publisherText.toLower();
        if (publisherLowerText.contains(QStringLiteral("microsoft"))
            || publisherLowerText.contains(QStringLiteral("windows")))
        {
            return false;
        }
    }

    if (keywordText.isEmpty())
    {
        return true;
    }

    const QString haystackText =
        entry.itemNameText + QLatin1Char('\n')
        + entry.publisherText + QLatin1Char('\n')
        + entry.imagePathText + QLatin1Char('\n')
        + entry.commandText + QLatin1Char('\n')
        + entry.locationText + QLatin1Char('\n')
        + entry.userText + QLatin1Char('\n')
        + ks::i18n::sourceText(entry.userText) + QLatin1Char('\n')
        + entry.sourceTypeText + QLatin1Char('\n')
        + ks::i18n::sourceText(entry.sourceTypeText) + QLatin1Char('\n')
        + buildStatusText(entry.backendEntry) + QLatin1Char('\n')
        + entry.detailText + QLatin1Char('\n')
        + startupLocalizedDetailText(entry.detailText);
    return haystackText.contains(keywordText, Qt::CaseInsensitive);
}
