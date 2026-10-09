#include "StartupDock.Internal.h"

#include "../UI/StructuredFieldView.h"

using namespace startup_dock_detail;

namespace
{
    // boolText：
    // - 作用：把布尔值统一转换成中文“是/否”；
    // - 调用：启动项详细信息文本拼装时复用。
    QString boolText(const bool value)
    {
        return value
            ? startupText("startup.value.yes", QStringLiteral("是"))
            : startupText("startup.value.no", QStringLiteral("否"));
    }

    QString emptyValueText()
    {
        return startupText("startup.value.empty", QStringLiteral("<空>"));
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

    // buildEntryDetailText：
    // - 作用：把一条 StartupEntry 展开成详细信息文本；
    // - 调用：查看启动项详细信息时使用；
    // - 传入 entry：当前选中的启动项记录；
    // - 传出：返回可直接塞给 ks::ui::StructuredFieldView 的纯文本。
    ks::ui::FieldDocument buildEntryDetailText(const StartupDock::StartupEntry& entry)
    {
        ks::ui::FieldDocument detailText;
        detailText.field(QStringLiteral("名称"), QStringLiteral("%1").arg(entry.itemNameText));
        detailText.field(QStringLiteral("分类"), QStringLiteral("%1").arg(ks::i18n::sourceText(entry.categoryText)));
        detailText.field(QStringLiteral("发布者"), QStringLiteral("%1").arg(entry.publisherText.isEmpty() ? emptyValueText() : entry.publisherText));
        detailText.field(QStringLiteral("镜像路径"), QStringLiteral("%1").arg(entry.imagePathText.isEmpty() ? emptyValueText() : entry.imagePathText));
        detailText.field(QStringLiteral("命令"), QStringLiteral("%1").arg(entry.commandText.isEmpty() ? emptyValueText() : entry.commandText));
        detailText.field(QStringLiteral("来源位置"), QStringLiteral("%1").arg(entry.locationText.isEmpty() ? emptyValueText() : entry.locationText));
        detailText.field(QStringLiteral("分组位置"), QStringLiteral("%1").arg(entry.locationGroupText.isEmpty() ? emptyValueText() : entry.locationGroupText));
        detailText.field(QStringLiteral("注册表值名"), QStringLiteral("%1").arg(entry.registryValueNameText.isEmpty() ? emptyValueText() : entry.registryValueNameText));
        detailText.field(QStringLiteral("用户/上下文"), QStringLiteral("%1").arg(entry.userText.isEmpty() ? emptyValueText() : ks::i18n::sourceText(entry.userText)));
        detailText.field(QStringLiteral("类型"), QStringLiteral("%1").arg(entry.sourceTypeText.isEmpty() ? emptyValueText() : ks::i18n::sourceText(entry.sourceTypeText)));
        detailText.field(QStringLiteral("状态"), QStringLiteral("%1").arg(buildStatusText(entry.backendEntry)));
        detailText.field(QStringLiteral("可启用"), QStringLiteral("%1").arg(boolText(entry.backendEntry.canEnable)));
        detailText.field(QStringLiteral("可禁用"), QStringLiteral("%1").arg(boolText(entry.backendEntry.canDisable)));
        const bool actionAvailable = entry.backendEntry.canEnable
            || entry.backendEntry.canDisable
            || entry.canDelete;
        detailText.field(QStringLiteral("修改策略"), QStringLiteral("%1").arg(actionAvailable
                ? startupText("startup.value.warning_gated", QStringLiteral("警告后允许"))
                : startupText("startup.value.action_unavailable", QStringLiteral("没有可执行的来源定位器"))));
        detailText.field(QStringLiteral("风险提示"), QStringLiteral("%1").arg(startupRiskReasonText(entry.backendEntry)));
        detailText.field(QStringLiteral("风险等级"), QStringLiteral("%1").arg(startupRiskLevelText(entry.backendEntry.riskLevel)));
        detailText.field(QStringLiteral("补充说明"), QStringLiteral("%1").arg(entry.detailText.isEmpty() ? emptyValueText() : startupLocalizedDetailText(entry.detailText)));
        detailText.field(QStringLiteral("可打开文件位置"), QStringLiteral("%1").arg(boolText(entry.canOpenFileLocation)));
        detailText.field(QStringLiteral("可打开注册表位置"), QStringLiteral("%1").arg(boolText(entry.canOpenRegistryLocation)));
        detailText.field(QStringLiteral("可删除"), QStringLiteral("%1").arg(boolText(entry.canDelete)));
        detailText.field(QStringLiteral("删除整棵注册表子键"), QStringLiteral("%1").arg(boolText(entry.deleteRegistryTree)));
        detailText.field(QStringLiteral("唯一标识"), QStringLiteral("%1").arg(entry.uniqueIdText.isEmpty() ? QStringLiteral("<空>") : entry.uniqueIdText));
        return detailText;
    }

    // buildRegistryNodeDetailText：
    // - 作用：给注册表树的位置节点/占位节点生成详情文本；
    // - 调用：用户右键查看注册表位置节点详细信息时使用；
    // - 传入 treeItem：当前选中的树节点；
    // - 传出：返回可直接展示的文本内容。
    ks::ui::FieldDocument buildRegistryNodeDetailText(const QTreeWidgetItem* treeItem)
    {
        if (treeItem == nullptr)
        {
            return ks::ui::FieldDocument{}.note(startupText("startup.detail.node.empty", QStringLiteral("<空节点>")));
        }

        const StartupTreeNodeKind nodeKind = static_cast<StartupTreeNodeKind>(
            treeItem->data(0, kStartupTreeNodeKindRole).toInt());
        const QString kindText =
            nodeKind == StartupTreeNodeKind::Group
            ? startupText("startup.detail.node.registry_group", QStringLiteral("注册表位置节点"))
            : (nodeKind == StartupTreeNodeKind::Placeholder
                ? startupText("startup.detail.node.placeholder", QStringLiteral("占位节点"))
                : startupText("startup.detail.node.entry", QStringLiteral("条目节点")));

        ks::ui::FieldDocument detailText;
        detailText.field(QStringLiteral("节点类型"), QStringLiteral("%1").arg(kindText));
        detailText.field(QStringLiteral("显示文本"), QStringLiteral("%1").arg(treeItem->text(StartupDock::toStartupColumn(StartupDock::StartupColumn::Name))));
        detailText.field(QStringLiteral("注册表位置"), QStringLiteral("%1").arg(treeItem->data(0, kStartupTreeLocationRole).toString()));
        detailText.field(QStringLiteral("详情列"), QStringLiteral("%1").arg(treeItem->text(StartupDock::toStartupColumn(StartupDock::StartupColumn::Detail))));
        detailText.field(QStringLiteral("子节点数量"), QStringLiteral("%1").arg(treeItem->childCount()));
        return detailText;
    }

    // showStartupDetailDialog：
    // - 作用：统一弹出启动项/注册表节点详细信息窗口；
    // - 调用：右键菜单“查看启动项详细信息”动作触发；
    // - 传入 titleText/detailText：窗口标题与正文；
    // - 传出：无，直接模态显示。
    void showStartupDetailDialog(QWidget* parentWidget, const QString& titleText, const ks::ui::FieldDocument& detailText)
    {
        QDialog detailDialog(parentWidget);
        detailDialog.setObjectName(QStringLiteral("StartupDockDetailDialog"));
        detailDialog.setWindowTitle(titleText);
        detailDialog.resize(860, 620);
        // 详情弹窗强制使用不透明背景，避免浅色模式下出现黑底。
        detailDialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(detailDialog.objectName()));

        QVBoxLayout* layout = new QVBoxLayout(&detailDialog);
        ks::ui::StructuredFieldView* detailEditor = new ks::ui::StructuredFieldView(&detailDialog);

        detailEditor->setDocument(detailText);

        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &detailDialog);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &detailDialog, &QDialog::reject);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &detailDialog, &QDialog::accept);

        layout->addWidget(detailEditor, 1);
        layout->addWidget(buttonBox, 0);
        detailDialog.exec();
    }

    // openFilePropertiesByPath：
    // - 作用：打开文件属性对话框；
    // - 调用：右键菜单“转到文件属性”动作触发；
    // - 传入 filePathText：目标文件路径；
    // - 传出：返回 true 表示 ShellExecute 成功触发。
    bool openFilePropertiesByPath(const QString& filePathText, QString* errorTextOut)
    {
        if (filePathText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = startupText(
                    "startup.dialog.file_properties.error.empty_path",
                    QStringLiteral("文件路径为空。"));
            }
            return false;
        }

        const HINSTANCE shellResult = ::ShellExecuteW(
            nullptr,
            L"properties",
            reinterpret_cast<LPCWSTR>(QDir::toNativeSeparators(filePathText).utf16()),
            nullptr,
            nullptr,
            SW_SHOW);
        if (reinterpret_cast<INT_PTR>(shellResult) <= 32)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = startupText(
                    "startup.dialog.file_properties.error.failed",
                    QStringLiteral("ShellExecute(properties) 失败，返回值=%1"))
                    .arg(reinterpret_cast<INT_PTR>(shellResult));
            }
            return false;
        }
        return true;
    }
}

void StartupDock::showSelectedEntryDetails(const StartupCategory category, QTableWidget* tableWidget)
{
    if (category == StartupCategory::Registry)
    {
        QTreeWidgetItem* currentItem = (m_registryTree != nullptr) ? m_registryTree->currentItem() : nullptr;
        if (currentItem == nullptr)
        {
            return;
        }

        const int entryIndex = findEntryIndexByRegistryTreeItem(currentItem);
        if (entryIndex >= 0 && entryIndex < static_cast<int>(m_entryList.size()))
        {
            const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
            showStartupDetailDialog(
                this,
                startupText("startup.dialog.entry_detail.title", QStringLiteral("启动项详细信息 - %1"))
                    .arg(entry.itemNameText),
                buildEntryDetailText(entry));
        }
        else
        {
            showStartupDetailDialog(
                this,
                startupText("startup.dialog.registry_detail.title", QStringLiteral("注册表位置详细信息")),
                buildRegistryNodeDetailText(currentItem));
        }
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

    const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
    showStartupDetailDialog(
        this,
        startupText("startup.dialog.entry_detail.title", QStringLiteral("启动项详细信息 - %1"))
            .arg(entry.itemNameText),
        buildEntryDetailText(entry));
}

void StartupDock::openSelectedFileProperties(const StartupCategory category, QTableWidget* tableWidget)
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

    const StartupEntry& entry = m_entryList[static_cast<std::size_t>(entryIndex)];
    if (!entry.canOpenFileLocation || entry.imagePathText.trimmed().isEmpty())
    {
        QMessageBox::information(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText(
                "startup.dialog.file_properties.no_path",
                QStringLiteral("该条目没有可查看属性的文件路径。")));
        return;
    }

    QString errorText;
    if (!openFilePropertiesByPath(entry.imagePathText, &errorText))
    {
        QMessageBox::warning(
            this,
            startupText("startup.dialog.title", QStringLiteral("启动项")),
            startupText("startup.dialog.file_properties.failed", QStringLiteral("打开文件属性失败：%1"))
                .arg(errorText));
    }
}
