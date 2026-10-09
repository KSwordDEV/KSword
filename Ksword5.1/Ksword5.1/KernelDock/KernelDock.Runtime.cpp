
#include "KernelDock.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/ThemeItemForeground.h"

// ============================================================
// KernelDock.Runtime.cpp
// 作用说明：
// 1) 承载 KernelDock 的异步刷新流程；
// 2) 承载三个表格的重建逻辑；
// 3) 承载详情联动和当前选中项解析。
// ============================================================

#include "KernelDockAtomWorker.h"
#include "KernelDockObjectNamespaceWorker.h"
#include "KernelDockQueryWorker.h"
#include "../UI/StructuredFieldView.h"
#include "../theme.h"

#include <QBrush>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QMap>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <algorithm> // std::count_if：统计失败项。
#include <limits>    // std::numeric_limits：定义树节点哨兵值。
#include <thread>    // std::thread：后台刷新任务。

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // statusLabelStyle：
    // - 作用：统一状态标签颜色与字重。
    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // safeText：
    // - 作用：把空文本替换为占位符，避免详情区出现空白字段。
    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.runtime.placeholder.empty", QStringLiteral("<空>")));
    }

    QString emptyText()
    {
        return kernelText("kernel.runtime.placeholder.empty", QStringLiteral("<空>"));
    }

    // ObjectNamespaceColumn：对象命名空间树列索引。
    enum class ObjectNamespaceColumn : int
    {
        Name = 0,
        Type,
        PathOrScope,
        Status,
        SymbolicTarget,
        Count
    };

    // ObjectNamespaceNodeKind：对象命名空间树节点类型。
    enum class ObjectNamespaceNodeKind : int
    {
        Root = 0,
        Directory,
        ObjectEntry
    };

    // 对象命名空间树自定义角色：
    // - SourceIndexRole：对象节点对应 m_objectNamespaceRows 的索引。
    // - NodeKindRole：节点类型（根/目录/对象）。
    // - NodePathRole：节点路径（根路径/目录路径/完整对象路径）。
    // - NodeDescriptionRole：节点补充说明文本。
    constexpr int SourceIndexRole = Qt::UserRole + 1;
    constexpr int NodeKindRole = Qt::UserRole + 2;
    constexpr int NodePathRole = Qt::UserRole + 3;
    constexpr int NodeDescriptionRole = Qt::UserRole + 4;

    // kInvalidSourceIndex：树节点未绑定对象记录时使用的哨兵值。
    constexpr qulonglong kInvalidSourceIndex = std::numeric_limits<qulonglong>::max();

    // leafNameFromObjectPath：
    // - 作用：从对象路径提取最后一段名称用于树节点显示。
    QString leafNameFromObjectPath(const QString& fullPathText)
    {
        const int slashIndex = fullPathText.lastIndexOf('\\');
        if (slashIndex < 0)
        {
            return fullPathText;
        }
        if (slashIndex + 1 >= fullPathText.size())
        {
            return fullPathText;
        }
        return fullPathText.mid(slashIndex + 1);
    }

    // appendPropertyRow：
    // - 作用：向属性表追加一条“字段名 + 字段值”记录，并设为只读。
    void appendPropertyRow(QTableWidget* propertyTable, const QString& fieldNameText, const QString& fieldValueText)
    {
        if (propertyTable == nullptr)
        {
            return;
        }

        const int rowIndex = propertyTable->rowCount();
        propertyTable->insertRow(rowIndex);

        auto* nameItem = new QTableWidgetItem(fieldNameText);
        auto* valueItem = new QTableWidgetItem(fieldValueText);

        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);

        propertyTable->setItem(rowIndex, 0, nameItem);
        propertyTable->setItem(rowIndex, 1, valueItem);
    }

    // findFirstEntryItem：
    // - 作用：在树中查找第一条绑定对象记录的节点。
    // - 返回：找到返回节点指针；否则返回 nullptr。
    QTreeWidgetItem* findFirstEntryItem(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return nullptr;
        }

        for (int rootIndex = 0; rootIndex < treeWidget->topLevelItemCount(); ++rootIndex)
        {
            QTreeWidgetItem* rootItem = treeWidget->topLevelItem(rootIndex);
            if (rootItem == nullptr)
            {
                continue;
            }

            for (int directoryIndex = 0; directoryIndex < rootItem->childCount(); ++directoryIndex)
            {
                QTreeWidgetItem* directoryItem = rootItem->child(directoryIndex);
                if (directoryItem == nullptr)
                {
                    continue;
                }

                for (int entryIndex = 0; entryIndex < directoryItem->childCount(); ++entryIndex)
                {
                    QTreeWidgetItem* entryItem = directoryItem->child(entryIndex);
                    if (entryItem == nullptr)
                    {
                        continue;
                    }

                    bool convertOk = false;
                    const qulonglong sourceIndex = entryItem->data(0, SourceIndexRole).toULongLong(&convertOk);
                    if (convertOk && sourceIndex != kInvalidSourceIndex)
                    {
                        return entryItem;
                    }
                }
            }
        }

        return nullptr;
    }

    // AtomColumn：原子表列索引。
    enum class AtomColumn : int
    {
        Value = 0,
        Hex,
        Name,
        Source,
        Status,
        Count
    };

    // NtQueryColumn：历史 NtQuery 表列索引。
    enum class NtQueryColumn : int
    {
        Category = 0,
        Function,
        QueryItem,
        Status,
        Summary,
        Count
    };
}

void KernelDock::refreshObjectNamespaceAsync()
{
    if (m_objectNamespaceRefreshRunning.exchange(true))
    {
        kLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] 对象命名空间刷新被忽略：已有任务运行。" << eol;
        return;
    }

    m_refreshObjectNamespaceButton->setEnabled(false);
    m_objectNamespaceStatusLabel->setText(kernelText("kernel.runtime.object_namespace.status.refreshing", QStringLiteral("状态：刷新中...")));
    m_objectNamespaceStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelObjectNamespaceEntry> resultRows;
        QString errorText;
        const bool success = runObjectNamespaceSnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(
            qApp, [guardThis, success, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_objectNamespaceRefreshRunning.store(false);
            guardThis->m_refreshObjectNamespaceButton->setEnabled(true);

            if (!success)
            {
                guardThis->m_objectNamespaceStatusLabel->setText(kernelText("kernel.runtime.object_namespace.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->m_objectNamespaceStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                guardThis->m_objectNamespaceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(errorText));

                kLogEvent failEvent;
                err << failEvent
                    << "[KernelDock] 对象命名空间刷新失败: "
                    << errorText.toStdString()
                    << eol;
                return;
            }

            guardThis->m_objectNamespaceRows = std::move(resultRows);
            guardThis->rebuildObjectNamespaceTable(guardThis->m_objectNamespaceFilterEdit->text().trimmed());

            const std::size_t failedCount = static_cast<std::size_t>(
                std::count_if(
                    guardThis->m_objectNamespaceRows.begin(),
                    guardThis->m_objectNamespaceRows.end(),
                    [](const KernelObjectNamespaceEntry& entry) {
                        return !entry.querySucceeded;
                    }));

            guardThis->m_objectNamespaceStatusLabel->setText(
                kernelText("kernel.runtime.object_namespace.status.summary", QStringLiteral("状态：已刷新 %1 项，异常 %2 项"))
                .arg(guardThis->m_objectNamespaceRows.size())
                .arg(failedCount));
            guardThis->m_objectNamespaceStatusLabel->setStyleSheet(
                statusLabelStyle(failedCount == 0 ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));

            if (guardThis->m_objectNamespaceTree->topLevelItemCount() > 0)
            {
                guardThis->selectFirstObjectNamespaceEntryItem();
            }
            else
            {
                guardThis->rebuildObjectNamespacePropertyTable(
                    nullptr,
                    kernelText("kernel.runtime.placeholder.no_visible_nodes", QStringLiteral("<无可见节点>")),
                    kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
                    kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")),
                    kernelText("kernel.runtime.object_namespace.empty.filtered", QStringLiteral("当前筛选条件下无可见对象记录。")));
                guardThis->m_objectNamespaceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.object_namespace.empty.filtered", QStringLiteral("当前筛选条件下无可见对象记录。"))));
            }

            kLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] 对象命名空间刷新完成, total="
                << guardThis->m_objectNamespaceRows.size()
                << ", failed="
                << failedCount
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshAtomTableAsync()
{
    if (m_atomRefreshRunning.exchange(true))
    {
        kLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] 原子表刷新被忽略：已有任务运行。" << eol;
        return;
    }

    m_refreshAtomButton->setEnabled(false);
    m_atomStatusLabel->setText(kernelText("kernel.runtime.atom.status.refreshing", QStringLiteral("状态：刷新中...")));
    m_atomStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelAtomEntry> resultRows;
        QString errorText;
        const bool success = runAtomTableSnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(
            qApp, [guardThis, success, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_atomRefreshRunning.store(false);
            guardThis->m_refreshAtomButton->setEnabled(true);

            if (!success)
            {
                guardThis->m_atomStatusLabel->setText(kernelText("kernel.runtime.atom.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->m_atomStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                guardThis->m_atomDetailEditor->setDocument(ks::ui::FieldDocument{}.note(errorText));

                kLogEvent failEvent;
                err << failEvent
                    << "[KernelDock] 原子表刷新失败: "
                    << errorText.toStdString()
                    << eol;
                return;
            }

            guardThis->m_atomRows = std::move(resultRows);
            guardThis->rebuildAtomTable(guardThis->m_atomFilterEdit->text().trimmed());
            guardThis->m_atomStatusLabel->setText(
                kernelText("kernel.runtime.atom.status.summary", QStringLiteral("状态：已刷新 %1 项"))
                .arg(guardThis->m_atomRows.size()));
            guardThis->m_atomStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::SuccessHex()));

            if (guardThis->m_atomTable->rowCount() > 0)
            {
                guardThis->m_atomTable->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->m_atomDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.atom.empty", QStringLiteral("当前环境未发现可见原子记录。"))));
            }

            kLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] 原子表刷新完成, count="
                << guardThis->m_atomRows.size()
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::refreshNtQueryAsync()
{
    if (m_ntQueryRefreshRunning.exchange(true))
    {
        kLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] NtQuery 刷新被忽略：已有任务运行。" << eol;
        return;
    }

    m_refreshNtQueryButton->setEnabled(false);
    m_ntQueryStatusLabel->setText(kernelText("kernel.runtime.nt_query.status.refreshing", QStringLiteral("状态：刷新中...")));
    m_ntQueryStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelNtQueryResultEntry> resultRows;
        QString errorText;
        const bool success = runNtQuerySnapshotTask(resultRows, errorText);

        QMetaObject::invokeMethod(
            qApp, [guardThis, success, errorText, resultRows = std::move(resultRows)]() mutable {
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_ntQueryRefreshRunning.store(false);
            guardThis->m_refreshNtQueryButton->setEnabled(true);

            if (!success)
            {
                guardThis->m_ntQueryStatusLabel->setText(kernelText("kernel.runtime.nt_query.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->m_ntQueryStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                guardThis->m_ntQueryDetailEditor->setDocument(ks::ui::FieldDocument{}.note(errorText));

                kLogEvent failEvent;
                err << failEvent
                    << "[KernelDock] NtQuery 刷新失败: "
                    << errorText.toStdString()
                    << eol;
                return;
            }

            guardThis->m_ntQueryResults = std::move(resultRows);
            guardThis->rebuildNtQueryTable();

            int successCount = 0;
            for (const KernelNtQueryResultEntry& entry : guardThis->m_ntQueryResults)
            {
                if (entry.statusCode >= 0)
                {
                    ++successCount;
                }
            }

            guardThis->m_ntQueryStatusLabel->setText(
                kernelText("kernel.runtime.nt_query.status.summary", QStringLiteral("状态：已刷新 %1 项，成功 %2 项"))
                .arg(guardThis->m_ntQueryResults.size())
                .arg(successCount));
            guardThis->m_ntQueryStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::SuccessHex()));

            if (guardThis->m_ntQueryTable->rowCount() > 0)
            {
                guardThis->m_ntQueryTable->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->m_ntQueryDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.nt_query.empty", QStringLiteral("无可展示的 NtQuery 结果。"))));
            }

            kLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] NtQuery 刷新完成, total="
                << guardThis->m_ntQueryResults.size()
                << ", success="
                << successCount
                << eol;
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildObjectNamespaceTable(const QString& filterKeyword)
{
    if (m_objectNamespaceTree == nullptr)
    {
        return;
    }

    m_objectNamespaceTree->clear();

    // rootItemMap：缓存“根路径 -> 根节点”映射，避免重复创建根节点。
    QMap<QString, QTreeWidgetItem*> rootItemMap;
    // directoryItemMap：缓存“根路径+目录路径 -> 目录节点”映射，避免重复创建目录节点。
    QMap<QString, QTreeWidgetItem*> directoryItemMap;

    for (std::size_t sourceIndex = 0; sourceIndex < m_objectNamespaceRows.size(); ++sourceIndex)
    {
        const KernelObjectNamespaceEntry& entry = m_objectNamespaceRows[sourceIndex];
        const bool matched = filterKeyword.isEmpty()
            || entry.rootPathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.scopeDescriptionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.directoryPathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.objectNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.objectTypeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fullPathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.enumApiText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.symbolicLinkTargetText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!matched)
        {
            continue;
        }

        QTreeWidgetItem* rootItem = rootItemMap.value(entry.rootPathText, nullptr);
        if (rootItem == nullptr)
        {
            rootItem = new QTreeWidgetItem(m_objectNamespaceTree);
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::Name), entry.rootPathText);
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::Type), kernelText("kernel.runtime.object_namespace.node.root_directory", QStringLiteral("根目录")));
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::PathOrScope), safeText(entry.scopeDescriptionText));
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::Status), kernelText("kernel.runtime.object_namespace.node.root", QStringLiteral("根节点")));
            rootItem->setText(static_cast<int>(ObjectNamespaceColumn::SymbolicTarget), kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")));
            rootItem->setData(0, SourceIndexRole, kInvalidSourceIndex);
            rootItem->setData(0, NodeKindRole, static_cast<int>(ObjectNamespaceNodeKind::Root));
            rootItem->setData(0, NodePathRole, entry.rootPathText);
            rootItem->setData(0, NodeDescriptionRole, entry.scopeDescriptionText);
            ks::ui::ApplyThemeItemForeground(rootItem,
                static_cast<int>(ObjectNamespaceColumn::Type),
                ks::ui::ItemForegroundRole::Accent);

            rootItemMap.insert(entry.rootPathText, rootItem);
        }

        const QString directoryKeyText = entry.rootPathText + QChar('\n') + entry.directoryPathText;
        QTreeWidgetItem* directoryItem = directoryItemMap.value(directoryKeyText, nullptr);
        if (directoryItem == nullptr)
        {
            directoryItem = new QTreeWidgetItem(rootItem);
            directoryItem->setText(
                static_cast<int>(ObjectNamespaceColumn::Name),
                leafNameFromObjectPath(entry.directoryPathText));
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::Type), kernelText("kernel.runtime.object_namespace.node.directory", QStringLiteral("目录")));
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::PathOrScope), entry.directoryPathText);
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::Status), kernelText("kernel.runtime.object_namespace.node.enumerated", QStringLiteral("已展开枚举")));
            directoryItem->setText(static_cast<int>(ObjectNamespaceColumn::SymbolicTarget), kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")));
            directoryItem->setData(0, SourceIndexRole, kInvalidSourceIndex);
            directoryItem->setData(0, NodeKindRole, static_cast<int>(ObjectNamespaceNodeKind::Directory));
            directoryItem->setData(0, NodePathRole, entry.directoryPathText);
            directoryItem->setData(0, NodeDescriptionRole, entry.scopeDescriptionText);
            ks::ui::ApplyThemeItemForeground(directoryItem,
                static_cast<int>(ObjectNamespaceColumn::Type),
                ks::ui::ItemForegroundRole::Accent);

            directoryItemMap.insert(directoryKeyText, directoryItem);
        }

        auto* objectItem = new QTreeWidgetItem(directoryItem);
        const QString objectNameText = entry.objectNameText.trimmed().isEmpty()
            ? kernelText("kernel.runtime.placeholder.unnamed_object", QStringLiteral("<未命名对象>"))
            : entry.objectNameText;
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::Name), objectNameText);
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::Type), safeText(entry.objectTypeText));
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::PathOrScope), safeText(entry.fullPathText));
        objectItem->setText(static_cast<int>(ObjectNamespaceColumn::Status), safeText(entry.statusText));
        objectItem->setText(
            static_cast<int>(ObjectNamespaceColumn::SymbolicTarget),
            safeText(entry.symbolicLinkTargetText));
        objectItem->setData(0, SourceIndexRole, static_cast<qulonglong>(sourceIndex));
        objectItem->setData(0, NodeKindRole, static_cast<int>(ObjectNamespaceNodeKind::ObjectEntry));
        objectItem->setData(0, NodePathRole, entry.fullPathText);
        objectItem->setData(0, NodeDescriptionRole, entry.scopeDescriptionText);

        if (!entry.querySucceeded)
        {
            ks::ui::ApplyThemeItemForeground(objectItem,
                static_cast<int>(ObjectNamespaceColumn::Status),
                ks::ui::ItemForegroundRole::Warning);
        }
        else if (entry.isDirectory)
        {
            ks::ui::ApplyThemeItemForeground(objectItem,
                static_cast<int>(ObjectNamespaceColumn::Type),
                ks::ui::ItemForegroundRole::Accent);
        }
    }

    if (!filterKeyword.isEmpty())
    {
        m_objectNamespaceTree->expandAll();
    }
    else
    {
        for (int rootIndex = 0; rootIndex < m_objectNamespaceTree->topLevelItemCount(); ++rootIndex)
        {
            QTreeWidgetItem* rootItem = m_objectNamespaceTree->topLevelItem(rootIndex);
            if (rootItem == nullptr)
            {
                continue;
            }
            rootItem->setExpanded(true);
            for (int directoryIndex = 0; directoryIndex < rootItem->childCount(); ++directoryIndex)
            {
                QTreeWidgetItem* directoryItem = rootItem->child(directoryIndex);
                if (directoryItem != nullptr)
                {
                    directoryItem->setExpanded(false);
                }
            }
        }
    }

    if (m_objectNamespaceTree->currentItem() == nullptr)
    {
        selectFirstObjectNamespaceEntryItem();
    }
}

void KernelDock::rebuildObjectNamespacePropertyTable(
    const KernelObjectNamespaceEntry* entry,
    const QString& nodeNameText,
    const QString& nodeTypeText,
    const QString& nodePathText,
    const QString& nodeDescriptionText)
{
    if (m_objectNamespacePropertyTable == nullptr)
    {
        return;
    }

    m_objectNamespacePropertyTable->setRowCount(0);

    if (entry == nullptr)
    {
        appendPropertyRow(m_objectNamespacePropertyTable, kernelText("kernel.runtime.object_namespace.property.node_name", QStringLiteral("节点名称")), safeText(nodeNameText));
        appendPropertyRow(m_objectNamespacePropertyTable, kernelText("kernel.runtime.object_namespace.property.node_type", QStringLiteral("节点类型")), safeText(nodeTypeText));
        appendPropertyRow(m_objectNamespacePropertyTable, kernelText("kernel.runtime.object_namespace.property.node_path", QStringLiteral("节点路径")), safeText(nodePathText));
        appendPropertyRow(m_objectNamespacePropertyTable, kernelText("kernel.runtime.object_namespace.property.node_description", QStringLiteral("节点说明")), safeText(nodeDescriptionText));
        appendPropertyRow(
            m_objectNamespacePropertyTable,
            kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
            kernelText("kernel.runtime.object_namespace.property.tree_summary", QStringLiteral("当前节点是树层级摘要，展开下级并选择对象项可查看完整字段。")));
        return;
    }

    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.root_path", QStringLiteral("rootPathText（根目录）")),
        safeText(entry->rootPathText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.scope_description", QStringLiteral("scopeDescriptionText（作用说明）")),
        safeText(entry->scopeDescriptionText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.directory_path", QStringLiteral("directoryPathText（当前目录）")),
        safeText(entry->directoryPathText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.object_name", QStringLiteral("objectNameText（对象名）")),
        safeText(entry->objectNameText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.object_type", QStringLiteral("objectTypeText（对象类型）")),
        safeText(entry->objectTypeText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.full_path", QStringLiteral("fullPathText（完整路径）")),
        safeText(entry->fullPathText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.enum_api", QStringLiteral("enumApiText（枚举API）")),
        safeText(entry->enumApiText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.symbolic_target", QStringLiteral("symbolicLinkTargetText（符号链接目标）")),
        safeText(entry->symbolicLinkTargetText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.status_text", QStringLiteral("statusText（状态）")),
        safeText(entry->statusText));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.status_code", QStringLiteral("statusCode（NTSTATUS）")),
        QStringLiteral("0x%1").arg(static_cast<unsigned int>(entry->statusCode), 8, 16, QChar('0')).toUpper());
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.query_succeeded", QStringLiteral("querySucceeded（查询成功）")),
        entry->querySucceeded ? QStringLiteral("true") : QStringLiteral("false"));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.is_directory", QStringLiteral("isDirectory（是否目录）")),
        entry->isDirectory ? QStringLiteral("true") : QStringLiteral("false"));
    appendPropertyRow(
        m_objectNamespacePropertyTable,
        kernelText("kernel.runtime.object_namespace.property.is_symbolic_link", QStringLiteral("isSymbolicLink（是否符号链接）")),
        entry->isSymbolicLink ? QStringLiteral("true") : QStringLiteral("false"));
}

void KernelDock::selectFirstObjectNamespaceEntryItem()
{
    if (m_objectNamespaceTree == nullptr)
    {
        return;
    }

    QTreeWidgetItem* firstEntryItem = findFirstEntryItem(m_objectNamespaceTree);
    if (firstEntryItem != nullptr)
    {
        m_objectNamespaceTree->setCurrentItem(firstEntryItem, 0);
        return;
    }

    if (m_objectNamespaceTree->topLevelItemCount() > 0)
    {
        m_objectNamespaceTree->setCurrentItem(m_objectNamespaceTree->topLevelItem(0), 0);
        return;
    }

    rebuildObjectNamespacePropertyTable(
        nullptr,
        kernelText("kernel.runtime.placeholder.no_node", QStringLiteral("<无节点>")),
        kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
        kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")),
        kernelText("kernel.runtime.object_namespace.empty.tree", QStringLiteral("当前对象命名空间树为空。")));
    m_objectNamespaceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.object_namespace.empty.tree", QStringLiteral("当前对象命名空间树为空。"))));
}

void KernelDock::rebuildAtomTable(const QString& filterKeyword)
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_atomDetailEditor);
    if (m_atomTable == nullptr)
    {
        return;
    }

    m_atomTable->setSortingEnabled(false);
    m_atomTable->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < m_atomRows.size(); ++sourceIndex)
    {
        const KernelAtomEntry& entry = m_atomRows[sourceIndex];
        const QString valueText = QString::number(entry.atomValue);
        const QString hexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(entry.atomValue), 4, 16, QChar('0'))
            .toUpper();

        const bool matched = filterKeyword.isEmpty()
            || valueText.contains(filterKeyword, Qt::CaseInsensitive)
            || hexText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.atomNameText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!matched)
        {
            continue;
        }

        const int rowIndex = m_atomTable->rowCount();
        m_atomTable->insertRow(rowIndex);

        auto* valueItem = new QTableWidgetItem(valueText);
        valueItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* hexItem = new QTableWidgetItem(hexText);
        auto* nameItem = new QTableWidgetItem(entry.atomNameText);
        auto* sourceItem = new QTableWidgetItem(entry.sourceText);
        auto* statusItem = new QTableWidgetItem(entry.statusText);

        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);
        hexItem->setFlags(hexItem->flags() & ~Qt::ItemIsEditable);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        sourceItem->setFlags(sourceItem->flags() & ~Qt::ItemIsEditable);
        statusItem->setFlags(statusItem->flags() & ~Qt::ItemIsEditable);

        if (!entry.querySucceeded)
        {
            statusItem->setForeground(QBrush(KswordTheme::WarningAccentColor()));
        }

        m_atomTable->setItem(rowIndex, static_cast<int>(AtomColumn::Value), valueItem);
        m_atomTable->setItem(rowIndex, static_cast<int>(AtomColumn::Hex), hexItem);
        m_atomTable->setItem(rowIndex, static_cast<int>(AtomColumn::Name), nameItem);
        m_atomTable->setItem(rowIndex, static_cast<int>(AtomColumn::Source), sourceItem);
        m_atomTable->setItem(rowIndex, static_cast<int>(AtomColumn::Status), statusItem);
    }

    m_atomTable->setSortingEnabled(true);
}

void KernelDock::rebuildNtQueryTable()
{
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_ntQueryDetailEditor);
    if (m_ntQueryTable == nullptr)
    {
        return;
    }

    m_ntQueryTable->setSortingEnabled(false);
    m_ntQueryTable->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < m_ntQueryResults.size(); ++sourceIndex)
    {
        const KernelNtQueryResultEntry& entry = m_ntQueryResults[sourceIndex];
        const int rowIndex = m_ntQueryTable->rowCount();
        m_ntQueryTable->insertRow(rowIndex);

        auto* categoryItem = new QTableWidgetItem(entry.categoryText);
        categoryItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* functionItem = new QTableWidgetItem(entry.functionNameText);
        auto* queryItem = new QTableWidgetItem(entry.queryItemText);
        auto* statusItem = new QTableWidgetItem(entry.statusText);
        auto* summaryItem = new QTableWidgetItem(entry.summaryText);

        categoryItem->setFlags(categoryItem->flags() & ~Qt::ItemIsEditable);
        functionItem->setFlags(functionItem->flags() & ~Qt::ItemIsEditable);
        queryItem->setFlags(queryItem->flags() & ~Qt::ItemIsEditable);
        statusItem->setFlags(statusItem->flags() & ~Qt::ItemIsEditable);
        summaryItem->setFlags(summaryItem->flags() & ~Qt::ItemIsEditable);

        if (entry.statusCode < 0)
        {
            statusItem->setForeground(QBrush(KswordTheme::WarningAccentColor()));
        }

        m_ntQueryTable->setItem(rowIndex, static_cast<int>(NtQueryColumn::Category), categoryItem);
        m_ntQueryTable->setItem(rowIndex, static_cast<int>(NtQueryColumn::Function), functionItem);
        m_ntQueryTable->setItem(rowIndex, static_cast<int>(NtQueryColumn::QueryItem), queryItem);
        m_ntQueryTable->setItem(rowIndex, static_cast<int>(NtQueryColumn::Status), statusItem);
        m_ntQueryTable->setItem(rowIndex, static_cast<int>(NtQueryColumn::Summary), summaryItem);
    }

    m_ntQueryTable->setSortingEnabled(true);
}

bool KernelDock::currentObjectNamespaceSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0;

    if (m_objectNamespaceTree == nullptr)
    {
        return false;
    }

    QTreeWidgetItem* currentItem = m_objectNamespaceTree->currentItem();
    if (currentItem == nullptr)
    {
        return false;
    }

    bool convertOk = false;
    const qulonglong sourceIndex = currentItem->data(0, SourceIndexRole).toULongLong(&convertOk);
    if (!convertOk || sourceIndex == kInvalidSourceIndex)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(sourceIndex);
    return sourceIndexOut < m_objectNamespaceRows.size();
}

bool KernelDock::currentAtomSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0;

    if (m_atomTable == nullptr)
    {
        return false;
    }

    const int currentRow = m_atomTable->currentRow();
    if (currentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* valueItem = m_atomTable->item(currentRow, static_cast<int>(AtomColumn::Value));
    if (valueItem == nullptr)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(valueItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < m_atomRows.size();
}

const KernelObjectNamespaceEntry* KernelDock::currentObjectNamespaceEntry() const
{
    std::size_t sourceIndex = 0;
    if (!currentObjectNamespaceSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &m_objectNamespaceRows[sourceIndex];
}

const KernelAtomEntry* KernelDock::currentAtomEntry() const
{
    std::size_t sourceIndex = 0;
    if (!currentAtomSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &m_atomRows[sourceIndex];
}

void KernelDock::showObjectNamespaceDetailByCurrentRow()
{
    if (m_objectNamespaceDetailEditor == nullptr || m_objectNamespaceTree == nullptr)
    {
        return;
    }

    QTreeWidgetItem* currentItem = m_objectNamespaceTree->currentItem();
    if (currentItem == nullptr)
    {
        rebuildObjectNamespacePropertyTable(
            nullptr,
            kernelText("kernel.runtime.placeholder.unselected_node", QStringLiteral("<未选择节点>")),
            kernelText("kernel.runtime.placeholder.hint", QStringLiteral("提示")),
            kernelText("kernel.runtime.placeholder.none", QStringLiteral("<无>")),
            kernelText("kernel.runtime.object_namespace.detail.select_node", QStringLiteral("请选择左侧树节点查看对象字段。")));
        m_objectNamespaceDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.object_namespace.detail.initial", QStringLiteral("请选择对象命名空间树节点查看详情。"))));
        return;
    }

    const QString nodeNameText = safeText(currentItem->text(static_cast<int>(ObjectNamespaceColumn::Name)));
    const QString nodeTypeText = safeText(currentItem->text(static_cast<int>(ObjectNamespaceColumn::Type)));
    const QString nodePathText = safeText(currentItem->data(0, NodePathRole).toString());
    const QString nodeDescriptionText = safeText(currentItem->data(0, NodeDescriptionRole).toString());

    const KernelObjectNamespaceEntry* entry = currentObjectNamespaceEntry();
    if (entry == nullptr)
    {
        rebuildObjectNamespacePropertyTable(
            nullptr,
            nodeNameText,
            nodeTypeText,
            nodePathText,
            nodeDescriptionText);
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("对象命名空间节点"));
        document.field(QStringLiteral("当前节点名称"), nodeNameText);
        document.field(QStringLiteral("当前节点类型"), nodeTypeText, true);
        document.field(QStringLiteral("当前节点路径"), nodePathText);
        document.field(QStringLiteral("节点说明"), nodeDescriptionText, true);
        document.note(QStringLiteral("提示: 请选择目录下具体对象项以查看完整对象字段。"));
        m_objectNamespaceDetailEditor->setDocument(document);
        return;
    }

    rebuildObjectNamespacePropertyTable(
        entry,
        nodeNameText,
        nodeTypeText,
        nodePathText,
        nodeDescriptionText);

    ks::ui::FieldDocument document;
    document.section(QStringLiteral("对象命名空间详情"));
    document.field(QStringLiteral("树节点名称"), nodeNameText);
    document.field(QStringLiteral("树节点类型"), nodeTypeText, true);
    document.field(QStringLiteral("目录路径"), safeText(entry->rootPathText));
    document.field(QStringLiteral("作用说明"), safeText(entry->scopeDescriptionText), true);
    document.field(QStringLiteral("当前目录"), safeText(entry->directoryPathText));
    document.field(QStringLiteral("对象名"), safeText(entry->objectNameText));
    document.field(QStringLiteral("对象类型"), safeText(entry->objectTypeText), true);
    document.field(QStringLiteral("完整路径"), safeText(entry->fullPathText));
    document.field(QStringLiteral("枚举 API"), safeText(entry->enumApiText));
    document.field(QStringLiteral("符号链接目标"), safeText(entry->symbolicLinkTargetText));
    document.field(QStringLiteral("状态"), safeText(entry->statusText), true);
    document.field(QStringLiteral("是否目录"), entry->isDirectory ? QStringLiteral("是") : QStringLiteral("否"), true);
    document.field(QStringLiteral("是否符号链接"), entry->isSymbolicLink ? QStringLiteral("是") : QStringLiteral("否"), true);
    document.nodes += entry->detailDocument.nodes;
    m_objectNamespaceDetailEditor->setDocument(document);
}

void KernelDock::showAtomDetailByCurrentRow()
{
    if (m_atomDetailEditor == nullptr)
    {
        return;
    }

    const KernelAtomEntry* entry = currentAtomEntry();
    if (entry == nullptr)
    {
        m_atomDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.atom.detail.initial", QStringLiteral("请选择一条原子记录查看详情。"))));
        return;
    }

    ks::ui::FieldDocument document;
    document.section(QStringLiteral("原子详情"));
    document.field(QStringLiteral("Atom值"), QString::number(entry->atomValue));
    document.field(QStringLiteral("十六进制"), QStringLiteral("0x%1").arg(static_cast<unsigned int>(entry->atomValue), 4, 16, QChar('0')));
    document.field(QStringLiteral("名称"), safeText(entry->atomNameText));
    document.field(QStringLiteral("来源"), safeText(entry->sourceText));
    document.field(QStringLiteral("状态"), safeText(entry->statusText), true);
    document.nodes += entry->detailDocument.nodes;
    m_atomDetailEditor->setDocument(document);
}

void KernelDock::showNtQueryDetailByCurrentRow()
{
    if (m_ntQueryTable == nullptr || m_ntQueryDetailEditor == nullptr)
    {
        return;
    }

    const int currentRow = m_ntQueryTable->currentRow();
    if (currentRow < 0)
    {
        m_ntQueryDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.nt_query.detail.initial", QStringLiteral("请选择一条 NtQuery 结果查看详情。"))));
        return;
    }

    QTableWidgetItem* categoryItem = m_ntQueryTable->item(currentRow, static_cast<int>(NtQueryColumn::Category));
    if (categoryItem == nullptr)
    {
        m_ntQueryDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.nt_query.detail.no_row", QStringLiteral("当前行无有效数据。"))));
        return;
    }

    const std::size_t sourceIndex = static_cast<std::size_t>(categoryItem->data(Qt::UserRole).toULongLong());
    if (sourceIndex >= m_ntQueryResults.size())
    {
        m_ntQueryDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.runtime.nt_query.detail.out_of_range", QStringLiteral("索引越界。"))));
        return;
    }

    const KernelNtQueryResultEntry& entry = m_ntQueryResults[sourceIndex];
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("NtQuery 详情"));
    document.field(QStringLiteral("类别"), entry.categoryText, true);
    document.field(QStringLiteral("函数"), entry.functionNameText);
    document.field(QStringLiteral("查询项"), entry.queryItemText);
    document.field(QStringLiteral("状态"), entry.statusText, true);
    document.field(QStringLiteral("摘要"), entry.summaryText, true);
    document.nodes += entry.detailDocument.nodes;
    m_ntQueryDetailEditor->setDocument(document);
}
