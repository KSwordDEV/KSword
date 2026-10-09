
#include "KernelDock.h"

// ============================================================
// KernelDock.ContextMenu.cpp
// 作用说明：
// 1) 承载对象命名空间树右键菜单；
// 2) 承载原子表右键菜单；
// 3) 实现复制与针对对象/原子的快捷操作。
// ============================================================

#include "KernelDockAtomWorker.h"
#include "KernelHvmTab.h"
#include "KernelDockObjectNamespaceWorker.h"
#include "../UI/StructuredFieldView.h"
#include "../theme.h"

#include <QApplication>
#include <QClipboard>
#include <QDialog>
#include <QIcon>
#include <QLineEdit>
#include <QMenu>
#include <QModelIndex>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // safeText：
    // - 作用：复制时将空文本替换为占位符，避免 TSV 字段错位。
    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.context.placeholder.empty", QStringLiteral("<空>")));
    }

    // isNtDevicePath：
    // - 作用：判断路径是否为 NT 设备路径（\Device\...）。
    bool isNtDevicePath(const QString& pathText)
    {
        return pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive);
    }

    // copyTextToClipboard：
    // - 作用：统一剪贴板写入逻辑。
    void copyTextToClipboard(const QString& contentText)
    {
        if (QApplication::clipboard() != nullptr)
        {
            QApplication::clipboard()->setText(contentText);
        }
    }

    void showHvmFeatureDialog(
        QWidget* parent,
        const KernelHvmTab::FeatureArea featureArea)
    {
        auto* dialog = new QDialog(parent);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setModal(false);
        dialog->resize(1180, 760);
        switch (featureArea)
        {
        case KernelHvmTab::FeatureArea::Ept:
            dialog->setWindowTitle(
                kernelText(
                    "kernel.hvm.dialog.ept",
                    QStringLiteral("内核虚拟化 - EPT")));
            break;
        case KernelHvmTab::FeatureArea::NestedVmx:
            dialog->setWindowTitle(
                kernelText(
                    "kernel.hvm.dialog.nested",
                    QStringLiteral("内核虚拟化 - Nested VMX")));
            break;
        case KernelHvmTab::FeatureArea::Evmcs:
            dialog->setWindowTitle(
                kernelText(
                    "kernel.hvm.dialog.evmcs",
                    QStringLiteral("内核虚拟化 - Hyper-V eVMCS（partial）")));
            break;
        }
        auto* layout = new QVBoxLayout(dialog);
        layout->setContentsMargins(6, 6, 6, 6);
        layout->addWidget(
            new KernelHvmTab(featureArea, dialog),
            1);
        dialog->show();
        dialog->raise();
        dialog->activateWindow();
    }

    // treeItemAsTsv：
    // - 作用：把树节点当前行序列化为 TSV。
    QString treeItemAsTsv(const QTreeWidget* treeWidget, const QTreeWidgetItem* treeItem)
    {
        if (treeWidget == nullptr || treeItem == nullptr)
        {
            return QString();
        }

        QStringList fieldList;
        for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
        {
            fieldList.push_back(treeItem->text(columnIndex));
        }
        return fieldList.join('\t');
    }

    // objectNamespaceEntryAsTsv：
    // - 作用：把对象命名空间条目序列化为 TSV。
    QString objectNamespaceEntryAsTsv(const KernelObjectNamespaceEntry& entry)
    {
        return QStringLiteral("%1\t%2\t%3\t%4\t%5\t%6\t%7\t%8\t%9")
            .arg(
                safeText(entry.rootPathText),
                safeText(entry.scopeDescriptionText),
                safeText(entry.directoryPathText),
                safeText(entry.objectNameText),
                safeText(entry.objectTypeText),
                safeText(entry.fullPathText),
                safeText(entry.enumApiText),
                safeText(entry.symbolicLinkTargetText),
                safeText(entry.statusText));
    }

    // atomEntryAsTsv：
    // - 作用：把原子条目序列化为 TSV。
    QString atomEntryAsTsv(const KernelAtomEntry& entry)
    {
        const QString hexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(entry.atomValue), 4, 16, QChar('0'))
            .toUpper();

        return QStringLiteral("%1\t%2\t%3\t%4\t%5")
            .arg(QString::number(entry.atomValue), hexText, safeText(entry.atomNameText), safeText(entry.sourceText), safeText(entry.statusText));
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
}

void KernelDock::showObjectNamespaceContextMenu(const QPoint& localPosition)
{
    if (m_objectNamespaceTree == nullptr)
    {
        return;
    }

    QTreeWidgetItem* clickedItem = m_objectNamespaceTree->itemAt(localPosition);
    const int clickedColumn = m_objectNamespaceTree->columnAt(localPosition.x());
    if (clickedItem != nullptr)
    {
        m_objectNamespaceTree->setCurrentItem(clickedItem, clickedColumn >= 0 ? clickedColumn : 0);
    }

    QTreeWidgetItem* currentItem = m_objectNamespaceTree->currentItem();
    const KernelObjectNamespaceEntry* entry = currentObjectNamespaceEntry();
    const bool hasEntry = (entry != nullptr);
    const bool hasTreeNode = (currentItem != nullptr);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());

    QAction* refreshAction = contextMenu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.context.object.refresh", QStringLiteral("刷新对象命名空间")));
    contextMenu.addSeparator();

    QMenu* copyMenu = contextMenu.addMenu(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCellAction = copyMenu->addAction(QIcon(":/Icon/process_copy_cell.svg"), kernelText("kernel.context.menu.copy_cell", QStringLiteral("复制当前单元格")));
    QAction* copyObjectNameAction = copyMenu->addAction(kernelText("kernel.context.object.copy_name", QStringLiteral("复制对象名")));
    QAction* copyObjectTypeAction = copyMenu->addAction(kernelText("kernel.context.object.copy_type", QStringLiteral("复制对象类型")));
    QAction* copyFullPathAction = copyMenu->addAction(kernelText("kernel.context.object.copy_full_path", QStringLiteral("复制完整路径")));
    QAction* copySymbolicTargetAction = copyMenu->addAction(kernelText("kernel.context.object.copy_symbolic_target", QStringLiteral("复制符号链接目标")));
    QAction* copyEnumApiAction = copyMenu->addAction(kernelText("kernel.context.object.copy_enum_api", QStringLiteral("复制枚举 API")));
    QAction* copyRowAction = copyMenu->addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制当前行")));
    QAction* copySameRootRowsAction = copyMenu->addAction(kernelText("kernel.context.object.copy_same_directory", QStringLiteral("复制同目录路径全部行")));

    copyObjectNameAction->setEnabled(hasEntry);
    copyObjectTypeAction->setEnabled(hasEntry);
    copyFullPathAction->setEnabled(hasEntry);
    copySymbolicTargetAction->setEnabled(hasEntry && !entry->symbolicLinkTargetText.trimmed().isEmpty());
    copyEnumApiAction->setEnabled(hasEntry);
    copyRowAction->setEnabled(hasTreeNode);
    copySameRootRowsAction->setEnabled(hasEntry);

    QMenu* operationMenu = contextMenu.addMenu(QIcon(":/Icon/process_tree.svg"), kernelText("kernel.context.object.operation", QStringLiteral("对象操作")));
    QAction* filterByRootAction = operationMenu->addAction(kernelText("kernel.context.object.filter_root", QStringLiteral("用目录路径过滤")));
    QAction* filterByDirectoryAction = operationMenu->addAction(kernelText("kernel.context.object.filter_directory", QStringLiteral("用当前目录过滤")));
    QAction* filterByObjectNameAction = operationMenu->addAction(kernelText("kernel.context.object.filter_name", QStringLiteral("用对象名过滤")));
    QAction* resolveSymbolicLinkAction = operationMenu->addAction(kernelText("kernel.context.object.resolve_symbolic_target", QStringLiteral("解析符号链接目标")));
    QAction* mapDosPathAction = operationMenu->addAction(kernelText("kernel.context.object.map_dos_path", QStringLiteral("尝试映射为 DOS 路径")));

    contextMenu.addSeparator();
    QMenu* moreActionsMenu = contextMenu.addMenu(
        kernelText(
            "kernel.context.more_actions",
            QStringLiteral("更多操作")));
    QMenu* virtualizationMenu = moreActionsMenu->addMenu(
        kernelText(
            "kernel.context.virtualization",
            QStringLiteral("虚拟化")));
    QAction* eptAction = virtualizationMenu->addAction(
        QStringLiteral("EPT"));
    // "(partial)" 拿掉：vmcs02 合并、退出反射与影子 EPT 都已实现并验证过，
    // 留着这个后缀会让人以为点进去的是个探测桩。eVMCS 那一项保留，它确实还是。
    QAction* nestedVmxAction = virtualizationMenu->addAction(
        QStringLiteral("Nested VMX"));
    QAction* evmcsAction = virtualizationMenu->addAction(
        QStringLiteral("Hyper-V eVMCS (partial)"));

    filterByRootAction->setEnabled(hasEntry);
    filterByDirectoryAction->setEnabled(hasEntry);
    filterByObjectNameAction->setEnabled(hasEntry && !entry->objectNameText.trimmed().isEmpty());
    resolveSymbolicLinkAction->setEnabled(hasEntry && entry->isSymbolicLink);
    mapDosPathAction->setEnabled(hasEntry && (isNtDevicePath(entry->fullPathText) || isNtDevicePath(entry->symbolicLinkTargetText)));

    QAction* selectedAction = contextMenu.exec(m_objectNamespaceTree->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    kLogEvent menuEvent;
    info << menuEvent
        << "[KernelDock] 对象命名空间右键动作: "
        << selectedAction->text().toStdString()
        << eol;

    if (selectedAction == refreshAction)
    {
        refreshObjectNamespaceAsync();
        return;
    }

    if (selectedAction == eptAction)
    {
        showHvmFeatureDialog(
            this,
            KernelHvmTab::FeatureArea::Ept);
        return;
    }
    if (selectedAction == nestedVmxAction)
    {
        showHvmFeatureDialog(
            this,
            KernelHvmTab::FeatureArea::NestedVmx);
        return;
    }
    if (selectedAction == evmcsAction)
    {
        showHvmFeatureDialog(
            this,
            KernelHvmTab::FeatureArea::Evmcs);
        return;
    }

    if (selectedAction == copyCellAction)
    {
        QTreeWidgetItem* selectedTreeItem = m_objectNamespaceTree->currentItem();
        if (selectedTreeItem != nullptr)
        {
            int currentColumn = m_objectNamespaceTree->currentColumn();
            if (currentColumn < 0)
            {
                currentColumn = 0;
            }
            copyTextToClipboard(selectedTreeItem->text(currentColumn));
        }
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QTreeWidgetItem* selectedTreeItem = m_objectNamespaceTree->currentItem();
        if (hasEntry)
        {
            copyTextToClipboard(objectNamespaceEntryAsTsv(*entry));
        }
        else if (selectedTreeItem != nullptr)
        {
            copyTextToClipboard(treeItemAsTsv(m_objectNamespaceTree, selectedTreeItem));
        }
        return;
    }

    if (!hasEntry)
    {
        return;
    }

    if (selectedAction == copyObjectNameAction)
    {
        copyTextToClipboard(entry->objectNameText);
        return;
    }
    if (selectedAction == copyObjectTypeAction)
    {
        copyTextToClipboard(entry->objectTypeText);
        return;
    }
    if (selectedAction == copyFullPathAction)
    {
        copyTextToClipboard(entry->fullPathText);
        return;
    }
    if (selectedAction == copySymbolicTargetAction)
    {
        copyTextToClipboard(entry->symbolicLinkTargetText);
        return;
    }
    if (selectedAction == copyEnumApiAction)
    {
        copyTextToClipboard(entry->enumApiText);
        return;
    }
    if (selectedAction == copySameRootRowsAction)
    {
        QStringList rowList;
        for (const KernelObjectNamespaceEntry& rowEntry : m_objectNamespaceRows)
        {
            if (QString::compare(rowEntry.directoryPathText, entry->directoryPathText, Qt::CaseInsensitive) == 0)
            {
                rowList.push_back(objectNamespaceEntryAsTsv(rowEntry));
            }
        }
        copyTextToClipboard(rowList.join('\n'));
        return;
    }

    if (selectedAction == filterByRootAction)
    {
        m_objectNamespaceFilterEdit->setText(entry->rootPathText);
        return;
    }
    if (selectedAction == filterByDirectoryAction)
    {
        m_objectNamespaceFilterEdit->setText(entry->directoryPathText);
        return;
    }
    if (selectedAction == filterByObjectNameAction)
    {
        m_objectNamespaceFilterEdit->setText(entry->objectNameText);
        return;
    }
    if (selectedAction == resolveSymbolicLinkAction)
    {
        QString targetText;
        QString statusText;
        const bool resolveOk = queryObjectNamespaceSymbolicLinkTarget(entry->fullPathText, targetText, statusText);

        ks::ui::FieldDocument resultDocument;
        resultDocument.section(QStringLiteral("符号链接解析"));
        resultDocument.field(QStringLiteral("符号链接路径"), entry->fullPathText);
        resultDocument.field(QStringLiteral("解析状态"), statusText, true);
        resultDocument.field(QStringLiteral("目标路径"), resolveOk ? targetText : kernelText("kernel.context.placeholder.resolve_failed", QStringLiteral("<解析失败>")));

        std::size_t sourceIndex = 0;
        if (resolveOk && currentObjectNamespaceSourceIndex(sourceIndex))
        {
            m_objectNamespaceRows[sourceIndex].symbolicLinkTargetText = targetText;
            QTreeWidgetItem* selectedTreeItem = m_objectNamespaceTree->currentItem();
            if (selectedTreeItem != nullptr)
            {
                selectedTreeItem->setText(static_cast<int>(ObjectNamespaceColumn::SymbolicTarget), targetText);
            }
        }

        showObjectNamespaceDetailByCurrentRow();
        m_objectNamespaceDetailEditor->setDocument(resultDocument);
        return;
    }
    if (selectedAction == mapDosPathAction)
    {
        QString sourcePathText;
        if (isNtDevicePath(entry->fullPathText))
        {
            sourcePathText = entry->fullPathText;
        }
        else
        {
            sourcePathText = entry->symbolicLinkTargetText;
        }

        const std::vector<QString> candidateList = queryDosPathCandidatesByNtPath(sourcePathText);
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("DOS 路径映射"));
        document.field(QStringLiteral("路径"), sourcePathText);
        if (candidateList.empty())
        { document.note(QStringLiteral("未找到可用 DOS 路径映射。")); m_objectNamespaceDetailEditor->setDocument(document); return; }
        QStringList candidateTextList;
        for (const QString& candidate : candidateList)
        { candidateTextList.push_back(candidate); document.field(QStringLiteral("DOS 路径"), candidate); }
        copyTextToClipboard(candidateTextList.join('\n'));
        document.note(QStringLiteral("已找到 DOS 路径映射（并已复制）。"));
        m_objectNamespaceDetailEditor->setDocument(document);
        return;
    }
}

void KernelDock::showAtomContextMenu(const QPoint& localPosition)
{
    if (m_atomTable == nullptr)
    {
        return;
    }

    const QModelIndex clickedIndex = m_atomTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        m_atomTable->setCurrentCell(clickedIndex.row(), clickedIndex.column());
    }

    const KernelAtomEntry* entry = currentAtomEntry();
    const bool hasEntry = (entry != nullptr);

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());

    QAction* refreshAction = contextMenu.addAction(QIcon(":/Icon/process_refresh.svg"), kernelText("kernel.context.atom.refresh", QStringLiteral("刷新原子表")));
    contextMenu.addSeparator();

    QMenu* copyMenu = contextMenu.addMenu(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCellAction = copyMenu->addAction(QIcon(":/Icon/process_copy_cell.svg"), kernelText("kernel.context.menu.copy_cell", QStringLiteral("复制当前单元格")));
    QAction* copyValueAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_value", QStringLiteral("复制Atom值")));
    QAction* copyHexAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_hex", QStringLiteral("复制十六进制")));
    QAction* copyNameAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_name", QStringLiteral("复制名称")));
    QAction* copySourceAction = copyMenu->addAction(kernelText("kernel.context.atom.copy_source", QStringLiteral("复制来源")));
    QAction* copyRowAction = copyMenu->addAction(QIcon(":/Icon/process_copy_row.svg"), kernelText("kernel.context.menu.copy_row", QStringLiteral("复制当前行")));

    copyValueAction->setEnabled(hasEntry);
    copyHexAction->setEnabled(hasEntry);
    copyNameAction->setEnabled(hasEntry);
    copySourceAction->setEnabled(hasEntry);
    copyRowAction->setEnabled(hasEntry);

    QMenu* operationMenu = contextMenu.addMenu(QIcon(":/Icon/process_threads.svg"), kernelText("kernel.context.atom.operation", QStringLiteral("原子操作")));
    QAction* filterByNameAction = operationMenu->addAction(kernelText("kernel.context.atom.filter_name", QStringLiteral("用名称过滤")));
    QAction* verifyByNameAction = operationMenu->addAction(kernelText("kernel.context.atom.verify_global_find", QStringLiteral("使用GlobalFindAtomW校验")));
    QAction* copySnippetAction = operationMenu->addAction(kernelText("kernel.context.atom.copy_snippet", QStringLiteral("复制调用代码片段")));

    filterByNameAction->setEnabled(hasEntry && !entry->atomNameText.trimmed().isEmpty());
    verifyByNameAction->setEnabled(hasEntry && !entry->atomNameText.trimmed().isEmpty());
    copySnippetAction->setEnabled(hasEntry && !entry->atomNameText.trimmed().isEmpty());

    QAction* selectedAction = contextMenu.exec(m_atomTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    kLogEvent menuEvent;
    info << menuEvent
        << "[KernelDock] 原子表右键动作: "
        << selectedAction->text().toStdString()
        << eol;

    if (selectedAction == refreshAction)
    {
        refreshAtomTableAsync();
        return;
    }

    if (selectedAction == copyCellAction)
    {
        const int rowIndex = m_atomTable->currentRow();
        const int columnIndex = m_atomTable->currentColumn();
        if (rowIndex >= 0 && columnIndex >= 0)
        {
            QTableWidgetItem* cellItem = m_atomTable->item(rowIndex, columnIndex);
            if (cellItem != nullptr)
            {
                copyTextToClipboard(cellItem->text());
            }
        }
        return;
    }

    if (!hasEntry)
    {
        return;
    }

    if (selectedAction == copyValueAction)
    {
        copyTextToClipboard(QString::number(entry->atomValue));
        return;
    }
    if (selectedAction == copyHexAction)
    {
        const QString hexText = QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(entry->atomValue), 4, 16, QChar('0'))
            .toUpper();
        copyTextToClipboard(hexText);
        return;
    }
    if (selectedAction == copyNameAction)
    {
        copyTextToClipboard(entry->atomNameText);
        return;
    }
    if (selectedAction == copySourceAction)
    {
        copyTextToClipboard(entry->sourceText);
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyTextToClipboard(atomEntryAsTsv(*entry));
        return;
    }

    if (selectedAction == filterByNameAction)
    {
        m_atomFilterEdit->setText(entry->atomNameText);
        return;
    }
    if (selectedAction == verifyByNameAction)
    {
        std::uint16_t foundAtomValue = 0;
        ks::ui::FieldDocument verifyDocument;
        const bool verifyOk = verifyGlobalAtomByName(entry->atomNameText, foundAtomValue, verifyDocument);

        if (verifyOk)
        {
            for (int rowIndex = 0; rowIndex < m_atomTable->rowCount(); ++rowIndex)
            {
                QTableWidgetItem* valueItem = m_atomTable->item(rowIndex, static_cast<int>(AtomColumn::Value));
                if (valueItem == nullptr)
                {
                    continue;
                }

                if (valueItem->text() == QString::number(foundAtomValue))
                {
                    m_atomTable->setCurrentCell(rowIndex, static_cast<int>(AtomColumn::Value));
                    break;
                }
            }
        }

        m_atomDetailEditor->setDocument(verifyDocument);
        return;
    }
    if (selectedAction == copySnippetAction)
    {
        QString escapedNameText = entry->atomNameText;
        escapedNameText.replace('\\', QStringLiteral("\\\\"));
        escapedNameText.replace('"', QStringLiteral("\\\""));

        const QString snippetText = QStringLiteral("ATOM atomValue = GlobalFindAtomW(L\"%1\");")
            .arg(escapedNameText);

        copyTextToClipboard(snippetText);
        m_atomDetailEditor->setDocument(ks::ui::FieldDocument{}.section(QStringLiteral("调用代码片段")).field(QStringLiteral("代码"), snippetText));
        return;
    }
}
