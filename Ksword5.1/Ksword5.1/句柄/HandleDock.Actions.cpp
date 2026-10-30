#include "HandleDock.h"
#include <utility>
#include "../UI/StructuredFieldView.h"

// ============================================================
// HandleDock.Actions.cpp
// 作用：
// - 承载句柄模块的交互动作实现；
// - 承载对象类型详情、复制、跳转和逐行 R3/R0 关闭动作；
// - 与主 UI 文件拆开，控制单文件规模。
// ============================================================

#include <QApplication>
#include <QClipboard>
#include <QMessageBox>
#include <QStringList>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QFutureWatcher>
#include <QtConcurrent/QtConcurrentRun>
#include "../ArkDriverClient/ArkDriverClient.h"

namespace
{
    // boolText：
    // - 作用：把布尔值转成中文“是/否”；
    // - 本文件单独实现，避免依赖 UI cpp 内部匿名命名空间。
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }
}

void HandleDock::showObjectTypeDetailByCurrentRow()
{
    if (m_objectTypeTable == nullptr || m_objectTypeTable->currentItem() == nullptr)
    {
        m_objectTypeDetailFields->setDocument(ks::ui::FieldDocument{});
        return;
    }

    const QVariant rowIndexValue =
        m_objectTypeTable->currentItem()->data(static_cast<int>(ObjectTypeTableColumn::TypeIndex), Qt::UserRole);
    if (!rowIndexValue.isValid())
    {
        m_objectTypeDetailFields->setDocument(ks::ui::FieldDocument{});
        return;
    }
    const std::size_t rowIndex = static_cast<std::size_t>(rowIndexValue.toULongLong());
    if (rowIndex >= m_objectTypeRows.size())
    {
        m_objectTypeDetailFields->setDocument(ks::ui::FieldDocument{});
        return;
    }

    const HandleObjectTypeEntry& row = m_objectTypeRows[rowIndex];
    // 类型列表保持原模型，选中对象的字段直接投影为统一卡片。
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("Object Type"));
    auto addDetailRow = [&document](const QString& keyText, const QString& valueText)
        {
            document.field(keyText, valueText);
        };

    addDetailRow(QStringLiteral("类型编号"), QString::number(row.typeIndex));
    addDetailRow(QStringLiteral("类型名称"), row.typeNameText);
    addDetailRow(QStringLiteral("对象总数"), QString::number(row.totalObjectCount));
    addDetailRow(QStringLiteral("句柄总数"), QString::number(row.totalHandleCount));
    addDetailRow(QStringLiteral("访问掩码"), formatHex(row.validAccessMask, 0));
    addDetailRow(QStringLiteral("安全要求"), boolText(row.securityRequired));
    addDetailRow(QStringLiteral("维护句柄计数"), boolText(row.maintainHandleCount));
    addDetailRow(QStringLiteral("池类型"), QString::number(row.poolType));
    addDetailRow(QStringLiteral("默认分页池配额"), QString::number(row.defaultPagedPoolCharge));
    addDetailRow(QStringLiteral("默认非分页池配额"), QString::number(row.defaultNonPagedPoolCharge));
    m_objectTypeDetailFields->setDocument(document);
}

const HandleDock::HandleRow* HandleDock::selectedHandleRow()
{
    if (m_handleFilterPreparationPending || m_handleFilterProjectionDirty) return nullptr;
    QTreeWidgetItem* currentItem = m_tableWidget->currentItem();
    if (currentItem == nullptr)
    {
        return nullptr;
    }
    if (currentItem->data(0, ks::handle::HandleTreeItemKindRole).toInt() !=
        static_cast<int>(ks::handle::HandleTreeItemKind::HandleRow))
    {
        return nullptr;
    }
    const QVariant rowIndexValue = currentItem->data(0, ks::handle::HandleTreeSourceRowIndexRole);
    if (!rowIndexValue.isValid())
    {
        return nullptr;
    }
    const std::size_t rowIndex = static_cast<std::size_t>(rowIndexValue.toULongLong());
    if (rowIndex >= static_cast<std::size_t>(m_allRows.size()))
    {
        return nullptr;
    }
    return &m_allRows.at(static_cast<qsizetype>(rowIndex));
}

void HandleDock::copyCurrentHandleCell()
{
    QTreeWidgetItem* currentItem = m_tableWidget->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }
    const int columnIndex = m_tableWidget->currentColumn();
    if (columnIndex < 0)
    {
        return;
    }
    QApplication::clipboard()->setText(currentItem->text(columnIndex));
}

void HandleDock::copyCurrentHandleRow()
{
    QTreeWidgetItem* currentItem = m_tableWidget->currentItem();
    if (currentItem == nullptr)
    {
        return;
    }
    QStringList textList;
    for (int columnIndex = 0; columnIndex < static_cast<int>(HandleTableColumn::Count); ++columnIndex)
    {
        textList.push_back(currentItem->text(columnIndex));
    }
    QApplication::clipboard()->setText(textList.join('\t'));
}

void HandleDock::closeHandleRow(const HandleRow& selectedRow, const bool useDriver)
{
    // Menus and confirmation dialogs run nested event loops; hold values, never a pointer into m_allRows.
    const HandleRow row = selectedRow;
    const QString actionTitle = useDriver ? QStringLiteral("R0关闭句柄") : QStringLiteral("R3关闭句柄");

    const QString confirmText = QStringLiteral(
        "确认关闭目标句柄？\nPID=%1\nHandle=%2\nTypeIndex=%3\n类型=%4\n对象名=%5")
        .arg(row.processId)
        .arg(formatHex(row.handleValue, 0))
        .arg(row.typeIndex)
        .arg(row.typeName)
        .arg(formatObjectNameDisplayText(row));
    if (QMessageBox::question(
            this,
            actionTitle,
            confirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    // Native suspend/close and driver I/O may block. The worker owns only the captured identity.
    using CloseResult = std::pair<bool, std::string>;
    auto* watcher = new QFutureWatcher<CloseResult>(this);
    connect(watcher, &QFutureWatcher<CloseResult>::finished, this, [this, watcher, row, actionTitle]()
    {
        const CloseResult result = watcher->result();
        watcher->deleteLater();
        kLogEvent closeEvent;
        (result.first ? info : err) << closeEvent
            << "[HandleDock] close: pid=" << row.processId
            << ", handle=" << formatHex(row.handleValue, 0).toStdString()
            << ", backend=" << actionTitle.toStdString()
            << ", detail=" << result.second << eol;
        // Refresh failures too: the handle may have disappeared, or close succeeded but resume failed.
        requestAsyncRefresh(true);
        if (result.first)
        {
            QMessageBox::information(this, actionTitle,
                QStringLiteral("句柄关闭成功。\n%1").arg(QString::fromStdString(result.second)));
        }
        else
        {
            QMessageBox::warning(this, actionTitle,
                QStringLiteral("句柄关闭操作未完整完成。\n%1").arg(QString::fromStdString(result.second)));
        }
    });
    watcher->setFuture(QtConcurrent::run([row, useDriver]() -> CloseResult
    {
        if (useDriver)
        {
            const auto result = ksword::ark::DriverClient().closeHandle(
                row.processId, row.handleValue, row.processCreationTime, row.objectAddress);
            return { result.ok, result.message };
        }
        std::string detail;
        const bool ok = closeRemoteHandle(row, detail);
        return { ok, std::move(detail) };
    }));
}

void HandleDock::closeSameTypeHandlesInCurrentProcess()
{
    const HandleRow* selectedRow = selectedHandleRow();
    if (selectedRow == nullptr)
    {
        return;
    }

    std::vector<HandleRow> targetRows;
    targetRows.reserve(128);
    // 批量关闭范围使用完整快照 m_allRows，避免受当前过滤条件影响。
    for (const HandleRow& row : std::as_const(m_allRows))
    {
        if (row.processId == selectedRow->processId && row.typeIndex == selectedRow->typeIndex)
        {
            targetRows.push_back(row);
        }
    }
    if (targetRows.empty())
    {
        return;
    }

    const QString confirmText = QStringLiteral(
        "确认批量关闭同类型句柄？\nPID=%1\nTypeIndex=%2\n类型=%3\n目标数量=%4")
        .arg(selectedRow->processId)
        .arg(selectedRow->typeIndex)
        .arg(selectedRow->typeName)
        .arg(targetRows.size());
    if (QMessageBox::question(
            this,
            QStringLiteral("批量关闭句柄"),
            confirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    std::size_t successCount = 0;
    std::size_t failCount = 0;
    std::string lastErrorText;
    for (const HandleRow& targetRow : targetRows)
    {
        std::string detailText;
        const bool closeOk = closeRemoteHandle(targetRow, detailText);
        if (closeOk)
        {
            ++successCount;
        }
        else
        {
            ++failCount;
            lastErrorText = detailText;
        }
    }

    kLogEvent batchCloseEvent;
    info << batchCloseEvent
        << "[HandleDock] closeSameTypeHandlesInCurrentProcess: pid="
        << selectedRow->processId
        << ", typeIndex="
        << selectedRow->typeIndex
        << ", total="
        << targetRows.size()
        << ", success="
        << successCount
        << ", fail="
        << failCount
        << ", lastError="
        << lastErrorText
        << eol;

    QMessageBox::information(
        this,
        QStringLiteral("批量关闭句柄"),
        QStringLiteral("执行完成。\n成功: %1\n失败: %2\n最后错误: %3")
        .arg(successCount)
        .arg(failCount)
        .arg(QString::fromStdString(lastErrorText)));

    requestAsyncRefresh(true);
}
