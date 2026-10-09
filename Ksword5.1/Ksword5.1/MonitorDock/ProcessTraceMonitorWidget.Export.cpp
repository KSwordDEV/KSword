#include "ProcessTraceMonitorWidget.h"
#include "../theme.h"

// ============================================================
// ProcessTraceMonitorWidget.Export.cpp
// 作用：
// 1) 实现事件表右键菜单与结果导出；
// 2) 保持 Actions.cpp 低于 1000 行，满足项目拆分规范；
// 3) 复用进程详情跳转逻辑，便于结果联动。
// ============================================================

#include "MonitorTextViewer.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../ProcessDock/ProcessDetailWindow.h"

#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QMenu>
#include <QMessageBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>

#include <algorithm>
#include <string>

namespace
{
    // openProcessDetailWindow：
    // - 作用：按 PID 打开进程详情窗口；
    // - 调用：事件表右键“转到进程详情”复用该辅助函数。
    void openProcessDetailWindow(QWidget* parentWidget, const std::uint32_t pidValue)
    {
        if (pidValue == 0)
        {
            return;
        }

        // 事件表右键跳转必须快速返回 UI：
        // - 不在这里做 QueryProcessStaticDetailByPid；
        // - 详情窗口后台补齐慢字段并按需加载重型页。
        ks::process::ProcessRecord record;
        record.pid = pidValue;
        record.processName = ks::process::GetProcessNameByPID(pidValue);
        if (record.processName.empty())
        {
            record.processName = "PID_" + std::to_string(pidValue);
        }

        ProcessDetailWindow* detailWindow = new ProcessDetailWindow(record, nullptr);
        detailWindow->setAttribute(Qt::WA_DeleteOnClose, true);
        detailWindow->show();
        detailWindow->raise();
        detailWindow->activateWindow();
    }

    // extractPidFromPidTidText：
    // - 作用：从“PID / TID”文本中提取前半段 PID；
    // - 调用：事件表右键跳转进程详情时使用。
    bool extractPidFromPidTidText(const QString& pidTidText, std::uint32_t* pidOut)
    {
        if (pidOut == nullptr)
        {
            return false;
        }

        const QString pidText = pidTidText.section('/', 0, 0).trimmed();
        bool parseOk = false;
        const std::uint32_t pidValue = pidText.toUInt(&parseOk, 10);
        if (!parseOk || pidValue == 0)
        {
            return false;
        }

        *pidOut = pidValue;
        return true;
    }
}

void ProcessTraceMonitorWidget::showEventContextMenu(const QPoint& position)
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    const QModelIndex index = m_eventTable->indexAt(position);
    if (!index.isValid())
    {
        return;
    }

    const int row = index.row();
    const int column = index.column();

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* viewDetailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("查看返回详情"));
    menu.addSeparator();
    QAction* copyDetailAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制返回详情文本"));
    QAction* copyCellAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/log_clipboard.svg"), QStringLiteral("复制整行"));
    menu.addSeparator();
    QAction* gotoProcessAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("转到进程详细信息"));
    ks::online_scan::addVirusTotalSandboxMenu(
        &menu,
        this,
        [this, row]() -> ks::online_scan::SandboxUploadTarget {
            // 输入：进程定向事件表当前右键行。
            // 处理：优先从 PID/TID 列提取进程 PID；失败时再尝试 Root PID 列。
            // 返回：PID 对应进程镜像路径和来源文本；无法解析时返回 errorText，统一菜单 helper 负责弹窗。
            const auto itemTextAt = [this, row](const int column) -> QString {
                QTableWidgetItem* itemPointer = m_eventTable != nullptr ? m_eventTable->item(row, column) : nullptr;
                return itemPointer != nullptr ? itemPointer->text() : QString();
            };

            std::uint32_t pidValue = 0;
            if (!extractPidFromPidTidText(itemTextAt(EventColumnPidTid), &pidValue) &&
                !ks::online_scan::tryParsePidFromText(itemTextAt(EventColumnRootPid), &pidValue))
            {
                return {
                    QString(),
                    QStringLiteral("进程定向事件"),
                    QStringLiteral("当前事件行未解析出有效 PID 或 Root PID，无法上传发起进程文件。")
                };
            }

            const QString processPath = QString::fromStdString(ks::process::QueryProcessPathByPid(pidValue)).trimmed();
            if (processPath.isEmpty())
            {
                return {
                    QString(),
                    QStringLiteral("进程定向事件 PID=%1").arg(pidValue),
                    QStringLiteral("无法解析 PID=%1 的进程镜像路径。进程可能已退出，或当前权限不足。").arg(pidValue)
                };
            }

            return {
                processPath,
                QStringLiteral("进程定向事件 PID=%1").arg(pidValue),
                QString()
            };
        });

    QAction* selectedAction = menu.exec(m_eventTable->viewport()->mapToGlobal(position));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == viewDetailAction)
    {
        openEventDetailViewerForRow(row);
        return;
    }

    if (selectedAction == copyDetailAction)
    {
        QApplication::clipboard()->setText(eventDocumentForRow(row).toPlainText(true));
        return;
    }

    if (selectedAction == copyCellAction)
    {
        QTableWidgetItem* itemPointer = m_eventTable->item(row, column);
        if (itemPointer != nullptr)
        {
            QApplication::clipboard()->setText(itemPointer->text());
        }
        return;
    }

    if (selectedAction == copyRowAction)
    {
        QStringList rowTextList;
        for (int currentColumn = 0; currentColumn < EventColumnCount; ++currentColumn)
        {
            QTableWidgetItem* itemPointer = m_eventTable->item(row, currentColumn);
            rowTextList << (itemPointer != nullptr ? itemPointer->text() : QString());
        }
        QApplication::clipboard()->setText(rowTextList.join('\t'));
        return;
    }

    if (selectedAction == gotoProcessAction)
    {
        QTableWidgetItem* pidItem = m_eventTable->item(row, EventColumnPidTid);
        std::uint32_t pidValue = 0;
        if (pidItem == nullptr || !extractPidFromPidTidText(pidItem->text(), &pidValue))
        {
            QMessageBox::information(this, QStringLiteral("进程跳转"), QStringLiteral("当前行未解析出有效 PID。"));
            return;
        }
        openProcessDetailWindow(this, pidValue);
    }
}

ks::ui::FieldDocument ProcessTraceMonitorWidget::eventDocumentForRow(const int row) const
{
    if (m_eventTable == nullptr || row < 0 || row >= m_eventTable->rowCount()) return {};
    const auto itemTextAt = [this, row](const int column) -> QString {
        const QTableWidgetItem* item = m_eventTable->item(row, column);
        return item != nullptr ? item->text() : QString();
    };
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("事件"));
    document.field(QStringLiteral("时间(100ns)"), itemTextAt(EventColumnTime100ns));
    document.field(QStringLiteral("类型"), itemTextAt(EventColumnType));
    document.field(QStringLiteral("Provider"), itemTextAt(EventColumnProvider));
    document.field(QStringLiteral("事件ID"), itemTextAt(EventColumnEventId));
    document.field(QStringLiteral("事件名"), itemTextAt(EventColumnEventName));
    document.field(QStringLiteral("PID / TID"), itemTextAt(EventColumnPidTid));
    document.field(QStringLiteral("进程"), itemTextAt(EventColumnProcess));
    document.field(QStringLiteral("根PID"), itemTextAt(EventColumnRootPid));
    document.field(QStringLiteral("关系"), itemTextAt(EventColumnRelation));
    document.field(QStringLiteral("ActivityId"), itemTextAt(EventColumnActivityId));
    if (const QTableWidgetItem* item = m_eventTable->item(row, EventColumnTime100ns))
        document.nodes += item->data(Qt::UserRole + 4).value<ks::ui::FieldDocument>().nodes;
    return document;
}

void ProcessTraceMonitorWidget::openEventDetailViewerForRow(const int row) const
{
    if (m_eventTable == nullptr || row < 0 || row >= m_eventTable->rowCount()) return;
    const QTableWidgetItem* event = m_eventTable->item(row, EventColumnEventName);
    monitor_text_viewer::showReadOnlyDocumentWindow(
        const_cast<ProcessTraceMonitorWidget*>(this),
        QStringLiteral("进程定向监控详情 - %1").arg(event ? event->text() : QString()),
        eventDocumentForRow(row),
        QStringLiteral("monitor://process-trace/row-%1.txt").arg(row + 1));
}

void ProcessTraceMonitorWidget::exportVisibleRowsToTsv()
{
    if (m_eventTable == nullptr || m_eventTable->rowCount() == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出结果"), QStringLiteral("当前没有可导出的事件。"));
        return;
    }

    int visibleCount = 0;
    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        if (!m_eventTable->isRowHidden(row))
        {
            ++visibleCount;
        }
    }
    if (visibleCount == 0)
    {
        QMessageBox::information(this, QStringLiteral("导出结果"), QStringLiteral("当前筛选结果为空，没有可导出的可见行。"));
        return;
    }

    const QString defaultFileName = QStringLiteral("process_trace_%1.tsv")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss")));
    const QString pathText = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出进程定向监控结果"),
        defaultFileName,
        QStringLiteral("TSV 文件 (*.tsv);;文本文件 (*.txt)"));
    if (pathText.trimmed().isEmpty())
    {
        return;
    }

    QFile fileObject(pathText);
    if (!fileObject.open(QIODevice::WriteOnly | QIODevice::Text | QIODevice::Truncate))
    {
        QMessageBox::warning(this, QStringLiteral("导出结果"), QStringLiteral("无法写入文件：%1").arg(pathText));
        return;
    }

    QTextStream outputStream(&fileObject);

    QStringList headerTextList;
    for (int column = 0; column < EventColumnCount; ++column)
    {
        QTableWidgetItem* headerItem = m_eventTable->horizontalHeaderItem(column);
        headerTextList << (headerItem != nullptr ? headerItem->text() : QString());
    }
    outputStream << headerTextList.join('\t') << '\n';

    for (int row = 0; row < m_eventTable->rowCount(); ++row)
    {
        if (m_eventTable->isRowHidden(row))
        {
            continue;
        }

        QStringList rowTextList;
        for (int column = 0; column < EventColumnCount; ++column)
        {
            QTableWidgetItem* itemPointer = m_eventTable->item(row, column);
            rowTextList << (itemPointer != nullptr ? itemPointer->text().replace('\t', ' ') : QString());
        }
        outputStream << rowTextList.join('\t') << '\n';
    }

    fileObject.close();

    kLogEvent event;
    info << event
        << "[ProcessTraceMonitorWidget] 导出可见事件完成, path="
        << pathText.toStdString()
        << ", visibleCount="
        << visibleCount
        << eol;

    QMessageBox::information(this, QStringLiteral("导出结果"), QStringLiteral("导出完成：%1").arg(pathText));
}
