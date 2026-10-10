#include "../Internationalization/LanguageManager.h"
#include "RegistryDock.h"
#include "../UI/ToolbarMetrics.h"
#include "RegistryDocument.h"
#include "RegistryDocumentApply.h"
#include "RegistryWorkbenchAccess.h"
#include "RegistryAdvancedDialogs.h"
#include "RegistryValueEditorWidget.h"
#include "../UI/UI_All.h"
#include "../UI/VisibleTableWidget.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include "../UI/SecondaryPageLayout.h"
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QLabel>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QStandardPaths>
#include <QTableWidget>
#include <QThreadPool>
#include <QUrl>
#include <QUuid>
#include <QVBoxLayout>

namespace
{
    QString operationLabel(const RegistryApplyOperation& operation)
    {
        switch (operation.kind)
        {
        case RegistryApplyOperation::Kind::CreateKey:
            return operation.keyExistedBefore ? ks::i18n::sourceText(QStringLiteral("保留已有键")) : ks::i18n::sourceText(QStringLiteral("新建键"));
        case RegistryApplyOperation::Kind::DeleteTree: return ks::i18n::sourceText(QStringLiteral("删除子树"));
        case RegistryApplyOperation::Kind::SetValue:
            return operation.beforeValue.exists ? ks::i18n::sourceText(QStringLiteral("修改值")) : ks::i18n::sourceText(QStringLiteral("新建值"));
        case RegistryApplyOperation::Kind::DeleteValue: return ks::i18n::sourceText(QStringLiteral("删除值"));
        }
        return QString();
    }

    QString documentViewLabel(const int view, const bool useR0 = false)
    {
        return useR0 ? ks::i18n::sourceText(QStringLiteral("R0 / 本机视图")) : view == 32 ? ks::i18n::sourceText(QStringLiteral("Win32 / 32 位视图"))
            : view == 64 ? ks::i18n::sourceText(QStringLiteral("Win32 / 64 位视图")) : ks::i18n::sourceText(QStringLiteral("Win32 / 本机视图"));
    }
}

void RegistryDock::backupCurrentKey()
{
    const QString path = m_currentPath;
    const int view = m_viewBits;
    const QString output = QFileDialog::getSaveFileName(this,
        QStringLiteral("备份完整子树（Win32）"),
        QStringLiteral("registry_backup_%1.ksreg").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        QStringLiteral("注册表原始备份 (*.ksreg)"));
    if (output.isEmpty()) return;
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    const auto closed = m_operationsClosed;
    updateStatusBar(QStringLiteral("正在完整备份：%1").arg(documentViewLabel(view)));
    QThreadPool::globalInstance()->start([guarded, dispatcher, closed, path, view, output]() {
        RegistryDocument document;
        QString error;
        bool ok = RegistryDocumentService::captureWin32(path, view, document, error);
        if (closed->load()) return;
        if (ok) ok = RegistryDocumentService::saveBackup(output, document, error);
        dispatcher->post([guarded, ok, output, error]() {
            if (!guarded) return;
            guarded->updateStatusBar(ok ? QStringLiteral("完整原始备份已保存：%1").arg(output) : error);
            if (!ok) QMessageBox::warning(guarded, QStringLiteral("备份失败"), ks::i18n::packedSourceText(error));
        });
    });
}

void RegistryDock::exportCurrentKeyAsync()
{
    const QString path = m_currentPath;
    const int view = m_viewBits;
    const QString output = QFileDialog::getSaveFileName(this, QStringLiteral("导出完整 .reg（Win32）"),
        QStringLiteral("registry_%1.reg").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        QStringLiteral("REG 文件 (*.reg)"));
    if (output.isEmpty()) return;
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    const auto closed = m_operationsClosed;
    updateStatusBar(QStringLiteral("正在完整导出：%1").arg(documentViewLabel(view)));
    QThreadPool::globalInstance()->start([guarded, dispatcher, closed, path, view, output]() {
        RegistryDocument document;
        QString error;
        bool ok = RegistryDocumentService::captureWin32(path, view, document, error);
        if (closed->load()) return;
        if (ok) ok = RegistryDocumentService::saveRegFile(output, document, error);
        dispatcher->post([guarded, ok, output, error]() {
            if (!guarded) return;
            guarded->updateStatusBar(ok ? QStringLiteral("完整导出已保存：%1").arg(output) : error);
            if (!ok) QMessageBox::warning(guarded, QStringLiteral("导出失败"), ks::i18n::packedSourceText(error));
        });
    });
}

void RegistryDock::importRegFileAsync()
{
    if (m_applyingChanges || !preserveEditorDraft()) return;
    const RegistryAccessContext context = accessContext(); // 文件选择前冻结真实通道和视图。
    const QString input = QFileDialog::getOpenFileName(this, QStringLiteral("导入并预览 .reg"), QString(), QStringLiteral("REG 文件 (*.reg)"));
    if (input.isEmpty()) return;
    const int view = context.viewBits;
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    QThreadPool::globalInstance()->start([guarded, dispatcher, input, view, context]() {
        RegistryDocument document;
        QString error;
        const bool ok = RegistryDocumentService::parseRegFile(input, document, error);
        document.viewBits = view;
        dispatcher->post([guarded, ok, document, error, context]() {
            if (!guarded) return;
            if (ok) guarded->previewRegistryDocument(document, QStringLiteral("导入预览"), context.useR0);
            else QMessageBox::warning(guarded, QStringLiteral("导入失败"), ks::i18n::packedSourceText(error));
        });
    });
}

void RegistryDock::restoreBackup()
{
    if (m_applyingChanges || !preserveEditorDraft()) return;
    const RegistryAccessContext context = accessContext(); // 恢复入口不能在文件选择后隐式换源。
    const QString input = QFileDialog::getOpenFileName(this, QStringLiteral("恢复原始备份（合并）"), QString(),
        QStringLiteral("注册表原始备份 (*.ksreg *.json)"));
    if (input.isEmpty()) return;
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    QThreadPool::globalInstance()->start([guarded, dispatcher, input, context]() {
        RegistryDocument document;
        QString error;
        bool ok = RegistryDocumentService::loadBackup(input, document, error);
        if (!ok) ok = RegistryDocumentApplyService::loadOriginalBackup(input, document, error);
        dispatcher->post([guarded, ok, document, error, context]() {
            if (!guarded) return;
            if (ok) guarded->previewRegistryDocument(document, QStringLiteral("合并恢复预览"), context.useR0);
            else QMessageBox::warning(guarded, QStringLiteral("恢复失败"), ks::i18n::packedSourceText(error));
        });
    });
}

void RegistryDock::previewRegistryDocument(const RegistryDocument& document, const QString& title, const bool useR0)
{
    if (m_applyingChanges || !preserveEditorDraft()) return;
    m_applyingChanges = true;
    m_valueEditor->setEnabled(false);
    m_viewCombo->setEnabled(false);
    m_applyChangesButton->setEnabled(false);
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    const auto closed = m_operationsClosed;
    updateStatusBar(QStringLiteral("正在读取修改前的完整状态…"));
    QThreadPool::globalInstance()->start([guarded, dispatcher, closed, document, title, useR0]() {
        auto plan = std::make_shared<RegistryApplyPlan>();
        QString error;
        const bool ok = RegistryDocumentApplyService::prepareAccess(document, useR0, *plan, error);
        if (closed->load()) return;
        dispatcher->post([guarded, dispatcher, plan, title, error, ok]() {
            if (!guarded) return;
            if (!ok)
            {
                guarded->m_applyingChanges = false;
                guarded->m_valueEditor->setEnabled(true);
                guarded->m_viewCombo->setEnabled(true);
                guarded->updatePendingChanges();
                QMessageBox::warning(guarded, title, ks::i18n::packedSourceText(error));
                return;
            }
            QDialog dialog(guarded);
            dialog.setWindowTitle(title);
            ks::ui::StyleSecondaryWindow(&dialog);
            auto* layout = new QVBoxLayout(&dialog);
            ks::ui::StyleSecondaryContentLayout(layout);
            auto* source = new QLabel(QStringLiteral("%1 · %2 项操作。恢复采用合并方式，保留备份外新增数据；ACL 仅作备份元数据。")
                .arg(documentViewLabel(plan->viewBits, plan->useR0)).arg(plan->operations.size()), &dialog);
            source->setWordWrap(true);
            source->setTextFormat(Qt::PlainText);
            layout->addWidget(source);
            auto* table = new ks::ui::VisibleTableWidget(&dialog);
            table->setColumnCount(6);
            table->setHorizontalHeaderLabels({QStringLiteral("操作"), QStringLiteral("键路径"), QStringLiteral("值名"),
                QStringLiteral("原值 / 原子树"), QStringLiteral("新值"), QStringLiteral("结果")});
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setProperty("ks_i18n_preserve_model_data", true);
            table->setShowGrid(false);
            table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
            table->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
            ks::ui::SetTableActionBarMode(table, ks::ui::TableActionBarMode::Compact);
            layout->addWidget(table, 1);
            auto result = std::make_shared<RegistryApplyResult>();
            auto page = std::make_shared<int>(0);
            auto render = [table, plan, result, page]() {
                const qsizetype first = *page * 200;
                const qsizetype end = qMin(first + 200, plan->operations.size());
                table->setRowCount(static_cast<int>(end - first));
                for (qsizetype index = first; index < end; ++index)
                {
                    const auto& op = plan->operations.at(index);
                    QString before = op.beforeValue.exists ? RegistryDock::formatValueData(op.beforeValue.type, op.beforeValue.data) : ks::i18n::sourceText(QStringLiteral("不存在"));
                    if (op.kind == RegistryApplyOperation::Kind::DeleteTree)
                        before = ks::i18n::sourceText(QStringLiteral("%1 个键 / %2 个值")).arg(op.beforeTree.keys.size()).arg(op.beforeTree.values.size());
                    QString status = ks::i18n::sourceText(QStringLiteral("待应用"));
                    if (index < result->receipts.size())
                    {
                        const auto& receipt = result->receipts.at(index);
                        status = receipt.state == RegistryApplyReceipt::State::Success ? ks::i18n::sourceText(QStringLiteral("已回读验证"))
                            : receipt.state == RegistryApplyReceipt::State::NotRun ? ks::i18n::sourceText(QStringLiteral("未执行"))
                            : receipt.state == RegistryApplyReceipt::State::Canceled ? ks::i18n::sourceText(QStringLiteral("已停止"))
                            : (receipt.mutated ? ks::i18n::sourceText(QStringLiteral("可能部分修改：%1")) : ks::i18n::sourceText(QStringLiteral("失败：%1"))).arg(ks::i18n::packedSourceText(receipt.error));
                    }
                    const QStringList cells{operationLabel(op), op.keyPath, op.valueName.isEmpty() ? ks::i18n::sourceText(QStringLiteral("(默认)")) : op.valueName,
                        before, op.afterValue.exists ? RegistryDock::formatValueData(op.afterValue.type, op.afterValue.data) : QString(), status};
                    for (int column = 0; column < cells.size(); ++column)
                        table->setItem(static_cast<int>(index - first), column, new QTableWidgetItem(cells.at(column)));
                }
            };
            auto* paging = new QHBoxLayout;
            auto* previous = new QPushButton(QStringLiteral("上一页"), &dialog);
            auto* next = new QPushButton(QStringLiteral("下一页"), &dialog);
            auto* pageLabel = new QLabel(&dialog);
            paging->addWidget(previous); paging->addWidget(pageLabel); paging->addWidget(next); paging->addStretch();
            ks::ui::NormalizeToolbarRow(paging);
            layout->addLayout(paging);
            auto updatePage = [page, plan, render, previous, next, pageLabel]() {
                const int pages = qMax(1, static_cast<int>((plan->operations.size() + 199) / 200));
                *page = qBound(0, *page, pages - 1);
                previous->setEnabled(*page > 0); next->setEnabled(*page + 1 < pages);
                pageLabel->setText(QStringLiteral("%1 / %2").arg(*page + 1).arg(pages)); render();
            };
            QObject::connect(previous, &QPushButton::clicked, &dialog, [page, updatePage]() { --*page; updatePage(); });
            QObject::connect(next, &QPushButton::clicked, &dialog, [page, updatePage]() { ++*page; updatePage(); });
            const QString backupDirectory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
                + QStringLiteral("/registry-backups");
            const QString backupPath = backupDirectory + QStringLiteral("/before-%1-%2.ksreg")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")), QUuid::createUuid().toString(QUuid::WithoutBraces));
            auto* backupLabel = new QLabel(QStringLiteral("应用前将保存原状态备份：%1").arg(backupPath), &dialog);
            backupLabel->setWordWrap(true);
            backupLabel->setTextFormat(Qt::PlainText);
            layout->addWidget(backupLabel);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Apply | QDialogButtonBox::Close, &dialog);
            auto* apply = buttons->button(QDialogButtonBox::Apply);
            apply->setText(QStringLiteral("应用并验证"));
            apply->setEnabled(!plan->operations.isEmpty());
            // 导入预览的分页与备份说明留在内容区，提交独占底部操作区。
            ks::ui::StyleSecondaryButtonBox(buttons);
            ks::ui::StyleSecondaryFooter(buttons);
            layout->addWidget(buttons);
            auto started = std::make_shared<bool>(false);
            auto completed = std::make_shared<bool>(false);
            guarded->m_documentCancel = std::make_shared<std::atomic_bool>(false);
            const auto cancel = guarded->m_documentCancel;
            const QPointer<QDialog> guardedDialog(&dialog);
            QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, [cancel, &dialog]() { cancel->store(true); dialog.reject(); });
            QObject::connect(&dialog, &QDialog::rejected, &dialog, [cancel]() { cancel->store(true); });
            QObject::connect(apply, &QPushButton::clicked, &dialog,
                [guarded, dispatcher, plan, result, started, completed, cancel, guardedDialog, apply, backupDirectory, backupPath, render, backupLabel]() {
                    if (*started) return;
                    *started = true;
                    apply->setEnabled(false);
                    QThreadPool::globalInstance()->start([guarded, dispatcher, plan, result, completed, cancel,
                        guardedDialog, backupDirectory, backupPath, render, backupLabel]() {
                        auto workerResult = std::make_shared<RegistryApplyResult>();
                        workerResult->viewBits = plan->viewBits; // 备份失败也保留计划的准确来源。
                        workerResult->useR0 = plan->useR0;
                        QString failure;
                        bool saved = !cancel->load() && QDir().mkpath(backupDirectory)
                            && RegistryDocumentApplyService::saveOriginalBackup(*plan, backupPath, failure);
                        if (saved) RegistryDocumentApplyService::applyAccess(*plan, *workerResult, cancel.get());
                        else workerResult->error = failure.isEmpty() ? QStringLiteral("备份未保存，未应用任何操作。") : failure;
                        dispatcher->post([guarded, guardedDialog, workerResult, result, completed, backupPath, render, backupLabel]() {
                            if (!guarded) return;
                            *result = std::move(*workerResult);
                            *completed = true;
                            guarded->m_applyingChanges = false;
                            guarded->m_valueEditor->setEnabled(true);
                            guarded->m_viewCombo->setEnabled(true);
                            guarded->m_lastDocumentResult = result;
                            guarded->m_editorReady = false;
                            guarded->m_valueEditor->hide();
                            guarded->updatePendingChanges();
                            // 完成回执只能刷新同一真实视图/通道；用户已换来源时保留当前页面。
                            const RegistryAccessContext currentContext = guarded->accessContext();
                            if (currentContext.viewBits == result->viewBits && currentContext.useR0 == result->useR0)
                            {
                                QString navigation; // 只根据已实际核验成功的键回执调整导航。
                                for (const auto& receipt : result->receipts)
                                {
                                    if (receipt.state != RegistryApplyReceipt::State::Success || !receipt.mutated) continue;
                                    const auto& operation = receipt.operation;
                                    const qsizetype separator = operation.keyPath.lastIndexOf(QLatin1Char('\\'));
                                    const QString parent = separator < 0 ? QString() : operation.keyPath.left(separator);
                                    if (operation.kind == RegistryApplyOperation::Kind::DeleteTree
                                        && (guarded->m_currentPath.compare(operation.keyPath, Qt::CaseInsensitive) == 0
                                            || guarded->m_currentPath.startsWith(operation.keyPath + QLatin1Char('\\'), Qt::CaseInsensitive)))
                                    {
                                        navigation = parent;
                                        break; // 当前键已不存在，先回到被删除子树的父键。
                                    }
                                    if (result->receipts.size() == 1 && operation.kind == RegistryApplyOperation::Kind::CreateKey
                                        && parent.compare(guarded->m_currentPath, Qt::CaseInsensitive) == 0)
                                        navigation = operation.keyPath; // 恢复新建键后进入新键的原有行为。
                                }
                                if (!navigation.isEmpty()) guarded->navigateToPath(navigation, true);
                                else guarded->refreshCurrentKey(true); // 刷新树和完整值列表，不遗留已加载子节点。
                            }
                            guarded->updateStatusBar(result->completed ? QStringLiteral("导入 / 恢复已完成并回读验证。")
                                : QStringLiteral("未全部完成：%1；修改前备份：%2").arg(result->error, backupPath));
                            if (guardedDialog)
                            {
                                backupLabel->setText(result->completed ? QStringLiteral("已完成。修改前备份：%1").arg(backupPath)
                                    : QStringLiteral("未全部完成：%1\n修改前备份：%2").arg(result->error, backupPath));
                                render();
                            }
                        });
                    });
                });
            updatePage();
            ks::ui::applyResponsiveWindowGeometry(&dialog, guarded, QSize(1100, 720), QSize(480, 360));
            dialog.exec();
            if (!guarded) return;
            if (!*started || *completed)
            {
                guarded->m_applyingChanges = false;
                guarded->m_valueEditor->setEnabled(true);
                guarded->m_viewCombo->setEnabled(true);
                guarded->updatePendingChanges();
            }
        });
    });
}

void RegistryDock::showKeyPermissions()
{
    if (!m_applyingChanges) ShowRegistryKeyPermissions(this, m_currentPath, m_viewBits);
}

void RegistryDock::openOfflineHive()
{
    if (!m_applyingChanges) ShowRegistryOfflineHive(this);
}

void RegistryDock::openRelatedItem()
{
    if (!m_editorReady || (m_editorOriginalType != REG_SZ && m_editorOriginalType != REG_EXPAND_SZ)) return;
    QString text = QString::fromUtf16(reinterpret_cast<const char16_t*>(m_editorOriginalData.constData()), m_editorOriginalData.size() / 2);
    text.remove(QChar::Null);
    if (m_editorOriginalType == REG_EXPAND_SZ)
    {
        const DWORD bytes = ::ExpandEnvironmentStringsW(reinterpret_cast<const wchar_t*>(text.utf16()), nullptr, 0);
        if (bytes > 0 && bytes < 32768)
        {
            std::vector<wchar_t> expanded(bytes);
            if (::ExpandEnvironmentStringsW(reinterpret_cast<const wchar_t*>(text.utf16()), expanded.data(), bytes) <= bytes)
                text = QString::fromWCharArray(expanded.data());
        }
    }
    const QString registry = normalizeRegistryPath(text);
    if (!registry.isEmpty()) { addLocationTab(registry); return; }
    if (text.startsWith(QLatin1Char('"')))
    { const int quote = text.indexOf(QLatin1Char('"'), 1); if (quote > 0) text = text.mid(1, quote - 1); }
    if (!QFileInfo::exists(text))
    { QMessageBox::information(this, QStringLiteral("关联定位"), QStringLiteral("当前值未包含可确认的文件或注册表路径。")); return; }
    // Reveal a containing directory instead of executing a registry command line.
    QDesktopServices::openUrl(QUrl::fromLocalFile(QFileInfo(text).absolutePath()));
}
