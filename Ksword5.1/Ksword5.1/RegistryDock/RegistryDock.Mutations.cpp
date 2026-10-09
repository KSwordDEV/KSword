#include "RegistryDock.h"
#include "RegistryDocument.h"
#include "RegistryWorkbenchAccess.h"
#include "RegistryValueTransactions.h"

#include <QInputDialog>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QTableWidget>
#include <QTreeWidget>

// 创建键仍进入原有预览、备份和显式 Apply 链路；目标与通道在交互前冻结。
void RegistryDock::createSubKey()
{
    const QPointer<RegistryDock> guarded(this); // 输入框可能运行嵌套事件循环。
    const QString parent = m_currentPath; // 保留父键合法空格。
    const RegistryAccessContext context = accessContextForPath(parent); // 初始视图和通道。
    if (m_applyingChanges || !preserveEditorDraft() || !guarded) return;
    bool accepted = false; // 取消不产生可执行计划。
    const QString name = QInputDialog::getText(this, QStringLiteral("新建子键"),
        QStringLiteral("请输入子键名称："), QLineEdit::Normal, QStringLiteral("New Key"), &accepted);
    if (!guarded || !accepted) return;
    if (m_currentPath.compare(parent, Qt::CaseInsensitive) != 0 || m_viewBits != context.viewBits) return;
    if (name.isEmpty() || name.size() > 255 || name.contains(QLatin1Char('\\')) || name.contains(QChar(0)))
    {
        QMessageBox::warning(this, QStringLiteral("新建子键"), QStringLiteral("子键名称必须为 1 ～ 255 字符，不能包含反斜杠或 NUL。"));
        return;
    }
    const QString path = parent + QLatin1Char('\\') + name; // 精确目标不能从当前树重新获取。
    QString error;
    bool exists = false; // 查询失败不是缺失，也不能覆盖已有键。
    if (!RegistryWorkbenchAccess::keyExists(path, context, &exists, &error) || exists)
    {
        QMessageBox::warning(this, QStringLiteral("新建子键"), exists
            ? QStringLiteral("Registry key already exists; it was not replaced.") : error);
        return;
    }
    RegistryDocument document; // 共用状态机在 Apply 时还会重新验证存在性。
    document.viewBits = context.viewBits;
    document.keys.append({path, false, {}});
    document.operationOrder.append({RegistryDocumentOperation::Kind::Key, 0});
    previewRegistryDocument(document, QStringLiteral("新建子键"), context.useR0);
}

// 重命名使用捕获的原始目标与数据；回读/恢复结果来自正式共享事务状态机。
void RegistryDock::renameSelectedObject()
{
    const QPointer<RegistryDock> guarded(this); // 模态返回后确认页面还存在。
    const QString path = m_currentPath; // F2 或菜单启动时的真实键。
    const RegistryAccessContext context = accessContextForPath(path); // 冻结 WOW64/R0 决策。
    if (m_applyingChanges || !preserveEditorDraft() || !guarded) return;
    if ((m_valuesActive || m_valueTable->hasFocus()) && m_valueTable->currentRow() >= 0)
    {
        const auto* item = m_valueTable->item(m_valueTable->currentRow(), 0); // 仅模态前借用行对象。
        if (!item) return;
        const QString oldName = item->data(Qt::UserRole).toString(); // 默认值是真正的空名。
        if (oldName.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("重命名"), QStringLiteral("默认值不支持重命名。"));
            return;
        }
        RegistryValueState original; // 输入框打开前完整捕获原名基线。
        QString error;
        if (!RegistryWorkbenchAccess::read(path, oldName, context, &original, &error)
            || !original.exists || !original.complete)
        {
            QMessageBox::warning(this, QStringLiteral("重命名值"), error.isEmpty()
                ? QStringLiteral("原值不存在或数据不完整。") : error);
            return;
        }
        bool accepted = false;
        const QString newName = QInputDialog::getText(this, QStringLiteral("重命名值"),
            QStringLiteral("新名称："), QLineEdit::Normal, oldName, &accepted);
        if (!guarded || !accepted || newName.isEmpty()
            || newName.compare(oldName, Qt::CaseInsensitive) == 0) return;
        if (m_currentPath.compare(path, Qt::CaseInsensitive) != 0 || m_viewBits != context.viewBits) return;
        RegistryValueRenameResult result; // 保存两端实际状态和恢复失败诊断。
        const bool renamed = RegistryValueTransactions::rename(path, oldName, newName,
            {true, original.type, original.data}, context, result);
        refreshValueTable(); // 失败残留也从实际目标重读，禁止维持旧成功假象。
        if (!renamed)
        {
            QMessageBox::warning(this, QStringLiteral("重命名值"), result.error);
            return;
        }
        kLogEvent event; // 成功日志仅在两端实际回读一致后写入。
        info << event << "[RegistryDock] 重命名值已回读验证, path=" << path.toStdString()
            << ", oldName=" << oldName.toStdString() << ", newName=" << newName.toStdString() << eol;
        return;
    }

    // 键改名保留原对象和 ACL，只调用共享访问层的同父键系统 API。
    const qsizetype separator = path.lastIndexOf(QLatin1Char('\\')); // 无子组件时就是根键。
    if (separator < 0)
    {
        QMessageBox::information(this, QStringLiteral("重命名键"), QStringLiteral("根键不可重命名。"));
        return;
    }
    const QString oldName = path.mid(separator + 1);
    bool accepted = false;
    const QString newName = QInputDialog::getText(this, QStringLiteral("重命名键"),
        QStringLiteral("新键名："), QLineEdit::Normal, oldName, &accepted);
    if (!guarded || !accepted || newName.isEmpty()
        || newName.compare(oldName, Qt::CaseInsensitive) == 0) return;
    if (m_currentPath.compare(path, Qt::CaseInsensitive) != 0 || m_viewBits != context.viewBits) return;
    QString newPath; // 共享层输出经过实际两端存在性核验的路径。
    QString error;
    if (!RegistryWorkbenchAccess::renameKey(path, newName, context, &newPath, &error))
    {
        QMessageBox::warning(this, QStringLiteral("重命名键"), error);
        return;
    }
    navigateToPath(newPath, true);
}

// 保留既有树删除预览/备份/Apply 确认；搜索行目标和实际通道不随当前树变化。
void RegistryDock::deleteSearchResultKey(const QString& inputPath,
    const RegistryAccessContext* capturedContext)
{
    const QPointer<RegistryDock> guarded(this); // 暂存确认返回后检查生命周期。
    const QString path = inputPath; // 输入可能借用 m_currentPath，交互前必须复制。
    const RegistryAccessContext context = capturedContext ? *capturedContext
        : accessContextForPath(path); // 搜索行保留旧来源，普通树行使用启动时来源。
    if (m_applyingChanges || !preserveEditorDraft() || !guarded) return;
    if (path.isEmpty() || !path.contains(QLatin1Char('\\')))
    {
        QMessageBox::warning(this, QStringLiteral("删除键"), QStringLiteral("不能删除根键。"));
        return;
    }
    RegistryDocument document; // 准确的原始行路径，不取当前树键替代。
    document.viewBits = context.viewBits;
    document.keys.append({path, true, {}});
    document.operationOrder.append({RegistryDocumentOperation::Kind::Key, 0});
    previewRegistryDocument(document, QStringLiteral("删除子树预览"), context.useR0);
}
