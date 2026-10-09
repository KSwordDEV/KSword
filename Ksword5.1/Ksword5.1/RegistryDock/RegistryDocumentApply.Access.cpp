#include "RegistryAccessApplyBackend.h"

#include <QSet>

// 构造时复制来源；普通字段不会随着 Dock 切换模式改变。
RegistryAccessApplyBackend::RegistryAccessApplyBackend(const RegistryAccessContext& context)
    : m_context(context)
{
}

// 查询完整键存在性，失败时错误和缺失含义严格区分。
bool RegistryAccessApplyBackend::keyExists(const QString& path, bool& exists, QString& error)
{
    return RegistryWorkbenchAccess::keyExists(path, m_context, &exists, &error);
}

// 只接受完整原始值作为事务基线；不把摘要或传输失败当作空数据。
bool RegistryAccessApplyBackend::readValue(const QString& path, const QString& name,
    RegistryApplyValueState& value, QString& error)
{
    value = {};
    RegistryValueState current; // 同来源读取结果包含存在性和字节完整性。
    if (!RegistryWorkbenchAccess::read(path, name, m_context, &current, &error)) return false;
    if (!current.complete)
    {
        error = QStringLiteral("Incomplete registry data cannot be used as a transaction baseline.");
        return false;
    }
    value = {current.exists, current.type, current.data};
    return true;
}

// 完整树快照默认受 128 MiB 原始数据预算约束。
bool RegistryAccessApplyBackend::captureTree(const QString& path, RegistryDocument& tree, QString& error)
{
    return captureTreeBounded(path, 128LL * 1024 * 1024, tree, error);
}

// R0 枚举逐节点验证名字、完整性和预算；保留准确数据且不伪造不可获取的 ACL。
bool RegistryAccessApplyBackend::captureTreeBounded(const QString& path, const qint64 maximumDataBytes,
    RegistryDocument& tree, QString& error)
{
    tree = {};
    if (!m_context.useR0)
        return RegistryDocumentService::captureWin32(path, m_context.viewBits, tree, error, maximumDataBytes);
    RegistryDocument captured; // 失败时不会把半份子树暴露给可执行计划。
    captured.rootPath = path;
    captured.viewBits = m_context.viewBits;
    QStringList pending{path}; // 保存准确的子路径，不做名称裁剪。
    QSet<QString> visited; // 不区分大小写去重，拒绝损坏或重复的枚举图。
    qint64 dataBytes = 0; // 已捕获的完整字节总量，防止文档预算失效。
    while (!pending.isEmpty())
    {
        const QString currentPath = pending.takeLast();
        const QString foldedPath = currentPath.toCaseFolded();
        if (visited.contains(foldedPath) || visited.size() + pending.size() >= 100000
            || currentPath.count(QLatin1Char('\\')) - path.count(QLatin1Char('\\')) > 256)
        {
            error = QStringLiteral("Registry capture exceeds its traversal budget or contains duplicate keys.");
            return false;
        }
        visited.insert(foldedPath);
        RegistryKeyListing listing; // 不完整枚举禁止制作删除/恢复事务。
        if (!RegistryWorkbenchAccess::enumerate(currentPath, m_context, &listing, &error)) return false;
        if (!listing.complete)
        {
            error = listing.warning;
            return false;
        }
        captured.keys.append({currentPath, false, {}});
        captured.operationOrder.append({RegistryDocumentOperation::Kind::Key, captured.keys.size() - 1});
        QSet<QString> names; // 单键的原始值名按注册表大小写规则去重。
        for (const auto& value : listing.values)
        {
            if (!value.complete || names.contains(value.name.toCaseFolded()))
            {
                error = QStringLiteral("Registry capture contains incomplete or duplicate values.");
                return false;
            }
            names.insert(value.name.toCaseFolded());
            dataBytes += value.data.size();
            if (dataBytes > maximumDataBytes || captured.values.size() >= 250000)
            {
                error = QStringLiteral("Registry original capture exceeds its remaining data budget.");
                return false;
            }
            captured.values.append({currentPath, value.name, value.type, value.data, false});
            captured.operationOrder.append({RegistryDocumentOperation::Kind::Value, captured.values.size() - 1});
        }
        for (const auto& child : listing.subKeys)
        {
            if (child.isEmpty() || child.size() > 255 || child.contains(QLatin1Char('\\')) || child.contains(QChar(0)))
            {
                error = QStringLiteral("Invalid registry key component.");
                return false;
            }
            pending.append(currentPath + QLatin1Char('\\') + child);
        }
    }
    tree = std::move(captured);
    return true;
}

// 创建、设置与删除单值都复用唯一访问层，禁止隐藏的默认 Win32 路径。
bool RegistryAccessApplyBackend::createKey(const QString& path, QString& error)
{
    return RegistryWorkbenchAccess::createKey(path, m_context, &error);
}

bool RegistryAccessApplyBackend::setValue(const QString& path, const QString& name,
    const quint32 type, const QByteArray& data, QString& error)
{
    RegistryValueState value; // 完整原始字节和真实名称直接传递，不走展示文本编解码。
    value.name = name;
    value.type = type;
    value.data = data;
    value.exists = true;
    value.requiredBytes = static_cast<quint32>(data.size());
    return RegistryWorkbenchAccess::write(path, value, m_context, &error);
}

bool RegistryAccessApplyBackend::deleteValue(const QString& path, const QString& name, QString& error)
{
    return RegistryWorkbenchAccess::removeValue(path, name, m_context, &error);
}

// 普通访问层无法将原树比较和删除绑定在同一事务，直接调用同样在首写前拒绝。
bool RegistryAccessApplyBackend::deleteTree(const QString& path, const RegistryDocument& expectedTree, QString& error)
{
    Q_UNUSED(path);
    Q_UNUSED(expectedTree);
    error = m_context.useR0
        ? QStringLiteral("R0 registry protocol cannot safely delete registry trees. Select a Win32 32-bit or 64-bit view explicitly.")
        : QStringLiteral("This registry backend does not support atomic tree deletion.");
    return false;
}

// 以不可变通道准备文档；Win32 保留现有固定句柄/KTM 删除与 ACL 备份实现。
bool RegistryDocumentApplyService::prepareAccess(const RegistryDocument& document, const bool useR0,
    RegistryApplyPlan& plan, QString& error)
{
    if (!useR0) return prepareWin32(document, plan, error);
    RegistryAccessApplyBackend backend({document.viewBits, true});
    if (!prepareWithBackend(document, backend, plan, error)) return false;
    plan.useR0 = true;
    return true;
}

// 执行与撤销只读回执的来源，拒绝用当前用户选择代替原上下文。
bool RegistryDocumentApplyService::applyAccess(const RegistryApplyPlan& plan, RegistryApplyResult& result,
    const std::atomic_bool* canceledToken)
{
    if (!plan.useR0) return applyWin32(plan, result, canceledToken);
    RegistryAccessApplyBackend backend({plan.viewBits, true});
    return applyWithBackend(plan, backend, result, canceledToken);
}

bool RegistryDocumentApplyService::undoAccess(const RegistryApplyResult& previous, RegistryApplyResult& result,
    const std::atomic_bool* canceledToken)
{
    if (!previous.useR0) return undoWin32(previous, result, canceledToken);
    RegistryAccessApplyBackend backend({previous.viewBits, true});
    return undoWithBackend(previous, backend, result, canceledToken);
}
