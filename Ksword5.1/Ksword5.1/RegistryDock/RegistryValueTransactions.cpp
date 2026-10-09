#include "RegistryValueTransactions.h"
#include "RegistryDocumentApplyInternal.h"

// 构造只含一项的已冻结值计划，复用正式状态机执行和撤销信息。
bool RegistryValueTransactions::apply(const QString& path, const QString& name,
    const RegistryApplyValueState& before, const RegistryApplyValueState& after,
    const RegistryAccessContext& context, RegistryApplyResult& result,
    const std::atomic_bool* canceledToken)
{
    result = {}; // 参数校验失败不能遗留上次调用的成功回执。
    RegistryApplyOperation operation; // 写前快照和请求状态由 UI 草稿固定。
    if (!ks::registry::apply_detail::pathCanonical(path, operation.keyPath, result.error)) return false;
    operation.kind = after.exists ? RegistryApplyOperation::Kind::SetValue
        : RegistryApplyOperation::Kind::DeleteValue;
    operation.valueName = name;
    operation.keyExistedBefore = true;
    operation.beforeValue = before;
    operation.afterValue = after;
    RegistryApplyPlan plan; // 单值提交与文档提交使用同一回执规则。
    plan.viewBits = context.viewBits;
    plan.useR0 = context.useR0;
    plan.operations.append(operation);
    return RegistryDocumentApplyService::applyAccess(plan, result, canceledToken);
}

// 固定来源；默认值不支持 UI 改名，非空原名/目标转入真正原子移动入口。
bool RegistryValueTransactions::rename(const QString& path, const QString& oldName,
    const QString& newName, const RegistryApplyValueState& expected,
    const RegistryAccessContext& context, RegistryValueRenameResult& result)
{
    if (oldName.isEmpty() || newName.isEmpty())
    {
        result = {};
        result.error = QStringLiteral("Invalid registry value rename request.");
        return false;
    }
    return move(path, oldName, path, newName, expected, context, result);
}

// 可注入测试也必须声明真正事务能力，普通 read/set/delete 不能作为降级路径。
bool RegistryValueTransactions::renameWithBackend(const QString& path, const QString& oldName,
    const QString& newName, const RegistryApplyValueState& expected,
    RegistryApplyBackend& backend, RegistryValueRenameResult& result)
{
    if (oldName.isEmpty() || newName.isEmpty())
    {
        result = {};
        result.error = QStringLiteral("Invalid registry value rename request.");
        return false;
    }
    return moveWithBackend(path, oldName, path, newName, expected, backend, result);
}

// R0 v1 无原子事务/条件创建能力：写入前明确拒绝，用户须主动选择 Win32 视图。
bool RegistryValueTransactions::move(const QString& sourcePath, const QString& oldName,
    const QString& destinationPath, const QString& newName,
    const RegistryApplyValueState& expected, const RegistryAccessContext& context,
    RegistryValueRenameResult& result)
{
    result = {};
    if (context.useR0)
    {
        result.error = QStringLiteral("R0 registry protocol cannot atomically rename or move values. Select a Win32 32-bit or 64-bit view explicitly.");
        return false;
    }
    return RegistryDocumentApplyService::moveValueWin32(sourcePath, oldName, destinationPath, newName,
        expected, context.viewBits, result);
}

// 验证参数、来源和真实事务能力后一次调用；不得重新引入普通逐次补写/补删恢复。
bool RegistryValueTransactions::moveWithBackend(const QString& sourcePath, const QString& oldName,
    const QString& destinationPath, const QString& newName,
    const RegistryApplyValueState& expected, RegistryApplyBackend& backend,
    RegistryValueRenameResult& result)
{
    result = {};
    QString source;
    QString destination;
    if (!expected.exists || expected.data.size() > 16 * 1024 * 1024
        || oldName.size() > 16383 || newName.size() > 16383
        || oldName.contains(QChar(0)) || newName.contains(QChar(0))
        || !oldName.isValidUtf16() || !newName.isValidUtf16()
        || !ks::registry::apply_detail::pathCanonical(sourcePath, source, result.error)
        || !ks::registry::apply_detail::pathCanonical(destinationPath, destination, result.error))
    {
        if (result.error.isEmpty()) result.error = QStringLiteral("Invalid registry value rename request.");
        return false;
    }
    if (source.compare(destination, Qt::CaseInsensitive) == 0
        && oldName.compare(newName, Qt::CaseInsensitive) == 0)
    {
        result.error = QStringLiteral("Registry rename requires a different value name.");
        return false;
    }
    if (!backend.supportsAtomicValueMove())
    {
        result.error = QStringLiteral("This registry backend does not support atomic value moves.");
        return false;
    }
    QString error; // 事务后端负责提交、失败回滚和事务之外的实际回读。
    const bool ok = backend.moveValueAtomic(source, oldName, destination, newName, expected, result, error);
    result.error = error;
    if (!ok) return false;
    if (result.committed && result.state == RegistryValueRenameResult::State::Renamed && result.originalVerified
        && result.destinationVerified && !result.actualOriginal.exists
        && ks::registry::apply_detail::sameValue(result.actualDestination, expected)) return true;
    result.state = RegistryValueRenameResult::State::Unverified;
    result.error = QStringLiteral("Registry rename was not verified; inspect both names before retrying.");
    return false;
}
