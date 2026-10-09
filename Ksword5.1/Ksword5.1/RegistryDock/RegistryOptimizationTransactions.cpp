#include "RegistryOptimizationTransactions.h"
#include "RegistryDocumentApply.h"
#include "RegistryDocumentApplyInternal.h"
#include "RegistryValueTransactions.h"
#include <QDateTime>
#include <QDir>
#include <QStandardPaths>
#include <QUuid>

namespace ks::registry::optimization
{
namespace
{
// 原始操作路径规范为完整根，保留合法空格、默认空名和实际 WOW64 视图。
bool canonical(const QString& input, QString& output, QString* error)
{
    QString detail;
    const bool ok = apply_detail::pathCanonical(input, output, detail);
    if (error) *error = detail;
    return ok;
}

// 预览状态机负责捕获基线；这里保留已有优化批次确认策略，并实际回读所有提交结果。
bool applyDocument(const RegistryDocument& document, const RegistryAccessContext& context,
    QString* error, const RegistryValueState* expected = nullptr)
{
    RegistryApplyPlan plan; // 固定配置自己的通道，不从当前 Dock 获取来源。
    QString detail;
    if (!RegistryDocumentApplyService::prepareAccess(document, context.useR0, plan, detail))
    {
        if (error) *error = detail;
        return false;
    }
    if (expected)
    {
        // 颜色选择等模态交互前捕获的目标，不能被预览时新读取的数据替换。
        for (const auto& operation : plan.operations)
        {
            if (operation.kind != RegistryApplyOperation::Kind::SetValue
                && operation.kind != RegistryApplyOperation::Kind::DeleteValue) continue;
            if (operation.beforeValue.exists != expected->exists
                || (expected->exists && (operation.beforeValue.type != expected->type
                    || operation.beforeValue.data != expected->data)))
            {
                if (error) *error = QStringLiteral("Original registry value changed; optimization was not applied.");
                return false;
            }
        }
    }
    // 删除子树不能自动恢复 ACL，原始计划必须先保存完整备份才能执行。
    bool deletesTree = false;
    for (const auto& operation : plan.operations)
        if (operation.kind == RegistryApplyOperation::Kind::DeleteTree && operation.keyExistedBefore) deletesTree = true;
    if (deletesTree)
    {
        const QString directory = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)
            + QStringLiteral("/registry-backups");
        const QString backup = directory + QStringLiteral("/optimization-before-%1-%2.ksreg")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")),
                QUuid::createUuid().toString(QUuid::WithoutBraces));
        if (!QDir().mkpath(directory) || !RegistryDocumentApplyService::saveOriginalBackup(plan, backup, detail))
        {
            if (error) *error = detail.isEmpty() ? QStringLiteral("备份未保存，未应用任何操作。") : detail;
            return false;
        }
    }
    RegistryApplyResult result; // 不以 API bool 替代实际逐项回读回执。
    const bool ok = RegistryDocumentApplyService::applyAccess(plan, result);
    if (error) *error = result.error;
    return ok;
}
}

// 写入配置动作允许新建缺失键，但现有原值必须仍等于模态前读取的基线。
bool write(const QString& inputPath, const QString& name, const quint32 type,
    const QByteArray& bytes, const RegistryValueState& expected,
    const RegistryAccessContext& context, QString* error)
{
    QString path; // 与 DocumentApply 共用的严格完整路径。
    if (!canonical(inputPath, path, error)) return false;
    RegistryDocument document; // 文档状态机按原有父键创建顺序计划，避免默认视图旁路。
    document.viewBits = context.viewBits;
    document.values.append({path, name, type, bytes, false});
    document.operationOrder.append({RegistryDocumentOperation::Kind::Value, 0});
    return applyDocument(document, context, error, &expected);
}

// 删除准确目标与视图；Win32 子树保持正式 KTM/no-follow 与预览原树比较。
bool remove(const QString& inputPath, const QString& name, const bool isValue,
    const RegistryAccessContext& context, QString* error)
{
    QString path; // 不裁剪原路径中的合法组件空格。
    if (!canonical(inputPath, path, error)) return false;
    RegistryDocument document;
    document.viewBits = context.viewBits;
    RegistryValueState original; // 单值删除须保留准备前的原始基线。
    if (isValue)
    {
        if (!RegistryWorkbenchAccess::read(path, name, context, &original, error)) return false;
        if (!original.exists || !original.complete)
        {
            if (error) *error = QStringLiteral("Original registry value is absent or incomplete.");
            return false;
        }
        document.values.append({path, name, 0, {}, true});
        document.operationOrder.append({RegistryDocumentOperation::Kind::Value, 0});
    }
    else
    {
        bool exists = false; // 只针对已存在的非根键创建删除计划。
        if (!RegistryWorkbenchAccess::keyExists(path, context, &exists, error)) return false;
        if (!exists)
        {
            if (error) *error = QStringLiteral("Original registry key is absent.");
            return false;
        }
        document.keys.append({path, true, {}});
        document.operationOrder.append({RegistryDocumentOperation::Kind::Key, 0});
    }
    return applyDocument(document, context, error, isValue ? &original : nullptr);
}

// 值移动先证实目的缺失，再提交共用两端核验/失败恢复；键移动保留同父键原对象。
bool move(const QString& inputSource, const QString& oldName, const QString& inputTarget,
    const QString& newName, const bool isValue, const RegistryAccessContext& context, QString* error)
{
    QString source;
    QString target;
    if (!canonical(inputSource, source, error) || !canonical(inputTarget, target, error)) return false;
    if (!isValue)
    {
        const QString sourceParent = apply_detail::parentPath(source);
        const QString targetParent = apply_detail::parentPath(target);
        if (sourceParent.isEmpty() || sourceParent.compare(targetParent, Qt::CaseInsensitive) != 0)
        {
            if (error) *error = QStringLiteral("Only registry key renames within the same parent are supported.");
            return false;
        }
        QString actualTarget; // 共享访问层核验原名缺失、新名存在。
        return RegistryWorkbenchAccess::renameKey(source, target.mid(targetParent.size() + 1),
            context, &actualTarget, error);
    }
    RegistryValueState original; // 读取完整原字节，不使用显示摘要或格式化文本。
    if (!RegistryWorkbenchAccess::read(source, oldName, context, &original, error)
        || !original.exists || !original.complete)
    {
        if (error && error->isEmpty()) *error = QStringLiteral("Original registry value is absent or incomplete.");
        return false;
    }
    // 目的存在、缺失父键创建都留给同一个 KTM 事务；这里绝不提前写入目标键。
    RegistryValueRenameResult result; // 两端实际状态与恢复结果统一返回。
    const bool ok = RegistryValueTransactions::move(source, oldName, target, newName,
        {true, original.type, original.data}, context, result);
    if (error) *error = result.error;
    return ok;
}
}
