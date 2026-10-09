#include "RegistryDocumentApplyInternal.h"

#include <QFile>
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QSet>
#include <algorithm>
#include <utility>

// 共用路径、原始值和链接规则与 Win32 后端保持一致。
using namespace ks::registry::apply_detail;

namespace
{
// 比较完整树的键、安全描述符及原始值，拒绝丢项或竞争修改。
bool sameTree(const RegistryDocument& expected, const RegistryDocument& actual)
{
    if (expected.keys.size() != actual.keys.size() || expected.values.size() != actual.values.size())
        return false;
    QHash<QString, QByteArray> actualKeys;
    for (const auto& key : actual.keys)
        actualKeys.insert(folded(key.path), key.securityDescriptor);
    for (const auto& key : expected.keys) {
        const auto found = actualKeys.constFind(folded(key.path));
        if (found == actualKeys.constEnd() || (!key.securityDescriptor.isEmpty() && key.securityDescriptor != found.value()))
            return false;
    }
    QHash<QString, QHash<QString, RegistryApplyValueState>> values;
    for (const auto& value : actual.values)
        values[folded(value.keyPath)].insert(folded(value.name), {true, value.type, value.data});
    for (const auto& value : expected.values) {
        const auto path = values.constFind(folded(value.keyPath));
        if (path == values.constEnd())
            return false;
        const auto found = path.value().constFind(folded(value.name));
        if (found == path.value().constEnd() || !sameValue({true, value.type, value.data}, found.value()))
            return false;
    }
    return true;
}

// 模拟键保存原路径、安全元数据和不区分大小写的值索引。
struct SimulatedKey
{
    QString path;
    QByteArray security;
    QHash<QString, RegistryApplyValueState> values;
    QHash<QString, QString> names;
};

// 只读准备状态：模拟文档的顺序变化，保存每一步不可变的比较基线。
struct Preparation
{
    RegistryApplyBackend* backend = nullptr;
    RegistryApplyPlan plan;
    QHash<QString, SimulatedKey> keys;
    QStringList absentPrefixes;
    QString* error = nullptr;

    // 查询模拟状态或后端，present 输出结果，错误写入共享 error。
    bool exists(const QString& path, bool& present)
    {
        if (keys.contains(folded(path)))
        {
            present = true;
            return true;
        }
        for (const QString& missing : absentPrefixes) {
            if (inside(path, missing))
            {
                present = false;
                return true;
            }
        }
        if (!backend->keyExists(path, present, *error))
            return false;
        if (present)
            keys.insert(folded(path), {path, {}, {}, {}});
        else
            absentPrefixes.append(path);
        return true;
    }

    // 为路径和父键生成顺序创建计划；只记录计划，不实际创建。
    bool ensure(const QString& path, bool explicitSection)
    {
        bool present = false;
        if (!exists(path, present))
            return false;
        if (!present) {
            const QString parent = parentPath(path);
            if (parent.isEmpty())
                return failure(*error, QStringLiteral("A predefined registry root is unavailable."));
            if (!ensure(parent, false))
                return false;
        }
        if (!present || explicitSection) {
            RegistryApplyOperation op;
            op.kind = RegistryApplyOperation::Kind::CreateKey;
            op.keyPath = path;
            op.keyExistedBefore = present;
            plan.operations.append(std::move(op));
        }
        if (!present)
            keys.insert(folded(path), {path, {}, {}, {}});
        return true;
    }

    // 输入子树根，输出当前模拟快照，供删除前比较。
    RegistryDocument subtree(const QString& root) const
    {
        RegistryDocument tree;
        tree.rootPath = root;
        tree.viewBits = plan.viewBits;
        QStringList paths;
        for (const auto& key : keys) {
            if (inside(key.path, root))
                paths.append(key.path);
        }
        std::sort(paths.begin(), paths.end(), [](const QString& a, const QString& b) {
            return a.compare(b, Qt::CaseInsensitive) < 0;
        });
        for (const auto& path : paths) {
            const auto& key = keys[folded(path)];
            tree.keys.append({key.path, false, key.security});
            for (auto it = key.values.constBegin(); it != key.values.constEnd(); ++it) {
                if (it.value().exists)
                    tree.values.append({key.path, key.names.value(it.key()), it.value().type, it.value().data, false});
            }
        }
        return tree;
    }
};

// 保留文件操作顺序；仅无显式顺序的快照按先键后值生成。
QVector<RegistryDocumentOperation> sourceOrder(const RegistryDocument& document)
{
    if (!document.operationOrder.isEmpty())
        return document.operationOrder;
    QVector<RegistryDocumentOperation> order;
    for (qsizetype i = 0; i < document.keys.size(); ++i)
        order.append({RegistryDocumentOperation::Kind::Key, i});
    for (qsizetype i = 0; i < document.values.size(); ++i)
        order.append({RegistryDocumentOperation::Kind::Value, i});
    return order;
}
} // namespace

// 后端兼容的有界捕获默认实现；超预算时清空输出并失败。
bool RegistryApplyBackend::captureTreeBounded(const QString& path, qint64 maximumDataBytes,
    RegistryDocument& tree, QString& error)
{
    if (!captureTree(path, tree, error))
        return false;
    qint64 bytes = 0;
    for (const auto& key : tree.keys)
        bytes += key.securityDescriptor.size();
    for (const auto& value : tree.values)
        bytes += value.data.size();
    if (bytes > maximumDataBytes) {
        tree = {};
        return failure(error, QStringLiteral("Registry original capture exceeds its remaining data budget."));
    }
    return true;
}

// 输入文档和只读后端，输出逐项计划与原始备份；失败不产生可执行计划。
bool RegistryDocumentApplyService::prepareWithBackend(const RegistryDocument& document,
    RegistryApplyBackend& backend, RegistryApplyPlan& plan, QString& error)
{
    plan = {};
    error.clear();
    if ((document.viewBits != 0 && document.viewBits != 32 && document.viewBits != 64)
        || document.keys.size() + document.values.size() > kOperationLimit)
        return failure(error, QStringLiteral("Registry change view or operation count is invalid."));
    RegistryDocument source = document;
    QStringList roots;
    qint64 dataBytes = 0;
    for (auto& key : source.keys) {
        if (!pathCanonical(key.path, key.path, error))
            return false;
        if (key.deleteTree && parentPath(key.path).isEmpty())
            return failure(error, QStringLiteral("Deleting a predefined registry root is forbidden."));
        roots.append(key.path);
    }
    for (auto& value : source.values) {
        if (!pathCanonical(value.keyPath, value.keyPath, error))
            return false;
        if (value.name.size() > 16383 || !value.name.isValidUtf16() || value.name.contains(QChar(0))
            || value.data.size() > 16 * 1024 * 1024 || (value.deleteValue && !value.data.isEmpty()))
            return failure(error, QStringLiteral("Registry change value name or data is invalid."));
        dataBytes += value.data.size();
        if (dataBytes > kPlanDataLimit)
            return failure(error, QStringLiteral("Registry change exceeds the plan data budget."));
        roots.append(value.keyPath);
    }
    const auto order = sourceOrder(source);
    if (order.isEmpty() || order.size() != source.keys.size() + source.values.size())
        return failure(error, QStringLiteral("Registry change operation order is incomplete."));
    QSet<qsizetype> keyIndices, valueIndices;
    for (const auto& entry : order) {
        if (entry.kind == RegistryDocumentOperation::Kind::Key) {
            if (entry.index < 0 || entry.index >= source.keys.size() || keyIndices.contains(entry.index))
                return failure(error, QStringLiteral("Invalid registry change key operation index."));
            keyIndices.insert(entry.index);
        } else if (entry.kind == RegistryDocumentOperation::Kind::Value) {
            if (entry.index < 0 || entry.index >= source.values.size() || valueIndices.contains(entry.index))
                return failure(error, QStringLiteral("Invalid registry change value operation index."));
            valueIndices.insert(entry.index);
        } else {
            return failure(error, QStringLiteral("Unknown registry change operation kind."));
        }
    }
    std::sort(roots.begin(), roots.end(), [](const QString& a, const QString& b) {
        return (a + QLatin1Char('\\')).compare(b + QLatin1Char('\\'), Qt::CaseInsensitive) < 0;
    });
    QStringList selectedRoots;
    for (const auto& root : roots) {
        if (selectedRoots.isEmpty() || !inside(root, selectedRoots.last()))
            selectedRoots.append(root);
    }
    if (selectedRoots.size() > 100000)
        return failure(error, QStringLiteral("Registry change exceeds the target subtree count limit."));
    Preparation state;
    state.backend = &backend;
    state.error = &error;
    state.plan.viewBits = source.viewBits;
    qsizetype totalKeys = 0, totalValues = 0;
    for (const auto& root : selectedRoots) {
        bool present = false;
        if (!backend.keyExists(root, present, error))
            return false;
        if (!present) {
            state.absentPrefixes.append(root);
            state.plan.originallyAbsentKeys.append(root);
            continue;
        }
        RegistryDocument original;
        if (!backend.captureTreeBounded(root, kPlanDataLimit - dataBytes, original, error))
            return false;
        if (original.rootPath.compare(root, Qt::CaseInsensitive) != 0 || original.keys.isEmpty())
            return failure(error, QStringLiteral("Registry backend returned an incomplete original subtree."));
        totalKeys += original.keys.size();
        totalValues += original.values.size();
        if (totalKeys > 100000 || totalValues > 250000)
            return failure(error, QStringLiteral("Registry originals exceed the key or value budget."));
        for (const auto& key : original.keys) {
            if (!inside(key.path, root) || key.deleteTree)
                return failure(error, QStringLiteral("Registry backend returned an invalid original key."));
            state.keys.insert(folded(key.path), {key.path, key.securityDescriptor, {}, {}});
            dataBytes += key.securityDescriptor.size();
        }
        for (const auto& value : original.values) {
            auto found = state.keys.find(folded(value.keyPath));
            if (found == state.keys.end() || value.deleteValue)
                return failure(error, QStringLiteral("Registry backend returned an invalid original value."));
            found.value().values.insert(folded(value.name), {true, value.type, value.data});
            found.value().names.insert(folded(value.name), value.name);
            dataBytes += value.data.size();
        }
        if (dataBytes > kPlanDataLimit)
            return failure(error, QStringLiteral("Registry originals exceed the plan data budget."));
        state.plan.originalSubtrees.append(std::move(original));
    }
    for (const auto& entry : order) {
        if (entry.kind == RegistryDocumentOperation::Kind::Key) {
            const auto& key = source.keys.at(entry.index);
            if (!key.deleteTree) {
                if (!state.ensure(key.path, true))
                    return false;
            } else {
                RegistryApplyOperation op;
                op.kind = RegistryApplyOperation::Kind::DeleteTree;
                op.keyPath = key.path;
                if (!state.exists(key.path, op.keyExistedBefore))
                    return false;
                if (op.keyExistedBefore) {
                    op.beforeTree = state.subtree(key.path);
                    if (hasLink(op.beforeTree))
                        return failure(error, QStringLiteral("Registry tree deletion refuses symbolic links."));
                    const auto paths = state.keys.keys();
                    for (const auto& path : paths) {
                        if (inside(state.keys.value(path).path, key.path))
                            state.keys.remove(path);
                    }
                }
                state.absentPrefixes.append(key.path);
                state.plan.operations.append(std::move(op));
            }
        } else {
            const auto& value = source.values.at(entry.index);
            if (!state.ensure(value.keyPath, false))
                return false;
            auto& key = state.keys[folded(value.keyPath)];
            const auto link = key.values.constFind(folded(QStringLiteral("SymbolicLinkValue")));
            if (link != key.values.constEnd() && link.value().exists && link.value().type == 6)
                return failure(error, QStringLiteral("Registry value editing refuses symbolic links."));
            RegistryApplyOperation op;
            op.kind = value.deleteValue ? RegistryApplyOperation::Kind::DeleteValue : RegistryApplyOperation::Kind::SetValue;
            op.keyPath = value.keyPath;
            op.valueName = value.name;
            op.keyExistedBefore = true;
            op.beforeValue = key.values.value(folded(value.name));
            op.afterValue = value.deleteValue ? RegistryApplyValueState{} : RegistryApplyValueState{true, value.type, value.data};
            key.values.insert(folded(value.name), op.afterValue);
            key.names.insert(folded(value.name), value.name);
            state.plan.operations.append(std::move(op));
        }
        if (state.plan.operations.size() > kOperationLimit)
            return failure(error, QStringLiteral("Registry change exceeds the expanded operation budget."));
    }
    plan = std::move(state.plan);
    return true;
}

// 输入预览计划和原后端，逐项比较、执行与回读；result 记录状态及撤销边界。
bool RegistryDocumentApplyService::applyWithBackend(const RegistryApplyPlan& plan,
    RegistryApplyBackend& backend, RegistryApplyResult& result, const std::atomic_bool* canceledToken)
{
    result = {};
    result.viewBits = plan.viewBits;
    result.useR0 = plan.useR0;
    if ((plan.viewBits != 0 && plan.viewBits != 32 && plan.viewBits != 64)
        || plan.operations.isEmpty() || plan.operations.size() > kOperationLimit)
        return failure(result.error, QStringLiteral("Invalid registry apply plan."));
    for (const auto& operation : plan.operations) {
        QString normalized;
        if (!pathCanonical(operation.keyPath, normalized, result.error)
            || normalized != operation.keyPath
            || (operation.kind == RegistryApplyOperation::Kind::DeleteTree && parentPath(normalized).isEmpty())
            || operation.valueName.size() > 16383 || !operation.valueName.isValidUtf16()
            || operation.valueName.contains(QChar(0))
            || operation.beforeValue.data.size() > 16 * 1024 * 1024
            || operation.afterValue.data.size() > 16 * 1024 * 1024)
            return failure(result.error, QStringLiteral("Registry apply plan contains an unsafe path or value."));
        if ((operation.kind == RegistryApplyOperation::Kind::SetValue && !operation.afterValue.exists)
            || (operation.kind == RegistryApplyOperation::Kind::DeleteValue && operation.afterValue.exists))
            return failure(result.error, QStringLiteral("Registry apply plan contains inconsistent value state."));
        if (operation.kind == RegistryApplyOperation::Kind::DeleteTree && operation.keyExistedBefore
            && (operation.beforeTree.rootPath.compare(normalized, Qt::CaseInsensitive) != 0
                || operation.beforeTree.keys.isEmpty() || hasLink(operation.beforeTree)))
            return failure(result.error, QStringLiteral("Registry apply plan has no valid original deletion subtree."));
        RegistryApplyReceipt receipt;
        receipt.operation = operation;
        result.receipts.append(std::move(receipt));
    }
    // 必须先检查整个混合计划的能力，防止前面的普通写入成功后才拒绝不安全树删除。
    // 这里尚未调用后端读写；R0 不自动换成 Win32，回执保持未执行且无可撤销变更。
    if (!backend.supportsAtomicTreeDeletion())
    {
        for (auto& receipt : result.receipts)
        {
            if (receipt.operation.kind != RegistryApplyOperation::Kind::DeleteTree) continue;
            receipt.state = RegistryApplyReceipt::State::Failed;
            receipt.error = plan.useR0
                ? QStringLiteral("R0 registry protocol cannot safely delete registry trees. Select a Win32 32-bit or 64-bit view explicitly.")
                : QStringLiteral("This registry backend does not support atomic tree deletion.");
            result.error = receipt.error;
            return false;
        }
    }
    bool mutated = false, treeDeletion = false;
    for (auto& receipt : result.receipts) {
        auto stopForCancellation = [&]() {
            if (!canceledToken || !canceledToken->load(std::memory_order_relaxed))
                return false;
            receipt.state = RegistryApplyReceipt::State::Canceled;
            result.canceled = true;
            result.error = QStringLiteral("Registry application was canceled; completed changes remain applied.");
            result.canUndo = mutated && !treeDeletion;
            return true;
        };
        if (stopForCancellation())
            return false;
        auto& op = receipt.operation;
        QString error;
        bool ok = true;
        if (op.kind == RegistryApplyOperation::Kind::CreateKey || op.kind == RegistryApplyOperation::Kind::DeleteTree) {
            bool present = false;
            ok = backend.keyExists(op.keyPath, present, error);
            if (ok && stopForCancellation())
                return false;
            if (ok && present != op.keyExistedBefore)
                ok = failure(error, QStringLiteral("Registry key changed after preview: %1").arg(op.keyPath));
            if (ok && op.kind == RegistryApplyOperation::Kind::CreateKey && !present) {
                if (stopForCancellation())
                    return false;
                receipt.mutated = true;
                ok = backend.createKey(op.keyPath, error);
                if (ok) {
                    bool after = false;
                    ok = backend.keyExists(op.keyPath, after, error);
                    if (ok && !after)
                        ok = failure(error, QStringLiteral("Created registry key could not be verified."));
                    if (ok)
                        ok = backend.captureTree(op.keyPath, receipt.actualAfterTree, error);
                    if (ok && (receipt.actualAfterTree.keys.size() != 1 || !receipt.actualAfterTree.values.isEmpty()))
                        ok = failure(error, QStringLiteral("Created registry key changed during verification."));
                }
            } else if (ok && op.kind == RegistryApplyOperation::Kind::DeleteTree && present) {
                RegistryDocument current;
                ok = backend.captureTree(op.keyPath, current, error);
                if (ok && stopForCancellation())
                    return false;
                if (ok && (hasLink(current) || !sameTree(op.beforeTree, current)))
                    ok = failure(error, QStringLiteral("Registry subtree changed after preview: %1").arg(op.keyPath));
                if (ok) {
                    if (stopForCancellation())
                        return false;
                    receipt.mutated = true;
                    treeDeletion = true;
                    ok = backend.deleteTree(op.keyPath, op.beforeTree, error);
                    bool after = true;
                    if (ok)
                        ok = backend.keyExists(op.keyPath, after, error);
                    if (ok && after)
                        ok = failure(error, QStringLiteral("Deleted registry subtree is still present."));
                }
            }
        } else if (op.kind == RegistryApplyOperation::Kind::SetValue || op.kind == RegistryApplyOperation::Kind::DeleteValue) {
            RegistryApplyValueState before;
            ok = backend.readValue(op.keyPath, op.valueName, before, error);
            if (ok && stopForCancellation())
                return false;
            if (ok && !sameValue(before, op.beforeValue))
                ok = failure(error, QStringLiteral("Registry value changed after preview: %1\\%2").arg(op.keyPath, op.valueName));
            if (ok && !sameValue(before, op.afterValue)) {
                if (stopForCancellation())
                    return false;
                receipt.mutated = true;
                ok = op.afterValue.exists
                    ? backend.setValue(op.keyPath, op.valueName, op.afterValue.type, op.afterValue.data, error)
                    : backend.deleteValue(op.keyPath, op.valueName, error);
            }
            if (ok)
                ok = backend.readValue(op.keyPath, op.valueName, receipt.actualAfterValue, error);
            if (ok && !sameValue(receipt.actualAfterValue, op.afterValue))
                ok = failure(error, QStringLiteral("Registry write verification did not match the requested raw data."));
        } else {
            ok = failure(error, QStringLiteral("Unknown registry apply operation."));
        }
        if (!ok) {
            receipt.state = RegistryApplyReceipt::State::Failed;
            receipt.error = error;
            result.error = error;
            result.canceled = canceledToken && canceledToken->load(std::memory_order_relaxed);
            // A failed mutating call may have partially changed the target. It
            // cannot be automatically undone without a proven post-write state.
            result.canUndo = mutated && !treeDeletion && !receipt.mutated;
            return false;
        }
        receipt.state = RegistryApplyReceipt::State::Success;
        mutated = mutated || receipt.mutated;
    }
    result.completed = true;
    result.canUndo = mutated && !treeDeletion;
    return true;
}

// 按原提交成功回执生成逆序操作；部分撤销只保留仍待恢复的原回执。
bool RegistryDocumentApplyService::undoWithBackend(const RegistryApplyResult& previous,
    RegistryApplyBackend& backend, RegistryApplyResult& result, const std::atomic_bool* canceledToken)
{
    result = {};
    if (!previous.canUndo)
        return failure(result.error, QStringLiteral("This committed change requires restoration from its original backup."));
    RegistryApplyPlan undo;
    undo.viewBits = previous.viewBits;
    undo.useR0 = previous.useR0;
    const auto& originals = previous.undoAttempt ? previous.pendingUndoReceipts : previous.receipts;
    QVector<qsizetype> originalIndices;
    for (qsizetype i = originals.size(); i > 0; --i) {
        const auto& receipt = originals.at(i - 1);
        if (receipt.state != RegistryApplyReceipt::State::Success || !receipt.mutated)
            continue;
        RegistryApplyOperation op;
        op.keyPath = receipt.operation.keyPath;
        op.valueName = receipt.operation.valueName;
        op.keyExistedBefore = true;
        if (receipt.operation.kind == RegistryApplyOperation::Kind::CreateKey) {
            op.kind = RegistryApplyOperation::Kind::DeleteTree;
            op.beforeTree = receipt.actualAfterTree;
        } else if (receipt.operation.kind == RegistryApplyOperation::Kind::SetValue
            || receipt.operation.kind == RegistryApplyOperation::Kind::DeleteValue) {
            op.kind = receipt.operation.beforeValue.exists
                ? RegistryApplyOperation::Kind::SetValue : RegistryApplyOperation::Kind::DeleteValue;
            op.beforeValue = receipt.actualAfterValue;
            op.afterValue = receipt.operation.beforeValue;
        } else {
            return failure(result.error, QStringLiteral("Automatic undo refuses committed subtree deletions."));
        }
        undo.operations.append(std::move(op));
        originalIndices.append(i - 1);
    }
    if (undo.operations.isEmpty())
        return failure(result.error, QStringLiteral("There are no completed registry changes to undo."));
    const bool ok = applyWithBackend(undo, backend, result, canceledToken);
    result.undoAttempt = true;
    bool uncertainMutation = result.receipts.size() != originalIndices.size();
    for (qsizetype i = originalIndices.size(); i > 0; --i) {
        const qsizetype inverseIndex = i - 1;
        if (inverseIndex < result.receipts.size()) {
            const auto& inverse = result.receipts.at(inverseIndex);
            if (inverse.state == RegistryApplyReceipt::State::Success)
                continue;
            uncertainMutation = uncertainMutation || inverse.mutated;
        }
        result.pendingUndoReceipts.append(originals.at(originalIndices.at(inverseIndex)));
    }
    result.canUndo = !uncertainMutation && !result.pendingUndoReceipts.isEmpty();
    return ok;
}

// 原子保存完整原子树和缺失键元数据到 path；不改动注册表。
bool RegistryDocumentApplyService::saveOriginalBackup(const RegistryApplyPlan& plan,
    const QString& path, QString& error)
{
    error.clear();
    if (plan.viewBits != 0 && plan.viewBits != 32 && plan.viewBits != 64)
        return failure(error, QStringLiteral("Invalid registry original-backup view."));
    QJsonObject root;
    root.insert(QStringLiteral("format"), QStringLiteral("KSword.RegistryChangeOriginals"));
    root.insert(QStringLiteral("version"), 1);
    root.insert(QStringLiteral("viewBits"), plan.viewBits);
    QJsonArray segments;
    qint64 bytesTotal = 0;
    for (const auto& tree : plan.originalSubtrees) {
        if (tree.viewBits != plan.viewBits)
            return failure(error, QStringLiteral("Registry original-backup views do not match."));
        QByteArray bytes;
        if (!RegistryDocumentService::encodeBackup(tree, bytes, error))
            return false;
        bytesTotal += bytes.size();
        if (bytesTotal > kJournalLimit)
            return failure(error, QStringLiteral("Registry original backup exceeds the size budget."));
        segments.append(QJsonDocument::fromJson(bytes).object());
    }
    root.insert(QStringLiteral("segments"), segments);
    QJsonArray absent;
    for (const auto& key : plan.originallyAbsentKeys)
        absent.append(key);
    root.insert(QStringLiteral("originallyAbsentKeys"), absent);
    const QByteArray bytes = QJsonDocument(root).toJson(QJsonDocument::Compact);
    if (bytes.size() > kJournalLimit)
        return failure(error, QStringLiteral("Registry original backup exceeds the size budget."));
    QSaveFile file(path);
    file.setDirectWriteFallback(false);
    if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
        return failure(error, QStringLiteral("Cannot save registry original backup: %1").arg(file.errorString()));
    return true;
}

// 有界读取原状态备份，输出合并恢复文档；不删除备份外新增数据。
bool RegistryDocumentApplyService::loadOriginalBackup(const QString& path,
    RegistryDocument& mergeDocument, QString& error)
{
    mergeDocument = {};
    error.clear();
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly))
        return failure(error, QStringLiteral("Cannot open registry original backup: %1").arg(file.errorString()));
    if (file.size() < 0 || file.size() > kJournalLimit)
        return failure(error, QStringLiteral("Registry original backup exceeds the size budget."));
    const QByteArray bytes = file.read(kJournalLimit + 1);
    if (file.error() != QFileDevice::NoError || bytes.size() > kJournalLimit || !file.atEnd())
        return failure(error, QStringLiteral("Cannot read the complete registry original backup."));
    const QJsonDocument json = QJsonDocument::fromJson(bytes);
    if (!json.isObject())
        return failure(error, QStringLiteral("Invalid registry original-backup JSON."));
    const auto root = json.object();
    const double view = root.value(QStringLiteral("viewBits")).toDouble(-1);
    if (root.value(QStringLiteral("format")).toString() != QStringLiteral("KSword.RegistryChangeOriginals")
        || root.value(QStringLiteral("version")).toDouble(-1) != 1
        || (view != 0 && view != 32 && view != 64)
        || !root.value(QStringLiteral("segments")).isArray()
        || !root.value(QStringLiteral("originallyAbsentKeys")).isArray())
        return failure(error, QStringLiteral("Unsupported registry original-backup format."));
    RegistryDocument loaded;
    loaded.viewBits = static_cast<int>(view);
    const auto segments = root.value(QStringLiteral("segments")).toArray();
    if (segments.size() > 100000)
        return failure(error, QStringLiteral("Registry original backup exceeds the segment count limit."));
    QStringList roots;
    qint64 dataBytes = 0;
    for (const auto& segment : segments) {
        if (!segment.isObject())
            return failure(error, QStringLiteral("Invalid registry original-backup segment."));
        RegistryDocument tree;
        if (!RegistryDocumentService::decodeBackup(QJsonDocument(segment.toObject()).toJson(QJsonDocument::Compact), tree, error))
            return false;
        if (tree.viewBits != loaded.viewBits)
            return failure(error, QStringLiteral("Registry original-backup views do not match."));
        QString normalizedRoot;
        if (!pathCanonical(tree.rootPath, normalizedRoot, error))
            return false;
        roots.append(normalizedRoot);
        for (auto& key : tree.keys) {
            dataBytes += key.securityDescriptor.size();
            // Restore is merge-by-default; OWNER/GROUP/DACL remains metadata.
            loaded.operationOrder.append({RegistryDocumentOperation::Kind::Key, loaded.keys.size()});
            loaded.keys.append(std::move(key));
        }
        for (auto& value : tree.values) {
            dataBytes += value.data.size();
            loaded.operationOrder.append({RegistryDocumentOperation::Kind::Value, loaded.values.size()});
            loaded.values.append(std::move(value));
        }
        if (dataBytes > kPlanDataLimit || loaded.keys.size() > 100000 || loaded.values.size() > 250000)
            return failure(error, QStringLiteral("Registry original restore exceeds the data or item budget."));
    }
    std::sort(roots.begin(), roots.end(), [](const QString& a, const QString& b) {
        return (a + QLatin1Char('\\')).compare(b + QLatin1Char('\\'), Qt::CaseInsensitive) < 0;
    });
    for (qsizetype i = 1; i < roots.size(); ++i) {
        if (inside(roots.at(i), roots.at(i - 1)))
            return failure(error, QStringLiteral("Registry original-backup segments overlap."));
    }
    const auto absent = root.value(QStringLiteral("originallyAbsentKeys")).toArray();
    if (absent.size() > 100000)
        return failure(error, QStringLiteral("Registry original backup exceeds the absent-key count limit."));
    for (const auto& entry : absent) {
        QString normalized;
        if (!entry.isString() || !pathCanonical(entry.toString(), normalized, error))
            return failure(error, QStringLiteral("Invalid absent-key metadata in registry original backup."));
    }
    if (loaded.keys.isEmpty())
        return failure(error, QStringLiteral("The original backup contains no existing data to merge-restore."));
    mergeDocument = std::move(loaded);
    return true;
}
