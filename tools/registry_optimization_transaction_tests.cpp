// 正式优化/Access/DocumentApply/值移动代码，唯一边界是内存键映射，不连接真实注册表。
#include <QCoreApplication>
#include <QMap>
#include <QStringList>
#include <cstdio>
#include <cstdlib>
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryOptimizationTransactions.h"
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryAccessApplyBackend.h"
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryValueTransactions.h"
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryDocumentApplyInternal.h"

namespace fixture
{
unsigned checks = 0; // 实际执行断言，不把静态 source 搜索算作测试。
unsigned writes = 0; // 内存写操作总数，证明拒绝场景没有变更。
bool failDelete = false; // 原值删除失败必须由正式移动状态机恢复。
bool rejectCapture = false; // 拒绝子树捕获，证明未生成可执行删除计划。
bool insertDestinationBeforeCommit = false; // 提交前外部写者插入 B，事务快照不得覆盖它。
QVector<int> views; // 每次实际 mock 访问的冻结视图。
QVector<bool> channels; // 每次访问来源，不随 UI 当前页变化。
using Values = QMap<QString, RegistryValueState>;
QMap<QString, Values> keys; // 以视图和完整键路径区分两个来源。
const QString source = QStringLiteral("HKEY_LOCAL_MACHINE\\Fixture\\Source");
const QString target = QStringLiteral("HKEY_LOCAL_MACHINE\\Fixture\\Target");

void require(const bool ok, const char* text)
{
    ++checks;
    if (!ok) { std::fprintf(stderr, "FAIL: %s\n", text); std::abort(); }
}
QString identity(const QString& path, const int view)
{
    return QString::number(view) + QLatin1Char(':') + path.toCaseFolded();
}
void record(const RegistryAccessContext& context)
{
    views.append(context.viewBits);
    channels.append(context.useR0);
}
void put(const QString& path, const QString& name, const QByteArray& bytes, const int view)
{
    keys[identity(path, view)][name.toCaseFolded()] = {name, 3, bytes, true, true, static_cast<quint32>(bytes.size())};
}
void reset(const int view)
{
    keys.clear(); views.clear(); channels.clear(); writes = 0;
    failDelete = rejectCapture = insertDestinationBeforeCommit = false;
    keys[identity(QStringLiteral("HKEY_LOCAL_MACHINE"), view)];
    keys[identity(QStringLiteral("HKEY_LOCAL_MACHINE\\Fixture"), view)];
    keys[identity(target, view)];
    put(source, QStringLiteral("A"), QByteArray::fromHex("0081fe44"), view);
}
RegistryValueState value(const QString& path, const QString& name, const int view)
{
    auto result = keys.value(identity(path, view)).value(name.toCaseFolded());
    result.name = name;
    return result;
}
void proveView(const int view)
{
    require(!views.isEmpty(), "real shared entry invoked a mocked access");
    for (const int actual : views) require(actual == view, "every key and value operation retains profile view");
    for (const bool actual : channels) require(!actual, "profile Win32 source never changes to current UI R0");
}
}

// 所有共享访问 API 都由内存 map 实现；默认值空名和合法空格保持原样。
bool RegistryWorkbenchAccess::read(const QString& path, const QString& name,
    const RegistryAccessContext& context, RegistryValueState* state, QString* error)
{
    fixture::record(context);
    if (state) *state = fixture::value(path, name, context.viewBits);
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::keyExists(const QString& path, const RegistryAccessContext& context, bool* exists, QString* error)
{
    fixture::record(context);
    if (exists) *exists = fixture::keys.contains(fixture::identity(path, context.viewBits));
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::write(const QString& path, const RegistryValueState& state,
    const RegistryAccessContext& context, QString* error)
{
    fixture::record(context);
    ++fixture::writes;
    fixture::keys[fixture::identity(path, context.viewBits)][state.name.toCaseFolded()] = state;
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::removeValue(const QString& path, const QString& name,
    const RegistryAccessContext& context, QString* error)
{
    fixture::record(context);
    ++fixture::writes;
    if (fixture::failDelete && path == fixture::source)
    {
        if (error) *error = QStringLiteral("fixture source deletion denied");
        return false;
    }
    fixture::keys[fixture::identity(path, context.viewBits)].remove(name.toCaseFolded());
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::createKey(const QString& path, const RegistryAccessContext& context, QString* error)
{
    fixture::record(context);
    ++fixture::writes;
    fixture::keys[fixture::identity(path, context.viewBits)];
    if (error) error->clear();
    return true;
}
bool RegistryWorkbenchAccess::enumerate(const QString&, const RegistryAccessContext&, RegistryKeyListing*, QString*, bool) { std::abort(); }
bool RegistryWorkbenchAccess::renameKey(const QString& path, const QString& name,
    const RegistryAccessContext& context, QString* newPath, QString* error)
{
    fixture::record(context);
    const QString destination = path.left(path.lastIndexOf(QLatin1Char('\\')) + 1) + name;
    if (fixture::keys.contains(fixture::identity(destination, context.viewBits))) return false;
    ++fixture::writes;
    fixture::keys[fixture::identity(destination, context.viewBits)] = fixture::keys.take(fixture::identity(path, context.viewBits));
    if (newPath) *newPath = destination;
    if (error) error->clear();
    return true;
}

// 子树读取来自同一份内存来源；不得触发保存备份或真实 Win32 文档传输。
bool RegistryDocumentService::captureWin32(const QString& path, int view, RegistryDocument& tree, QString& error, qint64)
{
    fixture::record({view, false});
    if (fixture::rejectCapture) { error = QStringLiteral("fixture capture refused"); return false; }
    tree = {};
    tree.rootPath = path;
    tree.viewBits = view;
    const QString root = fixture::identity(path, view);
    for (auto it = fixture::keys.cbegin(); it != fixture::keys.cend(); ++it)
    {
        if (it.key() != root && !it.key().startsWith(root + QLatin1Char('\\'))) continue;
        const QString keyPath = path + it.key().mid(root.size());
        tree.keys.append({keyPath, false, {}});
        for (const auto& value : it.value()) tree.values.append({keyPath, value.name, value.type, value.data, false});
    }
    return true;
}
bool RegistryDocumentService::encodeBackup(const RegistryDocument&, QByteArray&, QString&) { std::abort(); }
bool RegistryDocumentService::decodeBackup(const QByteArray&, RegistryDocument&, QString&) { std::abort(); }
bool RegistryDocumentApplyService::prepareWin32(const RegistryDocument& document, RegistryApplyPlan& plan, QString& error)
{
    RegistryAccessApplyBackend backend({document.viewBits, false});
    return prepareWithBackend(document, backend, plan, error);
}
bool RegistryDocumentApplyService::applyWin32(const RegistryApplyPlan& plan, RegistryApplyResult& result, const std::atomic_bool* token)
{
    RegistryAccessApplyBackend backend({plan.viewBits, false});
    return applyWithBackend(plan, backend, result, token);
}
bool RegistryDocumentApplyService::undoWin32(const RegistryApplyResult& previous, RegistryApplyResult& result, const std::atomic_bool* token)
{
    RegistryAccessApplyBackend backend({previous.viewBits, false});
    return undoWithBackend(previous, backend, result, token);
}

// 优化入口的事务边界只由内存快照替换；真实 Windows KTM 绑定另由 atomic_move_tests 执行。
bool RegistryDocumentApplyService::moveValueWin32(const QString& source, const QString& oldName,
    const QString& target, const QString& newName, const RegistryApplyValueState& expected,
    const int view, RegistryValueRenameResult& result)
{
    fixture::record({view, false});
    result = {};
    const auto before = fixture::value(source, oldName, view);
    const auto destination = fixture::value(target, newName, view);
    result.originalVerified = result.destinationVerified = true;
    result.actualOriginal = {before.exists, before.type, before.data};
    result.actualDestination = {destination.exists, destination.type, destination.data};
    if (!ks::registry::apply_detail::sameValue(result.actualOriginal, expected) || destination.exists)
    {
        result.error = QStringLiteral("fixture transaction baseline or destination conflict");
        return false;
    }
    auto staged = fixture::keys; // 目标键创建和值移动都尚未写入 live map。
    staged[fixture::identity(target, view)][newName.toCaseFolded()] = {newName, expected.type,
        expected.data, true, true, static_cast<quint32>(expected.data.size())};
    staged[fixture::identity(source, view)].remove(oldName.toCaseFolded());
    if (fixture::failDelete)
    {
        result.state = RegistryValueRenameResult::State::Restored;
        result.error = QStringLiteral("fixture staged deletion refused; transaction rolled back");
        return false;
    }
    if (fixture::insertDestinationBeforeCommit)
    {
        fixture::put(target, newName, QByteArray("external-B"), view);
        result.state = RegistryValueRenameResult::State::Conflict;
        result.actualDestination = {true, 3, QByteArray("external-B")};
        result.error = QStringLiteral("fixture external writer conflicts with commit");
        return false; // 丢弃 staged，保留实际外部 B 和源 A。
    }
    fixture::keys = std::move(staged);
    fixture::writes += 2;
    result.committed = true;
    result.state = RegistryValueRenameResult::State::Renamed;
    result.actualOriginal = {};
    result.actualDestination = expected;
    return true;
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    using namespace fixture;
    QString error;
    for (const int view : {0, 32, 64})
    {
        const RegistryAccessContext context{view, false};
        reset(view);
        auto original = value(source, QStringLiteral("A"), view);
        require(ks::registry::optimization::write(source, QStringLiteral("A"), 3, QByteArray("new"), original, context, &error), "shared optimization set and readback");
        require(value(source, QStringLiteral("A"), view).data == "new", "requested full bytes stored");
        proveView(view);

        reset(view); insertDestinationBeforeCommit = true;
        require(!ks::registry::optimization::move(source, QStringLiteral("A"), target, QStringLiteral("B"), true, context, &error),
            "optimization commit conflict after destination check is not success");
        require(writes == 0 && value(source, QStringLiteral("A"), view).exists
            && value(target, QStringLiteral("B"), view).data == "external-B", "optimization retains late external B and original A");
        proveView(view);

        reset(view); original = value(source, QStringLiteral("A"), view);
        put(source, QStringLiteral("A"), QByteArray("external"), view);
        require(!ks::registry::optimization::write(source, QStringLiteral("A"), 3, QByteArray("new"), original, context, &error), "modal baseline conflict rejected");
        require(writes == 0 && value(source, QStringLiteral("A"), view).data == "external", "external data retained");

        reset(view); put(target, QStringLiteral("B"), QByteArray("B-original"), view);
        require(!ks::registry::optimization::move(source, QStringLiteral("A"), target, QStringLiteral("B"), true, context, &error), "optimization move destination exists rejected");
        require(writes == 0 && value(target, QStringLiteral("B"), view).data == "B-original", "move cannot overwrite B");
        proveView(view);

        reset(view); failDelete = true;
        require(!ks::registry::optimization::move(source, QStringLiteral("A"), target, QStringLiteral(" B "), true, context, &error), "cross-key source deletion failure reported");
        require(value(source, QStringLiteral("A"), view).exists && !value(target, QStringLiteral(" B "), view).exists, "cross-key destination rollback verified");
        proveView(view);

        reset(view); put(source, QString(), QByteArray::fromHex("0020fe00"), view);
        require(ks::registry::optimization::move(source, QString(), target, QString(), true, context, &error), "default value uses actual empty name across keys");
        require(!value(source, QString(), view).exists && value(target, QString(), view).data == QByteArray::fromHex("0020fe00"), "default raw bytes retained");
        proveView(view);

        reset(view); keys.remove(identity(target, view));
        require(ks::registry::optimization::move(source, QStringLiteral("A"), target, QStringLiteral(" B "), true, context, &error), "missing target key created by formal document plan");
        require(!value(source, QStringLiteral("A"), view).exists && value(target, QStringLiteral(" B "), view).exists, "raw whitespace value name not trimmed");
        proveView(view);

        reset(view); failDelete = true;
        require(!ks::registry::optimization::remove(source, QStringLiteral("A"), true, context, &error), "deletion failure not called success");
        require(value(source, QStringLiteral("A"), view).exists, "failed delete keeps raw original");
        proveView(view);

        reset(view); rejectCapture = true;
        require(!ks::registry::optimization::remove(source, QString(), false, context, &error), "tree capture denial stops before backup/write");
        require(writes == 0, "no tree mutation on incomplete baseline");
        proveView(view);
    }
    // 真实 Access/DocumentApply 混合计划：无事务树删除能力时，树前后的普通写入都不得开始。
    const RegistryAccessContext r0Context{0, true}; // 冻结的 R0 本机来源不能被 Win32 兜底替代。
    for (const int deletionIndex : {0, 1, 2})
    {
        reset(0);
        const RegistryValueState original = value(source, QStringLiteral("A"), 0); // 完整原始基线。
        const auto originalKeys = keys.keys(); // 捕获键集合，拒绝结果也必须没有创建父键。
        RegistryApplyOperation setValue; // 模拟在树删除前或后排队的普通值修改。
        setValue.kind = RegistryApplyOperation::Kind::SetValue;
        setValue.keyPath = source;
        setValue.valueName = QStringLiteral("A");
        setValue.beforeValue = {true, original.type, original.data};
        setValue.afterValue = {true, original.type, QByteArray("must-not-write")};
        RegistryApplyOperation createKey; // 混合计划的创建也必须被能力预检一起阻止。
        createKey.kind = RegistryApplyOperation::Kind::CreateKey;
        createKey.keyPath = source + QStringLiteral("\\MustNotCreate");
        RegistryApplyOperation deleteTree; // 即使旧共享状态机已比较原树，R0 也不能安全提交删除。
        deleteTree.kind = RegistryApplyOperation::Kind::DeleteTree;
        deleteTree.keyPath = source;
        deleteTree.keyExistedBefore = true;
        deleteTree.beforeTree.rootPath = source;
        deleteTree.beforeTree.keys.append({source, false, {}});
        deleteTree.beforeTree.values.append({source, original.name, original.type, original.data, false});
        RegistryApplyPlan plan; // 不经 UI 和真实注册表，直接执行正式计划状态机。
        plan.useR0 = true;
        plan.operations = {setValue, createKey};
        plan.operations.insert(deletionIndex, deleteTree);
        RegistryApplyResult result; // 拒绝回执保留来源，不能给出成功或自动撤销许可。
        require(!RegistryDocumentApplyService::applyAccess(plan, result), "R0 mixed plan rejected before its first write");
        require(writes == 0 && views.isEmpty() && channels.isEmpty(), "capability preflight performs zero backend calls and no fallback");
        require(keys.keys() == originalKeys && value(source, QStringLiteral("A"), 0).data == original.data,
            "all mixed-plan original keys and value bytes preserved");
        require(!result.completed && !result.canUndo && !result.canceled && result.useR0 && result.viewBits == 0,
            "rejection keeps frozen R0 receipt without claiming partial mutation");
        require(result.receipts.size() == 3 && result.error.contains(QStringLiteral("Win32"))
            && result.error.contains(QStringLiteral("R0")), "rejection explains the explicit supported source");
        for (qsizetype index = 0; index < result.receipts.size(); ++index)
        {
            const auto& receipt = result.receipts.at(index); // 仅不支持项失败，其余项保持未执行。
            require(!receipt.mutated && receipt.state == (index == deletionIndex
                ? RegistryApplyReceipt::State::Failed : RegistryApplyReceipt::State::NotRun),
                "mixed-plan receipts record zero mutation for every operation");
        }
        RegistryAccessApplyBackend directBackend(r0Context); // 绕过状态机也不能触发不安全删除。
        require(!directBackend.supportsAtomicTreeDeletion()
            && !directBackend.deleteTree(source, deleteTree.beforeTree, error), "direct R0 tree deletion fails closed");
        require(writes == 0 && views.isEmpty() && channels.isEmpty(), "direct deletion refusal performs zero backend calls");
    }
    // 正式 R0 单值写入能力继续保留；安全限制仅拒绝缺少原子条件能力的树删除。
    reset(0);
    const RegistryValueState originalR0 = value(source, QStringLiteral("A"), 0);
    RegistryApplyResult valueResult; // 单值真实回读结果与冻结 R0 来源对应。
    require(RegistryValueTransactions::apply(source, QStringLiteral("A"),
        {true, originalR0.type, originalR0.data}, {true, originalR0.type, QByteArray("R0-retained")},
        r0Context, valueResult), "supported R0 ordinary value apply remains available");
    require(writes == 1 && value(source, QStringLiteral("A"), 0).data == "R0-retained",
        "R0 value apply performs one write and reads actual bytes");
    for (const bool channel : channels) require(channel, "R0 value receipt never switches to Win32");
    std::printf("REGISTRY_OPTIMIZATION_TRANSACTIONS checks=%u failures=0 real_registry_calls=0\n", checks);
}
