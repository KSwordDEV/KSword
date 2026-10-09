#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryDocument.h"
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryDocumentApply.h"

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTemporaryDir>
#include <QtEndian>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>

namespace
{
int checks = 0;
void require(bool condition, const char* detail)
{
    ++checks;
    if (!condition) {
        std::cerr << "FAILED: " << detail << '\n';
        std::exit(1);
    }
}

void write(const QString& path, const QByteArray& bytes)
{
    QFile file(path);
    const bool opened = file.open(QIODevice::WriteOnly);
    if (!opened)
        std::cerr << path.toStdString() << ": " << file.errorString().toStdString() << '\n';
    require(opened, "open fixture file");
    require(file.write(bytes) == bytes.size(), "write fixture file");
}

QByteArray read(const QString& path)
{
    QFile file(path);
    require(file.open(QIODevice::ReadOnly), "read fixture file");
    return file.readAll();
}

QByteArray utf16(const QString& source)
{
    QByteArray bytes = QByteArray::fromHex("fffe");
    for (const QChar ch : source) {
        char unit[2] {};
        qToLittleEndian<quint16>(ch.unicode(), unit);
        bytes.append(unit, 2);
    }
    return bytes;
}

bool parseText(const QString& path, const QString& text, RegistryDocument& doc, QString& error)
{
    write(path, utf16(text));
    return RegistryDocumentService::parseRegFile(path, doc, error);
}

bool sameOperations(const RegistryDocument& a, const RegistryDocument& b)
{
    if (a.keys.size() != b.keys.size() || a.values.size() != b.values.size()
        || a.operationOrder.size() != b.operationOrder.size())
        return false;
    for (qsizetype i = 0; i < a.keys.size(); ++i) {
        if (a.keys.at(i).path != b.keys.at(i).path || a.keys.at(i).deleteTree != b.keys.at(i).deleteTree)
            return false;
    }
    for (qsizetype i = 0; i < a.values.size(); ++i) {
        const auto& av = a.values.at(i);
        const auto& bv = b.values.at(i);
        if (av.keyPath != bv.keyPath || av.name != bv.name || av.type != bv.type
            || av.data != bv.data || av.deleteValue != bv.deleteValue)
            return false;
    }
    for (qsizetype i = 0; i < a.operationOrder.size(); ++i) {
        if (a.operationOrder.at(i).kind != b.operationOrder.at(i).kind
            || a.operationOrder.at(i).index != b.operationOrder.at(i).index)
            return false;
    }
    return true;
}

class MockRegistry final : public RegistryApplyBackend
{
public:
    // 该单线程内存夹具没有外部写者，树比较与删除作为一次原子后端调用执行。
    bool supportsAtomicTreeDeletion() const override { return true; }
    RegistryDocument data;
    int writes = 0;
    int failWrite = -1;
    bool corruptReadback = false;
    bool captureFails = false;
    bool addUnexpectedChildOnDelete = false;
    std::atomic_bool* cancelAfterWrite = nullptr;
    std::atomic_bool* cancelAfterRead = nullptr;
    std::atomic_bool* cancelAfterCapture = nullptr;
    QVector<qint64> captureBudgets;

    MockRegistry()
    {
        data.keys.append({QStringLiteral("HKEY_CURRENT_USER"), false, {}});
        data.keys.append({QStringLiteral("HKEY_CURRENT_USER\\Software"), false, {}});
    }
    static bool insidePath(const QString& path, const QString& root)
    {
        return path.compare(root, Qt::CaseInsensitive) == 0
            || path.startsWith(root + QLatin1Char('\\'), Qt::CaseInsensitive);
    }
    bool keyExists(const QString& path, bool& present, QString&) override
    {
        present = false;
        for (const auto& key : data.keys)
            present = present || key.path.compare(path, Qt::CaseInsensitive) == 0;
        return true;
    }
    bool readValue(const QString& path, const QString& name, RegistryApplyValueState& state, QString& error) override
    {
        if (!failReadOnce.isEmpty() && name == failReadOnce) {
            failReadOnce.clear(); error = QStringLiteral("Mock transient read failure."); return false;
        }
        state = {};
        bool present = false;
        keyExists(path, present, error);
        if (!present) { error = QStringLiteral("Missing mock key."); return false; }
        for (const auto& value : data.values) {
            if (value.keyPath.compare(path, Qt::CaseInsensitive) == 0
                && value.name.compare(name, Qt::CaseInsensitive) == 0)
                state = {true, value.type, value.data};
        }
        if (corruptReadback && writes > 0 && state.exists)
            state.data += 'x';
        if (cancelAfterRead)
            cancelAfterRead->store(true);
        return true;
    }
    QString failReadOnce;
    bool captureTree(const QString& path, RegistryDocument& tree, QString& error) override
    {
        tree = {};
        if (captureFails) { error = QStringLiteral("Mock capture denied."); return false; }
        tree.rootPath = path;
        tree.viewBits = 32;
        for (const auto& key : data.keys) {
            if (insidePath(key.path, path))
                tree.keys.append(key);
        }
        for (const auto& value : data.values) {
            if (insidePath(value.keyPath, path))
                tree.values.append(value);
        }
        if (cancelAfterCapture)
            cancelAfterCapture->store(true);
        return !tree.keys.isEmpty();
    }
    bool captureTreeBounded(const QString& path, qint64 budget, RegistryDocument& tree, QString& error) override
    {
        captureBudgets.append(budget);
        return RegistryApplyBackend::captureTreeBounded(path, budget, tree, error);
    }
    bool mutate(QString& error)
    {
        ++writes;
        if (writes == failWrite) { error = QStringLiteral("Mock write failed."); return false; }
        if (cancelAfterWrite)
            cancelAfterWrite->store(true);
        return true;
    }
    bool createKey(const QString& path, QString& error) override
    {
        if (!mutate(error))
            return false;
        bool present = false;
        keyExists(path, present, error);
        if (present) { error = QStringLiteral("Mock key already exists."); return false; }
        const QString parent = path.left(path.lastIndexOf(QLatin1Char('\\')));
        keyExists(parent, present, error);
        if (!present) { error = QStringLiteral("Mock parent is missing."); return false; }
        data.keys.append({path, false, {}});
        return true;
    }
    bool setValue(const QString& path, const QString& name, quint32 type, const QByteArray& bytes, QString& error) override
    {
        if (!mutate(error))
            return false;
        for (auto& value : data.values) {
            if (value.keyPath.compare(path, Qt::CaseInsensitive) == 0
                && value.name.compare(name, Qt::CaseInsensitive) == 0) {
                value.type = type;
                value.data = bytes;
                return true;
            }
        }
        data.values.append({path, name, type, bytes, false});
        return true;
    }
    bool deleteValue(const QString& path, const QString& name, QString& error) override
    {
        if (!mutate(error))
            return false;
        for (qsizetype i = 0; i < data.values.size(); ++i) {
            if (data.values.at(i).keyPath.compare(path, Qt::CaseInsensitive) == 0
                && data.values.at(i).name.compare(name, Qt::CaseInsensitive) == 0) {
                data.values.removeAt(i);
                return true;
            }
        }
        error = QStringLiteral("Missing mock value.");
        return false;
    }
    bool deleteTree(const QString& path, const RegistryDocument& expectedTree, QString& error) override
    {
        if (!mutate(error))
            return false;
        if (addUnexpectedChildOnDelete)
            data.keys.append({path + QStringLiteral("\\UnexpectedAfterVerify"), false, {}});
        // 删除在独立内存快照上暂存，后续冲突时保留外部新增项并回滚全部本次删除。
        RegistryDocument staged = data;
        QVector<QString> paths;
        for (const auto& key : expectedTree.keys)
            paths.append(key.path);
        std::sort(paths.begin(), paths.end(), [](const QString& a, const QString& b) { return a.size() > b.size(); });
        for (const auto& authorized : paths) {
            for (const auto& key : staged.keys) {
                if (key.path.compare(authorized, Qt::CaseInsensitive) != 0 && insidePath(key.path, authorized)) {
                    error = QStringLiteral("Mock newly added child prevents parent deletion.");
                    return false;
                }
            }
            for (qsizetype i = staged.keys.size(); i > 0; --i) {
                if (staged.keys.at(i - 1).path.compare(authorized, Qt::CaseInsensitive) == 0)
                    staged.keys.removeAt(i - 1);
            }
            for (qsizetype i = staged.values.size(); i > 0; --i) {
                if (staged.values.at(i - 1).keyPath.compare(authorized, Qt::CaseInsensitive) == 0)
                    staged.values.removeAt(i - 1);
            }
        }
        data = std::move(staged); // 所有条件复核都通过时才一次发布原子删除结果。
        return true;
    }
};

void applyRegressions(const QString& journal)
{
    const QString root = QStringLiteral("HKEY_CURRENT_USER\\Software\\ApplyFixture");
    auto initial = [&]() {
        MockRegistry backend;
        backend.data.keys.append({root, false, {}});
        backend.data.keys.append({root + QStringLiteral("\\Empty"), false, {}});
        backend.data.values.append({root, QStringLiteral("Number"), 4, QByteArray::fromHex("01000000"), false});
        return backend;
    };
    RegistryDocument changes;
    changes.viewBits = 32;
    changes.keys.append({root, false, {}});
    changes.values.append({root, QStringLiteral("Number"), 4, QByteArray::fromHex("02000000"), false});
    changes.values.append({root, QStringLiteral("Number"), 3, QByteArray::fromHex("fe00ff"), false});
    QString error;
    auto backend = initial();
    RegistryApplyPlan plan;
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error), "read-only apply preparation");
    require(backend.writes == 0 && plan.operations.size() == 3, "preparation writes nothing and keeps repeats");
    require(plan.operations.at(1).beforeValue.data == QByteArray::fromHex("01000000")
        && plan.operations.at(2).beforeValue.data == QByteArray::fromHex("02000000"),
        "repeated values simulate the preceding operation");
    require(plan.originalSubtrees.size() == 1 && plan.originalSubtrees.first().keys.size() == 2,
        "original complete subtree retains empty child");
    RegistryApplyResult result, undone;
    require(RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "ordered apply succeeds");
    require(result.completed && result.canUndo && backend.writes == 2, "write receipts and undo availability");
    require(result.receipts.at(2).actualAfterValue.type == 3
        && result.receipts.at(2).actualAfterValue.data == QByteArray::fromHex("fe00ff"), "actual raw readback retained");
    require(RegistryDocumentApplyService::undoWithBackend(result, backend, undone), "committed repeated edits undo in reverse");
    RegistryApplyValueState actual;
    require(backend.readValue(root, QStringLiteral("Number"), actual, error)
        && actual.type == 4 && actual.data == QByteArray::fromHex("01000000"), "committed undo restores original raw value");
    require(undone.undoAttempt && !undone.canUndo && undone.pendingUndoReceipts.isEmpty(),
        "completed undo cannot be offered as another undo that redoes values");

    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error)
        && RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "undo retry repeated-value setup");
    std::atomic_bool undoCancel {false};
    backend.cancelAfterWrite = &undoCancel;
    require(!RegistryDocumentApplyService::undoWithBackend(result, backend, undone, &undoCancel)
        && undone.undoAttempt && undone.canUndo && undone.pendingUndoReceipts.size() == 1,
        "partial undo retains only original receipts still needing restoration");
    undoCancel.store(false); backend.cancelAfterWrite = nullptr;
    RegistryApplyResult retried;
    require(RegistryDocumentApplyService::undoWithBackend(undone, backend, retried), "canceled partial undo retry resumes");
    require(backend.readValue(root, QStringLiteral("Number"), actual, error)
        && actual.type == 4 && actual.data == QByteArray::fromHex("01000000"), "undo retry follows original same-value history");

    backend = initial();
    RegistryDocument twoValues;
    twoValues.viewBits = 32;
    twoValues.values.append({root, QStringLiteral("Number"), 4, QByteArray::fromHex("02000000"), false});
    twoValues.values.append({root, QStringLiteral("B"), 3, QByteArray("B1"), false});
    require(RegistryDocumentApplyService::prepareWithBackend(twoValues, backend, plan, error)
        && RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "partial undo read-failure setup");
    backend.failReadOnce = QStringLiteral("Number");
    require(!RegistryDocumentApplyService::undoWithBackend(result, backend, undone)
        && undone.canUndo && undone.pendingUndoReceipts.size() == 1, "transient failure permits only remaining undo retry");
    const int beforeRetryWrites = backend.writes;
    require(RegistryDocumentApplyService::undoWithBackend(undone, backend, retried)
        && backend.writes == beforeRetryWrites + 1, "retry never rewrites the already restored value");
    require(backend.readValue(root, QStringLiteral("B"), actual, error) && !actual.exists,
        "already undone creation stays absent after retry");
    require(backend.readValue(root, QStringLiteral("Number"), actual, error)
        && actual.data == QByteArray::fromHex("01000000"), "remaining value reaches its original data");

    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error)
        && RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "uncertain undo setup");
    backend.failWrite = backend.writes + 2;
    require(!RegistryDocumentApplyService::undoWithBackend(result, backend, undone) && !undone.canUndo,
        "failed mutating undo does not offer an unsafe retry");

    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error), "conflict prepare");
    backend.data.values.first().data = QByteArray::fromHex("09000000");
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "post-preview value conflict stops apply");
    require(backend.writes == 0 && result.receipts.at(1).state == RegistryApplyReceipt::State::Failed
        && result.receipts.at(2).state == RegistryApplyReceipt::State::NotRun, "conflict performs no writes and stops later items");

    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error), "partial failure prepare");
    backend.failWrite = 2;
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "write failure preserves partial receipt");
    require(result.receipts.at(1).state == RegistryApplyReceipt::State::Success
        && result.receipts.at(2).state == RegistryApplyReceipt::State::Failed && !result.canUndo,
        "uncertain failed mutation prevents automatic undo");
    backend.readValue(root, QStringLiteral("Number"), actual, error);
    require(actual.data == QByteArray::fromHex("02000000"), "completed earlier write remains applied");

    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error), "cancel prepare");
    std::atomic_bool cancel {true};
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result, &cancel)
        && result.canceled && backend.writes == 0, "pre-cancel writes nothing");
    cancel.store(false);
    backend.cancelAfterWrite = &cancel;
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result, &cancel)
        && result.canceled && backend.writes == 1 && result.canUndo, "cancel retains verified completed changes");
    cancel.store(false);
    backend.cancelAfterWrite = nullptr;
    require(RegistryDocumentApplyService::undoWithBackend(result, backend, undone), "canceled partial apply can undo verified items");
    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error), "read cancellation prepare");
    cancel.store(false);
    backend.cancelAfterRead = &cancel;
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result, &cancel)
        && result.canceled && backend.writes == 0, "cancellation during before-read prevents the next write");

    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error), "bad readback prepare");
    backend.corruptReadback = true;
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result) && !result.canUndo,
        "raw readback mismatch fails and prevents uncertain undo");

    backend = initial();
    RegistryDocument newKeys;
    newKeys.viewBits = 32;
    const QString deep = root + QStringLiteral("\\NewParent\\Deep");
    newKeys.keys.append({deep, false, {}});
    newKeys.values.append({deep, {}, 3, QByteArray::fromHex("0000ff"), false});
    require(RegistryDocumentApplyService::prepareWithBackend(newKeys, backend, plan, error), "missing parent creation prepare");
    require(plan.operations.size() == 3 && plan.operations.first().keyPath == root + QStringLiteral("\\NewParent"),
        "missing parent is an explicit checked operation");
    require(RegistryDocumentApplyService::applyWithBackend(plan, backend, result) && result.canUndo,
        "new nested key and value apply");
    require(RegistryDocumentApplyService::undoWithBackend(result, backend, undone), "new nested key actual undo");
    bool present = true;
    backend.keyExists(root + QStringLiteral("\\NewParent"), present, error);
    require(!present, "new parent removed after reverse value and child undo");

    backend = initial();
    const QString deleted = root + QStringLiteral("\\Old");
    backend.data.keys.append({deleted, false, {}});
    backend.data.keys.append({deleted + QStringLiteral("\\EmptyOldChild"), false, {}});
    backend.data.values.append({deleted, QStringLiteral("OldValue"), 1, QByteArray::fromHex("41000000"), false});
    RegistryDocument rebuild;
    rebuild.viewBits = 32;
    rebuild.keys.append({deleted, true, {}});
    rebuild.keys.append({deleted, false, {}});
    rebuild.values.append({deleted, QStringLiteral("NewValue"), 3, QByteArray::fromHex("feff"), false});
    rebuild.operationOrder = {{RegistryDocumentOperation::Kind::Key, 0}, {RegistryDocumentOperation::Kind::Key, 1},
        {RegistryDocumentOperation::Kind::Value, 0}};
    require(RegistryDocumentApplyService::prepareWithBackend(rebuild, backend, plan, error), "delete and rebuild source prepare");
    require(plan.operations.size() == 3 && plan.operations.at(0).beforeTree.keys.size() == 2
        && !plan.operations.at(1).keyExistedBefore && !plan.operations.at(2).beforeValue.exists,
        "delete and rebuild simulation uses post-delete empty state");
    require(RegistryDocumentApplyService::saveOriginalBackup(plan, journal, error), "original multi-segment journal save");
    require(RegistryDocumentApplyService::applyWithBackend(plan, backend, result) && !result.canUndo,
        "delete and rebuild apply avoids false full-tree undo claim");
    require(!RegistryDocumentApplyService::undoWithBackend(result, backend, undone), "tree deletion undo explicitly unavailable");
    backend.readValue(deleted, QStringLiteral("OldValue"), actual, error);
    require(!actual.exists, "deleted original value is gone before merge restore");
    RegistryDocument merge;
    require(RegistryDocumentApplyService::loadOriginalBackup(journal, merge, error) && merge.viewBits == 32,
        "original journal loads an explicit merge restore document");
    require(RegistryDocumentApplyService::prepareWithBackend(merge, backend, plan, error)
        && RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "original data merge restore");
    backend.readValue(deleted, QStringLiteral("OldValue"), actual, error);
    require(actual.exists && actual.data == QByteArray::fromHex("41000000"), "original raw value restored");
    backend.readValue(deleted, QStringLiteral("NewValue"), actual, error);
    require(actual.exists && actual.data == QByteArray::fromHex("feff"), "merge restore retains backup-external new values");
    backend.keyExists(deleted + QStringLiteral("\\EmptyOldChild"), present, error);
    require(present, "merge restore recreates original empty child");

    backend = initial();
    RegistryDocument deleteRoot;
    deleteRoot.viewBits = 32;
    deleteRoot.keys.append({root, true, {}});
    require(RegistryDocumentApplyService::prepareWithBackend(deleteRoot, backend, plan, error), "subtree conflict prepare");
    backend.data.keys.append({root + QStringLiteral("\\ExternallyAdded"), false, {}});
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result) && backend.writes == 0,
        "full subtree comparison protects externally added child");
    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(deleteRoot, backend, plan, error), "capture cancellation prepare");
    cancel.store(false);
    backend.cancelAfterCapture = &cancel;
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result, &cancel)
        && result.canceled && backend.writes == 0, "cancellation during subtree capture prevents deletion");
    backend = initial();
    require(RegistryDocumentApplyService::prepareWithBackend(deleteRoot, backend, plan, error), "fixed scope delete prepare");
    backend.addUnexpectedChildOnDelete = true;
    RegistryDocument afterConflict = backend.data; // 外部新增项保留，但授权原键和值不得因失败而部分删除。
    afterConflict.keys.append({root + QStringLiteral("\\UnexpectedAfterVerify"), false, {}});
    require(!RegistryDocumentApplyService::applyWithBackend(plan, backend, result), "new child after final comparison stops fixed-list deletion");
    backend.keyExists(root + QStringLiteral("\\UnexpectedAfterVerify"), present, error);
    require(present && result.receipts.first().state == RegistryApplyReceipt::State::Failed && !result.canUndo,
        "newly introduced child is never added to the authorized deletion list");
    require(sameOperations(backend.data, afterConflict), "atomic mock tree conflict rolls back every staged deletion");
    backend = initial();
    backend.data.values.append({root, QStringLiteral("SymbolicLinkValue"), 6, QByteArray::fromHex("41000000"), false});
    require(!RegistryDocumentApplyService::prepareWithBackend(deleteRoot, backend, plan, error)
        && plan.operations.isEmpty(), "symbolic-link subtree deletion rejected during preparation");
    backend = initial();
    backend.captureFails = true;
    require(!RegistryDocumentApplyService::prepareWithBackend(changes, backend, plan, error)
        && plan.operations.isEmpty() && backend.writes == 0, "incomplete original capture fails without writes");
    deleteRoot.keys.first().path = QStringLiteral("HKCU");
    require(!RegistryDocumentApplyService::prepareWithBackend(deleteRoot, backend, plan, error), "predefined-root deletion rejected");
    RegistryApplyPlan unsafe;
    RegistryApplyOperation unsafeOp;
    unsafeOp.kind = RegistryApplyOperation::Kind::DeleteTree;
    unsafeOp.keyPath = QStringLiteral("HKEY_CURRENT_USER");
    unsafeOp.keyExistedBefore = false;
    unsafe.operations.append(unsafeOp);
    require(!RegistryDocumentApplyService::applyWithBackend(unsafe, backend, result), "tampered root-deletion plan rejected");

    backend = initial();
    const QString sibling = QStringLiteral("HKEY_CURRENT_USER\\Software\\SiblingFixture");
    backend.data.keys.append({sibling, false, {}});
    backend.data.values.append({sibling, QStringLiteral("Old"), 3, QByteArray::fromHex("01feff00"), false});
    RegistryDocument twoRoots;
    twoRoots.viewBits = 32;
    twoRoots.keys = {{root, false, {}}, {sibling, false, {}}};
    twoRoots.values = {{root, QStringLiteral("A"), 3, QByteArray(1, 'a'), false},
        {sibling, QStringLiteral("B"), 3, QByteArray(1, 'b'), false}};
    require(RegistryDocumentApplyService::prepareWithBackend(twoRoots, backend, plan, error), "multiple original subtrees prepare");
    require(backend.captureBudgets.size() == 2 && backend.captureBudgets.at(1) == backend.captureBudgets.at(0) - 4,
        "each subsequent original capture receives the remaining total data budget");
}
} // namespace

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    // --existing-output 只复用已存在目录，适用于禁止新建临时目录的回归任务。
    std::unique_ptr<QTemporaryDir> temp;
    QString output;
    if (argc == 3 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--existing-output"))
    {
        output = QString::fromLocal8Bit(argv[2]);
        require(QDir(output).exists(), "existing output directory available");
    }
    else
    {
        temp = std::make_unique<QTemporaryDir>((argc > 1 ? QString::fromLocal8Bit(argv[1]) : QDir::tempPath())
            + QStringLiteral("/registry-document-files-XXXXXX"));
        require(temp->isValid(), "temporary files available");
        output = temp->path();
    }
    const QString reg = QDir(output).filePath(QStringLiteral("registry-review-input.reg"));
    const QString exported = QDir(output).filePath(QStringLiteral("registry-review-exported.reg"));
    const QString backupPath = QDir(output).filePath(QStringLiteral("registry-review-raw.ksreg"));
    QString error;
    RegistryDocument parsed;
    const QString header = QStringLiteral("Windows Registry Editor Version 5.00\r\n\r\n");
    const QString source = header + QStringLiteral(
        "; Comment\r\n"
        "[HKCU\\Software\\KSwordDocumentFixture]\r\n"
        "@=\"默认\\\\path\\\"quoted\\\"\"\r\n"
        "\"Dword\"=dword:ffffffff\r\n"
        "\"Zero\"=hex(0):\r\n"
        "\"Bytes\"=hex:00,01,fe,ff\r\n"
        "\"a=b\"=hex(7):41,00,00,00,\\\r\n"
        "  42,00,00,00,00,00\r\n"
        "\"RawOddSz\"=hex(1):41,00,fe\r\n"
        "\"UnknownType\"=hex(ffffffff):00,ff\r\n"
        "\"DeleteMe\"=-\r\n"
        "[-HKEY_CURRENT_USER\\Software\\KSwordDocumentFixture\\Child]\r\n"
        "[HKEY_CURRENT_USER\\Software\\KSwordDocumentFixture\\Child]\r\n"
        "\"Repeated\"=dword:1\r\n"
        "\"Repeated\"=dword:2\r\n"
        "[HKEY_LOCAL_MACHINE\\Software\\AnotherFixture]\r\n");
    require(parseText(reg, source, parsed, error), "UTF16 complex .reg parse");
    require(error.isEmpty(), "successful parse has no error");
    require(parsed.keys.size() == 4 && parsed.values.size() == 10, "all keys and values retained");
    require(parsed.operationOrder.size() == 14, "all operations retained");
    require(parsed.rootPath.isEmpty() && parsed.viewBits == 0, ".reg has no implicit root or view");
    require(parsed.values.first().name.isEmpty(), "default value raw name is empty");
    require(parsed.values.first().type == 1 && parsed.values.first().data.endsWith(QByteArray(2, '\0')),
        "quoted string encoded as null-terminated UTF16LE");
    require(parsed.values.at(1).data == QByteArray::fromHex("ffffffff"), "DWORD maximum preserved");
    require(parsed.values.at(2).data.isEmpty() && parsed.values.at(2).type == 0, "empty REG_NONE preserved");
    require(parsed.values.at(4).name == QStringLiteral("a=b")
        && parsed.values.at(4).data == QByteArray::fromHex("41000000420000000000"),
        "hex continuation with equals in value name");
    require(parsed.values.at(5).data.size() == 3, "malformed string raw bytes retained");
    require(parsed.values.at(6).type == 0xffffffffU, "unknown type preserved");
    require(parsed.values.at(7).deleteValue && parsed.keys.at(1).deleteTree, "destructive operations retained");
    require(parsed.operationOrder.at(9).kind == RegistryDocumentOperation::Kind::Key
        && parsed.operationOrder.at(9).index == 1, "key deletion has exact original order");
    require(RegistryDocumentService::saveRegFile(exported, parsed, error), "raw .reg export");
    const QByteArray exportBytes = read(exported);
    require(exportBytes.startsWith(QByteArray::fromHex("fffe")), "export is UTF16LE BOM");
    RegistryDocument roundTrip;
    require(RegistryDocumentService::parseRegFile(exported, roundTrip, error), "export can be parsed");
    require(sameOperations(parsed, roundTrip), "export round-trip preserves raw bytes and source order");

    const QString simple = header + QStringLiteral("[HKEY_CURRENT_USER\\Software\\KSwordDocumentFixture]\n@=\"é中文\"\n");
    write(reg, QByteArray::fromHex("efbbbf") + simple.toUtf8());
    require(RegistryDocumentService::parseRegFile(reg, roundTrip, error), "UTF8 BOM supported");
    const QByteArray utf8Data = roundTrip.values.first().data;
    require(parseText(reg, simple, roundTrip, error) && utf8Data == roundTrip.values.first().data,
        "UTF16 and UTF8 representations produce the same bytes");
    write(reg, simple.toUtf8());
    require(RegistryDocumentService::parseRegFile(reg, roundTrip, error), "valid unmarked UTF8 version 5 supported");
    write(reg, QByteArray("REGEDIT4\r\n\r\n[HKCU\\Software\\KSwordDocumentFixture]\r\n@=\"ANSI\"\r\n"));
    require(RegistryDocumentService::parseRegFile(reg, roundTrip, error), "REGEDIT4 ANSI supported");

    const QStringList badLines {
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=dword:100000000"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=dword:-1"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=dword:1g"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:0"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:00,"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:,00"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:00,,01"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex(z):00"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=qword:1"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=\"abc\\n\""),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=\"abc\"junk"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:00,\\"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:00,\\\n;ignored"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:00,\\\n[HKCU\\Software\\y]"),
        QStringLiteral("[HKCU\\Software\\x]\n\"v\"=hex:00 trailing"),
        QStringLiteral("[HKCU\\Software\\x]\n#unsupported"),
        QStringLiteral("[-HKCU]"),
        QStringLiteral("[-HKCU\\Software\\x]\n\"v\"=\"bad\""),
        QStringLiteral("[HKCU\\Software\\x"),
        QStringLiteral("[UNKNOWN\\x]"),
        QStringLiteral("[HKCU\\\\x]"),
        QStringLiteral("[HKCU\\x\\]"),
        QStringLiteral("@=\"missing section\""),
        QStringLiteral("[HKCU\\x]\n\"v\" missing equals"),
    };
    for (const QString& bad : badLines) {
        require(!parseText(reg, header + bad, roundTrip, error), "malformed .reg fails explicitly");
        require(!error.isEmpty() && roundTrip.keys.isEmpty() && roundTrip.values.isEmpty(),
            "failed .reg never exposes a partial document");
    }
    write(reg, QByteArray::fromHex("fffe4100ff"));
    require(!RegistryDocumentService::parseRegFile(reg, roundTrip, error), "odd UTF16 rejected");
    write(reg, QByteArray::fromHex("efbbbfff"));
    require(!RegistryDocumentService::parseRegFile(reg, roundTrip, error), "bad UTF8 BOM payload rejected");
    write(reg, QByteArray::fromHex("efbbbf") + simple.toUtf8() + QByteArray::fromHex("c3"));
    require(!RegistryDocumentService::parseRegFile(reg, roundTrip, error), "incomplete trailing UTF8 rejected");
    write(reg, utf16(simple) + QByteArray::fromHex("00d8"));
    require(!RegistryDocumentService::parseRegFile(reg, roundTrip, error), "incomplete trailing UTF16 surrogate rejected");
    write(reg, utf16(header + QStringLiteral("[HKCU\\x]\n@=\"a") + QChar(0) + QStringLiteral("b\"")));
    require(!RegistryDocumentService::parseRegFile(reg, roundTrip, error), "null text rejected");

    RegistryDocument backup;
    backup.rootPath = QStringLiteral("HKEY_CURRENT_USER\\Software\\KSwordDocumentFixture");
    backup.viewBits = 32;
    backup.keys.append({ backup.rootPath, false, {} });
    backup.keys.append({ backup.rootPath + QStringLiteral("\\EmptyChild"), false, {} });
    for (quint32 type : {0U, 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U, 10U, 11U, 0xffffffffU}) {
        RegistryDocumentValue value;
        value.keyPath = backup.rootPath;
        value.name = QStringLiteral("Type%1").arg(type);
        value.type = type;
        value.data = QByteArray::fromHex("000102feff0041000000");
        backup.values.append(value);
    }
    backup.values.append({ backup.rootPath, {}, 3, {}, false });
    // A minimal self-relative descriptor with a null DACL records unavailable
    // owner/group safely; this is metadata only and is never applied in this test.
    backup.keys.first().securityDescriptor = QByteArray::fromHex("0100048000000000000000000000000000000000");
    require(RegistryDocumentService::saveBackup(backupPath, backup, error), "complete raw backup save");
    const QByteArray originalBackup = read(backupPath);
    RegistryDocument loaded;
    require(RegistryDocumentService::loadBackup(backupPath, loaded, error), "raw backup load");
    require(loaded.viewBits == 32 && loaded.rootPath == backup.rootPath && loaded.keys.size() == 2,
        "view root and empty child retained");
    require(loaded.keys.first().securityDescriptor == backup.keys.first().securityDescriptor,
        "optional security metadata round-trip");
    require(loaded.values.size() == backup.values.size(), "all backup values retained");
    for (qsizetype i = 0; i < loaded.values.size(); ++i)
        require(loaded.values.at(i).type == backup.values.at(i).type
            && loaded.values.at(i).data == backup.values.at(i).data
            && loaded.values.at(i).name == backup.values.at(i).name, "type and raw bytes backup round-trip");
    require(RegistryDocumentService::saveRegFile(exported, loaded, error), "unordered backup grouped raw export");
    require(RegistryDocumentService::parseRegFile(exported, roundTrip, error), "unordered export parse");
    require(roundTrip.keys.size() == 2 && roundTrip.values.size() == backup.values.size(),
        "unordered export retains empty key and every value");
    for (qsizetype i = 0; i < roundTrip.values.size(); ++i)
        require(roundTrip.values.at(i).type == backup.values.at(i).type
            && roundTrip.values.at(i).data == backup.values.at(i).data,
            "all registry types export without interpreting raw bytes");

    QJsonObject json = QJsonDocument::fromJson(originalBackup).object();
    auto rejectJson = [&](const QJsonObject& invalid) {
        write(backupPath, QJsonDocument(invalid).toJson());
        require(!RegistryDocumentService::loadBackup(backupPath, loaded, error), "invalid backup rejected");
        require(!error.isEmpty() && loaded.keys.isEmpty(), "failed backup never exposes partial document");
    };
    QJsonObject invalid = json;
    invalid.insert(QStringLiteral("version"), 2);
    rejectJson(invalid);
    invalid = json;
    invalid.insert(QStringLiteral("viewBits"), 16);
    rejectJson(invalid);
    invalid = json;
    invalid.insert(QStringLiteral("keys"), QJsonArray());
    rejectJson(invalid);
    invalid = json;
    QJsonArray jsonValues = invalid.value(QStringLiteral("values")).toArray();
    QJsonObject first = jsonValues.first().toObject();
    first.insert(QStringLiteral("dataBase64"), QStringLiteral("AA=!"));
    jsonValues[0] = first;
    invalid.insert(QStringLiteral("values"), jsonValues);
    rejectJson(invalid);
    invalid = json;
    jsonValues = json.value(QStringLiteral("values")).toArray();
    first = jsonValues.first().toObject();
    first.insert(QStringLiteral("type"), 1.5);
    jsonValues[0] = first;
    invalid.insert(QStringLiteral("values"), jsonValues);
    rejectJson(invalid);
    invalid = json;
    QJsonArray jsonKeys = json.value(QStringLiteral("keys")).toArray();
    first = jsonKeys.first().toObject();
    first.insert(QStringLiteral("securityDescriptorBase64"), QStringLiteral("AA=="));
    jsonKeys[0] = first;
    invalid.insert(QStringLiteral("keys"), jsonKeys);
    rejectJson(invalid);

    write(backupPath, originalBackup);
    RegistryDocument incomplete = backup;
    incomplete.keys.append({ backup.rootPath + QStringLiteral("\\MissingParent\\Child"), false, {} });
    require(!RegistryDocumentService::saveBackup(backupPath, incomplete, error), "missing parent backup rejected");
    require(read(backupPath) == originalBackup, "validation failure preserves existing backup");
    incomplete = backup;
    incomplete.values.first().keyPath = QStringLiteral("HKEY_LOCAL_MACHINE\\Outside");
    require(!RegistryDocumentService::saveBackup(backupPath, incomplete, error), "outside root value rejected");
    incomplete = backup;
    incomplete.values.append(incomplete.values.first());
    require(!RegistryDocumentService::saveBackup(backupPath, incomplete, error), "duplicate value backup rejected");
    incomplete = backup;
    incomplete.keys.first().deleteTree = true;
    require(!RegistryDocumentService::saveBackup(backupPath, incomplete, error), "deletion in raw backup rejected");
    incomplete = backup;
    incomplete.values.first().data = QByteArray(16 * 1024 * 1024 + 1, 'x');
    require(!RegistryDocumentService::saveBackup(backupPath, incomplete, error), "oversized value rejected before save");
    incomplete = backup;
    incomplete.operationOrder.append({ RegistryDocumentOperation::Kind::Value, 0 });
    require(!RegistryDocumentService::saveRegFile(exported, incomplete, error), "incomplete operation order rejected");
    incomplete = backup;
    incomplete.values.first().name = QStringLiteral("line\nbreak");
    require(RegistryDocumentService::saveBackup(backupPath, incomplete, error), "raw backup retains newline value name");
    require(!RegistryDocumentService::saveRegFile(exported, incomplete, error),
        ".reg explicitly rejects unrepresentable newline name");
    require(!RegistryDocumentService::captureWin32(backup.rootPath, 16, loaded, error)
        && loaded.keys.isEmpty(), "bad capture view rejected before system access");
    applyRegressions(QDir(output).filePath(QStringLiteral("registry-review-originals.ksreg")));
    std::cout << "RegistryDocument file/codec regressions passed: " << checks << " checks.\n";
    return 0;
}
