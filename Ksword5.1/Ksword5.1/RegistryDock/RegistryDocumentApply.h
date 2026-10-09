#pragma once

#include "RegistryDocument.h"
#include <QStringList>
#include <atomic>

struct RegistryValueRenameResult; // 值事务回执在专用模块定义，避免后端接口循环包含。

struct RegistryApplyValueState
{
    bool exists = false;
    quint32 type = 0;
    QByteArray data;
};

struct RegistryApplyOperation
{
    enum class Kind { CreateKey, DeleteTree, SetValue, DeleteValue };
    Kind kind = Kind::CreateKey;
    QString keyPath;
    QString valueName;
    bool keyExistedBefore = false;
    RegistryApplyValueState beforeValue;
    RegistryApplyValueState afterValue;
    RegistryDocument beforeTree;
};

struct RegistryApplyPlan
{
    int viewBits = 0;
    bool useR0 = false; // 准备时冻结的访问通道；执行和撤销禁止重新选择。
    QVector<RegistryApplyOperation> operations;
    QVector<RegistryDocument> originalSubtrees;
    QStringList originallyAbsentKeys;
};

struct RegistryApplyReceipt
{
    enum class State { NotRun, Success, Failed, Canceled };
    RegistryApplyOperation operation;
    State state = State::NotRun;
    bool mutated = false;
    RegistryApplyValueState actualAfterValue;
    RegistryDocument actualAfterTree;
    QString error;
};

struct RegistryApplyResult
{
    int viewBits = 0;
    bool useR0 = false; // 对应实际写入来源，不能用当前页面模式恢复旧回执。
    bool completed = false;
    bool canceled = false;
    // 已有子树删除需要原始备份恢复；普通自动撤销不能丢弃原 ACL 继承语义。
    bool canUndo = false;
    QString error;
    QVector<RegistryApplyReceipt> receipts;
    // 重试撤销必须继续原提交的剩余回执，不能反转已部分撤销的结果而重做旧值。
    bool undoAttempt = false;
    QVector<RegistryApplyReceipt> pendingUndoReceipts;
};

// 文档编解码与状态机的可注入边界；实现保留原类型/原字节，禁止跟随注册表链接。
class RegistryApplyBackend
{
public:
    virtual ~RegistryApplyBackend() = default;
    virtual bool keyExists(const QString& path, bool& exists, QString& error) = 0;
    virtual bool readValue(const QString& path, const QString& name, RegistryApplyValueState& value, QString& error) = 0;
    virtual bool captureTree(const QString& path, RegistryDocument& tree, QString& error) = 0;
    virtual bool captureTreeBounded(const QString& path, qint64 maximumDataBytes,
        RegistryDocument& tree, QString& error);
    virtual bool createKey(const QString& path, QString& error) = 0;
    virtual bool setValue(const QString& path, const QString& name, quint32 type, const QByteArray& data, QString& error) = 0;
    virtual bool deleteValue(const QString& path, const QString& name, QString& error) = 0;
    virtual bool deleteTree(const QString& path, const RegistryDocument& expectedTree, QString& error) = 0;
    // 树删除必须将原树比较与删除绑定到同一事务；普通按路径删除默认没有此能力。
    virtual bool supportsAtomicTreeDeletion() const { return false; }
    // 只有真实事务后端可以移动值；普通读写后端不得伪装成原子能力。
    virtual bool supportsAtomicValueMove() const { return false; }
    virtual bool moveValueAtomic(const QString&, const QString&, const QString&, const QString&,
        const RegistryApplyValueState&, RegistryValueRenameResult&, QString& error)
    {
        error = QStringLiteral("This registry backend does not support atomic value moves.");
        return false;
    }
};

class RegistryDocumentApplyService final
{
public:
    // 输入文档及已冻结通道，输出同来源计划；R0 不伪造 Win32 ACL 元数据。
    static bool prepareAccess(const RegistryDocument& document, bool useR0,
        RegistryApplyPlan& plan, QString& error);
    // 输入准备好的计划/原回执，始终使用其中保存的视图和通道执行或恢复。
    static bool applyAccess(const RegistryApplyPlan& plan, RegistryApplyResult& result,
        const std::atomic_bool* canceledToken = nullptr);
    static bool undoAccess(const RegistryApplyResult& previous, RegistryApplyResult& result,
        const std::atomic_bool* canceledToken = nullptr);
    // Win32 原值、目的缺失、目标创建与删除在同一个 KTM 事务内，冲突不覆盖外部数据。
    static bool moveValueWin32(const QString& sourcePath, const QString& oldName,
        const QString& destinationPath, const QString& newName, const RegistryApplyValueState& expected,
        int viewBits, RegistryValueRenameResult& result);
    // 只读准备计划，宿主沿既有确认策略展示后才执行；合并恢复保留计划外数据。
    static bool prepareWin32(const RegistryDocument& document, RegistryApplyPlan& plan, QString& error);
    static bool applyWin32(const RegistryApplyPlan& plan, RegistryApplyResult& result,
        const std::atomic_bool* canceledToken = nullptr);
    static bool undoWin32(const RegistryApplyResult& previous, RegistryApplyResult& result,
        const std::atomic_bool* canceledToken = nullptr);
    // 备份保存完整原子树和原先缺失的键元数据；加载生成合并恢复，不删除新增数据。
    static bool saveOriginalBackup(const RegistryApplyPlan& plan, const QString& path, QString& error);
    static bool loadOriginalBackup(const QString& path, RegistryDocument& mergeDocument, QString& error);

    static bool prepareWithBackend(const RegistryDocument& document, RegistryApplyBackend& backend,
        RegistryApplyPlan& plan, QString& error);
    static bool applyWithBackend(const RegistryApplyPlan& plan, RegistryApplyBackend& backend,
        RegistryApplyResult& result, const std::atomic_bool* canceledToken = nullptr);
    static bool undoWithBackend(const RegistryApplyResult& previous, RegistryApplyBackend& backend,
        RegistryApplyResult& result, const std::atomic_bool* canceledToken = nullptr);
};
