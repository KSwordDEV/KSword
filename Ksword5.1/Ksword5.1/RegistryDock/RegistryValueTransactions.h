#pragma once

#include "RegistryDocumentApply.h"
#include "RegistryWorkbenchAccess.h"

// 值重命名回执：返回失败时仍需显示是否已修改或已恢复，不能只用一个 bool 猜测。
struct RegistryValueRenameResult
{
    enum class State { Rejected, Renamed, Restored, Conflict, Unverified };
    State state = State::Rejected; // 已证实的最终状态，默认没有开始写入。
    bool committed = false; // KTM 已提交才为 true；回读失败也不能隐藏已永久提交的事实。
    bool originalVerified = false; // 原名的实际回读成功且完整。
    bool destinationVerified = false; // 新名的实际回读成功且完整。
    RegistryApplyValueState actualOriginal; // 最新实际原名状态。
    RegistryApplyValueState actualDestination; // 最新实际目标状态。
    QString error; // 原始失败及恢复失败的合并诊断。
};

// 共享值事务入口：复用文档状态机的写前比对和回读；名称始终是原始注册表名称。
class RegistryValueTransactions final
{
public:
    // expected 在打开模态框前捕获；Win32 同事务提交/回滚，R0 能力不足时零写入拒绝。
    static bool rename(const QString& path, const QString& oldName, const QString& newName,
        const RegistryApplyValueState& expected, const RegistryAccessContext& context,
        RegistryValueRenameResult& result);
    // 注入同一后端以离线验证冲突/失败恢复，不使用真实注册表或剪贴板。
    static bool renameWithBackend(const QString& path, const QString& oldName, const QString& newName,
        const RegistryApplyValueState& expected, RegistryApplyBackend& backend,
        RegistryValueRenameResult& result);
    // 优化配置的跨键移动也保留同一视图；默认值仍用空名，目的存在时拒绝覆盖。
    static bool move(const QString& sourcePath, const QString& oldName,
        const QString& destinationPath, const QString& newName,
        const RegistryApplyValueState& expected, const RegistryAccessContext& context,
        RegistryValueRenameResult& result);
    static bool moveWithBackend(const QString& sourcePath, const QString& oldName,
        const QString& destinationPath, const QString& newName,
        const RegistryApplyValueState& expected, RegistryApplyBackend& backend,
        RegistryValueRenameResult& result);
    // 提交单值修改/删除，输入不可变 before/after；实际回执来自共用 DocumentApply。
    static bool apply(const QString& path, const QString& name,
        const RegistryApplyValueState& before, const RegistryApplyValueState& after,
        const RegistryAccessContext& context, RegistryApplyResult& result,
        const std::atomic_bool* canceledToken = nullptr);
};
