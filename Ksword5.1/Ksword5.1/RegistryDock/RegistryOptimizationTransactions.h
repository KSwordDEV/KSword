#pragma once

#include "RegistryWorkbenchAccess.h"

// 优化配置明确指定 Win32 本机/32 位视图；不借用注册表编辑页的当前 R0/视图选择。
namespace ks::registry::optimization
{
// 写入、删除与移动均复用正式事务状态机，error 包含实际回读或恢复失败。
bool write(const QString& path, const QString& name, quint32 type, const QByteArray& bytes,
    const RegistryValueState& expected, const RegistryAccessContext& context, QString* error);
bool remove(const QString& path, const QString& name, bool isValue,
    const RegistryAccessContext& context, QString* error);
bool move(const QString& source, const QString& oldName, const QString& target,
    const QString& newName, bool isValue, const RegistryAccessContext& context, QString* error);
}
