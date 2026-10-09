#pragma once

// 注册表应用内部共用校验：纯状态机与 Win32 后端共享边界，避免规则副本漂移。
#include "RegistryDocumentApply.h"

namespace ks::registry::apply_detail
{
// 操作、备份和原始数据预算，预览与执行入口使用相同上限。
inline constexpr qsizetype kOperationLimit = 300000;
inline constexpr qint64 kJournalLimit = 192LL * 1024 * 1024;
inline constexpr qint64 kPlanDataLimit = 128LL * 1024 * 1024;

// 将 message 写入 error，返回 false 供调用方停止操作。
inline bool failure(QString& error, const QString& message)
{
    error = message;
    return false;
}
// 输入原名称，返回不区分大小写的索引；实际目标名称仍保持原文。
inline QString folded(const QString& text)
{
    return text.toCaseFolded();
}
// 输入路径与授权根，返回路径是否严格位于该根自身或其子树。
inline bool inside(const QString& path, const QString& root)
{
    return path.compare(root, Qt::CaseInsensitive) == 0
        || path.startsWith(root + QLatin1Char('\\'), Qt::CaseInsensitive);
}

// 输入源路径，校验根、UTF-16、深度与组件长度，输出全名路径及失败原因。
// 保留组件空格和大小写，不转换用户的原始目标。
inline bool pathCanonical(const QString& source, QString& path, QString& error)
{
    const QString original = source;
    const QStringList roots { QStringLiteral("HKEY_CLASSES_ROOT"), QStringLiteral("HKEY_CURRENT_USER"),
        QStringLiteral("HKEY_LOCAL_MACHINE"), QStringLiteral("HKEY_USERS"), QStringLiteral("HKEY_CURRENT_CONFIG") };
    const QStringList aliases { QStringLiteral("HKCR"), QStringLiteral("HKCU"), QStringLiteral("HKLM"),
        QStringLiteral("HKU"), QStringLiteral("HKCC") };
    if (source.isEmpty() || source.size() > 32767 || !source.isValidUtf16()
        || source.contains(QChar(0)) || source.endsWith(QLatin1Char('\\')))
        return failure(error, QStringLiteral("Invalid registry change path."));
    const qsizetype slash = original.indexOf(QLatin1Char('\\'));
    const QString root = slash < 0 ? original : original.left(slash);
    int rootIndex = -1;
    for (int i = 0; i < roots.size(); ++i) {
        if (root.compare(roots.at(i), Qt::CaseInsensitive) == 0
            || root.compare(aliases.at(i), Qt::CaseInsensitive) == 0)
            rootIndex = i;
    }
    if (rootIndex < 0)
        return failure(error, QStringLiteral("Unsupported registry change root."));
    path = roots.at(rootIndex);
    if (slash >= 0) {
        const QStringList components = original.mid(slash + 1).split(QLatin1Char('\\'));
        if (components.size() > 256)
            return failure(error, QStringLiteral("Registry change path exceeds the depth limit."));
        for (const QString& component : components) {
            if (component.isEmpty() || component.size() > 255)
                return failure(error, QStringLiteral("Invalid registry change key component."));
        }
        path += QLatin1Char('\\') + original.mid(slash + 1);
    }
    return true;
}

// 输入完整路径，返回父键；预定义根没有父键，返回空字符串。
inline QString parentPath(const QString& path)
{
    const qsizetype slash = path.lastIndexOf(QLatin1Char('\\'));
    return slash < 0 ? QString() : path.left(slash);
}

// 比较存在状态、原始类型和全部字节；缺失值不比较无意义字段。
inline bool sameValue(const RegistryApplyValueState& a, const RegistryApplyValueState& b)
{
    return a.exists == b.exists && (!a.exists || (a.type == b.type && a.data == b.data));
}

// 检查捕获树中的 REG_LINK 标记；写入和删除不得沿注册表符号链接下探。
inline bool hasLink(const RegistryDocument& tree)
{
    for (const auto& value : tree.values) {
        if (value.type == 6 && value.name.compare(QStringLiteral("SymbolicLinkValue"), Qt::CaseInsensitive) == 0)
            return true;
    }
    return false;
}

} // namespace ks::registry::apply_detail
