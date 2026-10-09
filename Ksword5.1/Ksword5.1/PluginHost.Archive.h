#pragma once

// 插件 ZIP 共用一个有界解包器。调用方保留下载哈希、许可证、manifest 与 promotion 门禁。
// 只生成本地 PowerShell 解包命令，不请求网络，也不执行 ZIP 内任何文件。
#include <QString>
#include <QtGlobal>

namespace ks::plugin_host
{
    struct ArchiveLimits
    {
        qint64 maximumFileBytes = 1024LL * 1024 * 1024;     // 单文件展开上限。
        qint64 maximumExpandedBytes = 1024LL * 1024 * 1024; // 包的总展开上限。
        int maximumEntries = 100000;                       // 文件和目录条目总数。
        int maximumDepth = 64;                             // 每个路径的组件层数。
    };
    struct ArchiveLayout
    {
        QString expectedWrapper;             // 官方包唯一根目录，或普通包 installDirectory。
        bool allowRootPluginManifest = false; // 普通包兼容根目录 plugin.json；官方包不允许。
    };
    // archive/destination 是调用方拥有的绝对路径；目的目录由调用方创建并在失败时清理。
    // 所有 ZIP 条目先完成预检才写第一个文件，失败由进程非零退出通知原安装流程。
    // limits 可降低生产预算用于离线夹具，不可越过共享硬上限。无效参数返回空命令。
    QString buildArchiveExtractionScript(const QString& archive, const QString& destination,
        const ArchiveLayout& layout, const ArchiveLimits& limits = {});
}
