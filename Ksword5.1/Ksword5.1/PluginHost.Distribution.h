#pragma once

#include <QJsonObject>
#include <QList>
#include <QString>
#include <QUrl>

namespace ks::plugin_host
{
    // 上游 ZIP 的固定身份、完整目录映射及下载预算；不提供安装脚本。
    struct UpstreamAsset
    {
        QString name;                 // 下载进度中展示的组件名。
        QUrl url;                     // 指定仓库、标签、文件的 GitHub Release URL。
        QString sha256;               // 整个 ZIP 文件的 SHA-256。
        QString rootDirectory;        // ZIP 中唯一的顶层目录。
        QString destinationDirectory; // 在插件目录内保留完整 ZIP 的落点。
        qint64 maxArchiveBytes = 0;    // 最大压缩文件大小。
        QString repository;           // 发布者仓库 owner/name，必须与 URL 一致。
    };

    // 许可证和说明等小型文本也固定哈希，不参与程序执行。
    struct UpstreamMetadata
    {
        QString path;              // 插件目录内的相对文件路径。
        QUrl url;                  // 原始文本的 GitHub raw URL。
        QString sha256;            // 原始字节的 SHA-256。
        qint64 maxBytes = 0;        // 小型元数据下载预算。
    };

    // 经过解析的分发计划；description 原样作为本地安装回执保存。
    struct UpstreamPlan
    {
        QString id;                        // 与市场 id 和安装目录一致。
        QJsonObject manifest;              // 在安装完成前生成的 plugin.json。
        QList<UpstreamAsset> assets;        // 同一事务中的全部官方 ZIP。
        QList<UpstreamMetadata> metadata;   // 固定哈希的许可和说明。
        QJsonObject description;           // 已验证的 distribution JSON。
    };

    // 输入 JSON 与市场 id；成功输出计划，失败输出稳定错误码；不联网、不写文件。
    bool parseUpstreamDistribution(const QJsonObject& object, const QString& id,
        UpstreamPlan* plan, QString* error);
    // 验证 Windows 相对路径、SHA 与初始/重定向 URL，供解析器及下载器共同调用。
    bool safeUpstreamPath(const QString& path);
    bool validUpstreamSha256(const QString& digest);
    bool approvedUpstreamRedirect(const QUrl& url, const QUrl& original);
}
