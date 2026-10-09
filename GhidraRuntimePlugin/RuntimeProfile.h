#pragma once

#include <QByteArray>
#include <QJsonObject>
#include <QList>
#include <QString>
#include <QUrl>

namespace ks::plugin_host::ghidra_runtime
{
    struct RuntimeAsset
    {
        QString name;
        QUrl url;
        QString sha256;
        QString rootDirectory;
        QString destinationDirectory;
        qint64 maxArchiveBytes = 0;
    };

    // 离线构包的参考配置；生产下载使用市场的 upstream-assets 分发计划。
    QList<RuntimeAsset> assets();
    QJsonObject manifest();
    // 读取已安装目录内的清单；调用方先通过 validateDirectory 验证该目录。
    QJsonObject installedManifest(const QString& pluginDirectory);
    QJsonObject assetDescription();
    QByteArray licenseText();
    QByteArray noticeText();
    // Creates only new metadata files in the caller-owned staging directory.
    bool writePackageMetadata(const QString& pluginDirectory, QString* error = nullptr);
    // Validates an extracted package without executing Java/Ghidra or samples.
    bool validateDirectory(const QString& pluginDirectory, QString* error = nullptr);
}
