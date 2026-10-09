#pragma once

#include "PluginHost.Distribution.h"
#include <QObject>
#include <QPointer>
#include <functional>
#include <memory>

class QCryptographicHash;
class QNetworkAccessManager;
class QNetworkReply;
class QLockFile;
class QProcess;
class QSaveFile;
class QTimer;

namespace ks::plugin_host
{
    // 上游分发安装器：逐项下载并验哈希，完整解压到私有暂存区。
    // 输入已验证的计划和宿主清单验证函数；输出待事务推广的完整目录。
    // 不执行 Java、插件入口或任何远程安装脚本。
    class UpstreamAssetInstaller final : public QObject
    {
    public:
        using Progress = std::function<void(const QString&, int)>;
        using Completion = std::function<void(bool, const QString&, const QString&)>;
        using Validator = std::function<bool(const QString&, QString*)>;
        using Translator = std::function<QString(const QString&)>;
        explicit UpstreamAssetInstaller(QObject* parent = nullptr, Translator translator = {});
        ~UpstreamAssetInstaller() override;
        void start(const QString& pluginRoot, const UpstreamPlan& plan, Validator validator,
            Progress progress, Completion completion);
        void cancel();
#ifdef KSWORD_PLUGIN_INSTALL_TESTING
        // 仅测试构建允许本地夹具 URL；生产构建始终重新解析市场分发计划。
        void startForTests(const QString& pluginRoot,
            const UpstreamPlan& plan, Validator validator, Progress progress, Completion completion);
#endif
    private:
        void begin(const QString& pluginRoot, const UpstreamPlan& plan, Validator validator,
            Progress progress, Completion completion);
        void downloadNext();
        void openDownload(const QUrl& url);
        void consumeReply();
        void extractArchive();
        void finish(bool success, const QString& error);
        void stopOperations();
        void cleanupStage();
        bool report(const QString& stage, int percent);
        bool trustedRedirect(const QUrl& url) const;
        QString text(const QString& source) const;
        QNetworkAccessManager* m_network = nullptr;
        QPointer<QNetworkReply> m_reply;
        QPointer<QProcess> m_extractor;
        QTimer* m_deadline = nullptr;
        std::unique_ptr<QSaveFile> m_archive;
        std::unique_ptr<QCryptographicHash> m_digest;
        std::unique_ptr<QLockFile> m_installLock;
        QList<UpstreamAsset> m_assets; // ZIP 与小型元数据共用流式下载队列。
        UpstreamPlan m_plan; // 用于生成清单与安装回执。
        Validator m_validator; // 宿主提供的结构校验，不运行插件。
        QString m_pluginRoot;
        QString m_stage;
        QString m_archivePath;
        QString m_downloadError;
        Progress m_progress;
        Completion m_completion;
        Translator m_translator;
        qint64 m_received = 0;
        int m_assetIndex = 0;
        int m_redirectCount = 0;
        quint64 m_operationGeneration = 0;
        bool m_active = false;
        bool m_allowLocalTestAssets = false;
    };
}
