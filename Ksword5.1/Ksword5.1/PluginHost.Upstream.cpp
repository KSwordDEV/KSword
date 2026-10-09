#include "PluginHost.Upstream.h"
#include "PluginHost.Archive.h"
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QLockFile>
#include <QProcess>
#include <QSaveFile>
#include <QStandardPaths>
#include <QTimer>
#include <QUuid>
#include <algorithm>
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace ks::plugin_host
{
    UpstreamAssetInstaller::UpstreamAssetInstaller(QObject* parent, Translator translator)
        : QObject(parent), m_translator(std::move(translator))
    {
        m_network = new QNetworkAccessManager(this);
        m_deadline = new QTimer(this);
        m_deadline->setSingleShot(true);
        connect(m_deadline, &QTimer::timeout, this, [this]() {
            if (m_active) finish(false, text(QStringLiteral("上游插件安装超时。")));
        });
    }
    UpstreamAssetInstaller::~UpstreamAssetInstaller()
    {
        m_active = false;
        m_completion = {};
        stopOperations();
        cleanupStage();
    }
    QString UpstreamAssetInstaller::text(const QString& source) const
    {
        return m_translator ? m_translator(source) : source;
    }
    void UpstreamAssetInstaller::start(const QString& pluginRoot, const UpstreamPlan& plan,
        Validator validator, Progress progress, Completion completion)
    {
        if (!m_active) m_allowLocalTestAssets = false;
        begin(pluginRoot, plan, std::move(validator), std::move(progress), std::move(completion));
    }
#ifdef KSWORD_PLUGIN_INSTALL_TESTING
    void UpstreamAssetInstaller::startForTests(const QString& pluginRoot,
        const UpstreamPlan& plan, Validator validator, Progress progress, Completion completion)
    {
        if (!m_active) m_allowLocalTestAssets = true;
        begin(pluginRoot, plan, std::move(validator), std::move(progress), std::move(completion));
    }
#endif
    void UpstreamAssetInstaller::begin(const QString& pluginRoot,
        const UpstreamPlan& plan, Validator validator, Progress progress, Completion completion)
    {
        if (m_active)
        {
            if (completion) completion(false, {}, text(QStringLiteral("上游插件安装已在进行。")));
            return;
        }
        m_progress = std::move(progress);
        m_completion = std::move(completion);
        // 生产入口以原始 JSON 重新验证计划，拒绝调用方绕过 URL、路径或预算校验。
        m_plan = plan;
        QString planError;
        if (!m_allowLocalTestAssets && !parseUpstreamDistribution(plan.description, plan.id, &m_plan, &planError))
        {
            m_active = true;
            finish(false, planError);
            return;
        }
        m_validator = std::move(validator);
        m_assets = m_plan.assets;
        for (const auto& file : m_plan.metadata)
        {
            // 小型元数据只保存原始字节；不解压，不执行。
            m_assets.append({file.path, file.url, file.sha256, {}, file.path, file.maxBytes, {}});
        }
        m_assetIndex = 0;
        ++m_operationGeneration;
        m_active = true;
        if (m_plan.assets.isEmpty() || m_plan.assets.size() > 8 || !m_validator || !QDir().mkpath(pluginRoot))
        {
            finish(false, text(QStringLiteral("无法创建上游插件安装目录。")));
            return;
        }
        m_pluginRoot = QFileInfo(pluginRoot).canonicalFilePath();
        if (m_pluginRoot.isEmpty()) { finish(false, text(QStringLiteral("插件目录无法规范化。"))); return; }
        m_installLock = std::make_unique<QLockFile>(QDir(m_pluginRoot).filePath(QStringLiteral(".ksword-plugin-install-%1.lock").arg(m_plan.id)));
        m_installLock->setStaleLockTime(0);
        if (!m_installLock->tryLock(0))
        {
            finish(false, text(QStringLiteral("另一个窗口正在安装此上游插件。")));
            return;
        }
        m_stage = QDir(m_pluginRoot).filePath(QStringLiteral(".ksword-plugin-stage-%1-%2")
            .arg(m_plan.id, QUuid::createUuid().toString(QUuid::WithoutBraces)));
        if (!QDir().mkpath(QDir(m_stage).filePath(QStringLiteral(".archives"))))
        {
            finish(false, text(QStringLiteral("无法创建上游插件安装暂存目录。")));
            return;
        }
        m_deadline->start(30 * 60 * 1000);
        downloadNext();
    }
    bool UpstreamAssetInstaller::report(const QString& stage, const int percent)
    {
        const QPointer<UpstreamAssetInstaller> self(this);
        const auto generation = m_operationGeneration;
        const auto progress = m_progress;
        if (m_active && progress) progress(stage, std::clamp(percent, 0, 100));
        return self && m_active && generation == m_operationGeneration;
    }
    bool UpstreamAssetInstaller::trustedRedirect(const QUrl& url) const
    {
        if (m_allowLocalTestAssets && url.isLocalFile()) return true;
        // 初始 URL 在计划解析时绑定仓库；后续只允许该 URL 或 GitHub 的 Release CDN。
        return approvedUpstreamRedirect(url, m_assets[m_assetIndex].url);
    }
    void UpstreamAssetInstaller::downloadNext()
    {
        if (!m_active) return;
        if (m_assetIndex >= m_assets.size())
        {
            QString error;
            if (!report(text(QStringLiteral("正在验证上游插件清单和完整文件")), 95)) return;
            // 所有资源验哈希后才写生成清单；使用 NewOnly 拒绝载荷预埋同名文件。
            const auto writeJson = [this](const QString& name, const QJsonObject& object) {
                QFile file(QDir(m_stage).filePath(name));
                const auto bytes = QJsonDocument(object).toJson();
                return file.open(QIODevice::WriteOnly | QIODevice::NewOnly) &&
                    file.write(bytes) == bytes.size() && file.flush();
            };
            if (!writeJson(QStringLiteral("plugin.json"), m_plan.manifest) ||
                !writeJson(QStringLiteral("upstream-install.json"), m_plan.description) ||
                !m_validator(m_stage, &error))
            {
                finish(false, error.isEmpty() ? text(QStringLiteral("上游插件清单或运行环境验证失败。")) : error);
                return;
            }
            finish(true, {});
            return;
        }
        const auto& asset = m_assets[m_assetIndex];
        if (!trustedRedirect(asset.url) || !validUpstreamSha256(asset.sha256) || asset.maxArchiveBytes <= 0)
        {
            finish(false, text(QStringLiteral("上游插件下载配置不合法。")));
            return;
        }
        m_archivePath = QDir(m_stage).filePath(QStringLiteral(".archives/download-%1.zip").arg(m_assetIndex));
        m_archive = std::make_unique<QSaveFile>(m_archivePath);
        if (!m_archive->open(QIODevice::WriteOnly))
        {
            finish(false, text(QStringLiteral("无法创建运行环境下载文件：%1")).arg(m_archive->errorString()));
            return;
        }
        m_digest = std::make_unique<QCryptographicHash>(QCryptographicHash::Sha256);
        m_received = 0;
        m_redirectCount = 0;
        m_downloadError.clear();
        if (!report(text(QStringLiteral("正在下载 %1")).arg(asset.name), m_assetIndex * 90 / m_assets.size())) return;
        openDownload(asset.url);
    }
    void UpstreamAssetInstaller::openDownload(const QUrl& url)
    {
        QNetworkRequest request(url);
        request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
        request.setTransferTimeout(60000);
        request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("KSword-UpstreamAssets/1"));
        m_reply = m_network->get(request);
        auto* reply = m_reply.data();
        reply->setReadBufferSize(256 * 1024);
        connect(reply, &QNetworkReply::readyRead, this, [this, reply]() {
            if (m_active && reply == m_reply) consumeReply();
        });
        connect(reply, &QNetworkReply::downloadProgress, this, [this, reply](qint64 received, qint64 total) {
            if (!m_active || reply != m_reply) return;
            if (total > m_assets[m_assetIndex].maxArchiveBytes)
            {
                m_downloadError = text(QStringLiteral("官方运行环境包超过下载大小限制。"));
                reply->abort();
                return;
            }
            const int part = total > 0 ? static_cast<int>(std::min<qint64>(35, received * 35 / total)) : 0;
            report(text(QStringLiteral("正在下载 %1（%2 MiB）")).arg(m_assets[m_assetIndex].name)
                .arg(received / (1024.0 * 1024.0), 0, 'f', 1), (m_assetIndex * 90 + part * 2) / m_assets.size());
        });
        connect(reply, &QNetworkReply::finished, this, [this, reply]() {
            if (!m_active || reply != m_reply) return;
            const auto redirect = reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl();
            if (!redirect.isEmpty())
            {
                const auto target = reply->url().resolved(redirect);
                reply->deleteLater();
                m_reply.clear();
                if (!trustedRedirect(target) || ++m_redirectCount > 5)
                {
                    finish(false, text(QStringLiteral("官方运行环境下载跳转不被允许。")));
                    return;
                }
                openDownload(target);
                return;
            }
            const QPointer<UpstreamAssetInstaller> self(this);
            consumeReply();
            if (!self || !m_active || reply != m_reply) return;
            const bool ok = m_downloadError.isEmpty() && reply->error() == QNetworkReply::NoError;
            const auto error = !m_downloadError.isEmpty() ? m_downloadError : reply->errorString();
            reply->deleteLater();
            m_reply.clear();
            if (!ok || m_received == 0)
            {
                finish(false, text(QStringLiteral("上游插件资源下载失败：%1")).arg(error));
                return;
            }
            const auto digest = QString::fromLatin1(m_digest->result().toHex());
            if (digest.compare(m_assets[m_assetIndex].sha256, Qt::CaseInsensitive) != 0)
            {
                finish(false, text(QStringLiteral("运行环境 SHA-256 校验失败，已拒绝安装。")));
                return;
            }
            if (!m_archive->commit())
            {
                finish(false, text(QStringLiteral("无法保存已验证的运行环境包：%1")).arg(m_archive->errorString()));
                return;
            }
            m_archive.reset();
            m_digest.reset();
            extractArchive();
        });
    }
    void UpstreamAssetInstaller::consumeReply()
    {
        if (!m_reply || !m_archive || !m_downloadError.isEmpty()) return;
        // Redirect response bodies are not part of the pinned ZIP digest.
        if (!m_reply->attribute(QNetworkRequest::RedirectionTargetAttribute).toUrl().isEmpty())
        {
            m_reply->readAll();
            return;
        }
        while (m_reply->bytesAvailable() > 0)
        {
            const auto bytes = m_reply->read(256 * 1024);
            if (bytes.isEmpty()) break;
            if (bytes.size() > m_assets[m_assetIndex].maxArchiveBytes - m_received)
            {
                m_downloadError = text(QStringLiteral("运行环境下载超过大小限制。"));
                m_reply->abort();
                return;
            }
            if (m_archive->write(bytes) != bytes.size())
            {
                m_downloadError = text(QStringLiteral("无法写入运行环境暂存文件：%1")).arg(m_archive->errorString());
                m_reply->abort();
                return;
            }
            m_digest->addData(bytes);
            m_received += bytes.size();
        }
    }
    void UpstreamAssetInstaller::extractArchive()
    {
        // 元数据资源不交给解压器，校验后的文件原子移动到计划声明的落点。
        if (m_assetIndex >= m_plan.assets.size())
        {
            const auto target = QDir(m_stage).filePath(m_assets[m_assetIndex].destinationDirectory);
            if (!QDir().mkpath(QFileInfo(target).absolutePath()) || !QFile::rename(m_archivePath, target))
            {
                finish(false, text(QStringLiteral("无法保存已验证的上游插件元数据。")));
                return;
            }
            ++m_assetIndex;
            downloadNext();
            return;
        }
        auto powerShell = QStandardPaths::findExecutable(QStringLiteral("pwsh.exe"));
        if (powerShell.isEmpty()) powerShell = QStandardPaths::findExecutable(QStringLiteral("powershell.exe"));
        if (powerShell.isEmpty()) { finish(false, text(QStringLiteral("未找到 PowerShell，无法解压上游插件。"))); return; }
        const auto destination = QDir(m_stage).filePath(m_assets[m_assetIndex].destinationDirectory);
        if (!QDir().mkpath(destination)) { finish(false, text(QStringLiteral("无法创建运行环境解压目录。"))); return; }
        if (!report(text(QStringLiteral("正在安全解压 %1")).arg(m_assets[m_assetIndex].name), (m_assetIndex * 90 + 76) / m_assets.size())) return;
        const auto command = buildArchiveExtractionScript(m_archivePath, destination,
            ArchiveLayout{m_assets[m_assetIndex].rootDirectory, false},
            ArchiveLimits{1024LL * 1024 * 1024,
                std::min<qint64>(4LL * 1024 * 1024 * 1024, m_assets[m_assetIndex].maxArchiveBytes * 4), 100000, 64});
        if (command.isEmpty())
        {
            finish(false, text(QStringLiteral("运行环境解压失败：%1")).arg(QStringLiteral("archive_policy_invalid")));
            return;
        }
        auto* process = new QProcess(this);
        m_extractor = process;
        process->setProgram(powerShell);
        process->setProcessChannelMode(QProcess::SeparateChannels);
        process->setArguments({QStringLiteral("-NoLogo"), QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"),
            QStringLiteral("-Command"), command});
#ifdef Q_OS_WIN
        process->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) { args->flags |= CREATE_NO_WINDOW; });
#endif
        connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError error) {
            if (m_active && process == m_extractor && error == QProcess::FailedToStart)
                finish(false, text(QStringLiteral("无法启动运行环境解压器：%1")).arg(process->errorString()));
        });
        connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this, process](int code, QProcess::ExitStatus status) {
                if (!m_active || process != m_extractor) return;
                const auto details = QString::fromLocal8Bit(process->readAllStandardError().right(64 * 1024)).trimmed();
                m_extractor.clear();
                process->deleteLater();
                QFile::remove(m_archivePath);
                if (status != QProcess::NormalExit || code != 0)
                {
                    finish(false, text(QStringLiteral("运行环境解压失败：%1")).arg(details));
                    return;
                }
                ++m_assetIndex;
                downloadNext();
            });
        process->start();
    }
    void UpstreamAssetInstaller::stopOperations()
    {
        m_deadline->stop();
        if (m_reply)
        {
            disconnect(m_reply, nullptr, this, nullptr);
            m_reply->abort();
            m_reply->deleteLater();
            m_reply.clear();
        }
        if (m_extractor)
        {
            disconnect(m_extractor, nullptr, this, nullptr);
            m_extractor->kill();
            m_extractor->waitForFinished(5000);
            m_extractor->deleteLater();
            m_extractor.clear();
        }
        m_archive.reset();
        m_digest.reset();
    }
    void UpstreamAssetInstaller::cleanupStage()
    {
        if (m_stage.isEmpty() || m_pluginRoot.isEmpty()) return;
        const auto root = QFileInfo(m_pluginRoot).canonicalFilePath();
        const auto stage = QFileInfo(m_stage).canonicalFilePath();
        const auto prefix = QDir::cleanPath(root) + QLatin1Char('/');
        if (!root.isEmpty() && !stage.isEmpty() && stage.startsWith(prefix, Qt::CaseInsensitive) &&
            QFileInfo(m_stage).fileName().startsWith(QStringLiteral(".ksword-plugin-stage-%1-").arg(m_plan.id)) &&
            !QFileInfo(m_stage).isSymLink()) QDir(stage).removeRecursively();
        m_stage.clear();
    }
    void UpstreamAssetInstaller::finish(const bool success, const QString& error)
    {
        if (!m_active) return;
        m_active = false;
        stopOperations();
        auto completion = std::move(m_completion);
        m_progress = {};
        QString preparedStage;
        if (success)
        {
            preparedStage = m_stage;
            m_stage.clear(); // caller owns the verified stage and its promotion
        }
        else { cleanupStage(); m_installLock.reset(); }
        if (completion) completion(success, preparedStage, error);
    }
    void UpstreamAssetInstaller::cancel()
    {
        if (m_active) finish(false, text(QStringLiteral("上游插件安装已取消。")));
    }
}
