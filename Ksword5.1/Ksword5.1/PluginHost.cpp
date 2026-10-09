#include "PluginHost.h"
#include "PluginHost.Upstream.h"
#include "../../GhidraRuntimePlugin/RuntimeProfile.h"
#include "UI/CodeTextEdit.h"
#include "UI/VisibleTableWidget.h"

#include "theme.h"
#include "Internationalization/LanguageManager.h"
#include "ksword/log/log.h"

#include <QAbstractItemView>
#include <QBrush>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QEvent>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QMenu>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QPlainTextEdit>
#include <QProcess>
#include "UI/X64DbgNavigation.h"
#include <QProcessEnvironment>
#include <QProgressBar>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSaveFile>
#include <QSettings>
#include <QShowEvent>
#include <QSizePolicy>
#include <QStandardPaths>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QTextDocument>
#include <QTimer>
#include <QUrl>
#include <QVersionNumber>
#include <QUuid>
#include <QVBoxLayout>
#include <QWidget>

#include <functional>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include "../../DebuggerBackend/KswordPluginTheme.h"

namespace
{
    constexpr qint64 kMaxManifestBytes = 64 * 1024;
    constexpr qint64 kMaxMarketplaceArchiveBytes = 256LL * 1024LL * 1024LL;
    constexpr int kMaxVisualizationColumns = 8;
    constexpr int kMaxVisualizationSummaryItems = 8;
    constexpr int kMaxVisualizationRows = 10000;
    constexpr int kMaxBufferedStdoutBytes = 1024 * 1024;
    constexpr char kMarketplaceCatalogUrl[] = "https://raw.githubusercontent.com/KSwordDEV/Plugins/main/catalog.json";

    struct VisualizationValueStyle
    {
        QString label;
        QString tone;
    };

    struct VisualizationField
    {
        QString field;
        QString label;
        QString format;
        QHash<QString, VisualizationValueStyle> valueStyles;
    };

    struct PluginVisualization
    {
        bool enabled = false;
        QString type;
        QString title;
        QString startEvent;
        QString resultEvent;
        QString completeEvent;
        QString totalField;
        QList<VisualizationField> columns;
        QList<VisualizationField> summary;
    };

    struct PluginTabPresentation
    {
        bool enabled = false;
        QString command;
        QString title;
        QString readyEvent;
        int startupTimeoutMs = 15000;
    };

    struct PluginDescriptor
    {
        QString id;
        QString name;
        QString version;
        QString description;
        QString pluginType = QStringLiteral("command");
        QString runtime;
        QString entrypointPath;
        QString defaultCommand;
        QString pluginDirectory;
        QStringList targets;
        PluginVisualization visualization;
        PluginTabPresentation tabPresentation;
    };

    struct PluginListResult
    {
        QList<PluginDescriptor> plugins;
        QString pluginRoot;
        QStringList ignoredManifests;
    };

    struct MarketplacePlugin
    {
        QString id;
        QString name;
        QString version;
        QString description;
        QStringList targets;
        QString installDirectory;
        QUrl archiveUrl;
        QString sha256;
        QString licenseName;
        QUrl licenseUrl;
        bool upstreamAssets = false; // 分发方式独立于插件运行方式。
        ks::plugin_host::UpstreamPlan upstreamPlan; // 市场维护的完整安装事务。
    };

    enum class MarketplaceUpdateState
    {
        NotInstalled,
        Current,
        Available,
        NotComparable,
    };

    MarketplaceUpdateState marketplaceUpdateState(
        const QString& installedVersion,
        const QString& marketplaceVersion)
    {
        if (installedVersion.isEmpty())
        {
            return MarketplaceUpdateState::NotInstalled;
        }

        qsizetype installedSuffix = 0;
        qsizetype marketplaceSuffix = 0;
        const QVersionNumber installed = QVersionNumber::fromString(installedVersion.trimmed(), &installedSuffix);
        const QVersionNumber marketplace = QVersionNumber::fromString(marketplaceVersion.trimmed(), &marketplaceSuffix);
        if (installed.segments().isEmpty() || marketplace.segments().isEmpty() ||
            installedSuffix != installedVersion.trimmed().size() ||
            marketplaceSuffix != marketplaceVersion.trimmed().size())
        {
            return MarketplaceUpdateState::NotComparable;
        }
        return QVersionNumber::compare(marketplace, installed) > 0
            ? MarketplaceUpdateState::Available
            : MarketplaceUpdateState::Current;
    }

    QString marketplaceLicenseAcceptanceKey(const MarketplacePlugin& plugin)
    {
        return QStringLiteral("PluginMarketplace/AcceptedLicenses/%1").arg(plugin.id);
    }

    QString marketplaceLicenseFingerprint(
        const MarketplacePlugin& plugin,
        const QByteArray& licensePayload)
    {
        // 许可证正文哈希参与接受指纹，同一 URL 的内容变化也会强制重新确认。
        const QString contentSha256 = QString::fromLatin1(
            QCryptographicHash::hash(
                licensePayload,
                QCryptographicHash::Sha256).toHex());
        return plugin.licenseName
            + QChar('\n')
            + plugin.licenseUrl.toString(QUrl::FullyEncoded)
            + QChar('\n')
            + contentSha256;
    }

    bool isValidPluginId(const QString& id)
    {
        if (id.isEmpty() || id.size() > 64 || id.front() == QChar('-') || id.back() == QChar('-'))
        {
            return false;
        }
        for (const QChar character : id)
        {
            const bool lower = character >= QChar('a') && character <= QChar('z');
            const bool digit = character >= QChar('0') && character <= QChar('9');
            if (!lower && !digit && character != QChar('-'))
            {
                return false;
            }
        }
        return true;
    }

    bool isSafeRelativePath(const QString& value)
    {
        if (value.isEmpty() || value.size() > 240 || QDir::isAbsolutePath(value) || value.contains(QChar(':')))
        {
            return false;
        }
        QString normalized = value;
        normalized.replace(QChar('\\'), QChar('/'));
        const QStringList components = normalized.split(QChar('/'), Qt::SkipEmptyParts);
        if (components.isEmpty())
        {
            return false;
        }
        for (const QString& component : components)
        {
            if (component == QStringLiteral(".") || component == QStringLiteral(".."))
            {
                return false;
            }
        }
        return !value.startsWith(QChar('/')) && !value.startsWith(QChar('\\'));
    }

    bool isSafeCommandToken(const QString& value)
    {
        return !value.isEmpty() && value.size() <= 64 &&
            !value.contains(QChar('/')) && !value.contains(QChar('\\')) &&
            !value.contains(QChar(':')) && value != QStringLiteral(".") && value != QStringLiteral("..");
    }

    QString findPluginRoot()
    {
        const QString configuredRoot = qEnvironmentVariable("KSWORD_PLUGIN_ROOT").trimmed();
        if (!configuredRoot.isEmpty() && QDir(configuredRoot).exists())
        {
            return QDir(configuredRoot).absolutePath();
        }

        const QString currentCandidate = QDir::current().filePath(QStringLiteral("plugin"));
        if (QDir(currentCandidate).exists())
        {
            return QDir(currentCandidate).absolutePath();
        }

        QDir searchDirectory(QCoreApplication::applicationDirPath());
        for (int depth = 0; depth < 7; ++depth)
        {
            const QString candidate = searchDirectory.filePath(QStringLiteral("plugin"));
            if (QDir(candidate).exists())
            {
                return QDir(candidate).absolutePath();
            }
            if (!searchDirectory.cdUp())
            {
                break;
            }
        }
        return {};
    }

    QString resolvePluginInstallRoot()
    {
        const QString configuredRoot = qEnvironmentVariable("KSWORD_PLUGIN_ROOT").trimmed();
        if (!configuredRoot.isEmpty())
        {
            return QDir(configuredRoot).absolutePath();
        }

        const QString existingRoot = findPluginRoot();
        if (!existingRoot.isEmpty())
        {
            return existingRoot;
        }

        // 新安装的发行版尚未拥有 plugin\ 目录时，首个商城插件安装到主程序旁边。
        return QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("plugin"));
    }

    QString quotePowerShellLiteral(const QString& value)
    {
        QString escaped = value;
        escaped.replace(QChar('\''), QStringLiteral("''"));
        return QChar('\'') + escaped + QChar('\'');
    }

    bool readRequiredString(const QJsonObject& object, const char* key, QString* valueOut, QString* errorOut)
    {
        const QString value = object.value(QLatin1String(key)).toString().trimmed();
        if (value.isEmpty())
        {
            *errorOut = QStringLiteral("缺少或无效的清单字符串字段：%1").arg(QLatin1String(key));
            return false;
        }
        *valueOut = value;
        return true;
    }

    bool isValidProtocolName(const QString& value)
    {
        static const QRegularExpression pattern(QStringLiteral("^[A-Za-z_][A-Za-z0-9_.-]{0,63}$"));
        return pattern.match(value).hasMatch();
    }

    bool isAllowedVisualizationFormat(const QString& format)
    {
        return format == QStringLiteral("text") ||
            format == QStringLiteral("path") ||
            format == QStringLiteral("percent") ||
            format == QStringLiteral("integer") ||
            format == QStringLiteral("number") ||
            format == QStringLiteral("badge");
    }

    bool isAllowedVisualizationTone(const QString& tone)
    {
        return tone == QStringLiteral("success") ||
            tone == QStringLiteral("danger") ||
            tone == QStringLiteral("warning") ||
            tone == QStringLiteral("info") ||
            tone == QStringLiteral("muted");
    }

    bool parseVisualizationField(
        const QJsonValue& value,
        VisualizationField* fieldOut,
        QString* errorOut)
    {
        if (fieldOut == nullptr || errorOut == nullptr || !value.isObject())
        {
            if (errorOut != nullptr) *errorOut = QStringLiteral("visualization 字段定义必须是对象。");
            return false;
        }

        const QJsonObject object = value.toObject();
        VisualizationField field;
        if (!readRequiredString(object, "field", &field.field, errorOut) ||
            !readRequiredString(object, "label", &field.label, errorOut) ||
            !readRequiredString(object, "format", &field.format, errorOut))
        {
            return false;
        }
        field.format = field.format.toLower();
        if (!isValidProtocolName(field.field) || field.label.size() > 64 ||
            !isAllowedVisualizationFormat(field.format))
        {
            *errorOut = QStringLiteral("visualization 字段名、标签或 format 不合法。");
            return false;
        }

        const QJsonValue valuesValue = object.value(QStringLiteral("values"));
        if (!valuesValue.isUndefined())
        {
            if (field.format != QStringLiteral("badge") || !valuesValue.isObject())
            {
                *errorOut = QStringLiteral("visualization.values 仅允许用于 badge，且必须是对象。");
                return false;
            }
            const QJsonObject values = valuesValue.toObject();
            if (values.size() > 32)
            {
                *errorOut = QStringLiteral("visualization.values 最多允许 32 个映射。");
                return false;
            }
            for (auto iterator = values.constBegin(); iterator != values.constEnd(); ++iterator)
            {
                if (!isValidProtocolName(iterator.key()) || !iterator.value().isObject())
                {
                    *errorOut = QStringLiteral("visualization.values 的键或值不合法。");
                    return false;
                }
                VisualizationValueStyle style;
                const QJsonObject styleObject = iterator.value().toObject();
                if (!readRequiredString(styleObject, "label", &style.label, errorOut) ||
                    !readRequiredString(styleObject, "tone", &style.tone, errorOut))
                {
                    return false;
                }
                style.tone = style.tone.toLower();
                if (style.label.size() > 64 || !isAllowedVisualizationTone(style.tone))
                {
                    *errorOut = QStringLiteral("visualization.values 的 label 或 tone 不合法。");
                    return false;
                }
                field.valueStyles.insert(iterator.key(), style);
            }
        }
        if (field.format == QStringLiteral("badge") && field.valueStyles.isEmpty())
        {
            *errorOut = QStringLiteral("badge 字段必须提供非空 values 映射。");
            return false;
        }

        *fieldOut = field;
        return true;
    }

    bool parseVisualization(
        const QJsonObject& manifest,
        PluginVisualization* visualizationOut,
        QString* errorOut)
    {
        if (visualizationOut == nullptr || errorOut == nullptr)
        {
            return false;
        }

        *visualizationOut = {};
        const QJsonValue visualizationValue = manifest.value(QStringLiteral("visualization"));
        if (visualizationValue.isUndefined())
        {
            return true;
        }
        if (!visualizationValue.isObject())
        {
            *errorOut = QStringLiteral("visualization 必须是对象。");
            return false;
        }

        const QJsonObject object = visualizationValue.toObject();
        PluginVisualization visualization;
        if (!readRequiredString(object, "type", &visualization.type, errorOut) ||
            !readRequiredString(object, "title", &visualization.title, errorOut) ||
            !readRequiredString(object, "start_event", &visualization.startEvent, errorOut) ||
            !readRequiredString(object, "result_event", &visualization.resultEvent, errorOut) ||
            !readRequiredString(object, "complete_event", &visualization.completeEvent, errorOut) ||
            !readRequiredString(object, "total_field", &visualization.totalField, errorOut))
        {
            return false;
        }
        visualization.type = visualization.type.toLower();
        if (visualization.type != QStringLiteral("scan-table") ||
            visualization.title.size() > 96 ||
            !isValidProtocolName(visualization.startEvent) ||
            !isValidProtocolName(visualization.resultEvent) ||
            !isValidProtocolName(visualization.completeEvent) ||
            !isValidProtocolName(visualization.totalField))
        {
            *errorOut = QStringLiteral("visualization 的类型、标题、事件名或 total_field 不合法。");
            return false;
        }

        const QJsonArray columns = object.value(QStringLiteral("columns")).toArray();
        if (columns.isEmpty() || columns.size() > kMaxVisualizationColumns)
        {
            *errorOut = QStringLiteral("scan-table 必须定义 1 到 %1 个 columns。").arg(kMaxVisualizationColumns);
            return false;
        }
        QStringList columnNames;
        for (const QJsonValue& columnValue : columns)
        {
            VisualizationField field;
            if (!parseVisualizationField(columnValue, &field, errorOut))
            {
                return false;
            }
            if (columnNames.contains(field.field))
            {
                *errorOut = QStringLiteral("visualization.columns 不能包含重复 field。");
                return false;
            }
            columnNames.push_back(field.field);
            visualization.columns.push_back(field);
        }

        const QJsonValue summaryValue = object.value(QStringLiteral("summary"));
        if (!summaryValue.isUndefined())
        {
            if (!summaryValue.isArray() || summaryValue.toArray().size() > kMaxVisualizationSummaryItems)
            {
                *errorOut = QStringLiteral("visualization.summary 必须是数组，且最多 %1 项。")
                    .arg(kMaxVisualizationSummaryItems);
                return false;
            }
            QStringList summaryNames;
            for (const QJsonValue& summaryFieldValue : summaryValue.toArray())
            {
                VisualizationField field;
                if (!parseVisualizationField(summaryFieldValue, &field, errorOut))
                {
                    return false;
                }
                if (summaryNames.contains(field.field))
                {
                    *errorOut = QStringLiteral("visualization.summary 不能包含重复 field。");
                    return false;
                }
                summaryNames.push_back(field.field);
                visualization.summary.push_back(field);
            }
        }

        visualization.enabled = true;
        *visualizationOut = visualization;
        return true;
    }

    bool parseTabPresentation(
        const QJsonObject& manifest,
        const QString& pluginType,
        const QString& defaultCommand,
        PluginTabPresentation* presentationOut,
        QString* errorOut)
    {
        if (presentationOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        *presentationOut = {};
        const QJsonValue tabValue = manifest.value(QStringLiteral("tab"));
        const bool supportsTab = pluginType == QStringLiteral("tab") ||
            pluginType == QStringLiteral("hybrid");
        if (!supportsTab)
        {
            if (!tabValue.isUndefined())
            {
                *errorOut = QStringLiteral("tab 配置只允许用于 plugin_type=tab 或 hybrid 的插件。");
                return false;
            }
            return true;
        }
        if (!tabValue.isObject())
        {
            *errorOut = QStringLiteral("Tab 型插件必须提供 tab 配置对象。");
            return false;
        }

        const QJsonObject tabObject = tabValue.toObject();
        PluginTabPresentation presentation;
        presentation.command = tabObject.value(QStringLiteral("command")).toString().trimmed();
        if (presentation.command.isEmpty())
        {
            presentation.command = defaultCommand;
        }
        if (!readRequiredString(tabObject, "title", &presentation.title, errorOut) ||
            !readRequiredString(tabObject, "ready_event", &presentation.readyEvent, errorOut))
        {
            return false;
        }
        if (!isSafeCommandToken(presentation.command))
        {
            *errorOut = QStringLiteral("tab.command 不合法。");
            return false;
        }
        if (presentation.title.size() > 96 || !isValidProtocolName(presentation.readyEvent))
        {
            *errorOut = QStringLiteral("tab.title 或 tab.ready_event 不合法。");
            return false;
        }
        const QJsonValue timeoutValue = tabObject.value(QStringLiteral("startup_timeout_ms"));
        if (!timeoutValue.isUndefined())
        {
            const int timeoutMs = timeoutValue.toInt(-1);
            if (!timeoutValue.isDouble() || timeoutMs < 1000 || timeoutMs > 60000)
            {
                *errorOut = QStringLiteral("tab.startup_timeout_ms 必须介于 1000 与 60000 毫秒之间。");
                return false;
            }
            presentation.startupTimeoutMs = timeoutMs;
        }
        presentation.enabled = true;
        *presentationOut = presentation;
        return true;
    }

    bool isApprovedMarketplaceUrl(const QUrl& url)
    {
        return url.isValid() && url.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) == 0 &&
            url.host().compare(QStringLiteral("raw.githubusercontent.com"), Qt::CaseInsensitive) == 0 &&
            url.userInfo().isEmpty() && (url.port(-1) == -1 || url.port() == 443) &&
            !url.hasQuery() && !url.hasFragment();
    }

    QString networkReplyErrorText(QNetworkReply* reply)
    {
        const int httpStatus = reply != nullptr
            ? reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()
            : 0;
        const QString networkError = reply != nullptr ? reply->errorString() : QStringLiteral("未知网络错误");
        return httpStatus > 0
            ? QStringLiteral("HTTP %1：%2").arg(httpStatus).arg(networkError)
            : networkError;
    }

    bool parseMarketplacePlugin(const QJsonObject& object, MarketplacePlugin* pluginOut, QString* errorOut)
    {
        if (pluginOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        MarketplacePlugin plugin;
        QString archiveUrlText;
        QString licenseUrlText;
        if (!readRequiredString(object, "id", &plugin.id, errorOut) ||
            !readRequiredString(object, "name", &plugin.name, errorOut) ||
            !readRequiredString(object, "version", &plugin.version, errorOut) ||
            !readRequiredString(object, "description", &plugin.description, errorOut) ||
            !readRequiredString(object, "install_directory", &plugin.installDirectory, errorOut) ||
            !readRequiredString(object, "license_name", &plugin.licenseName, errorOut) ||
            !readRequiredString(object, "license_url", &licenseUrlText, errorOut))
        {
            return false;
        }
        if (!isValidPluginId(plugin.id) || !isValidPluginId(plugin.installDirectory))
        {
            *errorOut = QStringLiteral("商城条目的 id 或 install_directory 不合法。");
            return false;
        }
        plugin.licenseUrl = QUrl(licenseUrlText);
        if (!isApprovedMarketplaceUrl(plugin.licenseUrl))
        {
            *errorOut = QStringLiteral("商城仅接受 raw.githubusercontent.com 的 HTTPS 下载地址。");
            return false;
        }
        // 未声明 distribution 的旧条目保持 ZIP 分发；新条目按协议解析多资源计划。
        if (object.contains(QStringLiteral("distribution")))
        {
            plugin.upstreamAssets = true;
            if (!ks::plugin_host::parseUpstreamDistribution(object.value(QStringLiteral("distribution")).toObject(),
                    plugin.id, &plugin.upstreamPlan, errorOut) || plugin.installDirectory != plugin.id)
            {
                if (errorOut->isEmpty()) *errorOut = QStringLiteral("上游插件安装目录必须与 id 一致。");
                return false;
            }
            const auto& manifest = plugin.upstreamPlan.manifest;
            if (manifest.value(QStringLiteral("version")).toString() != plugin.version ||
                manifest.value(QStringLiteral("name")).toString() != plugin.name ||
                manifest.value(QStringLiteral("description")).toString() != plugin.description ||
                manifest.value(QStringLiteral("targets")) != object.value(QStringLiteral("targets")))
            {
                *errorOut = QStringLiteral("上游分发清单与商城元数据不一致。");
                return false;
            }
            // 许可证正文必须正是计划中的哈希固定文件，不能展示另一份文本后安装。
            bool licenseMatches = false;
            for (const auto& file : plugin.upstreamPlan.metadata)
            {
                if (file.path == manifest.value(QStringLiteral("license")).toString() && file.url == plugin.licenseUrl)
                    licenseMatches = true;
            }
            if (!licenseMatches)
            {
                *errorOut = QStringLiteral("上游插件许可证 URL 与分发计划不一致。");
                return false;
            }
        }
        else
        {
            if (!readRequiredString(object, "archive_url", &archiveUrlText, errorOut) ||
                !readRequiredString(object, "sha256", &plugin.sha256, errorOut)) return false;
            plugin.archiveUrl = QUrl(archiveUrlText);
            if (!isApprovedMarketplaceUrl(plugin.archiveUrl) || !ks::plugin_host::validUpstreamSha256(plugin.sha256))
            {
                *errorOut = QStringLiteral("商城 ZIP 下载地址或 SHA-256 不合法。");
                return false;
            }
        }
        const QJsonArray targetValues = object.value(QStringLiteral("targets")).toArray();
        for (const QJsonValue& value : targetValues)
        {
            const QString target = value.toString().trimmed().toLower();
            if ((target == QStringLiteral("file") || target == QStringLiteral("process") ||
                target == QStringLiteral("network") || target == QStringLiteral("tab") ||
                (plugin.upstreamAssets && target == QStringLiteral("decompiler"))) &&
                !plugin.targets.contains(target))
            {
                plugin.targets.push_back(target);
            }
        }
        if (plugin.targets.isEmpty())
        {
            *errorOut = QStringLiteral("商城条目的 targets 不包含受支持的插件能力。");
            return false;
        }
        *pluginOut = plugin;
        return true;
    }

    bool loadPluginManifestDirectory(
        const QString& pluginDirectory,
        const QString& pluginId,
        PluginDescriptor* descriptorOut,
        QString* errorOut)
    {
        if (descriptorOut == nullptr || errorOut == nullptr || !isValidPluginId(pluginId))
        {
            if (errorOut != nullptr)
            {
                *errorOut = QStringLiteral("插件 ID 只能包含小写字母、数字和连字符。");
            }
            return false;
        }

        const QFileInfo manifestInfo(QDir(pluginDirectory).filePath(QStringLiteral("plugin.json")));
        if (!manifestInfo.isFile() || manifestInfo.size() > kMaxManifestBytes)
        {
            *errorOut = QStringLiteral("缺少 plugin.json，或其大小超过 64 KiB。");
            return false;
        }

        QFile manifestFile(manifestInfo.absoluteFilePath());
        if (!manifestFile.open(QIODevice::ReadOnly))
        {
            *errorOut = QStringLiteral("无法读取 plugin.json：%1").arg(manifestFile.errorString());
            return false;
        }
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(manifestFile.readAll(), &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            *errorOut = QStringLiteral("plugin.json 不是有效 JSON：%1").arg(parseError.errorString());
            return false;
        }

        const QJsonObject object = document.object();
        if (object.value(QStringLiteral("ksword_plugin_api")).toString() != QStringLiteral("1"))
        {
            *errorOut = QStringLiteral("不支持的 ksword_plugin_api；当前仅支持 \"1\"。");
            return false;
        }

        PluginDescriptor descriptor;
        QString entrypoint;
        if (!readRequiredString(object, "id", &descriptor.id, errorOut) ||
            !readRequiredString(object, "name", &descriptor.name, errorOut) ||
            !readRequiredString(object, "version", &descriptor.version, errorOut) ||
            !readRequiredString(object, "description", &descriptor.description, errorOut) ||
            !readRequiredString(object, "runtime", &descriptor.runtime, errorOut))
        {
            return false;
        }
        descriptor.pluginType = object.value(QStringLiteral("plugin_type")).toString(QStringLiteral("command")).trimmed().toLower();
        if (descriptor.id == QStringLiteral("ghidra") && descriptor.pluginType != QStringLiteral("backend"))
        {
            *errorOut = QStringLiteral("Ghidra 插件只能声明 backend 类型。");
            return false;
        }
        if (descriptor.pluginType == QStringLiteral("backend"))
        {
            // A managed runtime is visible to the manager but has no command,
            // file/process/network target, native Tab, or entrypoint dispatch.
            if (pluginId != QStringLiteral("ghidra") || descriptor.id != pluginId ||
                !ks::plugin_host::ghidra_runtime::validateDirectory(pluginDirectory, errorOut))
            {
                if (errorOut->isEmpty()) *errorOut = QStringLiteral("Ghidra 后端插件清单或运行环境无效。");
                return false;
            }
            descriptor.pluginDirectory = QDir(pluginDirectory).absolutePath();
            descriptor.targets = QStringList{QStringLiteral("decompiler")};
            *descriptorOut = descriptor;
            return true;
        }
        if (!readRequiredString(object, "entrypoint", &entrypoint, errorOut) ||
            !readRequiredString(object, "default_command", &descriptor.defaultCommand, errorOut)) return false;
        if (descriptor.pluginType != QStringLiteral("command") &&
            descriptor.pluginType != QStringLiteral("tab") &&
            descriptor.pluginType != QStringLiteral("hybrid"))
        {
            *errorOut = QStringLiteral("plugin_type 只能是 command、tab、hybrid 或受支持的 backend。");
            return false;
        }
        if (descriptor.id != pluginId || !isValidPluginId(descriptor.id))
        {
            *errorOut = QStringLiteral("清单 id 必须与插件目录名完全一致。");
            return false;
        }
        if (descriptor.runtime != QStringLiteral("python") && descriptor.runtime != QStringLiteral("executable"))
        {
            *errorOut = QStringLiteral("runtime 只能是 python 或 executable。");
            return false;
        }
        if (!isSafeRelativePath(entrypoint) || !isSafeCommandToken(descriptor.defaultCommand))
        {
            *errorOut = QStringLiteral("entrypoint 或 default_command 含有不安全路径/令牌。");
            return false;
        }

        const QJsonArray targets = object.value(QStringLiteral("targets")).toArray();
        for (const QJsonValue& target : targets)
        {
            const QString targetText = target.toString().trimmed().toLower();
            const bool commandTarget =
                targetText == QStringLiteral("file") ||
                targetText == QStringLiteral("process") ||
                targetText == QStringLiteral("network");
            const bool allowedTarget = descriptor.pluginType == QStringLiteral("tab")
                ? targetText == QStringLiteral("tab")
                : descriptor.pluginType == QStringLiteral("hybrid")
                    ? commandTarget || targetText == QStringLiteral("tab")
                    : commandTarget;
            if (!allowedTarget)
            {
                *errorOut = descriptor.pluginType == QStringLiteral("tab")
                    ? QStringLiteral("Tab 型插件的 targets 只能包含 tab。")
                    : descriptor.pluginType == QStringLiteral("hybrid")
                        ? QStringLiteral("Hybrid 型插件的 targets 只能包含 file、process、network 和/或 tab。")
                        : QStringLiteral("命令型插件的 targets 只能包含 file、process 和/或 network。");
                return false;
            }
            if (!descriptor.targets.contains(targetText))
            {
                descriptor.targets.push_back(targetText);
            }
        }
        if (descriptor.targets.isEmpty())
        {
            *errorOut = descriptor.pluginType == QStringLiteral("tab")
                ? QStringLiteral("Tab 型插件的 targets 必须包含 tab。")
                : QStringLiteral("targets 必须包含 file、process 和/或 network。");
            return false;
        }
        if (descriptor.pluginType == QStringLiteral("hybrid"))
        {
            const bool hasCommandTarget =
                descriptor.targets.contains(QStringLiteral("file")) ||
                descriptor.targets.contains(QStringLiteral("process")) ||
                descriptor.targets.contains(QStringLiteral("network"));
            if (!descriptor.targets.contains(QStringLiteral("tab")) || !hasCommandTarget)
            {
                *errorOut = QStringLiteral("Hybrid 型插件的 targets 必须包含 tab 和至少一个命令目标。");
                return false;
            }
        }
        if (!parseVisualization(object, &descriptor.visualization, errorOut))
        {
            return false;
        }
        if (!parseTabPresentation(
                object,
                descriptor.pluginType,
                descriptor.defaultCommand,
                &descriptor.tabPresentation,
                errorOut))
        {
            return false;
        }
        if (descriptor.pluginType == QStringLiteral("tab") && descriptor.visualization.enabled)
        {
            *errorOut = QStringLiteral("Tab 型插件不能同时声明 scan-table visualization。");
            return false;
        }

        descriptor.pluginDirectory = QDir(pluginDirectory).absolutePath();
        descriptor.entrypointPath = QDir(descriptor.pluginDirectory).filePath(entrypoint);
        if (!QFileInfo(descriptor.entrypointPath).isFile())
        {
            *errorOut = QStringLiteral("入口文件不存在：%1").arg(entrypoint);
            return false;
        }
        *descriptorOut = descriptor;
        return true;
    }

    bool loadPluginManifest(
        const QString& pluginRoot,
        const QString& pluginId,
        PluginDescriptor* descriptorOut,
        QString* errorOut)
    {
        return loadPluginManifestDirectory(
            QDir(pluginRoot).filePath(pluginId), pluginId, descriptorOut, errorOut);
    }

    bool discoverPlugins(PluginListResult* resultOut, QString* errorOut)
    {
        if (resultOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        *resultOut = {};
        *errorOut = {};
        const QString pluginRoot = findPluginRoot();
        if (pluginRoot.isEmpty())
        {
            *errorOut = QStringLiteral("找不到 plugin 目录。请在程序目录部署 plugin\\，或设置 KSWORD_PLUGIN_ROOT。");
            return false;
        }

        const QDir rootDirectory(pluginRoot);
        const QStringList directoryNames = rootDirectory.entryList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Name);
        for (const QString& pluginId : directoryNames)
        {
            if (!isValidPluginId(pluginId))
            {
                continue;
            }
            PluginDescriptor descriptor;
            QString manifestError;
            if (loadPluginManifest(pluginRoot, pluginId, &descriptor, &manifestError))
            {
                resultOut->plugins.push_back(descriptor);
            }
            else if (QFileInfo(rootDirectory.filePath(pluginId + QStringLiteral("/plugin.json"))).isFile())
            {
                resultOut->ignoredManifests.push_back(QStringLiteral("%1：%2").arg(pluginId, manifestError));
            }
        }
        resultOut->pluginRoot = pluginRoot;
        return true;
    }

    QString targetName(const ks::plugin_host::TargetKind targetKind)
    {
        switch (targetKind)
        {
        case ks::plugin_host::TargetKind::File: return QStringLiteral("file");
        case ks::plugin_host::TargetKind::Process: return QStringLiteral("process");
        case ks::plugin_host::TargetKind::Network: return QStringLiteral("network");
        }
        return QString();
    }

    bool isUsableContext(const ks::plugin_host::InvocationContext& context, QString* errorOut)
    {
        if (context.targetKind == ks::plugin_host::TargetKind::File)
        {
            if (QFileInfo(context.filePath).isFile())
            {
                return true;
            }
            *errorOut = QStringLiteral("插件入口仅支持单个常规文件。");
            return false;
        }
        if (context.targetKind == ks::plugin_host::TargetKind::Network)
        {
            return true;
        }
        if (context.processId != 0)
        {
            return true;
        }
        *errorOut = QStringLiteral("当前进程没有有效 PID，不能交给插件。");
        return false;
    }

    bool buildPluginCommand(
        const PluginDescriptor& descriptor,
        const ks::plugin_host::InvocationContext& context,
        QString* programOut,
        QStringList* argumentsOut,
        QString* errorOut)
    {
        if (programOut == nullptr || argumentsOut == nullptr || errorOut == nullptr)
        {
            return false;
        }
        QStringList arguments;
        if (descriptor.runtime == QStringLiteral("python"))
        {
            QString python = qEnvironmentVariable("KSWORD_PLUGIN_PYTHON").trimmed();
            bool usePythonLauncher = false;
            if (!python.isEmpty() && !QFileInfo(python).isFile())
            {
                *errorOut = QStringLiteral("KSWORD_PLUGIN_PYTHON 未指向有效文件：%1").arg(python);
                return false;
            }
            if (python.isEmpty())
            {
                python = QStandardPaths::findExecutable(QStringLiteral("python.exe"));
            }
            if (python.isEmpty())
            {
                python = QStandardPaths::findExecutable(QStringLiteral("py.exe"));
                usePythonLauncher = !python.isEmpty();
            }
            if (python.isEmpty())
            {
                *errorOut = QStringLiteral("找不到 Python 运行时；请安装 python.exe/py.exe 或设置 KSWORD_PLUGIN_PYTHON。");
                return false;
            }
            *programOut = python;
            if (usePythonLauncher)
            {
                arguments << QStringLiteral("-3");
            }
            arguments << descriptor.entrypointPath;
        }
        else
        {
            *programOut = descriptor.entrypointPath;
        }

        arguments << QStringLiteral("--ksword-plugin") << descriptor.defaultCommand << QStringLiteral("--")
                  << QStringLiteral("--target-kind") << targetName(context.targetKind);
        if (context.targetKind == ks::plugin_host::TargetKind::File)
        {
            arguments << QStringLiteral("--path") << context.filePath;
        }
        else if (context.targetKind == ks::plugin_host::TargetKind::Process)
        {
            arguments << QStringLiteral("--pid") << QString::number(context.processId);
            if (!context.filePath.trimmed().isEmpty())
            {
                arguments << QStringLiteral("--path") << context.filePath;
            }
            if (!context.processName.trimmed().isEmpty())
            {
                arguments << QStringLiteral("--process-name") << context.processName;
            }
        }
        *argumentsOut = arguments;
        return true;
    }

    bool buildTabPluginCommand(
        const PluginDescriptor& descriptor,
        const WId parentWindowId,
        QString* programOut,
        QStringList* argumentsOut,
        QString* errorOut)
    {
        if (programOut == nullptr || argumentsOut == nullptr || errorOut == nullptr ||
            (descriptor.pluginType != QStringLiteral("tab") &&
             descriptor.pluginType != QStringLiteral("hybrid")) ||
            !descriptor.tabPresentation.enabled)
        {
            return false;
        }
        QStringList arguments;
        if (descriptor.runtime == QStringLiteral("python"))
        {
            QString python = qEnvironmentVariable("KSWORD_PLUGIN_PYTHON").trimmed();
            bool usePythonLauncher = false;
            if (!python.isEmpty() && !QFileInfo(python).isFile())
            {
                *errorOut = QStringLiteral("KSWORD_PLUGIN_PYTHON 未指向有效文件：%1").arg(python);
                return false;
            }
            if (python.isEmpty()) python = QStandardPaths::findExecutable(QStringLiteral("python.exe"));
            if (python.isEmpty())
            {
                python = QStandardPaths::findExecutable(QStringLiteral("py.exe"));
                usePythonLauncher = !python.isEmpty();
            }
            if (python.isEmpty())
            {
                *errorOut = QStringLiteral("找不到 Python 运行时；请安装 python.exe/py.exe 或设置 KSWORD_PLUGIN_PYTHON。");
                return false;
            }
            *programOut = python;
            if (usePythonLauncher) arguments << QStringLiteral("-3");
            arguments << descriptor.entrypointPath;
        }
        else
        {
            *programOut = descriptor.entrypointPath;
        }

        arguments << QStringLiteral("--ksword-plugin") << descriptor.tabPresentation.command << QStringLiteral("--")
            << QStringLiteral("--parent-hwnd") << QString::number(static_cast<qulonglong>(parentWindowId))
            << QStringLiteral("--host-pid") << QString::number(QCoreApplication::applicationPid());
        *argumentsOut = arguments;
        return true;
    }

    QString visualizationValueText(const QJsonValue& value, const QString& format)
    {
        if (value.isUndefined() || value.isNull())
        {
            return QStringLiteral("—");
        }
        if (format == QStringLiteral("percent") && value.isDouble())
        {
            double percent = value.toDouble();
            if (qAbs(percent) <= 1.0) percent *= 100.0;
            if (percent > 0.0 && percent < 0.01) return QStringLiteral("<0.01%");
            return QStringLiteral("%1%").arg(percent, 0, 'f', 2);
        }
        if (format == QStringLiteral("integer") && value.isDouble())
        {
            return QString::number(qRound64(value.toDouble()));
        }
        if (format == QStringLiteral("number") && value.isDouble())
        {
            return QString::number(value.toDouble(), 'g', 8);
        }
        if (value.isString())
        {
            return value.toString();
        }
        if (value.isDouble())
        {
            return QString::number(value.toDouble(), 'g', 12);
        }
        if (value.isBool())
        {
            return value.toBool() ? QStringLiteral("是") : QStringLiteral("否");
        }
        if (value.isArray())
        {
            return QString::fromUtf8(QJsonDocument(value.toArray()).toJson(QJsonDocument::Compact));
        }
        if (value.isObject())
        {
            return QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact));
        }
        return QStringLiteral("—");
    }

    QColor visualizationToneColor(const QString& tone)
    {
        if (tone == QStringLiteral("success")) return KswordTheme::SuccessColor();
        if (tone == QStringLiteral("danger")) return KswordTheme::ErrorColor();
        if (tone == QStringLiteral("warning")) return KswordTheme::WarningColor();
        if (tone == QStringLiteral("info")) return KswordTheme::InfoColor();
        if (tone == QStringLiteral("muted")) return KswordTheme::TextSecondaryColor();
        return KswordTheme::TextPrimaryColor();
    }

    class PluginRunDialog final : public QDialog
    {
    public:
        PluginRunDialog(
            QWidget* parent,
            const PluginDescriptor& descriptor,
            const ks::plugin_host::InvocationContext& context,
            const QString& program,
            const QStringList& arguments)
            : QDialog(parent),
              m_descriptor(descriptor)
        {
            setAttribute(Qt::WA_DeleteOnClose, true);
            setWindowTitle(descriptor.visualization.enabled
                ? descriptor.visualization.title
                : descriptor.name);
            setWindowIcon(QIcon(QStringLiteral(":/Icon/process_start.svg")));
            resize(920, 620);
            setModal(false);

            auto* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(16, 16, 16, 16);
            rootLayout->setSpacing(10);

            auto* titleLabel = new QLabel(
                descriptor.visualization.enabled ? descriptor.visualization.title : descriptor.name,
                this);
            titleLabel->setStyleSheet(QStringLiteral("font-size:18px;font-weight:700;color:%1;")
                .arg(KswordTheme::TextPrimaryHex()));
            rootLayout->addWidget(titleLabel);

            QString targetText;
            if (context.targetKind == ks::plugin_host::TargetKind::File)
            {
                targetText = QStringLiteral("目标文件：%1").arg(QDir::toNativeSeparators(context.filePath));
            }
            else if (context.targetKind == ks::plugin_host::TargetKind::Process)
            {
                targetText = QStringLiteral("目标进程：%1  PID %2")
                    .arg(context.processName.trimmed().isEmpty() ? QStringLiteral("未知进程") : context.processName)
                    .arg(context.processId);
                if (!context.filePath.trimmed().isEmpty())
                {
                    targetText += QStringLiteral("\n映像路径：%1").arg(QDir::toNativeSeparators(context.filePath));
                }
            }
            else
            {
                targetText = QStringLiteral("目标：实时网络流量");
            }
            auto* targetLabel = new QLabel(targetText, this);
            targetLabel->setWordWrap(true);
            targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            targetLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
            rootLayout->addWidget(targetLabel);

            m_progress = new QProgressBar(this);
            m_progress->setRange(0, 0);
            m_progress->setTextVisible(true);
            rootLayout->addWidget(m_progress);

            if (!descriptor.visualization.summary.isEmpty())
            {
                auto* summaryLayout = new QHBoxLayout();
                summaryLayout->setSpacing(18);
                for (const VisualizationField& field : descriptor.visualization.summary)
                {
                    auto* label = new QLabel(QStringLiteral("%1：—").arg(field.label), this);
                    label->setStyleSheet(QStringLiteral("font-weight:600;color:%1;")
                        .arg(KswordTheme::TextPrimaryHex()));
                    summaryLayout->addWidget(label);
                    m_summaryLabels.insert(field.field, label);
                }
                summaryLayout->addStretch(1);
                rootLayout->addLayout(summaryLayout);
            }

            m_tabs = new QTabWidget(this);
            if (descriptor.visualization.enabled)
            {
                m_resultTable = new ks::ui::VisibleTableWidget(m_tabs);
                m_resultTable->setColumnCount(descriptor.visualization.columns.size());
                QStringList labels;
                for (const VisualizationField& field : descriptor.visualization.columns) labels.push_back(field.label);
                m_resultTable->setHorizontalHeaderLabels(labels);
                m_resultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
                m_resultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
                m_resultTable->setSelectionMode(QAbstractItemView::SingleSelection);
                m_resultTable->setAlternatingRowColors(true);
                m_resultTable->setWordWrap(false);
                m_resultTable->setSortingEnabled(false);
                m_resultTable->verticalHeader()->setVisible(false);
                QHeaderView* header = m_resultTable->horizontalHeader();
                header->setStretchLastSection(false);
                for (int column = 0; column < descriptor.visualization.columns.size(); ++column)
                {
                    const QString format = descriptor.visualization.columns.at(column).format;
                    if (format == QStringLiteral("path"))
                    {
                        header->setSectionResizeMode(column, QHeaderView::Stretch);
                    }
                    else if (format == QStringLiteral("text"))
                    {
                        header->setSectionResizeMode(column, QHeaderView::Interactive);
                        m_resultTable->setColumnWidth(column, 180);
                    }
                    else
                    {
                        header->setSectionResizeMode(column, QHeaderView::ResizeToContents);
                    }
                }
                m_tabs->addTab(m_resultTable, QStringLiteral("扫描结果"));
            }
            else
            {
                m_plainOutput = new CodeTextEdit(m_tabs);
                static_cast<CodeTextEdit*>(m_plainOutput)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
                m_plainOutput->setReadOnly(true);
                m_plainOutput->setMaximumBlockCount(2000);
                m_tabs->addTab(m_plainOutput, QStringLiteral("插件输出"));
            }

            m_diagnostics = new CodeTextEdit(m_tabs);
            static_cast<CodeTextEdit*>(m_diagnostics)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            m_diagnostics->setReadOnly(true);
            m_diagnostics->setMaximumBlockCount(2000);
            m_diagnostics->setPlaceholderText(QStringLiteral("插件错误和协议诊断会显示在这里。"));
            m_tabs->addTab(m_diagnostics, QStringLiteral("诊断"));
            rootLayout->addWidget(m_tabs, 1);

            auto* footer = new QHBoxLayout();
            m_status = new QLabel(QStringLiteral("正在启动…"), this);
            m_status->setWordWrap(true);
            footer->addWidget(m_status, 1);
            m_closeButton = new QPushButton(QStringLiteral("取消"), this);
            footer->addWidget(m_closeButton);
            rootLayout->addLayout(footer);

            m_process = new QProcess(this);
            m_process->setProgram(program);
            m_process->setArguments(arguments);
            m_process->setWorkingDirectory(descriptor.pluginDirectory);
            m_process->setProcessChannelMode(QProcess::SeparateChannels);
            QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
            environment.insert(QStringLiteral("KSWORD_PLUGIN_ROOT"), findPluginRoot());
            m_process->setProcessEnvironment(environment);

            connect(m_closeButton, &QPushButton::clicked, this, [this]() {
                if (m_process->state() == QProcess::NotRunning) close();
                else cancelRun();
            });
            connect(m_process, &QProcess::started, this, [this]() {
                setStatus(QStringLiteral("正在扫描…"), QStringLiteral("info"));
            });
            connect(m_process, &QProcess::readyReadStandardOutput, this, [this]() {
                consumeStandardOutput(false);
            });
            connect(m_process, &QProcess::readyReadStandardError, this, [this]() {
                consumeStandardError();
            });
            connect(m_process, &QProcess::errorOccurred, this, [this](const QProcess::ProcessError error) {
                if (error != QProcess::FailedToStart || m_finished) return;
                m_finished = true;
                m_progress->setRange(0, 1);
                m_progress->setValue(0);
                appendDiagnostic(QStringLiteral("无法启动插件入口：%1").arg(m_process->errorString()));
                setStatus(QStringLiteral("启动失败"), QStringLiteral("danger"));
                m_closeButton->setText(QStringLiteral("关闭"));
                m_closeButton->setEnabled(true);
                if (m_tabs->count() > 1) m_tabs->setCurrentIndex(1);
            });
            connect(m_process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](const int exitCode, const QProcess::ExitStatus exitStatus) {
                    if (m_finished) return;
                    m_finished = true;
                    consumeStandardOutput(true);
                    consumeStandardError();
                    const bool protocolComplete = !m_descriptor.visualization.enabled || m_completeSeen;
                    const bool succeeded = exitStatus == QProcess::NormalExit && exitCode == 0 &&
                        !m_protocolError && protocolComplete && !m_cancelRequested;
                    if (m_cancelRequested)
                    {
                        setStatus(QStringLiteral("扫描已取消"), QStringLiteral("warning"));
                    }
                    else if (succeeded)
                    {
                        if (m_totalItems > 0)
                        {
                            m_progress->setRange(0, m_totalItems);
                            m_progress->setValue(qMin(m_completedItems, m_totalItems));
                        }
                        else
                        {
                            m_progress->setRange(0, 1);
                            m_progress->setValue(1);
                        }
                        setStatus(QStringLiteral("扫描完成，共处理 %1 项").arg(m_completedItems),
                            QStringLiteral("success"));
                    }
                    else
                    {
                        if (!protocolComplete)
                        {
                            appendDiagnostic(QStringLiteral("插件未发送声明的完成事件：%1")
                                .arg(m_descriptor.visualization.completeEvent));
                        }
                        setStatus(QStringLiteral("扫描失败（退出码 %1）").arg(exitCode),
                            QStringLiteral("danger"));
                        if (m_tabs->count() > 1) m_tabs->setCurrentIndex(1);
                    }
                    m_closeButton->setText(QStringLiteral("关闭"));
                    m_closeButton->setEnabled(true);
                    if (m_resultTable != nullptr) m_resultTable->setSortingEnabled(true);
                });
        }

        void start()
        {
            m_process->start();
        }

    protected:
        void closeEvent(QCloseEvent* event) override
        {
            if (m_process != nullptr && m_process->state() != QProcess::NotRunning)
            {
                cancelRun();
                event->ignore();
                return;
            }
            QDialog::closeEvent(event);
        }

    private:
        void cancelRun()
        {
            if (m_process == nullptr || m_process->state() == QProcess::NotRunning) return;
            m_cancelRequested = true;
            setStatus(QStringLiteral("正在取消扫描…"), QStringLiteral("warning"));
            m_closeButton->setEnabled(false);
            m_process->terminate();
            QTimer::singleShot(2000, m_process, [process = m_process]() {
                if (process->state() != QProcess::NotRunning) process->kill();
            });
        }

        void setStatus(const QString& text, const QString& tone)
        {
            m_status->setText(text);
            m_status->setStyleSheet(QStringLiteral("font-weight:600;color:%1;")
                .arg(visualizationToneColor(tone).name()));
        }

        void appendDiagnostic(const QString& text)
        {
            if (!text.trimmed().isEmpty()) m_diagnostics->appendPlainText(text.trimmed());
        }

        void consumeStandardError()
        {
            const QString text = QString::fromLocal8Bit(m_process->readAllStandardError());
            appendDiagnostic(text);
        }

        void consumeStandardOutput(const bool flushRemainder)
        {
            m_stdoutBuffer += m_process->readAllStandardOutput();
            int newlineIndex = -1;
            while ((newlineIndex = m_stdoutBuffer.indexOf('\n')) >= 0)
            {
                QByteArray line = m_stdoutBuffer.left(newlineIndex);
                m_stdoutBuffer.remove(0, newlineIndex + 1);
                if (line.endsWith('\r')) line.chop(1);
                processOutputLine(line);
            }
            if (m_stdoutBuffer.size() > kMaxBufferedStdoutBytes)
            {
                appendDiagnostic(QStringLiteral("插件输出存在超过 1 MiB 的无换行记录，已拒绝解析。"));
                m_stdoutBuffer.clear();
                m_protocolError = true;
            }
            if (flushRemainder && !m_stdoutBuffer.isEmpty())
            {
                processOutputLine(m_stdoutBuffer);
                m_stdoutBuffer.clear();
            }
        }

        void processOutputLine(const QByteArray& lineBytes)
        {
            const QString line = QString::fromUtf8(lineBytes).trimmed();
            if (line.isEmpty()) return;
            if (!m_descriptor.visualization.enabled)
            {
                m_plainOutput->appendPlainText(line);
                return;
            }

            QJsonParseError parseError;
            const QJsonDocument document = QJsonDocument::fromJson(lineBytes, &parseError);
            if (parseError.error != QJsonParseError::NoError || !document.isObject())
            {
                appendDiagnostic(QStringLiteral("无法解析插件 JSON Lines：%1\n%2")
                    .arg(parseError.errorString(), line));
                m_protocolError = true;
                return;
            }
            const QJsonObject object = document.object();
            if (object.value(QStringLiteral("protocol")).toString() != QStringLiteral("ksword-plugin/1") ||
                object.value(QStringLiteral("plugin_id")).toString() != m_descriptor.id)
            {
                appendDiagnostic(QStringLiteral("插件输出的 protocol 或 plugin_id 与清单不一致。"));
                m_protocolError = true;
                return;
            }

            const QString event = object.value(QStringLiteral("event")).toString();
            if (event == QStringLiteral("error"))
            {
                m_protocolError = true;
                appendDiagnostic(QStringLiteral("%1：%2")
                    .arg(object.value(QStringLiteral("code")).toString(QStringLiteral("plugin_error")),
                         object.value(QStringLiteral("message")).toString(QStringLiteral("插件报告错误"))));
                setStatus(QStringLiteral("插件报告错误"), QStringLiteral("danger"));
                return;
            }
            if (event == m_descriptor.visualization.startEvent)
            {
                m_totalItems = qMax(0, object.value(m_descriptor.visualization.totalField).toInt());
                if (m_totalItems > 0)
                {
                    m_progress->setRange(0, m_totalItems);
                    m_progress->setValue(0);
                    m_progress->setFormat(QStringLiteral("%v / %m"));
                }
                setStatus(m_totalItems > 0
                    ? QStringLiteral("正在扫描 0 / %1").arg(m_totalItems)
                    : QStringLiteral("正在扫描…"), QStringLiteral("info"));
                return;
            }
            if (event == m_descriptor.visualization.resultEvent)
            {
                appendResult(object);
                ++m_completedItems;
                if (m_totalItems > 0)
                {
                    m_progress->setValue(qMin(m_completedItems, m_totalItems));
                    setStatus(QStringLiteral("正在扫描 %1 / %2").arg(m_completedItems).arg(m_totalItems),
                        QStringLiteral("info"));
                }
                else
                {
                    setStatus(QStringLiteral("已处理 %1 项").arg(m_completedItems), QStringLiteral("info"));
                }
                return;
            }
            if (event == m_descriptor.visualization.completeEvent)
            {
                m_completeSeen = true;
                updateSummary(object);
                if (m_totalItems > 0) m_progress->setValue(qMin(m_completedItems, m_totalItems));
                setStatus(QStringLiteral("正在完成扫描…"), QStringLiteral("info"));
            }
        }

        void appendResult(const QJsonObject& object)
        {
            if (m_resultTable == nullptr) return;
            if (m_resultTable->rowCount() >= kMaxVisualizationRows)
            {
                if (!m_rowLimitReported)
                {
                    appendDiagnostic(QStringLiteral("扫描结果超过 %1 行，后续结果不再显示。")
                        .arg(kMaxVisualizationRows));
                    m_rowLimitReported = true;
                }
                return;
            }

            const int row = m_resultTable->rowCount();
            m_resultTable->insertRow(row);
            for (int column = 0; column < m_descriptor.visualization.columns.size(); ++column)
            {
                const VisualizationField& field = m_descriptor.visualization.columns.at(column);
                const QJsonValue value = object.value(field.field);
                QString text = visualizationValueText(value, field.format);
                QString tone;
                if (field.format == QStringLiteral("badge"))
                {
                    const VisualizationValueStyle style = field.valueStyles.value(value.toString());
                    if (!style.label.isEmpty()) text = style.label;
                    tone = style.tone;
                }
                auto* item = new QTableWidgetItem(text);
                if (!tone.isEmpty()) item->setForeground(QBrush(visualizationToneColor(tone)));
                if (field.format == QStringLiteral("path") || text.size() > 80) item->setToolTip(text);
                if (field.format == QStringLiteral("integer") ||
                    field.format == QStringLiteral("number") ||
                    field.format == QStringLiteral("percent"))
                {
                    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
                }
                m_resultTable->setItem(row, column, item);
            }
        }

        void updateSummary(const QJsonObject& object)
        {
            for (const VisualizationField& field : m_descriptor.visualization.summary)
            {
                QLabel* label = m_summaryLabels.value(field.field, nullptr);
                if (label == nullptr) continue;
                const QJsonValue value = object.value(field.field);
                QString text = visualizationValueText(value, field.format);
                QString tone;
                if (field.format == QStringLiteral("badge"))
                {
                    const VisualizationValueStyle style = field.valueStyles.value(value.toString());
                    if (!style.label.isEmpty()) text = style.label;
                    tone = style.tone;
                }
                label->setText(QStringLiteral("%1：%2").arg(field.label, text));
                label->setStyleSheet(QStringLiteral("font-weight:600;color:%1;")
                    .arg(tone.isEmpty()
                        ? KswordTheme::TextPrimaryColorHex()
                        : visualizationToneColor(tone).name()));
            }
        }

        PluginDescriptor m_descriptor;
        QProcess* m_process = nullptr;
        QProgressBar* m_progress = nullptr;
        QTabWidget* m_tabs = nullptr;
        QTableWidget* m_resultTable = nullptr;
        QPlainTextEdit* m_plainOutput = nullptr;
        QPlainTextEdit* m_diagnostics = nullptr;
        QLabel* m_status = nullptr;
        QPushButton* m_closeButton = nullptr;
        QHash<QString, QLabel*> m_summaryLabels;
        QByteArray m_stdoutBuffer;
        int m_totalItems = 0;
        int m_completedItems = 0;
        bool m_completeSeen = false;
        bool m_protocolError = false;
        bool m_cancelRequested = false;
        bool m_finished = false;
        bool m_rowLimitReported = false;
    };

    void launchPlugin(QWidget* owner, const PluginDescriptor& descriptor, const ks::plugin_host::InvocationContext& context)
    {
        if (descriptor.pluginType == QStringLiteral("backend")) return;
        QString contextError;
        if (!isUsableContext(context, &contextError))
        {
            QMessageBox::warning(owner, QStringLiteral("插件"), contextError);
            return;
        }

        QString program;
        QStringList arguments;
        QString commandError;
        if (!buildPluginCommand(descriptor, context, &program, &arguments, &commandError))
        {
            QMessageBox::warning(owner, QStringLiteral("插件：%1").arg(descriptor.name), commandError);
            return;
        }

        auto* dialog = new PluginRunDialog(owner, descriptor, context, program, arguments);
        dialog->show();
        dialog->raise();
        dialog->activateWindow();
        dialog->start();
    }

    class PluginTabPage final : public QWidget
    {
    public:
        PluginTabPage(QWidget* parent, const PluginDescriptor& descriptor)
            : QWidget(parent), m_descriptor(descriptor)
        {
            setObjectName(QStringLiteral("ksExternalPluginTab_%1").arg(descriptor.id));
            auto* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(4, 4, 4, 4);
            rootLayout->setSpacing(4);

            auto* statusRow = new QHBoxLayout();
            m_statusLabel = new QLabel(QStringLiteral("正在启动外部 Tab 插件…"), this);
            m_statusLabel->setWordWrap(true);
            statusRow->addWidget(m_statusLabel, 1);
            m_diagnosticsButton = new QPushButton(QStringLiteral("诊断"), this);
            m_retryButton = new QPushButton(QStringLiteral("重试"), this);
            m_retryButton->setVisible(false);
            statusRow->addWidget(m_diagnosticsButton);
            statusRow->addWidget(m_retryButton);
            rootLayout->addLayout(statusRow);

            m_surface = new QWidget(this);
            m_surface->setObjectName(QStringLiteral("ksExternalPluginNativeSurface"));
            m_surface->setAttribute(Qt::WA_NativeWindow, true);
            m_surface->setFocusPolicy(Qt::StrongFocus);
            m_surface->setStyleSheet(QStringLiteral("background:%1;border:1px solid %2;")
                .arg(KswordTheme::SurfaceHex(), KswordTheme::BorderHex()));
            m_surface->installEventFilter(this);
            rootLayout->addWidget(m_surface, 1);

            m_diagnostics = new CodeTextEdit(this);
            static_cast<CodeTextEdit*>(m_diagnostics)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            m_diagnostics->setReadOnly(true);
            m_diagnostics->setMaximumHeight(180);
            m_diagnostics->document()->setMaximumBlockCount(2000);
            m_diagnostics->setVisible(false);
            rootLayout->addWidget(m_diagnostics);

            connect(m_diagnosticsButton, &QPushButton::clicked, this, [this]() {
                m_diagnostics->setVisible(!m_diagnostics->isVisible());
            });
            connect(m_retryButton, &QPushButton::clicked, this, [this]() { start(); });
        }

        ~PluginTabPage() override
        {
            m_stopping = true;
            if (::IsWindow(m_pluginWindow))
            {
                ::PostMessageW(m_pluginWindow, WM_CLOSE, 0, 0);
            }
            if (m_process != nullptr && m_process->state() != QProcess::NotRunning)
            {
                m_process->terminate();
                if (!m_process->waitForFinished(1200))
                {
                    m_process->kill();
                    m_process->waitForFinished(800);
                }
            }
        }

    protected:
        // 主题快照在当前palette/style更新栈结束后发送，避免Qt构造/重排期间重入。
        void changeEvent(QEvent* event) override
        {
            QWidget::changeEvent(event);
            if (event->type() == QEvent::ApplicationPaletteChange ||
                event->type() == QEvent::PaletteChange)
            {
                schedulePluginThemeUpdate();
            }
        }

        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (!m_startScheduled)
            {
                m_startScheduled = true;
                QTimer::singleShot(0, this, [this]() { start(); });
            }
        }

        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (watched == m_surface &&
                (event->type() == QEvent::Resize || event->type() == QEvent::Show))
            {
                resizePluginWindow();
                if (event->type() == QEvent::Show) schedulePluginThemeUpdate();
            }
            if (watched == m_surface && event->type() == QEvent::MouseButtonPress && ::IsWindow(m_pluginWindow))
            {
                ::SetFocus(m_pluginWindow);
            }
            return QWidget::eventFilter(watched, event);
        }

    private:
        void start()
        {
            if (m_process != nullptr && m_process->state() != QProcess::NotRunning)
            {
                return;
            }
            m_failed = false;
            m_ready = false;
            m_pluginWindow = nullptr;
            m_stdoutBuffer.clear();
            m_retryButton->setVisible(false);
            m_statusLabel->setText(QStringLiteral("正在启动外部 Tab 插件…"));
            m_statusLabel->setStyleSheet({});

            QString program;
            QStringList arguments;
            QString errorText;
            const WId surfaceId = m_surface->winId();
            if (!buildTabPluginCommand(m_descriptor, surfaceId, &program, &arguments, &errorText))
            {
                fail(QStringLiteral("Tab 插件启动失败：%1").arg(errorText), false);
                return;
            }

            if (m_process != nullptr)
            {
                m_process->deleteLater();
            }
            m_process = new QProcess(this);
            m_process->setProgram(program);
            m_process->setArguments(arguments);
            m_process->setWorkingDirectory(m_descriptor.pluginDirectory);
            m_process->setProcessChannelMode(QProcess::SeparateChannels);
            QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
            environment.insert(QStringLiteral("KSWORD_PLUGIN_ROOT"), findPluginRoot());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_ID"), m_descriptor.id);
            environment.insert(QStringLiteral("KSWORD_PLUGIN_LANGUAGE"), ks::i18n::LanguageManager::instance().currentLanguageId());
            // 基础样式注入协议：
            // - 外部进程不会继承 Qt palette/QSS，因此以环境变量提供稳定的主题角色；
            // - 插件可以逐步选择消费这些值，不会因为未实现样式协议而无法启动；
            // - 当前为启动时快照，主题切换后重新打开/重试插件即可获得新值；
            // - 一律使用 *ColorHex() 静态角色：palette(...) 动态角色只有本进程的 QSS
            //   解析器认识，传给外部进程会变成无法识别的字面量。
            environment.insert(QStringLiteral("KSWORD_PLUGIN_STYLE_API"), QStringLiteral("1"));
            environment.insert(
                QStringLiteral("KSWORD_PLUGIN_THEME"),
                KswordTheme::IsDarkModeEnabled() ? QStringLiteral("dark") : QStringLiteral("light"));
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_WINDOW"), KswordTheme::WindowColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_SURFACE"), KswordTheme::SurfaceColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_SURFACE_ALT"), KswordTheme::SurfaceAltColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_TEXT_PRIMARY"), KswordTheme::TextPrimaryColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_TEXT_SECONDARY"), KswordTheme::TextSecondaryColorHex());
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_BORDER"), KswordTheme::BorderColorHex());
            environment.insert(
                QStringLiteral("KSWORD_PLUGIN_COLOR_ACCENT"),
                KswordTheme::AccentHex(KswordTheme::AccentRole::Blue));
            environment.insert(QStringLiteral("KSWORD_PLUGIN_COLOR_ON_ACCENT"), KswordTheme::OnAccentHex());
            m_process->setProcessEnvironment(environment);

            connect(m_process, &QProcess::started, this, [this]() {
                m_statusLabel->setText(QStringLiteral("插件进程已启动，等待窗口握手…"));
            });
            connect(m_process, &QProcess::readyReadStandardOutput, this, [this]() { consumeStdout(); });
            connect(m_process, &QProcess::readyReadStandardError, this, [this]() {
                const QString text = QString::fromUtf8(m_process->readAllStandardError());
                if (!text.isEmpty()) m_diagnostics->appendPlainText(text.trimmed());
            });
            connect(m_process, &QProcess::errorOccurred, this, [this](const QProcess::ProcessError error) {
                if (error == QProcess::FailedToStart)
                {
                    fail(QStringLiteral("Tab 插件启动失败：%1").arg(m_process->errorString()), false);
                }
            });
            connect(m_process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this](const int exitCode, const QProcess::ExitStatus exitStatus) {
                    if (m_stopping) return;
                    m_pluginWindow = nullptr;
                    const QString exitText = QStringLiteral("插件进程已退出：exit=%1, status=%2")
                        .arg(exitCode)
                        .arg(exitStatus == QProcess::NormalExit ? QStringLiteral("normal") : QStringLiteral("crashed"));
                    m_diagnostics->appendPlainText(exitText);
                    if (!m_failed) fail(exitText, false);
                });
            m_process->start();

            QPointer<PluginTabPage> guard(this);
            QTimer::singleShot(m_descriptor.tabPresentation.startupTimeoutMs, this, [guard]() {
                if (guard != nullptr && !guard->m_ready && !guard->m_failed)
                {
                    guard->fail(QStringLiteral("Tab 插件启动超时，未收到有效的窗口握手。"), true);
                }
            });
        }

        void consumeStdout();
        void processProtocolLine(const QByteArray& line);
        void resizePluginWindow();
        void schedulePluginThemeUpdate();
        void fail(const QString& message, bool stopProcess);

        PluginDescriptor m_descriptor;
        QProcess* m_process = nullptr;
        QWidget* m_surface = nullptr;
        QLabel* m_statusLabel = nullptr;
        QPushButton* m_diagnosticsButton = nullptr;
        QPushButton* m_retryButton = nullptr;
        QPlainTextEdit* m_diagnostics = nullptr;
        QByteArray m_stdoutBuffer;
        HWND m_pluginWindow = nullptr;
        bool m_ready = false;
        bool m_failed = false;
        bool m_stopping = false;
        bool m_startScheduled = false;
        bool m_themeUpdatePending = false; // 合并同一轮外观事件，生命周期由this约束。
    };

    void PluginTabPage::consumeStdout()
    {
        if (m_process == nullptr)
        {
            return;
        }
        m_stdoutBuffer += m_process->readAllStandardOutput();
        if (m_stdoutBuffer.size() > kMaxBufferedStdoutBytes && !m_stdoutBuffer.contains('\n'))
        {
            fail(QStringLiteral("Tab 插件 stdout 单行缓冲超过 1 MiB，已终止插件。"), true);
            return;
        }
        while (true)
        {
            const qsizetype newlineIndex = m_stdoutBuffer.indexOf('\n');
            if (newlineIndex < 0)
            {
                break;
            }
            if (newlineIndex > kMaxBufferedStdoutBytes)
            {
                fail(QStringLiteral("Tab 插件 stdout 单行缓冲超过 1 MiB，已终止插件。"), true);
                return;
            }
            QByteArray line = m_stdoutBuffer.left(newlineIndex);
            m_stdoutBuffer.remove(0, newlineIndex + 1);
            if (line.endsWith('\r')) line.chop(1);
            if (!line.trimmed().isEmpty()) processProtocolLine(line);
            if (m_failed) return;
        }
    }

    void PluginTabPage::processProtocolLine(const QByteArray& line)
    {
        QJsonParseError parseError;
        const QJsonDocument document = QJsonDocument::fromJson(line, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            m_diagnostics->appendPlainText(QString::fromUtf8(line));
            fail(QStringLiteral("Tab 插件输出不是有效的 JSON Lines 协议事件。"), true);
            return;
        }
        const QJsonObject object = document.object();
        if (object.value(QStringLiteral("protocol")).toString() != QStringLiteral("ksword-plugin/1") ||
            object.value(QStringLiteral("plugin_id")).toString() != m_descriptor.id)
        {
            fail(QStringLiteral("Tab 插件协议版本或 plugin_id 与清单不匹配。"), true);
            return;
        }
        const QString event = object.value(QStringLiteral("event")).toString();
        if (event == QStringLiteral("error"))
        {
            fail(QStringLiteral("Tab 插件报告错误：%1")
                .arg(object.value(QStringLiteral("message")).toString(QStringLiteral("未知错误"))), true);
            return;
        }
        if (event == QStringLiteral("log"))
        {
            const QString message = object.value(QStringLiteral("message")).toString();
            if (!message.isEmpty())
            {
                m_diagnostics->appendPlainText(message);
                info << "[PluginHost:" << m_descriptor.id.toStdString() << "] "
                    << message.toStdString() << eol;
            }
            return;
        }
        if (event != m_descriptor.tabPresentation.readyEvent)
        {
            m_diagnostics->appendPlainText(QString::fromUtf8(line));
            return;
        }

        const QJsonValue handleValue = object.value(QStringLiteral("hwnd"));
        bool handleOk = false;
        qulonglong numericHandle = 0;
        if (handleValue.isString())
        {
            numericHandle = handleValue.toString().toULongLong(&handleOk, 0);
        }
        else if (handleValue.isDouble() && handleValue.toDouble() > 0.0)
        {
            numericHandle = static_cast<qulonglong>(handleValue.toDouble());
            handleOk = true;
        }
        HWND candidateWindow = handleOk
            ? reinterpret_cast<HWND>(static_cast<quintptr>(numericHandle))
            : nullptr;
        if (!handleOk || !::IsWindow(candidateWindow))
        {
            fail(QStringLiteral("Tab 插件返回的窗口句柄无效。"), true);
            return;
        }

        DWORD owningProcessId = 0;
        ::GetWindowThreadProcessId(candidateWindow, &owningProcessId);
        if (m_process == nullptr || owningProcessId != static_cast<DWORD>(m_process->processId()))
        {
            fail(QStringLiteral("Tab 插件窗口不属于刚启动的插件进程，已拒绝嵌入。"), true);
            return;
        }
        const HWND expectedParent = reinterpret_cast<HWND>(m_surface->winId());
        if (::GetParent(candidateWindow) != expectedParent ||
            (::GetWindowLongPtrW(candidateWindow, GWL_STYLE) & WS_CHILD) == 0)
        {
            fail(QStringLiteral("Tab 插件窗口未作为宿主容器的直接 WS_CHILD 子窗口创建。"), true);
            return;
        }

        m_pluginWindow = candidateWindow;
        m_ready = true;
        m_failed = false;
        m_retryButton->setVisible(false);
        m_statusLabel->setStyleSheet({});
        m_statusLabel->setText(QStringLiteral("Tab 插件已连接（外部进程 PID %1）。")
            .arg(owningProcessId));
        ::ShowWindow(m_pluginWindow, SW_SHOW);
        resizePluginWindow();
        // 启动环境快照之后可能已换主题；握手完成时立即补当前色。
        schedulePluginThemeUpdate();
    }

    // 将最新主题发送给已通过PID与WS_CHILD父窗口核验的日志页。
    // 输出仅是有限超时的颜色消息，不重启插件、不触碰其后端/日志状态。
    void PluginTabPage::schedulePluginThemeUpdate()
    {
        if (m_themeUpdatePending || m_stopping)
        {
            return;
        }
        m_themeUpdatePending = true;
        QTimer::singleShot(0, this, [this]()
        {
            m_themeUpdatePending = false;
            if (!m_ready || m_stopping || m_process == nullptr || m_surface == nullptr ||
                !::IsWindow(m_pluginWindow))
            {
                return;
            }
            // 重验当前PID/直接父窗，避免退出后复用的HWND接收颜色消息。
            DWORD ownerPid = 0;
            ::GetWindowThreadProcessId(m_pluginWindow, &ownerPid);
            const HWND hostWindow = reinterpret_cast<HWND>(m_surface->winId());
            if (ownerPid != static_cast<DWORD>(m_process->processId()) ||
                ::GetParent(m_pluginWindow) != hostWindow)
            {
                return;
            }
            // 转为Win32实色；勾选轮廓以真实根底校准，避免白色强调种子不可见。
            const auto nativeColor = [](const QColor& value)
            {
                return RGB(value.red(), value.green(), value.blue());
            };
            ksword::plugin_theme::Packet packet;
            packet.window = nativeColor(KswordTheme::WindowColor());
            packet.surface = nativeColor(KswordTheme::SurfaceColor());
            packet.text = nativeColor(KswordTheme::TextPrimaryColor());
            packet.border = nativeColor(KswordTheme::BorderColor());
            packet.accent = nativeColor(KswordTheme::ControlGlyphColor(KswordTheme::WindowColor()));
            COPYDATASTRUCT copyData{}; // 消息仅在同步调用期间持有本地快照。
            copyData.dwData = ksword::plugin_theme::kCopyDataTag;
            copyData.cbData = sizeof(packet);
            copyData.lpData = &packet;
            DWORD_PTR reply = 0; // 老插件可忽略消息，挂起子进程也不能无限阻塞主窗口。
            ::SendMessageTimeoutW(m_pluginWindow, WM_COPYDATA,
                reinterpret_cast<WPARAM>(hostWindow), reinterpret_cast<LPARAM>(&copyData),
                SMTO_ABORTIFHUNG | SMTO_BLOCK, 50, &reply);
        });
    }

    void PluginTabPage::resizePluginWindow()
    {
        if (!::IsWindow(m_pluginWindow) || m_surface == nullptr)
        {
            return;
        }
        const QSize size = m_surface->size();
        ::MoveWindow(m_pluginWindow, 0, 0, qMax(1, size.width()), qMax(1, size.height()), TRUE);
    }

    void PluginTabPage::fail(const QString& message, const bool stopProcess)
    {
        if (m_stopping)
        {
            return;
        }
        m_failed = true;
        m_ready = false;
        m_pluginWindow = nullptr;
        m_statusLabel->setText(message);
        m_statusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;")
            .arg(KswordTheme::ErrorColor().name(QColor::HexRgb)));
        m_retryButton->setVisible(true);
        m_diagnostics->appendPlainText(message);
        if (stopProcess && m_process != nullptr && m_process->state() != QProcess::NotRunning)
        {
            m_process->terminate();
            QPointer<QProcess> processGuard(m_process);
            QTimer::singleShot(1500, this, [processGuard]() {
                if (processGuard != nullptr && processGuard->state() != QProcess::NotRunning)
                {
                    processGuard->kill();
                }
            });
        }
    }

    bool promoteExtractedPlugin(
        const MarketplacePlugin& plugin,
        const QString& pluginRoot,
        const QString& stagingDirectory,
        QString* errorOut)
    {
        if (errorOut == nullptr)
        {
            return false;
        }

        // Both marketplace layouts are accepted: plugin.json at the ZIP root,
        // or a single install-directory wrapper. Validate the actual extracted
        // directory before changing the installed plugin.
        const bool manifestAtRoot = QFileInfo(
            QDir(stagingDirectory).filePath(QStringLiteral("plugin.json"))).isFile();
        const QString extractedDirectory = manifestAtRoot
            ? stagingDirectory
            : QDir(stagingDirectory).filePath(plugin.installDirectory);
        PluginDescriptor extractedDescriptor;
        if (!loadPluginManifestDirectory(
                extractedDirectory, plugin.installDirectory, &extractedDescriptor, errorOut))
        {
            return false;
        }
        if (extractedDescriptor.id != plugin.id)
        {
            *errorOut = QStringLiteral("已解压插件的 id 与商城目录不一致。");
            return false;
        }

        // 上游计划生成的清单必须逐字段相同；版本、能力和入口不能被载荷替换。
        if (plugin.upstreamAssets)
        {
            QFile manifestFile(QDir(extractedDirectory).filePath(QStringLiteral("plugin.json")));
            if (!manifestFile.open(QIODevice::ReadOnly) ||
                QJsonDocument::fromJson(manifestFile.readAll()).object() != plugin.upstreamPlan.manifest)
            {
                *errorOut = QStringLiteral("已解压插件清单与上游分发计划不一致。");
                return false;
            }
        }
        QDir rootDirectory(pluginRoot);
        const QString stagingName = QFileInfo(stagingDirectory).fileName();
        const QString stagedPluginPath = manifestAtRoot
            ? stagingName
            : stagingName + QChar('/') + plugin.installDirectory;
        const QString backupName = QStringLiteral(".ksword-plugin-backup-%1-%2")
            .arg(plugin.installDirectory, QUuid::createUuid().toString(QUuid::WithoutBraces));
        const QString targetPath = rootDirectory.filePath(plugin.installDirectory);
        const bool targetExists = QFileInfo::exists(targetPath);

        if (targetExists && !rootDirectory.rename(plugin.installDirectory, backupName))
        {
            *errorOut = QStringLiteral("无法备份现有插件目录：%1").arg(QDir::toNativeSeparators(targetPath));
            return false;
        }

        if (!rootDirectory.rename(stagedPluginPath, plugin.installDirectory))
        {
            if (targetExists)
            {
                rootDirectory.rename(backupName, plugin.installDirectory);
            }
            *errorOut = QStringLiteral("无法将已验证插件安装到：%1").arg(QDir::toNativeSeparators(targetPath));
            return false;
        }

        if (targetExists)
        {
            // 新版本已经就位后，清理失败不应把一次成功安装报告为失败；
            // 遗留备份不会被发现为有效插件（名称不符合插件 ID 规则）。
            QDir(rootDirectory.filePath(backupName)).removeRecursively();
        }
        return true;
    }

    class PluginManagerDialog final : public QDialog
    {
    public:
        explicit PluginManagerDialog(QWidget* parent, const QString& preselectedId = QString())
            : QDialog(parent)
            , m_preselectedPluginId(preselectedId)
        {
            setAttribute(Qt::WA_DeleteOnClose, true);
            setWindowTitle(QStringLiteral("插件管理"));
            resize(840, 460);
            setModal(false);
            auto* layout = new QVBoxLayout(this);
            layout->setContentsMargins(8, 8, 8, 8);
            layout->setSpacing(6);

            // 插件列表与进程列表采用同一套紧凑表格几何基线。只在页面本地设置
            // 行高和滚动等几何属性，避免把尺寸规则放进 app 级 QSS 后污染标题栏
            // 或其它需要可变行高的表格。
            const auto configurePluginTable = [](QTableWidget* table) {
                if (table == nullptr)
                {
                    return;
                }
                table->setAlternatingRowColors(true);
                table->setShowGrid(false);
                table->setWordWrap(false);
                table->setCornerButtonEnabled(false);
                table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
                table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
                if (QHeaderView* verticalHeader = table->verticalHeader())
                {
                    verticalHeader->setVisible(false);
                    verticalHeader->setSectionResizeMode(QHeaderView::Fixed);
                    verticalHeader->setMinimumSectionSize(20);
                    verticalHeader->setDefaultSectionSize(24);
                }
            };

            m_networkManager = new QNetworkAccessManager(this);
            auto* tabWidget = new QTabWidget(this);
            m_mainTabs = tabWidget;
            auto* localPage = new QWidget(tabWidget);
            auto* localLayout = new QVBoxLayout(localPage);
            localLayout->setContentsMargins(6, 6, 6, 6);
            localLayout->setSpacing(4);
            m_table = new ks::ui::VisibleTableWidget(localPage);
            m_table->setColumnCount(4);
            m_table->setHorizontalHeaderLabels(QStringList{ QStringLiteral("名称"), QStringLiteral("版本"), QStringLiteral("目标"), QStringLiteral("说明") });
            m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
            m_table->setSelectionMode(QAbstractItemView::SingleSelection);
            m_table->horizontalHeader()->setStretchLastSection(true);
            configurePluginTable(m_table);
            auto* localActions = new QHBoxLayout();
            localActions->setSpacing(4);
            auto* refreshButton = new QPushButton(QStringLiteral("重新扫描本地"), localPage);
            auto* detailButton = new QPushButton(QStringLiteral("查看清单详情"), localPage);
            m_openFolderButton = new QPushButton(QStringLiteral("打开插件目录"), localPage);
            localActions->addWidget(refreshButton);
            localActions->addWidget(detailButton);
            localActions->addWidget(m_openFolderButton);
            localActions->addStretch(1);
            localLayout->addLayout(localActions);
            localLayout->addWidget(m_table);
            tabWidget->addTab(localPage, QStringLiteral("已安装"));

            auto* marketplacePage = new QWidget(tabWidget);
            auto* marketplaceLayout = new QVBoxLayout(marketplacePage);
            marketplaceLayout->setContentsMargins(6, 6, 6, 6);
            marketplaceLayout->setSpacing(4);
            m_marketplaceTable = new ks::ui::VisibleTableWidget(marketplacePage);
            m_marketplaceTable->setColumnCount(6);
            m_marketplaceTable->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("名称"), QStringLiteral("版本"), QStringLiteral("安装状态"), QStringLiteral("目标"), QStringLiteral("许可证"), QStringLiteral("说明") });
            m_marketplaceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
            m_marketplaceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
            m_marketplaceTable->setSelectionMode(QAbstractItemView::SingleSelection);
            m_marketplaceTable->horizontalHeader()->setStretchLastSection(true);
            configurePluginTable(m_marketplaceTable);
            auto* marketplaceActions = new QHBoxLayout();
            marketplaceActions->setSpacing(4);
            auto* refreshMarketplaceButton = new QPushButton(QStringLiteral("刷新商城"), marketplacePage);
            auto* checkUpdatesButton = new QPushButton(QStringLiteral("检查插件更新"), marketplacePage);
            auto* installButton = new QPushButton(QStringLiteral("同意许可证并一键安装"), marketplacePage);
            m_autoUpdateCheck = new QCheckBox(QStringLiteral("自动更新已授权插件"), marketplacePage);
            m_autoUpdateCheck->setToolTip(QStringLiteral("检查更新时，自动安装已确认当前许可证且有新版本的插件。许可证变化时会要求重新确认。"));
            QSettings settings;
            m_autoUpdateCheck->setChecked(settings.value(QStringLiteral("PluginMarketplace/AutoUpdate"), false).toBool());
            marketplaceActions->addWidget(refreshMarketplaceButton);
            marketplaceActions->addWidget(checkUpdatesButton);
            marketplaceActions->addWidget(installButton);
            marketplaceActions->addWidget(m_autoUpdateCheck);
            marketplaceActions->addStretch(1);
            marketplaceLayout->addLayout(marketplaceActions);
            marketplaceLayout->addWidget(m_marketplaceTable);
            tabWidget->addTab(marketplacePage, QStringLiteral("插件商城"));
            layout->addWidget(tabWidget, 1);

            m_status = new QLabel(this);
            m_status->setWordWrap(true);
            m_status->setMinimumWidth(0);
            m_status->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
            layout->addWidget(m_status);
            m_installProgress = new QProgressBar(this);
            m_installProgress->setTextVisible(true);
            m_installProgress->setVisible(false);
            layout->addWidget(m_installProgress);
            auto* footer = new QHBoxLayout();
            auto* closeButton = new QPushButton(QStringLiteral("关闭"), this);
            footer->addStretch(1);
            footer->addWidget(closeButton);
            layout->addLayout(footer);
            connect(refreshButton, &QPushButton::clicked, this, [this]() { refreshPlugins(); });
            connect(refreshMarketplaceButton, &QPushButton::clicked, this, [this]() { refreshMarketplace(); });
            connect(checkUpdatesButton, &QPushButton::clicked, this, [this]() { checkForUpdates(); });
            connect(detailButton, &QPushButton::clicked, this, [this]() { showSelectedDetails(); });
            connect(installButton, &QPushButton::clicked, this, [this]() { requestSelectedMarketplaceLicense(); });
            connect(m_autoUpdateCheck, &QCheckBox::toggled, this, [this](const bool enabled) {
                QSettings settings;
                settings.setValue(QStringLiteral("PluginMarketplace/AutoUpdate"), enabled);
                if (enabled)
                {
                    checkForUpdates();
                }
            });
            connect(m_openFolderButton, &QPushButton::clicked, this, [this]() {
                if (!m_pluginRoot.isEmpty()) QDesktopServices::openUrl(QUrl::fromLocalFile(m_pluginRoot));
            });
            connect(closeButton, &QPushButton::clicked, this, &QDialog::close);
            refreshPlugins();
            refreshMarketplace(true);
        }

    private:
        using InstallCompletion = std::function<void(bool, const QString&)>;

        void refreshPlugins()
        {
            PluginListResult result;
            QString errorText;
            m_table->setRowCount(0);
            m_plugins.clear();
            m_installedPluginsById.clear();
            m_pluginRoot.clear();
            if (!discoverPlugins(&result, &errorText))
            {
                m_status->setText(
                    QStringLiteral("插件目录不可用；详情已写入日志。"));
                kLogEvent discoveryEvent;
                warn << discoveryEvent
                    << "[PluginHost] plugin discovery failed, detail="
                    << errorText.toStdString()
                    << eol;
                m_openFolderButton->setEnabled(false);
                return;
            }
            m_plugins = result.plugins;
            for (const PluginDescriptor& descriptor : m_plugins)
            {
                m_installedPluginsById.insert(descriptor.id, descriptor);
            }
            m_pluginRoot = result.pluginRoot;
            for (const PluginDescriptor& descriptor : m_plugins)
            {
                const int row = m_table->rowCount();
                m_table->insertRow(row);
                m_table->setItem(row, 0, new QTableWidgetItem(descriptor.name));
                m_table->setItem(row, 1, new QTableWidgetItem(descriptor.version));
                m_table->setItem(row, 2, new QTableWidgetItem(descriptor.targets.join(QStringLiteral(", "))));
                m_table->setItem(row, 3, new QTableWidgetItem(descriptor.description));
            }
            if (!m_plugins.isEmpty()) m_table->selectRow(0);
            m_openFolderButton->setEnabled(QDir(m_pluginRoot).exists());
            QString status = QStringLiteral("已发现 %1 个有效插件。插件目录：%2")
                .arg(m_plugins.size())
                .arg(QDir::toNativeSeparators(m_pluginRoot));
            if (!result.ignoredManifests.isEmpty())
            {
                status += QStringLiteral(
                    "\n已忽略 %1 个清单；详情已写入日志。")
                    .arg(result.ignoredManifests.size());
                kLogEvent ignoredManifestEvent;
                warn << ignoredManifestEvent
                    << "[PluginHost] ignored plugin manifests, count="
                    << result.ignoredManifests.size()
                    << ", details="
                    << result.ignoredManifests
                        .join(QStringLiteral(" | "))
                        .toStdString()
                    << eol;
            }
            m_status->setText(status);
        }

        void showSelectedDetails()
        {
            const int row = m_table->currentRow();
            if (row < 0 || row >= m_plugins.size())
            {
                QMessageBox::information(this, QStringLiteral("插件管理"), QStringLiteral("请先选择一个插件。"));
                return;
            }
            const PluginDescriptor& descriptor = m_plugins.at(row);
            const QString detailText = QStringLiteral("id=%1\nversion=%2\nplugin_type=%3\nruntime=%4\nentrypoint=%5\ndefault_command=%6\ntargets=%7\nvisualization=%8\ndirectory=%9\n\n%10")
                .arg(descriptor.id)
                .arg(descriptor.version)
                .arg(descriptor.pluginType)
                .arg(descriptor.runtime)
                .arg(descriptor.entrypointPath)
                .arg(descriptor.defaultCommand)
                .arg(descriptor.targets.join(QStringLiteral(", ")))
                .arg(descriptor.visualization.enabled ? descriptor.visualization.type : QStringLiteral("none"))
                .arg(descriptor.pluginDirectory)
                .arg(descriptor.description);
            QMessageBox::information(this, QStringLiteral("插件清单：%1").arg(descriptor.name), detailText);
        }

        void refreshMarketplace(const bool checkForUpdates = false)
        {
            m_marketplaceTable->setRowCount(0);
            m_marketplacePlugins.clear();
            // 初始元数据快照使用同一公开协议；在线目录按 id 覆盖，后续版本由 plugins 维护。
            QFile bootstrap(QStringLiteral(":/plugin-marketplace/catalog.json"));
            if (bootstrap.open(QIODevice::ReadOnly))
            {
                const auto root = QJsonDocument::fromJson(bootstrap.readAll()).object();
                for (const auto& value : root.value(QStringLiteral("plugins")).toArray())
                {
                    MarketplacePlugin plugin;
                    QString error;
                    if (value.isObject() && parseMarketplacePlugin(value.toObject(), &plugin, &error))
                        m_marketplacePlugins.append(plugin);
                }
            }
            populateMarketplaceTable();
            selectMarketplaceEntry();
            const auto generation = ++m_marketplaceGeneration;
            m_status->setText(QStringLiteral("正在从 KSwordDEV/Plugins 读取插件商城目录…"));
            QNetworkRequest request(QUrl(QString::fromLatin1(kMarketplaceCatalogUrl)));
            request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("KSword-PluginMarketplace/1"));
            request.setAttribute(QNetworkRequest::CacheLoadControlAttribute, QNetworkRequest::PreferNetwork);
            QNetworkReply* reply = m_networkManager->get(request);
            connect(reply, &QNetworkReply::finished, this, [this, reply, checkForUpdates, generation]() {
                const QByteArray payload = reply->readAll();
                const bool networkOk = reply->error() == QNetworkReply::NoError;
                const QString networkError = networkOk ? QString() : networkReplyErrorText(reply);
                reply->deleteLater();
                if (generation != m_marketplaceGeneration) return;
                if (!networkOk)
                {
                    m_status->setText(QStringLiteral(
                        "在线插件商城暂不可用；已安装插件仍可使用。"));
                    kLogEvent requestEvent;
                    warn << requestEvent
                        << "[PluginHost] marketplace catalog request failed, detail="
                        << networkError.toStdString()
                        << eol;
                    return;
                }
                QJsonParseError parseError;
                const QJsonDocument document = QJsonDocument::fromJson(payload, &parseError);
                if (parseError.error != QJsonParseError::NoError || !document.isObject())
                {
                    m_status->setText(QStringLiteral(
                        "商城目录不是有效 JSON；详情已写入日志。"));
                    kLogEvent parseEvent;
                    warn << parseEvent
                        << "[PluginHost] marketplace catalog parse failed, detail="
                        << parseError.errorString().toStdString()
                        << eol;
                    return;
                }
                const QJsonObject root = document.object();
                if (root.value(QStringLiteral("ksword_plugin_marketplace_api")).toString() != QStringLiteral("1"))
                {
                    m_status->setText(QStringLiteral("商城目录版本不受支持。"));
                    return;
                }
                QStringList ignoredEntries;
                for (const QJsonValue& value : root.value(QStringLiteral("plugins")).toArray())
                {
                    MarketplacePlugin plugin;
                    QString errorText;
                    if (value.isObject() && parseMarketplacePlugin(value.toObject(), &plugin, &errorText))
                    {
                        // 同 id 的在线条目替换初始快照，确保市场能独立维护版本、JDK 和文件哈希。
                        for (qsizetype index = m_marketplacePlugins.size(); index > 0; --index)
                        {
                            if (m_marketplacePlugins[index - 1].id == plugin.id)
                                m_marketplacePlugins.removeAt(index - 1);
                        }
                        m_marketplacePlugins.push_back(plugin);
                    }
                    else
                    {
                        ignoredEntries.push_back(errorText.isEmpty() ? QStringLiteral("无效条目") : errorText);
                    }
                }
                populateMarketplaceTable();
                selectMarketplaceEntry();
                const QList<MarketplacePlugin> updates = availableMarketplaceUpdates();
                QString status = QStringLiteral("插件商城已从 KSwordDEV/Plugins 刷新：%1 个可下载插件，%2 个插件可更新。")
                    .arg(m_marketplacePlugins.size())
                    .arg(updates.size());
                if (!ignoredEntries.isEmpty())
                {
                    status += QStringLiteral(
                        " 已忽略 %1 个无效条目；详情已写入日志。")
                        .arg(ignoredEntries.size());
                    kLogEvent ignoredEntryEvent;
                    warn << ignoredEntryEvent
                        << "[PluginHost] ignored marketplace entries, count="
                        << ignoredEntries.size()
                        << ", details="
                        << ignoredEntries
                            .join(QStringLiteral(" | "))
                            .toStdString()
                        << eol;
                }
                m_status->setText(status);
                if (checkForUpdates && !m_autoUpdateInProgress &&
                    m_autoUpdateCheck != nullptr && m_autoUpdateCheck->isChecked())
                {
                    beginAutomaticUpdates(updates);
                }
            });
        }

        void checkForUpdates()
        {
            if (m_autoUpdateInProgress)
            {
                m_status->setText(QStringLiteral("插件自动更新正在进行，请等待当前队列完成。"));
                return;
            }
            refreshPlugins();
            refreshMarketplace(true);
        }

        QString installedVersionFor(const MarketplacePlugin& plugin) const
        {
            const auto installed = m_installedPluginsById.constFind(plugin.id);
            return installed == m_installedPluginsById.cend() ? QString() : installed->version;
        }

        MarketplaceUpdateState updateStateFor(const MarketplacePlugin& plugin) const
        {
            return marketplaceUpdateState(installedVersionFor(plugin), plugin.version);
        }

        QString updateStateText(const MarketplacePlugin& plugin) const
        {
            const QString installedVersion = installedVersionFor(plugin);
            switch (updateStateFor(plugin))
            {
            case MarketplaceUpdateState::NotInstalled:
                return QStringLiteral("未安装");
            case MarketplaceUpdateState::Current:
                return QStringLiteral("已是最新（%1）").arg(installedVersion);
            case MarketplaceUpdateState::Available:
                return QStringLiteral("可更新：%1 → %2").arg(installedVersion, plugin.version);
            case MarketplaceUpdateState::NotComparable:
                return QStringLiteral("版本无法比较（本地 %1）").arg(installedVersion);
            }
            return QStringLiteral("未知");
        }

        QList<MarketplacePlugin> availableMarketplaceUpdates() const
        {
            QList<MarketplacePlugin> updates;
            for (const MarketplacePlugin& plugin : m_marketplacePlugins)
            {
                if (updateStateFor(plugin) == MarketplaceUpdateState::Available)
                {
                    updates.push_back(plugin);
                }
            }
            return updates;
        }

        void populateMarketplaceTable()
        {
            m_marketplaceTable->setRowCount(0);
            for (const MarketplacePlugin& plugin : m_marketplacePlugins)
            {
                const int row = m_marketplaceTable->rowCount();
                m_marketplaceTable->insertRow(row);
                m_marketplaceTable->setItem(row, 0, new QTableWidgetItem(plugin.name));
                m_marketplaceTable->setItem(row, 1, new QTableWidgetItem(plugin.version));
                m_marketplaceTable->setItem(row, 2, new QTableWidgetItem(updateStateText(plugin)));
                m_marketplaceTable->setItem(row, 3, new QTableWidgetItem(plugin.targets.join(QStringLiteral(", "))));
                m_marketplaceTable->setItem(row, 4, new QTableWidgetItem(plugin.licenseName));
                m_marketplaceTable->setItem(row, 5, new QTableWidgetItem(plugin.description));
            }
        }

        void selectMarketplaceEntry()
        {
            if (!m_preselectedPluginId.isEmpty())
            {
                for (int row = 0; row < m_marketplacePlugins.size(); ++row)
                {
                    if (m_marketplacePlugins[row].id != m_preselectedPluginId) continue;
                    m_marketplaceTable->selectRow(row);
                    m_mainTabs->setCurrentIndex(1);
                    m_preselectedPluginId.clear();
                    return;
                }
            }
            if (m_marketplaceTable->currentRow() < 0 && !m_marketplacePlugins.isEmpty()) m_marketplaceTable->selectRow(0);
        }

        bool hasMarketplaceLicenseAcceptanceRecord(const MarketplacePlugin& plugin) const
        {
            QSettings settings;
            return !settings.value(
                marketplaceLicenseAcceptanceKey(plugin)).toString().isEmpty();
        }

        bool hasAcceptedMarketplaceLicense(
            const MarketplacePlugin& plugin,
            const QByteArray& licensePayload) const
        {
            // 只有名称、URL 和本次实际下载正文都一致时，旧接受记录才仍然有效。
            QSettings settings;
            return settings.value(
                marketplaceLicenseAcceptanceKey(plugin)).toString()
                == marketplaceLicenseFingerprint(plugin, licensePayload);
        }

        void updateInstallProgress(const QString& stage, const int percent)
        {
            m_installProgress->setVisible(true);
            m_installProgress->setRange(0, 100);
            m_installProgress->setValue(qBound(0, percent, 100));
            m_installProgress->setFormat(stage + QStringLiteral("：%p%"));
        }

        void updateDownloadProgress(const MarketplacePlugin& plugin, const qint64 received, const qint64 total)
        {
            if (total <= 0)
            {
                m_installProgress->setVisible(true);
                m_installProgress->setRange(0, 0);
                m_installProgress->setFormat(QStringLiteral("正在下载 %1…").arg(plugin.name));
                return;
            }
            const int overallPercent = qBound(0, static_cast<int>((received * 70) / total), 70);
            updateInstallProgress(
                QStringLiteral("正在下载 %1（%2 / %3 MiB）")
                    .arg(plugin.name)
                    .arg(QString::number(received / (1024.0 * 1024.0), 'f', 1))
                    .arg(QString::number(total / (1024.0 * 1024.0), 'f', 1)),
                overallPercent);
        }

        void finishInstallProgress(const bool keepVisible = false)
        {
            if (keepVisible)
            {
                return;
            }
            QTimer::singleShot(1400, this, [this]() {
                if (!m_autoUpdateInProgress)
                {
                    m_installProgress->setVisible(false);
                }
            });
        }

        // requestMarketplaceLicensePayload：
        // - 输入 plugin/completion：商城插件和异步完成回调；
        // - 处理：下载实际许可证正文，并把网络错误或空正文统一归一化；
        // - 输出：回调收到成功标记、原始正文和可展示错误，不触发 ZIP 下载。
        void requestMarketplaceLicensePayload(
            const MarketplacePlugin& plugin,
            const std::function<void(bool, QByteArray, QString)>& completion)
        {
            QNetworkRequest request(plugin.licenseUrl);
            request.setHeader(
                QNetworkRequest::UserAgentHeader,
                QStringLiteral("KSword-PluginMarketplace/1"));
            QNetworkReply* reply = m_networkManager->get(request);
            connect(
                reply,
                &QNetworkReply::finished,
                this,
                [reply, plugin, completion]() {
                    const QByteArray payload = reply->readAll();
                    const bool networkOk =
                        reply->error() == QNetworkReply::NoError;
                    const QString failureMessage = networkOk
                        ? QStringLiteral("许可证正文为空。")
                        : networkReplyErrorText(reply);
                    reply->deleteLater();
                    // 上游许可证与实际安装文件共用固定哈希，内容变化必须由维护者更新清单。
                    if (plugin.upstreamAssets)
                    {
                        for (const auto& file : plugin.upstreamPlan.metadata)
                        {
                            if (file.url == plugin.licenseUrl && file.path ==
                                plugin.upstreamPlan.manifest.value(QStringLiteral("license")).toString())
                            {
                                const auto digest = QString::fromLatin1(QCryptographicHash::hash(payload, QCryptographicHash::Sha256).toHex());
                                if (payload.size() > file.maxBytes || digest.compare(file.sha256, Qt::CaseInsensitive) != 0)
                                {
                                    completion(false, {}, QStringLiteral("上游插件许可证 SHA-256 校验失败。"));
                                    return;
                                }
                            }
                        }
                    }
                    completion(
                        networkOk && !payload.isEmpty(),
                        payload,
                        failureMessage);
                });
        }

        void beginAutomaticUpdates(const QList<MarketplacePlugin>& updates)
        {
            m_autoUpdateQueue.clear();
            int pendingLicenseConfirmation = 0;
            for (const MarketplacePlugin& plugin : updates)
            {
                if (!plugin.upstreamAssets && hasMarketplaceLicenseAcceptanceRecord(plugin))
                {
                    m_autoUpdateQueue.push_back(plugin);
                }
                else
                {
                    ++pendingLicenseConfirmation;
                }
            }
            if (m_autoUpdateQueue.isEmpty())
            {
                m_status->setText(pendingLicenseConfirmation > 0
                    ? QStringLiteral("发现 %1 个更新；其中 %2 个需要确认当前许可证，未自动安装。")
                        .arg(updates.size())
                        .arg(pendingLicenseConfirmation)
                    : QStringLiteral("插件已是最新。"));
                return;
            }

            m_autoUpdateInProgress = true;
            m_autoUpdateTotal = m_autoUpdateQueue.size();
            m_autoUpdateCompleted = 0;
            m_autoUpdateFailures.clear();
            m_status->setText(QStringLiteral("开始自动更新 %1 个已授权插件。").arg(m_autoUpdateTotal));
            startNextAutomaticUpdate();
        }

        void startNextAutomaticUpdate()
        {
            if (m_autoUpdateQueue.isEmpty())
            {
                m_autoUpdateInProgress = false;
                refreshPlugins();
                populateMarketplaceTable();
                if (m_autoUpdateFailures.isEmpty())
                {
                    m_status->setText(QStringLiteral("已自动更新 %1 个插件。").arg(m_autoUpdateCompleted));
                    updateInstallProgress(QStringLiteral("自动更新完成"), 100);
                }
                else
                {
                    m_status->setText(QStringLiteral(
                        "自动更新完成：%1 个成功，%2 个失败；详情已写入日志。")
                        .arg(m_autoUpdateCompleted - m_autoUpdateFailures.size())
                        .arg(m_autoUpdateFailures.size()));
                    kLogEvent autoUpdateEvent;
                    warn << autoUpdateEvent
                        << "[PluginHost] automatic update completed with failures, completed="
                        << m_autoUpdateCompleted
                        << ", failureCount="
                        << m_autoUpdateFailures.size()
                        << ", failureDetails="
                        << m_autoUpdateFailures
                            .join(QStringLiteral(" | "))
                            .toStdString()
                        << eol;
                }
                finishInstallProgress();
                return;
            }

            const MarketplacePlugin plugin = m_autoUpdateQueue.takeFirst();
            const int current = m_autoUpdateTotal - m_autoUpdateQueue.size();
            updateInstallProgress(QStringLiteral("自动更新 %1（%2 / %3）").arg(plugin.name).arg(current).arg(m_autoUpdateTotal), 0);
            requestMarketplaceLicensePayload(
                plugin,
                [this, plugin](
                    const bool licenseReadOk,
                    const QByteArray licensePayload,
                    const QString& licenseError) {
                    if (!licenseReadOk
                        || !hasAcceptedMarketplaceLicense(
                            plugin,
                            licensePayload))
                    {
                        ++m_autoUpdateCompleted;
                        const QString failureMessage = licenseReadOk
                            ? QStringLiteral("许可证正文已变化，需要手动重新确认。")
                            : QStringLiteral("无法核验许可证：%1")
                                .arg(licenseError);
                        m_autoUpdateFailures.push_back(
                            QStringLiteral("%1：%2")
                                .arg(plugin.name, failureMessage));
                        startNextAutomaticUpdate();
                        return;
                    }

                    // 自动更新只有在本次正文哈希仍与接受记录一致时才下载 ZIP。
                    downloadMarketplaceArchive(
                        plugin,
                        [this, plugin](
                            const bool success,
                            const QString& message) {
                            ++m_autoUpdateCompleted;
                            if (!success)
                            {
                                m_autoUpdateFailures.push_back(
                                    QStringLiteral("%1：%2")
                                        .arg(plugin.name, message));
                            }
                            startNextAutomaticUpdate();
                        });
                });
        }

        void requestSelectedMarketplaceLicense()
        {
            if (m_upstreamInstaller || m_licenseRequestInProgress)
            {
                m_status->setText(QStringLiteral("上游插件安装正在进行，请等待或关闭窗口取消。"));
                return;
            }
            if (m_autoUpdateInProgress)
            {
                m_status->setText(QStringLiteral("插件自动更新正在进行，请等待当前队列完成。"));
                return;
            }
            const int row = m_marketplaceTable->currentRow();
            if (row < 0 || row >= m_marketplacePlugins.size())
            {
                QMessageBox::information(this, QStringLiteral("插件商城"), QStringLiteral("请先在“插件商城”中选择一个插件。"));
                return;
            }
            const MarketplacePlugin plugin = m_marketplacePlugins.at(row);
            m_licenseRequestInProgress = true;
            m_status->setText(QStringLiteral("正在读取 %1 的许可证；同意前不会下载或安装插件。").arg(plugin.name));
            requestMarketplaceLicensePayload(
                plugin,
                [this, plugin](
                    const bool success,
                    const QByteArray licensePayload,
                    const QString& errorMessage) {
                    m_licenseRequestInProgress = false;
                    if (!success)
                    {
                        QMessageBox::warning(
                            this,
                            QStringLiteral("插件商城"),
                            QStringLiteral("无法读取许可证：%1")
                                .arg(errorMessage));
                        return;
                    }
                    if (hasAcceptedMarketplaceLicense(
                            plugin,
                            licensePayload))
                    {
                        m_status->setText(
                            QStringLiteral("%1 的许可证正文未变化，继续下载安装。")
                                .arg(plugin.name));
                        downloadMarketplaceArchive(plugin);
                        return;
                    }
                    showLicenseAgreement(plugin, licensePayload);
                });
        }

        void showLicenseAgreement(
            const MarketplacePlugin& plugin,
            const QByteArray& licensePayload)
        {
            auto* licenseDialog = new QDialog(this);
            const QPointer<PluginManagerDialog> self(this);
            const QPointer<QDialog> licenseGuard(licenseDialog);
            licenseDialog->setWindowTitle(QStringLiteral("许可证：%1").arg(plugin.name));
            licenseDialog->resize(780, 620);
            auto* layout = new QVBoxLayout(licenseDialog);
            auto* label = new QLabel(QStringLiteral("安装 %1 前，请阅读并同意：%2。未同意不会发起插件 ZIP 下载。")
                .arg(plugin.name, plugin.licenseName), licenseDialog);
            label->setWordWrap(true);
            layout->addWidget(label);
            auto* text = new CodeTextEdit(licenseDialog);
            static_cast<CodeTextEdit*>(text)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
            text->setReadOnly(true);
            text->setPlainText(QString::fromUtf8(licensePayload));
            layout->addWidget(text, 1);
            auto* agree = new QCheckBox(QStringLiteral("我已阅读并同意上述插件许可证"), licenseDialog);
            layout->addWidget(agree);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, licenseDialog);
            QPushButton* acceptButton = buttons->addButton(QStringLiteral("同意并一键安装"), QDialogButtonBox::AcceptRole);
            acceptButton->setEnabled(false);
            layout->addWidget(buttons);
            connect(agree, &QCheckBox::toggled, acceptButton, &QPushButton::setEnabled);
            connect(buttons, &QDialogButtonBox::accepted, licenseDialog, &QDialog::accept);
            connect(buttons, &QDialogButtonBox::rejected, licenseDialog, &QDialog::reject);
            const auto decision = licenseDialog->exec();
            if (licenseGuard) licenseGuard->deleteLater();
            if (!self) return;
            if (decision != QDialog::Accepted)
            {
                m_status->setText(QStringLiteral("未同意许可证，未下载或安装 %1。").arg(plugin.name));
                return;
            }
            QSettings settings;
            settings.setValue(
                marketplaceLicenseAcceptanceKey(plugin),
                marketplaceLicenseFingerprint(plugin, licensePayload));
            downloadMarketplaceArchive(plugin);
        }

        void completeMarketplaceInstall(
            const InstallCompletion& completion,
            const bool success,
            const QString& message)
        {
            const QPointer<PluginManagerDialog> self(this);
            if (!success)
            {
                m_status->setText(QStringLiteral("插件安装失败：%1").arg(message));
                updateInstallProgress(QStringLiteral("安装失败"), 0);
                if (!completion)
                {
                    QMessageBox::warning(this, QStringLiteral("插件商城"), message);
                }
            }
            if (!self) return;
            if (completion)
            {
                completion(success, message);
            }
            else
            {
                finishInstallProgress();
            }
        }

        void downloadMarketplaceArchive(
            const MarketplacePlugin& plugin,
            InstallCompletion completion = {})
        {
            if (plugin.upstreamAssets)
            {
                installUpstreamAssets(plugin, completion);
                return;
            }
            m_status->setText(QStringLiteral("正在下载 %1；将校验 SHA-256 后一键安装。").arg(plugin.name));
            updateInstallProgress(QStringLiteral("正在下载 %1").arg(plugin.name), 0);
            QNetworkRequest request(plugin.archiveUrl);
            request.setHeader(QNetworkRequest::UserAgentHeader, QStringLiteral("KSword-PluginMarketplace/1"));
            QNetworkReply* reply = m_networkManager->get(request);
            connect(reply, &QNetworkReply::downloadProgress, this,
                [this, plugin](const qint64 received, const qint64 total) {
                    updateDownloadProgress(plugin, received, total);
                });
            connect(reply, &QNetworkReply::finished, this, [this, reply, plugin, completion]() {
                const QByteArray archiveBytes = reply->readAll();
                const bool networkOk = reply->error() == QNetworkReply::NoError;
                const QString networkError = networkOk ? QString() : networkReplyErrorText(reply);
                reply->deleteLater();
                if (!networkOk)
                {
                    completeMarketplaceInstall(completion, false, QStringLiteral("插件下载失败：%1").arg(networkError));
                    return;
                }
                if (archiveBytes.isEmpty() || archiveBytes.size() > kMaxMarketplaceArchiveBytes)
                {
                    completeMarketplaceInstall(completion, false, QStringLiteral("插件包为空或超过 256 MiB 限制。"));
                    return;
                }
                updateInstallProgress(QStringLiteral("正在校验 %1 的 SHA-256").arg(plugin.name), 75);
                const QString actualSha256 = QString::fromLatin1(QCryptographicHash::hash(archiveBytes, QCryptographicHash::Sha256).toHex());
                if (actualSha256.compare(plugin.sha256, Qt::CaseInsensitive) != 0)
                {
                    completeMarketplaceInstall(completion, false, QStringLiteral("SHA-256 校验失败，已拒绝安装插件。"));
                    return;
                }
                updateInstallProgress(QStringLiteral("SHA-256 校验通过"), 80);
                installMarketplaceArchive(plugin, archiveBytes, completion);
            });
        }

        void installUpstreamAssets(const MarketplacePlugin& plugin, const InstallCompletion& completion)
        {
            if (m_upstreamInstaller)
            {
                completeMarketplaceInstall(completion, false, QStringLiteral("上游插件安装已在进行。"));
                return;
            }
            auto* installer = new ks::plugin_host::UpstreamAssetInstaller(this,
                [](const QString& source) { return ks::i18n::sourceText(source); });
            installer->setObjectName(QStringLiteral("ksword_upstream_asset_installer"));
            m_upstreamInstaller = installer;
            const auto pluginRoot = resolvePluginInstallRoot();
            // 将生产清单解析器作为结构校验入口，安装阶段不执行任何插件。
            installer->start(pluginRoot, plugin.upstreamPlan,
                [plugin](const QString& stage, QString* error) {
                    PluginDescriptor descriptor;
                    return loadPluginManifestDirectory(stage, plugin.installDirectory, &descriptor, error);
                },
                [this](const QString& stage, int percent) {
                    updateInstallProgress(stage, percent);
                    m_status->setText(stage);
                },
                [this, plugin, pluginRoot, completion, installer](bool success, const QString& stage, const QString& error) {
                    m_upstreamInstaller.clear();
                    installer->deleteLater();
                    if (!success)
                    {
                        completeMarketplaceInstall(completion, false, error);
                        return;
                    }
                    QString installError;
                    const bool promoted = promoteExtractedPlugin(plugin, pluginRoot, stage, &installError);
                    // Stage is a generated sibling below this exact plugin root;
                    // successful root-layout promotion has already renamed it.
                    if (QFileInfo::exists(stage))
                    {
                        const auto canonicalRoot = QFileInfo(pluginRoot).canonicalFilePath();
                        const auto canonicalStage = QFileInfo(stage).canonicalFilePath();
                        if (!canonicalRoot.isEmpty() && canonicalStage.startsWith(canonicalRoot + QLatin1Char('/'), Qt::CaseInsensitive) &&
                            QFileInfo(stage).fileName().startsWith(QStringLiteral(".ksword-plugin-stage-%1-").arg(plugin.id)) && !QFileInfo(stage).isSymLink())
                            QDir(canonicalStage).removeRecursively();
                    }
                    if (!promoted)
                    {
                        completeMarketplaceInstall(completion, false, installError);
                        return;
                    }
                    refreshPlugins();
                    populateMarketplaceTable();
                    selectMarketplaceEntry();
                    const auto message = QStringLiteral("上游插件 %1 已安装到：%2").arg(plugin.name, QDir::toNativeSeparators(QDir(pluginRoot).filePath(plugin.installDirectory)));
                    m_status->setText(message);
                    updateInstallProgress(QStringLiteral("上游插件安装完成"), 100);
                    const QPointer<PluginManagerDialog> self(this);
                    if (!completion) QMessageBox::information(this, QStringLiteral("插件商城"), message);
                    if (!self) return;
                    completeMarketplaceInstall(completion, true, message);
                });
        }

        void installMarketplaceArchive(
            const MarketplacePlugin& plugin,
            const QByteArray& archiveBytes,
            const InstallCompletion& completion)
        {
            const QString pluginRoot = resolvePluginInstallRoot();
            if (!QDir().mkpath(pluginRoot))
            {
                completeMarketplaceInstall(completion, false, QStringLiteral("无法创建插件目录：%1")
                    .arg(QDir::toNativeSeparators(pluginRoot)));
                return;
            }

            {
                updateInstallProgress(QStringLiteral("正在准备 %1 的已验证安装包").arg(plugin.name), 84);
                const QString archivePath = QDir(pluginRoot).filePath(
                    QStringLiteral(".ksword-plugin-download-%1.zip")
                        .arg(QUuid::createUuid().toString(QUuid::WithoutBraces)));
                QSaveFile archiveFile(archivePath);
                if (!archiveFile.open(QIODevice::WriteOnly) ||
                    archiveFile.write(archiveBytes) != archiveBytes.size() ||
                    !archiveFile.commit())
                {
                    QFile::remove(archivePath);
                    completeMarketplaceInstall(completion, false,
                        QStringLiteral("无法准备已验证的插件包：%1").arg(archiveFile.errorString()));
                    return;
                }
                installVerifiedMarketplaceArchive(plugin, pluginRoot, archivePath, completion);
            }
        }

        void installVerifiedMarketplaceArchive(
            const MarketplacePlugin& plugin,
            const QString& pluginRoot,
            const QString& archivePath,
            const InstallCompletion& completion)
        {
            const QString stagingName = QStringLiteral(".ksword-plugin-stage-%1-%2")
                .arg(plugin.installDirectory, QUuid::createUuid().toString(QUuid::WithoutBraces));
            const QString stagingPath = QDir(pluginRoot).filePath(stagingName);
            if (!QDir().mkpath(stagingPath))
            {
                QFile::remove(archivePath);
                completeMarketplaceInstall(completion, false, QStringLiteral("无法创建插件安装暂存目录。"));
                return;
            }

            const QString powerShell = QStandardPaths::findExecutable(QStringLiteral("powershell.exe"));
            if (powerShell.isEmpty())
            {
                QDir(stagingPath).removeRecursively();
                QFile::remove(archivePath);
                completeMarketplaceInstall(completion, false, QStringLiteral("未找到 Windows PowerShell，无法解压插件包。"));
                return;
            }

            auto* extractor = new QProcess(this);
            extractor->setProcessChannelMode(QProcess::SeparateChannels);
            const QString command = QStringLiteral("$ErrorActionPreference='Stop'; Expand-Archive -LiteralPath %1 -DestinationPath %2 -Force")
                .arg(quotePowerShellLiteral(archivePath), quotePowerShellLiteral(stagingPath));
            extractor->setProgram(powerShell);
            extractor->setArguments(QStringList{
                QStringLiteral("-NoLogo"), QStringLiteral("-NoProfile"), QStringLiteral("-NonInteractive"),
                QStringLiteral("-Command"), command });
            m_status->setText(QStringLiteral("已验证 %1，正在安全解压并安装…").arg(plugin.name));
            updateInstallProgress(QStringLiteral("正在安全解压 %1").arg(plugin.name), 90);
            connect(extractor, &QProcess::errorOccurred, this,
                [this, extractor, archivePath, stagingPath, completion](const QProcess::ProcessError error) {
                    if (error != QProcess::FailedToStart) return;
                    QDir(stagingPath).removeRecursively();
                    QFile::remove(archivePath);
                    completeMarketplaceInstall(completion, false, QStringLiteral("无法启动插件解压器：%1")
                        .arg(extractor->errorString()));
                    extractor->deleteLater();
                });
            connect(extractor, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
                [this, extractor, archivePath, plugin, pluginRoot, stagingPath, completion](const int exitCode, const QProcess::ExitStatus exitStatus) {
                    const QString details = QString::fromLocal8Bit(extractor->readAllStandardError()).trimmed();
                    extractor->deleteLater();
                    QFile::remove(archivePath);
                    if (exitStatus != QProcess::NormalExit || exitCode != 0)
                    {
                        QDir(stagingPath).removeRecursively();
                        QString message = QStringLiteral("插件包解压失败（退出码 %1）。").arg(exitCode);
                        if (!details.isEmpty()) message += QStringLiteral("\n%1").arg(details);
                        completeMarketplaceInstall(completion, false, message);
                        return;
                    }

                    updateInstallProgress(QStringLiteral("正在验证并替换 %1").arg(plugin.name), 95);
                    QString installError;
                    const bool installed = promoteExtractedPlugin(plugin, pluginRoot, stagingPath, &installError);
                    QDir(stagingPath).removeRecursively();
                    if (!installed)
                    {
                        completeMarketplaceInstall(completion, false,
                            QStringLiteral("插件包已验证，但安装被拒绝：%1").arg(installError));
                        return;
                    }
                    refreshPlugins();
                    const QString message = QStringLiteral("已一键安装并验证 %1 到 %2。")
                        .arg(plugin.name, QDir::toNativeSeparators(QDir(pluginRoot).filePath(plugin.installDirectory)));
                    m_status->setText(message);
                    updateInstallProgress(QStringLiteral("%1 安装完成").arg(plugin.name), 100);
                    if (!completion)
                    {
                        QMessageBox::information(this, QStringLiteral("插件商城"), QStringLiteral("%1 已安装，可立即从“插件”菜单调用。")
                            .arg(plugin.name));
                    }
                    completeMarketplaceInstall(completion, true, message);
                });
            extractor->start();
        }

        QTableWidget* m_table = nullptr;
        QTabWidget* m_mainTabs = nullptr;
        QTableWidget* m_marketplaceTable = nullptr;
        QLabel* m_status = nullptr;
        QProgressBar* m_installProgress = nullptr;
        QCheckBox* m_autoUpdateCheck = nullptr;
        QPushButton* m_openFolderButton = nullptr;
        QNetworkAccessManager* m_networkManager = nullptr;
        QPointer<ks::plugin_host::UpstreamAssetInstaller> m_upstreamInstaller;
        QList<PluginDescriptor> m_plugins;
        QHash<QString, PluginDescriptor> m_installedPluginsById;
        QList<MarketplacePlugin> m_marketplacePlugins;
        QList<MarketplacePlugin> m_autoUpdateQueue;
        QStringList m_autoUpdateFailures;
        int m_autoUpdateTotal = 0;
        int m_autoUpdateCompleted = 0;
        bool m_autoUpdateInProgress = false;
        QString m_pluginRoot;
        QString m_preselectedPluginId;
        quint64 m_marketplaceGeneration = 0;
        bool m_licenseRequestInProgress = false;
    };
}

void ks::plugin_host::populateTargetMenu(QMenu* menu, QWidget* owner, const InvocationContext& context)
{
    if (menu == nullptr || owner == nullptr) return;
    menu->clear();
    menu->setToolTipsVisible(true);
    QString contextError;
    if (!isUsableContext(context, &contextError))
    {
        QAction* action = menu->addAction(contextError);
        action->setEnabled(false);
        return;
    }
    PluginListResult result;
    QString errorText;
    if (!discoverPlugins(&result, &errorText))
    {
        QAction* action = menu->addAction(QStringLiteral("插件不可用：%1").arg(errorText));
        action->setEnabled(false);
        return;
    }
    const QString target = targetName(context.targetKind);
    int addedActions = 0;
    for (const PluginDescriptor& descriptor : result.plugins)
    {
        if (descriptor.pluginType == QStringLiteral("backend")) continue;
        if (!descriptor.targets.contains(target)) continue;
        QAction* action = menu->addAction(descriptor.name);
        action->setToolTip(QStringLiteral("%1\nID：%2\n目标：%3")
            .arg(descriptor.description, descriptor.id, descriptor.targets.join(QStringLiteral(", "))));
        const InvocationContext boundContext = context; // 冻结菜单来源的原进程记录，避免 PID 复用重新授权。
        const bool debuggerProcessTarget = descriptor.id == QStringLiteral("x96dbg")
            && context.targetKind == TargetKind::Process;
        if (debuggerProcessTarget)
        {
            // 原记录没有创建时间时仅禁用导航；不从当前同号进程补齐旧目标的身份。
            action->setEnabled(ks::ui::x64dbg_navigation::HasCapturedIdentity(
                boundContext.processId, boundContext.processCreateTime100ns));
        }
        QObject::connect(action, &QAction::triggered, owner, [owner, descriptor, boundContext]() {
            if (descriptor.id == QStringLiteral("x96dbg") && boundContext.targetKind == TargetKind::Process)
            {
                if (!ks::ui::x64dbg_navigation::HasCapturedIdentity(
                        boundContext.processId, boundContext.processCreateTime100ns))
                {
                    return;
                }
                ks::ui::x64dbg_navigation::Open(owner,
                    {boundContext.processId, boundContext.processCreateTime100ns,
                        boundContext.memoryAddress,
                        boundContext.navigateMemoryDump
                            ? ks::ui::x64dbg_navigation::View::Dump
                            : ks::ui::x64dbg_navigation::View::Disassembly});
                return;
            }
            launchPlugin(owner, descriptor, boundContext);
        });
        ++addedActions;
    }
    if (addedActions == 0)
    {
        QString emptyText;
        switch (context.targetKind)
        {
        case TargetKind::File: emptyText = QStringLiteral("没有声明支持文件目标的插件"); break;
        case TargetKind::Process: emptyText = QStringLiteral("没有声明支持进程目标的插件"); break;
        case TargetKind::Network: emptyText = QStringLiteral("没有声明支持网络目标的插件"); break;
        }
        QAction* action = menu->addAction(emptyText);
        action->setEnabled(false);
    }
}

int ks::plugin_host::populateTabPlugins(QTabWidget* tabWidget, QWidget* owner)
{
    if (tabWidget == nullptr || owner == nullptr)
    {
        return 0;
    }
    PluginListResult result;
    QString errorText;
    if (!discoverPlugins(&result, &errorText))
    {
        return 0;
    }
    int addedTabs = 0;
    for (const PluginDescriptor& descriptor : result.plugins)
    {
        if ((descriptor.pluginType != QStringLiteral("tab") &&
             descriptor.pluginType != QStringLiteral("hybrid")) ||
            !descriptor.tabPresentation.enabled ||
            !descriptor.targets.contains(QStringLiteral("tab")))
        {
            continue;
        }
        auto* page = new PluginTabPage(tabWidget, descriptor);
        page->setProperty("kswordPluginId", descriptor.id);
        tabWidget->addTab(
            page,
            QIcon(QStringLiteral(":/Icon/process_start.svg")),
            descriptor.tabPresentation.title);
        tabWidget->setTabToolTip(tabWidget->indexOf(page), descriptor.description);
        ++addedTabs;
    }
    return addedTabs;
}

namespace
{
    // hostWindowIsLayered 作用：
    // - 判断控件所在顶层窗口当前是否为分层窗口（WS_EX_LAYERED）。
    // 为什么以此为判据而不是读 backgroundTransparencyEnabled 配置：
    // - 背景透明只能在原生窗口创建前声明，改了配置但尚未重启时，
    //   配置值与窗口实际状态并不一致；
    // - 真正决定 Tab 插件能否显示的是窗口此刻是否分层。
    // 入参 widgetValue：任意已挂到窗口树上的控件。
    // 返回值：顶层窗口带 WS_EX_LAYERED 返回 true；无法判定时返回 false（按可用处理）。
    bool hostWindowIsLayered(const QWidget* widgetValue)
    {
        if (widgetValue == nullptr)
        {
            return false;
        }
        const QWidget* topLevelWidget = widgetValue->window();
        if (topLevelWidget == nullptr || !topLevelWidget->isVisible())
        {
            return false;
        }
        const HWND topLevelHandle =
            reinterpret_cast<HWND>(const_cast<QWidget*>(topLevelWidget)->winId());
        if (topLevelHandle == nullptr || ::IsWindow(topLevelHandle) == FALSE)
        {
            return false;
        }
        const LONG_PTR extendedStyle = ::GetWindowLongPtrW(topLevelHandle, GWL_EXSTYLE);
        return (extendedStyle & WS_EX_LAYERED) != 0;
    }

    // PluginContainerShowWatcher 作用：
    // - 在插件容器每次显示时回调，用于复查背景透明告警条是否该出现；
    // - 容器创建时往往还没挂进窗口树，只有显示后才查得到顶层窗口句柄。
    // 说明：只重写虚函数、不声明信号槽，因此无需 Q_OBJECT 与 moc 参与构建。
    class PluginContainerShowWatcher final : public QObject
    {
    public:
        PluginContainerShowWatcher(QObject* parentObject, std::function<void()> callbackValue)
            : QObject(parentObject)
            , m_callback(std::move(callbackValue))
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventValue) override
        {
            if (eventValue->type() == QEvent::Show && m_callback)
            {
                m_callback();
            }
            return QObject::eventFilter(watchedObject, eventValue);
        }

    private:
        std::function<void()> m_callback; // 显示时执行的复查回调。
    };
}

QWidget* ks::plugin_host::createTabPluginContainer(QWidget* parent)
{
    auto* container = new QWidget(parent);
    container->setObjectName(QStringLiteral("ksTabPluginContainer"));

    auto* rootLayout = new QVBoxLayout(container);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // 背景透明告警条：
    // Tab 插件的画面由外部进程的 WS_CHILD 原生子窗口承载，而 Windows 的分层窗口
    // （WA_TranslucentBackground + FramelessWindowHint 的组合结果）整窗由
    // UpdateLayeredWindow 一次性合成，不会绘制原生子窗口——插件窗口存在、也收得到
    // 消息，但永远画不出来。这是平台行为，样式层无法规避，只能如实告知。
    auto* transparencyWarningBanner = new QWidget(container);
    transparencyWarningBanner->setObjectName(QStringLiteral("ksTabPluginTransparencyWarning"));
    auto* warningLayout = new QHBoxLayout(transparencyWarningBanner);
    warningLayout->setContentsMargins(10, 6, 10, 6);
    warningLayout->setSpacing(8);
    auto* warningLabel = new QLabel(
        ks::i18n::text(
            QStringLiteral("plugin.tab.transparency.warning"),
            // 整句写成单个字面量：i18n 审计逐个字面量提取，拆行会把同一句话
            // 割成两条词条，翻译时无法保证语序。
            QStringLiteral("已开启背景透明：Windows 分层窗口不会绘制插件的原生子窗口，Tab 插件可能无法显示或显示异常。如需使用，请在「设置 → 外观」关闭背景透明后重启程序。")),
        transparencyWarningBanner);
    warningLabel->setObjectName(QStringLiteral("ksTabPluginTransparencyWarningText"));
    warningLabel->setWordWrap(true);
    warningLayout->addWidget(warningLabel, 1);
    transparencyWarningBanner->setVisible(false);
    rootLayout->addWidget(transparencyWarningBanner, 0);

    auto* tabWidget = new QTabWidget(container);
    tabWidget->setObjectName(QStringLiteral("ksTabPluginHost"));
    tabWidget->setDocumentMode(true);
    tabWidget->setMovable(false);
    tabWidget->setTabsClosable(false);
    rootLayout->addWidget(tabWidget, 1);

    // 宿主侧基础样式只锚定插件容器，不污染其它 Dock 或插件原生子窗口。
    const QString pluginContainerStyle = QStringLiteral(
        "QWidget#ksTabPluginContainer{background-color:%1;color:%2;}"
        "QTabWidget#ksTabPluginHost::pane{background-color:%1;border:none;}"
        "QTabWidget#ksTabPluginHost QTabBar::tab{background-color:%4;color:%2;border:none;"
        "border-radius:0;padding:3px 12px;min-height:22px;margin:0;}"
        "QTabWidget#ksTabPluginHost QTabBar::tab:selected{background-color:%5;color:%6;font-weight:700;}"
        "QTabWidget#ksTabPluginHost QTabBar::tab:hover:!selected{background-color:%7;}"
        "QWidget#ksTabPluginEmptyState{background-color:%1;color:%2;}"
        "QLabel#ksTabPluginEmptyTitle{color:%2;font-size:16px;font-weight:600;}"
        "QLabel#ksTabPluginEmptyHint{color:%8;}"
        "QPushButton#ksTabPluginManageButton{background-color:%5;color:%6;border:1px solid %5;"
        "border-radius:3px;padding:4px 10px;font-weight:600;}"
        "QPushButton#ksTabPluginManageButton:hover{background-color:%9;border-color:%9;}"
        "QPushButton#ksTabPluginManageButton:pressed{background-color:%10;border-color:%10;}"
        "QWidget#ksTabPluginTransparencyWarning{background-color:%11;border:1px solid %12;"
        "border-radius:3px;margin:6px 6px 0 6px;}"
        "QLabel#ksTabPluginTransparencyWarningText{color:%12;}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::SurfaceAltHex())
        .arg(KswordTheme::ActiveTabBackgroundHex())
        .arg(KswordTheme::ActiveTabTextHex())
        .arg(KswordTheme::SurfaceMutedColorHex())
        .arg(KswordTheme::TextSecondaryHex())
        .arg(KswordTheme::PrimaryBlueSolidHoverHex())
        .arg(KswordTheme::PrimaryBluePressedHex)
        .arg(KswordTheme::ThemeColorName(KswordTheme::WarningBackgroundColor()))
        .arg(KswordTheme::WarningHex());
    container->setStyleSheet(pluginContainerStyle);

    // 容器创建时可能还没挂进窗口树，顶层窗口句柄尚不可查；
    // 放到事件循环下一轮再判定，并在每次显示时复查（切换 Dock 后仍准确）。
    const auto refreshTransparencyWarning =
        [container, transparencyWarningBanner]()
        {
            transparencyWarningBanner->setVisible(hostWindowIsLayered(container));
        };
    QTimer::singleShot(0, container, refreshTransparencyWarning);
    container->installEventFilter(new PluginContainerShowWatcher(container, refreshTransparencyWarning));

    if (populateTabPlugins(tabWidget, container) == 0)
    {
        auto* emptyPage = new QWidget(tabWidget);
        emptyPage->setObjectName(QStringLiteral("ksTabPluginEmptyState"));
        auto* emptyLayout = new QVBoxLayout(emptyPage);
        emptyLayout->setContentsMargins(24, 24, 24, 24);
        emptyLayout->setSpacing(10);
        emptyLayout->addStretch(1);

        auto* titleLabel = new QLabel(
            ks::i18n::text(QStringLiteral("plugin.tab.empty.title"), QStringLiteral("尚未安装 Tab 型插件")),
            emptyPage);
        titleLabel->setObjectName(QStringLiteral("ksTabPluginEmptyTitle"));
        titleLabel->setAlignment(Qt::AlignCenter);
        emptyLayout->addWidget(titleLabel);

        auto* hintLabel = new QLabel(
            ks::i18n::text(
                QStringLiteral("plugin.tab.empty.hint"),
                QStringLiteral("请从插件管理器安装 Tab 型插件，安装完成后重启 KSword。")),
            emptyPage);
        hintLabel->setObjectName(QStringLiteral("ksTabPluginEmptyHint"));
        hintLabel->setAlignment(Qt::AlignCenter);
        hintLabel->setWordWrap(true);
        emptyLayout->addWidget(hintLabel);

        auto* buttonRow = new QHBoxLayout();
        buttonRow->addStretch(1);
        auto* manageButton = new QPushButton(
            ks::i18n::text(QStringLiteral("plugin.tab.empty.manage"), QStringLiteral("打开插件管理器")),
            emptyPage);
        manageButton->setObjectName(QStringLiteral("ksTabPluginManageButton"));
        buttonRow->addWidget(manageButton);
        buttonRow->addStretch(1);
        emptyLayout->addLayout(buttonRow);
        emptyLayout->addStretch(1);

        QObject::connect(manageButton, &QPushButton::clicked, emptyPage, [emptyPage]() {
            ks::plugin_host::showPluginManager(emptyPage);
        });
        tabWidget->addTab(
            emptyPage,
            ks::i18n::text(QStringLiteral("plugin.tab.empty.overview"), QStringLiteral("概览")));
    }

    return container;
}
void ks::plugin_host::showPluginManager(QWidget* owner, const QString& preselectedPluginId)
{
    auto* dialog = new PluginManagerDialog(owner, preselectedPluginId);
    dialog->show();
    dialog->raise();
    dialog->activateWindow();
}
