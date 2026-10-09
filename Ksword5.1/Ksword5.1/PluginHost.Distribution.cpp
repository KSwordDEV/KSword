#include "PluginHost.Distribution.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QStringList>
#include <cmath>

namespace ks::plugin_host
{
    namespace
    {
        // 将协议错误传回调用方；协议模块不产生 UI 或日志副作用。
        bool reject(QString* error, const char* code)
        {
            if (error) *error = QString::fromLatin1(code);
            return false;
        }

        // HTTPS 不允许用户信息、非标准端口、查询或片段。
        bool plainHttps(const QUrl& url)
        {
            return url.isValid() && url.scheme() == QStringLiteral("https") &&
                url.userInfo().isEmpty() && (url.port(-1) == -1 || url.port() == 443) &&
                !url.hasQuery() && !url.hasFragment();
        }

        // 仓库身份只允许 owner/name；URL 的前两个路径段必须逐字对应。
        bool repositoryName(const QString& repository)
        {
            static const QRegularExpression pattern(QStringLiteral("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"));
            const auto parts = repository.split(u'/');
            return pattern.match(repository).hasMatch() && parts.size() == 2 &&
                parts[0] != QStringLiteral(".") && parts[0] != QStringLiteral("..") &&
                parts[1] != QStringLiteral(".") && parts[1] != QStringLiteral("..");
        }

        // 只接受明确标签下的 ZIP 文件，不允许 latest、API 或源码归档路径。
        bool releaseUrl(const QUrl& url, const QString& repository)
        {
            const auto parts = url.path().split(u'/', Qt::KeepEmptyParts);
            return plainHttps(url) && url.host() == QStringLiteral("github.com") &&
                repositoryName(repository) && parts.size() == 7 && parts[0].isEmpty() &&
                parts[1] + u'/' + parts[2] == repository &&
                parts[3] == QStringLiteral("releases") && parts[4] == QStringLiteral("download") &&
                safeUpstreamPath(parts[5]) && parts[5].compare(QStringLiteral("latest"), Qt::CaseInsensitive) != 0 &&
                safeUpstreamPath(parts[6]) && parts[6].endsWith(QStringLiteral(".zip"), Qt::CaseInsensitive);
        }

        // 数字预算必须是 JSON 整数，不能用负数、字符串或截断的小数绕过限制。
        bool byteBudget(const QJsonValue& value, qint64 maximum, qint64* output)
        {
            const double number = value.toDouble(-1);
            if (!value.isDouble() || !std::isfinite(number) || number < 1 ||
                number > static_cast<double>(maximum) || std::floor(number) != number) return false;
            *output = static_cast<qint64>(number);
            return true;
        }

        // 禁止两个输出命名空间交叠，避免 ZIP 或元数据覆盖另一个组件。
        bool overlaps(const QString& first, const QString& second)
        {
            return first.compare(second, Qt::CaseInsensitive) == 0 ||
                first.startsWith(second + u'/', Qt::CaseInsensitive) ||
                second.startsWith(first + u'/', Qt::CaseInsensitive);
        }
    }

    bool safeUpstreamPath(const QString& path)
    {
        if (path.isEmpty() || path.size() > 240 || path.contains(u'\\') || path.startsWith(u'/')) return false;
        // 所有路径段排除 Windows 别名、控制字符及结尾空格/点。
        static const QRegularExpression invalid(QStringLiteral("[\\x00-\\x1f:<>\"|?*]"));
        static const QRegularExpression device(QStringLiteral("^(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\\..*)?$"),
            QRegularExpression::CaseInsensitiveOption);
        for (const auto& part : path.split(u'/'))
        {
            if (part.isEmpty() || part == QStringLiteral(".") || part == QStringLiteral("..") ||
                part.endsWith(u'.') || part.endsWith(u' ') || invalid.match(part).hasMatch() ||
                device.match(part).hasMatch() || part.startsWith(QStringLiteral(".archives"), Qt::CaseInsensitive)) return false;
        }
        return true;
    }

    bool validUpstreamSha256(const QString& digest)
    {
        static const QRegularExpression pattern(QStringLiteral("^[0-9A-Fa-f]{64}$"));
        return pattern.match(digest).hasMatch();
    }

    bool approvedUpstreamRedirect(const QUrl& url, const QUrl& original)
    {
        // Release CDN 的签名查询是 GitHub 正常跳转的一部分；仍限定 HTTPS 与 CDN 域。
        if (!url.isValid() || url.scheme() != QStringLiteral("https") || !url.userInfo().isEmpty() ||
            (url.port(-1) != -1 && url.port() != 443) || url.hasFragment()) return false;
        if (url == original) return true;
        if (original.host() == QStringLiteral("raw.githubusercontent.com")) return false;
        return url.host() == QStringLiteral("release-assets.githubusercontent.com") ||
            url.host() == QStringLiteral("objects.githubusercontent.com");
    }

    bool parseUpstreamDistribution(const QJsonObject& object, const QString& id,
        UpstreamPlan* plan, QString* error)
    {
        // 首先核对协议、平台、插件身份及清单预算，未知平台不会被安装。
        if (!plan || !object.value(QStringLiteral("type")).isString() ||
            object.value(QStringLiteral("type")).toString() != QStringLiteral("upstream-assets") ||
            object.value(QStringLiteral("platform")).toString() != QStringLiteral("windows-x64"))
            return reject(error, "upstream_type_or_platform_invalid");
        UpstreamPlan parsed;
        parsed.id = id;
        parsed.manifest = object.value(QStringLiteral("manifest")).toObject();
        parsed.description = object;
        static const QRegularExpression pluginId(QStringLiteral("^[a-z0-9][a-z0-9-]{0,63}$"));
        if (!pluginId.match(id).hasMatch() || parsed.manifest.value(QStringLiteral("id")).toString() != id ||
            parsed.manifest.value(QStringLiteral("ksword_plugin_api")).toString() != QStringLiteral("1") ||
            QJsonDocument(object).toJson().size() > 64 * 1024)
            return reject(error, "upstream_manifest_invalid");
        for (const auto* field : {"name", "version", "description", "runtime"})
        {
            if (parsed.manifest.value(QLatin1String(field)).toString().trimmed().isEmpty())
                return reject(error, "upstream_manifest_invalid");
        }
        // 运行协议沿用现有清单；完整文件结构将在下载完成后由宿主验证。
        const auto runtime = parsed.manifest.value(QStringLiteral("runtime")).toString();
        const auto pluginType = parsed.manifest.value(QStringLiteral("plugin_type")).toString(QStringLiteral("command"));
        if (runtime != QStringLiteral("executable") && runtime != QStringLiteral("python") &&
            !(id == QStringLiteral("ghidra") && runtime == QStringLiteral("ghidra") && pluginType == QStringLiteral("backend")))
            return reject(error, "upstream_runtime_invalid");
        // 声明的仓库作为维护者审核后的发布者身份；每个 URL 必须绑定该仓库。
        const auto assets = object.value(QStringLiteral("assets")).toArray();
        if (assets.isEmpty() || assets.size() > 8) return reject(error, "upstream_assets_invalid");
        QStringList outputs {QStringLiteral("plugin.json"), QStringLiteral("upstream-install.json")};
        QStringList repositories {QStringLiteral("KSwordDEV/Plugins"), QStringLiteral("KSwordDEV/KSword")};
        for (const auto& value : assets)
        {
            const auto assetObject = value.toObject();
            UpstreamAsset asset;
            asset.name = assetObject.value(QStringLiteral("name")).toString();
            asset.url = QUrl(assetObject.value(QStringLiteral("url")).toString());
            asset.sha256 = assetObject.value(QStringLiteral("sha256")).toString();
            asset.repository = assetObject.value(QStringLiteral("repository")).toString();
            asset.rootDirectory = assetObject.value(QStringLiteral("root_directory")).toString();
            asset.destinationDirectory = assetObject.value(QStringLiteral("destination_directory")).toString();
            if (asset.name.isEmpty() || !releaseUrl(asset.url, asset.repository) || !validUpstreamSha256(asset.sha256) ||
                !safeUpstreamPath(asset.rootDirectory) || asset.rootDirectory.contains(u'/') ||
                !safeUpstreamPath(asset.destinationDirectory) ||
                !byteBudget(assetObject.value(QStringLiteral("max_archive_bytes")), 1024LL * 1024 * 1024, &asset.maxArchiveBytes))
                return reject(error, "upstream_asset_invalid");
            // 按完整目标目录保留官方树；各组件不能共享或嵌套落点。
            for (const auto& output : outputs)
                if (overlaps(output, asset.destinationDirectory)) return reject(error, "upstream_output_collision");
            outputs.append(asset.destinationDirectory);
            repositories.append(asset.repository);
            parsed.assets.append(asset);
        }
        // 可执行入口和后端路径必须来自官方 ZIP 树，不能指向 plugins 提供的元数据。
        const auto inAsset = [&parsed](const QString& path) {
            if (!safeUpstreamPath(path)) return false;
            for (const auto& asset : parsed.assets)
            {
                const auto root = asset.destinationDirectory + u'/' + asset.rootDirectory;
                if (path == root || path.startsWith(root + u'/')) return true;
            }
            return false;
        };
        if (pluginType == QStringLiteral("backend"))
        {
            if (!inAsset(parsed.manifest.value(QStringLiteral("runtime_root")).toString()) ||
                !inAsset(parsed.manifest.value(QStringLiteral("java_executable")).toString()))
                return reject(error, "upstream_entrypoint_invalid");
        }
        else if (!inAsset(parsed.manifest.value(QStringLiteral("entrypoint")).toString()))
            return reject(error, "upstream_entrypoint_invalid");
        // 仅接收源仓库或 KSword 元数据仓库的 raw 文本，禁止下载脚本作为安装步骤。
        const auto metadata = object.value(QStringLiteral("metadata")).toArray();
        if (metadata.isEmpty() || metadata.size() > 16) return reject(error, "upstream_metadata_invalid");
        bool hasLicense = false;
        const auto license = parsed.manifest.value(QStringLiteral("license")).toString();
        if (!safeUpstreamPath(license)) return reject(error, "upstream_license_invalid");
        for (const auto& value : metadata)
        {
            const auto metadataObject = value.toObject();
            UpstreamMetadata file;
            file.path = metadataObject.value(QStringLiteral("path")).toString();
            file.url = QUrl(metadataObject.value(QStringLiteral("url")).toString());
            file.sha256 = metadataObject.value(QStringLiteral("sha256")).toString();
            const auto parts = file.url.path().split(u'/', Qt::KeepEmptyParts);
            const auto leaf = file.path.section(u'/', -1);
            const bool textFile = leaf.endsWith(QStringLiteral(".txt"), Qt::CaseInsensitive) ||
                leaf.endsWith(QStringLiteral(".md"), Qt::CaseInsensitive) ||
                leaf.endsWith(QStringLiteral(".json"), Qt::CaseInsensitive) ||
                leaf == QStringLiteral("LICENSE") || leaf == QStringLiteral("NOTICE");
            if (!textFile || !safeUpstreamPath(file.path) || !plainHttps(file.url) ||
                file.url.host() != QStringLiteral("raw.githubusercontent.com") || parts.size() < 5 ||
                !repositories.contains(parts[1] + u'/' + parts[2]) || parts[3].isEmpty() ||
                !safeUpstreamPath(parts.mid(3).join(u'/')) || !validUpstreamSha256(file.sha256) ||
                !byteBudget(metadataObject.value(QStringLiteral("max_bytes")), 1024 * 1024, &file.maxBytes))
                return reject(error, "upstream_metadata_invalid");
            for (const auto& output : outputs)
                if (overlaps(output, file.path)) return reject(error, "upstream_output_collision");
            outputs.append(file.path);
            hasLicense |= file.path == license;
            parsed.metadata.append(file);
        }
        if (!hasLicense) return reject(error, "upstream_license_missing");
        *plan = parsed;
        if (error) error->clear();
        return true;
    }
}
