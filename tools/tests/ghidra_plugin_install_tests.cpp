// The parser/promotion definitions below are copied verbatim from the source
// tree under test. Runtime profile and native ZIP installer are linked normally.
// ZIPs contain inert dummy runtime files; no Java/Ghidra/sample is executed.
#include <QtCore/QtCore>
#include <Windows.h>
#include "GhidraRuntimePlugin/RuntimeProfile.h"
#include "Ksword5.1/Ksword5.1/PluginHost.Upstream.h"
#include "production_plugin_helpers.inc"
#include <cstdio>
#include <cstdlib>

namespace
{
    unsigned checks = 0;
    QString caseRoot;
    QString inertExecutable;
    using Plan = ks::plugin_host::UpstreamPlan;
    using Asset = ks::plugin_host::UpstreamAsset;

    void check(bool value, const char* description)
    {
        ++checks;
        if (!value) { std::fprintf(stderr, "FAIL [%u] %s\n", checks, description); std::exit(1); }
    }
    void put(const QString& path, const QByteArray& bytes)
    {
        if (!QDir().mkpath(QFileInfo(path).absolutePath())) { std::fprintf(stderr, "Fixture mkdir failed\n"); std::exit(2); }
        QFile file(path);
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size()) {
            std::fprintf(stderr, "Fixture write failed\n"); std::exit(2);
        }
    }
    QByteArray get(const QString& path)
    {
        QFile file(path);
        return file.open(QIODevice::ReadOnly) ? file.readAll() : QByteArray();
    }
    QByteArray inertPe()
    {
        return get(inertExecutable); // Compiled by this runner; never executed here.
    }
    void fixtureRuntime(const QString& path, bool metadata = true)
    {
        using namespace ks::plugin_host::ghidra_runtime;
        const auto object = manifest();
        const auto ghidra = object.value(QStringLiteral("runtime_root")).toString() + u'/';
        const auto java = object.value(QStringLiteral("java_executable")).toString();
        const auto jdk = java.left(java.size() - QStringLiteral("bin/java.exe").size());
        put(path + u'/' + ghidra + QStringLiteral("Ghidra/Framework/Utility/lib/Utility.jar"), "inert fixture jar");
        put(path + u'/' + ghidra + QStringLiteral("Ghidra/application.properties"), "application.version=12.0.4\n");
        put(path + u'/' + ghidra + QStringLiteral("Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe"), inertPe());
        put(path + u'/' + ghidra + QStringLiteral("Ghidra/Features/Decompiler/LICENSE.txt"), "fixture GPLv3 license marker\n");
        put(path + u'/' + ghidra + QStringLiteral("LICENSE"), "fixture upstream license marker\n");
        put(path + u'/' + ghidra + QStringLiteral("NOTICE"), "fixture upstream notice marker\n");
        put(path + u'/' + ghidra + QStringLiteral("licenses/fixture.txt"), "fixture component license\n");
        put(path + u'/' + ghidra + QStringLiteral("GPL/fixture.txt"), "fixture GPL component source marker\n");
        put(path + u'/' + java, inertPe());
        put(path + u'/' + jdk + QStringLiteral("release"),
            "JAVA_VERSION=\"21.0.12.1\"\nOS_ARCH=\"x86_64\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n");
        put(path + u'/' + jdk + QStringLiteral("NOTICE"), "fixture JDK notice\n");
        put(path + u'/' + jdk + QStringLiteral("legal/java.base/LICENSE"), "fixture GPLv2 license marker\n");
        put(path + u'/' + jdk + QStringLiteral("legal/java.base/ADDITIONAL_LICENSE_INFO"), "fixture classpath exception marker\n");
        put(path + u'/' + jdk + QStringLiteral("lib/src.zip"), "fixture source archive marker\n");
        if (metadata) {
            QString error;
            check(writePackageMetadata(path, &error), "canonical runtime metadata can be written into its owned stage");
        }
    }
    void metadataAndParser()
    {
        using namespace ks::plugin_host::ghidra_runtime;
        const auto path = caseRoot + QStringLiteral("/canonical");
        fixtureRuntime(path);
        QString error;
        check(validateDirectory(path, &error), "complete inert runtime validates without executing any binary");
        check(!writePackageMetadata(path, &error), "metadata writer cannot silently replace files in an existing package");
        PluginDescriptor descriptor;
        check(loadPluginManifestDirectory(path, QStringLiteral("ghidra"), &descriptor, &error),
            "production manager recognizes the standalone Ghidra backend plugin");
        check(descriptor.pluginType == QStringLiteral("backend") && descriptor.runtime == QStringLiteral("ghidra")
            && descriptor.targets == QStringList{QStringLiteral("decompiler")}
            && descriptor.entrypointPath.isEmpty() && descriptor.defaultCommand.isEmpty()
            && !descriptor.tabPresentation.enabled && !descriptor.visualization.enabled,
            "backend plugin has no ordinary executable command or separate UI tab");
        const QList<QPair<QString, QJsonValue>> faults {
            {QStringLiteral("entrypoint"), QStringLiteral("jdk/jdk-21.0.12.1+1/bin/java.exe")},
            {QStringLiteral("default_command"), QStringLiteral("info")},
            {QStringLiteral("tab"), QJsonObject{}},
            {QStringLiteral("visualization"), QJsonObject{}},
            {QStringLiteral("targets"), QJsonArray{QStringLiteral("process")}},
            {QStringLiteral("runtime"), QStringLiteral("executable")},
            {QStringLiteral("runtime_root"), QStringLiteral("../outside")},
            {QStringLiteral("java_executable"), QStringLiteral("C:/outside/java.exe")}
        };
        for (const auto& fault : faults) {
            auto changed = manifest(); changed.insert(fault.first, fault.second);
            put(path + QStringLiteral("/plugin.json"), QJsonDocument(changed).toJson());
            check(!loadPluginManifestDirectory(path, QStringLiteral("ghidra"), &descriptor, &error)
                && !error.isEmpty(), "invalid backend behavior and escaping runtime paths reject through the real manager");
        }
        auto executableGhidra = manifest();
        executableGhidra.insert(QStringLiteral("plugin_type"), QStringLiteral("command"));
        executableGhidra.insert(QStringLiteral("runtime"), QStringLiteral("executable"));
        executableGhidra.insert(QStringLiteral("entrypoint"), QStringLiteral("jdk/jdk-21.0.12.1+1/bin/java.exe"));
        executableGhidra.insert(QStringLiteral("default_command"), QStringLiteral("info"));
        executableGhidra.insert(QStringLiteral("targets"), QJsonArray{QStringLiteral("process")});
        put(path + QStringLiteral("/plugin.json"), QJsonDocument(executableGhidra).toJson());
        check(!loadPluginManifestDirectory(path, QStringLiteral("ghidra"), &descriptor, &error),
            "reserved Ghidra id cannot be rewritten as an ordinary executable plugin");
        put(path + QStringLiteral("/plugin.json"), QJsonDocument(manifest()).toJson());
        const auto java = path + u'/' + manifest().value(QStringLiteral("java_executable")).toString();
        check(QFile::remove(java) && !validateDirectory(path, &error), "missing bundled Java rejects incomplete installation");
        put(java, inertPe());
        check(QFile::remove(path + QStringLiteral("/NOTICE.md")) && !validateDirectory(path, &error),
            "missing license notice prevents an apparently complete backend package");
        put(path + QStringLiteral("/NOTICE.md"), noticeText());
        check(validateDirectory(path, &error), "repairing real required components restores runtime readiness");

        const auto legacy = caseRoot + QStringLiteral("/legacy");
        put(legacy + QStringLiteral("/fixture.exe"), inertPe());
        put(legacy + QStringLiteral("/plugin.json"), QJsonDocument(QJsonObject{
            {QStringLiteral("ksword_plugin_api"), QStringLiteral("1")}, {QStringLiteral("id"), QStringLiteral("legacy")},
            {QStringLiteral("name"), QStringLiteral("Existing executable")}, {QStringLiteral("version"), QStringLiteral("1.0")},
            {QStringLiteral("description"), QStringLiteral("existing protocol fixture")},
            {QStringLiteral("runtime"), QStringLiteral("executable")}, {QStringLiteral("entrypoint"), QStringLiteral("fixture.exe")},
            {QStringLiteral("default_command"), QStringLiteral("info")},
            {QStringLiteral("targets"), QJsonArray{QStringLiteral("process")}}}).toJson());
        check(loadPluginManifestDirectory(legacy, QStringLiteral("legacy"), &descriptor, &error)
            && descriptor.pluginType == QStringLiteral("command") && !descriptor.entrypointPath.isEmpty(),
            "existing executable plugin parsing remains compatible");
        std::puts("Plugin metadata/parser checks completed");
    }

    void promotion()
    {
        const MarketplacePlugin plugin{.id=QStringLiteral("ghidra"), .installDirectory=QStringLiteral("ghidra")};
        for (const bool wrapped : {false, true}) {
            const auto root = caseRoot + (wrapped ? QStringLiteral("/wrapped") : QStringLiteral("/root"));
            const auto stage = root + QStringLiteral("/.stage");
            const auto content = wrapped ? stage + QStringLiteral("/ghidra") : stage;
            fixtureRuntime(content);
            put(root + QStringLiteral("/ghidra/old-marker.txt"), "existing plugin preserved until commit");
            QString error;
            check(promoteExtractedPlugin(plugin, root, stage, &error), "validated root and wrapped backend packages promote transactionally");
            check(ks::plugin_host::ghidra_runtime::validateDirectory(root + QStringLiteral("/ghidra"), &error)
                && !QFileInfo::exists(root + QStringLiteral("/ghidra/old-marker.txt")),
                "successful backend replacement contains the full verified runtime");
        }
        const auto root = caseRoot + QStringLiteral("/bad-promotion");
        const auto stage = root + QStringLiteral("/.stage");
        fixtureRuntime(stage);
        put(root + QStringLiteral("/ghidra/old-marker.txt"), "unchanged existing plugin");
        QFile::remove(stage + QStringLiteral("/LICENSE.txt"));
        QString error;
        check(!promoteExtractedPlugin(plugin, root, stage, &error)
            && get(root + QStringLiteral("/ghidra/old-marker.txt")) == "unchanged existing plugin",
            "invalid backend package cannot replace an installed plugin");
        std::puts("Plugin promotion checks completed");
    }

    // 从实际发布元数据解析计划，测试不另写一套协议定义。
    Plan catalogPlan()
    {
        const auto catalog = QJsonDocument::fromJson(get(QStringLiteral("PluginMarketplace/catalog.json"))).object();
        const auto entry = catalog.value(QStringLiteral("plugins")).toArray().first().toObject();
        MarketplacePlugin plugin;
        QString error;
        check(parseMarketplacePlugin(entry, &plugin, &error) && plugin.upstreamAssets,
            "production marketplace parser accepts the published upstream entry");
        return plugin.upstreamPlan;
    }

    // 校验生产协议的信任边界与旧 ZIP 兼容性；不访问任何下载端点。
    void distributionProtocol()
    {
        using namespace ks::plugin_host;
        const auto original = catalogPlan().description;
        QString error;
        UpstreamPlan parsed;
        for (const auto& field : {QStringLiteral("platform"), QStringLiteral("type")})
        {
            auto changed = original;
            changed.insert(field, QStringLiteral("unsupported"));
            check(!parseUpstreamDistribution(changed, QStringLiteral("ghidra"), &parsed, &error),
                "unsupported upstream platform and distribution type reject before download");
        }
        const QList<QPair<QString, QJsonValue>> faults {
            {QStringLiteral("repository"), QStringLiteral("attacker/ghidra")},
            {QStringLiteral("url"), QStringLiteral("https://github.com/NationalSecurityAgency/ghidra/releases/latest/download/ghidra.zip")},
            {QStringLiteral("url"), QStringLiteral("https://github.com/attacker/ghidra/releases/download/v1/ghidra.zip")},
            {QStringLiteral("url"), QStringLiteral("http://github.com/NationalSecurityAgency/ghidra/releases/download/v1/ghidra.zip")},
            {QStringLiteral("sha256"), QString(64, QLatin1Char('z'))},
            {QStringLiteral("root_directory"), QStringLiteral("../outside")},
            {QStringLiteral("destination_directory"), QStringLiteral("C:/outside")},
            {QStringLiteral("destination_directory"), QStringLiteral("jdk/nested")},
            {QStringLiteral("destination_directory"), QStringLiteral(".archives")},
            {QStringLiteral("max_archive_bytes"), 1.5},
            {QStringLiteral("max_archive_bytes"), 2.0 * 1024 * 1024 * 1024}
        };
        for (const auto& fault : faults)
        {
            auto changed = original;
            auto assets = changed.value(QStringLiteral("assets")).toArray();
            auto asset = assets.first().toObject();
            asset.insert(fault.first, fault.second);
            assets.replace(0, asset);
            changed.insert(QStringLiteral("assets"), assets);
            check(!parseUpstreamDistribution(changed, QStringLiteral("ghidra"), &parsed, &error) && !error.isEmpty(),
                "repository mismatch, unpinned URL, unsafe paths, digests and budgets reject");
        }
        // 元数据只能是固定哈希文本，不能充当从 plugins 仓库下载的可执行载荷。
        auto changed = original;
        auto files = changed.value(QStringLiteral("metadata")).toArray();
        auto file = files.first().toObject();
        file.insert(QStringLiteral("path"), QStringLiteral("install.ps1"));
        files.replace(0, file);
        changed.insert(QStringLiteral("metadata"), files);
        check(!parseUpstreamDistribution(changed, QStringLiteral("ghidra"), &parsed, &error),
            "upstream metadata cannot carry executable installer scripts");
        const QUrl release(original.value(QStringLiteral("assets")).toArray().first().toObject().value(QStringLiteral("url")).toString());
        check(approvedUpstreamRedirect(QUrl(QStringLiteral("https://release-assets.githubusercontent.com/vendor/file?signature=fixture")), release),
            "normal signed GitHub release CDN redirect is accepted");
        for (const auto& target : {QStringLiteral("https://attacker.example/file"),
            QStringLiteral("http://release-assets.githubusercontent.com/file"),
            QStringLiteral("https://github.com/attacker/repo/releases/download/v1/file.zip")})
            check(!approvedUpstreamRedirect(QUrl(target), release), "redirect cannot switch publisher or downgrade HTTPS");
        auto entry = QJsonDocument::fromJson(get(QStringLiteral("GhidraRuntimePlugin/marketplace-entry.json"))).object();
        MarketplacePlugin plugin;
        check(parseMarketplacePlugin(entry, &plugin, &error), "standalone publication entry matches embedded snapshot");
        entry.insert(QStringLiteral("version"), QStringLiteral("999.0"));
        check(!parseMarketplacePlugin(entry, &plugin, &error), "marketplace version cannot differ from generated manifest");
        entry = {{QStringLiteral("id"), QStringLiteral("legacy")}, {QStringLiteral("name"), QStringLiteral("Legacy")},
            {QStringLiteral("version"), QStringLiteral("1.0")}, {QStringLiteral("description"), QStringLiteral("legacy fixture")},
            {QStringLiteral("install_directory"), QStringLiteral("legacy")},
            {QStringLiteral("targets"), QJsonArray{QStringLiteral("process")}},
            {QStringLiteral("archive_url"), QStringLiteral("https://raw.githubusercontent.com/KSwordDEV/Plugins/main/legacy.zip")},
            {QStringLiteral("sha256"), QString(64, QLatin1Char('a'))},
            {QStringLiteral("license_name"), QStringLiteral("Fixture license")},
            {QStringLiteral("license_url"), QStringLiteral("https://raw.githubusercontent.com/KSwordDEV/Plugins/main/LICENSE.txt")}};
        check(parseMarketplacePlugin(entry, &plugin, &error) && !plugin.upstreamAssets,
            "ordinary ZIP marketplace entries remain compatible without a distribution field");
    }

    // 构造 ZIP 与小型文本的本地夹具；本地 URL 只在专用测试构建入口可用。
    Plan localAssets(const QString& source, const QString& output, const QString& fault = QStringLiteral("valid"),
        Plan result = catalogPlan())
    {
        for (int index = 0; index < result.assets.size(); ++index)
        {
            auto& asset = result.assets[index];
            const auto zip = output + QStringLiteral("/asset-%1.zip").arg(index);
            QProcess generator;
            const auto python = qEnvironmentVariable("KSWORD_PLUGIN_TEST_PYTHON");
            generator.start(python.isEmpty() ? QStandardPaths::findExecutable(QStringLiteral("python")) : python, {
                QDir::current().filePath(QStringLiteral("tools/tests/create_ghidra_plugin_fixtures.py")),
                QStringLiteral("--source"), source + u'/' + asset.destinationDirectory + u'/' + asset.rootDirectory,
                QStringLiteral("--output"), zip, QStringLiteral("--mode"),
                index == (fault == QStringLiteral("missing-source") ? 1 : 0) ? fault : QStringLiteral("valid")});
            if (!generator.waitForFinished(10000) || generator.exitCode() != 0)
            {
                std::fprintf(stderr, "Fixture ZIP generator failed: %s\n", generator.readAllStandardError().constData());
                std::exit(2);
            }
            asset.url = QUrl::fromLocalFile(zip);
            asset.sha256 = QString::fromLatin1(QCryptographicHash::hash(get(zip), QCryptographicHash::Sha256).toHex());
            asset.maxArchiveBytes = 1024 * 1024;
        }
        for (auto& file : result.metadata)
        {
            const auto local = QDir::current().filePath(QStringLiteral("GhidraRuntimePlugin/") + file.path);
            file.url = QUrl::fromLocalFile(local);
        }
        return result;
    }

    struct Outcome { bool completed = false; bool success = false; QString stage; QString error; int progress = 0; QString progressStage; };
    Outcome install(const QString& root, const Plan& assets, bool cancelOnProgress = false)
    {
        Outcome result;
        QEventLoop loop;
        ks::plugin_host::UpstreamAssetInstaller installer;
        QTimer watchdog;
        watchdog.setSingleShot(true);
        QObject::connect(&watchdog, &QTimer::timeout, &loop, [&]() {
            std::fprintf(stderr, "Native fixture watchdog stage=%s\n", result.progressStage.toUtf8().constData());
            installer.cancel(); loop.quit();
        });
        watchdog.start(120000);
        installer.startForTests(root, assets,
            [assets](const QString& stage, QString* error) {
                PluginDescriptor descriptor;
                return loadPluginManifestDirectory(stage, assets.id, &descriptor, error);
            }, [&](const QString& stage, int percent) {
            ++result.progress;
            result.progressStage = stage;
            check(percent >= 0 && percent <= 100, "native installer progress stays within the public percentage range");
            if (cancelOnProgress) installer.cancel();
        }, [&](bool ok, const QString& stage, const QString& error) {
            result.completed = true; result.success = ok; result.stage = stage; result.error = error; loop.quit();
        });
        if (!result.completed) loop.exec();
        check(result.completed, "native asynchronous installer finishes its owned operation");
        return result;
    }
    bool noStages(const QString& root)
    {
        return QDir(root).entryList({QStringLiteral(".ksword-plugin-stage-ghidra-*")},
            QDir::Dirs | QDir::Hidden | QDir::NoDotAndDotDot).isEmpty();
    }
    void nativeInstaller()
    {
        const auto source = caseRoot + QStringLiteral("/zip-source");
        fixtureRuntime(source);
        const auto assets = localAssets(source, caseRoot + QStringLiteral("/valid-zips"));
        const auto root = caseRoot + QStringLiteral("/native 空格 plugins");
        put(root + QStringLiteral("/ghidra/old-marker.txt"), "native original plugin");
        auto success = install(root, assets);
        QString error;
        const bool prepared = success.success && !success.stage.isEmpty()
            && ks::plugin_host::ghidra_runtime::validateDirectory(success.stage, &error);
        if (!prepared) std::fprintf(stderr, "Native fixture preparation error: %s %s\n",
            success.error.toUtf8().constData(), error.toUtf8().constData());
        check(prepared,
            "real download/hash/native extraction produces a fully validated inert backend stage");
        check(get(root + QStringLiteral("/ghidra/old-marker.txt")) == "native original plugin",
            "native preparation never changes an installed runtime before manager promotion");
        const MarketplacePlugin plugin{.id=QStringLiteral("ghidra"), .installDirectory=QStringLiteral("ghidra")};
        check(promoteExtractedPlugin(plugin, root, success.stage, &error)
            && ks::plugin_host::ghidra_runtime::validateDirectory(root + QStringLiteral("/ghidra"), &error),
            "native prepared stage commits through the same production manager transaction");
        put(root + QStringLiteral("/ghidra/preserved-marker.txt"), "keep after rejected update");
        for (const auto& fault : {QStringLiteral("checksum"), QStringLiteral("download-size"), QStringLiteral("traversal"),
            QStringLiteral("device"), QStringLiteral("link"), QStringLiteral("duplicate"),
            QStringLiteral("wrong-wrapper"), QStringLiteral("missing-source"), QStringLiteral("metadata-checksum")}) {
            auto bad = fault == QStringLiteral("checksum") || fault == QStringLiteral("download-size")
                || fault == QStringLiteral("metadata-checksum") ? assets : localAssets(source, caseRoot + u'/' + fault, fault);
            if (fault == QStringLiteral("checksum")) bad.assets[0].sha256 = QString(64, QLatin1Char('0'));
            if (fault == QStringLiteral("download-size")) bad.assets[0].maxArchiveBytes = 1;
            if (fault == QStringLiteral("metadata-checksum")) bad.metadata.last().sha256 = QString(64, QLatin1Char('0'));
            const auto result = install(root, bad);
            check(!result.success && result.stage.isEmpty() && !result.error.isEmpty() && noStages(root),
                "invalid hash size archive path or legal/source payload leaves no usable partial plugin");
            check(get(root + QStringLiteral("/ghidra/preserved-marker.txt")) == "keep after rejected update",
                "rejected native update preserves the existing installed plugin");
        }
        const auto cancelled = install(root, assets, true);
        check(!cancelled.success && !cancelled.error.isEmpty() && noStages(root),
            "cancelling from progress cleans the private stage without publishing a package");
        ks::plugin_host::UpstreamAssetInstaller first;
        ks::plugin_host::UpstreamAssetInstaller second;
        Outcome firstResult, secondResult;
        first.startForTests(root, assets, [](const QString&, QString*) { return true; }, {}, [&](bool ok, const QString&, const QString& error) {
            firstResult.completed = true; firstResult.success = ok; firstResult.error = error;
        });
        second.startForTests(root, assets, [](const QString&, QString*) { return true; }, {}, [&](bool ok, const QString&, const QString& error) {
            secondResult.completed = true; secondResult.success = ok; secondResult.error = error;
        });
        check(secondResult.completed && !secondResult.success && !secondResult.error.isEmpty(),
            "two native manager instances cannot concurrently replace the same installed runtime");
        first.cancel();
        check(firstResult.completed && !firstResult.success && noStages(root),
            "cancelling the lock owner leaves no stage from either installer");
        QPointer<ks::plugin_host::UpstreamAssetInstaller> retiring = new ks::plugin_host::UpstreamAssetInstaller;
        bool completedAfterDeletion = false;
        retiring->startForTests(root, assets, [](const QString&, QString*) { return true; }, [retiring](const QString&, int) { delete retiring.data(); },
            [&](bool, const QString&, const QString&) { completedAfterDeletion = true; });
        QCoreApplication::processEvents();
        check(retiring.isNull() && !completedAfterDeletion && noStages(root),
            "destroying installer from progress safely cancels all callbacks and owned files");
        // 同一安装器能够处理普通命令插件，证明安装逻辑不依赖 ghidra id 或两项资源。
        auto generic = assets;
        generic.id = QStringLiteral("vendor-tool");
        generic.assets = {assets.assets.first()};
        generic.manifest = {{QStringLiteral("ksword_plugin_api"), QStringLiteral("1")},
            {QStringLiteral("id"), generic.id}, {QStringLiteral("name"), QStringLiteral("Vendor tool")},
            {QStringLiteral("version"), QStringLiteral("1.0")}, {QStringLiteral("description"), QStringLiteral("generic upstream fixture")},
            {QStringLiteral("runtime"), QStringLiteral("executable")},
            {QStringLiteral("entrypoint"), QStringLiteral("runtime/ghidra_12.0.4_PUBLIC/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe")},
            {QStringLiteral("default_command"), QStringLiteral("info")},
            {QStringLiteral("targets"), QJsonArray{QStringLiteral("process")}},
            {QStringLiteral("license"), QStringLiteral("LICENSE.txt")}};
        generic.description.insert(QStringLiteral("manifest"), generic.manifest);
        generic.description.insert(QStringLiteral("assets"), QJsonArray{assets.description.value(QStringLiteral("assets")).toArray().first()});
        Plan genericParsed;
        check(ks::plugin_host::parseUpstreamDistribution(generic.description, generic.id, &genericParsed, &error),
            "generic executable plan passes the same production protocol parser");
        const auto ordinary = install(root, generic);
        MarketplacePlugin genericPlugin;
        genericPlugin.id = generic.id;
        genericPlugin.installDirectory = generic.id;
        genericPlugin.upstreamAssets = true;
        genericPlugin.upstreamPlan = generic;
        check(ordinary.success && promoteExtractedPlugin(genericPlugin, root, ordinary.stage, &error),
            "one-resource upstream executable installs through the production promotion transaction");
        // 模拟维护者同时更新包版本、Ghidra/JDK 版本和官方 ZIP 顶层目录。
        // 所有内容仍是本地惰性夹具，绝不执行 Java 或分析样本。
        auto future = catalogPlan();
        const auto futureSource = caseRoot + QStringLiteral("/future-source");
        fixtureRuntime(futureSource);
        check(QDir(futureSource + QStringLiteral("/runtime")).rename(QStringLiteral("ghidra_12.0.4_PUBLIC"), QStringLiteral("ghidra_next")) &&
            QDir(futureSource + QStringLiteral("/jdk")).rename(QStringLiteral("jdk-21.0.12.1+1"), QStringLiteral("jdk_next")),
            "future fixture uses changed archive roots");
        future.assets[0].rootDirectory = QStringLiteral("ghidra_next");
        future.assets[1].rootDirectory = QStringLiteral("jdk_next");
        future.manifest.insert(QStringLiteral("version"), QStringLiteral("12.0.4.1"));
        future.manifest.insert(QStringLiteral("runtime_version"), QStringLiteral("12.0.5"));
        future.manifest.insert(QStringLiteral("java_version"), QStringLiteral("21.0.13"));
        future.manifest.insert(QStringLiteral("runtime_root"), QStringLiteral("runtime/ghidra_next"));
        future.manifest.insert(QStringLiteral("java_executable"), QStringLiteral("jdk/jdk_next/bin/java.exe"));
        future.description.insert(QStringLiteral("manifest"), future.manifest);
        auto futureDescriptions = future.description.value(QStringLiteral("assets")).toArray();
        for (int index = 0; index < future.assets.size(); ++index)
        {
            auto asset = futureDescriptions[index].toObject();
            asset.insert(QStringLiteral("root_directory"), future.assets[index].rootDirectory);
            futureDescriptions.replace(index, asset);
        }
        future.description.insert(QStringLiteral("assets"), futureDescriptions);
        put(futureSource + QStringLiteral("/runtime/ghidra_next/Ghidra/application.properties"), "application.version=12.0.5\n");
        put(futureSource + QStringLiteral("/jdk/jdk_next/release"),
            "JAVA_VERSION=\"21.0.13\"\nOS_ARCH=\"x86_64\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n");
        future = localAssets(futureSource, caseRoot + QStringLiteral("/future-zips"), QStringLiteral("valid"), future);
        const auto updated = install(root, future);
        MarketplacePlugin futurePlugin;
        futurePlugin.id = QStringLiteral("ghidra");
        futurePlugin.installDirectory = futurePlugin.id;
        futurePlugin.upstreamAssets = true;
        futurePlugin.upstreamPlan = future;
        check(updated.success && promoteExtractedPlugin(futurePlugin, root, updated.stage, &error),
            "changed package and runtime versions install without rebuilding a fixed runtime profile");
        const auto installed = ks::plugin_host::ghidra_runtime::installedManifest(root + QStringLiteral("/ghidra"));
        check(installed == future.manifest && ks::plugin_host::ghidra_runtime::validateDirectory(root + QStringLiteral("/ghidra"), &error),
            "installed manifest resolves the new runtime and bundled Java paths");
        // 被篡改的安装回执不能让不匹配的运行环境被标记为就绪。
        put(root + QStringLiteral("/ghidra/jdk/jdk_next/release"), "JAVA_VERSION=\"21.0.12.1\"\n");
        check(!ks::plugin_host::ghidra_runtime::validateDirectory(root + QStringLiteral("/ghidra"), &error),
            "future runtime still verifies its actual version against the distribution manifest");
        // 生产入口重新解析 JSON，不允许测试本地 URL 被意外用于正常安装。
        auto invalidProduction = generic;
        auto invalidAssets = invalidProduction.description.value(QStringLiteral("assets")).toArray();
        auto invalidAsset = invalidAssets.first().toObject();
        invalidAsset.insert(QStringLiteral("url"), generic.assets.first().url.toString());
        invalidAssets.replace(0, invalidAsset);
        invalidProduction.description.insert(QStringLiteral("assets"), invalidAssets);
        bool refused = false;
        ks::plugin_host::UpstreamAssetInstaller production;
        production.start(root, invalidProduction, [](const QString&, QString*) { return true; }, {},
            [&](bool ok, const QString&, const QString&) { refused = !ok; });
        check(refused, "production entry rejects local resource URLs even in a test-enabled binary");
        std::puts("Native plugin installer checks completed");
    }

    int officialInstall(const QString& ghidraZip, const QString& jdkZip, const QString& pluginRoot)
    {
        auto assets = catalogPlan();
        assets.assets[0].url = QUrl::fromLocalFile(ghidraZip);
        assets.assets[1].url = QUrl::fromLocalFile(jdkZip);
        ks::plugin_host::UpstreamAssetInstaller installer;
        QEventLoop loop;
        QTimer watchdog;
        watchdog.setSingleShot(true);
        bool completed = false, installed = false;
        QString failure;
        int lastPercent = -10;
        QObject::connect(&watchdog, &QTimer::timeout, &loop, [&]() { installer.cancel(); loop.quit(); });
        watchdog.start(600000);
        for (auto& file : assets.metadata)
            file.url = QUrl::fromLocalFile(QDir::current().filePath(QStringLiteral("GhidraRuntimePlugin/") + file.path));
        installer.startForTests(pluginRoot, assets, ks::plugin_host::ghidra_runtime::validateDirectory,
            [&](const QString& stage, int percent) {
            if (percent >= lastPercent + 10 || stage.contains(QStringLiteral("解压")) || percent >= 95) {
                std::printf("OFFICIAL_INSTALL_PROGRESS=%d %s\n", percent, stage.toUtf8().constData());
                lastPercent = percent;
            }
        }, [&](bool ok, const QString& stage, const QString& error) {
            completed = true;
            if (!ok) failure = error;
            else {
                QString promotionError;
                const MarketplacePlugin plugin{.id=QStringLiteral("ghidra"), .installDirectory=QStringLiteral("ghidra")};
                installed = promoteExtractedPlugin(plugin, pluginRoot, stage, &promotionError)
                    && ks::plugin_host::ghidra_runtime::validateDirectory(pluginRoot + QStringLiteral("/ghidra"), &promotionError);
                if (!installed) failure = promotionError;
            }
            loop.quit();
        });
        if (!completed) loop.exec();
        std::printf("GHIDRA_OFFICIAL_PLUGIN_INSTALL=%s DIRECTORY=%s ERROR=%s\n",
            completed && installed ? "PASS" : "FAIL", pluginRoot.toUtf8().constData(), failure.toUtf8().constData());
        return completed && installed ? 0 : 1;
    }
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    if (argc < 3) return 2;
    inertExecutable = QString::fromLocal8Bit(argv[2]);
    if (!QFileInfo(inertExecutable).isFile()) return 2;
    if (argc == 7 && QString::fromLocal8Bit(argv[3]) == QStringLiteral("--official-install"))
        return officialInstall(QString::fromLocal8Bit(argv[4]), QString::fromLocal8Bit(argv[5]), QString::fromLocal8Bit(argv[6]));
    QTemporaryDir temporary(QString::fromLocal8Bit(argv[1]) + QStringLiteral("/cases-XXXXXX"));
    if (!temporary.isValid()) return 2;
    caseRoot = temporary.path();
    distributionProtocol();
    metadataAndParser();
    promotion();
    nativeInstaller();
    std::printf("GHIDRA_PLUGIN_PORTABLE_RESULT=PASS CHECKS=%u\n", checks);
}
