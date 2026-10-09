// 使用生产 SnapshotWorkbenchWidget 和 Qt 鼠标/键盘事件验证行内暂存，绝不访问真实内存。
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexView.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchCompareView.h"
#include "workbench_pseudocode_contract_tests.h"
#include "workbench_integration_regression_tests.h"
#include "../Ksword5.1/Ksword5.1/UI/CodeTextEdit.h"
#include <QApplication>
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchDisasmView.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchTextView.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/MemoryRowCanvas.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexCanvas.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexViewWidgets.h"
#include "../Ksword5.1/Ksword5.1/UI/MemorySnapshotBytesProvider.h"
#include "../Ksword5.1/Ksword5.1/UI/Decompiler/GhidraDecompiler.h"
#include "../GhidraRuntimePlugin/RuntimeProfile.h"
#include <QComboBox>
#include <QCheckBox>
#include <QClipboard>
#include <QCryptographicHash>
#include <QDialog>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QFontDatabase>
#include <QLineEdit>
#include <QLabel>
#include <QMenu>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSettings>
#include <QTableWidget>
#include <QTabBar>
#include <QTabWidget>
#include <QTextBlock>
#include <QTest>
#include <QTimer>
#include <QTemporaryDir>
#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <string>
#include <typeinfo>

namespace fixture { extern QString lastManagedPlugin; }

namespace
{
    unsigned checks = 0; // 已执行的断言数。
    QString previewDirectory;
    QString protocolLauncher;

    // require 接收断言及说明，失败退出非零，成功累计计数。
    void require(bool condition, const char* description)
    {
        ++checks;
        if (!condition)
        {
            std::cerr << "FAIL [" << checks << "]: " << description << '\n';
            std::exit(1);
        }
    }

    // flushEvents 处理委托关闭与排队的缓存事务，不进行目标进程读写。
    void flushEvents()
    {
        QApplication::processEvents();
        QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
        QApplication::processEvents();
    }

    template<class Predicate>
    bool waitFor(Predicate predicate, int milliseconds = 6000)
    {
        QElapsedTimer timer;
        timer.start();
        while (!predicate() && timer.elapsed() < milliseconds) QTest::qWait(5);
        flushEvents();
        return predicate();
    }

    struct FixtureEnvironment
    {
        const char* name;
        QByteArray previous;
        bool present;
        FixtureEnvironment(const char* key, const QByteArray& value)
            : name(key), previous(qgetenv(key)), present(qEnvironmentVariableIsSet(key))
        { qputenv(name, value); }
        ~FixtureEnvironment()
        {
            if (present) qputenv(name, previous);
            else qunsetenv(name);
        }
    };

    void writeFixtureFile(const QString& path, const QByteArray& bytes)
    {
        QFile file(path);
        require(file.open(QIODevice::WriteOnly) && file.write(bytes) == bytes.size(),
            "isolated protocol fixture file can be created");
    }

    QString createHeadlessFixture(QTemporaryDir& directory)
    {
        require(directory.isValid(), "isolated headless fixture has a temporary directory");
        require(QDir().mkpath(directory.path() + QStringLiteral("/Ghidra/Framework/Utility/lib")),
            "isolated headless directory structure is available");
        writeFixtureFile(directory.path() + QStringLiteral("/Ghidra/Framework/Utility/lib/Utility.jar"), "fixture");
        writeFixtureFile(directory.path() + QStringLiteral("/Ghidra/application.properties"), "application.version=12.0\n");
        return directory.path();
    }

    // Real adapter/process/validation, deterministic protocol producer only.
    // This does not claim the fixture output came from the Ghidra decompiler.
    void checkHeadlessProtocol()
    {
        using namespace ks::ui;
        QTemporaryDir directory;
        const auto root = createHeadlessFixture(directory);
        FixtureEnvironment java("KSWORD_GHIDRA_JAVA", protocolLauncher.toLocal8Bit());
        FixtureEnvironment ghidra("KSWORD_GHIDRA_DIR", root.toLocal8Bit());
        FixtureEnvironment mode("KSWORD_GHIDRA_FIXTURE_MODE", "success");
        FixtureEnvironment delay("KSWORD_GHIDRA_FIXTURE_DELAY", "0");
        DecompilerRequest request;
        request.bytes = QByteArray::fromHex("b82a000000c3");
        request.baseAddress = request.selectedAddress = 0x140001000ULL;
        GhidraDecompiler backend;
        backend.setGhidraDirectory(root);
        QVector<DecompilerResult> results;
        QObject::connect(&backend, &GhidraDecompiler::finished, &backend,
            [&](const DecompilerResult& result) { results.push_back(result); });
        require(backend.start(request), "valid captured bytes schedule a headless process");
        require(waitFor([&]() { return !results.isEmpty(); }), "headless success completes asynchronously");
        require(results.back().success && results.back().code.contains(QStringLiteral("return 42;"))
            && results.back().functionAddress == request.selectedAddress
            && results.back().lineAddresses.at(0) == request.selectedAddress
            && results.back().lineAddressValid.at(0) && !results.back().lineAddressValid.at(1)
            && !backend.isRunning(), "validated headless output keeps exact addresses and line validity");
        require(request.bytes == QByteArray::fromHex("b82a000000c3"),
            "headless analysis leaves caller captured bytes unchanged");

        for (const auto* rejected : {"wrong-sha", "wrong-address", "wrong-schema", "malformed",
            "failure", "long-code", "nonzero", "outside-line", "empty-function", "bad-instruction"})
        {
            results.clear();
            qputenv("KSWORD_GHIDRA_FIXTURE_MODE", rejected);
            require(backend.start(request), "protocol rejection scenario really starts the external process");
            require(waitFor([&]() { return !results.isEmpty(); }), "invalid protocol result finishes within the test limit");
            require(!results.back().success && results.back().code.isEmpty()
                && !results.back().error.isEmpty() && !backend.isRunning(),
                "invalid or mismatched evidence cannot publish C pseudocode");
            if (QByteArray(rejected) == "bad-instruction")
                require(results.back().error == QStringLiteral("invalid_instruction_data"),
                    "generated bad-instruction warning has a specific failure instead of successful C");
        }

        // 实际 stdout 可混入旧令牌和错误阶段；只接受本次请求的有效单调阶段。
        QVector<DecompilerProgress> progress;
        const auto progressConnection = QObject::connect(&backend, &GhidraDecompiler::progressChanged,
            &backend, [&](const DecompilerProgress& event) { progress.push_back(event); });
        results.clear();
        qputenv("KSWORD_GHIDRA_FIXTURE_MODE", "progress-spoof");
        require(backend.start(request) && waitFor([&]() { return !results.isEmpty(); }),
            "spoofed progress is exercised through an actual asynchronous producer process");
        require(results.back().success && progress.size() == 8,
            "stale-token unknown-stage invalid-count and backward progress are all ignored");
        require(progress.front().stage == DecompilerStage::PreparingSnapshot
            && progress.back().stage == DecompilerStage::Rendering
            && progress.back().completedUnits == 4 && progress.back().totalUnits == 4,
            "valid progress retains actual completed and total output lines");
        require(std::is_sorted(progress.cbegin(), progress.cend(), [](const auto& left, const auto& right) {
            return static_cast<int>(left.stage) < static_cast<int>(right.stage);
        }), "accepted backend progress never moves to an earlier stage");
        QObject::disconnect(progressConnection);
        results.clear();
        qputenv("KSWORD_GHIDRA_FIXTURE_MODE", "warning-string");
        require(backend.start(request) && waitFor([&]() { return !results.isEmpty(); }),
            "ordinary diagnostic wording is exercised as a program string literal");
        require(results.back().success && results.back().code.contains(QStringLiteral("return"))
            && results.back().code.contains(QStringLiteral("Control flow encountered bad instruction data")),
            "ordinary string literal wording cannot be misclassified as a generated warning");

        results.clear();
        qputenv("KSWORD_GHIDRA_FIXTURE_MODE", "success");
        request.baseAddress = request.selectedAddress = 0;
        require(backend.start(request) && waitFor([&]() { return !results.isEmpty(); }),
            "raw captured address zero is a valid decompile request");
        require(results.back().success && results.back().functionAddress == 0
            && results.back().lineAddressValid.at(0) && results.back().lineAddresses.at(0) == 0,
            "zero address mappings stay distinct from unmapped C lines");

        for (int invalid = 0; invalid < 3; ++invalid)
        {
            results.clear();
            auto rejected = request;
            if (invalid == 0) rejected.bytes.clear();
            if (invalid == 1) rejected.selectedAddress = static_cast<quint64>(rejected.bytes.size());
            if (invalid == 2) rejected.baseAddress = rejected.selectedAddress = UINT64_MAX;
            backend.start(rejected);
            require(waitFor([&]() { return !results.isEmpty(); }) && !results.back().success
                && results.back().code.isEmpty(), "empty out-of-range and wrapping snapshots reject decompilation");
        }

        results.clear();
        qputenv("KSWORD_GHIDRA_FIXTURE_DELAY", "1200");
        require(backend.start(request), "cancellation scenario starts a delayed external process");
        QTest::qWait(40);
        require(backend.isRunning(), "cancellation is exercised while the production adapter is busy");
        backend.cancel();
        require(waitFor([&]() { return !backend.isRunning(); }), "cancelled headless process leaves busy state");
        require(std::none_of(results.cbegin(), results.cend(), [](const auto& result) { return result.success; }),
            "cancelled process cannot publish successful pseudocode");
        QPointer<GhidraDecompiler> retiring = new GhidraDecompiler;
        retiring->setGhidraDirectory(root);
        require(retiring->start(request), "owner destruction scenario starts a delayed external process");
        QTest::qWait(40);
        delete retiring.data();
        flushEvents();
        require(retiring.isNull(), "destroying the backend stops its child process safely");

        qputenv("KSWORD_GHIDRA_FIXTURE_DELAY", "0");
        const auto cancelledLaunchRecord = directory.filePath(QStringLiteral("progress-cancelled-launch.txt"));
        FixtureEnvironment progressLaunchRecord("KSWORD_GHIDRA_FIXTURE_LAUNCH_RECORD", cancelledLaunchRecord.toLocal8Bit());
        QPointer<GhidraDecompiler> deleteOnProgress = new GhidraDecompiler;
        DecompilerStage deletionStage = DecompilerStage::Rendering;
        deleteOnProgress->setGhidraDirectory(root);
        QObject::connect(deleteOnProgress, &GhidraDecompiler::progressChanged, &backend,
            [&](const DecompilerProgress& event) {
                deletionStage = event.stage;
                delete deleteOnProgress.data();
            });
        require(deleteOnProgress->start(request) && waitFor([&]() { return deleteOnProgress.isNull(); }),
            "queued backend progress can synchronously retire its owner before launching Java");
        require(deletionStage == DecompilerStage::PreparingSnapshot && !QFileInfo::exists(cancelledLaunchRecord),
            "retirement really occurs during snapshot preparation without any launcher execution");
        QPointer<GhidraDecompiler> deleteOnStart = new GhidraDecompiler;
        deleteOnStart->setGhidraDirectory(root);
        QObject::connect(deleteOnStart, &GhidraDecompiler::runningChanged, qApp,
            [deleteOnStart](bool running) { if (running) delete deleteOnStart.data(); });
        const bool scheduledBeforeDeletion = deleteOnStart->start(request);
        require(scheduledBeforeDeletion && deleteOnStart.isNull(),
            "a synchronous running observer may destroy the backend without post-signal access");
        flushEvents();

        QPointer<GhidraDecompiler> deleteOnFinished = new GhidraDecompiler;
        deleteOnFinished->setGhidraDirectory(root);
        QObject::connect(deleteOnFinished, &GhidraDecompiler::finished, qApp,
            [deleteOnFinished](const auto&) { delete deleteOnFinished.data(); });
        require(deleteOnFinished->start(request)
            && waitFor([&]() { return deleteOnFinished.isNull(); }),
            "a completion observer may destroy the backend before any trailing state signal");

        GhidraDecompiler reentrant;
        reentrant.setGhidraDirectory(root);
        QVector<DecompilerResult> restartedResults;
        bool restarted = false;
        auto second = request;
        second.selectedAddress = 1;
        QObject::connect(&reentrant, &GhidraDecompiler::finished, &reentrant,
            [&](const auto& result) {
                restartedResults.push_back(result);
                if (restartedResults.size() == 1) restarted = reentrant.start(second);
            });
        require(reentrant.start(request) && waitFor([&]() { return restartedResults.size() == 2; }),
            "a completion callback can schedule the next captured analysis");
        require(restarted && restartedResults.at(0).success && restartedResults.at(1).success
            && restartedResults.at(0).functionAddress == 0 && restartedResults.at(1).functionAddress == 1
            && !reentrant.isRunning(), "reentrant requests retain ordered result identities and final idle state");
    }

    void checkInstalledRuntimeDiscovery()
    {
        using namespace ks::ui;
        using namespace ks::plugin_host::ghidra_runtime;
        QTemporaryDir directory;
        require(directory.isValid(), "plugin discovery fixtures have an isolated writable root");
        const auto plugins = directory.path() + QStringLiteral("/plugin");
        const auto plugin = plugins + QStringLiteral("/ghidra");
        const auto metadata = manifest();
        const auto runtimeRelative = metadata.value(QStringLiteral("runtime_root")).toString();
        const auto runtime = plugin + u'/' + runtimeRelative;
        const auto javaRelative = metadata.value(QStringLiteral("java_executable")).toString();
        const auto java = plugin + u'/' + javaRelative;
        const auto jdkRelative = javaRelative.left(javaRelative.size() - QStringLiteral("bin/java.exe").size());
        const auto put = [&](const QString& relative, const QByteArray& bytes) {
            const auto path = plugin + u'/' + relative;
            require(QDir().mkpath(QFileInfo(path).absolutePath()), "plugin payload parent is in its owned fixture");
            writeFixtureFile(path, bytes);
        };
        QFile executable(protocolLauncher);
        require(executable.open(QIODevice::ReadOnly), "the compiled inert launcher is readable for runtime discovery");
        const auto exeBytes = executable.readAll();
        put(runtimeRelative + QStringLiteral("/Ghidra/Framework/Utility/lib/Utility.jar"), "fixture jar");
        put(runtimeRelative + QStringLiteral("/Ghidra/application.properties"), "application.version=12.0.4\n");
        put(runtimeRelative + QStringLiteral("/Ghidra/Features/Decompiler/os/win_x86_64/decompile.exe"), exeBytes);
        put(runtimeRelative + QStringLiteral("/Ghidra/Features/Decompiler/LICENSE.txt"), "fixture GPL license\n");
        put(runtimeRelative + QStringLiteral("/LICENSE"), "fixture upstream license\n");
        put(runtimeRelative + QStringLiteral("/licenses/fixture.txt"), "fixture component license\n");
        put(runtimeRelative + QStringLiteral("/GPL/fixture.txt"), "fixture GPL source marker\n");
        put(javaRelative, exeBytes);
        put(jdkRelative + QStringLiteral("release"),
            "JAVA_VERSION=\"21.0.12.1\"\nOS_ARCH=\"x86_64\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\n");
        put(jdkRelative + QStringLiteral("NOTICE"), "fixture JDK notice\n");
        put(jdkRelative + QStringLiteral("legal/java.base/LICENSE"), "fixture JDK license\n");
        put(jdkRelative + QStringLiteral("legal/java.base/ADDITIONAL_LICENSE_INFO"), "fixture classpath exception\n");
        put(jdkRelative + QStringLiteral("lib/src.zip"), "fixture source marker\n");
        QString error;
        require(writePackageMetadata(plugin, &error) && validateDirectory(plugin, &error),
            "canonical managed runtime discovery fixture passes the actual production profile");
        FixtureEnvironment pluginRoot("KSWORD_PLUGIN_ROOT", plugins.toLocal8Bit());
        FixtureEnvironment explicitRoot("KSWORD_GHIDRA_DIR", "");
        FixtureEnvironment explicitJava("KSWORD_GHIDRA_JAVA", "");
        FixtureEnvironment javaHome("JAVA_HOME", "");
        FixtureEnvironment jdkHome("JDK_HOME", "");
        FixtureEnvironment mode("KSWORD_GHIDRA_FIXTURE_MODE", "success");
        FixtureEnvironment delay("KSWORD_GHIDRA_FIXTURE_DELAY", "0");
        const auto recordPath = directory.path() + QStringLiteral("/launched-java.txt");
        FixtureEnvironment record("KSWORD_GHIDRA_FIXTURE_LAUNCH_RECORD", recordPath.toLocal8Bit());
        require(QFileInfo(GhidraDecompiler::installedPluginDirectory()).canonicalFilePath()
            == QFileInfo(plugin).canonicalFilePath()
            && QFileInfo(GhidraDecompiler::findGhidraDirectory()).canonicalFilePath()
            == QFileInfo(runtime).canonicalFilePath(),
            "complete managed plugin is automatically selected without manual runtime paths");
        GhidraDecompiler backend;
        QVector<DecompilerResult> results;
        QObject::connect(&backend, &GhidraDecompiler::finished, &backend,
            [&](const auto& result) { results.push_back(result); });
        DecompilerRequest request;
        request.bytes = QByteArray::fromHex("b82a000000c3");
        request.baseAddress = request.selectedAddress = 0x1000;
        require(backend.start(request) && waitFor([&]() { return !results.isEmpty(); }) && results.back().success,
            "managed backend executes its isolated protocol through bundled Java without JAVA_HOME");
        QFile recorded(recordPath);
        require(recorded.open(QIODevice::ReadOnly)
            && QFileInfo(QString::fromUtf8(recorded.readAll())).canonicalFilePath() == QFileInfo(java).canonicalFilePath(),
            "runtime launch selects the plugin-local Java executable rather than an unrelated PATH runtime");
        require(QFile::remove(java) && GhidraDecompiler::installedPluginDirectory().isEmpty(),
            "an installed plugin missing its Java payload cannot be discovered as ready");
        put(javaRelative, exeBytes);
        auto escaped = metadata;
        escaped.insert(QStringLiteral("runtime_root"), QStringLiteral("../outside"));
        put(QStringLiteral("plugin.json"), QJsonDocument(escaped).toJson());
        require(GhidraDecompiler::installedPluginDirectory().isEmpty(),
            "runtime metadata escaping the installed plugin is rejected before discovery");
    }

    void checkPeFileAddressMapping()
    {
        using namespace ks::ui;
        SnapshotWorkbenchWidget owner;
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        const auto snapshot = std::make_shared<const std::vector<std::uint8_t>>(0x1000, 0x90);
        constexpr std::uint64_t imageBase = 0x140000000ULL;
        const FileAnalysisRegion text{0x200, 0x100, 0x1000, 0x180, QStringLiteral(".text"), true};
        owner.setSnapshot(QByteArray(0x100, static_cast<char>(0x90)), 0x200,
            DisassemblyArchitecture::X64, 0x200, QStringLiteral("pe-map-fixture"));
        owner.setFileAnalysisContext(snapshot, imageBase, {text});
        require(owner.fileOffsetToVirtualAddress(0x200) == imageBase + 0x1000
            && owner.fileOffsetToVirtualAddress(0x205) == imageBase + 0x1005
            && owner.fileOffsetToVirtualAddress(0x2ff) == imageBase + 0x10ff,
            "PE mappings preserve raw section delta and full-width virtual address");
        require(!owner.fileOffsetToVirtualAddress(0x180) && !owner.fileOffsetToVirtualAddress(0x300),
            "PE gaps and virtual-only tails have no fabricated file address mapping");
        auto padded = text;
        padded.virtualSize = 0x80;
        owner.setFileAnalysisContext(snapshot, imageBase, {padded});
        require(owner.fileOffsetToVirtualAddress(0x27f) && !owner.fileOffsetToVirtualAddress(0x280),
            "raw file alignment padding beyond virtual content cannot claim a mapped code address");
        padded.virtualSize = 0;
        owner.setFileAnalysisContext(snapshot, imageBase, {padded});
        require(owner.fileOffsetToVirtualAddress(0x2ff) == imageBase + 0x10ff,
            "zero virtual size retains its explicit raw section extent");
        auto overlap = text;
        overlap.name = QStringLiteral(".overlap");
        owner.setFileAnalysisContext(snapshot, imageBase, {text, overlap});
        require(!owner.fileOffsetToVirtualAddress(0x205),
            "ambiguous overlapping sections reject mapping even with matching numeric virtual addresses");
        owner.setFileAnalysisContext(snapshot, UINT64_MAX - 0x800, {text});
        require(!owner.fileOffsetToVirtualAddress(0x200), "PE virtual address arithmetic never wraps");
        auto oversizedRva = text;
        oversizedRva.rva = UINT64_C(0x100000000);
        owner.setFileAnalysisContext(snapshot, imageBase, {oversizedRva});
        require(!owner.fileOffsetToVirtualAddress(0x200), "PE section RVA remains within its actual 32-bit field");
        auto truncated = text;
        truncated.fileOffset = 0xff0;
        owner.setFileAnalysisContext(snapshot, imageBase, {truncated});
        require(!owner.fileOffsetToVirtualAddress(0x1000),
            "section declarations cannot map bytes outside the captured backing file");
        const FileAnalysisRegion header{0, 0x100, 0, 0x100, QStringLiteral("headers"), false};
        owner.setFileAnalysisContext(snapshot, 0, {header});
        require(owner.fileOffsetToVirtualAddress(0).has_value()
            && owner.fileOffsetToVirtualAddress(0).value() == 0,
            "an explicitly mapped file origin retains numeric virtual address zero");
        const FileAnalysisRegion bss{0x500, 0, 0x3000, 0x100, QStringLiteral(".bss"), false};
        owner.setFileAnalysisContext(snapshot, imageBase, {bss});
        require(!owner.fileOffsetToVirtualAddress(0x500), "zero-fill sections have no invented raw-file bytes");
        owner.setFileAnalysisContext(snapshot, imageBase, {text});
        owner.setSnapshot(QByteArray::fromHex("b82a000000c3"), 0x200,
            DisassemblyArchitecture::X64, 0x200, QStringLiteral("different-file"));
        require(!owner.fileOffsetToVirtualAddress(0x200),
            "new snapshots cannot inherit old file-to-virtual address metadata");
        owner.setFileAnalysisContext(snapshot, imageBase, {text});
        owner.clear();
        require(!owner.fileOffsetToVirtualAddress(0x200), "clear removes PE context together with the bytes");
    }

    std::shared_ptr<const std::vector<std::uint8_t>> syntheticPe()
    {
        auto bytes = std::make_shared<std::vector<std::uint8_t>>(0x400, 0);
        const auto write = [&](std::size_t offset, std::uint64_t value, unsigned count) {
            for (unsigned index = 0; index < count; ++index)
                bytes->at(offset + index) = static_cast<std::uint8_t>(value >> (index * 8));
        };
        write(0, 0x5a4d, 2);
        write(0x3c, 0x80, 4);
        write(0x80, 0x4550, 4);
        write(0x84, 0x8664, 2);
        write(0x86, 1, 2);
        write(0x94, 0xf0, 2);
        write(0x98, 0x20b, 2);
        write(0x98 + 16, 0x1000, 4);
        write(0x98 + 24, 0x140000000ULL, 8);
        write(0x98 + 56, 0x2000, 4);
        write(0x98 + 60, 0x200, 4);
        write(0x188 + 8, 0x100, 4);
        write(0x188 + 12, 0x1000, 4);
        write(0x188 + 16, 0x200, 4);
        write(0x188 + 20, 0x200, 4);
        write(0x188 + 36, 0x60000020, 4); // .text 是明确声明为可执行、可读的代码节。
        const auto code = QByteArray::fromHex("b82a000000c3");
        std::copy(code.cbegin(), code.cend(), bytes->begin() + 0x200);
        return bytes;
    }

    void checkPeDecodeAndFollow()
    {
        using namespace ks::ui;
        constexpr std::uint64_t imageBase = 0x140000000ULL;
        auto image = std::make_shared<std::vector<std::uint8_t>>(*syntheticPe());
        image->resize(0x600, 0x90);
        const auto write = [&](std::size_t offset, std::uint64_t value, unsigned count) {
            for (unsigned index = 0; index < count; ++index)
                image->at(offset + index) = static_cast<std::uint8_t>(value >> (index * 8));
        };
        write(0x86, 2, 2);
        write(0x98 + 56, 0x4000, 4);
        write(0x1b0 + 8, 0x100, 4);
        write(0x1b0 + 12, 0x3000, 4);
        write(0x1b0 + 16, 0x200, 4);
        write(0x1b0 + 20, 0x400, 4);
        image->at(0x400) = 0xc3;
        const QVector<FileAnalysisRegion> regions{
            {0x200, 0x200, 0x1000, 0x100, QStringLiteral(".text"), true},
            {0x400, 0x200, 0x3000, 0x100, QStringLiteral(".other"), true},
            {0, 0, 0x2000, 0x100, QStringLiteral(".bss"), false}};
        SnapshotWorkbenchWidget owner;
        owner.resize(1100, 650);
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        owner.setEditable(false);
        owner.show();
        const auto load = [&](const QByteArray& instruction) {
            std::copy(instruction.cbegin(), instruction.cend(), image->begin() + 0x200);
            const QByteArray snapshot(reinterpret_cast<const char*>(image->data()), static_cast<qsizetype>(image->size()));
            owner.setSnapshot(snapshot, 0, DisassemblyArchitecture::X64, 0x200, QStringLiteral("PE-branch-fixture"));
            owner.setFileAnalysisContext(image, imageBase, regions);
            owner.showDisassemblyAt(0x200);
            flushEvents();
        };
        load(QByteArray::fromHex("e8fb1f0000c3"));
        auto* view = owner.disassemblyView();
        const auto call = view->model()->rowAt(0);
        bool parsed = false;
        const auto decodedTarget = call ? call->operands.trimmed().mid(2).toULongLong(&parsed, 16) : 0;
        require(call && call->decoded && call->address == 0x200
            && call->mnemonic.compare(QStringLiteral("call"), Qt::CaseInsensitive) == 0
            && parsed && decodedTarget == imageBase + 0x3000,
            "PE relative call operands use the real virtual address while rows retain raw file offsets");
        view->canvas()->setSelectedRow(0);
        QTest::keyClick(view->canvas(), Qt::Key_Return);
        flushEvents();
        require(view->anchorAddress() == 0x400 && owner.hexEditor()->caretAddress() == 0x400
            && owner.selectedInstruction() && owner.selectedInstruction()->address == 0x400
            && owner.selectedInstruction()->originalBytes == QByteArray::fromHex("c3"),
            "Enter follows a PE call across differently mapped sections to its actual captured target bytes");
        QTest::keyClick(view->canvas(), Qt::Key_Backspace);
        flushEvents();
        require(view->anchorAddress() == 0x200, "PE branch back-navigation restores the raw source offset");
        for (const auto& unavailable : {QByteArray::fromHex("e8fb0f0000c3"), QByteArray::fromHex("e8fb140000c3")})
        {
            load(unavailable);
            view->canvas()->setSelectedRow(0);
            QTest::keyClick(view->canvas(), Qt::Key_Return);
            flushEvents();
            require(view->anchorAddress() == 0x200 && owner.hexEditor()->caretAddress() == 0x200,
                "PE calls to zero-fill or unmapped virtual ranges cannot jump to fabricated file offsets");
        }
        load(QByteArray::fromHex("488b05f91f0000c3"));
        const auto rip = view->model()->rowAt(0);
        bool ripMapped = false;
        if (rip)
        {
            QRegularExpression numbers(QStringLiteral("0x[0-9a-fA-F]+"));
            auto matches = numbers.globalMatch(rip->operands);
            while (matches.hasNext())
                if (matches.next().captured().mid(2).toULongLong(nullptr, 16) == imageBase + 0x3000) ripMapped = true;
        }
        require(rip && rip->decoded && ripMapped,
            "PE RIP-relative operands use virtual locations independently of the file-offset row label");
        image->at(0x2ff) = 0x48;
        const QByteArray boundarySnapshot(reinterpret_cast<const char*>(image->data()), static_cast<qsizetype>(image->size()));
        owner.setSnapshot(boundarySnapshot, 0, DisassemblyArchitecture::X64, 0x2ff);
        owner.setFileAnalysisContext(image, imageBase, regions);
        owner.showDisassemblyAt(0x2ff);
        flushEvents();
        const auto boundary = view->model()->rowAt(0);
        require(boundary && !boundary->decoded && boundary->address == 0x2ff
            && boundary->bytes == QByteArray::fromHex("48"),
            "instruction decoding never borrows raw alignment padding past a mapped PE section tail");
        owner.showDisassemblyAt(0x300);
        flushEvents();
        require(view->model()->rowAt(0) && !view->model()->rowAt(0)->decoded,
            "unmapped PE file padding remains visible as bytes without claiming executable instructions");
        owner.setAddressKind(SnapshotAddressKind::MemoryAddress);
        owner.setSnapshot(QByteArray::fromHex("e8fb1f0000c3"), imageBase + 0x1000);
        owner.showDisassemblyAt(imageBase + 0x1000);
        flushEvents();
        const auto memoryCall = view->model()->rowAt(0);
        parsed = false;
        require(memoryCall && memoryCall->address == imageBase + 0x1000
            && memoryCall->operands.trimmed().mid(2).toULongLong(&parsed, 16) == imageBase + 0x3000 && parsed,
            "returning to a raw memory snapshot keeps ordinary virtual instruction addresses unchanged");
    }

    void checkPseudocodeSharedView()
    {
        using namespace ks::ui;
        QTemporaryDir directory;
        const auto root = createHeadlessFixture(directory);
        FixtureEnvironment java("KSWORD_GHIDRA_JAVA", protocolLauncher.toLocal8Bit());
        FixtureEnvironment ghidra("KSWORD_GHIDRA_DIR", root.toLocal8Bit());
        FixtureEnvironment mode("KSWORD_GHIDRA_FIXTURE_MODE", "success");
        FixtureEnvironment delay("KSWORD_GHIDRA_FIXTURE_DELAY", "0");
        constexpr std::uint64_t base = 0x140001000ULL;
        const auto original = QByteArray::fromHex("b82a000000c3");
        SnapshotWorkbenchWidget owner;
        owner.resize(1100, 650);
        owner.setSnapshot(original, base, DisassemblyArchitecture::X64, base, QStringLiteral("C-source-one"));
        owner.show();
        auto* tabs = owner.findChild<QTabWidget*>();
        auto* code = owner.pseudocodeView();
        auto* configured = owner.findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"));
        auto* locateHex = owner.findChild<QPushButton*>(QStringLiteral("memory_pseudocode_locate_hex"));
        auto* locateDisassembly = owner.findChild<QPushButton*>(QStringLiteral("memory_pseudocode_locate_disassembly"));
        require(tabs && tabs->count() == 5 && code && code->isReadOnly() && configured
            && locateHex && locateDisassembly, "C is a fifth read-only page on the actual shared byte editor");
        auto* installPlugin = owner.findChild<QPushButton*>(QStringLiteral("memory_install_ghidra_plugin"));
        require(installPlugin != nullptr, "shared C exposes the managed plugin installation action");
#ifndef KSWORD_EDITOR_PRODUCTION_OBJECT_TESTS
        fixture::lastManagedPlugin.clear();
        installPlugin->click();
        require(fixture::lastManagedPlugin == QStringLiteral("ghidra"),
            "shared C opens native plugin management with the Ghidra backend preselected");
#endif
        configured->setText(root);
        QVector<DecompilerResult> results;
        QObject::connect(owner.decompiler(), &GhidraDecompiler::finished, &owner,
            [&](const auto& result) { results.push_back(result); });
        owner.showPseudocodeAt(base + 5);
        require(tabs->currentIndex() == 4 && owner.decompiler()->isRunning(),
            "show pseudocode uses the selected captured address and starts asynchronous analysis");
        require(waitFor([&]() { return !owner.decompiler()->isRunning(); })
            && code->toPlainText().contains(QStringLiteral("return 42;")),
            "validated headless C renders in the shared component");
        // Scanner 同窗命中只移动地址，不重读字节；直接点 C 按钮必须分析新的 B。
        auto* decompileButton = owner.findChild<QPushButton*>(QStringLiteral("memory_decompile_function"));
        require(decompileButton != nullptr, "C function button is available on the shared page");
        owner.jumpToAddress(base);
        decompileButton->click();
        require(waitFor([&]() { return !owner.decompiler()->isRunning(); }) && !results.isEmpty()
            && results.last().success && results.last().functionAddress == base,
            "same-window Scanner navigation changes the actual C process request from A to B");
        owner.hexEditor()->jumpToAddress(base + 5);
        decompileButton->click();
        require(waitFor([&]() { return !owner.decompiler()->isRunning(); }) && results.last().success
            && results.last().functionAddress == base + 5,
            "native HEX caret motion also synchronizes the actual C analysis request");
        flushEvents();
        if (!previewDirectory.isEmpty())
            require(owner.grab().save(previewDirectory + QStringLiteral("/shared-pseudocode-fixture.png")),
                "the real shared C page renders to an inspectable preview");
        auto* codeEditor = dynamic_cast<CodeTextEdit*>(code);
        require(codeEditor != nullptr, "shared C uses the production numbered code editor");
        auto* gutter = codeEditor->findChild<QWidget*>(QStringLiteral("code_editor_gutter"));
        require(gutter != nullptr, "shared C exposes the actual painted number gutter");
        const auto shortGutter = gutter->width();
        qputenv("KSWORD_GHIDRA_FIXTURE_MODE", "many-lines");
        owner.showPseudocodeAt(base + 5);
        require(waitFor([&]() { return !owner.decompiler()->isRunning(); })
            && code->document()->blockCount() > 100 && gutter->width() > shortGutter,
            "safe text mutation replays line-count changes so long C output widens its native number gutter");
        qputenv("KSWORD_GHIDRA_FIXTURE_MODE", "success");
        const auto rendered = code->toPlainText();
        QTest::keyClicks(code, "overwrite");
        require(code->toPlainText() == rendered && owner.data() == original && !owner.hasChanges(),
            "read-only C keyboard input cannot modify code text or captured bytes");
        QTextCursor cursor(code->document()->findBlockByNumber(1));
        code->setTextCursor(cursor);
        require(!locateHex->isEnabled() && !locateDisassembly->isEnabled(),
            "a C line without an instruction mapping cannot trigger an invented jump");
        cursor = QTextCursor(code->document()->findBlockByNumber(2));
        code->setTextCursor(cursor);
        require(locateHex->isEnabled() && locateDisassembly->isEnabled(),
            "mapped C statements enable both shared byte and disassembly jumps");
        std::uint64_t observedAddress = 0;
        QObject::connect(&owner, &SnapshotWorkbenchWidget::currentAddressChanged, &owner,
            [&](std::uint64_t address) { observedAddress = address; });
        locateHex->click();
        require(tabs->currentIndex() == 0 && owner.hexEditor()->caretAddress() == base + 5
            && observedAddress == base + 5, "C statement navigation preserves the full address and notifies its host");
        tabs->setCurrentIndex(4);
        locateDisassembly->click();
        flushEvents();
        require(tabs->currentIndex() == 1 && owner.selectedInstruction()
            && owner.selectedInstruction()->address == base + 5,
            "C statement navigation selects the matching real instruction");
        owner.setEditable(true);
        require(owner.hexEditor()->setByteQuiet(base + 1, 43),
            "the staged-byte test updates a valid shared cache byte");
        owner.refreshFromHexEditor();
        require(code->toPlainText().isEmpty() && owner.hasChanges(),
            "staged byte changes invalidate old C evidence immediately");
        results.clear();
        owner.showPseudocodeAt(base);
        require(waitFor([&]() { return !owner.decompiler()->isRunning(); }) && !results.isEmpty()
            && results.back().success
            && results.back().snapshotSha256 == QCryptographicHash::hash(owner.data(), QCryptographicHash::Sha256),
            "new C analysis imports the current staged bytes with their exact SHA256");
        owner.undo();
        require(code->toPlainText().isEmpty() && owner.data() == original,
            "undo invalidates C derived from the staged bytes");
        require(gutter->width() == shortGutter,
            "clearing old C restores the short native line-number gutter");

        qputenv("KSWORD_GHIDRA_FIXTURE_DELAY", "500");
        owner.showPseudocodeAt(base);
        QTest::qWait(35);
        owner.setSnapshot(original, base, DisassemblyArchitecture::X64, base, QStringLiteral("C-source-two"));
        require(waitFor([&]() { return !owner.decompiler()->isRunning(); }) && code->toPlainText().isEmpty()
            && owner.data() == original, "same-address source replacement cancels stale C and preserves new evidence");
        qputenv("KSWORD_GHIDRA_FIXTURE_DELAY", "0");

        const auto pe = syntheticPe();
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        owner.setEditable(false);
        owner.setSnapshot(original, 0x200, DisassemblyArchitecture::X64, 0x200, QStringLiteral("PE-C-source"));
        owner.setFileAnalysisContext(pe, 0x140000000ULL,
            {{0x200, 0x200, 0x1000, 0x100, QStringLiteral(".text"), true}});
        results.clear();
        owner.showPseudocodeAt(0x200);
        require(waitFor([&]() { return !owner.decompiler()->isRunning(); }) && !results.isEmpty()
            && results.back().success && results.back().functionAddress == base,
            "PE pseudocode passes the mapped VA to the backend while the shared editor displays file offsets");
        code->setTextCursor(QTextCursor(code->document()->findBlockByNumber(2)));
        locateHex->click();
        require(tabs->currentIndex() == 0 && owner.hexEditor()->caretAddress() == 0x200
            && owner.data() == original && !owner.hasChanges(),
            "PE C navigation converts its instruction VA back to the exact read-only file offset");
        owner.setFileAnalysisContext(pe, 0x140000000ULL,
            {{0x200, 0x200, 0x1000, 0x100, QStringLiteral(".text"), true}}, false);
        results.clear();
        owner.showPseudocodeAt(0x200);
        flushEvents();
        require(!owner.decompiler()->isRunning() && results.isEmpty() && code->toPlainText().isEmpty(),
            "non-x86 PE context cannot silently fall back to an x86 raw decompile");

        owner.setCapturedAddressRange(0, 0x400);
        quint64 requestedAddress = 0, requestedLength = 0;
        unsigned requests = 0;
        bool capturedRequestsBounded = true; // 所有预取和定位均不得超出冻结文件范围。
        QObject::connect(&owner, &SnapshotWorkbenchWidget::windowRequested, &owner,
            [&](quint64 address, quint64 length) {
                requestedAddress = address;
                requestedLength = length;
                capturedRequestsBounded = capturedRequestsBounded && address < 0x400 && length > 0
                    && length <= 0x400 - address;
                ++requests;
            });
        owner.jumpToAddress(0x3f0);
        require(requests == 1 && requestedAddress == 0x3f0 && requestedLength == 0x10
            && owner.data() == original, "off-window analysis navigation requests only the available captured file tail");
        owner.jumpToAddress(0x400);
        require(requests == 1, "captured-range navigation never requests a byte past the file tail");
        // C 页映射后的地址可落在同一文件的其它捕获窗口，不扩大允许范围。
        auto* sharedC = owner.findChild<WorkbenchPseudocodeView*>();
        const auto beforeHexNavigation = requests;
        sharedC->requestHexLocate(0x3e0);
        require(requests > beforeHexNavigation && requestedAddress == 0x3e0 && requestedLength == 0x20
            && tabs->currentIndex() == 0, "C HEX navigation requests a bounded off-window captured tail");
        const auto beforeAssemblyNavigation = requests;
        sharedC->requestDisasmLocate(0x3e8);
        // 首次装配反汇编可先预取当前窗口；最终定位必须仍是指定的合法尾部。
        require(requests > beforeAssemblyNavigation && requestedAddress == 0x3e8 && requestedLength == 0x18
            && tabs->currentIndex() == 1, "C assembly navigation requests a bounded off-window captured tail");
        const auto beforePseudocodeNavigation = requests;
        owner.showPseudocodeAt(0x3f0);
        require(requests == beforePseudocodeNavigation + 1 && requestedAddress == 0x3f0 && requestedLength == 0x10
            && tabs->currentIndex() == 4 && !owner.decompiler()->isRunning(),
            "off-window C activation waits for captured bytes before starting analysis");
        const auto completedNavigationRequests = requests;
        sharedC->requestHexLocate(0x400);
        sharedC->requestDisasmLocate(0x400);
        owner.showPseudocodeAt(0x400);
        require(requests == completedNavigationRequests && capturedRequestsBounded,
            "all C navigation paths reject addresses beyond the captured tail");
        owner.clear();
        owner.jumpToAddress(0x3f0);
        require(requests == completedNavigationRequests && code->toPlainText().isEmpty(),
            "clear removes old captured-range callbacks and C evidence");
        owner.setSnapshot(original, 0x200);
        owner.setCapturedAddressRange(0, 0x400);
        owner.setSnapshot(original, 0x200, DisassemblyArchitecture::X64, 0x200, QStringLiteral("new-capture"));
        owner.jumpToAddress(0x3f0);
        require(requests == completedNavigationRequests, "source replacement removes the prior source captured range");

        QPointer<SnapshotWorkbenchWidget> retiring = new SnapshotWorkbenchWidget;
        retiring->setSnapshot(original, base);
        retiring->findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(root);
        qputenv("KSWORD_GHIDRA_FIXTURE_DELAY", "500");
        retiring->showPseudocodeAt(base);
        QTest::qWait(35);
        delete retiring.data();
        flushEvents();
        require(retiring.isNull(), "destroying a shared editor safely cancels pending headless analysis");

        QPointer<SnapshotWorkbenchWidget> deleteOnAddress = new SnapshotWorkbenchWidget;
        deleteOnAddress->setSnapshot(original, base);
        QObject::connect(deleteOnAddress, &SnapshotWorkbenchWidget::currentAddressChanged, qApp,
            [deleteOnAddress](quint64) { delete deleteOnAddress.data(); });
        deleteOnAddress->showPseudocodeAt(base);
        require(deleteOnAddress.isNull(),
            "pseudocode activation permits its host to destroy the editor during an address notification");
        flushEvents();
        QPointer<SnapshotWorkbenchWidget> deleteOnRunning = new SnapshotWorkbenchWidget;
        deleteOnRunning->setSnapshot(original, base);
        deleteOnRunning->findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(root);
        QObject::connect(deleteOnRunning->decompiler(), &GhidraDecompiler::runningChanged, qApp,
            [deleteOnRunning](bool running) { if (running) delete deleteOnRunning.data(); });
        deleteOnRunning->showPseudocodeAt(base);
        require(deleteOnRunning.isNull(),
            "pseudocode launch permits synchronous owner destruction from backend state observers");
        flushEvents();

        qputenv("KSWORD_GHIDRA_FIXTURE_DELAY", "0");
        QPointer<SnapshotWorkbenchWidget> deleteOnCodeClear = new SnapshotWorkbenchWidget;
        deleteOnCodeClear->setSnapshot(original, base);
        deleteOnCodeClear->findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(root);
        deleteOnCodeClear->showPseudocodeAt(base);
        require(waitFor([&]() { return !deleteOnCodeClear->decompiler()->isRunning(); })
            && !deleteOnCodeClear->pseudocodeView()->toPlainText().isEmpty(),
            "snapshot-clear lifetime scenario begins with populated real C output");
        QObject::connect(deleteOnCodeClear->pseudocodeView(), &QPlainTextEdit::textChanged, qApp,
            [deleteOnCodeClear]() { delete deleteOnCodeClear.data(); });
        deleteOnCodeClear->setSnapshot(original, base, DisassemblyArchitecture::X64,
            base, QStringLiteral("destroy-on-C-clear"));
        require(deleteOnCodeClear.isNull(),
            "snapshot replacement survives owner destruction from clearing old C text");
        flushEvents();

        SnapshotWorkbenchWidget replacedDuringResult;
        replacedDuringResult.setSnapshot(original, base, DisassemblyArchitecture::X64,
            base, QStringLiteral("C-result-before-replacement"));
        replacedDuringResult.findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(root);
        bool replaced = false;
        QObject::connect(replacedDuringResult.pseudocodeView(), &QPlainTextEdit::textChanged,
            &replacedDuringResult, [&]() {
                if (replaced) return;
                replaced = true;
                replacedDuringResult.setSnapshot(original, base, DisassemblyArchitecture::X64,
                    base, QStringLiteral("C-result-after-replacement"));
            });
        replacedDuringResult.showPseudocodeAt(base);
        require(waitFor([&]() { return !replacedDuringResult.decompiler()->isRunning(); }) && replaced,
            "result-delivery reentrancy test actually replaces the captured source");
        const auto* replacementStatus = replacedDuringResult.findChild<QLabel*>(QStringLiteral("memory_pseudocode_status"));
        require(replacedDuringResult.pseudocodeView()->toPlainText().isEmpty() && replacementStatus
            && !replacementStatus->text().contains(QStringLiteral("fixture_function"))
            && replacementStatus->toolTip().isEmpty(),
            "a callback that replaces the source cannot publish the old function status or diagnostics afterwards");

        SnapshotWorkbenchWidget restartedDuringInvalidation;
        restartedDuringInvalidation.setSnapshot(original, base);
        restartedDuringInvalidation.findChild<QLineEdit*>(QStringLiteral("memory_decompiler_directory"))->setText(root);
        restartedDuringInvalidation.showPseudocodeAt(base);
        require(waitFor([&]() { return !restartedDuringInvalidation.decompiler()->isRunning(); })
            && !restartedDuringInvalidation.pseudocodeView()->toPlainText().isEmpty(),
            "nested decompile scenario begins with populated C output");
        bool restartedInner = false;
        QObject::connect(restartedDuringInvalidation.pseudocodeView(), &QPlainTextEdit::textChanged,
            &restartedDuringInvalidation, [&]() {
                if (restartedInner) return;
                restartedInner = true;
                restartedDuringInvalidation.showPseudocodeAt(base + 5);
            });
        restartedDuringInvalidation.showPseudocodeAt(base);
        require(waitFor([&]() { return !restartedDuringInvalidation.decompiler()->isRunning(); }) && restartedInner,
            "clearing old C really schedules a nested decompile at a different address");
        const auto* restartedStatus = restartedDuringInvalidation.findChild<QLabel*>(QStringLiteral("memory_pseudocode_status"));
        const auto innerAddress = QStringLiteral("0x%1").arg(base + 5, 0, 16).toUpper();
        require(restartedStatus && restartedStatus->text().count(innerAddress) == 2,
            "an outer invalidation cannot relabel the nested function result with its old analysis position");
    }

    // Exercise the production row canvas, including its selection/edit distinction.
    QLineEdit* clickEditor(ks::ui::SnapshotWorkbenchWidget& widget)
    {
        auto* view = widget.disassemblyView();
        auto* canvas = view->canvas();
        if (view->isEditing())
        {
            if (auto* active = view->findChild<QLineEdit*>(QStringLiteral("ksMemwbDisasmInlineEditor")))
                QTest::keyClick(active, Qt::Key_Escape);
            flushEvents();
        }
        const auto point = canvas->contentRect(0).center();
        QTest::mouseClick(canvas->viewport(), Qt::LeftButton, Qt::NoModifier, point);
        flushEvents();
        require(!view->isEditing(), "single click selects without starting assembly editing");
        QTest::mouseDClick(canvas->viewport(), Qt::LeftButton, Qt::NoModifier, point);
        flushEvents();
        auto* editor = view->findChild<QLineEdit*>(QStringLiteral("ksMemwbDisasmInlineEditor"));
        require(editor != nullptr && editor->isVisible(), "double click opens the canvas inline editor");
        for (auto* window : QApplication::topLevelWidgets())
            require(qobject_cast<QDialog*>(window) == nullptr || !window->isVisible(), "inline editing opens no dialog");
        return editor;
    }

    // submit 输入整条指令并按 Enter；只允许改变编辑器缓存。
    void submit(ks::ui::SnapshotWorkbenchWidget& widget, const char* instruction)
    {
        auto* editor = clickEditor(widget);
        editor->setText(QString::fromLatin1(instruction));
        QTest::keyClick(editor, Qt::Key_Return);
        flushEvents();
    }

    // 真实菜单/汇编预览的父销毁与陈旧请求回归。只操作假快照，不访问任何目标内存。
    // 场景 0/1 在菜单/对话框期间销毁宿主；2/3 在成功预览后暂停权限或替换目标；4 正常提交。
    void checkModalLifetimeAndStaleRequests()
    {
        constexpr std::uint64_t modalBase = 0x1000; // 所有目标共用地址，避免只靠地址误通过
        const QByteArray bytes = QByteArray::fromHex("b801000000c3");
        for (int scenario = 0; scenario < 5; ++scenario)
        {
            QPointer<ks::ui::SnapshotWorkbenchWidget> owner = new ks::ui::SnapshotWorkbenchWidget;
            owner->resize(1100, 650);
            owner->setSnapshot(bytes, modalBase);
            owner->setEditable(true);
            owner->show();
            owner->showDisassemblyAt(modalBase);
            flushEvents();
            bool drovePopup = false; // 必须确实进入目标弹窗，不能把未触发测试当成安全
            QTimer watchdog; // 超时仅关闭本用例弹窗，作用域退出便撤销定时任务
            watchdog.setSingleShot(true);
            QObject::connect(&watchdog, &QTimer::timeout, &watchdog, []() {
                if (auto* popup = QApplication::activePopupWidget()) { popup->close(); }
                if (auto* modal = QApplication::activeModalWidget()) { modal->close(); }
            });
            watchdog.start(3000);
            QTimer::singleShot(0, owner.data(), [&]() {
                auto* menu = qobject_cast<QMenu*>(QApplication::activePopupWidget());
                if (menu == nullptr) { return; }
                if (scenario == 0)
                {
                    drovePopup = true;
                    delete owner.data();
                    return;
                }
                QAction* assemblyAction = nullptr; // 冻结菜单中真实汇编动作
                for (auto* action : menu->actions())
                {
                    if (action->text().contains(QStringLiteral("汇编编辑"))) { assemblyAction = action; }
                }
                if (assemblyAction == nullptr) { menu->close(); return; }
                QTimer::singleShot(0, owner.data(), [&]() {
                    auto* dialog = qobject_cast<QDialog*>(QApplication::activeModalWidget());
                    if (dialog == nullptr) { return; }
                    if (scenario == 1)
                    {
                        drovePopup = true;
                        delete owner.data();
                        return;
                    }
                    auto* source = dialog->findChild<QPlainTextEdit*>(QStringLiteral("ksMemwbAssemblySource"));
                    QPushButton* compile = nullptr;
                    QPushButton* stage = nullptr;
                    for (auto* button : dialog->findChildren<QPushButton*>())
                    {
                        if (button->text().contains(QStringLiteral("编译"))) { compile = button; }
                        if (button->text().contains(QStringLiteral("填入暂存"))) { stage = button; }
                    }
                    if (source == nullptr || compile == nullptr || stage == nullptr) { dialog->reject(); return; }
                    source->setPlainText(QStringLiteral("nop"));
                    compile->click();
                    drovePopup = stage->isEnabled();
                    if (!drovePopup) { dialog->reject(); return; }
                    if (scenario == 2) { owner->setEditable(false); owner->setEditable(true); }
                    if (scenario == 3)
                    {
                        owner->setSnapshot(bytes, modalBase, ks::ui::DisassemblyArchitecture::X64,
                            modalBase, QStringLiteral("new-target"));
                    }
                    stage->click();
                });
                menu->setActiveAction(assemblyAction);
                QTest::keyClick(menu, Qt::Key_Return);
            });
            auto* canvas = owner->disassemblyView()->canvas();
            emit canvas->contextMenuRequested(canvas->rowRect(0).center());
            watchdog.stop();
            require(drovePopup, "modal regression enters the requested popup");
            if (scenario < 2)
            {
                require(owner.isNull(), "parent destruction exits modal interaction safely");
            }
            else
            {
                require(owner != nullptr, "normal modal return keeps its owner");
                if (owner->hasChanges() != (scenario == 4))
                    std::cerr << "Modal scenario " << scenario << " cache=" << owner->data().toHex().constData() << '\n';
                require(owner->hasChanges() == (scenario == 4), "stale assembly payload cannot change new context");
                delete owner.data();
            }
            flushEvents();
        }
    }

    void checkSnapshotTextBounds()
    {
        using namespace ks::ui;
        SnapshotWorkbenchWidget owner;
        constexpr std::uint64_t snapshotBase = 0x2000;
        owner.setSnapshot(QByteArray(128, 'A'), snapshotBase,
            DisassemblyArchitecture::X64, snapshotBase + 8);
        owner.textView()->setEncoding(WorkbenchTextView::Encoding::Utf8);
        owner.findChild<QTabWidget*>()->setCurrentIndex(2);
        auto* text = owner.textView();
        require(!text->canvas()->rows().isEmpty(), "snapshot text starts from captured bytes");
        text->canvas()->requestMore(-1, 3);
        require(text->windowAddress() == snapshotBase && !text->canvas()->rows().isEmpty(),
            "snapshot text backward browse clamps to its actual captured base");
        require(text->canvas()->rows().front().address == snapshotBase,
            "snapshot text lookbehind cannot read below the captured base");
        text->setWindow(snapshotBase + 127, 1);
        text->canvas()->requestMore(1, 3);
        require(text->windowAddress() == snapshotBase + 127,
            "snapshot text forward browse stops at its actual captured tail");
        require(text->canvas()->rows().size() == 1 && text->canvas()->rows().front().bytes == QByteArray("A"),
            "captured tail remains visible after a rejected forward move");

        owner.setSnapshot(QByteArray(16, 'X'), 0xFFFFFFF0ULL, DisassemblyArchitecture::X86);
        text->setWindow(0xFFFFFFFFULL, 1);
        text->canvas()->requestMore(1, 3);
        require(text->windowAddress() == 0xFFFFFFFFULL && !text->canvas()->rows().isEmpty(),
            "32-bit snapshot text does not browse beyond its last captured address");

        owner.setSnapshot(QByteArray("Z"), UINT64_MAX, DisassemblyArchitecture::X64);
        text->canvas()->requestMore(-1, 3);
        text->canvas()->requestMore(1, 3);
        require(text->windowAddress() == UINT64_MAX && text->canvas()->rows().size() == 1
            && text->canvas()->rows().front().bytes == QByteArray("Z"),
            "one-byte UINT64_MAX snapshot keeps bounded text navigation without overflow");
        owner.clear();
        require(text->canvas()->rows().isEmpty(), "empty snapshot has no text evidence");
        text->canvas()->requestMore(1, 3);
        require(text->canvas()->rows().isEmpty(), "empty snapshot cannot browse stale captured bytes");
    }

    // 快照 HEX 的首行取实际捕获基址，高位地址不扩展成包含不可读前缀的空间。
    void checkSnapshotHexInitialPosition()
    {
        using namespace ks::ui;
        constexpr std::uint64_t snapshotBase = 0x7FFE6E5B0000ULL;
        const QByteArray bytes(4096, 'X'); // 可读人工快照，不访问真实进程。
        SnapshotWorkbenchWidget owner;
        owner.resize(1100, 650);
        owner.setSnapshot(bytes, snapshotBase, DisassemblyArchitecture::X64);
        owner.show();
        flushEvents();
        auto* canvas = owner.hexEditor()->findChild<HexCanvas*>();
        require(canvas != nullptr, "high-address snapshot uses the shared HEX canvas");
        require(canvas->firstVisibleRow() == 0 && canvas->caretAddress() == snapshotBase,
            "high-address snapshot opens at its first captured row");
        auto visible = canvas->visibleAddressRange();
        require(visible && visible->first == snapshotBase && visible->last < snapshotBase + bytes.size(),
            "initial snapshot viewport contains only its actual captured range");
        require(owner.data() == bytes, "initial HEX positioning preserves captured evidence");
        owner.resize(700, 480);
        flushEvents();
        visible = canvas->visibleAddressRange();
        require(canvas->firstVisibleRow() == 0 && visible && visible->first == snapshotBase,
            "first resize preserves the high-address snapshot top row");
    }

    void checkKernelModalParentLifetime()
    {
        QPointer<ks::ui::KernelDisassemblyDialog> owner = new ks::ui::KernelDisassemblyDialog;
        owner->setSnapshot(QByteArray::fromHex("90c3"), 0xFFFF800000002000ULL,
            ks::ui::DisassemblyArchitecture::X64, QStringLiteral("lifetime fixture"));
        owner->setKernelMutationEnabled(true);
        bool entered = false;
        QTimer::singleShot(0, owner, [&]() {
            entered = QApplication::activeModalWidget() != nullptr;
            delete owner.data();
        });
        owner->requestModifyBytes(0xFFFF800000002000ULL, QByteArray::fromHex("90"));
        require(entered && owner.isNull(), "kernel modal evidence owner may retire without deleting a stack dialog");
        flushEvents();
    }

    QByteArray capturedRowBytes(const ks::ui::MemoryRowCanvas* canvas)
    {
        QByteArray bytes;
        for (const auto& row : canvas->rows()) bytes += row.bytes;
        return bytes;
    }

    void saveFilePreview(ks::ui::SnapshotWorkbenchWidget& owner, const QString& name)
    {
        if (previewDirectory.isEmpty()) return;
        for (const auto& size : {QSize(1100, 650), QSize(700, 480)})
        {
            owner.resize(size);
            flushEvents();
            const auto path = QDir(previewDirectory).filePath(name + QLatin1Char('-')
                + QString::number(size.width()) + QLatin1Char('x') + QString::number(size.height()) + QStringLiteral(".png"));
            require(owner.grab().save(path), "file shared-view preview is saved");
        }
        owner.resize(1100, 650);
        flushEvents();
    }

    // File coordinates must remain 64-bit independently of the code decoder.
    // All bytes here are synthetic snapshots; no disk or process is written.
    void checkFileSnapshotViews()
    {
        using namespace ks::ui;
        constexpr std::uint64_t fileOffset = 0x100002000ULL;
        const auto bytes = QByteArray::fromHex("b801000000c3");
        SnapshotWorkbenchWidget owner;
        require(owner.addressKind() == SnapshotAddressKind::MemoryAddress,
            "existing snapshot owners default to memory addresses");
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        owner.setEditable(false);
        owner.setSnapshot(bytes, fileOffset, DisassemblyArchitecture::X86,
            fileOffset, QStringLiteral("fixture-file-one"));
        owner.resize(1100, 650);
        owner.show();
        owner.activateWindow();
        auto* tabs = owner.findChild<QTabWidget*>();
        require(tabs != nullptr && tabs->count() == 5,
            "file snapshots expose shared hex disassembly text comparison and C tabs");
        require(owner.baseAddress() == fileOffset && owner.data() == bytes
            && owner.hexEditor()->baseAddress() == fileOffset,
            "hex retains file offset above four GiB without changing bytes");
        require(!owner.hexEditor()->isEditable() && !owner.disassemblyView()->isEditable(),
            "file owner read-only permission applies to both editing surfaces");
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        require(owner.data() == bytes, "reapplying the same coordinate domain keeps the snapshot");

        owner.showDisassemblyAt(fileOffset);
        flushEvents();
        auto* disasm = owner.disassemblyView();
        auto* canvas = disasm->canvas();
        require(!disasm->isX64() && owner.currentArchitecture() == DisassemblyArchitecture::X86,
            "file address width does not force the x86 decoder into x64");
        require(canvas->rows().size() >= 2 && canvas->rows().front().address == fileOffset
            && canvas->rows().at(1).address == fileOffset + 5 && canvas->rows().at(1).bytes == QByteArray::fromHex("c3"),
            "x86 decoded instruction rows retain full 64-bit file offsets");
        require(canvas->rows().front().tokens.front().text.compare(QStringLiteral("mov"), Qt::CaseInsensitive) == 0
            && capturedRowBytes(canvas) == bytes,
            "disassembly uses exactly the shared snapshot without zero padding");
        require(!canvas->rows().back().selectable && canvas->rows().back().bytes.isEmpty()
            && canvas->rows().back().tokens.front().text == QStringLiteral("超出已读取窗口"),
            "a file snapshot ending on a full instruction reports its actual captured limit");
        auto* decodedStatus = disasm->findChild<QLabel*>(QStringLiteral("ksMemwbDisasmStatus"));
        require(decodedStatus != nullptr && decodedStatus->text().contains(QStringLiteral("只读"))
            && !decodedStatus->text().contains(QStringLiteral("行内编辑")),
            "read-only file disassembly status describes the actual permission");
        owner.setEditable(true);
        require(decodedStatus->text().contains(QStringLiteral("行内编辑"))
            && !decodedStatus->text().contains(QStringLiteral("只读")),
            "live permission enable immediately restores editing status");
        owner.setEditable(false);
        require(decodedStatus->text().contains(QStringLiteral("只读"))
            && !decodedStatus->text().contains(QStringLiteral("行内编辑"))
            && disasm->anchorAddress() == fileOffset && capturedRowBytes(canvas) == bytes,
            "live permission pause immediately restores read-only status without replacing bytes");
        saveFilePreview(owner, QStringLiteral("file-disassembly"));
        canvas->setSelectedRow(1);
        const auto selectedInstruction = owner.selectedInstruction();
        require(owner.hexEditor()->caretAddress() == fileOffset + 5
            && selectedInstruction && selectedInstruction->address == fileOffset + 5,
            "instruction selection synchronizes the absolute file offset to hex");
        owner.showDisassemblyAt(fileOffset + 5);
        flushEvents();
        require(capturedRowBytes(canvas) == QByteArray::fromHex("c3"),
            "disassembly at the captured tail contains only its actual final byte");
        canvas->requestMore(1, 3);
        flushEvents();
        require(disasm->anchorAddress() == fileOffset + 5
            && capturedRowBytes(canvas) == QByteArray::fromHex("c3"),
            "file disassembly cannot browse beyond its captured tail");
        owner.showDisassemblyAt(fileOffset);
        flushEvents();
        canvas->requestMore(-1, 3);
        flushEvents();
        require(disasm->anchorAddress() == fileOffset && capturedRowBytes(canvas) == bytes,
            "file disassembly cannot browse below its captured start");

        owner.openFindPanel();
        flushEvents();
        auto* disasmFind = disasm->findChild<QLineEdit*>(QStringLiteral("ksMemwbDisasmFind"));
        require(tabs->currentIndex() == 1 && disasmFind != nullptr && disasmFind->isVisible()
            && QApplication::focusWidget() == disasmFind,
            "shared find command opens and focuses disassembly search in place");
        tabs->setCurrentIndex(2);
        owner.jumpToAddress(fileOffset);
        owner.textView()->setEncoding(WorkbenchTextView::Encoding::Utf8);
        flushEvents();
        auto* text = owner.textView();
        require(text->windowAddress() == fileOffset && !text->canvas()->rows().isEmpty()
            && text->canvas()->rows().front().address == fileOffset
            && capturedRowBytes(text->canvas()) == bytes,
            "x86 file text retains full offset and reads the same bytes as hex and disassembly");
        text->canvas()->requestMore(-1, 3);
        require(text->windowAddress() == fileOffset && capturedRowBytes(text->canvas()) == bytes,
            "file text lookbehind clamps at the captured offset");
        text->setWindow(fileOffset + 5, 1);
        text->canvas()->requestMore(1, 3);
        require(text->windowAddress() == fileOffset + 5
            && capturedRowBytes(text->canvas()) == QByteArray::fromHex("c3"),
            "file text at the captured tail contains no invented padding");
        owner.openFindPanel();
        flushEvents();
        auto* textFind = text->findChild<QLineEdit*>(QStringLiteral("ksMemwbTextFind"));
        require(tabs->currentIndex() == 2 && textFind != nullptr && QApplication::focusWidget() == textFind,
            "shared find command focuses text search in place");

        tabs->setCurrentIndex(1);
        owner.showDisassemblyAt(fileOffset);
        flushEvents();
        QTest::mouseDClick(canvas->viewport(), Qt::LeftButton, Qt::NoModifier, canvas->contentRect(0).center());
        QTest::keyClick(canvas, Qt::Key_Return);
        QTest::keyClick(canvas, Qt::Key_F2);
        disasm->beginSelectedInstructionEdit();
        emit disasm->stageRequested(fileOffset, QByteArray::fromHex("90"));
        flushEvents();
        require(!disasm->isEditing() && owner.data() == bytes && !owner.hasChanges(),
            "read-only disassembly rejects double click keyboard and stale stage requests");
        int editingControls = 0;
        for (const auto* button : owner.findChildren<QPushButton*>())
        {
            if (button->text() == QStringLiteral("汇编编辑")
                || button->text().contains(QStringLiteral("撤销"))
                || button->text().contains(QStringLiteral("重做")))
            {
                ++editingControls;
                require(button->isHidden(), "file read-only view hides unavailable editing controls");
            }
        }
        require(editingControls >= 3, "read-only visibility checks cover assembly undo and redo controls");
        tabs->setCurrentIndex(0);
        owner.jumpToAddress(fileOffset);
        auto* hexCanvas = owner.hexEditor()->findChild<HexCanvas*>();
        require(hexCanvas != nullptr, "file hex uses the production canvas");
        hexCanvas->setCaretAddress(fileOffset);
        QTest::keyClicks(hexCanvas, "90");
        owner.undo();
        owner.redo();
        flushEvents();
        require(owner.data() == bytes && !owner.hasChanges(),
            "read-only file keyboard undo and redo cannot stage bytes");

        tabs->setCurrentIndex(3);
        auto* comparisonPage = owner.findChild<WorkbenchCompareView*>();
        auto* comparison = comparisonPage ? comparisonPage->model() : nullptr;
        require(comparison && comparison->headerData(0, Qt::Horizontal, Qt::DisplayRole).toString() == QStringLiteral("文件偏移"),
            "file comparison names its actual coordinate column as file offset");
        require(comparison->rowCount() == 0, "an unchanged snapshot has no pending diff rows");
        const auto reread = QByteArray::fromHex("b802000000c3");
        owner.setSnapshot(reread, fileOffset, DisassemblyArchitecture::X86,
            fileOffset, QStringLiteral("fixture-file-one"));
        comparisonPage->setMode(WorkbenchCompareView::Mode::ExternalChange);
        flushEvents();
        require(comparison->rowCount() == 1
            && comparison->index(0, 0).data(Qt::UserRole).toULongLong() == fileOffset
            && QByteArray::fromHex(comparison->index(0, 1).data().toString().toLatin1()) == bytes
            && QByteArray::fromHex(comparison->index(0, 2).data().toString().toLatin1()) == reread
            && !owner.hasChanges(),
            "actual same-file rereads compare exact bytes in the formal shared virtual model");
        owner.setSnapshot(reread, fileOffset, DisassemblyArchitecture::X86,
            fileOffset, QStringLiteral("fixture-file-two"));
        flushEvents();
        require(comparison->rowCount() == 0, "comparison cannot inherit a different file baseline");
        owner.openFindPanel();
        require(tabs->currentIndex() == 0, "comparison find switches to the shared hex search surface");

        const auto utf8 = QByteArray::fromHex("efbbbf48656c6c6fe4b896e7958c");
        owner.setSnapshot(utf8, fileOffset, DisassemblyArchitecture::X86);
        tabs->setCurrentIndex(2);
        text->setEncoding(WorkbenchTextView::Encoding::Auto);
        flushEvents();
        require(text->hasBom() && text->effectiveEncoding() == WorkbenchTextView::Encoding::Utf8
            && text->renderedText().contains(QStringLiteral("Hello世界")),
            "file snapshots reuse BOM-aware Unicode text decoding");
        saveFilePreview(owner, QStringLiteral("file-text"));
        owner.clear();
        flushEvents();
        require(owner.data().isEmpty() && owner.originalBytes().isEmpty()
            && capturedRowBytes(canvas).isEmpty() && text->canvas()->rows().isEmpty()
            && comparison->rowCount() == 0 && !owner.selectedInstruction(),
            "clearing a failed file read removes old bytes from every shared view");
        canvas->requestMore(1, 3);
        text->canvas()->requestMore(-1, 3);
        require(capturedRowBytes(canvas).isEmpty() && text->canvas()->rows().isEmpty(),
            "cleared file views cannot recover stale bytes by browsing");
        owner.setSnapshot(bytes, fileOffset, DisassemblyArchitecture::X86);
        owner.setSnapshot(QByteArray(2, 'X'), UINT64_MAX, DisassemblyArchitecture::X86);
        flushEvents();
        require(owner.data().isEmpty() && capturedRowBytes(canvas).isEmpty()
            && text->canvas()->rows().isEmpty(), "wrapping file snapshots clear previous evidence");
        owner.setSnapshot(QByteArray("Z"), UINT64_MAX, DisassemblyArchitecture::X86);
        text->setWindow(UINT64_MAX, 1);
        text->canvas()->requestMore(1, 3);
        require(text->windowAddress() == UINT64_MAX && capturedRowBytes(text->canvas()) == QByteArray("Z"),
            "x86 file text preserves the final 64-bit offset without overflow");
    }

    void checkFileOffsetZero()
    {
        using namespace ks::ui;
        const auto bytes = QByteArray::fromHex("b801000000c3");
        const auto reread = QByteArray::fromHex("b802000000c3");
        SnapshotWorkbenchWidget owner;
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        owner.setEditable(false);
        owner.setSnapshot(bytes, 0, DisassemblyArchitecture::X86, 0, QStringLiteral("file-origin-fixture"));
        owner.showDisassemblyAt(0);
        flushEvents();
        auto* disasm = owner.disassemblyView();
        require(disasm->hasAnchor() && disasm->anchorAddress() == 0 && capturedRowBytes(disasm->canvas()) == bytes,
            "the first file snapshot establishes a real decode anchor at offset zero");
        const auto first = owner.selectedInstruction();
        require(first && first->address == 0 && first->originalBytes == QByteArray::fromHex("b801000000"),
            "file origin selects the exact first mov instruction instead of an empty unanchored view");

        owner.setSnapshot(reread, 0, DisassemblyArchitecture::X86, 0, QStringLiteral("file-origin-fixture"));
        flushEvents();
        const auto refreshed = owner.selectedInstruction();
        require(disasm->hasAnchor() && disasm->anchorAddress() == 0 && capturedRowBytes(disasm->canvas()) == reread
            && refreshed && refreshed->address == 0 && refreshed->originalBytes == QByteArray::fromHex("b802000000"),
            "refeeding file offset zero decodes the new bytes after the view resets its anchor");
        owner.clear();
        owner.setSnapshot(QByteArray::fromHex("90"), 0, DisassemblyArchitecture::X64);
        flushEvents();
        const auto reloaded = owner.selectedInstruction();
        require(disasm->hasAnchor() && disasm->anchorAddress() == 0 && capturedRowBytes(disasm->canvas()) == QByteArray::fromHex("90")
            && reloaded && reloaded->address == 0 && reloaded->originalBytes == QByteArray::fromHex("90"),
            "a cleared file view reloads and selects the exact new byte at offset zero");
    }

    void checkCapturedDisassemblyEndNote()
    {
        using namespace ks::ui;
        SnapshotWorkbenchWidget owner;
        constexpr std::uint64_t offset = 0x100002000ULL;
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        owner.setSnapshot(QByteArray(5000, static_cast<char>(0x90)), offset, DisassemblyArchitecture::X86);
        owner.showDisassemblyAt(offset);
        flushEvents();
        auto* canvas = owner.disassemblyView()->canvas();
        require(capturedRowBytes(canvas).size() == 4096
            && !canvas->rows().back().selectable && canvas->rows().back().bytes.isEmpty()
            && canvas->rows().back().tokens.front().text == QStringLiteral("继续滚动以读取下一段"),
            "a bounded decode window still offers continuation when more captured bytes exist");
        owner.showDisassemblyAt(offset + 4096);
        flushEvents();
        require(capturedRowBytes(canvas).size() == 904
            && canvas->rows().back().tokens.front().text == QStringLiteral("超出已读取窗口"),
            "moving into the final captured decode window replaces the continuation hint");
        owner.setSnapshot(QByteArray::fromHex("90"), UINT64_MAX, DisassemblyArchitecture::X86);
        owner.showDisassemblyAt(UINT64_MAX);
        flushEvents();
        require(capturedRowBytes(canvas) == QByteArray::fromHex("90")
            && canvas->rows().back().tokens.front().text == QStringLiteral("超出已读取窗口"),
            "the one-byte UINT64_MAX file offset reports its captured limit without overflow");
    }

    // Context-menu population is exercised without triggering a debugger action.
    // The portable runner substitutes only the external navigation helper.
    void checkFileContextIsolation()
    {
        using namespace ks::ui;
        const auto hasProcessNavigation = [](const QMenu& menu) {
            const auto actions = menu.actions();
            return std::any_of(actions.cbegin(), actions.cend(), [](const QAction* action) {
                // 生产菜单和便携桩均带稳定的工具名，不依赖桩专用文案。
                return action->text().contains(QStringLiteral("x64dbg"), Qt::CaseInsensitive);
            });
        };
        SnapshotWorkbenchWidget owner;
        constexpr std::uint64_t offset = 0x2000;
        const auto bytes = QByteArray::fromHex("90c3");
        owner.setSnapshot(bytes, offset, DisassemblyArchitecture::X64,
            offset, QStringLiteral("same-numeric-source"));
        owner.setProcessContext(123, 456);
        QMenu processMenu;
        emit owner.disassemblyView()->contextMenuAboutToShow(&processMenu, offset, true);
        require(hasProcessNavigation(processMenu), "memory snapshot retains explicitly supplied process navigation");
        owner.setAddressKind(SnapshotAddressKind::FileOffset);
        require(owner.data().isEmpty(), "changing coordinate domain clears the old snapshot");
        owner.setSnapshot(bytes, offset, DisassemblyArchitecture::X86,
            offset, QStringLiteral("same-numeric-source"));
        owner.setProcessContext(123, 456);
        QMenu fileDisasmMenu, fileTextMenu;
        emit owner.disassemblyView()->contextMenuAboutToShow(&fileDisasmMenu, offset, true);
        emit owner.textView()->contextMenuAboutToShow(&fileTextMenu, offset, true);
        require(!hasProcessNavigation(fileDisasmMenu) && !hasProcessNavigation(fileTextMenu),
            "file offsets reject inherited and explicitly resupplied process targets");
        owner.setAddressKind(SnapshotAddressKind::MemoryAddress);
        owner.setSnapshot(bytes, offset, DisassemblyArchitecture::X64,
            offset, QStringLiteral("same-numeric-source"));
        QMenu newMemoryMenu;
        emit owner.disassemblyView()->contextMenuAboutToShow(&newMemoryMenu, offset, true);
        require(!hasProcessNavigation(newMemoryMenu), "returning to memory mode cannot resurrect an old process target");

        QPointer<SnapshotWorkbenchWidget> retiring = new SnapshotWorkbenchWidget;
        retiring->setSnapshot(bytes, offset);
        QObject::connect(retiring, &SnapshotWorkbenchWidget::bytesChanged, retiring,
            [retiring]() { delete retiring.data(); });
        retiring->setAddressKind(SnapshotAddressKind::FileOffset);
        require(retiring.isNull(), "coordinate change remains safe when clearing destroys its owner");
        flushEvents();
    }
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv); // 离屏 Qt 事件循环。
    QFontDatabase::addApplicationFont(QStringLiteral("C:/Windows/Fonts/msyh.ttc"));
    if (QFontDatabase::families().contains(QStringLiteral("Microsoft YaHei")))
        application.setFont(QFont(QStringLiteral("Microsoft YaHei"), 9));
    if (argc > 1)
    {
        previewDirectory = QString::fromLocal8Bit(argv[1]);
        require(QDir().mkpath(previewDirectory), "preview output directory is available");
    }
    if (argc > 2) protocolLauncher = QString::fromLocal8Bit(argv[2]);
    // 测试偏好只写到截图输出下的 INI，隔离用户注册表和正式应用设置。
    QCoreApplication::setOrganizationName(QStringLiteral("KSwordTests"));
    QCoreApplication::setApplicationName(QStringLiteral("UnifiedSnapshotUi"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    const auto preferencesRoot = previewDirectory.isEmpty() ? QDir::currentPath() : previewDirectory;
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, preferencesRoot);
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, preferencesRoot);
    ks::ui::SnapshotWorkbenchWidget widget; // 生产编辑器，快照完全由测试提供。
    RunWorkbenchIntegrationRegressionTests(require);
    constexpr std::uint64_t base = 0x1000;
    const auto original = QByteArray::fromHex("b801000000c3"); // mov eax,1; ret。
    widget.resize(1100, 650);
    widget.setSnapshot(original, base);
    widget.setEditable(true);
    widget.show();
    widget.showDisassemblyAt(base);
    flushEvents();

    // 内嵌十六进制编辑器已是 HexView 门面：内部是自绘 HexCanvas，不再有旧的页签与 18 列表格。
    require(widget.hexEditor()->findChild<ks::ui::HexCanvas*>() != nullptr, "embedded HEX paints with HexCanvas");
    require(widget.hexEditor()->findChild<QTableWidget*>() == nullptr, "embedded HEX has no legacy table");
    require(widget.hexEditor()->findChild<QTabWidget*>() == nullptr, "embedded HEX has no legacy tab widget");
    // setHexOnlyView(true) 由统一编辑器调用：隐藏 HexView 自带状态条，避免与统一状态条重复。
    ks::ui::HexViewStatusBar* hexStatusBar = nullptr;
    for (auto* child : widget.hexEditor()->findChildren<QWidget*>())
        if (auto* bar = dynamic_cast<ks::ui::HexViewStatusBar*>(child)) hexStatusBar = bar;
    require(hexStatusBar != nullptr && hexStatusBar->isHidden(), "embedded HEX status bar hidden");

    require(widget.disassemblyView()->findChild<QTableWidget*>() == nullptr, "disassembly has no legacy instruction table");
    require(widget.disassemblyView()->canvas()->rows().size() >= 2, "canvas exposes actual instruction rows");
    auto* editor = clickEditor(widget);
    require(editor->text().startsWith(QStringLiteral("mov ")), "content pane edits the complete instruction");
    require(editor->width() > 100, "inline editor spans the right content pane");
    QTest::keyClick(editor, Qt::Key_Return);
    flushEvents();
    require(widget.data() == original && !widget.hasChanges(), "unchanged edit preserves bytes");

    // 错误空白和较长指令不能影响缓存或相邻 ret。
    submit(widget, "mov eax, 1 0");
    require(widget.data() == original, "invalid whitespace leaves cache unchanged");
    submit(widget, "mov rax, 1122334455667788");
    require(widget.data() == original, "long instruction cannot overwrite neighbor");
    submit(widget, "mov eax, 2");
    require(widget.data() == QByteArray::fromHex("b802000000c3"), "Enter stages valid instruction");
    require(widget.originalBytes() == original, "staging does not accept original snapshot");
    widget.undo();
    require(widget.data() == original, "inline edit participates in undo");
    widget.redo();
    require(widget.data() == QByteArray::fromHex("b802000000c3"), "inline edit participates in redo");
    widget.undo();

    // Esc 取消；缩短的指令填 NOP，长度和下一条指令保持不变。
    editor = clickEditor(widget);
    editor->setText(QStringLiteral("mov eax, 3"));
    QTest::keyClick(editor, Qt::Key_Escape);
    flushEvents();
    require(widget.data() == original, "Escape cancels inline edit");
    submit(widget, "nop");
    require(widget.data() == QByteArray::fromHex("9090909090c3"), "short instruction pads original span");
    widget.undo();
    require(widget.data() == original, "padded edit undoes as one transaction");

    // New snapshots, architecture and permissions cancel the frozen editor.
    QPointer<QLineEdit> frozenEditor = clickEditor(widget);
    frozenEditor->setText(QStringLiteral("mov eax, 4"));
    widget.setSnapshot(original, base + 0x100);
    widget.showDisassemblyAt(base + 0x100);
    flushEvents();
    require(!frozenEditor || !frozenEditor->isVisible(), "snapshot replacement cancels frozen inline input");
    require(widget.data() == original && !widget.hasChanges(), "replacement snapshot remains unchanged");

    frozenEditor = clickEditor(widget);
    frozenEditor->setText(QStringLiteral("mov eax, 6"));
    QComboBox* architecture = nullptr;
    for (auto* combo : widget.findChildren<QComboBox*>())
        if (combo->count() == 2 && combo->itemText(0) == QStringLiteral("x86")
            && combo->itemText(1) == QStringLiteral("x64")) architecture = combo;
    require(architecture != nullptr, "snapshot architecture selector found");
    architecture->setCurrentIndex(0);
    flushEvents();
    require(!frozenEditor || !frozenEditor->isVisible(), "architecture change cancels frozen inline input");
    require(widget.data() == original, "architecture change preserves snapshot bytes");
    architecture->setCurrentIndex(1);
    flushEvents();

    frozenEditor = clickEditor(widget);
    frozenEditor->setText(QStringLiteral("mov eax, 5"));
    widget.setEditable(false);
    flushEvents();
    require(!frozenEditor || !frozenEditor->isVisible(), "read-only transition cancels input");
    require(widget.data() == original, "read-only transition preserves cache");
    widget.setSnapshot(original, base);
    widget.showDisassemblyAt(base);
    flushEvents();
    auto* canvas = widget.disassemblyView()->canvas();
    QTest::mouseDClick(canvas->viewport(), Qt::LeftButton, Qt::NoModifier, canvas->contentRect(0).center());
    flushEvents();
    require(!widget.disassemblyView()->isEditing(), "read-only double click cannot edit");

    // A selected instruction maps to its complete range in the HEX facade.
    std::uint64_t selectionStart = 99, selectionEnd = 99;
    bool selected = false;
    const auto selectionConnection = QObject::connect(widget.hexEditor(), &ks::ui::HexView::selectionChanged, &widget,
        [&](std::uint64_t first, std::uint64_t last, bool valid) {
            selectionStart = first; selectionEnd = last; selected = valid;
        });
    canvas->setSelectedRow(1);
    canvas->setSelectedRow(0);
    require(selected && selectionStart == 0 && selectionEnd == 5, "instruction selection synchronizes all five bytes to HEX");
    QObject::disconnect(selectionConnection);

    // Provider bounds, references and priority are tested independently of painting.
    ks::ui::MemorySnapshotBytesProvider provider;
    const auto baseline = QByteArray::fromHex("01020304");
    provider.setSnapshot(base, QByteArray::fromHex("01090304"), baseline,
        QByteArray::fromHex("00080304"), 32, true);
    const auto window = provider.FetchWindow(base, 65536);
    using Kind = ksword::memwb::ByteChangeKind;
    require(window.ok && window.bytes.size() == 4, "provider clips at the captured tail");
    require(window.validMask == std::vector<std::uint8_t>(4, 1), "only actual snapshot bytes are valid");
    require(window.changeKinds[0] == Kind::ExternalChange, "actual reread changes retain the previous reference");
    require(window.changeKinds[1] == Kind::Pending, "pending edits take priority over external changes");
    require(provider.AddressBits() == 32 && provider.HasPreviousRead(), "provider publishes architecture and previous-read availability");
    require(!provider.FetchWindow(base - 1, 2).ok && !provider.FetchWindow(base + 4, 1).ok,
        "provider rejects uncaptured address ranges");
    require(provider.FetchWindow(base, 0).ok, "empty requests have an explicit successful empty window");
    provider.setSnapshot(base, baseline, baseline, {}, 64, false);
    require(!provider.HasPreviousRead() && provider.FetchWindow(base, 4).changeKinds[0] == Kind::Unchanged,
        "highlight suppression and unavailable previous reads stay separate");
    std::cerr << "Checking modal lifetime\n";
    checkModalLifetimeAndStaleRequests();
    std::cerr << "Checking snapshot text bounds\n";
    checkSnapshotTextBounds();
    checkSnapshotHexInitialPosition();
    std::cerr << "Checking kernel modal lifetime\n";
    checkKernelModalParentLifetime();
    std::cerr << "Checking file snapshots\n";
    checkFileSnapshotViews();
    checkFileOffsetZero();
    checkCapturedDisassemblyEndNote();
    checkFileContextIsolation();
    std::cerr << "Checking PE address mapping\n";
    checkPeFileAddressMapping();
    std::cerr << "Checking PE decoding and follow\n";
    checkPeDecodeAndFollow();
    if (!protocolLauncher.isEmpty())
    {
        std::cerr << "Checking headless protocol\n";
        checkHeadlessProtocol();
        std::cerr << "Checking installed runtime discovery\n";
        checkInstalledRuntimeDiscovery();
        std::cerr << "Checking shared C view\n";
        checkPseudocodeSharedView();
    }
    RunWorkbenchPseudocodeContractTests(require);
    std::cout << "PASS: " << checks << " memory editor Qt checks\n";
}
