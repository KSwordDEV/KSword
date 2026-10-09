#include "GhidraDecompiler.h"
#include "../../../../GhidraRuntimePlugin/RuntimeProfile.h"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QProcessEnvironment>
#include <QPointer>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTimer>
#include <QtEndian>
#include <algorithm>
#include <limits>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace
{
    constexpr qsizetype MaximumCodeBytes = 1024 * 1024;
    constexpr qint64 MaximumResultBytes = 4 * 1024 * 1024;
    constexpr qint64 MaximumLogBytes = 8 * 1024 * 1024;
    constexpr qsizetype RetainedDiagnosticBytes = 256 * 1024;
    const QString UtilityJar = QStringLiteral("Ghidra/Framework/Utility/lib/Utility.jar");

    // Original KSword script, compiled by Ghidra in the isolated request cache.
    // Calls the actual Ghidra decompiler; does not synthesize C from assembly.
    constexpr const char GhidraScript[] = R"KSWORD_JAVA(// KSword headless C pseudocode adapter. Original implementation.
// @category KSword
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.io.InputStream;
import java.util.*;

public class GhidraPseudocode extends GhidraScript {
    private static final int MAX_CODE_BYTES = 1024 * 1024;
    private static String quote(String text) {
        if (text == null) text = "";
        StringBuilder result = new StringBuilder("\"");
        for (int i = 0; i < text.length(); ++i) {
            char c = text.charAt(i);
            switch (c) {
                case '\\': result.append("\\\\"); break;
                case '"': result.append("\\\""); break;
                case '\n': result.append("\\n"); break;
                case '\r': result.append("\\r"); break;
                case '\t': result.append("\\t"); break;
                default:
                    if (c < 32) result.append(String.format("\\u%04x", (int)c));
                    else result.append(c);
            }
        }
        return result.append('"').toString();
    }
    private static String hex(Address address) {
        return Long.toUnsignedString(address.getOffset(), 16);
    }
    private static String hash(String file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(Paths.get(file))) {
            byte[] block = new byte[65536];
            int count;
            while ((count = input.read(block)) != -1) digest.update(block, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private Address statementAddress(ClangToken token, Function function) {
        // Prefer the emitted statement's instruction address, not a variable's
        // storage/data address. Only addresses in this function are navigable.
        ClangNode node = token;
        while (node != null) {
            if (node instanceof ClangStatement) {
                Address address = node.getMinAddress();
                if (address != null && function.getBody().contains(address)) return address;
            }
            node = node.Parent();
        }
        Address address = token.getMinAddress();
        return address != null && function.getBody().contains(address) ? address : null;
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) throw new IllegalArgumentException("invalid_arguments");
        Address selected = currentProgram.getAddressFactory().getDefaultAddressSpace()
            .getAddress(Long.parseUnsignedLong(args[1], 16));
        if (args[0].equals("prepare")) {
            // Avoid following a sample's PDB/debug path or fetching symbols.
            Map<String,String> options = getCurrentAnalysisOptionsAndValues(currentProgram);
            for (String key : options.keySet()) {
                if (key.toLowerCase(Locale.ROOT).contains("pdb")) {
                    setAnalysisOption(currentProgram, key, "false");
                }
            }
            if (args[2].equals("raw") && currentProgram.getMemory().contains(selected)) {
                disassemble(selected);
                createFunction(selected, null);
            }
            return;
        }
        if (!args[0].equals("decompile") || args.length != 8)
            throw new IllegalArgumentException("invalid_arguments");
        int seconds = Integer.parseInt(args[2]);
        Path output = Paths.get(args[3]);
        String sha = hash(args[4]);
        boolean raw = args[6].equals("raw");
        String prefix = "{\"schemaVersion\":1,\"selectedAddress\":" + quote(args[1]) +
            ",\"snapshotSha256\":" + quote(sha);
        DecompInterface decompiler = new DecompInterface();
        try {
            int bits = currentProgram.getLanguage().getDefaultSpace().getSize();
            if (bits != Integer.parseInt(args[5]) ||
                !currentProgram.getLanguage().getProcessor().toString().equalsIgnoreCase("x86"))
                throw new IllegalArgumentException("unsupported_architecture");
            if (!currentProgram.getMemory().contains(selected))
                throw new IllegalArgumentException("invalid_address");
            Function function = currentProgram.getFunctionManager().getFunctionContaining(selected);
            if (function == null) throw new IllegalArgumentException("no_function_at_address");
            DecompileOptions options = new DecompileOptions();
            options.setMaxPayloadMBytes(8);
            decompiler.setOptions(options);
            decompiler.toggleCCode(true);
            decompiler.toggleSyntaxTree(true);
            if (!decompiler.openProgram(currentProgram))
                throw new IllegalStateException("decompilation_failed");
            DecompileResults result = decompiler.decompileFunction(function, seconds, monitor);
            if (!result.decompileCompleted() || result.getCCodeMarkup() == null) {
                String failure = result.isTimedOut() ? "timeout" : "decompilation_failed";
                throw new IllegalStateException(failure);
            }
            PrettyPrinter printer = new PrettyPrinter(function, result.getCCodeMarkup(), null);
            StringBuilder code = new StringBuilder();
            StringBuilder addresses = new StringBuilder("[");
            boolean first = true;
            for (ClangLine line : printer.getLines()) {
                monitor.checkCancelled();
                if (!first) addresses.append(',');
                first = false;
                code.append(PrettyPrinter.getText(line)).append('\n');
                if (code.length() > MAX_CODE_BYTES) throw new IllegalStateException("output_limit");
                Address minimum = null;
                for (ClangToken token : line.getAllTokens()) {
                    Address address = statementAddress(token, function);
                    if (address != null && (minimum == null || address.compareTo(minimum) < 0))
                        minimum = address;
                }
                addresses.append(minimum == null ? "null" : quote(hex(minimum)));
            }
            if (code.toString().getBytes(StandardCharsets.UTF_8).length > MAX_CODE_BYTES)
                throw new IllegalStateException("output_limit");
            addresses.append(']');
            String json = prefix + ",\"success\":true,\"code\":" + quote(code.toString()) +
                ",\"functionName\":" + quote(function.getName()) + ",\"functionAddress\":" +
                quote(hex(function.getEntryPoint())) + ",\"boundaryInferred\":" + raw +
                ",\"lineAddresses\":" + addresses + "}";
            Files.writeString(output, json, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
        } catch (Exception failure) {
            String message = failure.getMessage();
            Set<String> known = Set.of("unsupported_architecture", "invalid_address",
                "no_function_at_address", "timeout", "output_limit", "decompilation_failed");
            String error = known.contains(message) ? message : "decompilation_failed";
            String json = prefix + ",\"success\":false,\"error\":" + quote(error) + "}";
            Files.writeString(output, json, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE);
            printerr(error);
        } finally {
            decompiler.dispose();
        }
    }
}
)KSWORD_JAVA";

    template<typename T> bool readLe(const QByteArray& bytes, quint64 offset, T& result)
    {
        if (offset > quint64(bytes.size()) || sizeof(T) > quint64(bytes.size()) - offset) return false;
        result = qFromLittleEndian<T>(bytes.constData() + qsizetype(offset));
        return true;
    }

    QString validateRequest(const ks::ui::DecompilerRequest& request)
    {
        using ks::ui::DecompilerInputKind;
        if (request.bytes.isEmpty()) return QStringLiteral("empty_snapshot");
        if (request.inputKind != DecompilerInputKind::RawMemory &&
            request.inputKind != DecompilerInputKind::PortableExecutable) return QStringLiteral("invalid_pe");
        const auto maximum = request.inputKind == DecompilerInputKind::PortableExecutable
            ? ks::ui::GhidraDecompiler::MaximumPeBytes : ks::ui::GhidraDecompiler::MaximumRawBytes;
        if (request.bytes.size() > maximum) return QStringLiteral("snapshot_too_large");
        if (request.inputKind == DecompilerInputKind::RawMemory) {
            const quint64 size = quint64(request.bytes.size());
            const quint64 addressLimit = request.x64 ? std::numeric_limits<quint64>::max()
                : quint64(std::numeric_limits<quint32>::max());
            if (request.baseAddress > addressLimit || size - 1 > addressLimit - request.baseAddress ||
                request.selectedAddress < request.baseAddress ||
                request.selectedAddress - request.baseAddress >= size) return QStringLiteral("invalid_address");
            return {};
        }
        quint16 mz = 0, machine = 0, sections = 0, optionalSize = 0, magic = 0;
        quint32 peOffset = 0, signature = 0, imageSize = 0;
        const QByteArray& bytes = request.bytes;
        if (!readLe(bytes, 0, mz) || mz != 0x5a4d || !readLe(bytes, 0x3c, peOffset) ||
            !readLe(bytes, peOffset, signature) || signature != 0x00004550 ||
            !readLe(bytes, quint64(peOffset) + 4, machine) ||
            !readLe(bytes, quint64(peOffset) + 6, sections) ||
            !readLe(bytes, quint64(peOffset) + 20, optionalSize)) return QStringLiteral("invalid_pe");
        if (machine != 0x14c && machine != 0x8664) return QStringLiteral("unsupported_architecture");
        if ((machine == 0x8664) != request.x64) return QStringLiteral("unsupported_architecture");
        const quint64 optional = quint64(peOffset) + 24;
        if (!readLe(bytes, optional, magic) || magic != (request.x64 ? 0x20b : 0x10b) ||
            optionalSize < (request.x64 ? 112 : 96) || sections == 0 || sections > 96 ||
            !readLe(bytes, optional + 56, imageSize)) return QStringLiteral("invalid_pe");
        quint64 imageBase = 0;
        if (request.x64) {
            if (!readLe(bytes, optional + 24, imageBase)) return QStringLiteral("invalid_pe");
        } else {
            quint32 base32 = 0;
            if (!readLe(bytes, optional + 28, base32)) return QStringLiteral("invalid_pe");
            imageBase = base32;
        }
        if (imageSize == 0 || imageBase > std::numeric_limits<quint64>::max() - imageSize ||
            (!request.x64 && quint64(imageSize) - 1 > quint64(std::numeric_limits<quint32>::max()) - imageBase) ||
            request.selectedAddress < imageBase || request.selectedAddress - imageBase >= imageSize)
            return QStringLiteral("unmapped_pe_address");
        const quint64 table = optional + optionalSize;
        if (table > quint64(bytes.size()) || quint64(sections) * 40 > quint64(bytes.size()) - table)
            return QStringLiteral("invalid_pe");
        const quint64 selectedRva = request.selectedAddress - imageBase;
        int matches = 0;
        for (quint16 index = 0; index < sections; ++index) {
            quint32 rva = 0, rawSize = 0, rawOffset = 0, virtualSize = 0;
            const quint64 section = table + quint64(index) * 40;
            if (!readLe(bytes, section + 8, virtualSize) || !readLe(bytes, section + 12, rva) ||
                !readLe(bytes, section + 16, rawSize) || !readLe(bytes, section + 20, rawOffset) ||
                rawOffset > quint64(bytes.size()) || rawSize > quint64(bytes.size()) - rawOffset ||
                quint64(rva) + std::max(virtualSize, rawSize) > imageSize) return QStringLiteral("invalid_pe");
            const quint32 backedSize = std::min(rawSize, virtualSize ? virtualSize : rawSize);
            if (selectedRva >= rva && selectedRva - rva < backedSize) ++matches;
        }
        return matches == 1 ? QString() : QStringLiteral("unmapped_pe_address");
    }

    bool validDirectory(const QString& directory)
    {
        return !directory.isEmpty() && QFileInfo(QDir(directory).filePath(UtilityJar)).isFile() &&
            QFileInfo(QDir(directory).filePath(QStringLiteral("Ghidra/application.properties"))).isFile();
    }

    QString installedGhidraPlugin()
    {
        QString root = qEnvironmentVariable("KSWORD_PLUGIN_ROOT").trimmed();
        if (root.isEmpty())
        {
            const auto current = QDir::current().filePath(QStringLiteral("plugin"));
            if (QDir(current).exists()) root = current;
            else
            {
                QDir search(QCoreApplication::applicationDirPath());
                for (int depth = 0; depth < 7; ++depth)
                {
                    const auto candidate = search.filePath(QStringLiteral("plugin"));
                    if (QDir(candidate).exists()) { root = candidate; break; }
                    if (!search.cdUp()) break;
                }
            }
        }
        if (root.isEmpty()) return {};
        const auto plugin = QDir(root).filePath(QStringLiteral("ghidra"));
        return ks::plugin_host::ghidra_runtime::validateDirectory(plugin)
            ? QDir(plugin).absolutePath() : QString();
    }

    QString findJava(const QString& ghidraDirectory)
    {
        const QString overridePath = qEnvironmentVariable("KSWORD_GHIDRA_JAVA");
        if (!overridePath.isEmpty()) return QFileInfo(overridePath).isFile() ? QFileInfo(overridePath).absoluteFilePath() : QString();
#ifdef Q_OS_WIN
        const QString name = QStringLiteral("java.exe");
#else
        const QString name = QStringLiteral("java");
#endif
        const auto plugin = installedGhidraPlugin();
        if (!plugin.isEmpty())
        {
            const auto metadata = ks::plugin_host::ghidra_runtime::installedManifest(plugin);
            const auto runtime = QDir(plugin).filePath(metadata.value(QStringLiteral("runtime_root")).toString());
            if (QFileInfo(runtime).canonicalFilePath().compare(QFileInfo(ghidraDirectory).canonicalFilePath(),
#ifdef Q_OS_WIN
                    Qt::CaseInsensitive
#else
                    Qt::CaseSensitive
#endif
                ) == 0)
                return QDir(plugin).filePath(metadata.value(QStringLiteral("java_executable")).toString());
        }
        for (const auto key : { "JAVA_HOME", "JDK_HOME" }) {
            const QString home = qEnvironmentVariable(key);
            const QString candidate = QDir(home).filePath(QStringLiteral("bin/") + name);
            if (!home.isEmpty() && QFileInfo(candidate).isFile()) return QFileInfo(candidate).absoluteFilePath();
        }
        return QStandardPaths::findExecutable(name);
    }

    bool writeFile(const QString& path, const QByteArray& bytes)
    {
        QFile file(path);
        return file.open(QIODevice::WriteOnly | QIODevice::NewOnly) &&
            file.write(bytes) == bytes.size() && file.flush();
    }

    bool parseHex(const QJsonValue& value, quint64& address)
    {
        if (!value.isString()) return false;
        const QString text = value.toString();
        if (text.isEmpty() || text.size() > 16) return false;
        for (const QChar character : text) {
            if (!((character >= u'0' && character <= u'9') ||
                (character >= u'a' && character <= u'f') || (character >= u'A' && character <= u'F'))) return false;
        }
        bool ok = false;
        address = text.toULongLong(&ok, 16);
        return ok;
    }
}

namespace ks::ui
{
    struct GhidraDecompiler::State
    {
        QString directory;
        std::unique_ptr<QTemporaryDir> temporary;
        QProcess* process = nullptr;
        QTimer* deadline = nullptr;
        QTimer* outputCheck = nullptr;
        QString resultPath;
        QString logPath;
        QString scriptLogPath;
        QString stopReason;
        QByteArray diagnosticBytes;
        qint64 receivedBytes = 0;
        QByteArray hash;
        quint64 selectedAddress = 0;
        quint64 revision = 0;
        QVector<QPair<quint64, quint64>> addressRanges;
        bool running = false;
#ifdef Q_OS_WIN
        HANDLE job = nullptr;
#endif
    };

    GhidraDecompiler::GhidraDecompiler(QObject* parent) : QObject(parent), m_state(std::make_unique<State>())
    {
        qRegisterMetaType<DecompilerResult>();
        m_state->deadline = new QTimer(this);
        m_state->deadline->setSingleShot(true);
        connect(m_state->deadline, &QTimer::timeout, this, [this] { stopProcess(QStringLiteral("timeout")); });
        m_state->outputCheck = new QTimer(this);
        m_state->outputCheck->setInterval(500);
        connect(m_state->outputCheck, &QTimer::timeout, this, [this] {
            if (QFileInfo(m_state->resultPath).size() > MaximumResultBytes ||
                QFileInfo(m_state->logPath).size() > MaximumLogBytes ||
                QFileInfo(m_state->scriptLogPath).size() > MaximumLogBytes) stopProcess(QStringLiteral("output_limit"));
        });
    }

    GhidraDecompiler::~GhidraDecompiler()
    {
        m_state->deadline->stop();
        m_state->outputCheck->stop();
        if (m_state->process) {
            m_state->process->disconnect(this);
#ifdef Q_OS_WIN
            if (m_state->job) TerminateJobObject(m_state->job, 1);
#endif
            m_state->process->kill();
            m_state->process->waitForFinished(1000);
        }
#ifdef Q_OS_WIN
        if (m_state->job) CloseHandle(m_state->job);
#endif
    }

    bool GhidraDecompiler::isRunning() const { return m_state->running; }
    QString GhidraDecompiler::ghidraDirectory() const { return m_state->directory.isEmpty() ? findGhidraDirectory() : m_state->directory; }
    void GhidraDecompiler::setGhidraDirectory(const QString& directory) { m_state->directory = directory.isEmpty() ? QString() : QDir::cleanPath(directory); }

    QString GhidraDecompiler::findGhidraDirectory()
    {
        const QString environment = qEnvironmentVariable("KSWORD_GHIDRA_DIR");
        if (!environment.isEmpty()) return validDirectory(environment) ? QFileInfo(environment).absoluteFilePath() : QString();
        const auto plugin = installedGhidraPlugin();
        if (!plugin.isEmpty())
            return QDir(plugin).filePath(ks::plugin_host::ghidra_runtime::installedManifest(plugin)
                .value(QStringLiteral("runtime_root")).toString());
        const QDir executable(QCoreApplication::applicationDirPath());
        for (const QString& relative : { QStringLiteral("tools/ghidra"), QStringLiteral("ghidra") }) {
            const QString candidate = executable.filePath(relative);
            if (validDirectory(candidate)) return candidate;
        }
        return {};
    }

    QString GhidraDecompiler::installedPluginDirectory() { return installedGhidraPlugin(); }

    bool GhidraDecompiler::start(const DecompilerRequest& request)
    {
        if (m_state->running) return false;
        m_state->running = true;
        m_state->stopReason.clear();
        m_state->diagnosticBytes.clear();
        m_state->receivedBytes = 0;
        m_state->hash.clear();
        m_state->selectedAddress = request.selectedAddress;
        m_state->addressRanges.clear();
        const quint64 revision = ++m_state->revision;
        QTimer::singleShot(0, this, [this, request, revision] {
            if (!m_state->running || revision != m_state->revision) return;
            if (!m_state->stopReason.isEmpty()) { complete(m_state->stopReason); return; }
            launch(request);
        });
        // Scheduling precedes the public signal: an observer may delete us.
        emit runningChanged(true);
        return true;
    }

    void GhidraDecompiler::launch(const DecompilerRequest& request)
    {
        const QString validation = validateRequest(request);
        if (!validation.isEmpty()) { complete(validation); return; }
        const QString directory = ghidraDirectory();
        if (!validDirectory(directory)) { complete(QStringLiteral("ghidra_not_configured")); return; }
        const QString java = findJava(directory);
        if (java.isEmpty()) { complete(QStringLiteral("java_not_found")); return; }
        m_state->temporary = std::make_unique<QTemporaryDir>(QDir::tempPath() + QStringLiteral("/KSword-decompile-XXXXXX"));
        if (!m_state->temporary->isValid()) { complete(QStringLiteral("temporary_file_error")); return; }
        const QDir temporary(m_state->temporary->path());
        const QString input = temporary.filePath(request.inputKind == DecompilerInputKind::PortableExecutable
            ? QStringLiteral("snapshot.exe") : QStringLiteral("snapshot.bin"));
        m_state->resultPath = temporary.filePath(QStringLiteral("result.json"));
        m_state->logPath = temporary.filePath(QStringLiteral("analysis.log"));
        m_state->scriptLogPath = temporary.filePath(QStringLiteral("script.log"));
        if (!writeFile(input, request.bytes) ||
            !writeFile(temporary.filePath(QStringLiteral("GhidraPseudocode.java")), QByteArray(GhidraScript))) {
            complete(QStringLiteral("temporary_file_error")); return;
        }
        m_state->hash = QCryptographicHash::hash(request.bytes, QCryptographicHash::Sha256);
        if (request.inputKind == DecompilerInputKind::RawMemory) {
            m_state->addressRanges.append(qMakePair(request.baseAddress, request.baseAddress + quint64(request.bytes.size()) - 1));
        } else {
            quint32 peOffset = 0;
            quint16 optionalSize = 0, sections = 0;
            quint64 imageBase = 0;
            readLe(request.bytes, 0x3c, peOffset);
            readLe(request.bytes, quint64(peOffset) + 6, sections);
            readLe(request.bytes, quint64(peOffset) + 20, optionalSize);
            const quint64 optional = quint64(peOffset) + 24;
            if (request.x64) readLe(request.bytes, optional + 24, imageBase);
            else {
                quint32 base = 0;
                readLe(request.bytes, optional + 28, base);
                imageBase = base;
            }
            for (quint16 index = 0; index < sections; ++index) {
                quint32 rva = 0, rawSize = 0, virtualSize = 0;
                const quint64 section = optional + optionalSize + quint64(index) * 40;
                readLe(request.bytes, section + 12, rva);
                readLe(request.bytes, section + 16, rawSize);
                readLe(request.bytes, section + 8, virtualSize);
                const quint32 backedSize = std::min(rawSize, virtualSize ? virtualSize : rawSize);
                if (backedSize) m_state->addressRanges.append(qMakePair(imageBase + rva, imageBase + rva + backedSize - 1));
            }
        }
        const int seconds = std::clamp(request.timeoutSeconds, 10, 300);
        const QString selected = QString::number(request.selectedAddress, 16);
        const QString kind = request.inputKind == DecompilerInputKind::RawMemory ? QStringLiteral("raw") : QStringLiteral("pe");
        QStringList arguments {
            QStringLiteral("-Xmx1G"), QStringLiteral("-Xshare:off"), QStringLiteral("-XX:ParallelGCThreads=2"),
            QStringLiteral("-XX:CICompilerCount=2"), QStringLiteral("-Djava.awt.headless=true"),
            QStringLiteral("-Djava.system.class.loader=ghidra.GhidraClassLoader"),
            QStringLiteral("-Dfile.encoding=UTF-8"), QStringLiteral("-Duser.language=en"), QStringLiteral("-Duser.country=US"),
            QStringLiteral("-Djavax.xml.accessExternalDTD="), QStringLiteral("-Djavax.xml.accessExternalSchema="),
            QStringLiteral("-Djavax.xml.accessExternalStylesheet="), QStringLiteral("--enable-native-access=ALL-UNNAMED"),
            QStringLiteral("-Dapplication.settingsdir=") + temporary.filePath(QStringLiteral("settings")),
            QStringLiteral("-Dapplication.cachedir=") + temporary.filePath(QStringLiteral("cache")),
            QStringLiteral("-Dapplication.tempdir=") + temporary.filePath(QStringLiteral("scratch")),
            QStringLiteral("-Djava.io.tmpdir=") + temporary.path(),
            QStringLiteral("-cp"), QDir(directory).filePath(UtilityJar), QStringLiteral("ghidra.Ghidra"),
            QStringLiteral("ghidra.app.util.headless.AnalyzeHeadless"), temporary.path(), QStringLiteral("Snapshot"),
            QStringLiteral("-import"), input, QStringLiteral("-deleteProject"),
            QStringLiteral("-max-cpu"), QStringLiteral("2"), QStringLiteral("-analysisTimeoutPerFile"), QString::number(seconds),
            QStringLiteral("-log"), m_state->logPath, QStringLiteral("-scriptlog"), m_state->scriptLogPath,
            QStringLiteral("-scriptPath"), temporary.path()
        };
        if (request.inputKind == DecompilerInputKind::RawMemory) {
            arguments << QStringLiteral("-loader") << QStringLiteral("BinaryLoader")
                << QStringLiteral("-processor") << (request.x64 ? QStringLiteral("x86:LE:64:default") : QStringLiteral("x86:LE:32:default"))
                << QStringLiteral("-cspec") << QStringLiteral("windows")
                << QStringLiteral("-loader-baseAddr") << QString::number(request.baseAddress, 16);
        } else {
            arguments << QStringLiteral("-loader") << QStringLiteral("PeLoader");
        }
        arguments << QStringLiteral("-preScript") << QStringLiteral("GhidraPseudocode.java")
            << QStringLiteral("prepare") << selected << kind
            << QStringLiteral("-postScript") << QStringLiteral("GhidraPseudocode.java")
            << QStringLiteral("decompile") << selected << QString::number(seconds) << m_state->resultPath << input
            << (request.x64 ? QStringLiteral("64") : QStringLiteral("32")) << kind << QStringLiteral("1");
        auto* process = new QProcess(this);
        m_state->process = process;
        process->setWorkingDirectory(temporary.path());
        QProcessEnvironment environment = QProcessEnvironment::systemEnvironment();
        for (const auto key : { "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "CLASSPATH" })
            environment.remove(QString::fromLatin1(key));
        process->setProcessEnvironment(environment);
        process->setProcessChannelMode(QProcess::MergedChannels);
#ifdef Q_OS_WIN
        m_state->job = CreateJobObjectW(nullptr, nullptr);
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits {};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!m_state->job || !SetInformationJobObject(m_state->job, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
            complete(QStringLiteral("process_isolation_failed")); return;
        }
        process->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) {
            args->flags |= CREATE_NO_WINDOW;
        });
        connect(process, &QProcess::started, this, [this, process] {
            HANDLE handle = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, FALSE, DWORD(process->processId()));
            const bool assigned = handle && AssignProcessToJobObject(m_state->job, handle);
            if (handle) CloseHandle(handle);
            if (!assigned) stopProcess(QStringLiteral("process_isolation_failed"));
        });
#endif
        connect(process, &QProcess::readyReadStandardOutput, this, &GhidraDecompiler::collectOutput);
        connect(process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart) complete(QStringLiteral("process_start_failed"));
        });
        connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
            [this](int exitCode, QProcess::ExitStatus status) {
                collectOutput();
                if (!m_state->stopReason.isEmpty()) complete(m_state->stopReason);
                else if (status != QProcess::NormalExit || exitCode != 0) complete(QStringLiteral("process_exit_failed"));
                else complete();
            });
        m_state->deadline->start(seconds * 1000);
        m_state->outputCheck->start();
        process->start(java, arguments);
    }

    void GhidraDecompiler::collectOutput()
    {
        if (!m_state->process) return;
        const QByteArray chunk = m_state->process->readAllStandardOutput();
        m_state->receivedBytes += chunk.size();
        m_state->diagnosticBytes.append(chunk.right(RetainedDiagnosticBytes));
        if (m_state->diagnosticBytes.size() > RetainedDiagnosticBytes)
            m_state->diagnosticBytes.remove(0, m_state->diagnosticBytes.size() - RetainedDiagnosticBytes);
        if (m_state->receivedBytes > MaximumLogBytes) stopProcess(QStringLiteral("output_limit"));
    }

    void GhidraDecompiler::cancel() { if (m_state->running) stopProcess(QStringLiteral("cancelled")); }

    void GhidraDecompiler::stopProcess(const QString& reason)
    {
        if (!m_state->running || !m_state->stopReason.isEmpty()) return;
        m_state->stopReason = reason;
        m_state->deadline->stop();
        m_state->outputCheck->stop();
        if (m_state->process && m_state->process->state() != QProcess::NotRunning) {
#ifdef Q_OS_WIN
            if (m_state->job) TerminateJobObject(m_state->job, 1);
#endif
            m_state->process->kill();
        } else {
            const quint64 revision = m_state->revision;
            QTimer::singleShot(0, this, [this, revision] {
                if (m_state->running && revision == m_state->revision) complete(m_state->stopReason);
            });
        }
    }

    void GhidraDecompiler::complete(const QString& error)
    {
        if (!m_state->running) return;
        m_state->deadline->stop();
        m_state->outputCheck->stop();
        DecompilerResult result;
        result.error = error;
        result.snapshotSha256 = m_state->hash;
        result.diagnostics = QString::fromUtf8(m_state->diagnosticBytes);
        if (result.error.isEmpty()) {
            QFile file(m_state->resultPath);
            if (!file.open(QIODevice::ReadOnly) || file.size() > MaximumResultBytes) {
                result.error = file.size() > MaximumResultBytes ? QStringLiteral("output_limit") : QStringLiteral("invalid_result");
            } else {
                QJsonParseError parseError;
                const QJsonDocument document = QJsonDocument::fromJson(file.read(MaximumResultBytes + 1), &parseError);
                const QJsonObject object = document.object();
                quint64 selected = 0;
                if (parseError.error != QJsonParseError::NoError || !document.isObject() ||
                    object.value(QStringLiteral("schemaVersion")).toInt() != 1 ||
                    !object.value(QStringLiteral("success")).isBool() ||
                    !parseHex(object.value(QStringLiteral("selectedAddress")), selected) || selected != m_state->selectedAddress) {
                    result.error = QStringLiteral("invalid_result");
                } else if (object.value(QStringLiteral("snapshotSha256")).toString().toLatin1().toLower() != m_state->hash.toHex()) {
                    result.error = QStringLiteral("snapshot_mismatch");
                } else if (!object.value(QStringLiteral("success")).toBool()) {
                    const QString backendError = object.value(QStringLiteral("error")).toString();
                    const QStringList allowed { QStringLiteral("unsupported_architecture"), QStringLiteral("invalid_address"),
                        QStringLiteral("no_function_at_address"), QStringLiteral("timeout"), QStringLiteral("output_limit"), QStringLiteral("decompilation_failed") };
                    result.error = allowed.contains(backendError) ? backendError : QStringLiteral("decompilation_failed");
                } else {
                    result.code = object.value(QStringLiteral("code")).toString();
                    result.functionName = object.value(QStringLiteral("functionName")).toString();
                    const auto lines = object.value(QStringLiteral("lineAddresses")).toArray();
                    qsizetype lineCount = result.code.count(u'\n') + 1;
                    if (result.code.endsWith(u'\n')) --lineCount;
                    const auto capturedAddress = [this](quint64 address) {
                        return std::any_of(m_state->addressRanges.cbegin(), m_state->addressRanges.cend(),
                            [address](const auto& range) { return address >= range.first && address <= range.second; });
                    };
                    bool valid = !result.code.isEmpty() && result.code.toUtf8().size() <= MaximumCodeBytes &&
                        !result.functionName.isEmpty() && result.functionName.size() <= 4096 && object.value(QStringLiteral("lineAddresses")).isArray() &&
                        lines.size() == lineCount && parseHex(object.value(QStringLiteral("functionAddress")), result.functionAddress) &&
                        capturedAddress(result.functionAddress);
                    for (const auto& value : lines) {
                        quint64 address = 0;
                        const bool mapped = !value.isNull();
                        if (mapped && (!parseHex(value, address) || !capturedAddress(address))) valid = false;
                        result.lineAddresses.append(address);
                        result.lineAddressValid.append(mapped);
                    }
                    result.boundaryInferred = object.value(QStringLiteral("boundaryInferred")).toBool();
                    if (valid) result.success = true;
                    else { result.code.clear(); result.lineAddresses.clear(); result.lineAddressValid.clear(); result.error = QStringLiteral("invalid_result"); }
                }
            }
        }
        if (m_state->process) {
            m_state->process->disconnect(this);
            m_state->process->deleteLater();
            m_state->process = nullptr;
        }
#ifdef Q_OS_WIN
        if (m_state->job) { CloseHandle(m_state->job); m_state->job = nullptr; }
#endif
        m_state->temporary.reset();
        m_state->running = false;
        const quint64 revision = m_state->revision;
        const QPointer<GhidraDecompiler> guard(this);
        // Publish the completed request before a state observer can start a new
        // request. A finished observer may also delete us or restart analysis.
        emit finished(result);
        if (guard && revision == m_state->revision && !m_state->running)
            emit runningChanged(false);
    }
}
