// Synthetic, non-executed bytes through the production asynchronous Ghidra host.
// The optional protocol producer is this same executable; it never claims to
// decompile and is selected only for explicit response-validation cases.
#include "UI/Decompiler/GhidraDecompiler.h"
#include "UI/Decompiler/RawCodePlanner.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>
#include <QtEndian>
#include <cstdio>
#include <algorithm>

namespace
{
    using namespace ks::ui;
    constexpr quint64 Base = 0x180001000ull;
    struct Case
    {
        QString name;
        DecompilerRequest request;
        bool success = true;
        QString error;
        bool sparse = true;
        quint64 entry = Base;
        quint32 instructionCount = 0;
        quint64 mappedLine = Base;
        QString expression;
        int cancelAfterMs = -1;
        QString producer;
        bool planned = false;
        QString planningError;
    };

    DecompilerRequest raw(const QByteArray& bytes, quint64 entry = Base, bool x64 = true)
    {
        DecompilerRequest request;
        request.entryAddress = entry;
        request.selectedAddress = entry;
        request.x64 = x64;
        request.timeoutSeconds = 45;
        request.segments.append({entry, bytes});
        request.bodyRanges.append({entry, quint64(bytes.size())});
        return request;
    }

    template<typename T> void put(QByteArray& bytes, qsizetype at, T value)
    {
        qToLittleEndian<T>(value, bytes.data() + at);
    }

    QByteArray pe()
    {
        QByteArray bytes(0x400, '\0');
        put<quint16>(bytes, 0, 0x5a4d); put<quint32>(bytes, 0x3c, 0x80);
        put<quint32>(bytes, 0x80, 0x4550); put<quint16>(bytes, 0x84, 0x8664);
        put<quint16>(bytes, 0x86, 1); put<quint16>(bytes, 0x94, 0xf0); put<quint16>(bytes, 0x96, 0x22);
        put<quint16>(bytes, 0x98, 0x20b); put<quint32>(bytes, 0x9c, 0x200);
        put<quint32>(bytes, 0xa8, 0x1000); put<quint32>(bytes, 0xac, 0x1000);
        put<quint64>(bytes, 0xb0, 0x140000000ull); put<quint32>(bytes, 0xb8, 0x1000);
        put<quint32>(bytes, 0xbc, 0x200); put<quint16>(bytes, 0xc0, 6); put<quint16>(bytes, 0xc8, 6);
        put<quint32>(bytes, 0xd0, 0x2000); put<quint32>(bytes, 0xd4, 0x200); put<quint16>(bytes, 0xdc, 3);
        put<quint64>(bytes, 0xe0, 0x100000); put<quint64>(bytes, 0xe8, 0x1000);
        put<quint64>(bytes, 0xf0, 0x100000); put<quint64>(bytes, 0xf8, 0x1000);
        put<quint32>(bytes, 0x104, 16); bytes.replace(0x188, 5, ".text");
        put<quint32>(bytes, 0x190, 5); put<quint32>(bytes, 0x194, 0x1000);
        put<quint32>(bytes, 0x198, 0x200); put<quint32>(bytes, 0x19c, 0x200);
        put<quint32>(bytes, 0x1ac, 0x60000020); bytes.replace(0x200, 5, QByteArray::fromHex("8bc103c2c3"));
        return bytes;
    }

    Case plannedCase(const char* name, const QByteArray& window, quint64 entryOffset,
        quint64 selectedOffset, quint64 mappedLine, quint32 instructions)
    {
        using Planner = ks::ui::detail::RawCodePlanner;
        Planner::Config config;
        config.entryAddress = Base + entryOffset; config.selectedAddress = Base + selectedOffset;
        config.firstAddress = Base; config.lastAddress = Base + quint64(window.size()) - 1;
        Planner planner(config);
        Case result; result.name = QString::fromLatin1(name); result.planned = true;
        result.entry = config.entryAddress; result.mappedLine = mappedLine; result.instructionCount = instructions;
        bool complete = false;
        for (unsigned turn = 0; turn < 10000; ++turn) {
            const auto step = planner.advance([&](std::uint64_t address, std::uint64_t length) {
                Planner::Page page; page.address = address;
                if (address < Base || address - Base > quint64(window.size()) || length > quint64(window.size()) - (address - Base)) return page;
                const auto offset = static_cast<qsizetype>(address - Base);
                const auto bytes = window.mid(offset, static_cast<qsizetype>(length));
                page.ok = true;
                const auto* begin = reinterpret_cast<const std::uint8_t*>(bytes.constData());
                page.bytes.assign(begin, begin + bytes.size()); page.validMask.assign(static_cast<std::size_t>(bytes.size()), 1);
                return page;
            });
            if (step.status == Planner::Status::Complete) { complete = true; break; }
            if (step.status != Planner::Status::Yield) {
                result.planningError = QString::fromStdString(step.error.empty() ? "unexpected_need_data" : step.error); break;
            }
        }
        if (!complete) { if (result.planningError.isEmpty()) result.planningError = QStringLiteral("planner_turn_limit"); return result; }
        result.request.entryAddress = config.entryAddress; result.request.selectedAddress = config.selectedAddress;
        result.request.timeoutSeconds = 45;
        for (const auto& segment : planner.segments())
            result.request.segments.append({segment.address, QByteArray(reinterpret_cast<const char*>(segment.bytes.data()), static_cast<qsizetype>(segment.bytes.size()))});
        for (const auto& range : planner.bodyRanges()) result.request.bodyRanges.append({range.address, range.length});
        if (planner.instructionCount() != instructions) result.planningError = QStringLiteral("unexpected_planner_instruction_count");
        return result;
    }

    QVector<Case> cases()
    {
        QVector<Case> result;
        QByteArray farWindow(0x4000, '\xcc');
        farWindow.replace(0, 14, QByteArray::fromHex("85c90f84f8200000b801000000c3"));
        farWindow.replace(0x2100, 6, QByteArray::fromHex("b82a000000c3"));
        result.append(plannedCase("planned-far-branch", farWindow, 0, 8, Base + 0x2100, 6));
        QByteArray constantWindow(0x4000, '\xcc');
        constantWindow.replace(0, 7, QByteArray::fromHex("8b05fa2f0000c3"));
        constantWindow.replace(0x3000, 4, QByteArray::fromHex("78563412"));
        auto constant = plannedCase("planned-rip-constant", constantWindow, 0, 1, Base, 2);
        constant.expression = QStringLiteral("0x12345678"); result.append(std::move(constant));
        QByteArray crossingWindow(0x2000, '\xcc');
        crossingWindow.replace(0xffe, 6, QByteArray::fromHex("b82a000000c3"));
        result.append(plannedCase("planned-cross-page", crossingWindow, 0xffe, 0xfff, Base + 0xffe, 2));
        const auto add = [&result](const char* name, DecompilerRequest request, quint32 count = 0) -> Case& {
            Case value;
            value.name = QString::fromLatin1(name); value.request = std::move(request); value.instructionCount = count;
            value.entry = value.request.entryAddress.value_or(Base); value.mappedLine = value.entry;
            result.append(std::move(value)); return result.last();
        };
        auto request = raw(QByteArray::fromHex("85c90f84f8200000b801000000c3"));
        request.selectedAddress = Base + 8;
        request.segments.append({Base + 0x2100, QByteArray::fromHex("b82a000000c3")});
        request.bodyRanges.append({Base + 0x2100, 6});
        add("far-branch", request, 6).mappedLine = Base + 0x2100;
        request = raw(QByteArray::fromHex("8b05fa2f0000c3"));
        request.segments.append({Base + 0x3000, QByteArray::fromHex("78563412")});
        add("rip-constant", request, 2).expression = QStringLiteral("0x12345678");
        request = raw(QByteArray::fromHex("b82a000000c3"), 0);
        request.selectedAddress = 1;
        add("zero-entry", request, 2);
        add("x86", raw(QByteArray::fromHex("558bec8b450803450c5dc3"), 0x1000, false), 6).expression = QStringLiteral("+");
        add("lea", raw(QByteArray::fromHex("488d05f9ff0f00c3")), 2);
        add("write-only", raw(QByteArray::fromHex("8905fa2f0000c3")), 2);
        add("gs", raw(QByteArray::fromHex("65488b042530000000c3")), 2);
        add("call-boundary", raw(QByteArray::fromHex("e8fb0f000083c001c3")), 3);
        request = raw(QByteArray::fromHex("eb04"));
        request.segments.append({Base + 6, QByteArray::fromHex("c3")});
        auto& missing = add("missing-edge", request);
        missing.success = false; missing.error = QStringLiteral("incomplete_control_flow");
        auto& indirect = add("indirect-jump", raw(QByteArray::fromHex("ffe0")));
        indirect.success = false; indirect.error = QStringLiteral("incomplete_control_flow");
        auto& dataMissing = add("missing-read", raw(QByteArray::fromHex("8b05fa2f0000c3")));
        dataMissing.success = false; dataMissing.error = QStringLiteral("snapshot_unreadable");
        request = raw(QByteArray::fromHex("b82a000000c3")); request.entryAddress.reset();
        auto& noEntry = add("missing-entry", request);
        noEntry.success = false; noEntry.error = QStringLiteral("entry_unknown");
        request = raw(QByteArray::fromHex("b82a000000c3"));
        request.segments = {{Base, QByteArray::fromHex("9090")}, {Base + 4, QByteArray::fromHex("90c3")}};
        auto& hole = add("body-hole", request);
        hole.success = false; hole.error = QStringLiteral("snapshot_unreadable");
        request = raw(QByteArray::fromHex("b82a000000c3")); request.segments.append({Base + 1, QByteArray(1, '\x90')});
        auto& overlap = add("overlap", request);
        overlap.success = false; overlap.error = QStringLiteral("invalid_address");
        request = raw(QByteArray::fromHex("b82a000000c3")); request.segments[0].bytes = QByteArray(1024 * 1024 + 1, '\x90');
        auto& budget = add("capture-budget", request);
        budget.success = false; budget.error = QStringLiteral("analysis_budget_exceeded");
        request = {};
        request.baseAddress = request.selectedAddress = 0xfffff80000001000ull;
        request.bytes = QByteArray::fromHex("8bc103c2c3"); request.timeoutSeconds = 45;
        auto& dense = add("legacy-raw", request);
        dense.sparse = false; dense.entry = dense.mappedLine = request.selectedAddress;
        dense.expression = QStringLiteral("+");
        request = {};
        request.inputKind = DecompilerInputKind::PortableExecutable; request.bytes = pe();
        request.selectedAddress = 0x140001002ull; request.timeoutSeconds = 45;
        auto& portable = add("legacy-pe", request);
        portable.sparse = false; portable.entry = portable.mappedLine = 0x140001000ull;
        portable.expression = QStringLiteral("+");
        auto& cancel = add("cancel", raw(QByteArray::fromHex("b82a000000c3")));
        cancel.success = false; cancel.error = QStringLiteral("cancelled"); cancel.cancelAfterMs = 1000;
        for (const auto* mode : {"correct", "wrong-sha", "wrong-entry", "outside-body", "no-control"}) {
            request = raw(QByteArray::fromHex("b82a000000c3"), 0); request.selectedAddress = 1;
            request.segments.append({0x1000, QByteArray("ABCD")});
            auto& protocol = add(qPrintable(QStringLiteral("protocol-") + QString::fromLatin1(mode)), request, 2);
            protocol.producer = QString::fromLatin1(mode);
            protocol.success = protocol.producer == QStringLiteral("correct");
            protocol.error = protocol.success ? QString() : protocol.producer == QStringLiteral("wrong-sha")
                ? QStringLiteral("snapshot_mismatch") : QStringLiteral("invalid_result");
        }
        return result;
    }

    class ProducerEnvironment
    {
    public:
        explicit ProducerEnvironment(const QString& mode)
        {
            if (mode.isEmpty()) return;
            active = true; previousJava = qgetenv("KSWORD_GHIDRA_JAVA"); previousMode = qgetenv("KSWORD_SPARSE_TEST_PRODUCER");
            hadJava = qEnvironmentVariableIsSet("KSWORD_GHIDRA_JAVA"); hadMode = qEnvironmentVariableIsSet("KSWORD_SPARSE_TEST_PRODUCER");
            qputenv("KSWORD_GHIDRA_JAVA", QCoreApplication::applicationFilePath().toLocal8Bit());
            qputenv("KSWORD_SPARSE_TEST_PRODUCER", mode.toLatin1());
        }
        ~ProducerEnvironment()
        {
            if (!active) return;
            if (hadJava) qputenv("KSWORD_GHIDRA_JAVA", previousJava); else qunsetenv("KSWORD_GHIDRA_JAVA");
            if (hadMode) qputenv("KSWORD_SPARSE_TEST_PRODUCER", previousMode); else qunsetenv("KSWORD_SPARSE_TEST_PRODUCER");
        }
    private:
        bool active = false, hadJava = false, hadMode = false;
        QByteArray previousJava, previousMode;
    };

    int produce(const QStringList& args)
    {
        const int index = args.indexOf(QStringLiteral("-postScript"));
        if (index < 0 || args.size() < index + 8) return 2;
        QFile input(args[index + 3]); if (!input.open(QIODevice::ReadOnly)) return 3;
        const auto bytes = input.readAll(); const auto spec = QJsonDocument::fromJson(bytes).object();
        const QString entry = spec.value(QStringLiteral("entryAddress")).toString();
        const auto mode = qEnvironmentVariable("KSWORD_SPARSE_TEST_PRODUCER");
        auto digest = QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex();
        if (mode == QStringLiteral("wrong-sha")) digest = QByteArray(64, '0');
        qint64 captured = 0;
        for (const auto value : spec.value(QStringLiteral("segments")).toArray())
            captured += QByteArray::fromBase64(value.toObject().value(QStringLiteral("bytes")).toString().toLatin1()).size();
        const auto returnedEntry = mode == QStringLiteral("wrong-entry")
            ? QString::number(entry.toULongLong(nullptr, 16) + 5, 16) : entry;
        QJsonArray lines; lines.append(entry); lines.append(QJsonValue::Null);
        lines.append(mode == QStringLiteral("outside-body") ? QStringLiteral("1000") : entry); lines.append(QJsonValue::Null);
        QJsonObject result {{QStringLiteral("schemaVersion"), 1}, {QStringLiteral("success"), true},
            {QStringLiteral("selectedAddress"), args[index + 4]}, {QStringLiteral("snapshotSha256"), QString::fromLatin1(digest)},
            {QStringLiteral("functionAddress"), returnedEntry}, {QStringLiteral("functionName"), QStringLiteral("protocol_producer_only")},
            {QStringLiteral("code"), QStringLiteral("int protocol_producer_only(void)\n{\n    return 42;\n}\n")},
            {QStringLiteral("lineAddresses"), lines}, {QStringLiteral("rawControlFlow"), true},
            {QStringLiteral("selectedCovered"), true}, {QStringLiteral("controlFlowComplete"), mode != QStringLiteral("no-control")},
            {QStringLiteral("decodedInstructions"), 2}, {QStringLiteral("capturedBytes"), captured}};
        QFile output(args[index + 6]); if (!output.open(QIODevice::WriteOnly)) return 4;
        output.write(QJsonDocument(result).toJson(QJsonDocument::Compact)); return 0;
    }

    bool runCase(const Case& test, QJsonArray& records)
    {
        if (!test.planningError.isEmpty()) {
            std::printf("[FAIL] %s planner=%s\n", test.name.toUtf8().constData(), test.planningError.toUtf8().constData());
            records.append(QJsonObject{{QStringLiteral("case"), test.name}, {QStringLiteral("pass"), false}, {QStringLiteral("planningError"), test.planningError}});
            return false;
        }
        ProducerEnvironment producer(test.producer);
        GhidraDecompiler backend;
        backend.setGhidraDirectory(qEnvironmentVariable("KSWORD_GHIDRA_DIR"));
        QEventLoop loop;
        DecompilerResult result;
        bool done = false, watchdogExpired = false;
        QVector<DecompilerProgress> progress;
        QObject::connect(&backend, &GhidraDecompiler::finished, &loop, [&](const DecompilerResult& value) {
            result = value; done = true; loop.quit();
        });
        QObject::connect(&backend, &GhidraDecompiler::progressChanged, &loop, [&](const auto& value) { progress.append(value); });
        QTimer watchdog; watchdog.setSingleShot(true);
        QObject::connect(&watchdog, &QTimer::timeout, &loop, [&] { watchdogExpired = true; backend.cancel(); loop.quit(); });
        watchdog.start(65000);
        QElapsedTimer elapsed; elapsed.start();
        const bool started = backend.start(test.request);
        if (test.cancelAfterMs >= 0) QTimer::singleShot(test.cancelAfterMs, &backend, &GhidraDecompiler::cancel);
        if (started) loop.exec();
        bool ok = started && done && !watchdogExpired && !backend.isRunning() && result.success == test.success && result.error == test.error;
        if (test.success) {
            bool mapped = false;
            for (qsizetype i = 0; i < result.lineAddresses.size(); ++i)
                mapped |= result.lineAddressValid.value(i) && result.lineAddresses[i] >= test.mappedLine && result.lineAddresses[i] < test.mappedLine + 16;
            ok = ok && result.rawControlFlow == test.sparse && result.functionAddress == test.entry && mapped &&
                !result.code.isEmpty() && result.code.contains(test.expression);
            if (test.sparse) {
                quint64 bytes = 0; for (const auto& segment : test.request.segments) bytes += quint64(segment.bytes.size());
                ok = ok && result.decodedInstructions == test.instructionCount && result.capturedBytes == bytes;
            }
            if (test.producer.isEmpty()) {
                bool analyzed = false, decompiled = false, rendered = false, ordered = true;
                int previous = -1;
                for (const auto& value : progress) {
                    const int stage = static_cast<int>(value.stage); ordered &= stage >= previous; previous = stage;
                    analyzed |= value.stage == DecompilerStage::Analyzing;
                    decompiled |= value.stage == DecompilerStage::Decompiling;
                    rendered |= value.stage == DecompilerStage::Rendering && value.totalUnits > 0 && value.completedUnits == value.totalUnits;
                }
                ok = ok && analyzed && decompiled && rendered && ordered;
            }
        } else ok = ok && result.code.isEmpty() && result.lineAddresses.isEmpty();
        if (test.cancelAfterMs >= 0) ok = ok && elapsed.elapsed() < 10000;
        std::printf("[%s] %s success=%d error=%s instructions=%u elapsedMs=%lld\n", ok ? "PASS" : "FAIL",
            test.name.toUtf8().constData(), int(result.success), result.error.toUtf8().constData(), result.decodedInstructions,
            static_cast<long long>(elapsed.elapsed()));
        if (!ok) std::fprintf(stderr, "%s\n%s\n", result.code.toUtf8().constData(), result.diagnostics.toUtf8().constData());
        std::fflush(stdout);
        records.append(QJsonObject{{QStringLiteral("case"), test.name}, {QStringLiteral("pass"), ok},
            {QStringLiteral("productionPlanner"), test.planned},
            {QStringLiteral("success"), result.success}, {QStringLiteral("error"), result.error},
            {QStringLiteral("decodedInstructions"), static_cast<int>(result.decodedInstructions)},
            {QStringLiteral("elapsedMs"), elapsed.elapsed()}, {QStringLiteral("code"), result.code},
            {QStringLiteral("diagnostics"), result.diagnostics},
            {QStringLiteral("snapshotSha256"), QString::fromLatin1(result.snapshotSha256.toHex())}});
        return ok;
    }
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    const auto arguments = application.arguments();
    if (arguments.contains(QStringLiteral("-postScript"))) return produce(arguments);
    const auto all = cases();
    if (arguments.contains(QStringLiteral("--list"))) {
        for (const auto& test : all) std::puts(test.name.toUtf8().constData());
        return 0;
    }
    QStringList selected;
    for (int i = 1; i < arguments.size(); ++i) {
        if (arguments[i] == QStringLiteral("--core"))
            selected.append({QStringLiteral("planned-far-branch"), QStringLiteral("planned-rip-constant"), QStringLiteral("planned-cross-page"),
                QStringLiteral("far-branch"), QStringLiteral("rip-constant"), QStringLiteral("zero-entry"),
                QStringLiteral("x86"), QStringLiteral("lea"), QStringLiteral("write-only"), QStringLiteral("gs"),
                QStringLiteral("missing-edge"), QStringLiteral("indirect-jump"), QStringLiteral("legacy-pe"), QStringLiteral("cancel")});
        else if (arguments[i] == QStringLiteral("--case") && i + 1 < arguments.size()) selected.append(arguments[++i]);
        else { std::fprintf(stderr, "Unknown argument or missing case name\n"); return 2; }
    }
    for (const auto& name : selected)
        if (std::none_of(all.cbegin(), all.cend(), [&](const Case& value) { return value.name == name; })) {
            std::fprintf(stderr, "Unknown case: %s\n", name.toUtf8().constData()); return 2;
        }
    QJsonArray records;
    unsigned failures = 0, count = 0;
    for (const auto& test : all) {
        if (!selected.isEmpty() && !selected.contains(test.name)) continue;
        ++count; if (!runCase(test, records)) ++failures;
        const auto output = qEnvironmentVariable("KSWORD_SPARSE_TEST_OUTPUT");
        if (!output.isEmpty()) { QFile file(output); if (file.open(QIODevice::WriteOnly)) file.write(QJsonDocument(records).toJson(QJsonDocument::Indented)); }
    }
    std::printf("GHIDRA_SPARSE_BACKEND_RESULT=%s CASES=%u FAILURES=%u\n", failures ? "FAIL" : "PASS", count, failures);
    return failures ? 1 : 0;
}
