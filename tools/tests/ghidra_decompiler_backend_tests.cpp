// Actual Ghidra runtime regression; requires KSWORD_GHIDRA_DIR and a JDK.
// QtCore-only host, intentionally does not include the production main GUI.
#include "UI/Decompiler/GhidraDecompiler.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QEventLoop>
#include <QElapsedTimer>
#include <QFile>
#include <QTimer>
#include <QtEndian>
#include <cstdio>

namespace
{
    template<typename T> void put(QByteArray& bytes, qsizetype offset, T value)
    {
        qToLittleEndian<T>(value, bytes.data() + offset);
    }

    QByteArray peSnapshot()
    {
        QByteArray bytes(0x400, '\0');
        put<quint16>(bytes, 0, 0x5a4d);
        put<quint32>(bytes, 0x3c, 0x80);
        put<quint32>(bytes, 0x80, 0x4550);
        put<quint16>(bytes, 0x84, 0x8664);
        put<quint16>(bytes, 0x86, 1);
        put<quint16>(bytes, 0x94, 0xf0);
        put<quint16>(bytes, 0x96, 0x22);
        put<quint16>(bytes, 0x98, 0x20b);
        put<quint32>(bytes, 0x9c, 0x200);
        put<quint32>(bytes, 0xa8, 0x1000);
        put<quint32>(bytes, 0xac, 0x1000);
        put<quint64>(bytes, 0xb0, 0x140000000ull);
        put<quint32>(bytes, 0xb8, 0x1000);
        put<quint32>(bytes, 0xbc, 0x200);
        put<quint16>(bytes, 0xc0, 6);
        put<quint16>(bytes, 0xc8, 6);
        put<quint32>(bytes, 0xd0, 0x2000);
        put<quint32>(bytes, 0xd4, 0x200);
        put<quint16>(bytes, 0xdc, 3);
        put<quint64>(bytes, 0xe0, 0x100000);
        put<quint64>(bytes, 0xe8, 0x1000);
        put<quint64>(bytes, 0xf0, 0x100000);
        put<quint64>(bytes, 0xf8, 0x1000);
        put<quint32>(bytes, 0x104, 16);
        bytes.replace(0x188, 5, ".text");
        put<quint32>(bytes, 0x190, 5);
        put<quint32>(bytes, 0x194, 0x1000);
        put<quint32>(bytes, 0x198, 0x200);
        put<quint32>(bytes, 0x19c, 0x200);
        put<quint32>(bytes, 0x1ac, 0x60000020);
        bytes.replace(0x200, 5, QByteArray::fromHex("8bc103c2c3"));
        return bytes;
    }

    // 人工 PE 的函数返回诊断文字本身，验证字符串不会被当作 Ghidra 的警告注释。
    QByteArray peWarningStringSnapshot()
    {
        QByteArray bytes = peSnapshot();
        bytes.append(QByteArray(0x200, '\0'));
        const QByteArray text("Control flow encountered bad instruction data");
        put<quint16>(bytes, 0x86, 2);
        put<quint32>(bytes, 0xd0, 0x3000);
        put<quint32>(bytes, 0x190, 8);
        bytes.replace(0x200, 8, QByteArray::fromHex("488d05f90f0000c3"));
        bytes.replace(0x1b0, 6, ".rdata");
        put<quint32>(bytes, 0x1b8, quint32(text.size() + 1));
        put<quint32>(bytes, 0x1bc, 0x2000);
        put<quint32>(bytes, 0x1c0, 0x200);
        put<quint32>(bytes, 0x1c4, 0x400);
        put<quint32>(bytes, 0x1d4, 0x40000040);
        bytes.replace(0x400, text.size(), text);
        bytes[0x400 + text.size()] = '\0';
        return bytes;
    }

    bool run(ks::ui::GhidraDecompiler& backend, const ks::ui::DecompilerRequest& request,
        const char* name, quint64 expectedEntry, const QString& expression)
    {
        QEventLoop loop;
        ks::ui::DecompilerResult result;
        QVector<ks::ui::DecompilerProgress> progress;
        bool done = false;
        const auto connection = QObject::connect(&backend, &ks::ui::GhidraDecompiler::finished,
            &loop, [&](const auto& value) { result = value; done = true; loop.quit(); });
        const auto progressConnection = QObject::connect(&backend, &ks::ui::GhidraDecompiler::progressChanged,
            &loop, [&](const auto& value) { progress.append(value); });
        QTimer watchdog;
        watchdog.setSingleShot(true);
        QObject::connect(&watchdog, &QTimer::timeout, &loop, [&] { backend.cancel(); loop.quit(); });
        watchdog.start(180000);
        backend.start(request);
        loop.exec();
        QObject::disconnect(connection);
        QObject::disconnect(progressConnection);
        bool sawAnalysis = false, sawDecompile = false, sawRendering = false;
        bool ordered = true;
        int previous = -1;
        for (const auto& value : progress) {
            const int stage = static_cast<int>(value.stage);
            ordered = ordered && stage >= previous;
            previous = stage;
            sawAnalysis = sawAnalysis || value.stage == ks::ui::DecompilerStage::Analyzing;
            sawDecompile = sawDecompile || value.stage == ks::ui::DecompilerStage::Decompiling;
            sawRendering = sawRendering || (value.stage == ks::ui::DecompilerStage::Rendering &&
                value.totalUnits > 0 && value.completedUnits == value.totalUnits);
        }
        bool mapped = false;
        for (qsizetype index = 0; index < result.lineAddresses.size(); ++index) {
            if (result.lineAddressValid.value(index) && result.lineAddresses[index] >= expectedEntry &&
                result.lineAddresses[index] < expectedEntry + 32) mapped = true;
        }
        const bool ok = done && result.success && result.functionAddress == expectedEntry &&
            result.code.contains(QStringLiteral("return")) && result.code.contains(expression) && mapped &&
            result.snapshotSha256 == QCryptographicHash::hash(request.bytes, QCryptographicHash::Sha256) &&
            ordered && sawAnalysis && sawDecompile && sawRendering;
        std::printf("[%s] %s error=%s entry=%llx mapped=%d\n", ok ? "PASS" : "FAIL", name,
            result.error.toUtf8().constData(), static_cast<unsigned long long>(result.functionAddress), int(mapped));
        std::printf("%s\n", result.code.toUtf8().constData());
        std::printf("progress stages=%lld ordered=%d analysis=%d decompile=%d rendering=%d\n",
            static_cast<long long>(progress.size()), int(ordered), int(sawAnalysis), int(sawDecompile), int(sawRendering));
        if (!ok) std::fprintf(stderr, "%s\n", result.diagnostics.toUtf8().constData());
        std::fflush(stdout);
        return ok;
    }

    bool cancellation(ks::ui::GhidraDecompiler& backend, const ks::ui::DecompilerRequest& request)
    {
        QEventLoop loop;
        QElapsedTimer elapsed;
        elapsed.start();
        ks::ui::DecompilerResult result;
        bool done = false;
        const auto connection = QObject::connect(&backend, &ks::ui::GhidraDecompiler::finished,
            &loop, [&](const auto& value) { result = value; done = true; loop.quit(); });
        QTimer::singleShot(250, &loop, [&] { backend.cancel(); });
        QTimer::singleShot(5000, &loop, &QEventLoop::quit);
        backend.start(request);
        loop.exec();
        QObject::disconnect(connection);
        const bool ok = done && !backend.isRunning() && !result.success &&
            result.error == QStringLiteral("cancelled") && !result.snapshotSha256.isEmpty() && elapsed.elapsed() < 5000;
        std::printf("[%s] actual JVM asynchronous cancellation elapsed=%lld error=%s\n", ok ? "PASS" : "FAIL",
            static_cast<long long>(elapsed.elapsed()), result.error.toUtf8().constData());
        return ok;
    }

    bool rejection(ks::ui::GhidraDecompiler& backend, const ks::ui::DecompilerRequest& request,
        const char* name, const QString& error, int deadline = 2000)
    {
        QEventLoop loop;
        ks::ui::DecompilerResult result;
        bool done = false;
        const auto connection = QObject::connect(&backend, &ks::ui::GhidraDecompiler::finished,
            &loop, [&](const auto& value) { result = value; done = true; loop.quit(); });
        QTimer::singleShot(deadline, &loop, [&] { backend.cancel(); loop.quit(); });
        backend.start(request);
        loop.exec();
        QObject::disconnect(connection);
        const bool ok = done && !result.success && result.error == error && !backend.isRunning();
        std::printf("[%s] rejection %s error=%s\n", ok ? "PASS" : "FAIL", name, result.error.toUtf8().constData());
        if (!ok) std::printf("%s\n%s\n", result.code.toUtf8().constData(), result.diagnostics.toUtf8().constData());
        std::fflush(stdout);
        return ok;
    }

    // 重放实际模块基址被当作 RAW 代码和坏指令被宣称成功的故障。
    int failureReproduction(ks::ui::GhidraDecompiler& backend)
    {
        int failures = 0;
        ks::ui::DecompilerRequest request;
        request.bytes = peSnapshot();
        request.baseAddress = 0x7ffe6e5b0000ull;
        request.selectedAddress = request.baseAddress;
        if (!rejection(backend, request, "RAW complete PE header is data", QStringLiteral("non_code_address"), 180000)) ++failures;
        request.bytes = QByteArray(64, '\0');
        request.bytes.append(char(0x0f));
        if (!rejection(backend, request, "RAW zero data ends in invalid instruction", QStringLiteral("invalid_instruction_data"), 180000)) ++failures;
        return failures;
    }

    int validation(ks::ui::GhidraDecompiler& backend)
    {
        int failures = 0;
        ks::ui::DecompilerRequest request;
        request.inputKind = ks::ui::DecompilerInputKind::PortableExecutable;
        request.bytes = peSnapshot();
        request.selectedAddress = 0x140001005ull;
        if (!rejection(backend, request, "raw alignment padding past VirtualSize", QStringLiteral("unmapped_pe_address"))) ++failures;
        request.selectedAddress = 0x140001000ull;
        put<quint16>(request.bytes, 0x84, 0xaa64);
        if (!rejection(backend, request, "ARM64 is not x64", QStringLiteral("unsupported_architecture"))) ++failures;
        request.bytes = peSnapshot();
        request.x64 = false;
        if (!rejection(backend, request, "PE architecture does not match decoder", QStringLiteral("unsupported_architecture"))) ++failures;
        request.x64 = true;
        request.bytes = peSnapshot();
        put<quint16>(request.bytes, 0x86, 2);
        request.bytes.replace(0x1b0, 40, request.bytes.mid(0x188, 40));
        if (!rejection(backend, request, "duplicate overlapping VA sections", QStringLiteral("unmapped_pe_address"))) ++failures;
        request.bytes = peSnapshot();
        put<quint32>(request.bytes, 0x190, 0x800);
        request.selectedAddress = 0x140001200ull;
        if (!rejection(backend, request, "virtual zero-fill past captured raw bytes", QStringLiteral("unmapped_pe_address"))) ++failures;
        request.bytes = peSnapshot().left(0x202);
        request.selectedAddress = 0x140001000ull;
        if (!rejection(backend, request, "truncated complete PE capture", QStringLiteral("invalid_pe"))) ++failures;
        request.bytes = peSnapshot();
        put<quint32>(request.bytes, 0x1ac, 0x40000040);
        if (!rejection(backend, request, "PE captured non-executable section", QStringLiteral("non_code_address"))) ++failures;
        request.inputKind = ks::ui::DecompilerInputKind::RawMemory;
        request.bytes = QByteArray::fromHex("8bc103c2c3");
        request.baseAddress = ~quint64(0);
        request.selectedAddress = request.baseAddress;
        if (!rejection(backend, request, "unsigned RAW range overflow", QStringLiteral("invalid_address"))) ++failures;
        request.x64 = false;
        request.baseAddress = 0xffffffffull;
        request.selectedAddress = request.baseAddress;
        if (!rejection(backend, request, "32-bit RAW range overflow", QStringLiteral("invalid_address"))) ++failures;
        request.bytes.clear();
        if (!rejection(backend, request, "empty snapshot", QStringLiteral("empty_snapshot"))) ++failures;
        return failures;
    }
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    ks::ui::GhidraDecompiler backend;
    if (application.arguments().contains(QStringLiteral("--failure-repro-only"))) {
        const int failures = failureReproduction(backend);
        std::printf("GHIDRA_FAILURE_REPRO_RESULT=%s FAILURES=%d\n", failures ? "FAIL" : "PASS", failures);
        return failures ? 1 : 0;
    }
    if (application.arguments().contains(QStringLiteral("--literal-repro-only"))) {
        ks::ui::DecompilerRequest literal;
        literal.bytes = peWarningStringSnapshot();
        literal.inputKind = ks::ui::DecompilerInputKind::PortableExecutable;
        literal.selectedAddress = 0x140001000ull;
        return run(backend, literal, "PE normal return string is not a diagnostic", literal.selectedAddress,
            QStringLiteral("Control flow encountered bad instruction data")) ? 0 : 1;
    }
    int failures = validation(backend);
    if (application.arguments().contains(QStringLiteral("--validation-only"))) {
        std::printf("GHIDRA_VALIDATION_RESULT=%s FAILURES=%d\n", failures ? "FAIL" : "PASS", failures);
        return failures ? 1 : 0;
    }
    const bool peOnly = application.arguments().contains(QStringLiteral("--pe-only"));
    failures += failureReproduction(backend);
    ks::ui::DecompilerRequest request;
    if (!peOnly) {
    request.bytes = QByteArray::fromHex("8bc103c2c3");
    request.baseAddress = 0xfffff80000001000ull;
    request.selectedAddress = request.baseAddress;
    if (!run(backend, request, "RAW x64 unsigned kernel VA sum", request.baseAddress, QStringLiteral("+"))) ++failures;
    request.bytes = QByteArray::fromHex("4d5a8bc103c2c3");
    if (!run(backend, request, "RAW MZ instruction prefix is not a complete PE header", request.baseAddress, QStringLiteral("+"))) ++failures;
    request.bytes = QByteArray::fromHex("8bc12bc2c3");
    if (!run(backend, request, "RAW current staged snapshot subtraction", request.baseAddress, QStringLiteral("-"))) ++failures;
    request.bytes = QByteArray::fromHex("8bc13bca7d028bc2c3");
    if (!run(backend, request, "RAW x64 conditional C control flow", request.baseAddress, QStringLiteral("if"))) ++failures;
    request.x64 = false;
    request.baseAddress = 0x1000;
    request.selectedAddress = request.baseAddress;
    request.bytes = QByteArray::fromHex("558bec8b450803450c5dc3");
    if (!run(backend, request, "RAW x86 stack arguments", request.baseAddress, QStringLiteral("+"))) ++failures;
    }
    request.x64 = true;
    request.inputKind = ks::ui::DecompilerInputKind::PortableExecutable;
    request.bytes = peSnapshot();
    request.baseAddress = 0;
    request.selectedAddress = 0x140001002ull;
    if (!run(backend, request, "PE containing function selected in middle", 0x140001000ull, QStringLiteral("+"))) ++failures;
    request.bytes = peWarningStringSnapshot();
    request.selectedAddress = 0x140001000ull;
    if (!run(backend, request, "PE normal return string is not a diagnostic", request.selectedAddress,
        QStringLiteral("Control flow encountered bad instruction data"))) ++failures;
    if (!cancellation(backend, request)) ++failures;
    std::printf("GHIDRA_RUNTIME_RESULT=%s FAILURES=%d\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
