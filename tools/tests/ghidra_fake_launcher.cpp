// Isolated protocol fixture. It does not load Java, execute imported code or
// claim to decompile; the production backend launches and validates its output.
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QThread>
#include <cstdio>

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    const auto recordPath = qEnvironmentVariable("KSWORD_GHIDRA_FIXTURE_LAUNCH_RECORD");
    if (!recordPath.isEmpty())
    {
        QFile record(recordPath);
        if (!record.open(QIODevice::WriteOnly)) return 5;
        record.write(QCoreApplication::applicationFilePath().toUtf8());
    }
    const auto arguments = application.arguments();
    const auto scriptIndex = arguments.indexOf(QStringLiteral("-postScript"));
    if (scriptIndex < 0 || arguments.size() < scriptIndex + 9
        || arguments.at(scriptIndex + 1) != QStringLiteral("GhidraPseudocode.java")
        || arguments.at(scriptIndex + 2) != QStringLiteral("decompile")) return 2;
    const auto selected = arguments.at(scriptIndex + 3);
    const auto outputPath = arguments.at(scriptIndex + 5);
    const auto snapshotPath = arguments.at(scriptIndex + 6);
    const auto mode = qEnvironmentVariable("KSWORD_GHIDRA_FIXTURE_MODE");
    const auto delay = qEnvironmentVariableIntValue("KSWORD_GHIDRA_FIXTURE_DELAY");
    if (delay > 0) QThread::msleep(static_cast<unsigned long>(delay));
    QFile snapshot(snapshotPath);
    if (!snapshot.open(QIODevice::ReadOnly)) return 3;
    auto digest = QCryptographicHash::hash(snapshot.readAll(), QCryptographicHash::Sha256).toHex();
    if (mode == QStringLiteral("wrong-sha")) digest = QByteArray(64, '0');
    const auto code = mode == QStringLiteral("many-lines")
        ? QStringLiteral("int fixture_function(void)\n{\n")
            + QStringLiteral("    fixture_value++;\n").repeated(120) + QStringLiteral("    return 42;\n}\n")
        : mode == QStringLiteral("long-code")
        ? QString(1024 * 1024 + 1, QLatin1Char('x'))
        : QStringLiteral("int fixture_function(void)\n{\n    return 42;\n}\n");
    QJsonArray lineAddresses;
    lineAddresses.append(selected);
    lineAddresses.append(QJsonValue::Null);
    lineAddresses.append(selected);
    lineAddresses.append(QJsonValue::Null);
    if (mode == QStringLiteral("many-lines"))
        while (lineAddresses.size() < code.count(u'\n')) lineAddresses.append(QJsonValue::Null);
    if (mode == QStringLiteral("outside-line")) lineAddresses[2] = QStringLiteral("ffffffffffffffff");
    QJsonObject result{{QStringLiteral("schemaVersion"), 1},
        {QStringLiteral("success"), mode != QStringLiteral("failure")},
        {QStringLiteral("code"), code},
        {QStringLiteral("error"), mode == QStringLiteral("failure") ? QStringLiteral("fixture decompiler failure") : QString()},
        {QStringLiteral("functionName"), QStringLiteral("fixture_function")},
        {QStringLiteral("functionAddress"), selected},
        {QStringLiteral("selectedAddress"), mode == QStringLiteral("wrong-address") ? QStringLiteral("ffffffffffffffff") : selected},
        {QStringLiteral("snapshotSha256"), QString::fromLatin1(digest)},
        {QStringLiteral("boundaryInferred"), false},
        {QStringLiteral("lineAddresses"), lineAddresses}};
    if (mode == QStringLiteral("wrong-schema")) result[QStringLiteral("schemaVersion")] = 99;
    if (mode == QStringLiteral("empty-function")) result[QStringLiteral("functionName")] = QString();
    QFile output(outputPath);
    if (!output.open(QIODevice::WriteOnly)) return 4;
    output.write(mode == QStringLiteral("malformed") ? QByteArray("{malformed")
        : QJsonDocument(result).toJson(QJsonDocument::Compact));
    output.close();
    std::fputs("fixture launcher only; no Ghidra execution\n", stderr);
    return mode == QStringLiteral("nonzero") ? 9 : 0;
}
