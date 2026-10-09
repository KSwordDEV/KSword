#include "../RuntimeProfile.h"
#include <QCoreApplication>
#include <QJsonDocument>
#include <cstdio>

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    using namespace ks::plugin_host::ghidra_runtime;
    if (app.arguments().size() < 3) return 2;
    const auto action = app.arguments().at(1);
    const auto directory = app.arguments().at(2);
    QString error;
    const bool ok = action == QStringLiteral("write") ? writePackageMetadata(directory, &error)
        : action == QStringLiteral("validate") && validateDirectory(directory, &error);
    std::printf("RUNTIME_PROFILE_%s=%s ERROR=%s\n", action.toUpper().toUtf8().constData(), ok ? "PASS" : "FAIL", error.toUtf8().constData());
    return ok ? 0 : 1;
}
