// 真正的 C 页面/Qt 编辑器/后端生命周期夹具；合成字节，不启动分析进程或目标 I/O。
#include "../workbench_pseudocode_contract_tests.h"
#include <QApplication>
#include <QCoreApplication>
#include <QDir>
#include <QSettings>
#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    application.setQuitOnLastWindowClosed(false);
    // 无组织名称的隔离 INI 设置不会落到生产注册表或用户配置；本夹具不编辑路径表单。
    QCoreApplication::setOrganizationName(QString());
    QCoreApplication::setApplicationName(QStringLiteral("workbench-pseudocode-ui-regression"));
    QSettings::setDefaultFormat(QSettings::IniFormat);
    const auto logs = QDir::current().filePath(QStringLiteral(".codex-build-logs"));
    QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, logs);
    QSettings::setPath(QSettings::IniFormat, QSettings::SystemScope, logs);
    unsigned checks = 0; // 本次进程实际执行的断言数。
    const auto require = [&checks](const bool condition, const char* description) {
        ++checks;
        std::printf("[%s] %u %s\n", condition ? "PASS" : "FAIL", checks, description);
        std::fflush(stdout);
        if (!condition) std::exit(1);
    };
    const auto arguments = application.arguments(); // 可独立隔离每个同步销毁探针。
    if (arguments.size() == 3 && arguments.at(1) == QStringLiteral("--case"))
    {
        const QStringList names {QStringLiteral("show-context"), QStringLiteral("show-delete"), QStringLiteral("hide-delete"),
            QStringLiteral("hide-new-request"), QStringLiteral("value-delete"),
            QStringLiteral("value-context"), QStringLiteral("cancel-running")};
        require(names.contains(arguments.at(2)), "standalone runner recognizes the requested reentry case");
        RunWorkbenchPseudocodeProgressReentryTests(require, arguments.at(2));
    }
    else
    {
        require(arguments.size() == 1, "standalone runner accepts only its documented optional case selector");
        RunWorkbenchPseudocodeContractTests(require);
    }
    std::printf("WORKBENCH_PSEUDOCODE_UI_RESULT=PASS CHECKS=%u\n", checks);
    return 0;
}
