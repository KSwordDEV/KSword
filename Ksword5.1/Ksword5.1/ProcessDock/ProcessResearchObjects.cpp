#include "ProcessResearchObjects.h"
#include <QCoreApplication>
#include <QDir>
#include <QFileInfo>

namespace ksword::detection
{
    bool CollectResearchObjects(int id, const ScanInputs& inputs, ScanResult& result,
        MethodReport& report, const CancelCheck& stop)
    {
        switch (id)
        {
        case 3: case 5: case 8: case 11: case 12: case 13: case 14: case 15:
        case 16: case 18: case 21: case 23: case 25: case 29: case 30: case 62: break;
        default: return false;
        }
        const QDir plugins(QCoreApplication::applicationDirPath() + QStringLiteral("/forensics"));
        if (!QFileInfo(plugins.filePath(QStringLiteral("kswordobjects.py"))).isFile())
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("缺少随主程序部署的取证插件 kswordobjects.py。");
            return true;
        }
        RunVolatilityPlugin(result, report, inputs, stop, QStringLiteral("kswordobjects.KswordObjects"),
            {QStringLiteral("--method"), QString::number(id)}, plugins.absolutePath());
        return true;
    }
}
