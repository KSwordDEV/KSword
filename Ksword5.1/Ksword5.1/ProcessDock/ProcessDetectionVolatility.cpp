#include "ProcessDetectionForensics.h"
#include <bit>
#include <iterator>
#include <QFileInfo>
#include <QProcess>
#include <QProcessEnvironment>

namespace ksword::detection
{
    namespace
    {
        enum class RecordKind { Observation, CrossView, ExecutionFinding };
        struct Plugin { const char* id; QString name; RecordKind kind = RecordKind::Observation; };
        const Plugin plugins[] = {
            {"windows.pslist.PsList", QStringLiteral("镜像活动进程链表")},
            {"windows.psscan.PsScan", QStringLiteral("镜像 EPROCESS 池扫描")},
            {"windows.thrdscan.ThrdScan", QStringLiteral("镜像 ETHREAD 池扫描")},
            {"windows.malware.psxview.PsXView", QStringLiteral("镜像进程四视图比对"), RecordKind::CrossView},
            {"windows.netscan.NetScan", QStringLiteral("镜像网络端点池扫描")},
            {"windows.malware.hollowprocesses.HollowProcesses", QStringLiteral("镜像进程空洞化检查"), RecordKind::ExecutionFinding},
            {"windows.malware.processghosting.ProcessGhosting", QStringLiteral("镜像进程 Ghosting 检查"), RecordKind::ExecutionFinding},
            {"windows.malware.ldrmodules.LdrModules", QStringLiteral("镜像 PEB 模块链与映射")},
            {"windows.malware.malfind.Malfind", QStringLiteral("镜像可疑可执行内存"), RecordKind::ExecutionFinding},
            {"windows.malware.suspicious_threads.SuspiciousThreads", QStringLiteral("镜像可疑线程入口"), RecordKind::ExecutionFinding},
            {"windows.malware.drivermodule.DriverModule", QStringLiteral("镜像驱动对象与模块比对")},
            {"windows.callbacks.Callbacks", QStringLiteral("镜像内核回调归属")},
            {"windows.ssdt.SSDT", QStringLiteral("镜像系统调用表归属")},
        };
        constexpr MethodMask firstPlugin = 1ULL << 40;
        constexpr qsizetype maxBytes = 24 * 1024 * 1024;
        constexpr int rowLimit = 4096;

        // Volatility's CSV renderer quotes multiline fields, doubles quotes and escapes
        // backslashes. Reading text here also preserves 64-bit addresses exactly.
        bool nextRow(const QByteArray& bytes, qsizetype& pos, QStringList& row)
        {
            row.clear();
            QByteArray field;
            bool quoted = false;
            while (pos < bytes.size())
            {
                const char c = bytes[pos++];
                if (c == '\\' && pos < bytes.size()) field += bytes[pos++];
                else if (c == '"' && quoted && pos < bytes.size() && bytes[pos] == '"')
                {
                    field += '"';
                    ++pos;
                }
                else if (c == '"') quoted = !quoted;
                else if (!quoted && (c == ',' || c == '\n'))
                {
                    if (c == '\n' && field.endsWith('\r')) field.chop(1);
                    row.append(QString::fromUtf8(field));
                    field.clear();
                    if (c == '\n') return true;
                }
                else field += c;
            }
            if (quoted) return false;
            row.append(QString::fromUtf8(field));
            return true;
        }

        void parseRows(const QByteArray& output, RecordKind kind, const QString& imagePath, ScanResult& result,
            MethodReport& report, const CancelCheck& stop, bool truncated = false)
        {
            qsizetype pos = 0;
            QStringList header, row;
            while (pos < output.size() && nextRow(output, pos, header) && header.size() == 1 && header.first().isEmpty()) {}
            if (header.size() < 2 || header.first() != QLatin1String("TreeDepth"))
            {
                report.status = Status::Failed;
                report.detail = QStringLiteral("无法识别 Volatility 的 CSV 表头。");
                return;
            }
            auto value = [&](const char* column) { return row.value(header.indexOf(QString::fromLatin1(column))); };
            while (pos < output.size())
            {
                if (stop()) { report.status = Status::Cancelled; break; }
                if (!nextRow(output, pos, row) || (row.size() != header.size() && !(row.size() == 1 && row[0].isEmpty())))
                {
                    report.status = Status::Partial;
                    report.detail = QStringLiteral("取证输出包含不完整的记录。");
                    break;
                }
                if (truncated && pos == output.size()) break;
                if (row.size() == 1) continue;
                if (report.count >= rowLimit)
                {
                    report.status = Status::Partial;
                    report.detail = QStringLiteral("已达到单项证据行数上限。");
                    break;
                }
                Evidence evidence;
                evidence.methods = report.method;
                evidence.scope = imagePath;
                evidence.pid = value("PID").toUInt();
                evidence.image = value("ImageFileName");
                if (evidence.image.isEmpty()) evidence.image = value("Name");
                if (evidence.image.isEmpty()) evidence.image = value("Process");
                if (kind == RecordKind::CrossView && value("pslist").compare(QLatin1String("false"), Qt::CaseInsensitive) == 0)
                    evidence.category = QStringLiteral("镜像活动链表缺项");
                else if (kind == RecordKind::ExecutionFinding)
                    evidence.category = QStringLiteral("镜像可疑执行线索");
                else
                    evidence.category = QStringLiteral("镜像取证记录");
                QStringList details;
                for (qsizetype i = 1; i < header.size(); ++i)
                    if (!row[i].isEmpty()) details.append(header[i] + QLatin1Char('=') + row[i]);
                evidence.detail = details.join(QLatin1String(" | "));
                // psxview's baseline belongs to this image. Keep its discrepancy in
                // the raw columns, separate from the live Toolhelp comparison.
                result.evidence.append(std::move(evidence));
                ++report.count;
            }
        }
    }

    QVector<Method> VolatilityMethods()
    {
        QVector<Method> list;
        for (size_t i = 0; i < std::size(plugins); ++i)
            list.append({firstPlugin << i, plugins[i].name, Cost::Slow});
        return list;
    }

    void ReadVolatility(ScanResult& result, MethodReport& report, const ScanInputs& inputs, const CancelCheck& stop)
    {
        const QFileInfo program(inputs.volatilityProgram);
        const QFileInfo memory(inputs.memoryImage);
        if (!program.isAbsolute() || !program.isFile() || program.suffix().compare(QLatin1String("exe"), Qt::CaseInsensitive) != 0 ||
            !memory.isAbsolute() || !memory.isFile() || !memory.isReadable())
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("请在检测方法中选择 Volatility 3 可执行文件和可读内存镜像。");
            return;
        }
        const auto index = std::countr_zero(report.method) - std::countr_zero(firstPlugin);
        if (index < 0 || index >= static_cast<int>(std::size(plugins))) { report.status = Status::Failed; return; }
        QProcess process;
        auto env = QProcessEnvironment::systemEnvironment();
        env.insert(QStringLiteral("PYTHONIOENCODING"), QStringLiteral("utf-8"));
        process.setProcessEnvironment(env);
        process.setWorkingDirectory(program.absolutePath());
        process.start(program.absoluteFilePath(), {QStringLiteral("--offline"), QStringLiteral("-q"),
            QStringLiteral("-r"), QStringLiteral("csv"), QStringLiteral("-f"), memory.absoluteFilePath(),
            QString::fromLatin1(plugins[index].id)}, QIODevice::ReadOnly);
        if (!process.waitForStarted(5000))
        {
            report.status = Status::Failed;
            report.detail = process.errorString();
            return;
        }
        QByteArray output, errors;
        do
        {
            process.waitForFinished(100);
            output += process.readAllStandardOutput();
            errors = (errors + process.readAllStandardError()).right(2048);
            if (stop() || output.size() > maxBytes)
            {
                process.kill();
                process.waitForFinished(5000);
                report.status = stop() ? Status::Cancelled : Status::Partial;
                if (report.status == Status::Partial)
                {
                    // Only parse through full CSV records from the bounded prefix.
                    parseRows(output.first(maxBytes), plugins[index].kind, memory.absoluteFilePath(), result, report, stop, true);
                    report.status = Status::Partial;
                    report.detail = QStringLiteral("取证输出达到读取上限。");
                }
                return;
            }
        } while (process.state() != QProcess::NotRunning);
        if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0)
        {
            report.status = Status::Failed;
            const auto diagnostic = errors.trimmed() + '\n' + output.right(2048).trimmed();
            report.detail = QStringLiteral("%1 (%2)\n%3").arg(QString::fromLatin1(plugins[index].id))
                .arg(process.exitCode()).arg(QString::fromUtf8(diagnostic).trimmed());
            return;
        }
        report.detail = QString::fromLatin1(plugins[index].id) + QLatin1String(" | ") + memory.absoluteFilePath();
        parseRows(output, plugins[index].kind, memory.absoluteFilePath(), result, report, stop);
    }
}
