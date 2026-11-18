#include "ProcessDetectionForensics.h"
#include <QDir>
#include <QFile>
#include <QMap>

namespace ksword::detection
{
    void ReadMountedMemory(ScanResult& result, MethodReport& report, const QString& root, const CancelCheck& stop)
    {
        if (root.isEmpty() || !QDir::isAbsolutePath(root))
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("请在检测方法中选择 MemProcFS 挂载目录。");
            return;
        }
        const QDir mount(root);
        const bool dtb = report.method == MountedDtb;
        if (dtb)
        {
            QFile progress(mount.filePath(QStringLiteral("misc/procinfo/progress_percent.txt")));
            if (!progress.open(QIODevice::ReadOnly) || progress.read(32).trimmed() != "100")
            {
                report.status = Status::Unavailable;
                report.detail = QStringLiteral("MemProcFS 页表根分析尚未就绪。");
                return;
            }
        }
        const QString path = mount.filePath(dtb ? QStringLiteral("misc/procinfo/dtb.txt") : QStringLiteral("sys/memory/pfndb.txt"));
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly))
        {
            report.status = Status::Unavailable;
            report.detail = path + QLatin1String(" | ") + file.errorString();
            return;
        }
        struct Owner { quint64 count = 0; quint64 firstPfn = 0; quint64 firstVa = 0; };
        QMap<quint32, Owner> privatePages;
        quint64 skipped = 0, parsed = 0;
        while (!file.atEnd())
        {
            if (stop()) { report.status = Status::Cancelled; break; }
            const QByteArray line = file.readLine(512);
            if (line.isEmpty()) break;
            if (!line.endsWith('\n') && !file.atEnd()) { ++skipped; break; }
            const auto trimmed = line.simplified();
            if (trimmed.isEmpty() || trimmed.startsWith("PFN#") || trimmed.startsWith("====")) continue;
            const auto fields = trimmed.split(' ');
            if (fields.size() < (dtb ? 5 : 6)) { ++skipped; continue; }
            bool idOk = false, pidOk = false, addressOk = false, otherOk = false;
            const auto index = fields[0].toULongLong(&idOk, 16);
            const auto pid = fields[1].toUInt(&pidOk, 10);
            const auto address = fields[dtb ? 2 : 5].toULongLong(&addressOk, 16);
            const auto object = dtb ? fields[3].toULongLong(&otherOk, 16) : 0;
            if (!idOk || !pidOk || !addressOk || (dtb && (!otherOk || !address || (address & 0xfff))))
            {
                ++skipped;
                continue;
            }
            ++parsed;
            if (dtb)
            {
                if (report.count == 8192) { ++skipped; break; }
                Evidence evidence;
                evidence.methods = report.method;
                evidence.scope = path;
                evidence.pid = pid;
                evidence.objectAddress = object;
                evidence.category = !pid && !object ? QStringLiteral("待核实的无归属页表根") : QStringLiteral("页表根归属");
                evidence.image = QString::fromUtf8(fields.mid(4).join(' '));
                evidence.detail = (!pid && !object ? QStringLiteral("待核实的无归属页表根")
                                                   : QStringLiteral("页表根归属"))
                    + QStringLiteral(" | DTB=0x%1").arg(address, 0, 16);
                result.evidence.append(std::move(evidence));
                ++report.count;
            }
            else if (pid && fields[3] == "ProcPriv")
            {
                if (privatePages.size() >= 8192 && !privatePages.contains(pid)) { ++skipped; break; }
                auto& owner = privatePages[pid];
                if (!owner.count) { owner.firstPfn = index; owner.firstVa = address; }
                ++owner.count;
            }
        }
        for (auto it = privatePages.cbegin(); it != privatePages.cend(); ++it)
        {
            Evidence evidence;
            evidence.methods = report.method;
            evidence.scope = path;
            evidence.pid = it.key();
            evidence.category = QStringLiteral("私有物理页归属");
            evidence.detail = QStringLiteral("ProcPriv=%1 | PFN=0x%2 | VA=0x%3")
                .arg(it->count).arg(it->firstPfn, 0, 16).arg(it->firstVa, 0, 16);
            result.evidence.append(std::move(evidence));
            ++report.count;
        }
        if (report.status != Status::Cancelled && (skipped || file.error() != QFileDevice::NoError || !parsed))
            report.status = parsed ? Status::Partial : Status::Failed;
        report.detail = QStringLiteral("%1 · 已解析 %2 行，跳过 %3 行。").arg(path).arg(parsed).arg(skipped);
        if (file.error() != QFileDevice::NoError) report.detail += QLatin1String(" | ") + file.errorString();
    }
}
