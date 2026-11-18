#include "ProcessDetectionForensics.h"
#include <QFile>
#include <QFileInfo>
#include <QtEndian>
#include <array>

namespace ksword::detection
{
    namespace
    {
        constexpr quint64 pageSize = 4096;
        constexpr quint64 pfnMask = 0x000ffffffffff000ULL;
        constexpr quint64 userPresent = 5;
        constexpr quint64 large = 1ULL << 7;
        quint64 entry(const char* page, int index)
        {
            return qFromLittleEndian<quint64>(page + sizeof(quint64) * index);
        }

        // Follow a bounded user-mode path. Only table pages inside this flat capture
        // can validate a candidate. A missing page leaves the candidate unconfirmed.
        bool userMapping(QFile& file, quint64 offset, quint64 size, int level, int& budget, bool& ioFailure)
        {
            if (offset >= size || budget <= 0) return false;
            --budget;
            std::array<char, pageSize> page;
            constexpr qint64 bytes = static_cast<qint64>(pageSize);
            if (!file.seek(static_cast<qint64>(offset)) || file.read(page.data(), bytes) != bytes)
            { ioFailure = true; return false; }
            for (int i = 0; i < 512; ++i)
            {
                const auto value = entry(page.data(), i);
                if ((value & userPresent) != userPresent) continue;
                const auto pa = value & pfnMask;
                if (level == 1 && pa < size) return true;
                if (level > 1 && (value & large))
                {
                    const quint64 leafSize = level == 3 ? (1ULL << 30) : (1ULL << 21);
                    // Bit 12 is PAT for a large leaf. Other low physical bits are reserved.
                    if (!(pa & (leafSize - 1) & ~quint64(0x1000)) && (pa & ~(leafSize - 1)) < size) return true;
                }
                else if (level > 1 && userMapping(file, pa, size, level - 1, budget, ioFailure)) return true;
                if (budget <= 0 || ioFailure) break;
            }
            return false;
        }
    }

    void ScanRawPageRoots(ScanResult& result, MethodReport& report, const QString& path, const CancelCheck& stop)
    {
        QFile file(path), tables(path);
        if (!QFileInfo(path).isAbsolute() || !QFileInfo(path).isFile() ||
            !file.open(QIODevice::ReadOnly) || !tables.open(QIODevice::ReadOnly))
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("请选择偏移从物理地址零开始、保留物理空洞的原始镜像。");
            return;
        }
        const auto prefix = file.peek(8);
        const auto size = static_cast<quint64>(file.size());
        if (!size || size % pageSize || prefix.startsWith("PAGEDUMP") || prefix.startsWith("PAGEDU64") ||
            prefix.startsWith("MDMP") || prefix.startsWith("\x7f" "ELF") || prefix.startsWith("EVF") ||
            prefix.startsWith("QFI\xfb") || prefix.startsWith("vhdxfile"))
        {
            report.status = Status::Failed;
            report.detail = QStringLiteral("该输入不符合平坦物理镜像的格式。");
            return;
        }
        quint64 scanned = 0, unresolved = 0;
        bool ioFailure = false;
        while (scanned < size / pageSize && !ioFailure)
        {
            if (stop()) { report.status = Status::Cancelled; break; }
            const QByteArray block = file.read(1024 * 1024);
            if (block.isEmpty() || block.size() % pageSize) { ioFailure = true; break; }
            for (qsizetype cursor = 0; cursor < block.size(); cursor += pageSize)
            {
                const auto* page = block.constData() + cursor;
                const auto phys = scanned++ * pageSize;
                if (phys == 0) continue;
                int self = 256;
                for (; self < 512; ++self)
                {
                    const auto val = entry(page, self);
                    if ((val & (userPresent | large | pfnMask)) == (phys | 1)) break;
                }
                if (self == 512) continue;
                int budget = 32;
                bool valid = false;
                for (int i = 0; i < 256 && budget && !ioFailure; ++i)
                {
                    const auto val = entry(page, i);
                    if ((val & (userPresent | large)) == userPresent &&
                        userMapping(tables, val & pfnMask, size, 3, budget, ioFailure)) { valid = true; break; }
                }
                if (ioFailure) break;
                if (!valid) { ++unresolved; continue; }
                Evidence evidence;
                evidence.methods = report.method;
                evidence.category = QStringLiteral("自引用页表根候选");
                evidence.scope = path;
                evidence.detail = QStringLiteral("PML4=0x%1 | self[%2] | user mapping").arg(phys, 0, 16).arg(self);
                result.evidence.append(std::move(evidence));
                if (++report.count == 8192) break;
            }
            if (report.count == 8192) break;
        }
        if (report.status != Status::Cancelled && (scanned < size / pageSize || ioFailure))
            report.status = scanned ? Status::Partial : Status::Failed;
        report.detail = QStringLiteral("已检查 %1/%2 页，自引用但未验证用户映射 %3 页。")
            .arg(scanned).arg(size / pageSize).arg(unresolved);
    }
}
