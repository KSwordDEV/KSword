#include "DiskCaptureTransaction.h"
#include <limits>

namespace ks::misc
{
    bool CapturedDiskMatches(const DiskCapturedRange& captured, const DiskDeviceInfo& selected,
        const unsigned long backend, const std::uint64_t generation)
    {
        // 序列号/容量变化即使磁盘号没有变，也不能沿用旧捕获。
        const auto& source = captured.source;
        return captured.generation == generation && captured.backend == backend &&
            source.diskIndex == selected.diskIndex && source.devicePath == selected.devicePath &&
            source.serial == selected.serial && source.vendor == selected.vendor && source.model == selected.model &&
            source.sizeBytes == selected.sizeBytes && source.bytesPerSector == selected.bytesPerSector;
    }

    DiskWriteReceipt ApplyCapturedDiskWrite(const DiskCapturedRange& captured,
        const QByteArray& replacement, const DiskWritePorts& ports)
    {
        DiskWriteReceipt receipt;
        const auto length = static_cast<std::uint64_t>(captured.original.size()); // length：冻结基线长度。
        const auto sector = captured.source.bytesPerSector; // sector：读取来源的逻辑扇区大小。
        if (captured.deviceIdentity.isEmpty() || captured.source.diskIndex < 0 || !length ||
            length > std::numeric_limits<std::uint32_t>::max() || replacement.size() != captured.original.size() ||
            !sector || captured.offset % sector || length % sector || captured.offset >= captured.source.sizeBytes ||
            length > captured.source.sizeBytes - captured.offset || !ports.identity || !ports.read || !ports.write)
        {
            receipt.error = QStringLiteral("捕获磁盘身份、范围或扇区对齐无效，请重新读取后再写回。");
            return receipt;
        }

        QString currentIdentity; // currentIdentity：每个阶段重新取得的设备身份。
        const auto sameIdentity = [&]() {
            currentIdentity.clear();
            if (!ports.identity(currentIdentity, receipt.error) || currentIdentity != captured.deviceIdentity)
            {
                if (receipt.error.isEmpty()) receipt.error = QStringLiteral("捕获磁盘身份已改变，本次写回已拒绝。");
                return false;
            }
            return true;
        };
        if (!sameIdentity()) return receipt;

        QByteArray before; // before：写入前的真实回读，不能拿编辑器缓存代替。
        if (!ports.read(before, receipt.error)) return receipt;
        if (before != captured.original)
        {
            receipt.error = QStringLiteral("磁盘原字节已改变，本次写回已拒绝，请重新读取。");
            return receipt;
        }
        if (!sameIdentity()) return receipt;

        // 已调用写端口之后，任何失败都使旧捕获失效；不自动覆盖目标做盲目回滚。
        receipt.writeAttempted = true;
        if (!ports.write(replacement, receipt.error)) return receipt;
        if (!ports.read(receipt.observed, receipt.error))
        {
            if (receipt.error.isEmpty()) receipt.error = QStringLiteral("写入完成但回读失败，不能确认写回成功。");
            return receipt;
        }
        if (receipt.observed != replacement)
        {
            receipt.error = QStringLiteral("写入后回读不一致，不能确认写回成功，请重新读取。");
            return receipt;
        }
        if (!sameIdentity()) return receipt;
        receipt.success = true;
        return receipt;
    }
}
