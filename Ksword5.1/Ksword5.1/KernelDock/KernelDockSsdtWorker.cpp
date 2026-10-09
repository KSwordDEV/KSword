#include "KernelDockSsdtWorker.h"

#include "KernelCleanImageBaseline.h"
#include "../ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cstdint>
#include <vector>
#include <utility>

#include <QStringList>

namespace
{
    QString formatAddressHex(const std::uint64_t addressValue)
    {
        return QStringLiteral("0x%1")
            .arg(addressValue, 16, 16, QChar('0'))
            .toUpper();
    }

    std::vector<std::uint8_t> littleEndianBytes(
        const std::uint64_t value,
        const std::uint32_t byteCount)
    {
        std::vector<std::uint8_t> bytes;
        bytes.reserve(byteCount);
        for (std::uint32_t index = 0; index < byteCount; ++index)
        {
            bytes.push_back(static_cast<std::uint8_t>(
                (value >> (index * 8U)) & 0xFFU));
        }
        return bytes;
    }

    std::uint64_t littleEndianValue(
        const std::vector<std::uint8_t>& bytes)
    {
        std::uint64_t value = 0U;
        const std::size_t count = std::min<std::size_t>(
            bytes.size(),
            sizeof(value));
        for (std::size_t index = 0; index < count; ++index)
        {
            value |= static_cast<std::uint64_t>(bytes[index])
                << (index * 8U);
        }
        return value;
    }

    QString byteText(const std::vector<std::uint8_t>& bytes)
    {
        QStringList parts;
        parts.reserve(static_cast<int>(bytes.size()));
        for (const std::uint8_t byte : bytes)
        {
            parts.push_back(QStringLiteral("%1")
                .arg(byte, 2, 16, QChar('0')).toUpper());
        }
        return parts.join(QLatin1Char(' '));
    }

    // ssdtWorkerIoMessageText：
    // - 输入：ArkDriverClient::enumerateSsdt 返回的原始 message；
    // - 处理：将 DeviceIoControl/unsupported/DynData/buffer 等底层日志转换成人读说明；
    // - 返回：用于 SSDT 页错误提示的中文短文本。
    QString ssdtWorkerIoMessageText(const QString& rawMessageText)
    {
        const QString trimmedText = rawMessageText.trimmed();
        if (trimmedText.isEmpty())
        {
            return QStringLiteral("驱动未返回额外说明。");
        }

        const QString lowerText = trimmedText.toLower();
        if (lowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。");
        }
        if (lowerText.contains(QStringLiteral("unsupported")) ||
            lowerText.contains(QStringLiteral("not supported")) ||
            lowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return QStringLiteral("当前驱动暂不支持 SSDT 枚举接口。");
        }
        if (lowerText.contains(QStringLiteral("dyndata")) ||
            lowerText.contains(QStringLiteral("capability")))
        {
            return QStringLiteral("动态偏移能力未满足，SSDT 表地址或解析字段暂不可用。");
        }
        if (lowerText.contains(QStringLiteral("buffer")) &&
            (lowerText.contains(QStringLiteral("small")) || lowerText.contains(QStringLiteral("trunc"))))
        {
            return QStringLiteral("驱动返回缓冲区不足，SSDT 结果可能被截断。");
        }
        return trimmedText;
    }
}

bool runSsdtSnapshotTask(std::vector<KernelSsdtEntry>& rowsOut, QString& errorTextOut)
{
    rowsOut.clear();
    errorTextOut.clear();

    // KernelDock only asks ArkDriverClient for the R0 SSDT snapshot. The worker
    // still owns UI row shaping, sorting, and localized error text.
    const ksword::ark::DriverClient driverClient;
    const ksword::ark::SsdtEnumResult enumResult = driverClient.enumerateSsdt(
        KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);
    if (!enumResult.io.ok)
    {
        errorTextOut = QStringLiteral("查询 SSDT 失败，error=%1，detail=%2")
            .arg(enumResult.io.win32Error)
            .arg(ssdtWorkerIoMessageText(QString::fromStdString(enumResult.io.message)));
        return false;
    }

    std::uint32_t tableEntrySize = 0U;
    for (const ksword::ark::SsdtEntry& entry : enumResult.entries)
    {
        if (entry.tableEntrySize != 0U && entry.tableEntrySize <= sizeof(std::uint64_t))
        {
            tableEntrySize = entry.tableEntrySize;
            break;
        }
    }
    ks::kernel::CleanImageBaselineResult tableBaseline;
    if (enumResult.serviceTableBase != 0U
        && enumResult.serviceCountFromTable != 0U
        && tableEntrySize != 0U
        && static_cast<std::uint64_t>(enumResult.serviceCountFromTable)
            * tableEntrySize <= 64U * 1024U)
    {
        tableBaseline =
            ks::kernel::KernelCleanImageBaseline::compareAddress(
                enumResult.serviceTableBase,
                enumResult.serviceCountFromTable * tableEntrySize);
    }

    rowsOut.reserve(enumResult.entries.size());
    for (const ksword::ark::SsdtEntry& sourceEntry : enumResult.entries)
    {
        KernelSsdtEntry row{};
        row.serviceIndex = static_cast<std::uint32_t>(sourceEntry.serviceIndex);
        row.flags = static_cast<std::uint32_t>(sourceEntry.flags);
        row.zwRoutineAddress = static_cast<std::uint64_t>(sourceEntry.zwRoutineAddress);
        row.serviceRoutineAddress = static_cast<std::uint64_t>(sourceEntry.serviceRoutineAddress);
        row.serviceTableBase = static_cast<std::uint64_t>(enumResult.serviceTableBase);
        row.tableEntryAddress =
            static_cast<std::uint64_t>(sourceEntry.tableEntryAddress);
        row.currentTableValue =
            static_cast<std::uint64_t>(sourceEntry.currentTableValue);
        row.tableEntrySize =
            static_cast<std::uint32_t>(sourceEntry.tableEntrySize);
        row.currentTableBytes = littleEndianBytes(
            row.currentTableValue,
            row.tableEntrySize);
        row.cleanBaselineStatus = tableBaseline.statusText;
        row.cleanBaselinePath = tableBaseline.imagePath;
        if (tableBaseline.available
            && row.tableEntryAddress >= enumResult.serviceTableBase)
        {
            const std::uint64_t byteOffset =
                row.tableEntryAddress - enumResult.serviceTableBase;
            if (byteOffset <= tableBaseline.cleanBytes.size()
                && row.tableEntrySize
                    <= tableBaseline.cleanBytes.size() - byteOffset)
            {
                const auto first =
                    tableBaseline.cleanBytes.cbegin()
                    + static_cast<std::ptrdiff_t>(byteOffset);
                row.cleanTableBytes.assign(
                    first,
                    first + row.tableEntrySize);
                row.cleanTableValue =
                    littleEndianValue(row.cleanTableBytes);
                row.cleanBaselineAvailable = true;
                row.cleanBaselineDiffers =
                    row.cleanTableBytes != row.currentTableBytes;
                row.cleanBaselineStatus = row.cleanBaselineDiffers
                    ? QStringLiteral("当前编码槽值与已验证磁盘映像不同")
                    : QStringLiteral("当前编码槽值与已验证磁盘映像一致");
            }
        }
        row.serviceNameText = QString::fromLocal8Bit(sourceEntry.serviceName.data(), static_cast<int>(sourceEntry.serviceName.size()));
        row.moduleNameText = QString::fromLocal8Bit(sourceEntry.moduleName.data(), static_cast<int>(sourceEntry.moduleName.size()));
        row.indexResolved = (row.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED) != 0U;
        const bool tableAddressValid = (row.flags & KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID) != 0U;
        row.querySucceeded = true;

        QStringList statusParts;
        statusParts.push_back(row.indexResolved ? QStringLiteral("索引已解析") : QStringLiteral("索引未解析"));
        statusParts.push_back(tableAddressValid ? QStringLiteral("表项地址已解析") : QStringLiteral("表项地址不可用"));
        statusParts.push_back(row.cleanBaselineAvailable
            ? (row.cleanBaselineDiffers
                ? QStringLiteral("磁盘基线差异")
                : QStringLiteral("磁盘基线一致"))
            : QStringLiteral("磁盘基线不可用"));
        row.statusText = statusParts.join(QStringLiteral(" | "));

        row.detailDocument = {};
        row.detailDocument.field(QStringLiteral("协议版本"), QStringLiteral("%1").arg(enumResult.version));
        row.detailDocument.field(QStringLiteral("总条目"), QStringLiteral("%1").arg(enumResult.totalCount));
        row.detailDocument.field(QStringLiteral("返回条目"), QStringLiteral("%1").arg(enumResult.returnedCount));
        row.detailDocument.field(QStringLiteral("服务名称"), QStringLiteral("%1").arg(row.serviceNameText.isEmpty() ? QStringLiteral("<空>") : row.serviceNameText));
        row.detailDocument.field(QStringLiteral("模块名称"), QStringLiteral("%1").arg(row.moduleNameText.isEmpty() ? QStringLiteral("<空>") : row.moduleNameText));
        row.detailDocument.field(QStringLiteral("服务索引"), QStringLiteral("%1").arg(row.indexResolved ? QString::number(row.serviceIndex) : QStringLiteral("<未知>")));
        row.detailDocument.field(QStringLiteral("Zw导出地址"), QStringLiteral("%1").arg(formatAddressHex(row.zwRoutineAddress)));
        row.detailDocument.field(QStringLiteral("服务表基址"), QStringLiteral("%1").arg(formatAddressHex(row.serviceTableBase)));
        row.detailDocument.field(QStringLiteral("表项服务地址"), QStringLiteral("%1").arg(formatAddressHex(row.serviceRoutineAddress)));
        row.detailDocument.field(QStringLiteral("表项槽位地址"), QStringLiteral("%1").arg(formatAddressHex(row.tableEntryAddress)));
        row.detailDocument.field(QStringLiteral("当前编码槽值"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(row.currentTableValue),
                0,
                16)));
        row.detailDocument.field(QStringLiteral("磁盘基线槽值"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<qulonglong>(row.cleanTableValue),
                0,
                16)));
        row.detailDocument.field(QStringLiteral("当前槽字节"), QStringLiteral("%1").arg(byteText(row.currentTableBytes)));
        row.detailDocument.field(QStringLiteral("基线槽字节"), QStringLiteral("%1").arg(byteText(row.cleanTableBytes)));
        row.detailDocument.field(QStringLiteral("槽位宽度"), QStringLiteral("%1").arg(row.tableEntrySize));
        row.detailDocument.field(QStringLiteral("基线状态"), QStringLiteral("%1").arg(row.cleanBaselineStatus));
        row.detailDocument.field(QStringLiteral("基线映像"), QStringLiteral("%1").arg(row.cleanBaselinePath));
        row.detailDocument.field(QStringLiteral("驱动标志"), QStringLiteral("0x%1").arg(QStringLiteral("%1").arg(static_cast<unsigned int>(row.flags), 8, 16, QChar('0'))));

        rowsOut.push_back(std::move(row));
    }

    std::sort(rowsOut.begin(), rowsOut.end(), [](const KernelSsdtEntry& left, const KernelSsdtEntry& right) {
        if (left.indexResolved != right.indexResolved)
        {
            return left.indexResolved && !right.indexResolved;
        }
        if (left.serviceIndex != right.serviceIndex)
        {
            return left.serviceIndex < right.serviceIndex;
        }
        return QString::compare(left.serviceNameText, right.serviceNameText, Qt::CaseInsensitive) < 0;
    });

    return true;
}
