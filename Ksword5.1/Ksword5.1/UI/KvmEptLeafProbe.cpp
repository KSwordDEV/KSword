#include "KvmEptLeafProbe.h"

#include "KvmControl.h"

#include "../Internationalization/LanguageManager.h"

#include <QByteArray>

namespace ks::ui
{
    namespace
    {
        // EPT 项里的物理帧字段。低 12 位是权限/内存类型/AD 等，高位保留。
        constexpr quint64 kFrameMask = 0x000FFFFFFFFFF000ULL;
        // 大页帧掩码：PD 上是 2 MiB 对齐，PDPT 上是 1 GiB 对齐。
        constexpr quint64 kFrameMask2Mib = 0x000FFFFFFFE00000ULL;
        constexpr quint64 kFrameMask1Gib = 0x000FFFFFC0000000ULL;

        constexpr quint64 kAccessRead = 0x1ULL;
        constexpr quint64 kAccessWrite = 0x2ULL;
        constexpr quint64 kAccessExecute = 0x4ULL;
        constexpr quint64 kIgnorePat = 0x40ULL;
        constexpr quint64 kLargePage = 0x80ULL;
        constexpr quint64 kSuppressVe = 0x8000000000000000ULL;

        constexpr int kLevelCount = 4;
        // 四级 EPT 只翻译 48 位客户机物理地址，再高的位在走表里根本不参与
        // 索引。不拦下来的话，一个越界地址会被静默截断成另一页的读数 ——
        // 那正是这条判据最不能出的错。
        constexpr quint64 kAddressLimit = 0x0001000000000000ULL;

        // levelIndex：第 level 级在表内的槽位下标。
        // PML4 取 47..39，PDPT 取 38..30，PD 取 29..21，PT 取 20..12。
        quint32 levelIndex(const quint64 address, const int level)
        {
            const int shift = 39 - (level * 9);
            return static_cast<quint32>((address >> shift) & 0x1FFULL);
        }

        // decodeLittleEndian：把驱动回来的 8 字节拼成项值。
        // 驱动按物理内存原样回传，x86 是小端，所以从高字节往回叠。
        quint64 decodeLittleEndian(const QByteArray& payload)
        {
            quint64 value = 0;
            for (int index = 7; index >= 0; --index)
            {
                value = (value << 8) |
                    static_cast<quint64>(
                        static_cast<unsigned char>(payload.at(index)));
            }
            return value;
        }

        // fillAccessBits：把权限三位与叶项的附属字段摊到记录上。
        void fillAccessBits(EptLeafEntryRecord& record)
        {
            record.readable = (record.entry & kAccessRead) != 0ULL;
            record.writable = (record.entry & kAccessWrite) != 0ULL;
            record.executable = (record.entry & kAccessExecute) != 0ULL;
        }
    }

    QString eptLeafLevelName(const int level)
    {
        switch (level)
        {
        case 0:
            return QStringLiteral("PML4");
        case 1:
            return QStringLiteral("PDPT");
        case 2:
            return QStringLiteral("PD");
        case 3:
            return QStringLiteral("PT");
        default:
            break;
        }
        return QStringLiteral("?");
    }

    EptLeafProbeResult readBaseEptLeaf(const quint64 targetGpa)
    {
        EptLeafProbeResult result;
        result.targetGpa = targetGpa;
        result.pageBaseGpa = targetGpa & kFrameMask;

        if (targetGpa >= kAddressLimit)
        {
            result.message = ks::i18n::sourceText(QStringLiteral("目标地址超出四级 EPT 能翻译的 48 位客户机物理地址范围，走表会静默落到另一页上，因此直接拒绝。"));
            return result;
        }

        // 根地址与两个盲区标注都来自同一次快照，避免两次查询之间后端被换掉。
        const auto state = ksword::kvm::queryState();
        result.eptPointer = state.eptPointer;
        result.localEptArmed = state.localEptArmed;
        result.eptpSwitchArmed = state.eptpSwitchArmed;

        if (state.eptPointer == 0ULL)
        {
            // 没有根就没有表可走。但"为什么没有根"分成两类，用户要做的事完全
            // 不同：机器根本不具备条件（换机器/改固件/关 VBS），还是只差一次
            // 准备。合成一句"读不到"会把人送去查错的地方。
            switch (state.availability)
            {
            case ksword::kvm::KvmAvailability::DriverNotRunning:
            case ksword::kvm::KvmAvailability::UnsupportedCpu:
            case ksword::kvm::KvmAvailability::FirmwareDisabled:
            case ksword::kvm::KvmAvailability::HypervisorConflict:
            case ksword::kvm::KvmAvailability::BackendNotImplemented:
            case ksword::kvm::KvmAvailability::NestedNotAllowed:
            case ksword::kvm::KvmAvailability::Faulted:
                result.message = ksword::kvm::describeAvailability(
                    state.availability);
                break;
            case ksword::kvm::KvmAvailability::Available:
            case ksword::kvm::KvmAvailability::NotPrepared:
            default:
                result.message = state.resourcesReady
                    ? ks::i18n::sourceText(QStringLiteral("驱动已准备资源但尚未建立 EPT 层次（eptPointer 为零），没有可以走的表。"))
                    : ks::i18n::sourceText(QStringLiteral("驱动尚未准备资源（eptPointer 为零），没有可以走的表。先准备资源再回读。"));
                break;
            }
            return result;
        }

        // 只取根地址：低 12 位是内存类型、页走表层数与 AD 使能，不是物理位。
        result.eptRoot = state.eptPointer & kFrameMask;

        quint64 tableBase = result.eptRoot;
        for (int level = 0; level < kLevelCount; ++level)
        {
            EptLeafEntryRecord& record = result.levels[level];
            record.index = levelIndex(result.pageBaseGpa, level);
            record.tableBase = tableBase;
            record.entryAddress =
                tableBase + (static_cast<quint64>(record.index) * 8ULL);
            result.walkedLevels = level + 1;

            const auto memory = ksword::kvm::readPhysical(
                record.entryAddress,
                8UL);
            if (!memory.ok || memory.data.size() < 8)
            {
                record.failure = memory.message.isEmpty()
                    ? ks::i18n::sourceText(QStringLiteral("读取该页表项失败。"))
                    : memory.message;
                result.message = ks::i18n::sourceText(QStringLiteral("走到 %1 级时读取页表项失败：%2"))
                    .arg(eptLeafLevelName(level))
                    .arg(record.failure);
                return result;
            }

            record.read = true;
            record.entry = decodeLittleEndian(memory.data);
            fillAccessBits(record);
            record.largePage = level >= 1 && level <= 2 &&
                (record.entry & kLargePage) != 0ULL;

            // 项为零表示这一级没有映射，再往下走读到的是别的东西。
            if (record.entry == 0ULL)
            {
                result.ok = true;
                result.unmapped = true;
                result.message = ks::i18n::sourceText(QStringLiteral("这一页在基座 EPT 层次里没有映射：%1 级的项为零，走表到此为止。"))
                    .arg(eptLeafLevelName(level));
                return result;
            }

            // 大页在 PDPT / PD 上以 bit7 标记，命中就说明这一级已经是叶。
            if (record.largePage)
            {
                result.ok = true;
                result.reachedLeaf = true;
                result.largePage = true;
                result.leafLevel = level;
                result.leafEntry = record.entry;
                result.leafFrameAddress = record.entry &
                    (level == 1 ? kFrameMask1Gib : kFrameMask2Mib);
                break;
            }

            if (level == kLevelCount - 1)
            {
                result.ok = true;
                result.reachedLeaf = true;
                result.leafLevel = level;
                result.leafEntry = record.entry;
                result.leafFrameAddress = record.entry & kFrameMask;
                break;
            }

            tableBase = record.entry & kFrameMask;
        }

        if (!result.reachedLeaf)
        {
            // 走满四级却没认定叶，说明上面的分支漏了一种形状。宁可明说也不要
            // 让调用方拿一个默认全零的结论去判断"这一页没权限"。
            result.message = ks::i18n::sourceText(QStringLiteral("走满四级仍未认定叶项，读回的层次形状超出本探针的预期。"));
            result.ok = false;
            return result;
        }

        result.readable = (result.leafEntry & kAccessRead) != 0ULL;
        result.writable = (result.leafEntry & kAccessWrite) != 0ULL;
        result.executable = (result.leafEntry & kAccessExecute) != 0ULL;
        result.memoryType =
            static_cast<quint32>((result.leafEntry >> 3) & 0x7ULL);
        result.ignorePat = (result.leafEntry & kIgnorePat) != 0ULL;
        result.suppressVe = (result.leafEntry & kSuppressVe) != 0ULL;

        result.message = result.largePage
            ? ks::i18n::sourceText(QStringLiteral("叶落在 %1 级的大页上：这一项管的是整段范围而不止目标这一页。"))
                .arg(eptLeafLevelName(result.leafLevel))
            : ks::i18n::sourceText(QStringLiteral("已读回基座 EPT 层次里这一页的叶项。"));
        return result;
    }
}
