// WorkbenchSettings.cpp
// 作用：WorkbenchSettings.h 的实现——按 HexViewSettings.cpp 的写法逐键读写，
// 任何异常（状态错误、键缺失、类型不对）一律退回头文件注释里写明的默认值。

#include "WorkbenchSettings.h"

#include <QSettings>
#include <QVariant>

#include <initializer_list>

namespace ks::ui::workbench_settings
{
    namespace
    {
        // ChannelKeyForScope：三个范围各自的通道键；scopeValue 越界返回空串，
        // 调用方据此走默认值分支。0=进程、1=内核、2=物理，与 Scope 枚举数值一致。
        QString ChannelKeyForScope(const std::uint32_t scopeValue)
        {
            switch (scopeValue)
            {
            case 0: return QStringLiteral("memwb/workbench/channel/process");
            case 1: return QStringLiteral("memwb/workbench/channel/kernel");
            case 2: return QStringLiteral("memwb/workbench/channel/physical");
            default: return QString();
            }
        }

        // DefaultChannelForScope：读取失败或越界时的默认通道值——进程->R3(0)，内核/物理->R0(1)。
        std::uint32_t DefaultChannelForScope(const std::uint32_t scopeValue)
        {
            return scopeValue == 0U ? 0U : 1U;
        }

        // ReadUInt：按键读一个无符号整数，状态异常/键缺失/类型非法/超出
        // [0, maxValueInclusive] 都返回 fallback。
        // B6：原来的版本没有 maxValueInclusive 这个参数，读到任意合法 uint32（哪怕是
        // 7、99 这种枚举根本没有的值）都原样返回——头文件注释明明写着"一律退回
        // 默认"，实现却没做这件事。LoadScope/LoadWriteMode/LoadChannelForScope 都
        // 必须校验到各自的允许集合，不能只校验"能不能解析成数字"。
        std::uint32_t ReadUInt(const QString& key, const std::uint32_t fallback, const std::uint32_t maxValueInclusive)
        {
            const QSettings settings;
            if (settings.status() != QSettings::NoError || key.isEmpty())
            {
                return fallback;
            }
            const QVariant stored = settings.value(key);
            if (!stored.isValid())
            {
                return fallback;
            }
            bool ok = false;
            const std::uint32_t parsed = stored.toString().toUInt(&ok);
            if (!ok || parsed > maxValueInclusive)
            {
                return fallback;
            }
            return parsed;
        }

        // WriteUInt：写一个整数键，失败静默忽略。
        void WriteUInt(const QString& key, const std::uint32_t value)
        {
            if (key.isEmpty())
            {
                return;
            }
            QSettings settings;
            settings.setValue(key, value);
            settings.sync();
        }

        // ReadBool：按键读布尔值，解析规则与 HexViewSettings 一致（仅认 "true"/"1" 为真）。
        bool ReadBool(const QString& key, const bool fallback)
        {
            const QSettings settings;
            if (settings.status() != QSettings::NoError)
            {
                return fallback;
            }
            const QVariant stored = settings.value(key);
            if (!stored.isValid())
            {
                return fallback;
            }
            if (stored.typeId() == QMetaType::Bool)
            {
                return stored.toBool();
            }
            const QString text = stored.toString().trimmed().toLower();
            return text == QStringLiteral("true") || text == QStringLiteral("1");
        }

        // WriteBool：写布尔键，失败静默忽略。
        void WriteBool(const QString& key, const bool value)
        {
            QSettings settings;
            settings.setValue(key, value);
            settings.sync();
        }

        // ReadInt：按键读有符号整数，失败退回 fallback；min/max 给合法区间，越界也退回 fallback。
        int ReadInt(const QString& key, const int fallback, const int minValue, const int maxValue)
        {
            const QSettings settings;
            if (settings.status() != QSettings::NoError)
            {
                return fallback;
            }
            const QVariant stored = settings.value(key);
            if (!stored.isValid())
            {
                return fallback;
            }
            bool ok = false;
            const int parsed = stored.toString().toInt(&ok);
            if (!ok || parsed < minValue || parsed > maxValue)
            {
                return fallback;
            }
            return parsed;
        }

        // WriteInt：写整数键，失败静默忽略。
        void WriteInt(const QString& key, const int value)
        {
            QSettings settings;
            settings.setValue(key, value);
            settings.sync();
        }

        // ReadIntFromAllowedSet：按键读整数，只认 allowedValues 里枚举出的几个合法值
        // （而不是一段连续区间）。B6——bytesPerRow/groupSize 不是"1..256 之间任意值
        // 都行"，画布（HexCanvas.h::setBytesPerRow/setGroupSize）只接受
        // 8/16/32/48/64 与 1/2/4/8 这几个具体值，读到 7 或 3 这种区间内但不在允许
        // 集合里的值必须退回默认，不能原样交给画布（画布会拒绝，装配层却已经把
        // 这个非法值当成"当前设置"用了，两边状态就分叉了）。
        int ReadIntFromAllowedSet(
            const QString& key, const int fallback, const std::initializer_list<int> allowedValues)
        {
            const QSettings settings;
            if (settings.status() != QSettings::NoError)
            {
                return fallback;
            }
            const QVariant stored = settings.value(key);
            if (!stored.isValid())
            {
                return fallback;
            }
            bool ok = false;
            const int parsed = stored.toString().toInt(&ok);
            if (!ok)
            {
                return fallback;
            }
            for (const int allowed : allowedValues)
            {
                if (parsed == allowed)
                {
                    return parsed;
                }
            }
            return fallback;
        }

        // NormalizeStringList：去空白、去重（保留先出现者）、截断到上限，供地址历史/隐藏列共用。
        QStringList NormalizeStringList(const QStringList& values, const int limit)
        {
            QStringList cleaned;
            for (const QString& raw : values)
            {
                const QString entry = raw.trimmed();
                if (entry.isEmpty() || cleaned.contains(entry))
                {
                    continue;
                }
                cleaned.push_back(entry);
                if (limit > 0 && cleaned.size() >= limit)
                {
                    break;
                }
            }
            return cleaned;
        }

        // ReadStringList：按键读字符串列表，失败返回空列表；读到即按 limit 清理。
        QStringList ReadStringList(const QString& key, const int limit)
        {
            const QSettings settings;
            if (settings.status() != QSettings::NoError)
            {
                return QStringList();
            }
            const QVariant stored = settings.value(key);
            if (!stored.isValid())
            {
                return QStringList();
            }
            return NormalizeStringList(stored.toStringList(), limit);
        }

        // WriteStringList：清理后写入；空列表直接移除键（读回即"没有记录"）。
        void WriteStringList(const QString& key, const QStringList& values, const int limit)
        {
            QSettings settings;
            const QStringList cleaned = NormalizeStringList(values, limit);
            if (cleaned.isEmpty())
            {
                settings.remove(key);
            }
            else
            {
                settings.setValue(key, cleaned);
            }
            settings.sync();
        }
    }

    std::uint32_t LoadScope()
    {
        // B6：Scope 只有 0..2 三个合法值（进程/内核/物理），越界一律退回默认 0。
        return ReadUInt(QStringLiteral("memwb/workbench/scope"), 0U, 2U);
    }

    void SaveScope(const std::uint32_t scope)
    {
        WriteUInt(QStringLiteral("memwb/workbench/scope"), scope);
    }

    std::uint32_t LoadChannelForScope(const std::uint32_t scopeValue)
    {
        const QString key = ChannelKeyForScope(scopeValue);
        // S-f（第二轮审核可疑点，已核实保留原样）：审核报告指出 LoadChannelForScope
        // (1/2) 可能读出 R3(0)，R3 结构上不支持内核/物理范围。但本函数的既有契约
        // （见头文件注释）只负责"数字落在 0..2 合法区间"这一层校验，范围/通道的
        // 结构性兼容由调用方经 restoreChannelMemory → ChannelMemory::Restore 清洗
        // （S-f 原文本身也点明了这一点）。RunSettingsRoundTripTest 显式验证了
        // "物理范围存 0（R3），读回必须仍是 0"（与默认 R0 不同、也与内核键不同，
        // 用来确认三个范围分别存在独立的键，不会互相串）——如果这里再按
        // ChannelSupportsScope 清洗，这条已验证的往返会直接变成读回默认值 1，
        // 与规格矛盾。因此保留原样，不在这一层重复 Restore 已经做的清洗。
        // B6：合法通道值只有 0..2（R3/R0/HVM）。3（DDMA）故意也当越界处理——
        // ux.md 与 ChannelMemory::Restore 的规则一致："DDMA 永不作启动默认"，
        // 持久化读回同样不能把 DDMA 当成某个范围的默认通道。
        return ReadUInt(key, DefaultChannelForScope(scopeValue), 2U);
    }

    void SaveChannelForScope(const std::uint32_t scopeValue, const std::uint32_t channelValue)
    {
        const QString key = ChannelKeyForScope(scopeValue);
        WriteUInt(key, channelValue);
    }

    std::uint32_t LoadWriteMode()
    {
        // B6：WriteMode 只有 0（立即）/1（暂存后应用）两个合法值。
        return ReadUInt(QStringLiteral("memwb/workbench/writeMode"), 0U, 1U);
    }

    void SaveWriteMode(const std::uint32_t mode)
    {
        WriteUInt(QStringLiteral("memwb/workbench/writeMode"), mode);
    }

    QStringList LoadAddrHistory()
    {
        return ReadStringList(QStringLiteral("memwb/workbench/addrHistory"), kAddrHistoryLimit);
    }

    void SaveAddrHistory(const QStringList& history)
    {
        WriteStringList(QStringLiteral("memwb/workbench/addrHistory"), history, kAddrHistoryLimit);
    }

    QStringList PushAddrHistory(const QStringList& history, const QString& entry)
    {
        const QString trimmed = entry.trimmed();
        if (trimmed.isEmpty())
        {
            return NormalizeStringList(history, kAddrHistoryLimit);
        }
        QStringList merged;
        merged.push_back(trimmed);
        merged.append(history);
        return NormalizeStringList(merged, kAddrHistoryLimit);
    }

    bool LoadSidebarVisible()
    {
        return ReadBool(QStringLiteral("memwb/workbench/sidebarVisible"), false);
    }

    void SaveSidebarVisible(const bool visible)
    {
        WriteBool(QStringLiteral("memwb/workbench/sidebarVisible"), visible);
    }

    int LoadSidebarWidth()
    {
        // B6：下限从 1 改成 120——1px 宽的侧栏实际上等于"看不见也点不到"，不是一个
        // 有意义的侧栏宽度，读到这种历史遗留/损坏值时应该当成非法值退回默认。
        return ReadInt(QStringLiteral("memwb/workbench/sidebarWidth"), 300, 120, 100000);
    }

    void SaveSidebarWidth(const int width)
    {
        // S-g（第二轮审核可疑点，已核实保留原样）：Save 不做范围校验，只是原样
        // 写入；真正的下限校验只在 LoadSidebarWidth 侧生效——存入低于 120 的值，
        // 下次 Load 会退回默认 300，而不是把刚存的值收口到 120 再认。这与本文件
        // 头部注明的失败语义（"写失败静默忽略，下次读取自然退回默认"）以及
        // RunSettingsRoundTripTest（SaveSidebarWidth(119) 之后必须读回 300，不是
        // 120）的既有预期一致——Load 侧的区间校验就是这份设置唯一的合法性来源，
        // Save 不重复校验不是遗漏，是单一来源的设计；若改成 Save 侧收口会让
        // 119 读回 120，反而制造出一个新的、未被任何规格要求的"自动纠正"语义。
        WriteInt(QStringLiteral("memwb/workbench/sidebarWidth"), width);
    }

    int LoadSubTab()
    {
        return ReadInt(QStringLiteral("memwb/workbench/subTab"), 0, 0, 4);
    }

    void SaveSubTab(const int subTab)
    {
        WriteInt(QStringLiteral("memwb/workbench/subTab"), subTab);
    }

    int LoadBytesPerRow()
    {
        // B6：画布（HexCanvas.h::setBytesPerRow）只接受 8/16/32/48/64 这五个具体值，
        // 不是"1..256 区间内任意值"；读到 7 这类区间内但不合法的值，画布会拒绝，
        // 但装配层若直接把 LoadBytesPerRow() 的返回值当成"当前生效值"用，两边状态
        // 就分叉了，必须在这里就按允许集合校验。
        return ReadIntFromAllowedSet(QStringLiteral("memwb/workbench/bytesPerRow"), 16, {8, 16, 32, 48, 64});
    }

    void SaveBytesPerRow(const int bytesPerRow)
    {
        WriteInt(QStringLiteral("memwb/workbench/bytesPerRow"), bytesPerRow);
    }

    int LoadGroupSize()
    {
        // B6：画布（HexCanvas.h::setGroupSize）只接受 1/2/4/8。
        return ReadIntFromAllowedSet(QStringLiteral("memwb/workbench/groupSize"), 1, {1, 2, 4, 8});
    }

    void SaveGroupSize(const int groupSize)
    {
        WriteInt(QStringLiteral("memwb/workbench/groupSize"), groupSize);
    }

    bool LoadRowWidthAuto()
    {
        // 默认 true：内存工作台的十六进制页默认按窗口宽度自适应行宽（只在 loadSettings 路径里生效）。
        return ReadBool(QStringLiteral("memwb/workbench/rowWidthAuto"), true);
    }

    void SaveRowWidthAuto(const bool automatic)
    {
        WriteBool(QStringLiteral("memwb/workbench/rowWidthAuto"), automatic);
    }

    int LoadHexZoom()
    {
        // ReadInt 对越界值退回 fallback（0），与头文件承诺一致；区间取头文件里的两个常量，不另写字面量。
        return ReadInt(QStringLiteral("memwb/workbench/hexZoom"), 0, kHexZoomMin, kHexZoomMax);
    }

    void SaveHexZoom(const int level)
    {
        WriteInt(QStringLiteral("memwb/workbench/hexZoom"), level);
    }

    bool LoadLiveRefresh()
    {
        return ReadBool(QStringLiteral("memwb/workbench/liveRefresh"), false);
    }

    void SaveLiveRefresh(const bool enabled)
    {
        WriteBool(QStringLiteral("memwb/workbench/liveRefresh"), enabled);
    }

    int LoadLiveIntervalMs()
    {
        return ReadInt(QStringLiteral("memwb/workbench/liveIntervalMs"), 1000, 200, 60000);
    }

    void SaveLiveIntervalMs(const int intervalMs)
    {
        WriteInt(QStringLiteral("memwb/workbench/liveIntervalMs"), intervalMs);
    }

    int LoadAddrBookColumnGroup()
    {
        return ReadInt(QStringLiteral("memwb/workbench/addrBook/columnGroup"), 0, 0, 2);
    }

    void SaveAddrBookColumnGroup(const int columnGroup)
    {
        WriteInt(QStringLiteral("memwb/workbench/addrBook/columnGroup"), columnGroup);
    }

    QStringList LoadAddrBookHiddenColumns()
    {
        return ReadStringList(QStringLiteral("memwb/workbench/addrBook/hiddenColumns"), 0);
    }

    void SaveAddrBookHiddenColumns(const QStringList& hiddenColumns)
    {
        WriteStringList(QStringLiteral("memwb/workbench/addrBook/hiddenColumns"), hiddenColumns, 0);
    }

    int LoadAddrBookKind()
    {
        return ReadInt(QStringLiteral("memwb/workbench/addrBook/kind"), -1, -1, 2);
    }

    void SaveAddrBookKind(const int kind)
    {
        WriteInt(QStringLiteral("memwb/workbench/addrBook/kind"), kind);
    }

    bool LoadDiagExpanded()
    {
        return ReadBool(QStringLiteral("memwb/workbench/diagExpanded"), false);
    }

    void SaveDiagExpanded(const bool expanded)
    {
        WriteBool(QStringLiteral("memwb/workbench/diagExpanded"), expanded);
    }

    int LoadTextEncoding()
    {
        return ReadInt(QStringLiteral("memwb/workbench/text/encoding"), 0, 0, 8);
    }

    void SaveTextEncoding(const int encoding)
    {
        WriteInt(QStringLiteral("memwb/workbench/text/encoding"), encoding);
    }

}
