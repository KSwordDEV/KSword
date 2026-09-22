#include "IntegrityRiskPresentation.h"

#include "../ArkDriverClient/ArkDriverTypes.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QBrush>
#include <QColor>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>

namespace
{
    // riskSeparator：多个风险位之间的统一分隔符（原四份实现里有三份用它，Descriptor 页原先用 " / "）。
    const QString& riskSeparator()
    {
        static const QString separator = QStringLiteral(" | ");
        return separator;
    }

    // kDangerMask：分级为 Danger 的风险位集合。
    // - 这些位要么是“被改了”的直接证据（OWNER_MISMATCH / OUTSIDE_DRIVER_IMAGE / TARGET_NON_EXEC / PROC_DETOUR /
    //   IDT 三个基线位 / DESCRIPTOR_INVALID / 三个环与跨驱动挂接），要么是隐藏行为总标志（HIDDEN_HOOK）；
    // - 其余位（不可用、查询失败、模块未解析、CPU 保护位关闭、截断等）只是需要人看一眼，归 Notice。
    constexpr quint32 kDangerMask =
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_BASELINE_CHANGED) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_DIVERGED) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_RELOCATED) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH) |
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_PROC_DETOUR);

    constexpr quint32 kHiddenHookBit =
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK);
    constexpr quint32 kLayoutUnverifiedBit =
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_LAYOUT_UNVERIFIED);

    // kOrdinaryRiskBits：除 HIDDEN_HOOK 之外的全部已知位，按位值升序，也是风险文字里的出现顺序。
    // HIDDEN_HOOK 不在此表：它要排在文字最前面，由 riskText 单独处理。
    constexpr quint32 kOrdinaryRiskBits[] = {
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_BASELINE_CHANGED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_DIVERGED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_RELOCATED),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_OBJTYPE_PROC_NON_CORE),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_PROC_DETOUR),
        static_cast<quint32>(KSWORD_ARK_DRIVER_INTEGRITY_RISK_LAYOUT_UNVERIFIED)
    };

    // riskLabel：
    // - 输入：单个风险位；
    // - 处理：查该位的界面文字（键沿用原 DriverDock / KernelDescriptorTableTab 已有的词条，
    //   四个 IDT 位沿用 kernel.descriptor.risk.*，其余沿用 driver.integrity.risk.*）；
    // - 返回：文字；不是已知位时返回空串，由调用方走十六进制兜底。
    QString riskLabel(const quint32 riskBit)
    {
        switch (riskBit)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_HIDDEN_HOOK:
            return ks::i18n::contextText(
                QStringLiteral("driver.integrity.risk.hidden_hook"),
                QStringLiteral("存在隐藏行为：二级指针被劫持"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_UNAVAILABLE:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.unavailable"), QStringLiteral("不可用"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_QUERY_FAILED:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.query_failed"), QStringLiteral("查询失败"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_MODULE_UNRESOLVED:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.module_unresolved"), QStringLiteral("模块未解析"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_OWNER_MISMATCH:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.owner_mismatch"), QStringLiteral("Owner不匹配"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_OUTSIDE_DRIVER_IMAGE:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.outside_image"), QStringLiteral("外跳"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_SECTION_MISMATCH:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.section_mismatch"), QStringLiteral("Section不匹配"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_SERVICE_MISSING:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.service_missing"), QStringLiteral("服务缺失"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_EMPTY_UNLOAD:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.empty_unload"), QStringLiteral("Unload为空"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_DEVICE_LOOP:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.device_loop"), QStringLiteral("Device环"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_ATTACHED_LOOP:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.attached_loop"), QStringLiteral("Attached环"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_CROSS_DRIVER_ATTACH:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.cross_driver_attach"), QStringLiteral("跨驱动挂接"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_NULL_POINTER:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.null_pointer"), QStringLiteral("空指针"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_NON_CORE_OWNER:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.idt_external_owner"), QStringLiteral("IDT外部Owner"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_WP_DISABLED:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.wp_disabled"), QStringLiteral("WP关闭"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_NXE_DISABLED:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.nxe_disabled"), QStringLiteral("NXE关闭"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMEP_DISABLED:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.smep_disabled"), QStringLiteral("SMEP关闭"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_CPU_SMAP_DISABLED:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.smap_disabled"), QStringLiteral("SMAP关闭"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_DESCRIPTOR_INVALID:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.descriptor_invalid"), QStringLiteral("描述符异常"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_DYNDATA_UNAVAILABLE:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.dyndata_unavailable"), QStringLiteral("DynData缺失"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_TRUNCATED:
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.truncated"), QStringLiteral("截断"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_BASELINE_CHANGED:
            return ks::i18n::contextText(QStringLiteral("kernel.descriptor.risk.baseline_changed"), QStringLiteral("偏离启动期基线"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_DIVERGED:
            return ks::i18n::contextText(QStringLiteral("kernel.descriptor.risk.table_diverged"), QStringLiteral("IDT 表与多数 CPU 不一致"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_IDT_TABLE_RELOCATED:
            return ks::i18n::contextText(QStringLiteral("kernel.descriptor.risk.table_relocated"), QStringLiteral("IDT 表被重定位"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_TARGET_NON_EXEC:
            return ks::i18n::contextText(QStringLiteral("kernel.descriptor.risk.target_non_exec"), QStringLiteral("目标不在可执行节"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_OBJTYPE_PROC_NON_CORE:
            return ks::i18n::contextText(
                QStringLiteral("driver.integrity.risk.objtype_proc_non_core"),
                QStringLiteral("核心对象类型的方法指针落在 ntoskrnl 之外"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_PROC_DETOUR:
            return ks::i18n::contextText(
                QStringLiteral("driver.integrity.risk.proc_detour"),
                QStringLiteral("函数入口是跳板（内联绕行）"));
        case KSWORD_ARK_DRIVER_INTEGRITY_RISK_LAYOUT_UNVERIFIED:
            return ks::i18n::contextText(
                QStringLiteral("driver.integrity.risk.layout_unverified"),
                QStringLiteral("结构布局未验证（本机无法做此项检查）"));
        default:
            return QString();
        }
    }

    // knownRiskMask：全部已知风险位的并集，用来找出“未识别的残余位”。
    quint32 knownRiskMask()
    {
        quint32 mask = kHiddenHookBit;
        for (const quint32 riskBit : kOrdinaryRiskBits)
        {
            mask |= riskBit;
        }
        return mask;
    }

    // hex32Text：残余位的十六进制兜底文字，固定 8 位、数字部分大写，前缀保持小写 0x。
    QString hex32Text(const quint32 value)
    {
        return QStringLiteral("0x")
            + QString::number(value, 16).rightJustified(8, QLatin1Char('0')).toUpper();
    }
}

namespace ks::ui::integrity
{
    QString classText(const quint32 evidenceClass)
    {
        // 输入：KSWORD_ARK_DRIVER_INTEGRITY_CLASS_*。
        // 处理：映射为各页统一的证据类名称（与 DriverDock 既有写法一致，都是不需要翻译的标识名）。
        // 返回：类名称；未知类回退成 Class(N)。
        switch (evidenceClass)
        {
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MODULE_VIEW: return QStringLiteral("ModuleView");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_PS_LOADED_MODULES: return QStringLiteral("PsLoadedModules");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_OBJECT: return QStringLiteral("DriverObject");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DRIVER_SECTION: return QStringLiteral("DriverSection");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MAJOR_FUNCTION: return QStringLiteral("MajorFunction");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_FAST_IO: return QStringLiteral("FastIo");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_START_IO: return QStringLiteral("StartIo");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DEVICE_CHAIN: return QStringLiteral("DeviceChain");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_SERVICE: return QStringLiteral("Service");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_CPU_CONTROL: return QStringLiteral("CPU");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_DESCRIPTOR_TABLE: return QStringLiteral("Descriptor");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_MSR_ENTRY: return QStringLiteral("MSR");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_IDT_HANDLER: return QStringLiteral("IDT");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_OPTIONAL_GLOBAL: return QStringLiteral("OptionalGlobal");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_GDT_DESCRIPTOR: return QStringLiteral("GDT");
        case KSWORD_ARK_DRIVER_INTEGRITY_CLASS_INTERRUPT_OBJECT: return QStringLiteral("InterruptObject");
        default: return QStringLiteral("Class(%1)").arg(evidenceClass);
        }
    }

    QString riskText(const quint32 riskFlags)
    {
        // 输入：KSWORD_ARK_DRIVER_INTEGRITY_RISK_* 位集合。
        // 处理：HIDDEN_HOOK 永远排在最前面（“存在隐藏行为”开头），其余已知位按位值升序，
        //       未识别的残余位以十六进制追加在最后，保证“有位但文字为空”的情况不会再出现。
        // 返回：无风险返回“正常”。
        if (riskFlags == 0U)
        {
            return ks::i18n::contextText(QStringLiteral("driver.integrity.risk.normal"), QStringLiteral("正常"));
        }

        QStringList parts;
        if ((riskFlags & kHiddenHookBit) != 0U)
        {
            parts.push_back(riskLabel(kHiddenHookBit));
        }
        for (const quint32 riskBit : kOrdinaryRiskBits)
        {
            if ((riskFlags & riskBit) != 0U)
            {
                parts.push_back(riskLabel(riskBit));
            }
        }
        const quint32 residualBits = riskFlags & ~knownRiskMask();
        if (residualBits != 0U)
        {
            parts.push_back(hex32Text(residualBits));
        }
        return parts.join(riskSeparator());
    }

    Tier tierOf(const quint32 riskFlags)
    {
        // 输入：风险位集合。
        // 处理：0 为 Clean；含 Danger 位为 Danger；只带 LAYOUT_UNVERIFIED 的行是“这一项检查在本机做不了”，
        //       不是异常，归 Clean（文字仍由 riskText 写出来）；其余非零为 Notice。
        // 返回：分级。
        if (riskFlags == 0U)
        {
            return Tier::Clean;
        }
        if ((riskFlags & kDangerMask) != 0U)
        {
            return Tier::Danger;
        }
        if ((riskFlags & ~kLayoutUnverifiedBit) == 0U)
        {
            return Tier::Clean;
        }
        return Tier::Notice;
    }

    void applyRowHighlight(
        QTableWidget* const table,
        const int row,
        const Tier tier,
        const QString& detailText)
    {
        // 输入：表格、行号、分级和 tooltip 文字。
        // 处理：Danger/Notice 对整行每个单元格设前景色+底色；Clean 清回 QBrush()，
        //       这样行被复用或表格被重建时不会残留旧颜色，交替行底色也能透出来。
        //       颜色走绘制路径令牌（QColor），换主题后由调用方重建表格即可刷新。
        // 返回：无。
        if (table == nullptr || row < 0 || row >= table->rowCount())
        {
            return;
        }

        QBrush foregroundBrush;
        QBrush backgroundBrush;
        switch (tier)
        {
        case Tier::Danger:
            foregroundBrush = QBrush(KswordTheme::ErrorColor());
            backgroundBrush = QBrush(KswordTheme::WithAlpha(
                KswordTheme::ErrorBackgroundColor(),
                KswordTheme::IsDarkModeEnabled() ? 140 : 255));
            break;
        case Tier::Notice:
            foregroundBrush = QBrush(KswordTheme::WarningColor());
            backgroundBrush = QBrush(KswordTheme::WithAlpha(
                KswordTheme::WarningBackgroundColor(),
                KswordTheme::IsDarkModeEnabled() ? 110 : 255));
            break;
        case Tier::Clean:
        default:
            break;
        }

        for (int column = 0; column < table->columnCount(); ++column)
        {
            QTableWidgetItem* const item = table->item(row, column);
            if (item == nullptr)
            {
                continue;
            }
            // 值没变就不写：绝大多数行是 Clean 且单元格是新建的，逐格写三次空值会白白触发大量 dataChanged；
            // 而复用行上残留的旧颜色/旧 tooltip 与目标值不等，仍会被清掉。
            if (item->foreground() != foregroundBrush)
            {
                item->setForeground(foregroundBrush);
            }
            if (item->background() != backgroundBrush)
            {
                item->setBackground(backgroundBrush);
            }
            if (item->toolTip() != detailText)
            {
                item->setToolTip(detailText);
            }
        }
    }

    QString tooltipText(const quint32 riskFlags)
    {
        // 输入：风险位集合。
        // 处理：基础内容是 riskText；带 HIDDEN_HOOK 时追加一句解释，让用户明白为什么这一项值得警惕。
        // 返回：tooltip 文字。
        QString text = riskText(riskFlags);
        if ((riskFlags & kHiddenHookBit) != 0U)
        {
            text += QStringLiteral("\n")
                + ks::i18n::contextText(
                    QStringLiteral("driver.integrity.tooltip.hidden_hook"),
                    QStringLiteral("一级地址（IDT 网关 / 对象类型地址）看起来是干净的，但沿它走到的二级指针被改到了别处，只核对一级地址的检测会漏掉这一项。"));
        }
        return text;
    }

    void applyRiskRowHighlight(QTableWidget* const table, const int row, const quint32 riskFlags)
    {
        // 输入：表格、行号和该行的风险位。
        // 处理：分级、tooltip 都由风险位推出，再交给 applyRowHighlight；
        //       风险位为 0 的行不挂“正常”tooltip（每格都弹一句“正常”只是噪音）。
        // 返回：无。
        applyRowHighlight(
            table,
            row,
            tierOf(riskFlags),
            riskFlags == 0U ? QString() : tooltipText(riskFlags));
    }
}
