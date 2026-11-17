#include "../UI/StructuredFieldView.h"
#include "../UI/TableContextMenu.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "KernelDock.h"
#include "../UI/TableInteractionSupport.h"

#include <memory>
#include "../UI/VisibleTableWidget.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../ArkDriverClient/ArkLocalDynDataProfile.h"
#include "../UI/CodeEditorWidget.h"
#include "../ksword/profile/ProfileJsonLoader.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QByteArray>
#include <QClipboard>
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPixmap>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QStringList>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdint>
#include <limits>
#include <thread>
#include <unordered_map>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // DynDataColumn：
    // - 作用：定义动态偏移字段表列索引；
    // - 使用 enum class 避免魔法数字扩散到渲染与读取逻辑。
    enum class DynDataColumn : int
    {
        Field = 0,
        Offset,
        Status,
        Source,
        Feature,
        Capability,
        Count
    };

    // SummaryColumn：
    // - 作用：定义摘要表两列布局；
    // - Field/Value 模式便于添加 R0 诊断项。
    enum class SummaryColumn : int
    {
        Name = 0,
        Value,
        Count
    };

    // CapabilityDisplay：
    // - 作用：把 capability bit 与 UI 文案绑定；
    // - 处理逻辑：刷新摘要和字段详情时复用同一张表。
    struct CapabilityDisplay
    {
        std::uint64_t mask = 0;      // mask：KSW_CAP_* 单 bit。
        const char* name = nullptr;  // name：英文稳定名称。
        const wchar_t* title = nullptr; // title：中文功能说明。
        const char* contextKey = nullptr;
    };

    using ksword::ark::LocalPdbProfile;
    const auto findMatchingPdbProfile = [](const ksword::ark::ArkDynModuleIdentity& identity, QString& diagnostics) {
        return ksword::ark::findMatchingPdbProfile(identity, diagnostics, kernelText);
    };

    QString safeText(const QString& valueText, const QString& fallbackText);
    QString safeText(const QString& valueText);
    QString formatHex32(std::uint32_t value);
    QString formatHex64(std::uint64_t value);
    QString formatNtStatus(long statusValue);
    QString formatOffset(std::uint32_t offsetValue);
    QString boolText(bool enabled);
    QString moduleClassText(std::uint32_t classId);
    bool statusFlagEnabled(std::uint32_t flags, std::uint32_t flag);

    // v4CountText：
    // - 输入 returnedCount/totalCount：ArkDriverClient 从 R0 响应解析出的返回行数和总行数；
    // - 处理：统一压缩成“returned / total”文本，便于 profile 表格和详情复用；
    // - 返回：可直接展示的计数字符串。
    QString v4CountText(std::uint32_t returnedCount, std::uint32_t totalCount)
    {
        return QStringLiteral("%1 / %2")
            .arg(returnedCount)
            .arg(totalCount);
    }

    // v4IoStateText：
    // - 输入 queryOk/unsupported：ArkDriverClient wrapper 的 IO 成功状态和旧驱动兼容标记；
    // - 处理：把传输成功、旧驱动不支持和失败三类状态转成短文本；
    // - 返回：profile 摘要表使用的状态文本。
    QString v4IoStateText(bool queryOk, bool unsupported)
    {
        if (queryOk)
        {
            return kernelText("kernel.dyndata.v4.io.success", QStringLiteral("成功"));
        }

        return unsupported
            ? kernelText("kernel.dyndata.v4.io.unsupported", QStringLiteral("旧驱动不支持"))
            : kernelText("kernel.dyndata.v4.io.failure", QStringLiteral("失败"));
    }

    // appendV4StatusLine：
    // - 输入 lines/name/queryOk/unsupported/returnedCount/totalCount/messageText：单类 v4 查询状态；
    // - 处理：向详情文本追加 count、IO 状态和 ArkDriverClient message；
    // - 返回：无，lines 通过引用被追加。
    void appendV4StatusLine(
        QStringList& lines,
        const QString& name,
        bool queryOk,
        bool unsupported,
        std::uint32_t returnedCount,
        std::uint32_t totalCount,
        const QString& messageText)
    {
        lines << QStringLiteral("%1: count=%2, io=%3, message=%4")
            .arg(name)
            .arg(v4CountText(returnedCount, totalCount))
            .arg(v4IoStateText(queryOk, unsupported))
            .arg(safeText(messageText));
    }



    // v4ItemKindText：
    // - 输入 itemKind：R0 返回的 KSW_DYN_V4_ITEM_KIND_* 数值；
    // - 处理：转换为 schema 中的稳定英文类型名；
    // - 返回：表格可读文本，未知值保留数值便于排查协议版本差异。
    QString v4ItemKindText(const std::uint32_t itemKind)
    {
        switch (itemKind)
        {
        case KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET:
            return QStringLiteral("StructOffset");
        case KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA:
            return QStringLiteral("GlobalRva");
        case KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA:
            return QStringLiteral("FunctionRva");
        case KSW_DYN_V4_ITEM_KIND_ENUM_VALUE:
            return QStringLiteral("EnumValue");
        case KSW_DYN_V4_ITEM_KIND_TYPE_SIZE:
            return QStringLiteral("TypeSize");
        case KSW_DYN_V4_ITEM_KIND_BIT_FIELD:
            return QStringLiteral("BitField");
        case KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL:
            return QStringLiteral("ListHeadGlobal");
        default:
            return QStringLiteral("Unknown(%1)").arg(itemKind);
        }
    }

    // v4ItemFlagsText：
    // - 输入 flags：R0 返回的 v4 item flags；
    // - 处理：把 required/optional 位拆成人读文本，同时保留十六进制；
    // - 返回：表格“Flags”列文本。
    QString v4ItemFlagsText(const std::uint32_t flags)
    {
        QStringList parts;
        if ((flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U)
        {
            parts << QStringLiteral("required");
        }
        if ((flags & KSW_DYN_V4_ITEM_FLAG_OPTIONAL) != 0U)
        {
            parts << QStringLiteral("optional");
        }
        if (parts.isEmpty())
        {
            parts << QStringLiteral("none");
        }
        parts << formatHex32(flags);
        return parts.join(QStringLiteral(" / "));
    }

    // v4ItemValueText：
    // - 输入 item：R0 返回的完整 v4 item packet；
    // - 处理：合并 valueLow/valueHigh，并根据 item kind 添加偏移/RVA/大小语义；
    // - 返回：表格“值”列文本。
    QString v4ItemValueText(const KSW_DYN_V4_ITEM_PACKET& item)
    {
        const std::uint64_t value =
            (static_cast<std::uint64_t>(item.valueHigh) << 32U) |
            static_cast<std::uint64_t>(item.valueLow);
        const QString hexText = formatHex64(value);
        switch (item.itemKind)
        {
        case KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET:
            return QStringLiteral("offset %1").arg(hexText);
        case KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA:
        case KSW_DYN_V4_ITEM_KIND_FUNCTION_RVA:
        case KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL:
            return QStringLiteral("RVA %1").arg(hexText);
        case KSW_DYN_V4_ITEM_KIND_TYPE_SIZE:
            return QStringLiteral("size %1").arg(hexText);
        default:
            return hexText;
        }
    }

    // v4ItemMatchesFilter：
    // - 输入 entry/filterKeyword：v4 item 行和用户筛选文本；
    // - 处理：在模块、kind、id、group、value 和 aux 文本中做包含匹配；
    // - 返回：true 表示该行应该显示。
    bool v4ItemMatchesFilter(const KernelDynDataV4ItemEntry& entry, const QString& filterKeyword)
    {
        if (filterKeyword.isEmpty())
        {
            return true;
        }

        const QString haystack = QStringLiteral("%1 %2 %3 %4 %5 %6 %7")
            .arg(moduleClassText(entry.moduleClassId))
            .arg(entry.kindText)
            .arg(entry.itemId)
            .arg(entry.itemIndex)
            .arg(entry.capabilityGroupId)
            .arg(formatHex64(entry.value))
            .arg(entry.auxText);
        return haystack.contains(filterKeyword, Qt::CaseInsensitive);
    }





    // kCapabilities：
    // - 作用：枚举 Phase 0 暴露的全部 capability；
    // - 返回行为：由 helper 函数格式化为摘要、详情或缺失列表。
    constexpr std::array<CapabilityDisplay, 23> kCapabilities{ {
        { KSW_CAP_DYN_NTOS_ACTIVE, "KSW_CAP_DYN_NTOS_ACTIVE", L"ntoskrnl profile 已激活", "kernel.driver_status.capability.ntos_active" },
        { KSW_CAP_DYN_LXCORE_ACTIVE, "KSW_CAP_DYN_LXCORE_ACTIVE", L"lxcore profile 已激活", "kernel.driver_status.capability.lxcore_active" },
        { KSW_CAP_OBJECT_TYPE_FIELDS, "KSW_CAP_OBJECT_TYPE_FIELDS", L"对象类型字段", "kernel.driver_status.capability.object_type_fields" },
        { KSW_CAP_HANDLE_TABLE_DECODE, "KSW_CAP_HANDLE_TABLE_DECODE", L"句柄表解码", "kernel.driver_status.capability.handle_table_decode" },
        { KSW_CAP_PROCESS_OBJECT_TABLE, "KSW_CAP_PROCESS_OBJECT_TABLE", L"进程 ObjectTable", "kernel.driver_status.capability.process_object_table" },
        { KSW_CAP_THREAD_STACK_FIELDS, "KSW_CAP_THREAD_STACK_FIELDS", L"线程栈字段", "kernel.driver_status.capability.thread_stack_fields" },
        { KSW_CAP_THREAD_IO_COUNTERS, "KSW_CAP_THREAD_IO_COUNTERS", L"线程 I/O 计数", "kernel.driver_status.capability.thread_io_counters" },
        { KSW_CAP_ALPC_FIELDS, "KSW_CAP_ALPC_FIELDS", L"ALPC 字段", "kernel.driver_status.capability.alpc_fields" },
        { KSW_CAP_SECTION_CONTROL_AREA, "KSW_CAP_SECTION_CONTROL_AREA", L"Section/ControlArea", "kernel.driver_status.capability.section_control_area" },
        { KSW_CAP_PROCESS_PROTECTION_PATCH, "KSW_CAP_PROCESS_PROTECTION_PATCH", L"进程保护修改", "kernel.driver_status.capability.process_protection" },
        { KSW_CAP_WSL_LXCORE_FIELDS, "KSW_CAP_WSL_LXCORE_FIELDS", L"WSL/lxcore 字段", "kernel.driver_status.capability.wsl_lxcore_fields" },
        { KSW_CAP_ETW_GUID_FIELDS, "KSW_CAP_ETW_GUID_FIELDS", L"ETW GUID/Registration 字段", "kernel.driver_status.capability.etw_guid_fields" },
        { KSW_CAP_CALLBACK_NOTIFY_GLOBALS, "KSW_CAP_CALLBACK_NOTIFY_GLOBALS", L"Callback Notify 全局 RVA", "kernel.driver_status.capability.callback_notify_globals" },
        { KSW_CAP_CALLBACK_REGISTRY_GLOBALS, "KSW_CAP_CALLBACK_REGISTRY_GLOBALS", L"Registry Callback 全局 RVA", "kernel.driver_status.capability.callback_registry_globals" },
        { KSW_CAP_CALLBACK_OBJECT_FIELDS, "KSW_CAP_CALLBACK_OBJECT_FIELDS", L"Object Callback 结构偏移", "kernel.driver_status.capability.callback_object_fields" },
        { KSW_CAP_PROCESS_LIST_FIELDS, "KSW_CAP_PROCESS_LIST_FIELDS", L"进程链表字段", "kernel.driver_status.capability.process_list_fields" },
        { KSW_CAP_THREAD_LIST_FIELDS, "KSW_CAP_THREAD_LIST_FIELDS", L"线程链表字段", "kernel.driver_status.capability.thread_list_fields" },
        { KSW_CAP_CID_TABLE_WALK, "KSW_CAP_CID_TABLE_WALK", L"CID 表遍历", "kernel.driver_status.capability.cid_table_walk" },
        { KSW_CAP_KERNEL_MODULE_LIST_FIELDS, "KSW_CAP_KERNEL_MODULE_LIST_FIELDS", L"内核模块链表字段", "kernel.driver_status.capability.kernel_module_list_fields" },
        { KSW_CAP_DRIVER_OBJECT_FIELDS, "KSW_CAP_DRIVER_OBJECT_FIELDS", L"驱动对象字段", "kernel.driver_status.capability.driver_object_fields" },
        { KSW_CAP_KERNEL_GLOBALS, "KSW_CAP_KERNEL_GLOBALS", L"内核全局 RVA", "kernel.driver_status.capability.kernel_globals" },
        { KSW_CAP_TOKEN_INTEGRITY_FIELDS, "KSW_CAP_TOKEN_INTEGRITY_FIELDS", L"Token 完整性字段", "kernel.driver_status.capability.token_integrity_fields" },
        { KSW_CAP_TOKEN_PRIVATE_FIELDS, "KSW_CAP_TOKEN_PRIVATE_FIELDS", L"Token 私有字段", "kernel.driver_status.capability.token_private_fields" }
    } };

    // blueButtonStyle：
    // - 输入：无；
    // - 处理：读取全局主题按钮样式；
    // - 返回：可直接 setStyleSheet 的按钮样式文本。
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    // blueInputStyle：
    // - 输入：无；
    // - 处理：使用主题色拼接 QLineEdit 样式；
    // - 返回：筛选框样式文本。
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // headerStyle：
    // - 输入：无；
    // - 处理：使用主题色拼接表头样式；
    // - 返回：可直接应用到 QHeaderView 的样式文本。
    QString headerStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:%2;border:0;border-bottom:1px solid %3;font-weight:500;padding:4px 8px;}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::BorderHex());
    }

    // itemSelectionStyle：
    // - 输入：无；
    // - 处理：统一表格选中态颜色；
    // - 返回：表格 selection 样式文本。
    QString itemSelectionStyle()
    {
        return QString();
    }

    // copyMenuStyle：
    // - 输入：无；
    // - 处理：为 DynData 表格右键菜单提供不透明背景和明确选中态；
    // - 返回：可直接应用到 QMenu 的样式文本。
    QString copyMenuStyle()
    {
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;}"
            "QMenu::item{padding:5px 24px 5px 24px;background:transparent;}"
            "QMenu::item:selected{background:%4;color:palette(highlighted-text);}"
            "QMenu::item:disabled{color:%5;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::TextSecondaryHex());
    }

    // tableRowText：
    // - 输入 table/rowIndex：目标表格和源行号；
    // - 处理：读取每列当前文本并用 Tab 拼接；
    // - 返回：可复制到剪贴板的 TSV 行。
    QString tableRowText(QTableWidget* table, const int rowIndex)
    {
        if (table == nullptr || rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return QString();
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        return fields.join(QLatin1Char('\t'));
    }

    // installDynDataCopyMenu：
    // - 输入 table：DynData 摘要、字段或 profile 表；
    // - 处理：安装“复制当前行”右键菜单，兼容 NoSelection 摘要表；
    // - 返回：无，只读复制，不改变驱动状态。
    void installDynDataCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            const int rowIndex = clickedIndex.isValid() ? clickedIndex.row() : table->currentRow();
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(copyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                kernelText("kernel.driver_status.menu.copy_row", QStringLiteral("复制当前行")));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
            copyRowAction->setEnabled(rowIndex >= 0 && rowIndex < table->rowCount());
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(tableRowText(table, rowIndex));
                }
            }
        });
    }

    // statusLabelStyle：
    // - 输入 colorHex：目标文字颜色；
    // - 处理：拼接 QLabel 样式；
    // - 返回：加粗状态文本样式。
    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // safeText：
    // - 输入 valueText/fallbackText：待展示文本和兜底文本；
    // - 处理：去除首尾空白后判断是否为空；
    // - 返回：非空原文或兜底占位符。
    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.dyndata.placeholder.empty", QStringLiteral("<空>")));
    }

    // stringToQString：
    // - 输入 valueText：ArkDriverClient 返回的 UTF-8/ANSI 小字符串；
    // - 处理：按 UTF-8 转换，兼容 ASCII 字段名；
    // - 返回：Qt 展示字符串。
    QString stringToQString(const std::string& valueText)
    {
        return QString::fromUtf8(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    // friendlyDynDataIoMessage：
    // - 输入 valueText：DynData wrapper 的 io.message；
    // - 处理：把底层 IOCTL/unsupported/capability 文本转为可读说明；
    // - 返回：摘要表、profile 报告和详情区可以直接展示的文本。
    QString friendlyDynDataIoMessage(const std::string& valueText)
    {
        const QString rawText = stringToQString(valueText).trimmed();
        if (rawText.isEmpty())
        {
            return kernelText("kernel.dyndata.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.dyndata.message.communication_failure", QStringLiteral("驱动通信失败或当前驱动版本不支持该 DynData 查询入口。"));
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.dyndata.message.unsupported", QStringLiteral("当前驱动不支持该 DynData 协议版本。"));
        }
        if (rawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.dyndata.message.capability", QStringLiteral("DynData 能力未满足，相关运行时详情暂不可用。"));
        }
        return rawText;
    }

    // wideStringToQString：
    // - 输入 valueText：ArkDriverClient 返回的宽字符串；
    // - 处理：按 wchar_t 数组转换；
    // - 返回：Qt 展示字符串。
    QString wideStringToQString(const std::wstring& valueText)
    {
        return QString::fromWCharArray(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    // formatHex32：
    // - 输入 value：32 位数值；
    // - 处理：补零并使用大写十六进制；
    // - 返回：0xXXXXXXXX 格式文本。
    QString formatHex32(const std::uint32_t value)
    {
        return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper();
    }

    // formatHex64：
    // - 输入 value：64 位数值；
    // - 处理：补零并使用大写十六进制；
    // - 返回：0xXXXXXXXXXXXXXXXX 格式文本。
    QString formatHex64(const std::uint64_t value)
    {
        return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0')).toUpper();
    }

    // formatNtStatus：
    // - 输入 statusValue：NTSTATUS signed long；
    // - 处理：保留底层 32 bit 原样展示；
    // - 返回：0xXXXXXXXX 格式文本。
    QString formatNtStatus(const long statusValue)
    {
        return formatHex32(static_cast<std::uint32_t>(statusValue));
    }

    // formatOffset：
    // - 输入 offsetValue：字段偏移；
    // - 处理：识别 DynData 不可用哨兵；
    // - 返回：可读偏移文本或 <不可用>。
    QString formatOffset(const std::uint32_t offsetValue)
    {
        if (offsetValue == 0xFFFFFFFFU || offsetValue == 0x0000FFFFU)
        {
            return kernelText("kernel.dyndata.placeholder.unavailable", QStringLiteral("<不可用>"));
        }
        return QStringLiteral("0x%1").arg(offsetValue, 4, 16, QChar('0')).toUpper();
    }

    // fieldPresent：
    // - 输入 flags/offset：R0 字段 flags 和偏移值；
    // - 处理：同时检查 PRESENT bit 与不可用哨兵；
    // - 返回：true 表示字段可用。
    bool fieldPresent(const std::uint32_t flags, const std::uint32_t offset)
    {
        return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
            offset != 0xFFFFFFFFU &&
            offset != 0x0000FFFFU;
    }

    // statusFlagEnabled：
    // - 输入 flags/flag：状态位图和目标 bit；
    // - 处理：按位检测；
    // - 返回：true 表示目标状态启用。
    bool statusFlagEnabled(const std::uint32_t flags, const std::uint32_t flag)
    {
        return (flags & flag) == flag;
    }

    // boolText：
    // - 输入 enabled：布尔状态；
    // - 处理：转换为中文；
    // - 返回：“是”或“否”。
    QString boolText(const bool enabled)
    {
        return enabled
            ? kernelText("kernel.driver_status.value.yes", QStringLiteral("是"))
            : kernelText("kernel.driver_status.value.no", QStringLiteral("否"));
    }

    // moduleClassText：
    // - 输入 classId：KSW_DYN_PROFILE_CLASS_*；
    // - 处理：转换为 UI 可读文本；
    // - 返回：profile class 文案。
    QString moduleClassText(const std::uint32_t classId)
    {
        switch (classId)
        {
        case KSW_DYN_PROFILE_CLASS_NTOSKRNL:
            return QStringLiteral("ntoskrnl");
        case KSW_DYN_PROFILE_CLASS_NTKRLA57:
            return QStringLiteral("ntkrla57");
        case KSW_DYN_PROFILE_CLASS_LXCORE:
            return QStringLiteral("lxcore");
        case KSW_DYN_PROFILE_CLASS_FLTMGR:
            return QStringLiteral("fltmgr");
        case KSW_DYN_PROFILE_CLASS_CI:
            return QStringLiteral("ci");
        default:
            return QStringLiteral("unknown(%1)").arg(classId);
        }
    }

    // sourceText：
    // - 输入 source：KSW_DYN_FIELD_SOURCE_*；
    // - 处理：转换为 UI 可读文本；
    // - 返回：字段来源文案。
    QString sourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
            return QStringLiteral("System Informer");
        case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Ksword runtime pattern");
        case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
            return QStringLiteral("Ksword extra table");
        case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    // profileSourceDisplayText：
    // - 输入 sourceTextValue：LocalPdbProfile 记录的来源标识；
    // - 处理：把内部来源标识转换为 DynData 摘要页可读文本；
    // - 返回：PDB profile pack、scattered JSON 或兜底来源文本。
    QString profileSourceDisplayText(const QString& sourceTextValue)
    {
        if (sourceTextValue == QStringLiteral("pack"))
        {
            return QStringLiteral("PDB profile pack");
        }
        if (sourceTextValue == QStringLiteral("scattered-json"))
        {
            return QStringLiteral("PDB profile scattered JSON");
        }
        if (sourceTextValue == QStringLiteral("runtime-exact-pdb"))
        {
            return kernelText(
                "kernel.dyndata.profile.source.runtime_exact_pdb",
                QStringLiteral("运行时精确 PDB"));
        }
        return sourceTextValue.trimmed().isEmpty()
            ? kernelText("kernel.dyndata.placeholder.empty", QStringLiteral("<空>"))
            : sourceTextValue;
    }

    // capabilityNames：
    // - 输入 mask：能力位图；
    // - 处理：遍历能力表并拼接命中名称；
    // - 返回：逗号分隔名称；无命中返回 None。
    QString capabilityNames(const std::uint64_t mask)
    {
        QStringList names;
        for (const CapabilityDisplay& capability : kCapabilities)
        {
            if ((mask & capability.mask) == capability.mask)
            {
                names << QString::fromLatin1(capability.name);
            }
        }
        return names.isEmpty() ? QStringLiteral("None") : names.join(QStringLiteral(", "));
    }

    // capabilityReport：
    // - 输入 mask：能力位图；
    // - 处理：逐项列出启用/禁用；
    // - 返回：多行报告文本。
    ks::ui::FieldDocument capabilityReport(const std::uint64_t mask)
    {
        ks::ui::FieldDocument lines;
        for (const CapabilityDisplay& capability : kCapabilities)
        {
            const bool enabled = (mask & capability.mask) == capability.mask;
            lines.section(QStringLiteral("Capability"));
            lines.field(QStringLiteral("Name"), QString::fromLatin1(capability.name));
            lines.field(QStringLiteral("Enabled"), enabled ? QStringLiteral("[ON]") : QStringLiteral("[OFF]"));
            lines.field(QStringLiteral("说明"), kernelText(capability.contextKey, QString::fromWCharArray(capability.title)));
        }
        return lines;
    }

    // disabledCapabilitySummary：
    // - 输入 mask：能力位图；
    // - 处理：收集未启用能力中文名；
    // - 返回：缺失能力摘要。
    QString disabledCapabilitySummary(const std::uint64_t mask)
    {
        QStringList disabledItems;
        for (const CapabilityDisplay& capability : kCapabilities)
        {
            if ((mask & capability.mask) != capability.mask)
            {
                disabledItems << kernelText(capability.contextKey, QString::fromWCharArray(capability.title));
            }
        }
        return disabledItems.isEmpty()
            ? kernelText("kernel.dyndata.capability.none", QStringLiteral("无"))
            : disabledItems.join(QStringLiteral(", "));
    }

    // convertModuleIdentity：
    // - 输入 source：ArkDriverClient 模块身份；
    // - 处理：转换到 KernelDock 内部模型；
    // - 返回：KernelDynDataModuleIdentity 值对象。
    KernelDynDataModuleIdentity convertModuleIdentity(const ksword::ark::ArkDynModuleIdentity& source)
    {
        KernelDynDataModuleIdentity result{};
        result.present = source.present;
        result.classId = source.classId;
        result.machine = source.machine;
        result.timeDateStamp = source.timeDateStamp;
        result.sizeOfImage = source.sizeOfImage;
        result.imageBase = source.imageBase;
        result.moduleNameText = wideStringToQString(source.moduleName);
        return result;
    }

    // convertV4PacketIdentity：
    // - 输入 source：queryDynDataV4Modules 返回的共享模块身份包；
    // - 处理：按固定长度安全提取模块名，并转换为 profile 查找所需 R3 类型；
    // - 返回：ArkDynModuleIdentity 值对象。
    ksword::ark::ArkDynModuleIdentity convertV4PacketIdentity(
        const KSW_DYN_MODULE_IDENTITY_PACKET& source)
    {
        ksword::ark::ArkDynModuleIdentity result{};
        result.present = source.present != 0UL;
        result.classId = static_cast<std::uint32_t>(source.classId);
        result.machine = static_cast<std::uint32_t>(source.machine);
        result.timeDateStamp =
            static_cast<std::uint32_t>(source.timeDateStamp);
        result.sizeOfImage =
            static_cast<std::uint32_t>(source.sizeOfImage);
        result.imageBase = static_cast<std::uint64_t>(source.imageBase);
        std::size_t moduleNameLength = 0U;
        while (moduleNameLength < KSW_DYN_MODULE_NAME_CHARS &&
            source.moduleName[moduleNameLength] != L'\0')
        {
            ++moduleNameLength;
        }
        result.moduleName.assign(
            source.moduleName,
            source.moduleName + moduleNameLength);
        return result;
    }

    // moduleDetailText：
    // - 输入 title/source：模块标题和身份结构；
    // - 处理：格式化模块 identity；
    // - 返回：多行诊断文本。
    ks::ui::FieldDocument moduleDetailText(const QString& title, const KernelDynDataModuleIdentity& source)
    {
        if (!source.present)
        {
            { ks::ui::FieldDocument document;
        document.section(title);
        document.note(QStringLiteral("<未加载或未识别>"));
        return document; }
        }

        { ks::ui::FieldDocument document;
        document.section(title);
        document.field(QStringLiteral("ModuleName"), QStringLiteral("%1").arg(safeText(source.moduleNameText)));
        document.field(QStringLiteral("Class"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(moduleClassText(source.classId))).arg(QStringLiteral("%1").arg(source.classId)));
        document.field(QStringLiteral("Machine"), QStringLiteral("%1").arg(formatHex32(source.machine)));
        document.field(QStringLiteral("TimeDateStamp"), QStringLiteral("%1").arg(formatHex32(source.timeDateStamp)));
        document.field(QStringLiteral("SizeOfImage"), QStringLiteral("%1").arg(formatHex32(source.sizeOfImage)));
        document.field(QStringLiteral("ImageBase"), QStringLiteral("%1").arg(formatHex64(source.imageBase)));
        return document; }
    }

    // appendSummaryRow：
    // - 输入 table/name/value：摘要表、字段名和值；
    // - 处理：追加只读行；
    // - 返回：无。
    void appendSummaryRow(QTableWidget* table, const QString& nameText, const QString& valueText)
    {
        if (table == nullptr)
        {
            return;
        }

        const int rowIndex = table->rowCount();
        table->insertRow(rowIndex);

        auto* nameItem = new QTableWidgetItem(nameText);
        auto* valueItem = new QTableWidgetItem(valueText);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);

        table->setItem(rowIndex, static_cast<int>(SummaryColumn::Name), nameItem);
        table->setItem(rowIndex, static_cast<int>(SummaryColumn::Value), valueItem);
    }

    // setReadonlyItem：
    // - 输入 table/row/column/item：目标表、行列和 item；
    // - 处理：去掉可编辑 flag 后放入表格；
    // - 返回：无。
    void setReadonlyItem(QTableWidget* table, const int rowIndex, const DynDataColumn column, QTableWidgetItem* item)
    {
        if (table == nullptr || item == nullptr)
        {
            delete item;
            return;
        }

        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        table->setItem(rowIndex, static_cast<int>(column), item);
    }

    // buildFieldDetail：
    // - 输入 entry/summary：字段行和当前摘要；
    // - 处理：生成详情面板文本，包含能力依赖和全局状态；
    // - 返回：多行详情文本。
    ks::ui::FieldDocument buildFieldDetail(const KernelDynDataFieldEntry& entry, const KernelDynDataSummary& summary)
    {
        { ks::ui::FieldDocument document;
        document.field(QStringLiteral("字段名"), QStringLiteral("%1").arg(safeText(entry.fieldNameText)));
        document.field(QStringLiteral("字段ID"), QStringLiteral("%1").arg(entry.fieldId));
        document.field(QStringLiteral("偏移"), QStringLiteral("%1").arg(formatOffset(entry.offset)));
        document.field(QStringLiteral("状态"), QStringLiteral("%1").arg(safeText(entry.statusText)));
        document.field(QStringLiteral("来源"), QStringLiteral("%1").arg(safeText(entry.sourceNameText)));
        document.field(QStringLiteral("功能"), QStringLiteral("%1").arg(safeText(entry.featureNameText)));
        document.field(QStringLiteral("字段标志"), QStringLiteral("%1").arg(formatHex32(entry.flags)));
        document.field(QStringLiteral("字段能力位"), QStringLiteral("%1").arg(formatHex64(entry.capabilityMask)));
        document.field(QStringLiteral("字段能力名"), QStringLiteral("%1").arg(capabilityNames(entry.capabilityMask)));
        document.field(QStringLiteral("当前全局能力位"), QStringLiteral("%1").arg(formatHex64(summary.capabilityMask)));
        document.field(QStringLiteral("当前未启用能力"), QStringLiteral("%1").arg(disabledCapabilitySummary(summary.capabilityMask)));
        document.field(QStringLiteral("R0不可用原因"), QStringLiteral("%1").arg(safeText(summary.unavailableReasonText)));
        return document; }
    }

    // buildDynDataReport：
    // - 输入 summary/rows：摘要和字段行；
    // - 处理：拼出可复制的完整诊断报告；
    // - 返回：多行报告文本。
    QString moduleProfileStateText(const KernelDynDataProfileModuleResult& result)
    {
        const QString notAttempted = kernelText("kernel.dyndata.module.not_attempted", QStringLiteral("未下发"));
        return kernelText("kernel.dyndata.module.state", QStringLiteral("命中=%1；格式有效=%2；本次接受=%3；驱动当前已接受=%4；EX=%5；V4=%6；应用=%7；拒绝=%8；%9"))
            .arg(boolText(result.found), boolText(result.valid), boolText(result.acceptedThisRefresh), boolText(result.active),
                 result.exAttempted ? formatNtStatus(result.exStatus) : notAttempted,
                 result.v4Attempted ? formatNtStatus(result.v4Status) : notAttempted)
            .arg(result.appliedItems).arg(result.rejectedItems).arg(result.message);
    }

    ks::ui::FieldDocument buildDynDataReport(const KernelDynDataSummary& summary, const std::vector<KernelDynDataFieldEntry>& rows)
    {
        ks::ui::FieldDocument lines;
        lines.note(QStringLiteral("Ksword DynData Diagnostic Report"));
        lines.field(QStringLiteral("StatusQueryOk"), QStringLiteral("%1").arg(boolText(summary.statusQueryOk)));
        lines.field(QStringLiteral("FieldsQueryOk"), QStringLiteral("%1").arg(boolText(summary.fieldsQueryOk)));
        lines.field(QStringLiteral("StatusFlags"), QStringLiteral("%1").arg(formatHex32(summary.statusFlags)));
        lines.field(QStringLiteral("CapabilityMask"), QStringLiteral("%1").arg(formatHex64(summary.capabilityMask)));
        lines.field(QStringLiteral("SystemInformerDataVersion"), QStringLiteral("%1").arg(summary.systemInformerDataVersion));
        lines.field(QStringLiteral("SystemInformerDataLength"), QStringLiteral("%1").arg(summary.systemInformerDataLength));
        lines.field(QStringLiteral("LastStatus"), QStringLiteral("%1").arg(formatNtStatus(summary.lastStatus)));
        lines.field(QStringLiteral("MatchedProfileClass"), QStringLiteral("%1").arg(moduleClassText(summary.matchedProfileClass)));
        lines.field(QStringLiteral("MatchedProfileOffset"), QStringLiteral("%1").arg(formatHex32(summary.matchedProfileOffset)));
        lines.field(QStringLiteral("MatchedFieldsId"), QStringLiteral("%1").arg(summary.matchedFieldsId));
        lines.field(QStringLiteral("UnavailableReason"), QStringLiteral("%1").arg(safeText(summary.unavailableReasonText)));
        lines.field(QStringLiteral("PdbProfileActive"), QStringLiteral("%1").arg(boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE))));
        lines.field(QStringLiteral("PdbProfileScanAttempted"), QStringLiteral("%1").arg(boolText(summary.pdbProfileScanAttempted)));
        lines.field(QStringLiteral("PdbProfileFound"), QStringLiteral("%1").arg(boolText(summary.pdbProfileFound)));
        lines.field(QStringLiteral("PdbProfileAppliedThisRefresh"), QStringLiteral("%1").arg(boolText(summary.pdbProfileApplied)));
        lines.field(QStringLiteral("PdbProfileSource"), QStringLiteral("%1").arg(safeText(summary.pdbProfileSourceText)));
        lines.field(QStringLiteral("PdbProfileName"), QStringLiteral("%1").arg(safeText(summary.pdbProfileNameText)));
        lines.field(QStringLiteral("PdbProfilePath"), QStringLiteral("%1").arg(safeText(summary.pdbProfilePathText)));
        lines.field(QStringLiteral("PdbProfileStatus"), QStringLiteral("%1").arg(formatNtStatus(summary.pdbProfileStatus)));
        lines.field(QStringLiteral("PdbProfileAppliedFields"), QStringLiteral("%1").arg(summary.pdbProfileAppliedFields));
        lines.field(QStringLiteral("PdbProfileRejectedFields"), QStringLiteral("%1").arg(summary.pdbProfileRejectedFields));
        lines.field(QStringLiteral("PdbProfileUnknownFields"), QStringLiteral("%1").arg(summary.pdbProfileUnknownFields));
        lines.field(QStringLiteral("PdbProfileIgnoredJsonFields"), QStringLiteral("%1").arg(summary.pdbProfileIgnoredJsonFields));
        lines.field(QStringLiteral("PdbProfileMessage"), QStringLiteral("%1").arg(safeText(summary.pdbProfileMessageText)));
        lines.field(QStringLiteral("PdbProfileIo"), QStringLiteral("%1").arg(safeText(summary.pdbProfileIoMessageText)));
        for (const auto& module : summary.profileModules)
        {
            lines.section(module.moduleName);
            lines.field(kernelText("kernel.dyndata.module.application", QStringLiteral("模块偏移应用")), moduleProfileStateText(module));
            lines.field(QStringLiteral("ProfileIo"), safeText(module.ioMessage));
        }
        lines.nodes += moduleDetailText(QStringLiteral("ntoskrnl"), summary.ntoskrnl).nodes;
        lines.nodes += moduleDetailText(QStringLiteral("lxcore"), summary.lxcore).nodes;

        lines.section(QStringLiteral("Capabilities"));
        lines.nodes += capabilityReport(summary.capabilityMask).nodes;

        lines.section(QStringLiteral("Fields"));
        for (const KernelDynDataFieldEntry& entry : rows)
        {
            lines.section(QStringLiteral("Field"));
            lines.field(QStringLiteral("Name"), safeText(entry.fieldNameText));
            lines.field(QStringLiteral("Offset"), formatOffset(entry.offset));
            lines.field(QStringLiteral("Status"), safeText(entry.statusText));
            lines.field(QStringLiteral("Source"), safeText(entry.sourceNameText));
            lines.field(QStringLiteral("Feature"), safeText(entry.featureNameText));
            lines.field(QStringLiteral("CapabilityMask"), formatHex64(entry.capabilityMask));
        }
        return lines;
    }

    // populateSummaryTable：
    // - 输入 table/summary/visibleRows：摘要表、摘要数据和当前字段总数；
    // - 处理：重建两列表格；
    // - 返回：无。
    void populateSummaryTable(QTableWidget* table, const KernelDynDataSummary& summary, const std::size_t visibleRows)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setSortingEnabled(false);
        table->setRowCount(0);
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.initialized", QStringLiteral("DynData 初始化")), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_INITIALIZED)));
        appendSummaryRow(table, QStringLiteral("ntoskrnl profile"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE)));
        appendSummaryRow(table, QStringLiteral("lxcore profile"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE)));
        appendSummaryRow(table, QStringLiteral("Ksword runtime offset"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE)));
        appendSummaryRow(table, QStringLiteral("PDB profile active"), boolText(statusFlagEnabled(summary.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)));
        for (const auto& module : summary.profileModules)
        {
            appendSummaryRow(table, module.moduleName, moduleProfileStateText(module));
        }
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_scan", QStringLiteral("NTOS PDB profile 扫描")), boolText(summary.pdbProfileScanAttempted));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_found", QStringLiteral("NTOS PDB profile 命中")), boolText(summary.pdbProfileFound));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_applied", QStringLiteral("NTOS PDB profile 本次应用")), boolText(summary.pdbProfileApplied));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_source", QStringLiteral("NTOS PDB profile 来源")), safeText(summary.pdbProfileSourceText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_name", QStringLiteral("NTOS PDB profile 名称")), safeText(summary.pdbProfileNameText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_path", QStringLiteral("NTOS PDB profile 路径")), safeText(summary.pdbProfilePathText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_status", QStringLiteral("NTOS PDB profile 状态")), formatNtStatus(summary.pdbProfileStatus));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_fields", QStringLiteral("NTOS PDB profile 字段")), QStringLiteral("applied=%1 rejected=%2 unknown=%3 ignoredJson=%4")
            .arg(summary.pdbProfileAppliedFields)
            .arg(summary.pdbProfileRejectedFields)
            .arg(summary.pdbProfileUnknownFields)
            .arg(summary.pdbProfileIgnoredJsonFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_message", QStringLiteral("PDB profile 消息")), safeText(summary.pdbProfileMessageText));
        appendSummaryRow(table, QStringLiteral("PDB profile IO"), safeText(summary.pdbProfileIoMessageText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.system_informer_version", QStringLiteral("System Informer 版本")), QString::number(summary.systemInformerDataVersion));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.system_informer_length", QStringLiteral("System Informer 数据长度")), QString::number(summary.systemInformerDataLength));
        appendSummaryRow(table, QStringLiteral("LastStatus"), formatNtStatus(summary.lastStatus));
        appendSummaryRow(table, QStringLiteral("MatchedProfileClass"), QStringLiteral("%1 (%2)").arg(moduleClassText(summary.matchedProfileClass)).arg(summary.matchedProfileClass));
        appendSummaryRow(table, QStringLiteral("MatchedProfileOffset"), formatHex32(summary.matchedProfileOffset));
        appendSummaryRow(table, QStringLiteral("MatchedFieldsId"), QString::number(summary.matchedFieldsId));
        appendSummaryRow(table, QStringLiteral("CapabilityMask"), formatHex64(summary.capabilityMask));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.field_count", QStringLiteral("字段总数/当前返回")), QStringLiteral("%1 / %2")
            .arg(summary.fieldCount)
            .arg(static_cast<qulonglong>(visibleRows)));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.disabled_capabilities", QStringLiteral("禁用能力")), disabledCapabilitySummary(summary.capabilityMask));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.unavailable_reason", QStringLiteral("不可用原因")), safeText(summary.unavailableReasonText));
        appendSummaryRow(table, QStringLiteral("Status IO"), safeText(summary.statusIoMessageText));
        appendSummaryRow(table, QStringLiteral("Fields IO"), safeText(summary.fieldsIoMessageText));
        appendSummaryRow(table, QStringLiteral("ntoskrnl"), moduleDetailText(QStringLiteral("ntoskrnl"), summary.ntoskrnl).toPlainText(true).replace(QStringLiteral("\n"), QStringLiteral("; ")));
        appendSummaryRow(table, QStringLiteral("lxcore"), moduleDetailText(QStringLiteral("lxcore"), summary.lxcore).toPlainText(true).replace(QStringLiteral("\n"), QStringLiteral("; ")));
        table->setSortingEnabled(false);
    }

    // populateProfileStatusTable：
    // - 输入 table/summary：profile 状态页表格和 DynData 摘要；
    // - 处理：仅展示 PDB profile 相关状态，便于确认命中、回退和降级情况；
    // - 返回：无。
    void populateProfileStatusTable(QTableWidget* table, const KernelDynDataSummary& summary)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setSortingEnabled(false);
        table->setRowCount(0);
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.scan_attempted", QStringLiteral("扫描尝试")), boolText(summary.pdbProfileScanAttempted));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.found", QStringLiteral("找到匹配")), boolText(summary.pdbProfileFound));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.applied", QStringLiteral("已应用")), boolText(summary.pdbProfileApplied));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.r0_status", QStringLiteral("R0 状态")), formatNtStatus(summary.pdbProfileStatus));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.applied_fields", QStringLiteral("已应用字段")), QString::number(summary.pdbProfileAppliedFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.rejected_fields", QStringLiteral("拒绝字段")), QString::number(summary.pdbProfileRejectedFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.unknown_fields", QStringLiteral("未知字段")), QString::number(summary.pdbProfileUnknownFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.ignored_json_fields", QStringLiteral("忽略 JSON 字段")), QString::number(summary.pdbProfileIgnoredJsonFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.source", QStringLiteral("来源")), profileSourceDisplayText(summary.pdbProfileSourceText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.name", QStringLiteral("名称")), safeText(summary.pdbProfileNameText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.path", QStringLiteral("路径")), safeText(summary.pdbProfilePathText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.message", QStringLiteral("消息")), safeText(summary.pdbProfileMessageText));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.io_message", QStringLiteral("IO 消息")), safeText(summary.pdbProfileIoMessageText));
        appendSummaryRow(table, QStringLiteral("V4 modules"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4ModulesReturnedCount, summary.dynDataV4ModulesTotalCount))
            .arg(v4IoStateText(summary.dynDataV4ModulesQueryOk, summary.dynDataV4ModulesUnsupported))
            .arg(safeText(summary.dynDataV4ModulesIoMessageText)));
        appendSummaryRow(table, QStringLiteral("V4 capability groups"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4CapabilityGroupsReturnedCount, summary.dynDataV4CapabilityGroupsTotalCount))
            .arg(v4IoStateText(summary.dynDataV4CapabilityGroupsQueryOk, summary.dynDataV4CapabilityGroupsUnsupported))
            .arg(safeText(summary.dynDataV4CapabilityGroupsIoMessageText)));
        appendSummaryRow(table, QStringLiteral("V4 missing items"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4MissingItemsReturnedCount, summary.dynDataV4MissingItemsTotalCount))
            .arg(v4IoStateText(summary.dynDataV4MissingItemsQueryOk, summary.dynDataV4MissingItemsUnsupported))
            .arg(safeText(summary.dynDataV4MissingItemsIoMessageText)));
        appendSummaryRow(table, QStringLiteral("V4 accepted items"), QStringLiteral("%1, io=%2, %3")
            .arg(v4CountText(summary.dynDataV4ItemsReturnedCount, summary.dynDataV4ItemsTotalCount))
            .arg(v4IoStateText(summary.dynDataV4ItemsQueryOk, summary.dynDataV4ItemsUnsupported))
            .arg(safeText(summary.dynDataV4ItemsIoMessageText)));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.field_stats", QStringLiteral("字段统计")), QStringLiteral("applied=%1 rejected=%2 unknown=%3 ignoredJson=%4")
            .arg(summary.pdbProfileAppliedFields)
            .arg(summary.pdbProfileRejectedFields)
            .arg(summary.pdbProfileUnknownFields)
            .arg(summary.pdbProfileIgnoredJsonFields));
        appendSummaryRow(table, kernelText("kernel.dyndata.profile_status.matched_module", QStringLiteral("匹配模块")), safeText(summary.ntoskrnl.moduleNameText));
        appendSummaryRow(table, QStringLiteral("classId"), moduleClassText(summary.ntoskrnl.classId));
        appendSummaryRow(table, QStringLiteral("machine"), formatHex32(summary.ntoskrnl.machine));
        appendSummaryRow(table, QStringLiteral("timestamp"), formatHex32(summary.ntoskrnl.timeDateStamp));
        appendSummaryRow(table, QStringLiteral("imageSize"), formatHex32(summary.ntoskrnl.sizeOfImage));
        appendSummaryRow(table, QStringLiteral("imageBase"), formatHex64(summary.ntoskrnl.imageBase));
        table->setSortingEnabled(false);
    }

    // shouldShowField：
    // - 输入 entry/filterKeyword：字段行和筛选关键字；
    // - 处理：在字段名、偏移、来源、功能、状态和能力名中匹配；
    // - 返回：true 表示该行应显示。
    bool shouldShowField(const KernelDynDataFieldEntry& entry, const QString& filterKeyword)
    {
        if (filterKeyword.isEmpty())
        {
            return true;
        }

        return entry.fieldNameText.contains(filterKeyword, Qt::CaseInsensitive) ||
            formatOffset(entry.offset).contains(filterKeyword, Qt::CaseInsensitive) ||
            entry.statusText.contains(filterKeyword, Qt::CaseInsensitive) ||
            entry.sourceNameText.contains(filterKeyword, Qt::CaseInsensitive) ||
            entry.featureNameText.contains(filterKeyword, Qt::CaseInsensitive) ||
            capabilityNames(entry.capabilityMask).contains(filterKeyword, Qt::CaseInsensitive);
    }

    // queryDynDataSnapshot：
    // - 输入 summaryOut/rowsOut/v4ItemRowsOut：输出摘要、字段缓存和 v4 accepted item 缓存；
    // - 处理：通过 ArkDriverClient 查询 DynData 基础/v4 IOCTL 并转换模型；
    // - 返回：true 表示至少 status 和 fields 查询都成功。
    bool queryDynDataSnapshot(
        KernelDynDataSummary& summaryOut,
        std::vector<KernelDynDataFieldEntry>& rowsOut,
        std::vector<KernelDynDataV4ItemEntry>& v4ItemRowsOut)
    {
        ksword::ark::DriverClient client;
        const ksword::ark::DynDataStatusResult initialStatusResult = client.queryDynDataStatus();
        const ksword::ark::DynDataV4ModulesResult initialV4ModulesResult = client.queryDynDataV4Modules();
        const ksword::ark::DynDataV4CapabilityGroupsResult initialV4GroupsResult =
            client.queryDynDataV4CapabilityGroups();

        bool pdbProfileScanAttempted = false;
        bool pdbProfileFound = false;
        bool requeryAfterProfileApply = false;
        long pdbProfileStatus = 0;
        std::uint32_t pdbProfileAppliedFields = 0U;
        std::uint32_t pdbProfileRejectedFields = 0U;
        std::uint32_t pdbProfileUnknownFields = 0U;
        std::uint32_t pdbProfileIgnoredJsonFields = 0U;
        QString pdbProfileNameText;
        QString pdbProfilePathText;
        QString pdbProfileSourceText;
        QString pdbProfileMessageText;
        QString pdbProfileIoMessageText;
        std::vector<KernelDynDataProfileModuleResult> moduleResults;
        KernelDynDataProfileModuleResult ntosResult;
        ntosResult.moduleClassId = initialStatusResult.ntoskrnl.classId;
        ntosResult.moduleName = QString::fromStdWString(initialStatusResult.ntoskrnl.moduleName);
        if (ntosResult.moduleName.isEmpty())
        {
            ntosResult.moduleName = QStringLiteral("NTOS");
        }

        if (initialStatusResult.io.ok)
        {
            const bool pdbProfileAlreadyActive =
                statusFlagEnabled(initialStatusResult.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
            const bool callbackProfileAlreadyActive =
                statusFlagEnabled(initialStatusResult.statusFlags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE);
            const bool v3ProfileAlreadyActive =
                (initialStatusResult.capabilityMask &
                    (KSW_CAP_PROCESS_LIST_FIELDS |
                        KSW_CAP_THREAD_LIST_FIELDS |
                        KSW_CAP_CID_TABLE_WALK |
                        KSW_CAP_KERNEL_MODULE_LIST_FIELDS |
                        KSW_CAP_DRIVER_OBJECT_FIELDS |
                        KSW_CAP_KERNEL_GLOBALS)) != 0ULL;
            const bool v4ModuleProfileAlreadyActive = initialV4ModulesResult.io.ok && std::any_of(
                initialV4ModulesResult.entries.begin(),
                initialV4ModulesResult.entries.end(),
                [&initialStatusResult](const KSW_DYN_V4_MODULE_STATUS_ENTRY& entry) {
                    return entry.module.image.classId == initialStatusResult.ntoskrnl.classId &&
                        entry.module.image.machine == initialStatusResult.ntoskrnl.machine &&
                        entry.module.image.timeDateStamp == initialStatusResult.ntoskrnl.timeDateStamp &&
                        entry.module.image.sizeOfImage == initialStatusResult.ntoskrnl.sizeOfImage &&
                        (entry.statusFlags & KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) != 0U;
                });
            const bool v4ProfileAlreadyActive = v4ModuleProfileAlreadyActive;
            if (pdbProfileAlreadyActive && callbackProfileAlreadyActive && v3ProfileAlreadyActive && v4ProfileAlreadyActive)
            {
                // 此处是驱动已接受档案，而非本轮 apply 失败；状态页不能显示“已应用：否”。
                // 不伪造本轮应用计数，后续 V4 accepted items 查询继续提供真实缓存内容。
                pdbProfileFound = true;
                pdbProfileMessageText = kernelText("kernel.dyndata.profile.apply.already_active", QStringLiteral("R0 已经启用 v4 DynData profile，本次刷新跳过重复 apply。"));
            }
            else
            {
                pdbProfileScanAttempted = true;
                QString scanDiagnostics;
                LocalPdbProfile profile =
                    findMatchingPdbProfile(
                        initialStatusResult.ntoskrnl,
                        scanDiagnostics);
                pdbProfileMessageText = scanDiagnostics;
                ntosResult.found = profile.matched;
                ntosResult.valid = profile.valid;
                if (profile.matched)
                {
                    pdbProfileFound = true;
                    pdbProfileSourceText = profileSourceDisplayText(profile.sourceText);
                    pdbProfileNameText = stringToQString(profile.applyInput.profileName);
                    pdbProfilePathText = profile.pathText;
                    pdbProfileIgnoredJsonFields = profile.ignoredUnknownFields;

                    if (!profile.valid)
                    {
                        pdbProfileStatus = static_cast<long>(0xC000000DUL);
                        pdbProfileMessageText = profile.diagnosticsText;
                    }
                    else if (pdbProfileAlreadyActive &&
                        callbackProfileAlreadyActive &&
                        v3ProfileAlreadyActive &&
                        profile.applyV4Input.items.empty())
                    {
                        pdbProfileMessageText = kernelText("kernel.dyndata.profile.apply.v4_skip", QStringLiteral("R0 已启用 v4 DynData profile，当前匹配 profile 无可用 item，本次刷新跳过重复 apply。"));
                    }
                    else
                    {
                        QStringList applyMessages;
                        bool anyApplySucceeded = false;

                        if (!profile.applyExInput.items.empty() &&
                            !(pdbProfileAlreadyActive && callbackProfileAlreadyActive && v3ProfileAlreadyActive))
                        {
                            const ksword::ark::DynDataProfileApplyExResult applyExResult =
                                client.applyDynDataProfileEx(profile.applyExInput);
                            if (!pdbProfileIoMessageText.isEmpty())
                            {
                                pdbProfileIoMessageText += QStringLiteral(" | ");
                            }
                            pdbProfileIoMessageText += applyExResult.io.ok ? stringToQString(applyExResult.io.message) : friendlyDynDataIoMessage(applyExResult.io.message);
                            ntosResult.exAttempted = true;
                            ntosResult.exStatus = applyExResult.status;
                            ntosResult.exAccepted = applyExResult.io.ok && applyExResult.status == 0 && applyExResult.rejectedItemCount == 0U;
                            ntosResult.appliedItems += applyExResult.appliedItemCount;
                            ntosResult.rejectedItems += applyExResult.rejectedItemCount;
                            pdbProfileStatus = applyExResult.status;
                            pdbProfileAppliedFields += applyExResult.appliedItemCount;
                            pdbProfileRejectedFields += applyExResult.rejectedItemCount;
                            pdbProfileUnknownFields += applyExResult.unknownItemCount;
                            if (!applyExResult.message.empty())
                            {
                                applyMessages << wideStringToQString(applyExResult.message);
                            }
                            anyApplySucceeded = anyApplySucceeded || (applyExResult.io.ok && applyExResult.status == 0);
                        }

                        if (!profile.applyV4Input.items.empty() && !v4ProfileAlreadyActive)
                        {
                            const ksword::ark::DynDataV4ApplyResult applyV4Result =
                                client.applyDynDataProfileV4(profile.applyV4Input);
                            if (!pdbProfileIoMessageText.isEmpty())
                            {
                                pdbProfileIoMessageText += QStringLiteral(" | ");
                            }
                            pdbProfileIoMessageText += applyV4Result.io.ok ? stringToQString(applyV4Result.io.message) : friendlyDynDataIoMessage(applyV4Result.io.message);
                            ntosResult.v4Attempted = true;
                            ntosResult.v4Status = applyV4Result.response.status;
                            ntosResult.v4Accepted = applyV4Result.io.ok && applyV4Result.response.status == 0 &&
                                applyV4Result.response.rejectedItemCount == 0U && applyV4Result.response.missingRequiredItemCount == 0U;
                            ntosResult.appliedItems += applyV4Result.response.appliedItemCount;
                            ntosResult.rejectedItems += applyV4Result.response.rejectedItemCount;
                            // A successful V4 cache must not hide a failed EX projection.
                            if (!ntosResult.exAttempted || ntosResult.exStatus == 0)
                            {
                                pdbProfileStatus = applyV4Result.response.status;
                            }
                            pdbProfileAppliedFields += applyV4Result.response.appliedItemCount;
                            pdbProfileRejectedFields += applyV4Result.response.rejectedItemCount;
                            if (applyV4Result.response.message[0] != L'\0')
                            {
                                applyMessages << wideStringToQString(applyV4Result.response.message);
                            }
                            anyApplySucceeded = anyApplySucceeded ||
                                (applyV4Result.io.ok &&
                                 applyV4Result.response.status == 0 &&
                                 applyV4Result.response.rejectedItemCount == 0U &&
                                 applyV4Result.response.missingRequiredItemCount == 0U);
                        }

                        if (!applyMessages.isEmpty())
                        {
                            pdbProfileMessageText = applyMessages.join(QStringLiteral(" | "));
                        }
                        ntosResult.acceptedThisRefresh = anyApplySucceeded &&
                            (!ntosResult.exAttempted || ntosResult.exAccepted) &&
                            (!ntosResult.v4Attempted || ntosResult.v4Accepted);
                        requeryAfterProfileApply = anyApplySucceeded;
                    }
                }
            }
        }
        else
        {
            pdbProfileMessageText = kernelText("kernel.dyndata.profile.status_query_failed", QStringLiteral("DynData status 查询失败，无法确认 ntoskrnl identity，跳过 PDB profile 扫描。"));
            pdbProfileIoMessageText = friendlyDynDataIoMessage(initialStatusResult.io.message);
        }

        // v4 模块 profile 必须按各自当前映像身份精确选择；ntoskrnl status
        // 不包含 fltmgr/ci 身份，因此 companion profile 从 v4 初始快照逐模块加载。
        if (initialV4ModulesResult.io.ok)
        {
            for (const KSW_DYN_V4_MODULE_STATUS_ENTRY& moduleEntry :
                 initialV4ModulesResult.entries)
            {
                const bool supportedCompanion =
                    moduleEntry.module.image.classId ==
                        KSW_DYN_PROFILE_CLASS_FLTMGR ||
                    moduleEntry.module.image.classId ==
                        KSW_DYN_PROFILE_CLASS_CI;
                if (!supportedCompanion ||
                    moduleEntry.module.image.present == 0UL)
                {
                    continue;
                }

                KernelDynDataProfileModuleResult moduleResult;
                moduleResult.moduleClassId = moduleEntry.module.image.classId;
                moduleResult.moduleName = QString::fromStdWString(convertV4PacketIdentity(moduleEntry.module.image).moduleName);
                moduleResult.active = (moduleEntry.statusFlags & KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) != 0U;
                if (moduleResult.active)
                {
                    moduleResult.found = true;
                    moduleResult.valid = true;
                    moduleResults.push_back(moduleResult);
                    continue;
                }
                const ksword::ark::ArkDynModuleIdentity moduleIdentity =
                    convertV4PacketIdentity(moduleEntry.module.image);
                QString moduleScanDiagnostics;
                LocalPdbProfile moduleProfile =
                    findMatchingPdbProfile(
                        moduleIdentity,
                        moduleScanDiagnostics);
                moduleResult.found = moduleProfile.matched;
                moduleResult.valid = moduleProfile.valid;
                moduleResult.message = moduleScanDiagnostics;
                if (!moduleProfile.matched)
                {
                    moduleResults.push_back(moduleResult);
                    continue;
                }
                if (!moduleProfile.valid ||
                    moduleProfile.applyV4Input.items.empty())
                {
                    moduleResult.message = moduleProfile.diagnosticsText;
                    moduleResults.push_back(moduleResult);
                    continue;
                }

                const ksword::ark::DynDataV4ApplyResult moduleApplyResult =
                    client.applyDynDataProfileV4(
                        moduleProfile.applyV4Input);
                moduleResult.v4Attempted = true;
                moduleResult.v4Status = moduleApplyResult.response.status;
                moduleResult.ioMessage = moduleApplyResult.io.ok ? stringToQString(moduleApplyResult.io.message) : friendlyDynDataIoMessage(moduleApplyResult.io.message);
                moduleResult.appliedItems = moduleApplyResult.response.appliedItemCount;
                moduleResult.rejectedItems = moduleApplyResult.response.rejectedItemCount;
                moduleResult.message = wideStringToQString(moduleApplyResult.response.message);
                const bool moduleApplySucceeded =
                    moduleApplyResult.io.ok &&
                    moduleApplyResult.response.status == 0 &&
                    moduleApplyResult.response.rejectedItemCount == 0U &&
                    moduleApplyResult.response.missingRequiredItemCount == 0U;
                moduleResult.v4Accepted = moduleApplySucceeded;
                moduleResult.acceptedThisRefresh = moduleApplySucceeded;
                moduleResults.push_back(moduleResult);
                requeryAfterProfileApply =
                    requeryAfterProfileApply ||
                    moduleApplySucceeded;
            }
        }

        ksword::ark::DynDataStatusResult statusResult = initialStatusResult;
        if (requeryAfterProfileApply)
        {
            const ksword::ark::DynDataStatusResult refreshedStatusResult = client.queryDynDataStatus();
            if (refreshedStatusResult.io.ok)
            {
                statusResult = refreshedStatusResult;
            }
            else if (pdbProfileIoMessageText.isEmpty())
            {
                pdbProfileIoMessageText = friendlyDynDataIoMessage(refreshedStatusResult.io.message);
            }
        }

        const ksword::ark::DynDataFieldsResult fieldsResult = client.queryDynDataFields();
        const ksword::ark::DynDataCapabilitiesResult capabilitiesResult = client.queryDynDataCapabilities();
        const ksword::ark::DynDataV4ModulesResult v4ModulesResult = client.queryDynDataV4Modules();
        const ksword::ark::DynDataV4CapabilityGroupsResult v4CapabilityGroupsResult =
            client.queryDynDataV4CapabilityGroups();
        const ksword::ark::DynDataV4MissingItemsResult v4MissingItemsResult =
            client.queryDynDataV4MissingItems();
        const ksword::ark::DynDataV4ItemsResult v4ItemsResult =
            client.queryDynDataV4Items();

        // 以最终驱动回读补齐缓存状态：部分能力已接受或本轮跳过/失败，不等于缓存被撤销。
        // 仅接受当前 NTOS 精确身份的 V4 条目，避免其它模块的档案冒充内核档案。
        const auto acceptedNtosModule = std::find_if(
            v4ModulesResult.entries.begin(),
            v4ModulesResult.entries.end(),
            [&statusResult](const KSW_DYN_V4_MODULE_STATUS_ENTRY& entry) {
                return statusResult.io.ok && statusResult.ntoskrnl.present && entry.module.image.present != 0UL &&
                    entry.module.image.classId == statusResult.ntoskrnl.classId &&
                    entry.module.image.machine == statusResult.ntoskrnl.machine &&
                    entry.module.image.timeDateStamp == statusResult.ntoskrnl.timeDateStamp &&
                    entry.module.image.sizeOfImage == statusResult.ntoskrnl.sizeOfImage &&
                    (entry.statusFlags & KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) != 0U;
            });
        const bool cachedNtosProfileAccepted = v4ModulesResult.io.ok &&
            acceptedNtosModule != v4ModulesResult.entries.end();
        const bool cachedPdbProfileAccepted = statusResult.io.ok &&
            statusFlagEnabled(statusResult.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
        pdbProfileFound = pdbProfileFound || cachedNtosProfileAccepted || cachedPdbProfileAccepted;
        if (cachedNtosProfileAccepted && pdbProfileNameText.isEmpty())
        {
            // 回执是定长数组；按数组边界找终止符，不依赖驱动返回字符串必定以 NUL 结尾。
            const auto& profileName = acceptedNtosModule->module.profileName;
            const auto nameEnd = std::find(std::begin(profileName), std::end(profileName), '\0');
            pdbProfileNameText = QString::fromUtf8(
                profileName,
                static_cast<qsizetype>(std::distance(std::begin(profileName), nameEnd)));
        }

        ntosResult.found = pdbProfileFound;
        // A cached accepted profile must not hide a format failure in this scan.
        if (!pdbProfileScanAttempted && (cachedNtosProfileAccepted || cachedPdbProfileAccepted))
        {
            ntosResult.valid = true;
        }
        ntosResult.active = cachedNtosProfileAccepted || cachedPdbProfileAccepted;
        ntosResult.message = pdbProfileMessageText;
        ntosResult.ioMessage = pdbProfileIoMessageText;
        moduleResults.insert(moduleResults.begin(), ntosResult);
        for (auto& module : moduleResults)
        {
            for (const auto& entry : v4ModulesResult.entries)
            {
                if (module.moduleClassId != ntosResult.moduleClassId && v4ModulesResult.io.ok &&
                    entry.module.image.present != 0UL && entry.module.image.classId == module.moduleClassId)
                {
                    module.active = (entry.statusFlags & KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) != 0U;
                }
            }
        }

        summaryOut = KernelDynDataSummary{};
        rowsOut.clear();
        v4ItemRowsOut.clear();

        summaryOut.statusQueryOk = statusResult.io.ok;
        summaryOut.fieldsQueryOk = fieldsResult.io.ok;
        summaryOut.statusIoMessageText = friendlyDynDataIoMessage(statusResult.io.message);
        summaryOut.fieldsIoMessageText = friendlyDynDataIoMessage(fieldsResult.io.message);
        summaryOut.pdbProfileScanAttempted = pdbProfileScanAttempted;
        summaryOut.pdbProfileFound = pdbProfileFound;
        summaryOut.pdbProfileApplied = ntosResult.acceptedThisRefresh;
        summaryOut.profileModules = std::move(moduleResults);
        summaryOut.pdbProfileStatus = pdbProfileStatus;
        summaryOut.pdbProfileAppliedFields = pdbProfileAppliedFields;
        summaryOut.pdbProfileRejectedFields = pdbProfileRejectedFields;
        summaryOut.pdbProfileUnknownFields = pdbProfileUnknownFields;
        summaryOut.pdbProfileIgnoredJsonFields = pdbProfileIgnoredJsonFields;
        summaryOut.pdbProfileSourceText = pdbProfileSourceText;
        summaryOut.pdbProfileNameText = pdbProfileNameText;
        summaryOut.pdbProfilePathText = pdbProfilePathText;
        summaryOut.pdbProfileMessageText = pdbProfileMessageText;
        summaryOut.pdbProfileIoMessageText = pdbProfileIoMessageText;
        summaryOut.dynDataV4ModulesQueryOk = v4ModulesResult.io.ok;
        summaryOut.dynDataV4ModulesUnsupported = v4ModulesResult.unsupported;
        summaryOut.dynDataV4ModulesTotalCount = v4ModulesResult.totalCount;
        summaryOut.dynDataV4ModulesReturnedCount = v4ModulesResult.returnedCount;
        summaryOut.dynDataV4ModulesIoMessageText = friendlyDynDataIoMessage(v4ModulesResult.io.message);
        summaryOut.dynDataV4CapabilityGroupsQueryOk = v4CapabilityGroupsResult.io.ok;
        summaryOut.dynDataV4CapabilityGroupsUnsupported = v4CapabilityGroupsResult.unsupported;
        summaryOut.dynDataV4CapabilityGroupsTotalCount = v4CapabilityGroupsResult.totalCount;
        summaryOut.dynDataV4CapabilityGroupsReturnedCount = v4CapabilityGroupsResult.returnedCount;
        summaryOut.dynDataV4CapabilityGroupsIoMessageText = friendlyDynDataIoMessage(v4CapabilityGroupsResult.io.message);
        summaryOut.dynDataV4MissingItemsQueryOk = v4MissingItemsResult.io.ok;
        summaryOut.dynDataV4MissingItemsUnsupported = v4MissingItemsResult.unsupported;
        summaryOut.dynDataV4MissingItemsTotalCount = v4MissingItemsResult.totalCount;
        summaryOut.dynDataV4MissingItemsReturnedCount = v4MissingItemsResult.returnedCount;
        summaryOut.dynDataV4MissingItemsIoMessageText = friendlyDynDataIoMessage(v4MissingItemsResult.io.message);
        summaryOut.dynDataV4ItemsQueryOk = v4ItemsResult.io.ok;
        summaryOut.dynDataV4ItemsUnsupported = v4ItemsResult.unsupported;
        summaryOut.dynDataV4ItemsTotalCount = v4ItemsResult.totalCount;
        summaryOut.dynDataV4ItemsReturnedCount = v4ItemsResult.returnedCount;
        summaryOut.dynDataV4ItemsIoMessageText = friendlyDynDataIoMessage(v4ItemsResult.io.message);

        v4ItemRowsOut.reserve(v4ItemsResult.entries.size());
        for (const KSW_DYN_V4_ITEM_STATUS_ENTRY& sourceEntry : v4ItemsResult.entries)
        {
            const KSW_DYN_V4_ITEM_PACKET& sourceItem = sourceEntry.item;
            KernelDynDataV4ItemEntry row{};
            row.moduleClassId = sourceEntry.moduleClassId;
            row.itemIndex = sourceEntry.itemIndex;
            row.itemId = sourceItem.itemId;
            row.itemKind = sourceItem.itemKind;
            row.flags = sourceItem.flags;
            row.capabilityGroupId = sourceItem.capabilityGroupId;
            row.value =
                (static_cast<std::uint64_t>(sourceItem.valueHigh) << 32U) |
                static_cast<std::uint64_t>(sourceItem.valueLow);
            row.kindText = v4ItemKindText(sourceItem.itemKind);
            row.flagsText = v4ItemFlagsText(sourceItem.flags);
            row.auxText = QStringLiteral("aux0=%1; aux1=%2; aux2=%3; aux3=%4")
                .arg(formatHex32(sourceItem.aux0))
                .arg(formatHex32(sourceItem.aux1))
                .arg(formatHex32(sourceItem.aux2))
                .arg(formatHex32(sourceItem.aux3));
            row.detailDocument = {};
            row.detailDocument.field(QStringLiteral("module"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(moduleClassText(row.moduleClassId))).arg(QStringLiteral("%1").arg(row.moduleClassId)));
            row.detailDocument.field(QStringLiteral("itemIndex"), QStringLiteral("%1").arg(row.itemIndex));
            row.detailDocument.field(QStringLiteral("itemId"), QStringLiteral("%1").arg(row.itemId));
            row.detailDocument.field(QStringLiteral("kind"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(row.kindText)).arg(QStringLiteral("%1").arg(row.itemKind)));
            row.detailDocument.field(QStringLiteral("flags"), QStringLiteral("%1").arg(row.flagsText));
            row.detailDocument.field(QStringLiteral("capabilityGroupId"), QStringLiteral("%1").arg(row.capabilityGroupId));
            row.detailDocument.field(QStringLiteral("value"), QStringLiteral("%1").arg(v4ItemValueText(sourceItem)));
            row.detailDocument.note(QStringLiteral("%1").arg(row.auxText));
            v4ItemRowsOut.push_back(row);
        }

        if (statusResult.io.ok)
        {
            summaryOut.statusFlags = statusResult.statusFlags;
            summaryOut.systemInformerDataVersion = statusResult.systemInformerDataVersion;
            summaryOut.systemInformerDataLength = statusResult.systemInformerDataLength;
            summaryOut.lastStatus = statusResult.lastStatus;
            summaryOut.matchedProfileClass = statusResult.matchedProfileClass;
            summaryOut.matchedProfileOffset = statusResult.matchedProfileOffset;
            summaryOut.matchedFieldsId = statusResult.matchedFieldsId;
            summaryOut.fieldCount = statusResult.fieldCount;
            summaryOut.capabilityMask = statusResult.capabilityMask;
            summaryOut.ntoskrnl = convertModuleIdentity(statusResult.ntoskrnl);
            summaryOut.lxcore = convertModuleIdentity(statusResult.lxcore);
            summaryOut.unavailableReasonText = wideStringToQString(statusResult.unavailableReason);
        }

        if (capabilitiesResult.io.ok)
        {
            summaryOut.capabilityMask = capabilitiesResult.capabilityMask;
            summaryOut.statusFlags = capabilitiesResult.statusFlags != 0U ? capabilitiesResult.statusFlags : summaryOut.statusFlags;
        }

        if (fieldsResult.io.ok)
        {
            rowsOut.reserve(fieldsResult.entries.size());
            for (const ksword::ark::DynDataFieldEntry& sourceEntry : fieldsResult.entries)
            {
                KernelDynDataFieldEntry row{};
                row.fieldId = sourceEntry.fieldId;
                row.flags = sourceEntry.flags;
                row.source = sourceEntry.source;
                row.offset = sourceEntry.offset;
                row.capabilityMask = sourceEntry.capabilityMask;
                row.fieldNameText = stringToQString(sourceEntry.fieldName);
                row.sourceNameText = !sourceEntry.sourceName.empty()
                    ? stringToQString(sourceEntry.sourceName)
                    : sourceText(sourceEntry.source);
                row.featureNameText = stringToQString(sourceEntry.featureName);
                row.statusText = fieldPresent(row.flags, row.offset)
                    ? kernelText("kernel.dyndata.field.status.available", QStringLiteral("可用"))
                    : (row.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U
                        ? kernelText("kernel.dyndata.field.status.required_missing", QStringLiteral("缺失(必需)"))
                        : kernelText("kernel.dyndata.field.status.optional_missing", QStringLiteral("缺失(可选)"));
                row.detailDocument = buildFieldDetail(row, summaryOut);
                rowsOut.push_back(row);
            }
        }

        return summaryOut.statusQueryOk && summaryOut.fieldsQueryOk;
    }
}

void KernelDock::initializeDynDataTab()
{
    if (m_selfDriverInnerTabWidget == nullptr ||
        m_dynDataOverviewLayout != nullptr)
    {
        return;
    }

    // 总览与 PDB Profile 直接挂在“Ksword自身驱动”页签容器中，
    // 避免“动态偏移 -> 总览/PDB Profile”的无内容中间层。
    m_dynDataOverviewPage = new QWidget(m_selfDriverInnerTabWidget);
    m_dynDataOverviewLayout = new QVBoxLayout(m_dynDataOverviewPage);
    m_dynDataOverviewLayout->setContentsMargins(0, 0, 0, 0);
    m_dynDataOverviewLayout->setSpacing(6);

    m_dynDataToolLayout = new QHBoxLayout();
    m_dynDataToolLayout->setContentsMargins(0, 0, 0, 0);
    m_dynDataToolLayout->setSpacing(6);

    m_refreshDynDataButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), m_dynDataOverviewPage);
    m_refreshDynDataButton->setToolTip(kernelText("kernel.dyndata.toolbar.refresh.tooltip", QStringLiteral("刷新 R0 DynData 状态和字段表")));
    m_refreshDynDataButton->setStyleSheet(blueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshDynDataButton);

    m_copyDynDataReportButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), kernelText("kernel.dyndata.toolbar.copy_report", QStringLiteral("复制诊断")), m_dynDataOverviewPage);
    m_copyDynDataReportButton->setToolTip(kernelText("kernel.dyndata.toolbar.copy_report.tooltip", QStringLiteral("复制 DynData 状态、能力和字段列表到剪贴板")));
    m_copyDynDataReportButton->setStyleSheet(blueButtonStyle());

    m_dynDataFilterEdit = new QLineEdit(m_dynDataOverviewPage);
    m_dynDataFilterEdit->setPlaceholderText(kernelText("kernel.dyndata.toolbar.filter.placeholder", QStringLiteral("按字段名/偏移/状态/来源/功能/capability 筛选")));
    m_dynDataFilterEdit->setToolTip(kernelText("kernel.dyndata.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤动态偏移字段表")));
    m_dynDataFilterEdit->setClearButtonEnabled(true);
    ks::ui::StyleSearchField(m_dynDataFilterEdit);

    m_dynDataStatusLabel = new QLabel(kernelText("kernel.dyndata.status.waiting", QStringLiteral("状态：等待刷新")), m_dynDataOverviewPage);
    m_dynDataStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));

    m_dynDataToolLayout->addWidget(m_refreshDynDataButton, 0);
    m_dynDataToolLayout->addWidget(m_copyDynDataReportButton, 0);
    m_dynDataToolLayout->addWidget(m_dynDataFilterEdit, 1);
    m_dynDataToolLayout->addWidget(m_dynDataStatusLabel, 0);
    ks::ui::NormalizeToolbarRow(m_dynDataToolLayout);
    m_dynDataOverviewLayout->addLayout(m_dynDataToolLayout);

    QSplitter* verticalSplitter = new QSplitter(Qt::Vertical, m_dynDataOverviewPage);
    m_dynDataOverviewLayout->addWidget(verticalSplitter, 1);

    m_dynDataSummaryTable = new ks::ui::VisibleTableWidget(verticalSplitter);
    // 动态偏移身份摘要已有统一诊断报告，隐藏重复工具条。
    ks::ui::SetTableActionBarMode(m_dynDataSummaryTable, ks::ui::TableActionBarMode::None);
    m_dynDataSummaryTable->setColumnCount(static_cast<int>(SummaryColumn::Count));
    m_dynDataSummaryTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.summary.header.item", QStringLiteral("项目")),
        kernelText("kernel.driver_status.summary.header.value", QStringLiteral("值")) });
    m_dynDataSummaryTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_dynDataSummaryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dynDataSummaryTable->setAlternatingRowColors(true);
    m_dynDataSummaryTable->setStyleSheet(itemSelectionStyle());
    m_dynDataSummaryTable->setCornerButtonEnabled(false);
    m_dynDataSummaryTable->verticalHeader()->setVisible(false);
    m_dynDataSummaryTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_dynDataSummaryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_dynDataSummaryTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(SummaryColumn::Value), QHeaderView::Stretch);
    m_dynDataSummaryTable->setColumnWidth(static_cast<int>(SummaryColumn::Name), 220);
    m_dynDataSummaryTable->setToolTip(kernelText("kernel.dyndata.summary.tooltip", QStringLiteral("DynData 精确匹配、模块身份和 capability 摘要")));
    installDynDataCopyMenu(m_dynDataSummaryTable);

    QSplitter* lowerSplitter = new QSplitter(Qt::Horizontal, verticalSplitter);

    m_dynDataFieldTable = new ks::ui::VisibleTableWidget(lowerSplitter);
    // 偏移字段是已匹配静态配置，用紧凑复制导出节省空间。
    ks::ui::SetTableActionBarMode(m_dynDataFieldTable, ks::ui::TableActionBarMode::Compact);
    m_dynDataFieldTable->setColumnCount(static_cast<int>(DynDataColumn::Count));
    m_dynDataFieldTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.dyndata.table.header.field", QStringLiteral("字段")),
        kernelText("kernel.dyndata.table.header.offset", QStringLiteral("偏移")),
        kernelText("kernel.driver_status.capability.header.state", QStringLiteral("状态")),
        kernelText("kernel.dyndata.table.header.source", QStringLiteral("来源")),
        kernelText("kernel.driver_status.capability.header.feature", QStringLiteral("功能")),
        QStringLiteral("Capability")
        });
    m_dynDataFieldTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_dynDataFieldTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_dynDataFieldTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dynDataFieldTable->setAlternatingRowColors(true);
    m_dynDataFieldTable->setStyleSheet(itemSelectionStyle());
    m_dynDataFieldTable->setCornerButtonEnabled(false);
    m_dynDataFieldTable->verticalHeader()->setVisible(false);
    m_dynDataFieldTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_dynDataFieldTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_dynDataFieldTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(DynDataColumn::Field), QHeaderView::Stretch);
    m_dynDataFieldTable->setColumnWidth(static_cast<int>(DynDataColumn::Offset), 100);
    m_dynDataFieldTable->setColumnWidth(static_cast<int>(DynDataColumn::Status), 110);
    m_dynDataFieldTable->setColumnWidth(static_cast<int>(DynDataColumn::Source), 180);
    m_dynDataFieldTable->setColumnWidth(static_cast<int>(DynDataColumn::Feature), 180);
    m_dynDataFieldTable->setColumnWidth(static_cast<int>(DynDataColumn::Capability), 180);
    installDynDataCopyMenu(m_dynDataFieldTable);

    m_dynDataDetailEditor = new ks::ui::StructuredFieldView(lowerSplitter);
    // 普通字段详情不依赖 tree()；完整诊断使用共享后台投影，避免同步建树。
    m_dynDataDetailEditor->setValueModelProjection();

    m_dynDataDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.dyndata.detail.initial", QStringLiteral("请选择一条动态偏移字段查看详情。"))));

    verticalSplitter->setStretchFactor(0, 2);
    verticalSplitter->setStretchFactor(1, 5);
    lowerSplitter->setStretchFactor(0, 3);
    lowerSplitter->setStretchFactor(1, 2);

    m_dynDataTabIndex = m_selfDriverInnerTabWidget->addTab(
        m_dynDataOverviewPage,
        QIcon(QStringLiteral(":/Icon/process_priority.svg")),
        kernelText("kernel.dyndata.tab.overview", QStringLiteral("总览")));
    m_selfDriverInnerTabWidget->setTabToolTip(
        m_dynDataTabIndex,
        kernelText(
            "kernel.main.tab.dyn_data.tooltip",
            QStringLiteral("System Informer DynData 精确匹配状态与字段列表")));

    m_dynDataProfilePage = new QWidget(m_selfDriverInnerTabWidget);
    m_dynDataProfileLayout = new QVBoxLayout(m_dynDataProfilePage);
    m_dynDataProfileLayout->setContentsMargins(4, 4, 4, 4);
    m_dynDataProfileLayout->setSpacing(6);

    m_dynDataProfileStatusLabel = new QLabel(kernelText("kernel.dyndata.profile_status.waiting", QStringLiteral("状态：等待刷新")), m_dynDataProfilePage);
    m_dynDataProfileStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));
    m_dynDataProfileLayout->addWidget(m_dynDataProfileStatusLabel, 0);

    QSplitter* profileSplitter = new QSplitter(Qt::Vertical, m_dynDataProfilePage);
    m_dynDataProfileLayout->addWidget(profileSplitter, 1);

    m_dynDataProfileSummaryTable = new ks::ui::VisibleTableWidget(profileSplitter);
    // Profile 身份键值摘要不需要快照冻结。
    ks::ui::SetTableActionBarMode(m_dynDataProfileSummaryTable, ks::ui::TableActionBarMode::None);
    m_dynDataProfileSummaryTable->setColumnCount(2);
    m_dynDataProfileSummaryTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.summary.header.item", QStringLiteral("项目")),
        kernelText("kernel.driver_status.summary.header.value", QStringLiteral("值")) });
    m_dynDataProfileSummaryTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_dynDataProfileSummaryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dynDataProfileSummaryTable->setAlternatingRowColors(true);
    m_dynDataProfileSummaryTable->setStyleSheet(itemSelectionStyle());
    m_dynDataProfileSummaryTable->setCornerButtonEnabled(false);
    m_dynDataProfileSummaryTable->verticalHeader()->setVisible(false);
    m_dynDataProfileSummaryTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_dynDataProfileSummaryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_dynDataProfileSummaryTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    installDynDataCopyMenu(m_dynDataProfileSummaryTable);

    m_dynDataV4ItemTable = new ks::ui::VisibleTableWidget(profileSplitter);
    // 已接受 PDB item 清单为静态配置列表，保留复制导出。
    ks::ui::SetTableActionBarMode(m_dynDataV4ItemTable, ks::ui::TableActionBarMode::Compact);
    m_dynDataV4ItemTable->setColumnCount(9);
    m_dynDataV4ItemTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.dyndata.v4.header.module", QStringLiteral("模块")),
        kernelText("kernel.dyndata.v4.header.index", QStringLiteral("序号")),
        QStringLiteral("ItemId"),
        QStringLiteral("Kind"),
        QStringLiteral("Group"),
        QStringLiteral("Flags"),
        QStringLiteral("Value"),
        QStringLiteral("Aux"),
        kernelText("kernel.dyndata.v4.header.description", QStringLiteral("说明"))
        });
    m_dynDataV4ItemTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_dynDataV4ItemTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_dynDataV4ItemTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dynDataV4ItemTable->setAlternatingRowColors(true);
    m_dynDataV4ItemTable->setStyleSheet(itemSelectionStyle());
    m_dynDataV4ItemTable->setCornerButtonEnabled(false);
    m_dynDataV4ItemTable->verticalHeader()->setVisible(false);
    m_dynDataV4ItemTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_dynDataV4ItemTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_dynDataV4ItemTable->horizontalHeader()->setSectionResizeMode(8, QHeaderView::Stretch);
    m_dynDataV4ItemTable->setToolTip(kernelText("kernel.dyndata.v4.tooltip", QStringLiteral("R0 已接受并缓存的 DynData v4 PDB item 清单，只读展示，不触发业务消费。")));
    installDynDataCopyMenu(m_dynDataV4ItemTable);

    m_dynDataProfileDetailEditor = new ks::ui::StructuredFieldView(profileSplitter);
    // 总览刷新也更新此隐藏页，规范文档立即可用，树投影等到可见时再准备。
    m_dynDataProfileDetailEditor->setValueModelProjection();

    m_dynDataProfileDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.dyndata.profile_status.detail.initial", QStringLiteral("请先刷新动态偏移，再查看 PDB profile 管理状态。"))));

    profileSplitter->setStretchFactor(0, 2);
    profileSplitter->setStretchFactor(1, 3);
    profileSplitter->setStretchFactor(2, 2);

    m_dynDataProfileTabIndex = m_selfDriverInnerTabWidget->addTab(
        m_dynDataProfilePage,
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("PDB Profile"));

    // 信号连接：刷新、筛选、当前行详情和报告复制都在本页内部完成。
    connect(m_refreshDynDataButton, &QPushButton::clicked, this, [this]() {
        refreshDynDataAsync();
    });
    connect(m_copyDynDataReportButton, &QPushButton::clicked, this, [this]() {
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr)
        {
            clipboard->setText(buildDynDataReport(m_dynDataSummary, m_dynDataRows).toPlainText(true));
            m_dynDataStatusLabel->setText(kernelText("kernel.dyndata.status.report_copied", QStringLiteral("状态：诊断报告已复制")));
        }
    });
    connect(m_dynDataFilterEdit, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildDynDataFieldTable(filterText.trimmed());
        rebuildDynDataV4ItemTable(filterText.trimmed());
    });
    connect(m_dynDataFieldTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showDynDataDetailByCurrentRow();
    });
}

void KernelDock::requestDynDataRefresh()
{
    if (!m_dynDataTabInitialized)
    {
        initializeDynDataTab();
        m_dynDataTabInitialized = true;
    }

    refreshDynDataAsync();
}

void KernelDock::refreshDynDataAsync()
{
    if (m_dynDataRefreshRunning.exchange(true))
    {
        kLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] DynData 刷新被忽略：已有任务运行。" << eol;
        return;
    }

    m_refreshDynDataButton->setEnabled(false);
    m_dynDataStatusLabel->setText(kernelText("kernel.dyndata.status.refreshing", QStringLiteral("状态：刷新中...")));
    m_dynDataStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    const auto texts = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    std::thread([guardThis, texts]() {
        ksword::kernel_dock_internal::ResultTextScope textScope(texts);
        KernelDynDataSummary summary;
        std::vector<KernelDynDataFieldEntry> rows;
        std::vector<KernelDynDataV4ItemEntry> v4ItemRows;
        const bool success = queryDynDataSnapshot(summary, rows, v4ItemRows);
        // 完整报告只生成一次；UI 回填共享该值，不在隐藏详情中重新拼装。
        auto report = buildDynDataReport(summary, rows);

        QMetaObject::invokeMethod(guardThis, [guardThis, success, summary = std::move(summary), rows = std::move(rows), v4ItemRows = std::move(v4ItemRows), report = std::move(report)]() mutable {
            const auto deferredSummary =
                std::make_shared<KernelDynDataSummary>(std::move(summary));
            const auto deferredRows =
                std::make_shared<std::vector<KernelDynDataFieldEntry>>(std::move(rows));
            const auto deferredV4Rows =
                std::make_shared<std::vector<KernelDynDataV4ItemEntry>>(std::move(v4ItemRows));
            auto commitResult = [
                guardThis,
                success,
                deferredSummary,
                deferredRows,
                deferredV4Rows,
                report = std::move(report)]() mutable
            {
            KernelDynDataSummary& summary = *deferredSummary;
            std::vector<KernelDynDataFieldEntry>& rows = *deferredRows;
            std::vector<KernelDynDataV4ItemEntry>& v4ItemRows = *deferredV4Rows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_dynDataRefreshRunning.store(false);
            guardThis->m_refreshDynDataButton->setEnabled(true);
            guardThis->m_dynDataSummary = std::move(summary);
            guardThis->m_dynDataRows = std::move(rows);
            guardThis->m_dynDataV4ItemRows = std::move(v4ItemRows);

            populateSummaryTable(
                guardThis->m_dynDataSummaryTable,
                guardThis->m_dynDataSummary,
                guardThis->m_dynDataRows.size());
            guardThis->rebuildDynDataFieldTable(guardThis->m_dynDataFilterEdit->text().trimmed(), false);
            guardThis->rebuildDynDataV4ItemTable(guardThis->m_dynDataFilterEdit->text().trimmed());

            const std::size_t missingRequiredCount = static_cast<std::size_t>(
                std::count_if(
                    guardThis->m_dynDataRows.begin(),
                    guardThis->m_dynDataRows.end(),
                    [](const KernelDynDataFieldEntry& entry) {
                        return (entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U &&
                            !fieldPresent(entry.flags, entry.offset);
                    }));

            if (!success)
            {
                guardThis->m_dynDataStatusLabel->setText(kernelText("kernel.dyndata.status.refresh_failed", QStringLiteral("状态：刷新失败")));
                guardThis->m_dynDataStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                guardThis->m_dynDataDetailEditor->setDocument(report);
                populateProfileStatusTable(guardThis->m_dynDataProfileSummaryTable, guardThis->m_dynDataSummary);
                if (guardThis->m_dynDataProfileStatusLabel != nullptr)
                {
                    guardThis->m_dynDataProfileStatusLabel->setText(kernelText("kernel.dyndata.profile_status.failed", QStringLiteral("状态：profile 诊断失败，保留现有摘要")));
                    guardThis->m_dynDataProfileStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                }
                if (guardThis->m_dynDataProfileDetailEditor != nullptr)
                {
                    guardThis->m_dynDataProfileDetailEditor->setDocument(report);
                }
            }
            else
            {
                const bool ntosActive = statusFlagEnabled(guardThis->m_dynDataSummary.statusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE);
                const bool pdbProfileActive = statusFlagEnabled(guardThis->m_dynDataSummary.statusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
                guardThis->m_dynDataStatusLabel->setText(
                    kernelText("kernel.dyndata.status.summary", QStringLiteral("状态：%1%2，字段 %3 项，缺失必需 %4 项"))
                    .arg(ntosActive ? kernelText("kernel.dyndata.status.ntos_hit", QStringLiteral("ntos profile 已命中")) : kernelText("kernel.dyndata.status.ntos_miss", QStringLiteral("ntos profile 未命中")))
                    .arg(pdbProfileActive ? kernelText("kernel.dyndata.status.pdb_enabled_suffix", QStringLiteral("，PDB profile 已启用")) : QString())
                    .arg(static_cast<qulonglong>(guardThis->m_dynDataRows.size()))
                    .arg(static_cast<qulonglong>(missingRequiredCount)));
                guardThis->m_dynDataStatusLabel->setStyleSheet(
                    statusLabelStyle(ntosActive && pdbProfileActive && missingRequiredCount == 0U ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));

                guardThis->showDynDataDetailByCurrentRow();

                populateProfileStatusTable(guardThis->m_dynDataProfileSummaryTable, guardThis->m_dynDataSummary);
                if (guardThis->m_dynDataProfileStatusLabel != nullptr)
                {
                    guardThis->m_dynDataProfileStatusLabel->setText(
                        kernelText("kernel.dyndata.profile_status.summary", QStringLiteral("状态：%1，profile %2"))
                        .arg(ntosActive ? kernelText("kernel.dyndata.status.ntos_hit", QStringLiteral("ntos profile 已命中")) : kernelText("kernel.dyndata.status.ntos_miss", QStringLiteral("ntos profile 未命中")))
                        .arg(pdbProfileActive ? kernelText("kernel.dyndata.status.enabled", QStringLiteral("已启用")) : kernelText("kernel.dyndata.status.disabled", QStringLiteral("未启用"))));
                    guardThis->m_dynDataProfileStatusLabel->setStyleSheet(
                        statusLabelStyle(ntosActive && pdbProfileActive ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));
                }
                if (guardThis->m_dynDataProfileDetailEditor != nullptr)
                {
                    guardThis->m_dynDataProfileDetailEditor->setDocument(report);
                }
            }

            kLogEvent doneEvent;
            info << doneEvent
                << "[KernelDock] DynData 刷新完成, success="
                << success
                << ", fields="
                << guardThis->m_dynDataRows.size()
                << ", caps="
                << formatHex64(guardThis->m_dynDataSummary.capabilityMask)
                << eol;

            if (guardThis->m_timerDpcRefreshAfterDynData.exchange(false))
            {
                guardThis->refreshTimerDpcAsync();
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-dyndata-snapshot-apply"),
                {
                    guardThis->m_dynDataSummaryTable,
                    guardThis->m_dynDataFieldTable,
                    guardThis->m_dynDataProfileSummaryTable,
                    guardThis->m_dynDataV4ItemTable
                },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildDynDataFieldTable(const QString& filterKeyword, const bool updateDetail)
{
    if (m_dynDataFieldTable == nullptr)
    {
        return;
    }

    const auto* currentItem = m_dynDataFieldTable->item(
        m_dynDataFieldTable->currentRow(), static_cast<int>(DynDataColumn::Field));
    const QVariant selectedField = currentItem ? currentItem->data(Qt::UserRole + 1) : QVariant();
    std::vector<std::size_t> visibleSources;
    visibleSources.reserve(m_dynDataRows.size());
    for (std::size_t sourceIndex = 0U; sourceIndex < m_dynDataRows.size(); ++sourceIndex)
    {
        if (shouldShowField(m_dynDataRows[sourceIndex], filterKeyword))
            visibleSources.push_back(sourceIndex);
    }

    // 清表发出的 currentCellChanged 曾同步展开全部诊断；只发布最终选中字段。
    QSignalBlocker blocker(m_dynDataFieldTable);
    m_dynDataFieldTable->setSortingEnabled(false);
    m_dynDataFieldTable->setRowCount(0);
    m_dynDataFieldTable->setRowCount(static_cast<int>(visibleSources.size()));
    int rowIndex = 0;
    for (const std::size_t sourceIndex : visibleSources)
    {
        const KernelDynDataFieldEntry& entry = m_dynDataRows[sourceIndex];

        auto* fieldItem = new QTableWidgetItem(safeText(entry.fieldNameText));
        auto* offsetItem = new QTableWidgetItem(formatOffset(entry.offset));
        auto* statusItem = new QTableWidgetItem(safeText(entry.statusText));
        auto* sourceItem = new QTableWidgetItem(safeText(entry.sourceNameText));
        auto* featureItem = new QTableWidgetItem(safeText(entry.featureNameText));
        auto* capabilityItem = new QTableWidgetItem(formatHex64(entry.capabilityMask));

        fieldItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        fieldItem->setData(Qt::UserRole + 1, entry.fieldId);
        if (!fieldPresent(entry.flags, entry.offset))
        {
            statusItem->setForeground(QBrush((entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U
                ? KswordTheme::ErrorColor()
                : KswordTheme::WarningAccentColor()));
        }
        else
        {
            statusItem->setForeground(QBrush(KswordTheme::SuccessColor()));
        }

        setReadonlyItem(m_dynDataFieldTable, rowIndex, DynDataColumn::Field, fieldItem);
        setReadonlyItem(m_dynDataFieldTable, rowIndex, DynDataColumn::Offset, offsetItem);
        setReadonlyItem(m_dynDataFieldTable, rowIndex, DynDataColumn::Status, statusItem);
        setReadonlyItem(m_dynDataFieldTable, rowIndex, DynDataColumn::Source, sourceItem);
        setReadonlyItem(m_dynDataFieldTable, rowIndex, DynDataColumn::Feature, featureItem);
        setReadonlyItem(m_dynDataFieldTable, rowIndex, DynDataColumn::Capability, capabilityItem);
        ++rowIndex;
    }

    m_dynDataFieldTable->setSortingEnabled(true);
    int selectedRow = m_dynDataFieldTable->rowCount() > 0 ? 0 : -1;
    if (selectedField.isValid())
    {
        for (int row = 0; row < m_dynDataFieldTable->rowCount(); ++row)
        {
            if (m_dynDataFieldTable->item(row, static_cast<int>(DynDataColumn::Field))->data(Qt::UserRole + 1) == selectedField)
            {
                selectedRow = row;
                break;
            }
        }
    }
    m_dynDataFieldTable->setCurrentCell(selectedRow, 0);
    blocker.unblock();
    if (updateDetail) showDynDataDetailByCurrentRow();
}

void KernelDock::rebuildDynDataV4ItemTable(const QString& filterKeyword)
{
    if (m_dynDataV4ItemTable == nullptr)
    {
        return;
    }

    // insertReadonlyCell：
    // - 输入 row/column/text：目标单元格位置和展示文本；
    // - 处理：创建不可编辑 item 并写入 v4 item 表；
    // - 返回：无，表格所有列均为只读审计信息。
    const auto insertReadonlyCell = [this](const int row, const int column, const QString& text)
    {
        QTableWidgetItem* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        m_dynDataV4ItemTable->setItem(row, column, item);
    };

    const QSignalBlocker blocker(m_dynDataV4ItemTable);
    std::vector<const KernelDynDataV4ItemEntry*> visibleRows;
    visibleRows.reserve(m_dynDataV4ItemRows.size());
    for (const KernelDynDataV4ItemEntry& entry : m_dynDataV4ItemRows)
    {
        if (v4ItemMatchesFilter(entry, filterKeyword)) visibleRows.push_back(&entry);
    }
    m_dynDataV4ItemTable->setSortingEnabled(false);
    m_dynDataV4ItemTable->setRowCount(0);
    m_dynDataV4ItemTable->setRowCount(static_cast<int>(std::max<std::size_t>(1U, visibleRows.size())));

    int rowIndex = 0;
    for (const KernelDynDataV4ItemEntry* source : visibleRows)
    {
        const KernelDynDataV4ItemEntry& entry = *source;
        insertReadonlyCell(rowIndex, 0, moduleClassText(entry.moduleClassId));
        insertReadonlyCell(rowIndex, 1, QString::number(entry.itemIndex));
        insertReadonlyCell(rowIndex, 2, QString::number(entry.itemId));
        insertReadonlyCell(rowIndex, 3, entry.kindText);
        insertReadonlyCell(rowIndex, 4, QString::number(entry.capabilityGroupId));
        insertReadonlyCell(rowIndex, 5, entry.flagsText);
        insertReadonlyCell(rowIndex, 6, formatHex64(entry.value));
        insertReadonlyCell(rowIndex, 7, entry.auxText);
        insertReadonlyCell(rowIndex, 8, entry.detailDocument.toPlainText(true).replace(QStringLiteral("\n"), QStringLiteral("; ")));
        ++rowIndex;
    }

    if (visibleRows.empty())
    {
        const QString stateText = v4IoStateText(m_dynDataSummary.dynDataV4ItemsQueryOk, m_dynDataSummary.dynDataV4ItemsUnsupported);
        const QString detailText = kernelText("kernel.dyndata.v4.empty.detail", QStringLiteral("V4 accepted item 查询状态：%1；返回 %2/%3；%4"))
            .arg(stateText)
            .arg(m_dynDataSummary.dynDataV4ItemsReturnedCount)
            .arg(m_dynDataSummary.dynDataV4ItemsTotalCount)
            .arg(safeText(m_dynDataSummary.dynDataV4ItemsIoMessageText));
        const int rowIndex = 0;
        insertReadonlyCell(rowIndex, 0, kernelText("kernel.dyndata.v4.empty.item", QStringLiteral("<无v4 item>")));
        insertReadonlyCell(rowIndex, 1, QStringLiteral("N/A"));
        insertReadonlyCell(rowIndex, 2, QStringLiteral("N/A"));
        insertReadonlyCell(rowIndex, 3, stateText);
        insertReadonlyCell(rowIndex, 4, QStringLiteral("N/A"));
        insertReadonlyCell(rowIndex, 5, QStringLiteral("N/A"));
        insertReadonlyCell(rowIndex, 6, QStringLiteral("N/A"));
        insertReadonlyCell(rowIndex, 7, QStringLiteral("N/A"));
        insertReadonlyCell(rowIndex, 8, detailText);
    }

    m_dynDataV4ItemTable->setSortingEnabled(true);
}

bool KernelDock::currentDynDataFieldSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;

    if (m_dynDataFieldTable == nullptr)
    {
        return false;
    }

    const int currentRow = m_dynDataFieldTable->currentRow();
    if (currentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* fieldItem = m_dynDataFieldTable->item(currentRow, static_cast<int>(DynDataColumn::Field));
    if (fieldItem == nullptr)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(fieldItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < m_dynDataRows.size();
}

const KernelDynDataFieldEntry* KernelDock::currentDynDataFieldEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentDynDataFieldSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &m_dynDataRows[sourceIndex];
}

void KernelDock::showDynDataDetailByCurrentRow()
{
    if (m_dynDataDetailEditor == nullptr)
    {
        return;
    }

    const KernelDynDataFieldEntry* entry = currentDynDataFieldEntry();
    if (entry == nullptr)
    {
        m_dynDataDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.dyndata.empty.filtered", QStringLiteral("当前筛选条件下没有动态偏移字段。"))));
        return;
    }

    auto document = entry->detailDocument;
    document.nodes += moduleDetailText(QStringLiteral("ntoskrnl"), m_dynDataSummary.ntoskrnl).nodes;
    document.nodes += moduleDetailText(QStringLiteral("lxcore"), m_dynDataSummary.lxcore).nodes;
    document.nodes += capabilityReport(m_dynDataSummary.capabilityMask).nodes;
    m_dynDataDetailEditor->setDocument(document);
}
