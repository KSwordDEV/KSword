#include "../UI/StructuredFieldView.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "KernelDock.h"
#include "../UI/TableInteractionSupport.h"

#include <memory>
#include "../UI/VisibleTableWidget.h"

#include "../ArkDriverClient/ArkDriverClient.h"
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

    // LocalPdbProfile：
    // - 作用：保存一个本地 JSON profile 解析结果；
    // - 输入来源：profiles/ark_dyndata/*.json；
    // - 返回行为：作为 DriverClient::applyDynDataProfile 的输入，不持有 PDB 文件。
    struct LocalPdbProfile
    {
        bool valid = false;                              // valid：R3 语法和范围校验是否通过。
        bool matched = false;                            // matched：module identity 是否精确匹配当前 ntoskrnl。
        std::uint32_t ignoredUnknownFields = 0;          // ignoredUnknownFields：JSON 中 R3 不认识的字段数。
        QString sourceText;                              // sourceText：profile 来源，区分 pack 与散落 JSON。
        QString pathText;                                // pathText：profile 文件路径。
        QString diagnosticsText;                         // diagnosticsText：解析/校验诊断。
        ksword::ark::DynDataProfileApplyInput applyInput; // applyInput：可直接打包给 R0 的 v1 profile。
        ksword::ark::DynDataProfileApplyExInput applyExInput; // applyExInput：可直接打包给 R0 的 v2/v3 typed-item profile。
        ksword::ark::DynDataV4ApplyInput applyV4Input;    // applyV4Input：可直接发送给 R0 v4 存储层的稳定 item profile。
        std::uint32_t exAppliedCount = 0;               // exAppliedCount：v2/v3 typed items 数量。
        std::uint32_t callbackItemCount = 0;            // callbackItemCount：原始 callbackItems 条目数。
        std::uint32_t typedItemCount = 0;               // typedItemCount：v3 items/typedItems 条目数。
        std::uint32_t v4ItemCount = 0;                  // v4ItemCount：v4 stable item 数量。
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
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
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

    // fieldIdForProfileName：
    // - 输入 fieldName：JSON profile 中的字段名；
    // - 处理：映射到 shared/driver/KswordArkDynDataIoctl.h 中的字段 ID；
    // - 返回：命中返回 true，否则 false，由调用方记录未知字段诊断。
    bool fieldIdForProfileName(const QString& fieldName, std::uint32_t& fieldIdOut)
    {
        static const std::unordered_map<std::string, std::uint32_t> kFieldIds = {
            { "EpObjectTable", KSW_DYN_FIELD_ID_EP_OBJECT_TABLE },
            { "EpSectionObject", KSW_DYN_FIELD_ID_EP_SECTION_OBJECT },
            { "EpUniqueProcessId", KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID },
            { "_EPROCESS.UniqueProcessId", KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID },
            { "EpActiveProcessLinks", KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS },
            { "_EPROCESS.ActiveProcessLinks", KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS },
            { "EpThreadListHead", KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD },
            { "_EPROCESS.ThreadListHead", KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD },
            { "EpImageFileName", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME },
            { "_EPROCESS.ImageFileName", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_NAME },
            { "EpToken", KSW_DYN_FIELD_ID_EP_TOKEN },
            { "_EPROCESS.Token", KSW_DYN_FIELD_ID_EP_TOKEN },
            { "EpFlags", KSW_DYN_FIELD_ID_EP_FLAGS },
            { "_EPROCESS.Flags", KSW_DYN_FIELD_ID_EP_FLAGS },
            { "EpFlags2", KSW_DYN_FIELD_ID_EP_FLAGS2 },
            { "_EPROCESS.Flags2", KSW_DYN_FIELD_ID_EP_FLAGS2 },
            { "EpRundownProtect", KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT },
            { "_EPROCESS.RundownProtect", KSW_DYN_FIELD_ID_EP_RUNDOWN_PROTECT },
            { "EpProcessLock", KSW_DYN_FIELD_ID_EP_PROCESS_LOCK },
            { "_EPROCESS.ProcessLock", KSW_DYN_FIELD_ID_EP_PROCESS_LOCK },
            { "EpCreateTime", KSW_DYN_FIELD_ID_EP_CREATE_TIME },
            { "_EPROCESS.CreateTime", KSW_DYN_FIELD_ID_EP_CREATE_TIME },
            { "EpExitTime", KSW_DYN_FIELD_ID_EP_EXIT_TIME },
            { "_EPROCESS.ExitTime", KSW_DYN_FIELD_ID_EP_EXIT_TIME },
            { "EpExitStatus", KSW_DYN_FIELD_ID_EP_EXIT_STATUS },
            { "_EPROCESS.ExitStatus", KSW_DYN_FIELD_ID_EP_EXIT_STATUS },
            { "EpPeb", KSW_DYN_FIELD_ID_EP_PEB },
            { "_EPROCESS.Peb", KSW_DYN_FIELD_ID_EP_PEB },
            { "EpSession", KSW_DYN_FIELD_ID_EP_SESSION },
            { "_EPROCESS.Session", KSW_DYN_FIELD_ID_EP_SESSION },
            { "EpWin32Process", KSW_DYN_FIELD_ID_EP_WIN32_PROCESS },
            { "_EPROCESS.Win32Process", KSW_DYN_FIELD_ID_EP_WIN32_PROCESS },
            { "EpWow64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "EpWoW64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "_EPROCESS.WoW64Process", KSW_DYN_FIELD_ID_EP_WOW64_PROCESS },
            { "EpInheritedFromUniqueProcessId", KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID },
            { "_EPROCESS.InheritedFromUniqueProcessId", KSW_DYN_FIELD_ID_EP_INHERITED_FROM_UNIQUE_PROCESS_ID },
            { "EpSeAuditProcessCreationInfo", KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO },
            { "_EPROCESS.SeAuditProcessCreationInfo", KSW_DYN_FIELD_ID_EP_SE_AUDIT_PROCESS_CREATION_INFO },
            { "EpJob", KSW_DYN_FIELD_ID_EP_JOB },
            { "_EPROCESS.Job", KSW_DYN_FIELD_ID_EP_JOB },
            { "EpDeviceMap", KSW_DYN_FIELD_ID_EP_DEVICE_MAP },
            { "_EPROCESS.DeviceMap", KSW_DYN_FIELD_ID_EP_DEVICE_MAP },
            { "EpDebugPort", KSW_DYN_FIELD_ID_EP_DEBUG_PORT },
            { "_EPROCESS.DebugPort", KSW_DYN_FIELD_ID_EP_DEBUG_PORT },
            { "EpExceptionPortData", KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA },
            { "_EPROCESS.ExceptionPortData", KSW_DYN_FIELD_ID_EP_EXCEPTION_PORT_DATA },
            { "EpSectionBaseAddress", KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS },
            { "_EPROCESS.SectionBaseAddress", KSW_DYN_FIELD_ID_EP_SECTION_BASE_ADDRESS },
            { "EpImageFilePointer", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER },
            { "_EPROCESS.ImageFilePointer", KSW_DYN_FIELD_ID_EP_IMAGE_FILE_POINTER },
            { "EpPriorityClass", KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS },
            { "_EPROCESS.PriorityClass", KSW_DYN_FIELD_ID_EP_PRIORITY_CLASS },
            { "EpActiveThreads", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS },
            { "_EPROCESS.ActiveThreads", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS },
            { "EpVadRoot", KSW_DYN_FIELD_ID_EP_VAD_ROOT },
            { "_EPROCESS.VadRoot", KSW_DYN_FIELD_ID_EP_VAD_ROOT },
            { "EpVadHint", KSW_DYN_FIELD_ID_EP_VAD_HINT },
            { "_EPROCESS.VadHint", KSW_DYN_FIELD_ID_EP_VAD_HINT },
            { "EpCloneRoot", KSW_DYN_FIELD_ID_EP_CLONE_ROOT },
            { "_EPROCESS.CloneRoot", KSW_DYN_FIELD_ID_EP_CLONE_ROOT },
            { "EpNumberOfPrivatePages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES },
            { "_EPROCESS.NumberOfPrivatePages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_PRIVATE_PAGES },
            { "EpNumberOfLockedPages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES },
            { "_EPROCESS.NumberOfLockedPages", KSW_DYN_FIELD_ID_EP_NUMBER_OF_LOCKED_PAGES },
            { "EpCommitCharge", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE },
            { "_EPROCESS.CommitCharge", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE },
            { "EpCommitChargePeak", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK },
            { "_EPROCESS.CommitChargePeak", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_PEAK },
            { "EpPeakVirtualSize", KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE },
            { "_EPROCESS.PeakVirtualSize", KSW_DYN_FIELD_ID_EP_PEAK_VIRTUAL_SIZE },
            { "EpVirtualSize", KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE },
            { "_EPROCESS.VirtualSize", KSW_DYN_FIELD_ID_EP_VIRTUAL_SIZE },
            { "EpSessionProcessLinks", KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS },
            { "_EPROCESS.SessionProcessLinks", KSW_DYN_FIELD_ID_EP_SESSION_PROCESS_LINKS },
            { "EpMitigationFlags", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS },
            { "_EPROCESS.MitigationFlags", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS },
            { "EpMitigationFlags2", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2 },
            { "_EPROCESS.MitigationFlags2", KSW_DYN_FIELD_ID_EP_MITIGATION_FLAGS2 },
            { "EpProcessQuotaUsage", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE },
            { "_EPROCESS.ProcessQuotaUsage", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_USAGE },
            { "EpProcessQuotaPeak", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK },
            { "_EPROCESS.ProcessQuotaPeak", KSW_DYN_FIELD_ID_EP_PROCESS_QUOTA_PEAK },
            { "EpAddressCreationLock", KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK },
            { "_EPROCESS.AddressCreationLock", KSW_DYN_FIELD_ID_EP_ADDRESS_CREATION_LOCK },
            { "EpPageTableCommitmentLock", KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK },
            { "_EPROCESS.PageTableCommitmentLock", KSW_DYN_FIELD_ID_EP_PAGE_TABLE_COMMITMENT_LOCK },
            { "EpRotateInProgress", KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS },
            { "_EPROCESS.RotateInProgress", KSW_DYN_FIELD_ID_EP_ROTATE_IN_PROGRESS },
            { "EpForkInProgress", KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS },
            { "_EPROCESS.ForkInProgress", KSW_DYN_FIELD_ID_EP_FORK_IN_PROGRESS },
            { "EpCommitChargeJob", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB },
            { "_EPROCESS.CommitChargeJob", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_JOB },
            { "EpCookie", KSW_DYN_FIELD_ID_EP_COOKIE },
            { "_EPROCESS.Cookie", KSW_DYN_FIELD_ID_EP_COOKIE },
            { "EpWorkingSetWatch", KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH },
            { "_EPROCESS.WorkingSetWatch", KSW_DYN_FIELD_ID_EP_WORKING_SET_WATCH },
            { "EpWin32WindowStation", KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION },
            { "_EPROCESS.Win32WindowStation", KSW_DYN_FIELD_ID_EP_WIN32_WINDOW_STATION },
            { "EpOwnerProcessId", KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID },
            { "_EPROCESS.OwnerProcessId", KSW_DYN_FIELD_ID_EP_OWNER_PROCESS_ID },
            { "EpQuotaBlock", KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK },
            { "_EPROCESS.QuotaBlock", KSW_DYN_FIELD_ID_EP_QUOTA_BLOCK },
            { "EpEtwDataSource", KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE },
            { "_EPROCESS.EtwDataSource", KSW_DYN_FIELD_ID_EP_ETW_DATA_SOURCE },
            { "EpPageDirectoryPte", KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE },
            { "_EPROCESS.PageDirectoryPte", KSW_DYN_FIELD_ID_EP_PAGE_DIRECTORY_PTE },
            { "EpSecurityPort", KSW_DYN_FIELD_ID_EP_SECURITY_PORT },
            { "_EPROCESS.SecurityPort", KSW_DYN_FIELD_ID_EP_SECURITY_PORT },
            { "EpJobLinks", KSW_DYN_FIELD_ID_EP_JOB_LINKS },
            { "_EPROCESS.JobLinks", KSW_DYN_FIELD_ID_EP_JOB_LINKS },
            { "EpHighestUserAddress", KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS },
            { "_EPROCESS.HighestUserAddress", KSW_DYN_FIELD_ID_EP_HIGHEST_USER_ADDRESS },
            { "EpImagePathHash", KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH },
            { "_EPROCESS.ImagePathHash", KSW_DYN_FIELD_ID_EP_IMAGE_PATH_HASH },
            { "EpDefaultHardErrorProcessing", KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING },
            { "_EPROCESS.DefaultHardErrorProcessing", KSW_DYN_FIELD_ID_EP_DEFAULT_HARD_ERROR_PROCESSING },
            { "EpLastThreadExitStatus", KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS },
            { "_EPROCESS.LastThreadExitStatus", KSW_DYN_FIELD_ID_EP_LAST_THREAD_EXIT_STATUS },
            { "EpPrefetchTrace", KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE },
            { "_EPROCESS.PrefetchTrace", KSW_DYN_FIELD_ID_EP_PREFETCH_TRACE },
            { "EpLockedPagesList", KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST },
            { "_EPROCESS.LockedPagesList", KSW_DYN_FIELD_ID_EP_LOCKED_PAGES_LIST },
            { "EpReadOperationCount", KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT },
            { "_EPROCESS.ReadOperationCount", KSW_DYN_FIELD_ID_EP_READ_OPERATION_COUNT },
            { "EpWriteOperationCount", KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT },
            { "_EPROCESS.WriteOperationCount", KSW_DYN_FIELD_ID_EP_WRITE_OPERATION_COUNT },
            { "EpOtherOperationCount", KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT },
            { "_EPROCESS.OtherOperationCount", KSW_DYN_FIELD_ID_EP_OTHER_OPERATION_COUNT },
            { "EpReadTransferCount", KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT },
            { "_EPROCESS.ReadTransferCount", KSW_DYN_FIELD_ID_EP_READ_TRANSFER_COUNT },
            { "EpWriteTransferCount", KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT },
            { "_EPROCESS.WriteTransferCount", KSW_DYN_FIELD_ID_EP_WRITE_TRANSFER_COUNT },
            { "EpOtherTransferCount", KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT },
            { "_EPROCESS.OtherTransferCount", KSW_DYN_FIELD_ID_EP_OTHER_TRANSFER_COUNT },
            { "EpCommitChargeLimit", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT },
            { "_EPROCESS.CommitChargeLimit", KSW_DYN_FIELD_ID_EP_COMMIT_CHARGE_LIMIT },
            { "EpVm", KSW_DYN_FIELD_ID_EP_VM },
            { "_EPROCESS.Vm", KSW_DYN_FIELD_ID_EP_VM },
            { "EpMmProcessLinks", KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS },
            { "_EPROCESS.MmProcessLinks", KSW_DYN_FIELD_ID_EP_MM_PROCESS_LINKS },
            { "EpModifiedPageCount", KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT },
            { "_EPROCESS.ModifiedPageCount", KSW_DYN_FIELD_ID_EP_MODIFIED_PAGE_COUNT },
            { "EpVadCount", KSW_DYN_FIELD_ID_EP_VAD_COUNT },
            { "_EPROCESS.VadCount", KSW_DYN_FIELD_ID_EP_VAD_COUNT },
            { "EpVadPhysicalPages", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES },
            { "_EPROCESS.VadPhysicalPages", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES },
            { "EpVadPhysicalPagesLimit", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT },
            { "_EPROCESS.VadPhysicalPagesLimit", KSW_DYN_FIELD_ID_EP_VAD_PHYSICAL_PAGES_LIMIT },
            { "EpAlpcContext", KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT },
            { "_EPROCESS.AlpcContext", KSW_DYN_FIELD_ID_EP_ALPC_CONTEXT },
            { "EpTimerResolutionLink", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK },
            { "_EPROCESS.TimerResolutionLink", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_LINK },
            { "EpTimerResolutionStackRecord", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD },
            { "_EPROCESS.TimerResolutionStackRecord", KSW_DYN_FIELD_ID_EP_TIMER_RESOLUTION_STACK_RECORD },
            { "EpRequestedTimerResolution", KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION },
            { "_EPROCESS.RequestedTimerResolution", KSW_DYN_FIELD_ID_EP_REQUESTED_TIMER_RESOLUTION },
            { "EpSmallestTimerResolution", KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION },
            { "_EPROCESS.SmallestTimerResolution", KSW_DYN_FIELD_ID_EP_SMALLEST_TIMER_RESOLUTION },
            { "EpInvertedFunctionTable", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE },
            { "_EPROCESS.InvertedFunctionTable", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE },
            { "EpInvertedFunctionTableLock", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK },
            { "_EPROCESS.InvertedFunctionTableLock", KSW_DYN_FIELD_ID_EP_INVERTED_FUNCTION_TABLE_LOCK },
            { "EpActiveThreadsHighWatermark", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK },
            { "_EPROCESS.ActiveThreadsHighWatermark", KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS_HIGH_WATERMARK },
            { "EpLargePrivateVadCount", KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT },
            { "_EPROCESS.LargePrivateVadCount", KSW_DYN_FIELD_ID_EP_LARGE_PRIVATE_VAD_COUNT },
            { "EpThreadListLock", KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK },
            { "_EPROCESS.ThreadListLock", KSW_DYN_FIELD_ID_EP_THREAD_LIST_LOCK },
            { "EpWnfContext", KSW_DYN_FIELD_ID_EP_WNF_CONTEXT },
            { "_EPROCESS.WnfContext", KSW_DYN_FIELD_ID_EP_WNF_CONTEXT },
            { "EpFlags3", KSW_DYN_FIELD_ID_EP_FLAGS3 },
            { "_EPROCESS.Flags3", KSW_DYN_FIELD_ID_EP_FLAGS3 },
            { "EpDiskCounters", KSW_DYN_FIELD_ID_EP_DISK_COUNTERS },
            { "_EPROCESS.DiskCounters", KSW_DYN_FIELD_ID_EP_DISK_COUNTERS },
            { "TokTokenSource", KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE },
            { "_TOKEN.TokenSource", KSW_DYN_FIELD_ID_TOK_TOKEN_SOURCE },
            { "TokTokenId", KSW_DYN_FIELD_ID_TOK_TOKEN_ID },
            { "_TOKEN.TokenId", KSW_DYN_FIELD_ID_TOK_TOKEN_ID },
            { "TokAuthenticationId", KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID },
            { "_TOKEN.AuthenticationId", KSW_DYN_FIELD_ID_TOK_AUTHENTICATION_ID },
            { "TokParentTokenId", KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID },
            { "_TOKEN.ParentTokenId", KSW_DYN_FIELD_ID_TOK_PARENT_TOKEN_ID },
            { "TokExpirationTime", KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME },
            { "_TOKEN.ExpirationTime", KSW_DYN_FIELD_ID_TOK_EXPIRATION_TIME },
            { "TokTokenLock", KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK },
            { "_TOKEN.TokenLock", KSW_DYN_FIELD_ID_TOK_TOKEN_LOCK },
            { "TokModifiedId", KSW_DYN_FIELD_ID_TOK_MODIFIED_ID },
            { "_TOKEN.ModifiedId", KSW_DYN_FIELD_ID_TOK_MODIFIED_ID },
            { "TokPrivileges", KSW_DYN_FIELD_ID_TOK_PRIVILEGES },
            { "_TOKEN.Privileges", KSW_DYN_FIELD_ID_TOK_PRIVILEGES },
            { "TokAuditPolicy", KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY },
            { "_TOKEN.AuditPolicy", KSW_DYN_FIELD_ID_TOK_AUDIT_POLICY },
            { "TokSessionId", KSW_DYN_FIELD_ID_TOK_SESSION_ID },
            { "_TOKEN.SessionId", KSW_DYN_FIELD_ID_TOK_SESSION_ID },
            { "TokUserAndGroupCount", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT },
            { "_TOKEN.UserAndGroupCount", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUP_COUNT },
            { "TokRestrictedSidCount", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT },
            { "_TOKEN.RestrictedSidCount", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_COUNT },
            { "TokVariableLength", KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH },
            { "_TOKEN.VariableLength", KSW_DYN_FIELD_ID_TOK_VARIABLE_LENGTH },
            { "TokDynamicCharged", KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED },
            { "_TOKEN.DynamicCharged", KSW_DYN_FIELD_ID_TOK_DYNAMIC_CHARGED },
            { "TokDynamicAvailable", KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE },
            { "_TOKEN.DynamicAvailable", KSW_DYN_FIELD_ID_TOK_DYNAMIC_AVAILABLE },
            { "TokDefaultOwnerIndex", KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX },
            { "_TOKEN.DefaultOwnerIndex", KSW_DYN_FIELD_ID_TOK_DEFAULT_OWNER_INDEX },
            { "TokUserAndGroups", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS },
            { "_TOKEN.UserAndGroups", KSW_DYN_FIELD_ID_TOK_USER_AND_GROUPS },
            { "TokRestrictedSids", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS },
            { "_TOKEN.RestrictedSids", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SIDS },
            { "TokPrimaryGroup", KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP },
            { "_TOKEN.PrimaryGroup", KSW_DYN_FIELD_ID_TOK_PRIMARY_GROUP },
            { "TokDynamicPart", KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART },
            { "_TOKEN.DynamicPart", KSW_DYN_FIELD_ID_TOK_DYNAMIC_PART },
            { "TokDefaultDacl", KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL },
            { "_TOKEN.DefaultDacl", KSW_DYN_FIELD_ID_TOK_DEFAULT_DACL },
            { "TokTokenType", KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE },
            { "_TOKEN.TokenType", KSW_DYN_FIELD_ID_TOK_TOKEN_TYPE },
            { "TokImpersonationLevel", KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL },
            { "_TOKEN.ImpersonationLevel", KSW_DYN_FIELD_ID_TOK_IMPERSONATION_LEVEL },
            { "TokTokenFlags", KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS },
            { "_TOKEN.TokenFlags", KSW_DYN_FIELD_ID_TOK_TOKEN_FLAGS },
            { "TokTokenInUse", KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE },
            { "_TOKEN.TokenInUse", KSW_DYN_FIELD_ID_TOK_TOKEN_IN_USE },
            { "TokIntegrityLevelIndex", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX },
            { "_TOKEN.IntegrityLevelIndex", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_INDEX },
            { "TokMandatoryPolicy", KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY },
            { "_TOKEN.MandatoryPolicy", KSW_DYN_FIELD_ID_TOK_MANDATORY_POLICY },
            { "TokLogonSession", KSW_DYN_FIELD_ID_TOK_LOGON_SESSION },
            { "_TOKEN.LogonSession", KSW_DYN_FIELD_ID_TOK_LOGON_SESSION },
            { "TokOriginatingLogonSession", KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION },
            { "_TOKEN.OriginatingLogonSession", KSW_DYN_FIELD_ID_TOK_ORIGINATING_LOGON_SESSION },
            { "TokSidHash", KSW_DYN_FIELD_ID_TOK_SID_HASH },
            { "_TOKEN.SidHash", KSW_DYN_FIELD_ID_TOK_SID_HASH },
            { "TokRestrictedSidHash", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH },
            { "_TOKEN.RestrictedSidHash", KSW_DYN_FIELD_ID_TOK_RESTRICTED_SID_HASH },
            { "TokPSecurityAttributes", KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES },
            { "_TOKEN.pSecurityAttributes", KSW_DYN_FIELD_ID_TOK_P_SECURITY_ATTRIBUTES },
            { "TokPackage", KSW_DYN_FIELD_ID_TOK_PACKAGE },
            { "_TOKEN.Package", KSW_DYN_FIELD_ID_TOK_PACKAGE },
            { "TokCapabilities", KSW_DYN_FIELD_ID_TOK_CAPABILITIES },
            { "_TOKEN.Capabilities", KSW_DYN_FIELD_ID_TOK_CAPABILITIES },
            { "TokCapabilityCount", KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT },
            { "_TOKEN.CapabilityCount", KSW_DYN_FIELD_ID_TOK_CAPABILITY_COUNT },
            { "TokCapabilitiesHash", KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH },
            { "_TOKEN.CapabilitiesHash", KSW_DYN_FIELD_ID_TOK_CAPABILITIES_HASH },
            { "TokLowboxNumberEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY },
            { "_TOKEN.LowboxNumberEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_NUMBER_ENTRY },
            { "TokLowboxHandlesEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY },
            { "_TOKEN.LowboxHandlesEntry", KSW_DYN_FIELD_ID_TOK_LOWBOX_HANDLES_ENTRY },
            { "TokPClaimAttributes", KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES },
            { "_TOKEN.pClaimAttributes", KSW_DYN_FIELD_ID_TOK_P_CLAIM_ATTRIBUTES },
            { "TokTrustLevelSid", KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID },
            { "_TOKEN.TrustLevelSid", KSW_DYN_FIELD_ID_TOK_TRUST_LEVEL_SID },
            { "TokTrustLinkedToken", KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN },
            { "_TOKEN.TrustLinkedToken", KSW_DYN_FIELD_ID_TOK_TRUST_LINKED_TOKEN },
            { "TokIntegrityLevelSidValue", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE },
            { "_TOKEN.IntegrityLevelSidValue", KSW_DYN_FIELD_ID_TOK_INTEGRITY_LEVEL_SID_VALUE },
            { "TokTokenSidValues", KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES },
            { "_TOKEN.TokenSidValues", KSW_DYN_FIELD_ID_TOK_TOKEN_SID_VALUES },
            { "TokSessionObject", KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT },
            { "_TOKEN.SessionObject", KSW_DYN_FIELD_ID_TOK_SESSION_OBJECT },
            { "TokVariablePart", KSW_DYN_FIELD_ID_TOK_VARIABLE_PART },
            { "_TOKEN.VariablePart", KSW_DYN_FIELD_ID_TOK_VARIABLE_PART },
            { "HtHandleContentionEvent", KSW_DYN_FIELD_ID_HT_HANDLE_CONTENTION_EVENT },
            { "HtTableCode", KSW_DYN_FIELD_ID_HT_TABLE_CODE },
            { "_HANDLE_TABLE.TableCode", KSW_DYN_FIELD_ID_HT_TABLE_CODE },
            { "HtHandleCount", KSW_DYN_FIELD_ID_HT_HANDLE_COUNT },
            { "_HANDLE_TABLE.HandleCount", KSW_DYN_FIELD_ID_HT_HANDLE_COUNT },
            { "HteLowValue", KSW_DYN_FIELD_ID_HTE_LOW_VALUE },
            { "_HANDLE_TABLE_ENTRY.LowValue", KSW_DYN_FIELD_ID_HTE_LOW_VALUE },
            { "OtName", KSW_DYN_FIELD_ID_OT_NAME },
            { "OtIndex", KSW_DYN_FIELD_ID_OT_INDEX },
            { "ObDecodeShift", KSW_DYN_FIELD_ID_OB_DECODE_SHIFT },
            { "ObAttributesShift", KSW_DYN_FIELD_ID_OB_ATTRIBUTES_SHIFT },
            { "KtInitialStack", KSW_DYN_FIELD_ID_KT_INITIAL_STACK },
            { "KtStackLimit", KSW_DYN_FIELD_ID_KT_STACK_LIMIT },
            { "KtStackBase", KSW_DYN_FIELD_ID_KT_STACK_BASE },
            { "KtKernelStack", KSW_DYN_FIELD_ID_KT_KERNEL_STACK },
            { "KtProcess", KSW_DYN_FIELD_ID_KT_PROCESS },
            { "_KTHREAD.Process", KSW_DYN_FIELD_ID_KT_PROCESS },
            { "EtCid", KSW_DYN_FIELD_ID_ET_CID },
            { "_ETHREAD.Cid", KSW_DYN_FIELD_ID_ET_CID },
            { "EtThreadListEntry", KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY },
            { "_ETHREAD.ThreadListEntry", KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY },
            { "EtStartAddress", KSW_DYN_FIELD_ID_ET_START_ADDRESS },
            { "_ETHREAD.StartAddress", KSW_DYN_FIELD_ID_ET_START_ADDRESS },
            { "EtWin32StartAddress", KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS },
            { "_ETHREAD.Win32StartAddress", KSW_DYN_FIELD_ID_ET_WIN32_START_ADDRESS },
            { "KtReadOperationCount", KSW_DYN_FIELD_ID_KT_READ_OPERATION_COUNT },
            { "KtWriteOperationCount", KSW_DYN_FIELD_ID_KT_WRITE_OPERATION_COUNT },
            { "KtOtherOperationCount", KSW_DYN_FIELD_ID_KT_OTHER_OPERATION_COUNT },
            { "KtReadTransferCount", KSW_DYN_FIELD_ID_KT_READ_TRANSFER_COUNT },
            { "KtWriteTransferCount", KSW_DYN_FIELD_ID_KT_WRITE_TRANSFER_COUNT },
            { "KtOtherTransferCount", KSW_DYN_FIELD_ID_KT_OTHER_TRANSFER_COUNT },
            { "MmSectionControlArea", KSW_DYN_FIELD_ID_MM_SECTION_CONTROL_AREA },
            { "MmControlAreaListHead", KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LIST_HEAD },
            { "MmControlAreaLock", KSW_DYN_FIELD_ID_MM_CONTROL_AREA_LOCK },
            { "AlpcCommunicationInfo", KSW_DYN_FIELD_ID_ALPC_COMMUNICATION_INFO },
            { "AlpcOwnerProcess", KSW_DYN_FIELD_ID_ALPC_OWNER_PROCESS },
            { "AlpcConnectionPort", KSW_DYN_FIELD_ID_ALPC_CONNECTION_PORT },
            { "AlpcServerCommunicationPort", KSW_DYN_FIELD_ID_ALPC_SERVER_COMMUNICATION_PORT },
            { "AlpcClientCommunicationPort", KSW_DYN_FIELD_ID_ALPC_CLIENT_COMMUNICATION_PORT },
            { "AlpcHandleTable", KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE },
            { "AlpcHandleTableLock", KSW_DYN_FIELD_ID_ALPC_HANDLE_TABLE_LOCK },
            { "AlpcAttributes", KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES },
            { "AlpcAttributesFlags", KSW_DYN_FIELD_ID_ALPC_ATTRIBUTES_FLAGS },
            { "AlpcPortContext", KSW_DYN_FIELD_ID_ALPC_PORT_CONTEXT },
            { "AlpcPortObjectLock", KSW_DYN_FIELD_ID_ALPC_PORT_OBJECT_LOCK },
            { "AlpcSequenceNo", KSW_DYN_FIELD_ID_ALPC_SEQUENCE_NO },
            { "AlpcState", KSW_DYN_FIELD_ID_ALPC_STATE },
            { "LxPicoProc", KSW_DYN_FIELD_ID_LX_PICO_PROC },
            { "LxPicoProcInfo", KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO },
            { "LxPicoProcInfoPID", KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO_PID },
            { "LxPicoThrdInfo", KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO },
            { "LxPicoThrdInfoTID", KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO_TID },
            { "EpProtection", KSW_DYN_FIELD_ID_EP_PROTECTION },
            { "EpSignatureLevel", KSW_DYN_FIELD_ID_EP_SIGNATURE_LEVEL },
            { "EpSectionSignatureLevel", KSW_DYN_FIELD_ID_EP_SECTION_SIGNATURE_LEVEL },
            { "EgeGuid", KSW_DYN_FIELD_ID_EGE_GUID },
            { "EreGuidEntry", KSW_DYN_FIELD_ID_ERE_GUID_ENTRY },
            { "KldrInLoadOrderLinks", KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS },
            { "_KLDR_DATA_TABLE_ENTRY.InLoadOrderLinks", KSW_DYN_FIELD_ID_KLDR_IN_LOAD_ORDER_LINKS },
            { "KldrDllBase", KSW_DYN_FIELD_ID_KLDR_DLL_BASE },
            { "_KLDR_DATA_TABLE_ENTRY.DllBase", KSW_DYN_FIELD_ID_KLDR_DLL_BASE },
            { "KldrSizeOfImage", KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE },
            { "_KLDR_DATA_TABLE_ENTRY.SizeOfImage", KSW_DYN_FIELD_ID_KLDR_SIZE_OF_IMAGE },
            { "KldrFullDllName", KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME },
            { "_KLDR_DATA_TABLE_ENTRY.FullDllName", KSW_DYN_FIELD_ID_KLDR_FULL_DLL_NAME },
            { "KldrBaseDllName", KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME },
            { "_KLDR_DATA_TABLE_ENTRY.BaseDllName", KSW_DYN_FIELD_ID_KLDR_BASE_DLL_NAME },
            { "KldrFlags", KSW_DYN_FIELD_ID_KLDR_FLAGS },
            { "_KLDR_DATA_TABLE_ENTRY.Flags", KSW_DYN_FIELD_ID_KLDR_FLAGS },
            { "DoDriverStart", KSW_DYN_FIELD_ID_DO_DRIVER_START },
            { "_DRIVER_OBJECT.DriverStart", KSW_DYN_FIELD_ID_DO_DRIVER_START },
            { "DoDriverSize", KSW_DYN_FIELD_ID_DO_DRIVER_SIZE },
            { "_DRIVER_OBJECT.DriverSize", KSW_DYN_FIELD_ID_DO_DRIVER_SIZE },
            { "DoDriverSection", KSW_DYN_FIELD_ID_DO_DRIVER_SECTION },
            { "_DRIVER_OBJECT.DriverSection", KSW_DYN_FIELD_ID_DO_DRIVER_SECTION },
            { "DoMajorFunction", KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION },
            { "_DRIVER_OBJECT.MajorFunction", KSW_DYN_FIELD_ID_DO_MAJOR_FUNCTION },
            { "DoFastIoDispatch", KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH },
            { "_DRIVER_OBJECT.FastIoDispatch", KSW_DYN_FIELD_ID_DO_FAST_IO_DISPATCH },
            { "DoDriverUnload", KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD },
            { "_DRIVER_OBJECT.DriverUnload", KSW_DYN_FIELD_ID_DO_DRIVER_UNLOAD },
            // 卸载驱动记录字段：
            // - 输入：PDB profile generator 输出的短字段名或 type.field 名称；
            // - 处理：映射到 shared DynData ID，供后续 apply-profile(-ex) 写入 R0；
            // - 返回：本表不返回值，调用方通过 fieldIdOut 获得协议字段编号。
            { "UldName", KSW_DYN_FIELD_ID_ULD_NAME },
            { "_UNLOADED_DRIVERS.Name", KSW_DYN_FIELD_ID_ULD_NAME },
            { "UldStartAddress", KSW_DYN_FIELD_ID_ULD_START_ADDRESS },
            { "_UNLOADED_DRIVERS.StartAddress", KSW_DYN_FIELD_ID_ULD_START_ADDRESS },
            { "UldEndAddress", KSW_DYN_FIELD_ID_ULD_END_ADDRESS },
            { "_UNLOADED_DRIVERS.EndAddress", KSW_DYN_FIELD_ID_ULD_END_ADDRESS },
            { "UldCurrentTime", KSW_DYN_FIELD_ID_ULD_CURRENT_TIME },
            { "_UNLOADED_DRIVERS.CurrentTime", KSW_DYN_FIELD_ID_ULD_CURRENT_TIME },
            { "UldTypeSize", KSW_DYN_FIELD_ID_ULD_TYPE_SIZE },
            { "_UNLOADED_DRIVERS.TypeSize", KSW_DYN_FIELD_ID_ULD_TYPE_SIZE },
            { "RtlAvlBalancedRoot", KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT },
            { "_RTL_AVL_TABLE.BalancedRoot", KSW_DYN_FIELD_ID_RTL_AVL_BALANCED_ROOT },
            { "RtlAvlOrderedPointer", KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER },
            { "_RTL_AVL_TABLE.OrderedPointer", KSW_DYN_FIELD_ID_RTL_AVL_ORDERED_POINTER },
            { "RtlAvlWhichOrderedElement", KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT },
            { "_RTL_AVL_TABLE.WhichOrderedElement", KSW_DYN_FIELD_ID_RTL_AVL_WHICH_ORDERED_ELEMENT },
            { "RtlAvlNumberGenericTableElements", KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS },
            { "_RTL_AVL_TABLE.NumberGenericTableElements", KSW_DYN_FIELD_ID_RTL_AVL_NUMBER_GENERIC_TABLE_ELEMENTS },
            { "RtlAvlDepthOfTree", KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE },
            { "_RTL_AVL_TABLE.DepthOfTree", KSW_DYN_FIELD_ID_RTL_AVL_DEPTH_OF_TREE },
            { "RtlAvlRestartKey", KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY },
            { "_RTL_AVL_TABLE.RestartKey", KSW_DYN_FIELD_ID_RTL_AVL_RESTART_KEY },
            { "RtlAvlDeleteCount", KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT },
            { "_RTL_AVL_TABLE.DeleteCount", KSW_DYN_FIELD_ID_RTL_AVL_DELETE_COUNT },
            { "RtlAvlTypeSize", KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE },
            { "_RTL_AVL_TABLE.TypeSize", KSW_DYN_FIELD_ID_RTL_AVL_TYPE_SIZE },
            { "PiDdbDriverName", KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME },
            { "_PIDDB_CACHE_ENTRY.DriverName", KSW_DYN_FIELD_ID_PIDDB_DRIVER_NAME },
            { "PiDdbTimeDateStamp", KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP },
            { "_PIDDB_CACHE_ENTRY.TimeDateStamp", KSW_DYN_FIELD_ID_PIDDB_TIME_DATE_STAMP },
            { "PiDdbLoadStatus", KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS },
            { "_PIDDB_CACHE_ENTRY.LoadStatus", KSW_DYN_FIELD_ID_PIDDB_LOAD_STATUS },
            { "PiDdbTypeSize", KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE },
            { "_PIDDB_CACHE_ENTRY.TypeSize", KSW_DYN_FIELD_ID_PIDDB_TYPE_SIZE },
            { "PspCidTable", KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE },
            { "PsLoadedModuleList", KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST },
            { "MmUnloadedDrivers", KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS },
            { "PiDDBCacheTable", KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE },
            { "PiDDBLock", KSW_DYN_FIELD_ID_KG_PIDDB_LOCK },
            // Kernel Global RVA 映射：
            // - 输入：PDB profile pack 中的 Shadow SSDT 全局符号名；
            // - 处理：映射到 shared DynData 字段 ID，避免 EX apply 将该项计入 ignored；
            // - 返回：本表不返回值，调用方通过 fieldIdOut 获得协议字段编号。
            { "KeServiceDescriptorTableShadow", KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW },
            { "KgKeServiceDescriptorTableShadow", KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW },
            { "MmLastUnloadedDriver", KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER },
            { "PspCreateProcessNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE },
            { "PspCreateThreadNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE },
            { "PspLoadImageNotifyRoutine", KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE },
            { "PspNotifyEnableMask", KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK },
            { "CmCallbackListHead", KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD },
            { "_OBJECT_TYPE.CallbackList", KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST },
            { "_CALLBACK_ENTRY_ITEM.EntryList", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST },
            { "_CALLBACK_ENTRY_ITEM.EntryItemList", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST },
            { "_CALLBACK_ENTRY_ITEM.PreOperation", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION },
            { "_CALLBACK_ENTRY_ITEM.PostOperation", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION },
            { "_CALLBACK_ENTRY_ITEM.Operations", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS },
            { "_CALLBACK_ENTRY_ITEM.CallbackEntry", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY },
            { "_CALLBACK_ENTRY.Altitude", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE },
            { "_CALLBACK_ENTRY.RegistrationContext", KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT }
        };

        const auto iterator = kFieldIds.find(fieldName.toStdString());
        if (iterator == kFieldIds.end())
        {
            fieldIdOut = 0U;
            return false;
        }

        fieldIdOut = iterator->second;
        return true;
    }


    // fieldIdIsCallbackGlobal：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 callbackItems/v2 使用的 callback 全局 RVA；
    // - 返回：true 表示该字段应作为 callback GlobalRva 发送给 EX IOCTL。
    bool fieldIdIsCallbackGlobal(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_CB_PSP_CREATE_PROCESS_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_CREATE_THREAD_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_LOAD_IMAGE_NOTIFY_ROUTINE:
        case KSW_DYN_FIELD_ID_CB_PSP_NOTIFY_ENABLE_MASK:
        case KSW_DYN_FIELD_ID_CB_CM_CALLBACK_LIST_HEAD:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsKernelGlobal：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 v3 typed items 使用的内核全局 RVA；
    // - 返回：true 表示该字段应作为非 callback GlobalRva 发送给 EX IOCTL。
    bool fieldIdIsKernelGlobal(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_KG_PSP_CID_TABLE:
        case KSW_DYN_FIELD_ID_KG_PS_LOADED_MODULE_LIST:
        case KSW_DYN_FIELD_ID_KG_MM_UNLOADED_DRIVERS:
        case KSW_DYN_FIELD_ID_KG_PIDDB_CACHE_TABLE:
        case KSW_DYN_FIELD_ID_KG_PIDDB_LOCK:
        case KSW_DYN_FIELD_ID_KG_KE_SERVICE_DESCRIPTOR_TABLE_SHADOW:
        case KSW_DYN_FIELD_ID_KG_MM_LAST_UNLOADED_DRIVER:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsGlobalRva：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：汇总 callback 和 kernel global 两类 GlobalRva 项；
    // - 返回：true 表示字段值应按 RVA 校验和提交。
    bool fieldIdIsGlobalRva(const std::uint32_t fieldId)
    {
        return fieldIdIsCallbackGlobal(fieldId) || fieldIdIsKernelGlobal(fieldId);
    }

    // fieldIdIsCallbackOffset：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 callbackItems/v2 使用的 callback 结构偏移；
    // - 返回：true 表示该字段应作为 callback StructOffset 发送给 EX IOCTL。
    bool fieldIdIsCallbackOffset(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_CB_OBJECT_TYPE_CALLBACK_LIST:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_ENTRY_LIST:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_PRE_OPERATION:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_POST_OPERATION:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_OPERATIONS:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ITEM_CALLBACK_ENTRY:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_ALTITUDE:
        case KSW_DYN_FIELD_ID_CB_CALLBACK_ENTRY_REGISTRATION_CONTEXT:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsLxcoreOffset：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：识别 System Informer lxcore profile 字段，当前 ntoskrnl PDB EX apply 不承载这些字段；
    // - 返回：true 表示该字段不能放入 ntoskrnl v3 StructOffset typed item。
    bool fieldIdIsLxcoreOffset(const std::uint32_t fieldId)
    {
        switch (fieldId)
        {
        case KSW_DYN_FIELD_ID_LX_PICO_PROC:
        case KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO:
        case KSW_DYN_FIELD_ID_LX_PICO_PROC_INFO_PID:
        case KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO:
        case KSW_DYN_FIELD_ID_LX_PICO_THRD_INFO_TID:
            return true;
        default:
            return false;
        }
    }

    // fieldIdIsStructOffset：
    // - 输入 fieldId：共享协议字段 ID；
    // - 处理：排除 GlobalRva 和 lxcore-only 字段后，允许已知字段通过 StructOffset 路径应用；
    // - 返回：true 表示字段值应按结构偏移校验和提交。
    bool fieldIdIsStructOffset(const std::uint32_t fieldId)
    {
        return fieldId != 0U &&
            fieldId <= KSW_DYN_FIELD_ID_MAX &&
            !fieldIdIsGlobalRva(fieldId) &&
            !fieldIdIsLxcoreOffset(fieldId);
    }

    QString callbackItemKindText(const QString& kindText)
    {
        const QString normalized = kindText.trimmed();
        if (normalized.compare(QStringLiteral("GlobalRva"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("GlobalRva");
        }
        if (normalized.compare(QStringLiteral("StructOffset"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("StructOffset");
        }
        if (normalized.compare(QStringLiteral("TypeSize"), Qt::CaseInsensitive) == 0)
        {
            return QStringLiteral("TypeSize");
        }
        return normalized;
    }

    // profileContainsExItem：
    // - 输入 profile/fieldId：当前本地 profile 和候选字段 ID；
    // - 处理：扫描已展开的 EX item，避免 callbackItems 与 v3 items 重复提交；
    // - 返回：true 表示字段 ID 已存在。
    bool profileContainsExItem(const LocalPdbProfile& profile, const std::uint32_t fieldId)
    {
        return std::any_of(
            profile.applyExInput.items.begin(),
            profile.applyExInput.items.end(),
            [fieldId](const ksword::ark::DynDataProfileExItem& item) {
                return item.itemId == fieldId;
            });
    }

    // appendProfileExItem：
    // - 输入 profile/fieldId/itemKind/value/required：待追加的 typed item 数据；
    // - 处理：设置 EX IOCTL 所需 itemKind、value 和 callback/required 标志；
    // - 返回：无返回值，profile.applyExInput.items 会按需追加一项。
    void appendProfileExItem(
        LocalPdbProfile& profile,
        const std::uint32_t fieldId,
        const std::uint32_t itemKind,
        const std::uint32_t value,
        const bool required)
    {
        ksword::ark::DynDataProfileExItem exItem{};
        exItem.itemId = fieldId;
        exItem.itemKind = itemKind;
        exItem.value = value;
        exItem.flags = required ? KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED : 0U;
        if (fieldIdIsCallbackGlobal(fieldId) || fieldIdIsCallbackOffset(fieldId))
        {
            exItem.flags |= KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
        }
        profile.applyExInput.items.push_back(exItem);
        profile.exAppliedCount = static_cast<std::uint32_t>(profile.applyExInput.items.size());
    }

    // parseProfileUInt32 前置声明：
    // - 输入 value：JSON 数值或字符串；
    // - 处理/返回：实际解析逻辑位于下方定义，此处只允许 callbackItems 解析 helper 提前调用。
    bool parseProfileUInt32(const QJsonValue& value, std::uint32_t& valueOut);

    bool loadCallbackItemsFromJson(
        const QJsonArray& callbackItemsArray,
        LocalPdbProfile& profile,
        QStringList& diagnostics,
        bool& hasCallbackItemsOut)
    {
        hasCallbackItemsOut = false;
        if (callbackItemsArray.isEmpty())
        {
            return true;
        }

        hasCallbackItemsOut = true;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& itemValue : callbackItemsArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.non_object", QStringLiteral("callbackItems 包含非对象项，已忽略。"));
                continue;
            }

            const QJsonObject itemObject = itemValue.toObject();
            const QString itemName = itemObject.value(QStringLiteral("name")).toString().trimmed();
            const QString itemKind = callbackItemKindText(itemObject.value(QStringLiteral("kind")).toString());
            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(itemName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }

            std::uint32_t value = 0U;
            if (!parseProfileUInt32(itemObject.value(QStringLiteral("value")), value))
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.parse_failed", QStringLiteral("callbackItems 解析失败: %1")).arg(itemName);
                return false;
            }

            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId])
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.duplicate", QStringLiteral("callbackItems 含重复字段: %1")).arg(itemName);
                return false;
            }
            seenFieldIds[fieldId] = true;

            if (itemKind == QStringLiteral("GlobalRva"))
            {
                if (!fieldIdIsCallbackGlobal(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_global_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 global")).arg(itemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.global_rva_out_of_range", QStringLiteral("callbackItems global RVA 越界: %1")).arg(itemName);
                    return false;
                }
                ksword::ark::DynDataProfileExItem exItem{};
                exItem.itemId = fieldId;
                exItem.itemKind = KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA;
                exItem.value = value;
                exItem.flags = KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED | KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
                profile.applyExInput.items.push_back(exItem);
            }
            else if (itemKind == QStringLiteral("StructOffset"))
            {
                if (!fieldIdIsCallbackOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_struct_offset_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 struct offset")).arg(itemName);
                    return false;
                }
                ksword::ark::DynDataProfileExItem exItem{};
                exItem.itemId = fieldId;
                exItem.itemKind = KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET;
                exItem.value = value;
                exItem.flags = KSW_DYN_PROFILE_EX_ITEM_FLAG_REQUIRED | KSW_DYN_PROFILE_EX_ITEM_FLAG_CALLBACK;
                profile.applyExInput.items.push_back(exItem);
            }
            else if (itemKind == QStringLiteral("TypeSize"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.callback.kind_type_size_mismatch", QStringLiteral("callbackItems 语义不匹配: %1 不是 type size")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, true);
            }
            else
            {
                diagnostics << kernelText("kernel.dyndata.profile.callback.kind_unsupported", QStringLiteral("callbackItems kind 不支持: %1")).arg(itemName);
                return false;
            }

            profile.callbackItemCount += 1U;
        }

        profile.exAppliedCount = static_cast<std::uint32_t>(profile.applyExInput.items.size());
        return true;
    }

    // loadTypedItemsFromJson：
    // - 输入 typedItemsArray/profile/diagnostics/hasTypedItemsOut：v3 items 数组、输出 profile 和诊断容器；
    // - 处理：解析 name/kind/value，把 StructOffset 与 GlobalRva 统一展开为 EX IOCTL item；
    // - 返回：true 表示 typed items 可用或为空；false 表示命中项语义/范围错误。
    bool loadTypedItemsFromJson(
        const QJsonArray& typedItemsArray,
        LocalPdbProfile& profile,
        QStringList& diagnostics,
        bool& hasTypedItemsOut)
    {
        hasTypedItemsOut = false;
        if (typedItemsArray.isEmpty())
        {
            return true;
        }

        hasTypedItemsOut = true;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& itemValue : typedItemsArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.non_object", QStringLiteral("typed items 包含非对象项，已忽略。"));
                continue;
            }

            const QJsonObject itemObject = itemValue.toObject();
            const QString itemName = itemObject.value(QStringLiteral("name")).toString().trimmed();
            const QString itemKind = callbackItemKindText(itemObject.value(QStringLiteral("kind")).toString());
            const bool required = itemObject.value(QStringLiteral("required")).toBool(false);

            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(itemName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }

            std::uint32_t value = 0U;
            if (!parseProfileUInt32(itemObject.value(QStringLiteral("value")), value))
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.parse_failed", QStringLiteral("typed items 解析失败: %1")).arg(itemName);
                return false;
            }

            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId] || profileContainsExItem(profile, fieldId))
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.duplicate", QStringLiteral("typed items 含重复字段: %1")).arg(itemName);
                return false;
            }
            seenFieldIds[fieldId] = true;

            if (itemKind == QStringLiteral("GlobalRva"))
            {
                if (!fieldIdIsGlobalRva(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_global_rva_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 global RVA")).arg(itemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_GLOBAL_RVA_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.global_rva_out_of_range", QStringLiteral("typed items global RVA 越界: %1")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA, value, required);
            }
            else if (itemKind == QStringLiteral("StructOffset"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_struct_offset_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 struct offset")).arg(itemName);
                    return false;
                }
                if (value == 0xFFFFFFFFU || value > KSW_DYN_PROFILE_OFFSET_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.struct_offset_out_of_range", QStringLiteral("typed items struct offset 越界: %1")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, required);
            }
            else if (itemKind == QStringLiteral("TypeSize"))
            {
                if (!fieldIdIsStructOffset(fieldId))
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.kind_type_size_mismatch", QStringLiteral("typed items 语义不匹配: %1 不是 type size")).arg(itemName);
                    return false;
                }
                if (value == 0U || value > KSW_DYN_PROFILE_OFFSET_MAX)
                {
                    diagnostics << kernelText("kernel.dyndata.profile.typed.type_size_out_of_range", QStringLiteral("typed items type size 越界: %1")).arg(itemName);
                    return false;
                }
                appendProfileExItem(profile, fieldId, KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET, value, required);
            }
            else
            {
                diagnostics << kernelText("kernel.dyndata.profile.typed.kind_unsupported", QStringLiteral("typed items kind 不支持: %1")).arg(itemName);
                return false;
            }
            profile.typedItemCount += 1U;
        }

        return true;
    }

    // parseProfileUInt32：
    // - 输入 value：JSON 数值或 0x 前缀字符串；
    // - 处理：进行 32-bit 无符号范围校验；
    // - 返回：成功解析 true，失败 false。
    bool parseProfileUInt32(const QJsonValue& value, std::uint32_t& valueOut)
    {
        bool ok = false;
        qulonglong parsedValue = 0ULL;

        valueOut = 0U;
        if (value.isString())
        {
            QString text = value.toString().trimmed();
            int base = 10;
            if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
            {
                text = text.mid(2);
                base = 16;
            }
            parsedValue = text.toULongLong(&ok, base);
        }
        else if (value.isDouble())
        {
            const double numericValue = value.toDouble();
            if (numericValue >= 0.0 && numericValue <= static_cast<double>(std::numeric_limits<std::uint32_t>::max()))
            {
                parsedValue = static_cast<qulonglong>(numericValue);
                ok = true;
            }
        }

        if (!ok || parsedValue > static_cast<qulonglong>(std::numeric_limits<std::uint32_t>::max()))
        {
            return false;
        }

        valueOut = static_cast<std::uint32_t>(parsedValue);
        return true;
    }

    template <std::size_t Size>
    void copyV4Utf8(char (&destination)[Size], const QString& source)
    {
        static_assert(Size > 0U);
        const QByteArray bytes = source.toUtf8();
        const std::size_t copyLength = std::min<std::size_t>(Size - 1U, static_cast<std::size_t>(bytes.size()));
        std::memset(destination, 0, Size);
        if (copyLength != 0U)
        {
            std::memcpy(destination, bytes.constData(), copyLength);
        }
    }

    template <std::size_t Size>
    void copyV4Wide(wchar_t (&destination)[Size], const std::wstring& source)
    {
        static_assert(Size > 0U);
        const std::size_t copyLength = std::min<std::size_t>(Size - 1U, source.size());
        std::fill(std::begin(destination), std::end(destination), L'\0');
        if (copyLength != 0U)
        {
            std::copy_n(source.begin(), copyLength, destination);
        }
    }

    bool v4ItemIdSupported(const std::uint32_t itemId)
    {
        if (itemId >= 1U && itemId <= KSW_DYN_FIELD_ID_MAX)
        {
            return true;
        }
        switch (itemId)
        {
        case KSW_DYN_V4_ITEM_ID_ETH_ACTIVE_EX_WORKER:
        case KSW_DYN_V4_ITEM_ID_KPRCB_TIMER_TABLE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TIMER_ENTRIES:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_ENTRY:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_LIST_ENTRY:
        case KSW_DYN_V4_ITEM_ID_KTIMER_DUE_TIME:
        case KSW_DYN_V4_ITEM_ID_KTIMER_DPC:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TIMER_TYPE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_PERIOD:
        case KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_ROUTINE:
        case KSW_DYN_V4_ITEM_ID_KDPC_DEFERRED_CONTEXT:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TABLE_ENTRY_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_KTIMER_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_KDPC_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_FLT_FILTER_OPERATIONS:
        case KSW_DYN_V4_ITEM_ID_CI_KERNEL_HASH_BUCKET_LIST:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_CACHE_LOCK:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_NEXT:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_DRIVER_NAME:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TIME_DATE_STAMP:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_LOAD_STATUS:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_BASE:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_IMAGE_SIZE:
        case KSW_DYN_V4_ITEM_ID_CI_HASH_ENTRY_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_PSP_SYSTEM_PARTITION:
        case KSW_DYN_V4_ITEM_ID_WQ_EXP_BUILTIN_PRIORITIES:
        case KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_EX_PARTITION:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_WORK_QUEUES:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_WORK_PRI_QUEUE:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_QUEUE_INDEX:
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_ENTRY_LIST_HEAD:
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_THREAD_LIST_HEAD:
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE:
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_QUEUE_LIST_ENTRY:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_LIST:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_ROUTINE:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_PARAMETER:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_POOL_UNTRUSTED:
        case KSW_DYN_V4_ITEM_ID_WQ_EPARTITION_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_PARTITION_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_EX_WORK_QUEUE_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_KPRI_QUEUE_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_KTHREAD_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_WORK_ITEM_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_START_ADDRESS:
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TYPE_SIZE:
        case KSW_DYN_V4_ITEM_ID_WQ_ETHREAD_TCB:
            return true;
        default:
            return false;
        }
    }

    bool loadV4ItemsFromJson(
        const QJsonArray& itemArray,
        const QJsonArray& groupArray,
        const ksword::ark::ArkDynModuleIdentity& currentIdentity,
        const QString& profileName,
        const QString& pdbName,
        const QString& pdbGuid,
        const std::uint32_t pdbAge,
        LocalPdbProfile& profile,
        QStringList& diagnostics)
    {
        if (itemArray.isEmpty() || groupArray.isEmpty() ||
            itemArray.size() > static_cast<int>(KSW_DYN_V4_MAX_ITEMS_PER_MODULE) ||
            groupArray.size() > static_cast<int>(KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE))
        {
            diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
            return false;
        }

        std::array<bool, KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE + 1U> seenGroups{};
        std::unordered_map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> expectedCounts;
        profile.applyV4Input.capabilityGroups.clear();
        profile.applyV4Input.items.clear();
        for (const QJsonValue& groupValue : groupArray)
        {
            if (!groupValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            const QJsonObject groupObject = groupValue.toObject();
            std::uint32_t groupId = 0U;
            std::uint32_t flags = 0U;
            std::uint32_t requiredCount = 0U;
            std::uint32_t optionalCount = 0U;
            if (!parseProfileUInt32(groupObject.value(QStringLiteral("groupId")), groupId) ||
                !parseProfileUInt32(groupObject.value(QStringLiteral("flags")), flags) ||
                !parseProfileUInt32(groupObject.value(QStringLiteral("requiredItemCount")), requiredCount) ||
                !parseProfileUInt32(groupObject.value(QStringLiteral("optionalItemCount")), optionalCount) ||
                groupId == 0U || groupId > KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE || seenGroups[groupId])
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            seenGroups[groupId] = true;
            KSW_DYN_V4_CAPABILITY_GROUP_PACKET group{};
            group.groupId = groupId;
            group.flags = flags;
            group.requiredItemCount = requiredCount;
            group.optionalItemCount = optionalCount;
            copyV4Utf8(group.groupName, groupObject.value(QStringLiteral("groupName")).toString());
            profile.applyV4Input.capabilityGroups.push_back(group);
            expectedCounts[groupId] = {requiredCount, optionalCount};
        }

        std::array<bool, 2048U> seenItems{};
        std::unordered_map<std::uint32_t, std::pair<std::uint32_t, std::uint32_t>> actualCounts;
        for (const QJsonValue& itemValue : itemArray)
        {
            if (!itemValue.isObject())
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            const QJsonObject itemObject = itemValue.toObject();
            std::uint32_t itemId = 0U;
            std::uint32_t itemKind = 0U;
            std::uint32_t flags = 0U;
            std::uint32_t groupId = 0U;
            std::uint32_t valueLow = 0U;
            std::uint32_t valueHigh = 0U;
            std::uint32_t aux[4]{};
            if (!parseProfileUInt32(itemObject.value(QStringLiteral("itemId")), itemId) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("itemKind")), itemKind) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("flags")), flags) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("capabilityGroupId")), groupId) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("valueLow")), valueLow) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("valueHigh")), valueHigh) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux0")), aux[0]) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux1")), aux[1]) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux2")), aux[2]) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("aux3")), aux[3]) ||
                !v4ItemIdSupported(itemId) || itemId >= seenItems.size() || seenItems[itemId] ||
                itemKind < KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET || itemKind > KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL ||
                (flags != KSW_DYN_V4_ITEM_FLAG_REQUIRED && flags != KSW_DYN_V4_ITEM_FLAG_OPTIONAL) ||
                groupId == 0U || !seenGroups[groupId])
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 无效。"));
                return false;
            }
            seenItems[itemId] = true;
            KSW_DYN_V4_ITEM_PACKET item{};
            item.itemId = itemId;
            item.itemKind = itemKind;
            item.flags = flags;
            item.capabilityGroupId = groupId;
            item.valueLow = valueLow;
            item.valueHigh = valueHigh;
            item.aux0 = aux[0];
            item.aux1 = aux[1];
            item.aux2 = aux[2];
            item.aux3 = aux[3];
            profile.applyV4Input.items.push_back(item);
            // v4 core items are the single source of truth.  Derive the
            // legacy EX projection in memory so existing field consumers keep
            // working without storing a second offset array in the pack.
            if (itemId >= 1U && itemId <= KSW_DYN_FIELD_ID_MAX &&
                (itemKind == KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_TYPE_SIZE ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA ||
                 itemKind == KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL))
            {
                const std::uint32_t exKind =
                    (itemKind == KSW_DYN_V4_ITEM_KIND_GLOBAL_RVA ||
                     itemKind == KSW_DYN_V4_ITEM_KIND_LIST_HEAD_GLOBAL)
                    ? KSW_DYN_PROFILE_EX_ITEM_KIND_GLOBAL_RVA
                    : KSW_DYN_PROFILE_EX_ITEM_KIND_STRUCT_OFFSET;
                appendProfileExItem(
                    profile,
                    itemId,
                    exKind,
                    valueLow,
                    (flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U);
            }
            auto& counts = actualCounts[groupId];
            if ((flags & KSW_DYN_V4_ITEM_FLAG_REQUIRED) != 0U)
            {
                counts.first += 1U;
            }
            else
            {
                counts.second += 1U;
            }
        }
        for (const auto& expected : expectedCounts)
        {
            const auto actual = actualCounts[expected.first];
            if (actual != expected.second)
            {
                diagnostics << kernelText("kernel.dyndata.pack.v4.invalid", QStringLiteral("v4 pack items/capabilityGroups 计数不一致。"));
                return false;
            }
        }

        profile.applyV4Input.flags = 0U;
        profile.applyV4Input.module.image.present = currentIdentity.present ? 1UL : 0UL;
        profile.applyV4Input.module.image.classId = currentIdentity.classId;
        profile.applyV4Input.module.image.machine = currentIdentity.machine;
        profile.applyV4Input.module.image.timeDateStamp = currentIdentity.timeDateStamp;
        profile.applyV4Input.module.image.sizeOfImage = currentIdentity.sizeOfImage;
        profile.applyV4Input.module.image.imageBase = currentIdentity.imageBase;
        copyV4Wide(profile.applyV4Input.module.image.moduleName, currentIdentity.moduleName);
        copyV4Utf8(profile.applyV4Input.module.profileName, profileName);
        copyV4Utf8(profile.applyV4Input.module.pdb.pdbName, pdbName);
        copyV4Utf8(profile.applyV4Input.module.pdb.pdbGuid, pdbGuid);
        profile.applyV4Input.module.pdb.pdbAge = pdbAge;
        profile.applyExInput.profileName = profileName.toStdString();
        profile.applyExInput.pdbName = pdbName.toStdString();
        profile.applyExInput.pdbGuid = pdbGuid.toStdString();
        profile.applyExInput.pdbAge = pdbAge;
        profile.applyExInput.ntoskrnl = currentIdentity;
        profile.v4ItemCount = static_cast<std::uint32_t>(profile.applyV4Input.items.size());
        return true;
    }

    // profileClassIdFromText：
    // - 输入 classText：JSON module.class；
    // - 处理：转换到 R0 profile class id；
    // - 返回：成功 true，未知 class false。
    bool profileClassIdFromText(const QString& classText, std::uint32_t& classIdOut)
    {
        const QString normalized = classText.trimmed().toLower();
        if (normalized == QStringLiteral("ntoskrnl") ||
            normalized == QStringLiteral("ntoskrnl.exe") ||
            normalized == QStringLiteral("ntkrnlmp") ||
            normalized == QStringLiteral("ntkrnlmp.exe"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_NTOSKRNL;
            return true;
        }
        if (normalized == QStringLiteral("ntkrla57") || normalized == QStringLiteral("ntkrla57.exe"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_NTKRLA57;
            return true;
        }
        if (normalized == QStringLiteral("fltmgr") || normalized == QStringLiteral("fltmgr.sys"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_FLTMGR;
            return true;
        }
        if (normalized == QStringLiteral("ci") ||
            normalized == QStringLiteral("ci.dll") ||
            normalized == QStringLiteral("ci.sys"))
        {
            classIdOut = KSW_DYN_PROFILE_CLASS_CI;
            return true;
        }

        classIdOut = 0U;
        return false;
    }

    // profileClassIdFromJsonValue：
    // - 输入 value：pack profile 中的 moduleClassId；
    // - 处理：解析 uint32 并限制到已知 class；
    // - 返回：成功 true，失败 false。
    bool profileClassIdFromJsonValue(const QJsonValue& value, std::uint32_t& classIdOut)
    {
        std::uint32_t parsedValue = 0U;
        if (!parseProfileUInt32(value, parsedValue))
        {
            classIdOut = 0U;
            return false;
        }

        switch (parsedValue)
        {
        case KSW_DYN_PROFILE_CLASS_NTOSKRNL:
        case KSW_DYN_PROFILE_CLASS_NTKRLA57:
        case KSW_DYN_PROFILE_CLASS_LXCORE:
        case KSW_DYN_PROFILE_CLASS_FLTMGR:
        case KSW_DYN_PROFILE_CLASS_CI:
            classIdOut = parsedValue;
            return true;
        default:
            classIdOut = 0U;
            return false;
        }
    }

    // appendUniquePath：
    // - 输入 paths/pathText：待维护列表和候选路径；
    // - 处理：清理路径并进行大小写不敏感去重；
    // - 返回：无，paths 按需追加。
    void appendUniquePath(QStringList& paths, const QString& pathText)
    {
        const QString trimmed = pathText.trimmed();
        if (trimmed.isEmpty())
        {
            return;
        }

        const QString cleaned = QDir::cleanPath(trimmed);
        if (!cleaned.isEmpty() && !paths.contains(cleaned, Qt::CaseInsensitive))
        {
            paths << cleaned;
        }
    }

    // profilePackSearchPaths：
    // - 输入：无；
    // - 处理：优先读取程序目录 pack，并允许环境变量指定调试 pack；
    // - 返回：候选 pack 文件路径列表，不保证存在。
    QStringList profilePackSearchPaths()
    {
        QStringList paths;
        appendUniquePath(paths, qEnvironmentVariable("KSWORD_ARK_PROFILE_PACK"));
        appendUniquePath(paths, QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        appendUniquePath(paths, QDir::current().filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        return paths;
    }

    // profileSearchDirectories：
    // - 输入：无；
    // - 处理：仅当 KSWORD_ARK_PROFILE_DIR 显式设置时启用散落 JSON 调试 fallback；
    // - 返回：候选目录列表，不保证目录存在。
    QStringList profileSearchDirectories()
    {
        QStringList directories;
        appendUniquePath(directories, qEnvironmentVariable("KSWORD_ARK_PROFILE_DIR"));
        return directories;
    }

    // loadPdbProfileFile：
    // - 输入 filePath/currentIdentity：候选 JSON 文件和当前 R0 ntoskrnl identity；
    // - 处理：解析 module identity、字段表和 offset 范围；
    // - 返回：LocalPdbProfile；matched=false 表示不是当前内核 profile。
    LocalPdbProfile loadPdbProfileFile(const QString& filePath, const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbProfile profile;
        profile.sourceText = QStringLiteral("scattered-json");
        profile.pathText = QDir::toNativeSeparators(filePath);

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument document = ks::profile::readProfileJsonDocument(filePath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            profile.diagnosticsText = readErrorText.isEmpty()
                ? kernelText("kernel.dyndata.profile.json_parse_failed", QStringLiteral("JSON 解析失败: %1")).arg(parseError.errorString())
                : readErrorText;
            return profile;
        }

        const QJsonObject rootObject = document.object();
        const QJsonObject moduleObject = rootObject.value(QStringLiteral("module")).toObject();
        std::uint32_t profileClass = 0U;
        std::uint32_t machine = 0U;
        std::uint32_t timeDateStamp = 0U;
        std::uint32_t sizeOfImage = 0U;
        if (!profileClassIdFromText(moduleObject.value(QStringLiteral("class")).toString(), profileClass) ||
            !parseProfileUInt32(moduleObject.value(QStringLiteral("machine")), machine) ||
            !parseProfileUInt32(moduleObject.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
            !parseProfileUInt32(moduleObject.value(QStringLiteral("sizeOfImage")), sizeOfImage))
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.identity_missing", QStringLiteral("profile module identity 字段缺失或格式无效。"));
            return profile;
        }

        profile.matched = currentIdentity.present &&
            currentIdentity.classId == profileClass &&
            currentIdentity.machine == machine &&
            currentIdentity.timeDateStamp == timeDateStamp &&
            currentIdentity.sizeOfImage == sizeOfImage;
        if (!profile.matched)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.identity_mismatch", QStringLiteral("profile identity 不匹配当前内核。"));
            return profile;
        }

        const QJsonObject fieldsObject = rootObject.value(QStringLiteral("fields")).toObject();
        profile.applyInput.profileName = rootObject.value(QStringLiteral("profileName")).toString(QFileInfo(filePath).baseName()).toStdString();
        profile.applyInput.pdbName = moduleObject.value(QStringLiteral("pdbName")).toString().toStdString();
        profile.applyInput.pdbGuid = moduleObject.value(QStringLiteral("pdbGuid")).toString().toStdString();
        std::uint32_t pdbAge = 0U;
        if (parseProfileUInt32(moduleObject.value(QStringLiteral("pdbAge")), pdbAge))
        {
            profile.applyInput.pdbAge = pdbAge;
        }
        profile.applyInput.ntoskrnl = currentIdentity;

        std::uint32_t invalidOffsetCount = 0U;
        for (auto iterator = fieldsObject.constBegin(); iterator != fieldsObject.constEnd(); ++iterator)
        {
            std::uint32_t fieldId = 0U;
            std::uint32_t offset = 0U;
            if (!fieldIdForProfileName(iterator.key(), fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }
            if (!parseProfileUInt32(iterator.value(), offset) ||
                offset == 0xFFFFFFFFU ||
                offset > KSW_DYN_PROFILE_OFFSET_MAX)
            {
                invalidOffsetCount += 1U;
                continue;
            }

            ksword::ark::DynDataProfileField field{};
            field.fieldId = fieldId;
            field.offset = offset;
            profile.applyInput.fields.push_back(field);
        }

        QJsonArray typedItemsArray = rootObject.value(QStringLiteral("items")).toArray();
        if (typedItemsArray.isEmpty())
        {
            typedItemsArray = rootObject.value(QStringLiteral("typedItems")).toArray();
        }
        const QJsonArray callbackItemsArray = typedItemsArray.isEmpty()
            ? rootObject.value(QStringLiteral("callbackItems")).toArray()
            : QJsonArray();
        QStringList callbackDiagnostics;
        bool hasCallbackItems = false;
        if (!callbackItemsArray.isEmpty() && !loadCallbackItemsFromJson(callbackItemsArray, profile, callbackDiagnostics, hasCallbackItems))
        {
            profile.diagnosticsText = callbackDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasCallbackItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
        }
        QStringList typedDiagnostics;
        bool hasTypedItems = false;
        if (!loadTypedItemsFromJson(typedItemsArray, profile, typedDiagnostics, hasTypedItems))
        {
            profile.diagnosticsText = typedDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasTypedItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
            profile.applyInput.fields.clear();
        }
        if (fieldsObject.isEmpty() && !hasTypedItems)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.fields_empty", QStringLiteral("profile fields 为空。"));
            return profile;
        }

        if (invalidOffsetCount != 0U && !hasTypedItems)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.invalid_offset", QStringLiteral("profile 含 %1 个越界或无效 offset，R3 已拒绝应用。")).arg(invalidOffsetCount);
            return profile;
        }
        if ((profile.applyInput.fields.empty() && profile.applyExInput.items.empty()) ||
            profile.applyInput.fields.size() > KSW_DYN_PROFILE_MAX_FIELDS ||
            profile.applyExInput.items.size() > KSW_DYN_PROFILE_EX_MAX_ITEMS)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.profile.count_invalid", QStringLiteral("profile 有效字段/item 数量异常: fields=%1 items=%2。"))
                .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
                .arg(static_cast<qulonglong>(profile.applyExInput.items.size()));
            return profile;
        }

        profile.valid = true;
        profile.diagnosticsText = kernelText("kernel.dyndata.profile.matched_summary", QStringLiteral("profile 匹配，字段 %1 个，typed 项 %2 个，callback 项 %3 个，忽略未知字段 %4 个。"))
            .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
            .arg(static_cast<qulonglong>(profile.typedItemCount))
            .arg(static_cast<qulonglong>(profile.callbackItemCount))
            .arg(profile.ignoredUnknownFields);
        return profile;
    }

    // loadPdbProfilePackEntry：
    // - 输入 pack 记录/currentIdentity/fieldDictionary/packVersion：pack profile 条目、当前内核身份、字段字典和版本；
    // - 处理：把 v3 typed items 和 v4 stable items 展开为 apply input；
    // - 返回：LocalPdbProfile；matched=false 表示不是当前内核 profile。
    LocalPdbProfile loadPdbProfilePackEntry(
        const QJsonObject& packEntry,
        const QJsonArray& fieldDictionary,
        const std::uint32_t packVersion,
        const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbProfile profile;
        profile.sourceText = QStringLiteral("pack");

        std::uint32_t profileClass = 0U;
        std::uint32_t machine = 0U;
        std::uint32_t timeDateStamp = 0U;
        std::uint32_t sizeOfImage = 0U;
        if (!profileClassIdFromJsonValue(packEntry.value(QStringLiteral("moduleClassId")), profileClass) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("machine")), machine) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
            !parseProfileUInt32(packEntry.value(QStringLiteral("sizeOfImage")), sizeOfImage))
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.identity_missing", QStringLiteral("pack profile identity 字段缺失或格式无效。"));
            return profile;
        }

        profile.matched = currentIdentity.present &&
            currentIdentity.classId == profileClass &&
            currentIdentity.machine == machine &&
            currentIdentity.timeDateStamp == timeDateStamp &&
            currentIdentity.sizeOfImage == sizeOfImage;
        if (!profile.matched)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.identity_mismatch", QStringLiteral("pack profile identity 不匹配当前内核。"));
            return profile;
        }

        // Release packs are v4-only.  The old fields/typedItems/legacyItems
        // projections are intentionally ignored even if a stale local file
        // still contains them.
        const QJsonArray fieldsArray;
        const QJsonArray typedItemsArray;
        const QJsonArray v4ItemsArray = packVersion == 4U
            ? packEntry.value(QStringLiteral("items")).toArray()
            : QJsonArray();
        if (fieldsArray.isEmpty() && typedItemsArray.isEmpty() && v4ItemsArray.isEmpty())
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.fields_empty", QStringLiteral("pack profile fields/items 均为空。"));
            return profile;
        }

        const QJsonValue profileNameValue = packEntry.value(QStringLiteral("profileName"));
        const QJsonValue pdbNameValue = packEntry.value(QStringLiteral("pdbName"));
        const QJsonValue pdbGuidValue = packEntry.value(QStringLiteral("pdbGuid"));
        QString profileNameText = profileNameValue.toString().trimmed();
        if (profileNameText.isEmpty())
        {
            profileNameText = QStringLiteral("pack-profile");
        }
        profile.applyInput.profileName = profileNameText.toStdString();
        profile.applyInput.pdbName = pdbNameValue.toString().toStdString();
        profile.applyInput.pdbGuid = pdbGuidValue.toString().toStdString();
        std::uint32_t pdbAge = 0U;
        if (parseProfileUInt32(packEntry.value(QStringLiteral("pdbAge")), pdbAge))
        {
            profile.applyInput.pdbAge = pdbAge;
        }
        profile.applyInput.ntoskrnl = currentIdentity;

        std::uint32_t invalidFieldCount = 0U;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenFieldIds{};
        for (const QJsonValue& entryValue : fieldsArray)
        {
            const QJsonArray pairArray = entryValue.toArray();
            if (pairArray.size() != 2)
            {
                invalidFieldCount += 1U;
                continue;
            }

            std::uint32_t fieldIndex = 0U;
            std::uint32_t offset = 0U;
            if (!parseProfileUInt32(pairArray.at(0), fieldIndex) ||
                !parseProfileUInt32(pairArray.at(1), offset) ||
                fieldIndex >= static_cast<std::uint32_t>(fieldDictionary.size()))
            {
                invalidFieldCount += 1U;
                continue;
            }

            const QString fieldName = fieldDictionary.at(static_cast<int>(fieldIndex)).toString();
            std::uint32_t fieldId = 0U;
            if (!fieldIdForProfileName(fieldName, fieldId))
            {
                profile.ignoredUnknownFields += 1U;
                continue;
            }
            if (offset == 0xFFFFFFFFU || offset > KSW_DYN_PROFILE_OFFSET_MAX)
            {
                invalidFieldCount += 1U;
                continue;
            }
            if (fieldId >= seenFieldIds.size() || seenFieldIds[fieldId])
            {
                invalidFieldCount += 1U;
                continue;
            }
            seenFieldIds[fieldId] = true;

            ksword::ark::DynDataProfileField field{};
            field.fieldId = fieldId;
            field.offset = offset;
            profile.applyInput.fields.push_back(field);
        }

        const QJsonArray callbackItemsArray;
        QStringList callbackDiagnostics;
        bool hasCallbackItems = false;
        if (!callbackItemsArray.isEmpty() && !loadCallbackItemsFromJson(callbackItemsArray, profile, callbackDiagnostics, hasCallbackItems))
        {
            profile.diagnosticsText = callbackDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasCallbackItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
        }

        QStringList typedDiagnostics;
        bool hasTypedItems = false;
        if (!loadTypedItemsFromJson(typedItemsArray, profile, typedDiagnostics, hasTypedItems))
        {
            profile.diagnosticsText = typedDiagnostics.join(QStringLiteral(" | "));
            return profile;
        }
        if (hasTypedItems)
        {
            profile.applyExInput.profileName = profile.applyInput.profileName;
            profile.applyExInput.pdbName = profile.applyInput.pdbName;
            profile.applyExInput.pdbGuid = profile.applyInput.pdbGuid;
            profile.applyExInput.pdbAge = profile.applyInput.pdbAge;
            profile.applyExInput.ntoskrnl = currentIdentity;
            profile.applyInput.fields.clear();
        }
        if (packVersion == 4U)
        {
            QStringList v4Diagnostics;
            if (!loadV4ItemsFromJson(
                    v4ItemsArray,
                    packEntry.value(QStringLiteral("capabilityGroups")).toArray(),
                    currentIdentity,
                    profileNameText,
                    QString::fromStdString(profile.applyInput.pdbName),
                    QString::fromStdString(profile.applyInput.pdbGuid),
                    profile.applyInput.pdbAge,
                    profile,
                    v4Diagnostics))
            {
                profile.diagnosticsText = v4Diagnostics.join(QStringLiteral(" | "));
                return profile;
            }
        }
        if (invalidFieldCount != 0U && v4ItemsArray.isEmpty())
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.invalid_fields", QStringLiteral("pack profile 含 %1 个越界或无效字段，R3 已拒绝应用。"))
                .arg(invalidFieldCount);
            return profile;
        }
        if ((profile.applyInput.fields.empty() && profile.applyExInput.items.empty() && profile.applyV4Input.items.empty()) ||
            profile.applyInput.fields.size() > KSW_DYN_PROFILE_MAX_FIELDS ||
            profile.applyExInput.items.size() > KSW_DYN_PROFILE_EX_MAX_ITEMS)
        {
            profile.diagnosticsText = kernelText("kernel.dyndata.pack.count_invalid", QStringLiteral("pack profile 有效字段/item 数量异常: fields=%1 items=%2。"))
                .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
                .arg(static_cast<qulonglong>(profile.applyExInput.items.size()));
            return profile;
        }

        profile.valid = true;
        profile.diagnosticsText = kernelText("kernel.dyndata.pack.matched_summary", QStringLiteral("pack profile 匹配，字段 %1 个，typed 项 %2 个，callback 项 %3 个，v4 项 %4 个，忽略未知字段 %5 个。"))
            .arg(static_cast<qulonglong>(profile.applyInput.fields.size()))
            .arg(static_cast<qulonglong>(profile.typedItemCount))
            .arg(static_cast<qulonglong>(profile.callbackItemCount))
            .arg(static_cast<qulonglong>(profile.v4ItemCount))
            .arg(profile.ignoredUnknownFields);
        return profile;
    }

    // loadPdbProfilePackFile：
    // - 输入 filePath/currentIdentity/diagnosticsOut：候选 pack、当前内核身份和诊断输出；
    // - 处理：校验 v4 pack schema 和 profiles 数组，寻找精确匹配条目；
    // - 返回：匹配 profile；未命中或 pack 无效时 valid=false/matched=false。
    LocalPdbProfile loadPdbProfilePackFile(const QString& filePath, const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        bestProfile.sourceText = QStringLiteral("pack");
        bestProfile.pathText = QDir::toNativeSeparators(filePath);

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument document = ks::profile::readProfileJsonDocument(filePath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            diagnosticsOut = readErrorText.isEmpty()
                ? kernelText("kernel.dyndata.pack.json_parse_failed", QStringLiteral("PDB profile pack JSON 解析失败: %1")).arg(parseError.errorString())
                : readErrorText;
            return bestProfile;
        }

        const QJsonObject rootObject = document.object();
        std::uint32_t schemaVersion = 0U;
        std::uint32_t packVersion = 0U;
        if (!parseProfileUInt32(rootObject.value(QStringLiteral("schemaVersion")), schemaVersion) ||
            !parseProfileUInt32(rootObject.value(QStringLiteral("packVersion")), packVersion) ||
            schemaVersion != 1U || packVersion != 4U)
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.version_unsupported", QStringLiteral("PDB profile pack schemaVersion/packVersion 不支持。"));
            return bestProfile;
        }

        const QJsonArray fieldDictionary = rootObject.value(QStringLiteral("fieldDictionary")).toArray();
        const QJsonArray profilesArray = rootObject.value(QStringLiteral("profiles")).toArray();
        if (!fieldDictionary.isEmpty() || profilesArray.isEmpty())
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.dictionary_or_profiles_empty", QStringLiteral("PDB profile pack 字段字典或 profile 列表为空。"));
            return bestProfile;
        }

        std::uint32_t invalidDictionaryFields = 0U;
        std::array<bool, KSW_DYN_FIELD_ID_MAX + 1U> seenDictionaryFieldIds{};
        for (const QJsonValue& fieldNameValue : fieldDictionary)
        {
            std::uint32_t ignoredFieldId = 0U;
            if (!fieldNameValue.isString() || !fieldIdForProfileName(fieldNameValue.toString(), ignoredFieldId))
            {
                invalidDictionaryFields += 1U;
                continue;
            }
            if (ignoredFieldId >= seenDictionaryFieldIds.size() || seenDictionaryFieldIds[ignoredFieldId])
            {
                invalidDictionaryFields += 1U;
                continue;
            }
            seenDictionaryFieldIds[ignoredFieldId] = true;
        }
        if (invalidDictionaryFields != 0U)
        {
            diagnosticsOut = kernelText("kernel.dyndata.pack.unknown_dictionary_fields", QStringLiteral("PDB profile pack 字段字典包含 %1 个未知字段，已拒绝。"))
                .arg(invalidDictionaryFields);
            return bestProfile;
        }

        std::uint32_t scannedCount = 0U;
        std::uint32_t invalidMatchedCount = 0U;
        for (const QJsonValue& profileValue : profilesArray)
        {
            if (!profileValue.isObject())
            {
                continue;
            }

            scannedCount += 1U;
            LocalPdbProfile profile = loadPdbProfilePackEntry(profileValue.toObject(), fieldDictionary, packVersion, currentIdentity);
            profile.pathText = QDir::toNativeSeparators(filePath);
            if (profile.matched)
            {
                if (profile.valid)
                {
                    diagnosticsOut = kernelText("kernel.dyndata.pack.matched", QStringLiteral("PDB profile pack 命中；路径=%1，profiles=%2，扫描=%3，%4"))
                        .arg(QDir::toNativeSeparators(filePath))
                        .arg(static_cast<qulonglong>(profilesArray.size()))
                        .arg(scannedCount)
                        .arg(profile.diagnosticsText);
                    return profile;
                }

                invalidMatchedCount += 1U;
                if (!bestProfile.matched)
                {
                    bestProfile = profile;
                    bestProfile.pathText = QDir::toNativeSeparators(filePath);
                }
            }
        }

        diagnosticsOut = kernelText("kernel.dyndata.pack.not_matched", QStringLiteral("PDB profile pack 未命中；路径=%1，profiles=%2，扫描=%3，无效命中=%4。"))
            .arg(QDir::toNativeSeparators(filePath))
            .arg(static_cast<qulonglong>(profilesArray.size()))
            .arg(scannedCount)
            .arg(invalidMatchedCount);
        return bestProfile;
    }

    // findMatchingPdbProfilePack：
    // - 输入 currentIdentity/diagnosticsOut：当前内核身份和诊断输出；
    // - 处理：按默认 pack 路径和环境变量路径查找，返回第一条有效命中；
    // - 返回：匹配 profile；未命中时 valid=false/matched=false。
    LocalPdbProfile findMatchingPdbProfilePack(const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        QStringList diagnostics;
        std::uint32_t existingPackCount = 0U;

        for (const QString& packPath : profilePackSearchPaths())
        {
            const QString resolvedPackPath = ks::profile::resolveProfileJsonPath(packPath);
            if (resolvedPackPath.isEmpty())
            {
                diagnostics << kernelText("kernel.dyndata.pack.missing", QStringLiteral("pack 不存在: %1")).arg(QDir::toNativeSeparators(packPath));
                continue;
            }

            existingPackCount += 1U;
            QString packDiagnostics;
            LocalPdbProfile profile = loadPdbProfilePackFile(resolvedPackPath, currentIdentity, packDiagnostics);
            diagnostics << packDiagnostics;
            if (profile.matched)
            {
                if (profile.valid)
                {
                    diagnosticsOut = diagnostics.join(QStringLiteral(" | "));
                    return profile;
                }
                if (!bestProfile.matched)
                {
                    bestProfile = profile;
                }
            }
        }

        diagnosticsOut = kernelText("kernel.dyndata.pack.no_match", QStringLiteral("未找到匹配 PDB profile pack；检查 %1 个存在的 pack。%2"))
            .arg(existingPackCount)
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return bestProfile;
    }

    // findMatchingPdbProfile：
    // - 输入 currentIdentity/diagnosticsOut：当前 ntoskrnl identity 和诊断输出；
    // - 处理：优先扫描 compact pack；仅当 KSWORD_ARK_PROFILE_DIR 显式设置时扫描散落 JSON；
    // - 返回：匹配 profile；未命中时 valid=false/matched=false。
    LocalPdbProfile findMatchingPdbProfile(const ksword::ark::ArkDynModuleIdentity& currentIdentity, QString& diagnosticsOut)
    {
        LocalPdbProfile bestProfile;
        QStringList diagnostics;

        if (!currentIdentity.present)
        {
            diagnosticsOut = kernelText("kernel.dyndata.profile.identity_unavailable", QStringLiteral("当前 ntoskrnl identity 不可用，跳过 PDB profile 扫描。"));
            return bestProfile;
        }

        QString packDiagnostics;
        LocalPdbProfile packProfile = findMatchingPdbProfilePack(currentIdentity, packDiagnostics);
        diagnostics << packDiagnostics;
        if (packProfile.valid)
        {
            diagnosticsOut = packDiagnostics;
            return packProfile;
        }
        if (packProfile.matched)
        {
            return packProfile;
        }

        diagnosticsOut = kernelText("kernel.dyndata.profile.pack_only_no_match", QStringLiteral("未找到匹配的 v4 PDB profile pack。%1"))
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return packProfile;
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
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_scan", QStringLiteral("PDB profile 扫描")), boolText(summary.pdbProfileScanAttempted));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_found", QStringLiteral("PDB profile 命中")), boolText(summary.pdbProfileFound));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_applied", QStringLiteral("PDB profile 本次应用")), boolText(summary.pdbProfileApplied));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_source", QStringLiteral("PDB profile 来源")), safeText(summary.pdbProfileSourceText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_name", QStringLiteral("PDB profile 名称")), safeText(summary.pdbProfileNameText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_path", QStringLiteral("PDB profile 路径")), safeText(summary.pdbProfilePathText));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_status", QStringLiteral("PDB profile 状态")), formatNtStatus(summary.pdbProfileStatus));
        appendSummaryRow(table, kernelText("kernel.dyndata.summary.pdb_fields", QStringLiteral("PDB profile 字段")), QStringLiteral("applied=%1 rejected=%2 unknown=%3 ignoredJson=%4")
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
        bool pdbProfileApplied = false;
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
                pdbProfileApplied = true;
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
                if (profile.matched)
                {
                    pdbProfileFound = true;
                    pdbProfileSourceText = profileSourceDisplayText(profile.sourceText);
                    pdbProfileNameText = stringToQString(profile.applyInput.profileName);
                    pdbProfilePathText = profile.pathText;
                    pdbProfileIgnoredJsonFields = profile.ignoredUnknownFields;

                    if (!profile.valid)
                    {
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
                            pdbProfileIoMessageText += friendlyDynDataIoMessage(applyExResult.io.message);
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
                            pdbProfileIoMessageText += friendlyDynDataIoMessage(applyV4Result.io.message);
                            pdbProfileStatus = applyV4Result.response.status;
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
                        pdbProfileApplied = anyApplySucceeded;
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
                    moduleEntry.module.image.present == 0UL ||
                    (moduleEntry.statusFlags &
                        KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED) != 0U)
                {
                    continue;
                }

                pdbProfileScanAttempted = true;
                const ksword::ark::ArkDynModuleIdentity moduleIdentity =
                    convertV4PacketIdentity(moduleEntry.module.image);
                const QString moduleLabel =
                    QString::fromStdWString(moduleIdentity.moduleName);
                QString moduleScanDiagnostics;
                LocalPdbProfile moduleProfile =
                    findMatchingPdbProfile(
                        moduleIdentity,
                        moduleScanDiagnostics);
                const QString moduleDiagnosticBlock =
                    QStringLiteral("%1: %2")
                        .arg(moduleLabel, moduleScanDiagnostics);
                if (!pdbProfileMessageText.isEmpty())
                {
                    pdbProfileMessageText += QStringLiteral(" | ");
                }
                pdbProfileMessageText += moduleDiagnosticBlock;

                if (!moduleProfile.matched)
                {
                    continue;
                }
                pdbProfileFound = true;
                if (pdbProfileSourceText.isEmpty())
                {
                    pdbProfileSourceText =
                        profileSourceDisplayText(moduleProfile.sourceText);
                    pdbProfileNameText =
                        stringToQString(
                            moduleProfile.applyInput.profileName);
                    pdbProfilePathText = moduleProfile.pathText;
                }
                pdbProfileIgnoredJsonFields +=
                    moduleProfile.ignoredUnknownFields;
                if (!moduleProfile.valid ||
                    moduleProfile.applyV4Input.items.empty())
                {
                    continue;
                }

                const ksword::ark::DynDataV4ApplyResult moduleApplyResult =
                    client.applyDynDataProfileV4(
                        moduleProfile.applyV4Input);
                if (!pdbProfileIoMessageText.isEmpty())
                {
                    pdbProfileIoMessageText += QStringLiteral(" | ");
                }
                pdbProfileIoMessageText +=
                    friendlyDynDataIoMessage(
                        moduleApplyResult.io.message);
                pdbProfileStatus =
                    moduleApplyResult.response.status;
                pdbProfileAppliedFields +=
                    moduleApplyResult.response.appliedItemCount;
                pdbProfileRejectedFields +=
                    moduleApplyResult.response.rejectedItemCount;
                if (moduleApplyResult.response.message[0] != L'\0')
                {
                    pdbProfileMessageText +=
                        QStringLiteral(" | %1: ").arg(moduleLabel);
                    pdbProfileMessageText +=
                        wideStringToQString(
                            moduleApplyResult.response.message);
                }
                const bool moduleApplySucceeded =
                    moduleApplyResult.io.ok &&
                    moduleApplyResult.response.status == 0 &&
                    moduleApplyResult.response.rejectedItemCount == 0U &&
                    moduleApplyResult.response.missingRequiredItemCount == 0U;
                pdbProfileApplied =
                    pdbProfileApplied || moduleApplySucceeded;
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
        pdbProfileApplied = pdbProfileApplied || cachedNtosProfileAccepted || cachedPdbProfileAccepted;
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

        summaryOut = KernelDynDataSummary{};
        rowsOut.clear();
        v4ItemRowsOut.clear();

        summaryOut.statusQueryOk = statusResult.io.ok;
        summaryOut.fieldsQueryOk = fieldsResult.io.ok;
        summaryOut.statusIoMessageText = friendlyDynDataIoMessage(statusResult.io.message);
        summaryOut.fieldsIoMessageText = friendlyDynDataIoMessage(fieldsResult.io.message);
        summaryOut.pdbProfileScanAttempted = pdbProfileScanAttempted;
        summaryOut.pdbProfileFound = pdbProfileFound;
        summaryOut.pdbProfileApplied = pdbProfileApplied;
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
    std::thread([guardThis]() {
        KernelDynDataSummary summary;
        std::vector<KernelDynDataFieldEntry> rows;
        std::vector<KernelDynDataV4ItemEntry> v4ItemRows;
        const bool success = queryDynDataSnapshot(summary, rows, v4ItemRows);

        QMetaObject::invokeMethod(guardThis, [guardThis, success, summary = std::move(summary), rows = std::move(rows), v4ItemRows = std::move(v4ItemRows)]() mutable {
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
                deferredV4Rows]() mutable
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
            guardThis->rebuildDynDataFieldTable(guardThis->m_dynDataFilterEdit->text().trimmed());
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
                guardThis->m_dynDataDetailEditor->setDocument(buildDynDataReport(guardThis->m_dynDataSummary, guardThis->m_dynDataRows));
                populateProfileStatusTable(guardThis->m_dynDataProfileSummaryTable, guardThis->m_dynDataSummary);
                if (guardThis->m_dynDataProfileStatusLabel != nullptr)
                {
                    guardThis->m_dynDataProfileStatusLabel->setText(kernelText("kernel.dyndata.profile_status.failed", QStringLiteral("状态：profile 诊断失败，保留现有摘要")));
                    guardThis->m_dynDataProfileStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                }
                if (guardThis->m_dynDataProfileDetailEditor != nullptr)
                {
                    guardThis->m_dynDataProfileDetailEditor->setDocument(buildDynDataReport(guardThis->m_dynDataSummary, guardThis->m_dynDataRows));
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

                if (guardThis->m_dynDataFieldTable->rowCount() > 0)
                {
                    guardThis->m_dynDataFieldTable->setCurrentCell(0, 0);
                }
                else
                {
                    guardThis->m_dynDataDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.dyndata.empty.filtered", QStringLiteral("当前筛选条件下没有动态偏移字段。"))));
                }

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
                    guardThis->m_dynDataProfileDetailEditor->setDocument(buildDynDataReport(guardThis->m_dynDataSummary, guardThis->m_dynDataRows));
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

void KernelDock::rebuildDynDataFieldTable(const QString& filterKeyword)
{
    if (m_dynDataFieldTable == nullptr)
    {
        return;
    }

    m_dynDataFieldTable->setSortingEnabled(false);
    m_dynDataFieldTable->setRowCount(0);

    for (std::size_t sourceIndex = 0U; sourceIndex < m_dynDataRows.size(); ++sourceIndex)
    {
        const KernelDynDataFieldEntry& entry = m_dynDataRows[sourceIndex];
        if (!shouldShowField(entry, filterKeyword))
        {
            continue;
        }

        const int rowIndex = m_dynDataFieldTable->rowCount();
        m_dynDataFieldTable->insertRow(rowIndex);

        auto* fieldItem = new QTableWidgetItem(safeText(entry.fieldNameText));
        auto* offsetItem = new QTableWidgetItem(formatOffset(entry.offset));
        auto* statusItem = new QTableWidgetItem(safeText(entry.statusText));
        auto* sourceItem = new QTableWidgetItem(safeText(entry.sourceNameText));
        auto* featureItem = new QTableWidgetItem(safeText(entry.featureNameText));
        auto* capabilityItem = new QTableWidgetItem(formatHex64(entry.capabilityMask));

        fieldItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
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
    }

    m_dynDataFieldTable->setSortingEnabled(true);
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

    m_dynDataV4ItemTable->setSortingEnabled(false);
    m_dynDataV4ItemTable->setRowCount(0);

    for (const KernelDynDataV4ItemEntry& entry : m_dynDataV4ItemRows)
    {
        if (!v4ItemMatchesFilter(entry, filterKeyword))
        {
            continue;
        }

        const int rowIndex = m_dynDataV4ItemTable->rowCount();
        m_dynDataV4ItemTable->insertRow(rowIndex);
        insertReadonlyCell(rowIndex, 0, moduleClassText(entry.moduleClassId));
        insertReadonlyCell(rowIndex, 1, QString::number(entry.itemIndex));
        insertReadonlyCell(rowIndex, 2, QString::number(entry.itemId));
        insertReadonlyCell(rowIndex, 3, entry.kindText);
        insertReadonlyCell(rowIndex, 4, QString::number(entry.capabilityGroupId));
        insertReadonlyCell(rowIndex, 5, entry.flagsText);
        insertReadonlyCell(rowIndex, 6, formatHex64(entry.value));
        insertReadonlyCell(rowIndex, 7, entry.auxText);
        insertReadonlyCell(rowIndex, 8, entry.detailDocument.toPlainText(true).replace(QStringLiteral("\n"), QStringLiteral("; ")));
    }

    if (m_dynDataV4ItemTable->rowCount() == 0)
    {
        const QString stateText = v4IoStateText(m_dynDataSummary.dynDataV4ItemsQueryOk, m_dynDataSummary.dynDataV4ItemsUnsupported);
        const QString detailText = kernelText("kernel.dyndata.v4.empty.detail", QStringLiteral("V4 accepted item 查询状态：%1；返回 %2/%3；%4"))
            .arg(stateText)
            .arg(m_dynDataSummary.dynDataV4ItemsReturnedCount)
            .arg(m_dynDataSummary.dynDataV4ItemsTotalCount)
            .arg(safeText(m_dynDataSummary.dynDataV4ItemsIoMessageText));
        const int rowIndex = m_dynDataV4ItemTable->rowCount();
        m_dynDataV4ItemTable->insertRow(rowIndex);
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
        m_dynDataDetailEditor->setDocument(buildDynDataReport(m_dynDataSummary, m_dynDataRows));
        return;
    }

    auto document = entry->detailDocument;
    document.nodes += moduleDetailText(QStringLiteral("ntoskrnl"), m_dynDataSummary.ntoskrnl).nodes;
    document.nodes += moduleDetailText(QStringLiteral("lxcore"), m_dynDataSummary.lxcore).nodes;
    document.nodes += capabilityReport(m_dynDataSummary.capabilityMask).nodes;
    m_dynDataDetailEditor->setDocument(document);
}
