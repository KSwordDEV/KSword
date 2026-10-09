#include "../UI/StructuredFieldView.h"
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
#include <QJsonParseError>
#include <QJsonValue>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QStringList>
#include <QSplitter>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <limits>
#include <thread>
#include <utility>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // DriverSummaryColumn and DriverCapabilityColumn keep table layout explicit.
    enum class DriverSummaryColumn : int { Name = 0, Value, Count };
    enum class DriverCapabilityColumn : int { Feature = 0, State, Policy, RequiredDyn, PresentDyn, Dependency, Reason, Count };

    struct CapabilityDisplay
    {
        std::uint64_t mask = 0;
        const char* name = nullptr;
        const wchar_t* title = nullptr;
        const char* contextKey = nullptr;
    };

    struct PolicyDisplay
    {
        std::uint32_t mask = 0;
        const char* name = nullptr;
        const wchar_t* title = nullptr;
        const char* contextKey = nullptr;
    };

    // LocalPdbPackMatch：
    // - 输入来源：程序目录或环境变量指定的 compact profile pack；
    // - 处理逻辑：只做本地 pack 的 identity 精确匹配和轻量诊断，不应用 profile；
    // - 返回行为：由 queryDriverStatusSnapshot 填入 KernelDriverStatusSummary 展示。
    struct LocalPdbPackMatch
    {
        bool scanned = false;                 // scanned：是否实际检查过至少一个候选 pack。
        bool matched = false;                 // matched：是否有 class/machine/timestamp/size 完全命中的 profile。
        bool valid = false;                   // valid：命中 profile 是否包含可用字段数组。
        std::uint32_t existingPackCount = 0;  // existingPackCount：存在且可读前尝试解析的 pack 文件数。
        std::uint32_t profileCount = 0;       // profileCount：pack 内 profile 总数。
        std::uint32_t scannedProfileCount = 0; // scannedProfileCount：本次扫描过的 profile 数。
        std::uint32_t fieldCount = 0;         // fieldCount：命中 profile 声明字段数。
        std::uint32_t typedItemCount = 0;     // typedItemCount：命中 profile 声明 v3 items 数。
        std::uint32_t callbackItemCount = 0;  // callbackItemCount：命中 profile 声明 callbackItems 数。
        bool activeProcessLinksPresent = false; // activeProcessLinksPresent：命中 profile 是否包含 ActiveProcessLinks。
        std::uint32_t activeProcessLinksOffset = 0xFFFFFFFFU; // activeProcessLinksOffset：本地 pack 中的 ActiveProcessLinks 偏移。
        double coveragePercent = -1.0;        // coveragePercent：release_sync 计算的 profile 覆盖率，负数表示未知。
        QString profileNameText;              // profileNameText：命中 profileName。
        QString versionText;                  // versionText：从 profileName 提取的 Windows 版本号。
        QString pathText;                     // pathText：命中或最后诊断的 pack 路径。
        QString messageText;                  // messageText：给 UI 展示的匹配/失败原因。
    };

    // kDynCapabilities：
    // - 作用：列出所有可由 R0 DynData 暴露的 capability bit；
    // - 处理逻辑：驱动状态页、能力详情和筛选都复用该表。
    constexpr std::array<CapabilityDisplay, 23> kDynCapabilities{ {
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

    // kSecurityPolicies lists every policy bit currently surfaced by Phase 1.
    constexpr std::array<PolicyDisplay, 5> kSecurityPolicies{ {
        { KSWORD_ARK_SECURITY_POLICY_FLAG_ACTIVE, "POLICY_ACTIVE", L"安全策略启用", "kernel.driver_status.policy.active" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_MUTATING_ACTIONS, "ALLOW_MUTATING_ACTIONS", L"允许进程修改动作", "kernel.driver_status.policy.mutating_actions" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_CALLBACK_CONTROL, "ALLOW_CALLBACK_CONTROL", L"允许回调控制", "kernel.driver_status.policy.callback_control" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_PROCESS_PROTECTION, "ALLOW_PROCESS_PROTECTION", L"允许进程保护修改", "kernel.driver_status.policy.process_protection" },
        { KSWORD_ARK_SECURITY_POLICY_ALLOW_KERNEL_SNAPSHOTS, "ALLOW_KERNEL_SNAPSHOTS", L"允许内核快照", "kernel.driver_status.policy.kernel_snapshots" }
    } };

    QString blueButtonStyle() { return KswordTheme::ThemedButtonStyle(); }

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

    QString headerStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    QString itemSelectionStyle()
    {
        return QString();
    }

    // driverStatusCopyMenuStyle：
    // - 输入：无；
    // - 处理：显式设置右键菜单背景、文字、选中态和禁用态；
    // - 返回：可直接应用到 QMenu 的样式。
    QString driverStatusCopyMenuStyle()
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

    // driverStatusRowText：
    // - 输入 table/rowIndex：驱动状态表和目标行；
    // - 处理：按列读取单元格文本并拼接为 TSV；
    // - 返回：可复制文本，行无效时返回空字符串。
    QString driverStatusRowText(QTableWidget* table, const int rowIndex)
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

    // installDriverStatusCopyMenu：
    // - 输入 table：驱动状态摘要表或能力矩阵表；
    // - 处理：安装复制当前行的只读右键菜单；
    // - 返回：无，不执行任何 R0 查询或写入动作。
    void installDriverStatusCopyMenu(QTableWidget* table)
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
            menu.setStyleSheet(driverStatusCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                kernelText("kernel.driver_status.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(rowIndex >= 0 && rowIndex < table->rowCount());
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                QClipboard* clipboard = QApplication::clipboard();
                if (clipboard != nullptr)
                {
                    clipboard->setText(driverStatusRowText(table, rowIndex));
                }
            }
        });
    }

    QString statusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    QString safeText(const QString& valueText, const QString& fallbackText)
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    QString safeText(const QString& valueText)
    {
        return safeText(valueText, kernelText("kernel.driver_status.placeholder.empty", QStringLiteral("<空>")));
    }

    QString stringToQString(const std::string& valueText)
    {
        return QString::fromUtf8(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    // friendlyDriverStatusIoMessage：
    // - 输入 valueText：ArkDriverClient 返回的 io.message；
    // - 处理：把 DeviceIoControl/unsupported/DynData 等底层短语转为中文诊断；
    // - 返回：驱动状态摘要表和详情报告可直接展示的文本。
    QString friendlyDriverStatusIoMessage(const std::string& valueText)
    {
        const QString rawText = stringToQString(valueText).trimmed();
        if (rawText.isEmpty())
        {
            return kernelText("kernel.driver_status.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.driver_status.message.communication_failure", QStringLiteral("驱动通信失败或当前驱动版本不支持该状态查询入口。"));
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.driver_status.message.unsupported", QStringLiteral("当前驱动不支持该状态/能力查询入口。"));
        }
        if (rawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return kernelText("kernel.driver_status.message.capability", QStringLiteral("动态偏移能力不足，部分驱动能力会显示为不可用。"));
        }
        return rawText;
    }

    // wideStringToQString：
    // - 输入 valueText：ArkDriverClient 返回的宽字符串；
    // - 处理：按 wchar_t 数组安全转换为 QString；
    // - 返回：Qt UI 可直接展示的文本。
    QString wideStringToQString(const std::wstring& valueText)
    {
        return QString::fromWCharArray(valueText.c_str(), static_cast<int>(valueText.size()));
    }

    QString formatHex32(const std::uint32_t value) { return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')).toUpper(); }
    QString formatHex64(const std::uint64_t value) { return QStringLiteral("0x%1").arg(value, 16, 16, QChar('0')).toUpper(); }
    QString formatNtStatus(const long value) { return formatHex32(static_cast<std::uint32_t>(value)); }
    QString boolText(const bool value)
    {
        return value
            ? kernelText("kernel.driver_status.value.yes", QStringLiteral("是"))
            : kernelText("kernel.driver_status.value.no", QStringLiteral("否"));
    }
    bool flagEnabled(const std::uint32_t flags, const std::uint32_t flag) { return (flags & flag) == flag; }

    // fieldOffsetPresent：
    // - 输入 flags/offset：R0 返回的字段状态位和偏移；
    // - 处理：同时检查 PRESENT bit 和不可用哨兵；
    // - 返回：true 表示该字段当前有可信可用偏移值。
    bool fieldOffsetPresent(const std::uint32_t flags, const std::uint32_t offset)
    {
        return (flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
            offset != 0xFFFFFFFFU &&
            offset != 0x0000FFFFU;
    }

    // offsetAvailable：
    // - 输入 offset：本地 profile 或 R0 字段表中的偏移值；
    // - 处理：统一过滤两个历史不可用哨兵，避免 UI 把缺失值显示为可用偏移；
    // - 返回：true 表示偏移可用于后续诊断展示。
    bool offsetAvailable(const std::uint32_t offset)
    {
        return offset != 0xFFFFFFFFU && offset != 0x0000FFFFU;
    }

    // formatOffset32：
    // - 输入 offset：32-bit 字段偏移；
    // - 处理：对不可用哨兵显示 <不可用>，否则同时显示 hex/decimal 便于和 WinDbg/PDB 对照；
    // - 返回：可直接放入摘要表或诊断报告的偏移文本。
    QString formatOffset32(const std::uint32_t offset)
    {
        if (!offsetAvailable(offset))
        {
            return kernelText("kernel.driver_status.placeholder.unavailable", QStringLiteral("<不可用>"));
        }
        return QStringLiteral("%1 (%2)").arg(formatHex32(offset)).arg(offset);
    }

    // parseProfileUInt32：
    // - 输入 value：pack JSON 中可能是数字或 0x 字符串的值；
    // - 处理：按 32-bit 无符号整数解析并做范围校验；
    // - 返回：成功解析 true，失败 false，同时写入 valueOut。
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

    // appendUniquePath：
    // - 输入 paths/pathText：候选路径列表与待添加路径；
    // - 处理：清理路径并做大小写不敏感去重；
    // - 返回：无返回值，paths 会按需追加。
    void appendUniquePath(QStringList& paths, const QString& pathText)
    {
        const QString trimmed = pathText.trimmed();
        if (trimmed.isEmpty())
        {
            return;
        }

        const QString cleanedPath = QDir::cleanPath(trimmed);
        if (!cleanedPath.isEmpty() && !paths.contains(cleanedPath, Qt::CaseInsensitive))
        {
            paths << cleanedPath;
        }
    }

    // profilePackSearchPaths：
    // - 输入：无；
    // - 处理：按 Release 默认路径、调试环境变量、当前目录兜底构造候选 pack；
    // - 返回：候选文件路径列表，调用方仍需检查是否存在。
    QStringList profilePackSearchPaths()
    {
        QStringList paths;
        appendUniquePath(paths, qEnvironmentVariable("KSWORD_ARK_PROFILE_PACK"));
        appendUniquePath(paths, QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        appendUniquePath(paths, QDir::current().filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
        return paths;
    }

    // moduleClassText：
    // - 输入 classId：KSW_DYN_PROFILE_CLASS_*；
    // - 处理：转换为用户能理解的内核模块类别；
    // - 返回：ntoskrnl/ntkrla57/lxcore 或 unknown(...) 文本。
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
    // - 处理：把 R0 字段来源转换为用户可读文本；
    // - 返回：System Informer/runtime/PDB profile 等来源名称。
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

    // extractVersionFromProfileName：
    // - 输入 profileName：生成器写入的 profileName；
    // - 处理：提取第一个 Windows 四段版本号；
    // - 返回：命中返回版本文本，否则返回空字符串。
    QString extractVersionFromProfileName(const QString& profileName)
    {
        static const QRegularExpression kVersionPattern(QStringLiteral("(\\d+\\.\\d+\\.\\d+\\.\\d+)"));
        const QRegularExpressionMatch match = kVersionPattern.match(profileName);
        return match.hasMatch() ? match.captured(1) : QString();
    }

    // extractActiveProcessLinksFromPackEntry：
    // - 输入 profileObject/fieldDictionary：已命中当前 ntoskrnl identity 的 compact profile；
    // - 处理：解析 v4 items 中的 EpActiveProcessLinks StructOffset。
    // - 返回：成功提取可用偏移 true，并写出 offsetOut；否则 false。
    bool extractActiveProcessLinksFromPackEntry(
        const QJsonObject& profileObject,
        std::uint32_t& offsetOut)
    {
        offsetOut = 0xFFFFFFFFU;

        const QJsonArray itemsArray = profileObject.value(QStringLiteral("items")).toArray();
        for (const QJsonValue& itemValue : itemsArray)
        {
            if (!itemValue.isObject())
            {
                continue;
            }

            const QJsonObject itemObject = itemValue.toObject();
            const QString itemName = itemObject.value(QStringLiteral("name")).toString().trimmed();
            std::uint32_t itemId = 0U;
            std::uint32_t itemKind = 0U;
            if (!parseProfileUInt32(itemObject.value(QStringLiteral("itemId")), itemId) ||
                !parseProfileUInt32(itemObject.value(QStringLiteral("itemKind")), itemKind) ||
                itemId != KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS ||
                itemKind != KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
                (itemName != QStringLiteral("EpActiveProcessLinks") &&
                 itemName != QStringLiteral("_EPROCESS.ActiveProcessLinks")))
            {
                continue;
            }

            std::uint32_t parsedOffset = 0U;
            if (parseProfileUInt32(itemObject.value(QStringLiteral("valueLow")), parsedOffset) &&
                offsetAvailable(parsedOffset))
            {
                offsetOut = parsedOffset;
                return true;
            }
        }

        return false;
    }

    // findMatchingLocalPdbProfilePack：
    // - 输入 currentIdentity：R0 识别到的当前 ntoskrnl identity；
    // - 处理：解析 compact JSON pack 并用 class/machine/timestamp/size 精确匹配；
    // - 返回：匹配结果和诊断；不会修改驱动状态，也不会应用 profile。
    LocalPdbPackMatch findMatchingLocalPdbProfilePack(const ksword::ark::ArkDynModuleIdentity& currentIdentity)
    {
        LocalPdbPackMatch result;
        QStringList diagnostics;

        if (!currentIdentity.present)
        {
            result.messageText = kernelText("kernel.driver_status.pdb.identity_unavailable", QStringLiteral("当前 ntoskrnl identity 不可用，无法匹配本地 PDB profile pack。"));
            return result;
        }

        for (const QString& candidatePath : profilePackSearchPaths())
        {
            const QString resolvedCandidatePath = ks::profile::resolveProfileJsonPath(candidatePath);
            if (resolvedCandidatePath.isEmpty())
            {
                diagnostics << kernelText("kernel.driver_status.pdb.pack_missing", QStringLiteral("pack 不存在: %1")).arg(QDir::toNativeSeparators(candidatePath));
                continue;
            }

            result.scanned = true;
            result.existingPackCount += 1U;
            result.pathText = QDir::toNativeSeparators(resolvedCandidatePath);

            QJsonParseError parseError{};
            QString readErrorText;
            const QJsonDocument document = ks::profile::readProfileJsonDocument(resolvedCandidatePath, &parseError, &readErrorText);
            if (parseError.error != QJsonParseError::NoError || !document.isObject())
            {
                diagnostics << (readErrorText.isEmpty()
                    ? kernelText("kernel.driver_status.pdb.json_parse_failed", QStringLiteral("pack JSON 解析失败: %1 (%2)")).arg(result.pathText, parseError.errorString())
                    : kernelText("kernel.driver_status.pdb.json_read_failed", QStringLiteral("pack JSON 读取失败: %1 (%2)")).arg(result.pathText, readErrorText));
                continue;
            }

            const QJsonObject rootObject = document.object();
            std::uint32_t schemaVersion = 0U;
            std::uint32_t packVersion = 0U;
            if (!parseProfileUInt32(rootObject.value(QStringLiteral("schemaVersion")), schemaVersion) ||
                !parseProfileUInt32(rootObject.value(QStringLiteral("packVersion")), packVersion) ||
                schemaVersion != 1U ||
                packVersion != 4U)
            {
                diagnostics << kernelText("kernel.driver_status.pdb.version_unsupported", QStringLiteral("pack schemaVersion/packVersion 不支持: %1")).arg(result.pathText);
                continue;
            }

            const QJsonArray profilesArray = rootObject.value(QStringLiteral("profiles")).toArray();
            result.profileCount = static_cast<std::uint32_t>(profilesArray.size());
            if (profilesArray.isEmpty())
            {
                diagnostics << kernelText("kernel.driver_status.pdb.profile_list_empty", QStringLiteral("pack profile 列表为空: %1")).arg(result.pathText);
                continue;
            }

            for (const QJsonValue& profileValue : profilesArray)
            {
                if (!profileValue.isObject())
                {
                    continue;
                }

                result.scannedProfileCount += 1U;
                const QJsonObject profileObject = profileValue.toObject();
                std::uint32_t moduleClassId = 0U;
                std::uint32_t machine = 0U;
                std::uint32_t timeDateStamp = 0U;
                std::uint32_t sizeOfImage = 0U;
                if (!parseProfileUInt32(profileObject.value(QStringLiteral("moduleClassId")), moduleClassId) ||
                    !parseProfileUInt32(profileObject.value(QStringLiteral("machine")), machine) ||
                    !parseProfileUInt32(profileObject.value(QStringLiteral("timeDateStamp")), timeDateStamp) ||
                    !parseProfileUInt32(profileObject.value(QStringLiteral("sizeOfImage")), sizeOfImage))
                {
                    continue;
                }

                if (currentIdentity.classId != moduleClassId ||
                    currentIdentity.machine != machine ||
                    currentIdentity.timeDateStamp != timeDateStamp ||
                    currentIdentity.sizeOfImage != sizeOfImage)
                {
                    continue;
                }

                const QJsonArray itemsArray = profileObject.value(QStringLiteral("items")).toArray();
                result.matched = true;
                result.valid = !itemsArray.isEmpty();
                result.fieldCount = 0U;
                result.typedItemCount = static_cast<std::uint32_t>(itemsArray.size());
                result.callbackItemCount = 0U;
                result.activeProcessLinksPresent = extractActiveProcessLinksFromPackEntry(
                    profileObject,
                    result.activeProcessLinksOffset);
                const double coveragePercent = profileObject.value(QStringLiteral("coveragePercent")).toDouble(-1.0);
                result.coveragePercent = coveragePercent >= 0.0 ? coveragePercent : -1.0;
                result.profileNameText = profileObject.value(QStringLiteral("profileName")).toString(QStringLiteral("pack-profile"));
                result.versionText = extractVersionFromProfileName(result.profileNameText);
                result.messageText = result.valid
                    ? kernelText("kernel.driver_status.pdb.matched", QStringLiteral("本地 PDB profile pack 命中；profiles=%1，扫描=%2，字段=%3，typedItems=%4，callbackItems=%5，ActiveProcessLinks=%6，覆盖率=%7。"))
                        .arg(result.profileCount)
                        .arg(result.scannedProfileCount)
                        .arg(result.fieldCount)
                        .arg(result.typedItemCount)
                        .arg(result.callbackItemCount)
                        .arg(result.activeProcessLinksPresent ? formatOffset32(result.activeProcessLinksOffset) : kernelText("kernel.driver_status.placeholder.missing", QStringLiteral("<缺失>")))
                        .arg(result.coveragePercent >= 0.0 ? QStringLiteral("%1%").arg(result.coveragePercent, 0, 'f', 1) : kernelText("kernel.driver_status.placeholder.unknown", QStringLiteral("<未知>")))
                    : kernelText("kernel.driver_status.pdb.matched_invalid", QStringLiteral("本地 PDB profile pack 命中 identity，但 fields/items 均为空，已视为无效。"));
                return result;
            }

            diagnostics << kernelText("kernel.driver_status.pdb.not_matched", QStringLiteral("pack 未命中: %1 (profiles=%2)")).arg(result.pathText).arg(result.profileCount);
        }

        result.messageText = kernelText("kernel.driver_status.pdb.no_match", QStringLiteral("未找到匹配 PDB profile pack；检查 %1 个存在的 pack。%2"))
            .arg(result.existingPackCount)
            .arg(diagnostics.join(QStringLiteral(" | ")));
        return result;
    }

    QString capabilityNames(const std::uint64_t mask)
    {
        QStringList names;
        for (const CapabilityDisplay& item : kDynCapabilities)
        {
            if ((mask & item.mask) == item.mask)
            {
                names << QStringLiteral("%1 (%2)")
                    .arg(QString::fromLatin1(item.name))
                    .arg(kernelText(item.contextKey, QString::fromWCharArray(item.title)));
            }
        }
        return names.isEmpty() ? QStringLiteral("None") : names.join(QStringLiteral(", "));
    }

    QString policyNames(const std::uint32_t mask)
    {
        QStringList names;
        for (const PolicyDisplay& item : kSecurityPolicies)
        {
            if ((mask & item.mask) == item.mask)
            {
                names << QStringLiteral("%1 (%2)")
                    .arg(QString::fromLatin1(item.name))
                    .arg(kernelText(item.contextKey, QString::fromWCharArray(item.title)));
            }
        }
        return names.isEmpty() ? QStringLiteral("None") : names.join(QStringLiteral(", "));
    }

    // kernelIdentityText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：把 ntoskrnl identity 的关键 PE 字段压成单行；
    // - 返回：可放入摘要表和诊断详情的当前内核身份文本。
    QString kernelIdentityText(const KernelDriverStatusSummary& summary)
    {
        if (!summary.ntoskrnlIdentityPresent)
        {
            return kernelText("kernel.driver_status.placeholder.unrecognized", QStringLiteral("<未识别>"));
        }

        return kernelText("kernel.driver_status.kernel_identity", QStringLiteral("%1，Class=%2 (%3)，Machine=%4，TimeDateStamp=%5，SizeOfImage=%6，Base=%7"))
            .arg(safeText(summary.ntoskrnlModuleNameText))
            .arg(moduleClassText(summary.ntoskrnlClassId))
            .arg(summary.ntoskrnlClassId)
            .arg(formatHex32(summary.ntoskrnlMachine))
            .arg(formatHex32(summary.ntoskrnlTimeDateStamp))
            .arg(formatHex32(summary.ntoskrnlSizeOfImage))
            .arg(formatHex64(summary.ntoskrnlImageBase));
    }

    // kernelVersionText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：优先使用本地 PDB profileName 中的四段 Windows 版本号；
    // - 返回：识别到的 Windows 内核版本，未命中时返回明确占位。
    QString kernelVersionText(const KernelDriverStatusSummary& summary)
    {
        if (!summary.localPdbProfileVersionText.trimmed().isEmpty())
        {
            return summary.localPdbProfileVersionText;
        }
        return summary.ntoskrnlIdentityPresent
            ? kernelText("kernel.driver_status.placeholder.identity_version", QStringLiteral("<identity 已识别，版本号需匹配 PDB profile 后确认>"))
            : kernelText("kernel.driver_status.placeholder.unrecognized", QStringLiteral("<未识别>"));
    }

    // fieldCoverageText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：汇总 R0 字段总数、返回字段和可用字段；
    // - 返回：用户可读字段覆盖率文本。
    QString fieldCoverageText(const KernelDriverStatusSummary& summary)
    {
        QString coverageText = kernelText("kernel.driver_status.field_coverage", QStringLiteral("可用 %1 / 返回 %2 / R0声明 %3，必需缺失 %4"))
            .arg(summary.dynDataPresentFieldCount)
            .arg(summary.dynDataReturnedFieldCount)
            .arg(summary.dynDataFieldCount)
            .arg(summary.dynDataRequiredMissingCount);
        if (summary.localPdbProfileCoveragePercent >= 0.0)
        {
            coverageText += kernelText("kernel.driver_status.field_coverage.pack", QStringLiteral("，pack覆盖率 %1%"))
                .arg(summary.localPdbProfileCoveragePercent, 0, 'f', 1);
        }
        return coverageText;
    }

    // fieldSourceSummaryText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：按当前可用字段的来源分类计数；
    // - 返回：字段来源分布文本。
    QString fieldSourceSummaryText(const KernelDriverStatusSummary& summary)
    {
        return kernelText("kernel.driver_status.field_sources", QStringLiteral("PDB=%1，RuntimePattern=%2，SystemInformer=%3，Extra=%4，不可用=%5"))
            .arg(summary.dynDataPdbProfileFieldCount)
            .arg(summary.dynDataRuntimePatternFieldCount)
            .arg(summary.dynDataSystemInformerFieldCount)
            .arg(summary.dynDataExtraTableFieldCount)
            .arg(summary.dynDataUnavailableFieldCount);
    }

    // localPdbProfileText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：把本地 pack 命中、版本、字段和路径合成单行；
    // - 返回：摘要表展示的本地 profile 状态文本。
    QString localPdbProfileText(const KernelDriverStatusSummary& summary)
    {
        if (summary.localPdbProfileMatched)
        {
            return kernelText("kernel.driver_status.pdb.summary.matched", QStringLiteral("命中：%1，版本=%2，字段=%3，typedItems=%4，callbackItems=%5，ActiveProcessLinks=%6，coverage=%7，packProfiles=%8，路径=%9"))
                .arg(safeText(summary.localPdbProfileNameText))
                .arg(safeText(summary.localPdbProfileVersionText, kernelText("kernel.driver_status.placeholder.not_extracted", QStringLiteral("<未提取>"))))
                .arg(summary.localPdbProfileFieldCount)
                .arg(summary.localPdbProfileTypedItemCount)
                .arg(summary.localPdbProfileCallbackItemCount)
                .arg(summary.localPdbProfileActiveProcessLinksPresent
                    ? formatOffset32(summary.localPdbProfileActiveProcessLinksOffset)
                    : kernelText("kernel.driver_status.placeholder.missing", QStringLiteral("<缺失>")))
                .arg(summary.localPdbProfileCoveragePercent >= 0.0 ? QStringLiteral("%1%").arg(summary.localPdbProfileCoveragePercent, 0, 'f', 1) : kernelText("kernel.driver_status.placeholder.unknown", QStringLiteral("<未知>")))
                .arg(summary.localPdbProfilePackProfileCount)
                .arg(safeText(summary.localPdbProfilePathText));
        }

        return safeText(summary.localPdbProfileMessageText, kernelText("kernel.driver_status.pdb.summary.not_matched", QStringLiteral("未命中或未扫描。")));
    }

    // activeProcessLinksOffsetText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：合并本地 pack 提取值与 R0 当前字段表值，突出二者是否都可用；
    // - 返回：用于摘要表/报告的 ActiveProcessLinks 偏移诊断文本。
    QString activeProcessLinksOffsetText(const KernelDriverStatusSummary& summary)
    {
        const QString localText = summary.localPdbProfileActiveProcessLinksPresent
            ? formatOffset32(summary.localPdbProfileActiveProcessLinksOffset)
            : kernelText("kernel.driver_status.placeholder.missing", QStringLiteral("<缺失>"));
        const QString r0Text = summary.dynDataActiveProcessLinksPresent
            ? formatOffset32(summary.dynDataActiveProcessLinksOffset)
            : kernelText("kernel.driver_status.placeholder.not_applied", QStringLiteral("<未应用>"));
        return kernelText("kernel.driver_status.active_process_links", QStringLiteral("LocalPack=%1；R0=%2；R0Source=%3"))
            .arg(localText)
            .arg(r0Text)
            .arg(sourceText(summary.dynDataActiveProcessLinksSource));
    }

    // callbackProfileCoverageText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：把 callback profile active 标志和三类 callback capability 合成一行；
    // - 返回：用户可直接判断 notify/registry/object 是否走可信 PDB 数据的文本。
    QString callbackProfileCoverageText(const KernelDriverStatusSummary& summary)
    {
        return kernelText("kernel.driver_status.callback_coverage", QStringLiteral("Active=%1，Notify=%2，Registry=%3，Object=%4，packCallbackItems=%5，packTypedItems=%6"))
            .arg(boolText(summary.callbackProfileActive))
            .arg(boolText(summary.callbackNotifyTrusted))
            .arg(boolText(summary.callbackRegistryTrusted))
            .arg(boolText(summary.callbackObjectTrusted))
            .arg(summary.localPdbProfileCallbackItemCount)
            .arg(summary.localPdbProfileTypedItemCount);
    }

    // trustedOffsetText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：根据 R0 PDB profile active 标志、字段来源和 pack 命中状态判断可信偏移；
    // - 返回：用户层面的可信偏移状态说明。
    QString trustedOffsetText(const KernelDriverStatusSummary& summary)
    {
        if (summary.trustedPdbOffsetsActive)
        {
            return kernelText("kernel.driver_status.trusted_offsets.active", QStringLiteral("已启用可信 PDB 偏移；PDB字段 %1 / 可用字段 %2，pack=%3，callback=%4。"))
                .arg(summary.dynDataPdbProfileFieldCount)
                .arg(summary.dynDataPresentFieldCount)
                .arg(summary.localPdbProfileMatched
                    ? kernelText("kernel.driver_status.value.matched", QStringLiteral("命中"))
                    : kernelText("kernel.driver_status.value.unconfirmed", QStringLiteral("未确认")))
                .arg(callbackProfileCoverageText(summary));
        }
        if (summary.localPdbProfileMatched)
        {
            return kernelText("kernel.driver_status.trusted_offsets.pack_matched", QStringLiteral("本地 pack 已匹配当前内核，但 R0 当前字段来源尚未切换到 PDB profile。"));
        }
        if (summary.dynDataPresentFieldCount != 0U)
        {
            return kernelText("kernel.driver_status.trusted_offsets.dyndata_only", QStringLiteral("当前有可用 DynData 字段，但未发现 PDB profile 字段；来源=%1。"))
                .arg(fieldSourceSummaryText(summary));
        }
        return kernelText("kernel.driver_status.trusted_offsets.none", QStringLiteral("暂无可用可信偏移。"));
    }

    // dynDataIoText：
    // - 输入 summary：驱动状态摘要；
    // - 处理：拼接 DynData status/fields 两个 IOCTL 的结果；
    // - 返回：R3/R0 通信诊断文本。
    QString dynDataIoText(const KernelDriverStatusSummary& summary)
    {
        return kernelText("kernel.driver_status.dyndata_io", QStringLiteral("Status=%1 (%2)；Fields=%3 (%4)"))
            .arg(boolText(summary.dynDataStatusQueryOk))
            .arg(safeText(summary.dynDataStatusIoMessageText))
            .arg(boolText(summary.dynDataFieldsQueryOk))
            .arg(safeText(summary.dynDataFieldsIoMessageText));
    }

    QString statusBadges(const KernelDriverStatusSummary& summary)
    {
        QStringList badges;
        badges << (summary.driverLoaded ? QStringLiteral("Driver Loaded") : QStringLiteral("Driver Missing"));
        if (!summary.protocolOk) { badges << QStringLiteral("Protocol Mismatch"); }
        if (summary.dynDataMissing) { badges << QStringLiteral("DynData Missing"); }
        if (summary.pdbProfileActive) { badges << QStringLiteral("PDB Profile Active"); }
        if (summary.callbackProfileActive) { badges << QStringLiteral("Callback Profile Active"); }
        if (summary.localPdbProfileMatched) { badges << QStringLiteral("Pack Matched"); }
        if (summary.trustedPdbOffsetsActive) { badges << QStringLiteral("Trusted Offsets"); }
        if (summary.callbackNotifyTrusted || summary.callbackRegistryTrusted || summary.callbackObjectTrusted) { badges << QStringLiteral("Trusted Callback Data"); }
        if (summary.dynDataRequiredMissingCount != 0U) { badges << QStringLiteral("Required Offsets Missing"); }
        if (summary.limited) { badges << QStringLiteral("Limited"); }
        return badges.join(QStringLiteral(", "));
    }

    QString dynDataStatusText(const std::uint32_t flags)
    {
        QStringList parts;
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_INITIALIZED)) { parts << QStringLiteral("Initialized"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE)) { parts << QStringLiteral("NtosActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_LXCORE_ACTIVE)) { parts << QStringLiteral("LxcoreActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_EXTRA_ACTIVE)) { parts << QStringLiteral("ExtraActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE)) { parts << QStringLiteral("PdbProfileActive"); }
        if (flagEnabled(flags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE)) { parts << QStringLiteral("CallbackProfileActive"); }
        return parts.isEmpty() ? QStringLiteral("None") : parts.join(QStringLiteral(", "));
    }

    QString featureFlagText(const std::uint32_t flags)
    {
        QStringList parts;
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_REQUIRES_DYNDATA)) { parts << QStringLiteral("Requires DynData"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_MUTATING)) { parts << QStringLiteral("Mutating"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_KERNEL_ONLY)) { parts << QStringLiteral("Kernel Only"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_READ_ONLY)) { parts << QStringLiteral("Read Only"); }
        if (flagEnabled(flags, KSWORD_ARK_FEATURE_FLAG_POLICY_GATED)) { parts << QStringLiteral("Policy Gated"); }
        return parts.isEmpty() ? QStringLiteral("None") : parts.join(QStringLiteral(", "));
    }

    QString stateText(const std::uint32_t state, const QString& fallbackText)
    {
        switch (state)
        {
        case KSWORD_ARK_FEATURE_STATE_AVAILABLE: return QStringLiteral("Available");
        case KSWORD_ARK_FEATURE_STATE_UNAVAILABLE: return QStringLiteral("Unavailable");
        case KSWORD_ARK_FEATURE_STATE_DEGRADED: return QStringLiteral("Degraded");
        case KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY: return QStringLiteral("Denied by policy");
        default: return safeText(fallbackText, QStringLiteral("Unknown"));
        }
    }

    QBrush stateBrush(const std::uint32_t state)
    {
        if (state == KSWORD_ARK_FEATURE_STATE_AVAILABLE) { return QBrush(KswordTheme::SuccessColor()); }
        if (state == KSWORD_ARK_FEATURE_STATE_DEGRADED) { return QBrush(KswordTheme::WarningColor()); }
        if (state == KSWORD_ARK_FEATURE_STATE_DENIED_BY_POLICY) { return QBrush(KswordTheme::AccentColor(KswordTheme::AccentRole::Purple)); }
        return QBrush(KswordTheme::ErrorColor());
    }

    void appendSummaryRow(QTableWidget* table, const QString& nameText, const QString& valueText)
    {
        if (table == nullptr) { return; }
        const int row = table->rowCount();
        table->insertRow(row);
        auto* nameItem = new QTableWidgetItem(nameText);
        auto* valueItem = new QTableWidgetItem(valueText);
        nameItem->setFlags(nameItem->flags() & ~Qt::ItemIsEditable);
        valueItem->setFlags(valueItem->flags() & ~Qt::ItemIsEditable);
        table->setItem(row, static_cast<int>(DriverSummaryColumn::Name), nameItem);
        table->setItem(row, static_cast<int>(DriverSummaryColumn::Value), valueItem);
    }

    void setReadonlyItem(QTableWidget* table, const int row, const DriverCapabilityColumn column, QTableWidgetItem* item)
    {
        if (table == nullptr || item == nullptr) { delete item; return; }
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        table->setItem(row, static_cast<int>(column), item);
    }

    ks::ui::FieldDocument buildCapabilityDetail(const KernelDriverCapabilityEntry& entry, const KernelDriverStatusSummary& summary)
    {
        ks::ui::FieldDocument lines;
        lines.field(QStringLiteral("功能"), QStringLiteral("%1").arg(safeText(entry.featureNameText)));
        lines.field(QStringLiteral("FeatureId"), QStringLiteral("%1").arg(entry.featureId));
        lines.field(QStringLiteral("状态"), QStringLiteral("%1").arg(stateText(entry.state, entry.stateNameText)));
        lines.field(QStringLiteral("功能标志"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex32(entry.flags))).arg(QStringLiteral("%1").arg(featureFlagText(entry.flags))));

        lines.field(QStringLiteral("依赖字段"), QStringLiteral("%1").arg(safeText(entry.dependencyText, QStringLiteral("None"))));
        lines.field(QStringLiteral("状态原因"), QStringLiteral("%1").arg(safeText(entry.reasonText, QStringLiteral("Feature is available."))));

        lines.field(QStringLiteral("所需安全策略"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex32(entry.requiredPolicyFlags))).arg(QStringLiteral("%1").arg(policyNames(entry.requiredPolicyFlags))));
        lines.field(QStringLiteral("被拒绝策略位"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex32(entry.deniedPolicyFlags))).arg(QStringLiteral("%1").arg(policyNames(entry.deniedPolicyFlags))));
        lines.field(QStringLiteral("所需 DynData capability"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex64(entry.requiredDynDataMask))).arg(QStringLiteral("%1").arg(capabilityNames(entry.requiredDynDataMask))));
        lines.field(QStringLiteral("已满足 DynData capability"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex64(entry.presentDynDataMask))).arg(QStringLiteral("%1").arg(capabilityNames(entry.presentDynDataMask))));
        lines.field(QStringLiteral("全局 DynData capability"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex64(summary.dynDataCapabilityMask))).arg(QStringLiteral("%1").arg(capabilityNames(summary.dynDataCapabilityMask))));

        lines.field(QStringLiteral("当前内核"), QStringLiteral("%1").arg(kernelIdentityText(summary)));
        lines.field(QStringLiteral("识别版本"), QStringLiteral("%1").arg(kernelVersionText(summary)));
        lines.field(QStringLiteral("本地 PDB profile"), QStringLiteral("%1").arg(localPdbProfileText(summary)));
        lines.field(QStringLiteral("ActiveProcessLinks 偏移"), QStringLiteral("%1").arg(activeProcessLinksOffsetText(summary)));
        lines.field(QStringLiteral("可信偏移"), QStringLiteral("%1").arg(trustedOffsetText(summary)));
        lines.field(QStringLiteral("字段覆盖"), QStringLiteral("%1").arg(fieldCoverageText(summary)));
        lines.field(QStringLiteral("字段来源"), QStringLiteral("%1").arg(fieldSourceSummaryText(summary)));

        lines.field(QStringLiteral("驱动状态"), QStringLiteral("%1").arg(statusBadges(summary)));
        lines.field(QStringLiteral("最近 R0 错误"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg(formatNtStatus(summary.lastErrorStatus))).arg(QStringLiteral("%1").arg(safeText(summary.lastErrorSourceText, QStringLiteral("None")))).arg(QStringLiteral("%1").arg(safeText(summary.lastErrorSummaryText, QStringLiteral("None")))));
        return lines;
    }

    ks::ui::FieldDocument buildDriverStatusReport(const KernelDriverStatusSummary& summary, const std::vector<KernelDriverCapabilityEntry>& rows)
    {
        ks::ui::FieldDocument lines;
        lines.note(QStringLiteral("Ksword Driver Capability Diagnostic Report"));
        lines.field(QStringLiteral("Status"), QStringLiteral("%1").arg(statusBadges(summary)));
        lines.field(QStringLiteral("QueryOk"), QStringLiteral("%1").arg(boolText(summary.queryOk)));
        lines.field(QStringLiteral("IoMessage"), QStringLiteral("%1").arg(safeText(summary.ioMessageText)));
        lines.field(QStringLiteral("CapabilityProtocolVersion"), QStringLiteral("%1").arg(summary.version));
        lines.field(QStringLiteral("DriverProtocolVersion"), QStringLiteral("%1").arg(formatHex32(summary.driverProtocolVersion)));
        lines.field(QStringLiteral("ExpectedDriverProtocolVersion"), QStringLiteral("%1").arg(formatHex32(KSWORD_ARK_DRIVER_PROTOCOL_VERSION)));
        lines.field(QStringLiteral("StatusFlags"), QStringLiteral("%1").arg(formatHex32(summary.statusFlags)));
        lines.field(QStringLiteral("SecurityPolicyFlags"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex32(summary.securityPolicyFlags))).arg(QStringLiteral("%1").arg(policyNames(summary.securityPolicyFlags))));
        lines.field(QStringLiteral("DynDataStatusFlags"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex32(summary.dynDataStatusFlags))).arg(QStringLiteral("%1").arg(dynDataStatusText(summary.dynDataStatusFlags))));
        lines.field(QStringLiteral("DynDataCapabilityMask"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(formatHex64(summary.dynDataCapabilityMask))).arg(QStringLiteral("%1").arg(capabilityNames(summary.dynDataCapabilityMask))));
        lines.field(QStringLiteral("DynDataStatusQueryOk"), QStringLiteral("%1").arg(boolText(summary.dynDataStatusQueryOk)));
        lines.field(QStringLiteral("DynDataFieldsQueryOk"), QStringLiteral("%1").arg(boolText(summary.dynDataFieldsQueryOk)));
        lines.field(QStringLiteral("CurrentKernel"), QStringLiteral("%1").arg(kernelIdentityText(summary)));
        lines.field(QStringLiteral("RecognizedVersion"), QStringLiteral("%1").arg(kernelVersionText(summary)));
        lines.field(QStringLiteral("LocalPdbProfileMatched"), QStringLiteral("%1").arg(boolText(summary.localPdbProfileMatched)));
        lines.field(QStringLiteral("LocalPdbProfileName"), QStringLiteral("%1").arg(safeText(summary.localPdbProfileNameText, QStringLiteral("None"))));
        lines.field(QStringLiteral("LocalPdbProfilePath"), QStringLiteral("%1").arg(safeText(summary.localPdbProfilePathText, QStringLiteral("None"))));
        lines.field(QStringLiteral("LocalPdbProfileMessage"), QStringLiteral("%1").arg(safeText(summary.localPdbProfileMessageText, QStringLiteral("None"))));
        lines.field(QStringLiteral("ActiveProcessLinksOffset"), QStringLiteral("%1").arg(activeProcessLinksOffsetText(summary)));
        lines.field(QStringLiteral("CallbackProfileCoverage"), QStringLiteral("%1").arg(callbackProfileCoverageText(summary)));
        lines.field(QStringLiteral("PdbProfileActive"), QStringLiteral("%1").arg(boolText(summary.pdbProfileActive)));
        lines.field(QStringLiteral("CallbackProfileActive"), QStringLiteral("%1").arg(boolText(summary.callbackProfileActive)));
        lines.field(QStringLiteral("TrustedPdbOffsetsActive"), QStringLiteral("%1").arg(boolText(summary.trustedPdbOffsetsActive)));
        lines.field(QStringLiteral("TrustedOffsetSummary"), QStringLiteral("%1").arg(trustedOffsetText(summary)));
        lines.field(QStringLiteral("FieldCoverage"), QStringLiteral("%1").arg(fieldCoverageText(summary)));
        lines.field(QStringLiteral("FieldSources"), QStringLiteral("%1").arg(fieldSourceSummaryText(summary)));
        lines.field(QStringLiteral("SystemInformerData"), QStringLiteral("version=%1 length=%2").arg(QStringLiteral("%1").arg(summary.dynDataSystemInformerDataVersion)).arg(QStringLiteral("%1").arg(summary.dynDataSystemInformerDataLength)));
        lines.field(QStringLiteral("MatchedProfile"), QStringLiteral("class=%1 (%2) offset=%3 fieldsId=%4").arg(QStringLiteral("%1").arg(moduleClassText(summary.dynDataMatchedProfileClass))).arg(QStringLiteral("%1").arg(summary.dynDataMatchedProfileClass)).arg(QStringLiteral("%1").arg(formatHex32(summary.dynDataMatchedProfileOffset))).arg(QStringLiteral("%1").arg(summary.dynDataMatchedFieldsId)));
        lines.field(QStringLiteral("DynDataUnavailableReason"), QStringLiteral("%1").arg(safeText(summary.dynDataUnavailableReasonText, QStringLiteral("None"))));
        lines.field(QStringLiteral("DynDataIo"), QStringLiteral("%1").arg(dynDataIoText(summary)));
        lines.field(QStringLiteral("LastError"), QStringLiteral("%1 / %2 / %3").arg(QStringLiteral("%1").arg(formatNtStatus(summary.lastErrorStatus))).arg(QStringLiteral("%1").arg(safeText(summary.lastErrorSourceText, QStringLiteral("None")))).arg(QStringLiteral("%1").arg(safeText(summary.lastErrorSummaryText, QStringLiteral("None")))));
        lines.field(QStringLiteral("FeatureCount"), QStringLiteral("returned=%1 total=%2").arg(QStringLiteral("%1").arg(summary.returnedFeatureCount)).arg(QStringLiteral("%1").arg(summary.totalFeatureCount)));
        lines.section(QStringLiteral("Features"));
        for (const KernelDriverCapabilityEntry& entry : rows)
        {
            lines.section(QStringLiteral("Capability"));
            lines.field(QStringLiteral("Feature"), safeText(entry.featureNameText));
            lines.field(QStringLiteral("State"), stateText(entry.state, entry.stateNameText));
            lines.field(QStringLiteral("PolicyFlags"), formatHex32(entry.requiredPolicyFlags));
            lines.field(QStringLiteral("RequiredDynDataMask"), formatHex64(entry.requiredDynDataMask));
            lines.field(QStringLiteral("PresentDynDataMask"), formatHex64(entry.presentDynDataMask));
            lines.field(QStringLiteral("Dependency"), safeText(entry.dependencyText, QStringLiteral("None")));
            lines.field(QStringLiteral("Reason"), safeText(entry.reasonText, QStringLiteral("None")));
        }
        return lines;
    }

    void populateSummaryTable(QTableWidget* table, const KernelDriverStatusSummary& summary, const std::size_t visibleRows)
    {
        if (table == nullptr) { return; }
        table->setSortingEnabled(false);
        table->setRowCount(0);
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.status_bar", QStringLiteral("状态栏")), statusBadges(summary));
        appendSummaryRow(table, QStringLiteral("Driver Loaded"), boolText(summary.driverLoaded));
        appendSummaryRow(table, QStringLiteral("Protocol OK"), boolText(summary.protocolOk));
        appendSummaryRow(table, QStringLiteral("DynData Missing"), boolText(summary.dynDataMissing));
        appendSummaryRow(table, QStringLiteral("Limited"), boolText(summary.limited));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.current_kernel", QStringLiteral("当前内核")), kernelIdentityText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.recognized_version", QStringLiteral("识别版本")), kernelVersionText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.local_pdb", QStringLiteral("本地 PDB profile")), localPdbProfileText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.active_process_links", QStringLiteral("ActiveProcessLinks 偏移")), activeProcessLinksOffsetText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.callback_coverage", QStringLiteral("Callback profile 覆盖")), callbackProfileCoverageText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.trusted_offsets", QStringLiteral("可信偏移")), trustedOffsetText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.field_coverage", QStringLiteral("字段覆盖")), fieldCoverageText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.field_sources", QStringLiteral("字段来源")), fieldSourceSummaryText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.required_missing", QStringLiteral("缺失必需字段")), QString::number(summary.dynDataRequiredMissingCount));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.capability_version", QStringLiteral("能力协议版本")), QString::number(summary.version));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.driver_protocol", QStringLiteral("驱动协议版本")), formatHex32(summary.driverProtocolVersion));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.expected_protocol", QStringLiteral("期望协议版本")), formatHex32(KSWORD_ARK_DRIVER_PROTOCOL_VERSION));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.status_flags", QStringLiteral("状态位")), formatHex32(summary.statusFlags));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.security_policy", QStringLiteral("安全策略位")), QStringLiteral("%1 (%2)").arg(formatHex32(summary.securityPolicyFlags)).arg(policyNames(summary.securityPolicyFlags)));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.dyndata_status", QStringLiteral("DynData 状态位")), QStringLiteral("%1 (%2)").arg(formatHex32(summary.dynDataStatusFlags)).arg(dynDataStatusText(summary.dynDataStatusFlags)));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.dyndata_capability", QStringLiteral("DynData 能力位")), QStringLiteral("%1 (%2)").arg(formatHex64(summary.dynDataCapabilityMask)).arg(capabilityNames(summary.dynDataCapabilityMask)));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.system_informer", QStringLiteral("System Informer 数据")), QStringLiteral("version=%1 length=%2")
            .arg(summary.dynDataSystemInformerDataVersion)
            .arg(summary.dynDataSystemInformerDataLength));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.matched_profile", QStringLiteral("匹配内置 Profile")), QStringLiteral("class=%1 (%2) offset=%3 fieldsId=%4")
            .arg(moduleClassText(summary.dynDataMatchedProfileClass))
            .arg(summary.dynDataMatchedProfileClass)
            .arg(formatHex32(summary.dynDataMatchedProfileOffset))
            .arg(summary.dynDataMatchedFieldsId));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.callback_trusted", QStringLiteral("Callback profile 可信覆盖")), callbackProfileCoverageText(summary));
        appendSummaryRow(table, QStringLiteral("DynData R3 IO"), dynDataIoText(summary));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.dyndata_unavailable_reason", QStringLiteral("DynData 不可用原因")), safeText(summary.dynDataUnavailableReasonText, QStringLiteral("None")));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.feature_count", QStringLiteral("功能数")), kernelText("kernel.driver_status.summary.feature_count_value", QStringLiteral("显示 %1 / 返回 %2 / 总计 %3")).arg(visibleRows).arg(summary.returnedFeatureCount).arg(summary.totalFeatureCount));
        appendSummaryRow(table, kernelText("kernel.driver_status.summary.last_error", QStringLiteral("最近错误")), QStringLiteral("%1 / %2 / %3").arg(formatNtStatus(summary.lastErrorStatus)).arg(safeText(summary.lastErrorSourceText, QStringLiteral("None"))).arg(safeText(summary.lastErrorSummaryText, QStringLiteral("None"))));
        appendSummaryRow(table, QStringLiteral("R3 IO"), safeText(summary.ioMessageText));
    }

    // buildDriverStatusLabelText：
    // - 输入 summary 和 capability 行数；
    // - 处理：为顶部状态栏生成一句可读摘要；
    // - 返回：适合 QLabel 直接显示的状态文本。
    QString buildDriverStatusLabelText(const KernelDriverStatusSummary& summary, const std::size_t capabilityCount)
    {
        const QString kernelSummaryText = summary.ntoskrnlIdentityPresent
            ? QStringLiteral("%1 / %2").arg(safeText(summary.ntoskrnlModuleNameText), kernelVersionText(summary))
            : kernelText("kernel.driver_status.placeholder.kernel_unrecognized", QStringLiteral("内核未识别"));
        const QString offsetText = trustedOffsetText(summary);
        if (!summary.queryOk && !summary.dynDataStatusQueryOk)
        {
            return kernelText("kernel.driver_status.status.both_queries_failed", QStringLiteral("状态：驱动与 DynData 查询均失败"));
        }

        return kernelText("kernel.driver_status.status.summary", QStringLiteral("状态：%1；%2；功能 %3 项；可信偏移 %4"))
            .arg(statusBadges(summary))
            .arg(kernelSummaryText)
            .arg(capabilityCount)
            .arg(offsetText);
    }

    bool shouldShowCapability(const KernelDriverCapabilityEntry& entry, const QString& filter)
    {
        if (filter.isEmpty()) { return true; }
        return entry.featureNameText.contains(filter, Qt::CaseInsensitive) ||
            stateText(entry.state, entry.stateNameText).contains(filter, Qt::CaseInsensitive) ||
            entry.dependencyText.contains(filter, Qt::CaseInsensitive) ||
            entry.reasonText.contains(filter, Qt::CaseInsensitive) ||
            featureFlagText(entry.flags).contains(filter, Qt::CaseInsensitive) ||
            policyNames(entry.requiredPolicyFlags).contains(filter, Qt::CaseInsensitive) ||
            capabilityNames(entry.requiredDynDataMask).contains(filter, Qt::CaseInsensitive) ||
            formatHex64(entry.requiredDynDataMask).contains(filter, Qt::CaseInsensitive);
    }

    bool queryDriverStatusSnapshot(KernelDriverStatusSummary& summaryOut, std::vector<KernelDriverCapabilityEntry>& rowsOut)
    {
        ksword::ark::DriverClient client;
        const ksword::ark::DriverCapabilitiesQueryResult queryResult = client.queryDriverCapabilities();
        const ksword::ark::DynDataStatusResult statusResult = client.queryDynDataStatus();
        const ksword::ark::DynDataFieldsResult fieldsResult = client.queryDynDataFields();

        summaryOut = KernelDriverStatusSummary{};
        rowsOut.clear();
        summaryOut.queryOk = queryResult.io.ok;
        summaryOut.driverLoaded = queryResult.io.ok || queryResult.io.win32Error != ERROR_FILE_NOT_FOUND;
        summaryOut.ioMessageText = friendlyDriverStatusIoMessage(queryResult.io.message);

        summaryOut.dynDataStatusQueryOk = statusResult.io.ok;
        summaryOut.dynDataFieldsQueryOk = fieldsResult.io.ok;
        summaryOut.dynDataStatusIoMessageText = friendlyDriverStatusIoMessage(statusResult.io.message);
        summaryOut.dynDataFieldsIoMessageText = friendlyDriverStatusIoMessage(fieldsResult.io.message);

        if (queryResult.io.ok)
        {
            summaryOut.version = queryResult.version;
            summaryOut.driverProtocolVersion = queryResult.driverProtocolVersion;
            summaryOut.statusFlags = queryResult.statusFlags;
            summaryOut.securityPolicyFlags = queryResult.securityPolicyFlags;
            summaryOut.dynDataStatusFlags = queryResult.dynDataStatusFlags;
            summaryOut.lastErrorStatus = queryResult.lastErrorStatus;
            summaryOut.totalFeatureCount = queryResult.totalFeatureCount;
            summaryOut.returnedFeatureCount = queryResult.returnedFeatureCount;
            summaryOut.dynDataCapabilityMask = queryResult.dynDataCapabilityMask;
            summaryOut.lastErrorSourceText = stringToQString(queryResult.lastErrorSource);
            summaryOut.lastErrorSummaryText = stringToQString(queryResult.lastErrorSummary);
        }
        else if (statusResult.io.ok)
        {
            summaryOut.dynDataStatusFlags = statusResult.statusFlags;
            summaryOut.dynDataCapabilityMask = statusResult.capabilityMask;
            summaryOut.lastErrorStatus = statusResult.lastStatus;
        }

        summaryOut.driverLoaded = flagEnabled(summaryOut.statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_DRIVER_LOADED) ||
            queryResult.io.ok ||
            statusResult.io.ok ||
            fieldsResult.io.ok;
        summaryOut.protocolOk = (queryResult.io.ok &&
            flagEnabled(summaryOut.statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_PROTOCOL_OK) &&
            summaryOut.driverProtocolVersion == KSWORD_ARK_DRIVER_PROTOCOL_VERSION);

        if (statusResult.io.ok)
        {
            summaryOut.dynDataStatusFlags = statusResult.statusFlags;
            summaryOut.dynDataSystemInformerDataVersion = statusResult.systemInformerDataVersion;
            summaryOut.dynDataSystemInformerDataLength = statusResult.systemInformerDataLength;
            summaryOut.dynDataMatchedProfileClass = statusResult.matchedProfileClass;
            summaryOut.dynDataMatchedProfileOffset = statusResult.matchedProfileOffset;
            summaryOut.dynDataMatchedFieldsId = statusResult.matchedFieldsId;
            summaryOut.dynDataFieldCount = statusResult.fieldCount;
            summaryOut.dynDataCapabilityMask = statusResult.capabilityMask;
            summaryOut.ntoskrnlIdentityPresent = statusResult.ntoskrnl.present;
            summaryOut.ntoskrnlClassId = statusResult.ntoskrnl.classId;
            summaryOut.ntoskrnlMachine = statusResult.ntoskrnl.machine;
            summaryOut.ntoskrnlTimeDateStamp = statusResult.ntoskrnl.timeDateStamp;
            summaryOut.ntoskrnlSizeOfImage = statusResult.ntoskrnl.sizeOfImage;
            summaryOut.ntoskrnlImageBase = statusResult.ntoskrnl.imageBase;
            summaryOut.ntoskrnlModuleNameText = wideStringToQString(statusResult.ntoskrnl.moduleName);
            summaryOut.dynDataUnavailableReasonText = wideStringToQString(statusResult.unavailableReason);
        }

        if (fieldsResult.io.ok)
        {
            if (summaryOut.dynDataFieldCount == 0U)
            {
                summaryOut.dynDataFieldCount = fieldsResult.totalCount;
            }
            summaryOut.dynDataReturnedFieldCount = fieldsResult.returnedCount != 0U
                ? fieldsResult.returnedCount
                : static_cast<std::uint32_t>(fieldsResult.entries.size());
            for (const ksword::ark::DynDataFieldEntry& entry : fieldsResult.entries)
            {
                if (fieldOffsetPresent(entry.flags, entry.offset))
                {
                    summaryOut.dynDataPresentFieldCount += 1U;
                    switch (entry.source)
                    {
                    case KSW_DYN_FIELD_SOURCE_PDB_PROFILE:
                        summaryOut.dynDataPdbProfileFieldCount += 1U;
                        break;
                    case KSW_DYN_FIELD_SOURCE_RUNTIME_PATTERN:
                        summaryOut.dynDataRuntimePatternFieldCount += 1U;
                        break;
                    case KSW_DYN_FIELD_SOURCE_SYSTEM_INFORMER:
                        summaryOut.dynDataSystemInformerFieldCount += 1U;
                        break;
                    case KSW_DYN_FIELD_SOURCE_KSWORD_EXTRA_TABLE:
                        summaryOut.dynDataExtraTableFieldCount += 1U;
                        break;
                    default:
                        summaryOut.dynDataUnavailableFieldCount += 1U;
                        break;
                    }
                }
                else
                {
                    summaryOut.dynDataUnavailableFieldCount += 1U;
                }

                if ((entry.flags & KSW_DYN_FIELD_FLAG_REQUIRED) != 0U && !fieldOffsetPresent(entry.flags, entry.offset))
                {
                    summaryOut.dynDataRequiredMissingCount += 1U;
                }

                if (entry.fieldId == KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS)
                {
                    summaryOut.dynDataActiveProcessLinksPresent = fieldOffsetPresent(entry.flags, entry.offset);
                    summaryOut.dynDataActiveProcessLinksOffset = entry.offset;
                    summaryOut.dynDataActiveProcessLinksSource = entry.source;
                }
            }
        }

        if (statusResult.io.ok && statusResult.ntoskrnl.present)
        {
            const LocalPdbPackMatch packMatch = findMatchingLocalPdbProfilePack(statusResult.ntoskrnl);
            summaryOut.localPdbProfileMatched = packMatch.matched && packMatch.valid;
            summaryOut.localPdbProfilePackProfileCount = packMatch.profileCount;
            summaryOut.localPdbProfileFieldCount = packMatch.fieldCount;
            summaryOut.localPdbProfileTypedItemCount = packMatch.typedItemCount;
            summaryOut.localPdbProfileNameText = packMatch.profileNameText;
            summaryOut.localPdbProfileVersionText = packMatch.versionText;
            summaryOut.localPdbProfilePathText = packMatch.pathText;
            summaryOut.localPdbProfileMessageText = packMatch.messageText;
            summaryOut.localPdbProfileCallbackItemCount = packMatch.callbackItemCount;
            summaryOut.localPdbProfileActiveProcessLinksPresent = packMatch.activeProcessLinksPresent;
            summaryOut.localPdbProfileActiveProcessLinksOffset = packMatch.activeProcessLinksOffset;
            summaryOut.localPdbProfileCoveragePercent = packMatch.coveragePercent;
        }

        summaryOut.pdbProfileActive = flagEnabled(summaryOut.dynDataStatusFlags, KSW_DYN_STATUS_FLAG_PDB_PROFILE_ACTIVE);
        summaryOut.callbackProfileActive = flagEnabled(summaryOut.dynDataStatusFlags, KSW_DYN_STATUS_FLAG_CALLBACK_PROFILE_ACTIVE);
        summaryOut.callbackNotifyTrusted = (summaryOut.dynDataCapabilityMask & KSW_CAP_CALLBACK_NOTIFY_GLOBALS) != 0ULL;
        summaryOut.callbackRegistryTrusted = (summaryOut.dynDataCapabilityMask & KSW_CAP_CALLBACK_REGISTRY_GLOBALS) != 0ULL;
        summaryOut.callbackObjectTrusted = (summaryOut.dynDataCapabilityMask & KSW_CAP_CALLBACK_OBJECT_FIELDS) != 0ULL;
        summaryOut.trustedPdbOffsetsActive = summaryOut.pdbProfileActive ||
            summaryOut.callbackProfileActive ||
            summaryOut.dynDataPdbProfileFieldCount > 0U;
        summaryOut.dynDataMissing = !summaryOut.dynDataStatusQueryOk ||
            !flagEnabled(summaryOut.dynDataStatusFlags, KSW_DYN_STATUS_FLAG_NTOS_ACTIVE);
        summaryOut.limited = !summaryOut.protocolOk ||
            flagEnabled(summaryOut.statusFlags, KSWORD_ARK_DRIVER_STATUS_FLAG_LIMITED) ||
            !summaryOut.dynDataStatusQueryOk;

        rowsOut.reserve(queryResult.entries.size());
        for (const ksword::ark::DriverFeatureCapabilityEntry& sourceEntry : queryResult.entries)
        {
            KernelDriverCapabilityEntry row{};
            row.featureId = sourceEntry.featureId;
            row.state = sourceEntry.state;
            row.flags = sourceEntry.flags;
            row.requiredPolicyFlags = sourceEntry.requiredPolicyFlags;
            row.deniedPolicyFlags = sourceEntry.deniedPolicyFlags;
            row.requiredDynDataMask = sourceEntry.requiredDynDataMask;
            row.presentDynDataMask = sourceEntry.presentDynDataMask;
            row.featureNameText = stringToQString(sourceEntry.featureName);
            row.stateNameText = stateText(sourceEntry.state, stringToQString(sourceEntry.stateName));
            row.dependencyText = stringToQString(sourceEntry.dependencyText);
            row.reasonText = stringToQString(sourceEntry.reasonText);
            row.detailDocument = buildCapabilityDetail(row, summaryOut);
            rowsOut.push_back(std::move(row));
        }

        return summaryOut.queryOk && summaryOut.protocolOk;
    }
}

void KernelDock::initializeDriverStatusTab()
{
    if (m_driverStatusPage == nullptr || m_driverStatusLayout != nullptr) { return; }

    m_driverStatusLayout = new QVBoxLayout(m_driverStatusPage);
    m_driverStatusLayout->setContentsMargins(4, 4, 4, 4);
    m_driverStatusLayout->setSpacing(6);

    m_driverStatusToolLayout = new QHBoxLayout();
    m_driverStatusToolLayout->setContentsMargins(0, 0, 0, 0);
    m_driverStatusToolLayout->setSpacing(6);

    m_refreshDriverStatusButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QString(), m_driverStatusPage);
    m_refreshDriverStatusButton->setToolTip(kernelText("kernel.driver_status.toolbar.refresh.tooltip", QStringLiteral("刷新 KswordARK 驱动状态、协议、安全策略和能力矩阵")));
    m_refreshDriverStatusButton->setStyleSheet(blueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshDriverStatusButton);

    m_copyDriverStatusReportButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), kernelText("kernel.driver_status.toolbar.copy_report", QStringLiteral("复制诊断")), m_driverStatusPage);
    m_copyDriverStatusReportButton->setToolTip(kernelText("kernel.driver_status.toolbar.copy_report.tooltip", QStringLiteral("复制统一驱动状态和能力矩阵诊断报告")));
    m_copyDriverStatusReportButton->setStyleSheet(blueButtonStyle());

    m_driverStatusFilterEdit = new QLineEdit(m_driverStatusPage);
    m_driverStatusFilterEdit->setPlaceholderText(kernelText("kernel.driver_status.toolbar.filter.placeholder", QStringLiteral("按功能/状态/策略/DynData capability/依赖字段筛选")));
    m_driverStatusFilterEdit->setToolTip(kernelText("kernel.driver_status.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤驱动能力矩阵")));
    m_driverStatusFilterEdit->setClearButtonEnabled(true);
    m_driverStatusFilterEdit->setStyleSheet(blueInputStyle());

    m_driverStatusLabel = new QLabel(kernelText("kernel.driver_status.status.waiting", QStringLiteral("状态：等待刷新")), m_driverStatusPage);
    m_driverStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::TextSecondaryHex()));

    m_driverStatusToolLayout->addWidget(m_refreshDriverStatusButton, 0);
    m_driverStatusToolLayout->addWidget(m_copyDriverStatusReportButton, 0);
    m_driverStatusToolLayout->addWidget(m_driverStatusFilterEdit, 1);
    m_driverStatusToolLayout->addWidget(m_driverStatusLabel, 0);
    m_driverStatusLayout->addLayout(m_driverStatusToolLayout);

    QSplitter* verticalSplitter = new QSplitter(Qt::Vertical, m_driverStatusPage);
    m_driverStatusLayout->addWidget(verticalSplitter, 1);

    m_driverStatusSummaryTable = new ks::ui::VisibleTableWidget(verticalSplitter);
    m_driverStatusSummaryTable->setColumnCount(static_cast<int>(DriverSummaryColumn::Count));
    m_driverStatusSummaryTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.summary.header.item", QStringLiteral("项目")),
        kernelText("kernel.driver_status.summary.header.value", QStringLiteral("值")) });
    m_driverStatusSummaryTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_driverStatusSummaryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_driverStatusSummaryTable->setAlternatingRowColors(true);
    m_driverStatusSummaryTable->setStyleSheet(itemSelectionStyle());
    m_driverStatusSummaryTable->setCornerButtonEnabled(false);
    m_driverStatusSummaryTable->verticalHeader()->setVisible(false);
    m_driverStatusSummaryTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_driverStatusSummaryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_driverStatusSummaryTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(DriverSummaryColumn::Value), QHeaderView::Stretch);
    m_driverStatusSummaryTable->setColumnWidth(static_cast<int>(DriverSummaryColumn::Name), 220);
    installDriverStatusCopyMenu(m_driverStatusSummaryTable);

    QSplitter* lowerSplitter = new QSplitter(Qt::Horizontal, verticalSplitter);
    m_driverCapabilityTable = new ks::ui::VisibleTableWidget(lowerSplitter);
    m_driverCapabilityTable->setColumnCount(static_cast<int>(DriverCapabilityColumn::Count));
    m_driverCapabilityTable->setHorizontalHeaderLabels(QStringList{
        kernelText("kernel.driver_status.capability.header.feature", QStringLiteral("功能")),
        kernelText("kernel.driver_status.capability.header.state", QStringLiteral("状态")),
        kernelText("kernel.driver_status.capability.header.policy", QStringLiteral("策略")),
        kernelText("kernel.driver_status.capability.header.required_dyndata", QStringLiteral("所需DynData")),
        kernelText("kernel.driver_status.capability.header.present_dyndata", QStringLiteral("已满足DynData")),
        kernelText("kernel.driver_status.capability.header.dependency", QStringLiteral("依赖字段")),
        kernelText("kernel.driver_status.capability.header.reason", QStringLiteral("原因")) });
    m_driverCapabilityTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_driverCapabilityTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_driverCapabilityTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_driverCapabilityTable->setAlternatingRowColors(true);
    m_driverCapabilityTable->setStyleSheet(itemSelectionStyle());
    m_driverCapabilityTable->setCornerButtonEnabled(false);
    m_driverCapabilityTable->verticalHeader()->setVisible(false);
    m_driverCapabilityTable->horizontalHeader()->setStyleSheet(headerStyle());
    m_driverCapabilityTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_driverCapabilityTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(DriverCapabilityColumn::Feature), QHeaderView::Stretch);
    m_driverCapabilityTable->setColumnWidth(static_cast<int>(DriverCapabilityColumn::State), 140);
    m_driverCapabilityTable->setColumnWidth(static_cast<int>(DriverCapabilityColumn::RequiredDyn), 180);
    m_driverCapabilityTable->setColumnWidth(static_cast<int>(DriverCapabilityColumn::PresentDyn), 180);
    m_driverCapabilityTable->setColumnWidth(static_cast<int>(DriverCapabilityColumn::Dependency), 280);
    installDriverStatusCopyMenu(m_driverCapabilityTable);

    m_driverCapabilityDetailEditor = new ks::ui::StructuredFieldView(lowerSplitter);

    m_driverCapabilityDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.driver_status.detail.initial", QStringLiteral("请选择一条驱动功能能力查看依赖字段和诊断详情。"))));

    verticalSplitter->setStretchFactor(0, 2);
    verticalSplitter->setStretchFactor(1, 5);
    lowerSplitter->setStretchFactor(0, 3);
    lowerSplitter->setStretchFactor(1, 2);

    connect(m_refreshDriverStatusButton, &QPushButton::clicked, this, [this]() { refreshDriverStatusAsync(); });
    connect(m_copyDriverStatusReportButton, &QPushButton::clicked, this, [this]() {
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr)
        {
            clipboard->setText(buildDriverStatusReport(m_driverStatusSummary, m_driverCapabilityRows).toPlainText(true));
            m_driverStatusLabel->setText(kernelText("kernel.driver_status.status.report_copied", QStringLiteral("状态：诊断报告已复制")));
        }
    });
    connect(m_driverStatusFilterEdit, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildDriverCapabilityTable(filterText.trimmed());
    });
    connect(m_driverCapabilityTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showDriverCapabilityDetailByCurrentRow();
    });
}

void KernelDock::refreshDriverStatusAsync()
{
    if (m_driverStatusRefreshRunning.exchange(true))
    {
        kLogEvent skipEvent;
        dbg << skipEvent << "[KernelDock] 驱动状态刷新被忽略：已有任务运行。" << eol;
        return;
    }

    m_refreshDriverStatusButton->setEnabled(false);
    m_driverStatusLabel->setText(kernelText("kernel.driver_status.status.refreshing", QStringLiteral("状态：刷新中...")));
    m_driverStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::PrimaryBlueHex));

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        KernelDriverStatusSummary summary;
        std::vector<KernelDriverCapabilityEntry> rows;
        const bool success = queryDriverStatusSnapshot(summary, rows);

        QMetaObject::invokeMethod(guardThis, [guardThis, success, summary = std::move(summary), rows = std::move(rows)]() mutable {
            const auto deferredSummary =
                std::make_shared<KernelDriverStatusSummary>(std::move(summary));
            const auto deferredRows =
                std::make_shared<std::vector<KernelDriverCapabilityEntry>>(std::move(rows));
            auto commitResult = [guardThis, success, deferredSummary, deferredRows]() mutable
            {
            KernelDriverStatusSummary& summary = *deferredSummary;
            std::vector<KernelDriverCapabilityEntry>& rows = *deferredRows;
            if (guardThis == nullptr) { return; }

            guardThis->m_driverStatusRefreshRunning.store(false);
            guardThis->m_refreshDriverStatusButton->setEnabled(true);
            guardThis->m_driverStatusSummary = std::move(summary);
            guardThis->m_driverCapabilityRows = std::move(rows);
            populateSummaryTable(guardThis->m_driverStatusSummaryTable, guardThis->m_driverStatusSummary, guardThis->m_driverCapabilityRows.size());
            guardThis->rebuildDriverCapabilityTable(guardThis->m_driverStatusFilterEdit->text().trimmed());

            if (!success)
            {
                guardThis->m_driverStatusLabel->setText(buildDriverStatusLabelText(
                    guardThis->m_driverStatusSummary,
                    guardThis->m_driverCapabilityRows.size()));
                guardThis->m_driverStatusLabel->setStyleSheet(statusLabelStyle(KswordTheme::ErrorHex()));
                guardThis->m_driverCapabilityDetailEditor->setDocument(buildDriverStatusReport(guardThis->m_driverStatusSummary, guardThis->m_driverCapabilityRows));
                return;
            }

            const std::size_t unavailableCount = static_cast<std::size_t>(std::count_if(
                guardThis->m_driverCapabilityRows.begin(),
                guardThis->m_driverCapabilityRows.end(),
                [](const KernelDriverCapabilityEntry& entry) { return entry.state != KSWORD_ARK_FEATURE_STATE_AVAILABLE; }));
            guardThis->m_driverStatusLabel->setText(buildDriverStatusLabelText(
                guardThis->m_driverStatusSummary,
                guardThis->m_driverCapabilityRows.size()));
            const bool healthyOffsets = guardThis->m_driverStatusSummary.trustedPdbOffsetsActive &&
                guardThis->m_driverStatusSummary.dynDataRequiredMissingCount == 0U;
            guardThis->m_driverStatusLabel->setStyleSheet(statusLabelStyle(
            unavailableCount == 0U && healthyOffsets ? KswordTheme::SuccessHex() : KswordTheme::WarningHex()));

            if (guardThis->m_driverCapabilityTable->rowCount() > 0)
            {
                guardThis->m_driverCapabilityTable->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->m_driverCapabilityDetailEditor->setDocument(ks::ui::FieldDocument{}.note(kernelText("kernel.driver_status.empty.filtered", QStringLiteral("当前筛选条件下没有驱动能力记录。"))));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-driver-status-snapshot-apply"),
                { guardThis->m_driverStatusSummaryTable, guardThis->m_driverCapabilityTable },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildDriverCapabilityTable(const QString& filterKeyword)
{
    if (m_driverCapabilityTable == nullptr) { return; }

    m_driverCapabilityTable->setSortingEnabled(false);
    m_driverCapabilityTable->setRowCount(0);

    for (std::size_t sourceIndex = 0U; sourceIndex < m_driverCapabilityRows.size(); ++sourceIndex)
    {
        const KernelDriverCapabilityEntry& entry = m_driverCapabilityRows[sourceIndex];
        if (!shouldShowCapability(entry, filterKeyword)) { continue; }

        const int row = m_driverCapabilityTable->rowCount();
        m_driverCapabilityTable->insertRow(row);
        auto* featureItem = new QTableWidgetItem(safeText(entry.featureNameText));
        auto* stateItem = new QTableWidgetItem(stateText(entry.state, entry.stateNameText));
        auto* policyItem = new QTableWidgetItem(formatHex32(entry.requiredPolicyFlags));
        auto* requiredItem = new QTableWidgetItem(formatHex64(entry.requiredDynDataMask));
        auto* presentItem = new QTableWidgetItem(formatHex64(entry.presentDynDataMask));
        auto* dependencyItem = new QTableWidgetItem(safeText(entry.dependencyText, QStringLiteral("None")));
        auto* reasonItem = new QTableWidgetItem(safeText(entry.reasonText, QStringLiteral("None")));

        featureItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        stateItem->setForeground(stateBrush(entry.state));
        if (entry.deniedPolicyFlags != 0U) { policyItem->setForeground(QBrush(KswordTheme::ErrorColor())); }
        if (entry.requiredDynDataMask != 0ULL && entry.presentDynDataMask != entry.requiredDynDataMask)
        {
            presentItem->setForeground(QBrush(KswordTheme::ErrorColor()));
        }

        setReadonlyItem(m_driverCapabilityTable, row, DriverCapabilityColumn::Feature, featureItem);
        setReadonlyItem(m_driverCapabilityTable, row, DriverCapabilityColumn::State, stateItem);
        setReadonlyItem(m_driverCapabilityTable, row, DriverCapabilityColumn::Policy, policyItem);
        setReadonlyItem(m_driverCapabilityTable, row, DriverCapabilityColumn::RequiredDyn, requiredItem);
        setReadonlyItem(m_driverCapabilityTable, row, DriverCapabilityColumn::PresentDyn, presentItem);
        setReadonlyItem(m_driverCapabilityTable, row, DriverCapabilityColumn::Dependency, dependencyItem);
        setReadonlyItem(m_driverCapabilityTable, row, DriverCapabilityColumn::Reason, reasonItem);
    }

    m_driverCapabilityTable->setSortingEnabled(true);
    populateSummaryTable(m_driverStatusSummaryTable, m_driverStatusSummary, static_cast<std::size_t>(m_driverCapabilityTable->rowCount()));
}

bool KernelDock::currentDriverCapabilitySourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;
    if (m_driverCapabilityTable == nullptr) { return false; }
    const int currentRow = m_driverCapabilityTable->currentRow();
    if (currentRow < 0) { return false; }

    QTableWidgetItem* featureItem = m_driverCapabilityTable->item(currentRow, static_cast<int>(DriverCapabilityColumn::Feature));
    if (featureItem == nullptr) { return false; }

    sourceIndexOut = static_cast<std::size_t>(featureItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < m_driverCapabilityRows.size();
}

const KernelDriverCapabilityEntry* KernelDock::currentDriverCapabilityEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentDriverCapabilitySourceIndex(sourceIndex)) { return nullptr; }
    return &m_driverCapabilityRows[sourceIndex];
}

void KernelDock::showDriverCapabilityDetailByCurrentRow()
{
    if (m_driverCapabilityDetailEditor == nullptr) { return; }

    const KernelDriverCapabilityEntry* entry = currentDriverCapabilityEntry();
    if (entry == nullptr)
    {
        m_driverCapabilityDetailEditor->setDocument(buildDriverStatusReport(m_driverStatusSummary, m_driverCapabilityRows));
        return;
    }

    m_driverCapabilityDetailEditor->setDocument(entry->detailDocument);
}
