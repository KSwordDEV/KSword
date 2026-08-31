#include "StartupDock.Internal.h"

#include "../theme.h"

#include <QPainter>
#include <QPixmap>
#include <QSvgRenderer>


namespace startup_dock_detail
{
    QIcon createBlueIcon(const char* resourcePath, const QSize& iconSize)
    {
        const QString iconPath = QString::fromUtf8(resourcePath);
        QSvgRenderer renderer(iconPath);
        if (!renderer.isValid())
        {
            return QIcon(iconPath);
        }

        QPixmap pixmap(iconSize);
        pixmap.fill(Qt::transparent);

        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        renderer.render(&painter, QRectF(0, 0, iconSize.width(), iconSize.height()));
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(pixmap.rect(), KswordTheme::PrimaryBlueColor);
        painter.end();

        return QIcon(pixmap);
    }

    QTableWidgetItem* createReadOnlyItem(const QString& textValue)
    {
        QTableWidgetItem* itemPointer = new QTableWidgetItem(textValue);
        itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
        itemPointer->setToolTip(textValue);
        return itemPointer;
    }

    QString winErrorText(const DWORD errorCode)
    {
        LPWSTR bufferPointer = nullptr;
        const DWORD charCount = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&bufferPointer),
            0,
            nullptr);
        if (charCount == 0 || bufferPointer == nullptr)
        {
            return QStringLiteral("Win32Error=%1").arg(errorCode);
        }

        const QString messageText = QString::fromWCharArray(bufferPointer).trimmed();
        ::LocalFree(bufferPointer);
        return QStringLiteral("%1 (code=%2)").arg(messageText).arg(errorCode);
    }

    QString buildStatusText(const bool enabled)
    {
        return enabled
            ? startupText("startup.value.enabled", QStringLiteral("启用"))
            : startupText("startup.value.disabled", QStringLiteral("禁用"));
    }

    QString buildStatusText(const ks::startup::StartupEntry& entry)
    {
        if (entry.actionKind != ks::startup::StartupActionKind::ScmStartType)
        {
            return buildStatusText(entry.enabled);
        }
        switch (entry.actionLocator.serviceStartMode)
        {
        case ks::startup::StartupScmStartMode::Boot:
            return startupText("startup.value.scm.boot", QStringLiteral("引导启动"));
        case ks::startup::StartupScmStartMode::System:
            return startupText("startup.value.scm.system", QStringLiteral("系统启动"));
        case ks::startup::StartupScmStartMode::Automatic:
            return startupText("startup.value.scm.automatic", QStringLiteral("自动启动"));
        case ks::startup::StartupScmStartMode::Manual:
            return startupText("startup.value.scm.manual", QStringLiteral("手动启动"));
        case ks::startup::StartupScmStartMode::Disabled:
            return startupText("startup.value.scm.disabled", QStringLiteral("已禁用"));
        case ks::startup::StartupScmStartMode::None:
        default:
            return buildStatusText(entry.enabled);
        }
    }

    QString startupRiskReasonText(const ks::startup::StartupEntry& backendEntry)
    {
        QString fallbackText = QString::fromUtf8(
            backendEntry.riskReasonText.c_str(),
            static_cast<qsizetype>(backendEntry.riskReasonText.size())).trimmed();
        if (fallbackText.isEmpty())
        {
            fallbackText = startupText(
                "startup.risk_reason.unspecified",
                QStringLiteral("后端未提供风险说明"));
        }

        if (backendEntry.riskReasonCode.empty())
        {
            return fallbackText;
        }

        const std::string translationKey = "startup.risk_reason." + backendEntry.riskReasonCode;
        return startupText(translationKey.c_str(), fallbackText);
    }

    QString startupLocalizedDetailText(const QString& detailText)
    {
        const QString taskStatePrefix = QStringLiteral("状态=");
        const QString taskTriggerSeparator = QStringLiteral("；触发器=");
        const QString taskDescriptionSeparator = QStringLiteral("；描述=");
        const qsizetype triggerIndex = detailText.indexOf(taskTriggerSeparator);
        const qsizetype descriptionIndex = detailText.indexOf(
            taskDescriptionSeparator,
            triggerIndex < 0 ? 0 : triggerIndex + taskTriggerSeparator.size());
        if (detailText.startsWith(taskStatePrefix)
            && triggerIndex >= taskStatePrefix.size()
            && descriptionIndex > triggerIndex)
        {
            const QString stateText = detailText.sliced(
                taskStatePrefix.size(),
                triggerIndex - taskStatePrefix.size());
            const qsizetype triggerValueStart = triggerIndex + taskTriggerSeparator.size();
            const QString triggerText = detailText.sliced(
                triggerValueStart,
                descriptionIndex - triggerValueStart);
            const QString descriptionText = detailText.sliced(
                descriptionIndex + taskDescriptionSeparator.size());
            return startupText(
                "startup.detail.scheduled_task",
                QStringLiteral("状态：%1；触发器：%2；描述：%3"))
                .arg(stateText)
                .arg(triggerText)
                .arg(descriptionText);
        }

        const QString backupPrefix = QStringLiteral("KSword 备份=");
        if (detailText.startsWith(backupPrefix))
        {
            return startupText(
                "startup.detail.backup_record",
                QStringLiteral("KSword 备份记录：%1"))
                .arg(detailText.sliced(backupPrefix.size()));
        }

        const QString parkingPrefix = QStringLiteral("KSword 暂存=");
        if (detailText.startsWith(parkingPrefix))
        {
            return startupText(
                "startup.detail.parking_path",
                QStringLiteral("KSword 暂存路径：%1"))
                .arg(detailText.sliced(parkingPrefix.size()));
        }
        return ks::i18n::sourceText(detailText);
    }

    QStringList parseCsvLine(const QString& csvLineText)
    {
        QStringList fieldList;
        QString currentFieldText;
        bool inQuotes = false;

        for (int index = 0; index < csvLineText.size(); ++index)
        {
            const QChar currentChar = csvLineText.at(index);
            if (currentChar == QChar('"'))
            {
                if (inQuotes && index + 1 < csvLineText.size() && csvLineText.at(index + 1) == QChar('"'))
                {
                    currentFieldText.push_back(QChar('"'));
                    ++index;
                }
                else
                {
                    inQuotes = !inQuotes;
                }
                continue;
            }

            if (!inQuotes && currentChar == QChar(','))
            {
                fieldList.push_back(currentFieldText);
                currentFieldText.clear();
                continue;
            }

            currentFieldText.push_back(currentChar);
        }

        fieldList.push_back(currentFieldText);
        return fieldList;
    }

    namespace
    {
        // fromBackendText 作用：
        // - 把 ks::startup 使用的 UTF-8 std::string 转回 Qt UI 字符串；
        // - 输入 textValue：后端文本字段；
        // - 输出 QString：供表格/树/菜单展示使用。
        QString fromBackendText(const std::string& textValue)
        {
            return QString::fromUtf8(textValue.c_str(), static_cast<int>(textValue.size()));
        }

        // fromBackendCategory 作用：
        // - 把 ks::startup::StartupCategory 映射为 StartupDock::StartupCategory；
        // - 输入 category：后端枚举分类；
        // - 输出 UI 层分类枚举，未知值回退到 All。
        StartupDock::StartupCategory fromBackendCategory(const ks::startup::StartupCategory category)
        {
            switch (category)
            {
            case ks::startup::StartupCategory::All:
                return StartupDock::StartupCategory::All;
            case ks::startup::StartupCategory::Logon:
                return StartupDock::StartupCategory::Logon;
            case ks::startup::StartupCategory::Services:
                return StartupDock::StartupCategory::Services;
            case ks::startup::StartupCategory::Drivers:
                return StartupDock::StartupCategory::Drivers;
            case ks::startup::StartupCategory::Tasks:
                return StartupDock::StartupCategory::Tasks;
            case ks::startup::StartupCategory::ImageHijack:
                return StartupDock::StartupCategory::ImageHijack;
            case ks::startup::StartupCategory::Registry:
                return StartupDock::StartupCategory::Registry;
            case ks::startup::StartupCategory::Wmi:
                return StartupDock::StartupCategory::Wmi;
            case ks::startup::StartupCategory::Hidden:
                return StartupDock::StartupCategory::Hidden;
            default:
                return StartupDock::StartupCategory::All;
            }
        }
    }

    void appendBackendStartupEntries(
        std::vector<StartupDock::StartupEntry>* entryListOut,
        const std::vector<ks::startup::StartupEntry>& backendEntryList)
    {
        if (entryListOut == nullptr)
        {
            return;
        }

        entryListOut->reserve(entryListOut->size() + backendEntryList.size());
        for (const ks::startup::StartupEntry& backendEntry : backendEntryList)
        {
            // 转换原则：
            // - 后端只负责枚举与文本/布尔字段；
            // - QIcon 留空，后续仍由 StartupDock::resolveEntryIcon 在 UI 线程解析。
            StartupDock::StartupEntry entry;
            entry.backendEntry = backendEntry;
            entry.uniqueIdText = fromBackendText(backendEntry.uniqueIdText);
            entry.category = fromBackendCategory(backendEntry.category);
            entry.categoryText = fromBackendText(backendEntry.categoryText);
            entry.itemNameText = fromBackendText(backendEntry.itemNameText);
            entry.publisherText = fromBackendText(backendEntry.publisherText);
            entry.imagePathText = QDir::toNativeSeparators(fromBackendText(backendEntry.imagePathText));
            entry.commandText = fromBackendText(backendEntry.commandText);
            entry.locationText = QDir::toNativeSeparators(fromBackendText(backendEntry.locationText));
            entry.locationGroupText = QDir::toNativeSeparators(fromBackendText(backendEntry.locationGroupText));
            entry.registryValueNameText = fromBackendText(backendEntry.registryValueNameText);
            entry.userText = fromBackendText(backendEntry.userText);
            entry.detailText = fromBackendText(backendEntry.detailText);
            entry.sourceTypeText = fromBackendText(backendEntry.sourceTypeText);
            entry.enabled = backendEntry.enabled;
            entry.canOpenFileLocation = backendEntry.canOpenFileLocation;
            entry.canOpenRegistryLocation = backendEntry.canOpenRegistryLocation;
            entry.canDelete = backendEntry.canDelete;
            entry.deleteRegistryTree = backendEntry.deleteRegistryTree;
            entryListOut->push_back(std::move(entry));
        }
    }
}
