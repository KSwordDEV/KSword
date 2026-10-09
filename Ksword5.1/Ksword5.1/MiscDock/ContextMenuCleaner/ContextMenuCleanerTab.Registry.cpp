#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateEntriesForArea(const MenuArea area) const
{
    // 关联/命名空间分区：
    // - 这三类需要枚举注册表值或执行第三方判定，使用独立实现文件；
    // - 格式右键菜单仍复用下方 shell/shellex 统一解析链路。
    if (area == MenuArea::UrlBinding)
    {
        return enumerateUrlBindingEntries();
    }
    if (area == MenuArea::OpenWith)
    {
        return enumerateOpenWithEntries();
    }
    if (area == MenuArea::ExplorerHome)
    {
        return enumerateExplorerHomeEntries();
    }

    std::vector<RegistryLocationDefinition> locations;
    if (area == MenuArea::InternetExplorer)
    {
        addIeMenuExtLocations(&locations);
    }
    else if (area == MenuArea::Desktop)
    {
        addUserAndMachineClassLocations(&locations, QStringLiteral("DesktopBackground\\Shell"), QStringLiteral("桌面背景"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("DesktopBackground\\shellex\\ContextMenuHandlers"), QStringLiteral("桌面背景处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\Background\\shell"), QStringLiteral("目录背景"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\Background\\shellex\\ContextMenuHandlers"), QStringLiteral("目录背景处理器"), QStringLiteral("shellex"), false, true);
    }
    else if (area == MenuArea::File)
    {
        addUserAndMachineClassLocations(&locations, QStringLiteral("*\\shell"), QStringLiteral("所有文件"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("*\\shellex\\ContextMenuHandlers"), QStringLiteral("所有文件处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("AllFilesystemObjects\\shell"), QStringLiteral("文件系统对象"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("AllFilesystemObjects\\shellex\\ContextMenuHandlers"), QStringLiteral("文件系统对象处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\shell"), QStringLiteral("目录"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\shellex\\ContextMenuHandlers"), QStringLiteral("目录处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Folder\\shell"), QStringLiteral("文件夹"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Folder\\shellex\\ContextMenuHandlers"), QStringLiteral("文件夹处理器"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Drive\\shell"), QStringLiteral("磁盘驱动器"), QStringLiteral("shell"), true, false);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Drive\\shellex\\ContextMenuHandlers"), QStringLiteral("磁盘驱动器处理器"), QStringLiteral("shellex"), false, true);
    }
    else if (area == MenuArea::FormatMenu)
    {
        addFormatContextMenuLocations(&locations);
    }

    QVector<ContextMenuEntry> entries;
    for (const RegistryLocationDefinition& location : locations)
    {
        const QStringList subKeys = enumerateRegistrySubKeys(location.rootKey, location.subKeyPath, location.viewFlag);
        for (const QString& subKeyName : subKeys)
        {
            const QString fullSubKey = QStringLiteral("%1\\%2").arg(location.subKeyPath, subKeyName);
            ContextMenuEntry entry;
            entry.area = area;
            entry.rootKey = location.rootKey;
            entry.rootLabel = location.rootLabel;
            entry.subKeyPath = fullSubKey;
            entry.viewFlag = location.viewFlag;
            entry.sourceGroup = location.sourceGroup;
            entry.entryKind = location.entryKind;
            entry.itemName = subKeyName;
            entry.canDelete = true;

            ks::ui::FieldDocument detailList;
            if (location.ieMenuExt)
            {
                const QString defaultCommand = queryRegistryValueText(location.rootKey, fullSubKey, QString(), location.viewFlag).value_or(QString());
                const QString contexts = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("Contexts"), location.viewFlag).value_or(QString());
                const QString flags = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("Flags"), location.viewFlag).value_or(QString());
                entry.displayName = subKeyName;
                entry.commandOrHandler = defaultCommand;
                entry.statusText = defaultCommand.trimmed().isEmpty() ? QStringLiteral("命令为空") : QStringLiteral("正常");
                appendOptionalDetail(&detailList, QStringLiteral("Contexts"), contexts);
                appendOptionalDetail(&detailList, QStringLiteral("Flags"), flags);
            }
            else if (location.shellVerb)
            {
                const QString defaultName = queryRegistryValueText(location.rootKey, fullSubKey, QString(), location.viewFlag).value_or(QString());
                const QString muiVerb = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("MUIVerb"), location.viewFlag).value_or(QString());
                const QString icon = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("Icon"), location.viewFlag).value_or(QString());
                const QString appliesTo = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("AppliesTo"), location.viewFlag).value_or(QString());
                const QString command = queryRegistryValueText(location.rootKey, fullSubKey + QStringLiteral("\\command"), QString(), location.viewFlag).value_or(QString());
                const QString delegateExecute = queryRegistryValueText(location.rootKey, fullSubKey + QStringLiteral("\\command"), QStringLiteral("DelegateExecute"), location.viewFlag).value_or(QString());
                const QString explorerCommandHandler = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("ExplorerCommandHandler"), location.viewFlag).value_or(QString());
                const QString subCommands = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("SubCommands"), location.viewFlag).value_or(QString());
                const QString extendedSubCommandsKey = queryRegistryValueText(location.rootKey, fullSubKey, QStringLiteral("ExtendedSubCommandsKey"), location.viewFlag).value_or(QString());
                const bool legacyDisabled = registryValueExists(location.rootKey, fullSubKey, QStringLiteral("LegacyDisable"), location.viewFlag);
                const bool programmaticOnly = registryValueExists(location.rootKey, fullSubKey, QStringLiteral("ProgrammaticAccessOnly"), location.viewFlag);
                const bool extendedOnly = registryValueExists(location.rootKey, fullSubKey, QStringLiteral("Extended"), location.viewFlag);

                entry.displayName = firstNonEmpty({ muiVerb, defaultName, subKeyName });
                entry.commandOrHandler = firstNonEmpty({ command, delegateExecute, explorerCommandHandler, subCommands, extendedSubCommandsKey });
                if (legacyDisabled)
                {
                    entry.statusText = QStringLiteral("已禁用(LegacyDisable)");
                }
                else if (programmaticOnly)
                {
                    entry.statusText = QStringLiteral("仅程序访问");
                }
                else if (extendedOnly)
                {
                    entry.statusText = QStringLiteral("Shift 扩展菜单");
                }
                else if (entry.commandOrHandler.trimmed().isEmpty())
                {
                    entry.statusText = QStringLiteral("命令为空");
                }
                else
                {
                    entry.statusText = QStringLiteral("正常");
                }
                appendOptionalDetail(&detailList, QStringLiteral("Icon"), icon);
                appendOptionalDetail(&detailList, QStringLiteral("AppliesTo"), appliesTo);
                appendOptionalDetail(&detailList, QStringLiteral("DelegateExecute"), delegateExecute);
                appendOptionalDetail(&detailList, QStringLiteral("ExplorerCommandHandler"), explorerCommandHandler);
                appendOptionalDetail(&detailList, QStringLiteral("SubCommands"), subCommands);
                appendOptionalDetail(&detailList, QStringLiteral("ExtendedSubCommandsKey"), extendedSubCommandsKey);
            }
            else if (location.shellExtension)
            {
                const QString clsid = queryRegistryValueText(location.rootKey, fullSubKey, QString(), location.viewFlag).value_or(QString());
                const QString friendlyName = queryClsidFriendlyName(clsid);
                const QString serverPath = queryClsidServerPath(clsid);
                entry.clsidText = clsid;
                entry.displayName = firstNonEmpty({ friendlyName, subKeyName });
                entry.commandOrHandler = firstNonEmpty({ clsid, serverPath });
                entry.statusText = looksLikeClsid(clsid) ? QStringLiteral("正常") : QStringLiteral("CLSID 为空/异常");
                appendOptionalDetail(&detailList, QStringLiteral("CLSID"), clsid);
                appendOptionalDetail(&detailList, QStringLiteral("Server"), serverPath);
            }

            entry.details = detailList;
            entries.push_back(entry);
        }
    }

    return entries;
}

} // namespace ks::misc
