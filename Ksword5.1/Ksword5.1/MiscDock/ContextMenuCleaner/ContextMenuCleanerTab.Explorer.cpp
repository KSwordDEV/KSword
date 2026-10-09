#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <QDir>
#include <QSet>
#include <QStringList>

#include <array>
#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    // NamespaceLocation：
    // - 作用：描述 Explorer Desktop/MyComputer/HomeFolder 下的一处 NameSpace 容器；
    // - 调用：enumerateExplorerHomeEntries 按位置枚举直接 CLSID 子键；
    // - 输出：保留真实根键/视图，确保删除和枚举命中同一注册表位置。
    struct NamespaceLocation
    {
        HKEY rootKey = nullptr;     // rootKey：Win32 根键。
        QString rootLabel;          // rootLabel：表格显示用根键文本。
        QString parentPath;         // parentPath：CLSID 子键所在容器路径。
        REGSAM viewFlag = 0;        // viewFlag：机器 32/64 位视图。
        QString sourceGroup;        // sourceGroup：主页/桌面/此电脑来源说明。
        bool userScope = false;     // userScope：当前用户位置更可能是第三方注册。
    };

    // knownSystemNamespaceIds：
    // - 输入：无；
    // - 处理：集中维护 Windows 常见 Home、Gallery、库、系统文件夹和设备命名空间；
    // - 返回：用于保护内置条目的小写 CLSID 集合，不把系统组件交给删除按钮。
    const QSet<QString>& knownSystemNamespaceIds()
    {
        static const QSet<QString> ids{
            QStringLiteral("{031e4825-7b94-4dc3-b131-e946b44c8dd5}"),
            QStringLiteral("{04731b67-d933-450a-90e6-4acd2e9408fe}"),
            QStringLiteral("{1cf1260c-4dd0-4ebb-811f-33c572699fde}"),
            QStringLiteral("{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"),
            QStringLiteral("{26ee0668-a00a-44d7-9371-beb064c98683}"),
            QStringLiteral("{374de290-123f-4565-9164-39c4925e467b}"),
            QStringLiteral("{3add1653-eb32-4cb0-bbd7-dfa0abb5acca}"),
            QStringLiteral("{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"),
            QStringLiteral("{4336a54d-038b-4685-ab02-99bb52d3fb8b}"),
            QStringLiteral("{450d8fba-ad25-11d0-98a8-0800361b1103}"),
            QStringLiteral("{5399e694-6ce5-4d6c-8fce-1d8870fdcba0}"),
            QStringLiteral("{59031a47-3f72-44a7-89c5-5595fe6b30ee}"),
            QStringLiteral("{645ff040-5081-101b-9f08-00aa002f954e}"),
            QStringLiteral("{a0953c92-50dc-43bf-be83-3742fed03c9c}"),
            QStringLiteral("{a8cdff1c-4878-43be-b5fd-f8091c1c60d0}"),
            QStringLiteral("{b2b4a4d1-2754-4140-a2eb-9a76d9d7cdc6}"),
            QStringLiteral("{b4bfcc3a-db2c-424c-b029-7fe99a87c641}"),
            QStringLiteral("{d3162b92-9365-467a-956b-92703aca08af}"),
            QStringLiteral("{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}"),
            QStringLiteral("{f02c1a0d-be21-4350-88b0-7367fc96ef3c}"),
            QStringLiteral("{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"),
            QStringLiteral("{f874310e-b6b7-47dc-bc84-b9e6b38f5903}")
        };
        return ids;
    }

    // looksLikeWindowsComponent：
    // - 输入 clsid/default/friendly/server/target：命名空间的多类身份线索；
    // - 处理：结合内置 CLSID、Windows 目录和 Microsoft 产品标记识别系统/第一方组件；
    // - 返回：true 表示本页隐藏并保护，false 允许进入第三方候选判断。
    bool looksLikeWindowsComponent(
        const QString& clsidText,
        const QString& defaultName,
        const QString& friendlyName,
        const QString& serverPath,
        const QString& targetPath)
    {
        if (knownSystemNamespaceIds().contains(clsidText.trimmed().toLower()))
        {
            return true;
        }

        // 文本证据：
        // - 内置项大量使用 CLSID_* 资源标识；
        // - OneDrive/Windows/Microsoft 归入系统或第一方，不作为“第三方程序”展示。
        const QString combinedText = QStringList{
            defaultName,
            friendlyName,
            serverPath,
            targetPath }.join('\n').toLower();
        if (combinedText.contains(QStringLiteral("clsid_"))
            || combinedText.contains(QStringLiteral("microsoft"))
            || combinedText.contains(QStringLiteral("windows"))
            || combinedText.contains(QStringLiteral("onedrive")))
        {
            return true;
        }
        const QString normalizedServer = QDir::fromNativeSeparators(serverPath).toLower();
        return normalizedServer.contains(QStringLiteral("/windows/"))
            || normalizedServer.contains(QStringLiteral("%systemroot%"))
            || normalizedServer.contains(QStringLiteral("%windir%"));
    }

    // shouldExposeThirdPartyNamespace：
    // - 输入 location 与命名空间线索；
    // - 处理：用户级非系统项直接纳入；机器级仅在有非 Windows Server/Target 证据时纳入；
    // - 返回：是否显示在“资源管理器主页第三方程序”页并允许删除。
    bool shouldExposeThirdPartyNamespace(
        const NamespaceLocation& location,
        const QString& clsidText,
        const QString& defaultName,
        const QString& friendlyName,
        const QString& serverPath,
        const QString& targetPath)
    {
        if (looksLikeWindowsComponent(
                clsidText,
                defaultName,
                friendlyName,
                serverPath,
                targetPath))
        {
            return false;
        }
        if (location.userScope)
        {
            return true;
        }
        return !serverPath.trimmed().isEmpty()
            || !targetPath.trimmed().isEmpty();
    }

    // appendBaseLocations：
    // - 输入 output/root/rootLabel/view/userScope：待追加数组与一个注册表范围；
    // - 处理：加入 Desktop、This PC、HomeFolder 及 DelegateFolders 常见容器；
    // - 输出：后续再按实际存在性枚举，缺失路径自然返回空列表。
    void appendBaseLocations(
        std::vector<NamespaceLocation>* output,
        HKEY rootKey,
        const QString& rootLabel,
        const REGSAM viewFlag,
        const bool userScope)
    {
        if (output == nullptr)
        {
            return;
        }
        const QString explorerBase =
            QStringLiteral("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer");
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            explorerBase + QStringLiteral("\\Desktop\\NameSpace"),
            viewFlag,
            QStringLiteral("Explorer 桌面/主页"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            explorerBase + QStringLiteral("\\Desktop\\NameSpace\\DelegateFolders"),
            viewFlag,
            QStringLiteral("Explorer 主页委托文件夹"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            explorerBase + QStringLiteral("\\MyComputer\\NameSpace"),
            viewFlag,
            QStringLiteral("此电脑命名空间"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            explorerBase + QStringLiteral("\\MyComputer\\NameSpace\\DelegateFolders"),
            viewFlag,
            QStringLiteral("此电脑委托文件夹"),
            userScope });
        output->push_back(NamespaceLocation{
            rootKey,
            rootLabel,
            explorerBase + QStringLiteral("\\HomeFolder\\NameSpace\\DelegateFolders"),
            viewFlag,
            QStringLiteral("Explorer HomeFolder"),
            userScope });

        // Windows 11 分支：
        // - 部分版本把主页/Gallery 等注册到 Desktop\NameSpace_<build tag>；
        // - 动态发现同名前缀，避免把具体系统构建号写死。
        const QString desktopPath = explorerBase + QStringLiteral("\\Desktop");
        const QStringList desktopSubKeys = enumerateRegistrySubKeys(
            rootKey,
            desktopPath,
            viewFlag);
        for (const QString& childName : desktopSubKeys)
        {
            if (!childName.startsWith(
                    QStringLiteral("NameSpace_"),
                    Qt::CaseInsensitive))
            {
                continue;
            }
            output->push_back(NamespaceLocation{
                rootKey,
                rootLabel,
                QStringLiteral("%1\\%2").arg(desktopPath, childName),
                viewFlag,
                QStringLiteral("Windows 11 主页命名空间"),
                userScope });
        }
    }
}

// enumerateExplorerHomeEntries：
// - 只展示第三方或当前用户注册的 Explorer 命名空间；
// - Windows 内置 CLSID、Windows 目录 Server 和 Microsoft/OneDrive 组件被保护并隐藏；
// - 删除目标是 NameSpace 容器中的单个 CLSID 子树，不删除应用自身 CLSID 类注册。
QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateExplorerHomeEntries() const
{
    std::vector<NamespaceLocation> locations;
    appendBaseLocations(
        &locations,
        HKEY_CURRENT_USER,
        QStringLiteral("HKCU"),
        0,
        true);
    appendBaseLocations(
        &locations,
        HKEY_LOCAL_MACHINE,
        QStringLiteral("HKLM(64位)"),
        KEY_WOW64_64KEY,
        false);
    appendBaseLocations(
        &locations,
        HKEY_LOCAL_MACHINE,
        QStringLiteral("HKLM(32位)"),
        KEY_WOW64_32KEY,
        false);

    QVector<ContextMenuEntry> entries;
    QSet<QString> seenTargets;
    for (const NamespaceLocation& location : locations)
    {
        const QStringList childKeys = enumerateRegistrySubKeys(
            location.rootKey,
            location.parentPath,
            location.viewFlag);
        for (const QString& clsidText : childKeys)
        {
            if (!looksLikeClsid(clsidText))
            {
                continue;
            }
            const QString fullSubKey = QStringLiteral("%1\\%2")
                .arg(location.parentPath, clsidText);
            const QString targetIdentity = QStringLiteral("%1|%2|%3")
                .arg(location.rootLabel, fullSubKey)
                .arg(location.viewFlag)
                .toLower();
            if (seenTargets.contains(targetIdentity))
            {
                continue;
            }

            // 名称和落点解析：
            // - NameSpace 子键默认值常保存产品 token；
            // - CLSID 类注册提供友好名、COM Server 或目标文件夹路径。
            const QString defaultName = queryRegistryValueText(
                location.rootKey,
                fullSubKey,
                QString(),
                location.viewFlag).value_or(QString());
            const QString friendlyName = queryClsidFriendlyName(clsidText);
            const QString serverPath = queryClsidServerPath(clsidText);
            const QString classPath = QStringLiteral("Software\\Classes\\CLSID\\%1")
                .arg(clsidText);
            QString targetPath = queryRegistryValueText(
                HKEY_CURRENT_USER,
                classPath + QStringLiteral("\\Instance\\InitPropertyBag"),
                QStringLiteral("TargetFolderPath"),
                0).value_or(QString());
            if (targetPath.trimmed().isEmpty())
            {
                targetPath = queryRegistryValueText(
                    HKEY_LOCAL_MACHINE,
                    classPath + QStringLiteral("\\Instance\\InitPropertyBag"),
                    QStringLiteral("TargetFolderPath"),
                    location.viewFlag).value_or(QString());
            }
            if (!shouldExposeThirdPartyNamespace(
                    location,
                    clsidText,
                    defaultName,
                    friendlyName,
                    serverPath,
                    targetPath))
            {
                continue;
            }
            seenTargets.insert(targetIdentity);

            ContextMenuEntry entry;
            entry.area = MenuArea::ExplorerHome;
            entry.rootKey = location.rootKey;
            entry.rootLabel = location.rootLabel;
            entry.subKeyPath = fullSubKey;
            entry.viewFlag = location.viewFlag;
            entry.sourceGroup = location.sourceGroup;
            entry.entryKind = QStringLiteral("Explorer NameSpace");
            entry.itemName = clsidText;
            entry.displayName = firstNonEmpty({
                friendlyName,
                defaultName,
                clsidText });
            entry.commandOrHandler = firstNonEmpty({
                targetPath,
                serverPath,
                defaultName });
            entry.clsidText = clsidText;
            entry.statusText = location.userScope
                ? QStringLiteral("当前用户第三方项")
                : QStringLiteral("全局第三方项");
            ks::ui::FieldDocument details;
            appendOptionalDetail(&details, QStringLiteral("注册名"), defaultName);
            appendOptionalDetail(&details, QStringLiteral("CLSID"), clsidText);
            appendOptionalDetail(&details, QStringLiteral("Server"), serverPath);
            appendOptionalDetail(&details, QStringLiteral("Target"), targetPath);
            entry.details = details;
            entry.canDelete = true;
            entries.push_back(entry);
        }
    }
    return entries;
}

} // namespace ks::misc
