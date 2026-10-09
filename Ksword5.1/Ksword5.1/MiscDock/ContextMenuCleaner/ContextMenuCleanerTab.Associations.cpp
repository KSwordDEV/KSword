#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <QHash>
#include <QSet>
#include <QStringList>

#include <array>
#include <cstddef>
#include <tuple>
#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    // ClassRootDefinition：
    // - 作用：把 HKCU/HKLM 两种位数的 Software\Classes 入口统一成可遍历数组；
    // - 调用：URL、打开方式和格式右键菜单枚举器共享；
    // - 输出：不持有句柄，只保存根键常量、显示名、路径与视图标志。
    struct ClassRootDefinition
    {
        HKEY rootKey = nullptr;    // rootKey：Win32 注册表根键。
        QString rootLabel;         // rootLabel：表格显示用根键名称。
        QString classesPath;       // classesPath：Software\Classes 实际位置。
        REGSAM viewFlag = 0;       // viewFlag：HKLM 32/64 位视图标志。
        bool userScope = false;    // userScope：是否属于当前用户覆盖层。
    };

    // classRoots：
    // - 输入：无；
    // - 处理：固定返回当前用户、64 位全局和 32 位全局 Classes 入口；
    // - 返回：按用户优先顺序排列的三项数组。
    std::array<ClassRootDefinition, 3> classRoots()
    {
        return {
            ClassRootDefinition{
                HKEY_CURRENT_USER,
                QStringLiteral("HKCU"),
                QStringLiteral("Software\\Classes"),
                0,
                true },
            ClassRootDefinition{
                HKEY_LOCAL_MACHINE,
                QStringLiteral("HKLM(64位)"),
                QStringLiteral("Software\\Classes"),
                KEY_WOW64_64KEY,
                false },
            ClassRootDefinition{
                HKEY_LOCAL_MACHINE,
                QStringLiteral("HKLM(32位)"),
                QStringLiteral("Software\\Classes"),
                KEY_WOW64_32KEY,
                false }
        };
    }

    // joinedClassPath：
    // - 输入 root/classRelativePath：Classes 根定义和相对 ProgID/扩展名路径；
    // - 处理：统一拼接，避免各枚举器散落 Software\Classes 字符串；
    // - 返回：可直接传给 Win32 注册表 helper 的完整子键路径。
    QString joinedClassPath(
        const ClassRootDefinition& root,
        const QString& classRelativePath)
    {
        return QStringLiteral("%1\\%2").arg(root.classesPath, classRelativePath);
    }

    // ClassKeyBranchPresence：
    // - 作用：记录一个 Classes 关联键下 shell / shellex / OpenWithProgids 分支是否存在；
    // - 调用：格式右键菜单枚举用它把「每个关联键多次 RegOpenKeyEx 探测」收敛成一次子键枚举；
    // - 输出：纯布尔快照，不持有注册表句柄；关联键不存在时三个字段全为 false。
    struct ClassKeyBranchPresence
    {
        bool hasShellBranch = false;           // hasShellBranch：是否存在 shell 子键。
        bool hasShellExtensionBranch = false;  // hasShellExtensionBranch：是否存在 shellex 子键。
        bool hasOpenWithProgidsBranch = false; // hasOpenWithProgidsBranch：是否存在 OpenWithProgids 子键。
    };

    // queryMergedClassValue：
    // - 输入 relativePath/valueName/preferredView：Classes 相对位置和值名；
    // - 处理：按 HKCU、首选 HKLM 视图、另一 HKLM 视图依次解析合并关联；
    // - 返回：第一个非空值，适合解析 ProgID 友好名和打开命令。
    QString queryMergedClassValue(
        const QString& relativePath,
        const QString& valueName,
        const REGSAM preferredView)
    {
        const QString userPath = QStringLiteral("Software\\Classes\\%1").arg(relativePath);
        const QString userValue = queryRegistryValueText(
            HKEY_CURRENT_USER,
            userPath,
            valueName,
            0).value_or(QString());
        if (!userValue.trimmed().isEmpty())
        {
            return userValue.trimmed();
        }

        // 全局回退：
        // - 先使用条目自身视图，保证 32 位关联优先解析 32 位 ProgID；
        // - 再查另一视图，应对扩展名和应用注册分布在不同视图的安装器。
        const std::array<REGSAM, 2> machineViews = preferredView == KEY_WOW64_32KEY
            ? std::array<REGSAM, 2>{ KEY_WOW64_32KEY, KEY_WOW64_64KEY }
            : std::array<REGSAM, 2>{ KEY_WOW64_64KEY, KEY_WOW64_32KEY };
        for (const REGSAM viewFlag : machineViews)
        {
            const QString machineValue = queryRegistryValueText(
                HKEY_LOCAL_MACHINE,
                userPath,
                valueName,
                viewFlag).value_or(QString());
            if (!machineValue.trimmed().isEmpty())
            {
                return machineValue.trimmed();
            }
        }
        return QString();
    }

    // handlerRelativePath：
    // - 输入 handlerName/executableHandler：ProgID 或 exe 名及其类型；
    // - 处理：exe 映射到 Applications\<exe>，ProgID 保持原样；
    // - 返回：可继续拼接 shell\open\command 的 Classes 相对路径。
    QString handlerRelativePath(
        const QString& handlerName,
        const bool executableHandler)
    {
        if (executableHandler)
        {
            return QStringLiteral("Applications\\%1").arg(handlerName);
        }
        return handlerName;
    }

    // handlerDisplayName：
    // - 输入 handlerName/executableHandler/viewFlag：候选处理器身份；
    // - 处理：读取 FriendlyAppName 或 ProgID 默认描述，缺失时回退原始名称；
    // - 返回：打开方式表格使用的场景化显示名。
    QString handlerDisplayName(
        const QString& handlerName,
        const bool executableHandler,
        const REGSAM viewFlag)
    {
        const QString relativePath = handlerRelativePath(handlerName, executableHandler);
        const QString friendlyName = queryMergedClassValue(
            relativePath,
            QStringLiteral("FriendlyAppName"),
            viewFlag);
        const QString defaultName = queryMergedClassValue(
            relativePath,
            QString(),
            viewFlag);
        return firstNonEmpty({ friendlyName, defaultName, handlerName });
    }

    // handlerCommand：
    // - 输入 handlerName/executableHandler/viewFlag：候选处理器身份；
    // - 处理：沿处理器 Classes 注册读取 shell\open\command 默认值；
    // - 返回：用于识别程序落点的命令行，缺失时为空。
    QString handlerCommand(
        const QString& handlerName,
        const bool executableHandler,
        const REGSAM viewFlag)
    {
        const QString relativePath = handlerRelativePath(handlerName, executableHandler)
            + QStringLiteral("\\shell\\open\\command");
        return queryMergedClassValue(relativePath, QString(), viewFlag);
    }

}

bool ContextMenuCleanerTab::isProtectedUrlBindingEntry(const ContextMenuEntry& entry)
{
    if (entry.area != MenuArea::UrlBinding
        || entry.rootKey != HKEY_LOCAL_MACHINE
        || entry.deleteKind != DeleteKind::RegistryTree)
    {
        return false;
    }

    const QString classesPrefix = QStringLiteral("Software\\Classes\\");
    if (!entry.subKeyPath.startsWith(classesPrefix, Qt::CaseInsensitive))
    {
        return true;
    }
    const QString schemeName = entry.subKeyPath.mid(classesPrefix.size()).trimmed();
    if (schemeName.isEmpty() || schemeName.contains('\\'))
    {
        return true;
    }

    // 明确覆盖审计复现项；ms-* 是 Windows 保留 URI 命名空间。
    static const QSet<QString> protectedSchemes = {
        QStringLiteral("windowsdefender"),
        QStringLiteral("ms-device-enrollment"),
        QStringLiteral("ms-search"),
        QStringLiteral("ms-windows-search"),
        QStringLiteral("ms-actioncenter"),
        QStringLiteral("ms-print-addprinter"),
        QStringLiteral("explorer.zipselection")
    };
    if (protectedSchemes.contains(schemeName.toLower())
        || schemeName.startsWith(QStringLiteral("ms-"), Qt::CaseInsensitive))
    {
        return true;
    }

    const QString openPath = entry.subKeyPath + QStringLiteral("\\shell\\open");
    const QString commandPath = openPath + QStringLiteral("\\command");
    if (registryValueExists(
            entry.rootKey,
            entry.subKeyPath,
            QStringLiteral("EditFlags"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            commandPath,
            QStringLiteral("DelegateExecute"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            openPath,
            QStringLiteral("PackageId"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            openPath,
            QStringLiteral("ActivatableClassId"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            openPath,
            QStringLiteral("ContractId"),
            entry.viewFlag)
        || registryValueExists(
            entry.rootKey,
            entry.subKeyPath + QStringLiteral("\\Application"),
            QStringLiteral("AppUserModelId"),
            entry.viewFlag))
    {
        return true;
    }

    return false;
}

// enumerateUrlBindingEntries：
// - 枚举 Classes 中带 URL Protocol 值的协议注册；
// - 额外枚举当前用户 UrlAssociations\UserChoice，允许单独清除默认绑定；
// - 系统/Packaged COM/DelegateExecute 协议只读，第三方机器级协议保留高风险删除能力。
QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateUrlBindingEntries() const
{
    QVector<ContextMenuEntry> entries;
    for (const ClassRootDefinition& root : classRoots())
    {
        const QStringList classNames = enumerateRegistrySubKeys(
            root.rootKey,
            root.classesPath,
            root.viewFlag);
        for (const QString& schemeName : classNames)
        {
            if (schemeName.startsWith('.'))
            {
                continue;
            }

            const QString protocolPath = joinedClassPath(root, schemeName);
            if (!registryValueExists(
                    root.rootKey,
                    protocolPath,
                    QStringLiteral("URL Protocol"),
                    root.viewFlag))
            {
                continue;
            }

            // 单条协议注册：
            // - 默认值通常是 URL:<产品> Protocol；
            // - open command 是判断系统/第三方来源和排障失效绑定的核心证据。
            const QString displayName = queryRegistryValueText(
                root.rootKey,
                protocolPath,
                QString(),
                root.viewFlag).value_or(QString());
            const QString command = queryRegistryValueText(
                root.rootKey,
                protocolPath + QStringLiteral("\\shell\\open\\command"),
                QString(),
                root.viewFlag).value_or(QString());
            const QString icon = queryRegistryValueText(
                root.rootKey,
                protocolPath + QStringLiteral("\\DefaultIcon"),
                QString(),
                root.viewFlag).value_or(QString());
            ContextMenuEntry entry;
            entry.area = MenuArea::UrlBinding;
            entry.rootKey = root.rootKey;
            entry.rootLabel = root.rootLabel;
            entry.subKeyPath = protocolPath;
            entry.viewFlag = root.viewFlag;
            entry.sourceGroup = root.userScope
                ? QStringLiteral("当前用户协议注册")
                : QStringLiteral("全局协议注册");
            entry.entryKind = QStringLiteral("URL Protocol");
            entry.itemName = schemeName;
            entry.displayName = firstNonEmpty({ displayName, schemeName });
            entry.commandOrHandler = command;
            const bool protectedProtocol = isProtectedUrlBindingEntry(entry);
            entry.statusText = protectedProtocol
                ? QStringLiteral("系统/封装协议（保护）")
                : (!root.userScope
                    ? QStringLiteral("全局第三方协议（高风险，可删除）")
                    : command.trimmed().isEmpty()
                    ? QStringLiteral("打开命令为空")
                    : QStringLiteral("协议已注册"));
            ks::ui::FieldDocument details;
            appendOptionalDetail(&details, QStringLiteral("Icon"), icon);
            appendOptionalDetail(
                &details,
                QStringLiteral("范围"),
                root.userScope ? QStringLiteral("当前用户") : QStringLiteral("所有用户"));
            entry.details = details;
            entry.canDelete = !protectedProtocol;
            entries.push_back(entry);
        }
    }

    // 当前默认绑定：
    // - UserChoice 带系统生成 Hash，本页不尝试编辑 ProgId 或伪造 Hash；
    // - 删除整个 UserChoice 仅重置该用户的选择，后续由 Windows 重新询问或回退。
    const QString userChoiceBase =
        QStringLiteral("Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations");
    const QStringList associatedSchemes = enumerateRegistrySubKeys(
        HKEY_CURRENT_USER,
        userChoiceBase,
        0);
    for (const QString& schemeName : associatedSchemes)
    {
        const QString choicePath = QStringLiteral("%1\\%2\\UserChoice")
            .arg(userChoiceBase, schemeName);
        const QString progId = queryRegistryValueText(
            HKEY_CURRENT_USER,
            choicePath,
            QStringLiteral("ProgId"),
            0).value_or(QString());
        if (progId.trimmed().isEmpty())
        {
            continue;
        }

        ContextMenuEntry entry;
        entry.area = MenuArea::UrlBinding;
        entry.rootKey = HKEY_CURRENT_USER;
        entry.rootLabel = QStringLiteral("HKCU");
        entry.subKeyPath = choicePath;
        entry.sourceGroup = QStringLiteral("当前默认 URL 绑定");
        entry.entryKind = QStringLiteral("UserChoice");
        entry.itemName = schemeName;
        entry.displayName = handlerDisplayName(progId, false, KEY_WOW64_64KEY);
        entry.commandOrHandler = handlerCommand(progId, false, KEY_WOW64_64KEY);
        entry.statusText = QStringLiteral("当前用户默认");
        entry.details.note(QStringLiteral("ProgId=%1；Hash 由 Windows 维护").arg(progId));
        entry.canDelete = true;
        entries.push_back(entry);
    }
    return entries;
}

// enumerateOpenWithEntries：
// - 枚举 Explorer\FileExts 记录的用户历史候选；
// - 枚举 Classes 扩展名下 OpenWithProgids/OpenWithList 的已注册候选；
// - 每一行绑定到精确值或应用子键，删除不会触碰扩展名默认 ProgID/UserChoice。
QVector<ContextMenuCleanerTab::ContextMenuEntry> ContextMenuCleanerTab::enumerateOpenWithEntries() const
{
    QVector<ContextMenuEntry> entries;
    QSet<QString> seenTargets;

    // appendValueEntry：
    // - 输入注册表值位置、扩展名、处理器身份与来源；
    // - 处理：解析显示名/命令并生成“单值删除”快照；
    // - 输出：去重后追加到 entries，避免不同扫描链路重复显示同一目标。
    const auto appendValueEntry = [&entries, &seenTargets](
        HKEY rootKey,
        const QString& rootLabel,
        const QString& parentPath,
        const REGSAM viewFlag,
        const QString& extensionName,
        const QString& handlerName,
        const QString& valueName,
        const QString& sourceGroup,
        const QString& entryKind,
        const bool executableHandler,
        const bool cleanupMru) {
        if (handlerName.trimmed().isEmpty() || valueName.isEmpty())
        {
            return;
        }
        const QString targetIdentity = QStringLiteral("%1|%2|%3")
            .arg(rootLabel, parentPath, valueName)
            .toLower();
        if (seenTargets.contains(targetIdentity))
        {
            return;
        }
        seenTargets.insert(targetIdentity);

        ContextMenuEntry entry;
        entry.area = MenuArea::OpenWith;
        entry.rootKey = rootKey;
        entry.rootLabel = rootLabel;
        entry.subKeyPath = parentPath;
        entry.viewFlag = viewFlag;
        entry.sourceGroup = sourceGroup;
        entry.entryKind = entryKind;
        entry.itemName = extensionName;
        entry.displayName = handlerDisplayName(handlerName, executableHandler, viewFlag);
        entry.commandOrHandler = handlerCommand(handlerName, executableHandler, viewFlag);
        entry.statusText = entry.commandOrHandler.trimmed().isEmpty()
            ? QStringLiteral("处理器命令未解析")
            : QStringLiteral("候选处理器");
        entry.details.note(executableHandler
            ? QStringLiteral("应用=%1；值名=%2").arg(handlerName, valueName)
            : QStringLiteral("ProgID=%1；值名=%2").arg(handlerName, valueName));
        entry.deleteKind = DeleteKind::RegistryValue;
        entry.valueName = valueName;
        entry.cleanupOpenWithMru = cleanupMru;
        entry.canDelete = true;
        entries.push_back(entry);
    };

    // Explorer 用户历史：
    // - OpenWithList 的 a/b/c 值保存 exe，MRUList 只保存顺序且不单独展示；
    // - OpenWithProgids 的值名本身就是 ProgID，数据通常为空。
    const QString explorerFileExts =
        QStringLiteral("Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts");
    const QStringList userExtensions = enumerateRegistrySubKeys(
        HKEY_CURRENT_USER,
        explorerFileExts,
        0);
    for (const QString& extensionName : userExtensions)
    {
        if (!extensionName.startsWith('.'))
        {
            continue;
        }
        const QString extensionPath = QStringLiteral("%1\\%2")
            .arg(explorerFileExts, extensionName);
        const QString openWithListPath = extensionPath + QStringLiteral("\\OpenWithList");
        for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                 HKEY_CURRENT_USER,
                 openWithListPath,
                 0))
        {
            if (value.valueName.compare(
                    QStringLiteral("MRUList"),
                    Qt::CaseInsensitive) == 0)
            {
                continue;
            }
            appendValueEntry(
                HKEY_CURRENT_USER,
                QStringLiteral("HKCU"),
                openWithListPath,
                0,
                extensionName,
                value.valueText,
                value.valueName,
                QStringLiteral("用户打开历史"),
                QStringLiteral("OpenWithList"),
                true,
                true);
        }

        const QString openWithProgidsPath =
            extensionPath + QStringLiteral("\\OpenWithProgids");
        for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                 HKEY_CURRENT_USER,
                 openWithProgidsPath,
                 0))
        {
            appendValueEntry(
                HKEY_CURRENT_USER,
                QStringLiteral("HKCU"),
                openWithProgidsPath,
                0,
                extensionName,
                value.valueName,
                value.valueName,
                QStringLiteral("用户候选 ProgID"),
                QStringLiteral("OpenWithProgids"),
                false,
                false);
        }
    }

    // Classes 候选：
    // - OpenWithProgids 使用命名值；
    // - 旧式 OpenWithList 使用 exe 名子键，删除粒度因此是单个应用子树。
    for (const ClassRootDefinition& root : classRoots())
    {
        const QStringList classNames = enumerateRegistrySubKeys(
            root.rootKey,
            root.classesPath,
            root.viewFlag);
        for (const QString& extensionName : classNames)
        {
            if (!extensionName.startsWith('.'))
            {
                continue;
            }
            const QString extensionPath = joinedClassPath(root, extensionName);
            const QString progidsPath = extensionPath + QStringLiteral("\\OpenWithProgids");
            for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                     root.rootKey,
                     progidsPath,
                     root.viewFlag))
            {
                appendValueEntry(
                    root.rootKey,
                    root.rootLabel,
                    progidsPath,
                    root.viewFlag,
                    extensionName,
                    value.valueName,
                    value.valueName,
                    root.userScope
                        ? QStringLiteral("当前用户 Classes")
                        : QStringLiteral("全局 Classes"),
                    QStringLiteral("OpenWithProgids"),
                    false,
                    false);
            }

            const QString legacyListPath = extensionPath + QStringLiteral("\\OpenWithList");
            const QStringList applicationNames = enumerateRegistrySubKeys(
                root.rootKey,
                legacyListPath,
                root.viewFlag);
            for (const QString& applicationName : applicationNames)
            {
                const QString applicationPath = QStringLiteral("%1\\%2")
                    .arg(legacyListPath, applicationName);
                const QString targetIdentity = QStringLiteral("%1|%2")
                    .arg(root.rootLabel, applicationPath)
                    .toLower();
                if (seenTargets.contains(targetIdentity))
                {
                    continue;
                }
                seenTargets.insert(targetIdentity);

                ContextMenuEntry entry;
                entry.area = MenuArea::OpenWith;
                entry.rootKey = root.rootKey;
                entry.rootLabel = root.rootLabel;
                entry.subKeyPath = applicationPath;
                entry.viewFlag = root.viewFlag;
                entry.sourceGroup = root.userScope
                    ? QStringLiteral("当前用户 Classes")
                    : QStringLiteral("全局 Classes");
                entry.entryKind = QStringLiteral("OpenWithList 子键");
                entry.itemName = extensionName;
                entry.displayName = handlerDisplayName(
                    applicationName,
                    true,
                    root.viewFlag);
                entry.commandOrHandler = handlerCommand(
                    applicationName,
                    true,
                    root.viewFlag);
                entry.statusText = QStringLiteral("旧式候选应用");
                entry.details.note(QStringLiteral("应用=%1").arg(applicationName));
                entry.canDelete = true;
                entries.push_back(entry);
            }
        }
    }
    return entries;
}

} // namespace ks::misc

namespace ks::misc::context_menu_cleaner_detail
{
    // addFormatContextMenuLocations：
    // - 输入 outputList：调用方持有的扫描位置数组，本函数只追加不清空，空指针直接返回；
    // - 处理：收集扩展名直接 shell/shellex、默认/候选 ProgID shell/shellex，
    //   以及 SystemFileAssociations\.ext 与 PerceivedType 的 shell/shellex 父键；
    // - 返回：无返回值，结果全部写入 outputList。
    //
    // 注册表往返收敛（这里是本页最重的一处扫描，必须把 O(扩展名 × 根) 次 RegOpenKeyEx 压下去）：
    // 1) 三个 Classes 根的一级子键、以及各根 SystemFileAssociations 的一级子键各只枚举一次，
    //    「扩展名/ProgID/感知类型 在该根是否存在」改为内存哈希查表，不存在时零注册表往返；
    // 2) 每个关联键的 shell / shellex / OpenWithProgids 三个分支由一次子键枚举同时判定并缓存，
    //    没有 shell 也没有 shellex 的关联键（绝大多数扩展名）直接跳过后续两次枚举；
    // 3) 已探测过的菜单父键无论是否命中都记入 probedLocations，
    //    避免三轮 sourceRoot 对同一个不存在的位置重复探测三遍。
    void addFormatContextMenuLocations(
        std::vector<RegistryLocationDefinition>* outputList)
    {
        if (outputList == nullptr)
        {
            return;
        }

        const std::array<ClassRootDefinition, 3> roots = classRoots();

        // 根级一次性索引：
        // - classesChildNameLists：各根 Classes 一级子键原始名，主循环直接复用，不再重复枚举；
        // - classesChildNameSets/systemFileAssociationChildNameSets：同一批名字的小写集合，用于存在性查表；
        // - 集合为空表示该根索引不可用（枚举失败或确实无子键），后续退回逐键探测保持原有覆盖面。
        std::array<QStringList, 3> classesChildNameLists;
        std::array<QSet<QString>, 3> classesChildNameSets;
        std::array<QSet<QString>, 3> systemFileAssociationChildNameSets;
        for (std::size_t rootIndex = 0; rootIndex < roots.size(); ++rootIndex)
        {
            const ClassRootDefinition& indexedRoot = roots[rootIndex];
            classesChildNameLists[rootIndex] = enumerateRegistrySubKeys(
                indexedRoot.rootKey,
                indexedRoot.classesPath,
                indexedRoot.viewFlag);
            for (const QString& childName : classesChildNameLists[rootIndex])
            {
                classesChildNameSets[rootIndex].insert(childName.toLower());
            }
            if (!classesChildNameSets[rootIndex].contains(
                    QStringLiteral("systemfileassociations")))
            {
                continue;
            }
            const QStringList associationChildNames = enumerateRegistrySubKeys(
                indexedRoot.rootKey,
                joinedClassPath(
                    indexedRoot,
                    QStringLiteral("SystemFileAssociations")),
                indexedRoot.viewFlag);
            for (const QString& childName : associationChildNames)
            {
                systemFileAssociationChildNameSets[rootIndex].insert(childName.toLower());
            }
        }

        // associationKeyMayExist：
        // - 输入 rootIndex/associationPath：Classes 根下标与关联相对路径（扩展名、ProgID 或 SystemFileAssociations\X）；
        // - 处理：用根级索引判断该关联键是否可能存在，索引不可用时保守放行；
        // - 返回：false 表示可以确定该键不存在，调用方可以省掉全部注册表往返。
        const auto associationKeyMayExist =
            [&classesChildNameSets, &systemFileAssociationChildNameSets](
                const std::size_t rootIndex,
                const QString& associationPath) -> bool
        {
            if (classesChildNameSets[rootIndex].isEmpty())
            {
                return true;
            }
            const qsizetype separatorIndex = associationPath.indexOf('\\');
            const QString topLevelName = separatorIndex < 0
                ? associationPath
                : associationPath.left(separatorIndex);
            if (!classesChildNameSets[rootIndex].contains(topLevelName.toLower()))
            {
                return false;
            }
            if (separatorIndex < 0)
            {
                return true;
            }
            if (topLevelName.compare(
                    QStringLiteral("SystemFileAssociations"),
                    Qt::CaseInsensitive) != 0
                || systemFileAssociationChildNameSets[rootIndex].isEmpty())
            {
                return true;
            }
            const QString remainingPath = associationPath.mid(separatorIndex + 1);
            if (remainingPath.contains('\\'))
            {
                return true;
            }
            return systemFileAssociationChildNameSets[rootIndex].contains(
                remainingPath.toLower());
        };

        // branchPresenceCache：
        // - 键为「根显示名|关联相对路径」小写文本，值为该关联键的分支存在性快照；
        // - 同一个 ProgID 被多个扩展名引用、同一扩展名被三轮 sourceRoot 复扫时都直接命中缓存。
        QHash<QString, ClassKeyBranchPresence> branchPresenceCache;

        // branchPresenceOf：
        // - 输入 rootIndex/associationPath：Classes 根下标与关联相对路径；
        // - 处理：先做存在性查表，必要时用一次子键枚举同时判定 shell/shellex/OpenWithProgids，并写入缓存；
        // - 返回：该关联键的分支存在性快照，键不存在或不可枚举时三个字段全为 false。
        const auto branchPresenceOf =
            [&roots, &branchPresenceCache, &associationKeyMayExist](
                const std::size_t rootIndex,
                const QString& associationPath) -> ClassKeyBranchPresence
        {
            const ClassRootDefinition& root = roots[rootIndex];
            const QString cacheKey = QStringLiteral("%1|%2")
                .arg(root.rootLabel, associationPath)
                .toLower();
            const auto cachedIterator = branchPresenceCache.constFind(cacheKey);
            if (cachedIterator != branchPresenceCache.constEnd())
            {
                return cachedIterator.value();
            }

            ClassKeyBranchPresence presence;
            if (associationKeyMayExist(rootIndex, associationPath))
            {
                const QStringList childNames = enumerateRegistrySubKeys(
                    root.rootKey,
                    joinedClassPath(root, associationPath),
                    root.viewFlag);
                for (const QString& childName : childNames)
                {
                    if (childName.compare(
                            QStringLiteral("shell"),
                            Qt::CaseInsensitive) == 0)
                    {
                        presence.hasShellBranch = true;
                    }
                    else if (childName.compare(
                                 QStringLiteral("shellex"),
                                 Qt::CaseInsensitive) == 0)
                    {
                        presence.hasShellExtensionBranch = true;
                    }
                    else if (childName.compare(
                                 QStringLiteral("OpenWithProgids"),
                                 Qt::CaseInsensitive) == 0)
                    {
                        presence.hasOpenWithProgidsBranch = true;
                    }
                }
            }
            branchPresenceCache.insert(cacheKey, presence);
            return presence;
        };

        // probedLocations：
        // - 记录「已探测过」而不是「已命中」的菜单父键身份；
        // - 不存在的位置也会被记住，三轮 sourceRoot 不会对同一个空位置反复 RegOpenKeyEx。
        QSet<QString> probedLocations;

        // appendMenuLocations：
        // - 输入 rootIndex/associationPath/sourceGroup：Classes 根下标、相对关联键和来源描述；
        // - 处理：先按分支快照跳过没有 shell/shellex 的关联键，再只对真有子项的菜单父键追加扫描位置；
        // - 输出：无返回值，同一个根键/视图/路径只追加一次，控制大规模扩展名扫描结果。
        const auto appendMenuLocations =
            [outputList, &roots, &probedLocations, &branchPresenceOf](
                const std::size_t rootIndex,
                const QString& associationPath,
                const QString& sourceGroup)
        {
            const ClassRootDefinition& root = roots[rootIndex];
            const ClassKeyBranchPresence presence = branchPresenceOf(
                rootIndex,
                associationPath);
            if (!presence.hasShellBranch && !presence.hasShellExtensionBranch)
            {
                return;
            }

            const std::array<std::tuple<QString, QString, bool, bool, bool>, 2> menuKinds{
                std::make_tuple(
                    QStringLiteral("shell"),
                    QStringLiteral("shell"),
                    true,
                    false,
                    presence.hasShellBranch),
                std::make_tuple(
                    QStringLiteral("shellex\\ContextMenuHandlers"),
                    QStringLiteral("shellex"),
                    false,
                    true,
                    presence.hasShellExtensionBranch)
            };
            for (const auto& [pathSuffix, entryKind, shellVerb, shellExtension, branchPresent]
                 : menuKinds)
            {
                if (!branchPresent)
                {
                    continue;
                }
                const QString menuPath = QStringLiteral("%1\\%2\\%3")
                    .arg(root.classesPath, associationPath, pathSuffix);
                const QString identity = QStringLiteral("%1|%2|%3")
                    .arg(root.rootLabel, menuPath)
                    .arg(root.viewFlag)
                    .toLower();
                if (probedLocations.contains(identity))
                {
                    continue;
                }
                probedLocations.insert(identity);
                if (enumerateRegistrySubKeys(
                        root.rootKey,
                        menuPath,
                        root.viewFlag).isEmpty())
                {
                    continue;
                }
                outputList->push_back(RegistryLocationDefinition{
                    root.rootKey,
                    root.rootLabel,
                    menuPath,
                    root.viewFlag,
                    sourceGroup,
                    entryKind,
                    shellVerb,
                    shellExtension,
                    false });
            }
        };

        // 扩展名关联扫描：
        // - 每个来源根复用上面已经枚举好的扩展名列表，并读取其默认 ProgID/OpenWithProgids；
        // - ProgID 可能注册在另一视图或 HKLM，因此对三类 Classes 根分别探测（存在性先查表）。
        for (std::size_t sourceRootIndex = 0; sourceRootIndex < roots.size(); ++sourceRootIndex)
        {
            const ClassRootDefinition& sourceRoot = roots[sourceRootIndex];
            for (const QString& extensionName : classesChildNameLists[sourceRootIndex])
            {
                if (!extensionName.startsWith('.'))
                {
                    continue;
                }
                appendMenuLocations(
                    sourceRootIndex,
                    extensionName,
                    QStringLiteral("扩展名 %1").arg(extensionName));

                // SystemFileAssociations 的 .ext 分支不依赖默认 ProgID；
                // 在每个 Classes 根都探测，兼容用户覆盖和两种机器视图。
                for (std::size_t targetRootIndex = 0; targetRootIndex < roots.size(); ++targetRootIndex)
                {
                    appendMenuLocations(
                        targetRootIndex,
                        QStringLiteral("SystemFileAssociations\\%1").arg(extensionName),
                        QStringLiteral("格式关联 %1").arg(extensionName));
                }

                // extensionPresence 来自上面 appendMenuLocations 已经填好的缓存，这里是纯内存命中；
                // 没有 OpenWithProgids 子键时跳过一次值枚举。
                const ClassKeyBranchPresence extensionPresence = branchPresenceOf(
                    sourceRootIndex,
                    extensionName);
                const QString extensionPath = joinedClassPath(
                    sourceRoot,
                    extensionName);
                QStringList progIds;
                const QString defaultProgId = queryRegistryValueText(
                    sourceRoot.rootKey,
                    extensionPath,
                    QString(),
                    sourceRoot.viewFlag).value_or(QString());
                if (!defaultProgId.trimmed().isEmpty())
                {
                    progIds.push_back(defaultProgId.trimmed());
                }
                if (extensionPresence.hasOpenWithProgidsBranch)
                {
                    const QString progidsPath =
                        extensionPath + QStringLiteral("\\OpenWithProgids");
                    for (const RegistryValueSnapshot& value : enumerateRegistryValues(
                             sourceRoot.rootKey,
                             progidsPath,
                             sourceRoot.viewFlag))
                    {
                        if (!value.valueName.trimmed().isEmpty())
                        {
                            progIds.push_back(value.valueName.trimmed());
                        }
                    }
                }
                progIds.removeDuplicates();

                // ProgID 菜单：
                // - 对所有 Classes 根探测真实注册位置；
                // - sourceGroup 保留扩展名链路，便于用户理解“此菜单影响哪种格式”。
                for (const QString& progId : progIds)
                {
                    if (progId.contains('\\') || progId.contains('/'))
                    {
                        continue;
                    }
                    for (std::size_t targetRootIndex = 0; targetRootIndex < roots.size(); ++targetRootIndex)
                    {
                        appendMenuLocations(
                            targetRootIndex,
                            progId,
                            QStringLiteral("%1 → %2").arg(extensionName, progId));
                    }
                }

                const QString perceivedType = queryRegistryValueText(
                    sourceRoot.rootKey,
                    extensionPath,
                    QStringLiteral("PerceivedType"),
                    sourceRoot.viewFlag).value_or(QString());
                if (!perceivedType.trimmed().isEmpty()
                    && !perceivedType.contains('\\')
                    && !perceivedType.contains('/'))
                {
                    for (std::size_t targetRootIndex = 0; targetRootIndex < roots.size(); ++targetRootIndex)
                    {
                        appendMenuLocations(
                            targetRootIndex,
                            QStringLiteral("SystemFileAssociations\\%1")
                                .arg(perceivedType.trimmed()),
                            QStringLiteral("%1 感知类型 %2")
                                .arg(extensionName, perceivedType.trimmed()));
                    }
                }
            }
        }
    }
}
