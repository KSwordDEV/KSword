// ============================================================
// ContextMenuCleanerTab.BackupFile.cpp
// 作用：
// 1) 把本页纳管的全部右键菜单注册表位置（多根键 × 32/64 视图）递归导出成一个 JSON 文件，
//    默认落在 exe 同级目录的 ContextMenuBackups 下；
// 2) 支持从该文件恢复：恢复前先把"当前状态"也整份导出（带时间戳），
//    因为"恢复备份"本身就等于遗弃当前状态；
// 3) 目的：本程序若在测量期间异常退出、注册表里留下临时禁用覆盖项，用户可以一键回到干净状态。
//
// 与 ContextMenuCleanerTab.Backup.cpp 的区别：
// - 那个是"URL 绑定页删除前"的**注册表内**批次备份（RecBackup 键 + batchId）；
// - 本文件是**文件级**的整份快照，跨七个子页通用，也是崩溃兜底手段。
// ============================================================

#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMessageBox>
#include <QStandardPaths>
#include <QStringList>

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    // 备份文件格式标识与版本：解析时先校验，避免把别的 JSON 当备份吃进去。
    constexpr char kBackupSchema[] = "ksword-context-menu-backup";
    constexpr int kBackupFormatVersion = 1;

    // 递归深度上限：菜单注册表结构很浅，超过这个深度说明结构异常，宁可不收录也不冒险。
    constexpr int kMaxBackupDepth = 8;

    // 单次读取值数据的缓冲上限（字节）。菜单项的值都很小，64KB 足够。
    constexpr DWORD kValueBufferBytes = 64U * 1024U;

    // rootIdFromKey：把注册表根键转成可写入 JSON 的稳定标识。
    // 入参 rootKey：根键句柄；返回：标识字符串（未知根键返回空）。
    QString rootIdFromKey(const HKEY rootKey)
    {
        if (rootKey == HKEY_CURRENT_USER)
        {
            return QStringLiteral("HKCU");
        }
        if (rootKey == HKEY_LOCAL_MACHINE)
        {
            return QStringLiteral("HKLM");
        }
        if (rootKey == HKEY_CLASSES_ROOT)
        {
            return QStringLiteral("HKCR");
        }
        return QString();
    }

    // rootKeyFromId：标识字符串还原成根键句柄。
    // 入参 id：标识；返回：根键句柄（未知返回 nullptr）。
    HKEY rootKeyFromId(const QString& id)
    {
        if (id == QStringLiteral("HKCU"))
        {
            return HKEY_CURRENT_USER;
        }
        if (id == QStringLiteral("HKLM"))
        {
            return HKEY_LOCAL_MACHINE;
        }
        if (id == QStringLiteral("HKCR"))
        {
            return HKEY_CLASSES_ROOT;
        }
        return nullptr;
    }

    // viewIdFromFlag：把 WOW64 视图标记转成字符串，用于备份与恢复时保持同一视图。
    // 入参 viewFlag：REGSAM 视图标记；返回："64"、"32" 或 "default"。
    QString viewIdFromFlag(const REGSAM viewFlag)
    {
        if ((viewFlag & KEY_WOW64_64KEY) != 0U)
        {
            return QStringLiteral("64");
        }
        if ((viewFlag & KEY_WOW64_32KEY) != 0U)
        {
            return QStringLiteral("32");
        }
        return QStringLiteral("default");
    }

    // viewFlagFromId：字符串还原成 REGSAM 视图标记。
    // 入参 id：视图标识；返回：REGSAM 标记（未知返回 0）。
    REGSAM viewFlagFromId(const QString& id)
    {
        if (id == QStringLiteral("64"))
        {
            return KEY_WOW64_64KEY;
        }
        if (id == QStringLiteral("32"))
        {
            return KEY_WOW64_32KEY;
        }
        return 0;
    }

    // registryLocationsForBackup：本页需要纳管的全部菜单注册表位置。
    // 说明：复用 Internal.h 里既有的三类位置构造 helper，保证与"枚举"口径完全一致——
    // 备份范围必须 ≥ 枚举范围，否则恢复会漏项。
    // 入参：无；返回：位置定义数组。
    std::vector<RegistryLocationDefinition> registryLocationsForBackup()
    {
        std::vector<RegistryLocationDefinition> locations;

        // 文件与文件夹的 shell / shellex：覆盖 * / AllFilesystemObjects / Directory / Folder / Drive。
        addUserAndMachineClassLocations(&locations, QStringLiteral("*"),
            QStringLiteral("文件 *"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("AllFilesystemObjects"),
            QStringLiteral("全部文件系统对象"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory"),
            QStringLiteral("文件夹"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Directory\\Background"),
            QStringLiteral("文件夹背景"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Folder"),
            QStringLiteral("文件夹(Folder)"), QStringLiteral("shellex"), false, true);
        addUserAndMachineClassLocations(&locations, QStringLiteral("Drive"),
            QStringLiteral("驱动器"), QStringLiteral("shellex"), false, true);

        // IE 右键菜单（MenuExt）与资源管理器主页命名空间。
        addIeMenuExtLocations(&locations);

        // 格式右键菜单（扩展名 / ProgID / SystemFileAssociations）。
        addFormatContextMenuLocations(&locations);

        return locations;
    }

    // encodeValue：把一个注册表值转成 JSON。
    // 入参 type：REG_* 类型；data：原始数据指针；size：数据字节数。
    // 返回：JSON 值；遇到不支持的类型返回 QJsonValue::Undefined。
    QJsonValue encodeValue(const DWORD type, const BYTE* data, const DWORD size)
    {
        switch (type)
        {
        case REG_SZ:
        case REG_EXPAND_SZ:
            // 字符串型按 UTF-16 读取，去掉结尾的 NUL。
            return QJsonValue(QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data),
                static_cast<int>(size / sizeof(wchar_t))).remove(QChar(u'\0')));

        case REG_MULTI_SZ:
        {
            // 多字符串型拆成 JSON 数组，保留每一项的原文。
            QJsonArray items;
            const wchar_t* cursor = reinterpret_cast<const wchar_t*>(data);
            const wchar_t* end = cursor + size / sizeof(wchar_t);
            while (cursor < end && *cursor != L'\0')
            {
                const QString item = QString::fromWCharArray(cursor);
                items.append(item);
                cursor += item.size() + 1;
            }
            return items;
        }

        case REG_DWORD:
            return QJsonValue(size >= sizeof(DWORD)
                ? static_cast<int>(*reinterpret_cast<const DWORD*>(data))
                : 0);

        case REG_QWORD:
        {
            if (size < sizeof(ULONGLONG))
            {
                return QJsonValue(0);
            }
            // QJsonValue 只能存 double，QWORD 用量级有限的场景够用（这里都是小整数）。
            return QJsonValue(static_cast<double>(*reinterpret_cast<const ULONGLONG*>(data)));
        }

        case REG_BINARY:
            return QJsonValue(QString::fromLatin1(
                QByteArray(reinterpret_cast<const char*>(data), static_cast<int>(size)).toBase64()));

        default:
            return QJsonValue(QJsonValue::Undefined);
        }
    }

    // readKeyValues：读取一个键的全部值并序列化进 entries。
    // 入参 hKey：已打开的键；out：输出数组；errorTextOut：可空，失败原因。
    // 返回：成功 true，失败 false。
    bool readKeyValues(HKEY hKey, QJsonArray* out, QString* errorTextOut)
    {
        std::vector<BYTE> nameBuffer(32U * 1024U);
        std::vector<BYTE> dataBuffer(kValueBufferBytes);

        for (DWORD index = 0;; ++index)
        {
            DWORD nameLength = static_cast<DWORD>(nameBuffer.size());
            DWORD type = 0;
            DWORD dataLength = static_cast<DWORD>(dataBuffer.size());
            const LSTATUS status = ::RegEnumValueW(hKey, index,
                reinterpret_cast<wchar_t*>(nameBuffer.data()), &nameLength,
                nullptr, &type, dataBuffer.data(), &dataLength);
            if (status == ERROR_NO_MORE_ITEMS)
            {
                return true;
            }
            if (status != ERROR_SUCCESS)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("RegEnumValueW 失败，错误码=%1").arg(status);
                }
                return false;
            }

            const QString valueName = QString::fromWCharArray(
                reinterpret_cast<const wchar_t*>(nameBuffer.data()), static_cast<int>(nameLength));
            const QJsonValue encoded = encodeValue(type, dataBuffer.data(), dataLength);
            if (encoded.isUndefined())
            {
                // 不支持的类型（例如 REG_LINK）跳过，不阻断整份备份。
                continue;
            }

            QJsonObject valueObject;
            valueObject.insert(QStringLiteral("name"), valueName);
            valueObject.insert(QStringLiteral("type"), static_cast<int>(type));
            valueObject.insert(QStringLiteral("data"), encoded);
            out->append(valueObject);
        }
    }

    // collectKeyRecursively：递归收集一个键及其全部子键。
    // 入参 rootKey/subKeyPath/viewFlag/rootId：位置信息；entries：输出；depth：当前深度。
    // 返回：无（打不开的键直接跳过，不计入备份，恢复时会被当成"当前多出"的键删掉，
    //        因此这里必须只跳过"确实不存在"的情况）。
    void collectKeyRecursively(
        const HKEY rootKey,
        const QString& subKeyPath,
        const REGSAM viewFlag,
        const QString& rootId,
        QJsonArray* entries,
        const int depth)
    {
        if (depth > kMaxBackupDepth)
        {
            return;
        }

        HKEY key = nullptr;
        if (::RegOpenKeyExW(rootKey, subKeyPath.toStdWString().c_str(), 0,
                KEY_READ | viewFlag, &key) != ERROR_SUCCESS)
        {
            return;
        }

        // 先把本键的值收进来（即使没有值也要留下键记录，否则恢复时会漏建空键）。
        QJsonArray values;
        readKeyValues(key, &values, nullptr);
        QJsonObject entryObject;
        entryObject.insert(QStringLiteral("root"), rootId);
        entryObject.insert(QStringLiteral("view"), viewIdFromFlag(viewFlag));
        entryObject.insert(QStringLiteral("path"), subKeyPath);
        entryObject.insert(QStringLiteral("values"), values);
        entries->append(entryObject);

        // 再递归子键。
        std::vector<QString> children;
        std::vector<wchar_t> nameBuffer(16U * 1024U);
        for (DWORD index = 0;; ++index)
        {
            DWORD nameLength = static_cast<DWORD>(nameBuffer.size());
            const LSTATUS status = ::RegEnumKeyExW(key, index, nameBuffer.data(), &nameLength,
                nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (status != ERROR_SUCCESS)
            {
                break;
            }
            children.push_back(QString::fromWCharArray(nameBuffer.data(), static_cast<int>(nameLength)));
        }
        ::RegCloseKey(key);

        for (const QString& child : children)
        {
            collectKeyRecursively(rootKey, subKeyPath + QLatin1Char('\\') + child,
                viewFlag, rootId, entries, depth + 1);
        }
    }

    // deleteKeyTreeRecursively：删除一个键及其全部子键。
    // 入参 rootKey/subKeyPath/viewFlag：位置；errorTextOut：可空，失败原因。
    // 返回：成功 true。
    bool deleteKeyTreeRecursively(
        const HKEY rootKey,
        const QString& subKeyPath,
        const REGSAM viewFlag,
        QString* errorTextOut)
    {
        HKEY key = nullptr;
        if (::RegOpenKeyExW(rootKey, subKeyPath.toStdWString().c_str(), 0,
                KEY_READ | KEY_WRITE | viewFlag, &key) != ERROR_SUCCESS)
        {
            // 已经不存在，视为成功。
            return true;
        }

        std::vector<QString> children;
        std::vector<wchar_t> nameBuffer(16U * 1024U);
        for (DWORD index = 0;; ++index)
        {
            DWORD nameLength = static_cast<DWORD>(nameBuffer.size());
            const LSTATUS status = ::RegEnumKeyExW(key, index, nameBuffer.data(), &nameLength,
                nullptr, nullptr, nullptr, nullptr);
            if (status == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (status != ERROR_SUCCESS)
            {
                break;
            }
            children.push_back(QString::fromWCharArray(nameBuffer.data(), static_cast<int>(nameLength)));
        }
        ::RegCloseKey(key);

        // 先删子键再删自己，避免"键非空"错误。
        for (const QString& child : children)
        {
            deleteKeyTreeRecursively(rootKey, subKeyPath + QLatin1Char('\\') + child,
                viewFlag, errorTextOut);
        }

        const LSTATUS status = ::RegDeleteKeyExW(rootKey, subKeyPath.toStdWString().c_str(),
            viewFlag, 0);
        if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除 %1 失败，错误码=%2")
                    .arg(subKeyPath, QString::number(status));
            }
            return false;
        }
        return true;
    }

    // applyBackupValue：把一条备份里的值写回注册表。
    // 入参 key：目标键；name：值名；type：REG_*；data：JSON 数据；errorTextOut：可空。
    // 返回：成功 true。
    bool applyBackupValue(
        HKEY key,
        const QString& name,
        const DWORD type,
        const QJsonValue& data,
        QString* errorTextOut)
    {
        const std::wstring wideName = name.toStdWString();
        const wchar_t* namePointer = name.isEmpty() ? nullptr : wideName.c_str();
        LSTATUS status = ERROR_SUCCESS;

        switch (type)
        {
        case REG_SZ:
        case REG_EXPAND_SZ:
        {
            const std::wstring value = data.toString().toStdWString();
            status = ::RegSetValueExW(key, namePointer, 0, type,
                reinterpret_cast<const BYTE*>(value.c_str()),
                static_cast<DWORD>((value.size() + 1) * sizeof(wchar_t)));
            break;
        }
        case REG_MULTI_SZ:
        {
            // 多字符串以双 NUL 结尾。
            std::wstring joined;
            for (const QJsonValue& item : data.toArray())
            {
                joined += item.toString().toStdWString();
                joined.push_back(L'\0');
            }
            joined.push_back(L'\0');
            status = ::RegSetValueExW(key, namePointer, 0, type,
                reinterpret_cast<const BYTE*>(joined.c_str()),
                static_cast<DWORD>(joined.size() * sizeof(wchar_t)));
            break;
        }
        case REG_DWORD:
        {
            const DWORD value = static_cast<DWORD>(data.toInt());
            status = ::RegSetValueExW(key, namePointer, 0, type,
                reinterpret_cast<const BYTE*>(&value), sizeof(value));
            break;
        }
        case REG_QWORD:
        {
            const ULONGLONG value = static_cast<ULONGLONG>(data.toDouble());
            status = ::RegSetValueExW(key, namePointer, 0, type,
                reinterpret_cast<const BYTE*>(&value), sizeof(value));
            break;
        }
        case REG_BINARY:
        {
            const QByteArray bytes = QByteArray::fromBase64(data.toString().toLatin1());
            status = ::RegSetValueExW(key, namePointer, 0, type,
                reinterpret_cast<const BYTE*>(bytes.constData()),
                static_cast<DWORD>(bytes.size()));
            break;
        }
        default:
            return true; // 未知类型按"跳过"处理，不阻断恢复。
        }

        if (status != ERROR_SUCCESS && errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("写入值 %1 失败，错误码=%2")
                .arg(name.isEmpty() ? QStringLiteral("(默认)") : name, QString::number(status));
        }
        return status == ERROR_SUCCESS;
    }
}  // namespace

QString ContextMenuCleanerTab::contextMenuBackupDirectory() const
{
    // 首选 exe 同级目录（便携、用户一眼能找到）；不可写时回落到用户本地目录。
    const QString besideExe = QDir(QCoreApplication::applicationDirPath())
        .filePath(QStringLiteral("ContextMenuBackups"));
    QDir directory(besideExe);
    if (directory.mkpath(QStringLiteral(".")))
    {
        // 用一次真实写入探测权限：mkpath 成功不代表能写文件（只读盘上也可能建出目录）。
        QFile probe(directory.filePath(QStringLiteral(".write_probe")));
        if (probe.open(QIODevice::WriteOnly))
        {
            probe.close();
            probe.remove();
            return besideExe;
        }
    }

    const QString fallback = QDir(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation))
        .filePath(QStringLiteral("ContextMenuBackups"));
    QDir().mkpath(fallback);
    return fallback;
}

bool ContextMenuCleanerTab::exportContextMenuBackupToFile(QString* filePathOut, QString* errorTextOut) const
{
    const std::vector<RegistryLocationDefinition> locations = registryLocationsForBackup();

    QJsonArray entries;
    for (const RegistryLocationDefinition& location : locations)
    {
        const QString rootId = rootIdFromKey(location.rootKey);
        if (rootId.isEmpty() || location.subKeyPath.isEmpty())
        {
            continue;
        }
        collectKeyRecursively(location.rootKey, location.subKeyPath, location.viewFlag,
            rootId, &entries, 0);
    }

    if (entries.isEmpty())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("没有采集到任何菜单注册表项，已放弃写出备份文件");
        }
        return false;
    }

    QJsonObject document;
    document.insert(QStringLiteral("schema"), QString::fromLatin1(kBackupSchema));
    document.insert(QStringLiteral("formatVersion"), kBackupFormatVersion);
    document.insert(QStringLiteral("createdUtc"),
        QDateTime::currentDateTimeUtc().toString(Qt::ISODate));
    document.insert(QStringLiteral("entryCount"), entries.size());
    document.insert(QStringLiteral("entries"), entries);

    const QString directory = contextMenuBackupDirectory();
    const QString fileName = QStringLiteral("context-menu-%1.json")
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd-HHmmss")));
    const QString filePath = QDir(directory).filePath(fileName);

    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("无法写入备份文件：%1").arg(filePath);
        }
        return false;
    }
    file.write(QJsonDocument(document).toJson(QJsonDocument::Indented));
    file.close();

    if (filePathOut != nullptr)
    {
        *filePathOut = filePath;
    }
    return true;
}

QString ContextMenuCleanerTab::backupContextMenuToFile(const bool showSuccessMessage)
{
    QString filePath;
    QString errorText;
    if (!exportContextMenuBackupToFile(&filePath, &errorText))
    {
        kLogEvent event;
        err << event << "[ContextMenuCleanerTab] 备份右键菜单失败: "
            << errorText.toStdString() << eol;
        if (showSuccessMessage)
        {
            QMessageBox::warning(this, QStringLiteral("备份右键菜单"),
                QStringLiteral("备份失败：%1").arg(errorText));
        }
        return QString();
    }

    kLogEvent event;
    info << event << "[ContextMenuCleanerTab] 已备份右键菜单: "
         << filePath.toStdString() << eol;
    if (showSuccessMessage)
    {
        QMessageBox::information(this, QStringLiteral("备份右键菜单"),
            QStringLiteral("已导出整份右键菜单注册表：\n%1").arg(QDir::toNativeSeparators(filePath)));
    }
    return filePath;
}

void ContextMenuCleanerTab::restoreContextMenuFromFile()
{
    const QString directory = contextMenuBackupDirectory();
    const QString filePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择右键菜单备份文件"),
        directory,
        QStringLiteral("Ksword 菜单备份 (*.json)"));
    if (filePath.isEmpty())
    {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(this, QStringLiteral("恢复备份"),
            QStringLiteral("无法打开备份文件：%1").arg(QDir::toNativeSeparators(filePath)));
        return;
    }
    const QJsonDocument document = QJsonDocument::fromJson(file.readAll());
    file.close();

    const QJsonObject rootObject = document.object();
    if (rootObject.value(QStringLiteral("schema")).toString() != QString::fromLatin1(kBackupSchema))
    {
        QMessageBox::warning(this, QStringLiteral("恢复备份"),
            QStringLiteral("这个文件不是 Ksword 的右键菜单备份（schema 不匹配）。"));
        return;
    }
    const QJsonArray entries = rootObject.value(QStringLiteral("entries")).toArray();
    if (entries.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("恢复备份"),
            QStringLiteral("备份文件里没有任何条目，已中止。"));
        return;
    }

    // 恢复前先把当前状态整份导出：恢复本身等于遗弃当前状态，必须留退路。
    QString safetyPath;
    QString safetyError;
    if (!exportContextMenuBackupToFile(&safetyPath, &safetyError))
    {
        QMessageBox::warning(this, QStringLiteral("恢复备份"),
            QStringLiteral("恢复前的当前状态备份失败，为避免不可逆操作已中止：\n%1").arg(safetyError));
        return;
    }
    const QString beforeRestorePath = QStringLiteral("%1-before-restore.json").arg(safetyPath.left(safetyPath.size() - 5));

    const QMessageBox::StandardButton confirm = QMessageBox::question(
        this,
        QStringLiteral("恢复备份"),
        QStringLiteral("将用备份覆盖当前右键菜单注册表：\n%1\n\n恢复前的当前状态已自动另存为：\n%2\n\n注意：恢复等于遗弃当前状态，安装后新增的菜单项会被删除。继续吗？")
            .arg(QDir::toNativeSeparators(filePath), QDir::toNativeSeparators(beforeRestorePath)),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirm != QMessageBox::Yes)
    {
        QMessageBox::information(this, QStringLiteral("恢复备份"),
            QStringLiteral("已取消。当前状态备份保留在：\n%1")
                .arg(QDir::toNativeSeparators(beforeRestorePath)));
        return;
    }

    kLogEvent event;
    info << event << "[ContextMenuCleanerTab] 开始恢复右键菜单备份: "
         << filePath.toStdString() << ", 恢复前状态: " << beforeRestorePath.toStdString() << eol;

    // 收集备份里出现过的位置，用于判断"当前多出来的键"。
    QStringList restoredPaths;
    for (const QJsonValue& value : entries)
    {
        const QJsonObject entryObject = value.toObject();
        restoredPaths.push_back(entryObject.value(QStringLiteral("path")).toString());
    }

    int writtenKeys = 0;
    int writtenValues = 0;
    int deletedKeys = 0;
    QStringList failures;

    // 第一步：删除当前存在、但备份里没有的键（从深到浅），随后重建备份里的键。
    const std::vector<RegistryLocationDefinition> locations = registryLocationsForBackup();
    for (const RegistryLocationDefinition& location : locations)
    {
        if (location.subKeyPath.isEmpty())
        {
            continue;
        }
        // 只有"本位置下的键"归本位置管，避免把别的分类误删。
        const QString prefix = location.subKeyPath + QLatin1Char('\\');
        QStringList currentPaths;
        {
            HKEY key = nullptr;
            if (::RegOpenKeyExW(location.rootKey, location.subKeyPath.toStdWString().c_str(), 0,
                    KEY_READ | location.viewFlag, &key) == ERROR_SUCCESS)
            {
                std::vector<wchar_t> nameBuffer(16U * 1024U);
                for (DWORD index = 0;; ++index)
                {
                    DWORD nameLength = static_cast<DWORD>(nameBuffer.size());
                    if (::RegEnumKeyExW(key, index, nameBuffer.data(), &nameLength,
                            nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    {
                        break;
                    }
                    currentPaths.push_back(prefix + QString::fromWCharArray(
                        nameBuffer.data(), static_cast<int>(nameLength)));
                }
                ::RegCloseKey(key);
            }
        }

        for (const QString& currentPath : currentPaths)
        {
            bool keep = false;
            for (const QString& restoredPath : restoredPaths)
            {
                if (restoredPath == currentPath || restoredPath.startsWith(currentPath + QLatin1Char('\\')))
                {
                    keep = true;
                    break;
                }
            }
            if (!keep)
            {
                QString deleteError;
                if (deleteKeyTreeRecursively(location.rootKey, currentPath,
                        location.viewFlag, &deleteError))
                {
                    ++deletedKeys;
                }
                else
                {
                    failures.push_back(deleteError);
                }
            }
        }
    }

    // 第二步：按备份写回键与值。
    for (const QJsonValue& value : entries)
    {
        const QJsonObject entryObject = value.toObject();
        const HKEY rootKey = rootKeyFromId(entryObject.value(QStringLiteral("root")).toString());
        const QString path = entryObject.value(QStringLiteral("path")).toString();
        const REGSAM viewFlag = viewFlagFromId(entryObject.value(QStringLiteral("view")).toString());
        if (rootKey == nullptr || path.isEmpty())
        {
            continue;
        }

        HKEY key = nullptr;
        if (::RegCreateKeyExW(rootKey, path.toStdWString().c_str(), 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_WRITE | viewFlag, nullptr, &key, nullptr)
            != ERROR_SUCCESS)
        {
            failures.push_back(QStringLiteral("创建 %1 失败").arg(path));
            continue;
        }
        ++writtenKeys;

        for (const QJsonValue& valueEntry : entryObject.value(QStringLiteral("values")).toArray())
        {
            const QJsonObject valueObject = valueEntry.toObject();
            QString valueError;
            if (applyBackupValue(key,
                    valueObject.value(QStringLiteral("name")).toString(),
                    static_cast<DWORD>(valueObject.value(QStringLiteral("type")).toInt()),
                    valueObject.value(QStringLiteral("data")),
                    &valueError))
            {
                ++writtenValues;
            }
            else
            {
                failures.push_back(valueError);
            }
        }
        ::RegCloseKey(key);
    }

    // 第三步：刷新所有子页，让界面与注册表重新对齐。
    const std::array<MenuArea, 7> allAreas{
        MenuArea::InternetExplorer, MenuArea::Desktop, MenuArea::File, MenuArea::UrlBinding,
        MenuArea::OpenWith, MenuArea::FormatMenu, MenuArea::ExplorerHome };
    for (const MenuArea area : allAreas)
    {
        AreaWidgets* areaWidgets = widgetsForArea(area);
        if (areaWidgets != nullptr && areaWidgets->hasLoaded)
        {
            refreshArea(area);
        }
    }

    info << event << "[ContextMenuCleanerTab] 恢复完成: 写回键=" << writtenKeys
         << ", 写回值=" << writtenValues << ", 删除当前多出的键=" << deletedKeys
         << ", 失败=" << failures.size() << eol;

    QString summary = QStringLiteral("恢复完成。\n\n写回注册表键：%1\n写回注册表值：%2\n删除当前多出的键：%3\n恢复前状态备份：%4")
        .arg(writtenKeys).arg(writtenValues).arg(deletedKeys)
        .arg(QDir::toNativeSeparators(beforeRestorePath));
    if (!failures.isEmpty())
    {
        summary += QStringLiteral("\n\n失败项（前 5 条）：\n%1").arg(failures.mid(0, 5).join(QLatin1Char('\n')));
    }
    QMessageBox::information(this, QStringLiteral("恢复备份"), summary);
}

}  // namespace ks::misc
