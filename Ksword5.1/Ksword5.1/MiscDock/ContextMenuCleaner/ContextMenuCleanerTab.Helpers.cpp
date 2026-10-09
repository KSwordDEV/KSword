#include "ContextMenuCleanerTab.Internal.h"

#include "../../theme.h"

#include <QVector>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>

#pragma comment(lib, "Advapi32.lib")

namespace ks::misc::context_menu_cleaner_detail
{
    // buildInputStyle：
    // - 输入：无；
    // - 处理：复用项目主题色生成输入框样式；
    // - 返回：可直接 setStyleSheet 的样式文本。
    QString buildInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // buildHeaderStyle：
    // - 输入：无；
    // - 处理：生成表头浅/深色兼容样式；
    // - 返回：可应用到 QHeaderView 的样式文本。
    QString buildHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{"
            "  color:%1;"
            "  background:transparent; /* %2 */"
            "  border:1px solid %3;"
            "  font-weight:600;"
            "}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    // winErrorText：
    // - 输入 errorCode：Win32 错误码；
    // - 处理：调用 FormatMessageW 解析系统错误文本；
    // - 返回：中文/系统语言错误文本，解析失败时返回十六进制错误码。
    QString winErrorText(const DWORD errorCode)
    {
        wchar_t* messageBuffer = nullptr;
        const DWORD copiedChars = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);
        QString messageText;
        if (copiedChars > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer, static_cast<int>(copiedChars)).trimmed();
            ::LocalFree(messageBuffer);
        }
        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("Win32 error 0x%1")
                .arg(static_cast<qulonglong>(errorCode), 0, 16)
                .toUpper();
        }
        return messageText;
    }

    // valueNamePointer：
    // - 输入 valueName：Qt 字符串，null 表示默认值；
    // - 处理：把默认值映射为 nullptr，把命名值映射为 UTF-16 指针；
    // - 返回：可传给 RegQueryValueExW 的 value name 指针。
    const wchar_t* valueNamePointer(const QString& valueName)
    {
        return valueName.isNull() ? nullptr : reinterpret_cast<const wchar_t*>(valueName.utf16());
    }

    // trimTrailingNullWide：
    // - 输入 text：可能带尾部 NUL 的宽字符串；
    // - 处理：删除注册表字符串常见的一个或多个尾部 NUL；
    // - 返回：便于 UI 展示的干净字符串。
    QString trimTrailingNullWide(std::wstring text)
    {
        while (!text.empty() && text.back() == L'\0')
        {
            text.pop_back();
        }
        return QString::fromStdWString(text).trimmed();
    }

    // registryDataToText：
    // - 输入 valueType/rawData：RegQueryValueExW 返回的类型与原始字节；
    // - 处理：按常见注册表类型转为短文本；
    // - 返回：用于命令/详情列展示的字符串。
    QString registryDataToText(const DWORD valueType, const std::vector<std::uint8_t>& rawData)
    {
        if (rawData.empty())
        {
            return QString();
        }

        if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
        {
            const std::size_t wcharCount = rawData.size() / sizeof(wchar_t);
            if (wcharCount == 0)
            {
                return QString();
            }
            const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawData.data());
            QString text = trimTrailingNullWide(std::wstring(textBegin, textBegin + wcharCount));
            if (valueType == REG_EXPAND_SZ && !text.isEmpty())
            {
                std::vector<wchar_t> expandedBuffer(32768, L'\0');
                const DWORD copiedChars = ::ExpandEnvironmentStringsW(
                    reinterpret_cast<const wchar_t*>(text.utf16()),
                    expandedBuffer.data(),
                    static_cast<DWORD>(expandedBuffer.size()));
                if (copiedChars > 0 && copiedChars < expandedBuffer.size())
                {
                    text = QString::fromWCharArray(expandedBuffer.data()).trimmed();
                }
            }
            return text;
        }

        if (valueType == REG_MULTI_SZ)
        {
            QStringList items;
            const std::size_t wcharCount = rawData.size() / sizeof(wchar_t);
            const wchar_t* textBegin = reinterpret_cast<const wchar_t*>(rawData.data());
            std::size_t offset = 0;
            while (offset < wcharCount)
            {
                const std::size_t startOffset = offset;
                while (offset < wcharCount && textBegin[offset] != L'\0')
                {
                    ++offset;
                }
                if (offset == startOffset)
                {
                    break;
                }
                const QString item = QString::fromWCharArray(
                    textBegin + startOffset,
                    static_cast<int>(offset - startOffset)).trimmed();
                if (!item.isEmpty())
                {
                    items.push_back(item);
                }
                if (offset < wcharCount)
                {
                    ++offset;
                }
            }
            return items.join(QStringLiteral(" | "));
        }

        if (valueType == REG_DWORD && rawData.size() >= sizeof(DWORD))
        {
            const DWORD value = *reinterpret_cast<const DWORD*>(rawData.data());
            return QStringLiteral("%1 (0x%2)")
                .arg(static_cast<qulonglong>(value))
                .arg(static_cast<qulonglong>(value), 8, 16, QChar('0'))
                .toUpper();
        }

        if (valueType == REG_QWORD && rawData.size() >= sizeof(qulonglong))
        {
            const qulonglong value = *reinterpret_cast<const qulonglong*>(rawData.data());
            return QStringLiteral("%1 (0x%2)")
                .arg(value)
                .arg(value, 16, 16, QChar('0'))
                .toUpper();
        }

        QStringList bytes;
        const int displayCount = std::min<int>(static_cast<int>(rawData.size()), 16);
        for (int i = 0; i < displayCount; ++i)
        {
            bytes.push_back(QStringLiteral("%1").arg(rawData[static_cast<std::size_t>(i)], 2, 16, QChar('0')).toUpper());
        }
        if (rawData.size() > static_cast<std::size_t>(displayCount))
        {
            bytes.push_back(QStringLiteral("...(%1 bytes)").arg(static_cast<qulonglong>(rawData.size())));
        }
        return bytes.join(' ');
    }

    // queryRegistryValueText：
    // - 输入 root/subKey/valueName/viewFlag：目标注册表值位置；
    // - 处理：读取原始值并转换为显示文本；
    // - 返回：成功时返回文本，失败或值不存在时返回 std::nullopt。
    std::optional<QString> queryRegistryValueText(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        const REGSAM viewFlag)
    {
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return std::nullopt;
        }

        DWORD valueType = REG_NONE;
        DWORD bufferBytes = 0;
        const LONG sizeResult = ::RegQueryValueExW(
            openedKey,
            valueNamePointer(valueName),
            nullptr,
            &valueType,
            nullptr,
            &bufferBytes);
        if (sizeResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return std::nullopt;
        }

        std::vector<std::uint8_t> rawData(static_cast<std::size_t>(std::max<DWORD>(bufferBytes, sizeof(wchar_t))));
        const LONG dataResult = ::RegQueryValueExW(
            openedKey,
            valueNamePointer(valueName),
            nullptr,
            &valueType,
            rawData.data(),
            &bufferBytes);
        ::RegCloseKey(openedKey);
        if (dataResult != ERROR_SUCCESS)
        {
            return std::nullopt;
        }
        rawData.resize(static_cast<std::size_t>(bufferBytes));
        return registryDataToText(valueType, rawData);
    }

    // registryValueExists：
    // - 输入 root/subKey/valueName/viewFlag：目标注册表值位置；
    // - 处理：只查询值头部，不读取数据内容；
    // - 返回：值存在返回 true，否则 false。
    bool registryValueExists(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        const REGSAM viewFlag)
    {
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return false;
        }
        DWORD valueType = REG_NONE;
        const LONG queryResult = ::RegQueryValueExW(
            openedKey,
            valueNamePointer(valueName),
            nullptr,
            &valueType,
            nullptr,
            nullptr);
        ::RegCloseKey(openedKey);
        return queryResult == ERROR_SUCCESS || queryResult == ERROR_MORE_DATA;
    }

    // enumerateRegistrySubKeys：
    // - 输入 root/subKey/viewFlag：父键位置；
    // - 处理：枚举一级子键名，忽略中途权限错误的单项；
    // - 返回：子键名称列表，打开失败时返回空列表。
    QStringList enumerateRegistrySubKeys(HKEY rootKey, const QString& subKeyPath, const REGSAM viewFlag)
    {
        QStringList resultList;
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return resultList;
        }

        DWORD index = 0;
        while (true)
        {
            std::vector<wchar_t> nameBuffer(256, L'\0');
            DWORD nameChars = static_cast<DWORD>(nameBuffer.size());
            FILETIME writeTime{};
            LONG enumResult = ::RegEnumKeyExW(
                openedKey,
                index,
                nameBuffer.data(),
                &nameChars,
                nullptr,
                nullptr,
                nullptr,
                &writeTime);
            if (enumResult == ERROR_MORE_DATA)
            {
                nameBuffer.resize(nameBuffer.size() * 2, L'\0');
                nameChars = static_cast<DWORD>(nameBuffer.size());
                enumResult = ::RegEnumKeyExW(
                    openedKey,
                    index,
                    nameBuffer.data(),
                    &nameChars,
                    nullptr,
                    nullptr,
                    nullptr,
                    &writeTime);
            }
            if (enumResult == ERROR_NO_MORE_ITEMS)
            {
                break;
            }
            if (enumResult == ERROR_SUCCESS)
            {
                resultList.push_back(QString::fromWCharArray(nameBuffer.data(), static_cast<int>(nameChars)));
            }
            ++index;
        }

        ::RegCloseKey(openedKey);
        resultList.sort(Qt::CaseInsensitive);
        return resultList;
    }

    // enumerateRegistryValues：
    // - 输入 root/subKey/viewFlag：目标注册表键与 WOW64 视图；
    // - 处理：先查询最大名称/数据尺寸，再逐值读取并转换为可展示文本；
    // - 返回：按值名不区分大小写排序的快照，打开失败时返回空数组。
    QVector<RegistryValueSnapshot> enumerateRegistryValues(
        HKEY rootKey,
        const QString& subKeyPath,
        const REGSAM viewFlag)
    {
        QVector<RegistryValueSnapshot> resultList;
        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | viewFlag,
            &openedKey);
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            return resultList;
        }

        // 尺寸查询：
        // - maxValueNameChars 不包含结尾 NUL，因此分配时额外加一；
        // - maxValueDataBytes 允许为零，仍保留一个字节避免 data() 为空。
        DWORD valueCount = 0;
        DWORD maxValueNameChars = 0;
        DWORD maxValueDataBytes = 0;
        const LONG infoResult = ::RegQueryInfoKeyW(
            openedKey,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            &valueCount,
            &maxValueNameChars,
            &maxValueDataBytes,
            nullptr,
            nullptr);
        if (infoResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(openedKey);
            return resultList;
        }

        // 值枚举：
        // - 每轮重置缓冲区长度，因为 RegEnumValueW 会写回实际长度；
        // - REG_NONE 空数据仍保留值名，打开方式 ProgID 正是这种常见形式。
        std::vector<wchar_t> nameBuffer(
            static_cast<std::size_t>(maxValueNameChars) + 2,
            L'\0');
        std::vector<std::uint8_t> dataBuffer(
            static_cast<std::size_t>(std::max<DWORD>(maxValueDataBytes, 1)),
            0);
        for (DWORD valueIndex = 0; valueIndex < valueCount; ++valueIndex)
        {
            DWORD nameChars = static_cast<DWORD>(nameBuffer.size());
            DWORD dataBytes = static_cast<DWORD>(dataBuffer.size());
            DWORD valueType = REG_NONE;
            const LONG enumResult = ::RegEnumValueW(
                openedKey,
                valueIndex,
                nameBuffer.data(),
                &nameChars,
                nullptr,
                &valueType,
                dataBuffer.data(),
                &dataBytes);
            if (enumResult != ERROR_SUCCESS)
            {
                continue;
            }

            RegistryValueSnapshot snapshot;
            snapshot.valueName = QString::fromWCharArray(
                nameBuffer.data(),
                static_cast<int>(nameChars));
            snapshot.valueType = valueType;
            const std::vector<std::uint8_t> rawData(
                dataBuffer.begin(),
                dataBuffer.begin() + static_cast<std::ptrdiff_t>(dataBytes));
            snapshot.valueText = registryDataToText(valueType, rawData);
            resultList.push_back(snapshot);
        }

        ::RegCloseKey(openedKey);
        std::sort(
            resultList.begin(),
            resultList.end(),
            [](const RegistryValueSnapshot& left, const RegistryValueSnapshot& right) {
                return QString::compare(left.valueName, right.valueName, Qt::CaseInsensitive) < 0;
            });
        return resultList;
    }

    // rootPathText：
    // - 输入 rootLabel/subKeyPath：显示根键与子键；
    // - 处理：拼接成完整注册表路径；
    // - 返回：用于表格与剪贴板的路径文本。
    QString rootPathText(const QString& rootLabel, const QString& subKeyPath)
    {
        return QStringLiteral("%1\\%2").arg(rootLabel, subKeyPath);
    }

    // registryTargetPathText：
    // - 输入 rootLabel/subKeyPath/valueTarget/valueName：删除目标组成部分；
    // - 处理：子树沿用普通路径，注册表值追加清晰的“值”标记；
    // - 返回：不会被误解为整棵子树的精确 UI/剪贴板路径。
    QString registryTargetPathText(
        const QString& rootLabel,
        const QString& subKeyPath,
        const bool valueTarget,
        const QString& valueName)
    {
        const QString keyPath = rootPathText(rootLabel, subKeyPath);
        if (!valueTarget)
        {
            return keyPath;
        }
        const QString shownValueName = valueName.isEmpty()
            ? QStringLiteral("(默认)")
            : valueName;
        return QStringLiteral("%1 [值: %2]").arg(keyPath, shownValueName);
    }

    // firstNonEmpty：
    // - 输入 values：候选文本列表；
    // - 处理：按顺序返回第一段非空文本；
    // - 返回：非空候选或空字符串。
    QString firstNonEmpty(const std::initializer_list<QString>& values)
    {
        for (const QString& value : values)
        {
            if (!value.trimmed().isEmpty())
            {
                return value.trimmed();
            }
        }
        return QString();
    }

    // looksLikeClsid：
    // - 输入 text：注册表中读取的字符串；
    // - 处理：粗略识别 {GUID} 形式 CLSID；
    // - 返回：符合 CLSID 外形返回 true。
    bool looksLikeClsid(const QString& text)
    {
        const QString trimmedText = text.trimmed();
        return trimmedText.size() >= 38 && trimmedText.startsWith('{') && trimmedText.endsWith('}');
    }

    // queryClsidValue：
    // - 输入 clsid/subPath/valueName/viewFlag：CLSID 相对路径和值名；
    // - 处理：读取 HKCR\\CLSID 下的友好名或 Server 路径；
    // - 返回：存在时返回文本，否则返回空字符串。
    QString queryClsidValue(
        const QString& clsidText,
        const QString& subPath,
        const QString& valueName,
        const REGSAM viewFlag)
    {
        if (!looksLikeClsid(clsidText))
        {
            return QString();
        }
        QString path = QStringLiteral("CLSID\\%1").arg(clsidText.trimmed());
        if (!subPath.isEmpty())
        {
            path += QStringLiteral("\\%1").arg(subPath);
        }
        const std::optional<QString> value = queryRegistryValueText(
            HKEY_CLASSES_ROOT,
            path,
            valueName,
            viewFlag);
        return value.has_value() ? value->trimmed() : QString();
    }

    // queryClsidFriendlyName：
    // - 输入 clsid：COM 类标识符；
    // - 处理：优先查询 64 位 HKCR，失败后查询 32 位 HKCR；
    // - 返回：COM 友好名称，缺失时为空。
    QString queryClsidFriendlyName(const QString& clsidText)
    {
        QString friendlyName = queryClsidValue(clsidText, QString(), QString(), KEY_WOW64_64KEY);
        if (friendlyName.isEmpty())
        {
            friendlyName = queryClsidValue(clsidText, QString(), QString(), KEY_WOW64_32KEY);
        }
        return friendlyName;
    }

    // queryClsidServerPath：
    // - 输入 clsid：COM 类标识符；
    // - 处理：尝试读取 InprocServer32 与 LocalServer32；
    // - 返回：Server 路径或空字符串。
    QString queryClsidServerPath(const QString& clsidText)
    {
        for (const REGSAM viewFlag : { KEY_WOW64_64KEY, KEY_WOW64_32KEY })
        {
            QString serverPath = queryClsidValue(clsidText, QStringLiteral("InprocServer32"), QString(), viewFlag);
            if (!serverPath.isEmpty())
            {
                return serverPath;
            }
            serverPath = queryClsidValue(clsidText, QStringLiteral("LocalServer32"), QString(), viewFlag);
            if (!serverPath.isEmpty())
            {
                return serverPath;
            }
        }
        return QString();
    }

    // appendOptionalDetail：
    // - 输入 detailList/name/value：详情列表、字段名、字段值；
    // - 处理：仅当 value 非空时追加 name=value；
    // - 返回：无。
    void appendOptionalDetail(ks::ui::FieldDocument* detailList, const QString& name, const QString& value)
    {
        if (detailList == nullptr || value.trimmed().isEmpty())
        {
            return;
        }
        detailList->field(name, value.trimmed());
    }

    // deleteRegistryTreeWithView：
    // - 输入 root/subKeyPath/viewFlag：待删除注册表子树；
    // - 处理：先按指定 WOW64 视图打开父键，再 RegDeleteTreeW 删除子键；
    // - 返回：成功或目标已不存在返回 true，失败返回 false 并写 errorTextOut。
    bool deleteRegistryTreeWithView(
        HKEY rootKey,
        const QString& subKeyPath,
        const REGSAM viewFlag,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        const QString trimmedPath = subKeyPath.trimmed();
        if (trimmedPath.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("注册表子键路径为空。");
            }
            return false;
        }

        const int slashIndex = trimmedPath.lastIndexOf('\\');
        const QString parentPath = slashIndex > 0 ? trimmedPath.left(slashIndex) : QString();
        const QString childName = slashIndex > 0 ? trimmedPath.mid(slashIndex + 1) : trimmedPath;
        if (childName.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法删除根键或空子键。");
            }
            return false;
        }

        HKEY parentKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            parentPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(parentPath.utf16()),
            0,
            DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE | viewFlag,
            &parentKey);
        if (openResult == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        if (openResult != ERROR_SUCCESS || parentKey == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(openResult));
            }
            return false;
        }

        const LONG deleteResult = ::RegDeleteTreeW(
            parentKey,
            reinterpret_cast<const wchar_t*>(childName.utf16()));
        ::RegCloseKey(parentKey);
        if (deleteResult == ERROR_SUCCESS || deleteResult == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        if (errorTextOut != nullptr)
        {
            *errorTextOut = winErrorText(static_cast<DWORD>(deleteResult));
        }
        return false;
    }

    // deleteRegistryValueWithView：
    // - 输入 root/subKey/valueName/viewFlag/cleanupOpenWithMru：精确值位置和清理策略；
    // - 处理：删除单个值；若它来自 Explorer OpenWithList，则同步移除 MRUList 中的槽位字母；
    // - 返回：目标已不存在或删除成功返回 true，失败返回 false 并写 Win32 错误。
    bool deleteRegistryValueWithView(
        HKEY rootKey,
        const QString& subKeyPath,
        const QString& valueName,
        const REGSAM viewFlag,
        const bool cleanupOpenWithMru,
        QString* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (subKeyPath.trimmed().isEmpty() || valueName.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("注册表键路径或值名称为空。");
            }
            return false;
        }

        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            reinterpret_cast<const wchar_t*>(subKeyPath.utf16()),
            0,
            KEY_QUERY_VALUE | KEY_SET_VALUE | viewFlag,
            &openedKey);
        if (openResult == ERROR_FILE_NOT_FOUND)
        {
            return true;
        }
        if (openResult != ERROR_SUCCESS || openedKey == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(openResult));
            }
            return false;
        }

        // 删除值：
        // - valueName 始终是命名值，避免误删整个 OpenWithList/OpenWithProgids 键；
        // - 已不存在按幂等成功处理，便于重复刷新或批量操作。
        const LONG deleteResult = ::RegDeleteValueW(
            openedKey,
            reinterpret_cast<const wchar_t*>(valueName.utf16()));
        if (deleteResult != ERROR_SUCCESS && deleteResult != ERROR_FILE_NOT_FOUND)
        {
            ::RegCloseKey(openedKey);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = winErrorText(static_cast<DWORD>(deleteResult));
            }
            return false;
        }

        // MRU 修复：
        // - Explorer 历史列表用 a/b/c 槽位和值 MRUList 保存顺序；
        // - 删除槽位后尽力同步字符串，失败不回滚已经完成的精确删除。
        if (cleanupOpenWithMru)
        {
            DWORD mruType = REG_NONE;
            DWORD mruBytes = 0;
            const LONG sizeResult = ::RegQueryValueExW(
                openedKey,
                L"MRUList",
                nullptr,
                &mruType,
                nullptr,
                &mruBytes);
            if (sizeResult == ERROR_SUCCESS && mruType == REG_SZ && mruBytes >= sizeof(wchar_t))
            {
                std::vector<wchar_t> mruBuffer(
                    static_cast<std::size_t>(mruBytes / sizeof(wchar_t)) + 1,
                    L'\0');
                DWORD copiedBytes = mruBytes;
                const LONG queryResult = ::RegQueryValueExW(
                    openedKey,
                    L"MRUList",
                    nullptr,
                    &mruType,
                    reinterpret_cast<LPBYTE>(mruBuffer.data()),
                    &copiedBytes);
                if (queryResult == ERROR_SUCCESS)
                {
                    QString mruText = QString::fromWCharArray(mruBuffer.data());
                    mruText.remove(valueName, Qt::CaseInsensitive);
                    const DWORD updatedBytes = static_cast<DWORD>(
                        (mruText.size() + 1) * sizeof(wchar_t));
                    (void)::RegSetValueExW(
                        openedKey,
                        L"MRUList",
                        0,
                        REG_SZ,
                        reinterpret_cast<const BYTE*>(mruText.utf16()),
                        updatedBytes);
                }
            }
        }

        ::RegCloseKey(openedKey);
        return true;
    }

    // addUserAndMachineClassLocations：
    // - 输入 outputList/classesRelativePath/sourceGroup/entryKind/type flags；
    // - 处理：为 HKCU Software\\Classes 和 HKLM 64/32 Software\\Classes 添加扫描项；
    // - 返回：无。
    void addUserAndMachineClassLocations(
        std::vector<RegistryLocationDefinition>* outputList,
        const QString& classesRelativePath,
        const QString& sourceGroup,
        const QString& entryKind,
        const bool shellVerb,
        const bool shellExtension)
    {
        if (outputList == nullptr)
        {
            return;
        }

        outputList->push_back(RegistryLocationDefinition{
            HKEY_CURRENT_USER,
            QStringLiteral("HKCU"),
            QStringLiteral("Software\\Classes\\%1").arg(classesRelativePath),
            0,
            sourceGroup,
            entryKind,
            shellVerb,
            shellExtension,
            false });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(64位)"),
            QStringLiteral("Software\\Classes\\%1").arg(classesRelativePath),
            KEY_WOW64_64KEY,
            sourceGroup,
            entryKind,
            shellVerb,
            shellExtension,
            false });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(32位)"),
            QStringLiteral("Software\\Classes\\%1").arg(classesRelativePath),
            KEY_WOW64_32KEY,
            sourceGroup,
            entryKind,
            shellVerb,
            shellExtension,
            false });
    }

    // addIeMenuExtLocations：
    // - 输入 outputList：扫描目录输出数组；
    // - 处理：添加 HKCU/HKLM 下 Internet Explorer MenuExt 位置；
    // - 返回：无。
    void addIeMenuExtLocations(std::vector<RegistryLocationDefinition>* outputList)
    {
        if (outputList == nullptr)
        {
            return;
        }
        outputList->push_back(RegistryLocationDefinition{
            HKEY_CURRENT_USER,
            QStringLiteral("HKCU"),
            QStringLiteral("Software\\Microsoft\\Internet Explorer\\MenuExt"),
            0,
            QStringLiteral("Internet Explorer"),
            QStringLiteral("IE MenuExt"),
            false,
            false,
            true });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(64位)"),
            QStringLiteral("Software\\Microsoft\\Internet Explorer\\MenuExt"),
            KEY_WOW64_64KEY,
            QStringLiteral("Internet Explorer"),
            QStringLiteral("IE MenuExt"),
            false,
            false,
            true });
        outputList->push_back(RegistryLocationDefinition{
            HKEY_LOCAL_MACHINE,
            QStringLiteral("HKLM(32位)"),
            QStringLiteral("Software\\Microsoft\\Internet Explorer\\MenuExt"),
            KEY_WOW64_32KEY,
            QStringLiteral("Internet Explorer"),
            QStringLiteral("IE MenuExt"),
            false,
            false,
            true });
    }
}
