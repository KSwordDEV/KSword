#include "RegistryDock/RegistryDock.h"
#include "Framework/PrivilegeElevationPrompt.h"
#include "UI/TableInteractionSupport.h"
#include "UI/VisibleTableWidget.h"
#include "Internationalization/LanguageManager.h"

#include "ArkDriverClient/ArkDriverClient.h"
#include "RegistryDock/RegistryOptimizationPage.h"

// ============================================================
// RegistryDock.cpp
// 说明：
// 1) 提供类 regedit 的键树导航和键值编辑；
// 2) 支持导入/导出 .reg；
// 3) 支持后台搜索，避免阻塞 UI。
// ============================================================

#include "theme.h"

#include <QApplication>
#include <QClipboard>
#include <QComboBox>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStackedWidget>
#include <QStatusBar>
#include <QTabWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QThreadPool>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>

namespace
{
    // 统一按钮风格：与主界面保持同一主题。
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    // 统一输入框风格：路径栏、搜索栏复用同一套样式。
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:3px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // 表头风格：提升信息密集列表的可读性。
    QString blueHeaderStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    // TreeItem 角色常量：保存路径和懒加载状态。
    constexpr int kRolePath = Qt::UserRole + 1;
    constexpr int kRoleLoaded = Qt::UserRole + 2;
    constexpr int kRolePlaceholder = Qt::UserRole + 3;
    // kRoleLoadToken：子键懒加载令牌，非 0 表示该节点已有一次后台枚举在途；
    // 后台结果回投 UI 线程时用它淘汰被新请求取代的过期结果。
    constexpr int kRoleLoadToken = Qt::UserRole + 4;

    // 子键懒加载节流：UI 线程每轮事件循环最多创建的子节点数量。
    // HKCR 这类巨型键有上万个子键，一次性构造会让界面冻结数秒。
    constexpr int kSubKeyItemBatchSize = 300;

    // kPendingTreeSelectionProperty：
    // - 作用：把“待定位路径”挂在键树控件的动态属性上；
    // - 说明：子键加载改成异步后，路径定位只能逐级推进，后台落地后凭该属性继续下探；
    //         用动态属性而非成员变量，避免为异步定位额外改动共享头文件。
    constexpr const char* kPendingTreeSelectionProperty = "kswordPendingTreeSelectionPath";

    // g_nextSubKeyLoadToken：
    // - 作用：全局单调递增的懒加载令牌发号器，保证同一节点的新请求总能淘汰旧请求。
    std::atomic<quint64> g_nextSubKeyLoadToken{ 1 };

    // 搜索结果节流：限制后台积压与表格对象数量，保证大量命中时 UI 仍可交互。
    constexpr std::size_t kMaxPendingSearchRows = 4096;
    constexpr std::size_t kSearchFlushBatchSize = 160;
    constexpr int kMaxSearchResultRows = 20000;

    // 搜索结果角色：展示文字会因语言和默认值格式而变化，处置必须使用原始元数据。
    constexpr int kSearchResultRoleTargetKind = Qt::UserRole + 40;
    constexpr int kSearchResultRoleRawValueName = Qt::UserRole + 41;
    constexpr int kSearchResultTargetKey = 1;
    constexpr int kSearchResultTargetValue = 2;

    // 根键映射结构：支持全名与缩写两种输入。
    struct RootEntry
    {
        const wchar_t* fullName = nullptr;
        const wchar_t* shortName = nullptr;
        HKEY root = nullptr;
    };

    const std::array<RootEntry, 5> kRootMap{
        RootEntry{ L"HKEY_CLASSES_ROOT", L"HKCR", HKEY_CLASSES_ROOT },
        RootEntry{ L"HKEY_CURRENT_USER", L"HKCU", HKEY_CURRENT_USER },
        RootEntry{ L"HKEY_LOCAL_MACHINE", L"HKLM", HKEY_LOCAL_MACHINE },
        RootEntry{ L"HKEY_USERS", L"HKU", HKEY_USERS },
        RootEntry{ L"HKEY_CURRENT_CONFIG", L"HKCC", HKEY_CURRENT_CONFIG }
    };

    // trimDefaultValueName：界面“默认值”映射为 WinAPI 空名字。
    QString trimDefaultValueName(const QString& valueName)
    {
        const QString trimmed = valueName.trimmed();
        if (trimmed.isEmpty() || trimmed == QStringLiteral("(默认)"))
        {
            return QString();
        }
        return trimmed;
    }

    // queryCurrentUserSidText：
    // - 作用：解析当前进程所属用户 SID 文本（用于 HKCU -> \REGISTRY\USER\<SID> 映射）；
    // - 失败时返回空字符串，调用方可走保守兜底路径。
    QString queryCurrentUserSidText()
    {
        HANDLE tokenHandle = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
        {
            return QString();
        }

        DWORD tokenInfoBytes = 0;
        ::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &tokenInfoBytes);
        if (tokenInfoBytes == 0)
        {
            ::CloseHandle(tokenHandle);
            return QString();
        }

        QByteArray tokenBuffer(static_cast<int>(tokenInfoBytes), 0);
        if (!::GetTokenInformation(tokenHandle, TokenUser, tokenBuffer.data(), tokenInfoBytes, &tokenInfoBytes))
        {
            ::CloseHandle(tokenHandle);
            return QString();
        }
        ::CloseHandle(tokenHandle);

        const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.constData());
        if (tokenUser == nullptr || tokenUser->User.Sid == nullptr)
        {
            return QString();
        }

        LPWSTR sidTextBuffer = nullptr;
        if (!::ConvertSidToStringSidW(tokenUser->User.Sid, &sidTextBuffer) || sidTextBuffer == nullptr)
        {
            return QString();
        }

        const QString sidText = QString::fromWCharArray(sidTextBuffer).trimmed();
        ::LocalFree(sidTextBuffer);
        return sidText;
    }

    // buildKernelRegistryPath：
    // - 作用：把 HK*/HKEY_* 形式转换为内核命名空间 \REGISTRY\...；
    // - 返回：可直接用于驱动/内核回调规则的路径文本。
    QString buildKernelRegistryPath(const QString& registryPathText)
    {
        QString normalizedPath = registryPathText.trimmed();
        normalizedPath.replace('/', '\\');
        while (normalizedPath.contains(QStringLiteral("\\\\")))
        {
            normalizedPath.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
        }
        if (normalizedPath.endsWith('\\'))
        {
            normalizedPath.chop(1);
        }
        if (normalizedPath.isEmpty())
        {
            return QString();
        }

        if (normalizedPath.startsWith(QStringLiteral("\\REGISTRY\\"), Qt::CaseInsensitive)
            || normalizedPath.compare(QStringLiteral("\\REGISTRY"), Qt::CaseInsensitive) == 0)
        {
            return normalizedPath;
        }

        auto restPathAfterRoot = [&normalizedPath](const QString& rootText) {
            QString restPath = normalizedPath.mid(rootText.size());
            while (restPath.startsWith('\\'))
            {
                restPath.remove(0, 1);
            }
            return restPath;
        };

        auto buildWithRoot = [](const QString& kernelRootPath, const QString& restPath) {
            if (restPath.isEmpty())
            {
                return kernelRootPath;
            }
            return QStringLiteral("%1\\%2").arg(kernelRootPath, restPath);
        };

        if (normalizedPath.startsWith(QStringLiteral("HKLM"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKLM")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_LOCAL_MACHINE"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE"), restPathAfterRoot(QStringLiteral("HKEY_LOCAL_MACHINE")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKU"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKU")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_USERS"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\USER"), restPathAfterRoot(QStringLiteral("HKEY_USERS")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKCR"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKCR")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_CLASSES_ROOT"), Qt::CaseInsensitive))
        {
            return buildWithRoot(QStringLiteral("\\REGISTRY\\MACHINE\\SOFTWARE\\Classes"), restPathAfterRoot(QStringLiteral("HKEY_CLASSES_ROOT")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKCC"), Qt::CaseInsensitive))
        {
            return buildWithRoot(
                QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current"),
                restPathAfterRoot(QStringLiteral("HKCC")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKEY_CURRENT_CONFIG"), Qt::CaseInsensitive))
        {
            return buildWithRoot(
                QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current"),
                restPathAfterRoot(QStringLiteral("HKEY_CURRENT_CONFIG")));
        }
        if (normalizedPath.startsWith(QStringLiteral("HKCU"), Qt::CaseInsensitive)
            || normalizedPath.startsWith(QStringLiteral("HKEY_CURRENT_USER"), Qt::CaseInsensitive))
        {
            static const QString cachedUserSid = queryCurrentUserSidText();
            const QString userRootPath = cachedUserSid.isEmpty()
                ? QStringLiteral("\\REGISTRY\\USER")
                : QStringLiteral("\\REGISTRY\\USER\\%1").arg(cachedUserSid);
            const QString restPath = normalizedPath.startsWith(QStringLiteral("HKCU"), Qt::CaseInsensitive)
                ? restPathAfterRoot(QStringLiteral("HKCU"))
                : restPathAfterRoot(QStringLiteral("HKEY_CURRENT_USER"));
            return buildWithRoot(userRootPath, restPath);
        }

        return normalizedPath;
    }

    // bytesToHex：把二进制输出为十六进制字符串。
    QString bytesToHex(const QByteArray& bytes, int maxCount)
    {
        QStringList parts;
        const int showCount = std::min<int>(maxCount, bytes.size());
        for (int i = 0; i < showCount; ++i)
        {
            parts << QStringLiteral("%1").arg(static_cast<unsigned char>(bytes.at(i)), 2, 16, QLatin1Char('0')).toUpper();
        }
        if (bytes.size() > showCount)
        {
            parts << QStringLiteral("...");
        }
        return parts.join(' ');
    }

    // formatNtStatus：把 R0 返回的 NTSTATUS 格式化成固定宽度十六进制。
    QString formatNtStatus(const long statusValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(statusValue)), 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // registryDataToByteArray：
    // - 作用：把 ArkDriverClient 的字节向量转换为 Qt 原始数据；
    // - 返回：QByteArray，空向量返回空数组。
    QByteArray registryDataToByteArray(const std::vector<std::uint8_t>& dataBytes)
    {
        if (dataBytes.empty())
        {
            return QByteArray();
        }
        return QByteArray(
            reinterpret_cast<const char*>(dataBytes.data()),
            static_cast<int>(dataBytes.size()));
    }

    // byteArrayToRegistryData：
    // - 作用：把 Qt 原始数据转换为 R0 协议需要的 std::vector<uint8_t>；
    // - 返回：逐字节复制后的向量。
    std::vector<std::uint8_t> byteArrayToRegistryData(const QByteArray& rawData)
    {
        if (rawData.isEmpty())
        {
            return {};
        }
        const auto* begin = reinterpret_cast<const std::uint8_t*>(rawData.constData());
        return std::vector<std::uint8_t>(begin, begin + rawData.size());
    }

    // registryIoFailureText：
    // - 作用：把 DeviceIoControl 层失败转换为用户可读文本；
    // - 返回：包含 Win32 错误、NTSTATUS 和 ArkDriverClient 详情。
    QString registryIoMessageText(const std::string& rawMessage)
    {
        // registryIoMessageText：
        // - 输入：ArkDriverClient 返回的原始 io.message；
        // - 处理：把 DeviceIoControl/unsupported/capability 等底层日志归一为中文说明；
        // - 返回：适合 QMessageBox 和状态文本展示的短句。
        const QString rawText = QString::fromStdString(rawMessage).trimmed();
        if (rawText.isEmpty())
        {
            return QStringLiteral("驱动未提供额外说明。");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动通信失败或 R3/R0 协议不匹配，请确认驱动已加载且版本一致。");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动或协议暂不支持该注册表 R0 操作。");
        }
        if (rawText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("DynData"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动能力或动态偏移未满足，无法完成该注册表 R0 操作。");
        }
        if (rawText.contains(QStringLiteral("version mismatch"), Qt::CaseInsensitive))
        {
            return QStringLiteral("R3/R0/shared 协议版本不一致，请同步后重试。");
        }
        return rawText;
    }

    QString registryIoFailureText(const QString& actionText, const ksword::ark::IoResult& ioResult)
    {
        return QStringLiteral("%1失败：驱动通信失败，Win32=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(ioResult.win32Error)
            .arg(formatNtStatus(ioResult.ntStatus))
            .arg(registryIoMessageText(ioResult.message));
    }

    // registryReadFailureText：
    // - 作用：把 R0 读取失败转换为统一错误文本；
    // - 返回：包含聚合状态和底层 Zw* 状态。
    QString registryReadFailureText(const QString& actionText, const ksword::ark::RegistryReadResult& result)
    {
        if (!result.io.ok)
        {
            return registryIoFailureText(actionText, result.io);
        }
        return QStringLiteral("%1失败：R0状态=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(result.status)
            .arg(formatNtStatus(result.lastStatus))
            .arg(registryIoMessageText(result.io.message));
    }

    // registryEnumFailureText：
    // - 作用：把 R0 枚举失败转换为统一错误文本；
    // - 返回：包含聚合状态、NTSTATUS 和通信详情。
    QString registryEnumFailureText(const QString& actionText, const ksword::ark::RegistryEnumResult& result)
    {
        if (!result.io.ok)
        {
            return registryIoFailureText(actionText, result.io);
        }
        return QStringLiteral("%1失败：R0状态=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(result.status)
            .arg(formatNtStatus(result.lastStatus))
            .arg(registryIoMessageText(result.io.message));
    }

    // registryOperationFailureText：
    // - 作用：把 R0 写操作失败转换为统一错误文本；
    // - 返回：包含操作状态、NTSTATUS 和通信详情。
    QString registryOperationFailureText(const QString& actionText, const ksword::ark::RegistryOperationResult& result)
    {
        if (!result.io.ok)
        {
            return registryIoFailureText(actionText, result.io);
        }
        return QStringLiteral("%1失败：R0状态=%2，NTSTATUS=%3，详情=%4")
            .arg(actionText)
            .arg(result.status)
            .arg(formatNtStatus(result.lastStatus))
            .arg(registryIoMessageText(result.io.message));
    }

    // registryEnumUsable：
    // - 作用：判断 R0 枚举响应是否可用于 UI 展示；
    // - 返回：成功和部分成功均可展示，硬失败不可展示。
    bool registryEnumUsable(const ksword::ark::RegistryEnumResult& result)
    {
        return result.io.ok &&
            (result.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS ||
                result.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL);
    }

    // registryOperationSucceeded：
    // - 作用：判断 R0 写操作是否完成；
    // - 返回：通信成功且聚合状态为 SUCCESS。
    bool registryOperationSucceeded(const ksword::ark::RegistryOperationResult& result)
    {
        return result.io.ok &&
            result.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
    }

    // SubKeyEnumOutcome：
    // - 作用：后台线程枚举子键后回投 UI 线程的纯值类型结果，不含任何 QWidget 引用；
    // - 入参：无；
    // - 返回：无。enumerationOk 为 false 时按 win32ErrorCode / failureText 输出失败原因。
    struct SubKeyEnumOutcome
    {
        QStringList subKeyNames;                // 枚举到的子键名，保持注册表返回顺序。
        bool enumerationOk = false;             // 枚举是否成功完成。
        LONG win32ErrorCode = ERROR_SUCCESS;    // Win32 分支的打开失败码。
        QString failureText;                    // R0 分支的失败描述。
    };

    // collectSubKeyNamesByWin32：
    // - 作用：在后台线程用 Win32 API 枚举一个注册表键的全部子键名；
    // - 入参 rootKey：根键句柄；subPath：根键下的相对路径，可为空表示根键本身；
    // - 返回：枚举结果值对象；打开失败时 enumerationOk 为 false 并带上 Win32 错误码。
    SubKeyEnumOutcome collectSubKeyNamesByWin32(HKEY rootKey, const QString& subPath)
    {
        SubKeyEnumOutcome outcome;

        HKEY openedKey = nullptr;
        const LONG openResult = ::RegOpenKeyExW(
            rootKey,
            subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()),
            0,
            KEY_ENUMERATE_SUB_KEYS,
            &openedKey);
        if (openResult != ERROR_SUCCESS)
        {
            outcome.win32ErrorCode = openResult;
            return outcome;
        }

        wchar_t nameBuffer[512] = {};
        DWORD enumerationIndex = 0;
        DWORD nameLength = static_cast<DWORD>(std::size(nameBuffer));
        while (::RegEnumKeyExW(openedKey, enumerationIndex, nameBuffer, &nameLength, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS)
        {
            outcome.subKeyNames.push_back(QString::fromWCharArray(nameBuffer, static_cast<int>(nameLength)));
            ++enumerationIndex;
            nameLength = static_cast<DWORD>(std::size(nameBuffer));
        }

        ::RegCloseKey(openedKey);
        outcome.enumerationOk = true;
        return outcome;
    }

    // collectSubKeyNamesByR0：
    // - 作用：在后台线程通过 KswordARK 驱动枚举一个注册表键的全部子键名；
    // - 入参 kernelKeyPath：\REGISTRY\... 形式的内核路径；
    // - 返回：枚举结果值对象；驱动不可用或返回硬失败时 enumerationOk 为 false。
    SubKeyEnumOutcome collectSubKeyNamesByR0(const QString& kernelKeyPath)
    {
        SubKeyEnumOutcome outcome;

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryEnumResult enumResult = driverClient.enumerateRegistryKey(
            kernelKeyPath.toStdWString(),
            KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS);
        if (!registryEnumUsable(enumResult))
        {
            outcome.failureText = registryEnumFailureText(QStringLiteral("R0枚举子键"), enumResult);
            return outcome;
        }

        for (const ksword::ark::RegistrySubKeyEntry& subKeyEntry : enumResult.subKeys)
        {
            const QString subKeyName = QString::fromStdWString(subKeyEntry.name);
            if (subKeyName.trimmed().isEmpty())
            {
                continue;
            }
            outcome.subKeyNames.push_back(subKeyName);
        }

        outcome.enumerationOk = true;
        return outcome;
    }

    // resolveTreeItemByPath：
    // - 作用：按注册表路径逐级在键树里定位节点，只查已存在的节点，不触发任何加载；
    // - 入参 treeWidget：键树控件；registryPath：完整注册表路径；
    // - 返回：命中的节点指针；路径上任一级缺失时返回 nullptr。
    //   后台结果回投时用路径而不是裸指针重新定位，可彻底避免节点已被销毁的悬垂访问。
    QTreeWidgetItem* resolveTreeItemByPath(QTreeWidget* treeWidget, const QString& registryPath)
    {
        if (treeWidget == nullptr)
        {
            return nullptr;
        }

        const QStringList segments = registryPath.split(QLatin1Char('\\'), Qt::SkipEmptyParts);
        if (segments.isEmpty())
        {
            return nullptr;
        }

        QTreeWidgetItem* currentItem = nullptr;
        for (int topLevelIndex = 0; topLevelIndex < treeWidget->topLevelItemCount(); ++topLevelIndex)
        {
            QTreeWidgetItem* candidateItem = treeWidget->topLevelItem(topLevelIndex);
            if (candidateItem != nullptr && candidateItem->text(0).compare(segments.first(), Qt::CaseInsensitive) == 0)
            {
                currentItem = candidateItem;
                break;
            }
        }
        if (currentItem == nullptr)
        {
            return nullptr;
        }

        for (int segmentIndex = 1; segmentIndex < segments.size(); ++segmentIndex)
        {
            QTreeWidgetItem* nextItem = nullptr;
            for (int childIndex = 0; childIndex < currentItem->childCount(); ++childIndex)
            {
                QTreeWidgetItem* childItem = currentItem->child(childIndex);
                if (childItem == nullptr || childItem->data(0, kRolePlaceholder).toBool())
                {
                    continue;
                }
                if (childItem->text(0).compare(segments.at(segmentIndex), Qt::CaseInsensitive) == 0)
                {
                    nextItem = childItem;
                    break;
                }
            }
            if (nextItem == nullptr)
            {
                return nullptr;
            }
            currentItem = nextItem;
        }

        return currentItem;
    }

    // appendSubKeyItemsBatched：
    // - 作用：把后台枚举出的子键名分批插入键树，每轮事件循环最多插入 kSubKeyItemBatchSize 个节点，
    //         避免一次性构造上万个 QTreeWidgetItem 触发同等数量的模型信号而冻结界面；
    // - 入参 guardedTree：键树弱引用；parentPath：目标父节点路径；requestToken：本次加载令牌；
    //         subKeyNames：共享的子键名列表；startIndex：本批起始下标；onFinished：全部插入完成后的 UI 线程回调；
    // - 返回：无。父节点已销毁或令牌已过期时直接放弃剩余插入。
    void appendSubKeyItemsBatched(
        const QPointer<QTreeWidget>& guardedTree,
        const QString& parentPath,
        const quint64 requestToken,
        const std::shared_ptr<const QStringList>& subKeyNames,
        const int startIndex,
        const std::function<void()>& onFinished)
    {
        if (guardedTree.isNull() || subKeyNames == nullptr)
        {
            return;
        }

        QTreeWidgetItem* parentItem = resolveTreeItemByPath(guardedTree.data(), parentPath);
        if (parentItem == nullptr)
        {
            return;
        }
        if (parentItem->data(0, kRoleLoadToken).toULongLong() != requestToken)
        {
            return;
        }

        const int totalCount = static_cast<int>(subKeyNames->size());
        const int endIndex = std::min(startIndex + kSubKeyItemBatchSize, totalCount);
        for (int nameIndex = startIndex; nameIndex < endIndex; ++nameIndex)
        {
            const QString& subKeyName = subKeyNames->at(nameIndex);
            QTreeWidgetItem* childItem = new QTreeWidgetItem(parentItem);
            childItem->setText(0, subKeyName);
            childItem->setData(0, kRolePath, parentPath + QStringLiteral("\\") + subKeyName);
            childItem->setData(0, kRoleLoaded, false);
            childItem->setData(0, kRolePlaceholder, false);
            childItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
            // 用展开指示器策略代替占位子项：省掉与子键等量的第二批 QTreeWidgetItem。
            childItem->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
        }

        if (endIndex < totalCount)
        {
            QTimer::singleShot(0, guardedTree.data(),
                [guardedTree, parentPath, requestToken, subKeyNames, endIndex, onFinished]()
                {
                    appendSubKeyItemsBatched(guardedTree, parentPath, requestToken, subKeyNames, endIndex, onFinished);
                });
            return;
        }

        parentItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
        parentItem->setData(0, kRoleLoaded, true);
        parentItem->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
        if (onFinished)
        {
            onFinished();
        }
    }

    // NewRegistryValueInput 作用：
    // - 承载“新建值”对话框输出结果；
    // - 由调用方传给 writeRegistryValue 写入注册表。
    struct NewRegistryValueInput
    {
        QString valueName;       // valueName：值名称，空字符串表示默认值。
        DWORD valueType = REG_SZ; // valueType：注册表值类型（REG_*）。
        QByteArray valueData;    // valueData：原始字节数据（按 WinAPI 写入格式组织）。
    };

    // parseUnsignedIntegerText 作用：
    // - 支持把字符串解析为无符号整数（十进制或十六进制）；
    // - 返回 true 表示解析成功，numericOut 返回数值。
    bool parseUnsignedIntegerText(
        const QString& text,
        const int base,
        quint64* numericOut)
    {
        if (numericOut == nullptr)
        {
            return false;
        }

        QString normalized = text.trimmed();
        if (base == 16 && normalized.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalized = normalized.mid(2).trimmed();
        }
        normalized.remove(' ');
        if (normalized.isEmpty())
        {
            return false;
        }

        bool parseOk = false;
        const quint64 numericValue = normalized.toULongLong(&parseOk, base);
        if (!parseOk)
        {
            return false;
        }

        *numericOut = numericValue;
        return true;
    }

    // NewRegistryValueDialog 作用：
    // - 提供“值名称 + 类型 + 数据”的完整输入界面；
    // - 针对数值类型提供十进制/十六进制双输入框并自动同步。
    class NewRegistryValueDialog final : public QDialog
    {
    public:
        // 构造函数：
        // - parent：Qt 父窗口；
        // - 默认选中 REG_SZ，允许用户继续切换类型。
        explicit NewRegistryValueDialog(QWidget* parent)
            : QDialog(parent)
        {
            setWindowTitle(QStringLiteral("新建注册表值"));
            resize(560, 320);

            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            QFormLayout* formLayout = new QFormLayout();
            rootLayout->addLayout(formLayout);

            m_valueNameEdit = new QLineEdit(this);
            m_valueNameEdit->setPlaceholderText(QStringLiteral("留空表示默认值"));
            m_valueNameEdit->setToolTip(QStringLiteral("注册表值名称，留空表示(默认)"));
            formLayout->addRow(QStringLiteral("值名称"), m_valueNameEdit);

            m_valueTypeCombo = new QComboBox(this);
            m_valueTypeCombo->addItem(QStringLiteral("REG_SZ"), static_cast<int>(REG_SZ));
            m_valueTypeCombo->addItem(QStringLiteral("REG_EXPAND_SZ"), static_cast<int>(REG_EXPAND_SZ));
            m_valueTypeCombo->addItem(QStringLiteral("REG_MULTI_SZ"), static_cast<int>(REG_MULTI_SZ));
            m_valueTypeCombo->addItem(QStringLiteral("REG_DWORD"), static_cast<int>(REG_DWORD));
            m_valueTypeCombo->addItem(QStringLiteral("REG_QWORD"), static_cast<int>(REG_QWORD));
            m_valueTypeCombo->addItem(QStringLiteral("REG_BINARY"), static_cast<int>(REG_BINARY));
            m_valueTypeCombo->setToolTip(QStringLiteral("选择要创建的注册表值类型"));
            formLayout->addRow(QStringLiteral("值类型"), m_valueTypeCombo);

            m_valueStack = new QStackedWidget(this);
            rootLayout->addWidget(m_valueStack, 1);

            // 字符串页：用于 REG_SZ 与 REG_EXPAND_SZ。
            QWidget* stringPage = new QWidget(this);
            QVBoxLayout* stringLayout = new QVBoxLayout(stringPage);
            stringLayout->setContentsMargins(0, 0, 0, 0);
            m_stringEdit = new QLineEdit(stringPage);
            m_stringEdit->setPlaceholderText(QStringLiteral("输入字符串值"));
            m_stringEdit->setToolTip(QStringLiteral("字符串类型数据"));
            stringLayout->addWidget(new QLabel(QStringLiteral("字符串数据"), stringPage));
            stringLayout->addWidget(m_stringEdit);
            m_valueStack->addWidget(stringPage);

            // 多字符串页：每行一个子字符串，内部将自动组装为 MULTI_SZ。
            QWidget* multiStringPage = new QWidget(this);
            QVBoxLayout* multiLayout = new QVBoxLayout(multiStringPage);
            multiLayout->setContentsMargins(0, 0, 0, 0);
            m_multiStringEdit = new QTextEdit(multiStringPage);
            m_multiStringEdit->setPlaceholderText(QStringLiteral("每行一个字符串，空行将忽略"));
            m_multiStringEdit->setToolTip(QStringLiteral("多字符串类型数据（每行一个）"));
            multiLayout->addWidget(new QLabel(QStringLiteral("多字符串数据（逐行输入）"), multiStringPage));
            multiLayout->addWidget(m_multiStringEdit, 1);
            m_valueStack->addWidget(multiStringPage);

            // 数值页：十进制与十六进制双输入框实时同步，满足审计/调试习惯。
            QWidget* numericPage = new QWidget(this);
            QFormLayout* numericLayout = new QFormLayout(numericPage);
            m_decimalEdit = new QLineEdit(numericPage);
            m_decimalEdit->setPlaceholderText(QStringLiteral("十进制，例如 123456"));
            m_decimalEdit->setToolTip(QStringLiteral("十进制输入，自动同步到十六进制"));
            m_hexEdit = new QLineEdit(numericPage);
            m_hexEdit->setPlaceholderText(QStringLiteral("十六进制，例如 0x1E240"));
            m_hexEdit->setToolTip(QStringLiteral("十六进制输入，自动同步到十进制"));
            numericLayout->addRow(QStringLiteral("十进制"), m_decimalEdit);
            numericLayout->addRow(QStringLiteral("十六进制"), m_hexEdit);
            m_valueStack->addWidget(numericPage);

            // 二进制页：按字节输入十六进制文本，支持空格分隔。
            QWidget* binaryPage = new QWidget(this);
            QVBoxLayout* binaryLayout = new QVBoxLayout(binaryPage);
            binaryLayout->setContentsMargins(0, 0, 0, 0);
            m_binaryEdit = new QLineEdit(binaryPage);
            m_binaryEdit->setPlaceholderText(QStringLiteral("例如：4D 5A 90 00"));
            m_binaryEdit->setToolTip(QStringLiteral("按字节输入十六进制，使用空格分隔"));
            binaryLayout->addWidget(new QLabel(QStringLiteral("二进制字节（十六进制）"), binaryPage));
            binaryLayout->addWidget(m_binaryEdit);
            m_valueStack->addWidget(binaryPage);

            QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
            rootLayout->addWidget(buttonBox);
            connect(buttonBox, &QDialogButtonBox::accepted, this, [this]() {
                QString errorText;
                if (!validateInput(&errorText))
                {
                    QMessageBox::warning(this, QStringLiteral("新建值"), errorText);
                    return;
                }
                accept();
            });
            connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

            connect(m_valueTypeCombo, &QComboBox::currentIndexChanged, this, [this](int) {
                updateDataPageByType();
            });
            connect(m_decimalEdit, &QLineEdit::textChanged, this, [this](const QString&) {
                syncNumericText(true);
            });
            connect(m_hexEdit, &QLineEdit::textChanged, this, [this](const QString&) {
                syncNumericText(false);
            });

            m_decimalEdit->setText(QStringLiteral("0"));
            updateDataPageByType();
        }

        // buildOutput 作用：
        // - 在对话框 accept 后输出可直接写入 WinAPI 的结构；
        // - 调用前需保证 validateInput 已通过。
        NewRegistryValueInput buildOutput() const
        {
            NewRegistryValueInput output;
            output.valueName = m_valueNameEdit->text().trimmed();
            output.valueType = static_cast<DWORD>(m_valueTypeCombo->currentData().toInt());

            if (output.valueType == REG_SZ || output.valueType == REG_EXPAND_SZ)
            {
                QString textValue = m_stringEdit->text();
                textValue.append(QChar::Null);
                output.valueData = QByteArray(
                    reinterpret_cast<const char*>(textValue.utf16()),
                    textValue.size() * static_cast<int>(sizeof(char16_t)));
                return output;
            }

            if (output.valueType == REG_MULTI_SZ)
            {
                QStringList lineList = m_multiStringEdit->toPlainText().split('\n');
                QString mergedText;
                for (QString line : lineList)
                {
                    line = line.trimmed();
                    if (line.isEmpty())
                    {
                        continue;
                    }
                    mergedText.append(line);
                    mergedText.append(QChar::Null);
                }
                mergedText.append(QChar::Null);
                output.valueData = QByteArray(
                    reinterpret_cast<const char*>(mergedText.utf16()),
                    mergedText.size() * static_cast<int>(sizeof(char16_t)));
                return output;
            }

            if (output.valueType == REG_DWORD || output.valueType == REG_QWORD)
            {
                quint64 numericValue = 0;
                if (!parseUnsignedIntegerText(m_decimalEdit->text(), 10, &numericValue))
                {
                    parseUnsignedIntegerText(m_hexEdit->text(), 16, &numericValue);
                }
                if (output.valueType == REG_DWORD)
                {
                    const quint32 dwordValue = static_cast<quint32>(numericValue & 0xFFFFFFFFULL);
                    output.valueData = QByteArray(
                        reinterpret_cast<const char*>(&dwordValue),
                        static_cast<int>(sizeof(dwordValue)));
                }
                else
                {
                    output.valueData = QByteArray(
                        reinterpret_cast<const char*>(&numericValue),
                        static_cast<int>(sizeof(numericValue)));
                }
                return output;
            }

            const QStringList byteTextList = m_binaryEdit->text().split(
                QRegularExpression(QStringLiteral("[,\\s]+")),
                Qt::SkipEmptyParts);
            for (const QString& byteText : byteTextList)
            {
                bool parseOk = false;
                const int byteValue = byteText.toInt(&parseOk, 16);
                if (!parseOk || byteValue < 0 || byteValue > 255)
                {
                    continue;
                }
                output.valueData.push_back(static_cast<char>(byteValue));
            }
            return output;
        }

    private:
        // validateInput 作用：
        // - 在点击确定时校验字段完整性与格式合法性；
        // - errorTextOut 返回可直接显示给用户的错误文本。
        bool validateInput(QString* errorTextOut) const
        {
            auto setError = [errorTextOut](const QString& text) {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = text;
                }
            };

            const DWORD valueType = static_cast<DWORD>(m_valueTypeCombo->currentData().toInt());
            if (valueType == REG_DWORD || valueType == REG_QWORD)
            {
                quint64 numericValue = 0;
                bool parseOk = parseUnsignedIntegerText(m_decimalEdit->text(), 10, &numericValue);
                if (!parseOk)
                {
                    parseOk = parseUnsignedIntegerText(m_hexEdit->text(), 16, &numericValue);
                }
                if (!parseOk)
                {
                    setError(QStringLiteral("数值格式无效，请输入十进制或十六进制数字。"));
                    return false;
                }
                if (valueType == REG_DWORD && numericValue > 0xFFFFFFFFULL)
                {
                    setError(QStringLiteral("DWORD 范围应在 0 ~ 0xFFFFFFFF。"));
                    return false;
                }
                return true;
            }

            if (valueType == REG_BINARY)
            {
                const QStringList byteTextList = m_binaryEdit->text().split(
                    QRegularExpression(QStringLiteral("[,\\s]+")),
                    Qt::SkipEmptyParts);
                for (const QString& byteText : byteTextList)
                {
                    bool parseOk = false;
                    const int byteValue = byteText.toInt(&parseOk, 16);
                    if (!parseOk || byteValue < 0 || byteValue > 255)
                    {
                        setError(QStringLiteral("二进制字节格式无效：%1").arg(byteText));
                        return false;
                    }
                }
                return true;
            }

            return true;
        }

        // updateDataPageByType 作用：
        // - 根据 REG 类型切换输入页；
        // - 保证输入控件与目标数据模型一致。
        void updateDataPageByType()
        {
            const DWORD valueType = static_cast<DWORD>(m_valueTypeCombo->currentData().toInt());
            if (valueType == REG_SZ || valueType == REG_EXPAND_SZ)
            {
                m_valueStack->setCurrentIndex(0);
                return;
            }
            if (valueType == REG_MULTI_SZ)
            {
                m_valueStack->setCurrentIndex(1);
                return;
            }
            if (valueType == REG_DWORD || valueType == REG_QWORD)
            {
                m_valueStack->setCurrentIndex(2);
                return;
            }
            m_valueStack->setCurrentIndex(3);
        }

        // syncNumericText 作用：
        // - 十进制/十六进制双向同步；
        // - fromDecimal=true 表示用户刚编辑十进制框，反之同步十六进制框。
        void syncNumericText(const bool fromDecimal)
        {
            if (m_syncingNumberText)
            {
                return;
            }

            m_syncingNumberText = true;
            quint64 numericValue = 0;
            bool parseOk = false;
            if (fromDecimal)
            {
                parseOk = parseUnsignedIntegerText(m_decimalEdit->text(), 10, &numericValue);
                if (parseOk)
                {
                    QSignalBlocker blocker(m_hexEdit);
                    m_hexEdit->setText(QStringLiteral("0x%1").arg(numericValue, 0, 16).toUpper());
                }
            }
            else
            {
                parseOk = parseUnsignedIntegerText(m_hexEdit->text(), 16, &numericValue);
                if (parseOk)
                {
                    QSignalBlocker blocker(m_decimalEdit);
                    m_decimalEdit->setText(QString::number(numericValue));
                }
            }
            m_syncingNumberText = false;
        }

    private:
        QLineEdit* m_valueNameEdit = nullptr;      // m_valueNameEdit：值名称输入框。
        QComboBox* m_valueTypeCombo = nullptr;     // m_valueTypeCombo：值类型下拉框。
        QStackedWidget* m_valueStack = nullptr;    // m_valueStack：不同类型的数据输入页。
        QLineEdit* m_stringEdit = nullptr;         // m_stringEdit：字符串类型输入框。
        QTextEdit* m_multiStringEdit = nullptr;    // m_multiStringEdit：多字符串输入框。
        QLineEdit* m_decimalEdit = nullptr;        // m_decimalEdit：十进制输入框。
        QLineEdit* m_hexEdit = nullptr;            // m_hexEdit：十六进制输入框。
        QLineEdit* m_binaryEdit = nullptr;         // m_binaryEdit：二进制字节输入框。
        bool m_syncingNumberText = false;          // m_syncingNumberText：防止双向同步递归触发。
    };
}

RegistryDock::RegistryDock(QWidget* parent)
    : QWidget(parent)
{
    {
        kLogEvent event;
        info << event << "[RegistryDock] 构造开始，准备初始化注册表模块。" << eol;
    }

    initializeUi();
    initializeConnections();
    initializeRootItems();
    navigateToPath(QStringLiteral("HKEY_CURRENT_USER"), true);

    {
        kLogEvent event;
        info << event << "[RegistryDock] 构造完成，默认定位到 HKEY_CURRENT_USER。" << eol;
    }
}

RegistryDock::~RegistryDock()
{
    kLogEvent event;
    info << event << "[RegistryDock] 析构开始，准备停止搜索线程。" << eol;

    stopSearch(true);
    if (m_searchFlushTimer != nullptr)
    {
        m_searchFlushTimer->stop();
    }

    kLogEvent finishEvent;
    info << finishEvent << "[RegistryDock] 析构完成，后台资源已回收。" << eol;
}

void RegistryDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    m_registryTabWidget = new QTabWidget(this);
    m_rootLayout->addWidget(m_registryTabWidget, 1);

    m_registryEditorPage = new QWidget(m_registryTabWidget);
    m_registryEditorLayout = new QVBoxLayout(m_registryEditorPage);
    m_registryEditorLayout->setContentsMargins(0, 0, 0, 0);
    m_registryEditorLayout->setSpacing(6);

    m_toolBarWidget = new QWidget(m_registryEditorPage);
    m_toolBarLayout = new QHBoxLayout(m_toolBarWidget);
    m_toolBarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolBarLayout->setSpacing(4);

    // 导航图标与文件管理器保持一致，统一“后退/前进”视觉语义。
    m_backButton = new QPushButton(QIcon(":/Icon/file_nav_back.svg"), QString(), m_toolBarWidget);
    m_forwardButton = new QPushButton(QIcon(":/Icon/file_nav_forward.svg"), QString(), m_toolBarWidget);
    m_refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_toolBarWidget);
    m_newKeyButton = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QString(), m_toolBarWidget);
    m_newValueButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_toolBarWidget);
    m_renameButton = new QPushButton(QIcon(":/Icon/process_priority.svg"), QString(), m_toolBarWidget);
    m_deleteButton = new QPushButton(QIcon(":/Icon/process_terminate.svg"), QString(), m_toolBarWidget);
    m_importButton = new QPushButton(QIcon(":/Icon/reg_import.svg"), QString(), m_toolBarWidget);
    m_exportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QString(), m_toolBarWidget);
    m_searchButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), m_toolBarWidget);
    m_stopSearchButton = new QPushButton(QIcon(":/Icon/process_pause.svg"), QString(), m_toolBarWidget);

    m_backButton->setToolTip(QStringLiteral("后退"));
    m_forwardButton->setToolTip(QStringLiteral("前进"));
    m_refreshButton->setToolTip(QStringLiteral("刷新"));
    m_newKeyButton->setToolTip(QStringLiteral("新建子键"));
    m_newValueButton->setToolTip(QStringLiteral("新建值"));
    m_renameButton->setToolTip(QStringLiteral("重命名"));
    m_deleteButton->setToolTip(QStringLiteral("删除"));
    m_importButton->setToolTip(QStringLiteral("导入 .reg"));
    m_exportButton->setToolTip(QStringLiteral("导出 .reg"));
    m_searchButton->setToolTip(QStringLiteral("开始搜索"));
    m_stopSearchButton->setToolTip(QStringLiteral("停止搜索"));

    for (QPushButton* button : { m_backButton, m_forwardButton, m_refreshButton, m_newKeyButton, m_newValueButton,
            m_renameButton, m_deleteButton, m_importButton, m_exportButton, m_searchButton, m_stopSearchButton })
    {
        button->setStyleSheet(blueButtonStyle());
        button->setFixedWidth(34);
    }

    m_pathEdit = new QLineEdit(m_toolBarWidget);
    m_pathEdit->setStyleSheet(blueInputStyle());
    m_pathEdit->setPlaceholderText(QStringLiteral("输入路径后回车，例如 HKEY_LOCAL_MACHINE\\SOFTWARE"));

    m_driverRegistryModeLabel = new QLabel(m_toolBarWidget);
    m_driverRegistryModeLabel->setMinimumWidth(118);
    m_driverRegistryModeLabel->setAlignment(Qt::AlignCenter);
    m_driverRegistryModeLabel->setToolTip(QStringLiteral("驱动可用时启用增强的注册表浏览与编辑。"));

    m_searchEdit = new QLineEdit(m_toolBarWidget);
    m_searchEdit->setStyleSheet(blueInputStyle());
    m_searchEdit->setPlaceholderText(QStringLiteral("搜索键/值/数据"));
    m_searchEdit->setMaximumWidth(320);

    m_toolBarLayout->addWidget(m_backButton);
    m_toolBarLayout->addWidget(m_forwardButton);
    m_toolBarLayout->addWidget(m_refreshButton);
    m_toolBarLayout->addWidget(m_newKeyButton);
    m_toolBarLayout->addWidget(m_newValueButton);
    m_toolBarLayout->addWidget(m_renameButton);
    m_toolBarLayout->addWidget(m_deleteButton);
    m_toolBarLayout->addWidget(m_importButton);
    m_toolBarLayout->addWidget(m_exportButton);
    m_toolBarLayout->addWidget(m_pathEdit, 1);
    m_toolBarLayout->addWidget(m_driverRegistryModeLabel, 0);
    m_toolBarLayout->addWidget(m_searchEdit, 0);
    m_toolBarLayout->addWidget(m_searchButton);
    m_toolBarLayout->addWidget(m_stopSearchButton);

    m_registryEditorLayout->addWidget(m_toolBarWidget, 0);

    m_mainSplitter = new QSplitter(Qt::Horizontal, m_registryEditorPage);
    m_registryEditorLayout->addWidget(m_mainSplitter, 1);

    m_keyTree = new QTreeWidget(m_mainSplitter);
    m_keyTree->setColumnCount(1);
    m_keyTree->setHeaderLabel(QStringLiteral("注册表键"));
    m_keyTree->header()->setStyleSheet(blueHeaderStyle());
    m_keyTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_keyTree->setMinimumWidth(360);

    m_rightTabWidget = new QTabWidget(m_mainSplitter);

    m_valueTable = new ks::ui::VisibleTableWidget(m_rightTabWidget);
    m_valueTable->setColumnCount(3);
    m_valueTable->setHorizontalHeaderLabels(QStringList{ QStringLiteral("名称"), QStringLiteral("类型"), QStringLiteral("数据") });
    m_valueTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_valueTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_valueTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    // 关闭角按钮，避免左上角出现默认白色单元格。
    m_valueTable->setCornerButtonEnabled(false);
    m_valueTable->setAlternatingRowColors(true);
    m_valueTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_valueTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_valueTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_valueTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_valueTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    m_searchResultTable = new ks::ui::VisibleTableWidget(m_rightTabWidget);
    m_searchResultTable->setColumnCount(5);
    m_searchResultTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("键路径"), QStringLiteral("值名"), QStringLiteral("类型"), QStringLiteral("数据预览"), QStringLiteral("命中来源")
        });
    m_searchResultTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_searchResultTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_searchResultTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_searchResultTable->setCornerButtonEnabled(false);
    m_searchResultTable->setAlternatingRowColors(true);
    m_searchResultTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_searchResultTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    m_searchResultTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);

    m_rightTabWidget->addTab(m_valueTable, QStringLiteral("值列表"));
    m_rightTabWidget->addTab(m_searchResultTable, QStringLiteral("搜索结果"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_rightTabWidget, m_valueTable, QStringLiteral("registry.tab.values"), QStringLiteral("值列表"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_rightTabWidget, m_searchResultTable, QStringLiteral("registry.tab.search_results"), QStringLiteral("搜索结果"));

    m_mainSplitter->setStretchFactor(0, 1);
    m_mainSplitter->setStretchFactor(1, 2);

    m_statusBar = new QStatusBar(m_registryEditorPage);
    m_pathStatusLabel = new QLabel(QStringLiteral("路径: -"), m_statusBar);
    m_summaryStatusLabel = new QLabel(QStringLiteral("状态: 就绪"), m_statusBar);
    m_statusBar->addWidget(m_pathStatusLabel, 1);
    m_statusBar->addPermanentWidget(m_summaryStatusLabel, 0);
    m_registryEditorLayout->addWidget(m_statusBar, 0);

    m_searchFlushTimer = new QTimer(this);
    m_searchFlushTimer->setInterval(100);
    m_stopSearchButton->setEnabled(false);
    refreshRegistryDriverModeIndicator();

    m_optimizationPage = new RegistryOptimizationPage(m_registryTabWidget);
    m_registryTabWidget->addTab(m_registryEditorPage, QStringLiteral("注册表编辑"));
    m_registryTabWidget->addTab(m_optimizationPage, QStringLiteral("系统优化"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_registryTabWidget, m_registryEditorPage, QStringLiteral("registry.tab.editor"), QStringLiteral("注册表编辑"));
    ks::i18n::LanguageManager::instance().bindTab(
        m_registryTabWidget, m_optimizationPage, QStringLiteral("registry.tab.optimization"), QStringLiteral("系统优化"));
}

void RegistryDock::initializeConnections()
{
    connect(m_backButton, &QPushButton::clicked, this, [this]() {
        if (m_navigationIndex <= 0 || m_navigationHistory.empty()) return;
        m_navigationIndex -= 1;
        navigateToPath(m_navigationHistory[static_cast<std::size_t>(m_navigationIndex)], false);
    });

    connect(m_forwardButton, &QPushButton::clicked, this, [this]() {
        if (m_navigationHistory.empty()) return;
        const int nextIndex = m_navigationIndex + 1;
        if (nextIndex < 0 || nextIndex >= static_cast<int>(m_navigationHistory.size())) return;
        m_navigationIndex = nextIndex;
        navigateToPath(m_navigationHistory[static_cast<std::size_t>(m_navigationIndex)], false);
    });

    connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshCurrentKey(true); });
    connect(m_pathEdit, &QLineEdit::returnPressed, this, [this]() { navigateToPath(m_pathEdit->text().trimmed(), true); });

    connect(m_keyTree, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item) { ensureTreeItemLoaded(item); });
    connect(m_keyTree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* item, QTreeWidgetItem*) {
        if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
        const QString path = item->data(0, kRolePath).toString();
        if (!path.isEmpty() && path.compare(m_currentPath, Qt::CaseInsensitive) != 0) navigateToPath(path, true);
    });

    connect(m_keyTree, &QTreeWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showTreeContextMenu(pos); });
    connect(m_valueTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) { showValueContextMenu(pos); });
    connect(m_valueTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem*) { editSelectedValue(); });

    connect(m_newKeyButton, &QPushButton::clicked, this, [this]() { createSubKey(); });
    connect(m_newValueButton, &QPushButton::clicked, this, [this]() { createValue(); });
    connect(m_renameButton, &QPushButton::clicked, this, [this]() { renameSelectedObject(); });
    connect(m_deleteButton, &QPushButton::clicked, this, [this]() { deleteSelectedObject(); });
    connect(m_importButton, &QPushButton::clicked, this, [this]() { importRegFileAsync(); });
    connect(m_exportButton, &QPushButton::clicked, this, [this]() { exportCurrentKeyAsync(); });
    connect(m_searchButton, &QPushButton::clicked, this, [this]() { startSearchAsync(); });
    connect(m_stopSearchButton, &QPushButton::clicked, this, [this]() { stopSearch(false); });
    connect(m_searchEdit, &QLineEdit::returnPressed, this, [this]() { startSearchAsync(); });
    connect(m_searchFlushTimer, &QTimer::timeout, this, [this]() { flushPendingSearchRows(); });

    connect(m_searchResultTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& pos) {
        // 搜索结果菜单：
        // - 输入：用户在搜索结果表中的右键位置；
        // - 处理：同步当前行，支持复制；值命中还可按行保存的原始目标删除值。
        // - 返回：无；删除走既有 R0 优先 / R3 回退路径。
        const QModelIndex hit = m_searchResultTable->indexAt(pos);
        if (hit.isValid()) m_searchResultTable->setCurrentCell(hit.row(), hit.column());

        const int row = m_searchResultTable->currentRow();
        const QTableWidgetItem* pathItem = row >= 0 ? m_searchResultTable->item(row, 0) : nullptr;
        const QTableWidgetItem* valueNameItem = row >= 0 ? m_searchResultTable->item(row, 1) : nullptr;
        const bool isKeyResult = pathItem != nullptr
            && pathItem->data(kSearchResultRoleTargetKind).toInt() == kSearchResultTargetKey;
        const bool isValueResult = pathItem != nullptr
            && pathItem->data(kSearchResultRoleTargetKind).toInt() == kSearchResultTargetValue;

        QMenu menu(this);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        QAction* copyRowAction = menu.addAction(QIcon(":/Icon/process_copy_row.svg"), QStringLiteral("复制当前行"));
        copyRowAction->setEnabled(row >= 0);
        QAction* deleteValueAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除该值"));
        deleteValueAction->setEnabled(isValueResult && valueNameItem != nullptr);
        QAction* deleteKeyAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除该键（含子项）"));
        deleteKeyAction->setEnabled(isKeyResult);

        const QAction* action = menu.exec(m_searchResultTable->viewport()->mapToGlobal(pos));
        if (action == deleteKeyAction)
        {
            if (pathItem != nullptr)
            {
                deleteSearchResultKey(pathItem->text());
            }
            return;
        }
        if (action == deleteValueAction)
        {
            if (pathItem == nullptr || valueNameItem == nullptr)
            {
                return;
            }
            deleteSearchResultValue(
                pathItem->text(),
                valueNameItem->data(kSearchResultRoleRawValueName).toString());
            return;
        }
        if (action != copyRowAction) return;

        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard == nullptr || row < 0 || row >= m_searchResultTable->rowCount()) return;

        QStringList fields;
        fields.reserve(m_searchResultTable->columnCount());
        for (int column = 0; column < m_searchResultTable->columnCount(); ++column)
        {
            const QTableWidgetItem* item = m_searchResultTable->item(row, column);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        clipboard->setText(fields.join(QLatin1Char('\t')));
    });

    connect(m_searchResultTable, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item) {
        if (item == nullptr) return;
        QTableWidgetItem* pathItem = m_searchResultTable->item(item->row(), 0);
        if (pathItem == nullptr) return;
        navigateToPath(pathItem->text().trimmed(), true);
        m_rightTabWidget->setCurrentWidget(m_valueTable);
    });
}

void RegistryDock::initializeRootItems()
{
    m_keyTree->clear();
    for (const RootEntry& entry : kRootMap)
    {
        QTreeWidgetItem* item = new QTreeWidgetItem(m_keyTree);
        item->setText(0, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRolePath, QString::fromWCharArray(entry.fullName));
        item->setData(0, kRoleLoaded, false);
        item->setData(0, kRolePlaceholder, false);
        item->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
        // 根键一定可展开：用指示器策略代替占位子项，展开时才异步枚举真实子键。
        item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
    }
}
bool RegistryDock::parseRegistryPath(const QString& pathText, HKEY* rootKeyOut, QString* subPathOut)
{
    if (rootKeyOut == nullptr || subPathOut == nullptr) return false;

    QString text = pathText.trimmed();
    text.replace('/', '\\');
    while (text.contains(QStringLiteral("\\\\"))) text.replace(QStringLiteral("\\\\"), QStringLiteral("\\"));
    if (text.endsWith('\\')) text.chop(1);
    if (text.isEmpty()) return false;

    const int split = text.indexOf('\\');
    const QString rootText = split < 0 ? text : text.left(split);
    const QString subPath = split < 0 ? QString() : text.mid(split + 1);

    for (const RootEntry& entry : kRootMap)
    {
        const QString full = QString::fromWCharArray(entry.fullName);
        const QString shortName = QString::fromWCharArray(entry.shortName);
        if (rootText.compare(full, Qt::CaseInsensitive) == 0 || rootText.compare(shortName, Qt::CaseInsensitive) == 0)
        {
            *rootKeyOut = entry.root;
            *subPathOut = subPath;
            return true;
        }
    }
    return false;
}

QString RegistryDock::normalizeRegistryPath(const QString& pathText)
{
    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(pathText, &root, &subPath)) return QString();
    QString output = rootKeyToText(root);
    if (!subPath.isEmpty()) output += QStringLiteral("\\") + subPath;
    return output;
}

QString RegistryDock::rootKeyToText(HKEY rootKey)
{
    for (const RootEntry& entry : kRootMap)
    {
        if (entry.root == rootKey) return QString::fromWCharArray(entry.fullName);
    }
    return QStringLiteral("<Unknown>");
}

QString RegistryDock::valueTypeToText(DWORD type)
{
    switch (type)
    {
    case REG_NONE: return QStringLiteral("REG_NONE");
    case REG_SZ: return QStringLiteral("REG_SZ");
    case REG_EXPAND_SZ: return QStringLiteral("REG_EXPAND_SZ");
    case REG_BINARY: return QStringLiteral("REG_BINARY");
    case REG_DWORD: return QStringLiteral("REG_DWORD");
    case REG_MULTI_SZ: return QStringLiteral("REG_MULTI_SZ");
    case REG_QWORD: return QStringLiteral("REG_QWORD");
    default: return QStringLiteral("REG_%1").arg(type);
    }
}

QString RegistryDock::formatValueData(DWORD type, const QByteArray& data)
{
    if (data.isEmpty()) return QStringLiteral("<empty>");

    if (type == REG_SZ || type == REG_EXPAND_SZ)
    {
        QString text = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.constData()), data.size() / sizeof(wchar_t));
        text.remove(QChar::Null);
        return text;
    }
    if (type == REG_MULTI_SZ)
    {
        QString text = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data.constData()), data.size() / sizeof(wchar_t));
        return text.split(QChar::Null, Qt::SkipEmptyParts).join(QStringLiteral(" | "));
    }
    if (type == REG_DWORD && data.size() >= static_cast<int>(sizeof(DWORD)))
    {
        const DWORD value = *reinterpret_cast<const DWORD*>(data.constData());
        return QStringLiteral("0x%1 (%2)").arg(value, 8, 16, QLatin1Char('0')).arg(value);
    }
    if (type == REG_QWORD && data.size() >= static_cast<int>(sizeof(quint64)))
    {
        const quint64 value = *reinterpret_cast<const quint64*>(data.constData());
        return QStringLiteral("0x%1 (%2)").arg(static_cast<qulonglong>(value), 16, 16, QLatin1Char('0')).arg(static_cast<qulonglong>(value));
    }
    return bytesToHex(data, 64);
}

QString RegistryDock::winErrorText(LONG code)
{
    wchar_t* buffer = nullptr;
    const DWORD size = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(code),
        0,
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    QString text = QStringLiteral("错误码 %1").arg(code);
    if (size > 0 && buffer != nullptr)
    {
        text += QStringLiteral(": ") + QString::fromWCharArray(buffer, static_cast<int>(size)).trimmed();
    }
    if (buffer != nullptr) ::LocalFree(buffer);
    return text;
}

bool RegistryDock::readRegistryValueRaw(HKEY root, const QString& subPath, const QString& valueName, DWORD* typeOut, QByteArray* dataOut, QString* errorOut)
{
    if (typeOut == nullptr || dataOut == nullptr) return false;
    if (errorOut != nullptr) errorOut->clear();

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(openResult);
        return false;
    }

    const QString realName = trimDefaultValueName(valueName);
    const wchar_t* valuePtr = realName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(realName.utf16());

    DWORD type = REG_NONE;
    DWORD size = 0;
    LONG queryResult = ::RegQueryValueExW(key, valuePtr, nullptr, &type, nullptr, &size);
    if (queryResult != ERROR_SUCCESS)
    {
        ::RegCloseKey(key);
        if (errorOut != nullptr) *errorOut = winErrorText(queryResult);
        return false;
    }

    QByteArray data;
    data.resize(static_cast<int>(size));
    if (size > 0)
    {
        queryResult = ::RegQueryValueExW(key, valuePtr, nullptr, &type, reinterpret_cast<LPBYTE>(data.data()), &size);
        if (queryResult != ERROR_SUCCESS)
        {
            ::RegCloseKey(key);
            if (errorOut != nullptr) *errorOut = winErrorText(queryResult);
            return false;
        }
    }

    ::RegCloseKey(key);
    *typeOut = type;
    *dataOut = data;
    return true;
}

bool RegistryDock::writeRegistryValue(HKEY root, const QString& subPath, const QString& valueName, DWORD type, const QByteArray& rawData, QString* errorOut)
{
    if (errorOut != nullptr) errorOut->clear();

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(openResult);
        return false;
    }

    const QString realName = trimDefaultValueName(valueName);
    const wchar_t* valuePtr = realName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(realName.utf16());
    LONG setResult = ::RegSetValueExW(
        key,
        valuePtr,
        0,
        type,
        reinterpret_cast<const BYTE*>(rawData.constData()),
        static_cast<DWORD>(rawData.size()));
    ::RegCloseKey(key);

    if (setResult != ERROR_SUCCESS)
    {
        if (errorOut != nullptr) *errorOut = winErrorText(setResult);
        return false;
    }
    return true;
}

void RegistryDock::refreshRegistryDriverModeIndicator()
{
    // 作用：刷新路径输入栏旁边的 R0 注册表读写标识。
    // 返回：无；仅更新 QLabel 文本、颜色与提示。
    if (m_driverRegistryModeLabel == nullptr)
    {
        return;
    }

    const bool enabled = shouldUseRegistryR0();
    if (enabled)
    {
        m_driverRegistryModeLabel->setText(QStringLiteral("R0读写: 开启"));
        m_driverRegistryModeLabel->setStyleSheet(QStringLiteral(
            "QLabel{border:1px solid %1;border-radius:3px;"
            "background:%2;color:%1;padding:2px 6px;font-weight:600;}"
        ).arg(KswordTheme::SuccessColor().name(QColor::HexRgb))
         .arg(KswordTheme::RgbaColorName(KswordTheme::SuccessColor(), 41)));
        m_driverRegistryModeLabel->setToolTip(QStringLiteral("驱动可用时启用增强的注册表浏览与编辑。"));
        return;
    }

    m_driverRegistryModeLabel->setText(QStringLiteral("R0读写: 关闭"));
    // 关闭态没有语义色可言，边框/文字一律走动态 palette，胶囊本身不再自带底色。
    m_driverRegistryModeLabel->setStyleSheet(QStringLiteral(
        "QLabel{border:1px solid %1;border-radius:3px;"
        "background:transparent;/* %3 */color:%2;padding:2px 6px;font-weight:600;}"
    ).arg(KswordTheme::BorderHex())
     .arg(KswordTheme::TextSecondaryHex())
     .arg(KswordTheme::RgbaColorName(KswordTheme::SurfaceAltColor(), 36)));
    m_driverRegistryModeLabel->setToolTip(QStringLiteral("驱动不可用，当前使用标准注册表模式。"));
}

bool RegistryDock::shouldUseRegistryR0() const
{
    // 作用：通过 ArkDriverClient 打开设备来判断驱动是否在线。
    // 返回：true 表示后续注册表操作应走 R0；false 表示使用 Win32 回退。
    const ksword::ark::DriverClient driverClient;
    ksword::ark::DriverHandle handle = driverClient.open(GENERIC_READ | GENERIC_WRITE);
    return handle.isValid();
}

bool RegistryDock::readRegistryValueAny(
    const QString& keyPath,
    const QString& valueName,
    DWORD* typeOut,
    QByteArray* dataOut,
    QString* errorTextOut)
{
    // 作用：封装注册表值读取策略，R0 在线时不再通过 Win32 读取。
    // 返回：读取成功返回 true，并填写 typeOut/dataOut。
    if (typeOut == nullptr || dataOut == nullptr)
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("读取参数无效。");
        return false;
    }
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(keyPath);
        if (kernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryReadResult readResult = driverClient.readRegistryValue(
            kernelPath.toStdWString(),
            trimDefaultValueName(valueName).toStdWString(),
            KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);
        if (readResult.io.ok && readResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS)
        {
            *typeOut = static_cast<DWORD>(readResult.valueType);
            *dataOut = registryDataToByteArray(readResult.data);
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryReadFailureText(QStringLiteral("R0读取注册表值"), readResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }
    return readRegistryValueRaw(root, subPath, valueName, typeOut, dataOut, errorTextOut);
}

bool RegistryDock::writeRegistryValueAny(
    const QString& keyPath,
    const QString& valueName,
    DWORD valueType,
    const QByteArray& rawData,
    QString* errorTextOut)
{
    // 作用：封装注册表值写入策略，R0 在线时全部通过驱动执行。
    // 返回：写入成功返回 true。
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(keyPath);
        if (kernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryOperationResult operationResult = driverClient.setRegistryValue(
            kernelPath.toStdWString(),
            trimDefaultValueName(valueName).toStdWString(),
            static_cast<std::uint32_t>(valueType),
            byteArrayToRegistryData(rawData));
        if (registryOperationSucceeded(operationResult))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0写入注册表值"), operationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }
    return writeRegistryValue(root, subPath, valueName, valueType, rawData, errorTextOut);
}

bool RegistryDock::createRegistryKeyAny(const QString& fullKeyPath, QString* errorTextOut)
{
    // 作用：创建注册表键，R0 在线时直接传完整内核键路径给驱动。
    // 返回：创建成功或键已存在时返回 true。
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(fullKeyPath);
        if (kernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("目标路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryOperationResult operationResult =
            driverClient.createRegistryKey(kernelPath.toStdWString());
        if (registryOperationSucceeded(operationResult) ||
            (operationResult.io.ok && operationResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0创建注册表键"), operationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(fullKeyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(fullKeyPath);
        return false;
    }

    HKEY created = nullptr;
    const LONG createResult = ::RegCreateKeyExW(
        root,
        subPath.isEmpty() ? L"" : reinterpret_cast<const wchar_t*>(subPath.utf16()),
        0,
        nullptr,
        REG_OPTION_NON_VOLATILE,
        KEY_READ | KEY_WRITE,
        nullptr,
        &created,
        nullptr);
    if (created != nullptr)
    {
        ::RegCloseKey(created);
    }
    if (createResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(createResult);
        return false;
    }
    return true;
}

bool RegistryDock::deleteRegistryKeyByR0Recursive(
    const QString& kernelKeyPath,
    QString* errorTextOut) const
{
    // 作用：仅依赖 R0 枚举和删除，递归清空并删除指定键。
    // 返回：整棵子树删除成功返回 true。
    if (errorTextOut != nullptr) errorTextOut->clear();
    if (kernelKeyPath.trimmed().isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("内核注册表路径为空。");
        return false;
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::RegistryEnumResult enumResult = driverClient.enumerateRegistryKey(
        kernelKeyPath.toStdWString(),
        KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
    if (!registryEnumUsable(enumResult))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryEnumFailureText(QStringLiteral("R0枚举待删除注册表键"), enumResult);
        }
        return false;
    }

    for (const ksword::ark::RegistrySubKeyEntry& childEntry : enumResult.subKeys)
    {
        const QString childName = QString::fromStdWString(childEntry.name);
        if (childName.trimmed().isEmpty())
        {
            continue;
        }
        const QString childKernelPath = kernelKeyPath + QStringLiteral("\\") + childName;
        if (!deleteRegistryKeyByR0Recursive(childKernelPath, errorTextOut))
        {
            return false;
        }
    }

    for (const ksword::ark::RegistryValueEntry& valueEntry : enumResult.values)
    {
        const QString valueName = QString::fromStdWString(valueEntry.name);
        const ksword::ark::RegistryOperationResult deleteValueResult = driverClient.deleteRegistryValue(
            kernelKeyPath.toStdWString(),
            trimDefaultValueName(valueName).toStdWString());
        if (!registryOperationSucceeded(deleteValueResult) &&
            !(deleteValueResult.io.ok && deleteValueResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = registryOperationFailureText(QStringLiteral("R0删除注册表值"), deleteValueResult);
            }
            return false;
        }
    }

    const ksword::ark::RegistryOperationResult deleteKeyResult =
        driverClient.deleteRegistryKey(kernelKeyPath.toStdWString());
    if (registryOperationSucceeded(deleteKeyResult) ||
        (deleteKeyResult.io.ok && deleteKeyResult.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_NOT_FOUND))
    {
        return true;
    }

    if (errorTextOut != nullptr)
    {
        *errorTextOut = registryOperationFailureText(QStringLiteral("R0删除注册表键"), deleteKeyResult);
    }
    return false;
}

bool RegistryDock::deleteRegistryKeyAny(const QString& fullKeyPath, QString* errorTextOut)
{
    // 作用：删除注册表键树，R0 在线时不调用 RegDeleteTreeW。
    // 返回：删除成功返回 true。
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(fullKeyPath);
        if (kernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("目标路径无法转换为内核路径。");
            return false;
        }
        return deleteRegistryKeyByR0Recursive(kernelPath, errorTextOut);
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(fullKeyPath, &root, &subPath) || subPath.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表键路径无效或指向根键。");
        return false;
    }

    const LONG deleteResult = ::RegDeleteTreeW(
        root,
        reinterpret_cast<const wchar_t*>(subPath.utf16()));
    if (deleteResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(deleteResult);
        return false;
    }
    return true;
}

bool RegistryDock::deleteRegistryValueAny(
    const QString& keyPath,
    const QString& valueName,
    QString* errorTextOut)
{
    // 作用：删除注册表值，R0 在线时通过驱动删除默认值或命名值。
    // 返回：删除成功返回 true。
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(keyPath);
        if (kernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryOperationResult operationResult = driverClient.deleteRegistryValue(
            kernelPath.toStdWString(),
            trimDefaultValueName(valueName).toStdWString());
        if (registryOperationSucceeded(operationResult))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0删除注册表值"), operationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(openResult);
        return false;
    }

    const QString realName = trimDefaultValueName(valueName);
    LONG deleteResult = ::RegDeleteValueW(key, realName.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(realName.utf16()));
    ::RegCloseKey(key);
    if (deleteResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(deleteResult);
        return false;
    }
    return true;
}

bool RegistryDock::renameRegistryValueAny(
    const QString& keyPath,
    const QString& oldValueName,
    const QString& newValueName,
    QString* errorTextOut)
{
    // 作用：重命名注册表值，R0 在线时由驱动完成读写删除序列。
    // 返回：重命名成功返回 true。
    if (errorTextOut != nullptr) errorTextOut->clear();

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(keyPath);
        if (kernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryOperationResult operationResult = driverClient.renameRegistryValue(
            kernelPath.toStdWString(),
            oldValueName.toStdWString(),
            newValueName.toStdWString());
        if (registryOperationSucceeded(operationResult))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0重命名注册表值"), operationResult);
        }
        return false;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(keyPath, &root, &subPath))
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("注册表路径无效：%1").arg(keyPath);
        return false;
    }

    DWORD type = REG_NONE;
    QByteArray data;
    if (!readRegistryValueRaw(root, subPath, oldValueName, &type, &data, errorTextOut))
    {
        return false;
    }
    if (!writeRegistryValue(root, subPath, newValueName, type, data, errorTextOut))
    {
        return false;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_SET_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(openResult);
        return false;
    }
    const LONG deleteResult = ::RegDeleteValueW(key, reinterpret_cast<const wchar_t*>(oldValueName.utf16()));
    ::RegCloseKey(key);
    if (deleteResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(deleteResult);
        return false;
    }
    return true;
}

bool RegistryDock::renameRegistryKeyAny(
    const QString& fullKeyPath,
    const QString& newKeyName,
    QString* newFullKeyPathOut,
    QString* errorTextOut)
{
    // 作用：重命名当前键；R0 在线时直接调用驱动的 ZwRenameKey 封装。
    // 返回：重命名成功返回 true，并输出新的 UI 路径。
    if (errorTextOut != nullptr) errorTextOut->clear();
    if (newFullKeyPathOut != nullptr) newFullKeyPathOut->clear();

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(fullKeyPath, &root, &subPath) || subPath.isEmpty())
    {
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("根键不可重命名或路径无效。");
        return false;
    }

    const int slashPos = subPath.lastIndexOf('\\');
    const QString parentPath = slashPos < 0 ? QString() : subPath.left(slashPos);
    QString newPath = rootKeyToText(root);
    if (!parentPath.isEmpty())
    {
        newPath += QStringLiteral("\\") + parentPath;
    }
    newPath += QStringLiteral("\\") + newKeyName;

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(fullKeyPath);
        if (kernelPath.isEmpty())
        {
            if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("当前注册表路径无法转换为内核路径。");
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryOperationResult operationResult = driverClient.renameRegistryKey(
            kernelPath.toStdWString(),
            newKeyName.toStdWString());
        if (registryOperationSucceeded(operationResult))
        {
            if (newFullKeyPathOut != nullptr) *newFullKeyPathOut = newPath;
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = registryOperationFailureText(QStringLiteral("R0重命名注册表键"), operationResult);
        }
        return false;
    }

    HKEY parentKey = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, parentPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(parentPath.utf16()), 0, KEY_WRITE, &parentKey);
    if (openResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(openResult);
        return false;
    }

    using RegRenameKeyFunc = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR);
    const HMODULE advapiModule = ::GetModuleHandleW(L"Advapi32.dll");
    RegRenameKeyFunc renameKey = advapiModule != nullptr
        ? reinterpret_cast<RegRenameKeyFunc>(::GetProcAddress(advapiModule, "RegRenameKey"))
        : nullptr;
    if (renameKey == nullptr)
    {
        ::RegCloseKey(parentKey);
        if (errorTextOut != nullptr) *errorTextOut = QStringLiteral("系统不支持 RegRenameKey。");
        return false;
    }

    const QString oldKeyName = slashPos < 0 ? subPath : subPath.mid(slashPos + 1);
    LONG renameResult = renameKey(parentKey, reinterpret_cast<const wchar_t*>(oldKeyName.utf16()), reinterpret_cast<const wchar_t*>(newKeyName.utf16()));
    ::RegCloseKey(parentKey);
    if (renameResult != ERROR_SUCCESS)
    {
        if (errorTextOut != nullptr) *errorTextOut = winErrorText(renameResult);
        return false;
    }
    if (newFullKeyPathOut != nullptr) *newFullKeyPathOut = newPath;
    return true;
}

void RegistryDock::updateStatusBar(const QString& message)
{
    m_pathStatusLabel->setText(QStringLiteral("路径: %1").arg(m_currentPath));
    m_summaryStatusLabel->setText(message);
}

void RegistryDock::navigateToPath(const QString& path, bool recordHistory)
{
    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 导航请求, input="
            << path.toStdString()
            << ", recordHistory="
            << (recordHistory ? "true" : "false")
            << eol;
    }

    const QString normalized = normalizeRegistryPath(path);
    if (normalized.isEmpty())
    {
        kLogEvent event;
        warn << event << "[RegistryDock] 导航失败：无效路径, input=" << path.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("注册表"), QStringLiteral("无效路径：%1").arg(path));
        return;
    }

    m_currentPath = normalized;
    m_pathEdit->setText(normalized);

    if (recordHistory)
    {
        if (m_navigationIndex + 1 < static_cast<int>(m_navigationHistory.size()))
        {
            m_navigationHistory.erase(m_navigationHistory.begin() + m_navigationIndex + 1, m_navigationHistory.end());
        }
        if (m_navigationHistory.empty() || m_navigationHistory.back().compare(normalized, Qt::CaseInsensitive) != 0)
        {
            m_navigationHistory.push_back(normalized);
        }
        m_navigationIndex = static_cast<int>(m_navigationHistory.size()) - 1;
    }

    m_backButton->setEnabled(m_navigationIndex > 0);
    m_forwardButton->setEnabled(m_navigationIndex >= 0 && (m_navigationIndex + 1) < static_cast<int>(m_navigationHistory.size()));
    refreshRegistryDriverModeIndicator();

    selectTreeItemByPath(normalized);
    refreshCurrentKey(true);

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 导航成功, normalized="
            << normalized.toStdString()
            << ", historySize="
            << m_navigationHistory.size()
            << ", historyIndex="
            << m_navigationIndex
            << eol;
    }
}

void RegistryDock::selectTreeItemByPath(const QString& path)
{
    const QString normalized = normalizeRegistryPath(path);
    if (normalized.isEmpty()) return;

    const QStringList segments = normalized.split('\\', Qt::SkipEmptyParts);
    if (segments.isEmpty()) return;

    // 记录待定位路径：子键加载已改为异步，本次调用只能走到“已加载”的最深一级，
    // 剩余层级由后台枚举落地后的回调重新进入本函数继续下探。
    m_keyTree->setProperty(kPendingTreeSelectionProperty, normalized);

    QTreeWidgetItem* current = nullptr;
    for (int i = 0; i < m_keyTree->topLevelItemCount(); ++i)
    {
        QTreeWidgetItem* item = m_keyTree->topLevelItem(i);
        if (item->text(0).compare(segments.first(), Qt::CaseInsensitive) == 0)
        {
            current = item;
            break;
        }
    }
    if (current == nullptr)
    {
        m_keyTree->setProperty(kPendingTreeSelectionProperty, QString());
        return;
    }

    bool waitingForSubKeyLoad = false;
    for (int i = 1; i < segments.size(); ++i)
    {
        if (!current->data(0, kRoleLoaded).toBool())
        {
            // 该级还没有子键数据：投递一次后台枚举，本轮先停在这里。
            ensureTreeItemLoaded(current);
            waitingForSubKeyLoad = current->data(0, kRoleLoadToken).toULongLong() != 0;
            break;
        }

        QTreeWidgetItem* next = nullptr;
        for (int childIndex = 0; childIndex < current->childCount(); ++childIndex)
        {
            QTreeWidgetItem* child = current->child(childIndex);
            if (child == nullptr || child->data(0, kRolePlaceholder).toBool()) continue;
            if (child->text(0).compare(segments.at(i), Qt::CaseInsensitive) == 0)
            {
                next = child;
                break;
            }
        }
        if (next == nullptr) break;
        current = next;
    }

    if (!waitingForSubKeyLoad)
    {
        m_keyTree->setProperty(kPendingTreeSelectionProperty, QString());
    }

    QSignalBlocker blocker(m_keyTree);
    m_keyTree->setCurrentItem(current);
    m_keyTree->scrollToItem(current);
}

void RegistryDock::ensureTreeItemLoaded(QTreeWidgetItem* item)
{
    if (item == nullptr || item->data(0, kRolePlaceholder).toBool()) return;
    if (item->data(0, kRoleLoaded).toBool()) return;
    // 已有一次后台枚举在途：不重复投递，等它落地即可。
    if (item->data(0, kRoleLoadToken).toULongLong() != 0) return;

    const QString itemPath = item->data(0, kRolePath).toString();
    {
        kLogEvent event;
        dbg << event << "[RegistryDock] 展开节点并加载子键, path=" << itemPath.toStdString() << eol;
    }

    // 枚举入参在 UI 线程算好后按值带进后台线程：后台只做纯数据采集，不碰任何控件。
    const bool useRegistryR0 = shouldUseRegistryR0();
    QString kernelPath;
    HKEY rootKey = nullptr;
    QString subPath;
    bool enumerationSourceReady = false;
    if (useRegistryR0)
    {
        kernelPath = buildKernelRegistryPath(itemPath);
        enumerationSourceReady = !kernelPath.isEmpty();
    }
    else
    {
        enumerationSourceReady = parseRegistryPath(itemPath, &rootKey, &subPath);
    }

    if (!enumerationSourceReady)
    {
        qDeleteAll(item->takeChildren());
        item->setData(0, kRoleLoaded, true);
        item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
        return;
    }

    // 后台枚举期间保留一个占位子项，维持展开箭头并给出“正在加载”的视觉反馈。
    qDeleteAll(item->takeChildren());
    QTreeWidgetItem* loadingPlaceholder = new QTreeWidgetItem(item);
    loadingPlaceholder->setText(0, QStringLiteral("..."));
    loadingPlaceholder->setData(0, kRolePlaceholder, true);
    // 占位项不可选中：结果落地时它会被删除，避免删除当前项引发多余的导航。
    loadingPlaceholder->setFlags(Qt::ItemIsEnabled);

    const quint64 requestToken = g_nextSubKeyLoadToken.fetch_add(1, std::memory_order_relaxed);
    item->setData(0, kRoleLoadToken, static_cast<qulonglong>(requestToken));
    item->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);

    const QPointer<RegistryDock> guardedSelf(this);
    const QPointer<QTreeWidget> guardedTree(m_keyTree);
    QThreadPool::globalInstance()->start(
        [guardedSelf, guardedTree, requestToken, itemPath, kernelPath, subPath, rootKey, useRegistryR0]()
        {
            const SubKeyEnumOutcome collected = useRegistryR0
                ? collectSubKeyNamesByR0(kernelPath)
                : collectSubKeyNamesByWin32(rootKey, subPath);

            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr) { return; }

            QMetaObject::invokeMethod(appInstance,
                [guardedSelf, guardedTree, requestToken, itemPath, collected]()
                {
                    if (guardedTree.isNull()) { return; }

                    // 用路径而不是裸指针重新定位：节点可能已在等待期间被销毁或重建。
                    QTreeWidgetItem* targetItem = resolveTreeItemByPath(guardedTree.data(), itemPath);
                    if (targetItem == nullptr) { return; }
                    if (targetItem->data(0, kRoleLoadToken).toULongLong() != requestToken) { return; }

                    qDeleteAll(targetItem->takeChildren());

                    if (!collected.enumerationOk)
                    {
                        {
                            kLogEvent event;
                            warn << event
                                << "[RegistryDock] 加载子键失败, path="
                                << itemPath.toStdString()
                                << ", error="
                                << (collected.failureText.isEmpty()
                                    ? winErrorText(collected.win32ErrorCode).toStdString()
                                    : collected.failureText.toStdString())
                                << eol;
                        }
                        targetItem->setData(0, kRoleLoadToken, static_cast<qulonglong>(0));
                        targetItem->setData(0, kRoleLoaded, true);
                        targetItem->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicatorWhenChildless);
                        return;
                    }

                    const int loadedChildCount = static_cast<int>(collected.subKeyNames.size());
                    const std::shared_ptr<const QStringList> sharedSubKeyNames =
                        std::make_shared<const QStringList>(collected.subKeyNames);
                    const std::function<void()> onSubKeysApplied =
                        [guardedSelf, guardedTree, itemPath, loadedChildCount]()
                        {
                            {
                                kLogEvent event;
                                info << event
                                    << "[RegistryDock] 子键加载完成, path="
                                    << itemPath.toStdString()
                                    << ", childCount="
                                    << loadedChildCount
                                    << eol;
                            }

                            // 路径定位是逐级异步推进的：本级子键就位后继续下探待定位路径。
                            if (guardedSelf.isNull() || guardedTree.isNull()) { return; }
                            const QString pendingSelectionPath =
                                guardedTree->property(kPendingTreeSelectionProperty).toString();
                            if (pendingSelectionPath.isEmpty()) { return; }
                            guardedSelf->selectTreeItemByPath(pendingSelectionPath);
                        };

                    appendSubKeyItemsBatched(
                        guardedTree,
                        itemPath,
                        requestToken,
                        sharedSubKeyNames,
                        0,
                        onSubKeysApplied);
                });
        });
}

void RegistryDock::refreshCurrentKey(bool)
{
    kLogEvent event;
    info << event << "[RegistryDock] 刷新当前键, path=" << m_currentPath.toStdString() << eol;
    refreshRegistryDriverModeIndicator();
    refreshValueTable();
}

void RegistryDock::refreshValueTable()
{
    {
        kLogEvent event;
        dbg << event << "[RegistryDock] 开始刷新值列表, path=" << m_currentPath.toStdString() << eol;
    }

    m_valueTable->setRowCount(0);

    if (shouldUseRegistryR0())
    {
        const QString kernelPath = buildKernelRegistryPath(m_currentPath);
        if (kernelPath.isEmpty())
        {
            kLogEvent event;
            warn << event << "[RegistryDock] R0刷新失败：内核路径无效, path=" << m_currentPath.toStdString() << eol;
            updateStatusBar(QStringLiteral("状态: 内核路径无效"));
            return;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::RegistryEnumResult enumResult = driverClient.enumerateRegistryKey(
            kernelPath.toStdWString(),
            KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
        if (!registryEnumUsable(enumResult))
        {
            const QString errorText = registryEnumFailureText(QStringLiteral("R0刷新值列表"), enumResult);
            kLogEvent event;
            warn << event << "[RegistryDock] R0刷新值列表失败, path=" << m_currentPath.toStdString() << ", error=" << errorText.toStdString() << eol;
            updateStatusBar(QStringLiteral("状态: R0打开失败 - %1").arg(errorText));
            return;
        }

        for (const ksword::ark::RegistryValueEntry& valueEntry : enumResult.values)
        {
            const QString valueName = QString::fromStdWString(valueEntry.name);
            const QByteArray bytes = registryDataToByteArray(valueEntry.data);
            const int row = m_valueTable->rowCount();
            m_valueTable->insertRow(row);

            QTableWidgetItem* nameItem = new QTableWidgetItem(valueName.isEmpty()
                ? ks::i18n::sourceText(QStringLiteral("(默认)"))
                : valueName);
            nameItem->setData(Qt::UserRole, valueName);
            m_valueTable->setItem(row, 0, nameItem);
            m_valueTable->setItem(row, 1, new QTableWidgetItem(valueTypeToText(static_cast<DWORD>(valueEntry.valueType))));

            QString dataText = formatValueData(static_cast<DWORD>(valueEntry.valueType), bytes);
            if (valueEntry.requiredBytes > valueEntry.dataBytes)
            {
                dataText += QStringLiteral("  <R0预览截断 %1/%2 字节>")
                    .arg(valueEntry.dataBytes)
                    .arg(valueEntry.requiredBytes);
            }
            m_valueTable->setItem(row, 2, new QTableWidgetItem(dataText));
        }

        updateStatusBar(QStringLiteral("状态: R0已加载 %1/%2 个值")
            .arg(enumResult.returnedValueCount)
            .arg(enumResult.valueCount));

        kLogEvent finishEvent;
        info << finishEvent
            << "[RegistryDock] R0值列表刷新完成, path="
            << m_currentPath.toStdString()
            << ", returned="
            << enumResult.returnedValueCount
            << ", total="
            << enumResult.valueCount
            << eol;
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(m_currentPath, &root, &subPath))
    {
        kLogEvent event;
        warn << event << "[RegistryDock] 刷新失败：路径无效, path=" << m_currentPath.toStdString() << eol;
        updateStatusBar(QStringLiteral("状态: 路径无效"));
        return;
    }

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE, &key);
    if (openResult != ERROR_SUCCESS)
    {
        kLogEvent event;
        warn << event
            << "[RegistryDock] 打开键失败, path="
            << m_currentPath.toStdString()
            << ", error="
            << winErrorText(openResult).toStdString()
            << eol;
        updateStatusBar(QStringLiteral("状态: 打开失败 - %1").arg(winErrorText(openResult)));
        return;
    }

    DWORD valueCount = 0;
    DWORD maxNameLength = 0;
    DWORD maxDataLength = 0;
    ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &valueCount, &maxNameLength, &maxDataLength, nullptr, nullptr);

    DWORD defaultType = REG_NONE;
    DWORD defaultSize = 0;
    LONG defaultQuery = ::RegQueryValueExW(key, nullptr, nullptr, &defaultType, nullptr, &defaultSize);
    if (defaultQuery == ERROR_SUCCESS)
    {
        QByteArray defaultData;
        defaultData.resize(static_cast<int>(defaultSize));
        if (defaultSize > 0)
        {
            ::RegQueryValueExW(key, nullptr, nullptr, &defaultType, reinterpret_cast<LPBYTE>(defaultData.data()), &defaultSize);
        }

        m_valueTable->insertRow(0);
        QTableWidgetItem* nameItem = new QTableWidgetItem(
            ks::i18n::sourceText(QStringLiteral("(默认)")));
        nameItem->setData(Qt::UserRole, QString());
        m_valueTable->setItem(0, 0, nameItem);
        m_valueTable->setItem(0, 1, new QTableWidgetItem(valueTypeToText(defaultType)));
        m_valueTable->setItem(0, 2, new QTableWidgetItem(formatValueData(defaultType, defaultData)));
    }

    std::vector<wchar_t> nameBuffer(static_cast<std::size_t>(maxNameLength + 4), L'\0');
    std::vector<unsigned char> dataBuffer(static_cast<std::size_t>(maxDataLength + 8), 0);

    for (DWORD index = 0; index < valueCount; ++index)
    {
        DWORD nameLength = static_cast<DWORD>(nameBuffer.size() - 1);
        DWORD dataLength = static_cast<DWORD>(dataBuffer.size());
        DWORD type = REG_NONE;
        LONG enumResult = ::RegEnumValueW(key, index, nameBuffer.data(), &nameLength, nullptr, &type, dataBuffer.data(), &dataLength);
        if (enumResult != ERROR_SUCCESS) continue;

        const QString valueName = QString::fromWCharArray(nameBuffer.data(), static_cast<int>(nameLength));
        if (valueName.isEmpty()) continue;

        const QByteArray bytes(reinterpret_cast<const char*>(dataBuffer.data()), static_cast<int>(dataLength));
        const int row = m_valueTable->rowCount();
        m_valueTable->insertRow(row);
        QTableWidgetItem* nameItem = new QTableWidgetItem(valueName);
        nameItem->setData(Qt::UserRole, valueName);
        m_valueTable->setItem(row, 0, nameItem);
        m_valueTable->setItem(row, 1, new QTableWidgetItem(valueTypeToText(type)));
        m_valueTable->setItem(row, 2, new QTableWidgetItem(formatValueData(type, bytes)));
    }

    ::RegCloseKey(key);
    updateStatusBar(QStringLiteral("状态: 已加载 %1 个值").arg(m_valueTable->rowCount()));

    kLogEvent finishEvent;
    info << finishEvent
        << "[RegistryDock] 值列表刷新完成, path="
        << m_currentPath.toStdString()
        << ", valueCount="
        << m_valueTable->rowCount()
        << eol;
}
void RegistryDock::showTreeContextMenu(const QPoint& pos)
{
    QTreeWidgetItem* item = m_keyTree->itemAt(pos);
    if (item != nullptr && !item->data(0, kRolePlaceholder).toBool()) m_keyTree->setCurrentItem(item);

    QMenu menu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* newKeyAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("新建子键"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    menu.addSeparator();
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* r0ReadDefaultAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("R0读取默认值"));
    QAction* refreshAction = menu.addAction(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新"));
    menu.addSeparator();
    QAction* exportAction = menu.addAction(QIcon(":/Icon/log_export.svg"), QStringLiteral("导出 .reg"));
    QAction* importAction = menu.addAction(QIcon(":/Icon/reg_import.svg"), QStringLiteral("导入 .reg"));

    QAction* action = menu.exec(m_keyTree->viewport()->mapToGlobal(pos));
    if (action == nullptr) return;

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 树右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << m_currentPath.toStdString()
            << eol;
    }
    if (action == newKeyAction) createSubKey();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
    else if (action == copyKernelPathAction) copyCurrentKernelPathToClipboard();
    else if (action == r0ReadDefaultAction) readDefaultValueByR0();
    else if (action == refreshAction) refreshCurrentKey(true);
    else if (action == exportAction) exportCurrentKeyAsync();
    else if (action == importAction) importRegFileAsync();
}

void RegistryDock::showValueContextMenu(const QPoint& pos)
{
    const QModelIndex hit = m_valueTable->indexAt(pos);
    if (hit.isValid()) m_valueTable->setCurrentCell(hit.row(), hit.column());

    QMenu menu(this);
    // 显式填充菜单背景，避免浅色模式下继承透明样式出现黑底。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* editAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("修改"));
    QAction* newAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("新建值"));
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除"));
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* r0ReadAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("R0读取该值"));

    QAction* action = menu.exec(m_valueTable->viewport()->mapToGlobal(pos));
    if (action == nullptr) return;

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 值右键动作, action="
            << action->text().toStdString()
            << ", currentPath="
            << m_currentPath.toStdString()
            << eol;
    }
    if (action == editAction) editSelectedValue();
    else if (action == newAction) createValue();
    else if (action == renameAction) renameSelectedObject();
    else if (action == deleteAction) deleteSelectedObject();
    else if (action == copyPathAction) copyCurrentPathToClipboard();
    else if (action == copyKernelPathAction) copySelectedValueKernelPathToClipboard();
    else if (action == r0ReadAction) readSelectedValueByR0();
}

void RegistryDock::createSubKey()
{
    bool ok = false;
    const QString keyName = QInputDialog::getText(this, QStringLiteral("新建子键"), QStringLiteral("请输入子键名称："), QLineEdit::Normal, QStringLiteral("New Key"), &ok).trimmed();
    if (!ok || keyName.isEmpty()) return;

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 新建子键请求, parentPath="
            << m_currentPath.toStdString()
            << ", keyName="
            << keyName.toStdString()
            << eol;
    }

    QString errorText;
    const QString fullKeyPath = m_currentPath + QStringLiteral("\\") + keyName;
    if (!createRegistryKeyAny(fullKeyPath, &errorText))
    {
        // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新建注册表子键"), errorText);
        kLogEvent event;
        warn << event << "[RegistryDock] 新建子键失败, error=" << errorText.toStdString() << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新建子键"), errorText);
        }
        return;
    }

    kLogEvent event;
    info << event << "[RegistryDock] 新建子键成功, fullPath=" << fullKeyPath.toStdString() << eol;
    navigateToPath(fullKeyPath, true);
}

void RegistryDock::createValue()
{
    // 统一使用详细对话框输入：值名称、值类型、值数据一次性完成。
    NewRegistryValueDialog dialog(this);
    if (dialog.exec() != QDialog::Accepted)
    {
        kLogEvent event;
        dbg << event
            << "[RegistryDock] 新建值取消：用户关闭输入对话框。"
            << eol;
        return;
    }

    const NewRegistryValueInput inputValue = dialog.buildOutput();
    const QString valueName = inputValue.valueName;
    const DWORD type = inputValue.valueType;
    const QByteArray data = inputValue.valueData;

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 新建值请求, path="
            << m_currentPath.toStdString()
            << ", valueName="
            << valueName.toStdString()
            << ", type="
            << valueTypeToText(type).toStdString()
            << ", dataSize="
            << data.size()
            << eol;
    }

    QString errorText;
    if (!writeRegistryValueAny(m_currentPath, valueName, type, data, &errorText))
    {
        // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新建注册表值"), errorText);
        kLogEvent event;
        warn << event << "[RegistryDock] 新建值失败, path=" << m_currentPath.toStdString() << ", error=" << errorText.toStdString() << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新建值"), errorText);
        }
        return;
    }

    kLogEvent event;
    info << event << "[RegistryDock] 新建值成功, path=" << m_currentPath.toStdString() << ", valueName=" << valueName.toStdString() << eol;
    refreshValueTable();
}

void RegistryDock::renameSelectedObject()
{
    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 重命名请求, path="
            << m_currentPath.toStdString()
            << ", valueTableFocus="
            << (m_valueTable->hasFocus() ? "true" : "false")
            << eol;
    }

    if (m_valueTable->hasFocus() && m_valueTable->currentRow() >= 0)
    {
        const int row = m_valueTable->currentRow();
        QTableWidgetItem* nameItem = m_valueTable->item(row, 0);
        if (nameItem == nullptr) return;

        const QString oldName = nameItem->data(Qt::UserRole).toString();
        if (oldName.isEmpty())
        {
            QMessageBox::information(this, QStringLiteral("重命名"), QStringLiteral("默认值不支持重命名。"));
            return;
        }

        bool ok = false;
        const QString newName = QInputDialog::getText(this, QStringLiteral("重命名值"), QStringLiteral("新名称："), QLineEdit::Normal, oldName, &ok).trimmed();
        if (!ok || newName.isEmpty() || newName.compare(oldName, Qt::CaseInsensitive) == 0) return;

        QString errorText;
        if (!renameRegistryValueAny(m_currentPath, oldName, newName, &errorText))
        {
            // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
            const bool privilegePromptHandled =
                ks::ui::promptForPrivilegeFailure(this, QStringLiteral("重命名注册表值"), errorText);
            kLogEvent event;
            warn << event << "[RegistryDock] 重命名值失败, error=" << errorText.toStdString() << eol;
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(this, QStringLiteral("重命名值"), errorText);
            }
            return;
        }

        kLogEvent event;
        info << event
            << "[RegistryDock] 重命名值成功, oldName="
            << oldName.toStdString()
            << ", newName="
            << newName.toStdString()
            << eol;

        refreshValueTable();
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(m_currentPath, &root, &subPath)) return;
    if (subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("重命名键"), QStringLiteral("根键不可重命名。"));
        return;
    }

    const int slashPos = subPath.lastIndexOf('\\');
    const QString parentPath = slashPos < 0 ? QString() : subPath.left(slashPos);
    const QString oldKeyName = slashPos < 0 ? subPath : subPath.mid(slashPos + 1);

    bool ok = false;
    const QString newKeyName = QInputDialog::getText(this, QStringLiteral("重命名键"), QStringLiteral("新键名："), QLineEdit::Normal, oldKeyName, &ok).trimmed();
    if (!ok || newKeyName.isEmpty() || newKeyName.compare(oldKeyName, Qt::CaseInsensitive) == 0) return;

    QString newPath;
    QString errorText;
    if (!renameRegistryKeyAny(m_currentPath, newKeyName, &newPath, &errorText))
    {
        // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("重命名注册表键"), errorText);
        kLogEvent event;
        warn << event << "[RegistryDock] 重命名键失败, error=" << errorText.toStdString() << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("重命名键"), errorText);
        }
        return;
    }

    kLogEvent event;
    info << event
        << "[RegistryDock] 重命名键成功, oldKey="
        << oldKeyName.toStdString()
        << ", newKey="
        << newKeyName.toStdString()
        << ", newPath="
        << newPath.toStdString()
        << eol;
    navigateToPath(newPath, true);
}

void RegistryDock::deleteSelectedObject()
{
    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 删除请求, path="
            << m_currentPath.toStdString()
            << ", valueTableFocus="
            << (m_valueTable->hasFocus() ? "true" : "false")
            << eol;
    }

    if (m_valueTable->hasFocus() && m_valueTable->currentRow() >= 0)
    {
        QTableWidgetItem* nameItem = m_valueTable->item(m_valueTable->currentRow(), 0);
        if (nameItem == nullptr) return;
        const QString valueName = nameItem->data(Qt::UserRole).toString();

        QMessageBox::StandardButton choice = QMessageBox::question(
            this,
            QStringLiteral("删除值"),
            QStringLiteral("确定删除值“%1”吗？").arg(valueName.isEmpty() ? QStringLiteral("(默认)") : valueName),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (choice != QMessageBox::Yes) return;

        QString errorText;
        if (!deleteRegistryValueAny(m_currentPath, valueName, &errorText))
        {
            // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
            const bool privilegePromptHandled =
                ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表值"), errorText);
            kLogEvent event;
            warn << event << "[RegistryDock] 删除值失败, error=" << errorText.toStdString() << eol;
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(this, QStringLiteral("删除值"), errorText);
            }
            return;
        }

        kLogEvent event;
        info << event << "[RegistryDock] 删除值成功, valueName=" << valueName.toStdString() << eol;
        refreshValueTable();
        return;
    }

    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(m_currentPath, &root, &subPath)) return;
    if (subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("删除键"), QStringLiteral("根键不可删除。"));
        return;
    }

    QMessageBox::StandardButton choice = QMessageBox::question(
        this,
        QStringLiteral("删除键"),
        QStringLiteral("确定删除键“%1”及其子项吗？").arg(m_currentPath),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes) return;

    const int slashPos = subPath.lastIndexOf('\\');
    const QString parentPath = slashPos < 0 ? QString() : subPath.left(slashPos);
    const QString keyName = slashPos < 0 ? subPath : subPath.mid(slashPos + 1);

    QString errorText;
    if (!deleteRegistryKeyAny(m_currentPath, &errorText))
    {
        // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表键"), errorText);
        kLogEvent event;
        warn << event << "[RegistryDock] 删除键失败, error=" << errorText.toStdString() << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("删除键"), errorText);
        }
        return;
    }

    kLogEvent event;
    info << event << "[RegistryDock] 删除键成功, keyName=" << keyName.toStdString() << eol;

    QString parentFullPath = rootKeyToText(root);
    if (!parentPath.isEmpty()) parentFullPath += QStringLiteral("\\") + parentPath;
    navigateToPath(parentFullPath, true);
}

void RegistryDock::deleteSearchResultValue(const QString& keyPath, const QString& rawValueName)
{
    // 搜索结果处置不能借用当前树选择：搜索期间用户可能已导航到另一把键。
    const QString normalizedKeyPath = keyPath.trimmed();
    if (normalizedKeyPath.isEmpty())
    {
        return;
    }

    const QString displayValueName = rawValueName.isEmpty() ? QStringLiteral("(默认)") : rawValueName;
    const QMessageBox::StandardButton choice = QMessageBox::question(
        this,
        QStringLiteral("删除值"),
        QStringLiteral("确定删除注册表值“%1”吗？\n\n键路径：%2")
            .arg(displayValueName, normalizedKeyPath),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (!deleteRegistryValueAny(normalizedKeyPath, rawValueName, &errorText))
    {
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表值"), errorText);
        kLogEvent event;
        warn << event
            << "[RegistryDock] 搜索结果删除值失败, keyPath="
            << normalizedKeyPath.toStdString()
            << ", valueName="
            << rawValueName.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("删除值"), errorText);
        }
        return;
    }

    kLogEvent event;
    info << event
        << "[RegistryDock] 搜索结果删除值成功, keyPath="
        << normalizedKeyPath.toStdString()
        << ", valueName="
        << rawValueName.toStdString()
        << eol;

    // 删除成功后仅移除同一精确值命中；同一个键中的其它搜索证据仍有效。
    if (m_searchResultTable != nullptr)
    {
        for (int row = m_searchResultTable->rowCount() - 1; row >= 0; --row)
        {
            const QTableWidgetItem* pathItem = m_searchResultTable->item(row, 0);
            const QTableWidgetItem* valueNameItem = m_searchResultTable->item(row, 1);
            if (pathItem == nullptr || valueNameItem == nullptr
                || pathItem->data(kSearchResultRoleTargetKind).toInt() != kSearchResultTargetValue)
            {
                continue;
            }
            if (pathItem->text().compare(normalizedKeyPath, Qt::CaseInsensitive) == 0
                && valueNameItem->data(kSearchResultRoleRawValueName).toString() == rawValueName)
            {
                m_searchResultTable->removeRow(row);
            }
        }
    }
    refreshValueTable();
}

void RegistryDock::deleteSearchResultKey(const QString& keyPath)
{
    // 搜索结果处置不能借用当前树选择：搜索期间用户可能已导航到另一把键。
    const QString normalizedKeyPath = keyPath.trimmed();
    HKEY root = nullptr;
    QString subPath;
    if (!parseRegistryPath(normalizedKeyPath, &root, &subPath) || subPath.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("删除键"), QStringLiteral("根键不可删除。"));
        return;
    }

    const QMessageBox::StandardButton choice = QMessageBox::question(
        this,
        QStringLiteral("删除键"),
        QStringLiteral("确定删除注册表键“%1”及其所有子项吗？").arg(normalizedKeyPath),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (choice != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (!deleteRegistryKeyAny(normalizedKeyPath, &errorText))
    {
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("删除注册表键"), errorText);
        kLogEvent event;
        warn << event
            << "[RegistryDock] 搜索结果删除键失败, keyPath="
            << normalizedKeyPath.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("删除键"), errorText);
        }
        return;
    }

    kLogEvent event;
    info << event
        << "[RegistryDock] 搜索结果删除键成功, keyPath="
        << normalizedKeyPath.toStdString()
        << eol;

    const QString targetPrefix = normalizedKeyPath + QStringLiteral("\\");
    if (m_searchResultTable != nullptr)
    {
        // 键删除会连带删除所有子键及其值，不能保留这些过期审计行。
        for (int row = m_searchResultTable->rowCount() - 1; row >= 0; --row)
        {
            const QTableWidgetItem* pathItem = m_searchResultTable->item(row, 0);
            if (pathItem == nullptr)
            {
                continue;
            }
            const QString resultKeyPath = pathItem->text();
            if (resultKeyPath.compare(normalizedKeyPath, Qt::CaseInsensitive) == 0
                || resultKeyPath.startsWith(targetPrefix, Qt::CaseInsensitive))
            {
                m_searchResultTable->removeRow(row);
            }
        }
    }

    const bool currentPathWasDeleted = m_currentPath.compare(normalizedKeyPath, Qt::CaseInsensitive) == 0
        || m_currentPath.startsWith(targetPrefix, Qt::CaseInsensitive);
    if (currentPathWasDeleted)
    {
        const int slashPos = subPath.lastIndexOf('\\');
        const QString parentSubPath = slashPos < 0 ? QString() : subPath.left(slashPos);
        QString parentFullPath = rootKeyToText(root);
        if (!parentSubPath.isEmpty())
        {
            parentFullPath += QStringLiteral("\\") + parentSubPath;
        }
        navigateToPath(parentFullPath, true);
    }
    else
    {
        refreshValueTable();
    }
}

void RegistryDock::editSelectedValue()
{
    const int row = m_valueTable->currentRow();
    {
        kLogEvent event;
        info << event << "[RegistryDock] 编辑值请求, path=" << m_currentPath.toStdString() << ", row=" << row << eol;
    }
    if (row < 0) return;
    QTableWidgetItem* nameItem = m_valueTable->item(row, 0);
    if (nameItem == nullptr) return;

    const QString valueName = nameItem->data(Qt::UserRole).toString();

    DWORD type = REG_NONE;
    QByteArray data;
    QString errorText;
    if (!readRegistryValueAny(m_currentPath, valueName, &type, &data, &errorText))
    {
        kLogEvent event;
        warn << event << "[RegistryDock] 编辑值失败：读取原值失败, error=" << errorText.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("编辑值"), errorText);
        return;
    }

    bool ok = false;
    QByteArray outputData = data;

    if (type == REG_DWORD || type == REG_QWORD)
    {
        qulonglong oldValue = 0;
        if (type == REG_DWORD && data.size() >= static_cast<int>(sizeof(DWORD))) oldValue = *reinterpret_cast<const DWORD*>(data.constData());
        if (type == REG_QWORD && data.size() >= static_cast<int>(sizeof(quint64))) oldValue = *reinterpret_cast<const quint64*>(data.constData());

        const QString text = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入新数值："), QLineEdit::Normal, QString::number(oldValue), &ok).trimmed();
        if (!ok) return;

        bool parseOk = false;
        const qulonglong parsed = text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)
            ? text.mid(2).toULongLong(&parseOk, 16)
            : text.toULongLong(&parseOk, 10);
        if (!parseOk)
        {
            QMessageBox::warning(this, QStringLiteral("编辑值"), QStringLiteral("数值格式无效。"));
            return;
        }

        if (type == REG_DWORD)
        {
            const DWORD v = static_cast<DWORD>(parsed);
            outputData = QByteArray(reinterpret_cast<const char*>(&v), sizeof(v));
        }
        else
        {
            const quint64 v = static_cast<quint64>(parsed);
            outputData = QByteArray(reinterpret_cast<const char*>(&v), sizeof(v));
        }
    }
    else if (type == REG_BINARY)
    {
        const QString text = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入十六进制字节："), QLineEdit::Normal, bytesToHex(data, 512), &ok).trimmed();
        if (!ok) return;

        outputData.clear();
        const QStringList parts = text.split(QRegularExpression(QStringLiteral("\\s+")), Qt::SkipEmptyParts);
        for (const QString& part : parts)
        {
            bool parseOk = false;
            const int byteValue = part.toInt(&parseOk, 16);
            if (!parseOk || byteValue < 0 || byteValue > 255)
            {
                QMessageBox::warning(this, QStringLiteral("编辑值"), QStringLiteral("字节无效：%1").arg(part));
                return;
            }
            outputData.push_back(static_cast<char>(byteValue));
        }
    }
    else
    {
        QString text = QInputDialog::getText(this, QStringLiteral("编辑值"), QStringLiteral("输入字符串："), QLineEdit::Normal, formatValueData(type, data), &ok);
        if (!ok) return;
        text.append(QChar::Null);
        outputData = QByteArray(reinterpret_cast<const char*>(text.utf16()), text.size() * sizeof(char16_t));
    }

    if (!writeRegistryValueAny(m_currentPath, valueName, type, outputData, &errorText))
    {
        // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("编辑注册表值"), errorText);
        kLogEvent event;
        warn << event << "[RegistryDock] 编辑值失败：写入失败, error=" << errorText.toStdString() << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("编辑值"), errorText);
        }
        return;
    }

    kLogEvent event;
    info << event
        << "[RegistryDock] 编辑值成功, valueName="
        << valueName.toStdString()
        << ", type="
        << valueTypeToText(type).toStdString()
        << eol;
    refreshValueTable();
}

void RegistryDock::copyCurrentPathToClipboard()
{
    QApplication::clipboard()->setText(m_currentPath);

    kLogEvent event;
    info << event << "[RegistryDock] 复制路径到剪贴板, path=" << m_currentPath.toStdString() << eol;
}

void RegistryDock::copyCurrentKernelPathToClipboard()
{
    const QString kernelPath = buildKernelRegistryPath(m_currentPath);
    if (kernelPath.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(kernelPath);

    kLogEvent event;
    info << event
        << "[RegistryDock] 复制内核模式地址到剪贴板, path="
        << m_currentPath.toStdString()
        << ", kernelPath="
        << kernelPath.toStdString()
        << eol;
}

void RegistryDock::copySelectedValueKernelPathToClipboard()
{
    QString targetPath = m_currentPath;
    const int selectedRow = m_valueTable->currentRow();
    if (selectedRow >= 0)
    {
        QTableWidgetItem* valueNameItem = m_valueTable->item(selectedRow, 0);
        if (valueNameItem != nullptr)
        {
            const QString valueName = valueNameItem->data(Qt::UserRole).toString().trimmed();
            if (!valueName.isEmpty())
            {
                targetPath += QStringLiteral("\\") + valueName;
            }
        }
    }

    const QString kernelPath = buildKernelRegistryPath(targetPath);
    if (kernelPath.isEmpty())
    {
        return;
    }

    QApplication::clipboard()->setText(kernelPath);

    kLogEvent event;
    info << event
        << "[RegistryDock] 复制值内核模式地址到剪贴板, path="
        << targetPath.toStdString()
        << ", kernelPath="
        << kernelPath.toStdString()
        << eol;
}

void RegistryDock::readSelectedValueByR0()
{
    const int selectedRow = m_valueTable->currentRow();
    QString valueName;
    if (selectedRow >= 0)
    {
        QTableWidgetItem* valueNameItem = m_valueTable->item(selectedRow, 0);
        if (valueNameItem != nullptr)
        {
            valueName = valueNameItem->data(Qt::UserRole).toString();
        }
    }

    readRegistryValueByR0(valueName);
}

void RegistryDock::readDefaultValueByR0()
{
    readRegistryValueByR0(QString());
}

void RegistryDock::readRegistryValueByR0(const QString& valueName)
{
    // 作用：把当前 UI 路径转换为 \REGISTRY\...，然后通过 R0 只读 IOCTL 查询值。
    // 返回：无；结果通过对话框和状态栏展示。
    const QString kernelPath = buildKernelRegistryPath(m_currentPath);
    if (kernelPath.isEmpty())
    {
        QMessageBox::warning(this, QStringLiteral("R0读取注册表"), QStringLiteral("当前注册表路径无效。"));
        return;
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::RegistryReadResult readResult = driverClient.readRegistryValue(
        kernelPath.toStdWString(),
        valueName.toStdWString(),
        KSWORD_ARK_REGISTRY_DATA_MAX_BYTES);

    QByteArray rawData;
    if (!readResult.data.empty())
    {
        rawData = QByteArray(
            reinterpret_cast<const char*>(readResult.data.data()),
            static_cast<int>(readResult.data.size()));
    }

    const QString valueDisplayName = valueName.trimmed().isEmpty()
        ? QStringLiteral("(默认)")
        : valueName;
    const QString formattedData = readResult.data.empty()
        ? QStringLiteral("<空>")
        : formatValueData(static_cast<DWORD>(readResult.valueType), rawData);
    const QString statusText = QStringLiteral(
        "路径：%1\n"
        "值名：%2\n"
        "状态：%3\n"
        "类型：%4\n"
        "数据长度：%5 / 需要：%6\n"
        "NTSTATUS：0x%7\n\n"
        "数据：\n%8")
        .arg(kernelPath)
        .arg(valueDisplayName)
        .arg(readResult.io.ok ? QString::number(readResult.status) : QStringLiteral("IOCTL失败"))
        .arg(valueTypeToText(static_cast<DWORD>(readResult.valueType)))
        .arg(readResult.dataBytes)
        .arg(readResult.requiredBytes)
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(readResult.lastStatus)), 8, 16, QChar('0'))
        .arg(formattedData);

    kLogEvent event;
    (readResult.io.ok && readResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS ? info : warn)
        << event
        << "[RegistryDock] R0读取注册表完成, path="
        << kernelPath.toStdString()
        << ", valueName="
        << valueName.toStdString()
        << ", ok="
        << (readResult.io.ok ? "true" : "false")
        << ", status="
        << readResult.status
        << ", detail="
        << registryIoMessageText(readResult.io.message).toStdString()
        << eol;

    updateStatusBar(QStringLiteral("R0读取注册表：%1").arg(readResult.io.ok ? QStringLiteral("完成") : QStringLiteral("失败")));
    if (readResult.io.ok && readResult.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS)
    {
        QMessageBox::information(this, QStringLiteral("R0读取注册表"), statusText);
    }
    else
    {
        QMessageBox::warning(this, QStringLiteral("R0读取注册表"), statusText + QStringLiteral("\n\n详情：%1").arg(registryIoMessageText(readResult.io.message)));
    }
}

void RegistryDock::exportCurrentKeyAsync()
{
    if (m_currentPath.isEmpty()) return;

    kLogEvent event;
    info << event << "[RegistryDock] 导出请求, keyPath=" << m_currentPath.toStdString() << eol;

    const QString outputPath = QFileDialog::getSaveFileName(
        this,
        QStringLiteral("导出 .reg"),
        QStringLiteral("registry_%1.reg").arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMdd_HHmmss"))),
        QStringLiteral("REG 文件 (*.reg)"));
    if (outputPath.trimmed().isEmpty()) return;

    if (m_progressPid == 0) m_progressPid = kPro.addReusable(this, "注册表", "导出");
    kPro.set(m_progressPid, "导出中", 0, 20.0f);

    QPointer<RegistryDock> guardThis(this);
    const QString keyPath = m_currentPath;
    std::thread([guardThis, keyPath, outputPath]() {
        QProcess process;
        process.start(QStringLiteral("reg.exe"), QStringList{ QStringLiteral("export"), keyPath, outputPath, QStringLiteral("/y") });
        process.waitForFinished(-1);

        const bool ok = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        const QString errText = QString::fromLocal8Bit(process.readAllStandardError());

        QMetaObject::invokeMethod(qApp, [guardThis, ok, errText, outputPath]() {
            if (guardThis == nullptr) return;
            kPro.set(guardThis->m_progressPid, "导出完成", 0, 100.0f);
            if (ok)
            {
                kLogEvent event;
                info << event << "[RegistryDock] 导出成功, outputPath=" << outputPath.toStdString() << eol;
                QMessageBox::information(guardThis, QStringLiteral("导出 .reg"), QStringLiteral("导出成功：%1").arg(outputPath));
            }
            else
            {
                // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
                const bool privilegePromptHandled =
                    ks::ui::promptForPrivilegeFailure(guardThis, QStringLiteral("导出注册表文件"), errText);
                kLogEvent event;
                warn << event << "[RegistryDock] 导出失败, error=" << errText.toStdString() << eol;
                if (!privilegePromptHandled)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("导出 .reg"),
                        QStringLiteral("导出失败：\n%1").arg(errText));
                }
            }
        }, Qt::QueuedConnection);
    }).detach();
}

void RegistryDock::importRegFileAsync()
{
    const QString inputPath = QFileDialog::getOpenFileName(this, QStringLiteral("导入 .reg"), QString(), QStringLiteral("REG 文件 (*.reg)"));
    if (inputPath.trimmed().isEmpty()) return;

    kLogEvent event;
    info << event << "[RegistryDock] 导入请求, inputPath=" << inputPath.toStdString() << eol;

    if (m_progressPid == 0) m_progressPid = kPro.addReusable(this, "注册表", "导入");
    kPro.set(m_progressPid, "导入中", 0, 20.0f);

    QPointer<RegistryDock> guardThis(this);
    std::thread([guardThis, inputPath]() {
        QProcess process;
        process.start(QStringLiteral("reg.exe"), QStringList{ QStringLiteral("import"), inputPath });
        process.waitForFinished(-1);

        const bool ok = process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
        const QString errText = QString::fromLocal8Bit(process.readAllStandardError());

        QMetaObject::invokeMethod(qApp, [guardThis, ok, errText]() {
            if (guardThis == nullptr) return;
            kPro.set(guardThis->m_progressPid, "导入完成", 0, 100.0f);
            if (ok)
            {
                kLogEvent event;
                info << event << "[RegistryDock] 导入成功。" << eol;
                QMessageBox::information(guardThis, QStringLiteral("导入 .reg"), QStringLiteral("导入成功。"));
                guardThis->refreshCurrentKey(true);
            }
            else
            {
                // privilegePromptHandled：权限恢复提示已展示时抑制旧失败框。
                const bool privilegePromptHandled =
                    ks::ui::promptForPrivilegeFailure(guardThis, QStringLiteral("导入注册表文件"), errText);
                kLogEvent event;
                warn << event << "[RegistryDock] 导入失败, error=" << errText.toStdString() << eol;
                if (!privilegePromptHandled)
                {
                    QMessageBox::warning(
                        guardThis,
                        QStringLiteral("导入 .reg"),
                        QStringLiteral("导入失败：\n%1").arg(errText));
                }
            }
        }, Qt::QueuedConnection);
    }).detach();
}
void RegistryDock::startSearchAsync()
{
    if (m_searchRunning.load())
    {
        kLogEvent event;
        dbg << event << "[RegistryDock] 搜索请求被忽略：已有搜索在运行。" << eol;
        return;
    }

    const QString keyword = m_searchEdit->text().trimmed();
    if (keyword.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("搜索"), QStringLiteral("请输入关键字。"));
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[RegistryDock] 启动搜索, path="
            << m_currentPath.toStdString()
            << ", keyword="
            << keyword.toStdString()
            << eol;
    }

    const bool useR0Search = shouldUseRegistryR0();
    HKEY root = nullptr;
    QString subPath;
    QString kernelStartPath;
    QString displayStartPath = m_currentPath;
    if (useR0Search)
    {
        kernelStartPath = buildKernelRegistryPath(m_currentPath);
        if (kernelStartPath.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("搜索"), QStringLiteral("当前路径无法转换为内核注册表路径。"));
            return;
        }
    }
    else if (!parseRegistryPath(m_currentPath, &root, &subPath))
    {
        return;
    }

    m_searchRunning.store(true);
    m_searchStopFlag.store(false);
    m_searchScannedKeys = 0;
    m_searchHitCount = 0;
    m_searchResultTable->setRowCount(0);
    m_rightTabWidget->setCurrentWidget(m_searchResultTable);
    m_searchButton->setEnabled(false);
    m_stopSearchButton->setEnabled(true);

    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        m_pendingRows.clear();
    }

    if (m_progressPid == 0) m_progressPid = kPro.addReusable(this, "注册表", "搜索");
    kPro.set(m_progressPid, "搜索开始", 0, 5.0f);
    m_searchFlushTimer->start();

    QPointer<RegistryDock> guardThis(this);
    SearchOptions options;
    m_searchThread = std::make_unique<std::thread>([guardThis, root, subPath, keyword, options, useR0Search, kernelStartPath, displayStartPath]() {
        if (guardThis == nullptr) return;

        std::size_t scanned = 0;
        std::size_t hits = 0;
        if (useR0Search)
        {
            guardThis->searchRegistryRecursiveByR0(kernelStartPath, displayStartPath, keyword, options, &scanned, &hits);
        }
        else
        {
            guardThis->searchRegistryRecursive(root, subPath, keyword, options, &scanned, &hits);
        }

        QMetaObject::invokeMethod(qApp, [guardThis, scanned, hits]() {
            if (guardThis == nullptr) return;
            // 读取停止标记必须位于复位之前，确保交互停止与自然完成显示不同状态。
            const bool wasStopped = guardThis->m_searchStopFlag.load();
            guardThis->m_searchRunning.store(false);
            guardThis->m_searchStopFlag.store(false);
            if (guardThis->m_searchThread != nullptr && guardThis->m_searchThread->joinable())
            {
                guardThis->m_searchThread->join();
                guardThis->m_searchThread.reset();
            }
            guardThis->flushPendingSearchRows();
            guardThis->m_searchButton->setEnabled(true);
            guardThis->m_stopSearchButton->setEnabled(false);
            guardThis->updateStatusBar(wasStopped
                ? QStringLiteral("状态: 搜索已停止")
                : QStringLiteral("状态: 搜索完成，扫描 %1 键，命中 %2 项").arg(scanned).arg(hits));
            kPro.set(guardThis->m_progressPid, wasStopped ? "搜索停止" : "搜索完成", 0, 100.0f);

            kLogEvent event;
            info << event
                << (wasStopped ? "[RegistryDock] 搜索已停止, scanned=" : "[RegistryDock] 搜索完成, scanned=")
                << scanned
                << ", hits="
                << hits
                << eol;
        }, Qt::QueuedConnection);
    });
}

void RegistryDock::stopSearch(bool waitForThread)
{
    kLogEvent event;
    info << event
        << "[RegistryDock] 停止搜索请求, waitForThread="
        << (waitForThread ? "true" : "false")
        << eol;

    m_searchStopFlag.store(true);

    if (m_searchThread == nullptr || !m_searchThread->joinable())
    {
        m_searchThread.reset();
        m_searchRunning.store(false);
        m_searchButton->setEnabled(true);
        m_stopSearchButton->setEnabled(false);
        if (m_searchFlushTimer != nullptr) m_searchFlushTimer->stop();
        return;
    }

    if (waitForThread)
    {
        m_searchThread->join();
        m_searchThread.reset();
        m_searchRunning.store(false);
        m_searchButton->setEnabled(true);
        m_stopSearchButton->setEnabled(false);
        if (m_searchFlushTimer != nullptr) m_searchFlushTimer->stop();
        return;
    }

    // 交互停止不能移走唯一的线程所有权：析构路径需要用它同步等待，
    // 才能保证递归搜索不会在 RegistryDock 释放后继续访问成员。
    m_stopSearchButton->setEnabled(false);
    updateStatusBar(QStringLiteral("状态: 搜索已停止"));
}

void RegistryDock::enqueuePendingSearchRow(PendingSearchRow&& row)
{
    std::lock_guard<std::mutex> lock(m_pendingMutex);
    if (m_pendingRows.size() < kMaxPendingSearchRows)
    {
        m_pendingRows.push_back(std::move(row));
    }
}

void RegistryDock::flushPendingSearchRows()
{
    // 搜索线程只负责入队；菜单打开时不消费队列，
    // 避免批量扩容让右键动作保存的结果行发生漂移。
    const QPointer<RegistryDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("registry-search-result-flush"),
        {m_searchResultTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->flushPendingSearchRows();
            }
        }))
    {
        return;
    }

    std::vector<PendingSearchRow> rows;
    bool hasPendingRows = false;
    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        const std::size_t count = std::min<std::size_t>(kSearchFlushBatchSize, m_pendingRows.size());
        rows.reserve(count);
        for (std::size_t i = 0; i < count; ++i)
        {
            rows.push_back(std::move(m_pendingRows.front()));
            m_pendingRows.pop_front();
        }
        hasPendingRows = !m_pendingRows.empty();
    }

    const int availableRows = std::max(0, kMaxSearchResultRows - m_searchResultTable->rowCount());
    const int rowsToAppend = std::min(availableRows, static_cast<int>(rows.size()));
    if (rowsToAppend > 0)
    {
        const int firstRow = m_searchResultTable->rowCount();
        const bool updatesEnabled = m_searchResultTable->updatesEnabled();
        m_searchResultTable->setUpdatesEnabled(false);
        m_searchResultTable->setRowCount(firstRow + rowsToAppend);
        for (int index = 0; index < rowsToAppend; ++index)
        {
            const PendingSearchRow& row = rows[static_cast<std::size_t>(index)];
            const int tableRow = firstRow + index;
            QTableWidgetItem* keyPathItem = new QTableWidgetItem(row.keyPathText);
            keyPathItem->setData(
                kSearchResultRoleTargetKind,
                row.isKeyResult ? kSearchResultTargetKey : kSearchResultTargetValue);
            QTableWidgetItem* valueNameItem = new QTableWidgetItem(row.valueNameText);
            if (!row.isKeyResult)
            {
                // 默认值展示文本与真实的空 Win32 名称分开保存，避免同名显示值歧义。
                valueNameItem->setData(kSearchResultRoleRawValueName, row.rawValueName);
            }
            m_searchResultTable->setItem(tableRow, 0, keyPathItem);
            m_searchResultTable->setItem(tableRow, 1, valueNameItem);
            m_searchResultTable->setItem(tableRow, 2, new QTableWidgetItem(row.valueTypeText));
            m_searchResultTable->setItem(tableRow, 3, new QTableWidgetItem(row.valueDataPreviewText));
            m_searchResultTable->setItem(tableRow, 4, new QTableWidgetItem(row.hitSourceText));
        }
        m_searchResultTable->setUpdatesEnabled(updatesEnabled);
        if (updatesEnabled) m_searchResultTable->viewport()->update();
    }

    if (!m_searchRunning.load() && !hasPendingRows && m_searchFlushTimer != nullptr)
    {
        m_searchFlushTimer->stop();
    }
}

void RegistryDock::searchRegistryRecursive(HKEY root, const QString& subPath, const QString& keyword, const SearchOptions& options, std::size_t* scanned, std::size_t* hit)
{
    if (m_searchStopFlag.load()) return;

    HKEY key = nullptr;
    LONG openResult = ::RegOpenKeyExW(root, subPath.isEmpty() ? nullptr : reinterpret_cast<const wchar_t*>(subPath.utf16()), 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &key);
    if (openResult != ERROR_SUCCESS) return;

    if (scanned != nullptr) *scanned += 1;

    const QString fullPath = rootKeyToText(root) + (subPath.isEmpty() ? QString() : QStringLiteral("\\") + subPath);
    const QString keyName = subPath.isEmpty() ? rootKeyToText(root) : subPath.mid(subPath.lastIndexOf('\\') + 1);

    auto containsText = [&keyword, &options](const QString& text) {
        return options.caseSensitive ? text.contains(keyword) : text.contains(keyword, Qt::CaseInsensitive);
    };

    if (options.searchKeyName && containsText(keyName))
    {
        PendingSearchRow row;
        row.keyPathText = fullPath;
        row.valueNameText = QStringLiteral("<Key>");
        row.valueTypeText = QStringLiteral("<Key>");
        row.valueDataPreviewText = QStringLiteral("-");
        row.hitSourceText = QStringLiteral("KeyName");
        row.isKeyResult = true;
        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    DWORD subKeyCount = 0;
    DWORD maxSubKeyLen = 0;
    DWORD valueCount = 0;
    DWORD maxValueNameLen = 0;
    DWORD maxValueDataLen = 0;
    ::RegQueryInfoKeyW(key, nullptr, nullptr, nullptr, &subKeyCount, &maxSubKeyLen, nullptr, &valueCount, &maxValueNameLen, &maxValueDataLen, nullptr, nullptr);

    std::vector<wchar_t> valueNameBuffer(static_cast<std::size_t>(maxValueNameLen + 4), L'\0');
    std::vector<unsigned char> valueDataBuffer(static_cast<std::size_t>(maxValueDataLen + 8), 0);

    for (DWORD index = 0; index < valueCount; ++index)
    {
        if (m_searchStopFlag.load()) break;

        DWORD valueNameLen = static_cast<DWORD>(valueNameBuffer.size() - 1);
        DWORD valueDataLen = static_cast<DWORD>(valueDataBuffer.size());
        DWORD valueType = REG_NONE;
        LONG enumResult = ::RegEnumValueW(key, index, valueNameBuffer.data(), &valueNameLen, nullptr, &valueType, valueDataBuffer.data(), &valueDataLen);
        if (enumResult != ERROR_SUCCESS) continue;

        const QString valueName = QString::fromWCharArray(valueNameBuffer.data(), static_cast<int>(valueNameLen));
        const QByteArray valueData(reinterpret_cast<const char*>(valueDataBuffer.data()), static_cast<int>(valueDataLen));
        const QString valueText = formatValueData(valueType, valueData);

        bool matched = false;
        QString sourceText;
        if (options.searchValueName && containsText(valueName))
        {
            matched = true;
            sourceText = QStringLiteral("ValueName");
        }
        if (!matched && options.searchValueData && containsText(valueText))
        {
            matched = true;
            sourceText = QStringLiteral("ValueData");
        }
        if (!matched) continue;

        PendingSearchRow row;
        row.keyPathText = fullPath;
        row.valueNameText = valueName.isEmpty() ? QStringLiteral("(默认)") : valueName;
        row.rawValueName = valueName;
        row.valueTypeText = valueTypeToText(valueType);
        row.valueDataPreviewText = valueText;
        row.hitSourceText = sourceText;

        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    if (scanned != nullptr && (*scanned % 64 == 0))
    {
        const std::size_t scannedSnapshot = *scanned;
        const std::size_t hitSnapshot = (hit == nullptr) ? 0 : *hit;
        QPointer<RegistryDock> guardThis(this);
        QMetaObject::invokeMethod(qApp, [guardThis, scannedSnapshot, hitSnapshot]() {
            if (guardThis == nullptr) return;
            guardThis->updateStatusBar(QStringLiteral("状态: 搜索中，扫描 %1 键，命中 %2 项").arg(scannedSnapshot).arg(hitSnapshot));
            const float progress = 5.0f + static_cast<float>(std::min<std::size_t>(scannedSnapshot, 4000)) / 50.0f;
            kPro.set(guardThis->m_progressPid, "搜索中", 0, std::min(progress, 95.0f));
        }, Qt::QueuedConnection);
    }

    std::vector<wchar_t> subNameBuffer(static_cast<std::size_t>(maxSubKeyLen + 4), L'\0');
    for (DWORD subIndex = 0; subIndex < subKeyCount; ++subIndex)
    {
        if (m_searchStopFlag.load()) break;

        DWORD subNameLen = static_cast<DWORD>(subNameBuffer.size() - 1);
        LONG subResult = ::RegEnumKeyExW(key, subIndex, subNameBuffer.data(), &subNameLen, nullptr, nullptr, nullptr, nullptr);
        if (subResult != ERROR_SUCCESS) continue;

        const QString childName = QString::fromWCharArray(subNameBuffer.data(), static_cast<int>(subNameLen));
        const QString childPath = subPath.isEmpty() ? childName : subPath + QStringLiteral("\\") + childName;
        searchRegistryRecursive(root, childPath, keyword, options, scanned, hit);
    }

    ::RegCloseKey(key);
}

void RegistryDock::searchRegistryRecursiveByR0(
    const QString& kernelKeyPath,
    const QString& displayKeyPath,
    const QString& keyword,
    const SearchOptions& options,
    std::size_t* scanned,
    std::size_t* hit)
{
    // 作用：使用驱动递归枚举注册表键和值并匹配关键字。
    // 返回：无；结果通过 m_pendingRows 异步刷入搜索表。
    if (m_searchStopFlag.load())
    {
        return;
    }

    const ksword::ark::DriverClient driverClient;
    const ksword::ark::RegistryEnumResult enumResult = driverClient.enumerateRegistryKey(
        kernelKeyPath.toStdWString(),
        KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES);
    if (!registryEnumUsable(enumResult))
    {
        kLogEvent event;
        warn << event
            << "[RegistryDock] R0搜索枚举失败, kernelPath="
            << kernelKeyPath.toStdString()
            << ", detail="
            << registryEnumFailureText(QStringLiteral("R0搜索枚举"), enumResult).toStdString()
            << eol;
        return;
    }

    if (scanned != nullptr)
    {
        *scanned += 1;
    }

    auto containsText = [&keyword, &options](const QString& text) {
        return options.caseSensitive ? text.contains(keyword) : text.contains(keyword, Qt::CaseInsensitive);
    };

    const int lastSlash = displayKeyPath.lastIndexOf('\\');
    const QString keyName = lastSlash < 0 ? displayKeyPath : displayKeyPath.mid(lastSlash + 1);
    if (options.searchKeyName && containsText(keyName))
    {
        PendingSearchRow row;
        row.keyPathText = displayKeyPath;
        row.valueNameText = QStringLiteral("<Key>");
        row.valueTypeText = QStringLiteral("<Key>");
        row.valueDataPreviewText = QStringLiteral("-");
        row.hitSourceText = QStringLiteral("KeyName/R0");
        row.isKeyResult = true;
        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    for (const ksword::ark::RegistryValueEntry& valueEntry : enumResult.values)
    {
        if (m_searchStopFlag.load())
        {
            break;
        }

        const QString valueName = QString::fromStdWString(valueEntry.name);
        const QByteArray valueData = registryDataToByteArray(valueEntry.data);
        QString valueText = formatValueData(static_cast<DWORD>(valueEntry.valueType), valueData);
        if (valueEntry.requiredBytes > valueEntry.dataBytes)
        {
            valueText += QStringLiteral(" <R0预览截断 %1/%2>").arg(valueEntry.dataBytes).arg(valueEntry.requiredBytes);
        }

        bool matched = false;
        QString sourceText;
        if (options.searchValueName && containsText(valueName))
        {
            matched = true;
            sourceText = QStringLiteral("ValueName/R0");
        }
        if (!matched && options.searchValueData && containsText(valueText))
        {
            matched = true;
            sourceText = QStringLiteral("ValueData/R0");
        }
        if (!matched)
        {
            continue;
        }

        PendingSearchRow row;
        row.keyPathText = displayKeyPath;
        row.valueNameText = valueName.isEmpty() ? QStringLiteral("(默认)") : valueName;
        row.rawValueName = valueName;
        row.valueTypeText = valueTypeToText(static_cast<DWORD>(valueEntry.valueType));
        row.valueDataPreviewText = valueText;
        row.hitSourceText = sourceText;

        enqueuePendingSearchRow(std::move(row));
        if (hit != nullptr) *hit += 1;
    }

    if (scanned != nullptr && (*scanned % 64 == 0))
    {
        const std::size_t scannedSnapshot = *scanned;
        const std::size_t hitSnapshot = (hit == nullptr) ? 0 : *hit;
        QPointer<RegistryDock> guardThis(this);
        QMetaObject::invokeMethod(qApp, [guardThis, scannedSnapshot, hitSnapshot]() {
            if (guardThis == nullptr) return;
            guardThis->updateStatusBar(QStringLiteral("状态: R0搜索中，扫描 %1 键，命中 %2 项").arg(scannedSnapshot).arg(hitSnapshot));
            const float progress = 5.0f + static_cast<float>(std::min<std::size_t>(scannedSnapshot, 4000)) / 50.0f;
            kPro.set(guardThis->m_progressPid, "R0搜索中", 0, std::min(progress, 95.0f));
        }, Qt::QueuedConnection);
    }

    for (const ksword::ark::RegistrySubKeyEntry& childEntry : enumResult.subKeys)
    {
        if (m_searchStopFlag.load())
        {
            break;
        }

        const QString childName = QString::fromStdWString(childEntry.name);
        if (childName.trimmed().isEmpty())
        {
            continue;
        }
        searchRegistryRecursiveByR0(
            kernelKeyPath + QStringLiteral("\\") + childName,
            displayKeyPath + QStringLiteral("\\") + childName,
            keyword,
            options,
            scanned,
            hit);
    }
}
