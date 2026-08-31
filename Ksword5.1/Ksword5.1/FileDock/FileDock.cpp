#include "FileDock.h"
#include "../Framework/DestructiveActionConfirmation.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/UI_All.h"
#include "FilePropertyPeAnalyzer.h"
#include "DriverFileSystemParser.h"
#include "IrpFileSystemParser.h"
#include "FileHandleUsageScanner.h"
#include "../Internationalization/LanguageManager.h"
#include "../MainWindow.h"

// ============================================================
// FileDock.cpp
// 说明：
// - 该文件实现双栏资源管理器核心交互；
// - 支持导航、过滤、排序、基础文件操作与文件详情展示。
// ============================================================

#include "../theme.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/HexEditorWidget.h"
#include "../UI/ReportStructuredView.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableInteractionSupport.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../KernelDock/KernelCleanImageBaseline.h"
#include "../PluginHost.h"
#include "../ksword/file/file_handle_tools.h"
#include "../ksword/file/file_metadata_transaction.h"
#include "../ksword/file/file.h"

#include <QApplication>
#include <QAbstractItemView>
#include <QAction>
#include <QByteArray>
#include <QButtonGroup>
#include <QClipboard>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QCryptographicHash>
#include <QDesktopServices>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QDateTime>
#include <QDateTimeEdit>
#include <QEvent>
#include <QFile>
#include <QFileDevice>
#include <QFileInfo>
#include <QFileDialog>
#include <QFileSystemModel>
#include <QFont>
#include <QFormLayout>
#include <QFrame>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QListView>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QMouseEvent>
#include <QPlainTextEdit>
#include <QPair>
#include <QTextEdit>
#include <QPointer>
#include <QPalette>
#include <QProgressBar>
#include <QProcess>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QScreen>
#include <QScrollArea>
#include <QSaveFile>
#include <QSet>
#include <QShortcut>
#include <QSizePolicy>
#include <QSortFilterProxyModel>
#include <QSpinBox>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QStorageInfo>
#include <QStyle>
#include <QStringList>
#include <QStackedWidget>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThreadPool>
#include <QToolButton>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QTreeView>
#include <QTimeZone>
#include <QUrl>
#include <QUuid>
#include <QVector>
#include <QVBoxLayout>
#include <QWindow>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winioctl.h>
#include <Wbemidl.h>
#include <fltUser.h>
#include <atlbase.h>
#include <comdef.h>

#include <array>
#include <algorithm>
#include <cstddef>
#include <chrono>
#include <condition_variable>
#include <cctype>
#include <cmath>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <utility>

#include <Aclapi.h>
#include <Sddl.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "FltLib.lib")

#ifndef SECURITY_MANDATORY_MEDIUM_PLUS_RID
#define SECURITY_MANDATORY_MEDIUM_PLUS_RID (SECURITY_MANDATORY_MEDIUM_RID + 0x100UL)
#endif

#ifndef SECURITY_MANDATORY_PROTECTED_PROCESS_RID
#define SECURITY_MANDATORY_PROTECTED_PROCESS_RID 0x5000UL
#endif

#ifndef SYSTEM_MANDATORY_LABEL_NO_WRITE_UP
#define SYSTEM_MANDATORY_LABEL_NO_WRITE_UP 0x1UL
#endif

#ifndef LABEL_SECURITY_INFORMATION
#define LABEL_SECURITY_INFORMATION 0x00000010L
#endif

namespace
{
    // isDeletedFileSafelyRecoverable 作用：
    // - 统一判断扫描结果是否可进入恢复流程；
    // - 非驻留数据只有完整度与 runlist 均通过扫描校验时才返回 true。
    bool isDeletedFileSafelyRecoverable(
        const ks::file::NtfsDeletedFileEntry& entryValue)
    {
        return entryValue.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::Resident ||
            entryValue.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::NonResidentIntact;
    }

    // deletedFileRecoveryCapabilityText 作用：
    // - 将底层恢复能力转换为表格可读文本；
    // - 文本明确说明非驻留数据必须导出到其它卷。
    QString deletedFileRecoveryCapabilityText(
        const ks::file::NtfsDeletedFileEntry& entryValue)
    {
        switch (entryValue.recoveryCapability)
        {
        case ks::file::NtfsRecoveryCapability::Resident:
            return QStringLiteral("Resident 可恢复");
        case ks::file::NtfsRecoveryCapability::NonResidentIntact:
            return QStringLiteral("非驻留完整可恢复（需其它卷）");
        case ks::file::NtfsRecoveryCapability::NonResidentAtRisk:
            return QStringLiteral("非驻留簇已复用或完整度未知");
        case ks::file::NtfsRecoveryCapability::UnsupportedStream:
            return QStringLiteral("压缩、加密或跨记录流暂不支持");
        case ks::file::NtfsRecoveryCapability::MetadataOnly:
        default:
            return QStringLiteral("仅元数据");
        }
    }

    // localVolumeRootForPath 作用：
    // - 从本地绝对路径提取“C:\”形式卷根；
    // - UNC/网络路径返回空字符串，不会被误判为源卷。
    QString localVolumeRootForPath(const QString& pathText)
    {
        const QString nativePath =
            QDir::toNativeSeparators(QDir::cleanPath(pathText.trimmed()));
        if (nativePath.size() < 2 || nativePath[1] != QChar(':'))
        {
            return QString();
        }
        return nativePath.left(2).toUpper() + QStringLiteral("\\");
    }

    // safeRecoveryFileName 作用：
    // - 把来自 MFT 的原始名称转换为可由 Win32 普通文件 API 创建的叶名称；
    // - 过滤路径分隔符、ADS 冒号、控制字符、尾随点/空格和 DOS 保留设备名；
    // - 返回空字符串表示调用方应改用 deleted_<MFT>.bin 占位名。
    QString safeRecoveryFileName(const QString& requestedFileName)
    {
        QString safeFileName = requestedFileName.trimmed();
        constexpr qsizetype MaximumRecoveryFileNameLength = 180;
        const QString invalidCharacterSet =
            QStringLiteral("<>:\"/\\|?*");
        for (qsizetype characterIndex = 0;
             characterIndex < safeFileName.size();
             ++characterIndex)
        {
            const QChar characterValue = safeFileName.at(characterIndex);
            if (characterValue.unicode() < 0x20U ||
                invalidCharacterSet.contains(characterValue))
            {
                safeFileName[characterIndex] = QChar('_');
            }
        }

        while (safeFileName.endsWith(QChar('.')) ||
               safeFileName.endsWith(QChar(' ')))
        {
            safeFileName.chop(1);
        }
        if (safeFileName.size() > MaximumRecoveryFileNameLength)
        {
            safeFileName.truncate(MaximumRecoveryFileNameLength);
            if (!safeFileName.isEmpty() &&
                safeFileName.back().isHighSurrogate())
            {
                safeFileName.chop(1);
            }
        }

        const QString deviceBaseName =
            safeFileName.section(QChar('.'), 0, 0).toUpper();
        const bool isReservedDeviceName =
            deviceBaseName == QStringLiteral("CON") ||
            deviceBaseName == QStringLiteral("PRN") ||
            deviceBaseName == QStringLiteral("AUX") ||
            deviceBaseName == QStringLiteral("NUL") ||
            (deviceBaseName.size() == 4 &&
             (deviceBaseName.startsWith(QStringLiteral("COM")) ||
              deviceBaseName.startsWith(QStringLiteral("LPT"))) &&
             deviceBaseName.back() >= QChar('1') &&
             deviceBaseName.back() <= QChar('9'));
        if (isReservedDeviceName)
        {
            safeFileName.prepend(QChar('_'));
        }
        if (safeFileName == QStringLiteral(".") ||
            safeFileName == QStringLiteral(".."))
        {
            safeFileName.clear();
        }
        return safeFileName;
    }

    // uniqueRecoveryTargetPath 作用：
    // - 为批量恢复生成不覆盖现有文件、也不互相冲突的输出路径；
    // - 冲突时在扩展名前附加 MFT 记录号及递增序号。
    QString uniqueRecoveryTargetPath(
        const QString& outputDirectory,
        const QString& requestedFileName,
        const std::uint64_t fileReference,
        QSet<QString>& reservedPathSet)
    {
        QString safeFileName = safeRecoveryFileName(requestedFileName);
        if (safeFileName.isEmpty() ||
            safeFileName == QStringLiteral(".") ||
            safeFileName == QStringLiteral(".."))
        {
            safeFileName = QStringLiteral("deleted_%1.bin")
                .arg(static_cast<qulonglong>(fileReference));
        }

        const QFileInfo nameInfo(safeFileName);
        const QString baseName = nameInfo.completeBaseName().isEmpty()
            ? safeFileName
            : nameInfo.completeBaseName();
        const QString suffixText = nameInfo.completeSuffix();
        QString candidatePath = QDir(outputDirectory).filePath(safeFileName);
        int collisionIndex = 0;
        while (QFileInfo::exists(candidatePath) ||
               reservedPathSet.contains(candidatePath.toCaseFolded()))
        {
            ++collisionIndex;
            const QString collisionName = suffixText.isEmpty()
                ? QStringLiteral("%1_mft%2_%3")
                    .arg(baseName)
                    .arg(static_cast<qulonglong>(fileReference))
                    .arg(collisionIndex)
                : QStringLiteral("%1_mft%2_%3.%4")
                    .arg(baseName)
                    .arg(static_cast<qulonglong>(fileReference))
                    .arg(collisionIndex)
                    .arg(suffixText);
            candidatePath = QDir(outputDirectory).filePath(collisionName);
        }
        reservedPathSet.insert(candidatePath.toCaseFolded());
        return candidatePath;
    }

    struct DriverDeleteTarget
    {
        QString path;
        bool isDirectory = false;
    };

    enum class UnlockOperationMode
    {
        CloseHandleR3 = 0,
        TerminateProcessR3,
        TerminateProcessR0
    };

    struct UnlockProcessCandidate
    {
        std::uint32_t processId = 0U;
        std::uint64_t processCreationTime = 0U;
        QString processName;
        QString processImagePath;
        QStringList matchedTargetList;
        QStringList matchRuleList;
        std::size_t matchCount = 0U;
        bool isCurrentProcess = false;
        bool isCriticalProcess = false;
    };

    struct UnlockHandleCandidate
    {
        std::uint32_t processId = 0U;
        std::uint64_t processCreationTime = 0U;
        QString processName;
        QString processImagePath;
        std::uint64_t handleValue = 0U;
        std::uint32_t grantedAccess = 0U;
        QString matchedTargetPath;
        bool matchedByDirectoryRule = false;
        QString matchRuleText;
        QString objectName;
        QString enumerationSource;
        bool isCurrentProcess = false;
        bool isCriticalProcess = false;
    };

    struct UnlockSelectionResult
    {
        bool accepted = false;
        UnlockOperationMode operationMode = UnlockOperationMode::CloseHandleR3;
        std::vector<std::uint32_t> selectedProcessIdList;
        std::vector<UnlockHandleCandidate> selectedHandleList;
    };

    // installFileTableCopyMenu 作用：
    // - 输入：FileDock 内临时弹窗或工具页表格；
    // - 处理：安装只读复制当前行右键菜单；
    // - 返回：无。前置声明用于上方文件解锁选择弹窗复用后文 helper。
    void installFileTableCopyMenu(QTableWidget* tableWidget, int processIdColumn = -1);

    // UnlockSelectionSharedState：
    // - 作用：在线程与 UI 队列之间传递解锁器选择结果；
    // - 说明：使用 shared_ptr 托管，避免 FileDock 析构时队列中的 UI 回调访问已释放栈变量。
    struct UnlockSelectionSharedState
    {
        std::mutex mutex;                         // mutex：保护 completed 与 result 的互斥锁。
        std::condition_variable condition;        // condition：通知后台线程 UI 选择已完成。
        bool completed = false;                   // completed：标记 UI 选择流程是否已经写入结果。
        UnlockSelectionResult result;             // result：保存用户选择的操作方式及句柄/PID 目标。
    };

    struct FileIntegrityLevelPreset
    {
        DWORD rid;              // rid：S-1-16-* Mandatory Label 的最后一级 RID。
        const char* nameText;   // nameText：菜单与日志中的稳定英文名。
        const char* detailText; // detailText：面向用户的中文说明。
    };

    const FileIntegrityLevelPreset FileIntegrityLevelPresets[] =
    {
        { SECURITY_MANDATORY_UNTRUSTED_RID, "Untrusted", "不受信任完整性" },
        { SECURITY_MANDATORY_LOW_RID, "Low", "低完整性" },
        { SECURITY_MANDATORY_MEDIUM_RID, "Medium", "中完整性" },
        { SECURITY_MANDATORY_MEDIUM_PLUS_RID, "MediumPlus", "中高完整性" },
        { SECURITY_MANDATORY_HIGH_RID, "High", "高完整性" },
        { SECURITY_MANDATORY_SYSTEM_RID, "System", "系统完整性" }
    };

    // isSupportedFileMandatoryIntegrityRid 作用：
    // - 输入：integrityRid 为准备写入文件/目录 Mandatory Label 的 S-1-16-* RID；
    // - 处理：只允许 Windows 文件对象可接受的 MIC 等级。ProtectedProcess/SecureProcess
    //   属于令牌/进程语义，写入文件 SACL 会被内核安全 API 拒绝为 STATUS_INVALID_LABEL；
    // - 返回：true 表示可继续调用 R0/R3 写 LABEL_SECURITY_INFORMATION，false 表示前端应直接拒绝。
    bool isSupportedFileMandatoryIntegrityRid(const DWORD integrityRid)
    {
        for (const FileIntegrityLevelPreset& preset : FileIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return true;
            }
        }
        return false;
    }

    // formatFileWin32Error 作用：
    // - 输入：stepText 表示失败步骤，errorCode 为 Win32 错误码；
    // - 处理：生成稳定错误文本，避免不同系统语言下 FormatMessage 文案不一致；
    // - 返回：可直接展示和写入日志的 QString。
    QString formatFileWin32Error(const QString& stepText, const DWORD errorCode)
    {
        return QStringLiteral("%1 failed, error=%2").arg(stepText).arg(errorCode);
    }

    // enableFileContextPrivilege 作用：
    // - 输入：privilegeName 为当前进程令牌中的特权名，例如 SeSecurityPrivilege；
    // - 处理：临时启用当前进程 Token 上已有特权，不具备该特权时静默失败；
    // - 返回：true 表示 AdjustTokenPrivileges 成功启用，false 表示无法启用。
    bool enableFileContextPrivilege(const wchar_t* privilegeName)
    {
        if (privilegeName == nullptr)
        {
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            ::CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        const BOOL adjustOk = ::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr);
        const DWORD adjustError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        return adjustOk != FALSE && adjustError == ERROR_SUCCESS;
    }

    // allocateFileMandatoryIntegritySid 作用：
    // - 输入：integrityRid 为 Mandatory Label RID；
    // - 处理：构造 S-1-16-integrityRid SID，调用者负责 FreeSid；
    // - 返回：成功时 true 并写入 sidOut，失败时 false 并输出 detailText。
    bool allocateFileMandatoryIntegritySid(
        const DWORD integrityRid,
        PSID* sidOut,
        QString* detailText)
    {
        if (sidOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("sidOut is null");
            }
            return false;
        }
        *sidOut = nullptr;

        SID_IDENTIFIER_AUTHORITY mandatoryLabelAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        if (::AllocateAndInitializeSid(
            &mandatoryLabelAuthority,
            1,
            integrityRid,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            sidOut) == FALSE)
        {
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(
                    QStringLiteral("AllocateAndInitializeSid"),
                    ::GetLastError());
            }
            return false;
        }
        return true;
    }

    // fileIntegrityNameFromRid 作用：
    // - 输入：Mandatory Label RID；
    // - 处理：优先匹配菜单预设，否则退化为十六进制 RID；
    // - 返回：用于菜单、提示框和日志的短名称。
    QString fileIntegrityNameFromRid(const DWORD integrityRid)
    {
        for (const FileIntegrityLevelPreset& preset : FileIntegrityLevelPresets)
        {
            if (preset.rid == integrityRid)
            {
                return QString::fromLatin1(preset.nameText);
            }
        }
        return QStringLiteral("RID=0x%1").arg(integrityRid, 0, 16).toUpper();
    }

    // queryFileIntegrityRid 作用：
    // - 输入：filePath 为文件或目录路径；
    // - 处理：读取 LABEL_SECURITY_INFORMATION，扫描 SYSTEM_MANDATORY_LABEL_ACE_TYPE；
    // - 返回：成功时 true 并写入 ridOut；没有显式标签时按 Windows 默认 Medium 处理。
    bool queryFileIntegrityRid(
        const QString& filePath,
        DWORD* ridOut,
        bool* implicitMediumOut,
        QString* detailText)
    {
        if (ridOut == nullptr)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("ridOut is null");
            }
            return false;
        }
        *ridOut = 0;
        if (implicitMediumOut != nullptr)
        {
            *implicitMediumOut = false;
        }

        (void)enableFileContextPrivilege(SE_SECURITY_NAME);

        std::wstring pathBuffer = QDir::toNativeSeparators(filePath).toStdWString();
        PACL labelAcl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        const DWORD queryResult = ::GetNamedSecurityInfoW(
            pathBuffer.data(),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            nullptr,
            &labelAcl,
            &securityDescriptor);
        if (queryResult != ERROR_SUCCESS)
        {
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(
                    QStringLiteral("GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)"),
                    queryResult);
            }
            return false;
        }

        bool foundLabel = false;
        DWORD foundRid = SECURITY_MANDATORY_MEDIUM_RID;
        if (labelAcl != nullptr)
        {
            ACL_SIZE_INFORMATION aclSizeInfo{};
            if (::GetAclInformation(
                labelAcl,
                &aclSizeInfo,
                static_cast<DWORD>(sizeof(aclSizeInfo)),
                AclSizeInformation) != FALSE)
            {
                for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
                {
                    LPVOID acePointer = nullptr;
                    if (::GetAce(labelAcl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                    {
                        continue;
                    }

                    const ACE_HEADER* aceHeader = reinterpret_cast<const ACE_HEADER*>(acePointer);
                    if (aceHeader->AceType != SYSTEM_MANDATORY_LABEL_ACE_TYPE)
                    {
                        continue;
                    }

                    const ACCESS_ALLOWED_ACE* mandatoryAce =
                        reinterpret_cast<const ACCESS_ALLOWED_ACE*>(acePointer);
                    PSID labelSid = const_cast<DWORD*>(&mandatoryAce->SidStart);
                    if (labelSid == nullptr ||
                        ::IsValidSid(labelSid) == FALSE ||
                        *::GetSidSubAuthorityCount(labelSid) == 0)
                    {
                        continue;
                    }

                    foundRid = *::GetSidSubAuthority(
                        labelSid,
                        static_cast<DWORD>(*::GetSidSubAuthorityCount(labelSid) - 1));
                    foundLabel = true;
                    break;
                }
            }
        }

        if (securityDescriptor != nullptr)
        {
            ::LocalFree(securityDescriptor);
        }

        *ridOut = foundRid;
        if (!foundLabel && implicitMediumOut != nullptr)
        {
            *implicitMediumOut = true;
        }
        if (detailText != nullptr)
        {
            *detailText = foundLabel
                ? QStringLiteral("explicit label=%1").arg(fileIntegrityNameFromRid(foundRid))
                : QStringLiteral("no explicit mandatory label; using implicit Medium");
        }
        return true;
    }

    // setFileIntegrityLevelByPath 作用：
    // - 输入：filePath 为文件或目录路径，integrityRid 为目标 Mandatory Label RID；
    // - 处理：构造只包含 Mandatory Label ACE 的 ACL，并通过 LABEL_SECURITY_INFORMATION 写入；
    // - 返回：ERROR_SUCCESS 表示写入成功，失败时 detailText 包含 Win32 诊断。
    DWORD setFileIntegrityLevelByPath(
        const QString& filePath,
        const DWORD integrityRid,
        QString* detailText)
    {
        if (!isSupportedFileMandatoryIntegrityRid(integrityRid))
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("unsupported file mandatory label RID=0x%1; "
                    "ProtectedProcess/SecureProcess labels are token-only and cannot be written to file objects")
                    .arg(integrityRid, 0, 16);
            }
            return ERROR_INVALID_PARAMETER;
        }

        (void)enableFileContextPrivilege(SE_SECURITY_NAME);
        (void)enableFileContextPrivilege(SE_RESTORE_NAME);

        PSID integritySid = nullptr;
        QString sidDetailText;
        if (!allocateFileMandatoryIntegritySid(integrityRid, &integritySid, &sidDetailText))
        {
            DWORD sidError = ::GetLastError();
            if (sidError == ERROR_SUCCESS)
            {
                sidError = ERROR_INVALID_SID;
            }
            if (detailText != nullptr)
            {
                *detailText = sidDetailText;
            }
            return sidError;
        }

        const DWORD sidLength = ::GetLengthSid(integritySid);
        const DWORD aclBytes = static_cast<DWORD>(
            sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) + sidLength);
        PACL labelAcl = reinterpret_cast<PACL>(::LocalAlloc(LPTR, aclBytes));
        if (labelAcl == nullptr)
        {
            const DWORD allocError = ::GetLastError();
            ::FreeSid(integritySid);
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("LocalAlloc(ACL)"), allocError);
            }
            return allocError;
        }

        DWORD result = ERROR_SUCCESS;
        if (::InitializeAcl(labelAcl, aclBytes, ACL_REVISION) == FALSE)
        {
            result = ::GetLastError();
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("InitializeAcl"), result);
            }
        }
        else if (::AddMandatoryAce(
            labelAcl,
            ACL_REVISION,
            0,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            integritySid) == FALSE)
        {
            result = ::GetLastError();
            if (detailText != nullptr)
            {
                *detailText = formatFileWin32Error(QStringLiteral("AddMandatoryAce"), result);
            }
        }
        else
        {
            std::wstring pathBuffer = QDir::toNativeSeparators(filePath).toStdWString();
            result = ::SetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                LABEL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                nullptr,
                labelAcl);
            if (detailText != nullptr)
            {
                *detailText = result == ERROR_SUCCESS
                    ? QStringLiteral("已写入文件完整性：%1，RID=0x%2，路径=%3")
                        .arg(fileIntegrityNameFromRid(integrityRid))
                        .arg(integrityRid, 0, 16)
                        .arg(QDir::toNativeSeparators(filePath))
                    : formatFileWin32Error(
                        QStringLiteral("SetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)"),
                        result);
            }
        }

        ::LocalFree(labelAcl);
        ::FreeSid(integritySid);
        return result;
    }

    // resolveVisibleDialogParent 作用：
    // - 为文件解锁器选择一个可见父窗口；
    // - Shell 右键会使用隐藏 FileDock 宿主，不能直接把弹窗挂在隐藏控件上。
    QWidget* resolveVisibleDialogParent(QWidget* const preferredParent)
    {
        QWidget* candidate = preferredParent;
        if (candidate != nullptr)
        {
            QWidget* const topLevel = candidate->window();
            if (topLevel != nullptr)
            {
                candidate = topLevel;
            }
        }
        if (candidate != nullptr && candidate->isVisible())
        {
            return candidate;
        }
        if (QWidget* const activeWindow = QApplication::activeWindow(); activeWindow != nullptr)
        {
            return activeWindow;
        }
        const QWidgetList topLevelWidgetList = QApplication::topLevelWidgets();
        for (QWidget* const widget : topLevelWidgetList)
        {
            if (widget != nullptr && widget->isVisible())
            {
                return widget;
            }
        }
        return preferredParent;
    }

    int calculateFileStandaloneWindowMaxWidth(
        QWidget* candidateParent,
        QWidget* fallbackWindow,
        const double ratio,
        const int fallbackWidth)
    {
        // 输入：
        // - candidateParent：优先参考的客户区控件；
        // - fallbackWindow：当前独立窗口，用于屏幕回退；
        // - ratio：客户区宽度比例；
        // - fallbackWidth：回退宽度。
        // 处理：
        // - 优先使用父控件 contentsRect 宽度；
        // - 父控件不可用时使用活动窗口客户区；
        // - 最后使用屏幕可用区域宽度。
        // 返回：按比例计算出的最大宽度；仅在完全无法判断时使用回退宽度。
        int clientWidth = 0;
        if (candidateParent != nullptr && candidateParent->contentsRect().width() > 0)
        {
            clientWidth = candidateParent->contentsRect().width();
        }

        if (clientWidth <= 0)
        {
            QWidget* activeWindow = QApplication::activeWindow();
            if (activeWindow != nullptr &&
                activeWindow != fallbackWindow &&
                activeWindow->contentsRect().width() > 0)
            {
                clientWidth = activeWindow->contentsRect().width();
            }
        }

        QScreen* targetScreen = nullptr;
        if (candidateParent != nullptr && candidateParent->windowHandle() != nullptr)
        {
            targetScreen = candidateParent->windowHandle()->screen();
        }
        if (targetScreen == nullptr && fallbackWindow != nullptr && fallbackWindow->windowHandle() != nullptr)
        {
            targetScreen = fallbackWindow->windowHandle()->screen();
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (clientWidth <= 0 && targetScreen != nullptr)
        {
            clientWidth = targetScreen->availableGeometry().width();
        }

        const int boundedFallbackWidth = std::max(1, fallbackWidth);
        if (clientWidth <= 0 || ratio <= 0.0)
        {
            return boundedFallbackWidth;
        }
        return std::max(1, static_cast<int>(std::floor(static_cast<double>(clientWidth) * ratio)));
    }

    void applyFileStandaloneWindowWidthLimit(
        QWidget* window,
        QWidget* candidateParent,
        const QSize& preferredSize,
        const double ratio)
    {
        // 输入：
        // - window：待约束的文件属性窗口；
        // - candidateParent：客户区宽度来源；
        // - preferredSize：原始设计尺寸；
        // - ratio：最大宽度比例。
        // 处理：设置 maximumWidth 并裁剪初始 resize 宽度。
        // 返回：无。
        if (window == nullptr)
        {
            return;
        }

        const int maxWidth = calculateFileStandaloneWindowMaxWidth(
            candidateParent,
            window,
            ratio,
            preferredSize.width());
        window->setMaximumWidth(maxWidth);
        window->resize(std::min(preferredSize.width(), maxWidth), preferredSize.height());
    }

    // buildOpaqueStandaloneDialogStyle 作用：
    // - 生成独立弹窗不透明样式；
    // - 前置声明用于供解锁器选择对话框在 helper 正式定义前调用。
    QString buildOpaqueStandaloneDialogStyle(const QString& dialogObjectName);

    QString unlockOperationModeToText(const UnlockOperationMode mode)
    {
        if (mode == UnlockOperationMode::CloseHandleR3)
        {
            return QStringLiteral("R3 关闭句柄");
        }
        return mode == UnlockOperationMode::TerminateProcessR0
            ? QStringLiteral("R0 结束进程")
            : QStringLiteral("R3 结束进程");
    }

    QString formatHandleValueText(const std::uint64_t handleValue)
    {
        if (handleValue == 0U)
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(handleValue), 0, 16)
            .toUpper();
    }

    void appendUniqueText(QStringList& list, const QString& text)
    {
        const QString normalizedText = text.trimmed();
        if (!normalizedText.isEmpty() && !list.contains(normalizedText))
        {
            list.push_back(normalizedText);
        }
    }

    // QueryNtQueryInformationFilePtr：动态解析 NtQueryInformationFile，避免 FileDock 额外依赖
    // 其它 user-mode 模块。
    using NtQueryInformationFileFn = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FILE_INFORMATION_CLASS);

    // queryBitLockerVolumeText：前置声明，供卷快照辅助函数先调用。
    QString queryBitLockerVolumeText(const QString& driveLetter);

    // FileVolumeAuditSnapshot：汇总卷、存储和 BitLocker 状态的轻量只读模型。
    struct FileVolumeAuditSnapshot
    {
        QString volumeRoot;
        QString mountPointsText;
        QString devicePathText;
        QString fsNameText;
        QString labelText;
        QString storageText;
        QString bitLockerText;
        QString volumeStackText;
        QString filterText;
    };

    // VolumePathFromAnyPath：把任意本地路径压缩成卷根目录（例如 C:\）。
    QString volumePathFromAnyPath(const QString& pathText)
    {
        const QString normalizedPath = QDir::toNativeSeparators(pathText).trimmed();
        if (normalizedPath.isEmpty())
        {
            return QString();
        }

        std::array<wchar_t, MAX_PATH + 4U> buffer{};
        const BOOL ok = ::GetVolumePathNameW(
            normalizedPath.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (ok == FALSE)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    // buildMountPointsText：读取卷对应的 DOS 挂载点列表，失败时返回空。
    QString buildMountPointsText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        DWORD requiredChars = 0;
        ::GetVolumePathNamesForVolumeNameW(
            volumeRoot.toStdWString().c_str(),
            nullptr,
            0,
            &requiredChars);
        if (requiredChars == 0)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(static_cast<std::size_t>(requiredChars) + 2U, L'\0');
        if (::GetVolumePathNamesForVolumeNameW(
            volumeRoot.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &requiredChars) == FALSE)
        {
            return QString();
        }

        QStringList paths;
        const wchar_t* cursor = buffer.data();
        while (cursor != nullptr && *cursor != L'\0')
        {
            const QString pathText = QString::fromWCharArray(cursor);
            if (!pathText.isEmpty())
            {
                paths << pathText;
            }
            cursor += pathText.size() + 1;
        }
        return paths.join(QStringLiteral(", "));
    }

    // buildVolumeDevicePathText：把卷名解析为设备路径（例如 \Device\HarddiskVolumeX）。
    QString buildVolumeDevicePathText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        QString dosName = volumeRoot;
        if (dosName.endsWith(QChar('\\')))
        {
            dosName.chop(1);
        }

        std::array<wchar_t, 1024U> buffer{};
        const DWORD chars = ::QueryDosDeviceW(
            dosName.toStdWString().c_str(),
            buffer.data(),
            static_cast<DWORD>(buffer.size()));
        if (chars == 0)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data());
    }

    // buildVolumeInfoText：读取卷标、文件系统和基本属性。
    QString buildVolumeInfoText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        std::array<wchar_t, MAX_PATH + 1U> labelBuffer{};
        std::array<wchar_t, MAX_PATH + 1U> fsBuffer{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD fsFlags = 0;
        if (::GetVolumeInformationW(
            volumeRoot.toStdWString().c_str(),
            labelBuffer.data(),
            static_cast<DWORD>(labelBuffer.size()),
            &serialNumber,
            &maxComponentLength,
            &fsFlags,
            fsBuffer.data(),
            static_cast<DWORD>(fsBuffer.size())) == FALSE)
        {
            return QString();
        }

        return QStringLiteral("Label=%1 | FS=%2 | Serial=0x%3 | Flags=0x%4")
            .arg(QString::fromWCharArray(labelBuffer.data()))
            .arg(QString::fromWCharArray(fsBuffer.data()))
            .arg(serialNumber, 8, 16, QChar('0'))
            .arg(fsFlags, 8, 16, QChar('0'))
            .toUpper();
    }

    // queryVolumeLabelAndFileSystemText：只读取卷标与文件系统名称，供 Storage/FVE 页复用。
    // 输入：volumeRoot 为卷根路径（例如 C:\）；labelOut/fileSystemOut 接收读取结果。
    // 返回：读取成功时为 true；失败时保持输出为空。
    bool queryVolumeLabelAndFileSystemText(
        const QString& volumeRoot,
        QString& labelOut,
        QString& fileSystemOut)
    {
        labelOut.clear();
        fileSystemOut.clear();
        if (volumeRoot.trimmed().isEmpty())
        {
            return false;
        }

        std::array<wchar_t, MAX_PATH + 1U> labelBuffer{};
        std::array<wchar_t, MAX_PATH + 1U> fsBuffer{};
        DWORD serialNumber = 0;
        DWORD maxComponentLength = 0;
        DWORD fsFlags = 0;
        if (::GetVolumeInformationW(
            volumeRoot.toStdWString().c_str(),
            labelBuffer.data(),
            static_cast<DWORD>(labelBuffer.size()),
            &serialNumber,
            &maxComponentLength,
            &fsFlags,
            fsBuffer.data(),
            static_cast<DWORD>(fsBuffer.size())) == FALSE)
        {
            return false;
        }

        labelOut = QString::fromWCharArray(labelBuffer.data()).trimmed();
        fileSystemOut = QString::fromWCharArray(fsBuffer.data()).trimmed();
        return true;
    }

    // buildStorageDescriptorText：读取存储设备描述符。
    QString buildStorageDescriptorText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QString();
        }

        HANDLE handleValue = ::CreateFileW(
            volumeRoot.toStdWString().c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handleValue == INVALID_HANDLE_VALUE)
        {
            return QStringLiteral("CreateFile=%1").arg(::GetLastError());
        }

        QString result;
        STORAGE_PROPERTY_QUERY query{};
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;
        std::array<std::uint8_t, 1024U> buffer{};
        DWORD returnedBytes = 0;
        if (::DeviceIoControl(
            handleValue,
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query,
            static_cast<DWORD>(sizeof(query)),
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            &returnedBytes,
            nullptr) != FALSE
            && returnedBytes >= sizeof(STORAGE_DEVICE_DESCRIPTOR))
        {
            const auto* descriptor = reinterpret_cast<const STORAGE_DEVICE_DESCRIPTOR*>(buffer.data());
            result = QStringLiteral("BusType=%1 | Removable=%2 | RawSize=%3")
                .arg(static_cast<unsigned long>(descriptor->BusType))
                .arg(descriptor->RemovableMedia ? QStringLiteral("是") : QStringLiteral("否"))
                .arg(returnedBytes);
        }
        ::CloseHandle(handleValue);
        return result;
    }

    // buildVolumeStackText：把卷根、设备路径、文件系统拼成稳定的只读“卷栈”摘要。
    // 输入：volumeRoot/devicePathText/fsText 均为可空的可见状态文本。
    // 返回：适合 UI 展示的单行或多行链式摘要。
    QString buildVolumeStackText(
        const QString& volumeRoot,
        const QString& devicePathText,
        const QString& fsText,
        const QString& mountPointsText)
    {
        QStringList parts;
        appendUniqueText(parts, volumeRoot);
        appendUniqueText(parts, devicePathText);
        appendUniqueText(parts, fsText);
        appendUniqueText(parts, mountPointsText);
        if (parts.isEmpty())
        {
            return QString();
        }
        return parts.join(QStringLiteral(" -> "));
    }

    // buildBitLockerStatusText：只读查询 BitLocker 可见状态，失败后给降级说明。
    QString buildBitLockerStatusText(const QString& volumeRoot)
    {
        if (volumeRoot.trimmed().isEmpty())
        {
            return QStringLiteral("BitLocker: <unknown>");
        }

        return queryBitLockerVolumeText(volumeRoot.left(2));
    }

    // queryFileVolumeAuditSnapshot：汇总 FileDock 三个新页所需的卷/存储/FVE 视图。
    FileVolumeAuditSnapshot queryFileVolumeAuditSnapshot(const QString& filePath)
    {
        FileVolumeAuditSnapshot snapshot{};
        snapshot.volumeRoot = volumePathFromAnyPath(filePath);
        if (snapshot.volumeRoot.isEmpty())
        {
            return snapshot;
        }

        snapshot.mountPointsText = buildMountPointsText(snapshot.volumeRoot);
        snapshot.devicePathText = buildVolumeDevicePathText(snapshot.volumeRoot);
        QString volumeLabelText;
        QString fileSystemText;
        if (queryVolumeLabelAndFileSystemText(snapshot.volumeRoot, volumeLabelText, fileSystemText))
        {
            snapshot.labelText = volumeLabelText;
            snapshot.fsNameText = fileSystemText;
        }
        snapshot.volumeStackText = buildVolumeStackText(
            snapshot.volumeRoot,
            snapshot.devicePathText,
            snapshot.fsNameText,
            snapshot.mountPointsText);
        const QString volumeInfoText = buildVolumeInfoText(snapshot.volumeRoot);
        const QString storageDescriptorText = buildStorageDescriptorText(snapshot.volumeRoot);
        snapshot.storageText = QStringList{ volumeInfoText, storageDescriptorText }.join(QStringLiteral(" | "));
        snapshot.bitLockerText = buildBitLockerStatusText(snapshot.volumeRoot);
        snapshot.filterText = QStringLiteral("仅只读枚举，不做卸载/绕过/修改。");
        return snapshot;
    }

    // openReadOnlyFileHandle：以只读、共享最大化方式打开文件或目录。
    HANDLE openReadOnlyFileHandle(const QString& pathText, const bool directoryHint)
    {
        const QString normalizedPath = QDir::toNativeSeparators(pathText).trimmed();
        if (normalizedPath.isEmpty())
        {
            return INVALID_HANDLE_VALUE;
        }

        DWORD flags = FILE_ATTRIBUTE_NORMAL;
        if (directoryHint)
        {
            flags |= FILE_FLAG_BACKUP_SEMANTICS;
        }

        return ::CreateFileW(
            normalizedPath.toStdWString().c_str(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr,
            OPEN_EXISTING,
            flags,
            nullptr);
    }

    // queryFileStandardInfoText：读取 DeletePending / 文件大小 / 链接数等标准信息。
    bool queryFileStandardInfoText(
        HANDLE fileHandle,
        QString& detailsOut,
        QString& statusOut)
    {
        detailsOut.clear();
        statusOut.clear();
        if (fileHandle == nullptr || fileHandle == INVALID_HANDLE_VALUE)
        {
            statusOut = QStringLiteral("句柄无效");
            return false;
        }

        FILE_STANDARD_INFO standardInfo{};
        if (::GetFileInformationByHandleEx(
            fileHandle,
            FileStandardInfo,
            &standardInfo,
            static_cast<DWORD>(sizeof(standardInfo))) == FALSE)
        {
            statusOut = QStringLiteral("GetFileInformationByHandleEx(FileStandardInfo) 失败，Win32=%1")
                .arg(::GetLastError());
            return false;
        }

        detailsOut = QStringLiteral("DeletePending: %1\n")
            .arg(standardInfo.DeletePending ? QStringLiteral("是") : QStringLiteral("否"));
        detailsOut += QStringLiteral("Directory: %1\n")
            .arg(standardInfo.Directory ? QStringLiteral("是") : QStringLiteral("否"));
        detailsOut += QStringLiteral("AllocationSize: %1\n")
            .arg(static_cast<qlonglong>(standardInfo.AllocationSize.QuadPart));
        detailsOut += QStringLiteral("EndOfFile: %1\n")
            .arg(static_cast<qlonglong>(standardInfo.EndOfFile.QuadPart));
        detailsOut += QStringLiteral("NumberOfLinks: %1\n")
            .arg(static_cast<unsigned long>(standardInfo.NumberOfLinks));
        detailsOut += QStringLiteral("采集句柄 ShareAccess: READ|WRITE|DELETE\n");
        statusOut = QStringLiteral("OK");
        return true;
    }

    // createReadOnlyAuditTextPage：创建一个只读文本页，统一文本可选与布局风格。
    // 输入：parent 为页面父对象，content 为页面文本。
    // 返回：承载 CodeEditorWidget 的 QWidget 页面；没有返回值以外副作用。
    QWidget* createReadOnlyAuditTextPage(QWidget* parent, const QString& content)
    {
        QWidget* page = new QWidget(parent);
        QVBoxLayout* layout = new QVBoxLayout(page);
        CodeEditorWidget* editor = new CodeEditorWidget(page);
        editor->setReadOnly(true);
        editor->setLocalizedText(content);
        layout->addWidget(editor, 1);
        return page;
    }

    // readUtf16FieldAtOffset：从返回缓冲中读取 UTF-16 偏移字段，供 FltLib 枚举结构解析。
    // 输入：buffer/bytesReturned 指向完整返回缓冲；fieldOffset/fieldLength 为字节级字段位置。
    // 返回：成功时返回去尾空白后的字符串；失败返回空字符串。
    QString readUtf16FieldAtOffset(
        const void* buffer,
        const std::size_t bytesReturned,
        const USHORT fieldOffset,
        const USHORT fieldLength)
    {
        if (buffer == nullptr || bytesReturned == 0U || fieldLength == 0U)
        {
            return QString();
        }
        const std::size_t startOffset = static_cast<std::size_t>(fieldOffset);
        const std::size_t lengthBytes = static_cast<std::size_t>(fieldLength);
        if (startOffset >= bytesReturned || (startOffset + lengthBytes) > bytesReturned)
        {
            return QString();
        }
        const auto* charBuffer = reinterpret_cast<const wchar_t*>(
            static_cast<const std::uint8_t*>(buffer) + startOffset);
        return QString::fromWCharArray(charBuffer, static_cast<int>(lengthBytes / sizeof(wchar_t))).trimmed();
    }

    // filterFilesystemTypeToText：把 FLT_FILESYSTEM_TYPE 枚举转成可读文本。
    // 输入：filesystemType 为 FltUser 返回的文件系统类型。
    // 返回：对应文件系统名称；未知枚举保留数值。
    QString filterFilesystemTypeToText(const FLT_FILESYSTEM_TYPE filesystemType)
    {
        switch (filesystemType)
        {
        case FLT_FSTYPE_UNKNOWN: return QStringLiteral("Unknown");
        case FLT_FSTYPE_RAW: return QStringLiteral("RAW");
        case FLT_FSTYPE_NTFS: return QStringLiteral("NTFS");
        case FLT_FSTYPE_FAT: return QStringLiteral("FAT");
        case FLT_FSTYPE_CDFS: return QStringLiteral("CDFS");
        case FLT_FSTYPE_UDFS: return QStringLiteral("UDFS");
        case FLT_FSTYPE_LANMAN: return QStringLiteral("LANMAN");
        case FLT_FSTYPE_WEBDAV: return QStringLiteral("WebDAV");
        case FLT_FSTYPE_RDPDR: return QStringLiteral("RDPDR");
        case FLT_FSTYPE_NFS: return QStringLiteral("NFS");
        case FLT_FSTYPE_MS_NETWARE: return QStringLiteral("MS_NETWARE");
        case FLT_FSTYPE_NETWARE: return QStringLiteral("NETWARE");
        case FLT_FSTYPE_BSUDF: return QStringLiteral("BsUDF");
        case FLT_FSTYPE_MUP: return QStringLiteral("MUP");
        case FLT_FSTYPE_RSFX: return QStringLiteral("RsFx");
        case FLT_FSTYPE_ROXIO_UDF1: return QStringLiteral("RoxioUDF1");
        case FLT_FSTYPE_ROXIO_UDF2: return QStringLiteral("RoxioUDF2");
        case FLT_FSTYPE_ROXIO_UDF3: return QStringLiteral("RoxioUDF3");
        case FLT_FSTYPE_TACIT: return QStringLiteral("Tacit");
        case FLT_FSTYPE_FS_REC: return QStringLiteral("FsRec");
        case FLT_FSTYPE_INCD: return QStringLiteral("InCD");
        case FLT_FSTYPE_INCD_FAT: return QStringLiteral("InCDFat");
        case FLT_FSTYPE_EXFAT: return QStringLiteral("exFAT");
        case FLT_FSTYPE_PSFS: return QStringLiteral("PSFS");
        case FLT_FSTYPE_GPFS: return QStringLiteral("GPFS");
        case FLT_FSTYPE_NPFS: return QStringLiteral("NPFS");
        case FLT_FSTYPE_MSFS: return QStringLiteral("MSFS");
        case FLT_FSTYPE_CSVFS: return QStringLiteral("CSVFS");
        case FLT_FSTYPE_REFS: return QStringLiteral("ReFS");
        case FLT_FSTYPE_OPENAFS: return QStringLiteral("OpenAFS");
        case FLT_FSTYPE_CIMFS: return QStringLiteral("CIMFS");
        default:
            return QStringLiteral("Type=%1").arg(static_cast<int>(filesystemType));
        }
    }

    // appendMinifilterRecordText：把单条 Filter 枚举记录压成可读文本。
    // 输入：buffer/bytesReturned 为 FilterFindFirst/Next 返回数据。
    // 返回：无；直接追加到 content。
    void appendMinifilterRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(FILTER_AGGREGATE_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer);
        const bool isMinifilter = (record->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
        const QString filterName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);
        const QString altitude = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterAltitudeBufferOffset, record->Type.MiniFilter.FilterAltitudeLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterAltitudeBufferOffset, record->Type.LegacyFilter.FilterAltitudeLength);
        const QString recordKind = isMinifilter ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter");

        content += QStringLiteral("名称: %1\n").arg(filterName.isEmpty() ? QStringLiteral("<unknown>") : filterName);
        content += QStringLiteral("类型: %1\n").arg(recordKind);
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        if (isMinifilter)
        {
            content += QStringLiteral("FrameID: %1\n").arg(record->Type.MiniFilter.FrameID);
            content += QStringLiteral("NumberOfInstances: %1\n").arg(record->Type.MiniFilter.NumberOfInstances);
        }
        content += QStringLiteral("Altitude: %1\n").arg(altitude.isEmpty() ? QStringLiteral("<unknown>") : altitude);
    }

    // enumerateMinifilterText：只读枚举 Filter 列表并生成摘要文本。
    // 输入：无。
    // 返回：包含 Filter 名称、Altitude、FrameID 和实例数的可见文本。
    QString enumerateMinifilterText()
    {
        QString content;
        content += QStringLiteral("[Minifilter]\n");
        content += QStringLiteral("枚举来源: FilterFindFirst / FilterFindNext\n");
        content += QStringLiteral("展示字段: FilterName, Altitude, FrameID, NumberOfInstances, Flags\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE enumHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterFindFirst(
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &enumHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        auto appendRecord = [&](const QString& prefixText)
        {
            content += prefixText;
            appendMinifilterRecordText(content, buffer.data(), bytesReturned);
            content += QStringLiteral("\n");
        };

        appendRecord(QStringLiteral("\n"));

        for (;;)
        {
            bytesReturned = 0;
            hr = ::FilterFindNext(
                enumHandle,
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                appendRecord(QStringLiteral(""));
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (enumHandle != nullptr)
        {
            ::FilterFindClose(enumHandle);
        }
        return content;
    }

    // appendInstanceRecordText：把单条 Instance 枚举记录压成可读文本。
    // 输入：buffer/bytesReturned 为 FilterInstanceFindFirst/Next 返回数据。
    // 返回：无；直接追加到 content。
    void appendInstanceRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(INSTANCE_AGGREGATE_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const INSTANCE_AGGREGATE_STANDARD_INFORMATION*>(buffer);
        const bool isMinifilter = (record->Flags & FLTFL_IASI_IS_MINIFILTER) != 0;
        const QString instanceName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.InstanceNameBufferOffset, record->Type.MiniFilter.InstanceNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, 0, 0);
        const QString altitude = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.AltitudeBufferOffset, record->Type.MiniFilter.AltitudeLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.AltitudeBufferOffset, record->Type.LegacyFilter.AltitudeLength);
        const QString volumeName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.VolumeNameBufferOffset, record->Type.MiniFilter.VolumeNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.VolumeNameBufferOffset, record->Type.LegacyFilter.VolumeNameLength);
        const QString filterName = isMinifilter
            ? readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.MiniFilter.FilterNameBufferOffset, record->Type.MiniFilter.FilterNameLength)
            : readUtf16FieldAtOffset(buffer, bytesReturned, record->Type.LegacyFilter.FilterNameBufferOffset, record->Type.LegacyFilter.FilterNameLength);

        content += QStringLiteral("实例名: %1\n").arg(instanceName.isEmpty() ? QStringLiteral("<unknown>") : instanceName);
        content += QStringLiteral("类型: %1\n").arg(isMinifilter ? QStringLiteral("Minifilter") : QStringLiteral("LegacyFilter"));
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        if (isMinifilter)
        {
            content += QStringLiteral("FrameID: %1\n").arg(record->Type.MiniFilter.FrameID);
            content += QStringLiteral("VolumeFileSystemType: %1\n")
                .arg(filterFilesystemTypeToText(record->Type.MiniFilter.VolumeFileSystemType));
        }
        content += QStringLiteral("Altitude: %1\n").arg(altitude.isEmpty() ? QStringLiteral("<unknown>") : altitude);
        content += QStringLiteral("VolumeName: %1\n").arg(volumeName.isEmpty() ? QStringLiteral("<unknown>") : volumeName);
        content += QStringLiteral("FilterName: %1\n").arg(filterName.isEmpty() ? QStringLiteral("<unknown>") : filterName);
    }

    // enumerateInstanceText：枚举全部 minifilter/legacy instance，给出 Volume 关联摘要。
    // 输入：无。
    // 返回：实例列表的只读文本。
    QString enumerateInstanceText()
    {
        QString content;
        content += QStringLiteral("[Instance]\n");
        content += QStringLiteral("枚举来源: FilterInstanceFindFirst / FilterInstanceFindNext\n");
        content += QStringLiteral("展示字段: InstanceName, Altitude, VolumeName, FilterName, VolumeFileSystemType\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE findHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterFindFirst(
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &findHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 无法先枚举 Filter 列表 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        for (;;)
        {
            const auto* filterRecord = reinterpret_cast<const FILTER_AGGREGATE_STANDARD_INFORMATION*>(buffer.data());
            const bool isMinifilter = (filterRecord->Flags & FLTFL_ASI_IS_MINIFILTER) != 0;
            const QString filterName = isMinifilter
                ? readUtf16FieldAtOffset(buffer.data(), bytesReturned, filterRecord->Type.MiniFilter.FilterNameBufferOffset, filterRecord->Type.MiniFilter.FilterNameLength)
                : readUtf16FieldAtOffset(buffer.data(), bytesReturned, filterRecord->Type.LegacyFilter.FilterNameBufferOffset, filterRecord->Type.LegacyFilter.FilterNameLength);
            if (!filterName.isEmpty())
            {
                content += QStringLiteral("\n[Filter] %1\n").arg(filterName);
            }

            HANDLE instanceHandle = nullptr;
            std::vector<std::uint8_t> instanceBuffer(16U * 1024U, 0U);
            DWORD instanceBytesReturned = 0;
            if (!filterName.isEmpty())
            {
                for (;;)
                {
                    hr = ::FilterInstanceFindFirst(
                        filterName.toStdWString().c_str(),
                        InstanceAggregateStandardInformation,
                        instanceBuffer.data(),
                        static_cast<DWORD>(instanceBuffer.size()),
                        &instanceBytesReturned,
                        &instanceHandle);
                    if (SUCCEEDED(hr))
                    {
                        break;
                    }
                    if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                    {
                        instanceBuffer.resize(instanceBuffer.size() * 2U);
                        continue;
                    }
                    break;
                }
                if (SUCCEEDED(hr))
                {
                    for (;;)
                    {
                        content += QStringLiteral("  - ");
                        appendInstanceRecordText(content, instanceBuffer.data(), instanceBytesReturned);
                        content += QStringLiteral("\n");

                        instanceBytesReturned = 0;
                        hr = ::FilterInstanceFindNext(
                            instanceHandle,
                            InstanceAggregateStandardInformation,
                            instanceBuffer.data(),
                            static_cast<DWORD>(instanceBuffer.size()),
                            &instanceBytesReturned);
                        if (SUCCEEDED(hr))
                        {
                            continue;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
                        {
                            break;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                        {
                            instanceBuffer.resize(instanceBuffer.size() * 2U);
                            continue;
                        }
                        content += QStringLiteral("  ! 继续枚举实例失败 HRESULT=0x%1\n")
                            .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                        break;
                    }
                }
                else
                {
                    content += QStringLiteral("  ! FilterInstanceFindFirst 失败 HRESULT=0x%1\n")
                        .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                }
            }

            bytesReturned = 0;
            hr = ::FilterFindNext(
                findHandle,
                FilterAggregateStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举 Filter 失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (findHandle != nullptr)
        {
            ::FilterFindClose(findHandle);
        }
        return content;
    }

    // appendVolumeRecordText：把单条 Volume 枚举记录压成可读文本。
    // 输入：buffer/bytesReturned 为 FilterVolumeFindFirst/Next 返回数据。
    // 返回：无；直接追加到 content。
    void appendVolumeRecordText(
        QString& content,
        const void* buffer,
        const std::size_t bytesReturned)
    {
        if (buffer == nullptr || bytesReturned < sizeof(FILTER_VOLUME_STANDARD_INFORMATION))
        {
            return;
        }

        const auto* record = reinterpret_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer);
        const QString volumeName = readUtf16FieldAtOffset(
            buffer,
            bytesReturned,
            offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName),
            record->FilterVolumeNameLength);
        content += QStringLiteral("卷名: %1\n").arg(volumeName.isEmpty() ? QStringLiteral("<unknown>") : volumeName);
        content += QStringLiteral("Flags: 0x%1\n").arg(record->Flags, 8, 16, QChar('0')).toUpper();
        content += QStringLiteral("FrameID: %1\n").arg(record->FrameID);
        content += QStringLiteral("FileSystemType: %1\n").arg(filterFilesystemTypeToText(record->FileSystemType));
    }

    // enumerateVolumeText：枚举 FilterManager 公开 Volume 列表并给出卷栈关联摘要。
    // 输入：无。
    // 返回：Volume 列表与可见状态文本。
    QString enumerateVolumeText()
    {
        QString content;
        content += QStringLiteral("[Volume]\n");
        content += QStringLiteral("枚举来源: FilterVolumeFindFirst / FilterVolumeFindNext\n");
        content += QStringLiteral("展示字段: VolumeName, FileSystemType, FrameID, Flags, AttachedInstances\n");

        std::vector<std::uint8_t> buffer(16U * 1024U, 0U);
        DWORD bytesReturned = 0;
        HANDLE volumeHandle = nullptr;
        HRESULT hr = E_FAIL;
        for (;;)
        {
            hr = ::FilterVolumeFindFirst(
                FilterVolumeStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned,
                &volumeHandle);
            if (SUCCEEDED(hr))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("状态: 枚举失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            return content;
        }

        for (;;)
        {
            content += QStringLiteral("\n");
            appendVolumeRecordText(content, buffer.data(), bytesReturned);

            const auto* volumeRecord = reinterpret_cast<const FILTER_VOLUME_STANDARD_INFORMATION*>(buffer.data());
            const QString volumeName = readUtf16FieldAtOffset(
                buffer.data(),
                bytesReturned,
                offsetof(FILTER_VOLUME_STANDARD_INFORMATION, FilterVolumeName),
                volumeRecord->FilterVolumeNameLength);
            if (!volumeName.isEmpty())
            {
                HANDLE instanceHandle = nullptr;
                std::vector<std::uint8_t> instanceBuffer(16U * 1024U, 0U);
                DWORD instanceBytesReturned = 0;
                if (!volumeName.isEmpty())
                {
                    for (;;)
                    {
                        hr = ::FilterVolumeInstanceFindFirst(
                            volumeName.toStdWString().c_str(),
                            InstanceAggregateStandardInformation,
                            instanceBuffer.data(),
                            static_cast<DWORD>(instanceBuffer.size()),
                            &instanceBytesReturned,
                            &instanceHandle);
                        if (SUCCEEDED(hr))
                        {
                            break;
                        }
                        if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                        {
                            instanceBuffer.resize(instanceBuffer.size() * 2U);
                            continue;
                        }
                        break;
                    }
                    if (SUCCEEDED(hr))
                    {
                        content += QStringLiteral("AttachedInstances:\n");
                        for (;;)
                        {
                            content += QStringLiteral("  - ");
                            appendInstanceRecordText(content, instanceBuffer.data(), instanceBytesReturned);
                            content += QStringLiteral("\n");

                            instanceBytesReturned = 0;
                            hr = ::FilterVolumeInstanceFindNext(
                                instanceHandle,
                                InstanceAggregateStandardInformation,
                                instanceBuffer.data(),
                                static_cast<DWORD>(instanceBuffer.size()),
                                &instanceBytesReturned);
                            if (SUCCEEDED(hr))
                            {
                                continue;
                            }
                            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
                            {
                                break;
                            }
                            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
                            {
                                instanceBuffer.resize(instanceBuffer.size() * 2U);
                                continue;
                            }
                            content += QStringLiteral("  ! 继续枚举卷实例失败 HRESULT=0x%1\n")
                                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                            break;
                        }
                    }
                    else
                    {
                        content += QStringLiteral("AttachedInstances: FilterVolumeInstanceFindFirst 失败 HRESULT=0x%1\n")
                            .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
                    }
                }
            }

            bytesReturned = 0;
            hr = ::FilterVolumeFindNext(
                volumeHandle,
                FilterVolumeStandardInformation,
                buffer.data(),
                static_cast<DWORD>(buffer.size()),
                &bytesReturned);
            if (SUCCEEDED(hr))
            {
                continue;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS))
            {
                break;
            }
            if (hr == HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) || hr == HRESULT_FROM_WIN32(ERROR_MORE_DATA))
            {
                buffer.resize(buffer.size() * 2U);
                continue;
            }
            content += QStringLiteral("继续枚举 Volume 失败 HRESULT=0x%1\n")
                .arg(static_cast<qulonglong>(static_cast<unsigned long>(hr)), 8, 16, QChar('0')).toUpper();
            break;
        }

        if (volumeHandle != nullptr)
        {
            ::FilterVolumeFindClose(volumeHandle);
        }
        return content;
    }

    // queryBitLockerVolumeText 作用：
    // - 用途：给出 Win32_EncryptableVolume 视角的 BitLocker 只读状态文本；
    // - 入参：driveLetter 为目标盘符（例如 C:）；
    // - 返回：可直接展示的状态文本。
    // 说明：这里原本会 CoInitializeEx + CoCreateInstance(CLSID_WbemLocator) +
    // ConnectServer(ROOT\CIMV2\Security\MicrosoftVolumeEncryption) + CoSetProxyBlanket，
    // 但把 SELECT 语句拼出来之后从来没有 ExecQuery，最终仍旧只输出下面这一句降级文本；
    // 也就是说整条 WMI 连接链（冷启动要拉起 provider host，几百毫秒到数秒）是白付的成本。
    // 在真正实现 ExecQuery 之前直接返回同一句降级文本，不再连接 WMI；
    // BitLocker 的真实可见状态由 Storage 页的“R0 审计补充 / BitLocker FVE”段落给出。
    QString queryBitLockerVolumeText(const QString& driveLetter)
    {
        if (driveLetter.trimmed().isEmpty())
        {
            return QStringLiteral("BitLocker: <无盘符>");
        }

        return QStringLiteral("BitLocker WMI: 查询语句已准备，当前版本保留降级文本展示。");
    }

    bool isCriticalProcessName(const QString& processName)
    {
        const QString normalizedName = processName.trimmed().toLower();
        if (normalizedName.isEmpty())
        {
            return false;
        }

        static const std::set<QString> criticalNameSet =
        {
            QStringLiteral("smss.exe"),
            QStringLiteral("csrss.exe"),
            QStringLiteral("wininit.exe"),
            QStringLiteral("services.exe"),
            QStringLiteral("lsass.exe"),
            QStringLiteral("winlogon.exe")
        };
        return criticalNameSet.find(normalizedName) != criticalNameSet.end();
    }

    // isPathReparsePoint：
    // - 作用：判断目标路径是否为重解析点（符号链接/Junction 等）；
    // - 用于目录递归删除时避免误跟进到链接目标。
    bool isPathReparsePoint(const QString& path)
    {
        const std::wstring nativePathText = QDir::toNativeSeparators(path).toStdWString();
        if (nativePathText.empty())
        {
            return false;
        }

        const DWORD fileAttributes = ::GetFileAttributesW(nativePathText.c_str());
        if (fileAttributes == INVALID_FILE_ATTRIBUTES)
        {
            return false;
        }
        return (fileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U;
    }

    QString formatWin32ErrorText(const std::uint32_t errorCode)
    {
        if (errorCode == ERROR_SUCCESS)
        {
            return QStringLiteral("0");
        }

        wchar_t* messageBuffer = nullptr;
        const DWORD chars = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);
        QString messageText;
        if (chars > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer, static_cast<int>(chars)).trimmed();
        }
        if (messageBuffer != nullptr)
        {
            ::LocalFree(messageBuffer);
        }
        return messageText.isEmpty()
            ? QString::number(errorCode)
            : QStringLiteral("%1 (%2)").arg(errorCode).arg(messageText);
    }

    QString formatReparseTagText(const std::uint32_t tagValue)
    {
        return QStringLiteral("0x%1")
            .arg(tagValue, 8, 16, QChar('0'))
            .toUpper();
    }

    ks::file::ReparsePointQueryResult queryReparsePointForUi(const QString& path)
    {
        const QString nativePathText = QDir::toNativeSeparators(path).trimmed();
        if (nativePathText.isEmpty())
        {
            ks::file::ReparsePointQueryResult result{};
            result.errorText = L"路径为空。";
            result.win32Error = ERROR_INVALID_PARAMETER;
            return result;
        }

        const DWORD attributes = ::GetFileAttributesW(nativePathText.toStdWString().c_str());
        const bool directoryHint = attributes != INVALID_FILE_ATTRIBUTES
            && ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U);
        return ks::file::QueryReparsePointInfo(nativePathText.toStdWString(), directoryHint);
    }

    // reparseKindMarkerForBatch 作用：
    // - 供平铺模型批量回填时使用的重解析点标记查询；
    // - 与 reparseKindMarkerForPath 的区别在于**限额**：整批回填最多做
    //   kMaxBatchReparseProbes 次同步查询，超出后一律返回空。
    // 为什么要限额：
    // - 每一行都要 GetFileAttributesW，重解析点行还要再打开文件发 FSCTL，
    //   全都是 UI 线程上的同步文件 IO；
    // - R0/IRP 读取方式本来就是用来看"WinAPI 视角有问题"的路径，对这些路径
    //   Win32 查询可能长时间阻塞甚至挂住，一行卡住整个界面就没响应了；
    // - 上万行的目录即使每行只花几十微秒，累计也是秒级卡顿。
    // 代价是超出限额的行不显示重解析点标记，这比界面失去响应好得多。
    constexpr int kMaxBatchReparseProbes = 512;

    QString reparseKindMarkerForPath(const QString& path)
    {
        const QString nativePathText = QDir::toNativeSeparators(path).trimmed();
        if (nativePathText.isEmpty())
        {
            return QString();
        }

        const DWORD attributes = ::GetFileAttributesW(nativePathText.toStdWString().c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0U)
        {
            return QString();
        }

        const ks::file::ReparsePointQueryResult result = queryReparsePointForUi(nativePathText);
        const QString kindText = QString::fromStdWString(result.kindName).trimmed();
        return kindText.isEmpty() ? QStringLiteral("UNKNOWN_REPARSE") : kindText;
    }

    QString reparseTargetFromResult(const ks::file::ReparsePointQueryResult& result)
    {
        QString targetText = QString::fromStdWString(result.resolvedTargetPath).trimmed();
        if (targetText.isEmpty())
        {
            targetText = QString::fromStdWString(result.printName).trimmed();
        }
        if (targetText.isEmpty())
        {
            targetText = QString::fromStdWString(result.substituteName).trimmed();
        }
        return QDir::toNativeSeparators(targetText);
    }

    QString formatReparsePointText(const QString& path)
    {
        const ks::file::ReparsePointQueryResult result = queryReparsePointForUi(path);
        QString content;
        content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(path));

        if (!result.pathOpened)
        {
            content += QStringLiteral("状态: 无法打开目标（使用 FILE_FLAG_OPEN_REPARSE_POINT）\n");
            content += QStringLiteral("Win32错误: %1\n").arg(formatWin32ErrorText(result.win32Error));
            content += QStringLiteral("原因: %1\n").arg(QString::fromStdWString(result.errorText));
            return content;
        }

        if (!result.querySucceeded)
        {
            content += QStringLiteral("状态: FSCTL_GET_REPARSE_POINT 查询失败\n");
            content += QStringLiteral("是否重解析点: %1\n").arg(result.isReparsePoint ? QStringLiteral("是") : QStringLiteral("否"));
            content += QStringLiteral("Win32错误: %1\n").arg(formatWin32ErrorText(result.win32Error));
            content += QStringLiteral("原因: %1\n").arg(QString::fromStdWString(result.errorText));
            return content;
        }

        content += QStringLiteral("状态: OK\n");
        content += QStringLiteral("Reparse Tag: %1\n").arg(formatReparseTagText(result.tag));
        content += QStringLiteral("Tag名称: %1\n").arg(QString::fromStdWString(result.tagName));
        content += QStringLiteral("类型标记: %1\n").arg(QString::fromStdWString(result.kindName));
        content += QStringLiteral("Microsoft Tag: %1\n").arg(result.isMicrosoftTag ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("Name Surrogate: %1\n").arg(result.isNameSurrogate ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("是否相对链接: %1\n").arg(result.isRelative ? QStringLiteral("是") : QStringLiteral("否"));
        content += QStringLiteral("Substitute Name: %1\n").arg(QString::fromStdWString(result.substituteName));
        content += QStringLiteral("Print Name: %1\n").arg(QString::fromStdWString(result.printName));
        content += QStringLiteral("解析目标路径: %1\n").arg(reparseTargetFromResult(result));
        content += QStringLiteral("原始信息: %1\n").arg(QString::fromStdWString(result.rawPayloadText));
        content += QStringLiteral("Raw Hex Preview: %1\n").arg(QString::fromStdWString(result.rawHexPreview));
        if (!result.errorText.empty())
        {
            content += QStringLiteral("解析提示: %1\n").arg(QString::fromStdWString(result.errorText));
        }
        return content;
    }

    class ReparseAwareFileSystemModel final : public QFileSystemModel
    {
    public:
        explicit ReparseAwareFileSystemModel(QObject* parent = nullptr)
            : QFileSystemModel(parent)
        {
        }

        QVariant data(const QModelIndex& index, const int role = Qt::DisplayRole) const override
        {
            const QVariant baseValue = QFileSystemModel::data(index, role);
            if (!index.isValid())
            {
                return baseValue;
            }

            if (role != Qt::DisplayRole && role != Qt::ToolTipRole)
            {
                return baseValue;
            }

            QVariant localizedBaseValue = baseValue;
            if (role == Qt::DisplayRole &&
                (index.column() == 1 || index.column() == 2) &&
                baseValue.metaType().id() == QMetaType::QString)
            {
                localizedBaseValue = ks::i18n::displayText(baseValue.toString());
            }

            const QString markerText = reparseKindMarkerForPath(filePath(index));
            if (markerText.isEmpty())
            {
                return localizedBaseValue;
            }
            const QString localizedMarkerText = ks::i18n::displayText(markerText);

            if (role == Qt::ToolTipRole)
            {
                QString toolTipText = baseValue.toString();
                if (!toolTipText.isEmpty())
                {
                    toolTipText += QLatin1Char('\n');
                }
                toolTipText += ks::i18n::displayText(QStringLiteral("重解析点: %1"))
                    .arg(localizedMarkerText);
                return toolTipText;
            }

            if (index.column() == 0)
            {
                return QStringLiteral("%1 [%2]").arg(baseValue.toString(), localizedMarkerText);
            }
            if (index.column() == 2)
            {
                const QString typeText = localizedBaseValue.toString().trimmed();
                return typeText.isEmpty()
                    ? localizedMarkerText
                    : QStringLiteral("%1 / %2").arg(localizedMarkerText, typeText);
            }
            return localizedBaseValue;
        }

        QVariant headerData(
            const int section,
            const Qt::Orientation orientation,
            const int role = Qt::DisplayRole) const override
        {
            const QVariant baseValue = QFileSystemModel::headerData(section, orientation, role);
            if (orientation == Qt::Horizontal
                && role == Qt::DisplayRole
                && baseValue.metaType().id() == QMetaType::QString)
            {
                return ks::i18n::displayText(baseValue.toString());
            }
            return baseValue;
        }
    };

    // buildDriverNtPath：
    // - 作用：把 Win32 路径转成驱动可直接使用的 NT 路径；
    // - 规则：普通盘符路径转成 \??\C:\...，UNC 路径转成 \??\UNC\...
    QString buildDriverNtPath(const QString& path)
    {
        const QString nativePathText = QDir::toNativeSeparators(path).trimmed();
        if (nativePathText.isEmpty())
        {
            return QString();
        }
        if (nativePathText.startsWith(QStringLiteral("\\??\\")))
        {
            return nativePathText;
        }
        if (nativePathText.startsWith(QStringLiteral("\\\\?\\")))
        {
            return QStringLiteral("\\??\\") + nativePathText.mid(4);
        }
        if (nativePathText.startsWith(QStringLiteral("\\Device\\")))
        {
            return nativePathText;
        }
        if (nativePathText.startsWith(QStringLiteral("\\\\")))
        {
            return QStringLiteral("\\??\\UNC\\") + nativePathText.mid(2);
        }
        return QStringLiteral("\\??\\") + nativePathText;
    }

    // buildLiteralNameFilterPattern：
    // - 作用：把关键字转成 QFileSystemModel::setNameFilters 可用的“包含匹配”通配符；
    // - 说明：对 *, ?, [, ] 做转义，避免用户输入被当作通配符语法。
    QString buildLiteralNameFilterPattern(const QString& keywordText)
    {
        QString escapedKeyword = keywordText;
        escapedKeyword.replace(QStringLiteral("["), QStringLiteral("[[]"));
        escapedKeyword.replace(QStringLiteral("]"), QStringLiteral("[]]"));
        escapedKeyword.replace(QStringLiteral("*"), QStringLiteral("[*]"));
        escapedKeyword.replace(QStringLiteral("?"), QStringLiteral("[?]"));
        return QStringLiteral("*%1*").arg(escapedKeyword);
    }

    // queryShortPathText：
    // - 作用：查询目标路径对应的 Win32 短路径（8.3）；
    // - 失败时返回空字符串，调用方可决定是否走原名兜底。
    QString queryShortPathText(const QString& path)
    {
        const std::wstring nativePathText = QDir::toNativeSeparators(path).toStdWString();
        if (nativePathText.empty())
        {
            return QString();
        }

        const DWORD requiredChars = ::GetShortPathNameW(nativePathText.c_str(), nullptr, 0);
        if (requiredChars == 0)
        {
            return QString();
        }

        QVector<wchar_t> shortPathBuffer(static_cast<int>(requiredChars) + 2, L'\0');
        const DWORD copiedChars = ::GetShortPathNameW(
            nativePathText.c_str(),
            shortPathBuffer.data(),
            static_cast<DWORD>(shortPathBuffer.size()));
        if (copiedChars == 0 || copiedChars >= static_cast<DWORD>(shortPathBuffer.size()))
        {
            return QString();
        }
        return QString::fromWCharArray(shortPathBuffer.data(), static_cast<int>(copiedChars));
    }

    QString normalizeFileDockPath(const QString& path)
    {
        return QDir::toNativeSeparators(QDir::cleanPath(path.trimmed()));
    }

    bool pathEqualsCaseInsensitive(const QString& left, const QString& right)
    {
        return normalizeFileDockPath(left).compare(
            normalizeFileDockPath(right),
            Qt::CaseInsensitive) == 0;
    }

    void closeWin32Handle(HANDLE& handleValue)
    {
        if (handleValue != nullptr && handleValue != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(handleValue);
            handleValue = INVALID_HANDLE_VALUE;
        }
    }

    QString oplockCompletionText(const bool completionOk, const unsigned long completionError)
    {
        if (completionOk)
        {
            return QStringLiteral("已触发/完成");
        }
        if (completionError == ERROR_OPERATION_ABORTED)
        {
            return QStringLiteral("已取消");
        }
        if (completionError == ERROR_HANDLE_EOF)
        {
            return QStringLiteral("目标句柄已关闭");
        }
        return QStringLiteral("完成失败，Win32=%1").arg(completionError);
    }

    // openKswordArkDriverHandle：
    // - 作用：通过 ArkDriverClient 连接 KswordARK 控制设备；
    // - 返回 move-only 句柄对象，避免 Dock 直接 CloseHandle。
    ksword::ark::DriverHandle openKswordArkDriverHandle(std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        const ksword::ark::DriverClient driverClient;
        ksword::ark::DriverHandle driverHandle = driverClient.open();
        if (driverHandle.isValid())
        {
            return driverHandle;
        }

        if (detailTextOut != nullptr)
        {
            const DWORD lastError = ::GetLastError();
            std::ostringstream oss;
            oss << "open KswordARK driver failed, error=" << lastError;
            *detailTextOut = oss.str();
        }
        return driverHandle;
    }

    // deletePathByR0Driver：
    // - 作用：向 ArkDriverClient 发送“删除单一路径”IOCTL；
    // - 参数 isDirectory 用于驱动端选择目录/文件打开语义。
    bool deletePathByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const QString& path,
        const bool isDirectory,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid driver handle";
            }
            return false;
        }

        const QString driverNtPath = buildDriverNtPath(path);
        if (driverNtPath.isEmpty())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "empty path";
            }
            return false;
        }

        const std::wstring ntPathText = driverNtPath.toStdWString();
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult result = driverClient.deletePath(driverHandle, ntPathText, isDirectory);
        if (detailTextOut != nullptr)
        {
            std::ostringstream oss;
            oss << "path=" << QDir::toNativeSeparators(path).toStdString()
                << ", directory=" << (isDirectory ? 1 : 0)
                << ", bytesReturned=" << result.bytesReturned;
            if (result.ok)
            {
                oss << ", ioctl=ok";
            }
            else
            {
                oss << ", ioctl=fail, error=" << result.win32Error;
                if (!result.message.empty())
                {
                    oss << ", detail=" << result.message;
                }
            }
            *detailTextOut = oss.str();
        }
        return result.ok;
    }

    bool shouldFallbackFileIntegrityToR3(
        const ksword::ark::IoResult& io,
        const bool unsupported)
    {
        // 输入：ArkDriverClient 的通信结果和 unsupported 标记。
        // 处理：只把驱动未装载、旧驱动缺 IOCTL 或请求无法通过当前 R0 协议发送归类为 R3 fallback。
        // 返回：true 表示可尝试 R3；R0 已返回语义失败时返回 false，避免掩盖 ZwSetSecurityObject 失败原因。
        if (io.ok)
        {
            return false;
        }
        if (unsupported)
        {
            return true;
        }

        return io.win32Error == ERROR_FILE_NOT_FOUND ||
            io.win32Error == ERROR_PATH_NOT_FOUND ||
            io.win32Error == ERROR_SERVICE_DOES_NOT_EXIST ||
            io.win32Error == ERROR_INVALID_FUNCTION ||
            io.win32Error == ERROR_NOT_SUPPORTED ||
            io.win32Error == ERROR_INVALID_PARAMETER;
    }

    DWORD setFileIntegrityLevelByR0ThenR3(
        const QString& filePath,
        const DWORD integrityRid,
        QString* const detailText)
    {
        // 输入：Win32/Qt 文件路径和 Mandatory Label RID。
        // 处理：先将路径转换为驱动 NT 路径并调用 R0；驱动不可用/旧驱动时回退 SetNamedSecurityInfoW。
        // 返回：ERROR_SUCCESS 表示 R0 或 fallback R3 成功；失败时返回 Win32 或 NTSTATUS 数值并写入 detailText。
        if (!isSupportedFileMandatoryIntegrityRid(integrityRid))
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("unsupported file mandatory label RID=0x%1; "
                    "file objects only support Untrusted/Low/Medium/MediumPlus/High/System")
                    .arg(integrityRid, 0, 16);
            }
            return ERROR_INVALID_PARAMETER;
        }

        const QString driverNtPath = buildDriverNtPath(filePath);
        if (driverNtPath.isEmpty())
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("empty path");
            }
            return ERROR_INVALID_PARAMETER;
        }

        const QFileInfo fileInfo(filePath);
        const bool isDirectory = fileInfo.isDir();
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::FileIntegrityResult r0Result =
            driverClient.setFileIntegrity(driverNtPath.toStdWString(), isDirectory, integrityRid);
        const bool r0Applied = r0Result.io.ok &&
            r0Result.status == KSWORD_ARK_FILE_INTEGRITY_STATUS_APPLIED &&
            r0Result.lastStatus >= 0;
        if (r0Applied)
        {
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("R0 ok: %1, ntPath=%2")
                    .arg(QString::fromStdString(r0Result.io.message))
                    .arg(driverNtPath);
            }
            return ERROR_SUCCESS;
        }

        if (shouldFallbackFileIntegrityToR3(r0Result.io, r0Result.unsupported))
        {
            QString r3DetailText;
            const DWORD r3Result = setFileIntegrityLevelByPath(
                filePath,
                integrityRid,
                &r3DetailText);
            if (detailText != nullptr)
            {
                *detailText = QStringLiteral("R0 unavailable/unsupported: %1 | R3 %2: %3")
                    .arg(QString::fromStdString(r0Result.io.message))
                    .arg(r3Result == ERROR_SUCCESS ? QStringLiteral("ok") : QStringLiteral("failed"))
                    .arg(r3DetailText.isEmpty() ? QStringLiteral("no detail") : r3DetailText);
            }
            return r3Result;
        }

        if (detailText != nullptr)
        {
            *detailText = QStringLiteral("R0 failed: %1, status=%2, nt=0x%3, win32=%4, ntPath=%5")
                .arg(QString::fromStdString(r0Result.io.message))
                .arg(r0Result.status)
                .arg(static_cast<unsigned long>(r0Result.lastStatus), 0, 16)
                .arg(r0Result.io.win32Error)
                .arg(driverNtPath);
        }
        if (!r0Result.io.ok)
        {
            return r0Result.io.win32Error == ERROR_SUCCESS
                ? ERROR_GEN_FAILURE
                : r0Result.io.win32Error;
        }
        return r0Result.lastStatus == 0
            ? ERROR_GEN_FAILURE
            : static_cast<DWORD>(r0Result.lastStatus);
    }

    // terminateProcessByR0Driver：
    // - 作用：复用同一个 ArkDriverClient 句柄发送结束进程 IOCTL；
    // - 返回值：true=驱动返回成功，false=驱动返回失败或句柄无效。
    bool terminateProcessByR0Driver(
        ksword::ark::DriverHandle& driverHandle,
        const std::uint32_t processId,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (!driverHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid driver handle";
            }
            return false;
        }

        if (processId == 0U || processId <= 4U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::IoResult result = driverClient.terminateProcess(
            driverHandle,
            processId,
            static_cast<long>(0xC0000005u));
        if (detailTextOut != nullptr)
        {
            *detailTextOut = result.message;
        }
        return result.ok;
    }

    bool terminateProcessByR3(
        const std::uint32_t processId,
        const std::uint64_t expectedCreationTime,
        std::string* const detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        if (processId == 0U || processId <= 4U || processId == static_cast<std::uint32_t>(::GetCurrentProcessId()))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "invalid target pid";
            }
            return false;
        }

        // 用扫描时的创建时间复核 PID，并通过同一个已验证句柄结束进程。
        // 持有该句柄期间旧进程对象不会销毁，因此 PID 不能被复用到另一个进程。
        HANDLE processHandle = nullptr;
        std::string identityDetailText;
        if (!ks::file::OpenProcessForVerifiedAction(
                processId,
                expectedCreationTime,
                PROCESS_TERMINATE | SYNCHRONIZE,
                processHandle,
                identityDetailText))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = identityDetailText;
            }
            return false;
        }

        const BOOL terminateResult = ::TerminateProcess(processHandle, static_cast<UINT>(0xC0000005U));
        const DWORD terminateError = terminateResult == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(processHandle);
        const bool terminateOk = terminateResult != FALSE;

        if (detailTextOut != nullptr)
        {
            std::ostringstream oss;
            oss << "pid=" << processId;
            if (terminateOk)
            {
                oss << ", TerminateProcess=ok";
            }
            else
            {
                oss << ", TerminateProcess=fail, error=" << terminateError;
            }
            *detailTextOut = oss.str();
        }
        return terminateOk;
    }

    // showUnlockSelectionDialog：
    // - 作用：展示文件解锁器扫描结果，并让用户选择关闭句柄或结束进程；
    // - 参数 parent：父窗口，用于模态弹窗归属；
    // - 参数 processCandidateList：按 PID 聚合后的占用进程列表；
    // - 参数 handleCandidateList：按 PID+Handle 展开的可关闭句柄列表；
    // - 返回：用户确认的操作模式与选中目标；取消时 accepted=false。
    UnlockSelectionResult showUnlockSelectionDialog(
        QWidget* const parent,
        const std::vector<UnlockProcessCandidate>& processCandidateList,
        const std::vector<UnlockHandleCandidate>& handleCandidateList)
    {
        UnlockSelectionResult result;
        if (processCandidateList.empty() && handleCandidateList.empty())
        {
            return result;
        }

        QDialog dialog(parent);
        dialog.setObjectName(QStringLiteral("FileUnlockerSelectionDialog"));
        dialog.setStyleSheet(buildOpaqueStandaloneDialogStyle(dialog.objectName()));
        dialog.setWindowTitle(QStringLiteral("文件解锁器 - 选择操作目标"));
        dialog.resize(1080, 620);

        QVBoxLayout* const rootLayout = new QVBoxLayout(&dialog);
        QLabel* const tipLabel = new QLabel(
            QStringLiteral("已扫描到以下占用来源。建议先关闭选中句柄；若仍无法删除/重命名，再改用结束进程兜底。未勾选的目标不会处理。"),
            &dialog);
        tipLabel->setWordWrap(true);
        rootLayout->addWidget(tipLabel);

        QHBoxLayout* const modeLayout = new QHBoxLayout();
        QLabel* const modeLabel = new QLabel(QStringLiteral("操作方式："), &dialog);
        QComboBox* const modeComboBox = new QComboBox(&dialog);
        const bool hasClosableHandle = std::any_of(
            handleCandidateList.begin(),
            handleCandidateList.end(),
            [](const UnlockHandleCandidate& candidate) {
                return candidate.handleValue != 0U
                    && candidate.processCreationTime != 0U
                    && !candidate.matchedTargetPath.trimmed().isEmpty()
                    && candidate.processId > 4U
                    && !candidate.isCurrentProcess
                    && !candidate.isCriticalProcess;
            });
        modeComboBox->addItem(QStringLiteral("关闭选中句柄(R3，推荐先尝试)"));
        modeComboBox->addItem(QStringLiteral("结束选中进程(R3)"));
        modeComboBox->addItem(QStringLiteral("结束选中进程(R0，更强力)"));
        if (!hasClosableHandle)
        {
            modeComboBox->setCurrentIndex(1);
        }
        modeLayout->addWidget(modeLabel);
        modeLayout->addWidget(modeComboBox, 1);
        rootLayout->addLayout(modeLayout);

        QStackedWidget* const tableStack = new QStackedWidget(&dialog);
        QTableWidget* const handleTable = new ks::ui::VisibleTableWidget(static_cast<int>(handleCandidateList.size()), 7, &dialog);
        handleTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("选择"),
            QStringLiteral("PID"),
            QStringLiteral("进程名"),
            QStringLiteral("Handle"),
            QStringLiteral("GrantedAccess"),
            QStringLiteral("命中路径"),
            QStringLiteral("说明") });
        handleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        handleTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        handleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        handleTable->verticalHeader()->setVisible(false);
        handleTable->horizontalHeader()->setStretchLastSection(true);
        installFileTableCopyMenu(handleTable, 1);

        QTableWidget* const processTable = new ks::ui::VisibleTableWidget(static_cast<int>(processCandidateList.size()), 6, &dialog);
        processTable->setHorizontalHeaderLabels(QStringList{
            QStringLiteral("选择"),
            QStringLiteral("PID"),
            QStringLiteral("进程名"),
            QStringLiteral("命中数"),
            QStringLiteral("命中路径"),
            QStringLiteral("说明") });
        processTable->setSelectionBehavior(QAbstractItemView::SelectRows);
        processTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
        processTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
        processTable->verticalHeader()->setVisible(false);
        processTable->horizontalHeader()->setStretchLastSection(true);
        installFileTableCopyMenu(processTable, 1);

        auto makeTableItem = [](const QString& text, const bool enabled) {
            QTableWidgetItem* const item = new QTableWidgetItem(text);
            item->setFlags(enabled
                ? (Qt::ItemIsSelectable | Qt::ItemIsEnabled)
                : Qt::ItemIsSelectable);
            return item;
            };

        for (int row = 0; row < static_cast<int>(handleCandidateList.size()); ++row)
        {
            const UnlockHandleCandidate& candidate = handleCandidateList[static_cast<std::size_t>(row)];
            const bool canCloseHandle = candidate.handleValue != 0U
                && candidate.processCreationTime != 0U
                && !candidate.matchedTargetPath.trimmed().isEmpty()
                && !candidate.isCurrentProcess
                && !candidate.isCriticalProcess
                && candidate.processId > 4U;

            QTableWidgetItem* const checkItem = new QTableWidgetItem();
            checkItem->setCheckState(Qt::Unchecked);
            checkItem->setData(Qt::UserRole, row);
            checkItem->setFlags(canCloseHandle
                ? (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable | Qt::ItemIsEnabled)
                : (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable));
            handleTable->setItem(row, 0, checkItem);

            QStringList noteList;
            appendUniqueText(noteList, candidate.objectName);
            appendUniqueText(noteList, candidate.processImagePath);
            appendUniqueText(noteList, candidate.matchRuleText);
            appendUniqueText(noteList, candidate.enumerationSource);
            if (candidate.handleValue == 0U)
            {
                noteList.push_back(QStringLiteral("无句柄值：该来源可能是进程映像/模块映射，不能用 R3 关闭句柄处理"));
            }
            if (candidate.isCurrentProcess)
            {
                noteList.push_back(QStringLiteral("已保护：当前 Ksword 进程，不可关闭句柄"));
            }
            if (candidate.isCriticalProcess)
            {
                noteList.push_back(QStringLiteral("已保护：关键系统进程，不可关闭句柄"));
            }
            if (candidate.processCreationTime == 0U || candidate.matchedTargetPath.trimmed().isEmpty())
            {
                noteList.push_back(QStringLiteral("身份不可验证：请重新扫描后再操作"));
            }

            handleTable->setItem(row, 1, makeTableItem(QString::number(candidate.processId), canCloseHandle));
            handleTable->setItem(row, 2, makeTableItem(candidate.processName.isEmpty() ? QStringLiteral("Unknown") : candidate.processName, canCloseHandle));
            handleTable->setItem(row, 3, makeTableItem(formatHandleValueText(candidate.handleValue), canCloseHandle));
            handleTable->setItem(row, 4, makeTableItem(formatHandleValueText(candidate.grantedAccess), canCloseHandle));
            handleTable->setItem(row, 5, makeTableItem(candidate.matchedTargetPath, canCloseHandle));
            handleTable->setItem(row, 6, makeTableItem(noteList.join(QStringLiteral("\n")), canCloseHandle));
        }

        for (int row = 0; row < static_cast<int>(processCandidateList.size()); ++row)
        {
            const UnlockProcessCandidate& candidate = processCandidateList[static_cast<std::size_t>(row)];
            const bool protectedProcess = candidate.isCurrentProcess
                || candidate.isCriticalProcess
                || candidate.processCreationTime == 0U;

            QTableWidgetItem* const checkItem = new QTableWidgetItem();
            checkItem->setCheckState(Qt::Unchecked);
            checkItem->setData(Qt::UserRole, static_cast<qulonglong>(candidate.processId));
            checkItem->setFlags(protectedProcess
                ? (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable)
                : (Qt::ItemIsUserCheckable | Qt::ItemIsSelectable | Qt::ItemIsEnabled));
            processTable->setItem(row, 0, checkItem);

            auto makeTextItem = [protectedProcess](const QString& text) {
                QTableWidgetItem* const item = new QTableWidgetItem(text);
                item->setFlags(protectedProcess
                    ? Qt::ItemIsSelectable
                    : (Qt::ItemIsSelectable | Qt::ItemIsEnabled));
                return item;
                };

            QStringList noteList;
            appendUniqueText(noteList, candidate.processImagePath);
            for (const QString& ruleText : candidate.matchRuleList)
            {
                appendUniqueText(noteList, ruleText);
            }
            if (candidate.isCurrentProcess)
            {
                noteList.push_back(QStringLiteral("已保护：当前 Ksword 进程，不可选择"));
            }
            if (candidate.isCriticalProcess)
            {
                noteList.push_back(QStringLiteral("已保护：关键系统进程，不可选择"));
            }
            if (candidate.processCreationTime == 0U)
            {
                noteList.push_back(QStringLiteral("身份不可验证：请重新扫描后再操作"));
            }

            processTable->setItem(row, 1, makeTextItem(QString::number(candidate.processId)));
            processTable->setItem(row, 2, makeTextItem(candidate.processName.isEmpty() ? QStringLiteral("Unknown") : candidate.processName));
            processTable->setItem(row, 3, makeTextItem(QString::number(candidate.matchCount)));
            processTable->setItem(row, 4, makeTextItem(candidate.matchedTargetList.join(QStringLiteral("\n"))));
            processTable->setItem(row, 5, makeTextItem(noteList.join(QStringLiteral("\n"))));
        }

        handleTable->resizeColumnsToContents();
        processTable->resizeColumnsToContents();
        tableStack->addWidget(handleTable);
        tableStack->addWidget(processTable);
        tableStack->setCurrentIndex(modeComboBox->currentIndex() == 0 ? 0 : 1);
        rootLayout->addWidget(tableStack, 1);

        QDialogButtonBox* const buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialog);
        QPushButton* const selectAllButton = buttonBox->addButton(QStringLiteral("全选当前可操作项"), QDialogButtonBox::ActionRole);
        QPushButton* const clearButton = buttonBox->addButton(QStringLiteral("清空选择"), QDialogButtonBox::ActionRole);
        buttonBox->button(QDialogButtonBox::Ok)->setText(modeComboBox->currentIndex() == 0
            ? QStringLiteral("关闭选中句柄")
            : QStringLiteral("执行选中操作"));
        buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
        rootLayout->addWidget(buttonBox);

        auto collectSelectedHandles = [&handleTable, &handleCandidateList]() {
            std::vector<UnlockHandleCandidate> selectedHandleList;
            for (int row = 0; row < handleTable->rowCount(); ++row)
            {
                QTableWidgetItem* const item = handleTable->item(row, 0);
                if (item == nullptr
                    || !(item->flags() & Qt::ItemIsEnabled)
                    || item->checkState() != Qt::Checked)
                {
                    continue;
                }
                selectedHandleList.push_back(handleCandidateList[static_cast<std::size_t>(row)]);
            }
            return selectedHandleList;
            };

        auto collectSelectedIds = [&processTable, &processCandidateList]() {
            std::vector<std::uint32_t> selectedProcessIdList;
            for (int row = 0; row < processTable->rowCount(); ++row)
            {
                QTableWidgetItem* const item = processTable->item(row, 0);
                if (item == nullptr
                    || !(item->flags() & Qt::ItemIsEnabled)
                    || item->checkState() != Qt::Checked)
                {
                    continue;
                }
                selectedProcessIdList.push_back(processCandidateList[static_cast<std::size_t>(row)].processId);
            }
            return selectedProcessIdList;
            };

        auto setCheckedForTable = [](QTableWidget* const targetTable, const Qt::CheckState checkState) {
            for (int row = 0; row < targetTable->rowCount(); ++row)
            {
                QTableWidgetItem* const item = targetTable->item(row, 0);
                if (item != nullptr && (item->flags() & Qt::ItemIsEnabled))
                {
                    item->setCheckState(checkState);
                }
            }
            };
        QObject::connect(selectAllButton, &QPushButton::clicked, [&modeComboBox, &handleTable, &processTable, &setCheckedForTable]() {
            setCheckedForTable(modeComboBox->currentIndex() == 0 ? handleTable : processTable, Qt::Checked);
            });
        QObject::connect(clearButton, &QPushButton::clicked, [&modeComboBox, &handleTable, &processTable, &setCheckedForTable]() {
            setCheckedForTable(modeComboBox->currentIndex() == 0 ? handleTable : processTable, Qt::Unchecked);
            });
        QObject::connect(modeComboBox, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [&tableStack, &buttonBox](const int modeIndex) {
                tableStack->setCurrentIndex(modeIndex == 0 ? 0 : 1);
                buttonBox->button(QDialogButtonBox::Ok)->setText(modeIndex == 0
                    ? QStringLiteral("关闭选中句柄")
                    : QStringLiteral("执行选中操作"));
            });
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, [&dialog, &modeComboBox, &collectSelectedHandles, &collectSelectedIds]() {
            if (modeComboBox->currentIndex() == 0 && collectSelectedHandles().empty())
            {
                QMessageBox::information(
                    &dialog,
                    QStringLiteral("文件解锁器"),
                    QStringLiteral("请至少选择一个要关闭的句柄。"));
                return;
            }
            if (modeComboBox->currentIndex() != 0 && collectSelectedIds().empty())
            {
                QMessageBox::information(
                    &dialog,
                    QStringLiteral("文件解锁器"),
                    QStringLiteral("请至少选择一个要结束的进程。"));
                return;
            }
            dialog.accept();
            });

        if (dialog.exec() != QDialog::Accepted)
        {
            return result;
        }

        result.accepted = true;
        result.operationMode = modeComboBox->currentIndex() == 0
            ? UnlockOperationMode::CloseHandleR3
            : (modeComboBox->currentIndex() == 2
                ? UnlockOperationMode::TerminateProcessR0
                : UnlockOperationMode::TerminateProcessR3);
        if (result.operationMode == UnlockOperationMode::CloseHandleR3)
        {
            result.selectedHandleList = collectSelectedHandles();
        }
        else
        {
            result.selectedProcessIdList = collectSelectedIds();
        }
        return result;
    }

    // collectOccupyProcessIdsByPath：
    // - 作用：调用现有占用扫描器，提取“占用目标路径”的 PID 集合；
    // - 说明：这里运行在 R3，结果只用于展示/诊断，不能隐式结束进程。
    std::vector<std::uint32_t> collectOccupyProcessIdsByPath(
        const QString& path,
        QStringList* const detailTextListOut)
    {
        if (detailTextListOut != nullptr)
        {
            detailTextListOut->clear();
        }

        const std::vector<QString> scanTargets{ path };
        const filedock::handleusage::HandleUsageScanResult scanResult =
            filedock::handleusage::scanHandleUsageByPaths(
                scanTargets,
                0,
                false);

        std::set<std::uint32_t> processIdSet;
        QStringList processPreviewList;
        constexpr std::size_t MaxPreviewCount = 6U;
        for (const filedock::handleusage::HandleUsageEntry& entry : scanResult.entries)
        {
            if (entry.processId == 0U || entry.processId <= 4U)
            {
                continue;
            }

            const std::uint32_t processId = entry.processId;
            const auto insertResult = processIdSet.insert(processId);
            if (!insertResult.second)
            {
                continue;
            }

            if (processPreviewList.size() < static_cast<int>(MaxPreviewCount))
            {
                const QString processName =
                    entry.processName.trimmed().isEmpty()
                    ? QStringLiteral("Unknown")
                    : entry.processName.trimmed();
                processPreviewList.push_back(
                    QStringLiteral("%1(%2)").arg(processName).arg(processId));
            }
        }

        if (detailTextListOut != nullptr)
        {
            const QString diagnosticText = scanResult.diagnosticText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : scanResult.diagnosticText.simplified();
            detailTextListOut->push_back(
                QStringLiteral("occupyScan matched=%1, diagnostic=%2")
                .arg(scanResult.matchedHandleCount)
                .arg(diagnosticText));

            if (!processPreviewList.isEmpty())
            {
                detailTextListOut->push_back(
                    QStringLiteral("occupyPidPreview=%1")
                    .arg(processPreviewList.join(QStringLiteral(", "))));
            }
        }

        return std::vector<std::uint32_t>(processIdSet.begin(), processIdSet.end());
    }

    // 强制删除档要在展开每一层之前修权限，声明前置到这里，定义仍在多权限删除小节内。
    DWORD takeOwnershipAndGrantFullControl(
        const QString& path,
        bool isDirectory,
        QString* detailTextOut);
    bool clearDeleteBlockingAttributes(const QString& path);

    // appendDriverDeleteTargetsPostOrder：
    // - 作用：把目录展开成“子项先删、目录后删”的后序列表；
    // - 说明：重解析点目录不递归进入，只删除链接本身；
    // - repairPermissionBeforeEnumerate：强制删除档专用。目录 DACL 拒绝列举时
    //   entryInfoList 只会返回空列表，展开结果会把非空目录当成空目录，
    //   所以必须在枚举每一层之前先接管所有权并授权，否则后面删除必然失败。
    bool appendDriverDeleteTargetsPostOrder(
        const QString& rootPath,
        std::vector<DriverDeleteTarget>& targetsOut,
        QString& errorTextOut,
        const bool repairPermissionBeforeEnumerate = false)
    {
        const QFileInfo rootInfo(rootPath);
        const bool rootExists = rootInfo.exists() || rootInfo.isSymLink();
        if (!rootExists)
        {
            errorTextOut = QStringLiteral("路径不存在：%1").arg(QDir::toNativeSeparators(rootPath));
            return false;
        }

        const bool isDirectory = rootInfo.isDir();
        const bool isReparsePoint = isPathReparsePoint(rootPath);
        if (isDirectory && !isReparsePoint)
        {
            if (repairPermissionBeforeEnumerate)
            {
                QString repairDetailText;
                (void)takeOwnershipAndGrantFullControl(rootPath, true, &repairDetailText);
                (void)clearDeleteBlockingAttributes(rootPath);
            }

            const QFileInfoList childInfoList = QDir(rootPath).entryInfoList(
                QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System,
                QDir::DirsFirst | QDir::Name);
            for (const QFileInfo& childInfo : childInfoList)
            {
                if (!appendDriverDeleteTargetsPostOrder(
                        childInfo.absoluteFilePath(),
                        targetsOut,
                        errorTextOut,
                        repairPermissionBeforeEnumerate))
                {
                    return false;
                }
            }
        }

        targetsOut.push_back(DriverDeleteTarget{ rootPath, isDirectory });
        return true;
    }

    // ============================================================
    // 多权限递归删除（issue #155）
    // - 七个档位共用同一套“后序展开 + 逐项删除”的语义，差别只在权限/后端手段；
    // - R0 档优先让驱动在内核内部展开，避免 R3 枚举被目录 DACL 拒绝。
    // ============================================================

    // FileDeleteBatchStats：一批删除的统计与失败明细。
    struct FileDeleteBatchStats
    {
        std::uint64_t recycledCount = 0U;            // 成功移入回收站的项数。
        std::uint64_t deletedFileCount = 0U;         // 永久删除的文件数。
        std::uint64_t deletedDirectoryCount = 0U;    // 永久删除的目录数。
        std::uint64_t pendingRebootCount = 0U;       // 登记为重启后删除的项数。
        std::uint64_t failedCount = 0U;              // 失败项数。
        std::uint64_t skippedReparseCount = 0U;      // 只删链接本身、未跟进目标的重解析点数。
        std::uint64_t permissionRepairCount = 0U;    // 触发过“接管所有权 + 授权”的项数。
        bool driverUnavailable = false;              // R0 档：驱动设备打不开。
        bool driverRecursionUnsupported = false;     // R0 档：旧驱动不支持内核递归，已回退 R3 展开。
        QStringList errors;                          // 失败明细，用于日志与提示。
        QStringList permanentlyDeleted;              // 回收站档中被降级为永久删除的项。
    };

    // clearDeleteBlockingAttributes：
    // - 作用：清掉只读/隐藏/系统属性，这三者会直接让 DeleteFileW/RemoveDirectoryW 失败；
    // - 返回：true 表示属性已可删除（本来就正常也算成功）。
    bool clearDeleteBlockingAttributes(const QString& path)
    {
        const std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        const DWORD attributes = ::GetFileAttributesW(nativePath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            return false;
        }

        constexpr DWORD kBlockingAttributes =
            FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
        if ((attributes & kBlockingAttributes) == 0U)
        {
            return true;
        }

        DWORD newAttributes = attributes & ~kBlockingAttributes;
        if (newAttributes == 0U)
        {
            newAttributes = FILE_ATTRIBUTE_NORMAL;
        }
        return ::SetFileAttributesW(nativePath.c_str(), newAttributes) != FALSE;
    }

    // allocateBuiltinAdministratorsSid：
    // - 作用：构造 BUILTIN\Administrators（S-1-5-32-544）SID，调用方用 LocalFree 释放。
    PSID allocateBuiltinAdministratorsSid()
    {
        PSID administratorsSid = nullptr;
        if (::ConvertStringSidToSidW(L"S-1-5-32-544", &administratorsSid) == FALSE)
        {
            return nullptr;
        }
        return administratorsSid;
    }

    // takeOwnershipAndGrantFullControl：
    // - 作用：把目标的所有者改为 BUILTIN\Administrators，并追加一条完全控制 ACE；
    // - 说明：这是“强制删除”与 R3 兜底重试的权限手段，不改变文件内容；
    // - 返回：Win32 错误码，ERROR_SUCCESS 表示所有者与 DACL 都已写入。
    DWORD takeOwnershipAndGrantFullControl(
        const QString& path,
        const bool isDirectory,
        QString* const detailTextOut)
    {
        // 接管所有权需要 SeTakeOwnershipPrivilege；把所有者设成 Administrators 而不是
        // 当前账户还需要 SeRestorePrivilege，两者都只在管理员令牌里存在。
        (void)enableFileContextPrivilege(SE_TAKE_OWNERSHIP_NAME);
        (void)enableFileContextPrivilege(SE_RESTORE_NAME);
        (void)enableFileContextPrivilege(SE_BACKUP_NAME);
        (void)enableFileContextPrivilege(SE_SECURITY_NAME);

        PSID administratorsSid = allocateBuiltinAdministratorsSid();
        if (administratorsSid == nullptr)
        {
            const DWORD sidError = ::GetLastError();
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatFileWin32Error(QStringLiteral("ConvertStringSidToSidW(S-1-5-32-544)"), sidError);
            }
            return sidError == ERROR_SUCCESS ? ERROR_INVALID_PARAMETER : sidError;
        }

        std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        DWORD ownerResult = ::SetNamedSecurityInfoW(
            nativePath.data(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            administratorsSid,
            nullptr,
            nullptr,
            nullptr);

        PACL oldDacl = nullptr;
        PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
        DWORD daclResult = ::GetNamedSecurityInfoW(
            nativePath.data(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            &oldDacl,
            nullptr,
            &securityDescriptor);

        PACL newDacl = nullptr;
        if (daclResult == ERROR_SUCCESS)
        {
            EXPLICIT_ACCESS_W explicitAccess{};
            explicitAccess.grfAccessPermissions = FILE_ALL_ACCESS;
            explicitAccess.grfAccessMode = GRANT_ACCESS;
            // 目录让新 ACE 向下继承，这样后续枚举与逐项删除才不会再被子项的继承规则挡住。
            explicitAccess.grfInheritance = isDirectory
                ? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE)
                : NO_INHERITANCE;
            explicitAccess.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_GROUP;
            explicitAccess.Trustee.ptstrName = reinterpret_cast<LPWSTR>(administratorsSid);

            daclResult = ::SetEntriesInAclW(1, &explicitAccess, oldDacl, &newDacl);
            if (daclResult == ERROR_SUCCESS)
            {
                daclResult = ::SetNamedSecurityInfoW(
                    nativePath.data(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr,
                    nullptr,
                    newDacl,
                    nullptr);
            }
        }

        if (newDacl != nullptr)
        {
            ::LocalFree(newDacl);
        }
        if (securityDescriptor != nullptr)
        {
            ::LocalFree(securityDescriptor);
        }
        ::LocalFree(administratorsSid);

        if (detailTextOut != nullptr)
        {
            *detailTextOut = QStringLiteral("takeOwner=%1, grantDacl=%2")
                .arg(ownerResult)
                .arg(daclResult);
        }

        if (ownerResult != ERROR_SUCCESS)
        {
            return ownerResult;
        }
        return daclResult;
    }

    // removeSinglePathByWin32：
    // - 作用：按目录/文件语义执行一次 Win32 删除；重解析点目录只删链接本身；
    // - 返回：true 表示已删除，失败时通过 lastErrorOut 输出 Win32 错误码。
    bool removeSinglePathByWin32(
        const QString& path,
        const bool isDirectory,
        DWORD* const lastErrorOut)
    {
        const std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        const BOOL removeOk = isDirectory
            ? ::RemoveDirectoryW(nativePath.c_str())
            : ::DeleteFileW(nativePath.c_str());
        if (removeOk != FALSE)
        {
            return true;
        }

        if (lastErrorOut != nullptr)
        {
            *lastErrorOut = ::GetLastError();
        }
        return false;
    }

    // schedulePathDeleteOnReboot：
    // - 作用：把目标登记到 PendingFileRenameOperations，由会话管理器在下次启动时删除；
    // - 说明：需要管理员权限；目录必须在登记序列里排在其子项之后才能删成功。
    bool schedulePathDeleteOnReboot(const QString& path, DWORD* const lastErrorOut)
    {
        const std::wstring nativePath = QDir::toNativeSeparators(path).toStdWString();
        if (::MoveFileExW(nativePath.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT) != FALSE)
        {
            return true;
        }

        if (lastErrorOut != nullptr)
        {
            *lastErrorOut = ::GetLastError();
        }
        return false;
    }

    // deleteExpandedTargetByR3：
    // - 输入：单个后序展开目标、是否允许提权修复；
    // - 处理：先清属性直删，失败且允许提权时接管所有权并授权后重试；
    // - 返回：true 表示已删除，失败时把可诊断的错误文本写入 errorTextOut。
    bool deleteExpandedTargetByR3(
        const DriverDeleteTarget& target,
        const bool allowPermissionRepair,
        bool* const permissionRepairedOut,
        QString* const errorTextOut)
    {
        if (permissionRepairedOut != nullptr)
        {
            *permissionRepairedOut = false;
        }

        (void)clearDeleteBlockingAttributes(target.path);

        DWORD lastError = ERROR_SUCCESS;
        if (removeSinglePathByWin32(target.path, target.isDirectory, &lastError))
        {
            return true;
        }

        if (!allowPermissionRepair)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除失败：%1（error=%2）")
                    .arg(QDir::toNativeSeparators(target.path))
                    .arg(lastError);
            }
            return false;
        }

        QString repairDetailText;
        const DWORD repairResult =
            takeOwnershipAndGrantFullControl(target.path, target.isDirectory, &repairDetailText);
        if (permissionRepairedOut != nullptr)
        {
            *permissionRepairedOut = true;
        }

        (void)clearDeleteBlockingAttributes(target.path);
        DWORD retryError = ERROR_SUCCESS;
        if (removeSinglePathByWin32(target.path, target.isDirectory, &retryError))
        {
            return true;
        }

        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("强制删除失败：%1（首次 error=%2，接管所有权=%3[%4]，重试 error=%5）")
                .arg(QDir::toNativeSeparators(target.path))
                .arg(lastError)
                .arg(repairResult)
                .arg(repairDetailText)
                .arg(retryError);
        }
        return false;
    }

    // expandDeleteTargetsForBatch：
    // - 作用：把用户选中的路径展开成后序删除序列；
    // - 说明：强制删除档在枚举每一层之前接管所有权，否则目录拒绝列举时根本枚举不到子项。
    std::vector<DriverDeleteTarget> expandDeleteTargetsForBatch(
        const std::vector<QString>& paths,
        const bool repairPermissionWhileExpanding,
        FileDeleteBatchStats& statsInOut)
    {
        std::vector<DriverDeleteTarget> targets;
        for (const QString& path : paths)
        {
            if (repairPermissionWhileExpanding)
            {
                const QFileInfo rootInfo(path);
                QString repairDetailText;
                (void)takeOwnershipAndGrantFullControl(path, rootInfo.isDir(), &repairDetailText);
                (void)clearDeleteBlockingAttributes(path);
            }

            QString errorText;
            if (!appendDriverDeleteTargetsPostOrder(
                    path,
                    targets,
                    errorText,
                    repairPermissionWhileExpanding))
            {
                statsInOut.failedCount += 1U;
                statsInOut.errors.push_back(errorText);
            }
        }
        return targets;
    }

    // appendDriverDeleteFailureDetail：
    // - 作用：R0 删除失败时补充占用来源提示；
    // - 说明：只扫描不结束进程，绕过文件解锁器的显式确认流程是不可接受的。
    void appendDriverDeleteFailureDetail(
        const QString& path,
        const bool isDirectory,
        const QString& baseDetailText,
        FileDeleteBatchStats& statsInOut)
    {
        QStringList errorLines;
        errorLines.push_back(baseDetailText);

        if (!isDirectory)
        {
            QStringList scanDetails;
            const std::vector<std::uint32_t> occupyPids =
                collectOccupyProcessIdsByPath(path, &scanDetails);
            errorLines.push_back(
                QStringLiteral("occupyPidCount=%1, autoTerminate=disabled").arg(occupyPids.size()));
            errorLines.push_back(
                QStringLiteral("请先使用“文件解锁器”选择并确认要结束的占用进程，再重新执行驱动删除。"));
            errorLines.append(scanDetails);
        }

        statsInOut.errors.push_back(errorLines.join(QStringLiteral(" | ")));
    }

    // deleteTreeByDriverPerNode：
    // - 作用：旧驱动不支持内核递归时的回退路径，由 R3 展开后序序列逐项调用单点删除 IOCTL；
    // - 说明：这条路径受 R3 枚举权限限制，目录拒绝列举时会失败，属于预期降级。
    void deleteTreeByDriverPerNode(
        ksword::ark::DriverHandle& driverHandle,
        const QString& rootPath,
        FileDeleteBatchStats& statsInOut)
    {
        std::vector<DriverDeleteTarget> targets;
        QString expandErrorText;
        if (!appendDriverDeleteTargetsPostOrder(rootPath, targets, expandErrorText))
        {
            statsInOut.failedCount += 1U;
            statsInOut.errors.push_back(expandErrorText);
            return;
        }

        for (const DriverDeleteTarget& target : targets)
        {
            std::string detailText;
            if (deletePathByR0Driver(driverHandle, target.path, target.isDirectory, &detailText))
            {
                if (target.isDirectory)
                {
                    statsInOut.deletedDirectoryCount += 1U;
                }
                else
                {
                    statsInOut.deletedFileCount += 1U;
                }
                continue;
            }

            statsInOut.failedCount += 1U;
            appendDriverDeleteFailureDetail(
                target.path,
                target.isDirectory,
                QString::fromStdString(detailText),
                statsInOut);
        }
    }

    // describeDriverDeleteResponse：把 R0 统计响应转成一行可读诊断文本。
    QString describeDriverDeleteResponse(
        const QString& path,
        const ksword::ark::DeletePathResult& driverResult)
    {
        const KSWORD_ARK_DELETE_PATH_RESPONSE& response = driverResult.response;
        QString failedPathText;
        if (response.failedPathLengthChars > 0U)
        {
            failedPathText = QString::fromWCharArray(
                response.failedPath,
                static_cast<int>(response.failedPathLengthChars));
        }

        return QStringLiteral(
            "驱动删除未完成：%1（state=%2, files=%3, dirs=%4, failed=%5, visited=%6, depth=%7, "
            "responseFlags=0x%8, lastStatus=0x%9, firstFailed=%10）")
            .arg(QDir::toNativeSeparators(path))
            .arg(response.deleteStatus)
            .arg(response.deletedFileCount)
            .arg(response.deletedDirectoryCount)
            .arg(response.failedCount)
            .arg(response.visitedCount)
            .arg(response.maxDepthReached)
            .arg(response.responseFlags, 0, 16)
            .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(response.lastStatus)), 0, 16)
            .arg(failedPathText.isEmpty()
                ? QStringLiteral("-")
                : QDir::toNativeSeparators(failedPathText));
    }

    // runDriverDeleteBatch：R0 档执行体。
    // - 目录优先交给驱动在内核内递归展开，这样目录 DACL 拒绝列举也能删干净；
    // - 仅底层方案可在旧驱动拒绝递归标志时回退 R3 展开；IRP/POSIX 必须安全失败，
    //   避免用户选中的后端被静默替换。
    FileDeleteBatchStats runDriverDeleteBatch(
        const std::vector<QString>& paths,
        const ksword::ark::FileDeleteBackend backend,
        const std::function<void(float)>& progressCallback)
    {
        FileDeleteBatchStats stats;

        std::string openDriverDetailText;
        ksword::ark::DriverHandle driverHandle = openKswordArkDriverHandle(&openDriverDetailText);
        if (!driverHandle.isValid())
        {
            stats.driverUnavailable = true;
            stats.failedCount += static_cast<std::uint64_t>(paths.size());
            stats.errors.push_back(
                QStringLiteral("无法连接 KswordARK 驱动设备：%1")
                    .arg(QString::fromStdString(openDriverDetailText)));
            return stats;
        }

        const ksword::ark::DriverClient driverClient;
        const std::size_t totalCount = paths.size();
        for (std::size_t index = 0; index < totalCount; ++index)
        {
            const QString& path = paths[index];
            const QFileInfo pathInfo(path);
            const bool isDirectory = pathInfo.isDir();
            const bool isReparsePointPath = isPathReparsePoint(path);
            const bool wantRecursive = isDirectory && !isReparsePointPath;

            const QString driverNtPath = buildDriverNtPath(path);
            if (driverNtPath.isEmpty())
            {
                stats.failedCount += 1U;
                stats.errors.push_back(
                    QStringLiteral("NT 路径转换失败：%1").arg(QDir::toNativeSeparators(path)));
            }
            else
            {
                const ksword::ark::DeletePathResult driverResult = driverClient.deletePathEx(
                    driverHandle,
                    driverNtPath.toStdWString(),
                    isDirectory,
                    wantRecursive,
                    true,
                    backend);

                if (driverResult.unsupported)
                {
                    if (backend == ksword::ark::FileDeleteBackend::Native)
                    {
                        stats.driverRecursionUnsupported = true;
                        deleteTreeByDriverPerNode(driverHandle, path, stats);
                    }
                    else
                    {
                        stats.failedCount += 1U;
                        const QString backendText =
                            backend == ksword::ark::FileDeleteBackend::Irp
                                ? QStringLiteral("IRP")
                                : QStringLiteral("POSIX");
                        stats.errors.push_back(QStringLiteral(
                            "当前 KswordARK 驱动不支持 R0 %1 删除后端，请重新部署本次构建的驱动：%2")
                            .arg(backendText)
                            .arg(QDir::toNativeSeparators(path)));
                    }
                }
                else if (!driverResult.io.ok)
                {
                    stats.failedCount += 1U;
                    appendDriverDeleteFailureDetail(
                        path,
                        isDirectory,
                        QStringLiteral("驱动删除失败：%1（%2）")
                            .arg(QDir::toNativeSeparators(path))
                            .arg(QString::fromStdString(driverResult.io.message)),
                        stats);
                }
                else
                {
                    const KSWORD_ARK_DELETE_PATH_RESPONSE& response = driverResult.response;
                    stats.deletedFileCount += response.deletedFileCount;
                    stats.deletedDirectoryCount += response.deletedDirectoryCount;
                    stats.failedCount += response.failedCount;
                    stats.skippedReparseCount += response.skippedReparseCount;
                    if (response.deleteStatus != KSWORD_ARK_DELETE_PATH_STATUS_COMPLETED)
                    {
                        if (response.failedCount == 0U)
                        {
                            // 限额截断这类情况本身没有失败节点，但结果并不完整，必须计一次失败。
                            stats.failedCount += 1U;
                        }
                        appendDriverDeleteFailureDetail(
                            path,
                            isDirectory,
                            describeDriverDeleteResponse(path, driverResult),
                            stats);
                    }
                }
            }

            if (progressCallback)
            {
                progressCallback(
                    5.0f + (static_cast<float>(index + 1) / static_cast<float>(totalCount)) * 90.0f);
            }
        }

        driverHandle.reset();
        return stats;
    }

    // runFileDeleteBatch：
    // - 输入：选中路径集合、权限档位与进度回调；
    // - 处理：按档位选择删除手段，目录在任何一档都按后序序列处理；
    // - 返回：统计与失败明细，由 UI 线程汇总展示。
    FileDeleteBatchStats runFileDeleteBatch(
        const std::vector<QString>& paths,
        const FileDeleteMode mode,
        const std::function<void(float)>& progressCallback)
    {
        FileDeleteBatchStats stats;
        if (paths.empty())
        {
            return stats;
        }

        if (mode == FileDeleteMode::DriverR0Native)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::Native,
                progressCallback);
        }
        if (mode == FileDeleteMode::DriverR0Irp)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::Irp,
                progressCallback);
        }
        if (mode == FileDeleteMode::DriverR0Posix)
        {
            return runDriverDeleteBatch(
                paths,
                ksword::ark::FileDeleteBackend::Posix,
                progressCallback);
        }

        if (mode == FileDeleteMode::RecycleBin)
        {
            // QFile::moveToTrash 内部要用 Shell 的 IFileOperation，必须在本线程自备
            // COM 套间；RPC_E_CHANGED_MODE 表示已有套间，此时不能再配对 CoUninitialize。
            const HRESULT comInitResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
            const bool comUninitializeNeeded = SUCCEEDED(comInitResult);

            const std::size_t totalCount = paths.size();
            for (std::size_t index = 0; index < totalCount; ++index)
            {
                const QString& path = paths[index];
                bool removeOk = QFile::moveToTrash(path);
                if (removeOk)
                {
                    stats.recycledCount += 1U;
                }
                else
                {
                    // 回收站不可用（网络位置、可移动磁盘、回收站停用等）时降级为永久删除，
                    // 这一步会改变可逆性，所以必须单独记账并在收尾时如实告诉用户。
                    const QFileInfo pathInfo(path);
                    if (pathInfo.isDir())
                    {
                        if (isPathReparsePoint(path))
                        {
                            removeOk = (::RemoveDirectoryW(
                                QDir::toNativeSeparators(path).toStdWString().c_str()) != FALSE);
                            if (removeOk)
                            {
                                stats.skippedReparseCount += 1U;
                            }
                        }
                        else
                        {
                            removeOk = QDir(path).removeRecursively();
                        }
                        if (removeOk)
                        {
                            stats.deletedDirectoryCount += 1U;
                        }
                    }
                    else
                    {
                        removeOk = QFile::remove(path);
                        if (removeOk)
                        {
                            stats.deletedFileCount += 1U;
                        }
                    }

                    if (removeOk)
                    {
                        stats.permanentlyDeleted.push_back(path);
                    }
                    else
                    {
                        stats.failedCount += 1U;
                        stats.errors.push_back(
                            QStringLiteral("删除失败：%1").arg(QDir::toNativeSeparators(path)));
                    }
                }

                if (progressCallback)
                {
                    progressCallback(
                        5.0f + (static_cast<float>(index + 1) / static_cast<float>(totalCount)) * 90.0f);
                }
            }

            if (comUninitializeNeeded)
            {
                ::CoUninitialize();
            }
            return stats;
        }

        const bool forceMode = (mode == FileDeleteMode::ForceR3);
        const bool pendingRebootMode = (mode == FileDeleteMode::PendingReboot);
        if (pendingRebootMode)
        {
            // 会话管理器在启动早期按登记顺序执行删除，写入这张表需要 SeRestorePrivilege。
            (void)enableFileContextPrivilege(SE_RESTORE_NAME);
            (void)enableFileContextPrivilege(SE_BACKUP_NAME);
        }

        const std::vector<DriverDeleteTarget> targets =
            expandDeleteTargetsForBatch(paths, forceMode, stats);
        const std::size_t totalTargetCount = targets.size();
        for (std::size_t index = 0; index < totalTargetCount; ++index)
        {
            const DriverDeleteTarget& target = targets[index];
            const bool targetIsReparsePoint = target.isDirectory && isPathReparsePoint(target.path);

            if (pendingRebootMode)
            {
                DWORD scheduleError = ERROR_SUCCESS;
                if (schedulePathDeleteOnReboot(target.path, &scheduleError))
                {
                    stats.pendingRebootCount += 1U;
                }
                else
                {
                    stats.failedCount += 1U;
                    stats.errors.push_back(
                        QStringLiteral("登记重启后删除失败：%1（error=%2）")
                            .arg(QDir::toNativeSeparators(target.path))
                            .arg(scheduleError));
                }
            }
            else
            {
                bool permissionRepaired = false;
                QString errorText;
                if (deleteExpandedTargetByR3(target, forceMode, &permissionRepaired, &errorText))
                {
                    if (target.isDirectory)
                    {
                        stats.deletedDirectoryCount += 1U;
                    }
                    else
                    {
                        stats.deletedFileCount += 1U;
                    }
                    if (targetIsReparsePoint)
                    {
                        stats.skippedReparseCount += 1U;
                    }
                }
                else
                {
                    stats.failedCount += 1U;
                    stats.errors.push_back(errorText);
                }

                if (permissionRepaired)
                {
                    stats.permissionRepairCount += 1U;
                }
            }

            if (progressCallback)
            {
                progressCallback(
                    5.0f + (static_cast<float>(index + 1) / static_cast<float>(totalTargetCount)) * 90.0f);
            }
        }

        return stats;
    }

    // 手动解析模型列定义：名称/大小/类型/修改时间/完整路径/是否目录。
    enum class ManualModelColumn : int
    {
        Name = 0,
        Size = 1,
        Type = 2,
        ModifiedTime = 3,
        FullPath = 4,
        IsDirectory = 5,
        Count = 6
    };

    // manualFsTypeToText 作用：手动解析结果类型转可读文本。
    QString manualFsTypeToText(const ks::file::ManualFsType fsType)
    {
        switch (fsType)
        {
        case ks::file::ManualFsType::Ntfs:
            return QStringLiteral("NTFS");
        case ks::file::ManualFsType::Fat32:
            return QStringLiteral("FAT32");
        case ks::file::ManualFsType::ExFat:
            return QStringLiteral("exFAT");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // markSuspiciousRowIfNeeded 作用：
    // - 输入：刚构造好的一行、该行条目名、疑似隐藏项名称集合（已折叠大小写）；
    // - 处理：命中时给整行加醒目底色和说明性 tooltip；
    // - 说明：这份名单来自"绕过路径可见、常规路径不可见"的差集，是 MFT/IRP 两种
    //   解析方式的核心产出。只在状态栏报一个数字，用户仍然无法定位到具体是哪几行。
    void markSuspiciousRowIfNeeded(
        const QList<QStandardItem*>& rowItems,
        const QString& entryName,
        const QSet<QString>& suspiciousNameSet)
    {
        if (suspiciousNameSet.isEmpty() ||
            !suspiciousNameSet.contains(entryName.toCaseFolded()))
        {
            return;
        }

        // 用低透明度的告警色铺底：既要一眼看见，又不能盖掉选中态和交替行色。
        QColor highlightColor(
            KswordTheme::AccentHex(KswordTheme::AccentRole::Orange));
        highlightColor.setAlpha(72);
        const QString tipText = QStringLiteral(
            "该条目只有绕过过滤层或直读 $MFT 才能看到，常规目录枚举视图中不存在。");
        for (QStandardItem* rowItem : rowItems)
        {
            if (rowItem == nullptr)
            {
                continue;
            }
            rowItem->setBackground(highlightColor);
            rowItem->setToolTip(tipText);
        }
    }

    // buildSuspiciousNameSet 作用：把疑似隐藏项名单折叠大小写后转成集合，
    // 避免在逐行回填时做 O(n) 线性查找。
    QSet<QString> buildSuspiciousNameSet(const QStringList& names)
    {
        QSet<QString> nameSet;
        nameSet.reserve(names.size() + 8);
        for (const QString& nameText : names)
        {
            nameSet.insert(nameText.toCaseFolded());
        }
        return nameSet;
    }

    // 统一按钮样式，保持与主界面蓝色主题一致。
    QString buildBlueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    // 统一输入控件样式。
    QString buildBlueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit,QPlainTextEdit,QTextEdit{"
            "  border:1px solid %2;"
            "  border-radius:3px;"
            "  background:%3;"
            "  color:%4;"
            "  padding:2px 6px;"
            "}"
            "QLineEdit:focus,QPlainTextEdit:focus,QTextEdit:focus{"
            "  border:1px solid %1;}")
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            + KswordTheme::ThemedComboBoxStyle();
    }

    // buildContextMenuStyle 作用：
    // - 为 FileDock 文件列表右键菜单生成独立主题样式；
    // - 修复浅色主题下菜单背景错误保持黑色，导致文字不可见的问题。
    QString buildContextMenuStyle()
    {
        const QString disabledTextColor = KswordTheme::TextDisabledColorHex();

        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "}"
            "QMenu::item{"
            "  padding:3px 16px 3px 12px;"
            "  background:transparent;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:%6;"
            "}"
            "QMenu::item:disabled{"
            "  color:%5;"
            "  background:transparent;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:2px 6px;"
            "}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(disabledTextColor)
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    void installFileTableCopyMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installFileTableCopyMenu：
        // - 输入：FileDock 内临时弹窗或工具页表格；
        // - 处理：右键选中当前行，并把该行所有列按 TSV 复制到剪贴板；
        // - 返回：无。只读复制，不触发删除、恢复、关闭句柄等动作。
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(tableWidget, &QTableWidget::customContextMenuRequested, tableWidget, [tableWidget, processIdColumn](const QPoint& localPosition)
        {
            const auto clickedIndex = tableWidget->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu menu(tableWidget);
            menu.setStyleSheet(buildContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
            const QTableWidgetItem* processIdItem =
                processIdColumn >= 0 && processIdColumn < tableWidget->columnCount() && tableWidget->currentRow() >= 0
                ? tableWidget->item(tableWidget->currentRow(), processIdColumn)
                : nullptr;
            bool processIdOk = false;
            const quint32 processId = processIdItem != nullptr
                ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = nullptr;
            if (processIdColumn >= 0)
            {
                openProcessAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processIdOk && processId != 0U);
            }

            QAction* selectedAction = menu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            const int rowIndex = tableWidget->currentRow();
            if (clipboardObject == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
            {
                return;
            }

            QStringList fields;
            fields.reserve(tableWidget->columnCount());
            for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* item = tableWidget->item(rowIndex, columnIndex);
                fields.push_back(item != nullptr ? item->text() : QString());
            }
            clipboardObject->setText(fields.join(QLatin1Char('\t')));
        });
    }

    // installFileTreeCopyMenu 作用：
    // - 输入 treeWidget：FileDock 内以树表展示的只读结果；
    // - 处理：右键选中当前行，并把该行所有列按 TSV 复制到剪贴板；
    // - 返回：无。只读复制，不执行解锁、关闭句柄、删除文件等动作。
    void installFileTreeCopyMenu(QTreeWidget* treeWidget, const int processIdColumn)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(treeWidget, &QTreeWidget::customContextMenuRequested, treeWidget, [treeWidget, processIdColumn](const QPoint& localPosition)
        {
            QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
            if (clickedItem != nullptr)
            {
                treeWidget->setCurrentItem(clickedItem);
            }

            QMenu menu(treeWidget);
            menu.setStyleSheet(buildContextMenuStyle());
            QAction* copyRowAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(treeWidget->currentItem() != nullptr);
            QTreeWidgetItem* const processIdItem = treeWidget->currentItem();
            bool processIdOk = false;
            const quint32 processId =
                processIdItem != nullptr && processIdColumn >= 0 && processIdColumn < treeWidget->columnCount()
                ? processIdItem->text(processIdColumn).trimmed().toUInt(&processIdOk, 10)
                : 0U;
            QAction* openProcessAction = menu.addAction(
                QIcon(QStringLiteral(":/Icon/process_details.svg")),
                QStringLiteral("转到进程详细信息"));
            openProcessAction->setEnabled(processIdOk && processId != 0U);

            QAction* selectedAction = menu.exec(treeWidget->viewport()->mapToGlobal(localPosition));
            if (selectedAction == openProcessAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
                return;
            }
            if (selectedAction != copyRowAction)
            {
                return;
            }

            QClipboard* clipboardObject = QApplication::clipboard();
            QTreeWidgetItem* currentItem = treeWidget->currentItem();
            if (clipboardObject == nullptr || currentItem == nullptr)
            {
                return;
            }

            QStringList fields;
            fields.reserve(treeWidget->columnCount());
            for (int columnIndex = 0; columnIndex < treeWidget->columnCount(); ++columnIndex)
            {
                fields.push_back(currentItem->text(columnIndex));
            }
            clipboardObject->setText(fields.join(QLatin1Char('\t')));
        });
    }

    // propertyTreeToPlainText 作用：
    // - 把“名称/值”两列属性树整棵导出为缩进文本；
    // - 属性页从纯文本块改成属性树后，这里替代原来的“全选文本框再复制”。
    // 入参 treeWidget：目标属性树；为空时返回空串。
    // 返回：分组用方括号成行、属性行为“名称: 值”的多行文本。
    QString propertyTreeToPlainText(const QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return {};
        }

        QString exportedText;
        for (int groupIndex = 0; groupIndex < treeWidget->topLevelItemCount(); ++groupIndex)
        {
            const QTreeWidgetItem* groupItem = treeWidget->topLevelItem(groupIndex);
            if (groupItem == nullptr)
            {
                continue;
            }

            exportedText += groupItem->text(1).isEmpty()
                ? QStringLiteral("[%1]\n").arg(groupItem->text(0))
                : QStringLiteral("[%1] %2\n").arg(groupItem->text(0), groupItem->text(1));
            for (int rowIndex = 0; rowIndex < groupItem->childCount(); ++rowIndex)
            {
                const QTreeWidgetItem* rowItem = groupItem->child(rowIndex);
                if (rowItem == nullptr)
                {
                    continue;
                }
                exportedText += QStringLiteral("  %1: %2\n").arg(rowItem->text(0), rowItem->text(1));
            }
            exportedText += QStringLiteral("\n");
        }
        return exportedText;
    }

    // installPropertyTreeCopyMenu 作用：
    // - 给“名称/值”两列属性树装上右键复制菜单；
    // - 提供“只复制值 / 复制整行 / 复制全部”三种粒度：只读文本框时代想取一条路径
    //   得先手工划选，属性树把每条属性变成独立行后应当直接可取。
    // 入参 treeWidget：目标属性树；为空时忽略。
    // 返回：无。
    void installPropertyTreeCopyMenu(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            treeWidget,
            &QTreeWidget::customContextMenuRequested,
            treeWidget,
            [treeWidget](const QPoint& localPosition)
            {
                QTreeWidgetItem* clickedItem = treeWidget->itemAt(localPosition);
                if (clickedItem != nullptr)
                {
                    treeWidget->setCurrentItem(clickedItem);
                }

                QMenu menu(treeWidget);
                menu.setStyleSheet(buildContextMenuStyle());
                QAction* copyValueAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_cell.svg")),
                    QStringLiteral("复制值"));
                QAction* copyRowAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                QAction* copyAllAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制全部"));
                copyValueAction->setEnabled(clickedItem != nullptr && !clickedItem->text(1).isEmpty());
                copyRowAction->setEnabled(clickedItem != nullptr);

                QAction* selectedAction = menu.exec(treeWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == nullptr)
                {
                    return;
                }

                QString clipboardText;
                if (selectedAction == copyValueAction && clickedItem != nullptr)
                {
                    clipboardText = clickedItem->text(1);
                }
                else if (selectedAction == copyRowAction && clickedItem != nullptr)
                {
                    clipboardText = clickedItem->text(1).isEmpty()
                        ? clickedItem->text(0)
                        : QStringLiteral("%1: %2").arg(clickedItem->text(0), clickedItem->text(1));
                }
                else if (selectedAction == copyAllAction)
                {
                    clipboardText = propertyTreeToPlainText(treeWidget);
                }

                QClipboard* clipboardObject = QApplication::clipboard();
                if (clipboardObject != nullptr && !clipboardText.isEmpty())
                {
                    clipboardObject->setText(clipboardText);
                }
            });
    }

    // appendPropertyGroup 作用：
    // - 在属性树里新建一个默认展开的顶层分组；
    // - 分组行加粗且不可选中，避免被当成一条属性复制走。
    // 入参 tree：目标属性树；titleText：已翻译的分组标题。
    // 返回：新建分组节点，生命周期由树接管。
    QTreeWidgetItem* appendPropertyGroup(QTreeWidget* tree, const QString& titleText)
    {
        QTreeWidgetItem* groupItem = new QTreeWidgetItem(tree);
        groupItem->setText(0, titleText);
        QFont groupFont = groupItem->font(0);
        groupFont.setBold(true);
        groupItem->setFont(0, groupFont);
        groupItem->setFlags(groupItem->flags() & ~Qt::ItemIsSelectable);
        groupItem->setExpanded(true);
        return groupItem;
    }

    // appendPropertyRow 作用：
    // - 往分组下追加一行“属性名 + 值”；
    // - 值同时写入 ToolTip，超长路径被列宽截断时悬停仍可看全。
    // 入参 groupItem：所属分组；nameText/valueText：已翻译的名称与值。
    // 返回：新建行节点，生命周期由树接管。
    QTreeWidgetItem* appendPropertyRow(
        QTreeWidgetItem* groupItem,
        const QString& nameText,
        const QString& valueText)
    {
        QTreeWidgetItem* rowItem = new QTreeWidgetItem(groupItem);
        rowItem->setText(0, nameText);
        rowItem->setText(1, valueText);
        rowItem->setToolTip(1, valueText);
        return rowItem;
    }

    // configurePropertyTree 作用：
    // - 统一属性树的外观与交互：两列、可折叠、不可编辑、不排序、带复制菜单；
    // - 常规页和各审计页共用，避免同一个窗口里出现两套表现不一致的属性视图。
    // 入参 treeWidget：目标属性树；为空时忽略。
    // 返回：无。
    void configurePropertyTree(QTreeWidget* treeWidget)
    {
        if (treeWidget == nullptr)
        {
            return;
        }

        treeWidget->setColumnCount(2);
        // 字号与统一报告控件里的结构视图同一档：同一个窗口里两种结构化视图不能有两种字号。
        // 同时标记字体自管：MainWindow 在外观设置变更后会把所有 item view 刷成应用字体，
        // 不打这个标记的话，用户一改字体设置这里就被刷回默认档。
        treeWidget->setProperty("ksword_preserve_custom_font", true);
        treeWidget->setFont(ks::ui::ScaledReportFont(treeWidget->font()));
        treeWidget->setRootIsDecorated(true);
        treeWidget->setAlternatingRowColors(true);
        treeWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
        treeWidget->setEditTriggers(QAbstractItemView::NoEditTriggers);
        treeWidget->setUniformRowHeights(true);
        // 行的先后顺序本身有含义（报告是按采集顺序写的），因此不开排序。
        treeWidget->setSortingEnabled(false);
        if (treeWidget->header() != nullptr)
        {
            treeWidget->header()->setStretchLastSection(true);
        }
        installPropertyTreeCopyMenu(treeWidget);
    }

    // g_preferPlainTextReportView 作用：
    // - 记住用户最近一次选择的视图，之后新打开的页面沿用同一选择；
    // - 只在进程内有效、不落盘：这是“这次排查我想怎么看”，不是需要长期保存的偏好。
    bool g_preferPlainTextReportView = false;

    // buildSwitchableView 作用：
    // - 输入 parent、已填好的属性树和同一份内容的只读文本视图；
    // - 处理：两者叠进 QStackedWidget，右上角放一个视图切换下拉框；
    //   结构视图按字段分行，适合逐条查看和复制；原始文本保留完整报告，
    //   适合 Ctrl+F 全文检索和整段贴进工单。两者各有不可替代的场合，
    //   所以不替用户二选一，而是当场可切；
    // - 返回：可直接放进页面布局的容器控件。
    QWidget* buildSwitchableView(
        QWidget* parent,
        QTreeWidget* propertyTree,
        CodeEditorWidget* textEditor)
    {
        QWidget* container = new QWidget(parent);
        QVBoxLayout* containerLayout = new QVBoxLayout(container);
        containerLayout->setContentsMargins(0, 0, 0, 0);
        containerLayout->setSpacing(4);

        auto& languageManager = ks::i18n::LanguageManager::instance();
        QComboBox* viewModeCombo = new QComboBox(container);
        viewModeCombo->addItem(QStringLiteral("结构视图"));
        viewModeCombo->addItem(QStringLiteral("原始文本"));
        languageManager.bindComboBoxItem(
            viewModeCombo, 0, QStringLiteral("file.detail.view.structured"), QStringLiteral("结构视图"));
        languageManager.bindComboBoxItem(
            viewModeCombo, 1, QStringLiteral("file.detail.view.plain_text"), QStringLiteral("原始文本"));
        viewModeCombo->setToolTip(
            QStringLiteral("结构视图按字段分行，便于逐条查看和复制；原始文本保留完整报告，便于全文检索和整段复制"));
        languageManager.bindToolTip(
            viewModeCombo,
            QStringLiteral("file.detail.view.tooltip"),
            QStringLiteral("结构视图按字段分行，便于逐条查看和复制；原始文本保留完整报告，便于全文检索和整段复制"));

        QHBoxLayout* headerLayout = new QHBoxLayout();
        headerLayout->setContentsMargins(0, 0, 0, 0);
        headerLayout->addStretch(1);
        headerLayout->addWidget(viewModeCombo, 0);
        containerLayout->addLayout(headerLayout, 0);

        QStackedWidget* viewStack = new QStackedWidget(container);
        viewStack->addWidget(propertyTree);
        viewStack->addWidget(textEditor);
        containerLayout->addWidget(viewStack, 1);

        const int initialViewIndex = g_preferPlainTextReportView ? 1 : 0;
        viewModeCombo->setCurrentIndex(initialViewIndex);
        viewStack->setCurrentIndex(initialViewIndex);
        QObject::connect(
            viewModeCombo,
            QOverload<int>::of(&QComboBox::currentIndexChanged),
            viewStack,
            [viewStack](const int viewIndex)
            {
                viewStack->setCurrentIndex(viewIndex);
                g_preferPlainTextReportView = viewIndex == 1;
            });
        return container;
    }

    // buildReportView 作用：
    // - 输入 parent 和审计页生成的报告原文；
    // - 处理：交给统一的只读报告控件，由它按内容形态自行决定结构化呈现，
    //   并在工具栏给出“结构视图 / 原始文本”切换按钮；
    // - 取舍说明：本文件原先自带一套“只认 [分组] 的属性树 + 下拉切换框”的解析实现。
    //   全局报告控件上线后两套并存会让同一页出现两个入口、两种解析口径，
    //   而且本地那套只解析得出属性树，解析不出对齐表格和机器码块，因此整体换成统一控件；
    // - 返回：可直接放进页面布局的控件。
    QWidget* buildReportView(QWidget* parent, const QString& reportText)
    {
        CodeEditorWidget* textEditor = new CodeEditorWidget(parent);
        textEditor->setReadOnly(true);
        textEditor->setLocalizedText(reportText);
        return textEditor;
    }

    // buildOpaqueStandaloneDialogStyle 作用：
    // - 为“独立弹窗”覆盖父级 Dock 透明样式，防止浅色主题下出现黑底；
    // - 强制编辑区/表格区使用 palette(base) 作为不透明背景。
    QString buildOpaqueStandaloneDialogStyle(const QString& dialogObjectName)
    {
        return QStringLiteral(
            "QDialog#%1{"
            "  background-color:palette(window) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QTabWidget::pane{"
            "  background-color:palette(window) !important;"
            "  border:1px solid palette(mid) !important;"
            "}"
            "QDialog#%1 QPlainTextEdit,"
            "QDialog#%1 QTextEdit,"
            "QDialog#%1 QTreeWidget,"
            "QDialog#%1 QTableWidget,"
            "QDialog#%1 QAbstractScrollArea,"
            "QDialog#%1 QAbstractScrollArea::viewport{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}"
            "QDialog#%1 QHeaderView::section{"
            "  background-color:palette(base) !important;"
            "  color:palette(text) !important;"
            "}")
            .arg(dialogObjectName);
    }

    // buildFileDetailDialogPalette：
    // - 为文件属性窗口建立与进程属性窗口相同的 Window/Surface/Base 分层；
    // - 显式设置 Base，避免 CodeEditor 和表格在不同主题下各自回退到系统颜色。
    QPalette buildFileDetailDialogPalette(const QWidget* const fallbackWidget)
    {
        QPalette palette = qApp != nullptr
            ? qApp->palette()
            : (fallbackWidget != nullptr ? fallbackWidget->palette() : QPalette());
        palette.setColor(QPalette::Window, KswordTheme::WindowColor());
        palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Button, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::Mid, KswordTheme::BorderColor());
        palette.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
        palette.setColor(
            QPalette::HighlightedText,
            KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()));
        palette.setColor(QPalette::Disabled, QPalette::WindowText, KswordTheme::TextDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::Text, KswordTheme::TextDisabledColor());
        palette.setColor(QPalette::Disabled, QPalette::ButtonText, KswordTheme::TextDisabledColor());
        return palette;
    }

    // applyFileDetailSurfacePalette：
    // - 为独立窗口及其页面强制不透明 Surface；
    // - 防止透明子页露出 WindowColor，而编辑器/表格使用 Base 导致底色断层。
    void applyFileDetailSurfacePalette(QWidget* const widget, const QPalette& palette)
    {
        if (widget == nullptr)
        {
            return;
        }
        widget->setPalette(palette);
        widget->setAutoFillBackground(true);
        widget->setAttribute(Qt::WA_StyledBackground, true);
    }

    // buildFileDetailDialogStyle：
    // - 文件属性窗口复用进程属性的“Window 外层 + Surface 内容页 + 左侧导航”视觉层次；
    // - 所有可读文本容器、表头和滚动区域均显式使用 Surface，避免同窗内文字底色不一致。
    QString buildFileDetailDialogStyle()
    {
        return QStringLiteral(
            "QDialog#FileDetailDialogRoot{"
            "  background:%1;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QGroupBox{"
            "  border:1px solid %3;"
            "  border-radius:4px;"
            "  margin-top:8px;"
            "  padding-top:8px;"
            "  background:%4;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QGroupBox::title{"
            "  subcontrol-origin:margin;"
            "  left:8px;"
            "  padding:0 4px;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QLineEdit,"
            "QDialog#FileDetailDialogRoot QPlainTextEdit,"
            "QDialog#FileDetailDialogRoot QTextEdit{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:3px 6px;"
            "  selection-background-color:%5;"
            "  selection-color:%7;"
            "}"
            "QDialog#FileDetailDialogRoot QTableWidget,"
            "QDialog#FileDetailDialogRoot QTreeWidget{"
            "  background:%4;"
            "  alternate-background-color:%6;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  gridline-color:%3;"
            "}"
            "QDialog#FileDetailDialogRoot QAbstractScrollArea::viewport{"
            "  background:%4;"
            "  color:%2;"
            "}"
            "QDialog#FileDetailDialogRoot QTableCornerButton::section,"
            "QDialog#FileDetailDialogRoot QHeaderView::section{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  padding:4px;"
            "  font-weight:600;"
            "}"
            "QDialog#FileDetailDialogRoot QTabWidget::pane{"
            "  border:1px solid %3;"
            "  background:%4;"
            "}"
            "QWidget#FileDetailTabNavigation{"
            "  background:%4;"
            "  border:1px solid %3;"
            "  border-radius:4px;"
            "}"
            "QWidget#FileDetailTabNavigation QToolButton{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:5px 8px;"
            "}"
            "QWidget#FileDetailTabNavigation QToolButton:checked{"
            "  background:%5;"
            "  color:%7;"
            "  border-color:%5;"
            "}"
            "QWidget#FileDetailTabNavigation QToolButton:hover:!checked{"
            "  background:%6;"
            "}"
            "QDialog#FileDetailDialogRoot QPushButton{"
            "  background:%4;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:4px 10px;"
            "}"
            "QDialog#FileDetailDialogRoot QPushButton:hover{"
            "  background:%6;"
            "  border-color:%5;"
            "}"
            "QDialog#FileDetailDialogRoot QPushButton:pressed{"
            "  background:%5;"
            "  color:%7;"
            "  border-color:%5;"
            "}"
            "QDialog#FileDetailDialogRoot QProgressBar{"
            "  background:%6;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  text-align:center;"
            "}"
            "QDialog#FileDetailDialogRoot QProgressBar::chunk{"
            "  background:%5;"
            "  border-radius:2px;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar:vertical{"
            "  background:%4;"
            "  width:12px;"
            "  margin:0;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar:horizontal{"
            "  background:%4;"
            "  height:12px;"
            "  margin:0;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:vertical,"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:horizontal{"
            "  background:%5;"
            "  min-height:20px;"
            "  min-width:20px;"
            "  border-radius:4px;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:vertical:hover,"
            "QDialog#FileDetailDialogRoot QScrollBar::handle:horizontal:hover{"
            "  background:%1;"
            "}"
            "QDialog#FileDetailDialogRoot QScrollBar::add-line,"
            "QDialog#FileDetailDialogRoot QScrollBar::sub-line,"
            "QDialog#FileDetailDialogRoot QScrollBar::add-page,"
            "QDialog#FileDetailDialogRoot QScrollBar::sub-page{"
            "  background:%4;"
            "  border:none;"
            "}")
            .arg(KswordTheme::WindowColorHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::ControlAccentHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    // buildLogPreviewText 作用：
    // - 把多行结果压缩成单条日志预览文本，避免批量错误把日志面板刷满；
    // - 参数 sourceLines：原始明细文本集合；参数 maxLineCount：最多保留的行数；
    // - 返回：适合直接写入日志的 QString。
    QString buildLogPreviewText(const QStringList& sourceLines, const int maxLineCount = 8)
    {
        if (sourceLines.isEmpty())
        {
            return QStringLiteral("(空)");
        }

        QStringList previewLines;
        const int sourceLineCount = static_cast<int>(sourceLines.size());
        const int previewCount = sourceLineCount < maxLineCount
            ? sourceLineCount
            : maxLineCount;
        previewLines.reserve(previewCount + 1);
        for (int index = 0; index < previewCount; ++index)
        {
            previewLines.push_back(sourceLines[index]);
        }
        if (sourceLines.size() > previewCount)
        {
            previewLines.push_back(
                QStringLiteral("... 其余 %1 行省略").arg(sourceLines.size() - previewCount));
        }
        return previewLines.join(QStringLiteral("\n"));
    }

    // 面包屑按钮样式：视觉上“嵌入输入框”，并保留轻量 hover 提示。
    QString buildBreadcrumbButtonStyle()
    {
        return QStringLiteral(
            "QToolButton{"
            "  color:%1;"
            "  background:transparent;"
            "  border:none;"
            "  padding:0 4px;"
            "}"
            "QToolButton:hover{"
            "  background:%2;"
            "  color:%1;"
            "  border-radius:3px;"
            "}"
            "QToolButton:pressed{"
            "  background:%3;"
            "  color:%4;"
            "}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue, -14, -40))
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    // 递归复制目录：用于跨面板复制目录场景。
    bool copyDirectoryRecursively(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        if (isPathReparsePoint(sourcePath))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                .arg(QDir::toNativeSeparators(sourcePath));
            return false;
        }

        QDir sourceDir(sourcePath);
        if (!sourceDir.exists())
        {
            errorTextOut = QStringLiteral("源目录不存在: %1").arg(sourcePath);
            return false;
        }

        QDir targetDir;
        if (!targetDir.mkpath(targetPath))
        {
            errorTextOut = QStringLiteral("创建目标目录失败: %1").arg(targetPath);
            return false;
        }

        const QFileInfoList entries = sourceDir.entryInfoList(
            QDir::NoDotAndDotDot | QDir::AllEntries | QDir::Hidden | QDir::System);
        for (const QFileInfo& info : entries)
        {
            const QString src = info.absoluteFilePath();
            const QString dst = QDir(targetPath).filePath(info.fileName());

            if (info.isSymLink() || isPathReparsePoint(src))
            {
                errorTextOut = ks::i18n::displayText(QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                    .arg(QDir::toNativeSeparators(src));
                return false;
            }

            if (info.isDir())
            {
                if (!copyDirectoryRecursively(src, dst, errorTextOut))
                {
                    return false;
                }
            }
            else
            {
                if (!QFile::copy(src, dst))
                {
                    errorTextOut = QStringLiteral("复制文件失败: %1 -> %2").arg(src, dst);
                    return false;
                }
            }
        }

        return true;
    }

    // copyFileTransactionally 作用：先写同目录临时文件，完整落盘后再替换目标；失败时保留旧目标。
    bool copyFileTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        QFile sourceFile(sourcePath);
        if (!sourceFile.open(QIODevice::ReadOnly))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("打开源文件失败: %1 (%2)"))
                .arg(sourcePath, sourceFile.errorString());
            return false;
        }

        QSaveFile targetFile(targetPath);
        // 禁止 direct-write fallback，避免临时文件创建失败时直接截断现有目标。
        targetFile.setDirectWriteFallback(false);
        if (!targetFile.open(QIODevice::WriteOnly))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("创建目标临时文件失败: %1 (%2)"))
                .arg(targetPath, targetFile.errorString());
            return false;
        }

        QByteArray copyBuffer(1024 * 1024, Qt::Uninitialized);
        while (true)
        {
            const qint64 bytesRead = sourceFile.read(copyBuffer.data(), copyBuffer.size());
            if (bytesRead < 0)
            {
                targetFile.cancelWriting();
                errorTextOut = ks::i18n::displayText(QStringLiteral("读取源文件失败: %1 (%2)"))
                    .arg(sourcePath, sourceFile.errorString());
                return false;
            }
            if (bytesRead == 0)
            {
                break;
            }
            if (targetFile.write(copyBuffer.data(), bytesRead) != bytesRead)
            {
                targetFile.cancelWriting();
                errorTextOut = ks::i18n::displayText(QStringLiteral("写入目标临时文件失败: %1 (%2)"))
                    .arg(targetPath, targetFile.errorString());
                return false;
            }
        }

        targetFile.setPermissions(QFileInfo(sourcePath).permissions());
        if (!targetFile.commit())
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("提交目标文件失败: %1 (%2)"))
                .arg(targetPath, targetFile.errorString());
            return false;
        }
        return true;
    }

    // uniqueSiblingTransactionPath 作用：为目录替换生成同卷临时路径，保证 rename 可回滚。
    QString uniqueSiblingTransactionPath(const QString& targetPath, const QString& roleText)
    {
        const QFileInfo targetInfo(targetPath);
        const QString transactionName = QStringLiteral("-ksword-%1-%2-%3")
            .arg(
                roleText,
                targetInfo.fileName(),
                QUuid::createUuid().toString(QUuid::WithoutBraces));
        return targetInfo.dir().filePath(transactionName);
    }

    // removeTransactionPath 作用：清理本次事务创建的文件或目录，不跟随其它目标路径。
    bool removeTransactionPath(const QString& path)
    {
        const QFileInfo pathInfo(path);
        if (!pathInfo.exists() && !pathInfo.isSymLink())
        {
            return true;
        }
        if (pathInfo.isDir() && !pathInfo.isSymLink())
        {
            return QDir(path).removeRecursively();
        }
        return QFile::remove(path);
    }

    // copyDirectoryTransactionally 作用：完整复制到同级 staging，再以 backup 回滚方式替换目标目录。
    bool copyDirectoryTransactionally(const QString& sourcePath, const QString& targetPath, QString& errorTextOut)
    {
        const QString stagingPath = uniqueSiblingTransactionPath(targetPath, QStringLiteral("staging"));
        const QString backupPath = uniqueSiblingTransactionPath(targetPath, QStringLiteral("backup"));
        const bool targetExisted = QFileInfo::exists(targetPath);

        if (!copyDirectoryRecursively(sourcePath, stagingPath, errorTextOut))
        {
            removeTransactionPath(stagingPath);
            return false;
        }

        QDir renameDir;
        if (targetExisted && !renameDir.rename(targetPath, backupPath))
        {
            removeTransactionPath(stagingPath);
            errorTextOut = ks::i18n::displayText(QStringLiteral("备份现有目标目录失败: %1 -> %2"))
                .arg(targetPath, backupPath);
            return false;
        }

        if (!renameDir.rename(stagingPath, targetPath))
        {
            const bool rollbackOk = !targetExisted || renameDir.rename(backupPath, targetPath);
            removeTransactionPath(stagingPath);
            errorTextOut = rollbackOk
                ? ks::i18n::displayText(QStringLiteral("提交目标目录失败，旧目标已恢复: %1")).arg(targetPath)
                : ks::i18n::displayText(QStringLiteral("提交目标目录失败且旧目标恢复失败: %1，备份位于 %2"))
                    .arg(targetPath, backupPath);
            return false;
        }

        if (targetExisted && !removeTransactionPath(backupPath))
        {
            errorTextOut = ks::i18n::displayText(QStringLiteral("目录已替换，但旧目标备份清理失败: %1"))
                .arg(backupPath);
            return false;
        }
        return true;
    }

    // runCommandCaptureText：
    // - 作用：同步执行 cmd 命令并返回标准输出/错误输出合并文本。
    // - 参数 commandText：传入 cmd /C 后执行的命令字符串。
    // - 参数 outputTextOut：返回执行输出文本，便于错误提示。
    // - 参数 exitCodeOut：返回进程退出码，调用方用于判断成功/失败。
    bool runCommandCaptureText(const QString& commandText, QString& outputTextOut, int& exitCodeOut)
    {
        QProcess process;
        process.setProgram(QStringLiteral("cmd.exe"));
        process.setArguments(QStringList{ QStringLiteral("/C"), commandText });
        process.start();
        process.waitForFinished(-1);

        const QByteArray stdOutBytes = process.readAllStandardOutput();
        const QByteArray stdErrBytes = process.readAllStandardError();
        outputTextOut = QString::fromLocal8Bit(stdOutBytes + stdErrBytes).trimmed();
        exitCodeOut = process.exitCode();
        return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    }

    // openCommandPromptInDirectory：
    // - 作用：用 Win32 CreateProcessW 显式创建一个新控制台 cmd.exe，并把工作目录设置为目标路径；
    // - 参数 workPath：要作为 cmd 当前目录的文件夹路径；会转换为 Windows 原生分隔符；
    // - 参数 errorCodeOut：返回 CreateProcessW 失败时的 GetLastError，成功时为 ERROR_SUCCESS；
    // - 返回：true 表示 cmd 进程已创建；false 表示创建失败。
    bool openCommandPromptInDirectory(const QString& workPath, DWORD* const errorCodeOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }

        const QString nativeWorkPath = QDir::toNativeSeparators(workPath);
        std::wstring commandLineText = L"cmd.exe /K";
        std::wstring currentDirectoryText = nativeWorkPath.toStdWString();
        if (currentDirectoryText.empty())
        {
            currentDirectoryText = QDir::toNativeSeparators(QDir::homePath()).toStdWString();
        }

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};

        const BOOL createOk = ::CreateProcessW(
            nullptr,
            commandLineText.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NEW_CONSOLE,
            nullptr,
            currentDirectoryText.c_str(),
            &startupInfo,
            &processInfo);
        if (createOk == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        if (processInfo.hThread != nullptr)
        {
            ::CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            ::CloseHandle(processInfo.hProcess);
        }
        return true;
    }

    // takeOwnershipBySystemCommand：
    // - 作用：对目标路径执行 takeown 与 icacls，获取所有权并授权管理员组完全控制。
    // - 参数 targetPath：待处理文件/目录路径。
    // - 参数 detailTextOut：输出步骤详情（失败时用于提示）。
    // - 返回：全部步骤成功时返回 true。
    bool takeOwnershipBySystemCommand(const QString& targetPath, QString& detailTextOut)
    {
        const QFileInfo info(targetPath);
        const QString quotedPath = QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(targetPath));
        const QString takeOwnCommand = info.isDir()
            ? QStringLiteral("takeown /F %1 /A /R /D Y").arg(quotedPath)
            : QStringLiteral("takeown /F %1 /A").arg(quotedPath);
        const QString grantCommand = info.isDir()
            ? QStringLiteral("icacls %1 /grant *S-1-5-32-544:F /T /C").arg(quotedPath)
            : QStringLiteral("icacls %1 /grant *S-1-5-32-544:F /C").arg(quotedPath);

        QString firstOutput;
        int firstExitCode = -1;
        const bool takeOwnOk = runCommandCaptureText(takeOwnCommand, firstOutput, firstExitCode);

        QString secondOutput;
        int secondExitCode = -1;
        const bool grantOk = runCommandCaptureText(grantCommand, secondOutput, secondExitCode);

        detailTextOut = QStringLiteral(
            "目标: %1\n"
            "takeown命令: %2\n"
            "takeown退出码: %3\n"
            "takeown输出:\n%4\n\n"
            "icacls命令: %5\n"
            "icacls退出码: %6\n"
            "icacls输出:\n%7")
            .arg(QDir::toNativeSeparators(targetPath))
            .arg(takeOwnCommand)
            .arg(firstExitCode)
            .arg(firstOutput.isEmpty() ? QStringLiteral("<无输出>") : firstOutput)
            .arg(grantCommand)
            .arg(secondExitCode)
            .arg(secondOutput.isEmpty() ? QStringLiteral("<无输出>") : secondOutput);
        return takeOwnOk && grantOk;
    }

    // sidUseToText 作用：
    // - 把 SID_NAME_USE 枚举转换为可读文本；
    // - 用于 ACL 列表中显示主体类型（用户/组/域等）。
    QString sidUseToText(const SID_NAME_USE sidUse)
    {
        switch (sidUse)
        {
        case SidTypeUser: return QStringLiteral("User");
        case SidTypeGroup: return QStringLiteral("Group");
        case SidTypeDomain: return QStringLiteral("Domain");
        case SidTypeAlias: return QStringLiteral("Alias");
        case SidTypeWellKnownGroup: return QStringLiteral("WellKnownGroup");
        case SidTypeDeletedAccount: return QStringLiteral("DeletedAccount");
        case SidTypeInvalid: return QStringLiteral("Invalid");
        case SidTypeUnknown: return QStringLiteral("Unknown");
        case SidTypeComputer: return QStringLiteral("Computer");
        case SidTypeLabel: return QStringLiteral("Label");
        default: return QStringLiteral("Other");
        }
    }

    // sidToStringText 作用：
    // - 把 PSID 转换为标准字符串形式（S-1-5-...）；
    // - 失败时返回包含错误信息的占位文本。
    QString sidToStringText(PSID sidValue)
    {
        if (sidValue == nullptr)
        {
            return QStringLiteral("<空SID>");
        }
        LPWSTR sidStringBuffer = nullptr;
        if (::ConvertSidToStringSidW(sidValue, &sidStringBuffer) == FALSE || sidStringBuffer == nullptr)
        {
            return QStringLiteral("<SID转换失败 code=%1>").arg(::GetLastError());
        }
        QString sidText = QString::fromWCharArray(sidStringBuffer);
        ::LocalFree(sidStringBuffer);
        return sidText;
    }

    // sidToAccountText 作用：
    // - 通过 LookupAccountSidW 解析 SID 的域名与账户名；
    // - 解析失败时保留错误码，便于权限审计定位。
    QString sidToAccountText(PSID sidValue)
    {
        if (sidValue == nullptr)
        {
            return QStringLiteral("<空SID>");
        }

        wchar_t accountBuffer[256] = {};
        wchar_t domainBuffer[256] = {};
        DWORD accountSize = static_cast<DWORD>(std::size(accountBuffer));
        DWORD domainSize = static_cast<DWORD>(std::size(domainBuffer));
        SID_NAME_USE sidUse = SidTypeUnknown;
        if (::LookupAccountSidW(
            nullptr,
            sidValue,
            accountBuffer,
            &accountSize,
            domainBuffer,
            &domainSize,
            &sidUse) == FALSE)
        {
            return QStringLiteral("<账户解析失败 code=%1>").arg(::GetLastError());
        }

        const QString accountText = QString::fromWCharArray(accountBuffer);
        const QString domainText = QString::fromWCharArray(domainBuffer);
        if (domainText.isEmpty())
        {
            return QStringLiteral("%1 (%2)").arg(accountText, sidUseToText(sidUse));
        }
        return QStringLiteral("%1\\%2 (%3)").arg(domainText, accountText, sidUseToText(sidUse));
    }

    // aceTypeToText 作用：
    // - 把 ACE_HEADER::AceType 转换为可读文本；
    // - 未覆盖类型保留原始数值，避免信息丢失。
    QString aceTypeToText(const BYTE aceType)
    {
        switch (aceType)
        {
        case ACCESS_ALLOWED_ACE_TYPE: return QStringLiteral("ACCESS_ALLOWED");
        case ACCESS_DENIED_ACE_TYPE: return QStringLiteral("ACCESS_DENIED");
        case SYSTEM_AUDIT_ACE_TYPE: return QStringLiteral("SYSTEM_AUDIT");
        case SYSTEM_ALARM_ACE_TYPE: return QStringLiteral("SYSTEM_ALARM");
        case ACCESS_ALLOWED_OBJECT_ACE_TYPE: return QStringLiteral("ACCESS_ALLOWED_OBJECT");
        case ACCESS_DENIED_OBJECT_ACE_TYPE: return QStringLiteral("ACCESS_DENIED_OBJECT");
        case SYSTEM_AUDIT_OBJECT_ACE_TYPE: return QStringLiteral("SYSTEM_AUDIT_OBJECT");
        case SYSTEM_MANDATORY_LABEL_ACE_TYPE: return QStringLiteral("MANDATORY_LABEL");
        default:
            return QStringLiteral("ACE_%1").arg(aceType);
        }
    }

    // aceFlagsToText 作用：
    // - 解析 ACE 继承/审计标志位；
    // - 返回以“|”分隔的复合文本。
    QString aceFlagsToText(const BYTE aceFlags)
    {
        QStringList flagList;
        if ((aceFlags & OBJECT_INHERIT_ACE) != 0) flagList << QStringLiteral("OBJECT_INHERIT");
        if ((aceFlags & CONTAINER_INHERIT_ACE) != 0) flagList << QStringLiteral("CONTAINER_INHERIT");
        if ((aceFlags & NO_PROPAGATE_INHERIT_ACE) != 0) flagList << QStringLiteral("NO_PROPAGATE");
        if ((aceFlags & INHERIT_ONLY_ACE) != 0) flagList << QStringLiteral("INHERIT_ONLY");
        if ((aceFlags & INHERITED_ACE) != 0) flagList << QStringLiteral("INHERITED");
        if ((aceFlags & SUCCESSFUL_ACCESS_ACE_FLAG) != 0) flagList << QStringLiteral("AUDIT_SUCCESS");
        if ((aceFlags & FAILED_ACCESS_ACE_FLAG) != 0) flagList << QStringLiteral("AUDIT_FAIL");
        return flagList.isEmpty() ? QStringLiteral("None") : flagList.join('|');
    }

    // accessMaskToText 作用：
    // - 把文件系统访问掩码拆解为常见权限名；
    // - 既保留 GENERIC_*，也保留 FILE_* 细粒度权限。
    QString accessMaskToText(const DWORD accessMask)
    {
        QStringList rightList;
        if ((accessMask & GENERIC_ALL) != 0) rightList << QStringLiteral("GENERIC_ALL");
        if ((accessMask & GENERIC_READ) != 0) rightList << QStringLiteral("GENERIC_READ");
        if ((accessMask & GENERIC_WRITE) != 0) rightList << QStringLiteral("GENERIC_WRITE");
        if ((accessMask & GENERIC_EXECUTE) != 0) rightList << QStringLiteral("GENERIC_EXECUTE");
        if ((accessMask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS) rightList << QStringLiteral("FILE_ALL_ACCESS");
        if ((accessMask & FILE_GENERIC_READ) == FILE_GENERIC_READ) rightList << QStringLiteral("FILE_GENERIC_READ");
        if ((accessMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE) rightList << QStringLiteral("FILE_GENERIC_WRITE");
        if ((accessMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE) rightList << QStringLiteral("FILE_GENERIC_EXECUTE");
        if ((accessMask & FILE_READ_DATA) != 0) rightList << QStringLiteral("READ_DATA");
        if ((accessMask & FILE_WRITE_DATA) != 0) rightList << QStringLiteral("WRITE_DATA");
        if ((accessMask & FILE_APPEND_DATA) != 0) rightList << QStringLiteral("APPEND_DATA");
        if ((accessMask & FILE_EXECUTE) != 0) rightList << QStringLiteral("EXECUTE");
        if ((accessMask & FILE_READ_ATTRIBUTES) != 0) rightList << QStringLiteral("READ_ATTRIBUTES");
        if ((accessMask & FILE_WRITE_ATTRIBUTES) != 0) rightList << QStringLiteral("WRITE_ATTRIBUTES");
        if ((accessMask & FILE_READ_EA) != 0) rightList << QStringLiteral("READ_EA");
        if ((accessMask & FILE_WRITE_EA) != 0) rightList << QStringLiteral("WRITE_EA");
        if ((accessMask & DELETE) != 0) rightList << QStringLiteral("DELETE");
        if ((accessMask & READ_CONTROL) != 0) rightList << QStringLiteral("READ_CONTROL");
        if ((accessMask & WRITE_DAC) != 0) rightList << QStringLiteral("WRITE_DAC");
        if ((accessMask & WRITE_OWNER) != 0) rightList << QStringLiteral("WRITE_OWNER");
        if ((accessMask & SYNCHRONIZE) != 0) rightList << QStringLiteral("SYNCHRONIZE");
        return rightList.isEmpty() ? QStringLiteral("None") : rightList.join('|');
    }

    struct FileSecurityAceRow
    {
        QString scopeText;       // scopeText：ACE 来源范围，当前主要为 DACL/SACL。
        QString typeText;        // typeText：ACE 类型文本，例如 ACCESS_ALLOWED。
        QString flagsText;       // flagsText：继承/审计标志文本。
        DWORD mask = 0;          // mask：原始访问掩码，用于显示和后续编辑定位。
        QString rightsText;      // rightsText：mask 拆解后的常见文件权限名。
        QString sidText;         // sidText：字符串 SID，便于稳定定位。
        QString accountText;     // accountText：LookupAccountSidW 解析出的账户名。
        DWORD aceIndex = 0;      // aceIndex：ACL 内 ACE 序号。
        bool canEdit = false;    // canEdit：当前 UI 是否允许对该 ACE 执行删除/替换。
    };

    struct FileSecuritySnapshot
    {
        bool descriptorOk = false;        // descriptorOk：Owner/Group/DACL 是否读取成功。
        bool saclOk = false;              // saclOk：SACL 是否读取成功。
        DWORD descriptorError = ERROR_SUCCESS; // descriptorError：读取 Owner/Group/DACL 的 Win32 错误码。
        DWORD saclError = ERROR_SUCCESS;       // saclError：读取 SACL 的 Win32 错误码。
        QString ownerSidText;             // ownerSidText：Owner SID 字符串。
        QString ownerAccountText;         // ownerAccountText：Owner 账户文本。
        QString groupSidText;             // groupSidText：Primary Group SID 字符串。
        QString groupAccountText;         // groupAccountText：Primary Group 账户文本。
        QString detailText;               // detailText：兼容旧版本的完整文本明细，读取失败也会保留错误。
        std::vector<FileSecurityAceRow> aceRows; // aceRows：表格化 ACE 列表。
    };

    // appendAclRows：
    // - 输入 scopeText/aclValue：ACL 名称与 Windows ACL 指针。
    // - 处理：解析支持的 ACE 结构并转换为 UI 表格行；未知 ACE 仍进入文本明细。
    // - 返回：无，解析出的行追加到 rowsOut。
    void appendAclRows(const QString& scopeText, PACL aclValue, std::vector<FileSecurityAceRow>& rowsOut)
    {
        if (aclValue == nullptr)
        {
            return;
        }

        ACL_SIZE_INFORMATION aclSizeInfo{};
        if (::GetAclInformation(
            aclValue,
            &aclSizeInfo,
            static_cast<DWORD>(sizeof(aclSizeInfo)),
            AclSizeInformation) == FALSE)
        {
            return;
        }

        for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
        {
            LPVOID acePointer = nullptr;
            if (::GetAce(aclValue, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
            {
                continue;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            DWORD accessMask = 0;
            PSID aceSid = nullptr;
            bool editableAce = false;

            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                editableAce = scopeText == QStringLiteral("DACL") && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                break;
            }
            case ACCESS_DENIED_ACE_TYPE:
            {
                ACCESS_DENIED_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                editableAce = scopeText == QStringLiteral("DACL") && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                break;
            }
            case SYSTEM_AUDIT_ACE_TYPE:
            {
                SYSTEM_AUDIT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            {
                ACCESS_ALLOWED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
            {
                ACCESS_DENIED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            {
                SYSTEM_AUDIT_OBJECT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            default:
                break;
            }

            FileSecurityAceRow row;
            row.scopeText = scopeText;
            row.typeText = aceTypeToText(aceHeader->AceType);
            row.flagsText = aceFlagsToText(aceHeader->AceFlags);
            row.mask = accessMask;
            row.rightsText = accessMaskToText(accessMask);
            row.sidText = sidToStringText(aceSid);
            row.accountText = sidToAccountText(aceSid);
            row.aceIndex = aceIndex;
            row.canEdit = editableAce && aceSid != nullptr;
            rowsOut.push_back(row);
        }
    }

    // createReadonlyTableItem：
    // - 输入 cellText：待展示文本。
    // - 处理：创建不可编辑表格单元格，避免权限表误触编辑。
    // - 返回：新建 QTableWidgetItem，由表格接管生命周期。
    QTableWidgetItem* createReadonlyTableItem(const QString& cellText)
    {
        QTableWidgetItem* item = new QTableWidgetItem(cellText);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    // formatAccessMaskHex：
    // - 输入 accessMask：Win32 文件访问掩码。
    // - 处理：统一格式化为 8 位十六进制。
    // - 返回：0x 前缀大写文本。
    QString formatAccessMaskHex(const DWORD accessMask)
    {
        return QStringLiteral("0x%1")
            .arg(accessMask, 8, 16, QLatin1Char('0'))
            .toUpper();
    }

    // appendAclText 作用：
    // - 解析 ACL 中每一条 ACE，输出类型、标志、掩码、SID 与账户名；
    // - titleText 用于区分 DACL 与 SACL 段落。
    void appendAclText(const QString& titleText, PACL aclValue, QString& contentOut)
    {
        contentOut += QStringLiteral("\n[%1]\n").arg(titleText);
        if (aclValue == nullptr)
        {
            contentOut += QStringLiteral("ACL: <null>\n");
            return;
        }

        ACL_SIZE_INFORMATION aclSizeInfo{};
        if (::GetAclInformation(
            aclValue,
            &aclSizeInfo,
            static_cast<DWORD>(sizeof(aclSizeInfo)),
            AclSizeInformation) == FALSE)
        {
            contentOut += QStringLiteral("读取 ACL 信息失败, code=%1\n").arg(::GetLastError());
            return;
        }

        contentOut += QStringLiteral("ACE数量: %1\n").arg(aclSizeInfo.AceCount);
        for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
        {
            LPVOID acePointer = nullptr;
            if (::GetAce(aclValue, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
            {
                contentOut += QStringLiteral("  - ACE[%1] 读取失败, code=%2\n").arg(aceIndex).arg(::GetLastError());
                continue;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            DWORD accessMask = 0;
            PSID aceSid = nullptr;

            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_ACE_TYPE:
            {
                ACCESS_DENIED_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_ACE_TYPE:
            {
                SYSTEM_AUDIT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_ALLOWED_OBJECT_ACE_TYPE:
            {
                ACCESS_ALLOWED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case ACCESS_DENIED_OBJECT_ACE_TYPE:
            {
                ACCESS_DENIED_OBJECT_ACE* aceBody = reinterpret_cast<ACCESS_DENIED_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_AUDIT_OBJECT_ACE_TYPE:
            {
                SYSTEM_AUDIT_OBJECT_ACE* aceBody = reinterpret_cast<SYSTEM_AUDIT_OBJECT_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
            {
                ACCESS_ALLOWED_ACE* aceBody = reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer);
                accessMask = aceBody->Mask;
                aceSid = reinterpret_cast<PSID>(&aceBody->SidStart);
                break;
            }
            default:
                break;
            }

            contentOut += QStringLiteral("  - ACE[%1]\n").arg(aceIndex);
            contentOut += QStringLiteral("    类型: %1\n").arg(aceTypeToText(aceHeader->AceType));
            contentOut += QStringLiteral("    标志: %1\n").arg(aceFlagsToText(aceHeader->AceFlags));
            contentOut += QStringLiteral("    Mask: 0x%1\n").arg(accessMask, 8, 16, QLatin1Char('0'));
            contentOut += QStringLiteral("    权限: %1\n").arg(accessMaskToText(accessMask));
            contentOut += QStringLiteral("    SID: %1\n").arg(sidToStringText(aceSid));
            contentOut += QStringLiteral("    账户: %1\n").arg(sidToAccountText(aceSid));
        }
    }

    // 简单文件详情对话框：按 Tab 展示通用/安全/哈希/签名/PE/字符串/十六进制。
    class FileDetailDialog final : public QDialog
    {
    public:
        explicit FileDetailDialog(
            const QString& filePath,
            QWidget* parent = nullptr,
            const QString& initialTabKey = QString())
            : FileDetailDialog(QStringList{ filePath }, parent, initialTabKey)
        {
        }

        explicit FileDetailDialog(
            const QStringList& filePaths,
            QWidget* parent = nullptr,
            const QString& initialTabKey = QString())
            : QDialog(parent)
            , m_filePaths(filePaths)
            , m_filePath(filePaths.value(0))
            , m_batchMode(filePaths.size() > 1)
            , m_initialTabKey(initialTabKey.trimmed().toLower())
        {
            QStringList normalizedPaths;
            QSet<QString> seenPaths;
            for (const QString& candidatePath : m_filePaths)
            {
                const QString normalizedPath = QDir::cleanPath(
                    QDir::toNativeSeparators(candidatePath.trimmed()));
                const QString identityKey = normalizedPath.toLower();
                if (!normalizedPath.isEmpty() && !seenPaths.contains(identityKey))
                {
                    seenPaths.insert(identityKey);
                    normalizedPaths.push_back(normalizedPath);
                }
            }
            m_filePaths = normalizedPaths;
            m_filePath = m_filePaths.value(0);
            m_batchMode = m_filePaths.size() > 1;
            m_hashCancelRequested = std::make_shared<std::atomic_bool>(false);
            m_usageScanCancelRequested = std::make_shared<std::atomic_bool>(false);
            // 文件属性与进程属性同为独立、非模态详情窗；不要继承隐藏 Dock 的子窗口外观。
            setWindowFlag(Qt::Window, true);
            setWindowModality(Qt::NonModal);
            setAttribute(Qt::WA_DeleteOnClose, true);
            setObjectName(QStringLiteral("FileDetailDialogRoot"));
            setWindowTitle(m_batchMode
                ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项")).arg(m_filePaths.size())
                : QStringLiteral("文件属性 - %1").arg(QFileInfo(m_filePath).fileName()));
            // 文件属性窗内容可能包含超长路径、证书链和 PE 字段：
            // - 最大宽度按父窗口客户区 75% 限制；
            // - 初始宽度同步裁剪，防止窗口被长文本撑出屏幕。
            applyFileStandaloneWindowWidthLimit(
                this,
                resolveVisibleDialogParent(parent),
                QSize(1160, 760),
                0.75);

            // 采用与进程属性相同的左侧导航结构：QTabWidget 继续承载现有懒加载逻辑，
            // 仅隐藏原生顶栏并改由可翻译的垂直导航按钮驱动。
            QVBoxLayout* dialogLayout = new QVBoxLayout(this);
            dialogLayout->setContentsMargins(8, 8, 8, 8);
            dialogLayout->setSpacing(6);
            QHBoxLayout* rootLayout = new QHBoxLayout();
            rootLayout->setContentsMargins(0, 0, 0, 0);
            rootLayout->setSpacing(6);
            dialogLayout->addLayout(rootLayout, 1);

            m_tabNavigation = new QWidget(this);
            m_tabNavigation->setObjectName(QStringLiteral("FileDetailTabNavigation"));
            m_tabNavigation->setFixedWidth(210);
            m_tabNavigation->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
            QVBoxLayout* navigationLayout = new QVBoxLayout(m_tabNavigation);
            navigationLayout->setContentsMargins(5, 5, 5, 5);
            navigationLayout->setSpacing(4);

            m_tabWidget = new QTabWidget(this);
            m_tabWidget->tabBar()->hide();
            m_tabNavigationButtonGroup = new QButtonGroup(this);
            m_tabNavigationButtonGroup->setExclusive(true);
            rootLayout->addWidget(m_tabNavigation);
            rootLayout->addWidget(m_tabWidget, 1);

            m_tabWidget->addTab(buildGeneralTab(), QStringLiteral("常规信息"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("metadata")), QStringLiteral("元数据编辑"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("reparse")), QStringLiteral("重解析点 / 符号链接"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("security")), QStringLiteral("安全与权限"));
            m_tabWidget->addTab(buildHashTab(), QStringLiteral("哈希与完整性"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("usage")), QStringLiteral("文件占用与解锁"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("fileobject")), QStringLiteral("FileObject / Section / ControlArea"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("storage")), QStringLiteral("Storage / MountMgr / FVE"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("filters")), QStringLiteral("Minifilter / Instance / Volume"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("signature")), QStringLiteral("数字签名"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("pe")), QStringLiteral("PE信息"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("dependencies")), QStringLiteral("依赖 DLL"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("strings")), QStringLiteral("字符串"));
            m_tabWidget->addTab(buildDeferredTab(QStringLiteral("hex")), QStringLiteral("十六进制"));
            // addTab 会让 Qt 重新显示 tabBar，必须在页面齐备后再次隐藏。
            m_tabWidget->tabBar()->hide();

            const QList<QPair<QString, QString>> detailTabTranslations{
                {QStringLiteral("file.detail.tab.general"), QStringLiteral("常规信息")},
                {QStringLiteral("file.detail.tab.metadata"), QStringLiteral("元数据编辑")},
                {QStringLiteral("file.detail.tab.reparse"), QStringLiteral("重解析点 / 符号链接")},
                {QStringLiteral("file.detail.tab.security"), QStringLiteral("安全与权限")},
                {QStringLiteral("file.detail.tab.hash"), QStringLiteral("哈希与完整性")},
                {QStringLiteral("file.detail.tab.usage"), QStringLiteral("文件占用与解锁")},
                {QStringLiteral("file.detail.tab.fileobject"), QStringLiteral("FileObject / Section / ControlArea")},
                {QStringLiteral("file.detail.tab.storage"), QStringLiteral("Storage / MountMgr / FVE")},
                {QStringLiteral("file.detail.tab.filters"), QStringLiteral("Minifilter / Instance / Volume")},
                {QStringLiteral("file.detail.tab.signature"), QStringLiteral("数字签名")},
                {QStringLiteral("file.detail.tab.pe"), QStringLiteral("PE信息")},
                {QStringLiteral("file.detail.tab.dependencies"), QStringLiteral("依赖 DLL")},
                {QStringLiteral("file.detail.tab.strings"), QStringLiteral("字符串")},
                {QStringLiteral("file.detail.tab.hex"), QStringLiteral("十六进制")}
            };
            for (int tabIndex = 0; tabIndex < detailTabTranslations.size(); ++tabIndex)
            {
                const auto& translation = detailTabTranslations.at(tabIndex);
                ks::i18n::LanguageManager::instance().bindTab(
                    m_tabWidget,
                    m_tabWidget->widget(tabIndex),
                    translation.first,
                    translation.second);
            }

            const QList<QString> navigationIconPathList{
                QStringLiteral(":/Icon/process_details.svg"),
                QStringLiteral(":/Icon/process_copy_cell.svg"),
                QStringLiteral(":/Icon/file_nav_forward.svg"),
                QStringLiteral(":/Icon/file_owner.svg"),
                QStringLiteral(":/Icon/process_performance.svg"),
                QStringLiteral(":/Icon/process_main.svg"),
                QStringLiteral(":/Icon/process_details.svg"),
                QStringLiteral(":/Icon/disk_storage.svg"),
                QStringLiteral(":/Icon/filter_funnel.svg"),
                QStringLiteral(":/Icon/process_critical.svg"),
                QStringLiteral(":/Icon/process_list.svg"),
                QStringLiteral(":/Icon/process_copy_row.svg"),
                QStringLiteral(":/Icon/file_find.svg"),
                QStringLiteral(":/Icon/process_copy_cell.svg")
            };
            for (int tabIndex = 0; tabIndex < detailTabTranslations.size(); ++tabIndex)
            {
                const auto& translation = detailTabTranslations.at(tabIndex);
                QToolButton* navigationButton = new QToolButton(m_tabNavigation);
                navigationButton->setCheckable(true);
                navigationButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
                navigationButton->setIcon(QIcon(navigationIconPathList.value(tabIndex)));
                navigationButton->setIconSize(QSize(18, 18));
                navigationButton->setMinimumHeight(30);
                navigationButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
                ks::i18n::LanguageManager::instance().bindText(
                    navigationButton,
                    translation.first,
                    translation.second);
                ks::i18n::LanguageManager::instance().bindToolTip(
                    navigationButton,
                    translation.first,
                    translation.second);
                m_tabNavigationButtonGroup->addButton(navigationButton, tabIndex);
                m_tabNavigationButtons.push_back(navigationButton);
                navigationLayout->addWidget(navigationButton);
                connect(navigationButton, &QToolButton::clicked, this, [this, tabIndex]()
                    {
                        if (m_tabWidget != nullptr)
                        {
                            m_tabWidget->setCurrentIndex(tabIndex);
                        }
                    });
            }
            if (m_batchMode)
            {
                const QSet<int> batchEnabledTabs{ 0, 1, 4 };
                for (int tabIndex = 0; tabIndex < m_tabNavigationButtons.size(); ++tabIndex)
                {
                    QToolButton* const navigationButton = m_tabNavigationButtons.at(tabIndex);
                    if (navigationButton == nullptr || batchEnabledTabs.contains(tabIndex))
                    {
                        continue;
                    }
                    navigationButton->setEnabled(false);
                    m_tabWidget->setTabEnabled(tabIndex, false);
                    navigationButton->setToolTip(ks::i18n::sourceText(QStringLiteral(
                        "批量模式下此分析页不可用。请只选择一个目标后打开该页。")));
                }
                QLabel* batchHintLabel = new QLabel(
                    ks::i18n::sourceText(QStringLiteral(
                        "批量模式：常规信息显示汇总，哈希与元数据编辑支持批量处理；其余单文件分析页已禁用。")),
                    m_tabNavigation);
                batchHintLabel->setWordWrap(true);
                batchHintLabel->setObjectName(QStringLiteral("FileDetailBatchHint"));
                navigationLayout->addWidget(batchHintLabel);
            }
            navigationLayout->addStretch(1);

            QFrame* saveBar = new QFrame(this);
            saveBar->setObjectName(QStringLiteral("FileMetadataSaveBar"));
            QHBoxLayout* saveLayout = new QHBoxLayout(saveBar);
            saveLayout->setContentsMargins(8, 6, 8, 6);
            m_backupBeforeSaveCheck = new QCheckBox(
                ks::i18n::sourceText(QStringLiteral("创建备份再修改")), saveBar);
            m_backupBeforeSaveCheck->setChecked(true);
            m_pendingChangesLabel = new QLabel(
                ks::i18n::sourceText(QStringLiteral("● 暂无待保存修改")), saveBar);
            m_pendingChangesLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            m_discardPendingButton = new QPushButton(
                ks::i18n::sourceText(QStringLiteral("放弃暂存")), saveBar);
            m_saveAllButton = new QPushButton(
                ks::i18n::sourceText(QStringLiteral("保存全部修改")), saveBar);
            m_saveAllButton->setDefault(true);
            m_discardPendingButton->setEnabled(false);
            m_saveAllButton->setEnabled(false);
            saveLayout->addWidget(m_backupBeforeSaveCheck);
            saveLayout->addWidget(m_pendingChangesLabel, 1);
            saveLayout->addWidget(m_discardPendingButton);
            saveLayout->addWidget(m_saveAllButton);
            dialogLayout->addWidget(saveBar, 0);
            connect(m_discardPendingButton, &QPushButton::clicked, this,
                [this]() { discardPendingChanges(); });
            connect(m_saveAllButton, &QPushButton::clicked, this,
                [this]() { saveAllPendingChanges(); });

            connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](const int tabIndex)
                {
                    if (tabIndex >= 0 && tabIndex < m_tabNavigationButtons.size())
                    {
                        QToolButton* const navigationButton = m_tabNavigationButtons.at(tabIndex);
                        if (navigationButton != nullptr)
                        {
                            navigationButton->setChecked(true);
                        }
                    }
                    activateDeferredTab(m_tabWidget, tabIndex);
                });
            constexpr int usageTabIndex = 5;
            if (m_initialTabKey == QStringLiteral("usage"))
            {
                m_tabWidget->setCurrentIndex(usageTabIndex);
            }
            else if (!m_tabNavigationButtons.isEmpty())
            {
                m_tabNavigationButtons.front()->setChecked(true);
            }
            applyThemeStyle();
        }

        ~FileDetailDialog() override
        {
            // 关闭即销毁的属性窗不能留下继续跑全系统枚举的任务；两个后台入口
            // 都只共享原子取消标记，不在析构线程等待，也不访问已经释放的控件。
            if (m_hashCancelRequested != nullptr)
            {
                m_hashCancelRequested->store(true);
            }
            if (m_usageScanCancelRequested != nullptr)
            {
                m_usageScanCancelRequested->store(true);
            }
        }

    protected:
        void closeEvent(QCloseEvent* event) override
        {
            if (event == nullptr)
            {
                return;
            }
            if (m_transactionBusy)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("正在保存文件元数据")),
                    ks::i18n::sourceText(QStringLiteral(
                        "保存事务仍在运行。请等待逐操作结果返回后再关闭窗口。")));
                event->ignore();
                return;
            }
            if (pendingTargetCount() > 0)
            {
                const QMessageBox::StandardButton choice = QMessageBox::question(
                    this,
                    ks::i18n::sourceText(QStringLiteral("放弃暂存修改")),
                    ks::i18n::sourceText(QStringLiteral(
                        "仍有尚未写入的暂存修改。关闭窗口将放弃这些修改，文件不会变化。是否关闭？")),
                    QMessageBox::Yes | QMessageBox::No,
                    QMessageBox::No);
                if (choice != QMessageBox::Yes)
                {
                    event->ignore();
                    return;
                }
            }
            QDialog::closeEvent(event);
        }

        void changeEvent(QEvent* event) override
        {
            QDialog::changeEvent(event);
            if (event == nullptr)
            {
                return;
            }
            if (event->type() == QEvent::LanguageChange)
            {
                setWindowTitle(m_batchMode
                    ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项")).arg(m_filePaths.size())
                    : ks::i18n::displayText(QStringLiteral("文件属性 - %1"))
                        .arg(QFileInfo(m_filePath).fileName()));
                refreshGeneralTab();
                return;
            }
            if (event->type() == QEvent::ApplicationPaletteChange ||
                event->type() == QEvent::PaletteChange)
            {
                applyThemeStyle();
            }
        }

    private:
        void applyThemeStyle()
        {
            if (m_themeStyleApplying)
            {
                return;
            }
            m_themeStyleApplying = true;

            const QPalette dialogPalette = buildFileDetailDialogPalette(this);
            QPalette surfacePalette = dialogPalette;
            surfacePalette.setColor(QPalette::Window, KswordTheme::SurfaceColor());
            surfacePalette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
            applyFileDetailSurfacePalette(this, dialogPalette);
            setStyleSheet(buildFileDetailDialogStyle());

            applyFileDetailSurfacePalette(m_tabNavigation, surfacePalette);
            applyFileDetailSurfacePalette(m_tabWidget, surfacePalette);
            if (m_tabWidget != nullptr)
            {
                for (int tabIndex = 0; tabIndex < m_tabWidget->count(); ++tabIndex)
                {
                    applyFileDetailSurfacePalette(m_tabWidget->widget(tabIndex), surfacePalette);
                }
            }

            m_themeStyleApplying = false;
        }

        struct HashCalculationResult
        {
            bool openOk = false;       // openOk：文件是否成功打开。
            bool cancelled = false;    // cancelled：用户是否取消。
            qint64 totalBytes = 0;     // totalBytes：文件总大小。
            qint64 readBytes = 0;      // readBytes：实际读取字节数。
            qint64 elapsedMs = 0;      // elapsedMs：耗时毫秒。
            QString sha256Text;        // sha256Text：十六进制 SHA256。
            QFileDevice::FileError fileError = QFileDevice::NoError; // fileError：稳定、与系统 UI 语言无关的错误码。
        };

        struct PrintableStringsPreview
        {
            QString sourcePrefixText;  // sourcePrefixText：应用生成且需要翻译的说明。
            QString rawStringText;     // rawStringText：从文件提取的原始字符串，不得翻译。
        };

        struct FileMetadataSnapshot
        {
            bool ok = false;                 // ok：是否成功打开目标并读取 FileBasicInfo。
            DWORD win32Error = ERROR_SUCCESS; // win32Error：失败步骤的 Win32 错误码。
            FILE_BASIC_INFO basicInfo{};     // basicInfo：四个时间戳与完整属性位快照。
            bool identityAvailable = false;  // identityAvailable：卷序列号与文件索引是否可用于复核。
            DWORD volumeSerialNumber = 0U;   // volumeSerialNumber：文件所在卷身份。
            std::uint64_t fileIndex = 0U;    // fileIndex：同一卷内稳定文件身份。
        };

        struct FileMetadataUpdateRequest
        {
            std::array<bool, 4> updateTime{};       // updateTime：逐项决定是否写入对应时间。
            std::array<LARGE_INTEGER, 4> timeValue{}; // timeValue：本地编辑值转换后的 FILETIME 100ns。
            bool updateAttributes = false;         // updateAttributes：可编辑属性位是否发生变化。
            DWORD editableAttributes = 0U;         // editableAttributes：六个允许编辑的属性位。
            bool validateIdentity = false;         // validateIdentity：写入前是否必须匹配初始文件身份。
            DWORD expectedVolumeSerialNumber = 0U; // expectedVolumeSerialNumber：初始卷身份。
            std::uint64_t expectedFileIndex = 0U;  // expectedFileIndex：初始文件索引。
        };

        struct FileMetadataUpdateResult
        {
            bool ok = false;                  // ok：写入调用与回读是否都成功。
            bool verificationMatched = false; // verificationMatched：回读值是否匹配请求。
            DWORD win32Error = ERROR_SUCCESS; // win32Error：失败时保留稳定错误码。
            FileMetadataSnapshot snapshot;   // snapshot：写入后的实际 FileBasicInfo。
        };

        static const std::array<DWORD, 6>& editableFileAttributeMasks()
        {
            // 只开放 SetFileInformationByHandle(FileBasicInfo) 可直接、可逆切换的属性。
            // DIRECTORY/REPARSE_POINT/COMPRESSED/ENCRYPTED/SPARSE 等结构性位必须走各自专用 API。
            static const std::array<DWORD, 6> masks{
                FILE_ATTRIBUTE_READONLY,
                FILE_ATTRIBUTE_HIDDEN,
                FILE_ATTRIBUTE_SYSTEM,
                FILE_ATTRIBUTE_ARCHIVE,
                FILE_ATTRIBUTE_TEMPORARY,
                FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
            };
            return masks;
        }

        static DWORD editableFileAttributeMask()
        {
            DWORD mask = 0U;
            for (const DWORD attributeMask : editableFileAttributeMasks())
            {
                mask |= attributeMask;
            }
            return mask;
        }

        static HANDLE openFileMetadataHandle(
            const QString& filePath,
            const DWORD desiredAccess,
            DWORD& errorOut)
        {
            // OPEN_REPARSE_POINT 保证叶节点是链接时修改链接自身，而不是静默跟随到目标。
            // BACKUP_SEMANTICS 同时允许目录句柄；共享删除避免与资源管理器产生不必要冲突。
            const std::wstring nativePath = QDir::toNativeSeparators(filePath).toStdWString();
            if (nativePath.empty())
            {
                errorOut = ERROR_INVALID_PARAMETER;
                return INVALID_HANDLE_VALUE;
            }

            HANDLE fileHandle = ::CreateFileW(
                nativePath.c_str(),
                desiredAccess,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                nullptr);
            errorOut = fileHandle == INVALID_HANDLE_VALUE ? ::GetLastError() : ERROR_SUCCESS;
            return fileHandle;
        }

        static FileMetadataSnapshot readFileMetadataSnapshot(
            const QString& filePath,
            const DWORD desiredAccess = FILE_READ_ATTRIBUTES)
        {
            FileMetadataSnapshot snapshot;
            HANDLE fileHandle = openFileMetadataHandle(filePath, desiredAccess, snapshot.win32Error);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                return snapshot;
            }

            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &snapshot.basicInfo,
                    sizeof(snapshot.basicInfo)) == FALSE)
            {
                snapshot.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return snapshot;
            }

            snapshot.ok = true;
            snapshot.win32Error = ERROR_SUCCESS;
            BY_HANDLE_FILE_INFORMATION identityInfo{};
            if (::GetFileInformationByHandle(fileHandle, &identityInfo) != FALSE)
            {
                snapshot.identityAvailable = true;
                snapshot.volumeSerialNumber = identityInfo.dwVolumeSerialNumber;
                snapshot.fileIndex =
                    (static_cast<std::uint64_t>(identityInfo.nFileIndexHigh) << 32U) |
                    static_cast<std::uint64_t>(identityInfo.nFileIndexLow);
            }
            closeWin32Handle(fileHandle);
            return snapshot;
        }

        static QDateTime fileMetadataTimeToLocalDateTime(const LARGE_INTEGER timeValue)
        {
            // Windows 时间从 1601-01-01 UTC 起按 100ns 计数；Qt 使用 1970-01-01 毫秒。
            constexpr qint64 WindowsEpochOffset100ns = 116444736000000000LL;
            if (timeValue.QuadPart <= 0)
            {
                return {};
            }
            const qint64 millisecondsSinceUnixEpoch =
                (timeValue.QuadPart - WindowsEpochOffset100ns) / 10000LL;
            return QDateTime::fromMSecsSinceEpoch(millisecondsSinceUnixEpoch, QTimeZone::UTC).toLocalTime();
        }

        static LARGE_INTEGER localDateTimeToFileMetadataTime(const QDateTime& dateTime)
        {
            constexpr qint64 WindowsEpochOffset100ns = 116444736000000000LL;
            LARGE_INTEGER timeValue{};
            if (!dateTime.isValid())
            {
                return timeValue;
            }
            timeValue.QuadPart =
                dateTime.toUTC().toMSecsSinceEpoch() * 10000LL + WindowsEpochOffset100ns;
            return timeValue;
        }

        static std::array<LARGE_INTEGER, 4> fileMetadataTimes(const FILE_BASIC_INFO& basicInfo)
        {
            return {
                basicInfo.CreationTime,
                basicInfo.LastAccessTime,
                basicInfo.LastWriteTime,
                basicInfo.ChangeTime
            };
        }

        static FileMetadataUpdateResult writeFileMetadata(
            const QString& filePath,
            const FileMetadataUpdateRequest& request)
        {
            FileMetadataUpdateResult result;
            HANDLE fileHandle = openFileMetadataHandle(
                filePath,
                FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES,
                result.win32Error);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                return result;
            }

            FILE_BASIC_INFO currentInfo{};
            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &currentInfo,
                    sizeof(currentInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }

            BY_HANDLE_FILE_INFORMATION identityInfo{};
            const bool identityAvailable =
                ::GetFileInformationByHandle(fileHandle, &identityInfo) != FALSE;
            const std::uint64_t currentFileIndex = identityAvailable
                ? ((static_cast<std::uint64_t>(identityInfo.nFileIndexHigh) << 32U) |
                    static_cast<std::uint64_t>(identityInfo.nFileIndexLow))
                : 0U;
            if (request.validateIdentity)
            {
                if (!identityAvailable)
                {
                    result.win32Error = ::GetLastError();
                    closeWin32Handle(fileHandle);
                    return result;
                }
                if (identityInfo.dwVolumeSerialNumber != request.expectedVolumeSerialNumber ||
                    currentFileIndex != request.expectedFileIndex)
                {
                    result.win32Error = ERROR_FILE_INVALID;
                    closeWin32Handle(fileHandle);
                    return result;
                }
            }

            // 在同一句柄上二次读取后基于最新值合并，避免编辑页停留期间外部属性变化被覆盖。
            // FILE_BASIC_INFO 中值为 0 的时间字段与 FileAttributes 都表示“不修改”，因此只填入
            // 用户明确选择的时间；属性无变化时也保持 0，避免重写加密/压缩等结构性状态。
            FILE_BASIC_INFO updatedInfo{};
            if (request.updateTime[0]) updatedInfo.CreationTime = request.timeValue[0];
            if (request.updateTime[1]) updatedInfo.LastAccessTime = request.timeValue[1];
            if (request.updateTime[2]) updatedInfo.LastWriteTime = request.timeValue[2];
            if (request.updateTime[3]) updatedInfo.ChangeTime = request.timeValue[3];
            if (request.updateAttributes)
            {
                updatedInfo.FileAttributes = currentInfo.FileAttributes;
                updatedInfo.FileAttributes &= ~editableFileAttributeMask();
                updatedInfo.FileAttributes &= ~FILE_ATTRIBUTE_NORMAL;
                updatedInfo.FileAttributes |=
                    request.editableAttributes & editableFileAttributeMask();
                if (updatedInfo.FileAttributes == 0U)
                {
                    updatedInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
                }
            }

            if (::SetFileInformationByHandle(
                    fileHandle,
                    FileBasicInfo,
                    &updatedInfo,
                    sizeof(updatedInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }

            if (::GetFileInformationByHandleEx(
                    fileHandle,
                    FileBasicInfo,
                    &result.snapshot.basicInfo,
                    sizeof(result.snapshot.basicInfo)) == FALSE)
            {
                result.win32Error = ::GetLastError();
                closeWin32Handle(fileHandle);
                return result;
            }
            closeWin32Handle(fileHandle);

            result.snapshot.ok = true;
            result.snapshot.win32Error = ERROR_SUCCESS;
            result.snapshot.identityAvailable = identityAvailable;
            result.snapshot.volumeSerialNumber = identityAvailable
                ? identityInfo.dwVolumeSerialNumber
                : 0U;
            result.snapshot.fileIndex = currentFileIndex;
            result.ok = true;
            result.win32Error = ERROR_SUCCESS;
            result.verificationMatched = true;
            const std::array<LARGE_INTEGER, 4> actualTimes =
                fileMetadataTimes(result.snapshot.basicInfo);
            for (std::size_t timeIndex = 0; timeIndex < request.updateTime.size(); ++timeIndex)
            {
                if (request.updateTime[timeIndex] &&
                    actualTimes[timeIndex].QuadPart != request.timeValue[timeIndex].QuadPart)
                {
                    // FAT/exFAT 等文件系统可能按自身粒度舍入时间；写入仍成功，但 UI 必须展示回读值。
                    result.verificationMatched = false;
                }
            }
            if (request.updateAttributes &&
                (result.snapshot.basicInfo.FileAttributes & editableFileAttributeMask()) !=
                    (request.editableAttributes & editableFileAttributeMask()))
            {
                result.verificationMatched = false;
            }
            return result;
        }

        static QString formatHexValue(const quint64 value, const int digitCount)
        {
            // 用途：统一 0x 前缀的十六进制写法。
            // 说明：只把数字部分转大写。对整串调用 toUpper() 会连前缀一起变成 "0X"，
            //       和 WinDbg、微软文档里的写法对不上，复制出去还要手工改。
            // 入参 value：待格式化的值；digitCount：补零到的最少位数，<=0 表示不补零。
            // 返回：例如 0x0000A020。
            QString digitsText = QString::number(value, 16).toUpper();
            if (digitCount > 0)
            {
                digitsText = digitsText.rightJustified(digitCount, QLatin1Char('0'));
            }
            return QStringLiteral("0x%1").arg(digitsText);
        }

        static QString formatHex64(const std::uint64_t value)
        {
            // 用途：统一格式化 R0 诊断地址。
            // 返回：0x 前缀、数字部分大写的十六进制字符串。
            return formatHexValue(static_cast<quint64>(value), 0);
        }

        static QString formatNtStatus(const long status)
        {
            // 用途：NTSTATUS 同时显示十六进制和十进制，便于对照 WinDbg。
            // 返回：例如 0xC0000034 (-1073741772)。
            return QStringLiteral("%1 (%2)")
                .arg(formatHexValue(static_cast<quint64>(static_cast<std::uint32_t>(status)), 8))
                .arg(status);
        }

        static QString formatAuditBool(const bool value)
        {
            // 用途：把 R0 审计布尔值统一转成中文，避免各页混用 true/false。
            // 返回：是/否，供 IO 状态、truncated、unsupported 字段使用。
            return value ? QStringLiteral("是") : QStringLiteral("否");
        }

        static QString friendlyFileIoMessage(const std::string& messageText)
        {
            // 用途：把 ArkDriverClient 的原始 io.message 翻译成文件页可读说明。
            // 输入：messageText 为 wrapper 返回的 UTF-8/ASCII 诊断文本。
            // 返回：中文说明；仅用于 UI 展示，不改变原始 IO 状态字段。
            if (messageText.empty())
            {
                return QStringLiteral("无额外驱动消息");
            }

            const QString rawText = QString::fromStdString(messageText).trimmed();
            if (rawText.isEmpty())
            {
                return QStringLiteral("无额外驱动消息");
            }
            if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该文件审计入口");
            }
            if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
                rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
            {
                return QStringLiteral("当前驱动版本尚未提供该文件审计入口");
            }
            if (rawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
                rawText.contains(QStringLiteral("entrySize"), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动返回数据格式不完整，已保留当前页面其它只读证据");
            }
            if (rawText == QStringLiteral("empty nt path"))
            {
                return QStringLiteral("缺少可传递给驱动的 NT 路径，R0 文件信息查询已跳过");
            }
            if (rawText.startsWith(QStringLiteral("version="), Qt::CaseInsensitive))
            {
                return QStringLiteral("驱动已返回结构化文件审计数据");
            }
            return rawText;
        }

        static QString fixedWideAuditText(const wchar_t* const textBuffer, const std::size_t maxChars)
        {
            // 用途：读取 shared/driver 固定宽字符数组，避免 UI 猜测协议字段。
            // 输入：textBuffer 为协议字段首地址，maxChars 为数组容量。
            // 返回：遇到 NUL 截断后的 QString；空字段返回 <empty>。
            if (textBuffer == nullptr || maxChars == 0U)
            {
                return QStringLiteral("<empty>");
            }

            std::size_t length = 0U;
            while (length < maxChars && textBuffer[length] != L'\0')
            {
                ++length;
            }
            if (length == 0U)
            {
                return QStringLiteral("<empty>");
            }
            return QString::fromWCharArray(textBuffer, static_cast<int>(length));
        }

        template <std::size_t CharCount>
        static QString fixedWideAuditText(const wchar_t (&textBuffer)[CharCount])
        {
            // 用途：固定数组重载，调用方不需要重复写 std::size。
            // 返回：固定 UTF-16 字段的安全显示文本。
            return fixedWideAuditText(textBuffer, CharCount);
        }

        template <typename AuditResult>
        static QString formatAuditResultHeader(
            const QString& titleText,
            const AuditResult& result,
            const std::uint32_t responseFlags,
            const bool explicitTruncated)
        {
            // 用途：生成所有 R0 文件/存储审计 wrapper 的统一摘要头。
            // 输入：titleText 为审计块标题，result 为 ArkDriverClient 返回结构。
            // 返回：包含 IO、total/returned、truncated 和可读说明的多行文本。
            const bool countTruncated = result.returnedCount < result.totalCount;
            const bool truncated = explicitTruncated || countTruncated;
            QString content;
            content += QStringLiteral("[%1]\n").arg(titleText);
            content += QStringLiteral("IO状态: %1\n").arg(result.io.ok ? QStringLiteral("OK") : QStringLiteral("FAIL"));
            content += QStringLiteral("unsupported: %1\n").arg(formatAuditBool(result.unsupported));
            content += QStringLiteral("version: %1\n").arg(result.version);
            content += QStringLiteral("status: %1\n").arg(result.status);
            content += QStringLiteral("totalCount: %1\n").arg(result.totalCount);
            content += QStringLiteral("returnedCount: %1\n").arg(result.returnedCount);
            content += QStringLiteral("truncated: %1\n").arg(formatAuditBool(truncated));
            content += QStringLiteral("entrySize/rowSize: %1\n").arg(result.entrySize);
            content += QStringLiteral("responseFlags: 0x%1\n").arg(responseFlags, 8, 16, QChar('0')).toUpper();
            content += QStringLiteral("lastStatus: %1\n").arg(formatNtStatus(result.lastStatus));
            content += QStringLiteral("win32Error: %1\n").arg(result.io.win32Error);
            content += QStringLiteral("bytesReturned: %1\n").arg(result.io.bytesReturned);
            content += QStringLiteral("说明: %1\n").arg(friendlyFileIoMessage(result.io.message));
            return content;
        }

        static QString formatMinifilterInventoryRows(const ksword::ark::MinifilterInventoryResult& result)
        {
            // 用途：展开 R0 Minifilter inventory 的前若干真实行。
            // 处理：只显示名称、Altitude、Volume、Frame、对象地址和 owner hint。
            // 返回：可追加到 Filter topology 页的只读文本。
            QString content;
            const std::size_t rowLimit = std::min<std::size_t>(result.entries.size(), 16U);
            for (std::size_t index = 0U; index < rowLimit; ++index)
            {
                const KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY& row = result.entries[index];
                content += QStringLiteral("  #%1 Filter=%2 Altitude=%3 Volume=%4 Instance=%5 VolumeBindings=%6 Frame=%7\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(fixedWideAuditText(row.filterName))
                    .arg(fixedWideAuditText(row.altitude))
                    .arg(fixedWideAuditText(row.volumeName))
                    .arg(row.instanceCount)
                    .arg(row.volumeBindingInstanceCount)
                    .arg(row.frameId);
                content += QStringLiteral("     FilterObject=%1 VolumeObject=%2 CallbackOwner=%3 OwnerStatus=%4 FieldFlags=0x%5 SourceFlags=0x%6 Status=%7\n")
                    .arg(formatHex64(row.filterObject))
                    .arg(formatHex64(row.volumeObject))
                    .arg(fixedWideAuditText(row.callbackOwnerModule))
                    .arg(formatNtStatus(row.callbackOwnerStatus))
                    .arg(row.fieldFlags, 8, 16, QChar('0'))
                    .arg(row.sourceFlags, 8, 16, QChar('0'))
                    .arg(row.status)
                    .toUpper();
            }
            if (result.entries.size() > rowLimit)
            {
                content += QStringLiteral("  ... 已省略 %1 行，完整数量见 returnedCount。\n")
                    .arg(static_cast<qulonglong>(result.entries.size() - rowLimit));
            }
            return content;
        }

        static QString formatVolumeStackAuditRows(const ksword::ark::StorageVolumeStackAuditResult& result)
        {
            // 用途：展开 R0 VolumeStack 审计结果的前若干设备栈行。
            // 输入：queryVolumeStackAudit 的返回值。
            // 返回：包含 DeviceObject/DriverObject/风险/置信度的只读文本。
            QString content;
            content += QStringLiteral("fvevolPresent: %1\n").arg(result.fvevolPresent);
            content += QStringLiteral("fvevolPosition: %1\n").arg(result.fvevolPosition);
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const std::size_t rowLimit = std::min<std::size_t>(result.rows.size(), 12U);
            for (std::size_t index = 0U; index < rowLimit; ++index)
            {
                const KSWORD_ARK_VOLUME_STACK_ROW& row = result.rows[index];
                content += QStringLiteral("  #%1 StackIndex=%2 Driver=%3 Volume=%4 Confidence=%5 Risk=0x%6\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(row.stackIndex)
                    .arg(fixedWideAuditText(row.driverName))
                    .arg(fixedWideAuditText(row.volumeDeviceName))
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     DeviceObject=%1 DriverObject=%2 Attached=%3 Lower=%4 Type=0x%5 Characteristics=0x%6 Status=%7 Detail=%8\n")
                    .arg(formatHex64(row.deviceObjectAddress))
                    .arg(formatHex64(row.driverObjectAddress))
                    .arg(formatHex64(row.attachedDeviceAddress))
                    .arg(formatHex64(row.lowerDeviceAddress))
                    .arg(row.deviceType, 8, 16, QChar('0'))
                    .arg(row.deviceCharacteristics, 8, 16, QChar('0'))
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail))
                    .toUpper();
            }
            if (result.rows.size() > rowLimit)
            {
                content += QStringLiteral("  ... 已省略 %1 行，完整数量见 returnedCount。\n")
                    .arg(static_cast<qulonglong>(result.rows.size() - rowLimit));
            }
            return content;
        }

        static QString formatBitlockerFveAuditRows(const ksword::ark::StorageBitlockerFveAuditResult& result)
        {
            // 用途：展开 BitLocker/FVE 安全状态摘要，明确不展示密钥材料。
            // 输入：queryBitlockerFveAudit 的返回值。
            // 返回：保护/转换/锁定状态、protector 类型计数和风险文本。
            QString content;
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const std::size_t rowLimit = std::min<std::size_t>(result.rows.size(), 8U);
            for (std::size_t index = 0U; index < rowLimit; ++index)
            {
                const KSWORD_ARK_BITLOCKER_FVE_ROW& row = result.rows[index];
                content += QStringLiteral("  #%1 Volume=%2 FvePresent=%3 FvePosition=%4 Protection=%5 Conversion=%6 Lock=%7 Confidence=%8 Risk=0x%9\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(fixedWideAuditText(row.volumeDeviceName))
                    .arg(row.fvevolPresent)
                    .arg(row.fvevolStackPosition)
                    .arg(row.protectionStatus)
                    .arg(row.conversionStatus)
                    .arg(row.lockStatus)
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     ProtectorCounts: TPM=%1 TPM+PIN=%2 RecoveryPassword=%3 RecoveryKey=%4 StartupKey=%5 ClearOrSuspended=%6 Status=%7 Detail=%8\n")
                    .arg(row.keyProtectorTypeCountTpm)
                    .arg(row.keyProtectorTypeCountTpmPin)
                    .arg(row.keyProtectorTypeCountRecoveryPassword)
                    .arg(row.keyProtectorTypeCountRecoveryKey)
                    .arg(row.keyProtectorTypeCountStartupKey)
                    .arg(row.keyProtectorTypeCountClearOrSuspended)
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail));
            }
            return content;
        }

        static QString formatMountMgrMappingAuditRows(const ksword::ark::StorageMountMgrMappingAuditResult& result)
        {
            // 用途：展开 MountMgr 盘符/GUID/NT 设备路径映射审计。
            // 输入：queryMountMgrMappingAudit 的返回值。
            // 返回：映射名称、风险、置信度和 detail 文本。
            QString content;
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const std::size_t rowLimit = std::min<std::size_t>(result.rows.size(), 16U);
            for (std::size_t index = 0U; index < rowLimit; ++index)
            {
                const KSWORD_ARK_MOUNTMGR_MAPPING_ROW& row = result.rows[index];
                content += QStringLiteral("  #%1 Drive=%2 Guid=%3 NtPath=%4 Confidence=%5 Risk=0x%6 Status=%7 Detail=%8\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(fixedWideAuditText(row.driveLetter))
                    .arg(fixedWideAuditText(row.volumeGuid))
                    .arg(fixedWideAuditText(row.ntDevicePath))
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail))
                    .toUpper();
            }
            if (result.rows.size() > rowLimit)
            {
                content += QStringLiteral("  ... 已省略 %1 行，完整数量见 returnedCount。\n")
                    .arg(static_cast<qulonglong>(result.rows.size() - rowLimit));
            }
            return content;
        }

        static QString formatFilesystemIntegrityAuditRows(const ksword::ark::StorageFilesystemIntegrityAuditResult& result)
        {
            // 用途：展开文件系统 DriverObject/FastIo/Dispatch 完整性审计行。
            // 输入：queryFilesystemIntegrityAudit 的返回值。
            // 返回：slot、目标地址、owner 模块、风险和置信度文本。
            QString content;
            content += QStringLiteral("fieldFlags: 0x%1\n")
                .arg(result.fieldFlags, 8, 16, QChar('0'))
                .toUpper();
            const auto byteText = [](const std::vector<std::uint8_t>& bytes) {
                QString text;
                for (const std::uint8_t byte : bytes)
                {
                    if (!text.isEmpty())
                    {
                        text += QLatin1Char(' ');
                    }
                    text += QStringLiteral("%1").arg(byte, 2, 16, QLatin1Char('0')).toUpper();
                }
                return text;
            };
            const std::size_t rowLimit = result.rows.size();
            std::map<std::uint64_t, ks::kernel::CleanImageBaselineResult> baselineCache;
            for (std::size_t index = 0U; index < rowLimit; ++index)
            {
                const KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW& row = result.rows[index];
                if (row.targetAddress != 0U &&
                    baselineCache.find(row.targetAddress) == baselineCache.end())
                {
                    baselineCache.emplace(
                        row.targetAddress,
                        ks::kernel::KernelCleanImageBaseline::compareAddress(
                            row.targetAddress,
                            16U));
                }
                const ks::kernel::CleanImageBaselineResult baseline =
                    row.targetAddress == 0U
                    ? ks::kernel::CleanImageBaselineResult{}
                    : baselineCache.at(row.targetAddress);
                content += QStringLiteral("  #%1 FsKind=%2 SlotType=%3 SlotIndex=%4 Driver=%5 Owner=%6 Confidence=%7 Risk=0x%8\n")
                    .arg(static_cast<qulonglong>(index))
                    .arg(row.fileSystemKind)
                    .arg(row.slotType)
                    .arg(row.slotIndex)
                    .arg(fixedWideAuditText(row.driverName))
                    .arg(fixedWideAuditText(row.ownerModuleName))
                    .arg(row.confidence)
                    .arg(row.riskFlags, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     DriverObject=%1 DriverStart=%2 DriverSize=0x%3 SlotAddress=%4 Target=%5 OwnerBase=%6 OwnerSize=0x%7 Status=%8 Detail=%9\n")
                    .arg(formatHex64(row.driverObjectAddress))
                    .arg(formatHex64(row.driverStart))
                    .arg(row.driverSize, 8, 16, QChar('0'))
                    .arg(formatHex64(row.slotAddress))
                    .arg(formatHex64(row.targetAddress))
                    .arg(formatHex64(row.ownerModuleBase))
                    .arg(row.ownerModuleSize, 8, 16, QChar('0'))
                    .arg(formatNtStatus(row.lastStatus))
                    .arg(fixedWideAuditText(row.detail))
                    .toUpper();
                content += QStringLiteral("     BaselineScope=TARGET_PROLOGUE_ONLY CleanImageBaseline=%1 IdentityMatched=%2 CodeIntegrityTrusted=%3 SigningLevel=%4 Relocated=%5 Differs=%6 Image=%7 RVA=0x%8\n")
                    .arg(baseline.available ? QStringLiteral("AVAILABLE") : QStringLiteral("UNAVAILABLE"))
                    .arg(baseline.identityMatched ? QStringLiteral("YES") : QStringLiteral("NO"))
                    .arg(baseline.codeIntegrityTrusted ? QStringLiteral("YES") : QStringLiteral("NO"))
                    .arg(baseline.signingLevel)
                    .arg(baseline.relocationApplied ? QStringLiteral("YES") : QStringLiteral("NO"))
                    .arg(baseline.available
                        ? (baseline.differs ? QStringLiteral("YES") : QStringLiteral("NO"))
                        : QStringLiteral("UNKNOWN"))
                    .arg(baseline.imagePath.isEmpty() ? QStringLiteral("<unavailable>") : baseline.imagePath)
                    .arg(baseline.relativeVirtualAddress, 8, 16, QChar('0'))
                    .toUpper();
                content += QStringLiteral("     SHA256=%1\n     SigningThumbprint=%2\n     ObservedBytes=%3\n     CleanBytes=%4\n     BaselineDetail=%5\n")
                    .arg(baseline.imageSha256.isEmpty() ? QStringLiteral("<unavailable>") : baseline.imageSha256)
                    .arg(baseline.signingThumbprint.isEmpty() ? QStringLiteral("<unavailable>") : baseline.signingThumbprint)
                    .arg(byteText(baseline.observedBytes))
                    .arg(byteText(baseline.cleanBytes))
                    .arg(baseline.statusText);
            }
            return content;
        }

        static QString fileTimeToText(const std::int64_t fileTimeValue)
        {
            // 用途：把 Windows FILETIME 语义的 100ns 时间戳转为本地时间文本。
            // 返回：可读时间；0 表示不可用。
            if (fileTimeValue <= 0)
            {
                return QStringLiteral("<Unavailable>");
            }

            constexpr std::int64_t windowsToUnix100Ns = 116444736000000000LL;
            const std::int64_t unixMilliseconds = (fileTimeValue - windowsToUnix100Ns) / 10000LL;
            if (unixMilliseconds <= 0)
            {
                return QStringLiteral("<Invalid:%1>").arg(fileTimeValue);
            }
            // Qt 6.9 已废弃 Qt::TimeSpec 重载；这里显式使用 UTC 时区，
            // 再转换为本地时间，保持 FILETIME 展示语义不变。
            return QDateTime::fromMSecsSinceEpoch(unixMilliseconds, QTimeZone::UTC)
                .toLocalTime()
                .toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
        }

        static QString fileAttributesToText(const std::uint32_t attributes)
        {
            // 用途：拆解 FILE_ATTRIBUTE_*，让 R0 和 R3 属性差异可读。
            // 返回：属性名列表；无显式位时返回 NORMAL/0。
            QStringList parts;
            if ((attributes & FILE_ATTRIBUTE_READONLY) != 0U) parts << QStringLiteral("READONLY");
            if ((attributes & FILE_ATTRIBUTE_HIDDEN) != 0U) parts << QStringLiteral("HIDDEN");
            if ((attributes & FILE_ATTRIBUTE_SYSTEM) != 0U) parts << QStringLiteral("SYSTEM");
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0U) parts << QStringLiteral("DIRECTORY");
            if ((attributes & FILE_ATTRIBUTE_ARCHIVE) != 0U) parts << QStringLiteral("ARCHIVE");
            if ((attributes & FILE_ATTRIBUTE_DEVICE) != 0U) parts << QStringLiteral("DEVICE");
            if ((attributes & FILE_ATTRIBUTE_NORMAL) != 0U) parts << QStringLiteral("NORMAL");
            if ((attributes & FILE_ATTRIBUTE_TEMPORARY) != 0U) parts << QStringLiteral("TEMPORARY");
            if ((attributes & FILE_ATTRIBUTE_SPARSE_FILE) != 0U) parts << QStringLiteral("SPARSE_FILE");
            if ((attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U) parts << QStringLiteral("REPARSE_POINT");
            if ((attributes & FILE_ATTRIBUTE_COMPRESSED) != 0U) parts << QStringLiteral("COMPRESSED");
            if ((attributes & FILE_ATTRIBUTE_OFFLINE) != 0U) parts << QStringLiteral("OFFLINE");
            if ((attributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED) != 0U) parts << QStringLiteral("NOT_CONTENT_INDEXED");
            if ((attributes & FILE_ATTRIBUTE_ENCRYPTED) != 0U) parts << QStringLiteral("ENCRYPTED");
            if ((attributes & FILE_ATTRIBUTE_INTEGRITY_STREAM) != 0U) parts << QStringLiteral("INTEGRITY_STREAM");
            if ((attributes & FILE_ATTRIBUTE_NO_SCRUB_DATA) != 0U) parts << QStringLiteral("NO_SCRUB_DATA");
            if (parts.isEmpty())
            {
                parts << QStringLiteral("0");
            }
            return QStringLiteral("0x%1 (%2)")
                .arg(attributes, 8, 16, QChar('0'))
                .arg(parts.join(QStringLiteral("|")))
                .toUpper();
        }

        static QString fileInfoStatusText(const std::uint32_t status)
        {
            // 用途：把共享协议状态码翻译为 UI 文本。
            // 返回：状态名称。
            switch (status)
            {
            case KSWORD_ARK_FILE_INFO_STATUS_OK:
                return QStringLiteral("OK");
            case KSWORD_ARK_FILE_INFO_STATUS_PARTIAL:
                return QStringLiteral("Partial");
            case KSWORD_ARK_FILE_INFO_STATUS_OPEN_FAILED:
                return QStringLiteral("Open Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_BASIC_FAILED:
                return QStringLiteral("Basic Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_STANDARD_FAILED:
                return QStringLiteral("Standard Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_OBJECT_FAILED:
                return QStringLiteral("Object Failed");
            case KSWORD_ARK_FILE_INFO_STATUS_NAME_FAILED:
                return QStringLiteral("Name Failed");
            default:
                return QStringLiteral("Unavailable");
            }
        }

        static ksword::ark::FileInfoQueryResult queryR0FileInfo(const QFileInfo& info, const QString& ntPathText)
        {
            // 用途：通过 ArkDriverClient 调用 R0 文件基础信息查询。
            // 返回：驱动不可用时 ok=false，常规页自动回退 R3 展示。
            ksword::ark::FileInfoQueryResult result{};
            if (ntPathText.trimmed().isEmpty())
            {
                result.io.ok = false;
                result.io.win32Error = ERROR_INVALID_PARAMETER;
                result.io.message = "empty nt path";
                return result;
            }

            unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL;
            if (info.isDir())
            {
                flags |= KSWORD_ARK_QUERY_FILE_INFO_FLAG_DIRECTORY;
            }

            const ksword::ark::DriverClient driverClient;
            return driverClient.queryFileInfo(ntPathText.toStdWString(), flags);
        }

        QString formatR0FileInfoText(const ksword::ark::FileInfoQueryResult& result) const
        {
            // 用途：生成 R0 文件信息页文本。
            // 返回：包含状态、大小、时间戳、对象诊断地址和失败原因的多行文本。
            QString content;
            if (!result.io.ok)
            {
                content += QStringLiteral("状态: Unavailable\n");
                content += QStringLiteral("原因: %1\n").arg(friendlyFileIoMessage(result.io.message));
                content += QStringLiteral("Win32错误: %1\n").arg(result.io.win32Error);
                return content;
            }

            content += QStringLiteral("协议版本: %1\n").arg(result.version);
            content += QStringLiteral("查询状态: %1 (%2)\n").arg(fileInfoStatusText(result.queryStatus)).arg(result.queryStatus);
            content += QStringLiteral("字段标志: 0x%1\n").arg(result.fieldFlags, 8, 16, QChar('0')).toUpper();
            content += QStringLiteral("OpenStatus: %1\n").arg(formatNtStatus(result.openStatus));
            content += QStringLiteral("BasicStatus: %1\n").arg(formatNtStatus(result.basicStatus));
            content += QStringLiteral("StandardStatus: %1\n").arg(formatNtStatus(result.standardStatus));
            content += QStringLiteral("ObjectStatus: %1\n").arg(formatNtStatus(result.objectStatus));
            content += QStringLiteral("NameStatus: %1\n").arg(formatNtStatus(result.nameStatus));
            content += QStringLiteral("大小(EndOfFile): %1 字节\n").arg(static_cast<qlonglong>(result.endOfFile));
            content += QStringLiteral("分配大小: %1 字节\n").arg(static_cast<qlonglong>(result.allocationSize));
            content += QStringLiteral("属性: %1\n").arg(fileAttributesToText(result.fileAttributes));
            content += QStringLiteral("创建时间: %1\n").arg(fileTimeToText(result.creationTime));
            content += QStringLiteral("最后访问: %1\n").arg(fileTimeToText(result.lastAccessTime));
            content += QStringLiteral("最后写入: %1\n").arg(fileTimeToText(result.lastWriteTime));
            content += QStringLiteral("ChangeTime: %1\n").arg(fileTimeToText(result.changeTime));
            content += QStringLiteral("FileObject: %1\n").arg(formatHex64(result.fileObjectAddress));
            content += QStringLiteral("SectionObjectPointers: %1\n").arg(formatHex64(result.sectionObjectPointersAddress));
            content += QStringLiteral("DataSectionObject: %1\n").arg(formatHex64(result.dataSectionObjectAddress));
            content += QStringLiteral("ImageSectionObject: %1\n").arg(formatHex64(result.imageSectionObjectAddress));
            content += QStringLiteral("R0说明: %1\n").arg(friendlyFileIoMessage(result.io.message));
            return content;
        }

        // formatFileSizeText 作用：
        // - 文件大小同时给出易读单位和精确字节数，避免只有一串数字要用户自己数位数；
        // - 不足 1KB 时没有换算价值，只给字节数。
        // 入参 sizeBytes：字节数。
        // 返回：例如“1.21 MB（1268736 字节）”。
        static QString formatFileSizeText(const qulonglong sizeBytes)
        {
            static const std::array<const char*, 5> unitNames{ "B", "KB", "MB", "GB", "TB" };
            double scaledValue = static_cast<double>(sizeBytes);
            std::size_t unitIndex = 0;
            while (scaledValue >= 1024.0 && (unitIndex + 1) < unitNames.size())
            {
                scaledValue /= 1024.0;
                ++unitIndex;
            }
            if (unitIndex == 0)
            {
                return ks::i18n::displayText(QStringLiteral("%1 字节")).arg(sizeBytes);
            }
            return ks::i18n::displayText(QStringLiteral("%1 %2（%3 字节）"))
                .arg(QString::number(scaledValue, 'f', 2))
                .arg(QString::fromLatin1(unitNames[unitIndex]))
                .arg(sizeBytes);
        }

        // fileAttributeFlagRows 作用：
        // - 输入 attributes：FILE_ATTRIBUTE_* 位集合；
        // - 处理：只展开已置位的属性，逐位给出 Win32 常量名和中文含义；
        //   原先这些位被压成一个 A|B|C 串，除了记得住常量名的人谁都读不出来；
        // - 返回：常量名/含义对的列表；一位都没置位时返回空列表，由调用方补一行说明。
        static QList<QPair<QString, QString>> fileAttributeFlagRows(const std::uint32_t attributes)
        {
            QList<QPair<QString, QString>> flagRows;
            const auto appendFlag =
                [&flagRows, attributes](
                    const std::uint32_t mask,
                    const QString& nameText,
                    const QString& descriptionText)
                {
                    if ((attributes & mask) != 0U)
                    {
                        flagRows.append(QPair<QString, QString>(nameText, descriptionText));
                    }
                };

            appendFlag(FILE_ATTRIBUTE_READONLY, QStringLiteral("READONLY"), QStringLiteral("只读，写入前要先去掉该属性"));
            appendFlag(FILE_ATTRIBUTE_HIDDEN, QStringLiteral("HIDDEN"), QStringLiteral("隐藏，资源管理器默认不显示"));
            appendFlag(FILE_ATTRIBUTE_SYSTEM, QStringLiteral("SYSTEM"), QStringLiteral("系统文件，属于操作系统的一部分"));
            appendFlag(FILE_ATTRIBUTE_DIRECTORY, QStringLiteral("DIRECTORY"), QStringLiteral("目录"));
            appendFlag(FILE_ATTRIBUTE_ARCHIVE, QStringLiteral("ARCHIVE"), QStringLiteral("存档位，备份程序据此判断是否需要重新备份"));
            appendFlag(FILE_ATTRIBUTE_DEVICE, QStringLiteral("DEVICE"), QStringLiteral("设备，保留给系统使用"));
            appendFlag(FILE_ATTRIBUTE_NORMAL, QStringLiteral("NORMAL"), QStringLiteral("没有其它属性"));
            appendFlag(FILE_ATTRIBUTE_TEMPORARY, QStringLiteral("TEMPORARY"), QStringLiteral("临时文件，系统会尽量把内容留在内存里"));
            appendFlag(FILE_ATTRIBUTE_SPARSE_FILE, QStringLiteral("SPARSE_FILE"), QStringLiteral("稀疏文件，全零区段不实际占用磁盘"));
            appendFlag(FILE_ATTRIBUTE_REPARSE_POINT, QStringLiteral("REPARSE_POINT"), QStringLiteral("重解析点，符号链接和装载点由它实现"));
            appendFlag(FILE_ATTRIBUTE_COMPRESSED, QStringLiteral("COMPRESSED"), QStringLiteral("NTFS 压缩"));
            appendFlag(FILE_ATTRIBUTE_OFFLINE, QStringLiteral("OFFLINE"), QStringLiteral("内容已转到离线存储，访问会明显变慢"));
            appendFlag(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, QStringLiteral("NOT_CONTENT_INDEXED"), QStringLiteral("不建内容索引，Windows 搜索不检索正文"));
            appendFlag(FILE_ATTRIBUTE_ENCRYPTED, QStringLiteral("ENCRYPTED"), QStringLiteral("EFS 加密"));
            appendFlag(FILE_ATTRIBUTE_INTEGRITY_STREAM, QStringLiteral("INTEGRITY_STREAM"), QStringLiteral("ReFS 完整性流，写入时带校验和"));
            appendFlag(FILE_ATTRIBUTE_NO_SCRUB_DATA, QStringLiteral("NO_SCRUB_DATA"), QStringLiteral("排除在 ReFS 数据完整性扫描之外"));
            return flagRows;
        }

        void refreshGeneralTab()
        {
            // 用途：按当前语言和已加载的 R0 数据重建常规页属性树。
            // 处理：整棵清空后重建，语言切换与 R0 异步返回走同一条路径。
            // 返回：无。
            if (m_generalPropertyTree == nullptr)
            {
                return;
            }

            const auto translated = [](const QString& sourceText)
                {
                    return ks::i18n::displayText(sourceText);
                };
            auto& languageManager = ks::i18n::LanguageManager::instance();
            const QFileInfo info(m_filePath);
            const QString nativePath = QDir::toNativeSeparators(info.absoluteFilePath());
            const QString ntPathText = m_generalNtPathText.isEmpty()
                ? translated(QStringLiteral("<转换失败>"))
                : m_generalNtPathText;
            const QString yesText = languageManager.contextText(
                QStringLiteral("file.detail.value.yes"), QStringLiteral("是"));
            const QString noText = languageManager.contextText(
                QStringLiteral("file.detail.value.no"), QStringLiteral("否"));
            const QString timeFormat = QStringLiteral("yyyy-MM-dd HH:mm:ss");

            m_generalPropertyTree->clear();
            m_generalPropertyTree->setHeaderLabels(QStringList{
                translated(QStringLiteral("属性")),
                translated(QStringLiteral("值"))
                });

            QTreeWidgetItem* pathGroup = appendPropertyGroup(
                m_generalPropertyTree, translated(QStringLiteral("路径")));
            appendPropertyRow(pathGroup, translated(QStringLiteral("Win32 路径")), nativePath);
            appendPropertyRow(pathGroup, translated(QStringLiteral("NT 路径")), ntPathText);
            appendPropertyRow(
                pathGroup,
                translated(QStringLiteral("查询来源")),
                !m_generalR0Loaded
                    ? translated(QStringLiteral("R3 QFileInfo（R0 信息正在后台加载）"))
                    : (m_generalR0Info.io.ok
                        ? translated(QStringLiteral("R3 QFileInfo + R0 KswordARK"))
                        : translated(QStringLiteral("R3 QFileInfo（R0 不可用）"))));

            QTreeWidgetItem* basicGroup = appendPropertyGroup(
                m_generalPropertyTree, translated(QStringLiteral("基本信息")));
            appendPropertyRow(basicGroup, translated(QStringLiteral("文件名")), info.fileName());
            appendPropertyRow(basicGroup, translated(QStringLiteral("扩展名")), info.suffix());
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("大小")),
                formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, info.size()))));
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("创建时间")),
                info.birthTime().toString(timeFormat));
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("修改时间")),
                info.lastModified().toString(timeFormat));
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("访问时间")),
                info.lastRead().toString(timeFormat));
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("可执行")),
                info.isExecutable() ? yesText : noText);
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("隐藏")),
                info.isHidden() ? yesText : noText);
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("可写")),
                info.isWritable() ? yesText : noText);
            appendPropertyRow(
                basicGroup,
                translated(QStringLiteral("重解析点")),
                isPathReparsePoint(info.absoluteFilePath())
                    ? translated(QStringLiteral("是（首屏只判断属性位，不追踪链接目标）"))
                    : noText);

            QTreeWidgetItem* kernelGroup = appendPropertyGroup(
                m_generalPropertyTree, translated(QStringLiteral("内核视图（R0）")));
            if (!m_generalR0Loaded)
            {
                appendPropertyRow(
                    kernelGroup,
                    translated(QStringLiteral("状态")),
                    translated(QStringLiteral("正在后台查询，属性窗口不会等待驱动返回")));
                syncGeneralTextView();
                return;
            }
            if (!m_generalR0Info.io.ok)
            {
                appendPropertyRow(
                    kernelGroup,
                    translated(QStringLiteral("状态")),
                    translated(QStringLiteral("不可用")));
                appendPropertyRow(
                    kernelGroup,
                    translated(QStringLiteral("原因")),
                    translated(friendlyFileIoMessage(m_generalR0Info.io.message)));
                appendPropertyRow(
                    kernelGroup,
                    translated(QStringLiteral("Win32 错误码")),
                    QString::number(m_generalR0Info.io.win32Error));
                syncGeneralTextView();
                return;
            }

            if (!m_generalR0Info.objectName.empty())
            {
                appendPropertyRow(
                    kernelGroup,
                    translated(QStringLiteral("R0 对象名")),
                    QString::fromStdWString(m_generalR0Info.objectName));
            }
            appendPropertyRow(
                kernelGroup,
                translated(QStringLiteral("大小（EndOfFile）")),
                formatFileSizeText(static_cast<qulonglong>(m_generalR0Info.endOfFile)));
            appendPropertyRow(
                kernelGroup,
                translated(QStringLiteral("磁盘占用（分配大小）")),
                formatFileSizeText(static_cast<qulonglong>(m_generalR0Info.allocationSize)));
            appendPropertyRow(
                kernelGroup,
                translated(QStringLiteral("创建时间")),
                fileTimeToText(m_generalR0Info.creationTime));
            appendPropertyRow(
                kernelGroup,
                translated(QStringLiteral("最后访问")),
                fileTimeToText(m_generalR0Info.lastAccessTime));
            appendPropertyRow(
                kernelGroup,
                translated(QStringLiteral("最后写入")),
                fileTimeToText(m_generalR0Info.lastWriteTime));
            appendPropertyRow(
                kernelGroup,
                translated(QStringLiteral("元数据变更（ChangeTime）")),
                fileTimeToText(m_generalR0Info.changeTime));
            appendPropertyRow(
                kernelGroup,
                translated(QStringLiteral("R0 说明")),
                translated(friendlyFileIoMessage(m_generalR0Info.io.message)));

            QTreeWidgetItem* attributeGroup = appendPropertyGroup(
                m_generalPropertyTree, translated(QStringLiteral("文件属性位")));
            attributeGroup->setText(1, formatHexValue(m_generalR0Info.fileAttributes, 8));
            const QList<QPair<QString, QString>> attributeRows =
                fileAttributeFlagRows(m_generalR0Info.fileAttributes);
            if (attributeRows.isEmpty())
            {
                appendPropertyRow(
                    attributeGroup,
                    translated(QStringLiteral("无置位属性")),
                    QString());
            }
            for (const QPair<QString, QString>& attributeRow : attributeRows)
            {
                appendPropertyRow(attributeGroup, attributeRow.first, translated(attributeRow.second));
            }

            // 驱动诊断地址对普通用户没有意义，默认折叠，需要时再展开。
            QTreeWidgetItem* diagnosticGroup = appendPropertyGroup(
                m_generalPropertyTree, translated(QStringLiteral("驱动诊断")));
            diagnosticGroup->setExpanded(false);
            appendPropertyRow(
                diagnosticGroup,
                translated(QStringLiteral("协议版本")),
                QString::number(m_generalR0Info.version));
            appendPropertyRow(
                diagnosticGroup,
                translated(QStringLiteral("查询状态")),
                QStringLiteral("%1 (%2)")
                    .arg(fileInfoStatusText(m_generalR0Info.queryStatus))
                    .arg(m_generalR0Info.queryStatus));
            appendPropertyRow(
                diagnosticGroup,
                translated(QStringLiteral("字段标志")),
                formatHexValue(m_generalR0Info.fieldFlags, 8));
            appendPropertyRow(diagnosticGroup, QStringLiteral("OpenStatus"), formatNtStatus(m_generalR0Info.openStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("BasicStatus"), formatNtStatus(m_generalR0Info.basicStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("StandardStatus"), formatNtStatus(m_generalR0Info.standardStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("ObjectStatus"), formatNtStatus(m_generalR0Info.objectStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("NameStatus"), formatNtStatus(m_generalR0Info.nameStatus));
            appendPropertyRow(diagnosticGroup, QStringLiteral("FileObject"), formatHex64(m_generalR0Info.fileObjectAddress));
            appendPropertyRow(diagnosticGroup, QStringLiteral("SectionObjectPointers"), formatHex64(m_generalR0Info.sectionObjectPointersAddress));
            appendPropertyRow(diagnosticGroup, QStringLiteral("DataSectionObject"), formatHex64(m_generalR0Info.dataSectionObjectAddress));
            appendPropertyRow(diagnosticGroup, QStringLiteral("ImageSectionObject"), formatHex64(m_generalR0Info.imageSectionObjectAddress));

            syncGeneralTextView();
        }

        // syncGeneralTextView 作用：
        // - 把当前属性树导出成缩进文本，回填到常规页的文本视图；
        // - 文本视图不再单独拼一份内容：两种视图共用同一份已翻译数据，
        //   语言切换或 R0 结果到达后不会出现“树更新了、文本还是旧的”。
        // 返回：无。
        void syncGeneralTextView()
        {
            if (m_generalTextEditor == nullptr)
            {
                return;
            }

            // 树内容已经过翻译，这里必须用 setRawText，避免再翻一次。
            m_generalTextEditor->setRawText(propertyTreeToPlainText(m_generalPropertyTree));
        }

        void startHashCalculation(
            CodeEditorWidget* textEditorWidget,
            QProgressBar* progressBar,
            QPushButton* startButton,
            QPushButton* cancelButton)
        {
            // 用途：启动 SHA256 后台流式计算。
            // 处理：每块读取后检查取消标记并异步更新进度。
            // 返回：无；结果通过 QueuedConnection 回填 UI。
            if (textEditorWidget == nullptr || progressBar == nullptr ||
                startButton == nullptr || cancelButton == nullptr)
            {
                return;
            }

            if (m_hashCancelRequested == nullptr)
            {
                m_hashCancelRequested = std::make_shared<std::atomic_bool>(false);
            }
            m_hashCancelRequested->store(false);

            startButton->setEnabled(false);
            cancelButton->setEnabled(true);
            cancelButton->setText(QStringLiteral("取消"));
            progressBar->setValue(0);
            textEditorWidget->setLocalizedText(QStringLiteral("正在计算 SHA256，请等待...\n目标: %1")
                .arg(QDir::toNativeSeparators(m_filePath)));

            const QString filePathSnapshot = m_filePath;
            const auto cancelFlag = m_hashCancelRequested;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            QPointer<QProgressBar> progressGuard(progressBar);
            QPointer<QPushButton> startGuard(startButton);
            QPointer<QPushButton> cancelGuard(cancelButton);

            auto* task = QRunnable::create([guardThis, editorGuard, progressGuard, startGuard, cancelGuard, filePathSnapshot, cancelFlag]()
                {
                    HashCalculationResult result{};
                    const auto beginTime = std::chrono::steady_clock::now();
                    QFile file(filePathSnapshot);
                    result.totalBytes = QFileInfo(filePathSnapshot).size();

                    if (!file.open(QIODevice::ReadOnly))
                    {
                        result.fileError = file.error();
                    }
                    else
                    {
                        result.openOk = true;
                        QCryptographicHash sha256(QCryptographicHash::Sha256);
                        constexpr qint64 chunkBytes = 1024 * 1024;
                        auto lastProgressTime = std::chrono::steady_clock::now();

                        while (!file.atEnd())
                        {
                            if (cancelFlag != nullptr && cancelFlag->load())
                            {
                                result.cancelled = true;
                                break;
                            }

                            const QByteArray chunk = file.read(chunkBytes);
                            if (chunk.isEmpty())
                            {
                                if (file.error() != QFileDevice::NoError)
                                {
                                    result.fileError = file.error();
                                }
                                break;
                            }

                            sha256.addData(chunk);
                            result.readBytes += chunk.size();

                            const auto nowTime = std::chrono::steady_clock::now();
                            const bool shouldReport =
                                std::chrono::duration_cast<std::chrono::milliseconds>(nowTime - lastProgressTime).count() >= 100;
                            if (shouldReport && guardThis != nullptr && progressGuard != nullptr)
                            {
                                lastProgressTime = nowTime;
                                const int progressValue = result.totalBytes > 0
                                    ? static_cast<int>((result.readBytes * 1000LL) / result.totalBytes)
                                    : 1000;
                                FileDetailDialog* targetDialog = guardThis.data();
                                if (targetDialog == nullptr)
                                {
                                    continue;
                                }
                                QMetaObject::invokeMethod(
                                    targetDialog,
                                    [progressGuard, progressValue]()
                                    {
                                        if (progressGuard != nullptr)
                                        {
                                            progressGuard->setValue(std::min(progressValue, 1000));
                                        }
                                    },
                                    Qt::QueuedConnection);
                            }
                        }

                        if (!result.cancelled && result.fileError == QFileDevice::NoError)
                        {
                            result.sha256Text = QString::fromLatin1(sha256.result().toHex());
                        }
                        file.close();
                    }

                    result.elapsedMs = static_cast<qint64>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - beginTime).count());

                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, editorGuard, progressGuard, startGuard, cancelGuard, result]()
                        {
                            if (guardThis == nullptr || editorGuard == nullptr ||
                                progressGuard == nullptr || startGuard == nullptr ||
                                cancelGuard == nullptr)
                            {
                                return;
                            }

                            startGuard->setEnabled(true);
                            cancelGuard->setEnabled(false);
                            cancelGuard->setText(QStringLiteral("取消"));
                            progressGuard->setValue(result.totalBytes > 0
                                ? static_cast<int>((result.readBytes * 1000LL) / result.totalBytes)
                                : 1000);

                            const double elapsedSeconds = std::max(0.001, static_cast<double>(result.elapsedMs) / 1000.0);
                            const double speedMiB = (static_cast<double>(result.readBytes) / (1024.0 * 1024.0)) / elapsedSeconds;

                            QString content;
                            content += QStringLiteral("算法: SHA256\n");
                            content += QStringLiteral("来源: 用户态流式读取(QCryptographicHash)\n");
                            content += QStringLiteral("文件: %1\n").arg(QDir::toNativeSeparators(guardThis->m_filePath));
                            content += QStringLiteral("总大小: %1 字节\n").arg(result.totalBytes);
                            content += QStringLiteral("已读取: %1 字节\n").arg(result.readBytes);
                            content += QStringLiteral("耗时: %1 ms\n").arg(result.elapsedMs);
                            content += QStringLiteral("速度: %1 MiB/s\n").arg(QString::number(speedMiB, 'f', 2));
                            content += QStringLiteral("是否取消: %1\n").arg(result.cancelled ? QStringLiteral("是") : QStringLiteral("否"));
                            if (result.fileError != QFileDevice::NoError)
                            {
                                content += QStringLiteral("QFile错误码: %1\n")
                                    .arg(static_cast<int>(result.fileError));
                            }
                            if (!result.sha256Text.isEmpty())
                            {
                                content += QStringLiteral("SHA256: %1\n").arg(result.sha256Text);
                            }
                            editorGuard->setLocalizedText(content);
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void requestHashCancel(QPushButton* cancelButton)
        {
            // 用途：设置哈希取消标记。
            // 返回：无；后台线程在下一次块边界观察该标记。
            if (m_hashCancelRequested != nullptr)
            {
                m_hashCancelRequested->store(true);
            }
            if (cancelButton != nullptr)
            {
                cancelButton->setEnabled(false);
                cancelButton->setText(QStringLiteral("正在取消..."));
            }
        }

        struct UsageSelection
        {
            std::uint32_t processId = 0;
            std::uint64_t processCreationTime = 0;
            std::uint64_t handleValue = 0;
            QString processName;
            QString matchedTargetPath;
            bool matchedByDirectoryRule = false;
        };

        static constexpr int usageProcessIdRole = Qt::UserRole;
        static constexpr int usageProcessCreationTimeRole = Qt::UserRole + 1;
        static constexpr int usageHandleValueRole = Qt::UserRole + 2;
        static constexpr int usageMatchedTargetPathRole = Qt::UserRole + 3;
        static constexpr int usageDirectoryMatchRole = Qt::UserRole + 4;

        static bool readUsageSelection(QTreeWidget* table, UsageSelection& selectionOut)
        {
            // 用途：从当前行取回扫描时的 PID/创建时间/句柄身份。
            // 这些隐藏字段必须与可见行一起保存，操作前才能拒绝 PID 复用或陈旧句柄。
            if (table == nullptr || table->currentItem() == nullptr)
            {
                return false;
            }

            QTreeWidgetItem* const item = table->currentItem();
            selectionOut.processId = item->data(0, usageProcessIdRole).toUInt();
            selectionOut.processCreationTime =
                item->data(0, usageProcessCreationTimeRole).toULongLong();
            selectionOut.handleValue = item->data(0, usageHandleValueRole).toULongLong();
            selectionOut.processName = item->text(1);
            selectionOut.matchedTargetPath = item->data(0, usageMatchedTargetPathRole).toString();
            selectionOut.matchedByDirectoryRule = item->data(0, usageDirectoryMatchRole).toBool();
            return selectionOut.processId != 0U;
        }

        void closeSelectedUsageHandle(
            QTreeWidget* table,
            QLabel* statusLabel,
            QPushButton* refreshButton)
        {
            UsageSelection selection;
            if (!readUsageSelection(table, selection))
            {
                QMessageBox::information(this, QStringLiteral("关闭句柄"), QStringLiteral("请先选择一条句柄记录。"));
                return;
            }
            if (selection.processId <= 4U ||
                selection.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
                selection.processCreationTime == 0U || selection.handleValue == 0U ||
                isCriticalProcessName(selection.processName))
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("关闭句柄"),
                    QStringLiteral("当前记录没有可关闭的远程句柄，或目标进程受保护。"));
                return;
            }

            const QString processText = selection.processName.trimmed().isEmpty()
                ? QStringLiteral("Unknown")
                : selection.processName;
            if (!ks::ui::confirmDestructiveAction(
                    this,
                    QStringLiteral("file-detail-usage-close-handle-r3"),
                    QStringLiteral("关闭句柄（R3）"),
                    QStringLiteral("%1（PID %2）的句柄 %3")
                        .arg(processText)
                        .arg(selection.processId)
                        .arg(formatHex64(selection.handleValue)),
                    QStringLiteral("关闭正在使用的文件句柄可能导致目标进程读写失败或数据丢失。")))
            {
                return;
            }

            std::string detailText;
            const bool closeOk = ks::file::CloseRemoteHandle(
                selection.processId,
                selection.handleValue,
                selection.processCreationTime,
                selection.matchedTargetPath.toStdWString(),
                selection.matchedByDirectoryRule,
                detailText);
            if (!closeOk)
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("关闭句柄（R3）"),
                    QStringLiteral("关闭句柄失败：%1").arg(QString::fromStdString(detailText)));
                return;
            }

            statusLabel->setText(QStringLiteral("● 句柄已关闭，正在重新扫描占用状态..."));
            refreshUsageTable(table, statusLabel, refreshButton);
        }

        void terminateSelectedUsageProcess(
            QTreeWidget* table,
            QLabel* statusLabel,
            QPushButton* refreshButton,
            const bool useKernelDriver)
        {
            UsageSelection selection;
            if (!readUsageSelection(table, selection))
            {
                QMessageBox::information(this, QStringLiteral("结束进程"), QStringLiteral("请先选择一条句柄记录。"));
                return;
            }
            if (selection.processId <= 4U ||
                selection.processId == static_cast<std::uint32_t>(::GetCurrentProcessId()) ||
                selection.processCreationTime == 0U ||
                isCriticalProcessName(selection.processName))
            {
                QMessageBox::warning(
                    this,
                    QStringLiteral("结束进程"),
                    QStringLiteral("当前记录没有可结束的进程，或目标 PID 受保护。"));
                return;
            }

            const QString actionTitle = useKernelDriver
                ? QStringLiteral("结束进程（R0）")
                : QStringLiteral("结束进程（R3）");
            const QString processText = selection.processName.trimmed().isEmpty()
                ? QStringLiteral("Unknown")
                : selection.processName;
            const QString riskText = useKernelDriver
                ? QStringLiteral("驱动级结束操作不可逆，可能造成数据丢失、系统不稳定或蓝屏。")
                : QStringLiteral("结束进程会丢失该进程未保存的数据。");
            if (!ks::ui::confirmDestructiveAction(
                    this,
                    useKernelDriver
                        ? QStringLiteral("file-detail-usage-terminate-r0")
                        : QStringLiteral("file-detail-usage-terminate-r3"),
                    actionTitle,
                    QStringLiteral("PID %1（%2）").arg(selection.processId).arg(processText),
                    riskText))
            {
                return;
            }

            std::string detailText;
            bool terminateOk = false;
            if (useKernelDriver)
            {
                // 先持有已校验创建时间的进程句柄，防止驱动按 PID 查找时命中复用后的新进程。
                HANDLE verifiedProcessHandle = nullptr;
                if (ks::file::OpenProcessForVerifiedAction(
                        selection.processId,
                        selection.processCreationTime,
                        SYNCHRONIZE,
                        verifiedProcessHandle,
                        detailText))
                {
                    ksword::ark::DriverHandle driverHandle = openKswordArkDriverHandle(&detailText);
                    if (driverHandle.isValid())
                    {
                        terminateOk = terminateProcessByR0Driver(driverHandle, selection.processId, &detailText);
                    }
                    ::CloseHandle(verifiedProcessHandle);
                }
            }
            else
            {
                terminateOk = terminateProcessByR3(
                    selection.processId,
                    selection.processCreationTime,
                    &detailText);
            }

            if (!terminateOk)
            {
                QMessageBox::warning(this, actionTitle, QString::fromStdString(detailText));
                return;
            }

            statusLabel->setText(QStringLiteral("● 进程已结束，正在重新扫描占用状态..."));
            refreshUsageTable(table, statusLabel, refreshButton);
        }

        void refreshUsageTable(QTreeWidget* table, QLabel* statusLabel, QPushButton* refreshButton)
        {
            // 用途：异步刷新属性页内的文件占用列表。
            // 处理：调用 FileHandleUsageScanner，结果显示 PID/Handle/GrantedAccess/来源。
            // 返回：无。
            if (table == nullptr || statusLabel == nullptr || refreshButton == nullptr)
            {
                return;
            }

            QFileInfo info(m_filePath);
            if (!info.exists())
            {
                statusLabel->setText(QStringLiteral("● 目标不存在，无法扫描占用。"));
                return;
            }

            refreshButton->setEnabled(false);
            table->clear();
            statusLabel->setText(QStringLiteral("● 正在扫描文件占用..."));
            if (m_usageScanProgressBar != nullptr)
            {
                m_usageScanProgressBar->setRange(0, 100);
                m_usageScanProgressBar->setValue(0);
                m_usageScanProgressBar->setFormat(QStringLiteral("%p%"));
            }
            m_usageScanInProgress = true;
            m_usageRetryAfterR0Start = false;
            m_usageR0StartedDuringScan = false;
            m_usageScanCancelRequested->store(false);

            const std::vector<QString> targetPaths{ info.absoluteFilePath() };
            const std::shared_ptr<std::atomic_bool> cancelRequested =
                m_usageScanCancelRequested;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QTreeWidget> tableGuard(table);
            QPointer<QLabel> statusGuard(statusLabel);
            QPointer<QPushButton> refreshGuard(refreshButton);
            QPointer<QProgressBar> progressGuard(m_usageScanProgressBar);
            QPointer<QObject> uiDispatcher(QCoreApplication::instance());

            auto* task = QRunnable::create([guardThis, tableGuard, statusGuard, refreshGuard,
                                             progressGuard, uiDispatcher, targetPaths, cancelRequested]()
                {
                    const filedock::handleusage::HandleUsageScanResult scanResult =
                        filedock::handleusage::scanHandleUsageByPaths(
                            targetPaths,
                            0,
                            true,
                            [cancelRequested]()
                            {
                                return cancelRequested->load();
                            },
                            [guardThis, progressGuard, uiDispatcher, cancelRequested](
                                const QString&,
                                const float progressValue)
                            {
                                QObject* const dispatcher = uiDispatcher.data();
                                if (cancelRequested->load() || guardThis == nullptr ||
                                    progressGuard == nullptr || dispatcher == nullptr)
                                {
                                    return;
                                }
                                const int percentage = static_cast<int>(std::clamp(progressValue, 0.0f, 100.0f));
                                QMetaObject::invokeMethod(
                                    dispatcher,
                                    [guardThis, progressGuard, cancelRequested, percentage]()
                                    {
                                        if (!cancelRequested->load() && guardThis != nullptr &&
                                            progressGuard != nullptr)
                                        {
                                            progressGuard->setValue(percentage);
                                        }
                                    },
                                    Qt::QueuedConnection);
                            });
                    QObject* dispatcher = uiDispatcher.data();
                    if (cancelRequested->load() || dispatcher == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        dispatcher,
                        [guardThis, tableGuard, statusGuard, refreshGuard,
                         progressGuard, cancelRequested, scanResult]()
                        {
                            if (cancelRequested->load() || guardThis == nullptr || tableGuard == nullptr ||
                                statusGuard == nullptr || refreshGuard == nullptr)
                            {
                                return;
                            }

                            const auto scanSnapshot =
                                std::make_shared<filedock::handleusage::HandleUsageScanResult>(scanResult);
                            const auto commitSnapshot =
                                [guardThis, tableGuard, statusGuard, refreshGuard, progressGuard, scanSnapshot]()
                            {
                                if (guardThis == nullptr || tableGuard == nullptr || statusGuard == nullptr ||
                                    refreshGuard == nullptr)
                                {
                                    return;
                                }

                                tableGuard->setSortingEnabled(false);
                                tableGuard->clear();
                                for (const filedock::handleusage::HandleUsageEntry& entry : scanSnapshot->entries)
                                {
                                    auto* item = new QTreeWidgetItem();
                                    item->setText(0, QString::number(entry.processId));
                                    item->setText(1, entry.processName);
                                    item->setText(2, entry.handleValue == 0
                                        ? QStringLiteral("-")
                                        : formatHex64(entry.handleValue));
                                    item->setText(3, entry.grantedAccess == 0
                                        ? QStringLiteral("-")
                                        : QStringLiteral("0x%1").arg(entry.grantedAccess, 8, 16, QChar('0')).toUpper());
                                    item->setText(4, entry.objectName);
                                    item->setText(5, entry.matchedTargetPath);
                                    const QString sourceText = entry.enumerationSource.trimmed().isEmpty()
                                        ? QStringLiteral("R3 DuplicateHandle")
                                        : entry.enumerationSource;
                                    const QString ruleText = entry.matchRuleText.trimmed().isEmpty()
                                        ? (entry.matchedByDirectoryRule ? QStringLiteral("目录前缀") : QStringLiteral("精确"))
                                        : entry.matchRuleText;
                                    item->setText(6, QStringLiteral("%1 | %2").arg(sourceText, ruleText));
                                    item->setData(0, usageProcessIdRole, static_cast<qulonglong>(entry.processId));
                                    item->setData(0, usageProcessCreationTimeRole, static_cast<qulonglong>(entry.processCreationTime));
                                    item->setData(0, usageHandleValueRole, static_cast<qulonglong>(entry.handleValue));
                                    item->setData(0, usageMatchedTargetPathRole, entry.matchedTargetPath);
                                    item->setData(0, usageDirectoryMatchRole, entry.matchedByDirectoryRule);
                                    tableGuard->addTopLevelItem(item);
                                }
                                tableGuard->setSortingEnabled(true);
                                if (tableGuard->header() != nullptr)
                                {
                                    tableGuard->resizeColumnToContents(0);
                                    tableGuard->resizeColumnToContents(1);
                                    tableGuard->resizeColumnToContents(2);
                                    tableGuard->resizeColumnToContents(3);
                                }
                                if (tableGuard->topLevelItemCount() > 0)
                                {
                                    tableGuard->setCurrentItem(tableGuard->topLevelItem(0));
                                }

                                QString statusText = QStringLiteral("● 扫描完成 %1 ms | 总句柄:%2 | 文件句柄:%3 | 命中:%4")
                                    .arg(scanSnapshot->elapsedMs)
                                    .arg(scanSnapshot->totalHandleCount)
                                    .arg(scanSnapshot->fileLikeHandleCount)
                                    .arg(scanSnapshot->matchedHandleCount);
                                if (!scanSnapshot->diagnosticText.trimmed().isEmpty())
                                {
                                    statusText += QStringLiteral(
                                        " | 存在诊断；详情已写入日志。");
                                    kLogEvent diagnosticEvent;
                                    warn << diagnosticEvent
                                        << "[FileDetailDialog] usage scan completed with diagnostics, matchedHandleCount="
                                        << scanSnapshot->matchedHandleCount
                                        << ", diagnostic="
                                        << scanSnapshot->diagnosticText.toStdString()
                                        << eol;
                                }
                                statusGuard->setText(statusText);
                                if (progressGuard != nullptr)
                                {
                                    progressGuard->setValue(100);
                                }
                                refreshGuard->setEnabled(true);

                                guardThis->m_usageScanInProgress = false;
                                if (!scanSnapshot->r3HandleFallbackUsed)
                                {
                                    guardThis->m_usageRetryAfterR0Start = false;
                                    guardThis->m_usageR0StartedDuringScan = false;
                                    return;
                                }

                                // DriverClient 已在本轮先调用 R0，并由 MainWindow 在 UI 线程提示启用。
                                // 若服务在 R3 回落期间启动，提交当前 R3 结果后只自动重扫一次；
                                // 否则保持 R3 结果并等待后续的 R0 启动成功通知。
                                if (guardThis->m_usageR0StartedDuringScan)
                                {
                                    guardThis->m_usageR0StartedDuringScan = false;
                                    QMetaObject::invokeMethod(
                                        guardThis.data(),
                                        [guardThis, tableGuard, statusGuard, refreshGuard]()
                                        {
                                            if (guardThis != nullptr && tableGuard != nullptr &&
                                                statusGuard != nullptr && refreshGuard != nullptr)
                                            {
                                                guardThis->refreshUsageTable(
                                                    tableGuard.data(),
                                                    statusGuard.data(),
                                                    refreshGuard.data());
                                            }
                                        },
                                        Qt::QueuedConnection);
                                    return;
                                }
                                guardThis->m_usageRetryAfterR0Start = true;
                            };

                            if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                                guardThis.data(),
                                QStringLiteral("file-detail-usage-snapshot"),
                                { tableGuard.data() },
                                commitSnapshot))
                            {
                                return;
                            }
                            commitSnapshot();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void startR0FileInfoLoad(const QFileInfo& info, const QString& ntPathText)
        {
            // 用途：后台读取 R0 文件基础信息，避免常规页构建时阻塞属性窗口打开。
            // 输入：info/ntPathText 为查询目标；界面数据由成员保存，便于语言切换时完整重绘。
            // 处理：工作线程调用 ArkDriverClient；UI 线程保存结果并按当前语言重建正文。
            // 返回：无；对话框关闭或控件释放后自动丢弃结果。
            if (m_generalPropertyTree == nullptr)
            {
                return;
            }

            const std::uint64_t loadGeneration = ++m_generalR0LoadGeneration;
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, info, ntPathText, loadGeneration]()
                {
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    const ksword::ark::FileInfoQueryResult r0Info =
                        FileDetailDialog::queryR0FileInfo(info, ntPathText);
                    targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, r0Info, loadGeneration]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->m_generalR0LoadGeneration != loadGeneration)
                            {
                                return;
                            }

                            guardThis->m_generalR0Info = r0Info;
                            guardThis->m_generalR0Loaded = true;
                            guardThis->refreshGeneralTab();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        static FileSecuritySnapshot loadFileSecuritySnapshot(const QString& nativePath)
        {
            // 用途：读取 Owner/Group/DACL/SACL 并生成权限页快照。
            // 输入：nativePath 为 Windows 本机路径；调用者确保在后台线程执行。
            // 处理：同步调用 Windows 安全 API，同时保留旧文本明细和新表格行。
            // 返回：FileSecuritySnapshot；读取失败时 detailText 包含错误码，aceRows 可为空。
            FileSecuritySnapshot snapshot;
            QString content;
            std::wstring nativePathBuffer = nativePath.toStdWString();

            PSID ownerSid = nullptr;
            PSID groupSid = nullptr;
            PACL dacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            const DWORD queryMask = OWNER_SECURITY_INFORMATION
                | GROUP_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION;
            const DWORD queryResult = ::GetNamedSecurityInfoW(
                nativePathBuffer.data(),
                SE_FILE_OBJECT,
                queryMask,
                &ownerSid,
                &groupSid,
                &dacl,
                nullptr,
                &securityDescriptor);
            snapshot.descriptorError = queryResult;
            if (queryResult != ERROR_SUCCESS)
            {
                content += QStringLiteral("\n深层安全描述符读取失败, code=%1\n").arg(queryResult);
            }
            else
            {
                snapshot.descriptorOk = true;
                snapshot.ownerSidText = sidToStringText(ownerSid);
                snapshot.ownerAccountText = sidToAccountText(ownerSid);
                snapshot.groupSidText = sidToStringText(groupSid);
                snapshot.groupAccountText = sidToAccountText(groupSid);

                content += QStringLiteral("\n[Owner]\n");
                content += QStringLiteral("SID: %1\n").arg(snapshot.ownerSidText);
                content += QStringLiteral("账户: %1\n").arg(snapshot.ownerAccountText);

                content += QStringLiteral("\n[Primary Group]\n");
                content += QStringLiteral("SID: %1\n").arg(snapshot.groupSidText);
                content += QStringLiteral("账户: %1\n").arg(snapshot.groupAccountText);

                appendAclText(QStringLiteral("DACL"), dacl, content);
                appendAclRows(QStringLiteral("DACL"), dacl, snapshot.aceRows);
                ::LocalFree(securityDescriptor);
            }

            PSID saclOwnerSid = nullptr;
            PSID saclGroupSid = nullptr;
            PACL sacl = nullptr;
            PSECURITY_DESCRIPTOR saclDescriptor = nullptr;
            const DWORD saclResult = ::GetNamedSecurityInfoW(
                nativePathBuffer.data(),
                SE_FILE_OBJECT,
                SACL_SECURITY_INFORMATION,
                &saclOwnerSid,
                &saclGroupSid,
                nullptr,
                &sacl,
                &saclDescriptor);
            snapshot.saclError = saclResult;
            if (saclResult == ERROR_SUCCESS)
            {
                snapshot.saclOk = true;
                appendAclText(QStringLiteral("SACL"), sacl, content);
                appendAclRows(QStringLiteral("SACL"), sacl, snapshot.aceRows);
                ::LocalFree(saclDescriptor);
            }
            else
            {
                content += QStringLiteral("\n[SACL]\n");
                content += QStringLiteral("读取失败（通常需要 SeSecurityPrivilege）, code=%1\n").arg(saclResult);
            }

            content += QStringLiteral("\n说明：Mask 显示为十六进制，权限列为常见位标志拆解。");
            snapshot.detailText = content;
            return snapshot;
        }

        static QString buildSecurityDeepText(const QString& nativePath)
        {
            // 用途：兼容旧调用点，生成纯文本安全描述符明细。
            // 输入：nativePath 为 Windows 本机路径。
            // 处理：委托 loadFileSecuritySnapshot，避免维护两套 ACL 解析逻辑。
            // 返回：可展示文本；失败时包含错误码。
            return loadFileSecuritySnapshot(nativePath).detailText;
        }

        void populateSecurityWidgets(
            QTableWidget* aceTable,
            CodeEditorWidget* detailEditor,
            QLabel* statusLabel,
            const QString& baseContent,
            const FileSecuritySnapshot& snapshot)
        {
            // 用途：把后台读取的权限快照回填到权限页 UI。
            // 输入：aceTable/detailEditor/statusLabel 为目标控件，snapshot 为读取结果。
            // 处理：表格展示可编辑 DACL ACE，详情框保留完整文本和错误码。
            // 返回：无；控件为空时跳过对应更新。
            if (aceTable != nullptr &&
                ks::ui::IsTableUiCommitBlockedByContextMenu({ aceTable }))
            {
                const auto snapshotGuard = std::make_shared<FileSecuritySnapshot>(snapshot);
                const QPointer<FileDetailDialog> safeThis(this);
                const QPointer<QTableWidget> tableGuard(aceTable);
                const QPointer<CodeEditorWidget> editorGuard(detailEditor);
                const QPointer<QLabel> statusGuard(statusLabel);
                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    this,
                    QStringLiteral("file-detail-security-snapshot"),
                    { aceTable },
                    [safeThis, tableGuard, editorGuard, statusGuard, baseContent, snapshotGuard]()
                    {
                        if (!safeThis.isNull())
                        {
                            safeThis->populateSecurityWidgets(
                                tableGuard,
                                editorGuard,
                                statusGuard,
                                baseContent,
                                *snapshotGuard);
                        }
                    }))
                {
                    return;
                }
            }

            if (aceTable != nullptr)
            {
                aceTable->setSortingEnabled(false);
                aceTable->setRowCount(static_cast<int>(snapshot.aceRows.size()));
                for (int rowIndex = 0; rowIndex < static_cast<int>(snapshot.aceRows.size()); ++rowIndex)
                {
                    const FileSecurityAceRow& row = snapshot.aceRows[static_cast<std::size_t>(rowIndex)];
                    aceTable->setItem(rowIndex, 0, createReadonlyTableItem(row.scopeText));
                    aceTable->setItem(rowIndex, 1, createReadonlyTableItem(QString::number(row.aceIndex)));
                    aceTable->setItem(rowIndex, 2, createReadonlyTableItem(row.typeText));
                    aceTable->setItem(rowIndex, 3, createReadonlyTableItem(row.accountText));
                    aceTable->setItem(rowIndex, 4, createReadonlyTableItem(row.sidText));
                    aceTable->setItem(rowIndex, 5, createReadonlyTableItem(formatAccessMaskHex(row.mask)));
                    aceTable->setItem(rowIndex, 6, createReadonlyTableItem(row.rightsText));
                    aceTable->setItem(rowIndex, 7, createReadonlyTableItem(row.flagsText));
                    aceTable->setItem(rowIndex, 8, createReadonlyTableItem(row.canEdit ? QStringLiteral("可编辑") : QStringLiteral("只读展示")));
                    for (int columnIndex = 0; columnIndex < aceTable->columnCount(); ++columnIndex)
                    {
                        QTableWidgetItem* item = aceTable->item(rowIndex, columnIndex);
                        if (item == nullptr)
                        {
                            continue;
                        }
                        item->setData(Qt::UserRole + 1, row.scopeText);
                        item->setData(Qt::UserRole + 2, static_cast<qulonglong>(row.aceIndex));
                        item->setData(Qt::UserRole + 3, row.sidText);
                        item->setData(Qt::UserRole + 4, row.typeText);
                        item->setData(Qt::UserRole + 5, static_cast<qulonglong>(row.mask));
                        item->setData(Qt::UserRole + 6, row.canEdit);
                    }
                }
                aceTable->setSortingEnabled(true);
                aceTable->resizeColumnsToContents();
            }

            if (detailEditor != nullptr)
            {
                QString detailText = baseContent;
                if (snapshot.descriptorOk)
                {
                    detailText += QStringLiteral("\n[摘要]\nOwner: %1 | %2\nPrimary Group: %3 | %4\n")
                        .arg(snapshot.ownerAccountText)
                        .arg(snapshot.ownerSidText)
                        .arg(snapshot.groupAccountText)
                        .arg(snapshot.groupSidText);
                }
                detailText += snapshot.detailText;
                detailEditor->setLocalizedText(detailText);
            }

            if (statusLabel != nullptr)
            {
                const QString daclState = snapshot.descriptorOk
                    ? QStringLiteral("DACL 已读取")
                    : QStringLiteral("DACL 读取失败:%1").arg(snapshot.descriptorError);
                const QString saclState = snapshot.saclOk
                    ? QStringLiteral("SACL 已读取")
                    : QStringLiteral("SACL 只读失败:%1").arg(snapshot.saclError);
                statusLabel->setText(QStringLiteral("● %1；%2；ACE=%3")
                    .arg(daclState)
                    .arg(saclState)
                    .arg(snapshot.aceRows.size()));
            }
        }

        void startSecurityDeepLoad(
            QTableWidget* aceTable,
            CodeEditorWidget* detailEditor,
            QLabel* statusLabel,
            const QString& baseContent,
            const QString& nativePath)
        {
            // 用途：后台执行深层 ACL/SACL 解析并刷新权限页 UI。
            // 输入：baseContent 为快速权限摘要，nativePath 为目标路径。
            // 处理：工作线程读取安全描述符，UI 线程更新表格、状态和详情文本。
            // 返回：无；控件失效时丢弃结果。
            if (aceTable == nullptr || detailEditor == nullptr || statusLabel == nullptr)
            {
                return;
            }

            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QTableWidget> tableGuard(aceTable);
            QPointer<CodeEditorWidget> editorGuard(detailEditor);
            QPointer<QLabel> statusGuard(statusLabel);
            auto* task = QRunnable::create([guardThis, tableGuard, editorGuard, statusGuard, baseContent, nativePath]()
                {
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    const FileSecuritySnapshot snapshot = FileDetailDialog::loadFileSecuritySnapshot(nativePath);
                    targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, tableGuard, editorGuard, statusGuard, baseContent, snapshot]()
                        {
                            if (guardThis != nullptr)
                            {
                                guardThis->populateSecurityWidgets(
                                    tableGuard,
                                    editorGuard,
                                    statusGuard,
                                    baseContent,
                                    snapshot);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        DWORD maskFromSecurityPreset(const int presetIndex)
        {
            // 用途：把权限预设下拉框映射为 Windows 文件访问掩码。
            // 输入：presetIndex 为 QComboBox 当前索引。
            // 处理：优先覆盖常见文件安全页语义，减少用户手工拼位需求。
            // 返回：FILE_* / 标准权限组合掩码。
            switch (presetIndex)
            {
            case 0:
                return FILE_GENERIC_READ;
            case 1:
                return FILE_GENERIC_WRITE;
            case 2:
                return FILE_GENERIC_READ | FILE_GENERIC_WRITE;
            case 3:
                return FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
            case 4:
                return FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE;
            case 5:
                return FILE_ALL_ACCESS;
            default:
                return FILE_GENERIC_READ;
            }
        }

        DWORD maskFromSecurityChecks(
            QCheckBox* readCheck,
            QCheckBox* writeCheck,
            QCheckBox* executeCheck,
            QCheckBox* deleteCheck,
            QCheckBox* writeDacCheck,
            QCheckBox* writeOwnerCheck)
        {
            // 用途：把高级复选框合成为访问掩码。
            // 输入：各权限复选框控件，可为空。
            // 处理：只采纳勾选的权限位；未勾选时返回 0。
            // 返回：访问掩码。
            DWORD mask = 0;
            if (readCheck != nullptr && readCheck->isChecked()) mask |= FILE_GENERIC_READ;
            if (writeCheck != nullptr && writeCheck->isChecked()) mask |= FILE_GENERIC_WRITE;
            if (executeCheck != nullptr && executeCheck->isChecked()) mask |= FILE_GENERIC_EXECUTE;
            if (deleteCheck != nullptr && deleteCheck->isChecked()) mask |= DELETE;
            if (writeDacCheck != nullptr && writeDacCheck->isChecked()) mask |= WRITE_DAC;
            if (writeOwnerCheck != nullptr && writeOwnerCheck->isChecked()) mask |= WRITE_OWNER;
            return mask;
        }

        DWORD inheritanceFlagsFromCombo(const int inheritIndex)
        {
            // 用途：把继承范围下拉框映射为 EXPLICIT_ACCESS 继承标志。
            // 输入：inheritIndex 为 QComboBox 当前索引。
            // 处理：文件默认不继承，目录可选择子对象继承。
            // 返回：NO_INHERITANCE / SUB_CONTAINERS_AND_OBJECTS_INHERIT 等标志。
            switch (inheritIndex)
            {
            case 1:
                return SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            case 2:
                return SUB_OBJECTS_ONLY_INHERIT;
            case 3:
                return SUB_CONTAINERS_ONLY_INHERIT;
            default:
                return NO_INHERITANCE;
            }
        }

        bool extractAceSidAndType(LPVOID acePointer, BYTE* aceTypeOut, PSID* sidOut)
        {
            // 用途：从常见 ACE 结构取出 AceType 与 SID 指针。
            // 输入：acePointer 来自 GetAce。
            // 处理：只解析当前 UI 支持删除的 DACL ACE 类型。
            // 返回：成功解析返回 true；未知类型返回 false。
            if (acePointer == nullptr || aceTypeOut == nullptr || sidOut == nullptr)
            {
                return false;
            }

            ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
            *aceTypeOut = aceHeader->AceType;
            *sidOut = nullptr;
            switch (aceHeader->AceType)
            {
            case ACCESS_ALLOWED_ACE_TYPE:
                *sidOut = reinterpret_cast<PSID>(&reinterpret_cast<ACCESS_ALLOWED_ACE*>(acePointer)->SidStart);
                return true;
            case ACCESS_DENIED_ACE_TYPE:
                *sidOut = reinterpret_cast<PSID>(&reinterpret_cast<ACCESS_DENIED_ACE*>(acePointer)->SidStart);
                return true;
            default:
                return false;
            }
        }

        DWORD applySecurityAceChange(
            const QString& accountText,
            const DWORD accessMask,
            const ACCESS_MODE accessMode,
            const DWORD inheritanceFlags,
            QString& detailTextOut)
        {
            // 用途：添加或设置一个 DACL ACE。
            // 输入：accountText 为账户名或 SID 字符串，accessMask 为权限掩码，accessMode 为允许/拒绝模式。
            // 处理：读取现有 DACL，调用 SetEntriesInAclW 合成新 DACL，再写回文件对象。
            // 返回：Win32 错误码；ERROR_SUCCESS 表示写入成功。
            const QString normalizedAccount = accountText.trimmed();
            if (normalizedAccount.isEmpty())
            {
                detailTextOut = QStringLiteral("账户不能为空。可填写 DOMAIN\\User、BUILTIN\\Administrators 或 S-1-...。");
                return ERROR_INVALID_PARAMETER;
            }
            if (accessMask == 0)
            {
                detailTextOut = QStringLiteral("权限掩码为 0，未执行写入。");
                return ERROR_INVALID_PARAMETER;
            }

            std::wstring pathBuffer = QDir::toNativeSeparators(m_filePath).toStdWString();
            PACL oldDacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            DWORD result = ::GetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                &oldDacl,
                nullptr,
                &securityDescriptor);
            if (result != ERROR_SUCCESS)
            {
                detailTextOut = QStringLiteral("读取现有 DACL 失败，code=%1。").arg(result);
                return result;
            }

            std::wstring accountBuffer = normalizedAccount.toStdWString();
            PSID trusteeSid = nullptr;
            const bool accountLooksLikeSid = normalizedAccount.startsWith(QStringLiteral("S-"), Qt::CaseInsensitive);
            if (accountLooksLikeSid)
            {
                if (::ConvertStringSidToSidW(accountBuffer.c_str(), &trusteeSid) == FALSE || trusteeSid == nullptr)
                {
                    result = ::GetLastError();
                    if (securityDescriptor != nullptr)
                    {
                        ::LocalFree(securityDescriptor);
                    }
                    detailTextOut = QStringLiteral("SID 字符串解析失败，code=%1，SID=%2。")
                        .arg(result)
                        .arg(normalizedAccount);
                    return result;
                }
            }

            EXPLICIT_ACCESS_W explicitAccess{};
            explicitAccess.grfAccessPermissions = accessMask;
            explicitAccess.grfAccessMode = accessMode;
            explicitAccess.grfInheritance = inheritanceFlags;
            explicitAccess.Trustee.TrusteeForm = accountLooksLikeSid ? TRUSTEE_IS_SID : TRUSTEE_IS_NAME;
            explicitAccess.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            explicitAccess.Trustee.ptstrName = accountLooksLikeSid
                ? reinterpret_cast<LPWSTR>(trusteeSid)
                : accountBuffer.data();

            PACL newDacl = nullptr;
            result = ::SetEntriesInAclW(1, &explicitAccess, oldDacl, &newDacl);
            if (result == ERROR_SUCCESS)
            {
                result = ::SetNamedSecurityInfoW(
                    pathBuffer.data(),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    nullptr,
                    nullptr,
                    newDacl,
                    nullptr);
            }

            if (newDacl != nullptr)
            {
                ::LocalFree(newDacl);
            }
            if (trusteeSid != nullptr)
            {
                ::LocalFree(trusteeSid);
            }
            if (securityDescriptor != nullptr)
            {
                ::LocalFree(securityDescriptor);
            }

            detailTextOut = result == ERROR_SUCCESS
                ? QStringLiteral("已写入 DACL：账户=%1，模式=%2，Mask=%3，继承标志=0x%4。")
                    .arg(normalizedAccount)
                    .arg(accessMode == DENY_ACCESS ? QStringLiteral("拒绝") : QStringLiteral("允许/设置"))
                    .arg(formatAccessMaskHex(accessMask))
                    .arg(inheritanceFlags, 0, 16)
                : QStringLiteral("写入 DACL 失败，code=%1。账户=%2，Mask=%3。")
                    .arg(result)
                    .arg(normalizedAccount)
                    .arg(formatAccessMaskHex(accessMask));
            return result;
        }

        DWORD deleteSelectedDaclAce(QTableWidget* aceTable, QString& detailTextOut)
        {
            // 用途：删除权限表中当前选中的非继承 DACL ACE。
            // 输入：aceTable 为权限页 ACE 表格，当前行保存 SID/类型/序号元数据。
            // 处理：读取现有 DACL，复制除目标 ACE 外的原始 ACE 字节，最后 SetNamedSecurityInfoW 写回。
            // 返回：Win32 错误码；ERROR_SUCCESS 表示删除成功。
            if (aceTable == nullptr || aceTable->currentRow() < 0)
            {
                detailTextOut = QStringLiteral("请先在 DACL 表格中选择一条可编辑 ACE。");
                return ERROR_INVALID_PARAMETER;
            }

            const int rowIndex = aceTable->currentRow();
            QTableWidgetItem* firstItem = aceTable->item(rowIndex, 0);
            if (firstItem == nullptr)
            {
                detailTextOut = QStringLiteral("选中行无元数据，无法删除。");
                return ERROR_INVALID_PARAMETER;
            }

            const QString scopeText = firstItem->data(Qt::UserRole + 1).toString();
            const DWORD selectedAceIndex = firstItem->data(Qt::UserRole + 2).toUInt();
            const QString selectedSidText = firstItem->data(Qt::UserRole + 3).toString();
            const QString selectedTypeText = firstItem->data(Qt::UserRole + 4).toString();
            const bool canEdit = firstItem->data(Qt::UserRole + 6).toBool();
            if (scopeText != QStringLiteral("DACL") || !canEdit)
            {
                detailTextOut = QStringLiteral("当前 ACE 只能展示，不能由此按钮修改。继承 ACE、SACL 和对象 ACE 需要在来源对象或审计页处理。");
                return ERROR_ACCESS_DENIED;
            }

            std::wstring pathBuffer = QDir::toNativeSeparators(m_filePath).toStdWString();
            PACL oldDacl = nullptr;
            PSECURITY_DESCRIPTOR securityDescriptor = nullptr;
            DWORD result = ::GetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                &oldDacl,
                nullptr,
                &securityDescriptor);
            if (result != ERROR_SUCCESS)
            {
                detailTextOut = QStringLiteral("读取现有 DACL 失败，code=%1。").arg(result);
                return result;
            }
            if (oldDacl == nullptr)
            {
                if (securityDescriptor != nullptr)
                {
                    ::LocalFree(securityDescriptor);
                }
                detailTextOut = QStringLiteral("当前 DACL 为空，无法删除 ACE。");
                return ERROR_NOT_FOUND;
            }

            ACL_SIZE_INFORMATION aclSizeInfo{};
            if (::GetAclInformation(oldDacl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation) == FALSE)
            {
                result = ::GetLastError();
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("读取 ACL 信息失败，code=%1。").arg(result);
                return result;
            }

            DWORD newAclBytes = sizeof(ACL);
            bool targetFound = false;
            for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
            {
                LPVOID acePointer = nullptr;
                if (::GetAce(oldDacl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                {
                    result = ::GetLastError();
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("读取 ACE[%1] 失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }

                ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
                BYTE aceType = 0;
                PSID aceSid = nullptr;
                const bool sidOk = extractAceSidAndType(acePointer, &aceType, &aceSid);
                const bool isTarget = sidOk
                    && aceIndex == selectedAceIndex
                    && aceTypeToText(aceType) == selectedTypeText
                    && sidToStringText(aceSid) == selectedSidText
                    && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                if (isTarget)
                {
                    targetFound = true;
                    continue;
                }
                newAclBytes += aceHeader->AceSize;
            }

            if (!targetFound)
            {
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("未在当前 DACL 中找到匹配 ACE，可能权限已被其它进程修改。请刷新后重试。");
                return ERROR_NOT_FOUND;
            }

            PACL newDacl = reinterpret_cast<PACL>(::LocalAlloc(LPTR, newAclBytes));
            if (newDacl == nullptr)
            {
                result = ::GetLastError();
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("分配新 DACL 失败，code=%1。").arg(result);
                return result;
            }

            const DWORD aclRevision = oldDacl->AclRevision;
            if (::InitializeAcl(newDacl, newAclBytes, aclRevision) == FALSE)
            {
                result = ::GetLastError();
                ::LocalFree(newDacl);
                ::LocalFree(securityDescriptor);
                detailTextOut = QStringLiteral("初始化新 DACL 失败，code=%1。").arg(result);
                return result;
            }

            for (DWORD aceIndex = 0; aceIndex < aclSizeInfo.AceCount; ++aceIndex)
            {
                LPVOID acePointer = nullptr;
                if (::GetAce(oldDacl, aceIndex, &acePointer) == FALSE || acePointer == nullptr)
                {
                    result = ::GetLastError();
                    ::LocalFree(newDacl);
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("复制 ACE[%1] 前读取失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }

                ACE_HEADER* aceHeader = reinterpret_cast<ACE_HEADER*>(acePointer);
                BYTE aceType = 0;
                PSID aceSid = nullptr;
                const bool sidOk = extractAceSidAndType(acePointer, &aceType, &aceSid);
                const bool isTarget = sidOk
                    && aceIndex == selectedAceIndex
                    && aceTypeToText(aceType) == selectedTypeText
                    && sidToStringText(aceSid) == selectedSidText
                    && (aceHeader->AceFlags & INHERITED_ACE) == 0;
                if (isTarget)
                {
                    continue;
                }
                if (::AddAce(newDacl, aclRevision, MAXDWORD, acePointer, aceHeader->AceSize) == FALSE)
                {
                    result = ::GetLastError();
                    ::LocalFree(newDacl);
                    ::LocalFree(securityDescriptor);
                    detailTextOut = QStringLiteral("复制 ACE[%1] 到新 DACL 失败，code=%2。").arg(aceIndex).arg(result);
                    return result;
                }
            }

            result = ::SetNamedSecurityInfoW(
                pathBuffer.data(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                newDacl,
                nullptr);
            ::LocalFree(newDacl);
            ::LocalFree(securityDescriptor);

            detailTextOut = result == ERROR_SUCCESS
                ? QStringLiteral("已删除 ACE[%1]：%2 | %3。").arg(selectedAceIndex).arg(selectedTypeText, selectedSidText)
                : QStringLiteral("删除 ACE 写回失败，code=%1。").arg(result);
            return result;
        }

        void startSignatureLoad(CodeEditorWidget* textEditorWidget)
        {
            // 用途：后台先用 R3 WinVerifyTrust/证书链/Catalog API 验证，再补充 KswordARK
            // PE Security Directory、WIN_CERTIFICATE 外层结构和内核 CI 缓存签名等级。
            // 输入：textEditorWidget 为签名页显示目标。
            // 处理：R3 与 R0 证据并列展示，不经过 PowerShell。
            // 返回：无。
            if (textEditorWidget == nullptr)
            {
                return;
            }

            textEditorWidget->setLocalizedText(
                QStringLiteral("正在通过 R3 WinVerifyTrust 与 KswordARK R0 读取签名证据...\n目标: %1")
                    .arg(QDir::toNativeSeparators(m_filePath)));

            const QString filePathSnapshot = m_filePath;
            const QString ntPathSnapshot = buildDriverNtPath(filePathSnapshot);
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            auto* task = QRunnable::create([guardThis, editorGuard, filePathSnapshot, ntPathSnapshot]()
                {
                    QString finalText;
                    const ks::file::metadata::SignatureInspection r3Signature =
                        ks::file::metadata::inspectSignature(filePathSnapshot);
                    finalText += QStringLiteral("[R3 WinVerifyTrust / 证书链]\n");
                    finalText += QStringLiteral("WinVerifyTrust: 0x%1\n")
                        .arg(static_cast<quint32>(r3Signature.trustStatus), 8, 16, QLatin1Char('0'));
                    finalText += QStringLiteral("嵌入式签名: %1\n")
                        .arg(r3Signature.embedded ? QStringLiteral("是") : QStringLiteral("否"));
                    finalText += QStringLiteral("Catalog 签名: %1\n")
                        .arg(r3Signature.catalog ? QStringLiteral("是") : QStringLiteral("否"));
                    finalText += QStringLiteral("Catalog 路径: %1\n")
                        .arg(r3Signature.catalogPath.isEmpty() ? QStringLiteral("-") : r3Signature.catalogPath);
                    finalText += QStringLiteral("签名者: %1\n")
                        .arg(r3Signature.signer.isEmpty() ? QStringLiteral("-") : r3Signature.signer);
                    finalText += QStringLiteral("颁发者: %1\n")
                        .arg(r3Signature.issuer.isEmpty() ? QStringLiteral("-") : r3Signature.issuer);
                    finalText += QStringLiteral("证书 SHA-256: %1\n")
                        .arg(r3Signature.sha256Fingerprint.isEmpty()
                            ? QStringLiteral("-") : r3Signature.sha256Fingerprint);
                    finalText += QStringLiteral("有效期: %1 → %2\n")
                        .arg(r3Signature.validFrom.isEmpty() ? QStringLiteral("-") : r3Signature.validFrom)
                        .arg(r3Signature.validUntil.isEmpty() ? QStringLiteral("-") : r3Signature.validUntil);
                    finalText += QStringLiteral("时间戳签名者: %1\n")
                        .arg(r3Signature.timestampSigner.isEmpty()
                            ? QStringLiteral("-") : r3Signature.timestampSigner);
                    finalText += QStringLiteral("链状态: %1\n\n")
                        .arg(r3Signature.chainStatus.isEmpty() ? QStringLiteral("-") : r3Signature.chainStatus);
                    if (ntPathSnapshot.isEmpty())
                    {
                        finalText += QStringLiteral("无法生成供内核使用的 NT 路径。\n");
                        finalText += QStringLiteral("目标: %1")
                            .arg(QDir::toNativeSeparators(filePathSnapshot));
                    }
                    else
                    {
                        const ksword::ark::ImageSignatureQueryResult signatureResult =
                            ksword::ark::DriverClient().queryImageSignature(ntPathSnapshot.toStdWString());
                        finalText += QStringLiteral("[R0 内核签名证据]\n");
                        finalText += QStringLiteral("目标: %1\n")
                            .arg(QDir::toNativeSeparators(filePathSnapshot));
                        finalText += QStringLiteral("NT 路径: %1\n\n").arg(ntPathSnapshot);
                        finalText += QString::fromStdString(
                            ksword::ark::formatImageSignatureEvidence(signatureResult));
                        finalText += QStringLiteral("\n");
                        finalText += QStringLiteral(
                            "结论边界：WinVerifyTrust 负责 R3 信任验证；PE 证书表及 WIN_CERTIFICATE 是磁盘结构证据；CI cached signing level 是独立的内核缓存结果。Catalog 签名不能从目标文件本身删除。");
                    }

                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [editorGuard, finalText]()
                        {
                            if (editorGuard != nullptr)
                            {
                                editorGuard->setLocalizedText(finalText);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void startPeAnalysisLoad(CodeEditorWidget* textEditorWidget)
        {
            // 用途：后台执行 PE 深度解析文本生成。
            // 输入：textEditorWidget 为 PE 信息页显示目标。
            // 处理：调用 FilePropertyPeAnalyzer，避免 Import/Export/Directory 解析卡住 UI。
            // 返回：无。
            if (textEditorWidget == nullptr)
            {
                return;
            }

            textEditorWidget->setLocalizedText(QStringLiteral("PE 信息加载中...\n目标: %1")
                .arg(QDir::toNativeSeparators(m_filePath)));
            const QString filePathSnapshot = m_filePath;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            auto* task = QRunnable::create([guardThis, editorGuard, filePathSnapshot]()
                {
                    const QString peText = file_dock_detail::buildPeAnalysisText(filePathSnapshot);
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [editorGuard, peText]()
                        {
                            if (editorGuard != nullptr)
                            {
                                editorGuard->setLocalizedText(peText);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        static PrintableStringsPreview extractPrintableStringsPreview(const QString& filePath)
        {
            // 用途：以分块方式提取可打印 ASCII 字符串，替代 readAll。
            // 输入：filePath 为目标文件路径。
            // 处理：最多输出 2000 条字符串，最多扫描 128MiB，避免超大文件长时间占用线程。
            // 返回：可翻译的程序说明与必须逐字保留的文件字符串分开承载。
            PrintableStringsPreview preview{};
            QFile file(filePath);
            if (!file.open(QIODevice::ReadOnly))
            {
                preview.sourcePrefixText = QStringLiteral("无法读取文件，无法提取字符串。\nQFile错误码: %1")
                    .arg(static_cast<int>(file.error()));
                return preview;
            }

            constexpr qint64 kChunkBytes = 1024 * 1024;
            constexpr qint64 kMaxScanBytes = 128LL * 1024LL * 1024LL;
            QString current;
            QStringList result;
            qint64 scannedBytes = 0;
            while (!file.atEnd() && result.size() < 2000 && scannedBytes < kMaxScanBytes)
            {
                const QByteArray bytes = file.read(std::min(kChunkBytes, kMaxScanBytes - scannedBytes));
                if (bytes.isEmpty())
                {
                    break;
                }
                scannedBytes += bytes.size();
                for (char ch : bytes)
                {
                    const unsigned char c = static_cast<unsigned char>(ch);
                    if (std::isprint(c) != 0)
                    {
                        current.append(QChar::fromLatin1(ch));
                    }
                    else
                    {
                        if (current.length() >= 4)
                        {
                            result.append(current);
                            if (result.size() >= 2000)
                            {
                                break;
                            }
                        }
                        current.clear();
                    }
                }
            }
            if (current.length() >= 4 && result.size() < 2000)
            {
                result.append(current);
            }

            preview.rawStringText = result.join('\n');
            if (preview.rawStringText.trimmed().isEmpty())
            {
                preview.sourcePrefixText = QStringLiteral("<未提取到可打印字符串，或文件内容全部为二进制不可见字符。>");
            }
            if (!file.atEnd())
            {
                if (!preview.sourcePrefixText.isEmpty())
                {
                    preview.sourcePrefixText += QStringLiteral("\n\n");
                }
                preview.sourcePrefixText += QStringLiteral("[提示] 已达到扫描/显示上限：扫描 %1 字节，显示 %2 条。\n\n")
                    .arg(scannedBytes)
                    .arg(result.size());
            }
            return preview;
        }

        void startStringsLoad(CodeEditorWidget* textEditorWidget)
        {
            // 用途：后台提取字符串页内容。
            // 输入：textEditorWidget 为字符串页显示目标。
            // 处理：分块扫描文件，结果完成后回填 UI。
            // 返回：无。
            if (textEditorWidget == nullptr)
            {
                return;
            }

            textEditorWidget->setLocalizedText(QStringLiteral("字符串扫描中...\n目标: %1")
                .arg(QDir::toNativeSeparators(m_filePath)));
            const QString filePathSnapshot = m_filePath;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<CodeEditorWidget> editorGuard(textEditorWidget);
            auto* task = QRunnable::create([guardThis, editorGuard, filePathSnapshot]()
                {
                    const PrintableStringsPreview preview = FileDetailDialog::extractPrintableStringsPreview(filePathSnapshot);
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [editorGuard, preview]()
                        {
                            if (editorGuard != nullptr)
                            {
                                editorGuard->setLocalizedTextWithRawSuffix(
                                    preview.sourcePrefixText,
                                    preview.rawStringText);
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        static QString dependencyRowsToClipboardText(QTableWidget* table, const bool dllOnly)
        {
            // 用途：把依赖 DLL 表格选中行转换为剪贴板文本。
            // 输入：table 为依赖页表格，dllOnly 控制只复制 DLL 名称还是整行。
            // 返回：以换行分隔的文本；没有选中行时返回空字符串。
            if (table == nullptr)
            {
                return QString();
            }

            std::set<int> selectedRows;
            if (table->selectionModel() != nullptr)
            {
                const QModelIndexList rowIndexes = table->selectionModel()->selectedRows();
                for (const QModelIndex& index : rowIndexes)
                {
                    selectedRows.insert(index.row());
                }
            }
            if (selectedRows.empty() && table->currentRow() >= 0)
            {
                selectedRows.insert(table->currentRow());
            }

            QStringList lines;
            QStringList seenDllNames;
            for (const int rowIndex : selectedRows)
            {
                if (rowIndex < 0 || rowIndex >= table->rowCount())
                {
                    continue;
                }
                if (dllOnly)
                {
                    const QTableWidgetItem* dllItem = table->item(rowIndex, 0);
                    const QString dllName = dllItem != nullptr ? dllItem->text().trimmed() : QString();
                    if (!dllName.isEmpty() && !seenDllNames.contains(dllName, Qt::CaseInsensitive))
                    {
                        seenDllNames.push_back(dllName);
                        lines.push_back(dllName);
                    }
                    continue;
                }

                QStringList columns;
                for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
                    columns.push_back(item != nullptr ? item->text() : QString());
                }
                lines.push_back(columns.join('\t'));
            }
            return lines.join('\n');
        }

        void populateDependencyTable(QTableWidget* table, QLabel* statusLabel, const file_dock_detail::PeDependencyResult& result, const qint64 elapsedMs)
        {
            // 用途：把后台解析出的依赖 DLL 结果填入表格。
            // 输入：table/statusLabel 为 UI 控件，result 为结构化导入表，elapsedMs 为解析耗时。
            // 处理：批量禁用排序和刷新，减少大量导入项时的 UI 抖动。
            // 返回：无。
            if (table == nullptr || statusLabel == nullptr)
            {
                return;
            }

            table->setSortingEnabled(false);
            table->setUpdatesEnabled(false);
            table->clearContents();
            constexpr int kMaxDisplayedDependencyRows = 20000;
            const int totalRowCount = static_cast<int>(result.rows.size());
            const int displayedRowCount = std::min(totalRowCount, kMaxDisplayedDependencyRows);
            table->setRowCount(displayedRowCount);
            for (int rowIndex = 0; rowIndex < displayedRowCount; ++rowIndex)
            {
                const file_dock_detail::PeDependencyRow& row = result.rows[rowIndex];
                const QString functionText = row.importMode == QStringLiteral("Ordinal")
                    ? QStringLiteral("#%1").arg(row.ordinalText)
                    : (row.functionName.trimmed().isEmpty() ? QStringLiteral("-") : row.functionName);

                table->setItem(rowIndex, 0, new QTableWidgetItem(row.dllName));
                table->setItem(rowIndex, 1, new QTableWidgetItem(functionText));
                table->setItem(rowIndex, 2, new QTableWidgetItem(row.hintText));
                table->setItem(rowIndex, 3, new QTableWidgetItem(row.importMode));
                table->setItem(rowIndex, 4, new QTableWidgetItem(row.thunkRvaText));
                table->setItem(rowIndex, 5, new QTableWidgetItem(row.diagnosticText));
            }
            table->setUpdatesEnabled(true);
            table->setSortingEnabled(true);
            if (table->horizontalHeader() != nullptr)
            {
                table->resizeColumnToContents(0);
                table->resizeColumnToContents(1);
                table->resizeColumnToContents(2);
                table->resizeColumnToContents(3);
            }

            if (!result.success)
            {
                statusLabel->setText(result.isPe
                    ? QStringLiteral("● PE 解析失败，未能读取依赖 DLL。耗时 %1 ms").arg(elapsedMs)
                    : QStringLiteral("● 不适用：目标不是 PE 文件。耗时 %1 ms").arg(elapsedMs));
                return;
            }
            if (!result.errorText.trimmed().isEmpty() && result.rows.isEmpty())
            {
                statusLabel->setText(QStringLiteral("● %1 耗时 %2 ms").arg(result.errorText.trimmed()).arg(elapsedMs));
                return;
            }
            QString statusText = QStringLiteral("● 加载完成 %1 ms | DLL:%2 | 导入项:%3")
                .arg(elapsedMs)
                .arg(result.dllNames.size())
                .arg(result.rows.size());
            if (displayedRowCount < totalRowCount)
            {
                statusText += QStringLiteral(" | 表格仅显示前 %1 行").arg(displayedRowCount);
            }
            statusLabel->setText(statusText);
        }

        void startDependencyLoad(QTableWidget* table, QLabel* statusLabel, CodeEditorWidget* detailEditor)
        {
            // 用途：后台读取 EXE/DLL Import Directory 并展示依赖 DLL。
            // 输入：table/statusLabel/detailEditor 为依赖页 UI 控件。
            // 处理：工作线程解析 PE；UI 线程填表和显示错误详情，失败不阻塞不崩溃。
            // 返回：无。
            if (table == nullptr || statusLabel == nullptr || detailEditor == nullptr)
            {
                return;
            }

            statusLabel->setText(QStringLiteral("● 正在后台读取 Import Directory..."));
            detailEditor->setLocalizedText(QStringLiteral("依赖 DLL 加载中...\n目标: %1")
                .arg(QDir::toNativeSeparators(m_filePath)));

            const QString filePathSnapshot = m_filePath;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QTableWidget> tableGuard(table);
            QPointer<QLabel> statusGuard(statusLabel);
            QPointer<CodeEditorWidget> detailGuard(detailEditor);
            auto* task = QRunnable::create([guardThis, tableGuard, statusGuard, detailGuard, filePathSnapshot]()
                {
                    const auto beginTime = std::chrono::steady_clock::now();
                    const file_dock_detail::PeDependencyResult result =
                        file_dock_detail::analyzePeDependencies(filePathSnapshot);
                    const qint64 elapsedMs = static_cast<qint64>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - beginTime).count());

                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, tableGuard, statusGuard, detailGuard, result, elapsedMs]()
                        {
                            if (guardThis == nullptr || tableGuard == nullptr ||
                                statusGuard == nullptr || detailGuard == nullptr)
                            {
                                return;
                            }

                            const auto resultSnapshot =
                                std::make_shared<file_dock_detail::PeDependencyResult>(result);
                            const auto commitSnapshot =
                                [guardThis, tableGuard, statusGuard, detailGuard, resultSnapshot, elapsedMs]()
                            {
                                if (guardThis == nullptr || tableGuard == nullptr ||
                                    statusGuard == nullptr || detailGuard == nullptr)
                                {
                                    return;
                                }

                                guardThis->populateDependencyTable(
                                    tableGuard,
                                    statusGuard,
                                    *resultSnapshot,
                                    elapsedMs);
                                QString detailText;
                                detailText += QStringLiteral("目标: %1\n")
                                    .arg(QDir::toNativeSeparators(guardThis->m_filePath));
                                if (!resultSnapshot->success ||
                                    !resultSnapshot->errorText.trimmed().isEmpty())
                                {
                                    detailText += QStringLiteral("%1\n")
                                        .arg(resultSnapshot->errorText.trimmed());
                                }
                                else
                                {
                                    detailText += QStringLiteral("依赖 DLL 名称:\n");
                                    for (const QString& dllName : resultSnapshot->dllNames)
                                    {
                                        detailText += QStringLiteral("  - %1\n").arg(dllName);
                                    }
                                }
                                detailGuard->setLocalizedText(detailText);
                            };

                            if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                                guardThis.data(),
                                QStringLiteral("file-detail-dependency-snapshot"),
                                { tableGuard.data() },
                                commitSnapshot))
                            {
                                return;
                            }
                            commitSnapshot();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void setMetadataEditorBusy(const bool busy)
        {
            m_metadataEditorBusy = busy;
            const bool editorEnabled = m_metadataHasSnapshot && !busy;
            for (std::size_t timeIndex = 0; timeIndex < m_metadataTimeChecks.size(); ++timeIndex)
            {
                if (m_metadataTimeChecks[timeIndex] != nullptr)
                {
                    m_metadataTimeChecks[timeIndex]->setEnabled(editorEnabled);
                }
                if (m_metadataTimeEdits[timeIndex] != nullptr)
                {
                    const bool timeSelected = m_metadataTimeChecks[timeIndex] != nullptr &&
                        m_metadataTimeChecks[timeIndex]->isChecked();
                    m_metadataTimeEdits[timeIndex]->setEnabled(editorEnabled && timeSelected);
                }
            }
            for (QCheckBox* const attributeCheck : m_metadataAttributeChecks)
            {
                if (attributeCheck != nullptr)
                {
                    attributeCheck->setEnabled(editorEnabled);
                }
            }
            if (m_metadataRefreshButton != nullptr)
            {
                m_metadataRefreshButton->setEnabled(!busy);
            }
            if (m_metadataApplyButton != nullptr)
            {
                m_metadataApplyButton->setEnabled(editorEnabled);
            }
        }

        void applyMetadataSnapshotToEditor(const FileMetadataSnapshot& snapshot)
        {
            if (!snapshot.ok)
            {
                return;
            }

            m_metadataApplyingSnapshot = true;
            m_metadataSnapshot = snapshot;
            m_metadataHasSnapshot = true;
            const std::array<LARGE_INTEGER, 4> timeValues = fileMetadataTimes(snapshot.basicInfo);
            for (std::size_t timeIndex = 0; timeIndex < timeValues.size(); ++timeIndex)
            {
                if (m_metadataTimeChecks[timeIndex] != nullptr)
                {
                    m_metadataTimeChecks[timeIndex]->setChecked(false);
                }
                if (m_metadataTimeEdits[timeIndex] != nullptr)
                {
                    QDateTime dateTime = fileMetadataTimeToLocalDateTime(timeValues[timeIndex]);
                    if (!dateTime.isValid())
                    {
                        dateTime = QDateTime::currentDateTime();
                    }
                    m_metadataTimeEdits[timeIndex]->setDateTime(dateTime);
                }
            }

            const auto& attributeMasks = editableFileAttributeMasks();
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeMasks.size();
                 ++attributeIndex)
            {
                if (m_metadataAttributeChecks[attributeIndex] != nullptr)
                {
                    m_metadataAttributeChecks[attributeIndex]->setChecked(
                        (snapshot.basicInfo.FileAttributes & attributeMasks[attributeIndex]) != 0U);
                    m_metadataAttributeTouched[attributeIndex] = false;
                }
            }
            m_metadataApplyingSnapshot = false;
            setMetadataEditorBusy(false);
        }

        static FileMetadataSnapshot metadataSnapshotForEditor(
            const ks::file::metadata::FileSnapshot& snapshot)
        {
            FileMetadataSnapshot editorSnapshot;
            editorSnapshot.ok = snapshot.ok;
            editorSnapshot.win32Error = snapshot.win32Error;
            editorSnapshot.basicInfo = snapshot.basicInfo;
            editorSnapshot.identityAvailable = snapshot.identity.available;
            editorSnapshot.volumeSerialNumber = snapshot.identity.volumeSerialNumber;
            editorSnapshot.fileIndex = snapshot.identity.fileIndex;
            return editorSnapshot;
        }

        void applyBatchMetadataSnapshotsToEditor(
            const QList<ks::file::metadata::FileSnapshot>& snapshots)
        {
            if (snapshots.isEmpty())
            {
                return;
            }
            applyMetadataSnapshotToEditor(metadataSnapshotForEditor(snapshots.front()));
            if (!m_batchMode)
            {
                return;
            }

            m_metadataApplyingSnapshot = true;
            const auto& attributeMasks = editableFileAttributeMasks();
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeMasks.size();
                 ++attributeIndex)
            {
                QCheckBox* const attributeCheck = m_metadataAttributeChecks[attributeIndex];
                if (attributeCheck == nullptr)
                {
                    continue;
                }
                const DWORD attributeMask = attributeMasks[attributeIndex];
                const bool firstValue =
                    (snapshots.front().basicInfo.FileAttributes & attributeMask) != 0U;
                const bool allSame = std::all_of(
                    snapshots.cbegin(),
                    snapshots.cend(),
                    [attributeMask, firstValue](const ks::file::metadata::FileSnapshot& item)
                    {
                        return ((item.basicInfo.FileAttributes & attributeMask) != 0U) == firstValue;
                    });
                attributeCheck->setTristate(true);
                attributeCheck->setCheckState(
                    allSame
                        ? (firstValue ? Qt::Checked : Qt::Unchecked)
                        : Qt::PartiallyChecked);
                m_metadataAttributeTouched[attributeIndex] = false;
            }
            m_metadataApplyingSnapshot = false;
        }

        void refreshMetadataEditor()
        {
            if (m_metadataStatusLabel == nullptr || m_metadataEditorBusy)
            {
                return;
            }

            if (pendingTargetCount() > 0)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                    ks::i18n::sourceText(QStringLiteral(
                        "存在尚未保存的暂存修改。请先保存或放弃暂存，再重新读取。")));
                return;
            }

            m_metadataHasSnapshot = false;
            setMetadataEditorBusy(true);
            m_metadataStatusLabel->setText(
                ks::i18n::sourceText(QStringLiteral("● 正在后台读取文件元数据...")));
            const std::uint64_t operationGeneration = ++m_metadataOperationGeneration;
            const QStringList filePathSnapshots = m_filePaths;
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, filePathSnapshots, operationGeneration]()
                {
                    QList<ks::file::metadata::FileSnapshot> snapshots;
                    snapshots.reserve(filePathSnapshots.size());
                    for (const QString& filePath : filePathSnapshots)
                    {
                        snapshots.push_back(ks::file::metadata::readFileSnapshot(filePath));
                    }
                    FileDetailDialog* targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, snapshots, filePathSnapshots, operationGeneration]()
                        {
                            if (guardThis == nullptr ||
                                guardThis->m_metadataOperationGeneration != operationGeneration)
                            {
                                return;
                            }
                            QList<ks::file::metadata::FileSnapshot> successfulSnapshots;
                            QList<ks::file::metadata::TargetPatch> targetPatches;
                            int failedCount = 0;
                            DWORD firstError = ERROR_SUCCESS;
                            for (qsizetype index = 0; index < snapshots.size(); ++index)
                            {
                                const ks::file::metadata::FileSnapshot& snapshot = snapshots.at(index);
                                if (!snapshot.ok)
                                {
                                    ++failedCount;
                                    if (firstError == ERROR_SUCCESS) firstError = snapshot.win32Error;
                                    continue;
                                }
                                successfulSnapshots.push_back(snapshot);
                                ks::file::metadata::TargetPatch patch;
                                patch.originalPath = filePathSnapshots.value(index);
                                patch.snapshot = snapshot;
                                targetPatches.push_back(patch);
                            }

                            guardThis->m_pendingPatches = targetPatches;
                            guardThis->m_metadataHasSnapshot = !successfulSnapshots.isEmpty();
                            if (successfulSnapshots.isEmpty())
                            {
                                guardThis->setMetadataEditorBusy(false);
                                guardThis->m_metadataStatusLabel->setText(
                                    ks::i18n::displayText(QStringLiteral("● 元数据读取失败：%1"))
                                        .arg(formatWin32ErrorText(firstError)));
                                guardThis->updatePendingSaveUi();
                                return;
                            }

                            guardThis->applyBatchMetadataSnapshotsToEditor(successfulSnapshots);
                            if (guardThis->m_metadataStatusLabel != nullptr)
                            {
                                guardThis->m_metadataStatusLabel->setText(failedCount == 0
                                    ? ks::i18n::sourceText(QStringLiteral(
                                        "● 已读取 %1 个目标。编辑内容只会暂存，底部保存前文件不会变化。"))
                                        .arg(successfulSnapshots.size())
                                    : ks::i18n::sourceText(QStringLiteral(
                                        "● 已读取 %1 个目标，%2 个目标读取失败。失败目标不会进入保存事务。"))
                                        .arg(successfulSnapshots.size())
                                        .arg(failedCount));
                            }
                            guardThis->updatePendingSaveUi();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void applyMetadataEditorChanges()
        {
            if (!m_metadataHasSnapshot || m_metadataEditorBusy)
            {
                return;
            }

            const std::array<QString, 4> timeNames{
                QStringLiteral("创建时间"),
                QStringLiteral("最后访问时间"),
                QStringLiteral("最后写入时间"),
                QStringLiteral("元数据变更时间（ChangeTime）")
            };
            std::array<bool, 4> updateTime{};
            std::array<LARGE_INTEGER, 4> timeValues{};
            bool hasTimeChange = false;
            for (std::size_t timeIndex = 0; timeIndex < updateTime.size(); ++timeIndex)
            {
                if (m_metadataTimeChecks[timeIndex] == nullptr ||
                    m_metadataTimeEdits[timeIndex] == nullptr ||
                    !m_metadataTimeChecks[timeIndex]->isChecked())
                {
                    continue;
                }
                const QDateTime editedDateTime = m_metadataTimeEdits[timeIndex]->dateTime();
                if (!editedDateTime.isValid())
                {
                    QMessageBox::warning(
                        this,
                        ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                        ks::i18n::sourceText(QStringLiteral("%1不是有效的日期时间。"))
                            .arg(ks::i18n::sourceText(timeNames[timeIndex])));
                    return;
                }
                updateTime[timeIndex] = true;
                timeValues[timeIndex] = localDateTimeToFileMetadataTime(editedDateTime);
                hasTimeChange = true;
            }

            const auto& attributeMasks = editableFileAttributeMasks();
            const bool hasAttributeChange = std::any_of(
                m_metadataAttributeTouched.cbegin(),
                m_metadataAttributeTouched.cend(),
                [](const bool touched) { return touched; });
            if (!hasTimeChange && !hasAttributeChange)
            {
                QMessageBox::information(
                    this,
                    ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                    ks::i18n::sourceText(QStringLiteral("没有需要暂存的基础元数据改动。")));
                return;
            }

            for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                patch.basic.updateTime = updateTime;
                patch.basic.timeValue = timeValues;
                patch.basic.updateAttributes = hasAttributeChange;
                DWORD editableAttributes =
                    patch.snapshot.basicInfo.FileAttributes & editableFileAttributeMask();
                for (std::size_t attributeIndex = 0;
                     attributeIndex < attributeMasks.size();
                     ++attributeIndex)
                {
                    if (!m_metadataAttributeTouched[attributeIndex] ||
                        m_metadataAttributeChecks[attributeIndex] == nullptr)
                    {
                        continue;
                    }
                    if (m_metadataAttributeChecks[attributeIndex]->checkState() == Qt::Checked)
                    {
                        editableAttributes |= attributeMasks[attributeIndex];
                    }
                    else
                    {
                        editableAttributes &= ~attributeMasks[attributeIndex];
                    }
                }
                patch.basic.editableAttributes = editableAttributes;
            }

            if (m_metadataStatusLabel != nullptr)
            {
                m_metadataStatusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "● 基础元数据已暂存。点击窗口底部“保存全部修改”后才会写入文件。")));
            }
            updatePendingSaveUi();
        }

        int pendingTargetCount() const
        {
            return static_cast<int>(std::count_if(
                m_pendingPatches.cbegin(),
                m_pendingPatches.cend(),
                [](const ks::file::metadata::TargetPatch& patch)
                {
                    return !patch.empty();
                }));
        }

        bool ensurePendingPatchesForStaging()
        {
            if (!m_pendingPatches.isEmpty())
            {
                return true;
            }
            QList<ks::file::metadata::TargetPatch> patches;
            for (const QString& path : m_filePaths)
            {
                const ks::file::metadata::FileSnapshot snapshot =
                    ks::file::metadata::readFileSnapshot(path);
                if (!snapshot.ok)
                {
                    QMessageBox::warning(
                        this,
                        ks::i18n::sourceText(QStringLiteral("元数据编辑")),
                        ks::i18n::sourceText(QStringLiteral("无法读取目标快照：%1\n%2"))
                            .arg(QDir::toNativeSeparators(path))
                            .arg(formatWin32ErrorText(snapshot.win32Error)));
                    return false;
                }
                ks::file::metadata::TargetPatch patch;
                patch.originalPath = path;
                patch.snapshot = snapshot;
                patches.push_back(patch);
            }
            m_pendingPatches = patches;
            return !m_pendingPatches.isEmpty();
        }

        int pendingOperationCount() const
        {
            int count = 0;
            for (const ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                if (patch.empty()) continue;
                if (patch.basic.updateAttributes ||
                    std::any_of(patch.basic.updateTime.cbegin(), patch.basic.updateTime.cend(),
                        [](const bool value) { return value; })) ++count;
                if (patch.rename) ++count;
                if (patch.setShortName) ++count;
                if (patch.caseSensitive != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (!patch.shellProperties.empty()) ++count;
                count += patch.streams.size();
                count += patch.extendedAttributes.size();
                if (!patch.security.empty()) ++count;
                if (patch.compression != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.sparse != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.encryption != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.integrityStream != ks::file::metadata::ChangeState::Unchanged) ++count;
                if (patch.objectId.update) ++count;
                count += patch.hardLinkPaths.size();
                if (patch.reparse.update) ++count;
                count += patch.peResources.size();
                if (patch.signatureDisposition ==
                    ks::file::metadata::SignatureDisposition::RemoveEmbedded) ++count;
            }
            return count;
        }

        void updatePendingSaveUi()
        {
            const int targetCount = pendingTargetCount();
            const int operationCount = pendingOperationCount();
            if (m_pendingChangesLabel != nullptr)
            {
                m_pendingChangesLabel->setText(targetCount > 0
                    ? ks::i18n::sourceText(QStringLiteral(
                        "● 已暂存：%1 个目标，%2 类操作。文件尚未发生变化。"))
                        .arg(targetCount)
                        .arg(operationCount)
                    : ks::i18n::sourceText(QStringLiteral("● 暂无待保存修改")));
            }
            if (m_saveAllButton != nullptr)
            {
                m_saveAllButton->setEnabled(targetCount > 0 && !m_transactionBusy);
            }
            if (m_discardPendingButton != nullptr)
            {
                m_discardPendingButton->setEnabled(targetCount > 0 && !m_transactionBusy);
            }
        }

        void resetPatchKeepingSnapshot(ks::file::metadata::TargetPatch& patch)
        {
            const QString originalPath = patch.originalPath;
            const ks::file::metadata::FileSnapshot snapshot = patch.snapshot;
            patch = {};
            patch.originalPath = originalPath;
            patch.snapshot = snapshot;
        }

        void discardPendingChanges()
        {
            if (m_transactionBusy)
            {
                return;
            }
            for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                resetPatchKeepingSnapshot(patch);
            }
            m_metadataApplyingSnapshot = true;
            for (QCheckBox* const timeCheck : m_metadataTimeChecks)
            {
                if (timeCheck != nullptr) timeCheck->setChecked(false);
            }
            m_metadataApplyingSnapshot = false;
            m_metadataAttributeTouched.fill(false);
            if (m_metadataStatusLabel != nullptr)
            {
                m_metadataStatusLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("● 已放弃全部暂存修改，文件未发生变化。")));
            }
            updatePendingSaveUi();
            if (m_metadataHasSnapshot)
            {
                QList<ks::file::metadata::FileSnapshot> snapshots;
                for (const ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                {
                    if (patch.snapshot.ok) snapshots.push_back(patch.snapshot);
                }
                applyBatchMetadataSnapshotsToEditor(snapshots);
            }
        }

        static QString transactionOperationText(const QString& operation)
        {
            if (operation == QStringLiteral("identity")) return QStringLiteral("身份复核");
            if (operation == QStringLiteral("backup")) return QStringLiteral("创建备份");
            if (operation == QStringLiteral("backup-required")) return QStringLiteral("备份要求");
            if (operation == QStringLiteral("basic")) return QStringLiteral("基础属性与时间");
            if (operation == QStringLiteral("rename")) return QStringLiteral("重命名");
            if (operation == QStringLiteral("short-name")) return QStringLiteral("8.3 短文件名");
            if (operation == QStringLiteral("case-sensitive")) return QStringLiteral("目录大小写敏感");
            if (operation == QStringLiteral("shell-properties")) return QStringLiteral("Shell 属性");
            if (operation.startsWith(QStringLiteral("ads:"))) return QStringLiteral("ADS：%1").arg(operation.mid(4));
            if (operation.startsWith(QStringLiteral("ea:"))) return QStringLiteral("EA：%1").arg(operation.mid(3));
            if (operation == QStringLiteral("security-sddl")) return QStringLiteral("安全描述符 SDDL");
            if (operation == QStringLiteral("security-ace")) return QStringLiteral("新增或修改 ACE");
            if (operation == QStringLiteral("security-remove-ace")) return QStringLiteral("删除 ACE");
            if (operation == QStringLiteral("compression")) return QStringLiteral("NTFS 压缩");
            if (operation == QStringLiteral("sparse")) return QStringLiteral("稀疏文件");
            if (operation == QStringLiteral("encryption")) return QStringLiteral("EFS 加密");
            if (operation == QStringLiteral("integrity-stream")) return QStringLiteral("Integrity Stream");
            if (operation == QStringLiteral("object-id")) return QStringLiteral("Object ID");
            if (operation.startsWith(QStringLiteral("hard-link:"))) return QStringLiteral("硬链接：%1").arg(operation.mid(10));
            if (operation == QStringLiteral("reparse")) return QStringLiteral("重解析点原始数据");
            if (operation == QStringLiteral("pe-resources")) return QStringLiteral("PE 资源");
            if (operation == QStringLiteral("signature-remove")) return QStringLiteral("清除嵌入式签名");
            if (operation == QStringLiteral("rollback")) return QStringLiteral("失败回滚");
            if (operation == QStringLiteral("readback")) return QStringLiteral("写后回读");
            return operation;
        }

        void showTransactionResults(const ks::file::metadata::TransactionResult& result)
        {
            QDialog* dialog = new QDialog(this);
            dialog->setAttribute(Qt::WA_DeleteOnClose, true);
            dialog->setWindowTitle(ks::i18n::sourceText(QStringLiteral("文件元数据保存结果")));
            dialog->resize(1080, 560);
            QVBoxLayout* layout = new QVBoxLayout(dialog);

            QLabel* summaryLabel = new QLabel(result.ok
                ? ks::i18n::sourceText(QStringLiteral("● 全部目标保存并回读完成。"))
                : ks::i18n::sourceText(QStringLiteral(
                    "● 部分目标保存失败。失败目标已尽可能回滚，请查看逐操作结果。")),
                dialog);
            summaryLabel->setWordWrap(true);
            layout->addWidget(summaryLabel);

            QTableWidget* table = new ks::ui::VisibleTableWidget(dialog);
            table->setColumnCount(6);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("目标"),
                QStringLiteral("操作"),
                QStringLiteral("结果"),
                QStringLiteral("错误"),
                QStringLiteral("详情"),
                QStringLiteral("备份") });
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setAlternatingRowColors(true);
            int rowCount = 0;
            for (const ks::file::metadata::TargetResult& target : result.targets)
            {
                rowCount += target.operations.size();
            }
            table->setRowCount(rowCount);
            int row = 0;
            for (const ks::file::metadata::TargetResult& target : result.targets)
            {
                for (const ks::file::metadata::OperationResult& operation : target.operations)
                {
                    table->setItem(row, 0, new QTableWidgetItem(QDir::toNativeSeparators(target.originalPath)));
                    table->setItem(row, 1, new QTableWidgetItem(transactionOperationText(operation.operation)));
                    table->setItem(row, 2, new QTableWidgetItem(operation.ok
                        ? (operation.verified ? QStringLiteral("成功并验证") : QStringLiteral("成功，未验证"))
                        : QStringLiteral("失败")));
                    table->setItem(row, 3, new QTableWidgetItem(operation.ok
                        ? QStringLiteral("0")
                        : QStringLiteral("%1 · %2")
                            .arg(operation.win32Error)
                            .arg(formatWin32ErrorText(operation.win32Error))));
                    table->setItem(row, 4, new QTableWidgetItem(operation.detail));
                    table->setItem(row, 5, new QTableWidgetItem(QDir::toNativeSeparators(target.backupPath)));
                    ++row;
                }
            }
            installFileTableCopyMenu(table);
            if (table->horizontalHeader() != nullptr)
            {
                table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
                table->horizontalHeader()->setStretchLastSection(true);
            }
            layout->addWidget(table, 1);
            QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
            connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::close);
            layout->addWidget(buttons);
            dialog->show();
        }

        void setTransactionBusy(const bool busy)
        {
            m_transactionBusy = busy;
            if (m_backupBeforeSaveCheck != nullptr) m_backupBeforeSaveCheck->setEnabled(!busy);
            if (m_tabNavigation != nullptr) m_tabNavigation->setEnabled(!busy);
            if (m_tabWidget != nullptr) m_tabWidget->setEnabled(!busy);
            setMetadataEditorBusy(busy);
            updatePendingSaveUi();
        }

        void saveAllPendingChanges()
        {
            if (m_transactionBusy)
            {
                return;
            }
            QList<ks::file::metadata::TargetPatch> patches;
            for (const ks::file::metadata::TargetPatch& patch : m_pendingPatches)
            {
                if (!patch.empty()) patches.push_back(patch);
            }
            if (patches.isEmpty())
            {
                return;
            }

            bool requiresBackup = false;
            bool signedTargetWillChange = false;
            bool hasCatalogSignature = false;
            for (const ks::file::metadata::TargetPatch& patch : patches)
            {
                requiresBackup = requiresBackup || patch.highRisk();
                if (!patch.snapshot.directory)
                {
                    const ks::file::metadata::SignatureInspection signature =
                        ks::file::metadata::inspectSignature(patch.originalPath);
                    signedTargetWillChange = signedTargetWillChange ||
                        signature.embedded || signature.catalog;
                    hasCatalogSignature = hasCatalogSignature || signature.catalog;
                }
            }
            if (requiresBackup &&
                (m_backupBeforeSaveCheck == nullptr || !m_backupBeforeSaveCheck->isChecked()))
            {
                QMessageBox::warning(
                    this,
                    ks::i18n::sourceText(QStringLiteral("必须创建备份")),
                    ks::i18n::sourceText(QStringLiteral(
                        "暂存内容包含高风险操作。EA 原始数据、Object ID、重解析点、PE 资源和签名清除必须勾选“创建备份再修改”。")));
                return;
            }

            if (signedTargetWillChange)
            {
                QMessageBox signaturePrompt(this);
                signaturePrompt.setIcon(QMessageBox::Warning);
                signaturePrompt.setWindowTitle(
                    ks::i18n::sourceText(QStringLiteral("已签名文件将被修改")));
                signaturePrompt.setText(
                    ks::i18n::sourceText(QStringLiteral(
                        "修改已签名文件后，Authenticode 验证可能失效。请选择签名数据处理方式。")) +
                    (hasCatalogSignature
                        ? QLatin1Char('\n') + ks::i18n::sourceText(QStringLiteral(
                            "检测到 Catalog 签名。Catalog 只能显示失效状态，无法从文件本身删除。"))
                        : QString()));
                QPushButton* removeButton = signaturePrompt.addButton(
                    ks::i18n::sourceText(QStringLiteral("清除嵌入式签名并继续")),
                    QMessageBox::AcceptRole);
                QPushButton* preserveButton = signaturePrompt.addButton(
                    ks::i18n::sourceText(QStringLiteral("保留签名数据并继续")),
                    QMessageBox::DestructiveRole);
                QPushButton* cancelButton = signaturePrompt.addButton(
                    QMessageBox::Cancel);
                signaturePrompt.setDefaultButton(cancelButton);
                signaturePrompt.exec();
                if (signaturePrompt.clickedButton() == cancelButton)
                {
                    return;
                }
                if (signaturePrompt.clickedButton() == removeButton)
                {
                    for (ks::file::metadata::TargetPatch& patch : patches)
                    {
                        if (patch.snapshot.embeddedSignature)
                        {
                            patch.signatureDisposition =
                                ks::file::metadata::SignatureDisposition::RemoveEmbedded;
                        }
                    }
                }
                else if (signaturePrompt.clickedButton() != preserveButton)
                {
                    return;
                }
            }

            requiresBackup = std::any_of(
                patches.cbegin(),
                patches.cend(),
                [](const ks::file::metadata::TargetPatch& patch) { return patch.highRisk(); });
            if (requiresBackup &&
                (m_backupBeforeSaveCheck == nullptr || !m_backupBeforeSaveCheck->isChecked()))
            {
                QMessageBox::warning(
                    this,
                    ks::i18n::sourceText(QStringLiteral("必须创建备份")),
                    ks::i18n::sourceText(QStringLiteral(
                        "当前签名处理或高风险修改要求先创建备份。请勾选“创建备份再修改”。")));
                return;
            }

            const QMessageBox::StandardButton confirmation = QMessageBox::question(
                this,
                ks::i18n::sourceText(QStringLiteral("确认保存全部修改")),
                ks::i18n::sourceText(QStringLiteral(
                    "将保存 %1 个目标、%2 类暂存操作。保存前会重新校验文件身份，随后备份、写入并回读。是否继续？"))
                    .arg(patches.size())
                    .arg(pendingOperationCount()),
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No);
            if (confirmation != QMessageBox::Yes)
            {
                return;
            }

            setTransactionBusy(true);
            if (m_pendingChangesLabel != nullptr)
            {
                m_pendingChangesLabel->setText(
                    ks::i18n::sourceText(QStringLiteral("● 正在后台保存、回读并生成逐操作结果...")));
            }
            ks::file::metadata::TransactionOptions options;
            options.createBackup = m_backupBeforeSaveCheck != nullptr &&
                m_backupBeforeSaveCheck->isChecked();
            QPointer<FileDetailDialog> guardThis(this);
            auto* task = QRunnable::create([guardThis, patches, options]()
                {
                    const ks::file::metadata::TransactionResult result =
                        ks::file::metadata::executeTransaction(patches, options);
                    if (guardThis == nullptr) return;
                    QMetaObject::invokeMethod(
                        guardThis.data(),
                        [guardThis, result]()
                        {
                            if (guardThis == nullptr) return;
                            QStringList updatedPaths = guardThis->m_filePaths;
                            for (ks::file::metadata::TargetPatch& pendingPatch : guardThis->m_pendingPatches)
                            {
                                const auto resultIterator = std::find_if(
                                    result.targets.cbegin(),
                                    result.targets.cend(),
                                    [&pendingPatch](const ks::file::metadata::TargetResult& target)
                                    {
                                        return QDir::cleanPath(target.originalPath).compare(
                                            QDir::cleanPath(pendingPatch.originalPath),
                                            Qt::CaseInsensitive) == 0;
                                    });
                                if (resultIterator == result.targets.cend() || !resultIterator->ok)
                                {
                                    continue;
                                }
                                for (QString& path : updatedPaths)
                                {
                                    if (QDir::cleanPath(path).compare(
                                        QDir::cleanPath(pendingPatch.originalPath),
                                        Qt::CaseInsensitive) == 0)
                                    {
                                        path = resultIterator->finalPath;
                                    }
                                }
                                pendingPatch = {};
                                pendingPatch.originalPath = resultIterator->finalPath;
                                pendingPatch.snapshot = resultIterator->finalSnapshot;
                            }
                            guardThis->m_filePaths = updatedPaths;
                            guardThis->m_filePath = updatedPaths.value(0);
                            guardThis->setTransactionBusy(false);
                            guardThis->showTransactionResults(result);
                            guardThis->updatePendingSaveUi();
                            if (result.ok)
                            {
                                guardThis->setWindowTitle(guardThis->m_batchMode
                                    ? ks::i18n::sourceText(QStringLiteral("批量文件属性 - %1 项"))
                                        .arg(guardThis->m_filePaths.size())
                                    : ks::i18n::displayText(QStringLiteral("文件属性 - %1"))
                                        .arg(QFileInfo(guardThis->m_filePath).fileName()));
                                if (guardThis->m_metadataStatusLabel != nullptr)
                                {
                                    guardThis->m_metadataStatusLabel->setText(
                                        ks::i18n::sourceText(QStringLiteral(
                                            "● 所有暂存修改已保存并完成写后回读。")));
                                }
                                guardThis->m_generalR0Loaded = false;
                                if (!guardThis->m_batchMode)
                                {
                                    guardThis->refreshGeneralTab();
                                    const QFileInfo refreshedInfo(guardThis->m_filePath);
                                    guardThis->startR0FileInfoLoad(
                                        refreshedInfo,
                                        guardThis->m_generalNtPathText);
                                }
                            }
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        QWidget* buildDeferredTab(const QString& lazyKey)
        {
            // 用途：创建文件属性窗口的轻量占位页。
            // 处理：只保存 lazyKey 和提示文本，不读取文件、不启动外部进程；
            // 返回：首次切换到该页时由 activateDeferredTab 替换为真实页面。
            QWidget* page = new QWidget(this);
            page->setProperty("ks_file_detail_lazy_key", lazyKey);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QLabel* loadingLabel = new QLabel(page);
            loadingLabel->setWordWrap(true);
            loadingLabel->setText(QStringLiteral(
                "该页面将在首次打开时加载。\n"
                "这样文件属性窗口可以先快速弹出，PE/签名/字符串等重型分析不会阻塞首屏。"));
            layout->addWidget(loadingLabel, 0);
            layout->addStretch(1);
            return page;
        }

        void activateDeferredTab(QTabWidget* tabWidget, const int tabIndex)
        {
            // 用途：首次选中懒加载页时，用真实页面替换占位页。
            // 输入 tabWidget/tabIndex：当前属性窗口 Tab 容器和被激活的索引。
            // 处理：根据 lazyKey 创建对应页面；重型页面内部继续走后台线程。
            // 返回：无；已加载页面不会重复替换。
            if (tabWidget == nullptr || tabIndex < 0)
            {
                return;
            }

            QWidget* placeholderPage = tabWidget->widget(tabIndex);
            if (placeholderPage == nullptr)
            {
                return;
            }
            const QString lazyKey = placeholderPage
                ->property("ks_file_detail_lazy_key")
                .toString()
                .trimmed()
                .toLower();
            if (lazyKey.isEmpty())
            {
                return;
            }

            const QPointer<QTabWidget> tabGuard(tabWidget);
            const QPointer<QWidget> placeholderGuard(placeholderPage);
            ks::ui::scheduleDeferredTabActivation(
                this,
                tabWidget,
                tabIndex,
                placeholderPage,
                [this, tabGuard, placeholderGuard, tabIndex, lazyKey]()
                {
                    if (tabGuard.isNull() || placeholderGuard.isNull() ||
                        tabGuard->currentIndex() != tabIndex ||
                        tabGuard->widget(tabIndex) != placeholderGuard.data())
                    {
                        return;
                    }

                    QWidget* realPage = nullptr;
                    if (lazyKey == QStringLiteral("metadata"))
                    {
                        realPage = buildMetadataTab();
                    }
                    else if (lazyKey == QStringLiteral("security"))
                    {
                        realPage = buildSecurityTab();
                    }
                    else if (lazyKey == QStringLiteral("reparse"))
                    {
                        realPage = buildReparseTab();
                    }
                    else if (lazyKey == QStringLiteral("usage"))
                    {
                        realPage = buildUsageTab();
                    }
                    else if (lazyKey == QStringLiteral("fileobject"))
                    {
                        realPage = buildFileObjectTab();
                    }
                    else if (lazyKey == QStringLiteral("storage"))
                    {
                        realPage = buildStorageTab();
                    }
                    else if (lazyKey == QStringLiteral("filters"))
                    {
                        realPage = buildFilterTopologyTab();
                    }
                    else if (lazyKey == QStringLiteral("signature"))
                    {
                        realPage = buildSignatureTab();
                    }
                    else if (lazyKey == QStringLiteral("pe"))
                    {
                        realPage = buildPeTab();
                    }
                    else if (lazyKey == QStringLiteral("dependencies"))
                    {
                        realPage = buildDependencyTab();
                    }
                    else if (lazyKey == QStringLiteral("strings"))
                    {
                        realPage = buildStringsTab();
                    }
                    else if (lazyKey == QStringLiteral("hex"))
                    {
                        realPage = buildHexTab();
                    }

                    if (realPage == nullptr || tabGuard.isNull() || placeholderGuard.isNull() ||
                        tabGuard->widget(tabIndex) != placeholderGuard.data())
                    {
                        if (realPage != nullptr)
                        {
                            realPage->deleteLater();
                        }
                        return;
                    }

                    const QString titleText = tabGuard->tabText(tabIndex);
                    tabGuard->removeTab(tabIndex);
                    tabGuard->insertTab(tabIndex, realPage, titleText);
                    // 新建的懒加载页也必须立即拿到 Surface 调色板，不能回退到系统 Base。
                    applyThemeStyle();
                    tabGuard->setCurrentIndex(tabIndex);
                    placeholderGuard->deleteLater();
                });
        }

        QWidget* buildGeneralTab()
        {
            if (m_batchMode)
            {
                QWidget* page = new QWidget(this);
                QVBoxLayout* layout = new QVBoxLayout(page);
                quint64 totalSize = 0U;
                int fileCount = 0;
                int directoryCount = 0;
                QTableWidget* table = new ks::ui::VisibleTableWidget(page);
                table->setColumnCount(6);
                table->setHorizontalHeaderLabels(QStringList{
                    QStringLiteral("路径"),
                    QStringLiteral("类型"),
                    QStringLiteral("大小"),
                    QStringLiteral("属性"),
                    QStringLiteral("最后修改"),
                    QStringLiteral("状态") });
                table->setRowCount(m_filePaths.size());
                table->setSelectionBehavior(QAbstractItemView::SelectRows);
                table->setSelectionMode(QAbstractItemView::ExtendedSelection);
                table->setEditTriggers(QAbstractItemView::NoEditTriggers);
                table->setAlternatingRowColors(true);
                for (qsizetype row = 0; row < m_filePaths.size(); ++row)
                {
                    const QString path = m_filePaths.at(row);
                    const QFileInfo info(path);
                    const bool exists = info.exists();
                    if (exists && info.isDir()) ++directoryCount;
                    if (exists && info.isFile())
                    {
                        ++fileCount;
                        totalSize += static_cast<quint64>(std::max<qint64>(0, info.size()));
                    }
                    const std::wstring nativePathText = QDir::toNativeSeparators(path).toStdWString();
                    const DWORD attributes = ::GetFileAttributesW(nativePathText.c_str());
                    table->setItem(static_cast<int>(row), 0,
                        new QTableWidgetItem(QDir::toNativeSeparators(path)));
                    table->setItem(static_cast<int>(row), 1,
                        new QTableWidgetItem(info.isDir()
                            ? QStringLiteral("目录")
                            : (info.isFile() ? QStringLiteral("文件") : QStringLiteral("其它"))));
                    table->setItem(static_cast<int>(row), 2,
                        new QTableWidgetItem(info.isFile()
                            ? formatFileSizeText(static_cast<qulonglong>(std::max<qint64>(0, info.size())))
                            : QStringLiteral("-")));
                    table->setItem(static_cast<int>(row), 3,
                        new QTableWidgetItem(attributes == INVALID_FILE_ATTRIBUTES
                            ? QStringLiteral("-")
                            : fileAttributesToText(attributes)));
                    table->setItem(static_cast<int>(row), 4,
                        new QTableWidgetItem(info.lastModified().isValid()
                            ? info.lastModified().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                            : QStringLiteral("-")));
                    table->setItem(static_cast<int>(row), 5,
                        new QTableWidgetItem(exists ? QStringLiteral("可访问") : QStringLiteral("不存在或不可访问")));
                }
                QLabel* summary = new QLabel(
                    ks::i18n::sourceText(QStringLiteral(
                        "已选择 %1 项：文件 %2，目录 %3，文件总大小 %4。"))
                        .arg(m_filePaths.size())
                        .arg(fileCount)
                        .arg(directoryCount)
                        .arg(formatFileSizeText(totalSize)),
                    page);
                summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
                layout->addWidget(summary);
                installFileTableCopyMenu(table);
                if (table->horizontalHeader() != nullptr)
                {
                    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
                    table->horizontalHeader()->setStretchLastSection(true);
                }
                layout->addWidget(table, 1);
                return page;
            }

            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            // 常规页原本是一整块只读文本：属性名和值靠冒号对齐，取一条路径要手工划选，
            // 超长值只能左右找，属性位还被压成一个 A|B|C 串。改成两列属性树后，
            // 每条属性是独立一行，可单独复制，分组可折叠，值列还能悬停看全。
            // 文本视图并未废弃，只是移到右上角切换框后面：整段复制和全文检索仍然需要它。
            m_generalPropertyTree = new QTreeWidget(page);
            configurePropertyTree(m_generalPropertyTree);
            m_generalTextEditor = new CodeEditorWidget(page);
            m_generalTextEditor->setReadOnly(true);
            // 常规页的属性树是从 R0 返回的结构体逐字段搭出来的：带分组、十六进制格式化和
            // 属性位展开，比解析纯文本得到的结果更准。所以这页保留自己的切换框，
            // 关掉文本控件内置的那套结构视图，避免同一页出现两个入口、两种解析口径。
            m_generalTextEditor->setStructuredReportViewEnabled(false);

            const QFileInfo info(m_filePath);
            m_generalNtPathText = buildDriverNtPath(info.absoluteFilePath());
            m_generalR0Loaded = false;
            m_generalR0Info = {};
            refreshGeneralTab();

            layout->addWidget(
                buildSwitchableView(page, m_generalPropertyTree, m_generalTextEditor), 1);
            startR0FileInfoLoad(info, m_generalNtPathText);
            return page;
        }

        static QComboBox* buildChangeStateCombo(QWidget* parent)
        {
            QComboBox* combo = new QComboBox(parent);
            combo->addItem(QStringLiteral("不修改"),
                static_cast<int>(ks::file::metadata::ChangeState::Unchanged));
            combo->addItem(QStringLiteral("启用"),
                static_cast<int>(ks::file::metadata::ChangeState::Enabled));
            combo->addItem(QStringLiteral("禁用"),
                static_cast<int>(ks::file::metadata::ChangeState::Disabled));
            return combo;
        }

        static ks::file::metadata::ChangeState changeStateFromCombo(const QComboBox* combo)
        {
            return combo == nullptr
                ? ks::file::metadata::ChangeState::Unchanged
                : static_cast<ks::file::metadata::ChangeState>(combo->currentData().toInt());
        }

        static QByteArray parseMetadataHexText(const QString& text, bool* okOut)
        {
            QString normalized = text;
            normalized.remove(QRegularExpression(QStringLiteral("[^0-9A-Fa-f]")));
            const bool valid = (normalized.size() % 2) == 0;
            if (okOut != nullptr) *okOut = valid;
            return valid ? QByteArray::fromHex(normalized.toLatin1()) : QByteArray();
        }

        static QByteArray metadataEditorBytes(
            const QPlainTextEdit* editor,
            const QComboBox* formatCombo,
            bool* okOut)
        {
            if (editor == nullptr)
            {
                if (okOut != nullptr) *okOut = false;
                return {};
            }
            if (formatCombo != nullptr && formatCombo->currentIndex() == 1)
            {
                return parseMetadataHexText(editor->toPlainText(), okOut);
            }
            if (okOut != nullptr) *okOut = true;
            return editor->toPlainText().toUtf8();
        }

        void refreshMetadataStreamTable(QTableWidget* table)
        {
            if (table == nullptr) return;
            table->setRowCount(0);
            const QStringList paths = m_filePaths;
            QPointer<QTableWidget> tableGuard(table);
            auto* task = QRunnable::create([tableGuard, paths]()
                {
                    QList<QStringList> rows;
                    for (const QString& path : paths)
                    {
                        DWORD error = ERROR_SUCCESS;
                        const QList<ks::file::metadata::StreamEntry> streams =
                            ks::file::metadata::enumerateStreams(path, &error);
                        if (error != ERROR_SUCCESS)
                        {
                            rows.push_back(QStringList{
                                path,
                                QStringLiteral("<读取失败>"),
                                QString::number(error) });
                            continue;
                        }
                        for (const ks::file::metadata::StreamEntry& stream : streams)
                        {
                            rows.push_back(QStringList{
                                path,
                                stream.name,
                                QString::number(stream.size) });
                        }
                    }
                    if (tableGuard == nullptr) return;
                    QMetaObject::invokeMethod(tableGuard.data(), [tableGuard, rows]()
                        {
                            if (tableGuard == nullptr) return;
                            tableGuard->setRowCount(rows.size());
                            for (qsizetype row = 0; row < rows.size(); ++row)
                            {
                                const QStringList values = rows.at(row);
                                for (int column = 0; column < values.size(); ++column)
                                {
                                    tableGuard->setItem(static_cast<int>(row), column,
                                        new QTableWidgetItem(values.at(column)));
                                }
                            }
                        }, Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        void refreshMetadataEaTable(QTableWidget* table)
        {
            if (table == nullptr) return;
            table->setRowCount(0);
            const QStringList paths = m_filePaths;
            QPointer<QTableWidget> tableGuard(table);
            auto* task = QRunnable::create([tableGuard, paths]()
                {
                    QList<QStringList> rows;
                    for (const QString& path : paths)
                    {
                        DWORD error = ERROR_SUCCESS;
                        const QList<ks::file::metadata::ExtendedAttributeEntry> entries =
                            ks::file::metadata::enumerateExtendedAttributes(path, &error);
                        if (error != ERROR_SUCCESS)
                        {
                            rows.push_back(QStringList{
                                path,
                                QStringLiteral("<读取失败>"),
                                QString::number(error),
                                QString() });
                            continue;
                        }
                        for (const ks::file::metadata::ExtendedAttributeEntry& entry : entries)
                        {
                            rows.push_back(QStringList{
                                path,
                                entry.name,
                                QString::number(entry.value.size()),
                                QString::fromLatin1(entry.value.left(64).toHex(' ').toUpper()) });
                        }
                    }
                    if (tableGuard == nullptr) return;
                    QMetaObject::invokeMethod(tableGuard.data(), [tableGuard, rows]()
                        {
                            if (tableGuard == nullptr) return;
                            tableGuard->setRowCount(rows.size());
                            for (qsizetype row = 0; row < rows.size(); ++row)
                            {
                                const QStringList values = rows.at(row);
                                for (int column = 0; column < values.size(); ++column)
                                {
                                    tableGuard->setItem(static_cast<int>(row), column,
                                        new QTableWidgetItem(values.at(column)));
                                }
                            }
                        }, Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        QWidget* buildMetadataNameAndFilesystemPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QFormLayout* form = new QFormLayout();

            QCheckBox* renameCheck = new QCheckBox(QStringLiteral("暂存重命名"), page);
            QLineEdit* renameEdit = new QLineEdit(page);
            renameEdit->setText(m_batchMode ? QString() : QFileInfo(m_filePath).fileName());
            renameEdit->setEnabled(!m_batchMode);
            renameCheck->setEnabled(!m_batchMode);
            form->addRow(renameCheck, renameEdit);

            QCheckBox* shortNameCheck = new QCheckBox(QStringLiteral("设置 8.3 短文件名"), page);
            QLineEdit* shortNameEdit = new QLineEdit(page);
            shortNameEdit->setPlaceholderText(QStringLiteral("例如 SAMPLE~1.TXT；留空可清除短名"));
            shortNameEdit->setEnabled(!m_batchMode);
            shortNameCheck->setEnabled(!m_batchMode);
            form->addRow(shortNameCheck, shortNameEdit);

            QComboBox* caseSensitiveCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("目录大小写敏感"), caseSensitiveCombo);
            QComboBox* compressionCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("NTFS 压缩"), compressionCombo);
            QComboBox* sparseCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("稀疏文件"), sparseCombo);
            QComboBox* encryptionCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("EFS 加密"), encryptionCombo);
            QComboBox* integrityCombo = buildChangeStateCombo(page);
            form->addRow(QStringLiteral("Integrity Stream"), integrityCombo);

            QComboBox* objectIdAction = new QComboBox(page);
            objectIdAction->addItems(QStringList{
                QStringLiteral("不修改"),
                QStringLiteral("设置 Object ID"),
                QStringLiteral("删除 Object ID") });
            QLineEdit* objectIdEdit = new QLineEdit(page);
            objectIdEdit->setPlaceholderText(QStringLiteral("16 字节或完整 64 字节十六进制"));
            QHBoxLayout* objectIdLayout = new QHBoxLayout();
            objectIdLayout->addWidget(objectIdAction);
            objectIdLayout->addWidget(objectIdEdit, 1);
            form->addRow(QStringLiteral("Object ID"), objectIdLayout);

            QPlainTextEdit* hardLinksEdit = new QPlainTextEdit(page);
            hardLinksEdit->setPlaceholderText(QStringLiteral("每行一个要创建的硬链接完整路径；仅单文件模式可用"));
            hardLinksEdit->setMaximumHeight(70);
            hardLinksEdit->setEnabled(!m_batchMode);
            form->addRow(QStringLiteral("新增硬链接"), hardLinksEdit);
            layout->addLayout(form);

            QHBoxLayout* hardLinkQueryLayout = new QHBoxLayout();
            QPushButton* queryHardLinksButton = new QPushButton(QStringLiteral("枚举现有硬链接"), page);
            QLabel* hardLinkQueryResult = new QLabel(QStringLiteral("-"), page);
            hardLinkQueryResult->setTextInteractionFlags(Qt::TextSelectableByMouse);
            hardLinkQueryResult->setWordWrap(true);
            queryHardLinksButton->setEnabled(!m_batchMode);
            hardLinkQueryLayout->addWidget(queryHardLinksButton);
            hardLinkQueryLayout->addWidget(hardLinkQueryResult, 1);
            layout->addLayout(hardLinkQueryLayout);

            QLabel* hint = new QLabel(QStringLiteral(
                "压缩、稀疏、EFS、Integrity Stream、Object ID 均通过公开 Win32/FSCTL 在 R3 完成。"
                "文件长度、有效数据长度、分配大小仍保持只读。"), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存名称与文件系统修改"), page);
            layout->addWidget(stageButton, 0, Qt::AlignRight);
            layout->addStretch(1);

            connect(queryHardLinksButton, &QPushButton::clicked, this,
                [this, hardLinkQueryResult]()
                {
                    DWORD error = ERROR_SUCCESS;
                    const QStringList links = ks::file::metadata::enumerateHardLinks(m_filePath, &error);
                    hardLinkQueryResult->setText(error == ERROR_SUCCESS
                        ? links.join(QStringLiteral(" | "))
                        : QStringLiteral("枚举失败：%1").arg(formatWin32ErrorText(error)));
                });

            connect(stageButton, &QPushButton::clicked, this,
                [this, renameCheck, renameEdit, shortNameCheck, shortNameEdit,
                 caseSensitiveCombo, compressionCombo, sparseCombo, encryptionCombo,
                 integrityCombo, objectIdAction, objectIdEdit, hardLinksEdit]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QByteArray objectIdBytes;
                    if (objectIdAction->currentIndex() == 1)
                    {
                        bool objectIdOk = false;
                        objectIdBytes = parseMetadataHexText(objectIdEdit->text(), &objectIdOk);
                        if (!objectIdOk || (objectIdBytes.size() != 16 && objectIdBytes.size() != 64))
                        {
                            QMessageBox::warning(this, QStringLiteral("Object ID"),
                                QStringLiteral("Object ID 必须是 16 字节或完整 64 字节十六进制。"));
                            return;
                        }
                    }
                    const QStringList hardLinkPaths = hardLinksEdit->toPlainText()
                        .split(QRegularExpression(QStringLiteral("[\\r\\n]+")), Qt::SkipEmptyParts);
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.rename = !m_batchMode && renameCheck->isChecked();
                        patch.newName = renameEdit->text().trimmed();
                        patch.setShortName = !m_batchMode && shortNameCheck->isChecked();
                        patch.shortName = shortNameEdit->text().trimmed();
                        patch.caseSensitive = patch.snapshot.directory
                            ? changeStateFromCombo(caseSensitiveCombo)
                            : ks::file::metadata::ChangeState::Unchanged;
                        patch.compression = changeStateFromCombo(compressionCombo);
                        patch.sparse = patch.snapshot.directory
                            ? ks::file::metadata::ChangeState::Unchanged
                            : changeStateFromCombo(sparseCombo);
                        patch.encryption = changeStateFromCombo(encryptionCombo);
                        patch.integrityStream = changeStateFromCombo(integrityCombo);
                        patch.objectId.update = objectIdAction->currentIndex() != 0;
                        patch.objectId.remove = objectIdAction->currentIndex() == 2;
                        patch.objectId.objectId = objectIdBytes;
                        patch.hardLinkPaths = m_batchMode ? QStringList() : hardLinkPaths;
                    }
                    updatePendingSaveUi();
                });
            return page;
        }

        QWidget* buildMetadataShellPropertyPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QGridLayout* grid = new QGridLayout();
            struct ShellRow
            {
                QCheckBox* update = nullptr;
                QLineEdit* editor = nullptr;
            };
            const QStringList labels{
                QStringLiteral("标题"),
                QStringLiteral("主题"),
                QStringLiteral("作者（分号分隔）"),
                QStringLiteral("标签 / 关键字（分号分隔）"),
                QStringLiteral("注释"),
                QStringLiteral("版权") };
            std::array<ShellRow, 6> rows{};
            for (int index = 0; index < static_cast<int>(rows.size()); ++index)
            {
                rows[static_cast<std::size_t>(index)].update =
                    new QCheckBox(QStringLiteral("修改"), page);
                rows[static_cast<std::size_t>(index)].editor = new QLineEdit(page);
                grid->addWidget(rows[static_cast<std::size_t>(index)].update, index, 0);
                grid->addWidget(new QLabel(labels.at(index), page), index, 1);
                grid->addWidget(rows[static_cast<std::size_t>(index)].editor, index, 2);
            }
            QCheckBox* ratingCheck = new QCheckBox(QStringLiteral("修改"), page);
            QSpinBox* ratingSpin = new QSpinBox(page);
            ratingSpin->setRange(0, 99);
            grid->addWidget(ratingCheck, 6, 0);
            grid->addWidget(new QLabel(QStringLiteral("评分（0-99）"), page), 6, 1);
            grid->addWidget(ratingSpin, 6, 2);
            grid->setColumnStretch(2, 1);
            layout->addLayout(grid);

            QLabel* status = new QLabel(QStringLiteral("可从第一个目标读取当前 Shell 属性。"), page);
            status->setWordWrap(true);
            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取当前值"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 Shell 属性"), page);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addWidget(status);
            layout->addLayout(actions);
            layout->addStretch(1);

            connect(loadButton, &QPushButton::clicked, this, [this, rows, ratingSpin, status]()
                {
                    status->setText(QStringLiteral("● 正在后台读取 Shell 属性..."));
                    const QString path = m_filePath;
                    QPointer<FileDetailDialog> dialogGuard(this);
                    QPointer<QLabel> statusGuard(status);
                    auto* task = QRunnable::create([dialogGuard, statusGuard, path, rows, ratingSpin]()
                        {
                            const ks::file::metadata::ShellProperties properties =
                                ks::file::metadata::readShellProperties(path);
                            if (dialogGuard == nullptr) return;
                            QMetaObject::invokeMethod(dialogGuard.data(),
                                [dialogGuard, statusGuard, properties, rows, ratingSpin]()
                                {
                                    if (dialogGuard == nullptr || statusGuard == nullptr) return;
                                    if (!properties.ok)
                                    {
                                        statusGuard->setText(QStringLiteral("● Shell 属性读取失败：%1")
                                            .arg(formatWin32ErrorText(properties.win32Error)));
                                        return;
                                    }
                                    const QStringList values{
                                        properties.title,
                                        properties.subject,
                                        properties.authors.join(QStringLiteral("; ")),
                                        properties.keywords.join(QStringLiteral("; ")),
                                        properties.comment,
                                        properties.copyright };
                                    for (int index = 0; index < values.size(); ++index)
                                    {
                                        if (rows[static_cast<std::size_t>(index)].editor != nullptr)
                                        {
                                            rows[static_cast<std::size_t>(index)].editor->setText(values.at(index));
                                        }
                                    }
                                    ratingSpin->setValue(static_cast<int>(properties.rating));
                                    statusGuard->setText(QStringLiteral("● 已读取第一个目标的当前值。"));
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                });
            connect(stageButton, &QPushButton::clicked, this, [this, rows, ratingCheck, ratingSpin, status]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        auto& shell = patch.shellProperties;
                        shell.updateTitle = rows[0].update->isChecked();
                        shell.title = rows[0].editor->text();
                        shell.updateSubject = rows[1].update->isChecked();
                        shell.subject = rows[1].editor->text();
                        shell.updateAuthors = rows[2].update->isChecked();
                        shell.authors = rows[2].editor->text().split(QLatin1Char(';'), Qt::SkipEmptyParts);
                        shell.updateKeywords = rows[3].update->isChecked();
                        shell.keywords = rows[3].editor->text().split(QLatin1Char(';'), Qt::SkipEmptyParts);
                        shell.updateComment = rows[4].update->isChecked();
                        shell.comment = rows[4].editor->text();
                        shell.updateCopyright = rows[5].update->isChecked();
                        shell.copyright = rows[5].editor->text();
                        shell.updateRating = ratingCheck->isChecked();
                        shell.rating = static_cast<quint32>(ratingSpin->value());
                    }
                    status->setText(QStringLiteral("● Shell 属性已暂存。"));
                    updatePendingSaveUi();
                });
            return page;
        }

        QWidget* buildMetadataAdsPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QTableWidget* table = new ks::ui::VisibleTableWidget(page);
            table->setColumnCount(3);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("目标"), QStringLiteral("数据流"), QStringLiteral("字节数") });
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            installFileTableCopyMenu(table);
            layout->addWidget(table, 1);

            QGridLayout* editorLayout = new QGridLayout();
            QLineEdit* nameEdit = new QLineEdit(page);
            nameEdit->setPlaceholderText(QStringLiteral("例如 Zone.Identifier"));
            QComboBox* formatCombo = new QComboBox(page);
            formatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            QCheckBox* removeCheck = new QCheckBox(QStringLiteral("删除该数据流"), page);
            QPlainTextEdit* dataEdit = new QPlainTextEdit(page);
            dataEdit->setMaximumHeight(120);
            editorLayout->addWidget(new QLabel(QStringLiteral("流名称"), page), 0, 0);
            editorLayout->addWidget(nameEdit, 0, 1);
            editorLayout->addWidget(formatCombo, 0, 2);
            editorLayout->addWidget(removeCheck, 0, 3);
            editorLayout->addWidget(dataEdit, 1, 0, 1, 4);
            layout->addLayout(editorLayout);

            QGroupBox* zoneGroup = new QGroupBox(QStringLiteral("Zone.Identifier 结构化编辑"), page);
            QFormLayout* zoneLayout = new QFormLayout(zoneGroup);
            QSpinBox* zoneIdSpin = new QSpinBox(zoneGroup);
            zoneIdSpin->setRange(0, 4);
            zoneIdSpin->setValue(3);
            QLineEdit* referrerEdit = new QLineEdit(zoneGroup);
            QLineEdit* hostEdit = new QLineEdit(zoneGroup);
            QPushButton* buildZoneButton = new QPushButton(QStringLiteral("生成结构化内容"), zoneGroup);
            zoneLayout->addRow(QStringLiteral("ZoneId"), zoneIdSpin);
            zoneLayout->addRow(QStringLiteral("ReferrerUrl"), referrerEdit);
            zoneLayout->addRow(QStringLiteral("HostUrl"), hostEdit);
            zoneLayout->addRow(QString(), buildZoneButton);
            layout->addWidget(zoneGroup);

            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新数据流"), page);
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取选中流"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 ADS 操作"), page);
            actions->addWidget(refreshButton);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);

            connect(refreshButton, &QPushButton::clicked, this,
                [this, table]() { refreshMetadataStreamTable(table); });
            connect(buildZoneButton, &QPushButton::clicked, this,
                [nameEdit, formatCombo, dataEdit, zoneIdSpin, referrerEdit, hostEdit]()
                {
                    nameEdit->setText(QStringLiteral("Zone.Identifier"));
                    formatCombo->setCurrentIndex(0);
                    QString content = QStringLiteral("[ZoneTransfer]\r\nZoneId=%1\r\n")
                        .arg(zoneIdSpin->value());
                    if (!referrerEdit->text().trimmed().isEmpty())
                        content += QStringLiteral("ReferrerUrl=%1\r\n").arg(referrerEdit->text().trimmed());
                    if (!hostEdit->text().trimmed().isEmpty())
                        content += QStringLiteral("HostUrl=%1\r\n").arg(hostEdit->text().trimmed());
                    dataEdit->setPlainText(content);
                });
            connect(loadButton, &QPushButton::clicked, this, [this, table, nameEdit, formatCombo, dataEdit]()
                {
                    const int row = table->currentRow();
                    if (row < 0 || table->item(row, 0) == nullptr || table->item(row, 1) == nullptr) return;
                    const QString path = table->item(row, 0)->text();
                    const QString name = table->item(row, 1)->text();
                    nameEdit->setText(name);
                    DWORD error = ERROR_SUCCESS;
                    const QByteArray data = ks::file::metadata::readStream(path, name, &error);
                    if (error != ERROR_SUCCESS)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"),
                            QStringLiteral("读取数据流失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    const bool printable = std::all_of(data.cbegin(), data.cend(), [](const char value)
                        {
                            const unsigned char byte = static_cast<unsigned char>(value);
                            return byte == '\r' || byte == '\n' || byte == '\t' || byte >= 0x20U;
                        });
                    formatCombo->setCurrentIndex(printable ? 0 : 1);
                    dataEdit->setPlainText(printable
                        ? QString::fromUtf8(data)
                        : QString::fromLatin1(data.toHex(' ').toUpper()));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, nameEdit, formatCombo, removeCheck, dataEdit]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QString name = nameEdit->text().trimmed();
                    if (name.startsWith(QLatin1Char(':'))) name.remove(0, 1);
                    if (name.endsWith(QStringLiteral(":$DATA"), Qt::CaseInsensitive)) name.chop(6);
                    if (name.isEmpty() || name.compare(QStringLiteral("$DATA"), Qt::CaseInsensitive) == 0)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"),
                            QStringLiteral("默认数据流保持只读。请输入命名数据流名称。"));
                        return;
                    }
                    bool dataOk = true;
                    const QByteArray data = removeCheck->isChecked()
                        ? QByteArray()
                        : metadataEditorBytes(dataEdit, formatCombo, &dataOk);
                    if (!dataOk)
                    {
                        QMessageBox::warning(this, QStringLiteral("ADS"), QStringLiteral("十六进制数据格式无效。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.streams.erase(std::remove_if(patch.streams.begin(), patch.streams.end(),
                            [&name](const ks::file::metadata::NamedBinaryPatch& item)
                            {
                                return item.name.compare(name, Qt::CaseInsensitive) == 0;
                            }), patch.streams.end());
                        ks::file::metadata::NamedBinaryPatch stream;
                        stream.name = name;
                        stream.action = removeCheck->isChecked()
                            ? ks::file::metadata::BinaryPatchAction::Remove
                            : ks::file::metadata::BinaryPatchAction::Replace;
                        stream.data = data;
                        patch.streams.push_back(stream);
                    }
                    updatePendingSaveUi();
                });
            QMetaObject::invokeMethod(page, [this, table]() { refreshMetadataStreamTable(table); },
                Qt::QueuedConnection);
            return page;
        }

        QWidget* buildMetadataEaPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QTableWidget* table = new ks::ui::VisibleTableWidget(page);
            table->setColumnCount(4);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("目标"), QStringLiteral("EA 名称"),
                QStringLiteral("字节数"), QStringLiteral("值预览") });
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            installFileTableCopyMenu(table);
            layout->addWidget(table, 1);

            QLineEdit* nameEdit = new QLineEdit(page);
            nameEdit->setPlaceholderText(QStringLiteral("EA 名称，最长 255 字节"));
            QComboBox* formatCombo = new QComboBox(page);
            formatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            QCheckBox* needEaCheck = new QCheckBox(QStringLiteral("FILE_NEED_EA"), page);
            QCheckBox* removeCheck = new QCheckBox(QStringLiteral("删除该 EA"), page);
            QPlainTextEdit* dataEdit = new QPlainTextEdit(page);
            dataEdit->setMaximumHeight(120);
            QHBoxLayout* header = new QHBoxLayout();
            header->addWidget(nameEdit, 1);
            header->addWidget(formatCombo);
            header->addWidget(needEaCheck);
            header->addWidget(removeCheck);
            layout->addLayout(header);
            layout->addWidget(dataEdit);

            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新 EA"), page);
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取选中 EA"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存 EA 操作"), page);
            actions->addWidget(refreshButton);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);
            connect(refreshButton, &QPushButton::clicked, this,
                [this, table]() { refreshMetadataEaTable(table); });
            connect(loadButton, &QPushButton::clicked, this,
                [this, table, nameEdit, formatCombo, dataEdit, needEaCheck]()
                {
                    const int row = table->currentRow();
                    if (row < 0 || table->item(row, 0) == nullptr || table->item(row, 1) == nullptr) return;
                    DWORD error = ERROR_SUCCESS;
                    const auto entries = ks::file::metadata::enumerateExtendedAttributes(
                        table->item(row, 0)->text(), &error);
                    const QString name = table->item(row, 1)->text();
                    const auto iterator = std::find_if(entries.cbegin(), entries.cend(),
                        [&name](const ks::file::metadata::ExtendedAttributeEntry& item)
                        {
                            return item.name == name;
                        });
                    if (error != ERROR_SUCCESS || iterator == entries.cend())
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"),
                            QStringLiteral("读取 EA 失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    nameEdit->setText(iterator->name);
                    needEaCheck->setChecked(iterator->needEa);
                    formatCombo->setCurrentIndex(1);
                    dataEdit->setPlainText(QString::fromLatin1(iterator->value.toHex(' ').toUpper()));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, nameEdit, formatCombo, dataEdit, needEaCheck, removeCheck]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    const QString name = nameEdit->text().trimmed();
                    if (name.isEmpty() || name.toUtf8().size() > 255)
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"), QStringLiteral("EA 名称无效。"));
                        return;
                    }
                    bool dataOk = true;
                    const QByteArray data = removeCheck->isChecked()
                        ? QByteArray()
                        : metadataEditorBytes(dataEdit, formatCombo, &dataOk);
                    if (!dataOk || data.size() > 65535)
                    {
                        QMessageBox::warning(this, QStringLiteral("EA"),
                            QStringLiteral("EA 值必须是不超过 65535 字节的有效数据。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.extendedAttributes.erase(
                            std::remove_if(patch.extendedAttributes.begin(), patch.extendedAttributes.end(),
                                [&name](const ks::file::metadata::NamedBinaryPatch& item)
                                {
                                    return item.name.compare(name, Qt::CaseInsensitive) == 0;
                                }),
                            patch.extendedAttributes.end());
                        ks::file::metadata::NamedBinaryPatch ea;
                        ea.name = name;
                        ea.needEa = needEaCheck->isChecked();
                        ea.action = removeCheck->isChecked()
                            ? ks::file::metadata::BinaryPatchAction::Remove
                            : ks::file::metadata::BinaryPatchAction::Replace;
                        ea.data = data;
                        patch.extendedAttributes.push_back(ea);
                    }
                    updatePendingSaveUi();
                });
            QMetaObject::invokeMethod(page, [this, table]() { refreshMetadataEaTable(table); },
                Qt::QueuedConnection);
            return page;
        }

        QWidget* buildMetadataSecurityPage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QLabel* hint = new QLabel(QStringLiteral(
                "可编辑 Owner、Primary Group、DACL、SACL、Mandatory Integrity 与继承保护。"
                "SDDL 会在保存事务中通过 Windows 安全 API 写入。"), page);
            hint->setWordWrap(true);
            layout->addWidget(hint);
            QPlainTextEdit* sddlEdit = new QPlainTextEdit(page);
            sddlEdit->setPlaceholderText(QStringLiteral("例如 O:...G:...D:...S:..."));
            layout->addWidget(sddlEdit, 1);
            QHBoxLayout* scopes = new QHBoxLayout();
            QCheckBox* ownerCheck = new QCheckBox(QStringLiteral("Owner"), page);
            QCheckBox* groupCheck = new QCheckBox(QStringLiteral("Primary Group"), page);
            QCheckBox* daclCheck = new QCheckBox(QStringLiteral("DACL"), page);
            QCheckBox* saclCheck = new QCheckBox(QStringLiteral("SACL / Mandatory Label"), page);
            QCheckBox* protectDaclCheck = new QCheckBox(QStringLiteral("保护 DACL 继承"), page);
            QCheckBox* protectSaclCheck = new QCheckBox(QStringLiteral("保护 SACL 继承"), page);
            daclCheck->setChecked(true);
            scopes->addWidget(ownerCheck);
            scopes->addWidget(groupCheck);
            scopes->addWidget(daclCheck);
            scopes->addWidget(saclCheck);
            scopes->addWidget(protectDaclCheck);
            scopes->addWidget(protectSaclCheck);
            scopes->addStretch(1);
            layout->addLayout(scopes);
            QHBoxLayout* effectiveLayout = new QHBoxLayout();
            QLineEdit* effectiveTrusteeEdit = new QLineEdit(page);
            effectiveTrusteeEdit->setPlaceholderText(QStringLiteral(
                "账户或 SID，例如 BUILTIN\\Users / Everyone / S-1-5-32-545"));
            QPushButton* effectiveButton = new QPushButton(QStringLiteral("检查有效权限"), page);
            QLabel* effectiveResult = new QLabel(QStringLiteral("Mask: -"), page);
            effectiveResult->setTextInteractionFlags(Qt::TextSelectableByMouse);
            effectiveLayout->addWidget(effectiveTrusteeEdit, 1);
            effectiveLayout->addWidget(effectiveButton);
            effectiveLayout->addWidget(effectiveResult);
            layout->addLayout(effectiveLayout);
            QLabel* status = new QLabel(QStringLiteral("可从第一个目标读取 Owner、Group 与 DACL SDDL。"), page);
            status->setWordWrap(true);
            layout->addWidget(status);
            QHBoxLayout* actions = new QHBoxLayout();
            QPushButton* loadButton = new QPushButton(QStringLiteral("读取当前 SDDL"), page);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存安全描述符"), page);
            actions->addWidget(loadButton);
            actions->addStretch(1);
            actions->addWidget(stageButton);
            layout->addLayout(actions);
            connect(loadButton, &QPushButton::clicked, this, [this, sddlEdit, status]()
                {
                    status->setText(QStringLiteral("● 正在后台读取安全描述符..."));
                    const QString path = m_filePath;
                    QPointer<QPlainTextEdit> editorGuard(sddlEdit);
                    QPointer<QLabel> statusGuard(status);
                    auto* task = QRunnable::create([path, editorGuard, statusGuard]()
                        {
                            DWORD error = ERROR_SUCCESS;
                            const QString sddl =
                                ks::file::metadata::readSecurityDescriptorSddl(path, &error);
                            if (editorGuard == nullptr || statusGuard == nullptr) return;
                            QMetaObject::invokeMethod(editorGuard.data(),
                                [editorGuard, statusGuard, sddl, error]()
                                {
                                    if (editorGuard == nullptr || statusGuard == nullptr) return;
                                    if (error != ERROR_SUCCESS)
                                    {
                                        statusGuard->setText(QStringLiteral("● SDDL 读取失败：%1")
                                            .arg(formatWin32ErrorText(error)));
                                        return;
                                    }
                                    editorGuard->setPlainText(sddl);
                                    statusGuard->setText(QStringLiteral("● 当前 SDDL 已读取。"));
                                }, Qt::QueuedConnection);
                        });
                    task->setAutoDelete(true);
                    QThreadPool::globalInstance()->start(task);
                });
            connect(effectiveButton, &QPushButton::clicked, this,
                [this, effectiveTrusteeEdit, effectiveResult]()
                {
                    DWORD accessMask = 0U;
                    const DWORD error = ks::file::metadata::queryEffectiveAccessMask(
                        m_filePath,
                        effectiveTrusteeEdit->text(),
                        &accessMask);
                    effectiveResult->setText(error == ERROR_SUCCESS
                        ? QStringLiteral("Mask: 0x%1 · %2")
                            .arg(accessMask, 8, 16, QLatin1Char('0'))
                            .arg(accessMaskToText(accessMask))
                        : QStringLiteral("检查失败：%1").arg(formatWin32ErrorText(error)));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, sddlEdit, ownerCheck, groupCheck, daclCheck, saclCheck,
                 protectDaclCheck, protectSaclCheck, status]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    SECURITY_INFORMATION information = 0U;
                    if (ownerCheck->isChecked()) information |= OWNER_SECURITY_INFORMATION;
                    if (groupCheck->isChecked()) information |= GROUP_SECURITY_INFORMATION;
                    if (daclCheck->isChecked()) information |= DACL_SECURITY_INFORMATION;
                    if (saclCheck->isChecked()) information |= SACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION;
                    if (protectDaclCheck->isChecked())
                        information |= DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
                    if (protectSaclCheck->isChecked())
                        information |= SACL_SECURITY_INFORMATION | PROTECTED_SACL_SECURITY_INFORMATION;
                    if (information == 0U || sddlEdit->toPlainText().trimmed().isEmpty())
                    {
                        QMessageBox::warning(this, QStringLiteral("安全描述符"),
                            QStringLiteral("请填写 SDDL 并至少选择一个写入范围。"));
                        return;
                    }
                    PSECURITY_DESCRIPTOR descriptor = nullptr;
                    if (::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        sddlEdit->toPlainText().trimmed().toStdWString().c_str(),
                        SDDL_REVISION_1, &descriptor, nullptr) == FALSE)
                    {
                        QMessageBox::warning(this, QStringLiteral("安全描述符"),
                            QStringLiteral("SDDL 格式无效：%1")
                                .arg(formatWin32ErrorText(::GetLastError())));
                        return;
                    }
                    ::LocalFree(descriptor);
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.security.replaceSddl = true;
                        patch.security.sddl = sddlEdit->toPlainText().trimmed();
                        patch.security.securityInformation = information;
                    }
                    status->setText(QStringLiteral("● 安全描述符已暂存。"));
                    updatePendingSaveUi();
                });
            return page;
        }

        QWidget* buildMetadataPeAndReparsePage(QWidget* parent)
        {
            QWidget* page = new QWidget(parent);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QGroupBox* reparseGroup = new QGroupBox(QStringLiteral("重解析点原始缓冲"), page);
            QVBoxLayout* reparseLayout = new QVBoxLayout(reparseGroup);
            QHBoxLayout* reparseActions = new QHBoxLayout();
            QComboBox* reparseAction = new QComboBox(reparseGroup);
            reparseAction->addItems(QStringList{
                QStringLiteral("不修改"),
                QStringLiteral("写入原始缓冲"),
                QStringLiteral("删除重解析点") });
            QPushButton* loadReparseButton = new QPushButton(QStringLiteral("读取当前原始缓冲"), reparseGroup);
            reparseActions->addWidget(reparseAction);
            reparseActions->addWidget(loadReparseButton);
            reparseActions->addStretch(1);
            QPlainTextEdit* reparseEdit = new QPlainTextEdit(reparseGroup);
            reparseEdit->setPlaceholderText(QStringLiteral("完整 REPARSE_DATA_BUFFER 十六进制，包含 Tag/Length/Reserved"));
            reparseEdit->setMaximumHeight(100);
            reparseLayout->addLayout(reparseActions);
            reparseLayout->addWidget(reparseEdit);
            layout->addWidget(reparseGroup);

            QGroupBox* resourceGroup = new QGroupBox(QStringLiteral("PE 资源编辑"), page);
            QGridLayout* resourceLayout = new QGridLayout(resourceGroup);
            QComboBox* resourcePreset = new QComboBox(resourceGroup);
            resourcePreset->addItems(QStringList{
                QStringLiteral("VERSIONINFO（RT_VERSION #16）"),
                QStringLiteral("Manifest（RT_MANIFEST #24）"),
                QStringLiteral("其它资源") });
            QLineEdit* resourceTypeEdit = new QLineEdit(QStringLiteral("#16"), resourceGroup);
            QLineEdit* resourceNameEdit = new QLineEdit(QStringLiteral("#1"), resourceGroup);
            QSpinBox* resourceLanguageSpin = new QSpinBox(resourceGroup);
            resourceLanguageSpin->setRange(0, 65535);
            QComboBox* resourceFormatCombo = new QComboBox(resourceGroup);
            resourceFormatCombo->addItems(QStringList{ QStringLiteral("文本 UTF-8"), QStringLiteral("十六进制") });
            resourceFormatCombo->setCurrentIndex(1);
            QCheckBox* removeResourceCheck = new QCheckBox(QStringLiteral("删除该资源"), resourceGroup);
            QPushButton* loadResourceButton = new QPushButton(QStringLiteral("读取当前资源"), resourceGroup);
            QPlainTextEdit* resourceDataEdit = new QPlainTextEdit(resourceGroup);
            resourceDataEdit->setMaximumHeight(110);
            resourceLayout->addWidget(resourcePreset, 0, 0);
            resourceLayout->addWidget(new QLabel(QStringLiteral("类型"), resourceGroup), 0, 1);
            resourceLayout->addWidget(resourceTypeEdit, 0, 2);
            resourceLayout->addWidget(new QLabel(QStringLiteral("名称 / ID"), resourceGroup), 0, 3);
            resourceLayout->addWidget(resourceNameEdit, 0, 4);
            resourceLayout->addWidget(new QLabel(QStringLiteral("语言 ID"), resourceGroup), 1, 0);
            resourceLayout->addWidget(resourceLanguageSpin, 1, 1);
            resourceLayout->addWidget(resourceFormatCombo, 1, 2);
            resourceLayout->addWidget(removeResourceCheck, 1, 3);
            resourceLayout->addWidget(loadResourceButton, 1, 4);
            resourceLayout->addWidget(resourceDataEdit, 2, 0, 1, 5);
            layout->addWidget(resourceGroup);

            QCheckBox* clearSignatureCheck = new QCheckBox(
                QStringLiteral("保存时清除嵌入式 Authenticode 签名（Catalog 签名不会被删除）"), page);
            layout->addWidget(clearSignatureCheck);
            QLabel* warning = new QLabel(QStringLiteral(
                "原始重解析点、PE 资源和签名清除属于高风险操作，必须启用底部备份选项。"
                "VERSIONINFO 可用原始十六进制编辑，Manifest 可用 UTF-8 文本编辑，其它资源支持原始字节。"), page);
            warning->setWordWrap(true);
            layout->addWidget(warning);
            QPushButton* stageButton = new QPushButton(QStringLiteral("暂存重解析点 / PE / 签名操作"), page);
            layout->addWidget(stageButton, 0, Qt::AlignRight);
            layout->addStretch(1);

            connect(resourcePreset, &QComboBox::currentIndexChanged, this,
                [resourceTypeEdit, resourceNameEdit, resourceFormatCombo](const int index)
                {
                    if (index == 0)
                    {
                        resourceTypeEdit->setText(QStringLiteral("#16"));
                        resourceNameEdit->setText(QStringLiteral("#1"));
                        resourceFormatCombo->setCurrentIndex(1);
                    }
                    else if (index == 1)
                    {
                        resourceTypeEdit->setText(QStringLiteral("#24"));
                        resourceNameEdit->setText(QStringLiteral("#1"));
                        resourceFormatCombo->setCurrentIndex(0);
                    }
                });
            connect(loadReparseButton, &QPushButton::clicked, this, [this, reparseEdit]()
                {
                    DWORD error = ERROR_SUCCESS;
                    const QByteArray data = ks::file::metadata::readRawReparseData(m_filePath, &error);
                    if (error != ERROR_SUCCESS)
                    {
                        QMessageBox::warning(this, QStringLiteral("重解析点"),
                            QStringLiteral("读取原始缓冲失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    reparseEdit->setPlainText(QString::fromLatin1(data.toHex(' ').toUpper()));
                });
            connect(loadResourceButton, &QPushButton::clicked, this,
                [this, resourceTypeEdit, resourceNameEdit, resourceLanguageSpin,
                 resourceFormatCombo, resourceDataEdit]()
                {
                    DWORD error = ERROR_SUCCESS;
                    const QByteArray data = ks::file::metadata::readPeResource(
                        m_filePath,
                        resourceTypeEdit->text(),
                        resourceNameEdit->text(),
                        static_cast<WORD>(resourceLanguageSpin->value()),
                        &error);
                    if (error != ERROR_SUCCESS)
                    {
                        QMessageBox::warning(this, QStringLiteral("PE 资源"),
                            QStringLiteral("读取资源失败：%1").arg(formatWin32ErrorText(error)));
                        return;
                    }
                    resourceDataEdit->setPlainText(resourceFormatCombo->currentIndex() == 0
                        ? QString::fromUtf8(data)
                        : QString::fromLatin1(data.toHex(' ').toUpper()));
                });
            connect(stageButton, &QPushButton::clicked, this,
                [this, reparseAction, reparseEdit, resourceTypeEdit, resourceNameEdit,
                 resourceLanguageSpin, resourceFormatCombo, removeResourceCheck,
                 resourceDataEdit, clearSignatureCheck]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    QByteArray reparseBytes;
                    if (reparseAction->currentIndex() == 1)
                    {
                        bool reparseOk = false;
                        reparseBytes = parseMetadataHexText(reparseEdit->toPlainText(), &reparseOk);
                        if (!reparseOk || reparseBytes.size() < 8 ||
                            reparseBytes.size() > MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
                        {
                            QMessageBox::warning(this, QStringLiteral("重解析点"),
                                QStringLiteral("原始重解析缓冲必须是 8 到 16384 字节的有效十六进制。"));
                            return;
                        }
                    }
                    const bool hasResourceInput =
                        !resourceTypeEdit->text().trimmed().isEmpty() &&
                        !resourceNameEdit->text().trimmed().isEmpty() &&
                        (removeResourceCheck->isChecked() || !resourceDataEdit->toPlainText().isEmpty());
                    QByteArray resourceBytes;
                    if (hasResourceInput && !removeResourceCheck->isChecked())
                    {
                        bool resourceOk = false;
                        resourceBytes = metadataEditorBytes(
                            resourceDataEdit, resourceFormatCombo, &resourceOk);
                        if (!resourceOk)
                        {
                            QMessageBox::warning(this, QStringLiteral("PE 资源"),
                                QStringLiteral("资源十六进制格式无效。"));
                            return;
                        }
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        patch.reparse.update = reparseAction->currentIndex() != 0;
                        patch.reparse.remove = reparseAction->currentIndex() == 2;
                        patch.reparse.rawBuffer = reparseBytes;
                        patch.signatureDisposition = clearSignatureCheck->isChecked()
                            ? ks::file::metadata::SignatureDisposition::RemoveEmbedded
                            : ks::file::metadata::SignatureDisposition::Preserve;
                        if (hasResourceInput)
                        {
                            ks::file::metadata::PeResourcePatch resource;
                            resource.type = resourceTypeEdit->text().trimmed();
                            resource.name = resourceNameEdit->text().trimmed();
                            resource.language = static_cast<WORD>(resourceLanguageSpin->value());
                            resource.action = removeResourceCheck->isChecked()
                                ? ks::file::metadata::BinaryPatchAction::Remove
                                : ks::file::metadata::BinaryPatchAction::Replace;
                            resource.data = resourceBytes;
                            patch.peResources.push_back(resource);
                        }
                    }
                    updatePendingSaveUi();
                });
            return page;
        }

        QTabWidget* buildMetadataAdvancedTabs(QWidget* parent)
        {
            QTabWidget* tabs = new QTabWidget(parent);
            tabs->addTab(buildMetadataNameAndFilesystemPage(tabs), QStringLiteral("名称与文件系统"));
            tabs->addTab(buildMetadataShellPropertyPage(tabs), QStringLiteral("Shell 属性"));
            tabs->addTab(buildMetadataAdsPage(tabs), QStringLiteral("ADS"));
            tabs->addTab(buildMetadataEaPage(tabs), QStringLiteral("EA"));
            tabs->addTab(buildMetadataSecurityPage(tabs), QStringLiteral("安全描述符"));
            tabs->addTab(buildMetadataPeAndReparsePage(tabs), QStringLiteral("重解析点 / PE / 签名"));
            return tabs;
        }

        QWidget* buildMetadataTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            layout->setSpacing(10);

            QLabel* targetLabel = new QLabel(
                m_batchMode
                    ? ks::i18n::sourceText(QStringLiteral("批量目标：%1 项"))
                        .arg(m_filePaths.size())
                    : ks::i18n::sourceText(QStringLiteral("目标：%1"))
                        .arg(QDir::toNativeSeparators(m_filePath)),
                page);
            targetLabel->setWordWrap(true);
            targetLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(targetLabel);

            QLabel* hintLabel = new QLabel(
                ks::i18n::sourceText(QStringLiteral(
                    "时间按本地时区显示，精确到毫秒；只有勾选“修改”的时间字段才会写入。")) +
                QLatin1Char('\n') +
                ks::i18n::sourceText(QStringLiteral(
                    "属性编辑只开放可直接切换的位，目录、重解析点、压缩、加密、稀疏等结构性属性始终保留。")) +
                QLatin1Char('\n') +
                ks::i18n::sourceText(QStringLiteral(
                    "本页按钮只会暂存修改。窗口底部“保存全部修改”是唯一写入入口。")),
                page);
            hintLabel->setWordWrap(true);
            layout->addWidget(hintLabel);

            QGroupBox* timeGroup = new QGroupBox(QStringLiteral("文件时间"), page);
            QGridLayout* timeLayout = new QGridLayout(timeGroup);
            timeLayout->setColumnStretch(2, 1);
            timeLayout->addWidget(new QLabel(QStringLiteral("写入"), timeGroup), 0, 0);
            timeLayout->addWidget(new QLabel(QStringLiteral("字段"), timeGroup), 0, 1);
            timeLayout->addWidget(new QLabel(QStringLiteral("本地时间（含毫秒）"), timeGroup), 0, 2);

            const std::array<QString, 4> timeNames{
                QStringLiteral("创建时间"),
                QStringLiteral("最后访问时间"),
                QStringLiteral("最后写入时间"),
                QStringLiteral("元数据变更时间（ChangeTime）")
            };
            // 0 在 FileBasicInformation 的“设置”语义中表示保持不变，故不允许选择恰好为
            // FILETIME epoch 的 1601-01-01 00:00:00 UTC；从次日开始可避免时区换算后落到 0。
            const QDateTime minimumDateTime(QDate(1601, 1, 2), QTime(0, 0));
            const QDateTime maximumDateTime(QDate(9999, 12, 31), QTime(23, 59, 59, 999));
            for (std::size_t timeIndex = 0; timeIndex < timeNames.size(); ++timeIndex)
            {
                QCheckBox* modifyCheck = new QCheckBox(QStringLiteral("修改"), timeGroup);
                QDateTimeEdit* dateTimeEdit = new QDateTimeEdit(timeGroup);
                dateTimeEdit->setCalendarPopup(true);
                dateTimeEdit->setDisplayFormat(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
                dateTimeEdit->setMinimumDateTime(minimumDateTime);
                dateTimeEdit->setMaximumDateTime(maximumDateTime);
                dateTimeEdit->setEnabled(false);
                m_metadataTimeChecks[timeIndex] = modifyCheck;
                m_metadataTimeEdits[timeIndex] = dateTimeEdit;
                timeLayout->addWidget(modifyCheck, static_cast<int>(timeIndex) + 1, 0);
                timeLayout->addWidget(
                    new QLabel(timeNames[timeIndex], timeGroup),
                    static_cast<int>(timeIndex) + 1,
                    1);
                timeLayout->addWidget(dateTimeEdit, static_cast<int>(timeIndex) + 1, 2);
                connect(modifyCheck, &QCheckBox::toggled, dateTimeEdit,
                    [this, dateTimeEdit](const bool checked)
                    {
                        dateTimeEdit->setEnabled(
                            checked && m_metadataHasSnapshot && !m_metadataEditorBusy);
                    });
            }
            layout->addWidget(timeGroup);

            QGroupBox* attributeGroup = new QGroupBox(QStringLiteral("可编辑文件属性"), page);
            QGridLayout* attributeLayout = new QGridLayout(attributeGroup);
            const std::array<QString, 6> attributeNames{
                QStringLiteral("只读（READONLY）"),
                QStringLiteral("隐藏（HIDDEN）"),
                QStringLiteral("系统（SYSTEM）"),
                QStringLiteral("存档（ARCHIVE）"),
                QStringLiteral("临时（TEMPORARY）"),
                QStringLiteral("不建内容索引（NOT_CONTENT_INDEXED）")
            };
            for (std::size_t attributeIndex = 0;
                 attributeIndex < attributeNames.size();
                 ++attributeIndex)
            {
                QCheckBox* attributeCheck =
                    new QCheckBox(attributeNames[attributeIndex], attributeGroup);
                m_metadataAttributeChecks[attributeIndex] = attributeCheck;
                attributeLayout->addWidget(
                    attributeCheck,
                    static_cast<int>(attributeIndex / 2),
                    static_cast<int>(attributeIndex % 2));
                connect(attributeCheck, &QCheckBox::checkStateChanged, this,
                    [this, attributeIndex](const Qt::CheckState state)
                    {
                        if (!m_metadataApplyingSnapshot && state != Qt::PartiallyChecked)
                        {
                            m_metadataAttributeTouched[attributeIndex] = true;
                        }
                    });
            }
            layout->addWidget(attributeGroup);

            layout->addWidget(buildMetadataAdvancedTabs(page), 1);

            QHBoxLayout* actionLayout = new QHBoxLayout();
            m_metadataRefreshButton = new QPushButton(QStringLiteral("重新读取"), page);
            m_metadataApplyButton = new QPushButton(QStringLiteral("暂存基础修改"), page);
            actionLayout->addStretch(1);
            actionLayout->addWidget(m_metadataRefreshButton);
            actionLayout->addWidget(m_metadataApplyButton);
            layout->addLayout(actionLayout);

            m_metadataStatusLabel = new QLabel(QStringLiteral("● 等待读取文件元数据。"), page);
            m_metadataStatusLabel->setWordWrap(true);
            layout->addWidget(m_metadataStatusLabel);

            connect(m_metadataRefreshButton, &QPushButton::clicked, this,
                [this]() { refreshMetadataEditor(); });
            connect(m_metadataApplyButton, &QPushButton::clicked, this,
                [this]() { applyMetadataEditorChanges(); });

            m_metadataHasSnapshot = false;
            setMetadataEditorBusy(false);
            QMetaObject::invokeMethod(page, [this]() { refreshMetadataEditor(); }, Qt::QueuedConnection);
            return page;
        }

        QWidget* buildReparseTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            QString content;
            if (!isPathReparsePoint(m_filePath))
            {
                content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(m_filePath));
                content += QStringLiteral("状态: 当前目标不是 FILE_ATTRIBUTE_REPARSE_POINT。\n");
            }
            else
            {
                content += formatReparsePointText(m_filePath);
            }

            layout->addWidget(buildReportView(page, content), 1);
            return page;
        }

        QWidget* buildSecurityTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            const QString nativePath = QDir::toNativeSeparators(m_filePath);
            QString baseContent;
            baseContent += QStringLiteral("目标路径: %1\n").arg(nativePath);

            // 先给出 Qt 维度的快速权限摘要，便于与 ACL 细节对照。
            QFileInfo info(m_filePath);
            baseContent += QStringLiteral("快速权限摘要:\n");
            baseContent += QStringLiteral("Read: %1\n").arg(info.isReadable() ? QStringLiteral("允许") : QStringLiteral("拒绝"));
            baseContent += QStringLiteral("Write: %1\n").arg(info.isWritable() ? QStringLiteral("允许") : QStringLiteral("拒绝"));
            baseContent += QStringLiteral("Execute: %1\n").arg(info.isExecutable() ? QStringLiteral("允许") : QStringLiteral("拒绝"));

            QGroupBox* operationGroup = new QGroupBox(QStringLiteral("权限编辑"), page);
            QGridLayout* operationLayout = new QGridLayout(operationGroup);

            QLineEdit* accountEdit = new QLineEdit(operationGroup);
            accountEdit->setPlaceholderText(QStringLiteral("账户或 SID，例如 BUILTIN\\Administrators / Everyone / S-1-5-32-544"));
            accountEdit->setStyleSheet(buildBlueInputStyle());

            QComboBox* accessModeCombo = new QComboBox(operationGroup);
            accessModeCombo->setStyleSheet(buildBlueInputStyle());
            accessModeCombo->addItem(QStringLiteral("允许：添加/合并"), static_cast<int>(GRANT_ACCESS));
            accessModeCombo->addItem(QStringLiteral("允许：替换该主体权限"), static_cast<int>(SET_ACCESS));
            accessModeCombo->addItem(QStringLiteral("拒绝：添加/合并"), static_cast<int>(DENY_ACCESS));

            QComboBox* presetCombo = new QComboBox(operationGroup);
            presetCombo->setStyleSheet(buildBlueInputStyle());
            presetCombo->addItems(QStringList{
                QStringLiteral("读取"),
                QStringLiteral("写入"),
                QStringLiteral("读取 + 写入"),
                QStringLiteral("读取 + 执行"),
                QStringLiteral("修改"),
                QStringLiteral("完全控制") });
            presetCombo->setCurrentIndex(4);

            QLineEdit* customMaskEdit = new QLineEdit(operationGroup);
            customMaskEdit->setPlaceholderText(QStringLiteral("可选自定义 Mask，如 0x001F01FF；留空使用预设/复选框"));
            customMaskEdit->setStyleSheet(buildBlueInputStyle());

            QComboBox* inheritanceCombo = new QComboBox(operationGroup);
            inheritanceCombo->setStyleSheet(buildBlueInputStyle());
            inheritanceCombo->addItems(QStringList{
                QStringLiteral("仅当前对象"),
                QStringLiteral("目录和文件继承"),
                QStringLiteral("仅文件继承"),
                QStringLiteral("仅目录继承") });

            QCheckBox* readCheck = new QCheckBox(QStringLiteral("读"), operationGroup);
            QCheckBox* writeCheck = new QCheckBox(QStringLiteral("写"), operationGroup);
            QCheckBox* executeCheck = new QCheckBox(QStringLiteral("执行"), operationGroup);
            QCheckBox* deleteCheck = new QCheckBox(QStringLiteral("删除"), operationGroup);
            QCheckBox* writeDacCheck = new QCheckBox(QStringLiteral("改 DACL"), operationGroup);
            QCheckBox* writeOwnerCheck = new QCheckBox(QStringLiteral("改所有者"), operationGroup);

            QPushButton* applyAceButton = new QPushButton(QStringLiteral("应用 ACE"), operationGroup);
            QPushButton* deleteAceButton = new QPushButton(QStringLiteral("删除选中 ACE"), operationGroup);
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新权限"), operationGroup);
            applyAceButton->setToolTip(
                QStringLiteral("按上面选择的账户和权限，给该文件新增一条访问控制规则（ACE）"));
            deleteAceButton->setToolTip(
                QStringLiteral("删除列表中选中的那条文件访问控制规则（ACE）"));
            applyAceButton->setStyleSheet(buildBlueButtonStyle());
            deleteAceButton->setStyleSheet(buildBlueButtonStyle());
            refreshButton->setStyleSheet(buildBlueButtonStyle());

            operationLayout->addWidget(new QLabel(QStringLiteral("主体"), operationGroup), 0, 0);
            operationLayout->addWidget(accountEdit, 0, 1, 1, 5);
            operationLayout->addWidget(new QLabel(QStringLiteral("动作"), operationGroup), 1, 0);
            operationLayout->addWidget(accessModeCombo, 1, 1);
            operationLayout->addWidget(new QLabel(QStringLiteral("预设"), operationGroup), 1, 2);
            operationLayout->addWidget(presetCombo, 1, 3);
            operationLayout->addWidget(new QLabel(QStringLiteral("继承"), operationGroup), 1, 4);
            operationLayout->addWidget(inheritanceCombo, 1, 5);
            operationLayout->addWidget(new QLabel(QStringLiteral("权限位"), operationGroup), 2, 0);
            operationLayout->addWidget(readCheck, 2, 1);
            operationLayout->addWidget(writeCheck, 2, 2);
            operationLayout->addWidget(executeCheck, 2, 3);
            operationLayout->addWidget(deleteCheck, 2, 4);
            operationLayout->addWidget(writeDacCheck, 2, 5);
            operationLayout->addWidget(writeOwnerCheck, 3, 1);
            operationLayout->addWidget(new QLabel(QStringLiteral("Mask"), operationGroup), 4, 0);
            operationLayout->addWidget(customMaskEdit, 4, 1, 1, 3);
            operationLayout->addWidget(applyAceButton, 4, 4);
            operationLayout->addWidget(deleteAceButton, 4, 5);
            operationLayout->addWidget(refreshButton, 5, 5);
            layout->addWidget(operationGroup, 0);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 正在读取安全描述符..."), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(statusLabel, 0);

            QSplitter* splitter = new QSplitter(Qt::Vertical, page);
            QTableWidget* aceTable = new ks::ui::VisibleTableWidget(splitter);
            aceTable->setColumnCount(9);
            aceTable->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("范围"),
                QStringLiteral("序号"),
                QStringLiteral("类型"),
                QStringLiteral("账户"),
                QStringLiteral("SID"),
                QStringLiteral("Mask"),
                QStringLiteral("权限"),
                QStringLiteral("标志"),
                QStringLiteral("编辑状态")
                });
            aceTable->setAlternatingRowColors(true);
            aceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
            aceTable->setSelectionMode(QAbstractItemView::SingleSelection);
            aceTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
            aceTable->setSortingEnabled(true);
            if (aceTable->horizontalHeader() != nullptr)
            {
                aceTable->horizontalHeader()->setStretchLastSection(true);
            }
            installFileTableCopyMenu(aceTable);

            CodeEditorWidget* detailEditor = new CodeEditorWidget(splitter);
            detailEditor->setReadOnly(true);
            detailEditor->setLocalizedText(baseContent + QStringLiteral(
                "\n深层 Owner/Group/DACL/SACL 正在后台加载...\n"
                "\n操作说明：\n"
                "- 上方表格用于结构化展示 ACE；继承 ACE、SACL、对象 ACE 默认只读展示。\n"
                "- 应用 ACE 使用 Windows 安全 API 写 DACL，失败会保留错误码。\n"
                "- 删除选中 ACE 只删除非继承 DACL 中精确匹配的当前 ACE。\n"));

            splitter->addWidget(aceTable);
            splitter->addWidget(detailEditor);
            splitter->setStretchFactor(0, 3);
            splitter->setStretchFactor(1, 2);
            layout->addWidget(splitter, 1);

            const auto syncChecksFromPreset = [this, presetCombo, readCheck, writeCheck, executeCheck, deleteCheck, writeDacCheck, writeOwnerCheck]()
                {
                    const DWORD presetMask = maskFromSecurityPreset(presetCombo->currentIndex());
                    readCheck->setChecked((presetMask & FILE_GENERIC_READ) == FILE_GENERIC_READ);
                    writeCheck->setChecked((presetMask & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE);
                    executeCheck->setChecked((presetMask & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE);
                    deleteCheck->setChecked((presetMask & DELETE) != 0);
                    writeDacCheck->setChecked((presetMask & WRITE_DAC) != 0);
                    writeOwnerCheck->setChecked((presetMask & WRITE_OWNER) != 0);
                };
            syncChecksFromPreset();
            connect(presetCombo, &QComboBox::currentIndexChanged, this, [syncChecksFromPreset](int)
                {
                    syncChecksFromPreset();
                });

            const auto refreshSecurityUi = [this, aceTable, detailEditor, statusLabel, baseContent, nativePath]()
                {
                    if (aceTable != nullptr)
                    {
                        aceTable->setRowCount(0);
                    }
                    if (statusLabel != nullptr)
                    {
                        statusLabel->setText(QStringLiteral("● 正在读取安全描述符..."));
                    }
                    if (detailEditor != nullptr)
                    {
                        detailEditor->setLocalizedText(baseContent + QStringLiteral("\n深层 Owner/Group/DACL/SACL 正在后台加载...\n"));
                    }
                    startSecurityDeepLoad(aceTable, detailEditor, statusLabel, baseContent, nativePath);
                };

            connect(refreshButton, &QPushButton::clicked, this, refreshSecurityUi);
            connect(applyAceButton, &QPushButton::clicked, this,
                [this,
                accountEdit,
                accessModeCombo,
                inheritanceCombo,
                customMaskEdit,
                readCheck,
                writeCheck,
                executeCheck,
                deleteCheck,
                writeDacCheck,
                writeOwnerCheck,
                statusLabel]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    DWORD accessMask = maskFromSecurityChecks(
                        readCheck,
                        writeCheck,
                        executeCheck,
                        deleteCheck,
                        writeDacCheck,
                        writeOwnerCheck);
                    const QString customMaskText = customMaskEdit->text().trimmed();
                    if (!customMaskText.isEmpty())
                    {
                        bool parseOk = false;
                        const qulonglong parsedMask = customMaskText.toULongLong(&parseOk, 0);
                        if (!parseOk || parsedMask > 0xFFFFFFFFULL)
                        {
                            QMessageBox::warning(this, QStringLiteral("权限编辑"), QStringLiteral("自定义 Mask 格式无效：%1").arg(customMaskText));
                            return;
                        }
                        accessMask = static_cast<DWORD>(parsedMask);
                    }

                    if (accountEdit->text().trimmed().isEmpty() || accessMask == 0U)
                    {
                        QMessageBox::warning(this, QStringLiteral("权限编辑"),
                            QStringLiteral("请填写主体，并选择至少一个权限位。"));
                        return;
                    }
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        ks::file::metadata::SecurityAcePatch ace;
                        ace.trustee = accountEdit->text().trimmed();
                        ace.accessMask = accessMask;
                        ace.accessMode = static_cast<DWORD>(accessModeCombo->currentData().toInt());
                        ace.inheritance = inheritanceFlagsFromCombo(inheritanceCombo->currentIndex());
                        patch.security.aceChanges.push_back(ace);
                    }
                    if (statusLabel != nullptr)
                        statusLabel->setText(QStringLiteral("● ACE 修改已暂存，尚未写入文件。"));
                    updatePendingSaveUi();
                });

            connect(deleteAceButton, &QPushButton::clicked, this, [this, aceTable, statusLabel]()
                {
                    if (!ensurePendingPatchesForStaging()) return;
                    const int row = aceTable != nullptr ? aceTable->currentRow() : -1;
                    if (row < 0 || aceTable->item(row, 0) == nullptr)
                    {
                        QMessageBox::information(this, QStringLiteral("删除 ACE"),
                            QStringLiteral("请先选择一条可编辑的非继承 DACL ACE。"));
                        return;
                    }
                    QTableWidgetItem* const item = aceTable->item(row, 0);
                    if (!item->data(Qt::UserRole + 6).toBool())
                    {
                        QMessageBox::information(this, QStringLiteral("删除 ACE"),
                            QStringLiteral("继承 ACE、SACL 与对象 ACE保持只读，不能在此直接删除。"));
                        return;
                    }
                    const QString typeText = item->data(Qt::UserRole + 4).toString();
                    BYTE aceType = 0xFFU;
                    if (typeText == QStringLiteral("ACCESS_ALLOWED")) aceType = ACCESS_ALLOWED_ACE_TYPE;
                    if (typeText == QStringLiteral("ACCESS_DENIED")) aceType = ACCESS_DENIED_ACE_TYPE;
                    if (aceType == 0xFFU)
                    {
                        return;
                    }
                    BYTE aceFlags = 0U;
                    const QString flagsText = aceTable->item(row, 7) != nullptr
                        ? aceTable->item(row, 7)->text()
                        : QString();
                    if (flagsText.contains(QStringLiteral("OBJECT_INHERIT"))) aceFlags |= OBJECT_INHERIT_ACE;
                    if (flagsText.contains(QStringLiteral("CONTAINER_INHERIT"))) aceFlags |= CONTAINER_INHERIT_ACE;
                    if (flagsText.contains(QStringLiteral("NO_PROPAGATE"))) aceFlags |= NO_PROPAGATE_INHERIT_ACE;
                    if (flagsText.contains(QStringLiteral("INHERIT_ONLY"))) aceFlags |= INHERIT_ONLY_ACE;
                    for (ks::file::metadata::TargetPatch& patch : m_pendingPatches)
                    {
                        ks::file::metadata::SecurityAceRemoval removal;
                        removal.aceType = aceType;
                        removal.aceFlags = aceFlags;
                        removal.accessMask = static_cast<DWORD>(
                            item->data(Qt::UserRole + 5).toULongLong());
                        removal.sid = item->data(Qt::UserRole + 3).toString();
                        patch.security.aceRemovals.push_back(removal);
                    }
                    if (statusLabel != nullptr)
                        statusLabel->setText(QStringLiteral("● 删除 ACE 操作已暂存，尚未写入文件。"));
                    updatePendingSaveUi();
                });

            QMetaObject::invokeMethod(page, refreshSecurityUi, Qt::QueuedConnection);
            return page;
        }

        QWidget* buildHashTab()
        {
            if (m_batchMode)
            {
                QWidget* page = new QWidget(this);
                QVBoxLayout* layout = new QVBoxLayout(page);
                QHBoxLayout* toolbar = new QHBoxLayout();
                QPushButton* startButton = new QPushButton(QStringLiteral("批量计算 SHA256"), page);
                QPushButton* cancelButton = new QPushButton(QStringLiteral("取消"), page);
                cancelButton->setEnabled(false);
                QLabel* statusLabel = new QLabel(QStringLiteral("● 等待开始批量哈希"), page);
                toolbar->addWidget(startButton);
                toolbar->addWidget(cancelButton);
                toolbar->addWidget(statusLabel, 1);
                layout->addLayout(toolbar);
                QProgressBar* progress = new QProgressBar(page);
                progress->setRange(0, m_filePaths.size());
                progress->setValue(0);
                layout->addWidget(progress);
                QTableWidget* table = new ks::ui::VisibleTableWidget(page);
                table->setColumnCount(4);
                table->setHorizontalHeaderLabels(QStringList{
                    QStringLiteral("目标"), QStringLiteral("状态"),
                    QStringLiteral("SHA256"), QStringLiteral("错误") });
                table->setRowCount(m_filePaths.size());
                table->setSelectionBehavior(QAbstractItemView::SelectRows);
                table->setSelectionMode(QAbstractItemView::ExtendedSelection);
                table->setEditTriggers(QAbstractItemView::NoEditTriggers);
                table->setAlternatingRowColors(true);
                for (qsizetype row = 0; row < m_filePaths.size(); ++row)
                {
                    table->setItem(static_cast<int>(row), 0,
                        new QTableWidgetItem(QDir::toNativeSeparators(m_filePaths.at(row))));
                    table->setItem(static_cast<int>(row), 1,
                        new QTableWidgetItem(QStringLiteral("等待")));
                    table->setItem(static_cast<int>(row), 2, new QTableWidgetItem());
                    table->setItem(static_cast<int>(row), 3, new QTableWidgetItem());
                }
                installFileTableCopyMenu(table);
                if (table->horizontalHeader() != nullptr)
                    table->horizontalHeader()->setStretchLastSection(true);
                layout->addWidget(table, 1);
                connect(cancelButton, &QPushButton::clicked, this, [this, cancelButton]()
                    {
                        if (m_hashCancelRequested != nullptr)
                            m_hashCancelRequested->store(true);
                        cancelButton->setEnabled(false);
                    });
                connect(startButton, &QPushButton::clicked, this,
                    [this, table, progress, statusLabel, startButton, cancelButton]()
                    {
                        m_hashCancelRequested = std::make_shared<std::atomic_bool>(false);
                        const auto cancelRequested = m_hashCancelRequested;
                        const QStringList paths = m_filePaths;
                        startButton->setEnabled(false);
                        cancelButton->setEnabled(true);
                        progress->setValue(0);
                        statusLabel->setText(QStringLiteral("● 正在后台计算批量 SHA256..."));
                        QPointer<QTableWidget> tableGuard(table);
                        QPointer<QProgressBar> progressGuard(progress);
                        QPointer<QLabel> statusGuard(statusLabel);
                        QPointer<QPushButton> startGuard(startButton);
                        QPointer<QPushButton> cancelGuard(cancelButton);
                        auto* task = QRunnable::create(
                            [tableGuard, progressGuard, statusGuard, startGuard, cancelGuard,
                             cancelRequested, paths]()
                            {
                                int completed = 0;
                                for (qsizetype row = 0; row < paths.size(); ++row)
                                {
                                    if (cancelRequested->load()) break;
                                    QString stateText;
                                    QString hashText;
                                    QString errorText;
                                    const QFileInfo info(paths.at(row));
                                    if (!info.isFile())
                                    {
                                        stateText = QStringLiteral("已跳过");
                                        errorText = QStringLiteral("不是普通文件");
                                    }
                                    else
                                    {
                                        QFile file(paths.at(row));
                                        if (!file.open(QIODevice::ReadOnly))
                                        {
                                            stateText = QStringLiteral("失败");
                                            errorText = file.errorString();
                                        }
                                        else
                                        {
                                            QCryptographicHash hash(QCryptographicHash::Sha256);
                                            while (!file.atEnd() && !cancelRequested->load())
                                            {
                                                const QByteArray block = file.read(1024 * 1024);
                                                if (block.isEmpty() && file.error() != QFileDevice::NoError) break;
                                                hash.addData(block);
                                            }
                                            if (cancelRequested->load())
                                            {
                                                stateText = QStringLiteral("已取消");
                                            }
                                            else if (file.error() != QFileDevice::NoError)
                                            {
                                                stateText = QStringLiteral("失败");
                                                errorText = file.errorString();
                                            }
                                            else
                                            {
                                                stateText = QStringLiteral("完成");
                                                hashText = QString::fromLatin1(hash.result().toHex().toUpper());
                                            }
                                        }
                                    }
                                    ++completed;
                                    if (tableGuard == nullptr) return;
                                    QMetaObject::invokeMethod(tableGuard.data(),
                                        [tableGuard, progressGuard, row, completed, stateText, hashText, errorText]()
                                        {
                                            if (tableGuard == nullptr) return;
                                            tableGuard->item(static_cast<int>(row), 1)->setText(stateText);
                                            tableGuard->item(static_cast<int>(row), 2)->setText(hashText);
                                            tableGuard->item(static_cast<int>(row), 3)->setText(errorText);
                                            if (progressGuard != nullptr) progressGuard->setValue(completed);
                                        }, Qt::QueuedConnection);
                                }
                                if (statusGuard == nullptr) return;
                                QMetaObject::invokeMethod(statusGuard.data(),
                                    [statusGuard, startGuard, cancelGuard, cancelRequested, completed, paths]()
                                    {
                                        if (statusGuard == nullptr) return;
                                        statusGuard->setText(cancelRequested->load()
                                            ? QStringLiteral("● 批量哈希已取消，完成 %1 / %2。")
                                                .arg(completed).arg(paths.size())
                                            : QStringLiteral("● 批量哈希完成，共处理 %1 项。")
                                                .arg(completed));
                                        if (startGuard != nullptr) startGuard->setEnabled(true);
                                        if (cancelGuard != nullptr) cancelGuard->setEnabled(false);
                                    }, Qt::QueuedConnection);
                            });
                        task->setAutoDelete(true);
                        QThreadPool::globalInstance()->start(task);
                    });
                return page;
            }

            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QHBoxLayout* toolbarLayout = new QHBoxLayout();
            QPushButton* startButton = new QPushButton(QStringLiteral("计算 SHA256"), page);
            QPushButton* cancelButton = new QPushButton(QStringLiteral("取消"), page);
            cancelButton->setEnabled(false);
            toolbarLayout->addWidget(startButton, 0);
            toolbarLayout->addWidget(cancelButton, 0);
            toolbarLayout->addStretch(1);
            layout->addLayout(toolbarLayout);

            QProgressBar* progressBar = new QProgressBar(page);
            progressBar->setRange(0, 1000);
            progressBar->setValue(0);
            layout->addWidget(progressBar, 0);

            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);
            layout->addWidget(textEditorWidget, 1);

            textEditorWidget->setLocalizedText(QStringLiteral(
                "Phase 10 哈希页：\n"
                "- SHA256 使用用户态流式读取，避免一次性读入大文件。\n"
                "- 点击“取消”会在下一个块读取边界停止。\n"
                "- 可用 PowerShell Get-FileHash -Algorithm SHA256 进行对比。\n"));

            connect(startButton, &QPushButton::clicked, this, [this, textEditorWidget, progressBar, startButton, cancelButton]()
                {
                    startHashCalculation(textEditorWidget, progressBar, startButton, cancelButton);
                });
            connect(cancelButton, &QPushButton::clicked, this, [this, cancelButton]()
                {
                    requestHashCancel(cancelButton);
                });
            return page;
        }

        QWidget* buildUsageTab()
        {
            // 用途：Phase-10 把现有文件占用扫描结果直接嵌入属性窗口。
            // 处理：这里只创建轻量 UI，不在首次切换 Tab 时自动扫描，避免系统句柄枚举
            //       和结果回填让属性窗口卡顿；用户点击“刷新占用”后再后台扫描。
            //       Scanner 先调用 R0 HandleTable；R0 未启用时由全局入口提示用户，
            //       本轮回落 R3，服务启用成功后属性页再自动重扫一次。
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QHBoxLayout* toolbarLayout = new QHBoxLayout();
            QPushButton* refreshButton = new QPushButton(QStringLiteral("刷新占用"), page);
            refreshButton->setIcon(QIcon(QStringLiteral(":/Icon/handle_refresh.svg")));
            refreshButton->setIconSize(QSize(16, 16));
            refreshButton->setToolTip(QStringLiteral("重新扫描当前文件或目录的占用句柄"));

            QPushButton* closeHandleButton = new QPushButton(QStringLiteral("关闭句柄（R3）"), page);
            closeHandleButton->setIcon(QIcon(QStringLiteral(":/Icon/handle_close.svg")));
            closeHandleButton->setIconSize(QSize(16, 16));
            closeHandleButton->setToolTip(QStringLiteral("校验选中记录后，从用户态关闭该远程文件句柄"));
            closeHandleButton->setEnabled(false);

            QPushButton* terminateR3Button = new QPushButton(QStringLiteral("结束进程（R3）"), page);
            terminateR3Button->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
            terminateR3Button->setIconSize(QSize(16, 16));
            terminateR3Button->setToolTip(QStringLiteral("校验 PID 和进程创建时间后，从用户态结束占用进程"));
            terminateR3Button->setEnabled(false);

            QPushButton* terminateR0Button = new QPushButton(QStringLiteral("结束进程（R0）"), page);
            terminateR0Button->setIcon(QIcon(QStringLiteral(":/Icon/process_terminate.svg")));
            terminateR0Button->setIconSize(QSize(16, 16));
            terminateR0Button->setToolTip(QStringLiteral("校验 PID 和进程创建时间后，由 KswordARK 驱动结束占用进程"));
            terminateR0Button->setEnabled(false);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 未扫描，点击“刷新占用”开始枚举文件占用。"), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            toolbarLayout->addWidget(refreshButton, 0);
            toolbarLayout->addWidget(closeHandleButton, 0);
            toolbarLayout->addWidget(terminateR3Button, 0);
            toolbarLayout->addWidget(terminateR0Button, 0);
            toolbarLayout->addStretch(1);
            layout->addLayout(toolbarLayout);
            layout->addWidget(statusLabel, 0);

            QProgressBar* usageProgressBar = new QProgressBar(page);
            usageProgressBar->setRange(0, 100);
            usageProgressBar->setValue(0);
            usageProgressBar->setFormat(QStringLiteral("%p%"));
            m_usageScanProgressBar = usageProgressBar;
            layout->addWidget(usageProgressBar, 0);

            QTreeWidget* table = new QTreeWidget(page);
            table->setColumnCount(7);
            table->setHeaderLabels(QStringList{
                QStringLiteral("PID"),
                QStringLiteral("进程名"),
                QStringLiteral("Handle"),
                QStringLiteral("GrantedAccess"),
                QStringLiteral("对象/路径"),
                QStringLiteral("命中目标"),
                QStringLiteral("枚举来源")
                });
            table->setRootIsDecorated(false);
            table->setAlternatingRowColors(true);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::SingleSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setSortingEnabled(true);
            if (table->header() != nullptr)
            {
                table->header()->setStretchLastSection(true);
            }
            installFileTreeCopyMenu(table, 0);
            layout->addWidget(table, 1);

            connect(refreshButton, &QPushButton::clicked, this, [this, table, statusLabel, refreshButton]()
                {
                    refreshUsageTable(table, statusLabel, refreshButton);
                });
            connect(table, &QTreeWidget::currentItemChanged, this,
                [closeHandleButton, terminateR3Button, terminateR0Button](QTreeWidgetItem* currentItem)
                {
                    const std::uint32_t processId = currentItem == nullptr
                        ? 0U
                        : currentItem->data(0, usageProcessIdRole).toUInt();
                    const std::uint64_t creationTime = currentItem == nullptr
                        ? 0U
                        : currentItem->data(0, usageProcessCreationTimeRole).toULongLong();
                    const std::uint64_t handleValue = currentItem == nullptr
                        ? 0U
                        : currentItem->data(0, usageHandleValueRole).toULongLong();
                    const QString processName = currentItem == nullptr ? QString() : currentItem->text(1);
                    const bool processActionAllowed = processId > 4U &&
                        processId != static_cast<std::uint32_t>(::GetCurrentProcessId()) &&
                        creationTime != 0U && !isCriticalProcessName(processName);
                    closeHandleButton->setEnabled(processActionAllowed && handleValue != 0U);
                    terminateR3Button->setEnabled(processActionAllowed);
                    terminateR0Button->setEnabled(processActionAllowed);
                });
            connect(closeHandleButton, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    closeSelectedUsageHandle(table, statusLabel, refreshButton);
                });
            connect(terminateR3Button, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    terminateSelectedUsageProcess(table, statusLabel, refreshButton, false);
                });
            connect(terminateR0Button, &QPushButton::clicked, this,
                [this, table, statusLabel, refreshButton]()
                {
                    terminateSelectedUsageProcess(table, statusLabel, refreshButton, true);
                });

            MainWindow* const mainWindow = qobject_cast<MainWindow*>(parentWidget() != nullptr
                ? parentWidget()->window()
                : nullptr);
            if (mainWindow != nullptr)
            {
                connect(mainWindow, &MainWindow::r0DriverServiceStarted, this,
                    [this, table, statusLabel, refreshButton]()
                    {
                        if (m_usageScanInProgress)
                        {
                            m_usageR0StartedDuringScan = true;
                            return;
                        }
                        if (!m_usageRetryAfterR0Start)
                        {
                            return;
                        }
                        m_usageRetryAfterR0Start = false;
                        refreshUsageTable(table, statusLabel, refreshButton);
                    });
            }

            if (m_initialTabKey == QStringLiteral("usage"))
            {
                // 从“文件占用与解锁”入口进入时直接扫描；
                // 普通属性窗口手动切页仍保持按需刷新，避免无意义的全系统枚举。
                QMetaObject::invokeMethod(
                    this,
                    [this, table, statusLabel, refreshButton]()
                    {
                        refreshUsageTable(table, statusLabel, refreshButton);
                    },
                    Qt::QueuedConnection);
            }
            return page;
        }

        QWidget* buildFileObjectTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            // 文件对象详情是“分组 + 名称: 值”的审计输出：
            // - 用属性树展示，字段可逐条复制，说明性整句跨列成行；
            // - 只读展示，不提供关闭句柄、解锁、删除等动作。

            const QString nativePath = QDir::toNativeSeparators(m_filePath);
            QString content;
            content += QStringLiteral("目标路径: %1\n").arg(nativePath);
            content += QStringLiteral("说明: 这里只做只读对象/句柄视图，不提供解锁、删除或绕过动作。\n\n");

            const QFileInfo info(m_filePath);
            const bool directoryHint = info.isDir();
            HANDLE fileHandle = openReadOnlyFileHandle(m_filePath, directoryHint);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                content += QStringLiteral("打开失败: %1\n").arg(::GetLastError());
                layout->addWidget(buildReportView(page, content), 1);
                return page;
            }

            QString standardInfoText;
            QString standardStatusText;
            const bool standardOk = queryFileStandardInfoText(fileHandle, standardInfoText, standardStatusText);
            content += QStringLiteral("[FileStandardInfo]\n");
            content += standardOk ? standardInfoText : QStringLiteral("读取失败: %1\n").arg(standardStatusText);
            content += QStringLiteral("\n[FileObject / Section / ControlArea]\n");
            const QString ntPathText = buildDriverNtPath(m_filePath);
            const ksword::ark::FileInfoQueryResult r0Info = queryR0FileInfo(info, ntPathText);
            content += formatR0FileInfoText(r0Info);
            const ksword::ark::FileSectionMappingsQueryResult sectionView =
                ksword::ark::DriverClient().queryFileSectionMappings(
                    ntPathText.toStdWString(),
                    KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL,
                    KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT);
            content += QStringLiteral("\n[ControlArea Cross-View]\n");
            if (sectionView.io.ok)
            {
                content += QStringLiteral("查询状态: %1\n").arg(sectionView.queryStatus);
                content += QStringLiteral("查询说明: %1\n").arg(friendlyFileIoMessage(sectionView.io.message));
                content += QStringLiteral("FileObject: %1\n").arg(formatHex64(sectionView.fileObjectAddress));
                content += QStringLiteral("SectionObjectPointers: %1\n").arg(formatHex64(sectionView.sectionObjectPointersAddress));
                content += QStringLiteral("DataControlArea: %1\n").arg(formatHex64(sectionView.dataControlAreaAddress));
                content += QStringLiteral("ImageControlArea: %1\n").arg(formatHex64(sectionView.imageControlAreaAddress));
                content += QStringLiteral("映射数量: %1 / %2\n")
                    .arg(sectionView.returnedCount)
                    .arg(sectionView.totalCount);
                content += QStringLiteral("跨视图：R3 文件标准信息给出 DeletePending；R0 侧给出 FileObject / SectionObjectPointers / ControlArea。\n");
            }
            else
            {
                content += QStringLiteral("查询失败: %1\n").arg(friendlyFileIoMessage(sectionView.io.message));
                content += QStringLiteral("跨视图：当前仅保留 R0 FileInfo 结果，ControlArea 查询降级。\n");
            }
            content += QStringLiteral("\n[Cross-View]\n");
            content += QStringLiteral("R0 FileObject: %1\n").arg(formatHex64(r0Info.fileObjectAddress));
            content += QStringLiteral("R0 SectionObjectPointers: %1\n").arg(formatHex64(r0Info.sectionObjectPointersAddress));
            content += QStringLiteral("R0 DataSectionObject: %1\n").arg(formatHex64(r0Info.dataSectionObjectAddress));
            content += QStringLiteral("R0 ImageSectionObject: %1\n").arg(formatHex64(r0Info.imageSectionObjectAddress));
            content += QStringLiteral("R3 DeletePending/Share: 通过 FileStandardInfo 和共享只读打开侧写。\n");
            content += QStringLiteral("R3 Shared flags: 采集句柄使用 READ|WRITE|DELETE 共享，仅用于只读探测。\n");
            ::CloseHandle(fileHandle);
            layout->addWidget(buildReportView(page, content), 1);
            return page;
        }

        QWidget* buildStorageTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            // 存储/BitLocker 审计输出同样是“分组 + 名称: 值”：
            // - 用属性树展示，卷栈、挂载点、BitLocker 状态各占一行，可单独复制；
            // - 页面仍只读，不提供卸载、解锁、绕过等动作。
            // 首屏只放占位报告：卷 IOCTL 与 4 个 R0 审计都在后台采集，切页不再等待。

            QString placeholderText;
            placeholderText += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(m_filePath));
            placeholderText += QStringLiteral("正在加载...\n");
            QWidget* placeholderReportView = buildReportView(page, placeholderText);
            layout->addWidget(placeholderReportView, 1);
            startStorageAuditLoad(page, placeholderReportView);
            return page;
        }

        void startStorageAuditLoad(QWidget* storagePage, QWidget* placeholderReportView)
        {
            // 用途：把 Storage / MountMgr / FVE 页的采集整体挪到后台线程。
            // 输入：storagePage 为该页根控件；placeholderReportView 为首屏占位报告视图。
            // 返回：无；采集完成后在 UI 线程用真实报告视图替换占位视图。
            // 原因：卷 IOCTL（IOCTL_STORAGE_QUERY_PROPERTY 可能唤旋休眠盘）与 4 个
            // ArkDriverClient 审计 IOCTL（每次都要 CreateFileW 打开设备再同步下发）
            // 串起来单次切页要 0.3-3 秒，留在 QTabWidget::currentChanged 里就是整窗卡死。
            if (storagePage == nullptr)
            {
                return;
            }

            const QString filePathSnapshot = m_filePath;
            QPointer<FileDetailDialog> guardThis(this);
            QPointer<QWidget> pageGuard(storagePage);
            QPointer<QWidget> placeholderGuard(placeholderReportView);
            auto* task = QRunnable::create(
                [guardThis, pageGuard, placeholderGuard, filePathSnapshot]()
                {
                    // 后台只产出报告文本这一个值类型，不碰任何 QWidget。
                    const QString reportText = buildStorageAuditReportText(filePathSnapshot);

                    FileDetailDialog* const targetDialog = guardThis.data();
                    if (targetDialog == nullptr)
                    {
                        return;
                    }

                    QMetaObject::invokeMethod(
                        targetDialog,
                        [guardThis, pageGuard, placeholderGuard, reportText]()
                        {
                            if (guardThis.isNull() || pageGuard.isNull())
                            {
                                return;
                            }

                            QWidget* const page = pageGuard.data();
                            QVBoxLayout* const pageLayout = qobject_cast<QVBoxLayout*>(page->layout());
                            if (pageLayout == nullptr)
                            {
                                return;
                            }

                            if (!placeholderGuard.isNull())
                            {
                                pageLayout->removeWidget(placeholderGuard.data());
                                placeholderGuard->hide();
                                placeholderGuard->deleteLater();
                            }
                            pageLayout->addWidget(buildReportView(page, reportText), 1);
                            // 采集回来后才建的视图同样要拿到 Surface 调色板，不能回退到系统 Base。
                            guardThis->applyThemeStyle();
                        },
                        Qt::QueuedConnection);
                });
            task->setAutoDelete(true);
            QThreadPool::globalInstance()->start(task);
        }

        static QString buildStorageAuditReportText(const QString& filePathText)
        {
            // 用途：生成 Storage / MountMgr / FVE 页的完整只读报告文本。
            // 输入：filePathText 为目标文件路径。
            // 返回：可直接交给 buildReportView 的报告原文。
            // 约束：本函数只做数据采集与字符串拼接，必须在后台线程调用。
            const FileVolumeAuditSnapshot snapshot = queryFileVolumeAuditSnapshot(filePathText);
            QString content;
            content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(filePathText));
            content += QStringLiteral("卷根: %1\n").arg(snapshot.volumeRoot.isEmpty() ? QStringLiteral("<unknown>") : snapshot.volumeRoot);
            content += QStringLiteral("卷栈: %1\n").arg(snapshot.volumeStackText.isEmpty() ? QStringLiteral("<unknown>") : snapshot.volumeStackText);
            content += QStringLiteral("挂载点: %1\n").arg(snapshot.mountPointsText.isEmpty() ? QStringLiteral("<unknown>") : snapshot.mountPointsText);
            content += QStringLiteral("设备路径: %1\n").arg(snapshot.devicePathText.isEmpty() ? QStringLiteral("<unknown>") : snapshot.devicePathText);
            content += QStringLiteral("文件系统: %1\n").arg(snapshot.fsNameText.isEmpty() ? QStringLiteral("<unknown>") : snapshot.fsNameText);
            content += QStringLiteral("卷标: %1\n").arg(snapshot.labelText.isEmpty() ? QStringLiteral("<unknown>") : snapshot.labelText);
            content += QStringLiteral("存储描述: %1\n").arg(snapshot.storageText.isEmpty() ? QStringLiteral("<unknown>") : snapshot.storageText);
            content += QStringLiteral("BitLocker: %1\n").arg(snapshot.bitLockerText.isEmpty() ? QStringLiteral("<unknown>") : snapshot.bitLockerText);
            content += QStringLiteral("\n说明：本页只展示可见状态，不做解锁、卸载、绕过或密钥导出。\n");
            content += QStringLiteral("说明：DeviceObject 在此页以卷设备路径做只读侧写，不触碰内核对象本身。\n");

            // R0 审计补充：
            // - 只通过 ArkDriverClient 调用只读 wrapper；
            // - volumeAuditPath 优先使用 NT 设备路径，缺失时退回卷根；
            // - 每个 wrapper 均输出 IO、计数、截断和 message，便于和 R3 侧结果交叉核对。
            const QString volumeAuditPath = snapshot.devicePathText.isEmpty()
                ? snapshot.volumeRoot
                : snapshot.devicePathText;
            const std::wstring volumeAuditPathWide = volumeAuditPath.toStdWString();
            const ksword::ark::DriverClient driverClient;

            const ksword::ark::StorageVolumeStackAuditResult volumeStackAudit =
                driverClient.queryVolumeStackAudit(volumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / VolumeStack"),
                volumeStackAudit,
                volumeStackAudit.responseFlags,
                false);
            content += formatVolumeStackAuditRows(volumeStackAudit);

            const ksword::ark::StorageMountMgrMappingAuditResult mountMgrAudit =
                driverClient.queryMountMgrMappingAudit(volumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / MountMgr"),
                mountMgrAudit,
                mountMgrAudit.responseFlags,
                false);
            content += formatMountMgrMappingAuditRows(mountMgrAudit);

            const ksword::ark::StorageFilesystemIntegrityAuditResult filesystemAudit =
                driverClient.queryFilesystemIntegrityAudit(volumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / FilesystemIntegrity"),
                filesystemAudit,
                filesystemAudit.responseFlags,
                false);
            content += formatFilesystemIntegrityAuditRows(filesystemAudit);

            const ksword::ark::StorageBitlockerFveAuditResult bitlockerAudit =
                driverClient.queryBitlockerFveAudit(volumeAuditPathWide);
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / BitLocker FVE"),
                bitlockerAudit,
                bitlockerAudit.responseFlags,
                false);
            content += formatBitlockerFveAuditRows(bitlockerAudit);
            return content;
        }

        QWidget* buildFilterTopologyTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            // Minifilter 拓扑同样是“分组 + 名称: 值”的审计明细：
            // - 用属性树展示，每个过滤器/实例/卷的字段可逐条复制；
            // - 页面只展示枚举和 R0 inventory，不提供 detach/bypass/remove。

            QString content;
            content += QStringLiteral("目标路径: %1\n").arg(QDir::toNativeSeparators(m_filePath));
            content += QStringLiteral("说明: 本页只展示 FilterManager 公开枚举接口与字段定义，不做卸载、绕过或拦截修改。\n\n");
            content += enumerateMinifilterText();
            content += QStringLiteral("\n");
            content += enumerateInstanceText();
            content += QStringLiteral("\n");
            content += enumerateVolumeText();

            // R0 审计补充：
            // - queryMinifilterInventory 通过 ArkDriverClient 统一访问驱动；
            // - 结果追加在 FilterManager 公开枚举之后，保留原有 R3 逻辑；
            // - 不提供卸载、detach、bypass、callback 修改等动作。
            const ksword::ark::MinifilterInventoryResult minifilterAudit =
                ksword::ark::DriverClient().queryMinifilterInventory();
            content += QStringLiteral("\n");
            content += formatAuditResultHeader(
                QStringLiteral("R0 审计补充 / MinifilterInventory"),
                minifilterAudit,
                minifilterAudit.responseFlags,
                (minifilterAudit.responseFlags & KSWORD_ARK_MINIFILTER_INVENTORY_RESPONSE_FLAG_TRUNCATED) != 0U);
            content += formatMinifilterInventoryRows(minifilterAudit);
            layout->addWidget(buildReportView(page, content), 1);
            return page;
        }

        QWidget* buildSignatureTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);
            layout->addWidget(textEditorWidget, 1);
            startSignatureLoad(textEditorWidget);
            return page;
        }

        QWidget* buildPeTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);

            layout->addWidget(textEditorWidget, 1);
            startPeAnalysisLoad(textEditorWidget);
            return page;
        }

        QWidget* buildDependencyTab()
        {
            // 用途：创建“依赖 DLL”页 UI。
            // 处理：表格展示 DLL/函数/Ordinal/Hint/IAT RVA，底部文本显示摘要或错误；
            //      真实 PE Import Directory 解析由后台线程完成。
            // 返回：可嵌入属性窗口的 QWidget。
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            QLabel* statusLabel = new QLabel(QStringLiteral("● 等待加载依赖 DLL"), page);
            statusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(statusLabel, 0);

            QTableWidget* table = new ks::ui::VisibleTableWidget(page);
            table->setColumnCount(6);
            table->setHorizontalHeaderLabels(QStringList{
                QStringLiteral("DLL 名称"),
                QStringLiteral("函数名 / Ordinal"),
                QStringLiteral("Hint"),
                QStringLiteral("导入方式"),
                QStringLiteral("Thunk/IAT RVA"),
                QStringLiteral("诊断")
                });
            table->setAlternatingRowColors(true);
            table->setSelectionBehavior(QAbstractItemView::SelectRows);
            table->setSelectionMode(QAbstractItemView::ExtendedSelection);
            table->setEditTriggers(QAbstractItemView::NoEditTriggers);
            table->setSortingEnabled(true);
            table->setContextMenuPolicy(Qt::CustomContextMenu);
            if (table->horizontalHeader() != nullptr)
            {
                table->horizontalHeader()->setStretchLastSection(true);
            }
            layout->addWidget(table, 3);

            CodeEditorWidget* detailEditor = new CodeEditorWidget(page);
            detailEditor->setReadOnly(true);
            layout->addWidget(detailEditor, 1);

            connect(table, &QTableWidget::customContextMenuRequested, this, [table](const QPoint& position)
                {
                    if (table == nullptr)
                    {
                        return;
                    }

                    QMenu menu(table);
                    menu.setStyleSheet(buildContextMenuStyle());
                    QAction* copyRowsAction = menu.addAction(QStringLiteral("复制选中行"));
                    QAction* copyDllAction = menu.addAction(QStringLiteral("复制 DLL 名称"));
                    QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(position));
                    if (selectedAction == nullptr)
                    {
                        return;
                    }
                    if (selectedAction != copyRowsAction && selectedAction != copyDllAction)
                    {
                        return;
                    }

                    const bool dllOnly = selectedAction == copyDllAction;
                    const QString clipboardText = dependencyRowsToClipboardText(table, dllOnly);
                    if (!clipboardText.isEmpty() && QApplication::clipboard() != nullptr)
                    {
                        QApplication::clipboard()->setText(clipboardText);
                    }
                });

            startDependencyLoad(table, statusLabel, detailEditor);
            return page;
        }

        QWidget* buildStringsTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);
            CodeEditorWidget* textEditorWidget = new CodeEditorWidget(page);
            textEditorWidget->setReadOnly(true);
            layout->addWidget(textEditorWidget, 1);
            startStringsLoad(textEditorWidget);

            return page;
        }

        QWidget* buildHexTab()
        {
            QWidget* page = new QWidget(this);
            QVBoxLayout* layout = new QVBoxLayout(page);

            // 统一复用 HexEditorWidget，避免各处重复实现十六进制转储逻辑。
            HexEditorWidget* hexEditorWidget = new HexEditorWidget(page);
            hexEditorWidget->setEditable(false);
            hexEditorWidget->setBytesPerRow(16);
            layout->addWidget(hexEditorWidget, 1);

            // hexHintLabel 用途：提示用户该页面默认仅预览文件前部字节。
            QLabel* hexHintLabel = new QLabel(page);
            hexHintLabel->setWordWrap(true);
            layout->addWidget(hexHintLabel, 0);

            // 文件详情页只读取前 2MB，防止超大文件导致属性窗口卡顿。
            constexpr qint64 kMaxPreviewBytes = 2 * 1024 * 1024;
            QFile file(m_filePath);
            if (!file.open(QIODevice::ReadOnly))
            {
                hexHintLabel->setText(QStringLiteral("无法读取文件，无法显示十六进制。"));
                hexEditorWidget->clearData();
                return page;
            }

            const qint64 totalBytes = file.size();
            const QByteArray bytes = file.read(kMaxPreviewBytes);
            file.close();

            if (bytes.isEmpty())
            {
                hexHintLabel->setText(QStringLiteral("文件为空。"));
                hexEditorWidget->clearData();
                return page;
            }

            // 直接把预览字节交给 HexEditorWidget，使用统一滚动、查找、跳转能力。
            hexEditorWidget->setByteArray(bytes, 0);

            if (totalBytes > bytes.size())
            {
                hexHintLabel->setText(
                    QStringLiteral("当前仅预览文件前 %1 字节，总大小 %2 字节。")
                    .arg(bytes.size())
                    .arg(totalBytes));
            }
            else
            {
                hexHintLabel->setText(
                    QStringLiteral("已加载完整文件，共 %1 字节。")
                    .arg(totalBytes));
            }

            return page;
        }

    private:
        QStringList m_filePaths; // 当前详情窗口对应的全部目标；单文件模式仅一项。
        QString m_filePath;   // 单文件目标或批量模式第一项，供现有只读分析页复用。
        bool m_batchMode = false; // 多目标时只开放常规汇总、批量哈希与元数据编辑。
        QString m_initialTabKey; // 外部入口指定的初始页；usage 入口会自动扫描。
        QWidget* m_tabNavigation = nullptr; // 文件属性左侧导航容器。
        QTabWidget* m_tabWidget = nullptr; // 继续承载现有的页面与懒加载机制。
        QButtonGroup* m_tabNavigationButtonGroup = nullptr; // 保证左侧导航单选。
        QVector<QToolButton*> m_tabNavigationButtons; // 与 Tab 索引一一对应，供切页时同步选中态。
        QTreeWidget* m_generalPropertyTree = nullptr; // 常规页属性树，语言切换或 R0 返回时整棵重建。
        CodeEditorWidget* m_generalTextEditor = nullptr; // 常规页文本视图，内容由属性树导出，随树同步刷新。
        QString m_generalNtPathText; // 常规页复用的 NT 路径，避免切换语言时重复查询。
        bool m_generalR0Loaded = false; // R0 文件信息是否已完成后台读取。
        ksword::ark::FileInfoQueryResult m_generalR0Info{}; // 保留原始 R0 数据供双语重绘。
        std::uint64_t m_generalR0LoadGeneration = 0U; // 淘汰元数据写入前发起的旧 R0 查询。
        std::array<QCheckBox*, 4> m_metadataTimeChecks{}; // 四个时间字段的逐项写入开关。
        std::array<QDateTimeEdit*, 4> m_metadataTimeEdits{}; // 四个本地时间编辑器。
        std::array<QCheckBox*, 6> m_metadataAttributeChecks{}; // 六个可直接切换的属性位。
        std::array<bool, 6> m_metadataAttributeTouched{}; // 批量混合状态下只写入用户实际切换的属性。
        bool m_metadataApplyingSnapshot = false; // 回填混合状态时不把程序赋值误判为用户修改。
        QPushButton* m_metadataRefreshButton = nullptr; // 重新读取最新 FileBasicInfo。
        QPushButton* m_metadataApplyButton = nullptr; // 把基础元数据改动加入统一暂存事务。
        QLabel* m_metadataStatusLabel = nullptr; // 读取、写入与回读验证状态。
        FileMetadataSnapshot m_metadataSnapshot{}; // 编辑器当前展示的属性快照。
        bool m_metadataHasSnapshot = false; // 防止读取失败后使用未初始化值写入。
        bool m_metadataEditorBusy = false; // 防止重复读取或重复应用。
        std::uint64_t m_metadataOperationGeneration = 0U; // 淘汰关闭/刷新后迟到的后台结果。
        QList<ks::file::metadata::TargetPatch> m_pendingPatches; // 各目标的统一 R3 暂存补丁。
        QCheckBox* m_backupBeforeSaveCheck = nullptr; // 保存前复制目标或生成目录元数据清单。
        QLabel* m_pendingChangesLabel = nullptr; // 底部统一保存栏的待处理摘要。
        QPushButton* m_discardPendingButton = nullptr; // 放弃全部未写入补丁。
        QPushButton* m_saveAllButton = nullptr; // 唯一会触发文件写入的入口。
        bool m_transactionBusy = false; // 保存事务运行期间锁定编辑和重复提交。
        std::shared_ptr<std::atomic_bool> m_hashCancelRequested; // 哈希计算取消标记，后台线程共享。
        std::shared_ptr<std::atomic_bool> m_usageScanCancelRequested; // 文件占用扫描取消标记，关闭属性窗时置位。
        QProgressBar* m_usageScanProgressBar = nullptr; // 属性页文件占用扫描的阶段进度条。
        bool m_usageScanInProgress = false; // 属性页占用扫描是否仍在后台执行。
        bool m_usageRetryAfterR0Start = false; // R3 回落结果是否等待下一次 R0 启动成功后重扫。
        bool m_usageR0StartedDuringScan = false; // R0 是否在当前 R3 回落扫描完成前已经启动。
        bool m_themeStyleApplying = false; // 避免 PaletteChange 触发样式重入。
    };

    // kRecoveryVolumeProbeGenerationProperty 作用：
    // - 用途：记录“这是第几次卷探测请求”，以动态属性挂在恢复页的卷下拉框上；
    // - 入参：无（作为 QObject::property/setProperty 的键使用）；
    // - 返回：无。之所以不放进 FileDock 成员，是为了在不改动 FileDock.h 的前提下
    //   仍然具备“淘汰被新请求取代的旧结果”的能力。
    constexpr const char* const kRecoveryVolumeProbeGenerationProperty =
        "ks_recovery_volume_probe_generation";

    // kFileDeleteInProgressProperty 作用：
    // - 用途：标记“删除任务正在后台执行”，以动态属性挂在 FileDock 上；
    // - 入参：无（作为 QObject::property/setProperty 的键使用）；
    // - 返回：无。语义与 m_transferInProgress 一致，同样只用于防重入。
    constexpr const char* const kFileDeleteInProgressProperty = "ks_file_delete_in_progress";

    // collectNtfsVolumeRootList 作用：
    // - 用途：枚举当前可用于误删扫描的 NTFS 卷根，必须在后台线程调用；
    // - 入参：无；内部自行枚举逻辑盘；
    // - 返回：NTFS 卷根路径列表（原生分隔符，例如 C:\）。
    // 说明：GetVolumeInformationW 在空光驱上会等待介质就绪、在断线的映射网络盘上会等待
    // SMB 会话超时，所以先用 GetDriveTypeW 把光驱、网络映射和无根设备挡掉；同时用
    // SetThreadErrorMode 关闭本线程的“请插入磁盘”系统弹窗，避免后台探测把模态框弹到用户脸上。
    QVector<QString> collectNtfsVolumeRootList()
    {
        QVector<QString> ntfsVolumeRootList;

        DWORD previousThreadErrorMode = 0;
        const bool threadErrorModeChanged =
            ::SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previousThreadErrorMode) != FALSE;

        const QFileInfoList driveInfoList = QDir::drives();
        for (const QFileInfo& driveInfo : driveInfoList)
        {
            const QString volumeRootPath = QDir::toNativeSeparators(driveInfo.absoluteFilePath());
            const UINT driveTypeValue = ::GetDriveTypeW(volumeRootPath.toStdWString().c_str());
            if (driveTypeValue == DRIVE_CDROM
                || driveTypeValue == DRIVE_REMOTE
                || driveTypeValue == DRIVE_NO_ROOT_DIR
                || driveTypeValue == DRIVE_UNKNOWN)
            {
                // 这几类要么必然不是可做误删扫描的本地卷，要么正是把 GetVolumeInformationW
                // 拖到数秒甚至数十秒的元凶，直接跳过，不做后续探测。
                continue;
            }

            const ks::file::ManualFsType fileSystemType =
                ks::file::ManualFileSystemParser::detectFileSystemType(volumeRootPath);
            if (fileSystemType != ks::file::ManualFsType::Ntfs)
            {
                continue;
            }

            ntfsVolumeRootList.push_back(volumeRootPath);
        }

        if (threadErrorModeChanged)
        {
            ::SetThreadErrorMode(previousThreadErrorMode, nullptr);
        }
        return ntfsVolumeRootList;
    }
}

struct FileDock::FileOplockAccessRecord
{
    std::uint32_t processId = 0U;
    QString processName;
    QString processImagePath;
    std::uint64_t hitCount = 0U;
    std::uint64_t handleHitCount = 0U;
    std::uint64_t firstBreakSequence = 0U;
    std::uint64_t lastBreakSequence = 0U;
    std::uint64_t lastHandleValue = 0U;
    std::uint32_t lastGrantedAccess = 0U;
    QString firstSeenText;
    QString lastSeenText;
    QStringList matchedTargetList;
    QStringList matchRuleList;
    QStringList enumerationSourceList;
    QStringList objectNameList;
};

struct FileDock::FileOplockEntry
{
    QString path;
    FileOplockLevel level = FileOplockLevel::Level1;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    HANDLE eventHandle = nullptr;
    OVERLAPPED overlapped{};
    bool ioPending = false;
    std::thread waitThread;
    std::mutex ioMutex;
    std::mutex accessRecordMutex;
    std::vector<FileOplockAccessRecord> accessRecords;
    QString lastAccessScanDiagnostic;
    std::uint64_t uncapturedBreakCount = 0U;
    std::atomic_bool releaseRequested{ false };
    std::atomic_bool rearmWarningReported{ false };
    std::atomic<std::uint64_t> breakCount{ 0 };

    ~FileOplockEntry()
    {
        closeWin32Handle(fileHandle);
        closeWin32Handle(eventHandle);
    }
};

QString FileDock::fileOplockLevelText(const FileOplockLevel level)
{
    switch (level)
    {
    case FileOplockLevel::Level1:
        return QStringLiteral("Level 1");
    case FileOplockLevel::Level2:
        return QStringLiteral("Level 2");
    case FileOplockLevel::Batch:
        return QStringLiteral("Batch");
    case FileOplockLevel::Filter:
        return QStringLiteral("Filter");
    }
    return QStringLiteral("Level 1");
}

unsigned long FileDock::fileOplockControlCode(const FileOplockLevel level)
{
    switch (level)
    {
    case FileOplockLevel::Level1:
        return FSCTL_REQUEST_OPLOCK_LEVEL_1;
    case FileOplockLevel::Level2:
        return FSCTL_REQUEST_OPLOCK_LEVEL_2;
    case FileOplockLevel::Batch:
        return FSCTL_REQUEST_BATCH_OPLOCK;
    case FileOplockLevel::Filter:
        return FSCTL_REQUEST_FILTER_OPLOCK;
    }
    return FSCTL_REQUEST_OPLOCK_LEVEL_1;
}

bool FileDock::requestFileOplock(FileOplockEntry& entry, unsigned long& requestError)
{
    requestError = ERROR_SUCCESS;
    if (entry.releaseRequested.load())
    {
        requestError = ERROR_OPERATION_ABORTED;
        return false;
    }

    std::lock_guard<std::mutex> lock(entry.ioMutex);
    if (entry.releaseRequested.load())
    {
        requestError = ERROR_OPERATION_ABORTED;
        return false;
    }
    if (entry.fileHandle == nullptr ||
        entry.fileHandle == INVALID_HANDLE_VALUE ||
        entry.eventHandle == nullptr)
    {
        requestError = ERROR_INVALID_HANDLE;
        return false;
    }

    (void)::ResetEvent(entry.eventHandle);
    entry.overlapped = OVERLAPPED{};
    entry.overlapped.hEvent = entry.eventHandle;

    const BOOL requestOk = ::DeviceIoControl(
        entry.fileHandle,
        static_cast<DWORD>(fileOplockControlCode(entry.level)),
        nullptr,
        0,
        nullptr,
        0,
        nullptr,
        &entry.overlapped);
    requestError = requestOk ? ERROR_SUCCESS : ::GetLastError();
    entry.ioPending = requestOk == FALSE && requestError == ERROR_IO_PENDING;
    if (requestOk != FALSE)
    {
        return false;
    }
    if (requestError == ERROR_IO_PENDING)
    {
        entry.rearmWarningReported.store(false);
        return true;
    }

    return false;
}

bool FileDock::acknowledgeFileOplockBreak(FileOplockEntry& entry, unsigned long& acknowledgeError)
{
    acknowledgeError = ERROR_SUCCESS;
    if (entry.level == FileOplockLevel::Level2 || entry.releaseRequested.load())
    {
        return true;
    }
    if (entry.fileHandle == nullptr || entry.fileHandle == INVALID_HANDLE_VALUE)
    {
        acknowledgeError = ERROR_INVALID_HANDLE;
        return false;
    }

    DWORD bytesReturned = 0;
    BOOL acknowledgeOk = FALSE;
    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    {
        std::lock_guard<std::mutex> lock(entry.ioMutex);
        if (entry.releaseRequested.load())
        {
            acknowledgeError = ERROR_OPERATION_ABORTED;
            return false;
        }
        if (entry.fileHandle == nullptr ||
            entry.fileHandle == INVALID_HANDLE_VALUE ||
            entry.eventHandle == nullptr)
        {
            acknowledgeError = ERROR_INVALID_HANDLE;
            return false;
        }

        fileHandle = entry.fileHandle;
        (void)::ResetEvent(entry.eventHandle);
        entry.overlapped = OVERLAPPED{};
        entry.overlapped.hEvent = entry.eventHandle;
        acknowledgeOk = ::DeviceIoControl(
            fileHandle,
            FSCTL_OPLOCK_BREAK_ACK_NO_2,
            nullptr,
            0,
            nullptr,
            0,
            &bytesReturned,
            &entry.overlapped);
        acknowledgeError = acknowledgeOk ? ERROR_SUCCESS : ::GetLastError();
        entry.ioPending = acknowledgeOk == FALSE && acknowledgeError == ERROR_IO_PENDING;
    }

    if (!acknowledgeOk && acknowledgeError == ERROR_IO_PENDING)
    {
        acknowledgeOk = ::GetOverlappedResult(
            fileHandle,
            &entry.overlapped,
            &bytesReturned,
            TRUE);
        acknowledgeError = acknowledgeOk ? ERROR_SUCCESS : ::GetLastError();
        {
            std::lock_guard<std::mutex> lock(entry.ioMutex);
            entry.ioPending = false;
        }
    }

    return acknowledgeOk != FALSE;
}

void FileDock::cancelFileOplockRequest(FileOplockEntry& entry)
{
    std::lock_guard<std::mutex> lock(entry.ioMutex);
    if (entry.fileHandle != nullptr && entry.fileHandle != INVALID_HANDLE_VALUE)
    {
        if (entry.ioPending)
        {
            (void)::CancelIoEx(entry.fileHandle, &entry.overlapped);
        }
    }
    if (!entry.ioPending && entry.eventHandle != nullptr)
    {
        (void)::SetEvent(entry.eventHandle);
    }
}

std::size_t FileDock::recordFileOplockAccessPrograms(
    FileOplockEntry& entry,
    const std::uint64_t breakSequence)
{
    if (entry.path.trimmed().isEmpty() || entry.releaseRequested.load())
    {
        return 0U;
    }

    const std::vector<QString> scanTargets{ entry.path };
    const filedock::handleusage::HandleUsageScanResult scanResult =
        filedock::handleusage::scanHandleUsageByPaths(scanTargets, 0, true);

    const std::uint32_t currentProcessId = static_cast<std::uint32_t>(::GetCurrentProcessId());
    const QString nowText = QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz"));
    std::map<std::uint32_t, FileOplockAccessRecord> scanRecordByPid;
    for (const filedock::handleusage::HandleUsageEntry& scanEntry : scanResult.entries)
    {
        if (scanEntry.processId == 0U ||
            scanEntry.processId <= 4U ||
            scanEntry.processId == currentProcessId)
        {
            continue;
        }

        FileOplockAccessRecord& scanRecord = scanRecordByPid[scanEntry.processId];
        if (scanRecord.processId == 0U)
        {
            scanRecord.processId = scanEntry.processId;
            scanRecord.processName = scanEntry.processName.trimmed();
            scanRecord.processImagePath = scanEntry.processImagePath.trimmed();
            scanRecord.firstBreakSequence = breakSequence;
            scanRecord.firstSeenText = nowText;
        }
        if (scanRecord.processName.isEmpty() && !scanEntry.processName.trimmed().isEmpty())
        {
            scanRecord.processName = scanEntry.processName.trimmed();
        }
        if (scanRecord.processImagePath.isEmpty() && !scanEntry.processImagePath.trimmed().isEmpty())
        {
            scanRecord.processImagePath = scanEntry.processImagePath.trimmed();
        }

        scanRecord.lastBreakSequence = breakSequence;
        scanRecord.lastSeenText = nowText;
        scanRecord.handleHitCount += 1U;
        scanRecord.lastHandleValue = scanEntry.handleValue;
        scanRecord.lastGrantedAccess = scanEntry.grantedAccess;
        appendUniqueText(scanRecord.matchedTargetList, scanEntry.matchedTargetPath);
        appendUniqueText(scanRecord.matchRuleList, scanEntry.matchRuleText);
        appendUniqueText(scanRecord.enumerationSourceList, scanEntry.enumerationSource);
        appendUniqueText(scanRecord.objectNameList, scanEntry.objectName);
    }

    std::lock_guard<std::mutex> lock(entry.accessRecordMutex);
    entry.lastAccessScanDiagnostic = scanResult.diagnosticText.trimmed().isEmpty()
        ? QStringLiteral("-")
        : scanResult.diagnosticText.simplified();
    if (scanRecordByPid.empty())
    {
        entry.uncapturedBreakCount += 1U;
        return 0U;
    }

    for (const auto& scanPair : scanRecordByPid)
    {
        const FileOplockAccessRecord& scanRecord = scanPair.second;
        auto existingIterator = std::find_if(
            entry.accessRecords.begin(),
            entry.accessRecords.end(),
            [&scanRecord](const FileOplockAccessRecord& record) {
                return record.processId == scanRecord.processId;
            });

        if (existingIterator == entry.accessRecords.end())
        {
            FileOplockAccessRecord newRecord = scanRecord;
            newRecord.hitCount = 1U;
            entry.accessRecords.push_back(newRecord);
            continue;
        }

        FileOplockAccessRecord& existingRecord = *existingIterator;
        existingRecord.hitCount += 1U;
        existingRecord.handleHitCount += scanRecord.handleHitCount;
        existingRecord.lastBreakSequence = scanRecord.lastBreakSequence;
        existingRecord.lastSeenText = scanRecord.lastSeenText;
        existingRecord.lastHandleValue = scanRecord.lastHandleValue;
        existingRecord.lastGrantedAccess = scanRecord.lastGrantedAccess;
        if (existingRecord.processName.isEmpty() && !scanRecord.processName.isEmpty())
        {
            existingRecord.processName = scanRecord.processName;
        }
        if (existingRecord.processImagePath.isEmpty() && !scanRecord.processImagePath.isEmpty())
        {
            existingRecord.processImagePath = scanRecord.processImagePath;
        }
        for (const QString& text : scanRecord.matchedTargetList)
        {
            appendUniqueText(existingRecord.matchedTargetList, text);
        }
        for (const QString& text : scanRecord.matchRuleList)
        {
            appendUniqueText(existingRecord.matchRuleList, text);
        }
        for (const QString& text : scanRecord.enumerationSourceList)
        {
            appendUniqueText(existingRecord.enumerationSourceList, text);
        }
        for (const QString& text : scanRecord.objectNameList)
        {
            appendUniqueText(existingRecord.objectNameList, text);
        }
    }

    return scanRecordByPid.size();
}

FileDock::FileDock(QWidget* parent)
    : QWidget(parent)
{
    // 构造日志：记录文件模块启动。
    kLogEvent event;
    info << event << "[FileDock] 构造开始，初始化双栏资源管理器。" << eol;

    initializeUi();
}

FileDock::~FileDock()
{
    // 析构阶段先释放持有型 Oplock，再停止解锁器后台线程。
    releaseAllActiveOplocks(false);
    m_unlockerWorkerStopRequested.store(true);
    std::thread workerThread;
    {
        std::lock_guard<std::mutex> lock(m_unlockerWorkerMutex);
        if (m_unlockerWorkerThread.joinable())
        {
            workerThread = std::move(m_unlockerWorkerThread);
        }
    }
    if (workerThread.joinable())
    {
        workerThread.join();
    }
}

void FileDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    const auto refreshPanelView = [](FilePanelWidgets& panel)
        {
            if (panel.fileView != nullptr && panel.fileView->viewport() != nullptr)
            {
                // ReparseAwareFileSystemModel::data() 按当前语言即时生成大小和类型；
                // 主动刷新 viewport，避免等待目录变化或重新启动后才重新取数。
                panel.fileView->viewport()->update();
            }
            if (panel.compactFileView != nullptr && panel.compactFileView->viewport() != nullptr)
            {
                panel.compactFileView->viewport()->update();
            }
        };
    refreshPanelView(m_leftPanel);
    refreshPanelView(m_rightPanel);
}

bool FileDock::eventFilter(QObject* watched, QEvent* event)
{
    // 读取方式下拉框吞掉滚轮：它的每一次切换都会触发一轮目录重解析，
    // 纯 MFT / R0 IRP 这两种还是全卷级别的重活。鼠标从列表滚到工具条上时
    // 一次滚动就能连着切好几档，等于连续排队几轮全盘扫描。
    // 切换必须是用户点开下拉框做出的明确选择。
    if (event != nullptr && event->type() == QEvent::Wheel &&
        ((m_leftPanel.readModeCombo != nullptr && watched == m_leftPanel.readModeCombo) ||
         (m_rightPanel.readModeCombo != nullptr && watched == m_rightPanel.readModeCombo)))
    {
        return true;
    }

    // QFileSystemModel/QTreeView 在右键按下阶段会按默认鼠标选择规则更新当前行。
    // 这里提前处理文件列表 viewport 的右键：命中已选中行时保留现有多选集合；
    // 命中未选中行时切换为该单行，保证后续自定义菜单读取 selectedPaths() 一致。
    if (event != nullptr && event->type() == QEvent::MouseButtonPress)
    {
        QMouseEvent* const mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent != nullptr && mouseEvent->button() == Qt::RightButton)
        {
            FilePanelWidgets* targetPanel = nullptr;
            QAbstractItemView* targetView = nullptr;
            if (m_leftPanel.fileView != nullptr && watched == m_leftPanel.fileView->viewport())
            {
                targetPanel = &m_leftPanel;
                targetView = m_leftPanel.fileView;
            }
            else if (m_rightPanel.fileView != nullptr && watched == m_rightPanel.fileView->viewport())
            {
                targetPanel = &m_rightPanel;
                targetView = m_rightPanel.fileView;
            }
            else if (m_leftPanel.compactFileView != nullptr && watched == m_leftPanel.compactFileView->viewport())
            {
                targetPanel = &m_leftPanel;
                targetView = m_leftPanel.compactFileView;
            }
            else if (m_rightPanel.compactFileView != nullptr && watched == m_rightPanel.compactFileView->viewport())
            {
                targetPanel = &m_rightPanel;
                targetView = m_rightPanel.compactFileView;
            }

            if (targetPanel != nullptr && targetView != nullptr)
            {
                const QModelIndex hitIndex = targetView->indexAt(mouseEvent->pos());
                QItemSelectionModel* const selectionModel = targetView->selectionModel();
                if (hitIndex.isValid() && selectionModel != nullptr)
                {
                    const QModelIndex hitRowIndex = hitIndex.siblingAtColumn(0);
                    const bool hitAlreadySelected =
                        selectionModel->isRowSelected(hitIndex.row(), hitIndex.parent()) ||
                        (hitRowIndex.isValid() && selectionModel->isSelected(hitRowIndex));
                    if (!hitAlreadySelected)
                    {
                        selectionModel->select(hitIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
                    }
                    // 只更新 current index，不调用 QTreeView::setCurrentIndex()，避免 Qt 按普通点击规则清掉多选集合。
                    selectionModel->setCurrentIndex(hitIndex, QItemSelectionModel::NoUpdate);
                    return true;
                }
            }
        }
    }

    return QWidget::eventFilter(watched, event);
}

void FileDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    // 顶层改为竖排 Tab：文件管理 + 文件恢复。
    m_rootTabWidget = new QTabWidget(this);
    m_rootTabWidget->setTabPosition(QTabWidget::West);
    m_rootTabWidget->setDocumentMode(true);
    m_rootLayout->addWidget(m_rootTabWidget, 1);

    m_fileManagerPage = new QWidget(m_rootTabWidget);
    QVBoxLayout* managerLayout = new QVBoxLayout(m_fileManagerPage);
    managerLayout->setContentsMargins(0, 0, 0, 0);
    managerLayout->setSpacing(0);

    m_mainSplitter = new QSplitter(Qt::Horizontal, m_fileManagerPage);
    // 文件管理双栏的分界线必须由用户和可用 viewport 决定：
    // - 不允许某一侧文件列表因长文件名/表头列宽变化把对侧挤开；
    // - 子面板不可折叠，避免极窄窗口下某侧被内容最小宽度吞掉。
    m_mainSplitter->setChildrenCollapsible(false);
    managerLayout->addWidget(m_mainSplitter, 1);

    initializePanel(m_leftPanel, QStringLiteral("左侧面板"));
    initializePanel(m_rightPanel, QStringLiteral("右侧面板"));
    m_mainSplitter->addWidget(m_leftPanel.rootWidget);
    m_mainSplitter->addWidget(m_rightPanel.rootWidget);
    m_mainSplitter->setStretchFactor(0, 1);
    m_mainSplitter->setStretchFactor(1, 1);

    m_rootTabWidget->addTab(m_fileManagerPage, QStringLiteral("文件管理"));
    initializeRecoveryPage();
    if (m_fileRecoveryPage != nullptr)
    {
        m_rootTabWidget->addTab(m_fileRecoveryPage, QStringLiteral("文件恢复"));
    }
    initializeIrpBuilderPage();
    if (m_irpBuilderPage != nullptr)
    {
        m_rootTabWidget->addTab(m_irpBuilderPage, QStringLiteral("IRP 构造"));
    }
    ks::i18n::LanguageManager::instance().bindTab(
        m_rootTabWidget, m_fileManagerPage, QStringLiteral("file.tab.manager"), QStringLiteral("文件管理"));
    if (m_fileRecoveryPage != nullptr)
    {
        ks::i18n::LanguageManager::instance().bindTab(
            m_rootTabWidget, m_fileRecoveryPage, QStringLiteral("file.tab.recovery"), QStringLiteral("文件恢复"));
    }
    if (m_irpBuilderPage != nullptr)
    {
        ks::i18n::LanguageManager::instance().bindTab(
            m_rootTabWidget, m_irpBuilderPage, QStringLiteral("file.tab.irpbuilder"), QStringLiteral("IRP 构造"));
    }
}

void FileDock::initializePanel(FilePanelWidgets& panel, const QString& titleText)
{
    // 记录面板名称，后续日志统一附带“左侧/右侧”标签便于排障定位。
    panel.panelNameText = titleText;

    {
        kLogEvent event;
        info << event
            << "[FileDock] 开始初始化面板, panel="
            << titleText.toStdString()
            << eol;
    }

    panel.rootWidget = new QWidget(m_mainSplitter);
    // 文件面板根容器横向可收缩：
    // - 输入：QSplitter 分配的当前宽度；
    // - 处理：忽略内部文件列表的动态 sizeHint，防止选中文件或目录加载时推动分界线；
    // - 返回：无返回值，实际布局仍由 rootLayout 管理。
    panel.rootWidget->setMinimumWidth(0);
    panel.rootWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    panel.rootLayout = new QVBoxLayout(panel.rootWidget);
    panel.rootLayout->setContentsMargins(4, 4, 4, 4);
    panel.rootLayout->setSpacing(4);

    // 标题栏：区分左右面板。
    QLabel* titleLabel = new QLabel(titleText, panel.rootWidget);
    titleLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:700;").arg(KswordTheme::PrimaryBlueHex));
    panel.rootLayout->addWidget(titleLabel, 0);

    panel.navWidget = new QWidget(panel.rootWidget);
    panel.navLayout = new QHBoxLayout(panel.navWidget);
    panel.navLayout->setContentsMargins(0, 0, 0, 0);
    panel.navLayout->setSpacing(4);

    panel.backButton = new QPushButton(QIcon(":/Icon/file_nav_back.svg"), QString(), panel.navWidget);
    panel.backButton->setToolTip(QStringLiteral("后退"));
    panel.backButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.backButton);

    panel.forwardButton = new QPushButton(QIcon(":/Icon/file_nav_forward.svg"), QString(), panel.navWidget);
    panel.forwardButton->setToolTip(QStringLiteral("前进"));
    panel.forwardButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.forwardButton);

    panel.upButton = new QPushButton(QIcon(":/Icon/file_nav_up.svg"), QString(), panel.navWidget);
    panel.upButton->setToolTip(QStringLiteral("上级目录"));
    panel.upButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.upButton);

    panel.refreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), panel.navWidget);
    panel.refreshButton->setToolTip(QStringLiteral("刷新当前目录"));
    panel.refreshButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(panel.refreshButton);

    // 地址区域采用“堆叠控件”：
    // - 面包屑页：默认显示；
    // - 编辑页：点击空白热区后切换，按 Enter 跳转。
    panel.pathStack = new QStackedWidget(panel.navWidget);
    panel.pathStack->setMinimumWidth(260);

    panel.breadcrumbWidget = new QWidget(panel.pathStack);
    panel.breadcrumbWidget->setObjectName(QStringLiteral("EmbeddedBreadcrumbWidget"));
    panel.breadcrumbWidget->setStyleSheet(QStringLiteral(
        "QWidget#EmbeddedBreadcrumbWidget{"
        "  border:1px solid %1;"
        "  border-radius:3px;"
        "  background:%2;"
        "}").arg(KswordTheme::BorderHex(), KswordTheme::SurfaceHex()));
    panel.breadcrumbLayout = new QHBoxLayout(panel.breadcrumbWidget);
    panel.breadcrumbLayout->setContentsMargins(6, 2, 6, 2);
    panel.breadcrumbLayout->setSpacing(2);

    panel.pathEdit = new QLineEdit(panel.pathStack);
    panel.pathEdit->setPlaceholderText(QStringLiteral("输入路径后按回车跳转"));
    panel.pathEdit->setStyleSheet(buildBlueInputStyle());

    // 驱动器下拉框：
    // - 固定放在地址栏右侧，直接跳转任意盘符根目录；
    // - 解决默认路径体验更偏向当前系统盘的问题。
    panel.driveCombo = new QComboBox(panel.navWidget);
    panel.driveCombo->setStyleSheet(buildBlueInputStyle());
    panel.driveCombo->setMinimumWidth(92);
    panel.driveCombo->setMaximumWidth(140);
    panel.driveCombo->setToolTip(QStringLiteral("快速跳转到任意驱动器根目录"));

    panel.pathStack->addWidget(panel.breadcrumbWidget);
    panel.pathStack->addWidget(panel.pathEdit);

    panel.navLayout->addWidget(panel.backButton);
    panel.navLayout->addWidget(panel.forwardButton);
    panel.navLayout->addWidget(panel.upButton);
    panel.navLayout->addWidget(panel.refreshButton);
    panel.navLayout->addWidget(panel.pathStack, 1);
    panel.navLayout->addWidget(panel.driveCombo, 0);
    panel.rootLayout->addWidget(panel.navWidget, 0);

    panel.toolWidget = new QWidget(panel.rootWidget);
    panel.toolLayout = new QHBoxLayout(panel.toolWidget);
    panel.toolLayout->setContentsMargins(0, 0, 0, 0);
    panel.toolLayout->setSpacing(4);

    panel.viewModeCombo = new QComboBox(panel.toolWidget);
    panel.viewModeCombo->setStyleSheet(buildBlueInputStyle());
    panel.viewModeCombo->addItems(QStringList{ QStringLiteral("图标视图"), QStringLiteral("列表视图"), QStringLiteral("详情视图"), QStringLiteral("树形视图") });
    panel.viewModeCombo->setToolTip(QStringLiteral("切换文件显示模式，默认使用详情视图"));
    panel.viewModeCombo->setCurrentIndex(2);

    panel.showSystemCheck = new QCheckBox(QStringLiteral("系统"), panel.toolWidget);
    panel.showHiddenCheck = new QCheckBox(QStringLiteral("隐藏"), panel.toolWidget);
    panel.showSystemCheck->setChecked(true);
    panel.showHiddenCheck->setChecked(true);

    panel.sortModeCombo = new QComboBox(panel.toolWidget);
    panel.sortModeCombo->setStyleSheet(buildBlueInputStyle());
    panel.sortModeCombo->addItems(QStringList{ QStringLiteral("名称"), QStringLiteral("大小"), QStringLiteral("修改时间"), QStringLiteral("类型") });

    panel.readModeCombo = new QComboBox(panel.toolWidget);
    panel.readModeCombo->setStyleSheet(buildBlueInputStyle());
    panel.readModeCombo->addItems(QStringList{
        QStringLiteral("Windows API"),
        QStringLiteral("手动解析文件系统"),
        QStringLiteral("R0 驱动解析"),
        QStringLiteral("作为NTFS解析"),
        QStringLiteral("作为FAT32解析"),
        QStringLiteral("作为exFAT解析"),
        QStringLiteral("作为MFT解析"),
        QStringLiteral("R0 IRP 解析") });
    // 装事件过滤器吞掉滚轮：见 eventFilter 里的说明。
    panel.readModeCombo->installEventFilter(this);
    panel.readModeCombo->setFocusPolicy(Qt::StrongFocus);
    panel.readModeCombo->setToolTip(QStringLiteral(
        "切换目录读取方式：Windows API、R3 原始卷手动解析、"
        "R0 驱动目录解析，强制按 NTFS/FAT32/exFAT 解析，\n"
        "作为MFT解析（仅 NTFS：卷偏移直读 $MFT，禁用一切 WinAPI/FSCTL 回退），\n"
        "R0 IRP 解析（内核自建 IRP 把目录查询直发基础文件系统设备，绕过过滤层；\n"
        "打开阶段仍走正常路径，只在 CREATE 上做的拦截发现不了）。\n"
        "后两种会与常规视图对照，把只有绕过路径可见的条目标为疑似隐藏项。"));

    panel.filterEdit = new QLineEdit(panel.toolWidget);
    panel.filterEdit->setPlaceholderText(QStringLiteral("快速过滤"));
    panel.filterEdit->setStyleSheet(buildBlueInputStyle());

    panel.toolLayout->addWidget(panel.viewModeCombo, 0);
    panel.toolLayout->addWidget(panel.showSystemCheck, 0);
    panel.toolLayout->addWidget(panel.showHiddenCheck, 0);
    panel.toolLayout->addWidget(panel.sortModeCombo, 0);
    panel.toolLayout->addWidget(panel.readModeCombo, 0);
    panel.toolLayout->addWidget(panel.filterEdit, 1);
    panel.rootLayout->addWidget(panel.toolWidget, 0);

    panel.fsModel = new ReparseAwareFileSystemModel(panel.rootWidget);
    panel.fsModel->setReadOnly(false);
    panel.fsModel->setResolveSymlinks(true);
    panel.fsModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
    // 关闭“仅灰显不隐藏”行为，确保名称过滤严格只显示匹配项。
    panel.fsModel->setNameFilterDisables(false);

    panel.proxyModel = new QSortFilterProxyModel(panel.rootWidget);
    panel.proxyModel->setSourceModel(panel.fsModel);
    panel.proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    panel.proxyModel->setFilterKeyColumn(0);

    panel.manualModel = new QStandardItemModel(panel.rootWidget);
    panel.manualModel->setColumnCount(static_cast<int>(ManualModelColumn::Count));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::Name), Qt::Horizontal, QStringLiteral("名称"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::Size), Qt::Horizontal, QStringLiteral("大小"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::Type), Qt::Horizontal, QStringLiteral("类型"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::ModifiedTime), Qt::Horizontal, QStringLiteral("修改时间"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::FullPath), Qt::Horizontal, QStringLiteral("完整路径"));
    panel.manualModel->setHeaderData(static_cast<int>(ManualModelColumn::IsDirectory), Qt::Horizontal, QStringLiteral("目录标记"));

    panel.manualProxyModel = new QSortFilterProxyModel(panel.rootWidget);
    panel.manualProxyModel->setSourceModel(panel.manualModel);
    panel.manualProxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    panel.manualProxyModel->setFilterKeyColumn(static_cast<int>(ManualModelColumn::Name));

    panel.fileViewStack = new QStackedWidget(panel.rootWidget);
    panel.fileViewStack->setMinimumWidth(0);
    panel.fileViewStack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);

    panel.compactFileView = new QListView(panel.fileViewStack);
    panel.compactFileView->setMinimumWidth(0);
    panel.compactFileView->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    panel.compactFileView->setModel(panel.proxyModel);
    panel.compactFileView->setModelColumn(0);
    panel.compactFileView->setEditTriggers(QAbstractItemView::EditKeyPressed);
    panel.compactFileView->setContextMenuPolicy(Qt::CustomContextMenu);
    panel.compactFileView->viewport()->installEventFilter(this);
    panel.compactFileView->setDragEnabled(true);
    panel.compactFileView->setAcceptDrops(true);
    panel.compactFileView->setDropIndicatorShown(true);
    panel.compactFileView->setDragDropMode(QAbstractItemView::DragDrop);
    panel.compactFileView->setDefaultDropAction(Qt::MoveAction);
    panel.compactFileView->setDragDropOverwriteMode(false);

    panel.fileView = new QTreeView(panel.fileViewStack);
    // 文件列表由 FileDock 自己管理列宽和滚动行为：
    // - 禁用全局 TableColumnAutoFit，避免 QFileSystemModel 某些长名称/类型列在选择或加载时重算列宽；
    // - 横向 size policy 使用 Ignored，确保 QTreeView 的 header/内容宽度不会反向撑大 QSplitter 子面板。
    panel.fileView->setMinimumWidth(0);
    panel.fileView->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    ks::ui::SetTableColumnAutoFitEnabled(panel.fileView, false);
    panel.fileView->setModel(panel.proxyModel);
    panel.fileView->setEditTriggers(QAbstractItemView::EditKeyPressed);
    panel.fileView->setContextMenuPolicy(Qt::CustomContextMenu);
    panel.fileView->viewport()->installEventFilter(this);
    panel.fileView->setSortingEnabled(true);
    panel.fileView->setDragEnabled(true);
    panel.fileView->setAcceptDrops(true);
    panel.fileView->setDropIndicatorShown(true);
    panel.fileView->setDragDropMode(QAbstractItemView::DragDrop);
    panel.fileView->setDefaultDropAction(Qt::MoveAction);
    panel.fileView->setDragDropOverwriteMode(false);
    panel.fileView->header()->setStretchLastSection(false);
    panel.fileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    panel.fileView->header()->setStyleSheet(QStringLiteral("QHeaderView::section{color:%1;}").arg(KswordTheme::PrimaryBlueHex));
    // 两种控件共享同一个选择模型，切换视图后多选、当前项和右键动作保持一致。
    QItemSelectionModel* compactSelectionModel = panel.compactFileView->selectionModel();
    panel.compactFileView->setSelectionModel(panel.fileView->selectionModel());
    if (compactSelectionModel != nullptr && compactSelectionModel != panel.fileView->selectionModel())
    {
        compactSelectionModel->deleteLater();
    }
    configureFileViewSelection(panel);
    panel.fileViewStack->addWidget(panel.compactFileView);
    panel.fileViewStack->addWidget(panel.fileView);
    panel.fileViewStack->setCurrentWidget(panel.fileView);
    panel.rootLayout->addWidget(panel.fileViewStack, 1);

    panel.statusBar = new QStatusBar(panel.rootWidget);
    panel.pathStatusLabel = new QLabel(QStringLiteral("路径: -"), panel.statusBar);
    panel.selectionStatusLabel = new QLabel(QStringLiteral("选中: 0"), panel.statusBar);
    panel.diskStatusLabel = new QLabel(QStringLiteral("磁盘: -"), panel.statusBar);
    panel.parserStatusLabel = new QLabel(QStringLiteral("解析器: Windows API"), panel.statusBar);
    panel.statusBar->addWidget(panel.pathStatusLabel, 1);
    panel.statusBar->addPermanentWidget(panel.parserStatusLabel, 0);
    panel.statusBar->addPermanentWidget(panel.selectionStatusLabel, 0);
    panel.statusBar->addPermanentWidget(panel.diskStatusLabel, 0);
    panel.rootLayout->addWidget(panel.statusBar, 0);

    // 初始化读取模式并同步模型。
    applyReadModeToPanel(panel);
    initializeConnections(panel);
    refreshDriveCombo(panel);

    // 默认定位到系统根目录。
    const QString defaultPath = QDir::rootPath();
    navigateToPath(panel, defaultPath, true);

    {
        kLogEvent event;
        info << event
            << "[FileDock] 面板初始化完成, panel="
            << panel.panelNameText.toStdString()
            << ", defaultPath="
            << QDir::toNativeSeparators(defaultPath).toStdString()
            << eol;
    }
}

void FileDock::initializeConnections(FilePanelWidgets& panel)
{
    // 返回按钮：回退到上一个历史路径。
    connect(panel.backButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.historyIndex <= 0 || panel.history.empty())
        {
            return;
        }

        panel.historyIndex -= 1;
        const QString targetPath = panel.history.at(static_cast<std::size_t>(panel.historyIndex));
        {
            kLogEvent event;
            info << event
                << "[FileDock] 历史后退, panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, targetPath, false);
    });

    // 前进按钮：进入历史中的下一个路径。
    connect(panel.forwardButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.history.empty())
        {
            return;
        }
        const int nextIndex = panel.historyIndex + 1;
        if (nextIndex < 0 || nextIndex >= static_cast<int>(panel.history.size()))
        {
            return;
        }

        panel.historyIndex = nextIndex;
        const QString targetPath = panel.history.at(static_cast<std::size_t>(panel.historyIndex));
        {
            kLogEvent event;
            info << event
                << "[FileDock] 历史前进, panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, targetPath, false);
    });

    // 上级目录按钮：从当前目录切到 parent。
    connect(panel.upButton, &QPushButton::clicked, this, [this, &panel]() {
        if (panel.currentPath.isEmpty())
        {
            return;
        }

        QDir currentDir(panel.currentPath);
        if (!currentDir.cdUp())
        {
            return;
        }

        {
            kLogEvent event;
            info << event
                << "[FileDock] 上级目录跳转, panel="
                << panel.panelNameText.toStdString()
                << ", from="
                << QDir::toNativeSeparators(panel.currentPath).toStdString()
                << ", to="
                << QDir::toNativeSeparators(currentDir.absolutePath()).toStdString()
                << eol;
        }
        navigateToPath(panel, currentDir.absolutePath(), true);
    });

    // 刷新按钮：重新加载当前目录。
    connect(panel.refreshButton, &QPushButton::clicked, this, [this, &panel]() {
        kLogEvent event;
        info << event
            << "[FileDock] 手动刷新目录, panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
        refreshPanel(panel);
    });

    // 地址栏回车：按输入路径导航并自动回到面包屑显示模式。
    connect(panel.pathEdit, &QLineEdit::returnPressed, this, [this, &panel]() {
        const QString targetPath = panel.pathEdit->text().trimmed();
        {
            kLogEvent event;
            info << event
                << "[FileDock] 地址栏回车导航, panel="
                << panel.panelNameText.toStdString()
                << ", input="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << eol;
        }
        navigateToPath(panel, targetPath, true);
        setPathEditMode(panel, false);
    });

    // 驱动器下拉框切换：直接跳转到对应盘符根目录。
    connect(panel.driveCombo, &QComboBox::currentIndexChanged, this, [this, &panel](const int indexValue) {
        if (indexValue < 0)
        {
            return;
        }

        const QString targetRootPath = panel.driveCombo->itemData(indexValue).toString();
        if (targetRootPath.trimmed().isEmpty())
        {
            return;
        }

        if (panel.currentPath.compare(targetRootPath, Qt::CaseInsensitive) == 0)
        {
            return;
        }

        kLogEvent event;
        info << event
            << "[FileDock] 驱动器下拉框跳转, panel="
            << panel.panelNameText.toStdString()
            << ", targetRoot="
            << QDir::toNativeSeparators(targetRootPath).toStdString()
            << eol;
        navigateToPath(panel, targetRootPath, true);
    });

    // 编辑完成但未回车时：回退到面包屑，避免长期停留在文本编辑态。
    connect(panel.pathEdit, &QLineEdit::editingFinished, this, [this, &panel]() {
        if (!panel.pathEditMode)
        {
            return;
        }
        if (panel.pathEdit->hasFocus())
        {
            return;
        }
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        setPathEditMode(panel, false);
    });

    // ESC：取消路径编辑并恢复当前路径文本。
    QShortcut* cancelPathEditShortcut = new QShortcut(QKeySequence(Qt::Key_Escape), panel.pathEdit);
    connect(cancelPathEditShortcut, &QShortcut::activated, this, [this, &panel]() {
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        setPathEditMode(panel, false);
        kLogEvent event;
        dbg << event
            << "[FileDock] 取消路径编辑, panel="
            << panel.panelNameText.toStdString()
            << eol;
    });

    // 视图切换：根据当前模式调整列显示与图标大小。
    connect(panel.viewModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        applyPanelFilterAndSort(panel);
    });

    // 系统文件显隐切换。
    connect(panel.showSystemCheck, &QCheckBox::toggled, this, [this, &panel](bool) {
        applyPanelFilterAndSort(panel);
    });

    // 隐藏文件显隐切换。
    connect(panel.showHiddenCheck, &QCheckBox::toggled, this, [this, &panel](bool) {
        applyPanelFilterAndSort(panel);
    });

    // 排序模式切换。
    connect(panel.sortModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        applyPanelFilterAndSort(panel);
    });

    // 读取模式切换：Windows API 与手动解析模型实时切换。
    connect(panel.readModeCombo, &QComboBox::currentIndexChanged, this, [this, &panel](int) {
        panel.manualLoadedPath.clear();
        panel.manualSourceDetail.clear();
        panel.manualResultPartial = false;
        if (panel.manualModel != nullptr)
        {
            panel.manualModel->setRowCount(0);
        }
        applyReadModeToPanel(panel);
        refreshPanel(panel);
    });

    // 快速过滤输入：实时更新代理模型。
    connect(panel.filterEdit, &QLineEdit::textChanged, this, [this, &panel](const QString&) {
        applyPanelFilterAndSort(panel);
    });

    // 双击打开：目录进入，文件交给系统默认程序。
    connect(panel.fileView, &QTreeView::doubleClicked, this, [this, &panel](const QModelIndex& proxyIndex) {
        if (!proxyIndex.isValid())
        {
            return;
        }

        const QString path = currentIndexPath(panel);
        if (path.isEmpty())
        {
            return;
        }

        QFileInfo info(path);
        if (info.isDir())
        {
            navigateToPath(panel, path, true);
            return;
        }

        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });
    connect(panel.compactFileView, &QListView::doubleClicked, this, [this, &panel](const QModelIndex& proxyIndex) {
        if (!proxyIndex.isValid())
        {
            return;
        }

        const QString path = currentIndexPath(panel);
        if (path.isEmpty())
        {
            return;
        }

        QFileInfo info(path);
        if (info.isDir())
        {
            navigateToPath(panel, path, true);
            return;
        }

        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });

    connect(panel.compactFileView, &QListView::customContextMenuRequested, this, [this, &panel](const QPoint& pos) {
        showPanelContextMenu(panel, pos);
    });


    // 右键菜单入口。
    connect(panel.fileView, &QTreeView::customContextMenuRequested, this, [this, &panel](const QPoint& pos) {
        showPanelContextMenu(panel, pos);
    });

    // 选中变化时刷新状态栏。
    connect(panel.fileView->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this, &panel](const QItemSelection&, const QItemSelection&) {
        updatePanelStatus(panel);
    });

    // 模型目录加载完成后更新状态栏，提示当前目录数据可见。
    connect(panel.fsModel, &QFileSystemModel::directoryLoaded, this, [this, &panel](const QString&) {
        updatePanelStatus(panel);
    });

    // Alt+D：快速切换到路径编辑模式，行为与常见文件管理器保持一致。
    QShortcut* editPathShortcut = new QShortcut(QKeySequence(Qt::ALT | Qt::Key_D), panel.rootWidget);
    connect(editPathShortcut, &QShortcut::activated, this, [this, &panel]() {
        setPathEditMode(panel, true);
    });

    // Enter 快捷键：打开选中项。
    QShortcut* openShortcut = new QShortcut(QKeySequence(Qt::Key_Return), panel.fileView);
    openShortcut->setContext(Qt::WidgetShortcut);
    connect(openShortcut, &QShortcut::activated, this, [this, &panel]() {
        openSelectedItems(panel);
    });
    QShortcut* openShortcutEnter = new QShortcut(QKeySequence(Qt::Key_Enter), panel.fileView);
    openShortcutEnter->setContext(Qt::WidgetShortcut);
    connect(openShortcutEnter, &QShortcut::activated, this, [this, &panel]() {
        openSelectedItems(panel);
    });

    // F2 重命名快捷键。
    QShortcut* renameShortcut = new QShortcut(QKeySequence(Qt::Key_F2), panel.fileView);
    renameShortcut->setContext(Qt::WidgetShortcut);
    connect(renameShortcut, &QShortcut::activated, this, [this, &panel]() {
        renameSelectedItem(panel);
    });

    // Delete 删除快捷键。
    QShortcut* deleteShortcut = new QShortcut(QKeySequence(Qt::Key_Delete), panel.fileView);
    deleteShortcut->setContext(Qt::WidgetShortcut);
    connect(deleteShortcut, &QShortcut::activated, this, [this, &panel]() {
        deleteSelectedItem(panel);
    });

    // Ctrl+C 必须保持“无副作用”：资源管理器里它只把内容放进剪贴板，
    // 真正落盘要等 Ctrl+V。此前这里绑的是“立即复制到对侧面板”，
    // 按下即写入目标目录且无确认，与用户预期完全相反；Ctrl+X 更是
    // 直接移动源文件。现改为复制所选路径到剪贴板，并解绑 Ctrl+X。
    // 面板间传输仍可用右键菜单的“复制到对侧面板/移动到对侧面板”，
    // 那里的名字已经明确说明了动作与目标。
    QShortcut* copyShortcut = new QShortcut(QKeySequence::Copy, panel.fileView);
    copyShortcut->setContext(Qt::WidgetShortcut);
    connect(copyShortcut, &QShortcut::activated, this, [this, &panel]() {
        copySelectedItemPath(panel);
    });

    // QListView 使用自己的 WidgetShortcut，避免把 Enter/Delete 等按键扩散到地址栏和过滤输入框。
    const auto bindCompactShortcut =
        [this, &panel](const QKeySequence& keySequence, const auto& handler)
        {
            QShortcut* shortcut = new QShortcut(keySequence, panel.compactFileView);
            shortcut->setContext(Qt::WidgetShortcut);
            connect(shortcut, &QShortcut::activated, this, handler);
        };
    bindCompactShortcut(QKeySequence(Qt::Key_Return), [this, &panel]() { openSelectedItems(panel); });
    bindCompactShortcut(QKeySequence(Qt::Key_Enter), [this, &panel]() { openSelectedItems(panel); });
    bindCompactShortcut(QKeySequence(Qt::Key_F2), [this, &panel]() { renameSelectedItem(panel); });
    bindCompactShortcut(QKeySequence(Qt::Key_Delete), [this, &panel]() { deleteSelectedItem(panel); });
    bindCompactShortcut(QKeySequence::Copy, [this, &panel]() { copySelectedItemPath(panel); });

}

void FileDock::navigateToPath(FilePanelWidgets& panel, const QString& pathText, bool recordHistory)
{
    {
        kLogEvent event;
        info << event
            << "[FileDock] 导航请求, panel="
            << panel.panelNameText.toStdString()
            << ", input="
            << QDir::toNativeSeparators(pathText).toStdString()
            << ", recordHistory="
            << (recordHistory ? "true" : "false")
            << eol;
    }

    // 去除空白并标准化路径格式，避免历史里混入重复写法。
    const QString trimmedPath = pathText.trimmed();
    if (trimmedPath.isEmpty())
    {
        kLogEvent event;
        warn << event
            << "[FileDock] 导航取消：输入路径为空, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    QString normalizedPath = QDir::cleanPath(QDir::fromNativeSeparators(trimmedPath));

    // 允许用户直接输入裸盘符（如 D:）后跳转到盘根目录。
    if (normalizedPath.size() == 2
        && normalizedPath.at(1) == QChar(':')
        && normalizedPath.at(0).isLetter())
    {
        normalizedPath += QDir::separator();
    }

    QDir targetDir(normalizedPath);
    if (!targetDir.exists())
    {
        kLogEvent event;
        warn << event << "[FileDock] 导航失败，目录不存在: " << normalizedPath.toStdString() << eol;
        QMessageBox::warning(this, QStringLiteral("路径无效"), QStringLiteral("目录不存在：%1").arg(normalizedPath));
        return;
    }

    // 根据当前读取模式更新模型根路径。
    if (currentModeIsManual(panel))
    {
        // 手动解析模式使用平铺模型，根索引固定为无效索引。
        panel.fileView->setRootIndex(QModelIndex());
        panel.compactFileView->setRootIndex(QModelIndex());
    }
    else
    {
        const QModelIndex sourceRootIndex = panel.fsModel->setRootPath(normalizedPath);
        const QModelIndex proxyRootIndex = panel.proxyModel->mapFromSource(sourceRootIndex);
        panel.fileView->setRootIndex(proxyRootIndex);
        panel.compactFileView->setRootIndex(proxyRootIndex);
    }
    panel.currentPath = normalizedPath;
    panel.pathEdit->setText(QDir::toNativeSeparators(normalizedPath));
    refreshDriveCombo(panel);

    // 记录历史：当用户主动导航时清理“前进分支”再追加。
    if (recordHistory)
    {
        if (panel.historyIndex + 1 < static_cast<int>(panel.history.size()))
        {
            panel.history.erase(
                panel.history.begin() + panel.historyIndex + 1,
                panel.history.end());
        }

        if (panel.history.empty() || panel.history.back() != normalizedPath)
        {
            panel.history.push_back(normalizedPath);
            panel.historyIndex = static_cast<int>(panel.history.size()) - 1;
        }
        else
        {
            panel.historyIndex = static_cast<int>(panel.history.size()) - 1;
        }
    }

    // 同步按钮可用性状态。
    const bool canGoBack = panel.historyIndex > 0;
    const bool canGoForward = panel.historyIndex >= 0
        && (panel.historyIndex + 1) < static_cast<int>(panel.history.size());
    panel.backButton->setEnabled(canGoBack);
    panel.forwardButton->setEnabled(canGoForward);

    // 导航后更新面包屑、过滤排序和状态栏。
    rebuildBreadcrumb(panel);
    setPathEditMode(panel, false);
    applyPanelFilterAndSort(panel);
    updatePanelStatus(panel);

    {
        kLogEvent event;
        info << event
            << "[FileDock] 导航成功, panel="
            << panel.panelNameText.toStdString()
            << ", normalizedPath="
            << QDir::toNativeSeparators(normalizedPath).toStdString()
            << ", historySize="
            << panel.history.size()
            << ", historyIndex="
            << panel.historyIndex
            << eol;
    }
}

void FileDock::refreshPanel(FilePanelWidgets& panel)
{
    {
        kLogEvent event;
        dbg << event
            << "[FileDock] 刷新面板, panel="
            << panel.panelNameText.toStdString()
            << ", currentPath="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    // 没有当前目录时回到系统根路径，保证面板始终可用。
    if (panel.currentPath.isEmpty())
    {
        navigateToPath(panel, QDir::rootPath(), true);
        return;
    }

    // 复用导航逻辑触发模型重载，不写历史避免污染。
    if (currentModeIsManual(panel))
    {
        panel.manualLoadedPath.clear();
    }
    else
    {
        recreateFileSystemModel(panel);
    }
    navigateToPath(panel, panel.currentPath, false);
}

void FileDock::rebuildBreadcrumb(FilePanelWidgets& panel)
{
    if (panel.breadcrumbLayout == nullptr)
    {
        return;
    }

    {
        kLogEvent event;
        dbg << event
            << "[FileDock] 重建面包屑, panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    // 清理旧的面包屑按钮和分隔符，防止布局叠加。
    while (QLayoutItem* item = panel.breadcrumbLayout->takeAt(0))
    {
        if (QWidget* widget = item->widget())
        {
            widget->deleteLater();
        }
        delete item;
    }

    const QString nativePath = QDir::toNativeSeparators(panel.currentPath);
    if (nativePath.isEmpty())
    {
        return;
    }

    int crumbButtonCount = 0;
    QStringList pathParts = nativePath.split(QDir::separator(), Qt::SkipEmptyParts);
    QString runningPath;

    // Windows 驱动器路径（如 C:\）单独处理，保证首段可点击。
    if (nativePath.contains(':'))
    {
        const int colonIndex = nativePath.indexOf(':');
        if (colonIndex >= 0)
        {
            runningPath = nativePath.left(colonIndex + 1) + QDir::separator();
            QString driveText = runningPath;
            driveText.chop(1);

            QToolButton* driveButton = new QToolButton(panel.breadcrumbWidget);
            driveButton->setText(driveText);
            driveButton->setStyleSheet(buildBreadcrumbButtonStyle());
            driveButton->setToolTip(QStringLiteral("跳转到 %1").arg(driveText));
            panel.breadcrumbLayout->addWidget(driveButton, 0);
            crumbButtonCount += 1;
            connect(driveButton, &QToolButton::clicked, this, [this, &panel, runningPath]() {
                kLogEvent event;
                info << event
                    << "[FileDock] 面包屑跳转(盘符), panel="
                    << panel.panelNameText.toStdString()
                    << ", targetPath="
                    << QDir::toNativeSeparators(runningPath).toStdString()
                    << eol;
                navigateToPath(panel, runningPath, true);
            });

            if (!pathParts.isEmpty() && pathParts.front().contains(':'))
            {
                pathParts.removeFirst();
            }
        }
    }
    else if (nativePath.startsWith(QDir::separator()))
    {
        runningPath = QString(QDir::separator());
        QToolButton* rootButton = new QToolButton(panel.breadcrumbWidget);
        rootButton->setText(QStringLiteral("/"));
        rootButton->setStyleSheet(buildBreadcrumbButtonStyle());
        rootButton->setToolTip(QStringLiteral("跳转到根目录"));
        panel.breadcrumbLayout->addWidget(rootButton, 0);
        crumbButtonCount += 1;
        connect(rootButton, &QToolButton::clicked, this, [this, &panel]() {
            kLogEvent event;
            info << event
                << "[FileDock] 面包屑跳转(根目录), panel="
                << panel.panelNameText.toStdString()
                << eol;
            navigateToPath(panel, QString(QDir::separator()), true);
        });
    }

    // 逐段创建路径按钮，支持点击任意层级跳转。
    for (int i = 0; i < pathParts.size(); ++i)
    {
        const QString& part = pathParts.at(i);
        if (part.isEmpty())
        {
            continue;
        }

        if (!runningPath.isEmpty() && !runningPath.endsWith(QDir::separator()))
        {
            runningPath += QDir::separator();
        }
        runningPath += part;

        QLabel* sepLabel = new QLabel(QStringLiteral(">"), panel.breadcrumbWidget);
        sepLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::PrimaryBlueHex));
        panel.breadcrumbLayout->addWidget(sepLabel, 0);

        const QString capturePath = runningPath;
        QToolButton* partButton = new QToolButton(panel.breadcrumbWidget);
        partButton->setText(part);
        partButton->setStyleSheet(buildBreadcrumbButtonStyle());
        partButton->setToolTip(QStringLiteral("跳转到 %1").arg(capturePath));
        panel.breadcrumbLayout->addWidget(partButton, 0);
        crumbButtonCount += 1;
        connect(partButton, &QToolButton::clicked, this, [this, &panel, capturePath]() {
            kLogEvent event;
            info << event
                << "[FileDock] 面包屑跳转(路径段), panel="
                << panel.panelNameText.toStdString()
                << ", targetPath="
                << QDir::toNativeSeparators(capturePath).toStdString()
                << eol;
            navigateToPath(panel, capturePath, true);
        });
    }

    // 面包屑末尾添加“透明热区”：
    // - 点击路径按钮=按段回退；
    // - 点击空白区域=切换到文本编辑模式。
    panel.breadcrumbEditTriggerButton = new QPushButton(panel.breadcrumbWidget);
    panel.breadcrumbEditTriggerButton->setFlat(true);
    panel.breadcrumbEditTriggerButton->setCursor(Qt::IBeamCursor);
    panel.breadcrumbEditTriggerButton->setToolTip(QStringLiteral("点击空白区域编辑路径"));
    panel.breadcrumbEditTriggerButton->setStyleSheet(QStringLiteral(
        "QPushButton{border:none;background:transparent;color:%1;}"
        "QPushButton:hover{background:%2;color:%1;}")
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::IsDarkModeEnabled() ? KswordTheme::SurfaceMutedColorHex() : KswordTheme::PrimaryBlueSubtleHex()));
    panel.breadcrumbLayout->addWidget(panel.breadcrumbEditTriggerButton, 1);
    connect(panel.breadcrumbEditTriggerButton, &QPushButton::clicked, this, [this, &panel]() {
        kLogEvent event;
        info << event
            << "[FileDock] 点击面包屑空白区进入路径编辑, panel="
            << panel.panelNameText.toStdString()
            << eol;
        setPathEditMode(panel, true);
    });

    {
        kLogEvent event;
        dbg << event
            << "[FileDock] 面包屑重建完成, panel="
            << panel.panelNameText.toStdString()
            << ", breadcrumbButtonCount="
            << crumbButtonCount
            << eol;
    }
}

void FileDock::setPathEditMode(FilePanelWidgets& panel, bool editMode)
{
    if (panel.pathStack == nullptr || panel.pathEdit == nullptr || panel.breadcrumbWidget == nullptr)
    {
        return;
    }

    if (panel.pathEditMode == editMode)
    {
        return;
    }

    panel.pathEditMode = editMode;
    if (editMode)
    {
        panel.pathStack->setCurrentWidget(panel.pathEdit);
        panel.pathEdit->setText(QDir::toNativeSeparators(panel.currentPath));
        panel.pathEdit->setFocus();
        panel.pathEdit->selectAll();
    }
    else
    {
        panel.pathStack->setCurrentWidget(panel.breadcrumbWidget);
        panel.pathEdit->clearFocus();
    }

    kLogEvent event;
    dbg << event
        << "[FileDock] 地址栏显示模式切换, panel="
        << panel.panelNameText.toStdString()
        << ", mode="
        << (editMode ? "edit" : "breadcrumb")
        << eol;
}

void FileDock::updatePanelStatus(FilePanelWidgets& panel)
{
    // 路径状态：直接显示当前目录。
    panel.pathStatusLabel->setText(QStringLiteral("路径: %1").arg(QDir::toNativeSeparators(panel.currentPath)));

    // 统计选中项数量与总大小（文件夹大小不做递归统计，避免卡顿）。
    const std::vector<QString> selectedItemPaths = selectedPaths(panel);
    std::uint64_t totalSize = 0;
    for (const QString& path : selectedItemPaths)
    {
        QFileInfo info(path);
        if (info.isFile())
        {
            totalSize += static_cast<std::uint64_t>(std::max<qint64>(0, info.size()));
        }
    }

    QString attributeHint;
    if (selectedItemPaths.size() == 1)
    {
        QFileInfo info(selectedItemPaths.front());
        QStringList attrs;
        if (!info.isWritable())
        {
            attrs.push_back(QStringLiteral("只读"));
        }
        if (info.isHidden())
        {
            attrs.push_back(QStringLiteral("隐藏"));
        }
        if (info.isSymLink())
        {
            attrs.push_back(QStringLiteral("链接"));
        }
        if (!attrs.isEmpty())
        {
            attributeHint = QStringLiteral(" [%1]").arg(attrs.join(','));
        }
    }

    panel.selectionStatusLabel->setText(
        QStringLiteral("选中: %1  大小: %2%3")
        .arg(selectedItemPaths.size())
        .arg(formatSizeText(totalSize))
        .arg(attributeHint));

    // 磁盘状态：显示当前分区剩余空间。
    const QStorageInfo storageInfo(panel.currentPath);
    if (storageInfo.isValid() && storageInfo.isReady())
    {
        panel.diskStatusLabel->setText(
            QStringLiteral("剩余: %1 / 总计: %2")
            .arg(formatSizeText(static_cast<std::uint64_t>(storageInfo.bytesAvailable())))
            .arg(formatSizeText(static_cast<std::uint64_t>(storageInfo.bytesTotal()))));
    }
    else
    {
        panel.diskStatusLabel->setText(QStringLiteral("磁盘: -"));
    }

    // 状态日志去重：只有内容变化时输出，避免选区抖动造成日志风暴。
    const QString statusSignature = QStringLiteral("%1|%2|%3|%4")
        .arg(panel.currentPath)
        .arg(selectedItemPaths.size())
        .arg(static_cast<qulonglong>(totalSize))
        .arg(panel.diskStatusLabel->text());
    if (statusSignature != panel.lastStatusLogSignature)
    {
        panel.lastStatusLogSignature = statusSignature;
        kLogEvent event;
        dbg << event
            << "[FileDock] 状态栏更新, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << selectedItemPaths.size()
            << ", selectedBytes="
            << static_cast<qulonglong>(totalSize)
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }
}

void FileDock::applyPanelFilterAndSort(FilePanelWidgets& panel)
{
    const bool manualMode = currentModeIsManual(panel);
    const int modeIndex = panel.viewModeCombo->currentIndex();
    const QString filterText = panel.filterEdit->text().trimmed();

    // 图标/列表使用 QListView 的真实布局；详情/树形保留 QTreeView 的多列与层级能力。
    const bool compactMode = (modeIndex == 0 || modeIndex == 1);
    if (compactMode)
    {
        panel.fileViewStack->setCurrentWidget(panel.compactFileView);
        panel.compactFileView->setTextElideMode(Qt::ElideMiddle);
        if (modeIndex == 0)
        {
            panel.compactFileView->setViewMode(QListView::IconMode);
            panel.compactFileView->setResizeMode(QListView::Adjust);
            panel.compactFileView->setMovement(QListView::Static);
            panel.compactFileView->setFlow(QListView::LeftToRight);
            panel.compactFileView->setWrapping(true);
            panel.compactFileView->setGridSize(QSize(128, 96));
            panel.compactFileView->setSpacing(6);
            panel.compactFileView->setWordWrap(true);
            panel.compactFileView->setUniformItemSizes(true);
            panel.compactFileView->setIconSize(QSize(48, 48));
        }
        else
        {
            panel.compactFileView->setViewMode(QListView::ListMode);
            panel.compactFileView->setResizeMode(QListView::Adjust);
            panel.compactFileView->setMovement(QListView::Static);
            panel.compactFileView->setFlow(QListView::TopToBottom);
            panel.compactFileView->setWrapping(false);
            panel.compactFileView->setGridSize(QSize());
            panel.compactFileView->setSpacing(2);
            panel.compactFileView->setWordWrap(false);
            panel.compactFileView->setUniformItemSizes(true);
            panel.compactFileView->setIconSize(QSize(20, 20));
        }
    }
    else
    {
        panel.fileViewStack->setCurrentWidget(panel.fileView);
    }

    if (manualMode)
    {
        // 手动模式下仅在“当前路径未加载且未在解析”时才拉起新任务，
        // 避免过滤/排序改动触发同一路径重复全盘扫描。
        const bool loadedMatchesCurrentPath =
            (panel.manualLoadedPath.compare(panel.currentPath, Qt::CaseInsensitive) == 0);
        const bool samePathParsing =
            panel.manualParseInProgress
            && (panel.manualParsingPath.compare(panel.currentPath, Qt::CaseInsensitive) == 0);
        if (!loadedMatchesCurrentPath && !samePathParsing)
        {
            requestAsyncManualReload(panel, false);
        }

        if (filterText.isEmpty())
        {
            panel.manualProxyModel->setFilterRegularExpression(QRegularExpression());
        }
        else
        {
            const QString pattern = QStringLiteral(".*%1.*").arg(QRegularExpression::escape(filterText));
            panel.manualProxyModel->setFilterRegularExpression(
                QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption));
        }

        int sortColumn = static_cast<int>(ManualModelColumn::Name);
        switch (panel.sortModeCombo->currentIndex())
        {
        case 1:
            sortColumn = static_cast<int>(ManualModelColumn::Size);
            break;
        case 2:
            sortColumn = static_cast<int>(ManualModelColumn::ModifiedTime);
            break;
        case 3:
            sortColumn = static_cast<int>(ManualModelColumn::Type);
            break;
        default:
            sortColumn = static_cast<int>(ManualModelColumn::Name);
            break;
        }
        panel.fileView->sortByColumn(sortColumn, Qt::AscendingOrder);

        const bool showDetailColumns = (modeIndex == 2 || modeIndex == 3);
        panel.fileView->setIconSize(modeIndex == 0 ? QSize(32, 32) : QSize(18, 18));
        panel.fileView->setRootIsDecorated(false);
        panel.fileView->setItemsExpandable(false);
        panel.fileView->setIndentation(10);

        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::Size), !showDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::Type), !showDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::ModifiedTime), !showDetailColumns);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::FullPath), true);
        panel.fileView->setColumnHidden(static_cast<int>(ManualModelColumn::IsDirectory), true);
    }
    else
    {
        // 组合模型过滤标志：按用户勾选决定是否显示隐藏/系统文件。
        QDir::Filters filters = QDir::AllEntries | QDir::NoDotAndDotDot;
        if (panel.showHiddenCheck->isChecked())
        {
            filters |= QDir::Hidden;
        }
        if (panel.showSystemCheck->isChecked())
        {
            filters |= QDir::System;
        }
        panel.fsModel->setFilter(filters);

        if (filterText.isEmpty())
        {
            panel.fsModel->setNameFilters(QStringList());
        }
        else
        {
            panel.fsModel->setNameFilters(QStringList{
                buildLiteralNameFilterPattern(filterText)
                });
        }
        // Windows API 模式改由 QFileSystemModel 执行名称过滤，代理层只保留排序职责。
        panel.proxyModel->setFilterRegularExpression(QRegularExpression());

        int sortColumn = 0;
        switch (panel.sortModeCombo->currentIndex())
        {
        case 1:
            sortColumn = 1;
            break;
        case 2:
            sortColumn = 3;
            break;
        case 3:
            sortColumn = 2;
            break;
        default:
            sortColumn = 0;
            break;
        }
        panel.fileView->sortByColumn(sortColumn, Qt::AscendingOrder);

        const bool showDetailColumns = (modeIndex == 2 || modeIndex == 3);
        panel.fileView->setIconSize(modeIndex == 0 ? QSize(32, 32) : QSize(18, 18));
        panel.fileView->setRootIsDecorated(modeIndex == 3);
        panel.fileView->setItemsExpandable(modeIndex == 3);
        panel.fileView->setIndentation(modeIndex == 3 ? 18 : 10);
        for (int column = 1; column < panel.fsModel->columnCount(); ++column)
        {
            panel.fileView->setColumnHidden(column, !showDetailColumns);
        }
        if (modeIndex == 1)
        {
            panel.fileView->setRootIsDecorated(false);
            panel.fileView->setItemsExpandable(false);
        }
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(QStringLiteral("解析器: Windows API"));
        }
    }

    // 过滤参数日志去重：仅在用户真实调整条件时输出详细参数。
    const QString filterSignature = QStringLiteral("%1|%2|%3|%4|%5|%6")
        .arg(panel.showHiddenCheck->isChecked() ? 1 : 0)
        .arg(panel.showSystemCheck->isChecked() ? 1 : 0)
        .arg(panel.sortModeCombo->currentIndex())
        .arg(panel.viewModeCombo->currentIndex())
        .arg(panel.readModeCombo->currentIndex())
        .arg(panel.filterEdit->text());
    if (filterSignature != panel.lastFilterLogSignature)
    {
        panel.lastFilterLogSignature = filterSignature;
        kLogEvent event;
        info << event
            << "[FileDock] 过滤/排序参数变更, panel="
            << panel.panelNameText.toStdString()
            << ", showHidden="
            << (panel.showHiddenCheck->isChecked() ? "true" : "false")
            << ", showSystem="
            << (panel.showSystemCheck->isChecked() ? "true" : "false")
            << ", sortModeIndex="
            << panel.sortModeCombo->currentIndex()
            << ", viewModeIndex="
            << panel.viewModeCombo->currentIndex()
            << ", readModeIndex="
            << panel.readModeCombo->currentIndex()
            << ", keyword="
            << panel.filterEdit->text().toStdString()
            << eol;
    }

    updatePanelStatus(panel);
}

void FileDock::refreshDriveCombo(FilePanelWidgets& panel)
{
    if (panel.driveCombo == nullptr)
    {
        return;
    }

    const QSignalBlocker blocker(panel.driveCombo);
    panel.driveCombo->clear();

    const QFileInfoList driveList = QDir::drives();
    int selectedIndex = -1;
    for (const QFileInfo& driveInfo : driveList)
    {
        const QString rootPath = QDir::toNativeSeparators(driveInfo.absoluteFilePath());
        QString displayText = rootPath;
        if (displayText.endsWith(QDir::separator()))
        {
            displayText.chop(1);
        }
        panel.driveCombo->addItem(displayText, rootPath);

        if (!panel.currentPath.isEmpty()
            && panel.currentPath.startsWith(driveInfo.absoluteFilePath(), Qt::CaseInsensitive))
        {
            selectedIndex = panel.driveCombo->count() - 1;
        }
    }

    if (selectedIndex >= 0)
    {
        panel.driveCombo->setCurrentIndex(selectedIndex);
    }
}

void FileDock::applyReadModeToPanel(FilePanelWidgets& panel)
{
    if (panel.fileView == nullptr || panel.compactFileView == nullptr || panel.fileViewStack == nullptr)
    {
        return;
    }

    if (currentModeIsManual(panel))
    {
        panel.fileView->setModel(panel.manualProxyModel);
        panel.fileView->setRootIndex(QModelIndex());
        panel.compactFileView->setModel(panel.manualProxyModel);
        panel.compactFileView->setModelColumn(0);
        panel.compactFileView->setRootIndex(QModelIndex());
        panel.showHiddenCheck->setEnabled(false);
        panel.showSystemCheck->setEnabled(false);
        if (panel.parserStatusLabel != nullptr)
        {
            const ManualParseBackend backend = manualParseBackendForPanel(panel);
            if (backend == ManualParseBackend::ManualFs)
            {
                const ks::file::ManualFsType requestedFsType =
                    requestedManualFsTypeForPanel(panel);
                panel.parserStatusLabel->setText(
                    requestedFsType == ks::file::ManualFsType::Unknown
                    ? QStringLiteral("解析器: 手动解析")
                    : QStringLiteral("解析器: %1 (待解析)")
                        .arg(manualFsTypeToText(requestedFsType)));
            }
            else
            {
                panel.parserStatusLabel->setText(
                    QStringLiteral("解析器: %1 (待查询)")
                        .arg(parseBackendDisplayText(backend)));
            }
        }
    }
    else
    {
        panel.fileView->setModel(panel.proxyModel);
        panel.compactFileView->setModel(panel.proxyModel);
        panel.compactFileView->setModelColumn(0);
        panel.showHiddenCheck->setEnabled(true);
        panel.showSystemCheck->setEnabled(true);
        if (!panel.currentPath.isEmpty())
        {
            const QModelIndex sourceRootIndex = panel.fsModel->setRootPath(panel.currentPath);
            const QModelIndex proxyRootIndex = panel.proxyModel->mapFromSource(sourceRootIndex);
            panel.fileView->setRootIndex(proxyRootIndex);
            panel.compactFileView->setRootIndex(proxyRootIndex);
        }
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(QStringLiteral("解析器: Windows API"));
        }
    }

    configureFileViewSelection(panel);
    panel.fileView->header()->setStretchLastSection(false);
    panel.fileView->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    QItemSelectionModel* selectionModel = panel.fileView->selectionModel();
    QItemSelectionModel* compactSelectionModel = panel.compactFileView->selectionModel();
    panel.compactFileView->setSelectionModel(panel.fileView->selectionModel());
    if (compactSelectionModel != nullptr && compactSelectionModel != panel.fileView->selectionModel())
    {
        compactSelectionModel->deleteLater();
    }

    if (selectionModel != nullptr)
    {
        QObject::disconnect(selectionModel, nullptr, this, nullptr);
        connect(selectionModel, &QItemSelectionModel::selectionChanged, this, [this, &panel](const QItemSelection&, const QItemSelection&) {
            updatePanelStatus(panel);
        });
    }
}

void FileDock::configureFileViewSelection(FilePanelWidgets& panel)
{
    if (panel.fileView == nullptr)
    {
        return;
    }

    // 文件面板的批量删除、复制、剪切、R0 删除等动作都从 selectedRows(0) 收集路径。
    // 因此无论初始创建还是切换 Windows API/手动解析模型后，都必须保持“整行扩展多选”。
    panel.fileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    panel.fileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
    panel.compactFileView->setSelectionBehavior(QAbstractItemView::SelectRows);
    panel.compactFileView->setSelectionMode(QAbstractItemView::ExtendedSelection);
}

void FileDock::recreateFileSystemModel(FilePanelWidgets& panel)
{
    if (panel.rootWidget == nullptr || panel.proxyModel == nullptr)
    {
        return;
    }

    // QFileSystemModel 对目录项元数据有缓存；同一路径 setRootPath() 往往不会重新读取文件大小。
    // 手动刷新时重建模型，保证 size/mtime 等列从磁盘重新枚举，同时代理模型和视图仍沿用原对象。
    QFileSystemModel* const oldModel = panel.fsModel;
    panel.fsModel = new ReparseAwareFileSystemModel(panel.rootWidget);
    panel.fsModel->setReadOnly(false);
    panel.fsModel->setResolveSymlinks(true);
    panel.fsModel->setFilter(QDir::AllEntries | QDir::NoDotAndDotDot);
    panel.fsModel->setNameFilterDisables(false);
    panel.proxyModel->setSourceModel(panel.fsModel);

    connect(panel.fsModel, &QFileSystemModel::directoryLoaded, this, [this, &panel](const QString&) {
        updatePanelStatus(panel);
    });

    if (oldModel != nullptr)
    {
        oldModel->deleteLater();
    }
}

bool FileDock::reloadManualModel(FilePanelWidgets& panel, const bool showWarningMessage)
{
    if (panel.manualModel == nullptr || panel.currentPath.isEmpty())
    {
        return false;
    }

    std::vector<ks::file::ManualDirectoryEntry> entries;
    ks::file::ManualFsType fsType = ks::file::ManualFsType::Unknown;
    QString errorText;
    QString sourceDetail;
    // usedWinApiFallback：记录手动 NTFS 解析是否已经降级到 Windows API。
    bool usedWinApiFallback = false;
    bool partialResult = false;
    QStringList suspiciousNames;
    const ManualParseBackend parseBackend = manualParseBackendForPanel(panel);
    const bool driverMode = parseBackendIsKernel(parseBackend);
    const QString backendText = parseBackendDisplayText(parseBackend);
    const ks::file::ManualFsType requestedFsType = requestedManualFsTypeForPanel(panel);
    const int requestedReadMode = panel.readModeCombo != nullptr
        ? panel.readModeCombo->currentIndex()
        : 0;
    const bool parseOk = runManualParseBackend(
        parseBackend,
        panel.currentPath,
        requestedFsType,
        entries,
        fsType,
        errorText,
        usedWinApiFallback,
        partialResult,
        sourceDetail,
        suspiciousNames);

    panel.manualModel->removeRows(0, panel.manualModel->rowCount());
    panel.lastManualFsType = fsType;
    panel.manualRequestedFsType = requestedFsType;
    panel.manualRequestedReadMode = requestedReadMode;
    panel.manualResultPartial = partialResult;
    panel.manualSourceDetail = sourceDetail;
    panel.manualSuspiciousNames = suspiciousNames;
    if (!parseOk)
    {
        // privilegePromptHandled：恢复提示已处理权限问题时不再显示手动解析通用错误。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            driverMode
                ? QStringLiteral("%1目录").arg(backendText)
                : QStringLiteral("读取原始文件系统数据"),
            errorText);
        panel.manualLoadedPath.clear();
        if (panel.parserStatusLabel != nullptr)
        {
            panel.parserStatusLabel->setText(
                QStringLiteral("解析器: %1失败").arg(backendText));
        }
        if (showWarningMessage && !privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("%1失败").arg(backendText),
                QStringLiteral("路径: %1\n错误: %2")
                .arg(QDir::toNativeSeparators(panel.currentPath))
                .arg(errorText));
        }

        kLogEvent event;
        warn << event
            << "[FileDock] 目录解析失败, source="
            << parseBackendLogTag(parseBackend)
            << ", panel="
            << panel.panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        return false;
    }

    const QSet<QString> suspiciousNameSet = buildSuspiciousNameSet(suspiciousNames);
    // reparseProbeBudget：本批回填允许的同步重解析点探测次数。
    int reparseProbeBudget = kMaxBatchReparseProbes;
    for (const ks::file::ManualDirectoryEntry& itemValue : entries)
    {
        QList<QStandardItem*> rowItems;
        rowItems.reserve(static_cast<int>(ManualModelColumn::Count));

        QStandardItem* nameItem = new QStandardItem(itemValue.name);
        nameItem->setIcon(QApplication::style()->standardIcon(
            itemValue.isDirectory ? QStyle::SP_DirIcon : QStyle::SP_FileIcon));
        nameItem->setData(itemValue.absolutePath, Qt::UserRole);
        nameItem->setData(itemValue.isDirectory, Qt::UserRole + 1);
        rowItems.push_back(nameItem);

        QStandardItem* sizeItem = new QStandardItem(itemValue.isDirectory ? QStringLiteral("-") : formatSizeText(itemValue.sizeBytes));
        sizeItem->setData(static_cast<qulonglong>(itemValue.sizeBytes), Qt::UserRole);
        rowItems.push_back(sizeItem);

        QString typeText = itemValue.typeText;
        // 限额内才做同步探测，见 kMaxBatchReparseProbes 的说明。
        if (reparseProbeBudget > 0)
        {
            --reparseProbeBudget;
            const QString reparseMarkerText =
                reparseKindMarkerForPath(itemValue.absolutePath);
            if (!reparseMarkerText.isEmpty())
            {
                typeText = QStringLiteral("%1 / %2").arg(reparseMarkerText, typeText);
            }
        }
        rowItems.push_back(new QStandardItem(typeText));
        rowItems.push_back(new QStandardItem(itemValue.modifiedTime.isValid()
            ? itemValue.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
            : QStringLiteral("-")));
        rowItems.push_back(new QStandardItem(QDir::toNativeSeparators(itemValue.absolutePath)));
        rowItems.push_back(new QStandardItem(itemValue.isDirectory ? QStringLiteral("1") : QStringLiteral("0")));
        markSuspiciousRowIfNeeded(rowItems, itemValue.name, suspiciousNameSet);
        panel.manualModel->appendRow(rowItems);
    }

    if (panel.parserStatusLabel != nullptr)
    {
        // 手动链路失败后若已回退到 Windows API，则必须明确展示真实来源，避免 UI 误导。
        if (!sourceDetail.isEmpty())
        {
            QString statusText = QStringLiteral("解析器: %1").arg(sourceDetail);
            if (!suspiciousNames.isEmpty())
            {
                statusText += QStringLiteral("；疑似隐藏项 %1 个")
                    .arg(suspiciousNames.size());
            }
            panel.parserStatusLabel->setText(statusText);
        }
        else if (usedWinApiFallback)
        {
            panel.parserStatusLabel->setText(
                QStringLiteral("解析器: Windows API 回退 (%1)")
                .arg(manualFsTypeToText(fsType)));
        }
        else
        {
            panel.parserStatusLabel->setText(
                QStringLiteral("解析器: %1 (手动)")
                .arg(manualFsTypeToText(fsType)));
        }
    }
    panel.manualLoadedPath = panel.currentPath;

    kLogEvent event;
    info << event
        << "[FileDock] 目录解析完成, source="
        << parseBackendLogTag(parseBackend)
        << ", panel="
        << panel.panelNameText.toStdString()
        << ", partial="
        << (partialResult ? "true" : "false")
        << ", fsType="
        << manualFsTypeToText(fsType).toStdString()
        << ", rows="
        << entries.size()
        << ", path="
        << QDir::toNativeSeparators(panel.currentPath).toStdString()
        << eol;
    return true;
}

void FileDock::requestAsyncManualReload(FilePanelWidgets& panel, const bool showWarningMessage)
{
    if (panel.manualModel == nullptr || panel.currentPath.isEmpty())
    {
        return;
    }

    // requestedPath：记录本次调用目标路径，避免在异步流程里读取到后续变更值。
    const QString requestedPath = panel.currentPath;
    const ks::file::ManualFsType requestedFsType = requestedManualFsTypeForPanel(panel);
    const int requestedReadMode = panel.readModeCombo != nullptr
        ? panel.readModeCombo->currentIndex()
        : 0;
    const ManualParseBackend parseBackend = manualParseBackendForPanel(panel);
    const bool driverMode = parseBackendIsKernel(parseBackend);
    const QString backendText = parseBackendDisplayText(parseBackend);

    // 路径已经加载且当前没有任务运行时，直接复用结果，避免无意义重复解析。
    if (!panel.manualParseInProgress
        && panel.manualLoadedPath.compare(requestedPath, Qt::CaseInsensitive) == 0
        && panel.manualRequestedFsType == requestedFsType
        && panel.manualRequestedReadMode == requestedReadMode)
    {
        return;
    }

    panel.manualRequestedFsType = requestedFsType;
    panel.manualRequestedReadMode = requestedReadMode;

    // 若已有后台任务在跑，仅在“目标请求发生变化”时登记 pending。
    // 判据必须连读取方式一起比：同一个目录换一种解析方式，结果是完全不同的
    // 两份数据（WinAPI 视图 / 纯 MFT 视图 / IRP 绕过视图）。只比路径会把
    // 换方式的请求当成重复请求丢掉，最终表格里留着旧后端的结果，
    // 下拉框却显示新方式——看起来就是"切了没反应"。
    if (panel.manualParseInProgress)
    {
        const bool samePathRunning =
            (panel.manualParsingPath.compare(requestedPath, Qt::CaseInsensitive) == 0)
            && (panel.manualParsingReadMode == requestedReadMode);
        if (samePathRunning)
        {
            panel.manualParsePendingShowWarning =
                panel.manualParsePendingShowWarning || showWarningMessage;
            return;
        }

        panel.manualParsePending = true;
        panel.manualParsePendingShowWarning = panel.manualParsePendingShowWarning || showWarningMessage;

        {
            kLogEvent event;
            dbg << event
                << "[FileDock] 手动解析任务排队, panel="
                << panel.panelNameText.toStdString()
                << ", runningPath="
                << QDir::toNativeSeparators(panel.manualParsingPath).toStdString()
                << ", pendingPath="
                << QDir::toNativeSeparators(requestedPath).toStdString()
                << eol;
        }
        return;
    }

    panel.manualParseInProgress = true;
    panel.manualParsePending = false;
    panel.manualParsePendingShowWarning = false;
    panel.manualParseRequestSerial += 1;
    panel.manualParsingPath = requestedPath;
    panel.manualParsingReadMode = requestedReadMode;

    // 记录请求上下文：用于后台线程回传时校验“结果是否过期”。
    const int requestSerial = panel.manualParseRequestSerial;
    const QString requestPath = requestedPath;
    const QString panelNameText = panel.panelNameText;
    const bool leftPanelRequest = (&panel == &m_leftPanel);

    // 平铺解析进度条：R3 原始解析与 R0 内核枚举共用同一套异步回填机制。
    const QString parserTaskText = QStringLiteral(" ") + backendText;
    const int progressPid = kPro.add(this, "文件", (panelNameText + parserTaskText).toStdString());
    kPro.set(progressPid, "准备解析目录", 0, 5.0f);

    if (panel.parserStatusLabel != nullptr)
    {
        panel.parserStatusLabel->setText(
            QStringLiteral("解析器: %1中...").arg(backendText));
    }
    if (panel.readModeCombo != nullptr)
    {
        panel.readModeCombo->setEnabled(false);
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 启动异步平铺解析, source="
            << parseBackendLogTag(parseBackend)
            << ", panel="
            << panelNameText.toStdString()
            << ", path="
            << QDir::toNativeSeparators(requestPath).toStdString()
            << ", requestSerial="
            << requestSerial
            << eol;
    }

    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, leftPanelRequest, requestPath, requestedFsType, requestedReadMode, parseBackend, driverMode, backendText, panelNameText, showWarningMessage, requestSerial, progressPid]() {
        kPro.set(
            progressPid,
            (backendText + QStringLiteral("目录中")).toStdString(),
            0,
            35.0f);

        std::vector<ks::file::ManualDirectoryEntry> parsedEntries;
        ks::file::ManualFsType parsedFsType = ks::file::ManualFsType::Unknown;
        QString parseErrorText;
        // usedWinApiFallback：记录后台解析是否已退回到 Windows API，供 UI 正确显示状态。
        bool usedWinApiFallback = false;
        bool partialResult = false;
        QString sourceDetail;
        QStringList suspiciousNames;
        const bool parseOk = runManualParseBackend(
            parseBackend,
            requestPath,
            requestedFsType,
            parsedEntries,
            parsedFsType,
            parseErrorText,
            usedWinApiFallback,
            partialResult,
            sourceDetail,
            suspiciousNames);

        kPro.set(progressPid, parseOk ? "生成目录列表中" : "解析失败，整理错误信息", 0, 78.0f);

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        const bool invokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis,
             leftPanelRequest,
             requestPath,
             requestedFsType,
             requestedReadMode,
             parseBackend,
             driverMode,
             backendText,
             panelNameText,
             showWarningMessage,
             requestSerial,
             progressPid,
             parseOk,
             parsedEntries = std::move(parsedEntries),
             parsedFsType,
             parseErrorText,
             usedWinApiFallback,
             partialResult,
             sourceDetail,
             suspiciousNames]() mutable {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                FilePanelWidgets& targetPanel = leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                if (targetPanel.manualParseRequestSerial != requestSerial)
                {
                    // 过期结果直接丢弃，避免“慢任务覆盖新路径数据”。
                    // 运行状态只有在这一批结果确实属于当前那次运行时才清：
                    // 路径不符说明面板已经在跑另一次解析，清了会让它误以为空闲。
                    if (targetPanel.manualParsingPath.compare(requestPath, Qt::CaseInsensitive) == 0)
                    {
                        targetPanel.manualParseInProgress = false;
                        targetPanel.manualParsingPath.clear();
                    }
                    // 下拉框的可用性与运行状态解绑，无条件恢复。
                    // 它是在本次请求开始时被禁用的，只要这次请求走到了终点
                    //（无论采纳还是丢弃）就必须放开；放在上面的条件分支里，
                    // 一旦路径对不上就再也没有人把它打开，表现就是"选了某个
                    // 读取方式之后下拉框彻底点不动"。
                    if (targetPanel.readModeCombo != nullptr &&
                        !targetPanel.manualParseInProgress)
                    {
                        targetPanel.readModeCombo->setEnabled(true);
                    }

                    {
                        kLogEvent event;
                        warn << event
                            << "[FileDock] 丢弃过期平铺解析结果, source="
                            << parseBackendLogTag(parseBackend)
                            << ", panel="
                            << panelNameText.toStdString()
                            << ", path="
                            << QDir::toNativeSeparators(requestPath).toStdString()
                            << ", requestSerial="
                            << requestSerial
                            << ", currentSerial="
                            << targetPanel.manualParseRequestSerial
                            << eol;
                    }

                    kPro.set(progressPid, "结果过期已忽略", 0, 100.0f);

                    if (!targetPanel.manualParseInProgress && targetPanel.manualParsePending)
                    {
                        const bool pendingShowWarning = targetPanel.manualParsePendingShowWarning;
                        targetPanel.manualParsePending = false;
                        targetPanel.manualParsePendingShowWarning = false;
                        safeThis->requestAsyncManualReload(targetPanel, pendingShowWarning);
                    }
                    return;
                }

                const auto parsedEntriesSnapshot =
                    std::make_shared<std::vector<ks::file::ManualDirectoryEntry>>(
                        std::move(parsedEntries));
                const auto commitSnapshot =
                    [safeThis,
                     leftPanelRequest,
                     requestPath,
                     requestedFsType,
                     requestedReadMode,
                     parseBackend,
                     driverMode,
                     backendText,
                     panelNameText,
                     showWarningMessage,
                     requestSerial,
                     progressPid,
                     parseOk,
                     parsedEntriesSnapshot,
                     parsedFsType,
                     parseErrorText,
                     usedWinApiFallback,
                     partialResult,
                     sourceDetail,
                     suspiciousNames]()
                {
                    if (safeThis.isNull())
                    {
                        kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                        return;
                    }

                    FilePanelWidgets& commitPanel =
                        leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                    if (commitPanel.manualParseRequestSerial != requestSerial)
                    {
                        return;
                    }

                    commitPanel.manualParseInProgress = false;
                    commitPanel.manualParsingPath.clear();
                    commitPanel.manualRequestedFsType = requestedFsType;
                    commitPanel.manualRequestedReadMode = requestedReadMode;
                    commitPanel.manualResultPartial = partialResult;
                    commitPanel.manualSourceDetail = sourceDetail;
                    commitPanel.manualSuspiciousNames = suspiciousNames;
                    if (commitPanel.readModeCombo != nullptr)
                    {
                        commitPanel.readModeCombo->setEnabled(true);
                    }

                    commitPanel.manualModel->setRowCount(0);
                    commitPanel.lastManualFsType = parsedFsType;

                    if (!parseOk)
                    {
                        // 失败时也记住路径，避免过滤/排序触发连续重试。
                        commitPanel.manualLoadedPath = requestPath;
                        if (commitPanel.parserStatusLabel != nullptr)
                        {
                            commitPanel.parserStatusLabel->setText(
                                QStringLiteral("解析器: %1失败").arg(backendText));
                        }

                        // 原始文件系统枚举需要直接读取卷设备；普通令牌会返回 ERROR_ACCESS_DENIED。
                        // 异步完成回调必须与同步入口一样接入统一提权恢复，否则模式切换只会留下空表。
                        const bool privilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(
                                safeThis.data(),
                                driverMode
                                ? QStringLiteral("%1目录").arg(backendText)
                                : QStringLiteral("读取原始文件系统数据"),
                                parseErrorText);
                        if (showWarningMessage && !privilegePromptHandled)
                        {
                            QMessageBox::warning(
                                safeThis.data(),
                                QStringLiteral("%1失败").arg(backendText),
                                QStringLiteral("路径: %1\n错误: %2")
                                .arg(QDir::toNativeSeparators(requestPath))
                                .arg(parseErrorText));
                        }

                        kLogEvent event;
                        warn << event
                            << "[FileDock] 异步平铺解析失败, source="
                            << parseBackendLogTag(parseBackend)
                            << ", panel="
                            << panelNameText.toStdString()
                            << ", path="
                            << QDir::toNativeSeparators(requestPath).toStdString()
                            << ", error="
                            << parseErrorText.toStdString()
                            << eol;
                    }
                    else
                    {
                        // 批量回填模型：
                        // - 不再阻断 manualModel 信号，避免 proxy 无法感知新增行导致“日志显示有 rows 但视图空白”。
                        // - 通过临时关闭视图重绘降低批量插入期间的 UI 开销。
                        if (commitPanel.fileView != nullptr)
                        {
                            commitPanel.fileView->setUpdatesEnabled(false);
                            commitPanel.compactFileView->setUpdatesEnabled(false);
                        }
                        const QSet<QString> suspiciousNameSet =
                            buildSuspiciousNameSet(suspiciousNames);
                        // reparseProbeBudget：本批回填允许的同步重解析点探测次数。
                        int reparseProbeBudget = kMaxBatchReparseProbes;
                        for (const ks::file::ManualDirectoryEntry& itemValue : *parsedEntriesSnapshot)
                        {
                            QList<QStandardItem*> rowItems;
                            rowItems.reserve(static_cast<int>(ManualModelColumn::Count));

                            QStandardItem* nameItem = new QStandardItem(itemValue.name);
                            nameItem->setIcon(QApplication::style()->standardIcon(
                                itemValue.isDirectory ? QStyle::SP_DirIcon : QStyle::SP_FileIcon));
                            nameItem->setData(itemValue.absolutePath, Qt::UserRole);
                            nameItem->setData(itemValue.isDirectory, Qt::UserRole + 1);
                            rowItems.push_back(nameItem);

                            QStandardItem* sizeItem = new QStandardItem(
                                itemValue.isDirectory
                                ? QStringLiteral("-")
                                : formatSizeText(itemValue.sizeBytes));
                            sizeItem->setData(
                                static_cast<qulonglong>(itemValue.sizeBytes),
                                Qt::UserRole);
                            rowItems.push_back(sizeItem);

                            QString typeText = itemValue.typeText;
                            // 限额内才做同步探测，见 kMaxBatchReparseProbes 的说明。
                            // 这条路径尤其关键：R0/IRP 读取方式一次可以回填上万行，
                            // 逐行做 Win32 查询会把 UI 线程按住好几秒。
                            if (reparseProbeBudget > 0)
                            {
                                --reparseProbeBudget;
                                const QString reparseMarkerText =
                                    reparseKindMarkerForPath(itemValue.absolutePath);
                                if (!reparseMarkerText.isEmpty())
                                {
                                    typeText = QStringLiteral("%1 / %2")
                                        .arg(reparseMarkerText, typeText);
                                }
                            }
                            rowItems.push_back(new QStandardItem(typeText));
                            rowItems.push_back(new QStandardItem(
                                itemValue.modifiedTime.isValid()
                                ? itemValue.modifiedTime.toString(
                                    QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                                : QStringLiteral("-")));
                            rowItems.push_back(new QStandardItem(
                                QDir::toNativeSeparators(itemValue.absolutePath)));
                            rowItems.push_back(new QStandardItem(
                                itemValue.isDirectory
                                ? QStringLiteral("1")
                                : QStringLiteral("0")));
                            markSuspiciousRowIfNeeded(
                                rowItems, itemValue.name, suspiciousNameSet);
                            commitPanel.manualModel->appendRow(rowItems);
                        }
                        if (commitPanel.manualProxyModel != nullptr)
                        {
                            commitPanel.manualProxyModel->invalidate();
                        }
                        if (commitPanel.fileView != nullptr)
                        {
                            commitPanel.fileView->setRootIndex(QModelIndex());
                            commitPanel.compactFileView->setRootIndex(QModelIndex());
                            commitPanel.fileView->setUpdatesEnabled(true);
                            commitPanel.compactFileView->setUpdatesEnabled(true);
                        }

                        if (commitPanel.parserStatusLabel != nullptr)
                        {
                            // 异步路径与同步路径保持同一展示规则，并明确标示真实数据来源。
                            if (!sourceDetail.isEmpty())
                            {
                                QString statusText =
                                    QStringLiteral("解析器: %1").arg(sourceDetail);
                                if (!suspiciousNames.isEmpty())
                                {
                                    statusText += QStringLiteral("；疑似隐藏项 %1 个")
                                        .arg(suspiciousNames.size());
                                }
                                commitPanel.parserStatusLabel->setText(statusText);
                            }
                            else if (usedWinApiFallback)
                            {
                                commitPanel.parserStatusLabel->setText(
                                    QStringLiteral("解析器: Windows API 回退 (%1)")
                                    .arg(manualFsTypeToText(parsedFsType)));
                            }
                            else
                            {
                                commitPanel.parserStatusLabel->setText(
                                    QStringLiteral("解析器: %1 (手动)")
                                    .arg(manualFsTypeToText(parsedFsType)));
                            }
                        }
                        commitPanel.manualLoadedPath = requestPath;

                        kLogEvent event;
                        info << event
                            << "[FileDock] 异步平铺解析完成, source="
                            << parseBackendLogTag(parseBackend)
                            << ", panel="
                            << panelNameText.toStdString()
                            << ", fsType="
                            << manualFsTypeToText(parsedFsType).toStdString()
                            << ", rows="
                            << parsedEntriesSnapshot->size()
                            << ", partial="
                            << (partialResult ? "true" : "false")
                            << ", path="
                            << QDir::toNativeSeparators(requestPath).toStdString()
                            << eol;
                    }

                    // 模型回填后重新应用过滤/排序，让视图立即更新到当前条件。
                    safeThis->applyPanelFilterAndSort(commitPanel);
                    kPro.set(
                        progressPid,
                        (backendText +
                            (parseOk
                                ? QStringLiteral("完成")
                                : QStringLiteral("失败"))).toStdString(),
                        0,
                        100.0f);

                    // 若解析过程中用户又切了目录，完成后立即执行挂起请求。
                    if (!commitPanel.manualParseInProgress && commitPanel.manualParsePending)
                    {
                        const bool pendingShowWarning =
                            commitPanel.manualParsePendingShowWarning;
                        commitPanel.manualParsePending = false;
                        commitPanel.manualParsePendingShowWarning = false;
                        safeThis->requestAsyncManualReload(commitPanel, pendingShowWarning);
                    }
                };

                const QString commitKey = leftPanelRequest
                    ? QStringLiteral("file-manual-model-left")
                    : QStringLiteral("file-manual-model-right");
                if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    commitKey,
                    { targetPanel.fileView },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);

        if (!invokeOk)
        {
            kPro.set(progressPid, "回调失败", 0, 100.0f);
        }
    }).detach();
}

bool FileDock::currentModeIsManual(const FilePanelWidgets& panel) const
{
    return panel.readModeCombo != nullptr && panel.readModeCombo->currentIndex() >= 1;
}

bool FileDock::currentModeUsesDriver(const FilePanelWidgets& panel) const
{
    // R0 驱动解析与 R0 IRP 解析都由内核应答；其它平铺模式仍在 R3 完成。
    return parseBackendIsKernel(manualParseBackendForPanel(panel));
}

ks::file::ManualFsType FileDock::requestedManualFsTypeForPanel(const FilePanelWidgets& panel) const
{
    if (panel.readModeCombo == nullptr)
    {
        return ks::file::ManualFsType::Unknown;
    }

    switch (panel.readModeCombo->currentIndex())
    {
    case 3:
        return ks::file::ManualFsType::Ntfs;
    case 4:
        return ks::file::ManualFsType::Fat32;
    case 5:
        return ks::file::ManualFsType::ExFat;
    case 6:
        // 纯 MFT 扫描只在 NTFS 上成立，强制按 NTFS 解析。
        return ks::file::ManualFsType::Ntfs;
    default:
        return ks::file::ManualFsType::Unknown;
    }
}

FileDock::ManualParseBackend FileDock::manualParseBackendForPanel(
    const FilePanelWidgets& panel) const
{
    if (panel.readModeCombo == nullptr)
    {
        return ManualParseBackend::WindowsApi;
    }

    switch (panel.readModeCombo->currentIndex())
    {
    case 0:
        return ManualParseBackend::WindowsApi;
    case 2:
        return ManualParseBackend::R0Driver;
    case 6:
        return ManualParseBackend::MftStrict;
    case 7:
        return ManualParseBackend::R0Irp;
    default:
        // 1/3/4/5 都是 R3 手动解析，区别只在强制文件系统类型。
        return ManualParseBackend::ManualFs;
    }
}

bool FileDock::parseBackendIsKernel(const ManualParseBackend backend)
{
    return backend == ManualParseBackend::R0Driver ||
        backend == ManualParseBackend::R0Irp;
}

QString FileDock::parseBackendDisplayText(const ManualParseBackend backend)
{
    switch (backend)
    {
    case ManualParseBackend::R0Driver:
        return QStringLiteral("R0 驱动解析");
    case ManualParseBackend::R0Irp:
        return QStringLiteral("R0 IRP 解析");
    case ManualParseBackend::MftStrict:
        return QStringLiteral("纯 MFT 解析");
    case ManualParseBackend::ManualFs:
        return QStringLiteral("手动解析");
    case ManualParseBackend::WindowsApi:
    default:
        return QStringLiteral("Windows API");
    }
}

const char* FileDock::parseBackendLogTag(const ManualParseBackend backend)
{
    switch (backend)
    {
    case ManualParseBackend::R0Driver:
        return "R0";
    case ManualParseBackend::R0Irp:
        return "R0-IRP";
    case ManualParseBackend::MftStrict:
        return "R3-mft";
    case ManualParseBackend::ManualFs:
        return "R3-manual";
    case ManualParseBackend::WindowsApi:
    default:
        return "WinAPI";
    }
}

bool FileDock::runManualParseBackend(
    const ManualParseBackend backend,
    const QString& pathText,
    const ks::file::ManualFsType requestedFsType,
    std::vector<ks::file::ManualDirectoryEntry>& entriesOut,
    ks::file::ManualFsType& fsTypeOut,
    QString& errorTextOut,
    bool& usedWinApiFallbackOut,
    bool& partialOut,
    QString& sourceDetailOut,
    QStringList& suspiciousNamesOut)
{
    usedWinApiFallbackOut = false;
    partialOut = false;
    sourceDetailOut.clear();
    suspiciousNamesOut.clear();

    switch (backend)
    {
    case ManualParseBackend::R0Driver:
        return ks::file::DriverFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &partialOut,
            &sourceDetailOut);

    case ManualParseBackend::R0Irp:
    {
        ks::file::IrpScanDiagnostics diagnostics;
        const bool parseOk = ks::file::IrpFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &partialOut,
            &sourceDetailOut,
            &diagnostics);
        if (parseOk)
        {
            suspiciousNamesOut = diagnostics.bypassOnlyNames;
        }
        return parseOk;
    }

    case ManualParseBackend::MftStrict:
    {
        ks::file::MftScanDiagnostics diagnostics;
        fsTypeOut = ks::file::ManualFsType::Ntfs;
        const bool parseOk = ks::file::ManualFileSystemParser::enumerateDirectoryByMft(
            pathText,
            entriesOut,
            errorTextOut,
            &diagnostics);
        if (!parseOk)
        {
            return false;
        }
        suspiciousNamesOut = diagnostics.mftOnlyNames;
        sourceDetailOut = diagnostics.comparisonAvailable
            ? QStringLiteral("纯 MFT 解析；条目=%1；目录枚举视图=%2；仅 MFT 可见=%3")
                .arg(diagnostics.mftEntryCount)
                .arg(diagnostics.winApiEntryCount)
                .arg(diagnostics.mftOnlyNames.size())
            : QStringLiteral("纯 MFT 解析；条目=%1；未取得目录枚举对照")
                .arg(diagnostics.mftEntryCount);
        return true;
    }

    case ManualParseBackend::ManualFs:
    case ManualParseBackend::WindowsApi:
    default:
        return ks::file::ManualFileSystemParser::enumerateDirectory(
            pathText,
            entriesOut,
            fsTypeOut,
            errorTextOut,
            &usedWinApiFallbackOut,
            requestedFsType);
    }
}

void FileDock::initializeRecoveryPage()
{
    m_fileRecoveryPage = new QWidget(m_rootTabWidget);
    QVBoxLayout* recoveryLayout = new QVBoxLayout(m_fileRecoveryPage);
    recoveryLayout->setContentsMargins(6, 6, 6, 6);
    recoveryLayout->setSpacing(6);

    QWidget* toolWidget = new QWidget(m_fileRecoveryPage);
    QHBoxLayout* toolLayout = new QHBoxLayout(toolWidget);
    toolLayout->setContentsMargins(0, 0, 0, 0);
    toolLayout->setSpacing(6);

    m_recoveryVolumeCombo = new QComboBox(toolWidget);
    m_recoveryVolumeCombo->setStyleSheet(buildBlueInputStyle());
    m_recoveryVolumeCombo->setToolTip(QStringLiteral("选择要扫描误删文件的 NTFS 卷。"));

    m_recoveryRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), toolWidget);
    m_recoveryRefreshButton->setToolTip(QStringLiteral("刷新可扫描卷列表"));
    m_recoveryRefreshButton->setStyleSheet(buildBlueButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(m_recoveryRefreshButton);

    m_recoveryScanButton = new QPushButton(QIcon(":/Icon/log_track.svg"), QStringLiteral("扫描误删"), toolWidget);
    m_recoveryScanButton->setToolTip(QStringLiteral("解析 NTFS MFT，扫描删除项"));
    m_recoveryScanButton->setStyleSheet(buildBlueButtonStyle());

    m_recoveryExportButton = new QPushButton(QIcon(":/Icon/log_export.svg"), QStringLiteral("恢复选中"), toolWidget);
    m_recoveryExportButton->setToolTip(QStringLiteral(
        "支持 Resident 与完整非驻留数据；非驻留文件必须导出到其它卷，恢复前后都会复核卷位图。"));
    m_recoveryExportButton->setStyleSheet(buildBlueButtonStyle());

    // 扫描结果动辄上万条，必须能就地查找，否则只能靠滚动条翻找。
    m_recoveryFilterEdit = new QLineEdit(toolWidget);
    m_recoveryFilterEdit->setPlaceholderText(QStringLiteral("查找结果（文件名/路径/恢复能力）"));
    m_recoveryFilterEdit->setClearButtonEnabled(true);
    m_recoveryFilterEdit->setStyleSheet(buildBlueInputStyle());
    m_recoveryFilterEdit->setToolTip(QStringLiteral(
        "按输入内容实时筛选扫描结果，匹配行以外的条目会被隐藏。"));

    m_recoveryFilterRegexButton = new QToolButton(toolWidget);
    m_recoveryFilterRegexButton->setText(QStringLiteral(".*"));
    m_recoveryFilterRegexButton->setCheckable(true);
    m_recoveryFilterRegexButton->setToolTip(QStringLiteral(
        "按正则表达式筛选，例如 \\.docx?$ 只看 doc/docx"));

    toolLayout->addWidget(new QLabel(QStringLiteral("卷: "), toolWidget), 0);
    toolLayout->addWidget(m_recoveryVolumeCombo, 1);
    toolLayout->addWidget(m_recoveryRefreshButton, 0);
    toolLayout->addWidget(m_recoveryScanButton, 0);
    toolLayout->addWidget(m_recoveryFilterEdit, 1);
    toolLayout->addWidget(m_recoveryFilterRegexButton, 0);
    toolLayout->addWidget(m_recoveryExportButton, 0);
    recoveryLayout->addWidget(toolWidget, 0);

    m_recoveryTable = new ks::ui::VisibleTableWidget(m_fileRecoveryPage);
    m_recoveryTable->setColumnCount(7);
    m_recoveryTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("文件名"),
        QStringLiteral("路径提示"),
        QStringLiteral("大小"),
        QStringLiteral("修改时间"),
        QStringLiteral("记录号"),
        QStringLiteral("完整度"),
        QStringLiteral("恢复能力")
        });
    m_recoveryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_recoveryTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_recoveryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_recoveryTable->verticalHeader()->setVisible(false);
    m_recoveryTable->horizontalHeader()->setStretchLastSection(true);
    m_recoveryTable->setAlternatingRowColors(true);
    installRecoveryTableMenu();

    // 结果区用堆叠容器：没有结果时显示居中的引导页，
    // 否则工具条右端那个“扫描误删”按钮在整片空白表格旁边很难被注意到。
    m_recoveryViewStack = new QStackedWidget(m_fileRecoveryPage);

    m_recoveryEmptyPage = new QWidget(m_recoveryViewStack);
    QVBoxLayout* emptyLayout = new QVBoxLayout(m_recoveryEmptyPage);
    emptyLayout->setContentsMargins(24, 24, 24, 24);
    emptyLayout->setSpacing(12);
    emptyLayout->addStretch(1);

    m_recoveryEmptyHintLabel = new QLabel(
        QStringLiteral("选择 NTFS 卷后开始扫描，可在此列出仍可恢复的误删文件。"),
        m_recoveryEmptyPage);
    m_recoveryEmptyHintLabel->setAlignment(Qt::AlignCenter);
    m_recoveryEmptyHintLabel->setWordWrap(true);
    emptyLayout->addWidget(m_recoveryEmptyHintLabel, 0);

    m_recoveryEmptyScanButton = new QPushButton(
        QIcon(":/Icon/log_track.svg"),
        QStringLiteral("开始扫描误删文件"),
        m_recoveryEmptyPage);
    m_recoveryEmptyScanButton->setStyleSheet(buildBlueButtonStyle());
    m_recoveryEmptyScanButton->setMinimumHeight(38);
    m_recoveryEmptyScanButton->setMinimumWidth(200);
    m_recoveryEmptyScanButton->setToolTip(QStringLiteral("解析 NTFS MFT，扫描删除项"));

    QHBoxLayout* emptyButtonLayout = new QHBoxLayout();
    emptyButtonLayout->addStretch(1);
    emptyButtonLayout->addWidget(m_recoveryEmptyScanButton, 0);
    emptyButtonLayout->addStretch(1);
    emptyLayout->addLayout(emptyButtonLayout, 0);
    emptyLayout->addStretch(1);

    m_recoveryViewStack->addWidget(m_recoveryEmptyPage);
    m_recoveryViewStack->addWidget(m_recoveryTable);
    m_recoveryViewStack->setCurrentWidget(m_recoveryEmptyPage);
    recoveryLayout->addWidget(m_recoveryViewStack, 1);

    m_recoveryStatusLabel = new QLabel(QStringLiteral("请选择NTFS卷并开始扫描。"), m_fileRecoveryPage);
    recoveryLayout->addWidget(m_recoveryStatusLabel, 0);

    connect(m_recoveryRefreshButton, &QPushButton::clicked, this, [this]() {
        refreshRecoveryVolumeList();
    });
    connect(m_recoveryScanButton, &QPushButton::clicked, this, [this]() {
        scanDeletedFilesForRecovery();
    });
    connect(m_recoveryEmptyScanButton, &QPushButton::clicked, this, [this]() {
        scanDeletedFilesForRecovery();
    });
    connect(m_recoveryExportButton, &QPushButton::clicked, this, [this]() {
        recoverSelectedDeletedFiles();
    });
    connect(m_recoveryFilterEdit, &QLineEdit::textChanged, this, [this](const QString&) {
        applyRecoveryFilter();
    });
    connect(m_recoveryFilterRegexButton, &QToolButton::toggled, this, [this](bool) {
        applyRecoveryFilter();
    });

    refreshRecoveryVolumeList();
}

void FileDock::applyRecoveryFilter()
{
    // applyRecoveryFilter：
    // - 输入：查找框文本与正则开关；
    // - 处理：逐行比对已缓存的删除项字段，用 setRowHidden 就地隐藏不匹配行；
    // - 返回：无。只影响可见性，不改动 m_deletedRecoveryItems 与行号映射，
    //   因此右键属性、恢复选中拿到的行号依然直接对应缓存下标。
    if (m_recoveryTable == nullptr || m_recoveryFilterEdit == nullptr)
    {
        return;
    }

    const QString queryText = m_recoveryFilterEdit->text().trimmed();
    const bool useRegex =
        m_recoveryFilterRegexButton != nullptr && m_recoveryFilterRegexButton->isChecked();

    QRegularExpression regexValue;
    bool regexUsable = false;
    if (!queryText.isEmpty() && useRegex)
    {
        regexValue = QRegularExpression(
            queryText,
            QRegularExpression::CaseInsensitiveOption);
        regexUsable = regexValue.isValid();
        // 正则写到一半必然是非法的，这里不把整张表清空，保持上一次的可见状态。
        if (!regexUsable)
        {
            m_recoveryFilterEdit->setToolTip(QStringLiteral("正则表达式无效，已暂不筛选。"));
            return;
        }
    }
    m_recoveryFilterEdit->setToolTip(QStringLiteral(
        "按输入内容实时筛选扫描结果，匹配行以外的条目会被隐藏。"));

    const int rowCount = m_recoveryTable->rowCount();
    int visibleCount = 0;
    // 上万行逐行改可见性会触发大量重排，先关掉刷新再统一恢复。
    m_recoveryTable->setUpdatesEnabled(false);
    for (int row = 0; row < rowCount; ++row)
    {
        bool matched = queryText.isEmpty();
        if (!matched && row < static_cast<int>(m_deletedRecoveryItems.size()))
        {
            const ks::file::NtfsDeletedFileEntry& itemValue =
                m_deletedRecoveryItems[static_cast<std::size_t>(row)];
            // 只比对用户真正会搜的三个字段，避免大小/时间数字造成误命中。
            const QStringList searchFields{
                itemValue.fileName,
                itemValue.pathHint,
                deletedFileRecoveryCapabilityText(itemValue) };
            for (const QString& fieldText : searchFields)
            {
                if (useRegex)
                {
                    if (regexUsable && regexValue.match(fieldText).hasMatch())
                    {
                        matched = true;
                        break;
                    }
                }
                else if (fieldText.contains(queryText, Qt::CaseInsensitive))
                {
                    matched = true;
                    break;
                }
            }
        }

        m_recoveryTable->setRowHidden(row, !matched);
        if (matched)
        {
            ++visibleCount;
        }
    }
    m_recoveryTable->setUpdatesEnabled(true);

    if (m_recoveryStatusLabel != nullptr && !m_deletedRecoveryItems.empty())
    {
        m_recoveryStatusLabel->setText(
            queryText.isEmpty()
            ? m_recoveryBaseStatusText
            : QStringLiteral("%1｜筛选出 %2 / %3 项")
                .arg(m_recoveryBaseStatusText)
                .arg(visibleCount)
                .arg(rowCount));
    }
}

void FileDock::updateRecoveryViewState(const bool hasResults, const QString& emptyHintText)
{
    if (m_recoveryViewStack == nullptr)
    {
        return;
    }
    if (m_recoveryEmptyHintLabel != nullptr && !emptyHintText.isEmpty())
    {
        m_recoveryEmptyHintLabel->setText(emptyHintText);
    }
    m_recoveryViewStack->setCurrentWidget(
        hasResults
        ? static_cast<QWidget*>(m_recoveryTable)
        : static_cast<QWidget*>(m_recoveryEmptyPage));
}

void FileDock::installRecoveryTableMenu()
{
    // installRecoveryTableMenu：
    // - 输入：删除项结果表格的右键点击；
    // - 处理：在通用的“复制当前行”之外，补上“文件属性”和“恢复选中”，
    //   让这两个主操作不必再去工具条右端找按钮；
    // - 返回：无。属性只读展示，恢复走与工具条按钮完全相同的入口。
    if (m_recoveryTable == nullptr)
    {
        return;
    }

    m_recoveryTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_recoveryTable, &QTableWidget::customContextMenuRequested, this,
        [this](const QPoint& localPosition)
    {
        if (m_recoveryTable == nullptr)
        {
            return;
        }
        const QModelIndex clickedIndex = m_recoveryTable->indexAt(localPosition);
        // 右键空白处不改变既有多选；点在行上才把当前行切过去。
        if (clickedIndex.isValid() && !m_recoveryTable->selectionModel()->isSelected(clickedIndex))
        {
            m_recoveryTable->selectRow(clickedIndex.row());
        }

        const int currentRow = clickedIndex.isValid()
            ? clickedIndex.row()
            : m_recoveryTable->currentRow();
        const bool hasRow = currentRow >= 0
            && currentRow < static_cast<int>(m_deletedRecoveryItems.size());
        const bool hasSelection =
            !m_recoveryTable->selectionModel()->selectedRows().isEmpty();

        QMenu menu(m_recoveryTable);
        menu.setStyleSheet(buildContextMenuStyle());

        QAction* propertyAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("文件属性"));
        propertyAction->setEnabled(hasRow);

        QAction* recoverAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/log_export.svg")),
            QStringLiteral("恢复选中"));
        recoverAction->setEnabled(hasSelection && !m_recoveryRecoverInProgress);

        menu.addSeparator();
        QAction* copyRowAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            QStringLiteral("复制当前行"));
        copyRowAction->setEnabled(currentRow >= 0);

        QAction* selectedAction =
            menu.exec(m_recoveryTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == nullptr)
        {
            return;
        }
        if (selectedAction == propertyAction)
        {
            showDeletedFilePropertiesDialog(currentRow);
            return;
        }
        if (selectedAction == recoverAction)
        {
            recoverSelectedDeletedFiles();
            return;
        }
        if (selectedAction != copyRowAction)
        {
            return;
        }

        QClipboard* clipboardObject = QApplication::clipboard();
        if (clipboardObject == nullptr
            || currentRow < 0
            || currentRow >= m_recoveryTable->rowCount())
        {
            return;
        }
        QStringList fields;
        fields.reserve(m_recoveryTable->columnCount());
        for (int columnIndex = 0; columnIndex < m_recoveryTable->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = m_recoveryTable->item(currentRow, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        clipboardObject->setText(fields.join(QLatin1Char('\t')));
    });
}

void FileDock::showDeletedFilePropertiesDialog(const int rowIndex)
{
    if (rowIndex < 0 || rowIndex >= static_cast<int>(m_deletedRecoveryItems.size()))
    {
        return;
    }
    const ks::file::NtfsDeletedFileEntry& itemValue =
        m_deletedRecoveryItems[static_cast<std::size_t>(rowIndex)];

    QDialog dialog(this);
    dialog.setObjectName(QStringLiteral("DeletedFilePropertyDialog"));
    dialog.setStyleSheet(buildOpaqueStandaloneDialogStyle(dialog.objectName()));
    dialog.setWindowTitle(QStringLiteral("删除项属性"));
    dialog.resize(620, 460);

    QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);

    // 属性用只读表格展示：字段多且需要整段复制，比 QFormLayout 更实用。
    QTableWidget* propertyTable = new ks::ui::VisibleTableWidget(&dialog);
    propertyTable->setColumnCount(2);
    propertyTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("属性"),
        QStringLiteral("值") });
    propertyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    propertyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    propertyTable->verticalHeader()->setVisible(false);
    propertyTable->horizontalHeader()->setStretchLastSection(true);
    propertyTable->setAlternatingRowColors(true);
    installFileTableCopyMenu(propertyTable);

    const QString integrityText = (itemValue.estimatedIntegrityPercent >= 0)
        ? QStringLiteral("%1%").arg(itemValue.estimatedIntegrityPercent)
        : QStringLiteral("未知");
    const QString modifiedText = itemValue.modifiedTime.isValid()
        ? itemValue.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
        : QStringLiteral("-");

    const QVector<QPair<QString, QString>> propertyRows{
        { QStringLiteral("文件名"), itemValue.fileName },
        { QStringLiteral("原始文件名是否保留"),
          itemValue.hasOriginalName
          ? QStringLiteral("是")
          : QStringLiteral("否（当前为系统生成的占位名）") },
        { QStringLiteral("路径提示"), itemValue.pathHint },
        { QStringLiteral("大小"),
          QStringLiteral("%1 (%2 字节)")
              .arg(formatSizeText(itemValue.sizeBytes))
              .arg(static_cast<qulonglong>(itemValue.sizeBytes)) },
        { QStringLiteral("修改时间"), modifiedText },
        { QStringLiteral("MFT 记录号"),
          QString::number(static_cast<qulonglong>(itemValue.fileReference)) },
        { QStringLiteral("MFT 序列号"), QString::number(itemValue.sequenceNumber) },
        { QStringLiteral("完整度"), integrityText },
        { QStringLiteral("恢复能力"), deletedFileRecoveryCapabilityText(itemValue) },
        { QStringLiteral("驻留数据已就绪"),
          itemValue.residentDataReady ? QStringLiteral("是") : QStringLiteral("否") },
        { QStringLiteral("是否可安全恢复"),
          isDeletedFileSafelyRecoverable(itemValue)
          ? QStringLiteral("是")
          : QStringLiteral("否（恢复入口会拒绝此项）") },
    };

    propertyTable->setRowCount(propertyRows.size());
    for (int row = 0; row < propertyRows.size(); ++row)
    {
        propertyTable->setItem(row, 0, new QTableWidgetItem(propertyRows[row].first));
        propertyTable->setItem(row, 1, new QTableWidgetItem(propertyRows[row].second));
    }
    propertyTable->resizeColumnToContents(0);
    rootLayout->addWidget(propertyTable, 1);

    QLabel* noteLabel = new QLabel(
        QStringLiteral("以上为扫描时刻的 MFT 快照；恢复前会按记录号和序列号重新校验，不依赖此处的旧数据。"),
        &dialog);
    noteLabel->setWordWrap(true);
    rootLayout->addWidget(noteLabel, 0);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    buttonBox->button(QDialogButtonBox::Close)->setText(QStringLiteral("关闭"));
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    rootLayout->addWidget(buttonBox, 0);

    dialog.exec();
}

void FileDock::refreshRecoveryVolumeList()
{
    if (m_recoveryVolumeCombo == nullptr)
    {
        return;
    }

    // 卷探测（GetDriveTypeW + GetVolumeInformationW）会在空光驱、断线映射网络盘上
    // 阻塞数秒到数十秒，而本函数在“文件”页首次构造时就会被调用，留在 UI 线程等于
    // 让整窗在首次点开 Tab 时假死。这里只做“清空列表 + 置灰入口”，真实探测放后台。
    const quint64 requestGeneration =
        m_recoveryVolumeCombo->property(kRecoveryVolumeProbeGenerationProperty).toULongLong() + 1U;
    m_recoveryVolumeCombo->setProperty(
        kRecoveryVolumeProbeGenerationProperty, static_cast<qulonglong>(requestGeneration));

    m_recoveryVolumeCombo->clear();
    m_recoveryVolumeCombo->setEnabled(false);
    if (m_recoveryRefreshButton != nullptr)
    {
        m_recoveryRefreshButton->setEnabled(false);
    }
    if (m_recoveryScanButton != nullptr)
    {
        m_recoveryScanButton->setEnabled(false);
        if (m_recoveryEmptyScanButton != nullptr) { m_recoveryEmptyScanButton->setEnabled(false); }
    }
    if (m_recoveryStatusLabel != nullptr)
    {
        m_recoveryStatusLabel->setText(QStringLiteral("正在刷新..."));
    }

    const QPointer<FileDock> guardedSelf(this);
    QThreadPool::globalInstance()->start(
        [guardedSelf, requestGeneration]()
        {
            // 后台只产出值类型（卷根字符串列表），不触碰任何 QWidget。
            const QVector<QString> ntfsVolumeRootList = collectNtfsVolumeRootList();

            FileDock* const targetDock = guardedSelf.data();
            if (targetDock == nullptr)
            {
                return;
            }

            QMetaObject::invokeMethod(
                targetDock,
                [guardedSelf, requestGeneration, ntfsVolumeRootList]()
                {
                    if (guardedSelf.isNull())
                    {
                        return;
                    }

                    FileDock* const dock = guardedSelf.data();
                    if (dock->m_recoveryVolumeCombo == nullptr)
                    {
                        return;
                    }
                    // generation：只接受最后一次刷新请求的结果，淘汰已被取代的旧探测。
                    const quint64 currentGeneration = dock->m_recoveryVolumeCombo
                        ->property(kRecoveryVolumeProbeGenerationProperty)
                        .toULongLong();
                    if (currentGeneration != requestGeneration)
                    {
                        return;
                    }

                    // commitVolumeList：卷列表落地动作，直接提交与弹层收起后的回投共用同一份实现。
                    auto commitVolumeList = [guardedSelf, requestGeneration, ntfsVolumeRootList]()
                    {
                        if (guardedSelf.isNull())
                        {
                            return;
                        }
                        FileDock* const commitDock = guardedSelf.data();
                        if (commitDock->m_recoveryVolumeCombo == nullptr)
                        {
                            return;
                        }
                        // 延迟回投期间可能又发起了新一轮探测，落地前重新校验代次。
                        const quint64 latestGeneration = commitDock->m_recoveryVolumeCombo
                            ->property(kRecoveryVolumeProbeGenerationProperty)
                            .toULongLong();
                        if (latestGeneration != requestGeneration)
                        {
                            return;
                        }

                        commitDock->m_recoveryVolumeCombo->clear();
                        for (const QString& volumeRootPath : ntfsVolumeRootList)
                        {
                            const QString displayText = QStringLiteral("%1 (NTFS)").arg(volumeRootPath);
                            commitDock->m_recoveryVolumeCombo->addItem(displayText, volumeRootPath);
                        }
                        commitDock->m_recoveryVolumeCombo->setEnabled(true);

                        if (commitDock->m_recoveryRefreshButton != nullptr)
                        {
                            commitDock->m_recoveryRefreshButton->setEnabled(true);
                        }
                        // 扫描按钮的禁用权归误删扫描/恢复任务：探测结束不能把它们置灰的状态改回去。
                        if (commitDock->m_recoveryScanButton != nullptr
                            && !commitDock->m_recoveryScanInProgress
                            && !commitDock->m_recoveryRecoverInProgress)
                        {
                            commitDock->m_recoveryScanButton->setEnabled(true);
                            if (commitDock->m_recoveryEmptyScanButton != nullptr) { commitDock->m_recoveryEmptyScanButton->setEnabled(true); }
                        }

                        if (commitDock->m_recoveryStatusLabel != nullptr)
                        {
                            if (commitDock->m_recoveryVolumeCombo->count() == 0)
                            {
                                commitDock->m_recoveryStatusLabel->setText(
                                    QStringLiteral("未检测到可扫描的 NTFS 卷。"));
                            }
                            else
                            {
                                commitDock->m_recoveryStatusLabel->setText(
                                    QStringLiteral("已刷新卷列表，可执行误删扫描。"));
                            }
                        }

                        kLogEvent event;
                        info << event
                            << "[FileDock] 刷新文件恢复卷列表, count="
                            << commitDock->m_recoveryVolumeCombo->count()
                            << eol;
                    };

                    // 卷下拉框展开期间清空重填，会让弹层继续抓着鼠标键盘但内容失效，
                    // 界面表现为点不动；这里推迟到弹层收起后再落地。
                    if (ks::ui::DeferUiCommitIfComboBoxPopupOpen(
                            dock,
                            QStringLiteral("file-recovery-volume-combo-apply"),
                            commitVolumeList))
                    {
                        return;
                    }
                    commitVolumeList();
                },
                Qt::QueuedConnection);
        });
}

void FileDock::scanDeletedFilesForRecovery()
{
    // 对外保留同步入口名，内部改为异步实现，避免阻塞 UI。
    scanDeletedFilesForRecoveryAsync();
}

void FileDock::scanDeletedFilesForRecoveryAsync()
{
    if (m_recoveryVolumeCombo == nullptr || m_recoveryTable == nullptr || m_recoveryStatusLabel == nullptr)
    {
        return;
    }
    if (m_recoveryScanInProgress)
    {
        return;
    }
    if (m_recoveryVolumeCombo->currentIndex() < 0)
    {
        QMessageBox::warning(this, QStringLiteral("文件恢复"), QStringLiteral("请先选择 NTFS 卷。"));
        return;
    }

    const QString rootPath = m_recoveryVolumeCombo->currentData().toString();
    m_recoveryStatusLabel->setText(QStringLiteral("正在扫描：%1").arg(rootPath));
    m_recoveryScanInProgress = true;
    if (m_recoveryScanButton != nullptr)
    {
        m_recoveryScanButton->setEnabled(false);
        if (m_recoveryEmptyScanButton != nullptr) { m_recoveryEmptyScanButton->setEnabled(false); }
    }
    if (m_recoveryExportButton != nullptr)
    {
        m_recoveryExportButton->setEnabled(false);
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 开始扫描误删文件, volume="
            << QDir::toNativeSeparators(rootPath).toStdString()
            << eol;
    }

    const int progressPid = kPro.add(this, "文件恢复", "扫描误删");
    kPro.set(progressPid, "准备扫描卷", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, rootPath, progressPid]() {
        QString errorText;
        std::vector<ks::file::NtfsDeletedFileEntry> deletedItems;

        kPro.set(progressPid, "准备读取 NTFS 元数据", 0, 3.0f);
        const bool scanOk = ks::file::ManualFileSystemParser::enumerateNtfsDeletedFiles(
            rootPath,
            deletedItems,
            errorText,
            [progressPid](const int percentValue, const QString& stageText) {
                const int boundedPercent = std::clamp(percentValue, 0, 100);
                kPro.set(progressPid, stageText.toStdString(), 0, static_cast<float>(boundedPercent));
            });
        if (!scanOk)
        {
            kPro.set(progressPid, "扫描失败，整理错误信息", 0, 82.0f);
        }

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis,
             rootPath,
             progressPid,
             scanOk,
             deletedItems = std::move(deletedItems),
             errorText]() mutable {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                const auto deletedItemsSnapshot =
                    std::make_shared<std::vector<ks::file::NtfsDeletedFileEntry>>(
                        std::move(deletedItems));
                const auto commitSnapshot =
                    [safeThis,
                     rootPath,
                     progressPid,
                     scanOk,
                     deletedItemsSnapshot,
                     errorText]()
                {
                    if (safeThis.isNull())
                    {
                        kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                        return;
                    }

                    safeThis->m_recoveryScanInProgress = false;
                    if (safeThis->m_recoveryScanButton != nullptr)
                    {
                        safeThis->m_recoveryScanButton->setEnabled(true);
                        if (safeThis->m_recoveryEmptyScanButton != nullptr) { safeThis->m_recoveryEmptyScanButton->setEnabled(true); }
                    }
                    if (safeThis->m_recoveryExportButton != nullptr)
                    {
                        safeThis->m_recoveryExportButton->setEnabled(true);
                    }

                    if (!scanOk)
                    {
                        safeThis->m_recoveryStatusLabel->setText(
                            QStringLiteral("扫描失败：%1").arg(errorText));
                        kLogEvent event;
                        err << event
                            << "[FileDock] 扫描误删失败, volume="
                            << QDir::toNativeSeparators(rootPath).toStdString()
                            << ", error="
                            << errorText.toStdString()
                            << eol;
                        safeThis->updateRecoveryViewState(
                            false,
                            QStringLiteral("扫描未能完成，可更换卷或确认程序以管理员权限运行后重试。"));
                        QMessageBox::warning(safeThis.data(), QStringLiteral("扫描失败"), errorText);
                        kPro.set(progressPid, "扫描失败", 0, 100.0f);
                        return;
                    }

                    safeThis->m_deletedRecoveryItems = std::move(*deletedItemsSnapshot);
                    safeThis->m_recoveryTable->setUpdatesEnabled(false);
                    safeThis->m_recoveryTable->setSortingEnabled(false);
                    safeThis->m_recoveryTable->clearContents();
                    safeThis->m_recoveryTable->setRowCount(
                        static_cast<int>(safeThis->m_deletedRecoveryItems.size()));
                    for (int row = 0;
                         row < static_cast<int>(safeThis->m_deletedRecoveryItems.size());
                         ++row)
                    {
                        const ks::file::NtfsDeletedFileEntry& itemValue =
                            safeThis->m_deletedRecoveryItems[static_cast<std::size_t>(row)];
                        // 完整度文本：优先显示估计百分比，无法评估时明确标记为未知。
                        const QString integrityText =
                            (itemValue.estimatedIntegrityPercent >= 0)
                            ? QStringLiteral("%1%").arg(itemValue.estimatedIntegrityPercent)
                            : QStringLiteral("未知");

                        // 恢复能力文本：明确区分驻留、完整非驻留、已复用与不支持布局。
                        QString recoverabilityText =
                            deletedFileRecoveryCapabilityText(itemValue);
                        if (!itemValue.hasOriginalName)
                        {
                            recoverabilityText += QStringLiteral(" / 缺名");
                        }

                        QTableWidgetItem* nameItem = new QTableWidgetItem(itemValue.fileName);
                        if (!itemValue.hasOriginalName)
                        {
                            nameItem->setToolTip(
                                QStringLiteral("该条目原始文件名已丢失，当前名称为系统生成的占位名。"));
                        }
                        safeThis->m_recoveryTable->setItem(row, 0, nameItem);
                        safeThis->m_recoveryTable->setItem(
                            row, 1, new QTableWidgetItem(itemValue.pathHint));
                        safeThis->m_recoveryTable->setItem(
                            row, 2, new QTableWidgetItem(formatSizeText(itemValue.sizeBytes)));
                        safeThis->m_recoveryTable->setItem(row, 3, new QTableWidgetItem(
                            itemValue.modifiedTime.isValid()
                            ? itemValue.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))
                            : QStringLiteral("-")));
                        safeThis->m_recoveryTable->setItem(
                            row,
                            4,
                            new QTableWidgetItem(
                                QStringLiteral("%1 / seq %2")
                                    .arg(static_cast<qulonglong>(itemValue.fileReference))
                                    .arg(itemValue.sequenceNumber)));
                        safeThis->m_recoveryTable->setItem(
                            row, 5, new QTableWidgetItem(integrityText));
                        safeThis->m_recoveryTable->setItem(
                            row, 6, new QTableWidgetItem(recoverabilityText));
                    }
                    safeThis->m_recoveryTable->setUpdatesEnabled(true);

                    const int residentReadyCount = static_cast<int>(std::count_if(
                        safeThis->m_deletedRecoveryItems.begin(),
                        safeThis->m_deletedRecoveryItems.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return item.recoveryCapability ==
                                ks::file::NtfsRecoveryCapability::Resident;
                        }));
                    const int nonResidentReadyCount = static_cast<int>(std::count_if(
                        safeThis->m_deletedRecoveryItems.begin(),
                        safeThis->m_deletedRecoveryItems.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return item.recoveryCapability ==
                                ks::file::NtfsRecoveryCapability::NonResidentIntact;
                        }));
                    const int safelyRecoverableCount = static_cast<int>(std::count_if(
                        safeThis->m_deletedRecoveryItems.begin(),
                        safeThis->m_deletedRecoveryItems.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return isDeletedFileSafelyRecoverable(item);
                        }));
                    const int highIntegrityCount = static_cast<int>(std::count_if(
                        safeThis->m_deletedRecoveryItems.begin(),
                        safeThis->m_deletedRecoveryItems.end(),
                        [](const ks::file::NtfsDeletedFileEntry& item) {
                            return item.estimatedIntegrityPercent >= 80;
                        }));

                    // 基准文案单独留存：筛选时要在它后面追加“筛选出 N / M 项”，
                    // 清空查找框后还要能原样还原。
                    safeThis->m_recoveryBaseStatusText =
                        QStringLiteral(
                            "扫描完成：%1 项（可安全恢复 %2 项：Resident %3，完整非驻留 %4；完整度≥80%% %5 项）")
                        .arg(safeThis->m_deletedRecoveryItems.size())
                        .arg(safelyRecoverableCount)
                        .arg(residentReadyCount)
                        .arg(nonResidentReadyCount)
                        .arg(highIntegrityCount);
                    safeThis->m_recoveryStatusLabel->setText(safeThis->m_recoveryBaseStatusText);

                    safeThis->updateRecoveryViewState(
                        !safeThis->m_deletedRecoveryItems.empty(),
                        QStringLiteral("本次扫描未发现仍可恢复的删除项，可更换卷后重新扫描。"));

                    // 重新扫描后沿用当前查找条件，省去用户再输一次。
                    safeThis->applyRecoveryFilter();

                    kLogEvent event;
                    info << event
                        << "[FileDock] 扫描误删完成, volume="
                        << QDir::toNativeSeparators(rootPath).toStdString()
                        << ", total="
                        << safeThis->m_deletedRecoveryItems.size()
                        << eol;
                    kPro.set(progressPid, "扫描完成", 0, 100.0f);
                };

                if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    QStringLiteral("file-recovery-scan-snapshot"),
                    { safeThis->m_recoveryTable },
                    commitSnapshot))
                {
                    return;
                }
                commitSnapshot();
            },
            Qt::QueuedConnection);
    }).detach();
}

void FileDock::recoverSelectedDeletedFiles()
{
    // 对外保留同步入口名，内部改为异步实现，避免阻塞 UI。
    recoverSelectedDeletedFilesAsync();
}

void FileDock::recoverSelectedDeletedFilesAsync()
{
    if (m_recoveryTable == nullptr || m_recoveryVolumeCombo == nullptr)
    {
        return;
    }
    if (m_recoveryRecoverInProgress)
    {
        return;
    }
    const QModelIndexList selectedRows = m_recoveryTable->selectionModel()->selectedRows();
    if (selectedRows.empty())
    {
        QMessageBox::information(this, QStringLiteral("文件恢复"), QStringLiteral("请先在列表中选择要恢复的条目。"));
        return;
    }

    const QString exportDir = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("选择恢复输出目录"),
        QDir::homePath());
    if (exportDir.isEmpty())
    {
        return;
    }

    const QString volumeRoot = m_recoveryVolumeCombo->currentData().toString();
    std::vector<ks::file::NtfsDeletedFileEntry> selectedItems;
    selectedItems.reserve(static_cast<std::size_t>(selectedRows.size()));
    for (const QModelIndex& rowIndex : selectedRows)
    {
        const int rowValue = rowIndex.row();
        if (rowValue < 0 || rowValue >= static_cast<int>(m_deletedRecoveryItems.size()))
        {
            continue;
        }
        selectedItems.push_back(m_deletedRecoveryItems[static_cast<std::size_t>(rowValue)]);
    }
    if (selectedItems.empty())
    {
        QMessageBox::information(this, QStringLiteral("文件恢复"), QStringLiteral("未读取到有效恢复条目。"));
        return;
    }
    const bool hasSafelyRecoverableItem = std::any_of(
        selectedItems.begin(),
        selectedItems.end(),
        [](const ks::file::NtfsDeletedFileEntry& item) {
            return isDeletedFileSafelyRecoverable(item);
        });
    if (!hasSafelyRecoverableItem)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("文件恢复"),
            QStringLiteral("选中项均不满足安全恢复条件；请查看“恢复能力”和“完整度”列。"));
        return;
    }

    const bool hasIntactNonResidentItem = std::any_of(
        selectedItems.begin(),
        selectedItems.end(),
        [](const ks::file::NtfsDeletedFileEntry& item) {
            return item.recoveryCapability ==
                ks::file::NtfsRecoveryCapability::NonResidentIntact;
        });
    const QString sourceVolumeRoot = localVolumeRootForPath(volumeRoot);
    const QString outputVolumeRoot = localVolumeRootForPath(exportDir);
    if (hasIntactNonResidentItem &&
        !sourceVolumeRoot.isEmpty() &&
        sourceVolumeRoot.compare(outputVolumeRoot, Qt::CaseInsensitive) == 0)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("非驻留恢复需要其它卷"),
            QStringLiteral(
                "选中项包含非驻留文件。不能把恢复结果写回源卷 %1，"
                "因为输出文件分配空间时可能直接覆盖待恢复簇。\n\n"
                "请重新选择其它本地卷或网络目录。")
                .arg(sourceVolumeRoot));
        return;
    }

    m_recoveryRecoverInProgress = true;
    if (m_recoveryScanButton != nullptr)
    {
        m_recoveryScanButton->setEnabled(false);
        if (m_recoveryEmptyScanButton != nullptr) { m_recoveryEmptyScanButton->setEnabled(false); }
    }
    if (m_recoveryExportButton != nullptr)
    {
        m_recoveryExportButton->setEnabled(false);
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 开始恢复选中误删项, volume="
            << QDir::toNativeSeparators(volumeRoot).toStdString()
            << ", selectedRows="
            << selectedItems.size()
            << eol;
    }

    const int progressPid = kPro.add(this, "文件恢复", "恢复选中");
    kPro.set(progressPid, "准备恢复", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, progressPid, volumeRoot, exportDir, selectedItems]() {
        int successCount = 0;
        QStringList failTextList;
        QSet<QString> reservedTargetPathSet;

        for (std::size_t index = 0; index < selectedItems.size(); ++index)
        {
            const ks::file::NtfsDeletedFileEntry& deletedItem = selectedItems[index];
            QString exportName = deletedItem.fileName.trimmed();
            if (exportName.isEmpty())
            {
                exportName = QStringLiteral("deleted_%1.bin").arg(deletedItem.fileReference);
            }
            const QString targetPath = uniqueRecoveryTargetPath(
                exportDir,
                exportName,
                deletedItem.fileReference,
                reservedTargetPathSet);
            QString errorText;
            const bool ok = ks::file::ManualFileSystemParser::recoverNtfsDeletedFile(
                volumeRoot,
                deletedItem,
                targetPath,
                errorText,
                [progressPid, index, itemCount = selectedItems.size()](
                    const int itemPercent,
                    const QString& stageText) {
                    const float completedItemRatio =
                        static_cast<float>(index) /
                        static_cast<float>(std::max<std::size_t>(itemCount, 1));
                    const float currentItemRatio =
                        (static_cast<float>(std::clamp(itemPercent, 0, 100)) / 100.0f) /
                        static_cast<float>(std::max<std::size_t>(itemCount, 1));
                    const float mappedProgress =
                        5.0f + (completedItemRatio + currentItemRatio) * 90.0f;
                    kPro.set(
                        progressPid,
                        stageText.toStdString(),
                        0,
                        mappedProgress);
                });
            if (ok)
            {
                ++successCount;
            }
            else
            {
                failTextList.push_back(QStringLiteral("%1: %2").arg(exportName, errorText));
            }

            const float progress = 5.0f
                + (static_cast<float>(index + 1) / static_cast<float>(selectedItems.size())) * 90.0f;
            kPro.set(progressPid, "恢复处理中", 0, progress);
        }

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, progressPid, successCount, failTextList]() {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                safeThis->m_recoveryRecoverInProgress = false;
                if (safeThis->m_recoveryScanButton != nullptr)
                {
                    safeThis->m_recoveryScanButton->setEnabled(true);
                    if (safeThis->m_recoveryEmptyScanButton != nullptr) { safeThis->m_recoveryEmptyScanButton->setEnabled(true); }
                }
                if (safeThis->m_recoveryExportButton != nullptr)
                {
                    safeThis->m_recoveryExportButton->setEnabled(true);
                }

                const QString summaryText = QStringLiteral("恢复完成：成功 %1，失败 %2。")
                    .arg(successCount)
                    .arg(failTextList.size());
                safeThis->m_recoveryStatusLabel->setText(summaryText);

                if (failTextList.empty())
                {
                    kLogEvent event;
                    info << event
                        << "[FileDock] 恢复完成, success="
                        << successCount
                        << ", failed=0"
                        << eol;
                    QMessageBox::information(safeThis.data(), QStringLiteral("文件恢复"), summaryText);
                }
                else
                {
                    kLogEvent event;
                    warn << event
                        << "[FileDock] 恢复部分失败, success="
                        << successCount
                        << ", failed="
                        << failTextList.size()
                        << eol;
                    QMessageBox::warning(
                        safeThis.data(),
                        QStringLiteral("文件恢复"),
                        summaryText + QStringLiteral("\n\n失败明细：\n") + failTextList.join('\n'));
                }

                kPro.set(progressPid, "恢复完成", 0, 100.0f);
            },
            Qt::QueuedConnection);
    }).detach();
}

void FileDock::showPanelContextMenu(FilePanelWidgets& panel, const QPoint& localPos)
{
    kLogEvent menuOpenEvent;
    dbg << menuOpenEvent
        << "[FileDock] 打开右键菜单, panel="
        << panel.panelNameText.toStdString()
        << ", localPos=("
        << localPos.x()
        << ","
        << localPos.y()
        << ")"
        << eol;

    // 右键命中行时，优先保证“命中行”与“选中集合”一致。
    // 说明：若命中的是已选中行，则保留原多选；若命中未选中行，则切成该单行。
    QAbstractItemView* menuView =
        (panel.viewModeCombo->currentIndex() <= 1)
        ? static_cast<QAbstractItemView*>(panel.compactFileView)
        : static_cast<QAbstractItemView*>(panel.fileView);
    const QModelIndex hitIndex = menuView->indexAt(localPos);
    QItemSelectionModel* selectionModel = menuView->selectionModel();
    if (hitIndex.isValid() && selectionModel != nullptr)
    {
        const QModelIndex hitRowIndex = hitIndex.siblingAtColumn(0);
        const bool hitAlreadySelected =
            selectionModel->isRowSelected(hitIndex.row(), hitIndex.parent()) ||
            (hitRowIndex.isValid() && selectionModel->isSelected(hitRowIndex));
        if (!hitAlreadySelected)
        {
            selectionModel->select(hitIndex, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
        }
        // 右键菜单入口只同步当前焦点，不让 current index 更新反向破坏多选集合。
        selectionModel->setCurrentIndex(hitIndex, QItemSelectionModel::NoUpdate);
    }

    // 右键菜单所使用的数据统一来自“当前选中集合”。
    const std::vector<QString> menuPaths = selectedPaths(panel);
    const bool hasSelection = !menuPaths.empty();
    const bool isSingleSelection = menuPaths.size() == 1;
    const QString firstPath = isSingleSelection ? menuPaths.front() : QString();
    DWORD firstFileIntegrityRid = 0;
    bool firstFileIntegrityImplicitMedium = false;
    QString firstFileIntegrityDetailText;
    const bool firstFileIntegrityKnown = hasSelection &&
        queryFileIntegrityRid(
            menuPaths.front(),
            &firstFileIntegrityRid,
            &firstFileIntegrityImplicitMedium,
            &firstFileIntegrityDetailText);

    // 统计选中内容类型：用于控制菜单可用状态，避免多选时误触单文件功能。
    bool hasAnyFile = false;
    QStringList linkTargetList;
    for (const QString& path : menuPaths)
    {
        QFileInfo info(path);
        hasAnyFile = hasAnyFile || info.isFile();
        if (isPathReparsePoint(path))
        {
            const ks::file::ReparsePointQueryResult reparseResult = queryReparsePointForUi(path);
            const QString targetText = reparseTargetFromResult(reparseResult).trimmed();
            if (!targetText.isEmpty() && !linkTargetList.contains(targetText, Qt::CaseInsensitive))
            {
                linkTargetList.push_back(targetText);
            }
        }
    }
    const QString firstLinkTarget = (!linkTargetList.isEmpty() && isSingleSelection) ? linkTargetList.front() : QString();

    // 复制/移动是双栏文件管理器语义：源面板的选中项会直接落到对侧面板。
    // 菜单文案必须把目标面板说清楚，避免用户误解为 Windows 剪贴板“复制/剪切”。
    FilePanelWidgets* const transferTargetPanel = oppositePanelFor(panel);
    const QString transferTargetText = (transferTargetPanel != nullptr)
        ? transferTargetPanel->panelNameText
        : QStringLiteral("对侧面板");
    const QString localizedTransferTargetText = ks::i18n::displayText(transferTargetText);
    const QString copyToPanelText = ks::i18n::displayText(QStringLiteral("复制到%1"))
        .arg(localizedTransferTargetText);
    const QString moveToPanelText = ks::i18n::displayText(QStringLiteral("移动到%1"))
        .arg(localizedTransferTargetText);

    QMenu menu(this);
    menu.setStyleSheet(buildContextMenuStyle());
    QAction* openAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("打开/运行"));
    QAction* copyPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制路径(Ctrl+C)"));
    QAction* copyKernelPathAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制内核模式地址"));
    QAction* copyShortNameAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制短文件名"));
    QAction* copyLinkTargetAction = menu.addAction(QIcon(":/Icon/process_copy_cell.svg"), QStringLiteral("复制链接目标"));
    QAction* openLinkTargetAction = menu.addAction(QIcon(":/Icon/process_start.svg"), QStringLiteral("打开链接目标"));
    QAction* locateLinkTargetAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("定位链接目标"));
    menu.addSeparator();
    QAction* copyAction = menu.addAction(QIcon(":/Icon/log_copy.svg"), copyToPanelText);
    QAction* cutAction = menu.addAction(QIcon(":/Icon/process_suspend.svg"), moveToPanelText);
    QAction* renameAction = menu.addAction(QIcon(":/Icon/process_priority.svg"), QStringLiteral("重命名(F2)"));
    QAction* deleteAction = menu.addAction(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除(Delete)"));
    // 删除方式按权限强度从低到高排列：越靠下越不可逆、要求的权限越高。
    QMenu* deleteModeMenu = menu.addMenu(QIcon(":/Icon/process_terminate.svg"), QStringLiteral("删除方式（递归/多权限）"));
    deleteModeMenu->setToolTipsVisible(true);
    QAction* permanentDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("永久删除（R3·当前权限）"));
    permanentDeleteAction->setToolTip(
        QStringLiteral("以当前用户权限递归永久删除，不进回收站；目录按子项先删、目录后删的顺序处理。"));
    QAction* forceDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/file_owner.svg"), QStringLiteral("强制删除（R3·接管所有权）"));
    forceDeleteAction->setToolTip(
        QStringLiteral("清除只读/隐藏/系统属性，必要时接管所有权并授予完全控制后再递归删除；需要管理员权限。"));
    QAction* pendingRebootDeleteAction = deleteModeMenu->addAction(
        QIcon(":/Icon/process_resume.svg"), QStringLiteral("重启后删除（R3·启动时执行）"));
    pendingRebootDeleteAction->setToolTip(
        QStringLiteral("登记 PendingFileRenameOperations，由系统在下次重启早期删除；适合正被占用的目标，需要管理员权限。"));
    // R0 作为顶层快捷入口，避免强制用户再穿过“删除方式”子菜单；三个动作仍共用
    // 统一的不可逆确认、后台递归和统计链路。
    QMenu* r0DeleteMenu = menu.addMenu(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("R0"));
    r0DeleteMenu->setToolTipsVisible(true);
    QAction* driverNativeDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动（底层方案）"));
    driverNativeDeleteAction->setToolTip(QStringLiteral(
        "由 R0 用 ZwCreateFile/ZwSetInformationFile 删除；失败时保留现有的 DispositionEx 兼容重试。"));
    QAction* driverIrpDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动(IRP)"));
    driverIrpDeleteAction->setToolTip(QStringLiteral(
        "由 R0 构造 IRP_MJ_SET_INFORMATION/FileDispositionInformation 并投递完整文件系统栈；不回退到底层方案。"));
    QAction* driverPosixDeleteAction = r0DeleteMenu->addAction(
        QIcon(":/Icon/process_terminate.svg"), QStringLiteral("驱动(POSIX)"));
    driverPosixDeleteAction->setToolTip(QStringLiteral(
        "由 R0 使用 FileDispositionInformationEx 的 POSIX unlink 语义；是否可用取决于系统与文件系统，不回退到其它后端。"));
    QAction* unlockByDriverAction = menu.addAction(
        QIcon(":/Icon/handle_close.svg"),
        ks::i18n::displayText(QStringLiteral("文件解锁器")));
    unlockByDriverAction->setToolTip(QStringLiteral("在文件属性中扫描占用，并提供关闭句柄、R3/R0 结束进程操作"));
    QMenu* addOplockMenu = menu.addMenu(QIcon(":/Icon/plus.svg"), QStringLiteral("添加 Oplock（访问计数）"));
    QAction* addOplockLevel1Action = addOplockMenu->addAction(QStringLiteral("Level 1 - 独占读写缓存，别人访问会计数"));
    QAction* addOplockLevel2Action = addOplockMenu->addAction(QStringLiteral("Level 2 - 共享只读缓存，别人写入会计数"));
    QAction* addOplockBatchAction = addOplockMenu->addAction(QStringLiteral("Batch - 缓存反复打开关闭，访问时计数"));
    QAction* addOplockFilterAction = addOplockMenu->addAction(QStringLiteral("Filter - 扫描器/过滤器用，访问前计数"));
    QAction* showOplockRecordsAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("查看 Oplock 访问记录"));
    QAction* releaseOplockAction = menu.addAction(QIcon(":/Icon/process_resume.svg"), QStringLiteral("释放当前 Oplock"));
    QAction* releaseAllOplocksAction = menu.addAction(QIcon(":/Icon/process_resume.svg"), QStringLiteral("释放全部 Oplock"));
    QAction* takeOwnerAction = menu.addAction(QIcon(":/Icon/file_owner.svg"), QStringLiteral("取得所有权"));
    QMenu* fileIntegritySubMenu = menu.addMenu(QIcon(":/Icon/file_owner.svg"), QStringLiteral("文件完整性"));
    fileIntegritySubMenu->setToolTipsVisible(true);
    fileIntegritySubMenu->setEnabled(hasSelection);
    if (!firstFileIntegrityKnown && hasSelection)
    {
        fileIntegritySubMenu->setToolTip(QStringLiteral("当前文件完整性读取失败：%1")
            .arg(firstFileIntegrityDetailText));
    }
    else if (firstFileIntegrityKnown && firstFileIntegrityImplicitMedium)
    {
        fileIntegritySubMenu->setToolTip(QStringLiteral("当前未设置显式 Mandatory Label，Windows 按 Medium 处理。"));
    }
    else if (hasSelection && menuPaths.size() > 1U)
    {
        fileIntegritySubMenu->setToolTip(QStringLiteral("多选时圆点按第一项的文件完整性显示，执行时会批量写入所有选中项。"));
    }
    for (const FileIntegrityLevelPreset& preset : FileIntegrityLevelPresets)
    {
        const bool isCurrentLevel = firstFileIntegrityKnown && firstFileIntegrityRid == preset.rid;
        QAction* integrityAction = fileIntegritySubMenu->addAction(
            QIcon(":/Icon/file_owner.svg"),
            QStringLiteral("%1 %2 - %3")
                .arg(isCurrentLevel ? QStringLiteral("●") : QStringLiteral(" "))
                .arg(QString::fromLatin1(preset.nameText))
                .arg(QString::fromUtf8(preset.detailText)));
        integrityAction->setData(static_cast<unsigned int>(preset.rid));
    }
    menu.addSeparator();
    QAction* newFileAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("新建文件"));
    QAction* newFolderAction = menu.addAction(QIcon(":/Icon/process_open_folder.svg"), QStringLiteral("新建文件夹"));
    QAction* openTerminalAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("在终端中打开"));
    menu.addSeparator();
    QAction* columnAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("选择列..."));
    QAction* detailAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("属性..."));
    menu.addSeparator();

    // 分析动作改为顶层菜单，减少层级并提升右键操作效率。
    QAction* hashAction = menu.addAction(QIcon(":/Icon/log_track.svg"), QStringLiteral("计算哈希值"));
    QAction* signAction = menu.addAction(QIcon(":/Icon/process_critical.svg"), QStringLiteral("检查数字签名"));
    QAction* entropyAction = menu.addAction(QIcon(":/Icon/disk_analyze.svg"), QStringLiteral("计算熵值"));
    QAction* hexAction = menu.addAction(QIcon(":/Icon/process_details.svg"), QStringLiteral("十六进制查看"));
    QAction* peAction = menu.addAction(QIcon(":/Icon/process_list.svg"), QStringLiteral("在PE查看器中打开"));
    QAction* mappedProcessScanAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("扫描映射进程(R0)"));
    QMenu* pluginMenu = menu.addMenu(QIcon(":/Icon/process_start.svg"), QStringLiteral("插件"));

    // 结合选中集合动态启用菜单项，保证“多选”和“右键动作”行为一致。
    const bool singleFileOnly = isSingleSelection && QFileInfo(firstPath).isFile();
    ks::plugin_host::InvocationContext pluginContext;
    pluginContext.targetKind = ks::plugin_host::TargetKind::File;
    pluginContext.filePath = firstPath;
    ks::plugin_host::populateTargetMenu(pluginMenu, this, pluginContext);
    const bool firstPathHasOplock = singleFileOnly && hasActiveOplockForPath(firstPath);
    const std::uint64_t firstPathOplockBreakCount = firstPathHasOplock
        ? activeOplockBreakCountForPath(firstPath)
        : 0U;
    const std::size_t firstPathOplockAccessProcessCount = firstPathHasOplock
        ? activeOplockAccessProcessCountForPath(firstPath)
        : 0U;
    const std::size_t currentOplockCount = activeOplockCount();
    openAction->setEnabled(hasSelection);
    copyPathAction->setEnabled(hasSelection);
    copyKernelPathAction->setEnabled(hasSelection);
    copyShortNameAction->setEnabled(hasSelection);
    copyLinkTargetAction->setEnabled(!linkTargetList.isEmpty());
    openLinkTargetAction->setEnabled(!firstLinkTarget.isEmpty());
    locateLinkTargetAction->setEnabled(!firstLinkTarget.isEmpty());
    copyAction->setEnabled(hasSelection);
    cutAction->setEnabled(hasSelection);
    renameAction->setEnabled(isSingleSelection);
    deleteAction->setEnabled(hasSelection);
    deleteModeMenu->setEnabled(hasSelection);
    permanentDeleteAction->setEnabled(hasSelection);
    forceDeleteAction->setEnabled(hasSelection);
    pendingRebootDeleteAction->setEnabled(hasSelection);
    r0DeleteMenu->setEnabled(hasSelection);
    driverNativeDeleteAction->setEnabled(hasSelection);
    driverIrpDeleteAction->setEnabled(hasSelection);
    driverPosixDeleteAction->setEnabled(hasSelection);
    unlockByDriverAction->setEnabled(isSingleSelection);
    const bool canAddOplock = singleFileOnly && !firstPathHasOplock;
    addOplockMenu->setEnabled(canAddOplock);
    addOplockLevel1Action->setEnabled(canAddOplock);
    addOplockLevel2Action->setEnabled(canAddOplock);
    addOplockBatchAction->setEnabled(canAddOplock);
    addOplockFilterAction->setEnabled(canAddOplock);
    if (firstPathHasOplock)
    {
        showOplockRecordsAction->setText(
            QStringLiteral("查看 Oplock 访问记录（%1 个进程）").arg(firstPathOplockAccessProcessCount));
        releaseOplockAction->setText(
            QStringLiteral("释放当前 Oplock（已触发 %1 次）").arg(firstPathOplockBreakCount));
    }
    showOplockRecordsAction->setEnabled(firstPathHasOplock);
    releaseOplockAction->setEnabled(firstPathHasOplock);
    releaseAllOplocksAction->setEnabled(currentOplockCount > 0U);
    takeOwnerAction->setEnabled(hasSelection);
    detailAction->setEnabled(hasSelection);
    hashAction->setEnabled(hasAnyFile);
    signAction->setEnabled(hasAnyFile);
    entropyAction->setEnabled(hasAnyFile);
    hexAction->setEnabled(singleFileOnly);
    peAction->setEnabled(singleFileOnly);
    mappedProcessScanAction->setEnabled(hasAnyFile);
    pluginMenu->setEnabled(singleFileOnly);

    QAction* selectedAction = menu.exec(menuView->viewport()->mapToGlobal(localPos));
    if (selectedAction == nullptr)
    {
        kLogEvent menuCancelEvent;
        dbg << menuCancelEvent
            << "[FileDock] 右键菜单取消, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    {
        kLogEvent menuActionEvent;
        info << menuActionEvent
            << "[FileDock] 右键菜单执行动作, panel="
            << panel.panelNameText.toStdString()
            << ", action="
            << selectedAction->text().toStdString()
            << ", selectedCount="
            << menuPaths.size()
            << eol;
    }

    if (selectedAction->parent() == fileIntegritySubMenu)
    {
        const DWORD integrityRid = selectedAction->data().toUInt();
        setSelectedFileIntegrityLevel(
            panel,
            integrityRid,
            fileIntegrityNameFromRid(integrityRid));
        return;
    }
    if (selectedAction == openAction)
    {
        openSelectedItems(panel);
        return;
    }
    if (selectedAction == copyPathAction)
    {
        copySelectedItemPath(panel);
        return;
    }
    if (selectedAction == copyKernelPathAction)
    {
        copySelectedItemKernelPath(panel);
        return;
    }
    if (selectedAction == copyShortNameAction)
    {
        copySelectedItemShortName(panel);
        return;
    }
    if (selectedAction == copyLinkTargetAction)
    {
        QApplication::clipboard()->setText(linkTargetList.join(QStringLiteral("\n")));
        kLogEvent event;
        info << event
            << "[FileDock] 复制链接目标到剪贴板, panel="
            << panel.panelNameText.toStdString()
            << ", count="
            << linkTargetList.size()
            << eol;
        return;
    }
    if (selectedAction == openLinkTargetAction)
    {
        const bool openOk = QDesktopServices::openUrl(QUrl::fromLocalFile(firstLinkTarget));
        if (!openOk)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("打开链接目标"),
                QStringLiteral("无法打开链接目标：%1").arg(QDir::toNativeSeparators(firstLinkTarget)));
        }
        return;
    }
    if (selectedAction == locateLinkTargetAction)
    {
        const QFileInfo targetInfo(firstLinkTarget);
        const QString locatePath = targetInfo.isDir()
            ? targetInfo.absoluteFilePath()
            : targetInfo.absolutePath();
        if (locatePath.trimmed().isEmpty() || !QDir(locatePath).exists())
        {
            QMessageBox::warning(
                this,
                QStringLiteral("定位链接目标"),
                QStringLiteral("目标所在目录不存在或不可访问：%1").arg(QDir::toNativeSeparators(firstLinkTarget)));
            return;
        }
        navigateToPath(panel, locatePath, true);
        return;
    }
    if (selectedAction == copyAction)
    {
        copySelectedItems(panel);
        return;
    }
    if (selectedAction == cutAction)
    {
        cutSelectedItems(panel);
        return;
    }
    if (selectedAction == renameAction)
    {
        renameSelectedItem(panel);
        return;
    }
    if (selectedAction == deleteAction)
    {
        deleteSelectedItem(panel);
        return;
    }
    if (selectedAction == permanentDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::PermanentR3);
        return;
    }
    if (selectedAction == forceDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::ForceR3);
        return;
    }
    if (selectedAction == pendingRebootDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::PendingReboot);
        return;
    }
    if (selectedAction == driverNativeDeleteAction)
    {
        deleteSelectedItemByDriver(panel);
        return;
    }
    if (selectedAction == driverIrpDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::DriverR0Irp);
        return;
    }
    if (selectedAction == driverPosixDeleteAction)
    {
        deleteSelectedItemsWithMode(panel, FileDeleteMode::DriverR0Posix);
        return;
    }
    if (selectedAction == unlockByDriverAction)
    {
        if (!isSingleSelection)
        {
            QMessageBox::information(
                this,
                QStringLiteral("文件解锁器"),
                QStringLiteral("文件解锁器暂不支持多文件批量解除占用，请只选择一个文件或目录。"));
            return;
        }
        unlockSelectedItemsByDriver(panel);
        return;
    }
    if (selectedAction == addOplockLevel1Action)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Level1);
        return;
    }
    if (selectedAction == addOplockLevel2Action)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Level2);
        return;
    }
    if (selectedAction == addOplockBatchAction)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Batch);
        return;
    }
    if (selectedAction == addOplockFilterAction)
    {
        addOplockToSelectedFile(panel, FileOplockLevel::Filter);
        return;
    }
    if (selectedAction == showOplockRecordsAction)
    {
        showSelectedFileOplockAccessRecords(panel);
        return;
    }
    if (selectedAction == releaseOplockAction)
    {
        releaseSelectedFileOplock(panel);
        return;
    }
    if (selectedAction == releaseAllOplocksAction)
    {
        releaseAllActiveOplocks(true);
        return;
    }
    if (selectedAction == takeOwnerAction)
    {
        takeOwnershipSelectedItems(panel);
        return;
    }
    if (selectedAction == newFileAction)
    {
        createNewFileOrFolder(panel, false);
        return;
    }
    if (selectedAction == newFolderAction)
    {
        createNewFileOrFolder(panel, true);
        return;
    }
    if (selectedAction == openTerminalAction)
    {
        const QString workPath = panel.currentPath.isEmpty() ? QDir::homePath() : panel.currentPath;
        DWORD terminalErrorCode = ERROR_SUCCESS;
        const bool startOk = openCommandPromptInDirectory(workPath, &terminalErrorCode);
        kLogEvent terminalEvent;
        if (!startOk)
        {
            warn << terminalEvent
                << "[FileDock] 在终端中打开失败, panel="
                << panel.panelNameText.toStdString()
                << ", workPath="
                << QDir::toNativeSeparators(workPath).toStdString()
                << ", error="
                << terminalErrorCode
                << eol;
        }
        else
        {
            info << terminalEvent
                << "[FileDock] 在终端中打开完成, panel="
                << panel.panelNameText.toStdString()
                << ", workPath="
                << QDir::toNativeSeparators(workPath).toStdString()
                << eol;
        }
        return;
    }
    if (selectedAction == columnAction)
    {
        showColumnManagerDialog(panel);
        return;
    }
    if (selectedAction == detailAction)
    {
        QStringList detailPaths;
        detailPaths.reserve(static_cast<qsizetype>(menuPaths.size()));
        for (const QString& path : menuPaths) detailPaths.push_back(path);
        showFileDetailDialog(detailPaths);

        kLogEvent detailEvent;
        info << detailEvent
            << "[FileDock] 属性窗口打开完成, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << menuPaths.size()
            << eol;
        return;
    }
    if (selectedAction == hashAction)
    {
        // 哈希计算支持多选：仅对文件条目计算，目录自动跳过。
        if (!hasAnyFile)
        {
            kLogEvent hashEmptyEvent;
            warn << hashEmptyEvent
                << "[FileDock] 哈希计算取消：未选中文件, panel="
                << panel.panelNameText.toStdString()
                << eol;
            return;
        }

        kLogEvent hashEvent;
        int successCount = 0;
        QStringList failedLines;
        for (const QString& path : menuPaths)
        {
            QFileInfo fileInfo(path);
            if (!fileInfo.isFile())
            {
                continue;
            }

            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                failedLines << QStringLiteral("%1 | 无法打开文件。")
                    .arg(QDir::toNativeSeparators(path));
                continue;
            }

            QCryptographicHash md5(QCryptographicHash::Md5);
            QCryptographicHash sha1(QCryptographicHash::Sha1);
            QCryptographicHash sha256(QCryptographicHash::Sha256);
            while (!file.atEnd())
            {
                const QByteArray chunk = file.read(1024 * 256);
                md5.addData(chunk);
                sha1.addData(chunk);
                sha256.addData(chunk);
            }
            file.close();

            successCount += 1;
            info << hashEvent
                << "[FileDock] 哈希计算结果, filePath="
                << QDir::toNativeSeparators(path).toStdString()
                << ", md5="
                << QString::fromLatin1(md5.result().toHex()).toStdString()
                << ", sha1="
                << QString::fromLatin1(sha1.result().toHex()).toStdString()
                << ", sha256="
                << QString::fromLatin1(sha256.result().toHex()).toStdString()
                << eol;
        }

        if (!failedLines.isEmpty())
        {
            warn << hashEvent
                << "[FileDock] 哈希计算部分失败, panel="
                << panel.panelNameText.toStdString()
                << ", successCount="
                << successCount
                << ", failCount="
                << failedLines.size()
                << ", failedPreview=\n"
                << buildLogPreviewText(failedLines).toStdString()
                << eol;
        }

        info << hashEvent
            << "[FileDock] 哈希计算完成, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failedLines.size()
            << eol;
        return;
    }
    if (selectedAction == signAction)
    {
        // 数字签名入口与属性页联动，支持多选逐个打开详情。
        if (!hasAnyFile)
        {
            kLogEvent signEmptyEvent;
            warn << signEmptyEvent
                << "[FileDock] 签名检查取消：未选中文件, panel="
                << panel.panelNameText.toStdString()
                << eol;
            return;
        }

        constexpr std::size_t kMaxAutoOpenSignCount = 8;
        std::size_t openedCount = 0;
        for (const QString& path : menuPaths)
        {
            if (!QFileInfo(path).isFile())
            {
                continue;
            }
            if (openedCount >= kMaxAutoOpenSignCount)
            {
                break;
            }
            showFileDetailDialog(path);
            openedCount += 1;
        }

        const std::size_t fileSelectionCount = static_cast<std::size_t>(std::count_if(
            menuPaths.begin(),
            menuPaths.end(),
            [](const QString& path)
            {
                return QFileInfo(path).isFile();
            }));
        kLogEvent signEvent;
        if (openedCount == kMaxAutoOpenSignCount && fileSelectionCount > kMaxAutoOpenSignCount)
        {
            warn << signEvent
                << "[FileDock] 签名检查已截断打开数量, panel="
                << panel.panelNameText.toStdString()
                << ", openedCount="
                << openedCount
                << ", fileSelectionCount="
                << fileSelectionCount
                << eol;
        }

        info << signEvent
            << "[FileDock] 签名检查完成, panel="
            << panel.panelNameText.toStdString()
            << ", openedCount="
            << openedCount
            << ", fileSelectionCount="
            << fileSelectionCount
            << eol;
        return;
    }
    if (selectedAction == entropyAction)
    {
        // 熵值计算支持多选：仅统计文件条目。
        if (!hasAnyFile)
        {
            kLogEvent entropyEmptyEvent;
            warn << entropyEmptyEvent
                << "[FileDock] 熵值计算取消：未选中文件, panel="
                << panel.panelNameText.toStdString()
                << eol;
            return;
        }

        kLogEvent entropyEvent;
        int successCount = 0;
        QStringList failedLines;
        for (const QString& path : menuPaths)
        {
            QFileInfo fileInfo(path);
            if (!fileInfo.isFile())
            {
                continue;
            }

            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                failedLines << QStringLiteral("%1 | 无法打开文件。")
                    .arg(QDir::toNativeSeparators(path));
                continue;
            }

            std::array<std::uint64_t, 256> bucket{};
            std::uint64_t totalCount = 0;
            while (!file.atEnd())
            {
                const QByteArray chunk = file.read(1024 * 256);
                for (unsigned char byteValue : chunk)
                {
                    bucket[byteValue] += 1;
                    totalCount += 1;
                }
            }
            file.close();

            double entropy = 0.0;
            if (totalCount > 0)
            {
                for (std::uint64_t count : bucket)
                {
                    if (count == 0)
                    {
                        continue;
                    }
                    const double p = static_cast<double>(count) / static_cast<double>(totalCount);
                    entropy -= p * std::log2(p);
                }
            }

            successCount += 1;
            info << entropyEvent
                << "[FileDock] 熵值计算结果, filePath="
                << QDir::toNativeSeparators(path).toStdString()
                << ", entropy="
                << QString::number(entropy, 'f', 4).toStdString()
                << eol;
        }

        if (!failedLines.isEmpty())
        {
            warn << entropyEvent
                << "[FileDock] 熵值计算部分失败, panel="
                << panel.panelNameText.toStdString()
                << ", successCount="
                << successCount
                << ", failCount="
                << failedLines.size()
                << ", failedPreview=\n"
                << buildLogPreviewText(failedLines).toStdString()
                << eol;
        }

        info << entropyEvent
            << "[FileDock] 熵值计算完成, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failedLines.size()
            << eol;
        return;
    }
    if (selectedAction == hexAction || selectedAction == peAction)
    {
        if (!firstPath.isEmpty() && QFileInfo(firstPath).isFile())
        {
            showFileDetailDialog(firstPath);
        }
        return;
    }
    if (selectedAction == mappedProcessScanAction)
    {
        openMappedProcessScanWindow(menuPaths);
        return;
    }
}

void FileDock::openSelectedItems(FilePanelWidgets& panel)
{
    // 打开逻辑支持多选：目录与文件分开处理，避免多目录时误切换当前面板路径。
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 打开选中项, panel="
            << panel.panelNameText.toStdString()
            << ", count="
            << paths.size()
            << eol;
    }

    int successCount = 0;
    int failCount = 0;
    QStringList failedPaths;
    for (const QString& path : paths)
    {
        QFileInfo info(path);
        if (info.isDir())
        {
            if (paths.size() == 1)
            {
                navigateToPath(panel, path, true);
                successCount += 1;
            }
            else
            {
                const bool openOk = QDesktopServices::openUrl(QUrl::fromLocalFile(path));
                if (openOk)
                {
                    successCount += 1;
                }
                else
                {
                    failCount += 1;
                    failedPaths.push_back(QDir::toNativeSeparators(path));
                }
            }
            continue;
        }

        const bool openOk = QDesktopServices::openUrl(QUrl::fromLocalFile(path));
        if (openOk)
        {
            successCount += 1;
        }
        else
        {
            failCount += 1;
            failedPaths.push_back(QDir::toNativeSeparators(path));
        }
    }

    kLogEvent resultEvent;
    if (failCount > 0)
    {
        warn << resultEvent
            << "[FileDock] 打开选中项部分失败, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failCount
            << ", failedPreview=\n"
            << buildLogPreviewText(failedPaths).toStdString()
            << eol;
        return;
    }

    info << resultEvent
        << "[FileDock] 打开选中项完成, panel="
        << panel.panelNameText.toStdString()
        << ", successCount="
        << successCount
        << eol;
}

void FileDock::copySelectedItemPath(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    QStringList lines;
    for (const QString& path : paths)
    {
        lines << QDir::toNativeSeparators(path);
    }
    QApplication::clipboard()->setText(lines.join('\n'));

    kLogEvent event;
    info << event
        << "[FileDock] 复制路径到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << paths.size()
        << eol;
}

void FileDock::copySelectedItemKernelPath(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    QStringList lines;
    lines.reserve(static_cast<int>(paths.size()));
    for (const QString& path : paths)
    {
        const QString kernelPath = buildDriverNtPath(path);
        lines << (kernelPath.isEmpty() ? QDir::toNativeSeparators(path) : kernelPath);
    }
    QApplication::clipboard()->setText(lines.join('\n'));

    kLogEvent event;
    info << event
        << "[FileDock] 复制内核模式地址到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << paths.size()
        << eol;
}

void FileDock::copySelectedItemShortName(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    QStringList shortNameLines;
    shortNameLines.reserve(static_cast<int>(paths.size()));

    int shortNameHitCount = 0;
    int fallbackCount = 0;
    for (const QString& path : paths)
    {
        const QString shortPathText = queryShortPathText(path);
        QString shortNameText;
        if (!shortPathText.isEmpty())
        {
            shortNameText = QFileInfo(shortPathText).fileName().trimmed();
            if (shortNameText.isEmpty())
            {
                shortNameText = QDir::toNativeSeparators(shortPathText);
            }
            shortNameHitCount += 1;
        }
        else
        {
            shortNameText = QFileInfo(path).fileName().trimmed();
            if (shortNameText.isEmpty())
            {
                shortNameText = QDir::toNativeSeparators(path);
            }
            fallbackCount += 1;
        }

        shortNameLines << shortNameText;
    }

    QApplication::clipboard()->setText(shortNameLines.join('\n'));

    kLogEvent event;
    info << event
        << "[FileDock] 复制短文件名到剪贴板, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << paths.size()
        << ", shortNameHitCount="
        << shortNameHitCount
        << ", fallbackCount="
        << fallbackCount
        << eol;
}

void FileDock::copySelectedItems(FilePanelWidgets& panel)
{
    transferSelectedItemsToOppositePanel(panel, false);
}

void FileDock::cutSelectedItems(FilePanelWidgets& panel)
{
    transferSelectedItemsToOppositePanel(panel, true);
}

FileDock::FilePanelWidgets* FileDock::oppositePanelFor(FilePanelWidgets& sourcePanel)
{
    if (&sourcePanel == &m_leftPanel)
    {
        return &m_rightPanel;
    }
    if (&sourcePanel == &m_rightPanel)
    {
        return &m_leftPanel;
    }
    return nullptr;
}

void FileDock::transferSelectedItemsToOppositePanel(FilePanelWidgets& sourcePanel, bool moveItems)
{
    if (m_transferInProgress)
    {
        return;
    }

    const std::vector<QString> selectedItemPaths = selectedPaths(sourcePanel);
    if (selectedItemPaths.empty())
    {
        return;
    }

    FilePanelWidgets* const targetPanel = oppositePanelFor(sourcePanel);
    if (targetPanel == nullptr || targetPanel->currentPath.trimmed().isEmpty())
    {
        kLogEvent event;
        warn << event
            << "[FileDock] 跨面板文件传输取消：无法解析目标面板, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << eol;
        return;
    }

    const QDir targetDir(targetPanel->currentPath);
    if (!targetDir.exists())
    {
        kLogEvent event;
        warn << event
            << "[FileDock] 跨面板文件传输取消：目标目录不存在, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << ", targetPanel="
            << targetPanel->panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(targetPanel->currentPath).toStdString()
            << eol;
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 跨面板文件传输请求, sourcePanel="
            << sourcePanel.panelNameText.toStdString()
            << ", targetPanel="
            << targetPanel->panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(targetPanel->currentPath).toStdString()
            << ", count="
            << selectedItemPaths.size()
            << ", mode="
            << (moveItems ? "move" : "copy")
            << eol;
    }

    // 复制/剪切在双栏中改为“源面板 -> 对侧面板当前目录”的直接动作，不再经过内部粘贴缓存。
    // 进度标题沿用右键菜单的目标面板文案，避免再出现容易误解的“剪切到对侧”。
    const QString localizedTargetPanelText = ks::i18n::displayText(targetPanel->panelNameText);
    const QString progressTitle = moveItems
        ? ks::i18n::displayText(QStringLiteral("移动到%1")).arg(localizedTargetPanelText)
        : ks::i18n::displayText(QStringLiteral("复制到%1")).arg(localizedTargetPanelText);
    const int progressPid = kPro.add(this, "文件", progressTitle.toStdString());
    kPro.set(progressPid, moveItems ? "准备移动" : "准备复制", 0, 5.0f);
    m_transferInProgress = true;

    const bool sourceWasLeftPanel = &sourcePanel == &m_leftPanel;
    const QString targetDirectoryPath = targetPanel->currentPath;
    const QString sourcePanelNameText = sourcePanel.panelNameText;
    const QString targetPanelNameText = targetPanel->panelNameText;
    const QPointer<FileDock> safeThis(this);
    const QPointer<QApplication> applicationGuard(qApp);

    QThreadPool::globalInstance()->start(
        [safeThis,
            applicationGuard,
            selectedItemPaths,
            targetDirectoryPath,
            sourcePanelNameText,
            targetPanelNameText,
            sourceWasLeftPanel,
            moveItems,
            progressPid]()
        {
            QStringList errorLines;
            const QDir workerTargetDir(targetDirectoryPath);
            const std::size_t totalCount = selectedItemPaths.size();

            for (std::size_t i = 0; i < totalCount; ++i)
            {
                const QString sourcePath = selectedItemPaths[i];
                QFileInfo sourceInfo(sourcePath);
                if (isPathReparsePoint(sourcePath))
                {
                    errorLines << ks::i18n::displayText(
                        QStringLiteral("为避免越界递归，不复制符号链接或重解析点: %1"))
                        .arg(QDir::toNativeSeparators(sourcePath));
                    continue;
                }
                if (!sourceInfo.exists())
                {
                    errorLines << QStringLiteral("源不存在：%1").arg(sourcePath);
                    continue;
                }

                const QString targetPath = workerTargetDir.filePath(sourceInfo.fileName());
                if (QDir::cleanPath(sourcePath).compare(QDir::cleanPath(targetPath), Qt::CaseInsensitive) == 0)
                {
                    errorLines << QStringLiteral("源和目标相同，已跳过：%1").arg(sourcePath);
                    continue;
                }
                if (sourceInfo.isDir())
                {
                    const QString cleanSourceDirPath = QDir::cleanPath(sourceInfo.absoluteFilePath());
                    const QString cleanTargetPath = QDir::cleanPath(targetPath);
                    const QString sourcePrefix = cleanSourceDirPath.endsWith(QLatin1Char('/'))
                        ? cleanSourceDirPath
                        : cleanSourceDirPath + QLatin1Char('/');
                    if (cleanTargetPath.startsWith(sourcePrefix, Qt::CaseInsensitive))
                    {
                        errorLines << QStringLiteral("不能把目录复制或移动到自身子目录：%1 -> %2")
                            .arg(sourcePath, targetPath);
                        continue;
                    }
                }

                bool itemOk = false;
                QString copyErrorText;
                if (moveItems)
                {
                    // 剪切优先尝试同卷重命名，失败再走事务复制和源删除。
                    itemOk = QFile::rename(sourcePath, targetPath);
                    if (!itemOk && sourceInfo.isDir())
                    {
                        itemOk = copyDirectoryTransactionally(sourcePath, targetPath, copyErrorText);
                        if (itemOk && !QDir(sourcePath).removeRecursively())
                        {
                            itemOk = false;
                            copyErrorText = ks::i18n::displayText(
                                QStringLiteral("目标已写入，但删除源目录失败: %1"))
                                .arg(sourcePath);
                        }
                    }
                    else if (!itemOk)
                    {
                        itemOk = copyFileTransactionally(sourcePath, targetPath, copyErrorText);
                        if (itemOk && !QFile::remove(sourcePath))
                        {
                            itemOk = false;
                            copyErrorText = ks::i18n::displayText(
                                QStringLiteral("目标已写入，但删除源文件失败: %1"))
                                .arg(sourcePath);
                        }
                    }
                }
                else if (sourceInfo.isDir())
                {
                    itemOk = copyDirectoryTransactionally(sourcePath, targetPath, copyErrorText);
                }
                else
                {
                    itemOk = copyFileTransactionally(sourcePath, targetPath, copyErrorText);
                }

                if (!itemOk)
                {
                    errorLines << copyErrorText;
                }

                if (!applicationGuard.isNull())
                {
                    const float progress = 5.0f +
                        (static_cast<float>(i + 1) / static_cast<float>(totalCount)) * 90.0f;
                    QMetaObject::invokeMethod(
                        applicationGuard.data(),
                        [progressPid, moveItems, progress]()
                        {
                            kPro.set(progressPid, moveItems ? "移动处理中" : "复制处理中", 0, progress);
                        },
                        Qt::QueuedConnection);
                }
            }

            if (applicationGuard.isNull())
            {
                return;
            }

            QMetaObject::invokeMethod(
                applicationGuard.data(),
                [safeThis,
                    errorLines = std::move(errorLines),
                    sourcePanelNameText,
                    targetPanelNameText,
                    sourceWasLeftPanel,
                    moveItems,
                    progressPid,
                    totalCount]()
                {
                    kPro.set(progressPid, moveItems ? "移动完成" : "复制完成", 0, 100.0f);
                    if (safeThis.isNull())
                    {
                        return;
                    }

                    FileDock* const dock = safeThis.data();
                    dock->m_transferInProgress = false;
                    FilePanelWidgets& completedSourcePanel = sourceWasLeftPanel
                        ? dock->m_leftPanel
                        : dock->m_rightPanel;
                    FilePanelWidgets& completedTargetPanel = sourceWasLeftPanel
                        ? dock->m_rightPanel
                        : dock->m_leftPanel;
                    dock->refreshPanel(completedSourcePanel);
                    dock->refreshPanel(completedTargetPanel);

                    if (!errorLines.isEmpty())
                    {
                        kLogEvent event;
                        warn << event
                            << "[FileDock] 跨面板文件传输部分失败, sourcePanel="
                            << sourcePanelNameText.toStdString()
                            << ", targetPanel="
                            << targetPanelNameText.toStdString()
                            << ", errorCount="
                            << errorLines.size()
                            << ", errorPreview=\n"
                            << buildLogPreviewText(errorLines).toStdString()
                            << eol;
                        return;
                    }

                    kLogEvent event;
                    info << event
                        << "[FileDock] 跨面板文件传输完成, sourcePanel="
                        << sourcePanelNameText.toStdString()
                        << ", targetPanel="
                        << targetPanelNameText.toStdString()
                        << ", totalCount="
                        << totalCount
                        << ", mode="
                        << (moveItems ? "move" : "copy")
                        << eol;
                },
                Qt::QueuedConnection);
        });
}

void FileDock::createNewFileOrFolder(FilePanelWidgets& panel, bool createFolder)
{
    {
        kLogEvent event;
        info << event
            << "[FileDock] 新建请求, panel="
            << panel.panelNameText.toStdString()
            << ", type="
            << (createFolder ? "folder" : "file")
            << ", currentPath="
            << QDir::toNativeSeparators(panel.currentPath).toStdString()
            << eol;
    }

    bool ok = false;
    const QString inputName = QInputDialog::getText(
        this,
        createFolder ? QStringLiteral("新建文件夹") : QStringLiteral("新建文件"),
        QStringLiteral("请输入名称："),
        QLineEdit::Normal,
        createFolder ? QStringLiteral("新建文件夹") : QStringLiteral("新建文件.txt"),
        &ok);
    if (!ok)
    {
        return;
    }

    const QString trimmedName = inputName.trimmed();
    if (trimmedName.isEmpty())
    {
        return;
    }

    const QString targetPath = QDir(panel.currentPath).filePath(trimmedName);
    bool createOk = false;
    if (createFolder)
    {
        QDir dir;
        createOk = dir.mkpath(targetPath);
    }
    else
    {
        QFile file(targetPath);
        createOk = file.open(QIODevice::WriteOnly | QIODevice::Truncate);
        file.close();
    }

    if (!createOk)
    {
        kLogEvent event;
        err << event
            << "[FileDock] 新建失败, panel="
            << panel.panelNameText.toStdString()
            << ", targetPath="
            << QDir::toNativeSeparators(targetPath).toStdString()
            << eol;
        return;
    }

    refreshPanel(panel);

    kLogEvent event;
    info << event
        << "[FileDock] 新建成功, panel="
        << panel.panelNameText.toStdString()
        << ", targetPath="
        << QDir::toNativeSeparators(targetPath).toStdString()
        << eol;
}

void FileDock::renameSelectedItem(FilePanelWidgets& panel)
{
    const QString path = currentIndexPath(panel);
    if (path.isEmpty())
    {
        return;
    }

    {
        kLogEvent event;
        info << event
            << "[FileDock] 重命名请求, panel="
            << panel.panelNameText.toStdString()
            << ", oldPath="
            << QDir::toNativeSeparators(path).toStdString()
            << eol;
    }

    QFileInfo oldInfo(path);
    bool ok = false;
    const QString newName = QInputDialog::getText(
        this,
        QStringLiteral("重命名"),
        QStringLiteral("新名称："),
        QLineEdit::Normal,
        oldInfo.fileName(),
        &ok);
    if (!ok)
    {
        return;
    }

    const QString trimmedName = newName.trimmed();
    if (trimmedName.isEmpty() || trimmedName == oldInfo.fileName())
    {
        return;
    }

    const QString newPath = oldInfo.dir().filePath(trimmedName);
    bool renameOk = false;
    if (oldInfo.isDir())
    {
        QDir parentDir = oldInfo.dir();
        renameOk = parentDir.rename(oldInfo.fileName(), trimmedName);
    }
    else
    {
        renameOk = QFile::rename(path, newPath);
    }

    if (!renameOk)
    {
        kLogEvent event;
        err << event
            << "[FileDock] 重命名失败, panel="
            << panel.panelNameText.toStdString()
            << ", oldPath="
            << QDir::toNativeSeparators(path).toStdString()
            << ", newPath="
            << QDir::toNativeSeparators(newPath).toStdString()
            << eol;
        return;
    }

    refreshPanel(panel);

    kLogEvent event;
    info << event
        << "[FileDock] 重命名成功, panel="
        << panel.panelNameText.toStdString()
        << ", oldPath="
        << QDir::toNativeSeparators(path).toStdString()
        << ", newPath="
        << QDir::toNativeSeparators(newPath).toStdString()
        << eol;
}

void FileDock::deleteSelectedItem(FilePanelWidgets& panel)
{
    // Delete 快捷键与右键顶层「删除」都走可还原的回收站档，
    // 更强的权限手段统一放在「删除方式」子菜单里显式选择。
    deleteSelectedItemsWithMode(panel, FileDeleteMode::RecycleBin);
}

void FileDock::deleteSelectedItemByDriver(FilePanelWidgets& panel)
{
    deleteSelectedItemsWithMode(panel, FileDeleteMode::DriverR0Native);
}

void FileDock::deleteSelectedItemsWithMode(FilePanelWidgets& panel, const FileDeleteMode mode)
{
    // 防重入：删除和跨面板传输一样是整批文件系统写操作，收尾还要刷新面板，
    // 期间不能再接受第二次删除请求（否则两批任务会互相刷掉对方的结果）。
    if (property(kFileDeleteInProgressProperty).toBool())
    {
        return;
    }

    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    // 档位文案必须把“可逆性 + 权限手段”说清楚：
    // 用户对“删除”的预期来自资源管理器（进回收站、可还原），而下面四档都不可撤销，
    // 不提前说明就等于让不可逆操作伪装成可撤销操作。
    QString modeNameText;
    QString confirmTitleText;
    QString confirmBodyText;
    switch (mode)
    {
    case FileDeleteMode::RecycleBin:
        modeNameText = QStringLiteral("删除到回收站");
        confirmTitleText = QStringLiteral("删除确认");
        confirmBodyText = QStringLiteral(
            "确定要把选中的 %1 项移到回收站吗？\n\n"
            "若某些项无法移入回收站（例如位于网络位置、可移动磁盘，或回收站已停用），"
            "将改为永久删除且无法还原；完成后会告知具体数量。")
            .arg(paths.size());
        break;
    case FileDeleteMode::PermanentR3:
        modeNameText = QStringLiteral("永久删除");
        confirmTitleText = QStringLiteral("永久删除确认");
        confirmBodyText = QStringLiteral(
            "将以当前用户权限永久删除选中的 %1 项，不进入回收站、无法还原。\n\n"
            "目录会按“子项先删、目录后删”的顺序递归删除；符号链接/联接点只删除链接本身，"
            "不会跟进到链接目标。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::ForceR3:
        modeNameText = QStringLiteral("强制删除（接管所有权）");
        confirmTitleText = QStringLiteral("强制删除确认");
        confirmBodyText = QStringLiteral(
            "将对选中的 %1 项执行强制删除：清除只读/隐藏/系统属性，必要时把所有者改为 "
            "BUILTIN\\Administrators 并授予完全控制，然后递归永久删除。\n\n"
            "所有权与访问控制项会被真实修改且不会自动还原，删除本身也无法撤销。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::PendingReboot:
        modeNameText = QStringLiteral("重启后删除");
        confirmTitleText = QStringLiteral("重启后删除确认");
        confirmBodyText = QStringLiteral(
            "将把选中的 %1 项登记到 PendingFileRenameOperations，由系统在下次重启的早期阶段删除。\n\n"
            "适用于正被占用、当前无法删除的目标；登记后文件在重启前仍然存在，"
            "删除结果要等重启后才能确认。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::DriverR0Native:
        modeNameText = QStringLiteral("R0 驱动（底层方案）");
        confirmTitleText = QStringLiteral("R0 底层删除确认");
        confirmBodyText = QStringLiteral(
            "将通过 KswordARK 驱动的底层 Zw* 方案硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树由 R0 递归展开后序删除，因此目录拒绝列举时也能删干净；失败时会执行现有 DispositionEx 兼容重试。符号链接/联接点只删除链接本身。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::DriverR0Irp:
        modeNameText = QStringLiteral("R0 驱动(IRP)");
        confirmTitleText = QStringLiteral("R0 IRP 删除确认");
        confirmBodyText = QStringLiteral(
            "将由 KswordARK 驱动构造 IRP_MJ_SET_INFORMATION / FileDispositionInformation，通过完整文件系统栈硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树仍由 R0 后序递归展开；此模式不会回退到底层方案。符号链接/联接点只删除链接本身。是否继续？")
            .arg(paths.size());
        break;
    case FileDeleteMode::DriverR0Posix:
        modeNameText = QStringLiteral("R0 驱动(POSIX)");
        confirmTitleText = QStringLiteral("R0 POSIX 删除确认");
        confirmBodyText = QStringLiteral(
            "将由 KswordARK 驱动使用 FileDispositionInformationEx 的 POSIX unlink 语义，硬删除选中的 %1 项，不进入回收站、无法还原。\n\n目录树仍由 R0 后序递归展开；支持情况取决于 Windows 版本与文件系统，失败时不会回退到 IRP 或底层方案。是否继续？")
            .arg(paths.size());
        break;
    default:
        return;
    }

    {
        kLogEvent requestEvent;
        info << requestEvent
            << "[FileDock] 删除请求, panel="
            << panel.panelNameText.toStdString()
            << ", mode="
            << modeNameText.toStdString()
            << ", count="
            << paths.size()
            << eol;
    }

    // 接管所有权与 PendingFileRenameOperations 都要求管理员令牌，
    // 未提权时直接引导重启提权，避免用户在一堆 error=5 里猜原因。
    if (mode == FileDeleteMode::ForceR3 || mode == FileDeleteMode::PendingReboot)
    {
        if (!ks::ui::isCurrentProcessElevated())
        {
            (void)ks::ui::requestAdministratorRestartForFeature(this, modeNameText);
            return;
        }
    }

    const QMessageBox::StandardButton userChoice = QMessageBox::question(
        this,
        confirmTitleText,
        confirmBodyText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (userChoice != QMessageBox::Yes)
    {
        return;
    }

    const int progressPid = kPro.add(this, "文件", modeNameText.toStdString());
    kPro.set(progressPid, "删除开始", 0, 5.0f);
    setProperty(kFileDeleteInProgressProperty, true);

    // 删除整体放在后台线程：moveToTrash 走 Shell IFileOperation（每项固定几十毫秒），
    // 递归展开还要走完整棵树，多选或删大目录时同步执行会把事件循环占死数秒到数分钟，
    // 连 kPro 进度条都刷不出来。写法与同文件的 transferSelectedItemsToOppositePanel 保持一致。
    const bool sourceWasLeftPanel = &panel == &m_leftPanel;
    const QString panelNameText = panel.panelNameText;
    const QPointer<FileDock> guardedSelf(this);
    const QPointer<QApplication> applicationGuard(qApp);

    QThreadPool::globalInstance()->start(
        [guardedSelf, applicationGuard, paths, panelNameText, modeNameText, mode, sourceWasLeftPanel, progressPid]()
        {
            // 进度按整数百分比节流：大目录会产生上万次回调，逐次 post 会把主线程事件队列打爆。
            int lastProgressBucket = 5;
            const auto progressReporter =
                [&lastProgressBucket, applicationGuard, progressPid](const float progress)
                {
                    const int bucket = static_cast<int>(progress);
                    if (bucket <= lastProgressBucket)
                    {
                        return;
                    }
                    lastProgressBucket = bucket;
                    if (applicationGuard.isNull())
                    {
                        return;
                    }
                    QMetaObject::invokeMethod(
                        applicationGuard.data(),
                        [progressPid, progress]()
                        {
                            kPro.set(progressPid, "删除处理中", 0, progress);
                        },
                        Qt::QueuedConnection);
                };

            FileDeleteBatchStats stats = runFileDeleteBatch(paths, mode, progressReporter);

            if (applicationGuard.isNull())
            {
                return;
            }

            QMetaObject::invokeMethod(
                applicationGuard.data(),
                [guardedSelf,
                    stats = std::move(stats),
                    panelNameText,
                    modeNameText,
                    mode,
                    sourceWasLeftPanel,
                    progressPid,
                    originalCount = paths.size()]()
                {
                    kPro.set(progressPid, "删除完成", 0, 100.0f);
                    if (guardedSelf.isNull())
                    {
                        return;
                    }

                    FileDock* const dock = guardedSelf.data();
                    dock->setProperty(kFileDeleteInProgressProperty, false);
                    FilePanelWidgets& completedPanel = sourceWasLeftPanel
                        ? dock->m_leftPanel
                        : dock->m_rightPanel;
                    dock->refreshPanel(completedPanel);

                    QStringList summaryLines;
                    if (stats.recycledCount > 0U)
                    {
                        summaryLines << QStringLiteral("已移入回收站：%1 项").arg(stats.recycledCount);
                    }
                    if ((stats.deletedFileCount + stats.deletedDirectoryCount) > 0U)
                    {
                        summaryLines << QStringLiteral("已永久删除：文件 %1 个、目录 %2 个")
                            .arg(stats.deletedFileCount)
                            .arg(stats.deletedDirectoryCount);
                    }
                    if (stats.pendingRebootCount > 0U)
                    {
                        summaryLines << QStringLiteral("已登记重启后删除：%1 项").arg(stats.pendingRebootCount);
                    }
                    if (stats.skippedReparseCount > 0U)
                    {
                        summaryLines << QStringLiteral("重解析点只删除了链接本身：%1 项")
                            .arg(stats.skippedReparseCount);
                    }
                    if (stats.permissionRepairCount > 0U)
                    {
                        summaryLines << QStringLiteral("触发接管所有权/授权的项：%1 项（所有权与 DACL 已被修改，不会自动还原）")
                            .arg(stats.permissionRepairCount);
                    }
                    if (stats.driverRecursionUnsupported)
                    {
                        summaryLines << QStringLiteral("当前 R0 驱动不支持内核递归删除，已回退为 R3 展开逐项删除。");
                    }
                    if (stats.failedCount > 0U)
                    {
                        summaryLines << QStringLiteral("失败：%1 项").arg(stats.failedCount);
                    }

                    {
                        kLogEvent completionEvent;
                        (stats.failedCount > 0U ? warn : info) << completionEvent
                            << "[FileDock] 删除完成, panel="
                            << panelNameText.toStdString()
                            << ", mode="
                            << modeNameText.toStdString()
                            << ", requested="
                            << originalCount
                            << ", recycled="
                            << stats.recycledCount
                            << ", files="
                            << stats.deletedFileCount
                            << ", dirs="
                            << stats.deletedDirectoryCount
                            << ", pendingReboot="
                            << stats.pendingRebootCount
                            << ", failed="
                            << stats.failedCount
                            << ", errorPreview=\n"
                            << buildLogPreviewText(stats.errors).toStdString()
                            << eol;
                    }

                    if (stats.driverUnavailable)
                    {
                        QMessageBox::warning(
                            dock,
                            QStringLiteral("驱动删除"),
                            QStringLiteral("无法连接 KswordARK 驱动设备，请先启用 R0 驱动。\n\n%1")
                                .arg(buildLogPreviewText(stats.errors)));
                        return;
                    }

                    // 有项目未能进回收站时必须显式告知：这些项已不可还原，
                    // 用户需要据此判断还能不能靠回收站补救。
                    if (!stats.permanentlyDeleted.isEmpty())
                    {
                        QMessageBox::warning(
                            dock,
                            QStringLiteral("部分项目已永久删除"),
                            QStringLiteral("有 %1 项无法移入回收站，已被永久删除，无法从回收站还原：\n\n%2")
                                .arg(stats.permanentlyDeleted.size())
                                .arg(buildLogPreviewText(stats.permanentlyDeleted)));
                    }

                    if (stats.failedCount > 0U)
                    {
                        QMessageBox::warning(
                            dock,
                            modeNameText,
                            QStringLiteral("%1 未全部完成。\n\n%2\n\n失败明细（最多显示前若干条）：\n%3")
                                .arg(modeNameText)
                                .arg(summaryLines.join(QStringLiteral("\n")))
                                .arg(buildLogPreviewText(stats.errors)));
                        return;
                    }

                    if (mode == FileDeleteMode::PendingReboot && stats.pendingRebootCount > 0U)
                    {
                        QMessageBox::information(
                            dock,
                            modeNameText,
                            QStringLiteral("%1\n\n目标仍然存在，系统会在下次重启的早期阶段执行删除。")
                                .arg(summaryLines.join(QStringLiteral("\n"))));
                    }
                },
                Qt::QueuedConnection);
        });
}

void FileDock::unlockSelectedItemsByDriver(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }
    if (paths.size() != 1)
    {
        // 当前文件解锁器会先扫描占用来源，再让用户选择关闭句柄或结束进程。
        // 多路径下候选句柄/进程关系容易混在一起，暂不提供批量入口，避免误结束无关进程。
        QMessageBox::information(
            this,
            QStringLiteral("文件解锁器"),
            QStringLiteral("文件解锁器暂不支持多文件批量解除占用，请只选择一个文件或目录。"));
        kLogEvent event;
        info << event
            << "[FileDock] 文件解锁器取消：暂不支持多选, panel="
            << panel.panelNameText.toStdString()
            << ", selectedCount="
            << paths.size()
            << eol;
        return;
    }

    unlockPathsByDriver(paths, QStringLiteral("panel_context_menu"), &panel);
}

void FileDock::addOplockToSelectedFile(FilePanelWidgets& panel, const FileOplockLevel level)
{
    const QString levelText = fileOplockLevelText(level);
    const unsigned long controlCode = fileOplockControlCode(level);
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("请只选择一个文件。"));
        return;
    }

    const QFileInfo fileInfo(paths.front());
    if (!fileInfo.isFile())
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("Oplock 入口当前只支持普通文件。"));
        return;
    }

    const QString normalizedPath = normalizeFileDockPath(fileInfo.absoluteFilePath());
    if (hasActiveOplockForPath(normalizedPath))
    {
        QMessageBox::information(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("该文件已经由 FileDock 持有 Oplock：\n%1").arg(normalizedPath));
        return;
    }

    std::wstring nativePath = normalizedPath.toStdWString();
    HANDLE fileHandle = ::CreateFileW(
        nativePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        nullptr);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        const DWORD errorCode = ::GetLastError();
        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("打开文件失败，无法请求 %1 Oplock，Win32=%2：\n%3")
                .arg(levelText)
                .arg(errorCode)
                .arg(normalizedPath));
        kLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：CreateFileW, path="
            << normalizedPath.toStdString()
            << ", level="
            << levelText.toStdString()
            << ", error="
            << errorCode
            << eol;
        return;
    }

    auto oplockEntry = std::make_shared<FileOplockEntry>();
    oplockEntry->path = normalizedPath;
    oplockEntry->level = level;
    oplockEntry->fileHandle = fileHandle;
    oplockEntry->eventHandle = ::CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (oplockEntry->eventHandle == nullptr)
    {
        const DWORD errorCode = ::GetLastError();
        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("创建 %1 Oplock 等待事件失败，Win32=%2。").arg(levelText).arg(errorCode));
        kLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：CreateEventW, path="
            << normalizedPath.toStdString()
            << ", level="
            << levelText.toStdString()
            << ", error="
            << errorCode
            << eol;
        return;
    }
    unsigned long requestError = ERROR_SUCCESS;
    if (!requestFileOplock(*oplockEntry, requestError))
    {
        if (requestError == ERROR_SUCCESS)
        {
            QMessageBox::information(
                this,
                QStringLiteral("添加 Oplock"),
                QStringLiteral("%1 Oplock 请求已立即完成，没有保持中的 Oplock：\n%2")
                    .arg(levelText, normalizedPath));
            kLogEvent event;
            info << event
                << "[FileDock] 添加 Oplock：请求同步完成, path="
                << normalizedPath.toStdString()
                << ", level="
                << levelText.toStdString()
                << eol;
            return;
        }

        QMessageBox::warning(
            this,
            QStringLiteral("添加 Oplock"),
            QStringLiteral("请求 %1 Oplock 失败，Win32=%2：\n%3")
                .arg(levelText)
                .arg(requestError)
                .arg(normalizedPath));
        kLogEvent event;
        warn << event
            << "[FileDock] 添加 Oplock 失败：DeviceIoControl, path="
            << normalizedPath.toStdString()
            << ", level="
            << levelText.toStdString()
            << ", controlCode=0x"
            << QString::number(controlCode, 16).toStdString()
            << ", error="
            << requestError
            << eol;
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        m_activeOplocks.push_back(oplockEntry);
    }

    QPointer<FileDock> safeThis(this);
    oplockEntry->waitThread = std::thread([safeThis, oplockEntry]() {
        for (;;)
        {
            bool completionOk = false;
            DWORD completionError = ERROR_SUCCESS;
            DWORD bytesTransferred = 0;
            HANDLE fileHandle = INVALID_HANDLE_VALUE;
            {
                std::lock_guard<std::mutex> lock(oplockEntry->ioMutex);
                fileHandle = oplockEntry->fileHandle;
            }
            completionOk = (::GetOverlappedResult(
                fileHandle,
                &oplockEntry->overlapped,
                &bytesTransferred,
                TRUE) != FALSE);
            if (!completionOk)
            {
                completionError = ::GetLastError();
            }
            {
                std::lock_guard<std::mutex> lock(oplockEntry->ioMutex);
                oplockEntry->ioPending = false;
            }

            if (oplockEntry->releaseRequested.load())
            {
                break;
            }

            const std::uint64_t breakSequence = oplockEntry->breakCount.fetch_add(1U) + 1U;
            unsigned long acknowledgeError = ERROR_SUCCESS;
            const bool acknowledgeOk = completionOk
                ? FileDock::acknowledgeFileOplockBreak(*oplockEntry, acknowledgeError)
                : false;
            const std::size_t capturedProcessCount =
                (completionOk && acknowledgeOk && !oplockEntry->releaseRequested.load())
                ? FileDock::recordFileOplockAccessPrograms(*oplockEntry, breakSequence)
                : 0U;

            if (safeThis != nullptr)
            {
                QMetaObject::invokeMethod(
                    safeThis,
                    [
                        safeThis,
                        oplockEntry,
                        completionOk,
                        completionError,
                        acknowledgeOk,
                        acknowledgeError,
                        capturedProcessCount
                    ]() {
                        if (safeThis != nullptr)
                        {
                            safeThis->handleOplockCompleted(
                                oplockEntry,
                                completionOk,
                                completionError,
                                acknowledgeOk,
                                acknowledgeError,
                                capturedProcessCount);
                        }
                    },
                    Qt::QueuedConnection);
            }

            if (!completionOk || !acknowledgeOk)
            {
                break;
            }

            for (;;)
            {
                if (oplockEntry->releaseRequested.load())
                {
                    break;
                }

                unsigned long rearmError = ERROR_SUCCESS;
                if (FileDock::requestFileOplock(*oplockEntry, rearmError))
                {
                    break;
                }
                if (oplockEntry->releaseRequested.load())
                {
                    break;
                }

                if (!oplockEntry->rearmWarningReported.exchange(true) && safeThis != nullptr)
                {
                    QMetaObject::invokeMethod(
                        safeThis,
                        [safeThis, oplockEntry, rearmError]() {
                            if (safeThis != nullptr)
                            {
                                safeThis->handleOplockRearmPending(oplockEntry, rearmError);
                            }
                        },
                        Qt::QueuedConnection);
                }

                if (oplockEntry->eventHandle != nullptr)
                {
                    (void)::ResetEvent(oplockEntry->eventHandle);
                    (void)::WaitForSingleObject(oplockEntry->eventHandle, 250);
                }
                else
                {
                    ::Sleep(250);
                }
            }

            if (oplockEntry->releaseRequested.load())
            {
                break;
            }
        }
    });

    QMessageBox::information(
        this,
        QStringLiteral("添加 Oplock"),
        QStringLiteral("已为文件添加 %1 Oplock。保持期间如果其它进程触发访问，将累计次数并自动重新挂起，直到手动释放：\n%2")
            .arg(levelText, normalizedPath));
    kLogEvent event;
    info << event
        << "[FileDock] 添加 Oplock 成功, path="
        << normalizedPath.toStdString()
        << ", level="
        << levelText.toStdString()
        << ", controlCode=0x"
        << QString::number(controlCode, 16).toStdString()
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::releaseSelectedFileOplock(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放 Oplock"),
            QStringLiteral("请只选择一个已添加 Oplock 的文件。"));
        return;
    }

    const QString normalizedPath = normalizeFileDockPath(paths.front());
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        auto iterator = std::find_if(
            m_activeOplocks.begin(),
            m_activeOplocks.end(),
            [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr && pathEqualsCaseInsensitive(entry->path, normalizedPath);
            });
        if (iterator != m_activeOplocks.end())
        {
            targetEntry = *iterator;
            m_activeOplocks.erase(iterator);
        }
    }

    if (targetEntry == nullptr)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放 Oplock"),
            QStringLiteral("当前文件没有由 FileDock 持有的 Oplock：\n%1").arg(normalizedPath));
        return;
    }

    const std::uint64_t breakCount = targetEntry->breakCount.load();
    std::size_t accessProcessCount = 0U;
    std::uint64_t uncapturedBreakCount = 0U;
    {
        std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
        accessProcessCount = targetEntry->accessRecords.size();
        uncapturedBreakCount = targetEntry->uncapturedBreakCount;
    }
    const QString levelText = fileOplockLevelText(targetEntry->level);
    targetEntry->releaseRequested.store(true);
    cancelFileOplockRequest(*targetEntry);
    if (targetEntry->waitThread.joinable() &&
        targetEntry->waitThread.get_id() != std::this_thread::get_id())
    {
        targetEntry->waitThread.join();
    }

    QMessageBox::information(
        this,
        QStringLiteral("释放 Oplock"),
        QStringLiteral("已释放 %1 Oplock。\n触发次数：%2\n记录进程：%3\n未捕获触发：%4\n文件：%5")
            .arg(levelText)
            .arg(breakCount)
            .arg(accessProcessCount)
            .arg(uncapturedBreakCount)
            .arg(normalizedPath));
    kLogEvent event;
    info << event
        << "[FileDock] 释放当前 Oplock, path="
        << normalizedPath.toStdString()
        << ", level="
        << levelText.toStdString()
        << ", breakCount="
        << breakCount
        << ", accessProcessCount="
        << accessProcessCount
        << ", uncapturedBreakCount="
        << uncapturedBreakCount
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::showSelectedFileOplockAccessRecords(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.size() != 1U)
    {
        QMessageBox::information(
            this,
            QStringLiteral("Oplock 访问记录"),
            QStringLiteral("请只选择一个已添加 Oplock 的文件。"));
        return;
    }

    const QString normalizedPath = normalizeFileDockPath(paths.front());
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        auto iterator = std::find_if(
            m_activeOplocks.begin(),
            m_activeOplocks.end(),
            [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr &&
                    !entry->releaseRequested.load() &&
                    pathEqualsCaseInsensitive(entry->path, normalizedPath);
            });
        if (iterator != m_activeOplocks.end())
        {
            targetEntry = *iterator;
        }
    }

    if (targetEntry == nullptr)
    {
        QMessageBox::information(
            this,
            QStringLiteral("Oplock 访问记录"),
            QStringLiteral("当前文件没有由 FileDock 持有的 Oplock：\n%1").arg(normalizedPath));
        return;
    }

    std::vector<FileOplockAccessRecord> accessRecords;
    QString diagnosticText;
    std::uint64_t uncapturedBreakCount = 0U;
    {
        std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
        accessRecords = targetEntry->accessRecords;
        diagnosticText = targetEntry->lastAccessScanDiagnostic;
        uncapturedBreakCount = targetEntry->uncapturedBreakCount;
    }
    std::sort(
        accessRecords.begin(),
        accessRecords.end(),
        [](const FileOplockAccessRecord& left, const FileOplockAccessRecord& right) {
            if (left.lastBreakSequence != right.lastBreakSequence)
            {
                return left.lastBreakSequence > right.lastBreakSequence;
            }
            return left.processId < right.processId;
        });

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("Oplock 访问记录"));
    dialog.resize(1180, 620);

    auto* layout = new QVBoxLayout(&dialog);
    auto* summaryLabel = new QLabel(
        QStringLiteral("文件：%1\n级别：%2 | 触发次数：%3 | 记录进程：%4 | 未捕获触发：%5\n最近扫描：%6")
            .arg(normalizedPath)
            .arg(fileOplockLevelText(targetEntry->level))
            .arg(targetEntry->breakCount.load())
            .arg(accessRecords.size())
            .arg(uncapturedBreakCount)
            .arg(diagnosticText.trimmed().isEmpty() ? QStringLiteral("-") : diagnosticText),
        &dialog);
    summaryLabel->setWordWrap(true);
    layout->addWidget(summaryLabel);

    auto* table = new ks::ui::VisibleTableWidget(static_cast<int>(accessRecords.size()), 13, &dialog);
    table->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("PID"),
        QStringLiteral("进程名"),
        QStringLiteral("触发命中"),
        QStringLiteral("句柄命中"),
        QStringLiteral("访问掩码"),
        QStringLiteral("最近句柄"),
        QStringLiteral("首次触发"),
        QStringLiteral("最近触发"),
        QStringLiteral("首次时间"),
        QStringLiteral("最近时间"),
        QStringLiteral("命中路径"),
        QStringLiteral("规则/来源"),
        QStringLiteral("映像路径")
    });
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);
    installFileTableCopyMenu(table, 0);

    auto makeItem = [](const QString& text) {
        auto* item = new QTableWidgetItem(text);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    };

    for (int row = 0; row < static_cast<int>(accessRecords.size()); ++row)
    {
        const FileOplockAccessRecord& record = accessRecords[static_cast<std::size_t>(row)];
        const QStringList ruleAndSourceList = QStringList{
            record.matchRuleList.join(QStringLiteral("\n")),
            record.enumerationSourceList.join(QStringLiteral("\n")),
            record.objectNameList.join(QStringLiteral("\n"))
        };
        table->setItem(row, 0, makeItem(QString::number(record.processId)));
        table->setItem(row, 1, makeItem(record.processName.isEmpty() ? QStringLiteral("Unknown") : record.processName));
        table->setItem(row, 2, makeItem(QString::number(record.hitCount)));
        table->setItem(row, 3, makeItem(QString::number(record.handleHitCount)));
        table->setItem(row, 4, makeItem(formatHandleValueText(record.lastGrantedAccess)));
        table->setItem(row, 5, makeItem(formatHandleValueText(record.lastHandleValue)));
        table->setItem(row, 6, makeItem(QString::number(record.firstBreakSequence)));
        table->setItem(row, 7, makeItem(QString::number(record.lastBreakSequence)));
        table->setItem(row, 8, makeItem(record.firstSeenText));
        table->setItem(row, 9, makeItem(record.lastSeenText));
        table->setItem(row, 10, makeItem(record.matchedTargetList.join(QStringLiteral("\n"))));
        table->setItem(row, 11, makeItem(ruleAndSourceList.join(QStringLiteral("\n"))));
        table->setItem(row, 12, makeItem(record.processImagePath));
    }
    table->resizeColumnsToContents();
    layout->addWidget(table, 1);

    auto* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
    QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    dialog.exec();
}

void FileDock::releaseAllActiveOplocks(const bool showMessage)
{
    std::vector<std::shared_ptr<FileOplockEntry>> entries;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        entries.swap(m_activeOplocks);
    }

    std::uint64_t totalBreakCount = 0;
    std::uint64_t totalUncapturedBreakCount = 0;
    std::size_t totalAccessProcessCount = 0U;
    for (const std::shared_ptr<FileOplockEntry>& entry : entries)
    {
        if (entry == nullptr)
        {
            continue;
        }
        totalBreakCount += entry->breakCount.load();
        {
            std::lock_guard<std::mutex> lock(entry->accessRecordMutex);
            totalAccessProcessCount += entry->accessRecords.size();
            totalUncapturedBreakCount += entry->uncapturedBreakCount;
        }
        entry->releaseRequested.store(true);
        cancelFileOplockRequest(*entry);
    }

    for (const std::shared_ptr<FileOplockEntry>& entry : entries)
    {
        if (entry != nullptr &&
            entry->waitThread.joinable() &&
            entry->waitThread.get_id() != std::this_thread::get_id())
        {
            entry->waitThread.join();
        }
    }

    if (showMessage)
    {
        QMessageBox::information(
            this,
            QStringLiteral("释放全部 Oplock"),
            QStringLiteral("已释放 %1 个 Oplock，累计触发 %2 次，记录进程 %3 个，未捕获触发 %4 次。")
                .arg(entries.size())
                .arg(totalBreakCount)
                .arg(totalAccessProcessCount)
                .arg(totalUncapturedBreakCount));
    }
    if (!entries.empty())
    {
        kLogEvent event;
        info << event
            << "[FileDock] 释放全部 Oplock, count="
            << entries.size()
            << ", totalBreakCount="
            << totalBreakCount
            << ", totalAccessProcessCount="
            << totalAccessProcessCount
            << ", totalUncapturedBreakCount="
            << totalUncapturedBreakCount
            << eol;
    }
}

bool FileDock::hasActiveOplockForPath(const QString& filePath) const
{
    const QString normalizedPath = normalizeFileDockPath(filePath);
    std::lock_guard<std::mutex> lock(m_activeOplockMutex);
    return std::any_of(
        m_activeOplocks.begin(),
        m_activeOplocks.end(),
        [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr &&
                !entry->releaseRequested.load() &&
                pathEqualsCaseInsensitive(entry->path, normalizedPath);
        });
}

std::size_t FileDock::activeOplockCount() const
{
    std::lock_guard<std::mutex> lock(m_activeOplockMutex);
    return static_cast<std::size_t>(std::count_if(
        m_activeOplocks.begin(),
        m_activeOplocks.end(),
        [](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr && !entry->releaseRequested.load();
        }));
}

std::uint64_t FileDock::activeOplockBreakCountForPath(const QString& filePath) const
{
    const QString normalizedPath = normalizeFileDockPath(filePath);
    std::lock_guard<std::mutex> lock(m_activeOplockMutex);
    auto iterator = std::find_if(
        m_activeOplocks.begin(),
        m_activeOplocks.end(),
        [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
            return entry != nullptr &&
                !entry->releaseRequested.load() &&
                pathEqualsCaseInsensitive(entry->path, normalizedPath);
        });
    if (iterator == m_activeOplocks.end() || *iterator == nullptr)
    {
        return 0U;
    }
    return (*iterator)->breakCount.load();
}

std::size_t FileDock::activeOplockAccessProcessCountForPath(const QString& filePath) const
{
    const QString normalizedPath = normalizeFileDockPath(filePath);
    std::shared_ptr<FileOplockEntry> targetEntry;
    {
        std::lock_guard<std::mutex> lock(m_activeOplockMutex);
        auto iterator = std::find_if(
            m_activeOplocks.begin(),
            m_activeOplocks.end(),
            [&normalizedPath](const std::shared_ptr<FileOplockEntry>& entry) {
                return entry != nullptr &&
                    !entry->releaseRequested.load() &&
                    pathEqualsCaseInsensitive(entry->path, normalizedPath);
            });
        if (iterator != m_activeOplocks.end())
        {
            targetEntry = *iterator;
        }
    }
    if (targetEntry == nullptr)
    {
        return 0U;
    }

    std::lock_guard<std::mutex> lock(targetEntry->accessRecordMutex);
    return targetEntry->accessRecords.size();
}

void FileDock::handleOplockCompleted(
    std::shared_ptr<FileOplockEntry> entry,
    const bool completionOk,
    const unsigned long completionError,
    const bool acknowledgeOk,
    const unsigned long acknowledgeError,
    const std::size_t capturedProcessCount)
{
    if (entry == nullptr)
    {
        return;
    }

    const bool wasManualRelease = entry->releaseRequested.load();
    if (wasManualRelease)
    {
        return;
    }

    const QString stateText = oplockCompletionText(completionOk, completionError);
    const QString levelText = fileOplockLevelText(entry->level);
    const std::uint64_t breakCount = entry->breakCount.load();
    kLogEvent event;
    info << event
        << "[FileDock] Oplock 访问触发, path="
        << entry->path.toStdString()
        << ", level="
        << levelText.toStdString()
        << ", breakCount="
        << breakCount
        << ", completionOk="
        << (completionOk ? "true" : "false")
        << ", completionError="
        << completionError
        << ", state="
        << stateText.toStdString()
        << ", acknowledgeOk="
        << (acknowledgeOk ? "true" : "false")
        << ", acknowledgeError="
        << acknowledgeError
        << ", capturedProcessCount="
        << capturedProcessCount
        << ", activeCount="
        << activeOplockCount()
        << eol;
}

void FileDock::handleOplockRearmPending(
    std::shared_ptr<FileOplockEntry> entry,
    const unsigned long requestError)
{
    if (entry == nullptr || entry->releaseRequested.load())
    {
        return;
    }

    const QString levelText = fileOplockLevelText(entry->level);
    kLogEvent event;
    warn << event
        << "[FileDock] Oplock 触发后重新挂起暂时失败，将后台重试, path="
        << entry->path.toStdString()
        << ", level="
        << levelText.toStdString()
        << ", breakCount="
        << entry->breakCount.load()
        << ", requestError="
        << requestError
        << eol;
}

void FileDock::unlockPathsByDriver(
    const std::vector<QString>& targetPaths,
    const QString& triggerTag,
    FilePanelWidgets* panelForRefresh)
{
    std::vector<QString> paths;
    paths.reserve(targetPaths.size());
    for (const QString& path : targetPaths)
    {
        const QString normalizedPath = QDir::toNativeSeparators(path.trimmed());
        if (!normalizedPath.isEmpty())
        {
            paths.push_back(normalizedPath);
        }
    }
    if (paths.empty())
    {
        return;
    }

    // 旧解锁器入口直达文件属性的统一占用/解锁页。
    // 属性窗口关闭时通过共享取消标记使扫描回调安全失效。
    Q_UNUSED(triggerTag);
    Q_UNUSED(panelForRefresh);
    openHandleUsageScanWindow(paths);
    return;

    enum class RefreshTarget
    {
        Both = 0,
        Left,
        Right
    };
    const RefreshTarget refreshTarget =
        (panelForRefresh == &m_leftPanel) ? RefreshTarget::Left :
        (panelForRefresh == &m_rightPanel) ? RefreshTarget::Right :
        RefreshTarget::Both;

    QWidget* const dialogParent = resolveVisibleDialogParent(this);
    const QMessageBox::StandardButton scanChoice = QMessageBox::question(
        dialogParent,
        QStringLiteral("文件解锁器扫描确认"),
        QStringLiteral("将扫描选中路径的占用来源。扫描完成后可选择关闭句柄，或改用 R3/R0 结束进程兜底。\n是否开始扫描？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (scanChoice != QMessageBox::Yes)
    {
        return;
    }

    struct UnlockJobResult
    {
        bool scanCompleted = false;
        QStringList scanDetailList;
        std::vector<UnlockProcessCandidate> processCandidateList;
        std::vector<UnlockHandleCandidate> handleCandidateList;
        UnlockOperationMode operationMode = UnlockOperationMode::CloseHandleR3;
        std::vector<std::uint32_t> selectedProcessIdList;
        std::vector<UnlockHandleCandidate> selectedHandleList;
        std::size_t closeHandleSuccessCount = 0U;
        std::size_t terminateSuccessCount = 0U;
        QStringList operationFailList;
        QStringList skippedTargetList;
        QString driverErrorText;
    };

    {
        std::lock_guard<std::mutex> lock(m_unlockerWorkerMutex);
        if (m_unlockerWorkerRunning.load())
        {
            QMessageBox::information(dialogParent, QStringLiteral("文件解锁器"), QStringLiteral("已有解锁任务正在执行，请稍候。"));
            return;
        }
        if (m_unlockerWorkerThread.joinable())
        {
            m_unlockerWorkerThread.join();
        }
        m_unlockerWorkerStopRequested.store(false);
        m_unlockerWorkerRunning.store(true);
    }

    const int progressPid = kPro.add(this, "文件", "文件解锁器");
    kPro.set(progressPid, "准备扫描占用来源", 0, 5.0f);

    QPointer<FileDock> safeThis(this);
    {
        std::lock_guard<std::mutex> lock(m_unlockerWorkerMutex);
        m_unlockerWorkerThread = std::thread([safeThis, paths, triggerTag, refreshTarget, progressPid, this]() {
        UnlockJobResult jobResult;
        const auto markWorkerStopped = [this]() {
            this->m_unlockerWorkerRunning.store(false);
            };
        const auto stopRequested = [this]()
        {
            return this->m_unlockerWorkerStopRequested.load();
        };

        kPro.set(progressPid, "扫描占用来源", 0, 35.0f);
        const filedock::handleusage::HandleUsageScanResult scanResult =
            filedock::handleusage::scanHandleUsageByPaths(
                paths,
                progressPid,
                true,
                stopRequested);
        if (stopRequested())
        {
            kPro.set(progressPid, "用户取消", 0, 100.0f);
            markWorkerStopped();
            return;
        }
        jobResult.scanCompleted = true;
        jobResult.scanDetailList.push_back(
            QStringLiteral("matched=%1, elapsedMs=%2, diagnostic=%3")
            .arg(scanResult.matchedHandleCount)
            .arg(scanResult.elapsedMs)
            .arg(scanResult.diagnosticText.trimmed().isEmpty()
                ? QStringLiteral("-")
                : scanResult.diagnosticText.simplified()));

        std::map<std::uint32_t, UnlockProcessCandidate> candidateByPid;
        const std::uint32_t currentProcessId = static_cast<std::uint32_t>(::GetCurrentProcessId());
        for (const filedock::handleusage::HandleUsageEntry& entry : scanResult.entries)
        {
            if (stopRequested())
            {
                kPro.set(progressPid, "用户取消", 0, 100.0f);
                markWorkerStopped();
                return;
            }
            if (entry.processId == 0U)
            {
                continue;
            }

            UnlockProcessCandidate& processCandidate = candidateByPid[entry.processId];
            processCandidate.processId = entry.processId;
            if (processCandidate.matchCount == 0U)
            {
                processCandidate.processCreationTime = entry.processCreationTime;
            }
            else if (processCandidate.processCreationTime != entry.processCreationTime)
            {
                // 同一轮扫描中 PID 身份不一致说明进程已退出/复用；清零使后续动作失败关闭。
                processCandidate.processCreationTime = 0U;
            }
            if (processCandidate.processName.isEmpty() && !entry.processName.trimmed().isEmpty())
            {
                processCandidate.processName = entry.processName.trimmed();
            }
            if (processCandidate.processImagePath.isEmpty() && !entry.processImagePath.trimmed().isEmpty())
            {
                processCandidate.processImagePath = entry.processImagePath.trimmed();
            }
            appendUniqueText(processCandidate.matchedTargetList, entry.matchedTargetPath);
            appendUniqueText(processCandidate.matchRuleList, entry.matchRuleText);
            processCandidate.matchCount += 1U;
            processCandidate.isCurrentProcess = entry.processId == currentProcessId;
            processCandidate.isCriticalProcess = entry.processId <= 4U || isCriticalProcessName(processCandidate.processName);

            UnlockHandleCandidate handleCandidate{};
            handleCandidate.processId = entry.processId;
            handleCandidate.processCreationTime = entry.processCreationTime;
            handleCandidate.processName = entry.processName.trimmed();
            handleCandidate.processImagePath = entry.processImagePath.trimmed();
            handleCandidate.handleValue = entry.handleValue;
            handleCandidate.grantedAccess = entry.grantedAccess;
            handleCandidate.matchedTargetPath = entry.matchedTargetPath;
            handleCandidate.matchedByDirectoryRule = entry.matchedByDirectoryRule;
            handleCandidate.matchRuleText = entry.matchRuleText;
            handleCandidate.objectName = entry.objectName;
            handleCandidate.enumerationSource = entry.enumerationSource;
            handleCandidate.isCurrentProcess = processCandidate.isCurrentProcess;
            handleCandidate.isCriticalProcess = processCandidate.isCriticalProcess;
            jobResult.handleCandidateList.push_back(handleCandidate);
        }

        jobResult.processCandidateList.reserve(candidateByPid.size());
        for (const auto& entry : candidateByPid)
        {
            if (stopRequested())
            {
                kPro.set(progressPid, "用户取消", 0, 100.0f);
                markWorkerStopped();
                return;
            }
            jobResult.processCandidateList.push_back(entry.second);
        }

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        UnlockSelectionResult selectionResult;
        const std::shared_ptr<UnlockSelectionSharedState> selectionState =
            std::make_shared<UnlockSelectionSharedState>();
        const bool selectionInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [selectionState, safeThis, progressPid, jobResult]() {
                QWidget* const unlockerDialogParent = resolveVisibleDialogParent(safeThis.data());
                UnlockSelectionResult uiSelectionResult;
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                }
                else if (jobResult.processCandidateList.empty() && jobResult.handleCandidateList.empty())
                {
                    QMessageBox::information(
                        unlockerDialogParent,
                        QStringLiteral("文件解锁器"),
                        QStringLiteral("未发现占用来源，无需解锁。"));
                    kPro.set(progressPid, "未发现占用来源", 0, 100.0f);
                }
                else
                {
                    uiSelectionResult = showUnlockSelectionDialog(
                        unlockerDialogParent,
                        jobResult.processCandidateList,
                        jobResult.handleCandidateList);
                }

                {
                    std::lock_guard<std::mutex> lock(selectionState->mutex);
                    selectionState->result = uiSelectionResult;
                    selectionState->completed = true;
                }

                selectionState->condition.notify_all();
            },
            Qt::QueuedConnection);
        if (!selectionInvokeOk)
        {
            kPro.set(progressPid, "回调失败", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        {
            std::unique_lock<std::mutex> lock(selectionState->mutex);
            while (!selectionState->completed)
            {
                if (safeThis.isNull() || this->m_unlockerWorkerStopRequested.load())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    markWorkerStopped();
                    return;
                }

                selectionState->condition.wait_for(lock, std::chrono::milliseconds(100));
            }

            selectionResult = selectionState->result;
        }

        const bool noSelectedHandle = selectionResult.selectedHandleList.empty();
        const bool noSelectedProcess = selectionResult.selectedProcessIdList.empty();
        if (!selectionResult.accepted
            || (selectionResult.operationMode == UnlockOperationMode::CloseHandleR3 && noSelectedHandle)
            || (selectionResult.operationMode != UnlockOperationMode::CloseHandleR3 && noSelectedProcess))
        {
            kPro.set(progressPid, "用户取消", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        jobResult.operationMode = selectionResult.operationMode;
        jobResult.selectedHandleList = selectionResult.selectedHandleList;
        jobResult.selectedProcessIdList = selectionResult.selectedProcessIdList;
        kPro.set(progressPid, unlockOperationModeToText(jobResult.operationMode).toStdString(), 0, 55.0f);

        if (jobResult.operationMode == UnlockOperationMode::CloseHandleR3)
        {
            const std::size_t totalHandleCount = jobResult.selectedHandleList.size();
            for (std::size_t index = 0; index < totalHandleCount; ++index)
            {
                if (safeThis.isNull() || this->m_unlockerWorkerStopRequested.load())
                {
                    break;
                }

                const UnlockHandleCandidate& handleCandidate = jobResult.selectedHandleList[index];
                if (handleCandidate.processId <= 4U
                    || handleCandidate.handleValue == 0U
                    || handleCandidate.isCurrentProcess
                    || handleCandidate.isCriticalProcess)
                {
                    jobResult.skippedTargetList.push_back(
                        QStringLiteral("pid=%1 | handle=%2 | %3 | 已保护或无效，未关闭")
                        .arg(handleCandidate.processId)
                        .arg(formatHandleValueText(handleCandidate.handleValue))
                        .arg(handleCandidate.processName.isEmpty() ? QStringLiteral("Unknown") : handleCandidate.processName));
                    continue;
                }

                std::string detailText;
                const bool closeOk = ks::file::CloseRemoteHandle(
                    handleCandidate.processId,
                    handleCandidate.handleValue,
                    handleCandidate.processCreationTime,
                    handleCandidate.matchedTargetPath.toStdWString(),
                    handleCandidate.matchedByDirectoryRule,
                    detailText);
                if (closeOk)
                {
                    jobResult.closeHandleSuccessCount += 1U;
                }
                else
                {
                    jobResult.operationFailList.push_back(
                        QStringLiteral("pid=%1 | handle=%2 | %3 | %4")
                        .arg(handleCandidate.processId)
                        .arg(formatHandleValueText(handleCandidate.handleValue))
                        .arg(handleCandidate.processName.isEmpty() ? QStringLiteral("Unknown") : handleCandidate.processName)
                        .arg(QString::fromStdString(detailText)));
                }

                const float progress =
                    55.0f + (static_cast<float>(index + 1) / static_cast<float>(totalHandleCount)) * 40.0f;
                kPro.set(progressPid, "关闭选中句柄", 0, progress);
            }
        }
        else
        {
            ksword::ark::DriverHandle driverHandle;
            if (jobResult.operationMode == UnlockOperationMode::TerminateProcessR0)
            {
                std::string openDriverDetailText;
                driverHandle = openKswordArkDriverHandle(&openDriverDetailText);
                if (!driverHandle.isValid())
                {
                    jobResult.driverErrorText = QString::fromStdString(openDriverDetailText);
                }
            }

            std::map<std::uint32_t, UnlockProcessCandidate> candidateBySelectedPid;
            for (const UnlockProcessCandidate& candidate : jobResult.processCandidateList)
            {
                candidateBySelectedPid[candidate.processId] = candidate;
            }

            if (jobResult.operationMode == UnlockOperationMode::TerminateProcessR0
                && !driverHandle.isValid())
            {
                jobResult.operationFailList.push_back(
                    QStringLiteral("R0 驱动连接失败：%1")
                    .arg(jobResult.driverErrorText));
            }
            else
            {
                const std::size_t totalProcessCount = jobResult.selectedProcessIdList.size();
                for (std::size_t index = 0; index < totalProcessCount; ++index)
                {
                    if (safeThis.isNull() || this->m_unlockerWorkerStopRequested.load())
                    {
                        break;
                    }

                    const std::uint32_t processId = jobResult.selectedProcessIdList[index];
                    const auto candidateIter = candidateBySelectedPid.find(processId);
                    const QString processName = (candidateIter != candidateBySelectedPid.end())
                        ? candidateIter->second.processName
                        : QString();
                    const std::uint64_t processCreationTime = (candidateIter != candidateBySelectedPid.end())
                        ? candidateIter->second.processCreationTime
                        : 0U;
                    const bool protectedProcess = candidateIter != candidateBySelectedPid.end()
                        && (candidateIter->second.isCurrentProcess
                            || candidateIter->second.isCriticalProcess
                            || candidateIter->second.processCreationTime == 0U);
                    if (processId <= 4U
                        || processId == static_cast<std::uint32_t>(::GetCurrentProcessId())
                        || protectedProcess
                        || processCreationTime == 0U)
                    {
                        jobResult.skippedTargetList.push_back(
                            QStringLiteral("pid=%1 | %2 | 已保护，未结束")
                            .arg(processId)
                            .arg(processName.isEmpty() ? QStringLiteral("Unknown") : processName));
                        continue;
                    }

                    std::string detailText;
                    bool terminateOk = false;
                    if (jobResult.operationMode == UnlockOperationMode::TerminateProcessR0)
                    {
                        // 即使由驱动执行结束，也先持有已核对创建时间的 R3 进程句柄；
                        // 这样驱动按 PID 查询期间不会命中复用后的另一个进程对象。
                        HANDLE verifiedProcessHandle = nullptr;
                        if (ks::file::OpenProcessForVerifiedAction(
                                processId,
                                processCreationTime,
                                SYNCHRONIZE,
                                verifiedProcessHandle,
                                detailText))
                        {
                            terminateOk = terminateProcessByR0Driver(driverHandle, processId, &detailText);
                            ::CloseHandle(verifiedProcessHandle);
                        }
                    }
                    else
                    {
                        terminateOk = terminateProcessByR3(
                            processId,
                            processCreationTime,
                            &detailText);
                    }
                    if (terminateOk)
                    {
                        jobResult.terminateSuccessCount += 1U;
                    }
                    else
                    {
                        jobResult.operationFailList.push_back(
                            QStringLiteral("pid=%1 | %2 | %3")
                            .arg(processId)
                            .arg(processName.isEmpty() ? QStringLiteral("Unknown") : processName)
                            .arg(QString::fromStdString(detailText)));
                    }

                    const float progress =
                        55.0f + (static_cast<float>(index + 1) / static_cast<float>(totalProcessCount)) * 40.0f;
                    kPro.set(progressPid, "结束选中进程", 0, progress);
                }
            }

            driverHandle.reset();
        }

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            markWorkerStopped();
            return;
        }

        const bool finishInvokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, triggerTag, refreshTarget, progressPid, jobResult, paths, markWorkerStopped]() {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }
                QWidget* const unlockerDialogParent = resolveVisibleDialogParent(safeThis.data());

                QList<QAbstractItemView*> affectedViews;
                if (refreshTarget == RefreshTarget::Left)
                {
                    affectedViews.push_back(safeThis->m_leftPanel.fileView);
                }
                else if (refreshTarget == RefreshTarget::Right)
                {
                    affectedViews.push_back(safeThis->m_rightPanel.fileView);
                }
                else
                {
                    affectedViews.push_back(safeThis->m_leftPanel.fileView);
                    affectedViews.push_back(safeThis->m_rightPanel.fileView);
                }
                const auto refreshPanels = [safeThis, refreshTarget]()
                {
                    if (safeThis.isNull())
                    {
                        return;
                    }
                    if (refreshTarget == RefreshTarget::Left)
                    {
                        safeThis->refreshPanel(safeThis->m_leftPanel);
                    }
                    else if (refreshTarget == RefreshTarget::Right)
                    {
                        safeThis->refreshPanel(safeThis->m_rightPanel);
                    }
                    else
                    {
                        safeThis->refreshPanel(safeThis->m_leftPanel);
                        safeThis->refreshPanel(safeThis->m_rightPanel);
                    }
                };
                const QString refreshKey =
                    refreshTarget == RefreshTarget::Left
                    ? QStringLiteral("file-unlocker-panel-refresh-left")
                    : (refreshTarget == RefreshTarget::Right
                        ? QStringLiteral("file-unlocker-panel-refresh-right")
                        : QStringLiteral("file-unlocker-panel-refresh-both"));
                if (!ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    refreshKey,
                    affectedViews,
                    refreshPanels))
                {
                    refreshPanels();
                }

                const QString modeText = unlockOperationModeToText(jobResult.operationMode);
                const std::size_t selectedCount = (jobResult.operationMode == UnlockOperationMode::CloseHandleR3)
                    ? jobResult.selectedHandleList.size()
                    : jobResult.selectedProcessIdList.size();
                const std::size_t successCount = (jobResult.operationMode == UnlockOperationMode::CloseHandleR3)
                    ? jobResult.closeHandleSuccessCount
                    : jobResult.terminateSuccessCount;
                const QString summaryText = QStringLiteral("操作方式：%1\n扫描到占用进程：%2\n扫描到句柄记录：%3\n选中目标：%4\n成功处理：%5\n失败/跳过：%6")
                    .arg(modeText)
                    .arg(jobResult.processCandidateList.size())
                    .arg(jobResult.handleCandidateList.size())
                    .arg(selectedCount)
                    .arg(successCount)
                    .arg(jobResult.operationFailList.size() + jobResult.skippedTargetList.size());
                if (jobResult.operationFailList.isEmpty() && jobResult.skippedTargetList.isEmpty())
                {
                    QMessageBox::information(
                        unlockerDialogParent,
                        QStringLiteral("文件解锁器"),
                        summaryText);
                }
                else
                {
                    const QString failurePreview = buildLogPreviewText(jobResult.operationFailList + jobResult.skippedTargetList, 8);
                    // privilegePromptHandled：恢复提示已解释失败时不再显示汇总警告框。
                    const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                        unlockerDialogParent,
                        QStringLiteral("文件解锁器"),
                        failurePreview);
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::warning(
                            unlockerDialogParent,
                            QStringLiteral("文件解锁器"),
                            summaryText + QStringLiteral("\n\n明细（节选）：\n%1")
                            .arg(buildLogPreviewText(jobResult.operationFailList + jobResult.skippedTargetList, 8)));
                    }
                }

                kLogEvent event;
                if (!jobResult.operationFailList.isEmpty() || !jobResult.skippedTargetList.isEmpty())
                {
                    warn << event
                        << "[FileDock] 文件解锁器部分失败, panel="
                        << triggerTag.toStdString()
                        << ", mode="
                        << modeText.toStdString()
                        << ", targetCount="
                        << paths.size()
                        << ", occupyProcessCount="
                        << jobResult.processCandidateList.size()
                        << ", handleRecordCount="
                        << jobResult.handleCandidateList.size()
                        << ", selectedCount="
                        << selectedCount
                        << ", successCount="
                        << successCount
                        << ", failCount="
                        << (jobResult.operationFailList.size() + jobResult.skippedTargetList.size())
                        << ", scanPreview=\n"
                        << buildLogPreviewText(jobResult.scanDetailList).toStdString()
                        << ", failPreview=\n"
                        << buildLogPreviewText(jobResult.operationFailList + jobResult.skippedTargetList).toStdString()
                        << eol;
                }
                else
                {
                    info << event
                        << "[FileDock] 文件解锁器完成, panel="
                        << triggerTag.toStdString()
                        << ", mode="
                        << modeText.toStdString()
                        << ", targetCount="
                        << paths.size()
                        << ", occupyProcessCount="
                        << jobResult.processCandidateList.size()
                        << ", handleRecordCount="
                        << jobResult.handleCandidateList.size()
                        << ", selectedCount="
                        << selectedCount
                        << ", successCount="
                        << successCount
                        << eol;
                }

                kPro.set(progressPid, "文件解锁器完成", 0, 100.0f);
                markWorkerStopped();
            },
            Qt::QueuedConnection);
        if (!finishInvokeOk)
        {
            kPro.set(progressPid, "回调失败", 0, 100.0f);
            markWorkerStopped();
        }
        });
    }
}

void FileDock::unlockFileByPath(const QString& targetPath)
{
    const QString normalizedPath = QDir::toNativeSeparators(targetPath.trimmed());
    if (normalizedPath.isEmpty())
    {
        return;
    }

    unlockPathsByDriver(std::vector<QString>{ normalizedPath }, QStringLiteral("system_context_menu"), nullptr);
}

void FileDock::takeOwnershipSelectedItems(FilePanelWidgets& panel)
{
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("取得文件所有权并授予完全控制"));
        return;
    }

    kLogEvent startEvent;
    info << startEvent
        << "[FileDock] 取得所有权请求, panel="
        << panel.panelNameText.toStdString()
        << ", count="
        << paths.size()
        << eol;

    const QMessageBox::StandardButton userChoice = QMessageBox::question(
        this,
        QStringLiteral("取得所有权"),
        QStringLiteral("将对选中的 %1 项执行“取得所有权 + 完全控制授权”。\n此操作可能需要管理员权限，是否继续？")
        .arg(paths.size()),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (userChoice != QMessageBox::Yes)
    {
        return;
    }

    const int progressPid = kPro.add(this, "文件", "取得所有权");
    kPro.set(progressPid, "准备执行", 0, 5.0f);

    const bool leftPanelRequest = (&panel == &m_leftPanel);
    const QString panelNameText = panel.panelNameText;
    QPointer<FileDock> safeThis(this);
    std::thread([safeThis, paths, progressPid, leftPanelRequest, panelNameText]()
    {
        QStringList errorDetails;
        for (std::size_t index = 0; index < paths.size(); ++index)
        {
            const QString& targetPath = paths[index];
            QString detailText;
            const bool itemOk = takeOwnershipBySystemCommand(targetPath, detailText);
            if (!itemOk)
            {
                errorDetails.push_back(detailText);
            }

            const float progress = 5.0f + (static_cast<float>(index + 1) / static_cast<float>(paths.size())) * 90.0f;
            kPro.set(progressPid, "处理中", 0, progress);
        }
        kPro.set(progressPid, "完成", 0, 100.0f);

        if (safeThis.isNull())
        {
            kPro.set(progressPid, "界面已关闭", 0, 100.0f);
            return;
        }

        const bool invokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, progressPid, leftPanelRequest, panelNameText, paths, errorDetails]()
            {
                if (safeThis.isNull())
                {
                    kPro.set(progressPid, "界面已关闭", 0, 100.0f);
                    return;
                }

                FilePanelWidgets& targetPanel = leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                const auto refreshTargetPanel = [safeThis, leftPanelRequest]()
                {
                    if (!safeThis.isNull())
                    {
                        FilePanelWidgets& commitPanel =
                            leftPanelRequest ? safeThis->m_leftPanel : safeThis->m_rightPanel;
                        safeThis->refreshPanel(commitPanel);
                    }
                };
                const QString refreshKey = leftPanelRequest
                    ? QStringLiteral("file-ownership-refresh-left")
                    : QStringLiteral("file-ownership-refresh-right");
                if (!ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                    safeThis.data(),
                    refreshKey,
                    { targetPanel.fileView },
                    refreshTargetPanel))
                {
                    refreshTargetPanel();
                }
                if (!errorDetails.isEmpty())
                {
                    kLogEvent failEvent;
                    warn << failEvent
                        << "[FileDock] 取得所有权部分失败, panel="
                        << panelNameText.toStdString()
                        << ", failCount="
                        << errorDetails.size()
                        << ", detailPreview=\n"
                        << buildLogPreviewText(errorDetails).toStdString()
                        << eol;
                    return;
                }

                kLogEvent finishEvent;
                info << finishEvent
                    << "[FileDock] 取得所有权完成, panel="
                    << panelNameText.toStdString()
                    << ", successCount="
                    << paths.size()
                    << eol;
            },
            Qt::QueuedConnection);
        if (!invokeOk)
        {
            kPro.set(progressPid, "回调失败", 0, 100.0f);
        }
    }).detach();
}

void FileDock::setSelectedFileIntegrityLevel(
    FilePanelWidgets& panel,
    const unsigned long integrityRid,
    const QString& levelDisplayText)
{
    // 输入：当前面板选中项、目标完整性 RID 和显示文本。
    // 处理：逐个先调用 R0 内核 API 写入 LABEL_SECURITY_INFORMATION，驱动不可用/旧驱动时回退 R3，并汇总失败项。
    // 返回：无返回值；成功/失败通过日志、进度条和消息框反馈。
    const std::vector<QString> paths = selectedPaths(panel);
    if (paths.empty())
    {
        kLogEvent emptyEvent;
        warn << emptyEvent
            << "[FileDock] 设置文件完整性被忽略：未选中路径, panel="
            << panel.panelNameText.toStdString()
            << eol;
        return;
    }

    const QMessageBox::StandardButton userChoice = QMessageBox::question(
        this,
        QStringLiteral("设置文件完整性"),
        QStringLiteral("将对选中的 %1 项写入文件 Mandatory Label：%2。\n"
            "该操作会影响低/中/高完整性进程对对象的写入权限，可能需要管理员权限。是否继续？")
            .arg(paths.size())
            .arg(levelDisplayText),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (userChoice != QMessageBox::Yes)
    {
        return;
    }

    const DWORD targetIntegrityRid = static_cast<DWORD>(integrityRid);
    const int progressPid = kPro.add(this, "文件", "设置文件完整性");
    kPro.set(progressPid, "准备执行", 0, 5.0f);

    QStringList failureDetails;
    std::size_t successCount = 0U;
    // privilegePromptHandled：多个目标失败时最多展示一次权限恢复提示，并抑制最终重复弹窗。
    bool privilegePromptHandled = false;
    for (std::size_t index = 0; index < paths.size(); ++index)
    {
        const QString& targetPath = paths[index];
        QString detailText;
        const DWORD result = setFileIntegrityLevelByR0ThenR3(
            targetPath,
            targetIntegrityRid,
            &detailText);
        if (result == ERROR_SUCCESS)
        {
            successCount += 1U;
            kLogEvent itemEvent;
            info << itemEvent
                << "[FileDock] 设置文件完整性成功, panel="
                << panel.panelNameText.toStdString()
                << ", path="
                << QDir::toNativeSeparators(targetPath).toStdString()
                << ", rid=0x"
                << QString::number(targetIntegrityRid, 16).toStdString()
                << ", detail="
                << detailText.toStdString()
                << eol;
        }
        else
        {
            if (!privilegePromptHandled)
            {
                privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("设置文件完整性级别"),
                    result);
            }
            failureDetails.push_back(QStringLiteral("%1 | code=%2 | %3")
                .arg(QDir::toNativeSeparators(targetPath))
                .arg(result)
                .arg(detailText));
        }

        const float progress = 5.0f + (static_cast<float>(index + 1) / static_cast<float>(paths.size())) * 90.0f;
        kPro.set(progressPid, "处理中", 0, progress);
    }

    refreshPanel(panel);
    kPro.set(progressPid, "完成", 0, 100.0f);

    const QString summaryText = QStringLiteral("文件完整性设置完成：成功 %1，失败 %2，目标=%3。")
        .arg(successCount)
        .arg(failureDetails.size())
        .arg(levelDisplayText);
    if (!failureDetails.isEmpty())
    {
        kLogEvent failEvent;
        warn << failEvent
            << "[FileDock] 设置文件完整性部分失败, panel="
            << panel.panelNameText.toStdString()
            << ", successCount="
            << successCount
            << ", failCount="
            << failureDetails.size()
            << ", detailPreview=\n"
            << buildLogPreviewText(failureDetails).toStdString()
            << eol;
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("设置文件完整性"),
                summaryText + QStringLiteral("\n\n失败明细：\n") + failureDetails.join('\n'));
        }
        return;
    }

    kLogEvent finishEvent;
    info << finishEvent
        << "[FileDock] 设置文件完整性完成, panel="
        << panel.panelNameText.toStdString()
        << ", successCount="
        << successCount
        << ", target="
        << levelDisplayText.toStdString()
        << eol;
    QMessageBox::information(this, QStringLiteral("设置文件完整性"), summaryText);
}

void FileDock::showColumnManagerDialog(FilePanelWidgets& panel)
{
    {
        kLogEvent event;
        info << event
            << "[FileDock] 打开列管理器, panel="
            << panel.panelNameText.toStdString()
            << eol;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("列管理器"));
    dialog.resize(340, 260);

    QVBoxLayout* rootLayout = new QVBoxLayout(&dialog);
    QLabel* tipLabel = new QLabel(QStringLiteral("勾选表示显示该列，可拖拽表头调整顺序。"), &dialog);
    tipLabel->setWordWrap(true);
    rootLayout->addWidget(tipLabel, 0);

    const bool manualMode = currentModeIsManual(panel);
    const int columnCount = manualMode
        ? (panel.manualModel == nullptr ? 0 : panel.manualModel->columnCount())
        : (panel.fsModel == nullptr ? 0 : panel.fsModel->columnCount());
    std::vector<QCheckBox*> columnChecks;
    columnChecks.reserve(static_cast<std::size_t>(columnCount));
    for (int column = 0; column < columnCount; ++column)
    {
        const QString columnName = manualMode
            ? panel.manualModel->headerData(column, Qt::Horizontal).toString()
            : panel.fsModel->headerData(column, Qt::Horizontal).toString();
        QCheckBox* checkBox = new QCheckBox(columnName, &dialog);
        checkBox->setChecked(!panel.fileView->isColumnHidden(column));
        checkBox->setToolTip(QStringLiteral("切换列“%1”显示状态").arg(columnName));
        rootLayout->addWidget(checkBox, 0);
        columnChecks.push_back(checkBox);
    }
    rootLayout->addStretch(1);

    QDialogButtonBox* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &dialog);
    rootLayout->addWidget(buttonBox, 0);
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);

    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    for (int column = 0; column < static_cast<int>(columnChecks.size()); ++column)
    {
        const bool visible = columnChecks[static_cast<std::size_t>(column)]->isChecked();
        panel.fileView->setColumnHidden(column, !visible);
    }

    kLogEvent event;
    info << event
        << "[FileDock] 列管理器应用完成, panel="
        << panel.panelNameText.toStdString()
        << eol;
}

void FileDock::showFileDetailDialog(const QString& filePath, const QString& initialTabKey)
{
    showFileDetailDialog(QStringList{ filePath }, initialTabKey);
}

void FileDock::showFileDetailDialog(const QStringList& filePaths, const QString& initialTabKey)
{
    QStringList existingPaths;
    QSet<QString> seenPaths;
    for (const QString& candidatePath : filePaths)
    {
        const QString normalizedPath = QDir::cleanPath(
            QDir::toNativeSeparators(candidatePath.trimmed()));
        const QString identityKey = normalizedPath.toLower();
        if (!normalizedPath.isEmpty() && !seenPaths.contains(identityKey) &&
            QFileInfo::exists(normalizedPath))
        {
            seenPaths.insert(identityKey);
            existingPaths.push_back(normalizedPath);
        }
    }
    if (existingPaths.isEmpty())
    {
        kLogEvent event;
        warn << event << "[FileDock] 打开文件详情失败：没有可访问目标" << eol;
        return;
    }

    FileDetailDialog* dialog = new FileDetailDialog(existingPaths, this, initialTabKey);
    dialog->setWindowFlag(Qt::WindowStaysOnTopHint, false);
    dialog->show();
    dialog->raise();
    dialog->activateWindow();

    kLogEvent event;
    info << event
        << "[FileDock] 打开文件详情窗口, targetCount="
        << existingPaths.size()
        << eol;
}

void FileDock::openFileDetailByPath(const QString& filePath)
{
    showFileDetailDialog(filePath);
}

QString FileDock::currentIndexPath(const FilePanelWidgets& panel) const
{
    if (panel.fileView == nullptr)
    {
        return QString();
    }

    const QModelIndex proxyIndex = panel.fileView->currentIndex();
    if (!proxyIndex.isValid())
    {
        return QString();
    }

    if (currentModeIsManual(panel))
    {
        if (panel.manualProxyModel == nullptr || panel.manualModel == nullptr)
        {
            return QString();
        }

        const QModelIndex sourceIndex = panel.manualProxyModel->mapToSource(proxyIndex);
        if (!sourceIndex.isValid())
        {
            return QString();
        }

        const QStandardItem* fullPathItem = panel.manualModel->item(
            sourceIndex.row(),
            static_cast<int>(ManualModelColumn::FullPath));
        if (fullPathItem == nullptr)
        {
            return QString();
        }
        return fullPathItem->text();
    }

    if (panel.proxyModel == nullptr || panel.fsModel == nullptr)
    {
        return QString();
    }
    const QModelIndex sourceIndex = panel.proxyModel->mapToSource(proxyIndex);
    return sourceIndex.isValid() ? panel.fsModel->filePath(sourceIndex) : QString();
}

std::vector<QString> FileDock::selectedPaths(const FilePanelWidgets& panel) const
{
    std::vector<QString> result;
    if (panel.fileView == nullptr || panel.fileView->selectionModel() == nullptr)
    {
        return result;
    }

    const QModelIndexList selectedRows = panel.fileView->selectionModel()->selectedRows(0);
    result.reserve(static_cast<std::size_t>(selectedRows.size()));

    if (currentModeIsManual(panel))
    {
        if (panel.manualProxyModel == nullptr || panel.manualModel == nullptr)
        {
            return result;
        }
        for (const QModelIndex& proxyIndex : selectedRows)
        {
            const QModelIndex sourceIndex = panel.manualProxyModel->mapToSource(proxyIndex);
            if (!sourceIndex.isValid())
            {
                continue;
            }
            const QStandardItem* fullPathItem = panel.manualModel->item(
                sourceIndex.row(),
                static_cast<int>(ManualModelColumn::FullPath));
            if (fullPathItem == nullptr)
            {
                continue;
            }
            const QString pathText = fullPathItem->text();
            if (pathText.isEmpty())
            {
                continue;
            }
            if (std::find(result.begin(), result.end(), pathText) == result.end())
            {
                result.push_back(pathText);
            }
        }
    }
    else
    {
        if (panel.proxyModel == nullptr || panel.fsModel == nullptr)
        {
            return result;
        }
        for (const QModelIndex& proxyIndex : selectedRows)
        {
            const QModelIndex sourceIndex = panel.proxyModel->mapToSource(proxyIndex);
            if (!sourceIndex.isValid())
            {
                continue;
            }
            const QString path = panel.fsModel->filePath(sourceIndex);
            if (path.isEmpty())
            {
                continue;
            }
            if (std::find(result.begin(), result.end(), path) == result.end())
            {
                result.push_back(path);
            }
        }
    }

    // 如果多选为空但存在当前行，回退为当前行路径，便于右键单项操作。
    if (result.empty())
    {
        const QString currentPath = currentIndexPath(panel);
        if (!currentPath.isEmpty())
        {
            result.push_back(currentPath);
        }
    }
    return result;
}

QString FileDock::formatSizeText(std::uint64_t sizeBytes)
{
    static const std::array<const char*, 5> units{ "B", "KB", "MB", "GB", "TB" };
    double value = static_cast<double>(sizeBytes);
    std::size_t unitIndex = 0;
    while (value >= 1024.0 && (unitIndex + 1) < units.size())
    {
        value /= 1024.0;
        ++unitIndex;
    }

    if (unitIndex == 0)
    {
        return QStringLiteral("%1 %2").arg(static_cast<qulonglong>(sizeBytes)).arg(units[unitIndex]);
    }
    return QStringLiteral("%1 %2").arg(QString::number(value, 'f', 2)).arg(units[unitIndex]);
}
