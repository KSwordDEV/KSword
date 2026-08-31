#include "KernelDock.h"
#include "../UI/TableInteractionSupport.h"

#include <memory>
#include "../UI/VisibleTableWidget.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../FileDock/FilePropertyPeAnalyzer.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/DetailLayoutHost.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QHash>
#include <QIcon>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QList>
#include <QMenu>
#include <QMetaObject>
#include <QMessageBox>
#include <QPoint>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QStringList>
#include <QSplitter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "Version.lib")

using ksword::kernel_dock_internal::kernelText;

namespace
{
    struct CallbackEnumVersionText
    {
        QString company;
        QString fileVersion;
        QString description;
    };

    QString callbackEnumQueryVersionString(const QString& filePath, const wchar_t* valueName)
    {
        // 作用：读取驱动版本资源中的 CompanyName/FileVersion/FileDescription。
        // 返回：首个匹配翻译表的值；资源缺失时返回空字符串。
        DWORD ignoredHandle = 0;
        const std::wstring nativePath = QDir::toNativeSeparators(filePath).toStdWString();
        const DWORD versionBytes = ::GetFileVersionInfoSizeW(nativePath.c_str(), &ignoredHandle);
        if (versionBytes == 0U || valueName == nullptr)
        {
            return QString();
        }

        std::vector<unsigned char> versionBuffer(versionBytes);
        if (::GetFileVersionInfoW(nativePath.c_str(), 0, versionBytes, versionBuffer.data()) == FALSE)
        {
            return QString();
        }

        struct LanguageAndCodePage
        {
            WORD language;
            WORD codePage;
        };
        LanguageAndCodePage* translations = nullptr;
        UINT translationBytes = 0;
        std::vector<LanguageAndCodePage> candidates;
        if (::VerQueryValueW(
                versionBuffer.data(),
                L"\\VarFileInfo\\Translation",
                reinterpret_cast<void**>(&translations),
                &translationBytes) != FALSE
            && translations != nullptr
            && translationBytes >= sizeof(LanguageAndCodePage))
        {
            const std::size_t translationCount = translationBytes / sizeof(LanguageAndCodePage);
            candidates.assign(translations, translations + translationCount);
        }
        candidates.push_back({ 0x0409, 0x04B0 });
        candidates.push_back({ 0x0000, 0x04B0 });

        for (const LanguageAndCodePage& candidate : candidates)
        {
            const QString queryPath = QStringLiteral("\\StringFileInfo\\%1%2\\%3")
                .arg(candidate.language, 4, 16, QLatin1Char('0'))
                .arg(candidate.codePage, 4, 16, QLatin1Char('0'))
                .arg(QString::fromWCharArray(valueName));
            wchar_t* valueText = nullptr;
            UINT valueChars = 0;
            if (::VerQueryValueW(
                    versionBuffer.data(),
                    reinterpret_cast<LPCWSTR>(queryPath.utf16()),
                    reinterpret_cast<void**>(&valueText),
                    &valueChars) != FALSE
                && valueText != nullptr
                && valueChars != 0U)
            {
                return QString::fromWCharArray(valueText, static_cast<int>(valueChars - 1U)).trimmed();
            }
        }
        return QString();
    }

    CallbackEnumVersionText callbackEnumQueryVersionText(const QString& filePath)
    {
        // 作用：一次性读取任意回调模块的公司、文件版本与文件描述。
        // 返回：允许字段分别为空的版本文本。
        CallbackEnumVersionText result;
        result.company = callbackEnumQueryVersionString(filePath, L"CompanyName");
        result.fileVersion = callbackEnumQueryVersionString(filePath, L"FileVersion");
        result.description = callbackEnumQueryVersionString(filePath, L"FileDescription");
        return result;
    }

    QString callbackEnumButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString callbackEnumInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:2px;background:transparent;/* %3 */color:%4;padding:2px 6px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    QString callbackEnumHeaderStyle()
    {
        return QStringLiteral(
            "QHeaderView::section{color:%1;background:transparent;/* %2 */border:1px solid %3;font-weight:600;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::BorderHex());
    }

    QString callbackEnumSelectionStyle()
    {
        return QString();
    }

    QString callbackEnumStatusLabelStyle(const QString& colorHex)
    {
        return QStringLiteral("color:%1;font-weight:600;").arg(colorHex);
    }

    // callbackEnumStatusNotSupported：
    // - 作用：为 user-mode 编译单元提供与 NTSTATUS 一致的“不支持”返回值；
    // - 输入：无；
    // - 返回：STATUS_NOT_SUPPORTED 的等价 long 常量，避免当前文件依赖额外 ntstatus 头。
    constexpr long callbackEnumStatusNotSupported()
    {
        return static_cast<long>(0xC00000BBL);
    }

    QString callbackEnumSafeText(
        const QString& valueText,
        const QString& fallbackText = kernelText("kernel.callback.enum.placeholder.empty", QStringLiteral("<空>")))
    {
        return valueText.trimmed().isEmpty() ? fallbackText : valueText;
    }

    // callbackEnumIoMessageText：
    // - 输入：ArkDriverClient 返回的原始 message 文本；
    // - 处理：把 DeviceIoControl/unsupported/capability/buffer 等底层词汇转换成回调枚举页可读说明；
    // - 返回：适合详情框和表格末列展示的中文短句，避免直接暴露 IOCTL 调试日志。
    QString callbackEnumIoMessageText(const QString& rawMessageText)
    {
        const QString trimmedText = rawMessageText.trimmed();
        if (trimmedText.isEmpty())
        {
            return kernelText("kernel.callback.enum.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }

        const QString lowerText = trimmedText.toLower();
        if (lowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return kernelText("kernel.callback.enum.message.communication_failure", QStringLiteral("驱动 IOCTL 调用失败或当前驱动版本不匹配。"));
        }
        if (lowerText.contains(QStringLiteral("unsupported")) ||
            lowerText.contains(QStringLiteral("not supported")) ||
            lowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return kernelText("kernel.callback.enum.message.unsupported", QStringLiteral("当前驱动暂不支持该回调枚举/移除接口。"));
        }
        if (lowerText.contains(QStringLiteral("capability")) ||
            lowerText.contains(QStringLiteral("dyndata")))
        {
            return kernelText("kernel.callback.enum.message.capability", QStringLiteral("动态偏移能力未满足，回调结构或全局地址暂不可用。"));
        }
        if (lowerText.contains(QStringLiteral("buffer")) &&
            (lowerText.contains(QStringLiteral("small")) || lowerText.contains(QStringLiteral("trunc"))))
        {
            return kernelText("kernel.callback.enum.message.buffer_short", QStringLiteral("驱动返回缓冲区不足，结果可能被截断。"));
        }
        return trimmedText;
    }

    QString callbackEnumFormatAddress(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 16, 16, QChar('0'))
            .toUpper();
    }

    QString callbackEnumWindowsDirectoryPath()
    {
        // 作用：解析 Windows 目录，用于把 \SystemRoot\xxx 转成可打开的 Win32 路径。
        // 返回：Windows 目录绝对路径；失败时回退环境变量。
        wchar_t windowsPathBuffer[MAX_PATH] = {};
        const UINT copiedChars = ::GetWindowsDirectoryW(windowsPathBuffer, MAX_PATH);
        if (copiedChars > 0U && copiedChars < MAX_PATH)
        {
            return QDir::toNativeSeparators(QString::fromWCharArray(windowsPathBuffer));
        }

        const QString envPath = qEnvironmentVariable("SystemRoot");
        return envPath.isEmpty()
            ? QStringLiteral("C:\\Windows")
            : QDir::toNativeSeparators(envPath);
    }

    QString callbackEnumSystemDrivePrefix()
    {
        // 作用：从 Windows 目录中提取系统盘符，处理 \Windows\xxx 这类内核路径。
        // 返回：形如 C: 的盘符；无法判断时返回 C:。
        const QString windowsPath = callbackEnumWindowsDirectoryPath();
        if (windowsPath.size() >= 2 && windowsPath.at(1) == QLatin1Char(':'))
        {
            return windowsPath.left(2);
        }
        return QStringLiteral("C:");
    }

    QString callbackEnumMapNtDevicePathToDosPath(const QString& ntPathText)
    {
        // 作用：尝试把 \Device\HarddiskVolumeX\... 映射为 C:\...。
        // 返回：映射成功返回 Win32 路径；失败返回空字符串。
        const QString normalizedNtPath = QDir::toNativeSeparators(ntPathText.trimmed());
        if (!normalizedNtPath.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            return QString();
        }

        for (wchar_t driveLetter = L'A'; driveLetter <= L'Z'; ++driveLetter)
        {
            const QString driveName = QStringLiteral("%1:").arg(QChar(driveLetter));
            wchar_t deviceNameBuffer[1024] = {};
            const DWORD copiedChars = ::QueryDosDeviceW(
                reinterpret_cast<LPCWSTR>(driveName.utf16()),
                deviceNameBuffer,
                static_cast<DWORD>(sizeof(deviceNameBuffer) / sizeof(deviceNameBuffer[0])));
            if (copiedChars == 0U)
            {
                continue;
            }

            const QString deviceName = QDir::toNativeSeparators(QString::fromWCharArray(deviceNameBuffer));
            if (deviceName.isEmpty() || !normalizedNtPath.startsWith(deviceName, Qt::CaseInsensitive))
            {
                continue;
            }

            const QString suffixText = normalizedNtPath.mid(deviceName.size());
            return QDir::toNativeSeparators(driveName + suffixText);
        }

        return QString();
    }

    QString callbackEnumNormalizeModulePath(const QString& modulePathText)
    {
        // 作用：把 R0 返回的模块路径规范化为 R3 可访问的 Win32 文件路径。
        // 返回：可访问 Win32 路径；无法转换时返回空字符串。
        QString pathText = modulePathText.trimmed();
        if (pathText.isEmpty() || pathText == QStringLiteral("<未解析>"))
        {
            return QString();
        }

        pathText = QDir::toNativeSeparators(pathText);
        if (pathText.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive))
        {
            pathText = pathText.mid(4);
        }
        if (pathText.startsWith(QStringLiteral("\\SystemRoot\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumWindowsDirectoryPath() + pathText.mid(QStringLiteral("\\SystemRoot").size());
        }
        else if (pathText.startsWith(QStringLiteral("SystemRoot\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumWindowsDirectoryPath() + QStringLiteral("\\") + pathText.mid(QStringLiteral("SystemRoot\\").size());
        }
        else if (pathText.startsWith(QStringLiteral("\\Windows\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumSystemDrivePrefix() + pathText;
        }
        else if (pathText.startsWith(QStringLiteral("\\Device\\"), Qt::CaseInsensitive))
        {
            pathText = callbackEnumMapNtDevicePathToDosPath(pathText);
        }

        if (pathText.size() >= 2 && pathText.at(1) == QLatin1Char(':'))
        {
            const QFileInfo fileInfo(pathText);
            return fileInfo.exists() ? fileInfo.absoluteFilePath() : QDir::toNativeSeparators(pathText);
        }
        return QString();
    }

    QString callbackEnumBuildModuleFileGeneralText(const QString& filePath)
    {
        // 作用：生成模块文件详情窗口的常规信息页。
        // 返回：包含路径、大小和时间戳的纯文本。
        const QFileInfo fileInfo(filePath);
        const QString unavailableText = QStringLiteral("<不可用>");
        const auto yesNoText = [](const bool value) {
            return value ? QStringLiteral("是") : QStringLiteral("否");
        };
        return QStringLiteral(
            "文件路径：%1\n"
            "文件名：%2\n"
            "所在目录：%3\n"
            "是否存在：%4\n"
            "大小：%5 字节\n"
            "创建时间：%6\n"
            "修改时间：%7\n"
            "访问时间：%8\n"
            "可读：%9\n"
            "可写：%10\n"
            "可执行：%11")
            .arg(QDir::toNativeSeparators(fileInfo.absoluteFilePath()))
            .arg(fileInfo.fileName())
            .arg(QDir::toNativeSeparators(fileInfo.absolutePath()))
            .arg(yesNoText(fileInfo.exists()))
            .arg(fileInfo.exists() ? QString::number(fileInfo.size()) : unavailableText)
            .arg(fileInfo.birthTime().isValid() ? fileInfo.birthTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")) : unavailableText)
            .arg(fileInfo.lastModified().isValid() ? fileInfo.lastModified().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")) : unavailableText)
            .arg(fileInfo.lastRead().isValid() ? fileInfo.lastRead().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss.zzz")) : unavailableText)
            .arg(yesNoText(fileInfo.isReadable()))
            .arg(yesNoText(fileInfo.isWritable()))
            .arg(yesNoText(fileInfo.isExecutable()));
    }

    void callbackEnumShowModuleFileDetailDialog(QWidget* parentWidget, const QString& filePath)
    {
        // 作用：弹出模块文件详细信息窗口，复用 FileDock 的 PE 解析报告。
        // 返回：无；窗口为模态，关闭后自动释放局部对象。
        QDialog detailDialog(parentWidget);
        detailDialog.setObjectName(QStringLiteral("CallbackEnumModuleFileDetailDialog"));
        detailDialog.setWindowTitle(kernelText("kernel.callback.enum.file.title", QStringLiteral("模块文件详细信息 - %1"))
            .arg(QFileInfo(filePath).fileName()));
        detailDialog.resize(980, 680);
        detailDialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(detailDialog.objectName()));

        QVBoxLayout* rootLayout = new QVBoxLayout(&detailDialog);
        QTabWidget* tabWidget = new QTabWidget(&detailDialog);
        rootLayout->addWidget(tabWidget, 1);

        CodeEditorWidget* generalEditor = new CodeEditorWidget(&detailDialog);
        generalEditor->setReadOnly(true);
        generalEditor->setLocalizedText(callbackEnumBuildModuleFileGeneralText(filePath));
        tabWidget->addTab(generalEditor, kernelText("kernel.callback.enum.file.tab.general", QStringLiteral("常规信息")));

        CodeEditorWidget* peEditor = new CodeEditorWidget(&detailDialog);
        peEditor->setReadOnly(true);
        peEditor->setLocalizedText(file_dock_detail::buildPeAnalysisText(filePath));
        tabWidget->addTab(peEditor, kernelText("kernel.callback.enum.file.tab.pe", QStringLiteral("PE信息")));

        QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, &detailDialog);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &detailDialog, &QDialog::reject);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &detailDialog, &QDialog::accept);
        rootLayout->addWidget(buttonBox, 0);
        detailDialog.exec();
    }

    bool callbackEnumOpenModuleInExplorer(const QString& filePath)
    {
        // 作用：用 Explorer 定位模块文件，失败时返回 false 让调用方更新状态栏。
        // 返回：成功启动 Explorer 返回 true。
        if (filePath.trimmed().isEmpty())
        {
            return false;
        }
        const QString nativePath = QDir::toNativeSeparators(filePath);
        const QString selectArgument = QStringLiteral("/select,\"%1\"").arg(nativePath);
        return QProcess::startDetached(QStringLiteral("explorer.exe"), QStringList{ selectArgument });
    }

    QString callbackEnumClassText(const std::uint32_t callbackClass)
    {
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
            return kernelText("kernel.callback.enum.class.registry", QStringLiteral("注册表 CmCallback"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
            return kernelText("kernel.callback.enum.class.process", QStringLiteral("进程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
            return kernelText("kernel.callback.enum.class.thread", QStringLiteral("线程 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
            return kernelText("kernel.callback.enum.class.image", QStringLiteral("镜像加载 Notify"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
            return QStringLiteral("Object Callback");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
            return QStringLiteral("Minifilter");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
            return QStringLiteral("WFP Callout");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
            return QStringLiteral("ETW Provider/Consumer");
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_GENERIC_KERNEL:
            return kernelText("kernel.callback.enum.class.generic_kernel", QStringLiteral("通用内核 CallbackObject"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK:
            return kernelText("kernel.callback.enum.class.bugcheck", QStringLiteral("BugCheck 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_BUGCHECK_REASON:
            return kernelText("kernel.callback.enum.class.bugcheck_reason", QStringLiteral("BugCheckReason 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_SHUTDOWN:
            return kernelText("kernel.callback.enum.class.shutdown", QStringLiteral("Shutdown 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_FILE_SYSTEM:
            return kernelText("kernel.callback.enum.class.file_system", QStringLiteral("文件系统注册变化"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_LOGON_SESSION:
            return kernelText("kernel.callback.enum.class.logon_session", QStringLiteral("登录会话终止"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE_VERIFICATION:
            return kernelText("kernel.callback.enum.class.image_verification", QStringLiteral("镜像验证回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_NMI:
            return kernelText("kernel.callback.enum.class.nmi", QStringLiteral("NMI 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER:
            return kernelText(
                "kernel.callback.enum.class.legacy_fs_filter",
                QStringLiteral("旧式 FS Filter pre/post 链"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_POWER_SETTING:
            return kernelText("kernel.callback.enum.class.power_setting", QStringLiteral("电源设置回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_COALESCING:
            return kernelText("kernel.callback.enum.class.coalescing", QStringLiteral("Coalescing 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PRIORITY:
            return kernelText("kernel.callback.enum.class.priority", QStringLiteral("优先级回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_DEBUG_PRINT:
            return kernelText("kernel.callback.enum.class.debug_print", QStringLiteral("调试打印回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_EMP:
            return kernelText("kernel.callback.enum.class.emp", QStringLiteral("EMP Provider 回调"));
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PLUG_PLAY:
            return kernelText("kernel.callback.enum.class.plug_play", QStringLiteral("即插即用回调"));
        default:
            return kernelText("kernel.callback.enum.placeholder.unknown_with_value", QStringLiteral("未知(%1)"))
                .arg(callbackClass);
        }
    }

    QString callbackEnumSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF:
            return kernelText("kernel.callback.enum.source.ksword_self", QStringLiteral("Ksword 自身注册"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION:
            return kernelText("kernel.callback.enum.source.fltmgr", QStringLiteral("FltMgr 公开枚举"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED:
            return kernelText("kernel.callback.enum.source.private_unsupported", QStringLiteral("私有结构诊断"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN:
            return kernelText("kernel.callback.enum.source.private_pattern", QStringLiteral("私有特征定位"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY:
            return kernelText("kernel.callback.enum.source.private_notify_array", QStringLiteral("Psp Notify 数组"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST:
            return kernelText("kernel.callback.enum.source.private_registry_list", QStringLiteral("Cm 回调链表"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST:
            return kernelText("kernel.callback.enum.source.private_object_type_list", QStringLiteral("Ob 对象类型链表"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API:
            return kernelText("kernel.callback.enum.source.wfp_api", QStringLiteral("WFP 管理 API"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA:
            return QStringLiteral("ETW DynData");
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PDB_PROFILE:
            return kernelText("kernel.callback.enum.source.pdb_profile", QStringLiteral("PDB 可信 profile"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API:
            return kernelText("kernel.callback.enum.source.public_api", QStringLiteral("公开 API"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST:
            return kernelText("kernel.callback.enum.source.bugcheck_list", QStringLiteral("BugCheck 记录链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST:
            return kernelText("kernel.callback.enum.source.filesystem_list", QStringLiteral("文件系统通知链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST:
            return kernelText("kernel.callback.enum.source.logon_list", QStringLiteral("登录会话通知链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT:
            return kernelText("kernel.callback.enum.source.callback_object", QStringLiteral("CallbackObject 注册链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN:
            return kernelText("kernel.callback.enum.source.driver_object_scan", QStringLiteral("DriverObject/DeviceObject 扫描"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY:
            return kernelText("kernel.callback.enum.source.object_directory", QStringLiteral("对象目录枚举"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST:
            return kernelText("kernel.callback.enum.source.nmi_list", QStringLiteral("NMI 私有注册链"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL:
            return kernelText(
                "kernel.callback.enum.source.legacy_fs_public_structural",
                QStringLiteral("公开 FS Filter 枚举 + ClassInitData 结构签名"));
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK:
            return kernelText(
                "kernel.callback.enum.source.private_special_callback",
                QStringLiteral("私有特殊回调表/链"));
        default:
            return kernelText("kernel.callback.enum.placeholder.unknown_with_value", QStringLiteral("未知(%1)"))
                .arg(source);
        }
    }

    QString callbackEnumRegistrationTypeText(const std::uint32_t registrationType)
    {
        // 作用：把当前协议的具体注册 API 类型映射为可筛选文本。
        // 返回：未知或旧协议行显示“未分类”。
        switch (registrationType)
        {
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_LEGACY:
            return kernelText(
                "kernel.callback.enum.registration_type.process_legacy",
                QStringLiteral("进程 Notify（Legacy）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX:
            return kernelText(
                "kernel.callback.enum.registration_type.process_ex",
                QStringLiteral("进程 Notify（Ex）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PROCESS_EX2:
            return kernelText(
                "kernel.callback.enum.registration_type.process_ex2",
                QStringLiteral("进程 Notify（Ex2）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_LEGACY:
            return kernelText(
                "kernel.callback.enum.registration_type.thread_legacy",
                QStringLiteral("线程 Notify（Legacy）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_NON_SYSTEM:
            return kernelText(
                "kernel.callback.enum.registration_type.thread_ex_non_system",
                QStringLiteral("线程 Notify（Ex/NonSystem）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_THREAD_EX_SUBSYSTEMS:
            return kernelText(
                "kernel.callback.enum.registration_type.thread_ex_subsystems",
                QStringLiteral("线程 Notify（Ex/Subsystems）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_LEGACY_OR_EX_DEFAULT:
            return kernelText(
                "kernel.callback.enum.registration_type.image_legacy_or_ex_default",
                QStringLiteral("镜像 Notify（Legacy/Ex 默认）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_EX_CONFLICTING_ARCHITECTURE:
            return kernelText(
                "kernel.callback.enum.registration_type.image_ex_conflicting_architecture",
                QStringLiteral("镜像 Notify（Ex/冲突架构）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_CLASSIC:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_classic",
                QStringLiteral("BugCheck（经典）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_SECONDARY_DUMP:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_secondary_dump",
                QStringLiteral("BugCheckReason（SecondaryDump）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_DUMP_IO:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_dump_io",
                QStringLiteral("BugCheckReason（DumpIo）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_TRIAGE_DUMP:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_triage_dump",
                QStringLiteral("BugCheckReason（TriageDump）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_BUGCHECK_REASON_OTHER:
            return kernelText(
                "kernel.callback.enum.registration_type.bugcheck_reason_other",
                QStringLiteral("BugCheckReason（其他）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_SHUTDOWN:
            return kernelText(
                "kernel.callback.enum.registration_type.shutdown",
                QStringLiteral("Shutdown 通知"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_FILE_SYSTEM_CHANGE:
            return kernelText(
                "kernel.callback.enum.registration_type.file_system_change",
                QStringLiteral("文件系统注册变化"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_LEGACY:
            return kernelText(
                "kernel.callback.enum.registration_type.logon_legacy",
                QStringLiteral("登录会话（Legacy）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LOGON_EX:
            return kernelText(
                "kernel.callback.enum.registration_type.logon_ex",
                QStringLiteral("登录会话（Ex）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_INFORMATIONAL:
            return kernelText(
                "kernel.callback.enum.registration_type.image_verify_informational",
                QStringLiteral("镜像验证（Informational）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_IMAGE_VERIFY_BLOCK:
            return kernelText(
                "kernel.callback.enum.registration_type.image_verify_block",
                QStringLiteral("镜像验证（Block）"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_GENERIC_CALLBACK_OBJECT:
            return kernelText(
                "kernel.callback.enum.registration_type.generic_callback_object",
                QStringLiteral("通用 CallbackObject"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_NMI:
            return kernelText(
                "kernel.callback.enum.registration_type.nmi",
                QStringLiteral("NMI 回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DESKTOP_OBJECT:
            return kernelText(
                "kernel.callback.enum.registration_type.desktop_object",
                QStringLiteral("Desktop 对象回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_CLASS_INIT:
            return kernelText(
                "kernel.callback.enum.registration_type.legacy_fs_class_init",
                QStringLiteral("Legacy FS ClassInitData"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_PRE:
            return kernelText(
                "kernel.callback.enum.registration_type.legacy_fs_pre",
                QStringLiteral("Legacy FS Pre 回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_LEGACY_FS_POST:
            return kernelText(
                "kernel.callback.enum.registration_type.legacy_fs_post",
                QStringLiteral("Legacy FS Post 回调"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_POWER_SETTING:
            return kernelText(
                "kernel.callback.enum.registration_type.power_setting",
                QStringLiteral("PoRegisterPowerSettingCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_COALESCING:
            return kernelText(
                "kernel.callback.enum.registration_type.coalescing",
                QStringLiteral("PoRegisterCoalescingCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PRIORITY:
            return kernelText(
                "kernel.callback.enum.registration_type.priority",
                QStringLiteral("IoRegisterPriorityCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_DEBUG_PRINT:
            return kernelText(
                "kernel.callback.enum.registration_type.debug_print",
                QStringLiteral("DbgSetDebugPrintCallback"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_EMP:
            return kernelText(
                "kernel.callback.enum.registration_type.emp",
                QStringLiteral("EmpProviderRegister"));
        case KSWORD_ARK_CALLBACK_REGISTRATION_TYPE_PLUG_PLAY:
            return kernelText(
                "kernel.callback.enum.registration_type.plug_play",
                QStringLiteral("IoRegisterPlugPlayNotification"));
        default:
            return kernelText("kernel.callback.enum.registration_type.unclassified", QStringLiteral("未分类"));
        }
    }

    enum class CallbackEnumRemovePolicyKind : int
    {
        NotRemovable = 0,
        RemovableVerified,
        RemovableCandidate,
        ExperimentalOnly
    };

    bool callbackEnumHasField(const KernelCallbackEnumEntry& entry, const std::uint32_t fieldFlag)
    {
        // Input: one cached callback row and one KSWORD_ARK_CALLBACK_ENUM_FIELD_* bit.
        // Processing: masks the legacy fieldFlags value without looking at future protocol bytes.
        // Return: true only when the existing protocol explicitly marks the field as present.
        return (entry.fieldFlags & fieldFlag) != 0U;
    }

    bool callbackEnumFieldIndicatesTrusted(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks the optional trusted field bit only when the shared header has it.
        // Return: true when R0 explicitly marked this row as trusted; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED)
        return callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_TRUSTED);
#else
        return false;
#endif
    }

    bool callbackEnumFieldIndicatesVerifiedRemove(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks the optional verified-remove field bit when available.
        // Return: true when R0 says the safe remove path is verified; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE)
        return callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_VERIFIED_REMOVE);
#else
        return false;
#endif
    }

    bool callbackEnumFieldIndicatesExperimentalRemove(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks the optional experimental-remove field bit when available.
        // Return: true when R0 says this row only has an experimental unlink path; false otherwise.
#if defined(KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE)
        return callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_EXPERIMENTAL_REMOVE);
#else
        return false;
#endif
    }

    bool callbackEnumTrustFlagsIndicateTrusted(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: reads optional trust flags without making old shared headers incompatible.
        // Return: true for PDB/revalidated trust; false when the flags are absent or unrelated.
#if defined(KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE) && defined(KSWORD_ARK_CALLBACK_TRUST_REVALIDATED)
        return (entry.trustFlags & (KSWORD_ARK_CALLBACK_TRUST_PDB_PROFILE | KSWORD_ARK_CALLBACK_TRUST_REVALIDATED)) != 0U;
#else
        return entry.trustFlags != 0U;
#endif
    }

    bool callbackEnumTrustFlagsIndicatePublicApi(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks optional trust flags for public API provenance.
        // Return: true when R0 explicitly reports public API trust; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API)
        return (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_PUBLIC_API) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumTrustFlagsIndicateFallbackPattern(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks optional trust flags for fallback/pattern provenance.
        // Return: true when R0 explicitly reports fallback evidence; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN)
        return (entry.trustFlags & KSWORD_ARK_CALLBACK_TRUST_FALLBACK_PATTERN) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumRemoveBehaviorIndicatesPublicApi(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: reads optional remove-behavior flags for the safe public API path.
        // Return: true when the future protocol marks public API removal; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API)
        return (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumRemoveBehaviorIndicatesExperimentalUnlink(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: reads optional remove-behavior flags for experimental unlink.
        // Return: true when the future protocol marks unlink-only behavior; false on old headers.
#if defined(KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK)
        return (entry.removeBehavior & KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK) != 0U;
#else
        return false;
#endif
    }

    bool callbackEnumIsPublicApiSource(const std::uint32_t source)
    {
        // Input: the shared callback enumeration source id.
        // Processing: maps sources that came from documented management/enumeration APIs.
        // Return: true for public API backed sources; false for private/fallback diagnostics.
        return source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_WFP_MGMT_API
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PUBLIC_API
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_DRIVER_OBJECT_SCAN
            || source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_LEGACY_FS_PUBLIC_AND_STRUCTURAL;
    }

    bool callbackEnumIsFallbackPatternSource(const std::uint32_t source)
    {
        // Input: the shared callback enumeration source id.
        // Processing: groups private arrays/lists/pattern probes as fallback-style evidence.
        // Return: true when the source should be presented as fallback/pattern only.
        switch (source)
        {
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NOTIFY_ARRAY:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_REGISTRY_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_OBJECT_TYPE_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_ETW_DYNDATA:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_BUGCHECK_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_FILESYSTEM_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_LOGON_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_CALLBACK_OBJECT:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_OBJECT_DIRECTORY:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_NMI_LIST:
        case KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_SPECIAL_CALLBACK:
            return true;
        default:
            return false;
        }
    }

    bool callbackEnumIsUnsupportedSource(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: combines the explicit unsupported source with unsupported row status.
        // Return: true when UI should show unsupported instead of trusted/public/fallback.
        return entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_UNSUPPORTED
            || entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED;
    }

    bool callbackEnumIsTrustedSource(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row with legacy and reserved trust metadata.
        // Processing: treats Ksword-owned rows as trusted today and leaves PDB trust flags
        //             reserved for future protocol parsing.
        // Return: true for rows that are trusted without requiring private fallback evidence.
        return entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_KSWORD_SELF
            || callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_OWNED_BY_KSWORD)
            || callbackEnumFieldIndicatesTrusted(entry)
            || callbackEnumTrustFlagsIndicateTrusted(entry);
    }

    QString callbackEnumSourceTrustText(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: collapses current source ids plus reserved trust flags into the four
        //             UX buckets requested for PDB trusted callback readiness.
        // Return: display text that includes trusted/fallback/public api/unsupported keywords.
        if (callbackEnumIsUnsupportedSource(entry))
        {
            return kernelText("kernel.callback.enum.trust.unsupported", QStringLiteral("unsupported（当前协议/平台未支持）"));
        }
        if (callbackEnumIsTrustedSource(entry))
        {
            return kernelText("kernel.callback.enum.trust.trusted", QStringLiteral("trusted（可信/自有或预留 PDB）"));
        }
        if (callbackEnumIsPublicApiSource(entry.source)
            || callbackEnumTrustFlagsIndicatePublicApi(entry)
            || callbackEnumRemoveBehaviorIndicatesPublicApi(entry))
        {
            return kernelText("kernel.callback.enum.trust.public_api", QStringLiteral("public api（公开 API）"));
        }
        if (callbackEnumIsFallbackPatternSource(entry.source)
            || callbackEnumTrustFlagsIndicateFallbackPattern(entry))
        {
            return kernelText("kernel.callback.enum.trust.fallback_pattern", QStringLiteral("fallback/pattern（私有结构诊断）"));
        }
        return kernelText("kernel.callback.enum.trust.fallback", QStringLiteral("fallback（未知来源保守展示）"));
    }

    std::uint32_t callbackEnumRemoveTypeForClass(const std::uint32_t callbackClass)
    {
        // Input: callback enum class from the shared enum protocol.
        // Processing: maps enum classes to the old REMOVE_EXTERNAL_CALLBACK request classes.
        // Return: external remove class id; 0 means no compatible old remove request exists.
        switch (callbackClass)
        {
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_REGISTRY:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_PROCESS:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_THREAD:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_IMAGE:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_OBJECT:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_WFP_CALLOUT:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT;
        case KSWORD_ARK_CALLBACK_ENUM_CLASS_ETW_PROVIDER:
            return KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER;
        default:
            return 0U;
        }
    }

    std::uint64_t callbackEnumRemoveRequestValue(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: chooses the value accepted by the legacy remove protocol. The field is
        //             named callbackAddress, but WFP currently carries calloutId there.
        // Return: non-zero request value for removeExternalCallback, or 0 when unavailable.
        if (entry.callbackAddress != 0U
            && (callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS)
                || callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER)
                || callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE)
                || (entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE) != 0U))
        {
            return entry.callbackAddress;
        }
        if (entry.registrationAddress != 0U
            && callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER))
        {
            return entry.registrationAddress;
        }
        return 0U;
    }

    bool callbackEnumHasExperimentalStorageValue(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: checks legacy diagnostic addresses and reserved raw storage metadata.
        // Return: true when UI can describe an unlink-only candidate without sending IOCTLs.
        return entry.rawStorageValue != 0U
            || entry.callbackAddress != 0U
            || entry.registrationAddress != 0U
            || entry.contextAddress != 0U;
    }

    CallbackEnumRemovePolicyKind callbackEnumRemovePolicyKind(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: derives a conservative UI policy from legacy removable-candidate bits,
        //             source trust class, and the presence of a legacy remove request value.
        // Return: the display policy; this does not create any new driver protocol.
        if (callbackEnumIsUnsupportedSource(entry)
            || entry.status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK
            || callbackEnumRemoveTypeForClass(entry.callbackClass) == 0U)
        {
            return CallbackEnumRemovePolicyKind::NotRemovable;
        }

        const bool removableCandidate =
            callbackEnumHasField(entry, KSWORD_ARK_CALLBACK_ENUM_FIELD_REMOVABLE_CANDIDATE);
        const bool hasLegacyRemoveValue = callbackEnumRemoveRequestValue(entry) != 0U;
        const bool verifiedRemove =
            callbackEnumFieldIndicatesVerifiedRemove(entry)
            || callbackEnumRemoveBehaviorIndicatesPublicApi(entry);
        const bool experimentalRemove =
            callbackEnumFieldIndicatesExperimentalRemove(entry)
            || callbackEnumRemoveBehaviorIndicatesExperimentalUnlink(entry);
        if (hasLegacyRemoveValue
            && (verifiedRemove || (removableCandidate && callbackEnumIsPublicApiSource(entry.source))))
        {
            return CallbackEnumRemovePolicyKind::RemovableVerified;
        }
        if (removableCandidate && hasLegacyRemoveValue)
        {
            return CallbackEnumRemovePolicyKind::RemovableCandidate;
        }
        if ((experimentalRemove
            || callbackEnumIsFallbackPatternSource(entry.source)
            || callbackEnumTrustFlagsIndicateFallbackPattern(entry))
            && callbackEnumHasExperimentalStorageValue(entry))
        {
            return CallbackEnumRemovePolicyKind::ExperimentalOnly;
        }
        return CallbackEnumRemovePolicyKind::NotRemovable;
    }

    QString callbackEnumRemovePolicyText(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: converts the derived policy to stable UX wording.
        // Return: display text containing the requested removable policy keywords.
        switch (callbackEnumRemovePolicyKind(entry))
        {
        case CallbackEnumRemovePolicyKind::RemovableVerified:
            return kernelText("kernel.callback.enum.remove_policy.verified", QStringLiteral("removable verified（公开 API 可验证）"));
        case CallbackEnumRemovePolicyKind::RemovableCandidate:
            return kernelText("kernel.callback.enum.remove_policy.candidate", QStringLiteral("removable candidate（旧协议候选）"));
        case CallbackEnumRemovePolicyKind::ExperimentalOnly:
            return kernelText("kernel.callback.enum.remove_policy.experimental", QStringLiteral("experimental only（仅预留 unlink）"));
        case CallbackEnumRemovePolicyKind::NotRemovable:
        default:
            return kernelText("kernel.callback.enum.remove_policy.not_removable", QStringLiteral("not removable（不可移除）"));
        }
    }

    bool callbackEnumCanUseLegacySafeRemove(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: allows only verified/candidate policies to call old removeExternalCallback.
        // Return: true when the context menu may invoke ArkDriverClient::removeExternalCallback.
        const CallbackEnumRemovePolicyKind policy = callbackEnumRemovePolicyKind(entry);
        return policy == CallbackEnumRemovePolicyKind::RemovableVerified
            || policy == CallbackEnumRemovePolicyKind::RemovableCandidate;
    }

    bool callbackEnumRequiresSecondConfirmation(const KernelCallbackEnumEntry& entry)
    {
        // Input: one cached callback row.
        // Processing: requires confirmation for every row that can change kernel callback
        //             state, and especially for fallback/pattern or unlink-only rows.
        // Return: true when the detail pane/menu should require a QMessageBox confirmation.
        return callbackEnumRemovePolicyKind(entry) != CallbackEnumRemovePolicyKind::NotRemovable;
    }

    QString callbackEnumYesNoText(const bool value)
    {
        // Input: boolean UI state.
        // Processing: maps it to localized yes/no text.
        // Return: "是" for true, "否" for false.
        return kernelText(
            value ? "kernel.callback.enum.boolean.yes" : "kernel.callback.enum.boolean.no",
            value ? QStringLiteral("是") : QStringLiteral("否"));
    }

    QString callbackEnumIdentityHashText(const std::uint64_t identityHash)
    {
        // Input: reserved identity hash from ArkDriverClient.
        // Processing: keeps the current v1 protocol compatible by showing an empty value for 0.
        // Return: hex hash text or an explicit empty placeholder.
        if (identityHash == 0U)
        {
            return kernelText("kernel.callback.enum.placeholder.empty", QStringLiteral("<空>"));
        }
        return callbackEnumFormatAddress(identityHash);
    }

    QString callbackEnumNtStatusText(const long ntstatus)
    {
        // Input: NTSTATUS value returned by the driver response.
        // Processing: formats the signed status as the conventional 8-digit hex value.
        // Return: uppercase NTSTATUS text suitable for labels and detail panes.
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(ntstatus)), 8, 16, QChar('0'))
            .toUpper();
    }

    QString callbackEnumRemoveMappingText(const std::uint32_t mappingFlags)
    {
        // Input: KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_* bits from the old remove response.
        // Processing: expands known bits while keeping unknown future bits visible.
        // Return: human-readable mapping flag summary.
        QStringList flagList;
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE) != 0U)
        {
            flagList.push_back(QStringLiteral("module"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED) != 0U)
        {
            flagList.push_back(QStringLiteral("enumerated"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API) != 0U)
        {
            flagList.push_back(QStringLiteral("public api"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED) != 0U)
        {
            flagList.push_back(QStringLiteral("pdb trusted"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL) != 0U)
        {
            flagList.push_back(QStringLiteral("experimental"));
        }
        const std::uint32_t knownFlags =
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PDB_TRUSTED |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_EXPERIMENTAL;
        const std::uint32_t unknownFlags = mappingFlags & ~knownFlags;
        if (unknownFlags != 0U)
        {
            flagList.push_back(QStringLiteral("unknown=0x%1")
                .arg(static_cast<qulonglong>(unknownFlags), 8, 16, QChar('0'))
                .toUpper());
        }
        return flagList.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.none", QStringLiteral("<无>"))
            : flagList.join(QStringLiteral(", "));
    }

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST callbackEnumBuildLegacyRemoveRequest(const KernelCallbackEnumEntry& entry)
    {
        // Input: one selected callback enumeration row.
        // Processing: maps enum metadata to the existing v1 removeExternalCallback request.
        // Return: initialized request packet; callbackClass/address are zero when not compatible.
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST requestPacket{};
        requestPacket.size = sizeof(requestPacket);
        requestPacket.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
        requestPacket.callbackClass = callbackEnumRemoveTypeForClass(entry.callbackClass);
        requestPacket.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
        requestPacket.callbackAddress = callbackEnumRemoveRequestValue(entry);
        return requestPacket;
    }

    KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST callbackEnumBuildExRemoveRequest(
        const KernelCallbackEnumEntry& entry,
        const std::uint32_t removeFlags,
        const std::uint32_t removeBehavior)
    {
        // Input: one selected callback enumeration row plus remove policy/flags.
        // Processing: copies row metadata into the EX request packet for R0 validation.
        // Return: initialized EX request packet.
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST requestPacket{};
        requestPacket.size = sizeof(requestPacket);
        requestPacket.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
        requestPacket.callbackClass = callbackEnumRemoveTypeForClass(entry.callbackClass);
        requestPacket.flags = removeFlags;
        requestPacket.callbackAddress = callbackEnumRemoveRequestValue(entry);
        requestPacket.registrationAddress = entry.registrationAddress;
        requestPacket.rawStorageValue = entry.rawStorageValue;
        requestPacket.enumerationGeneration = entry.generation;
        requestPacket.identityHash = entry.identityHash;
        requestPacket.source = entry.source;
        requestPacket.operationMask = entry.operationMask;
        requestPacket.objectTypeMask = entry.objectTypeMask;
        requestPacket.trustFlags = entry.trustFlags;
        requestPacket.removeBehavior = removeBehavior;
        return requestPacket;
    }

    QString callbackEnumExRemoveDetailText(
        const KernelCallbackEnumEntry& entry,
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST& requestPacket,
        const ksword::ark::CallbackRemoveExResult& removeResult)
    {
        // Input: selected row, EX request packet, and EX remove result.
        // Processing: renders the full semantic response.
        // Return: detail text for the callback enum detail pane.
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE& responsePacket = removeResult.response;
        const QString modulePath = QString::fromWCharArray(responsePacket.modulePath);
        const QString serviceName = QString::fromWCharArray(responsePacket.serviceName);
        const QString messageText = QString::fromWCharArray(responsePacket.message);
        return kernelText("kernel.callback.enum.remove.ex.detail", QStringLiteral(
            "EX移除请求已执行。\n"
            "- 类型：%1\n"
            "- 来源：%2\n"
            "- 可信状态：%3\n"
            "- 移除策略：%4\n"
            "- 请求类：%5\n"
            "- 请求值：%6\n"
            "- RemoveBehavior：0x%7\n"
            "- TrustFlags：0x%8\n"
            "- Generation：%9\n"
            "- IdentityHash：%10\n"
            "- Win32：%11\n"
            "- 返回字节：%12\n"
            "- NTSTATUS：%13\n"
            "- Revalidation：%14\n"
            "- 映射标志：%15\n"
            "- 模块路径：%16\n"
            "- 模块基址：%17\n"
            "- 模块大小：0x%18\n"
            "- 服务名：%19\n"
            "- 消息：%20\n"
            "- ArkDriverClient：%21"))
            .arg(entry.classText)
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(static_cast<qulonglong>(requestPacket.callbackClass))
            .arg(callbackEnumFormatAddress(requestPacket.callbackAddress))
            .arg(QString::number(static_cast<qulonglong>(requestPacket.removeBehavior), 16).toUpper())
            .arg(QString::number(static_cast<qulonglong>(requestPacket.trustFlags), 16).toUpper())
            .arg(static_cast<qulonglong>(requestPacket.enumerationGeneration))
            .arg(callbackEnumIdentityHashText(requestPacket.identityHash))
            .arg(static_cast<qulonglong>(removeResult.io.win32Error))
            .arg(static_cast<qulonglong>(removeResult.io.bytesReturned))
            .arg(callbackEnumNtStatusText(responsePacket.ntstatus))
            .arg(callbackEnumNtStatusText(responsePacket.revalidationStatus))
            .arg(callbackEnumRemoveMappingText(responsePacket.mappingFlags))
            .arg(modulePath.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>")) : modulePath)
            .arg(callbackEnumFormatAddress(responsePacket.moduleBase))
            .arg(QString::number(static_cast<qulonglong>(responsePacket.moduleSize), 16).toUpper())
            .arg(serviceName.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unmatched", QStringLiteral("<未匹配>")) : serviceName)
            .arg(messageText.isEmpty() ? kernelText("kernel.callback.enum.placeholder.none", QStringLiteral("<无>")) : messageText)
            .arg(callbackEnumIoMessageText(QString::fromStdString(removeResult.io.message)));
    }

    QString callbackEnumLegacyRemoveDetailText(
        const KernelCallbackEnumEntry& entry,
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST& requestPacket,
        const ksword::ark::CallbackRemoveResult& removeResult)
    {
        // Input: selected row, request packet, and ArkDriverClient remove result.
        // Processing: renders both transport and R0 semantic fields without assuming success.
        // Return: full detail text for the callback enum detail pane.
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE& responsePacket = removeResult.response;
        const QString modulePath = QString::fromWCharArray(responsePacket.modulePath);
        const QString serviceName = QString::fromWCharArray(responsePacket.serviceName);
        return kernelText("kernel.callback.enum.remove.legacy.detail", QStringLiteral(
            "安全移除请求已执行。\n"
            "- 类型：%1\n"
            "- 来源：%2\n"
            "- 可信状态：%3\n"
            "- 移除策略：%4\n"
            "- 请求类：%5\n"
            "- 请求值：%6\n"
            "- Win32：%7\n"
            "- 返回字节：%8\n"
            "- NTSTATUS：%9\n"
            "- 映射标志：%10\n"
            "- 模块路径：%11\n"
            "- 模块基址：%12\n"
            "- 模块大小：0x%13\n"
            "- 服务名：%14\n"
            "- 驱动消息：%15"))
            .arg(entry.classText)
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(static_cast<qulonglong>(requestPacket.callbackClass))
            .arg(callbackEnumFormatAddress(requestPacket.callbackAddress))
            .arg(static_cast<qulonglong>(removeResult.io.win32Error))
            .arg(static_cast<qulonglong>(removeResult.io.bytesReturned))
            .arg(callbackEnumNtStatusText(responsePacket.ntstatus))
            .arg(callbackEnumRemoveMappingText(responsePacket.mappingFlags))
            .arg(modulePath.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>")) : modulePath)
            .arg(callbackEnumFormatAddress(responsePacket.moduleBase))
            .arg(QString::number(static_cast<qulonglong>(responsePacket.moduleSize), 16).toUpper())
            .arg(serviceName.isEmpty() ? kernelText("kernel.callback.enum.placeholder.unmatched", QStringLiteral("<未匹配>")) : serviceName)
            .arg(callbackEnumIoMessageText(QString::fromStdString(removeResult.io.message)));
    }

    bool callbackEnumConfirmSafeRemove(QWidget* parentWidget, const KernelCallbackEnumEntry& entry)
    {
        // Input: parent widget and selected row.
        // Processing: shows a second confirmation before any EX public-API remove IOCTL is sent.
        // Return: true when the user explicitly confirms the safe public/API remove action.
        const QString warningText = kernelText("kernel.callback.enum.remove.safe.confirm", QStringLiteral(
            "即将执行安全移除。\n\n"
            "类别：%1\n"
            "名称：%2\n"
            "来源：%3\n"
            "可信状态：%4\n"
            "移除策略：%5\n"
            "请求值：%6\n"
            "可信：%7\n\n"
            "此操作会修改内核回调注册，可能影响系统稳定性。是否继续？"))
            .arg(entry.classText)
            .arg(callbackEnumSafeText(entry.nameText))
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(callbackEnumFormatAddress(callbackEnumRemoveRequestValue(entry)))
            .arg(callbackEnumYesNoText(callbackEnumIsTrustedSource(entry)));
        return QMessageBox::question(
            parentWidget,
            kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
            warningText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) == QMessageBox::Yes;
    }

    void callbackEnumExecuteSafeRemove(
        QWidget* parentWidget,
        QLabel* statusLabel,
        CodeEditorWidget* detailEditor,
        const KernelCallbackEnumEntry& entry)
    {
        // Input: UI sinks plus the selected callback row.
        // Processing: validates the EX packet, asks for confirmation, then calls ArkDriverClient.
        // Return: no return value; status/detail widgets and QMessageBox carry the outcome.
        if (!callbackEnumCanUseLegacySafeRemove(entry))
        {
            QMessageBox::information(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.unavailable", QStringLiteral("当前记录不支持安全移除。")));
            return;
        }

        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST requestPacket =
            callbackEnumBuildExRemoveRequest(
                entry,
                KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE,
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_PUBLIC_API |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION);
        if (requestPacket.callbackClass == 0U || requestPacket.callbackAddress == 0U)
        {
            QMessageBox::warning(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.missing_value", QStringLiteral("当前记录缺少可用的类型或地址/标识值。")));
            return;
        }

        if (!callbackEnumConfirmSafeRemove(parentWidget, entry))
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.safe.cancelled", QStringLiteral("状态：已取消安全移除")));
            }
            return;
        }

        const ksword::ark::DriverClient driverClient;
        const ksword::ark::CallbackRemoveExResult removeResult =
            driverClient.removeExternalCallbackEx(requestPacket);
        if (detailEditor != nullptr)
        {
            detailEditor->setLocalizedText(callbackEnumExRemoveDetailText(entry, requestPacket, removeResult));
        }

        if (!removeResult.io.ok)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(
                    kernelText("kernel.callback.enum.remove.safe.io_failed", QStringLiteral("状态：安全移除失败，Win32=%1"))
                    .arg(static_cast<qulonglong>(removeResult.io.win32Error)));
            }
            QMessageBox::warning(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.call_failed", QStringLiteral("回调移除失败，Win32=%1。"))
                    .arg(static_cast<qulonglong>(removeResult.io.win32Error)));
            return;
        }

        if (removeResult.response.ntstatus >= 0)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.safe.completed", QStringLiteral("状态：安全移除完成")));
            }
        }
        else
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(
                    kernelText("kernel.callback.enum.remove.safe.driver_failed", QStringLiteral("状态：驱动返回失败，NTSTATUS=%1"))
                    .arg(callbackEnumNtStatusText(removeResult.response.ntstatus)));
            }
            QMessageBox::warning(
                parentWidget,
                kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")),
                kernelText("kernel.callback.enum.remove.safe.driver_failed_message", QStringLiteral("驱动返回失败，NTSTATUS=%1。"))
                    .arg(callbackEnumNtStatusText(removeResult.response.ntstatus)));
        }
    }

    void callbackEnumShowExperimentalUnlinkNotice(
        QWidget* parentWidget,
        QLabel* statusLabel,
        CodeEditorWidget* detailEditor,
        const KernelCallbackEnumEntry& entry)
    {
        // Input: UI sinks plus the selected callback row.
        // Processing: presents a strong confirmation and then sends the EX request
        //             with experimental-unlink flags. R0 currently rejects the path.
        // Return: no return value; result details are shown in UI.
        if (callbackEnumRemovePolicyKind(entry) == CallbackEnumRemovePolicyKind::NotRemovable
            || callbackEnumRemoveRequestValue(entry) == 0U)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.experimental.not_target", QStringLiteral("状态：当前条目无法移除")));
            }
            QMessageBox::information(
                parentWidget,
                kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")),
                kernelText("kernel.callback.enum.remove.experimental.no_value", QStringLiteral("当前条目没有可用的回调地址或标识值，无法执行移除。")));
            return;
        }

        const QString confirmText = kernelText("kernel.callback.enum.remove.experimental.confirm", QStringLiteral(
            "强制移除可能破坏内核数据，导致系统不稳定、蓝屏或安全产品状态异常。\n\n"
            "类别：%1\n"
            "名称：%2\n"
            "来源：%3\n"
            "可信状态：%4\n"
            "移除策略：%5\n"
            "存储值：%6\n\n"
            "仅在已确认目标异常并接受上述风险时继续。"))
            .arg(entry.classText)
            .arg(callbackEnumSafeText(entry.nameText))
            .arg(entry.sourceText)
            .arg(entry.sourceTrustText)
            .arg(entry.removePolicyText)
            .arg(callbackEnumFormatAddress(entry.rawStorageValue));
        const QMessageBox::StandardButton reply = QMessageBox::warning(
            parentWidget,
            kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")),
            confirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (reply != QMessageBox::Yes)
        {
            if (statusLabel != nullptr)
            {
                statusLabel->setText(kernelText("kernel.callback.enum.remove.experimental.cancelled", QStringLiteral("状态：已取消强制移除")));
            }
            return;
        }

        const ksword::ark::DriverClient driverClient;
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST requestPacket =
            callbackEnumBuildExRemoveRequest(
                entry,
                KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_EXPERIMENTAL_UNLINK |
                KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_REQUIRE_REVALIDATION,
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_EXPERIMENTAL_UNLINK |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_REQUIRE_REVALIDATION |
                KSWORD_ARK_CALLBACK_REMOVE_BEHAVIOR_FORCE_AFTER_PUBLIC_FAILURE);
        const ksword::ark::CallbackRemoveExResult removeResult =
            driverClient.removeExternalCallbackEx(requestPacket);
        if (detailEditor != nullptr)
        {
            detailEditor->setLocalizedText(callbackEnumExRemoveDetailText(entry, requestPacket, removeResult));
        }
        if (statusLabel != nullptr)
        {
            statusLabel->setText(removeResult.io.ok && removeResult.response.ntstatus == callbackEnumStatusNotSupported()
                ? kernelText("kernel.callback.enum.remove.experimental.rejected", QStringLiteral("状态：强制移除被驱动拒绝"))
                : kernelText("kernel.callback.enum.remove.experimental.completed", QStringLiteral("状态：强制移除请求已完成")));
        }
        QMessageBox::information(
            parentWidget,
            kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")),
            removeResult.io.ok
                ? kernelText("kernel.callback.enum.remove.experimental.processed", QStringLiteral("强制移除请求已处理，请查看详情中的状态码。"))
                : kernelText("kernel.callback.enum.remove.experimental.io_failed", QStringLiteral("强制移除请求失败，Win32=%1。"))
                    .arg(static_cast<qulonglong>(removeResult.io.win32Error)));
    }

    QString callbackEnumPrimaryAddressText(const KernelCallbackEnumEntry& entry)
    {
        // 作用：根据 fieldFlags 选择表格主地址，避免把定位/诊断行误显示为 0 地址。
        // 返回：真实回调地址、全局/节点地址、诊断地址或“无回调地址”占位文本。
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS) != 0U
            && entry.callbackAddress != 0U)
        {
            return callbackEnumFormatAddress(entry.callbackAddress);
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_IDENTIFIER) != 0U
            && entry.callbackAddress != 0U)
        {
            return kernelText("kernel.callback.enum.address.identifier", QStringLiteral("标识 %1"))
                .arg(callbackEnumFormatAddress(entry.callbackAddress));
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_HANDLE) != 0U
            && entry.callbackAddress != 0U)
        {
            return kernelText("kernel.callback.enum.address.handle", QStringLiteral("句柄 %1"))
                .arg(callbackEnumFormatAddress(entry.callbackAddress));
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_REGISTRATION_ADDRESS) != 0U
            && entry.registrationAddress != 0U)
        {
            const bool locateRow = entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_PRIVATE_PATTERN_SCAN;
            return kernelText("kernel.callback.enum.address.registration", QStringLiteral("%1 %2"))
                .arg(locateRow
                    ? kernelText("kernel.callback.enum.address.global", QStringLiteral("全局"))
                    : kernelText("kernel.callback.enum.address.node", QStringLiteral("节点")))
                .arg(callbackEnumFormatAddress(entry.registrationAddress));
        }
        if ((entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_CONTEXT_ADDRESS) != 0U
            && entry.contextAddress != 0U)
        {
            return kernelText("kernel.callback.enum.address.diagnostic", QStringLiteral("诊断 %1"))
                .arg(callbackEnumFormatAddress(entry.contextAddress));
        }
        return kernelText("kernel.callback.enum.address.none", QStringLiteral("<无回调地址>"));
    }

    QString callbackEnumNtStatusText(const std::uint64_t value)
    {
        return QString::number(
            static_cast<quint32>(value),
            16).rightJustified(8, QLatin1Char('0')).toUpper();
    }

    QString callbackEnumLegacyFsPairStateText(const std::uint64_t pairEvidence)
    {
        return (pairEvidence & (1ULL << 32)) != 0ULL
            ? kernelText(
                "kernel.callback.enum.legacy_fs.pair.paired",
                QStringLiteral("pre/post 成对"))
            : kernelText(
                "kernel.callback.enum.legacy_fs.pair.single",
                QStringLiteral("单边回调"));
    }

    QString callbackEnumLocalizedDetailText(
        const ksword::ark::CallbackEnumEntry& source,
        const KernelCallbackEnumEntry& entry)
    {
        if (source.callbackClass != KSWORD_ARK_CALLBACK_ENUM_CLASS_LEGACY_FS_FILTER ||
            (source.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_DETAIL_ARGS) == 0U ||
            source.detailCode == KSWORD_ARK_CALLBACK_ENUM_DETAIL_NONE)
        {
            return entry.detailText;
        }

        switch (source.detailCode)
        {
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_EMPTY:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.public_empty",
                QStringLiteral("公开 API 未返回旧式文件系统过滤驱动；NTSTATUS=0x%1。"))
                .arg(callbackEnumNtStatusText(source.detailArgs[0]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_COUNT_LIMIT:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.count_limit",
                QStringLiteral("公开 API 报告 %1 个过滤驱动，超过 %2 行安全上限；本轮失败关闭。"))
                .arg(source.detailArgs[0])
                .arg(source.detailArgs[1]);
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_NOT_FOUND:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.class_init_not_found",
                QStringLiteral("%1：公开枚举确认旧式 FS filter，但在 DriverExtension+0x%2..0x%3 未找到结构签名唯一的 ClassInitData（NTSTATUS=0x%4）。"))
                .arg(entry.nameText)
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(QString::number(source.detailArgs[2], 16).toUpper())
                .arg(callbackEnumNtStatusText(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_AMBIGUOUS:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.class_init_ambiguous",
                QStringLiteral("%1：DriverExtension+0x%2..0x%3 出现多个结构签名候选；为避免误判，本轮失败关闭（NTSTATUS=0x%4）。"))
                .arg(entry.nameText)
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(QString::number(source.detailArgs[2], 16).toUpper())
                .arg(callbackEnumNtStatusText(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_CLASS_INIT_VALIDATED:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.class_init_validated",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；Size=%3；登记 %4 个 pre/post 回调；结构/版本证据已独立验证，各槽 owner 将逐项判定。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(source.detailArgs[2])
                .arg(source.detailArgs[3]);
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_MATCH:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.owner_match",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；%3；pair=%4；回调 owner 与登记驱动匹配（base=%5）。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(callbackEnumLegacyFsPairStateText(source.detailArgs[2]))
                .arg(source.detailArgs[2] & 0xFFFFFFFFULL)
                .arg(callbackEnumFormatAddress(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_MISMATCH:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.owner_mismatch",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；%3；pair=%4；回调模块 base=%5，与登记驱动 base=%6 不匹配，标记为可疑。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(callbackEnumLegacyFsPairStateText(source.detailArgs[2]))
                .arg(source.detailArgs[2] & 0xFFFFFFFFULL)
                .arg(callbackEnumFormatAddress(entry.moduleBase))
                .arg(callbackEnumFormatAddress(source.detailArgs[3]));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_OWNER_UNRESOLVED:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.owner_unresolved",
                QStringLiteral("ClassInitData=%1；DriverExtension+0x%2；%3；pair=%4；无法解析回调 owner（NTSTATUS=0x%5），状态保持未知。"))
                .arg(callbackEnumFormatAddress(source.detailArgs[0]))
                .arg(QString::number(source.detailArgs[1], 16).toUpper())
                .arg(callbackEnumLegacyFsPairStateText(source.detailArgs[2]))
                .arg(source.detailArgs[2] & 0xFFFFFFFFULL)
                .arg(callbackEnumNtStatusText(
                    static_cast<std::uint64_t>(
                        static_cast<std::uint32_t>(entry.lastStatus))));
        case KSWORD_ARK_CALLBACK_ENUM_DETAIL_LEGACY_FS_PUBLIC_ENUM_FAILED:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.public_enum_failed",
                QStringLiteral("公开 API 枚举失败；NTSTATUS=0x%1，返回数量=%2，分配容量=%3；未解释可能不完整的 DriverObject 数组。"))
                .arg(callbackEnumNtStatusText(source.detailArgs[0]))
                .arg(source.detailArgs[1])
                .arg(source.detailArgs[2]);
        default:
            return kernelText(
                "kernel.callback.enum.legacy_fs.detail.unknown_code",
                QStringLiteral("Legacy FS 诊断代码未知：%1。"))
                .arg(source.detailCode);
        }
    }

    QString callbackEnumRowStatusText(const std::uint32_t status, const long lastStatus)
    {
        switch (status)
        {
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNKNOWN:
            return kernelText("kernel.callback.enum.status.unknown", QStringLiteral("未知"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_OK:
            return kernelText("kernel.callback.enum.status.ok", QStringLiteral("可见/成功"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED:
            return kernelText("kernel.callback.enum.status.not_registered", QStringLiteral("未注册"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED:
            return kernelText("kernel.callback.enum.status.unsupported", QStringLiteral("当前不支持"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED:
            return kernelText("kernel.callback.enum.status.query_failed", QStringLiteral("查询失败(0x%1)"))
                .arg(QString::number(static_cast<quint32>(lastStatus), 16).rightJustified(8, QLatin1Char('0')).toUpper());
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_BUFFER_TRUNCATED:
            return kernelText("kernel.callback.enum.status.buffer_truncated", QStringLiteral("缓冲截断"));
        case KSWORD_ARK_CALLBACK_ENUM_STATUS_SUSPICIOUS:
            return kernelText("kernel.callback.enum.status.suspicious", QStringLiteral("可疑"));
        default:
            return kernelText("kernel.callback.enum.placeholder.unknown_with_value", QStringLiteral("未知(%1)"))
                .arg(status);
        }
    }

    KernelCallbackEnumEntry callbackEnumConvertEntry(const ksword::ark::CallbackEnumEntry& source)
    {
        KernelCallbackEnumEntry row;
        row.callbackClass = source.callbackClass;
        row.source = source.source;
        row.status = source.status;
        row.fieldFlags = source.fieldFlags;
        row.trustFlags = source.trustFlags;
        row.removeBehavior = source.removeBehavior;
        row.removeFlags = source.removeBehavior;
        row.operationMask = source.operationMask;
        row.objectTypeMask = source.objectTypeMask;
        row.registrationType = source.registrationType;
        row.generation = source.generation;
        row.lastStatus = source.lastStatus;
        row.callbackAddress = source.callbackAddress;
        row.contextAddress = source.contextAddress;
        row.registrationAddress = source.registrationAddress;
        row.identityHash = source.identityHash;
        row.rawStorageValue = source.rawStorageValue;
        row.moduleBase = source.moduleBase;
        row.moduleSize = source.moduleSize;
        row.classText = callbackEnumClassText(source.callbackClass);
        row.registrationTypeText = callbackEnumRegistrationTypeText(source.registrationType);
        row.sourceText = callbackEnumSourceText(source.source);
        row.sourceTrustText = callbackEnumSourceTrustText(row);
        row.removePolicyText = callbackEnumRemovePolicyText(row);
        row.statusText = callbackEnumRowStatusText(source.status, source.lastStatus);
        row.nameText = QString::fromStdWString(source.name);
        row.altitudeText = QString::fromStdWString(source.altitude);
        row.modulePathText = QString::fromStdWString(source.modulePath);
        row.detailText = QString::fromStdWString(source.detail);
        row.detailText = callbackEnumLocalizedDetailText(source, row);
        row.requiresSecondConfirmation = callbackEnumRequiresSecondConfirmation(row);
        row.fallbackPatternOnly = callbackEnumIsFallbackPatternSource(row.source);
        return row;
    }

    enum class CallbackEnumColumn : int
    {
        Class = 0,
        RegistrationType,
        Source,
        Trust,
        Status,
        RemovePolicy,
        Name,
        CallbackAddress,
        Module,
        Company,
        FileVersion,
        FileDescription,
        Altitude,
        Count
    };

    QString callbackEnumColumnHeaderText(const CallbackEnumColumn column)
    {
        // 作用：把回调遍历表格列枚举映射为右键菜单和剪贴板表头文本。
        // 返回：该列对应的中文表头；未知列返回“未知列”。
        switch (column)
        {
        case CallbackEnumColumn::Class:
            return kernelText("kernel.callback.enum.header.class", QStringLiteral("类别"));
        case CallbackEnumColumn::RegistrationType:
            return kernelText("kernel.callback.enum.header.registration_type", QStringLiteral("注册类型"));
        case CallbackEnumColumn::Source:
            return kernelText("kernel.callback.enum.header.source", QStringLiteral("来源"));
        case CallbackEnumColumn::Trust:
            return kernelText("kernel.callback.enum.header.trust", QStringLiteral("可信状态"));
        case CallbackEnumColumn::Status:
            return kernelText("kernel.callback.enum.header.status", QStringLiteral("状态"));
        case CallbackEnumColumn::RemovePolicy:
            return kernelText("kernel.callback.enum.header.remove_policy", QStringLiteral("移除策略"));
        case CallbackEnumColumn::Name:
            return kernelText("kernel.callback.enum.header.name", QStringLiteral("名称"));
        case CallbackEnumColumn::CallbackAddress:
            return kernelText("kernel.callback.enum.header.callback_address", QStringLiteral("回调/对象地址"));
        case CallbackEnumColumn::Module:
            return kernelText("kernel.callback.enum.header.module", QStringLiteral("模块"));
        case CallbackEnumColumn::Company:
            return kernelText("kernel.callback.enum.header.company", QStringLiteral("公司"));
        case CallbackEnumColumn::FileVersion:
            return kernelText("kernel.callback.enum.header.file_version", QStringLiteral("文件版本"));
        case CallbackEnumColumn::FileDescription:
            return kernelText("kernel.callback.enum.header.file_description", QStringLiteral("文件描述"));
        case CallbackEnumColumn::Altitude:
            return QStringLiteral("Altitude");
        default:
            return kernelText("kernel.callback.enum.header.unknown", QStringLiteral("未知列"));
        }
    }

    int callbackEnumVisibleColumnCount(QTableWidget* table)
    {
        // 作用：统计可见列，防止表头菜单隐藏最后一列。
        // 返回：当前可见列数。
        if (table == nullptr)
        {
            return 0;
        }

        int visibleCount = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++visibleCount;
            }
        }
        return visibleCount;
    }

    void callbackEnumInstallHeaderColumnMenu(QTableWidget* table)
    {
        // 作用：安装表头右键列显隐菜单；默认显示全部列，用户可按需隐藏。
        // 返回：无。
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* headerView = table->horizontalHeader();
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            headerView,
            &QHeaderView::customContextMenuRequested,
            table,
            [table, headerView](const QPoint& localPosition)
            {
                QMenu menu(table);
                menu.setStyleSheet(KswordTheme::ContextMenuStyle());
                for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* headerItem =
                        table->horizontalHeaderItem(columnIndex);
                    QAction* columnAction = menu.addAction(
                        headerItem != nullptr
                            ? headerItem->text()
                            : QStringLiteral("Column %1").arg(columnIndex));
                    columnAction->setCheckable(true);
                    columnAction->setChecked(!table->isColumnHidden(columnIndex));
                    columnAction->setData(columnIndex);
                }

                QAction* selectedAction =
                    menu.exec(headerView->viewport()->mapToGlobal(localPosition));
                if (selectedAction == nullptr)
                {
                    return;
                }

                const int columnIndex = selectedAction->data().toInt();
                const bool shouldShow = selectedAction->isChecked();
                if (!shouldShow && callbackEnumVisibleColumnCount(table) <= 1)
                {
                    table->setColumnHidden(columnIndex, false);
                    return;
                }

                table->setColumnHidden(columnIndex, !shouldShow);
            });
    }

    QString callbackEnumEntryColumnText(
        const KernelCallbackEnumEntry& entry,
        const CallbackEnumColumn column)
    {
        // 作用：从缓存行中提取指定表格列文本，保证复制菜单不依赖当前单元格对象。
        // 返回：可直接写入剪贴板的单列文本。
        switch (column)
        {
        case CallbackEnumColumn::Class:
            return entry.classText;
        case CallbackEnumColumn::RegistrationType:
            return entry.registrationTypeText;
        case CallbackEnumColumn::Source:
            return entry.sourceText;
        case CallbackEnumColumn::Trust:
            return entry.sourceTrustText;
        case CallbackEnumColumn::Status:
            return entry.statusText;
        case CallbackEnumColumn::RemovePolicy:
            return entry.removePolicyText;
        case CallbackEnumColumn::Name:
            return callbackEnumSafeText(entry.nameText);
        case CallbackEnumColumn::CallbackAddress:
            return callbackEnumPrimaryAddressText(entry);
        case CallbackEnumColumn::Module:
            return entry.modulePathText.isEmpty()
                ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>"))
                : entry.modulePathText;
        case CallbackEnumColumn::Company:
            return callbackEnumSafeText(entry.companyText);
        case CallbackEnumColumn::FileVersion:
            return callbackEnumSafeText(entry.fileVersionText);
        case CallbackEnumColumn::FileDescription:
            return callbackEnumSafeText(entry.fileDescriptionText);
        case CallbackEnumColumn::Altitude:
            return callbackEnumSafeText(entry.altitudeText);
        default:
            return QString();
        }
    }

    QString callbackEnumEntryAsTsv(const KernelCallbackEnumEntry& entry)
    {
        // 作用：把一条回调遍历记录按表格列顺序序列化为 TSV。
        // 返回：单行 TSV，不包含换行符。
        QStringList fieldList;
        fieldList.reserve(static_cast<int>(CallbackEnumColumn::Count));
        for (int columnIndex = 0; columnIndex < static_cast<int>(CallbackEnumColumn::Count); ++columnIndex)
        {
            fieldList.push_back(callbackEnumEntryColumnText(
                entry,
                static_cast<CallbackEnumColumn>(columnIndex)));
        }
        return fieldList.join('\t');
    }

    QString callbackEnumHeaderAsTsv()
    {
        // 作用：生成回调遍历表头 TSV，配合“复制表头+选中行”使用。
        // 返回：表头单行 TSV。
        QStringList headerList;
        headerList.reserve(static_cast<int>(CallbackEnumColumn::Count));
        for (int columnIndex = 0; columnIndex < static_cast<int>(CallbackEnumColumn::Count); ++columnIndex)
        {
            headerList.push_back(callbackEnumColumnHeaderText(static_cast<CallbackEnumColumn>(columnIndex)));
        }
        return headerList.join('\t');
    }

    std::vector<int> callbackEnumSelectedVisualRows(
        const QTableWidget* tableWidget,
        const int fallbackRow)
    {
        // 作用：收集当前可视表格中所有选中行，按可视行号排序去重。
        // 返回：可视行号数组；没有显式选择时使用 fallbackRow 兜底。
        std::vector<int> selectedRows;
        if (tableWidget == nullptr)
        {
            return selectedRows;
        }

        const QList<QTableWidgetItem*> selectedItems = tableWidget->selectedItems();
        selectedRows.reserve(static_cast<std::size_t>(selectedItems.size()));
        for (QTableWidgetItem* item : selectedItems)
        {
            if (item != nullptr)
            {
                selectedRows.push_back(item->row());
            }
        }

        if (selectedRows.empty() && fallbackRow >= 0)
        {
            selectedRows.push_back(fallbackRow);
        }

        std::sort(selectedRows.begin(), selectedRows.end());
        selectedRows.erase(std::unique(selectedRows.begin(), selectedRows.end()), selectedRows.end());
        return selectedRows;
    }

    std::vector<std::size_t> callbackEnumSelectedSourceIndices(
        const QTableWidget* tableWidget,
        const std::vector<KernelCallbackEnumEntry>& sourceRows,
        const int fallbackRow)
    {
        // 作用：把表格可视选中行转换成 m_callbackEnumRows 的源索引。
        // 返回：有效源索引数组，顺序与当前排序/筛选后的可视顺序一致。
        std::vector<std::size_t> sourceIndices;
        if (tableWidget == nullptr)
        {
            return sourceIndices;
        }

        const std::vector<int> selectedRows = callbackEnumSelectedVisualRows(tableWidget, fallbackRow);
        sourceIndices.reserve(selectedRows.size());
        for (const int visualRow : selectedRows)
        {
            QTableWidgetItem* classItem = tableWidget->item(
                visualRow,
                static_cast<int>(CallbackEnumColumn::Class));
            if (classItem == nullptr)
            {
                continue;
            }

            const std::size_t sourceIndex =
                static_cast<std::size_t>(classItem->data(Qt::UserRole).toULongLong());
            if (sourceIndex < sourceRows.size())
            {
                sourceIndices.push_back(sourceIndex);
            }
        }
        return sourceIndices;
    }

    void callbackEnumCopyTextToClipboard(const QString& contentText)
    {
        // 作用：统一写入系统剪贴板；QApplication 未就绪时静默跳过。
        // 返回：无。
        QClipboard* clipboard = QApplication::clipboard();
        if (clipboard != nullptr)
        {
            clipboard->setText(contentText);
        }
    }
}

void KernelDock::initializeCallbackEnumTab()
{
    if (m_callbackEnumPage == nullptr || m_callbackEnumLayout != nullptr)
    {
        return;
    }

    m_callbackEnumLayout = new QVBoxLayout(m_callbackEnumPage);
    m_callbackEnumLayout->setContentsMargins(4, 4, 4, 4);
    m_callbackEnumLayout->setSpacing(6);

    m_callbackEnumToolLayout = new QHBoxLayout();
    m_callbackEnumToolLayout->setContentsMargins(0, 0, 0, 0);
    m_callbackEnumToolLayout->setSpacing(6);

    m_refreshCallbackEnumButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_callbackEnumPage);
    m_refreshCallbackEnumButton->setToolTip(kernelText("kernel.callback.enum.toolbar.refresh.tooltip", QStringLiteral("刷新回调遍历结果")));
    m_refreshCallbackEnumButton->setStyleSheet(callbackEnumButtonStyle());
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshCallbackEnumButton);

    m_callbackEnumFilterEdit = new QLineEdit(m_callbackEnumPage);
    m_callbackEnumFilterEdit->setPlaceholderText(kernelText("kernel.callback.enum.toolbar.filter.placeholder", QStringLiteral("按类别/注册类型/来源/名称/地址/模块/公司/版本/描述筛选")));
    m_callbackEnumFilterEdit->setToolTip(kernelText("kernel.callback.enum.toolbar.filter.tooltip", QStringLiteral("输入关键字后实时过滤回调遍历结果")));
    m_callbackEnumFilterEdit->setClearButtonEnabled(true);
    m_callbackEnumFilterEdit->setStyleSheet(callbackEnumInputStyle());

    m_callbackEnumStatusLabel = new QLabel(kernelText("kernel.callback.enum.status.waiting", QStringLiteral("状态：等待刷新")), m_callbackEnumPage);
    m_callbackEnumStatusLabel->setStyleSheet(callbackEnumStatusLabelStyle(KswordTheme::TextSecondaryHex()));

    m_callbackEnumToolLayout->addWidget(m_refreshCallbackEnumButton, 0);
    m_callbackEnumToolLayout->addWidget(m_callbackEnumFilterEdit, 1);
    m_callbackEnumToolLayout->addWidget(m_callbackEnumStatusLabel, 0);
    m_callbackEnumLayout->addLayout(m_callbackEnumToolLayout);

    QSplitter* splitter = new QSplitter(Qt::Vertical, m_callbackEnumPage);
    m_callbackEnumLayout->addWidget(splitter, 1);

    QTabWidget* callbackViewTabs = new QTabWidget(splitter);
    m_callbackEnumTable = new ks::ui::VisibleTableWidget(callbackViewTabs);
    m_callbackEnumTable->setColumnCount(static_cast<int>(CallbackEnumColumn::Count));
    m_callbackEnumTable->setHorizontalHeaderLabels(QStringList{
        callbackEnumColumnHeaderText(CallbackEnumColumn::Class),
        callbackEnumColumnHeaderText(CallbackEnumColumn::RegistrationType),
        callbackEnumColumnHeaderText(CallbackEnumColumn::Source),
        callbackEnumColumnHeaderText(CallbackEnumColumn::Trust),
        callbackEnumColumnHeaderText(CallbackEnumColumn::Status),
        callbackEnumColumnHeaderText(CallbackEnumColumn::RemovePolicy),
        callbackEnumColumnHeaderText(CallbackEnumColumn::Name),
        callbackEnumColumnHeaderText(CallbackEnumColumn::CallbackAddress),
        callbackEnumColumnHeaderText(CallbackEnumColumn::Module),
        callbackEnumColumnHeaderText(CallbackEnumColumn::Company),
        callbackEnumColumnHeaderText(CallbackEnumColumn::FileVersion),
        callbackEnumColumnHeaderText(CallbackEnumColumn::FileDescription),
        callbackEnumColumnHeaderText(CallbackEnumColumn::Altitude)
        });
    m_callbackEnumTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_callbackEnumTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_callbackEnumTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_callbackEnumTable->setAlternatingRowColors(true);
    m_callbackEnumTable->setStyleSheet(callbackEnumSelectionStyle());
    m_callbackEnumTable->setCornerButtonEnabled(false);
    m_callbackEnumTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_callbackEnumTable->verticalHeader()->setVisible(false);
    m_callbackEnumTable->horizontalHeader()->setStyleSheet(callbackEnumHeaderStyle());
    m_callbackEnumTable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_callbackEnumTable->horizontalHeader()->setSectionResizeMode(static_cast<int>(CallbackEnumColumn::Name), QHeaderView::Stretch);
    m_callbackEnumTable->setColumnWidth(static_cast<int>(CallbackEnumColumn::Trust), 170);
    m_callbackEnumTable->setColumnWidth(static_cast<int>(CallbackEnumColumn::RemovePolicy), 200);
    m_callbackEnumTable->setColumnWidth(static_cast<int>(CallbackEnumColumn::CallbackAddress), 180);
    m_callbackEnumTable->setColumnWidth(static_cast<int>(CallbackEnumColumn::Module), 220);
    m_callbackEnumTable->setColumnWidth(static_cast<int>(CallbackEnumColumn::FileDescription), 220);
    callbackEnumInstallHeaderColumnMenu(m_callbackEnumTable);
    callbackViewTabs->addTab(
        m_callbackEnumTable,
        kernelText("kernel.callback.enum.view.list", QStringLiteral("回调列表")));

    m_minifilterCallbackTree = new QTreeWidget(callbackViewTabs);
    m_minifilterCallbackTree->setColumnCount(10);
    m_minifilterCallbackTree->setHeaderLabels(QStringList{
        kernelText("kernel.callback.enum.minifilter.header.filter_operation", QStringLiteral("Filter / 操作")),
        kernelText("kernel.callback.enum.minifilter.header.stage", QStringLiteral("类型")),
        kernelText("kernel.callback.enum.minifilter.header.callback", QStringLiteral("Pre/Post 回调")),
        kernelText("kernel.callback.enum.minifilter.header.driver", QStringLiteral("驱动")),
        kernelText("kernel.callback.enum.minifilter.header.path", QStringLiteral("驱动路径")),
        kernelText("kernel.callback.enum.minifilter.header.company", QStringLiteral("公司")),
        kernelText("kernel.callback.enum.minifilter.header.file_version", QStringLiteral("文件版本")),
        kernelText("kernel.callback.enum.minifilter.header.description", QStringLiteral("描述")),
        QStringLiteral("Altitude"),
        kernelText("kernel.callback.enum.minifilter.header.source", QStringLiteral("来源/可信状态"))
        });
    m_minifilterCallbackTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_minifilterCallbackTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_minifilterCallbackTree->setAlternatingRowColors(true);
    m_minifilterCallbackTree->setUniformRowHeights(true);
    m_minifilterCallbackTree->setStyleSheet(callbackEnumSelectionStyle());
    m_minifilterCallbackTree->header()->setStyleSheet(callbackEnumHeaderStyle());
    m_minifilterCallbackTree->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
    m_minifilterCallbackTree->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_minifilterCallbackTree->setColumnWidth(2, 180);
    m_minifilterCallbackTree->setColumnWidth(4, 280);
    m_minifilterCallbackTree->setToolTip(kernelText(
        "kernel.callback.enum.minifilter.tooltip",
        QStringLiteral("按 Filter 展开真实 IRP_MJ_* Pre/Post 回调；双击回调可查看驱动文件详情")));
    callbackViewTabs->addTab(
        m_minifilterCallbackTree,
        kernelText("kernel.callback.enum.view.minifilter_tree", QStringLiteral("Minifilter 回调树")));

    m_callbackEnumDetailEditor = new CodeEditorWidget(splitter);
    m_callbackEnumDetailEditor->setReadOnly(true);
    m_callbackEnumDetailEditor->setText(kernelText("kernel.callback.enum.detail.initial", QStringLiteral("请选择一条回调记录查看详情。")));

    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    // 回调遍历与 CID 表一样受全局四类详情布局控制。QTabWidget 是 splitter 的直接
    // 子面板，注册后由统一宿主在下方折叠、右侧、行内与独立窗口之间重排。
    ks::ui::DetailLayoutHost* const callbackDetailLayoutHost =
        ks::ui::DetailLayoutRegistry::registerHost(
            m_callbackEnumTable,
            m_callbackEnumDetailEditor,
            m_callbackEnumPage);

    initializeCallbackRemovePanel();

    connect(m_refreshCallbackEnumButton, &QPushButton::clicked, this, [this]() {
        refreshCallbackEnumAsync();
    });
    connect(m_callbackEnumFilterEdit, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        rebuildCallbackEnumTable(filterText.trimmed());
    });
    connect(callbackViewTabs, &QTabWidget::currentChanged, this,
        [this, callbackViewTabs, callbackDetailLayoutHost](const int tabIndex) {
            if (callbackDetailLayoutHost == nullptr)
            {
                return;
            }
            callbackDetailLayoutHost->clearEmbeddedDetails();
            callbackDetailLayoutHost->setTableView(
                tabIndex == callbackViewTabs->indexOf(m_minifilterCallbackTree)
                    ? static_cast<QAbstractItemView*>(m_minifilterCallbackTree)
                    : static_cast<QAbstractItemView*>(m_callbackEnumTable));
        });
    connect(m_callbackEnumTable, &QTableWidget::currentCellChanged, this, [this](int, int, int, int) {
        showCallbackEnumDetailByCurrentRow();
    });
    connect(m_callbackEnumTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showCallbackEnumContextMenu(localPosition);
    });
    connect(m_minifilterCallbackTree, &QTreeWidget::currentItemChanged, this, [this](QTreeWidgetItem* currentItem) {
        if (currentItem == nullptr)
        {
            showCallbackEnumDetail(nullptr);
            return;
        }
        const std::size_t sourceIndex = static_cast<std::size_t>(
            currentItem->data(0, Qt::UserRole).toULongLong());
        showCallbackEnumDetail(
            sourceIndex < m_callbackEnumRows.size() ? &m_callbackEnumRows[sourceIndex] : nullptr);
    });
    connect(m_minifilterCallbackTree, &QTreeWidget::itemDoubleClicked, this, [this](QTreeWidgetItem* item) {
        if (item == nullptr)
        {
            return;
        }
        const std::size_t sourceIndex = static_cast<std::size_t>(
            item->data(0, Qt::UserRole).toULongLong());
        if (sourceIndex >= m_callbackEnumRows.size())
        {
            return;
        }
        const QString modulePath = callbackEnumNormalizeModulePath(
            m_callbackEnumRows[sourceIndex].modulePathText);
        if (!modulePath.isEmpty() && QFileInfo::exists(modulePath))
        {
            callbackEnumShowModuleFileDetailDialog(this, modulePath);
        }
    });
}

void KernelDock::refreshCallbackEnumAsync()
{
    if (m_callbackEnumRefreshRunning.exchange(true))
    {
        return;
    }

    if (m_refreshCallbackEnumButton != nullptr)
    {
        m_refreshCallbackEnumButton->setEnabled(false);
    }
    if (m_callbackEnumStatusLabel != nullptr)
    {
        m_callbackEnumStatusLabel->setText(kernelText("kernel.callback.enum.status.refreshing", QStringLiteral("状态：刷新中...")));
        m_callbackEnumStatusLabel->setStyleSheet(callbackEnumStatusLabelStyle(KswordTheme::PrimaryBlueHex));
    }

    QPointer<KernelDock> guardThis(this);
    std::thread([guardThis]() {
        std::vector<KernelCallbackEnumEntry> resultRows;
        QString errorText;
        std::uint32_t responseFlags = 0;
        std::uint32_t responseVersion = 0;
        std::uint32_t snapshotPageCount = 0;
        std::uint32_t snapshotRetryCount = 0;
        std::uint64_t snapshotHash = 0;
        bool snapshotConsistent = false;
        const ksword::ark::DriverClient driverClient;
        const ksword::ark::CallbackEnumResult enumResult = driverClient.enumerateCallbacks();
        const bool success = enumResult.io.ok;

        if (success)
        {
            QHash<QString, CallbackEnumVersionText> versionCache;
            responseFlags = enumResult.flags;
            responseVersion = enumResult.version;
            snapshotPageCount = enumResult.pageCount;
            snapshotRetryCount = enumResult.snapshotRetryCount;
            snapshotHash = enumResult.snapshotHash;
            snapshotConsistent = enumResult.snapshotConsistent;
            resultRows.reserve(enumResult.entries.size());
            for (const ksword::ark::CallbackEnumEntry& entry : enumResult.entries)
            {
                KernelCallbackEnumEntry row = callbackEnumConvertEntry(entry);
                const QString modulePath = callbackEnumNormalizeModulePath(row.modulePathText);
                if (!modulePath.isEmpty() && QFileInfo::exists(modulePath))
                {
                    const QString cacheKey = modulePath.toLower();
                    auto versionIterator = versionCache.constFind(cacheKey);
                    if (versionIterator == versionCache.cend())
                    {
                        versionCache.insert(
                            cacheKey,
                            callbackEnumQueryVersionText(modulePath));
                        versionIterator = versionCache.constFind(cacheKey);
                    }
                    const CallbackEnumVersionText versionText = versionIterator.value();
                    row.companyText = versionText.company;
                    row.fileVersionText = versionText.fileVersion;
                    row.fileDescriptionText = versionText.description;
                }
                resultRows.push_back(std::move(row));
            }
        }
        else
        {
            errorText = kernelText("kernel.callback.enum.error.io", QStringLiteral("回调遍历 IOCTL 调用失败。\nWin32=%1\n详情=%2"))
                .arg(enumResult.io.win32Error)
                .arg(callbackEnumIoMessageText(QString::fromStdString(enumResult.io.message)));
        }

        QMetaObject::invokeMethod(
            guardThis,
            [guardThis,
             success,
             errorText,
             responseFlags,
             responseVersion,
             snapshotPageCount,
             snapshotRetryCount,
             snapshotHash,
             snapshotConsistent,
             resultRows = std::move(resultRows)]() mutable {
            const auto deferredRows =
                std::make_shared<std::vector<KernelCallbackEnumEntry>>(std::move(resultRows));
            auto commitResult = [
                guardThis,
                success,
                errorText,
                responseFlags,
                responseVersion,
                snapshotPageCount,
                snapshotRetryCount,
                snapshotHash,
                snapshotConsistent,
                deferredRows]() mutable
            {
            std::vector<KernelCallbackEnumEntry>& resultRows = *deferredRows;
            if (guardThis == nullptr)
            {
                return;
            }

            guardThis->m_callbackEnumRefreshRunning.store(false);
            if (guardThis->m_refreshCallbackEnumButton != nullptr)
            {
                guardThis->m_refreshCallbackEnumButton->setEnabled(true);
            }

            if (!success)
            {
                guardThis->m_callbackEnumStatusLabel->setText(kernelText("kernel.callback.enum.status.failed", QStringLiteral("状态：刷新失败")));
                guardThis->m_callbackEnumStatusLabel->setStyleSheet(callbackEnumStatusLabelStyle(KswordTheme::ErrorHex()));
                guardThis->m_callbackEnumDetailEditor->setText(errorText);
                return;
            }

            guardThis->m_callbackEnumRows = std::move(resultRows);
            guardThis->rebuildCallbackEnumTable(guardThis->m_callbackEnumFilterEdit->text().trimmed());

            std::size_t unsupportedCount = 0U;
            for (const KernelCallbackEnumEntry& entry : guardThis->m_callbackEnumRows)
            {
                if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED)
                {
                    ++unsupportedCount;
                }
            }

            const bool truncated = (responseFlags & KSWORD_ARK_ENUM_CALLBACK_RESPONSE_FLAG_TRUNCATED) != 0U;
            const QString snapshotSuffix =
                responseVersion >= KSWORD_ARK_CALLBACK_ENUM_PROTOCOL_VERSION && snapshotConsistent
                ? kernelText(
                    "kernel.callback.enum.status.snapshot_consistent_suffix",
                    QStringLiteral("，快照一致（%1 页，重试 %2 次，Hash %3）"))
                    .arg(snapshotPageCount)
                    .arg(snapshotRetryCount)
                    .arg(callbackEnumFormatAddress(snapshotHash))
                : kernelText(
                    "kernel.callback.enum.status.snapshot_legacy_suffix",
                    QStringLiteral("，旧协议未提供快照一致性校验（%1 页）"))
                    .arg(snapshotPageCount);
            guardThis->m_callbackEnumStatusLabel->setText(
                kernelText("kernel.callback.enum.status.summary", QStringLiteral("状态：已刷新 %1 项，私有未支持 %2 项%3%4"))
                .arg(guardThis->m_callbackEnumRows.size())
                .arg(unsupportedCount)
                .arg(truncated ? kernelText("kernel.callback.enum.status.truncated_suffix", QStringLiteral("，响应截断")) : QString())
                .arg(snapshotSuffix));
            guardThis->m_callbackEnumStatusLabel->setStyleSheet(callbackEnumStatusLabelStyle(
                truncated || !snapshotConsistent ? KswordTheme::WarningHex() : KswordTheme::SuccessHex()));

            if (guardThis->m_callbackEnumTable->rowCount() > 0)
            {
                guardThis->m_callbackEnumTable->setCurrentCell(0, 0);
            }
            else
            {
                guardThis->m_callbackEnumDetailEditor->setText(kernelText("kernel.callback.enum.empty", QStringLiteral("当前环境未返回可见回调记录。")));
            }
            };

            if (guardThis == nullptr)
            {
                return;
            }
            if (ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
                guardThis.data(),
                QStringLiteral("kernel-callback-enum-snapshot-apply"),
                { guardThis->m_callbackEnumTable, guardThis->m_minifilterCallbackTree },
                commitResult))
            {
                return;
            }
            commitResult();
        }, Qt::QueuedConnection);
    }).detach();
}

void KernelDock::rebuildCallbackEnumTable(const QString& filterKeyword)
{
    if (m_callbackEnumTable == nullptr)
    {
        return;
    }

    m_callbackEnumTable->setSortingEnabled(false);
    m_callbackEnumTable->setRowCount(0);

    for (std::size_t sourceIndex = 0; sourceIndex < m_callbackEnumRows.size(); ++sourceIndex)
    {
        const KernelCallbackEnumEntry& entry = m_callbackEnumRows[sourceIndex];
        const QString addressText = callbackEnumPrimaryAddressText(entry);
        const QString moduleText = entry.modulePathText.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>"))
            : entry.modulePathText;
        const bool matched = filterKeyword.isEmpty()
            || entry.classText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.registrationTypeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceTrustText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.removePolicyText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.nameText.contains(filterKeyword, Qt::CaseInsensitive)
            || addressText.contains(filterKeyword, Qt::CaseInsensitive)
            || moduleText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.companyText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileVersionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileDescriptionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.altitudeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.detailText.contains(filterKeyword, Qt::CaseInsensitive);
        if (!matched)
        {
            continue;
        }

        const int rowIndex = m_callbackEnumTable->rowCount();
        m_callbackEnumTable->insertRow(rowIndex);

        auto* classItem = new QTableWidgetItem(entry.classText);
        classItem->setData(Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        auto* registrationTypeItem = new QTableWidgetItem(entry.registrationTypeText);
        auto* sourceItem = new QTableWidgetItem(entry.sourceText);
        auto* trustItem = new QTableWidgetItem(entry.sourceTrustText);
        auto* statusItem = new QTableWidgetItem(entry.statusText);
        auto* removePolicyItem = new QTableWidgetItem(entry.removePolicyText);
        auto* nameItem = new QTableWidgetItem(callbackEnumSafeText(entry.nameText));
        auto* addressItem = new QTableWidgetItem(addressText);
        auto* moduleItem = new QTableWidgetItem(moduleText);
        auto* companyItem = new QTableWidgetItem(callbackEnumSafeText(entry.companyText));
        auto* fileVersionItem = new QTableWidgetItem(callbackEnumSafeText(entry.fileVersionText));
        auto* fileDescriptionItem = new QTableWidgetItem(callbackEnumSafeText(entry.fileDescriptionText));
        auto* altitudeItem = new QTableWidgetItem(callbackEnumSafeText(entry.altitudeText));

        if (callbackEnumIsTrustedSource(entry))
        {
            trustItem->setForeground(QBrush(KswordTheme::SuccessColor()));
        }
        else if (entry.fallbackPatternOnly)
        {
            trustItem->setForeground(QBrush(KswordTheme::WarningColor()));
        }
        else if (callbackEnumIsUnsupportedSource(entry))
        {
            trustItem->setForeground(QBrush(KswordTheme::TextSecondaryColor()));
        }

        if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_SUSPICIOUS)
        {
            statusItem->setForeground(QBrush(KswordTheme::ErrorColor()));
        }
        else if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNKNOWN)
        {
            statusItem->setForeground(QBrush(KswordTheme::WarningColor()));
        }
        else if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_UNSUPPORTED)
        {
            statusItem->setForeground(QBrush(KswordTheme::WarningColor()));
        }
        else if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_QUERY_FAILED)
        {
            statusItem->setForeground(QBrush(KswordTheme::ErrorColor()));
        }

        switch (callbackEnumRemovePolicyKind(entry))
        {
        case CallbackEnumRemovePolicyKind::RemovableVerified:
            removePolicyItem->setForeground(QBrush(KswordTheme::SuccessColor()));
            break;
        case CallbackEnumRemovePolicyKind::RemovableCandidate:
        case CallbackEnumRemovePolicyKind::ExperimentalOnly:
            removePolicyItem->setForeground(QBrush(KswordTheme::WarningColor()));
            break;
        case CallbackEnumRemovePolicyKind::NotRemovable:
        default:
            removePolicyItem->setForeground(QBrush(KswordTheme::TextSecondaryColor()));
            break;
        }

        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Class), classItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::RegistrationType), registrationTypeItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Source), sourceItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Trust), trustItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Status), statusItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::RemovePolicy), removePolicyItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Name), nameItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::CallbackAddress), addressItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Module), moduleItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Company), companyItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::FileVersion), fileVersionItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::FileDescription), fileDescriptionItem);
        m_callbackEnumTable->setItem(rowIndex, static_cast<int>(CallbackEnumColumn::Altitude), altitudeItem);
    }

    m_callbackEnumTable->setSortingEnabled(true);

    if (m_minifilterCallbackTree == nullptr)
    {
        return;
    }

    m_minifilterCallbackTree->setUpdatesEnabled(false);
    m_minifilterCallbackTree->clear();
    QHash<qulonglong, QTreeWidgetItem*> filterParents;
    const auto entryMatchesFilter = [&filterKeyword](const KernelCallbackEnumEntry& entry) {
        const QString addressText = callbackEnumPrimaryAddressText(entry);
        return filterKeyword.isEmpty()
            || entry.classText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.registrationTypeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.sourceTrustText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.statusText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.nameText.contains(filterKeyword, Qt::CaseInsensitive)
            || addressText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.modulePathText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.companyText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileVersionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.fileDescriptionText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.altitudeText.contains(filterKeyword, Qt::CaseInsensitive)
            || entry.detailText.contains(filterKeyword, Qt::CaseInsensitive);
    };

    for (std::size_t sourceIndex = 0; sourceIndex < m_callbackEnumRows.size(); ++sourceIndex)
    {
        const KernelCallbackEnumEntry& entry = m_callbackEnumRows[sourceIndex];
        const bool isFilterParent =
            entry.callbackClass == KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER
            && entry.source == KSWORD_ARK_CALLBACK_ENUM_SOURCE_FLTMGR_ENUMERATION
            && entry.callbackAddress == 0U
            && entry.registrationAddress != 0U;
        if (!isFilterParent)
        {
            continue;
        }

        auto* parentItem = new QTreeWidgetItem(m_minifilterCallbackTree);
        parentItem->setText(0, callbackEnumSafeText(entry.nameText));
        parentItem->setText(
            1,
            kernelText("kernel.callback.enum.minifilter.type.filter", QStringLiteral("Filter")));
        parentItem->setText(8, callbackEnumSafeText(entry.altitudeText));
        parentItem->setText(9, entry.sourceText + QStringLiteral(" / ") + entry.sourceTrustText);
        parentItem->setData(0, Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        parentItem->setData(0, Qt::UserRole + 1, entryMatchesFilter(entry));
        parentItem->setData(0, Qt::UserRole + 2, false);
        parentItem->setToolTip(0, entry.detailText);
        parentItem->setExpanded(true);
        filterParents.insert(static_cast<qulonglong>(entry.registrationAddress), parentItem);
    }

    for (std::size_t sourceIndex = 0; sourceIndex < m_callbackEnumRows.size(); ++sourceIndex)
    {
        const KernelCallbackEnumEntry& entry = m_callbackEnumRows[sourceIndex];
        if (entry.callbackClass != KSWORD_ARK_CALLBACK_ENUM_CLASS_MINIFILTER
            || entry.contextAddress == 0U)
        {
            continue;
        }

        QTreeWidgetItem* parentItem =
            filterParents.value(static_cast<qulonglong>(entry.contextAddress), nullptr);
        if (parentItem == nullptr)
        {
            continue;
        }

        QString modulePath = callbackEnumNormalizeModulePath(entry.modulePathText);
        if (modulePath.isEmpty())
        {
            modulePath = entry.modulePathText;
        }
        const QString moduleFileName = modulePath.isEmpty()
            ? QString()
            : QFileInfo(modulePath).fileName();
        QString stageText;
        if (entry.nameText.endsWith(QStringLiteral("/ PreOperation"), Qt::CaseInsensitive))
        {
            stageText = QStringLiteral("PreOperation");
        }
        else if (entry.nameText.endsWith(QStringLiteral("/ PostOperation"), Qt::CaseInsensitive))
        {
            stageText = QStringLiteral("PostOperation");
        }
        else
        {
            stageText = entry.statusText;
        }

        auto* callbackItem = new QTreeWidgetItem(parentItem);
        callbackItem->setText(0, callbackEnumSafeText(entry.nameText));
        callbackItem->setText(1, stageText);
        callbackItem->setText(
            2,
            entry.callbackAddress == 0U
                ? kernelText("kernel.callback.enum.address.none", QStringLiteral("<无回调地址>"))
                : callbackEnumFormatAddress(entry.callbackAddress));
        callbackItem->setText(3, moduleFileName);
        callbackItem->setText(4, modulePath);
        callbackItem->setText(5, entry.companyText);
        callbackItem->setText(6, entry.fileVersionText);
        callbackItem->setText(7, entry.fileDescriptionText);
        callbackItem->setText(8, callbackEnumSafeText(entry.altitudeText));
        callbackItem->setText(9, entry.sourceText + QStringLiteral(" / ") + entry.sourceTrustText);
        callbackItem->setData(0, Qt::UserRole, static_cast<qulonglong>(sourceIndex));
        callbackItem->setData(0, Qt::UserRole + 1, entryMatchesFilter(entry));
        callbackItem->setToolTip(0, entry.detailText);
        callbackItem->setToolTip(
            4,
            kernelText(
                "kernel.callback.enum.minifilter.path.tooltip",
                QStringLiteral("双击此回调可查看驱动文件常规信息和 PE 明细")));
        if (entry.fallbackPatternOnly)
        {
            callbackItem->setForeground(9, QBrush(KswordTheme::WarningColor()));
        }

        if (parentItem->text(4).isEmpty() && !modulePath.isEmpty())
        {
            parentItem->setText(3, moduleFileName);
            parentItem->setText(4, modulePath);
            parentItem->setText(5, entry.companyText);
            parentItem->setText(6, entry.fileVersionText);
            parentItem->setText(7, entry.fileDescriptionText);
        }
        if (entryMatchesFilter(entry))
        {
            parentItem->setData(0, Qt::UserRole + 2, true);
        }
    }

    for (int parentIndex = 0; parentIndex < m_minifilterCallbackTree->topLevelItemCount(); ++parentIndex)
    {
        QTreeWidgetItem* parentItem = m_minifilterCallbackTree->topLevelItem(parentIndex);
        const bool parentMatched = parentItem->data(0, Qt::UserRole + 1).toBool();
        const bool childMatched = parentItem->data(0, Qt::UserRole + 2).toBool();
        parentItem->setHidden(!filterKeyword.isEmpty() && !parentMatched && !childMatched);
        for (int childIndex = 0; childIndex < parentItem->childCount(); ++childIndex)
        {
            QTreeWidgetItem* childItem = parentItem->child(childIndex);
            const bool rowMatched = childItem->data(0, Qt::UserRole + 1).toBool();
            childItem->setHidden(!filterKeyword.isEmpty() && !parentMatched && !rowMatched);
        }
    }
    m_minifilterCallbackTree->setUpdatesEnabled(true);
}

bool KernelDock::currentCallbackEnumSourceIndex(std::size_t& sourceIndexOut) const
{
    sourceIndexOut = 0U;
    if (m_callbackEnumTable == nullptr)
    {
        return false;
    }

    const int currentRow = m_callbackEnumTable->currentRow();
    if (currentRow < 0)
    {
        return false;
    }

    QTableWidgetItem* classItem = m_callbackEnumTable->item(currentRow, static_cast<int>(CallbackEnumColumn::Class));
    if (classItem == nullptr)
    {
        return false;
    }

    sourceIndexOut = static_cast<std::size_t>(classItem->data(Qt::UserRole).toULongLong());
    return sourceIndexOut < m_callbackEnumRows.size();
}

const KernelCallbackEnumEntry* KernelDock::currentCallbackEnumEntry() const
{
    std::size_t sourceIndex = 0U;
    if (!currentCallbackEnumSourceIndex(sourceIndex))
    {
        return nullptr;
    }
    return &m_callbackEnumRows[sourceIndex];
}

void KernelDock::showCallbackEnumDetailByCurrentRow()
{
    showCallbackEnumDetail(currentCallbackEnumEntry());
}

void KernelDock::showCallbackEnumDetail(const KernelCallbackEnumEntry* entry)
{
    if (m_callbackEnumDetailEditor == nullptr)
    {
        return;
    }

    if (entry == nullptr)
    {
        m_callbackEnumDetailEditor->setText(kernelText("kernel.callback.enum.detail.initial", QStringLiteral("请选择一条回调记录查看详情。")));
        return;
    }

    const QString win32ModulePath = callbackEnumNormalizeModulePath(entry->modulePathText);
    const QString detailText = kernelText("kernel.callback.enum.detail.full_v2", QStringLiteral(
        "类别: %1\n"
        "注册类型: %2\n"
        "来源: %3\n"
        "可信状态: %4\n"
        "移除策略: %5\n"
        "是否需要二次确认: %6\n"
        "是否仅为定位线索: %7\n"
        "状态: %8\n"
        "名称: %9\n"
        "Altitude: %10\n"
        "主地址显示: %11\n"
        "真实回调地址: %12\n"
        "上下文/诊断值: %13\n"
        "注册句柄/Cookie/全局节点: %14\n"
        "模块路径: %15\n"
        "Win32模块路径: %16\n"
        "公司: %17\n"
        "文件版本: %18\n"
        "文件描述: %19\n"
        "模块基址: %20\n"
        "模块大小: 0x%21\n"
        "操作掩码: 0x%22\n"
        "对象类型掩码: 0x%23\n"
        "字段标志: 0x%24\n"
        "可信标志: 0x%25\n"
        "移除行为: 0x%26\n"
        "移除标志: 0x%27\n"
        "Generation: %28\n"
        "IdentityHash: %29\n"
        "RawStorageValue: %30\n"
        "LastStatus: 0x%31\n\n"
        "说明: 主地址优先显示真实回调函数；无法获取时会显示可用于定位的节点或标识值。\n\n"
        "详情:\n%32"))
        .arg(entry->classText)
        .arg(entry->registrationTypeText)
        .arg(entry->sourceText)
        .arg(entry->sourceTrustText)
        .arg(entry->removePolicyText)
        .arg(callbackEnumYesNoText(entry->requiresSecondConfirmation))
        .arg(callbackEnumYesNoText(entry->fallbackPatternOnly))
        .arg(entry->statusText)
        .arg(callbackEnumSafeText(entry->nameText))
        .arg(callbackEnumSafeText(entry->altitudeText))
        .arg(callbackEnumPrimaryAddressText(*entry))
        .arg(callbackEnumFormatAddress(entry->callbackAddress))
        .arg(callbackEnumFormatAddress(entry->contextAddress))
        .arg(callbackEnumFormatAddress(entry->registrationAddress))
        .arg(entry->modulePathText.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.unresolved", QStringLiteral("<未解析>"))
            : entry->modulePathText)
        .arg(win32ModulePath.isEmpty()
            ? kernelText("kernel.callback.enum.placeholder.unmapped", QStringLiteral("<不可映射或不存在>"))
            : win32ModulePath)
        .arg(callbackEnumSafeText(entry->companyText))
        .arg(callbackEnumSafeText(entry->fileVersionText))
        .arg(callbackEnumSafeText(entry->fileDescriptionText))
        .arg(callbackEnumFormatAddress(entry->moduleBase))
        .arg(QString::number(static_cast<qulonglong>(entry->moduleSize), 16).toUpper())
        .arg(static_cast<qulonglong>(entry->operationMask), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->objectTypeMask), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->fieldFlags), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->trustFlags), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->removeBehavior), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->removeFlags), 8, 16, QChar('0'))
        .arg(static_cast<qulonglong>(entry->generation))
        .arg(callbackEnumIdentityHashText(entry->identityHash))
        .arg(callbackEnumFormatAddress(entry->rawStorageValue))
        .arg(static_cast<qulonglong>(static_cast<std::uint32_t>(entry->lastStatus)), 8, 16, QChar('0'))
        .arg(callbackEnumSafeText(entry->detailText, kernelText("kernel.callback.enum.placeholder.no_detail", QStringLiteral("<无详情>"))));

    m_callbackEnumDetailEditor->setText(detailText);
}

void KernelDock::showCallbackEnumContextMenu(const QPoint& localPosition)
{
    if (m_callbackEnumTable == nullptr)
    {
        return;
    }

    // 右键选区规则：
    // - 点在未选中行上时切换为该单行；
    // - 点在已选中行上时保留 Ctrl 多选集合；
    // - 点在空白处时保留现有选择，复制动作继续对当前选择生效。
    QTableWidgetItem* clickedItem = m_callbackEnumTable->itemAt(localPosition);
    const int clickedRow = clickedItem != nullptr ? clickedItem->row() : -1;
    const int clickedColumn = m_callbackEnumTable->columnAt(localPosition.x());
    if (clickedItem != nullptr)
    {
        if (!clickedItem->isSelected())
        {
            m_callbackEnumTable->clearSelection();
            m_callbackEnumTable->setCurrentItem(clickedItem);
            m_callbackEnumTable->selectRow(clickedRow);
        }
        else
        {
            if (QItemSelectionModel* selectionModel = m_callbackEnumTable->selectionModel())
            {
                // 右键点在已选中行时只移动当前单元格，不清空 Ctrl 多选集合。
                selectionModel->setCurrentIndex(
                    m_callbackEnumTable->indexFromItem(clickedItem),
                    QItemSelectionModel::NoUpdate);
            }
        }
    }

    const int fallbackRow = clickedRow >= 0 ? clickedRow : m_callbackEnumTable->currentRow();
    const std::vector<std::size_t> selectedSourceIndices =
        callbackEnumSelectedSourceIndices(m_callbackEnumTable, m_callbackEnumRows, fallbackRow);
    const bool hasSelection = !selectedSourceIndices.empty();
    QString clickedModulePath;
    if (clickedRow >= 0)
    {
        std::vector<std::size_t> clickedSourceIndices =
            callbackEnumSelectedSourceIndices(m_callbackEnumTable, m_callbackEnumRows, clickedRow);
        if (!clickedSourceIndices.empty() && clickedSourceIndices.front() < m_callbackEnumRows.size())
        {
            clickedModulePath = callbackEnumNormalizeModulePath(
                m_callbackEnumRows[clickedSourceIndices.front()].modulePathText);
        }
    }
    if (clickedModulePath.isEmpty() && !selectedSourceIndices.empty() && selectedSourceIndices.front() < m_callbackEnumRows.size())
    {
        clickedModulePath = callbackEnumNormalizeModulePath(
            m_callbackEnumRows[selectedSourceIndices.front()].modulePathText);
    }
    const bool hasModuleFile = !clickedModulePath.isEmpty() && QFileInfo(clickedModulePath).exists();
    const KernelCallbackEnumEntry* actionEntry = nullptr;
    if (selectedSourceIndices.size() == 1U && selectedSourceIndices.front() < m_callbackEnumRows.size())
    {
        actionEntry = &m_callbackEnumRows[selectedSourceIndices.front()];
    }
    const bool hasSingleActionEntry = actionEntry != nullptr;
    const CallbackEnumRemovePolicyKind selectedRemovePolicy =
        hasSingleActionEntry ? callbackEnumRemovePolicyKind(*actionEntry) : CallbackEnumRemovePolicyKind::NotRemovable;
    const bool canUseLegacySafeRemove =
        hasSingleActionEntry && callbackEnumCanUseLegacySafeRemove(*actionEntry);
    const bool canUseExperimentalUnlink =
        hasSingleActionEntry && selectedRemovePolicy != CallbackEnumRemovePolicyKind::NotRemovable;

    QMenu contextMenu(this);
    contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());

    QAction* refreshAction = contextMenu.addAction(
        QIcon(":/Icon/process_refresh.svg"),
        kernelText("kernel.callback.enum.menu.refresh", QStringLiteral("刷新回调遍历")));
    QAction* openModuleFolderAction = contextMenu.addAction(
        QIcon(":/Icon/process_open_folder.svg"),
        kernelText("kernel.callback.enum.menu.open_module_folder", QStringLiteral("打开模块所在目录")));
    QAction* moduleFileDetailAction = contextMenu.addAction(
        QIcon(":/Icon/process_details.svg"),
        kernelText("kernel.callback.enum.menu.module_detail", QStringLiteral("模块文件详细信息")));
    openModuleFolderAction->setEnabled(hasModuleFile);
    moduleFileDetailAction->setEnabled(hasModuleFile);
    QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
        &contextMenu,
        this,
        [clickedModulePath, actionEntry]() -> ks::online_scan::SandboxUploadTarget
        {
            // 输入：当前回调行已规范化的模块文件路径。
            // 处理：直接上传命中的模块文件；无文件时交由统一错误提示。
            // 返回：待上传路径和来源说明。
            ks::online_scan::SandboxUploadTarget uploadTarget;
            uploadTarget.filePath = clickedModulePath;
            uploadTarget.sourceText = kernelText("kernel.callback.enum.upload.source", QStringLiteral("内核回调模块 %1"))
                .arg(actionEntry != nullptr
                    ? actionEntry->nameText
                    : kernelText("kernel.callback.enum.placeholder.unknown_callback", QStringLiteral("<未知回调>")));
            return uploadTarget;
        });
    if (uploadVirusTotalAction != nullptr)
    {
        uploadVirusTotalAction->setEnabled(hasModuleFile);
    }
    contextMenu.addSeparator();

    QAction* safeRemoveAction = contextMenu.addAction(kernelText("kernel.callback.enum.remove.safe.title", QStringLiteral("安全移除")));
    safeRemoveAction->setToolTip(kernelText("kernel.callback.enum.remove.safe.tooltip", QStringLiteral("使用受支持的安全方式移除回调。")));
    safeRemoveAction->setEnabled(canUseLegacySafeRemove);
    QAction* experimentalUnlinkAction = contextMenu.addAction(kernelText("kernel.callback.enum.remove.experimental.title", QStringLiteral("强制移除（实验性）")));
    experimentalUnlinkAction->setToolTip(kernelText("kernel.callback.enum.remove.experimental.tooltip", QStringLiteral("需要再次确认；只对可操作项目开放。")));
    experimentalUnlinkAction->setEnabled(canUseExperimentalUnlink);
    contextMenu.addSeparator();

    QMenu* copyMenu = contextMenu.addMenu(
        QIcon(":/Icon/process_copy_row.svg"),
        kernelText("kernel.context.menu.copy", QStringLiteral("复制")));
    QAction* copyCurrentColumnAction = copyMenu->addAction(
        QIcon(":/Icon/process_copy_cell.svg"),
        kernelText("kernel.callback.enum.menu.copy_current_column", QStringLiteral("复制当前列（选中行）")));
    QAction* copySelectedRowsAction = copyMenu->addAction(
        QIcon(":/Icon/process_copy_row.svg"),
        kernelText("kernel.context.menu.copy_row", QStringLiteral("复制选中行（TSV）")));
    QAction* copySelectedRowsWithHeaderAction = copyMenu->addAction(
        kernelText("kernel.callback.enum.menu.copy_header_rows", QStringLiteral("复制表头+选中行（TSV）")));
    QAction* copyDetailAction = copyMenu->addAction(
        kernelText("kernel.callback.enum.menu.copy_detail", QStringLiteral("复制详情（选中行）")));
    copyMenu->addSeparator();

    QMenu* copyColumnMenu = copyMenu->addMenu(kernelText("kernel.callback.enum.menu.copy_columns", QStringLiteral("复制指定栏目（选中行）")));
    for (int columnIndex = 0; columnIndex < static_cast<int>(CallbackEnumColumn::Count); ++columnIndex)
    {
        const CallbackEnumColumn column = static_cast<CallbackEnumColumn>(columnIndex);
        QAction* columnAction = copyColumnMenu->addAction(callbackEnumColumnHeaderText(column));
        columnAction->setData(columnIndex);
    }

    copyCurrentColumnAction->setEnabled(hasSelection);
    copySelectedRowsAction->setEnabled(hasSelection);
    copySelectedRowsWithHeaderAction->setEnabled(hasSelection);
    copyDetailAction->setEnabled(hasSelection);
    copyColumnMenu->setEnabled(hasSelection);

    QAction* selectedAction = contextMenu.exec(m_callbackEnumTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }

    if (selectedAction == refreshAction)
    {
        refreshCallbackEnumAsync();
        return;
    }

    if (selectedAction == openModuleFolderAction)
    {
        const bool opened = callbackEnumOpenModuleInExplorer(clickedModulePath);
        if (m_callbackEnumStatusLabel != nullptr)
        {
            m_callbackEnumStatusLabel->setText(opened
                ? kernelText("kernel.callback.enum.status.module_folder_opened", QStringLiteral("状态：已打开模块所在目录"))
                : kernelText("kernel.callback.enum.status.module_folder_failed", QStringLiteral("状态：打开模块所在目录失败")));
        }
        return;
    }

    if (selectedAction == moduleFileDetailAction)
    {
        callbackEnumShowModuleFileDetailDialog(this, clickedModulePath);
        if (m_callbackEnumStatusLabel != nullptr)
        {
            m_callbackEnumStatusLabel->setText(kernelText("kernel.callback.enum.status.module_detail_opened", QStringLiteral("状态：已打开模块文件详细信息")));
        }
        return;
    }
    if (selectedAction == uploadVirusTotalAction)
    {
        return;
    }

    if (selectedAction == safeRemoveAction)
    {
        if (actionEntry != nullptr)
        {
            callbackEnumExecuteSafeRemove(
                this,
                m_callbackEnumStatusLabel,
                m_callbackEnumDetailEditor,
                *actionEntry);
        }
        return;
    }

    if (selectedAction == experimentalUnlinkAction)
    {
        if (actionEntry != nullptr)
        {
            callbackEnumShowExperimentalUnlinkNotice(
                this,
                m_callbackEnumStatusLabel,
                m_callbackEnumDetailEditor,
                *actionEntry);
        }
        return;
    }

    if (!hasSelection)
    {
        return;
    }

    const auto buildColumnText = [this, &selectedSourceIndices](const CallbackEnumColumn column) -> QString
    {
        // 作用：把指定栏目在所有选中行中的值拼成多行文本。
        // 返回：以换行分隔的栏目值。
        QStringList valueList;
        valueList.reserve(static_cast<int>(selectedSourceIndices.size()));
        for (const std::size_t sourceIndex : selectedSourceIndices)
        {
            if (sourceIndex < m_callbackEnumRows.size())
            {
                valueList.push_back(callbackEnumEntryColumnText(m_callbackEnumRows[sourceIndex], column));
            }
        }
        return valueList.join('\n');
    };

    if (selectedAction == copyCurrentColumnAction)
    {
        int activeColumn = clickedColumn >= 0 ? clickedColumn : m_callbackEnumTable->currentColumn();
        if (activeColumn < 0 || activeColumn >= static_cast<int>(CallbackEnumColumn::Count))
        {
            activeColumn = static_cast<int>(CallbackEnumColumn::Class);
        }
        callbackEnumCopyTextToClipboard(buildColumnText(static_cast<CallbackEnumColumn>(activeColumn)));
        if (m_callbackEnumStatusLabel != nullptr)
        {
            m_callbackEnumStatusLabel->setText(kernelText("kernel.callback.enum.status.column_copied", QStringLiteral("状态：已复制 %1 行的“%2”栏目"))
                .arg(static_cast<qulonglong>(selectedSourceIndices.size()))
                .arg(callbackEnumColumnHeaderText(static_cast<CallbackEnumColumn>(activeColumn))));
        }
        return;
    }

    if (selectedAction == copySelectedRowsAction || selectedAction == copySelectedRowsWithHeaderAction)
    {
        QStringList rowList;
        rowList.reserve(static_cast<int>(selectedSourceIndices.size()) + 1);
        if (selectedAction == copySelectedRowsWithHeaderAction)
        {
            rowList.push_back(callbackEnumHeaderAsTsv());
        }
        for (const std::size_t sourceIndex : selectedSourceIndices)
        {
            if (sourceIndex < m_callbackEnumRows.size())
            {
                rowList.push_back(callbackEnumEntryAsTsv(m_callbackEnumRows[sourceIndex]));
            }
        }
        callbackEnumCopyTextToClipboard(rowList.join('\n'));
        if (m_callbackEnumStatusLabel != nullptr)
        {
            m_callbackEnumStatusLabel->setText(kernelText("kernel.callback.enum.status.rows_copied", QStringLiteral("状态：已复制 %1 行回调记录"))
                .arg(static_cast<qulonglong>(selectedSourceIndices.size())));
        }
        return;
    }

    if (selectedAction == copyDetailAction)
    {
        QStringList detailList;
        detailList.reserve(static_cast<int>(selectedSourceIndices.size()));
        for (const std::size_t sourceIndex : selectedSourceIndices)
        {
            if (sourceIndex >= m_callbackEnumRows.size())
            {
                continue;
            }

            const KernelCallbackEnumEntry& entry = m_callbackEnumRows[sourceIndex];
            detailList.push_back(kernelText("kernel.callback.enum.copy.detail_item", QStringLiteral("[%1] %2\n%3"))
                .arg(entry.classText)
                .arg(callbackEnumSafeText(entry.nameText))
                .arg(callbackEnumSafeText(entry.detailText, kernelText("kernel.callback.enum.placeholder.no_detail", QStringLiteral("<无详情>")))));
        }
        callbackEnumCopyTextToClipboard(detailList.join(QStringLiteral("\n\n---\n\n")));
        if (m_callbackEnumStatusLabel != nullptr)
        {
            m_callbackEnumStatusLabel->setText(kernelText("kernel.callback.enum.status.details_copied", QStringLiteral("状态：已复制 %1 行详情"))
                .arg(static_cast<qulonglong>(selectedSourceIndices.size())));
        }
        return;
    }

    const QList<QAction*> columnActionList = copyColumnMenu->actions();
    if (columnActionList.contains(selectedAction))
    {
        const int columnIndex = selectedAction->data().toInt();
        if (columnIndex >= 0 && columnIndex < static_cast<int>(CallbackEnumColumn::Count))
        {
            const CallbackEnumColumn column = static_cast<CallbackEnumColumn>(columnIndex);
            callbackEnumCopyTextToClipboard(buildColumnText(column));
            if (m_callbackEnumStatusLabel != nullptr)
            {
                m_callbackEnumStatusLabel->setText(kernelText("kernel.callback.enum.status.column_copied", QStringLiteral("状态：已复制 %1 行的“%2”栏目"))
                    .arg(static_cast<qulonglong>(selectedSourceIndices.size()))
                    .arg(callbackEnumColumnHeaderText(column)));
            }
        }
    }
}
