#include "KernelDock.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../theme.h"

#include <QComboBox>
#include <QCoreApplication>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QStringList>
#include <QThreadPool>
#include <QVBoxLayout>

#include <atomic>

using ksword::kernel_dock_internal::kernelText;

namespace
{
    // g_callbackRemoveResolveGeneration：
    // - 用途：淘汰已被新一次“安全移除”取代的服务名反查回投；
    // - 说明：手工移除面板全局只有一个实例，这里用文件级计数器避免改 KernelDock.h。
    std::atomic<quint64> g_callbackRemoveResolveGeneration{ 0ULL };

    // callbackRemoveParseAddress：
    // - 作用：把输入文本解析为 64 位地址（支持 0x 前缀）。
    bool callbackRemoveParseAddress(const QString& textValue, quint64& addressOut)
    {
        QString normalizedText = textValue.trimmed();
        bool parseOk = false;

        if (normalizedText.isEmpty())
        {
            return false;
        }

        if (normalizedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            normalizedText = normalizedText.mid(2);
        }

        addressOut = normalizedText.toULongLong(&parseOk, 16);
        return parseOk;
    }

    // callbackRemoveIoMessageText：
    // - 输入：ArkDriverClient::CallbackRemoveResult 中的原始 IO message；
    // - 处理：把 DeviceIoControl/unsupported/capability 等底层短语转为回调移除页可读诊断；
    // - 返回：详情框展示文本；保留用户需要的失败原因，不直接暴露 IOCTL 调试串。
    QString callbackRemoveIoMessageText(const QString& rawMessageText)
    {
        const QString trimmedText = rawMessageText.trimmed();
        if (trimmedText.isEmpty())
        {
            return kernelText("kernel.callback.remove.message.no_driver_message", QStringLiteral("驱动未返回额外说明。"));
        }

        const QString lowerText = trimmedText.toLower();
        if (lowerText.contains(QStringLiteral("deviceiocontrol")))
        {
            return kernelText("kernel.callback.remove.message.communication_failure", QStringLiteral("驱动 IOCTL 调用失败或 R3/R0 协议版本不匹配。"));
        }
        if (lowerText.contains(QStringLiteral("unsupported")) ||
            lowerText.contains(QStringLiteral("not supported")) ||
            lowerText.contains(QStringLiteral("status=0xc00000bb")))
        {
            return kernelText("kernel.callback.remove.message.unsupported", QStringLiteral("当前驱动暂不支持该回调移除入口。"));
        }
        if (lowerText.contains(QStringLiteral("capability")) ||
            lowerText.contains(QStringLiteral("dyndata")))
        {
            return kernelText("kernel.callback.remove.message.capability", QStringLiteral("动态偏移能力未满足，回调对象或模块归属暂不可解析。"));
        }
        return trimmedText;
    }

    // callbackRemoveNormalizePath：规范化路径，便于匹配驱动服务映射。
    QString callbackRemoveNormalizePath(const QString& pathText)
    {
        QString normalizedText = pathText.trimmed().toLower();
        normalizedText.replace(QStringLiteral("\""), QString());
        normalizedText.replace(QStringLiteral("\\??\\"), QStringLiteral(""));
        normalizedText.replace(QStringLiteral("\\systemroot"), QStringLiteral("c:\\windows"));
        return normalizedText;
    }

    // callbackRemoveResolveServiceByModule：根据模块路径推断对应的服务名。
    QString callbackRemoveResolveServiceByModule(const QString& modulePath)
    {
        const QString normalizedModulePath = callbackRemoveNormalizePath(modulePath);
        if (normalizedModulePath.isEmpty())
        {
            return QString();
        }

        SC_HANDLE scmHandle = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (scmHandle == nullptr)
        {
            return QString();
        }

        DWORD requiredBytes = 0;
        DWORD serviceCount = 0;
        DWORD resumeHandle = 0;
        (void)::EnumServicesStatusExW(
            scmHandle,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            nullptr,
            0,
            &requiredBytes,
            &serviceCount,
            &resumeHandle,
            nullptr);
        if (requiredBytes == 0)
        {
            ::CloseServiceHandle(scmHandle);
            return QString();
        }

        QByteArray serviceBuffer;
        serviceBuffer.resize(static_cast<int>(requiredBytes));
        auto* serviceArray = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(serviceBuffer.data());
        if (!::EnumServicesStatusExW(
            scmHandle,
            SC_ENUM_PROCESS_INFO,
            SERVICE_DRIVER,
            SERVICE_STATE_ALL,
            reinterpret_cast<LPBYTE>(serviceArray),
            requiredBytes,
            &requiredBytes,
            &serviceCount,
            &resumeHandle,
            nullptr))
        {
            ::CloseServiceHandle(scmHandle);
            return QString();
        }

        QString mappedServiceName;
        for (DWORD index = 0; index < serviceCount; ++index)
        {
            SC_HANDLE serviceHandle = ::OpenServiceW(
                scmHandle,
                serviceArray[index].lpServiceName,
                SERVICE_QUERY_CONFIG);
            if (serviceHandle == nullptr)
            {
                continue;
            }

            DWORD configBytes = 0;
            (void)::QueryServiceConfigW(serviceHandle, nullptr, 0, &configBytes);
            if (configBytes == 0)
            {
                ::CloseServiceHandle(serviceHandle);
                continue;
            }

            QByteArray configBuffer;
            configBuffer.resize(static_cast<int>(configBytes));
            auto* configInfo = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
            if (::QueryServiceConfigW(serviceHandle, configInfo, configBytes, &configBytes) && configInfo->lpBinaryPathName != nullptr)
            {
                const QString serviceBinaryPath = callbackRemoveNormalizePath(QString::fromWCharArray(configInfo->lpBinaryPathName));
                const QString serviceFileName = QFileInfo(serviceBinaryPath).fileName();
                if (!serviceFileName.isEmpty() && normalizedModulePath.endsWith(serviceFileName))
                {
                    mappedServiceName = QString::fromWCharArray(serviceArray[index].lpServiceName);
                    ::CloseServiceHandle(serviceHandle);
                    break;
                }
            }

            ::CloseServiceHandle(serviceHandle);
        }

        ::CloseServiceHandle(scmHandle);
        return mappedServiceName;
    }

    // callbackRemoveMappingText：
    // - Input：旧 removeExternalCallback 响应中的 mappingFlags。
    // - Processing：展开当前 shared 协议已定义的映射来源位，并保留未知位。
    // - Return：用于详情面板展示的映射来源文本。
    QString callbackRemoveMappingText(const unsigned long mappingFlags)
    {
        QStringList flagList;
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE) != 0UL)
        {
            flagList.push_back(QStringLiteral("module"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED) != 0UL)
        {
            flagList.push_back(QStringLiteral("enumerated"));
        }
        if ((mappingFlags & KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API) != 0UL)
        {
            flagList.push_back(QStringLiteral("public api"));
        }

        const unsigned long knownFlags =
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_MODULE |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_ENUMERATED |
            KSWORD_ARK_EXTERNAL_CALLBACK_MAPPING_FLAG_PUBLIC_API;
        const unsigned long unknownFlags = mappingFlags & ~knownFlags;
        if (unknownFlags != 0UL)
        {
            flagList.push_back(QStringLiteral("unknown=0x%1")
                .arg(static_cast<qulonglong>(unknownFlags), 8, 16, QChar('0'))
                .toUpper());
        }
        return flagList.isEmpty()
            ? kernelText("kernel.callback.remove.placeholder.none", QStringLiteral("<无>"))
            : flagList.join(QStringLiteral(", "));
    }

}

void KernelDock::initializeCallbackRemovePanel()
{
    if (m_callbackEnumPage == nullptr || m_callbackEnumLayout == nullptr || m_callbackRemoveLayout != nullptr)
    {
        return;
    }

    // 该面板随“回调遍历”页一起创建，避免继续占用一个独立顶层 Tab。
    // 输入：无用户数据；处理：创建手动类型/地址移除表单；返回：无，控件归属 Qt 父子树。
    m_callbackRemoveContentWidget = new QWidget(m_callbackEnumPage);
    m_callbackRemoveContentWidget->setObjectName(QStringLiteral("ksCallbackRemoveEmbeddedPanel"));
    m_callbackRemoveContentWidget->setStyleSheet(QStringLiteral(
        "#ksCallbackRemoveEmbeddedPanel{border:1px solid %1;border-radius:3px;background:transparent;/* %2 */}")
        .arg(KswordTheme::BorderHex())
        .arg(KswordTheme::SurfaceHex()));

    m_callbackRemoveLayout = new QVBoxLayout(m_callbackRemoveContentWidget);
    m_callbackRemoveLayout->setContentsMargins(6, 6, 6, 6);
    m_callbackRemoveLayout->setSpacing(6);

    QLabel* titleLabel = new QLabel(kernelText("kernel.callback.remove.title", QStringLiteral("手动回调移除")), m_callbackRemoveContentWidget);
    titleLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::PrimaryBlueHex));
    m_callbackRemoveLayout->addWidget(titleLabel, 0);

    m_callbackRemoveToolLayout = new QHBoxLayout();
    m_callbackRemoveToolLayout->setContentsMargins(0, 0, 0, 0);
    m_callbackRemoveToolLayout->setSpacing(6);

    m_callbackRemoveTypeCombo = new QComboBox(m_callbackRemoveContentWidget);
    m_callbackRemoveTypeCombo->addItem(kernelText("kernel.callback.remove.type.process", QStringLiteral("进程创建/退出 Notify")), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_PROCESS));
    m_callbackRemoveTypeCombo->addItem(kernelText("kernel.callback.remove.type.thread", QStringLiteral("线程创建/退出 Notify")), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_THREAD));
    m_callbackRemoveTypeCombo->addItem(kernelText("kernel.callback.remove.type.image", QStringLiteral("镜像加载 Notify")), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_IMAGE));
    m_callbackRemoveTypeCombo->addItem(QStringLiteral("Object Callback"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_OBJECT));
    m_callbackRemoveTypeCombo->addItem(QStringLiteral("Registry Callback"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_REGISTRY));
    m_callbackRemoveTypeCombo->addItem(QStringLiteral("Minifilter"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_MINIFILTER));
    m_callbackRemoveTypeCombo->addItem(QStringLiteral("WFP Callout"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_WFP_CALLOUT));
    m_callbackRemoveTypeCombo->addItem(QStringLiteral("ETW Provider/Consumer"), static_cast<quint32>(KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_TYPE_ETW_PROVIDER));

    m_callbackRemoveAddressEdit = new QLineEdit(m_callbackRemoveContentWidget);
    m_callbackRemoveAddressEdit->setPlaceholderText(kernelText("kernel.callback.remove.address.placeholder", QStringLiteral("输入回调地址（例如 0xFFFFF80012345678）")));
    m_callbackRemoveAddressEdit->setClearButtonEnabled(true);

    m_callbackRemoveButton = new QPushButton(kernelText("kernel.callback.remove.button.safe", QStringLiteral("安全移除")), m_callbackRemoveContentWidget);
    m_callbackRemoveButton->setStyleSheet(KswordTheme::ThemedButtonStyle());

    m_callbackRemoveStatusLabel = new QLabel(kernelText("kernel.callback.remove.status.waiting", QStringLiteral("状态：等待操作")), m_callbackRemoveContentWidget);
    m_callbackRemoveStatusLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;").arg(KswordTheme::TextSecondaryHex()));

    m_callbackRemoveToolLayout->addWidget(new QLabel(kernelText("kernel.callback.remove.label.type", QStringLiteral("类型：")), m_callbackRemoveContentWidget));
    m_callbackRemoveToolLayout->addWidget(m_callbackRemoveTypeCombo, 0);
    m_callbackRemoveToolLayout->addWidget(m_callbackRemoveAddressEdit, 1);
    m_callbackRemoveToolLayout->addWidget(m_callbackRemoveButton, 0);
    m_callbackRemoveLayout->addLayout(m_callbackRemoveToolLayout);
    m_callbackRemoveLayout->addWidget(m_callbackRemoveStatusLabel, 0);

    m_callbackEnumLayout->addWidget(m_callbackRemoveContentWidget, 0);

    connect(m_callbackRemoveButton, &QPushButton::clicked, this, [this]() {
        quint64 callbackAddress = 0;
        if (!callbackRemoveParseAddress(m_callbackRemoveAddressEdit->text(), callbackAddress) || callbackAddress == 0)
        {
            QMessageBox::warning(this, kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")), kernelText("kernel.callback.remove.address.invalid", QStringLiteral("请输入合法的十六进制回调地址。")));
            return;
        }

        // 同一个“安全移除”在枚举页是有前置确认的（KernelDock.CallbackEnum.cpp
        // callbackEnumConfirmSafeRemove：Yes|No，默认 No），本页手工填地址这条路径却直接下发。
        // 手工路径反而更该确认：地址是用户裸手打进来的，没有枚举行携带的来源/可信/移除策略
        // 元数据可供交叉核对。这里补齐，措辞与枚举页保持一致。
        const QString removeConfirmText =
            kernelText("kernel.callback.remove.confirm", QStringLiteral(
                "即将按手工填写的地址移除内核回调。\n\n"
                "类别：%1\n"
                "地址：0x%2\n\n"
                "该地址由你手工输入，本页没有枚举行的来源与可信信息可供交叉核对。\n"
                "此操作会修改内核回调注册，可能影响系统稳定性。是否继续？"))
                .arg(m_callbackRemoveTypeCombo->currentText())
                .arg(QString::number(callbackAddress, 16).toUpper());
        if (QMessageBox::question(
                this,
                kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                removeConfirmText,
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) != QMessageBox::Yes)
        {
            return;
        }

        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST requestPacket{};
        requestPacket.size = sizeof(requestPacket);
        requestPacket.version = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_PROTOCOL_VERSION;
        requestPacket.callbackClass = static_cast<quint32>(m_callbackRemoveTypeCombo->currentData().toUInt());
        requestPacket.flags = KSWORD_ARK_EXTERNAL_CALLBACK_REMOVE_FLAG_NONE;
        requestPacket.callbackAddress = callbackAddress;

        const ksword::ark::DriverClient driverClient;
        const bool experimentalUnlinkEnabled = driverClient.supportsExternalCallbackExperimentalUnlink();
        const ksword::ark::CallbackRemoveResult removeResult = driverClient.removeExternalCallback(requestPacket);
        const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE& responsePacket = removeResult.response;
        const DWORD bytesReturned = removeResult.io.bytesReturned;

        if (!removeResult.io.ok)
        {
            m_callbackRemoveStatusLabel->setText(kernelText("kernel.callback.remove.status.io_failed", QStringLiteral("状态：移除失败，error=%1"))
                .arg(removeResult.io.win32Error));
            const QString errorDetailText = kernelText("kernel.callback.remove.detail.io_failed", QStringLiteral("回调移除失败，Win32 错误码=%1。\n地址=0x%2\n详情=%3"))
                .arg(removeResult.io.win32Error)
                .arg(QString::number(callbackAddress, 16).toUpper())
                .arg(callbackRemoveIoMessageText(QString::fromStdString(removeResult.io.message)));
            QMessageBox::warning(this, kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")), errorDetailText);
            return;
        }

        const QString modulePath = QString::fromWCharArray(responsePacket.modulePath);
        const QString responseServiceName = QString::fromWCharArray(responsePacket.serviceName);

        // composeCallbackRemoveDetailText：
        // - 入参 localServiceNameText：本地 SCM 服务映射结果，未完成时用“未解析”占位；
        // - 处理：把本轮移除响应的全部字段拼成详情文本，供同步渲染与异步补齐复用；
        // - 返回：用于结果弹窗的详情文本。
        const auto composeCallbackRemoveDetailText =
            [typeText = m_callbackRemoveTypeCombo->currentText(),
             callbackAddress,
             bytesReturned,
             ntstatusValue = static_cast<quint32>(responsePacket.ntstatus),
             mappingText = callbackRemoveMappingText(responsePacket.mappingFlags),
             modulePath,
             moduleBase = static_cast<quint64>(responsePacket.moduleBase),
             moduleSize = static_cast<quint64>(responsePacket.moduleSize),
             responseServiceName,
             experimentalUnlinkEnabled](const QString& localServiceNameText)
        {
            return kernelText("kernel.callback.remove.detail.full", QStringLiteral(
                "安全移除请求已执行。\n"
                "- 类型：%1\n"
                "- 地址：0x%2\n"
                "- 返回字节：%3\n"
                "- NTSTATUS：0x%4\n"
                "- 映射标志：%5\n"
                "- 模块路径：%6\n"
                "- 模块基址：0x%7\n"
                "- 模块大小：0x%8\n"
                "- 驱动返回服务名：%9\n"
                "- 本地服务映射：%10\n"
                "- 操作模式：%11"))
                .arg(typeText)
                .arg(QString::number(callbackAddress, 16).toUpper())
                .arg(bytesReturned)
                .arg(QString::number(ntstatusValue, 16).rightJustified(8, QLatin1Char('0')).toUpper())
                .arg(mappingText)
                .arg(modulePath.isEmpty() ? kernelText("kernel.callback.remove.placeholder.unresolved", QStringLiteral("未解析")) : modulePath)
                .arg(QString::number(moduleBase, 16).toUpper())
                .arg(QString::number(moduleSize, 16).toUpper())
                .arg(responseServiceName.isEmpty() ? kernelText("kernel.callback.remove.placeholder.not_returned", QStringLiteral("未返回")) : responseServiceName)
                .arg(localServiceNameText)
                .arg(experimentalUnlinkEnabled
                    ? kernelText("kernel.callback.remove.unlink.compiled_but_unused", QStringLiteral("已编译扩展宏，但本页不执行 unlink"))
                    : kernelText("kernel.callback.remove.unlink.protocol_disabled", QStringLiteral("当前 shared 协议未启用 REMOVE_EXTERNAL_CALLBACK_EX")));
        };

        // 本地服务名反查要枚举全量 SCM 驱动服务并逐条 QueryServiceConfigW，最坏在秒级。
        // 内核回调此刻已经被改，结果弹窗在反查完成后再展示，避免弹出缺少本地服务
        // 映射的半成品详情。
        const QString unmatchedServiceText = kernelText("kernel.callback.remove.placeholder.unmatched", QStringLiteral("未匹配"));

        const QPointer<KernelDock> guardedSelf(this);
        const quint64 requestGeneration = g_callbackRemoveResolveGeneration.fetch_add(1ULL) + 1ULL;
        const bool removalSucceeded = responsePacket.ntstatus >= 0;
        QThreadPool::globalInstance()->start(
            [guardedSelf, requestGeneration, modulePath, unmatchedServiceText, removalSucceeded, composeCallbackRemoveDetailText]()
            {
                const QString resolvedServiceName = callbackRemoveResolveServiceByModule(modulePath);
                const QString localServiceNameText = resolvedServiceName.isEmpty()
                    ? unmatchedServiceText
                    : resolvedServiceName;

                QCoreApplication* const appInstance = QCoreApplication::instance();
                if (appInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(appInstance,
                    [guardedSelf, requestGeneration, localServiceNameText, removalSucceeded, composeCallbackRemoveDetailText]()
                    {
                        if (guardedSelf == nullptr)
                        {
                            return;
                        }
                        if (g_callbackRemoveResolveGeneration.load() != requestGeneration)
                        {
                            return;
                        }
                        const QString detailText = composeCallbackRemoveDetailText(localServiceNameText);
                        if (removalSucceeded)
                        {
                            QMessageBox::information(
                                guardedSelf,
                                kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                                detailText);
                        }
                        else
                        {
                            QMessageBox::warning(
                                guardedSelf,
                                kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")),
                                detailText);
                        }
                    });
            });

        if (responsePacket.ntstatus >= 0)
        {
            m_callbackRemoveStatusLabel->setText(kernelText("kernel.callback.remove.status.completed", QStringLiteral("状态：移除完成。")));
        }
        else
        {
            m_callbackRemoveStatusLabel->setText(kernelText("kernel.callback.remove.status.driver_failed", QStringLiteral("状态：驱动返回失败，NTSTATUS=0x%1"))
                .arg(QString::number(static_cast<quint32>(responsePacket.ntstatus), 16).toUpper()));
            QMessageBox::warning(this, kernelText("kernel.callback.remove.title.short", QStringLiteral("回调移除")), m_callbackRemoveStatusLabel->text());
        }
    });
}
