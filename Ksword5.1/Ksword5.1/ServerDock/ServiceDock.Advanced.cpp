#include "ServiceDock.Internal.h"

#include <cwchar>
#include <sddl.h>

using namespace service_dock_detail;

namespace
{
    // parseMultiSzText 作用：解析 Win32 MULTI_SZ 文本到 QStringList。
    QStringList parseMultiSzText(const wchar_t* multiSzPointer)
    {
        QStringList resultList;
        if (multiSzPointer == nullptr)
        {
            return resultList;
        }

        const wchar_t* cursorPointer = multiSzPointer;
        while (*cursorPointer != L'\0')
        {
            const QString itemText = QString::fromWCharArray(cursorPointer).trimmed();
            if (!itemText.isEmpty())
            {
                resultList.push_back(itemText);
            }
            cursorPointer += wcslen(cursorPointer) + 1;
        }
        return resultList;
    }

    // queryConfig2BufferByName reads a variable-size SERVICE_CONFIG_* block via ks::service.
    bool queryConfig2BufferByName(
        const QString& serviceNameText,
        const DWORD infoLevel,
        std::vector<std::uint8_t>* dataBufferOut)
    {
        if (dataBufferOut == nullptr || serviceNameText.trimmed().isEmpty())
        {
            return false;
        }

        // UI passes only the service name and requested info level; ks::service owns SCM handles.
        return ks::service::QueryServiceConfig2Raw(
            serviceNameText.trimmed().toStdWString(),
            static_cast<std::uint32_t>(infoLevel),
            dataBufferOut);
    }

    // queryServicePermissionVisible checks OpenService access through ks::service.
    bool queryServicePermissionVisible(const QString& serviceNameText, const DWORD desiredAccess)
    {
        return ks::service::CanOpenServiceWithAccess(
            serviceNameText.trimmed().toStdWString(),
            static_cast<std::uint32_t>(desiredAccess));
    }

    // scActionTypeToText 作用：把失败动作类型值转成可读文本。
    QString scActionTypeToText(const SC_ACTION_TYPE actionTypeValue)
    {
        switch (actionTypeValue)
        {
        case SC_ACTION_NONE:
            return QStringLiteral("无动作");
        case SC_ACTION_RESTART:
            return QStringLiteral("重启服务");
        case SC_ACTION_REBOOT:
            return QStringLiteral("重启系统");
        case SC_ACTION_RUN_COMMAND:
            return QStringLiteral("执行命令");
        default:
            return QStringLiteral("未知");
        }
    }

    // triggerTypeToText 作用：把触发器类型值转换为友好文本。
    QString triggerTypeToText(const DWORD triggerTypeValue)
    {
        switch (triggerTypeValue)
        {
        case SERVICE_TRIGGER_TYPE_DEVICE_INTERFACE_ARRIVAL:
            return QStringLiteral("设备接口到达");
        case SERVICE_TRIGGER_TYPE_IP_ADDRESS_AVAILABILITY:
            return QStringLiteral("IP 地址可用性变化");
        case SERVICE_TRIGGER_TYPE_DOMAIN_JOIN:
            return QStringLiteral("域加入/退出");
        case SERVICE_TRIGGER_TYPE_FIREWALL_PORT_EVENT:
            return QStringLiteral("防火墙端口事件");
        case SERVICE_TRIGGER_TYPE_GROUP_POLICY:
            return QStringLiteral("组策略变更");
        case SERVICE_TRIGGER_TYPE_NETWORK_ENDPOINT:
            return QStringLiteral("网络端点");
        case SERVICE_TRIGGER_TYPE_CUSTOM_SYSTEM_STATE_CHANGE:
            return QStringLiteral("自定义系统状态变化");
        case SERVICE_TRIGGER_TYPE_CUSTOM:
            return QStringLiteral("自定义触发器");
        default:
            return QStringLiteral("未知类型");
        }
    }

    // triggerActionToText 作用：把触发器动作值转换为友好文本。
    QString triggerActionToText(const DWORD triggerActionValue)
    {
        switch (triggerActionValue)
        {
        case SERVICE_TRIGGER_ACTION_SERVICE_START:
            return QStringLiteral("启动服务");
        case SERVICE_TRIGGER_ACTION_SERVICE_STOP:
            return QStringLiteral("停止服务");
        default:
            return QStringLiteral("未知动作");
        }
    }

    // guidToText 作用：把 GUID 转成标准字符串。
    QString guidToText(const GUID& guidValue)
    {
        wchar_t guidBuffer[64] = {};
        const int guidBufferCount = static_cast<int>(sizeof(guidBuffer) / sizeof(guidBuffer[0]));
        if (::StringFromGUID2(guidValue, guidBuffer, guidBufferCount) <= 0)
        {
            return QStringLiteral("<invalid-guid>");
        }
        return QString::fromWCharArray(guidBuffer);
    }

}

QString ServiceDock::queryServiceDllPathByName(const QString& serviceNameText) const
{
    const QString normalizedServiceNameText = serviceNameText.trimmed();
    if (normalizedServiceNameText.isEmpty())
    {
        return QString();
    }

    const QString registryPathText = QStringLiteral(
        "SYSTEM\\CurrentControlSet\\Services\\%1\\Parameters").arg(normalizedServiceNameText);
    HKEY openedKey = nullptr;
    const LONG openResult = ::RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        reinterpret_cast<LPCWSTR>(registryPathText.utf16()),
        0,
        KEY_READ,
        &openedKey);
    if (openResult != ERROR_SUCCESS || openedKey == nullptr)
    {
        return QString();
    }

    DWORD valueType = 0;
    DWORD requiredBytes = 0;
    LONG queryResult = ::RegQueryValueExW(openedKey, L"ServiceDll", nullptr, &valueType, nullptr, &requiredBytes);
    if (queryResult != ERROR_SUCCESS || requiredBytes == 0 || (valueType != REG_EXPAND_SZ && valueType != REG_SZ))
    {
        ::RegCloseKey(openedKey);
        return QString();
    }

    std::vector<wchar_t> valueBuffer((requiredBytes / sizeof(wchar_t)) + 2, L'\0');
    queryResult = ::RegQueryValueExW(
        openedKey,
        L"ServiceDll",
        nullptr,
        &valueType,
        reinterpret_cast<LPBYTE>(valueBuffer.data()),
        &requiredBytes);
    ::RegCloseKey(openedKey);
    if (queryResult != ERROR_SUCCESS)
    {
        return QString();
    }

    QString rawPathText = QString::fromWCharArray(valueBuffer.data()).trimmed();
    if (rawPathText.isEmpty())
    {
        return QString();
    }

    wchar_t expandedPathBuffer[MAX_PATH * 4] = {};
    const DWORD expandedPathBufferCount =
        static_cast<DWORD>(sizeof(expandedPathBuffer) / sizeof(expandedPathBuffer[0]));
    const DWORD expandedLength = ::ExpandEnvironmentStringsW(
        reinterpret_cast<LPCWSTR>(rawPathText.utf16()),
        expandedPathBuffer,
        expandedPathBufferCount);
    if (expandedLength > 0 && expandedLength < expandedPathBufferCount)
    {
        rawPathText = QString::fromWCharArray(expandedPathBuffer).trimmed();
    }
    return QDir::toNativeSeparators(rawPathText);
}

bool ServiceDock::isServiceFilePresent(const QString& filePathText) const
{
    const QFileInfo fileInfo(filePathText.trimmed());
    return fileInfo.exists() && fileInfo.isFile();
}





ks::ui::FieldDocument ServiceDock::buildDependencyDetailText(const ServiceEntry& entry) const
{
    QStringList forwardServiceList;
    QStringList forwardGroupList;

    ks::service::ServiceConfig config;
    if (ks::service::QueryServiceConfig(entry.serviceNameText.toStdWString(), &config) &&
        !config.dependenciesMultiSz.empty())
    {
        const QStringList rawDependencyList = parseMultiSzText(config.dependenciesMultiSz.c_str());
        for (const QString& dependencyText : rawDependencyList)
        {
            if (dependencyText.startsWith('+'))
            {
                forwardGroupList.push_back(dependencyText.mid(1));
            }
            else
            {
                forwardServiceList.push_back(dependencyText);
            }
        }
    }

    QStringList reverseServiceList;
    std::vector<std::wstring> reverseNames;
    if (ks::service::QueryDependentServiceNames(
        entry.serviceNameText.toStdWString(),
        SERVICE_STATE_ALL,
        &reverseNames))
    {
        for (const std::wstring& reverseName : reverseNames)
        {
            reverseServiceList.push_back(QString::fromStdWString(reverseName));
        }
    }

    ks::ui::FieldDocument detailLineList;
    detailLineList.section(QStringLiteral("依存关系"));
    detailLineList.field(QStringLiteral("当前服务"), QStringLiteral("%1").arg(entry.serviceNameText));
    if (forwardServiceList.isEmpty() && forwardGroupList.isEmpty())
    {
        detailLineList.field(QStringLiteral("正向依赖"), QStringLiteral("无"), true);
    }
    else
    {
        for (const QString& serviceDependencyText : forwardServiceList)
        {
            const int targetIndex = findServiceIndexByName(serviceDependencyText);
            const QString runningMarkText =
                (targetIndex >= 0 && m_serviceList[static_cast<std::size_t>(targetIndex)].currentState == SERVICE_RUNNING)
                ? QStringLiteral("运行中")
                : QStringLiteral("未运行/缺失");
            detailLineList.field(QStringLiteral("依赖服务"), QStringLiteral("%1 [%2]").arg(QStringLiteral("%1").arg(serviceDependencyText)).arg(QStringLiteral("%1").arg(runningMarkText)));
        }
        for (const QString& groupDependencyText : forwardGroupList)
        {
            detailLineList.field(QStringLiteral("依赖组"), QStringLiteral("%1").arg(groupDependencyText));
        }
    }
    if (reverseServiceList.isEmpty())
    {
        detailLineList.field(QStringLiteral("反向依赖"), QStringLiteral("无"), true);
    }
    else
    {
        for (const QString& reverseServiceText : reverseServiceList)
        {
            detailLineList.field(QStringLiteral("被依赖"), QStringLiteral("%1").arg(reverseServiceText));
        }
    }
    detailLineList.field(QStringLiteral("正向依赖数量"), QStringLiteral("%1").arg(forwardServiceList.size() + forwardGroupList.size()));
    detailLineList.field(QStringLiteral("反向依赖数量"), QStringLiteral("%1").arg(reverseServiceList.size()));
    return detailLineList;
}





ks::ui::FieldDocument ServiceDock::buildTriggerDetailText(const ServiceEntry& entry) const
{
    ks::ui::FieldDocument detailLineList;
    std::vector<std::uint8_t> triggerBuffer;
    if (!queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_TRIGGER_INFO, &triggerBuffer))
    {
        return ks::ui::FieldDocument{}.note(QStringLiteral("触发器：未配置或当前系统不支持读取"));
    }

    const SERVICE_TRIGGER_INFO* triggerInfoPointer =
        reinterpret_cast<const SERVICE_TRIGGER_INFO*>(triggerBuffer.data());
    detailLineList.field(QStringLiteral("触发器数量"), QStringLiteral("%1").arg(triggerInfoPointer->cTriggers));
    for (DWORD triggerIndex = 0; triggerIndex < triggerInfoPointer->cTriggers; ++triggerIndex)
    {
        const SERVICE_TRIGGER& triggerItem = triggerInfoPointer->pTriggers[triggerIndex];
        detailLineList.section(QStringLiteral("Trigger"));
        detailLineList.field(QStringLiteral("Index"), QString::number(triggerIndex + 1));
        detailLineList.field(QStringLiteral("类型"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(triggerTypeToText(triggerItem.dwTriggerType))).arg(QStringLiteral("%1").arg(triggerItem.dwTriggerType)));
        detailLineList.field(QStringLiteral("动作"), QStringLiteral("%1 (%2)").arg(QStringLiteral("%1").arg(triggerActionToText(triggerItem.dwAction))).arg(QStringLiteral("%1").arg(triggerItem.dwAction)));
        detailLineList.field(QStringLiteral("子类型GUID"), QStringLiteral("%1").arg((triggerItem.pTriggerSubtype != nullptr)
                ? guidToText(*triggerItem.pTriggerSubtype)
                : QStringLiteral("未提供")));
        detailLineList.field(QStringLiteral("数据项数量"), QStringLiteral("%1").arg(triggerItem.cDataItems));

        for (DWORD dataIndex = 0; dataIndex < triggerItem.cDataItems; ++dataIndex)
        {
            const SERVICE_TRIGGER_SPECIFIC_DATA_ITEM& dataItem = triggerItem.pDataItems[dataIndex];
            QString dataPreviewText;
            if (dataItem.cbData == 0 || dataItem.pData == nullptr)
            {
                dataPreviewText = QStringLiteral("空数据");
            }
            else if (dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_STRING
                || dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_LEVEL
                || dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ANY
                || dataItem.dwDataType == SERVICE_TRIGGER_DATA_TYPE_KEYWORD_ALL)
            {
                dataPreviewText = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(dataItem.pData));
            }
            else
            {
                QByteArray rawBytes(reinterpret_cast<const char*>(dataItem.pData), static_cast<int>(dataItem.cbData));
                dataPreviewText = QString::fromLatin1(rawBytes.toHex(' '));
            }
            detailLineList.section(QStringLiteral("Data item"));
            detailLineList.field(QStringLiteral("Index"), QString::number(dataIndex));
            detailLineList.field(QStringLiteral("Type"), QString::number(dataItem.dwDataType));
            detailLineList.field(QStringLiteral("Size"), QString::number(dataItem.cbData));
            detailLineList.field(QStringLiteral("Value"), dataPreviewText);
        }
    }

    return detailLineList;
}


ks::ui::FieldDocument ServiceDock::buildSecurityDetailText(const ServiceEntry& entry) const
{
    ks::ui::FieldDocument detailLineList;

    std::vector<std::uint8_t> sidTypeBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_SERVICE_SID_INFO, &sidTypeBuffer))
    {
        const SERVICE_SID_INFO* sidInfoPointer = reinterpret_cast<const SERVICE_SID_INFO*>(sidTypeBuffer.data());
        detailLineList.field(QStringLiteral("ServiceSidType"), QStringLiteral("%1").arg(sidInfoPointer->dwServiceSidType));
    }

    std::vector<std::uint8_t> privilegeBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO, &privilegeBuffer))
    {
        const SERVICE_REQUIRED_PRIVILEGES_INFOW* privilegeInfoPointer =
            reinterpret_cast<const SERVICE_REQUIRED_PRIVILEGES_INFOW*>(privilegeBuffer.data());
        const QStringList privilegeList = parseMultiSzText(privilegeInfoPointer->pmszRequiredPrivileges);
        detailLineList.field(QStringLiteral("RequiredPrivileges"), privilegeList.isEmpty()
            ? QStringLiteral("未声明") : privilegeList.join(QStringLiteral(", ")), privilegeList.isEmpty());
    }

    std::vector<std::uint8_t> launchProtectedBuffer;
    if (queryConfig2BufferByName(entry.serviceNameText, SERVICE_CONFIG_LAUNCH_PROTECTED, &launchProtectedBuffer))
    {
        const SERVICE_LAUNCH_PROTECTED_INFO* launchProtectedPointer =
            reinterpret_cast<const SERVICE_LAUNCH_PROTECTED_INFO*>(launchProtectedBuffer.data());
        detailLineList.field(QStringLiteral("LaunchProtected"), QStringLiteral("%1").arg(launchProtectedPointer->dwLaunchProtected));
    }

    std::wstring sddlText;
    if (ks::service::QueryServiceSecuritySddl(
        entry.serviceNameText.toStdWString(),
        DACL_SECURITY_INFORMATION,
        &sddlText))
    {
        detailLineList.field(QStringLiteral("SDDL"), QStringLiteral("%1").arg(QString::fromStdWString(sddlText)));
    }

    detailLineList.section(QStringLiteral("权限可见化"));
    detailLineList.field(QStringLiteral("Start"), queryServicePermissionVisible(entry.serviceNameText, SERVICE_START) ? QStringLiteral("可用") : QStringLiteral("不可用"), true);
    detailLineList.field(QStringLiteral("Stop"), queryServicePermissionVisible(entry.serviceNameText, SERVICE_STOP) ? QStringLiteral("可用") : QStringLiteral("不可用"), true);
    detailLineList.field(QStringLiteral("ChangeConfig"), queryServicePermissionVisible(entry.serviceNameText, SERVICE_CHANGE_CONFIG) ? QStringLiteral("可用") : QStringLiteral("不可用"), true);
    detailLineList.field(QStringLiteral("Delete"), queryServicePermissionVisible(entry.serviceNameText, DELETE) ? QStringLiteral("可用") : QStringLiteral("不可用"), true);
    return detailLineList;
}


ks::ui::FieldDocument ServiceDock::buildRiskDetailText(const ServiceEntry& entry) const
{
    ks::ui::FieldDocument detailLineList;
    detailLineList.field(QStringLiteral("风险摘要"), QStringLiteral("%1").arg(entry.riskSummaryText));
    if (entry.riskTagList.isEmpty())
    {
        detailLineList.note(QStringLiteral("未命中风险标签。"));
    }
    else
    {
        for (const QString& riskTagText : entry.riskTagList)
        {
            detailLineList.note(QStringLiteral("- %1").arg(QStringLiteral("%1").arg(riskTagText)));
        }
    }
    return detailLineList;
}

ks::ui::FieldDocument ServiceDock::buildExportDetailText(const ServiceEntry& entry) const
{
    ks::ui::FieldDocument detailLineList;
    detailLineList.field(QStringLiteral("当前服务"), QStringLiteral("%1").arg(entry.serviceNameText));
    detailLineList.field(QStringLiteral("当前可见服务数"), QStringLiteral("%1").arg(m_serviceTable == nullptr ? 0 : m_serviceTable->rowCount()));
    detailLineList.field(QStringLiteral("导出列表"), QStringLiteral("支持 TSV（当前筛选结果）"), true);
    detailLineList.field(QStringLiteral("导出单服务"), QStringLiteral("支持 JSON（完整配置快照）"), true);
    detailLineList.field(QStringLiteral("刷新策略"), QStringLiteral("支持“刷新当前服务”与“刷新全部服务”分层更新"), true);
    return detailLineList;
}
