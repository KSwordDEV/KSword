#include "HardwareDeviceManagerPage.h"

// ============================================================
// HardwareDeviceManagerPage.cpp
// 作用：
// 1) 使用 SetupAPI/CfgMgr 枚举 PnP 设备；
// 2) 按 InstanceId/Parent 构建设备树，展示类似 System Informer 的列布局；
// 3) 支持当前/全部设备切换、异常高亮、搜索过滤与详情查看。
// ============================================================

#include "../theme.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/DetailLayoutRegistry.h"

#include <QAction>
#include <QCheckBox>
#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QPointer>
#include <QPushButton>
#include <QHash>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>
#include <QVariant>

#include <algorithm>
#include <cwchar>
#include <iterator>
#include <memory>
#include <thread>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Cfgmgr32.h>
#include <initguid.h>
#include <devpkey.h>
#include <Objbase.h>
#include <SetupAPI.h>

#pragma comment(lib, "Cfgmgr32.lib")
#pragma comment(lib, "Setupapi.lib")

namespace
{
    // DeviceTreeColumn：
    // - 作用：定义设备树表格列索引；
    // - 处理逻辑：插入和更新节点时统一引用；
    // - 返回行为：枚举本身无返回值。
    enum DeviceTreeColumn : int
    {
        ColumnName = 0,
        ColumnManufacturer,
        ColumnService,
        ColumnClass,
        ColumnEnumerator,
        ColumnInstalled,
        ColumnCount
    };

    // propertyString 作用：
    // - 输入：SetupAPI 设备信息句柄、设备数据、属性键；
    // - 处理：读取 DEVPROP_TYPE_STRING 属性；
    // - 返回：成功时返回字符串，失败或类型不匹配时返回空字符串。
    QString propertyString(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        DWORD requiredSize = 0;
        SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            nullptr,
            0,
            &requiredSize,
            0);
        if (requiredSize == 0 || propertyType != DEVPROP_TYPE_STRING)
        {
            return QString();
        }

        std::vector<BYTE> buffer(requiredSize + sizeof(wchar_t), 0);
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr,
            0))
        {
            return QString();
        }

        return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.data())).trimmed();
    }

    // propertyStringList 作用：
    // - 输入：SetupAPI 设备信息句柄、设备数据、属性键；
    // - 处理：读取 DEVPROP_TYPE_STRING_LIST 多字符串属性；
    // - 返回：使用换行连接的字符串列表，失败时返回空字符串。
    QString propertyStringList(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        DWORD requiredSize = 0;
        SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            nullptr,
            0,
            &requiredSize,
            0);
        if (requiredSize == 0 || propertyType != DEVPROP_TYPE_STRING_LIST)
        {
            return QString();
        }

        std::vector<BYTE> buffer(requiredSize + sizeof(wchar_t), 0);
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr,
            0))
        {
            return QString();
        }

        QStringList valueList;
        const wchar_t* cursor = reinterpret_cast<const wchar_t*>(buffer.data());
        while (cursor != nullptr && *cursor != L'\0')
        {
            const QString valueText = QString::fromWCharArray(cursor).trimmed();
            if (!valueText.isEmpty())
            {
                valueList.append(valueText);
            }
            cursor += wcslen(cursor) + 1;
        }
        return valueList.join(QStringLiteral("\n"));
    }

    // propertyBool 作用：
    // - 输入：SetupAPI 设备信息句柄、设备数据、属性键；
    // - 处理：读取 DEVPROP_TYPE_BOOLEAN 属性；
    // - 返回：成功读取且值为 TRUE 时返回 true。
    bool propertyBool(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        DEVPROP_BOOLEAN value = DEVPROP_FALSE;
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&value),
            sizeof(value),
            nullptr,
            0))
        {
            return false;
        }
        return propertyType == DEVPROP_TYPE_BOOLEAN && value == DEVPROP_TRUE;
    }

    // propertyUInt32 作用：
    // - 输入：SetupAPI 设备信息句柄、设备数据、属性键；
    // - 处理：读取 DEVPROP_TYPE_UINT32 属性；
    // - 返回：成功时返回数值，否则返回 0。
    unsigned long propertyUInt32(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        unsigned long value = 0;
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&value),
            sizeof(value),
            nullptr,
            0))
        {
            return 0;
        }
        return propertyType == DEVPROP_TYPE_UINT32 ? value : 0;
    }

    // propertyFileTimeText 作用：
    // - 输入：SetupAPI 设备信息句柄、设备数据、属性键；
    // - 处理：读取 DEVPROP_TYPE_FILETIME 并转成本地时间文本；
    // - 返回：成功时返回 yyyy-MM-dd HH:mm:ss，失败时返回空字符串。
    QString propertyFileTimeText(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        FILETIME fileTime{};
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&fileTime),
            sizeof(fileTime),
            nullptr,
            0)
            || propertyType != DEVPROP_TYPE_FILETIME)
        {
            return QString();
        }

        FILETIME localFileTime{};
        SYSTEMTIME systemTime{};
        if (!FileTimeToLocalFileTime(&fileTime, &localFileTime)
            || !FileTimeToSystemTime(&localFileTime, &systemTime))
        {
            return QString();
        }

        return QStringLiteral("%1-%2-%3 %4:%5:%6")
            .arg(systemTime.wYear, 4, 10, QLatin1Char('0'))
            .arg(systemTime.wMonth, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wDay, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wHour, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wMinute, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wSecond, 2, 10, QLatin1Char('0'));
    }

    // propertyGuidText 作用：
    // - 输入：SetupAPI 设备信息句柄、设备数据、属性键；
    // - 处理：读取 DEVPROP_TYPE_GUID 并格式化为大括号 GUID；
    // - 返回：成功时返回 GUID 文本，否则返回空字符串。
    QString propertyGuidText(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DEVPROPKEY& propertyKey)
    {
        DEVPROPTYPE propertyType = 0;
        GUID guidValue{};
        if (!SetupDiGetDevicePropertyW(
            deviceInfoSet,
            deviceInfoData,
            &propertyKey,
            &propertyType,
            reinterpret_cast<PBYTE>(&guidValue),
            sizeof(guidValue),
            nullptr,
            0)
            || propertyType != DEVPROP_TYPE_GUID)
        {
            return QString();
        }

        wchar_t buffer[64] = {};
        if (StringFromGUID2(guidValue, buffer, static_cast<int>(std::size(buffer))) <= 0)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer);
    }

    // registryPropertyString 作用：
    // - 输入：SetupAPI 设备信息句柄、设备数据、SPDRP_* 属性编号；
    // - 处理：读取老式设备注册表属性，补齐部分 DEVPROPKEY 不稳定字段；
    // - 返回：字符串/多字符串属性使用换行连接，失败时返回空字符串。
    QString registryPropertyString(
        HDEVINFO deviceInfoSet,
        SP_DEVINFO_DATA* deviceInfoData,
        const DWORD propertyValue)
    {
        DWORD requiredSize = 0;
        DWORD propertyType = 0;
        SetupDiGetDeviceRegistryPropertyW(
            deviceInfoSet,
            deviceInfoData,
            propertyValue,
            &propertyType,
            nullptr,
            0,
            &requiredSize);
        if (requiredSize == 0)
        {
            return QString();
        }

        std::vector<BYTE> buffer(requiredSize + sizeof(wchar_t) * 2U, 0);
        if (!SetupDiGetDeviceRegistryPropertyW(
            deviceInfoSet,
            deviceInfoData,
            propertyValue,
            &propertyType,
            buffer.data(),
            static_cast<DWORD>(buffer.size()),
            nullptr))
        {
            return QString();
        }

        if (propertyType == REG_MULTI_SZ)
        {
            QStringList valueList;
            const wchar_t* cursor = reinterpret_cast<const wchar_t*>(buffer.data());
            while (cursor != nullptr && *cursor != L'\0')
            {
                const QString valueText = QString::fromWCharArray(cursor).trimmed();
                if (!valueText.isEmpty())
                {
                    valueList.append(valueText);
                }
                cursor += wcslen(cursor) + 1;
            }
            return valueList.join(QStringLiteral("\n"));
        }

        if (propertyType == REG_SZ || propertyType == REG_EXPAND_SZ)
        {
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.data())).trimmed();
        }

        return QString();
    }

    // serviceImagePath 作用：
    // - 输入：设备 Service 名；
    // - 处理：读取 HKLM\SYSTEM\CurrentControlSet\Services\<Service>\ImagePath；
    // - 返回：成功时返回驱动服务映像路径，失败时返回空字符串。
    QString serviceImagePath(const QString& serviceNameText)
    {
        if (serviceNameText.trimmed().isEmpty())
        {
            return QString();
        }

        const QString keyPath = QStringLiteral("SYSTEM\\CurrentControlSet\\Services\\%1").arg(serviceNameText.trimmed());
        HKEY serviceKey = nullptr;
        if (RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            reinterpret_cast<LPCWSTR>(keyPath.utf16()),
            0,
            KEY_READ,
            &serviceKey) != ERROR_SUCCESS)
        {
            return QString();
        }

        DWORD valueType = 0;
        DWORD valueSize = 0;
        const LONG querySizeResult = RegQueryValueExW(
            serviceKey,
            L"ImagePath",
            nullptr,
            &valueType,
            nullptr,
            &valueSize);
        if (querySizeResult != ERROR_SUCCESS || valueSize == 0)
        {
            RegCloseKey(serviceKey);
            return QString();
        }

        std::vector<BYTE> buffer(valueSize + sizeof(wchar_t), 0);
        const LONG queryValueResult = RegQueryValueExW(
            serviceKey,
            L"ImagePath",
            nullptr,
            &valueType,
            buffer.data(),
            &valueSize);
        RegCloseKey(serviceKey);
        if (queryValueResult != ERROR_SUCCESS || (valueType != REG_SZ && valueType != REG_EXPAND_SZ))
        {
            return QString();
        }

        return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.data())).trimmed();
    }

    // driverRegistryPathFromClassKey 作用：
    // - 输入：ClassGuid 与 Driver key name，例如 "0001"；
    // - 处理：拼接设备管理器驱动注册表路径；
    // - 返回：字段完整时返回 HKLM\SYSTEM\CurrentControlSet\Control\Class\{GUID}\0001。
    QString driverRegistryPathFromClassKey(const QString& classGuidText, const QString& driverKeyText)
    {
        if (classGuidText.trimmed().isEmpty() || driverKeyText.trimmed().isEmpty())
        {
            return QString();
        }

        return QStringLiteral("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Class\\%1\\%2")
            .arg(classGuidText.trimmed(), driverKeyText.trimmed());
    }

    // formatWin32Error 作用：
    // - 输入：Win32 错误码；
    // - 处理：调用 FormatMessageW 获取系统错误文本；
    // - 返回：包含十进制、十六进制和消息正文的诊断字符串。
    QString formatWin32Error(const DWORD errorCode)
    {
        wchar_t* messageBuffer = nullptr;
        const DWORD writtenLength = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            0,
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);

        QString messageText;
        if (writtenLength > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer).trimmed();
            LocalFree(messageBuffer);
        }

        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("未知错误");
        }

        return QStringLiteral("%1 (0x%2): %3")
            .arg(errorCode)
            .arg(errorCode, 8, 16, QLatin1Char('0'))
            .arg(messageText);
    }

    // currentProcessIsElevated 作用：
    // - 输入：当前进程；
    // - 处理：查询 TokenElevation；
    // - 返回：管理员提升运行时返回 true，否则返回 false。
    bool currentProcessIsElevated()
    {
        HANDLE tokenHandle = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle))
        {
            return false;
        }

        TOKEN_ELEVATION elevation{};
        DWORD returnLength = 0;
        const BOOL queryOk = GetTokenInformation(
            tokenHandle,
            TokenElevation,
            &elevation,
            sizeof(elevation),
            &returnLength);
        CloseHandle(tokenHandle);
        return queryOk != FALSE && elevation.TokenIsElevated != 0;
    }

    // instanceIdFromDevInst 前置声明：
    // - findDeviceInfoDataByInstanceId 需要在重新定位设备时回退读取 CfgMgr Instance ID；
    // - 实现放在下方，声明放在这里避免函数定义顺序导致编译失败。
    QString instanceIdFromDevInst(DEVINST devInst);

    // findDeviceInfoDataByInstanceId 作用：
    // - 输入：PnP Instance ID；
    // - 处理：优先用 SetupDiOpenDeviceInfoW 精确打开单个 DevNode，失败再回退全类线性枚举；
    // - 返回：成功时填充 deviceInfoSetOut/deviceInfoDataOut，调用方必须 SetupDiDestroyDeviceInfoList。
    bool findDeviceInfoDataByInstanceId(
        const QString& instanceIdText,
        HDEVINFO* const deviceInfoSetOut,
        SP_DEVINFO_DATA* const deviceInfoDataOut,
        QString* const errorTextOut)
    {
        if (deviceInfoSetOut == nullptr || deviceInfoDataOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("内部错误：输出参数为空。");
            }
            return false;
        }

        *deviceInfoSetOut = INVALID_HANDLE_VALUE;
        ZeroMemory(deviceInfoDataOut, sizeof(*deviceInfoDataOut));
        deviceInfoDataOut->cbSize = sizeof(SP_DEVINFO_DATA);
        // normalizedInstanceIdText 用途：统一去掉首尾空白，供精确定位与线性回退共用同一份文本。
        const QString normalizedInstanceIdText = instanceIdText.trimmed();
        if (normalizedInstanceIdText.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("设备 Instance ID 为空。");
            }
            return false;
        }

        // 精确定位优先：
        // - SetupDiCreateDeviceInfoList + SetupDiOpenDeviceInfoW 只解析目标 DevNode；
        // - 避免 DIGCF_ALLCLASSES（不带 DIGCF_PRESENT）把数千个历史设备逐个读属性。
        HDEVINFO targetedDeviceInfoSet = SetupDiCreateDeviceInfoList(nullptr, nullptr);
        if (targetedDeviceInfoSet != INVALID_HANDLE_VALUE)
        {
            SP_DEVINFO_DATA targetedDeviceInfoData{};
            targetedDeviceInfoData.cbSize = sizeof(targetedDeviceInfoData);
            if (SetupDiOpenDeviceInfoW(
                targetedDeviceInfoSet,
                reinterpret_cast<LPCWSTR>(normalizedInstanceIdText.utf16()),
                nullptr,
                0,
                &targetedDeviceInfoData))
            {
                *deviceInfoSetOut = targetedDeviceInfoSet;
                *deviceInfoDataOut = targetedDeviceInfoData;
                return true;
            }
            SetupDiDestroyDeviceInfoList(targetedDeviceInfoSet);
        }

        // 回退路径：极少数 DevNode 无法被 SetupDiOpenDeviceInfoW 打开时，仍按旧逻辑线性扫描。
        HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, DIGCF_ALLCLASSES);
        if (deviceInfoSet == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupDiGetClassDevsW 失败：%1").arg(formatWin32Error(GetLastError()));
            }
            return false;
        }

        for (DWORD index = 0;; ++index)
        {
            SP_DEVINFO_DATA candidateData{};
            candidateData.cbSize = sizeof(candidateData);
            if (!SetupDiEnumDeviceInfo(deviceInfoSet, index, &candidateData))
            {
                break;
            }

            QString candidateInstanceId = propertyString(deviceInfoSet, &candidateData, DEVPKEY_Device_InstanceId);
            if (candidateInstanceId.isEmpty())
            {
                candidateInstanceId = instanceIdFromDevInst(candidateData.DevInst);
            }
            if (candidateInstanceId.compare(normalizedInstanceIdText, Qt::CaseInsensitive) == 0)
            {
                *deviceInfoSetOut = deviceInfoSet;
                *deviceInfoDataOut = candidateData;
                return true;
            }
        }

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("未找到设备：%1").arg(instanceIdText);
        }
        return false;
    }

    // instanceIdFromDevInst 作用：
    // - 输入：CfgMgr devinst；
    // - 处理：调用 CM_Get_Device_IDW 获取实例 ID；
    // - 返回：成功时返回实例 ID，否则返回空字符串。
    QString instanceIdFromDevInst(DEVINST devInst)
    {
        ULONG charCount = 0;
        if (CM_Get_Device_ID_Size(&charCount, devInst, 0) != CR_SUCCESS || charCount == 0)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(static_cast<std::size_t>(charCount) + 2U, L'\0');
        if (CM_Get_Device_IDW(devInst, buffer.data(), static_cast<ULONG>(buffer.size()), 0) != CR_SUCCESS)
        {
            return QString();
        }
        return QString::fromWCharArray(buffer.data()).trimmed();
    }

    // deviceStatusText 作用：
    // - 输入：CfgMgr 状态和问题码；
    // - 处理：生成详情区可读状态摘要；
    // - 返回：状态字符串。
    QString deviceStatusText(const ULONG statusFlags, const ULONG problemCode)
    {
        QStringList partList;
        partList.append(QStringLiteral("DN=0x%1").arg(statusFlags, 8, 16, QLatin1Char('0')));
        if ((statusFlags & DN_STARTED) != 0)
        {
            partList.append(QStringLiteral("STARTED"));
        }
        if ((statusFlags & DN_HAS_PROBLEM) != 0)
        {
            partList.append(QStringLiteral("HAS_PROBLEM"));
        }
        if ((statusFlags & DN_DISABLEABLE) != 0)
        {
            partList.append(QStringLiteral("DISABLEABLE"));
        }
        if ((statusFlags & DN_REMOVABLE) != 0)
        {
            partList.append(QStringLiteral("REMOVABLE"));
        }
        if ((statusFlags & DN_PRIVATE_PROBLEM) != 0)
        {
            partList.append(QStringLiteral("PRIVATE_PROBLEM"));
        }
        if (problemCode != 0)
        {
            partList.append(QStringLiteral("Problem=%1").arg(problemCode));
        }
        return partList.join(QStringLiteral(" | "));
    }

    // safeDisplayText 作用：
    // - 输入：候选文本；
    // - 处理：空值统一展示为 '-'，避免表格大片空白难以阅读；
    // - 返回：可展示文本。
    QString safeDisplayText(const QString& valueText)
    {
        return valueText.trimmed().isEmpty() ? QStringLiteral("-") : valueText.trimmed();
    }

    // itemMatchesFilter 作用：
    // - 输入：设备项和小写过滤文本；
    // - 处理：在主要列和实例 ID 中做包含匹配；
    // - 返回：匹配时 true，空过滤条件永远 true。
    bool itemMatchesFilter(
        const HardwareDeviceManagerPage::DeviceEntry& entry,
        const QString& lowerFilterText)
    {
        if (lowerFilterText.isEmpty())
        {
            return true;
        }

        const QString joinedText = QStringLiteral("%1\n%2\n%3\n%4\n%5\n%6\n%7\n%8\n%9\n%10\n%11")
            .arg(entry.nameText)
            .arg(entry.manufacturerText)
            .arg(entry.serviceText)
            .arg(entry.classText)
            .arg(entry.enumeratorText)
            .arg(entry.instanceIdText)
            .arg(entry.parentInstanceIdText)
            .arg(entry.hardwareIdsText)
            .arg(entry.driverInfPathText)
            .arg(entry.driverProviderText)
            .arg(entry.serviceImagePathText)
            .toLower();
        return joinedText.contains(lowerFilterText);
    }

    // buildDevicePropertiesText 作用：
    // - 输入：设备快照；
    // - 处理：整理成设备属性页正文；
    // - 返回：适合 ks::ui::StructuredFieldView 展示的只读文本。
    ks::ui::FieldDocument buildDevicePropertiesText(const HardwareDeviceManagerPage::DeviceEntry& entry)
    {
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("常规"));
        document.field(QStringLiteral("名称"), QStringLiteral("%1").arg(safeDisplayText(entry.nameText)));
        document.field(QStringLiteral("制造商"), QStringLiteral("%1").arg(safeDisplayText(entry.manufacturerText)));
        document.field(QStringLiteral("设备类"), QStringLiteral("%1").arg(safeDisplayText(entry.classText)));
        document.field(QStringLiteral("Class GUID"), QStringLiteral("%1").arg(safeDisplayText(entry.classGuidText)));
        document.field(QStringLiteral("枚举器"), QStringLiteral("%1").arg(safeDisplayText(entry.enumeratorText)));
        document.field(QStringLiteral("位置"), QStringLiteral("%1").arg(safeDisplayText(entry.locationText)));
        document.field(QStringLiteral("已安装"), QStringLiteral("%1").arg(safeDisplayText(entry.installedText)));
        document.field(QStringLiteral("当前存在"), QStringLiteral("%1").arg(entry.isPresent ? QStringLiteral("Yes") : QStringLiteral("No")));
        document.field(QStringLiteral("存在问题"), QStringLiteral("%1").arg(entry.hasProblem ? QStringLiteral("Yes") : QStringLiteral("No")));
        document.field(QStringLiteral("问题"), QStringLiteral("%1").arg(safeDisplayText(entry.problemText)));
        document.field(QStringLiteral("状态"), QStringLiteral("%1").arg(safeDisplayText(entry.statusText)));
        document.section(QStringLiteral("标识"));
        document.field(QStringLiteral("实例 ID"), QStringLiteral("%1").arg(safeDisplayText(entry.instanceIdText)));
        document.field(QStringLiteral("父实例 ID"), QStringLiteral("%1").arg(safeDisplayText(entry.parentInstanceIdText)));
        document.field(QStringLiteral("硬件 ID"), QStringLiteral("%1").arg(safeDisplayText(entry.hardwareIdsText)));
        document.field(QStringLiteral("兼容 ID"), QStringLiteral("%1").arg(safeDisplayText(entry.compatibleIdsText)));
        document.section(QStringLiteral("驱动绑定"));
        document.field(QStringLiteral("服务"), QStringLiteral("%1").arg(safeDisplayText(entry.serviceText)));
        document.field(QStringLiteral("驱动键"), QStringLiteral("%1").arg(safeDisplayText(entry.driverText)));
        document.field(QStringLiteral("驱动注册表路径"), QStringLiteral("%1").arg(safeDisplayText(entry.driverRegistryPathText)));
        document.field(QStringLiteral("驱动 INF"), QStringLiteral("%1").arg(safeDisplayText(entry.driverInfPathText)));
        document.field(QStringLiteral("提供商"), QStringLiteral("%1").arg(safeDisplayText(entry.driverProviderText)));
        document.field(QStringLiteral("版本"), QStringLiteral("%1").arg(safeDisplayText(entry.driverVersionText)));
        document.field(QStringLiteral("日期"), QStringLiteral("%1").arg(safeDisplayText(entry.driverDateText)));
        document.field(QStringLiteral("服务 ImagePath"), QStringLiteral("%1").arg(safeDisplayText(entry.serviceImagePathText)));
        return document;
    }

    // buildDriverDetailsText 作用：
    // - 输入：设备快照；
    // - 处理：整理成“驱动程序详细信息”正文；
    // - 返回：INF、Provider、Version、服务镜像路径等驱动排障信息。
    ks::ui::FieldDocument buildDriverDetailsText(const HardwareDeviceManagerPage::DeviceEntry& entry)
    {
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("驱动"));
        document.field(QStringLiteral("设备"), QStringLiteral("%1").arg(safeDisplayText(entry.nameText)));
        document.field(QStringLiteral("实例 ID"), QStringLiteral("%1").arg(safeDisplayText(entry.instanceIdText)));
        document.field(QStringLiteral("服务"), QStringLiteral("%1").arg(safeDisplayText(entry.serviceText)));
        document.field(QStringLiteral("服务 ImagePath"), QStringLiteral("%1").arg(safeDisplayText(entry.serviceImagePathText)));
        document.field(QStringLiteral("驱动键"), QStringLiteral("%1").arg(safeDisplayText(entry.driverText)));
        document.field(QStringLiteral("驱动注册表路径"), QStringLiteral("%1").arg(safeDisplayText(entry.driverRegistryPathText)));
        document.field(QStringLiteral("驱动 INF"), QStringLiteral("%1").arg(safeDisplayText(entry.driverInfPathText)));
        document.field(QStringLiteral("提供商"), QStringLiteral("%1").arg(safeDisplayText(entry.driverProviderText)));
        document.field(QStringLiteral("版本"), QStringLiteral("%1").arg(safeDisplayText(entry.driverVersionText)));
        document.field(QStringLiteral("日期"), QStringLiteral("%1").arg(safeDisplayText(entry.driverDateText)));
        document.field(QStringLiteral("设备类"), QStringLiteral("%1").arg(safeDisplayText(entry.classText)));
        document.field(QStringLiteral("Class GUID"), QStringLiteral("%1").arg(safeDisplayText(entry.classGuidText)));
        document.section(QStringLiteral("匹配 ID"));
        document.field(QStringLiteral("硬件 ID"), QStringLiteral("%1").arg(safeDisplayText(entry.hardwareIdsText)));
        document.field(QStringLiteral("兼容 ID"), QStringLiteral("%1").arg(safeDisplayText(entry.compatibleIdsText)));
        document.section(QStringLiteral("说明"));
        document.note(QStringLiteral("- 卸载设备会移除当前 DevNode，可能要求重启或重新扫描硬件。"));
        document.note(QStringLiteral("- 删除驱动包只支持 oem*.inf"));
        document.note(QStringLiteral("系统内置 INF 或正在使用的驱动包通常会失败。"));
        return document;
    }

    // showTextDialog 作用：
    // - 输入：父窗口、标题、正文；
    // - 处理：使用项目 ks::ui::StructuredFieldView 弹出只读文本窗口；
    // - 返回值：无。
    void showTextDialog(QWidget* const parentWidget, const QString& titleText, const ks::ui::FieldDocument& bodyText)
    {
        QDialog dialog(parentWidget);
        dialog.setWindowTitle(titleText);
        dialog.resize(820, 620);

        QVBoxLayout* layout = new QVBoxLayout(&dialog);
        ks::ui::StructuredFieldView* editor = new ks::ui::StructuredFieldView(&dialog);

        editor->setDocument(bodyText);
        layout->addWidget(editor, 1);

        QPushButton* closeButton = new QPushButton(QStringLiteral("关闭"), &dialog);
        QObject::connect(closeButton, &QPushButton::clicked, &dialog, &QDialog::accept);
        QHBoxLayout* buttonLayout = new QHBoxLayout();
        buttonLayout->addStretch(1);
        buttonLayout->addWidget(closeButton);
        layout->addLayout(buttonLayout);

        dialog.exec();
    }

    // uninstallDeviceByInstanceId 作用：
    // - 输入：PnP Instance ID；
    // - 处理：定位 SP_DEVINFO_DATA 后调用 DIF_REMOVE；
    // - 返回：成功时 true；失败时 errorTextOut 保存 Win32 诊断。
    bool uninstallDeviceByInstanceId(const QString& instanceIdText, QString* const errorTextOut)
    {
        HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;
        SP_DEVINFO_DATA deviceInfoData{};
        QString findErrorText;
        if (!findDeviceInfoDataByInstanceId(instanceIdText, &deviceInfoSet, &deviceInfoData, &findErrorText))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = findErrorText;
            }
            return false;
        }

        SP_REMOVEDEVICE_PARAMS removeParams{};
        removeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        removeParams.ClassInstallHeader.InstallFunction = DIF_REMOVE;
        removeParams.Scope = DI_REMOVEDEVICE_GLOBAL;
        removeParams.HwProfile = 0;

        if (!SetupDiSetClassInstallParamsW(
            deviceInfoSet,
            &deviceInfoData,
            &removeParams.ClassInstallHeader,
            sizeof(removeParams)))
        {
            const DWORD errorCode = GetLastError();
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupDiSetClassInstallParamsW 失败：%1").arg(formatWin32Error(errorCode));
            }
            return false;
        }

        if (!SetupDiCallClassInstaller(DIF_REMOVE, deviceInfoSet, &deviceInfoData))
        {
            const DWORD errorCode = GetLastError();
            SetupDiDestroyDeviceInfoList(deviceInfoSet);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupDiCallClassInstaller(DIF_REMOVE) 失败：%1").arg(formatWin32Error(errorCode));
            }
            return false;
        }

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        return true;
    }

    // normalizeOemInfName 作用：
    // - 输入：SetupAPI/DEVPROP 返回的 INF 字段；
    // - 处理：提取文件名并只允许 oem*.inf；
    // - 返回：可传入 SetupUninstallOEMInfW 的 INF 文件名，非 OEM INF 返回空。
    QString normalizeOemInfName(const QString& infText)
    {
        QString normalizedText = infText.trimmed();
        if (normalizedText.isEmpty())
        {
            return QString();
        }

        normalizedText.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const int separatorIndex = normalizedText.lastIndexOf(QLatin1Char('\\'));
        if (separatorIndex >= 0)
        {
            normalizedText = normalizedText.mid(separatorIndex + 1);
        }

        if (!normalizedText.startsWith(QStringLiteral("oem"), Qt::CaseInsensitive)
            || !normalizedText.endsWith(QStringLiteral(".inf"), Qt::CaseInsensitive))
        {
            return QString();
        }
        return normalizedText;
    }

    // uninstallOemInfPackage 作用：
    // - 输入：INF 名称或路径；
    // - 处理：调用 SetupUninstallOEMInfW 删除第三方驱动包；
    // - 返回：成功时 true；失败时 errorTextOut 保存 Win32 诊断。
    bool uninstallOemInfPackage(const QString& infText, QString* const errorTextOut)
    {
        const QString oemInfName = normalizeOemInfName(infText);
        if (oemInfName.isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("当前设备没有可删除的 oem*.inf 驱动包。");
            }
            return false;
        }

        if (!SetupUninstallOEMInfW(
            reinterpret_cast<LPCWSTR>(oemInfName.utf16()),
            SUOI_FORCEDELETE,
            nullptr))
        {
            const DWORD errorCode = GetLastError();
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("SetupUninstallOEMInfW(%1) 失败：%2")
                    .arg(oemInfName, formatWin32Error(errorCode));
            }
            return false;
        }

        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        return true;
    }
}

HardwareDeviceManagerPage::HardwareDeviceManagerPage(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();
    refreshDevicesAsync(false);
}

void HardwareDeviceManagerPage::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("设备管理"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    headerLayout->addWidget(titleLabel, 0);

    m_statusLabel = new QLabel(QStringLiteral("正在枚举当前设备..."), this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(KswordTheme::TextSecondaryHex()));
    headerLayout->addWidget(m_statusLabel, 1);

    m_showAllDevicesCheck = new QCheckBox(QStringLiteral("显示全部设备"), this);
    m_showAllDevicesCheck->setToolTip(QStringLiteral("关闭时仅枚举当前存在设备；开启后包含历史/非当前设备。"));
    headerLayout->addWidget(m_showAllDevicesCheck, 0);

    m_showProblemOnlyCheck = new QCheckBox(QStringLiteral("只显示异常设备"), this);
    m_showProblemOnlyCheck->setToolTip(QStringLiteral("仅显示 HasProblem 或 CM_PROB 非 0 的设备节点，并保留其父级路径。"));
    headerLayout->addWidget(m_showProblemOnlyCheck, 0);

    m_searchEdit = new QLineEdit(this);
    m_searchEdit->setPlaceholderText(QStringLiteral("搜索名称、厂商、服务、类、枚举器、Instance ID..."));
    m_searchEdit->setMinimumWidth(220);
    headerLayout->addWidget(m_searchEdit, 1);

    m_refreshButton = new QPushButton(QStringLiteral("刷新"), this);
    m_refreshButton->setToolTip(QStringLiteral("重新通过 SetupAPI/CfgMgr 枚举 PnP 设备树"));
    headerLayout->addWidget(m_refreshButton, 0);
    m_rootLayout->addLayout(headerLayout, 0);

    m_splitter = new QSplitter(Qt::Vertical, this);
    m_splitter->setChildrenCollapsible(false);
    m_rootLayout->addWidget(m_splitter, 1);

    m_deviceTree = new QTreeWidget(m_splitter);
    m_deviceTree->setColumnCount(ColumnCount);
    m_deviceTree->setHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Manufacturer"),
        QStringLiteral("Service"),
        QStringLiteral("Class"),
        QStringLiteral("Enumerator"),
        QStringLiteral("Installed")
        });
    m_deviceTree->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_deviceTree->setSelectionMode(QAbstractItemView::SingleSelection);
    m_deviceTree->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_deviceTree->setContextMenuPolicy(Qt::CustomContextMenu);
    m_deviceTree->setUniformRowHeights(true);
    m_deviceTree->setAlternatingRowColors(true);
    m_deviceTree->header()->setStretchLastSection(false);
    m_deviceTree->header()->setSectionResizeMode(ColumnName, QHeaderView::Interactive);
    m_deviceTree->header()->setSectionResizeMode(ColumnManufacturer, QHeaderView::Interactive);
    m_deviceTree->header()->setSectionResizeMode(ColumnService, QHeaderView::ResizeToContents);
    m_deviceTree->header()->setSectionResizeMode(ColumnClass, QHeaderView::ResizeToContents);
    m_deviceTree->header()->setSectionResizeMode(ColumnEnumerator, QHeaderView::ResizeToContents);
    m_deviceTree->header()->setSectionResizeMode(ColumnInstalled, QHeaderView::ResizeToContents);
    m_deviceTree->setColumnWidth(ColumnName, 360);
    m_deviceTree->setColumnWidth(ColumnManufacturer, 190);
    m_splitter->addWidget(m_deviceTree);

    m_detailEditor = new ks::ui::StructuredFieldView(m_splitter);

    m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("选择一个设备查看详细属性。")));
    m_splitter->addWidget(m_detailEditor);

    // 已有 splitter 的两个直接面板由页面明确声明，避免误接管外层布局。
    ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_deviceTree, m_detailEditor, this, m_splitter, m_deviceTree, m_detailEditor);
    m_splitter->setStretchFactor(0, 4);
    m_splitter->setStretchFactor(1, 1);
}

void HardwareDeviceManagerPage::initializeConnections()
{
    connect(m_refreshButton, &QPushButton::clicked, this, [this]()
    {
        refreshDevicesAsync(true);
    });

    connect(m_showAllDevicesCheck, &QCheckBox::toggled, this, [this](const bool)
    {
        refreshDevicesAsync(true);
    });

    connect(m_showProblemOnlyCheck, &QCheckBox::toggled, this, [this](const bool)
    {
        if (m_deviceTree == nullptr)
        {
            return;
        }
        ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEditor);
        const QString filterText = m_searchEdit != nullptr ? m_searchEdit->text().trimmed().toLower() : QString();
        for (int index = 0; index < m_deviceTree->topLevelItemCount(); ++index)
        {
            applyFilterToTree(m_deviceTree->topLevelItem(index), filterText);
        }
        if (m_showProblemOnlyCheck != nullptr && m_showProblemOnlyCheck->isChecked())
        {
            m_deviceTree->expandAll();
        }
    });

    connect(m_searchEdit, &QLineEdit::textChanged, this, [this](const QString&)
    {
        if (m_deviceTree == nullptr)
        {
            return;
        }
        ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEditor);
        const QString filterText = m_searchEdit != nullptr ? m_searchEdit->text().trimmed().toLower() : QString();
        for (int index = 0; index < m_deviceTree->topLevelItemCount(); ++index)
        {
            applyFilterToTree(m_deviceTree->topLevelItem(index), filterText);
        }
        if (!filterText.isEmpty())
        {
            m_deviceTree->expandAll();
        }
    });

    connect(
        m_deviceTree,
        &QTreeWidget::currentItemChanged,
        this,
        [this](QTreeWidgetItem* currentItem, QTreeWidgetItem*)
        {
            updateDetailForItem(currentItem);
        });

    connect(
        m_deviceTree,
        &QTreeWidget::itemDoubleClicked,
        this,
        [this](QTreeWidgetItem*, int)
        {
            showSelectedDeviceProperties();
        });

    connect(
        m_deviceTree,
        &QTreeWidget::customContextMenuRequested,
        this,
        [this](const QPoint& localPosition)
        {
            showDeviceContextMenu(localPosition);
        });
}

void HardwareDeviceManagerPage::refreshDevicesAsync(const bool forceRefresh)
{
    bool expectedValue = false;
    if (!m_refreshing.compare_exchange_strong(expectedValue, true))
    {
        if (forceRefresh && m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("正在刷新，请等待当前枚举完成。"));
        }
        return;
    }

    const bool includeAllDevices = m_showAllDevicesCheck != nullptr && m_showAllDevicesCheck->isChecked();
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(includeAllDevices
            ? QStringLiteral("正在枚举全部设备...")
            : QStringLiteral("正在枚举当前设备..."));
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(false);
    }
    if (m_showAllDevicesCheck != nullptr)
    {
        m_showAllDevicesCheck->setEnabled(false);
    }

    QPointer<HardwareDeviceManagerPage> safeThis(this);
    std::thread([safeThis, includeAllDevices]()
    {
        std::vector<DeviceEntry> deviceList = enumerateDevicesSnapshot(includeAllDevices);
        if (safeThis.isNull())
        {
            return;
        }

        const bool invokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, deviceList = std::move(deviceList), includeAllDevices]() mutable
            {
                if (safeThis.isNull())
                {
                    return;
                }

                safeThis->applyDeviceSnapshot(
                    std::move(deviceList),
                    includeAllDevices);
            },
            Qt::QueuedConnection);

        if (!invokeOk && !safeThis.isNull())
        {
            safeThis->m_refreshing.store(false);
        }
    }).detach();
}

void HardwareDeviceManagerPage::applyDeviceSnapshot(
    std::vector<DeviceEntry> deviceList,
    const bool includeAllDevices)
{
    if (ks::ui::IsItemViewUiCommitBlockedByContextMenu({m_deviceTree}))
    {
        const QPointer<HardwareDeviceManagerPage> safeThis(this);
        ks::ui::DeferItemViewUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("hardware-device-tree-snapshot-apply"),
            {m_deviceTree},
            [safeThis,
                deviceList = std::move(deviceList),
                includeAllDevices]() mutable
            {
                if (!safeThis.isNull())
                {
                    safeThis->applyDeviceSnapshot(
                        std::move(deviceList),
                        includeAllDevices);
                }
            });
        return;
    }

    m_deviceList = std::move(deviceList);
    rebuildDeviceTree(m_deviceList);

    int problemCount = 0;
    for (const DeviceEntry& entry : m_deviceList)
    {
        if (entry.hasProblem)
        {
            ++problemCount;
        }
    }
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(
            QStringLiteral("%1设备：%2 项，异常：%3，刷新：%4")
            .arg(includeAllDevices ? QStringLiteral("全部") : QStringLiteral("当前"))
            .arg(static_cast<int>(m_deviceList.size()))
            .arg(problemCount)
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(true);
    }
    if (m_showAllDevicesCheck != nullptr)
    {
        m_showAllDevicesCheck->setEnabled(true);
    }
    m_refreshing.store(false);
}

void HardwareDeviceManagerPage::rebuildDeviceTree(const std::vector<DeviceEntry>& deviceList)
{
    if (m_deviceTree == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_detailEditor);

    m_deviceTree->clear();
    if (deviceList.empty())
    {
        if (m_detailEditor != nullptr)
        {
            m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("未枚举到设备。")));
        }
        return;
    }

    QSignalBlocker treeSignalBlocker(m_deviceTree);
    QHash<QString, QTreeWidgetItem*> itemByInstanceId;
    itemByInstanceId.reserve(static_cast<qsizetype>(deviceList.size()));
    std::vector<std::unique_ptr<QTreeWidgetItem>> itemOwnerList;
    itemOwnerList.reserve(deviceList.size());

    const QColor problemForeground = KswordTheme::ErrorColor();
    const QColor missingForeground = KswordTheme::TextSecondaryColor();
    const QColor normalForeground = QColor();

    for (const DeviceEntry& entry : deviceList)
    {
        std::unique_ptr<QTreeWidgetItem> itemPointer = std::make_unique<QTreeWidgetItem>();
        itemPointer->setText(ColumnName, safeDisplayText(entry.nameText));
        itemPointer->setText(ColumnManufacturer, safeDisplayText(entry.manufacturerText));
        itemPointer->setText(ColumnService, safeDisplayText(entry.serviceText));
        itemPointer->setText(ColumnClass, safeDisplayText(entry.classText));
        itemPointer->setText(ColumnEnumerator, safeDisplayText(entry.enumeratorText));
        itemPointer->setText(ColumnInstalled, safeDisplayText(entry.installedText));
        itemPointer->setToolTip(ColumnName, entry.instanceIdText);
        itemPointer->setData(
            ColumnName,
            Qt::UserRole,
            QVariant::fromValue(reinterpret_cast<quintptr>(&entry)));

        if (entry.hasProblem)
        {
            for (int column = 0; column < ColumnCount; ++column)
            {
                itemPointer->setForeground(column, problemForeground);
            }
            itemPointer->setToolTip(
                ColumnName,
                QStringLiteral("%1\n%2").arg(entry.instanceIdText, entry.problemText));
        }
        else if (!entry.isPresent)
        {
            for (int column = 0; column < ColumnCount; ++column)
            {
                itemPointer->setForeground(column, missingForeground);
            }
        }
        else
        {
            Q_UNUSED(normalForeground);
        }

        if (!entry.instanceIdText.isEmpty())
        {
            itemByInstanceId.insert(entry.instanceIdText.toLower(), itemPointer.get());
        }
        itemOwnerList.push_back(std::move(itemPointer));
    }

    for (std::size_t index = 0; index < deviceList.size(); ++index)
    {
        QTreeWidgetItem* itemPointer = itemOwnerList[index].get();
        const QString parentKey = deviceList[index].parentInstanceIdText.toLower();
        QTreeWidgetItem* parentItem = nullptr;
        if (!parentKey.isEmpty())
        {
            const auto parentIt = itemByInstanceId.constFind(parentKey);
            if (parentIt != itemByInstanceId.constEnd() && parentIt.value() != itemPointer)
            {
                parentItem = parentIt.value();
            }
        }

        if (parentItem != nullptr)
        {
            parentItem->addChild(itemOwnerList[index].release());
        }
        else
        {
            m_deviceTree->addTopLevelItem(itemOwnerList[index].release());
        }
    }

    m_deviceTree->sortItems(ColumnName, Qt::AscendingOrder);

    const QString filterText = m_searchEdit != nullptr ? m_searchEdit->text().trimmed().toLower() : QString();
    for (int index = 0; index < m_deviceTree->topLevelItemCount(); ++index)
    {
        applyFilterToTree(m_deviceTree->topLevelItem(index), filterText);
    }

    if (deviceList.size() <= 300 || !filterText.isEmpty())
    {
        m_deviceTree->expandToDepth(filterText.isEmpty() ? 1 : 99);
    }
    treeSignalBlocker.unblock();
    if (m_deviceTree->topLevelItemCount() > 0)
    {
        m_deviceTree->setCurrentItem(m_deviceTree->topLevelItem(0));
    }
}

bool HardwareDeviceManagerPage::applyFilterToTree(QTreeWidgetItem* itemPointer, const QString& filterText)
{
    if (itemPointer == nullptr)
    {
        return false;
    }

    bool childMatched = false;
    for (int childIndex = 0; childIndex < itemPointer->childCount(); ++childIndex)
    {
        if (applyFilterToTree(itemPointer->child(childIndex), filterText))
        {
            childMatched = true;
        }
    }

    const quintptr rawPointer = itemPointer->data(ColumnName, Qt::UserRole).value<quintptr>();
    const DeviceEntry* entryPointer = reinterpret_cast<const DeviceEntry*>(rawPointer);
    const bool selfMatched = entryPointer != nullptr && itemMatchesFilter(*entryPointer, filterText);
    const bool problemOnlyEnabled = m_showProblemOnlyCheck != nullptr && m_showProblemOnlyCheck->isChecked();
    const bool selfProblemMatched = entryPointer != nullptr && (!problemOnlyEnabled || entryPointer->hasProblem);
    const bool visible = (filterText.isEmpty() || selfMatched || childMatched)
        && (!problemOnlyEnabled || selfProblemMatched || childMatched);
    itemPointer->setHidden(!visible);
    return visible;
}

void HardwareDeviceManagerPage::updateDetailForItem(QTreeWidgetItem* itemPointer)
{
    if (m_detailEditor == nullptr)
    {
        return;
    }
    if (itemPointer == nullptr)
    {
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("选择一个设备查看详细属性。")));
        return;
    }

    const quintptr rawPointer = itemPointer->data(ColumnName, Qt::UserRole).value<quintptr>();
    const DeviceEntry* entryPointer = reinterpret_cast<const DeviceEntry*>(rawPointer);
    if (entryPointer == nullptr)
    {
        m_detailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前设备节点没有详情。")));
        return;
    }

    const DeviceEntry& entry = *entryPointer;
    m_detailEditor->setDocument(buildDevicePropertiesText(entry));
}

const HardwareDeviceManagerPage::DeviceEntry* HardwareDeviceManagerPage::selectedDeviceEntry() const
{
    // 输入：当前设备树选择。
    // 处理：读取 QTreeWidgetItem 上保存的 DeviceEntry 指针；该指针指向 m_deviceList 中的当前快照。
    // 返回：有有效选择时返回设备快照指针，否则返回 nullptr。
    if (m_deviceTree == nullptr || m_deviceTree->currentItem() == nullptr)
    {
        return nullptr;
    }

    const quintptr rawPointer = m_deviceTree->currentItem()->data(ColumnName, Qt::UserRole).value<quintptr>();
    return reinterpret_cast<const DeviceEntry*>(rawPointer);
}

void HardwareDeviceManagerPage::showDeviceContextMenu(const QPoint& localPosition)
{
    // 输入：设备树局部坐标。
    // 处理：如果点中有效设备节点，则提供设备管理器常用动作；卸载/删除包动作会在执行时再次确认。
    // 返回值：无。
    if (m_deviceTree == nullptr)
    {
        return;
    }

    QTreeWidgetItem* itemPointer = m_deviceTree->itemAt(localPosition);
    if (itemPointer == nullptr)
    {
        return;
    }
    m_deviceTree->setCurrentItem(itemPointer);

    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        return;
    }

    QMenu menu(this);
    // 右键菜单样式：
    // - 输入：当前设备树上下文菜单；
    // - 处理：显式使用主题不透明背景，避免继承透明父级导致浅色模式不可读；
    // - 返回：无，只影响菜单展示，不改变设备操作逻辑。
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* propertiesAction = menu.addAction(QStringLiteral("查看属性"));
    QAction* driverDetailsAction = menu.addAction(QStringLiteral("驱动程序详细信息"));
    QAction* copyInstanceIdAction = menu.addAction(QStringLiteral("复制 Instance ID"));
    menu.addSeparator();
    QAction* uninstallDeviceAction = menu.addAction(QStringLiteral("卸载设备..."));
    QAction* deleteDriverPackageAction = menu.addAction(QStringLiteral("删除驱动包..."));
    menu.addSeparator();
    QAction* refreshAction = menu.addAction(QStringLiteral("刷新"));

    const bool hasOemInf = !normalizeOemInfName(entryPointer->driverInfPathText).isEmpty();
    deleteDriverPackageAction->setEnabled(hasOemInf);
    if (!hasOemInf)
    {
        deleteDriverPackageAction->setToolTip(QStringLiteral("仅支持删除 oem*.inf 第三方驱动包。"));
    }

    QAction* selectedAction = menu.exec(m_deviceTree->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == propertiesAction)
    {
        showSelectedDeviceProperties();
    }
    else if (selectedAction == driverDetailsAction)
    {
        showSelectedDeviceDriverDetails();
    }
    else if (selectedAction == copyInstanceIdAction)
    {
        copySelectedDeviceInstanceId();
    }
    else if (selectedAction == uninstallDeviceAction)
    {
        uninstallSelectedDevice();
    }
    else if (selectedAction == deleteDriverPackageAction)
    {
        deleteSelectedDeviceDriverPackage();
    }
    else if (selectedAction == refreshAction)
    {
        refreshDevicesAsync(true);
    }
}

void HardwareDeviceManagerPage::showSelectedDeviceProperties()
{
    // 输入：当前选中的设备。
    // 处理：使用当前快照展示设备属性，避免在 UI 线程重新枚举造成卡顿。
    // 返回值：无。
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("设备属性"), QStringLiteral("请先选择一个设备。"));
        return;
    }

    showTextDialog(
        this,
        QStringLiteral("设备属性 - %1").arg(safeDisplayText(entryPointer->nameText)),
        buildDevicePropertiesText(*entryPointer));
}

void HardwareDeviceManagerPage::showSelectedDeviceDriverDetails()
{
    // 输入：当前选中的设备。
    // 处理：展示驱动程序详细信息，包括驱动服务、INF、Provider、Version 和服务镜像路径。
    // 返回值：无。
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("驱动程序详细信息"), QStringLiteral("请先选择一个设备。"));
        return;
    }

    showTextDialog(
        this,
        QStringLiteral("驱动程序详细信息 - %1").arg(safeDisplayText(entryPointer->nameText)),
        buildDriverDetailsText(*entryPointer));
}

void HardwareDeviceManagerPage::copySelectedDeviceInstanceId()
{
    // 输入：当前选中的设备。
    // 处理：复制 Instance ID 到系统剪贴板，并更新状态栏文本。
    // 返回值：无。
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr || entryPointer->instanceIdText.trimmed().isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("复制 Instance ID"), QStringLiteral("当前设备没有可复制的 Instance ID。"));
        return;
    }

    QClipboard* clipboard = QApplication::clipboard();
    if (clipboard != nullptr)
    {
        clipboard->setText(entryPointer->instanceIdText);
    }
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(QStringLiteral("已复制 Instance ID：%1").arg(entryPointer->instanceIdText));
    }
}

void HardwareDeviceManagerPage::uninstallSelectedDevice()
{
    // 输入：当前选中的设备。
    // 处理：管理员权限检查和二次确认后调用 SetupAPI DIF_REMOVE 卸载设备节点。
    // 返回值：无。
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("卸载设备"), QStringLiteral("请先选择一个设备。"));
        return;
    }
    if (!currentProcessIsElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("卸载设备"));
        return;
    }

    // targetInstanceIdText 用途：
    // - 确认框与后台任务期间 m_deviceList 可能被新快照整体替换，entryPointer 会失效；
    // - 因此先按值复制卸载所需的全部信息，后续流程不再解引用快照指针。
    const QString targetInstanceIdText = entryPointer->instanceIdText;
    const QString targetDeviceNameText = safeDisplayText(entryPointer->nameText);

    const QString confirmText = QStringLiteral(
        "确定要卸载此设备吗？\n\n"
        "名称：%1\n"
        "Instance ID：\n%2\n\n"
        "该操作可能导致设备暂时不可用，并可能要求重启。")
        .arg(targetDeviceNameText, safeDisplayText(targetInstanceIdText));
    if (QMessageBox::question(
        this,
        QStringLiteral("确认卸载设备"),
        confirmText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    // 复用刷新互斥标记：卸载期间禁止后台枚举与本操作并发访问同一 DevNode。
    bool expectedRefreshingValue = false;
    if (!m_refreshing.compare_exchange_strong(expectedRefreshingValue, true))
    {
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("正在刷新，请等待当前枚举完成。"));
        }
        return;
    }

    // applicationContext 与事件循环同寿命；工作线程不解引用页面指针，只把结果回投主线程。
    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_refreshing.store(false);
        return;
    }

    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(QStringLiteral("正在卸载设备，请稍候..."));
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(false);
    }
    if (m_showAllDevicesCheck != nullptr)
    {
        m_showAllDevicesCheck->setEnabled(false);
    }

    const QPointer<HardwareDeviceManagerPage> safeThis(this);
    std::thread([applicationContext, safeThis, targetInstanceIdText]()
    {
        // DIF_REMOVE 会加载类安装程序与协处理器，其中可能使用 COM；
        // 工作线程必须自建单线程套间并配对释放，COM 指针不跨线程传递。
        const HRESULT comInitializeStatus = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        QString errorText;
        const bool uninstallOk = uninstallDeviceByInstanceId(targetInstanceIdText, &errorText);

        if (SUCCEEDED(comInitializeStatus))
        {
            CoUninitialize();
        }

        QMetaObject::invokeMethod(
            applicationContext,
            [safeThis, uninstallOk, errorText]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                HardwareDeviceManagerPage* const pagePointer = safeThis.data();
                pagePointer->m_refreshing.store(false);
                if (pagePointer->m_refreshButton != nullptr)
                {
                    pagePointer->m_refreshButton->setEnabled(true);
                }
                if (pagePointer->m_showAllDevicesCheck != nullptr)
                {
                    pagePointer->m_showAllDevicesCheck->setEnabled(true);
                }

                if (!uninstallOk)
                {
                    if (pagePointer->m_statusLabel != nullptr)
                    {
                        pagePointer->m_statusLabel->setText(QStringLiteral("卸载设备失败"));
                    }

                    // privilegePromptHandled：记录设备卸载失败是否已由权限恢复流程处理。
                    const bool privilegePromptHandled =
                        ks::ui::promptForPrivilegeFailure(
                            pagePointer,
                            QStringLiteral("卸载设备"),
                            errorText);
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::critical(
                            pagePointer,
                            QStringLiteral("卸载设备失败"),
                            errorText.isEmpty() ? QStringLiteral("未知错误。") : errorText);
                    }
                    return;
                }

                QMessageBox::information(
                    pagePointer,
                    QStringLiteral("卸载设备"),
                    QStringLiteral("设备卸载请求已提交。若设备仍显示或状态未变化，请刷新或重启系统。"));
                pagePointer->refreshDevicesAsync(true);
            },
            Qt::QueuedConnection);
    }).detach();
}

void HardwareDeviceManagerPage::deleteSelectedDeviceDriverPackage()
{
    // 输入：当前选中的设备。
    // 处理：管理员权限检查和二次确认后删除 oem*.inf 驱动包。
    // 返回值：无。
    const DeviceEntry* entryPointer = selectedDeviceEntry();
    if (entryPointer == nullptr)
    {
        QMessageBox::information(this, QStringLiteral("删除驱动包"), QStringLiteral("请先选择一个设备。"));
        return;
    }
    if (!currentProcessIsElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("删除驱动包"));
        return;
    }

    const QString oemInfName = normalizeOemInfName(entryPointer->driverInfPathText);
    if (oemInfName.isEmpty())
    {
        QMessageBox::information(
            this,
            QStringLiteral("删除驱动包"),
            QStringLiteral("当前设备没有可删除的 oem*.inf 第三方驱动包。"));
        return;
    }

    // targetDeviceNameText 用途：确认框与后台任务期间快照可能被替换，先取值再走后续流程。
    const QString targetDeviceNameText = safeDisplayText(entryPointer->nameText);

    const QString confirmText = QStringLiteral(
        "确定要从 Driver Store 删除此驱动包吗？\n\n"
        "设备：%1\n"
        "INF：%2\n\n"
        "建议先卸载设备，再删除驱动包。该操作可能影响同包驱动的其它设备。")
        .arg(targetDeviceNameText, oemInfName);
    if (QMessageBox::question(
        this,
        QStringLiteral("确认删除驱动包"),
        confirmText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No) != QMessageBox::Yes)
    {
        return;
    }

    // 复用刷新互斥标记：删除驱动包期间禁止后台枚举与本操作并发触碰 Driver Store。
    bool expectedRefreshingValue = false;
    if (!m_refreshing.compare_exchange_strong(expectedRefreshingValue, true))
    {
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(QStringLiteral("正在刷新，请等待当前枚举完成。"));
        }
        return;
    }

    // applicationContext 与事件循环同寿命；工作线程不解引用页面指针，只把结果回投主线程。
    QObject* const applicationContext = QCoreApplication::instance();
    if (applicationContext == nullptr)
    {
        m_refreshing.store(false);
        return;
    }

    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(QStringLiteral("正在删除驱动包，请稍候..."));
    }
    if (m_refreshButton != nullptr)
    {
        m_refreshButton->setEnabled(false);
    }
    if (m_showAllDevicesCheck != nullptr)
    {
        m_showAllDevicesCheck->setEnabled(false);
    }

    const QPointer<HardwareDeviceManagerPage> safeThis(this);
    std::thread([applicationContext, safeThis, oemInfName]()
    {
        // SetupUninstallOEMInfW 会驱动 Driver Store 清理流程，内部可能使用 COM；
        // 工作线程自建单线程套间并配对释放，COM 指针不跨线程传递。
        const HRESULT comInitializeStatus = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

        QString errorText;
        const bool deleteOk = uninstallOemInfPackage(oemInfName, &errorText);

        if (SUCCEEDED(comInitializeStatus))
        {
            CoUninitialize();
        }

        QMetaObject::invokeMethod(
            applicationContext,
            [safeThis, oemInfName, deleteOk, errorText]()
            {
                if (safeThis.isNull())
                {
                    return;
                }

                HardwareDeviceManagerPage* const pagePointer = safeThis.data();
                pagePointer->m_refreshing.store(false);
                if (pagePointer->m_refreshButton != nullptr)
                {
                    pagePointer->m_refreshButton->setEnabled(true);
                }
                if (pagePointer->m_showAllDevicesCheck != nullptr)
                {
                    pagePointer->m_showAllDevicesCheck->setEnabled(true);
                }

                if (!deleteOk)
                {
                    if (pagePointer->m_statusLabel != nullptr)
                    {
                        pagePointer->m_statusLabel->setText(QStringLiteral("删除驱动包失败"));
                    }

                    // privilegePromptHandled：记录驱动包删除失败是否已由权限恢复流程处理。
                    const bool privilegePromptHandled =
                        ks::ui::promptForPrivilegeFailure(
                            pagePointer,
                            QStringLiteral("删除驱动包"),
                            errorText);
                    if (!privilegePromptHandled)
                    {
                        QMessageBox::critical(
                            pagePointer,
                            QStringLiteral("删除驱动包失败"),
                            errorText.isEmpty() ? QStringLiteral("未知错误。") : errorText);
                    }
                    return;
                }

                QMessageBox::information(
                    pagePointer,
                    QStringLiteral("删除驱动包"),
                    QStringLiteral("驱动包已删除：%1").arg(oemInfName));
                pagePointer->refreshDevicesAsync(true);
            },
            Qt::QueuedConnection);
    }).detach();
}

std::vector<HardwareDeviceManagerPage::DeviceEntry>
HardwareDeviceManagerPage::enumerateDevicesSnapshot(const bool includeAllDevices)
{
    std::vector<DeviceEntry> resultList;

    const DWORD flags = DIGCF_ALLCLASSES | (includeAllDevices ? 0U : DIGCF_PRESENT);
    HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(nullptr, nullptr, nullptr, flags);
    if (deviceInfoSet == INVALID_HANDLE_VALUE)
    {
        return resultList;
    }

    for (DWORD index = 0;; ++index)
    {
        SP_DEVINFO_DATA deviceInfoData{};
        deviceInfoData.cbSize = sizeof(deviceInfoData);
        if (!SetupDiEnumDeviceInfo(deviceInfoSet, index, &deviceInfoData))
        {
            break;
        }

        DeviceEntry entry;
        entry.nameText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_FriendlyName);
        if (entry.nameText.isEmpty())
        {
            entry.nameText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DeviceDesc);
        }
        entry.manufacturerText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Manufacturer);
        entry.serviceText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Service);
        entry.classText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Class);
        entry.enumeratorText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_EnumeratorName);
        entry.installedText = propertyFileTimeText(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_InstallDate);
        entry.instanceIdText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_InstanceId);
        entry.parentInstanceIdText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Parent);
        entry.classGuidText = propertyGuidText(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_ClassGuid);
        entry.driverText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_Driver);
        if (entry.driverText.isEmpty())
        {
            entry.driverText = registryPropertyString(deviceInfoSet, &deviceInfoData, SPDRP_DRIVER);
        }
        entry.driverInfPathText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverInfPath);
        entry.driverProviderText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverProvider);
        entry.driverVersionText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverVersion);
        entry.driverDateText = propertyFileTimeText(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_DriverDate);
        entry.driverRegistryPathText = driverRegistryPathFromClassKey(entry.classGuidText, entry.driverText);
        if (!entry.driverInfPathText.isEmpty())
        {
            entry.driverText = entry.driverText.isEmpty()
                ? entry.driverInfPathText
                : QStringLiteral("%1 | INF=%2").arg(entry.driverText, entry.driverInfPathText);
        }
        entry.locationText = propertyString(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_LocationInfo);
        entry.hardwareIdsText = propertyStringList(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_HardwareIds);
        entry.compatibleIdsText = propertyStringList(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_CompatibleIds);
        entry.serviceImagePathText = serviceImagePath(entry.serviceText);
        entry.isPresent = propertyBool(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_IsPresent);
        if (!includeAllDevices)
        {
            entry.isPresent = true;
        }
        entry.problemCode = propertyUInt32(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_ProblemCode);
        entry.hasProblem = propertyBool(deviceInfoSet, &deviceInfoData, DEVPKEY_Device_HasProblem)
            || entry.problemCode != 0;

        ULONG statusFlags = 0;
        ULONG problemCode = entry.problemCode;
        if (CM_Get_DevNode_Status(&statusFlags, &problemCode, deviceInfoData.DevInst, 0) == CR_SUCCESS)
        {
            entry.problemCode = problemCode;
            entry.hasProblem = entry.hasProblem || ((statusFlags & DN_HAS_PROBLEM) != 0) || problemCode != 0;
            entry.statusText = deviceStatusText(statusFlags, problemCode);
        }
        if (entry.problemCode != 0)
        {
            entry.problemText = QStringLiteral("CM_PROB=%1").arg(entry.problemCode);
        }

        if (entry.instanceIdText.isEmpty())
        {
            entry.instanceIdText = instanceIdFromDevInst(deviceInfoData.DevInst);
        }
        if (!entry.instanceIdText.isEmpty())
        {
            resultList.push_back(std::move(entry));
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    std::sort(
        resultList.begin(),
        resultList.end(),
        [](const DeviceEntry& left, const DeviceEntry& right)
        {
            return QString::localeAwareCompare(left.nameText, right.nameText) < 0;
        });
    return resultList;
}
