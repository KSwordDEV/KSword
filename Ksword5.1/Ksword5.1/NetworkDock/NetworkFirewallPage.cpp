#include "NetworkFirewallPage.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/DetailLayoutRegistry.h"

// ============================================================
// NetworkFirewallPage.cpp
// 作用：
// 1) 以 System Informer 的 fwmon/fwtab 思路为参照，展示 WFP 防火墙事件；
// 2) 动态解析 fwpuclnt.dll，支持历史枚举和实时订阅；
// 3) 只做 UI 展示和只读监控，不向 KswordARK 驱动发送 IOCTL。
// ============================================================

#include "../theme.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/GlobalDialogTheme.h"
#include "../ksword/process/process.h"

#include <QAbstractItemModel>
#include <QAbstractItemView>
#include <QAction>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QGuiApplication>
#include <QHash>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QMetaObject>
#include <QModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QSet>
#include <QSplitter>
#include <QStringList>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <comdef.h>
#include <fwpmu.h>
#include <fwpsu.h>
#include <netfw.h>
#include <Objbase.h>
#include <Rpc.h>
#include <Ws2tcpip.h>

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace
{
    // FirewallTableColumn：
    // - 作用：定义防火墙事件表列索引；
    // - 处理逻辑：插入、过滤和高亮时统一引用；
    // - 返回行为：枚举本身无返回值。
    enum FirewallTableColumn : int
    {
        ColumnName = 0,
        ColumnAction,
        ColumnDirection,
        ColumnRule,
        ColumnDescription,
        ColumnLocalAddress,
        ColumnLocalPort,
        ColumnLocalHost,
        ColumnRemoteAddress,
        ColumnRemotePort,
        ColumnRemoteHost,
        ColumnProtocol,
        ColumnTimestamp,
        ColumnCount
    };

    constexpr int kMaximumDisplayedFirewallEvents = 5000;
    constexpr std::size_t kMaximumQueuedLiveEvents = 2000U;

    void installFirewallTableCopyMenu(
        QTableWidget* tableWidget,
        const std::function<void(int)>& addBlockRuleHandler = {})
    {
        // installFirewallTableCopyMenu 作用：
        // - 输入：WFP 事件表或规则表；
        // - 处理：右键点击时同步当前行，并复制该行所有可见列为 TSV；
        // - 返回：无。该菜单只复制审计/规则证据，不修改防火墙状态。
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableWidget,
            &QTableWidget::customContextMenuRequested,
            tableWidget,
            [tableWidget, addBlockRuleHandler](const QPoint& localPosition)
            {
                const QModelIndex clickedIndex = tableWidget->indexAt(localPosition);
                if (clickedIndex.isValid())
                {
                    tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
                }

                QMenu contextMenu(tableWidget);
                contextMenu.setStyleSheet(KswordTheme::ContextMenuStyle());
                QAction* copyRowAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
                QAction* addBlockRuleAction = nullptr;
                if (addBlockRuleHandler)
                {
                    addBlockRuleAction = contextMenu.addAction(
                        QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
                        QStringLiteral("预填阻断规则"));
                    addBlockRuleAction->setEnabled(tableWidget->currentRow() >= 0);
                }

                const QAction* selectedAction = contextMenu.exec(
                    tableWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == addBlockRuleAction)
                {
                    addBlockRuleHandler(tableWidget->currentRow());
                    return;
                }
                if (selectedAction != copyRowAction)
                {
                    return;
                }

                QClipboard* clipboardObject = QGuiApplication::clipboard();
                const int rowIndex = tableWidget->currentRow();
                if (clipboardObject == nullptr || rowIndex < 0 || rowIndex >= tableWidget->rowCount())
                {
                    return;
                }

                QStringList rowFields;
                rowFields.reserve(tableWidget->columnCount());
                for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = tableWidget->item(rowIndex, columnIndex);
                    rowFields.push_back(item != nullptr ? item->text() : QString());
                }
                clipboardObject->setText(rowFields.join(QLatin1Char('\t')));
            });
    }

    // FirewallRuleTableColumn：
    // - 作用：定义规则管理表列索引；
    // - 处理逻辑：插入、过滤和启停按钮状态同步时统一引用；
    // - 返回行为：枚举本身无返回值。
    enum FirewallRuleTableColumn : int
    {
        RuleColumnName = 0,
        RuleColumnEnabled,
        RuleColumnAction,
        RuleColumnDirection,
        RuleColumnProfiles,
        RuleColumnProtocol,
        RuleColumnLocalPorts,
        RuleColumnRemotePorts,
        RuleColumnApplication,
        RuleColumnService,
        RuleColumnGrouping,
        RuleColumnDescription,
        RuleColumnCount
    };

    // WfpApi：
    // - 作用：保存动态解析出的 fwpuclnt.dll 函数指针；
    // - 处理逻辑：NetworkFirewallPage::ensureWfpApiLoaded 填充；
    // - 返回行为：纯结构体，无函数返回。
    struct WfpApi
    {
        using FwpmEngineOpen0Fn = DWORD(WINAPI*)(
            const wchar_t*,
            UINT32,
            SEC_WINNT_AUTH_IDENTITY_W*,
            const FWPM_SESSION0*,
            HANDLE*);
        using FwpmEngineClose0Fn = DWORD(WINAPI*)(HANDLE);
        using FwpmEngineSetOption0Fn = DWORD(WINAPI*)(HANDLE, FWPM_ENGINE_OPTION, const FWP_VALUE0*);
        using FwpmFreeMemory0Fn = void(WINAPI*)(void**);
        using FwpmFilterGetById0Fn = DWORD(WINAPI*)(HANDLE, UINT64, FWPM_FILTER0**);
        using FwpmNetEventCreateEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, const FWPM_NET_EVENT_ENUM_TEMPLATE0*, HANDLE*);
        using FwpmNetEventDestroyEnumHandle0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);
        using WfpNetEventCallbackFn = void(CALLBACK*)(void*, const void*);
        using FwpmNetEventEnumGenericFn = DWORD(WINAPI*)(HANDLE, HANDLE, UINT32, void***, UINT32*);
        using FwpmNetEventSubscribeGenericFn = DWORD(WINAPI*)(
            HANDLE,
            const FWPM_NET_EVENT_SUBSCRIPTION0*,
            WfpNetEventCallbackFn,
            void*,
            HANDLE*);
        using FwpmNetEventUnsubscribe0Fn = DWORD(WINAPI*)(HANDLE, HANDLE);

        FwpmEngineOpen0Fn engineOpen = nullptr;
        FwpmEngineClose0Fn engineClose = nullptr;
        FwpmEngineSetOption0Fn engineSetOption = nullptr;
        FwpmFreeMemory0Fn freeMemory = nullptr;
        FwpmFilterGetById0Fn filterGetById = nullptr;
        FwpmNetEventCreateEnumHandle0Fn eventCreateEnumHandle = nullptr;
        FwpmNetEventDestroyEnumHandle0Fn eventDestroyEnumHandle = nullptr;
        FwpmNetEventEnumGenericFn eventEnum = nullptr;
        FwpmNetEventSubscribeGenericFn eventSubscribe = nullptr;
        FwpmNetEventUnsubscribe0Fn eventUnsubscribe = nullptr;
    };

    WfpApi g_wfpApi;

    // ScopedBstr：
    // - 作用：托管 BSTR 生命周期，减少 SysFreeString 漏释放；
    // - 处理逻辑：构造时接收 BSTR，析构自动释放；
    // - 返回行为：可通过 get()/release() 传递底层句柄。
    class ScopedBstr final
    {
    public:
        explicit ScopedBstr(BSTR value = nullptr)
            : m_value(value)
        {
        }

        ~ScopedBstr()
        {
            if (m_value != nullptr)
            {
                SysFreeString(m_value);
                m_value = nullptr;
            }
        }

        ScopedBstr(const ScopedBstr&) = delete;
        ScopedBstr& operator=(const ScopedBstr&) = delete;

        ScopedBstr(ScopedBstr&& other) noexcept
            : m_value(other.m_value)
        {
            other.m_value = nullptr;
        }

        ScopedBstr& operator=(ScopedBstr&& other) noexcept
        {
            if (this != &other)
            {
                if (m_value != nullptr)
                {
                    SysFreeString(m_value);
                }
                m_value = other.m_value;
                other.m_value = nullptr;
            }
            return *this;
        }

        BSTR get() const
        {
            return m_value;
        }

        BSTR* put()
        {
            if (m_value != nullptr)
            {
                SysFreeString(m_value);
                m_value = nullptr;
            }
            return &m_value;
        }

        BSTR release()
        {
            BSTR value = m_value;
            m_value = nullptr;
            return value;
        }

    private:
        BSTR m_value = nullptr;
    };

    // ScopedVariant：
    // - 作用：托管 VARIANT 生命周期；
    // - 处理逻辑：构造时 VariantInit，析构时 VariantClear；
    // - 返回行为：通过 get() 暴露给 COM API。
    class ScopedVariant final
    {
    public:
        ScopedVariant()
        {
            VariantInit(&m_value);
        }

        ~ScopedVariant()
        {
            VariantClear(&m_value);
        }

        ScopedVariant(const ScopedVariant&) = delete;
        ScopedVariant& operator=(const ScopedVariant&) = delete;

        VARIANT* get()
        {
            return &m_value;
        }

        const VARIANT* get() const
        {
            return &m_value;
        }

    private:
        VARIANT m_value{};
    };

    // ScopedComInitialize：
    // - 作用：在当前线程内初始化/收束 COM；
    // - 处理逻辑：构造时 CoInitializeEx，成功时析构自动 CoUninitialize；
    // - 返回行为：通过 succeeded()/result() 暴露初始化状态。
    class ScopedComInitialize final
    {
    public:
        explicit ScopedComInitialize(const DWORD coinitFlags)
            : m_result(CoInitializeEx(nullptr, coinitFlags))
        {
            m_shouldUninitialize = SUCCEEDED(m_result);
        }

        ~ScopedComInitialize()
        {
            if (m_shouldUninitialize)
            {
                CoUninitialize();
            }
        }

        bool succeeded() const
        {
            return SUCCEEDED(m_result) || m_result == RPC_E_CHANGED_MODE;
        }

        HRESULT result() const
        {
            return m_result;
        }

    private:
        HRESULT m_result = E_FAIL;
        bool m_shouldUninitialize = false;
    };

    // releaseComPointer 作用：
    // - 输入：任意 COM 接口指针；
    // - 处理：非空时执行 Release；
    // - 返回：无。
    template <typename T>
    void releaseComPointer(T*& pointerValue)
    {
        if (pointerValue != nullptr)
        {
            pointerValue->Release();
            pointerValue = nullptr;
        }
    }

    // safeText 作用：
    // - 输入：候选文本；
    // - 处理：空文本统一显示为 '-'；
    // - 返回：可显示文本。
    QString safeText(const QString& valueText)
    {
        return valueText.trimmed().isEmpty() ? QStringLiteral("-") : valueText.trimmed();
    }

    // rawTextOrEmpty 作用：
    // - 输入：候选文本；
    // - 处理：仅做 trimmed，保留真正空字符串；
    // - 返回：适合写回规则对象的原始文本。
    QString rawTextOrEmpty(const QString& valueText)
    {
        return valueText.trimmed();
    }

    // qStringFromBstr 作用：
    // - 输入：COM BSTR；
    // - 处理：nullptr 时返回空 QString；
    // - 返回：Qt 文本。
    QString qStringFromBstr(BSTR valueText)
    {
        return valueText == nullptr ? QString() : QString::fromWCharArray(valueText);
    }

    // bstrFromQString 作用：
    // - 输入：Qt 文本；
    // - 处理：为空时返回 nullptr，否则分配 BSTR；
    // - 返回：调用方负责释放的 BSTR。
    BSTR bstrFromQString(const QString& valueText)
    {
        const QString trimmedText = valueText.trimmed();
        if (trimmedText.isEmpty())
        {
            return nullptr;
        }
        return SysAllocString(reinterpret_cast<const OLECHAR*>(trimmedText.utf16()));
    }

    // win32ErrorText 作用：
    // - 输入：Win32 错误码；
    // - 处理：调用 FormatMessage 获取系统说明；
    // - 返回：包含错误码和说明的文本。
    QString win32ErrorText(const DWORD errorCode)
    {
        wchar_t* messageBuffer = nullptr;
        const DWORD length = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            0,
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);
        QString messageText;
        if (length > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer).trimmed();
            LocalFree(messageBuffer);
        }
        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("未知错误");
        }
        return QStringLiteral("%1 (%2)").arg(messageText).arg(errorCode);
    }

    // fileTimeToText 作用：
    // - 输入：WFP 事件 FILETIME；
    // - 处理：转为本地时间；
    // - 返回：时间文本，失败时返回 '-'。
    QString fileTimeToText(const FILETIME& fileTime)
    {
        FILETIME localFileTime{};
        SYSTEMTIME systemTime{};
        if (!FileTimeToLocalFileTime(&fileTime, &localFileTime)
            || !FileTimeToSystemTime(&localFileTime, &systemTime))
        {
            return QStringLiteral("-");
        }
        return QStringLiteral("%1-%2-%3 %4:%5:%6.%7")
            .arg(systemTime.wYear, 4, 10, QLatin1Char('0'))
            .arg(systemTime.wMonth, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wDay, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wHour, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wMinute, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wSecond, 2, 10, QLatin1Char('0'))
            .arg(systemTime.wMilliseconds, 3, 10, QLatin1Char('0'));
    }

    // protocolText 作用：
    // - 输入：IP 协议号；
    // - 处理：转换常见协议；
    // - 返回：TCP/UDP/ICMP 等可读文本。
    QString protocolText(const UINT8 protocol)
    {
        switch (protocol)
        {
        case IPPROTO_TCP:
            return QStringLiteral("TCP");
        case IPPROTO_UDP:
            return QStringLiteral("UDP");
        case IPPROTO_ICMP:
            return QStringLiteral("ICMP");
        case IPPROTO_ICMPV6:
            return QStringLiteral("ICMPv6");
        default:
            return protocol == 0
                ? QStringLiteral("-")
                : QStringLiteral("%1").arg(static_cast<unsigned int>(protocol));
        }
    }

    // firewallRuleProtocolText 作用：
    // - 输入：Windows Firewall 协议值；
    // - 处理：转换为规则管理页可读文本；
    // - 返回：TCP/UDP/Any/数字协议。
    QString firewallRuleProtocolText(const long protocolValue)
    {
        switch (protocolValue)
        {
        case NET_FW_IP_PROTOCOL_TCP:
            return QStringLiteral("TCP");
        case NET_FW_IP_PROTOCOL_UDP:
            return QStringLiteral("UDP");
        case NET_FW_IP_PROTOCOL_ANY:
            return QStringLiteral("Any");
        case 1:
            return QStringLiteral("ICMPv4");
        case 58:
            return QStringLiteral("ICMPv6");
        default:
            return QString::number(protocolValue);
        }
    }

    // firewallRuleDirectionText 作用：
    // - 输入：规则方向值；
    // - 处理：转换为 In/Out；
    // - 返回：可读文本。
    QString firewallRuleDirectionText(const long directionValue)
    {
        switch (directionValue)
        {
        case NET_FW_RULE_DIR_IN:
            return QStringLiteral("In");
        case NET_FW_RULE_DIR_OUT:
            return QStringLiteral("Out");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // firewallRuleActionText 作用：
    // - 输入：规则动作值；
    // - 处理：转换为 Allow/Block；
    // - 返回：可读文本。
    QString firewallRuleActionText(const long actionValue)
    {
        switch (actionValue)
        {
        case NET_FW_ACTION_ALLOW:
            return QStringLiteral("Allow");
        case NET_FW_ACTION_BLOCK:
            return QStringLiteral("Block");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // firewallProfilesText 作用：
    // - 输入：Profile 位掩码；
    // - 处理：展开为 Domain/Private/Public 文本；
    // - 返回：拼接后的可读文本。
    QString firewallProfilesText(const long profilesValue)
    {
        if (profilesValue == NET_FW_PROFILE2_ALL)
        {
            return QStringLiteral("All");
        }

        QStringList profileTextList;
        if ((profilesValue & NET_FW_PROFILE2_DOMAIN) != 0)
        {
            profileTextList.push_back(QStringLiteral("Domain"));
        }
        if ((profilesValue & NET_FW_PROFILE2_PRIVATE) != 0)
        {
            profileTextList.push_back(QStringLiteral("Private"));
        }
        if ((profilesValue & NET_FW_PROFILE2_PUBLIC) != 0)
        {
            profileTextList.push_back(QStringLiteral("Public"));
        }
        return profileTextList.isEmpty()
            ? QStringLiteral("-")
            : profileTextList.join(QStringLiteral(" | "));
    }

    // composeRuleFingerprint 作用：
    // - 输入：规则关键展示字段；
    // - 处理：生成当前快照内稳定匹配键；
    // - 返回：规则匹配指纹。
    QString composeRuleFingerprint(
        const QString& nameText,
        const QString& applicationText,
        const QString& serviceText,
        const QString& localPortsText,
        const QString& remotePortsText,
        const QString& localAddressesText,
        const QString& remoteAddressesText,
        const long protocolValue,
        const long directionValue,
        const long actionValue,
        const long profilesValue)
    {
        return QStringLiteral("%1||%2||%3||%4||%5||%6||%7||%8||%9||%10||%11")
            .arg(rawTextOrEmpty(nameText))
            .arg(rawTextOrEmpty(applicationText))
            .arg(rawTextOrEmpty(serviceText))
            .arg(rawTextOrEmpty(localPortsText))
            .arg(rawTextOrEmpty(remotePortsText))
            .arg(rawTextOrEmpty(localAddressesText))
            .arg(rawTextOrEmpty(remoteAddressesText))
            .arg(protocolValue)
            .arg(directionValue)
            .arg(actionValue)
            .arg(profilesValue);
    }

    // directionText 作用：
    // - 输入：WFP 方向值；
    // - 处理：兼容普通 FWP_DIRECTION_* 与 System Informer 使用的 DirectionMap；
    // - 返回：In/Out/FWD/BI/Unknown。
    QString directionText(const UINT32 direction)
    {
        constexpr UINT32 DirectionMapInbound = 0x3900;
        constexpr UINT32 DirectionMapOutbound = 0x3901;
        constexpr UINT32 DirectionMapForward = 0x3902;
        constexpr UINT32 DirectionMapBidirectional = 0x3903;
        switch (direction)
        {
        case FWP_DIRECTION_INBOUND:
        case DirectionMapInbound:
            return QStringLiteral("In");
        case FWP_DIRECTION_OUTBOUND:
        case DirectionMapOutbound:
            return QStringLiteral("Out");
        case DirectionMapForward:
            return QStringLiteral("FWD");
        case DirectionMapBidirectional:
            return QStringLiteral("BI");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // actionText 作用：
    // - 输入：WFP 事件类型；
    // - 处理：映射为 System Informer 风格动作名；
    // - 返回：动作文本。
    QString actionText(const FWPM_NET_EVENT_TYPE type)
    {
        switch (type)
        {
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
            return QStringLiteral("DROP");
        case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
            return QStringLiteral("IPsec Block");
        case FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP:
            return QStringLiteral("Flood Protection");
        case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
            return QStringLiteral("Allowed");
        case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
            return QStringLiteral("DROP (AppContainer)");
        case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
            return QStringLiteral("Allowed (AppContainer)");
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
            return QStringLiteral("DROP (MAC)");
        case FWPM_NET_EVENT_TYPE_LPM_PACKET_ARRIVAL:
            return QStringLiteral("QoS Policy Packet");
        case FWPM_NET_EVENT_TYPE_IKEEXT_MM_FAILURE:
            return QStringLiteral("VPN Failure (Phase 1)");
        case FWPM_NET_EVENT_TYPE_IKEEXT_QM_FAILURE:
            return QStringLiteral("VPN Failure (Phase 2)");
        case FWPM_NET_EVENT_TYPE_IKEEXT_EM_FAILURE:
            return QStringLiteral("VPN Auth Failure");
        default:
            return QStringLiteral("Unknown");
        }
    }

    // isDropEvent 作用：
    // - 输入：WFP 事件类型；
    // - 处理：判断该事件是否应以红色突出；
    // - 返回：DROP/Block 类事件返回 true。
    bool isDropEvent(const FWPM_NET_EVENT_TYPE type)
    {
        return type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP
            || type == FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP
            || type == FWPM_NET_EVENT_TYPE_IPSEC_DOSP_DROP
            || type == FWPM_NET_EVENT_TYPE_CAPABILITY_DROP
            || type == FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC;
    }

    // addressTextFromHeader 作用：
    // - 输入：WFP 事件头、本地/远端标志；
    // - 处理：按 IPv4/IPv6 转换地址；
    // - 返回：地址文本，字段未设置时返回空字符串。
    QString addressTextFromHeader(const FWPM_NET_EVENT_HEADER3& header, const bool localAddress)
    {
        const UINT32 addressFlag = localAddress
            ? FWPM_NET_EVENT_FLAG_LOCAL_ADDR_SET
            : FWPM_NET_EVENT_FLAG_REMOTE_ADDR_SET;
        if ((header.flags & addressFlag) == 0)
        {
            return QString();
        }

        wchar_t buffer[INET6_ADDRSTRLEN] = {};
        if (header.ipVersion == FWP_IP_VERSION_V4)
        {
            IN_ADDR address{};
            address.S_un.S_addr = htonl(localAddress ? header.localAddrV4 : header.remoteAddrV4);
            if (InetNtopW(AF_INET, &address, buffer, static_cast<DWORD>(std::size(buffer))) != nullptr)
            {
                return QString::fromWCharArray(buffer);
            }
        }
        else if (header.ipVersion == FWP_IP_VERSION_V6)
        {
            IN6_ADDR address{};
            const FWP_BYTE_ARRAY16& sourceBytes = localAddress ? header.localAddrV6 : header.remoteAddrV6;
            std::memcpy(address.u.Byte, sourceBytes.byteArray16, 16);
            if (InetNtopW(AF_INET6, &address, buffer, static_cast<DWORD>(std::size(buffer))) != nullptr)
            {
                return QString::fromWCharArray(buffer);
            }
        }
        return QString();
    }

    // portTextFromHeader 作用：
    // - 输入：WFP 事件头、本地/远端标志；
    // - 处理：提取端口字段；
    // - 返回：端口文本，字段未设置时返回空字符串。
    QString portTextFromHeader(const FWPM_NET_EVENT_HEADER3& header, const bool localPort)
    {
        const UINT32 portFlag = localPort
            ? FWPM_NET_EVENT_FLAG_LOCAL_PORT_SET
            : FWPM_NET_EVENT_FLAG_REMOTE_PORT_SET;
        if ((header.flags & portFlag) == 0)
        {
            return QString();
        }
        return QString::number(localPort ? header.localPort : header.remotePort);
    }

    // appPathFromHeader 作用：
    // - 输入：WFP 事件头；
    // - 处理：从 appId byte blob 中保留原始 NT/Win32 路径；
    // - 返回：应用路径或空字符串。
    QString appPathFromHeader(const FWPM_NET_EVENT_HEADER3& header)
    {
        if ((header.flags & FWPM_NET_EVENT_FLAG_APP_ID_SET) == 0
            || header.appId.data == nullptr
            || header.appId.size <= sizeof(wchar_t))
        {
            return QString();
        }

        const int charCount = static_cast<int>((header.appId.size / sizeof(wchar_t)) - 1U);
        return QString::fromWCharArray(
            reinterpret_cast<const wchar_t*>(header.appId.data),
            std::max(0, charCount)).trimmed();
    }

    // appNameFromHeader 作用：
    // - 输入：WFP 事件头；
    // - 处理：从 appId 路径提取文件名用于表格展示；
    // - 返回：应用名或空字符串。
    QString appNameFromHeader(const FWPM_NET_EVENT_HEADER3& header)
    {
        QString pathText = appPathFromHeader(header);
        pathText = pathText.replace(QLatin1Char('\\'), QLatin1Char('/'));
        const int slashIndex = pathText.lastIndexOf(QLatin1Char('/'));
        return slashIndex >= 0 ? pathText.mid(slashIndex + 1) : pathText;
    }

    // resolveHostnameText 作用：
    // - 输入：IP 地址文本；
    // - 处理：对空地址、回环/本地场景保持轻量；调用 getnameinfo 做反查；
    // - 返回：解析成功时返回主机名，否则返回空字符串。
    QString resolveHostnameText(const QString& addressText)
    {
        if (addressText.isEmpty()
            || addressText == QStringLiteral("0.0.0.0")
            || addressText == QStringLiteral("::"))
        {
            return QString();
        }

        sockaddr_storage storage{};
        int family = AF_UNSPEC;
        if (InetPtonW(AF_INET, reinterpret_cast<PCWSTR>(addressText.utf16()), &reinterpret_cast<sockaddr_in*>(&storage)->sin_addr) == 1)
        {
            family = AF_INET;
            reinterpret_cast<sockaddr_in*>(&storage)->sin_family = AF_INET;
        }
        else if (InetPtonW(AF_INET6, reinterpret_cast<PCWSTR>(addressText.utf16()), &reinterpret_cast<sockaddr_in6*>(&storage)->sin6_addr) == 1)
        {
            family = AF_INET6;
            reinterpret_cast<sockaddr_in6*>(&storage)->sin6_family = AF_INET6;
        }
        if (family == AF_UNSPEC)
        {
            return QString();
        }

        wchar_t hostBuffer[NI_MAXHOST] = {};
        const int length = family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
        const int status = GetNameInfoW(
            reinterpret_cast<sockaddr*>(&storage),
            length,
            hostBuffer,
            static_cast<DWORD>(std::size(hostBuffer)),
            nullptr,
            0,
            NI_NAMEREQD);
        return status == 0 ? QString::fromWCharArray(hostBuffer) : QString();
    }

    // procAddress 作用：
    // - 输入：模块句柄和导出名；
    // - 处理：GetProcAddress 并转换为目标函数指针；
    // - 返回：目标函数指针或 nullptr。
    template <typename T>
    T procAddress(HMODULE moduleHandle, const char* name)
    {
        return reinterpret_cast<T>(GetProcAddress(moduleHandle, name));
    }

    // FirewallRuleEditorDialog：
    // - 作用：统一承载新增/编辑防火墙规则输入；
    // - 处理逻辑：把常见字段映射为轻量表单，校验必要项后输出规则快照；
    // - 返回行为：accept 时通过 ruleEntry() 返回用户输入。
    class FirewallRuleEditorDialog final : public QDialog
    {
    public:
        explicit FirewallRuleEditorDialog(
            const NetworkFirewallPage::FirewallRuleEntry* initialRuleEntry,
            QWidget* parent = nullptr)
            : QDialog(parent)
        {
            setWindowTitle(initialRuleEntry == nullptr ? QStringLiteral("新增防火墙规则") : QStringLiteral("编辑防火墙规则"));
            resize(620, 460);
            ks::ui::RefreshGlobalDialogTheme();

            QVBoxLayout* rootLayout = new QVBoxLayout(this);
            rootLayout->setContentsMargins(12, 12, 12, 12);
            rootLayout->setSpacing(10);

            QLabel* tipLabel = new QLabel(
                QStringLiteral("规则修改将直接写入 Windows Firewall。程序路径、端口和地址支持留空。"),
                this);
            tipLabel->setWordWrap(true);
            rootLayout->addWidget(tipLabel, 0);

            QFormLayout* formLayout = new QFormLayout();
            formLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
            formLayout->setFormAlignment(Qt::AlignTop);
            formLayout->setSpacing(8);

            m_nameEdit = new QLineEdit(this);
            m_descriptionEdit = new QLineEdit(this);
            m_applicationEdit = new QLineEdit(this);
            m_serviceEdit = new QLineEdit(this);
            m_localPortsEdit = new QLineEdit(this);
            m_remotePortsEdit = new QLineEdit(this);
            m_localAddressesEdit = new QLineEdit(this);
            m_remoteAddressesEdit = new QLineEdit(this);
            m_groupingEdit = new QLineEdit(this);

            m_protocolCombo = new QComboBox(this);
            m_protocolCombo->addItem(QStringLiteral("Any"), NET_FW_IP_PROTOCOL_ANY);
            m_protocolCombo->addItem(QStringLiteral("TCP"), NET_FW_IP_PROTOCOL_TCP);
            m_protocolCombo->addItem(QStringLiteral("UDP"), NET_FW_IP_PROTOCOL_UDP);
            m_protocolCombo->addItem(QStringLiteral("ICMPv4"), 1);
            m_protocolCombo->addItem(QStringLiteral("ICMPv6"), 58);

            m_directionCombo = new QComboBox(this);
            m_directionCombo->addItem(QStringLiteral("Inbound"), NET_FW_RULE_DIR_IN);
            m_directionCombo->addItem(QStringLiteral("Outbound"), NET_FW_RULE_DIR_OUT);

            m_actionCombo = new QComboBox(this);
            m_actionCombo->addItem(QStringLiteral("Allow"), NET_FW_ACTION_ALLOW);
            m_actionCombo->addItem(QStringLiteral("Block"), NET_FW_ACTION_BLOCK);

            m_enabledCheck = new QCheckBox(QStringLiteral("启用规则"), this);
            m_enabledCheck->setChecked(true);
            m_profileDomainCheck = new QCheckBox(QStringLiteral("Domain"), this);
            m_profilePrivateCheck = new QCheckBox(QStringLiteral("Private"), this);
            m_profilePublicCheck = new QCheckBox(QStringLiteral("Public"), this);

            QWidget* profileWidget = new QWidget(this);
            QHBoxLayout* profileLayout = new QHBoxLayout(profileWidget);
            profileLayout->setContentsMargins(0, 0, 0, 0);
            profileLayout->setSpacing(10);
            profileLayout->addWidget(m_profileDomainCheck);
            profileLayout->addWidget(m_profilePrivateCheck);
            profileLayout->addWidget(m_profilePublicCheck);
            profileLayout->addStretch(1);

            formLayout->addRow(QStringLiteral("名称"), m_nameEdit);
            formLayout->addRow(QStringLiteral("描述"), m_descriptionEdit);
            formLayout->addRow(QStringLiteral("程序"), m_applicationEdit);
            formLayout->addRow(QStringLiteral("服务"), m_serviceEdit);
            formLayout->addRow(QStringLiteral("方向"), m_directionCombo);
            formLayout->addRow(QStringLiteral("动作"), m_actionCombo);
            formLayout->addRow(QStringLiteral("协议"), m_protocolCombo);
            formLayout->addRow(QStringLiteral("本地端口"), m_localPortsEdit);
            formLayout->addRow(QStringLiteral("远端端口"), m_remotePortsEdit);
            formLayout->addRow(QStringLiteral("本地地址"), m_localAddressesEdit);
            formLayout->addRow(QStringLiteral("远端地址"), m_remoteAddressesEdit);
            formLayout->addRow(QStringLiteral("分组"), m_groupingEdit);
            formLayout->addRow(QStringLiteral("配置文件"), profileWidget);
            formLayout->addRow(QStringLiteral("状态"), m_enabledCheck);
            rootLayout->addLayout(formLayout, 1);

            QDialogButtonBox* buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
            rootLayout->addWidget(buttonBox, 0);

            connect(buttonBox, &QDialogButtonBox::accepted, this, [this]()
            {
                if (!buildRuleEntryFromUi(&m_ruleEntry))
                {
                    return;
                }
                accept();
            });
            connect(buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

            if (initialRuleEntry != nullptr)
            {
                loadRuleEntry(*initialRuleEntry);
            }
            else
            {
                m_profileDomainCheck->setChecked(true);
                m_profilePrivateCheck->setChecked(true);
                m_profilePublicCheck->setChecked(true);
            }
        }

        NetworkFirewallPage::FirewallRuleEntry ruleEntry() const
        {
            return m_ruleEntry;
        }

    private:
        void loadRuleEntry(const NetworkFirewallPage::FirewallRuleEntry& ruleEntry)
        {
            m_ruleEntry = ruleEntry;
            m_nameEdit->setText(ruleEntry.nameText);
            m_descriptionEdit->setText(ruleEntry.descriptionText);
            m_applicationEdit->setText(ruleEntry.applicationText);
            m_serviceEdit->setText(ruleEntry.serviceText);
            m_localPortsEdit->setText(ruleEntry.localPortsText);
            m_remotePortsEdit->setText(ruleEntry.remotePortsText);
            m_localAddressesEdit->setText(ruleEntry.localAddressesText);
            m_remoteAddressesEdit->setText(ruleEntry.remoteAddressesText);
            m_groupingEdit->setText(ruleEntry.groupingText);
            m_enabledCheck->setChecked(ruleEntry.enabled);

            const int protocolIndex = m_protocolCombo->findData(QVariant::fromValue(static_cast<qlonglong>(ruleEntry.protocolValue)));
            if (protocolIndex >= 0)
            {
                m_protocolCombo->setCurrentIndex(protocolIndex);
            }

            const int directionIndex = m_directionCombo->findData(QVariant::fromValue(static_cast<qlonglong>(ruleEntry.directionValue)));
            if (directionIndex >= 0)
            {
                m_directionCombo->setCurrentIndex(directionIndex);
            }

            const int actionIndex = m_actionCombo->findData(QVariant::fromValue(static_cast<qlonglong>(ruleEntry.actionValue)));
            if (actionIndex >= 0)
            {
                m_actionCombo->setCurrentIndex(actionIndex);
            }

            m_profileDomainCheck->setChecked((ruleEntry.profilesValue & NET_FW_PROFILE2_DOMAIN) != 0);
            m_profilePrivateCheck->setChecked((ruleEntry.profilesValue & NET_FW_PROFILE2_PRIVATE) != 0);
            m_profilePublicCheck->setChecked((ruleEntry.profilesValue & NET_FW_PROFILE2_PUBLIC) != 0);
        }

        bool buildRuleEntryFromUi(NetworkFirewallPage::FirewallRuleEntry* ruleEntryOut)
        {
            if (ruleEntryOut == nullptr)
            {
                return false;
            }

            const QString nameText = m_nameEdit->text().trimmed();
            if (nameText.isEmpty())
            {
                QMessageBox::warning(this, QStringLiteral("规则校验"), QStringLiteral("规则名称不能为空。"));
                m_nameEdit->setFocus();
                return false;
            }

            long profilesValue = 0;
            if (m_profileDomainCheck->isChecked())
            {
                profilesValue |= NET_FW_PROFILE2_DOMAIN;
            }
            if (m_profilePrivateCheck->isChecked())
            {
                profilesValue |= NET_FW_PROFILE2_PRIVATE;
            }
            if (m_profilePublicCheck->isChecked())
            {
                profilesValue |= NET_FW_PROFILE2_PUBLIC;
            }
            if (profilesValue == 0)
            {
                QMessageBox::warning(this, QStringLiteral("规则校验"), QStringLiteral("至少需要选择一个配置文件。"));
                return false;
            }

            NetworkFirewallPage::FirewallRuleEntry ruleEntry = m_ruleEntry;
            ruleEntry.nameText = nameText;
            ruleEntry.descriptionText = rawTextOrEmpty(m_descriptionEdit->text());
            ruleEntry.applicationText = rawTextOrEmpty(m_applicationEdit->text());
            ruleEntry.serviceText = rawTextOrEmpty(m_serviceEdit->text());
            ruleEntry.localPortsText = rawTextOrEmpty(m_localPortsEdit->text());
            ruleEntry.remotePortsText = rawTextOrEmpty(m_remotePortsEdit->text());
            ruleEntry.localAddressesText = rawTextOrEmpty(m_localAddressesEdit->text());
            ruleEntry.remoteAddressesText = rawTextOrEmpty(m_remoteAddressesEdit->text());
            ruleEntry.groupingText = rawTextOrEmpty(m_groupingEdit->text());
            ruleEntry.enabled = m_enabledCheck->isChecked();
            ruleEntry.protocolValue = m_protocolCombo->currentData().toLongLong();
            ruleEntry.directionValue = m_directionCombo->currentData().toLongLong();
            ruleEntry.actionValue = m_actionCombo->currentData().toLongLong();
            ruleEntry.profilesValue = profilesValue;
            ruleEntry.protocolText = firewallRuleProtocolText(ruleEntry.protocolValue);
            ruleEntry.directionText = firewallRuleDirectionText(ruleEntry.directionValue);
            ruleEntry.actionText = firewallRuleActionText(ruleEntry.actionValue);
            ruleEntry.profilesText = firewallProfilesText(ruleEntry.profilesValue);
            ruleEntry.fingerprintText = composeRuleFingerprint(
                ruleEntry.nameText,
                ruleEntry.applicationText,
                ruleEntry.serviceText,
                ruleEntry.localPortsText,
                ruleEntry.remotePortsText,
                ruleEntry.localAddressesText,
                ruleEntry.remoteAddressesText,
                ruleEntry.protocolValue,
                ruleEntry.directionValue,
                ruleEntry.actionValue,
                ruleEntry.profilesValue);
            *ruleEntryOut = std::move(ruleEntry);
            return true;
        }

    private:
        QLineEdit* m_nameEdit = nullptr;
        QLineEdit* m_descriptionEdit = nullptr;
        QLineEdit* m_applicationEdit = nullptr;
        QLineEdit* m_serviceEdit = nullptr;
        QLineEdit* m_localPortsEdit = nullptr;
        QLineEdit* m_remotePortsEdit = nullptr;
        QLineEdit* m_localAddressesEdit = nullptr;
        QLineEdit* m_remoteAddressesEdit = nullptr;
        QLineEdit* m_groupingEdit = nullptr;
        QComboBox* m_protocolCombo = nullptr;
        QComboBox* m_directionCombo = nullptr;
        QComboBox* m_actionCombo = nullptr;
        QCheckBox* m_enabledCheck = nullptr;
        QCheckBox* m_profileDomainCheck = nullptr;
        QCheckBox* m_profilePrivateCheck = nullptr;
        QCheckBox* m_profilePublicCheck = nullptr;
        NetworkFirewallPage::FirewallRuleEntry m_ruleEntry;
    };

    // ============================================================
    // 跨线程执行区
    // 以下文件级状态与函数只使用参数、局部变量和本文件的全局状态，绝不触碰
    // NetworkFirewallPage 的任何成员：后台任务一律 detach，页面析构后它们仍能
    // 安全跑完或提前取消，回投前再通过 FirewallAsyncTaskState 复核 owner。
    // ============================================================

    // FirewallAsyncTaskState：
    // - 作用：承载后台任务与页面之间的生命周期握手和任务串行位；
    // - 处理逻辑：页面析构时先置取消位、再清空 owner，后台任务据此放弃回投；
    // - 返回行为：纯状态结构，无函数返回。
    struct FirewallAsyncTaskState final
    {
        std::mutex dispatchMutex;                           // dispatchMutex：保护 owner 读写、实时句柄落库与回投提交。
        NetworkFirewallPage* owner = nullptr;               // owner：页面存活期间指向页面，析构时置空。
        std::atomic_bool cancelRequested{ false };          // cancelRequested：后台循环统一的取消位。
        std::atomic_bool ruleMutationInProgress{ false };   // ruleMutationInProgress：编辑/启停/删除的串行位。
        std::atomic_bool liveTransitionInProgress{ false }; // liveTransitionInProgress：实时监控启动的串行位。
        std::mutex completionMutex;                         // completionMutex：保护在跑任务计数。
        std::condition_variable completionSignal;           // completionSignal：任务退出时唤醒析构侧的限时等待。
        int activeWorkerCount = 0;                          // activeWorkerCount：仍在执行的后台任务数。
        std::mutex hostnameQueueMutex;                      // hostnameQueueMutex：保护待反查地址队列。
        QStringList pendingHostnameAddressList;             // pendingHostnameAddressList：等待反向 DNS 的地址。
        QSet<QString> pendingHostnameAddressSet;            // pendingHostnameAddressSet：队列去重集合。
        bool hostnameWorkerRunning = false;                 // hostnameWorkerRunning：同时最多一个反查任务。
    };

    // kAsyncWorkerShutdownWaitMilliseconds：析构时对在跑任务的限时等待上限。
    // 后台任务本身不触碰页面成员，超时后继续析构也是安全的，因此绝不死等。
    constexpr int kAsyncWorkerShutdownWaitMilliseconds = 500;

    // kResolvedHostnameBatchSize：反向 DNS 结果攒够多少条才回投一次。
    constexpr int kResolvedHostnameBatchSize = 64;

    // kMaximumCachedHostnameCount：反查缓存条目上限，超过后整体清空重来。
    constexpr int kMaximumCachedHostnameCount = 8192;

    std::mutex g_firewallTaskStateMutex; // g_firewallTaskStateMutex：保护页面 -> 握手状态注册表。
    QHash<const NetworkFirewallPage*, std::shared_ptr<FirewallAsyncTaskState>> g_firewallTaskStateTable; // 注册表本体。

    // acquireFirewallAsyncTaskState 作用：
    // - 输入：页面指针；
    // - 处理：取回该页面的握手状态，尚未注册时创建并把 owner 指向页面；
    // - 返回：握手状态；页面指针为空时返回空指针。
    std::shared_ptr<FirewallAsyncTaskState> acquireFirewallAsyncTaskState(NetworkFirewallPage* pagePointer)
    {
        if (pagePointer == nullptr)
        {
            return {};
        }

        std::lock_guard<std::mutex> registryGuard(g_firewallTaskStateMutex);
        const auto tableIterator = g_firewallTaskStateTable.constFind(pagePointer);
        if (tableIterator != g_firewallTaskStateTable.constEnd())
        {
            return tableIterator.value();
        }

        std::shared_ptr<FirewallAsyncTaskState> taskState = std::make_shared<FirewallAsyncTaskState>();
        taskState->owner = pagePointer;
        g_firewallTaskStateTable.insert(pagePointer, taskState);
        return taskState;
    }

    // lookupFirewallAsyncTaskState 作用：
    // - 输入：页面指针；
    // - 处理：只查询已注册的握手状态，不会新建；
    // - 返回：握手状态，未注册时返回空指针。
    std::shared_ptr<FirewallAsyncTaskState> lookupFirewallAsyncTaskState(const NetworkFirewallPage* pagePointer)
    {
        std::lock_guard<std::mutex> registryGuard(g_firewallTaskStateMutex);
        const auto tableIterator = g_firewallTaskStateTable.constFind(pagePointer);
        return tableIterator != g_firewallTaskStateTable.constEnd() ? tableIterator.value() : std::shared_ptr<FirewallAsyncTaskState>();
    }

    // detachFirewallAsyncTaskState 作用：
    // - 输入：页面指针；
    // - 处理：把握手状态摘出注册表，先置取消位再清空 owner；顺序不能颠倒，
    //         实时订阅任务正是靠“先看到取消位”才不会把回调挂到消亡中的页面上；
    // - 返回：摘出的握手状态，供调用方继续限时等待。
    std::shared_ptr<FirewallAsyncTaskState> detachFirewallAsyncTaskState(const NetworkFirewallPage* pagePointer)
    {
        std::shared_ptr<FirewallAsyncTaskState> taskState;
        {
            std::lock_guard<std::mutex> registryGuard(g_firewallTaskStateMutex);
            const auto tableIterator = g_firewallTaskStateTable.find(pagePointer);
            if (tableIterator == g_firewallTaskStateTable.end())
            {
                return taskState;
            }
            taskState = tableIterator.value();
            g_firewallTaskStateTable.erase(tableIterator);
        }

        taskState->cancelRequested.store(true);
        {
            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            taskState->owner = nullptr;
        }
        return taskState;
    }

    // AsyncWorkerScope：
    // - 作用：登记一个正在执行的后台任务；
    // - 处理逻辑：构造时计数加一，析构时减一并唤醒析构侧的限时等待；
    // - 返回行为：纯 RAII 对象，无函数返回。
    class AsyncWorkerScope final
    {
    public:
        explicit AsyncWorkerScope(std::shared_ptr<FirewallAsyncTaskState> taskState)
            : m_taskState(std::move(taskState))
        {
            if (m_taskState)
            {
                std::lock_guard<std::mutex> completionGuard(m_taskState->completionMutex);
                ++m_taskState->activeWorkerCount;
            }
        }

        ~AsyncWorkerScope()
        {
            if (!m_taskState)
            {
                return;
            }
            {
                std::lock_guard<std::mutex> completionGuard(m_taskState->completionMutex);
                --m_taskState->activeWorkerCount;
            }
            m_taskState->completionSignal.notify_all();
        }

        AsyncWorkerScope(const AsyncWorkerScope&) = delete;
        AsyncWorkerScope& operator=(const AsyncWorkerScope&) = delete;

    private:
        std::shared_ptr<FirewallAsyncTaskState> m_taskState;
    };

    // waitForFirewallAsyncWorkers 作用：
    // - 输入：握手状态、最长等待毫秒数；
    // - 处理：取消位已置位后限时等待在跑任务退出，超时立即返回，绝不死等；
    // - 返回：无。
    void waitForFirewallAsyncWorkers(
        const std::shared_ptr<FirewallAsyncTaskState>& taskState,
        const int timeoutMilliseconds)
    {
        if (!taskState)
        {
            return;
        }

        std::unique_lock<std::mutex> completionGuard(taskState->completionMutex);
        (void)taskState->completionSignal.wait_for(
            completionGuard,
            std::chrono::milliseconds(timeoutMilliseconds),
            [&taskState]()
            {
                return taskState->activeWorkerCount <= 0;
            });
    }

    std::mutex g_hostnameCacheMutex;              // g_hostnameCacheMutex：保护反向 DNS 结果缓存。
    QHash<QString, QString> g_hostnameCacheTable; // g_hostnameCacheTable：地址 -> 主机名，空值表示查过但无 PTR 记录。

    // lookupCachedHostnameText 作用：
    // - 输入：IP 地址文本、主机名输出；
    // - 处理：只读命中进程级反查缓存，绝不发起 DNS 请求；
    // - 返回：缓存已有结论（含“查过但没有记录”的空结果）时返回 true。
    bool lookupCachedHostnameText(const QString& addressText, QString* hostnameTextOut)
    {
        if (addressText.isEmpty())
        {
            return true;
        }

        std::lock_guard<std::mutex> cacheGuard(g_hostnameCacheMutex);
        const auto cacheIterator = g_hostnameCacheTable.constFind(addressText);
        if (cacheIterator == g_hostnameCacheTable.constEnd())
        {
            return false;
        }
        if (hostnameTextOut != nullptr)
        {
            *hostnameTextOut = cacheIterator.value();
        }
        return true;
    }

    // resolveAndCacheHostnameText 作用：
    // - 输入：IP 地址文本；
    // - 处理：命中缓存直接返回；未命中时做一次同步反向 DNS，并把结果（含空结果）写回缓存，
    //         避免同一个地址在每轮刷新里反复触发 DNS 超时；
    // - 返回：主机名，无 PTR 记录时返回空字符串。
    QString resolveAndCacheHostnameText(const QString& addressText)
    {
        QString cachedHostnameText;
        if (lookupCachedHostnameText(addressText, &cachedHostnameText))
        {
            return cachedHostnameText;
        }

        const QString resolvedHostnameText = resolveHostnameText(addressText);
        std::lock_guard<std::mutex> cacheGuard(g_hostnameCacheMutex);
        if (g_hostnameCacheTable.size() >= kMaximumCachedHostnameCount)
        {
            g_hostnameCacheTable.clear();
        }
        g_hostnameCacheTable.insert(addressText, resolvedHostnameText);
        return resolvedHostnameText;
    }

    // collectUnresolvedAddressList 作用：
    // - 输入：一批事件；
    // - 处理：挑出还没有主机名、且缓存里也没有结论的地址并去重；
    // - 返回：待异步反查的地址列表。
    QStringList collectUnresolvedAddressList(
        const std::vector<NetworkFirewallPage::FirewallEventEntry>& eventList)
    {
        QStringList pendingAddressList;
        QSet<QString> pendingAddressSet;
        for (const NetworkFirewallPage::FirewallEventEntry& eventEntry : eventList)
        {
            const std::array<QString, 2> candidateAddressList = {
                eventEntry.localAddressText,
                eventEntry.remoteAddressText
            };
            const std::array<QString, 2> resolvedHostnameList = {
                eventEntry.localHostText,
                eventEntry.remoteHostText
            };
            for (std::size_t candidateIndex = 0; candidateIndex < candidateAddressList.size(); ++candidateIndex)
            {
                const QString& addressText = candidateAddressList[candidateIndex];
                if (addressText.isEmpty() || !resolvedHostnameList[candidateIndex].isEmpty())
                {
                    continue;
                }
                if (pendingAddressSet.contains(addressText))
                {
                    continue;
                }
                if (lookupCachedHostnameText(addressText, nullptr))
                {
                    continue;
                }
                pendingAddressSet.insert(addressText);
                pendingAddressList.push_back(addressText);
            }
        }
        return pendingAddressList;
    }

    // applyResolvedHostnamesToEventTable 作用：
    // - 输入：事件表控件、地址 -> 主机名映射；
    // - 处理：在 UI 线程按地址列文本回填本地/远端主机名列；
    // - 返回：无。
    void applyResolvedHostnamesToEventTable(
        QTableWidget* eventTable,
        const QHash<QString, QString>& resolvedHostnameMap)
    {
        if (eventTable == nullptr || resolvedHostnameMap.isEmpty())
        {
            return;
        }

        constexpr std::array<int, 2> addressColumnList = { ColumnLocalAddress, ColumnRemoteAddress };
        constexpr std::array<int, 2> hostnameColumnList = { ColumnLocalHost, ColumnRemoteHost };
        eventTable->setUpdatesEnabled(false);
        for (int rowIndex = 0; rowIndex < eventTable->rowCount(); ++rowIndex)
        {
            for (std::size_t columnPairIndex = 0; columnPairIndex < addressColumnList.size(); ++columnPairIndex)
            {
                const QTableWidgetItem* addressItem = eventTable->item(rowIndex, addressColumnList[columnPairIndex]);
                QTableWidgetItem* hostnameItem = eventTable->item(rowIndex, hostnameColumnList[columnPairIndex]);
                if (addressItem == nullptr || hostnameItem == nullptr)
                {
                    continue;
                }
                const auto resolvedIterator = resolvedHostnameMap.constFind(addressItem->text());
                if (resolvedIterator == resolvedHostnameMap.constEnd() || resolvedIterator.value().isEmpty())
                {
                    continue;
                }
                hostnameItem->setText(resolvedIterator.value());
            }
        }
        eventTable->setUpdatesEnabled(true);
    }

    // submitResolvedHostnames 作用：
    // - 输入：事件表控件、握手状态、本批解析结果；
    // - 处理：在 owner 仍然有效时把结果回投给 UI 线程写表；
    // - 返回：页面已析构返回 false，调用方据此结束反查任务。
    bool submitResolvedHostnames(
        QTableWidget* eventTable,
        const std::shared_ptr<FirewallAsyncTaskState>& taskState,
        const QHash<QString, QString>& resolvedHostnameMap)
    {
        if (resolvedHostnameMap.isEmpty())
        {
            return true;
        }

        std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
        NetworkFirewallPage* const receiver = taskState->owner;
        if (receiver == nullptr)
        {
            return false;
        }
        QMetaObject::invokeMethod(
            receiver,
            [eventTable, taskState, resolvedHostnameMap]()
            {
                // 事件表是页面的子控件：owner 非空即代表控件仍然存活。
                std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                if (taskState->owner == nullptr)
                {
                    return;
                }
                applyResolvedHostnamesToEventTable(eventTable, resolvedHostnameMap);
            },
            Qt::QueuedConnection);
        return true;
    }

    // runHostnameResolutionWorker 作用：
    // - 输入：事件表控件、握手状态；
    // - 处理：串行消费待反查队列，每条地址前检查取消位，攒够一批就回投；
    // - 返回：无。整个任务只使用文件级缓存和控件公开接口，不触碰页面成员。
    void runHostnameResolutionWorker(QTableWidget* eventTable, const std::shared_ptr<FirewallAsyncTaskState>& taskState)
    {
        // 反查任务不登记 AsyncWorkerScope：单次 GetNameInfoW 在 PTR 缺失时可能要秒级
        // 才超时返回，析构不应该为它多等；它本身不触碰页面成员，可以自行跑完退出。
        QHash<QString, QString> resolvedHostnameMap;
        while (true)
        {
            QString addressText;
            {
                std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
                if (taskState->cancelRequested.load() || taskState->pendingHostnameAddressList.isEmpty())
                {
                    taskState->pendingHostnameAddressList.clear();
                    taskState->pendingHostnameAddressSet.clear();
                    taskState->hostnameWorkerRunning = false;
                    break;
                }
                addressText = taskState->pendingHostnameAddressList.takeFirst();
                taskState->pendingHostnameAddressSet.remove(addressText);
            }

            const QString resolvedHostnameText = resolveAndCacheHostnameText(addressText);
            if (!resolvedHostnameText.isEmpty())
            {
                resolvedHostnameMap.insert(addressText, resolvedHostnameText);
            }
            if (resolvedHostnameMap.size() < kResolvedHostnameBatchSize)
            {
                continue;
            }
            if (!submitResolvedHostnames(eventTable, taskState, resolvedHostnameMap))
            {
                std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
                taskState->pendingHostnameAddressList.clear();
                taskState->pendingHostnameAddressSet.clear();
                taskState->hostnameWorkerRunning = false;
                return;
            }
            resolvedHostnameMap.clear();
        }

        (void)submitResolvedHostnames(eventTable, taskState, resolvedHostnameMap);
    }

    // enqueueHostnameResolution 作用：
    // - 输入：事件表控件、握手状态、待反查地址列表；
    // - 处理：把地址并入去重队列，必要时 detach 唯一一个反查任务；
    // - 返回：无。
    void enqueueHostnameResolution(
        QTableWidget* eventTable,
        const std::shared_ptr<FirewallAsyncTaskState>& taskState,
        const QStringList& pendingAddressList)
    {
        if (eventTable == nullptr || !taskState || pendingAddressList.isEmpty())
        {
            return;
        }

        bool shouldStartWorker = false;
        {
            std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
            for (const QString& addressText : pendingAddressList)
            {
                if (taskState->pendingHostnameAddressSet.contains(addressText))
                {
                    continue;
                }
                taskState->pendingHostnameAddressSet.insert(addressText);
                taskState->pendingHostnameAddressList.push_back(addressText);
            }
            if (!taskState->hostnameWorkerRunning && !taskState->pendingHostnameAddressList.isEmpty())
            {
                taskState->hostnameWorkerRunning = true;
                shouldStartWorker = true;
            }
        }
        if (!shouldStartWorker)
        {
            return;
        }

        try
        {
            std::thread([eventTable, taskState]()
            {
                runHostnameResolutionWorker(eventTable, taskState);
            }).detach();
        }
        catch (...)
        {
            // 线程创建失败时放弃主机名补全，事件表保留纯 IP 显示。
            std::lock_guard<std::mutex> queueGuard(taskState->hostnameQueueMutex);
            taskState->pendingHostnameAddressList.clear();
            taskState->pendingHostnameAddressSet.clear();
            taskState->hostnameWorkerRunning = false;
        }
    }

    std::mutex g_wfpApiLoadMutex;         // g_wfpApiLoadMutex：保护 fwpuclnt.dll 的一次性解析。
    HMODULE g_fwpuclntModule = nullptr;   // g_fwpuclntModule：常驻进程的 fwpuclnt.dll 模块句柄。
    bool g_wfpApiReady = false;           // g_wfpApiReady：g_wfpApi 是否已完整解析。

    // ensureWfpApiLoadedShared 作用：
    // - 输入：错误文本输出；
    // - 处理：进程内只解析一次 fwpuclnt.dll 导出；模块刻意常驻不卸载，避免后台任务
    //         或实时订阅回调执行到已卸载的代码；
    // - 返回：关键导出齐全时 true。
    bool ensureWfpApiLoadedShared(QString* errorTextOut)
    {
        std::lock_guard<std::mutex> loadGuard(g_wfpApiLoadMutex);
        if (g_wfpApiReady)
        {
            return true;
        }

        if (g_fwpuclntModule == nullptr)
        {
            g_fwpuclntModule = LoadLibraryW(L"fwpuclnt.dll");
        }
        if (g_fwpuclntModule == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("无法加载 fwpuclnt.dll：%1").arg(win32ErrorText(GetLastError()));
            }
            return false;
        }

        HMODULE moduleHandle = g_fwpuclntModule;
        g_wfpApi.engineOpen = procAddress<WfpApi::FwpmEngineOpen0Fn>(moduleHandle, "FwpmEngineOpen0");
        g_wfpApi.engineClose = procAddress<WfpApi::FwpmEngineClose0Fn>(moduleHandle, "FwpmEngineClose0");
        g_wfpApi.engineSetOption = procAddress<WfpApi::FwpmEngineSetOption0Fn>(moduleHandle, "FwpmEngineSetOption0");
        g_wfpApi.freeMemory = procAddress<WfpApi::FwpmFreeMemory0Fn>(moduleHandle, "FwpmFreeMemory0");
        g_wfpApi.filterGetById = procAddress<WfpApi::FwpmFilterGetById0Fn>(moduleHandle, "FwpmFilterGetById0");
        g_wfpApi.eventCreateEnumHandle =
            procAddress<WfpApi::FwpmNetEventCreateEnumHandle0Fn>(moduleHandle, "FwpmNetEventCreateEnumHandle0");
        g_wfpApi.eventDestroyEnumHandle =
            procAddress<WfpApi::FwpmNetEventDestroyEnumHandle0Fn>(moduleHandle, "FwpmNetEventDestroyEnumHandle0");
        g_wfpApi.eventEnum = procAddress<WfpApi::FwpmNetEventEnumGenericFn>(moduleHandle, "FwpmNetEventEnum5");
        if (g_wfpApi.eventEnum == nullptr)
        {
            g_wfpApi.eventEnum = procAddress<WfpApi::FwpmNetEventEnumGenericFn>(moduleHandle, "FwpmNetEventEnum4");
        }
        if (g_wfpApi.eventEnum == nullptr)
        {
            g_wfpApi.eventEnum = procAddress<WfpApi::FwpmNetEventEnumGenericFn>(moduleHandle, "FwpmNetEventEnum3");
        }

        g_wfpApi.eventSubscribe = procAddress<WfpApi::FwpmNetEventSubscribeGenericFn>(moduleHandle, "FwpmNetEventSubscribe4");
        if (g_wfpApi.eventSubscribe == nullptr)
        {
            g_wfpApi.eventSubscribe = procAddress<WfpApi::FwpmNetEventSubscribeGenericFn>(moduleHandle, "FwpmNetEventSubscribe3");
        }
        g_wfpApi.eventUnsubscribe =
            procAddress<WfpApi::FwpmNetEventUnsubscribe0Fn>(moduleHandle, "FwpmNetEventUnsubscribe0");

        if (g_wfpApi.engineOpen == nullptr
            || g_wfpApi.engineClose == nullptr
            || g_wfpApi.engineSetOption == nullptr
            || g_wfpApi.freeMemory == nullptr
            || g_wfpApi.filterGetById == nullptr
            || g_wfpApi.eventCreateEnumHandle == nullptr
            || g_wfpApi.eventDestroyEnumHandle == nullptr
            || g_wfpApi.eventEnum == nullptr
            || g_wfpApi.eventSubscribe == nullptr
            || g_wfpApi.eventUnsubscribe == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("fwpuclnt.dll 缺少必要的 WFP 导出，当前系统不支持该防火墙事件视图。");
            }
            return false;
        }

        g_wfpApiReady = true;
        return true;
    }

    // openWfpEngineShared 作用：
    // - 输入：是否启用事件收集、engine 句柄输出、错误文本输出；
    // - 处理：打开 BFE engine，必要时写入全局 net event 采集开关；两者都是到 BFE 的
    //         RPC/策略提交，必须在后台线程调用；
    // - 返回：成功时 true。
    bool openWfpEngineShared(const bool enableCollection, HANDLE* engineHandleOut, QString* errorTextOut)
    {
        if (engineHandleOut == nullptr)
        {
            return false;
        }
        *engineHandleOut = nullptr;
        if (!ensureWfpApiLoadedShared(errorTextOut))
        {
            return false;
        }

        FWPM_SESSION0 session{};
        session.displayData.name = const_cast<wchar_t*>(L"KswordFirewallMonitor");
        session.displayData.description = const_cast<wchar_t*>(L"Ksword WFP firewall event monitor");
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;

        HANDLE engineHandle = nullptr;
        DWORD status = g_wfpApi.engineOpen(nullptr, RPC_C_AUTHN_DEFAULT, nullptr, &session, &engineHandle);
        if (status != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("打开 BFE/WFP engine 失败：%1。防火墙事件通常需要管理员权限。")
                    .arg(win32ErrorText(status));
            }
            return false;
        }

        if (enableCollection)
        {
            FWP_VALUE0 value{};
            value.type = FWP_UINT32;
            value.uint32 = TRUE;
            status = g_wfpApi.engineSetOption(engineHandle, FWPM_ENGINE_COLLECT_NET_EVENTS, &value);
            if (status != ERROR_SUCCESS)
            {
                g_wfpApi.engineClose(engineHandle);
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("开启 WFP net event collection 失败：%1。请以管理员运行。")
                        .arg(win32ErrorText(status));
                }
                return false;
            }

            value.type = FWP_UINT32;
            value.uint32 = FWPM_NET_EVENT_KEYWORD_INBOUND_MCAST
                | FWPM_NET_EVENT_KEYWORD_INBOUND_BCAST
                | FWPM_NET_EVENT_KEYWORD_CAPABILITY_DROP
                | FWPM_NET_EVENT_KEYWORD_CAPABILITY_ALLOW
                | FWPM_NET_EVENT_KEYWORD_CLASSIFY_ALLOW;
            g_wfpApi.engineSetOption(engineHandle, FWPM_ENGINE_NET_EVENT_MATCH_ANY_KEYWORDS, &value);
        }

        *engineHandleOut = engineHandle;
        return true;
    }

    // closeWfpEngineShared 作用：
    // - 输入：engine 句柄、是否关闭事件收集；
    // - 处理：可选复位全局事件采集开关并关闭 engine；
    // - 返回：无。
    void closeWfpEngineShared(HANDLE engineHandle, const bool disableCollection)
    {
        if (engineHandle == nullptr || g_wfpApi.engineClose == nullptr)
        {
            return;
        }
        if (disableCollection && g_wfpApi.engineSetOption != nullptr)
        {
            FWP_VALUE0 value{};
            value.type = FWP_UINT32;
            value.uint32 = FALSE;
            g_wfpApi.engineSetOption(engineHandle, FWPM_ENGINE_COLLECT_NET_EVENTS, &value);
        }
        g_wfpApi.engineClose(engineHandle);
    }

    // convertWfpEventToEntryShared 作用：
    // - 输入：FWPM_NET_EVENT 指针、engine 句柄；
    // - 处理：提取动作、方向、地址、端口、协议、规则名等字段；主机名只查进程级缓存，
    //         绝不在这里做同步反向 DNS，否则枚举主链路和 WFP 回调线程都会被 DNS 拖住；
    // - 返回：可显示事件。
    NetworkFirewallPage::FirewallEventEntry convertWfpEventToEntryShared(
        const void* wfpEventPointer,
        HANDLE engineHandle)
    {
        NetworkFirewallPage::FirewallEventEntry entry;
        const FWPM_NET_EVENT5* eventPointer = static_cast<const FWPM_NET_EVENT5*>(wfpEventPointer);
        if (eventPointer == nullptr)
        {
            return entry;
        }

        entry.actionText = actionText(eventPointer->type);
        entry.isDrop = isDropEvent(eventPointer->type);
        entry.descriptionText = entry.actionText;
        entry.timestampText = fileTimeToText(eventPointer->header.timeStamp);
        entry.protocolText = (eventPointer->header.flags & FWPM_NET_EVENT_FLAG_IP_PROTOCOL_SET) != 0
            ? protocolText(eventPointer->header.ipProtocol)
            : QString();
        entry.localAddressText = addressTextFromHeader(eventPointer->header, true);
        entry.localPortText = portTextFromHeader(eventPointer->header, true);
        entry.remoteAddressText = addressTextFromHeader(eventPointer->header, false);
        entry.remotePortText = portTextFromHeader(eventPointer->header, false);
        entry.applicationPathText = appPathFromHeader(eventPointer->header);
        entry.nameText = appNameFromHeader(eventPointer->header);
        if (entry.nameText.isEmpty())
        {
            entry.nameText = entry.actionText;
        }

        UINT64 filterId = 0;
        UINT32 rawDirection = 0;
        switch (eventPointer->type)
        {
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP:
            if (eventPointer->classifyDrop != nullptr)
            {
                filterId = eventPointer->classifyDrop->filterId;
                rawDirection = eventPointer->classifyDrop->msFwpDirection;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CLASSIFY_ALLOW:
            if (eventPointer->classifyAllow != nullptr)
            {
                filterId = eventPointer->classifyAllow->filterId;
                rawDirection = eventPointer->classifyAllow->msFwpDirection;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CAPABILITY_DROP:
            if (eventPointer->capabilityDrop != nullptr)
            {
                filterId = eventPointer->capabilityDrop->filterId;
                rawDirection = FWP_DIRECTION_OUTBOUND;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CAPABILITY_ALLOW:
            if (eventPointer->capabilityAllow != nullptr)
            {
                filterId = eventPointer->capabilityAllow->filterId;
                rawDirection = FWP_DIRECTION_OUTBOUND;
            }
            break;
        case FWPM_NET_EVENT_TYPE_CLASSIFY_DROP_MAC:
            if (eventPointer->classifyDropMac != nullptr)
            {
                filterId = eventPointer->classifyDropMac->filterId;
                rawDirection = eventPointer->classifyDropMac->msFwpDirection;
            }
            break;
        case FWPM_NET_EVENT_TYPE_IPSEC_KERNEL_DROP:
            if (eventPointer->ipsecDrop != nullptr)
            {
                filterId = eventPointer->ipsecDrop->filterId;
                rawDirection = static_cast<UINT32>(eventPointer->ipsecDrop->direction);
            }
            break;
        default:
            break;
        }
        entry.directionText = directionText(rawDirection);

        if (filterId != 0 && engineHandle != nullptr && g_wfpApi.filterGetById != nullptr)
        {
            FWPM_FILTER0* filterPointer = nullptr;
            if (g_wfpApi.filterGetById(engineHandle, filterId, &filterPointer) == ERROR_SUCCESS
                && filterPointer != nullptr)
            {
                if (filterPointer->displayData.name != nullptr)
                {
                    entry.ruleText = QString::fromWCharArray(filterPointer->displayData.name);
                }
                if (filterPointer->displayData.description != nullptr)
                {
                    entry.descriptionText = QString::fromWCharArray(filterPointer->displayData.description);
                }
                g_wfpApi.freeMemory(reinterpret_cast<void**>(&filterPointer));
            }
            if (entry.ruleText.isEmpty())
            {
                entry.ruleText = QStringLiteral("FilterId=%1").arg(filterId);
            }
        }

        (void)lookupCachedHostnameText(entry.localAddressText, &entry.localHostText);
        (void)lookupCachedHostnameText(entry.remoteAddressText, &entry.remoteHostText);
        return entry;
    }

    // enumerateHistoryWithEngineShared 作用：
    // - 输入：已打开的 engine 句柄、取消位、错误文本输出；
    // - 处理：分批调用 FwpmNetEventEnum*，每批和每条事件前都检查取消位，
    //         保证页面析构时能立即收敛；
    // - 返回：事件列表。
    std::vector<NetworkFirewallPage::FirewallEventEntry> enumerateHistoryWithEngineShared(
        HANDLE engineHandle,
        const std::atomic_bool* cancelFlag,
        QString* errorTextOut)
    {
        std::vector<NetworkFirewallPage::FirewallEventEntry> resultList;
        if (engineHandle == nullptr)
        {
            return resultList;
        }

        FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTemplate{};
        HANDLE enumHandle = nullptr;
        DWORD status = g_wfpApi.eventCreateEnumHandle(engineHandle, &enumTemplate, &enumHandle);
        if (status != ERROR_SUCCESS)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 WFP 事件枚举句柄失败：%1").arg(win32ErrorText(status));
            }
            return resultList;
        }

        while (cancelFlag == nullptr || !cancelFlag->load())
        {
            void** entries = nullptr;
            UINT32 count = 0;
            status = g_wfpApi.eventEnum(engineHandle, enumHandle, 256, &entries, &count);
            if (status != ERROR_SUCCESS)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("枚举 WFP 事件失败：%1").arg(win32ErrorText(status));
                }
                break;
            }
            if (count == 0 || entries == nullptr)
            {
                if (entries != nullptr)
                {
                    g_wfpApi.freeMemory(reinterpret_cast<void**>(&entries));
                }
                break;
            }

            for (UINT32 index = 0; index < count; ++index)
            {
                if (cancelFlag != nullptr && cancelFlag->load())
                {
                    break;
                }
                if (entries[index] != nullptr)
                {
                    resultList.push_back(convertWfpEventToEntryShared(entries[index], engineHandle));
                }
            }
            g_wfpApi.freeMemory(reinterpret_cast<void**>(&entries));
            if (resultList.size() >= static_cast<std::size_t>(kMaximumDisplayedFirewallEvents))
            {
                break;
            }
        }

        g_wfpApi.eventDestroyEnumHandle(engineHandle, enumHandle);
        std::reverse(resultList.begin(), resultList.end());
        return resultList;
    }

    // enumerateFirewallRulesSnapshotShared 作用：
    // - 输入：错误文本输出；
    // - 处理：在调用线程内自行初始化 COM，全量枚举系统防火墙规则并按名称排序；
    // - 返回：规则列表，失败时通过 errorTextOut 返回错误。
    std::vector<NetworkFirewallPage::FirewallRuleEntry> enumerateFirewallRulesSnapshotShared(QString* errorTextOut)
    {
        std::vector<NetworkFirewallPage::FirewallRuleEntry> resultList;
        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return resultList;
        }

        INetFwPolicy2* policyPointer = nullptr;
        HRESULT result = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&policyPointer));
        if (FAILED(result) || policyPointer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 INetFwPolicy2 失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        INetFwRules* rulesPointer = nullptr;
        result = policyPointer->get_Rules(&rulesPointer);
        if (FAILED(result) || rulesPointer == nullptr)
        {
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("获取防火墙规则集合失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        IUnknown* enumUnknownPointer = nullptr;
        result = rulesPointer->get__NewEnum(&enumUnknownPointer);
        if (FAILED(result) || enumUnknownPointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("获取规则枚举器失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        IEnumVARIANT* enumVariantPointer = nullptr;
        result = enumUnknownPointer->QueryInterface(IID_IEnumVARIANT, reinterpret_cast<void**>(&enumVariantPointer));
        releaseComPointer(enumUnknownPointer);
        if (FAILED(result) || enumVariantPointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("转换规则枚举器失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return resultList;
        }

        while (true)
        {
            ScopedVariant currentVariant;
            ULONG fetchedCount = 0;
            result = enumVariantPointer->Next(1, currentVariant.get(), &fetchedCount);
            if (result != S_OK || fetchedCount == 0)
            {
                break;
            }
            if (currentVariant.get()->vt != VT_DISPATCH || currentVariant.get()->pdispVal == nullptr)
            {
                continue;
            }

            INetFwRule* rulePointer = nullptr;
            result = currentVariant.get()->pdispVal->QueryInterface(__uuidof(INetFwRule), reinterpret_cast<void**>(&rulePointer));
            if (FAILED(result) || rulePointer == nullptr)
            {
                continue;
            }

            NetworkFirewallPage::FirewallRuleEntry ruleEntry;
            ScopedBstr nameText;
            ScopedBstr descriptionText;
            ScopedBstr applicationText;
            ScopedBstr serviceText;
            ScopedBstr localPortsText;
            ScopedBstr remotePortsText;
            ScopedBstr localAddressesText;
            ScopedBstr remoteAddressesText;
            ScopedBstr groupingText;
            VARIANT_BOOL enabledValue = VARIANT_FALSE;
            long protocolValue = 0;
            long directionValue = 0;
            long profilesValue = 0;
            NET_FW_ACTION actionValue = NET_FW_ACTION_BLOCK;

            rulePointer->get_Name(nameText.put());
            rulePointer->get_Description(descriptionText.put());
            rulePointer->get_ApplicationName(applicationText.put());
            rulePointer->get_ServiceName(serviceText.put());
            rulePointer->get_LocalPorts(localPortsText.put());
            rulePointer->get_RemotePorts(remotePortsText.put());
            rulePointer->get_LocalAddresses(localAddressesText.put());
            rulePointer->get_RemoteAddresses(remoteAddressesText.put());
            rulePointer->get_Grouping(groupingText.put());
            rulePointer->get_Enabled(&enabledValue);
            rulePointer->get_Protocol(&protocolValue);
            rulePointer->get_Direction(reinterpret_cast<NET_FW_RULE_DIRECTION*>(&directionValue));
            rulePointer->get_Profiles(&profilesValue);
            rulePointer->get_Action(&actionValue);

            ruleEntry.nameText = rawTextOrEmpty(qStringFromBstr(nameText.get()));
            ruleEntry.descriptionText = rawTextOrEmpty(qStringFromBstr(descriptionText.get()));
            ruleEntry.applicationText = rawTextOrEmpty(qStringFromBstr(applicationText.get()));
            ruleEntry.serviceText = rawTextOrEmpty(qStringFromBstr(serviceText.get()));
            ruleEntry.localPortsText = rawTextOrEmpty(qStringFromBstr(localPortsText.get()));
            ruleEntry.remotePortsText = rawTextOrEmpty(qStringFromBstr(remotePortsText.get()));
            ruleEntry.localAddressesText = rawTextOrEmpty(qStringFromBstr(localAddressesText.get()));
            ruleEntry.remoteAddressesText = rawTextOrEmpty(qStringFromBstr(remoteAddressesText.get()));
            ruleEntry.groupingText = rawTextOrEmpty(qStringFromBstr(groupingText.get()));
            ruleEntry.enabled = enabledValue == VARIANT_TRUE;
            ruleEntry.protocolValue = protocolValue;
            ruleEntry.directionValue = directionValue;
            ruleEntry.profilesValue = profilesValue;
            ruleEntry.actionValue = static_cast<long>(actionValue);
            ruleEntry.protocolText = firewallRuleProtocolText(ruleEntry.protocolValue);
            ruleEntry.directionText = firewallRuleDirectionText(ruleEntry.directionValue);
            ruleEntry.actionText = firewallRuleActionText(ruleEntry.actionValue);
            ruleEntry.profilesText = firewallProfilesText(ruleEntry.profilesValue);
            ruleEntry.fingerprintText = composeRuleFingerprint(
                ruleEntry.nameText,
                ruleEntry.applicationText,
                ruleEntry.serviceText,
                ruleEntry.localPortsText,
                ruleEntry.remotePortsText,
                ruleEntry.localAddressesText,
                ruleEntry.remoteAddressesText,
                ruleEntry.protocolValue,
                ruleEntry.directionValue,
                ruleEntry.actionValue,
                ruleEntry.profilesValue);
            resultList.push_back(std::move(ruleEntry));
            releaseComPointer(rulePointer);
        }

        releaseComPointer(enumVariantPointer);
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);

        std::sort(
            resultList.begin(),
            resultList.end(),
            [](const NetworkFirewallPage::FirewallRuleEntry& leftEntry,
               const NetworkFirewallPage::FirewallRuleEntry& rightEntry)
            {
                const int nameCompare = QString::compare(leftEntry.nameText, rightEntry.nameText, Qt::CaseInsensitive);
                if (nameCompare != 0)
                {
                    return nameCompare < 0;
                }
                return QString::compare(leftEntry.applicationText, rightEntry.applicationText, Qt::CaseInsensitive) < 0;
            });
        return resultList;
    }

    // firewallRuleNameOf 作用：
    // - 输入：一条系统规则；
    // - 处理：只读取规则名，供全量枚举时先做名称短路；
    // - 返回：规则名。
    QString firewallRuleNameOf(INetFwRule* rulePointer)
    {
        if (rulePointer == nullptr)
        {
            return QString();
        }
        ScopedBstr nameText;
        rulePointer->get_Name(nameText.put());
        return rawTextOrEmpty(qStringFromBstr(nameText.get()));
    }

    // firewallRuleFingerprintOf 作用：
    // - 输入：一条系统规则；
    // - 处理：读取参与匹配的 11 个属性并拼出指纹；
    // - 返回：规则指纹。
    QString firewallRuleFingerprintOf(INetFwRule* rulePointer)
    {
        if (rulePointer == nullptr)
        {
            return QString();
        }

        ScopedBstr nameText;
        ScopedBstr applicationText;
        ScopedBstr serviceText;
        ScopedBstr localPortsText;
        ScopedBstr remotePortsText;
        ScopedBstr localAddressesText;
        ScopedBstr remoteAddressesText;
        long protocolValue = 0;
        long directionValue = 0;
        long profilesValue = 0;
        NET_FW_ACTION actionValue = NET_FW_ACTION_BLOCK;

        rulePointer->get_Name(nameText.put());
        rulePointer->get_ApplicationName(applicationText.put());
        rulePointer->get_ServiceName(serviceText.put());
        rulePointer->get_LocalPorts(localPortsText.put());
        rulePointer->get_RemotePorts(remotePortsText.put());
        rulePointer->get_LocalAddresses(localAddressesText.put());
        rulePointer->get_RemoteAddresses(remoteAddressesText.put());
        rulePointer->get_Protocol(&protocolValue);
        rulePointer->get_Direction(reinterpret_cast<NET_FW_RULE_DIRECTION*>(&directionValue));
        rulePointer->get_Profiles(&profilesValue);
        rulePointer->get_Action(&actionValue);

        return composeRuleFingerprint(
            rawTextOrEmpty(qStringFromBstr(nameText.get())),
            rawTextOrEmpty(qStringFromBstr(applicationText.get())),
            rawTextOrEmpty(qStringFromBstr(serviceText.get())),
            rawTextOrEmpty(qStringFromBstr(localPortsText.get())),
            rawTextOrEmpty(qStringFromBstr(remotePortsText.get())),
            rawTextOrEmpty(qStringFromBstr(localAddressesText.get())),
            rawTextOrEmpty(qStringFromBstr(remoteAddressesText.get())),
            protocolValue,
            directionValue,
            static_cast<long>(actionValue),
            profilesValue);
    }

    // acquireFirewallRuleByFingerprint 作用：
    // - 输入：规则集合、目标规则名、目标规则指纹；
    // - 处理：先用 INetFwRules::Item 按名直取候选，指纹一致就直接命中；只有同名多条
    //         或指纹不符时才退化成全量枚举，且枚举时先读 Name 短路，避免对系统里
    //         上千条规则每条都读满 11 个属性；
    // - 返回：命中的规则指针（调用方负责 Release），未命中返回 nullptr。
    INetFwRule* acquireFirewallRuleByFingerprint(
        INetFwRules* rulesPointer,
        const QString& ruleNameText,
        const QString& fingerprintText)
    {
        if (rulesPointer == nullptr)
        {
            return nullptr;
        }

        if (!ruleNameText.isEmpty())
        {
            ScopedBstr ruleNameBstr(bstrFromQString(ruleNameText));
            INetFwRule* candidateRulePointer = nullptr;
            if (ruleNameBstr.get() != nullptr
                && SUCCEEDED(rulesPointer->Item(ruleNameBstr.get(), &candidateRulePointer))
                && candidateRulePointer != nullptr)
            {
                if (firewallRuleFingerprintOf(candidateRulePointer) == fingerprintText)
                {
                    return candidateRulePointer;
                }
                releaseComPointer(candidateRulePointer);
            }
        }

        IUnknown* enumUnknownPointer = nullptr;
        if (FAILED(rulesPointer->get__NewEnum(&enumUnknownPointer)) || enumUnknownPointer == nullptr)
        {
            return nullptr;
        }

        IEnumVARIANT* enumVariantPointer = nullptr;
        const HRESULT queryResult =
            enumUnknownPointer->QueryInterface(IID_IEnumVARIANT, reinterpret_cast<void**>(&enumVariantPointer));
        releaseComPointer(enumUnknownPointer);
        if (FAILED(queryResult) || enumVariantPointer == nullptr)
        {
            return nullptr;
        }

        INetFwRule* matchedRulePointer = nullptr;
        while (true)
        {
            ScopedVariant currentVariant;
            ULONG fetchedCount = 0;
            if (enumVariantPointer->Next(1, currentVariant.get(), &fetchedCount) != S_OK || fetchedCount == 0)
            {
                break;
            }
            if (currentVariant.get()->vt != VT_DISPATCH || currentVariant.get()->pdispVal == nullptr)
            {
                continue;
            }

            INetFwRule* rulePointer = nullptr;
            if (FAILED(currentVariant.get()->pdispVal->QueryInterface(
                    __uuidof(INetFwRule),
                    reinterpret_cast<void**>(&rulePointer)))
                || rulePointer == nullptr)
            {
                continue;
            }

            if (!ruleNameText.isEmpty() && firewallRuleNameOf(rulePointer) != ruleNameText)
            {
                releaseComPointer(rulePointer);
                continue;
            }
            if (firewallRuleFingerprintOf(rulePointer) == fingerprintText)
            {
                matchedRulePointer = rulePointer;
                break;
            }
            releaseComPointer(rulePointer);
        }

        releaseComPointer(enumVariantPointer);
        return matchedRulePointer;
    }

    // openFirewallRuleCollection 作用：
    // - 输入：策略对象输出、规则集合输出、错误文本输出；
    // - 处理：创建 INetFwPolicy2 并取出规则集合，失败时统一填充错误文本；
    // - 返回：成功时 true，调用方负责 Release 两个出参。
    bool openFirewallRuleCollection(
        INetFwPolicy2** policyPointerOut,
        INetFwRules** rulesPointerOut,
        QString* errorTextOut)
    {
        if (policyPointerOut == nullptr || rulesPointerOut == nullptr)
        {
            return false;
        }
        *policyPointerOut = nullptr;
        *rulesPointerOut = nullptr;

        INetFwPolicy2* policyPointer = nullptr;
        HRESULT result = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&policyPointer));
        if (FAILED(result) || policyPointer == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 INetFwPolicy2 失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }

        INetFwRules* rulesPointer = nullptr;
        result = policyPointer->get_Rules(&rulesPointer);
        if (FAILED(result) || rulesPointer == nullptr)
        {
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("获取规则集合失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }

        *policyPointerOut = policyPointer;
        *rulesPointerOut = rulesPointer;
        return true;
    }

    // updateFirewallRuleInSystemShared 作用：
    // - 输入：原规则名、原指纹、新规则内容、错误文本输出；
    // - 处理：在调用线程内自行初始化 COM，定位目标规则后逐字段写回；
    // - 返回：写回成功时 true。
    bool updateFirewallRuleInSystemShared(
        const QString& originalNameText,
        const QString& originalFingerprintText,
        const NetworkFirewallPage::FirewallRuleEntry& updatedRuleEntry,
        QString* errorTextOut)
    {
        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return false;
        }

        INetFwPolicy2* policyPointer = nullptr;
        INetFwRules* rulesPointer = nullptr;
        if (!openFirewallRuleCollection(&policyPointer, &rulesPointer, errorTextOut))
        {
            return false;
        }

        INetFwRule* rulePointer = acquireFirewallRuleByFingerprint(rulesPointer, originalNameText, originalFingerprintText);
        if (rulePointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("未找到要编辑的防火墙规则，规则可能已被外部修改。");
            }
            return false;
        }

        ScopedBstr updatedNameText(bstrFromQString(updatedRuleEntry.nameText));
        ScopedBstr updatedDescriptionText(bstrFromQString(updatedRuleEntry.descriptionText));
        ScopedBstr updatedApplicationText(bstrFromQString(updatedRuleEntry.applicationText));
        ScopedBstr updatedServiceText(bstrFromQString(updatedRuleEntry.serviceText));
        ScopedBstr updatedLocalPortsText(bstrFromQString(updatedRuleEntry.localPortsText));
        ScopedBstr updatedRemotePortsText(bstrFromQString(updatedRuleEntry.remotePortsText));
        ScopedBstr updatedLocalAddressesText(bstrFromQString(updatedRuleEntry.localAddressesText));
        ScopedBstr updatedRemoteAddressesText(bstrFromQString(updatedRuleEntry.remoteAddressesText));
        ScopedBstr updatedGroupingText(bstrFromQString(updatedRuleEntry.groupingText));

        HRESULT result = rulePointer->put_Name(updatedNameText.get());
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Description(updatedDescriptionText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_ApplicationName(updatedApplicationText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_ServiceName(updatedServiceText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Protocol(updatedRuleEntry.protocolValue);
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_LocalPorts(updatedLocalPortsText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_RemotePorts(updatedRemotePortsText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_LocalAddresses(updatedLocalAddressesText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_RemoteAddresses(updatedRemoteAddressesText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Grouping(updatedGroupingText.get());
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(updatedRuleEntry.directionValue));
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Profiles(updatedRuleEntry.profilesValue);
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Action(static_cast<NET_FW_ACTION>(updatedRuleEntry.actionValue));
        }
        if (SUCCEEDED(result))
        {
            result = rulePointer->put_Enabled(updatedRuleEntry.enabled ? VARIANT_TRUE : VARIANT_FALSE);
        }

        releaseComPointer(rulePointer);
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);

        if (FAILED(result))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("更新防火墙规则失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }
        return true;
    }

    // setFirewallRuleEnabledInSystemShared 作用：
    // - 输入：规则名、规则指纹、目标启用状态、错误文本输出；
    // - 处理：在调用线程内自行初始化 COM，定位目标规则后只写 Enabled；
    // - 返回：写回成功时 true。
    bool setFirewallRuleEnabledInSystemShared(
        const QString& ruleNameText,
        const QString& fingerprintText,
        const bool enabled,
        QString* errorTextOut)
    {
        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return false;
        }

        INetFwPolicy2* policyPointer = nullptr;
        INetFwRules* rulesPointer = nullptr;
        if (!openFirewallRuleCollection(&policyPointer, &rulesPointer, errorTextOut))
        {
            return false;
        }

        INetFwRule* rulePointer = acquireFirewallRuleByFingerprint(rulesPointer, ruleNameText, fingerprintText);
        if (rulePointer == nullptr)
        {
            releaseComPointer(rulesPointer);
            releaseComPointer(policyPointer);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("未找到要更新的防火墙规则，规则可能已被外部修改。");
            }
            return false;
        }

        const HRESULT result = rulePointer->put_Enabled(enabled ? VARIANT_TRUE : VARIANT_FALSE);
        releaseComPointer(rulePointer);
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);

        if (FAILED(result))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("更新规则启用状态失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }
        return true;
    }

    // deleteFirewallRulesFromSystemShared 作用：
    // - 输入：规则名列表、成功计数输出、错误文本输出；
    // - 处理：只创建一次 INetFwPolicy2/INetFwRules，循环 Remove，避免按条数重复建 COM 对象；
    // - 返回：全部删除成功时 true，中途失败时立即返回并保留已删数量。
    bool deleteFirewallRulesFromSystemShared(
        const QStringList& ruleNameList,
        int* deletedCountOut,
        QString* errorTextOut)
    {
        if (deletedCountOut != nullptr)
        {
            *deletedCountOut = 0;
        }

        ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
        if (!comInitializer.succeeded())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                    .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
            }
            return false;
        }

        INetFwPolicy2* policyPointer = nullptr;
        INetFwRules* rulesPointer = nullptr;
        if (!openFirewallRuleCollection(&policyPointer, &rulesPointer, errorTextOut))
        {
            return false;
        }

        HRESULT result = S_OK;
        int deletedCount = 0;
        for (const QString& ruleNameText : ruleNameList)
        {
            ScopedBstr ruleNameBstr(bstrFromQString(ruleNameText));
            result = rulesPointer->Remove(ruleNameBstr.get());
            if (FAILED(result))
            {
                break;
            }
            ++deletedCount;
        }

        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);
        if (deletedCountOut != nullptr)
        {
            *deletedCountOut = deletedCount;
        }

        if (FAILED(result))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("删除防火墙规则失败：0x%1")
                    .arg(static_cast<unsigned long>(result), 0, 16);
            }
            return false;
        }
        return true;
    }
}

NetworkFirewallPage::NetworkFirewallPage(QWidget* parent)
    : QWidget(parent)
{
    // 后台任务与页面之间只通过这个握手状态联系，构造时即注册，避免任何任务
    // 在页面还没登记时就去创建状态。
    (void)acquireFirewallAsyncTaskState(this);
    initializeUi();
    initializeConnections();
}

NetworkFirewallPage::~NetworkFirewallPage()
{
    // 所有后台任务都只使用文件级函数和入参副本，不触碰页面成员：这里先置取消位
    // 并清空回投 owner，再限时等待在跑任务收敛。等待超时也不死等——任务继续跑到底
    // 同样安全，它们只会发现 owner 已空并放弃回投。
    m_shuttingDown.store(true);
    if (m_liveFlushTimer != nullptr)
    {
        m_liveFlushTimer->stop();
    }

    const std::shared_ptr<FirewallAsyncTaskState> taskState = detachFirewallAsyncTaskState(this);
    waitForFirewallAsyncWorkers(taskState, kAsyncWorkerShutdownWaitMilliseconds);

    // 实时订阅的回调上下文就是本页面，必须在对象消亡前同步退订；m_shuttingDown 已置位，
    // stopLiveMonitor 会同步完成 engine 关闭，保证进程退出前复位全局事件采集开关。
    stopLiveMonitor();
    // fwpuclnt.dll 刻意常驻进程不再卸载：detach 的后台任务可能仍在其中执行，
    // 提前 FreeLibrary 会让它们跳进已卸载的代码。
}

void NetworkFirewallPage::requestInitialRefresh()
{
    bool expected = false;
    if (!m_initialRefreshRequested.compare_exchange_strong(expected, true))
    {
        return;
    }

    refreshHistoryAsync(false);
    refreshRulesAsync(false);
}

void NetworkFirewallPage::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(6, 6, 6, 6);
    m_rootLayout->setSpacing(6);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("防火墙"), this);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    headerLayout->addWidget(titleLabel, 0);

    m_statusLabel = new QLabel(QStringLiteral("正在加载 WFP 事件..."), this);
    m_statusLabel->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;").arg(KswordTheme::TextSecondaryHex()));
    m_statusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    headerLayout->addWidget(m_statusLabel, 1);
    m_rootLayout->addLayout(headerLayout, 0);

    m_innerTabWidget = new QTabWidget(this);
    m_rootLayout->addWidget(m_innerTabWidget, 1);

    initializeEventMonitorUi();
    initializeRuleManagerUi();

    m_liveFlushTimer = new QTimer(this);
    m_liveFlushTimer->setInterval(250);
}

void NetworkFirewallPage::initializeEventMonitorUi()
{
    m_eventMonitorPage = new QWidget(this);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_eventMonitorPage);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(6);

    QHBoxLayout* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);

    m_refreshHistoryButton = new QPushButton(QStringLiteral("刷新历史"), m_eventMonitorPage);
    m_refreshHistoryButton->setToolTip(QStringLiteral("枚举当前 BFE 会话可见的 WFP net event 历史记录"));
    toolbarLayout->addWidget(m_refreshHistoryButton, 0);

    m_startLiveButton = new QPushButton(QStringLiteral("启动实时"), m_eventMonitorPage);
    m_startLiveButton->setToolTip(QStringLiteral("开启 WFP net event collection 并订阅实时事件，需要管理员权限。"));
    toolbarLayout->addWidget(m_startLiveButton, 0);

    m_stopLiveButton = new QPushButton(QStringLiteral("停止实时"), m_eventMonitorPage);
    m_stopLiveButton->setEnabled(false);
    m_stopLiveButton->setToolTip(QStringLiteral("停止实时监控防火墙（WFP）事件"));
    toolbarLayout->addWidget(m_stopLiveButton, 0);

    m_clearButton = new QPushButton(QStringLiteral("清空"), m_eventMonitorPage);
    m_clearButton->setToolTip(QStringLiteral("清空下方的防火墙事件列表"));
    toolbarLayout->addWidget(m_clearButton, 0);

    m_searchEdit = new QLineEdit(m_eventMonitorPage);
    m_searchEdit->setPlaceholderText(QStringLiteral("搜索 Name/Action/Rule/地址/端口/协议..."));
    m_searchEdit->setMinimumWidth(240);
    toolbarLayout->addWidget(m_searchEdit, 1);

    m_dropOnlyCheck = new QCheckBox(QStringLiteral("仅 DROP"), m_eventMonitorPage);
    toolbarLayout->addWidget(m_dropOnlyCheck, 0);
    pageLayout->addLayout(toolbarLayout, 0);

    m_eventTable = new ks::ui::VisibleTableWidget(m_eventMonitorPage);
    m_eventTable->setColumnCount(ColumnCount);
    m_eventTable->setHorizontalHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Action"),
        QStringLiteral("Direction"),
        QStringLiteral("Rule"),
        QStringLiteral("Description"),
        QStringLiteral("Local address"),
        QStringLiteral("Local port"),
        QStringLiteral("Local host"),
        QStringLiteral("Remote address"),
        QStringLiteral("Remote port"),
        QStringLiteral("Remote host"),
        QStringLiteral("Protocol"),
        QStringLiteral("Timestamp")
        });
    m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eventTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_eventTable->setAlternatingRowColors(true);
    m_eventTable->verticalHeader()->setVisible(false);
    m_eventTable->horizontalHeader()->setStretchLastSection(false);
    m_eventTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_eventTable->setColumnWidth(ColumnName, 150);
    m_eventTable->setColumnWidth(ColumnAction, 125);
    m_eventTable->setColumnWidth(ColumnDirection, 70);
    m_eventTable->setColumnWidth(ColumnRule, 230);
    m_eventTable->setColumnWidth(ColumnDescription, 210);
    m_eventTable->setColumnWidth(ColumnLocalAddress, 130);
    m_eventTable->setColumnWidth(ColumnRemoteAddress, 130);
    m_eventTable->setColumnWidth(ColumnTimestamp, 170);
    installFirewallTableCopyMenu(m_eventTable, [this](const int rowIndex)
    {
        if (m_eventTable == nullptr || rowIndex < 0 || rowIndex >= m_eventTable->rowCount())
        {
            return;
        }

        const auto textAt = [this, rowIndex](const int column) -> QString
        {
            const QTableWidgetItem* item = m_eventTable->item(rowIndex, column);
            return item != nullptr ? item->text().trimmed() : QString();
        };
        const QTableWidgetItem* nameItem = m_eventTable->item(rowIndex, ColumnName);
        const QString applicationPathHint = nameItem != nullptr
            ? nameItem->data(Qt::UserRole + 1).toString().trimmed()
            : QString();
        const QString wfpDirection = textAt(ColumnDirection);
        const QString firewallDirection = wfpDirection.compare(QStringLiteral("In"), Qt::CaseInsensitive) == 0
            ? QStringLiteral("Inbound")
            : wfpDirection.compare(QStringLiteral("Out"), Qt::CaseInsensitive) == 0
                ? QStringLiteral("Outbound")
                : QStringLiteral("Unknown");
        addBlockRuleFromEvidence(
            textAt(ColumnRemoteAddress),
            textAt(ColumnRemotePort),
            textAt(ColumnProtocol),
            firewallDirection,
            QStringLiteral("WFP 事件"),
            0U,
            0U,
            QString(),
            applicationPathHint);
    });
    pageLayout->addWidget(m_eventTable, 1);

    if (m_innerTabWidget != nullptr)
    {
        m_innerTabWidget->addTab(m_eventMonitorPage, QStringLiteral("事件监控"));
    }
}

void NetworkFirewallPage::initializeRuleManagerUi()
{
    m_ruleManagerPage = new QWidget(this);
    QVBoxLayout* pageLayout = new QVBoxLayout(m_ruleManagerPage);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    pageLayout->setSpacing(6);

    QHBoxLayout* toolbarLayout = new QHBoxLayout();
    toolbarLayout->setContentsMargins(0, 0, 0, 0);
    toolbarLayout->setSpacing(8);

    m_refreshRulesButton = new QPushButton(QStringLiteral("刷新规则"), m_ruleManagerPage);
    m_refreshRulesButton->setIcon(QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_refreshRulesButton->setToolTip(QStringLiteral("重新枚举 Windows Firewall 规则"));
    toolbarLayout->addWidget(m_refreshRulesButton, 0);

    m_addRuleButton = new QPushButton(QStringLiteral("新增"), m_ruleManagerPage);
    m_addRuleButton->setIcon(QIcon(QStringLiteral(":/Icon/plus.svg")));
    m_addRuleButton->setToolTip(QStringLiteral("新增 Windows Firewall 规则"));
    toolbarLayout->addWidget(m_addRuleButton, 0);

    m_editRuleButton = new QPushButton(QStringLiteral("编辑"), m_ruleManagerPage);
    m_editRuleButton->setIcon(QIcon(QStringLiteral(":/Icon/process_details.svg")));
    m_editRuleButton->setToolTip(QStringLiteral("编辑选中的规则"));
    m_editRuleButton->setEnabled(false);
    toolbarLayout->addWidget(m_editRuleButton, 0);

    m_toggleRuleButton = new QPushButton(QStringLiteral("启用/禁用"), m_ruleManagerPage);
    m_toggleRuleButton->setIcon(QIcon(QStringLiteral(":/Icon/process_suspend.svg")));
    m_toggleRuleButton->setToolTip(QStringLiteral("切换选中规则的启用状态"));
    m_toggleRuleButton->setEnabled(false);
    toolbarLayout->addWidget(m_toggleRuleButton, 0);

    m_deleteRuleButton = new QPushButton(QStringLiteral("删除"), m_ruleManagerPage);
    m_deleteRuleButton->setIcon(QIcon(QStringLiteral(":/Icon/log_clear.svg")));
    m_deleteRuleButton->setToolTip(QStringLiteral("删除选中的规则"));
    m_deleteRuleButton->setEnabled(false);
    toolbarLayout->addWidget(m_deleteRuleButton, 0);

    m_ruleSearchEdit = new QLineEdit(m_ruleManagerPage);
    m_ruleSearchEdit->setPlaceholderText(QStringLiteral("搜索 Name/Application/Port/Protocol/Group..."));
    m_ruleSearchEdit->setMinimumWidth(240);
    toolbarLayout->addWidget(m_ruleSearchEdit, 1);

    m_ruleEnabledOnlyCheck = new QCheckBox(QStringLiteral("仅启用"), m_ruleManagerPage);
    toolbarLayout->addWidget(m_ruleEnabledOnlyCheck, 0);
    pageLayout->addLayout(toolbarLayout, 0);

    m_ruleSplitter = new QSplitter(Qt::Vertical, m_ruleManagerPage);
    m_ruleTable = new ks::ui::VisibleTableWidget(m_ruleSplitter);
    m_ruleTable->setColumnCount(RuleColumnCount);
    m_ruleTable->setHorizontalHeaderLabels({
        QStringLiteral("Name"),
        QStringLiteral("Enabled"),
        QStringLiteral("Action"),
        QStringLiteral("Direction"),
        QStringLiteral("Profiles"),
        QStringLiteral("Protocol"),
        QStringLiteral("Local Ports"),
        QStringLiteral("Remote Ports"),
        QStringLiteral("Application"),
        QStringLiteral("Service"),
        QStringLiteral("Grouping"),
        QStringLiteral("Description")
        });
    m_ruleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_ruleTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_ruleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_ruleTable->setAlternatingRowColors(true);
    m_ruleTable->verticalHeader()->setVisible(false);
    m_ruleTable->horizontalHeader()->setStretchLastSection(false);
    m_ruleTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_ruleTable->setColumnWidth(RuleColumnName, 180);
    m_ruleTable->setColumnWidth(RuleColumnApplication, 220);
    m_ruleTable->setColumnWidth(RuleColumnGrouping, 150);
    m_ruleTable->setColumnWidth(RuleColumnDescription, 220);
    m_ruleTable->setContextMenuPolicy(Qt::CustomContextMenu);

    // 完整详情固定放在规则表下方，默认约占页面高度四分之一。
    m_ruleDetailEditor = new CodeEditorWidget(m_ruleSplitter);
    m_ruleDetailEditor->setReadOnly(true);
    m_ruleDetailEditor->setLocalizedText(QStringLiteral("请选择一条防火墙规则查看完整详情。"));
    m_ruleSplitter->addWidget(m_ruleTable);
    m_ruleSplitter->addWidget(m_ruleDetailEditor);
    m_ruleSplitter->setStretchFactor(0, 3);
    m_ruleSplitter->setStretchFactor(1, 1);
    m_ruleSplitter->setSizes({ 720, 240 });
    pageLayout->addWidget(m_ruleSplitter, 1);

    ks::ui::DetailLayoutRegistry::registerHost(
        m_ruleTable, m_ruleDetailEditor, m_ruleManagerPage);

    if (m_innerTabWidget != nullptr)
    {
        m_innerTabWidget->addTab(m_ruleManagerPage, QStringLiteral("规则管理"));
    }
}

void NetworkFirewallPage::initializeConnections()
{
    connect(m_refreshHistoryButton, &QPushButton::clicked, this, [this]()
    {
        refreshHistoryAsync(true);
    });
    connect(m_startLiveButton, &QPushButton::clicked, this, [this]()
    {
        startLiveMonitor();
    });
    connect(m_stopLiveButton, &QPushButton::clicked, this, [this]()
    {
        stopLiveMonitor();
    });
    connect(m_clearButton, &QPushButton::clicked, this, [this]()
    {
        if (m_eventTable != nullptr)
        {
            m_eventTable->setRowCount(0);
        }
    });
    connect(m_searchEdit, &QLineEdit::textChanged, this, [this]()
    {
        applyFilterToRows();
    });
    connect(m_dropOnlyCheck, &QCheckBox::toggled, this, [this]()
    {
        applyFilterToRows();
    });
    connect(m_liveFlushTimer, &QTimer::timeout, this, [this]()
    {
        flushLiveEventsToUi();
    });
    connect(m_refreshRulesButton, &QPushButton::clicked, this, [this]()
    {
        refreshRulesAsync(true);
    });
    connect(m_addRuleButton, &QPushButton::clicked, this, [this]()
    {
        addFirewallRule();
    });
    connect(m_editRuleButton, &QPushButton::clicked, this, [this]()
    {
        editSelectedFirewallRule();
    });
    connect(m_toggleRuleButton, &QPushButton::clicked, this, [this]()
    {
        toggleSelectedFirewallRuleEnabled();
    });
    connect(m_deleteRuleButton, &QPushButton::clicked, this, [this]()
    {
        deleteSelectedFirewallRules();
    });
    connect(m_ruleSearchEdit, &QLineEdit::textChanged, this, [this]()
    {
        applyRuleFilterToRows();
    });
    connect(m_ruleEnabledOnlyCheck, &QCheckBox::toggled, this, [this]()
    {
        applyRuleFilterToRows();
    });
    connect(m_ruleTable, &QTableWidget::itemSelectionChanged, this, [this]()
    {
        updateRuleActionButtons();
        updateRuleDetailEditor();
    });
    connect(m_ruleTable, &QTableWidget::cellDoubleClicked, this, [this](const int, const int)
    {
        editSelectedFirewallRule();
    });
    connect(m_ruleTable, &QTableWidget::customContextMenuRequested, this, [this](const QPoint& position)
    {
        showRuleContextMenu(position);
    });
    m_liveFlushTimer->start();
}

void NetworkFirewallPage::refreshHistoryAsync(const bool forceRefresh)
{
    bool expectedValue = false;
    if (!m_refreshingHistory.compare_exchange_strong(expectedValue, true))
    {
        if (forceRefresh)
        {
            setStatusText(QStringLiteral("历史事件正在刷新，请稍候。"));
        }
        return;
    }

    if (m_refreshHistoryButton != nullptr)
    {
        m_refreshHistoryButton->setEnabled(false);
    }
    setStatusText(QStringLiteral("正在枚举 WFP 历史事件..."));

    const std::shared_ptr<FirewallAsyncTaskState> taskState = acquireFirewallAsyncTaskState(this);
    if (!taskState)
    {
        m_refreshingHistory.store(false);
        return;
    }
    // 事件表是页面子控件：只有在 owner 复核通过（页面存活）时才会被使用。
    QTableWidget* const eventTablePointer = m_eventTable;

    try
    {
        // 枚举任务只调用文件级函数，页面析构后仍可安全跑完，因此直接 detach。
        std::thread([taskState, eventTablePointer]()
        {
            const AsyncWorkerScope workerScope(taskState);
            std::vector<FirewallEventEntry> eventList;
            QString errorText;
            try
            {
                HANDLE engineHandle = nullptr;
                if (openWfpEngineShared(false, &engineHandle, &errorText))
                {
                    try
                    {
                        eventList = enumerateHistoryWithEngineShared(engineHandle, &taskState->cancelRequested, &errorText);
                    }
                    catch (...)
                    {
                        closeWfpEngineShared(engineHandle, false);
                        throw;
                    }
                    closeWfpEngineShared(engineHandle, false);
                }
            }
            catch (const std::exception& exception)
            {
                errorText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            if (taskState->cancelRequested.load())
            {
                return;
            }

            // 反向 DNS 已从枚举主链路里拆出来：先把 IP 摆上表，主机名交给独立任务回填。
            const QStringList pendingAddressList = collectUnresolvedAddressList(eventList);

            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            NetworkFirewallPage* const receiver = taskState->owner;
            if (receiver == nullptr)
            {
                return;
            }

            const bool invokeOk = QMetaObject::invokeMethod(
                receiver,
                [taskState, eventTablePointer, eventList = std::move(eventList), errorText, pendingAddressList]() mutable
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                        pagePointer = taskState->owner;
                    }
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (errorText.isEmpty())
                    {
                        pagePointer->appendEventsToTable(eventList, true);
                        pagePointer->setStatusText(
                            QStringLiteral("历史事件：%1 条，刷新：%2")
                            .arg(static_cast<int>(eventList.size()))
                            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
                        enqueueHostnameResolution(eventTablePointer, taskState, pendingAddressList);
                    }
                    else
                    {
                        pagePointer->setStatusText(errorText);
                    }
                    if (pagePointer->m_refreshHistoryButton != nullptr)
                    {
                        pagePointer->m_refreshHistoryButton->setEnabled(true);
                    }
                    pagePointer->m_refreshingHistory.store(false);
                },
                Qt::QueuedConnection);
            if (!invokeOk)
            {
                receiver->m_refreshingHistory.store(false);
            }
        }).detach();
    }
    catch (...)
    {
        m_refreshingHistory.store(false);
        if (m_refreshHistoryButton != nullptr)
        {
            m_refreshHistoryButton->setEnabled(true);
        }
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::startLiveMonitor()
{
    if (m_liveRunning.load())
    {
        setStatusText(QStringLiteral("实时防火墙监控已经启动。"));
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("实时防火墙事件监控"));
        return;
    }

    const std::shared_ptr<FirewallAsyncTaskState> taskState = acquireFirewallAsyncTaskState(this);
    if (!taskState)
    {
        return;
    }
    bool expectedTransition = false;
    if (!taskState->liveTransitionInProgress.compare_exchange_strong(expectedTransition, true))
    {
        setStatusText(QStringLiteral("实时防火墙监控已经启动。"));
        return;
    }

    // FwpmEngineOpen0 是到 BFE 的 RPC，FWPM_ENGINE_COLLECT_NET_EVENTS 更是一次全局
    // 引擎策略提交，合计典型 200ms~1.5s：整段搬到后台线程，UI 侧先置灰启动按钮。
    if (m_startLiveButton != nullptr)
    {
        m_startLiveButton->setEnabled(false);
    }

    try
    {
        std::thread([taskState]()
        {
            const AsyncWorkerScope workerScope(taskState);
            QString errorText;
            HANDLE engineHandle = nullptr;
            bool subscribed = false;
            try
            {
                if (openWfpEngineShared(true, &engineHandle, &errorText))
                {
                    FWPM_NET_EVENT_ENUM_TEMPLATE0 enumTemplate{};
                    FWPM_NET_EVENT_SUBSCRIPTION0 subscription{};
                    subscription.enumTemplate = &enumTemplate;
                    const HRESULT guidStatus = ::CoCreateGuid(&subscription.sessionKey);
                    if (FAILED(guidStatus))
                    {
                        errorText = QStringLiteral("启动实时防火墙事件订阅失败：%1。请确认以管理员运行。")
                            .arg(win32ErrorText(static_cast<DWORD>(guidStatus)));
                    }
                    else
                    {
                        // 订阅和句柄落库必须在同一把锁内完成：页面析构会先置取消位、再抢这把锁
                        // 清空 owner，因而要么订阅根本没装上，要么句柄已经写进页面、由析构里的
                        // stopLiveMonitor 负责退订，不存在把回调挂到消亡页面上的中间态。
                        std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
                        NetworkFirewallPage* const receiver = taskState->owner;
                        if (receiver != nullptr && !taskState->cancelRequested.load())
                        {
                            HANDLE subscriptionHandle = nullptr;
                            const DWORD status = g_wfpApi.eventSubscribe(
                                engineHandle,
                                &subscription,
                                &NetworkFirewallPage::liveEventCallback,
                                receiver,
                                &subscriptionHandle);
                            if (status == ERROR_SUCCESS)
                            {
                                receiver->m_liveEngineHandle = engineHandle;
                                receiver->m_liveSubscriptionHandle = subscriptionHandle;
                                receiver->m_liveRunning.store(true);
                                subscribed = true;
                                QMetaObject::invokeMethod(
                                    receiver,
                                    [taskState]()
                                    {
                                        NetworkFirewallPage* pagePointer = nullptr;
                                        {
                                            std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                                            pagePointer = taskState->owner;
                                        }
                                        taskState->liveTransitionInProgress.store(false);
                                        if (pagePointer == nullptr)
                                        {
                                            return;
                                        }
                                        if (pagePointer->m_startLiveButton != nullptr)
                                        {
                                            pagePointer->m_startLiveButton->setEnabled(false);
                                        }
                                        if (pagePointer->m_stopLiveButton != nullptr)
                                        {
                                            pagePointer->m_stopLiveButton->setEnabled(true);
                                        }
                                        pagePointer->setStatusText(QStringLiteral("实时防火墙监控已启动。"));
                                    },
                                    Qt::QueuedConnection);
                            }
                            else
                            {
                                errorText = QStringLiteral("启动实时防火墙事件订阅失败：%1。请确认以管理员运行。")
                                    .arg(win32ErrorText(status));
                            }
                        }
                    }
                }
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            if (subscribed)
            {
                return;
            }

            // 未能装上订阅：本任务独占 engine 句柄，就地复位采集开关并关闭。
            if (engineHandle != nullptr)
            {
                closeWfpEngineShared(engineHandle, true);
            }

            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            NetworkFirewallPage* const receiver = taskState->owner;
            if (receiver == nullptr)
            {
                taskState->liveTransitionInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [taskState, errorText]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                        pagePointer = taskState->owner;
                    }
                    taskState->liveTransitionInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (pagePointer->m_startLiveButton != nullptr)
                    {
                        pagePointer->m_startLiveButton->setEnabled(true);
                    }
                    if (!errorText.isEmpty())
                    {
                        pagePointer->setStatusText(errorText);
                    }
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        taskState->liveTransitionInProgress.store(false);
        if (m_startLiveButton != nullptr)
        {
            m_startLiveButton->setEnabled(true);
        }
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::stopLiveMonitor()
{
    void* engineHandleToClose = nullptr;
    {
        // 与“启动实时”后台任务共用同一把锁：实时句柄的写入与取出串行化，
        // 不会出现订阅刚装上、句柄还没落库就被停止路径漏掉的中间态。
        const std::shared_ptr<FirewallAsyncTaskState> taskState = lookupFirewallAsyncTaskState(this);
        std::unique_lock<std::mutex> dispatchGuard;
        if (taskState)
        {
            dispatchGuard = std::unique_lock<std::mutex>(taskState->dispatchMutex);
        }

        if (m_liveSubscriptionHandle != nullptr && g_wfpApi.eventUnsubscribe != nullptr && m_liveEngineHandle != nullptr)
        {
            // 退订必须同步做完：函数返回后 WFP 才保证不再回调本页面，异步化会留下悬垂上下文。
            g_wfpApi.eventUnsubscribe(
                static_cast<HANDLE>(m_liveEngineHandle),
                static_cast<HANDLE>(m_liveSubscriptionHandle));
            m_liveSubscriptionHandle = nullptr;
        }
        engineHandleToClose = m_liveEngineHandle;
        m_liveEngineHandle = nullptr;
    }

    const bool wasRunning = m_liveRunning.exchange(false);
    if (engineHandleToClose != nullptr)
    {
        if (m_shuttingDown.load())
        {
            // 析构路径：同步关闭，确保进程退出前把全局 net event 采集开关复位。
            closeWfpEngineShared(static_cast<HANDLE>(engineHandleToClose), true);
        }
        else
        {
            // 关闭事件采集同样是一次全局引擎策略提交，交给后台线程，避免按钮点击卡住界面。
            try
            {
                std::thread([engineHandleToClose]()
                {
                    closeWfpEngineShared(static_cast<HANDLE>(engineHandleToClose), true);
                }).detach();
            }
            catch (...)
            {
                closeWfpEngineShared(static_cast<HANDLE>(engineHandleToClose), true);
            }
        }
    }

    if (m_startLiveButton != nullptr)
    {
        m_startLiveButton->setEnabled(true);
    }
    if (m_stopLiveButton != nullptr)
    {
        m_stopLiveButton->setEnabled(false);
    }
    if (wasRunning)
    {
        setStatusText(QStringLiteral("实时防火墙监控已停止。"));
    }
}

void NetworkFirewallPage::appendEventsToTable(
    const std::vector<FirewallEventEntry>& eventList,
    const bool clearBeforeAppend)
{
    if (m_eventTable == nullptr)
    {
        return;
    }

    if (ks::ui::IsTableUiCommitBlockedByContextMenu({m_eventTable}))
    {
        const QPointer<NetworkFirewallPage> safeThis(this);
        ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("firewall-event-table-append"),
            {m_eventTable},
            [safeThis, eventList, clearBeforeAppend]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->appendEventsToTable(eventList, clearBeforeAppend);
                }
            });
        return;
    }

    const std::size_t maximumDisplayedEventCount =
        static_cast<std::size_t>(kMaximumDisplayedFirewallEvents);
    const std::size_t firstEventIndex = eventList.size() > maximumDisplayedEventCount
        ? eventList.size() - maximumDisplayedEventCount
        : 0U;
    const int incomingRowCount = static_cast<int>(eventList.size() - firstEventIndex);

    m_eventTable->setUpdatesEnabled(false);
    if (clearBeforeAppend)
    {
        m_eventTable->setRowCount(0);
    }

    // 只保留能与本批新事件共同落在显示上限内的最新旧行。QTableWidget 的模型一次
    // removeRows 可批量移动剩余行，避免逐行 removeRow(0) 反复搬移整个二维表。
    const int existingRowCount = m_eventTable->rowCount();
    const int existingRowsToKeep = std::max(0, kMaximumDisplayedFirewallEvents - incomingRowCount);
    const int existingRowsToRemove = std::max(0, existingRowCount - existingRowsToKeep);
    if (existingRowsToRemove > 0)
    {
        QAbstractItemModel* const eventTableModel = m_eventTable->model();
        if (eventTableModel == nullptr || !eventTableModel->removeRows(0, existingRowsToRemove))
        {
            // QTableWidget 的内部模型正常支持批量删除；异常实现下清空可确保上限仍成立。
            m_eventTable->setRowCount(0);
        }
    }

    const int firstNewRow = m_eventTable->rowCount();
    m_eventTable->setRowCount(firstNewRow + incomingRowCount);
    for (std::size_t eventIndex = firstEventIndex; eventIndex < eventList.size(); ++eventIndex)
    {
        const FirewallEventEntry& entry = eventList[eventIndex];
        const int row = firstNewRow + static_cast<int>(eventIndex - firstEventIndex);
        const std::array<QString, ColumnCount> values = {
            safeText(entry.nameText),
            safeText(entry.actionText),
            safeText(entry.directionText),
            safeText(entry.ruleText),
            safeText(entry.descriptionText),
            safeText(entry.localAddressText),
            safeText(entry.localPortText),
            safeText(entry.localHostText),
            safeText(entry.remoteAddressText),
            safeText(entry.remotePortText),
            safeText(entry.remoteHostText),
            safeText(entry.protocolText),
            safeText(entry.timestampText)
        };

        for (int column = 0; column < ColumnCount; ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(values[static_cast<std::size_t>(column)]);
            item->setData(Qt::UserRole, entry.isDrop);
            if (column == ColumnName)
            {
                item->setData(Qt::UserRole + 1, entry.applicationPathText);
            }
            // 不写入固定前景色：DROP/Allowed 均继承表格调色板，并可随主题切换自动更新。
            // 动作类别仍通过 Action 列和“仅 DROP”筛选判断。
            m_eventTable->setItem(row, column, item);
        }
    }
    applyFilterToRowRange(firstNewRow, incomingRowCount);
    m_eventTable->setUpdatesEnabled(true);
}

void NetworkFirewallPage::applyFilterToRows()
{
    if (m_eventTable == nullptr)
    {
        return;
    }
    applyFilterToRowRange(0, m_eventTable->rowCount());
}

void NetworkFirewallPage::applyFilterToRowRange(const int firstRow, const int rowCount)
{
    if (m_eventTable == nullptr || rowCount <= 0)
    {
        return;
    }
    const QString filterText = m_searchEdit != nullptr ? m_searchEdit->text().trimmed().toLower() : QString();
    const bool dropOnly = m_dropOnlyCheck != nullptr && m_dropOnlyCheck->isChecked();

    const int firstValidRow = std::clamp(firstRow, 0, m_eventTable->rowCount());
    const int lastValidRow = std::min(m_eventTable->rowCount(), firstValidRow + rowCount);
    for (int row = firstValidRow; row < lastValidRow; ++row)
    {
        bool isDrop = false;
        QString rowText;
        for (int column = 0; column < ColumnCount; ++column)
        {
            QTableWidgetItem* item = m_eventTable->item(row, column);
            if (item == nullptr)
            {
                continue;
            }
            rowText.append(item->text()).append(QLatin1Char('\n'));
            if (column == ColumnAction)
            {
                isDrop = item->data(Qt::UserRole).toBool();
            }
        }
        const bool textMatched = filterText.isEmpty() || rowText.toLower().contains(filterText);
        const bool dropMatched = !dropOnly || isDrop;
        m_eventTable->setRowHidden(row, !(textMatched && dropMatched));
    }
}

void NetworkFirewallPage::flushLiveEventsToUi()
{
    // 菜单打开时不提前 drain：实时队列保留原始顺序，关闭后一次性消费。
    const QPointer<NetworkFirewallPage> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("firewall-live-event-flush"),
        {m_eventTable},
        [safeThis]()
        {
            if (!safeThis.isNull())
            {
                safeThis->flushLiveEventsToUi();
            }
        }))
    {
        return;
    }

    std::deque<FirewallEventEntry> queuedEvents;
    {
        std::lock_guard<std::mutex> guard(m_liveEventMutex);
        if (m_liveEventQueue.empty())
        {
            return;
        }
        queuedEvents.swap(m_liveEventQueue);
    }

    std::vector<FirewallEventEntry> eventList;
    eventList.reserve(queuedEvents.size());
    while (!queuedEvents.empty())
    {
        eventList.push_back(std::move(queuedEvents.front()));
        queuedEvents.pop_front();
    }
    appendEventsToTable(eventList, false);
    // 实时事件的主机名同样不在 WFP 回调线程里做同步反查，改成事后异步回填。
    enqueueHostnameResolution(
        m_eventTable,
        acquireFirewallAsyncTaskState(this),
        collectUnresolvedAddressList(eventList));
    setStatusText(QStringLiteral("实时事件：追加 %1 条，总计 %2 条")
        .arg(static_cast<int>(eventList.size()))
        .arg(m_eventTable != nullptr ? m_eventTable->rowCount() : 0));
}

void NetworkFirewallPage::setStatusText(const QString& statusText)
{
    if (QThread::currentThread() == thread())
    {
        if (m_statusLabel != nullptr)
        {
            m_statusLabel->setText(statusText);
        }
        return;
    }
    QPointer<NetworkFirewallPage> safeThis(this);
    QMetaObject::invokeMethod(
        this,
        [safeThis, statusText]()
        {
            if (!safeThis.isNull() && safeThis->m_statusLabel != nullptr)
            {
                safeThis->m_statusLabel->setText(statusText);
            }
        },
        Qt::QueuedConnection);
}

void NetworkFirewallPage::refreshRulesAsync(const bool forceRefresh)
{
    bool expectedValue = false;
    if (!m_refreshingRules.compare_exchange_strong(expectedValue, true))
    {
        if (forceRefresh)
        {
            setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        }
        return;
    }

    if (m_refreshRulesButton != nullptr)
    {
        m_refreshRulesButton->setEnabled(false);
    }
    setStatusText(QStringLiteral("正在枚举 Windows Firewall 规则..."));

    const std::shared_ptr<FirewallAsyncTaskState> taskState = acquireFirewallAsyncTaskState(this);
    if (!taskState)
    {
        m_refreshingRules.store(false);
        return;
    }

    try
    {
        // 枚举任务只调用文件级函数，页面析构后仍可安全跑完，因此直接 detach。
        std::thread([taskState]()
        {
            const AsyncWorkerScope workerScope(taskState);
            std::vector<FirewallRuleEntry> ruleList;
            QString errorText;
            try
            {
                ruleList = enumerateFirewallRulesSnapshotShared(&errorText);
            }
            catch (const std::exception& exception)
            {
                errorText = QStringLiteral("刷新失败：%1").arg(QString::fromUtf8(exception.what()));
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            if (taskState->cancelRequested.load())
            {
                return;
            }

            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            NetworkFirewallPage* const receiver = taskState->owner;
            if (receiver == nullptr)
            {
                return;
            }

            const bool invokeOk = QMetaObject::invokeMethod(
                receiver,
                [taskState, ruleList = std::move(ruleList), errorText]() mutable
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                        pagePointer = taskState->owner;
                    }
                    if (pagePointer == nullptr)
                    {
                        return;
                    }

                    auto applyResult = [
                        taskState,
                        ruleSnapshot = std::move(ruleList),
                        errorText]() mutable
                    {
                        NetworkFirewallPage* deferredPagePointer = nullptr;
                        {
                            std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                            deferredPagePointer = taskState->owner;
                        }
                        if (deferredPagePointer == nullptr)
                        {
                            return;
                        }

                        if (errorText.isEmpty())
                        {
                            deferredPagePointer->m_ruleEntryList = ruleSnapshot;
                            deferredPagePointer->appendRulesToTable(deferredPagePointer->m_ruleEntryList, true);
                            deferredPagePointer->setStatusText(
                                QStringLiteral("防火墙规则：%1 条，刷新：%2")
                                .arg(static_cast<int>(deferredPagePointer->m_ruleEntryList.size()))
                                .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss"))));
                        }
                        else
                        {
                            deferredPagePointer->setStatusText(errorText);
                        }

                        if (deferredPagePointer->m_refreshRulesButton != nullptr)
                        {
                            deferredPagePointer->m_refreshRulesButton->setEnabled(true);
                        }
                        deferredPagePointer->updateRuleActionButtons();
                        deferredPagePointer->updateRuleDetailEditor();
                        deferredPagePointer->m_refreshingRules.store(false);
                    };

                    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                            pagePointer,
                            QStringLiteral("firewall-rule-refresh-result-apply"),
                            {pagePointer->m_ruleTable},
                            applyResult))
                    {
                        return;
                    }
                    applyResult();
                },
                Qt::QueuedConnection);
            if (!invokeOk)
            {
                receiver->m_refreshingRules.store(false);
            }
        }).detach();
    }
    catch (...)
    {
        m_refreshingRules.store(false);
        if (m_refreshRulesButton != nullptr)
        {
            m_refreshRulesButton->setEnabled(true);
        }
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::appendRulesToTable(
    const std::vector<FirewallRuleEntry>& ruleList,
    const bool clearBeforeAppend)
{
    if (m_ruleTable == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_ruleDetailEditor);

    if (ks::ui::IsTableUiCommitBlockedByContextMenu({m_ruleTable}))
    {
        const QPointer<NetworkFirewallPage> safeThis(this);
        ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("firewall-rule-table-append"),
            {m_ruleTable},
            [safeThis, ruleList, clearBeforeAppend]()
            {
                if (!safeThis.isNull())
                {
                    safeThis->appendRulesToTable(ruleList, clearBeforeAppend);
                }
            });
        return;
    }

    if (clearBeforeAppend)
    {
        m_ruleTable->setRowCount(0);
    }

    m_ruleTable->setUpdatesEnabled(false);
    for (const FirewallRuleEntry& ruleEntry : ruleList)
    {
        const int row = m_ruleTable->rowCount();
        m_ruleTable->insertRow(row);

        const std::array<QString, RuleColumnCount> valueList = {
            safeText(ruleEntry.nameText),
            ruleEntry.enabled ? QStringLiteral("Yes") : QStringLiteral("No"),
            safeText(ruleEntry.actionText),
            safeText(ruleEntry.directionText),
            safeText(ruleEntry.profilesText),
            safeText(ruleEntry.protocolText),
            safeText(ruleEntry.localPortsText),
            safeText(ruleEntry.remotePortsText),
            safeText(ruleEntry.applicationText),
            safeText(ruleEntry.serviceText),
            safeText(ruleEntry.groupingText),
            safeText(ruleEntry.descriptionText)
        };

        for (int column = 0; column < RuleColumnCount; ++column)
        {
            QTableWidgetItem* item = new QTableWidgetItem(valueList[static_cast<std::size_t>(column)]);
            item->setData(Qt::UserRole, ruleEntry.fingerprintText);
            item->setData(Qt::UserRole + 1, ruleEntry.enabled);
            if (!ruleEntry.enabled)
            {
                item->setForeground(KswordTheme::TextSecondaryColor());
            }
            else if (column == RuleColumnAction && ruleEntry.actionValue == NET_FW_ACTION_BLOCK)
            {
                item->setForeground(KswordTheme::ErrorColor());
            }
            m_ruleTable->setItem(row, column, item);
        }
    }
    m_ruleTable->setUpdatesEnabled(true);
    applyRuleFilterToRows();
}

void NetworkFirewallPage::applyRuleFilterToRows()
{
    if (m_ruleTable == nullptr)
    {
        return;
    }

    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_ruleDetailEditor);

    const QString filterText = m_ruleSearchEdit != nullptr ? m_ruleSearchEdit->text().trimmed().toLower() : QString();
    const bool enabledOnly = m_ruleEnabledOnlyCheck != nullptr && m_ruleEnabledOnlyCheck->isChecked();

    for (int row = 0; row < m_ruleTable->rowCount(); ++row)
    {
        QString rowText;
        bool enabled = false;
        for (int column = 0; column < RuleColumnCount; ++column)
        {
            QTableWidgetItem* item = m_ruleTable->item(row, column);
            if (item == nullptr)
            {
                continue;
            }
            rowText.append(item->text()).append(QLatin1Char('\n'));
            if (column == RuleColumnEnabled)
            {
                enabled = item->data(Qt::UserRole + 1).toBool();
            }
        }

        const bool textMatched = filterText.isEmpty() || rowText.toLower().contains(filterText);
        const bool enabledMatched = !enabledOnly || enabled;
        m_ruleTable->setRowHidden(row, !(textMatched && enabledMatched));
    }
}

void NetworkFirewallPage::updateRuleActionButtons()
{
    int visibleSelectedRowCount = 0;
    if (m_ruleTable != nullptr)
    {
        const QModelIndexList rowIndexList = m_ruleTable->selectionModel() != nullptr
            ? m_ruleTable->selectionModel()->selectedRows()
            : QModelIndexList{};
        for (const QModelIndex& rowIndex : rowIndexList)
        {
            if (!m_ruleTable->isRowHidden(rowIndex.row()))
            {
                ++visibleSelectedRowCount;
            }
        }
    }

    const bool hasSingleSelection = visibleSelectedRowCount == 1;
    const bool hasSelection = visibleSelectedRowCount > 0;

    if (m_editRuleButton != nullptr)
    {
        m_editRuleButton->setEnabled(hasSingleSelection);
    }
    if (m_toggleRuleButton != nullptr)
    {
        m_toggleRuleButton->setEnabled(hasSingleSelection);
    }
    if (m_deleteRuleButton != nullptr)
    {
        m_deleteRuleButton->setEnabled(hasSelection);
    }

    if (m_toggleRuleButton != nullptr && hasSingleSelection)
    {
        FirewallRuleEntry selectedRuleEntryValue;
        if (selectedRuleEntry(&selectedRuleEntryValue))
        {
            m_toggleRuleButton->setText(selectedRuleEntryValue.enabled ? QStringLiteral("禁用") : QStringLiteral("启用"));
        }
    }
    else if (m_toggleRuleButton != nullptr)
    {
        m_toggleRuleButton->setText(QStringLiteral("启用/禁用"));
    }
}

void NetworkFirewallPage::updateRuleDetailEditor()
{
    if (m_ruleDetailEditor == nullptr)
    {
        return;
    }

    FirewallRuleEntry ruleEntry;
    if (!selectedRuleEntry(&ruleEntry))
    {
        m_ruleDetailEditor->setLocalizedText(
            QStringLiteral("请选择一条防火墙规则查看完整详情。"));
        return;
    }

    const QString detailText = QStringLiteral(
        "名称：%1\n"
        "启用：%2\n"
        "动作：%3\n"
        "方向：%4\n"
        "配置文件：%5\n"
        "协议：%6\n"
        "本地端口：%7\n"
        "远端端口：%8\n"
        "本地地址：%9\n"
        "远端地址：%10\n"
        "应用程序：%11\n"
        "服务：%12\n"
        "分组：%13\n"
        "描述：%14\n"
        "规则指纹：%15")
        .arg(safeText(ruleEntry.nameText))
        .arg(ruleEntry.enabled ? QStringLiteral("是") : QStringLiteral("否"))
        .arg(safeText(ruleEntry.actionText))
        .arg(safeText(ruleEntry.directionText))
        .arg(safeText(ruleEntry.profilesText))
        .arg(safeText(ruleEntry.protocolText))
        .arg(safeText(ruleEntry.localPortsText))
        .arg(safeText(ruleEntry.remotePortsText))
        .arg(safeText(ruleEntry.localAddressesText))
        .arg(safeText(ruleEntry.remoteAddressesText))
        .arg(safeText(ruleEntry.applicationText))
        .arg(safeText(ruleEntry.serviceText))
        .arg(safeText(ruleEntry.groupingText))
        .arg(safeText(ruleEntry.descriptionText))
        .arg(safeText(ruleEntry.fingerprintText));
    m_ruleDetailEditor->setLocalizedText(detailText);
}

void NetworkFirewallPage::showRuleContextMenu(const QPoint& localPosition)
{
    if (m_ruleTable == nullptr)
    {
        return;
    }

    // 右键落在已经选中的行上时不能重设选择：selectRow 会把多选压回单行，
    // 用户框选十条规则再右键“删除规则”，实际只删掉了鼠标底下那一条，
    // 而且删完列表一刷新，剩下九条还在——看上去像操作没生效。
    // 只有右键点在选区之外时才把选择移过去，这也是资源管理器的行为。
    const QModelIndex clickedIndex = m_ruleTable->indexAt(localPosition);
    if (clickedIndex.isValid())
    {
        QItemSelectionModel* ruleSelectionModel = m_ruleTable->selectionModel();
        // 本表是 SelectRows，整行选中时点到的那一格自然也在选区内。
        const bool clickedRowAlreadySelected =
            ruleSelectionModel != nullptr && ruleSelectionModel->isSelected(clickedIndex);
        if (!clickedRowAlreadySelected)
        {
            m_ruleTable->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            m_ruleTable->selectRow(clickedIndex.row());
        }
        else if (ruleSelectionModel != nullptr)
        {
            // 保留整片选区，只把“当前项”移到右键处，菜单里的单条动作仍有明确目标。
            ruleSelectionModel->setCurrentIndex(clickedIndex, QItemSelectionModel::NoUpdate);
        }
    }

    FirewallRuleEntry selectedEntry;
    const bool hasSingleRule = selectedRuleEntry(&selectedEntry);
    const bool hasAnySelection =
        m_ruleTable->selectionModel() != nullptr
        && !m_ruleTable->selectionModel()->selectedRows().isEmpty();

    QMenu menu(m_ruleTable);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* addAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/plus.svg")),
        QStringLiteral("新增规则"));
    QAction* editAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("编辑规则"));
    editAction->setEnabled(hasSingleRule);
    QAction* toggleAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
        hasSingleRule && selectedEntry.enabled
            ? QStringLiteral("禁用规则")
            : QStringLiteral("启用规则"));
    toggleAction->setEnabled(hasSingleRule);
    QAction* refreshAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_refresh.svg")),
        QStringLiteral("刷新规则"));
    QAction* deleteAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/log_clear.svg")),
        QStringLiteral("删除规则"));
    deleteAction->setEnabled(hasAnySelection);
    menu.addSeparator();
    QAction* copyAction = menu.addAction(
        QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
        QStringLiteral("复制当前行"));
    copyAction->setEnabled(m_ruleTable->currentRow() >= 0);

    const QAction* selectedAction = menu.exec(
        m_ruleTable->viewport()->mapToGlobal(localPosition));
    if (selectedAction == addAction)
    {
        addFirewallRule();
    }
    else if (selectedAction == editAction)
    {
        editSelectedFirewallRule();
    }
    else if (selectedAction == toggleAction)
    {
        toggleSelectedFirewallRuleEnabled();
    }
    else if (selectedAction == refreshAction)
    {
        refreshRulesAsync(true);
    }
    else if (selectedAction == deleteAction)
    {
        deleteSelectedFirewallRules();
    }
    else if (selectedAction == copyAction)
    {
        const int rowIndex = m_ruleTable->currentRow();
        QStringList rowFields;
        rowFields.reserve(m_ruleTable->columnCount());
        for (int columnIndex = 0; columnIndex < m_ruleTable->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = m_ruleTable->item(rowIndex, columnIndex);
            rowFields.push_back(item != nullptr ? item->text() : QString());
        }
        if (QGuiApplication::clipboard() != nullptr)
        {
            QGuiApplication::clipboard()->setText(rowFields.join(QLatin1Char('\t')));
        }
    }
}

bool NetworkFirewallPage::selectedRuleEntry(FirewallRuleEntry* ruleEntryOut) const
{
    if (ruleEntryOut == nullptr || m_ruleTable == nullptr || m_ruleTable->selectionModel() == nullptr)
    {
        return false;
    }

    const QModelIndexList rowIndexList = m_ruleTable->selectionModel()->selectedRows();
    if (rowIndexList.isEmpty())
    {
        return false;
    }

    const int row = rowIndexList.front().row();
    const QTableWidgetItem* nameItem = m_ruleTable->item(row, RuleColumnName);
    if (nameItem == nullptr)
    {
        return false;
    }

    const QString fingerprintText = nameItem->data(Qt::UserRole).toString();
    const auto it = std::find_if(
        m_ruleEntryList.begin(),
        m_ruleEntryList.end(),
        [&fingerprintText](const FirewallRuleEntry& ruleEntry)
        {
            return ruleEntry.fingerprintText == fingerprintText;
        });
    if (it == m_ruleEntryList.end())
    {
        return false;
    }

    *ruleEntryOut = *it;
    return true;
}

int NetworkFirewallPage::ruleNameDuplicateCount(const QString& ruleNameText) const
{
    return static_cast<int>(std::count_if(
        m_ruleEntryList.begin(),
        m_ruleEntryList.end(),
        [&ruleNameText](const FirewallRuleEntry& ruleEntry)
        {
            return ruleEntry.nameText.compare(ruleNameText, Qt::CaseSensitive) == 0;
        }));
}

// enumerateFirewallRulesSnapshot 作用：
// - 输入：错误文本输出；
// - 处理：委托给文件级的 enumerateFirewallRulesSnapshotShared；实现下沉到文件级
//         是为了让 detach 的后台任务在页面析构后也能安全跑完；
// - 返回：规则列表。
std::vector<NetworkFirewallPage::FirewallRuleEntry>
NetworkFirewallPage::enumerateFirewallRulesSnapshot(QString* errorTextOut) const
{
    return enumerateFirewallRulesSnapshotShared(errorTextOut);
}

bool NetworkFirewallPage::addFirewallRuleEntryToSystem(
    const FirewallRuleEntry& ruleEntry,
    QString* errorTextOut) const
{
    ScopedComInitialize comInitializer(COINIT_APARTMENTTHREADED);
    if (!comInitializer.succeeded())
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("初始化 COM 失败：0x%1")
                .arg(static_cast<unsigned long>(comInitializer.result()), 0, 16);
        }
        return false;
    }

    INetFwPolicy2* policyPointer = nullptr;
    HRESULT result = CoCreateInstance(
        __uuidof(NetFwPolicy2),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwPolicy2),
        reinterpret_cast<void**>(&policyPointer));
    if (FAILED(result) || policyPointer == nullptr)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("创建 INetFwPolicy2 失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }

    INetFwRules* rulesPointer = nullptr;
    result = policyPointer->get_Rules(&rulesPointer);
    if (FAILED(result) || rulesPointer == nullptr)
    {
        releaseComPointer(policyPointer);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("获取规则集合失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }

    INetFwRule* newRulePointer = nullptr;
    result = CoCreateInstance(
        __uuidof(NetFwRule),
        nullptr,
        CLSCTX_INPROC_SERVER,
        __uuidof(INetFwRule),
        reinterpret_cast<void**>(&newRulePointer));
    if (FAILED(result) || newRulePointer == nullptr)
    {
        releaseComPointer(rulesPointer);
        releaseComPointer(policyPointer);
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("创建 INetFwRule 失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }

    ScopedBstr nameText(bstrFromQString(ruleEntry.nameText));
    ScopedBstr descriptionText(bstrFromQString(ruleEntry.descriptionText));
    ScopedBstr applicationText(bstrFromQString(ruleEntry.applicationText));
    ScopedBstr serviceText(bstrFromQString(ruleEntry.serviceText));
    ScopedBstr localPortsText(bstrFromQString(ruleEntry.localPortsText));
    ScopedBstr remotePortsText(bstrFromQString(ruleEntry.remotePortsText));
    ScopedBstr localAddressesText(bstrFromQString(ruleEntry.localAddressesText));
    ScopedBstr remoteAddressesText(bstrFromQString(ruleEntry.remoteAddressesText));
    ScopedBstr groupingText(bstrFromQString(ruleEntry.groupingText));

    result = newRulePointer->put_Name(nameText.get());
    if (SUCCEEDED(result) && descriptionText.get() != nullptr)
    {
        result = newRulePointer->put_Description(descriptionText.get());
    }
    if (SUCCEEDED(result) && applicationText.get() != nullptr)
    {
        result = newRulePointer->put_ApplicationName(applicationText.get());
    }
    if (SUCCEEDED(result) && serviceText.get() != nullptr)
    {
        result = newRulePointer->put_ServiceName(serviceText.get());
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Protocol(ruleEntry.protocolValue);
    }
    if (SUCCEEDED(result) && localPortsText.get() != nullptr)
    {
        result = newRulePointer->put_LocalPorts(localPortsText.get());
    }
    if (SUCCEEDED(result) && remotePortsText.get() != nullptr)
    {
        result = newRulePointer->put_RemotePorts(remotePortsText.get());
    }
    if (SUCCEEDED(result) && localAddressesText.get() != nullptr)
    {
        result = newRulePointer->put_LocalAddresses(localAddressesText.get());
    }
    if (SUCCEEDED(result) && remoteAddressesText.get() != nullptr)
    {
        result = newRulePointer->put_RemoteAddresses(remoteAddressesText.get());
    }
    if (SUCCEEDED(result) && groupingText.get() != nullptr)
    {
        result = newRulePointer->put_Grouping(groupingText.get());
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Direction(static_cast<NET_FW_RULE_DIRECTION>(ruleEntry.directionValue));
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Profiles(ruleEntry.profilesValue);
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Action(static_cast<NET_FW_ACTION>(ruleEntry.actionValue));
    }
    if (SUCCEEDED(result))
    {
        result = newRulePointer->put_Enabled(ruleEntry.enabled ? VARIANT_TRUE : VARIANT_FALSE);
    }
    if (SUCCEEDED(result))
    {
        result = rulesPointer->Add(newRulePointer);
    }

    releaseComPointer(newRulePointer);
    releaseComPointer(rulesPointer);
    releaseComPointer(policyPointer);

    if (FAILED(result))
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = QStringLiteral("写入防火墙规则失败：0x%1")
                .arg(static_cast<unsigned long>(result), 0, 16);
        }
        return false;
    }
    return true;
}

// updateFirewallRuleEntryInSystem 作用：
// - 输入：原指纹、新规则内容、错误文本输出；
// - 处理：委托给文件级的 updateFirewallRuleInSystemShared；规则名取自指纹首段，
//         用于先走 INetFwRules::Item 直取而不是整表枚举；
// - 返回：写回成功时 true。
bool NetworkFirewallPage::updateFirewallRuleEntryInSystem(
    const QString& originalFingerprintText,
    const FirewallRuleEntry& updatedRuleEntry,
    QString* errorTextOut) const
{
    return updateFirewallRuleInSystemShared(
        originalFingerprintText.section(QStringLiteral("||"), 0, 0),
        originalFingerprintText,
        updatedRuleEntry,
        errorTextOut);
}

// setFirewallRuleEnabledInSystem 作用：
// - 输入：规则指纹、目标启用状态、错误文本输出；
// - 处理：委托给文件级的 setFirewallRuleEnabledInSystemShared；规则名取自指纹首段；
// - 返回：写回成功时 true。
bool NetworkFirewallPage::setFirewallRuleEnabledInSystem(
    const QString& fingerprintText,
    const bool enabled,
    QString* errorTextOut) const
{
    return setFirewallRuleEnabledInSystemShared(
        fingerprintText.section(QStringLiteral("||"), 0, 0),
        fingerprintText,
        enabled,
        errorTextOut);
}

// deleteFirewallRuleFromSystem 作用：
// - 输入：规则名称、错误文本输出；
// - 处理：委托给文件级的 deleteFirewallRulesFromSystemShared 删除单条；
// - 返回：删除成功时 true。
bool NetworkFirewallPage::deleteFirewallRuleFromSystem(
    const QString& ruleNameText,
    QString* errorTextOut) const
{
    int deletedCount = 0;
    return deleteFirewallRulesFromSystemShared(QStringList{ruleNameText}, &deletedCount, errorTextOut);
}

void NetworkFirewallPage::addFirewallRule()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("新增防火墙规则"));
        return;
    }
    FirewallRuleEditorDialog dialog(nullptr, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    const FirewallRuleEntry ruleEntry = dialog.ruleEntry();
    QString errorText;
    if (!addFirewallRuleEntryToSystem(ruleEntry, &errorText))
    {
        // privilegePromptHandled：权限恢复提示已展示时仅保留页面状态，不重复弹窗。
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增防火墙规则"), errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新增规则失败"), errorText);
        }
        setStatusText(errorText);
        return;
    }

    setStatusText(QStringLiteral("已新增防火墙规则：%1").arg(ruleEntry.nameText));
    refreshRulesAsync(true);
}

void NetworkFirewallPage::addBlockRuleFromEvidence(
    const QString& remoteAddress,
    const QString& remotePort,
    const QString& protocolText,
    const QString& directionText,
    const QString& sourceText,
    const std::uint32_t observedProcessId,
    const std::uint64_t expectedProcessCreationTime100ns,
    const QString& expectedProcessImagePath,
    const QString& applicationPathHint)
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("新增防火墙规则"));
        return;
    }

    const bool isInbound = directionText.compare(QStringLiteral("Inbound"), Qt::CaseInsensitive) == 0;
    const bool isOutbound = directionText.compare(QStringLiteral("Outbound"), Qt::CaseInsensitive) == 0;
    if (!isInbound && !isOutbound)
    {
        QMessageBox::warning(
            this,
            QStringLiteral("预填阻断规则"),
            QStringLiteral("审计证据未包含可信的入站或出站方向，无法安全预填防火墙规则。"));
        return;
    }
    if (remoteAddress.trimmed().isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("预填阻断规则"),
            QStringLiteral("审计证据未包含可信的远端地址，无法安全预填防火墙规则。"));
        return;
    }

    FirewallRuleEntry initialRule;
    initialRule.nameText = QStringLiteral("KSword 阻断 - %1").arg(sourceText);

    // 不能把历史 NIDS 行中的裸 PID 直接写进规则。只有当前创建时间和镜像路径都与
    // 告警产生时的快照一致，才把“程序”条件预填到 Windows Firewall 规则中。
    bool processIdentityMatches = false;
    QString currentProcessImagePath;
    if (observedProcessId != 0U &&
        expectedProcessCreationTime100ns != 0U &&
        !expectedProcessImagePath.trimmed().isEmpty())
    {
        std::uint64_t creationTimeBeforePathRead100ns = 0U;
        if (ks::process::QueryProcessCreationTimeByPid(
                observedProcessId,
                &creationTimeBeforePathRead100ns,
                nullptr) &&
            creationTimeBeforePathRead100ns == expectedProcessCreationTime100ns)
        {
            currentProcessImagePath = QString::fromStdString(
                ks::process::QueryProcessPathByPid(observedProcessId)).trimmed();
            std::uint64_t creationTimeAfterPathRead100ns = 0U;
            if (ks::process::QueryProcessCreationTimeByPid(
                    observedProcessId,
                    &creationTimeAfterPathRead100ns,
                    nullptr) &&
                creationTimeAfterPathRead100ns == expectedProcessCreationTime100ns)
            {
                processIdentityMatches =
                    !currentProcessImagePath.isEmpty() &&
                    currentProcessImagePath.compare(
                        expectedProcessImagePath.trimmed(),
                        Qt::CaseInsensitive) == 0;
            }
        }
    }

    const QString trimmedApplicationPathHint = applicationPathHint.trimmed();
    const bool hasUsableApplicationPathHint =
        trimmedApplicationPathHint.size() >= 3 &&
        trimmedApplicationPathHint.at(1) == QLatin1Char(':') &&
        (trimmedApplicationPathHint.at(2) == QLatin1Char('\\') ||
            trimmedApplicationPathHint.at(2) == QLatin1Char('/'));
    if (processIdentityMatches)
    {
        initialRule.applicationText = currentProcessImagePath;
        initialRule.descriptionText = QStringLiteral(
            "由审计证据预填；已复核 PID=%1 的当前进程身份。请在保存前核对匹配范围。")
            .arg(observedProcessId);
    }
    else if (hasUsableApplicationPathHint)
    {
        initialRule.applicationText = trimmedApplicationPathHint;
        initialRule.descriptionText = QStringLiteral(
            "由审计证据预填；已带入 WFP 事件的应用程序路径。请在保存前核对匹配范围。");
    }
    else
    {
        initialRule.descriptionText = expectedProcessCreationTime100ns != 0U || !expectedProcessImagePath.trimmed().isEmpty()
            ? QStringLiteral("由审计证据预填；关联进程已退出、不可访问或 PID 已复用，未预填程序范围。请在保存前核对匹配范围。")
            : QStringLiteral("由审计证据预填；未能核验或提取应用程序范围。请在保存前核对匹配范围。");
    }
    initialRule.remoteAddressesText = remoteAddress.trimmed();
    initialRule.remotePortsText = remotePort.trimmed();
    initialRule.actionValue = NET_FW_ACTION_BLOCK;
    initialRule.directionValue = isInbound ? NET_FW_RULE_DIR_IN : NET_FW_RULE_DIR_OUT;
    initialRule.protocolValue = protocolText.compare(QStringLiteral("UDP"), Qt::CaseInsensitive) == 0
        ? NET_FW_IP_PROTOCOL_UDP
        : protocolText.compare(QStringLiteral("TCP"), Qt::CaseInsensitive) == 0
            ? NET_FW_IP_PROTOCOL_TCP
            : NET_FW_IP_PROTOCOL_ANY;
    initialRule.enabled = true;
    initialRule.profilesValue = NET_FW_PROFILE2_ALL;

    FirewallRuleEditorDialog dialog(&initialRule, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    const FirewallRuleEntry ruleEntry = dialog.ruleEntry();
    QString errorText;
    if (!addFirewallRuleEntryToSystem(ruleEntry, &errorText))
    {
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增防火墙规则"), errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新增规则失败"), errorText);
        }
        setStatusText(errorText);
        return;
    }
    setStatusText(QStringLiteral("已新增防火墙规则：%1").arg(ruleEntry.nameText));
    refreshRulesAsync(true);
}

void NetworkFirewallPage::addUdpEndpointBlockRuleFromEvidence(
    const QString& localEndpointText,
    const std::uint32_t observedProcessId)
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("新增防火墙规则"));
        return;
    }

    const QString normalizedEndpoint = localEndpointText.trimmed();
    const int portSeparator = normalizedEndpoint.lastIndexOf(QLatin1Char(':'));
    bool portOk = false;
    const quint16 localPort = portSeparator > 0
        ? normalizedEndpoint.mid(portSeparator + 1).toUShort(&portOk, 10)
        : 0U;
    QString localAddress = portSeparator > 0
        ? normalizedEndpoint.left(portSeparator).trimmed()
        : QString();
    if (localAddress.startsWith(QLatin1Char('[')) && localAddress.endsWith(QLatin1Char(']')))
    {
        localAddress = localAddress.mid(1, localAddress.size() - 2);
    }
    if (!portOk || localPort == 0U || localAddress.isEmpty())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("预填 UDP 阻断规则"),
            QStringLiteral("所选 UDP 端点格式无效，无法安全预填防火墙规则。"));
        return;
    }

    FirewallRuleEntry initialRule;
    initialRule.nameText = QStringLiteral("KSword 阻断 - NSI UDP");
    initialRule.descriptionText = QStringLiteral(
        "由 NSI UDP 端点预填；端点不携带方向，默认出站。请在保存前核对方向和匹配范围。PID=%1")
        .arg(observedProcessId);
    // 0.0.0.0/:: 代表任意本地地址；保留为空才能表达跨所有本机接口的同一端口规则。
    if (localAddress != QStringLiteral("0.0.0.0") && localAddress != QStringLiteral("::"))
    {
        initialRule.localAddressesText = localAddress;
    }
    initialRule.localPortsText = QString::number(localPort);
    initialRule.actionValue = NET_FW_ACTION_BLOCK;
    initialRule.directionValue = NET_FW_RULE_DIR_OUT;
    initialRule.protocolValue = NET_FW_IP_PROTOCOL_UDP;
    initialRule.enabled = true;
    initialRule.profilesValue = NET_FW_PROFILE2_ALL;

    FirewallRuleEditorDialog dialog(&initialRule, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    const FirewallRuleEntry ruleEntry = dialog.ruleEntry();
    QString errorText;
    if (!addFirewallRuleEntryToSystem(ruleEntry, &errorText))
    {
        const bool privilegePromptHandled =
            ks::ui::promptForPrivilegeFailure(this, QStringLiteral("新增防火墙规则"), errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, QStringLiteral("新增规则失败"), errorText);
        }
        setStatusText(errorText);
        return;
    }
    setStatusText(QStringLiteral("已新增防火墙规则：%1").arg(ruleEntry.nameText));
    refreshRulesAsync(true);
}

void NetworkFirewallPage::editSelectedFirewallRule()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("编辑防火墙规则"));
        return;
    }
    FirewallRuleEntry originalRuleEntry;
    if (!selectedRuleEntry(&originalRuleEntry))
    {
        return;
    }

    FirewallRuleEditorDialog dialog(&originalRuleEntry, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }

    const FirewallRuleEntry updatedRuleEntry = dialog.ruleEntry();
    const std::shared_ptr<FirewallAsyncTaskState> taskState = acquireFirewallAsyncTaskState(this);
    if (!taskState)
    {
        return;
    }
    bool expectedMutation = false;
    if (!taskState->ruleMutationInProgress.compare_exchange_strong(expectedMutation, true))
    {
        setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        return;
    }

    // 定位规则和逐字段写回都是到 MPSSVC 的策略提交，整段搬到后台线程；
    // UI 侧先置灰规则动作按钮，结果回来后由 updateRuleActionButtons 复原。
    if (m_editRuleButton != nullptr)
    {
        m_editRuleButton->setEnabled(false);
    }
    if (m_toggleRuleButton != nullptr)
    {
        m_toggleRuleButton->setEnabled(false);
    }
    if (m_deleteRuleButton != nullptr)
    {
        m_deleteRuleButton->setEnabled(false);
    }

    try
    {
        std::thread([taskState,
                     originalNameText = originalRuleEntry.nameText,
                     originalFingerprintText = originalRuleEntry.fingerprintText,
                     updatedRuleEntry]()
        {
            const AsyncWorkerScope workerScope(taskState);
            QString errorText;
            bool updated = false;
            try
            {
                updated = updateFirewallRuleInSystemShared(
                    originalNameText,
                    originalFingerprintText,
                    updatedRuleEntry,
                    &errorText);
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            NetworkFirewallPage* const receiver = taskState->owner;
            if (receiver == nullptr)
            {
                taskState->ruleMutationInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [taskState, updated, errorText, ruleNameText = updatedRuleEntry.nameText]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                        pagePointer = taskState->owner;
                    }
                    taskState->ruleMutationInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (!updated)
                    {
                        // privilegePromptHandled：权限恢复提示已展示时仅保留页面状态，不重复弹窗。
                        const bool privilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(pagePointer, QStringLiteral("编辑防火墙规则"), errorText);
                        if (!privilegePromptHandled)
                        {
                            QMessageBox::warning(pagePointer, QStringLiteral("编辑规则失败"), errorText);
                        }
                        pagePointer->setStatusText(errorText);
                        pagePointer->updateRuleActionButtons();
                        return;
                    }

                    pagePointer->setStatusText(QStringLiteral("已更新防火墙规则：%1").arg(ruleNameText));
                    pagePointer->refreshRulesAsync(true);
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        taskState->ruleMutationInProgress.store(false);
        updateRuleActionButtons();
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::toggleSelectedFirewallRuleEnabled()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("切换防火墙规则状态"));
        return;
    }
    FirewallRuleEntry selectedRuleEntryValue;
    if (!selectedRuleEntry(&selectedRuleEntryValue))
    {
        return;
    }

    const std::shared_ptr<FirewallAsyncTaskState> taskState = acquireFirewallAsyncTaskState(this);
    if (!taskState)
    {
        return;
    }
    bool expectedMutation = false;
    if (!taskState->ruleMutationInProgress.compare_exchange_strong(expectedMutation, true))
    {
        setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        return;
    }

    // 启停同样要先在系统里定位规则再提交策略，与编辑路径一样搬到后台执行。
    if (m_editRuleButton != nullptr)
    {
        m_editRuleButton->setEnabled(false);
    }
    if (m_toggleRuleButton != nullptr)
    {
        m_toggleRuleButton->setEnabled(false);
    }
    if (m_deleteRuleButton != nullptr)
    {
        m_deleteRuleButton->setEnabled(false);
    }

    const bool targetEnabled = !selectedRuleEntryValue.enabled;
    try
    {
        std::thread([taskState,
                     ruleNameText = selectedRuleEntryValue.nameText,
                     fingerprintText = selectedRuleEntryValue.fingerprintText,
                     targetEnabled]()
        {
            const AsyncWorkerScope workerScope(taskState);
            QString errorText;
            bool updated = false;
            try
            {
                updated = setFirewallRuleEnabledInSystemShared(ruleNameText, fingerprintText, targetEnabled, &errorText);
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            NetworkFirewallPage* const receiver = taskState->owner;
            if (receiver == nullptr)
            {
                taskState->ruleMutationInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [taskState, updated, errorText, ruleNameText, targetEnabled]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                        pagePointer = taskState->owner;
                    }
                    taskState->ruleMutationInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (!updated)
                    {
                        // privilegePromptHandled：权限恢复提示已展示时仅保留页面状态，不重复弹窗。
                        const bool privilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(pagePointer, QStringLiteral("切换防火墙规则状态"), errorText);
                        if (!privilegePromptHandled)
                        {
                            QMessageBox::warning(pagePointer, QStringLiteral("更新规则状态失败"), errorText);
                        }
                        pagePointer->setStatusText(errorText);
                        pagePointer->updateRuleActionButtons();
                        return;
                    }

                    pagePointer->setStatusText(QStringLiteral("规则 %1：%2")
                        .arg(ruleNameText)
                        .arg(targetEnabled ? QStringLiteral("已启用") : QStringLiteral("已禁用")));
                    pagePointer->refreshRulesAsync(true);
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        taskState->ruleMutationInProgress.store(false);
        updateRuleActionButtons();
        setStatusText(QStringLiteral("刷新失败"));
    }
}

void NetworkFirewallPage::deleteSelectedFirewallRules()
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("删除防火墙规则"));
        return;
    }
    if (m_ruleTable == nullptr || m_ruleTable->selectionModel() == nullptr)
    {
        return;
    }

    QStringList ruleNameList;
    const QModelIndexList rowIndexList = m_ruleTable->selectionModel()->selectedRows();
    for (const QModelIndex& rowIndex : rowIndexList)
    {
        if (m_ruleTable->isRowHidden(rowIndex.row()))
        {
            continue;
        }
        QTableWidgetItem* nameItem = m_ruleTable->item(rowIndex.row(), RuleColumnName);
        if (nameItem != nullptr)
        {
            ruleNameList.push_back(nameItem->text());
        }
    }
    ruleNameList.removeDuplicates();
    if (ruleNameList.isEmpty())
    {
        return;
    }

    const int duplicateCount = ruleNameList.size() == 1 ? ruleNameDuplicateCount(ruleNameList.front()) : 0;
    // 规则名称是系统原始数据；只翻译由页面生成的确认句式，避免改写规则证据。
    QString warningText = ruleNameList.size() == 1
        ? ks::i18n::sourceText(QStringLiteral("确定删除规则“%1”吗？")).arg(ruleNameList.front())
        : ks::i18n::sourceText(QStringLiteral("确定删除选中的 %1 条规则吗？")).arg(ruleNameList.size());
    if (duplicateCount > 1)
    {
        warningText.append(ks::i18n::sourceText(
            QStringLiteral("\n注意：同名规则存在 %1 条，Windows Firewall 将按名称删除同名项。"))
            .arg(duplicateCount));
    }

    const QMessageBox::StandardButton button = QMessageBox::question(
        this,
        QStringLiteral("删除防火墙规则"),
        warningText,
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (button != QMessageBox::Yes)
    {
        return;
    }

    const std::shared_ptr<FirewallAsyncTaskState> taskState = acquireFirewallAsyncTaskState(this);
    if (!taskState)
    {
        return;
    }
    bool expectedMutation = false;
    if (!taskState->ruleMutationInProgress.compare_exchange_strong(expectedMutation, true))
    {
        setStatusText(QStringLiteral("防火墙规则正在刷新，请稍候。"));
        return;
    }

    // 每条 Remove 都是一次到 MPSSVC 的策略提交，选中多行时线性累加；整个循环搬到
    // 后台线程，并且只创建一次 INetFwPolicy2/INetFwRules 复用给所有 Remove。
    if (m_editRuleButton != nullptr)
    {
        m_editRuleButton->setEnabled(false);
    }
    if (m_toggleRuleButton != nullptr)
    {
        m_toggleRuleButton->setEnabled(false);
    }
    if (m_deleteRuleButton != nullptr)
    {
        m_deleteRuleButton->setEnabled(false);
    }

    try
    {
        std::thread([taskState, ruleNameList]()
        {
            const AsyncWorkerScope workerScope(taskState);
            QString errorText;
            int deletedCount = 0;
            bool deleted = false;
            try
            {
                deleted = deleteFirewallRulesFromSystemShared(ruleNameList, &deletedCount, &errorText);
            }
            catch (...)
            {
                errorText = QStringLiteral("刷新失败");
            }

            std::lock_guard<std::mutex> dispatchGuard(taskState->dispatchMutex);
            NetworkFirewallPage* const receiver = taskState->owner;
            if (receiver == nullptr)
            {
                taskState->ruleMutationInProgress.store(false);
                return;
            }
            QMetaObject::invokeMethod(
                receiver,
                [taskState, deleted, deletedCount, errorText]()
                {
                    NetworkFirewallPage* pagePointer = nullptr;
                    {
                        std::lock_guard<std::mutex> stateGuard(taskState->dispatchMutex);
                        pagePointer = taskState->owner;
                    }
                    taskState->ruleMutationInProgress.store(false);
                    if (pagePointer == nullptr)
                    {
                        return;
                    }
                    if (!deleted)
                    {
                        // privilegePromptHandled：权限恢复提示已展示时仅保留页面状态，不重复弹窗。
                        const bool privilegePromptHandled =
                            ks::ui::promptForPrivilegeFailure(pagePointer, QStringLiteral("删除防火墙规则"), errorText);
                        if (!privilegePromptHandled)
                        {
                            QMessageBox::warning(pagePointer, QStringLiteral("删除规则失败"), errorText);
                        }
                        pagePointer->setStatusText(errorText);
                    }
                    else
                    {
                        pagePointer->setStatusText(QStringLiteral("已删除 %1 条防火墙规则。").arg(deletedCount));
                    }
                    pagePointer->refreshRulesAsync(true);
                },
                Qt::QueuedConnection);
        }).detach();
    }
    catch (...)
    {
        taskState->ruleMutationInProgress.store(false);
        updateRuleActionButtons();
        setStatusText(QStringLiteral("刷新失败"));
    }
}

// ensureWfpApiLoaded 作用：
// - 输入：错误文本输出；
// - 处理：委托给文件级的 ensureWfpApiLoadedShared，模块句柄同样收在文件级，
//         这样后台任务不必依赖页面成员；
// - 返回：关键导出齐全时 true。
bool NetworkFirewallPage::ensureWfpApiLoaded(QString* errorTextOut)
{
    return ensureWfpApiLoadedShared(errorTextOut);
}

// openWfpEngine 作用：
// - 输入：是否启用事件收集、engine 句柄输出、错误文本输出；
// - 处理：委托给文件级的 openWfpEngineShared；
// - 返回：成功时 true。
bool NetworkFirewallPage::openWfpEngine(
    const bool enableCollection,
    void** engineHandleOut,
    QString* errorTextOut)
{
    if (engineHandleOut == nullptr)
    {
        return false;
    }
    HANDLE engineHandle = nullptr;
    const bool opened = openWfpEngineShared(enableCollection, &engineHandle, errorTextOut);
    *engineHandleOut = engineHandle;
    return opened;
}

// closeWfpEngine 作用：
// - 输入：engine 句柄、是否关闭事件收集；
// - 处理：委托给文件级的 closeWfpEngineShared；
// - 无返回值。
void NetworkFirewallPage::closeWfpEngine(void* engineHandle, const bool disableCollection)
{
    closeWfpEngineShared(static_cast<HANDLE>(engineHandle), disableCollection);
}

// enumerateHistoryWithEngine 作用：
// - 输入：已打开 BFE engine、错误文本输出；
// - 处理：委托给文件级的 enumerateHistoryWithEngineShared；本入口不带取消位，
//         后台历史刷新走的是带取消位的文件级版本；
// - 返回：事件列表。
std::vector<NetworkFirewallPage::FirewallEventEntry>
NetworkFirewallPage::enumerateHistoryWithEngine(void* engineHandle, QString* errorTextOut)
{
    return enumerateHistoryWithEngineShared(static_cast<HANDLE>(engineHandle), nullptr, errorTextOut);
}

// convertWfpEventToEntry 作用：
// - 输入：FWPM_NET_EVENT 指针、engine 句柄；
// - 处理：委托给文件级的 convertWfpEventToEntryShared；主机名只查缓存，
//         WFP 回调线程不会再被同步反向 DNS 拖住；
// - 返回：可显示事件。
NetworkFirewallPage::FirewallEventEntry NetworkFirewallPage::convertWfpEventToEntry(
    const void* wfpEventPointer,
    void* engineHandle)
{
    return convertWfpEventToEntryShared(wfpEventPointer, static_cast<HANDLE>(engineHandle));
}

void NetworkFirewallPage::enqueueLiveEvent(const void* wfpEventPointer)
{
    if (!m_liveRunning.load() || wfpEventPointer == nullptr)
    {
        return;
    }
    FirewallEventEntry entry = convertWfpEventToEntry(wfpEventPointer, m_liveEngineHandle);
    std::lock_guard<std::mutex> guard(m_liveEventMutex);
    while (m_liveEventQueue.size() >= kMaximumQueuedLiveEvents)
    {
        m_liveEventQueue.pop_front();
    }
    m_liveEventQueue.push_back(std::move(entry));
}

void __stdcall NetworkFirewallPage::liveEventCallback(void* context, const void* eventPointer)
{
    NetworkFirewallPage* pagePointer = static_cast<NetworkFirewallPage*>(context);
    if (pagePointer != nullptr)
    {
        pagePointer->enqueueLiveEvent(eventPointer);
    }
}
