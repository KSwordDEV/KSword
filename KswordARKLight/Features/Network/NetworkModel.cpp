#include "NetworkModel.h"

#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../Core/Win32Lean.h"

#include <commctrl.h>
#include <iphlpapi.h>

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace Ksword::Features::Network {
namespace {
using ks::r3::network::BuildAfdRows;
using ks::r3::network::BuildNsiRows;

// Column 创建一个 Network 表格列。
// 输入：列标题、宽度和 ListView 对齐方式。
// 处理：只打包 UI 元数据，不访问 R0。
// 返回：NetworkAuditColumn 值对象。
NetworkAuditColumn Column(const wchar_t* title, const int width, const int format = LVCFMT_LEFT) {
    return NetworkAuditColumn{ width, format, title };
}

// RowVec 创建一行动态文本。
// 输入：已经格式化好的单元格数组。
// 处理：移动到 NetworkAuditRow，避免 const wchar_t* 生命周期问题。
// 返回：NetworkAuditRow 值对象。
NetworkAuditRow RowVec(std::vector<std::wstring> cells) {
    NetworkAuditRow row;
    row.cells = std::move(cells);
    return row;
}

// Utf8ToWideLossy 把 ArkDriverClient 的窄字符诊断转换为宽字符。
// 输入：通常是 ASCII/UTF-8 风格的 io.message。
// 处理：逐字节提升，诊断文本只用于表格展示。
// 返回：std::wstring；空输入返回空字符串。
std::wstring Utf8ToWideLossy(const std::string& text) {
    std::wstring wide;
    wide.reserve(text.size());
    for (const char ch : text) {
        wide.push_back(static_cast<unsigned char>(ch));
    }
    return wide;
}

// HexText 格式化 64 位整数。
// 输入：诊断地址、标志或计数。
// 处理：统一使用 0x + 大写十六进制。
// 返回：供 UI 表格直接显示的字符串。
std::wstring HexText(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}

// Ipv4Text 将 IP Helper 返回的 IPv4 DWORD 转成点分十进制。
// 输入：addr 是 MIB_* 行中的 IPv4 地址字段。
// 处理：按 Windows IP Helper 公开表的字节顺序逐字节展开。
// 返回：可显示的 IPv4 文本。


// NetworkPortText 将网络字节序端口转成本机可读十进制。
// 输入：portValue 来自 MIB_TCPROW_OWNER_PID / MIB_UDPROW_OWNER_PID。
// 处理：只取低 16 位并交换高低字节，不依赖 ws2_32 链接库。
// 返回：端口号文本。


// Win32StatusText 格式化 Win32/IP Helper 错误码。
// 输入：apiName 是失败 API 名，status 是返回码。
// 处理：保留十进制和十六进制，便于现场定位权限/平台差异。
// 返回：可放入表格说明列的文本。


// IpHelperApi 保存动态解析的 IP Helper 只读入口。
// 输入：LoadIpHelperApi 填充字段。
// 处理：NetworkModel 通过函数指针调用，避免新增 .vcxproj 链接库依赖。
// 返回：结构体本身无行为。


// LoadIpHelperApi 动态加载 iphlpapi.dll。
// 输入：errorText 接收失败原因，可为空。
// 处理：解析 AFD/NSI 页面需要的 documented 只读 API。
// 返回：成功时 api 可调用，失败时页面显示 unavailable。


// ProtocolStatusText 返回通用协议状态文本。
// 输入：ok/unsupported 两个 ArkDriverClient 结果状态。
// 处理：区分在线、旧驱动不支持和传输失败。
// 返回：中文状态文本。
std::wstring ProtocolStatusText(const bool ok, const bool unsupported) {
    if (ok) {
        return L"OK";
    }
    return unsupported ? L"驱动不支持" : L"驱动不可用/权限不足";
}

// AddressText 格式化网络地址。
// 输入：地址族和共享协议 16 字节地址。
// 处理：IPv4 使用点分十进制，IPv6 使用压缩前十六进制组。
// 返回：可读地址；未知地址族返回 <unknown>。
std::wstring AddressText(const unsigned long family, const unsigned char bytes[16]) {
    if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4) {
        std::wostringstream stream;
        stream << static_cast<unsigned int>(bytes[0]) << L'.'
               << static_cast<unsigned int>(bytes[1]) << L'.'
               << static_cast<unsigned int>(bytes[2]) << L'.'
               << static_cast<unsigned int>(bytes[3]);
        return stream.str();
    }
    if (family == KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6) {
        std::wostringstream stream;
        stream << std::hex << std::nouppercase;
        for (int index = 0; index < 16; index += 2) {
            if (index != 0) {
                stream << L":";
            }
            const unsigned int word = (static_cast<unsigned int>(bytes[index]) << 8U) |
                static_cast<unsigned int>(bytes[index + 1]);
            stream << word;
        }
        return stream.str();
    }
    return L"<unknown>";
}

// FixedWide 读取共享协议定长宽字符字段。
// 输入：字段指针和最大字符数。
// 处理：扫描到 NUL 或边界，避免旧驱动未写 NUL 时越界。
// 返回：安全字符串，空字段返回 <empty>。
std::wstring FixedWide(const wchar_t* text, const std::size_t maxChars) {
    if (text == nullptr || maxChars == 0U) {
        return L"<empty>";
    }
    std::size_t length = 0U;
    while (length < maxChars && text[length] != L'\0') {
        ++length;
    }
    if (length == 0U) {
        return L"<empty>";
    }
    return std::wstring(text, text + length);
}

// AddEndpointRows 追加 TCP/UDP endpoint 查询结果。
// 输入：协议名、ArkDriverClient endpoint 查询结果和输出 rows。
// 处理：先写 IOCTL 状态行，再逐条写 endpoint 诊断行。
// 返回：无返回值。
void AddEndpointRows(const std::wstring& protocol, const ksword::ark::NetworkEndpointAuditResult& query, std::vector<NetworkAuditRow>& rows) {
    rows.push_back(RowVec({
        protocol,
        ProtocolStatusText(query.io.ok, query.unsupported),
        L"ArkDriverClient",
        L"IOCTL endpoint",
        L"total=" + std::to_wstring(query.totalCount) + L" returned=" + std::to_wstring(query.returnedCount),
        Utf8ToWideLossy(query.io.message),
        L"只读 endpoint 快照，不断开连接。"
    }));
    for (const KSWORD_ARK_NETWORK_ENDPOINT_ROW& entry : query.entries) {
        rows.push_back(RowVec({
            protocol,
            std::to_wstring(entry.state),
            std::to_wstring(entry.owningPid),
            AddressText(entry.addressFamily, entry.localAddress) + L":" + std::to_wstring(entry.localPort),
            AddressText(entry.addressFamily, entry.remoteAddress) + L":" + std::to_wstring(entry.remotePort),
            HexText(entry.endpointObject),
            HexText(entry.flags),
            L"source=" + HexText(entry.sourceFlags) + L" transport=" + HexText(entry.transportObject)
        }));
    }
}

// BuildTcpUdpRows 查询 TCP/UDP R0 endpoint cross-view。
// 输入：无；处理：调用 ArkDriverClient wrapper，不裸 DeviceIoControl。
// 返回：可直接显示的表格行。
std::vector<NetworkAuditRow> BuildTcpUdpRows() {
    std::vector<NetworkAuditRow> rows;
    const ksword::ark::DriverClient client;
    AddEndpointRows(L"TCP", client.queryNetworkTcpEndpoints(), rows);
    AddEndpointRows(L"UDP", client.queryNetworkUdpEndpoints(), rows);
    rows.push_back(RowVec({ L"安全边界", L"只读", L"UI", L"无断连/无阻断", L"-", L"不调用 set-rules，不修改 WFP 规则。", L"展示 R0 endpoint 审计结果，可与 R3 公开 API 视图对照。" }));
    return rows;
}

// BuildWfpRows 查询 WFP provider/filter/callout inventory。
// 输入：无；处理：调用 ArkDriverClient::queryNetworkWfpInventory。
// 返回：WFP 表格行。
std::vector<NetworkAuditRow> BuildWfpRows() {
    std::vector<NetworkAuditRow> rows;
    const ksword::ark::DriverClient client;
    const ksword::ark::NetworkWfpInventoryResult query = client.queryNetworkWfpInventory();
    rows.push_back(RowVec({
        L"IOCTL_KSWORD_ARK_NETWORK_QUERY_WFP_INVENTORY",
        ProtocolStatusText(query.io.ok, query.unsupported),
        L"ArkDriverClient",
        L"total=" + std::to_wstring(query.totalCount) + L" returned=" + std::to_wstring(query.returnedCount),
        Utf8ToWideLossy(query.io.message),
        L"不删除 callout/filter，不关闭 engine。"
    }));
    for (const KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW& entry : query.entries) {
        rows.push_back(RowVec({
            std::to_wstring(entry.objectKind),
            L"layer=" + std::to_wstring(entry.layerId) + L" callout=" + std::to_wstring(entry.calloutId),
            HexText(entry.objectAddress),
            HexText(entry.classifyAddress),
            FixedWide(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS),
            L"flags=" + HexText(entry.flags) + L" field=" + HexText(entry.fieldMask)
        }));
    }
    return rows;
}

// BuildNdisRows 查询 NDIS 链路审计。
// 输入：无；处理：调用 ArkDriverClient::queryNetworkNdisChain。
// 返回：NDIS 表格行。
std::vector<NetworkAuditRow> BuildNdisRows() {
    std::vector<NetworkAuditRow> rows;
    const ksword::ark::DriverClient client;
    const ksword::ark::NetworkNdisChainResult query = client.queryNetworkNdisChain();
    rows.push_back(RowVec({
        L"IOCTL_KSWORD_ARK_NETWORK_QUERY_NDIS_CHAIN",
        ProtocolStatusText(query.io.ok, query.unsupported),
        L"ArkDriverClient",
        L"total=" + std::to_wstring(query.totalCount) + L" returned=" + std::to_wstring(query.returnedCount),
        Utf8ToWideLossy(query.io.message),
        L"不 pause/restart miniport，不 detach filter。"
    }));
    for (const KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW& entry : query.entries) {
        rows.push_back(RowVec({
            std::to_wstring(entry.objectKind),
            FixedWide(entry.componentName, KSWORD_ARK_NETWORK_NAME_CHARS),
            L"if=" + std::to_wstring(entry.ifIndex) + L" order=" + std::to_wstring(entry.filterOrder),
            HexText(entry.objectAddress),
            HexText(entry.parentObjectAddress),
            FixedWide(entry.ownerModule, KSWORD_ARK_NETWORK_NAME_CHARS),
            L"driver=" + HexText(entry.driverObject) + L" flags=" + HexText(entry.flags)
        }));
    }
    return rows;
}

// AppendTcpAfdProjectionRows 追加 TCP owner table 的 AFD-facing 投影。
// 输入：已解析 IP Helper API、输出行数组和最大返回行数。
// 处理：只调用 documented GetExtendedTcpTable，不读 AFD 私有结构。
// 返回：无返回值；失败时写入诊断行。


// AppendUdpAfdProjectionRows 追加 UDP owner table 的 AFD-facing 投影。
// 输入：已解析 IP Helper API、输出行数组和最大返回行数。
// 处理：只调用 documented GetExtendedUdpTable，不读取私有内核对象。
// 返回：无返回值；失败时写入诊断行。


// BuildAfdRows 构建 AFD endpoint 页面。
// 输入：无；处理：使用 documented TCP/UDP owner table 作为 AFD socket 投影。
// 返回：实际 R3 证据行；缺 API 时返回 unavailable 而非 unsupported 占位。


// BuildNsiRows 构建 NSI 摘要页面。
// 输入：无；处理：使用 IP Helper 的接口、地址、路由表作为 NSI-facing 证据。
// 返回：实际摘要行；缺 API 时返回 unavailable 而非 unsupported 占位。


} // namespace

NetworkAuditModel::NetworkAuditModel() {
    // Network I/O and R0 queries are scheduled by NetworkView after its
    // controls are visible, so opening or switching a dock never blocks.
}

void NetworkAuditModel::refresh() {
    // refresh 的输入为空；处理是重建所有页面行数据；返回为空。
    // 所有 R0 调用均通过 ArkDriverClient wrapper 完成。
    pages_ = BuildNetworkAuditPages();
}

void NetworkAuditModel::replacePages(std::vector<NetworkAuditPage> pages) {
    pages_ = std::move(pages);
}

const std::vector<NetworkAuditPage>& NetworkAuditModel::pages() const noexcept {
    return pages_;
}

const NetworkAuditPage* NetworkAuditModel::pageAt(const int index) const noexcept {
    if (index < 0 || index >= static_cast<int>(pages_.size())) {
        return nullptr;
    }
    return &pages_[static_cast<std::size_t>(index)];
}

std::vector<NetworkAuditPage> BuildNetworkAuditPages() {
    // BuildNetworkAuditPages 负责 ARKLight Network 的真实 R0 wrapper 接入。
    // 输入为空；处理时调用只读审计 wrapper；返回页面描述数组。
    std::vector<NetworkAuditPage> pages;

    pages.push_back({
        NetworkAuditPageId::TcpUdpCrossView,
        L"TCP/UDP R0 cross-view",
        L"合并 tcpip/netio/runtime 只读 endpoint 快照；驱动未加载时显示 Win32 错误。",
        {
            Column(L"协议", 80),
            Column(L"状态", 120),
            Column(L"PID/来源", 120),
            Column(L"Local", 180),
            Column(L"Remote", 180),
            Column(L"EndpointObject", 170),
            Column(L"Flags", 120),
            Column(L"说明", 420),
        },
        BuildTcpUdpRows()
    });

    pages.push_back({
        NetworkAuditPageId::AfdEndpoint,
        L"AFD endpoint",
        L"使用 documented TCP/UDP owner table 生成 AFD-facing 端点投影；不猜 AFD 私有结构。",
        {
            Column(L"项目", 160),
            Column(L"状态", 180),
            Column(L"来源", 160),
            Column(L"协议/接口", 220),
            Column(L"说明", 420),
            Column(L"安全边界", 360),
        },
        BuildAfdRows()
    });

    pages.push_back({
        NetworkAuditPageId::WfpInventory,
        L"WFP callout/filter/provider",
        L"展示 WFP provider、sublayer、filter、callout 以及 classify/notify/flowDelete owner module。",
        {
            Column(L"ObjectKind/IOCTL", 180),
            Column(L"状态/Layer", 160),
            Column(L"Object", 170),
            Column(L"Classify", 170),
            Column(L"Owner", 220),
            Column(L"Flags/说明", 460),
        },
        BuildWfpRows()
    });

    pages.push_back({
        NetworkAuditPageId::NdisChain,
        L"NDIS protocol/filter",
        L"展示 miniport、filter、protocol、binding 的只读链路表，并保留对象地址诊断。",
        {
            Column(L"Kind/IOCTL", 160),
            Column(L"Component", 240),
            Column(L"If/Order", 140),
            Column(L"Object", 170),
            Column(L"Parent", 170),
            Column(L"Owner", 220),
            Column(L"Flags/Driver", 420),
        },
        BuildNdisRows()
    });

    pages.push_back({
        NetworkAuditPageId::NsiSummary,
        L"NSI 表",
        L"使用 IP Helper 接口/地址/路由表生成 NSI-facing 只读摘要；不猜 NSI 私有结构。",
        {
            Column(L"项目", 160),
            Column(L"状态", 180),
            Column(L"来源", 160),
            Column(L"协议/接口", 220),
            Column(L"说明", 420),
            Column(L"安全边界", 360),
        },
        BuildNsiRows()
    });

    return pages;
}

} // namespace Ksword::Features::Network
