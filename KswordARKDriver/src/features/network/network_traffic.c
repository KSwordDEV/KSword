/*++

Module Name:

    network_traffic.c

Abstract:

    WFP IPv4/IPv6 IP-packet ring shared with loopback transport inspection.

Environment:

    Kernel-mode WFP callout driver

--*/

// 中文说明：普通 IP 层与独立回环模块使用同一内部 NDIS/WFP 合约。
#include "network_traffic.h"

// 中文说明：解析器只接受 TCP/UDP，并显式遍历这些 IPv6 扩展头。
#define KSWORD_ARK_IP_PROTOCOL_HOPOPTS 0U
#define KSWORD_ARK_IP_PROTOCOL_TCP 6U
#define KSWORD_ARK_IP_PROTOCOL_UDP 17U
#define KSWORD_ARK_IP_PROTOCOL_ROUTING 43U
#define KSWORD_ARK_IP_PROTOCOL_FRAGMENT 44U
#define KSWORD_ARK_IP_PROTOCOL_ESP 50U
#define KSWORD_ARK_IP_PROTOCOL_AH 51U
#define KSWORD_ARK_IP_PROTOCOL_NONE 59U
#define KSWORD_ARK_IP_PROTOCOL_DSTOPTS 60U
#define KSWORD_ARK_IP_PROTOCOL_MOBILITY 135U
#define KSWORD_ARK_IPV6_MAX_EXTENSION_HEADERS 8UL

// {D2B28BC6-9E08-4D07-9F7B-2BA821D8AA51}
// 中文说明：逐包 inspection filter 与既有 ALE filter 共用同一个动态子层。
static const GUID KSWORD_ARK_WFP_SUBLAYER =
{ 0xd2b28bc6, 0x9e08, 0x4d07, { 0x9f, 0x7b, 0x2b, 0xa8, 0x21, 0xd8, 0xaa, 0x51 } };

// {8FA3AACD-4A2E-414F-9BAF-9C23F6C39904}
static const GUID KSWORD_ARK_WFP_TRAFFIC_INBOUND_V4_CALLOUT =
{ 0x8fa3aacd, 0x4a2e, 0x414f, { 0x9b, 0xaf, 0x9c, 0x23, 0xf6, 0xc3, 0x99, 0x04 } };

// {6A89CEFE-06B8-4D17-B747-2D66218CD028}
static const GUID KSWORD_ARK_WFP_TRAFFIC_OUTBOUND_V4_CALLOUT =
{ 0x6a89cefe, 0x06b8, 0x4d17, { 0xb7, 0x47, 0x2d, 0x66, 0x21, 0x8c, 0xd0, 0x28 } };

// {A4DE4D86-8FB4-428B-8CA9-470BA5F37FA4}
static const GUID KSWORD_ARK_WFP_TRAFFIC_INBOUND_V6_CALLOUT =
{ 0xa4de4d86, 0x8fb4, 0x428b, { 0x8c, 0xa9, 0x47, 0x0b, 0xa5, 0xf3, 0x7f, 0xa4 } };

// {DB89C588-C0BA-44E0-B7E2-C9B0148DC0BB}
static const GUID KSWORD_ARK_WFP_TRAFFIC_OUTBOUND_V6_CALLOUT =
{ 0xdb89c588, 0xc0ba, 0x44e0, { 0xb7, 0xe2, 0xc9, 0xb0, 0x14, 0x8d, 0xc0, 0xbb } };

// Built-in layer GUIDs are copied from the WDK ABI so this driver does not
// depend on the GUID-definition import library for data symbols.
static const GUID KSWORD_ARK_FWPM_LAYER_INBOUND_IPPACKET_V4 =
{ 0xc86fd1bf, 0x21cd, 0x497e, { 0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58 } };
static const GUID KSWORD_ARK_FWPM_LAYER_OUTBOUND_IPPACKET_V4 =
{ 0x1e5c9fae, 0x8a84, 0x4135, { 0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd } };
static const GUID KSWORD_ARK_FWPM_LAYER_INBOUND_IPPACKET_V6 =
{ 0xf52032cb, 0x991c, 0x46e7, { 0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca } };
static const GUID KSWORD_ARK_FWPM_LAYER_OUTBOUND_IPPACKET_V6 =
{ 0xa3b3ab6b, 0x3564, 0x488c, { 0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63 } };

// 中文说明：单个逐包层的 runtime/engine 注册参数。
typedef struct _KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_CONFIG
{
    const GUID* CalloutKey; // CalloutKey：本驱动稳定 callout GUID。
    const GUID* LayerKey; // LayerKey：BFE 内置 IP packet layer GUID。
    PCWSTR CalloutName; // CalloutName：BFE 诊断名称。
    PCWSTR FilterName; // FilterName：BFE filter 诊断名称。
} KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_CONFIG;

// 中文说明：数组索引与原有四个 IPPACKET runtime ID 槽位一致。
static const KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_CONFIG g_KswordArkTrafficCalloutConfigs[
    KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT] =
{
    {
        &KSWORD_ARK_WFP_TRAFFIC_INBOUND_V4_CALLOUT,
        &KSWORD_ARK_FWPM_LAYER_INBOUND_IPPACKET_V4,
        L"KswordARK inbound IPv4 packet callout",
        L"KswordARK inbound IPv4 packet filter"
    },
    {
        &KSWORD_ARK_WFP_TRAFFIC_OUTBOUND_V4_CALLOUT,
        &KSWORD_ARK_FWPM_LAYER_OUTBOUND_IPPACKET_V4,
        L"KswordARK outbound IPv4 packet callout",
        L"KswordARK outbound IPv4 packet filter"
    },
    {
        &KSWORD_ARK_WFP_TRAFFIC_INBOUND_V6_CALLOUT,
        &KSWORD_ARK_FWPM_LAYER_INBOUND_IPPACKET_V6,
        L"KswordARK inbound IPv6 packet callout",
        L"KswordARK inbound IPv6 packet filter"
    },
    {
        &KSWORD_ARK_WFP_TRAFFIC_OUTBOUND_V6_CALLOUT,
        &KSWORD_ARK_FWPM_LAYER_OUTBOUND_IPPACKET_V6,
        L"KswordARK outbound IPv6 packet callout",
        L"KswordARK outbound IPv6 packet filter"
    }
};

C_ASSERT(RTL_NUMBER_OF(g_KswordArkTrafficCalloutConfigs) == KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT);
C_ASSERT(sizeof(((KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW*)0)->capturedBytes) ==
    KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES);

static USHORT
KswordARKNetworkTrafficReadNetworkU16(
    _In_reads_(2) const UCHAR* Bytes
    )
/*++

Routine Description:

    从未对齐网络字节序缓冲读取 16 位整数。

--*/
{
    // 中文说明：调用方已验证两字节边界，逐字节读取避免未对齐访问。
    return (USHORT)(((USHORT)Bytes[0] << 8U) | (USHORT)Bytes[1]);
}

static VOID
KswordARKNetworkTrafficAssignEndpoints(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row,
    _In_reads_(AddressLength) const UCHAR* SourceAddress,
    _In_reads_(AddressLength) const UCHAR* DestinationAddress,
    _In_ ULONG AddressLength,
    _In_ USHORT SourcePort,
    _In_ USHORT DestinationPort
    )
/*++

Routine Description:

    按报文方向把 IP 源/目的端点规范化为本地/远端端点。

--*/
{
    // 中文说明：防御无效行或地址宽度，禁止写越 16 字节协议字段。
    if (Row == NULL || SourceAddress == NULL || DestinationAddress == NULL ||
        (AddressLength != 4UL && AddressLength != 16UL)) {
        // 中文说明：无效输入不修改半成品行。
        return;
    }

    // 中文说明：出站报文的源端点属于本机。
    if (Row->direction == KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND) {
        // 中文说明：复制本地源地址。
        RtlCopyMemory(Row->localAddress, SourceAddress, AddressLength);
        // 中文说明：复制远端目的地址。
        RtlCopyMemory(Row->remoteAddress, DestinationAddress, AddressLength);
        // 中文说明：源端口规范化为本地端口。
        Row->localPort = SourcePort;
        // 中文说明：目的端口规范化为远端端口。
        Row->remotePort = DestinationPort;
    }
    else {
        // 中文说明：入站报文的目的端点属于本机。
        RtlCopyMemory(Row->localAddress, DestinationAddress, AddressLength);
        // 中文说明：源端点是远端。
        RtlCopyMemory(Row->remoteAddress, SourceAddress, AddressLength);
        // 中文说明：目的端口规范化为本地端口。
        Row->localPort = DestinationPort;
        // 中文说明：源端口规范化为远端端口。
        Row->remotePort = SourcePort;
    }
}

BOOLEAN
KswordARKNetworkTrafficParseTransport(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row,
    _In_ ULONG TransportOffset,
    _In_ ULONG PacketLength,
    _In_ UCHAR Protocol,
    _In_reads_(AddressLength) const UCHAR* SourceAddress,
    _In_reads_(AddressLength) const UCHAR* DestinationAddress,
    _In_ ULONG AddressLength
    )
/*++

Routine Description:

    解析 TCP/UDP 首部、payload 边界与方向规范化端点。

--*/
{
    // 中文说明：固定捕获前缀作为边界，绝不按 IP 声明长度越界读取。
    const ULONG capturedLength = Row != NULL ? Row->capturedLength : 0UL;
    // 中文说明：保存传输层源端口。
    USHORT sourcePort = 0U;
    // 中文说明：保存传输层目的端口。
    USHORT destinationPort = 0U;
    // 中文说明：保存 L4 payload 相对真实捕获层起点的偏移。
    ULONG payloadOffset = 0UL;

    // 中文说明：所有协议解析都至少需要源/目的端口四字节。
    if (Row == NULL || SourceAddress == NULL || DestinationAddress == NULL ||
        TransportOffset > capturedLength || capturedLength - TransportOffset < 4UL ||
        TransportOffset > PacketLength) {
        // 中文说明：截断到传输头之前的报文不能形成可靠 UI 行。
        return FALSE;
    }

    // 中文说明：读取网络序源端口。
    sourcePort = KswordARKNetworkTrafficReadNetworkU16(&Row->capturedBytes[TransportOffset]);
    // 中文说明：读取网络序目的端口。
    destinationPort = KswordARKNetworkTrafficReadNetworkU16(&Row->capturedBytes[TransportOffset + 2UL]);

    // 中文说明：TCP 至少需要固定 20 字节头并读取 data offset。
    if (Protocol == KSWORD_ARK_IP_PROTOCOL_TCP) {
        // 中文说明：保存 TCP data offset 推导的头长度。
        ULONG tcpHeaderLength = 0UL;

        // 中文说明：固定头不完整时拒绝，不伪造 payload 边界。
        if (capturedLength - TransportOffset < 20UL) {
            // 中文说明：等待后续完整报文，当前行不进入 ring。
            return FALSE;
        }
        // 中文说明：高四位是 32 位字数，转换为字节数。
        tcpHeaderLength = (ULONG)(Row->capturedBytes[TransportOffset + 12UL] >> 4U) * 4UL;
        // 中文说明：data offset 不得小于固定头，也不得越过完整/已捕获报文。
        if (tcpHeaderLength < 20UL ||
            tcpHeaderLength > PacketLength - TransportOffset ||
            tcpHeaderLength > capturedLength - TransportOffset) {
            // 中文说明：畸形或截断 TCP 首部不进入可信协议行。
            return FALSE;
        }
        // 中文说明：payload 紧随 TCP 可变长首部。
        payloadOffset = TransportOffset + tcpHeaderLength;
    }
    // 中文说明：UDP 固定头为 8 字节，并带独立 datagram 长度。
    else if (Protocol == KSWORD_ARK_IP_PROTOCOL_UDP) {
        // 中文说明：保存 UDP length 字段。
        ULONG udpLength = 0UL;
        // 中文说明：保存受 IP 总长约束的有效 UDP 长度。
        ULONG boundedUdpLength = 0UL;

        // 中文说明：UDP 固定头必须完整可读。
        if (capturedLength - TransportOffset < 8UL || PacketLength - TransportOffset < 8UL) {
            // 中文说明：不完整 UDP 首部无法形成端点记录。
            return FALSE;
        }
        // 中文说明：读取网络序 UDP datagram 长度。
        udpLength = (ULONG)KswordARKNetworkTrafficReadNetworkU16(
            &Row->capturedBytes[TransportOffset + 4UL]);
        // 中文说明：IPv4/普通 IPv6 UDP 长度至少包含 8 字节首部；0 仅保留给 IPv6 jumbogram。
        if (udpLength != 0UL && udpLength < 8UL) {
            // 中文说明：畸形 UDP length 不进入 ring。
            return FALSE;
        }
        // 中文说明：jumbogram 的 0 长度退回 IP 层可见长度，其余取 IP/UDP 较小值。
        boundedUdpLength = udpLength == 0UL ?
            (PacketLength - TransportOffset) :
            min(udpLength, PacketLength - TransportOffset);
        // 中文说明：有效 UDP 范围必须仍覆盖固定头。
        if (boundedUdpLength < 8UL) {
            // 中文说明：边界不一致时拒绝。
            return FALSE;
        }
        // 中文说明：payload 紧随 UDP 固定头。
        payloadOffset = TransportOffset + 8UL;
        // 中文说明：UDP payload 受独立 length 字段限制，而不是盲用全部 IP 尾部。
        Row->payloadLength = boundedUdpLength - 8UL;
    }
    else {
        // 中文说明：流量监控当前只消费 TCP/UDP，避免把 ICMP 等强制转换成 UI 枚举。
        return FALSE;
    }

    // 中文说明：写入稳定 IP 协议号。
    Row->protocol = (ULONG)Protocol;
    // 中文说明：保存 payload 偏移。
    Row->payloadOffset = payloadOffset;
    // 中文说明：TCP payload 使用捕获层总长减去首部；UDP 已按自身 length 设置。
    if (Protocol == KSWORD_ARK_IP_PROTOCOL_TCP) {
        // 中文说明：前置检查保证 payloadOffset 不大于 PacketLength。
        Row->payloadLength = PacketLength - payloadOffset;
    }
    // 中文说明：按方向写入本地/远端地址与端口。
    KswordARKNetworkTrafficAssignEndpoints(
        Row,
        SourceAddress,
        DestinationAddress,
        AddressLength,
        sourcePort,
        destinationPort);
    // 中文说明：TCP/UDP 行已完整形成。
    return TRUE;
}

static BOOLEAN
KswordARKNetworkTrafficParseIpv4(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row
    )
/*++

Routine Description:

    解析完整 IPv4 包头、分片状态和 TCP/UDP 边界。

--*/
{
    // 中文说明：保存 IPv4 IHL 字节数。
    ULONG ipHeaderLength = 0UL;
    // 中文说明：保存 IPv4 total length。
    ULONG packetLength = 0UL;
    // 中文说明：保存 fragment flags/offset 字段。
    USHORT fragmentField = 0U;
    // 中文说明：保存低 13 位分片偏移。
    USHORT fragmentOffset = 0U;
    // 中文说明：保存 IP protocol 字段。
    UCHAR protocol = 0U;

    // 中文说明：IPv4 固定头至少 20 字节。
    if (Row == NULL || Row->capturedLength < 20UL ||
        (Row->capturedBytes[0] >> 4U) != 4U) {
        // 中文说明：版本或固定头不合法时拒绝。
        return FALSE;
    }
    // 中文说明：IHL 单位为 32 位字，转换为字节。
    ipHeaderLength = (ULONG)(Row->capturedBytes[0] & 0x0FU) * 4UL;
    // 中文说明：IHL 必须覆盖固定头并位于捕获前缀内。
    if (ipHeaderLength < 20UL || ipHeaderLength > Row->capturedLength) {
        // 中文说明：选项区域不完整时无法定位 L4 首部。
        return FALSE;
    }
    // 中文说明：读取 IPv4 total length。
    packetLength = (ULONG)KswordARKNetworkTrafficReadNetworkU16(&Row->capturedBytes[2]);
    // 中文说明：总长不得小于 IP 首部。
    if (packetLength < ipHeaderLength) {
        // 中文说明：畸形总长拒绝。
        return FALSE;
    }
    // 中文说明：裁掉 NET_BUFFER 可能附带的 IP 包后尾部字节。
    if (Row->capturedLength > packetLength) {
        // 中文说明：协议只向 R3 暴露当前 IP 包范围。
        Row->capturedLength = packetLength;
    }

    // 中文说明：解析 IPv4 分片字段。
    fragmentField = KswordARKNetworkTrafficReadNetworkU16(&Row->capturedBytes[6]);
    // 中文说明：低 13 位是 8 字节单位的 fragment offset。
    fragmentOffset = (USHORT)(fragmentField & 0x1FFFU);
    // 中文说明：非首片没有 TCP/UDP 首部，不能形成可靠五元组。
    if (fragmentOffset != 0U) {
        // 中文说明：后续片由首片代表，不写入错误端口。
        return FALSE;
    }
    // 中文说明：MF 位表示首片仍属于分片数据报。
    if ((fragmentField & 0x2000U) != 0U) {
        // 中文说明：把首片语义上报给 R3。
        Row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_FRAGMENTED;
    }

    // 中文说明：写入 IPv4 协议属性。
    Row->addressFamily = KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV4;
    // 中文说明：IPv4 与 IPv6 标志互斥。
    Row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV4;
    // 中文说明：保存完整 IP total length。
    Row->totalPacketLength = packetLength;
    // 中文说明：读取 IP protocol。
    protocol = Row->capturedBytes[9];
    // 中文说明：解析 TCP/UDP 首部并规范化源/目的端点。
    return KswordARKNetworkTrafficParseTransport(
        Row,
        ipHeaderLength,
        packetLength,
        protocol,
        &Row->capturedBytes[12],
        &Row->capturedBytes[16],
        4UL);
}

static BOOLEAN
KswordARKNetworkTrafficParseIpv6(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row
    )
/*++

Routine Description:

    解析 IPv6 基础头和有界扩展头链，定位 TCP/UDP 首部。

--*/
{
    // 中文说明：IPv6 基础头固定为 40 字节。
    const ULONG baseHeaderLength = 40UL;
    // 中文说明：保存 IPv6 payload length。
    ULONG ipv6PayloadLength = 0UL;
    // 中文说明：保存完整包长。
    ULONG packetLength = 0UL;
    // 中文说明：保存当前 next-header 值。
    UCHAR nextHeader = 0U;
    // 中文说明：保存当前扩展头/L4 偏移。
    ULONG transportOffset = baseHeaderLength;
    // 中文说明：限制扩展头遍历次数，防止畸形链耗尽 classify 时间。
    ULONG extensionCount = 0UL;

    // 中文说明：IPv6 基础头必须完整且版本为 6。
    if (Row == NULL || Row->capturedLength < baseHeaderLength ||
        (Row->capturedBytes[0] >> 4U) != 6U) {
        // 中文说明：基础头不合法时拒绝。
        return FALSE;
    }
    // 中文说明：读取网络序 payload length。
    ipv6PayloadLength = (ULONG)KswordARKNetworkTrafficReadNetworkU16(&Row->capturedBytes[4]);
    // 中文说明：普通 IPv6 包总长为固定头加 payload；0 长度 jumbogram 退回 NET_BUFFER 可见长度。
    packetLength = ipv6PayloadLength == 0UL ?
        Row->totalPacketLength :
        baseHeaderLength + ipv6PayloadLength;
    // 中文说明：固定头必须位于声明的完整包内。
    if (packetLength < baseHeaderLength) {
        // 中文说明：整数/协议边界异常时拒绝。
        return FALSE;
    }
    // 中文说明：裁掉 NET_BUFFER 可能附带的 IP 包后尾部字节。
    if (Row->capturedLength > packetLength) {
        // 中文说明：只保留当前 IPv6 包范围。
        Row->capturedLength = packetLength;
    }
    // 中文说明：基础头第 6 字节是 next header。
    nextHeader = Row->capturedBytes[6];

    // 中文说明：逐个跳过允许的扩展头，直到 TCP/UDP 或明确不支持的协议。
    while (nextHeader != KSWORD_ARK_IP_PROTOCOL_TCP &&
        nextHeader != KSWORD_ARK_IP_PROTOCOL_UDP) {
        // 中文说明：限制扩展头数量和读取边界。
        if (extensionCount >= KSWORD_ARK_IPV6_MAX_EXTENSION_HEADERS ||
            transportOffset >= Row->capturedLength ||
            transportOffset >= packetLength) {
            // 中文说明：过深或截断扩展链不进入 ring。
            return FALSE;
        }

        // 中文说明：Hop-by-Hop、Routing、Destination、Mobility 使用 8 字节单位长度。
        if (nextHeader == KSWORD_ARK_IP_PROTOCOL_HOPOPTS ||
            nextHeader == KSWORD_ARK_IP_PROTOCOL_ROUTING ||
            nextHeader == KSWORD_ARK_IP_PROTOCOL_DSTOPTS ||
            nextHeader == KSWORD_ARK_IP_PROTOCOL_MOBILITY) {
            // 中文说明：扩展头前两字节必须可读。
            ULONG extensionLength = 0UL;
            // 中文说明：检查 next-header 与 hdr-ext-len 字节。
            if (Row->capturedLength - transportOffset < 2UL ||
                packetLength - transportOffset < 2UL) {
                // 中文说明：截断扩展头拒绝。
                return FALSE;
            }
            // 中文说明：保存下一个协议号。
            nextHeader = Row->capturedBytes[transportOffset];
            // 中文说明：Hdr Ext Len 不含首个 8 字节块。
            extensionLength = ((ULONG)Row->capturedBytes[transportOffset + 1UL] + 1UL) * 8UL;
            // 中文说明：扩展头必须完整落在声明包长与捕获前缀内。
            if (extensionLength < 8UL ||
                extensionLength > packetLength - transportOffset ||
                extensionLength > Row->capturedLength - transportOffset) {
                // 中文说明：畸形扩展长度拒绝。
                return FALSE;
            }
            // 中文说明：推进到下一个头。
            transportOffset += extensionLength;
        }
        // 中文说明：Fragment header 固定 8 字节。
        else if (nextHeader == KSWORD_ARK_IP_PROTOCOL_FRAGMENT) {
            // 中文说明：保存 fragment offset/flags 字段。
            USHORT fragmentField = 0U;
            // 中文说明：完整 fragment header 必须可读。
            if (Row->capturedLength - transportOffset < 8UL ||
                packetLength - transportOffset < 8UL) {
                // 中文说明：截断 fragment header 拒绝。
                return FALSE;
            }
            // 中文说明：读取下一个协议号。
            nextHeader = Row->capturedBytes[transportOffset];
            // 中文说明：读取网络序 fragment offset/flags。
            fragmentField = KswordARKNetworkTrafficReadNetworkU16(
                &Row->capturedBytes[transportOffset + 2UL]);
            // 中文说明：高 13 位包含 offset，非首片没有传输层端口。
            if ((fragmentField & 0xFFF8U) != 0U) {
                // 中文说明：后续片不伪造端口。
                return FALSE;
            }
            // 中文说明：所有带 fragment header 的首片均显式标记。
            Row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_FRAGMENTED;
            // 中文说明：跳过固定 fragment header。
            transportOffset += 8UL;
        }
        // 中文说明：Authentication Header 使用 32 位单位长度，另加两个单位。
        else if (nextHeader == KSWORD_ARK_IP_PROTOCOL_AH) {
            // 中文说明：保存 AH 总长度。
            ULONG authenticationHeaderLength = 0UL;
            // 中文说明：AH 前两字节必须可读。
            if (Row->capturedLength - transportOffset < 2UL ||
                packetLength - transportOffset < 2UL) {
                // 中文说明：截断 AH 拒绝。
                return FALSE;
            }
            // 中文说明：保存 AH 后续协议。
            nextHeader = Row->capturedBytes[transportOffset];
            // 中文说明：Payload Len 以 32 位为单位并减去 2。
            authenticationHeaderLength =
                ((ULONG)Row->capturedBytes[transportOffset + 1UL] + 2UL) * 4UL;
            // 中文说明：AH 必须至少 8 字节且完整位于边界内。
            if (authenticationHeaderLength < 8UL ||
                authenticationHeaderLength > packetLength - transportOffset ||
                authenticationHeaderLength > Row->capturedLength - transportOffset) {
                // 中文说明：畸形 AH 长度拒绝。
                return FALSE;
            }
            // 中文说明：推进到下一个头。
            transportOffset += authenticationHeaderLength;
        }
        else {
            // 中文说明：ESP、No Next Header 和其它未知协议无法安全定位明文 TCP/UDP。
            // 中文说明：未知协议不进入当前 TCP/UDP 监控模型。
            return FALSE;
        }
        // 中文说明：记录一次扩展头推进。
        extensionCount += 1UL;
    }

    // 中文说明：写入 IPv6 协议属性。
    Row->addressFamily = KSWORD_ARK_NETWORK_ADDRESS_FAMILY_IPV6;
    // 中文说明：IPv4 与 IPv6 标志互斥。
    Row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6;
    // 中文说明：保存完整 IPv6 包长。
    Row->totalPacketLength = packetLength;
    // 中文说明：基础头中的源/目的地址分别位于偏移 8/24。
    return KswordARKNetworkTrafficParseTransport(
        Row,
        transportOffset,
        packetLength,
        nextHeader,
        &Row->capturedBytes[8],
        &Row->capturedBytes[24],
        16UL);
}

BOOLEAN
KswordARKNetworkTrafficParsePacket(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row
    )
/*++

Routine Description:

    按 IP version 分派解析，并统一设置截断标志。

--*/
{
    // 中文说明：保存具体 IPv4/IPv6 解析结果。
    BOOLEAN parsed = FALSE;
    // 中文说明：至少需要一个版本字节。
    if (Row == NULL || Row->capturedLength == 0UL) {
        // 中文说明：空包不进入 ring。
        return FALSE;
    }

    // 中文说明：高四位选择 IPv4/IPv6 解析器。
    if ((Row->capturedBytes[0] >> 4U) == 4U) {
        // 中文说明：解析 IPv4。
        parsed = KswordARKNetworkTrafficParseIpv4(Row);
    }
    else if ((Row->capturedBytes[0] >> 4U) == 6U) {
        // 中文说明：解析 IPv6。
        parsed = KswordARKNetworkTrafficParseIpv6(Row);
    }
    // 中文说明：解析失败时不公开半成品。
    if (!parsed) {
        // 中文说明：调用方放弃当前 NET_BUFFER。
        return FALSE;
    }
    // 中文说明：捕获前缀短于完整 IP 包时显式标记截断。
    if (Row->capturedLength < Row->totalPacketLength) {
        // 中文说明：R3 详情页可据此提示只保存前缀。
        Row->flags |= KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_TRUNCATED;
    }
    // 中文说明：完整 TCP/UDP 行可写入 ring。
    return TRUE;
}

VOID
KswordARKNetworkTrafficRecordPacket(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* PacketRow,
    _In_ ULONG CaptureGeneration
    )
/*++

Routine Description:

    把已解析逐包记录写入固定非分页 ring。

--*/
{
    // 中文说明：获取静态网络运行时。
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    // 中文说明：保存获取逐包自旋锁前 IRQL。
    KIRQL oldIrql = PASSIVE_LEVEL;
    // 中文说明：保存本次写入槽位。
    ULONG writeIndex = 0UL;

    // 中文说明：空运行时或行不写入。
    if (runtime == NULL || PacketRow == NULL) {
        // 中文说明：不影响 WFP 放行判定。
        return;
    }
    if (InterlockedCompareExchange(
            &runtime->TrafficCaptureEnabled,
            0L,
            0L) == 0L ||
        (ULONG)InterlockedCompareExchange(
            &runtime->TrafficCaptureGeneration,
            0L,
            0L) != CaptureGeneration) {
        // 中文说明：UI 已停止后不再进入逐包 ring 临界区。
        return;
    }

    // 中文说明：自旋锁覆盖序号、覆盖计数和完整单槽复制。
    KeAcquireSpinLock(&runtime->TrafficLock, &oldIrql);
    if (InterlockedCompareExchange(
            &runtime->TrafficCaptureEnabled,
            0L,
            0L) == 0L ||
        (ULONG)InterlockedCompareExchange(
            &runtime->TrafficCaptureGeneration,
            0L,
            0L) != CaptureGeneration) {
        // 中文说明：与禁用控制串行化，阻止已越过外层检查的迟到写入。
        KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);
        return;
    }
    // 中文说明：读取下一写入槽位。
    writeIndex = runtime->TrafficWriteIndex;
    // 中文说明：在锁内分配严格递增序号。
    PacketRow->sequence = runtime->NextTrafficSequence;
    // 中文说明：推进下一序号。
    runtime->NextTrafficSequence += 1ULL;
    // 中文说明：完整固定行复制，读侧不会看到半写入数据。
    RtlCopyMemory(&runtime->TrafficRing[writeIndex], PacketRow, sizeof(*PacketRow));
    // 中文说明：推进并环绕写指针。
    runtime->TrafficWriteIndex =
        (writeIndex + 1UL) % KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
    // 中文说明：ring 未满时增加有效行数。
    if (runtime->TrafficCount < KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY) {
        // 中文说明：占用一个此前未使用的槽位。
        runtime->TrafficCount += 1UL;
    }
    else {
        // 中文说明：ring 已满时覆盖最旧包并累计丢弃数。
        runtime->DroppedTrafficCount += 1ULL;
    }
    // 中文说明：逐包 ring 元数据与行都完成后恢复 IRQL。
    KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);
}

static VOID
KswordARKNetworkTrafficCaptureNetBuffer(
    _Inout_ NET_BUFFER* NetBuffer,
    _In_ BOOLEAN Inbound,
    _In_ ULONG Direction,
    _In_ ULONG IpHeaderSize,
    _In_ ULONG ProcessId,
    _In_ ULONG CaptureGeneration
    )
/*++

Routine Description:

    从单个 NET_BUFFER 无分配复制有限报文前缀，恢复数据偏移后解析并写入 ring。

--*/
{
    // 中文说明：在栈上构造完整固定行，进入自旋锁前完成全部解析。
    KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW packetRow = { 0 };
    // 中文说明：保存 NET_BUFFER 当前可见长度。
    ULONG dataLength = 0UL;
    // 中文说明：保存本次最多复制的前缀长度。
    ULONG captureLength = 0UL;
    // 中文说明：保存 NdisGetDataBuffer 返回的连续地址。
    UCHAR* contiguousBytes = NULL;
    // 中文说明：记录入站路径是否成功回退到 IP 首部。
    BOOLEAN retreated = FALSE;
    // 中文说明：保存系统时间。
    LARGE_INTEGER systemTime = { 0 };

    // 中文说明：空 NET_BUFFER 不可访问。
    if (NetBuffer == NULL) {
        // 中文说明：不影响其它报文。
        return;
    }

    // 中文说明：入站 IPPACKET 数据偏移位于传输头，必须暂时回退 ipHeaderSize。
    if (Inbound) {
        // 中文说明：metadata 必须给出非零 IP 首部长度。
        if (IpHeaderSize == 0UL || NET_BUFFER_DATA_OFFSET(NetBuffer) < IpHeaderSize) {
            // 中文说明：无法恢复完整 IP 包时不伪造逐包数据。
            return;
        }
        // 中文说明：不分配新 MDL，只回退到同一 NET_BUFFER 中仍保留的 IP 头。
        if (NdisRetreatNetBufferDataStart(NetBuffer, IpHeaderSize, 0UL, NULL) != NDIS_STATUS_SUCCESS) {
            // 中文说明：回退失败时保持原数据偏移并放弃当前包。
            return;
        }
        // 中文说明：后续所有退出路径必须恢复此偏移。
        retreated = TRUE;
    }

    // 中文说明：读取回退后的完整 IP 包可见长度。
    dataLength = NET_BUFFER_DATA_LENGTH(NetBuffer);
    // 中文说明：空包无需调用 NdisGetDataBuffer。
    if (dataLength != 0UL) {
        // 中文说明：固定前缀上限避免 classify 热路径大额复制和非分页内存膨胀。
        captureLength = min(dataLength, KSWORD_ARK_NETWORK_TRAFFIC_MAX_CAPTURE_BYTES);
        // 中文说明：若 MDL 不连续，NDIS 将复制到 packetRow 固定缓冲。
        contiguousBytes = (UCHAR*)NdisGetDataBuffer(
            NetBuffer,
            captureLength,
            packetRow.capturedBytes,
            1UL,
            0UL);
        // 中文说明：连续指针可能直接指向原 MDL，此时显式复制到稳定行。
        if (contiguousBytes != NULL && contiguousBytes != packetRow.capturedBytes) {
            // 中文说明：复制长度已受固定数组上限约束。
            RtlCopyMemory(packetRow.capturedBytes, contiguousBytes, captureLength);
        }
    }

    // 中文说明：任何解析前先恢复入站 NET_BUFFER 数据偏移，避免影响 WFP 后续 callout。
    if (retreated) {
        // 中文说明：回退量与上面的 IpHeaderSize 完全一致。
        NdisAdvanceNetBufferDataStart(NetBuffer, IpHeaderSize, FALSE, NULL);
    }

    // 中文说明：NDIS 无法形成连续前缀时放弃当前包。
    if (contiguousBytes == NULL || captureLength == 0UL) {
        // 中文说明：偏移已恢复，可安全返回。
        return;
    }

    // 中文说明：写入稳定逐包 ABI 基础字段。
    packetRow.version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
    // 中文说明：写入当前固定行大小。
    packetRow.size = sizeof(packetRow);
    // 中文说明：序号在 ring 自旋锁内分配。
    packetRow.sequence = 0ULL;
    // 中文说明：读取 1601 UTC 起算的 100ns 系统时间。
    KeQuerySystemTime(&systemTime);
    // 中文说明：保存捕获时间。
    packetRow.timestamp100ns = (ULONG64)systemTime.QuadPart;
    // 中文说明：保存 IPPACKET 层方向。
    packetRow.direction = Direction;
    // 中文说明：保存 metadata PID，缺失时为 0。
    packetRow.processId = ProcessId;
    // 中文说明：保存实际复制的前缀长度，解析器可能按 IP total length 再收窄。
    packetRow.capturedLength = captureLength;
    // 中文说明：先保存 NET_BUFFER 可见总长，IPv6 jumbogram 的 payload length 为 0 时使用该值。
    packetRow.totalPacketLength = dataLength;

    // 中文说明：只把可完整解析的 TCP/UDP IPv4/IPv6 包写入 ring。
    if (KswordARKNetworkTrafficParsePacket(&packetRow)) {
        // 中文说明：解析成功后进入短自旋锁写入。
        KswordARKNetworkTrafficRecordPacket(
            &packetRow,
            CaptureGeneration);
    }
}

static VOID NTAPI
KswordARKNetworkTrafficClassifyFn(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ VOID* LayerData,
    _In_opt_ const FWPS_FILTER0* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut
    )
/*++

Routine Description:

    观察型 IPPACKET classify：逐个复制 NET_BUFFER 前缀，并始终返回 CONTINUE。

--*/
{
    // 中文说明：保存层推导出的流量方向。
    ULONG direction = 0UL;
    // 中文说明：标记入站层需要回退数据偏移。
    BOOLEAN inbound = FALSE;
    // 中文说明：保存 metadata IP 首部长度。
    ULONG ipHeaderSize = 0UL;
    // 中文说明：保存 metadata PID，通常由 R3 连接表补全。
    ULONG processId = 0UL;
    // 中文说明：遍历可能链接的 NBL。
    NET_BUFFER_LIST* netBufferList = NULL;
    // 中文说明：逐包数据面由 R3 显式启停，filter 本身保持常驻。
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    // 中文说明：把启用代次带到最终写入点，拒绝跨越停/启边界的迟到包。
    ULONG captureGeneration = 0UL;
    ULONG confirmedGeneration = 0UL;

    // 中文说明：inspection callout 不读取 filter/flow context，也不修改或吸收包。
    UNREFERENCED_PARAMETER(Filter);
    // 中文说明：本实现不关联 flow context。
    UNREFERENCED_PARAMETER(FlowContext);

    // 中文说明：拥有 ACTION_WRITE 时显式返回非终止 CONTINUE，保留其它 WFP 策略。
    if (ClassifyOut != NULL &&
        (ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) != 0U) {
        // 中文说明：观察型 callout 永远不 permit/block/absorb。
        ClassifyOut->actionType = FWP_ACTION_CONTINUE;
    }

    if (runtime == NULL) {
        // 中文说明：停止态只保持 WFP 放行语义，不解析也不复制 NET_BUFFER。
        return;
    }
    do {
        captureGeneration = (ULONG)InterlockedCompareExchange(
            &runtime->TrafficCaptureGeneration,
            0L,
            0L);
        if (InterlockedCompareExchange(
                &runtime->TrafficCaptureEnabled,
                0L,
                0L) == 0L) {
            // 中文说明：停止态只保持 WFP 放行语义，不解析也不复制 NET_BUFFER。
            return;
        }
        confirmedGeneration = (ULONG)InterlockedCompareExchange(
            &runtime->TrafficCaptureGeneration,
            0L,
            0L);
    } while (captureGeneration != confirmedGeneration);

    // 中文说明：层字段和包数据都必须存在。
    if (InFixedValues == NULL || LayerData == NULL) {
        // 中文说明：缺失数据时仅保持 CONTINUE。
        return;
    }

    // 中文说明：入站 IPv4/IPv6 层均需要从传输头回退到 IP 头。
    if (InFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V4 ||
        InFixedValues->layerId == FWPS_LAYER_INBOUND_IPPACKET_V6) {
        // 中文说明：规范化为入站方向。
        direction = KSWORD_ARK_NETWORK_DIRECTION_INBOUND;
        // 中文说明：启用回退路径。
        inbound = TRUE;
    }
    // 中文说明：出站 IPv4/IPv6 层数据偏移已经位于 IP 头。
    else if (InFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V4 ||
        InFixedValues->layerId == FWPS_LAYER_OUTBOUND_IPPACKET_V6) {
        // 中文说明：规范化为出站方向。
        direction = KSWORD_ARK_NETWORK_DIRECTION_OUTBOUND;
    }
    else {
        // 中文说明：未知层不尝试解释 LayerData。
        return;
    }

    // 中文说明：入站必须读取 WFP 提供的实际 IPv4 options/IPv6 header chain 前缀长度。
    if (inbound && InMetaValues != NULL &&
        (InMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_IP_HEADER_SIZE) != 0U) {
        // 中文说明：保存回退量。
        ipHeaderSize = InMetaValues->ipHeaderSize;
    }
    // 中文说明：在可用时读取 PID，否则 R3 通过端点表解析。
    processId = KswordARKNetworkTrafficReadProcessId(InMetaValues);

    // 中文说明：LayerData 在 IPPACKET 层是 NET_BUFFER_LIST。
    netBufferList = (NET_BUFFER_LIST*)LayerData;
    // 中文说明：遍历 NBL 链，确保 coalesced/批量路径中的每个包都被观察。
    while (netBufferList != NULL) {
        // 中文说明：遍历当前 NBL 的所有 NET_BUFFER。
        NET_BUFFER* netBuffer = NET_BUFFER_LIST_FIRST_NB(netBufferList);
        // 中文说明：逐个 NET_BUFFER 复制与解析。
        while (netBuffer != NULL) {
            // 中文说明：本函数不分配内存，也不长时间持锁。
            KswordARKNetworkTrafficCaptureNetBuffer(
                netBuffer,
                inbound,
                direction,
                ipHeaderSize,
                processId,
                captureGeneration);
            // 中文说明：推进当前 NBL 内的 NET_BUFFER 链。
            netBuffer = NET_BUFFER_NEXT_NB(netBuffer);
        }
        // 中文说明：推进 NBL 链。
        netBufferList = NET_BUFFER_LIST_NEXT_NBL(netBufferList);
    }
}

static NTSTATUS NTAPI
KswordARKNetworkTrafficNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER0* Filter
    )
/*++

Routine Description:

    接受逐包 callout filter 生命周期通知；当前不维护额外上下文。

--*/
{
    // 中文说明：不区分 add/delete 通知。
    UNREFERENCED_PARAMETER(NotifyType);
    // 中文说明：filter key 不参与逐包 ring。
    UNREFERENCED_PARAMETER(FilterKey);
    // 中文说明：filter 对象不保存自定义 context。
    UNREFERENCED_PARAMETER(Filter);
    // 中文说明：接受通知。
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKNetworkTrafficRegisterRuntimeCallouts(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    注册四个普通 IPPACKET callout，再接入四个回环 TRANSPORT callout。

--*/
{
    // 中文说明：保存 callout 配置索引。
    ULONG index = 0UL;
    // 中文说明：保存当前注册状态。
    NTSTATUS status = STATUS_SUCCESS;

    // 中文说明：runtime 与设备对象必须有效。
    if (Runtime == NULL || Runtime->DeviceObject == NULL) {
        // 中文说明：FwpsCalloutRegister0 需要设备对象。
        return STATUS_INVALID_PARAMETER;
    }

    // 中文说明：按稳定数组顺序注册，失败时统一回滚已注册项。
    for (index = 0UL; index < KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT; ++index) {
        // 中文说明：构造官方 FWPS_CALLOUT0。
        FWPS_CALLOUT0 callout = { 0 };
        // 中文说明：写入当前稳定 GUID。
        callout.calloutKey = *g_KswordArkTrafficCalloutConfigs[index].CalloutKey;
        // 中文说明：四层复用同一观察 classify，并通过 layerId 区分方向。
        callout.classifyFn = KswordARKNetworkTrafficClassifyFn;
        // 中文说明：使用无状态 notify。
        callout.notifyFn = KswordARKNetworkTrafficNotifyFn;
        // 中文说明：不关联 flow context，因此不需要 flowDeleteFn。
        callout.flowDeleteFn = NULL;
        // 中文说明：注册 runtime callout 并保存 ID。
        status = FwpsCalloutRegister0(
            Runtime->DeviceObject,
            &callout,
            &Runtime->TrafficCalloutIds[index]);
        // 中文说明：失败时终止后续注册。
        if (!NT_SUCCESS(status)) {
            // 中文说明：保存逐包能力失败状态。
            Runtime->TrafficCaptureStatus = status;
            // 中文说明：注销此前成功的 runtime callout。
            KswordARKNetworkTrafficUnregisterRuntimeCallouts(Runtime);
            // 中文说明：向父注册事务返回精确错误。
            return status;
        }
    }

    // 中文说明：回环 transport 单独持有四个槽位，不扩大原 runtime 结构。
    status = KswordARKNetworkTrafficLoopbackRegister(Runtime);
    // 中文说明：回环注册失败与普通层共用原子回滚路径。
    if (!NT_SUCCESS(status)) {
        // 中文说明：保留真实失败状态，不能把部分来源报告为就绪。
        Runtime->TrafficCaptureStatus = status;
        // 中文说明：统一清理普通层及回环层的部分注册。
        KswordARKNetworkTrafficUnregisterRuntimeCallouts(Runtime);
        // 中文说明：让父注册终止。
        return status;
    }
    // 中文说明：runtime callout 阶段成功，engine/filter 阶段稍后继续。
    Runtime->TrafficCaptureStatus = STATUS_SUCCESS;
    // 中文说明：返回成功。
    return STATUS_SUCCESS;
}

NTSTATUS
KswordARKNetworkTrafficAddEngineObjects(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    在父级 BFE 事务内添加普通 IP 与回环 TRANSPORT 的观察对象。

--*/
{
    // 中文说明：保存配置索引。
    ULONG index = 0UL;
    // 中文说明：保存当前 BFE 操作状态。
    NTSTATUS status = STATUS_SUCCESS;

    // 中文说明：父级必须已打开动态 engine。
    if (Runtime == NULL || Runtime->EngineHandle == NULL) {
        // 中文说明：无 engine 无法添加管理对象。
        return STATUS_INVALID_PARAMETER;
    }

    // 中文说明：先添加全部 callout 对象，供后续 filter 引用。
    for (index = 0UL; index < KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT; ++index) {
        // 中文说明：构造官方 FWPM_CALLOUT0。
        FWPM_CALLOUT0 callout = { 0 };
        // 中文说明：设置稳定 callout GUID。
        callout.calloutKey = *g_KswordArkTrafficCalloutConfigs[index].CalloutKey;
        // 中文说明：设置诊断名称。
        callout.displayData.name = (PWSTR)g_KswordArkTrafficCalloutConfigs[index].CalloutName;
        // 中文说明：绑定内置 IPv4/IPv6 IPPACKET layer。
        callout.applicableLayer = *g_KswordArkTrafficCalloutConfigs[index].LayerKey;
        // 中文说明：在父事务内添加 callout。
        status = FwpmCalloutAdd0(Runtime->EngineHandle, &callout, NULL, NULL);
        // 中文说明：失败时让父事务统一 abort。
        if (!NT_SUCCESS(status)) {
            // 中文说明：保存精确失败状态。
            Runtime->TrafficCaptureStatus = status;
            // 中文说明：返回失败。
            return status;
        }
    }

    // 中文说明：普通 IPPACKET 排除 loopback，与回环 TRANSPORT 分工不重叠。
    for (index = 0UL; index < KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT; ++index) {
        // 中文说明：构造官方 FWPM_FILTER0。
        FWPM_FILTER0 filter = { 0 };
        // 中文说明：显式排除回环，即使某条路径也经过 IPPACKET 也只记录一次。
        FWPM_FILTER_CONDITION0 condition = { 0 };
        // 中文说明：绑定当前 IPPACKET layer。
        filter.layerKey = *g_KswordArkTrafficCalloutConfigs[index].LayerKey;
        // 中文说明：设置诊断名称。
        filter.displayData.name = (PWSTR)g_KswordArkTrafficCalloutConfigs[index].FilterName;
        // 中文说明：复用既有 KswordARK 动态子层。
        filter.subLayerKey = KSWORD_ARK_WFP_SUBLAYER;
        // 中文说明：空权重让 BFE 在子层内选择标准权重。
        filter.weight.type = FWP_EMPTY;
        // 中文说明：inspection action 是非终止观察，不覆盖防火墙判定。
        filter.action.type = FWP_ACTION_CALLOUT_INSPECTION;
        // 中文说明：关联当前 callout GUID。
        filter.action.calloutKey = *g_KswordArkTrafficCalloutConfigs[index].CalloutKey;
        // 中文说明：与回环模块共用 WDK FLAGS 条件键。
        condition.fieldKey = KswordARKNetworkTrafficFlagsCondition;
        // 中文说明：保留所有未标记 IS_LOOPBACK 的普通 IP 包。
        condition.matchType = FWP_MATCH_FLAGS_NONE_SET;
        // 中文说明：FLAGS 使用 WFP UINT32 类型。
        condition.conditionValue.type = FWP_UINT32;
        // 中文说明：只排除回环位，不改变其它过滤条件。
        condition.conditionValue.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
        // 中文说明：单条件栈数组供同步添加调用使用。
        filter.numFilterConditions = 1U;
        // 中文说明：条件只影响观察入口，不影响防火墙判定。
        filter.filterCondition = &condition;
        // 中文说明：添加 filter 并保存 ID 供显式卸载。
        status = FwpmFilterAdd0(
            Runtime->EngineHandle,
            &filter,
            NULL,
            &Runtime->TrafficFilterIds[index]);
        // 中文说明：失败时让父事务回滚全部对象。
        if (!NT_SUCCESS(status)) {
            // 中文说明：保存精确失败状态。
            Runtime->TrafficCaptureStatus = status;
            // 中文说明：返回失败。
            return status;
        }
    }

    // 中文说明：回环对象仍属于同一父事务，失败时由父事务统一撤销。
    status = KswordARKNetworkTrafficLoopbackAdd(Runtime);
    // 中文说明：回环来源不可用时不报告逐包能力全部就绪。
    if (!NT_SUCCESS(status)) {
        // 中文说明：保存真实 BFE 错误。
        Runtime->TrafficCaptureStatus = status;
        // 中文说明：交由父层 abort，禁止半套来源。
        return status;
    }
    // 中文说明：callout/filter 均已加入当前事务。
    Runtime->TrafficCaptureStatus = STATUS_SUCCESS;
    // 中文说明：返回成功。
    return STATUS_SUCCESS;
}

VOID
KswordARKNetworkTrafficDeleteEngineObjects(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    从已打开 engine 删除逐包 filter/callout 对象并清零 ID。

--*/
{
    // 中文说明：保存逆序清理索引。
    LONG index = 0;

    // 中文说明：无 engine 时只清零可能来自已 abort 事务的 filter ID。
    if (Runtime == NULL) {
        // 中文说明：空 runtime 无法继续。
        return;
    }

    // 中文说明：先清理同一动态会话中的回环管理对象。
    KswordARKNetworkTrafficLoopbackDelete(Runtime);
    // 中文说明：先删 filter，避免仍引用 callout。
    for (index = (LONG)KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT - 1; index >= 0; --index) {
        // 中文说明：只删除已获得非零 ID 的 filter。
        if (Runtime->EngineHandle != NULL && Runtime->TrafficFilterIds[index] != 0ULL) {
            // 中文说明：忽略清理错误，继续释放其它对象。
            (VOID)FwpmFilterDeleteById0(
                Runtime->EngineHandle,
                Runtime->TrafficFilterIds[index]);
        }
        // 中文说明：无论 BFE 是否已随事务移除，都清零本地 ID。
        Runtime->TrafficFilterIds[index] = 0ULL;
    }

    // 中文说明：再按逆序删除 engine callout 对象。
    if (Runtime->EngineHandle != NULL) {
        // 中文说明：遍历全部稳定 callout GUID。
        for (index = (LONG)KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT - 1; index >= 0; --index) {
            // 中文说明：动态会话可能已清除对象，删除错误可忽略。
            (VOID)FwpmCalloutDeleteByKey0(
                Runtime->EngineHandle,
                g_KswordArkTrafficCalloutConfigs[index].CalloutKey);
        }
    }
}

VOID
KswordARKNetworkTrafficUnregisterRuntimeCallouts(
    _Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime
    )
/*++

Routine Description:

    注销普通 IP 和回环 TRANSPORT callout，支持部分初始化与重复清理。

--*/
{
    // 中文说明：保存逆序清理索引。
    LONG index = 0;

    // 中文说明：空 runtime 无需清理。
    if (Runtime == NULL) {
        // 中文说明：直接返回。
        return;
    }

    // 中文说明：先清退回环回调，原 ring 和捕获代次仍保持有效。
    KswordARKNetworkTrafficLoopbackUnregister();
    // 中文说明：逆序注销已注册 runtime callout。
    for (index = (LONG)KSWORD_ARK_NETWORK_TRAFFIC_CALLOUT_COUNT - 1; index >= 0; --index) {
        // 中文说明：0 表示该槽位未注册或已清理。
        if (Runtime->TrafficCalloutIds[index] != 0U) {
            // 中文说明：忽略单项注销错误，继续避免残留其它 callout。
            (VOID)FwpsCalloutUnregisterById0(Runtime->TrafficCalloutIds[index]);
            // 中文说明：清零本地 runtime ID。
            Runtime->TrafficCalloutIds[index] = 0U;
        }
    }
    // 中文说明：逐包能力位只在全部对象成功提交时才可保留。
    Runtime->RuntimeFlags &= ~KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED;
}

NTSTATUS
KswordARKNetworkQueryTrafficPackets(
    _In_ const KSWORD_ARK_NETWORK_TRAFFIC_QUERY_REQUEST* Request,
    _Out_writes_bytes_(OutputBufferLength) PVOID OutputBuffer,
    _In_ size_t OutputBufferLength,
    _Out_ size_t* BytesWrittenOut
    )
/*++

Routine Description:

    按 afterSequence 增量读取固定 IPv4/IPv6 逐包 ring。

--*/
{
    // 中文说明：变长响应头不包含 entries[1] 占位行。
    const size_t responseHeaderSize =
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE) -
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
    // 中文说明：获取固定非分页运行时。
    KSWORD_ARK_NETWORK_RUNTIME* runtime = KswordARKNetworkGetRuntime();
    // 中文说明：输出缓冲解释为版本化响应。
    KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE* response = NULL;
    // 中文说明：保存规范化行预算。
    ULONG maxRows = 0UL;
    // 中文说明：保存输出可容纳行数。
    ULONG outputRowCapacity = 0UL;
    // 中文说明：在收窄前使用 size_t 计算容量。
    size_t outputRowCapacitySize = 0U;
    // 中文说明：保存 ring 有效行数。
    ULONG packetCount = 0UL;
    // 中文说明：保存最旧槽位索引。
    ULONG oldestIndex = 0UL;
    // 中文说明：保存 cursor 后可用行数。
    ULONG availableCount = 0UL;
    // 中文说明：保存实际返回行数。
    ULONG returnedCount = 0UL;
    // 中文说明：保存本次最多复制的行数。
    ULONG targetReturnCount = 0UL;
    // 中文说明：保存逐行复制时重新读取的 ring 元数据。
    ULONG currentPacketCount = 0UL;
    ULONG currentOldestIndex = 0UL;
    // 中文说明：保存处理驱动重载后的有效 cursor。
    ULONG64 effectiveAfterSequence = 0ULL;
    // 中文说明：保存下一条待复制的稳定序号。
    ULONG64 desiredSequence = 0ULL;
    ULONG64 currentOldestSequence = 0ULL;
    ULONG64 currentNewestSequence = 0ULL;
    // 中文说明：保存获取逐包自旋锁前 IRQL。
    KIRQL oldIrql = PASSIVE_LEVEL;

    // 中文说明：所有必需参数都必须存在。
    if (Request == NULL || OutputBuffer == NULL || BytesWrittenOut == NULL || runtime == NULL) {
        // 中文说明：无法形成响应。
        return STATUS_INVALID_PARAMETER;
    }
    // 中文说明：失败路径默认无输出。
    *BytesWrittenOut = 0U;
    // 中文说明：输出至少容纳无行响应头。
    if (OutputBufferLength < responseHeaderSize) {
        // 中文说明：让 WDF 返回明确缓冲不足。
        return STATUS_BUFFER_TOO_SMALL;
    }

    // 中文说明：只清零固定头；实际返回行都会被完整覆盖。
    RtlZeroMemory(OutputBuffer, responseHeaderSize);
    // 中文说明：绑定响应头。
    response = (KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE*)OutputBuffer;
    // 中文说明：写入逐包子协议版本。
    response->version = KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION;
    // 中文说明：写入固定行 ABI 大小。
    response->entrySize = sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
    // 中文说明：公开固定 ring 容量。
    response->capacity = KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
    // 中文说明：只有普通 IP 和回环 transport filter 一并提交后才报告可用。
    response->status =
        ((runtime->RuntimeFlags & KSWORD_ARK_NETWORK_RUNTIME_PACKET_CAPTURE_STARTED) == 0UL) ?
        KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE :
        (InterlockedCompareExchange(
                &runtime->TrafficCaptureEnabled,
                0L,
                0L) != 0L ?
            KSWORD_ARK_NETWORK_STATUS_APPLIED :
            KSWORD_ARK_NETWORK_STATUS_DISABLED);
    // 中文说明：不可用时返回逐包注册的精确状态。
    response->lastStatus =
        (response->status == KSWORD_ARK_NETWORK_STATUS_APPLIED ||
            response->status == KSWORD_ARK_NETWORK_STATUS_DISABLED) ?
        STATUS_SUCCESS :
        runtime->TrafficCaptureStatus;

    // 中文说明：v1 使用精确请求大小、零标志和零保留字段。
    if (Request->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ||
        Request->size != sizeof(*Request) ||
        Request->flags != KSWORD_ARK_NETWORK_TRAFFIC_QUERY_FLAG_NONE ||
        Request->reserved != 0ULL) {
        // 中文说明：协议错误通过固定响应表达，DeviceIoControl 传输仍成功。
        response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
        // 中文说明：区分版本不匹配与其它非法字段。
        response->lastStatus =
            Request->version != KSWORD_ARK_NETWORK_TRAFFIC_PROTOCOL_VERSION ?
            STATUS_REVISION_MISMATCH :
            STATUS_INVALID_PARAMETER;
        // 中文说明：错误响应只含头。
        response->size = (ULONG)responseHeaderSize;
        // 中文说明：回报固定头长度。
        *BytesWrittenOut = responseHeaderSize;
        // 中文说明：传输成功，语义错误在响应中。
        return STATUS_SUCCESS;
    }

    // 中文说明：maxRows=0 使用保守默认预算。
    maxRows = Request->maxRows == 0UL ?
        KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS :
        Request->maxRows;
    // 中文说明：钳制单次持锁复制量。
    if (maxRows > KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS) {
        // 中文说明：使用稳定协议上限。
        maxRows = KSWORD_ARK_NETWORK_TRAFFIC_MAX_REQUESTED_ROWS;
    }
    // 中文说明：按除法计算输出行容量，避免乘加溢出。
    outputRowCapacitySize = (OutputBufferLength - responseHeaderSize) /
        sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW);
    // 中文说明：输出容量不得超过请求预算。
    if (outputRowCapacitySize > (size_t)maxRows) {
        // 中文说明：收窄到预算。
        outputRowCapacitySize = (size_t)maxRows;
    }
    // 中文说明：maxRows 小于 ULONG 上限，收窄安全。
    outputRowCapacity = (ULONG)outputRowCapacitySize;
    // 中文说明：无返回行时沿用请求 cursor。
    response->nextSequence = Request->afterSequence;
    // 中文说明：准备处理驱动重载 cursor。
    effectiveAfterSequence = Request->afterSequence;

    // 中文说明：只在锁内快照 ring 元数据，不再批量复制最多 256 个大行。
    KeAcquireSpinLock(&runtime->TrafficLock, &oldIrql);
    // 中文说明：捕获当前有效行数。
    packetCount = runtime->TrafficCount;
    // 中文说明：捕获累计覆盖数。
    response->droppedPacketCount = runtime->DroppedTrafficCount;
    // 中文说明：非空 ring 才有序号窗口。
    if (packetCount != 0UL) {
        // 中文说明：写指针向后退有效行数得到最旧槽。
        oldestIndex =
            (runtime->TrafficWriteIndex +
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                packetCount) %
            KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
        // 中文说明：报告仍可恢复的最旧序号。
        response->oldestSequence = runtime->TrafficRing[oldestIndex].sequence;
        // 中文说明：报告最后写入槽的最新序号。
        response->newestSequence =
            runtime->TrafficRing[
                (runtime->TrafficWriteIndex +
                    KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                    1UL) %
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY].sequence;

    }
    // 中文说明：元数据快照完成后立即恢复 IRQL，让 classify 写入继续前进。
    KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);

    if (packetCount != 0UL) {
        // 中文说明：驱动重载或新捕获会话后旧 R3 cursor 可能大于最新序号。
        if (effectiveAfterSequence > response->newestSequence) {
            response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET;
            effectiveAfterSequence = 0ULL;
            response->nextSequence = 0ULL;
        }

        // 中文说明：afterSequence=0 的协议语义是从当前最旧行开始，不把历史覆盖算成缺口。
        if (effectiveAfterSequence == 0ULL) {
            desiredSequence = response->oldestSequence;
        }
        else if (effectiveAfterSequence < response->newestSequence) {
            desiredSequence = effectiveAfterSequence + 1ULL;
            if (desiredSequence < response->oldestSequence) {
                response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP;
                response->cursorGapCount =
                    response->oldestSequence - desiredSequence;
                desiredSequence = response->oldestSequence;
            }
        }

        if (desiredSequence != 0ULL &&
            desiredSequence <= response->newestSequence) {
            // 中文说明：稳定序号连续，因此无需在锁内线性扫描 2048 个槽。
            availableCount = (ULONG)(
                response->newestSequence - desiredSequence + 1ULL);
            targetReturnCount = availableCount < outputRowCapacity
                ? availableCount
                : outputRowCapacity;
        }
    }

    // 中文说明：每次只在自旋锁内定位并复制一个固定行，写侧最多被单行 memcpy 阻塞。
    while (returnedCount < targetReturnCount &&
        desiredSequence != 0ULL &&
        desiredSequence <= response->newestSequence) {
        ULONG ringIndex = 0UL;
        ULONG64 ringOffset = 0ULL;

        KeAcquireSpinLock(&runtime->TrafficLock, &oldIrql);
        currentPacketCount = runtime->TrafficCount;
        if (currentPacketCount == 0UL) {
            KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);
            break;
        }

        currentOldestIndex =
            (runtime->TrafficWriteIndex +
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                currentPacketCount) %
            KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
        currentOldestSequence =
            runtime->TrafficRing[currentOldestIndex].sequence;
        currentNewestSequence =
            runtime->TrafficRing[
                (runtime->TrafficWriteIndex +
                    KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY -
                    1UL) %
                KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY].sequence;

        // 中文说明：高流量下目标槽可能在两次短锁之间被覆盖，跳到当前最旧行并记缺口。
        if (desiredSequence < currentOldestSequence) {
            response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_GAP;
            response->cursorGapCount +=
                currentOldestSequence - desiredSequence;
            desiredSequence = currentOldestSequence;
        }
        if (desiredSequence > currentNewestSequence ||
            desiredSequence > response->newestSequence) {
            KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);
            break;
        }

        ringOffset = desiredSequence - currentOldestSequence;
        if (ringOffset >= currentPacketCount) {
            KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);
            break;
        }
        ringIndex = (currentOldestIndex + (ULONG)ringOffset) %
            KSWORD_ARK_NETWORK_TRAFFIC_RING_CAPACITY;
        if (runtime->TrafficRing[ringIndex].sequence != desiredSequence) {
            response->status = KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED;
            response->lastStatus = STATUS_DATA_ERROR;
            KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);
            break;
        }

        RtlCopyMemory(
            &response->entries[returnedCount],
            &runtime->TrafficRing[ringIndex],
            sizeof(runtime->TrafficRing[ringIndex]));
        KeReleaseSpinLock(&runtime->TrafficLock, oldIrql);

        response->nextSequence = desiredSequence;
        returnedCount += 1UL;
        desiredSequence += 1ULL;
    }

    // 中文说明：回报 cursor 后可用行数。
    response->availablePacketCount = availableCount;
    // 中文说明：回报实际复制行数。
    response->returnedPacketCount = returnedCount;
    // 中文说明：预算不足时显式标记响应截断。
    if (availableCount > returnedCount) {
        // 中文说明：调用方应立即用 nextSequence 继续查询。
        response->flags |= KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED;
    }
    // 中文说明：计算精确变长响应大小；行数已受小预算限制，不会溢出 ULONG。
    response->size = (ULONG)(
        responseHeaderSize +
        ((size_t)returnedCount * sizeof(KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW)));
    // 中文说明：回报精确写入长度。
    *BytesWrittenOut = response->size;
    // 中文说明：响应形成成功。
    return STATUS_SUCCESS;
}
