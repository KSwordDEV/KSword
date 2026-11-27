#pragma once

// 中文说明：所有逐包实现共用同一 WDK NDIS 合约。
#include <ntddk.h>
#ifndef NDIS630
#define NDIS630
#endif
#include <ndis.h>
// 中文说明：匿名系统结构只在 WDK 头内部豁免告警。
#pragma warning(push)
#pragma warning(disable:4201 4214)
#include <fwpsk.h>
#include <fwpmk.h>
#pragma warning(pop)
#include "network_internal.h"

// 中文说明：IPPACKET 排除回环、TRANSPORT 只匹配回环，条件键来自同一 WDK 常量。
extern const GUID KswordARKNetworkTrafficFlagsCondition;

// 中文说明：两个捕获入口只读取 WFP 显式提供、且协议可表示的真实 PID。
static __forceinline ULONG KswordARKNetworkTrafficReadProcessId(
    _In_opt_ const FWPS_INCOMING_METADATA_VALUES0* Metadata)
{
    // 中文说明：缺失字段或宽度溢出时保持未知，不收窄成错误 PID。
    if (Metadata == NULL || (Metadata->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID) == 0U ||
        Metadata->processId > MAXULONG) {
        // 中文说明：消费者可继续按原规则做端点归属线索。
        return 0UL;
    }
    // 中文说明：经过边界检查后显式收窄到共享协议宽度。
    return (ULONG)Metadata->processId;
}

// 中文说明：IP 或 transport 记录共用原有捕获代次与同一 ring 写入点。
VOID KswordARKNetworkTrafficRecordPacket(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* PacketRow,
    _In_ ULONG CaptureGeneration);

// 中文说明：真实 transport 前缀复用原 TCP/UDP 解析，不另维护第二套解析器。
BOOLEAN KswordARKNetworkTrafficParseTransport(
    _Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row,
    _In_ ULONG TransportOffset,
    _In_ ULONG PacketLength,
    _In_ UCHAR Protocol,
    _In_reads_(AddressLength) const UCHAR* SourceAddress,
    _In_reads_(AddressLength) const UCHAR* DestinationAddress,
    _In_ ULONG AddressLength);

// 中文说明：仅真实回退得到的 IP 字节才交给同一 IPv4/IPv6 解析器。
BOOLEAN KswordARKNetworkTrafficParsePacket(_Inout_ KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW* Row);

// 中文说明：回环对象沿父动态会话注册，不改变安装、启停或 IOCTL。
NTSTATUS KswordARKNetworkTrafficLoopbackRegister(_Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime);
// 中文说明：回环过滤器加入既有父 BFE 事务。
NTSTATUS KswordARKNetworkTrafficLoopbackAdd(_Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime);
// 中文说明：父会话关闭前删除回环管理对象。
VOID KswordARKNetworkTrafficLoopbackDelete(_Inout_ KSWORD_ARK_NETWORK_RUNTIME* Runtime);
// 中文说明：在普通逐包 runtime 注销前等待回环回调清退。
VOID KswordARKNetworkTrafficLoopbackUnregister(VOID);
