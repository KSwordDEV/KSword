#pragma once

// ============================================================
// ksword/network/network_connection_tools.h
// 命名空间：ks::network
// 作用：
// 1) 枚举 TCP 连接快照（含 PID、进程名、本地/远端端点、状态）；
// 2) 枚举 UDP 端点快照（含 PID、进程名、本地端点）；
// 3) 支持按指定 TCP 连接参数执行 DELETE_TCB 终止连接。
//
// 设计说明：
// - 本文件采用“头文件内联实现”，避免新增 cpp 文件后还需修改工程文件；
// - 供 NetworkDock 与其它工具模块直接 include 使用。
// ============================================================

#include "../process/process.h"

#include <algorithm>    // std::sort：快照排序，便于 UI 稳定显示。
#include <cstddef>      // std::size_t：容器索引与长度。
#include <cstdint>      // 固定宽度整数：PID/IP/Port 等字段。
#include <cstring>      // std::memset：结构体清零保护。
#include <sstream>      // std::ostringstream：错误详情与四元组诊断文本。
#include <string>       // std::string：跨层文本表达。
#include <unordered_map>// PID -> 进程名缓存，避免重复查询。
#include <utility>      // std::move：记录对象移动进容器。
#include <vector>       // 快照输出容器。

// Winsock / IP Helper 头：
// - WinSock2 需要先于 windows.h 链路中的 winsock.h。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Iphlpapi.h>

// 链接依赖：
// - Iphlpapi：GetExtendedTcpTable/GetExtendedUdpTable/SetTcpEntry；
// - Ws2_32：inet_ntop/htons/htonl 等网络转换函数。
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

namespace ks::network
{
    // TcpConnectionRecord：
    // - TCP 连接快照记录；
    // - 同时保留文本地址与主机序地址，兼顾 UI 展示与连接控制。
    struct TcpConnectionRecord
    {
        std::uint32_t processId = 0;           // 所属进程 PID。
        std::string processName;               // 所属进程名（可能为空）。
        bool isIpv6 = false;                   // 地址族标识：false=IPv4，true=IPv6。

        std::uint32_t localIpv4HostOrder = 0;  // 本地 IPv4（主机序，终止连接时使用）。
        std::uint32_t localIpv4NetworkOrder = 0; // 本地 IPv4（网络序原始值，提交 SetTcpEntry 时优先使用）。
        std::uint16_t localPort = 0;           // 本地端口（主机序）。
        std::uint32_t localPortNetworkOrder = 0; // 本地端口（IP Helper 原始 DWORD，保留高位兼容 Windows 表项布局）。
        std::string localAddressText;          // 本地地址文本（IPv4/IPv6）。

        std::uint32_t remoteIpv4HostOrder = 0; // 远端 IPv4（主机序，终止连接时使用）。
        std::uint32_t remoteIpv4NetworkOrder = 0; // 远端 IPv4（网络序原始值，提交 SetTcpEntry 时优先使用）。
        std::uint16_t remotePort = 0;          // 远端端口（主机序）。
        std::uint32_t remotePortNetworkOrder = 0; // 远端端口（IP Helper 原始 DWORD，保留高位兼容 Windows 表项布局）。
        std::string remoteAddressText;         // 远端地址文本（IPv4/IPv6）。

        std::uint32_t tcpStateCode = 0;        // MIB_TCP_STATE_* 原始值。
        std::string tcpStateText;              // 状态文本（ESTABLISHED/LISTEN 等）。
    };

    // UdpEndpointRecord：
    // - UDP 端点快照记录；
    // - UDP 无“连接状态”，仅保留本地端点 + 进程归属。
    struct UdpEndpointRecord
    {
        std::uint32_t processId = 0;           // 所属进程 PID。
        std::string processName;               // 所属进程名（可能为空）。
        bool isIpv6 = false;                   // 地址族标识：false=IPv4，true=IPv6。

        std::uint32_t localIpv4HostOrder = 0;  // 本地 IPv4（主机序）。
        std::uint16_t localPort = 0;           // 本地端口（主机序）。
        std::string localAddressText;          // 本地地址文本（IPv4/IPv6）。
    };

    namespace connection_detail
    {
        // Ipv4NetworkOrderToText：
        // - 把“网络序 IPv4”转换为点分十进制文本；
        // - 失败时回退到 "0.0.0.0"。
        inline std::string Ipv4NetworkOrderToText(const std::uint32_t ipv4NetworkOrder)
        {
            in_addr ipv4Address{};
            ipv4Address.s_addr = ipv4NetworkOrder;

            char ipv4TextBuffer[INET_ADDRSTRLEN] = {};
            const PCSTR convertResult = ::inet_ntop(
                AF_INET,
                &ipv4Address,
                ipv4TextBuffer,
                static_cast<socklen_t>(sizeof(ipv4TextBuffer)));
            if (convertResult == nullptr)
            {
                return std::string("0.0.0.0");
            }
            return std::string(ipv4TextBuffer);
        }

        // Ipv6BytesToText：
        // - 把 16 字节 IPv6 地址转换为标准文本；
        // - 失败时回退到 "::"。
        inline std::string Ipv6BytesToText(const UCHAR ipv6Bytes[16])
        {
            IN6_ADDR ipv6Address{};
            std::memcpy(&ipv6Address, ipv6Bytes, sizeof(ipv6Address));

            char ipv6TextBuffer[INET6_ADDRSTRLEN] = {};
            const PCSTR convertResult = ::inet_ntop(
                AF_INET6,
                &ipv6Address,
                ipv6TextBuffer,
                static_cast<socklen_t>(sizeof(ipv6TextBuffer)));
            if (convertResult == nullptr)
            {
                return std::string("::");
            }
            return std::string(ipv6TextBuffer);
        }

        // TcpStateCodeToText：
        // - 把 MIB_TCP_STATE_* 状态值转换为易读文本；
        // - 未识别状态统一返回 "UNKNOWN"。
        inline std::string TcpStateCodeToText(const std::uint32_t stateCode)
        {
            switch (stateCode)
            {
            case MIB_TCP_STATE_CLOSED:      return "CLOSED";
            case MIB_TCP_STATE_LISTEN:      return "LISTEN";
            case MIB_TCP_STATE_SYN_SENT:    return "SYN_SENT";
            case MIB_TCP_STATE_SYN_RCVD:    return "SYN_RECV";
            case MIB_TCP_STATE_ESTAB:       return "ESTABLISHED";
            case MIB_TCP_STATE_FIN_WAIT1:   return "FIN_WAIT1";
            case MIB_TCP_STATE_FIN_WAIT2:   return "FIN_WAIT2";
            case MIB_TCP_STATE_CLOSE_WAIT:  return "CLOSE_WAIT";
            case MIB_TCP_STATE_CLOSING:     return "CLOSING";
            case MIB_TCP_STATE_LAST_ACK:    return "LAST_ACK";
            case MIB_TCP_STATE_TIME_WAIT:   return "TIME_WAIT";
            case MIB_TCP_STATE_DELETE_TCB:  return "DELETE_TCB";
            default:                        return "UNKNOWN";
            }
        }

        // FillProcessNameCacheIfNeeded：
        // - 延迟查询 PID 对应进程名并写入缓存；
        // - 避免在大连接表里重复调用 Query API 导致性能浪费。
        inline const std::string& FillProcessNameCacheIfNeeded(
            const std::uint32_t processId,
            std::unordered_map<std::uint32_t, std::string>& processNameCache)
        {
            const auto cacheIterator = processNameCache.find(processId);
            if (cacheIterator != processNameCache.end())
            {
                return cacheIterator->second;
            }

            const std::string processName = ks::process::GetProcessNameByPID(processId);
            const auto insertResult = processNameCache.insert({ processId, processName });
            return insertResult.first->second;
        }

        // IsIpv4TcpEndpointEqual：
        // - 输入：一个当前系统 TCP 行和一个 UI 缓存连接记录；
        // - 处理：逐项比较 IPv4 四元组，并可选比较 PID；
        // - 返回：完全匹配时返回 true，否则返回 false。
        inline bool IsIpv4TcpEndpointEqual(
            const MIB_TCPROW_OWNER_PID& row,
            const TcpConnectionRecord& connectionRecord,
            const bool compareProcessId)
        {
            if (connectionRecord.isIpv6)
            {
                return false;
            }
            if (compareProcessId &&
                static_cast<std::uint32_t>(row.dwOwningPid) != connectionRecord.processId)
            {
                return false;
            }
            const std::uint32_t rowLocalPort = row.dwLocalPort & 0xFFFFU;
            const std::uint32_t rowRemotePort = row.dwRemotePort & 0xFFFFU;
            const std::uint32_t recordLocalPort = connectionRecord.localPortNetworkOrder & 0xFFFFU;
            const std::uint32_t recordRemotePort = connectionRecord.remotePortNetworkOrder & 0xFFFFU;
            return row.dwLocalAddr == connectionRecord.localIpv4NetworkOrder &&
                row.dwRemoteAddr == connectionRecord.remoteIpv4NetworkOrder &&
                rowLocalPort == recordLocalPort &&
                rowRemotePort == recordRemotePort;
        }

        // BuildDeleteTcpRowFromOwnerPidRow：
        // - 输入：GetExtendedTcpTable 返回的 IPv4 TCP 原始行；
        // - 处理：保留原始地址/端口 DWORD，仅把状态改成 DELETE_TCB；
        // - 返回：可直接传给 SetTcpEntry 的 MIB_TCPROW。
        inline MIB_TCPROW BuildDeleteTcpRowFromOwnerPidRow(const MIB_TCPROW_OWNER_PID& sourceRow)
        {
            MIB_TCPROW tcpRow{};
            std::memset(&tcpRow, 0, sizeof(tcpRow));
            tcpRow.dwState = MIB_TCP_STATE_DELETE_TCB;
            tcpRow.dwLocalAddr = sourceRow.dwLocalAddr;
            tcpRow.dwLocalPort = sourceRow.dwLocalPort;
            tcpRow.dwRemoteAddr = sourceRow.dwRemoteAddr;
            tcpRow.dwRemotePort = sourceRow.dwRemotePort;
            return tcpRow;
        }

        // BuildDeleteTcpRowFromRecord：
        // - 输入：UI 缓存的 IPv4 TCP 记录；
        // - 处理：优先使用枚举时保存的原始网络序地址/端口，缺失时才回退主机序转换；
        // - 返回：可直接传给 SetTcpEntry 的 MIB_TCPROW。
        inline MIB_TCPROW BuildDeleteTcpRowFromRecord(const TcpConnectionRecord& connectionRecord)
        {
            MIB_TCPROW tcpRow{};
            std::memset(&tcpRow, 0, sizeof(tcpRow));
            tcpRow.dwState = MIB_TCP_STATE_DELETE_TCB;
            tcpRow.dwLocalAddr = connectionRecord.localIpv4NetworkOrder != 0
                ? connectionRecord.localIpv4NetworkOrder
                : htonl(connectionRecord.localIpv4HostOrder);
            tcpRow.dwRemoteAddr = connectionRecord.remoteIpv4NetworkOrder != 0
                ? connectionRecord.remoteIpv4NetworkOrder
                : htonl(connectionRecord.remoteIpv4HostOrder);
            tcpRow.dwLocalPort = connectionRecord.localPortNetworkOrder != 0
                ? static_cast<DWORD>(connectionRecord.localPortNetworkOrder & 0xFFFFU)
                : static_cast<DWORD>(htons(connectionRecord.localPort));
            tcpRow.dwRemotePort = connectionRecord.remotePortNetworkOrder != 0
                ? static_cast<DWORD>(connectionRecord.remotePortNetworkOrder & 0xFFFFU)
                : static_cast<DWORD>(htons(connectionRecord.remotePort));
            return tcpRow;
        }

        // GetTcpTerminationUnsupportedReason：
        // - 输入：UI 缓存的 TCP 记录；
        // - 处理：按 SetTcpEntry(DELETE_TCB) 的能力边界提前判定不可终止场景；
        // - 返回：可终止时返回空字符串，不可终止时返回给 UI/日志使用的原因文本。
        inline std::string GetTcpTerminationUnsupportedReason(const TcpConnectionRecord& connectionRecord)
        {
            // SetTcpEntry 只接受 IPv4 MIB_TCPROW；IPv6 行来自另一张表，不能转换成 MIB_TCPROW。
            if (connectionRecord.isIpv6)
            {
                return "IPv6 TCP 连接暂不支持通过 SetTcpEntry 终止。";
            }

            // LISTEN 行代表服务端监听端点，不是已建立连接 TCB：
            // - 典型远端端点为 0.0.0.0:0；
            // - SetTcpEntry(DELETE_TCB) 无法关闭监听 socket；
            // - 若需要释放端口，必须结束/控制持有该监听 socket 的进程或服务。
            if (connectionRecord.tcpStateCode == MIB_TCP_STATE_LISTEN)
            {
                return "LISTEN 是监听端口，不是已建立 TCP 连接；SetTcpEntry(DELETE_TCB) 不能关闭监听 socket。请结束/停止持有该端口的进程或服务。";
            }

            // CLOSED/DELETE_TCB 已不是可操作的活动连接；继续提交只会得到误导性错误码。
            if (connectionRecord.tcpStateCode == MIB_TCP_STATE_CLOSED ||
                connectionRecord.tcpStateCode == MIB_TCP_STATE_DELETE_TCB)
            {
                return "目标 TCP 行已处于关闭/删除状态，不需要再次提交 DELETE_TCB。";
            }

            // 没有远端端点通常说明它不是一个可删除的已建立/半关闭四元组。
            if (connectionRecord.remotePort == 0 ||
                connectionRecord.remoteAddressText.empty() ||
                connectionRecord.remoteAddressText == "0.0.0.0")
            {
                return "目标 TCP 行缺少有效远端端点，不是 SetTcpEntry 可终止的连接四元组。";
            }

            return std::string();
        }

        // IsTcpConnectionTerminableBySetTcpEntry：
        // - 输入：UI 缓存的 TCP 记录；
        // - 处理：复用原因构造函数，仅判断是否可执行 DELETE_TCB；
        // - 返回：当前记录可提交 SetTcpEntry 时返回 true，否则返回 false。
        inline bool IsTcpConnectionTerminableBySetTcpEntry(const TcpConnectionRecord& connectionRecord)
        {
            return GetTcpTerminationUnsupportedReason(connectionRecord).empty();
        }

        // FormatSetTcpEntryFailure：
        // - 输入：SetTcpEntry 返回码；
        // - 处理：把常见错误码补充成 UI 可读诊断，尤其区分权限、参数和连接已变化；
        // - 返回：可直接展示/记录的 UTF-8 文本。
        inline std::string FormatSetTcpEntryFailure(const DWORD setResult)
        {
            std::ostringstream stream;
            stream << "SetTcpEntry failed, code=" << setResult;
            if (setResult == ERROR_ACCESS_DENIED)
            {
                stream << " (需要以管理员权限运行，或目标连接受系统策略保护)";
            }
            else if (setResult == ERROR_MR_MID_NOT_FOUND)
            {
                stream << " (系统未提供该错误码的消息文本；常见于向 SetTcpEntry 提交了不支持的 TCP 行，例如 LISTEN 监听端口或已变化的连接)";
            }
            else if (setResult == ERROR_INVALID_PARAMETER)
            {
                stream << " (连接四元组无效、连接状态已变化，或该行不是可删除的 IPv4 TCP 连接)";
            }
            else if (setResult == ERROR_NOT_SUPPORTED)
            {
                stream << " (本机 IPv4 传输未配置或系统不支持该操作)";
            }
            else if (setResult == ERROR_NOT_FOUND)
            {
                stream << " (连接已不存在或快照已过期)";
            }
            return stream.str();
        }

        // AppendTcpEndpointText：
        // - 输入：连接记录；
        // - 处理：把 PID、状态、本地/远端端点追加到已有诊断流；
        // - 返回：无。
        inline void AppendTcpEndpointText(
            std::ostringstream& stream,
            const TcpConnectionRecord& connectionRecord)
        {
            stream
                << " pid=" << connectionRecord.processId
                << " state=" << connectionRecord.tcpStateText
                << " local=" << connectionRecord.localAddressText << ":" << connectionRecord.localPort
                << " remote=" << connectionRecord.remoteAddressText << ":" << connectionRecord.remotePort;
        }
    } // namespace connection_detail

    // GetTcpTerminationUnsupportedReason：
    // - 输入：TCP 连接快照记录；
    // - 处理：检查该记录是否属于 SetTcpEntry(DELETE_TCB) 支持的 IPv4 活动连接；
    // - 返回：可终止时返回空字符串；不可终止时返回面向用户的原因文本。
    inline std::string GetTcpTerminationUnsupportedReason(const TcpConnectionRecord& connectionRecord)
    {
        return connection_detail::GetTcpTerminationUnsupportedReason(connectionRecord);
    }

    // IsTcpConnectionTerminableBySetTcpEntry：
    // - 输入：TCP 连接快照记录；
    // - 处理：复用终止前置检查；
    // - 返回：记录可提交 SetTcpEntry(DELETE_TCB) 时返回 true，否则返回 false。
    inline bool IsTcpConnectionTerminableBySetTcpEntry(const TcpConnectionRecord& connectionRecord)
    {
        return connection_detail::IsTcpConnectionTerminableBySetTcpEntry(connectionRecord);
    }

    // EnumerateTcpConnectionRecords：
    // - 枚举当前系统 IPv4 + IPv6 TCP 连接快照；
    // - 成功时返回 true，并填充 recordsOut；
    // - 失败时返回 false，并在 errorTextOut 写入错误说明。
    inline bool EnumerateTcpConnectionRecords(
        std::vector<TcpConnectionRecord>& recordsOut,
        std::string* errorTextOut = nullptr,
        bool resolveProcessNames = true)
    {
        recordsOut.clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        // PID -> 进程名缓存，避免对同一 PID 重复查询。
        std::unordered_map<std::uint32_t, std::string> processNameCache;

        // appendIpv4Table 用途：枚举 IPv4 TCP 连接并追加到统一输出容器。
        auto appendIpv4Table = [&recordsOut, &processNameCache, resolveProcessNames](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedTcpTable(
                    tcpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + tcpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < tcpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_TCPROW_OWNER_PID& row = tcpTable->table[rowIndex];

                    TcpConnectionRecord record;
                    record.isIpv6 = false;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    if (resolveProcessNames) record.processName = connection_detail::FillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = ntohl(row.dwLocalAddr);
                    record.localIpv4NetworkOrder = row.dwLocalAddr;
                    record.remoteIpv4HostOrder = ntohl(row.dwRemoteAddr);
                    record.remoteIpv4NetworkOrder = row.dwRemoteAddr;
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localPortNetworkOrder = row.dwLocalPort;
                    record.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                    record.remotePortNetworkOrder = row.dwRemotePort;
                    record.localAddressText = connection_detail::Ipv4NetworkOrderToText(row.dwLocalAddr);
                    record.remoteAddressText = connection_detail::Ipv4NetworkOrderToText(row.dwRemoteAddr);
                    record.tcpStateCode = static_cast<std::uint32_t>(row.dwState);
                    record.tcpStateText = connection_detail::TcpStateCodeToText(record.tcpStateCode);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        // appendIpv6Table 用途：枚举 IPv6 TCP 连接并追加到统一输出容器。
        auto appendIpv6Table = [&recordsOut, &processNameCache, resolveProcessNames](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET6,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* tcpTable = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedTcpTable(
                    tcpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedTcpTable(AF_INET6,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + tcpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < tcpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_TCP6ROW_OWNER_PID& row = tcpTable->table[rowIndex];

                    TcpConnectionRecord record;
                    record.isIpv6 = true;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    if (resolveProcessNames) record.processName = connection_detail::FillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = 0;
                    record.localIpv4NetworkOrder = 0;
                    record.remoteIpv4HostOrder = 0;
                    record.remoteIpv4NetworkOrder = 0;
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localPortNetworkOrder = row.dwLocalPort;
                    record.remotePort = ntohs(static_cast<u_short>(row.dwRemotePort));
                    record.remotePortNetworkOrder = row.dwRemotePort;
                    record.localAddressText = connection_detail::Ipv6BytesToText(row.ucLocalAddr);
                    record.remoteAddressText = connection_detail::Ipv6BytesToText(row.ucRemoteAddr);
                    record.tcpStateCode = static_cast<std::uint32_t>(row.dwState);
                    record.tcpStateText = connection_detail::TcpStateCodeToText(record.tcpStateCode);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        std::string ipv4Error;
        std::string ipv6Error;
        const bool ipv4Ok = appendIpv4Table(&ipv4Error);
        const bool ipv6Ok = appendIpv6Table(&ipv6Error);
        if (!ipv4Ok && !ipv6Ok)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = "TCP v4/v6 均枚举失败: " + ipv4Error + " ; " + ipv6Error;
            }
            return false;
        }
        if (errorTextOut != nullptr && (!ipv4Ok || !ipv6Ok))
        {
            *errorTextOut = "部分枚举失败: " + ipv4Error + " ; " + ipv6Error;
        }

        // 按 PID/本地端点/远端端点排序，保证 UI 每次刷新行顺序稳定。
        std::sort(
            recordsOut.begin(),
            recordsOut.end(),
            [](const TcpConnectionRecord& left, const TcpConnectionRecord& right)
            {
                if (left.processId != right.processId)
                {
                    return left.processId < right.processId;
                }
                if (left.isIpv6 != right.isIpv6)
                {
                    return left.isIpv6 < right.isIpv6;
                }
                if (left.localIpv4HostOrder != right.localIpv4HostOrder)
                {
                    return left.localIpv4HostOrder < right.localIpv4HostOrder;
                }
                if (left.localPort != right.localPort)
                {
                    return left.localPort < right.localPort;
                }
                if (left.remoteIpv4HostOrder != right.remoteIpv4HostOrder)
                {
                    return left.remoteIpv4HostOrder < right.remoteIpv4HostOrder;
                }
                if (left.localAddressText != right.localAddressText)
                {
                    return left.localAddressText < right.localAddressText;
                }
                if (left.remoteAddressText != right.remoteAddressText)
                {
                    return left.remoteAddressText < right.remoteAddressText;
                }
                return left.remotePort < right.remotePort;
            });

        return true;
    }

    // EnumerateUdpEndpointRecords：
    // - 枚举当前系统 IPv4 + IPv6 UDP 端点快照；
    // - 成功时返回 true，并填充 recordsOut；
    // - 失败时返回 false，并在 errorTextOut 写入错误说明。
    inline bool EnumerateUdpEndpointRecords(
        std::vector<UdpEndpointRecord>& recordsOut,
        std::string* errorTextOut = nullptr,
        bool resolveProcessNames = true)
    {
        recordsOut.clear();
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        // PID 名称缓存，减少重复进程查询。
        std::unordered_map<std::uint32_t, std::string> processNameCache;

        // appendIpv4Table 用途：枚举 IPv4 UDP 端点并追加到统一输出容器。
        auto appendIpv4Table = [&recordsOut, &processNameCache, resolveProcessNames](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedUdpTable(
                    udpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + udpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < udpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_UDPROW_OWNER_PID& row = udpTable->table[rowIndex];

                    UdpEndpointRecord record;
                    record.isIpv6 = false;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    if (resolveProcessNames) record.processName = connection_detail::FillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = ntohl(row.dwLocalAddr);
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localAddressText = connection_detail::Ipv4NetworkOrderToText(row.dwLocalAddr);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        // appendIpv6Table 用途：枚举 IPv6 UDP 端点并追加到统一输出容器。
        auto appendIpv6Table = [&recordsOut, &processNameCache, resolveProcessNames](std::string* errorOut) -> bool
            {
                ULONG requiredBufferLength = 0;
                DWORD queryResult = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != ERROR_INSUFFICIENT_BUFFER || requiredBufferLength == 0)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET6,size) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
                auto* udpTable = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(tableBuffer.data());
                queryResult = ::GetExtendedUdpTable(
                    udpTable,
                    &requiredBufferLength,
                    TRUE,
                    AF_INET6,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (queryResult != NO_ERROR)
                {
                    if (errorOut != nullptr)
                    {
                        *errorOut = "GetExtendedUdpTable(AF_INET6,data) failed, code=" + std::to_string(queryResult);
                    }
                    return false;
                }

                recordsOut.reserve(recordsOut.size() + udpTable->dwNumEntries);
                for (DWORD rowIndex = 0; rowIndex < udpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_UDP6ROW_OWNER_PID& row = udpTable->table[rowIndex];

                    UdpEndpointRecord record;
                    record.isIpv6 = true;
                    record.processId = static_cast<std::uint32_t>(row.dwOwningPid);
                    if (resolveProcessNames) record.processName = connection_detail::FillProcessNameCacheIfNeeded(record.processId, processNameCache);
                    record.localIpv4HostOrder = 0;
                    record.localPort = ntohs(static_cast<u_short>(row.dwLocalPort));
                    record.localAddressText = connection_detail::Ipv6BytesToText(row.ucLocalAddr);
                    recordsOut.push_back(std::move(record));
                }
                return true;
            };

        std::string ipv4Error;
        std::string ipv6Error;
        const bool ipv4Ok = appendIpv4Table(&ipv4Error);
        const bool ipv6Ok = appendIpv6Table(&ipv6Error);
        if (!ipv4Ok && !ipv6Ok)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = "UDP v4/v6 均枚举失败: " + ipv4Error + " ; " + ipv6Error;
            }
            return false;
        }
        if (errorTextOut != nullptr && (!ipv4Ok || !ipv6Ok))
        {
            *errorTextOut = "部分枚举失败: " + ipv4Error + " ; " + ipv6Error;
        }

        // UDP 端点排序规则：PID -> 本地端点，保证 UI 行稳定。
        std::sort(
            recordsOut.begin(),
            recordsOut.end(),
            [](const UdpEndpointRecord& left, const UdpEndpointRecord& right)
            {
                if (left.processId != right.processId)
                {
                    return left.processId < right.processId;
                }
                if (left.isIpv6 != right.isIpv6)
                {
                    return left.isIpv6 < right.isIpv6;
                }
                if (left.localIpv4HostOrder != right.localIpv4HostOrder)
                {
                    return left.localIpv4HostOrder < right.localIpv4HostOrder;
                }
                if (left.localAddressText != right.localAddressText)
                {
                    return left.localAddressText < right.localAddressText;
                }
                return left.localPort < right.localPort;
            });

        return true;
    }

    // TerminateTcpConnectionByRecord：
    // - 终止指定 TCP 连接（调用 SetTcpEntry + DELETE_TCB）；
    // - 仅对 IPv4 TCP 行有效；
    // - detailTextOut 会返回可读说明，便于 UI 直接提示用户。
    inline bool TerminateTcpConnectionByRecord(
        const TcpConnectionRecord& connectionRecord,
        std::string* detailTextOut = nullptr)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        // 终止连接能力当前仅覆盖 IPv4（SetTcpEntry）；IPv6 连接仅支持展示，不支持终止。
        const std::string unsupportedReason = connection_detail::GetTcpTerminationUnsupportedReason(connectionRecord);
        if (!unsupportedReason.empty())
        {
            if (detailTextOut != nullptr)
            {
                std::ostringstream unsupportedStream;
                unsupportedStream << unsupportedReason;
                connection_detail::AppendTcpEndpointText(unsupportedStream, connectionRecord);
                *detailTextOut = unsupportedStream.str();
            }
            return false;
        }

        // Windows 公开的 SetTcpEntry 仅接受 IPv4 MIB_TCPROW：
        // - 文档/SDK 头说明只能把状态设置为 MIB_TCP_STATE_DELETE_TCB；
        // - 必须提交完整的 MIB_TCPROW；
        // - 因此关闭前重新读取当前 TCP 表，尽量用系统返回的原始 DWORD 行提交，
        //   避免 UI 快照过期或端口 DWORD 重组差异导致 ERROR_INVALID_PARAMETER。
        ULONG requiredBufferLength = 0;
        DWORD queryResult = ::GetExtendedTcpTable(
            nullptr,
            &requiredBufferLength,
            TRUE,
            AF_INET,
            TCP_TABLE_OWNER_PID_ALL,
            0);

        MIB_TCPROW deleteRow = connection_detail::BuildDeleteTcpRowFromRecord(connectionRecord);
        bool matchedCurrentRow = false;
        bool matchedWithoutPid = false;
        if (queryResult == ERROR_INSUFFICIENT_BUFFER && requiredBufferLength > 0)
        {
            std::vector<std::uint8_t> tableBuffer(requiredBufferLength, 0);
            auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
            queryResult = ::GetExtendedTcpTable(
                tcpTable,
                &requiredBufferLength,
                TRUE,
                AF_INET,
                TCP_TABLE_OWNER_PID_ALL,
                0);
            if (queryResult == NO_ERROR)
            {
                for (DWORD rowIndex = 0; rowIndex < tcpTable->dwNumEntries; ++rowIndex)
                {
                    const MIB_TCPROW_OWNER_PID& row = tcpTable->table[rowIndex];
                    if (connection_detail::IsIpv4TcpEndpointEqual(row, connectionRecord, true))
                    {
                        deleteRow = connection_detail::BuildDeleteTcpRowFromOwnerPidRow(row);
                        matchedCurrentRow = true;
                        break;
                    }
                    if (!matchedWithoutPid &&
                        connection_detail::IsIpv4TcpEndpointEqual(row, connectionRecord, false))
                    {
                        matchedWithoutPid = true;
                    }
                }

                if (!matchedCurrentRow)
                {
                    std::ostringstream staleStream;
                    staleStream << "当前 TCP 表未找到完全匹配连接";
                    if (matchedWithoutPid)
                    {
                        staleStream << "（四元组仍存在，但 PID 已变化）";
                    }
                    else
                    {
                        staleStream << "（连接可能已关闭或快照已过期）";
                    }
                    connection_detail::AppendTcpEndpointText(staleStream, connectionRecord);
                    if (detailTextOut != nullptr)
                    {
                        *detailTextOut = staleStream.str();
                    }
                    return false;
                }
            }
        }

        // SetTcpEntry 返回 NO_ERROR 表示成功，其它值均视为失败。
        const DWORD setResult = ::SetTcpEntry(&deleteRow);
        if (setResult != NO_ERROR)
        {
            if (detailTextOut != nullptr)
            {
                std::ostringstream failStream;
                failStream << connection_detail::FormatSetTcpEntryFailure(setResult);
                connection_detail::AppendTcpEndpointText(failStream, connectionRecord);
                if (!matchedCurrentRow)
                {
                    failStream << " (使用缓存行回退提交";
                    if (queryResult != ERROR_INSUFFICIENT_BUFFER && queryResult != NO_ERROR)
                    {
                        failStream << ", GetExtendedTcpTable code=" << queryResult;
                    }
                    failStream << ")";
                }
                *detailTextOut = failStream.str();
            }
            return false;
        }

        if (detailTextOut != nullptr)
        {
            std::ostringstream successStream;
            successStream << "SetTcpEntry DELETE_TCB succeeded";
            connection_detail::AppendTcpEndpointText(successStream, connectionRecord);
            *detailTextOut = successStream.str();
        }
        return true;
    }
} // namespace ks::network
