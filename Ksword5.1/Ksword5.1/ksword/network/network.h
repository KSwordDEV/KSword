#pragma once

// ============================================================
// ksword/network/network.h
// 命名空间：ks::network
// 作用：
// - 提供“收发双向 TCP/UDP 报文抓取”的基础能力（IPv4/IPv6 Raw Socket）；
// - 提供“报文端口 -> 进程 PID”解析能力（IP Helper 表）；
// - 提供“按 PID 软限速（Suspend/Resume）”的运行时控制能力；
// - 提供“TCP/UDP 连接快照枚举 + TCP 连接终止”的工具能力；
// - 提供“手动构造网络请求（TCP/UDP Winsock 参数可定制）”执行能力；
// - 供 NetworkDock UI 直接调用，保持 UI 与底层抓包逻辑解耦。
// ============================================================

#include "../process/process.h"

#include <array>        // std::array：IPv6 16 字节地址容器与键类型。
#include <algorithm>    // std::clamp/std::sort：限速参数规整与快照排序。
#include <atomic>       // std::atomic：线程运行标记与序号生成。
#include <chrono>       // steady_clock/system_clock：时间戳与刷新节流。
#include <cstdint>      // 固定宽度整数：PID/端口/长度等。
#include <cstring>      // std::memcpy：网络字节解析。
#include <functional>   // std::function：回调接口。
#include <limits>
#include <mutex>        // std::mutex：跨线程共享状态保护。
#include <optional>     // std::optional：可选动作事件。
#include <sstream>      // std::ostringstream：状态文本组装。
#include <string>       // std::string：跨层文本类型。
#include <thread>       // std::thread：后台抓包线程。
#include <unordered_map>// std::unordered_map：连接映射与缓存。
#include <unordered_set>// std::unordered_set：本机地址快速匹配。
#include <utility>      // std::pair：容器辅助。
#include <vector>       // std::vector：报文/表项容器。

// 连接管理工具：
// - TCP/UDP 连接快照枚举；
// - TCP 连接终止（DELETE_TCB）。
#include "network_connection_tools.h"
#include "./network_port_diagnostics.h"

// 手动请求工具：
// - 提供可配置的 Winsock 请求执行封装。
#include "network_request_tools.h"

// Win32 + Winsock 头文件。
// 注意：winsock2 需要先于 windows.h 链路中的 winsock.h。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Iphlpapi.h>
#include <Mstcpip.h>

// 链接依赖：
// - Ws2_32：socket/bind/select/recv/WsaStartup；
// - Iphlpapi：GetAdaptersAddresses/GetExtendedTcpTable/GetExtendedUdpTable。
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace ks::network
{
    // PacketTransportProtocol：当前仅关注 TCP/UDP。
    enum class PacketTransportProtocol : std::uint8_t
    {
        Tcp = 6,   // IP 协议号 6。
        Udp = 17   // IP 协议号 17。
    };

    // PacketDirection：报文方向枚举。
    enum class PacketDirection : std::uint8_t
    {
        Outbound = 0, // 出站（本机 -> 远端）。
        Inbound = 1,  // 入站（远端 -> 本机）。
        Unknown = 2   // 方向无法判定。
    };

    // RateLimitActionType：限速动作类型。
    enum class RateLimitActionType : std::uint8_t
    {
        SuspendProcess = 0, // 触发限速：挂起进程。
        ResumeProcess = 1   // 挂起窗口到期：恢复进程。
    };

    // PacketRecord：单个抓包事件在 UI 层展示所需的完整数据。
    struct PacketRecord
    {
        std::uint64_t sequenceId = 0;         // 报文序号（单调递增，UI 作为主键）。
        std::uint64_t captureTimestampMs = 0; // 抓包时间戳（Unix ms）。

        PacketTransportProtocol protocol = PacketTransportProtocol::Tcp; // 协议类型（TCP/UDP）。
        PacketDirection direction = PacketDirection::Unknown;            // 方向（Outbound/Inbound/Unknown）。

        std::uint32_t processId = 0;          // 归属进程 PID（0 表示暂未解析）。
        std::string processName;              // 归属进程名（缓存查询，可能为空）。
        std::string sourceText = "R3";        // 数据来源：R3 抓包、R0 WFP 逐包记录或兼容 ALE 流授权事件。
        std::uint64_t sourceSequenceId = 0;   // R0 WFP 原始事件序号；R3 抓包保持 0。
        std::uint32_t sourceFlags = 0;        // R0 WFP 事件语义标志；R3 抓包保持 0。

        std::string localAddress;             // 本地地址文本（IPv4/IPv6）。
        std::uint16_t localPort = 0;          // 本地端口。
        std::string remoteAddress;            // 远端地址文本（IPv4/IPv6）。
        std::uint16_t remotePort = 0;         // 远端端口。
        std::string remoteDomain;              // 远端域名：优先由本机 DNS 缓存异步回填。

        std::uint32_t totalPacketSize = 0;    // IP 报文总长度（字节）。
        std::uint32_t payloadSize = 0;        // L4 负载长度（字节）。
        std::size_t payloadOffset = 0;        // 在 packetBytes 中 payload 起始偏移。

        bool localToLocalAmbiguous = false;   // true 表示源/目的都属于本机（本地环回或本机双地址通信），方向需后续二次判定。
        bool packetBytesTruncated = false;    // true 表示 packetBytes 被截断保存。
        bool wfpAleEventNoPayload = false;    // true 表示 R0 WFP ALE 流授权事件，不是含 payload 的逐包记录。
        std::vector<std::uint8_t> packetBytes;// 保存的原始报文字节（用于详情窗口查看）。
    };

    // ProcessRateLimitRule：单个 PID 的限速策略配置。
    struct ProcessRateLimitRule
    {
        std::uint32_t processId = 0;          // 目标 PID。
        std::uint64_t processCreationTime100ns = 0; // PID 对应进程实例的创建时间，防止 PID 回收误操作。
        std::uint64_t bytesPerSecond = 0;     // 每秒允许发送的字节上限（B/s）。
        std::uint32_t suspendDurationMs = 250;// 超限后挂起时长（毫秒）。
        bool enabled = true;                  // 是否启用该规则。
    };

    // ProcessRateLimitSnapshot：UI 刷新限速表时使用的快照结构。
    struct ProcessRateLimitSnapshot
    {
        ProcessRateLimitRule rule;            // 规则配置副本。
        std::uint64_t currentWindowBytes = 0; // 当前统计窗口内累计发送字节。
        std::uint64_t triggerCount = 0;       // 触发限速次数。
        bool currentlySuspended = false;      // 当前是否处于“本组件触发的挂起”状态。
    };

    // RateLimitActionEvent：限速动作通知（挂起/恢复成功与否）。
    struct RateLimitActionEvent
    {
        std::uint64_t timestampMs = 0;            // 动作发生时间戳（Unix ms）。
        std::uint32_t processId = 0;              // 目标 PID。
        RateLimitActionType actionType = RateLimitActionType::SuspendProcess; // 动作类型。
        bool actionSucceeded = false;             // 动作是否执行成功。
        std::uint64_t configuredBytesPerSecond = 0;// 当时规则阈值（B/s）。
        std::string detailText;                   // 详细说明文本（可用于 UI 日志面板）。
    };

    // PacketProtocolToString：协议枚举转字符串。
    inline std::string PacketProtocolToString(const PacketTransportProtocol protocol)
    {
        switch (protocol)
        {
        case PacketTransportProtocol::Tcp:
            return "TCP";
        case PacketTransportProtocol::Udp:
            return "UDP";
        default:
            return "UNKNOWN";
        }
    }

    // PacketDirectionToString：方向枚举转字符串。
    inline std::string PacketDirectionToString(const PacketDirection direction)
    {
        switch (direction)
        {
        case PacketDirection::Outbound:
            return "Outbound";
        case PacketDirection::Inbound:
            return "Inbound";
        case PacketDirection::Unknown:
        default:
            return "Unknown";
        }
    }

    // RateLimitActionTypeToString：限速动作枚举转字符串。
    inline std::string RateLimitActionTypeToString(const RateLimitActionType actionType)
    {
        switch (actionType)
        {
        case RateLimitActionType::SuspendProcess:
            return "SuspendProcess";
        case RateLimitActionType::ResumeProcess:
            return "ResumeProcess";
        default:
            return "UnknownAction";
        }
    }

    namespace detail
    {
        // kMaxRetainedPacketBytes：
        // - 防止单包完整保存导致内存膨胀；
        // - 仍保留足够报文头 + 主要 payload，满足“内容查看”功能。
        constexpr std::size_t kMaxRetainedPacketBytes = 4096;

        // Ipv6Bytes：固定 16 字节 IPv6 地址容器（网络序逐字节存储）。
        // 说明：
        // - 必须在 ReadIpv6Bytes / Ipv6BytesToString 等函数之前声明，
        //   否则 MSVC 会在解析函数签名时把类型当成未定义标识符，
        //   进而引发连锁语法错误。
        using Ipv6Bytes = std::array<std::uint8_t, 16>;

        // NowTickMs：返回当前 Unix 毫秒时间戳。
        inline std::uint64_t NowTickMs()
        {
            const auto now = std::chrono::system_clock::now();
            const auto epochMs = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
            return static_cast<std::uint64_t>(epochMs.count());
        }

        // MakeWinSockErrorText：把 WinSock 错误码组装成可读文本。
        inline std::string MakeWinSockErrorText(const int errorCode)
        {
            std::ostringstream stream;
            stream << "WSAError=" << errorCode;
            return stream.str();
        }

        // ReadNetworkUInt16：从网络字节序读取 16 位整数并转主机序。
        inline std::uint16_t ReadNetworkUInt16(const std::uint8_t* dataPtr)
        {
            std::uint16_t valueNetwork = 0;
            std::memcpy(&valueNetwork, dataPtr, sizeof(valueNetwork));
            return ntohs(valueNetwork);
        }

        // ReadNetworkUInt32：从网络字节序读取 32 位整数并转主机序。
        inline std::uint32_t ReadNetworkUInt32(const std::uint8_t* dataPtr)
        {
            std::uint32_t valueNetwork = 0;
            std::memcpy(&valueNetwork, dataPtr, sizeof(valueNetwork));
            return ntohl(valueNetwork);
        }

        // ReadIpv6Bytes：从连续 16 字节缓冲读取 IPv6 地址。
        inline Ipv6Bytes ReadIpv6Bytes(const std::uint8_t* dataPtr)
        {
            Ipv6Bytes addressBytes{};
            if (dataPtr == nullptr)
            {
                return addressBytes;
            }
            std::memcpy(addressBytes.data(), dataPtr, addressBytes.size());
            return addressBytes;
        }

        // Ipv4HostToString：主机序 IPv4 转点分十进制文本。
        inline std::string Ipv4HostToString(const std::uint32_t hostOrderIpv4)
        {
            in_addr address{};
            address.s_addr = htonl(hostOrderIpv4);

            char textBuffer[INET_ADDRSTRLEN] = {};
            const PCSTR convertResult = ::inet_ntop(AF_INET, &address, textBuffer, static_cast<socklen_t>(sizeof(textBuffer)));
            if (convertResult == nullptr)
            {
                return std::string("0.0.0.0");
            }
            return std::string(textBuffer);
        }

        // Ipv6BytesToString：16 字节 IPv6 地址转文本。
        inline std::string Ipv6BytesToString(const Ipv6Bytes& ipv6Bytes)
        {
            IN6_ADDR ipv6Address{};
            std::memcpy(&ipv6Address, ipv6Bytes.data(), ipv6Bytes.size());

            char textBuffer[INET6_ADDRSTRLEN] = {};
            const PCSTR convertResult = ::inet_ntop(AF_INET6, &ipv6Address, textBuffer, static_cast<socklen_t>(sizeof(textBuffer)));
            if (convertResult == nullptr)
            {
                return std::string("::");
            }
            return std::string(textBuffer);
        }

        // LocalEndpointKey：本地地址+端口组合键（用于 UDP 与 TCP fallback）。
        inline std::uint64_t LocalEndpointKey(const std::uint32_t localIpv4HostOrder, const std::uint16_t localPortHostOrder)
        {
            return (static_cast<std::uint64_t>(localIpv4HostOrder) << 16) |
                static_cast<std::uint64_t>(localPortHostOrder);
        }

        // Ipv6BytesHasher：IPv6 地址哈希器，用于 unordered_set/map。
        struct Ipv6BytesHasher
        {
            std::size_t operator()(const Ipv6Bytes& addressBytes) const
            {
                std::size_t hashValue = 1469598103934665603ULL;
                for (const std::uint8_t byteValue : addressBytes)
                {
                    hashValue ^= static_cast<std::size_t>(byteValue);
                    hashValue *= 1099511628211ULL;
                }
                return hashValue;
            }
        };

        // Ipv6LocalEndpointKey：IPv6 本地端点键（地址 + 端口）。
        struct Ipv6LocalEndpointKey
        {
            Ipv6Bytes localAddress{};
            std::uint16_t localPort = 0;

            bool operator==(const Ipv6LocalEndpointKey& right) const
            {
                return localAddress == right.localAddress &&
                    localPort == right.localPort;
            }
        };

        // Ipv6LocalEndpointKeyHasher：IPv6 本地端点键哈希器。
        struct Ipv6LocalEndpointKeyHasher
        {
            std::size_t operator()(const Ipv6LocalEndpointKey& keyValue) const
            {
                Ipv6BytesHasher addressHasher;
                std::size_t hashValue = addressHasher(keyValue.localAddress);
                hashValue ^= static_cast<std::size_t>(keyValue.localPort) + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                return hashValue;
            }
        };

        // TcpEndpointKey：TCP 四元组键。
        struct TcpEndpointKey
        {
            std::uint32_t localIpv4 = 0;   // 本地 IPv4（主机序）。
            std::uint16_t localPort = 0;   // 本地端口（主机序）。
            std::uint32_t remoteIpv4 = 0;  // 远端 IPv4（主机序）。
            std::uint16_t remotePort = 0;  // 远端端口（主机序）。

            bool operator==(const TcpEndpointKey& right) const
            {
                return localIpv4 == right.localIpv4 &&
                    localPort == right.localPort &&
                    remoteIpv4 == right.remoteIpv4 &&
                    remotePort == right.remotePort;
            }
        };

        // TcpEndpointKeyV6：IPv6 TCP 四元组键。
        struct TcpEndpointKeyV6
        {
            Ipv6Bytes localIpv6{};       // 本地 IPv6（网络序 16 字节）。
            std::uint16_t localPort = 0; // 本地端口（主机序）。
            Ipv6Bytes remoteIpv6{};      // 远端 IPv6（网络序 16 字节）。
            std::uint16_t remotePort = 0;// 远端端口（主机序）。

            bool operator==(const TcpEndpointKeyV6& right) const
            {
                return localIpv6 == right.localIpv6 &&
                    localPort == right.localPort &&
                    remoteIpv6 == right.remoteIpv6 &&
                    remotePort == right.remotePort;
            }
        };

        // TcpEndpointKeyHasher：TCP 四元组哈希器。
        struct TcpEndpointKeyHasher
        {
            std::size_t operator()(const TcpEndpointKey& key) const
            {
                const std::uint64_t leftPart =
                    (static_cast<std::uint64_t>(key.localIpv4) << 32) |
                    (static_cast<std::uint64_t>(key.localPort) << 16) |
                    static_cast<std::uint64_t>(key.remotePort);
                const std::uint64_t rightPart = static_cast<std::uint64_t>(key.remoteIpv4);
                return static_cast<std::size_t>(leftPart ^ (rightPart * 0x9E3779B97F4A7C15ULL));
            }
        };

        // TcpEndpointKeyV6Hasher：IPv6 TCP 四元组哈希器。
        struct TcpEndpointKeyV6Hasher
        {
            std::size_t operator()(const TcpEndpointKeyV6& keyValue) const
            {
                Ipv6BytesHasher addressHasher;
                std::size_t hashValue = addressHasher(keyValue.localIpv6);
                hashValue ^= static_cast<std::size_t>(keyValue.localPort) + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                const std::size_t remoteHash = addressHasher(keyValue.remoteIpv6);
                hashValue ^= remoteHash + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                hashValue ^= static_cast<std::size_t>(keyValue.remotePort) + 0x9E3779B97F4A7C15ULL + (hashValue << 6) + (hashValue >> 2);
                return hashValue;
            }
        };

        // CaptureSocketEntry：单个绑定接口的 Raw Socket 信息。
        struct CaptureSocketEntry
        {
            SOCKET socketValue = INVALID_SOCKET; // Raw Socket 句柄。
            int addressFamily = AF_INET;         // 地址族（AF_INET / AF_INET6）。
            std::uint32_t localIpv4HostOrder = 0;// 绑定 IPv4（主机序，AF_INET 时有效）。
            Ipv6Bytes localIpv6Bytes{};          // 绑定 IPv6（网络序 16 字节，AF_INET6 时有效）。
            DWORD captureMode = RCVALL_ON;       // 抓包模式（RCVALL_ON / RCVALL_IPLEVEL），用于兼容不同网卡驱动。
            std::string localAddressText;        // 绑定地址文本（日志展示）。
        };

        // EnumerateActiveIpv4Addresses：
        // - 枚举“当前启用”的 IPv4 单播地址；
        // - 供抓包 socket 按接口逐个 bind。
        inline std::vector<std::uint32_t> EnumerateActiveIpv4Addresses()
        {
            std::vector<std::uint32_t> ipv4List;

            ULONG requiredBufferLength = 0;
            const ULONG queryFlags =
                GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER;

            const ULONG firstQueryResult = ::GetAdaptersAddresses(
                AF_INET,
                queryFlags,
                nullptr,
                nullptr,
                &requiredBufferLength);

            if (firstQueryResult != ERROR_BUFFER_OVERFLOW || requiredBufferLength == 0)
            {
                return ipv4List;
            }

            std::vector<std::uint8_t> buffer(requiredBufferLength, 0);
            auto* adapterList = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            const ULONG secondQueryResult = ::GetAdaptersAddresses(
                AF_INET,
                queryFlags,
                nullptr,
                adapterList,
                &requiredBufferLength);

            if (secondQueryResult != NO_ERROR)
            {
                return ipv4List;
            }

            std::unordered_set<std::uint32_t> uniqueAddressSet;
            for (IP_ADAPTER_ADDRESSES* adapter = adapterList; adapter != nullptr; adapter = adapter->Next)
            {
                // 只采集“已启动”网卡，避免无效 bind。
                if (adapter->OperStatus != IfOperStatusUp)
                {
                    continue;
                }

                for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
                    unicast != nullptr;
                    unicast = unicast->Next)
                {
                    if (unicast->Address.lpSockaddr == nullptr ||
                        unicast->Address.lpSockaddr->sa_family != AF_INET)
                    {
                        continue;
                    }

                    auto* ipv4Address = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
                    const std::uint32_t hostOrderAddress = ntohl(ipv4Address->sin_addr.s_addr);
                    if (hostOrderAddress == 0)
                    {
                        continue;
                    }
                    uniqueAddressSet.insert(hostOrderAddress);
                }
            }

            ipv4List.assign(uniqueAddressSet.begin(), uniqueAddressSet.end());
            return ipv4List;
        }

        // EnumerateActiveIpv6Addresses：
        // - 枚举“当前启用”的 IPv6 单播地址（含全局/本地链路地址）；
        // - 供 IPv6 Raw Socket 按接口逐个 bind。
        inline std::vector<Ipv6Bytes> EnumerateActiveIpv6Addresses()
        {
            std::vector<Ipv6Bytes> ipv6List;

            ULONG requiredBufferLength = 0;
            const ULONG queryFlags =
                GAA_FLAG_SKIP_ANYCAST |
                GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER;

            const ULONG firstQueryResult = ::GetAdaptersAddresses(
                AF_INET6,
                queryFlags,
                nullptr,
                nullptr,
                &requiredBufferLength);

            if (firstQueryResult != ERROR_BUFFER_OVERFLOW || requiredBufferLength == 0)
            {
                return ipv6List;
            }

            std::vector<std::uint8_t> buffer(requiredBufferLength, 0);
            auto* adapterList = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
            const ULONG secondQueryResult = ::GetAdaptersAddresses(
                AF_INET6,
                queryFlags,
                nullptr,
                adapterList,
                &requiredBufferLength);

            if (secondQueryResult != NO_ERROR)
            {
                return ipv6List;
            }

            std::unordered_set<Ipv6Bytes, Ipv6BytesHasher> uniqueAddressSet;
            for (IP_ADAPTER_ADDRESSES* adapter = adapterList; adapter != nullptr; adapter = adapter->Next)
            {
                if (adapter->OperStatus != IfOperStatusUp)
                {
                    continue;
                }

                for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress;
                    unicast != nullptr;
                    unicast = unicast->Next)
                {
                    if (unicast->Address.lpSockaddr == nullptr ||
                        unicast->Address.lpSockaddr->sa_family != AF_INET6)
                    {
                        continue;
                    }

                    auto* ipv6Address = reinterpret_cast<sockaddr_in6*>(unicast->Address.lpSockaddr);
                    // 过滤未指定地址 :: ，避免无效 bind。
                    if (::IN6_IS_ADDR_UNSPECIFIED(&ipv6Address->sin6_addr))
                    {
                        continue;
                    }

                    Ipv6Bytes addressBytes{};
                    std::memcpy(addressBytes.data(), &ipv6Address->sin6_addr, addressBytes.size());
                    uniqueAddressSet.insert(addressBytes);
                }
            }

            ipv6List.assign(uniqueAddressSet.begin(), uniqueAddressSet.end());
            return ipv6List;
        }

        // OpenCaptureSockets：
        // - 为每个活动 IPv4/IPv6 地址创建 Raw Socket；
        // - 开启 SIO_RCVALL 抓取 IP 层报文。
        inline std::vector<CaptureSocketEntry> OpenCaptureSockets(std::string* errorTextOut)
        {
            if (errorTextOut != nullptr)
            {
                errorTextOut->clear();
            }

            std::vector<CaptureSocketEntry> socketList;
            const std::vector<std::uint32_t> localIpv4List = EnumerateActiveIpv4Addresses();
            const std::vector<Ipv6Bytes> localIpv6List = EnumerateActiveIpv6Addresses();
            if (localIpv4List.empty() && localIpv6List.empty())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = "未枚举到可用 IPv4/IPv6 接口。";
                }
                return socketList;
            }

            // configureCaptureSocket 用途：统一执行 RCVALL、接收缓冲、非阻塞配置。
            // 说明：
            // - 某些驱动/虚拟网卡对 RCVALL_ON 支持不稳定；
            // - 增加 RCVALL_IPLEVEL 兜底，可显著降低“能抓 TCP 但丢 UDP/入站”的概率。
            auto configureCaptureSocket = [](SOCKET rawSocket, DWORD& captureModeOut) -> bool
                {
                    captureModeOut = RCVALL_ON;
                    const std::array<DWORD, 2> captureModeCandidates =
                    {
                        RCVALL_ON,
                        RCVALL_IPLEVEL
                    };

                    bool captureModeApplied = false;
                    for (const DWORD candidateMode : captureModeCandidates)
                    {
                        DWORD receiveAllFlag = candidateMode;
                        DWORD bytesReturned = 0;
                        if (::WSAIoctl(
                            rawSocket,
                            SIO_RCVALL,
                            &receiveAllFlag,
                            sizeof(receiveAllFlag),
                            nullptr,
                            0,
                            &bytesReturned,
                            nullptr,
                            nullptr) == SOCKET_ERROR)
                        {
                            continue;
                        }

                        captureModeOut = candidateMode;
                        captureModeApplied = true;
                        break;
                    }
                    if (!captureModeApplied)
                    {
                        return false;
                    }

                    // receiveBufferBytes 用途：提升内核接收缓冲上限，降低突发流量下的 socket 丢包概率。
                    int receiveBufferBytes = 8 * 1024 * 1024;
                    (void)::setsockopt(
                        rawSocket,
                        SOL_SOCKET,
                        SO_RCVBUF,
                        reinterpret_cast<const char*>(&receiveBufferBytes),
                        static_cast<int>(sizeof(receiveBufferBytes)));

                    // 设为非阻塞：配合 select 周期轮询，避免线程卡死。
                    u_long nonBlockingEnabled = 1;
                    ::ioctlsocket(rawSocket, FIONBIO, &nonBlockingEnabled);
                    return true;
                };

            // 先创建 IPv4 抓包 socket。
            for (const std::uint32_t localIpv4 : localIpv4List)
            {
                SOCKET rawSocket = ::socket(AF_INET, SOCK_RAW, IPPROTO_IP);
                if (rawSocket == INVALID_SOCKET)
                {
                    continue;
                }

                sockaddr_in bindAddress{};
                bindAddress.sin_family = AF_INET;
                bindAddress.sin_port = 0;
                bindAddress.sin_addr.s_addr = htonl(localIpv4);
                if (::bind(rawSocket, reinterpret_cast<sockaddr*>(&bindAddress), sizeof(bindAddress)) == SOCKET_ERROR)
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                DWORD captureMode = RCVALL_ON;
                if (!configureCaptureSocket(rawSocket, captureMode))
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                CaptureSocketEntry socketEntry;
                socketEntry.socketValue = rawSocket;
                socketEntry.addressFamily = AF_INET;
                socketEntry.localIpv4HostOrder = localIpv4;
                socketEntry.captureMode = captureMode;
                socketEntry.localAddressText = Ipv4HostToString(localIpv4);
                socketList.push_back(socketEntry);
            }

            // 再创建 IPv6 抓包 socket。
            for (const Ipv6Bytes& localIpv6 : localIpv6List)
            {
                SOCKET rawSocket = ::socket(AF_INET6, SOCK_RAW, IPPROTO_IPV6);
                if (rawSocket == INVALID_SOCKET)
                {
                    continue;
                }

                sockaddr_in6 bindAddress{};
                bindAddress.sin6_family = AF_INET6;
                bindAddress.sin6_port = 0;
                std::memcpy(&bindAddress.sin6_addr, localIpv6.data(), localIpv6.size());
                if (::bind(rawSocket, reinterpret_cast<sockaddr*>(&bindAddress), sizeof(bindAddress)) == SOCKET_ERROR)
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                DWORD captureMode = RCVALL_ON;
                if (!configureCaptureSocket(rawSocket, captureMode))
                {
                    ::closesocket(rawSocket);
                    continue;
                }

                CaptureSocketEntry socketEntry;
                socketEntry.socketValue = rawSocket;
                socketEntry.addressFamily = AF_INET6;
                socketEntry.localIpv6Bytes = localIpv6;
                socketEntry.captureMode = captureMode;
                socketEntry.localAddressText = Ipv6BytesToString(localIpv6);
                socketList.push_back(socketEntry);
            }

            if (socketList.empty() && errorTextOut != nullptr)
            {
                const int lastError = ::WSAGetLastError();
                std::ostringstream stream;
                stream << "Raw Socket 打开失败，通常需要管理员权限。"
                    << " " << MakeWinSockErrorText(lastError);
                *errorTextOut = stream.str();
            }

            return socketList;
        }

        // CloseCaptureSockets：关闭全部 Raw Socket。
        inline void CloseCaptureSockets(std::vector<CaptureSocketEntry>& socketList)
        {
            for (CaptureSocketEntry& socketEntry : socketList)
            {
                if (socketEntry.socketValue != INVALID_SOCKET)
                {
                    ::closesocket(socketEntry.socketValue);
                    socketEntry.socketValue = INVALID_SOCKET;
                }
            }
            socketList.clear();
        }

        // ParseIpv4Packet：
        // - 解析 IPv4 报文中的 TCP/UDP 头；
        // - 返回“本机相关流量”（出站/入站均保留）。
        inline bool ParseIpv4Packet(
            const std::uint8_t* packetBuffer,
            const std::size_t packetBufferLength,
            const std::unordered_set<std::uint32_t>& localIpv4Set,
            PacketRecord& packetOut)
        {
            if (packetBuffer == nullptr || packetBufferLength < 20)
            {
                return false;
            }

            // IPv4 首字节：高 4 位 Version，低 4 位 IHL(32bit words)。
            const std::uint8_t versionAndHeaderLength = packetBuffer[0];
            const std::uint8_t ipVersion = static_cast<std::uint8_t>(versionAndHeaderLength >> 4);
            const std::size_t ipHeaderLength = static_cast<std::size_t>(versionAndHeaderLength & 0x0F) * 4ULL;
            if (ipVersion != 4 || ipHeaderLength < 20 || packetBufferLength < ipHeaderLength)
            {
                return false;
            }

            // IP Total Length 是网络字节序，且可能小于接收缓冲长度。
            std::size_t totalLength = static_cast<std::size_t>(ReadNetworkUInt16(packetBuffer + 2));
            if (totalLength < ipHeaderLength)
            {
                return false;
            }
            totalLength = std::min(totalLength, packetBufferLength);

            // 协议字段：6=TCP，17=UDP。
            const std::uint8_t protocolField = packetBuffer[9];
            PacketTransportProtocol protocol = PacketTransportProtocol::Tcp;
            if (protocolField == IPPROTO_TCP)
            {
                protocol = PacketTransportProtocol::Tcp;
            }
            else if (protocolField == IPPROTO_UDP)
            {
                protocol = PacketTransportProtocol::Udp;
            }
            else
            {
                return false;
            }

            // 源/目的地址按主机序存储，便于后续比较与哈希。
            const std::uint32_t sourceIpv4 = ReadNetworkUInt32(packetBuffer + 12);
            const std::uint32_t destinationIpv4 = ReadNetworkUInt32(packetBuffer + 16);

            // 方向判定：
            // - source 在本机地址集合 => Outbound；
            // - destination 在本机地址集合 => Inbound；
            // - 源和目的都在本机地址集合 => 本机双端点通信（先标记为 Unknown，后续再拆分为入/出两条）。
            // - 两侧都不在本机地址集合 => 与本机无关（直接忽略）。
            const bool sourceIsLocal = (localIpv4Set.find(sourceIpv4) != localIpv4Set.end());
            const bool destinationIsLocal = (localIpv4Set.find(destinationIpv4) != localIpv4Set.end());
            const bool localToLocalAmbiguous = sourceIsLocal && destinationIsLocal;
            PacketDirection direction = PacketDirection::Unknown;
            if (sourceIsLocal && !destinationIsLocal)
            {
                direction = PacketDirection::Outbound;
            }
            else if (!sourceIsLocal && destinationIsLocal)
            {
                direction = PacketDirection::Inbound;
            }

            // 仅保留与本机相关的流量；若两侧都不是本机地址则跳过。
            if (!sourceIsLocal && !destinationIsLocal)
            {
                return false;
            }

            // sourcePort/destinationPort 用途：暂存报文头原始方向端口（src/dst）。
            std::uint16_t sourcePort = 0;
            std::uint16_t destinationPort = 0;
            std::size_t payloadOffset = 0;

            if (protocol == PacketTransportProtocol::Tcp)
            {
                // TCP 最小头 20 字节。
                const std::size_t tcpOffset = ipHeaderLength;
                if (totalLength < tcpOffset + 20)
                {
                    return false;
                }

                sourcePort = ReadNetworkUInt16(packetBuffer + tcpOffset);
                destinationPort = ReadNetworkUInt16(packetBuffer + tcpOffset + 2);

                const std::uint8_t tcpDataOffsetField = packetBuffer[tcpOffset + 12];
                const std::size_t tcpHeaderLength = static_cast<std::size_t>((tcpDataOffsetField >> 4) & 0x0F) * 4ULL;
                if (tcpHeaderLength < 20 || totalLength < tcpOffset + tcpHeaderLength)
                {
                    return false;
                }
                payloadOffset = tcpOffset + tcpHeaderLength;
            }
            else
            {
                // UDP 固定 8 字节头。
                const std::size_t udpOffset = ipHeaderLength;
                if (totalLength < udpOffset + 8)
                {
                    return false;
                }

                sourcePort = ReadNetworkUInt16(packetBuffer + udpOffset);
                destinationPort = ReadNetworkUInt16(packetBuffer + udpOffset + 2);
                payloadOffset = udpOffset + 8;
            }

            // local/remote 端点统一转换为“以本机为 local”的语义，便于 UI 与 PID 解析。
            // 说明：
            // - 本机双端点通信（localToLocalAmbiguous=true）先保持 src->dst 原始方向，
            //   由上层在 PID 解析阶段补发一条 Inbound 记录，实现双向完整展示。
            std::uint32_t localIpv4 = sourceIpv4;
            std::uint32_t remoteIpv4 = destinationIpv4;
            std::uint16_t localPort = sourcePort;
            std::uint16_t remotePort = destinationPort;
            if (direction == PacketDirection::Inbound)
            {
                localIpv4 = destinationIpv4;
                remoteIpv4 = sourceIpv4;
                localPort = destinationPort;
                remotePort = sourcePort;
            }

            // 组装输出结构，供 UI 直接使用。
            packetOut.protocol = protocol;
            packetOut.direction = direction;
            packetOut.processId = 0;
            packetOut.processName.clear();
            packetOut.localAddress = Ipv4HostToString(localIpv4);
            packetOut.localPort = localPort;
            packetOut.remoteAddress = Ipv4HostToString(remoteIpv4);
            packetOut.remotePort = remotePort;
            packetOut.totalPacketSize = static_cast<std::uint32_t>(totalLength);
            packetOut.payloadOffset = payloadOffset;
            packetOut.payloadSize = (payloadOffset <= totalLength)
                ? static_cast<std::uint32_t>(totalLength - payloadOffset)
                : 0U;
            packetOut.localToLocalAmbiguous = localToLocalAmbiguous;

            const std::size_t retainedLength = std::min(totalLength, kMaxRetainedPacketBytes);
            packetOut.packetBytes.assign(packetBuffer, packetBuffer + retainedLength);
            packetOut.packetBytesTruncated = (retainedLength < totalLength);

            return true;
        }

        // ParseIpv6Packet：
        // - 解析 IPv6 报文中的 TCP/UDP 头；
        // - 支持常见扩展头跳转，尽量减少“有流量但被误判为不可解析”的漏采。
        inline bool ParseIpv6Packet(
            const std::uint8_t* packetBuffer,
            const std::size_t packetBufferLength,
            const std::unordered_set<Ipv6Bytes, Ipv6BytesHasher>& localIpv6Set,
            PacketRecord& packetOut)
        {
            if (packetBuffer == nullptr || packetBufferLength < 40)
            {
                return false;
            }

            // IPv6 版本字段位于首字节高 4 位。
            const std::uint8_t versionField = static_cast<std::uint8_t>(packetBuffer[0] >> 4);
            if (versionField != 6)
            {
                return false;
            }

            // payloadLengthValue 用途：IPv6 负载长度（不含固定 40 字节头）。
            const std::size_t payloadLengthValue = static_cast<std::size_t>(ReadNetworkUInt16(packetBuffer + 4));
            std::size_t totalLength = 40 + payloadLengthValue;
            if (totalLength < 40)
            {
                return false;
            }
            totalLength = std::min(totalLength, packetBufferLength);

            const Ipv6Bytes sourceIpv6 = ReadIpv6Bytes(packetBuffer + 8);
            const Ipv6Bytes destinationIpv6 = ReadIpv6Bytes(packetBuffer + 24);

            const bool sourceIsLocal = (localIpv6Set.find(sourceIpv6) != localIpv6Set.end());
            const bool destinationIsLocal = (localIpv6Set.find(destinationIpv6) != localIpv6Set.end());
            const bool localToLocalAmbiguous = sourceIsLocal && destinationIsLocal;
            PacketDirection direction = PacketDirection::Unknown;
            if (sourceIsLocal && !destinationIsLocal)
            {
                direction = PacketDirection::Outbound;
            }
            else if (!sourceIsLocal && destinationIsLocal)
            {
                direction = PacketDirection::Inbound;
            }
            if (!sourceIsLocal && !destinationIsLocal)
            {
                return false;
            }

            // nextHeader 用途：当前协议头类型，初始值来自固定 IPv6 头。
            std::uint8_t nextHeader = packetBuffer[6];
            // transportOffset 用途：当前解析到的头偏移，最终应定位到 TCP/UDP 头起点。
            std::size_t transportOffset = 40;

            // 跳过扩展头直到 TCP/UDP。
            while (true)
            {
                if (nextHeader == IPPROTO_TCP || nextHeader == IPPROTO_UDP)
                {
                    break;
                }

                if (transportOffset >= totalLength)
                {
                    return false;
                }

                // No Next Header：没有 L4 内容，直接结束。
                if (nextHeader == 59)
                {
                    return false;
                }

                // Fragment 头：长度固定 8 字节。
                if (nextHeader == 44)
                {
                    if (transportOffset + 8 > totalLength)
                    {
                        return false;
                    }

                    // fragmentOffsetField 用途：片偏移 + 标志位；非首片通常不含 TCP/UDP 端口，无法还原端点。
                    const std::uint16_t fragmentOffsetField = ReadNetworkUInt16(packetBuffer + transportOffset + 2);
                    const std::uint16_t fragmentOffset = static_cast<std::uint16_t>((fragmentOffsetField & 0xFFF8U) >> 3);
                    if (fragmentOffset != 0)
                    {
                        return false;
                    }

                    nextHeader = packetBuffer[transportOffset];
                    transportOffset += 8;
                    continue;
                }

                // AH 头：长度单位为 32bit words，且不含前 2 个 32bit words。
                if (nextHeader == 51)
                {
                    if (transportOffset + 2 > totalLength)
                    {
                        return false;
                    }
                    const std::uint8_t ahLengthUnit = packetBuffer[transportOffset + 1];
                    const std::size_t ahHeaderLength = static_cast<std::size_t>(ahLengthUnit + 2U) * 4ULL;
                    if (ahHeaderLength < 8 || transportOffset + ahHeaderLength > totalLength)
                    {
                        return false;
                    }

                    nextHeader = packetBuffer[transportOffset];
                    transportOffset += ahHeaderLength;
                    continue;
                }

                // ESP 头在用户态无法可靠解析到端口，直接跳过该包。
                if (nextHeader == 50)
                {
                    return false;
                }

                // Hop-by-Hop / Routing / Destination Options：统一按 (HdrExtLen+1)*8 计算。
                if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60)
                {
                    if (transportOffset + 2 > totalLength)
                    {
                        return false;
                    }
                    const std::uint8_t extLengthUnit = packetBuffer[transportOffset + 1];
                    const std::size_t extHeaderLength = (static_cast<std::size_t>(extLengthUnit) + 1ULL) * 8ULL;
                    if (extHeaderLength < 8 || transportOffset + extHeaderLength > totalLength)
                    {
                        return false;
                    }

                    nextHeader = packetBuffer[transportOffset];
                    transportOffset += extHeaderLength;
                    continue;
                }

                // 其它协议头类型暂不支持。
                return false;
            }

            PacketTransportProtocol protocol = PacketTransportProtocol::Tcp;
            std::uint16_t sourcePort = 0;
            std::uint16_t destinationPort = 0;
            std::size_t payloadOffset = 0;

            if (nextHeader == IPPROTO_TCP)
            {
                protocol = PacketTransportProtocol::Tcp;
                if (transportOffset + 20 > totalLength)
                {
                    return false;
                }

                sourcePort = ReadNetworkUInt16(packetBuffer + transportOffset);
                destinationPort = ReadNetworkUInt16(packetBuffer + transportOffset + 2);

                const std::uint8_t tcpDataOffsetField = packetBuffer[transportOffset + 12];
                const std::size_t tcpHeaderLength = static_cast<std::size_t>((tcpDataOffsetField >> 4) & 0x0F) * 4ULL;
                if (tcpHeaderLength < 20 || transportOffset + tcpHeaderLength > totalLength)
                {
                    return false;
                }
                payloadOffset = transportOffset + tcpHeaderLength;
            }
            else
            {
                protocol = PacketTransportProtocol::Udp;
                if (transportOffset + 8 > totalLength)
                {
                    return false;
                }

                sourcePort = ReadNetworkUInt16(packetBuffer + transportOffset);
                destinationPort = ReadNetworkUInt16(packetBuffer + transportOffset + 2);
                payloadOffset = transportOffset + 8;
            }

            Ipv6Bytes localIpv6 = sourceIpv6;
            Ipv6Bytes remoteIpv6 = destinationIpv6;
            std::uint16_t localPort = sourcePort;
            std::uint16_t remotePort = destinationPort;
            if (direction == PacketDirection::Inbound)
            {
                localIpv6 = destinationIpv6;
                remoteIpv6 = sourceIpv6;
                localPort = destinationPort;
                remotePort = sourcePort;
            }

            packetOut.protocol = protocol;
            packetOut.direction = direction;
            packetOut.processId = 0;
            packetOut.processName.clear();
            packetOut.localAddress = Ipv6BytesToString(localIpv6);
            packetOut.localPort = localPort;
            packetOut.remoteAddress = Ipv6BytesToString(remoteIpv6);
            packetOut.remotePort = remotePort;
            packetOut.totalPacketSize = static_cast<std::uint32_t>(totalLength);
            packetOut.payloadOffset = payloadOffset;
            packetOut.payloadSize = (payloadOffset <= totalLength)
                ? static_cast<std::uint32_t>(totalLength - payloadOffset)
                : 0U;
            packetOut.localToLocalAmbiguous = localToLocalAmbiguous;

            const std::size_t retainedLength = std::min(totalLength, kMaxRetainedPacketBytes);
            packetOut.packetBytes.assign(packetBuffer, packetBuffer + retainedLength);
            packetOut.packetBytesTruncated = (retainedLength < totalLength);

            return true;
        }

        // ConnectionPidResolver：
        // - 周期刷新 TCP/UDP owning PID 表；
        // - 提供“连接四元组/本地端点 -> PID”映射能力。
        class ConnectionPidResolver final
        {
        public:
            // ResolveProcessId：按 IPv4 端点解析归属 PID。
            std::uint32_t ResolveProcessId(
                const PacketTransportProtocol protocol,
                const std::uint32_t localIpv4,
                const std::uint16_t localPort,
                const std::uint32_t remoteIpv4,
                const std::uint16_t remotePort)
            {
                const std::uint64_t nowTickMs = NowTickMs();
                RefreshIfRequired(nowTickMs);

                if (protocol == PacketTransportProtocol::Tcp)
                {
                    // 先做 TCP 四元组精确匹配。
                    const TcpEndpointKey exactKey{ localIpv4, localPort, remoteIpv4, remotePort };
                    const auto exactIterator = m_tcpPidByQuad.find(exactKey);
                    if (exactIterator != m_tcpPidByQuad.end())
                    {
                        return exactIterator->second;
                    }

                    // 再回退到本地端点匹配（例如某些瞬时连接阶段）。
                    const std::uint64_t localExactKey = LocalEndpointKey(localIpv4, localPort);
                    const auto localExactIterator = m_tcpPidByLocalEndpoint.find(localExactKey);
                    if (localExactIterator != m_tcpPidByLocalEndpoint.end())
                    {
                        return localExactIterator->second;
                    }

                    // 再尝试 0.0.0.0:port 的占位映射。
                    const std::uint64_t localWildcardKey = LocalEndpointKey(0, localPort);
                    const auto localWildcardIterator = m_tcpPidByLocalEndpoint.find(localWildcardKey);
                    if (localWildcardIterator != m_tcpPidByLocalEndpoint.end())
                    {
                        return localWildcardIterator->second;
                    }
                    return 0;
                }

                // UDP 主要按本地端点映射。
                const std::uint64_t udpLocalKey = LocalEndpointKey(localIpv4, localPort);
                const auto udpIterator = m_udpPidByLocalEndpoint.find(udpLocalKey);
                if (udpIterator != m_udpPidByLocalEndpoint.end())
                {
                    return udpIterator->second;
                }

                // 同样提供 0.0.0.0:port fallback。
                const std::uint64_t udpWildcardKey = LocalEndpointKey(0, localPort);
                const auto udpWildcardIterator = m_udpPidByLocalEndpoint.find(udpWildcardKey);
                if (udpWildcardIterator != m_udpPidByLocalEndpoint.end())
                {
                    return udpWildcardIterator->second;
                }
                return 0;
            }

            // ResolveProcessIdV6：按 IPv6 端点解析归属 PID。
            std::uint32_t ResolveProcessIdV6(
                const PacketTransportProtocol protocol,
                const Ipv6Bytes& localIpv6,
                const std::uint16_t localPort,
                const Ipv6Bytes& remoteIpv6,
                const std::uint16_t remotePort)
            {
                const std::uint64_t nowTickMs = NowTickMs();
                RefreshIfRequired(nowTickMs);

                if (protocol == PacketTransportProtocol::Tcp)
                {
                    const TcpEndpointKeyV6 exactKey{ localIpv6, localPort, remoteIpv6, remotePort };
                    const auto exactIterator = m_tcpPidByQuadV6.find(exactKey);
                    if (exactIterator != m_tcpPidByQuadV6.end())
                    {
                        return exactIterator->second;
                    }

                    const Ipv6LocalEndpointKey localExactKey{ localIpv6, localPort };
                    const auto localExactIterator = m_tcpPidByLocalEndpointV6.find(localExactKey);
                    if (localExactIterator != m_tcpPidByLocalEndpointV6.end())
                    {
                        return localExactIterator->second;
                    }

                    // IPv6 wildcard fallback：:::port。
                    const Ipv6Bytes wildcardAddress{};
                    const Ipv6LocalEndpointKey localWildcardKey{ wildcardAddress, localPort };
                    const auto localWildcardIterator = m_tcpPidByLocalEndpointV6.find(localWildcardKey);
                    if (localWildcardIterator != m_tcpPidByLocalEndpointV6.end())
                    {
                        return localWildcardIterator->second;
                    }
                    return 0;
                }

                const Ipv6LocalEndpointKey udpLocalKey{ localIpv6, localPort };
                const auto udpIterator = m_udpPidByLocalEndpointV6.find(udpLocalKey);
                if (udpIterator != m_udpPidByLocalEndpointV6.end())
                {
                    return udpIterator->second;
                }

                const Ipv6Bytes wildcardAddress{};
                const Ipv6LocalEndpointKey udpWildcardKey{ wildcardAddress, localPort };
                const auto udpWildcardIterator = m_udpPidByLocalEndpointV6.find(udpWildcardKey);
                if (udpWildcardIterator != m_udpPidByLocalEndpointV6.end())
                {
                    return udpWildcardIterator->second;
                }
                return 0;
            }

        private:
            // RefreshIfRequired：连接表刷新节流，避免每包都调用 IPHLPAPI。
            void RefreshIfRequired(const std::uint64_t nowTickMs)
            {
                // kRefreshIntervalMs 用途：连接表刷新节流间隔。
                // 下调到 250ms 可提升短连接/短 UDP 会话的 PID 映射命中率。
                constexpr std::uint64_t kRefreshIntervalMs = 250;
                if (m_lastRefreshTickMs != 0 &&
                    nowTickMs - m_lastRefreshTickMs < kRefreshIntervalMs)
                {
                    return;
                }

                RefreshTcpTable();
                RefreshUdpTable();
                m_lastRefreshTickMs = nowTickMs;
            }

            // RefreshTcpTable：刷新 TCP 四元组映射（IPv4 + IPv6）。
            void RefreshTcpTable()
            {
                m_tcpPidByQuad.clear();
                m_tcpPidByLocalEndpoint.clear();
                m_tcpPidByQuadV6.clear();
                m_tcpPidByLocalEndpointV6.clear();

                // 先刷新 IPv4。
                DWORD requiredLength = 0;
                const DWORD sizeQueryResultV4 = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (sizeQueryResultV4 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBuffer(requiredLength, 0);
                    DWORD tableLength = requiredLength;
                    const DWORD result = ::GetExtendedTcpTable(
                        tableBuffer.data(),
                        &tableLength,
                        FALSE,
                        AF_INET,
                        TCP_TABLE_OWNER_PID_ALL,
                        0);
                    if (result == NO_ERROR)
                    {
                        auto* tcpTable = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(tableBuffer.data());
                        if (tcpTable != nullptr)
                        {
                            m_tcpPidByQuad.reserve(tcpTable->dwNumEntries);
                            m_tcpPidByLocalEndpoint.reserve(tcpTable->dwNumEntries);

                            for (DWORD index = 0; index < tcpTable->dwNumEntries; ++index)
                            {
                                const MIB_TCPROW_OWNER_PID& row = tcpTable->table[index];
                                const std::uint32_t localIpv4 = ntohl(row.dwLocalAddr);
                                const std::uint16_t localPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint32_t remoteIpv4 = ntohl(row.dwRemoteAddr);
                                const std::uint16_t remotePort = ntohs(static_cast<u_short>(row.dwRemotePort & 0xFFFFu));
                                const std::uint32_t ownerPid = row.dwOwningPid;

                                const TcpEndpointKey quadKey{ localIpv4, localPort, remoteIpv4, remotePort };
                                m_tcpPidByQuad[quadKey] = ownerPid;

                                const std::uint64_t localKey = LocalEndpointKey(localIpv4, localPort);
                                m_tcpPidByLocalEndpoint[localKey] = ownerPid;
                            }
                        }
                    }
                }

                // 再刷新 IPv6。
                requiredLength = 0;
                const DWORD sizeQueryResultV6 = ::GetExtendedTcpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET6,
                    TCP_TABLE_OWNER_PID_ALL,
                    0);
                if (sizeQueryResultV6 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBufferV6(requiredLength, 0);
                    DWORD tableLengthV6 = requiredLength;
                    const DWORD resultV6 = ::GetExtendedTcpTable(
                        tableBufferV6.data(),
                        &tableLengthV6,
                        FALSE,
                        AF_INET6,
                        TCP_TABLE_OWNER_PID_ALL,
                        0);
                    if (resultV6 == NO_ERROR)
                    {
                        auto* tcpTableV6 = reinterpret_cast<PMIB_TCP6TABLE_OWNER_PID>(tableBufferV6.data());
                        if (tcpTableV6 != nullptr)
                        {
                            m_tcpPidByQuadV6.reserve(tcpTableV6->dwNumEntries);
                            m_tcpPidByLocalEndpointV6.reserve(tcpTableV6->dwNumEntries);
                            for (DWORD index = 0; index < tcpTableV6->dwNumEntries; ++index)
                            {
                                const MIB_TCP6ROW_OWNER_PID& row = tcpTableV6->table[index];
                                Ipv6Bytes localIpv6{};
                                Ipv6Bytes remoteIpv6{};
                                std::memcpy(localIpv6.data(), row.ucLocalAddr, localIpv6.size());
                                std::memcpy(remoteIpv6.data(), row.ucRemoteAddr, remoteIpv6.size());
                                const std::uint16_t localPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint16_t remotePort = ntohs(static_cast<u_short>(row.dwRemotePort & 0xFFFFu));
                                const std::uint32_t ownerPid = row.dwOwningPid;

                                const TcpEndpointKeyV6 quadKey{ localIpv6, localPort, remoteIpv6, remotePort };
                                m_tcpPidByQuadV6[quadKey] = ownerPid;

                                const Ipv6LocalEndpointKey localKey{ localIpv6, localPort };
                                m_tcpPidByLocalEndpointV6[localKey] = ownerPid;
                            }
                        }
                    }
                }
            }

            // RefreshUdpTable：刷新 UDP 本地端点映射（IPv4 + IPv6）。
            void RefreshUdpTable()
            {
                m_udpPidByLocalEndpoint.clear();
                m_udpPidByLocalEndpointV6.clear();

                // 先刷新 IPv4。
                DWORD requiredLength = 0;
                const DWORD sizeQueryResultV4 = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (sizeQueryResultV4 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBuffer(requiredLength, 0);
                    DWORD tableLength = requiredLength;
                    const DWORD result = ::GetExtendedUdpTable(
                        tableBuffer.data(),
                        &tableLength,
                        FALSE,
                        AF_INET,
                        UDP_TABLE_OWNER_PID,
                        0);
                    if (result == NO_ERROR)
                    {
                        auto* udpTable = reinterpret_cast<PMIB_UDPTABLE_OWNER_PID>(tableBuffer.data());
                        if (udpTable != nullptr)
                        {
                            m_udpPidByLocalEndpoint.reserve(udpTable->dwNumEntries);
                            for (DWORD index = 0; index < udpTable->dwNumEntries; ++index)
                            {
                                const MIB_UDPROW_OWNER_PID& row = udpTable->table[index];
                                const std::uint32_t localIpv4 = ntohl(row.dwLocalAddr);
                                const std::uint16_t localPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint32_t ownerPid = row.dwOwningPid;
                                const std::uint64_t localKey = LocalEndpointKey(localIpv4, localPort);
                                m_udpPidByLocalEndpoint[localKey] = ownerPid;
                            }
                        }
                    }
                }

                // 再刷新 IPv6。
                requiredLength = 0;
                const DWORD sizeQueryResultV6 = ::GetExtendedUdpTable(
                    nullptr,
                    &requiredLength,
                    FALSE,
                    AF_INET6,
                    UDP_TABLE_OWNER_PID,
                    0);
                if (sizeQueryResultV6 == ERROR_INSUFFICIENT_BUFFER && requiredLength > 0)
                {
                    std::vector<std::uint8_t> tableBufferV6(requiredLength, 0);
                    DWORD tableLengthV6 = requiredLength;
                    const DWORD resultV6 = ::GetExtendedUdpTable(
                        tableBufferV6.data(),
                        &tableLengthV6,
                        FALSE,
                        AF_INET6,
                        UDP_TABLE_OWNER_PID,
                        0);
                    if (resultV6 == NO_ERROR)
                    {
                        auto* udpTableV6 = reinterpret_cast<PMIB_UDP6TABLE_OWNER_PID>(tableBufferV6.data());
                        if (udpTableV6 != nullptr)
                        {
                            m_udpPidByLocalEndpointV6.reserve(udpTableV6->dwNumEntries);
                            for (DWORD index = 0; index < udpTableV6->dwNumEntries; ++index)
                            {
                                const MIB_UDP6ROW_OWNER_PID& row = udpTableV6->table[index];
                                Ipv6Bytes localIpv6{};
                                std::memcpy(localIpv6.data(), row.ucLocalAddr, localIpv6.size());
                                const std::uint16_t localPort = ntohs(static_cast<u_short>(row.dwLocalPort & 0xFFFFu));
                                const std::uint32_t ownerPid = row.dwOwningPid;
                                const Ipv6LocalEndpointKey localKey{ localIpv6, localPort };
                                m_udpPidByLocalEndpointV6[localKey] = ownerPid;
                            }
                        }
                    }
                }
            }

        private:
            std::uint64_t m_lastRefreshTickMs = 0; // 上次刷新连接表时间戳。

            // TCP 映射（四元组精确）。
            std::unordered_map<TcpEndpointKey, std::uint32_t, TcpEndpointKeyHasher> m_tcpPidByQuad;

            // TCP 映射（本地端点 fallback）。
            std::unordered_map<std::uint64_t, std::uint32_t> m_tcpPidByLocalEndpoint;

            // UDP 映射（本地端点）。
            std::unordered_map<std::uint64_t, std::uint32_t> m_udpPidByLocalEndpoint;

            // TCP IPv6 映射（四元组精确）。
            std::unordered_map<TcpEndpointKeyV6, std::uint32_t, TcpEndpointKeyV6Hasher> m_tcpPidByQuadV6;

            // TCP IPv6 映射（本地端点 fallback）。
            std::unordered_map<Ipv6LocalEndpointKey, std::uint32_t, Ipv6LocalEndpointKeyHasher> m_tcpPidByLocalEndpointV6;

            // UDP IPv6 映射（本地端点）。
            std::unordered_map<Ipv6LocalEndpointKey, std::uint32_t, Ipv6LocalEndpointKeyHasher> m_udpPidByLocalEndpointV6;
        };

        // ProcessNameResolver：
        // - 为 PID 提供轻量缓存，避免每包都跨进程查询进程名。
        class ProcessNameResolver final
        {
        public:
            // ResolveProcessName：解析并缓存进程名。
            std::string ResolveProcessName(const std::uint32_t processId)
            {
                if (processId == 0)
                {
                    return std::string();
                }

                const std::uint64_t nowTickMs = NowTickMs();
                const auto cacheIterator = m_cacheByPid.find(processId);
                if (cacheIterator != m_cacheByPid.end())
                {
                    constexpr std::uint64_t kCacheTtlMs = 2500;
                    if (nowTickMs - cacheIterator->second.lastUpdateTickMs <= kCacheTtlMs)
                    {
                        return cacheIterator->second.processName;
                    }
                }

                std::string processName = ks::process::GetProcessNameByPID(processId);
                if (processName.empty())
                {
                    processName = std::string("PID-") + std::to_string(processId);
                }

                CacheEntry cacheEntry;
                cacheEntry.processName = processName;
                cacheEntry.lastUpdateTickMs = nowTickMs;
                m_cacheByPid[processId] = cacheEntry;
                return processName;
            }

        private:
            // CacheEntry：进程名缓存条目。
            struct CacheEntry
            {
                std::string processName;           // 缓存的进程名。
                std::uint64_t lastUpdateTickMs = 0;// 更新时间戳。
            };

            std::unordered_map<std::uint32_t, CacheEntry> m_cacheByPid; // PID -> 名称缓存。
        };
    } // namespace detail

    // TrafficMonitorService：
    // - 对外提供 Start/Stop 与回调注册；
    // - 内部线程负责抓包、PID 解析、限速控制。
    class TrafficMonitorService final
    {
    public:
        // PacketCallback：上报单条报文记录。
        using PacketCallback = std::function<void(const PacketRecord&)>;

        // StatusCallback：上报状态文本（启动失败、线程停止、权限提示等）。
        using StatusCallback = std::function<void(const std::string&)>;

        // RateLimitActionCallback：上报限速动作事件（挂起/恢复）。
        using RateLimitActionCallback = std::function<void(const RateLimitActionEvent&)>;

    public:
        // 构造：初始化状态，不启动线程。
        TrafficMonitorService() = default;

        // 析构：确保线程停止并释放资源。
        ~TrafficMonitorService()
        {
            StopCapture();
        }

        // SetPacketCallback：设置报文回调。
        void SetPacketCallback(PacketCallback callback)
        {
            std::lock_guard<std::mutex> guard(m_stateMutex);
            m_packetCallback = std::move(callback);
        }

        // SetStatusCallback：设置状态回调。
        void SetStatusCallback(StatusCallback callback)
        {
            std::lock_guard<std::mutex> guard(m_stateMutex);
            m_statusCallback = std::move(callback);
        }

        // SetRateLimitActionCallback：设置限速动作回调。
        void SetRateLimitActionCallback(RateLimitActionCallback callback)
        {
            std::lock_guard<std::mutex> guard(m_stateMutex);
            m_rateLimitActionCallback = std::move(callback);
        }

        // StartCapture：
        // - 启动后台抓包线程；
        // - 若已运行则直接返回 true。
        bool StartCapture()
        {
            if (m_running.load(std::memory_order_relaxed))
            {
                return true;
            }

            // 如果上一次线程已自然退出但尚未 join，这里先清理。
            if (m_captureThread.joinable())
            {
                m_captureThread.join();
            }

            m_running.store(true, std::memory_order_relaxed);
            m_captureReady.store(false, std::memory_order_release);
            m_stopAttempted.store(false);
            m_resumeAtExitSucceeded.store(true);
            try
            {
                m_captureThread = std::thread([this]() { runCaptureThread(); });
            }
            catch (...)
            {
                m_running.store(false, std::memory_order_relaxed);
                emitStatus("抓包线程创建失败。");
                return false;
            }
            return true;
        }

        // StopCapture：
        // - 请求线程退出；
        // - 阻塞等待线程收尾（包括恢复被限速挂起的进程）。
        void RequestStopCapture() noexcept
        {
            m_running.store(false, std::memory_order_relaxed);
        }

        bool StopCapture()
        {
            RequestStopCapture();
            if (m_captureThread.joinable())
            {
                m_captureThread.join();
            }
            // The capture thread makes the initial restore attempt. A failed
            // restore remains owned for an explicit retained-cleanup Retry.
            if (!m_stopAttempted.exchange(true)) return m_resumeAtExitSucceeded.load();
            return forceResumeAllSuspendedProcesses();
        }

        // IsRunning：查询抓包线程是否处于运行状态。
        bool IsRunning() const
        {
            return m_running.load(std::memory_order_relaxed);
        }

        // IsCaptureReady：只有既有 Raw Socket 已成功打开并完成本机地址准备才返回 true。
        // 供无 UI 的采集所有者区分线程已创建与真实来源就绪；不表示系统具有完整抓包覆盖。
        bool IsCaptureReady() const noexcept
        {
            return m_captureReady.load(std::memory_order_acquire);
        }

        // UpsertRateLimitRule：
        // - 新增或更新某 PID + 创建时间的限速规则；
        // - 缺少进程身份或速率上限时拒绝创建，避免 PID 回收后误操作。
        void UpsertRateLimitRule(const ProcessRateLimitRule& inputRule)
        {
            if (inputRule.processId == 0 ||
                inputRule.processCreationTime100ns == 0 ||
                inputRule.bytesPerSecond == 0)
            {
                return;
            }

            ProcessRateLimitRule sanitizedRule = inputRule;
            sanitizedRule.suspendDurationMs = std::clamp<std::uint32_t>(sanitizedRule.suspendDurationMs, 50, 2000);

            bool needResumeExistingProcess = false;
            ProcessRateLimitRule existingRule{};
            {
                std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                RateLimitRuntime& runtime = m_rateLimitByPid[sanitizedRule.processId];
                needResumeExistingProcess = runtime.currentlySuspended;
                existingRule = runtime.rule;
                runtime.rule = sanitizedRule;
                runtime.windowStartTickMs = detail::NowTickMs();
                runtime.currentWindowBytes = 0;
                runtime.currentlySuspended = false;
                runtime.resumeTickMs = 0;
                // triggerCount 保留历史，方便 UI 查看总触发次数。
            }

            // 只恢复与旧规则身份匹配的实例，避免 PID 已回收时误恢复其它进程。
            if (needResumeExistingProcess)
            {
                std::string ignoredDetailText;
                (void)ks::process::ResumeProcessIfCreationTimeMatches(
                    existingRule.processId,
                    existingRule.processCreationTime100ns,
                    &ignoredDetailText);
            }
        }

        // RemoveRateLimitRule：移除指定 PID 的限速规则。
        bool RemoveRateLimitRule(const std::uint32_t processId)
        {
            if (processId == 0)
            {
                return false;
            }

            bool needResumeProcess = false;
            ProcessRateLimitRule existingRule{};
            {
                std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                const auto iterator = m_rateLimitByPid.find(processId);
                if (iterator == m_rateLimitByPid.end())
                {
                    return false;
                }
                needResumeProcess = iterator->second.currentlySuspended;
                existingRule = iterator->second.rule;
                m_rateLimitByPid.erase(iterator);
            }

            // 删除规则时只恢复原始实例，避免 PID 回收后影响新进程。
            if (needResumeProcess)
            {
                std::string ignoredDetailText;
                (void)ks::process::ResumeProcessIfCreationTimeMatches(
                    existingRule.processId,
                    existingRule.processCreationTime100ns,
                    &ignoredDetailText);
            }
            return true;
        }

        // ClearRateLimitRules：清空全部限速规则。
        void ClearRateLimitRules()
        {
            std::vector<ProcessRateLimitRule> rulesNeedResume;
            {
                std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                rulesNeedResume.reserve(m_rateLimitByPid.size());
                for (const auto& [processId, runtime] : m_rateLimitByPid)
                {
                    (void)processId;
                    if (runtime.currentlySuspended)
                    {
                        rulesNeedResume.push_back(runtime.rule);
                    }
                }
                m_rateLimitByPid.clear();
            }

            // 批量清空规则时只恢复各自保存的原始进程实例。
            for (const ProcessRateLimitRule& limitRule : rulesNeedResume)
            {
                std::string ignoredDetailText;
                (void)ks::process::ResumeProcessIfCreationTimeMatches(
                    limitRule.processId,
                    limitRule.processCreationTime100ns,
                    &ignoredDetailText);
            }
        }

        // SnapshotRateLimitRules：
        // - 返回限速规则快照（线程安全）；
        // - UI 可直接用于表格刷新。
        std::vector<ProcessRateLimitSnapshot> SnapshotRateLimitRules() const
        {
            std::vector<ProcessRateLimitSnapshot> snapshotList;
            std::lock_guard<std::mutex> guard(m_rateLimitMutex);
            snapshotList.reserve(m_rateLimitByPid.size());

            for (const auto& [processId, runtime] : m_rateLimitByPid)
            {
                (void)processId;
                ProcessRateLimitSnapshot snapshot;
                snapshot.rule = runtime.rule;
                snapshot.currentWindowBytes = runtime.currentWindowBytes;
                snapshot.triggerCount = runtime.triggerCount;
                snapshot.currentlySuspended = runtime.currentlySuspended;
                snapshotList.push_back(snapshot);
            }

            std::sort(
                snapshotList.begin(),
                snapshotList.end(),
                [](const ProcessRateLimitSnapshot& left, const ProcessRateLimitSnapshot& right)
                {
                    return left.rule.processId < right.rule.processId;
                });

            return snapshotList;
        }

    private:
        // RateLimitRuntime：限速规则的运行时状态。
        struct RateLimitRuntime
        {
            ProcessRateLimitRule rule;          // 用户配置。
            std::uint64_t windowStartTickMs = 0;// 当前统计窗口起始 ms。
            std::uint64_t currentWindowBytes = 0;// 当前窗口累计发送字节。
            bool currentlySuspended = false;    // 当前是否由本组件挂起。
            std::uint64_t resumeTickMs = 0;     // 计划恢复时间戳。
            std::uint64_t triggerCount = 0;     // 历史触发次数。
        };

    private:
        // runCaptureThread：后台线程主循环。
        void runCaptureThread()
        {
            // 线程启动后先初始化 WinSock。
            WSADATA wsaData{};
            const int startupResult = ::WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (startupResult != 0)
            {
                std::ostringstream stream;
                stream << "WSAStartup 失败: " << detail::MakeWinSockErrorText(startupResult);
                emitStatus(stream.str());
                m_running.store(false, std::memory_order_relaxed);
                return;
            }

            // 打开全部可用 Raw Socket（按活动 IPv4/IPv6 接口逐一绑定）。
            std::string socketOpenError;
            std::vector<detail::CaptureSocketEntry> captureSockets = detail::OpenCaptureSockets(&socketOpenError);
            if (captureSockets.empty())
            {
                std::ostringstream stream;
                stream << "网络监控启动失败: " << socketOpenError;
                emitStatus(stream.str());
                ::WSACleanup();
                m_running.store(false, std::memory_order_relaxed);
                return;
            }

            {
                std::size_t ipv4SocketCount = 0;
                std::size_t ipv6SocketCount = 0;
                std::size_t ipLevelFallbackCount = 0;
                for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
                {
                    if (socketEntry.addressFamily == AF_INET)
                    {
                        ++ipv4SocketCount;
                    }
                    else if (socketEntry.addressFamily == AF_INET6)
                    {
                        ++ipv6SocketCount;
                    }
                    if (socketEntry.captureMode == RCVALL_IPLEVEL)
                    {
                        ++ipLevelFallbackCount;
                    }
                }

                std::ostringstream stream;
                stream << "网络监控已启动，绑定接口数: " << captureSockets.size()
                    << "（IPv4=" << ipv4SocketCount
                    << ", IPv6=" << ipv6SocketCount
                    << ", IPLEVEL兜底=" << ipLevelFallbackCount
                    << "）";
                emitStatus(stream.str());
            }

            // 构建本机地址集合，用于快速判定报文方向。
            std::unordered_set<std::uint32_t> localIpv4Set;
            std::unordered_set<detail::Ipv6Bytes, detail::Ipv6BytesHasher> localIpv6Set;
            for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
            {
                if (socketEntry.addressFamily == AF_INET)
                {
                    localIpv4Set.insert(socketEntry.localIpv4HostOrder);
                }
                else if (socketEntry.addressFamily == AF_INET6)
                {
                    localIpv6Set.insert(socketEntry.localIpv6Bytes);
                }
            }

            // 补充回环地址：
            // - 某些环境下回环地址不会出现在活动网卡枚举里；
            // - 预先纳入集合可避免方向判定误判为 Unknown。
            localIpv4Set.insert(0x7F000001U); // 127.0.0.1
            detail::Ipv6Bytes ipv6Loopback{};
            ipv6Loopback[15] = 1;             // ::1
            localIpv6Set.insert(ipv6Loopback);

            detail::ConnectionPidResolver pidResolver;
            detail::ProcessNameResolver processNameResolver;
            std::vector<std::uint8_t> receiveBuffer(65536, 0);
            m_captureReady.store(true, std::memory_order_release);

            // 抓包循环：select 等待 + recv 读取 + 解析 + 回调。
            while (m_running.load(std::memory_order_relaxed))
            {
                const std::uint64_t nowTickMs = detail::NowTickMs();

                // 每轮先处理“应恢复”的限速任务，避免进程长时间挂起。
                consumeResumeActions(nowTickMs);

                fd_set readSet{};
                FD_ZERO(&readSet);
                for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
                {
                    if (socketEntry.socketValue != INVALID_SOCKET)
                    {
                        FD_SET(socketEntry.socketValue, &readSet);
                    }
                }

                // 轮询周期进一步下调到 25ms：
                // - 缩短 socket 内核缓冲驻留时间，降低突发场景丢包概率；
                // - 对短 UDP 报文和短连接的捕获更友好。
                timeval timeout{};
                timeout.tv_sec = 0;
                timeout.tv_usec = 25000;
                const int selectResult = ::select(0, &readSet, nullptr, nullptr, &timeout);
                if (selectResult == SOCKET_ERROR)
                {
                    const int selectError = ::WSAGetLastError();
                    std::ostringstream stream;
                    stream << "select 失败: " << detail::MakeWinSockErrorText(selectError);
                    emitStatus(stream.str());
                    break;
                }

                if (selectResult <= 0)
                {
                    continue;
                }

                for (const detail::CaptureSocketEntry& socketEntry : captureSockets)
                {
                    if (socketEntry.socketValue == INVALID_SOCKET)
                    {
                        continue;
                    }
                    if (FD_ISSET(socketEntry.socketValue, &readSet) == 0)
                    {
                        continue;
                    }

                    // maxPacketsPerSocketPerTick 用途：单轮对单个 socket 的最大拉取包数，避免某个高流量接口饿死其它接口。
                    // 上调上限可减少高流量下 backlog 累积，提升 UDP/入站突发包保留率。
                    constexpr std::size_t maxPacketsPerSocketPerTick = 1024;
                    std::size_t consumedPacketCount = 0;
                    while (m_running.load(std::memory_order_relaxed) &&
                        consumedPacketCount < maxPacketsPerSocketPerTick)
                    {
                        const int receivedLength = ::recv(
                            socketEntry.socketValue,
                            reinterpret_cast<char*>(receiveBuffer.data()),
                            static_cast<int>(receiveBuffer.size()),
                            0);
                        if (receivedLength <= 0)
                        {
                            // recvError 用途：识别“当前已读空”(wouldblock)与真实异常。
                            const int recvError = ::WSAGetLastError();
                            if (recvError == WSAEWOULDBLOCK || recvError == WSAETIMEDOUT)
                            {
                                break;
                            }
                            // 真实异常：本轮退出当前 socket，交给下一轮 select 再尝试。
                            break;
                        }
                        ++consumedPacketCount;

                        PacketRecord packetRecord;
                        bool parseOk = false;
                        if (socketEntry.addressFamily == AF_INET)
                        {
                            parseOk = detail::ParseIpv4Packet(
                                receiveBuffer.data(),
                                static_cast<std::size_t>(receivedLength),
                                localIpv4Set,
                                packetRecord);
                        }
                        else if (socketEntry.addressFamily == AF_INET6)
                        {
                            parseOk = detail::ParseIpv6Packet(
                                receiveBuffer.data(),
                                static_cast<std::size_t>(receivedLength),
                                localIpv6Set,
                                packetRecord);
                        }
                        if (!parseOk)
                        {
                            continue;
                        }

                        // captureTickMs 用途：同一原始报文衍生出的多条记录（本机双端点场景）共享同一采集时刻。
                        const std::uint64_t captureTickMs = detail::NowTickMs();

                        // finalizeAndEmitRecord 用途：
                        // - 为记录分配序号与时间戳；
                        // - 解析进程名；
                        // - 执行限速判定并上报到 UI。
                        auto finalizeAndEmitRecord = [&](PacketRecord& record)
                            {
                                record.sequenceId = m_packetSequence.fetch_add(1, std::memory_order_relaxed) + 1;
                                record.captureTimestampMs = captureTickMs;
                                record.processName = processNameResolver.ResolveProcessName(record.processId);
                                consumeRateLimitForPacket(record);
                                emitPacket(record);
                            };

                        // 端口映射 PID + 名称缓存解析。
                        if (socketEntry.addressFamily == AF_INET)
                        {
                            // sourceIpv4Host/destinationIpv4Host 用途：保留报文原始 src/dst 地址（主机序）。
                            const std::uint32_t sourceIpv4Host = detail::ReadNetworkUInt32(receiveBuffer.data() + 12);
                            const std::uint32_t destinationIpv4Host = detail::ReadNetworkUInt32(receiveBuffer.data() + 16);

                            // 本机双端点通信：同一原始包拆分为 Outbound + Inbound 两条记录，避免“入站全部缺失”。
                            if (packetRecord.localToLocalAmbiguous)
                            {
                                PacketRecord outboundRecord = packetRecord;
                                outboundRecord.direction = PacketDirection::Outbound;
                                outboundRecord.localAddress = detail::Ipv4HostToString(sourceIpv4Host);
                                outboundRecord.localPort = packetRecord.localPort;
                                outboundRecord.remoteAddress = detail::Ipv4HostToString(destinationIpv4Host);
                                outboundRecord.remotePort = packetRecord.remotePort;
                                outboundRecord.localToLocalAmbiguous = false;
                                outboundRecord.processId = pidResolver.ResolveProcessId(
                                    outboundRecord.protocol,
                                    sourceIpv4Host,
                                    outboundRecord.localPort,
                                    destinationIpv4Host,
                                    outboundRecord.remotePort);

                                PacketRecord inboundRecord = packetRecord;
                                inboundRecord.direction = PacketDirection::Inbound;
                                inboundRecord.localAddress = detail::Ipv4HostToString(destinationIpv4Host);
                                inboundRecord.localPort = packetRecord.remotePort;
                                inboundRecord.remoteAddress = detail::Ipv4HostToString(sourceIpv4Host);
                                inboundRecord.remotePort = packetRecord.localPort;
                                inboundRecord.localToLocalAmbiguous = false;
                                inboundRecord.processId = pidResolver.ResolveProcessId(
                                    inboundRecord.protocol,
                                    destinationIpv4Host,
                                    inboundRecord.localPort,
                                    sourceIpv4Host,
                                    inboundRecord.remotePort);

                                finalizeAndEmitRecord(outboundRecord);
                                finalizeAndEmitRecord(inboundRecord);
                                continue;
                            }

                            // localIpv4Host/remoteIpv4Host 用途：统一转换为“本机为 local”的地址语义。
                            std::uint32_t localIpv4Host = sourceIpv4Host;
                            std::uint32_t remoteIpv4Host = destinationIpv4Host;
                            if (packetRecord.direction == PacketDirection::Inbound)
                            {
                                localIpv4Host = destinationIpv4Host;
                                remoteIpv4Host = sourceIpv4Host;
                            }
                            packetRecord.processId = pidResolver.ResolveProcessId(
                                packetRecord.protocol,
                                localIpv4Host,
                                packetRecord.localPort,
                                remoteIpv4Host,
                                packetRecord.remotePort);
                            packetRecord.localToLocalAmbiguous = false;
                            finalizeAndEmitRecord(packetRecord);
                        }
                        else if (socketEntry.addressFamily == AF_INET6)
                        {
                            const detail::Ipv6Bytes sourceIpv6 = detail::ReadIpv6Bytes(receiveBuffer.data() + 8);
                            const detail::Ipv6Bytes destinationIpv6 = detail::ReadIpv6Bytes(receiveBuffer.data() + 24);

                            // IPv6 本机双端点通信同样拆分为双向记录，补足入站统计与过滤能力。
                            if (packetRecord.localToLocalAmbiguous)
                            {
                                PacketRecord outboundRecord = packetRecord;
                                outboundRecord.direction = PacketDirection::Outbound;
                                outboundRecord.localAddress = detail::Ipv6BytesToString(sourceIpv6);
                                outboundRecord.localPort = packetRecord.localPort;
                                outboundRecord.remoteAddress = detail::Ipv6BytesToString(destinationIpv6);
                                outboundRecord.remotePort = packetRecord.remotePort;
                                outboundRecord.localToLocalAmbiguous = false;
                                outboundRecord.processId = pidResolver.ResolveProcessIdV6(
                                    outboundRecord.protocol,
                                    sourceIpv6,
                                    outboundRecord.localPort,
                                    destinationIpv6,
                                    outboundRecord.remotePort);

                                PacketRecord inboundRecord = packetRecord;
                                inboundRecord.direction = PacketDirection::Inbound;
                                inboundRecord.localAddress = detail::Ipv6BytesToString(destinationIpv6);
                                inboundRecord.localPort = packetRecord.remotePort;
                                inboundRecord.remoteAddress = detail::Ipv6BytesToString(sourceIpv6);
                                inboundRecord.remotePort = packetRecord.localPort;
                                inboundRecord.localToLocalAmbiguous = false;
                                inboundRecord.processId = pidResolver.ResolveProcessIdV6(
                                    inboundRecord.protocol,
                                    destinationIpv6,
                                    inboundRecord.localPort,
                                    sourceIpv6,
                                    inboundRecord.remotePort);

                                finalizeAndEmitRecord(outboundRecord);
                                finalizeAndEmitRecord(inboundRecord);
                                continue;
                            }

                            detail::Ipv6Bytes localIpv6 = sourceIpv6;
                            detail::Ipv6Bytes remoteIpv6 = destinationIpv6;
                            if (packetRecord.direction == PacketDirection::Inbound)
                            {
                                localIpv6 = destinationIpv6;
                                remoteIpv6 = sourceIpv6;
                            }
                            packetRecord.processId = pidResolver.ResolveProcessIdV6(
                                packetRecord.protocol,
                                localIpv6,
                                packetRecord.localPort,
                                remoteIpv6,
                                packetRecord.remotePort);
                            packetRecord.localToLocalAmbiguous = false;
                            finalizeAndEmitRecord(packetRecord);
                        }
                    }
                }
            }

            // 线程退出前恢复所有“仍被本模块挂起”的进程，避免残留影响。
            m_resumeAtExitSucceeded.store(forceResumeAllSuspendedProcesses());

            detail::CloseCaptureSockets(captureSockets);
            ::WSACleanup();

            m_captureReady.store(false, std::memory_order_release);
            m_running.store(false, std::memory_order_relaxed);
            emitStatus("网络监控已停止。");
        }

        // consumeRateLimitForPacket：
        // - 对单包更新对应 PID 的发送窗口统计；
        // - 若超限则触发 SuspendProcess。
        void consumeRateLimitForPacket(const PacketRecord& packetRecord)
        {
            // 限速策略仅针对“发送方向”，入站流量不参与阈值统计。
            if (packetRecord.direction != PacketDirection::Outbound)
            {
                return;
            }

            if (packetRecord.processId == 0)
            {
                return;
            }

            std::optional<RateLimitActionEvent> suspendEvent;
            std::uint64_t expectedCreationTime100ns = 0U;
            {
                std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                const auto iterator = m_rateLimitByPid.find(packetRecord.processId);
                if (iterator == m_rateLimitByPid.end())
                {
                    return;
                }

                RateLimitRuntime& runtime = iterator->second;
                if (!runtime.rule.enabled || runtime.rule.bytesPerSecond == 0)
                {
                    return;
                }

                const std::uint64_t nowTickMs = packetRecord.captureTimestampMs;
                if (runtime.windowStartTickMs == 0 || nowTickMs - runtime.windowStartTickMs >= 1000)
                {
                    runtime.windowStartTickMs = nowTickMs;
                    runtime.currentWindowBytes = 0;
                }

                runtime.currentWindowBytes += packetRecord.totalPacketSize;
                if (runtime.currentlySuspended)
                {
                    return;
                }

                if (runtime.currentWindowBytes > runtime.rule.bytesPerSecond)
                {
                    runtime.currentlySuspended = true;
                    runtime.resumeTickMs = nowTickMs + runtime.rule.suspendDurationMs;
                    runtime.triggerCount += 1;

                    RateLimitActionEvent event;
                    event.timestampMs = nowTickMs;
                    event.processId = runtime.rule.processId;
                    event.actionType = RateLimitActionType::SuspendProcess;
                    event.actionSucceeded = false;
                    event.configuredBytesPerSecond = runtime.rule.bytesPerSecond;
                    event.detailText = "触发限速，准备挂起进程。";
                    expectedCreationTime100ns = runtime.rule.processCreationTime100ns;
                    suspendEvent = event;
                }
            }

            if (!suspendEvent.has_value())
            {
                return;
            }

            std::string detailText;
            const bool suspendOk = ks::process::SuspendProcessIfCreationTimeMatches(
                packetRecord.processId,
                expectedCreationTime100ns,
                &detailText);
            suspendEvent->actionSucceeded = suspendOk;
            if (suspendOk)
            {
                suspendEvent->detailText = "限速触发：进程已挂起。";
            }
            else
            {
                suspendEvent->detailText = "限速触发失败（挂起失败）: " + detailText;

                // 挂起失败则立即回滚“挂起状态”，避免后续逻辑误判。
                std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                const auto iterator = m_rateLimitByPid.find(packetRecord.processId);
                if (iterator != m_rateLimitByPid.end() &&
                    iterator->second.rule.processCreationTime100ns == expectedCreationTime100ns)
                {
                    iterator->second.currentlySuspended = false;
                    iterator->second.resumeTickMs = 0;
                }
            }

            emitRateLimitAction(*suspendEvent);
        }

        // consumeResumeActions：
        // - 扫描全部规则，找出“已到恢复时间”的 PID；
        // - 执行 ResumeProcess 并上报动作事件。
        void consumeResumeActions(const std::uint64_t nowTickMs)
        {
            std::vector<ProcessRateLimitRule> rulesToResume;
            {
                std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                for (auto& [processId, runtime] : m_rateLimitByPid)
                {
                    (void)processId;
                    if (!runtime.currentlySuspended)
                    {
                        continue;
                    }
                    if (runtime.resumeTickMs > nowTickMs)
                    {
                        continue;
                    }

                    runtime.currentlySuspended = false;
                    runtime.resumeTickMs = 0;
                    rulesToResume.push_back(runtime.rule);
                }
            }

            for (const ProcessRateLimitRule& limitRule : rulesToResume)
            {
                std::string detailText;
                const bool resumeOk = ks::process::ResumeProcessIfCreationTimeMatches(
                    limitRule.processId,
                    limitRule.processCreationTime100ns,
                    &detailText);

                if (!resumeOk)
                {
                    std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                    const auto found = m_rateLimitByPid.find(limitRule.processId);
                    if (found != m_rateLimitByPid.end()
                        && found->second.rule.processCreationTime100ns == limitRule.processCreationTime100ns)
                    {
                        // Preserve the unresolved recovery witness for STOP/Retry,
                        // without adding automatic retries to normal sampling.
                        found->second.currentlySuspended = true;
                        found->second.resumeTickMs = (std::numeric_limits<std::uint64_t>::max)();
                    }
                }

                RateLimitActionEvent event;
                event.timestampMs = nowTickMs;
                event.processId = limitRule.processId;
                event.actionType = RateLimitActionType::ResumeProcess;
                event.actionSucceeded = resumeOk;
                event.configuredBytesPerSecond = 0;
                event.detailText = resumeOk
                    ? "限速窗口结束：进程已恢复。"
                    : ("进程恢复失败: " + detailText);
                emitRateLimitAction(event);
            }
        }

        // forceResumeAllSuspendedProcesses：
        // - 在线程退出阶段执行；
        // - 保证不会遗留“被限速挂起”的进程。
        bool forceResumeAllSuspendedProcesses()
        {
            bool allResumed = true;
            std::vector<ProcessRateLimitRule> rulesToResume;
            {
                std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                for (auto& [processId, runtime] : m_rateLimitByPid)
                {
                    (void)processId;
                    if (!runtime.currentlySuspended)
                    {
                        continue;
                    }
                    rulesToResume.push_back(runtime.rule);
                }
            }

            for (const ProcessRateLimitRule& limitRule : rulesToResume)
            {
                std::string detailText;
                const bool resumeOk = ks::process::ResumeProcessIfCreationTimeMatches(
                    limitRule.processId,
                    limitRule.processCreationTime100ns,
                    &detailText);

                allResumed = allResumed && resumeOk;
                if (resumeOk)
                {
                    std::lock_guard<std::mutex> guard(m_rateLimitMutex);
                    const auto found = m_rateLimitByPid.find(limitRule.processId);
                    if (found != m_rateLimitByPid.end()
                        && found->second.rule.processCreationTime100ns == limitRule.processCreationTime100ns)
                    {
                        found->second.currentlySuspended = false;
                        found->second.resumeTickMs = 0;
                    }
                }

                RateLimitActionEvent event;
                event.timestampMs = detail::NowTickMs();
                event.processId = limitRule.processId;
                event.actionType = RateLimitActionType::ResumeProcess;
                event.actionSucceeded = resumeOk;
                event.configuredBytesPerSecond = 0;
                event.detailText = resumeOk
                    ? "监控停止：已恢复此前挂起的进程。"
                    : ("监控停止：恢复进程失败: " + detailText);
                emitRateLimitAction(event);
            }
            return allResumed;
        }

        // emitPacket：触发报文回调（线程安全复制回调对象）。
        void emitPacket(const PacketRecord& packetRecord) const
        {
            PacketCallback callbackCopy;
            {
                std::lock_guard<std::mutex> guard(m_stateMutex);
                callbackCopy = m_packetCallback;
            }
            if (callbackCopy)
            {
                callbackCopy(packetRecord);
            }
        }

        // emitStatus：触发状态回调。
        void emitStatus(const std::string& statusText) const
        {
            StatusCallback callbackCopy;
            {
                std::lock_guard<std::mutex> guard(m_stateMutex);
                callbackCopy = m_statusCallback;
            }
            if (callbackCopy)
            {
                callbackCopy(statusText);
            }
        }

        // emitRateLimitAction：触发限速动作回调。
        void emitRateLimitAction(const RateLimitActionEvent& actionEvent) const
        {
            RateLimitActionCallback callbackCopy;
            {
                std::lock_guard<std::mutex> guard(m_stateMutex);
                callbackCopy = m_rateLimitActionCallback;
            }
            if (callbackCopy)
            {
                callbackCopy(actionEvent);
            }
        }

    private:
        mutable std::mutex m_stateMutex; // 保护回调函数对象。
        PacketCallback m_packetCallback; // 报文事件回调。
        StatusCallback m_statusCallback; // 状态文本回调。
        RateLimitActionCallback m_rateLimitActionCallback; // 限速动作回调。

        std::atomic<bool> m_running{ false }; // 抓包线程运行标记。
        std::atomic<bool> m_captureReady{ false }; // 原生 sockets 与解析上下文实际就绪状态。
        std::thread m_captureThread;          // 后台抓包线程对象。
        std::atomic_bool m_stopAttempted{false};
        std::atomic_bool m_resumeAtExitSucceeded{true};
        std::atomic<std::uint64_t> m_packetSequence{ 0 }; // 报文序号生成器。

        mutable std::mutex m_rateLimitMutex; // 保护限速规则容器。
        std::unordered_map<std::uint32_t, RateLimitRuntime> m_rateLimitByPid; // PID -> 规则运行态。
    };
} // namespace ks::network
