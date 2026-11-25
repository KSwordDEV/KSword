#pragma once

#include "../../../evidence/EvidenceJson.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace ks::r3::monitor {

// Windows manifest provider 的规范小写 GUID，使用与归档 UUID 一致的文本写法。
inline constexpr std::string_view kKernelFileProviderId = "edd08927-9cc4-4e65-b970-c2560fb5c289";

struct KernelFileSourceView {
    std::string_view sourceId;       // 采集者提供的来源实例标识。
    std::string_view sourceEpoch;    // 采集者提供的本次会话代次 UUID。
    std::string_view bootId;         // 两个时钟共同所属的启动实例，由采集者核实。
    std::string_view fileTimeClockId; // 来源 FILETIME 时钟标识。
};

struct KernelFileReceiveQpcView {
    std::string_view clockId;    // 收包时钟标识，独立于来源时钟。
    std::uint64_t ticks = 0;    // 实测的收包 QPC tick，零是有效值。
    std::uint64_t frequencyHz = 0; // 实测 QPC 频率。
};

struct KernelFileDescriptor {
    std::uint16_t id = 0;      // Windows 原生 EVENT_DESCRIPTOR.Id。
    std::uint8_t version = 0; // 布局版本。
    std::uint8_t channel = 0; // 原生通道。
    std::uint8_t level = 0;   // 原生级别。
    std::uint8_t opcode = 0;  // 原生操作码。
    std::uint16_t task = 0;    // 原生任务。
    std::uint64_t keyword = 0; // 原生关键字掩码。
};

// 输入仅借用到函数返回。文件值必须来自调用方按版本解码的该条事件。
struct KernelFileObservationView {
    std::string_view providerId;                // 规范小写 provider GUID。
    KernelFileSourceView source;                // 已有来源及其时钟身份。
    KernelFileDescriptor descriptor;            // 原生 ETW 描述符。
    std::uint64_t sourceFileTime100ns = 0;        // 来源 EVENT_HEADER.TimeStamp 的 FILETIME 值。
    std::optional<KernelFileReceiveQpcView> receiveQpc; // 实测接收时钟，可缺。
    std::uint32_t headerPid = 0;                 // 记录上下文 PID。
    std::uint32_t headerTid = 0;                 // 记录上下文 TID。
    std::uint16_t originalPayloadBytes = 0;     // ETW UserDataLength。
    std::span<const std::uint8_t> payloadPrefix; // 从 UserData 开头取得的原始字节。

    std::optional<std::string_view> pathUtf8;   // 事件直接提供的路径，保留原有命名空间。
    std::optional<std::uint64_t> fileObject;     // 原生 FileObject 关联线索。
    std::optional<std::uint64_t> fileKey;        // 原生 FileKey 关联线索。
    std::optional<std::uint64_t> irp;            // 原生 IRP 关联线索。
    std::optional<std::uint64_t> requestedBytes; // 请求长度，仅 Read/Write。
    std::optional<std::uint64_t> byteOffset;     // 请求偏移，仅 Read/Write。
    std::optional<std::uint32_t> ntStatus;       // 原生完成状态，仅 OperationEnd。
    std::optional<std::uint32_t> issuingThreadId; // 原生 v1 线索，独立于线程实例和报头 TID。
    std::optional<std::uint16_t> headerFlags;    // 原生 ETW 头部布局与编码标记，离线手工输入可以缺失。
    std::optional<std::uint16_t> extendedDataCount; // 原生扩展项数，扩展负载没有整体复制。
    std::optional<std::string_view> activityId; // 原生活动 ID，规范小写 GUID 文本。
    std::optional<std::string_view> relatedActivityId; // 明确扩展项中的原生活动 ID。
};

// C++ 投影专用枚举。归档字典、事件编号及阶段编号由归档所有者分配。
enum class KernelFileObservationKind { ReadRequest, WriteRequest, OperationEnd };
enum class KernelFileProjectionStatus {
    Ok, UnsupportedProvider, UnsupportedEvent, InvalidSource,
    InvalidReceiveClock, InvalidPayloadLength, InvalidPath, InvalidFileFields,
    TruncatedPayload, MalformedPayload,
};

struct KernelFileRawEvidence {
    Ksword::Evidence::JsonValue metadata;  // RawRecord v1 对象元数据，含来源专用字段。
    std::vector<std::uint8_t> inlineBytes;  // 独立持有的 UserData 前缀。
};

struct KernelFileCanonicalEvidence {
    KernelFileObservationKind kind;         // 用于选择现有语义的投影枚举。
    std::uint64_t sourceTimestamp;          // 拟写入核心的来源 FILETIME。
    std::optional<std::uint64_t> receiveQpc; // 拟写入核心的已知 QPC，缺值保留缺失。
    Ksword::Evidence::JsonValue fields;     // 只含当前基础字段目录定义的字段。
};

struct KernelFileEvidence {
    KernelFileRawEvidence raw;              // 原始证据及元数据。
    KernelFileCanonicalEvidence canonical;  // 同一观察的规范投影。
};

struct KernelFileProjection {
    KernelFileProjectionStatus status;        // 不支持与输入错误分别报告。
    std::optional<KernelFileEvidence> evidence; // 仅 Ok 时携带拥有内存的结果。
};

// 由离线调用方传入单条 ETW 观察，返回 RawRecord/CanonicalEvent 的数据准备结果。
// 项目、采样、流和字典引用由归档所有者在实际写入时绑定。
KernelFileProjection ProjectKernelFileObservation(const KernelFileObservationView& observation);

} // namespace ks::r3::monitor
