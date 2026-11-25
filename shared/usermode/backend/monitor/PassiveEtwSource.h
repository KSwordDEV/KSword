#pragma once

#include "EtwSessionController.h"
#include "KernelFileEvidenceProjection.h"

#include <deque>

namespace ks::r3::monitor {

inline constexpr GUID kKernelFileProviderGuid{
    0xedd08927, 0x9cc4, 0x4e65, {0xb9, 0x70, 0xc2, 0x56, 0x0f, 0xb5, 0xc2, 0x89},
};
inline constexpr std::size_t kPassiveEtwMaxPayloadBytes = 16U * 1024U;
inline constexpr std::size_t kPassiveEtwMaxQueuedRecords = 4096;
inline constexpr std::size_t kPassiveEtwMaxQueuedPayloadBytes = 32U * 1024U * 1024U;

struct PassiveEtwOptions {
    GUID provider{};                             // 显式启用的唯一 provider。
    std::optional<std::uint32_t> headerPid;       // 可选报头过滤，零是有效过滤值。
    std::uint8_t level = TRACE_LEVEL_VERBOSE;    // EnableTraceEx2 的 Level 上限。
    std::uint64_t matchAnyKeyword = 0;           // 原生关键字掩码，零沿用 Windows 语义。
    std::size_t maxPayloadBytes = 4096;          // 每条复制的 UserData 前缀上限。
    std::size_t maxQueuedRecords = 512;          // 队列满时丢弃新记录。
};

enum class PassiveEtwState {
    Idle, Starting, Running, Stopping, Stopped, AccessDenied, ProviderUnavailable, Failed, CleanupPending,
};

struct PassiveEtwStatus {
    PassiveEtwState state = PassiveEtwState::Idle; // Readiness/运行状态以原生消费阶段为准。
    ULONG inputError = ERROR_SUCCESS;             // 选项或本端启动准备错误。
    EtwSessionEvidence native;                    // Start/Enable/Open/Process/Stop 与系统丢失各自保留。
    std::string sourceEpoch;                      // 每次受理启动生成的 UUID，来源序号缺失。
    std::uint64_t providerEvents = 0;             // 匹配 provider 的回调，成功 Enable 可仍为零。
    std::uint64_t headerFiltered = 0;            // 本端报头范围抑制，仅供诊断。
    std::uint64_t enqueued = 0;                  // 累计进入本端队列。
    std::uint64_t queueDropped = 0;              // 本端队列满的丢失，与系统计数独立。
    std::uint64_t payloadTruncated = 0;          // 接纳记录中因前缀限制而截短的条数。
    std::uint64_t malformedPayload = 0;          // 接纳记录中负载指针与长度不一致的条数。
    std::size_t queued = 0;                      // 当前排队未读取条数。
};

struct PassiveEtwRecord {
    std::string sourceEpoch;                       // 随记录保留来源代次，借用式复制本身留空。
    GUID provider{};                               // 原生 provider GUID。
    KernelFileDescriptor descriptor;               // 通用 ETW EVENT_DESCRIPTOR 的各字段。
    std::uint16_t headerFlags = 0;                  // 原生头标志，含事件布局位宽。
    std::uint32_t headerPid = 0, headerTid = 0;     // 仅记录上下文，不声明 actor 或 target。
    std::uint64_t sourceFileTime100ns = 0;          // ClientContext=2 的来源时钟原始值。
    std::optional<std::uint64_t> receivedQpc;       // 回调时实测的独立单调刻度。
    std::uint64_t qpcFrequencyHz = 0;               // 接收时钟频率，零表示不可得。
    GUID activityId{};                             // 原生头 ActivityId，零 GUID 原样保留。
    std::optional<GUID> relatedActivityId;           // 有效且唯一的 RelatedActivityId 扩展项。
    std::uint16_t extendedDataCount = 0;            // 保留原始项数，扩展负载未采。
    std::uint16_t originalPayloadBytes = 0;        // 原生 UserDataLength。
    bool malformedPayload = false;                 // 非空长度未提供负载指针。
    std::vector<std::uint8_t> payloadPrefix;        // 拥有的 UserData 字节，非文件实际内容。
};

enum class PassiveEtwDecodeStatus { Decoded, RawOnly, UnsupportedLayout, Truncated, Malformed };

struct PassiveKernelFileDecode {
    PassiveEtwDecodeStatus status = PassiveEtwDecodeStatus::RawOnly; // 未支持的记录仍可用作原始证据。
    std::optional<KernelFileObservationKind> kind;                   // 成功解码后的精确观察种类。
    std::optional<std::uint64_t> irp, fileObject, fileKey, byteOffset; // 弱关联键及请求偏移。
    std::optional<std::uint32_t> requestedBytes, ntStatus;             // 各自只在相应阶段可用。
    std::optional<std::uint32_t> issuingThreadId;                     // v1 载荷线索，无线程实例证明。
};

// 借用实时 EVENT_RECORD，返回独立的报头、时钟和负载前缀。仅用于 FILETIME 来源。
PassiveEtwRecord CopyPassiveEtwRecord(const EVENT_RECORD& record, std::size_t maxPayloadBytes,
    std::optional<std::uint64_t> receivedQpc = std::nullopt, std::uint64_t qpcFrequencyHz = 0);

// 按精确的 Kernel-File provider、任务、版本和位宽读取已登记的标量，不推导对象身份。
PassiveKernelFileDecode DecodePassiveKernelFileRecord(const PassiveEtwRecord& record);

// 严格解码后生成既有原始/规范投影。归档方提供本次来源、启动及接收时钟标识。
KernelFileProjection ProjectPassiveKernelFileRecord(const PassiveEtwRecord& record,
    const KernelFileSourceView& source, std::string_view receiveClockId);

// 各宿主持有独立实例。生命周期操作在其工作线程调用，排空/快照可在其他线程调用。
class PassiveEtwSource final {
public:
    PassiveEtwSource();
    ~PassiveEtwSource();
    PassiveEtwSource(const PassiveEtwSource&) = delete;
    PassiveEtwSource& operator=(const PassiveEtwSource&) = delete;

    // true 表示启动已受理，查询 status() 区分 Starting、Running、原生失败和任何生产者观测。
    bool start(const PassiveEtwOptions& options);
    // 停止唯一自有会话，等回调排空，不丢弃已入队记录。false 需保留实例并重试清退。
    bool stop();
    // 移出至多 maxRecords 个队首元素。完成排空后才能启动新来源代次。
    std::vector<PassiveEtwRecord> drain(std::size_t maxRecords);
    // 返回状态和分项计数，两类丢失不能混成单一事件数。
    PassiveEtwStatus status() const;

private:
    // 回调在 ETW 消费线程执行，报告报头筛选、深拷贝和队列结果。
    void accept(const EVENT_RECORD& record);

    mutable std::mutex lifecycleMutex_;   // 串行化 start 与 stop。
    mutable std::mutex dataMutex_;        // 保护本端状态和队列。
    PassiveEtwOptions options_;           // 当前来源冻结的选项。
    PassiveEtwStatus counts_;             // 当前来源的本端计数及启动准备状态。
    std::deque<PassiveEtwRecord> queue_;  // 先进先出，容量按本次选项冻结。
    std::uint64_t frequencyHz_ = 0;       // 启动时实测的 QPC 频率。
    bool nativeAttempted_ = false;        // 状态查询使用本次原生回执的许可。
    bool stopRequested_ = false;          // 区分主动停止和意外结束。
    bool stopInFlight_ = false;           // 状态查询不等待停止及排空完成。
    bool cleanupFailed_ = false;          // 保留原生清退失败，供宿主重试。
    EtwSessionController controller_;     // 最先析构，回调关联成员仍处于生命周期内。
};

} // namespace ks::r3::monitor
