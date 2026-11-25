#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace Ksword::ActionAnalyze::Detection {

inline constexpr wchar_t kSysmonChannel[] = L"Microsoft-Windows-Sysmon/Operational";
inline constexpr wchar_t kSysmonProvider[] = L"Microsoft-Windows-Sysmon";
inline constexpr wchar_t kSysmonProviderGuid[] = L"5770385f-c22a-43e0-bf4c-06f5698ffbd9";
inline constexpr std::uint32_t kSysmonThreadEventId = 8;
inline constexpr std::uint32_t kSysmonThreadEventVersion = 2;
inline constexpr std::uint32_t kSysmonMaxMatches = 128;
inline constexpr std::uint32_t kSysmonScanLimit = 4096;
inline constexpr std::uint32_t kSysmonReadBudgetMs = 5000;

// Sysmon 的 UUID 不承诺 RFC 随机版本。接受有/无大括号、大小写可混合；输出小写，不接受零 GUID。
std::optional<std::wstring> NormalizeSysmonGuid(std::wstring_view guid);

// 已从 Windows 事件日志的 System/EventData 取得并验证类型的值。报头的 PID/TID 不提取。
struct SysmonThreadFields {
    std::wstring channel, provider, providerGuid, computer;
    std::uint32_t eventId = 0;
    std::optional<std::uint32_t> version;
    std::uint64_t recordId = 0, timeCreatedFileTime = 0;
    std::wstring sourceGuid, targetGuid;
    std::uint32_t sourcePid = 0, targetPid = 0, newThreadId = 0;
    std::wstring startAddress;
    std::optional<std::wstring> sourceImage, targetImage, startModule, startFunction;
};

// GUID 是独立的 Sysmon 来源身份；PID 只是属性，不会转成 ActionAnalyze 本机启动/创建 FILETIME 实例。
struct SysmonThreadObservation {
    SysmonThreadFields fields;
    std::uint64_t reportedStartAddress = 0; // 线程起点元数据，不是实际 RIP。
};

enum class SysmonThreadDecode { Observed, OtherTarget, WrongSource, UnsupportedVersion, InvalidFields };
struct SysmonThreadDecoded {
    SysmonThreadDecode state = SysmonThreadDecode::InvalidFields;
    std::optional<SysmonThreadObservation> observation;
};

// 校验来源、版本和强来源身份。错误记录不生成创建观察；不同目标也不返回其数据。
SysmonThreadDecoded DecodeSysmonThreadEvent(std::wstring_view targetGuid, SysmonThreadFields fields);

enum class SysmonReadState {
    InvalidRequest, ChannelUnavailable, AccessDenied, ReadFailed, Exhausted, Partial,
};
enum class SysmonLimit { None, Scan, Matches, Time };

struct SysmonThreadQuery {
    std::wstring targetGuid;
    std::uint32_t maxMatches = 32;
    std::optional<std::uint64_t> recordId;
};

struct SysmonThreadReadResult {
    SysmonReadState state = SysmonReadState::InvalidRequest;
    SysmonLimit limit = SysmonLimit::None;
    std::wstring targetGuid;
    std::wstring_view nativeStage; // 只借用固定字符串，不依赖日志缓冲区。
    std::uint32_t nativeError = 0;
    std::uint32_t examined = 0, unsupportedVersions = 0, malformed = 0, renderFailed = 0;
    bool reachedEnd = false;
    std::vector<SysmonThreadObservation> observations;
};

// 仅读本机既存 Sysmon Operational，固定 Event 8/提供者，倒序、有界；不安装、不启用、不改日志。
SysmonThreadReadResult ReadLocalSysmonThreadEvents(const SysmonThreadQuery& query);

inline constexpr std::size_t kSysmonMaxQueuedObservations = 256;

enum class SysmonSubscriptionState {
    Idle, InvalidRequest, Starting, Running, Stopping, Stopped,
    ChannelUnavailable, AccessDenied, Discontinuous, Failed,
};

struct SysmonSubscriptionStatus {
    SysmonSubscriptionState state = SysmonSubscriptionState::Idle;
    std::wstring targetGuid;
    std::size_t capacity = 0, queued = 0;
    std::uint64_t examined = 0, enqueued = 0, queueDropped = 0;
    std::uint64_t unsupportedVersions = 0, malformed = 0, renderFailed = 0;
    std::wstring_view nativeStage, firstRenderFailureStage; // 固定字符串。
    std::uint32_t nativeError = 0, firstRenderError = 0, closeError = 0;
    bool subscribed = false; // 原生订阅曾建立，不证明 Sysmon 正在生成 Event 8。
    bool tailDeliveryUnconfirmed = false;
};

// 单次、本机、仅未来的 Sysmon Operational Event 8。独立线程读入，不需要查询请求推进；
// 队列满时丢弃新观察并计数。由宿主持有本次来源身份；不重订阅或回放历史。
class SysmonThreadSubscription final {
public:
    SysmonThreadSubscription();
    ~SysmonThreadSubscription();
    SysmonThreadSubscription(const SysmonThreadSubscription&) = delete;
    SysmonThreadSubscription& operator=(const SysmonThreadSubscription&) = delete;

    // true 表示后台启动已受理，status() 的 Running 才表示订阅建立。启动一次；无效请求不访问日志。
    bool start(std::wstring_view targetGuid, std::size_t capacity = kSysmonMaxQueuedObservations);
    // 唤醒并等待读线程退出，保留已入队观察；不保证通道尾部全部交付。可重复调用。
    void stop();
    // 移出至多 maxRecords 条，使用原生交付顺序；停后仍可排空。
    std::vector<SysmonThreadObservation> drain(std::size_t maxRecords);
    SysmonSubscriptionStatus status() const;

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace Ksword::ActionAnalyze::Detection
