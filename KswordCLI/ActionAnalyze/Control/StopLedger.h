#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ks::cli::action_analyze::control {

struct OwnerIdentity {
    std::string sampleId;
    std::string sessionId;
    std::string epoch;
    std::string backendInstanceId;
    bool operator==(const OwnerIdentity&) const = default;
};

struct ThreadIdentity {
    std::string threadId;
    std::string processInstanceId;
    bool operator==(const ThreadIdentity&) const = default;
};

struct FrozenStopGroup {
    std::string groupId;
    std::uint64_t membershipRevision = 0;
    std::string membershipSha256;
    std::vector<ThreadIdentity> requested;
    bool operator==(const FrozenStopGroup&) const = default;
};

struct NativeEventKey {
    std::string backendInstanceId;
    std::uint64_t serial = 0;
    bool operator==(const NativeEventKey&) const = default;
};

enum class StopPhase { CallEnter, CallReturn, ExecutionEnterAttempt };

// 仅由验证过实际事件和强线程身份的外部 owner 提交。站点阶段未知时仍能保留事件责任。
struct NativeStop {
    NativeEventKey event;
    ThreadIdentity eventThread;
    std::string stopId;
    std::optional<StopPhase> phase;
    bool operator==(const NativeStop&) const = default;
};

enum class MemberEvidence { Pending, CoveredByEvent, NoOwnedHold, Exited, Unknown };
enum class IncidentalQuality { Verified, Partial, NotCollected };
enum class MemberState { Pending, Held, NotHeld, Exited, ReleasePending, Released, RecoveryRequired, Unknown };
enum class OriginHold { Held, ReleasePending, RecoveryRequired, Released, Exited };
enum class GroupState {
    GroupBuilding, OriginHeld, HeldComplete, HeldPartial, NotHeld, ReleasePending, Released, RecoveryRequired, Ended,
    UnprojectableNativeHold
};
enum class EventState { Held, ReleasePending, Retryable, Indeterminate, Released, RetiredOnExit };

struct MemberSnapshot {
    std::string threadId;
    MemberState state;
    std::optional<std::string> stopId;
    MemberEvidence evidence;
};

struct OriginSnapshot {
    std::string threadId;
    StopPhase phase;
    OriginHold hold;
};

// 只读内部投影。UnprojectableNativeHold 需要公开契约新增表达，不能映射成 held-complete 或 ended。
struct StopGroupSnapshot {
    std::string sampleId;
    std::string sessionId;
    std::string epoch;
    std::string groupId;
    std::uint64_t stateRevision;
    std::uint64_t membershipRevision;
    std::string membershipSha256;
    GroupState state;
    std::optional<OriginSnapshot> origin;
    std::vector<MemberSnapshot> members;
    IncidentalQuality incidentalQuality;
    std::vector<std::string> incidentalThreadIds;
    bool historical;
};

// stopId 只用于定位。调用方须持活会话/后端和事件身份，公开快照中没有这些组合字段。
struct ReleaseRequest {
    OwnerIdentity owner;
    std::string groupId;
    std::string stopId;
    NativeEventKey event;
    std::string requestId;
    std::uint64_t expectedStateRevision = 0;
    bool operator==(const ReleaseRequest&) const = default;
};

struct ReleaseAttempt {
    ReleaseRequest request;
    std::uint64_t issuedRevision;
    bool operator==(const ReleaseAttempt&) const = default;
};

enum class ReleaseResult { Continued, StillPending, Indeterminate };

struct ReleaseReceipt {
    ReleaseResult result;
    std::optional<std::uint32_t> nativeError;
    bool operator==(const ReleaseReceipt&) const = default;
};

enum class LedgerResult {
    Applied, Duplicate, InvalidEvidence, MissingGroup, IdentityMismatch, Conflict, Capacity,
    StaleRevision, InvalidTransition, Historical, ReadbackRequired
};

struct ReleaseDecision {
    LedgerResult result;
    // 仅首次接受返回动作。重放以 QueryRelease 查询原始结果。
    std::optional<ReleaseAttempt> effect = std::nullopt;
};

struct ReleaseRecord {
    std::uint64_t issuedRevision;
    std::optional<ReleaseReceipt> receipt;
    std::optional<ReleaseReceipt> readback;
    bool eventRetiredOnExit = false;
};

struct EventResponsibility {
    std::string groupId;
    NativeEventKey event;
    ThreadIdentity actualEventThread;
    std::string stopId;
    EventState state;
    std::optional<std::string> lastRequestId;
};

// 本对象只在 CLI 的单一控制执行者上调用。查询返回值可以复制给输出线程。
// 活原生事件的原始句柄和 Continue 责任仍由同一外部调试线程持有。
class StopLedger final {
public:
    explicit StopLedger(OwnerIdentity owner);
    StopLedger(const StopLedger&) = delete;
    StopLedger& operator=(const StopLedger&) = delete;

    [[nodiscard]] LedgerResult Freeze(FrozenStopGroup group);
    [[nodiscard]] LedgerResult AdoptNativeStop(std::string_view groupId, const NativeStop& evidence);
    [[nodiscard]] LedgerResult ObserveMember(std::string_view groupId, const ThreadIdentity& thread,
        MemberEvidence evidence, std::optional<NativeEventKey> event = std::nullopt);
    [[nodiscard]] LedgerResult ObserveOriginExit(std::string_view groupId, const NativeEventKey& event,
        const ThreadIdentity& exitedThread);
    [[nodiscard]] LedgerResult ObserveIncidental(std::string_view groupId, const NativeEventKey& event,
        IncidentalQuality quality, std::vector<ThreadIdentity> known);
    [[nodiscard]] LedgerResult SealMembership(std::string_view groupId);
    // 由 owner 确认该组从未有原生事件或路由已排空。仅关闭成员证据收集不能证明这一点。
    [[nodiscard]] LedgerResult ConfirmNoNativeEvent(std::string_view groupId);

    [[nodiscard]] ReleaseDecision BeginRelease(const ReleaseRequest& request);
    [[nodiscard]] LedgerResult RecordReleaseReceipt(const ReleaseAttempt& attempt, ReleaseReceipt receipt);
    // 只准提交独立的已继续或仍持有证明。证明仍持有前须确认旧尝试已退出执行路径。
    [[nodiscard]] LedgerResult RecordReleaseReadback(const ReleaseAttempt& attempt, ReleaseReceipt proof);
    // 必须同时确认真实进程退出与精确原生事件已退休。仅 origin/成员退出不能清账。
    [[nodiscard]] LedgerResult RecordRetiredOnExit(std::string_view groupId, const NativeEventKey& event,
        std::string_view exitedProcessInstanceId);

    [[nodiscard]] std::optional<StopGroupSnapshot> Query(std::string_view groupId) const;
    [[nodiscard]] std::optional<ReleaseRecord> QueryRelease(std::string_view requestId) const;
    [[nodiscard]] std::optional<EventResponsibility> UnresolvedNativeResponsibility() const;
    [[nodiscard]] bool CanRetireLedger() const noexcept;

private:
    struct Member {
        ThreadIdentity identity;
        MemberEvidence evidence = MemberEvidence::Pending;
        bool wasCovered = false;
    };

    struct Group {
        FrozenStopGroup frozen;
        std::vector<Member> members;
        std::uint64_t revision = 1;
        bool membershipSealed = false;
        bool noNativeEventConfirmed = false;
        bool closed = false;
        std::optional<NativeStop> native;
        EventState eventState = EventState::Held;
        bool originExited = false;
        IncidentalQuality incidentalQuality = IncidentalQuality::NotCollected;
        std::vector<ThreadIdentity> incidental;
        std::optional<std::string> lastRequestId;
        std::size_t releaseAttempts = 0;
    };

    struct Command {
        ReleaseAttempt attempt;
        ReleaseRecord record;
    };

    Group* Find(std::string_view groupId);
    const Group* Find(std::string_view groupId) const;
    static MemberState ProjectMember(const Group& group, const Member& member);
    static GroupState ProjectGroup(const Group& group);
    void CloseIfResolved(Group& group);
    void ApplyReceipt(Group& group, ReleaseResult result);
    LedgerResult RecordRelease(const ReleaseAttempt& attempt, ReleaseReceipt receipt, bool readback);

    OwnerIdentity owner_;
    std::map<std::string, Group, std::less<>> groups_;
    std::map<std::string, Command, std::less<>> commands_;
    Group* active_ = nullptr;
    std::uint64_t lastNativeSerial_ = 0;
};

} // namespace ks::cli::action_analyze::control
