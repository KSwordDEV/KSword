#pragma once

#include <cstdint>
#include <string>

namespace ready_owner_failure {

// 触发器与外部原生 owner 之间只传递这一组稳定字段。
enum class ControlMode { Continue, Step };

struct AllocationIdentity {
    std::uint32_t pid = 0;
    std::uint64_t processCreationTime = 0;
    std::uint64_t allocationBase = 0;
    std::uint64_t address = 0;
    std::uint64_t bytes = 0;
};

struct HeldConfirmation {
    AllocationIdentity target;
    bool agentLoaded = false;
    bool nativeRecoveryBranch = false;
    bool statusHeld = false;
    bool breakpointHit = false;
    bool heldComplete = false;
    std::uint64_t eventPid = 0;
    std::uint64_t eventTid = 0;
    std::uint64_t eventSerial = 0;
    std::uint64_t stateRevision = 0;
    std::string ownerSampleId;
    std::string ownerSessionId;
    std::string ownerEpoch;
    std::string ownerBackendId;
    std::string groupId;
    std::string stopId;
    std::string eventBackendId;
};

struct ReleaseObservation {
    ControlMode mode = ControlMode::Continue;
    bool freeSucceeded = false;
    std::uint32_t freeError = 0;
    std::uint32_t preState = 0;
    std::uint64_t preAllocationBase = 0;
    std::uint64_t preRegionBytes = 0;
    std::uint32_t postState = 0;
    std::uint64_t postRegionBytes = 0;
    bool regionVerifiedFree = false;
};

struct RecoveryObservation {
    ControlMode mode = ControlMode::Continue;
    std::string status;
    bool firstRecoveryFailurePresent = false;
    std::string firstRecoveryFailureStage;
    std::uint32_t firstRecoveryFailureError = 0;
    std::string ownerSampleId;
    std::string ownerSessionId;
    std::string ownerEpoch;
    std::string ownerBackendId;
    std::string pendingEventBackendId;
    std::uint64_t pendingEventSerial = 0;
    std::string releaseRequestId;
};

} // namespace ready_owner_failure
