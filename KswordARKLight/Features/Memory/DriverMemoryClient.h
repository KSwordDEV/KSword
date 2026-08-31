#pragma once

#include "DriverMemoryModel.h"
#include "MemoryWritePlan.h"

#include <atomic>
#include <mutex>

namespace Ksword::Features::Memory {

// DriverMemoryWritebackCancellation serializes cancellation with request
// issuance. cancel() waits for one in-flight driver call if necessary, then
// prevents the writeback worker from issuing another read or write request.
// It is deliberately shared by the page and worker instead of relying on a
// best-effort callback cancellation after the page has been destroyed.
class DriverMemoryWritebackCancellation final {
public:
    void cancel();
    bool isCancellationRequested() const noexcept;
    std::unique_lock<std::mutex> lockIssuanceGate() const;

private:
    mutable std::mutex issuanceGate_;
    std::atomic_bool cancelled_ = false;
};

// DriverMemoryWritebackResult describes a staged, verified plan application.
// success means every block passed exact before/after reads and the full desired
// snapshot was read back exactly. forceRequired identifies the first remaining
// block that refused a non-FORCE write without reporting bytes written; the UI
// may then ask for a separate explicit confirmation to continue from that block
// only. cancelled always requires a fresh read before another attempt.
struct DriverMemoryWritebackResult {
    bool success = false;
    bool forceRequired = false;
    bool cancelled = false;
    std::size_t totalBlocks = 0;
    std::size_t verifiedBlocks = 0;
    std::size_t requestedBytes = 0;
    std::size_t bytesWritten = 0;
    std::size_t forceRequiredBlockIndex = 0;
    std::uint64_t failedAddress = 0;
    std::wstring statusText;
    DriverMemoryReadResult finalReadResult;
};

// DriverMemoryClient is the module-local facade for driver memory operations.
// The view depends only on this class, so UI code never performs raw driver I/O
// directly. Requests are forwarded to the shared ArkDriverClient implementation
// used by the full KswordARK project, which keeps IOCTL structure ownership in
// shared/driver and avoids duplicate protocol definitions.
class DriverMemoryClient final {
public:
    DriverMemoryClient();
    ~DriverMemoryClient();

    DriverMemoryClient(const DriverMemoryClient&) = delete;
    DriverMemoryClient& operator=(const DriverMemoryClient&) = delete;

    // ReadMemory sends a validated read request to the driver facade. Input is a
    // request produced by DriverMemoryModel; processing calls ArkDriverClient
    // readVirtualMemory without zero-fill fallback so unreadable ranges are not
    // misreported as successful all-zero buffers; output describes success,
    // status and returned bytes.
    DriverMemoryReadResult ReadMemory(const DriverMemoryReadRequest& request);

    // WriteMemory sends a validated write request to the driver facade. The
    // default uses only UI_CONFIRMED for compatibility with older drivers;
    // forceWrite is available solely after a separate explicit UI confirmation.
    DriverMemoryWriteResult WriteMemory(const DriverMemoryWriteRequest& request, bool forceWrite = false);

    // ApplyWritePlan freezes the supplied snapshot target, exact-preflights each
    // changed block, writes it, verifies it, then exactly re-reads the whole
    // desired snapshot. It never retries with FORCE unless forceWrite is true.
    // firstPendingBlock permits a separately confirmed FORCE continuation after
    // an older or policy-driven driver accepted a verified normal-write prefix;
    // that prefix is exact-rechecked before any remaining block is written.
    // cancellation is cooperative and checked before and after every driver
    // request; cancellation after a write always leaves the result requiring a
    // fresh snapshot rather than making a safety claim about target memory.
    DriverMemoryWritebackResult ApplyWritePlan(
        const MemoryWritePlan& plan,
        bool forceWrite,
        const DriverMemoryWritebackCancellation* cancellation = nullptr,
        std::size_t firstPendingBlock = 0U);
};

} // namespace Ksword::Features::Memory
