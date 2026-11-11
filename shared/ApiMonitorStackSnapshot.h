#pragma once

// Resolve only recorded stack addresses, on an existing bounded resolver's
// worker. Results are current observations, not historical module ownership.
#include "ApiMonitorCallerSnapshot.h"
#include <array>
#include <span>

namespace ks::winapi_monitor
{
    inline constexpr std::size_t kStackSnapshotMaximum = 8;
    enum class StackSnapshotState { Pending, Available, Unavailable };
    struct StackFrameSnapshot
    {
        std::uint64_t address = 0, requestId = 0, observedTime100ns = 0, imageOffset = 0;
        StackSnapshotState state = StackSnapshotState::Unavailable;
        bool imageOffsetAvailable = false;
        std::wstring mappedPath;
        std::string nearestExportName;
        std::uint64_t nearestExportDisplacement = 0, nearestExportObservedTime100ns = 0;
        CallerSnapshotStatus failure = CallerSnapshotStatus::QueryFailed;
    };

    // Each UI consumer must own its resolver; sharing a drain queue would allow
    // one consumer to discard another's responses. The owner must stop/join
    // the resolver off the UI thread, as for CallerSnapshotResolver itself.
    class StackSnapshotBatch final
    {
    public:
        explicit StackSnapshotBatch(CallerSnapshotResolver& resolver) : m_resolver(resolver) {}

        bool start(std::uint64_t generation, std::uint64_t sequence, std::uint32_t pid,
                   std::uint64_t creation, std::span<const std::uint64_t> addresses)
        {
            if (!generation || !sequence || !pid || !creation || addresses.size() > kStackSnapshotMaximum) return false;
            m_generation = generation; m_sequence = sequence; m_pid = pid; m_creation = creation;
            m_count = addresses.size(); m_pending = 0;
            for (std::size_t i = 0; i < m_count; ++i) {
                auto& frame = m_frames[i]; frame = {}; frame.address = addresses[i];
                if (++m_nextId == 0) ++m_nextId;
                frame.requestId = m_nextId;
                const CallerSnapshotRequest request{generation, sequence, pid, creation, frame.address, frame.requestId};
                if (m_resolver.submit(request) == CallerSnapshotResolver::SubmitStatus::Accepted) {
                    frame.state = StackSnapshotState::Pending; ++m_pending;
                }
            }
            return true;
        }

        bool poll()
        {
            bool changed = false;
            for (const auto& value : m_resolver.drain()) {
                const auto& request = value.request;
                if (request.generation != m_generation || request.sequence != m_sequence
                    || request.pid != m_pid || request.creationTime100ns != m_creation) continue;
                for (std::size_t i = 0; i < m_count; ++i) {
                    auto& frame = m_frames[i];
                    if (frame.state != StackSnapshotState::Pending || frame.requestId != request.requestId
                        || frame.address != request.address) continue;
                    --m_pending; changed = true;
                    frame.failure = value.status;
                    if (value.status != CallerSnapshotStatus::Available) {
                        frame.state = StackSnapshotState::Unavailable;
                        break;
                    }
                    frame.state = StackSnapshotState::Available;
                    frame.observedTime100ns = value.observedTime100ns;
                    frame.mappedPath = value.mappedPath;
                    // A valid image allocation base may only be used when the
                    // queried region actually contains this address.
                    if (value.state == MEM_COMMIT && value.type == MEM_IMAGE && value.allocationBase
                        && frame.address >= value.allocationBase && frame.address >= value.regionBase
                        && frame.address - value.regionBase < value.regionSize && !frame.mappedPath.empty()) {
                        frame.imageOffset = frame.address - value.allocationBase;
                        frame.imageOffsetAvailable = true;
                    }
                    break;
                }
            }
            return changed;
        }

        std::span<const StackFrameSnapshot> frames() const { return {m_frames.data(), m_count}; }
        std::size_t pending() const { return m_pending; }

    private:
        CallerSnapshotResolver& m_resolver;
        std::array<StackFrameSnapshot, kStackSnapshotMaximum> m_frames{};
        std::uint64_t m_generation = 0, m_sequence = 0, m_creation = 0, m_nextId = 0;
        std::uint32_t m_pid = 0;
        std::size_t m_count = 0, m_pending = 0;
    };
}
