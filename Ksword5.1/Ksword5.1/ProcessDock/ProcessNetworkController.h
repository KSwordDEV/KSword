#pragma once
#include "../ksword/network/network.h"
#include "../../../shared/usermode/backend/network/Connections.h"
#include <QString>
#include <memory>

namespace ks::network {
struct ProcessNetworkTarget {
    std::uint32_t pid = 0;
    std::uint64_t creationTime100ns = 0;
    std::wstring imagePath;
};
struct ProcessNetworkResult { bool success = false; QString message; };
struct ProcessPacketBatch {
    bool active = false, targetAlive = false, serviceRunning = false;
    std::uint64_t dropped = 0, receivedBytes = 0, sentBytes = 0;
    QString status;
    std::vector<PacketRecord> packets;
};

// All detail pages share one capture service. Each lease owns a validated
// process handle and a bounded mailbox; stopping one page leaves other leases.
class ProcessNetworkController final {
public:
    explicit ProcessNetworkController(ProcessNetworkTarget target);
    ~ProcessNetworkController();
    std::uint64_t beginStartRequest();
    ProcessNetworkResult startCapture(std::uint64_t generation); // worker-thread operation
    void stopCapture();                 // nonblocking cancellation
    ProcessPacketBatch takePackets(std::size_t maximum = 256);
    const ProcessNetworkTarget& target() const;
    static ProcessNetworkResult validateTarget(const ProcessNetworkTarget& target);
    static ks::r3::network::ConnectionEnumerationResult connections(const ProcessNetworkTarget& target);
    static ProcessNetworkResult disconnect(const ProcessNetworkTarget& target,
        const ks::r3::network::ConnectionEntry& connection);
    static ProcessNetworkResult exportPcap(const QString& path, const std::vector<PacketRecord>& packets);
    static ProcessNetworkResult exportDump(const QString& path, const std::vector<PacketRecord>& packets);
private:
    struct State;
    std::shared_ptr<State> m_state;
};
}
