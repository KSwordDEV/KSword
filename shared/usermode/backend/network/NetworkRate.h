#pragma once
#include <cstdint>
namespace ks::network {
struct NetworkRateSample {
    std::uint64_t receivedBytes = 0, sentBytes = 0, tick100ns = 0;
    bool available = false;
};
struct NetworkRate {
    double receivedKBps = 0, sentKBps = 0, totalKBps = 0;
    bool known = false;
};
inline NetworkRate CalculateNetworkRate(const NetworkRateSample& previous, const NetworkRateSample& current)
{
    if (!previous.available || !current.available || current.tick100ns <= previous.tick100ns
        || current.receivedBytes < previous.receivedBytes || current.sentBytes < previous.sentBytes) return {};
    const double seconds = static_cast<double>(current.tick100ns - previous.tick100ns) / 10000000.0;
    NetworkRate result;
    result.receivedKBps = static_cast<double>(current.receivedBytes - previous.receivedBytes) / seconds / 1024.0;
    result.sentKBps = static_cast<double>(current.sentBytes - previous.sentBytes) / seconds / 1024.0;
    result.totalKBps = result.receivedKBps + result.sentKBps;
    result.known = true;
    return result;
}
}
