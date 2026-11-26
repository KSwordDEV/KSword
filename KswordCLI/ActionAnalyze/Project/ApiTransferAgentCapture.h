#pragma once
#include "../../../shared/ApiMonitorCapture.h"
#include <atomic>
#include <memory>

namespace Ksword::ActionAnalyze {
// 单实例控制器只负责真实Agent会话和有界原包队列；不持有项目或归档writer。
class ApiTransferAgentCapture final {
public:
    struct Batch {
        std::vector<ks::winapi_monitor::ApiMonitorEventPacket> packets;
        std::optional<ks::winapi_monitor::CaptureStartupProgress> startup;
        std::optional<ks::winapi_monitor::CaptureResult> finished;
        std::uint64_t session = 0, coverageRevision = 0, dropped = 0;
        bool ready = false;
    };
    ApiTransferAgentCapture(DWORD pid, std::uint64_t creation,
        ks::winapi_monitor::InjectionEndpoint endpoint, std::wstring agentPath);
    ~ApiTransferAgentCapture();
    bool Start();
    void Stop() noexcept;
    bool Finished() const;
    Batch Drain(); // 仅handoff原worker调用；一次转移队列及唯一终态回执。
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}
