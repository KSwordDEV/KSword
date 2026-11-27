#pragma once
#include "ProjectNativeExecution.h"
#include "../../../shared/ApiTransferHandoffProtocol.h"
#include "../../../shared/ApiMonitorCapture.h"
#include <atomic>
#include <memory>

namespace Ksword::ActionAnalyze {
// 原采集worker持有，借用同一项目writer/sample；原生owner保留各自调试线程和恢复账。
class ApiTransferHandoff final {
public:
    // 同一原worker串行交付，含Ready前控制/coverage原包；回调异常停止递归采集并记Incomplete。
    using SourcePacket = std::function<void(DWORD, std::uint64_t,
        const ks::winapi_monitor::ApiMonitorEventPacket&)>;
    // 强实例及私有范围准入后、原API收到成功ACK前，在原writer线程登记同采样采集对象。
    using TargetDiscovered = std::function<void(DWORD, std::uint64_t)>;
    ApiTransferHandoff(ProjectDocument& project, std::string sampleId, DWORD sourcePid,
        std::uint64_t sourceCreation, const std::atomic_bool& cancel,
        const std::wstring& agentPath, SourcePacket onPacket, TargetDiscovered onTarget = {});
    ~ApiTransferHandoff();
    bool Start();
    void Poll();
    void Close();
    bool HasActiveAgents() const; // 根来源结束后，仍有安装中/活跃递归采集或待完成准入。
    // 沿现有主capture回调登记真实根Ready及终态；不更改共享capture回调协议。
    void OriginalSourceReady(std::uint64_t session, std::uint64_t coverageRevision);
    void OriginalSourceFinished();
    ks::winapi_monitor::InjectionEndpoint Endpoint() const;
    Evidence::JsonValue Describe() const;
    bool Incomplete() const; // 本轮拒绝、归档失败或原owner未清退时为真；不拿API采集成功覆盖控制缺口。
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}
