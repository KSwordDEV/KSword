#include "ApiTransferAgentCapture.h"
#include <mutex>
#include <thread>

namespace Ksword::ActionAnalyze {
namespace m = ks::winapi_monitor;
class ApiTransferAgentCapture::Impl {
public:
    DWORD pid;
    std::uint64_t creation;
    m::InjectionEndpoint endpoint;
    std::wstring agentPath; // 原主capture解析出的产品路径，沿同一来源传递。
    mutable std::mutex mutex;
    std::atomic_bool cancel{false};
    std::thread worker;
    Batch queued;
    bool finished = false;
    Impl(DWORD p, std::uint64_t c, m::InjectionEndpoint e, std::wstring path)
        : pid(p), creation(c), endpoint(std::move(e)), agentPath(std::move(path)) {}

    void Run()
    {
        m::CaptureResult result;
        try {
            m::CaptureRequest request;
            request.pid = pid;
            request.agentPath = agentPath;
            request.attachCreationFileTime = creation;
            request.attachConfirmed = request.strictReadOnlyObservation = true;
            request.durationMs = 0;
            request.startupTimeoutMs = 10000; // 在同步Hook交接总时限内完成真实Ready。
            request.eventLimit = 0;
            request.transferHandoff = endpoint;
            request.onControlPoll = [] {}; // 管道由原handoff worker持续服务，不在此线程重入项目。
            request.onStartupProgress = [&](const auto& progress) {
                std::lock_guard lock(mutex);
                queued.startup = progress;
            };
            request.onResidentReady = [&](auto session, auto revision) {
                std::lock_guard lock(mutex);
                queued.session = session;
                queued.coverageRevision = revision;
                queued.ready = session && revision;
            };
            request.onVerifiedPacket = [&](const auto& packet) {
                std::lock_guard lock(mutex);
                // 溢出真实计数并停止当前来源，不阻塞Agent或静默丢包后仍声称完整。
                if (queued.packets.size() >= 2048) { ++queued.dropped; cancel.store(true); return; }
                queued.packets.push_back(packet);
            };
            result = m::captureApiMonitor(request, cancel);
        } catch (...) {
            result.code = 3;
            try { result.errors.push_back(L"recursive Agent capture controller exception"); } catch (...) {}
        }
        std::lock_guard lock(mutex);
        queued.finished.emplace(std::move(result));
        finished = true;
    }
};
ApiTransferAgentCapture::ApiTransferAgentCapture(DWORD pid, std::uint64_t creation,
    m::InjectionEndpoint endpoint, std::wstring agentPath)
    : impl_(std::make_unique<Impl>(pid, creation, std::move(endpoint), std::move(agentPath))) {}
ApiTransferAgentCapture::~ApiTransferAgentCapture()
{
    Stop();
    if (impl_->worker.joinable()) impl_->worker.join();
}
bool ApiTransferAgentCapture::Start()
{
    if (impl_->worker.joinable()) return false;
    try { impl_->worker = std::thread([self = impl_.get()] { self->Run(); }); return true; }
    catch (...) {
        std::lock_guard lock(impl_->mutex);
        impl_->finished = true;
        // 线程未创建也必须可清退；低内存诊断分配失败不能让Close等待不存在的线程。
        try {
            impl_->queued.finished.emplace();
            impl_->queued.finished->errors.push_back(L"recursive Agent capture thread creation failed");
        } catch (...) {}
        return false;
    }
}
void ApiTransferAgentCapture::Stop() noexcept { impl_->cancel.store(true); }
bool ApiTransferAgentCapture::Finished() const { std::lock_guard lock(impl_->mutex); return impl_->finished; }
ApiTransferAgentCapture::Batch ApiTransferAgentCapture::Drain()
{
    std::lock_guard lock(impl_->mutex);
    Batch out;
    out.packets.swap(impl_->queued.packets);
    out.finished.swap(impl_->queued.finished);
    out.startup = impl_->queued.startup;
    out.session = impl_->queued.session;
    out.coverageRevision = impl_->queued.coverageRevision;
    out.ready = impl_->queued.ready;
    out.dropped = impl_->queued.dropped;
    return out;
}
}
