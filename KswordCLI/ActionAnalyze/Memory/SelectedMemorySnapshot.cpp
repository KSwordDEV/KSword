#include "SelectedMemorySnapshot.h"

#include <algorithm>

namespace ks::cli::action_analyze::memory {

SelectedMemorySnapshot CaptureSelectedMemory(HANDLE selectedProcess, const Plan& plan, const std::atomic_bool* cancel)
{
    SelectedMemorySnapshot snapshot; // 结果身份先冻结，任何准入失败也归属于本次显式请求。
    snapshot.plan = plan;
    PassiveDirtyMemory source; // 单次采样复用原生读取器，无独立轮询或后台采集线程。
    snapshot.status = source.Begin(selectedProcess, plan);
    if (snapshot.status.state != State::Active) return snapshot;

    const CapturedPageVisitor capture = [&](const PageObservation& page, std::span<const std::uint8_t> bytes) {
        // 观察器只交付完整且映射稳定的成功页；即时复制，回调后不保留借用视图。
        CapturedMemoryPage copy;
        copy.observation = page;
        copy.bytes.assign(bytes.begin(), bytes.end());
        snapshot.captured.push_back(std::move(copy));
    };
    auto sampled = source.PollCapture(capture, cancel); // 仅首次已到期轮，不补采缺页或改变目标保护。
    snapshot.status = sampled.status;
    snapshot.round = std::move(sampled.round);
    snapshot.completeRange = snapshot.round && snapshot.round->allPagesVisited && snapshot.round->endQpc &&
        snapshot.captured.size() == snapshot.round->pages.size() &&
        std::all_of(snapshot.round->pages.begin(), snapshot.round->pages.end(), [](const PageObservation& page) {
            return page.status == PageStatus::Sampled && page.content.has_value();
        }) && snapshot.status.state == State::Active;
    if (snapshot.status.state == State::Active) snapshot.status = source.Stop();
    return snapshot;
}

} // namespace ks::cli::action_analyze::memory
