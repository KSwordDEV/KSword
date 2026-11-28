#pragma once

#include <cstdint>
#include <mutex>

namespace Ksword::ActionAnalyze {

// 一轮活采共享最后控制意图；UI/CLI只发布请求，原writer独占应用原生暂停及恢复。
class ApiTransferControl final {
public:
    struct Intent {
        std::uint64_t revision = 0; // 非零递增的请求修订，不是实际Held证明。
        bool paused = false; // 本修订希望保留全部既有与随后加入的执行成员。
    };

    // 输入新修订和暂停意图，接纳返回true；旧修订不覆盖当前请求。
    bool Publish(std::uint64_t revision, bool paused)
    {
        const std::lock_guard lock(mutex_); // 同步发布两个字段，防止读到跨修订组合。
        if (!revision || revision <= intent_.revision) {
            return false;
        }
        intent_ = {revision, paused};
        return true;
    }

    // 返回拥有型快照；调用者不能持锁执行原生控制或文件读取。
    Intent Read() const
    {
        const std::lock_guard lock(mutex_); // 只保护短小内存复制，不等待目标线程。
        return intent_;
    }

private:
    mutable std::mutex mutex_; // 发布端与原采集worker间的唯一同步责任。
    Intent intent_; // 本轮最后接纳意图，销毁后不影响下一轮采样。
};

} // namespace Ksword::ActionAnalyze
