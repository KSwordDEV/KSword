#pragma once

#include "Protocol.h"

#include <memory>
#include <cstdint>

namespace ks::cli::action_analyze {

inline constexpr std::size_t kPendingFrames = 16;
inline constexpr unsigned kOutputTimeoutMs = 5000;

enum class InputKind { Line, Eof, Fatal, Break, OutputLost, Tick };

struct Input {
    InputKind kind;
    std::string line;
    Fault fault;
};

class Transport {
public:
    Transport();
    ~Transport();
    Transport(const Transport&) = delete;
    Transport& operator=(const Transport&) = delete;

    Fault Start(bool jsonl);
    // 仅启动指定标准输出流的writer，不读stdin或登记控制台处理器；供采集进度复用。
    Fault StartOutputOnly(std::uint32_t standardHandle);
    bool Interactive() const;
    Input Next(bool wakeForTick = false);
    bool Send(std::string frame);
    // 旁路进度使用非等待入队；队列满或输出失败直接返回false，不拖住原控制worker。
    bool TrySend(std::string frame);
    bool Finish();

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace ks::cli::action_analyze
