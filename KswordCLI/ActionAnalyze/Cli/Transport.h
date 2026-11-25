#pragma once

#include "Protocol.h"

#include <memory>

namespace ks::cli::action_analyze {

inline constexpr std::size_t kPendingFrames = 16;
inline constexpr unsigned kOutputTimeoutMs = 5000;

enum class InputKind { Line, Eof, Fatal, Break, OutputLost };

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
    bool Interactive() const;
    Input Next();
    bool Send(std::string frame);
    bool Finish();

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace ks::cli::action_analyze
