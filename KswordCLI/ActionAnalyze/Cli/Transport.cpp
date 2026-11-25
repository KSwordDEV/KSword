#include "Transport.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <process.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>

namespace ks::cli::action_analyze {
namespace {
using Clock = std::chrono::steady_clock;
constexpr auto kOutputTimeout = std::chrono::milliseconds(kOutputTimeoutMs);
std::atomic_bool closeSignal{false};

BOOL WINAPI OnConsoleControl(DWORD type) {
    // 离线阶段没有前台 job。Ctrl+Break 只发关闭信号，不能在原生回调内访问流或锁。
    if (type == CTRL_BREAK_EVENT) closeSignal.store(true);
    return type == CTRL_BREAK_EVENT || type == CTRL_C_EVENT;
}

bool IsConsole(HANDLE handle) {
    DWORD mode = 0;
    return GetConsoleMode(handle, &mode) != FALSE;
}

bool ValidHandle(HANDLE handle) { return handle != nullptr && handle != INVALID_HANDLE_VALUE; }

Fault Win32Fault(const char* id, const char* message, DWORD code) {
    return {id, message, std::nullopt, 3, "win32", code};
}

// CancelSynchronousIo 只取消已提交的操作。先撤销工作资格，再等线程退出，覆盖提交竞争。
void StopWorker(HANDLE worker) noexcept {
    if (!worker) return;
    while (WaitForSingleObject(worker, 20) == WAIT_TIMEOUT) (void)CancelSynchronousIo(worker);
    CloseHandle(worker);
}
} // namespace

struct Transport::State {
    struct Output {
        std::string bytes;
        Clock::time_point enqueued;
    };

    HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    HANDLE reader = nullptr;
    HANDLE writer = nullptr;
    bool consoleIn = IsConsole(in);
    bool consoleOut = IsConsole(out);
    bool jsonl = false;
    bool handler = false;
    std::mutex mutex;
    std::condition_variable changed;
    std::optional<Input> next;
    std::deque<Output> pending;
    std::optional<Clock::time_point> writing;
    bool outputLost = false;
    bool stopping = false;

    ~State() {
        {
            std::lock_guard lock(mutex);
            stopping = true;
        }
        changed.notify_all();
        StopWorker(reader);
        StopWorker(writer);
        if (handler) (void)SetConsoleCtrlHandler(OnConsoleControl, FALSE);
    }

    bool Publish(Input input) {
        std::unique_lock lock(mutex);
        changed.wait(lock, [&] { return !next || stopping; });
        if (stopping) return false;
        next = std::move(input);
        changed.notify_all();
        return true;
    }

    // 只缓冲一条完整行与当前分片。CR 仅当后续紧跟 LF 时不计入正文长度。
    void Read() {
        std::string line;
        std::string converted;
        wchar_t high = 0;
        for (;;) {
            {
                std::lock_guard lock(mutex);
                if (stopping) return;
            }
            char bytes[8192];
            wchar_t wide[2049];
            DWORD count = 0;
            const BOOL ok = consoleIn ? ReadConsoleW(in, wide + 1, 2048, &count, nullptr)
                                      : ReadFile(in, bytes, sizeof(bytes), &count, nullptr);
            const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
            if (consoleIn && (error == ERROR_OPERATION_ABORTED || (ok && !count))) continue;
            if (!ok && error != ERROR_BROKEN_PIPE && error != ERROR_HANDLE_EOF) {
                Publish({InputKind::Fatal, {}, Win32Fault("input-failed", "Could not read stdin", error)});
                return;
            }
            if (!ok || !count) break;
            std::string_view chunk(bytes, count);
            if (consoleIn) {
                // ReadConsoleW 的固定分片边界可能落在代理对中间。
                wchar_t* begin = wide + 1;
                if (high) { wide[0] = high; begin = wide; ++count; high = 0; }
                if (begin[count - 1] >= 0xd800 && begin[count - 1] <= 0xdbff) high = begin[--count];
                if (!count) continue;
                const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, begin,
                    static_cast<int>(count), nullptr, 0, nullptr, nullptr);
                if (!size) {
                    Publish({InputKind::Fatal, {}, Win32Fault("input-failed", "Could not decode console input", GetLastError())});
                    return;
                }
                converted.resize(size);
                (void)WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, begin, static_cast<int>(count),
                    converted.data(), size, nullptr, nullptr);
                chunk = converted;
            }
            for (const char ch : chunk) {
                if (ch == '\n') {
                    if (!line.empty() && line.back() == '\r') line.pop_back();
                    if (consoleIn && line == "\x1a") {
                        Publish({InputKind::Eof, {}, {}});
                        return;
                    }
                    if (!Publish({InputKind::Line, std::move(line), {}})) return;
                    line.clear();
                } else if (line.size() < kInputBytes || (line.size() == kInputBytes && ch == '\r')) {
                    line.push_back(ch);
                } else {
                    Publish({InputKind::Fatal, {}, {"line-too-long", "Input line exceeds 1 MiB", kInputBytes}});
                    return;
                }
            }
        }
        if (!line.empty()) {
            if (jsonl) {
                Publish({InputKind::Fatal, {}, {"unterminated-line", "Expected LF before EOF", line.size()}});
                return;
            }
            if (!Publish({InputKind::Line, std::move(line), {}})) return;
        }
        Publish({InputKind::Eof, {}, {}});
    }

    bool Write(const std::string& frame) {
        std::wstring wide;
        if (consoleOut) {
            const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, frame.data(),
                static_cast<int>(frame.size()), nullptr, 0);
            if (!size) return false;
            wide.resize(size);
            if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, frame.data(),
                static_cast<int>(frame.size()), wide.data(), size)) return false;
        }
        const std::size_t size = consoleOut ? wide.size() : frame.size();
        for (std::size_t at = 0; at < size;) {
            const auto remaining = static_cast<DWORD>(size - at);
            DWORD written = 0;
            const BOOL ok = consoleOut ? WriteConsoleW(out, wide.data() + at, remaining, &written, nullptr)
                                       : WriteFile(out, frame.data() + at, remaining, &written, nullptr);
            if (!ok || !written) return false;
            at += written;
        }
        return true;
    }

    void PumpOutput() {
        std::unique_lock lock(mutex);
        for (;;) {
            changed.wait(lock, [&] { return stopping || outputLost || !pending.empty(); });
            if (stopping || outputLost) return;
            auto item = std::move(pending.front());
            pending.pop_front();
            writing = item.enqueued;
            lock.unlock();
            const bool ok = Write(item.bytes);
            lock.lock();
            writing.reset();
            outputLost |= !ok;
            changed.notify_all();
        }
    }

    bool CheckOutput() {
        const auto oldest = writing ? writing : pending.empty() ? std::nullopt : std::optional(pending.front().enqueued);
        if (oldest && Clock::now() - *oldest >= kOutputTimeout) outputLost = true;
        return !outputLost;
    }

    static unsigned __stdcall ReadEntry(void* arg) noexcept {
        auto& self = *static_cast<State*>(arg);
        try { self.Read(); }
        catch (...) { self.Publish({InputKind::Fatal, {}, {"input-failed", "Input worker failed", std::nullopt, 3}}); }
        return 0;
    }

    static unsigned __stdcall WriteEntry(void* arg) noexcept {
        auto& self = *static_cast<State*>(arg);
        try { self.PumpOutput(); }
        catch (...) {
            std::lock_guard lock(self.mutex);
            self.outputLost = true;
            self.changed.notify_all();
        }
        return 0;
    }
};

Transport::Transport() : state_(std::make_unique<State>()) {}
Transport::~Transport() = default;

Fault Transport::Start(bool jsonl) {
    auto& state = *state_;
    state.jsonl = jsonl;
    if (!ValidHandle(state.in) || !ValidHandle(state.out))
        return Win32Fault("invalid-standard-stream", "A standard stream is unavailable", ERROR_INVALID_HANDLE);
    if (jsonl && (state.consoleIn || state.consoleOut))
        return {"invalid-standard-stream", "JSONL requires byte streams for both stdin and stdout"};
    closeSignal.store(false);
    state.handler = SetConsoleCtrlHandler(OnConsoleControl, TRUE) != FALSE;
    if (!state.handler) return Win32Fault("control-handler-failed", "Could not register console control handler", GetLastError());
    state.writer = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, State::WriteEntry, &state, 0, nullptr));
    state.reader = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, State::ReadEntry, &state, 0, nullptr));
    if (!state.writer || !state.reader) return {"worker-start-failed", "Could not start a transport worker", std::nullopt, 3};
    return {};
}

bool Transport::Interactive() const { return state_->consoleIn && state_->consoleOut; }

Input Transport::Next() {
    auto& state = *state_;
    std::unique_lock lock(state.mutex);
    for (;;) {
        if (!state.CheckOutput()) return {InputKind::OutputLost, {}, {}};
        if (closeSignal.load()) return {InputKind::Break, {}, {}};
        if (state.next) {
            auto item = std::move(*state.next);
            state.next.reset();
            state.changed.notify_all();
            return item;
        }
        state.changed.wait_for(lock, std::chrono::milliseconds(50));
    }
}

bool Transport::Send(std::string frame) {
    auto& state = *state_;
    std::unique_lock lock(state.mutex);
    // 允许正常读取方吸收短时突发。有界队列等待期间 writer 保持独立，超时则终止交付。
    while (state.CheckOutput() && state.pending.size() + (state.writing ? 1 : 0) >= kPendingFrames)
        state.changed.wait_for(lock, std::chrono::milliseconds(50));
    if (!state.CheckOutput()) return false;
    if (frame.size() > kOutputBytes + 1) {
        state.outputLost = true;
        state.changed.notify_all();
        return false;
    }
    state.pending.push_back({std::move(frame), Clock::now()});
    state.changed.notify_all();
    return true;
}

bool Transport::Finish() {
    auto& state = *state_;
    std::unique_lock lock(state.mutex);
    while (state.CheckOutput() && (state.writing || !state.pending.empty()))
        state.changed.wait_for(lock, std::chrono::milliseconds(50));
    return state.CheckOutput();
}

} // namespace ks::cli::action_analyze
