#pragma once
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace validation {
void Require(bool condition, const char* text);
void Check(BOOL success, const char* operation);
int FailureCount();

class Handle final {
public:
    explicit Handle(HANDLE value = nullptr) noexcept;
    ~Handle();
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE get() const noexcept { return value_; }
    void reset(HANDLE value = nullptr) noexcept;
    static int Count() noexcept;
private:
    HANDLE value_ = nullptr;
};

enum class Reason { UserBreakpoint, TemporaryBreakpoint, SingleStep, Exception };
struct Stop {
    Reason reason;
    DWORD code;
    DWORD thread;
    DWORD firstChance;
    std::uintptr_t address;
    CONTEXT context;
};

class DebugSession final {
public:
    DebugSession(const char* scenario, bool controlledException);
    ~DebugSession();
    DebugSession(const DebugSession&) = delete;
    DebugSession& operator=(const DebugSession&) = delete;
    std::uintptr_t Address(const unsigned char* localLabel) const;
    void Arm(std::uintptr_t address, Reason reason);
    void Remove(std::uintptr_t address);
    void CancelTemporary();
    bool IsOriginal(std::uintptr_t address) const;
    std::uintptr_t ReadPointer(std::uintptr_t address) const;
    unsigned char ReadByte(std::uintptr_t address) const;
    Stop WaitStop();
    void Continue(DWORD disposition = DBG_CONTINUE);
    void Step();
    void SetContext(CONTEXT context);
    void Finish();
    void AbortForCleanupTest();
private:
    struct Breakpoint { std::uintptr_t address; unsigned char original; Reason reason; bool armed; };
    void Launch(bool controlledException);
    void WriteByte(std::uintptr_t address, unsigned char value);
    bool NextEvent();
    void CloseEventHandles();
    void Cleanup() noexcept;
    const char* scenario_;
    Handle job_, process_, thread_;
    DWORD pid_ = 0, tid_ = 0;
    std::uintptr_t imageBase_ = 0;
    ULONGLONG deadline_ = 0;
    DEBUG_EVENT event_{};
    bool pending_ = false, exited_ = false, loaderBreakpointSeen_ = false;
    bool expectedAbort_ = false;
    DWORD exitCode_ = STILL_ACTIVE;
    std::vector<Breakpoint> breakpoints_;
};
}
