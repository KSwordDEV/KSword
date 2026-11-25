#pragma once

#include <Windows.h>
#include <cstddef>
#include <type_traits>

namespace sb02 {

constexpr DWORD kVersion = 1;
constexpr DWORD kReadyException = 0xe041a501;
constexpr DWORD kWow64Breakpoint = 0x4000001f;
constexpr DWORD kEntryError = 0x1234;
constexpr DWORD kObserverError = 0x5678;
constexpr DWORD kNoResult = 0xffffffff;
constexpr LONG kStaleSequence = 1;
constexpr LONG kEnterSequence = 2;
constexpr LONG kReturnSequence = 3;

enum class Phase : DWORD { Enter = 1, Return = 2 };
enum ReadyArg { EpochArg, VersionArg, EnterArg, ReturnArg, ForeignArg, StateArg, ReadyArgCount };

// 固定宽度，供 x64 owner 读取两个位数的子进程。槽内不传地址或句柄。
struct Hit {
    volatile LONG sequence;
    DWORD version;
    DWORD size;
    DWORD epoch;
    DWORD tid;
    Phase phase;
    LONG releaseCount;
    DWORD result;
    DWORD lastError;
    LONG64 publishedQpc;
};

struct State {
    Hit hit;
    volatile LONG heartbeat;
    DWORD workerTid;
    DWORD originalCalls;
    DWORD callerReached;
    DWORD callerResult;
    DWORD callerError;
    DWORD entryErrorSeen;
    DWORD semaphoreProbe;
    DWORD staleDelivered;
    DWORD foreignDelivered;
};

static_assert(std::is_trivially_copyable_v<State>);
static_assert(offsetof(Hit, publishedQpc) == 40 && sizeof(Hit) == 48);
static_assert(offsetof(State, heartbeat) == 48 && sizeof(State) == 88);

int RunChild(int argc, wchar_t** argv);

#if defined(_M_X64)
int RunOwner();
#endif

}  // namespace sb02

extern "C" void EnterGate();
extern "C" void ReturnGate();
extern "C" void ForeignGate();
