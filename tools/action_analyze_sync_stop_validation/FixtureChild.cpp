#include "Fixture.h"

#include <cwchar>
#include <limits>

namespace sb02 {
namespace {

State state{};
volatile LONG stopWorker = 0;

DWORD WINAPI HeartbeatWorker(void*) {
    while (!InterlockedCompareExchange(&stopWorker, 0, 0)) {
        InterlockedIncrement(&state.heartbeat);
        Sleep(1);
    }
    return 0;
}

DWORD WINAPI RetiredWorker(void*) { return 0; }

LONG Heartbeat() {
    return InterlockedCompareExchange(&state.heartbeat, 0, 0);
}

bool WaitForWorker() {
    const LONG old = Heartbeat();
    const ULONGLONG limit = GetTickCount64() + 1500;
    while (Heartbeat() == old) {
        if (GetTickCount64() >= limit) { return false; }
        Sleep(1);
    }
    return true;
}

int MatchLocalBreakpoint(const EXCEPTION_POINTERS* exception, void (*gate)()) {
    const auto& record = *exception->ExceptionRecord;
    return record.ExceptionCode == EXCEPTION_BREAKPOINT &&
        record.ExceptionAddress == reinterpret_cast<const void*>(gate)
        ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH;
}

bool RegisterRoute(DWORD epoch, DWORD retiredTid) {
    const ULONG_PTR arguments[] = {epoch, kVersion, reinterpret_cast<ULONG_PTR>(&EnterGate),
        reinterpret_cast<ULONG_PTR>(&ReturnGate), reinterpret_cast<ULONG_PTR>(&ForeignGate),
        reinterpret_cast<ULONG_PTR>(&state), retiredTid};
    // 若 owner 未确认，走本地拒绝路径，后续不会进入任何 INT3 站点。
    __try {
        RaiseException(kReadyException, 0, ReadyArgCount, arguments);
        return true;
    } __except (GetExceptionCode() == kReadyException ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
}

void Publish(LONG sequence, DWORD epoch, Phase phase, LONG releaseCount, DWORD result, DWORD error) {
    InterlockedExchange(&state.hit.sequence, 0);
    state.hit.version = kVersion;
    state.hit.size = sizeof(Hit);
    state.hit.epoch = epoch;
    state.hit.tid = GetCurrentThreadId();
    state.hit.phase = phase;
    state.hit.releaseCount = releaseCount;
    state.hit.result = result;
    state.hit.lastError = error;
    LARGE_INTEGER now{};
    QueryPerformanceCounter(&now);
    state.hit.publishedQpc = now.QuadPart;
    InterlockedExchange(&state.hit.sequence, sequence);
}

void ExerciseStaleEpoch(DWORD epoch, LONG releaseCount) {
    Publish(kStaleSequence, epoch ^ 1, Phase::Enter, releaseCount, kNoResult, kEntryError);
    __try {
        EnterGate();
    } __except (MatchLocalBreakpoint(GetExceptionInformation(), &EnterGate)) {
        ++state.staleDelivered;
    }
}

void ExerciseForeignBreakpoint() {
    __try {
        ForeignGate();
    } __except (MatchLocalBreakpoint(GetExceptionInformation(), &ForeignGate)) {
        ++state.foreignDelivered;
    }
}

// 只包围夹具自己的 ReleaseSemaphore 调用，原 API 和调用者各自保留实测结果。
__declspec(noinline) BOOL SelectedCall(HANDLE semaphore, LONG releaseCount, DWORD epoch, bool& workerResumed) {
    Publish(kEnterSequence, epoch, Phase::Enter, releaseCount, kNoResult, kEntryError);
    SetLastError(kEntryError);
    EnterGate();
    state.entryErrorSeen = GetLastError();
    const bool afterEnter = WaitForWorker();

    ++state.originalCalls;
    SetLastError(state.entryErrorSeen);
    const BOOL result = ReleaseSemaphore(semaphore, releaseCount, nullptr);
    const DWORD error = GetLastError();

    Publish(kReturnSequence, epoch, Phase::Return, releaseCount, static_cast<DWORD>(result), error);
    SetLastError(kObserverError);
    ReturnGate();
    workerResumed = WaitForWorker() && afterEnter;
    SetLastError(error);
    return result;
}

int Exercise(HANDLE semaphore, LONG releaseCount, DWORD epoch, DWORD retiredTid) {
    if (!WaitForWorker() || !RegisterRoute(epoch, retiredTid)) { return 21; }
    ExerciseStaleEpoch(epoch, releaseCount);
    if (state.staleDelivered != 1) { return 22; }

    bool workerResumed = false;
    const BOOL result = SelectedCall(semaphore, releaseCount, epoch, workerResumed);
    const DWORD error = GetLastError();
    state.callerResult = static_cast<DWORD>(result);
    state.callerError = error;
    state.callerReached = 1;
    state.semaphoreProbe = WaitForSingleObject(semaphore, 0);
    ExerciseForeignBreakpoint();

    const bool successCase = releaseCount == 1;
    return workerResumed && state.originalCalls == 1 && state.entryErrorSeen == kEntryError &&
        state.foreignDelivered == 1 && state.callerResult == state.hit.result &&
        state.callerError == state.hit.lastError &&
        (successCase ? (result == TRUE && state.semaphoreProbe == WAIT_OBJECT_0)
                     : (result == FALSE && error == ERROR_TOO_MANY_POSTS && state.semaphoreProbe == WAIT_TIMEOUT)) ? 0 : 23;
}

}  // namespace

int RunChild(int argc, wchar_t** argv) {
    const bool ledgerScope = argc == 5 && wcscmp(argv[4], L"--ledger-scope") == 0;
    if ((!ledgerScope && argc != 4) || !IsDebuggerPresent()) { return 20; }
    const LONG releaseCount = wcscmp(argv[2], L"success") == 0 ? 1 : wcscmp(argv[2], L"error") == 0 ? 2 : 0;
    wchar_t* end = nullptr;
    const auto parsedEpoch = wcstoull(argv[3], &end, 10);
    if (!releaseCount || !parsedEpoch || parsedEpoch > (std::numeric_limits<DWORD>::max)() || *end) { return 20; }

    DWORD retiredTid = 0;
    if (ledgerScope) {
        // 正常加入真实已退出线程，由外部调试器核对退出事件及原始对象。
        const HANDLE retired = CreateThread(nullptr, 0, RetiredWorker, nullptr, 0, &retiredTid);
        if (!retired) { return 27; }
        const DWORD retiredResult = WaitForSingleObject(retired, 1500);
        const BOOL retiredClosed = CloseHandle(retired);
        if (retiredResult != WAIT_OBJECT_0 || !retiredClosed) { return 28; }
    }
    HANDLE semaphore = CreateSemaphoreW(nullptr, 0, 1, nullptr);
    if (!semaphore) { return 24; }
    HANDLE worker = CreateThread(nullptr, 0, HeartbeatWorker, nullptr, 0, &state.workerTid);
    if (!worker) {
        CloseHandle(semaphore);
        return 25;
    }
    const int result = Exercise(semaphore, releaseCount, static_cast<DWORD>(parsedEpoch), retiredTid);
    InterlockedExchange(&stopWorker, 1);
    const DWORD wait = WaitForSingleObject(worker, 1500);
    const BOOL workerClosed = CloseHandle(worker);
    const BOOL semaphoreClosed = CloseHandle(semaphore);
    return wait == WAIT_OBJECT_0 && workerClosed && semaphoreClosed ? result : 26;
}

}  // namespace sb02

int wmain(int argc, wchar_t** argv) {
    if (argc > 1 && wcscmp(argv[1], L"--child") == 0) { return sb02::RunChild(argc, argv); }
#if defined(_M_X64)
    if (argc == 1) { return sb02::RunOwner(false); }
    if (argc == 2 && wcscmp(argv[1], L"--ledger") == 0) { return sb02::RunOwner(true); }
#endif
    return 2;
}
