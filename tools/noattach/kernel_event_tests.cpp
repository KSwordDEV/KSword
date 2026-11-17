// This body uses the actual included driver functions, never VMX or a kernel patch.
KNA_SESSION g_Kna{};
static CONTEXT contextStorage{}, captureStorage{}, targetFrame{};
static std::mutex frameMutex;
static unsigned int checks = 0;
static LONG suspendCount = 0;
static bool failGet = false, failSet = false;
static thread_local PETHREAD currentThread = reinterpret_cast<void*>(std::uintptr_t{1});
static std::atomic<unsigned int> revocations{0};
void* PsGetCurrentThread() { return currentThread; }
BOOLEAN PsIsThreadTerminating(PETHREAD) { return FALSE; }
void KnaRevoke() { ++revocations; InterlockedExchange(&g_Kna.Closing, 1); KeSetEvent(&g_Kna.ContinueEvent, 0, FALSE); }
void KnaReadFrames(PVOID trap, PVOID, PCONTEXT output)
{
    std::lock_guard<std::mutex> lock(frameMutex);
    *output = *static_cast<PCONTEXT>(trap);
}
void KnaWriteFrames(PVOID trap, PVOID, PCONTEXT input, ULONG, KPROCESSOR_MODE)
{
    std::lock_guard<std::mutex> lock(frameMutex);
    *static_cast<PCONTEXT>(trap) = *input;
}
static NTSTATUS NTAPI suspend(PETHREAD, PULONG old) { *old = static_cast<ULONG>(suspendCount++); return STATUS_SUCCESS; }
static NTSTATUS NTAPI resume(PETHREAD, PULONG old) { *old = static_cast<ULONG>(suspendCount); if (suspendCount) --suspendCount; return STATUS_SUCCESS; }
static NTSTATUS NTAPI getContext(PETHREAD, PCONTEXT output, KPROCESSOR_MODE)
{
    if (failGet) return STATUS_ACCESS_DENIED;
    std::lock_guard<std::mutex> lock(frameMutex); *output = targetFrame; return STATUS_SUCCESS;
}
static NTSTATUS NTAPI setContext(PETHREAD, PCONTEXT input, KPROCESSOR_MODE)
{
    if (failSet) return STATUS_ACCESS_DENIED;
    std::lock_guard<std::mutex> lock(frameMutex); targetFrame = *input; return STATUS_SUCCESS;
}
static void check(bool result, const char* description)
{
    if (!result) { std::cerr << "KERNEL_EVENT_FAIL " << description << '\n'; std::abort(); }
    ++checks;
}
template<class Predicate> static void until(Predicate predicate)
{
    const auto deadline = GetTickCount64() + 3000;
    while (GetTickCount64() < deadline) { if (predicate()) return; Sleep(1); }
    check(false, "condition reached before deadline");
}
static ULONG state()
{
    KIRQL old; KeAcquireSpinLock(&g_Kna.StateLock, &old); const auto value = g_Kna.State; KeReleaseSpinLock(&g_Kna.StateLock, old); return value;
}
static void issue(ULONG action, const KSWORD_ARK_KERNEL_NOATTACH_REQUEST& request = {})
{
    KIRQL old; KeAcquireSpinLock(&g_Kna.StateLock, &old);
    g_Kna.Pending = request; g_Kna.Action = action;
    g_Kna.State = action == KSWORD_ARK_HVM_NOATTACH_STEP ? KSWORD_ARK_HVM_NOATTACH_STEP_PENDING :
        action == KSWORD_ARK_HVM_NOATTACH_CONTINUE ? KSWORD_ARK_HVM_NOATTACH_CONTINUE_PENDING : KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING;
    KeSetEvent(&g_Kna.ContinueEvent, 0, FALSE); KeReleaseSpinLock(&g_Kna.StateLock, old);
}
int main()
{
    g_Kna.Initialized = 2; g_Kna.Owned = 1; g_Kna.Thread = currentThread;
    g_Kna.Context = &contextStorage; g_Kna.Capture = &captureStorage;
    g_Kna.Suspend = suspend; g_Kna.Resume = resume; g_Kna.GetContext = getContext; g_Kna.SetContext = setContext;
    g_Kna.ContinueEvent.handle = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    g_Kna.ObserverIdle.handle = CreateEventW(nullptr, TRUE, TRUE, nullptr);
    targetFrame.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    targetFrame.SegCs = 0x33; targetFrame.SegSs = 0x2B; targetFrame.EFlags = 0x202;
    targetFrame.Rip = 0x10000000; targetFrame.Rsp = 0x70000000; targetFrame.Rax = 0x100;
    g_Kna.State = KSWORD_ARK_HVM_NOATTACH_RUNNING;
    check(KnaRequestPause() == STATUS_SUCCESS, "pause accepted with real consumer ownership");
    check(suspendCount == 0 && !g_Kna.OwnSuspend && g_Kna.OwnTf, "own suspend count balanced, pending TF tracked");
    check((targetFrame.EFlags & 0x100) && state() == KSWORD_ARK_HVM_NOATTACH_PAUSE_PENDING, "TF arrangement is not a fake stop");
    targetFrame.Dr6 = 0x4000;
    EXCEPTION_RECORD debug{}; debug.ExceptionCode = STATUS_SINGLE_STEP;
    bool handled = false;
    std::thread target([&]() { handled = KnaObserve(&debug, nullptr, &targetFrame, UserMode, TRUE); });
    until([]() { return state() == KSWORD_ARK_HVM_NOATTACH_STOPPED; });
    check(g_Kna.Snapshot.stopId == 1 && g_Kna.Snapshot.rax == 0x100 && !g_Kna.OwnTf, "real exception publishes exact first stop");
    check((targetFrame.EFlags & 0x100) == 0, "self-owned TF cleared in actual stopped frame");
    KSWORD_ARK_KERNEL_NOATTACH_REQUEST add{}; add.operation = KSWORD_ARK_HVM_NOATTACH_ADD_BREAKPOINT; add.address = targetFrame.Rip;
    KIRQL old; KeAcquireSpinLock(&g_Kna.StateLock, &old);
    check(KnaEditBreakpoint(&add) == STATUS_SUCCESS, "first DR record accepted");
    check((g_Kna.Rows[0].flags & KSWORD_ARK_KERNEL_NOATTACH_BP_PENDING) != 0, "accepted config remains explicitly pending");
    KeReleaseSpinLock(&g_Kna.StateLock, old);
    issue(add.operation, add); until([]() { return state() == KSWORD_ARK_HVM_NOATTACH_STOPPED && g_Kna.Snapshot.stopId == 2; });
    check(targetFrame.Dr0 == add.address && (targetFrame.Dr7 & 1), "target thread actually commits DR configuration");
    check(!(g_Kna.Rows[0].flags & KSWORD_ARK_KERNEL_NOATTACH_BP_PENDING) && g_Kna.Snapshot.stopReason == 4, "config completion has new stop identity");
    KSWORD_ARK_KERNEL_NOATTACH_REQUEST edit{}; edit.operation = 9; edit.registerMask = 1; edit.registers.rax = 0x777;
    issue(edit.operation, edit); until([]() { return state() == 3 && g_Kna.Snapshot.stopId == 3; });
    check(targetFrame.Rax == 0x777 && g_Kna.Snapshot.rax == 0x777, "integer commit updates frame and authoritative document");
    issue(KSWORD_ARK_HVM_NOATTACH_STEP); target.join();
    check(handled && (targetFrame.EFlags & 0x100) && (targetFrame.EFlags & 0x10000), "STEP returns through real TF/RF state, not a timer");
    check(g_Kna.OwnTf && state() == 4 && g_Kna.Observer == 0, "next step is pending after old exception leaves");
    targetFrame.Rip += 3; targetFrame.Rax += 1; targetFrame.Dr6 = 0x4000;
    std::thread next([&]() { handled = KnaObserve(&debug, nullptr, &targetFrame, UserMode, TRUE); });
    until([]() { return state() == 3 && g_Kna.Snapshot.stopId == 4; });
    check(g_Kna.Snapshot.stopReason == 2 && g_Kna.Snapshot.rax == 0x778, "actual next exception reports TF step");
    issue(KSWORD_ARK_HVM_NOATTACH_CLOSE); InterlockedExchange(&g_Kna.Closing, 1); KeSetEvent(&g_Kna.ContinueEvent, 0, FALSE); next.join();
    check(handled && targetFrame.Dr0 == 0 && !(targetFrame.Dr7 & 1) && !(targetFrame.EFlags & 0x100), "close restores only owned debug state");
    check(g_Kna.Observer == 0 && revocations > 0, "actual observer completion enables lifecycle cleanup");
    g_Kna.Closing = 0; g_Kna.State = 1; g_Kna.Rows[0] = {}; g_Kna.OwnTf = TRUE;
    targetFrame.EFlags |= 0x100; targetFrame.Dr6 = 0;
    EXCEPTION_RECORD fault{}; fault.ExceptionCode = STATUS_ACCESS_VIOLATION;
    const auto previousStop = g_Kna.Snapshot.stopId;
    check(!KnaObserve(&fault, nullptr, &targetFrame, UserMode, TRUE), "unrelated target exception retains Windows dispatch");
    check(state() == 6 && !(targetFrame.EFlags & 0x100) && g_Kna.Snapshot.stopId == previousStop, "exception interruption never fabricates a completed step");
    g_Kna.State = 1; g_Kna.OwnTf = TRUE; targetFrame.EFlags |= 0x100; targetFrame.Dr6 = 0x4004;
    check(!KnaObserve(&debug, nullptr, &targetFrame, UserMode, TRUE), "mixed foreign DR cause is forwarded");
    check((targetFrame.Dr6 & 4) && !(targetFrame.EFlags & 0x100), "foreign cause survives owned TF cleanup");
    g_Kna.State = 1; g_Kna.OwnTf = FALSE; targetFrame.Dr6 = 0;
    currentThread = reinterpret_cast<void*>(std::uintptr_t{2});
    check(!KnaObserve(&debug, nullptr, &targetFrame, UserMode, TRUE), "other thread cannot borrow target stop");
    currentThread = g_Kna.Thread;
    g_Kna.State = 1; suspendCount = 2;
    check(KnaRequestPause() == STATUS_DEVICE_BUSY && suspendCount == 2 && !g_Kna.OwnSuspend, "external suspend counts are not cleared");
    suspendCount = 0; failGet = true; g_Kna.State = 1;
    check(KnaRequestPause() == STATUS_ACCESS_DENIED && suspendCount == 0, "capture failure balances only own suspension");
    failGet = false; failSet = true; g_Kna.State = 1; targetFrame.EFlags &= ~0x100UL;
    check(KnaRequestPause() == STATUS_ACCESS_DENIED && suspendCount == 0 && !g_Kna.OwnTf, "TF setup failure cannot leave a fake pending stop");
    CloseHandle(g_Kna.ContinueEvent.handle); CloseHandle(g_Kna.ObserverIdle.handle);
    std::cout << "KERNEL_EVENT_PASS checks=" << checks << " (production event/context/DR code, simulated frames, no patch)\n";
}
