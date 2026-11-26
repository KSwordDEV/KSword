#include "ExplorerProbe.h"
#include <TlHelp32.h>
#include <algorithm>
#include <cstdio>
#include <map>
#include <set>

namespace ExplorerProbe
{
    namespace
    {
        struct Thread
        {
            HANDLE handle = nullptr;
            size_t ledger = 0;
            bool initial = false;
            bool createEventSeen = false;
        };

        class Session
        {
            Shared& s;
            std::map<DWORD, Thread> threads;
            std::map<DWORD, ULONGLONG> exitedThreads;
            std::set<DWORD> hitThreads;
            DEBUG_EVENT event{};
            bool pending = false;
            bool attached = false;
            bool prepared = false;
            bool stopping = false;
            DWORD steppingTid = 0;
            DWORD cycleSteps = 0;
            LARGE_INTEGER cycleStart{};
            LARGE_INTEGER frequency{};
            ULONGLONG deadline = 0;
            DWORD continuation = DBG_CONTINUE;

            bool Fail(const char* where)
            {
                s.lastError = GetLastError();
                InterlockedExchange(&s.failed, 1);
                std::printf("CHILD_FAIL stage=%s error=%lu\n", where, s.lastError);
                return false;
            }

            bool AddThread(DWORD tid, HANDLE provided)
            {
                HANDLE copy = nullptr;
                const BOOL duplicated = DuplicateHandle(GetCurrentProcess(), provided,
                    GetCurrentProcess(), &copy, 0, FALSE, DUPLICATE_SAME_ACCESS);
                // The original debug-event handle is closed by Windows on EXIT_THREAD /
                // EXIT_PROCESS continuation. Closing it early lets that automatic close hit
                // an unrelated recycled handle. Only our duplicate belongs to this map.
                if (!duplicated) return Fail("duplicate_thread");
                const size_t index = static_cast<size_t>(s.ledgerCount);
                if (index >= maxThreads)
                {
                    CloseHandle(copy);
                    SetLastError(ERROR_TOO_MANY_TCBS);
                    return Fail("thread_capacity_or_duplicate");
                }
                FILETIME created{}, exited{}, kernel{}, user{};
                if (!GetThreadTimes(copy, &created, &exited, &kernel, &user))
                {
                    CloseHandle(copy);
                    return Fail("thread_identity");
                }
                const auto existing = threads.find(tid);
                if (existing != threads.end())
                {
                    CloseHandle(copy);
                    if (s.ledger[existing->second.ledger].created != FileTicks(created)
                        || existing->second.createEventSeen)
                    {
                        SetLastError(ERROR_INVALID_DATA);
                        return Fail("duplicate_thread_identity");
                    }
                    existing->second.createEventSeen = true;
                    ++s.createdThreads;
                    for (auto& call : s.calls) if (call.tid == tid) call.createSeen = 1;
                    return true;
                }
                s.ledger[index].tid = tid;
                s.ledger[index].created = FileTicks(created);
                InterlockedIncrement(&s.ledgerCount);
                threads.emplace(tid, Thread{copy, index, !prepared, true});
                s.peakThreads = (std::max)(s.peakThreads, static_cast<DWORD>(threads.size()));
                if (prepared)
                {
                    ++s.createdThreads;
                    for (auto& call : s.calls)
                        if (call.tid == tid) call.createSeen = 1;
                    if (steppingTid)
                    {
                        ++s.createdWhileStepping;
                        return Hold(threads.at(tid));
                    }
                }
                return true;
            }

            bool Hold(Thread& thread)
            {
                auto& ledger = s.ledger[thread.ledger];
                if (ledger.held) return true;
                const DWORD previous = SuspendThread(thread.handle);
                if (previous == static_cast<DWORD>(-1)) return Fail("suspend");
                ledger.previousSuspendCount = previous;
                InterlockedExchange(&ledger.held, 1);
                // Existing suspensions belong to somebody else; retain and then return only our count.
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(thread.handle, &context)) return Fail("verify_hold");
                return true;
            }

            bool Release(Thread& thread)
            {
                auto& ledger = s.ledger[thread.ledger];
                if (!ledger.held) return true;
                const DWORD previous = ResumeThread(thread.handle);
                if (previous == static_cast<DWORD>(-1)) return Fail("resume");
                InterlockedExchange(&ledger.held, 0);
                if (previous != ledger.previousSuspendCount + 1)
                {
                    SetLastError(ERROR_INVALID_STATE);
                    return Fail("external_suspend_count_changed");
                }
                return true;
            }

            bool ReleaseAll()
            {
                bool success = true;
                for (auto& [tid, thread] : threads)
                {
                    (void)tid;
                    if (!Release(thread)) success = false;
                }
                return success;
            }

            bool Protect(DWORD value)
            {
                DWORD previous = 0;
                if (!VirtualProtectEx(s.target, reinterpret_cast<void*>(s.watch), s.watchBytes,
                    value, &previous)) return Fail("protect");
                MEMORY_BASIC_INFORMATION memory{};
                if (VirtualQueryEx(s.target, reinterpret_cast<void*>(s.watch), &memory,
                    sizeof(memory)) != sizeof(memory) || memory.Protect != value)
                {
                    SetLastError(ERROR_INVALID_DATA);
                    return Fail("protection_readback");
                }
                return true;
            }

            bool RestoreProtection()
            {
                if (!s.protectionOwned) return true;
                if (!Protect(s.originalProtection)) return false;
                InterlockedExchange(&s.protectionOwned, 0);
                s.protectRestored = 1;
                return true;
            }

            bool ClearTf()
            {
                if (!steppingTid) return true;
                const auto found = threads.find(steppingTid);
                if (found == threads.end())
                {
                    steppingTid = 0;
                    return true;
                }
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(found->second.handle, &context)) return Fail("clear_tf_get");
                context.EFlags &= ~trapFlag;
                if (!SetThreadContext(found->second.handle, &context)) return Fail("clear_tf_set");
                if (!GetThreadContext(found->second.handle, &context) || (context.EFlags & trapFlag))
                {
                    SetLastError(ERROR_INVALID_STATE);
                    return Fail("clear_tf_readback");
                }
                InterlockedExchange(&s.ledger[found->second.ledger].ownTf, 0);
                steppingTid = 0;
                return true;
            }

            bool StopProbe()
            {
                // All threads are held by the current Windows debug event here.
                // Restore X before returning our TF or suspension responsibilities.
                stopping = true;
                const bool protection = RestoreProtection();
                const bool tf = ClearTf();
                const bool released = ReleaseAll();
                return protection && tf && released;
            }

            bool VerifyCompleteSet()
            {
                HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                if (snapshot == INVALID_HANDLE_VALUE) return Fail("thread_snapshot");
                THREADENTRY32 item{};
                item.dwSize = sizeof(item);
                bool complete = Thread32First(snapshot, &item) != FALSE;
                if (complete)
                {
                    do
                    {
                        if (item.th32OwnerProcessID != s.pid || threads.contains(item.th32ThreadID)) continue;
                        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT
                            | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION | SYNCHRONIZE,
                            FALSE, item.th32ThreadID);
                        if (!thread)
                        {
                            // A snapshot is not a live-thread barrier. Entries can disappear meanwhile.
                            if (GetLastError() == ERROR_INVALID_PARAMETER)
                            {
                                ++s.snapshotExitedThreads;
                                continue;
                            }
                            std::printf("MISSING_THREAD tid=%lu open_error=%lu\n", item.th32ThreadID, GetLastError());
                            complete = false;
                            continue;
                        }
                        FILETIME created{}, exited{}, kernel{}, user{};
                        if (WaitForSingleObject(thread, 0) == WAIT_OBJECT_0)
                        {
                            ++s.snapshotExitedThreads;
                            CloseHandle(thread);
                            continue;
                        }
                        const size_t index = static_cast<size_t>(s.ledgerCount);
                        if (index >= maxThreads || !GetThreadTimes(thread, &created, &exited, &kernel, &user)
                            || GetProcessIdOfThread(thread) != s.pid)
                        {
                            CloseHandle(thread);
                            complete = false;
                            continue;
                        }
                        const auto retired = exitedThreads.find(item.th32ThreadID);
                        if (retired != exitedThreads.end() && retired->second == FileTicks(created))
                        {
                            // EXIT_THREAD is authoritative even while the dying kernel object
                            // still appears in Toolhelp and its handle is not signaled yet.
                            ++s.snapshotExitedThreads;
                            std::printf("SNAPSHOT_AFTER_EXIT_EVENT tid=%lu\n", item.th32ThreadID);
                            CloseHandle(thread);
                            continue;
                        }
                        // External creation can become visible in Toolhelp before CREATE_THREAD
                        // is delivered. Retain exact identity and hold it; never claim the gate
                        // was delivered until the actual event arrives before user execution.
                        s.ledger[index].tid = item.th32ThreadID;
                        s.ledger[index].created = FileTicks(created);
                        InterlockedIncrement(&s.ledgerCount);
                        threads.emplace(item.th32ThreadID, Thread{thread, index, false, false});
                        ++s.snapshotPendingThreads;
                        std::printf("SNAPSHOT_PENDING_CREATE tid=%lu\n", item.th32ThreadID);
                        if (!Hold(threads.at(item.th32ThreadID))) complete = false;
                    } while (Thread32Next(snapshot, &item));
                }
                CloseHandle(snapshot);
                if (!complete)
                {
                    SetLastError(ERROR_NOT_FOUND);
                    return Fail("missing_live_thread");
                }
                return true;
            }

            bool Prepare()
            {
                if (!VerifyCompleteSet()) return false;
                s.attachedThreads = static_cast<DWORD>(threads.size());
                MEMORY_BASIC_INFORMATION memory{};
                if (VirtualQueryEx(s.target, reinterpret_cast<void*>(s.watch), &memory,
                    sizeof(memory)) != sizeof(memory) || memory.State != MEM_COMMIT
                    || memory.Protect != PAGE_EXECUTE_READ)
                {
                    SetLastError(ERROR_INVALID_DATA);
                    return Fail("require_original_rx");
                }
                s.originalProtection = memory.Protect;
                // Publish responsibility before mutation, so the guardian can restore either side.
                InterlockedExchange(&s.protectionOwned, 1);
                if (!Protect(PAGE_READONLY)) return false;
                prepared = true;
                std::printf("ARM pid=%lu threads=%lu watch=0x%llx bytes=%zu original=0x%lx\n",
                    s.pid, s.attachedThreads, static_cast<unsigned long long>(s.watch),
                    s.watchBytes, s.originalProtection);
                for (DWORD i = 0; i < s.requestedCalls; ++i)
                {
                    DWORD tid = 0;
                    HANDLE call = CreateRemoteThread(s.target, nullptr, 0,
                        reinterpret_cast<LPTHREAD_START_ROUTINE>(s.entry), s.argument, 0, &tid);
                    if (!call) return Fail("benign_remote_thread");
                    s.calls[i].tid = tid;
                    HANDLE guardianCopy = nullptr;
                    const BOOL copied = DuplicateHandle(GetCurrentProcess(), call, s.guardian,
                        &guardianCopy, SYNCHRONIZE | THREAD_QUERY_INFORMATION, FALSE, 0);
                    CloseHandle(call);
                    if (!copied) return Fail("guardian_call_handle");
                    s.calls[i].guardianHandle = guardianCopy;
                }
                return true;
            }

            bool Fault()
            {
                auto& record = event.u.Exception.ExceptionRecord;
                const auto fault = static_cast<std::uintptr_t>(record.ExceptionInformation[1]);
                const auto found = threads.find(event.dwThreadId);
                if (found == threads.end()) return Fail("fault_thread_missing");
                if (!found->second.createEventSeen)
                {
                    SetLastError(ERROR_INVALID_DATA);
                    return Fail("fault_before_real_create_event");
                }
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
                if (!GetThreadContext(found->second.handle, &context)) return Fail("fault_context");
                if (!Inside(context.Rip, s.execution, s.executionBytes))
                {
                    SetLastError(ERROR_INVALID_ADDRESS);
                    return Fail("fault_rip_outside_execution_range");
                }
                if ((context.EFlags & trapFlag) || (context.Dr7 & 0xff))
                {
                    SetLastError(ERROR_BUSY);
                    return Fail("external_tf_dr_or_nested_nx");
                }
                ++s.faults;
                if (found->second.initial) ++s.existingThreadFaults;
                hitThreads.insert(event.dwThreadId);
                s.distinctFaultThreads = static_cast<DWORD>(hitThreads.size());
                if ((context.Rip & ~0xfffull) != (fault & ~0xfffull)) ++s.crossPageFaults;
                for (auto& call : s.calls)
                {
                    if (call.tid == event.dwThreadId)
                    {
                        if (!call.createSeen)
                        {
                            SetLastError(ERROR_INVALID_DATA);
                            return Fail("execution_before_create_gate");
                        }
                        ++call.faults;
                    }
                }
                std::printf("NX tid=%lu rip=0x%llx fault=0x%llx first=%lu\n", event.dwThreadId,
                    static_cast<unsigned long long>(context.Rip),
                    static_cast<unsigned long long>(fault), event.u.Exception.dwFirstChance);
                if (steppingTid)
                {
                    if (steppingTid != event.dwThreadId && s.ledger[found->second.ledger].held)
                    {
                        // An AV can already be queued before our explicit hold. Consume our NX
                        // event, keep this thread suspended, and let it retry after rearm/release.
                        ++s.queuedFaults;
                        return true;
                    }
                    SetLastError(ERROR_BUSY);
                    return Fail("nested_nx_on_unheld_thread");
                }
                if (s.mode == Mode::Guardian)
                {
                    // This deliberate guardian test stops before TF or explicit suspensions exist.
                    SetEvent(s.faultReady);
                    WaitForSingleObject(s.guardian, INFINITE);
                    SetLastError(ERROR_PROCESS_ABORTED);
                    return Fail("guardian_did_not_terminate_controller");
                }
                QueryPerformanceCounter(&cycleStart);
                if (!VerifyCompleteSet()) return false;
                for (auto& [tid, thread] : threads)
                    if (tid != event.dwThreadId && !Hold(thread)) return false;
                steppingTid = event.dwThreadId;
                cycleSteps = 0;
                InterlockedExchange(&s.ledger[found->second.ledger].ownTf, 1);
                context.ContextFlags = CONTEXT_CONTROL;
                context.EFlags |= trapFlag;
                if (!SetThreadContext(found->second.handle, &context)) return Fail("set_own_tf");
                return Protect(s.originalProtection);
            }

            bool Step()
            {
                const auto found = threads.find(steppingTid);
                if (found == threads.end()) return Fail("step_thread_missing");
                CONTEXT context{};
                context.ContextFlags = CONTEXT_CONTROL;
                if (!GetThreadContext(found->second.handle, &context)) return Fail("step_context");
                ++cycleSteps;
                ++s.steps;
                LARGE_INTEGER now{};
                QueryPerformanceCounter(&now);
                const ULONGLONG elapsed = static_cast<ULONGLONG>(
                    (now.QuadPart - cycleStart.QuadPart) * 1000000 / frequency.QuadPart);
                s.maxCycleUs = (std::max)(s.maxCycleUs, elapsed);
                if (s.mode == Mode::AbortStep && Inside(context.Rip, s.execution, s.executionBytes))
                {
                    s.abortedInPage = 1;
                    return StopProbe();
                }
                if (!Inside(context.Rip, s.execution, s.executionBytes))
                {
                    if (!Protect(PAGE_READONLY) || !ClearTf()) return false;
                    ++s.rearms;
                    if (!ReleaseAll()) return false;
                    if (s.mode == Mode::Image && s.rearms >= s.goal) return StopProbe();
                    return true;
                }
                if (cycleSteps >= 512 || elapsed > 250000)
                {
                    SetLastError(ERROR_TIMEOUT);
                    return Fail("bounded_step_budget");
                }
                context.EFlags |= trapFlag;
                if (!SetThreadContext(found->second.handle, &context)) return Fail("continue_tf");
                return true;
            }

            bool HandleEvent()
            {
                continuation = DBG_CONTINUE;
                switch (event.dwDebugEventCode)
                {
                case CREATE_PROCESS_DEBUG_EVENT:
                    if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
                    return AddThread(event.dwThreadId, event.u.CreateProcessInfo.hThread);
                case CREATE_THREAD_DEBUG_EVENT:
                    return AddThread(event.dwThreadId, event.u.CreateThread.hThread);
                case EXIT_THREAD_DEBUG_EVENT:
                {
                    for (auto& call : s.calls)
                    {
                        if (call.tid == event.dwThreadId)
                        {
                            call.exitSeen = 1;
                            call.exitCode = event.u.ExitThread.dwExitCode;
                            ++s.callsCompleted;
                            if (call.exitCode != s.expectedExit || !call.faults || !call.createSeen)
                            {
                                SetLastError(ERROR_INVALID_DATA);
                                return Fail("call_exit_or_execution_evidence");
                            }
                        }
                    }
                    const auto found = threads.find(event.dwThreadId);
                    if (found != threads.end())
                    {
                        exitedThreads[event.dwThreadId] = s.ledger[found->second.ledger].created;
                        InterlockedExchange(&s.ledger[found->second.ledger].held, 0);
                        InterlockedExchange(&s.ledger[found->second.ledger].ownTf, 0);
                        CloseHandle(found->second.handle);
                        threads.erase(found);
                    }
                    if (event.dwThreadId == steppingTid)
                    {
                        steppingTid = 0;
                        return Fail("selected_thread_exited_inside_probe");
                    }
                    if (s.requestedCalls && s.callsCompleted == s.requestedCalls) return StopProbe();
                    return true;
                }
                case LOAD_DLL_DEBUG_EVENT:
                    if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
                    return true;
                case EXIT_PROCESS_DEBUG_EVENT:
                    SetLastError(ERROR_PROCESS_ABORTED);
                    return Fail("explorer_exited");
                case EXCEPTION_DEBUG_EVENT:
                {
                    const auto& record = event.u.Exception.ExceptionRecord;
                    continuation = DBG_EXCEPTION_NOT_HANDLED;
                    if (!prepared && record.ExceptionCode == EXCEPTION_BREAKPOINT)
                    {
                        continuation = DBG_CONTINUE;
                        return Prepare();
                    }
                    if (!stopping && prepared && record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION
                        && record.NumberParameters >= 2 && record.ExceptionInformation[0] == 8
                        && Inside(record.ExceptionInformation[1], s.watch, s.watchBytes))
                    {
                        const bool success = Fault();
                        // We own this protection-induced AV even if the experiment aborts.
                        continuation = DBG_CONTINUE;
                        return success;
                    }
                    if (steppingTid == event.dwThreadId && record.ExceptionCode == EXCEPTION_SINGLE_STEP)
                    {
                        continuation = DBG_CONTINUE;
                        return Step();
                    }
                    ++s.unknownFirstChance;
                    if (steppingTid || !event.u.Exception.dwFirstChance)
                    {
                        SetLastError(ERROR_UNHANDLED_EXCEPTION);
                        return Fail("unowned_exception_during_step_or_second_chance");
                    }
                    // Unknown exceptions retain Windows/target dispatch semantics.
                    return true;
                }
                default:
                    return true;
                }
            }

        public:
            explicit Session(Shared& shared) : s(shared) { QueryPerformanceFrequency(&frequency); }
            int Run()
            {
                if (!DebugActiveProcess(s.pid)) return Fail("attach") ? 0 : 1;
                attached = true;
                if (!DebugSetProcessKillOnExit(FALSE))
                {
                    Fail("disable_kill_on_exit");
                    DebugActiveProcessStop(s.pid);
                    attached = false;
                    return 1;
                }
                deadline = GetTickCount64() + 8000;
                while (!s.failed)
                {
                    if (!WaitForDebugEvent(&event, 100))
                    {
                        if (GetLastError() != ERROR_SEM_TIMEOUT) { Fail("wait_debug_event"); break; }
                        if (GetTickCount64() > deadline) { SetLastError(ERROR_TIMEOUT); Fail("deadline"); break; }
                        continue;
                    }
                    pending = true;
                    const bool success = HandleEvent();
                    if (!success) StopProbe();
                    if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation))
                    {
                        Fail("continue_debug_event");
                        break;
                    }
                    pending = false;
                    if (!success || (stopping && (!s.requestedCalls || s.callsCompleted == s.requestedCalls))) break;
                    if (GetTickCount64() > deadline)
                    {
                        SetLastError(ERROR_TIMEOUT);
                        Fail("busy_deadline");
                    }
                }
                if (s.protectionOwned || steppingTid)
                {
                    // On timeout, obtain a fresh process-wide native stop before cleanup.
                    if (!pending && DebugBreakProcess(s.target)
                        && WaitForDebugEvent(&event, 2000)) pending = true;
                    StopProbe();
                }
                if (pending)
                {
                    ContinueDebugEvent(event.dwProcessId, event.dwThreadId, continuation);
                    pending = false;
                }
                if (attached)
                {
                    if (!DebugActiveProcessStop(s.pid)) Fail("detach");
                    else s.detached = 1;
                    attached = false;
                }
                for (auto& [tid, thread] : threads)
                {
                    (void)tid;
                    CloseHandle(thread.handle);
                }
                InterlockedExchange(&s.done, 1);
                return s.failed ? 1 : 0;
            }
        };
    }

    int RunDebugSession(Shared& state)
    {
        Session session(state);
        return session.Run();
    }
}
