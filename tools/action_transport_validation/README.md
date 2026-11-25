# Native action transport dependency validation

Run from the repository with PowerShell 7:

```powershell
pwsh -NoProfile -File tools/action_transport_validation/Invoke-Validation.ps1
```

The script lowers its build host to `BelowNormal`, uses amd64 MSBuild and HostX64 with `/W4 /WX`, and prints absolute compiler, intermediate and output paths before compilation. It builds this project only, without Qt, drivers or product builds. Override `-MSBuild` with another installed **amd64** entry point if needed.

The project explicitly disables vcpkg app-local dependency deployment and uses existing installed runtime dependencies. Its implementation and fixed wire declarations are in the registered `.cpp`/`.h` pair; no `.inc` implementation is used.

- Fixed IntDir: `tools/action_transport_validation/x64/Release/`.
- OutDir from `../../Ksword.ReleaseOutput.props`: `Ksword5.1/x64/Release/`.
- Artifacts: `ActionTransportValidation.exe` and PDB; no runtime copy or test configuration.
- Evidence: `.codex-build-logs/behavior-planning/action-analyze-transport-build.log`, `action-analyze-transport-run.log`, and `action-analyze-transport-metadata.json` (hashes, OS, exits, declared thread identities, cleanup and stage times).

The executable launches its own current image using `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Each child gets only the explicitly allowed pipe endpoints, events, an anonymous shared mapping and a synchronize-only parent liveness handle. The parent verifies its `CreateProcess` PID, creation timestamp, image path, primary TID and ownership of every declared worker handle. This is a benign fixture protocol, separate from production design.

Each parent `Session` owns a separate, noninheritable Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The exact self-created child is assigned while still `CREATE_SUSPENDED`, before its first resume; membership, the kill-on-close limit and noninheritance are read back and asserted. The Job handle is absent from the inheritance allowlist. Job creation/configuration/assignment failure fails the fixture, and an assignment failure terminates and waits for only the exact still-suspended child. The fixture does not change an enclosing host Job or request breakaway.

1. A child uses the same synchronous worker for a 1 MiB telemetry write and subsequent command consumption. The parent does not drain the 4 KiB pipe initially: write-attempt event, pipe capacity, actual buffered bytes and unset writer-done event establish backpressure. A queued command has no applied state/ACK in the bounded observation. Draining and validating all telemetry frames then permits that **same** command's correlated applied ACK, demonstrating the dependency rather than inferring universal deadlock from a timeout.
2. A new child uses distinct telemetry and command reader threads/pipes. Applied ACK arrives while telemetry is still blocked.
3. A new child again uses separate threads/pipes. The external parent suspends all **three declared application threads**: primary business counter, telemetry writer, control reader. Each hold requires successful `GetThreadContext(CONTEXT_CONTROL)` before the parent publishes the freeze assertion. A command queues in the OS pipe, with no applied state or ACK. The parent returns only the control reader's own suspend count; the correlated applied ACK arrives with business context/ticks unchanged and both business and telemetry holds retained.

Control and telemetry use fixed 64-byte frames with magic/version/length, session/process identity, command ID, thread IDs and sequence/value. Control frames deliberately cross 5-byte writes and at-most-7-byte reads; framing accumulates partial reads. Only small bounded command/ACK frames are synchronously written to otherwise empty 4 KiB pipes. Reads poll `PeekNamedPipe` and never request more available data. Each stage has a 3.5-second observation budget and at most one second of parent cleanup; successful stages assert total elapsed time below five seconds. The runner has an independent 16-second emergency guard whose use is a failure.

Cleanup first returns only parent-owned suspend counts, signals stop, cancels the exact writer's synchronous I/O and closes the telemetry peer, then waits for the exact self-created process. Forced termination is reported as failure. Child code independently watches parent liveness and has an emergency deadline. All handles/mapping views are scoped; there are no persistent named IPC objects or test configurations to remove. Build outputs and evidence are retained in their fixed locations.

The child's liveness/deadline checks cannot run while all its declared threads are suspended. Once Job assignment has succeeded, killing the fixture parent closes its exclusive Job handle, so Job cleanup can terminate the enrolled child without requiring a child thread to execute. Normal success still requires releasing owned holds and observing exit zero **before** Job destruction. The normal three-stage metadata retains `parentKillFaultInjectionTested=false` because that invocation does not kill a parent. The separate fault-injection invocation below now records the tested failure path; it proves fixture termination, never production target recovery.

Limits: the fixture does not enumerate/freeze every OS/runtime-created thread, admit newly created threads during freeze, inject third-party targets, use drivers, alter security settings, open UI, or implement a production stop protocol. The result tests specific scheduling/transport dependencies on the recorded Windows build; it gives no throughput, latency distribution, production liveness or universal deadlock guarantee. No real product integration or GUI validation is implied.

The reported pipe capacity is the Windows pipe quota, not an asserted hard cap on `PeekNamedPipe` bytes: Windows may expose the full pending large write (observed: 1 MiB available against a reported 4 KiB quota). The evidence is that synchronous write remains incomplete until the peer reads or cancellation completes, rather than a claim that buffering never grows past 4 KiB.

Updated normal regression on 2026-11-24 after adding the fault-target mode: Windows 10 `10.0.19045` x64, build/run exits both zero, **37 passing assertions**, zero failures, and stage durations **735 / 484 / 734 ms**. All three children released parent-owned holds and exited zero without forced termination or guard activation. Current executable SHA-256 (supersedes the earlier `83358064...` artifact):

```text
D95DFD61006AF324ED3C377E2F020475F94D50E61F43B54AB1AA831780E33FE0
```

## Parent-death fault injection

```powershell
pwsh -NoProfile -File tools/action_transport_validation/Invoke-ParentDeathValidation.ps1
```

This builds and runs the normal regression, then launches the exact current image with `--parent-kill-target`. Its three declared child application threads are held and context-confirmed. The supervisor pins the child process handle, checks image and creation time, observes it alive for **5009 ms** (beyond the child's 4500 ms user-mode deadline), then kills only its exact newly created fixture parent. The enrolled child exited **4 ms** after that kill in this run, before any emergency cleanup. These are single observations, not latency bounds. All **7 supervisor assertions passed**; both exact processes exited and `emergencyCleanup=false`.

`-UseVerifiedBuild` skips the build/normal rerun only when the existing passing normal metadata still matches every recorded source and executable hash. It was used to correct the supervisor's initial mistaken exit-code assumption without repeating the already passing normal stages. Job termination produced child exit code **0**; zero by itself is not evidence of normal resume/cleanup. Readiness, the live negative-control interval, exact-parent termination, child exit and absence of parent cleanup together form the fault evidence.

Fault evidence is separate: `action-analyze-parent-death-run.log` and `action-analyze-parent-death-metadata.json` under `.codex-build-logs/behavior-planning/`. The initial failed supervisor result is retained with the `parent-death-initial-` prefix. An initial `/WX` build also found an unreachable return after the always-failing timeout path; that return was removed before the successful build. The expected kill is restricted to this fixture and must never become a production sample-termination or resume policy.

## Process TCP capability and permission test

```powershell
py -3 -B tools/action_transport_validation/validate_process_tcp.py
```

The Python fixture uses existing Python and Win32 IP Helper APIs, one benign self-created client, loopback-only sockets and an independent self-owned control connection. It selects and rechecks one established IPv4 TCP row by pinned child creation identity, PID and endpoint tuple, and only passes that tuple to `SetTcpEntry`. It changes no firewall rule, adapter, SSH session or driver state. The API itself accepts a tuple rather than a PID; owner-query/mutation races still need a product solution.

Current non-elevated Windows 10 run: `SetTcpEntry` returned **317**, the documented elevation failure. **12 assertions passed** for identity/selection, permission rejection, the target connection remaining usable, the unaffected bidirectional control connection and clean child exit. Overall result is **BLOCKED_PERMISSION**, not successful deletion; the command deliberately returns nonzero. `positiveDeleteTested=false`, `permissionNegativeControlPassed=true`, `emergencyCleanup=false`. No UAC elevation or security-setting change was attempted.

The elevated success path is prepared to check actual disconnect, an unaffected control channel and successful target reconnection (one-shot deletion is not continuous isolation), but remains unexecuted. IPv6, UDP and actual SSH behavior are not validated. Evidence uses `action-analyze-process-tcp-run.log` / `action-analyze-process-tcp-metadata.json`; the initial failure is retained with the `process-tcp-initial-` prefix. See [Microsoft SetTcpEntry semantics](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-settcpentry).
