# Win32 Debugger Query Validation

## Target

`target.py` is a self-owned x64 Python process. It loads the formal Release
`APIMonitor_x64.dll`, enables cooperative capture, and loops three real
`KernelBase` calls until the controller closes stdin:

- `IsDebuggerPresent`, expected FALSE with a successful query.
- `CheckRemoteDebuggerPresent(GetCurrentProcess())`, expected successful FALSE.
- `CheckRemoteDebuggerPresent(NULL)`, expected failure; the output starts TRUE
  and must remain untouched.

The first call result set is printed after capture ends. Calls are repeated so
the finite capture window includes actual Strong-hook packets. No packet is
synthesized and no third-party component is used.

## Acceptance After Source Ready

Wait for the coordinator's explicit source-ready notice before building or
running anything. Then make one BelowNormal, HostX64 Release x64 increment for
the formal Agent and CLI using `tools/action_analyze_validation/tracked_range_rearm_held/build_apimonitor_x64.ps1`
and `tools/Invoke-KSwordCliBuildCheck.ps1`. Run one short cooperative capture
with `target.py`, then use formal CLI raw replay and rule replay against that
capture. Keep original packet bytes, sample ID, raw coordinates, both binary
hashes, command exit codes, first assertion failure and cleanup outcome in the
batch receipt.

Acceptance requires all three to be actual Strong-hook packets in the same
sample. `IsDebuggerPresent` must classify as `process-query`, preserve
`result.succeeded=true` with `process.debuggerPresent=0`, and match the formal
debugger-absent rule. Successful `CheckRemoteDebuggerPresent` must preserve
success and output zero. The NULL-handle failure must report failure and must
not project `process.debuggerPresent` or match either presence/absence rule.

This preparation is not build or runtime evidence. Do not claim a pass from the
target's local return values alone.
