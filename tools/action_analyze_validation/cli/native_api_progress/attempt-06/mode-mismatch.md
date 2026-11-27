# Attempt 06 Mode Mismatch

Attempt 06 remains a historical `FAIL`. Its raw logs and `receipt.json` are unchanged.

The source was started with `--target` and the private
`KSWORD_APIMON_COOPERATIVE_SESSION_V1` directory. That source therefore loaded the
first-party Agent and enabled cooperative capture in the fixture. The requested
`control.api.capture` path, however, selected formal `ExplicitAttachment` and
published the PID-scoped configuration through `buildConfigPathForPid` (the
cooperative implementation in `MonitorAgent.cpp:317-343` was not the matching
source mode for this request). The controller verified the resident module and
published configuration, but the Agent never connected or reached verified
coverage. It then returned `capture-failed` with exit code `3` after about 45
seconds, with four startup frames and zero strict capture-progress frames.

This is a fixture/source-mode mismatch, not a repaired product result. The
attempt-07 source uses `--attachment-target`: it starts without the cooperative
environment, asserts that `GetModuleHandleW(APIMonitor_x64.dll)` is null, does
not load or enable the Agent itself, and retains only the existing self-
`WriteProcessMemory` loop for the later explicit attachment.
