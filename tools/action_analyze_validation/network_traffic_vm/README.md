# Win10 existing-WFP loopback validation

2026-11-27: **PASS for the narrow IPv4 inbound loopback archive and formal readback scenario.**
This does not close the whole ActionAnalyze item 7 or the 11-item acceptance list.
The earlier host raw-socket zero-packet FAIL remains unchanged.

## Actual product and guest

- Host formal CLI: `Ksword5.1/x64/Release/KswordCLI.exe`, SHA256
  `816BDA24663C8E19FB497096B613C807E0B53D51501DCB01FE8E41A8F4788A65`.
- Host formal driver copied to the guest: `Ksword5.1/x64/Release/KswordARK.sys`,
  3,659,264 bytes, SHA256
  `56C4FA626360D14F4DB0F4B4AB8DA63A48DE060102D1EF37AF88C7A09BC482DD`.
  Actual host signature status was `NotSigned`; the product was not rebuilt.
- Source coverage: `.codex-build-logs/native-balanced-batch/driver-release-build.log`
  line 159 compiles `network_traffic_loopback.c`, line 277 links the formal sys,
  line 278 reports `Driver is 'Universal'.` Exact source hash and UTC file times
  are saved in the run's `host-input.json`.
- VM: `E:/VMs/Windows10-20H2/Windows 10 x64.vmx`, Win10 build 19042,
  `DESKTOP-D2161R7`. Started using `vmrun ... start ... nogui`.
- Saved snapshot: `AA-WFP-before-20261127`, created before any guest deployment.
  The initial powered-off snapshot attempt was refused because the state had not
  changed; starting without a GUI then saving the snapshot succeeded.
- Guest already had `testsigning Yes` and Secure Boot false. No host or guest
  boot/signature policy changes were needed or made.
- Only the guest driver copy was signed using a new guest-local test certificate.
  Its signed SHA256 was
  `A646AFD75F8B7D1DCC685091634E99027D58E07285ACBE0FDE97583A66F282C5`;
  guest Authenticode validation succeeded. This is a test signature, not release
  signing validation.
- Temporary SCM service `KSwordAAWfp` loaded successfully (`sc start` exit 0),
  with `State=Running`, `Started=true`, exact image path
  `\??\C:\KSwordValidation\ActionAnalyzeWfp\KswordARK.sys`.
  Real `r0 traffic-start` returned enabled/generation 1, NTSTATUS 0.
  No separate loaded-module enumeration was performed.
- Deployment contained the CLI, sys, three matching MSVC runtime DLLs, signtool,
  and PowerShell scripts. No Qt runtime, GUI or Agent was deployed or started.

## One actual capture

The PowerShell/.NET fixture implements the existing `network_traffic_local`
scenario's one listener, one client, one unique marker, delayed explicit release,
and bounded cleanup. Both socket processes remain alive during capture. The
receiving listener is selected because this WFP path observes inbound transport.
Connections use only `127.0.0.1`.

- Project: `3006c7e4-47fe-4749-aca2-78b275581e31`.
- Sample: `206326a5-a1cf-4bb8-95c4-eb775d8675be`.
- Listener PID/create FILETIME: `1648` / `134402717995665643`.
- Client PID/create FILETIME: `2704` / `134402717999286252`.
- Endpoints: `127.0.0.1:50737` to `127.0.0.1:50735`.
- Marker: `KSWORD_AA_WFP_VM_20261127_22b97e3cbbc549feabaf4b9ffa6ebf76` plus newline.
- Explicit source: `existing-wfp`; actual source ID: `ksword-r0-wfp-existing`.
- Actual target window: `134402718003110000` to `134402718053200000`
  (5.009 seconds), `duration-elapsed`.
- Formal capture: exit 0, `sourceReady=true`, 3 packets, 191 retained IP bytes,
  `cleanupConfirmed=true`, queue dropped/cursor gap/unsupported all zero.
- Listener independently received the same 59-byte marker payload.

The final checkpoint (ordinal 2) contains termination status and zero packet
records. Reading ordinal 1 and then each exact record using the formal
`analyze network-read` command returned the real original packet bytes:

| Ordinal | Record sequence | Record offset | Producer sequence | IP bytes | TCP payload |
| --- | --- | --- | --- | --- | --- |
| 1 | 1 | 176 | 4009 | 52 | 0 |
| 1 | 2 | 1140 | 4011 | 40 | 0 |
| 1 | 3 | 2092 | 4012 | 99 | 59, exact marker plus newline |

Ordinal 1 checkpoint SHA256:
`6819dd283bf17233751cee1150980a72e8e2d956c05010e39d4d5bd4835eb68a`.
Ordinal 2 checkpoint SHA256:
`1f11331aec8bd380f7bbe799c753a82a40ddb652bd1b49c06d185fe410adce77`.
Marker payload SHA256:
`e929ae206c3dd58d1569efceaadeeacac64db3fcec90297b19768b650b4b4264`.

The offline verifier checks the returned IPv4 version/IHL/protocol/length,
loopback source/destination, real TCP ports/header length, exact payload,
PID/create window and per-record timestamps. All three records are
`ip-packet`, `complete`, not truncated. All carry `endpoint-table-hint` and
`creationFileTime=null`; the request's strong target identity does not upgrade
packet attribution. Capture coverage remains `unknown` and the readback reports
`sourceLossUnquantified=true`; zero counted loss does not prove complete traffic.

## Cleanup and limitations

- `r0 traffic-stop`, `sc stop`, `sc delete`: all exit 0.
- Temporary service absent, no own CLI/socket PowerShell process remains.
- Temporary certificate removed from guest My/Root/TrustedPublisher stores.
- The fixture hit its 60-second bounded cleanup before the subsequent explicit
  cleanup command: it terminated its still-live client, recording client exit
  `-1` and `cleanupConfirmed=true`. This is not natural successful client exit.
  The full capture and marker exchange occurred before that cleanup.
- Evidence was exported, the VM stopped and reverted to the saved snapshot;
  both operations exited 0. `vmrun list` then reported zero running VMs.
  Rollback removes this run's deployed files, service/certificate changes and
  project from the guest. The rollback snapshot is retained intentionally.
- The first Setup wrapper recorded `traffic-start exit=null` because Windows
  PowerShell's `Start-Process` wrapper lost the exited process's exit code.
  Original `Setup.failure.json` is retained. Its actual stdout proves traffic
  capture enabled successfully. The wrapper now uses a retained .NET Process;
  Setup was not repeated, and the real capture was executed once.
- No full IPv6, bidirectional, loss, GUI, performance or strong event-time process
  attribution acceptance is claimed.

## Commands and evidence

Host credential handling uses `Import-Clixml` and a WinRM HTTPS session to the
documented `CodexRemote` endpoint. No password is placed on a command line.
All guest runtime paths are fixed under `C:/KSwordValidation/ActionAnalyzeWfp/`.
The host evidence directory is `.codex-build-logs/action-analyze-wfp-vm/`, including
the original small project archive, exact CLI stdout/stderr/exit receipts,
`baseline.json`, `driver-loaded.json`, `signed-driver.json`, `cleanup.json`,
`vm-rollback.json`, `host-input.json` and `verification.json`.
Only text and small evidence archives were exported; no executable/runtime copy
was retained in the log directory. Repeated collection's identical nested copy
was hash-compared and removed, leaving one original project archive.

```powershell
tools/action_analyze_validation/network_traffic_vm/Invoke-WfpVm.ps1 -Phase Deploy
tools/action_analyze_validation/network_traffic_vm/Invoke-WfpVm.ps1 -Phase Setup
tools/action_analyze_validation/network_traffic_vm/Invoke-WfpVm.ps1 -Phase Capture
tools/action_analyze_validation/network_traffic_vm/Invoke-WfpVm.ps1 -Phase Cleanup
tools/action_analyze_validation/network_traffic_vm/Invoke-WfpVm.ps1 -Phase ReadArchives
tools/action_analyze_validation/network_traffic_vm/Invoke-WfpVm.ps1 -Phase Collect
python -B tools/action_analyze_validation/network_traffic_vm/verify_archive.py
```

Snapshot creation and final rollback are deliberately performed by the operator
using the authorized VMX and snapshot name, before Deploy and after Collect.
Do not repeat the scenario against an already-used guest validation directory.
