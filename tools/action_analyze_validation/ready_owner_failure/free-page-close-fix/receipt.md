# Ready-owner released-page Continue: close-fix receipt

Date: 2026-11-27. Scope: the existing `ReadyOwnerFailureRunner` / `ReadyOwnerFailureTrigger` fixed Release fixture, one incremental fixture build batch and one `--continue` run. No CLI, Agent, GUI, Step, or older chain was started.

## Build

- Confirmed before starting that no `ActionAnalyzeReadyOwnerFailureRunner.exe`, `ActionAnalyzeReadyOwnerFailureTrigger.exe`, or matching `MSBuild.exe` was active.
- One serial `Build` invocation per existing runner/trigger project, `Release|x64`, `/m:1`, `/p:PreferredToolArchitecture=x64`, `/p:PROCESSOR_ARCHITECTURE=AMD64`, `/p:PROCESSOR_ARCHITEW6432=AMD64`; MSBuild was launched with `BelowNormal` priority.
- Runner `IntDir`: `tools/action_analyze_validation/ready_owner_failure/x64/Release/`.
- Both projects resolve `OutDir` through `Ksword.ReleaseOutput.props` to `Ksword5.1/x64/Release/`.
- Host compiler guard requires `$(VCToolsInstallDir)bin\HostX64\x64\cl.exe`; the verified compiler is MSVC 14.44.35207 HostX64. Build state records `Release|x64`, SDK 10.0.28000.0. The runner CL tlog names both `ReadyOwnerFailureRunner.cpp` and the production `NativePrivateExecutionPage.cpp`; CL write/link tlogs include their objects.
- Both project invocations returned exit code `0`, recorded in `build-summary.json`. Raw MSBuild console text was not captured by the initial command wrapper; no reconstructed console log is presented as original output.

## Single runtime result

The one run used the fixed Release runner, `--continue`, and a new receipt/output leaf in this directory. Runner PID `51392` exited `0` at BelowNormal priority; target PID `40648` / creation time `134402772378707260` was the trigger-owned process. No matching runner, trigger, or target process remained after the run.

- Trigger allocation identity was passed through its own protocol and independently accepted by the production owner. This is **not Agent Ready evidence**: `agentLoaded=false`, `nativeRecoveryBranch=true`.
- Production owner reached the actual NX Held stop on the exact private page with matching stop/event/owner identity. Trigger `VirtualFreeEx` succeeded (`freeError=0`); post-release `VirtualQueryEx` verified `MEM_FREE` (`postState=65536`).
- The first real recovery failure is preserved verbatim: `stage=private-execution-page-rearm-external-protection error=487`, on `continue/1`. The trigger received the owner-sourced `firstRecoveryFailure` record.
- Subsequent owner close returned `status=7 stage=owner-closed error=0 clean=true attached=false`, with `firstRecoveryFailurePresent=true` and the original stage/error `private-execution-page-rearm-external-protection` / `487` still retained. The runner's `owner-cleanup-evidence` check passed. This demonstrates cleanup after the error; it does not erase or convert the earlier Continue recovery failure.
- `trigger-cleanup` passed because the runner received a line beginning `DONE`. This built runner did **not** copy the `DONE` fields into the receipt: target `childExitObserved`, target exit code, and execution count are absent. Do not infer a target AV, natural exit, stub completion, or successful business continuation from runner exit `0`, owner `clean=true`, or `trigger-cleanup`. Target business continuation is **NOT PROVEN**.
- New source-only fixture diagnostics now parse and record the full `DONE` fields, target exit code, trigger process exit code, and the final owner Query stage/error. These edits were made after the one build/run and are **not built or executed** in this receipt; no second run was made.

## Evidence and artifact identity

- New machine receipt: `runtime-receipt-continue.txt`.
- Captured runner stdout/stderr: `continue.stdout.txt`, `continue.stderr.txt` (stderr empty); invocation summary: `runtime-summary.json`.
- Earlier canonical FAIL remains untouched at `../runtime-receipt-continue-canonical-owner.txt`; its original `owner-cleanup-evidence` FAIL is not rewritten or reclassified.
- Original canonical FAIL SHA256: `9A513324821E30E1F461D7F435BDCA368E60B31FBB286D6C03C46CEB6B464191`. New runtime receipt SHA256: `ABA95420291FED759267B2DD83040C55D4C09A0AD35F8302784D623CAE4DB76F`; captured stdout SHA256: `CBC8450F2F42B3E4CD1521A63551D825705008CC1AD8F8603E550320C04ACCE7`; empty stderr SHA256: `E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855`.
- Fixed Release runner: `Ksword5.1/x64/Release/ActionAnalyzeReadyOwnerFailureRunner.exe`, SHA256 `A2C631AA048198A1203D8ECA2B13C6235787617BC9A557A3CCCD29071C6F4FFC`.
- Fixed Release trigger: `Ksword5.1/x64/Release/ActionAnalyzeReadyOwnerFailureTrigger.exe`, SHA256 `89D45FFBC766F89B3B64AC3684E85B60E2441596FCEAEEBAA54FA5251E249017`.
- Runner PDB SHA256 `55FE9E890624F77E0B0AB3871B25F80634F26FAC31EC270FE1BD11E9B05338CC`; trigger PDB SHA256 `A51D398051C32066E3D707BA741D67C1549FBFE6CEA0CB1E832C5CE2251CDED5`.
- Compiled production translation unit object `tools/action_analyze_validation/ready_owner_failure/x64/Release/NativePrivateExecutionPage.obj`, SHA256 `C5152A11C873700E1C2E085AD0F461AFF5D9BD78FFCC83FCEE2BA129430442B6`; production source `KswordCLI/ActionAnalyze/Control/NativePrivateExecutionPage.cpp`, SHA256 `56EE263E00B1843650D322BEEF7DD4254FE1BFCEA55A2465087C2E43A6940D1D` (commit `f878ce02e`).
- Runner source SHA256 after the unbuilt diagnostic-only edits: `155C0395D037CDFAB2EA24A948B6FC8B4374882A31CC6BB384726D4E31BBA374`. The built executable hash above, not this later source hash, identifies the one tested runner.
- All compiler/linker outputs remain in the fixed IntDir and unified Release OutDir. No temporary test configuration was created. No cleanup was performed on shared Release artifacts.

## Conclusion

The native owner cleanup after a confirmed released page is now observed clean while retaining the original Continue recovery failure. This is limited to the native recovery/close path. The failed Continue remains a failure, target exit/business continuation is unproven because its exit code was not captured, the old FAIL remains intact, and a complete Ready Agent chain is not established.
