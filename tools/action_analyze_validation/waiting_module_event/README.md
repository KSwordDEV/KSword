# Waiting Module Event Validation

This focused case covers the original owner's delayed-module path only. It does not use or assume `pauseOnArm`, and it does not repeat cancellation or ordinary Pause cases.

## Fixture

`waiting_module_child.c` waits before loading the DLL. After the controller confirms `waitingForModule`, the runner signals one load request. The child calls the exported `WaitingModuleEntry` exactly once. That function increments a self-owned counter; its instruction entry is the requested breakpoint. The target writes the returned count, signals completion, then stays alive with the DLL mapped until the controller has cleanly detached. Only then does it unload and naturally exit with code 0.

The image execution breakpoint does not change page protection. The restoration evidence is clean retirement of the same native owner before the target unloads/exits; do not report this as an NX/page-protection test.

## Fixed Artifacts

- Fixture projects: `WaitingModuleChild.vcxproj` and `WaitingModuleDll.vcxproj`.
- Fixture `IntDir`: each project's fixed `x64\Release\` directory under this folder.
- Fixture `OutDir`: repository `Ksword5.1\x64\Release\` via `Ksword.ReleaseOutput.props`.
- Outputs: `ActionAnalyzeWaitingModuleChild.exe` and `ActionAnalyzeWaitingModule.dll`.
- Runtime work/config: this folder's fixed `run\` directory; the runner refuses to overwrite it.
- Text evidence: `.codex-build-logs\waiting-module-event\`.

The two fixture projects must be built in the same authorized BelowNormal/HostX64 batch that produces the unified Release CLI/Agent artifacts. Do not invoke a separate build or rebuild after that batch. The runner has no build path and checks the notified CLI SHA256 before creating a target process.

The build owner should resolve the repository's verified 64-bit MSBuild and invoke these two additional projects in that same batch, in sequence, with the repository's standard x64 host arguments:

```powershell
$hostArgs = @('/p:PreferredToolArchitecture=x64', '/p:PROCESSOR_ARCHITECTURE=AMD64', '/p:PROCESSOR_ARCHITEW6432=AMD64')
& $msbuild 'tools\action_analyze_validation\waiting_module_event\WaitingModuleChild.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 @hostArgs /m:1 /v:minimal
if ($LASTEXITCODE -ne 0) { throw 'Waiting module child fixture build failed.' }
& $msbuild 'tools\action_analyze_validation\waiting_module_event\WaitingModuleDll.vcxproj' /t:Build /p:Configuration=Release /p:Platform=x64 @hostArgs /m:1 /v:minimal
if ($LASTEXITCODE -ne 0) { throw 'Waiting module DLL fixture build failed.' }
```

Do not run these lines independently from the authorized unified batch. The build handoff must record both fixture SHA256 values and the CLI SHA256; the latter is mandatory for the runner.

## One-Scenario Command

After the build owner provides the exact tested CLI SHA256 and confirms both fixture outputs belong to that batch, run once from the repository root:

```powershell
$runArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',
  'tools\action_analyze_validation\waiting_module_event\Invoke-WaitingModuleEventValidation.ps1',
  '-ExpectedCliSha256','<notified-64-hex-SHA256>')
Start-Process -FilePath (Get-Command pwsh).Source -ArgumentList $runArgs -Priority BelowNormal -Wait
```

Run the PowerShell host at BelowNormal. Do not run this command before receiving the artifact notification. It runs no GUI, does not compile, and uses only the owned target, owned DLL, and formal CLI.

## Pass Criteria

The receipt must show, in order: (1) one explicit member reports `waitingForModule=true` and no bound address before load; (2) the same owner changes to Armed with a nonzero module base after the one `LoadLibraryW`; (3) the exported entry produces a real held stop; (4) the same owner receives one explicit Continue; (5) the counter result is exactly 1; (6) controller shutdown is clean and formal CLI exits 0; (7) only after clean detach, the target unloads the DLL and naturally exits 0. Preserve failures as failures; do not retry the scenario.

`pauseOnArm` and NX page-protection restoration are outside this scope. The product's existing `waitForModule` admission remains limited to explicit ordinary image execution.
