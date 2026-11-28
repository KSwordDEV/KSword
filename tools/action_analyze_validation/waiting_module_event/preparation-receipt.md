# Waiting Module Event Validation Preparation

Status: prepared only. No build, target launch, CLI invocation, or GUI run has occurred.

## Frozen Scope

- One existing explicit-image execution-group member and its original native owner.
- Before `LoadLibraryW`, observe `control.breakpoint.waitingForModule=true` and no published address.
- Permit exactly one fixture DLL load, then require the same owner to report Armed with a nonzero module base.
- Execute the DLL export once, observe its actual held breakpoint, send one explicit Continue, and require the self-owned counter to equal 1.
- Cleanly shut down that owner and the CLI; only then permit the target to unload the DLL and naturally exit 0.
- No `pauseOnArm` assumption, cancellation replay, ordinary Pause replay, GUI, or NX page-protection claim.

The chosen image-export breakpoint does not change page protection. Restoration is evidenced by clean retirement of the same original owner before target DLL unload and natural exit. The product's existing wait admission is limited to explicit ordinary image execution.

## Prepared Inputs

- `waiting_module_child.c`: self-owned child, named-event gate before one `LoadLibraryW`, one export call, result capture, and a post-detach unload gate.
- `waiting_module_dll.c`: exported `WaitingModuleEntry`, whose real instruction entry is the stop site and whose counter increments once.
- `WaitingModuleChild.vcxproj` / `.filters` and `WaitingModuleDll.vcxproj` / `.filters`: fixed per-project Release IntDir and unified Release OutDir, with HostX64 checks.
- `Invoke-WaitingModuleEventValidation.ps1`: one-scenario runner with mandatory notified CLI SHA256, no build path, fixed runtime directory, ordered evidence checks, and machine-readable run receipt.
- `README.md`: same-batch fixture build handoff and single run command.

## Artifact Handoff Gate

Wait for the build owner to provide the exact unified Release CLI SHA256 and the SHA256 identities of both fixture outputs, confirming the child and DLL were produced in that same authorized BelowNormal/HostX64 batch. Do not inspect or rebuild against a newer HEAD. The runner refuses a CLI hash mismatch and does not build.

## Current Evidence

- Repository source review confirms the execution-group append path calls `AttachImageExecution(..., waitForModule=true)` and the original owner receives its Continue and clean Close.
- Protocol parsing does not expose a per-site `waitForModule` field; the explicit execution-group attachment is the production path under test.
- Source diff check: pass.
- Fixture build: not run, awaiting unified artifact batch.
- Runtime scenario: not run, awaiting exact artifact notification.
- GUI: prohibited and not run.

The complete receipt will be appended after the single authorized run. Any first failure remains recorded; this scenario must not be retried.
