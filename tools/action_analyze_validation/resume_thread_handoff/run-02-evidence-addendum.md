# run-02 Evidence Addendum

- Scope: explain the two phase assertion failures in the preserved run-02 attempt without changing its original log, receipt, raw package, or CLI stdout.
- Original verdict remains `VERDICT=FAIL FAILURES=2 BLOCKED=0`.
- The two failures are `kind6-phase-34268` and `kind6-phase-14884`. Both observed `handoffPhase=before-execution-dispatch`; the prior runner expected `before-thread-resume`.
- `before-execution-dispatch` is the stable product value for this handoff. Both `HookedResumeThread` and `HookedNtResumeThread` call `PrepareResumedPrivateExecution` before invoking their original API, so this label represents the pre-call protection/dispatch preparation point. The product phase field was not changed.
- The preserved run-02 evidence independently records exactly two kind-6 admissions for the expected source and target identities, distinct operation IDs `1` and `2`, exact pre-created instruction-pointer addresses, matching `entryObservation` thread identities and archived segment SHA-256 values, `completed=true`, `error=0`, and `nativeOwnerError=0`.
- The same run records both private stubs executing exactly once (`counter1=1`, `counter2=1`), both original page protections restored, and clean owner/Agent cleanup. Therefore the two phase mismatches are runner expectation mismatches, not evidence that the handoff failed.
- `run-01` remains the separate preflight/compiler-failure attempt and is reconciled in `.codex-build-logs/action-analyze-resume-thread-handoff/run-01-reconciliation.md`; it does not provide runtime evidence.
- The successful independent CLI `Release|x64` build artifact is `Ksword5.1/x64/Release/KswordCLI.exe`, SHA-256 `68FECACEA342F1EA985E5EF387E072058AB751F3AE77F4751862BA75A85F07B7`. That build receipt is separate from the run-02 scenario evidence.
