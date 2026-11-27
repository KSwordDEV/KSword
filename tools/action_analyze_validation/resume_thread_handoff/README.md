# ResumeThread Handoff Fixture

This fixture covers only transfer-handoff kind `6` (`ThreadResume`). It proves
that the product can observe the exact instruction pointer of a real suspended
thread immediately before a Win32 `ResumeThread` or direct
`ntdll!NtResumeThread` call, and that both threads subsequently execute their
pre-created private stubs once.

## Roles and protocol

- `F` allocates two private `PAGE_EXECUTE_READWRITE` pages, writes one counter
  stub per page, creates two genuinely suspended threads, and sets each x64
  `CONTEXT.Rip` to the exact stub address before publishing readiness.
- `A` opens both thread objects with query, context, suspend/resume, and
  synchronization rights. After the runner observes formal Agent readiness,
  it calls `ResumeThread` once for the first thread and direct
  `NtResumeThread` once for the second. It records the original previous
  suspend count and native status without issuing another suspension.
- The runner validates the final `transferHandoff` receipt, including exactly
  two kind-6 admissions, phase `before-execution-dispatch`, exact source/target and
  thread identities, distinct operation IDs, non-null `entryObservation`, the
  matching archived segment SHA-256, and clean owner retirement. It also
  checks both execution counters and original page protections while `F`
  remains alive.

No kind-4 or kind-5 range observation can satisfy this fixture. A successful
resume return without the exact `entryObservation` is not execution evidence.

## Fixed paths and execution boundary

Default invocation is source-only and does not compile, run the fixture, start
the formal CLI, or modify evidence:

```powershell
py -3.12 -B tools/action_analyze_validation/resume_thread_handoff/run_resume_thread_handoff.py
```

The explicit `--execute` path builds only the owned target with HostX64 MSVC
at `tools/action_analyze_validation/resume_thread_handoff/obj/Release` and
places the executable in the unified `Ksword5.1/x64/Release` directory. It
reuses the already-built formal `KswordCLI.exe` and `APIMonitor_x64.dll`; it
never rebuilds or copies product runtime files:

```powershell
py -3.12 -B tools/action_analyze_validation/resume_thread_handoff/run_resume_thread_handoff.py --execute
```

The run uses the fixed project path
`Ksword5.1/x64/Release/action-analyze-resume-thread-handoff/run-01/project`
and writes new evidence only under
`.codex-build-logs/action-analyze-resume-thread-handoff/run-01`. Existing
paths are refused rather than overwritten. Missing formal artifacts, missing
Agent readiness, unsupported phase/observation fields, identity mismatches,
or incomplete cleanup produce `BLOCKED` or `FAIL`; the runner never substitutes
another handoff kind.

Compilation and execution remain opt-in. This fixture does not perform GUI
automation and does not claim product or formal kind-6 evidence until the
explicit run completes with `PASS`.
