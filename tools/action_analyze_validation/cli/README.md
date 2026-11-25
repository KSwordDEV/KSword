# ActionAnalyze CLI product acceptance

Run from the repository root with Python 3.12 and the same `jsonschema` dependency used by the A0.2 vector checker. The product tests use the existing `Ksword5.1/x64/Release/KswordCLI.exe` and print its SHA-256 and the native exit codes.

```powershell
py -3.12 -B schemas/action_analyze/vectors/validate-request.py
py -3.12 -B schemas/action_analyze/check_base_v1.py
py -3.12 -B tools/action_analyze_validation/cli/smoke.py --profile shell
py -3.12 -B tools/action_analyze_validation/cli/smoke.py --profile project-v1
py -3.12 -B tools/action_analyze_validation/cli/smoke.py --profile archive-v1
py -3.12 -B tools/action_analyze_validation/cli/live_etw.py
py -3.12 -B tools/action_analyze_validation/cli/project_v1.py
py -3.12 -B tools/action_analyze_validation/cli/archive_v1.py
```

## Passive ETW session receipt

The HostX64 Release build passed with zero warnings and errors. The CLI executable in `Ksword5.1/x64/Release` has SHA-256 `68A8A1A9CFD670058E0DD3BC0AE1C2A5504C177A086E05DECF383F986FF8F079`. The owned file producer emitted six write and six verified read events. The JSONL test matched all 12 descriptors and eight-byte payloads and reopened the 8,881-byte Stored segment. Its 14 records include the plan and terminal coverage. Windows and the local queue reported zero lost records on that sample.

The test checked duplicate open, stop and close requests, rejected a changed request identity and a stale revision, and rejected a creation-time mismatch before adding a project sample. It exercised the duration limit, immediate EOF and the REPL lifecycle. Immediate EOF returned `ProcessTrace=87`, a verified raw segment, exit code `6` and `clean=true`. The REPL stop arrived before `ProcessTrace` and reported partial coverage. All owned processes exited and the fixed test project was removed.

The offline CLI passed its 16 request and 22 wire vectors and replay-ledger checks. The Stored raw archive passed 45 native checks, and the submitted schema passed 10 request vectors and four Release receipts. Local evidence is in `.codex-build-logs/action-analyze-cli-passive-live-final-build.log`, `.codex-build-logs/action-analyze-cli-passive-live-final-test.log` and `.codex-build-logs/action-analyze-cli-passive-live-offline-regression.log`.

The owned target also exited normally during a subsequent active capture. The controller reported `target-exited`, confirmed native cleanup, verified a 1,663-byte raw segment and exited `0` after close and shutdown. The test removed the project. See `.codex-build-logs/action-analyze-cli-target-exit.log`.

The slow-output test keeps stdin open and stops reading stdout after the first three replies. The CLI exits with code `3`. The reopened raw segment contains `stopReason=output-lost` and `nativeSessionStopped=true`. See `.codex-build-logs/action-analyze-cli-output-loss.log`.

The Release CLI also verified `sample.query` with `includeCapture:true` and the equivalent `sample status SAMPLE_ID capture` in a reopened read-only project. Both returned 12 observations, 8,881 checked bytes, the matching provider and target creation time, and the saved stop reason. A missing segment during capture and a truncated segment produced separate outcomes. The test restored the original bytes and removed the project. See `.codex-build-logs/action-analyze-cli-sample-capture-test.log`.

For readback with the production QtCore and Light readers, build `KswordARKLight/Features/ActionAnalyze/tests/StoredEvidenceValidation.vcxproj` and run `tools/action_analyze_validation/qt/Test-OfflineSegmentReader.ps1 -VerifyCliEtw`. Both readers checked all 12 events and the exact saved bytes from a single CLI-generated segment. The Qt window test is `py -3.12 -B tools/action_analyze_validation/qt/archive_etw_preview.py`. It verifies the existing archive open action, ETW filter, selected record and field values in the Release workspace.

`smoke.py` defaults to `--profile auto`. An explicit profile checks the advertised flags, exact method names and count against the selected profile. The `shell`, `project-v1`, and `archive-v1` profiles have 3, 11, and 12 methods respectively. All profiles exercise the controller methods, JSONL framing and shutdown, redirected REPL, help, option rejection, and the legacy R3 file metadata query against the checked-in request schema. The two profiles with project support account for the entry reserved for project close. A baseline `unsupported-method` vector applies only when the executable omits that method from capabilities. [A0.2 method contract](../../../schemas/action_analyze/method-contract-v1.md)

`project_v1.py` accepts `project-v1` and `archive-v1`. It gates fixture creation on the advertised profile and a valid JSONL greeting. It exercises two samples with distinct frozen settings in one process, generation-based pagination, stale and read-only writes, close and reopen, controller and REPL isolation, and bounded replay. The byte limit test checks that cached replies, project close, and shutdown remain available and that a rejected write leaves the reopened project unchanged.

`archive_v1.py` accepts `archive-v1`. It registers a sample through the CLI for each of two owned projects with ASCII and Unicode paths. It copies the checked-in Stored vectors into the registered sample directories and updates only the segment headers to bind the generated identities and ordinals. It checks `archive.inspect` in JSONL and the REPL, verifies that interpretation and durability remain unknown, and checks the segment bytes after inspection. [Stored vectors](../../../schemas/action_analyze/vectors/stored-v1.json)

Run the project and archive suites sequentially because both use `Ksword5.1/x64/Release/action-analyze-cli-validation/`. Each suite claims an empty fixed directory, refuses an existing directory, and checks directory identity, tracked paths, and reparse attributes before removing its fixture. Each suite exits `77` before creating the fixture when its provider is unavailable.

## First shell build evidence

The HostX64 Release artifact for implementation `6b459325e` passed the offline shell smoke. SHA-256 was `3DC8F4078307DC683A14C4F7CDC0EA5C52C893A02800F9ACF6B2A920D11A495E`. The original A0.2 set passed all 62 static vectors. Native coverage included 18 request vectors, 22 wire vectors, and six positive output shapes.

JSONL shutdown, clean EOF, replay ledger saturation, the redirected REPL, help, and the legacy metadata query exited `0`. The overlong and unterminated input sessions exited `1` with `protocol-failed` summaries. Invalid launch options and the legacy unknown-option check exited `1`. The legacy query reported `win32Error:0`.

The V1 harness returned skip code `77` against that artifact and left the scratch path absent.

## Unified project V1 build and test receipt

The 2026-11-24 HostX64 Release build completed with exit `0`, zero warnings, and zero errors. The build log is `.codex-build-logs/action-analyze-cli-project-20261124-224716.log`. The tested `Ksword5.1/x64/Release/KswordCLI.exe` was 6,049,280 bytes with SHA-256 `54569FA5788D53160D1A6B2D37744A839E0B2A5D525E50BA834ECB9B0752710B`.

| Check | Result |
| --- | --- |
| `validate-request.py` | Exit `0`. All 62 baseline and 47 project contract vectors passed. |
| `smoke.py --profile project-v1` | Exit `0`. The executable passed 16 baseline request vectors and all 22 wire vectors. The three baseline vectors for unavailable project methods were scoped to the shell profile. Help, capabilities, REPL, the R3 metadata query and clean session closure exited `0`. Invalid launch options, the legacy unknown option, and fatal framing sessions exited `1` as expected. |
| Replay entry limit | The executable accepted 4,095 ordinary replies and returned `request-ledger-full` with response code `6` on the next new request. Cached replay and fresh shutdown succeeded. The session exited `0`. |
| `project_v1.py` | Exit `0`. The two samples retained distinct frozen revisions across generation-based paging and reopen. Stale and read-only writes were rejected. The JSONL and REPL isolation checks passed. |
| Replay byte limit | With the advertised 32 MiB budget, the executable accepted 499 large project query replies before returning `request-ledger-full` with response code `6`. Cached replay, reserved project close and fresh shutdown succeeded. A read-only reopen verified that the rejected write left the project state intact. |
| Cleanup | The owned scratch directory was removed and its absence was verified. |

The first V1 smoke run sent the shell-only `project-write-option-unavailable-in-shell` vector to the advertised project provider and received `project-data-not-found` with native code `2`. The profile filter now omits all three corresponding shell-only vectors on the V1 artifact.

## Archive V1 build and test receipt

The 2026-11-24 BelowNormal HostX64 Release build completed with exit `0`, zero warnings, and zero errors. The build log is `.codex-build-logs/action-analyze-cli-archive-20261124-225953.log`. The tested executable was 6,078,976 bytes with SHA-256 `D58516ACF125270D1EE882598E25796A417EF986EA5F858037C5978D8F323A54`.

| Check | Result |
| --- | --- |
| `smoke.py --profile archive-v1` | Exit `0`. The advertised catalog had exactly 12 methods. The executable passed 16 request and 22 wire vectors. It accepted 4,095 ordinary replies before returning `request-ledger-full` with code `6`. Cached replay and fresh shutdown passed. |
| `project_v1.py` | Exit `0` with the archive profile. Project revision, sample, paging, reopen, and isolation checks passed. The byte limit bound after 499 large replies. Cached replay, reserved close, fresh shutdown, and the read-only reopen check passed. |
| `archive_v1.py` | Exit `0` for ASCII and Unicode project paths. A valid header framed 96 bytes. A tail truncated at byte 339 retained the 218-byte prefix and reported `end-of-file` at 339. A valid-CRC header with the wrong project ID reported `corrupt` with reason `identity` and a zero-byte prefix. Missing stream and missing segment returned their respective request errors with Win32 code `2`. Unknown optional and required record counts matched the vector cases. `interpretedBytes` and `durableBytes` were `null` throughout. The explicit 96-byte scan matched between JSONL and REPL. |
| Static contracts | All 62 baseline, 47 project and 37 archive inspection vectors passed. A0 base validation also passed 66 value, identity and JSON cases and 35 Stored cases, plus CRC and UUID checks. |
| Cleanup | Both suites removed the scratch path and verified its absence. The artifact SHA-256 matched across the runs. |

## R3 memory observation

Run `py -3.12 -B tools/action_analyze_validation/cli/memory_watch.py` against the formal Release CLI. The harness starts an owned Python process, allocates one non-executable data page inside it, and compares the CLI observations with the child's write receipt. The child releases its page and exits. The harness writes the CLI replies and sample receipt to `.codex-build-logs/action-analyze-memory-watch-report.json`.

The HostX64 Release build for SHA-256 `52185FAECBCE347C9FF8CF98A3F818447ADB4C8AA593817F50B766B8E01497AC` reported zero warnings and errors. The command observed two changed ranges at byte offsets 3 and 11, for four bytes total across 24 reads. A wrong creation time was rejected before any reads. Making the page inaccessible stopped sampling and retained eight earlier observations with Win32 error 487. The sample exited with code 0. The same CLI passed the existing `archive-v1` transport smoke.
