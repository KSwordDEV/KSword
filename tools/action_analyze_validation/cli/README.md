# ActionAnalyze CLI product acceptance

Run from the repository root with Python 3.12 and the same `jsonschema` dependency used by the A0.2 vector checker. Both scripts use the existing `Ksword5.1/x64/Release/KswordCLI.exe` and print its SHA-256 and the native exit codes.

```powershell
py -3.12 -B schemas/action_analyze/vectors/validate-request.py
py -3.12 -B tools/action_analyze_validation/cli/smoke.py --profile shell
py -3.12 -B tools/action_analyze_validation/cli/smoke.py --profile project-v1
py -3.12 -B tools/action_analyze_validation/cli/project_v1.py
```

`smoke.py` defaults to `--profile auto`. An explicit profile asserts what the executable must advertise. Both profiles exercise the same controller methods, JSONL framing and shutdown, redirected REPL, help, option rejection, and the legacy R3 file metadata query against the checked-in request schema. The shell profile checks that project methods are unavailable. The project profile checks its eight additional advertised methods against the method catalog and accounts for the entry reserved for project close. A baseline `unsupported-method` vector applies only when the executable omits that exact method from capabilities. The V1 harness exercises the advertised project methods against its owned project. [A0.2 method contract](../../../schemas/action_analyze/method-contract-v1.md)

`project_v1.py` gates fixture creation on the advertised project profile and a valid JSONL greeting. It exercises two samples with distinct frozen settings in one process, generation-based pagination, stale and read-only writes, close and reopen, controller and REPL isolation, and bounded replay. The byte limit test checks that cached replies, project close, and shutdown remain available and that a rejected write leaves the reopened project unchanged.

The V1 fixture lives only in `Ksword5.1/x64/Release/action-analyze-cli-validation/`. The harness claims an empty fixed directory, refuses an existing directory, and checks directory identity, tracked paths, and reparse attributes before removing its own fixture. V1 exits `77` when the binary advertises only the shell, before creating any fixture.

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
