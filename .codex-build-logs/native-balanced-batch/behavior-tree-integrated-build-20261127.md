# Three-end behavior-tree integration build receipt

Date: 2026-11-27

## Scope

- Source inputs present as ancestors of `HEAD` `5b214808a056dcf149e389bf3d47a1a0167314bd`:
  - `0e256f56a` network `published.loss`
  - `78d1d826a` CLI replay rule explanations
  - `a9098586e` Light behavior tree
  - `01a628a19` Qt behavior tree
  - `5b214808a` bilingual behavior-tree text
- Working tree was dirty before and after the builds. Existing user changes and untracked evidence were preserved.
- Build order was CLI, Qt, Light. No Agent, driver, GUI, target, VM, or new capture scenario was started.

## CLI

- Command: `tools/Invoke-KSwordNativeBuildCheck.ps1 -Product CLI`
- Configuration: `Release|x64`, HostX64, `BelowNormal`, `BuildProjectReferences=false`, fixed project/output directories.
- IntDir: `KswordCLI/x64/Release`
- OutDir: `Ksword5.1/x64/Release`
- Result: `SUCCESS`
- Exit code: `0`
- Artifact: `Ksword5.1/x64/Release/KswordCLI.exe`
- SHA-256: `48343B754BA5FAC998D6BE083633547F7944F93F9585311085BED5CDE0449353`
- The build compiled `ApiMonitorEvidenceCommand.cpp` and `CooperativeApiCapture.cpp`; no driver or Agent rebuild was performed.

## Qt

- Command: `tools/Invoke-KSwordBuildCheck.ps1 -Action Build -RepositoryRoot (Get-Location).Path -TimeoutMinutes 20`
- Configuration: `Release|x64`, HostX64, `BelowNormal`, fixed IntDir/OutDir, repository wrapper with built-in i18n audit.
- IntDir: `Ksword5.1/Ksword5.1/Ksword5.1/x64/Release`
- OutDir: `Ksword5.1/x64/Release`
- Result: `FAILURE`
- Exit code: `1`
- Failure class: `I18N_AUDIT_ERROR`
- First failure: missing source translation `behavior:%1:%2:%3:%4:%5` in both `zh-CN` and `en-US`.
- Raw log: `.codex-build-logs/ksword-build-check-20261127-134157.raw.log`
- No C++ compiler error occurred. Qt was not retried and no language-pack edit was made in this batch.
- The existing formal `Ksword5.1.exe` remained at SHA-256 `C6FA5BEAB57D7530BFAEE8B6598D8DDFF3176C6E483B890910DBC05B6BF6F09A`; this is not attributed as a successful artifact of the failed build.

## Light

- Command: `tools/Invoke-KSwordNativeBuildCheck.ps1 -Product Light`
- Configuration: `Release|x64`, HostX64, `BelowNormal`, fixed project/output directories, existing signed-driver reuse.
- IntDir: `KswordARKLight/x64/Release/obj`
- OutDir: `Ksword5.1/x64/Release`
- Result: `SUCCESS`
- Exit code: `0`
- Artifact: `Ksword5.1/x64/Release/KswordARKLight.exe`
- SHA-256: `B6BA0FC1953F6D7C4CAFD86B28433F97B64DAA7E53B782EB4AFDC50488BC151E`
- Non-fatal warning: `ActionAnalyzePage.cpp(832,19)` C4456 (`actionWidth` shadows an earlier local declaration).
- The existing signed driver was reused; no driver build, install, load, or runtime validation was performed.

## Replay and cleanup

- Read-only `api-evidence replay` was not run. The retained attempt-07 and behavior-history evidence contain no existing project directory/sample that is eligible under the requested replay-only boundary. The behavior-history failure had already removed its project in `finally`.
- No project, sample, capture, target, or replay input was created.
- Final process check found no active `MSBuild`, `cl`, `link`, `KswordCLI`, or `KswordARKLight` process. An unrelated pre-existing `Ksword5.1.exe` process was left untouched.
- Fixed build logs and the Qt raw log were retained. No temporary build project or runtime copy was created outside the approved fixed directories.

## Qt follow-up after the translation-key fix

- Follow-up authorization: one Qt incremental build after `88dfa77b5` registered the stable `behavior:%1:%2:%3:%4:%5` source key in both language packs. The source range also includes `2946df46e` network target capture windows; `6ba5fc62a` was the observed source commit at build end.
- Command: `tools/Invoke-KSwordBuildCheck.ps1 -Action Build -RepositoryRoot (Get-Location).Path -TimeoutMinutes 20`
- Configuration: `Release|x64`, HostX64, `BelowNormal`, `BuildProjectReferences=false`, fixed IntDir/OutDir, repository wrapper with built-in i18n audit.
- Build source window: `BUILD_SOURCE_COMMIT_BEGIN=88dfa77b5e3511e1ce9676d896bdb981275b639c`; `BUILD_SOURCE_COMMIT_END=6ba5fc62a5ce8d6dde3912a6688580830b05ab2f`; working tree dirty at both boundaries.
- IntDir: `Ksword5.1/Ksword5.1/Ksword5.1/x64/Release`
- OutDir: `Ksword5.1/x64/Release`
- Result: `SUCCESS`
- Exit code: `0`
- Duration: `190` seconds
- Artifact: `Ksword5.1/x64/Release/Ksword5.1.exe`
- Artifact bytes: `37133720`
- SHA-256: `6D97EA33C34A01DE8DF91EA99C7D9DCA93DB9864FD948B759B11A50F27569E4C`
- `I18N_AUDIT_PASSED=True`
- Raw log: `.codex-build-logs/ksword-build-check-20261127-140012.raw.log`
- No CLI rebuild, Light rebuild, GUI, target, Agent, driver, or capture was started in this follow-up. The prior Qt i18n failure above remains historical; this success supersedes it only for this follow-up build.

## Behavior-history scope update

- The retained `d2ea88b` behavior-history capture has `360` ordinary/source rows across `2` committed segments, `72` behavior matches, and a truncated recent-behavior window containing `32` entries. Its raw coordinates and bilingual behavior explanations are present in the retained receipt.
- The original behavior-history `FAIL` remains unchanged: the post-capture receipt path raised `KeyError: 'failed'` with controller exit `6`, and its temporary project was removed during `finally` cleanup.
- The retained attempt-07 `FAIL` remains unchanged: the runner compared `enqueuedFrames=13` with only four strict capture progress frames. No replay was performed because no eligible existing attempt-07 or behavior-history project/sample was retained; no replacement project or sample was created.
