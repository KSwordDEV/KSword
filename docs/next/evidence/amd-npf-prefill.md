# NPF demand-mapping cost reduction (2026-09-21)

Evidence: `artifacts/eventinj-clear-v6-black-screen-20260921-202` and `202b`.
The sum of sampled general hardware exits increased from 127720091 to 146774713
(delta 19054622). This is an all-exit counter, not an NPF counter: active snapshots
also show L1 MSR exits (0x7c). L2 flight rows show changing RIP/GPA and ordinary
intercepts alongside NPF. The evidence does not establish a single-page infinite
retry or prove that NPF alone explains the black screen.

Two targeted cost reductions:

- MMU composition preserves write permission when both revalidated source leaf D
  bits are already set. Either source D clear still requires a real first-write
  fault; read-only source permissions remain read-only.
- When both committed source translations use 2-MiB/1-GiB leaves, populate empty
  4-KiB siblings within their common aligned 2-MiB span. The same source paths,
  A/D accounting, cache attributes and permission intersection cover the span.
  No extra allocation, adjacent source-table reads, or cross-entry cache reuse.
  Existing siblings are retained. With any 4-KiB source leaf, behavior is unchanged.

Every virtual VMRUN still invalidates NPT02; no stale mapping reuse or weakened
invalidation was introduced. This is a bounded performance candidate, not proof
that a full L2 OS now boots. Actual source page sizes in the incident are unknown;
large-span benefits therefore remain conditional on the workload's source maps.

Validation: all 22 offline build-tests targets passed (`test-npf-prefill.log`).
New cases check source D reuse/clearing, read-only restrictions, all 512 sibling
frames, UC/NX preservation, write upgrade and span boundaries. Standard Release
x64 WDK build, x64 ApiValidator and CAT generation passed with zero warnings
(`build-npf-prefill.log`). Candidate: `tools/hvm_lab/artifacts/npf-prefill-v6`.
Unsigned, not loaded; no live VM/driver command, reset or hardware retest performed.
