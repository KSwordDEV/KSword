# Cache invalidation diagnostics (metrics v9)

2026-09-24. The running npt-transfer-cache-v7 VM remains at the Windows logo. User estimates roughly 1/20 native boot speed and observes alternating busy host cores. Neither the occupancy graph nor NPF totals identify thread migration or prove repeated cache clearing.

This candidate adds bounded per-CPU counters without changing cache eligibility, intercepts, ASIDs or hardware flush policy. Every entry-cache lookup records a hit or a reset result. Eighteen overlapping miss reasons distinguish disabled reuse, cold state, epoch change, owner-token discontinuity, nonzero virtual TLB_CONTROL and each of the existing thirteen cache keys. Cold entries do not attribute meaningless differences to previously uninitialized keys. INVLPGA and pool-recycle counts remain separate. `ownerTransitions` counts repeated ownership, while `ownerCpuTransitions` counts a VMCB acquired by a different Windows group:number identity; it is a scheduling correlation signal, not proof that a guest thread migrated.

The statistics live in preallocated session storage, saturate rather than wrap, and are copied under the existing general sequence validation. Failed snapshots remain invalid. The shared protocol is defined only in `shared/driver/`; metrics v9 rejects old versions/lengths. The main HVM protocol is unchanged. The CLI exports lossless 64-bit strings. The two-snapshot analyzer excludes incoherent, saturated, changed-generation and reset counters, reports CPU coverage, and does not sum overlapping reasons as independent resets.

Validation:

- All 23 offline HVM targets passed; session 2,616 checks cover cold/hit, seventeen reset scenarios, VMLOAD/VMSAVE continuity, overlapping reasons, saturation without control-flow changes and failed-reset accounting.
- Production CLI JSON fixture and Windows PowerShell 5.1 parsing passed; old-version and short responses rejected. Counter widths exceed 32 bits in the fixture.
- Analyzer cases cover complete deltas, invalid/odd sequence, saturation, generation changes, decreasing/inconsistent counters, duplicate topology, wrong version and invalid time intervals.
- General/nested/host evidence gates passed with synthetic inputs. Command parity and IOCTL audit passed.
- Standard MSVC/WDK Release x64 Build, Universal API validator and CAT generation passed with zero warnings. Driver, CLI and main-program logs are `tools/hvm_lab/build-cache-stats-*.log`. The main Release project compiled and linked with exit 0; its existing test-certificate trust verification warning is separate from compilation and loading.

Candidate directory: `tools/hvm_lab/artifacts/npt-cache-stats-v8`. SYS is unsigned; matched PDB, v8 CLI, updated exporter and analyzer are staged alongside it. The GUI binary is not rebuilt for this diagnostic handoff; use the staged CLI. No new candidate was loaded and no running driver or VM was stopped/reset during this change.

Next: user signs the new SYS, then coordinate VM shutdown and guarded driver swap. Collect two valid v8 samples during the slow logo phase. Determine actual reset frequency and dominant reasons before selecting the next optimization. A high hit rate would redirect investigation to exit/translation cost rather than repeated clearing. No full inner OS or performance pass is claimed.

## TLB gate finding

The first metrics-v8 live run showed the remaining gate: in one 5.7-second interval, 13,061 cache lookups all reset with the TLB gate, while the previous interval had a 68.3% hit fraction. VMware frequently sets VMCB `TLB_CONTROL`; this is an architectural request for the hardware TLB flush already performed on VMRUN, and does not by itself require rebuilding stable NPT02 tables. The follow-up metrics-v9 candidate retains a separate `tlbRequests` counter and no longer treats that field as a software shadow reset reason; the old reason slot is named `tlbGateReserved` and remains zero. Explicit INVLPGA, epoch changes, key changes and owner safety checks remain invalidating. The v9 candidate has not yet been loaded.
