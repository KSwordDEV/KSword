# NPT cache continuity through VMLOAD/VMSAVE

2026-09-24. Full inner Windows boot remains unverified. User corrected the current npt-walk-cache-v7 observation: Windows logo keeps spinning, no automatic repair screen, no obvious performance improvement.

## Live evidence before this fix

`artifacts/npt-walk-cache-v7-live-20260924-101733` contains the signed candidate swap, 32-CPU residency checks, VMware startup and read-only samples. The e/f pair has 32/32 valid hotspot pairs over 10.9712839 seconds: L1 exits +2,294,313, L2 exits +2,204,855, NPF +2,073,544 and virtual VMRUN +131,312. Approximately 189,000 NPF/s remain; these samples are not a controlled before/after performance benchmark. A shorter firmware phase does not establish Windows boot success or overall speedup.

## Defect and correction

Every owner-table acquisition advances LastToken, including VMLOAD/VMSAVE. SessionCache previously remembered only the last VMRUN token. A successful same-session VMLOAD/VMSAVE on the same translated physical VMCB therefore broke the continuity comparison and discarded reusable NPT02 mappings on the next VMRUN, even with unchanged cache keys and TLB_CONTROL=0.

SessionTransfer now carries its successful lease token into CacheOwnerToken only when the cached VMCB HPA and previous owner token both match. Publication occurs after successful release. Transfers on another HPA leave the cached token unchanged. Intervening acquisitions, including on another CPU, cannot repair a broken chain; failed/partial VMSAVE retains the existing fault/lease behavior. The next VMRUN still checks all cache keys, epoch and virtual TLB control. Hardware full TLB flush is unchanged.

## Verification and candidate

- New production-session regression failed before the fix at the preserved epoch/page-count assertion (`build-npt-transfer-before-tests.log`, exit 1).
- After the fix, all 23 offline targets passed (`build-npt-transfer-tests.log`, exit 0); session checks increased from 1,559 to 2,471. New cases cover repeated VMSAVE guest / VMLOAD host / VMLOAD guest / VMRUN sequences, same-CPU and cross-CPU intervening acquisitions, failed and partial writeback, explicit TLB flush and changed NCR3. Existing 17 cache-invalidation scenarios remain passing. Host-thread tests simulate transitions and are not hardware concurrency evidence.
- Standard Release x64 MSVC/WDK Build exit 0, API validator `Universal`, CAT generation with no errors/warnings (`build-npt-transfer-driver.log`).
- Unsigned candidate: `tools/hvm_lab/artifacts/npt-transfer-cache-v7/KswordARK.sys`, matching PDB and unchanged metrics-v7 CLI staged alongside it. This candidate has not been loaded or tested on hardware.

The running npt-walk-cache-v7 driver and VM were not stopped, reset or replaced during this correction. Next step: user signs the new SYS; coordinate a normal VM shutdown and guarded driver swap, then compare exits and actual Windows boot progress.
