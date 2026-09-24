# Black-screen hotspot diagnostics, metrics v7

The 2026-09-24 hardware run of resume-20260924 entered residency on 32/32 CPUs,
but the user reported a black-screen L2 VM with busy cores. Saved evidence lives
in `artifacts/black-screen-20260924-081502`. Global exits rose by 229200 over about
5.7 seconds. This counter includes L1 and L2, and one per-CPU snapshot was invalid;
its zeroed counters cannot be subtracted. Firmware/device logs showed continued
PCI/SVGA initialization, without proving Windows boot or identifying the cause.

This change adds diagnosis only, not a claimed black-screen fix:

- Capture level, raw code/RIP/info and ECX before general machine dispatch.
- Count legacy 0x00-0xff reasons exactly; keep NPF/INVALID/other separate.
- Keep the first 16 MSR identities per level with reads/writes/malformed direction
  counts; unknown identities after capacity contribute to an explicit overflow.
- Saturating 64-bit counters, no allocation, no guest-memory access, no VM control
  or additional instruction intercepts. Initialization starts a new counter epoch.
- A separate short writer sequence permits readers during lengthy general exit
  processing. Three bounded copy attempts use response memory, not a kernel-stack
  buffer. Failed snapshots have valid=0 and must be excluded from rate analysis.

Compare only matching CPU identities, boot IDs and run generations. Require
hotspots.valid=1 and saturated=0 in both samples. Never substitute general.valid
or flight.coherent for hotspots.valid. Overflow means MSR ranking is incomplete.
The last MSR identity is not necessarily associated with the last arbitrary exit RIP.

Protocol and clients: metrics version 7; normal HVM protocol unchanged. Driver,
hvm_ctl, shared command engine and GUI consume the shared layout. Old metrics
requests retain explicit version/length rejection. Export supports v6 and v7 with
the corresponding CLI; frozen old candidates were not overwritten.

Validation: 23 offline targets passed; production JSON formatting and PS5 decoding
passed; host self-test evidence (37), general acceptance and nested probe evidence
(16) checks passed with synthetic/recorded data. Driver Release x64 MSVC/WDK,
x64 ApiValidator and CAT generation passed, zero warnings. hvm_ctl and KswordCLI
built successfully. GUI built successfully with four existing compiler/deployment
warnings and a post-build test-signature verification warning; this is not driver
signing evidence. Build logs are in tools/hvm_lab with hotspots-v7 names.
New candidate: `tools/hvm_lab/artifacts/hotspots-v7`; unsigned and not loaded.
The active host driver and black-screen VM were not stopped/reset/unloaded.
