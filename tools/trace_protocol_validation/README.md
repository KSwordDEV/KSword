# Offline tracing protocol state models

These small Python standard-library models make selected planning constraints
executable. They are illustrative invariants, **not production API correctness,
Windows, IPC, tracing coverage, recovery, or performance proof**. No production
module is imported or source-scanned. Nothing builds or implements a tracing
engine. The parent session owns the separate physical IPC fixture.

Read against the current planning sources:

- [Main tracing plan](../../docs/恶意行为单点追踪与调试能力规划.md), especially
  sections 3.3, 5.6, 6.2, 7.1 and 8.1.
- [Behavior semantic rules plan](../../docs/行为语义规则模板收集与并入规划.md),
  especially sections 7, 8 and 10.

## Run

From the repository root:

```powershell
py -3 -B tools/trace_protocol_validation/test_protocol_model.py --write-results
```

Without `--write-results`, the runner only prints results. With it, the only file
written is the fixed JSON text log:
`.codex-build-logs/behavior-planning/action-analyze-protocol-model-results.json`.
It includes pass/failure counts, experiment counts, limitations and source hashes.
The runner returns nonzero on test failure, and writes failure results too.
Use `-B`; the test runner also disables bytecode before importing the model.
There are no test configuration files, compiled artifacts, external dependencies,
network requests, real pipes, worker processes, UI, injection, drivers, or actual
thread suspension. No random sleeps or waits are used.

## Predeclared assumptions and observable outcomes

The model deliberately uses tiny capacities and a fixed alphabet, not proposed
product defaults or approved budgets. `ProhibitedTransition(code)` is an explicit
rejection. Capacity losses and stale ACKs return distinct outcome strings and
increment fixed counters. Tests compare these outcomes with handwritten expected
traces and an independent event-order oracle. Rejected requests do not count as
successful protocol progress. Model `check()` assertions expose illegal state;
run normally, without Python's `-O` option.

| Model | Constraint and negative cases |
| --- | --- |
| `Startup` | Control reader exists before AgentReady. Initiator release requires the current configuration ACK and **both** `api` and `execution_probe` coverage entries. Applied config is separate from received ACK. Cancel/restart changes generation; delayed old-generation or other-session ACK cannot satisfy the new barrier. Wrong revision is rejected. |
| Target execution | Target control code is abstract thread 0 in a fixed two-user-thread target. When **ALL target user threads are suspended**, fresh Ready/config/coverage/ACK execution is impossible. Splitting a pipe changes no runnable state. An **EXTERNAL** control action must resume selected thread 0 before a fresh target ACK can be produced. A previously produced, buffered ACK may still be received by an external reader; that receipt is not new target execution. |
| `StopControl` | Stop identity is `(session epoch, stop epoch)`. Both modeled threads must confirm stopped before executable permission is restored and one selected thread is released. A foreign hold blocks that thread's selected execution. The selected thread must leave the page before rearm; other owned holds release only after explicit rearm. Releasing own holds does not release foreign holds or assert that the target is running. This is an ordering abstraction, not an instruction emulator or all-Windows-thread freeze proof. |
| Command identity | A bounded command ledger caches payload and outcome. Same ID/same payload returns the old outcome without repeating effects, even after another stop begins. Same ID/different payload is rejected. A new ID is a new command; an old stop token with a new ID cannot release the new stop. The ledger does not evict IDs: exhaustion rejects new work, while cached retries remain available. Session restart clears it only after clean closure. |
| `Capacity` | Six telemetry slots in eight total slots leave two exclusively available to control. Control may borrow unused telemetry capacity. Overflow is explicit, including control overflow; reservation is not an unlimited delivery guarantee. Control drains first. Draining rejects/counts new telemetry but accepts bounded late control. After closure, both kinds are explicitly rejected and cannot reopen the queue. |
| `SemanticBudget` | At most three entities, four partial matches total, two partials per entity and two event-ID references per partial. Overload marks incomplete and counts the precise limit. Logical window expiry and entity exit remove references and have distinct normal-cleanup counters. No semantic matches or causal facts are inferred. |
| Shutdown/owner loss | Shutdown cannot finish until queues drain **and** outstanding stop/recovery responsibility resolves. Even a requested stop with no stop ACK yet remains unresolved. Late stop ACKs remain accountable during draining/owner loss. Owner loss or failed recovery never proves release. Ordinary continue/selected-run commands cannot act for a lost owner. Successful external recovery is an assumed, explicit confirmation; unrelated foreign holds are preserved. New sessions cannot overwrite unresolved debt. |

There is no arbitrary callback, variable-sized payload, log history, or unbounded
state stored by these models. The test harness owns its separate bounded traces.
Unknown events are not fed to a permissive default handler.

## Deterministic adversarial checks

The runner enumerates all `6! = 720` permutations of reader/ready/apply/ACK/
coverage/release. Independent prerequisites admit exactly **3** orders and reject
**717** at their first prohibited transition. Another five scenarios omit one
required handshake event. This is exhaustive only for that six-event alphabet,
not for cancellation, arbitrary retries, real interleavings or the whole product.
All **28** distinct interleavings of six telemetry and two control arrivals also
preserve the reservation without loss. This does not model concurrent memory
operations, contention, wire delivery or OS scheduling.

Nine predeclared, deliberately broken variants remove individual constraints:
reader ordering, config ACK barrier, coverage barrier, stale-generation rejection,
target execution dependency, stop identity, command deduplication, control reserve,
and recovery-before-close. For each, the normal model blocks the counterexample
and the faulty variant exhibits the forbidden observable outcome. These are
negative controls for the model oracles, not discovered product vulnerabilities
and not a production mutation-testing score.

## Analytical state bounds

All retained identity/time inputs are integers in `0..255`; session, generation
and stop epochs reject exhaustion instead of wrapping. Diagnostic counters are
bounded at `65535`; the next increment raises `COUNTER_EXHAUSTED`. These artificial
limits keep the modeled domains finite, not service-lifetime recommendations.

| State category | Maximum logical retention |
| --- | ---: |
| Queue occupancy | 8 records; telemetry at most 6 |
| Reserved control capacity | 2 of those 8 records |
| Command cache | 4 records per session |
| Own stop-hold thread IDs | 2 |
| Fixed foreign-hold thread IDs | 2, immutable |
| Current stop token | 1 |
| Startup config ACK | 1 |
| Startup required coverage members | 2 |
| Target runnable thread IDs | 2 |
| Semantic entity IDs | 3 |
| Partial matches | `min(4, 3 * 2) = 4` |
| Evidence-ID references | `4 * 2 = 8` |
| Semantic notice counters | 6 |

Queue records are represented by occupancy counters; payload bytes, serialization,
kernel buffers, allocator overhead and archive/UI caches are not modeled. Thus
these are count bounds, **not byte or RSS bounds**. No benchmark, timing, throughput,
fairness, deadlock freedom in executable OS code, or maximum pause claim follows.
The model's finite command cache deliberately refuses new commands when full;
production cache retirement and long-session recovery need their own design.

## Scope of evidence

Tests establish consistency and fault sensitivity under the declared model
assumptions. They do not verify any existing Agent protocol or ABI, configuration
installation, wire framing, real process/thread identity, complete stop sets,
new-thread gating, target locks, selected-thread/page transitions, actual recovery,
controller survival, source attribution, upstream-rule equivalence, GUI behavior,
or memory/performance budgets. No product source, other fixture, documentation,
configuration, or Git state is modified by the test runner.
