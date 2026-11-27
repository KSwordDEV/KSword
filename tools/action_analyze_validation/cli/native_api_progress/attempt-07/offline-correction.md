# Attempt 07 Offline Assessment

The single attempt-07 run is preserved as executed. `receipt.json` remains a
`FAIL` receipt because the runner stopped at its own progress-delivery
assertion; the scenario was not rerun.

The assertion compared `captureProgress.enqueuedFrames` with the number of
strict `api-capture-progress` frames. The product queue counts both startup
frames and strict capture-progress frames. The attempt emitted 9 startup
frames and 4 strict progress frames, so the recorded `enqueuedFrames=13` was
correct. The runner expected `4`, which caused the `AssertionError` after the
Held-owner and identity checks and before the normal shutdown request. The
runner assertion is corrected in the working tree to compare `9 + 4`.

Offline extraction from the recorded `execution/1` response confirms the
product-side capture terminal state reached `held-complete`, with
`captureStatus=capture-partial`, `exitCode=6`, `connected=true`,
`started=true`, `completedInterval=true`, `lastProgressSequence=4`,
`droppedFrames=0`, and `outputDrained=true`. The raw stderr contains the final
segment checkpoint (`finalSegment=true`). The run log separately records the
original Held owner and stop identity as unchanged.

This evidence proves the explicit-attachment startup and progress delivery
for this narrow run, but it does not claim the normal controller shutdown
request completed: the harness assertion interrupted that final step. The
attempt remains a harness-failed validation, not a clean PASS.

The finalizer still stopped the source, closed the original Held target,
stopped the controller, removed the project/sites artifacts, and removed the
temporary target. A post-run process/filesystem audit found no matching
`native_api_progress`, `cooperative_api_capture`, `product_execution_group_append`,
`ActionAnalyzeAppendGroupChild`, or `KswordCLI` process, and found no residual
`project`, `sites.json`, `KswordApiMonCooperative`, execution-group object, or
temporary target artifact. No cooperative directory was created by this run.
