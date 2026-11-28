#include "AttachedApiCaptureCommand.h"
#include "ApiMonitorEvidenceCommand.h"

namespace ks::cli::action_analyze {
void RegisterAttachedApiCaptureCommand()
{
    Command command;
    command.path = L"analyze api-evidence attach";
    command.syntax = L"KswordCLI.exe analyze api-evidence attach --project PATH --title TITLE --pid PID --creation-filetime VALUE --confirm [--auto-transfer] [--transfer-control PATH] [--network-traffic raw-socket|existing-wfp] [--agent-etw 1] [--duration-ms MS] [--startup-progress 1] [--capture-progress 1] [--json]";
    command.summary = L"Explicitly load or reuse the product Agent on an exact authorized process and archive observed API calls.";
    command.options = L"Required: --project, --title, --pid, --creation-filetime, --confirm. R3 only. --auto-transfer arms private remote execution targets before intercepted thread/APC/context dispatch; saves and resumes native execution stops in trace mode.";
    command.notes = L"Does not require cooperative preloading. Uses the product Agent beside this executable, with no child injection or behavior modification. "
         L"Module loading is reported separately from SessionReady, HooksInstalled and a verified complete snapshot containing active observational coverage. "
         L"--network-traffic selects the existing packet source and archives PID hints and retained bytes to raw-network in the same sample, using the original writer. With --auto-transfer, admitted target instances join this source before the handoff ACK and remain in scope after the root exits; packet attribution stays a PID hint. It does not decrypt HTTPS. "
         L"--agent-etw 1 saves own Agent lifecycle events to raw-etw in the same sample. Automatic handoff adds target header PIDs to this source before ACK; header PIDs remain hints. "
        L"--startup-progress 1 emits verified startup stages as JSON lines to stderr; stdout remains the final result. "
        L"The final startup snapshot preserves the last reached stage and elapsedMs even when startup fails. "
        L"--duration-ms is 1,000-120,000 (default 3,000), or 0 until console cancellation or target exit. "
        L"Startup and stop/drain remain bounded. Continuous sessions return partial (6). "
        L"Ordinary packets use the existing project checkpoint pipeline; replay reads committed segments. "
        L"HooksRemoved means hooks stopped; the pinned Agent and retired code remain until target exit. R0 is rejected without fallback.";
    command.run = RunAttachedApiEvidence;
    command.notes += L" --transfer-control PATH requires --auto-transfer. It reads UTF-8 JSON {\"revision\":1,\"paused\":true} about every 100 ms (4 KiB maximum); revision is a nonzero increasing uint64 integer or decimal string and paused is a boolean. Missing files publish nothing and do not resume an accepted pause. A higher revision with paused=false resumes. Invalid changes preserve prior intent, report transferControlInput errors and make an otherwise successful capture partial (6). Actual acknowledgements remain in transferHandoff controlRevision/appliedControlRevision/pauseRequested/heldMembers.";
    command.notes += L" --capture-progress 1 emits committed API checkpoints, latest rule explanations, candidate coordinates and live transferHandoff/network/Agent-ETW snapshots as UTF-8 stderr JSONL. Source snapshots are change-only at most every 500 ms, including silent API intervals. The bounded queue never waits for free space on the capture worker; final captureProgress distinguishes enqueue/drop/drain from product completion. Progress and final rules retain up to 32 recentBehaviors with original coordinates, behaviorMatches and behaviorWindowTruncated; the bounded window is not the complete archive.";
    addCommand(std::move(command));
}
}
