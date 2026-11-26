#include "AttachedApiCaptureCommand.h"
#include "ApiMonitorEvidenceCommand.h"

namespace ks::cli::action_analyze {
void RegisterAttachedApiCaptureCommand()
{
    Command command;
    command.path = L"analyze api-evidence attach";
    command.syntax = L"KswordCLI.exe analyze api-evidence attach --project PATH --title TITLE --pid PID --creation-filetime VALUE --confirm [--duration-ms MS] [--startup-progress 1] [--json]";
    command.summary = L"Explicitly load or reuse the product Agent on an exact authorized process and archive observed API calls.";
    command.options = L"Required: --project, --title, --pid, --creation-filetime, --confirm. R3 only.";
    command.notes = L"Does not require cooperative preloading. Uses the product Agent beside this executable, with no child injection or behavior modification. "
         L"Module loading is reported separately from SessionReady, HooksInstalled and a verified complete snapshot containing active observational coverage. "
        L"--startup-progress 1 emits verified startup stages as JSON lines to stderr; stdout remains the final result. "
        L"The final startup snapshot preserves the last reached stage and elapsedMs even when startup fails. "
        L"--duration-ms is 1,000-120,000 (default 3,000), or 0 until console cancellation or target exit. "
        L"Startup and stop/drain remain bounded. Continuous sessions return partial (6). "
        L"Ordinary packets use the existing project checkpoint pipeline; replay reads committed segments. "
        L"HooksRemoved means hooks stopped; the pinned Agent and retired code remain until target exit. R0 is rejected without fallback.";
    command.run = RunAttachedApiEvidence;
    addCommand(std::move(command));
}
}
