#include "AttachedApiCapture.h"

namespace Ksword::ActionAnalyze {
CooperativeApiReceipt CaptureAttachedApi(ProjectDocument& document, const AttachedApiRequest& target,
    const std::atomic_bool& cancel, const CooperativeApiReady& onReady,
    const CooperativeApiCommitted& onCommitted, const CooperativeApiTransferCommitted& onTransfers)
{
    if (!target.confirmed || target.useR0Injection || !target.creationFileTime ||
        target.pid <= 4 || target.pid == GetCurrentProcessId()) {
        CooperativeApiReceipt rejected;
        rejected.sampleStatus = {ProjectError::InvalidArgument, ERROR_INVALID_PARAMETER, "attachedApiAdmission"};
        return rejected;
    }
    // 一套封段、原包回读、规则与候选流水线；默认合作入口仍不装载 Agent。
    const CooperativeApiRequest capture{target.pid, target.creationFileTime, target.durationMs,
        target.title, target.revisionId, false, ApiCaptureMode::ExplicitAttachment, target.boundSampleId};
    return CaptureCooperativeApi(document, capture, cancel, onReady, onCommitted, onTransfers);
}
}
