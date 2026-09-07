#include "LiveNavigation.h"

namespace Ksword::Evidence {

LiveNavigationDecision ResolveProcessNavigation(const ProcessInstanceId& saved,
                                                const LiveResolution& live) noexcept {
    if (!live.found) {
        return LiveNavigationDecision::RejectObjectExited;
    }
    switch (MatchProcessInstance(saved, live.liveProcess)) {
    case MatchResult::Confirmed:
        return LiveNavigationDecision::Allow;
    case MatchResult::NoMatch:
        // 同 PID 但创建时间/启动周期不同：PID 已被复用，绝不把操作交给新进程。
        return LiveNavigationDecision::RejectIdentityMismatch;
    case MatchResult::Candidate:
        break;
    }
    return LiveNavigationDecision::RejectIdentityUnverifiable;
}

const char* NavigationPageName(NavigationPage page) noexcept {
    switch (page) {
    case NavigationPage::Unknown:    return "Unknown";
    case NavigationPage::RiskCenter: return "RiskCenter";
    case NavigationPage::Driver:     return "Driver";
    case NavigationPage::Process:    return "Process";
    case NavigationPage::Thread:     return "Thread";
    case NavigationPage::Memory:     return "Memory";
    case NavigationPage::Network:    return "Network";
    case NavigationPage::Timeline:   return "Timeline";
    case NavigationPage::File:       return "File";
    case NavigationPage::Handle:     return "Handle";
    case NavigationPage::Registry:   return "Registry";
    }
    return "Unknown";
}

const char* NavigationOutcomeName(NavigationOutcome outcome) noexcept {
    switch (outcome) {
    case NavigationOutcome::Delivered:         return "Delivered";
    case NavigationOutcome::TargetPageMissing:  return "TargetPageMissing";
    case NavigationOutcome::ObjectNotPresent:   return "ObjectNotPresent";
    case NavigationOutcome::IdentityUnusable:   return "IdentityUnusable";
    case NavigationOutcome::EvidenceIdMissing:  return "EvidenceIdMissing";
    case NavigationOutcome::EvidenceNotSaved:   return "EvidenceNotSaved";
    }
    return "ObjectNotPresent";
}

NavigationOutcome DecideNavigation(const NavigationRequest& request,
                                   bool targetPageAvailable,
                                   bool objectPresentInPage,
                                   bool evidencePresentInSession) noexcept {
    // F-12：身份门槛无条件生效。requireExactMatch 说的是锚点精度，不是"要不要校验
    // 身份"；把它当开关会让 requireExactMatch=false 的调用拿一个空主键照样 Delivered。
    if (!request.object.navigable()) {
        return NavigationOutcome::IdentityUnusable;
    }
    // F-12：导航必须带证据 id，否则跳过去也回不到原始证据。空 id 早先直接短路掉了
    // 下面这条检查（`!empty() && ...`），"没带证据"反而比"带了但没保存"更容易过关。
    if (request.evidenceId.empty()) {
        return NavigationOutcome::EvidenceIdMissing;
    }
    if (!evidencePresentInSession) {
        // M-08：离线会话里没保存的数据不能悄悄现场补齐。
        return NavigationOutcome::EvidenceNotSaved;
    }
    if (!targetPageAvailable) {
        return NavigationOutcome::TargetPageMissing;
    }
    if (!objectPresentInPage) {
        return NavigationOutcome::ObjectNotPresent;
    }
    return NavigationOutcome::Delivered;
}

} // namespace Ksword::Evidence
