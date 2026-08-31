#pragma once

#include "ServiceModel.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Service {

// EnumerateServices reads every Win32 service and driver service from the SCM.
// There is no input; processing runs entirely on the calling thread and is safe
// to call from a worker; output is one snapshot plus a diagnostic string.
//
// Enumeration goes through ks::service::EnumerateServiceRecords, the same
// reusable layer the Qt build uses, rather than a second SCM reader written for
// this product: the pager, the config enrichment and the per-service error
// handling are subtle enough that two implementations would disagree in exactly
// the cases an audit cares about.
ServiceEnumerationResult EnumerateServices();

// QuerySingleService refreshes one row after an action completes. Input is the
// SCM short name; output carries success=false with a diagnostic when the
// service has since been deleted or became unreadable.
ServiceEnumerationResult QuerySingleService(const std::wstring& serviceName);

// ServiceDetailAvailability is scoped to an optional read-only detail query.
// The base ServiceEntry remains displayable when one of these sections is only
// partial or unavailable, so a denied optional SCM access never hides facts
// that were already collected during enumeration.
enum class ServiceDetailAvailability {
    Available,
    Partial,
    Unsupported,
};

// ServiceDetailSection carries the outcome of one independent SCM read. On a
// failure, diagnosticText begins with Partial or Unsupported so it can be
// shown unchanged in a native detail list and copied to TSV evidence.
struct ServiceDetailSection {
    ServiceDetailAvailability availability = ServiceDetailAvailability::Available;
    std::wstring diagnosticText;
};

// ServiceFailureActionSnapshot owns one configured SCM recovery action. Both
// raw numeric fields and actionText are retained so consumers can either emit
// precise TSV or render the already formatted text without querying SCM again.
struct ServiceFailureActionSnapshot {
    std::uint32_t actionType = 0;
    std::uint32_t delayMs = 0;
    std::wstring actionText;
};

// ServiceFailureSettingsSnapshot is the read-only representation of
// SERVICE_FAILURE_ACTIONS plus SERVICE_FAILURE_ACTIONS_FLAG. The has* flags
// preserve the reusable layer's distinction between an absent optional config
// block and a successfully read false value.
struct ServiceFailureSettingsSnapshot {
    std::uint32_t resetPeriodSeconds = 0;
    std::wstring rebootMessage;
    std::wstring command;
    std::vector<ServiceFailureActionSnapshot> actions;
    bool failureActionsOnNonCrash = false;
    bool hasFailureActions = false;
    bool hasFailureActionsFlag = false;
};

// ServiceDependencySnapshot keeps direct dependency services, +load-order
// groups, and direct reverse dependencies in separate vectors. It intentionally
// does not infer transitive relationships, which the SCM query does not prove.
struct ServiceDependencySnapshot {
    std::vector<std::wstring> directServiceNames;
    std::vector<std::wstring> loadOrderGroups;
    std::vector<std::wstring> directDependentServiceNames;
};

// ServiceDetailSnapshot is an immutable worker result for a selected service.
// properties is a flat, stable name/value projection for a list view or TSV;
// the typed sub-snapshots retain the individual field values for other callers.
// Failure settings and reverse dependencies are deliberately independent
// sections so one access failure never suppresses the other or the base data.
struct ServiceDetailSnapshot {
    ServiceEntry entry;
    std::vector<ServiceProperty> properties;
    ServiceFailureSettingsSnapshot failureSettings;
    ServiceDependencySnapshot dependencies;
    ServiceDetailSection failureSettingsStatus;
    ServiceDetailSection reverseDependenciesStatus;
};

// ServiceDetailAvailabilityText formats an optional-section result. It uses
// the stable English status tokens expected in diagnostics and TSV output.
std::wstring ServiceDetailAvailabilityText(ServiceDetailAvailability availability);

// QueryServiceReadOnlyDetails enriches an already-enumerated service row with
// read-only failure-recovery and direct reverse-dependency details. The two
// SCM calls are performed independently; failures become Partial or explicit
// Unsupported section diagnostics and never invalidate the base snapshot.
ServiceDetailSnapshot QueryServiceReadOnlyDetails(const ServiceEntry& entry);

// ResolveServiceImagePathForBrowser extracts the configured service image from
// an SCM binary command line, reuses the enumerator's existing system-root
// resolution rules, and returns a path candidate for a strict FileBrowser
// parent-directory route. It performs no file existence probe.
std::wstring ResolveServiceImagePathForBrowser(const std::wstring& binaryPath);

} // namespace Ksword::Features::Service
