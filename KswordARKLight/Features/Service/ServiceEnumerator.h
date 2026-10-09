#pragma once
#include "ServiceModel.h"
#include "../../../shared/usermode/backend/service/ServiceEnumerator.h"
namespace Ksword::Features::Service {
using ks::r3::service::EnumerateServices;
using ks::r3::service::QuerySingleService;
using ks::r3::service::ServiceDetailAvailabilityText;
using ks::r3::service::QueryServiceReadOnlyDetails;
using ks::r3::service::ResolveServiceImagePathForBrowser;
using ks::r3::service::ServiceDetailAvailability;
using ks::r3::service::ServiceDetailSection;
using ks::r3::service::ServiceFailureActionSnapshot;
using ks::r3::service::ServiceFailureSettingsSnapshot;
using ks::r3::service::ServiceDependencySnapshot;
using ks::r3::service::ServiceDetailSnapshot;
}
