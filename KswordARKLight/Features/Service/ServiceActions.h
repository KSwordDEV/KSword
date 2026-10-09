#pragma once
#include "ServiceModel.h"
#include "../../../shared/usermode/backend/service/ServiceActions.h"
namespace Ksword::Features::Service {
using ks::r3::service::StartServiceEntry;
using ks::r3::service::StopServiceEntry;
using ks::r3::service::PauseServiceEntry;
using ks::r3::service::ContinueServiceEntry;
using ks::r3::service::ApplyServiceStartType;
using ks::r3::service::ServiceActionResult;
using ks::r3::service::ServiceStartTypeChoice;
}
