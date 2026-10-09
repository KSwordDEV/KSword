#pragma once
#include "../../../shared/usermode/backend/process/ProcessDetailTypes.h"
namespace Ksword::Features::ProcessDetail {
using ks::r3::process_detail::ProcessBasicInfo;
using ks::r3::process_detail::ProcessThreadInfo;
using ks::r3::process_detail::ProcessModuleInfo;
using ks::r3::process_detail::ProcessR0AuditInfo;
using ks::r3::process_detail::ProcessDetailSnapshot;
using ks::r3::process_detail::ProcessTokenReportSnapshot;
using ks::r3::process_detail::ProcessTokenSwitchSnapshot;
using ks::r3::process_detail::ProcessPebSnapshot;
}
