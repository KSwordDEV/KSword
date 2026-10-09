#pragma once
#include "../../../shared/usermode/backend/monitor/EtwEventModel.h"
namespace Ksword::Features::Monitor {
using ks::r3::monitor::EtwEvent;
using ks::r3::monitor::EtwEventModel;
using ks::r3::monitor::GuidToString;
using ks::r3::monitor::FileTimeToLocalText;
using ks::r3::monitor::BuildVisibleEtwEventsTsv;
}
