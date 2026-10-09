#pragma once
#include "HardwareStatsModel.h"
#include "../../../shared/usermode/backend/hardware/PerformanceSampler.h"
namespace Ksword::Features::HardwareStats {
using ks::r3::hardware_stats::PerformanceScope;
using ks::r3::hardware_stats::PerformanceSampler;
using ks::r3::hardware_stats::MakePerformanceSampler;
}
