#pragma once
#include "../../../shared/usermode/backend/hardware/HardwareStatsTypes.h"
namespace Ksword::Features::HardwareStats {
using ks::r3::hardware_stats::PerformanceMetricRow;
using ks::r3::hardware_stats::DiskActivityRow;
using ks::r3::hardware_stats::PerformanceSnapshot;
using ks::r3::hardware_stats::UsbNodeKind;
using ks::r3::hardware_stats::UsbNode;
using ks::r3::hardware_stats::UsbTopologySnapshot;
using ks::r3::hardware_stats::BusDeviceRow;
using ks::r3::hardware_stats::BusDeviceSnapshot;
using ks::r3::hardware_stats::FormatByteSize;
using ks::r3::hardware_stats::FormatByteRate;
using ks::r3::hardware_stats::FormatPercent;
using ks::r3::hardware_stats::FormatRate;
using ks::r3::hardware_stats::FormatCount;
using ks::r3::hardware_stats::FormatDecimal;
using ks::r3::hardware_stats::FormatLatency;
using ks::r3::hardware_stats::FormatUpTime;
using ks::r3::hardware_stats::UsbNodeKindText;
using ks::r3::hardware_stats::IndentedName;
}
