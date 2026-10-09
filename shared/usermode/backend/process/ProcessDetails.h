#pragma once

#include "ProcessFields.h"
#include "../../../../Ksword5.1/Ksword5.1/ksword/process/process.h"

namespace ks::r3::process {

// Pure demand/formatting layer shared by the worker and regression tests.
std::uint32_t DetailDemandForColumns(const std::vector<ProcessFieldId>& columns);
void ApplyProcessDetailRecord(ProcessSnapshotRow& row, const ks::process::ProcessRecord& record);

} // namespace ks::r3::process
