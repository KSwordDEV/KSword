#pragma once

#include "ProcessDetails.h"

namespace ks::r3::process {
// Optional, read-only R3 queries; no imported dependency on newer Windows APIs.
void QueryProcessExtraDetails(ks::process::ProcessRecord& record, std::uint32_t demand, bool needEfficiency);
} // namespace ks::r3::process
