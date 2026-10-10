#pragma once

#include "ProcessDetails.h"

namespace ks::r3::process {
struct ProcessExtraEvidence {
    bool enterpriseKnown = false;
    DWORD enterpriseStates = 0;
    HRESULT enterpriseStatus = E_NOTIMPL;
    std::wstring enterpriseIdentity;
};
// Optional, read-only R3 queries; no imported dependency on newer Windows APIs.
void QueryProcessExtraDetails(ks::process::ProcessRecord& record, std::uint32_t demand, bool needEfficiency, ProcessExtraEvidence* evidence = nullptr);
} // namespace ks::r3::process
