#pragma once
#include "../Common.h"
#include "ProcessBasicInfoSupport.h"
namespace ks::r3::process_detail::detail {
bool AcquireDetailIdentityLease(DWORD processId, ULONGLONG expectedCreationTime100ns, ks::r3::common::UniqueHandle& identityProcess, std::wstring& statusText);
}
