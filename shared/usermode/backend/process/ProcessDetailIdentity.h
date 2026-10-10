#pragma once
#include "../Common.h"
#include "ProcessBasicInfoSupport.h"
namespace ks::r3::process_detail::detail {
struct DetailIdentityEvidence {bool opened=false,timeKnown=false,matched=false;DWORD openError=0,timeError=0;ULONGLONG creationTime=0;};
bool AcquireDetailIdentityLease(DWORD processId, ULONGLONG expectedCreationTime100ns, ks::r3::common::UniqueHandle& identityProcess, std::wstring& statusText,DetailIdentityEvidence* evidence=nullptr);
}
