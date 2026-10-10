#pragma once
#include "../Common.h"

namespace ks::r3::process {
struct ProcessIdentityEvidence {bool opened=false,timeKnown=false,matched=false,closeAttempted=false,closed=false;DWORD openError=0,timeError=0,closeError=0;ULONGLONG creationTime=0;};
ULONGLONG QueryProcessCreationTimeR3(DWORD processId, ULONGLONG expectedCreationTime100ns,ProcessIdentityEvidence* evidence=nullptr);
}
