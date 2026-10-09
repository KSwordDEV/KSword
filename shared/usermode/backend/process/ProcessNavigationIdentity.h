#pragma once
#include "../Common.h"

namespace ks::r3::process {
ULONGLONG QueryProcessCreationTimeR3(DWORD processId, ULONGLONG expectedCreationTime100ns);
}
