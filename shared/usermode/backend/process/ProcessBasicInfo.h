#pragma once
#include "ProcessDetailTypes.h"
namespace ks::r3::process_detail {
ProcessBasicInfo CollectBasicInfo(DWORD processId, bool& succeededOut);
}
