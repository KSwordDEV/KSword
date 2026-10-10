#pragma once
#include "../Common.h"
#include <cstdint>
#include "EventProcessImagePath.h"
namespace ks::r3::process {
std::wstring ProcessDisplayName(const std::uint32_t processId,ProcessImageEvidence* evidence=nullptr,ULONGLONG expectedCreationTime=0);
}
