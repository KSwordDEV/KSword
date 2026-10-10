#pragma once
#include "../Common.h"
#include "ProcessDetailTypes.h"
#include "ThreadActions.h"
#include <sddl.h>
#include <winternl.h>
#include <array>
#include <functional>
#include <cstddef>
#include <vector>
#include <string>
#include "ProcessToken.h"
namespace ks::r3::process_detail::token {
constexpr std::array<int, 10> kTokenBooleanInformationClasses{
    15, 23, 24, 26, 21, 29, 40, 46, 47, 48
};
ProcessTokenSwitchSnapshot CollectTokenSwitchSnapshot(
    const DWORD processId,
    const ULONGLONG expectedProcessCreationTime100ns);
ProcessDetailActionResult WriteTokenSwitches(DWORD processId, ULONGLONG expectedProcessCreationTime100ns, const std::array<bool, 12>& values);
ProcessDetailActionResult WriteTokenSwitch(DWORD processId,ULONGLONG expectedCreationTime,std::size_t index,bool enabled);
}
