#pragma once

#include "../../../shared/evidence/memory_workbench/MemoryIoPort.h"

namespace ksword::memwb_ports_detail
{
    // Shared by the production port and the real Win32 read-pipeline regression.
    ksword::memwb::IoReadResult ReadUserModeVirtual(
        std::uint32_t pid, std::uint64_t address, std::uint64_t length);
}
