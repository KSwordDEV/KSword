#pragma once

#include "ProcessDetectionForensics.h"

namespace ksword::detection
{
    // Virtual category: Ex2 installed AND process-event capture enabled for this sample.
    inline constexpr quint32 SubsystemCreationCapture = 0x80000000U;
    bool CollectResearchActivity(int id, const ScanInputs& inputs, ScanResult& result,
        MethodReport& report, const CancelCheck& stop);
}
