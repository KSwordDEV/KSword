#pragma once

#include "ProcessDetectionForensics.h"

namespace ksword::detection
{
    bool CollectResearchObjects(int id, const ScanInputs& inputs, ScanResult& result,
        MethodReport& report, const CancelCheck& stop);
}
