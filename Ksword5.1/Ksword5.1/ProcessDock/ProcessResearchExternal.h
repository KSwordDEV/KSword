#pragma once
#include "ProcessDetectionForensics.h"

namespace ksword::detection
{
    bool CollectResearchExternal(int id, const ScanInputs& inputs, ScanResult& result,
        MethodReport& report, const CancelCheck& stop);
    void ReadResearchKernelPaths(ScanResult& result, MethodReport& report, const CancelCheck& stop);
}
