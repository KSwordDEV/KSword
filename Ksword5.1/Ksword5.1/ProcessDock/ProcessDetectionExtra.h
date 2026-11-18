#pragma once

#include "ProcessDetectionMethods.h"

namespace ksword::detection
{
    QVector<Method> ExtraMethods();
    void CollectExtraMethods(ScanResult& result, const ScanInputs& inputs,
        const std::function<bool()>& cancelled);
}
