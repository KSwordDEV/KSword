#pragma once
#include "ProcessDetectionMethods.h"
#include <array>

namespace ksword::detection
{
    enum class ResearchBackend { Shared, Objects, Activity, External };
    struct ResearchPoint
    {
        int id;
        QString name;
        Cost cost;
        ResearchBackend backend;
        MethodMask sources;
    };
    const std::array<ResearchPoint, ResearchCount>& ResearchCatalog();
    QString ResearchSource(const ResearchPoint& point);
    DetectionSelection DetectionDefaults(bool deep);
    ScanResult RunSelected(const DetectionSelection& selection, const std::function<bool()>& cancelled = {},
        const ScanInputs& inputs = {});
}
