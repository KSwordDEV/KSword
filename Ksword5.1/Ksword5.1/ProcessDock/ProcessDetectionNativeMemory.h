#pragma once
#include "ProcessDetectionMethods.h"

namespace ksword::detection
{
    inline constexpr MethodMask PhysicalPageOwners = 1ULL << 13;
    inline constexpr MethodMask ProcessMemorySurvey = 1ULL << 14;
    inline constexpr MethodMask KernelCodePages = 1ULL << 15;
    inline constexpr MethodMask KernelWorkItems = 1ULL << 16;
    inline constexpr MethodMask TimerRoutines = 1ULL << 17;
    inline constexpr MethodMask ResidentMappings = 1ULL << 18;
    QVector<Method> NativeMemoryMethods();
    void CollectNativeMemory(ScanResult& result, const std::function<bool()>& cancelled);
}
