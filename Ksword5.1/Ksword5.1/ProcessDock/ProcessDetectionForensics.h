#pragma once

#include "ProcessDetectionMethods.h"
#include <QStringList>

namespace ksword::detection
{
    using CancelCheck = std::function<bool()>;
    inline constexpr MethodMask SecurityHistory = 1ULL << 32;
    inline constexpr MethodMask SysmonHistory = 1ULL << 33;
    inline constexpr MethodMask MountedDtb = 1ULL << 34;
    inline constexpr MethodMask MountedPfn = 1ULL << 35;
    inline constexpr MethodMask HvmWatchHistory = 1ULL << 36;
    inline constexpr MethodMask KernelIntegrity = 1ULL << 37;
    inline constexpr MethodMask CpuIntegrity = 1ULL << 38;
    inline constexpr MethodMask EtlProcesses = 1ULL << 53;
    inline constexpr MethodMask EtlThreads = 1ULL << 54;
    inline constexpr MethodMask RawPageRoots = 1ULL << 55;

    QVector<Method> VolatilityMethods();
    void RunVolatilityPlugin(ScanResult&, MethodReport&, const ScanInputs&, const CancelCheck&,
        const QString& plugin, const QStringList& args, const QString& pluginDirectory = {});
    void ReadVolatility(ScanResult& result, MethodReport& report, const ScanInputs& inputs, const CancelCheck& stop);
    void ReadMountedMemory(ScanResult& result, MethodReport& report, const QString& root, const CancelCheck& stop);
    void ReadEventHistory(ScanResult& result, MethodReport& report, const CancelCheck& stop);
    bool DecodeProcessHistoryEvent(const QString& document, Evidence& evidence);
    void ReadServiceInstallHistory(ScanResult& result, MethodReport& report, const CancelCheck& stop);
    void ReadEtl(ScanResult& result, MethodReport& report, const QString& path, const CancelCheck& stop);
    void ScanRawPageRoots(ScanResult& result, MethodReport& report, const QString& path, const CancelCheck& stop);
}
